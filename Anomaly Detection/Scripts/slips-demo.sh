#!/usr/bin/env bash
# ==============================================================
#  SLIPS LIVE CAPTURE DEMO  (~4 minutes, self-contained)
#
#  Shows Slips capturing real network traffic end to end:
#  packets -> Zeek flows -> per-host profiles -> evidence.
#
#  Usage:  bash "Anomaly Detection/Scripts/slips-demo.sh" [interface]
#          (defaults to eth0)
#
#  Leaves Slips running afterwards so you can answer questions live.
#  Stop with:  bash "Anomaly Detection/Scripts/slips-down.sh"
# ==============================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORMAT="$SCRIPT_DIR/slips-format.py"

IFACE="${1:-eth0}"
OUT="${SLIPS_OUT:-$HOME/slips-lab/demo-out}"
IMG="stratosphereips/slips:latest"

# ---- palette ----
C_HEAD=$'\033[1;38;5;74m'    # section headings - desaturated blue
C_DIM=$'\033[38;5;244m'      # secondary detail
C_OK=$'\033[38;5;72m'        # confirmations
C_KEY=$'\033[38;5;179m'      # values worth the eye landing on
C_RULE=$'\033[38;5;238m'     # rules
R=$'\033[0m'

hr()   { printf '%s%s%s\n' "$C_RULE" "──────────────────────────────────────────────────────────────" "$R"; }
head_(){ printf '\n%s%s%s\n' "$C_HEAD" "$*" "$R"; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$R"; }
ok()   { printf '    %s✓%s %s\n' "$C_OK" "$R" "$*"; }
key()  { printf '    %s%s%s\n' "$C_KEY" "$*" "$R"; }

hr
printf '%sSLIPS — LIVE NETWORK CAPTURE DEMO%s\n' "$C_HEAD" "$R"
dim "Zeek turns packets into flows; Slips groups flows into per-host"
dim "profiles split by timewindow, then runs 15 modules to raise evidence."
hr

# ---------------------------------------------------------------
head_ "[1/5] Preparing"
docker rm -f slips slips-redis >/dev/null 2>&1

# Slips writes as root inside the container, so its output is root-owned on
# the host and a plain `rm -rf` fails with "Permission denied" on the
# databases/ and redis/ subdirectories. Clear it from inside a container,
# which is also root, rather than requiring sudo.
mkdir -p "$OUT"
docker run --rm -v "$OUT":/output "$IMG" \
    bash -c 'rm -rf /output/* /output/.[!.]* 2>/dev/null; exit 0' >/dev/null 2>&1

MYIP=$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if [ -z "$MYIP" ]; then
    echo "ERROR: interface '$IFACE' not found. Available:" >&2
    ip -brief -4 addr show >&2
    exit 1
fi
GW=$(ip route | awk '/default/{print $3; exit}')
dim "    host $MYIP on $IFACE, gateway $GW"

# Redis is Slips' state store AND the pub/sub bus between its ~18 processes.
# v1.1.22 also crashes if it has to start Redis itself, so we start it first.
docker run -d --net=host --name slips-redis "$IMG" \
    /redis-stable/src/redis-server config/redis.conf.template \
    --port 6379 --bind 127.0.0.1 --daemonize no >/dev/null
for _ in $(seq 1 20); do
    docker exec slips-redis /redis-stable/src/redis-cli -p 6379 ping 2>/dev/null \
        | grep -q PONG && break
    sleep 1
done
ok "Redis ready on 127.0.0.1:6379"

# ---------------------------------------------------------------
head_ "[2/5] Starting Slips"
dim "    ~80s: 15 detection modules plus 45+ threat-intel feeds"
docker run -d --net=host --cap-add=NET_ADMIN --name slips \
    -v "$OUT":/output "$IMG" ./slips.py -i "$IFACE" -o /output >/dev/null

printf '    '
for i in $(seq 1 40); do
    docker logs slips 2>&1 | grep -q "Started Input Process" && break
    printf '%s·%s' "$C_DIM" "$R"; sleep 5
done
printf '\n'
docker logs slips 2>&1 \
    | grep -E "Detected host IP|Using redis server|local network|Started (Profiler|Input)" \
    | sed "s/^/    ${C_DIM}/;s/$/${R}/"

# ---------------------------------------------------------------
head_ "[3/5] Generating traffic"
dim "    a) ordinary browsing"
curl -s -o /dev/null --max-time 5 https://example.com    && ok "https://example.com"
curl -s -o /dev/null --max-time 5 https://wikipedia.org  && ok "https://wikipedia.org"
dig +short github.com >/dev/null 2>&1                    && ok "DNS lookup github.com"
ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1                   && ok "ping 8.8.8.8"

dim "    b) a port scan against our own gateway — the pattern Slips should flag"
for p in $(seq 20 90); do nc -z -w1 "$GW" "$p" 2>/dev/null; done
ok "probed 70 ports on $GW"

# ---------------------------------------------------------------
head_ "[4/5] Letting Slips process"
printf '    '
for _ in $(seq 1 12); do printf '%s·%s' "$C_DIM" "$R"; sleep 5; done
printf '\n'

# ---------------------------------------------------------------
head_ "[5/5] RESULTS"

head_ "Zeek turned packets into flows"
for f in conn dns ssl; do
    [ -f "$OUT/zeek_files/$f.log" ] || continue
    n=$(grep -vc '^#' "$OUT/zeek_files/$f.log" 2>/dev/null)
    printf '    %s%-10s%s %s%s%s entries\n' "$C_DIM" "$f.log" "$R" "$C_KEY" "$n" "$R"
done

head_ "Internet traffic captured"
grep -v '^#' "$OUT/zeek_files/conn.log" 2>/dev/null \
  | grep -v "\"id.resp_h\":\"172.28" \
  | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        f = json.loads(line)
        print("    %-16s -> %-16s %-5s %s" % (
            f.get("id.orig_h",""), f.get("id.resp_h",""),
            f.get("proto",""), f.get("service","")))
    except Exception: pass' 2>/dev/null | tail -5

SCAN=$(grep -v '^#' "$OUT/zeek_files/conn.log" 2>/dev/null | grep -c "\"id.resp_h\":\"$GW\"")
head_ "Port-scan traffic captured"
key "$SCAN flows to $GW — one per port probed"

head_ "Encrypted sessions (TLS server names, read from the handshake)"
grep -v '^#' "$OUT/zeek_files/ssl.log" 2>/dev/null \
  | python3 -c '
import sys, json
seen=set()
for line in sys.stdin:
    try:
        s=json.loads(line).get("server_name","")
        if s and s not in seen:
            seen.add(s); print("    "+s)
    except Exception: pass' 2>/dev/null | head -6
dim "    (feed hostnames here are Slips downloading its own threat intel)"

head_ "Behavioural profile built for this host"
dim "    'not_estab' across many dstports is the scan's shape, recorded as behaviour"
docker exec slips-redis /redis-stable/src/redis-cli -p 6379 -n 0 \
    keys "profile_${MYIP}*" 2>/dev/null | head -6 | sed 's/^/    /'

head_ "Evidence raised"
dim "    severity first; routine info-level noise collapsed"
if [ -s "$OUT/alerts/alerts.log" ]; then
    python3 "$FORMAT" --brief < "$OUT/alerts/alerts.log"
else
    dim "    (none yet — give it another minute, then re-check)"
fi

hr
printf '%sSlips is still running and watching %s%s\n' "$C_HEAD" "$IFACE" "$R"
dim "  live evidence : tail -f $OUT/alerts/alerts.log | python3 $FORMAT"
dim "  live flows    : docker exec slips bash -c \"grep -vc '^#' /output/zeek_files/conn.log\""
dim "  stop          : bash \"$SCRIPT_DIR/slips-down.sh\""
hr
