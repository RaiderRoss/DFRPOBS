#!/usr/bin/env bash
# Analyse a capture file offline instead of watching a live interface.
#
# This is the better way to learn Slips and to demo detections: it is
# reproducible, needs no root, and the bundled samples contain known attacks
# so you get real evidence rather than whatever happened to cross your NIC.
#
# Usage:
#   bash slips-analyse-pcap.sh                          # bundled portscan sample
#   bash slips-analyse-pcap.sh dataset/test7-malicious.pcap
#   bash slips-analyse-pcap.sh /path/to/your/own.pcap   # host paths work too
#
# Bundled samples worth trying (list them with --list):
#   dataset/test12-icmp-portscan.pcap              reliable scan detections
#   dataset/test19-malicious-ssh/malicious-ssh-bruteforce.pcap
#   dataset/test-cc/test-cc-capture-1.pcap         command-and-control
#   dataset/test7-malicious.pcap
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORMAT="$SCRIPT_DIR/slips-format.py"
IMG="stratosphereips/slips:latest"

if [ "${1:-}" = "--list" ]; then
    docker run --rm "$IMG" ls dataset/
    exit 0
fi

TARGET="${1:-dataset/test12-icmp-portscan.pcap}"
NAME=$(basename "$TARGET" | tr './' '__')
OUT="${SLIPS_OUT:-$HOME/slips-lab}/out-$NAME"

MOUNTS=(-v "$OUT":/output)
# If the user passed a real host file, mount it in rather than assuming it is
# one of the samples baked into the image.
if [ -f "$TARGET" ]; then
    ABS=$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")
    MOUNTS+=(-v "$ABS":/capture/"$(basename "$TARGET")":ro)
    TARGET="/capture/$(basename "$TARGET")"
fi

# Slips needs Redis, and v1.1.22 crashes if it has to start Redis itself.
if ! docker ps --format '{{.Names}}' | grep -q '^slips-redis$'; then
    docker rm -f slips-redis >/dev/null 2>&1
    docker run -d --net=host --name slips-redis "$IMG" \
        /redis-stable/src/redis-server config/redis.conf.template \
        --port 6379 --bind 127.0.0.1 --daemonize no >/dev/null
    sleep 3
fi

mkdir -p "$OUT"
echo "Analysing $TARGET  ->  $OUT"
echo "(expect ~5 min: startup dominates, not the analysis itself)"

# -m puts the analysis DB on a random port so it does not fight the cache
# Redis on 6379 and prompt for confirmation on a TTY-less run.
# -s saves the DB so you can reload it with -d instead of re-analysing.
docker run --rm --net=host "${MOUNTS[@]}" "$IMG" \
    ./slips.py -f "$TARGET" -o /output -m -s 2>&1 | tail -5

echo
echo "=== EVIDENCE ==="
if [ -s "$OUT/alerts/alerts.log" ]; then
    python3 "$FORMAT" < "$OUT/alerts/alerts.log"
else
    echo "  (no evidence crossed the threshold — a real result, not a failure)"
fi

echo
echo "Full output : $OUT"
echo "Structured  : $OUT/alerts/alerts.json"
echo "Flows       : $OUT/zeek_files/conn.log"
echo "Reload DB   : docker run --rm --net=host -v $OUT:/output $IMG \\"
echo "                ./slips.py -d /output/databases/dump.rdb -m"
