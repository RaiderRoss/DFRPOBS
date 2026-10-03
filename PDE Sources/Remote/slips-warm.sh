#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM. Keeps Slips ready to analyse a window.
#
#    slips-warm.sh redis    ensure the standing redis is up
#    slips-warm.sh warm     redis, then one Slips run over an empty
#                           capture, so its threat-intel feeds are
#                           downloaded and cached before any window
#    slips-warm.sh status   warm | warming | cold
#
#  Why: Slips caches ~45 threat-intel feeds in redis. Against an
#  empty cache a run downloads them all before analysing anything —
#  measured at 7 minutes here — and a VM stop empties redis. A warm
#  cache brings a window's analysis down to about one minute.
#  stack-up.sh runs `warm` in the background after every start.
# ==============================================================
set -u

IMG="${SLIPS_IMG:-stratosphereips/slips:v1.1.23}"   # pinned: see IDS/slips-lib.sh
REDIS="${SLIPS_REDIS:-pde-slips-redis}"
DIR="$HOME/pde-slips/.warm"

redis_up() {
	if ! docker ps --format '{{.Names}}' | grep -qx "$REDIS"; then
		docker rm -f "$REDIS" >/dev/null 2>&1 || true
		# Slips 1.1.22+ crashes if it has to start redis itself, so it must already be
		# listening. unless-stopped: it survives a docker restart, though not a VM stop
		# (it holds the cache in memory), which is what `warm` is for.
		docker run -d --restart unless-stopped --net=host --name "$REDIS" "$IMG" \
			/redis-stable/src/redis-server config/redis.conf.template \
			--port 6379 --bind 127.0.0.1 --daemonize no >/dev/null || return 1
	fi
	local i
	for i in $(seq 1 20); do
		docker exec "$REDIS" /redis-stable/src/redis-cli -p 6379 ping 2>/dev/null | grep -q PONG && return 0
		sleep 1
	done
	echo "redis did not answer" >&2
	return 1
}

case "${1:-status}" in
	redis)
		redis_up ;;
	warm)
		redis_up || exit 1
		mkdir -p "$DIR"
		rm -f "$DIR/done"
		# An empty but valid pcap: Slips starts, updates its feeds into redis, reads
		# nothing, and exits.
		python3 -c 'import struct,sys; sys.stdout.buffer.write(struct.pack("<IHHiIII",0xa1b2c3d4,2,4,0,0,65535,1))' > "$DIR/empty.pcap"
		touch "$DIR/running"
		timeout 1200 docker run --rm --net=host -v "$DIR":/output "$IMG" \
			./slips.py -f /output/empty.pcap -o /output/out > "$DIR/warm.log" 2>&1
		rc=$?
		rm -f "$DIR/running"
		[[ $rc -eq 0 ]] && date -u +%Y-%m-%dT%H:%M:%SZ > "$DIR/done"
		exit $rc ;;
	status)
		# Warm only if the warm-up finished since redis last started: a VM stop empties it.
		started=$(docker inspect -f '{{.State.StartedAt}}' "$REDIS" 2>/dev/null || true)
		if [[ -f "$DIR/running" ]]; then
			echo warming
		elif [[ -n "$started" && -f "$DIR/done" ]] \
			&& [[ $(date -d "$(cat "$DIR/done")" +%s) -ge $(date -d "$started" +%s) ]]; then
			echo warm
		else
			echo cold
		fi ;;
	*)
		echo "usage: slips-warm.sh redis|warm|status" >&2
		exit 2 ;;
esac
