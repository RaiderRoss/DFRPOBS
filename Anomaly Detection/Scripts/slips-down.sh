#!/usr/bin/env bash
# Stop Slips and its Redis. Neither is managed by docker compose, so they
# need removing directly rather than with `compose down`.
#
# Capture output is NOT deleted: it lives in the bind-mounted directory on
# the host (default ~/slips-lab/), which is the whole reason for mounting it.
set -u

removed=$(docker rm -f slips slips-redis slips-pcap 2>/dev/null)
if [ -n "$removed" ]; then
    echo "Removed: $(echo "$removed" | tr '\n' ' ')"
else
    echo "Nothing to remove — Slips was not running."
fi

echo
echo "Still running:"
docker ps --format '  {{.Names}} | {{.Status}}'
echo "  (no lines above = nothing running)"

echo
echo "Capture output preserved in: ${SLIPS_OUT:-$HOME/slips-lab}/"
