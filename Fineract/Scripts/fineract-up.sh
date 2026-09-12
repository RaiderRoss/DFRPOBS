#!/usr/bin/env bash
# Bring the Fineract stack up.
#
# Wraps `docker compose up -d` with the Kafka image override that Fineract
# 1.9.0 needs (see ../Workarounds/README.md). Without the second -f the
# pinned bitnami/kafka tag returns "manifest unknown" and compose fails.
#
# Usage:  bash Fineract/Scripts/fineract-up.sh
#
# The Fineract source is cloned separately inside WSL and is not part of this
# repo. Override its location with FINERACT_HOME if yours differs.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE="$SCRIPT_DIR/../Workarounds/fineract-compose-override.yml"
FINERACT_HOME="${FINERACT_HOME:-$HOME/fineract}"
COMPOSE_FILE="docker-compose-postgresql-kafka.yml"

if [ ! -d "$FINERACT_HOME" ]; then
    echo "ERROR: Fineract source not found at $FINERACT_HOME" >&2
    echo "Clone it first (see Fineract/Fineract_Setup.md), or set FINERACT_HOME." >&2
    exit 1
fi
if [ ! -f "$OVERRIDE" ]; then
    echo "ERROR: kafka override missing at $OVERRIDE" >&2
    exit 1
fi

# compose resolves ${PWD} in the volume paths and takes the project directory
# from the first -f file, so we must run from the Fineract checkout.
cd "$FINERACT_HOME" || exit 1
export PWD

echo "Starting Fineract from $FINERACT_HOME"
docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE" up -d
rc=$?
if [ $rc -ne 0 ]; then
    echo "compose failed (exit $rc)" >&2
    exit $rc
fi

echo
echo "=== containers ==="
docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE" ps \
    --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'

# The compose bridge is what Slips must watch to see container-to-container
# traffic; eth0 never carries it.
NETID=$(docker network inspect fineract_default -f '{{.Id}}' 2>/dev/null | cut -c1-12)
if [ -n "$NETID" ]; then
    echo
    echo "=== network ==="
    echo "  fineract_default -> br-$NETID   (use this with slips -i)"
fi

echo
echo "=== health ==="
for _ in $(seq 1 30); do
    body=$(curl -k -s --max-time 3 \
        https://localhost:8443/fineract-provider/actuator/health 2>/dev/null)
    if echo "$body" | grep -q '"status":"UP"'; then
        echo "  $body"
        exit 0
    fi
    sleep 5
done
echo "  API did not report UP within 150s — check: docker logs fineract-fineract-manager-1"
exit 1
