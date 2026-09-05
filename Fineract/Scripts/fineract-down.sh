#!/usr/bin/env bash
# Stop the Fineract stack.
#
# The same two -f flags used to bring it up are needed here: without the
# override, compose cannot resolve the dead bitnami/kafka tag and refuses to
# act on the project.
#
# Usage:
#   bash Fineract/Scripts/fineract-down.sh          # stop, keep data
#   bash Fineract/Scripts/fineract-down.sh --wipe   # also remove named volumes
#
# Plain `down` keeps the database: this compose file bind-mounts Postgres data
# under the Fineract checkout rather than using a named volume, so --wipe will
# not clear it either. Delete the bind-mount directory by hand for a true reset.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE="$SCRIPT_DIR/../Workarounds/fineract-compose-override.yml"
FINERACT_HOME="${FINERACT_HOME:-$HOME/fineract}"
COMPOSE_FILE="docker-compose-postgresql-kafka.yml"

EXTRA=""
if [ "${1:-}" = "--wipe" ]; then
    EXTRA="-v"
    echo "WARNING: removing named volumes as well."
fi

cd "$FINERACT_HOME" || { echo "No Fineract checkout at $FINERACT_HOME" >&2; exit 1; }
export PWD

docker compose -f "$COMPOSE_FILE" -f "$OVERRIDE" down $EXTRA

echo
echo "Still running:"
docker ps --format '  {{.Names}} | {{.Status}}'
echo "  (no lines above = nothing running)"
