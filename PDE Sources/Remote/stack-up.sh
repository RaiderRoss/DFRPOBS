#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM, not on the lab machine.
#
#  Brings the remote stack back after the VM starts. Docker comes
#  up on boot, but only fineract-db has a restart policy and the
#  Evidence Repository's backend and frontend are plain processes,
#  so after a stop/start nothing answers until this has run.
#
#  From the lab machine:  ./vm.sh start   (starts the VM, then this)
# ==============================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$REPO/Fineract" || exit 1
# The SecureRS listener is not run here — the PDE collector reads the topic instead — but
# compose interpolates every service's variables on every command, and the listener's
# ${SECURERS_API_KEY:?...} fails the whole file when unset.
if [[ ! -f .env ]]; then
	printf '%s\n' "# VM only: the SecureRS listener is not started on this host." \
		"SECURERS_API_KEY=unused-listener-not-started-on-vm" > .env
fi

docker compose -f docker-compose-fineract.yml up -d --wait --wait-timeout 600 \
	db kafka fineract-manager fineract-worker || { echo "FINERACT FAILED"; exit 1; }
echo "FINERACT UP"

# Built here rather than at capture time, so the first window after a sync does not pay
# for it. Cached, so a no-op when Kafka_Listener/ has not changed.
docker compose -f docker-compose-fineract.yml --profile pde build -q pde-collector \
	|| { echo "COLLECTOR BUILD FAILED"; exit 1; }
echo "COLLECTOR READY"

# A VM stop empties Slips' redis and with it the threat-intel cache. Refilled in the
# background now, so the first window after a start is analysed in a minute, not seven.
nohup bash "$REPO/PDE Sources/Remote/slips-warm.sh" warm </dev/null > "$HOME/slips-warm.out" 2>&1 &
echo "SLIPS WARMING (pid $!)"

exec "$REPO/PDE Sources/Remote/er-up.sh"
