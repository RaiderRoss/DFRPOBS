#!/usr/bin/env bash
# ==============================================================
#  The bank on this machine — for running the lab without the
#  research VM.
#
#    Banking/local-bank.sh up            start Fineract
#    Banking/local-bank.sh seed          prepare it for the banking source (safe to re-run)
#    Banking/local-bank.sh status        is it up, and has it been seeded
#    Banking/local-bank.sh stop          stop it, keeping its data
#    Banking/local-bank.sh reset --yes   stop it and delete its data
#
#  Then:   sudo ./lab.sh up --with-ids --local-bank
#  lab.sh runs `up` and `seed` itself when they are needed.
#
#  The same images and settings as the bank on the research VM
#  (Fineract/docker-compose-fineract.yml), so a window captured
#  against it is the same experiment; only Fineract's API is
#  published, on this machine's loopback (see
#  Banking/fineract-compose.local.yml).
#
#  Needs Docker with Compose 2.24 or later, and memory: the bank
#  alone uses about 4–5 GB, and with the IDS beside it about 7 GB.
#  The first `up` downloads about 2 GB of images, then Fineract
#  builds its database, which takes several minutes.
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lab-config.sh
source "$PDE_ROOT/lab-config.sh"

OVERRIDE="$PDE_ROOT/Banking/fineract-compose.local.yml"
UP_TIMEOUT="${UP_TIMEOUT:-1200}"

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# Compose is run from the Fineract directory: its database definition locates its files
# through ${PWD}.
#
# The SecureRS listener in the same compose file is not started for the lab, but compose
# checks every service's variables on every command, and the listener's ${SECURERS_API_KEY:?}
# fails the whole file when the key is unset. A placeholder is supplied for these commands
# only, and only when Fineract/.env does not set a real one — that file is never written.
compose() {
	(
		cd "$FINERACT_DIR"
		if ! grep -qsE '^SECURERS_API_KEY=.' .env && [[ -z "${SECURERS_API_KEY:-}" ]]; then
			export SECURERS_API_KEY="unused-listener-not-started-by-the-lab"
		fi
		docker compose -f docker-compose-fineract.yml -f "$OVERRIDE" "$@"
	)
}

version_at_least() {  # version_at_least <have> <need>
	[[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}

preflight() {
	command -v docker >/dev/null || die "Docker is not installed"
	docker info >/dev/null 2>&1 || die "Docker is not running, or this user may not use it (try sudo)"
	local v
	v=$(docker compose version --short 2>/dev/null) || die "Docker Compose v2 is not installed"
	v="${v#v}"
	version_at_least "$v" 2.24 || die "Docker Compose $v is too old; 2.24 or later is needed"
	[[ -f "$FINERACT_DIR/docker-compose-fineract.yml" ]] || die "no Fineract compose file in $FINERACT_DIR"
}

cmd_up() {
	preflight
	if local_bank_healthy; then
		log "the local bank is already up ($(local_bank_state))"
		return 0
	fi
	local avail
	avail=$(awk '/^MemAvailable:/ {printf "%.1f", $2 / 1048576}' /proc/meminfo)
	if awk -v a="$avail" 'BEGIN { exit !(a < 5) }'; then
		echo "warning: only ${avail} GB of memory is free; the bank needs about 4–5 GB, and with" >&2
		echo "         the IDS about 7 GB. On WSL, raise the limit in %UserProfile%\\.wslconfig." >&2
	fi
	log "starting the bank: PostgreSQL, Kafka and two Fineract nodes"
	log "the first start downloads about 2 GB and then builds the database — allow ten minutes"
	compose up -d --wait --wait-timeout "$UP_TIMEOUT" db kafka fineract-manager fineract-worker \
		|| die "the bank did not come up; its log: (cd \"$FINERACT_DIR\" && docker compose logs fineract-manager)"
	log "building the bank-events collector"
	compose --profile pde build -q pde-collector || die "could not build the bank-events collector"
	log "the bank is up at https://$LOCAL_BANK_TARGET/fineract-provider (this machine only)"
}

cmd_seed() {
	local_bank_healthy || die "the local bank is not up — Banking/local-bank.sh up"
	log "seeding the local bank (staff, customer role, eight customers and the mule)"
	python3 "$PDE_ROOT/Banking/fineract_seed.py" \
		--url "https://$LOCAL_BANK_TARGET/fineract-provider" --out "$LOCAL_BANK_SEED"
	# Run under sudo by lab.sh; the seed belongs to the person, not to root.
	if [[ -n "${SUDO_USER:-}" ]]; then chown "$SUDO_USER" "$LOCAL_BANK_SEED" 2>/dev/null || true; fi
	log "seed written to $LOCAL_BANK_SEED"
}

cmd_status() {
	local state; state=$(local_bank_state)
	echo "bank   ${state:-not running}"
	if [[ -r "$LOCAL_BANK_SEED" ]]; then
		echo "seed   $LOCAL_BANK_SEED"
	else
		echo "seed   none — Banking/local-bank.sh seed"
	fi
	[[ "$state" == *"(healthy)"* ]]
}

cmd_stop() {
	preflight
	# stop, not down: the containers and the database they hold are kept, so the seed stays
	# valid and the next `up` takes a minute rather than a rebuild.
	compose stop
	log "the local bank is stopped; its data is kept (Banking/local-bank.sh up to start it again)"
}

cmd_reset() {
	[[ "${1:-}" == "--yes" ]] || die "this deletes the local bank's database; run: Banking/local-bank.sh reset --yes"
	preflight
	compose --profile pde down -v
	rm -f "$LOCAL_BANK_SEED"
	log "the local bank and its data are gone; Banking/local-bank.sh up, then seed, to start afresh"
}

case "${1:-}" in
	up)     cmd_up ;;
	seed)   cmd_seed ;;
	status) cmd_status ;;
	stop)   cmd_stop ;;
	reset)  shift; cmd_reset "${1:-}" ;;
	*)      sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 2 ;;
esac
