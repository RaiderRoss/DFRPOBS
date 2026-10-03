#!/usr/bin/env bash
# ==============================================================
#  The research VM, from the lab machine.
#
#    ./vm.sh status        is it up, can this machine reach it
#    ./vm.sh start         start it and bring its stack up (~4 min)
#    ./vm.sh stop          close the tunnels and stop it
#    ./vm.sh sync          ship this branch's committed HEAD to it
#    ./vm.sh tunnel up     the repository and Fineract on this machine
#    ./vm.sh tunnel down
#    sudo ./vm.sh tundev up   the layer-3 tunnel device (ssh -w over IAP),
#                             so the lab's users reach the VM as themselves
#    ./vm.sh seed          prepare the bank for the banking source
#    ./vm.sh ssh           a shell on it
#
#  The lab — ufw, the namespace, the traffic, the packet capture —
#  runs here. Fineract, the Evidence Repository and Slips run
#  there. See Remote/README.md.
#
#  A stopped VM costs only its disk. Stop it when you are done.
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-config.sh
source "$PDE_ROOT/lab-config.sh"
[[ -f "$PDE_ROOT/pde.conf" ]] && . "$PDE_ROOT/pde.conf"
# shellcheck source=Remote/vm-lib.sh
source "$PDE_ROOT/Remote/vm-lib.sh"
# shellcheck source=Remote/tun-lib.sh
source "$PDE_ROOT/Remote/tun-lib.sh"

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { echo "error: $*" >&2; exit 1; }

REMOTE_REPO="\$HOME/$VM_REPO_DIR"

cmd_status() {
	local st
	echo "gcloud      $(vm_gcloud_bin 2>/dev/null || echo 'MISSING — Remote/install-gcloud.sh')"
	st="$(vm_status)"
	echo "vm          $VM_NAME ($VM_ZONE, project $VM_PROJECT): ${st:-cannot query — not logged in, or no access}"
	if [[ "$st" == "RUNNING" ]]; then
		if vm_ssh true </dev/null >/dev/null 2>&1; then
			echo "reachable   yes, over IAP"
			vm_ssh "cd $REMOTE_REPO 2>/dev/null && echo \"checkout    \$(git rev-parse --abbrev-ref HEAD) @ \$(git log --oneline -1)\"
				curl -sk --max-time 3 https://localhost:8443/fineract-provider/actuator/health | grep -q UP && echo 'fineract    up' || echo 'fineract    DOWN — ./vm.sh start'
				curl -s  --max-time 3 http://localhost:8080/actuator/health | grep -q UP && echo 'repository  up' || echo 'repository  DOWN — ./vm.sh start'
				echo \"slips cache \$(bash \"$REMOTE_REPO/PDE Sources/Remote/slips-warm.sh\" status 2>/dev/null || echo unknown)\"" </dev/null 2>/dev/null
		else
			echo "reachable   NO — SSH over IAP failed"
		fi
	fi
	local t
	for t in admin bank; do
		if vm_tunnel_running "$t"; then echo "tunnel      $t open"; else echo "tunnel      $t closed"; fi
	done
	[[ -r "${BANK_SEED:-$PDE_ROOT/Banking/seed.json}" ]] && echo "bank seed   present" || echo "bank seed   none — ./vm.sh seed"
}

wait_for_ssh() {
	local i
	for ((i = 0; i < 36; i++)); do
		vm_ssh true </dev/null >/dev/null 2>&1 && return 0
		sleep 5
	done
	return 1
}

cmd_start() {
	local st; st="$(vm_status)"
	[[ -n "$st" ]] || die "cannot query $VM_NAME — is gcloud logged in? (Remote/install-gcloud.sh)"
	if [[ "$st" != "RUNNING" ]]; then
		log "starting $VM_NAME"
		vm_gcloud compute instances start "$VM_NAME" --zone "$VM_ZONE" --quiet >/dev/null
	fi
	log "waiting for SSH over IAP"
	wait_for_ssh || die "the VM is running but SSH over IAP did not come up"
	vm_ssh "test -x \"$REMOTE_REPO/PDE Sources/Remote/stack-up.sh\"" </dev/null 2>/dev/null \
		|| die "the VM's checkout predates Remote/stack-up.sh — run ./vm.sh sync first"
	log "bringing the stack up (Fineract, Evidence Repository; Slips cache warms in the background)"
	vm_ssh "\"$REMOTE_REPO/PDE Sources/Remote/stack-up.sh\"" </dev/null
}

cmd_stop() {
	if vm_tunnel_running bank; then
		die "a lab is using the bank tunnel; stop the lab first (./lab.sh down, or quit the console)"
	fi
	vm_tunnel_stop admin
	log "stopping $VM_NAME"
	vm_gcloud compute instances stop "$VM_NAME" --zone "$VM_ZONE" --quiet >/dev/null
	log "stopped — only the disk is billed now"
}

# Ships the committed HEAD of the current branch as a git bundle, so the VM never holds a
# credential for the repository. Uncommitted work is not sent: what runs there is always
# something that exists in history here.
cmd_sync() {
	local repo branch tmp
	repo="$(git -C "$PDE_ROOT" rev-parse --show-toplevel)"
	branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD)"
	[[ "$branch" != "HEAD" ]] || die "detached HEAD; check out a branch first"
	if ! git -C "$repo" diff --quiet HEAD --; then
		echo "note: uncommitted changes are NOT sent — sync ships committed HEAD only" >&2
	fi
	tmp="$(mktemp)"
	trap 'rm -f "$tmp"' RETURN
	git -C "$repo" bundle create "$tmp" "$branch" 2>/dev/null
	log "sending $branch @ $(git -C "$repo" log --oneline -1) ($(stat -c %s "$tmp") bytes)"
	vm_ssh "cat > /tmp/pde-sync.bundle" < "$tmp"
	vm_ssh "set -e
		cd $REMOTE_REPO
		if ! git diff --quiet || ! git diff --cached --quiet; then
			echo 'the VM checkout has local changes; not overwriting them' >&2; exit 1
		fi
		git fetch -q /tmp/pde-sync.bundle '+refs/heads/$branch:refs/remotes/lab/$branch'
		git checkout -q -B '$branch' 'refs/remotes/lab/$branch'
		rm -f /tmp/pde-sync.bundle
		echo \"VM checkout now $branch @ \$(git log --oneline -1)\"
		cd Fineract && docker compose -f docker-compose-fineract.yml --profile pde build -q pde-collector \
			&& echo 'collector image rebuilt'" </dev/null
}

cmd_tunnel() {
	case "${1:-up}" in
		up)
			vm_admin_tunnel_start || die "could not open the admin tunnel"
			echo "repository  http://localhost:$VM_LOCAL_REPO_PORT   (DFRAAS_URL for submit-evidence.sh)"
			echo "fineract    https://localhost:$VM_LOCAL_FINERACT_PORT/fineract-provider" ;;
		down)
			vm_tunnel_stop admin ;;
		*) die "tunnel up|down" ;;
	esac
}

cmd_seed() {
	vm_admin_tunnel_start || die "could not open the admin tunnel"
	python3 "$PDE_ROOT/Banking/fineract_seed.py" \
		--url "https://127.0.0.1:$VM_LOCAL_FINERACT_PORT/fineract-provider" \
		--out "${BANK_SEED:-$PDE_ROOT/Banking/seed.json}"
}

cmd_ssh() {
	_vm_gcloud_cmd
	exec "${VM_GCLOUD[@]}" compute ssh "$VM_USER@$VM_NAME" --zone "$VM_ZONE" --tunnel-through-iap
}

# The layer-3 tunnel device, on its own so it can be brought up and proved before a whole
# lab is built on top of it. The lab does this itself in `lab.sh up`; this is the same
# thing, standalone.
cmd_tundev() {
	[[ $EUID -eq 0 ]] || die "tundev needs root (it creates an interface): sudo ./vm.sh tundev ${1:-up}"
	case "${1:-up}" in
		up)
			vm_reachable || die "the VM is not reachable; ./vm.sh start"
			tun_up || die "could not bring the tunnel device up"
			echo "tunnel      $TUN_LOCAL_IP -> $TUN_VM_IP on $TUN_DEV"
			echo "the bank    users reach it at $TUN_VM_IP:$BANK_PORT once the relay is up"
			echo "relay       sudo ./vm.sh tundev relay" ;;
		down)   tun_down ;;
		status) tun_status ;;
		relay)
			vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" relay-up \
				'$BANK_RELAY_LISTEN_IP' '$BANK_PORT' '$BANK_RELAY_TARGET'" </dev/null ;;
		*) die "tundev up|down|status|relay" ;;
	esac
}

# tundev is the one subcommand that must be root: it makes an interface, sets a sysctl and
# adds routes. Everything gcloud does underneath it is still handed back to the invoking
# user by vm-lib.sh, so the credential is still read from that user's home and never root's.
case "${1:-status}" in
	tundev) ;;
	*) [[ $EUID -ne 0 ]] || die "run as yourself, not root: gcloud's login lives in your home" ;;
esac

case "${1:-status}" in
	status) cmd_status ;;
	start)  cmd_start ;;
	stop)   cmd_stop ;;
	sync)   cmd_sync ;;
	tunnel) cmd_tunnel "${2:-up}" ;;
	tundev) cmd_tundev "${2:-up}" ;;
	seed)   cmd_seed ;;
	ssh)    cmd_ssh ;;
	-h|--help|help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//' ;;
	*) die "unknown command '$1' (status, start, stop, sync, tunnel, tundev, seed, ssh)" ;;
esac
