#!/usr/bin/env bash
# ==============================================================
#  PDE lab lifecycle — up, down, status.
#
#  Brings up the standing infrastructure a capture is taken
#  against: the client topology, the firewall, and the IDS. All
#  three then stay running across as many windows as you like,
#  which is how a bank actually runs them, and which means the
#  IDS pays its ~50s of startup once rather than per capture.
#
#  Captures are taken by Firewall/simulate-firewall.sh, which
#  detects a running lab and uses it instead of building its own.
#
#    sudo ./lab.sh up --with-ids
#    sudo Firewall/simulate-firewall.sh          # window 1
#    sudo Firewall/simulate-firewall.sh          # window 2
#    sudo ./lab.sh down
#
#  IMPORTANT: in the default mode, while the lab is up YOUR
#  firewall is enabled with test rules. `down` puts it back, and
#  `status` detects a session that did not survive a reboot.
#  --via-tunnel does not touch it at all.
#
#  The default mode needs no cloud at all: the users, the
#  firewall (this machine's ufw), the IDS (Slips in Docker) and
#  the bank's public web site all run here. So can the bank:
#    --local-bank     Fineract in Docker on this machine
#                     (Banking/local-bank.sh; started and seeded
#                     on first use), reached by the users through
#                     a relay on HOST_IP:BANK_PORT
#
#  Two sources can live on the research VM instead (Remote/):
#    --ids-remote     the IDS is a tcpdump on the veth here; each
#                     window's packets are analysed by Slips there
#    --with-banking   the bank is Fineract there, reached from the
#                     namespace through a tunnel on HOST_IP:BANK_PORT
#
#  Or the observation can move there wholesale:
#    --via-tunnel     the users stay here and keep their addresses,
#                     but reach the VM over a layer-3 tunnel device,
#                     so the VM's ufw is the firewall and Slips
#                     watches the device live. YOUR firewall is not
#                     touched at all in this mode. See Remote/TUNNEL.md.
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-config.sh
source "$PDE_ROOT/lab-config.sh"
# shellcheck source=Remote/vm-lib.sh
source "$PDE_ROOT/Remote/vm-lib.sh"
IDS_LIB="$PDE_ROOT/IDS/slips-lib.sh"
BANK_SEED="${BANK_SEED:-$PDE_ROOT/Banking/seed.json}"

WITH_IDS=0
IDS_REMOTE=0
WITH_BANKING=0
VIA_TUNNEL=0
LOCAL_BANK=0
IDS_READY_TIMEOUT=240
USERS=10

log()  { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die()  { echo "error: $*" >&2; exit 1; }

usage() {
	sed -n '3,/^# =====/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \?//'
	cat <<-EOF

	Commands:
	  up [--with-ids [--ids-remote]] [--with-banking | --local-bank] [--via-tunnel] [--users N]
	                                build the lab and leave it running
	  down                          restore the firewall and tear everything down
	  status                        report what is up, and detect a stale session

	EOF
}

lab_is_up() { [[ -f "$LAB_STATE" ]]; }

# Takes the namespace to look for rather than assuming the compiled-in default: the
# question is whether *this session's* namespace is alive, and a session may have
# recorded a different one. Checking the default would report a live lab on the strength
# of a namespace that has nothing to do with the recorded session.
netns_exists() {
	local ns="${1:-$NS}"
	ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$ns"
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------
lab_up() {
	[[ $EUID -eq 0 ]] || die "must run as root (firewall rules and network namespaces)"
	lab_is_up && die "a lab is already up — './lab.sh status', or './lab.sh down' first"
	command -v iptables >/dev/null || die "iptables not installed"
	# In tunnel mode the firewall is the VM's, so this machine needs neither ufw nor a
	# running rsyslog — and its own firewall is left completely alone.
	if [[ $VIA_TUNNEL -eq 0 ]]; then
		command -v ufw >/dev/null || die "ufw not installed"
		pgrep -x rsyslogd >/dev/null || die "rsyslogd is not running; ufw lines would not reach $UFW_LOG"
		command -v openssl >/dev/null || die "openssl not installed (the bank's web site needs a certificate)"
	fi
	# Before any rule is written: a contradiction between the port lists cannot be seen in
	# the finished dataset, only in the labels disagreeing with each other.
	lab_check_port_lists || die "the port lists contradict each other; fix lab-config.sh"

	# In tunnel mode the traffic arrives on the VM, so the IDS has to be there and watching
	# the device live. --ids-remote is the older split — sensor here, analysis there — and
	# the two cannot both be true of one lab.
	if [[ $VIA_TUNNEL -eq 1 && $IDS_REMOTE -eq 1 ]]; then
		die "--via-tunnel and --ids-remote are different designs; --via-tunnel already puts the IDS on the VM"
	fi
	if [[ $VIA_TUNNEL -eq 1 && $LOCAL_BANK -eq 1 ]]; then
		die "--via-tunnel uses the bank on the VM; --local-bank is for running without it"
	fi

	if [[ $WITH_IDS -eq 1 ]]; then
		[[ -f "$IDS_LIB" ]] || die "--with-ids needs $IDS_LIB"
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		if [[ $VIA_TUNNEL -eq 1 ]]; then
			: # checked below, once the VM has been confirmed reachable
		elif [[ $IDS_REMOTE -eq 1 ]]; then
			command -v tcpdump >/dev/null || die "--ids-remote needs tcpdump (apt install tcpdump)"
			slips_remote_preflight || die "remote IDS preflight failed"
		else
			slips_preflight || die "IDS preflight failed"
		fi
	fi

	if [[ $VIA_TUNNEL -eq 1 ]]; then
		# shellcheck source=Remote/tun-lib.sh
		source "$PDE_ROOT/Remote/tun-lib.sh"
		# shellcheck source=Remote/remote-source-lib.sh
		source "$PDE_ROOT/Remote/remote-source-lib.sh"
		vm_reachable || die "--via-tunnel needs the research VM (status: $(vm_status || echo unknown)); ./vm.sh start"
		remote_source_preflight || die "the VM cannot be read as a source"
		vm_ssh "test -f \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\"" </dev/null 2>/dev/null \
			|| die "the VM's checkout predates Remote/vm-net.sh — ./vm.sh sync"
		if [[ $WITH_IDS -eq 1 ]]; then
			vm_ssh "docker image inspect '${SLIPS_IMG:-stratosphereips/slips:v1.1.23}' >/dev/null 2>&1" </dev/null \
				|| die "the VM has no Slips image — on the VM: docker pull ${SLIPS_IMG:-stratosphereips/slips:v1.1.23}"
		fi
	fi
	if [[ $LOCAL_BANK -eq 1 ]]; then
		# The bank on this machine. Started and seeded here when it is not already, so one
		# command is enough on a fresh machine; once done, both steps are no-ops.
		BANK_SEED="$LOCAL_BANK_SEED"
		if ! local_bank_healthy; then
			log "the local bank is not up; starting it (Banking/local-bank.sh up)"
			bash "$PDE_ROOT/Banking/local-bank.sh" up || die "could not start the local bank"
		fi
		if [[ ! -r "$BANK_SEED" ]]; then
			log "the local bank has not been seeded; seeding it (Banking/local-bank.sh seed)"
			bash "$PDE_ROOT/Banking/local-bank.sh" seed || die "could not seed the local bank"
		fi
	elif [[ $WITH_BANKING -eq 1 ]]; then
		[[ -r "$BANK_SEED" ]] || die "--with-banking needs a seeded bank ($BANK_SEED); see Banking/README.md"
		vm_reachable || die "--with-banking needs the research VM (status: $(vm_status || echo unknown)); ./vm.sh start, or use --local-bank"
	fi

	modprobe xt_LOG 2>/dev/null || true
	modprobe nf_log_syslog 2>/dev/null || true

	mkdir -p "$LAB_DIR"

	# --- snapshot before touching anything -----------------------------------
	# Only in the local mode. In tunnel mode this host's firewall is not in the path and is
	# never touched, so there is nothing to snapshot and nothing that could be left behind —
	# the failure mode the whole restore mechanism exists for cannot occur.
	local orig_enabled orig_loglevel
	if [[ $VIA_TUNNEL -eq 1 ]]; then
		orig_enabled="untouched"
		orig_loglevel="untouched"
	else
		orig_enabled=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf | cut -d= -f2)
		orig_loglevel=$(grep -E '^LOGLEVEL=' /etc/ufw/ufw.conf | cut -d= -f2)
		cp -a /etc/ufw/user.rules "$LAB_DIR/user.rules.bak"
		cp -a /etc/ufw/user6.rules "$LAB_DIR/user6.rules.bak"
	fi

	# Written before the changes are made, not after. If this script dies halfway
	# through the setup, `down` still has everything it needs to undo the parts that
	# did land — a state file written at the end would be missing precisely when a
	# failure made it necessary.
	local lab_stamp; lab_stamp=$(date -u +%Y%m%d%H%M%S)
	# Every value is quoted. This file is sourced, and the repo path contains a space
	# ("PDE Sources"), so an unquoted LAB_SLIPS_OUT parses as an assignment followed by
	# a command — bash then reports "Sources/output/...: No such file or directory" from
	# a file that merely looks like configuration.
	cat > "$LAB_STATE" <<-EOF
	# PDE lab session state. Written by lab.sh up; consumed by lab.sh down and by
	# simulate-firewall.sh. Deleting this by hand orphans the firewall changes.
	LAB_STAMP="$lab_stamp"
	LAB_STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	LAB_WITH_IDS="$WITH_IDS"
	LAB_IDS_MODE="$([[ $IDS_REMOTE -eq 1 ]] && echo remote || echo local)"
	LAB_WITH_BANKING="$WITH_BANKING"
	LAB_VIA_TUNNEL="$VIA_TUNNEL"
	LAB_BANK_WHERE="$([[ $LOCAL_BANK -eq 1 ]] && echo local || echo vm)"
	LAB_BANK_SEED="$BANK_SEED"
	LAB_TUN_DEV="$TUN_DEV"
	LAB_TUN_VM_IP="$TUN_VM_IP"
	LAB_TARGET_IP="$([[ $VIA_TUNNEL -eq 1 ]] && echo "$TUN_VM_IP" || echo "$HOST_IP")"
	LAB_USERS="$USERS"
	LAB_ORIG_ENABLED="$orig_enabled"
	LAB_ORIG_LOGLEVEL="$orig_loglevel"
	LAB_NS="$NS"
	LAB_VETH_HOST="$VETH_HOST"
	LAB_SUBNET="$SUBNET"
	LAB_HOST_IP="$HOST_IP"
	LAB_SLIPS_OUT="$PDE_ROOT/output/sessions/ids-$lab_stamp"
	EOF
	log "state recorded in $LAB_STATE (ufw was ENABLED=$orig_enabled LOGLEVEL=$orig_loglevel)"

	# --- topology -------------------------------------------------------------
	log "creating namespace $NS with $USERS user addresses"
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true
	ip netns add "$NS"
	ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
	ip link set "$VETH_NS" netns "$NS"
	ip addr add "$HOST_IP/24" dev "$VETH_HOST"
	ip link set "$VETH_HOST" up
	ip netns exec "$NS" ip link set lo up
	local i
	for ((i = 1; i <= USERS; i++)); do
		ip netns exec "$NS" ip addr add "${USER_IP_BASE}$((USER_IP_OFFSET + i))/24" dev "$VETH_NS"
	done
	ip netns exec "$NS" ip link set "$VETH_NS" up

	# --- the tunnel, and everything the users now talk to on the far side ------
	#
	# Built after the namespace, because the route the users need is added inside it, and
	# before anything on the VM is bound to the tunnel address, which does not exist until
	# the device is up. Recorded before each step rather than after, so `down` can undo
	# whatever did land if a later step fails.
	if [[ $VIA_TUNNEL -eq 1 ]]; then
		log "opening the tunnel device $TUN_LOCAL_IP -> $TUN_VM_IP ($TUN_DEV) over IAP"
		echo 'LAB_TUNNEL="1"' >> "$LAB_STATE"
		tun_up "$NS" || die "could not bring the tunnel device up"

		echo 'LAB_VM_SERVICES="1"' >> "$LAB_STATE"
		log "starting the alert listener on $VM_NAME at $TUN_VM_IP ports $ALERT_PORTS"
		vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" listener-up \
			'$TUN_VM_IP' '$ALERT_PORTS'" </dev/null || die "could not start the alert listener on the VM"

		log "starting the bank's public web front on $VM_NAME at $TUN_VM_IP (http $WEB_HTTP_PORTS, https $WEB_HTTPS_PORTS)"
		vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" web-up \
			'$TUN_VM_IP' '$WEB_HTTP_PORTS' '$WEB_HTTPS_PORTS'" </dev/null || die "could not start the web front on the VM"

		if [[ $WITH_BANKING -eq 1 ]]; then
			log "starting the bank relay on $VM_NAME at $TUN_VM_IP:$BANK_PORT"
			vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" relay-up \
				'$BANK_RELAY_LISTEN_IP' '$BANK_PORT' '$BANK_RELAY_TARGET'" </dev/null \
				|| die "could not start the bank relay on the VM"
		fi
		cat >> "$LAB_STATE" <<-EOF
		LAB_ALERT_PORTS="$ALERT_PORTS"
		EOF
	else
		# --- listener behind the alert ports ----------------------------------
		# Bound to the host address, so it can only start once the veth carries it. Recorded
		# in the state file immediately: it runs in the root namespace, so deleting the
		# namespace would not stop it, and `down` must be able to find it even if setup
		# fails after this.
		log "starting the alert listener on $HOST_IP ports $ALERT_PORTS"
		local listener_pid
		listener_pid=$(alert_listener_start "$HOST_IP" "$LAB_DIR/alert-listener.pid" "$LAB_DIR/alert-listener.log") \
			|| die "could not start the alert listener"
		cat >> "$LAB_STATE" <<-EOF
		LAB_LISTENER_PID="$listener_pid"
		LAB_ALERT_PORTS="$ALERT_PORTS"
		EOF

		# --- the bank's public web site ---------------------------------------
		# What the honest customers browse: real pages over HTTP and HTTPS on the benign ports,
		# so their traffic is ordinary web traffic rather than connections to closed ports,
		# which a flow-based IDS cannot tell from a scan. The same site the VM serves.
		log "starting the bank's public web site on $HOST_IP (http $WEB_HTTP_PORTS, https $WEB_HTTPS_PORTS)"
		local web_pid
		web_pid=$(web_front_start "$HOST_IP" "$LAB_DIR/web-front.pid" "$LAB_DIR/web-front.log" "$LAB_DIR/web-tls") \
			|| die "could not start the bank's web site"
		echo "LAB_WEB_PID=\"$web_pid\"" >> "$LAB_STATE"
	fi

	# --- IDS, before the firewall --------------------------------------------
	if [[ $WITH_IDS -eq 1 && $VIA_TUNNEL -eq 1 ]]; then
		# Live on the device, on the VM. This is the mode the lab had before the IDS was
		# split, and the better one: Slips watches an interface continuously and its
		# per-source profile carries across windows, where file-mode analysis starts fresh
		# each window and can never accumulate. It reuses the VM's standing redis, so it
		# inherits the warm threat-intel cache instead of refetching ~45 feeds.
		local vm_slips_sub="pde-slips/live-$lab_stamp"
		# Wait for the background threat-intel warm-up to finish first. It is itself a Slips
		# run, and two of them saturate this VM's four vCPUs: measured load 4.0+, which broke
		# the SSH/IAP handshake and took out the lab's only way in mid-setup. Warming is
		# normally over well before this, so this usually returns at once.
		local warm_waited=0 warm_state=""
		while [[ $warm_waited -lt 600 ]]; do
			warm_state=$(vm_ssh "bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/slips-warm.sh\" status" 				</dev/null 2>/dev/null | tr -d '
' | head -1)
			[[ "$warm_state" != "warming" ]] && break
			[[ $warm_waited -eq 0 ]] && log "the VM is still warming Slips' feed cache; waiting (two Slips runs overload it)"
			sleep 15; warm_waited=$((warm_waited + 15))
		done
		[[ "$warm_state" == "warming" ]] && die "the VM is still warming Slips' cache after ${warm_waited}s; try again shortly"
		log "starting Slips on $VM_NAME, reading $TUN_DEV (loading modules and feeds)"
		echo "LAB_VM_SLIPS_SUB=\"$vm_slips_sub\"" >> "$LAB_STATE"
		vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" slips-up \
			'$TUN_DEV' '$VM_USER' '$vm_slips_sub' '$BANK_PORT'" </dev/null || die "could not start Slips on the VM"
		vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" slips-ready \
			'$IDS_READY_TIMEOUT'" </dev/null || die "Slips on the VM never became ready"
		local vm_slips_out
		vm_slips_out=$(vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" slips-outdir" \
			</dev/null | tr -d '\r' | head -1)
		[[ -n "$vm_slips_out" ]] || die "Slips is up on the VM but did not report its output directory"
		cat >> "$LAB_STATE" <<-EOF
		LAB_VM_SLIPS_OUT="$vm_slips_out"
		EOF
		log "Slips is reading $TUN_DEV on $VM_NAME (output $vm_slips_out)"
	elif [[ $WITH_IDS -eq 1 && $IDS_REMOTE -eq 1 ]]; then
		# The sensor stays here, the analysis goes to the VM: tcpdump writes the veth for
		# the whole session, and each capture slices its window out and ships it.
		local slips_out="$PDE_ROOT/output/sessions/ids-$lab_stamp"
		local tcpdump_pid
		log "capturing $VETH_HOST to $slips_out/veth.pcap (analysed per window by Slips on $VM_NAME)"
		tcpdump_pid=$(pcap_capture_start "$VETH_HOST" "$slips_out/veth.pcap" "$LAB_DIR/tcpdump.log") \
			|| die "could not start the packet capture"
		cat >> "$LAB_STATE" <<-EOF
		LAB_TCPDUMP_PID="$tcpdump_pid"
		LAB_PCAP="$slips_out/veth.pcap"
		EOF
	elif [[ $WITH_IDS -eq 1 ]]; then
		local slips_out="$PDE_ROOT/output/sessions/ids-$lab_stamp"
		mkdir -p "$slips_out"
		log "starting Slips on $VETH_HOST (loading modules and threat-intel feeds)"
		slips_start_redis || die "could not start the Slips redis"
		slips_start "$VETH_HOST" "$slips_out" "$BANK_PORT" || die "could not start Slips"
		slips_wait_ready "$IDS_READY_TIMEOUT" || die "Slips never became ready"
		log "Slips is reading $VETH_HOST"
	fi

	# --- the bank, on the host side of the veth ------------------------------
	# Bound to HOST_IP, so it can only open once the veth carries that address. A simulated
	# user reaching https://HOST_IP:BANK_PORT crosses this host's INPUT chain — ufw logs it —
	# and the tunnel carries it on to Fineract on the VM.
	# In tunnel mode the bank is already reachable: the relay above listens on the tunnel
	# address, which is where the users aim, and the port forward this block opens would be
	# a second, unused path to the same service.
	#
	# With --local-bank the bank is on this machine, published on the loopback only, and a relay
	# bound to HOST_IP does the same job: the user's call ends on this host's INPUT chain, where
	# ufw logs it, and the relay opens its own connection on to Fineract.
	if [[ $LOCAL_BANK -eq 1 ]]; then
		log "starting the bank relay $HOST_IP:$BANK_PORT -> the local bank at $LOCAL_BANK_TARGET"
		local relay_pid
		relay_pid=$(bank_relay_start "$HOST_IP:$BANK_PORT" "$LOCAL_BANK_TARGET" \
			"$LAB_DIR/bank-relay.pid" "$LAB_DIR/bank-relay.log") || die "could not start the bank relay"
		echo "LAB_BANK_RELAY_PID=\"$relay_pid\"" >> "$LAB_STATE"
	elif [[ $WITH_BANKING -eq 1 && $VIA_TUNNEL -eq 0 ]]; then
		log "opening the bank tunnel $HOST_IP:$BANK_PORT -> $VM_NAME:8443"
		vm_bank_tunnel_start || die "could not open the bank tunnel"
		echo 'LAB_BANK_TUNNEL="1"' >> "$LAB_STATE"
	fi

	# --- firewall -------------------------------------------------------------
	#
	# In tunnel mode it is the VM's, because the packets now cross the VM's INPUT chain and
	# this host only forwards them. The same rule set and the same unrate-limited verdict
	# LOG rules, scoped to what arrives on the tunnel device so nothing else on the VM is
	# logged into the evidence.
	#
	# firewall-up arms a watchdog that disables ufw again unless it is confirmed; the
	# confirmation is an SSH round trip that only succeeds if the rules did not lock us out.
	if [[ $VIA_TUNNEL -eq 1 ]]; then
		log "configuring ufw on $VM_NAME (logging low; verdict rules log every lab connection attempt on $TUN_DEV)"
		echo 'LAB_VM_FIREWALL="1"' >> "$LAB_STATE"
		vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" firewall-up \
			'$SUBNET' '$ALLOWED_PORTS' '$TUN_NUM'" </dev/null || die "could not configure ufw on the VM"
		# Proof the firewall did not cut the only way in, before the watchdog is cancelled.
		if vm_ssh true </dev/null >/dev/null 2>&1; then
			vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" firewall-keep" </dev/null \
				|| die "the VM's firewall is up but the watchdog could not be cancelled"
		else
			die "the VM stopped answering after its firewall came up; the watchdog will disable it shortly"
		fi
		# The tunnel itself must still carry traffic with the firewall in place — the rules
		# are scoped to the device, so a mistake in them shows up here and nowhere else.
		ping -c1 -W2 -I "$TUN_DEV" "$TUN_VM_IP" >/dev/null 2>&1 \
			|| die "the VM's firewall is up but $TUN_VM_IP no longer answers over $TUN_DEV"
		log "lab up (this machine's firewall was not touched)"
		echo
		echo "  The firewall evidence is ufw on $VM_NAME, not this machine."
		echo "  Capture windows with:  sudo Firewall/simulate-firewall.sh"
		echo "  Tear it down with:     sudo ./lab.sh down"
		return 0
	fi

	# Order carries the labelling. PRESERVE_PORTS overlaps MALICIOUS_PORTS (22, 5432);
	# if the preserve rules came first they would match the simulated attacker too and
	# those attempts would be logged as permitted. Subnet rules are scoped and go
	# first, so the host-wide rules can only ever match traffic from somewhere else.
	log "configuring ufw (logging low; the lab's verdict rules log every connection the users attempt)"
	local p
	IFS=',' read -ra _benign <<< "$BENIGN_PORTS"
	for p in "${_benign[@]}"; do
		ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
	done
	# Permitted as well: the guaranteed-alert profile needs its connections to complete,
	# and a denied SYN never does.
	IFS=',' read -ra _alert <<< "$ALERT_PORTS"
	for p in "${_alert[@]}"; do
		ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
	done
	# The bank's port is in ALLOWED_PORTS, so the verdict rules label it ALLOW whether or
	# not banking is on; permitting it always keeps the label and the rule in agreement.
	ufw allow from "$SUBNET" to any port "$BANK_PORT" proto tcp >/dev/null
	ufw deny from "$SUBNET" >/dev/null
	IFS=',' read -ra _preserve <<< "$PRESERVE_PORTS"
	for p in "${_preserve[@]}"; do
		ufw allow "$p/tcp" >/dev/null
	done
	# 'low', not 'full'. The evidence is the verdict rules below, which log every connection
	# attempt from the lab's subnet whatever ufw's own level is. 'full' adds a line for every packet this
	# machine handles — a local bank's Docker traffic included — and at that volume the
	# kernel's log buffer overflows and lines are lost; on the research VM it cost windows
	# thousands of lines before the level was lowered.
	ufw logging low >/dev/null
	ufw --force enable >/dev/null

	# Verdict logging installed directly: ufw hardcodes -m limit --limit 3/min
	# --limit-burst 10 onto every rule created with its `log` keyword, with no
	# loglevel check, which caps a window at ~11 verdict lines per rule however much
	# traffic crosses. Same kernel target, same prefixes, no rate limit. Removed when
	# ufw reloads on `down`.
	# ALLOWED_PORTS, not BENIGN_PORTS: the alert ports are permitted too, and the BLOCK rule
	# below is "everything else", so leaving them out would label permitted traffic BLOCK.
	iptables -I ufw-user-input 1 -s "$SUBNET" -p tcp -m multiport --dports "$ALLOWED_PORTS" \
		-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
	iptables -I ufw-user-input 2 -s "$SUBNET" -p tcp -m multiport ! --dports "$ALLOWED_PORTS" \
		-j LOG --log-prefix "[UFW BLOCK] " --log-level 4

	log "lab up"
	echo
	echo "  Your firewall is now ENABLED with test rules (logging low)."
	if [[ $LOCAL_BANK -eq 1 ]]; then echo "  The bank runs on this machine: Banking/local-bank.sh status"; fi
	echo "  Capture windows with:  sudo Firewall/simulate-firewall.sh"
	echo "  Put it back with:      sudo ./lab.sh down"
}

# ---------------------------------------------------------------------------
# down
# ---------------------------------------------------------------------------
lab_down() {
	[[ $EUID -eq 0 ]] || die "must run as root"
	lab_is_up || die "no lab session recorded ($LAB_STATE missing)"

	# Parsed, not sourced — see lab_get. Everything below also tolerates a missing or
	# damaged value and falls back to the compiled-in default, because a half-written
	# state file must still be enough to put the firewall back.
	local LAB_WITH_IDS LAB_NS LAB_VETH_HOST LAB_ORIG_ENABLED LAB_ORIG_LOGLEVEL LAB_SLIPS_OUT
	LAB_WITH_IDS=$(lab_get LAB_WITH_IDS 0)
	LAB_NS=$(lab_get LAB_NS "$NS")
	LAB_VETH_HOST=$(lab_get LAB_VETH_HOST "$VETH_HOST")
	LAB_ORIG_ENABLED=$(lab_get LAB_ORIG_ENABLED no)
	LAB_ORIG_LOGLEVEL=$(lab_get LAB_ORIG_LOGLEVEL low)
	LAB_SLIPS_OUT=$(lab_get LAB_SLIPS_OUT "")

	local LAB_VIA_TUNNEL; LAB_VIA_TUNNEL=$(lab_get LAB_VIA_TUNNEL 0)
	# Read now: the state file is gone by the time the closing note is printed.
	local local_bank=0
	[[ "$(lab_get LAB_BANK_WHERE vm)" == "local" && "$(lab_get LAB_WITH_BANKING 0)" == "1" ]] && local_bank=1

	# --- the VM's side, and the tunnel, first ---------------------------------
	# Everything here is best effort: the VM may already have been stopped, in which case its
	# services went with it, and a lab that cannot reach it must still be able to tear down
	# this machine's namespace and routes.
	if [[ "$LAB_VIA_TUNNEL" == "1" ]]; then
		# shellcheck source=Remote/tun-lib.sh
		source "$PDE_ROOT/Remote/tun-lib.sh"
		if [[ "$(lab_get LAB_VM_SERVICES 0)" == "1" ]] && vm_reachable; then
			log "stopping the VM's lab services"
			local vmnet="\"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\""
			[[ "$(lab_get LAB_WITH_IDS 0)" -eq 1 ]] && \
				vm_ssh "sudo bash $vmnet slips-down" </dev/null >/dev/null 2>&1 || true
			vm_ssh "sudo bash $vmnet listener-down" </dev/null >/dev/null 2>&1 || true
			vm_ssh "sudo bash $vmnet web-down"      </dev/null >/dev/null 2>&1 || true
			vm_ssh "sudo bash $vmnet relay-down"    </dev/null >/dev/null 2>&1 || true
			if [[ "$(lab_get LAB_VM_FIREWALL 0)" == "1" ]]; then
				log "restoring the VM's firewall"
				vm_ssh "sudo bash $vmnet firewall-down" </dev/null >/dev/null 2>&1 || true
			fi
		elif [[ "$(lab_get LAB_VM_SERVICES 0)" == "1" ]]; then
			echo "note: the VM is not reachable; its ufw and lab services were left as they are." >&2
			echo "      They go with the VM when it stops, and 'vm-net.sh firewall-down' undoes the rest." >&2
		fi
		log "closing the tunnel device"
		tun_down
	fi

	# In the root namespace, so tearing the namespace down below would not stop it.
	if [[ "$LAB_VIA_TUNNEL" != "1" ]]; then
		log "stopping the alert listener"
		alert_listener_stop "$(lab_get LAB_LISTENER_PID "")"
		rm -f "$LAB_DIR/alert-listener.pid"
		log "stopping the bank's web site"
		web_front_stop "$(lab_get LAB_WEB_PID "")"
		rm -f "$LAB_DIR/web-front.pid"
		if [[ $local_bank -eq 1 ]]; then
			log "stopping the bank relay"
			bank_relay_stop "$(lab_get LAB_BANK_RELAY_PID "")"
			rm -f "$LAB_DIR/bank-relay.pid"
		fi
	fi

	# The bank tunnel is bound to the veth's address; closed before that address goes.
	if [[ "$(lab_get LAB_BANK_TUNNEL 0)" == "1" ]] || vm_tunnel_running bank; then
		log "closing the bank tunnel"
		vm_tunnel_stop bank
	fi

	# Not in tunnel mode: Slips ran on the VM and was stopped there above. Calling the local
	# stop would look for containers on this machine that never existed.
	if [[ "${LAB_WITH_IDS:-0}" -eq 1 && -f "$IDS_LIB" && "$LAB_VIA_TUNNEL" != "1" ]]; then
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		if [[ "$(lab_get LAB_IDS_MODE local)" == "remote" ]]; then
			log "stopping the packet capture"
			pcap_capture_stop "$(lab_get LAB_TCPDUMP_PID "")"
		else
			log "stopping Slips"
			slips_stop
		fi
	fi

	log "tearing down namespace ${LAB_NS:-$NS}"
	ip netns pids "${LAB_NS:-$NS}" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "${LAB_NS:-$NS}" 2>/dev/null || true
	ip link del "${LAB_VETH_HOST:-$VETH_HOST}" 2>/dev/null || true

	# Only if this machine's firewall was the one in the path. In tunnel mode nothing here
	# was ever changed, and running the restore anyway would be actively harmful: the
	# recorded value is the sentinel "untouched", which is not "no", so the branch below
	# would ENABLE a firewall the lab never enabled.
	if [[ "$LAB_VIA_TUNNEL" != "1" ]]; then
		log "restoring firewall"
		cp -a "$LAB_DIR/user.rules.bak" /etc/ufw/user.rules 2>/dev/null || true
		cp -a "$LAB_DIR/user6.rules.bak" /etc/ufw/user6.rules 2>/dev/null || true
		ufw logging "${LAB_ORIG_LOGLEVEL:-low}" >/dev/null 2>&1 || true
		if [[ "${LAB_ORIG_ENABLED:-no}" == "no" ]]; then
			ufw --force disable >/dev/null 2>&1 || true
		else
			ufw --force enable >/dev/null 2>&1 || true
		fi
	fi

	if [[ -n "${SUDO_USER:-}" && -d "${LAB_SLIPS_OUT:-}" ]]; then
		chown -R "$SUDO_USER" "$LAB_SLIPS_OUT" 2>/dev/null || true
	fi

	rm -f "$LAB_STATE" "$LAB_DIR/user.rules.bak" "$LAB_DIR/user6.rules.bak"
	if [[ "$LAB_VIA_TUNNEL" == "1" ]]; then
		log "this machine's firewall was never touched; nothing to restore"
	else
		log "firewall restored to ENABLED=${LAB_ORIG_ENABLED:-no} LOGLEVEL=${LAB_ORIG_LOGLEVEL:-low}"
	fi
	[[ -n "${LAB_SLIPS_OUT:-}" ]] && echo "  Slips session output kept: $LAB_SLIPS_OUT"
	if [[ $local_bank -eq 1 ]]; then
		# Left running on purpose: it takes minutes to start, and its database is the seed's.
		echo "  The local bank is still running; Banking/local-bank.sh stop stops it, keeping its data."
	fi
	return 0
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
lab_status() {
	if ! lab_is_up; then
		echo "lab: down"
		local enabled; enabled=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null | cut -d= -f2)
		if [[ "$enabled" == "yes" ]]; then
			echo "note: ufw is enabled, but not by a lab session — left alone."
		fi
		return 0
	fi

	local started ns
	started=$(lab_get LAB_STARTED_UTC "?")
	ns=$(lab_get LAB_NS "$NS")
	if netns_exists "$ns"; then
		echo "lab: UP since $started"
		echo "  namespace   $ns ($(lab_get LAB_USERS "?") users)"
		if [[ "$(lab_get LAB_VIA_TUNNEL 0)" == "1" ]]; then
			echo "  mode        via the tunnel device — the VM observes, this machine forwards"
			echo "  target      users reach $(lab_get LAB_TARGET_IP "?"); this machine's firewall untouched"
			# shellcheck source=Remote/tun-lib.sh
			source "$PDE_ROOT/Remote/tun-lib.sh"
			if tun_session_running; then
				echo "  tunnel      $(lab_get LAB_TUN_DEV "$TUN_DEV") up to $VM_NAME"
			else
				echo "  tunnel      DOWN — windows would capture nothing; restart the lab"
			fi
			echo "  firewall    ufw on $VM_NAME, verdict rules on $(lab_get LAB_TUN_DEV "$TUN_DEV")"
		else
			echo "  firewall    ufw enabled with test rules, logging low"
		fi
		if [[ "$(lab_get LAB_WITH_IDS 0)" -ne 1 ]]; then
			echo "  ids         not running"
		elif [[ "$(lab_get LAB_VIA_TUNNEL 0)" == "1" ]]; then
			echo "  ids         slips on $VM_NAME, live on $(lab_get LAB_TUN_DEV "$TUN_DEV")"
		elif [[ "$(lab_get LAB_IDS_MODE local)" == "remote" ]]; then
			local tpid; tpid=$(lab_get LAB_TCPDUMP_PID "")
			if [[ -n "$tpid" && -d "/proc/$tpid" ]]; then
				echo "  ids         capturing $(lab_get LAB_VETH_HOST "$VETH_HOST") (pid $tpid); Slips on $VM_NAME per window"
			else
				echo "  ids         capture NOT running — windows would have no packets for Slips"
			fi
		else
			echo "  ids         slips on $(lab_get LAB_VETH_HOST "$VETH_HOST")"
		fi
		if [[ "$(lab_get LAB_WITH_BANKING 0)" -eq 1 && "$(lab_get LAB_BANK_WHERE vm)" == "local" ]]; then
			if helper_alive "$(lab_get LAB_BANK_RELAY_PID "")" "Remote/bank-relay.py"; then
				echo "  bank        relay $HOST_IP:$BANK_PORT -> the local bank ($(local_bank_state || true))"
			else
				echo "  bank        relay NOT running — banking windows will fail; restart the lab"
			fi
		elif [[ "$(lab_get LAB_WITH_BANKING 0)" -eq 1 ]]; then
			if vm_tunnel_running bank; then
				echo "  bank        tunnel $HOST_IP:$BANK_PORT -> $VM_NAME (Fineract)"
			else
				echo "  bank        tunnel DOWN — banking windows will fail; restart the lab"
			fi
		fi
		if [[ "$(lab_get LAB_VIA_TUNNEL 0)" != "1" ]]; then
			if helper_alive "$(lab_get LAB_WEB_PID "")" "Firewall/benign_web.py"; then
				echo "  web site    $HOST_IP ports $BENIGN_PORTS (pid $(lab_get LAB_WEB_PID ""))"
			else
				echo "  web site    NOT running — the customers' page loads will fail; restart the lab"
			fi
		fi
		local lpid; lpid=$(lab_get LAB_LISTENER_PID "")
		if [[ -n "$lpid" && -d "/proc/$lpid" ]]; then
			echo "  listener    ports $(lab_get LAB_ALERT_PORTS "?") on $HOST_IP (pid $lpid)"
		else
			echo "  listener    not running — guaranteed-alert connections will not complete"
		fi
		echo "  restores to ENABLED=$(lab_get LAB_ORIG_ENABLED "?") LOGLEVEL=$(lab_get LAB_ORIG_LOGLEVEL "?")"
		return 0
	fi

	# State recorded but the namespace is gone: the session did not survive. A reboot
	# is the usual cause, and it matters because ufw.service is enabled — the firewall
	# comes back up on boot still carrying the test rules, with nothing running that
	# would put it back.
	echo "lab: STALE"
	echo "  A session was recorded at $started but its namespace is gone,"
	echo "  most likely a reboot or 'wsl --shutdown'."
	echo
	echo "  Your firewall may still be enabled with the test rules on it."
	echo "  Recover with:  sudo ./lab.sh down"
	return 2
}

# ---------------------------------------------------------------------------
cmd="${1:-}"
[[ $# -gt 0 ]] && shift
while [[ $# -gt 0 ]]; do
	case "$1" in
		--with-ids) WITH_IDS=1; shift ;;
		--ids-remote) IDS_REMOTE=1; shift ;;
		--with-banking) WITH_BANKING=1; shift ;;
		--local-bank) LOCAL_BANK=1; WITH_BANKING=1; shift ;;
		--via-tunnel) VIA_TUNNEL=1; shift ;;
		--users) USERS="$2"; shift 2 ;;
		*) die "unknown option '$1'" ;;
	esac
done

case "$cmd" in
	up)     lab_up ;;
	down)   lab_down ;;
	status) lab_status ;;
	-h|--help|help|"") usage ;;
	*) die "unknown command '$cmd' (try: up, down, status)" ;;
esac
