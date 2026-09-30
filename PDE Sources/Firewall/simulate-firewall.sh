#!/usr/bin/env bash
#
# Ubuntu Firewall (ufw) PDE source simulator.
#
# Produces a genuine ufw log file for a controlled traffic scenario. Nothing about the
# log format is authored here: real packets cross the real INPUT chain and the kernel's
# netfilter LOG target writes the lines. What this script controls is the experiment —
# how many users, for how long, and what fraction of them behave maliciously.
#
# Requires root (it manipulates the firewall and creates a network namespace) and puts
# the host firewall back exactly as it found it on exit, including on Ctrl-C.
#
#   sudo ./simulate-firewall.sh --users 10 --duration 30 --malicious-pct 10
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USERS=10
DURATION=30
RATE=20
MALICIOUS_PCT=10
MALICIOUS_USERS=1
ATTACK_PROFILE=port-scan
SEED=1337
OUTDIR="$SCRIPT_DIR/../output"
DRY_RUN=0
KEEP_FIREWALL=0

# IDS correlation. When enabled, Slips sniffs the veth this script creates, so both
# sources observe the same packets over the same window.
WITH_IDS=0
IDS_READY_TIMEOUT=240
# Slips raises evidence in batches after it has seen the flows, so stopping it the
# instant the window closes reliably collects nothing. This is how long to keep it
# running past the window before collecting.
IDS_DRAIN=45

# Topology, port lists and lab paths live in one place so this script and lab.sh cannot
# drift apart on them — see the note there about why the port lists interact.
PDE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../lab-config.sh
source "$PDE_ROOT/lab-config.sh"

# A lab left running by lab.sh owns the topology, the firewall and the IDS. This script
# then only takes a window against it: no setup, no teardown, and crucially no restoring
# a firewall it did not configure. With no lab up it does the whole thing itself, which
# keeps the one-shot path — and its exit trap — exactly as it was.
LAB_MODE=0
LAB_WITH_IDS=0
LAB_IDS_MODE=local
LAB_PCAP=""
LAB_WITH_BANKING=0
LAB_SLIPS_OUT=""
LAB_USERS=0
LAB_STARTED_UTC=""
LAB_NS="$NS"
LAB_VETH_HOST="$VETH_HOST"
# Tunnel mode: the users stay here but everything that observes them is on the VM, so the
# firewall log, the IDS and the sessions' own authentication record are all read from there.
# TARGET_IP is what the generators aim at, and it is the one value that changes the traffic
# itself rather than only where it is collected from.
LAB_VIA_TUNNEL=0
LAB_VM_SLIPS_OUT=""
TARGET_IP="$HOST_IP"
if [[ -f "$LAB_STATE" ]]; then
	# Parsed rather than sourced — see lab_get in lab-config.sh.
	LAB_NS=$(lab_get LAB_NS "$NS")
	if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$LAB_NS"; then
		LAB_MODE=1
		LAB_WITH_IDS=$(lab_get LAB_WITH_IDS 0)
		LAB_IDS_MODE=$(lab_get LAB_IDS_MODE local)
		LAB_PCAP=$(lab_get LAB_PCAP "")
		LAB_WITH_BANKING=$(lab_get LAB_WITH_BANKING 0)
		LAB_SLIPS_OUT=$(lab_get LAB_SLIPS_OUT "")
		LAB_USERS=$(lab_get LAB_USERS 0)
		LAB_STARTED_UTC=$(lab_get LAB_STARTED_UTC "?")
		LAB_VETH_HOST=$(lab_get LAB_VETH_HOST "$VETH_HOST")
		LAB_VIA_TUNNEL=$(lab_get LAB_VIA_TUNNEL 0)
		LAB_VM_SLIPS_OUT=$(lab_get LAB_VM_SLIPS_OUT "")
		TARGET_IP=$(lab_get LAB_TARGET_IP "$HOST_IP")
	fi
fi

# The banking source: the bank's audit trail and its event stream over the same window,
# driven by generate_banking.py alongside the network traffic. Lab-only — the bank lives
# on the research VM, and only a lab holds the tunnel that reaches it.
WITH_BANKING=0
BANK_RATE=0.5
BANK_PROFILE=loan-fraud

usage() {
	sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Options:
	  --users N              simulated users, one source IP each   (default $USERS)
	  --duration S           capture window in seconds             (default $DURATION)
	  --rate R               connection attempts per second        (default $RATE)
	  --malicious-pct P      share of *events* that are malicious  (default $MALICIOUS_PCT)
	  --malicious-users N    how many *users* are attackers        (default $MALICIOUS_USERS)
	  --attack-profile P     attacker behaviour                    (default $ATTACK_PROFILE)
	                         port-scan|brute-force|db-probe|stealth|syn-burst|mixed|guaranteed-alert
	  --seed N               makes a run reproducible              (default $SEED)
	  --outdir DIR           where the log and manifest land       (default $OUTDIR)
	  --dry-run              print the firewall changes and exit
	  --keep-firewall        skip teardown (debugging only)
	  --with-ids             also run Slips on the veth, so the IDS observes the
	                         same packets over the same window (adds ~2 min of
	                         startup before the window, and --ids-drain after)
	  --ids-drain S          seconds to keep Slips running past the window so it
	                         can raise evidence for it       (default $IDS_DRAIN)
	  --with-banking         also drive the bank and collect its audit trail and
	                         event stream for the window (needs a lab started
	                         with --with-banking; the bank is on the research VM)
	  --bank-rate R          benign banking operations per second (default $BANK_RATE)
	  --bank-profile P       loan-fraud|none                  (default $BANK_PROFILE)

	Note that --malicious-pct and --malicious-users are independent knobs. "10%" of
	events and a 10:1 user ratio are not the same statement, and a brief should say
	which one it means: 10:1 users is 9.09% of users, not 10%.
	EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--users) USERS="$2"; shift 2 ;;
		--duration) DURATION="$2"; shift 2 ;;
		--rate) RATE="$2"; shift 2 ;;
		--malicious-pct) MALICIOUS_PCT="$2"; shift 2 ;;
		--malicious-users) MALICIOUS_USERS="$2"; shift 2 ;;
		--attack-profile) ATTACK_PROFILE="$2"; shift 2 ;;
		--seed) SEED="$2"; shift 2 ;;
		--outdir) OUTDIR="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--keep-firewall) KEEP_FIREWALL=1; shift ;;
		--with-ids) WITH_IDS=1; shift ;;
		--ids-drain) IDS_DRAIN="$2"; shift 2 ;;
		--with-banking) WITH_BANKING=1; shift ;;
		--bank-rate) BANK_RATE="$2"; shift 2 ;;
		--bank-profile) BANK_PROFILE="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $MALICIOUS_USERS -lt $USERS ]] || die "--malicious-users must be less than --users"
command -v ufw >/dev/null || die "ufw not installed"
command -v ip >/dev/null || die "iproute2 not installed"
# Used directly for verdict logging; see the note where the LOG rules are installed.
command -v iptables >/dev/null || die "iptables not installed"
command -v python3 >/dev/null || die "python3 not installed"
# Checked here too, not only in lab.sh: a one-shot capture builds its own rules, so it can
# mislabel a window on its own without a lab ever having existed.
lab_check_port_lists || die "the port lists contradict each other; fix lab-config.sh"

# --dry-run is what someone runs *before* deciding to let this touch their firewall, so
# it must not itself demand root.
if [[ $DRY_RUN -eq 0 ]]; then
	[[ $EUID -eq 0 ]] || die "must run as root (firewall rules and network namespaces)"
	pgrep -x rsyslogd >/dev/null || die "rsyslogd is not running; ufw log lines would not \
reach $UFW_LOG. Start it with: systemctl start rsyslog"
fi

IDS_LIB="$SCRIPT_DIR/../IDS/slips-lib.sh"

# A running lab decides whether there is an IDS; --with-ids on a capture cannot conjure
# one, and asking for it when the lab was built without one is a mistake worth naming
# rather than silently producing a firewall-only window.
if [[ $LAB_MODE -eq 1 ]]; then
	if [[ $WITH_IDS -eq 1 && "${LAB_WITH_IDS:-0}" -ne 1 ]]; then
		die "the running lab was built without an IDS; './lab.sh down' then './lab.sh up --with-ids'"
	fi
	WITH_IDS="${LAB_WITH_IDS:-0}"
	SLIPS_OUT="${LAB_SLIPS_OUT:-}"

	# An empty path here would not fail: slips_alerts_offset would report 0 and
	# slips_collect would read a file that does not exist, producing an empty evidence
	# file and a group manifest claiming the IDS found nothing. Silence that looks like
	# a result is the worst outcome available, so refuse instead.
	if [[ $WITH_IDS -eq 1 && -z "$SLIPS_OUT" ]]; then
		die "the lab records an IDS but no output directory; './lab.sh down' and start it again"
	fi

	# The lab created a fixed set of addresses in the namespace. Asking for more users
	# than exist would bind to addresses that are not there, and the failure would look
	# like a traffic problem rather than a configuration one.
	if [[ $USERS -gt "${LAB_USERS:-0}" ]]; then
		die "the running lab has ${LAB_USERS:-0} user addresses, --users asked for $USERS"
	fi
fi

if [[ $WITH_IDS -eq 1 ]]; then
	[[ -f "$IDS_LIB" ]] || die "--with-ids needs $IDS_LIB"
	# shellcheck source=../IDS/slips-lib.sh
	source "$IDS_LIB"
	# Only the one-shot path starts Slips, so only it needs to check it can. In lab
	# mode Slips is already up and was validated when the lab was built.
	if [[ $DRY_RUN -eq 0 && $LAB_MODE -eq 0 ]]; then
		slips_preflight || die "IDS preflight failed"
	fi
fi

# Where the IDS runs is the lab's decision too. Remote: the lab's tcpdump has been writing
# the veth to LAB_PCAP since it started, and this window's packets go to Slips on the VM.
IDS_REMOTE=0
if [[ $LAB_MODE -eq 1 && $WITH_IDS -eq 1 && "$LAB_IDS_MODE" == "remote" ]]; then
	IDS_REMOTE=1
fi

# Banking, likewise, is whatever the running lab was built with; it cannot be conjured for
# one capture, because the tunnel to the bank belongs to the lab.
if [[ $LAB_MODE -eq 1 ]]; then
	if [[ $WITH_BANKING -eq 1 && "${LAB_WITH_BANKING:-0}" -ne 1 ]]; then
		die "the running lab was built without the banking source; './lab.sh down' then './lab.sh up --with-banking'"
	fi
	WITH_BANKING="${LAB_WITH_BANKING:-0}"
elif [[ $WITH_BANKING -eq 1 ]]; then
	die "--with-banking needs a running lab (the bank tunnel belongs to it): ./lab.sh up --with-banking"
fi

if [[ $IDS_REMOTE -eq 1 || $WITH_BANKING -eq 1 || $LAB_VIA_TUNNEL -eq 1 ]]; then
	# shellcheck source=../Remote/vm-lib.sh
	source "$PDE_ROOT/Remote/vm-lib.sh"
fi
if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
	# shellcheck source=../Remote/tun-lib.sh
	source "$PDE_ROOT/Remote/tun-lib.sh"
	# shellcheck source=../Remote/remote-source-lib.sh
	source "$PDE_ROOT/Remote/remote-source-lib.sh"
	# shellcheck source=../Auth/auth-lib.sh
	source "$PDE_ROOT/Auth/auth-lib.sh"
fi
if [[ $WITH_BANKING -eq 1 ]]; then
	# shellcheck source=../Banking/banking-lib.sh
	source "$PDE_ROOT/Banking/banking-lib.sh"
	# The bank is reached at the tunnel's far end in this mode, through the relay that makes
	# the call cross the VM's INPUT chain. banking-lib.sh computes this from HOST_IP, which
	# is this machine — where nothing is listening.
	if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
		BANK_URL="https://${TARGET_IP}:${BANK_PORT}/fineract-provider"
	fi
fi

if [[ $DRY_RUN -eq 0 && $IDS_REMOTE -eq 1 ]]; then
	# An empty or stopped capture would not fail anything below: the slice would simply be
	# empty and Slips would report nothing — a quiet IDS that is really a dead sensor.
	[[ -n "$LAB_PCAP" && -s "$LAB_PCAP" ]] || die "the lab records a remote IDS but no capture file; restart the lab"
	_tpid=$(lab_get LAB_TCPDUMP_PID "")
	[[ -n "$_tpid" && -d "/proc/$_tpid" ]] || die "the lab's packet capture is not running; restart the lab"
	slips_remote_preflight || die "remote IDS preflight failed"
fi
if [[ $DRY_RUN -eq 0 && $WITH_BANKING -eq 1 ]]; then
	banking_preflight || die "banking preflight failed"
	# In tunnel mode the bank is reached through the relay on the tunnel device, not through
	# a port forward, so it is the tunnel that has to be up.
	if [[ $LAB_VIA_TUNNEL -eq 0 ]]; then
		vm_tunnel_running bank || die "the lab's bank tunnel is down; restart the lab"
	fi
fi

if [[ $DRY_RUN -eq 0 && $LAB_VIA_TUNNEL -eq 1 ]]; then
	# Every source in this mode is read from the VM, so a dropped tunnel is not a degraded
	# window, it is a window with no evidence in it at all.
	tun_session_running || die "the lab's tunnel device is down; './lab.sh down' then up"
	ping -c1 -W2 -I "$TUN_DEV" "$TUN_VM_IP" >/dev/null 2>&1 		|| die "the tunnel device is up but $TUN_VM_IP does not answer; restart the lab"
	remote_source_preflight || die "the VM's logs cannot be read"
	auth_preflight || die "the auth source preflight failed"
	if [[ $WITH_IDS -eq 1 ]]; then
		[[ -n "$LAB_VM_SLIPS_OUT" ]] || die "the lab records an IDS on the VM but no output directory; restart the lab"
	fi
fi

# guaranteed-alert depends on a listener and permit rules. A lab started before they
# existed has neither: every attempt would be denied, Slips would rate it MEDIUM at best,
# and the run would look like the IDS failing to alert. One-shot captures build their own.
if [[ "$ATTACK_PROFILE" == "guaranteed-alert" && $DRY_RUN -eq 0 ]]; then
	if [[ $LAB_MODE -eq 1 ]]; then
		if [[ -z "$(lab_get LAB_ALERT_PORTS "")" ]]; then
			die "the running lab predates the guaranteed-alert profile; restart it ('./lab.sh down', then up)"
		fi
		if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
			# The listener is on the VM in this mode, bound to the tunnel address, so there is
			# no local pid to look for. Checked by connecting to the port the way a simulated
			# user will, which covers the listener, the VM's permit rule and the tunnel at
			# once — a stronger check than a pid, on either path.
			_alert_port="${ALERT_PORTS%%,*}"
			# From INSIDE the namespace. The VM permits 10.99.0.0/24 and denies everything
			# else, so a probe sourced from this host's own tunnel address is correctly
			# refused, and would report a healthy lab as broken.
			ip netns exec "$LAB_NS" bash -c "exec 3<>/dev/tcp/$TUN_VM_IP/$_alert_port" 2>/dev/null \
				|| die "nothing answers $TUN_VM_IP:$_alert_port on $VM_NAME; restart the lab ('./lab.sh down', then up)"
		else
			LAB_LISTENER_PID=$(lab_get LAB_LISTENER_PID "")
			if [[ -z "$LAB_LISTENER_PID" || ! -d "/proc/$LAB_LISTENER_PID" ]]; then
				die "the lab's alert listener is not running; restart the lab ('./lab.sh down', then up)"
			fi
		fi
	fi
	# An alert is the IDS's to raise. Without it the traffic is still sent — permitted
	# connections to unusual ports, logged ALLOW — but nothing is watching to call it hostile.
	if [[ $WITH_IDS -ne 1 ]]; then
		echo "warning: guaranteed-alert without the IDS: the traffic is sent, but no alert can be raised" >&2
	fi
fi

# The LOG target is a module on the WSL kernel and is loaded on demand, but failing here
# with a clear message beats discovering an empty log file after the run.
modprobe xt_LOG 2>/dev/null || true
modprobe nf_log_syslog 2>/dev/null || true

# Build the user list.
declare -a USER_IPS=()
for ((i = 1; i <= USERS; i++)); do
	USER_IPS+=("${USER_IP_BASE}$((USER_IP_OFFSET + i))")
done
# Attackers are drawn from the end of the list so a run's benign users keep stable
# addresses as --malicious-users changes.
declare -a MALICIOUS_IPS=()
for ((i = 0; i < MALICIOUS_USERS; i++)); do
	MALICIOUS_IPS+=("${USER_IPS[$((USERS - 1 - i))]}")
done
USERS_CSV=$(IFS=,; echo "${USER_IPS[*]}")
MALICIOUS_CSV=$(IFS=,; echo "${MALICIOUS_IPS[*]:-}")

if [[ $DRY_RUN -eq 1 ]]; then
	cat <<-EOF
	Would apply:
	  ufw --force enable
	  ufw logging full                       # unrate-limited; see note below

	  # Order matters, and these are applied in this order:
	  ufw allow from $SUBNET to any port <${BENIGN_PORTS}> proto tcp
	  ufw allow from $SUBNET to any port <${ALERT_PORTS}> proto tcp    # guaranteed-alert target
	  ufw allow from $SUBNET to any port ${BANK_PORT} proto tcp           # the bank, via the lab's tunnel
	  ufw deny  from $SUBNET                                 # everything else = the attacker
	  ufw allow to any port <${PRESERVE_PORTS}> proto tcp    # keep dev stack reachable

	  PRESERVE_PORTS overlaps the attacker's port list (22, 5432), so the subnet rules
	  must come first — otherwise attacker traffic to those ports matches a permit rule
	  and is logged as allowed, mislabelling part of the dataset.

	  Then, into ufw's own chain, two unrate-limited LOG rules:
	  iptables -I ufw-user-input 1 -s $SUBNET -p tcp -m multiport --dports <${ALLOWED_PORTS}> \\
	           -j LOG --log-prefix "[UFW ALLOW] "
	  iptables -I ufw-user-input 2 -s $SUBNET -p tcp -m multiport ! --dports <${ALLOWED_PORTS}> \\
	           -j LOG --log-prefix "[UFW BLOCK] "

	  ufw's own 'log' keyword hardcodes -m limit --limit 3/min --limit-burst 10 with no
	  loglevel check, so it caps verdict lines at ~11 per rule per 30s no matter what
	  'logging full' says. These replace it. They are removed when ufw reloads on restore.

	  ip netns add $NS
	  veth $VETH_HOST <-> $VETH_NS, host $HOST_IP/24
	  namespace addresses: ${USER_IPS[*]}
	  attackers: ${MALICIOUS_IPS[*]:-none}
	  listener on $HOST_IP ports <${ALERT_PORTS}>, accept-and-close (guaranteed-alert)

	ufw rate-limits logging in two independent places, and both would gut a ${DURATION}s window:

	  1. the AUDIT chains, limited below loglevel 'high' — lifted by 'logging full'
	  2. the per-rule 'log' keyword, limited unconditionally with no loglevel check
	     — not lifted by anything, which is why the LOG rules above are installed
	     directly instead

	Without both, a run returns roughly 11 verdict lines per rule and looks like a
	firewall that saw almost no traffic.
	EOF
	exit 0
fi

# ---------------------------------------------------------------------------
# Infrastructure
#
# With a lab up, the topology, the firewall and the IDS already exist and outlive this
# capture, so there is nothing to build and — importantly — nothing to restore. Without
# one, this script builds the lot and puts it back on exit, which is the safe one-shot
# path and the reason the trap below still exists.
# ---------------------------------------------------------------------------
if [[ $LAB_MODE -eq 1 ]]; then
	log "using the running lab (${LAB_NS:-$NS}, started ${LAB_STARTED_UTC:-?})"
	[[ "${LAB_WITH_IDS:-0}" -eq 1 ]] && log "IDS already running on ${LAB_VETH_HOST:-$VETH_HOST}"
else
	# ---------------------------------------------------------------------------
	# Snapshot the firewall so the run is reversible
	# ---------------------------------------------------------------------------
	STATE_DIR=$(mktemp -d /tmp/pde-fw-state.XXXXXX)
	ORIG_ENABLED=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf | cut -d= -f2)
	ORIG_LOGLEVEL=$(grep -E '^LOGLEVEL=' /etc/ufw/ufw.conf | cut -d= -f2)
	cp -a /etc/ufw/user.rules "$STATE_DIR/user.rules"
	cp -a /etc/ufw/user6.rules "$STATE_DIR/user6.rules"
	log "firewall state saved to $STATE_DIR (was ENABLED=$ORIG_ENABLED LOGLEVEL=$ORIG_LOGLEVEL)"

	restore() {
		local rc=$?
		[[ $KEEP_FIREWALL -eq 1 ]] && { echo "--keep-firewall: leaving firewall and namespace in place"; return 0; }
		echo "restoring firewall and tearing down namespace..."
		# Slips must let go of the interface before it is deleted underneath it.
		if [[ $WITH_IDS -eq 1 ]] && declare -F slips_stop >/dev/null; then
			slips_stop
		fi
		alert_listener_stop "${LISTENER_PID:-}"
		ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
		ip netns del "$NS" 2>/dev/null || true
		ip link del "$VETH_HOST" 2>/dev/null || true
		cp -a "$STATE_DIR/user.rules" /etc/ufw/user.rules 2>/dev/null || true
		cp -a "$STATE_DIR/user6.rules" /etc/ufw/user6.rules 2>/dev/null || true
		ufw logging "$ORIG_LOGLEVEL" >/dev/null 2>&1 || true
		if [[ "$ORIG_ENABLED" == "no" ]]; then
			ufw --force disable >/dev/null 2>&1 || true
		else
			ufw --force enable >/dev/null 2>&1 || true
		fi
		rm -rf "$STATE_DIR"
		echo "firewall restored to ENABLED=$ORIG_ENABLED LOGLEVEL=$ORIG_LOGLEVEL"
		return $rc
	}
	LISTENER_PID=""
	trap restore EXIT INT TERM

	# ---------------------------------------------------------------------------
	# Network namespace: one address per simulated user
	# ---------------------------------------------------------------------------
	log "creating namespace $NS with $USERS user addresses"
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true

	ip netns add "$NS"
	ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
	ip link set "$VETH_NS" netns "$NS"
	ip addr add "$HOST_IP/24" dev "$VETH_HOST"
	ip link set "$VETH_HOST" up
	ip netns exec "$NS" ip link set lo up
	for ip_addr in "${USER_IPS[@]}"; do
		ip netns exec "$NS" ip addr add "$ip_addr/24" dev "$VETH_NS"
	done
	ip netns exec "$NS" ip link set "$VETH_NS" up

	# Answers the guaranteed-alert profile's connections. Host side and bound to the veth's
	# host address, so it can only start once that exists. Stopped by the trap.
	log "starting the alert listener on $HOST_IP ports $ALERT_PORTS"
	LISTENER_PID=$(alert_listener_start "$HOST_IP" "$STATE_DIR/alert-listener.pid" "$STATE_DIR/alert-listener.log") \
		|| die "could not start the alert listener"

	# ---------------------------------------------------------------------------
	# IDS
	#
	# Started here, between creating the interface and opening the window: Slips can only
	# attach to a veth that already exists, and it must be reading packets before any are
	# generated. Its ~80s of module and threat-feed loading is why this cannot be deferred
	# to just before the traffic — a window opened during startup is simply not observed.
	#
	# ufw is configured *after* this, so `logging full` is active for the window rather
	# than for the couple of minutes Slips spends starting up.
	# ---------------------------------------------------------------------------

	# Named for the run only once the window has a timestamp; until then Slips writes to a
	# scratch directory, because STAMP is deliberately taken from the window start and the
	# window has not opened yet.
	if [[ $WITH_IDS -eq 1 ]]; then
		# Dotted so the scratch directory does not sit among the window directories.
		# It is renamed into the window's own directory once the window has a stamp.
		SLIPS_OUT="$OUTDIR/.ids-run"
		rm -rf "$SLIPS_OUT"
		log "starting Slips on $VETH_HOST (loading modules and threat-intel feeds)"
		slips_start_redis || die "could not start the Slips redis"
		slips_start "$VETH_HOST" "$SLIPS_OUT" || die "could not start Slips"
		slips_wait_ready "$IDS_READY_TIMEOUT" || die "Slips never became ready"
		log "Slips is reading $VETH_HOST"
	fi

	# ---------------------------------------------------------------------------
	# Firewall
	# ---------------------------------------------------------------------------
	log "configuring ufw (logging=full, default deny incoming)"
	# Rule ORDER carries the labelling, and ufw evaluates in the order rules are added.
	# PRESERVE_PORTS deliberately overlaps MALICIOUS_PORTS (22 and 5432 are both a service
	# this host needs reachable and a port an attacker probes). If the preserve rules came
	# first they would match the simulated attacker too, and those attempts would be logged
	# as permitted — silently mislabelling part of the dataset. So the test subnet's rules
	# are added first and are scoped to the subnet, and the host-wide preserve rules can
	# only ever match traffic from somewhere else.
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

	# The bank's port is in ALLOWED_PORTS, so the verdict rules call it ALLOW; permitted
	# here too, so the rule and the label agree even with no bank behind it.
	ufw allow from "$SUBNET" to any port "$BANK_PORT" proto tcp >/dev/null

	# Everything else from the test subnet is the attacker. An explicit deny is clearer
	# than relying on the default policy and, unlike the default, it is unambiguously
	# attributable to this run.
	ufw deny from "$SUBNET" >/dev/null

	IFS=',' read -ra _preserve <<< "$PRESERVE_PORTS"
	for p in "${_preserve[@]}"; do
		ufw allow "$p/tcp" >/dev/null
	done
	ufw logging full >/dev/null
	ufw --force enable >/dev/null

	# ---------------------------------------------------------------------------
	# Verdict logging, installed directly rather than through ufw's `log` keyword.
	#
	# ufw hardcodes `-m limit --limit 3/min --limit-burst 10` onto every per-rule log,
	# with no loglevel check (backend_iptables.py: `limit_args` in the rule-snippet
	# builder). `ufw logging full` only lifts the limit from the AUDIT chains, which take
	# their own branch. The result is that a 30s window yields ~11 verdict lines per rule —
	# burst 10 plus 3/min for half a minute — however much traffic crosses the firewall,
	# while the AUDIT lines beside them are complete. A dataset labelled from that is
	# missing 95% of its verdicts.
	#
	# These rules live in ufw's own chain, use the same kernel LOG target and the same
	# prefixes; the only difference is the absence of a rate limit that exists to protect
	# syslog on a production host and has no place in a 30-second measurement. LOG does not
	# terminate a packet's traversal, so the allow/deny rules below still decide its fate.
	# ufw reloads its chains from user.rules on enable/disable, so these do not survive the
	# restore in the exit trap.
	# ---------------------------------------------------------------------------
	# ALLOWED_PORTS, not BENIGN_PORTS: the alert ports are permitted too, and the BLOCK rule
	# below is "everything else", so leaving them out would label permitted traffic BLOCK.
	iptables -I ufw-user-input 1 -s "$SUBNET" -p tcp -m multiport --dports "$ALLOWED_PORTS" \
		-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
	iptables -I ufw-user-input 2 -s "$SUBNET" -p tcp -m multiport ! --dports "$ALLOWED_PORTS" \
		-j LOG --log-prefix "[UFW BLOCK] " --log-level 4
	log "ufw active (verdict logging installed without ufw's 3/min cap)"
fi

# ---------------------------------------------------------------------------
# Capture window
# ---------------------------------------------------------------------------

# The bank's event stream is bounded by broker offsets, which take a few seconds to read
# over IAP. Taken before the window opens rather than at its first instant: everything
# published after this point is at or beyond these offsets, so nothing in the window can
# be missed, and the window start stays the moment traffic actually begins.
BANK_OFFSETS=""
if [[ $WITH_BANKING -eq 1 ]]; then
	log "recording the bank's event-stream offsets"
	BANK_OFFSETS=$(banking_offsets) || die "could not read the bank's event-stream offsets"
	[[ -n "$BANK_OFFSETS" ]] || die "the events collector returned no offsets"
fi

WINDOW_START_EPOCH=$(date -u +%s)
WINDOW_START_ISO=$(date -u -d "@$WINDOW_START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
STAMP=$(date -u -d "@$WINDOW_START_EPOCH" +%Y%m%d%H%M%S)

# Byte offset rather than a timestamp filter: syslog's traditional format has neither a
# year nor sub-second precision, so it cannot reliably bound a 30-second window on its own.
# In tunnel mode the firewall is the VM's, so the log is the VM's: the boundary is a byte
# offset taken there, and the range is fetched back after the window closes. Same mechanism,
# one machine further away.
if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
	SRC_LOG="$VM_UFW_LOG"
	LOG_OFFSET=$(remote_offset "$VM_UFW_LOG")
	if [[ "$VM_UFW_LOG" == "journal" ]]; then
		FW_LOG_DESC="the kernel journal on $VM_NAME (journalctl -k), lines matching [UFW"
	else
		FW_LOG_DESC="$VM_UFW_LOG on $VM_NAME"
	fi
	log "capturing from $SRC_LOG on $VM_NAME at byte offset $LOG_OFFSET"
else
	SRC_LOG="$UFW_LOG"
	[[ -f "$SRC_LOG" ]] || SRC_LOG="$KERN_LOG"
	LOG_OFFSET=$(stat -c %s "$SRC_LOG" 2>/dev/null || echo 0)
	FW_LOG_DESC="$SRC_LOG"
	log "capturing from $SRC_LOG at byte offset $LOG_OFFSET"
fi

# Same mechanism for the IDS, and for the same reason: both sources keep running and
# writing throughout, and the window is a bounded read against them rather than a pause.
IDS_ALERTS_OFFSET=0
PCAP_OFFSET=0
AUTH_OFFSET=""
if [[ $IDS_REMOTE -eq 1 ]]; then
	# Remote: the offset is into the lab's packet capture, and the window's packets are what
	# tcpdump writes after it.
	PCAP_OFFSET=$(pcap_offset "$LAB_PCAP")
elif [[ $LAB_VIA_TUNNEL -eq 1 && $WITH_IDS -eq 1 ]]; then
	# Slips is sniffing the device on the VM and writing there, so its evidence file is read
	# by an offset taken there, exactly as the firewall's is.
	IDS_ALERTS_OFFSET=$(remote_offset "$LAB_VM_SLIPS_OUT/alerts/alerts.log")
elif [[ $WITH_IDS -eq 1 ]]; then
	IDS_ALERTS_OFFSET=$(slips_alerts_offset "$SLIPS_OUT")
fi

# The remote-access source. Taken before the window for the same reason as the others, but
# it bounds only the *new* records: the login that authorised this window predates it, and
# the collector gathers that separately. See Auth/README.md.
if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
	AUTH_OFFSET=$(auth_offset) || AUTH_OFFSET=""
	[[ -n "$AUTH_OFFSET" ]] || { echo "warning: could not read sshd's offset on the VM; the auth source will be skipped" >&2; }
fi

# One directory per captured window. The window is the unit of evidence — an
# EvidenceGroup is exactly "these files, this window" — so the filesystem says the same
# thing the group manifest does. Names inside need no timestamp; the directory carries it.
RUN_DIR="$OUTDIR/$STAMP"
mkdir -p "$RUN_DIR"
# The names repeat the stamp the directory already carries, on purpose: a file that
# leaves the directory — uploaded to the repository, attached to a case — has to keep its
# identity, and "firewall.log" identifies nothing once it is somewhere else.
GT_JSON="$RUN_DIR/firewall_${STAMP}.groundtruth.json"
OUT_LOG="$RUN_DIR/firewall_${STAMP}.log"
MANIFEST="$RUN_DIR/firewall_${STAMP}.manifest.json"

BANK_GT="$RUN_DIR/banking_${STAMP}.groundtruth.json"
BANK_GEN_PID=""
if [[ $WITH_BANKING -eq 1 ]]; then
	# Alongside the network traffic, from the same namespace and the same user addresses:
	# the attacker who scans is the one who logs into the bank. Started first, since its
	# plan begins at the same t0 as the traffic's.
	log "driving the bank: benign ${BANK_RATE}/s, profile=${BANK_PROFILE}"
	ip netns exec "$LAB_NS" python3 "$BANK_GEN" \
		--seed-file "$BANK_SEED" --url "$BANK_URL" \
		--users "$USERS_CSV" --malicious-users "$MALICIOUS_CSV" \
		--duration "$DURATION" --rate "$BANK_RATE" --profile "$BANK_PROFILE" \
		--seed "$SEED" --out "$BANK_GT" &
	BANK_GEN_PID=$!
fi

log "generating traffic: ${USERS} users, ${DURATION}s, ${RATE}/s, ${MALICIOUS_PCT}% malicious, profile=${ATTACK_PROFILE}"
# $LAB_NS, not $NS: under a lab the namespace is whichever one that session recorded,
# and defaulting to the compiled-in name would run the traffic somewhere else entirely.
# They coincide today, which is exactly why this would go unnoticed until they did not.
ip netns exec "$LAB_NS" python3 "$SCRIPT_DIR/generate_traffic.py" \
	--users "$USERS_CSV" \
	--malicious-users "$MALICIOUS_CSV" \
	--target "$TARGET_IP" \
	--duration "$DURATION" \
	--rate "$RATE" \
	--malicious-pct "$MALICIOUS_PCT" \
	--attack-profile "$ATTACK_PROFILE" \
	--benign-ports "$BENIGN_PORTS" \
	--malicious-ports "$MALICIOUS_PORTS" \
	--alert-ports "$ALERT_PORTS" \
	--seed "$SEED" \
	--out "$GT_JSON"

CAPTURE_ERRORS=0
if [[ -n "$BANK_GEN_PID" ]]; then
	if ! wait "$BANK_GEN_PID" || [[ ! -s "$BANK_GT" ]]; then
		echo "error: the banking generator failed; the window has no banking evidence" >&2
		WITH_BANKING=0
		CAPTURE_ERRORS=1
	fi
fi

# Rounded UP to the whole second. Bounds are recorded in whole seconds, and truncating the
# end drops whatever happened in the window's last partial second: the start is floored
# and the end ceilinged, so both err outward and nothing inside the window falls outside
# its bounds. (Measured: two deposits at hh:mm:11.2 and .9 were lost from a window that
# closed at 11.95 and was recorded as ending at 11.)
WINDOW_END_ISO=$(date -u -d "@$(( $(date -u +%s) + 1 ))" +%Y-%m-%dT%H:%M:%SZ)

# rsyslog batches writes; without this the tail of the window is routinely missing.
log "waiting for rsyslog to flush"
sleep 3

# ---------------------------------------------------------------------------
# Extract, hash, seal
# ---------------------------------------------------------------------------
# In tunnel mode the log is on the VM, so the window's byte range is brought here first and
# everything below then runs against a local file exactly as it always did. The digest taken
# on the VM is checked on arrival, so the range is known to have crossed intact; the evidence
# artifact itself is hashed further down, after the filter.
FW_RANGE_BYTES=0
FW_RANGE_SHA=""
FW_RAW=""
if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
	FW_RAW="$RUN_DIR/.ufw-range"
	if read -r FW_RANGE_BYTES FW_RANGE_SHA < <(remote_slice "$VM_UFW_LOG" "$LOG_OFFSET" "$STAMP" "ufw-range.log" "$FW_RAW"); then
		log "fetched ${FW_RANGE_BYTES} bytes of $VM_UFW_LOG from $VM_NAME"
		SRC_LOG="$FW_RAW"
		LOG_OFFSET=0
	else
		die "could not bring the firewall's window home from $VM_NAME"
	fi
fi

tail -c "+$((LOG_OFFSET + 1))" "$SRC_LOG" 2>/dev/null \
	| grep -F "SRC=${USER_IP_BASE}" > "$OUT_LOG" || true
[[ -n "$FW_RAW" ]] && rm -f "$FW_RAW"

# NOT named LINES. `LINES` is a bash special variable: with `checkwinsize` on — the
# default since bash 5.0, and it applies to scripts too whenever the shell has a
# terminal — bash rewrites LINES with the terminal's height after *every* external
# command. The assignment below is correct and the value is destroyed one command later,
# so the manifest silently records the height of whoever's window ran it. It only
# reproduces on a tty, which is why piped tests never caught it.
LOG_LINES=$(wc -l < "$OUT_LOG")
BYTES=$(stat -c %s "$OUT_LOG")

# `grep -c` prints "0" *and* exits 1 when nothing matches, so `|| echo 0` emits "0\n0"
# — two values where the manifest expects one, which is a JSON syntax error rather than
# a wrong number. `|| true` keeps grep's own "0" and only suppresses the exit status.
count_lines() {
	local n
	n=$(grep -c "$1" "$OUT_LOG" 2>/dev/null || true)
	printf '%s' "${n:-0}"
}
BLOCKED=$(count_lines 'UFW BLOCK')
ALLOWED=$(count_lines 'UFW ALLOW')
# At `logging full` ufw also emits an [UFW AUDIT] line for every packet it sees, from
# the ufw-before-logging chains, in addition to any verdict line. Counted separately so
# the totals reconcile: a blocked packet produces both an AUDIT and a BLOCK line.
AUDITED=$(count_lines 'UFW AUDIT')

# Every captured line carries exactly one ufw prefix, so the verdicts must account for
# all of them. This is cheap and it is what would have caught LINES being silently
# replaced by the terminal height: 11 + 33 + 1136 against a reported 17.
TALLIED=$((BLOCKED + ALLOWED + AUDITED))
if [[ $TALLIED -ne $LOG_LINES ]]; then
	echo "warning: verdict counts do not reconcile with the line count" >&2
	echo "         ${BLOCKED} BLOCK + ${ALLOWED} ALLOW + ${AUDITED} AUDIT = ${TALLIED}, but the file has ${LOG_LINES} lines." >&2
	echo "         The manifest may be wrong; treat this run as suspect." >&2
fi

if [[ $LOG_LINES -eq 0 ]]; then
	echo "warning: no ufw log lines captured. Check that ufw logging is not being" >&2
	echo "         rate-limited and that $SRC_LOG is being written to." >&2
fi

# Facts needed to read the log's own timestamps, which the log itself does not carry.
#
# ufw lines come through rsyslog in RFC 3164 format: local time, no year, no timezone,
# whole seconds. Slips writes RFC 3339: UTC, explicit offset, microseconds. Same instant,
# two different renderings — 22:48:49 and 20:48:49 here — and nothing in the ufw line
# says which zone it is in. Rather than rewrite what the source produced, record what is
# needed to interpret it.
TZ_NAME=$(date +%Z)
TZ_OFFSET=$(date +%z)

# Hashed before anything else touches the file, per the SecureRS ingestion rule the
# Evidence Repository follows. This digest is what the EvidenceItem will carry.
SHA256=$(sha256sum "$OUT_LOG" | cut -d' ' -f1)
chmod 444 "$OUT_LOG"

# Which ufw and which kernel actually logged this. In tunnel mode that is the VM's, and a
# manifest naming this machine's would be describing software that logged nothing.
if [[ $LAB_VIA_TUNNEL -eq 1 ]]; then
	IFS='|' read -r FW_UFW_VERSION FW_KERNEL FW_HOST <<< "$(remote_firewall_facts)"
	FW_METHOD="real packets across the INPUT chain of $VM_NAME, arriving on $TUN_DEV from this machine's namespace over the tunnel device; log lines are kernel-generated and were not synthesised"
else
	FW_UFW_VERSION="$(ufw --version 2>/dev/null | head -1)"
	FW_KERNEL="$(uname -r)"
	FW_HOST="$(hostname)"
	FW_METHOD="real packets across the host INPUT chain; log lines are kernel-generated and were not synthesised"
fi

python3 - "$MANIFEST" <<PY
import json, sys
manifest = {
    "source": {
        "pde_source": "firewall",
        "product": "ufw",
        "version": "${FW_UFW_VERSION}",
        "kernel": "${FW_KERNEL}",
        "observed_on": "${FW_HOST}",
        "log_facility": "netfilter LOG target -> rsyslog -> ${FW_LOG_DESC}",
        "collection_method": "${FW_METHOD}",
    },
    "window": {
        "start_utc": "${WINDOW_START_ISO}",
        "end_utc": "${WINDOW_END_ISO}",
        "duration_seconds": ${DURATION},
    },
    # How to read the timestamps in the log file, which the log file cannot tell you
    # itself. Without this a ufw line is genuinely ambiguous: no year, no zone.
    "timestamps": {
        "log_line_format": "RFC 3164 syslog: 'Mon DD HH:MM:SS', LOCAL time, no year, "
                           "no timezone, whole seconds",
        "log_line_timezone": "${TZ_NAME}",
        "log_line_utc_offset": "${TZ_OFFSET}",
        "manifest_and_window_bounds": "UTC (RFC 3339, suffix Z)",
        "ids_evidence_format": "RFC 3339 with explicit offset, microseconds — already UTC",
        # Useful for ORDERING, not for conversion. Measured on this host, boot time from
        # /proc/stat and the boot time implied by printk's own timestamps disagree by
        # ~694s: WSL2 suspends the VM and printk's clock does not count suspended time.
        # So this field cannot be turned into an absolute instant, and any manifest
        # claiming otherwise would be wrong.
        "kernel_uptime_field": "The bracketed [12345.678901] on each line is a monotonic "
                               "clock with microsecond resolution. It orders events "
                               "within the window far more precisely than the "
                               "whole-second syslog timestamp, and is immune to wall-"
                               "clock adjustment. It is NOT convertible to an absolute "
                               "time on this host: the VM suspends, and printk's clock "
                               "does not advance while it does.",
    },
    "configuration": {
        "users": ${USERS},
        "malicious_users": ${MALICIOUS_USERS},
        "malicious_event_pct": ${MALICIOUS_PCT},
        "attack_profile": "${ATTACK_PROFILE}",
        "events_per_second": ${RATE},
        "seed": ${SEED},
        "subnet": "${SUBNET}",
        "benign_ports": [int(p) for p in "${BENIGN_PORTS}".split(",")],
        "malicious_ports": [int(p) for p in "${MALICIOUS_PORTS}".split(",")],
        "alert_ports": [int(p) for p in "${ALERT_PORTS}".split(",")],
    },
    "output": {
        "log_file": "firewall_${STAMP}.log",
        "ground_truth_file": "firewall_${STAMP}.groundtruth.json",
        "lines": ${LOG_LINES},
        "bytes": ${BYTES},
        "ufw_block_lines": ${BLOCKED},
        "ufw_allow_lines": ${ALLOWED},
        "ufw_audit_lines": ${AUDITED},
        "sha256": "${SHA256}",
    },
    "caveats": [
        "the log's own timestamps are LOCAL (${TZ_NAME}, ${TZ_OFFSET}) while every "
        "timestamp in this manifest, in the ground truth and in the IDS evidence is UTC. "
        "The same instant therefore reads two hours apart between firewall.log and "
        "ids.alerts.log; see the timestamps block. Nothing has been rewritten — a "
        "source's own output is left as the source produced it",
        "syslog timestamps carry no year and no sub-second precision; the authoritative "
        "window bounds are window.start_utc/end_utc, in whole seconds with the start rounded "
        "down and the end rounded up, so that nothing inside the window falls outside them",
        "lines are filtered to SRC=${USER_IP_BASE}* — unrelated host traffic logged in the "
        "same window is excluded. Both directions are kept, so the host's RST replies to "
        "refused connections appear alongside the inbound attempts",
        "ufw logging was set to 'full' for the run; at the default 'low' its LOG rules are "
        "rate-limited to 3/min and most of the window would be lost",
        "at 'full' ufw emits an [UFW AUDIT] line for every packet in addition to any "
        "verdict line, so lines exceeds the event count: a blocked attempt produces both "
        "an AUDIT and a BLOCK entry",
        "verdict logging ([UFW ALLOW] / [UFW BLOCK]) was installed as unrate-limited LOG "
        "rules in ufw's own ufw-user-input chain rather than via ufw's 'log' keyword, "
        "which hardcodes --limit 3/min --limit-burst 10 regardless of logging level and "
        "would cap a 30s window at roughly 11 verdict lines per rule. Same kernel LOG "
        "target, same prefixes, no rate limit",
        "a blocked SYN is retransmitted by the client kernel, so one blocked attempt can "
        "produce several BLOCK lines; count distinct SPT values, not lines, to recover "
        "the attempt count",
        "ALERT_PORTS (${ALERT_PORTS}) are permitted from the subnet and answered by a "
        "listener, so guaranteed-alert attempts are logged [UFW ALLOW] although the ground "
        "truth labels them malicious. That is the scenario: the firewall let the attack "
        "through, and only the IDS can say it was hostile",
    ],
}
json.dump(manifest, open(sys.argv[1], "w"), indent=2)
PY

# ---------------------------------------------------------------------------
# The other sources' evidence for the same window
#
# Banking starts first. Its collectors run on the VM and spend most of their time waiting
# for the bank's publish job, so they run while the IDS is being analysed, not after it.
# ---------------------------------------------------------------------------
IDS_LOG="$RUN_DIR/ids_${STAMP}.alerts.log"
GROUP_MANIFEST="$RUN_DIR/window_${STAMP}.group.json"
BANK_MANIFEST="$RUN_DIR/banking_${STAMP}.manifest.json"
IDS_TOTAL=0; IDS_KEPT=0; IDS_SHA=""; IDS_SEVERITIES="0 0 0 0 0"; IDS_ALERTS=0
IDS_OK=0
IDS_PCAP=""; IDS_PCAP_SHA=""; IDS_PCAP_PACKETS=0
BANK_COLLECT_PID=""
BANK_SUMMARY=""

if [[ $WITH_BANKING -eq 1 ]]; then
	BANK_EXPECT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["executed_ok"])' "$BANK_GT")
	log "collecting the bank's evidence on $VM_NAME: events and audit trail for ${BANK_EXPECT} operations"
	banking_collect "$STAMP" "$BANK_OFFSETS" "$WINDOW_START_ISO" "$WINDOW_END_ISO" "$BANK_EXPECT" "$RUN_DIR" \
		> "$RUN_DIR/.banking-collect.log" 2>&1 &
	BANK_COLLECT_PID=$!
fi

if [[ $IDS_REMOTE -eq 1 ]]; then
	# The sensor's side of it: this window's packets, cut from the lab's capture by the
	# offset taken as the window opened, and hashed before they leave this machine.
	IDS_PCAP="$RUN_DIR/ids_${STAMP}.pcap"
	read -r IDS_PCAP_PACKETS _ _ <<< "$(pcap_slice "$LAB_PCAP" "$PCAP_OFFSET" "$IDS_PCAP" || echo "0 0 0")" || true
	IDS_PCAP_PACKETS=${IDS_PCAP_PACKETS:-0}
	IDS_PCAP_SHA=$(sha256sum "$IDS_PCAP" | cut -d' ' -f1)
	chmod 444 "$IDS_PCAP"
	# Slips' whole output tree comes home beside the evidence: zeek_files/conn.log is the
	# flow record behind the findings, and "on what basis" is a question an investigation
	# will ask.
	SLIPS_OUT="$RUN_DIR/ids_${STAMP}"
	log "analysing the window's ${IDS_PCAP_PACKETS} packets with Slips on $VM_NAME (about a minute)"
	if slips_remote_analyse "$IDS_PCAP" "$STAMP" "$SLIPS_OUT"; then
		IDS_ALERTS_OFFSET=0
		IDS_OK=1
	else
		echo "error: remote IDS analysis failed; the window has no IDS evidence" >&2
		CAPTURE_ERRORS=1
	fi
elif [[ $WITH_IDS -eq 1 ]]; then
	# Slips raises evidence in batches once it has seen the flows, so the window's
	# findings do not exist yet at this point. Draining is not politeness, it is the
	# difference between collecting the evidence and collecting an empty file.
	log "draining Slips for ${IDS_DRAIN}s so it can raise evidence for the window"
	sleep "$IDS_DRAIN"
	IDS_OK=1
fi

# Tunnel mode: Slips ran on the VM, live on the device. Its tree comes home and the slicer
# below is pointed at it with the offset taken on the VM — the fetched alerts.log is that
# same whole file, so the offset still means there what it meant here.
if [[ $IDS_OK -eq 1 && $LAB_VIA_TUNNEL -eq 1 ]]; then
	SLIPS_OUT="$RUN_DIR/ids_${STAMP}"
	log "fetching Slips' output from $VM_NAME"
	if ! remote_slips_fetch "$LAB_VM_SLIPS_OUT" "$SLIPS_OUT"; then
		echo "error: could not fetch the IDS evidence; the window has none" >&2
		IDS_OK=0
		CAPTURE_ERRORS=1
	fi
fi


if [[ $IDS_OK -eq 1 ]]; then
	# Locally, collected while Slips is still running. An IDS is a continuously running
	# system that gets *read* against; halting one to gather evidence is not something a
	# bank would do. Consistency comes from the byte offset and the timestamp slice, exactly
	# as it does for the ufw log while rsyslog keeps writing underneath it. Remotely, Slips
	# analysed only this window's packets, so the whole file is the window and the offset
	# is 0; the timestamp slice still applies.
	#
	# Defended rather than trusted: `read` returns non-zero on an empty herestring,
	# which under `set -e` would abort the run at the point where the evidence has been
	# collected but nothing has been written down about it.
	IDS_COUNTS=$(slips_collect "$SLIPS_OUT" "$IDS_ALERTS_OFFSET" "$WINDOW_START_ISO" "$WINDOW_END_ISO" "$IDS_LOG" || echo "0 0")
	read -r IDS_TOTAL IDS_KEPT <<< "$IDS_COUNTS" || true
	IDS_TOTAL=${IDS_TOTAL:-0}
	IDS_KEPT=${IDS_KEPT:-0}
	# Must be exactly five numbers: the group manifest unpacks them positionally.
	IDS_SEVERITIES=$(slips_severity_counts "$IDS_LOG")
	if [[ $(printf '%s\n' $IDS_SEVERITIES | grep -c .) -ne 5 ]]; then
		echo "warning: severity counts unreadable ('$IDS_SEVERITIES'); recording zeros" >&2
		IDS_SEVERITIES="0 0 0 0 0"
	fi
	# Alert lines carry no threat level, so the counts above cannot include them.
	IDS_ALERTS=$(slips_alert_count "$IDS_LOG")
	IDS_SHA=$(sha256sum "$IDS_LOG" | cut -d' ' -f1)
	chmod 444 "$IDS_LOG"
	log "IDS evidence: ${IDS_KEPT} of ${IDS_TOTAL} lines fall inside the window, ${IDS_ALERTS} of them alerts"

	# Under a local lab, Slips outlives this capture and keeps writing into its session
	# directory; the slice above is all this capture takes. One-shot only: Slips is stopped
	# because the veth it is attached to is about to be torn down — teardown, not a step in
	# collecting — and its tree is moved in beside the evidence.
	if [[ $IDS_REMOTE -eq 0 && $LAB_MODE -eq 0 ]]; then
		slips_stop
		if [[ -d "$SLIPS_OUT" ]]; then
			rm -rf "$RUN_DIR/ids_${STAMP}"
			mv "$SLIPS_OUT" "$RUN_DIR/ids_${STAMP}"
			SLIPS_OUT="$RUN_DIR/ids_${STAMP}"
		fi
	fi
fi

if [[ -n "$BANK_COLLECT_PID" ]]; then
	if wait "$BANK_COLLECT_PID"; then
		BANK_SUMMARY=$(python3 "$BANK_MANIFEST_BUILDER" --run-dir "$RUN_DIR" --stamp "$STAMP" \
			--start "$WINDOW_START_ISO" --end "$WINDOW_END_ISO" --duration "$DURATION" --rate "$BANK_RATE" \
			--vm "$VM_NAME" --fineract-image "$BANK_FINERACT_IMAGE" --bank-url "$BANK_URL") || BANK_SUMMARY=""
	fi
	if [[ -z "$BANK_SUMMARY" ]]; then
		echo "error: banking collection failed; the window has no banking evidence. Collector output:" >&2
		sed 's/^/    /' "$RUN_DIR/.banking-collect.log" >&2 2>/dev/null || true
		WITH_BANKING=0
		CAPTURE_ERRORS=1
	else
		chmod 444 "$RUN_DIR/banking-events_${STAMP}.jsonl" "$RUN_DIR/banking-audit_${STAMP}.jsonl" \
			"$RUN_DIR/banking-events_${STAMP}.raw.jsonl"
		log "$BANK_SUMMARY"
	fi
	rm -f "$RUN_DIR/.banking-collect.log"
fi

# The remote-access source. Collected after the window like the others, but it reaches back
# past the window's start on purpose: the login that authorised this window is older than the
# window, and an evidence file holding only the window would say nobody authenticated.
AUTH_OK=0
AUTH_SHA=""
AUTH_ACCEPTED=0
AUTH_FAILED=0
AUTH_SUMMARY=""
if [[ $LAB_VIA_TUNNEL -eq 1 && -n "$AUTH_OFFSET" ]]; then
	log "collecting the tunnel's authentication record from $VM_NAME"
	if AUTH_SUMMARY=$(auth_collect "$STAMP" "$AUTH_OFFSET" "$WINDOW_START_ISO" "$WINDOW_END_ISO" "$RUN_DIR"); then
		AUTH_OK=1
		AUTH_SHA=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' 			"$RUN_DIR/auth_${STAMP}.meta.json" 2>/dev/null || echo "")
		read -r AUTH_ACCEPTED AUTH_FAILED < <(python3 -c 'import json,sys
c = json.load(open(sys.argv[1]))["counts"]
print(c["accepted_logins"], c["failed_attempts"])' "$RUN_DIR/auth_${STAMP}.meta.json" 2>/dev/null) || true
		chmod 444 "$RUN_DIR/auth_${STAMP}.log"
		log "auth evidence: ${AUTH_ACCEPTED:-0} accepted logins, ${AUTH_FAILED:-0} failed attempts"
	else
		echo "error: the auth source produced no evidence for this window" >&2
		CAPTURE_ERRORS=1
	fi
fi


# The group is the point of the exercise: one window, one attack, independent sources that
# each saw part of it. This is the record an EvidenceGroup row would be built from. Values
# go in through the environment rather than being pasted into the Python source.
if [[ $IDS_OK -eq 1 || $WITH_BANKING -eq 1 || $AUTH_OK -eq 1 ]]; then
	G_STAMP="$STAMP" G_START="$WINDOW_START_ISO" G_END="$WINDOW_END_ISO" G_DURATION="$DURATION" \
	G_USERS="$USERS" G_MAL_USERS="$MALICIOUS_USERS" G_MAL_PCT="$MALICIOUS_PCT" G_PROFILE="$ATTACK_PROFILE" \
	G_SEED="$SEED" G_SUBNET="$SUBNET" G_TZ_NAME="$TZ_NAME" G_TZ_OFFSET="$TZ_OFFSET" G_VETH="$VETH_HOST" \
	G_VM="${VM_NAME:-}" G_HOST_IP="$HOST_IP" G_BANK_PORT="$BANK_PORT" \
	G_VIA_TUNNEL="$LAB_VIA_TUNNEL" G_TARGET_IP="$TARGET_IP" G_TUN_DEV="${TUN_DEV:-}" \
	G_AUTH_OK="$AUTH_OK" G_AUTH_SHA="$AUTH_SHA" G_AUTH_ACCEPTED="${AUTH_ACCEPTED:-0}" \
	G_AUTH_FAILED="${AUTH_FAILED:-0}" \
	G_FW_SHA="$SHA256" G_FW_LINES="$LOG_LINES" G_FW_BLOCK="$BLOCKED" G_FW_ALLOW="$ALLOWED" G_FW_AUDIT="$AUDITED" \
	G_IDS_OK="$IDS_OK" G_IDS_REMOTE="$IDS_REMOTE" G_IDS_SHA="$IDS_SHA" G_IDS_KEPT="$IDS_KEPT" \
	G_IDS_TOTAL="$IDS_TOTAL" G_IDS_ALERTS="$IDS_ALERTS" G_IDS_SEV="$IDS_SEVERITIES" \
	G_IDS_PCAP_SHA="$IDS_PCAP_SHA" G_IDS_PCAP_PACKETS="$IDS_PCAP_PACKETS" \
	G_BANK_MANIFEST="$([[ $WITH_BANKING -eq 1 ]] && echo "$BANK_MANIFEST")" \
	python3 - "$GROUP_MANIFEST" <<'PY'
import json, os, sys
E = os.environ
n = lambda k: int(E.get(k) or 0)
stamp = E["G_STAMP"]

items = [{
    "pde_source": "firewall", "product": "ufw", "file": "firewall_%s.log" % stamp,
    "sha256": E["G_FW_SHA"], "lines": n("G_FW_LINES"), "ufw_block_lines": n("G_FW_BLOCK"),
    "ufw_allow_lines": n("G_FW_ALLOW"), "ufw_audit_lines": n("G_FW_AUDIT"),
}]
correlation, caveats = [], []

if E["G_IDS_OK"] == "1":
    crit, high, med, low, info = (E["G_IDS_SEV"].split() + ["0"] * 5)[:5]
    ids = {
        "pde_source": "ids", "product": "slips", "file": "ids_%s.alerts.log" % stamp,
        "sha256": E["G_IDS_SHA"], "evidence_lines": n("G_IDS_KEPT"),
        "evidence_lines_seen_total": n("G_IDS_TOTAL"), "alerts": n("G_IDS_ALERTS"),
        "threat_levels": {"critical": int(crit), "high": int(high), "medium": int(med),
                          "low": int(low), "info": int(info)},
    }
    remote = E["G_IDS_REMOTE"] == "1"
    if remote:
        ids["analysed"] = "on %s, by Slips in file mode, from this window's packets only" % E["G_VM"]
        ids["input_pcap"] = {"file": "ids_%s.pcap" % stamp, "sha256": E["G_IDS_PCAP_SHA"],
                             "packets": n("G_IDS_PCAP_PACKETS")}
        correlation.append(
            "The firewall and IDS items describe the same packets: tcpdump captured %s here while ufw "
            "logged the same traffic crossing the INPUT chain, and Slips analysed that capture — so the "
            "two are independent accounts of one attack rather than one record split in two." % E["G_VETH"])
    else:
        correlation.append(
            "The firewall and IDS items describe the same packets. Slips sniffed %s live while ufw logged "
            "the same traffic crossing the INPUT chain, so the two are independent accounts of one attack "
            "rather than one record split in two." % E["G_VETH"])
    items.append(ids)
    caveats += [
        "firewall.log is RFC 3164 syslog in LOCAL time (%s, %s, no year, whole seconds) while "
        "ids.alerts.log is RFC 3339 in UTC with microseconds. The same instant reads differently "
        "between them, and neither has been rewritten. window.start_utc/end_utc are UTC and are the "
        "common reference; the firewall manifest carries the conversion facts" % (E["G_TZ_NAME"], E["G_TZ_OFFSET"]),
        "IDS findings are sliced to the window by the timestamp on each evidence line; a line whose "
        "timestamp cannot be parsed is kept rather than dropped",
        "alerts counts Slips' own verdict lines ('Generated an alert given enough evidence on timewindow "
        "N'). They carry no threat level, so threat_levels does not include them",
    ]
    if remote:
        caveats.append(
            "Slips analysed this window on its own, starting fresh: its per-source profile and alert "
            "threshold do not carry over from earlier windows, as they would for a Slips sniffing "
            "continuously. An alert here was earned inside this window. The packets keep the timestamps "
            "this machine's kernel gave them, on the same clock as the window bounds")
    else:
        caveats.append(
            "Slips keeps its own 1-hour timewindows internally and its alert threshold accumulates per "
            "profile across that hour, not across this %ss window" % E["G_DURATION"])

if E.get("G_BANK_MANIFEST"):
    bm = json.load(open(E["G_BANK_MANIFEST"]))
    out, col, comp = bm["output"], bm["collection"], bm["completeness"]
    events_file, audit_file = "banking-events_%s.jsonl" % stamp, "banking-audit_%s.jsonl" % stamp
    items.append({
        "pde_source": "banking-events", "product": "fineract", "file": events_file,
        "sha256": out[events_file]["sha256"], "events": col["banking-events"]["events_in_window"],
        "by_type": col["banking-events"]["by_type"], "completeness": comp["banking-events"],
    })
    items.append({
        "pde_source": "banking-audit", "product": "fineract", "file": audit_file,
        "sha256": out[audit_file]["sha256"], "rows": col["banking-audit"]["rows"],
        "by_maker": col["banking-audit"]["by_maker"], "completeness": comp["banking-audit"],
    })
    sc = bm["scenario"]
    if sc.get("attacker_ip") and sc.get("attacker_used_login"):
        correlation.append(
            "The banking items record what the same users did at the bank. They reached it from their own "
            "addresses through the lab's tunnel on %s:%s, so the attacker (%s) appears in the firewall log "
            "as permitted connections to port %s and in the traffic the IDS analysed, and what those "
            "connections did appears in the bank's audit trail under the login they used (%s) and in its "
            "event stream." % (E["G_TARGET_IP"], E["G_BANK_PORT"], sc["attacker_ip"], E["G_BANK_PORT"],
                              sc["attacker_used_login"]))
    else:
        correlation.append("The banking items record the same users' activity at the bank in this window.")
    caveats.append(
        "banking timestamps are UTC from the bank's clock on the research VM, not this machine's; the "
        "banking manifest records the measured offset (bank_minus_lab_seconds) and how to read each field")

if E.get("G_AUTH_OK") == "1":
    items.append({
        "pde_source": "auth", "product": "openssh-sshd",
        "file": "auth_%s.log" % stamp, "sha256": E["G_AUTH_SHA"],
        "accepted_logins": n("G_AUTH_ACCEPTED"), "failed_attempts": n("G_AUTH_FAILED"),
        "meta_file": "auth_%s.meta.json" % stamp,
    })
    correlation.append(
        "The auth item is the session everything else in this window arrived inside. The users' "
        "packets reached %s over the tunnel device %s, which exists only within an authenticated "
        "SSH session to the VM, and that session's login is what this item records. It is the only "
        "source here that points at a person rather than at an address or an application login."
        % (E["G_TARGET_IP"], E["G_TUN_DEV"]))
    caveats += [
        "the auth item deliberately reaches back past window.start_utc. The tunnel is opened when "
        "the lab is built and carries every window after it, so the login that authorised this "
        "window predates it, and an item holding only the window would read as 'nobody "
        "authenticated'. The establishing session's lines and the window's own are separated by "
        "### marker lines, which are the collector's and not sshd's",
        "sshd records the session's source in Google's IAP forwarder range (35.235.240.0/20), not "
        "the address the analyst sat at. The real client address and the Google identity are in "
        "Cloud Audit Logs, which this window does not collect - see Auth/README.md",
        "every remote command the lab runs opens its own SSH session, so most accepted logins in a "
        "window are the lab working rather than a person. The tunnel's own session is identified by "
        "the pids recorded in auth_<ts>.meta.json",
    ]

if E.get("G_VIA_TUNNEL") == "1":
    caveats.append(
        "the firewall item is ufw on %s, not on the machine that generated the traffic. The users' "
        "packets keep their own source addresses across the tunnel device, so the VM's INPUT chain "
        "logged them as distinct sources; this machine only forwarded them and its own firewall was "
        "not in the path. One consequence for timing: the firewall, IDS and auth items are all on "
        "the VM's clock, and only the ground truth is on this machine's" % E["G_VM"])

group = {
    "group_id": stamp,
    "window": {"start_utc": E["G_START"], "end_utc": E["G_END"], "duration_seconds": n("G_DURATION"),
               "bounds": "whole seconds, start rounded down and end rounded up"},
    "scenario": {"users": n("G_USERS"), "malicious_users": n("G_MAL_USERS"),
                 "malicious_event_pct": n("G_MAL_PCT"), "attack_profile": E["G_PROFILE"],
                 "seed": n("G_SEED"), "subnet": E["G_SUBNET"]},
    "items": items,
    "correlation": " ".join(correlation),
    "caveats": caveats,
}
json.dump(group, open(sys.argv[1], "w"), indent=2)
PY
fi

# Files are created by root; hand them back to whoever invoked sudo. The window's directory
# too — left root's, it is the one place in output/ its owner cannot add a note to.
if [[ -n "${SUDO_USER:-}" ]]; then
	chown "$SUDO_USER" "$RUN_DIR" "$OUT_LOG" "$MANIFEST" "$GT_JSON" 2>/dev/null || true
	[[ -f "$GROUP_MANIFEST" ]] && chown "$SUDO_USER" "$GROUP_MANIFEST" 2>/dev/null || true
	if [[ $IDS_OK -eq 1 ]]; then
		chown "$SUDO_USER" "$IDS_LOG" 2>/dev/null || true
		[[ -n "$IDS_PCAP" ]] && chown "$SUDO_USER" "$IDS_PCAP" 2>/dev/null || true
		# Slips' tree: under a local lab it is still in use and `lab.sh down` hands it over.
		if [[ $IDS_REMOTE -eq 1 || $LAB_MODE -eq 0 ]]; then
			chown -R "$SUDO_USER" "$SLIPS_OUT" 2>/dev/null || true
		fi
	fi
	chown "$SUDO_USER" "$RUN_DIR"/banking* 2>/dev/null || true
	chown "$SUDO_USER" "$RUN_DIR"/auth_* 2>/dev/null || true
fi

log "captured $LOG_LINES lines ($BLOCKED BLOCK, $ALLOWED ALLOW)"
[[ $IDS_OK -eq 1 ]] && log "IDS: ${IDS_KEPT} lines in the window, ${IDS_ALERTS} of them alerts"
[[ -n "$BANK_SUMMARY" ]] && log "$BANK_SUMMARY"
log "sha256 $SHA256"
log "window directory: $RUN_DIR"
log "  firewall_${STAMP}.log              the evidence"
log "  firewall_${STAMP}.manifest.json    provenance and digest"
log "  firewall_${STAMP}.groundtruth.json labels, known before sending"
if [[ $IDS_OK -eq 1 ]]; then
	log "  ids_${STAMP}.alerts.log            IDS evidence for the same window"
	[[ -n "$IDS_PCAP" ]] && log "  ids_${STAMP}.pcap                  the packets Slips analysed"
fi
if [[ $WITH_BANKING -eq 1 ]]; then
	log "  banking-events_${STAMP}.jsonl      the bank's business events"
	log "  banking-audit_${STAMP}.jsonl       the bank's audit trail"
	log "  banking_${STAMP}.manifest.json     provenance, completeness, digests"
fi
if [[ $AUTH_OK -eq 1 ]]; then
	log "  auth_${STAMP}.log                  who opened the session it arrived in"
	log "  auth_${STAMP}.meta.json            provenance, the tunnel session, digest"
fi
[[ -f "$GROUP_MANIFEST" ]] && log "  window_${STAMP}.group.json         every source, one window"

if [[ $CAPTURE_ERRORS -ne 0 ]]; then
	echo "the capture completed with errors: a source above produced no evidence for this window" >&2
	exit 1
fi
