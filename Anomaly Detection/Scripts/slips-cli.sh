#!/usr/bin/env bash
# ==============================================================
#  SLIPS LAB CONSOLE
#
#  Interactive front end for the Slips demo: start/stop the stack,
#  simulate a chosen attack, and read the resulting evidence with
#  severity colouring.
#
#  Usage:  bash "Anomaly Detection/Scripts/slips-cli.sh"
# ==============================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORMAT="$SCRIPT_DIR/slips-format.py"
OUT="${SLIPS_OUT:-$HOME/slips-lab/cli-out}"
IMG="stratosphereips/slips:latest"
IFACE="${SLIPS_IFACE:-eth0}"

# ---- palette -------------------------------------------------
C_TITLE=$'\033[1;38;5;74m'
C_DIM=$'\033[38;5;244m'
C_OK=$'\033[38;5;72m'
C_WARN=$'\033[38;5;179m'
C_ERR=$'\033[38;5;167m'
C_KEY=$'\033[38;5;179m'
C_NUM=$'\033[1;38;5;110m'
C_RULE=$'\033[38;5;238m'
R=$'\033[0m'

rule() { printf '%s%s%s\n' "$C_RULE" "──────────────────────────────────────────────────────────────" "$R"; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$R" "$*"; }
err()  { printf '  %s✗%s %s\n' "$C_ERR" "$R" "$*"; }
head_(){ printf '\n%s%s%s\n' "$C_TITLE" "$*" "$R"; }
pause(){ printf '\n%s  press enter to continue%s' "$C_DIM" "$R"; read -r _; }

running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

# Slips runs as root inside the container, so everything it writes into the
# bind mount is root-owned on the host — including the databases/ and redis/
# subdirectories. Removing files from those needs write permission on the
# *directory*, which the host user does not have, so a plain `rm -rf` fails
# with "Permission denied". Clearing from inside a container sidesteps it
# without asking for sudo.
reset_output() {
    mkdir -p "$OUT"
    docker run --rm -v "$OUT":/output "$IMG" \
        bash -c 'rm -rf /output/* /output/.[!.]* 2>/dev/null; exit 0' >/dev/null 2>&1
}

host_ip() { ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
gateway() { ip route 2>/dev/null | awk '/default/{print $3; exit}'; }

# NOTE: `grep -c` prints 0 *and* exits 1 when there are no matches, so the
# obvious `grep -c ... || echo 0` emits "0\n0". Two values where one was
# expected then shifts every later printf argument. Count into a variable
# instead and emit exactly one line.
count_matches() {   # count_matches <file> <grep-args...>
    local file="$1"; shift
    local n=0
    [ -f "$file" ] && n=$(grep -c "$@" "$file" 2>/dev/null)
    printf '%s' "${n:-0}"
}
flow_count()     { count_matches "$OUT/zeek_files/conn.log" -v '^#'; }
evidence_count() { count_matches "$OUT/alerts/alerts.log" '.'; }
sev_count()      { count_matches "$OUT/alerts/alerts.log" "Threat level: $1"; }
# Pulled from the run's own log rather than assumed, so the banner always
# reflects what this instance actually decided.
local_net()  { grep -hoE "Used local network: \S+" "$OUT/slips.log" 2>/dev/null | tail -1 | awk '{print $4}'; }
threshold()  { grep -hoE "Using threshold: [0-9.]+" "$OUT/slips.log" 2>/dev/null | tail -1 | awk '{print $3}'; }
alert_count() {
    # A formal alert is logged separately from individual evidence.
    count_matches "$OUT/alerts/alerts.json" '"alert_ID"'
}

# ---- status banner -------------------------------------------
banner() {
    clear
    rule
    printf '%s  SLIPS LAB CONSOLE%s\n' "$C_TITLE" "$R"
    rule
    local sl rd
    if running slips; then sl="${C_OK}running${R}"; else sl="${C_DIM}stopped${R}"; fi
    if running slips-redis; then rd="${C_OK}running${R}"; else rd="${C_DIM}stopped${R}"; fi
    printf '  slips %-22b redis %-22b\n' "$sl" "$rd"
    printf '  %sinterface%s %-12s %shost%s %-16s %sgateway%s %s\n' \
        "$C_DIM" "$R" "$IFACE" "$C_DIM" "$R" "$(host_ip)" "$C_DIM" "$R" "$(gateway)"
    if running slips; then
        local hi md lo inf net thr breakdown
        hi=$(sev_count high); md=$(sev_count medium)
        lo=$(sev_count low);  inf=$(sev_count info)
        net="$(local_net)"; thr="$(threshold)"

        # Assembled as single strings, then printed with one %s each: an
        # argument count can no longer drift out of step with the format.
        breakdown="${C_ERR}${hi} high${R}  ${C_WARN}${md} medium${R}  ${C_OK}${lo} low${R}  ${C_DIM}${inf} info${R}"
        printf '  %s\n' "${C_DIM}flows${R} ${C_KEY}$(flow_count)${R}   ${C_DIM}evidence${R} ${C_KEY}$(evidence_count)${R}   ${C_DIM}(${R}${breakdown}${C_DIM})${R}"
        printf '  %s\n' "${C_DIM}alert threshold${R} ${C_KEY}${thr:-0.25}${R}   ${C_DIM}timewindow${R} 1h   ${C_DIM}local net${R} ${net:-detecting...}   ${C_DIM}alerts raised${R} ${C_KEY}$(alert_count)${R}"
    fi
    rule
}

# ---- lifecycle -----------------------------------------------
start_stack() {
    head_ "Starting the stack"

    if running slips; then
        warn "Slips is already running. Stop it first (option 2) to restart clean."
        pause; return
    fi

    mkdir -p "$OUT"
    if [ -z "$(host_ip)" ]; then
        err "interface '$IFACE' not found. Available:"
        ip -brief -4 addr show | sed 's/^/    /'
        pause; return
    fi

    # Redis holds all Slips state and is the pub/sub bus between its ~18
    # processes. v1.1.22 also crashes if it has to start Redis itself, so
    # it must already be listening on 6379 before Slips launches.
    if ! running slips-redis; then
        dim "  starting redis on 127.0.0.1:6379 ..."
        docker rm -f slips-redis >/dev/null 2>&1
        docker run -d --net=host --name slips-redis "$IMG" \
            /redis-stable/src/redis-server config/redis.conf.template \
            --port 6379 --bind 127.0.0.1 --daemonize no >/dev/null
        for _ in $(seq 1 20); do
            docker exec slips-redis /redis-stable/src/redis-cli -p 6379 ping 2>/dev/null \
                | grep -q PONG && break
            sleep 1
        done
        ok "redis ready"
    else
        ok "redis already running"
    fi

    dim "  clearing previous capture ..."
    reset_output
    docker rm -f slips >/dev/null 2>&1
    docker run -d --net=host --cap-add=NET_ADMIN --name slips \
        -v "$OUT":/output "$IMG" ./slips.py -i "$IFACE" -o /output >/dev/null

    dim "  loading 15 modules and 45+ threat-intel feeds (~80s) ..."
    printf '  '
    for _ in $(seq 1 40); do
        docker logs slips 2>&1 | grep -q "Started Input Process" && break
        printf '%s·%s' "$C_DIM" "$R"; sleep 5
    done
    printf '\n'

    if running slips; then
        ok "Slips is live on $IFACE"
        docker logs slips 2>&1 \
            | grep -E "Detected host IP|Using redis server|local network" \
            | sed "s/^/    ${C_DIM}/;s/$/${R}/"
    else
        err "Slips exited. Last lines:"
        docker logs slips 2>&1 | tail -12 | sed 's/^/    /'
    fi
    pause
}

stop_stack() {
    head_ "Stopping"
    docker rm -f slips slips-redis >/dev/null 2>&1
    ok "slips and redis removed"
    dim "  captured output kept at $OUT"
    pause
}

require_running() {
    if ! running slips; then
        err "Slips is not running — start it first (option 1)."
        pause; return 1
    fi
    return 0
}

# ---- attack simulations --------------------------------------
attack_menu() {
    require_running || return
    local gw; gw="$(gateway)"
    local subnet; subnet="$(host_ip | cut -d. -f1-3)"

    while true; do
        banner
        head_ "Simulate traffic"
        dim "  each option generates real packets on $IFACE"
        echo
        printf '  %s1%s  Vertical port scan      %s70 ports on %s — expect \"vertical port scan\", high%s\n'   "$C_NUM" "$R" "$C_DIM" "$gw" "$R"
        printf '  %s2%s  Horizontal port scan    %sport 445 across %s.1-60 — expect horizontal scan%s\n'      "$C_NUM" "$R" "$C_DIM" "$subnet" "$R"
        printf '  %s3%s  ICMP ping sweep         %sping %s.1-40 — expect \"ICMP address scan\"%s\n'           "$C_NUM" "$R" "$C_DIM" "$subnet" "$R"
        printf '  %s4%s  DNS burst               %s20 lookups — feeds dns.log, may flag DNS-without-connection%s\n' "$C_NUM" "$R" "$C_DIM" "$R"
        printf '  %s5%s  Normal browsing         %sbaseline traffic, should raise nothing%s\n'                 "$C_NUM" "$R" "$C_DIM" "$R"
        printf '  %s6%s  Long connection         %sheld 60s — C&C-style persistence%s\n'                       "$C_NUM" "$R" "$C_DIM" "$R"
        printf '  %s7%s  Self-signed certificate %srequires Fineract running on 8443%s\n'                      "$C_NUM" "$R" "$C_DIM" "$R"
        echo
        printf '  %s0%s  back\n' "$C_NUM" "$R"
        echo
        printf '  %sselect>%s ' "$C_TITLE" "$R"; read -r a

        case "$a" in
            1) head_ "Vertical port scan"
               dim "  probing 70 TCP ports on a single host — the signature of service discovery"
               for p in $(seq 20 90); do nc -z -w1 "$gw" "$p" 2>/dev/null; done
               ok "scanned ports 20-90 on $gw"; pause ;;
            2) head_ "Horizontal port scan"
               dim "  probing one port across many hosts — the signature of finding vulnerable machines"
               for h in $(seq 1 60); do nc -z -w1 "$subnet.$h" 445 2>/dev/null; done
               ok "probed port 445 across $subnet.1-60"; pause ;;
            3) head_ "ICMP ping sweep"
               dim "  mapping which hosts are alive before choosing a target"
               for h in $(seq 1 40); do ping -c1 -W1 "$subnet.$h" >/dev/null 2>&1 & done; wait
               ok "swept $subnet.1-40"; pause ;;
            4) head_ "DNS burst"
               dim "  resolving many names quickly; names never connected to look like beaconing"
               for d in a b c d e f g h i j k l m n o p q r s t; do
                   dig +short +time=1 +tries=1 "$d.example.com" >/dev/null 2>&1
               done
               ok "20 DNS lookups issued"; pause ;;
            5) head_ "Normal browsing"
               curl -s -o /dev/null --max-time 5 https://example.com   && ok "https://example.com"
               curl -s -o /dev/null --max-time 5 https://wikipedia.org && ok "https://wikipedia.org"
               ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1                  && ok "ping 8.8.8.8"
               dim "  this is the control case — it should not raise anything above info"
               pause ;;
            6) head_ "Long connection"
               dim "  holding a session open; sustained links are a C&C indicator"
               (nc -w 60 8.8.8.8 53 >/dev/null 2>&1 &)
               ok "connection to 8.8.8.8:53 held for 60s in the background"; pause ;;
            7) head_ "Self-signed certificate"
               if curl -k -s -o /dev/null --max-time 5 https://localhost:8443/fineract-provider/actuator/health; then
                   ok "connected to Fineract over its self-signed cert"
                   dim "  flow_alerts should record a self-signed certificate finding"
               else
                   err "Fineract is not responding on 8443"
                   dim "  start it with: bash Fineract/Scripts/fineract-up.sh"
               fi
               pause ;;
            0|q) return ;;
            *) ;;
        esac
    done
}

# ---- viewers -------------------------------------------------
view_evidence() {
    require_running || return
    banner
    head_ "Evidence — notable findings first"
    if [ -s "$OUT/alerts/alerts.log" ]; then
        python3 "$FORMAT" --brief < "$OUT/alerts/alerts.log"
    else
        dim "  nothing yet. Slips batches evidence — wait ~60s after generating traffic."
    fi
    pause
}

view_evidence_full() {
    require_running || return
    banner
    head_ "Evidence — full chronological"
    if [ -s "$OUT/alerts/alerts.log" ]; then
        python3 "$FORMAT" < "$OUT/alerts/alerts.log" | tail -60
    else
        dim "  nothing yet."
    fi
    pause
}

view_flows() {
    require_running || return
    banner
    head_ "Flows Zeek derived from packets"
    for f in conn dns ssl http; do
        [ -f "$OUT/zeek_files/$f.log" ] || continue
        printf '  %s%-10s%s %s%s%s entries\n' "$C_DIM" "$f.log" "$R" \
            "$C_KEY" "$(grep -vc '^#' "$OUT/zeek_files/$f.log")" "$R"
    done

    head_ "Most recent connections"
    grep -v '^#' "$OUT/zeek_files/conn.log" 2>/dev/null | tail -12 | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        f = json.loads(line)
        st = f.get("conn_state","")
        # S0 = no reply at all, the fingerprint of a probe against a closed port
        mark = "\033[38;5;179m probe\033[0m" if st == "S0" else ""
        print("    %-16s -> %-16s %-5s %-6s %s%s" % (
            f.get("id.orig_h",""), f.get("id.resp_h",""),
            f.get("proto",""), f.get("service","") or "-", st, mark))
    except Exception: pass' 2>/dev/null

    head_ "TLS server names seen"
    grep -v '^#' "$OUT/zeek_files/ssl.log" 2>/dev/null | python3 -c '
import sys, json
seen=set()
for line in sys.stdin:
    try:
        s=json.loads(line).get("server_name","")
        if s and s not in seen: seen.add(s); print("    "+s)
    except Exception: pass' 2>/dev/null | head -8
    pause
}

view_profile() {
    require_running || return
    banner
    head_ "Behavioural profile for $(host_ip)"
    dim "  Slips profiles LOCAL hosts only; external destinations are recorded"
    dim "  inside this profile rather than getting profiles of their own."
    echo
    docker exec slips-redis /redis-stable/src/redis-cli -p 6379 -n 0 \
        keys "profile_$(host_ip)*" 2>/dev/null | head -20 | sed 's/^/    /'
    echo
    dim "  'not_estab' across many dstports is a scan recorded as behaviour,"
    dim "  not as a signature match."
    pause
}

view_settings() {
    banner
    head_ "How Slips decides something is malicious"
    dim "  Modules raise EVIDENCE. Evidence accumulates per profile (one IP address),"
    dim "  per timewindow (one hour). When the accumulated threat for that IP in that"
    dim "  hour crosses the threshold, it becomes an ALERT."

    head_ "Threat levels and what they contribute"
    printf '    %s■ critical%s  weightiest — near-certain compromise\n'  "$C_ERR"  "$R"
    printf '    %s▲ high%s      strong signal, e.g. a confirmed port scan\n' "$C_ERR"  "$R"
    printf '    %s▲ medium%s    suspicious, e.g. probing an unknown port\n'  "$C_WARN" "$R"
    printf '    %s▪ low%s       mild\n'                                      "$C_OK"   "$R"
    printf '    %s· info%s      context only, e.g. talking to a private IP\n' "$C_DIM" "$R"

    head_ "Current settings"
    local thr net
    thr="$(threshold)"; net="$(local_net)"
    printf '    %s%-28s%s %s\n' "$C_DIM" "evidence_detection_threshold" "$R" "${thr:-0.25} (from this run)"
    printf '    %s%-28s%s %s\n' "$C_DIM" "time_window_width"            "$R" "3600s (1 hour)"
    printf '    %s%-28s%s %s\n' "$C_DIM" "local network"                "$R" "${net:-not detected yet}"
    printf '    %s%-28s%s %s\n' "$C_DIM" "redis (analysis / cache)"     "$R" "db0 / db1 on port 6379"

    head_ "Threshold options, from Slips' own config"
    printf '    %s0.08%s  super sensitive — more true positives, many more false ones\n' "$C_KEY" "$R"
    printf '    %s0.25%s  optimal — best balance of FPR and TPR %s(the default in use)%s\n' "$C_KEY" "$R" "$C_DIM" "$R"
    printf '    %s0.43%s  insensitive — only flags the most obvious cases\n' "$C_KEY" "$R"
    dim "    change via evidence_detection_threshold in config/slips.yaml"

    head_ "Why profiles only exist for local hosts"
    dim "    Slips profiles addresses inside ${net:-the detected local network}."
    dim "    Visiting example.com creates no profile for its IP — that connection"
    dim "    is recorded inside YOUR host's profile as an outbound tuple instead."
    pause
}

live_tail() {
    require_running || return
    banner
    head_ "Live evidence — ctrl-c to return"
    dim "  new findings appear as Slips raises them; there may be a pause between batches"
    echo

    # --stream so each finding prints on arrival; the default mode buffers all
    # of stdin to sort it, which never returns against `tail -f`.
    # Ctrl-C is the intended exit, so trap it rather than letting it escape.
    trap ':' INT
    tail -f -n 15 "$OUT/alerts/alerts.log" 2>/dev/null | python3 -u "$FORMAT" --stream
    trap - INT

    echo
    pause
}

# ---- main menu -----------------------------------------------
main_menu() {
    while true; do
        banner
        printf '  %s1%s  Start Slips + Redis\n'        "$C_NUM" "$R"
        printf '  %s2%s  Stop everything\n'            "$C_NUM" "$R"
        echo
        printf '  %s3%s  Simulate traffic / attacks\n' "$C_NUM" "$R"
        echo
        printf '  %s4%s  View evidence %s(notable first)%s\n'  "$C_NUM" "$R" "$C_DIM" "$R"
        printf '  %s5%s  View evidence %s(full log)%s\n'       "$C_NUM" "$R" "$C_DIM" "$R"
        printf '  %s6%s  View captured flows\n'                "$C_NUM" "$R"
        printf '  %s7%s  View behavioural profile\n'           "$C_NUM" "$R"
        printf '  %s8%s  Live evidence tail\n'                 "$C_NUM" "$R"
        echo
        printf '  %s9%s  How detection works %s(threshold, threat levels, settings)%s\n' "$C_NUM" "$R" "$C_DIM" "$R"
        echo
        printf '  %s0%s  Quit %s(leaves containers running)%s\n' "$C_NUM" "$R" "$C_DIM" "$R"
        echo
        printf '  %sselect>%s ' "$C_TITLE" "$R"; read -r choice || return

        case "$choice" in
            1) start_stack ;;
            2) stop_stack ;;
            3) attack_menu ;;
            4) view_evidence ;;
            5) view_evidence_full ;;
            6) view_flows ;;
            7) view_profile ;;
            8) live_tail ;;
            9) view_settings ;;
            0|q|Q) clear; dim "containers left running — option 2 stops them"; return ;;
            *) ;;
        esac
    done
}

# ---- preflight -----------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    err "docker not found on PATH"; exit 1
fi
if ! docker info >/dev/null 2>&1; then
    err "cannot reach the docker daemon"
    dim "  native engine: sudo systemctl start docker"
    exit 1
fi
for t in nc dig curl ping python3; do
    command -v "$t" >/dev/null 2>&1 || warn "$t not found — some options will not work"
done

main_menu
