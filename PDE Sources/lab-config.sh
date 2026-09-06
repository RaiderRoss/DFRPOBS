#!/usr/bin/env bash
# ==============================================================
#  Shared lab constants.
#
#  Sourced by lab.sh (which builds and tears the lab down) and by
#  simulate-firewall.sh (which captures windows against it). Kept
#  in one file because the port lists interact: PRESERVE_PORTS
#  deliberately overlaps MALICIOUS_PORTS, and rule ORDER is what
#  keeps that from mislabelling the dataset. Two copies of these
#  drifting apart would reintroduce that bug silently.
#
#  Defines variables only — no side effects.
# ==============================================================

# Where a running lab records what it changed, so it can be undone later. Inside the
# repo rather than /tmp on purpose: `D /tmp` in tmpfiles.d means /tmp is cleared on
# boot, which would destroy the restore data at exactly the moment a crashed session
# needs it. Gitignored.
LAB_DIR="${LAB_DIR:-$PDE_ROOT/.lab}"
LAB_STATE="$LAB_DIR/state.env"

# Test subnet. Deliberately not a range anything else on this host uses, so extraction
# can separate simulated traffic from whatever else the firewall happens to log.
SUBNET="10.99.0.0/24"
HOST_IP="10.99.0.1"
USER_IP_BASE="10.99.0."
USER_IP_OFFSET=10          # first user is 10.99.0.11

NS="pde-fw"
VETH_HOST="veth-pde-h"
VETH_NS="veth-pde-n"

# Ports the firewall permits — ordinary application traffic.
BENIGN_PORTS="80,443,8080"

# Ports the firewall denies — the sweep an attacker runs looking for a way in.
#
# Deliberately wide. The firewall logs a BLOCK however few ports are touched, but an
# IDS decides "vertical port scan" from the number of DISTINCT ports one source reaches
# for on one host inside a timewindow — measured at around 10 for Slips. A thin list
# leaves the IDS silent about an attack the firewall recorded plainly, which is the
# opposite of the correlation this exists to demonstrate. None may overlap BENIGN_PORTS.
MALICIOUS_PORTS="21,22,23,25,53,110,111,135,137,139,143,161,389,445,512,513,514,873,993,995,1080,1433,1521,2049,2375,3306,3389,5060,5432,5900,6379,8443,9200,11211,27017"

# Host services kept reachable while ufw is up, so a default-deny firewall does not cut
# off the dev stack or the Windows host's access to it. Overlaps MALICIOUS_PORTS on 22
# and 5432 — see the rule ordering in lab.sh, which is what stops that overlap
# mislabelling attacker traffic as permitted.
PRESERVE_PORTS="22,5432,5433,8080,9000,9001,19092,8081"

UFW_LOG="/var/log/ufw.log"
KERN_LOG="/var/log/kern.log"
