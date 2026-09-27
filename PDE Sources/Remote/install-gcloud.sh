#!/usr/bin/env bash
# ==============================================================
#  One-time setup: a native Linux gcloud for the lab, and the
#  named configuration it talks to the research VM through.
#
#  Run as yourself, not with sudo. Run it twice:
#    1. installs the SDK and creates the configuration
#    2. after you have logged in, records the account and checks
#       the VM can actually be reached
#
#    Remote/install-gcloud.sh
#    ~/google-cloud-sdk/bin/gcloud auth login --no-launch-browser
#    Remote/install-gcloud.sh
#
#  Nothing here activates a configuration or edits your shell's
#  PATH. The lab finds this SDK by path (vm-lib.sh), so the
#  Windows gcloud WSL exposes on PATH is left exactly as it was.
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lab-config.sh
source "$PDE_ROOT/lab-config.sh"

[[ $EUID -ne 0 ]] || { echo "run this as yourself, not root: credentials belong in your home" >&2; exit 1; }

SDK="$HOME/google-cloud-sdk"
G="$SDK/bin/gcloud"
cfg() { CLOUDSDK_ACTIVE_CONFIG_NAME="$VM_GCLOUD_CONFIG" "$G" "$@"; }

if [[ ! -x "$G" ]]; then
	echo "installing the Google Cloud CLI into $SDK"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	curl -fsSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz \
		-o "$tmp/sdk.tgz"
	tar -xzf "$tmp/sdk.tgz" -C "$HOME"
	"$SDK/install.sh" --quiet --usage-reporting=false --path-update=false \
		--command-completion=false >/dev/null
fi
echo "gcloud: $("$G" --version 2>/dev/null | head -1)"

if ! "$G" config configurations describe "$VM_GCLOUD_CONFIG" >/dev/null 2>&1; then
	"$G" config configurations create "$VM_GCLOUD_CONFIG" --no-activate >/dev/null
	echo "created configuration $VM_GCLOUD_CONFIG (not activated)"
fi
cfg config set project "$VM_PROJECT" >/dev/null 2>&1 || true
# Tolerated: gcloud validates a zone through the API, which fails before login, and under
# set -e that silently ended this script before it could say how to log in. Nothing depends
# on it — every call passes --zone.
cfg config set compute/zone "$VM_ZONE" >/dev/null 2>&1 || true

account="$("$G" auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)"
if [[ -z "$account" ]]; then
	echo
	echo "Not logged in yet. Log in, then run this script again:"
	echo "  $G auth login --no-launch-browser"
	exit 0
fi
cfg config set account "$account" >/dev/null 2>&1
echo "account: $account"

status="$(cfg compute instances describe "$VM_NAME" --zone "$VM_ZONE" --format='value(status)' 2>/dev/null || true)"
case "$status" in
	RUNNING)
		if cfg compute ssh "$VM_USER@$VM_NAME" --zone "$VM_ZONE" --tunnel-through-iap --quiet \
			--command true -- -T -o LogLevel=ERROR </dev/null >/dev/null 2>&1; then
			echo "VM $VM_NAME: running and reachable over IAP — setup complete"
		else
			echo "VM $VM_NAME is running but SSH over IAP failed; try: $G compute ssh $VM_NAME --tunnel-through-iap --configuration=$VM_GCLOUD_CONFIG"
			exit 1
		fi ;;
	"")
		echo "cannot see $VM_NAME in $VM_PROJECT as $account — wrong account, or no access to the project"
		exit 1 ;;
	*)
		echo "VM $VM_NAME is $status. Setup is complete; './vm.sh start' brings it up." ;;
esac
