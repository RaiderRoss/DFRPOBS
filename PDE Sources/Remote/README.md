# The research VM

The lab is split across two machines, and the split falls where the machines differ:

| here (WSL) | there (GCP VM `fineract-slips`, `africa-south1-a`) |
|---|---|
| ufw, the namespace, the traffic — they *are* this host's firewall and network | Fineract (pinned compose, with Kafka) |
| the IDS **sensor**: tcpdump on the veth, all session | the IDS **analysis**: Slips, once per window |
| the console | the Evidence Repository |

The firewall has to be local — the evidence is this machine's kernel logging packets
crossing its own INPUT chain. Everything heavy that is not tied to this host (about
10 GB of JVMs, Kafka, Postgres, MinIO and Slips) lives on the VM.

```
namespace 10.99.0.x ── veth ── 10.99.0.1 ──┬── ufw INPUT (logged)
                                            ├── tcpdump ──── window pcap ──► Slips on the VM
                                            └── :8443 bank tunnel ─ IAP ─► Fineract on the VM
this machine ── 127.0.0.1:18080 admin tunnel ─ IAP ─► Evidence Repository on the VM
```

## One-time setup

```bash
Remote/install-gcloud.sh                                   # a native Linux gcloud + the configuration
~/google-cloud-sdk/bin/gcloud auth login --no-launch-browser
Remote/install-gcloud.sh                                   # records the account, checks the VM
./vm.sh start                                              # the VM and its stack (~4 min)
./vm.sh seed                                               # prepare the bank; writes Banking/seed.json here
```

The Linux SDK is needed even though WSL already finds a `gcloud`: that one is the
*Windows* SDK leaking in through PATH. It keeps its login on the Windows side, disappears
under `sudo`, and hands SSH to PuTTY.

Every call names the configuration (`fineract-research`) per process and never activates
it, so nothing here can change which project the machine's default configuration points
at.

## Day to day

```bash
./vm.sh start      # VM, then Fineract and the repository (~4 min); Slips' cache warms behind it
./pde              # the console; its sources screen also starts and stops the VM
./vm.sh stop       # when done — a stopped VM costs only its disk
```

| | |
|---|---|
| `./vm.sh status` | up? reachable? which checkout? tunnels open? bank seeded? |
| `./vm.sh sync` | ship this branch's **committed** HEAD to the VM (a git bundle — the VM holds no GitHub credential) |
| `./vm.sh tunnel up` | the repository on `localhost:18080`, Fineract on `localhost:18443` |
| `./vm.sh ssh` | a shell there, as `pde` |

To browse the repository's frontend, forward its real ports (its CORS rule names
`localhost:5173` exactly):

```bash
~/google-cloud-sdk/bin/gcloud compute ssh pde@fineract-slips --tunnel-through-iap \
  --configuration=fineract-research -- -N -L 5173:localhost:5173 -L 8080:localhost:8080
```

## Things to know

**Nothing on the VM is reachable from the internet.** The only firewall rule admits
port 22 from Google's IAP range (`35.235.240.0/20`), so a connection has to pass a Google
login check before it reaches the VM. Everything else rides inside that SSH connection.
This matters more than usual: Fineract's compose publishes 8443 (default credentials),
5432 and a Java debugger on 0.0.0.0, and Docker bypasses host firewalls — the GCP firewall
is the only thing in front of them.

**One VM account, `pde`, for everyone.** gcloud would otherwise log in as whatever your
local username is — different in Windows and WSL, different for each teammate — and land
in an empty home. Each person's key maps onto `pde`, which holds the checkout and is in
the `docker` group.

**Slips' first run after a start is slow unless warmed.** Slips caches about 45
threat-intel feeds in redis; against an empty cache a run downloads them all first
(7 minutes, measured), against a warm one it analyses a window in about one. A VM stop
empties redis, so `stack-up.sh` re-warms it in the background after every start, and the
capture's preflight says so if it is still warming.

**The MinIO images are gone.** `minio/minio` and `minio/mc` have been withdrawn from
Docker Hub and quay.io, so the Evidence Repository's compose file cannot start on a
machine without them cached. `er-compose.vm.yml` substitutes Chainguard's builds on the
VM. They have no curl, so MinIO's health check is disabled rather than faked. The base
compose file needs the same fix.

**Image digests** in use are recorded on the VM in `~ltshi/IMAGES.txt` for the write-up.

## Files

| | runs |
|---|---|
| `vm-lib.sh` | here — sourced: gcloud, SSH over IAP, tunnels |
| `install-gcloud.sh` | here — one-time setup |
| `stack-up.sh` | there — the whole stack, after a start |
| `er-up.sh` | there — the Evidence Repository |
| `er-compose.vm.yml` | there — the MinIO substitution |
| `slips-warm.sh` | there — Slips' redis and threat-intel cache |
