# The SSH tunnel device, and why the evidence moves to the VM

The lab used to reach Fineract through a port forward: `-L 10.99.0.1:8443 -> the VM`. That
works for talking to the bank and is useless as evidence, because a forward's far end opens
its own connection. Every request arrived at the VM from the VM. Ten simulated users were
one address there, so the VM could not have been the firewall or the IDS — which is why ufw
and the packet sensor had to stay on the lab machine, and why the two ends ran on two clocks.

`ssh -w` carries a **layer-3 tun interface** inside the same IAP session instead. The
namespace's packets are routed onto it, so they arrive at the VM with the addresses they
left with:

```
WSL                                                     VM (fineract-slips)
  namespace 10.99.0.11-.20
        │  (their own source addresses, never rewritten)
     veth 10.99.0.1
        │  forwarded, not answered
     tun7 10.98.0.2 ═══ ssh -w, inside the IAP session ═══ tun7 10.98.0.1
                                                             │
                                                        ufw INPUT   ← firewall evidence
                                                        Slips       ← IDS, live on tun7
                                                        relay :8443 ← bank calls, on INPUT
                                                        sshd log    ← who opened the tunnel
```

Nothing new is exposed. The tunnel rides the one port the GCP firewall already admits (22,
from IAP's `35.235.240.0/20`), so the VM is still reachable only behind a Google login check.

## Why this is the realistic option

A bank's core banking back office is never on the internet. Staff reach it from inside or
over remote access, and the most common way into a real bank is a phished credential used
through that remote-access channel — which is exactly what the `loan-fraud` scenario models.
IAP plays the part of the bank's VPN gateway, and the tunnel is the officer arriving the way
a remote officer would.

It also opens a source the lab did not have. Every tunnel begins with an authenticated
login, recorded by the VM's sshd: who connected, when, as whom. That fills the empty
Authentication row in the sources table, and gives the investigation its first link —
*this login opened the session → from this address → which scanned the host → and logged
into the bank as `pde_officer`.*

The alternatives were weighed and rejected: whitelisting a home IP collapses all ten users
into one NATed address (and still misses the bank calls, which never cross INPUT); a second
attacker VM models post-foothold lateral movement rather than initial access, and costs a
machine.

## Addressing

`10.98.0.0/30`, deliberately **not** inside `SUBNET`. The lab subnet is directly connected
on the veth, so an address inside it is answered by the lab machine and never reaches the
tunnel. The users have to aim at something this host must route.

| | |
|---|---|
| `TUN_LOCAL_IP` `10.98.0.2` | the lab machine's end |
| `TUN_VM_IP` `10.98.0.1` | the VM's end — **and the address the simulated users target** |
| `TUN_NUM` `7` | `ssh -w` takes a number; the device is `tun7` on both ends |

The namespace gets a `/32` route to `TUN_VM_IP` via the veth (`tun_ns_route_add`). Without
it every connection fails inside the namespace with "Network is unreachable", which looks
exactly like the tunnel being down when it is up.

## The devices are pre-created, persistent, and owned

`ssh -w` does not make interfaces. It opens `/dev/net/tun` and attaches to `tun<N>`, and for
a non-root process that only works if the device already exists and belongs to it. Both ends
therefore create the device with root first:

```bash
ip tuntap add dev tun7 mode tun user <the ssh user>
```

The lab runs under `sudo`, but gcloud's credential lives in the invoking user's home, so
`vm-lib.sh` hands every gcloud call — and the ssh beneath it — back to `SUDO_USER`. A
root-owned device would be unopenable by the very process that needs it, and fails with a
bare `open failed` that says nothing about why.

**The `user` is load-bearing, not cosmetic.** Measured on this kernel (6.18.33.2-WSL2):

| device | attach as an unprivileged user |
|---|---|
| `user ltshikila` | succeeds |
| `user root` | `EPERM` |
| no `user` given | **succeeds** |

`/dev/net/tun` is mode `0666`, and the kernel's ownership check short-circuits when the
owner is unset — so a persistent tun created without `user` can be attached by any local
user on the box, who could then read or inject the lab's traffic. Always pass it.

## The VM's sshd

One drop-in, `/etc/ssh/sshd_config.d/60-pde-tunnel.conf`, with `PermitTunnel
point-to-point` — not `yes`, which would also permit layer-2 tunnels that nothing here
needs. `vm-net.sh` refuses to touch the main config, and refuses outright if the main config
has no `Include` for `sshd_config.d` (the file would otherwise be accepted and silently
ignored, and the tunnel request refused with no sign of why).

It is validated with `sshd -t` **before** anything is loaded, and then **reloaded, never
restarted**. A restart would drop the session running the script, and on a VM whose only
way in is IAP SSH that is not a recoverable mistake.

## The bank relay

Fineract is a Docker-published port. Packets to a published port are rewritten in
`nat/PREROUTING` and cross `FORWARD`, never `INPUT`, so the VM's ufw cannot log them — the
one connection an investigator most wants would be the one missing. `bank-relay.py` listens
on the tun address as an ordinary host process, so the user's connection is delivered
locally, crosses INPUT, and is logged like everything else; then it opens its own connection
to the container.

It passes bytes through and parses nothing, so Fineract's TLS is still negotiated between
the user and Fineract. It holds no key and is not a TLS terminator. It binds one address and
refuses `0.0.0.0`, which would publish the bank — default credentials and all — on every
interface the VM has.

**The relay cannot work unless Fineract's ports are bound to the loopback first.** The
tracked compose file publishes 8443 on `0.0.0.0`, so `docker-proxy` owns the tunnel address
too: the relay fails with `Address already in use`, and — worse — a call to
`10.98.0.1:8443` still *succeeds*, having gone straight to the published port and across
FORWARD where ufw cannot see it. The first tunnel run did exactly that and looked healthy.
`Remote/fineract-compose.vm.yml` binds the publications to `127.0.0.1`, which frees the
address and closes the exposure at the same time. Nothing inside the compose network
changes, and `collect-audit.sh` reaches Postgres through `docker exec` rather than a
published port.

## ufw on the VM

This is the one action here that can end in losing access to the VM, so it fails safe:

- **SSH is permitted first**, before the policy becomes deny. Port 22 from anywhere, because
  the GCP firewall already admits it only from IAP — scoping it again here would lock the VM
  out if Google ever changed that range.
- **`DEFAULT_FORWARD_POLICY=ACCEPT`.** ufw defaults it to DROP, and Docker's
  container-to-container and outbound traffic crosses FORWARD: leaving it would take
  Fineract's own database connection down. The evidence is INPUT, so this costs nothing.
- **A watchdog** disables ufw again after `FW_WATCHDOG_SECONDS` (default 600) unless
  `vm-net.sh firewall-keep` has confirmed the lab still has access. A wrong rule costs a
  wait, not the VM.
- Verdict logging goes in as raw `LOG` rules scoped to `tun7`, because ufw's own `log`
  keyword hardcodes `-m limit --limit 3/min`, which caps a window at ~11 lines per rule
  however much traffic crosses. Same finding as the local lab.

## Bringing it up

One-time, and it cannot be done for you — gcloud's login is interactive:

```bash
~/google-cloud-sdk/bin/gcloud auth login --no-launch-browser
Remote/install-gcloud.sh          # records the account, checks the VM
```

Then:

```bash
./vm.sh start                     # the VM and its stack
./vm.sh sync                      # ship this branch, so the VM has vm-net.sh
sudo ./vm.sh tundev up            # sshd drop-in, both devices, routes, the ssh -w session
sudo ./vm.sh tundev status        # device / session / far end / forwarding
sudo ./vm.sh tundev relay         # the bank on 10.98.0.1:8443
./vm.sh stop                      # a stopped VM costs only its disk
```

`tundev` is the one `vm.sh` subcommand that must be root: it makes an interface, sets a
sysctl and adds routes. gcloud underneath it still runs as the invoking user.

## State of this work

Measured against the VM on 2026-09-30, `fineract-slips` in `africa-south1-a`, over a
30-second window with 10 users and one attacker.

| | |
|---|---|
| tun ownership and unprivileged attach | **verified** on WSL 6.18.33.2 (table above) |
| the relay: passthrough, 300 KB payloads, 30 concurrent connections, `0.0.0.0` refusal | **verified** locally |
| `ssh -w` through `gcloud compute ssh --tunnel-through-iap` as non-root `pde` | **verified** |
| the layer-3 path | **verified** — 0% loss, RTT 48–142 ms (avg ~59 ms) |
| **source addresses survive the tunnel** | **verified** — the VM's `tcpdump -i tun7` recorded `10.99.0.99 > 10.98.0.1` and the reply back |
| the relay is genuinely in the path | **verified** — `curl` exit 7 with it stopped, `{"status":"UP"}` with it running |
| Fineract off `0.0.0.0` | **verified** — only `127.0.0.1:{8443,5432,9092}` listening |
| **ufw on the VM as the firewall source** | **verified** — 10 distinct sources logged on `IN=tun7`; the attacker BLOCKed on 32 distinct ports; the watchdog armed, access confirmed, watchdog cancelled |
| **Slips live on the tunnel device** | **verified** — 132 alerts, including *"Detected new vertical port scan to IP 10.98.0.1 from 10.99.0.20"* |
| **the bank over the relay** | **verified** — 19 of 19 operations present in both the audit trail and the event stream; `pde_officer` CREATE CLIENT / CREATE LOAN / APPROVE / DISBURSE with `checker_username` null |
| **the auth source** | **verified** — the tunnel's session identified by its fd on `/dev/net/tun`, its login collected |
| this machine's firewall | **never touched** in this mode, and `down` leaves it that way |

A window therefore holds five sources that independently describe one attacker:

```
firewall (VM ufw)   10 sources on tun7; 10.99.0.20 BLOCKed on 32 ports
ids      (Slips)    vertical port scan to 10.98.0.1 from 10.99.0.20
audit    (Fineract) pde_officer: CREATE CLIENT, CREATE LOAN, APPROVE, DISBURSE — no checker
events   (Kafka)    ClientCreate, LoanCreated, LoanApproved, LoanDisbursal
auth     (sshd)     the session all of it arrived inside
```

## Things this cost, and what they taught

Worth keeping, because each was silent rather than loud:

- **The firewall is read from the journal, not `/var/log/ufw.log`.** The LOG rules fired 628
  times for a window; `journalctl -k` held those lines and the file held none of them, with
  the rules' counters still climbing. rsyslog is in the path for the file and does not
  deliver them on this host. A window would otherwise report 0 firewall lines and look like
  a quiet network.
- **The tun device is remade every bring-up.** A persistent device an earlier sshd session
  attached to cannot be attached again; reusing one fails as "Tunnel forwarding failed",
  which says nothing about the cause.
- **`local a="$1" b="tun$a"` does not work.** `local` expands all its arguments before
  assigning any, so `b` became `tun`. That made teardown delete a device called `tun` and
  leave the real one behind, which is what kept breaking the next bring-up.
- **Two Slips runs saturate four vCPUs**, and the lab's only way in is SSH. Setup now waits
  for the background cache warm-up before starting the live IDS.
- **`grep -c` prints `0` and exits 1.** `|| echo 0` therefore yields `0\n0`. The firewall
  capture documents this; the auth collector walked into it anyway.
- **`logging full` on a busy VM is 121 MB a window** if the fetch is not filtered to the
  lab's own addresses. Now 413 KB.

## Still to do

- `MALICIOUS_PORTS` no longer contains 8443, so the attacker's sweep is 34 ports rather than
  35. `lab_check_port_lists` now refuses any lab whose port lists contradict each other.
- The auth source records IAP's forwarder address, not the analyst's. Cloud Audit Logs hold
  the Google identity and the real client address; collecting them would complete the chain.
- Slips' `--ids-remote` (file mode per window) and `--via-tunnel` (live) are now two distinct
  designs. The older one still works and is still the only option if the lab cannot reach
  the VM continuously.
