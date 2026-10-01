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
```

Nothing new is exposed. The tunnel rides the one port the GCP firewall already admits (22,
from IAP's `35.235.240.0/20`), so the VM is still reachable only behind a Google login check.

## Why this is the realistic option

A bank's core banking back office is never on the internet. Staff reach it from inside or
over remote access, and the most common way into a real bank is a phished credential used
through that remote-access channel — which is exactly what the `loan-fraud` scenario models.
IAP plays the part of the bank's VPN gateway, and the tunnel is the officer arriving the way
a remote officer would.

An sshd-based authentication source was built on top of this and then removed. It could
not attribute anything in this lab: every connection reaches the VM through IAP, so sshd
records Google's forwarder address rather than the person's; every teammate shares the
`pde` account; and all ten simulated users, attacker included, travel through one tunnel
session. It added a row to the sources table without telling an investigator anything that
helps find the attacker. Attribution comes from the bank's audit trail (the login) and the
firewall and IDS (the address), tied by time. The Authentication row stays with the
planned identity-provider source.

The alternatives were weighed and rejected: whitelisting a home IP collapses all ten users
into one NATed address (and still misses the bank calls, which never cross INPUT); a second
attacker VM models post-foothold lateral movement rather than initial access, and costs a
machine.

## Addressing

The tunnel is addressed in `10.98.0.0`, deliberately **not** inside `SUBNET`. The
lab subnet is directly connected on the veth, so an address inside it is answered by the lab
machine and never reaches the tunnel. The users have to aim at something this host must route.

| | |
|---|---|
| `TUN_LOCAL_IP` `10.98.0.2` | the lab machine's end, point-to-point |
| `TUN_VM_IP` `10.98.0.1/15` | the VM's end — **and the address the simulated users target** |
| `TUN_NUM` `7` | `ssh -w` takes a number; the device is `tun7` on both ends |

The VM's end is a `/15` (`TUN_VM_PREFIX`), so its network is `10.98.0.0`–`10.99.255.255` and
contains the users in `10.99.0.0/24`. That is how a VPN concentrator is set up — the client
pool is part of the internal network — and it matters to the IDS: live, Slips takes "local"
to mean the network of the interface it reads, and ignores `client_ips` (that setting applies
only to files). With a point-to-point address every user was outside the local network, and
Slips judged the bank's own customers as strangers.

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

- **ufw is reset first**, so rules a previous run left behind cannot reorder this one's.
- **Rule order is the policy.** The lab's allowed ports, then a deny for the rest of the lab
  subnet, then SSH. ufw evaluates in order, so SSH placed before the subnet deny let the
  attacker's port-22 probe through while the verdict rule logged it BLOCK — a connection the
  evidence called refused. With the deny first, what is logged is what happened.
- **SSH stays open to everyone else.** Port 22 from anywhere outside the lab, because the GCP
  firewall already admits it only from IAP — scoping it again here would lock the VM out if
  Google ever changed that range.
- **`DEFAULT_FORWARD_POLICY=ACCEPT`.** ufw defaults it to DROP, and Docker's
  container-to-container and outbound traffic crosses FORWARD: leaving it would take
  Fineract's own database connection down. The evidence is INPUT, so this costs nothing.
- **A watchdog** disables ufw again after `FW_WATCHDOG_SECONDS` (default 600) unless
  `vm-net.sh firewall-keep` has confirmed the lab still has access. A wrong rule costs a
  wait, not the VM.
- **`logging low`.** The evidence comes from the lab's own verdict rules, not from ufw's
  logging level, so the level only adds noise — and at `full` the noise overflowed the
  kernel's log buffer (below).
- Verdict logging goes in as raw `LOG` rules scoped to `tun7`, because ufw's own `log`
  keyword hardcodes `-m limit --limit 3/min`, which caps a window at ~11 lines per rule
  however much traffic crosses. Same finding as the local lab.

## The bank's web front, and Slips' list of services

A customer does not make bare TCP connections to closed ports; they load pages. The benign
users used to do exactly the former, and to a flow-based IDS a zero-byte, refused flow is a
scan: Slips' machine-learning detector flagged hundreds per window and brought innocent
users to its alert threshold. `Firewall/benign_web.py` now serves the bank's public site on
the tunnel address (HTTP on 80 and 8080, HTTPS on 443 with a self-signed certificate), and
each benign attempt sends a GET and reads the reply. The attacker's traffic is unchanged.

Slips also raises "unknown destination port" at HIGH for any established connection to a
port missing from its services list, and 8443 — the bank's API — is not in it. Every
customer who used the bank was flagged for it. `slips-up` mounts a copy of that list with the
bank's port added. The guaranteed-alert profile's ports stay unregistered on purpose: that
profile works by being the thing Slips has no record of.

The Evidence Repository's backend is bound to `127.0.0.1` for the same reason Fineract is:
on this VM "every interface" includes the lab's tunnel.

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

The path was first verified against the VM on 2026-09-30, `fineract-slips` in
`africa-south1-a`:

| | |
|---|---|
| tun ownership and unprivileged attach | **verified** on WSL 6.18.33.2 (table above) |
| the relay: passthrough, 300 KB payloads, 30 concurrent connections, `0.0.0.0` refusal | **verified** locally |
| `ssh -w` through `gcloud compute ssh --tunnel-through-iap` as non-root `pde` | **verified** |
| the layer-3 path | **verified** — 0% loss, RTT 48–142 ms (avg ~59 ms) |
| **source addresses survive the tunnel** | **verified** — the VM's `tcpdump -i tun7` recorded `10.99.0.99 > 10.98.0.1` and the reply back |
| the relay is genuinely in the path | **verified** — `curl` exit 7 with it stopped, `{"status":"UP"}` with it running |
| Fineract off `0.0.0.0` | **verified** — only `127.0.0.1:{8443,5432,9092}` listening |
| this machine's firewall | **never touched** in this mode, and `down` leaves it that way |

Then measured over an evaluation batch on 2026-09-30 and 2026-10-01: 24 windows, the seven
attack profiles with the `loan-fraud` bank scenario plus a no-attack baseline, three seeds each,
every window on a freshly built lab. 14 400 connection attempts and 423 bank operations:

| | |
|---|---|
| **firewall completeness** | 14 400 of 14 400 ground-truth attempts in the log by exact key, 100% in every window; 0 logged BLOCK that connected; verdict counts reconcile in 24 of 24 |
| **bank completeness** | 231 of 231 state-changing operations with their audit row and all their events (399 of 399); the fraud chain, with no checker, in 21 of 21 fraud windows |
| **integrity** | 96 of 96 evidence files re-hash to their recorded digests and are read-only |
| **IDS, attacker** | alerted in every db-probe and guaranteed-alert window (6 of 21), in no other; the port scan named in all 9 port-scan, stealth and mixed windows |
| **IDS, customers** | 0 of 216 benign host-windows alerted; every customer page load answered (13 140 of 13 140) |

A window therefore holds four sources that independently describe one attack:

```
firewall (VM ufw)   10 sources on tun7; 10.99.0.20 BLOCKed on the denied ports
ids      (Slips)    vertical port scan to 10.98.0.1 from 10.99.0.20
audit    (Fineract) lwazi.ndlovu CREATE LOAN; pde_officer APPROVE, DISBURSE — no checker
events   (Kafka)    LoanCreated, LoanApproved, LoanDisbursal, LoanDisbursalTransaction
```

## Things this cost, and what they taught

Worth keeping, because each was silent rather than loud:

- **The firewall is read from the journal, not `/var/log/ufw.log`.** rsyslog writes the file,
  and on this VM it ran 20–25 minutes behind real time under load, so a window read from the
  file was collected before its own lines arrived — 0 firewall lines, which looks like a
  quiet network.
- **ufw's `logging full` lost evidence.** It logs every packet on every interface, and on a
  busy VM that overflowed the kernel's log buffer: journald reported thousands of "missed"
  kernel messages per window, and the lab's own verdict lines were among them — missing from
  every log, not late. At `logging low` it reports none missed, and every ground-truth
  connection is in the firewall log.
- **The tun device is remade every bring-up.** A persistent device an earlier sshd session
  attached to cannot be attached again; reusing one fails as "Tunnel forwarding failed",
  which says nothing about the cause.
- **`local a="$1" b="tun$a"` does not work.** `local` expands all its arguments before
  assigning any, so `b` became `tun`. That made teardown delete a device called `tun` and
  leave the real one behind, which is what kept breaking the next bring-up.
- **Two Slips runs saturate four vCPUs**, and the lab's only way in is SSH. Setup now waits
  for the background cache warm-up before starting the live IDS.
- **Slips empties its output directory when it starts**, so a file the lab places there for
  it is gone by the time it looks. Its services list is kept beside the directory instead.
- **Slips is copied off the VM while it is still writing.** tar reports a file that changed
  under it with exit 1, which is the normal state of a live source; treating it as a failure
  dropped a whole window's IDS evidence. Only exit 2 and above fails the fetch.
- **A timeout sized for blocked ports cut off customers.** 0.25 s is right for a SYN nothing
  will answer, but over the tunnel a round trip plus a TLS handshake does not fit in it, and
  about 6% of page loads were abandoned half-way — flows no real customer leaves. Answered
  ports now get 5 s.
- **An HTTPS server that handshakes in `accept()` serves its port one customer at a time.**
  Wrapping the listening socket in TLS puts every handshake in the single accepting thread,
  so one slow handshake stalled every customer behind it — 43 failed page loads in one
  window. Handshakes now run in each connection's own thread.
- **IAP is sometimes unreachable for a second or two.** gcloud then fails with "Error while
  connecting ... Network is unreachable", and gcloud's bundled websocket library does not try
  again. One such drop during setup or collection cost a whole window — five in one batch.
  When the connection never opened nothing ran on the VM, so `vm_ssh` and the tunnel-device
  session now retry it (four attempts); a call that has input, or that failed after
  connecting, is still not retried. The message cannot tell those apart — a reconnect
  mid-session raises the same ones — so the test is where gcloud's traceback places the
  failure: in `InitiateConnection`, the connection's first opening.

## Still to do

- Slips' `--ids-remote` (file mode per window) and `--via-tunnel` (live) are two distinct
  designs. The older one still works and is still the only option if the lab cannot reach
  the VM continuously.
