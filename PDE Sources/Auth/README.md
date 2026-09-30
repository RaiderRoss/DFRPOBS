# PDE Source: Remote access (sshd on the research VM)

| source | read from | answers | registered as |
|---|---|---|---|
| `auth` | the VM's sshd record (`/var/log/auth.log`, or journald) | **who opened the session** the window's traffic arrived in | `pde-sim-sshd-01` (`AUTH_LOG`) |

This is the only source in the lab that attributes activity to a *person*. The firewall has
an address, the IDS has a profile, the bank has a login — and §3.5.3 of the proposal is
precisely about evidence that records an outcome with no way back to an actor. Every window's
traffic reaches the VM inside an authenticated SSH session, and this is the record of that
authentication. It is the first link in the chain:

```
this login opened the session  →  from which these addresses appeared
  →  which scanned the host    →  and logged into the bank as pde_officer
```

It exists only because the lab reaches the VM over the tunnel device. A port forward's far
end opens its connections locally, so there was no session to attribute; see
`Remote/TUNNEL.md`.

## The window does not bound this source the way it bounds the others

The tunnel is opened when the lab is built and carries every window taken afterwards, so
**the login that authorised a window almost always happened before that window opened.**
Slicing to the window alone would produce an empty file, which reads as "nobody
authenticated" — the exact opposite of the truth.

So the collector gathers two things, each under its own marker in the evidence file:

1. **The establishing session.** The sshd session that holds the tun device open is found by
   its file descriptor on `/dev/net/tun`, not guessed from timing — this VM accepts an SSH
   connection for *every* remote command the lab runs, and only one of them is the tunnel.
   Its lines are collected whatever their age.
2. **The window's own lines.** Everything sshd recorded between the window's bounds, taken
   from a byte offset read before the window opened — the same mechanism the ufw log uses.

The `###` marker lines are the collector's, and say so. The sshd lines between them are
byte-for-byte what sshd wrote.

## What it cannot show

- **The address is IAP's, not the analyst's.** Because the session arrives through
  Identity-Aware Proxy, sshd sees a source in Google's forwarder range
  (`35.235.240.0/20`) — not the home or office address the person actually sat at. The real
  client address and the authenticated Google identity are in **Cloud Audit Logs** for the
  IAP TCP forwarding operation, which is a different record from this one and is not
  collected here. Treated honestly, this source answers *which key and which VM account*,
  and the audit log answers *which person and from where*.
- **One VM account for everyone.** Every teammate's key maps onto `pde`
  (`lab-config.sh` explains why), so the login names the account, not the individual. A
  production bank would have one account per person; the key fingerprint in the log is the
  only thing here that distinguishes them.
- **The lab's own automation is in the same log.** `vm.sh`, the collectors and the status
  checks each open an SSH session, so accepted logins in a window are mostly the lab
  working, not a human. This is a finding rather than noise — it is what a shared service
  account looks like in an audit trail — and the tunnel session is identified separately so
  it can be told apart.
- **A reload is not a re-authentication.** `PermitTunnel` is enabled by a config reload, and
  the sessions that existed before it are untouched, so nothing in this log marks the moment
  tunnelling became possible.

## Output

In the window's directory, beside the others:

| file | |
|---|---|
| `auth_<ts>.log` | the evidence: sshd's own lines, the establishing session then the window |
| `auth_<ts>.meta.json` | provenance, which record was read, the tunnel session's pids, counts, digest |

## Files

| | runs |
|---|---|
| `collect-auth.sh` | on the VM: finds the tunnel's session, slices the window, hashes both |
| `auth-lib.sh` | here — sourced by the capture: offset, collect, fetch, verify the digest |
