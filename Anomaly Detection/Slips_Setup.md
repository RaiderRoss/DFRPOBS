# Slips

This guide explains how to run [Slips](https://github.com/stratosphereips/StratosphereLinuxIPS)
against live network traffic in a local WSL2 environment, with no cloud infrastructure
involved.

The purpose of this setup is to confirm Slips itself works end to end — captures traffic,
builds profiles, produces output — before any GCP Packet Mirroring / VM3 work begins. It is
a throwaway sandbox, not the eventual deployment.

## Structure

```
DFRPOBS/
├── Anomaly Detection/       # <- You are here
│   └── Slips_Setup.md
├── Evidence Repository/
├── Fineract/
│   └── Fineract_Setup.md
└── ...

# Slips runs as a container inside WSL — nothing is cloned into this repo.
```

---

## The one thing that will silently break this

**Do not run Slips under Docker Desktop.** Install Docker Engine natively inside the WSL2
distro instead.

Docker Desktop does not run containers inside your Ubuntu distro. It runs them inside a
separate hidden VM (visible as the `docker-desktop` entry in `wsl -l -v`); the `docker`
command in Ubuntu is only a remote control for it. `--net=host` means *"attach to the host
that is running this container"* — which under Docker Desktop is that hidden VM, not your
Ubuntu. Slips would faithfully watch the wrong machine's interfaces.

It does not error. It starts cleanly, reports a healthy interface, and captures nothing.
That is the worst possible failure mode, so it is worth being sure about.

Upstream issue: [docker/for-win#6736](https://github.com/docker/for-win/issues/6736).

---

## Prerequisites

- WSL 2 with Ubuntu (verified on Ubuntu 22.04 `jammy`)
- Windows 11 (verified on 25H2, build 26200) with WSL >= 2.0.0 (verified on 2.7.11.0)
- `sudo` access inside the distro
- ~10 GB free disk: the Slips image alone is **6.29 GB**
- **No Docker Desktop WSL integration on the distro you use** (see below)

Check WSL and Windows versions from PowerShell:

```powershell
wsl -l -v          # distro must show VERSION 2
wsl --version
```

---

## 1. Remove Docker Desktop from the equation

Skip this section if Docker Desktop was never integrated with your distro. Verify with:

```bash
which -a docker
```

If any result is `/usr/bin/docker` **and** no native engine is installed yet, or you see
`/Docker/host/bin/docker`, Docker Desktop is injecting its CLI and you must disable it.

Docker Desktop must be **fully stopped** while its settings are edited, or it rewrites the
file on exit. From PowerShell:

```powershell
# Stop it (the -Quit flag is unreliable; force-stopping is fine when no containers run)
Get-Process 'Docker Desktop','com.docker.backend','com.docker.build','com.docker.dev-envs' `
    -ErrorAction SilentlyContinue | Stop-Process -Force
```

Then edit `%APPDATA%\Docker\settings.json` and remove your distro from the integration list:

```json
"integratedWslDistros": [],
"enableIntegrationWithDefaultWslDistro": false,
"autoStart": false
```

Apply it, which also clears Docker Desktop's injected mounts:

```powershell
wsl --shutdown
```

Confirm the distro is clean — all three should be gone:

```bash
which -a docker            # no /usr/bin/docker, no /Docker/host/bin/docker
ls /var/run/docker.sock    # No such file or directory
```

> `/mnt/c/Program Files/Docker/Docker/resources/bin/docker` may still appear on `PATH`.
> That is the *Windows* binary, visible only because WSL appends the Windows `PATH`. Once
> the native engine installs to `/usr/bin/docker` it takes precedence. Harmless.

### Migrating a running stack off Docker Desktop

Images live in Docker Desktop's own storage and will **not** be visible to the native
engine. Export anything you cannot cheaply rebuild *before* disabling integration:

```bash
docker save fineract:latest -o ~/fineract-image.tar     # e.g. 499 MB
```

Then, after the native engine is running, import it:

```bash
docker load -i ~/fineract-image.tar
```

Images pulled from a registry (Postgres, Kafka, Slips) need no export — just re-pull.

---

## 2. Install Docker Engine natively

Inside the WSL2 shell. These are Docker's official Ubuntu apt-repo instructions:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Starting the daemon

Recent WSL images already run systemd. Check with `ps -p 1 -o comm=`:

- **`systemd`** — nothing more to do; the install enables the service automatically:
  ```bash
  sudo systemctl enable --now docker
  ```
- **`init`** — either start it manually each session (`sudo service docker start`), or enable
  systemd persistently by adding to `/etc/wsl.conf` and running `wsl --shutdown`:
  ```ini
  [boot]
  systemd=true
  ```

### Run docker without sudo

```bash
sudo usermod -aG docker $USER
```

Then `wsl --shutdown` from PowerShell and reopen the distro — the group only applies to new
sessions.

### Verify

```bash
which docker      # must be /usr/bin/docker, listed FIRST
docker version    # client and server should both respond, without sudo
docker context ls # 'default' -> unix:///var/run/docker.sock must be current, NOT desktop-linux
systemctl is-active docker
```

Verified working on **Docker CE 29.7.2**.

### If apt fails

Two problems seen on a real machine, neither caused by Docker:

- `E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'` — a previous
  package operation left packages half-configured. Run exactly that, then retry.
- A stray release repo in `/etc/apt/sources.list`, e.g. a `bionic` (18.04) line on a `jammy`
  (22.04) system. Mixing release series lets apt resolve dependencies against packages built
  for an older libc and is how package state gets wedged in the first place. Comment it out
  (keep a backup) and re-run `sudo apt-get update`.

---

## 3. Pull Slips

```bash
docker pull stratosphereips/slips:latest
```

6.29 GB, so expect this to take a while. Verified on **Slips v1.1.22**.

---

## 4. Start Redis first — this is not optional

Slips v1.1.22 **crashes on startup, every time, whenever it has to start its own Redis.**

```
File "slips_files/core/database/redis_db/database.py", line 472, in _start_redis_server
    cls.printer.print(
File "slips_files/common/abstracts/iobserver.py", line 29, in notify_observers
    observer.update(msg)
AttributeError: 'str' object has no attribute 'update'
```

**Cause.** `managers/redis_manager.py:233` deliberately passes an empty string as the logger:

```python
# we dont care about the logger here we're just making sure the
# server is up, this r isnt gonna be used later
logger = ""
redis = RedisDB(logger, redis_port, ...)
```

That string reaches `RedisDB.__new__` (`database.py:167`), which builds `Printer(logger, ...)`,
and `Printer.__init__` calls `add_observer(logger)` — so the observer list holds a bare `str`.
The first `printer.print()` inside `_start_redis_server` then calls `"".update(msg)`.

Note the traceback is misleading: line 472 is the *debug log of the redis command*, not an
error handler, and the exception is raised **after** config validation succeeds. The missing
`config/redis.conf` in the image is a red herring — Slips renders that itself at
`database.py:273`.

**Workaround.** `redis_manager` decides via
`start_redis_server = not utils.is_port_in_use(6379)`. If Redis is *already* listening,
`_start_redis_server()` is never called and the broken path is never reached. So start Redis
yourself, using the Slips image's own bundled Redis and config template so the settings match:

```bash
docker run -d \
  --net=host \
  --name slips-redis \
  stratosphereips/slips:latest \
  /redis-stable/src/redis-server config/redis.conf.template \
      --port 6379 --bind 127.0.0.1 --daemonize no
```

Confirm before continuing:

```bash
docker exec slips-redis /redis-stable/src/redis-cli -p 6379 ping   # PONG
```

No Slips source is modified by this. If you would rather not carry the workaround, try tag
`v1.1.21`, which may predate the regression.

---

## 5. Run Slips

Confirm the interface name first — it can change between WSL2 sessions:

```bash
ip -brief -4 addr show
```

Then:

```bash
docker run -d \
  --net=host \
  --cap-add=NET_ADMIN \
  --name slips \
  stratosphereips/slips:latest \
  ./slips.py -i eth0
```

Watch it come up:

```bash
docker logs -f slips
```

A healthy start looks like this:

```
Slips Version: 1.1.22
[main] Detected host IP: 172.28.89.36 for eth0
[main] Using redis server on port: 6379
[main] Detected gateway MAC: 00:15:5d:77:39:6e
[main] Used local network: 172.28.80.0/20 for interface eth0
Started Profiler Process [PID 97]
Started Input Process [PID 102]
```

Expected noise, safe to ignore:

- `Unable to register cuFFT/cuDNN/cuBLAS factory`, `failed call to cuInit` — no GPU present;
  TensorFlow falls back to CPU.
- `[feeds_update_manager] The data <x> is not valid` — malformed entries in upstream threat
  intel feeds.
- `WARNING: Published ports are discarded when using host network mode` — only if you pass
  `-p`, which is meaningless under `--net=host`. Omit it.

---

## 6. Verify capture

Generate traffic **from inside the WSL2 shell** (see the visibility section below for why):

```bash
curl -s -o /dev/null https://example.com
ping -c 4 8.8.8.8
curl -s -o /dev/null https://wikipedia.org
```

Then confirm Zeek is capturing and flows are landing:

```bash
# Zeek must be running on the right interface
docker exec slips bash -c "ps aux | grep '[b]ro -C -i'"

# Flow count (grows as traffic arrives)
docker exec slips bash -c "grep -vc '^#' output/eth0_*/zeek_files/conn.log"

# Your specific destination should appear
docker exec slips bash -c "grep -c '8.8.8.8' output/eth0_*/zeek_files/conn.log"
```

Confirm Slips is profiling, not merely capturing — substitute your own host IP:

```bash
docker exec slips-redis /redis-stable/src/redis-cli -p 6379 -n 0 keys 'profile_172.28.89.36*'
```

You should see timewindow keys:

```
profile_172.28.89.36_timewindow0
profile_172.28.89.36_timewindow0:OutTuples:symbols
profile_172.28.89.36_timewindow1:tcp:not_estab:34.117.59.81:dstports
```

### Reading the output correctly

**Slips profiles local hosts, not destinations.** It detects the local network from the
interface (`Used local network: 172.28.80.0/20`) and creates a profile only for addresses
inside it. External destinations are recorded as `OutTuples` / `dstports` *within* the local
host's profile.

So after curling `example.com`, `profile_104.20.23.154` **will not exist** — and that is
correct. The success signal is `profile_<your-wsl-ip>` with populated timewindows.

**`profile_*` key counts are not traffic.** A fresh instance holds ~166,000 `profile_*` keys
immediately, before any traffic. These are threat-intel indicators loaded by the TI modules —
they carry TTLs and `threat_level` fields. Do not read the key count as hosts observed.

**The stdout counter line is unreliable.** `Total analyzed IPs: N` is redrawn with a carriage
return, so `docker logs` shows only the first few, frozen at `0`. Trust `conn.log` and the
Redis profile keys instead.

### If nothing is captured

1. Confirm the engine is native, not Docker Desktop:
   `which docker` → `/usr/bin/docker`, and `docker context ls` → `default` is current.
2. Confirm the interface name matches what you passed to `-i` (`ip -brief -4 addr show`).
3. Confirm traffic is visible at OS level at all, outside Docker:
   `sudo tcpdump -i eth0 -n -c 5`.

---

## What traffic you can and cannot see

WSL2's default NAT networking exposes far less than you might expect:

| Traffic source | Visible on WSL `eth0`? |
|---|---|
| Processes inside WSL2 (`curl`, `ping`, containers on the default bridge) | **Yes** |
| Windows-side broadcast/multicast — mDNS, SSDP | **Yes** — crosses the shared vSwitch segment |
| Windows-side unicast — e.g. Chrome loading a website | **No** |
| Container-to-container traffic on a Docker Compose network | **No** — see below |

Expect Windows service-discovery noise in your captures. On the reference machine, `eth0`
carried mDNS queries from the Windows host at `172.28.80.1` (`_googlecast._tcp.local`,
`_spotify-connect._tcp.local`) and SSDP to `239.255.255.250`. Account for this before
interpreting results — it is not the sandbox misbehaving.

To capture Windows-side unicast traffic, WSL **mirrored networking mode** is required
(Windows 11 22H2+ and WSL >= 2.0.0). It is a global WSL networking change affecting every
distro, so enable it deliberately, not by default.

### Watching Fineract traffic

`-i eth0` **will not see it.** Compose creates its own bridge, and container-to-container
traffic never touches `eth0`:

```
eth0             UP    172.28.89.36/20     <- host traffic
br-af29f0e8bb90  UP    172.18.0.1/16       <- the fineract_default network
```

Point Slips at the bridge instead — find it with `docker network inspect fineract_default`,
or `ip -brief addr show` while the stack is up, then run Slips with `-i br-<id>`. Both
engines must be the same one: Fineract and Slips must run on the *native* engine for this to
work at all.

---

## Useful commands

| Task | Command |
|---|---|
| Start Redis (do this first) | `docker run -d --net=host --name slips-redis stratosphereips/slips:latest /redis-stable/src/redis-server config/redis.conf.template --port 6379 --bind 127.0.0.1 --daemonize no` |
| Start Slips | `docker run -d --net=host --cap-add=NET_ADMIN --name slips stratosphereips/slips:latest ./slips.py -i eth0` |
| Follow logs | `docker logs -f slips` |
| Stop everything | `docker rm -f slips slips-redis` |
| Flow count | `docker exec slips bash -c "grep -vc '^#' output/eth0_*/zeek_files/conn.log"` |
| Recent flows | `docker exec slips bash -c "grep -v '^#' output/eth0_*/zeek_files/conn.log \| tail -5"` |
| Alerts raised | `docker exec slips bash -c "cat output/eth0_*/alerts/alerts.log"` |
| Slips errors | `docker exec slips bash -c "cat output/eth0_*/errors.log"` |
| Copy output to host | `docker cp slips:/StratosphereLinuxIPS/output ./slips-output` |
| List profiles | `docker exec slips-redis /redis-stable/src/redis-cli -p 6379 -n 0 keys 'profile_<ip>*'` |

> Output lives inside the container at `/StratosphereLinuxIPS/output/eth0_<timestamp>/` and is
> **lost when the container is removed**. Copy anything worth keeping, or add a
> `-v $PWD/slips-output:/StratosphereLinuxIPS/output` bind mount.

---

## Known issues

| Symptom | Cause | Fix |
|---|---|---|
| Slips runs but captures nothing, no errors | Running under Docker Desktop; `--net=host` attached to its hidden VM | Install Docker Engine natively (section 1–2) |
| `AttributeError: 'str' object has no attribute 'update'` at startup | Slips v1.1.22 bug — `logger = ""` becomes a printer observer | Start Redis on 6379 first (section 4) |
| `Fatal error, can't open config file '.../config/redis.conf'` | Image ships only `redis.conf.template` | Not the real problem — see section 4 |
| No `profile_` key for a site you visited | By design — Slips profiles local hosts only | Check `profile_<your-wsl-ip>` instead |
| `Total analyzed IPs: 0` in `docker logs` despite traffic | Status line redrawn with `\r`; logs show only the first frames | Check `conn.log` and Redis keys |
| `error getting credentials ... docker-credential-desktop.exe` | Leftover Docker Desktop credential helper; WSL cannot execute Windows `.exe` | `printf '{}\n' > ~/.docker/config.json` (only if no registry logins are stored) |
| Fineract traffic invisible | It rides the compose bridge, not `eth0` | Use `-i br-<id>` (see above) |

---

## Next steps

Once Slips is confirmed capturing and profiling correctly here, return to the GCP plan —
VM3 + Internal Load Balancer + a Packet Mirroring policy targeting VM1 — to move from local
validation to the Fineract-facing deployment.

Not addressed here, since this is a throwaway local test rather than the eventual VM3
deployment: session persistence, resource limits, and Redis port conflicts if something else
already wants 6379.

---

*Verified 2026-08-10 on Ubuntu 22.04 (WSL 2.7.11.0, Windows 11 25H2 build 26200),
Docker CE 29.7.2, Slips v1.1.22.*
