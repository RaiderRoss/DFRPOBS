# Fineract
This guide explains how to fetch an build a fineract image locally using docker and wsl as well as provide some useful tips on using the scripts that interact with the fineract instance.

## Structure

```
DFRPOBS/
├── Anomaly Detection/       
├── Evidence Repo/           
├── Fineract/                # <- You are here
│   ├── Guides/              # Documentation and Fineract usage notes
│   ├── Seeding/             # Scripts to populate the base instance
│   ├── Scenarios/           # Threat simulation scripts for experiments
│   └── Scripts/             # Utility scripts (DB reset, health checks, etc.)
│       └── reset_db.sh
└── ...

# Fineract source (cloned separately inside WSL — not part of this repo)
\\wsl$\Ubuntu\home\<user>\fineract\
```

Fineract and its Docker containers run entirely inside WSL. This repo contains everything else including the scripts that interact with Fineract's API. The scripts work from any environment (Windows, WSL, Mac) since they just make HTTP requests to `localhost:8443`.

---

## Prerequisites

**General:**
- [Git](https://git-scm.com/)
- `curl` (or a REST client like Postman/Insomnia)

**Fineract Requirements (WSL):**
- [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/install) with Ubuntu
- [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/) with WSL 2 integration enabled
- [JDK 17](https://adoptium.net/) installed inside WSL

> **Note:** Each team member needs build and run their own local Fineract instance. No changes are made to the source code.

---

## Setting Up Fineract (WSL)

These steps are performed **inside WSL** (open a WSL terminal).

### 1. Clone Fineract

```bash
cd ~
git clone https://github.com/apache/fineract.git
cd fineract
git checkout tags/1.9.0 
```

### 2. Build the Docker image

```bash
./gradlew --no-daemon --console=plain :fineract-provider:jibDockerBuild -x test
```

This takes a few minutes on the first run. It compiles the Java source and packages it into a local Docker image.

### 3. Start the services

```bash
docker compose -f docker-compose-postgresql-kafka.yml up -d
```

This brings up Fineract, PostgreSQL, Kafka, and Zookeeper.

### 4. Verify Fineract is running

Wait 30–60 seconds for startup, then check:

```bash
curl -k https://localhost:8443/fineract-provider/actuator/health
```

You should get a response containing `"status":"UP"`.

Docker exposes port `8443` to both WSL and Windows, so the API is reachable from either environment at `https://localhost:8443`.

---


### Script Configuration

All seed and scenario scripts source a shared configuration file for the API connection details. Edit `Fineract/Scripts/config.sh` if your setup differs from the defaults:

```bash
# Fineract/Scripts/config.sh
BASE_URL="https://localhost:8443/fineract-provider/api/v1"
AUTH="Basic $(echo -n 'mifos:password' | base64)"
TENANT="default"
```

Each script begins with:

```bash
source "$(dirname "$0")/../Scripts/config.sh"
```

This means you can run scripts from any working directory and they will resolve the config path relative to themselves.

---

## Which Environment for What

| Task | Where to run | Why |
|------|-------------|-----|
| Clone & build Fineract | WSL | Needs Docker and JDK |
| `docker compose up/down` | WSL | Docker runs in WSL |
| `reset_db.sh`, `snapshot_db.sh` | WSL | Uses `docker exec` |
| Seed & scenario scripts | Anywhere | Just `curl` to `localhost:8443` |
| Anomaly Detection development | Anywhere | Depends on your stack |
| Evidence Repo work | Anywhere | Analysis and documentation |

---

## API Authentication

Fineract's default admin credentials:

- **Username:** `mifos`
- **Password:** `password`
- **Tenant ID:** `default`

Every API request needs these headers:

```bash
-H "Authorization: Basic $(echo -n 'mifos:password' | base64)" \
-H "Fineract-Platform-TenantId: default" \
-H "Content-Type: application/json"
```

---

## Useful Commands

All Docker commands must be run from WSL.

| Task | Command |
|------|---------|
| Start Fineract | `cd ~/fineract && docker compose -f docker-compose-postgresql-kafka.yml up -d` |
| Stop Fineract | `cd ~/fineract && docker compose -f docker-compose-postgresql-kafka.yml down` |
| Stop and wipe volumes | `cd ~/fineract && docker compose -f docker-compose-postgresql-kafka.yml down -v` |
| View Fineract logs | `docker logs -f fineract` |
| Check Kafka topics | `docker exec -it kafka kafka-topics --list --bootstrap-server localhost:9092` |
| Fineract API health | `curl -k https://localhost:8443/fineract-provider/actuator/health` |
| Reset DB to baseline | `bash Fineract/Scripts/reset_db.sh` |
