## Troubleshooting

**`FATAL: password authentication failed for user "postgres"`, manager exits (1)**

`config/docker/postgresql/docker-entrypoint-initdb.d/01-init.sh` did not run, so
the `postgres` role and tenant databases were never created. Two usual causes:

- The file is missing. Docker's response to a missing bind-mount source is to
  create an **empty directory** in its place — check that `01-init.sh` is a file,
  not a directory.
- The file has CRLF line endings, which stops it executing. See below.

The init script only runs on a **fresh** data volume, so after fixing it you
must `down -v` before `up -d`.

**Line endings**

The repo root `.gitattributes` forces LF on `*.sh`, `*.env`, `*.yml`, and
`*.avsc`. If you cloned before it existed and Git for Windows normalised things
to CRLF, re-normalise with:

```bash
git add --renormalize .
```

**Listener reports `Loaded 0 schemas`**

The image build didn't pick up `Kafka_Listener/schemas/`. Rebuild with
`--build`. If you have modified the compose file to bind-mount schemas from a
local path instead, note that Docker Desktop needs **backslashes** for WSL
paths — the `//wsl.localhost/...` form mounts an empty directory silently rather
than erroring.

**Listener is connected but no events appear**

Almost always the event types are still disabled — see "Enable external events".
Confirm with `SELECT count(*) FROM m_external_event;`; if that is 0, Fineract
isn't recording them, so the problem is upstream of Kafka.

**Manager reports `must be Batch Manager and Batch Worker too` and exits**

`FINERACT_REMOTE_JOB_MESSAGE_HANDLER_SPRING_EVENTS_ENABLED` is true. The
Spring-events job handler only works on an all-in-one node; this stack splits
manager and worker, so jobs must go over Kafka.
`config/docker/env/kafka-client.env` sets this correctly — check it isn't empty.

**Healthcheck fails with `"curl": executable file not found`**

The Fineract image is Alpine-based and has no `curl`. The compose healthcheck
uses the busybox `wget` applet instead; don't switch it back to `curl`.

---

## Known gaps

These are known-incomplete, not bugs to chase:

- `Scripts/reset_db.sh` and `Scripts/Scenarios/README.md` are placeholder stubs.
- `Scripts/Seeding/seed-client.sh` references `$OFFICE_ID` and `$STAFF_ID`
  without setting them, so it aborts under `set -u`.
- `Scripts/config.sh` is not sourced by either seeding script — both define
  their own connection settings. Changing `config.sh` currently has no effect.
- Kafka advertises itself only as `kafka:9092`, so clients running **outside**
  Docker cannot consume from it even though 9092 is published: they bootstrap
  via localhost, get told the broker is at `kafka:9092`, and fail to resolve it.
  Consuming from the host needs a second advertised listener.
- PostgreSQL uses an anonymous volume rather than a named one, so data
  persistence across `down` is easy to lose track of.
