# Fineract 1.9.0 workarounds

Apache Fineract 1.9.0 was released in 2024 and no longer builds or runs against
today's package repositories. Nothing here is a defect in our setup — these are
upstream dependencies that were removed from the internet after the release was
cut.

Both files apply **without modifying the Fineract source tree**, which is what
`Fineract_Setup.md` requires. Keep them here rather than editing `~/fineract`,
so a fresh clone of Fineract stays pristine and the fixes stay reviewable.

| File | Fixes | Applied with |
|---|---|---|
| `fineract-init.gradle` | Build fails: `Could not find com.burgstaller:okhttp-digest:1.10` | `./gradlew --init-script <file>` |
| `fineract-compose-override.yml` | Startup fails: `manifest for bitnami/kafka:3.5.1-debian-11-r7 not found` | `docker compose -f <compose> -f <file>` |

## Why each one is needed

**`okhttp-digest` — JCenter shutdown.** Fineract's docs tooling pulls this in
transitively (asciidoctor → jruby-gradle → http-builder-ng). It was only ever
published to JCenter, which shut down; the Gradle Plugin Portal now redirects
to Maven Central, which 404s. The library was relocated to
`io.github.rburgst:okhttp-digest` keeping the same Java packages, so an init
script substitutes the coordinate and adds `mavenCentral()` to the buildscript
classpath. The dependency is never executed by `jibDockerBuild`; it just has to
resolve.

**Kafka image — Bitnami catalog migration, August 2025.** Bitnami moved every
versioned tag from the `bitnami` namespace to `bitnamilegacy`. Fineract pins
`bitnami/kafka:3.5.1-debian-11-r7`, which now returns `manifest unknown`. The
override points at the identical image under the new namespace.

## Other environment issues (no file needed)

These bite on Docker Desktop / WSL2 setups and are fixed by configuration
rather than by anything in this directory:

- **`error getting credentials — docker-credential-desktop.exe: exec format
  error`** on `docker compose pull`. Docker Desktop leaves a Windows credential
  helper referenced in `~/.docker/config.json`, which WSL cannot execute. If no
  registry logins are stored, `printf '{}\n' > ~/.docker/config.json` clears it.

- **`dpkg was interrupted`** or a stray `bionic` (18.04) entry in
  `/etc/apt/sources.list` on a `jammy` (22.04) system, when installing Docker
  Engine. Run `sudo dpkg --configure -a` and comment out the mismatched repo.

## Notes on the compose file itself

Two things `Fineract_Setup.md` describes inaccurately, worth knowing when
reading logs:

- There is **no Zookeeper**. `bitnami/kafka:3.5.1` runs in KRaft mode
  (`KAFKA_CFG_PROCESS_ROLES=controller,broker`).
- The stack starts **three** Fineract JVMs, not one: `fineract-manager` (the
  API, port 8443, and the only node that runs Liquibase migrations) plus two
  `fineract-worker` replicas that execute batch jobs (ports 8444–8445). Each is
  capped at `-Xmx1G`. `docker compose ... up -d --scale fineract-worker=0`
  frees ~2 GB if you are not exercising batch jobs.
