#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM. Brings up the Evidence Repository:
#  its infrastructure through compose (plus the VM override), the
#  backend jar, and the Vite dev server.
#
#  Safe to run again: a backend or frontend already answering is
#  left alone rather than started twice on the same port.
# ==============================================================
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ER="$(cd "$HERE/../../Evidence Repository" && pwd)"
COMPOSE=(docker compose -f "$ER/docker-compose.yml" -f "$HERE/er-compose.vm.yml")

cd "$ER" || exit 1
[[ -f .env ]] || cp .env.example .env

"${COMPOSE[@]}" up -d --wait --wait-timeout 300 postgres minio redpanda redpanda-console \
	|| { echo "INFRA FAILED"; exit 1; }
timeout 120 "${COMPOSE[@]}" up minio-init >/dev/null 2>&1 || { echo "BUCKET INIT FAILED"; exit 1; }

if curl -sf --max-time 3 http://localhost:8080/actuator/health >/dev/null; then
	echo "backend already up"
else
	cd "$ER/backend" && sh mvnw -q -DskipTests package > ~/er-build.log 2>&1 \
		|| { echo "BUILD FAILED, see ~/er-build.log"; exit 1; }
	# Spring does not read .env itself; the variables have to be in its environment.
	set -a; . "$ER/.env"; set +a
	JAR=$(ls target/*.jar | grep -v plain | head -1)
	nohup java -jar "$JAR" </dev/null > ~/er-backend.log 2>&1 &
	echo "backend pid $!"
fi

if curl -sf -o /dev/null --max-time 3 http://127.0.0.1:5173/; then
	echo "frontend already up"
else
	cd "$ER/frontend" && npm ci --no-audit --no-fund > ~/er-npm.log 2>&1 \
		|| { echo "NPM FAILED, see ~/er-npm.log"; exit 1; }
	nohup npm run dev -- --host 127.0.0.1 --port 5173 </dev/null > ~/er-frontend.log 2>&1 &
	echo "frontend pid $!"
fi

# Up means answering, not launched. The backend takes ~15s to start.
for _ in $(seq 1 30); do
	curl -sf --max-time 3 http://localhost:8080/actuator/health >/dev/null && { echo "ER UP"; exit 0; }
	sleep 3
done
echo "BACKEND DID NOT ANSWER, see ~/er-backend.log"
exit 1
