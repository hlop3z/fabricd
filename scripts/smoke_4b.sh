#!/bin/sh
# Live-smoke for Step 4b: box (runlet) -> UDS -> fabricd -> Postgres, plus the in-process fallback.
# (Historical: the in-process fallback was removed by Step 5 — see smoke_5.sh.)
# Run inside rust:1.92-alpine on a docker network where Postgres is reachable as `postgres`,
# with the PARENT dir (holding this repo AND a runlet-js sibling checkout) mounted at /work
# and the workdir /work/fabricd.
set -e
apk add --no-cache musl-dev curl >/dev/null 2>&1

echo "== building fabricd + runlet (debug, two sibling workspaces) =="
cargo build -p fabricd --quiet
cargo build --manifest-path /work/runlet-js/Cargo.toml -p runlet --quiet

mkdir -p /tmp/smoke
cat > /tmp/smoke/config.json <<'JSON'
{
  "debug": true,
  "error_debug": true,
  "server": { "host": "127.0.0.1", "port": 3000 },
  "fabricd_socket": "/tmp/fabricd.sock",
  "resources": {
    "orders-db": { "kind": "db", "host": "postgres", "port": 5432, "user": "test", "password": "test", "database": "testdb" }
  }
}
JSON

REQ='{"script":"function handler(ctx){ var r = db.query(\"SELECT $1::int AS n\", [41]); return json({ n: r.rows[0].n }); }","config":{"io":{"db":["orders-db"]}}}'

echo "== starting fabricd =="
FABRICD_SOCKET=/tmp/fabricd.sock /work/fabricd/target/debug/fabricd >/tmp/smoke/fabricd.log 2>&1 &
FABRICD_PID=$!
sleep 1

echo "== starting runlet =="
( cd /tmp/smoke && /work/runlet-js/target/debug/runlet >/tmp/smoke/runlet.log 2>&1 ) &
RUNLET_PID=$!

ok=0
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then echo "runlet did not come up"; cat /tmp/smoke/runlet.log; exit 1; fi

echo "== [1] query via fabricd (UDS path) =="
RESP1=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP1"

echo "== fabricd log (should show a listening line + one session) =="
cat /tmp/smoke/fabricd.log

echo "== [2] kill fabricd, query again (in-process fallback) =="
kill "$FABRICD_PID" 2>/dev/null || true
sleep 1
RESP2=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP2"

echo "== runlet log tail (expect a 'falling back' warn after fabricd died) =="
tail -n 5 /tmp/smoke/runlet.log

kill "$RUNLET_PID" 2>/dev/null || true

echo "== verdict =="
echo "$RESP1" | grep -q '"n":41' && echo "PASS uds: n=41" || { echo "FAIL uds"; exit 1; }
echo "$RESP1" | grep -q '"db_requests":\[{' && echo "PASS uds: db_requests present" || echo "WARN uds: db_requests empty"
echo "$RESP2" | grep -q '"n":41' && echo "PASS fallback: n=41" || { echo "FAIL fallback"; exit 1; }
echo "ALL GOOD"
