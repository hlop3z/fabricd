#!/bin/sh
# Live-smoke for Step 5 (trust flip): the box holds NO credentials and NO drivers; it sends
# logical names to fabricd, which holds the `resources` table and the drivers. Verifies:
#   [1] a db.query routed box -> UDS -> fabricd -> Postgres, with metrics.
#   [2] no in-process fallback: with fabricd down, a driver request fails 503 EGRESS_UNAVAILABLE.
#   [3] an unknown resource name is rejected 400 RESOURCE_NOT_FOUND (resolved daemon-side).
# Run inside rust:1.92-alpine on a docker network where Postgres is reachable as `postgres`.
set -e
apk add --no-cache musl-dev curl >/dev/null 2>&1

echo "== building fabricd + runlet (debug) =="
cargo build -p fabricd -p runlet --quiet

mkdir -p /tmp/smoke
# Box config: a fabricd socket, NO resources (the box holds no credentials).
cat > /tmp/smoke/config.json <<'JSON'
{
  "debug": true,
  "error_debug": true,
  "server": { "host": "127.0.0.1", "port": 3000 },
  "fabricd_socket": "/tmp/fabricd.sock"
}
JSON
# fabricd config: the operator credential table.
cat > /tmp/smoke/fabricd.json <<'JSON'
{
  "socket": "/tmp/fabricd.sock",
  "resources": {
    "orders-db": { "kind": "db", "host": "postgres", "port": 5432, "user": "test", "password": "test", "database": "testdb" }
  }
}
JSON

REQ='{"script":"function handler(ctx){ var r = db.query(\"SELECT $1::int AS n\", [41]); return json({ n: r.rows[0].n }); }","config":{"io":{"db":["orders-db"]}}}'
REQ_BAD='{"script":"function handler(ctx){ return json({ ok: true }); }","config":{"io":{"db":["nope"]}}}'

echo "== starting fabricd =="
FABRICD_CONFIG=/tmp/smoke/fabricd.json FABRICD_SOCKET=/tmp/fabricd.sock /work/target/debug/fabricd >/tmp/smoke/fabricd.log 2>&1 &
FABRICD_PID=$!
sleep 1

echo "== starting runlet =="
( cd /tmp/smoke && /work/target/debug/runlet >/tmp/smoke/runlet.log 2>&1 ) &
RUNLET_PID=$!

ok=0
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then echo "runlet did not come up"; cat /tmp/smoke/runlet.log; exit 1; fi

echo "== [1] query via fabricd (box holds no creds) =="
RESP1=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP1"

echo "== [3] unknown resource name -> 400 RESOURCE_NOT_FOUND =="
RESP3=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ_BAD")
echo "$RESP3"

echo "== [2] kill fabricd, query again -> 503 EGRESS_UNAVAILABLE (no fallback) =="
kill "$FABRICD_PID" 2>/dev/null || true
sleep 1
RESP2=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP2"

kill "$RUNLET_PID" 2>/dev/null || true

echo "== verdict =="
echo "$RESP1" | grep -q '"n":41' && echo "PASS [1] uds: n=41" || { echo "FAIL [1]"; exit 1; }
echo "$RESP1" | grep -q '"db_requests":\[{' && echo "PASS [1] db_requests present" || echo "WARN [1] db_requests empty"
echo "$RESP3" | grep -q 'RESOURCE_NOT_FOUND' && echo "PASS [3] unknown name -> RESOURCE_NOT_FOUND" || { echo "FAIL [3]"; exit 1; }
echo "$RESP2" | grep -q 'EGRESS_UNAVAILABLE' && echo "PASS [2] no fallback -> EGRESS_UNAVAILABLE" || { echo "FAIL [2]"; exit 1; }
echo "ALL GOOD"
