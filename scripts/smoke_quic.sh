#!/bin/sh
# Live-smoke for the QUIC remote transport (Project B slice): the box reaches fabricd over a
# pinned-cert QUIC link with a client-auth token, instead of the local UDS. Verifies:
#   [1] a db.query routed box -> QUIC -> fabricd -> Postgres, with metrics (correct token).
#   [2] a WRONG token is refused at session open -> 400 UNAUTHENTICATED, no query runs.
#   [3] an ABSENT token (box auth disabled) is refused the same way.
#
# The QUIC transport is a real network hop (quinn over UDP + TLS 1.3 + cert pinning); here both
# ends run in one container over loopback so the script is self-contained and runnable on the same
# compose network as smoke_5.sh. To split across hosts, run fabricd in one container and each runlet
# in another, point `replicas` at fabricd's address, and copy the same cert pin — nothing else
# changes (that is the whole point of the transport).
#
# Run inside rust:1.92-alpine on a docker network where Postgres is reachable as `postgres`
# (e.g. the runlet-js repo's `docker compose up -d postgres`, then run this on that network),
# with the PARENT dir (holding this repo AND a runlet-js sibling checkout) mounted at /work
# and the workdir /work/fabricd.
set -e
apk add --no-cache musl-dev curl openssl >/dev/null 2>&1

echo "== building fabricd + runlet (debug, two sibling workspaces) =="
cargo build -p fabricd --quiet
cargo build --manifest-path /work/runlet-js/Cargo.toml -p runlet --quiet

mkdir -p /tmp/smoke/good /tmp/smoke/wrong /tmp/smoke/none

echo "== generating a self-signed server cert + computing its SHA-256 pin =="
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tmp/smoke/key.pem -out /tmp/smoke/cert.pem -days 1 -subj "/CN=fabricd" >/dev/null 2>&1
PIN=$(openssl x509 -in /tmp/smoke/cert.pem -outform DER | sha256sum | cut -d' ' -f1)
echo "pin=$PIN"

TOKEN="smoke-secret-token"

# fabricd: QUIC listener (no UDS), the operator credential table, static-token client auth.
cat > /tmp/smoke/fabricd.json <<JSON
{
  "resources": {
    "orders-db": { "kind": "db", "host": "postgres", "port": 5432, "user": "test", "password": "test", "database": "testdb" }
  },
  "quic": {
    "listen": "127.0.0.1:7000",
    "server_cert": "/tmp/smoke/cert.pem",
    "server_key": "/tmp/smoke/key.pem",
    "auth": { "mode": "static", "static_token": "$TOKEN" }
  }
}
JSON

# Box config template: QUIC transport pinning the daemon cert. $1 = port, $2 = auth block.
box_config() { # port  authline
  cat <<JSON
{
  "debug": true,
  "error_debug": true,
  "server": { "host": "127.0.0.1", "port": $1 },
  "fabricd_quic": {
    "replicas": ["127.0.0.1:7000"],
    "server_name": "fabricd",
    "server_cert_pin": "$PIN"$2
  }
}
JSON
}
box_config 3000 ", \"auth_token\": \"$TOKEN\""        > /tmp/smoke/good/config.json
box_config 3001 ", \"auth_token\": \"wrong-token\""   > /tmp/smoke/wrong/config.json
box_config 3002 ""                                    > /tmp/smoke/none/config.json

REQ='{"script":"function handler(ctx){ var r = db.query(\"SELECT $1::int AS n\", [41]); return json({ n: r.rows[0].n }); }","config":{"io":{"db":["orders-db"]}}}'

echo "== starting fabricd (quic) =="
FABRICD_CONFIG=/tmp/smoke/fabricd.json /work/fabricd/target/debug/fabricd >/tmp/smoke/fabricd.log 2>&1 &
FABRICD_PID=$!
sleep 1

start_box() { # dir port
  ( cd "$1" && /work/runlet-js/target/debug/runlet >"$1/runlet.log" 2>&1 ) &
  echo $!
  for _ in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$2/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "box on :$2 did not come up"; cat "$1/runlet.log"; exit 1
}

echo "== starting 3 boxes: good(:3000) wrong-token(:3001) no-token(:3002) =="
GOOD_PID=$(start_box /tmp/smoke/good 3000)
WRONG_PID=$(start_box /tmp/smoke/wrong 3001)
NONE_PID=$(start_box /tmp/smoke/none 3002)

echo "== [1] query via QUIC (correct token) =="
RESP1=$(curl -s -X POST http://127.0.0.1:3000/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP1"

echo "== [2] wrong token -> 400 UNAUTHENTICATED =="
RESP2=$(curl -s -X POST http://127.0.0.1:3001/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP2"

echo "== [3] absent token -> 400 UNAUTHENTICATED =="
RESP3=$(curl -s -X POST http://127.0.0.1:3002/execute -H 'content-type: application/json' -d "$REQ")
echo "$RESP3"

kill "$GOOD_PID" "$WRONG_PID" "$NONE_PID" "$FABRICD_PID" 2>/dev/null || true

echo "== verdict =="
echo "$RESP1" | grep -q '"n":41' && echo "PASS [1] quic: n=41" || { echo "FAIL [1]"; exit 1; }
echo "$RESP1" | grep -q '"db_requests":\[{' && echo "PASS [1] db_requests present" || echo "WARN [1] db_requests empty"
echo "$RESP2" | grep -q 'UNAUTHENTICATED' && echo "PASS [2] wrong token -> UNAUTHENTICATED" || { echo "FAIL [2]"; exit 1; }
echo "$RESP2" | grep -q '"n":41' && { echo "FAIL [2] query ran despite bad token"; exit 1; } || true
echo "$RESP3" | grep -q 'UNAUTHENTICATED' && echo "PASS [3] absent token -> UNAUTHENTICATED" || { echo "FAIL [3]"; exit 1; }
echo "ALL GOOD"
