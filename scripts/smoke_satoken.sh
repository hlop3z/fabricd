#!/usr/bin/env bash
# End-to-end for the QUIC `sa-token` client authenticator on a real Kubernetes cluster (KIND).
#
# Proves the production auth path the unit tests can't: a box pod presents a *real* projected
# ServiceAccount token (a cluster-signed OIDC JWT), and `fabricd` verifies it OFFLINE against the
# cluster JWKS before opening the egress session. Two boxes, identical but for the token audience:
#   [good] projected token audience = "fabricd"        -> db.query routed box -> QUIC -> fabricd -> pg, n=41
#   [bad]  projected token audience = "wrong-audience" -> rejected at session open -> UNAUTHENTICATED, no query
#
# Topology in-cluster (all in namespace `default`):
#   postgres      : the egress backend (fabricd resolves `orders-db` to it)
#   jwks (nginx)  : serves the *real* cluster JWKS (pulled once via `kubectl get --raw /openid/v1/jwks`)
#                   over plain HTTP, so fabricd needs no API-server auth/CA to fetch keys
#   fabricd       : QUIC listener, mode=sa-token (issuer from cluster discovery, audience=fabricd)
#   box-good/bad  : runlet, projected SA token via `auth_token_file`, pinning fabricd's self-signed cert
#
# Requires: docker, kind, kubectl, and the workspace build cache. Self-skips (exit 0) if any is
# missing. Set KEEP=1 to leave the cluster up for debugging. Mirrors smoke_quic.sh's verdict style.
set -u

CLUSTER="jsbox-satoken"
IMG="jsbox-satoken:test"
REG_VOL="jsbox_cargo_reg"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

skip() { echo "SKIP: $*"; exit 0; }
for tool in docker kind kubectl; do command -v "$tool" >/dev/null 2>&1 || skip "$tool not found"; done

# On Git Bash (Windows) `docker -v` needs a native path and MSYS must not rewrite the `:/dest`.
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
drun() { MSYS_NO_PATHCONV=1 docker "$@"; }

WD="$(mktemp -d)"
cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "KEEP=1 — leaving cluster '$CLUSTER' up (kubectl config current-context: $(kubectl config current-context 2>/dev/null))"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WD"
}
trap cleanup EXIT

echo "== [build] fabricd + runlet (debug, musl — reuses workspace cache) =="
drun run --rm -v "$(winpath "$REPO"):/work" -v "$REG_VOL:/usr/local/cargo/registry" -w /work rust:1.92-alpine \
  sh -c "apk add --no-cache musl-dev >/dev/null 2>&1 && cargo build -p fabricd -p runlet" || skip "build failed"

echo "== [image] building $IMG from the freshly-built binaries =="
# Assemble a clean build context ($WD) with just the binaries + Dockerfile — the repo .dockerignore
# excludes target/, so we cannot build from the repo root.
cp "$REPO/target/debug/fabricd" "$REPO/target/debug/runlet" "$REPO/scripts/Dockerfile.satoken" "$WD/" || { echo "binaries missing"; exit 1; }
mv "$WD/Dockerfile.satoken" "$WD/Dockerfile"
( cd "$WD" && drun build -t "$IMG" . ) >/dev/null || { echo "docker build failed"; exit 1; }

echo "== [cluster] creating KIND cluster '$CLUSTER' =="
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" >/dev/null
kubectl config use-context "kind-$CLUSTER" >/dev/null 2>&1

echo "== [image] loading images into the cluster =="
kind load docker-image "$IMG" --name "$CLUSTER" >/dev/null
# Preload the two stock images from the host cache so the nodes don't pull from the internet.
for stock in postgres:17-alpine nginx:alpine; do
  docker image inspect "$stock" >/dev/null 2>&1 && kind load docker-image "$stock" --name "$CLUSTER" >/dev/null 2>&1 || true
done

echo "== [oidc] deriving issuer + JWKS from the cluster SA signing key =="
# kind's API server does not serve the OIDC discovery/JWKS endpoints, so build the JWKS ourselves
# from the control-plane's SA signing public key + a real token's kid (both stable for the cluster).
# A minted token is only used to read iss + kid; each box gets its own auto-rotated projected token.
b64url_decode() {
  local s="$1"; local pad=$(( (4 - ${#s} % 4) % 4 ))
  printf '%s%s' "$s" "$(printf '=%.0s' $(seq 1 "$pad" 2>/dev/null))" | tr '_-' '/+' | base64 -d 2>/dev/null
}
TOK="$(kubectl create token default --audience=fabricd --duration=3600s)"
[ -n "$TOK" ] || { echo "could not mint a token"; exit 1; }
ISSUER="$(b64url_decode "$(printf '%s' "$TOK" | cut -d. -f2)" | grep -oE '"iss":"[^"]+"' | head -1 | sed 's/^"iss":"//; s/"$//')"
KID="$(b64url_decode "$(printf '%s' "$TOK" | cut -d. -f1)" | grep -oE '"kid":"[^"]+"' | head -1 | sed 's/^"kid":"//; s/"$//')"
[ -n "$ISSUER" ] && [ -n "$KID" ] || { echo "could not derive issuer/kid from token"; exit 1; }
drun exec "${CLUSTER}-control-plane" cat /etc/kubernetes/pki/sa.pub > "$WD/sa.pub"
drun run --rm -v "$(winpath "$WD"):/wd" -w /wd -e KID="$KID" alpine:3 sh -c '
  apk add --no-cache openssl >/dev/null 2>&1
  MODHEX=$(openssl rsa -pubin -in sa.pub -noout -modulus | sed "s/Modulus=//")
  N=$(printf "%s" "$MODHEX" | xxd -r -p | base64 -w0 | tr "+/" "-_" | tr -d "=")
  printf "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"AQAB\"}]}" "$KID" "$N" > jwks.json'
[ -s "$WD/jwks.json" ] || { echo "failed to build JWKS"; exit 1; }
echo "issuer=$ISSUER  kid=$KID  jwks=$(wc -c < "$WD/jwks.json") bytes"

echo "== [tls] generating fabricd's self-signed QUIC cert + SHA-256 pin =="
drun run --rm -v "$(winpath "$WD"):/wd" -w /wd alpine:3 sh -c '
  apk add --no-cache openssl >/dev/null 2>&1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout key.pem -out cert.pem -days 1 -subj "/CN=fabricd" >/dev/null 2>&1
  openssl x509 -in cert.pem -outform DER | sha256sum | cut -d" " -f1 > pin.txt'
PIN="$(cat "$WD/pin.txt")"
echo "pin=$PIN"

echo "== [config] rendering fabricd + box configs =="
cat > "$WD/fabricd.json" <<JSON
{
  "resources": {
    "orders-db": { "kind": "db", "host": "postgres.default.svc.cluster.local", "port": 5432, "user": "test", "password": "test", "database": "testdb" }
  },
  "quic": {
    "listen": "0.0.0.0:7000",
    "server_cert": "/etc/fabricd/cert.pem",
    "server_key": "/etc/fabricd/key.pem",
    "auth": {
      "mode": "sa-token",
      "issuer": "$ISSUER",
      "jwks_url": "http://jwks.default.svc.cluster.local/jwks.json",
      "audience": "fabricd",
      "jwks_refresh_secs": 5
    }
  }
}
JSON

# One box config for both pods — good vs bad differ only in the projected token's audience.
cat > "$WD/config.json" <<JSON
{
  "debug": true,
  "error_debug": true,
  "server": { "host": "127.0.0.1", "port": 3000 },
  "fabricd_quic": {
    "replicas": ["fabricd.default.svc.cluster.local:7000"],
    "server_name": "fabricd",
    "server_cert_pin": "$PIN",
    "auth_token_file": "/var/run/secrets/tokens/token"
  }
}
JSON

echo "== [apply] configmaps =="
kubectl create configmap fabricd-config \
  --from-file=fabricd.json="$(winpath "$WD/fabricd.json")" \
  --from-file=cert.pem="$(winpath "$WD/cert.pem")" \
  --from-file=key.pem="$(winpath "$WD/key.pem")" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create configmap box-config --from-file=config.json="$(winpath "$WD/config.json")" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create configmap jwks --from-file=jwks.json="$(winpath "$WD/jwks.json")" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

echo "== [apply] workloads =="
kubectl apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres }
spec:
  replicas: 1
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
      - name: postgres
        image: postgres:17-alpine
        env:
        - { name: POSTGRES_USER, value: test }
        - { name: POSTGRES_PASSWORD, value: test }
        - { name: POSTGRES_DB, value: testdb }
        ports: [ { containerPort: 5432 } ]
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  selector: { app: postgres }
  ports: [ { port: 5432, targetPort: 5432 } ]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: jwks }
spec:
  replicas: 1
  selector: { matchLabels: { app: jwks } }
  template:
    metadata: { labels: { app: jwks } }
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports: [ { containerPort: 80 } ]
        volumeMounts: [ { name: jwks, mountPath: /usr/share/nginx/html } ]
      volumes: [ { name: jwks, configMap: { name: jwks } } ]
---
apiVersion: v1
kind: Service
metadata: { name: jwks }
spec:
  selector: { app: jwks }
  ports: [ { port: 80, targetPort: 80 } ]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: fabricd }
spec:
  replicas: 1
  selector: { matchLabels: { app: fabricd } }
  template:
    metadata: { labels: { app: fabricd } }
    spec:
      containers:
      - name: fabricd
        image: $IMG
        imagePullPolicy: IfNotPresent
        command: [ fabricd ]
        env: [ { name: FABRICD_CONFIG, value: /etc/fabricd/fabricd.json } ]
        ports: [ { containerPort: 7000, protocol: UDP } ]
        volumeMounts: [ { name: cfg, mountPath: /etc/fabricd } ]
      volumes: [ { name: cfg, configMap: { name: fabricd-config } } ]
---
apiVersion: v1
kind: Service
metadata: { name: fabricd }
spec:
  selector: { app: fabricd }
  ports: [ { port: 7000, targetPort: 7000, protocol: UDP } ]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: box-good }
spec:
  replicas: 1
  selector: { matchLabels: { app: box-good } }
  template:
    metadata: { labels: { app: box-good } }
    spec:
      containers:
      - name: box
        image: $IMG
        imagePullPolicy: IfNotPresent
        command: [ runlet ]
        workingDir: /etc/box
        volumeMounts:
        - { name: cfg, mountPath: /etc/box }
        - { name: token, mountPath: /var/run/secrets/tokens }
      volumes:
      - { name: cfg, configMap: { name: box-config } }
      - name: token
        projected:
          sources:
          - serviceAccountToken: { audience: fabricd, expirationSeconds: 3600, path: token }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: box-bad }
spec:
  replicas: 1
  selector: { matchLabels: { app: box-bad } }
  template:
    metadata: { labels: { app: box-bad } }
    spec:
      containers:
      - name: box
        image: $IMG
        imagePullPolicy: IfNotPresent
        command: [ runlet ]
        workingDir: /etc/box
        volumeMounts:
        - { name: cfg, mountPath: /etc/box }
        - { name: token, mountPath: /var/run/secrets/tokens }
      volumes:
      - { name: cfg, configMap: { name: box-config } }
      - name: token
        projected:
          sources:
          - serviceAccountToken: { audience: wrong-audience, expirationSeconds: 3600, path: token }
YAML

echo "== [wait] rollouts =="
for dep in postgres jwks fabricd box-good box-bad; do
  kubectl rollout status "deploy/$dep" --timeout=150s || { echo "rollout $dep failed"; kubectl describe "deploy/$dep"; exit 1; }
done

REQ='{"script":"function handler(ctx){ var r = db.query(\"SELECT $1::int AS n\", [41]); return json({ n: r.rows[0].n }); }","config":{"io":{"db":["orders-db"]}}}'
curl_box() { kubectl exec "deploy/$1" -- curl -s -X POST localhost:3000/execute -H 'content-type: application/json' -d "$REQ" 2>/dev/null; }

echo "== [good] valid-audience token -> query runs (retry while fabricd loads JWKS) =="
GOOD=""
for _ in $(seq 1 30); do
  GOOD="$(curl_box box-good)"
  echo "$GOOD" | grep -q '"n":41' && break
  sleep 2
done
echo "good: $GOOD"

echo "== [bad] wrong-audience token -> UNAUTHENTICATED, no query =="
BAD="$(curl_box box-bad)"
echo "bad: $BAD"

echo "== verdict =="
rc=0
echo "$GOOD" | grep -q '"n":41' && echo "PASS [good] valid audience -> n=41 over QUIC+sa-token" || { echo "FAIL [good] expected n=41"; rc=1; }
echo "$BAD" | grep -q 'UNAUTHENTICATED' && echo "PASS [bad] wrong audience -> UNAUTHENTICATED" || { echo "FAIL [bad] expected UNAUTHENTICATED"; rc=1; }
echo "$BAD" | grep -q '"n":41' && { echo "FAIL [bad] query ran despite wrong-audience token"; rc=1; }
[ "$rc" = 0 ] && echo "ALL GOOD" || echo "FAILURES ABOVE"
exit $rc
