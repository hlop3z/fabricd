# fabricd → Go rewrite: the wire contract to implement

> **Status: planned rewrite.** `fabricd` is being reimplemented in **Go**. This document is the
> authoritative, byte-level specification of the contract a Go `fabricd` must speak so it remains a
> drop-in for the current Rust daemon. It was generated from the contract source of truth —
> `runlet-js` crate [`crates/runlet-wire`](https://github.com/hlop3z/runlet-js/tree/main/crates/runlet-wire)
> (`wire.rs`, `egress.rs`, `errors.rs`, `quic.rs`, `ct.rs`) — not from this daemon's Rust code.
>
> **Why Go.** `fabricd` is an I/O-bound credential-and-driver proxy — Go's sweet spot. Its driver
> ecosystem (pgx, go-redis, nats.go, mongo-go-driver) and ops toolkit (`slog`, Prometheus client,
> OpenTelemetry, graceful shutdown, connection pooling, retry/backoff, k8s integration) are mature
> and idiomatic for exactly this role. The sandbox (runlet) stays Rust/QuickJS; only the broker moves.
>
> **What is frozen vs free.** The **wire bytes** below are frozen (they're owned by `runlet-js`, and
> the box client is compiled against them). Everything *inside* the daemon — config format, the
> resolution table, driver implementations, pooling, resilience knobs, the `fabricd_*` Prometheus
> series, cert tooling — is broker-internal and may be redesigned freely in Go. See
> [§8](#8-what-is-not-part-of-the-contract).
>
> **The contract still lives in runlet-js.** A Go rewrite loses the compile-time coupling the Rust
> `use runlet_wire` gave us. If the rewrite ever needs a new message/field, the change is still made
> in `runlet-js/crates/runlet-wire` **first** (additive/compatible), then implemented here. The
> replacement safety net is the conformance suite ([§7](#7-acceptance-gate)) — it becomes
> load-bearing, not optional.

---

## 1. Framing — length-prefixed JSON

Every message on the wire (both transports) is one **frame**:

```
┌────────────────────┬──────────────────────────────┐
│ u32 length (LE)    │  N bytes of UTF-8 JSON        │
│ 4 bytes            │  (exactly `length` bytes)     │
└────────────────────┴──────────────────────────────┘
```

- Length prefix is **little-endian `uint32`**.
- Payload is **UTF-8 JSON** (`serde_json` on the Rust side → `encoding/json` on the Go side).
- **Hard cap: `length ≤ 67108864` (64 MiB).** Reject a larger length *before* allocating — never
  size a buffer from an unvalidated length.
- **Clean EOF at a frame boundary** (peer closes with no bytes pending before the 4-byte header) =
  graceful session end. Return "no frame" (nil), **not** an error. An EOF *mid-frame* (after the
  header, before `length` bytes arrive) is a truncation error.
- Write path: serialize → write 4-byte LE length → write JSON bytes → **flush**.

Go sketch:

```go
func writeFrame(w io.Writer, v any) error {
    b, err := json.Marshal(v)
    if err != nil { return err }
    if len(b) > 64<<20 { return errFrameTooLarge }
    var hdr [4]byte
    binary.LittleEndian.PutUint32(hdr[:], uint32(len(b)))
    if _, err := w.Write(hdr[:]); err != nil { return err }
    _, err = w.Write(b)
    return err
}
```

---

## 2. Transports

The **same framing** rides both. One box-request **session** = one duplex byte stream.

### 2.1 UDS (local, zero-config default)
- A Unix-domain stream socket the box dials (`fabricd_socket` on the box; `socket` in this config).
- **No token** on this hop — the socket file's filesystem permissions are the auth boundary. Scope
  it to the two processes (in k8s: a shared `emptyDir`).
- One connection = one session.

### 2.2 QUIC (remote, shared cluster service)
- **QUIC + TLS 1.3** (mandated by QUIC). **ALPN token: `fabricd/1`** — both ends must negotiate it;
  bump the suffix on any breaking framing change.
- **Server identity = a pinned self-signed cert.** The daemon presents one self-signed leaf cert
  (chain, leaf-first) + key. **No CA, no cert-manager, no mutual TLS.** The box pins the cert by the
  **SHA-256 of its DER encoding** and refuses any other. Client identity is a *separate, higher*
  layer (the `token` in `Init`, §4/§6) — not a client certificate.
- **One QUIC connection is long-lived; one bidirectional stream = one session.** The box calls
  `open_bi()` per request; the daemon `accept_bi()`s. Read the request frame(s) and write response
  frame(s) on that same stream.
- **Transport tuning (match these):** max idle timeout **30s**, keep-alive **10s**, max concurrent
  **bidi** streams **256** (per connection — bounds one box's fan-out), max concurrent **uni**
  streams **0** (unidirectional streams are refused; the protocol uses bidi only).

Go: use **`quic-go`'s raw stream API** (`Connection.AcceptStream` / `OpenStreamSync`).
**Do _not_ use `http3.Server`** — the box client speaks raw QUIC streams, not HTTP/3. (Switching to
HTTP/3 would be a *contract* change requiring a matching change to the box's `runlet-wire` client;
out of scope for a drop-in.) Pin the cert with `tls.Config.VerifyPeerCertificate` (or
`VerifyConnection`) comparing `sha256.Sum256(cert.Raw)` to the configured pin.

---

## 3. Session protocol

One session is strictly ordered on the stream: **`Init` → `Call`\* → `Drain`**, each request drawing
exactly one response, in order.

| Step | Box sends (`WireRequest`) | Daemon replies (`WireResponse`) |
|------|---------------------------|----------------------------------|
| 1 | `Init` (names + deadline + tenant + token) | `Ack` on full resolution, or `InitError{code,message}` if any name fails |
| 2..k | `Call` (name, action, payload) — one per `io.call(...)` | `Reply(Ok\|Err)` |
| last | `Drain` | `Metrics(BackendMetrics)` |

- **QUIC only:** validate the `Init.token` **before resolving any name** (§6). On auth failure, reject
  the session (the current Rust daemon closes the stream/connection).
- **Resolution is tenant-scoped.** Resolve each `Init.resources` name against the session tenant's
  binding set (name → kind → endpoint → credentials). A name bound to *another* tenant must resolve
  as not-found — existence never leaks across workspaces.
- **Out-of-order request** (a `Call` or `Drain` before `Init`) → `ProtocolError(message)`.
- Empty `resources` = a session that requested no egress (still valid; `Ack` it).

---

## 4. Message types & exact JSON

⚠️ **The single biggest gotcha: Rust `enum`s are externally tagged and Go has no sum types.** You
**must** hand-roll `MarshalJSON`/`UnmarshalJSON` for the enum types to match `serde`'s representation
byte-for-byte. The rules:
- **Unit variant** (no data) → a bare JSON **string**: `"Drain"`, `"Ack"`.
- **Data variant** → a single-key object `{"VariantName": <payload>}`.
- **`Result<T, E>`** is itself an externally-tagged enum → `{"Ok": <T>}` or `{"Err": <E>}`.

### 4.1 `WireRequest` (box → daemon) — you **deserialize** these

```jsonc
// Init  — note: tenant/token OMITTED when absent; resources may be []; timeout_ms always present
{"Init": {"resources": ["orders","cache"], "timeout_ms": 5000, "tenant": "acme", "token": "…"}}

// Call  — payload is a JSON *string* (the script's JSON-encoded args, opaque to you)
{"Call": {"name": "orders", "action": "query", "payload": "{\"sql\":\"SELECT 1\"}"}}

// Drain — unit variant
"Drain"
```

`WireInit` fields: `resources` `[]string` (optional, default `[]`), `timeout_ms` `uint64`
(**required** — the per-execution wall-clock budget / per-op client-side deadline), `tenant`
`string` (optional; the **trusted** acting-workspace id — scope resolution to it), `token` `string`
(optional; present on QUIC, absent on UDS — treat as a secret, never log).

`WireCall` fields: `name`, `action`, `payload` — all `string`, all required.

### 4.2 `WireResponse` (daemon → box) — you **serialize** these

```jsonc
"Ack"                                                   // Init fully resolved
{"InitError": {"code": "RESOURCE_NOT_FOUND", "message": "…"}}   // code ∈ {RESOURCE_NOT_FOUND, RESOURCE_KIND_MISMATCH} → box maps to 400
{"Reply": {"Ok": "{\"rows\":[…]}"}}                     // Call success: backend result as a JSON string
{"Reply": {"Err": { …EgressError… }}}                  // Call failure (§4.3)
{"Metrics": { …BackendMetrics… }}                       // answer to Drain (§4.4)
{"ProtocolError": "message"}                            // e.g. a Call before Init
```

### 4.3 `EgressError` (inside `Reply.Err`)

```jsonc
{
  "code": "DB_TIMEOUT",      // string — stable SCREAMING_SNAKE machine code
  "message": "…",            // string — human-safe cause (box surfaces it gated)
  "source": "db",            // string — capability tag: db|mongo|mail|redis|amq|auth (lowercase)
  "details": null,           // object | null — structured machine context, e.g. {"sqlstate":"40001"}
  "retryable": true,         // bool
  "owner": "operator"        // enum string — LOWERCASE: "caller" | "developer" | "operator"
}
```

**Emit all six fields** (the box's deserializer does not mark them `#[serde(default)]`); `details`
is JSON `null` when absent. `owner` is a lowercase enum string — default to `"operator"` unless you
have a reason to blame the caller (`"caller"`) or the script author (`"developer"`).

### 4.4 `BackendMetrics` (inside `Metrics`, answer to `Drain`)

An object with **all six arrays present** (each may be empty). Each element's fields (all required):

```jsonc
{
  "db":    [{"action":"query","duration_us":1234,"rows_returned":10,"rows_affected":0,"truncated":false}],
  "mongo": [{"action":"find","duration_us":900,"docs_returned":3,"docs_affected":0,"truncated":false}],
  "mail":  [{"action":"send","duration_us":5000,"recipients":2,"bytes":812,"accepted":true}],
  "redis": [{"action":"get","duration_us":120,"bytes":64,"hit":true}],
  "amq":   [{"action":"publish","duration_us":300,"messages":1,"bytes":128,"published":true}],
  "auth":  [{"action":"introspect","host":"idp.example","status":200,"duration_us":8000}]
}
```

`duration_us` is a `u128` on the Rust side; emit a plain JSON integer (real durations fit `int64`).
`status` is a `u16`. Everything else is a JSON number/bool/string as shown.

---

## 5. Error taxonomy (the `__runlet` shape)

`EgressError` is the wire form; the box renders a call failure into the `__runlet` tagged-error JSON
the JS wrapper throws:

```json
{"error":"<message>","code":"<CODE>","retryable":<bool>,"owner":"<owner>","source":"<source>","details":<obj?>}
```

You don't emit `__runlet` yourself — you emit `EgressError` (§4.3) and the box maps it. Keep `source`
to a known capability tag so the engine classifies the throw as a *capability* error (an unknown
source degrades to a script error). `owner` routes alerting: `operator` pages ops, `developer`/
`caller` do not.

---

## 6. Client auth (QUIC only) & constant-time compare

The box proves it may pull credentials via `Init.token`. The current daemon supports three modes;
preserve them:

- **`none`** — accept any (only safe on a strictly isolated network).
- **`static`** — an opaque shared secret. Compare in **constant time**.
- **`sa-token`** — a k8s projected ServiceAccount token, verified **offline** against the cluster
  JWKS (require `audience` + `issuer`; background-refresh the key set; **fail closed** until the
  first successful JWKS fetch). Go: `github.com/coreos/go-oidc` or `github.com/lestrrat-go/jwx`.

**Constant-time compare** (matches `runlet-wire::ct::ct_eq`): length difference short-circuits
(length is not the secret), equal-length inputs compared without a data-dependent branch.

```go
func ctEq(a, b []byte) bool {
    if len(a) != len(b) { return false }
    return subtle.ConstantTimeCompare(a, b) == 1
}
```

UDS carries no token — the socket's filesystem permissions are the boundary.

---

## 7. Acceptance gate

The Go daemon is "done" when it passes **both**, unchanged:

1. **This repo's driver-conformance suite** — [`docs/driver-conformance.md`](driver-conformance.md)
   + `docker-compose.yml`. It asserts each driver's behavior *through* the `runlet-wire` contract.
2. **runlet's integration suite** — `tests/test_simple.py` in `runlet-js`. Point it at the Go binary
   via **`FABRICD_BIN`** (the harness runs it as the sidecar); the box exercises it end-to-end over
   UDS and QUIC. The Go daemon must honor the config surface the harness expects (`FABRICD_CONFIG`,
   the `socket` / `quic` blocks, `resources`).

Treat these as the compiler you lost: run them in the Go repo's CI against `runlet-js` `main`.

---

## 8. What is **not** part of the contract

Free to (re)design idiomatically in Go — the box never sees any of it:

- **Config** — file format, `FABRICD_CONFIG` loading, the `resources` table shape, `quic`/`socket`
  blocks. (Keep the *keys* the conformance + integration harnesses set, per §7.)
- **Drivers & pooling** — pgx/go-redis/nats.go/mongo-go-driver/SMTP choices, connection pools,
  retry/backoff.
- **Resilience knobs** — `max_statement_timeout_ms` clamp, the per-target DB circuit breaker,
  cooldowns. (These are daemon-internal; the box's own deadline still rides in `Init.timeout_ms`.)
- **Observability** — the `fabricd_*` Prometheus series, `metrics_listen`, structured logging, OTel.
- **Cert tooling** — self-signed cert generation/rotation (the box only cares about the *pin*).

---

## 9. Build order for the rewrite (suggested)

1. **Framing + types** (§1, §4) with hand-rolled enum (un)marshaling, unit-tested against golden
   JSON captured from the Rust `runlet-wire` round-trip tests.
2. **UDS session host** (§2.1, §3) — `Init`→`Call`→`Drain` with a stub resolver + one real driver
   (Postgres via pgx). Get `test_simple.py` green over UDS with `FABRICD_BIN`.
3. **Resolver + remaining drivers**, tenant-scoping, `EgressError` mapping (§4.3, §5).
4. **QUIC transport** (§2.2) — pinned self-signed cert, ALPN `fabricd/1`, raw bidi streams, transport
   caps; then the three auth modes (§6).
5. **Observability + resilience** (§8) to reach production parity.
6. Full conformance + integration green (§7) → cutover.
</content>
