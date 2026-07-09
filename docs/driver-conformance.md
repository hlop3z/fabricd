# Driver conformance checklist

**Origin.** These behaviors were previously asserted in the box repo (`runlet-js`,
`tests/test_simple.py`) by driving the box's `/execute` endpoint with `io.call(...)`. With the
byo-capabilities / trust-flip split, the box owns none of this — it forwards logical names and
`fabricd` resolves them to a kind/endpoint/creds and runs the driver. So these are **fabricd's**
conformance requirements. The box tests were box-shaped (JS `handler` → `io.call`) and could not
move verbatim; this file captures the *intent* so it can be re-expressed as fabricd tests — either
Rust integration tests over `fabric-backends` (`db.rs`/`amq.rs`/`auth.rs`/`kv.rs`/`mail.rs`), or a
harness that speaks the `runlet-wire` protocol to a running `fabricd`.

**Infra.** `docker-compose.yml` (moved alongside this doc) brings up every backend below. Map a
`fabricd.json` resource table at the host ports; see `fabricd.conformance.example.json`.

The box↔fabricd wire (`WireCall {name, action, payload}` → `WireResponse::Reply(Result<String,
EgressError>)`) is unchanged; `action` tokens are `snake_case` (e.g. `user_info`, not `userInfo`).

---

## `db` — Postgres + CockroachDB (`fabric-backends/src/db.rs`)

Run the whole set against **both** `postgres` (5432) and `cockroach` (26257). CockroachDB differs
where noted (all integer literals are INT8).

**Type mapping (result JSON).** A value that doesn't fit a JS number exactly comes back as a
**string**; values that fit come back as JSON numbers/booleans/null.

- [ ] `SELECT 1 as num` → `1` (number). **CockroachDB:** `"1"` (string — INT8).
- [ ] Column names preserved and ordered: `SELECT 1 as a, 2 as b` → columns `["a","b"]`.
- [ ] `row_count` correct: `SELECT 1 UNION ALL SELECT 2` → `2`.
- [ ] Parameterized: `SELECT $1::text as name` with `["Bob"]` → `"Bob"`.
- [ ] Boolean param: `SELECT $1::boolean` with `[true]` → `true`.
- [ ] **BIGINT is always a string**: `9223372036854775807` → `"9223372036854775807"`, `typeof` string.
- [ ] **NUMERIC is a string**: `typeof` string (exactness preserved, e.g. `12345.67`).
- [ ] INT4 is a **number**. **CockroachDB:** `SERIAL`/`id` is INT8 → string.
- [ ] BOOLEAN column → `true`; TEXT column → `"Alice"`.
- [ ] JSONB pass-through: `'{"key":"val"}'` → object with `.key === "val"` (parsed, not a string).
- [ ] UUID → string; TIMESTAMPTZ → string.
- [ ] SQL `NULL` → JSON `null`.

**Execute / DML.**
- [ ] `INSERT` returns `rows_affected: 1`; `UPDATE` returns the affected count.

**Transactions.**
- [ ] `begin` + `execute` + `commit` → the row is visible afterward (`row_count 1`).
- [ ] `begin` + `execute` + `rollback` → the row is gone (`row_count 0`).
- [ ] Uncaught error mid-transaction → **auto-rollback** (no partial commit); surfaced as an error.

**Row cap.**
- [ ] A resource with `max_rows: 5`: a 50-row `generate_series` returns `truncated: true` and
      `row_count: 5`.

**Error classification** (drives the box's HTTP projection — keep the `EgressError` fault kind right).
- [ ] A permanent SQL error (`SELECT * FROM nonexistent_table_xyz`) → a **non-retryable** classified
      error (box parks it at 4xx). Not a success.
- [ ] An unreachable target (`host: broken-db.invalid`) → a **retryable** classified error (box maps
      to a retryable 5xx + `Retry-After`). Not a success, not permanent.

**Metrics.** Two `query` calls in one session → two entries in the drained `db` metrics
(`BackendMetrics`), surfaced by the box as `meta.io.<name>` with per-op detail.

**Setup SQL** used by the box suite (reuse for fixtures):
```sql
CREATE TABLE test_types (
  id SERIAL PRIMARY KEY, big BIGINT, num NUMERIC(10,2), flag BOOLEAN,
  name TEXT, data JSONB, ts TIMESTAMPTZ DEFAULT NOW(), uid UUID DEFAULT gen_random_uuid());
INSERT INTO test_types (big, num, flag, name, data)
VALUES (9223372036854775807, 12345.67, true, 'Alice', '{"key":"val"}');
CREATE TABLE test_txn (id SERIAL PRIMARY KEY, val TEXT);
```

---

## `db` resilience — clamp, breaker, pooler (moved with the trust flip)

These moved *to* fabricd and per the box comments were **not yet implemented there**. They are
conformance gaps to close, not just tests to copy.

**Statement-timeout ceiling** (`max_statement_timeout_ms`, was Tier 0 in the box):
- [ ] A resource requesting `statement_timeout_ms: 0` (unlimited) is **clamped** to the daemon
      ceiling: `SELECT pg_sleep(2)` is killed before it finishes.
- [ ] A resource requesting `statement_timeout_ms: 60000` (huge) is likewise clamped + killed.

**Circuit breaker** (was Tier 3; the `runlet-wire` `CircuitBreaker` exists — wire it in fabricd):
- [ ] Repeated connect failures to a dead target (`db-broken`) trip the breaker → subsequent calls
      fast-fail `DB_CIRCUIT_OPEN` (well under a connect wait, < ~1.5s) instead of blocking.
- [ ] A different, **healthy** target is unaffected by another target's open breaker.

**PgBouncer transaction-mode edges** (pooler on 6432; also run the safe cases direct on 5432):
- [ ] Session `SET statement_timeout` is a **hard guarantee on a direct connection** (a `-fast`
      resource kills `pg_sleep(3)`), but **best-effort through a txn-mode pooler** — record, don't
      assert, and confirm the server stays responsive after.
- [ ] Explicit transaction pins one server connection: a `TEMP TABLE ... ON COMMIT DROP` created,
      written, and read **within one begin/commit** holds (returns the inserted value).
- [ ] Prepared-statement reuse survives connection rotation: 25× the same parameterized query does
      **not** trip "prepared statement does not exist" (needs `MAX_PREPARED_STATEMENTS > 0`).

**Pooler `query_timeout` backstop** (was Tier 4; pooler set to 2s):
- [ ] `pg_sleep(3)` (over the 2s pooler ceiling, under the box's ~4s wall clock) is killed **by the
      pooler**, returning an error below the box wall-clock deadline; the pooler is healthy right after.

---

## `amq` — NATS backend (`fabric-backends/src/amq.rs`)

Backends: RabbitMQ (default, 5672) and NATS (`backend: "nats"`, 4222). The box suite covered NATS:
- [ ] `send` of a batch `[['ev.a',{i:1}], ['ev.b',{i:2}]]` → published count `2`.
- [ ] Single-pair shorthand `send(['ev.c',{i:3}])` → `1`.
- [ ] `request` to a subject with **no responder** → a classified error whose code starts `AMQ_`
      (use a short `request_timeout_ms`, e.g. 500, to keep it fast). Not a hang, not a success.

---

## `auth` — Keycloak + ZITADEL (`fabric-backends/src/auth.rs`)

Provider-agnostic OIDC/IAM. Keycloak (8081) is fully automatic (admin-cli password grant mints a
user token + a confidential client for introspection). ZITADEL (8082) needs its bootstrap SA PAT
(`./.zitadel/zitadel-admin-sa.pat`, gitignored) and covers discovery + userinfo + the throw path;
introspection-with-creds is exercised on Keycloak (ZITADEL introspection needs an API app).

- [ ] `user_info(valid_token)` → `ok: true` (OIDC discovery + bearer userinfo).
- [ ] `user_info` resolves `claims.sub` (a string).
- [ ] `user_info('garbage')` → **in-band** `{ ok: false, code: "AUTH_INVALID_TOKEN" }`, **never
      thrown** (a bad token is the caller's business flow, not an infra error).
- [ ] Per-token cache: two `user_info` calls for the same token = **one** upstream round trip
      (one metrics entry, `action: "user_info"`).
- [ ] `introspect` **without** configured client creds → **throws** a tagged capability error
      (misconfig is infra, not in-band).
- [ ] With creds (Keycloak): `introspect(valid)` → `claims.active: true`; `introspect('bogus')` →
      `claims.active: false`.

---

## `kv` (redis, 6379) and `mail` — not covered by the box suite

- `kv`/redis: `fabric-backends/src/kv.rs` ships but the box suite had no redis section
  post-byo-capabilities. Add basic conformance (string set/get; missing get → null) against the
  `redis` compose service.
- `mail`: **no SMTP catcher was moved** (the box compose had none). Add a Mailpit service (stub in
  `docker-compose.yml`) and a `kind: mail` resource to give `fabric-backends/src/mail.rs` a
  compose-backed conformance target.

---

## Notes for whoever implements this

- Keep `action` tokens `snake_case` and in sync with the box-side JS wrappers users compose
  (`find_one`, not `findOne`).
- The box classifies HTTP status off the `EgressError` fault kind (permanent → 4xx park, retryable
  → 5xx + Retry-After). Getting the fault classification right in the driver is what makes the box
  behave — assert the classification, not just "an error happened".
- The number/decimal string-mapping contract (BIGINT/NUMERIC/UUID/TIMESTAMP → string) is the seam
  that lets the box's in-script `$`/`Decimal` do exact math. It's a hard contract, not cosmetic.
