## Why

> **Cross-repo heads-up, seeded from `runlet-js`.** Two changes just landed and archived in the box
> repo that this daemon must catch up with in lockstep. This is a **seed proposal** — run
> `/opsx:explore` → `/opsx:propose` → `/opsx:decide` to flesh it into full artifacts (specs/design),
> then `/opsx:apply`. The authoritative detail lives in the box repo's archived changes:
>
> - `../runlet-js/openspec/changes/archive/2026-07-09-byo-capabilities/` (proposal.md, design.md D1–D9)
> - `../runlet-js/openspec/changes/archive/2026-07-09-resource-privilege-guard/` (design.md § Downstream, tasks §5)
> - `../runlet-js/docs/design/resource-egress.md` (the byo-capabilities note + the least-privilege / hardened-role section)

The box (`runlet`) is now a **framework, not a service**: it ships exactly three in-engine built-ins
(`http`, `s3`, `io`) and **no shipped driver-cap wrappers**. Everything else is reached through the one
primitive `io.call(name, action, payload)`. As a consequence the **wire contract this daemon consumes
changed** (a deliberate, non-additive break — the box owns `runlet-wire`, we consume it as a path dep,
so this daemon will fail to compile against the new crate until it adapts). Separately, the box already
carries the trusted tenant id in the handshake; the **least-privilege mandate** is now a spec contract
this daemon is expected to enforce.

## What changes (this daemon's work)

### 1. Consume `WireInit.resources` (flat logical names) — BREAKING

`WireInit` no longer has six per-kind `Option<String>` slots (`db`/`mongo`/`mail`/`redis`/`amq`/`auth`);
it now carries **`resources: Vec<String>`** (plus the unchanged `timeout_ms`, `tenant`, `token`). And
`WireCall.name` is now a **logical resource name** (`"orders"`), not a capability *kind* (`"db"`).

- At `Init`: resolve **each** name in `resources` against the tenant-scoped `resources` table
  (`fabric-backends/src/resources.rs`), building a **name → (kind, backend)** map for the session. The
  *kind* is looked up operator-side from the resource entry — the box is kind-blind and never sends it.
- At `Call`: route by the **logical name** to the backend resolved at `Init` (was: route by kind to the
  single per-kind binding). `BackendSet` (`fabric-backends`) becomes a per-name map, not per-kind.
- Keep `RESOURCE_NOT_FOUND` / `RESOURCE_KIND_MISMATCH` / tenant-scoping semantics; a name outside the
  tenant's bindings still resolves as `NotFound`.
- The break lands **in lockstep** with the box's `runlet-wire` bump — coordinate the merge.

### 2. Drop the `mongo` driver + `mongocrypt` (D4)

- Remove the `mongo` backend from `fabric-backends` (its `*Backend`, `*Config`, dispatch, resolve
  branch) and drop the `mongodb` + `mongocrypt` (C) dependency — the single worst line in the
  `cargo vet` / second-crypto-stack tail.
- `runlet-wire::BackendMetrics` still *has* a `mongo` field (the box kept it, additive-compatible); just
  stop populating it. Removing that field is a separate box-owned wire change — coordinate only if wanted.

### 3. Least-privilege preflight + boot gate + opt-out ban (from `resource-privilege-guard`)

The behavioral contract now lives in the box's `openspec/specs/tenant-egress` (requirements *"Multitenant
path forbids the privilege opt-out"* + the least-privilege framing on *"Tenant identity carried on the
egress session"*). This daemon implements it:

- A startup **privilege preflight**: a per-driver `privilege_concern()` probe (one per backend) that
  detects an over-privileged account (e.g. a Postgres superuser, Redis `default`, a mail open-relay, an
  amq admin/management user, an over-scoped auth client).
- An `allow_privileged` **per-resource config field** + **refuse to boot** when a resource is flagged
  over-privileged and the operator has not set it.
- **Derive the multitenant mandate from `WireInit.tenant`**: on a session carrying a trusted tenant id,
  treat `allow_privileged` as **void** and refuse to serve a flagged resource — **no new wire field**
  (the tenant presence is the signal; the box adds none).
- **Coverage-regression guard**: a driver with no probe ⇒ unverifiable ⇒ **not served** (so adding a
  driver without a probe fails closed, not open).

### 4. Ship as the optional reference broker image (D5)

The box demoted the broker from "shipped core" to an **optional reference `docker run` image**. Formalize
the existing `Dockerfile` as that published reference image; document that a box serving only
deterministic / `http` / `s3` / box-direct requests needs no broker at all.

## Impact

- **`fabric-backends`** — `BackendSet` keyed by logical name; `resources.rs` resolve returns `(kind,
  backend)` per name; the six probes + preflight; **mongo backend + `mongodb`/`mongocrypt` dep removed**.
- **`fabricd`** — `Init` builds the per-name session map from `resources`; `Call` routes by name; the
  `allow_privileged` config field + boot refusal; the tenant-derived opt-out ban.
- **`runlet-wire` (path dep, box-owned)** — consumed at its new shape; no edits here (a contract change is
  made in `runlet-js`).
- **Supply chain** — `cargo vet` / `cargo deny` shrink once `mongocrypt` is gone; re-run after the dep drop.
- **Docs/specs** — lift the fabricd-internal preflight/probe/boot-gate design out of the box's
  `resource-egress.md` § Downstream (informative) into this repo's own OpenSpec artifacts.
