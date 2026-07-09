# Tasks — adopt-byo-capabilities-contract (seed)

> Seeded cross-repo from `runlet-js` (byo-capabilities + resource-privilege-guard, both archived
> 2026-07-09). Treat this as a checklist to validate/expand via `/opsx:propose` + `/opsx:decide` before
> `/opsx:apply`. Cross-repo detail: `../runlet-js/openspec/changes/archive/2026-07-09-*/`.

## 1. Wire adaptation — flat logical names (BREAKING, lockstep with the box)

- [x] 1.1 Bump/point the `runlet-wire` path dep to the new shape; confirm `WireInit.resources: Vec<String>` (six per-kind fields gone) and that `WireCall.name` is a logical name, not a kind — path dep already tracked the box; consumed the flat shape
- [x] 1.2 At `Init` (`crates/fabricd/src/main.rs` session hosting): resolve **each** name in `resources` against the tenant-scoped table → build a per-session **name → binding** map (`resources.rs::resolve` → `ResolvedResources.by_name`, a `BTreeMap`; `main.rs` untouched — same `resolve`/`from_configs`/`metrics` signatures)
- [x] 1.3 `fabric-backends`: `BackendSet` now keys by **logical name** (a `BTreeMap<String, BackendSlot>`, `BackendSlot` an enum over the kinds); `Call` routes by name; two same-kind names coexist (verified: `pg`/`pgbouncer`/`cockroach` all `db`)
- [x] 1.4 `resources.rs`: `resolve` returns `name → binding` (kind read from the resolved binding, box is kind-blind); preserved `RESOURCE_NOT_FOUND` + cross-tenant → `NotFound`. `KindMismatch` variant kept for API stability but no longer produced (box asserts no kind)
- [x] 1.5 Rewrote resolve tests for the flat shape (incl. multi-name); `cargo build` + `cargo clippy` + `cargo test` green (34 unit tests)

## 2. Drop mongo (D4)

- [x] 2.1 Removed the `mongo` backend from `fabric-backends` (deleted `mongo.rs`, the `Mongo` `ResourceBinding` variant, the slot/dispatch, and the mongo-specific tests)
- [x] 2.2 Dropped the `mongodb` dependency (workspace + `fabric-backends` Cargo) — `mongocrypt` fell out transitively. Pruned the now-dead `mongodb`/`mongocrypt`/`mongocrypt-sys`/`mongodb-internal-macros` exemptions from `supply-chain/config.toml`
- [x] 2.3 `BackendMetrics.mongo` no longer populated (the `metrics()` builder never fills it; the box-owned `runlet-wire` field is left intact)

## 3. Least-privilege preflight + boot gate + opt-out ban (resource-privilege-guard)

- [ ] 3.1 Add a per-driver `privilege_concern()` probe for each remaining backend (`db`/`redis`/`mail`/`amq`/`auth`) — detect an over-privileged account
- [ ] 3.2 Startup **preflight**: probe every configured resource; **refuse to boot** on an over-privileged resource unless `allow_privileged: true` is set on it
- [ ] 3.3 Add the `allow_privileged` per-resource config field (default `false`)
- [ ] 3.4 Derive the multitenant mandate from `WireInit.tenant`: on a tenant-scoped session, treat `allow_privileged` as **void** and refuse a flagged resource — no new wire field
- [ ] 3.5 **Coverage-regression guard**: a backend with no probe is unverifiable ⇒ not served (fail closed)
- [ ] 3.6 Boot-refusal message points operators at the hardened-role recipes (box `docs/design/resource-egress.md#hardened-roles`)

## 4. Reference image + docs (D5)

- [ ] 4.1 Formalize/publish the `Dockerfile` as the optional reference broker image (`docker run`)
- [ ] 4.2 Lift the fabricd-internal preflight/probe/boot-gate design out of the box's `resource-egress.md` § Downstream (informative) into this repo's own OpenSpec `design.md`/specs
- [ ] 4.3 Note that a box serving only deterministic / `http` / `s3` / box-direct requests needs no broker

## 5. Wrap-up

- [x] 5.1 `cargo fmt` + `cargo clippy --workspace` + `cargo test --workspace` green (whole workspace), built on `rust:1.92-alpine` via Docker
- [~] 5.2 Coordinate the merge so the box's `runlet-wire` bump and this daemon's adaptation land together — **verified together**: the box's byo-capabilities commit + this daemon's §1/§2 adaptation pass the full box→fabricd integration suite end-to-end (239/239, incl. PostgreSQL/PgBouncer/CockroachDB/NATS via `io`); still to do is the actual coordinated push/merge of both repos

> **Scope note (2026-07-09):** §1 + §2 + §5 done — the daemon compiles against the new wire, drops
> mongo, and the driver-backed path is verified end-to-end. §3 (least-privilege preflight/boot gate)
> and §4 (reference image + docs) are **deferred** to a follow-up; they are security-hardening /
> packaging, orthogonal to the wire+mongo migration and not required for the integration suite to pass.
