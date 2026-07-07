# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

The **egress sidecar / broker** for [runlet](https://github.com/hlop3z/runlet-js): it holds
the operator credential table (`resources` config) and **all** the vendor drivers, and hosts a
`BackendSet` per session behind the `runlet-wire` protocol over a local **UDS** or a remote
**QUIC** listener. The box (runlet) forwards logical resource names; this daemon resolves them
— tenant-scoped, a cross-tenant name resolves as `NotFound` — so credentials never reach the
box and never cross workspaces. On QUIC it validates the box's `WireInit.token` via a
pluggable `ClientAuthenticator` (`crates/fabricd/src/auth.rs`: `none` / `static` /
`sa-token`); the `sa-token` provider verifies k8s projected ServiceAccount tokens **offline**
against the cluster JWKS (`fabric_backends::sa_token::JwksVerifier`, a background-refreshed
key cache, fail-closed until the first fetch).

**This daemon is replaceable by design.** The wire contract (the `Egress` trait, the framed
`Init`→`Call`\*→`Drain` session, the QUIC transport, the error taxonomy, `ct_eq`) is OWNED by
the box repo — crate `runlet-wire` in `runlet-js` — and consumed here as a **sibling-checkout
path dependency** (`../runlet-js/crates/runlet-wire`). Clone runlet-js next to this repo
before building. Never fork or vendor the contract; a contract change is made in runlet-js
and consumed here.

**Crates:**

- **`fabric-backends`** (`crates/fabric-backends/`) — the driver bag: per-capability JS-free
  `*Backend`s (`db`/`mongo`/`mail`/`redis`/`amq`/`auth`; string-in/string-out dispatch +
  metrics + `into_resource_error`), `BackendSet` (wires them behind `runlet_wire::Egress`),
  the `*Config` types, the tenant-scoped `TenantResourceBinding` table + `resolve`
  (`resources.rs`), and `sa_token`. Deliberately **featureless** (always carries every
  backend) and never depends on runlet-core (no QuickJS here).
- **`fabricd`** (`crates/fabricd/`) — the daemon binary: config load (`FABRICD_CONFIG`), the
  UDS accept loop, the QUIC listener + client auth, session hosting, connection/stream caps,
  and the `fabricd_*` Prometheus metrics endpoint (`metrics_listen`).

The design record stays canonical in the runlet-js repo: `docs/design/resource-egress.md`,
`docs/design/network-fabric.md`, `docs/deployment.md`.

## Commands

Uses [Task](https://taskfile.dev) (`Taskfile.yml`). Raw `cargo` equivalents in parens.

- **Sibling checkout first:** `git clone https://github.com/hlop3z/runlet-js ../runlet-js` —
  the workspace does not build without it.
- **Build:** `task build` (`cargo build`) · release: `task build-release`
- **Run:** `task run` (`cargo run -p fabricd`; config via `FABRICD_CONFIG`, default `fabricd.json` — copy `fabricd.example.json`)
- **Format / Lint:** `task fmt` / `task fmt-check` · `task clippy` (`cargo clippy`) — see the lint warning below
- **Unit tests:** `cargo test`
- **Everything:** `task` (fmt-check + clippy + tests + supply-chain) · `task check` (no supply-chain)
- **Supply chain:** `task supply-chain` (cargo-audit + cargo-deny + cargo-vet; install via `task setup`). **cargo-vet is version-pinned in lockstep between `task setup` and CI (`ci.yml`), currently 0.10.2** — the `imports.lock` format changes across versions, so bump both together.
- **Docker:** `task docker-build` — note the build **context is the parent directory** (`docker build -f Dockerfile ..`) because of the sibling path dep.
- **Pair-level smokes:** `scripts/smoke_4b.sh` / `smoke_5.sh` / `smoke_quic.sh` (run inside `rust:1.92-alpine` on a docker network with Postgres; they build `runlet` from the sibling checkout) and `scripts/smoke_satoken.sh` (KIND end-to-end for the QUIC `sa-token` authenticator; needs docker + kind + kubectl, self-skips otherwise).
- runlet's integration suite (`tests/test_simple.py` in the sibling repo) exercises this daemon end-to-end; it builds `fabricd` from this checkout automatically (or uses `FABRICD_BIN`).

### CRITICAL: `cargo build` does not run the clippy lints

The strict lint contract lives in `[lints]` in `Cargo.toml` (same gauntlet as runlet-js:
no `unwrap`/`expect`/`panic`, no bare arithmetic, no `as` casts, `missing_docs_in_private_items`,
no `#[allow]` — use `#[expect(..., reason="...")]`), and **`cargo build` / `cargo test` do NOT
enforce it** — only `cargo clippy` does. Always run `task clippy` before considering a change
done; a hard clippy error can short-circuit later lint passes, so re-run until truly clean.

## Build environment gotchas

- **`aws-lc-sys` (the rustls crypto backend) needs a C toolchain.** On plain Windows hosts
  without MSVC build tools + NASM, build via Docker (`rust:1.92-alpine` + `musl-dev`).
- **rustls provider is `aws-lc-rs`, not `ring`.** When adding a TLS-using dependency,
  configure it with `rustls-no-provider` + the dep's `aws-lc-rs` feature so it reuses the
  existing provider. Pulling `ring` (or default `native-tls`/OpenSSL) links a second crypto
  stack and bloats the binary.
- **Contract changes happen in runlet-js.** If a change here needs a new wire message/field,
  make the `runlet-wire` change in the sibling repo first (additive/compatible), then consume
  it here. CI pins the contract by cloning runlet-js `main`.

## Conventions

Same conventions as runlet-js: mirror an existing backend module when adding one
(`crates/fabric-backends/src/db.rs` is the canonical template), keep functions small
(cognitive-complexity thresholds in `clippy.toml`), FFI **action tokens are `snake_case`** and
must stay in sync with the JS wrapper method names in runlet-core (the wrappers live in the
runlet-js repo — a new backend action lands in both repos).
