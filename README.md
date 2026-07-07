# fabricd

The **egress sidecar / broker** for [runlet](https://github.com/hlop3z/runlet-js), the
sandboxed JavaScript execution service. `fabricd` holds the operator credential table and
**all** the vendor drivers (Postgres, MongoDB, SMTP, Redis, AMQP/NATS, OIDC); the box holds
neither. A runlet request names **logical resources** (`config.io`), the box forwards those
names over a session, and `fabricd` resolves them to real endpoints + credentials and performs
the I/O.

**This daemon is replaceable by design.** The wire contract it implements — the `Egress`
trait, the framed `Init`→`Call`\*→`Drain` session protocol, the QUIC transport, the error
taxonomy — is owned by the box repo (`runlet-js`, crate `crates/fabric-wire`). Anything that
speaks that contract can stand in for `fabricd`; nothing in `runlet-js` depends on this repo.

## Layout

- **`crates/fabric-backends`** — the driver bag: one JS-free `*Backend` per capability
  (`db`/`mongo`/`mail`/`redis`/`amq`/`auth`), the `BackendSet` that wires them behind the
  `fabric_wire::Egress` port, the `*Config` types, the tenant-scoped `resources` binding
  table, and `sa_token` (offline k8s ServiceAccount-token verification against the cluster
  JWKS). Featureless — the driver bag always carries every backend.
- **`crates/fabricd`** — the daemon (bin): hosts a `BackendSet` per session behind the
  `fabric-wire` protocol over **either transport** — a local **UDS** (the zero-config
  default) or a remote **QUIC** listener with a pluggable client authenticator
  (`none` / `static` / `sa-token`).

One UDS connection / one QUIC bi-stream = one box-request session
(`Init`(names+deadline+tenant) → `Call`\* → `Drain`(metrics)). Resolution is scoped to the
session tenant's binding set: a name bound for another tenant resolves as `NotFound`, so
credentials never reach the box and never cross workspaces.

## Building — sibling checkout required

The workspace path-depends on `../runlet-js/crates/fabric-wire`:

```sh
git clone https://github.com/hlop3z/runlet-js ../runlet-js   # once, next to this repo
cargo build            # or: task build
cargo clippy           # the strict lint gauntlet — cargo build does NOT run it
```

Docker (context is the parent directory holding both repos):

```sh
docker build -t fabricd -f Dockerfile ..    # or: task docker-build
```

## Configuration

`fabricd` reads its config from `FABRICD_CONFIG` (default `fabricd.json`). Copy
[`fabricd.example.json`](fabricd.example.json) → `fabricd.json` (gitignored — it holds real
credentials) and fill in your endpoints. Each key under `resources` is a logical name a
request may reference via `config.io`; the box only ever sends the name.

Transports:

- **UDS** (default): `"socket": "/run/fabricd/fabricd.sock"` — share the socket dir with the
  box, which sets `"fabricd_socket"` in its config.
- **QUIC** (remote): a `"quic"` block — listener address, cert/key (self-signed, the box pins
  the fingerprint), client auth mode (`none` / `static` / `sa-token`), and connection/stream
  caps. The box side sets `"fabricd_quic"`.

Driver-side resilience also lives here (e.g. `max_statement_timeout_ms`, the db breaker), and
backend metrics are exposed on the optional `metrics_listen` Prometheus endpoint
(`fabricd_*` series).

## Design docs

The design record stays canonical in the box repo:
[`resource-egress.md`](https://github.com/hlop3z/runlet-js/blob/main/docs/design/resource-egress.md)
(why drivers left the sandbox),
[`network-fabric.md`](https://github.com/hlop3z/runlet-js/blob/main/docs/design/network-fabric.md)
(the QUIC remote transport + sa-token auth), and
[`deployment.md`](https://github.com/hlop3z/runlet-js/blob/main/docs/deployment.md) §5
(running the pair).

## Tests / smokes

Unit tests are hermetic: `cargo test`. The pair-level live smokes live in `scripts/`
(`smoke_4b.sh`, `smoke_5.sh`, `smoke_quic.sh` — run in a `rust:1.92-alpine` container on a
docker network with Postgres; `smoke_satoken.sh` — the KIND end-to-end for the QUIC
`sa-token` authenticator). They build `runlet` from the sibling checkout. runlet's own
integration suite (`tests/test_simple.py` in runlet-js) also exercises this daemon end-to-end
and picks it up automatically from the sibling checkout (or `FABRICD_BIN`).
