//! In-process [`Egress`] adapter — wires this crate's own driver capabilities behind the
//! egress seam, so a consumer can run `io.call(...)` without a sidecar.
//!
//! Transitional: the JS-free backends it holds (`DbBackend`, `RedisBackend`, …) are exactly what
//! a sidecar (`fabricd`) hosts now that the drivers live outside the sandbox process — see
//! `docs/design/resource-egress.md` / `docs/design/network-fabric.md`.
//!
//! Build a fresh [`BackendSet`] per session from the resolved operator config (each backend
//! connects lazily on first use and carries the per-request deadline) and wire it as the session's
//! egress port. After the run, drain the aggregated per-capability [`metrics`](BackendSet::metrics)
//! into the response.
//!
//! Post byo-capabilities the box is **kind-blind**: it addresses a **flat list of logical resource
//! names**, so the set is a **name → backend** map (two names of the same kind coexist), not the
//! old per-kind slots. Covers `db`/`mail`/`redis`/`amq`/`auth`; `http` and `s3` remain in-engine
//! (no driver / pure signing). `mongo` was dropped with `mongocrypt`.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::runtime::Handle;

use runlet_wire::{CircuitBreaker, Egress, EgressError, ErrorOwner};

use runlet_wire::{AuthMetric, BackendMetrics, DbMetric, MailMetric, MeteredEgress, RedisMetric};

use crate::amq::{AmqError, AmqProducer};
use crate::auth::{AuthBackend, AuthConfig};
use crate::db::{DbBackend, DbConfig, DbDeps, DbError};
use crate::kv::{RedisBackend, RedisConfig, RedisError};
use crate::mail::{MailBackend, MailConfig, MailError};
use crate::resources::{ResolvedResources, ResourceBinding};

/// Shared runtime/resilience deps for the async backends (`db`). Cloned per backend.
#[derive(Debug, Clone)]
pub struct AsyncDeps {
    /// Runtime handle for the async drivers' `block_on` (the request thread's handle).
    pub handle: Handle,
    /// Optional shared `db` circuit breaker (Tier 3).
    pub breaker: Option<Arc<CircuitBreaker>>,
    /// Per-execution wall-clock budget (the per-query/op client-side deadline).
    pub timeout: Duration,
}

/// An in-process egress holding this session's capability backends, keyed by logical resource name.
///
/// Built with [`BackendSet::from_configs`] from the resolved operator config; each backend connects
/// lazily on first use.
#[derive(Default, Debug)]
pub struct BackendSet {
    /// Logical resource name → its lazily-connected backend (ordered, so metric aggregation is
    /// deterministic).
    backends: BTreeMap<String, BackendSlot>,
}

/// One resolved backend, tagged by kind. The `Egress::call` name selects the entry; the kind here
/// selects the dispatch + the metrics bucket.
#[derive(Debug)]
enum BackendSlot {
    /// A `db` (Postgres-family) backend.
    Db(DbSlot),
    /// A `mail`/SMTP backend.
    Mail(MailSlot),
    /// A `redis` backend.
    Redis(RedisSlot),
    /// An `amq` producer (stateless — connects per call).
    Amq(AmqProducer),
    /// An `auth` (OIDC/IAM) backend.
    Auth(AuthSlot),
}

impl BackendSlot {
    /// Builds a lazily-connected slot from one resolved binding.
    fn from_binding(binding: &ResourceBinding, deps: &AsyncDeps) -> Self {
        match binding {
            ResourceBinding::Db(cfg) => Self::Db(DbSlot {
                config: cfg.as_ref().clone(),
                deps: deps.clone(),
                backend: OnceLock::new(),
            }),
            ResourceBinding::Mail(cfg) => Self::Mail(MailSlot {
                config: cfg.as_ref().clone(),
                backend: OnceLock::new(),
            }),
            ResourceBinding::Redis(cfg) => Self::Redis(RedisSlot {
                config: cfg.as_ref().clone(),
                backend: OnceLock::new(),
            }),
            ResourceBinding::Amq(cfg) => Self::Amq(AmqProducer::new(cfg.as_ref().clone())),
            ResourceBinding::Auth(cfg) => Self::Auth(AuthSlot {
                config: cfg.as_ref().clone(),
                backend: OnceLock::new(),
            }),
        }
    }
}

impl BackendSet {
    /// An empty adapter (no resources wired).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from the session's resolved operator config: each `name → binding` becomes a
    /// lazily-connected backend. `deps` carries the runtime handle, the optional breaker, and the
    /// deadline. This is the daemon-side constructor — `fabricd` resolves the session's logical
    /// names to these bindings first.
    #[must_use]
    pub fn from_configs(configs: &ResolvedResources, deps: &AsyncDeps) -> Self {
        let mut backends = BTreeMap::new();
        for (name, binding) in &configs.by_name {
            drop(backends.insert(name.clone(), BackendSlot::from_binding(binding, deps)));
        }
        Self { backends }
    }

    /// Drains every wired backend's metrics into one [`BackendMetrics`], aggregated by kind across
    /// all names (so two `db` resources merge into `db`). Empty for any capability the run never
    /// touched; `mongo` is always empty (the driver was dropped, the wire field kept).
    #[must_use]
    pub fn metrics(&self) -> BackendMetrics {
        let mut metrics = BackendMetrics::default();
        for slot in self.backends.values() {
            match slot {
                BackendSlot::Db(db) => metrics.db.extend(db.drained()),
                BackendSlot::Mail(mail) => metrics.mail.extend(mail.drained()),
                BackendSlot::Redis(redis) => metrics.redis.extend(redis.drained()),
                BackendSlot::Amq(producer) => metrics.amq.extend(producer.drain_metrics()),
                BackendSlot::Auth(auth) => metrics.auth.extend(auth.drained()),
            }
        }
        metrics
    }
}

impl Egress for BackendSet {
    fn call(&self, name: &str, action: &str, payload_json: &str) -> Result<String, EgressError> {
        match self.backends.get(name) {
            Some(BackendSlot::Db(slot)) => dispatch_db(slot, action, payload_json),
            Some(BackendSlot::Mail(slot)) => dispatch_mail(slot, action, payload_json),
            Some(BackendSlot::Redis(slot)) => dispatch_redis(slot, action, payload_json),
            Some(BackendSlot::Amq(producer)) => dispatch_amq(producer, action, payload_json),
            Some(BackendSlot::Auth(slot)) => dispatch_auth(slot, action, payload_json),
            None => Err(unknown_egress(name)),
        }
    }
}

impl MeteredEgress for BackendSet {
    fn drain_metrics(&self) -> BackendMetrics {
        self.metrics()
    }
}

/// The error for an `io.call` naming a resource this session never resolved. A resolved session
/// only ever calls names it declared, so this is a fail-closed backstop, not a normal path.
fn unknown_egress(name: &str) -> EgressError {
    EgressError::new("engine", "IO_UNKNOWN", format!("unknown egress '{name}'"))
        .owner(ErrorOwner::Developer)
}

// -- Dispatch ---------------------------------------------------------------

/// `db`: unpack `{sql, params}` and dispatch.
fn dispatch_db(slot: &DbSlot, action: &str, payload_json: &str) -> Result<String, EgressError> {
    let backend = slot.backend()?;
    let args = parse_db_payload(payload_json)?;
    backend
        .call(action, &args.sql, &args.params_json)
        .map_err(DbError::into_resource_error)
}

/// `mail`: the payload is the send envelope, passed straight through.
fn dispatch_mail(slot: &MailSlot, action: &str, payload_json: &str) -> Result<String, EgressError> {
    slot.backend()?
        .call(action, payload_json)
        .map_err(MailError::into_resource_error)
}

/// `redis`: the payload is the op args, passed straight through.
fn dispatch_redis(
    slot: &RedisSlot,
    action: &str,
    payload_json: &str,
) -> Result<String, EgressError> {
    slot.backend()?
        .call(action, payload_json)
        .map_err(RedisError::into_resource_error)
}

/// `amq`: the payload is the batch / request, passed straight through.
fn dispatch_amq(
    producer: &AmqProducer,
    action: &str,
    payload_json: &str,
) -> Result<String, EgressError> {
    producer
        .call(action, payload_json)
        .map_err(AmqError::into_resource_error)
}

/// `auth`: unpack `{token}` and dispatch (the backend's `call` already maps its errors).
fn dispatch_auth(slot: &AuthSlot, action: &str, payload_json: &str) -> Result<String, EgressError> {
    let backend = slot.backend()?;
    let token = parse_auth_token(payload_json)?;
    backend.call(action, &token)
}

// -- Lazy slots -------------------------------------------------------------

/// Lazily-connected `db` egress: connect params + a connect-once cell.
#[derive(Debug)]
struct DbSlot {
    /// Operator connection config.
    config: DbConfig,
    /// Async runtime + breaker + deadline.
    deps: AsyncDeps,
    /// Connect-once cell (`Ok` backend or the classified `Err`, cached for the invocation).
    backend: OnceLock<Result<DbBackend, EgressError>>,
}

impl DbSlot {
    /// Returns the connected backend, connecting on first use.
    fn backend(&self) -> Result<&DbBackend, EgressError> {
        let deps = DbDeps {
            handle: &self.deps.handle,
            timeout: self.deps.timeout,
            breaker: self.deps.breaker.as_deref(),
        };
        match self
            .backend
            .get_or_init(|| DbBackend::connect_resource(&self.config, &deps))
        {
            Ok(backend) => Ok(backend),
            Err(err) => Err(err.clone()),
        }
    }

    /// The metrics recorded so far (empty if never connected/used).
    fn drained(&self) -> Vec<DbMetric> {
        match self.backend.get() {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }
}

/// Lazily-built `mail` egress.
#[derive(Debug)]
struct MailSlot {
    /// Operator config.
    config: MailConfig,
    /// Build-once cell.
    backend: OnceLock<Result<MailBackend, EgressError>>,
}

impl MailSlot {
    /// Returns the backend, building the transport on first use.
    fn backend(&self) -> Result<&MailBackend, EgressError> {
        match self
            .backend
            .get_or_init(|| MailBackend::connect_resource(&self.config))
        {
            Ok(backend) => Ok(backend),
            Err(err) => Err(err.clone()),
        }
    }

    /// The metrics recorded so far (empty if never built/used).
    fn drained(&self) -> Vec<MailMetric> {
        match self.backend.get() {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }
}

/// Lazily-connected `redis` egress.
#[derive(Debug)]
struct RedisSlot {
    /// Operator config.
    config: RedisConfig,
    /// Connect-once cell.
    backend: OnceLock<Result<RedisBackend, EgressError>>,
}

impl RedisSlot {
    /// Returns the connected backend, connecting on first use.
    fn backend(&self) -> Result<&RedisBackend, EgressError> {
        match self
            .backend
            .get_or_init(|| RedisBackend::connect_resource(&self.config))
        {
            Ok(backend) => Ok(backend),
            Err(err) => Err(err.clone()),
        }
    }

    /// The metrics recorded so far (empty if never connected/used).
    fn drained(&self) -> Vec<RedisMetric> {
        match self.backend.get() {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }
}

/// Lazily-built `auth` egress.
#[derive(Debug)]
struct AuthSlot {
    /// Operator config.
    config: AuthConfig,
    /// Build-once cell.
    backend: OnceLock<Result<AuthBackend, EgressError>>,
}

impl AuthSlot {
    /// Returns the backend, building the client on first use.
    fn backend(&self) -> Result<&AuthBackend, EgressError> {
        match self
            .backend
            .get_or_init(|| AuthBackend::connect_resource(&self.config))
        {
            Ok(backend) => Ok(backend),
            Err(err) => Err(err.clone()),
        }
    }

    /// The metrics recorded so far (empty if never built/used).
    fn drained(&self) -> Vec<AuthMetric> {
        match self.backend.get() {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }
}

// -- Payload unpacking ------------------------------------------------------

/// The `db` egress payload shape: `{ "sql": string, "params"?: array }`.
#[derive(Deserialize)]
struct DbPayload {
    /// The SQL text.
    sql: String,
    /// Bound parameters (defaults to an empty array when absent).
    #[serde(default)]
    params: Value,
}

/// Unpacked `db` payload: the SQL plus the re-serialized params array.
#[derive(Debug)]
struct DbArgs {
    /// SQL text passed straight to the backend.
    sql: String,
    /// JSON-encoded params array (the backend re-parses it).
    params_json: String,
}

/// Parses the `db` egress payload, defaulting missing/null params to `[]`.
fn parse_db_payload(payload_json: &str) -> Result<DbArgs, EgressError> {
    let payload: DbPayload = serde_json::from_str(payload_json).map_err(|err| {
        EgressError::new("db", "DB_BAD_PAYLOAD", format!("invalid db payload: {err}"))
            .owner(ErrorOwner::Developer)
    })?;
    let params_json = if payload.params.is_null() {
        "[]".to_owned()
    } else {
        serde_json::to_string(&payload.params).unwrap_or_else(|_err| "[]".to_owned())
    };
    Ok(DbArgs {
        sql: payload.sql,
        params_json,
    })
}

/// The `auth` egress payload: `{ "token": string }`.
#[derive(Deserialize)]
struct AuthPayload {
    /// Bearer token (may be empty).
    #[serde(default)]
    token: String,
}

/// Parses the `auth` payload into the bearer token string.
fn parse_auth_token(payload_json: &str) -> Result<String, EgressError> {
    let payload: AuthPayload = serde_json::from_str(payload_json).map_err(|err| {
        EgressError::new(
            "auth",
            "AUTH_REQUEST",
            format!("invalid auth payload: {err}"),
        )
        .owner(ErrorOwner::Developer)
    })?;
    Ok(payload.token)
}

#[cfg(test)]
mod tests {
    //! Covers the adapter glue that needs no live backend: payload unpacking and unknown-name
    //! routing. Real dispatch is covered by the per-capability integration suites against live
    //! backends.

    use super::{BackendSet, parse_auth_token, parse_db_payload};
    use runlet_wire::Egress;

    /// A well-formed `db` payload yields the SQL and a re-serialized params array.
    #[test]
    fn parses_db_sql_and_params() {
        let args = parse_db_payload(r#"{"sql":"SELECT $1","params":[7]}"#)
            .unwrap_or_else(|_err| unreachable!("valid payload"));
        assert_eq!(args.sql, "SELECT $1");
        assert_eq!(args.params_json, "[7]");
    }

    /// Missing `db` params default to an empty array.
    #[test]
    fn defaults_missing_db_params() {
        let args = parse_db_payload(r#"{"sql":"SELECT 1"}"#)
            .unwrap_or_else(|_err| unreachable!("valid payload"));
        assert_eq!(args.params_json, "[]");
    }

    /// The `auth` payload unpacks the token.
    #[test]
    fn parses_auth_token_field() {
        let token = parse_auth_token(r#"{"token":"abc"}"#)
            .unwrap_or_else(|_err| unreachable!("valid payload"));
        assert_eq!(token, "abc");
    }

    /// A malformed `db` payload is a developer-owned bad-payload error.
    #[test]
    fn rejects_malformed_db_payload() {
        let err = parse_db_payload("42").unwrap_err();
        assert_eq!(err.code, "DB_BAD_PAYLOAD");
        assert_eq!(err.source, "db");
    }

    /// A name with no backend wired for this session is a clear `IO_UNKNOWN`, not a panic.
    #[test]
    fn unknown_resource_is_rejected() {
        let err = BackendSet::new().call("nope", "ping", "{}").unwrap_err();
        assert_eq!(err.code, "IO_UNKNOWN");
    }
}
