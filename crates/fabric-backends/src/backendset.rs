//! In-process [`Egress`] adapter — wires this crate's own driver capabilities behind the
//! egress seam, so a consumer can run `io.call(...)` without a sidecar.
//!
//! Transitional: the JS-free backends it holds (`DbBackend`, `MongoBackend`, …) are exactly what
//! a sidecar (`fabricd`) will host once the drivers move out of the sandbox process — see
//! `docs/design/resource-egress.md` / `docs/design/network-fabric.md`. For now this adapter lets
//! the existing capabilities flow through the new seam unchanged.
//!
//! Build a fresh [`BackendSet`] per invocation (each backend connects lazily on first use and
//! carries the per-request deadline) and wire it as the invocation's egress port. After the run,
//! drain each capability's metrics (e.g. [`db_metrics`](BackendSet::db_metrics)) into the response.
//!
//! Covers the driver-backed capabilities `db`/`mongo`/`mail`/`redis`/`amq`/`auth`; `http` and
//! `s3` remain in-engine (no driver / pure signing).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tokio::runtime::Handle;

use fabric_wire::{CircuitBreaker, Egress, EgressError, ErrorOwner};

use crate::wire::{BackendMetrics, WireInit};

use crate::amq::{AmqConfig, AmqError, AmqMetric, AmqProducer};
use crate::auth::{AuthBackend, AuthConfig, AuthMetric};
use crate::db::{DbBackend, DbConfig, DbDeps, DbError, DbMetric};
use crate::kv::{RedisBackend, RedisConfig, RedisError, RedisMetric};
use crate::mail::{MailBackend, MailConfig, MailError, MailMetric};
use crate::mongo::{MongoBackend, MongoConfig, MongoDeps, MongoError, MongoMetric};

/// Shared runtime/resilience deps for the async backends (`db`, `mongo`). Cloned per backend.
#[derive(Debug, Clone)]
pub struct AsyncDeps {
    /// Runtime handle for the async drivers' `block_on` (the request thread's handle).
    pub handle: Handle,
    /// Optional shared `db` circuit breaker (Tier 3); ignored by `mongo`.
    pub breaker: Option<Arc<CircuitBreaker>>,
    /// Per-execution wall-clock budget (the per-query/op client-side deadline).
    pub timeout: Duration,
}

/// An in-process egress holding per-request capability backends.
///
/// Construct with [`BackendSet::new`] and attach capabilities with the `with_*` setters.
/// Each backend connects lazily on first use.
#[derive(Default, Debug)]
pub struct BackendSet {
    /// Lazily-connected `db` egress.
    db: Option<DbSlot>,
    /// Lazily-connected `mongo` egress.
    mongo: Option<MongoSlot>,
    /// Lazily-connected `mail` egress.
    mail: Option<MailSlot>,
    /// Lazily-connected `redis` egress.
    redis: Option<RedisSlot>,
    /// Lazily-connected `auth` egress.
    auth: Option<AuthSlot>,
    /// `amq` egress (stateless — connects per call, so built eagerly).
    amq: Option<AmqProducer>,
}

impl BackendSet {
    /// An empty adapter (no capabilities wired).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from a [`WireInit`] (the sidecar session-open message): each `Some` config
    /// becomes a lazily-connected backend. `deps` carries the runtime handle, the optional
    /// breaker, and the per-execution deadline (`init.timeout_ms`).
    #[must_use]
    pub fn from_init(init: &WireInit, deps: &AsyncDeps) -> Self {
        let mut set = Self::new();
        if let Some(cfg) = init.db.clone() {
            set = set.with_db(cfg, deps);
        }
        if let Some(cfg) = init.mongo.clone() {
            set = set.with_mongo(cfg, deps);
        }
        if let Some(cfg) = init.mail.clone() {
            set = set.with_mail(cfg);
        }
        if let Some(cfg) = init.redis.clone() {
            set = set.with_redis(cfg);
        }
        if let Some(cfg) = init.amq.clone() {
            set = set.with_amq(cfg);
        }
        if let Some(cfg) = init.auth.clone() {
            set = set.with_auth(cfg);
        }
        set
    }

    /// Drains every capability's metrics into one [`BackendMetrics`] (the consumer merges it into
    /// the response `meta.<cap>_requests`; empty for any capability the run never touched).
    #[must_use]
    pub fn metrics(&self) -> BackendMetrics {
        BackendMetrics {
            db: self.db_metrics(),
            mongo: self.mongo_metrics(),
            mail: self.mail_metrics(),
            redis: self.redis_metrics(),
            amq: self.amq_metrics(),
            auth: self.auth_metrics(),
        }
    }

    /// Wires the `db` capability (connects lazily on first use).
    #[must_use]
    pub fn with_db(mut self, config: DbConfig, deps: &AsyncDeps) -> Self {
        self.db = Some(DbSlot {
            config,
            deps: deps.clone(),
            backend: OnceLock::new(),
        });
        self
    }

    /// Wires the `mongo` capability (connects lazily on first use).
    #[must_use]
    pub fn with_mongo(mut self, config: MongoConfig, deps: &AsyncDeps) -> Self {
        self.mongo = Some(MongoSlot {
            config,
            deps: deps.clone(),
            backend: OnceLock::new(),
        });
        self
    }

    /// Wires the `mail` capability (builds the transport lazily on first use).
    #[must_use]
    pub fn with_mail(mut self, config: MailConfig) -> Self {
        self.mail = Some(MailSlot {
            config,
            backend: OnceLock::new(),
        });
        self
    }

    /// Wires the `redis` capability (connects lazily on first use).
    #[must_use]
    pub fn with_redis(mut self, config: RedisConfig) -> Self {
        self.redis = Some(RedisSlot {
            config,
            backend: OnceLock::new(),
        });
        self
    }

    /// Wires the `auth` capability (builds the client lazily on first use).
    #[must_use]
    pub fn with_auth(mut self, config: AuthConfig) -> Self {
        self.auth = Some(AuthSlot {
            config,
            backend: OnceLock::new(),
        });
        self
    }

    /// Wires the `amq` capability (stateless; opens a connection per call).
    #[must_use]
    pub fn with_amq(mut self, config: AmqConfig) -> Self {
        self.amq = Some(AmqProducer::new(config));
        self
    }

    /// The `db` metrics recorded so far (empty if `db` was never connected/used).
    #[must_use]
    pub fn db_metrics(&self) -> Vec<DbMetric> {
        match self.db.as_ref().and_then(|slot| slot.backend.get()) {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }

    /// The `mongo` metrics recorded so far.
    #[must_use]
    pub fn mongo_metrics(&self) -> Vec<MongoMetric> {
        match self.mongo.as_ref().and_then(|slot| slot.backend.get()) {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }

    /// The `mail` metrics recorded so far.
    #[must_use]
    pub fn mail_metrics(&self) -> Vec<MailMetric> {
        match self.mail.as_ref().and_then(|slot| slot.backend.get()) {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }

    /// The `redis` metrics recorded so far.
    #[must_use]
    pub fn redis_metrics(&self) -> Vec<RedisMetric> {
        match self.redis.as_ref().and_then(|slot| slot.backend.get()) {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }

    /// The `auth` metrics recorded so far.
    #[must_use]
    pub fn auth_metrics(&self) -> Vec<AuthMetric> {
        match self.auth.as_ref().and_then(|slot| slot.backend.get()) {
            Some(Ok(backend)) => backend.drain_metrics(),
            _ => Vec::new(),
        }
    }

    /// The `amq` metrics recorded so far.
    #[must_use]
    pub fn amq_metrics(&self) -> Vec<AmqMetric> {
        self.amq
            .as_ref()
            .map_or_else(Vec::new, AmqProducer::drain_metrics)
    }

    /// `db`: unpack `{sql, params}` and dispatch.
    fn call_db(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self
            .db
            .as_ref()
            .ok_or_else(|| not_configured("db"))?
            .backend()?;
        let args = parse_db_payload(payload_json)?;
        backend
            .call(action, &args.sql, &args.params_json)
            .map_err(DbError::into_resource_error)
    }

    /// `mongo`: unpack `{collection, data}` and dispatch.
    fn call_mongo(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self
            .mongo
            .as_ref()
            .ok_or_else(|| not_configured("mongo"))?
            .backend()?;
        let (collection, data_json) = parse_mongo_payload(payload_json)?;
        backend
            .call(action, &collection, &data_json)
            .map_err(MongoError::into_resource_error)
    }

    /// `mail`: the payload is the send envelope, passed straight through.
    fn call_mail(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self
            .mail
            .as_ref()
            .ok_or_else(|| not_configured("mail"))?
            .backend()?;
        backend
            .call(action, payload_json)
            .map_err(MailError::into_resource_error)
    }

    /// `redis`: the payload is the op args, passed straight through.
    fn call_redis(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self
            .redis
            .as_ref()
            .ok_or_else(|| not_configured("redis"))?
            .backend()?;
        backend
            .call(action, payload_json)
            .map_err(RedisError::into_resource_error)
    }

    /// `amq`: the payload is the batch / request, passed straight through.
    fn call_amq(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self.amq.as_ref().ok_or_else(|| not_configured("amq"))?;
        backend
            .call(action, payload_json)
            .map_err(AmqError::into_resource_error)
    }

    /// `auth`: unpack `{token}` and dispatch (the backend's `call` already maps its errors).
    fn call_auth(&self, action: &str, payload_json: &str) -> Result<String, EgressError> {
        let backend = self
            .auth
            .as_ref()
            .ok_or_else(|| not_configured("auth"))?
            .backend()?;
        let token = parse_auth_token(payload_json)?;
        backend.call(action, &token)
    }
}

impl Egress for BackendSet {
    fn call(&self, name: &str, action: &str, payload_json: &str) -> Result<String, EgressError> {
        match name {
            "db" => self.call_db(action, payload_json),
            "mongo" => self.call_mongo(action, payload_json),
            "mail" => self.call_mail(action, payload_json),
            "redis" => self.call_redis(action, payload_json),
            "amq" => self.call_amq(action, payload_json),
            "auth" => self.call_auth(action, payload_json),
            other => {
                Err(
                    EgressError::new("engine", "IO_UNKNOWN", format!("unknown egress '{other}'"))
                        .owner(ErrorOwner::Developer),
                )
            }
        }
    }
}

/// An [`Egress`] that also exposes its drained per-capability metrics.
///
/// Lets the consumer treat the in-process [`BackendSet`] and a future sidecar-client egress
/// uniformly: pass either as `dyn Egress` to an invocation, then `drain_metrics()` after the run.
pub trait MeteredEgress: Egress {
    /// The per-capability metrics recorded this session.
    fn drain_metrics(&self) -> BackendMetrics;
}

impl MeteredEgress for BackendSet {
    fn drain_metrics(&self) -> BackendMetrics {
        self.metrics()
    }
}

/// Builds the `<CAP>_NOT_CONFIGURED` error for a egress called without its backend wired.
fn not_configured(name: &str) -> EgressError {
    EgressError::new(
        name,
        format!("{}_NOT_CONFIGURED", name.to_uppercase()),
        format!("{name} egress is not configured"),
    )
    .owner(ErrorOwner::Developer)
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
}

/// Lazily-connected `mongo` egress.
#[derive(Debug)]
struct MongoSlot {
    /// Operator connection config.
    config: MongoConfig,
    /// Async runtime + deadline (breaker unused).
    deps: AsyncDeps,
    /// Connect-once cell.
    backend: OnceLock<Result<MongoBackend, EgressError>>,
}

impl MongoSlot {
    /// Returns the connected backend, connecting on first use.
    fn backend(&self) -> Result<&MongoBackend, EgressError> {
        let deps = MongoDeps {
            handle: &self.deps.handle,
            timeout: self.deps.timeout,
        };
        match self
            .backend
            .get_or_init(|| MongoBackend::connect_resource(&self.config, &deps))
        {
            Ok(backend) => Ok(backend),
            Err(err) => Err(err.clone()),
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

/// The `mongo` egress envelope: `{ "collection": string, "data": <mongo payload> }`.
#[derive(Deserialize)]
struct MongoEnvelope {
    /// Collection name.
    #[serde(default)]
    collection: String,
    /// The per-action mongo payload (filter/options/doc/…), re-serialized for the backend.
    #[serde(default)]
    data: Value,
}

/// Parses the `mongo` envelope into `(collection, data_json)`, defaulting null data to `{}`.
fn parse_mongo_payload(payload_json: &str) -> Result<(String, String), EgressError> {
    let envelope: MongoEnvelope = serde_json::from_str(payload_json).map_err(|err| {
        EgressError::new(
            "mongo",
            "MONGO_QUERY",
            format!("invalid mongo payload: {err}"),
        )
        .owner(ErrorOwner::Developer)
    })?;
    let data_json = if envelope.data.is_null() {
        "{}".to_owned()
    } else {
        serde_json::to_string(&envelope.data).unwrap_or_else(|_err| "{}".to_owned())
    };
    Ok((envelope.collection, data_json))
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
    //! Covers the adapter glue that needs no live backend: payload unpacking and the
    //! unknown-/unconfigured-egress errors. Real dispatch is covered by the per-capability
    //! integration suites against live backends.

    use super::{BackendSet, parse_auth_token, parse_db_payload, parse_mongo_payload};
    use fabric_wire::Egress;

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

    /// The `mongo` envelope unpacks the collection and re-serializes the data.
    #[test]
    fn parses_mongo_envelope() {
        let (collection, data) =
            parse_mongo_payload(r#"{"collection":"users","data":{"filter":{"a":1}}}"#)
                .unwrap_or_else(|_err| unreachable!("valid payload"));
        assert_eq!(collection, "users");
        assert!(data.contains("filter"), "data re-serialized: {data}");
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

    /// An unknown egress name is rejected without touching any backend.
    #[test]
    fn unknown_resource_is_rejected() {
        let err = BackendSet::new()
            .call("nope", "ping", "{}")
            .unwrap_err();
        assert_eq!(err.code, "IO_UNKNOWN");
    }

    /// Calling a capability with no backend wired is a clear `*_NOT_CONFIGURED`, not a panic.
    #[test]
    fn unconfigured_capability_is_reported() {
        let adapter = BackendSet::new();
        assert_eq!(
            adapter
                .call("redis", "get", r#"{"key":"k"}"#)
                .unwrap_err()
                .code,
            "REDIS_NOT_CONFIGURED"
        );
        assert_eq!(
            adapter.call("amq", "send", "{}").unwrap_err().code,
            "AMQ_NOT_CONFIGURED"
        );
    }
}
