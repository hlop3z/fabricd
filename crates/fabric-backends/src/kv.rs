//! Redis key/value client for the `QuickJS` sandbox (`redis` global).
//!
//! JS API: `redis.get/set/del/incr/expire`. Trust model matches `db`/`mail`: the
//! connection is operator-supplied in `config.redis`, so no SSRF guard — internal
//! Redis instances are intended to work. Values are **strings in / strings out**;
//! the script owns (de)serialization. Each op is metered.
//!
//! The module is named `kv` (not `redis`) so it doesn't shadow the `redis` crate.

use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use std::fmt::{self, Formatter};

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use fabric_wire::metrics::{self as sandbox, Collector};
use fabric_wire::{EgressError, ErrorOwner, Fault, RedisMetric};

/// Fallback fault for a Redis error with no specific predicate.
const REDIS_FALLBACK: Fault = Fault::new("REDIS_ERROR", true, ErrorOwner::Operator);
/// Fault for a Redis command that timed out.
const REDIS_TIMEOUT: Fault = Fault::new("REDIS_TIMEOUT", true, ErrorOwner::Operator);
/// Fault for a failure to reach Redis (inject-time connect, or a mid-session IO error).
pub const REDIS_CONNECTION_FAULT: Fault =
    Fault::new("REDIS_CONNECTION", true, ErrorOwner::Operator);

/// Per-request Redis configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    /// Connection URL, e.g. `redis://user:pass@host:6379/0`.
    pub url: String,
    /// Connect + command timeout in milliseconds (default 5000).
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// Default command timeout in milliseconds.
const fn default_timeout() -> u64 {
    5000
}

/// A Redis error carrying its classified [`Fault`] plus the raw message.
#[derive(Debug)]
pub struct RedisError {
    /// Classified code + retry hint + owner.
    fault: Fault,
    /// Raw driver/usage message.
    message: String,
}

impl RedisError {
    /// Builds a fallback (`REDIS_ERROR`) error — used for non-driver failures (payload
    /// parsing, lock, serialization, unknown action).
    const fn fallback(message: String) -> Self {
        Self {
            fault: REDIS_FALLBACK,
            message,
        }
    }

    /// Classifies a `redis` driver error.
    fn from_driver(err: &redis::RedisError) -> Self {
        Self {
            fault: classify(err),
            message: err.to_string(),
        }
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `redis`), preserving the classified code / retryable / owner.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "redis".to_owned(),
            details: None,
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// Returns `true` if an `inject_redis` error is a driver failure — a boxed
/// `redis::RedisError` — vs an engine-setup failure (function registration / eval). Lets
/// the engine map a dead Redis to a retryable `capability/redis/REDIS_CONNECTION`.
pub(crate) fn is_connect_error(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<redis::RedisError>().is_some()
}

/// Maps a `redis::RedisError` to a [`Fault`] (timeout / IO → retryable infra).
fn classify(err: &redis::RedisError) -> Fault {
    if err.is_timeout() {
        REDIS_TIMEOUT
    } else if err.is_io_error() {
        REDIS_CONNECTION_FAULT
    } else {
        REDIS_FALLBACK
    }
}

// -- Public API -------------------------------------------------------------

/// A connected, JS-free `redis` backend: a shared connection plus its own metrics, exposing a
/// single string-in/string-out [`call`](RedisBackend::call).
///
/// The reusable dispatch core behind the in-process [`Egress`](fabric_wire::Egress)
/// adapter (and the shape a sidecar hosts). Sync — no runtime handle needed. See
/// `docs/design/resource-egress.md`.
pub struct RedisBackend {
    /// Shared connection (one per request; serialized through the mutex).
    conn: Arc<Mutex<Connection>>,
    /// Per-operation metrics, drained by the consumer into `meta.redis_requests`.
    metrics: Collector<RedisMetric>,
}

impl fmt::Debug for RedisBackend {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisBackend")
            .finish_non_exhaustive()
    }
}

impl RedisBackend {
    /// Connects, mapping a failure to a [`EgressError`] (source `redis`): an IO failure →
    /// retryable `REDIS_CONNECTION`, else the retryable `REDIS_ERROR` fallback.
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] if the connection cannot be established.
    pub fn connect_resource(config: &RedisConfig) -> Result<Self, EgressError> {
        match connect(config) {
            Ok(conn) => Ok(Self {
                conn: Arc::new(Mutex::new(conn)),
                metrics: sandbox::new_collector(),
            }),
            Err(err) => {
                let fault = if is_connect_error(err.as_ref()) {
                    REDIS_CONNECTION_FAULT
                } else {
                    REDIS_FALLBACK
                };
                Err(EgressError {
                    code: fault.code.to_owned(),
                    message: err.to_string(),
                    source: "redis".to_owned(),
                    details: None,
                    retryable: fault.retryable,
                    owner: fault.owner,
                })
            }
        }
    }

    /// Runs one redis action, records a [`RedisMetric`], and returns the result JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`RedisError`] on a driver failure or a usage error.
    pub fn call(&self, action: &str, payload_json: &str) -> Result<String, RedisError> {
        let start = Instant::now();
        let result = dispatch(&self.conn, action, payload_json);
        sandbox::record(&self.metrics, build_metric(action, &result, start));
        result
    }

    /// Drains (clones out) the metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<RedisMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

/// Builds a Redis connection with read/write timeouts applied.
fn connect(config: &RedisConfig) -> Result<Connection, Box<dyn Error + Send + Sync>> {
    let client = redis::Client::open(config.url.as_str())?;
    let conn = client.get_connection()?;
    let timeout = Duration::from_millis(config.timeout_ms);
    conn.set_read_timeout(Some(timeout))?;
    conn.set_write_timeout(Some(timeout))?;
    Ok(conn)
}

// -- Dispatch ---------------------------------------------------------------

/// Routes a `__redis` call to the correct handler.
fn dispatch(
    conn: &Arc<Mutex<Connection>>,
    action: &str,
    payload_json: &str,
) -> Result<String, RedisError> {
    match action {
        "get" => do_get(conn, payload_json),
        "set" => do_set(conn, payload_json),
        "del" => do_del(conn, payload_json),
        "incr" => do_incr(conn, payload_json),
        "expire" => do_expire(conn, payload_json),
        other => Err(RedisError::fallback(format!(
            "unknown redis action: {other}"
        ))),
    }
}

/// Acquires the shared connection lock.
fn lock_conn(conn: &Arc<Mutex<Connection>>) -> Result<MutexGuard<'_, Connection>, RedisError> {
    conn.lock()
        .map_err(|err| RedisError::fallback(format!("lock error: {err}")))
}

/// Parses a payload, mapping failures to a fallback error.
fn parse<T: for<'de> Deserialize<'de>>(payload_json: &str) -> Result<T, RedisError> {
    serde_json::from_str(payload_json)
        .map_err(|err| RedisError::fallback(format!("invalid redis payload: {err}")))
}

/// Encodes a response object, mapping failures to a fallback error.
fn encode(value: &Value) -> Result<String, RedisError> {
    serde_json::to_string(value)
        .map_err(|err| RedisError::fallback(format!("serialize error: {err}")))
}

// -- Operations -------------------------------------------------------------

/// `GET key` → `{ value: string | null }`.
fn do_get(conn: &Arc<Mutex<Connection>>, payload_json: &str) -> Result<String, RedisError> {
    let payload: KeyPayload = parse(payload_json)?;
    let value: Option<String> = {
        let mut guard = lock_conn(conn)?;
        guard
            .get(&payload.key)
            .map_err(|err| RedisError::from_driver(&err))?
    };
    encode(&json!({ "value": value }))
}

/// `SET key value [EX ttl]` → `{ ok: true }`.
fn do_set(conn: &Arc<Mutex<Connection>>, payload_json: &str) -> Result<String, RedisError> {
    let payload: SetPayload = parse(payload_json)?;
    // Compute under the lock, then handle the error after the guard drops.
    let outcome: redis::RedisResult<()> = {
        let mut guard = lock_conn(conn)?;
        match payload.ttl {
            Some(ttl) => guard.set_ex(&payload.key, &payload.value, ttl),
            None => guard.set(&payload.key, &payload.value),
        }
    };
    outcome.map_err(|err| RedisError::from_driver(&err))?;
    encode(&json!({ "ok": true }))
}

/// `DEL key` → `{ count: number }`.
fn do_del(conn: &Arc<Mutex<Connection>>, payload_json: &str) -> Result<String, RedisError> {
    let payload: KeyPayload = parse(payload_json)?;
    let count: i64 = {
        let mut guard = lock_conn(conn)?;
        guard
            .del(&payload.key)
            .map_err(|err| RedisError::from_driver(&err))?
    };
    encode(&json!({ "count": count }))
}

/// `INCR key` → `{ value: number }`.
fn do_incr(conn: &Arc<Mutex<Connection>>, payload_json: &str) -> Result<String, RedisError> {
    let payload: KeyPayload = parse(payload_json)?;
    let value: i64 = {
        let mut guard = lock_conn(conn)?;
        guard
            .incr(&payload.key, 1_i64)
            .map_err(|err| RedisError::from_driver(&err))?
    };
    encode(&json!({ "value": value }))
}

/// `EXPIRE key seconds` → `{ set: bool }`.
fn do_expire(conn: &Arc<Mutex<Connection>>, payload_json: &str) -> Result<String, RedisError> {
    let payload: ExpirePayload = parse(payload_json)?;
    let set: bool = {
        let mut guard = lock_conn(conn)?;
        guard
            .expire(&payload.key, payload.seconds)
            .map_err(|err| RedisError::from_driver(&err))?
    };
    encode(&json!({ "set": set }))
}

// -- Payloads ---------------------------------------------------------------

/// Payload carrying just a key (`get`/`del`/`incr`).
#[derive(Debug, Deserialize)]
struct KeyPayload {
    /// The Redis key.
    #[serde(default)]
    key: String,
}

/// Payload for `set`.
#[derive(Debug, Deserialize)]
struct SetPayload {
    /// The Redis key.
    #[serde(default)]
    key: String,
    /// The value (a string — the script serializes objects itself).
    #[serde(default)]
    value: String,
    /// Optional TTL in seconds.
    #[serde(default)]
    ttl: Option<u64>,
}

/// Payload for `expire`.
#[derive(Debug, Deserialize)]
struct ExpirePayload {
    /// The Redis key.
    #[serde(default)]
    key: String,
    /// TTL in seconds.
    #[serde(default)]
    seconds: i64,
}

// -- Metrics ----------------------------------------------------------------

/// Builds a `RedisMetric` from the result of an operation.
fn build_metric(action: &str, result: &Result<String, RedisError>, start: Instant) -> RedisMetric {
    let (bytes, hit) = result
        .as_ref()
        .map_or((0, false), |json| value_stats(action, json));
    RedisMetric {
        action: action.to_owned(),
        duration_us: start.elapsed().as_micros(),
        bytes,
        hit,
    }
}

/// Extracts `(bytes, hit)` from a `get` response (zero/false for other ops).
fn value_stats(action: &str, json: &str) -> (usize, bool) {
    if action != "get" {
        return (0, false);
    }
    let parsed: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    parsed
        .get("value")
        .and_then(Value::as_str)
        .map_or((0, false), |text| (text.len(), true))
}
