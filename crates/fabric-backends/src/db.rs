//! `PostgreSQL`/`CockroachDB` client for the `QuickJS` sandbox.
//!
//! JS API: `db.query(sql, params?)`, `db.execute(sql, params?)`,
//! `db.begin()`, `db.commit()`, `db.rollback()`.
//!
//! i64/BIGINT/NUMERIC always serialized as strings for JS safety.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Handle;
use tokio::time::timeout;
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};
use tokio_postgres::{Client, Connection, NoTls};

use fabric_wire::metrics::{self as sandbox, Collector};
use fabric_wire::{CircuitBreaker, DbMetric, EgressError, ErrorOwner, Fault};

/// Fallback fault for any db error without a recognized driver `SqlState`.
const DB_FALLBACK: Fault = Fault::new("DB_ERROR", true, ErrorOwner::Operator);
/// Fault for a failure to reach the database — used for inject-time connect failures
/// (a query-time `08xxx` drop is classified the same way in [`classify_by_class`]).
pub const DB_CONNECTION_FAULT: Fault = Fault::new("DB_CONNECTION", true, ErrorOwner::Operator);
/// Fault for a query that exceeded the client-side execution deadline (Tier 2). Frees
/// the blocking thread even when the server-side `statement_timeout` was lost through a
/// transaction-mode pooler (see `docs/design/resilience.md`).
const DB_TIMEOUT: Fault = Fault::new("DB_TIMEOUT", true, ErrorOwner::Operator);
/// Fault for a `db` request refused because the circuit breaker is open (Tier 3) — the
/// target has been failing to connect, so we fast-fail instead of waiting on the timeout.
pub const DB_CIRCUIT_OPEN_FAULT: Fault = Fault::new("DB_CIRCUIT_OPEN", true, ErrorOwner::Operator);

/// Marker error returned at inject time when the breaker is open (no connect attempted).
#[derive(Debug)]
pub(crate) struct CircuitOpen;

impl Display for CircuitOpen {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("db circuit breaker open")
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "the default Error methods (source/description/cause) are correct for a marker error"
)]
impl Error for CircuitOpen {}

/// Returns `true` if an `inject_db` error is a breaker-open refusal (mapped to a
/// retryable `capability/db/DB_CIRCUIT_OPEN` rather than a server fault).
pub(crate) fn is_circuit_open(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<CircuitOpen>().is_some()
}

/// A db error carrying its classified [`Fault`], the raw message, and structured details.
#[derive(Debug)]
pub struct DbError {
    /// Classified code + retry hint + owner.
    fault: Fault,
    /// Raw driver/usage message.
    message: String,
    /// Structured machine context (e.g. `{sqlstate}`), surfaced ungated in `details`.
    details: Option<Value>,
}

impl DbError {
    /// Builds a fallback (`DB_ERROR`) error from a message — used for non-driver
    /// failures (param parsing, lock, serialization, unknown action).
    const fn fallback(message: String) -> Self {
        Self {
            fault: DB_FALLBACK,
            message,
            details: None,
        }
    }

    /// Classifies a `tokio_postgres` driver error by its `SqlState`, attaching the raw
    /// `sqlstate` as structured detail.
    fn from_driver(err: &tokio_postgres::Error) -> Self {
        let details = err
            .code()
            .map(|state| serde_json::json!({ "sqlstate": state.code() }));
        Self {
            fault: classify(err),
            message: err.to_string(),
            details,
        }
    }

    /// Builds the client-side deadline error (the query ran past the execution budget).
    fn timeout() -> Self {
        Self {
            fault: DB_TIMEOUT,
            message: "database query exceeded the execution deadline".to_owned(),
            details: None,
        }
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `db`), preserving the classified code / retryable / owner and the structured details.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "db".to_owned(),
            details: self.details.map(Box::new),
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// Maps a `tokio_postgres::Error` to a [`Fault`] by `SqlState` (docs/99-errors.md).
///
/// The `SqlState` exists only here, above the "stringify cliff" — once the error is
/// `format!`'d into a message the class is gone, so classification must happen now.
fn classify(err: &tokio_postgres::Error) -> Fault {
    let Some(state) = err.code() else {
        return DB_FALLBACK;
    };
    match state.code() {
        "40001" => Fault::new("DB_SERIALIZATION", true, ErrorOwner::Operator),
        "40P01" => Fault::new("DB_DEADLOCK", true, ErrorOwner::Operator),
        "57014" => Fault::new("DB_CANCELED", true, ErrorOwner::Operator),
        other => classify_by_class(other),
    }
}

/// Classifies by `SqlState` class (the first two chars) for the range-based codes.
fn classify_by_class(code: &str) -> Fault {
    match code.get(..2) {
        Some("08") => DB_CONNECTION_FAULT,
        Some("23") => Fault::new("DB_CONSTRAINT", false, ErrorOwner::Developer),
        Some("42") => Fault::new("DB_QUERY", false, ErrorOwner::Developer),
        _ => DB_FALLBACK,
    }
}

/// Per-request database configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DbConfig {
    /// Database host.
    pub host: String,
    /// Database port (default 5432).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Database user.
    pub user: String,
    /// Database password.
    pub password: String,
    /// Database name.
    pub database: String,
    /// Use SSL/TLS.
    #[serde(default)]
    pub ssl: bool,
    /// Query timeout in milliseconds (default 5000).
    #[serde(default = "default_statement_timeout")]
    pub statement_timeout_ms: u64,
    /// Max rows returned (default 1000).
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
}

/// Default port.
const fn default_port() -> u16 {
    5432
}
/// Default statement timeout.
const fn default_statement_timeout() -> u64 {
    5000
}
/// Default max rows.
const fn default_max_rows() -> usize {
    1000
}

// -- Public API -------------------------------------------------------------

/// Runtime and resilience dependencies threaded into [`inject_db`] / [`DbBackend::connect`].
///
/// Grouped so the connect entry point stays within the argument-count limit as the async
/// plumbing (Tier 2) and breaker (Tier 3) are added. Public so a consumer building a
/// [`DbBackend`] directly (e.g. the in-process adapter, or a sidecar) can supply them.
#[derive(Debug)]
pub struct DbDeps<'a> {
    /// Runtime handle driving the async driver from this blocking thread (`block_on`).
    pub handle: &'a Handle,
    /// Execution wall-clock budget, used as the per-query client-side deadline (Tier 2).
    pub timeout: Duration,
    /// Optional per-target circuit breaker fast-failing a flapping database (Tier 3).
    pub breaker: Option<&'a CircuitBreaker>,
}

/// A connected, JS-free `db` backend: a pooled async client plus the per-execution deadline
/// and row cap, exposing a single string-in/string-out [`call`](DbBackend::call).
///
/// This is the reusable dispatch core, holding no `QuickJS` state — shared by the in-process
/// `__db` capability (via [`inject_db`]) and the in-process
/// [`Egress`](fabric_wire::Egress) adapter (`crate::backendset`), and the same shape a
/// sidecar will host when the driver moves out of the sandbox process. See
/// `docs/design/resource-egress.md`.
pub struct DbBackend {
    /// Shared async client — one fresh connection per request; transactions reuse it.
    client: Arc<Client>,
    /// Runtime handle for `block_on` (the driver is async; the engine thread is blocking).
    handle: Handle,
    /// Absolute client-side deadline applied to every query (Tier 2).
    deadline: Instant,
    /// Max rows a query returns before truncation.
    max_rows: usize,
    /// Per-operation metrics, recorded by [`call`](DbBackend::call) and drained by the consumer
    /// (the egress adapter) into the response `meta.db_requests`.
    metrics: Collector<DbMetric>,
}

impl fmt::Debug for DbBackend {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        // The async client holds a live connection (not meaningfully printable); show only the
        // scalar config so `Debug` carries no socket/credential state.
        formatter
            .debug_struct("DbBackend")
            .field("deadline", &self.deadline)
            .field("max_rows", &self.max_rows)
            .finish_non_exhaustive()
    }
}

impl DbBackend {
    /// Connects (guarded by the optional breaker) and anchors the per-execution deadline.
    ///
    /// The deadline is anchored at connect time (≈ execution start) so total db time stays
    /// bounded by the wall-clock budget. A breaker-open refusal or a connect failure is
    /// returned as a boxed error the caller classifies (`is_circuit_open` / `is_connect_error`).
    ///
    /// # Errors
    ///
    /// Returns an error if the breaker is open or the connection fails.
    pub fn connect(
        config: &DbConfig,
        deps: &DbDeps<'_>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = connect_through_breaker(config, deps.handle, deps.breaker)?;
        // On the (practically impossible) `Instant` overflow, fall back to "now", which simply
        // makes queries deadline immediately.
        let deadline = Instant::now()
            .checked_add(deps.timeout)
            .unwrap_or_else(Instant::now);
        Ok(Self {
            client: Arc::new(client),
            handle: deps.handle.clone(),
            deadline,
            max_rows: config.max_rows,
            metrics: sandbox::new_collector(),
        })
    }

    /// Connects, mapping a failure straight to a [`EgressError`] (source `db`) for the egress
    /// seam: a breaker-open refusal → retryable `DB_CIRCUIT_OPEN`, any other connect failure →
    /// retryable `DB_CONNECTION`. The adapter surfaces this as a thrown capability error,
    /// identical to a query-time connection drop.
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] if the breaker is open or the connection fails.
    pub fn connect_resource(config: &DbConfig, deps: &DbDeps<'_>) -> Result<Self, EgressError> {
        Self::connect(config, deps).map_err(|err| connect_error_to_resource(err.as_ref()))
    }

    /// Runs one db action (`query`/`execute`/`begin`/`commit`/`rollback`), records a
    /// [`DbMetric`], and returns the result JSON — the string-in/string-out FFI contract, with
    /// no `QuickJS` involvement.
    ///
    /// # Errors
    ///
    /// Returns a [`DbError`] (classified fault) on driver failure, deadline elapse, or a usage
    /// error (bad params, unknown action).
    pub fn call(&self, action: &str, query: &str, params_json: &str) -> Result<String, DbError> {
        let start = Instant::now();
        let call = DbCall {
            handle: &self.handle,
            client: &self.client,
            deadline: self.deadline,
        };
        let result = dispatch(&call, action, query, params_json, self.max_rows);
        sandbox::record(&self.metrics, build_metric(action, &result, start));
        result
    }

    /// Drains (clones out) the per-operation metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<DbMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

/// Maps a `db` connect failure to a [`EgressError`]: breaker-open → `DB_CIRCUIT_OPEN`,
/// otherwise `DB_CONNECTION` (connect failures are the only outcome of `connect_through_breaker`).
fn connect_error_to_resource(err: &(dyn Error + Send + Sync + 'static)) -> EgressError {
    let fault = if is_circuit_open(err) {
        DB_CIRCUIT_OPEN_FAULT
    } else {
        DB_CONNECTION_FAULT
    };
    EgressError {
        code: fault.code.to_owned(),
        message: err.to_string(),
        source: "db".to_owned(),
        details: None,
        retryable: fault.retryable,
        owner: fault.owner,
    }
}

// -- Dispatch ---------------------------------------------------------------

/// Bundled context for one `__db` call: the runtime handle, the shared async client,
/// and the per-execution deadline. Grouped so dispatch/handlers stay within the
/// argument-count limit as the async plumbing is threaded through.
struct DbCall<'a> {
    /// Runtime handle for `block_on`.
    handle: &'a Handle,
    /// Shared async client (one fresh connection per request).
    client: &'a Arc<Client>,
    /// Absolute client-side deadline for every query in this execution.
    deadline: Instant,
}

/// Routes a `__db` call to the correct handler.
fn dispatch(
    call: &DbCall<'_>,
    action: &str,
    query: &str,
    params_json: &str,
    max_rows: usize,
) -> Result<String, DbError> {
    match action {
        "query" => do_query(call, query, params_json, max_rows),
        "execute" => do_execute(call, query, params_json),
        "begin" => do_simple(call, "BEGIN"),
        "commit" => do_simple(call, "COMMIT"),
        "rollback" => do_simple(call, "ROLLBACK"),
        other => Err(DbError::fallback(format!("unknown db action: {other}"))),
    }
}

/// Drives an async db future to completion on the pooled runtime, bounded by the
/// execution deadline. On elapse the future is dropped (cancelling the query: jsbox
/// uses a fresh per-request connection, never a pooled one, so teardown is a clean
/// cancellation — see `docs/design/resilience.md`) and a retryable `DB_TIMEOUT` is
/// returned, freeing the blocking thread regardless of any server-side timeout.
fn block_on_db<F, T>(call: &DbCall<'_>, fut: F) -> Result<T, DbError>
where
    F: Future<Output = Result<T, tokio_postgres::Error>>,
{
    let remaining = call.deadline.saturating_duration_since(Instant::now());
    call.handle.block_on(async move {
        match timeout(remaining, fut).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(driver)) => Err(DbError::from_driver(&driver)),
            Err(_elapsed) => Err(DbError::timeout()),
        }
    })
}

// -- Connection -------------------------------------------------------------

/// Connects, guarded by the circuit breaker (Tier 3). An open breaker fast-fails with
/// `CircuitOpen` (no connect attempt, no waiting on the connect timeout); otherwise the
/// connect outcome is recorded so repeated failures trip the breaker for this target.
fn connect_through_breaker(
    config: &DbConfig,
    handle: &Handle,
    breaker: Option<&CircuitBreaker>,
) -> Result<Client, Box<dyn Error + Send + Sync>> {
    let Some(guard) = breaker else {
        return handle.block_on(connect(config, handle));
    };
    let target = format!("{}:{}", config.host, config.port);
    if !guard.allow(&target) {
        return Err(Box::new(CircuitOpen));
    }
    let result = handle.block_on(connect(config, handle));
    guard.record(&target, result.is_ok());
    result
}

/// Connects to the database and applies the per-request `statement_timeout`.
///
/// The timeout is a session-level `SET`. This is correct for a direct connection and
/// for a session-mode pooler. Behind a **transaction-mode** pooler (`PgBouncer`
/// `pool_mode = transaction`) it is best-effort: the `SET` binds to one server
/// connection and a later autocommit statement may run on a different one. The robust
/// path there is an operator-side server default (`ALTER ROLE … SET statement_timeout`
/// or a `PgBouncer` `connect_query`) — see `docs/design/pooled-capabilities.md`. A
/// startup parameter (`options=-c statement_timeout=…`) is NOT usable: `PgBouncer`
/// rejects the connection with "unsupported startup parameter in options".
async fn connect(
    config: &DbConfig,
    handle: &Handle,
) -> Result<Client, Box<dyn Error + Send + Sync>> {
    let mut pg_config = tokio_postgres::Config::new();
    let _ = pg_config
        .host(&config.host)
        .port(config.port)
        .user(&config.user)
        .password(&config.password)
        .dbname(&config.database)
        .connect_timeout(Duration::from_secs(5));

    let client = if config.ssl {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let tls = postgres_rustls::MakeTlsConnector::new(tls_connector);
        let (client, connection) = pg_config.connect(tls).await?;
        spawn_connection_driver(handle, connection);
        client
    } else {
        let (client, connection) = pg_config.connect(NoTls).await?;
        spawn_connection_driver(handle, connection);
        client
    };

    // Server-side cap (best-effort behind a transaction-mode pooler; the client-side
    // deadline in `block_on_db` is the robust backstop). Safe: statement_timeout_ms is a
    // u64, cannot produce SQL injection.
    let timeout_cmd = format!("SET statement_timeout = '{}'", config.statement_timeout_ms);
    client.batch_execute(&timeout_cmd).await?;

    Ok(client)
}

/// Spawns the async driver that owns the socket and services queries. Dropping the
/// `Client` ends this task and closes the connection.
fn spawn_connection_driver<S, T>(handle: &Handle, connection: Connection<S, T>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    drop(handle.spawn(async move {
        if let Err(err) = connection.await {
            tracing::warn!("db connection closed: {err}");
        }
    }));
}

// -- Query / Execute --------------------------------------------------------

/// SELECT — returns `{columns, rows, row_count, truncated}`.
fn do_query(
    call: &DbCall<'_>,
    sql: &str,
    params_json: &str,
    max_rows: usize,
) -> Result<String, DbError> {
    let params = parse_params(params_json).map_err(DbError::fallback)?;
    let param_refs = build_param_refs(&params);

    let rows = block_on_db(call, call.client.query(sql, &param_refs))?;

    let columns = extract_columns(&rows);
    let (json_rows, truncated) = rows_to_json(&rows, max_rows);
    let row_count = json_rows.len();

    let result = serde_json::json!({
        "columns": columns,
        "rows": json_rows,
        "row_count": row_count,
        "truncated": truncated,
    });

    serde_json::to_string(&result)
        .map_err(|err| DbError::fallback(format!("serialize error: {err}")))
}

/// INSERT/UPDATE/DELETE — returns `{rows_affected}`.
fn do_execute(call: &DbCall<'_>, sql: &str, params_json: &str) -> Result<String, DbError> {
    let params = parse_params(params_json).map_err(DbError::fallback)?;
    let param_refs = build_param_refs(&params);

    let affected = block_on_db(call, call.client.execute(sql, &param_refs))?;

    Ok(format!("{{\"rows_affected\":{affected}}}"))
}

/// Simple command (BEGIN/COMMIT/ROLLBACK).
fn do_simple(call: &DbCall<'_>, cmd: &str) -> Result<String, DbError> {
    block_on_db(call, call.client.batch_execute(cmd))?;
    Ok("{\"ok\":true}".into())
}

// -- Column extraction ------------------------------------------------------

/// Extracts column names from query results.
fn extract_columns(rows: &[tokio_postgres::Row]) -> Vec<String> {
    rows.first()
        .map(|first| {
            first
                .columns()
                .iter()
                .map(|col| col.name().into())
                .collect()
        })
        .unwrap_or_default()
}

/// Converts rows to JSON values, truncating at `max_rows`.
fn rows_to_json(rows: &[tokio_postgres::Row], max_rows: usize) -> (Vec<Value>, bool) {
    let truncated = rows.len() > max_rows;
    let limit = if truncated { max_rows } else { rows.len() };

    let json_rows: Vec<Value> = rows.iter().take(limit).map(row_to_json).collect();
    (json_rows, truncated)
}

/// Converts a single row to a JSON object.
fn row_to_json(row: &tokio_postgres::Row) -> Value {
    let mut obj = serde_json::Map::new();
    for (idx, col) in row.columns().iter().enumerate() {
        drop(obj.insert(col.name().into(), column_to_json(row, idx, col.type_())));
    }
    Value::Object(obj)
}

/// Converts a column value to `serde_json::Value`.
///
/// Rule: i32 and smaller -> number. i64 and larger -> string. Always.
fn column_to_json(row: &tokio_postgres::Row, idx: usize, col_type: &Type) -> Value {
    match *col_type {
        Type::INT2 => get_or_null::<i16>(row, idx, Value::from),
        Type::INT4 | Type::OID => get_or_null::<i32>(row, idx, Value::from),
        Type::INT8 => get_or_null::<i64>(row, idx, |val| Value::String(val.to_string())),
        Type::FLOAT4 => get_or_null::<f32>(row, idx, |val| {
            serde_json::Number::from_f64(f64::from(val)).map_or(Value::Null, Value::Number)
        }),
        Type::FLOAT8 => get_or_null::<f64>(row, idx, |val| {
            serde_json::Number::from_f64(val).map_or(Value::Null, Value::Number)
        }),
        Type::BOOL => get_or_null::<bool>(row, idx, Value::Bool),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            get_or_null::<String>(row, idx, Value::String)
        }
        Type::JSON | Type::JSONB => get_or_null::<Value>(row, idx, |val| val),
        Type::UUID => get_or_null::<uuid::Uuid>(row, idx, |val| Value::String(val.to_string())),
        Type::TIMESTAMP => get_or_null::<chrono::NaiveDateTime>(row, idx, |val| {
            Value::String(val.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
        }),
        Type::TIMESTAMPTZ => get_or_null::<chrono::DateTime<chrono::Utc>>(row, idx, |val| {
            Value::String(val.to_rfc3339())
        }),
        Type::DATE => {
            get_or_null::<chrono::NaiveDate>(row, idx, |val| Value::String(val.to_string()))
        }
        Type::TIME => get_or_null::<chrono::NaiveTime>(row, idx, |val| {
            Value::String(val.format("%H:%M:%S%.f").to_string())
        }),
        Type::NUMERIC => {
            get_or_null::<rust_decimal::Decimal>(row, idx, |val| Value::String(val.to_string()))
        }
        Type::BYTEA => get_or_null::<Vec<u8>>(row, idx, |val| Value::String(BASE64.encode(&val))),
        // Fallback: try as String.
        _ => get_or_null::<String>(row, idx, Value::String),
    }
}

/// Tries to get a typed value; returns `Value::Null` on NULL or type mismatch.
fn get_or_null<'a, T: FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    idx: usize,
    convert: impl FnOnce(T) -> Value,
) -> Value {
    match row.try_get::<_, Option<T>>(idx) {
        Ok(Some(val)) => convert(val),
        Ok(None) => Value::Null,
        Err(_err) => {
            // Type mismatch fallback: try as string.
            match row.try_get::<_, Option<String>>(idx) {
                Ok(Some(text)) => Value::String(text),
                _ => Value::Null,
            }
        }
    }
}

// -- Parameters -------------------------------------------------------------

/// Parses JSON params into typed values.
fn parse_params(params_json: &str) -> Result<Vec<ParamValue>, String> {
    let values: Vec<Value> =
        serde_json::from_str(params_json).map_err(|err| format!("invalid params JSON: {err}"))?;
    Ok(values.into_iter().map(ParamValue::from).collect())
}

/// A typed parameter value.
#[derive(Debug)]
enum ParamValue {
    /// NULL.
    Null,
    /// Boolean.
    Bool(bool),
    /// 32-bit integer.
    Int4(i32),
    /// 64-bit integer.
    Int8(i64),
    /// 64-bit float.
    Float8(f64),
    /// Text.
    Text(String),
}

impl From<Value> for ParamValue {
    fn from(val: Value) -> Self {
        match val {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(flag),
            Value::Number(num) => num.as_i64().map_or_else(
                || Self::Float8(num.as_f64().unwrap_or(0.0)),
                |int| i32::try_from(int).map_or(Self::Int8(int), Self::Int4),
            ),
            Value::String(text) => Self::Text(text),
            Value::Array(arr) => {
                Self::Text(serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into()))
            }
            Value::Object(obj) => {
                Self::Text(serde_json::to_string(&obj).unwrap_or_else(|_| "{}".into()))
            }
        }
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "ToSql has encode_format with a sensible default"
)]
impl ToSql for ParamValue {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        match self {
            Self::Null => Ok(IsNull::Yes),
            Self::Bool(val) => val.to_sql(ty, out),
            Self::Int4(val) => val.to_sql(ty, out),
            Self::Int8(val) => val.to_sql(ty, out),
            Self::Float8(val) => val.to_sql(ty, out),
            Self::Text(val) => val.to_sql(ty, out),
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }
    tokio_postgres::types::to_sql_checked!();
}

/// Builds trait object references from param values.
fn build_param_refs(params: &[ParamValue]) -> Vec<&(dyn ToSql + Sync)> {
    params.iter().map(as_tosql_ref).collect()
}

/// Coerces a `ParamValue` to a `&dyn ToSql + Sync`.
fn as_tosql_ref(param: &ParamValue) -> &(dyn ToSql + Sync) {
    param
}

// -- Metrics ----------------------------------------------------------------

/// Builds a `DbMetric` from the result of an operation.
fn build_metric(action: &str, result: &Result<String, DbError>, start: Instant) -> DbMetric {
    let (rows_ret, rows_aff, trunc) = result
        .as_ref()
        .map(|json| extract_metric_info(action, json))
        .unwrap_or((0, 0, false));

    DbMetric {
        action: action.into(),
        duration_us: start.elapsed().as_micros(),
        rows_returned: rows_ret,
        rows_affected: rows_aff,
        truncated: trunc,
    }
}

/// Extracts metric info from a response JSON.
fn extract_metric_info(action: &str, json: &str) -> (usize, u64, bool) {
    let parsed: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    match action {
        "query" => {
            let rows = parsed.get("row_count").and_then(Value::as_u64).unwrap_or(0);
            let trunc = parsed
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            (usize::try_from(rows).unwrap_or(0), 0, trunc)
        }
        "execute" => {
            let affected = parsed
                .get("rows_affected")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            (0, affected, false)
        }
        _ => (0, 0, false),
    }
}

#[cfg(test)]
mod tests {
    //! Verifies the `DbError` → `EgressError` mapping used by the in-process egress adapter
    //! preserves the classified fault (code / retryable / owner) and the `db` source tag.

    use super::{DB_CONNECTION_FAULT, DbError};
    use fabric_wire::ErrorOwner;
    use serde_json::json;

    /// A fallback (`DB_ERROR`) maps across with its retry hint and operator owner, source `db`.
    #[test]
    fn fallback_maps_to_resource_error() {
        let resource_err = DbError::fallback("boom".to_owned()).into_resource_error();
        assert_eq!(resource_err.source, "db");
        assert_eq!(resource_err.code, "DB_ERROR");
        assert_eq!(resource_err.message, "boom");
        assert!(resource_err.retryable, "DB_ERROR is retryable");
        assert!(matches!(resource_err.owner, ErrorOwner::Operator));
        assert!(resource_err.details.is_none());
    }

    /// A classified driver fault carries its code, owner, and structured details through.
    #[test]
    fn driver_fault_preserves_code_and_details() {
        let resource_err = DbError {
            fault: DB_CONNECTION_FAULT,
            message: "connection refused".to_owned(),
            details: Some(json!({ "sqlstate": "08006" })),
        }
        .into_resource_error();
        assert_eq!(resource_err.code, "DB_CONNECTION");
        assert!(resource_err.retryable);
        assert_eq!(
            resource_err.details.as_deref(),
            Some(&json!({ "sqlstate": "08006" }))
        );
    }
}
