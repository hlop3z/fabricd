//! Document-database (`MongoDB`) client for the `QuickJS` sandbox (`mongo` global).
//!
//! JS API: `mongo.find/find_one/count/aggregate/insert_one/insert_many/update_one/
//! update_many/delete_one/delete_many`.
//!
//! Trust model matches `db`/`mail`: the connection is operator-supplied in
//! `config.mongo`, so there is no SSRF guard. Admitted as a first-class capability
//! (not routed over `api`) per `docs-sys/rfc.md` §3.5 — a trusted internal target with
//! document type-fidelity that JSON-over-HTTP would lose.
//!
//! Like `db` it is **async** (Tier 2 resilience): each operation runs via
//! `handle.block_on(timeout(deadline, fut))` on the `spawn_blocking` thread, so a hung
//! operation is bounded by the execution wall-clock budget. The string-in/string-out FFI
//! contract is unchanged. The driver connects lazily, so a dead database surfaces as a
//! capability throw (`MONGO_CONNECTION`) on first use rather than at inject time.

use std::fmt::{self, Formatter};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mongodb::bson::{self, Bson, Document};
use mongodb::error::{Error as DriverError, ErrorKind};
use mongodb::options::ClientOptions;
use mongodb::{Client, Collection, Database};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Handle;
use tokio::time::timeout;

use fabric_wire::metrics::{self as sandbox, Collector};
use fabric_wire::{EgressError, ErrorOwner, Fault, MongoMetric};

/// Fallback fault for any mongo error without a more specific classification.
const MONGO_FALLBACK: Fault = Fault::new("MONGO_ERROR", true, ErrorOwner::Operator);
/// Fault for a failure to reach / authenticate with the database.
const MONGO_CONNECTION: Fault = Fault::new("MONGO_CONNECTION", true, ErrorOwner::Operator);
/// Fault for an operation that exceeded the client-side execution deadline (Tier 2).
const MONGO_TIMEOUT: Fault = Fault::new("MONGO_TIMEOUT", true, ErrorOwner::Operator);
/// Fault for a write constraint violation (e.g. duplicate key).
const MONGO_WRITE: Fault = Fault::new("MONGO_WRITE", false, ErrorOwner::Developer);
/// Fault for a malformed filter / update / pipeline.
const MONGO_QUERY: Fault = Fault::new("MONGO_QUERY", false, ErrorOwner::Developer);

/// Default `MongoDB` port.
const fn default_port() -> u16 {
    27017
}
/// Default authentication database.
fn default_auth_source() -> String {
    "admin".to_owned()
}
/// Default per-operation timeout (milliseconds).
const fn default_op_timeout() -> u64 {
    5000
}
/// Default maximum documents returned by a read.
const fn default_max_docs() -> usize {
    1000
}

/// Per-request `MongoDB` configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MongoConfig {
    /// Database host.
    host: String,
    /// Database port (default 27017).
    #[serde(default = "default_port")]
    port: u16,
    /// Username (optional — omit for an unauthenticated database).
    #[serde(default)]
    username: Option<String>,
    /// Password (optional).
    #[serde(default)]
    password: Option<String>,
    /// Database name.
    database: String,
    /// Authentication database (default `admin`).
    #[serde(default = "default_auth_source")]
    auth_source: String,
    /// Use TLS.
    #[serde(default)]
    tls: bool,
    /// Path to a custom CA cert (PEM) for a self-hosted database with a private CA.
    #[serde(default)]
    ca_cert: Option<String>,
    /// Per-operation server-side timeout in milliseconds (default 5000).
    #[serde(default = "default_op_timeout")]
    op_timeout_ms: u64,
    /// Max documents returned by a read (default 1000).
    #[serde(default = "default_max_docs")]
    max_docs: usize,
}

/// A mongo error carrying its classified [`Fault`], the raw message, and structured details.
#[derive(Debug)]
pub struct MongoError {
    /// Classified code + retry hint + owner.
    fault: Fault,
    /// Raw driver/usage message.
    message: String,
    /// Structured machine context (e.g. `{code}`), surfaced ungated in `details`.
    details: Option<Value>,
}

impl MongoError {
    /// Builds a non-retryable query/usage error (bad filter, update, or pipeline).
    const fn query(message: String) -> Self {
        Self {
            fault: MONGO_QUERY,
            message,
            details: None,
        }
    }

    /// Builds the client-side deadline error (the operation ran past the execution budget).
    fn timeout() -> Self {
        Self {
            fault: MONGO_TIMEOUT,
            message: "mongo operation exceeded the execution deadline".to_owned(),
            details: None,
        }
    }

    /// Classifies a `mongodb` driver error into a [`Fault`].
    fn from_driver(err: &DriverError) -> Self {
        Self {
            fault: classify(err),
            message: err.to_string(),
            details: None,
        }
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `mongo`), preserving the classified code / retryable / owner and the structured details.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "mongo".to_owned(),
            details: self.details.map(Box::new),
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// Maps a `mongodb` driver error to a [`Fault`] by its kind (above the "stringify cliff").
fn classify(err: &DriverError) -> Fault {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "mongodb::error::ErrorKind is #[non_exhaustive]; a fallback arm is required"
    )]
    match &*err.kind {
        ErrorKind::Authentication { .. } | ErrorKind::Io(_) | ErrorKind::ServerSelection { .. } => {
            MONGO_CONNECTION
        }
        ErrorKind::Write(_) | ErrorKind::BulkWrite(_) => MONGO_WRITE,
        ErrorKind::Command(cmd) => classify_command(cmd.code),
        ErrorKind::InvalidArgument { .. } => MONGO_QUERY,
        _ => MONGO_FALLBACK,
    }
}

/// Classifies a server command error by its numeric code (`docs/99-errors.md`).
const fn classify_command(code: i32) -> Fault {
    match code {
        11_000 | 11_001 => MONGO_WRITE,
        13 | 18 => MONGO_CONNECTION,
        2 | 4 | 9 | 14 | 40 | 51 | 52 | 168 => MONGO_QUERY,
        _ => MONGO_FALLBACK,
    }
}

// -- Public API -------------------------------------------------------------

/// Runtime and deadline dependencies threaded into [`MongoBackend::connect_resource`].
///
/// Grouped so the connect entry point stays within the argument-count limit (mirrors
/// [`crate::db::DbDeps`]). Public so a consumer building a [`MongoBackend`] directly (the
/// in-process adapter, or a sidecar) can supply them.
#[derive(Debug)]
pub struct MongoDeps<'a> {
    /// Runtime handle driving the async driver from this blocking thread (`block_on`).
    pub handle: &'a Handle,
    /// Execution wall-clock budget, used as the per-operation client-side deadline (Tier 2).
    pub timeout: Duration,
}

/// A connected, JS-free `mongo` backend: the database handle (driver connects lazily) plus the
/// per-execution deadline, limits, and its own metrics, exposing a single
/// [`call`](MongoBackend::call).
///
/// The reusable async dispatch core behind the in-process
/// [`Egress`](fabric_wire::Egress) adapter (and the shape a sidecar hosts). See
/// `docs/design/resource-egress.md`.
pub struct MongoBackend {
    /// Runtime handle for `block_on` (the driver is async; the engine thread is blocking).
    handle: Handle,
    /// Per-request database handle (the driver connects lazily on first op).
    database: Database,
    /// Absolute client-side deadline applied to every operation (Tier 2).
    deadline: Instant,
    /// Max documents returned by a read.
    max_docs: usize,
    /// Server-side per-operation time limit.
    op_timeout: Duration,
    /// Per-operation metrics, drained by the consumer into `meta.mongo_requests`.
    metrics: Collector<MongoMetric>,
}

impl fmt::Debug for MongoBackend {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MongoBackend")
            .field("deadline", &self.deadline)
            .field("max_docs", &self.max_docs)
            .finish_non_exhaustive()
    }
}

impl MongoBackend {
    /// Builds the client (inside the runtime context so monitors spawn) and anchors the
    /// per-execution deadline. The driver connects lazily, so a build failure here is only a
    /// bad URI / option error, classified to a [`EgressError`] (source `mongo`); an
    /// unreachable database surfaces as a `MONGO_CONNECTION` error on the first op.
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] if client construction fails.
    pub fn connect_resource(
        config: &MongoConfig,
        deps: &MongoDeps<'_>,
    ) -> Result<Self, EgressError> {
        let uri = build_uri(config);
        let client = deps
            .handle
            .block_on(async {
                let options = ClientOptions::parse(&uri).await?;
                Client::with_options(options)
            })
            .map_err(|err: DriverError| MongoError::from_driver(&err).into_resource_error())?;
        Ok(Self {
            database: client.database(&config.database),
            handle: deps.handle.clone(),
            deadline: Instant::now()
                .checked_add(deps.timeout)
                .unwrap_or_else(Instant::now),
            max_docs: config.max_docs,
            op_timeout: Duration::from_millis(config.op_timeout_ms),
            metrics: sandbox::new_collector(),
        })
    }

    /// Runs one mongo action on `collection`, records a [`MongoMetric`], returns the result JSON.
    ///
    /// # Errors
    ///
    /// Returns a [`MongoError`] on a driver failure, deadline elapse, or a usage error.
    pub fn call(
        &self,
        action: &str,
        collection: &str,
        payload_json: &str,
    ) -> Result<String, MongoError> {
        let start = Instant::now();
        let mongo_call = MongoCall {
            handle: &self.handle,
            database: &self.database,
            deadline: self.deadline,
            max_docs: self.max_docs,
            op_timeout: self.op_timeout,
        };
        let result = dispatch(&mongo_call, action, collection, payload_json);
        sandbox::record(
            &self.metrics,
            build_metric(action, result.as_ref().ok(), start),
        );
        result.map(|outcome| outcome.json)
    }

    /// Drains (clones out) the metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<MongoMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

/// Builds a `mongodb://` connection URI for a single operator-supplied host.
///
/// A URI is used rather than the typed builder so every option (credentials, auth source,
/// direct connection, timeouts, TLS, custom CA file) is a documented connection-string key.
/// Credentials, auth source, and the CA path are percent-encoded.
fn build_uri(config: &MongoConfig) -> String {
    let mut uri = String::from("mongodb://");
    if let Some(username) = &config.username {
        uri.push_str(&encode(username));
        if let Some(password) = &config.password {
            uri.push(':');
            uri.push_str(&encode(password));
        }
        uri.push('@');
    }
    uri.push_str(&config.host);
    uri.push(':');
    uri.push_str(&config.port.to_string());
    uri.push_str("/?directConnection=true&appName=runlet");
    uri.push_str("&connectTimeoutMS=5000&serverSelectionTimeoutMS=5000");
    if config.username.is_some() {
        uri.push_str("&authSource=");
        uri.push_str(&encode(&config.auth_source));
    }
    if config.tls {
        uri.push_str("&tls=true");
        if let Some(ca) = &config.ca_cert {
            uri.push_str("&tlsCAFile=");
            uri.push_str(&encode(ca));
        }
    }
    uri
}

/// Percent-encodes a URI component (credentials, auth source, file path).
fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

// -- Dispatch ---------------------------------------------------------------

/// Bundled context for one `__mongo` call: the runtime handle, the database handle, the
/// per-execution deadline, and the read/timeout limits.
struct MongoCall<'a> {
    /// Runtime handle for `block_on`.
    handle: &'a Handle,
    /// Per-request database handle (connects lazily on first op).
    database: &'a Database,
    /// Absolute client-side deadline for every operation in this execution.
    deadline: Instant,
    /// Max documents returned by a read.
    max_docs: usize,
    /// Server-side per-operation time limit.
    op_timeout: Duration,
}

/// Successful operation result plus the stats needed to build a metric.
#[derive(Debug)]
struct MongoOutcome {
    /// JSON returned to JS.
    json: String,
    /// Documents returned (reads).
    docs_returned: usize,
    /// Documents affected (writes).
    docs_affected: u64,
    /// Whether a read result was truncated.
    truncated: bool,
}

/// Drives the async operation to completion on the pooled runtime, bounded by the
/// execution deadline (Tier 2). On elapse the future is dropped (cancelling the op) and a
/// retryable `MONGO_TIMEOUT` is returned, freeing the blocking thread.
fn dispatch(
    call: &MongoCall<'_>,
    action: &str,
    name: &str,
    payload_json: &str,
) -> Result<MongoOutcome, MongoError> {
    let payload: MongoPayload = serde_json::from_str(payload_json)
        .map_err(|err| MongoError::query(format!("invalid mongo payload: {err}")))?;
    let collection: Collection<Document> = call.database.collection(name);
    let remaining = call.deadline.saturating_duration_since(Instant::now());
    let action_owned = action.to_owned();
    call.handle.block_on(async move {
        match timeout(remaining, run(call, &collection, &action_owned, payload)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(MongoError::timeout()),
        }
    })
}

/// Routes one parsed `__mongo` call to its async handler.
async fn run(
    call: &MongoCall<'_>,
    collection: &Collection<Document>,
    action: &str,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    match action {
        "find" => do_find(call, collection, payload).await,
        "find_one" => do_find_one(collection, payload).await,
        "count" => do_count(call, collection, payload).await,
        "aggregate" => do_aggregate(call, collection, payload).await,
        "insert_one" => do_insert_one(collection, payload).await,
        "insert_many" => do_insert_many(collection, payload).await,
        "update_one" => do_update(collection, payload, false).await,
        "update_many" => do_update(collection, payload, true).await,
        "delete_one" => do_delete(collection, payload, false).await,
        "delete_many" => do_delete(collection, payload, true).await,
        other => Err(MongoError::query(format!("unknown mongo action: {other}"))),
    }
}

// -- Reads ------------------------------------------------------------------

/// `find` — returns `{docs, count, truncated}`.
async fn do_find(
    call: &MongoCall<'_>,
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let filter = json_to_doc(&payload.filter)?;
    let mut action = collection.find(filter).max_time(call.op_timeout);
    if let Some(limit) = payload.options.limit {
        action = action.limit(limit);
    }
    if let Some(skip) = payload.options.skip {
        action = action.skip(skip);
    }
    if let Some(sort) = &payload.options.sort {
        action = action.sort(json_to_doc(sort)?);
    }
    if let Some(projection) = &payload.options.projection {
        action = action.projection(json_to_doc(projection)?);
    }
    let cursor = action.await.map_err(|err| MongoError::from_driver(&err))?;
    drain_cursor(cursor, call.max_docs).await
}

/// `find_one` — returns the first matching document, or `null`.
async fn do_find_one(
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let filter = json_to_doc(&payload.filter)?;
    let found = collection
        .find_one(filter)
        .await
        .map_err(|err| MongoError::from_driver(&err))?;
    let present = found.is_some();
    let json = found.map_or_else(
        || "null".to_owned(),
        |doc| document_to_json(doc).to_string(),
    );
    Ok(MongoOutcome {
        json,
        docs_returned: usize::from(present),
        docs_affected: 0,
        truncated: false,
    })
}

/// `count` — returns `{count}`.
async fn do_count(
    call: &MongoCall<'_>,
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let filter = json_to_doc(&payload.filter)?;
    let count = collection
        .count_documents(filter)
        .max_time(call.op_timeout)
        .await
        .map_err(|err| MongoError::from_driver(&err))?;
    Ok(MongoOutcome {
        json: format!("{{\"count\":{count}}}"),
        docs_returned: 0,
        docs_affected: 0,
        truncated: false,
    })
}

/// `aggregate` — returns `{docs, count, truncated}`.
async fn do_aggregate(
    call: &MongoCall<'_>,
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let pipeline = pipeline_to_docs(payload.pipeline)?;
    let cursor = collection
        .aggregate(pipeline)
        .max_time(call.op_timeout)
        .await
        .map_err(|err| MongoError::from_driver(&err))?;
    drain_cursor(cursor, call.max_docs).await
}

/// Drains a cursor into a `{docs, count, truncated}` outcome, capping at `max_docs`.
async fn drain_cursor(
    mut cursor: mongodb::Cursor<Document>,
    max_docs: usize,
) -> Result<MongoOutcome, MongoError> {
    let mut docs: Vec<Value> = Vec::new();
    let mut truncated = false;
    while cursor
        .advance()
        .await
        .map_err(|err| MongoError::from_driver(&err))?
    {
        if docs.len() >= max_docs {
            truncated = true;
            break;
        }
        let doc: Document = cursor
            .deserialize_current()
            .map_err(|err| MongoError::from_driver(&err))?;
        docs.push(document_to_json(doc));
    }
    let count = docs.len();
    let json = serde_json::json!({ "docs": docs, "count": count, "truncated": truncated });
    Ok(MongoOutcome {
        json: json.to_string(),
        docs_returned: count,
        docs_affected: 0,
        truncated,
    })
}

// -- Writes -----------------------------------------------------------------

/// `insert_one` — returns `{inserted_id}`.
async fn do_insert_one(
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let doc = json_to_doc(&payload.doc)?;
    let result = collection
        .insert_one(doc)
        .await
        .map_err(|err| MongoError::from_driver(&err))?;
    let id = id_to_string(result.inserted_id);
    let encoded = serde_json::to_string(&id).unwrap_or_else(|_err| "\"\"".to_owned());
    Ok(MongoOutcome {
        json: format!("{{\"inserted_id\":{encoded}}}"),
        docs_returned: 0,
        docs_affected: 1,
        truncated: false,
    })
}

/// `insert_many` — returns `{inserted_count}`.
async fn do_insert_many(
    collection: &Collection<Document>,
    payload: MongoPayload,
) -> Result<MongoOutcome, MongoError> {
    let docs = docs_to_docs(payload.docs)?;
    if docs.is_empty() {
        return Err(MongoError::query(
            "mongo.insert_many requires at least one document".to_owned(),
        ));
    }
    let result = collection
        .insert_many(docs)
        .await
        .map_err(|err| MongoError::from_driver(&err))?;
    let count = u64::try_from(result.inserted_ids.len()).unwrap_or(u64::MAX);
    Ok(MongoOutcome {
        json: format!("{{\"inserted_count\":{count}}}"),
        docs_returned: 0,
        docs_affected: count,
        truncated: false,
    })
}

/// `update_one` / `update_many` — returns `{matched, modified}`.
async fn do_update(
    collection: &Collection<Document>,
    payload: MongoPayload,
    many: bool,
) -> Result<MongoOutcome, MongoError> {
    let filter = json_to_doc(&payload.filter)?;
    let update = json_to_doc(&payload.update)?;
    let result = if many {
        collection.update_many(filter, update).await
    } else {
        collection.update_one(filter, update).await
    }
    .map_err(|err| MongoError::from_driver(&err))?;
    Ok(MongoOutcome {
        json: format!(
            "{{\"matched\":{},\"modified\":{}}}",
            result.matched_count, result.modified_count
        ),
        docs_returned: 0,
        docs_affected: result.modified_count,
        truncated: false,
    })
}

/// `delete_one` / `delete_many` — returns `{deleted}`.
async fn do_delete(
    collection: &Collection<Document>,
    payload: MongoPayload,
    many: bool,
) -> Result<MongoOutcome, MongoError> {
    let filter = json_to_doc(&payload.filter)?;
    let result = if many {
        collection.delete_many(filter).await
    } else {
        collection.delete_one(filter).await
    }
    .map_err(|err| MongoError::from_driver(&err))?;
    Ok(MongoOutcome {
        json: format!("{{\"deleted\":{}}}", result.deleted_count),
        docs_returned: 0,
        docs_affected: result.deleted_count,
        truncated: false,
    })
}

// -- Payloads ---------------------------------------------------------------

/// Parsed `__mongo` payload — every field optional, interpreted per action.
#[derive(Debug, Default, Deserialize)]
struct MongoPayload {
    /// Filter document (reads, updates, deletes).
    #[serde(default)]
    filter: Value,
    /// Update document (updates).
    #[serde(default)]
    update: Value,
    /// Document to insert (`insert_one`).
    #[serde(default)]
    doc: Value,
    /// Documents to insert (`insert_many`).
    #[serde(default)]
    docs: Value,
    /// Aggregation pipeline (`aggregate`).
    #[serde(default)]
    pipeline: Value,
    /// Read options (`find`).
    #[serde(default)]
    options: FindOpts,
}

/// `find` options.
#[derive(Debug, Default, Deserialize)]
struct FindOpts {
    /// Max documents (driver-side).
    #[serde(default)]
    limit: Option<i64>,
    /// Documents to skip.
    #[serde(default)]
    skip: Option<u64>,
    /// Sort document.
    #[serde(default)]
    sort: Option<Value>,
    /// Projection document.
    #[serde(default)]
    projection: Option<Value>,
}

/// Converts a JSON value into a BSON `Document` (null → empty document). A non-object
/// value is a developer usage error.
fn json_to_doc(value: &Value) -> Result<Document, MongoError> {
    if value.is_null() {
        return Ok(Document::new());
    }
    match bson::to_bson(value) {
        Ok(Bson::Document(doc)) => Ok(doc),
        Ok(_other) => Err(MongoError::query("expected a JSON object".to_owned())),
        Err(err) => Err(MongoError::query(format!("invalid document: {err}"))),
    }
}

/// Converts a JSON array into a list of BSON documents (for pipelines / `insert_many`).
fn docs_to_docs(value: Value) -> Result<Vec<Document>, MongoError> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items.iter().map(json_to_doc).collect(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Object(_) => {
            Err(MongoError::query("expected a JSON array".to_owned()))
        }
    }
}

/// Pipelines share the array-of-documents conversion.
fn pipeline_to_docs(value: Value) -> Result<Vec<Document>, MongoError> {
    docs_to_docs(value)
}

// -- BSON -> JSON -----------------------------------------------------------

/// Converts a BSON document to a JSON object.
fn document_to_json(doc: Document) -> Value {
    let mut obj = serde_json::Map::new();
    for (key, val) in doc {
        drop(obj.insert(key, bson_to_json(val)));
    }
    Value::Object(obj)
}

/// Converts a BSON value to `serde_json::Value`.
///
/// Rule (mirrors `db`): values that don't fit a JS number exactly come back as strings —
/// `Int64`/`Decimal128` as strings, `ObjectId` as hex, `Date` as RFC 3339, `Binary` as
/// base64; `Int32`/`Double` as numbers; structural values pass through.
fn bson_to_json(value: Bson) -> Value {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "mongodb::bson::Bson is #[non_exhaustive]; exotic BSON types fall back to a string"
    )]
    match value {
        Bson::Double(num) => serde_json::Number::from_f64(num).map_or(Value::Null, Value::Number),
        Bson::String(text) => Value::String(text),
        Bson::Boolean(flag) => Value::Bool(flag),
        Bson::Null => Value::Null,
        Bson::Int32(int) => Value::from(int),
        Bson::Int64(int) => Value::String(int.to_string()),
        Bson::ObjectId(oid) => Value::String(oid.to_hex()),
        Bson::Decimal128(dec) => Value::String(dec.to_string()),
        Bson::DateTime(date) => Value::String(
            date.try_to_rfc3339_string()
                .unwrap_or_else(|_err| date.timestamp_millis().to_string()),
        ),
        Bson::Binary(bin) => Value::String(BASE64.encode(&bin.bytes)),
        Bson::Array(items) => Value::Array(items.into_iter().map(bson_to_json).collect()),
        Bson::Document(doc) => document_to_json(doc),
        other => Value::String(other.to_string()),
    }
}

/// Renders an inserted-id BSON value as a string (hex for `ObjectId`).
fn id_to_string(id: Bson) -> String {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "mongodb::bson::Bson is #[non_exhaustive]; any non-id type falls back to its string form"
    )]
    match id {
        Bson::ObjectId(oid) => oid.to_hex(),
        Bson::String(text) => text,
        other => bson_to_json(other).to_string(),
    }
}

// -- Metrics ----------------------------------------------------------------

/// Builds a `MongoMetric` from the outcome (or zeros on failure).
fn build_metric(action: &str, outcome: Option<&MongoOutcome>, start: Instant) -> MongoMetric {
    let (returned, affected, truncated) = outcome.map_or((0, 0, false), |out| {
        (out.docs_returned, out.docs_affected, out.truncated)
    });
    MongoMetric {
        action: action.to_owned(),
        duration_us: start.elapsed().as_micros(),
        docs_returned: returned,
        docs_affected: affected,
        truncated,
    }
}
