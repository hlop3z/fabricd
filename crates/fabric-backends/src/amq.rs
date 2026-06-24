//! `RabbitMQ` **producer** for the `QuickJS` sandbox (`amq` global).
//!
//! JS API: `amq.send([[routingKey, payload], …])` — list-always; Rust owns batching.
//! Trust model matches `db`/`mail`: the broker connection is operator-supplied in
//! `config.amq`, so no SSRF guard. Producer only (no consume/subscribe).
//!
//! `amqprs` is async, but capability closures run blocking (inside `spawn_blocking`),
//! so each `send` opens **one** connection + channel for the whole batch inside a
//! per-call current-thread `tokio` runtime (`block_on`), publishes every message, and
//! closes. One `send` call = one metered op, regardless of batch size.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use amqprs::BasicProperties;
use amqprs::channel::BasicPublishArguments;
use amqprs::connection::{Connection, OpenConnectionArguments};
use amqprs::tls::TlsAdaptor;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tokio::runtime::{Builder, Runtime};

use fabric_wire::metrics::{self as sandbox, Collector};
use fabric_wire::{EgressError, ErrorOwner, Fault};

/// Fallback fault for a publish/protocol error.
const AMQ_FALLBACK: Fault = Fault::new("AMQ_ERROR", true, ErrorOwner::Operator);
/// Fault for a failure to reach / authenticate with the broker.
const AMQ_CONNECTION: Fault = Fault::new("AMQ_CONNECTION", true, ErrorOwner::Operator);
/// Fault for a batch larger than `max_batch`.
const AMQ_BATCH: Fault = Fault::new("AMQ_BATCH_TOO_LARGE", false, ErrorOwner::Developer);
/// Fault for a request-reply that received no reply within the timeout (NATS backend).
const AMQ_TIMEOUT: Fault = Fault::new("AMQ_TIMEOUT", true, ErrorOwner::Operator);
/// Fault for an operation the selected backend does not support (e.g. `request` on `RabbitMQ`).
const AMQ_UNSUPPORTED: Fault = Fault::new("AMQ_UNSUPPORTED", false, ErrorOwner::Developer);

/// Messaging backend selected by `config.amq.backend`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AmqBackend {
    /// `RabbitMQ` (default) — AMQP producer.
    #[default]
    Rabbitmq,
    /// Subject-based messaging (`NATS`) — publish + request-reply.
    Nats,
}

/// Per-request messaging configuration (`RabbitMQ` or `NATS`, by `backend`).
#[derive(Debug, Clone, Deserialize)]
pub struct AmqConfig {
    /// Messaging backend (default `rabbitmq`).
    #[serde(default)]
    pub backend: AmqBackend,
    /// Broker host.
    pub host: String,
    /// Broker port (default 5672 for `RabbitMQ`, 4222 for NATS).
    #[serde(default)]
    pub port: Option<u16>,
    /// Username — `RabbitMQ` defaults to `guest`; NATS authenticates only when supplied.
    #[serde(default)]
    pub username: Option<String>,
    /// Password — `RabbitMQ` defaults to `guest`; NATS authenticates only when supplied.
    #[serde(default)]
    pub password: Option<String>,
    /// Bearer token auth (NATS backend only).
    #[serde(default)]
    pub token: Option<String>,
    /// Virtual host (`RabbitMQ`, default `/`).
    #[serde(default = "default_vhost")]
    pub vhost: String,
    /// Exchange to publish to (`RabbitMQ`, default `""` — the default exchange).
    #[serde(default)]
    pub exchange: String,
    /// Maximum messages per `send` call (default 100).
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    /// Request-reply timeout in milliseconds (NATS backend, default 5000).
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: u64,
    /// Use TLS. Reuses the `aws-lc-rs` rustls provider.
    #[serde(default)]
    pub tls: bool,
    /// Path to a custom CA cert (PEM) for a self-hosted broker. Omit for managed services
    /// (their public CAs are covered by the bundled webpki roots).
    #[serde(default)]
    pub ca_cert: Option<String>,
}

impl AmqConfig {
    /// Resolves the connection port, defaulting per backend.
    fn resolved_port(&self) -> u16 {
        self.port.unwrap_or(match self.backend {
            AmqBackend::Rabbitmq => 5672,
            AmqBackend::Nats => 4222,
        })
    }
}

/// Default virtual host.
fn default_vhost() -> String {
    "/".to_owned()
}
/// Default batch cap.
const fn default_max_batch() -> usize {
    100
}
/// Default request-reply timeout (milliseconds).
const fn default_request_timeout() -> u64 {
    5000
}

/// Metric recorded for each `amq.send` op.
#[derive(Debug, Clone, Serialize)]
pub struct AmqMetric {
    /// Operation type.
    action: String,
    /// Duration in microseconds.
    duration_us: u128,
    /// Number of messages in the batch.
    messages: usize,
    /// Total payload bytes published.
    bytes: usize,
    /// Whether the batch was accepted by the broker.
    published: bool,
}

impl AmqMetric {
    /// Operation duration in microseconds (for the per-capability latency histogram).
    #[must_use]
    pub const fn duration_us(&self) -> u128 {
        self.duration_us
    }
}

/// An amq error carrying its classified [`Fault`] plus the raw message.
#[derive(Debug)]
pub struct AmqError {
    /// Classified code + retry hint + owner.
    fault: Fault,
    /// Raw message.
    message: String,
}

impl AmqError {
    /// Builds a fallback (`AMQ_ERROR`) error.
    const fn fallback(message: String) -> Self {
        Self {
            fault: AMQ_FALLBACK,
            message,
        }
    }

    /// Builds a connection error (`AMQ_CONNECTION`).
    const fn connection(message: String) -> Self {
        Self {
            fault: AMQ_CONNECTION,
            message,
        }
    }

    /// Builds an unsupported-operation error (`AMQ_UNSUPPORTED`).
    const fn unsupported(message: String) -> Self {
        Self {
            fault: AMQ_UNSUPPORTED,
            message,
        }
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `amq`), preserving the classified code / retryable / owner.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "amq".to_owned(),
            details: None,
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// Successful send result plus the stats needed to build a metric.
#[derive(Debug)]
struct SendOutcome {
    /// JSON returned to JS.
    json: String,
    /// Number of messages published.
    messages: usize,
    /// Total payload bytes.
    bytes: usize,
}

// -- Public API -------------------------------------------------------------

/// A `amq` producer: the operator config plus its own metrics, exposing a single
/// [`call`](AmqProducer::call).
///
/// Stateless beyond config — each `send`/`request` opens its own
/// connection lazily (see module docs), so there is no setup I/O and construction is infallible.
/// The reusable dispatch core behind the in-process
/// [`Egress`](fabric_wire::Egress) adapter. (Named `AmqProducer`, not `*Backend`, since
/// [`AmqBackend`] is already the rabbitmq/nats selector enum.) See
/// `docs/design/resource-egress.md`.
#[derive(Debug)]
pub struct AmqProducer {
    /// Operator messaging config (host, backend, auth, batch cap, …).
    config: AmqConfig,
    /// Per-operation metrics, drained by the consumer into `meta.amq_requests`.
    metrics: Collector<AmqMetric>,
}

impl AmqProducer {
    /// Builds the producer from config (no I/O — connections are opened per call).
    #[must_use]
    pub fn new(config: AmqConfig) -> Self {
        Self {
            config,
            metrics: sandbox::new_collector(),
        }
    }

    /// Runs one amq action (`send`/`request`), records an [`AmqMetric`], returns the result JSON.
    ///
    /// # Errors
    ///
    /// Returns an [`AmqError`] on a connect/publish/protocol failure or a usage error.
    pub fn call(&self, action: &str, payload_json: &str) -> Result<String, AmqError> {
        let start = Instant::now();
        let result = dispatch(&self.config, action, payload_json);
        sandbox::record(
            &self.metrics,
            build_metric(action, result.as_ref().ok(), start),
        );
        result.map(|outcome| outcome.json)
    }

    /// Drains (clones out) the metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<AmqMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

// -- Dispatch ---------------------------------------------------------------

/// Routes an `__amq` call to the correct handler.
fn dispatch(config: &AmqConfig, action: &str, payload_json: &str) -> Result<SendOutcome, AmqError> {
    match action {
        "send" => do_send(config, payload_json),
        "request" => do_request(config, payload_json),
        other => Err(AmqError::fallback(format!("unknown amq action: {other}"))),
    }
}

/// Parses + validates the batch, then publishes it in one `block_on`.
fn do_send(config: &AmqConfig, payload_json: &str) -> Result<SendOutcome, AmqError> {
    let payload: SendPayload = serde_json::from_str(payload_json)
        .map_err(|err| AmqError::fallback(format!("invalid amq payload: {err}")))?;

    let count = payload.messages.len();
    if count == 0 {
        return Err(AmqError::fallback(
            "amq.send requires at least one message".to_owned(),
        ));
    }
    if count > config.max_batch {
        return Err(AmqError {
            fault: AMQ_BATCH,
            message: format!("batch too large: {count} (max {})", config.max_batch),
        });
    }

    let runtime = build_runtime()?;
    let bytes = match config.backend {
        AmqBackend::Rabbitmq => runtime.block_on(publish_batch(config, &payload.messages))?,
        AmqBackend::Nats => runtime.block_on(nats_publish(config, &payload.messages))?,
    };

    let json = format!("{{\"published\":{count}}}");
    Ok(SendOutcome {
        json,
        messages: count,
        bytes,
    })
}

/// Parses + dispatches a request-reply (`NATS` backend only).
fn do_request(config: &AmqConfig, payload_json: &str) -> Result<SendOutcome, AmqError> {
    if config.backend != AmqBackend::Nats {
        return Err(AmqError::unsupported(
            "amq.request requires the nats backend".to_owned(),
        ));
    }
    let req: RequestPayload = serde_json::from_str(payload_json)
        .map_err(|err| AmqError::fallback(format!("invalid amq payload: {err}")))?;

    let runtime = build_runtime()?;
    let (json, bytes) = runtime.block_on(nats_request(config, &req.subject, req.payload.get()))?;
    Ok(SendOutcome {
        json,
        messages: 1,
        bytes,
    })
}

/// Builds the per-call current-thread runtime used to drive the async client.
fn build_runtime() -> Result<Runtime, AmqError> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| AmqError::fallback(format!("failed to build runtime: {err}")))
}

/// Opens one connection + channel, publishes every message, then closes.
async fn publish_batch(config: &AmqConfig, messages: &[AmqMessage]) -> Result<usize, AmqError> {
    let username = config.username.as_deref().unwrap_or("guest");
    let password = config.password.as_deref().unwrap_or("guest");
    let mut args =
        OpenConnectionArguments::new(&config.host, config.resolved_port(), username, password);
    let _ = args.virtual_host(&config.vhost);
    if config.tls {
        let ca = config.ca_cert.as_deref().map(Path::new);
        let adaptor = TlsAdaptor::without_client_auth(ca, config.host.clone())
            .map_err(|err| AmqError::connection(format!("amq tls setup failed: {err}")))?;
        let _ = args.tls_adaptor(adaptor);
    }

    let connection = Connection::open(&args)
        .await
        .map_err(|err| AmqError::connection(format!("amq connect failed: {err}")))?;
    let channel = connection
        .open_channel(None)
        .await
        .map_err(|err| AmqError::connection(format!("amq channel failed: {err}")))?;

    let mut total_bytes: usize = 0;
    for message in messages {
        let content = message.payload.get().as_bytes().to_vec();
        total_bytes = total_bytes.saturating_add(content.len());
        let publish_args = BasicPublishArguments::new(&config.exchange, &message.key);
        channel
            .basic_publish(BasicProperties::default(), content, publish_args)
            .await
            .map_err(|err| AmqError::fallback(format!("amq publish failed: {err}")))?;
    }

    drop(channel.close().await);
    drop(connection.close().await);
    Ok(total_bytes)
}

// -- NATS backend -----------------------------------------------------------

/// Connects to the NATS server, applying auth (user/password or token) and TLS.
async fn nats_connect(config: &AmqConfig) -> Result<async_nats::Client, AmqError> {
    let mut opts = async_nats::ConnectOptions::new()
        .request_timeout(Some(Duration::from_millis(config.request_timeout_ms)));
    if let Some(username) = config.username.clone() {
        opts = opts.user_and_password(username, config.password.clone().unwrap_or_default());
    } else if let Some(token) = config.token.clone() {
        opts = opts.token(token);
    }
    if config.tls {
        opts = opts.require_tls(true);
        if let Some(ca) = config.ca_cert.clone() {
            opts = opts.add_root_certificates(PathBuf::from(ca));
        }
    }
    let address = format!("{}:{}", config.host, config.resolved_port());
    async_nats::connect_with_options(address, opts)
        .await
        .map_err(|err| AmqError::connection(format!("nats connect failed: {err}")))
}

/// Publishes every message to its subject, then flushes to confirm delivery.
async fn nats_publish(config: &AmqConfig, messages: &[AmqMessage]) -> Result<usize, AmqError> {
    let client = nats_connect(config).await?;
    let mut total_bytes: usize = 0;
    for message in messages {
        let content = message.payload.get().as_bytes().to_vec();
        total_bytes = total_bytes.saturating_add(content.len());
        client
            .publish(message.key.clone(), bytes::Bytes::from(content))
            .await
            .map_err(|err| AmqError::fallback(format!("nats publish failed: {err}")))?;
    }
    client
        .flush()
        .await
        .map_err(|err| AmqError::fallback(format!("nats flush failed: {err}")))?;
    Ok(total_bytes)
}

/// Sends a request and returns `({"reply": <body>}, request_bytes)`. The reply body is
/// parsed as JSON when valid, otherwise carried as a JSON string. Wrapping under `reply`
/// keeps an arbitrary reply that happens to contain an `error` field from being mistaken
/// for a capability error by the JS wrapper.
async fn nats_request(
    config: &AmqConfig,
    subject: &str,
    payload: &str,
) -> Result<(String, usize), AmqError> {
    let client = nats_connect(config).await?;
    let request_bytes = payload.len();
    let reply = client
        .request(
            subject.to_owned(),
            bytes::Bytes::from(payload.as_bytes().to_vec()),
        )
        .await
        .map_err(|err| AmqError {
            fault: classify_request_error(&err.to_string()),
            message: format!("nats request failed: {err}"),
        })?;
    let body_text = String::from_utf8_lossy(&reply.payload).into_owned();
    let body: serde_json::Value =
        serde_json::from_str(&body_text).unwrap_or(serde_json::Value::String(body_text));
    let wrapped = serde_json::json!({ "reply": body });
    Ok((wrapped.to_string(), request_bytes))
}

/// Classifies a NATS request error from its message: a missing responder or an elapsed
/// timeout is the retryable `AMQ_TIMEOUT`, anything else the retryable fallback. (NATS's
/// request error carries the cause in its `Display`, above the stringify cliff for callers.)
fn classify_request_error(message: &str) -> Fault {
    let lowered = message.to_lowercase();
    if lowered.contains("no responders")
        || lowered.contains("timed out")
        || lowered.contains("timeout")
    {
        AMQ_TIMEOUT
    } else {
        AMQ_FALLBACK
    }
}

// -- Payloads ---------------------------------------------------------------

/// Parsed `send` payload.
#[derive(Debug, Deserialize)]
struct SendPayload {
    /// The messages to publish.
    #[serde(default)]
    messages: Vec<AmqMessage>,
}

/// One message: a routing key + a raw-JSON payload (published as the body bytes).
#[derive(Debug, Deserialize)]
struct AmqMessage {
    /// Routing key (queue name for the default exchange).
    #[serde(default)]
    key: String,
    /// Payload — serialized to its JSON bytes as the message body.
    #[serde(default = "default_payload")]
    payload: Box<RawValue>,
}

/// Default payload (`null`) when a message omits one.
fn default_payload() -> Box<RawValue> {
    RawValue::from_string("null".to_owned()).unwrap_or_else(|_err| unreachable!())
}

/// Parsed `request` payload: a subject + a raw-JSON body.
#[derive(Debug, Deserialize)]
struct RequestPayload {
    /// Subject to send the request to.
    #[serde(default)]
    subject: String,
    /// Request body — serialized to its JSON bytes.
    #[serde(default = "default_payload")]
    payload: Box<RawValue>,
}

// -- Metrics ----------------------------------------------------------------

/// Builds an `AmqMetric` from the outcome (or zeros on failure).
fn build_metric(action: &str, outcome: Option<&SendOutcome>, start: Instant) -> AmqMetric {
    let (messages, bytes, published) =
        outcome.map_or((0, 0, false), |out| (out.messages, out.bytes, true));
    AmqMetric {
        action: action.to_owned(),
        duration_us: start.elapsed().as_micros(),
        messages,
        bytes,
        published,
    }
}
