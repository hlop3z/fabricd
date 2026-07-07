//! `fabricd`: the egress sidecar / broker for runlet.
//!
//! Hosts [`fabric_backends::BackendSet`] behind the [`runlet_wire::wire`] protocol over one of two
//! transports: a local **Unix-domain socket** (the zero-config default) and a remote **QUIC** link
//! (a shared, replicated cluster service many boxes reach over the network). The daemon owns the
//! operator credential table: the box sends only logical resource *names* (a `WireInit`), and
//! `fabricd` resolves them against its `resources` config. One client connection (UDS) or one QUIC
//! bidirectional stream = one box-request session: the client sends `Init` (selected names +
//! deadline, + an auth token on QUIC), the daemon validates the token, resolves + builds a fresh
//! `BackendSet` (lazy per-backend connect, so a transaction's `begin`→`commit` reuse one client),
//! then dispatches each `Call` and answers `Drain` with the metrics. On EOF the `BackendSet` drops,
//! tearing down its driver connections.
//!
//! The daemon links the network drivers (via `fabric-backends`) so the sandbox box does not — see
//! `docs/design/resource-egress.md` step 5 and `docs/design/network-fabric.md` (QUIC transport).

mod auth;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fabric_backends::{AsyncDeps, BackendSet, TenantResourceBinding, resolve};
use runlet_wire::Egress as _;
use runlet_wire::breaker::{BreakerConfig, CircuitBreaker};
use runlet_wire::quic::{ServerTls, server_endpoint};
use runlet_wire::wire::{WireCall, WireRequest, WireResponse, read_frame, write_frame};
use quinn::{Connection, Endpoint, Incoming};
use rustls::crypto::aws_lc_rs;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::task;
use tracing::{debug, info, warn};
use tracing_subscriber::fmt::init as init_tracing;

use crate::auth::{ClientAuthConfig, ClientAuthenticator};

/// Default socket path when neither config nor `FABRICD_SOCKET` sets one (and QUIC is off).
#[cfg(unix)]
const DEFAULT_SOCKET: &str = "/tmp/fabricd.sock";

/// Default ceiling on concurrently-open QUIC connections (hardening; config-overridable).
const fn default_max_connections() -> usize {
    1024
}

/// Default `db` circuit-breaker cool-down (ms) when `db_breaker_cooldown_ms` is `0`.
const DEFAULT_BREAKER_COOLDOWN_MS: u64 = 5000;

/// Daemon configuration, loaded from the `FABRICD_CONFIG` path (default `fabricd.json`).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FabricdConfig {
    /// Socket path to bind (env `FABRICD_SOCKET` overrides; defaults to [`DEFAULT_SOCKET`] only when
    /// QUIC is not configured).
    socket: Option<String>,
    /// The operator credential table: logical name → tenant-scoped driver binding. The box never
    /// sees these; `fabricd` resolves a name only within the session tenant's authorized bindings.
    resources: HashMap<String, TenantResourceBinding>,
    /// Tier-0 ceiling on a `db` resource's `statement_timeout_ms` (`0` = no clamp).
    max_statement_timeout_ms: u64,
    /// Circuit breaker (Tier 3): consecutive `db` connect failures (per `host:port`) that trip
    /// the breaker open. `0` = off. While open, `db` calls to that target fast-fail
    /// `DB_CIRCUIT_OPEN` (retryable) instead of waiting on the connect timeout to a dead
    /// database (see `docs/design/resilience.md`).
    db_breaker_threshold: u32,
    /// How long (ms) the `db` circuit breaker stays open before allowing a half-open probe.
    /// Used only when `db_breaker_threshold > 0`. `0` = default 5000.
    db_breaker_cooldown_ms: u64,
    /// Bind address for a plaintext HTTP `GET /metrics` listener (Prometheus text exposition:
    /// breaker trips, client-auth failures), e.g. `127.0.0.1:9090`. Omit (the default) for no
    /// metrics listener. Plaintext — bind it loopback/pod-local and scope it like the box's
    /// `/metrics` (never a public ingress).
    metrics_listen: Option<String>,
    /// Remote QUIC listener (the network transport). Omit for a local-only UDS sidecar.
    quic: Option<QuicListenerConfig>,
}

/// The remote QUIC listener's settings (the `quic` block).
#[derive(Debug, Deserialize)]
struct QuicListenerConfig {
    /// `host:port` to bind the UDP/QUIC endpoint (e.g. `0.0.0.0:7000`).
    listen: String,
    /// Path to the server certificate chain (PEM). The box pins this cert by fingerprint.
    server_cert: PathBuf,
    /// Path to the matching private key (PEM).
    server_key: PathBuf,
    /// Ceiling on concurrently-open connections (hardening).
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    /// Client-auth provider for the token in each `WireInit` (validated before name resolution).
    #[serde(default)]
    auth: ClientAuthConfig,
}

/// Shared, read-only daemon state handed to each connection.
#[derive(Debug)]
struct Shared {
    /// Operator credential table (tenant-scoped bindings).
    table: HashMap<String, TenantResourceBinding>,
    /// `db` statement-timeout ceiling (Tier 0).
    max_statement_timeout_ms: u64,
    /// Daemon-global per-target `db` circuit breaker (Tier 3); `None` = off. Shared across
    /// sessions — trip state must outlive the one-request session or it never accumulates.
    breaker: Option<Arc<CircuitBreaker>>,
    /// Running count of client-auth rejections (a spike is a security signal).
    auth_failures: AtomicU64,
}

/// A built QUIC listener: the endpoint, its client-auth provider, and the connection cap.
type QuicListener = (Endpoint, Arc<dyn ClientAuthenticator>, Arc<Semaphore>);

impl Shared {
    /// Records one client-auth rejection and returns the new running total.
    fn record_auth_failure(&self) -> u64 {
        self.auth_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }
}

/// Entry point — loads config, binds the configured listener(s), and serves until a shutdown signal.
///
/// # Errors
///
/// Returns an error if the config can't be read/parsed, no listener is configured, or a listener
/// can't be bound (socket, or the QUIC endpoint / its TLS material).
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    init_tracing();

    // Install `aws-lc-rs` as the single rustls provider (db SSL / rediss / amqps + the QUIC
    // transport all reuse it). The drivers live here now, so the daemon installs it.
    if aws_lc_rs::default_provider().install_default().is_err() {
        warn!("rustls crypto provider was already installed");
    }

    let config = load_config()?;
    // One breaker for the daemon's lifetime: per-target trip state accumulates across the
    // one-request sessions. `CircuitBreaker::new` returns `None` when the threshold is `0` (off).
    let breaker = CircuitBreaker::new(BreakerConfig {
        threshold: config.db_breaker_threshold,
        cooldown: Duration::from_millis(if config.db_breaker_cooldown_ms > 0 {
            config.db_breaker_cooldown_ms
        } else {
            DEFAULT_BREAKER_COOLDOWN_MS
        }),
    })
    .map(Arc::new);
    let shared = Arc::new(Shared {
        table: config.resources,
        max_statement_timeout_ms: config.max_statement_timeout_ms,
        breaker,
        auth_failures: AtomicU64::new(0),
    });

    // Decide which listeners to run. The local UDS stays the zero-config default; QUIC engages only
    // when `quic` is set. An explicit socket (env or config) always binds UDS too, so one daemon can
    // serve a local box (UDS) and remote boxes (QUIC) at once. UDS is a Unix-only tokio API — on
    // other platforms a configured socket is rejected loudly and QUIC is the sole transport.
    let explicit_socket = env::var("FABRICD_SOCKET")
        .ok()
        .or_else(|| config.socket.clone());
    #[cfg(not(unix))]
    if explicit_socket.is_some() {
        return Err(
            "`socket` / `FABRICD_SOCKET` (UDS) is unsupported on this platform; configure `quic`"
                .into(),
        );
    }
    #[cfg(unix)]
    let uds_path =
        explicit_socket.or_else(|| config.quic.is_none().then(|| DEFAULT_SOCKET.to_owned()));
    #[cfg(not(unix))]
    let uds_path: Option<String> = None;

    info!(
        resources = shared.table.len(),
        uds = ?uds_path,
        quic = config.quic.is_some(),
        db_breaker = shared.breaker.is_some(),
        "fabricd configuration loaded"
    );
    if uds_path.is_none() && config.quic.is_none() {
        return Err("no listener configured: set `socket` (UDS) and/or `quic` (remote)".into());
    }

    // Build the UDS listener (if any). UDS is gated by filesystem permissions, so it uses the
    // no-op authenticator — the box sends no token over it.
    #[cfg(unix)]
    let uds = match uds_path.as_deref() {
        Some(path) => {
            // A stale socket file from a previous run would make `bind` fail with EADDRINUSE.
            drop(fs::remove_file(path));
            let listener = UnixListener::bind(path)?;
            info!(socket = %path, "fabricd listening (uds)");
            Some(listener)
        }
        None => None,
    };
    #[cfg(unix)]
    let uds_auth: Arc<dyn ClientAuthenticator> =
        Arc::from(auth::build(&ClientAuthConfig::default())?);

    // Build the QUIC listener (if any): endpoint + its client-auth provider + the connection cap.
    let quic = match config.quic.as_ref() {
        Some(quic_cfg) => {
            let endpoint = build_quic_endpoint(quic_cfg)?;
            let authenticator: Arc<dyn ClientAuthenticator> =
                Arc::from(auth::build(&quic_cfg.auth)?);
            let conn_limit = Arc::new(Semaphore::new(quic_cfg.max_connections));
            info!(
                listen = %quic_cfg.listen,
                auth = ?authenticator,
                max_connections = quic_cfg.max_connections,
                "fabricd listening (quic)"
            );
            Some((endpoint, authenticator, conn_limit))
        }
        None => None,
    };

    // Build the metrics listener (if any): a plaintext `GET /metrics` scrape endpoint. Bound at
    // boot so a bad address fails loud instead of silently dropping observability.
    let metrics = match config.metrics_listen.as_deref() {
        Some(addr) => {
            let listener = TcpListener::bind(addr).await?;
            info!(listen = %addr, "fabricd listening (metrics)");
            Some(listener)
        }
        None => None,
    };

    #[cfg(unix)]
    run_listeners(
        uds.as_ref(),
        &uds_auth,
        quic.as_ref(),
        metrics.as_ref(),
        &shared,
    )
    .await;
    #[cfg(not(unix))]
    run_listeners(quic.as_ref(), metrics.as_ref(), &shared).await;

    // Clean up the socket file on a graceful exit.
    if let Some(path) = uds_path.as_deref() {
        drop(fs::remove_file(path));
    }
    info!("fabricd shut down");
    Ok(())
}

/// Loads [`FabricdConfig`] from `FABRICD_CONFIG` (default `fabricd.json`); a missing file yields
/// the empty default (no resources).
fn load_config() -> Result<FabricdConfig, Box<dyn Error + Send + Sync>> {
    let path = env::var("FABRICD_CONFIG").unwrap_or_else(|_err| "fabricd.json".to_owned());
    if !Path::new(&path).exists() {
        return Ok(FabricdConfig::default());
    }
    let text = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Builds the QUIC server endpoint from the listener config (parses the bind address, loads the
/// PEM cert/key, presents them with a pinned-cert-friendly TLS config).
///
/// # Errors
///
/// Returns an error if the listen address is malformed, the cert/key files can't be read/parsed, or
/// the UDP socket can't be bound.
fn build_quic_endpoint(cfg: &QuicListenerConfig) -> Result<Endpoint, Box<dyn Error + Send + Sync>> {
    let addr: SocketAddr = cfg.listen.parse()?;
    let cert_pem = fs::read(&cfg.server_cert)?;
    let key_pem = fs::read(&cfg.server_key)?;
    let tls = ServerTls::from_pem(&cert_pem, &key_pem)?;
    Ok(server_endpoint(addr, tls)?)
}

/// Runs the configured listener(s) until a shutdown signal. An absent listener parks forever
/// (`pending`), so `select!` resolves only on a live accept loop ending or the shutdown signal.
/// The UDS listener (and its authenticator) exists only on Unix.
async fn run_listeners(
    #[cfg(unix)] uds: Option<&UnixListener>,
    #[cfg(unix)] uds_auth: &Arc<dyn ClientAuthenticator>,
    quic: Option<&QuicListener>,
    metrics: Option<&TcpListener>,
    shared: &Arc<Shared>,
) {
    #[cfg(unix)]
    let uds_loop = async {
        match uds {
            Some(listener) => {
                if let Err(err) = uds_accept_loop(listener, shared, uds_auth).await {
                    warn!(error = %err, "uds accept loop ended");
                }
            }
            None => pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let uds_loop = pending::<()>();
    let quic_loop = async {
        match quic {
            Some((endpoint, authenticator, conn_limit)) => {
                quic_accept_loop(endpoint, shared, authenticator, conn_limit).await;
            }
            None => pending::<()>().await,
        }
    };
    let metrics_loop = async {
        match metrics {
            Some(listener) => metrics_accept_loop(listener, shared).await,
            None => pending::<()>().await,
        }
    };

    tokio::select! {
        () = uds_loop => {}
        () = quic_loop => {}
        () = metrics_loop => {}
        () = shutdown_signal() => info!("shutdown signal received"),
    }
}

/// Accepts metrics-scrape connections, answering each once (`GET /metrics`) on its own task.
/// An accept error stops the metrics listener but **parks** instead of returning — losing the
/// observability endpoint must never take down the egress listeners (the `select!` in
/// [`run_listeners`] treats a resolved loop as shutdown).
async fn metrics_accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let scrape_shared = Arc::clone(shared);
                drop(task::spawn(async move {
                    if let Err(err) = serve_metrics_once(stream, &scrape_shared).await {
                        debug!(error = %err, "metrics connection failed");
                    }
                }));
            }
            Err(err) => {
                warn!(error = %err, "metrics accept failed; metrics listener stopped");
                break;
            }
        }
    }
    pending::<()>().await;
}

/// Answers one HTTP exchange on `stream`: `GET /metrics` gets the Prometheus text exposition,
/// anything else a `404`. Just enough HTTP for a scrape — no framework, no TLS (the listener is
/// plaintext by contract; bind it loopback/pod-local).
async fn serve_metrics_once(mut stream: TcpStream, shared: &Shared) -> io::Result<()> {
    // One read is enough: a scrape's request head fits a packet, and only the request line matters.
    let mut buf = [0_u8; 1024];
    let read = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(buf.get(..read).unwrap_or(&[])).into_owned();
    let response = if is_metrics_request(&head) {
        let body = render_metrics(shared);
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned()
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Returns `true` when the request head's first line is a `GET /metrics` (any HTTP version).
fn is_metrics_request(head: &str) -> bool {
    head.lines()
        .next()
        .is_some_and(|line| line == "GET /metrics" || line.starts_with("GET /metrics "))
}

/// Renders the daemon's Prometheus text exposition: db breaker trips (Tier 3) and client-auth
/// rejections — the daemon-scoped counters that don't fit the per-session `Drain` metrics.
fn render_metrics(shared: &Shared) -> String {
    let trips = shared.breaker.as_ref().map_or(0, |breaker| breaker.trips());
    let auth_failures = shared.auth_failures.load(Ordering::Relaxed);
    format!(
        "# HELP fabricd_db_breaker_trips_total Cumulative db circuit-breaker open transitions (Tier 3).\n\
         # TYPE fabricd_db_breaker_trips_total counter\n\
         fabricd_db_breaker_trips_total {trips}\n\
         # HELP fabricd_auth_failures_total Cumulative client-auth rejections (a spike is a security signal).\n\
         # TYPE fabricd_auth_failures_total counter\n\
         fabricd_auth_failures_total {auth_failures}\n"
    )
}

/// Accepts UDS connections forever, spawning a per-connection session handler for each.
#[cfg(unix)]
async fn uds_accept_loop(
    listener: &UnixListener,
    shared: &Arc<Shared>,
    authenticator: &Arc<dyn ClientAuthenticator>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let session_shared = Arc::clone(shared);
        let session_auth = Arc::clone(authenticator);
        drop(task::spawn(async move {
            let (reader, writer) = stream.into_split();
            if let Err(err) = serve(reader, writer, &session_shared, session_auth.as_ref()).await {
                warn!(error = %err, "uds session ended with error");
            }
        }));
    }
}

/// Accepts QUIC connections until the endpoint closes, capping concurrency at `conn_limit`: each
/// accepted connection holds a permit for its lifetime, so the accept loop applies backpressure
/// once the ceiling is reached rather than admitting unbounded peers.
async fn quic_accept_loop(
    endpoint: &Endpoint,
    shared: &Arc<Shared>,
    authenticator: &Arc<dyn ClientAuthenticator>,
    conn_limit: &Arc<Semaphore>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(conn_limit).acquire_owned().await else {
            break; // the semaphore was closed — stop accepting
        };
        let session_shared = Arc::clone(shared);
        let session_auth = Arc::clone(authenticator);
        drop(task::spawn(async move {
            handle_quic_connection(incoming, &session_shared, &session_auth).await;
            drop(permit); // free the connection slot when the connection ends
        }));
    }
}

/// Completes one QUIC handshake, then serves each inbound bidirectional stream as its own session
/// (a box multiplexes one stream per request over the long-lived connection). Per-stream concurrency
/// is bounded by the transport's `max_concurrent_bidi_streams` cap (set in `runlet-wire`).
async fn handle_quic_connection(
    incoming: Incoming,
    shared: &Arc<Shared>,
    authenticator: &Arc<dyn ClientAuthenticator>,
) {
    let connection: Connection = match incoming.await {
        Ok(connection) => connection,
        Err(err) => {
            warn!(error = %err, "quic handshake failed");
            return;
        }
    };
    let peer = connection.remote_address();
    info!(%peer, "quic connection established");
    // Each inbound bi-stream is one session; the loop ends when the peer closes the connection
    // (or it idles out), which surfaces as an `Err` from `accept_bi`.
    while let Ok((send, recv)) = connection.accept_bi().await {
        let stream_shared = Arc::clone(shared);
        let stream_auth = Arc::clone(authenticator);
        drop(task::spawn(async move {
            // recv = inbound (reader), send = outbound (writer); one bi-stream = one session.
            if let Err(err) = serve(recv, send, &stream_shared, stream_auth.as_ref()).await {
                // A box dropping its stream after a completed session surfaces as a reset here —
                // expected, so log at debug, not warn.
                debug!(error = %err, "quic session stream ended");
            }
        }));
    }
}

/// Serves one session over any reader/writer pair (a UDS split or a QUIC bi-stream): read `Init`,
/// validate the client-auth token, resolve the selected names against the operator table, build the
/// `BackendSet`, then loop dispatching calls until the client closes (EOF).
async fn serve<R, W>(
    mut reader: R,
    mut writer: W,
    shared: &Shared,
    authenticator: &dyn ClientAuthenticator,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // The first frame must be `Init`; anything else is a protocol error.
    let init = match read_frame::<_, WireRequest>(&mut reader).await? {
        Some(WireRequest::Init(init)) => init,
        Some(WireRequest::Call(_) | WireRequest::Drain) => {
            write_frame(
                &mut writer,
                &WireResponse::ProtocolError("expected Init as the first frame".to_owned()),
            )
            .await?;
            return Ok(());
        }
        None => return Ok(()), // client connected then closed without a request
    };

    // Authenticate the client BEFORE touching the credential table. The token is a secret — never
    // log it. A rejection is reported as an `InitError` (the box maps it to a `400`).
    if let Err(reject) = authenticator.authenticate(init.token.as_deref()) {
        let total = shared.record_auth_failure();
        warn!(
            code = reject.code,
            auth_failures = total,
            "client auth rejected at session open"
        );
        write_frame(
            &mut writer,
            &WireResponse::InitError {
                code: reject.code.to_owned(),
                message: reject.message,
            },
        )
        .await?;
        return Ok(());
    }

    // The trust boundary: resolve the session's logical names against the operator table, scoped to
    // the session's trusted tenant (`init.tenant`). An unknown / out-of-tenant name or kind mismatch
    // is reported back so the box returns a `400`; a cross-tenant name resolves as `NotFound` so
    // existence never leaks across workspaces.
    let mut resolved = match resolve(&shared.table, &init) {
        Ok(resolved) => resolved,
        Err(err) => {
            write_frame(
                &mut writer,
                &WireResponse::InitError {
                    code: err.code().to_owned(),
                    message: err.message(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    resolved.clamp_db_statement_timeout(shared.max_statement_timeout_ms);

    let deps = AsyncDeps {
        handle: Handle::current(),
        // Daemon-global (Tier 3): the daemon owns the driver connections, so it owns the
        // connect breaker. The per-execution deadline (carried in `Init`) still bounds a
        // hung backend once connected.
        breaker: shared.breaker.clone(),
        timeout: Duration::from_millis(init.timeout_ms),
    };
    let backends = Arc::new(BackendSet::from_configs(&resolved, &deps));
    write_frame(&mut writer, &WireResponse::Ack).await?;

    while let Some(request) = read_frame::<_, WireRequest>(&mut reader).await? {
        let response = match request {
            WireRequest::Call(call) => dispatch(&backends, call).await,
            WireRequest::Drain => WireResponse::Metrics(Box::new(backends.metrics())),
            WireRequest::Init(_) => {
                WireResponse::ProtocolError("Init already received for this session".to_owned())
            }
        };
        write_frame(&mut writer, &response).await?;
    }
    Ok(())
}

/// Dispatches one call on a blocking thread. `BackendSet::call` drives the async drivers via
/// `Handle::block_on` internally, which must NOT run on a runtime worker — so it goes through
/// `spawn_blocking`. A task-join failure (a panic in the backend) becomes a protocol error.
async fn dispatch(backends: &Arc<BackendSet>, call: WireCall) -> WireResponse {
    let session = Arc::clone(backends);
    let joined =
        task::spawn_blocking(move || session.call(&call.name, &call.action, &call.payload)).await;
    match joined {
        Ok(result) => WireResponse::Reply(result),
        Err(join_err) => WireResponse::ProtocolError(format!("backend task failed: {join_err}")),
    }
}

/// Resolves when the process receives Ctrl+C or (on Unix) SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            warn!(error = %err, "failed to listen for Ctrl+C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                let _ = sig.recv().await;
            }
            Err(err) => warn!(error = %err, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    //! The metrics endpoint's request-line matching and text exposition.

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use runlet_wire::breaker::{BreakerConfig, CircuitBreaker};

    use super::{Shared, is_metrics_request, render_metrics};

    /// A `Shared` with no resources, an optional breaker, and a seeded auth-failure count.
    fn shared(breaker: Option<Arc<CircuitBreaker>>, auth_failures: u64) -> Shared {
        Shared {
            table: HashMap::new(),
            max_statement_timeout_ms: 0,
            breaker,
            auth_failures: AtomicU64::new(auth_failures),
        }
    }

    #[test]
    fn metrics_request_line_matches_get_metrics_only() {
        assert!(
            is_metrics_request("GET /metrics HTTP/1.1\r\nhost: x\r\n\r\n"),
            "a scrape request matches"
        );
        assert!(
            !is_metrics_request("GET / HTTP/1.1\r\n\r\n"),
            "other paths 404"
        );
        assert!(
            !is_metrics_request("POST /metrics HTTP/1.1\r\n\r\n"),
            "other methods 404"
        );
        assert!(
            !is_metrics_request("GET /metricsx HTTP/1.1\r\n\r\n"),
            "a path prefix does not match"
        );
    }

    #[test]
    fn renders_zero_trips_without_a_breaker() {
        let text = render_metrics(&shared(None, 0));
        assert!(
            text.contains("fabricd_db_breaker_trips_total 0"),
            "breaker off still exposes the series: {text}"
        );
        assert!(
            text.contains("fabricd_auth_failures_total 0"),
            "auth failures start at zero: {text}"
        );
    }

    #[test]
    fn renders_live_counters() {
        let breaker = CircuitBreaker::new(BreakerConfig {
            threshold: 1,
            cooldown: Duration::from_secs(60),
        })
        .map(Arc::new);
        let state = shared(breaker, 7);
        if let Some(cb) = state.breaker.as_ref() {
            cb.record("db:1", false); // threshold 1 → one failure trips it open
        }
        let text = render_metrics(&state);
        assert!(
            text.contains("fabricd_db_breaker_trips_total 1"),
            "a trip is counted: {text}"
        );
        assert!(
            text.contains("fabricd_auth_failures_total 7"),
            "auth failures render: {text}"
        );
    }
}
