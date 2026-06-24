//! `fabricd`: the local egress sidecar for runlet.
//!
//! Hosts [`fabric_backends::BackendSet`] behind a Unix-domain-socket wire protocol
//! ([`fabric_wire::wire`]). The daemon owns the operator credential table: the box sends only
//! logical resource *names* (a `WireInit`), and `fabricd` resolves them against its `resources`
//! config. One client connection = one box-request session: the client sends `Init` (selected
//! names + deadline), the daemon resolves + builds a fresh `BackendSet` (lazy per-backend connect,
//! so a transaction's `begin`→`commit` reuse one client), then dispatches each `Call` and answers
//! `Drain` with the metrics. On EOF the `BackendSet` drops, tearing down its driver connections.
//!
//! The daemon links the network drivers (via `fabric-backends`) so the sandbox box does not — see
//! `docs/design/resource-egress.md` step 5.

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fabric_backends::{AsyncDeps, BackendSet, ResourceBinding, resolve};
use fabric_wire::Egress as _;
use fabric_wire::wire::{WireCall, WireRequest, WireResponse, read_frame, write_frame};
use rustls::crypto::aws_lc_rs;
use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::Handle;
use tokio::signal;
use tokio::task;
use tracing::{info, warn};
use tracing_subscriber::fmt::init as init_tracing;

/// Default socket path when neither config nor `FABRICD_SOCKET` sets one.
const DEFAULT_SOCKET: &str = "/tmp/fabricd.sock";

/// Daemon configuration, loaded from the `FABRICD_CONFIG` path (default `fabricd.json`).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FabricdConfig {
    /// Socket path to bind (env `FABRICD_SOCKET` overrides; else `DEFAULT_SOCKET`).
    socket: Option<String>,
    /// The operator credential table: logical name → driver binding. The box never sees these.
    resources: HashMap<String, ResourceBinding>,
    /// Tier-0 ceiling on a `db` resource's `statement_timeout_ms` (`0` = no clamp).
    max_statement_timeout_ms: u64,
}

/// Shared, read-only daemon state handed to each connection.
#[derive(Debug)]
struct Shared {
    /// Operator credential table.
    table: HashMap<String, ResourceBinding>,
    /// `db` statement-timeout ceiling (Tier 0).
    max_statement_timeout_ms: u64,
}

/// Entry point — loads config, binds the UDS, and serves connections until a shutdown signal.
///
/// # Errors
///
/// Returns an error if the config can't be read/parsed or the socket can't be bound.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    init_tracing();

    // Install `aws-lc-rs` as the single rustls provider (db SSL / rediss / amqps reuse it). The
    // drivers live here now, so the daemon — not the box — installs it.
    if aws_lc_rs::default_provider().install_default().is_err() {
        warn!("rustls crypto provider was already installed");
    }

    let config = load_config()?;
    let socket_path = env::var("FABRICD_SOCKET")
        .ok()
        .or(config.socket)
        .unwrap_or_else(|| DEFAULT_SOCKET.to_owned());
    let shared = Arc::new(Shared {
        table: config.resources,
        max_statement_timeout_ms: config.max_statement_timeout_ms,
    });
    info!(
        socket = %socket_path,
        resources = shared.table.len(),
        "fabricd configuration loaded"
    );

    // A stale socket file from a previous run would make `bind` fail with EADDRINUSE; remove it
    // best-effort first (a genuine permission error surfaces at `bind`).
    drop(fs::remove_file(&socket_path));

    let listener = UnixListener::bind(&socket_path)?;
    info!(socket = %socket_path, "fabricd listening");

    tokio::select! {
        result = accept_loop(&listener, &shared) => {
            if let Err(err) = result {
                warn!(error = %err, "accept loop ended");
            }
        }
        () = shutdown_signal() => info!("shutdown signal received"),
    }

    // Clean up the socket file on a graceful exit.
    drop(fs::remove_file(&socket_path));
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

/// Accepts connections forever, spawning a per-connection session handler for each.
async fn accept_loop(
    listener: &UnixListener,
    shared: &Arc<Shared>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let session_shared = Arc::clone(shared);
        drop(task::spawn(async move {
            if let Err(err) = serve(stream, &session_shared).await {
                warn!(error = %err, "session ended with error");
            }
        }));
    }
}

/// Serves one session: read `Init`, resolve the selected names against the operator table, build
/// the `BackendSet`, then loop dispatching calls until the client closes the connection (EOF).
async fn serve(stream: UnixStream, shared: &Shared) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (mut reader, mut writer) = stream.into_split();

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

    // The trust boundary: resolve the session's logical names against the operator table. An
    // unknown name or kind mismatch is reported back so the box returns a `400`.
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
        // The breaker is box-side resilience today; the daemon relies on the per-execution
        // deadline (carried in `Init`) to bound a hung backend.
        breaker: None,
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
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
