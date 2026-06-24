//! `fabricd`: the local egress sidecar for runlet.
//!
//! Hosts [`fabric_backends::BackendSet`] behind a Unix-domain-socket wire protocol
//! ([`fabric_backends::wire`]). One client connection = one box-request session: the client sends
//! a [`WireRequest::Init`] (the resolved operator configs + deadline), the daemon builds a fresh
//! `BackendSet` (lazy per-backend connect, so a transaction's `begin`→`commit` reuse one client),
//! then dispatches each [`WireRequest::Call`] and answers [`WireRequest::Drain`] with the metrics.
//! On EOF the `BackendSet` drops, tearing down its driver connections.
//!
//! The daemon links the network drivers (via `fabric-backends`) so the sandbox box does not — see
//! `docs/design/resource-egress.md` step 4b.

use std::env;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use fabric_backends::wire::{WireCall, WireRequest, WireResponse, read_frame, write_frame};
use fabric_backends::{AsyncDeps, BackendSet};
use fabric_wire::Egress as _;
use rustls::crypto::aws_lc_rs;
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::Handle;
use tokio::task;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::fmt::init as init_tracing;

/// Default socket path when `FABRICD_SOCKET` is unset.
const DEFAULT_SOCKET: &str = "/tmp/fabricd.sock";

/// Entry point — binds the UDS and serves connections until a shutdown signal.
///
/// # Errors
///
/// Returns an error if the socket cannot be bound.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    init_tracing();

    // Install `aws-lc-rs` as the single rustls provider (db SSL / rediss / amqps reuse it). The
    // drivers live here now, so the daemon — not the box — installs it.
    if aws_lc_rs::default_provider().install_default().is_err() {
        warn!("rustls crypto provider was already installed");
    }

    let socket_path = env::var("FABRICD_SOCKET").unwrap_or_else(|_err| DEFAULT_SOCKET.to_owned());

    // A stale socket file from a previous run would make `bind` fail with EADDRINUSE; remove it
    // best-effort first (a genuine permission error surfaces at `bind`).
    drop(fs::remove_file(&socket_path));

    let listener = UnixListener::bind(&socket_path)?;
    info!(socket = %socket_path, "fabricd listening");

    tokio::select! {
        result = accept_loop(&listener) => {
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

/// Accepts connections forever, spawning a per-connection session handler for each.
async fn accept_loop(listener: &UnixListener) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        drop(task::spawn(async move {
            if let Err(err) = serve(stream).await {
                warn!(error = %err, "session ended with error");
            }
        }));
    }
}

/// Serves one session: read `Init`, build the `BackendSet`, then loop dispatching calls until the
/// client closes the connection (clean EOF).
async fn serve(stream: UnixStream) -> Result<(), Box<dyn Error + Send + Sync>> {
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

    let deps = AsyncDeps {
        handle: Handle::current(),
        // The breaker is box-side resilience today; the daemon relies on the per-execution
        // deadline (carried in `Init`) to bound a hung backend. Step 5 may move a breaker here.
        breaker: None,
        timeout: Duration::from_millis(init.timeout_ms),
    };
    let backends = Arc::new(BackendSet::from_init(&init, &deps));
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
