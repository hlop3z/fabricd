//! The `fabricd` wire protocol: length-prefixed JSON frames over a byte stream (UDS).
//!
//! One box-request maps to one connection ("session"): the box sends a [`WireInit`] (the resolved
//! operator configs + the per-execution deadline), then a [`WireCall`] per `io.call(...)`, then a
//! `Drain` to collect the metrics, then closes. The daemon builds one
//! [`BackendSet`](crate::BackendSet) per connection (lazy per-backend connect, so a transaction's
//! `begin`→`commit` reuse the same client), dispatches each call, and drops it on EOF.
//!
//! Error contract reuse: a call failure rides back as the same
//! [`EgressError`](fabric_wire::EgressError) the in-process path produces — the engine's existing
//! `__jsbox` classification consumes it unchanged.

use std::io::{Error as IoError, ErrorKind};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use fabric_wire::EgressError;

use crate::amq::{AmqConfig, AmqMetric};
use crate::auth::{AuthConfig, AuthMetric};
use crate::db::{DbConfig, DbMetric};
use crate::kv::{RedisConfig, RedisMetric};
use crate::mail::{MailConfig, MailMetric};
use crate::mongo::{MongoConfig, MongoMetric};

/// Hard cap on a single frame's payload (64 MiB) — a malformed/hostile length never allocates
/// without bound.
const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// The session-open message: the operator configs the daemon should wire + the deadline.
///
/// Each `Some` field becomes a lazily-connected backend; `None` leaves that capability
/// unconfigured (a call to it is `*_NOT_CONFIGURED`). `timeout_ms` is the per-execution wall-clock
/// budget (the per-query/op client-side deadline).
#[derive(Debug, Default, Clone, Serialize, serde::Deserialize)]
pub struct WireInit {
    /// `db` connection config.
    #[serde(default)]
    pub db: Option<DbConfig>,
    /// `mongo` connection config.
    #[serde(default)]
    pub mongo: Option<MongoConfig>,
    /// `mail` config.
    #[serde(default)]
    pub mail: Option<MailConfig>,
    /// `redis` config.
    #[serde(default)]
    pub redis: Option<RedisConfig>,
    /// `amq` config.
    #[serde(default)]
    pub amq: Option<AmqConfig>,
    /// `auth` config.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// Per-execution wall-clock budget in milliseconds (the per-op client-side deadline).
    pub timeout_ms: u64,
}

/// One egress call: capability kind, action, and the script's JSON payload.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct WireCall {
    /// Capability kind (`"db"`, `"mongo"`, …).
    pub name: String,
    /// Action (`"query"`, `"send"`, …).
    pub action: String,
    /// The script's JSON-encoded arguments (untrusted).
    pub payload: String,
}

/// A request frame from the box to the daemon.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum WireRequest {
    /// Open the session with the operator configs + deadline (sent once, first).
    Init(Box<WireInit>),
    /// Perform one egress call.
    Call(WireCall),
    /// Drain the per-capability metrics accumulated this session (sent last).
    Drain,
}

/// A response frame from the daemon to the box.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum WireResponse {
    /// Acknowledges [`WireRequest::Init`].
    Ack,
    /// The result of a [`WireRequest::Call`] — the backend JSON, or the classified egress error
    /// (which the engine renders into the `__jsbox` tag exactly as for an in-process call).
    Reply(Result<String, EgressError>),
    /// The drained per-capability metrics, answering [`WireRequest::Drain`].
    Metrics(Box<BackendMetrics>),
    /// A protocol-level failure (e.g. a `Call` before `Init`), carrying a human-safe message.
    ProtocolError(String),
}

/// The driver-backed capability metrics drained from one session.
///
/// Produced by [`BackendSet::metrics`](crate::BackendSet::metrics) (in-process) or carried back in
/// [`WireResponse::Metrics`] (sidecar); the consumer merges these into the response
/// `meta.<cap>_requests`. `http`/`s3` stay in-engine and are not here.
#[derive(Debug, Default, Clone, Serialize, serde::Deserialize)]
pub struct BackendMetrics {
    /// `db` operation metrics.
    pub db: Vec<DbMetric>,
    /// `mongo` operation metrics.
    pub mongo: Vec<MongoMetric>,
    /// `mail` operation metrics.
    pub mail: Vec<MailMetric>,
    /// `redis` operation metrics.
    pub redis: Vec<RedisMetric>,
    /// `amq` operation metrics.
    pub amq: Vec<AmqMetric>,
    /// `auth` operation metrics.
    pub auth: Vec<AuthMetric>,
}

/// Writes one length-prefixed JSON frame (`u32` LE length + the JSON bytes) and flushes.
///
/// # Errors
///
/// Returns an I/O error on a serialization failure, an oversized frame, or a write failure.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), IoError>
where
    W: AsyncWrite + Unpin + Send,
    T: Serialize + Sync + ?Sized,
{
    let bytes =
        serde_json::to_vec(value).map_err(|err| IoError::new(ErrorKind::InvalidData, err))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_err| IoError::new(ErrorKind::InvalidData, "frame too large to encode"))?;
    if len > MAX_FRAME_BYTES {
        return Err(IoError::new(ErrorKind::InvalidData, "frame exceeds size cap"));
    }
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one length-prefixed JSON frame. Returns `Ok(None)` on a clean EOF at a frame boundary
/// (the peer closed the session), `Ok(Some(value))` otherwise.
///
/// # Errors
///
/// Returns an I/O error on a truncated frame, an over-cap length, or a deserialization failure.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, IoError>
where
    R: AsyncRead + Unpin + Send,
    T: DeserializeOwned,
{
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_n) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(IoError::new(ErrorKind::InvalidData, "frame exceeds size cap"));
    }
    let size = usize::try_from(len)
        .map_err(|_err| IoError::new(ErrorKind::InvalidData, "frame length out of range"))?;
    let mut buf = vec![0_u8; size];
    let _ = reader.read_exact(&mut buf).await?;
    let value = serde_json::from_slice(&buf)
        .map_err(|err| IoError::new(ErrorKind::InvalidData, err))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    //! Frame round-trip over an in-memory duplex stream, plus the clean-EOF signal.

    use super::{BackendMetrics, WireCall, WireRequest, WireResponse, read_frame, write_frame};
    use fabric_wire::{EgressError, ErrorOwner};

    /// A request frame written then read back is byte-for-byte equivalent (checked structurally).
    #[tokio::test]
    async fn request_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let sent = WireRequest::Call(WireCall {
            name: "db".to_owned(),
            action: "query".to_owned(),
            payload: r#"{"sql":"SELECT 1"}"#.to_owned(),
        });
        write_frame(&mut a, &sent)
            .await
            .unwrap_or_else(|_err| unreachable!("write"));
        let got: WireRequest = read_frame(&mut b)
            .await
            .unwrap_or_else(|_err| unreachable!("read"))
            .unwrap_or_else(|| unreachable!("a frame"));
        match got {
            WireRequest::Call(call) => {
                assert_eq!(call.name, "db");
                assert_eq!(call.action, "query");
            }
            WireRequest::Init(_) | WireRequest::Drain => unreachable!("expected a Call"),
        }
    }

    /// An `EgressError` survives the `WireResponse::Reply` round-trip with its fields intact.
    #[tokio::test]
    async fn error_reply_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let err = EgressError::new("db", "DB_TIMEOUT", "boom")
            .retryable()
            .owner(ErrorOwner::Operator);
        write_frame(&mut a, &WireResponse::Reply(Err(err)))
            .await
            .unwrap_or_else(|_err| unreachable!("write"));
        let got: WireResponse = read_frame(&mut b)
            .await
            .unwrap_or_else(|_err| unreachable!("read"))
            .unwrap_or_else(|| unreachable!("a frame"));
        match got {
            WireResponse::Reply(Err(egress)) => {
                assert_eq!(egress.code, "DB_TIMEOUT");
                assert_eq!(egress.source, "db");
                assert!(egress.retryable);
            }
            WireResponse::Ack
            | WireResponse::Reply(Ok(_))
            | WireResponse::Metrics(_)
            | WireResponse::ProtocolError(_) => unreachable!("expected an error reply"),
        }
    }

    /// Reading at a clean frame boundary after the writer drops yields `Ok(None)`.
    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, mut b) = tokio::io::duplex(1024);
        drop(a);
        let got: Option<WireResponse> = read_frame(&mut b)
            .await
            .unwrap_or_else(|_err| unreachable!("read"));
        assert!(got.is_none(), "clean EOF returns None");
        // An empty BackendMetrics is the natural default, referenced to keep the import used.
        assert!(BackendMetrics::default().db.is_empty());
    }
}
