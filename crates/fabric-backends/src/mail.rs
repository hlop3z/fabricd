//! SMTP `mail` client for the `QuickJS` sandbox.
//!
//! JS API: `mail.send({ from?, to, cc?, bcc?, reply_to?, subject, text?, html? })`.
//!
//! Trust model matches `db` (not `http`): the relay host + credentials are
//! operator-supplied in `config.mail`, so no SSRF / private-IP block is applied —
//! internal/self-hosted relays are intended to work. Each send is metered.

use std::error::Error;
use std::fmt::{self, Formatter};
use std::time::{Duration, Instant};

use lettre::message::{Mailbox, Message, MessageBuilder, MultiPart, SinglePart};
use lettre::transport::smtp::Error as SmtpError;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use serde::{Deserialize, Serialize};

use runlet_wire::metrics::{self as sandbox, Collector};
use runlet_wire::{EgressError, ErrorOwner, Fault, MailMetric};

/// Fallback fault for any mail error that isn't a classified SMTP reply.
const MAIL_FALLBACK: Fault = Fault::new("MAIL_ERROR", true, ErrorOwner::Operator);
/// Fault for exhausting the per-execution op budget mid-send.
const MAIL_OP_LIMIT: Fault = Fault::new("MAIL_OP_LIMIT", false, ErrorOwner::Developer);

/// A mail error carrying its classified [`Fault`] plus the raw message.
#[derive(Debug)]
pub struct MailError {
    /// Classified code + retry hint.
    fault: Fault,
    /// Raw driver/usage message.
    message: String,
}

impl MailError {
    /// Builds a fallback (`MAIL_ERROR`) error — used for non-SMTP failures (payload
    /// parsing, recipient validation, address parsing, message building).
    const fn fallback(message: String) -> Self {
        Self {
            fault: MAIL_FALLBACK,
            message,
        }
    }

    /// Classifies an SMTP send error by transient/permanent reply class.
    fn from_driver(err: &SmtpError) -> Self {
        Self {
            fault: classify(err),
            message: err.to_string(),
        }
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `mail`), preserving the classified code / retryable / owner.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "mail".to_owned(),
            details: None,
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// Maps an SMTP error to a [`Fault`] (docs/99-errors.md). A 4xx reply is
/// transient (retry); a 5xx reply is permanent; anything else (connect/TLS/IO) falls
/// back to the retryable `MAIL_ERROR`.
fn classify(err: &SmtpError) -> Fault {
    if err.is_transient() {
        Fault::new("MAIL_TRANSIENT", true, ErrorOwner::Operator)
    } else if err.is_permanent() {
        Fault::new("MAIL_PERMANENT", false, ErrorOwner::Developer)
    } else {
        MAIL_FALLBACK
    }
}

/// Transport security mode for the SMTP connection.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Upgrade a plaintext connection with STARTTLS (default; usually port 587).
    #[default]
    Starttls,
    /// Implicit TLS from the first byte (SMTPS; usually port 465).
    Wrapper,
    /// No transport security (plaintext — internal relays / testing only).
    None,
}

/// Per-request mail configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MailConfig {
    /// SMTP relay host.
    pub host: String,
    /// SMTP relay port (default 587).
    #[serde(default = "default_port")]
    pub port: u16,
    /// SMTP auth user (empty = no authentication).
    #[serde(default)]
    pub user: String,
    /// SMTP auth password.
    #[serde(default)]
    pub password: String,
    /// Transport security mode (default STARTTLS).
    #[serde(default)]
    pub tls: TlsMode,
    /// Default From address (used when a send omits `from`).
    pub from: String,
    /// Maximum recipients (to + cc + bcc) per send (default 50).
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    /// Recipient-domain allowlist: when non-empty, every recipient's domain (to/cc/bcc) must
    /// be in this list (case-insensitive). Empty (default) = unrestricted. Set it for
    /// untrusted scripts so a handler can't turn the operator's relay into an open spam cannon.
    #[serde(default)]
    pub allowed_recipient_domains: Vec<String>,
    /// Per-execution cap on `mail.send` calls. `0` (default) = bounded only by the global
    /// `max_ops` budget; when set, the effective cap is `min(max_sends, max_ops)`.
    #[serde(default)]
    pub max_sends: usize,
    /// Connect + send timeout in milliseconds (default 10000).
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// Default SMTP port.
const fn default_port() -> u16 {
    587
}
/// Default recipient cap.
const fn default_max_recipients() -> usize {
    50
}
/// Default timeout in milliseconds.
const fn default_timeout() -> u64 {
    10_000
}

/// Parsed payload for a `send` operation.
#[derive(Debug, Deserialize)]
struct SendPayload {
    /// From address (empty = use the configured default).
    #[serde(default)]
    from: String,
    /// To recipients.
    #[serde(default)]
    to: Vec<String>,
    /// Cc recipients.
    #[serde(default)]
    cc: Vec<String>,
    /// Bcc recipients.
    #[serde(default)]
    bcc: Vec<String>,
    /// Reply-To address (empty = none).
    #[serde(default)]
    reply_to: String,
    /// Subject line.
    #[serde(default)]
    subject: String,
    /// Plain-text body (empty = none).
    #[serde(default)]
    text: String,
    /// HTML body (empty = none).
    #[serde(default)]
    html: String,
}

/// Successful send result plus the stats needed to build a metric.
#[derive(Debug)]
struct SendOutcome {
    /// JSON returned to JS.
    json: String,
    /// Recipient count for the metric.
    recipients: usize,
    /// Serialized message size for the metric.
    bytes: usize,
    /// Whether the server accepted the message.
    accepted: bool,
}

/// Shared context for a single `send` call (keeps the closure arg count low).
struct SendCtx<'a> {
    /// The pre-built SMTP transport.
    transport: &'a SmtpTransport,
    /// Default From address.
    default_from: &'a str,
    /// Recipient cap.
    max_recipients: usize,
    /// Recipient-domain allowlist (empty = unrestricted).
    allowed_domains: &'a [String],
}

// -- Public API -------------------------------------------------------------

/// A `mail` backend: the pre-built SMTP transport plus send policy and its own metrics,
/// exposing a single [`call`](MailBackend::call).
///
/// The reusable dispatch core behind the in-process [`Egress`](runlet_wire::Egress)
/// adapter. Sync. See `docs/design/resource-egress.md`.
pub struct MailBackend {
    /// Pre-built SMTP transport (connects per send, internally).
    transport: SmtpTransport,
    /// Default From address.
    default_from: String,
    /// Recipient cap per send.
    max_recipients: usize,
    /// Recipient-domain allowlist (empty = unrestricted).
    allowed_domains: Vec<String>,
    /// Per-execution `send` cap (`0` = bounded only by the global `max_ops` seam).
    max_sends: usize,
    /// Per-operation metrics, drained by the consumer into `meta.mail_requests`.
    metrics: Collector<MailMetric>,
}

impl fmt::Debug for MailBackend {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailBackend")
            .field("max_recipients", &self.max_recipients)
            .field("max_sends", &self.max_sends)
            .finish_non_exhaustive()
    }
}

impl MailBackend {
    /// Builds the SMTP transport from config; a setup failure maps to a retryable
    /// `MAIL_ERROR` [`EgressError`].
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] if transport construction fails.
    pub fn connect_resource(config: &MailConfig) -> Result<Self, EgressError> {
        let transport = build_transport(config).map_err(|err| EgressError {
            code: MAIL_FALLBACK.code.to_owned(),
            message: err.to_string(),
            source: "mail".to_owned(),
            details: None,
            retryable: MAIL_FALLBACK.retryable,
            owner: MAIL_FALLBACK.owner,
        })?;
        Ok(Self {
            transport,
            default_from: config.from.clone(),
            max_recipients: config.max_recipients,
            allowed_domains: config.allowed_recipient_domains.clone(),
            max_sends: config.max_sends,
            metrics: sandbox::new_collector(),
        })
    }

    /// Runs one mail action, records a [`MailMetric`], and returns the result JSON. Enforces the
    /// mail-specific `max_sends` sub-cap (the global `max_ops` is enforced by the egress seam).
    ///
    /// # Errors
    ///
    /// Returns a [`MailError`] on a send/validation failure or when `max_sends` is exhausted.
    pub fn call(&self, action: &str, payload_json: &str) -> Result<String, MailError> {
        if self.max_sends != 0 && sandbox::op_count(&self.metrics) >= self.max_sends {
            return Err(MailError {
                fault: MAIL_OP_LIMIT,
                message: format!("too many mail.send calls: limit is {}", self.max_sends),
            });
        }
        let start = Instant::now();
        let send_ctx = SendCtx {
            transport: &self.transport,
            default_from: &self.default_from,
            max_recipients: self.max_recipients,
            allowed_domains: &self.allowed_domains,
        };
        let result = dispatch(&send_ctx, action, payload_json);
        sandbox::record(
            &self.metrics,
            build_metric(action, result.as_ref().ok(), start),
        );
        result.map(|outcome| outcome.json)
    }

    /// Drains (clones out) the metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<MailMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

// -- Dispatch ---------------------------------------------------------------

/// Routes a `__mail` call to the correct handler.
fn dispatch(
    send_ctx: &SendCtx<'_>,
    action: &str,
    payload_json: &str,
) -> Result<SendOutcome, MailError> {
    match action {
        "send" => do_send(send_ctx, payload_json),
        other => Err(MailError::fallback(format!("unknown mail action: {other}"))),
    }
}

// -- Transport --------------------------------------------------------------

/// Builds the SMTP transport from config.
fn build_transport(config: &MailConfig) -> Result<SmtpTransport, Box<dyn Error + Send + Sync>> {
    let base = match config.tls {
        TlsMode::Starttls => SmtpTransport::starttls_relay(&config.host)?,
        TlsMode::Wrapper => SmtpTransport::relay(&config.host)?,
        TlsMode::None => SmtpTransport::builder_dangerous(&config.host),
    };

    let mut builder = base
        .port(config.port)
        .timeout(Some(Duration::from_millis(config.timeout_ms)));

    if !config.user.is_empty() {
        let creds = Credentials::new(config.user.clone(), config.password.clone());
        builder = builder.credentials(creds);
    }

    Ok(builder.build())
}

// -- Send -------------------------------------------------------------------

/// Builds and sends an email, returning the outcome.
fn do_send(send_ctx: &SendCtx<'_>, payload_json: &str) -> Result<SendOutcome, MailError> {
    let payload: SendPayload = serde_json::from_str(payload_json)
        .map_err(|err| MailError::fallback(format!("invalid mail payload: {err}")))?;

    let recipients = count_recipients(&payload);
    if recipients == 0 {
        return Err(MailError::fallback(
            "at least one recipient (to/cc/bcc) is required".to_owned(),
        ));
    }
    if recipients > send_ctx.max_recipients {
        return Err(MailError::fallback(format!(
            "too many recipients: {recipients} (max {})",
            send_ctx.max_recipients
        )));
    }
    enforce_recipient_domains(&payload, send_ctx.allowed_domains)?;

    let message = build_message(&payload, send_ctx.default_from).map_err(MailError::fallback)?;
    let bytes = message.formatted().len();

    match send_ctx.transport.send(&message) {
        Ok(response) => {
            let accepted = response.is_positive();
            let line = response.first_line().unwrap_or("");
            let escaped = serde_json::to_string(line).unwrap_or_else(|_err| "\"\"".into());
            let json = format!("{{\"accepted\":{accepted},\"response\":{escaped}}}");
            Ok(SendOutcome {
                json,
                recipients,
                bytes,
                accepted,
            })
        }
        Err(err) => Err(MailError::from_driver(&err)),
    }
}

/// Rejects any recipient whose domain isn't in `allowed` (case-insensitive). An empty list
/// means no restriction. Addresses are parsed to extract the domain, so a malformed address
/// is reported here rather than later in message building.
fn enforce_recipient_domains(payload: &SendPayload, allowed: &[String]) -> Result<(), MailError> {
    if allowed.is_empty() {
        return Ok(());
    }
    for addr in payload.to.iter().chain(&payload.cc).chain(&payload.bcc) {
        let mailbox = parse_mailbox(addr, "recipient").map_err(MailError::fallback)?;
        let domain = mailbox.email.domain().to_lowercase();
        if !allowed.iter().any(|allow| allow.to_lowercase() == domain) {
            return Err(MailError::fallback(format!(
                "recipient domain '{domain}' is not in allowed_recipient_domains"
            )));
        }
    }
    Ok(())
}

/// Counts total recipients across to/cc/bcc (saturating).
const fn count_recipients(payload: &SendPayload) -> usize {
    payload
        .to
        .len()
        .saturating_add(payload.cc.len())
        .saturating_add(payload.bcc.len())
}

/// Builds the `Message` from a payload, validating every address.
fn build_message(payload: &SendPayload, default_from: &str) -> Result<Message, String> {
    let from_str = if payload.from.is_empty() {
        default_from
    } else {
        payload.from.as_str()
    };
    let mut builder = Message::builder().from(parse_mailbox(from_str, "from")?);

    for addr in &payload.to {
        builder = builder.to(parse_mailbox(addr, "to")?);
    }
    for addr in &payload.cc {
        builder = builder.cc(parse_mailbox(addr, "cc")?);
    }
    for addr in &payload.bcc {
        builder = builder.bcc(parse_mailbox(addr, "bcc")?);
    }
    if !payload.reply_to.is_empty() {
        builder = builder.reply_to(parse_mailbox(&payload.reply_to, "reply_to")?);
    }

    builder = builder.subject(payload.subject.as_str());
    build_body(builder, payload)
}

/// Parses a single mailbox, mapping failures to a clear error.
fn parse_mailbox(addr: &str, field: &str) -> Result<Mailbox, String> {
    addr.parse::<Mailbox>()
        .map_err(|err| format!("invalid {field} address '{addr}': {err}"))
}

/// Attaches the body (plain, html, or multipart/alternative) and finalizes.
fn build_body(builder: MessageBuilder, payload: &SendPayload) -> Result<Message, String> {
    let has_text = !payload.text.is_empty();
    let has_html = !payload.html.is_empty();

    let built = if has_text && has_html {
        builder.multipart(MultiPart::alternative_plain_html(
            payload.text.clone(),
            payload.html.clone(),
        ))
    } else if has_html {
        builder.singlepart(SinglePart::html(payload.html.clone()))
    } else {
        builder.body(payload.text.clone())
    };

    built.map_err(|err| format!("failed to build message: {err}"))
}

// -- Metrics ----------------------------------------------------------------

/// Builds a `MailMetric` from the outcome (or zeros on failure).
fn build_metric(action: &str, outcome: Option<&SendOutcome>, start: Instant) -> MailMetric {
    let (recipients, bytes, accepted) = outcome.map_or((0, 0, false), |out| {
        (out.recipients, out.bytes, out.accepted)
    });

    MailMetric {
        action: action.into(),
        duration_us: start.elapsed().as_micros(),
        recipients,
        bytes,
        accepted,
    }
}

#[cfg(test)]
mod tests {
    //! Recipient-domain allowlist enforcement (the spam-cannon control).

    use super::{SendPayload, enforce_recipient_domains};

    /// A payload with the given `to` / `cc` recipients and everything else empty.
    fn payload(to: &[&str], cc: &[&str]) -> SendPayload {
        SendPayload {
            from: String::new(),
            to: to.iter().map(|addr| (*addr).to_owned()).collect(),
            cc: cc.iter().map(|addr| (*addr).to_owned()).collect(),
            bcc: Vec::new(),
            reply_to: String::new(),
            subject: String::new(),
            text: String::new(),
            html: String::new(),
        }
    }

    /// An allowlist from string literals.
    fn allow(domains: &[&str]) -> Vec<String> {
        domains.iter().map(|dom| (*dom).to_owned()).collect()
    }

    /// An empty allowlist places no restriction on recipients.
    #[test]
    fn empty_allowlist_permits_any_domain() {
        assert!(
            enforce_recipient_domains(&payload(&["user@anywhere.example"], &[]), &[]).is_ok(),
            "empty allowlist is unrestricted"
        );
    }

    /// An allowed domain passes, matched case-insensitively.
    #[test]
    fn allowed_domain_passes_case_insensitively() {
        let allowed = allow(&["example.com"]);
        assert!(
            enforce_recipient_domains(&payload(&["user@example.com"], &[]), &allowed).is_ok(),
            "exact domain allowed"
        );
        assert!(
            enforce_recipient_domains(&payload(&["user@EXAMPLE.COM"], &[]), &allowed).is_ok(),
            "case-insensitive domain allowed"
        );
    }

    /// An off-list recipient (in any of to/cc/bcc) rejects the whole send.
    #[test]
    fn disallowed_domain_is_rejected() {
        let allowed = allow(&["example.com"]);
        assert!(
            enforce_recipient_domains(&payload(&["user@evil.example"], &[]), &allowed).is_err(),
            "off-list domain rejected"
        );
        assert!(
            enforce_recipient_domains(
                &payload(&["ok@example.com"], &["bad@evil.example"]),
                &allowed
            )
            .is_err(),
            "a single off-list cc rejects the whole send"
        );
    }

    /// A recipient that doesn't parse as an address is rejected under an allowlist.
    #[test]
    fn malformed_address_is_rejected_under_allowlist() {
        let allowed = allow(&["example.com"]);
        assert!(
            enforce_recipient_domains(&payload(&["not-an-email"], &[]), &allowed).is_err(),
            "unparseable recipient rejected"
        );
    }
}
