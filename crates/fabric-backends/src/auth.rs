//! OIDC / IAM identity capability for the `QuickJS` sandbox.
//!
//! JS API: `auth.user_info(token)` and `auth.introspect(token)`.
//!
//! Trust model matches `db`/`mail` (not `http`): the issuer + endpoints are
//! **operator-supplied** in `config.auth`, so no SSRF / private-IP block is applied —
//! the client's bearer token is just a string placed into the `Authorization` header
//! toward the operator-named host. Validation is delegated to the IAM: a `GET
//! {userinfo}` round-trip is the validation oracle (no local JWT/JWKS crypto).
//!
//! Hybrid error surface (docs/99-errors.md): a token-validity outcome is the
//! **caller's** business flow, so an invalid/expired token returns **in-band**
//! (`{ ok: false, status }`, never thrown — like `api`). Infra failures the handler
//! can't act on (issuer down, misconfig) **throw** a tagged capability error (like
//! `db`/`mail`). Each call is metered.

use std::fmt::{self, Formatter};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use fabric_wire::metrics::{self as sandbox, Collector};
use fabric_wire::{AuthMetric, EgressError, ErrorOwner, Fault};

/// Issuer unreachable / 5xx / timeout — transient, page ops.
const AUTH_UNAVAILABLE: Fault = Fault::new("AUTH_UNAVAILABLE", true, ErrorOwner::Operator);
/// Deterministic request failure (misconfig, bad endpoint, unexpected status).
const AUTH_REQUEST: Fault = Fault::new("AUTH_REQUEST", false, ErrorOwner::Operator);

/// Default connect + read timeout in milliseconds.
const fn default_timeout() -> u64 {
    10_000
}

/// Per-request auth configuration (operator-supplied, trusted).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    /// OIDC issuer base URL (used for discovery + the metric host).
    pub issuer: String,
    /// Explicit userinfo endpoint (skips discovery when set).
    #[serde(default)]
    pub userinfo_url: Option<String>,
    /// Explicit introspection endpoint (skips discovery when set).
    #[serde(default)]
    pub introspect_url: Option<String>,
    /// OAuth client id for introspection Basic auth (empty = introspect disabled).
    #[serde(default)]
    pub client_id: String,
    /// OAuth client secret for introspection Basic auth.
    #[serde(default)]
    pub client_secret: String,
    /// Connect + read timeout in milliseconds (default 10000).
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// Endpoints resolved from OIDC discovery (each absent if the issuer omits it).
#[derive(Debug, Clone)]
struct Endpoints {
    /// `userinfo_endpoint` from the discovery document.
    userinfo: Option<String>,
    /// `introspection_endpoint` from the discovery document.
    introspect: Option<String>,
}

/// An auth error carrying its classified [`Fault`], a raw message, and optional details.
#[derive(Debug)]
pub struct AuthError {
    /// Classified code + retry hint.
    fault: Fault,
    /// Raw cause (surfaced gated, in `debug.raw`).
    message: String,
    /// Structured machine context (e.g. `{http_status}`).
    details: Option<Value>,
}

impl AuthError {
    /// Builds an error with no structured details.
    const fn new(fault: Fault, message: String) -> Self {
        Self {
            fault,
            message,
            details: None,
        }
    }

    /// Builds an error tagged with the upstream HTTP status.
    fn with_status(fault: Fault, message: &str, status: u16) -> Self {
        Self {
            fault,
            message: format!("{message} (status {status})"),
            details: Some(json!({ "http_status": status })),
        }
    }

    /// Classifies a `reqwest` transport error as a (retryable) availability failure.
    fn from_transport(err: &reqwest::Error) -> Self {
        Self::new(AUTH_UNAVAILABLE, format!("auth request failed: {err}"))
    }

    /// Converts into the capability-agnostic [`EgressError`] for the egress seam (source
    /// `auth`), preserving the classified code / retryable / owner and the structured details.
    #[must_use]
    pub fn into_resource_error(self) -> EgressError {
        EgressError {
            code: self.fault.code.to_owned(),
            message: self.message,
            source: "auth".to_owned(),
            details: self.details.map(Box::new),
            retryable: self.fault.retryable,
            owner: self.fault.owner,
        }
    }
}

/// In-band success/invalid result of one call: the JSON returned to JS + its status.
#[derive(Debug)]
struct AuthOutcome {
    /// JSON string the wrapper returns verbatim.
    json: String,
    /// IAM HTTP status (for the metric).
    status: u16,
}

/// Request-scoped auth runtime captured by the native closure.
///
/// Owns the blocking client + resolved config and memoizes OIDC discovery for the
/// life of the request (the closure is rebuilt per request, so this is never shared
/// across requests — keeping every instance stateless and interchangeable).
struct AuthState {
    /// Blocking HTTP client (no SSRF guard — trusted operator target).
    client: Client,
    /// Operator config.
    config: AuthConfig,
    /// Memoized discovery result (request-scoped).
    discovery: Mutex<Option<Endpoints>>,
}

// -- Public API -------------------------------------------------------------

/// An `auth` backend: the blocking client + resolved config (with request-scoped discovery
/// memo) plus its own metrics, exposing a single [`call`](AuthBackend::call).
///
/// The reusable dispatch core behind the in-process [`Egress`](fabric_wire::Egress)
/// adapter. Sync. See `docs/design/resource-egress.md`.
pub struct AuthBackend {
    /// Shared auth runtime (client + config + request-scoped discovery memo).
    state: AuthState,
    /// Issuer host (for the metric; no path/query).
    host: String,
    /// Per-operation metrics, drained by the consumer into `meta.auth_requests`.
    metrics: Collector<AuthMetric>,
}

impl fmt::Debug for AuthBackend {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthBackend")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl AuthBackend {
    /// Builds the blocking HTTP client; a build failure maps to a retryable `AUTH_UNAVAILABLE`
    /// [`EgressError`].
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] if client construction fails.
    pub fn connect_resource(config: &AuthConfig) -> Result<Self, EgressError> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|err| EgressError {
                code: AUTH_UNAVAILABLE.code.to_owned(),
                message: format!("auth client build failed: {err}"),
                source: "auth".to_owned(),
                details: None,
                retryable: AUTH_UNAVAILABLE.retryable,
                owner: AUTH_UNAVAILABLE.owner,
            })?;
        Ok(Self {
            host: issuer_host(&config.issuer),
            state: AuthState {
                client,
                config: config.clone(),
                discovery: Mutex::new(None),
            },
            metrics: sandbox::new_collector(),
        })
    }

    /// Runs one auth action (`user_info`/`introspect`), records an [`AuthMetric`], and returns
    /// the result JSON. An invalid/expired token is **in-band** (`Ok` with `{ok:false}`); infra
    /// failures are an `Err` the seam surfaces as a thrown capability error.
    ///
    /// # Errors
    ///
    /// Returns a [`EgressError`] for an infra failure (issuer down / misconfig / bad status).
    pub fn call(&self, action: &str, token: &str) -> Result<String, EgressError> {
        let start = Instant::now();
        let result = dispatch(&self.state, action, token);
        let status = result.as_ref().map_or(0, |outcome| outcome.status);
        sandbox::record(
            &self.metrics,
            build_metric(action, &self.host, status, start),
        );
        result
            .map(|outcome| outcome.json)
            .map_err(AuthError::into_resource_error)
    }

    /// Drains (clones out) the metrics recorded so far.
    #[must_use]
    pub fn drain_metrics(&self) -> Vec<AuthMetric> {
        sandbox::drain(Some(&self.metrics))
    }
}

/// Routes a `__auth` call to the correct handler.
fn dispatch(state: &AuthState, action: &str, token: &str) -> Result<AuthOutcome, AuthError> {
    match action {
        "user_info" => do_user_info(state, token),
        "introspect" => do_introspect(state, token),
        other => Err(AuthError::new(
            AUTH_REQUEST,
            format!("unknown auth action: {other}"),
        )),
    }
}

// -- user_info --------------------------------------------------------------

/// `GET {userinfo}` with `Authorization: Bearer <token>`. A 401/403 is the caller's
/// invalid token → in-band; 5xx/transport → throw `AUTH_UNAVAILABLE`; other → throw.
fn do_user_info(state: &AuthState, token: &str) -> Result<AuthOutcome, AuthError> {
    let url = state.resolve_userinfo()?;
    let (status, body) = send(state.client.get(&url).bearer_auth(token))?;

    if (200..=299).contains(&status) {
        return Ok(AuthOutcome {
            json: ok_claims_json(&parse_claims(&body, status)?),
            status,
        });
    }
    if status == 401 || status == 403 {
        return Ok(AuthOutcome {
            json: invalid_token_json(status),
            status,
        });
    }
    if (500..=599).contains(&status) {
        return Err(AuthError::with_status(
            AUTH_UNAVAILABLE,
            "userinfo unavailable",
            status,
        ));
    }
    Err(AuthError::with_status(
        AUTH_REQUEST,
        "userinfo request failed",
        status,
    ))
}

// -- introspect -------------------------------------------------------------

/// RFC 7662 `POST {introspect}` (Basic-auth client creds, `token=` form). Always
/// `{ ok: true, claims }` on 2xx (the script reads `claims.active`); non-2xx throws.
fn do_introspect(state: &AuthState, token: &str) -> Result<AuthOutcome, AuthError> {
    if state.config.client_id.is_empty() {
        return Err(AuthError::new(
            AUTH_REQUEST,
            "introspect requires config.auth.client_id/client_secret".to_owned(),
        ));
    }
    let url = state.resolve_introspect()?;
    // Build the `application/x-www-form-urlencoded` body by hand: reqwest's `.form()`
    // helper isn't compiled in with our reduced feature set.
    let form_body = format!("token={}", utf8_percent_encode(token, NON_ALPHANUMERIC));
    let request = state
        .client
        .post(&url)
        .basic_auth(&state.config.client_id, Some(&state.config.client_secret))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body);
    let (status, body) = send(request)?;

    if (200..=299).contains(&status) {
        return Ok(AuthOutcome {
            json: ok_claims_json(&parse_claims(&body, status)?),
            status,
        });
    }
    if (500..=599).contains(&status) {
        return Err(AuthError::with_status(
            AUTH_UNAVAILABLE,
            "introspection unavailable",
            status,
        ));
    }
    Err(AuthError::with_status(
        AUTH_REQUEST,
        "introspection request failed",
        status,
    ))
}

// -- Endpoint resolution (explicit override → OIDC discovery) ----------------

impl AuthState {
    /// Resolves the userinfo endpoint: explicit override, else discovery.
    fn resolve_userinfo(&self) -> Result<String, AuthError> {
        if let Some(url) = self.config.userinfo_url.as_ref() {
            return Ok(url.clone());
        }
        self.discover()?.userinfo.ok_or_else(|| {
            AuthError::new(
                AUTH_REQUEST,
                "issuer exposes no userinfo_endpoint".to_owned(),
            )
        })
    }

    /// Resolves the introspection endpoint: explicit override, else discovery.
    fn resolve_introspect(&self) -> Result<String, AuthError> {
        if let Some(url) = self.config.introspect_url.as_ref() {
            return Ok(url.clone());
        }
        self.discover()?.introspect.ok_or_else(|| {
            AuthError::new(
                AUTH_REQUEST,
                "issuer exposes no introspection_endpoint".to_owned(),
            )
        })
    }

    /// Returns the memoized discovery result, fetching it once per request if needed.
    fn discover(&self) -> Result<Endpoints, AuthError> {
        if let Ok(guard) = self.discovery.lock()
            && let Some(endpoints) = guard.as_ref()
        {
            return Ok(endpoints.clone());
        }
        let endpoints = self.fetch_discovery()?;
        if let Ok(mut guard) = self.discovery.lock() {
            *guard = Some(endpoints.clone());
        }
        Ok(endpoints)
    }

    /// `GET {issuer}/.well-known/openid-configuration` → parsed [`Endpoints`].
    fn fetch_discovery(&self) -> Result<Endpoints, AuthError> {
        let base = self.config.issuer.trim_end_matches('/');
        let url = format!("{base}/.well-known/openid-configuration");
        let (status, body) = send(self.client.get(&url))?;
        if !(200..=299).contains(&status) {
            return Err(AuthError::with_status(
                AUTH_REQUEST,
                "OIDC discovery failed",
                status,
            ));
        }
        let doc: Value = serde_json::from_str(&body).map_err(|err| {
            AuthError::new(AUTH_REQUEST, format!("invalid discovery document: {err}"))
        })?;
        Ok(Endpoints {
            userinfo: string_field(&doc, "userinfo_endpoint"),
            introspect: string_field(&doc, "introspection_endpoint"),
        })
    }
}

// -- HTTP + JSON helpers ----------------------------------------------------

/// Sends a prepared request, returning `(status, body)` or a classified error.
fn send(builder: RequestBuilder) -> Result<(u16, String), AuthError> {
    let response = builder
        .send()
        .map_err(|err| AuthError::from_transport(&err))?;
    let status = response.status().as_u16();
    let body = response.text().map_err(|err| {
        AuthError::new(AUTH_UNAVAILABLE, format!("failed to read response: {err}"))
    })?;
    Ok((status, body))
}

/// Parses an IAM response body into a claims object, erroring on non-JSON.
fn parse_claims(body: &str, status: u16) -> Result<Value, AuthError> {
    serde_json::from_str(body).map_err(|err| {
        AuthError::with_status(AUTH_REQUEST, &format!("invalid claims JSON: {err}"), status)
    })
}

/// Reads a non-empty string field off a JSON object.
fn string_field(doc: &Value, key: &str) -> Option<String> {
    doc.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Builds the in-band success JSON: `{ ok: true, claims }`.
fn ok_claims_json(claims: &Value) -> String {
    encode(&json!({ "ok": true, "claims": claims }))
}

/// Builds the in-band invalid-token JSON: `{ ok: false, status, code }`.
fn invalid_token_json(status: u16) -> String {
    encode(&json!({ "ok": false, "status": status, "code": "AUTH_INVALID_TOKEN" }))
}

/// Serializes a value to JSON, falling back to a safe error payload.
fn encode(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_err| r#"{"ok":false,"status":0,"code":"AUTH_INVALID_TOKEN"}"#.to_owned())
}

/// Extracts the issuer host for metrics (privacy: no path/query).
fn issuer_host(issuer: &str) -> String {
    reqwest::Url::parse(issuer)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Builds an `AuthMetric` from the call's action, host, and status.
fn build_metric(action: &str, host: &str, status: u16, start: Instant) -> AuthMetric {
    AuthMetric {
        action: action.into(),
        host: host.into(),
        status,
        duration_us: start.elapsed().as_micros(),
    }
}
