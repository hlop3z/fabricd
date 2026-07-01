//! Pluggable client authentication for the **remote (QUIC)** box↔`fabricd` transport.
//!
//! On the local UDS path, filesystem permissions gate the socket, so no token is sent or checked.
//! On the QUIC path `fabricd` is network-reachable, so the box presents an opaque credential in
//! [`WireInit.token`](fabric_wire::wire::WireInit::token) and the daemon validates it **before**
//! resolving any logical name — a `ClientAuthenticator` is the seam.
//!
//! Three providers ship, selected by `quic.auth.mode`:
//!
//! - **`none`** — no client auth (only safe on a trusted/isolated network, e.g. behind a strict
//!   k8s `NetworkPolicy`).
//! - **`static`** — an opaque shared secret, constant-time compared, accepting `static_token` or
//!   `previous_token` for zero-downtime rotation.
//! - **`sa-token`** (the production primary) — a k8s projected `ServiceAccount` token, verified
//!   **offline** against the cluster JWKS (RSA signature + `aud`/`iss`/`exp`) via
//!   [`fabric_backends::sa_token`]. Per-pod identity, kubelet rotation, and revocation (delete the
//!   `ServiceAccount`) with no shared secret or cert manager. The JWKS is refreshed by a background
//!   task, so the accept path stays synchronous and I/O-free; it is fail-closed until the first
//!   fetch. See `docs/design/network-fabric.md` (QUIC remote transport).

use std::error::Error;
use std::fmt::{self, Formatter};
use std::path::PathBuf;
use std::time::Duration;

use fabric_backends::sa_token::{JwksVerifier, SaTokenVerifyConfig};
use serde::Deserialize;

/// Stable request-category code the box surfaces (as a `400`) when client auth fails.
const UNAUTHENTICATED: &str = "UNAUTHENTICATED";

/// Why a client's [`WireInit.token`](fabric_wire::wire::WireInit::token) was rejected — carried back
/// to the box in a [`WireResponse::InitError`](fabric_wire::wire::WireResponse::InitError). The
/// message is human-safe (never echoes the token).
#[derive(Debug)]
pub(crate) struct AuthReject {
    /// Stable code (`UNAUTHENTICATED`).
    pub(crate) code: &'static str,
    /// Human-safe detail.
    pub(crate) message: String,
}

impl AuthReject {
    /// Builds an `UNAUTHENTICATED` rejection with the given (secret-free) message.
    fn new(message: &str) -> Self {
        Self {
            code: UNAUTHENTICATED,
            message: message.to_owned(),
        }
    }
}

/// Validates the box's client-auth token at session open, before any name resolution.
///
/// `Debug` so the chosen provider can be logged at startup (implementations must redact any secret
/// — see [`StaticAuthenticator`]); `Send + Sync` so one instance is shared across connections.
pub(crate) trait ClientAuthenticator: fmt::Debug + Send + Sync {
    /// Accepts (`Ok`) or rejects (`Err`) the presented token (`None` = the box sent no token).
    ///
    /// # Errors
    ///
    /// Returns an [`AuthReject`] when the token is missing or does not validate.
    fn authenticate(&self, token: Option<&str>) -> Result<(), AuthReject>;
}

/// The daemon's client-auth mode for the QUIC transport.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AuthMode {
    /// No client auth — only safe on a trusted/isolated network.
    #[default]
    None,
    /// Opaque shared static token, constant-time compared (current + optional previous).
    Static,
    /// k8s `ServiceAccount` token, verified offline against the cluster JWKS (the production primary).
    SaToken,
}

/// Daemon client-auth config for the QUIC transport (the `quic.auth` block).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct ClientAuthConfig {
    /// Which provider to use.
    pub(crate) mode: AuthMode,
    /// The current shared secret (mode `static`): required, non-empty.
    pub(crate) static_token: Option<String>,
    /// A previous shared secret still accepted during rotation (mode `static`, optional).
    pub(crate) previous_token: Option<String>,
    /// Expected token audience (mode `sa-token`): the `aud` the projected token must carry. Required.
    pub(crate) audience: Option<String>,
    /// Expected token issuer (mode `sa-token`): the cluster `iss`, also the OIDC discovery base when
    /// `jwks_url` is unset. Required.
    pub(crate) issuer: Option<String>,
    /// Explicit JWKS URL (mode `sa-token`): skips discovery. Prefer this in-cluster (e.g. the API
    /// server's `/openid/v1/jwks`) so reachability does not depend on the discovery document.
    pub(crate) jwks_url: Option<String>,
    /// CA bundle (PEM) the JWKS HTTP client must trust (mode `sa-token`): the mounted cluster CA.
    pub(crate) ca_cert: Option<PathBuf>,
    /// JWKS refresh interval in seconds (mode `sa-token`, optional; default 300).
    pub(crate) jwks_refresh_secs: Option<u64>,
}

/// Builds the configured [`ClientAuthenticator`].
///
/// # Errors
///
/// Returns an error if mode `static` is selected without a non-empty `static_token`, if mode
/// `sa-token` is selected without an `issuer` + `audience`, or if the `sa-token` JWKS HTTP client
/// cannot be built.
///
/// Mode `sa-token` spawns a background JWKS-refresh task, so `build` must be called from within a
/// `tokio` runtime (it is — `fabricd`'s `main` is async).
pub(crate) fn build(
    cfg: &ClientAuthConfig,
) -> Result<Box<dyn ClientAuthenticator>, Box<dyn Error + Send + Sync>> {
    match cfg.mode {
        AuthMode::None => Ok(Box::new(NoneAuthenticator)),
        AuthMode::Static => {
            let current = cfg
                .static_token
                .clone()
                .filter(|token| !token.is_empty())
                .ok_or("quic.auth.mode = static requires a non-empty static_token")?;
            let previous = cfg.previous_token.clone().filter(|token| !token.is_empty());
            Ok(Box::new(StaticAuthenticator { current, previous }))
        }
        AuthMode::SaToken => build_sa_token(cfg),
    }
}

/// Builds the `sa-token` authenticator: validates the required `issuer` + `audience`, assembles the
/// [`SaTokenVerifyConfig`], and spawns the verifier (background JWKS refresh).
fn build_sa_token(
    cfg: &ClientAuthConfig,
) -> Result<Box<dyn ClientAuthenticator>, Box<dyn Error + Send + Sync>> {
    let issuer = cfg
        .issuer
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or("quic.auth.mode = sa-token requires an issuer")?;
    let audience = cfg
        .audience
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or("quic.auth.mode = sa-token requires an audience")?;
    let mut verify_cfg = SaTokenVerifyConfig::new(issuer, audience);
    verify_cfg.jwks_url = cfg.jwks_url.clone().filter(|value| !value.is_empty());
    verify_cfg.ca_cert.clone_from(&cfg.ca_cert);
    if let Some(secs) = cfg.jwks_refresh_secs {
        verify_cfg.refresh = Duration::from_secs(secs);
    }
    let verifier = JwksVerifier::spawn(verify_cfg).map_err(|err| err.message)?;
    Ok(Box::new(SaTokenAuthenticator { verifier }))
}

/// Allows every session (no client auth). Used for the UDS path and `mode: none`.
#[derive(Debug)]
struct NoneAuthenticator;

impl ClientAuthenticator for NoneAuthenticator {
    fn authenticate(&self, _token: Option<&str>) -> Result<(), AuthReject> {
        Ok(())
    }
}

/// Validates an opaque shared secret in constant time, accepting the current or a previous token
/// (zero-downtime rotation).
struct StaticAuthenticator {
    /// The current accepted secret.
    current: String,
    /// A previous secret still accepted during a rotation window.
    previous: Option<String>,
}

impl fmt::Debug for StaticAuthenticator {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        // Never print the secrets — only whether a rotation token is configured.
        formatter
            .debug_struct("StaticAuthenticator")
            .field("previous_set", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientAuthenticator for StaticAuthenticator {
    fn authenticate(&self, token: Option<&str>) -> Result<(), AuthReject> {
        let presented = token.ok_or_else(|| AuthReject::new("missing client auth token"))?;
        let bytes = presented.as_bytes();
        if ct_eq(bytes, self.current.as_bytes()) {
            return Ok(());
        }
        if let Some(previous) = self.previous.as_deref()
            && ct_eq(bytes, previous.as_bytes())
        {
            return Ok(());
        }
        Err(AuthReject::new("client auth token rejected"))
    }
}

/// The k8s `ServiceAccount`-token provider: rejects an absent token, then defers to the offline
/// [`JwksVerifier`] (cluster-JWKS signature + `aud`/`iss`/`exp`). The verifier holds only public key
/// material, so its `Debug` carries no secret.
#[derive(Debug)]
struct SaTokenAuthenticator {
    /// The offline JWKS verifier (background-refreshed key cache).
    verifier: JwksVerifier,
}

impl ClientAuthenticator for SaTokenAuthenticator {
    fn authenticate(&self, token: Option<&str>) -> Result<(), AuthReject> {
        let presented = token.ok_or_else(|| AuthReject::new("missing client auth token"))?;
        self.verifier
            .verify(presented)
            .map_err(|err| AuthReject::new(&err.to_string()))
    }
}

/// Constant-time byte-slice equality. A length difference returns early (a token's length is not the
/// secret); equal-length inputs are compared without an early exit. Mirrors the box's `/execute`
/// bearer compare.
fn ct_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut acc = 0_u8;
    for (left, right) in lhs.iter().zip(rhs.iter()) {
        acc |= left ^ right;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    //! The static provider's accept/reject paths (current, rotation, missing, wrong) and the
    //! `none`/`sa-token` extremes.

    use super::{AuthMode, ClientAuthConfig, ClientAuthenticator as _, StaticAuthenticator, build};

    /// A static authenticator with a current secret and optional rotation token.
    fn static_auth(current: &str, previous: Option<&str>) -> StaticAuthenticator {
        StaticAuthenticator {
            current: current.to_owned(),
            previous: previous.map(str::to_owned),
        }
    }

    /// The current and the rotation token both authenticate; wrong/missing are rejected.
    #[test]
    fn static_accepts_current_and_previous() {
        let auth = static_auth("s3cret", Some("old-s3cret"));
        assert!(
            auth.authenticate(Some("s3cret")).is_ok(),
            "current token accepted"
        );
        assert!(
            auth.authenticate(Some("old-s3cret")).is_ok(),
            "rotation token accepted"
        );
        assert!(
            auth.authenticate(Some("wrong")).is_err(),
            "wrong token rejected"
        );
        assert!(auth.authenticate(None).is_err(), "missing token rejected");
    }

    /// With no rotation token, only the current secret authenticates.
    #[test]
    fn static_without_previous_rejects_others() {
        let auth = static_auth("only", None);
        assert!(auth.authenticate(Some("only")).is_ok(), "current accepted");
        assert!(
            auth.authenticate(Some("old")).is_err(),
            "no rotation token configured"
        );
    }

    /// Mode `none` accepts everything, including an absent token.
    #[test]
    fn none_mode_accepts_all() {
        let auth = build(&ClientAuthConfig::default()).unwrap_or_else(|_err| unreachable!("none"));
        assert!(auth.authenticate(None).is_ok(), "none accepts absent token");
        assert!(
            auth.authenticate(Some("anything")).is_ok(),
            "none accepts any"
        );
    }

    /// Mode `static` without a token fails to build.
    #[test]
    fn static_mode_requires_token() {
        let cfg = ClientAuthConfig {
            mode: AuthMode::Static,
            ..ClientAuthConfig::default()
        };
        assert!(build(&cfg).is_err(), "static needs a static_token");
    }

    /// Mode `sa-token` fails to build without both an issuer and an audience (validated before the
    /// verifier — and its background task — are constructed, so this needs no runtime).
    #[test]
    fn sa_token_requires_issuer_and_audience() {
        let no_issuer = ClientAuthConfig {
            mode: AuthMode::SaToken,
            audience: Some("fabricd".to_owned()),
            ..ClientAuthConfig::default()
        };
        assert!(build(&no_issuer).is_err(), "sa-token needs an issuer");

        let no_audience = ClientAuthConfig {
            mode: AuthMode::SaToken,
            issuer: Some("https://kubernetes.default.svc".to_owned()),
            ..ClientAuthConfig::default()
        };
        assert!(build(&no_audience).is_err(), "sa-token needs an audience");
    }

    /// The `sa-token` config surface (kebab-case mode + the new fields) deserializes from JSON.
    #[test]
    fn sa_token_config_deserializes() {
        let json = r#"{
            "mode": "sa-token",
            "issuer": "https://kubernetes.default.svc.cluster.local",
            "jwks_url": "https://api.internal/openid/v1/jwks",
            "audience": "fabricd",
            "ca_cert": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "jwks_refresh_secs": 120
        }"#;
        let cfg: ClientAuthConfig = serde_json::from_str(json)
            .unwrap_or_else(|_err| unreachable!("the sa-token config fixture parses"));
        assert!(matches!(cfg.mode, AuthMode::SaToken), "mode is sa-token");
        assert_eq!(
            cfg.issuer.as_deref(),
            Some("https://kubernetes.default.svc.cluster.local"),
            "issuer parsed"
        );
        assert_eq!(
            cfg.jwks_url.as_deref(),
            Some("https://api.internal/openid/v1/jwks"),
            "explicit jwks_url parsed"
        );
        assert_eq!(cfg.audience.as_deref(), Some("fabricd"), "audience parsed");
        assert_eq!(cfg.jwks_refresh_secs, Some(120), "refresh interval parsed");
        assert!(cfg.ca_cert.is_some(), "ca_cert path parsed");
    }
}
