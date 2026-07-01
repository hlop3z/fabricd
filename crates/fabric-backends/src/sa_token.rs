//! Offline k8s `ServiceAccount`-token verification for the `fabricd` QUIC `sa-token` client
//! authenticator.
//!
//! The box mounts a projected `ServiceAccount` token (a short-lived, kubelet-rotated OIDC JWT,
//! audience = `fabricd`) and presents it in
//! [`WireInit.token`](fabric_wire::wire::WireInit::token). `fabricd` verifies it **offline** against
//! the cluster JWKS — an RSA signature + `aud`/`iss`/`exp` claim check — with **no per-request
//! API-server round-trip**, giving per-pod identity, automatic rotation, and revocation (delete the
//! `ServiceAccount`) without a cert manager or shared secret.
//!
//! The QUIC accept path's [`authenticate`](crate) is **synchronous and must not block**, so the hot
//! path does no I/O: a [`tokio`] background task refetches the JWKS on an interval into an in-memory
//! cache, and [`JwksVerifier::verify`] is a pure offline check against the cached keys. Until the
//! first fetch succeeds the cache is empty and every token is rejected (**fail-closed**).
//!
//! Lives here (not in `fabricd`) because this crate already owns `reqwest` + the OIDC `auth`
//! capability; `fabricd` stays a thin host and wires the verifier in. See
//! `docs/design/network-fabric.md` (QUIC remote transport).

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Certificate, Client};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::sleep;
use tracing::{info, warn};

use fabric_wire::{EgressError, ErrorOwner, Fault};

/// Building the JWKS HTTP client failed (bad CA bundle, TLS setup) — retryable, operator-owned.
const SA_TOKEN_UNAVAILABLE: Fault = Fault::new("SA_TOKEN_UNAVAILABLE", true, ErrorOwner::Operator);

/// Default JWKS refresh interval in seconds when the config omits one.
const DEFAULT_REFRESH_SECS: u64 = 300;

/// Floor on the refresh interval, so a misconfigured `0` cannot busy-loop the JWKS endpoint.
const MIN_REFRESH: Duration = Duration::from_secs(1);

/// Map of JWK `kid` → verification key, rebuilt on each successful JWKS refresh.
type KeyMap = HashMap<String, DecodingKey>;

/// Configuration for a [`JwksVerifier`] (the `quic.auth.mode = sa-token` provider).
#[derive(Debug, Clone)]
pub struct SaTokenVerifyConfig {
    /// Expected token issuer (`iss` claim); also the OIDC discovery base when `jwks_url` is unset.
    pub issuer: String,
    /// Explicit JWKS URL; when `None`, discovered from `{issuer}/.well-known/openid-configuration`.
    pub jwks_url: Option<String>,
    /// Expected token audience (`aud` claim) — e.g. `fabricd`.
    pub audience: String,
    /// Optional CA bundle (PEM) the JWKS HTTP client must trust (e.g. the mounted cluster CA).
    pub ca_cert: Option<PathBuf>,
    /// How often the background task refetches the JWKS (floored at one second).
    pub refresh: Duration,
}

impl SaTokenVerifyConfig {
    /// Builds a config with the default refresh interval and discovery-derived JWKS URL.
    #[must_use]
    pub const fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer,
            jwks_url: None,
            audience,
            ca_cert: None,
            refresh: Duration::from_secs(DEFAULT_REFRESH_SECS),
        }
    }
}

/// Why a presented `sa-token` failed verification.
///
/// Every variant maps to an `UNAUTHENTICATED` rejection by the caller; the variant only shapes the
/// (secret-free) message. The token is never embedded in any message.
#[derive(Debug)]
pub enum VerifyError {
    /// The JWKS has not been fetched yet (fail-closed at boot or while the issuer is unreachable).
    KeysNotLoaded,
    /// The token header carried no `kid`.
    MissingKid,
    /// No key in the current JWKS matches the token's `kid` (unknown signer or pre-rotation key).
    UnknownKid,
    /// The token failed signature/claims validation (bad signature, wrong `aud`/`iss`, expired).
    Invalid(String),
    /// The key-cache lock was poisoned — an internal invariant failure.
    Internal,
}

impl Display for VerifyError {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeysNotLoaded => {
                formatter.write_str("sa-token verifier not ready (JWKS not loaded)")
            }
            Self::MissingKid => formatter.write_str("token header missing kid"),
            Self::UnknownKid => formatter.write_str("no JWKS key matches the token kid"),
            Self::Invalid(reason) => write!(formatter, "token invalid: {reason}"),
            Self::Internal => formatter.write_str("internal verifier error"),
        }
    }
}

/// Verifies k8s `ServiceAccount` JWTs offline against a background-refreshed JWKS cache.
pub struct JwksVerifier {
    /// `kid` → key, or `None` until the first successful JWKS fetch (fail-closed).
    keys: Arc<RwLock<Option<KeyMap>>>,
    /// Expected `aud` claim.
    audience: String,
    /// Expected `iss` claim.
    issuer: String,
}

impl fmt::Debug for JwksVerifier {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        // Keys are public material, but reporting only whether they are loaded keeps the line tidy.
        let loaded = self.keys.read().is_ok_and(|guard| guard.is_some());
        formatter
            .debug_struct("JwksVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("keys_loaded", &loaded)
            .finish()
    }
}

impl JwksVerifier {
    /// Builds the verifier and spawns the background JWKS refresh task, returning immediately. The
    /// cache is populated asynchronously, so verification is fail-closed until the first fetch.
    ///
    /// Must be called from within a `tokio` runtime (it is, from `fabricd`'s async `main`).
    ///
    /// # Errors
    ///
    /// Returns an [`EgressError`] if the HTTP client (including the optional CA bundle) cannot be
    /// built.
    pub fn spawn(config: SaTokenVerifyConfig) -> Result<Self, EgressError> {
        let client = build_client(config.ca_cert.as_ref())?;
        let keys = Arc::new(RwLock::new(None));
        let verifier = Self {
            keys: Arc::clone(&keys),
            audience: config.audience,
            issuer: config.issuer.clone(),
        };
        let refresh = config.refresh.max(MIN_REFRESH);
        drop(tokio::spawn(refresh_loop(
            client,
            config.issuer,
            config.jwks_url,
            keys,
            refresh,
        )));
        Ok(verifier)
    }

    /// Verifies `token` offline against the cached JWKS and the expected `aud`/`iss`.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] when keys are not yet loaded, no key matches the `kid`, or the
    /// signature/claims are invalid.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the read guard must span the kid lookup; the key is cloned out so the lock is \
                  released before the CPU-bound verify"
    )]
    pub fn verify(&self, token: &str) -> Result<(), VerifyError> {
        let header = decode_header(token).map_err(|err| VerifyError::Invalid(err.to_string()))?;
        let kid = header.kid.ok_or(VerifyError::MissingKid)?;
        // Clone the matching key out and release the lock before the (CPU-bound) verify, so a
        // concurrent JWKS refresh swap is never blocked on signature work.
        let key = {
            let guard = self.keys.read().map_err(|_poison| VerifyError::Internal)?;
            let map = guard.as_ref().ok_or(VerifyError::KeysNotLoaded)?;
            map.get(&kid).cloned().ok_or(VerifyError::UnknownKid)?
        };
        let _claims = decode::<Value>(token, &key, &self.validation())
            .map_err(|err| VerifyError::Invalid(err.to_string()))?;
        Ok(())
    }

    /// Builds the JWT validation policy: RS256, expected audience + issuer, expiry enforced (the
    /// `jsonwebtoken` default with a 60s leeway).
    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation
    }

    /// Test-only constructor with a pre-set cache (`Some` = loaded keys, `None` = fail-closed) and
    /// no background task.
    #[cfg(test)]
    fn with_cache(keys: Option<KeyMap>, audience: &str, issuer: &str) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            audience: audience.to_owned(),
            issuer: issuer.to_owned(),
        }
    }
}

/// Builds the async HTTP client used to fetch the JWKS, trusting an extra CA bundle when given.
fn build_client(ca_cert: Option<&PathBuf>) -> Result<Client, EgressError> {
    let mut builder = Client::builder();
    if let Some(path) = ca_cert {
        let pem = fs::read(path)
            .map_err(|err| client_error(&format!("read ca_cert {}: {err}", path.display())))?;
        let certs = Certificate::from_pem_bundle(&pem)
            .map_err(|err| client_error(&format!("parse ca_cert bundle: {err}")))?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|err| client_error(&format!("build JWKS client: {err}")))
}

/// Builds a retryable `SA_TOKEN_UNAVAILABLE` egress error for a client-build failure.
fn client_error(message: &str) -> EgressError {
    EgressError {
        code: SA_TOKEN_UNAVAILABLE.code.to_owned(),
        message: message.to_owned(),
        source: "sa-token".to_owned(),
        details: None,
        retryable: SA_TOKEN_UNAVAILABLE.retryable,
        owner: SA_TOKEN_UNAVAILABLE.owner,
    }
}

/// Background task: refetch the JWKS on `interval`, swapping the cache on success and keeping the
/// previous keys on a transient failure. Runs for the process lifetime.
#[expect(
    clippy::infinite_loop,
    reason = "the JWKS refresh task is intended to run for the whole process lifetime"
)]
async fn refresh_loop(
    client: Client,
    issuer: String,
    jwks_url: Option<String>,
    keys: Arc<RwLock<Option<KeyMap>>>,
    interval: Duration,
) {
    loop {
        match fetch_keys(&client, &issuer, jwks_url.as_deref()).await {
            Ok(map) => {
                let count = map.len();
                if let Ok(mut guard) = keys.write() {
                    *guard = Some(map);
                    info!(keys = count, "sa-token JWKS refreshed");
                } else {
                    warn!("sa-token JWKS cache lock poisoned; skipping swap");
                }
            }
            Err(err) => {
                warn!(error = %err, "sa-token JWKS refresh failed; keeping previous keys");
            }
        }
        sleep(interval).await;
    }
}

/// Fetches and parses the JWKS into a `kid` → key map, resolving the URL via discovery when needed.
async fn fetch_keys(
    client: &Client,
    issuer: &str,
    jwks_url: Option<&str>,
) -> Result<KeyMap, JwksFetchError> {
    let url = match jwks_url {
        Some(explicit) => explicit.to_owned(),
        None => discover_jwks_url(client, issuer).await?,
    };
    let set: JwkSet = get_json(client, &url).await?;
    Ok(build_key_map(&set))
}

/// `GET {issuer}/.well-known/openid-configuration` → its `jwks_uri`.
async fn discover_jwks_url(client: &Client, issuer: &str) -> Result<String, JwksFetchError> {
    let base = issuer.trim_end_matches('/');
    let doc: Value = get_json(client, &format!("{base}/.well-known/openid-configuration")).await?;
    doc.get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| JwksFetchError("discovery document has no jwks_uri".to_owned()))
}

/// `GET url` → deserialized JSON, mapping transport / non-2xx / decode failures to a fetch error.
async fn get_json<T: DeserializeOwned>(client: &Client, url: &str) -> Result<T, JwksFetchError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| JwksFetchError(format!("GET {url} failed: {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(JwksFetchError(format!("GET {url} returned {status}")));
    }
    response
        .json::<T>()
        .await
        .map_err(|err| JwksFetchError(format!("decode {url} failed: {err}")))
}

/// Converts every usable RSA key in the set into a `kid` → [`DecodingKey`] entry, skipping (with a
/// warning) keys that carry no `kid` or that fail conversion.
fn build_key_map(set: &JwkSet) -> KeyMap {
    let mut map = KeyMap::new();
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            warn!("sa-token JWKS entry without kid skipped");
            continue;
        };
        match DecodingKey::from_jwk(jwk) {
            Ok(key) => {
                let _previous = map.insert(kid, key);
            }
            Err(err) => warn!(error = %err, "sa-token JWKS key rejected"),
        }
    }
    map
}

/// A JWKS fetch / parse failure, surfaced only to the background task's log (never to the box).
#[derive(Debug)]
struct JwksFetchError(String);

impl Display for JwksFetchError {
    #[expect(
        clippy::renamed_function_params,
        reason = "`formatter` reads better than the trait's single-char `f` (min_ident_chars)"
    )]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    //! Hermetic verifier tests: a fixed throwaway RSA keypair signs JWTs that are checked against a
    //! JWKS built from its public modulus. No network, no cluster.

    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use super::{JwksVerifier, KeyMap, VerifyError, build_key_map};

    /// Expected issuer for the test tokens (a realistic in-cluster value).
    const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
    /// Expected audience for the test tokens.
    const AUDIENCE: &str = "fabricd";
    /// The `kid` carried by the test JWKS and (by default) the signed tokens.
    const KID: &str = "test-key-1";

    /// A throwaway 2048-bit RSA private key (PKCS#8 PEM). Test-only; not a real credential.
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwuwJ3ivQbAMTn
eR8E/8zldT5szUWjJs+X1MWfVmkz2LlOVJrdm85J8nlcfilbeZ85HhBPgNIv3+VL
an72hyLdSL5iKE0AtJET4LUjA84jEemSxshJELQ2jhc2lpWE1ZNUIQm3d6Rgb4Ji
5ECTtij77TBbJl4g96fJMhuqYIaMD/JPNv9PJMIBG9uJa72pw3vu5ULBgw41Rlor
77b/3ftLQkvMWwe2CTimdsVwnKtzwLKqAOqoNVxKqZ7oQ/rvBIBk81KUYhX48u5q
m/dgVZWNVhVa71kDgc5weyETxMwJIRR+4Ew6LHnMxAZGdCJrPmhN6nEW/s9+kaLi
yZKAg3xTAgMBAAECggEAPlcBJETmHX5UdqgxanSHBKuqRPvVpBrlIFQkD7QN8QVy
PDC43hH/HvOCnr87/HH22dGChGDXA58xRTyAI5sAj9kAmyRHIUgQYtghXQQTGyjO
4QDwlmFniFTv2Ege3tftm7/5qvdvirra3eJQ6ynW5CLDK2vpySxCycQ8oQlifJXv
EY/9r1CudEVdf2U7pZlCHXMMwbXDjcISvwsG2S7Af/AH28aQQUhkc+3tvWuOd55q
ql81p0+MRG10rUxjRaMBBkA2OFIeJTkek4ueLezUHJ9NhW4UrptvBtLSivkfIJf8
8/Z2yzZs/ydUNWGsURhpFc0lGn5Ikp0Y1KctN85KUQKBgQDik3gqJh4K/YfsNYok
PsRhs9XM51rzhrHHRSA6Vf3CnphfPJZOCzJoGnIjf7zkP/As4zniCrINc4x/+Dij
iXXwuvpoHj6WRJYviboq2qnDJTsuCL3jaiCerl5bvxIdXZu7adFMV4K5+TI84NAd
FtgNF71qkyHQ5fxKH4/8NZtkgwKBgQDHrmxEzEom2AmWDYbFYKS7WmRd7gR0XQaH
hDHaDBESW1evsNMmDIaLCzgldK1wBuq28l8BaVjmViaPZqfdNoXr+ncybLMy/fvi
gFDYWTtPoWQgv16IxuiVznvKpJ3AaG8k9Uh26phWwbs+RKtqfIdrvK0sWO/KqpIs
uBWl9lof8QKBgQCaZIbzobnDH3Qpn2ocvLCxKww7bkNpwpUOBqqpVcNvhQarjuuV
DsgwbCTuz7J1jqQo0kW1JDikNeK9qPVfauH1QlQz8rgPSXlVt3ImlY4srggfnFFY
0A6eUo910UOUwx7FnJvEe7VW6No05bSqvdBHS7AFGXFnmfBKyishX54d5QKBgGly
ygg23f3PXpiYQhCfrb6myJP16vJMYfNUs0LT1nwcMp08QvU37iElZpwZFrIvZOoB
6nwDVwgkfK6D5qficCyjEylUz/lguRDu9EKcNL8jmo3UoaaXbCIYbbUg45HFVNRu
l7r8vkAqhKgoeWF9q8IQXF8sBE3Bb/ofqIcBJqzxAoGBAJeERmZmBfb2wovwr6Wf
hXtdoaLz9xEyGhqvGH3sIudMfGTq/NZonRHghn0lIO+dB367ky9J3xu5jnqmBl0g
7OcqP81uW8d8//XVEQ55KdtyLv/3cLBKJUS8p2ZgHdq+HtJ6bpacZ1q3KToxR2Ma
fFR0RlxfJ5KpOfULpjPqVaj/
-----END PRIVATE KEY-----
";

    /// The base64url RSA modulus matching [`PRIVATE_PEM`]; the public exponent is `AQAB` (65537).
    const MODULUS: &str = "sLsCd4r0GwDE53kfBP_M5XU-bM1FoybPl9TFn1ZpM9i5TlSa3ZvOSfJ5XH4pW3mfOR4QT4DSL9_lS2p-9oci3Ui-YihNALSRE-C1IwPOIxHpksbISRC0No4XNpaVhNWTVCEJt3ekYG-CYuRAk7Yo--0wWyZeIPenyTIbqmCGjA_yTzb_TyTCARvbiWu9qcN77uVCwYMONUZaK--2_937S0JLzFsHtgk4pnbFcJyrc8CyqgDqqDVcSqme6EP67wSAZPNSlGIV-PLuapv3YFWVjVYVWu9ZA4HOcHshE8TMCSEUfuBMOix5zMQGRnQiaz5oTepxFv7PfpGi4smSgIN8Uw";

    /// Current UNIX time in seconds (test clock is assumed sane).
    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
            |_err| unreachable!("system clock predates the UNIX epoch"),
            |since| since.as_secs(),
        )
    }

    /// Builds a claims object with the given issuer, audience, and expiry.
    fn claims(iss: &str, aud: &str, exp: u64) -> Value {
        json!({
            "iss": iss,
            "aud": aud,
            "sub": "system:serviceaccount:default:box",
            "exp": exp,
        })
    }

    /// Builds a single-key JWKS document for the given `kid`.
    fn jwks_json(kid: &str) -> String {
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": MODULUS,
                "e": "AQAB",
            }]
        })
        .to_string()
    }

    /// Builds a loaded key cache from the JWKS for the given `kid`.
    fn key_map(kid: &str) -> KeyMap {
        let set: JwkSet = serde_json::from_str(&jwks_json(kid))
            .unwrap_or_else(|_err| unreachable!("static JWKS fixture parses"));
        build_key_map(&set)
    }

    /// Signs a JWT with the test key and the given header `kid` + claims.
    fn sign(kid: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        let key = EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes())
            .unwrap_or_else(|_err| unreachable!("static test PEM is a valid RSA key"));
        encode(&header, claims, &key)
            .unwrap_or_else(|_err| unreachable!("signing the test claims succeeds"))
    }

    /// Claims with a valid issuer/audience and an expiry one hour out.
    fn valid_claims() -> Value {
        claims(ISSUER, AUDIENCE, now_secs().saturating_add(3600))
    }

    /// A verifier with the loaded test key, for the happy/invalid-claim paths.
    fn loaded_verifier() -> JwksVerifier {
        JwksVerifier::with_cache(Some(key_map(KID)), AUDIENCE, ISSUER)
    }

    #[test]
    fn accepts_a_valid_token() {
        let verifier = loaded_verifier();
        let token = sign(KID, &valid_claims());
        assert!(
            verifier.verify(&token).is_ok(),
            "a correctly-signed token with the right aud/iss/exp is accepted"
        );
    }

    #[test]
    fn rejects_wrong_audience() {
        let verifier = loaded_verifier();
        let token = sign(
            KID,
            &claims(ISSUER, "someone-else", now_secs().saturating_add(3600)),
        );
        assert!(
            matches!(verifier.verify(&token), Err(VerifyError::Invalid(_))),
            "a token minted for another audience is rejected"
        );
    }

    #[test]
    fn rejects_wrong_issuer() {
        let verifier = loaded_verifier();
        let token = sign(
            KID,
            &claims(
                "https://evil.example.com",
                AUDIENCE,
                now_secs().saturating_add(3600),
            ),
        );
        assert!(
            matches!(verifier.verify(&token), Err(VerifyError::Invalid(_))),
            "a token from another issuer is rejected"
        );
    }

    #[test]
    fn rejects_expired_token() {
        let verifier = loaded_verifier();
        let token = sign(
            KID,
            &claims(ISSUER, AUDIENCE, now_secs().saturating_sub(3600)),
        );
        assert!(
            matches!(verifier.verify(&token), Err(VerifyError::Invalid(_))),
            "an expired token is rejected"
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let verifier = loaded_verifier();
        let token = sign(KID, &valid_claims());
        // Flip the final signature character to corrupt the RSA signature.
        let mut bytes = token.into_bytes();
        if let Some(last) = bytes.last_mut() {
            *last = if *last == b'A' { b'B' } else { b'A' };
        }
        let tampered = String::from_utf8(bytes)
            .unwrap_or_else(|_err| unreachable!("flipping an ASCII char keeps valid UTF-8"));
        assert!(
            matches!(verifier.verify(&tampered), Err(VerifyError::Invalid(_))),
            "a token with a corrupted signature is rejected"
        );
    }

    #[test]
    fn rejects_unknown_kid() {
        let verifier = loaded_verifier();
        // Sign with a kid the JWKS cache does not contain.
        let token = sign("rotated-away", &valid_claims());
        assert!(
            matches!(verifier.verify(&token), Err(VerifyError::UnknownKid)),
            "a token whose kid is not in the JWKS is rejected as UnknownKid"
        );
    }

    #[test]
    fn rejects_when_keys_not_loaded() {
        let verifier = JwksVerifier::with_cache(None, AUDIENCE, ISSUER);
        let token = sign(KID, &valid_claims());
        assert!(
            matches!(verifier.verify(&token), Err(VerifyError::KeysNotLoaded)),
            "before the first JWKS fetch the verifier is fail-closed"
        );
    }
}
