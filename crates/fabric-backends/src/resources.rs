//! The operator resource table + name→config resolution, owned by `fabricd`.
//!
//! After the trust flip the box never holds credentials: it sends logical resource *names* (a
//! [`WireInit`](fabric_wire::WireInit)), and the daemon resolves them against this table — the
//! endpoint/credentials live only here, operator-side. A name that isn't provisioned, or is the
//! wrong kind, is a [`ResolveError`] the daemon reports back so the box returns a `400`.

use std::collections::HashMap;
use std::hash::BuildHasher;

use serde::Deserialize;

use fabric_wire::WireInit;

use crate::amq::AmqConfig;
use crate::auth::AuthConfig;
use crate::db::DbConfig;
use crate::kv::RedisConfig;
use crate::mail::MailConfig;
use crate::mongo::MongoConfig;

/// One operator-declared logical resource: a driver `kind` tag + that driver's connection config.
///
/// Internally tagged, so `{"kind":"db","host":…}` selects the `db` capability and deserializes the
/// rest into its [`DbConfig`]. Boxed variants keep the enum small.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceBinding {
    /// A Postgres-family `db` resource.
    Db(Box<DbConfig>),
    /// A `mongo` document-database resource.
    Mongo(Box<MongoConfig>),
    /// A `mail`/SMTP resource.
    Mail(Box<MailConfig>),
    /// A `redis` resource.
    Redis(Box<RedisConfig>),
    /// An `amq` (`RabbitMQ`/`NATS`) message-broker resource.
    Amq(Box<AmqConfig>),
    /// An `auth` (OIDC/IAM) resource.
    Auth(Box<AuthConfig>),
}

impl ResourceBinding {
    /// The `db` config, if this binding is a `db` resource.
    #[must_use]
    pub fn as_db(&self) -> Option<&DbConfig> {
        match self {
            Self::Db(cfg) => Some(cfg.as_ref()),
            Self::Mongo(_) | Self::Mail(_) | Self::Redis(_) | Self::Amq(_) | Self::Auth(_) => None,
        }
    }

    /// The `mongo` config, if this binding is a `mongo` resource.
    #[must_use]
    pub fn as_mongo(&self) -> Option<&MongoConfig> {
        match self {
            Self::Mongo(cfg) => Some(cfg.as_ref()),
            Self::Db(_) | Self::Mail(_) | Self::Redis(_) | Self::Amq(_) | Self::Auth(_) => None,
        }
    }

    /// The `mail` config, if this binding is a `mail` resource.
    #[must_use]
    pub fn as_mail(&self) -> Option<&MailConfig> {
        match self {
            Self::Mail(cfg) => Some(cfg.as_ref()),
            Self::Db(_) | Self::Mongo(_) | Self::Redis(_) | Self::Amq(_) | Self::Auth(_) => None,
        }
    }

    /// The `redis` config, if this binding is a `redis` resource.
    #[must_use]
    pub fn as_redis(&self) -> Option<&RedisConfig> {
        match self {
            Self::Redis(cfg) => Some(cfg.as_ref()),
            Self::Db(_) | Self::Mongo(_) | Self::Mail(_) | Self::Amq(_) | Self::Auth(_) => None,
        }
    }

    /// The `amq` config, if this binding is an `amq` resource.
    #[must_use]
    pub fn as_amq(&self) -> Option<&AmqConfig> {
        match self {
            Self::Amq(cfg) => Some(cfg.as_ref()),
            Self::Db(_) | Self::Mongo(_) | Self::Mail(_) | Self::Redis(_) | Self::Auth(_) => None,
        }
    }

    /// The `auth` config, if this binding is an `auth` resource.
    #[must_use]
    pub fn as_auth(&self) -> Option<&AuthConfig> {
        match self {
            Self::Auth(cfg) => Some(cfg.as_ref()),
            Self::Db(_) | Self::Mongo(_) | Self::Mail(_) | Self::Redis(_) | Self::Amq(_) => None,
        }
    }
}

/// The operator config resolved for one session, ready to wire into a [`BackendSet`].
///
/// [`BackendSet`](crate::BackendSet)'s daemon-side constructor. Each field is `Some` only when the
/// session named a resource of that kind that resolved to a matching binding.
#[derive(Debug, Default, Clone)]
pub struct ResolvedConfigs {
    /// Resolved `db` config.
    pub db: Option<DbConfig>,
    /// Resolved `mongo` config.
    pub mongo: Option<MongoConfig>,
    /// Resolved `mail` config.
    pub mail: Option<MailConfig>,
    /// Resolved `redis` config.
    pub redis: Option<RedisConfig>,
    /// Resolved `amq` config.
    pub amq: Option<AmqConfig>,
    /// Resolved `auth` config.
    pub auth: Option<AuthConfig>,
}

impl ResolvedConfigs {
    /// Clamps the resolved `db` `statement_timeout_ms` to an operator ceiling (Tier 0). A ceiling
    /// of `0` means "no ceiling"; a request value of `0` ("unlimited") is raised to the ceiling so
    /// the daemon never issues an unbounded `SET statement_timeout`.
    pub fn clamp_db_statement_timeout(&mut self, ceiling_ms: u64) {
        if ceiling_ms == 0 {
            return;
        }
        if let Some(db) = self.db.as_mut() {
            db.statement_timeout_ms = if db.statement_timeout_ms == 0 {
                ceiling_ms
            } else {
                db.statement_timeout_ms.min(ceiling_ms)
            };
        }
    }
}

/// Why a requested resource name could not be resolved.
#[derive(Debug, Clone)]
pub enum ResolveError {
    /// No resource of any kind is provisioned under this name.
    NotFound(String),
    /// A resource exists under this name but is a different kind than requested.
    KindMismatch {
        /// The requested name.
        name: String,
        /// The kind the session asked for.
        kind: String,
    },
}

impl ResolveError {
    /// Stable request-category code (`RESOURCE_NOT_FOUND` / `RESOURCE_KIND_MISMATCH`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "RESOURCE_NOT_FOUND",
            Self::KindMismatch { .. } => "RESOURCE_KIND_MISMATCH",
        }
    }

    /// A human-safe message describing the failure.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotFound(name) => format!("no operator resource named `{name}`"),
            Self::KindMismatch { name, kind } => {
                format!("resource `{name}` is not a {kind} resource")
            }
        }
    }
}

/// Resolves each name selected in `init` against the operator `table`. A `None` selection stays
/// `None`; a named resource must exist and match the kind.
///
/// # Errors
///
/// Returns a [`ResolveError`] for the first unknown name or kind mismatch.
pub fn resolve<S: BuildHasher>(
    table: &HashMap<String, ResourceBinding, S>,
    init: &WireInit,
) -> Result<ResolvedConfigs, ResolveError> {
    Ok(ResolvedConfigs {
        db: pick(table, init.db.as_deref(), "db", ResourceBinding::as_db)?,
        mongo: pick(
            table,
            init.mongo.as_deref(),
            "mongo",
            ResourceBinding::as_mongo,
        )?,
        mail: pick(
            table,
            init.mail.as_deref(),
            "mail",
            ResourceBinding::as_mail,
        )?,
        redis: pick(
            table,
            init.redis.as_deref(),
            "redis",
            ResourceBinding::as_redis,
        )?,
        amq: pick(table, init.amq.as_deref(), "amq", ResourceBinding::as_amq)?,
        auth: pick(
            table,
            init.auth.as_deref(),
            "auth",
            ResourceBinding::as_auth,
        )?,
    })
}

/// Resolves one optional name: `None` → `Ok(None)`; a known, kind-matching name → its cloned
/// config; an unknown name or kind mismatch → the corresponding [`ResolveError`].
fn pick<T, F, S>(
    table: &HashMap<String, ResourceBinding, S>,
    name: Option<&str>,
    kind: &str,
    extract: F,
) -> Result<Option<T>, ResolveError>
where
    T: Clone,
    F: Fn(&ResourceBinding) -> Option<&T>,
    S: BuildHasher,
{
    let Some(resource_name) = name else {
        return Ok(None);
    };
    let Some(binding) = table.get(resource_name) else {
        return Err(ResolveError::NotFound(resource_name.to_owned()));
    };
    extract(binding)
        .cloned()
        .map(Some)
        .ok_or_else(|| ResolveError::KindMismatch {
            name: resource_name.to_owned(),
            kind: kind.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    //! Resolution against an operator table: kind-tag deserialization, the happy path, unknown
    //! names, and kind mismatches.

    use super::{ResolveError, ResourceBinding, resolve};
    use fabric_wire::WireInit;
    use std::collections::HashMap;

    /// One `db` (`orders-db`) and one `redis` (`cache`) binding, parsed from JSON.
    fn table() -> HashMap<String, ResourceBinding> {
        serde_json::from_str(
            r#"{
                "orders-db": {"kind":"db","host":"h","user":"u","password":"p","database":"d"},
                "cache": {"kind":"redis","url":"redis://h:6379"}
            }"#,
        )
        .unwrap_or_else(|err| unreachable!("valid resource table: {err}"))
    }

    /// A `WireInit` selecting one db name (other kinds unset).
    fn init_db(name: &str) -> WireInit {
        WireInit {
            db: Some(name.to_owned()),
            ..WireInit::default()
        }
    }

    /// The `kind` tag selects the variant.
    #[test]
    fn binding_kind_tag_selects_variant() {
        let table = table();
        assert!(matches!(
            table.get("orders-db"),
            Some(ResourceBinding::Db(_))
        ));
        assert!(matches!(
            table.get("cache"),
            Some(ResourceBinding::Redis(_))
        ));
    }

    /// A named, kind-matching resource resolves; unnamed kinds stay `None`.
    #[test]
    fn resolves_named_db() {
        let resolved = resolve(&table(), &init_db("orders-db"))
            .unwrap_or_else(|_err| unreachable!("orders-db resolves"));
        assert!(resolved.db.is_some(), "db resolved");
        assert!(resolved.mongo.is_none(), "unnamed kinds stay None");
    }

    /// An unknown name is `RESOURCE_NOT_FOUND`.
    #[test]
    fn unknown_name_is_not_found() {
        let err = resolve(&table(), &init_db("nope")).unwrap_err();
        assert_eq!(err.code(), "RESOURCE_NOT_FOUND");
        assert!(matches!(err, ResolveError::NotFound(_)));
    }

    /// Naming a resource of the wrong kind is `RESOURCE_KIND_MISMATCH`.
    #[test]
    fn kind_mismatch_is_reported() {
        let err = resolve(&table(), &init_db("cache")).unwrap_err();
        assert_eq!(err.code(), "RESOURCE_KIND_MISMATCH");
    }
}
