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

/// A [`ResourceBinding`] associated with the tenant authorized to use it.
///
/// The operator table maps a logical name to one of these. `tenant: None` is a **global**
/// (single-tenant / loopback) binding — resolvable only by a session that carries no tenant, so
/// existing non-multitenant configs keep working. `tenant: Some(id)` is resolvable only by a
/// session for exactly that tenant; a cross-tenant access never resolves (credentials and resources
/// never cross workspace boundaries). The binding's own `kind`+config are flattened in, so a table
/// entry reads `{"tenant":"ws_a","kind":"db","host":…}`.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantResourceBinding {
    /// The tenant authorized to resolve this binding (`None` = global / single-tenant).
    #[serde(default)]
    pub tenant: Option<String>,
    /// The driver binding (kind tag + connection config).
    #[serde(flatten)]
    pub binding: ResourceBinding,
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

/// Resolves each name selected in `init` against the operator `table`, scoped to the session tenant.
///
/// A `None` selection stays `None`; a named resource must exist, be authorized for the session's
/// tenant (`init.tenant`), and match the kind.
///
/// # Errors
///
/// Returns a [`ResolveError`] for the first unknown / out-of-tenant name or kind mismatch.
pub fn resolve<S: BuildHasher>(
    table: &HashMap<String, TenantResourceBinding, S>,
    init: &WireInit,
) -> Result<ResolvedConfigs, ResolveError> {
    let tenant = init.tenant.as_deref();
    Ok(ResolvedConfigs {
        db: pick(
            table,
            tenant,
            init.db.as_deref(),
            "db",
            ResourceBinding::as_db,
        )?,
        mongo: pick(
            table,
            tenant,
            init.mongo.as_deref(),
            "mongo",
            ResourceBinding::as_mongo,
        )?,
        mail: pick(
            table,
            tenant,
            init.mail.as_deref(),
            "mail",
            ResourceBinding::as_mail,
        )?,
        redis: pick(
            table,
            tenant,
            init.redis.as_deref(),
            "redis",
            ResourceBinding::as_redis,
        )?,
        amq: pick(
            table,
            tenant,
            init.amq.as_deref(),
            "amq",
            ResourceBinding::as_amq,
        )?,
        auth: pick(
            table,
            tenant,
            init.auth.as_deref(),
            "auth",
            ResourceBinding::as_auth,
        )?,
    })
}

/// Resolves one optional name, scoped to `session_tenant`: `None` → `Ok(None)`; a known,
/// tenant-authorized, kind-matching name → its cloned config; a kind mismatch → [`ResolveError`].
///
/// Tenant scoping is enforced here: a binding resolves only when its `tenant` equals the session's
/// tenant (both `None` = the single-tenant/loopback case). A cross-tenant access is reported as
/// `NotFound` — identical to a name that doesn't exist — so a tenant cannot probe the existence of
/// another tenant's resources.
fn pick<T, F, S>(
    table: &HashMap<String, TenantResourceBinding, S>,
    session_tenant: Option<&str>,
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
    let Some(entry) = table.get(resource_name) else {
        return Err(ResolveError::NotFound(resource_name.to_owned()));
    };
    // The trust boundary: a binding resolves only within its authorized tenant. A mismatch is
    // indistinguishable from absence, so cross-tenant existence never leaks.
    if entry.tenant.as_deref() != session_tenant {
        return Err(ResolveError::NotFound(resource_name.to_owned()));
    }
    extract(&entry.binding)
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

    use super::{ResolveError, ResourceBinding, TenantResourceBinding, resolve};
    use fabric_wire::WireInit;
    use std::collections::HashMap;

    /// One global `db` (`orders-db`) and one global `redis` (`cache`) binding, parsed from JSON
    /// (no `tenant` → global / single-tenant).
    fn table() -> HashMap<String, TenantResourceBinding> {
        serde_json::from_str(
            r#"{
                "orders-db": {"kind":"db","host":"h","user":"u","password":"p","database":"d"},
                "cache": {"kind":"redis","url":"redis://h:6379"}
            }"#,
        )
        .unwrap_or_else(|err| unreachable!("valid resource table: {err}"))
    }

    /// A tenant-scoped table: `a-db` bound for tenant `ws_a`, `b-db` bound for tenant `ws_b`.
    fn tenant_table() -> HashMap<String, TenantResourceBinding> {
        serde_json::from_str(
            r#"{
                "a-db": {"tenant":"ws_a","kind":"db","host":"ha","user":"u","password":"p","database":"d"},
                "b-db": {"tenant":"ws_b","kind":"db","host":"hb","user":"u","password":"p","database":"d"}
            }"#,
        )
        .unwrap_or_else(|err| unreachable!("valid tenant resource table: {err}"))
    }

    /// A `WireInit` selecting one db name (other kinds unset), for the given session tenant.
    fn init_db_for(name: &str, tenant: Option<&str>) -> WireInit {
        WireInit {
            db: Some(name.to_owned()),
            tenant: tenant.map(str::to_owned),
            ..WireInit::default()
        }
    }

    /// A `WireInit` selecting one db name with no session tenant (single-tenant path).
    fn init_db(name: &str) -> WireInit {
        init_db_for(name, None)
    }

    /// The `kind` tag selects the variant (flattened under the tenant wrapper).
    #[test]
    fn binding_kind_tag_selects_variant() {
        let table = table();
        assert!(matches!(
            table.get("orders-db").map(|entry| &entry.binding),
            Some(ResourceBinding::Db(_))
        ));
        assert!(matches!(
            table.get("cache").map(|entry| &entry.binding),
            Some(ResourceBinding::Redis(_))
        ));
        assert!(
            table
                .get("orders-db")
                .and_then(|entry| entry.tenant.as_deref())
                .is_none(),
            "no tenant tag → global binding"
        );
    }

    /// A named, kind-matching global resource resolves for a no-tenant session; unnamed kinds stay `None`.
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

    /// A name within the session tenant's bindings resolves.
    #[test]
    fn in_tenant_name_resolves() {
        let resolved = resolve(&tenant_table(), &init_db_for("a-db", Some("ws_a")))
            .unwrap_or_else(|_err| unreachable!("ws_a resolves its own binding"));
        assert!(resolved.db.is_some(), "in-tenant db resolved");
    }

    /// A name bound only for another tenant is refused (as `NotFound`, so existence never leaks) —
    /// and no config for the other tenant's resource is returned.
    #[test]
    fn cross_tenant_name_is_refused() {
        let err = resolve(&tenant_table(), &init_db_for("b-db", Some("ws_a"))).unwrap_err();
        assert_eq!(
            err.code(),
            "RESOURCE_NOT_FOUND",
            "cross-tenant looks absent"
        );
        assert!(matches!(err, ResolveError::NotFound(_)));
    }

    /// A tenant-scoped binding does not resolve for a session with no tenant, and vice versa.
    #[test]
    fn tenant_and_global_do_not_cross() {
        // Tenant-scoped binding, no-tenant session → refused.
        assert!(
            resolve(&tenant_table(), &init_db("a-db")).is_err(),
            "no-tenant session cannot reach a tenant-scoped binding"
        );
        // Global binding, tenant session → refused.
        assert!(
            resolve(&table(), &init_db_for("orders-db", Some("ws_a"))).is_err(),
            "tenant session cannot reach a global binding"
        );
    }
}
