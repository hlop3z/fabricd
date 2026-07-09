//! The operator resource table + name→config resolution, owned by `fabricd`.
//!
//! After the trust flip the box never holds credentials: it sends logical resource *names* (a
//! [`WireInit`](runlet_wire::WireInit)), and the daemon resolves them against this table — the
//! endpoint/credentials live only here, operator-side. A name that isn't provisioned, or is the
//! wrong kind, is a [`ResolveError`] the daemon reports back so the box returns a `400`.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use serde::Deserialize;

use runlet_wire::WireInit;

use crate::amq::AmqConfig;
use crate::auth::AuthConfig;
use crate::db::DbConfig;
use crate::kv::RedisConfig;
use crate::mail::MailConfig;

/// One operator-declared logical resource: a driver `kind` tag + that driver's connection config.
///
/// Internally tagged, so `{"kind":"db","host":…}` selects the `db` capability and deserializes the
/// rest into its [`DbConfig`]. Boxed variants keep the enum small.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceBinding {
    /// A Postgres-family `db` resource.
    Db(Box<DbConfig>),
    /// A `mail`/SMTP resource.
    Mail(Box<MailConfig>),
    /// A `redis` resource.
    Redis(Box<RedisConfig>),
    /// An `amq` (`RabbitMQ`/`NATS`) message-broker resource.
    Amq(Box<AmqConfig>),
    /// An `auth` (OIDC/IAM) resource.
    Auth(Box<AuthConfig>),
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
/// A per-session `name → binding` map: [`BackendSet::from_configs`](crate::BackendSet::from_configs)
/// turns each entry into a lazily-connected backend. `fabricd` builds it by resolving every logical
/// name the session listed in [`WireInit::resources`] against the operator table — the box is
/// kind-blind, so the kind comes from the resolved binding, never off the wire. Two names of the
/// same kind coexist (the flat model has no per-kind slot).
#[derive(Debug, Default, Clone)]
pub struct ResolvedResources {
    /// The resolved bindings for this session, keyed by logical resource name (ordered, so backend
    /// construction and metric aggregation are deterministic).
    pub by_name: BTreeMap<String, ResourceBinding>,
}

impl ResolvedResources {
    /// Clamps every resolved `db` binding's `statement_timeout_ms` to an operator ceiling (Tier 0).
    /// A ceiling of `0` means "no ceiling"; a request value of `0` ("unlimited") is raised to the
    /// ceiling so the daemon never issues an unbounded `SET statement_timeout`.
    pub fn clamp_db_statement_timeout(&mut self, ceiling_ms: u64) {
        if ceiling_ms == 0 {
            return;
        }
        for binding in self.by_name.values_mut() {
            if let ResourceBinding::Db(db) = binding {
                db.statement_timeout_ms = if db.statement_timeout_ms == 0 {
                    ceiling_ms
                } else {
                    db.statement_timeout_ms.min(ceiling_ms)
                };
            }
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

/// Resolves every logical name the session listed in [`WireInit::resources`] against the operator
/// `table`, scoped to the session tenant (`init.tenant`).
///
/// Each name must exist and be authorized for the session's tenant; the kind comes from the
/// resolved binding (the box never sends one). The result is a `name → binding` map ready for
/// [`BackendSet::from_configs`](crate::BackendSet::from_configs).
///
/// # Errors
///
/// Returns [`ResolveError::NotFound`] for the first unknown or out-of-tenant name. A cross-tenant
/// name is reported as `NotFound` — identical to absence — so a tenant cannot probe the existence
/// of another tenant's resources.
pub fn resolve<S: BuildHasher>(
    table: &HashMap<String, TenantResourceBinding, S>,
    init: &WireInit,
) -> Result<ResolvedResources, ResolveError> {
    let session_tenant = init.tenant.as_deref();
    let mut by_name = BTreeMap::new();
    for name in &init.resources {
        let Some(entry) = table.get(name) else {
            return Err(ResolveError::NotFound(name.clone()));
        };
        // The trust boundary: a binding resolves only within its authorized tenant (both `None` =
        // the single-tenant/loopback case). A mismatch is indistinguishable from absence, so
        // cross-tenant existence never leaks.
        if entry.tenant.as_deref() != session_tenant {
            return Err(ResolveError::NotFound(name.clone()));
        }
        drop(by_name.insert(name.clone(), entry.binding.clone()));
    }
    Ok(ResolvedResources { by_name })
}

#[cfg(test)]
mod tests {
    //! Resolution against an operator table: kind-tag deserialization, the happy path (incl.
    //! multiple names in one session), unknown names, and tenant scoping.

    use super::{ResolveError, ResourceBinding, TenantResourceBinding, resolve};
    use runlet_wire::WireInit;
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

    /// A `WireInit` selecting a flat list of logical names, for the given session tenant.
    fn init_names(names: &[&str], tenant: Option<&str>) -> WireInit {
        WireInit {
            resources: names.iter().map(|name| (*name).to_owned()).collect(),
            tenant: tenant.map(str::to_owned),
            ..WireInit::default()
        }
    }

    /// A `WireInit` selecting one name with no session tenant (single-tenant path).
    fn init_db(name: &str) -> WireInit {
        init_names(&[name], None)
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

    /// A named global resource resolves for a no-tenant session; unlisted names stay absent.
    #[test]
    fn resolves_named_db() {
        let resolved = resolve(&table(), &init_db("orders-db"))
            .unwrap_or_else(|_err| unreachable!("orders-db resolves"));
        assert!(
            matches!(
                resolved.by_name.get("orders-db"),
                Some(ResourceBinding::Db(_))
            ),
            "db resolved by name"
        );
        assert!(
            !resolved.by_name.contains_key("cache"),
            "unlisted names absent"
        );
    }

    /// Two names of different kinds in one session both resolve into the map (the flat model has no
    /// per-kind slot — a per-name map holds them side by side).
    #[test]
    fn resolves_multiple_names() {
        let resolved = resolve(&table(), &init_names(&["orders-db", "cache"], None))
            .unwrap_or_else(|_err| unreachable!("both names resolve"));
        assert!(matches!(
            resolved.by_name.get("orders-db"),
            Some(ResourceBinding::Db(_))
        ));
        assert!(matches!(
            resolved.by_name.get("cache"),
            Some(ResourceBinding::Redis(_))
        ));
    }

    /// An unknown name is `RESOURCE_NOT_FOUND`.
    #[test]
    fn unknown_name_is_not_found() {
        let err = resolve(&table(), &init_db("nope")).unwrap_err();
        assert_eq!(err.code(), "RESOURCE_NOT_FOUND");
        assert!(matches!(err, ResolveError::NotFound(_)));
    }

    /// A name within the session tenant's bindings resolves.
    #[test]
    fn in_tenant_name_resolves() {
        let resolved = resolve(&tenant_table(), &init_names(&["a-db"], Some("ws_a")))
            .unwrap_or_else(|_err| unreachable!("ws_a resolves its own binding"));
        assert!(
            resolved.by_name.contains_key("a-db"),
            "in-tenant db resolved"
        );
    }

    /// A name bound only for another tenant is refused (as `NotFound`, so existence never leaks).
    #[test]
    fn cross_tenant_name_is_refused() {
        let err = resolve(&tenant_table(), &init_names(&["b-db"], Some("ws_a"))).unwrap_err();
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
            resolve(&table(), &init_names(&["orders-db"], Some("ws_a"))).is_err(),
            "tenant session cannot reach a global binding"
        );
    }
}
