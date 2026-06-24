//! `fabric-backends`: the driver-backed egress backends for runlet.
//!
//! The half of the old `runlet-core` capability modules that holds the network drivers —
//! `db` (`tokio-postgres`), `mongo` (`mongodb`), `mail` (SMTP/`lettre`), `redis`, `amq`
//! (`RabbitMQ`/`NATS`), and `auth` (OIDC) — extracted so the sandbox (`runlet-core`) links no
//! driver. Each module exposes a JS-free `*Backend` (string-in/string-out dispatch + metrics +
//! `into_resource_error`); [`BackendSet`] wires them behind the [`fabric_wire::Egress`] port for
//! in-process use, and is the shape a sidecar (`fabricd`) hosts once the drivers move out of the
//! box process. The matching JS wrappers (`inject_wrapper` + `js/*.js`) stay in `runlet-core`.
//!
//! See `docs/design/resource-egress.md`.

pub mod amq;
pub mod auth;
pub mod backendset;
pub mod db;
pub mod kv;
pub mod mail;
pub mod mongo;
pub mod resources;

pub use crate::backendset::{AsyncDeps, BackendSet};
pub use crate::resources::{ResolveError, ResolvedConfigs, ResourceBinding, resolve};
