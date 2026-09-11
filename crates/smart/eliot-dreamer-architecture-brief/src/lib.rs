//! Deterministic, authority-preserving `ArchitectureBrief` projection.
//!
//! The crate is a pure candidate owner. It consumes the exact A-03
//! [`eliot_dreamer_contracts::SelfQueryInput`] closure, retains the complete supplied source closure,
//! and emits no acquisition, model, storage, authority, or canonical-write
//! effect.

#![forbid(unsafe_code)]

mod error;
mod projection;
mod synthesis;

pub use error::ArchitectureBriefError;
pub use projection::{ArchitectureBriefProjection, project_architecture_brief};
pub use synthesis::{
    DataAvailability, ModelSynthesis, MonetaryCostAvailability, RivalModels, RouteAvailability,
    RouteCostEnvelope,
};
