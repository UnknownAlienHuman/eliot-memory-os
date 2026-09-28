//! Stateless MCP contract and core bridge for ELIOT.
//!
//! This crate owns no transport, process, database, session, task, admission,
//! authority, verification, or finish state. The host-facing request contract
//! carries only inert operation intent and correlation.

#![forbid(unsafe_code)]

mod act_owner_input;
mod canonical_tool_source;
mod contract;
mod core;
mod host;
mod host_gateway;
mod schema;
mod semantic_profile;
mod surface_decision;

pub use act_owner_input::*;
pub use contract::*;
pub use core::*;
pub use host::*;
pub use host_gateway::*;
pub use schema::*;
pub use semantic_profile::*;
pub use surface_decision::*;

/// Stable package contract name.
pub const CONTRACT_NAME: &str = "eliot.surface.mcp";
/// Current package contract revision.
pub const CONTRACT_REVISION: &str = "1.2.0";
