//! Stateless MCP contract and core bridge for ELIOT.
//!
//! This crate owns no transport, process, database, session, task, admission,
//! authority, verification, or finish state. The host-facing request contract
//! carries only inert operation intent and correlation. Existing bound request
//! types remain Kernel/Governor-facing compatibility surfaces until the bridge
//! adapter and Kernel identity-binding units migrate under issue #77.

#![forbid(unsafe_code)]

mod contract;
mod core;
mod host;
mod host_gateway;
mod schema;

pub use contract::*;
pub use core::*;
pub use host::*;
pub use host_gateway::*;
pub use schema::*;

/// Stable package contract name.
pub const CONTRACT_NAME: &str = "eliot.surface.mcp";
/// Current package contract revision.
pub const CONTRACT_REVISION: &str = "1.2.0";
