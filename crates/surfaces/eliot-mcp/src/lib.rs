//! Stateless MCP contract and core bridge for ELIOT.
//!
//! This crate owns no transport, process, database, session, task, admission,
//! authority, verification, or finish state. Every call carries an explicit
//! application binding and is forwarded to an injected Kernel/Governor port.

#![forbid(unsafe_code)]

mod contract;
mod core;
mod schema;

pub use contract::*;
pub use core::*;
pub use schema::*;

/// Stable package contract name.
pub const CONTRACT_NAME: &str = "eliot.surface.mcp";
/// Current package contract revision.
pub const CONTRACT_REVISION: &str = "1.0.0";
