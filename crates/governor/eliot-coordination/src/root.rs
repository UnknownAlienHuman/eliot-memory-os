//! Production Governor coordination contract and owner.
//!
//! The established coordination implementation remains in `lib.rs`; this
//! composition root adds owner-local WorkLease issuance provenance without
//! rewriting the existing durable state machine or creating another owner.

#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod coordination;
mod work_lease_issuance;

pub use coordination::*;
pub use work_lease_issuance::*;
