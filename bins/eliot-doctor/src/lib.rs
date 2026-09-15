#![forbid(unsafe_code)]

//! Doctor's binary crate intentionally exposes only the canonical contract,
//! the single narrow admitted-effect composition surface, and the production
//! one-shot composition seam (local dispatch authority, bins-local dispatch
//! material, and the authenticated Kernel-client drive). Admission and
//! physical execution belong to the authenticated Kernel client and the
//! shared governed process contour; the `tests/` second-consumer proof
//! imports this same seam instead of compiling a second copy, which would
//! fork the types and void the proof.

pub mod admitted_effect;
pub mod dispatch_authority;
pub mod dispatched_material;
pub mod kernel_client;

pub use eliot_doctor_core::*;
