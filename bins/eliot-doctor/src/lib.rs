#![forbid(unsafe_code)]

//! Doctor's binary crate intentionally exposes only the canonical contract
//! plus the single narrow admitted-effect composition surface. Admission
//! and physical execution belong to the authenticated Kernel client and the
//! shared governed process contour.

pub mod admitted_effect;

pub use eliot_doctor_core::*;
