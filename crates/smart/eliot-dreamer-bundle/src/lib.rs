//! Native ingress boundary for bounded Dreamer input assembly.
//!
//! This crate owns assembly orchestration only. Canonical job, recipe,
//! material, Context, measurement and result shapes remain in their owning
//! contract crates.

#![forbid(unsafe_code)]

mod assembly;
mod budget;
mod finalization;
mod input;
mod packing;
mod recipe;

pub use assembly::AssemblyPlan;
pub use finalization::{AssemblyFinalObservations, finalize_bundle, plan_bundle};
pub use input::{AssemblyPolicy, AssemblyRequest, SuppliedAssemblyItem, SuppliedItemState};
