//! Capability cell placeholder.
//!
//! NOT IMPLEMENTED. This file exists only so that per-crate
//! `cargo check`, `cargo test` and `cargo clippy` run and report an
//! actionable result instead of a manifest error.
//!
//! Cell `smart.context.candidates`, order 16.
//! The purpose, contract and dependencies of this cell live in
//! `module.toml` next to this crate. The owning work unit replaces this
//! file and, on completion, moves the crate from the root
//! `workspace.exclude` into `workspace.members`.

#![forbid(unsafe_code)]

// Contracts-only projection boundary proof (issue 38 acceptance 4).
//
// The candidate projection may only reference the versioned,
// store-neutral epistemic contract surface. This const binds the crate
// against `eliot-epistemic-contracts` without requiring the concrete
// resolver or the issue-604 providers (TaskFrame, cue-activation,
// negative-memory, affordance). The full candidate builder stays
// NOT_IMPLEMENTED.
const _CONTRACTS_BOUNDARY: fn() = || {
    let _ = eliot_epistemic_contracts::CONTRACT_NAME;
    let _ = core::mem::size_of::<eliot_epistemic_contracts::CurrentEpistemicPosition>();
    let _ = core::mem::size_of::<eliot_epistemic_contracts::PositionRequest>();
};
