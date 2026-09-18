//! Static module identity for the bounded self-quality diagnosis candidate.
//!
//! The digest binds the module, crate, agent order, layers, and the three
//! versioned self-quality schema identities from the normative #971 contract,
//! using the shared [`eliot_contracts::sha256_hex`] primitive.

use eliot_conformance_contracts::{
    SELF_QUALITY_CANDIDATE_SCHEMA, SELF_QUALITY_HANDOFF_SCHEMA, SELF_QUALITY_SCHEMA,
};

/// Canonical module identity of this diagnosis cell.
pub const MODULE_ID: &str = "meta.self_quality.diagnosis";
/// Cargo package name backing this module.
pub const CRATE_NAME: &str = "eliot-self-quality";
/// Cognitive-wave agent order of this module.
pub const META_AGENT_ORDER: u32 = 38;
/// Source layer of this module.
pub const SOURCE_LAYER: &str = "C1";
/// Runtime layer of this module.
pub const RUNTIME_LAYER: &str = "R7";
/// Causal property owned by this module.
pub const CAUSAL_PROPERTY: &str = "bounded self-quality diagnosis candidate";
/// Proof ceiling of this module: candidate-only diagnosis, nothing more.
pub const PROOF_CEILING: &str = "module-proof-only: candidate-only diagnosis without Concilium planning, vote tally, source acquisition, probe execution, mutation, authority, effect, store, provider, model, clock, or finish";

/// Compute the module identity digest.
///
/// The preimage is
/// `meta.self_quality.diagnosis|eliot-self-quality|38|C1|R7|eliot.self-quality.input.v1|eliot.self-quality.candidate.v1|eliot.self-quality.handoff.v1`,
/// hashed with [`eliot_contracts::sha256_hex`]. Pure: no clock, no I/O.
pub fn module_digest() -> String {
    eliot_contracts::sha256_hex(
        format!(
            "{MODULE_ID}|{CRATE_NAME}|{META_AGENT_ORDER}|{SOURCE_LAYER}|{RUNTIME_LAYER}|{SELF_QUALITY_SCHEMA}|{SELF_QUALITY_CANDIDATE_SCHEMA}|{SELF_QUALITY_HANDOFF_SCHEMA}"
        )
        .as_bytes(),
    )
}
