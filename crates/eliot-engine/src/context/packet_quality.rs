//! Packet quality finalization — deterministic scoring and identity for the context packet.
//!
//! This module owns the contiguous packet-quality closure extracted
//! from `crates/eliot-engine/src/context.rs`:
//! `PacketQualityService` and its `finalize` plus directly owned private helper
//! `causal_bridge_missing_hops` in its quality/finalization block. Behavior,
//! serialization/hash/order/errors remain identical; no compiler, proof
//! validator, memory/provider/authority/write logic is moved.
//!
//! # Authority separation
//!
//! - **This child owns:** packet quality finalization — `PacketQualityService::finalize`
//!   deterministic packet-id hashing (`blake3` over `serde_json`), structured-bytes /
//!   token accounting, truth-coverage, causal-bridge completeness, suppression counts,
//!   signal density, and `PacketQualityReport` synthesis, plus helper
//!   `causal_bridge_missing_hops`. Pure deterministic computation; no I/O, store,
//!   provider, Dreamer, or authority decisions.
//! - **Parent retains:** `ContextCompiler`, `UnderstandingProofValidator`, `CognitiveGate`,
//!   `CompletionGate`, memory applicability / provider / authority / write logic, budget
//!   rendering, gate/admission, and all tests or unrelated helpers.
//! - **Semantic truth external:** `eliot-types` packet/report types and `EngineError`
//!   remain external contracts (`eliot-types`, `crate::error`).
//! - **No Dreamer / canonical-write / runtime authority:** no provider invocation,
//!   Dreamer orchestration, canonical store write, or service lifecycle is moved here.
//!
//! # Canonical handles
//!
//! Architecture: A7.1 (docs/architecture/A07-01-active-understanding-view.md#a71-active-understanding-view),
//! A7.4 (docs/architecture/A07-04-context-as-intervention.md#a74-context-as-intervention),
//! A7.6 (docs/architecture/A07-06-compaction-and-resume.md#a76-compaction-and-resume),
//! A7.9 (docs/architecture/A07-09-context-economy.md#a79-context-economy).
//! Implementation: I7.11 (docs/architecture/I07-11-context-payload-profiles-and-decision-safety-floor.md#i711-context-payload-profiles-and-decision-safety-floor),
//! I7.26 (docs/architecture/I07-26-reversible-payload-budget-and-omission-handles.md#i726-reversible-payload-budget-and-omission-handles),
//! I7.19 (docs/architecture/I07-19-reactive-context-sequence.md#i719-reactive-context-sequence),
//! I12.13 (docs/architecture/I12-13-context-compiler.md#i1213-context-compiler),
//! I12.14 (docs/architecture/I12-14-hot-path.md#i1214-hot-path),
//! I12.15 (docs/architecture/I12-15-bounded-spreading-activation.md#i1215-bounded-spreading-activation),
//! I12.16 (docs/architecture/I12-16-context-consistency.md#i1216-context-consistency),
//! I12.17 (docs/architecture/I12-17-compaction-and-resume.md#i1217-compaction-and-resume).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! # Import policy
//!
//! Exact direct imports are derived from the current `context.rs` source for
//! this closure only; no provider, Dreamer, canonical-write, or runtime
//! authority imports are introduced.

use eliot_types::{ContextPacketL3, MaterialPacketFrame, PacketQualityReport, PacketQualityResult};

use crate::EngineError;

#[derive(Clone, Copy, Debug, Default)]
pub struct PacketQualityService;

impl PacketQualityService {
    #[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
    pub fn finalize(
        packet: &mut ContextPacketL3,
        frame: Option<&MaterialPacketFrame>,
    ) -> Result<(), EngineError> {
        let frame = frame.cloned().unwrap_or_default();
        packet.packet_quality = None;
        packet.packet_id.clear();
        let content = serde_json::to_vec(packet)?;
        packet.packet_id = format!("eliot/packet/{}", blake3::hash(&content).to_hex());
        let structured_bytes = serde_json::to_vec(packet)?.len();
        let truth_total = packet.current_truth.len()
            + packet.relevant_supported_claims.len()
            + packet.weak_claims_warning.len()
            + packet.open_questions.len();
        let current_truth_coverage = if truth_total == 0 {
            0.0
        } else {
            packet.current_truth.len() as f32 / truth_total as f32
        };
        let causal_bridge_missing_hops = causal_bridge_missing_hops(packet.causal_bridge.len());
        let stale_items_suppressed = packet
            .memory_applicability
            .suppression_reasons
            .iter()
            .filter(|reason| !reason.contains("scope_mismatch"))
            .count();
        let wrong_scope_items_suppressed = packet
            .memory_applicability
            .suppression_reasons
            .iter()
            .filter(|reason| reason.contains("scope_mismatch"))
            .count();
        let signal_items = packet.current_truth.len()
            + packet.causal_bridge.len()
            + packet
                .decision_locality_suffix
                .exact_load_bearing_atoms
                .len()
            + usize::from(!packet.decision_locality_suffix.verifier.is_empty());
        let signal_density = if structured_bytes == 0 {
            0.0
        } else {
            (signal_items as f32 * 128.0 / structured_bytes as f32).min(1.0)
        };
        let task_frame_present =
            !packet.goal.trim().is_empty() && !packet.acceptance_items.is_empty();
        let verifier_present = !packet.decision_locality_suffix.verifier.trim().is_empty();
        let material_suffix_present = !packet
            .decision_locality_suffix
            .next_allowed_action
            .trim()
            .is_empty()
            && !packet
                .decision_locality_suffix
                .expected_observable
                .trim()
                .is_empty()
            && !packet
                .decision_locality_suffix
                .stop_condition
                .trim()
                .is_empty();
        let result = if !task_frame_present
            || packet.current_truth_snapshot.is_none()
            || !frame.negative_memory_checked
            || !verifier_present
            || !material_suffix_present
        {
            PacketQualityResult::Insufficient
        } else if !causal_bridge_missing_hops.is_empty()
            || current_truth_coverage < 0.5
            || packet
                .decision_locality_suffix
                .exact_load_bearing_atoms
                .is_empty()
        {
            PacketQualityResult::Degraded
        } else {
            PacketQualityResult::Sufficient
        };
        let report = PacketQualityReport {
            packet_id: packet.packet_id.clone(),
            task_id: packet.task_id.clone(),
            revision_fence: packet.at_revision,
            structured_bytes,
            estimated_tokens: structured_bytes.div_ceil(4),
            task_frame_present,
            current_truth_coverage,
            causal_bridge_hops: packet.causal_bridge.len(),
            causal_bridge_missing_hops,
            negative_memory_checked: frame.negative_memory_checked,
            exact_atoms_count: packet
                .decision_locality_suffix
                .exact_load_bearing_atoms
                .len(),
            material_unknowns: packet.decision_locality_suffix.open_unknowns.len(),
            verifier_present,
            stale_items_suppressed,
            wrong_scope_items_suppressed,
            tool_schema_bytes_visible: frame.tool_schema_bytes_visible,
            instruction_hotset_size: frame.instruction_hotset_size,
            signal_density,
            result,
        };
        packet.packet_quality = Some(report);
        Ok(())
    }
}

fn causal_bridge_missing_hops(hops: usize) -> Vec<String> {
    [
        "intent_to_owner",
        "owner_to_symbol_or_config",
        "symbol_or_config_to_runtime_or_artifact",
        "runtime_or_artifact_to_verifier",
    ]
    .into_iter()
    .skip(hops.min(4))
    .map(str::to_owned)
    .collect()
}
