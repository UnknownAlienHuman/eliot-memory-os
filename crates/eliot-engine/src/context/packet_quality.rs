//! Packet quality finalization — deterministic scoring and identity for the context packet.
//!
//! This module owns the contiguous, source-proven packet-quality closure extracted
//! from `crates/eliot-engine/src/context.rs` (canonical parent `f71070b`,
//! `origin/main` `f71070b2455483fb102ab196566f9faab5cda1cb`):
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
//! # Canonical handles (verified from local authoritative docs)
//!
//! Source of truth for architecture/implementation handles is the current source
//! tree `docs/architecture/ELIOT_ARCHITECTURE.md` (`4.5-draft`) and
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` (`0.29-draft`), plus
//! `docs/architecture/INDEX.md` (`E:context-compiler`). The persistent graph
//! `eliot-memory-os-f71070b-live` (61020 nodes / 292342 edges) and docs project
//! `eliot-architecture-docs-*` are evidence/routing layers only and were
//! consulted before source inspection per worktree `AGENTS.md`.
//!
//! - Architecture: `A7.1` Active Understanding View, `A7.4` Context as
//!   intervention, `A7.6` Compaction & resume, `A7.9` Context economy.
//! - Implementation: `I7.11` Context payload profiles and Decision Safety Floor,
//!   `I7.26` Reversible payload budget and omission handles (each compiled view
//!   emits `PacketQualityScorecard`), `I7.19` Reactive context sequence,
//!   `I12.13`–`I12.17` orientation/bounded context/compaction.
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
