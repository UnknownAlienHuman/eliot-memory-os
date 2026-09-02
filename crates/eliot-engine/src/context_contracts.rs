//! Typed packet-context contract — input, audit, and budget values for the context compiler.
//!
//! This module owns the contiguous typed packet-context contract extracted from
//! the top of `crates/eliot-engine/src/context.rs`: `PacketBudgetPolicy` and its
//! `impl`; `PacketRenderMode`; `PacketBudgetDecision`; `PacketCompileAudit`;
//! `PacketCompileAuditContext`; `PacketCompileAuditReport`;
//! `PacketSourceReadAudit`; `PacketCandidateOutcome`; `PacketRenderOutcome`;
//! `PacketCompileMode`; `PacketResolvedCues` and its `impl`;
//! `PacketPyramidSnapshot`; `PacketPyramidSource`; `PacketExperienceSource`;
//! `PacketTaskReceiptMetadata`; `PacketMeasurementView`; private
//! `PacketMeasurementAssignmentStatus`; and `PacketCompilePlan`.
//! `DEFAULT_PACKET_HARD_CEILING_TOKENS` remains defined in the parent `context`
//! module to keep one canonical ceiling definition.
//!
//! # Authority separation
//!
//! - **This child owns:** typed packet input, audit, and budget contract data.
//!   These are pure deterministic data types with no I/O, provider, Dreamer, or
//!   write authority.
//! - **Compiler remains in parent:** `context::ContextCompiler` and all
//!   `compile_*`, `finalize_*`, budget, gate, and admission functions retain
//!   compilation and gate/admission authority.
//! - **Semantic truth remains external:** understanding, experience, and pyramid
//!   semantics remain owned by their declared compilers and contracts.
//! - **No Dreamer / canonical-write / runtime authority:** no provider
//!   invocation, Dreamer orchestration, canonical store write, or service
//!   lifecycle code is moved here.
//!
//! # Current documentation authority
//!
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A7.1`, `A7.4`, `A7.6`, and
//!   `A7.9`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I7.11`, `I7.19`, `I7.26`,
//!   and `I12.13..I12.17`.
//! - `docs/architecture/INDEX.md`: `E:context-compiler` navigation.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! # Import policy
//!
//! Exact direct imports are derived from the current parent source for this
//! closure only; no provider, Dreamer, canonical-write, or runtime authority
//! imports are introduced.

use std::collections::BTreeMap;

use serde_json::Value;

use eliot_types::memory::GovernedGitScope;
use eliot_types::{
    CausalBridgeHop, CodeCortexReport, CompilePacketL3Request, ContextPacketL3, CoverageClass,
    ExperienceCase, MaterialPacketFrame, MemoryExposureMode, MemoryRevision,
    ProjectUnderstandingEvidence, ProjectUnderstandingModel, SessionId, TaskContract,
    UlInjectionMode, UlMetacognitionView, UlTaskClass,
};

use super::DEFAULT_PACKET_HARD_CEILING_TOKENS;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketBudgetPolicy {
    pub preferred_tokens: usize,
    pub hard_ceiling_tokens: usize,
    pub supplement_tokens: usize,
}

impl PacketBudgetPolicy {
    #[must_use]
    pub const fn governor_default(preferred_tokens: usize) -> Self {
        Self {
            preferred_tokens,
            hard_ceiling_tokens: DEFAULT_PACKET_HARD_CEILING_TOKENS,
            supplement_tokens: 0,
        }
    }

    #[must_use]
    pub const fn with_supplement_tokens(mut self, supplement_tokens: usize) -> Self {
        self.supplement_tokens = supplement_tokens;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketRenderMode {
    WithinPreferred,
    PreferredBudgetExceededByMandatoryFloor,
    PreferredBudgetClampedToHardCeiling,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketBudgetDecision {
    pub preferred_tokens: usize,
    pub hard_ceiling_tokens: usize,
    pub supplement_tokens: usize,
    pub budget_metadata_tokens: usize,
    pub packet_mandatory_floor_tokens: usize,
    pub mandatory_floor_tokens: usize,
    pub effective_tokens: usize,
    pub estimated_tokens: usize,
    pub render_mode: PacketRenderMode,
    pub section_tokens: BTreeMap<String, usize>,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketCompileAudit {
    pub project_understanding_compiles: usize,
    pub budget_renders: usize,
    pub identity_finalizations: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketCompileAuditContext {
    pub stages: Vec<String>,
    pub source_reads: PacketSourceReadAudit,
    pub read_counters: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketCompileAuditReport {
    pub stages: Vec<String>,
    pub source_reads: PacketSourceReadAudit,
    pub semantic: PacketCompileAudit,
    pub read_counters: BTreeMap<String, usize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketSourceReadAudit {
    pub current_state_reads: usize,
    pub l0_reads: usize,
    pub l2_reads: usize,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PacketCandidateOutcome {
    pub packet: ContextPacketL3,
    pub read_audit: PacketSourceReadAudit,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PacketRenderOutcome {
    pub packet: ContextPacketL3,
    pub project_understanding: ProjectUnderstandingModel,
    pub budget: PacketBudgetDecision,
    pub audit: PacketCompileAudit,
    pub compile_audit: PacketCompileAuditReport,
}

/// Execution class resolved before any memory-bearing packet source is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketCompileMode {
    Production,
    ShadowEvaluation,
    CertificationTreatment,
    CertificationControl,
}

/// Recall cues resolved before packet construction. Certification control must
/// provide the empty value so cue memory cannot be reached accidentally.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketResolvedCues {
    pub task_class_cues: Vec<String>,
    pub scope_refs: Vec<String>,
    pub concept_refs: Vec<String>,
}

impl PacketResolvedCues {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.task_class_cues.is_empty()
            && self.scope_refs.is_empty()
            && self.concept_refs.is_empty()
    }
}

/// Revision-fenced, already-resolved pyramid input. The compiler owns how this
/// source affects the packet, understanding, gate, and returned supplement.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketPyramidSnapshot {
    pub at_revision: MemoryRevision,
    pub understanding: Value,
    pub bridge: Vec<CausalBridgeHop>,
    pub metacognition: UlMetacognitionView,
    pub coverage: CoverageClass,
    pub blind_target: Option<String>,
    pub recommended_probe: Option<String>,
    pub subsystem_concept_id: Option<String>,
    pub required_invariant_refs: Vec<String>,
    pub project_evidence: ProjectUnderstandingEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PacketPyramidSource {
    /// Required for memory-free control.
    Forbidden,
    Unavailable {
        reason: String,
    },
    Resolved(Box<PacketPyramidSnapshot>),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "status", content = "cases", rename_all = "snake_case")]
pub enum PacketExperienceSource {
    /// Required for memory-free control.
    Forbidden,
    /// Raw source candidates. Need classification, deduplication, exposure
    /// filtering, applicability, and brief construction remain engine-owned.
    Cases(Vec<ExperienceCase>),
}

/// Task receipt material which is known before packet persistence and therefore
/// must participate in the complete returned-surface budget.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketTaskReceiptMetadata {
    pub exact_evidence_refs: Vec<String>,
    pub registered_verifiers: Vec<Value>,
}

/// Optional deterministic measurement view. It is response metadata, not a
/// source of packet semantics, but is still included in supplement accounting.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketMeasurementView {
    pub task_class: UlTaskClass,
    pub assignment_injection_mode: UlInjectionMode,
    pub effective_injection_mode: Option<UlInjectionMode>,
    pub config_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PacketMeasurementAssignmentStatus {
    PostCommitMeasurement,
    NotAssignedCounterfactual,
    NotAssignedRejected,
}

/// Complete compiler input resolved before candidate construction.
#[derive(Clone, Debug)]
pub struct PacketCompilePlan {
    pub request: CompilePacketL3Request,
    pub session_id: SessionId,
    pub compile_mode: PacketCompileMode,
    pub memory_exposure: MemoryExposureMode,
    pub task_contract: Option<TaskContract>,
    pub task_receipt_metadata: Option<PacketTaskReceiptMetadata>,
    pub previous_packet: Option<ContextPacketL3>,
    pub material_frame: Option<MaterialPacketFrame>,
    pub codecortex_reports: Vec<CodeCortexReport>,
    pub current_git_scope: Option<GovernedGitScope>,
    pub touched_paths: Vec<String>,
    pub resolved_cues: PacketResolvedCues,
    pub pyramid_source: PacketPyramidSource,
    pub experience_source: PacketExperienceSource,
    pub budget_policy: PacketBudgetPolicy,
    pub measurement_view: Option<PacketMeasurementView>,
}
