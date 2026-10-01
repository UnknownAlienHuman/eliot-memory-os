//! Typed packet-context contract — input, audit, and budget values for the context compiler.
//!
//! This module owns the contiguous, source-proven typed packet-context contract
//! closure extracted from the top of `crates/eliot-engine/src/context.rs`:
//! `PacketBudgetPolicy` and its `impl`; `PacketRenderMode`; `PacketBudgetDecision`;
//! `PacketCompileAudit`; `PacketCompileAuditContext`; `PacketCompileAuditReport`;
//! `PacketSourceReadAudit`; `PacketCandidateOutcome`; `PacketRenderOutcome`;
//! `PacketCompileMode`; `PacketResolvedCues` and its `impl`; `PacketPyramidSnapshot`;
//! `PacketPyramidSource`; `PacketExperienceSource`; `PacketTaskReceiptMetadata`;
//! `PacketMeasurementView`; private `PacketMeasurementAssignmentStatus`; and
//! `PacketCompilePlan`. `DEFAULT_PACKET_HARD_CEILING_TOKENS` remains defined in the
//! parent `context` module (narrow `super::` import) to keep the single canonical
//! ceiling definition.
//!
//! # Authority separation
//!
//! - **This child owns:** typed packet input / audit / budget contract data — the
//!   budget policy, render mode/decision, audit counters, source-read audit,
//!   candidate/render outcomes, compile mode, resolved cues, pyramid/experience
//!   sources, task-receipt metadata, measurement view, and the complete
//!   `PacketCompilePlan` value object. These are pure data types with
//!   deterministic derives and serde shape; they carry no I/O, provider,
//!   Dreamer, or write authority.
//! - **Compiler remains in parent:** `context::ContextCompiler` and all
//!   `compile_*` / `finalize_*` / budget / gate / admission functions retain
//!   compilation, token-budget rendering, and gate/admission authority. This
//!   module does not decide `PacketGate` / `Admission` / `Prediction` /
//!   `CompileResult` semantics and does not own the runtime read path.
//! - **Semantic truth remains external:** understanding, experience, and pyramid
//!   semantics remain owned by `ProjectUnderstandingCompiler`, semantic-memory,
//!   and `eliot-types` contracts; this contract only transports typed snapshots
//!   and revision-fenced handles.
//! - **No Dreamer / canonical-write / runtime authority:** no provider
//!   invocation, Dreamer orchestration, canonical store write, or service
//!   lifecycle code is moved here.
//!
//! Architecture: `A7.1` (`docs/architecture/A07-01-active-understanding-view.md`),
//! `A7.4` (`docs/architecture/A07-04-context-as-intervention.md`), `A7.6`
//! (`docs/architecture/A07-06-compaction-and-resume.md`), and `A7.9`
//! (`docs/architecture/A07-09-context-economy.md`). Implementation: `I7.11`
//! (`docs/architecture/I07-11-context-payload-profiles-and-decision-safety-floor.md`),
//! `I7.19` (`docs/architecture/I07-19-reactive-context-sequence.md`), `I7.26`
//! (`docs/architecture/I07-26-reversible-payload-budget-and-omission-handles.md`),
//! and `I12.13` (`docs/architecture/I12-13-context-compiler.md`),
//! `I12.17` (`docs/architecture/I12-17-compaction-and-resume.md`). Normative
//! precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! - Architecture: `A7.1` Active Understanding View, `A7.4` Context as
//!   intervention, `A7.6` Compaction & resume, `A7.9` Context economy.
//! - Implementation: `I7.11` Context payload profiles and Decision Safety Floor,
//!   `I7.19` Reactive context sequence, `I7.26` Reversible payload budget and
//!   omission handles, `I12.13`–`I12.17` orientation/bounded context/compaction.
//!
//! # Import policy
//!
//! Exact direct imports are derived from the current `context.rs` source for
//! this closure only; no provider, Dreamer, canonical-write, or runtime
//! authority imports are introduced.

use std::collections::BTreeMap;

use eliot_context_contracts::{ContextError, MeasurementStatus, StuEstimate};
use eliot_context_measurement::{MAX_MEASUREMENT_BYTES, stu_for_bytes, validate_envelope};
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
    /// Legacy numeric planning projection of the packet budget plus the named
    /// supplement and return-metadata allowances. The exact whole-packet STU
    /// measurement is retained separately in `stu_estimate`; neither value is
    /// an observed tokenizer count or proof of route fit.
    pub estimated_tokens: usize,
    /// Exact final packet UTF-8 byte length, bound to the serializer profile
    /// and content digest below. This compiler has no route/model input, so it
    /// cannot become a full #584 receipt.
    pub rendered_utf8_bytes: u64,
    /// Serializer identity used for the exact `ContextPacketL3` envelope.
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    /// Domain-separated digest of serializer identity, version and options.
    pub serializer_profile_digest: String,
    /// SHA-256 of the exact final serialized packet. Mutating packet bytes
    /// invalidates this binding and must be caught by `validate_packet_envelope`.
    pub content_digest: String,
    /// Canonical #704 STU estimate; empirical is false without a tokenizer observation.
    pub stu_estimate: StuEstimate,
    /// Actual route-tokenizer count, absent because no bound route observation is available.
    pub actual_tokens: Option<u64>,
    /// Measured fit is unknown until a route-bound tokenizer observation exists.
    pub measured_fit: Option<bool>,
    /// `ConservativeStu` records exact-byte plus unvalidated-STU evidence only;
    /// route binding and tokenizer observation remain unavailable.
    pub measurement_status: MeasurementStatus,
    pub render_mode: PacketRenderMode,
    pub section_tokens: BTreeMap<String, usize>,
    pub reason: String,
}

impl PacketBudgetDecision {
    /// Revalidate an envelope against the original exact-byte/profile binding.
    /// This never creates or repairs a binding: changed bytes, profile, STU,
    /// actual-token claims, or fit claims are rejected.
    pub fn validate_packet_envelope(&self, serialized: &[u8]) -> Result<(), ContextError> {
        let (serializer_id, serializer_version, options_digest, profile_digest) =
            packet_serializer_binding();
        if self.serializer_id != serializer_id
            || self.serializer_version != serializer_version
            || self.serializer_options_digest != options_digest
            || self.serializer_profile_digest != profile_digest
        {
            return Err(ContextError::IdentityConflict);
        }
        if self.actual_tokens.is_some()
            || self.measured_fit.is_some()
            || self.measurement_status != MeasurementStatus::ConservativeStu
            || self.stu_estimate.empirical
        {
            return Err(ContextError::UnknownMeasurement);
        }
        let envelope = validate_envelope(
            serialized,
            self.rendered_utf8_bytes,
            &self.content_digest,
            MAX_MEASUREMENT_BYTES,
        )?;
        let stu = stu_for_bytes(envelope.byte_len)?;
        // Read the original owner projection from the exact validated packet
        // bytes. Supplements and return metadata are separate planning costs,
        // not a claim that separately rounded parts measure the whole envelope.
        let packet: eliot_types::ContextPacketL3 =
            serde_json::from_slice(serialized).map_err(|_| ContextError::IdentityConflict)?;
        let legacy_total = packet
            .token_budget_report
            .estimated_tokens
            .checked_add(self.supplement_tokens)
            .and_then(|value| value.checked_add(self.budget_metadata_tokens))
            .ok_or(ContextError::Overflow)?;
        if self.stu_estimate.value != stu || self.estimated_tokens != legacy_total {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

pub(super) fn packet_serializer_binding() -> (String, String, String, String) {
    const SERIALIZER_ID: &str = "serde_json";
    const SERIALIZER_VERSION: &str = "eliot-context-packet-l3/v1";
    const SERIALIZER_OPTIONS: &[u8] =
        b"serde_json::to_vec; compact JSON; default serializer options; UTF-8";
    let options_digest = eliot_contracts::sha256_hex(SERIALIZER_OPTIONS);
    let profile_digest = eliot_contracts::sha256_hex(
        format!("{SERIALIZER_ID}\0{SERIALIZER_VERSION}\0{options_digest}").as_bytes(),
    );
    (
        SERIALIZER_ID.to_owned(),
        SERIALIZER_VERSION.to_owned(),
        options_digest,
        profile_digest,
    )
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
