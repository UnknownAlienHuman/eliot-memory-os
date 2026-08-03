use crate::project_understanding::{ProjectContinuityService, ProjectUnderstandingCompiler};
use crate::semantic_memory::{
    ExperienceRetrievalService, MemoryNeedService, deduplicate_experience_cases,
};
use crate::task_execution::TaskExecutionClassifier;
use crate::ul::{normalize_verifier, parse_expected_observable, prediction_id_for};
use crate::{
    EngineError, ReadService, SkillActivationContext, SkillCuratorService,
    SkillDistractorFilterService, StopCoordinationGate, WorkState, WriteAdmissionService,
    WriterHandle,
};
use eliot_types::memory::{
    CurrentGitScopeView, GovernedGitScope, MemoryApplicabilityDecision,
    MemoryApplicabilityDisposition, MemoryApplicabilityPacketView, MemoryProvenanceView,
};
use eliot_types::{
    CandidateDiffStatus, CandidateReviewDecision, CausalBridgeHop, ClaimCard, CodeCortexPacketView,
    CodeCortexReport, CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason,
    CognitiveGateRequest, CompilePacketL3Request, CompletionGateDecision, CompletionProof,
    CompletionStatus, ContextPacketL3, CoverageClass, CurrentStateRequest, CurrentStateResponse,
    CurrentTruthSnapshot, DecisionLocalitySuffix, EpistemicPacketState, EpistemicStatus,
    ExperienceCase, ExperienceRecallRequest, FetchAtomsL2Request, FetchAtomsL2Response,
    MaterialPacketFrame, MemoryAdmissionDecision, MemoryDecisionReceipt, MemoryExposureMode,
    MemoryExposurePolicy, MemoryLifecyclePacketView, MemoryRevision, PacketQualityReport,
    PacketQualityResult, PredictionConfidence, ProjectId, ProjectUnderstandingEvidence,
    ProjectUnderstandingModel, ReadConsistencyMode, RecallL0Request, RecallL0Response, SessionId,
    SkillCardV2, TaskContract, TaskId, TaskMeaningFrame, TokenBudgetReport, TruncationInfo,
    UlExperimentArm, UlInjectionMode, UlMetacognitionView, UlPrediction, UlTaskClass,
    UnderstandingProof, UnderstandingProofReceipt, VerifierArtifactRef, VerifierStatus, WorkItem,
    WorkItemStatus, WorkLease, WorkLeaseState,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use time::OffsetDateTime;

pub const DEFAULT_PACKET_HARD_CEILING_TOKENS: usize = 4_096;

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
enum PacketMeasurementAssignmentStatus {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketGateStatus {
    Allow,
    RequireProbe,
    RequirePacketRefresh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketGateReason {
    BlindSubsystem,
    MissingCapsuleInvariants,
    PyramidUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketGateCandidate {
    pub status: PacketGateStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<PacketGateReason>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_invariant_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concept_or_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_probe: Option<String>,
}

impl PacketGateCandidate {
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            status: PacketGateStatus::Allow,
            reason: None,
            missing_invariant_refs: Vec::new(),
            concept_or_path: None,
            suggested_probe: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketAdmissionStatus {
    Admitted,
    AdmittedDegraded,
    Counterfactual,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
// These independent authority flags are an explicit serialized decision
// surface; collapsing them would hide which capability the gate withheld.
#[allow(clippy::struct_excessive_bools)]
pub struct PacketAdmissionDecision {
    pub status: PacketAdmissionStatus,
    pub active_allowed: bool,
    pub continuity_allowed: bool,
    pub influence_authority_allowed: bool,
    pub counterfactual_only: bool,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PacketPredictionIntent {
    pub prediction_ref: String,
    pub prediction: UlPrediction,
    pub confidence: Option<PredictionConfidence>,
    pub subsystem_concept_id: Option<String>,
    pub source_frame_hash: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PacketCompileResult {
    pub packet: ContextPacketL3,
    pub project_understanding: ProjectUnderstandingModel,
    pub gate: PacketGateCandidate,
    pub admission: PacketAdmissionDecision,
    pub budget: PacketBudgetDecision,
    pub prediction_intents: Vec<PacketPredictionIntent>,
    pub response_supplement: Value,
    pub compile_audit: PacketCompileAuditReport,
    pub read_audit: PacketSourceReadAudit,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, thiserror::Error)]
#[error("PACKET_COMPILE_PLAN_INVALID: {reason}")]
pub struct PacketCompilePlanInvalid {
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, thiserror::Error)]
#[error(
    "PACKET_HARD_CEILING_EXCEEDED: mandatory floor {mandatory_floor_tokens} exceeds hard ceiling {hard_ceiling_tokens} (preferred {preferred_tokens})"
)]
pub struct PacketHardCeilingExceeded {
    pub preferred_tokens: usize,
    pub hard_ceiling_tokens: usize,
    pub mandatory_floor_tokens: usize,
    pub section_tokens: BTreeMap<String, usize>,
    pub expansion_handles: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PacketCompileError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    HardCeiling(#[from] PacketHardCeilingExceeded),
    #[error(transparent)]
    InvalidPlan(#[from] PacketCompilePlanInvalid),
}

#[derive(Clone, Debug)]
pub struct ContextCompiler {
    read: ReadService,
}

impl ContextCompiler {
    pub const fn new(read: ReadService) -> Self {
        Self { read }
    }

    /// Compiles the complete packet surface from one pre-resolved plan. The
    /// exposure branch is selected before `read_context`, project understanding
    /// is compiled once, and all deterministic response supplements participate
    /// in the same Governor budget decision.
    pub async fn compile_plan(
        &self,
        plan: PacketCompilePlan,
    ) -> Result<PacketCompileResult, PacketCompileError> {
        validate_packet_compile_plan(&plan)?;
        let memory_free_control = plan.memory_exposure == MemoryExposureMode::MemoryFreeControl;
        let candidate = self
            .compile_plan_candidate(&plan, memory_free_control)
            .await?;
        let read_audit = candidate.read_audit;
        let mut packet = candidate.packet;
        let (pyramid, project_evidence) =
            attach_packet_plan_sources(&plan, &mut packet, memory_free_control)?;

        let required_invariant_refs = pyramid.map_or_else(Vec::new, |snapshot| {
            snapshot.required_invariant_refs.clone()
        });
        let mut prepared_packet = prepare_packet_candidate(
            &packet,
            plan.material_frame.as_ref(),
            plan.task_contract.as_ref(),
            &project_evidence,
            plan.previous_packet.as_ref(),
        );
        let gate = packet_gate_candidate(
            &plan.pyramid_source,
            plan.compile_mode,
            plan.material_frame.as_ref(),
            &plan.touched_paths,
            &prepared_packet,
        );
        let admission = packet_admission_decision(&gate, plan.compile_mode);
        let prediction_specs = packet_prediction_specs(plan.material_frame.as_ref());
        let mut response_supplement = packet_response_supplement(
            &plan,
            &prepared_packet,
            &required_invariant_refs,
            &gate,
            &admission,
            prediction_specs.len(),
        )?;
        let supplement_tokens = serialized_supplement_tokens(&response_supplement)?;
        let budget_policy = plan.budget_policy.with_supplement_tokens(supplement_tokens);
        let audit_context = PacketCompileAuditContext {
            stages: [
                "plan_resolved",
                "source_candidate_assembled",
                "experience_attached_or_forbidden",
                "pyramid_attached_or_forbidden",
                "project_understanding_compiled",
                "gate_decided",
                "budget_rendered",
                "identity_finalized",
                "admission_decided",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            source_reads: read_audit,
            read_counters: BTreeMap::from([
                ("l0".to_owned(), read_audit.l0_reads),
                ("l2".to_owned(), read_audit.l2_reads),
                ("pyramid".to_owned(), usize::from(pyramid.is_some())),
                ("experience".to_owned(), usize::from(!memory_free_control)),
                ("skill".to_owned(), 0),
            ]),
        };
        let rendered = finalize_precompiled_packet_with_policy_and_audit_context(
            &mut prepared_packet,
            plan.material_frame.as_ref(),
            budget_policy,
            &plan.request.candidate_handles,
            audit_context,
        )?;
        let prediction_intents =
            finalize_packet_prediction_intents(&plan, pyramid, &rendered.packet, prediction_specs)?;
        finalize_response_supplement(
            &mut response_supplement,
            &rendered.packet,
            &prediction_intents,
        );
        let final_supplement_tokens = serialized_supplement_tokens(&response_supplement)?;
        if final_supplement_tokens != supplement_tokens {
            return Err(PacketCompilePlanInvalid {
                reason: format!(
                    "final response supplement changed token shape: planned {supplement_tokens}, final {final_supplement_tokens}"
                ),
            }
            .into());
        }
        Ok(PacketCompileResult {
            packet: rendered.packet,
            project_understanding: rendered.project_understanding,
            gate,
            admission,
            budget: rendered.budget,
            prediction_intents,
            response_supplement,
            compile_audit: rendered.compile_audit,
            read_audit,
        })
    }

    async fn compile_plan_candidate(
        &self,
        plan: &PacketCompilePlan,
        memory_free_control: bool,
    ) -> Result<PacketCandidateOutcome, EngineError> {
        if memory_free_control {
            return Ok(Self::compile_control_unfinalized(
                &plan.request,
                &plan.codecortex_reports,
                plan.current_git_scope.as_ref(),
                plan.material_frame.as_ref(),
            ));
        }
        self.compile_unfinalized_with_cues(
            &plan.request,
            &plan.codecortex_reports,
            plan.current_git_scope.as_ref(),
            plan.material_frame.as_ref(),
            &plan.resolved_cues,
        )
        .await
    }

    pub async fn compile(
        &self,
        request: &CompilePacketL3Request,
    ) -> Result<ContextPacketL3, EngineError> {
        self.compile_context(request, &[], None, None).await
    }

    pub async fn compile_with_codecortex(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
    ) -> Result<ContextPacketL3, EngineError> {
        self.compile_context(request, codecortex_reports, None, None)
            .await
    }

    pub async fn compile_material(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        frame: &MaterialPacketFrame,
    ) -> Result<ContextPacketL3, EngineError> {
        self.compile_context(request, codecortex_reports, None, Some(frame))
            .await
    }

    pub async fn compile_with_governed_git_scope(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: &GovernedGitScope,
    ) -> Result<ContextPacketL3, EngineError> {
        self.compile_context(request, codecortex_reports, Some(current_git_scope), None)
            .await
    }

    pub async fn compile_material_with_governed_git_scope(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: &GovernedGitScope,
        frame: &MaterialPacketFrame,
    ) -> Result<ContextPacketL3, EngineError> {
        self.compile_context(
            request,
            codecortex_reports,
            Some(current_git_scope),
            Some(frame),
        )
        .await
    }

    async fn compile_context(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: Option<&GovernedGitScope>,
        frame: Option<&MaterialPacketFrame>,
    ) -> Result<ContextPacketL3, EngineError> {
        let mut packet = self
            .compile_unfinalized(request, codecortex_reports, current_git_scope, frame)
            .await?;
        packet.project_understanding = Some(ProjectUnderstandingCompiler::compile(
            &packet,
            frame,
            None,
            &ProjectUnderstandingEvidence::default(),
        ));
        enforce_budget(&mut packet, request.max_tokens, &request.candidate_handles)?;
        PacketQualityService::finalize(&mut packet, frame)?;
        Ok(packet)
    }

    /// Builds the source-owned packet candidate without project understanding,
    /// attention-budget rendering, quality, or semantic identity finalization.
    ///
    /// Callers that already resolved the task contract and project evidence can
    /// pass this candidate to [`finalize_packet_candidate`].
    pub async fn compile_unfinalized(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: Option<&GovernedGitScope>,
        frame: Option<&MaterialPacketFrame>,
    ) -> Result<ContextPacketL3, EngineError> {
        Ok(self
            .compile_unfinalized_with_exposure(
                request,
                codecortex_reports,
                current_git_scope,
                frame,
                MemoryExposureMode::MatureExperienceOnly,
            )
            .await?
            .packet)
    }

    /// Builds an unfinalized candidate under an exposure mode selected before
    /// retrieval. `MemoryFreeControl` bypasses every current-state, L0, and L2
    /// read; it never loads a memory-bearing candidate and clears nothing after
    /// the fact.
    pub async fn compile_unfinalized_with_exposure(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: Option<&GovernedGitScope>,
        frame: Option<&MaterialPacketFrame>,
        memory_exposure: MemoryExposureMode,
    ) -> Result<PacketCandidateOutcome, EngineError> {
        if memory_exposure == MemoryExposureMode::MemoryFreeControl {
            return Ok(Self::compile_control_unfinalized(
                request,
                codecortex_reports,
                current_git_scope,
                frame,
            ));
        }

        self.compile_unfinalized_with_cues(
            request,
            codecortex_reports,
            current_git_scope,
            frame,
            &PacketResolvedCues::default(),
        )
        .await
    }

    async fn compile_unfinalized_with_cues(
        &self,
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: Option<&GovernedGitScope>,
        frame: Option<&MaterialPacketFrame>,
        resolved_cues: &PacketResolvedCues,
    ) -> Result<PacketCandidateOutcome, EngineError> {
        let (reads, read_audit) = self.read_context(request, resolved_cues).await?;
        let scope_claims = reads.fetch.claims.clone();
        let filters = normalized_filter(&request.candidate_handles);
        let buckets = bucket_claims(&reads.fetch.claims, &filters);
        let mut packet = assemble_packet(request, reads, buckets);
        if let Some(scope) = current_git_scope {
            resolve_memory_applicability(&mut packet, &scope_claims, scope);
        }
        populate_source_owned_packet_fields(
            &mut packet,
            request,
            codecortex_reports,
            current_git_scope,
            frame,
        );
        Ok(PacketCandidateOutcome { packet, read_audit })
    }

    /// Constructs the certification control candidate without holding or
    /// consulting a [`ReadService`]. This static path is the provider-free test
    /// seam proving that control compilation cannot perform memory reads.
    #[must_use]
    pub fn compile_control_unfinalized(
        request: &CompilePacketL3Request,
        codecortex_reports: &[CodeCortexReport],
        current_git_scope: Option<&GovernedGitScope>,
        frame: Option<&MaterialPacketFrame>,
    ) -> PacketCandidateOutcome {
        let mut packet = empty_packet(
            request,
            MemoryRevision::new(0),
            eliot_types::MemoryConfidence::None,
            false,
        );
        populate_source_owned_packet_fields(
            &mut packet,
            request,
            codecortex_reports,
            current_git_scope,
            frame,
        );
        PacketCandidateOutcome {
            packet,
            read_audit: PacketSourceReadAudit::default(),
        }
    }

    pub async fn compile_with_lifecycle_influence(
        &self,
        request: &CompilePacketL3Request,
        _writer: &WriterHandle,
        _admission: &WriteAdmissionService,
    ) -> Result<ContextPacketL3, EngineError> {
        let mut packet = self.compile(request).await?;
        packet.memory_lifecycle.lifecycle_warnings.push(
            "memory was loaded, but influence is not claimed until an outcome records an observable decision or verifier delta"
                .to_owned(),
        );
        Ok(packet)
    }

    pub async fn compile_with_skills(
        &self,
        request: &CompilePacketL3Request,
        skills: &[SkillCardV2],
        skill_context: &SkillActivationContext,
    ) -> Result<ContextPacketL3, EngineError> {
        let mut packet = self.compile(request).await?;
        let task_id = request.task_id.parse().unwrap_or_else(|_| TaskId::new_v7());
        let visible_skills = SkillCuratorService::visible_for_normal_l3(skills);
        packet.procedural_skills = SkillDistractorFilterService::procedural_packet(
            request.project_id,
            task_id,
            &visible_skills,
            skill_context,
        );
        enforce_budget(&mut packet, request.max_tokens, &request.candidate_handles)?;
        Ok(packet)
    }

    async fn read_context(
        &self,
        request: &CompilePacketL3Request,
        resolved_cues: &PacketResolvedCues,
    ) -> Result<(CompilerReads, PacketSourceReadAudit), EngineError> {
        let mut read_audit = PacketSourceReadAudit::default();
        for attempt in 0..2 {
            read_audit.current_state_reads += 1;
            let current_state = self
                .read
                .current_state(&CurrentStateRequest {
                    project_id: request.project_id,
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                })
                .await?;
            let revision = current_state.memory_revision;
            let mut handles = request.candidate_handles.clone();
            handles.extend(
                current_state
                    .verified_now
                    .iter()
                    .map(|claim| format!("claim:{}", claim.claim_id)),
            );
            read_audit.l0_reads += 1;
            let recall = self
                .read
                .recall_l0(&RecallL0Request {
                    project_id: request.project_id,
                    query: request.goal.clone(),
                    consistency: ReadConsistencyMode::AtLeastRevision,
                    at_least_revision: Some(revision),
                    lifecycle_audit: false,
                    task_id: request.task_id.parse().ok(),
                    task_class_cues: resolved_cues.task_class_cues.clone(),
                    scope_refs: resolved_cues.scope_refs.clone(),
                    concept_refs: resolved_cues.concept_refs.clone(),
                })
                .await?;
            handles.extend(recall.handles.iter().map(|preview| preview.handle.clone()));
            handles.sort();
            handles.dedup();
            read_audit.l2_reads += 1;
            let fetch = self
                .read
                .fetch_atoms_l2(&FetchAtomsL2Request {
                    project_id: request.project_id,
                    handles,
                    continuation: None,
                    consistency: ReadConsistencyMode::AtLeastRevision,
                    at_least_revision: Some(revision),
                })
                .await?;
            read_audit.current_state_reads += 1;
            let final_state = self
                .read
                .current_state(&CurrentStateRequest {
                    project_id: request.project_id,
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                })
                .await?;
            if revision == recall.at_revision
                && revision == fetch.at_revision
                && revision == final_state.memory_revision
            {
                return Ok((
                    CompilerReads {
                        current_state,
                        recall,
                        fetch,
                    },
                    read_audit,
                ));
            }
            if attempt == 1 {
                return Err(EngineError::ServiceNotReady {
                    service: "context-compiler".to_owned(),
                    reason: format!(
                        "could not obtain one stable current-truth and memory revision fence after retry: started {revision:?}, recall {:?}, fetch {:?}, finished {:?}",
                        recall.at_revision, fetch.at_revision, final_state.memory_revision
                    ),
                });
            }
        }
        unreachable!("bounded context read loop always returns")
    }
}

fn attach_packet_plan_sources<'a>(
    plan: &'a PacketCompilePlan,
    packet: &mut ContextPacketL3,
    memory_free_control: bool,
) -> Result<
    (
        Option<&'a PacketPyramidSnapshot>,
        ProjectUnderstandingEvidence,
    ),
    PacketCompilePlanInvalid,
> {
    let (pyramid, project_evidence) = match &plan.pyramid_source {
        PacketPyramidSource::Resolved(snapshot) => {
            let snapshot = snapshot.as_ref();
            if snapshot.at_revision != packet.at_revision {
                return Err(invalid_plan(format!(
                    "pyramid revision {} does not match source candidate revision {}",
                    snapshot.at_revision.value(),
                    packet.at_revision.value()
                )));
            }
            if packet.causal_bridge.is_empty() {
                packet.causal_bridge.clone_from(&snapshot.bridge);
            }
            (Some(snapshot), snapshot.project_evidence.clone())
        }
        PacketPyramidSource::Unavailable { .. } | PacketPyramidSource::Forbidden => {
            (None, ProjectUnderstandingEvidence::default())
        }
    };
    if !memory_free_control {
        let PacketExperienceSource::Cases(cases) = &plan.experience_source else {
            unreachable!("non-control experience source is validated before compilation")
        };
        let task_frame = packet_task_meaning_frame(plan, packet);
        let memory_need = MemoryNeedService::decide(&task_frame, None);
        let exposure_policy = MemoryExposurePolicy {
            mode: plan.memory_exposure,
            packet_cache_partition: format!("{:?}:{}", plan.memory_exposure, plan.request.task_id)
                .to_ascii_lowercase(),
            ..MemoryExposurePolicy::default()
        };
        let experience = ExperienceRetrievalService::recall(
            &ExperienceRecallRequest {
                project_id: plan.request.project_id,
                task_frame,
                need: memory_need.clone(),
                exposure_policy,
            },
            &deduplicate_experience_cases(cases.clone()),
        );
        packet.memory_need_decision = Some(memory_need);
        packet.experience_priors = experience.experience_priors;
    }
    if let Some(task) = &plan.task_contract {
        packet.memory_applicability.inclusion_reasons.push(format!(
            "eliot/task/{}@{}:canonical_task_state",
            task.task_id,
            task.memory_revision.value()
        ));
        packet.memory_applicability.inclusion_reasons.sort();
        packet.memory_applicability.inclusion_reasons.dedup();
    }
    Ok((pyramid, project_evidence))
}

fn invalid_plan(reason: impl Into<String>) -> PacketCompilePlanInvalid {
    PacketCompilePlanInvalid {
        reason: reason.into(),
    }
}

fn validate_packet_compile_plan(plan: &PacketCompilePlan) -> Result<(), PacketCompilePlanInvalid> {
    let memory_free_control = plan.memory_exposure == MemoryExposureMode::MemoryFreeControl;
    validate_plan_mode_and_memory_sources(plan, memory_free_control)?;
    validate_plan_scope_and_identity(plan)?;
    Ok(())
}

fn validate_plan_mode_and_memory_sources(
    plan: &PacketCompilePlan,
    memory_free_control: bool,
) -> Result<(), PacketCompilePlanInvalid> {
    match plan.compile_mode {
        PacketCompileMode::Production if memory_free_control => {
            return Err(invalid_plan(
                "production compilation cannot select memory_free_control",
            ));
        }
        PacketCompileMode::CertificationControl if !memory_free_control => {
            return Err(invalid_plan(
                "certification_control requires memory_free_control exposure",
            ));
        }
        PacketCompileMode::CertificationTreatment if memory_free_control => {
            return Err(invalid_plan(
                "certification_treatment requires governed memory exposure",
            ));
        }
        PacketCompileMode::Production
        | PacketCompileMode::ShadowEvaluation
        | PacketCompileMode::CertificationTreatment
        | PacketCompileMode::CertificationControl => {}
    }
    if memory_free_control {
        if !plan.resolved_cues.is_empty() {
            return Err(invalid_plan(
                "memory_free_control requires empty task/path/concept memory cues",
            ));
        }
        if !matches!(plan.pyramid_source, PacketPyramidSource::Forbidden) {
            return Err(invalid_plan(
                "memory_free_control requires a forbidden pyramid source",
            ));
        }
        if !matches!(plan.experience_source, PacketExperienceSource::Forbidden) {
            return Err(invalid_plan(
                "memory_free_control requires a forbidden experience source",
            ));
        }
        if plan.previous_packet.is_some() {
            return Err(invalid_plan(
                "memory_free_control cannot restore a previous memory-bearing packet",
            ));
        }
    } else {
        if matches!(plan.pyramid_source, PacketPyramidSource::Forbidden) {
            return Err(invalid_plan(
                "governed compilation requires a resolved or explicitly unavailable pyramid source",
            ));
        }
        if let PacketPyramidSource::Unavailable { reason } = &plan.pyramid_source
            && (reason.trim().is_empty() || reason.len() > 512)
        {
            return Err(invalid_plan(
                "unavailable pyramid source requires a non-empty reason of at most 512 bytes",
            ));
        }
        if !matches!(plan.experience_source, PacketExperienceSource::Cases(_)) {
            return Err(invalid_plan(
                "governed compilation requires raw experience candidates, even when empty",
            ));
        }
    }
    if plan.budget_policy.supplement_tokens != 0 {
        return Err(invalid_plan(
            "response supplement tokens are compiler-owned and must be zero in the plan",
        ));
    }
    if plan.task_receipt_metadata.is_some() && plan.task_contract.is_none() {
        return Err(invalid_plan(
            "task receipt metadata requires a resolved task contract",
        ));
    }
    if let Some(measurement) = &plan.measurement_view {
        if measurement.config_hash.trim().is_empty() {
            return Err(invalid_plan(
                "measurement view requires a non-empty configuration hash",
            ));
        }
        if memory_free_control && measurement.effective_injection_mode.is_some() {
            return Err(invalid_plan(
                "memory-free control cannot expose an effective injection mode",
            ));
        }
    }
    Ok(())
}

fn validate_plan_scope_and_identity(
    plan: &PacketCompilePlan,
) -> Result<(), PacketCompilePlanInvalid> {
    if let Some(task) = &plan.task_contract
        && (task.project_id != plan.request.project_id
            || task.task_id.to_string() != plan.request.task_id)
    {
        return Err(invalid_plan(
            "task contract project/task does not match the compile request",
        ));
    }
    if let Some(scope) = &plan.current_git_scope
        && scope.project_id != plan.request.project_id
    {
        return Err(invalid_plan(
            "governed Git scope project does not match the compile request",
        ));
    }
    if let Some(previous) = &plan.previous_packet
        && (previous.project_id != plan.request.project_id
            || previous.task_id != plan.request.task_id)
    {
        return Err(invalid_plan(
            "previous packet project/task does not match the compile request",
        ));
    }
    let expected_touched_paths = resolve_packet_scope_paths(
        &plan.request,
        plan.material_frame.as_ref(),
        &plan.codecortex_reports,
    );
    if plan.touched_paths != expected_touched_paths {
        return Err(invalid_plan(format!(
            "touched paths are not the canonical pre-candidate scope: expected {expected_touched_paths:?}, got {:?}",
            plan.touched_paths
        )));
    }
    if !packet_prediction_specs(plan.material_frame.as_ref()).is_empty()
        && TaskId::from_str(&plan.request.task_id).is_err()
    {
        return Err(invalid_plan(
            "machine-checkable prediction intents require a typed task_id",
        ));
    }
    Ok(())
}

/// Resolves the packet path scope before candidate construction. `CodeCortex`
/// evidence is used when the request/frame carries no path-bearing cue.
#[must_use]
pub fn resolve_packet_scope_paths(
    request: &CompilePacketL3Request,
    frame: Option<&MaterialPacketFrame>,
    codecortex_reports: &[CodeCortexReport],
) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(frame) = frame {
        for atom in &frame.exact_load_bearing_atoms {
            insert_scope_path_tokens(&mut values, atom);
        }
        for hop in &frame.causal_bridge {
            insert_scope_path_tokens(&mut values, &hop.from);
            insert_scope_path_tokens(&mut values, &hop.to);
            if let Some(reference) = &hop.evidence_ref {
                insert_scope_path_tokens(&mut values, reference);
            }
        }
    }
    for handle in &request.candidate_handles {
        insert_scope_path_tokens(&mut values, handle);
    }
    insert_scope_path_tokens(&mut values, &request.goal);
    if values.is_empty()
        && let Some(report) = codecortex_reports.last()
    {
        for evidence in report.tracked_files.iter().chain(&report.file_evidence) {
            insert_scope_path_tokens(&mut values, &evidence.path);
        }
        for evidence in &report.symbol_evidence {
            insert_scope_path_tokens(&mut values, &evidence.path);
        }
    }
    values.into_iter().collect()
}

fn insert_scope_path_tokens(paths: &mut BTreeSet<String>, value: &str) {
    paths.extend(eliot_types::path_cue_tokens(value));
}

fn packet_task_meaning_frame(
    plan: &PacketCompilePlan,
    packet: &ContextPacketL3,
) -> TaskMeaningFrame {
    TaskMeaningFrame {
        task_id: plan.request.task_id.clone(),
        user_goal: plan.request.goal.clone(),
        normalized_goal: eliot_types::normalize_unicode_lowercase(&plan.request.goal),
        execution_class: Some(packet.task_execution_class.clone()),
        task_or_action_type: "governed_task".to_owned(),
        desired_state_transition: plan.request.goal.clone(),
        problem_or_failure_signature: packet.open_questions.join(" "),
        project_module_boundary: packet
            .codecortex
            .as_ref()
            .map_or_else(Vec::new, |view| view.report_refs.clone()),
        files_symbols_config: packet.codecortex.as_ref().map_or_else(Vec::new, |view| {
            view.file_evidence
                .iter()
                .map(|evidence| evidence.path.clone())
                .collect()
        }),
        control_data_state_path: packet
            .causal_bridge
            .iter()
            .map(|hop| format!("{} -> {} -> {}", hop.from, hop.relation, hop.to))
            .collect(),
        constraints: plan
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.killed_paths.clone()),
        invariants: plan
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.acceptance_items.clone()),
        current_evidence: packet.exact_handles.clone(),
        material_unknowns: packet.open_questions.clone(),
        expected_artifact: plan
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.next_allowed_action.clone()),
        predicted_observable: plan
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.expected_observable.clone()),
        verifier_need: plan
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.verifier.clone()),
        abstraction_level_needed: "auto".to_owned(),
        codecortex_report_ref: plan.codecortex_reports.last().map(codecortex_report_ref),
        ..TaskMeaningFrame::default()
    }
}

fn packet_gate_candidate(
    pyramid_source: &PacketPyramidSource,
    compile_mode: PacketCompileMode,
    frame: Option<&MaterialPacketFrame>,
    touched_paths: &[String],
    packet: &ContextPacketL3,
) -> PacketGateCandidate {
    let pyramid = match (compile_mode, pyramid_source) {
        (PacketCompileMode::CertificationControl, PacketPyramidSource::Forbidden) => {
            return PacketGateCandidate::allow();
        }
        (_, PacketPyramidSource::Unavailable { reason }) => {
            return PacketGateCandidate {
                status: PacketGateStatus::RequirePacketRefresh,
                reason: Some(PacketGateReason::PyramidUnavailable),
                missing_invariant_refs: Vec::new(),
                concept_or_path: touched_paths.first().cloned(),
                suggested_probe: Some(format!(
                    "refresh pyramid evidence before admission: {}",
                    reason.trim()
                )),
            };
        }
        (_, PacketPyramidSource::Forbidden) => {
            return PacketGateCandidate {
                status: PacketGateStatus::RequirePacketRefresh,
                reason: Some(PacketGateReason::PyramidUnavailable),
                missing_invariant_refs: Vec::new(),
                concept_or_path: touched_paths.first().cloned(),
                suggested_probe: Some(
                    "resolve pyramid evidence; forbidden is valid only for certification control"
                        .to_owned(),
                ),
            };
        }
        (_, PacketPyramidSource::Resolved(pyramid)) => pyramid.as_ref(),
    };
    if let Some(frame) = frame {
        let missing_invariant_refs =
            packet_missing_invariant_refs(&pyramid.required_invariant_refs, frame);
        if !missing_invariant_refs.is_empty() {
            return PacketGateCandidate {
                status: PacketGateStatus::RequirePacketRefresh,
                reason: Some(PacketGateReason::MissingCapsuleInvariants),
                missing_invariant_refs,
                concept_or_path: None,
                suggested_probe: None,
            };
        }
        if pyramid.coverage == CoverageClass::Blind {
            let frame_stub =
                packet_material_frame_stub(packet, None, &pyramid.required_invariant_refs);
            return PacketGateCandidate {
                status: PacketGateStatus::RequireProbe,
                reason: Some(PacketGateReason::BlindSubsystem),
                missing_invariant_refs: Vec::new(),
                concept_or_path: Some(
                    pyramid
                        .blind_target
                        .clone()
                        .or_else(|| touched_paths.first().cloned())
                        .unwrap_or_else(|| "unknown".to_owned()),
                ),
                suggested_probe: Some(
                    pyramid
                        .recommended_probe
                        .clone()
                        .or_else(|| Some(frame.verifier.clone()))
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or(frame_stub.verifier),
                ),
            };
        }
    }
    PacketGateCandidate::allow()
}

fn packet_admission_decision(
    gate: &PacketGateCandidate,
    compile_mode: PacketCompileMode,
) -> PacketAdmissionDecision {
    let gate_status = match gate.status {
        PacketGateStatus::Allow => PacketAdmissionStatus::Admitted,
        PacketGateStatus::RequireProbe => PacketAdmissionStatus::AdmittedDegraded,
        PacketGateStatus::RequirePacketRefresh => PacketAdmissionStatus::Rejected,
    };
    let counterfactual_only = compile_mode == PacketCompileMode::ShadowEvaluation
        && gate_status != PacketAdmissionStatus::Rejected;
    let status = if counterfactual_only {
        PacketAdmissionStatus::Counterfactual
    } else {
        gate_status
    };
    let active_allowed = matches!(
        status,
        PacketAdmissionStatus::Admitted | PacketAdmissionStatus::AdmittedDegraded
    );
    PacketAdmissionDecision {
        status,
        active_allowed,
        continuity_allowed: active_allowed,
        influence_authority_allowed: active_allowed,
        counterfactual_only,
    }
}

fn packet_missing_invariant_refs(
    required_invariant_refs: &[String],
    frame: &MaterialPacketFrame,
) -> Vec<String> {
    let mut covered = frame
        .invariant_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    covered.extend(frame.waived_invariants.iter().filter_map(|waiver| {
        let reason = waiver.reason.trim();
        (!reason.is_empty() && reason.len() <= 240).then(|| waiver.invariant_ref.clone())
    }));
    required_invariant_refs
        .iter()
        .filter(|invariant| !covered.contains(*invariant))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn packet_material_frame_stub(
    packet: &ContextPacketL3,
    task: Option<&TaskContract>,
    required_invariant_refs: &[String],
) -> MaterialPacketFrame {
    let next_action = if packet
        .decision_locality_suffix
        .next_allowed_action
        .trim()
        .is_empty()
    {
        "inspect responsible boundary".to_owned()
    } else {
        packet.decision_locality_suffix.next_allowed_action.clone()
    };
    let verifier = if packet.decision_locality_suffix.verifier.trim().is_empty() {
        "cargo test --workspace".to_owned()
    } else {
        packet.decision_locality_suffix.verifier.clone()
    };
    let stop_condition = if packet
        .decision_locality_suffix
        .stop_condition
        .trim()
        .is_empty()
    {
        "stop on verifier failure".to_owned()
    } else {
        packet.decision_locality_suffix.stop_condition.clone()
    };
    MaterialPacketFrame {
        acceptance_items: task.map_or_else(Vec::new, |task| {
            task.acceptance_items
                .iter()
                .map(|item| item.description.clone())
                .collect()
        }),
        environment: packet
            .current_truth_snapshot
            .as_ref()
            .map_or_else(Vec::new, |snapshot| snapshot.environment.clone()),
        active_plan: vec![next_action.clone()],
        completed_work: task.map_or_else(Vec::new, |task| {
            task.acceptance_items
                .iter()
                .filter(|item| item.satisfied)
                .map(|item| item.description.clone())
                .collect()
        }),
        killed_paths: packet.killed_paths.clone(),
        causal_bridge: packet.causal_bridge.clone(),
        negative_memory_checked: !packet.negative_memory.is_empty()
            || packet
                .memory_decisions
                .iter()
                .any(|decision| decision.memory_handle.contains("failure")),
        exact_load_bearing_atoms: packet.exact_handles.clone(),
        cheapest_discriminative_probes: packet
            .decision_locality_suffix
            .cheapest_discriminative_probes
            .clone(),
        responsibility_contour_route_refs: packet
            .decision_locality_suffix
            .responsibility_contour_route_refs
            .clone(),
        next_allowed_action: next_action,
        expected_observable: String::new(),
        verifier: verifier.clone(),
        stop_condition,
        tool_schema_bytes_visible: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.tool_schema_bytes_visible),
        instruction_hotset_size: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.instruction_hotset_size),
        invariant_refs: required_invariant_refs.to_vec(),
        waived_invariants: Vec::new(),
        prediction_confidence: None,
        predicted_changed_paths: packet
            .exact_handles
            .iter()
            .flat_map(|handle| eliot_types::path_cue_tokens(handle))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        predicted_failing_verifiers: Vec::new(),
    }
}

fn packet_material_frame_required_edits(frame: &MaterialPacketFrame) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if frame.next_allowed_action.trim().is_empty() {
        fields.push("material_frame.next_allowed_action");
    }
    if frame.expected_observable.trim().is_empty() {
        fields.push("material_frame.expected_observable");
    }
    if frame.verifier.trim().is_empty() {
        fields.push("material_frame.verifier");
    }
    if frame.stop_condition.trim().is_empty() {
        fields.push("material_frame.stop_condition");
    }
    fields
}

#[derive(Clone, Debug)]
struct PacketPredictionSpec {
    prediction: UlPrediction,
    confidence: Option<PredictionConfidence>,
}

fn packet_prediction_specs(frame: Option<&MaterialPacketFrame>) -> Vec<PacketPredictionSpec> {
    let Some(frame) = frame else {
        return Vec::new();
    };
    let mut specs = Vec::new();
    if let Some((verifier, expected)) = parse_expected_observable(&frame.expected_observable) {
        specs.push(PacketPredictionSpec {
            prediction: UlPrediction::VerifierVerdict { verifier, expected },
            confidence: frame.prediction_confidence,
        });
    }
    let predicted_paths = frame
        .predicted_changed_paths
        .iter()
        .map(|path| eliot_types::normalize_observed_path(path))
        .filter(|path| !path.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let predicted_failing_verifiers = frame
        .predicted_failing_verifiers
        .iter()
        .map(|verifier| normalize_verifier(verifier))
        .filter(|verifier| !verifier.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !predicted_paths.is_empty() || !predicted_failing_verifiers.is_empty() {
        specs.push(PacketPredictionSpec {
            prediction: UlPrediction::BlastRadius {
                predicted_paths,
                predicted_failing_verifiers,
            },
            confidence: frame.prediction_confidence,
        });
    }
    specs
}

fn packet_prediction_placeholder_ref(index: usize) -> String {
    format!("prediction:ul-prediction-{index:032x}")
}

fn packet_prediction_source_frame_hash(
    frame: &MaterialPacketFrame,
) -> Result<String, serde_json::Error> {
    // A bounded invariant waiver changes gate admission, not the prediction
    // proposition. Excluding it keeps P7 prediction identities stable while
    // retaining every action/observable/verifier/blast-radius input.
    let mut prediction_frame = frame.clone();
    prediction_frame.waived_invariants.clear();
    Ok(blake3::hash(&serde_json::to_vec(&prediction_frame)?)
        .to_hex()
        .to_string())
}

fn packet_measurement_supplement(
    plan: &PacketCompilePlan,
    measurement: &PacketMeasurementView,
    admission: &PacketAdmissionDecision,
) -> Value {
    let arm = if plan.compile_mode == PacketCompileMode::CertificationControl {
        UlExperimentArm::Control
    } else {
        UlExperimentArm::Treatment
    };
    let assignment_status = match admission.status {
        PacketAdmissionStatus::Admitted | PacketAdmissionStatus::AdmittedDegraded => {
            PacketMeasurementAssignmentStatus::PostCommitMeasurement
        }
        PacketAdmissionStatus::Counterfactual => {
            PacketMeasurementAssignmentStatus::NotAssignedCounterfactual
        }
        PacketAdmissionStatus::Rejected => PacketMeasurementAssignmentStatus::NotAssignedRejected,
    };
    json!({
        "project_id": plan.request.project_id,
        "task_id": plan.request.task_id,
        "task_class": measurement.task_class,
        "arm": arm,
        "assignment_status": assignment_status,
        "packet_disposition": admission.status,
        "assignment_injection_mode": measurement.assignment_injection_mode,
        "effective_injection_mode": measurement.effective_injection_mode,
        "effective_memory_mode": if plan.memory_exposure == MemoryExposureMode::MemoryFreeControl {
            "memory_free_control"
        } else {
            "configured"
        },
        "config_hash": measurement.config_hash,
    })
}

fn packet_response_supplement(
    plan: &PacketCompilePlan,
    packet: &ContextPacketL3,
    required_invariant_refs: &[String],
    gate: &PacketGateCandidate,
    admission: &PacketAdmissionDecision,
    prediction_count: usize,
) -> Result<Value, EngineError> {
    let frame_stub =
        packet_material_frame_stub(packet, plan.task_contract.as_ref(), required_invariant_refs);
    let frame_stub_required_edits = packet_material_frame_required_edits(&frame_stub);
    let mut supplement = json!({
        "frame_stub": frame_stub,
        "frame_stub_ready": frame_stub_required_edits.is_empty(),
        "frame_stub_required_edits": frame_stub_required_edits,
        "packet_admission": admission,
    });
    match &plan.pyramid_source {
        PacketPyramidSource::Resolved(pyramid) => {
            supplement["ul_understanding"] = pyramid.understanding.clone();
            supplement["ul_meta"] = json!({
                "coverage": pyramid.coverage,
                "novelty_percent": pyramid.metacognition.novelty_percent,
                "danger": pyramid.metacognition.danger_paths,
                "recommended_probe": pyramid.recommended_probe,
                "blind_target": pyramid.blind_target,
                "scope_paths": plan.touched_paths,
            });
        }
        PacketPyramidSource::Unavailable { reason } => {
            supplement["ul_meta"] = json!({
                "status": "unavailable",
                "reason": reason,
                "scope_paths": plan.touched_paths,
            });
        }
        PacketPyramidSource::Forbidden => {}
    }
    if gate.status != PacketGateStatus::Allow {
        supplement["ul_gate"] = serde_json::to_value(gate)?;
    }
    if let Some(task) = &plan.task_contract {
        let task_contract_ref = format!(
            "eliot/task/{}@{}",
            task.task_id,
            task.memory_revision.value()
        );
        let mut exact_evidence_refs = plan
            .task_receipt_metadata
            .as_ref()
            .map_or_else(Vec::new, |metadata| metadata.exact_evidence_refs.clone());
        exact_evidence_refs.sort();
        exact_evidence_refs.dedup();
        supplement["task_contract"] = serde_json::to_value(task)?;
        supplement["task_truth_status"] = Value::String("current_canonical".to_owned());
        supplement["task_revision_fence"] = serde_json::to_value(task.memory_revision)?;
        supplement["packet_revision_fence"] = serde_json::to_value(packet.at_revision)?;
        supplement["task_contract_ref"] = Value::String(task_contract_ref.clone());
        supplement["current_truth_refs"] = json!([task_contract_ref]);
        supplement["exact_evidence_refs"] = serde_json::to_value(exact_evidence_refs)?;
        supplement["negative_memory_check_ref"] = Value::String(format!(
            "eliot/negative-memory/eliot/packet/{}",
            "0".repeat(64)
        ));
        supplement["negative_stale_exclusions"] =
            json!(["candidate observations are not verifier authority"]);
        supplement["registered_verifiers"] = plan.task_receipt_metadata.as_ref().map_or_else(
            || Value::Array(Vec::new()),
            |metadata| Value::Array(metadata.registered_verifiers.clone()),
        );
    }
    if prediction_count > 0 {
        let refs = (0..prediction_count)
            .map(packet_prediction_placeholder_ref)
            .collect::<Vec<_>>();
        supplement["prediction_refs"] = serde_json::to_value(&refs)?;
        supplement["prediction_ref"] = Value::String(refs[0].clone());
    } else if plan.material_frame.is_some() {
        supplement["ul_prediction"] = json!({"status": "not_machine_checkable"});
    }
    if let Some(measurement) = &plan.measurement_view {
        supplement["ul_experiment"] = packet_measurement_supplement(plan, measurement, admission);
    }
    Ok(supplement)
}

fn finalize_packet_prediction_intents(
    plan: &PacketCompilePlan,
    pyramid: Option<&PacketPyramidSnapshot>,
    packet: &ContextPacketL3,
    specs: Vec<PacketPredictionSpec>,
) -> Result<Vec<PacketPredictionIntent>, PacketCompilePlanInvalid> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let task_id = TaskId::from_str(&plan.request.task_id).map_err(|_| {
        invalid_plan("machine-checkable prediction intents require a typed task_id")
    })?;
    let frame = plan
        .material_frame
        .as_ref()
        .ok_or_else(|| invalid_plan("prediction specs require a material frame"))?;
    let source_frame_hash = packet_prediction_source_frame_hash(frame)
        .map_err(|error| invalid_plan(format!("material frame hash failed: {error}")))?;
    Ok(specs
        .into_iter()
        .map(|spec| {
            let prediction_id = prediction_id_for(
                plan.request.project_id,
                task_id,
                plan.session_id,
                &packet.packet_id,
                &spec.prediction,
                &source_frame_hash,
            );
            PacketPredictionIntent {
                prediction_ref: format!("prediction:{prediction_id}"),
                prediction: spec.prediction,
                confidence: spec.confidence,
                subsystem_concept_id: pyramid
                    .and_then(|snapshot| snapshot.subsystem_concept_id.clone()),
                source_frame_hash: source_frame_hash.clone(),
            }
        })
        .collect())
}

fn finalize_response_supplement(
    supplement: &mut Value,
    packet: &ContextPacketL3,
    prediction_intents: &[PacketPredictionIntent],
) {
    let Value::Object(object) = supplement else {
        return;
    };
    if object.contains_key("negative_memory_check_ref") {
        object.insert(
            "negative_memory_check_ref".to_owned(),
            Value::String(format!("eliot/negative-memory/{}", packet.packet_id)),
        );
    }
    if !prediction_intents.is_empty() {
        let refs = prediction_intents
            .iter()
            .map(|intent| intent.prediction_ref.clone())
            .collect::<Vec<_>>();
        object.insert(
            "prediction_refs".to_owned(),
            serde_json::to_value(&refs).unwrap_or(Value::Array(Vec::new())),
        );
        object.insert("prediction_ref".to_owned(), Value::String(refs[0].clone()));
    }
}

struct CompilerReads {
    current_state: CurrentStateResponse,
    recall: RecallL0Response,
    fetch: FetchAtomsL2Response,
}

struct ClaimBuckets {
    relevant_verified_claims: Vec<ClaimCard>,
    relevant_supported_claims: Vec<ClaimCard>,
    weak_claims_warning: Vec<ClaimCard>,
    negative_memory: Vec<ClaimCard>,
    known_decisions: Vec<ClaimCard>,
    open_questions: Vec<String>,
}

fn bucket_claims(claims: &[ClaimCard], filters: &HashSet<String>) -> ClaimBuckets {
    let mut buckets = ClaimBuckets {
        relevant_verified_claims: Vec::new(),
        relevant_supported_claims: Vec::new(),
        weak_claims_warning: Vec::new(),
        negative_memory: Vec::new(),
        known_decisions: Vec::new(),
        open_questions: Vec::new(),
    };

    for claim in claims
        .iter()
        .filter(|claim| filters.is_empty() || filters.contains(&claim_handle(claim)))
    {
        bucket_claim(claim, &mut buckets);
    }
    buckets
}

fn bucket_claim(claim: &ClaimCard, buckets: &mut ClaimBuckets) {
    match claim.status {
        EpistemicStatus::Verified => {
            buckets.relevant_verified_claims.push(claim.clone());
            if claim.statement.to_ascii_lowercase().contains("decision") {
                buckets.known_decisions.push(claim.clone());
            }
        }
        EpistemicStatus::Supported => buckets.relevant_supported_claims.push(claim.clone()),
        EpistemicStatus::Candidate | EpistemicStatus::Observed | EpistemicStatus::Unknown => {
            buckets.open_questions.push(format!(
                "claim:{} remains {:?}",
                claim.claim_id, claim.status
            ));
            buckets.weak_claims_warning.push(claim.clone());
        }
        EpistemicStatus::Contested
        | EpistemicStatus::Superseded
        | EpistemicStatus::Stale
        | EpistemicStatus::Rejected => {
            buckets.weak_claims_warning.push(claim.clone());
            buckets.negative_memory.push(claim.clone());
        }
    }
}

fn resolve_memory_applicability(
    packet: &mut ContextPacketL3,
    claims: &[ClaimCard],
    scope: &GovernedGitScope,
) {
    let mut verified_claims: Vec<_> = claims
        .iter()
        .filter(|claim| claim.status == EpistemicStatus::Verified)
        .cloned()
        .collect();
    verified_claims.sort_by_key(|claim| claim.claim_id.to_string());

    let mut authoritative = HashSet::new();
    let mut historical = Vec::new();
    let mut decisions = Vec::new();
    let mut inclusion_reasons = Vec::new();
    let mut suppression_reasons = Vec::new();
    let mut revalidation_reasons = Vec::new();

    for claim in verified_claims {
        let decision = classify_verified_claim(&claim, scope);
        let claim_id = claim.claim_id.to_string();
        let reason = format!("claim:{claim_id}:{}", decision.reason);
        match decision.disposition {
            MemoryApplicabilityDisposition::VerifiedNow => {
                authoritative.insert(claim_id);
                inclusion_reasons.push(reason);
            }
            MemoryApplicabilityDisposition::RevalidatedNow => {
                authoritative.insert(claim_id);
                inclusion_reasons.push(reason.clone());
                revalidation_reasons.push(reason);
            }
            MemoryApplicabilityDisposition::SuppressedHistorical => {
                suppression_reasons.push(reason);
                historical.push(claim);
            }
        }
        decisions.push(decision);
    }

    for summary in &packet.current_truth {
        let claim_id = summary.claim_id.to_string();
        if decisions
            .iter()
            .all(|decision| decision.memory_ref != format!("claim:{claim_id}"))
        {
            let reason = format!("claim:{claim_id}:canonical_git_provenance_missing");
            suppression_reasons.push(reason.clone());
            decisions.push(MemoryApplicabilityDecision {
                memory_ref: format!("claim:{claim_id}"),
                disposition: MemoryApplicabilityDisposition::SuppressedHistorical,
                provenance: MemoryProvenanceView::default(),
                reason: "canonical_git_provenance_missing".to_owned(),
            });
        }
    }

    packet
        .current_truth
        .retain(|claim| authoritative.contains(&claim.claim_id.to_string()));
    packet
        .relevant_verified_claims
        .retain(|claim| authoritative.contains(&claim.claim_id.to_string()));
    packet
        .known_decisions
        .retain(|claim| authoritative.contains(&claim.claim_id.to_string()));
    historical.sort_by_key(|claim| claim.claim_id.to_string());
    historical.dedup_by_key(|claim| claim.claim_id);
    decisions.sort_by(|left, right| left.memory_ref.cmp(&right.memory_ref));
    inclusion_reasons.sort();
    inclusion_reasons.dedup();
    suppression_reasons.sort();
    suppression_reasons.dedup();
    revalidation_reasons.sort();
    revalidation_reasons.dedup();
    packet.historical_memory = historical;
    packet.memory_applicability = MemoryApplicabilityPacketView {
        current_git_scope: Some(CurrentGitScopeView {
            project_id: scope.project_id,
            branch: scope.branch.clone(),
            commit: scope.commit.clone(),
            clean: scope.clean,
        }),
        decisions,
        inclusion_reasons,
        suppression_reasons,
        revalidation_reasons,
    };
}

fn classify_verified_claim(
    claim: &ClaimCard,
    scope: &GovernedGitScope,
) -> MemoryApplicabilityDecision {
    let provenance = claim_provenance(claim);
    let reason = if !scope.clean {
        "current_git_scope_dirty"
    } else if !project_scope_matches(provenance.project_scope.as_deref(), scope.project_id) {
        "project_scope_mismatch"
    } else if provenance.branch.as_deref() != Some(scope.branch.as_str()) {
        "branch_scope_mismatch"
    } else if !canonical_evidence_complete(&provenance) {
        "canonical_evidence_incomplete"
    } else if provenance.commit.as_deref() == Some(scope.commit.as_str()) {
        if artifact_content_matches(&provenance.artifact_refs, &scope.artifact_refs) {
            "canonical_evidence_exact_git_scope"
        } else {
            "artifact_content_changed"
        }
    } else if provenance
        .commit
        .as_ref()
        .is_some_and(|commit| scope.ancestor_commits.contains(commit))
    {
        if artifact_content_matches(&provenance.artifact_refs, &scope.artifact_refs) {
            "canonical_evidence_revalidated_on_descendant_commit"
        } else {
            "descendant_commit_requires_artifact_revalidation"
        }
    } else {
        "commit_not_current_or_ancestor"
    };
    let disposition = match reason {
        "canonical_evidence_exact_git_scope" => MemoryApplicabilityDisposition::VerifiedNow,
        "canonical_evidence_revalidated_on_descendant_commit" => {
            MemoryApplicabilityDisposition::RevalidatedNow
        }
        _ => MemoryApplicabilityDisposition::SuppressedHistorical,
    };
    MemoryApplicabilityDecision {
        memory_ref: format!("claim:{}", claim.claim_id),
        disposition,
        provenance,
        reason: reason.to_owned(),
    }
}

fn claim_provenance(claim: &ClaimCard) -> MemoryProvenanceView {
    let lineage = claim.payload.get("lineage");
    let project_scope = claim
        .payload
        .get("where_applicable")
        .and_then(serde_json::Value::as_array)
        .and_then(|values| {
            values.iter().find_map(|value| {
                value
                    .as_str()
                    .and_then(|value| value.strip_prefix("project:"))
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            })
        });
    let artifact_refs = lineage
        .and_then(|value| value.get("canonical_artifact_refs"))
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<VerifierArtifactRef>>(value).ok())
        .unwrap_or_default();
    let mut evidence_refs = Vec::new();
    if let Some(evidence_id) = claim
        .payload
        .get("evidence_id")
        .and_then(|value| value.as_str())
    {
        evidence_refs.push(format!("evidence:{evidence_id}"));
    }
    if let Some(verification_ids) = lineage
        .and_then(|value| value.get("verification_ids"))
        .and_then(serde_json::Value::as_array)
    {
        evidence_refs.extend(verification_ids.iter().filter_map(|value| {
            value
                .as_str()
                .map(|verification_id| format!("verification:{verification_id}"))
        }));
    }
    if let Some(receipt_id) = lineage
        .and_then(|value| value.get("controller_receipt_id"))
        .and_then(|value| value.as_str())
    {
        evidence_refs.push(format!("receipt:{receipt_id}"));
    }
    evidence_refs.sort();
    evidence_refs.dedup();
    MemoryProvenanceView {
        source_id: claim
            .payload
            .get("source_id")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        project_scope,
        branch: lineage
            .and_then(|value| value.get("branch"))
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        commit: lineage
            .and_then(|value| value.get("resulting_controller_commit"))
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        evidence_refs,
        artifact_refs,
    }
}

fn project_scope_matches(project_scope: Option<&str>, project_id: eliot_types::ProjectId) -> bool {
    let project_id = project_id.to_string();
    project_scope.is_some_and(|project_scope| {
        project_scope == project_id
            || (project_scope.len() == 8 && project_scope == &project_id[..8])
    })
}

fn canonical_evidence_complete(provenance: &MemoryProvenanceView) -> bool {
    !provenance.artifact_refs.is_empty()
        && provenance
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("evidence:"))
        && provenance
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("verification:"))
        && provenance
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("receipt:"))
}

fn artifact_content_matches(
    expected: &[VerifierArtifactRef],
    current: &[VerifierArtifactRef],
) -> bool {
    !expected.is_empty()
        && expected.iter().all(|expected| {
            current.iter().any(|current| {
                normalize_artifact_path(&current.resource_ref)
                    == normalize_artifact_path(&expected.resource_ref)
                    && current.content_hash == expected.content_hash
            })
        })
}

fn normalize_artifact_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn assemble_packet(
    request: &CompilePacketL3Request,
    reads: CompilerReads,
    buckets: ClaimBuckets,
) -> ContextPacketL3 {
    let exact_handles = collect_exact_handles(request, &reads.recall, &buckets);
    let source_receipts = collect_source_receipts(&reads.fetch);
    let at_revision = max_revision(reads.current_state.memory_revision, reads.fetch.at_revision);
    let mut packet = empty_packet(
        request,
        at_revision,
        reads.recall.memory_confidence,
        reads.recall.truncation.truncated || reads.fetch.truncation.truncated,
    );
    packet.current_truth = reads.current_state.verified_now;
    packet.relevant_verified_claims = buckets.relevant_verified_claims;
    packet.relevant_supported_claims = buckets.relevant_supported_claims;
    packet.weak_claims_warning = buckets.weak_claims_warning;
    packet.negative_memory = buckets.negative_memory;
    packet.recent_failures = reads.fetch.failure_fingerprints;
    packet.known_decisions = buckets.known_decisions;
    packet.open_questions = buckets.open_questions;
    packet.exact_handles = exact_handles;
    packet.source_receipts = source_receipts;
    packet
}

fn empty_packet(
    request: &CompilePacketL3Request,
    at_revision: MemoryRevision,
    memory_confidence: eliot_types::MemoryConfidence,
    retrieval_truncated: bool,
) -> ContextPacketL3 {
    ContextPacketL3 {
        packet_id: String::new(),
        project_id: request.project_id,
        task_id: request.task_id.clone(),
        goal: request.goal.clone(),
        task_execution_class: eliot_types::TaskExecutionClass::default(),
        project_understanding: None,
        memory_confidence,
        acceptance_items: Vec::new(),
        at_revision,
        current_truth: Vec::new(),
        relevant_verified_claims: Vec::new(),
        relevant_supported_claims: Vec::new(),
        weak_claims_warning: Vec::new(),
        negative_memory: Vec::new(),
        recent_failures: Vec::new(),
        known_decisions: Vec::new(),
        open_questions: Vec::new(),
        exact_handles: Vec::new(),
        source_receipts: Vec::new(),
        current_truth_snapshot: None,
        epistemic_state: EpistemicPacketState::default(),
        active_plan: Vec::new(),
        completed_work: Vec::new(),
        killed_paths: Vec::new(),
        causal_bridge: Vec::new(),
        memory_decisions: Vec::new(),
        experience_priors: Vec::new(),
        memory_need_decision: None,
        decision_locality_suffix: DecisionLocalitySuffix::default(),
        packet_quality: None,
        memory_applicability: MemoryApplicabilityPacketView::default(),
        historical_memory: Vec::new(),
        memory_lifecycle: MemoryLifecyclePacketView::default(),
        procedural_skills: eliot_types::ProceduralSkillPacketView::default(),
        token_budget_report: TokenBudgetReport {
            max_tokens: request.max_tokens,
            estimated_tokens: 0,
            truncated: false,
            sections_truncated: Vec::new(),
        },
        codecortex: None,
        truncation: TruncationInfo {
            truncated: retrieval_truncated,
            limit: request.max_tokens,
            returned: 0,
        },
    }
}

fn populate_source_owned_packet_fields(
    packet: &mut ContextPacketL3,
    request: &CompilePacketL3Request,
    codecortex_reports: &[CodeCortexReport],
    current_git_scope: Option<&GovernedGitScope>,
    frame: Option<&MaterialPacketFrame>,
) {
    packet.task_execution_class =
        TaskExecutionClassifier::classify(request, frame, &[], &packet.exact_handles);
    if TaskExecutionClassifier::should_attach_codecortex(
        request,
        frame,
        &[],
        &packet.task_execution_class,
    ) {
        attach_codecortex_reports(packet, codecortex_reports);
    }
    hydrate_material_packet(packet, request, current_git_scope, frame);
}

fn hydrate_material_packet(
    packet: &mut ContextPacketL3,
    request: &CompilePacketL3Request,
    current_git_scope: Option<&GovernedGitScope>,
    frame: Option<&MaterialPacketFrame>,
) {
    let frame = frame.cloned().unwrap_or_default();
    packet.current_truth_snapshot = current_git_scope.map(|scope| CurrentTruthSnapshot {
        project_id: scope.project_id,
        task_id: request.task_id.clone(),
        branch: scope.branch.clone(),
        commit: scope.commit.clone(),
        environment: frame.environment.clone(),
        revision_fence: packet.at_revision,
        captured_at: stable_revision_capture_time(packet.at_revision),
    });
    packet.epistemic_state = EpistemicPacketState {
        supported: packet
            .relevant_supported_claims
            .iter()
            .map(claim_handle)
            .collect(),
        assumed: packet
            .weak_claims_warning
            .iter()
            .filter(|claim| {
                matches!(
                    claim.status,
                    EpistemicStatus::Candidate | EpistemicStatus::Observed
                )
            })
            .map(claim_handle)
            .collect(),
        conflicted: packet
            .weak_claims_warning
            .iter()
            .filter(|claim| claim.status == EpistemicStatus::Contested)
            .map(claim_handle)
            .collect(),
        unknown: packet.open_questions.clone(),
    };
    packet.acceptance_items.clone_from(&frame.acceptance_items);
    packet.active_plan.clone_from(&frame.active_plan);
    packet.completed_work.clone_from(&frame.completed_work);
    packet.killed_paths.clone_from(&frame.killed_paths);
    packet.causal_bridge.clone_from(&frame.causal_bridge);
    let mut exact_atoms = frame.exact_load_bearing_atoms.clone();
    exact_atoms.extend(packet.exact_handles.iter().cloned());
    exact_atoms.sort();
    exact_atoms.dedup();
    packet.decision_locality_suffix = DecisionLocalitySuffix {
        exact_load_bearing_atoms: exact_atoms,
        open_unknowns: packet.open_questions.clone(),
        cheapest_discriminative_probes: frame.cheapest_discriminative_probes,
        responsibility_contour_route_refs: frame.responsibility_contour_route_refs,
        next_allowed_action: frame.next_allowed_action,
        expected_observable: frame.expected_observable,
        verifier: frame.verifier,
        stop_condition: frame.stop_condition,
    };
    packet.memory_decisions = memory_decision_receipts(packet);
}

fn memory_decision_receipts(packet: &ContextPacketL3) -> Vec<MemoryDecisionReceipt> {
    let Ok(task_id) = TaskId::from_str(&packet.task_id) else {
        return Vec::new();
    };
    packet
        .memory_applicability
        .decisions
        .iter()
        .map(|decision| {
            let admission = match decision.disposition {
                MemoryApplicabilityDisposition::VerifiedNow => {
                    MemoryAdmissionDecision::IncludeVerified
                }
                MemoryApplicabilityDisposition::RevalidatedNow => {
                    MemoryAdmissionDecision::RequireRevalidation
                }
                MemoryApplicabilityDisposition::SuppressedHistorical => {
                    if decision.reason.contains("scope") {
                        MemoryAdmissionDecision::SuppressWrongScope
                    } else {
                        MemoryAdmissionDecision::SuppressStale
                    }
                }
            };
            let source_and_anchor = decision
                .provenance
                .source_id
                .clone()
                .or_else(|| decision.provenance.evidence_refs.first().cloned())
                .unwrap_or_else(|| "unknown-source".to_owned());
            let mut scope = Vec::new();
            if let Some(project) = &decision.provenance.project_scope {
                scope.push(format!("project:{project}"));
            }
            if let Some(branch) = &decision.provenance.branch {
                scope.push(format!("branch:{branch}"));
            }
            if let Some(commit) = &decision.provenance.commit {
                scope.push(format!("commit:{commit}"));
            }
            MemoryDecisionReceipt {
                task_id,
                memory_handle: decision.memory_ref.clone(),
                source_and_anchor,
                scope,
                status: format!("{:?}", decision.disposition).to_ascii_lowercase(),
                freshness: decision.reason.clone(),
                authority: if decision.provenance.evidence_refs.is_empty() {
                    "unproven".to_owned()
                } else {
                    "canonical_evidence_chain".to_owned()
                },
                conflicts: Vec::new(),
                admission,
                action_effect: "not_yet_observed".to_owned(),
                verifier_effect: "not_yet_observed".to_owned(),
                future_activation: decision.reason.clone(),
                canonical_receipt: None,
            }
        })
        .collect()
}

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

pub fn codecortex_report_ref(report: &CodeCortexReport) -> String {
    let git_head = report.git_head.as_deref().unwrap_or("unknown");
    let dirty_state_hash = match report.scope_binding.dirty_state_hash.trim() {
        "" if report.dirty => "unknown-dirty",
        "" => "clean",
        value => value,
    };
    // A write receipt is persistence metadata, not report identity. Keeping it
    // out of this handle makes the pre-persistence and post-persistence packet
    // byte-identical for the same task/Git/dirty-state evidence.
    format!(
        "codecortex_report:{}:{}:{}",
        report.task, git_head, dirty_state_hash
    )
}

fn attach_codecortex_reports(packet: &mut ContextPacketL3, reports: &[CodeCortexReport]) {
    let Some(report) = reports.last() else {
        return;
    };
    let report_ref = codecortex_report_ref(report);
    if !packet
        .exact_handles
        .iter()
        .any(|handle| handle == &report_ref)
    {
        packet.exact_handles.push(report_ref.clone());
    }
    packet.codecortex = Some(CodeCortexPacketView {
        report_refs: vec![report_ref],
        git_head: report.git_head.clone(),
        scope_binding: report.scope_binding.clone(),
        file_evidence: report.file_evidence.clone(),
        symbol_evidence: report.symbol_evidence.clone(),
        diagnostic_evidence: report.diagnostic_evidence.clone(),
        verifier_map: report.verifier_evidence.clone(),
        blast_radius: report.blast_radius.clone(),
        unknowns: codecortex_unknowns(report),
    });
}

fn codecortex_unknowns(report: &CodeCortexReport) -> Vec<String> {
    let mut unknowns = report.adapter_notes.clone();
    if report.dirty {
        unknowns.push("git working tree was dirty when CodeCortex report was generated".to_owned());
    }
    for evidence in &report.verifier_evidence {
        if matches!(
            evidence.status.as_str(),
            "failed" | "unavailable" | "disabled"
        ) {
            unknowns.push(format!(
                "{} adapter status was {}: {}",
                evidence.name, evidence.status, evidence.summary
            ));
        }
    }
    unknowns.sort();
    unknowns.dedup();
    unknowns
}

fn collect_exact_handles(
    request: &CompilePacketL3Request,
    recall: &RecallL0Response,
    buckets: &ClaimBuckets,
) -> Vec<String> {
    let mut exact_handles = BTreeSet::new();
    for handle in request
        .candidate_handles
        .iter()
        .chain(recall.handles.iter().map(|preview| &preview.handle))
    {
        exact_handles.insert(handle.clone());
    }
    for claim in buckets
        .relevant_verified_claims
        .iter()
        .chain(buckets.relevant_supported_claims.iter())
        .chain(buckets.weak_claims_warning.iter())
    {
        exact_handles.insert(claim_handle(claim));
    }
    exact_handles.into_iter().collect()
}

fn collect_source_receipts(fetch: &FetchAtomsL2Response) -> Vec<String> {
    fetch
        .evidence_atoms
        .iter()
        .map(|evidence| format!("evidence:{}", evidence.evidence_id))
        .chain(
            fetch
                .verification_runs
                .iter()
                .map(|verification| format!("verification:{}", verification.verification_id)),
        )
        .collect()
}

#[derive(Clone, Debug)]
pub struct UnderstandingProofValidator {
    read: ReadService,
}

impl UnderstandingProofValidator {
    pub const fn new(read: ReadService) -> Self {
        Self { read }
    }

    pub async fn validate(
        &self,
        proof: &UnderstandingProof,
    ) -> Result<UnderstandingProofReceipt, EngineError> {
        self.validate_with_codecortex(proof, &[]).await
    }

    pub async fn validate_with_codecortex(
        &self,
        proof: &UnderstandingProof,
        codecortex_reports: &[CodeCortexReport],
    ) -> Result<UnderstandingProofReceipt, EngineError> {
        let fetch = self
            .read
            .fetch_atoms_l2(&FetchAtomsL2Request {
                project_id: proof.project_id,
                handles: proof
                    .current_truth_refs
                    .iter()
                    .chain(proof.evidence_refs.iter())
                    .cloned()
                    .collect(),
                continuation: None,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await?;
        let index = HandleIndex::from_claims_and_evidence(&fetch.claims, &fetch);
        let mut errors = BTreeSet::new();
        let mut checked_refs = BTreeSet::new();

        if proof.code_task {
            validate_code_grounding(proof, codecortex_reports, &mut errors, &mut checked_refs);
        } else if proof.current_truth_refs.is_empty() {
            errors.insert(CognitiveGateReason::MissingCurrentTruth);
        }
        for reference in &proof.current_truth_refs {
            checked_refs.insert(reference.clone());
            match index.claim_status(reference) {
                Some(status) if weak_truth_status(status) => {
                    errors.insert(CognitiveGateReason::WeakClaimUsedAsTruth);
                }
                Some(_) => {}
                None => {
                    errors.insert(CognitiveGateReason::MissingCurrentTruth);
                }
            }
        }

        if !proof.code_task && proof.evidence_refs.is_empty() {
            errors.insert(CognitiveGateReason::MissingEvidence);
        }
        for reference in &proof.evidence_refs {
            checked_refs.insert(reference.clone());
            if !index.contains_evidence(reference) {
                errors.insert(CognitiveGateReason::MissingEvidence);
            }
        }

        if proof.causal_bridge.trim().is_empty() || proof.invariants.is_empty() {
            errors.insert(CognitiveGateReason::InsufficientCausalBridge);
        }
        if !proof.negative_memory_checked {
            errors.insert(CognitiveGateReason::KnownFailureNotAddressed);
        }
        if proof.expected_verifiers.is_empty() {
            errors.insert(CognitiveGateReason::VerifierMissing);
        }
        validate_skill_grounding(proof, &mut errors, &mut checked_refs);
        if unsafe_action(&proof.planned_action) {
            errors.insert(CognitiveGateReason::UnsafeActionScope);
        }

        let validation_errors: Vec<_> = errors.into_iter().collect();
        Ok(UnderstandingProofReceipt {
            task_id: proof.task_id.clone(),
            project_id: proof.project_id,
            accepted: validation_errors.is_empty(),
            validation_errors,
            checked_refs: checked_refs.into_iter().collect(),
            code_task: proof.code_task,
            codecortex_report_refs: proof.codecortex_report_refs.clone(),
            files_to_change: proof.files_to_change.clone(),
            files_to_inspect: proof.files_to_inspect.clone(),
        })
    }
}

fn validate_code_grounding(
    proof: &UnderstandingProof,
    reports: &[CodeCortexReport],
    errors: &mut BTreeSet<CognitiveGateReason>,
    checked_refs: &mut BTreeSet<String>,
) {
    for reference in &proof.codecortex_report_refs {
        checked_refs.insert(reference.clone());
    }
    for file in proof
        .files_to_change
        .iter()
        .chain(proof.files_to_inspect.iter())
    {
        checked_refs.insert(format!("file:{file}"));
    }

    if proof.codecortex_report_refs.is_empty() {
        errors.insert(CognitiveGateReason::MissingCodeCortexReport);
    }
    if proof.files_to_change.is_empty() && proof.files_to_inspect.is_empty() {
        errors.insert(CognitiveGateReason::MissingCodeFileRefs);
    }
    if proof.causal_bridge_from_goal_to_code.trim().is_empty() {
        errors.insert(CognitiveGateReason::MissingCodeCausalBridge);
    }
    if !proof.blast_radius_acknowledged {
        errors.insert(CognitiveGateReason::BlastRadiusNotAcknowledged);
    }
    let Some(report) = reports.last() else {
        errors.insert(CognitiveGateReason::MissingCodeCortexReport);
        return;
    };
    let expected_ref = codecortex_report_ref(report);
    if !proof
        .codecortex_report_refs
        .iter()
        .any(|reference| reference == &expected_ref)
    {
        errors.insert(CognitiveGateReason::StaleCodeCortexReport);
    }
    let known_files = codecortex_known_files(report);
    for file in proof
        .files_to_change
        .iter()
        .chain(proof.files_to_inspect.iter())
    {
        if !known_files.contains(&normalize_code_path(file)) {
            errors.insert(CognitiveGateReason::CodeFileNotInReport);
        }
    }
}

fn codecortex_known_files(report: &CodeCortexReport) -> HashSet<String> {
    report
        .file_evidence
        .iter()
        .chain(report.tracked_files.iter())
        .map(|evidence| normalize_code_path(&evidence.path))
        .chain(
            report
                .symbol_evidence
                .iter()
                .map(|evidence| normalize_code_path(&evidence.path)),
        )
        .chain(
            report
                .blast_radius
                .files
                .iter()
                .map(|path| normalize_code_path(path)),
        )
        .collect()
}

fn normalize_code_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}

#[derive(Clone, Copy, Debug)]
pub struct CognitiveGate;

impl CognitiveGate {
    pub fn decide(request: &CognitiveGateRequest) -> CognitiveGateDecision {
        if unsafe_action(&request.requested_action)
            || request
                .receipt
                .validation_errors
                .contains(&CognitiveGateReason::UnsafeActionScope)
        {
            return decision(
                request,
                CognitiveGateOutcome::Block,
                &[CognitiveGateReason::UnsafeActionScope],
            );
        }
        if request
            .receipt
            .validation_errors
            .iter()
            .any(|reason| code_grounding_error(*reason))
        {
            return decision(
                request,
                CognitiveGateOutcome::Block,
                &request.receipt.validation_errors,
            );
        }
        if request
            .receipt
            .validation_errors
            .iter()
            .any(|reason| skill_grounding_error(*reason))
        {
            return decision(
                request,
                CognitiveGateOutcome::Block,
                &request.receipt.validation_errors,
            );
        }
        if request.receipt.accepted && request.receipt.code_task {
            return decision(
                request,
                CognitiveGateOutcome::AllowReadOnly,
                &[CognitiveGateReason::Allowed],
            );
        }
        if request.receipt.accepted {
            return decision(
                request,
                CognitiveGateOutcome::Allow,
                &[CognitiveGateReason::Allowed],
            );
        }
        if read_only_action(&request.requested_action) {
            return decision(
                request,
                CognitiveGateOutcome::AllowReadOnly,
                &request.receipt.validation_errors,
            );
        }
        if request.receipt.validation_errors == [CognitiveGateReason::MissingEvidence] {
            return decision(
                request,
                CognitiveGateOutcome::RequireProbe,
                &[CognitiveGateReason::MissingEvidence],
            );
        }
        decision(
            request,
            CognitiveGateOutcome::Block,
            &request.receipt.validation_errors,
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CompletionGate;

impl CompletionGate {
    pub fn decide(proof: &CompletionProof) -> CompletionGateDecision {
        let mut reasons = Vec::new();
        if proof.evidence.is_empty() {
            reasons.push("missing_completion_evidence".to_owned());
        }
        if proof.checks_run.is_empty() {
            reasons.push("missing_verifier_runs".to_owned());
        }
        if proof.acceptance_items.is_empty() {
            reasons.push("missing_acceptance_items".to_owned());
        }
        if !proof.checks_not_run.is_empty() {
            reasons.push("checks_not_run_present".to_owned());
        }
        if !proof.skill_refs.is_empty() && proof.skill_execution_proof_refs.is_empty() {
            reasons.push("missing_skill_execution_proof".to_owned());
        }
        if proof
            .skill_execution_proof_refs
            .iter()
            .any(|reference| reference.starts_with("failed:"))
        {
            reasons.push("required_skill_failed".to_owned());
        }
        for item in &proof.acceptance_items {
            if item.status != "verified" {
                reasons.push(format!("acceptance_not_verified:{}", item.item));
            }
            if item.evidence.trim().is_empty() || item.verifier.trim().is_empty() {
                reasons.push(format!("acceptance_missing_evidence:{}", item.item));
            }
        }

        let final_status = if reasons.iter().any(|reason| {
            reason == "required_skill_failed"
                || (reason.starts_with("acceptance_not_verified:") && reason.contains("failed"))
        }) {
            CompletionStatus::FailedVerifier
        } else if reasons.is_empty() {
            CompletionStatus::DoneVerified
        } else {
            CompletionStatus::PartialProgress
        };

        CompletionGateDecision {
            task_id: proof.task_id.clone(),
            project_id: proof.project_id,
            final_status,
            reasons,
        }
    }

    pub fn decide_with_incident_context(
        proof: &CompletionProof,
        incident_lockdown_active: bool,
    ) -> CompletionGateDecision {
        let mut decision = Self::decide(proof);
        if incident_lockdown_active {
            decision.reasons.push("incident_lockdown_active".to_owned());
            decision.final_status = CompletionStatus::UnsafeToFinish;
        }
        decision
    }

    pub fn decide_with_work_context(
        proof: &CompletionProof,
        work_item: Option<&WorkItem>,
        work_lease: Option<&WorkLease>,
    ) -> CompletionGateDecision {
        let base = Self::decide(proof);
        let mut reasons = base.reasons;
        match work_item {
            Some(item) => {
                if proof.project_id != item.project_id || proof.task_id != item.task_id.to_string()
                {
                    reasons.push("work_item_completion_proof_scope_mismatch".to_owned());
                }
                if item.required && item.status != WorkItemStatus::Completed {
                    reasons.push("work_item_not_satisfied".to_owned());
                }
                if item.required && item.status == WorkItemStatus::Completed {
                    for requirement in item
                        .required_verifiers
                        .iter()
                        .filter(|requirement| requirement.required_for_done)
                    {
                        let matching = item
                            .verifier_run_refs
                            .iter()
                            .filter(|reference| reference.name == requirement.name)
                            .collect::<Vec<_>>();
                        if matching.is_empty() {
                            reasons.push(format!(
                                "work_item_required_verifier_missing:{}",
                                requirement.name
                            ));
                        }
                        for reference in matching {
                            if reference.status != VerifierStatus::Passed {
                                reasons.push(format!(
                                    "work_item_required_verifier_failed:{}",
                                    requirement.name
                                ));
                            }
                            if !proof.evidence.iter().any(|evidence| {
                                evidence.contains(&reference.verifier_run_id.to_string())
                            }) {
                                reasons.push(format!(
                                    "completion_proof_missing_work_verifier_ref:{}",
                                    reference.verifier_run_id
                                ));
                            }
                        }
                    }
                }
            }
            None => reasons.push("missing_work_item".to_owned()),
        }
        match work_lease {
            Some(lease) => {
                if matches!(
                    lease.state,
                    WorkLeaseState::Revoked | WorkLeaseState::Expired | WorkLeaseState::Denied
                ) {
                    reasons.push("work_lease_not_satisfied".to_owned());
                }
                if let Some(item) = work_item
                    && item.work_item_id != lease.work_item_id
                {
                    reasons.push("work_item_lease_mismatch".to_owned());
                }
            }
            None => reasons.push("missing_work_lease".to_owned()),
        }

        let final_status = if base.final_status == CompletionStatus::FailedVerifier {
            CompletionStatus::FailedVerifier
        } else if reasons.is_empty() {
            CompletionStatus::DoneVerified
        } else {
            CompletionStatus::PartialProgress
        };

        CompletionGateDecision {
            task_id: proof.task_id.clone(),
            project_id: proof.project_id,
            final_status,
            reasons,
        }
    }

    /// Applies the existing completion owner to the canonical task's runtime
    /// evidence. This is intentionally a `CompletionGate` method: coordination,
    /// work, and candidate state constrain one task decision instead of
    /// creating another finish authority.
    pub fn decide_for_task(
        proof: &CompletionProof,
        project_id: ProjectId,
        task_id: TaskId,
        work_state: &WorkState,
        incident_lockdown_active: bool,
    ) -> CompletionGateDecision {
        let base = Self::decide_with_incident_context(proof, incident_lockdown_active);
        let mut reasons = base.reasons;

        if proof.project_id != project_id || proof.task_id != task_id.to_string() {
            reasons.push("completion_proof_task_scope_mismatch".to_owned());
        }

        let coordination =
            StopCoordinationGate.evaluate(work_state, Some(project_id), Some(task_id));
        if !coordination.allow {
            reasons.extend(
                coordination
                    .reasons
                    .into_iter()
                    .map(|reason| format!("stop_coordination:{reason}")),
            );
        }

        append_required_work_completion_reasons(
            proof,
            project_id,
            task_id,
            work_state,
            &mut reasons,
        );
        append_candidate_completion_reasons(proof, project_id, task_id, work_state, &mut reasons);

        let final_status = if base.final_status == CompletionStatus::UnsafeToFinish {
            CompletionStatus::UnsafeToFinish
        } else if base.final_status == CompletionStatus::FailedVerifier
            || reasons
                .iter()
                .any(|reason| reason.starts_with("required_work_item_verifier_failed:"))
        {
            CompletionStatus::FailedVerifier
        } else if reasons.is_empty() {
            CompletionStatus::DoneVerified
        } else {
            CompletionStatus::PartialProgress
        };

        CompletionGateDecision {
            task_id: proof.task_id.clone(),
            project_id: proof.project_id,
            final_status,
            reasons,
        }
    }
}

fn append_required_work_completion_reasons(
    proof: &CompletionProof,
    project_id: ProjectId,
    task_id: TaskId,
    work_state: &WorkState,
    reasons: &mut Vec<String>,
) {
    for item in work_state
        .work_items
        .iter()
        .filter(|item| item.project_id == project_id && item.task_id == task_id && item.required)
    {
        if item.status != WorkItemStatus::Completed {
            reasons.push(format!(
                "required_work_item_not_completed:{}",
                item.work_item_id
            ));
            continue;
        }
        if !proof
            .evidence
            .iter()
            .any(|evidence| evidence.contains(&item.work_item_id.to_string()))
        {
            reasons.push(format!(
                "completion_proof_missing_work_item_ref:{}",
                item.work_item_id
            ));
        }
        for requirement in item
            .required_verifiers
            .iter()
            .filter(|requirement| requirement.required_for_done)
        {
            let matching = item
                .verifier_run_refs
                .iter()
                .filter(|reference| reference.name == requirement.name)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                reasons.push(format!(
                    "required_work_item_verifier_missing:{}:{}",
                    item.work_item_id, requirement.name
                ));
                continue;
            }
            if matching
                .iter()
                .any(|reference| reference.status != VerifierStatus::Passed)
            {
                reasons.push(format!(
                    "required_work_item_verifier_failed:{}:{}",
                    item.work_item_id, requirement.name
                ));
            }
            for reference in matching {
                if !proof
                    .evidence
                    .iter()
                    .any(|evidence| evidence.contains(&reference.verifier_run_id.to_string()))
                {
                    reasons.push(format!(
                        "completion_proof_missing_work_verifier_ref:{}",
                        reference.verifier_run_id
                    ));
                }
            }
        }
    }
}

fn append_candidate_completion_reasons(
    proof: &CompletionProof,
    project_id: ProjectId,
    task_id: TaskId,
    work_state: &WorkState,
    reasons: &mut Vec<String>,
) {
    let mut latest_candidate_by_work_item = BTreeMap::new();
    for candidate in work_state.candidate_diffs.iter().filter(|candidate| {
        candidate.project_id == project_id
            && candidate.task_id == task_id
            && candidate.file_count > 0
            && !candidate.changed_files.is_empty()
    }) {
        latest_candidate_by_work_item
            .entry(candidate.work_item_id)
            .and_modify(|current: &mut &eliot_types::CandidateDiff| {
                if candidate.created_at > current.created_at {
                    *current = candidate;
                }
            })
            .or_insert(candidate);
    }
    for candidate in latest_candidate_by_work_item.into_values() {
        if candidate.capture_status != CandidateDiffStatus::AcceptedForPatchRunner
            || candidate.write_receipt.is_none()
        {
            reasons.push(format!(
                "candidate_diff_not_accepted:{}",
                candidate.candidate_diff_id
            ));
        }
        if !proof
            .evidence
            .iter()
            .any(|evidence| evidence.contains(&candidate.candidate_diff_id.to_string()))
        {
            reasons.push(format!(
                "completion_proof_missing_candidate_diff_ref:{}",
                candidate.candidate_diff_id
            ));
        }
        let latest_review = work_state
            .candidate_reviews
            .iter()
            .filter(|review| review.candidate_diff_id == candidate.candidate_diff_id)
            .max_by_key(|review| review.created_at);
        match latest_review {
            Some(review)
                if review.decision == CandidateReviewDecision::AcceptForPatchRunner
                    && review.write_receipt.is_some() =>
            {
                if !proof
                    .evidence
                    .iter()
                    .any(|evidence| evidence.contains(&review.review_id))
                {
                    reasons.push(format!(
                        "completion_proof_missing_candidate_review_ref:{}",
                        review.review_id
                    ));
                }
            }
            Some(review) => reasons.push(format!(
                "candidate_review_not_accepted:{}",
                review.review_id
            )),
            None => reasons.push(format!(
                "missing_candidate_review:{}",
                candidate.candidate_diff_id
            )),
        }
    }
}

fn decision(
    request: &CognitiveGateRequest,
    decision: CognitiveGateOutcome,
    reasons: &[CognitiveGateReason],
) -> CognitiveGateDecision {
    CognitiveGateDecision {
        task_id: request.receipt.task_id.clone(),
        project_id: request.receipt.project_id,
        decision,
        reasons: reasons.to_vec(),
    }
}

fn normalized_filter(handles: &[String]) -> HashSet<String> {
    handles
        .iter()
        .flat_map(|handle| {
            [
                handle.clone(),
                handle.trim_start_matches("claim:").to_owned(),
            ]
        })
        .collect()
}

fn claim_handle(claim: &ClaimCard) -> String {
    format!("claim:{}", claim.claim_id)
}

fn max_revision(left: MemoryRevision, right: MemoryRevision) -> MemoryRevision {
    if left >= right { left } else { right }
}

fn stable_revision_capture_time(revision: MemoryRevision) -> OffsetDateTime {
    i64::try_from(revision.value())
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

pub fn serialized_supplement_tokens<T: serde::Serialize>(
    supplement: &T,
) -> Result<usize, EngineError> {
    Ok(serde_json::to_vec(supplement)?.len().div_ceil(4))
}

#[derive(serde::Serialize)]
struct PacketReturnMetadataView<'a> {
    packet_budget_decision: &'a PacketBudgetDecision,
    compile_audit: &'a PacketCompileAuditReport,
}

pub fn packet_return_metadata_tokens(
    budget: &PacketBudgetDecision,
    compile_audit: &PacketCompileAuditReport,
) -> Result<usize, EngineError> {
    serialized_supplement_tokens(&PacketReturnMetadataView {
        packet_budget_decision: budget,
        compile_audit,
    })
}

/// Applies the Governor default hard ceiling to one already assembled packet
/// candidate. The candidate is cloned, so a hard-ceiling failure is
/// side-effect-free.
pub fn finalize_packet_candidate(
    candidate: &ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    task: Option<&TaskContract>,
    project_evidence: &ProjectUnderstandingEvidence,
    previous_packet: Option<&ContextPacketL3>,
    preferred_tokens: usize,
    required_handles: &[String],
) -> Result<PacketRenderOutcome, PacketCompileError> {
    finalize_packet_candidate_with_policy(
        candidate,
        frame,
        task,
        project_evidence,
        previous_packet,
        PacketBudgetPolicy::governor_default(preferred_tokens),
        required_handles,
    )
}

/// Strict/custom ceilings are exposed for Governor and isolated admin/test
/// callers. Production callers should use [`finalize_packet_candidate`].
pub fn finalize_packet_candidate_with_policy(
    candidate: &ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    task: Option<&TaskContract>,
    project_evidence: &ProjectUnderstandingEvidence,
    previous_packet: Option<&ContextPacketL3>,
    budget_policy: PacketBudgetPolicy,
    required_handles: &[String],
) -> Result<PacketRenderOutcome, PacketCompileError> {
    finalize_packet_candidate_with_policy_and_audit_context(
        candidate,
        frame,
        task,
        project_evidence,
        previous_packet,
        budget_policy,
        required_handles,
        PacketCompileAuditContext::default(),
    )
}

/// Finalizes one candidate while accounting for the exact named
/// `packet_budget_decision` and `compile_audit` response fields. The audit
/// context is caller-owned request metadata; semantic counters are engine-owned.
#[allow(clippy::too_many_arguments)]
pub fn finalize_packet_candidate_with_policy_and_audit_context(
    candidate: &ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    task: Option<&TaskContract>,
    project_evidence: &ProjectUnderstandingEvidence,
    previous_packet: Option<&ContextPacketL3>,
    budget_policy: PacketBudgetPolicy,
    required_handles: &[String],
    audit_context: PacketCompileAuditContext,
) -> Result<PacketRenderOutcome, PacketCompileError> {
    let mut packet =
        prepare_packet_candidate(candidate, frame, task, project_evidence, previous_packet);
    finalize_precompiled_packet_with_policy_and_audit_context(
        &mut packet,
        frame,
        budget_policy,
        required_handles,
        audit_context,
    )
}

fn prepare_packet_candidate(
    candidate: &ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    task: Option<&TaskContract>,
    project_evidence: &ProjectUnderstandingEvidence,
    previous_packet: Option<&ContextPacketL3>,
) -> ContextPacketL3 {
    let mut packet = candidate.clone();
    packet.packet_id.clear();
    packet.packet_quality = None;
    packet.project_understanding = None;

    // Restore packet-local continuity before compiling understanding so the
    // final model observes the restored task frame. The second restore is
    // idempotent and carries forward prior predictions after the model exists.
    ProjectContinuityService::restore(&mut packet, previous_packet);
    let project_understanding =
        ProjectUnderstandingCompiler::compile(&packet, frame, task, project_evidence);
    packet.project_understanding = Some(project_understanding);
    ProjectContinuityService::restore(&mut packet, previous_packet);
    packet
}

fn finalize_precompiled_packet_with_policy_and_audit_context(
    packet: &mut ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    budget_policy: PacketBudgetPolicy,
    required_handles: &[String],
    audit_context: PacketCompileAuditContext,
) -> Result<PacketRenderOutcome, PacketCompileError> {
    if packet.project_understanding.is_none() {
        return Err(EngineError::WriteRejected(
            "precompiled packet has no project understanding".to_owned(),
        )
        .into());
    }
    let audit = PacketCompileAudit {
        project_understanding_compiles: 1,
        budget_renders: 1,
        identity_finalizations: 1,
    };
    let compile_audit = PacketCompileAuditReport {
        stages: audit_context.stages,
        source_reads: audit_context.source_reads,
        semantic: audit.clone(),
        read_counters: audit_context.read_counters,
    };
    let mut budget_metadata_tokens = 0;
    for _ in 0..64 {
        let (mut rendered_packet, mut budget) = render_packet_with_budget_policy(
            packet,
            budget_policy,
            required_handles,
            budget_metadata_tokens,
        )?;
        PacketQualityService::finalize(&mut rendered_packet, frame)?;
        budget.section_tokens = packet_section_accounting(&rendered_packet)?;
        budget
            .section_tokens
            .insert("returned_supplements".to_owned(), budget.supplement_tokens);
        budget.section_tokens.insert(
            "packet_budget_decision_and_compile_audit".to_owned(),
            budget_metadata_tokens,
        );
        let next_metadata_tokens = packet_return_metadata_tokens(&budget, &compile_audit)?;
        if next_metadata_tokens == budget_metadata_tokens {
            let project_understanding =
                rendered_packet
                    .project_understanding
                    .clone()
                    .ok_or_else(|| {
                        EngineError::WriteRejected("final project understanding missing".to_owned())
                    })?;
            return Ok(PacketRenderOutcome {
                packet: rendered_packet,
                project_understanding,
                budget,
                audit,
                compile_audit,
            });
        }
        budget_metadata_tokens = next_metadata_tokens;
    }
    Err(EngineError::WriteRejected(
        "packet budget metadata fixed point did not converge".to_owned(),
    )
    .into())
}

fn render_packet_with_budget_policy(
    candidate: &ContextPacketL3,
    policy: PacketBudgetPolicy,
    required_handles: &[String],
    budget_metadata_tokens: usize,
) -> Result<(ContextPacketL3, PacketBudgetDecision), PacketCompileError> {
    let required_handles = required_handles.iter().collect::<BTreeSet<_>>();
    let (_, packet_mandatory_floor_tokens) = mandatory_floor(candidate, &required_handles, 0)?;
    let total_supplement_tokens = policy
        .supplement_tokens
        .saturating_add(budget_metadata_tokens);
    let (mandatory_floor_packet, mandatory_floor_tokens) =
        mandatory_floor(candidate, &required_handles, total_supplement_tokens)?;
    if mandatory_floor_tokens > policy.hard_ceiling_tokens {
        let expansion_handles =
            packet_expansion_handles(&mandatory_floor_packet, &required_handles);
        let mut section_tokens = packet_section_accounting(&mandatory_floor_packet)?;
        section_tokens.insert("returned_supplements".to_owned(), policy.supplement_tokens);
        section_tokens.insert(
            "packet_budget_decision_and_compile_audit".to_owned(),
            budget_metadata_tokens,
        );
        return Err(PacketHardCeilingExceeded {
            preferred_tokens: policy.preferred_tokens,
            hard_ceiling_tokens: policy.hard_ceiling_tokens,
            mandatory_floor_tokens,
            section_tokens,
            expansion_handles,
        }
        .into());
    }

    let preferred_within_ceiling = policy.preferred_tokens.min(policy.hard_ceiling_tokens);
    let effective_tokens = preferred_within_ceiling.max(mandatory_floor_tokens);
    let render_mode = if policy.preferred_tokens > policy.hard_ceiling_tokens {
        PacketRenderMode::PreferredBudgetClampedToHardCeiling
    } else if mandatory_floor_tokens > policy.preferred_tokens {
        PacketRenderMode::PreferredBudgetExceededByMandatoryFloor
    } else {
        PacketRenderMode::WithinPreferred
    };
    let reason = match render_mode {
        PacketRenderMode::WithinPreferred => "within_preferred_budget",
        PacketRenderMode::PreferredBudgetExceededByMandatoryFloor => {
            "preferred_budget_exceeded_by_mandatory_floor"
        }
        PacketRenderMode::PreferredBudgetClampedToHardCeiling => {
            "preferred_budget_clamped_to_hard_ceiling"
        }
    }
    .to_owned();

    let Some(mut packet) = fit_packet_to_limit(
        candidate,
        effective_tokens,
        total_supplement_tokens,
        &required_handles,
    )?
    else {
        let mut section_tokens = packet_section_accounting(&mandatory_floor_packet)?;
        section_tokens.insert("returned_supplements".to_owned(), policy.supplement_tokens);
        section_tokens.insert(
            "packet_budget_decision_and_compile_audit".to_owned(),
            budget_metadata_tokens,
        );
        return Err(PacketHardCeilingExceeded {
            preferred_tokens: policy.preferred_tokens,
            hard_ceiling_tokens: policy.hard_ceiling_tokens,
            mandatory_floor_tokens,
            section_tokens,
            expansion_handles: packet_expansion_handles(&mandatory_floor_packet, &required_handles),
        }
        .into());
    };
    let estimated_tokens = packet
        .token_budget_report
        .estimated_tokens
        .saturating_add(total_supplement_tokens);
    let mut section_tokens = packet_section_accounting(&packet)?;
    section_tokens.insert("returned_supplements".to_owned(), policy.supplement_tokens);
    section_tokens.insert(
        "packet_budget_decision_and_compile_audit".to_owned(),
        budget_metadata_tokens,
    );
    packet.token_budget_report.max_tokens = effective_tokens;
    Ok((
        packet,
        PacketBudgetDecision {
            preferred_tokens: policy.preferred_tokens,
            hard_ceiling_tokens: policy.hard_ceiling_tokens,
            supplement_tokens: policy.supplement_tokens,
            budget_metadata_tokens,
            packet_mandatory_floor_tokens,
            mandatory_floor_tokens,
            effective_tokens,
            estimated_tokens,
            render_mode,
            section_tokens,
            reason,
        },
    ))
}

fn packet_expansion_handles(
    packet: &ContextPacketL3,
    required_handles: &BTreeSet<&String>,
) -> Vec<String> {
    let mut handles = required_handles
        .iter()
        .map(|handle| (*handle).clone())
        .chain(packet.exact_handles.iter().cloned())
        .chain(packet.source_receipts.iter().cloned())
        .chain(
            packet
                .decision_locality_suffix
                .exact_load_bearing_atoms
                .iter()
                .cloned(),
        )
        .collect::<Vec<_>>();
    if let Some(understanding) = &packet.project_understanding {
        handles.extend(understanding.memory_refs_used.iter().cloned());
        handles.extend(understanding.current_truth_refs.iter().cloned());
        handles.extend(understanding.historical_or_stale_refs.iter().cloned());
        handles.extend(understanding.files_to_inspect.iter().cloned());
        handles.extend(understanding.files_to_change.iter().cloned());
    }
    handles.retain(|handle| !handle.trim().is_empty());
    handles.sort();
    handles.dedup();
    handles
}

fn mandatory_floor(
    candidate: &ContextPacketL3,
    required_handles: &BTreeSet<&String>,
    supplement_tokens: usize,
) -> Result<(ContextPacketL3, usize), EngineError> {
    let mut packet = candidate.clone();
    packet.packet_id.clear();
    packet.packet_quality = None;
    let mut sections_truncated = Vec::new();
    while trim_next(&mut packet, required_handles, &mut sections_truncated) {}
    let truncated = !sections_truncated.is_empty();
    packet.truncation.truncated |= truncated;
    packet.truncation.returned = packet.exact_handles.len();

    // The budget report is itself delivered content. Iterate both its estimate
    // and its effective limit to obtain a stable, reproducible floor.
    let mut floor = supplement_tokens;
    loop {
        let packet_tokens =
            finalize_budget_report(&mut packet, floor, truncated, &sections_truncated)?;
        let next = packet_tokens.saturating_add(supplement_tokens);
        if next == floor {
            return Ok((packet, next));
        }
        floor = next;
    }
}

fn fit_packet_to_limit(
    candidate: &ContextPacketL3,
    limit: usize,
    supplement_tokens: usize,
    required_handles: &BTreeSet<&String>,
) -> Result<Option<ContextPacketL3>, EngineError> {
    let mut packet = candidate.clone();
    packet.packet_id.clear();
    packet.packet_quality = None;
    let mut sections_truncated = Vec::new();
    loop {
        let truncated = !sections_truncated.is_empty();
        packet.truncation.truncated |= truncated;
        packet.truncation.returned = packet.exact_handles.len();
        let estimated = finalize_budget_report(&mut packet, limit, truncated, &sections_truncated)?;
        if estimated.saturating_add(supplement_tokens) <= limit {
            return Ok(Some(packet));
        }
        if !trim_next(&mut packet, required_handles, &mut sections_truncated) {
            return Ok(None);
        }
    }
}

fn enforce_budget(
    packet: &mut ContextPacketL3,
    max_tokens: usize,
    required_handles: &[String],
) -> Result<(), EngineError> {
    let required_handles = required_handles.iter().collect::<BTreeSet<_>>();
    let mut sections_truncated = Vec::new();
    packet.token_budget_report = TokenBudgetReport {
        max_tokens,
        estimated_tokens: 0,
        truncated: false,
        sections_truncated: Vec::new(),
    };

    loop {
        let content_estimate = estimate_tokens(packet)?;
        if content_estimate <= max_tokens {
            break;
        }
        if !trim_next(packet, &required_handles, &mut sections_truncated) {
            return Err(EngineError::PacketFloorExceedsBudget {
                max_tokens,
                estimated_tokens: content_estimate,
                section_tokens: packet_section_accounting(packet)?,
            });
        }
    }

    let truncated = !sections_truncated.is_empty();
    let verified_estimate =
        finalize_budget_report(packet, max_tokens, truncated, &sections_truncated)?;
    if verified_estimate > max_tokens {
        return Err(EngineError::PacketFloorExceedsBudget {
            max_tokens,
            estimated_tokens: verified_estimate,
            section_tokens: packet_section_accounting(packet)?,
        });
    }
    packet.truncation.truncated |= truncated;
    packet.truncation.returned = packet.exact_handles.len();
    Ok(())
}

fn finalize_budget_report(
    packet: &mut ContextPacketL3,
    max_tokens: usize,
    truncated: bool,
    sections_truncated: &[String],
) -> Result<usize, EngineError> {
    let mut estimated = 0;
    loop {
        packet.token_budget_report = TokenBudgetReport {
            max_tokens,
            estimated_tokens: estimated,
            truncated,
            sections_truncated: sections_truncated.to_owned(),
        };
        let next = estimate_tokens(packet)?;
        if next == estimated {
            return Ok(next);
        }
        debug_assert!(next > estimated);
        estimated = next;
    }
}

fn trim_next(
    packet: &mut ContextPacketL3,
    required_handles: &BTreeSet<&String>,
    sections: &mut Vec<String>,
) -> bool {
    trim_codecortex(packet, required_handles, sections)
        || trim_section(&mut packet.open_questions, "open_questions", sections)
        || trim_section(&mut packet.known_decisions, "known_decisions", sections)
        || trim_section(&mut packet.recent_failures, "recent_failures", sections)
        || trim_section(&mut packet.negative_memory, "negative_memory", sections)
        || trim_section(&mut packet.historical_memory, "historical_memory", sections)
        || trim_section(
            &mut packet.weak_claims_warning,
            "weak_claims_warning",
            sections,
        )
        || trim_section(
            &mut packet.relevant_supported_claims,
            "relevant_supported_claims",
            sections,
        )
        || trim_section(
            &mut packet.relevant_verified_claims,
            "relevant_verified_claims",
            sections,
        )
        || trim_section(&mut packet.current_truth, "current_truth", sections)
        || trim_section(
            &mut packet.procedural_skills.anti_scope_warnings,
            "procedural_skills.anti_scope_warnings",
            sections,
        )
        || trim_section(
            &mut packet.procedural_skills.activation_decisions,
            "procedural_skills.activation_decisions",
            sections,
        )
        || trim_section(
            &mut packet.procedural_skills.excluded_skills,
            "procedural_skills.excluded_skills",
            sections,
        )
        || trim_section(
            &mut packet.procedural_skills.included_skills,
            "procedural_skills.included_skills",
            sections,
        )
        || trim_section(&mut packet.source_receipts, "source_receipts", sections)
        || trim_non_requested_handle(&mut packet.exact_handles, required_handles, sections)
}

fn trim_codecortex(
    packet: &mut ContextPacketL3,
    required_handles: &BTreeSet<&String>,
    sections: &mut Vec<String>,
) -> bool {
    let Some(codecortex) = packet.codecortex.as_mut() else {
        return false;
    };
    if !codecortex.file_evidence.is_empty()
        || !codecortex.symbol_evidence.is_empty()
        || !codecortex.diagnostic_evidence.is_empty()
        || !codecortex.verifier_map.is_empty()
        || !codecortex.blast_radius.files.is_empty()
        || !codecortex.blast_radius.crates.is_empty()
        || !codecortex.blast_radius.reasons.is_empty()
        || !codecortex.unknowns.is_empty()
    {
        codecortex.file_evidence.clear();
        codecortex.symbol_evidence.clear();
        codecortex.diagnostic_evidence.clear();
        codecortex.verifier_map.clear();
        codecortex.blast_radius.files.clear();
        codecortex.blast_radius.crates.clear();
        codecortex.blast_radius.reasons.clear();
        codecortex.unknowns.clear();
        push_section(sections, "codecortex.full_to_scope_summary");
        return true;
    }
    if codecortex.git_head.is_some()
        || codecortex.scope_binding != eliot_types::CodeCortexScopeBinding::default()
    {
        codecortex.git_head = None;
        codecortex.scope_binding = eliot_types::CodeCortexScopeBinding::default();
        push_section(sections, "codecortex.scope_summary_to_handle");
        return true;
    }

    let report_refs = codecortex.report_refs.clone();
    packet.codecortex = None;
    packet.exact_handles.retain(|handle| {
        required_handles.contains(handle)
            || !report_refs.iter().any(|report_ref| report_ref == handle)
    });
    push_section(sections, "codecortex.handle_dropped");
    true
}

fn trim_non_requested_handle(
    handles: &mut Vec<String>,
    required_handles: &BTreeSet<&String>,
    sections: &mut Vec<String>,
) -> bool {
    let Some(index) = handles
        .iter()
        .rposition(|handle| !required_handles.contains(handle))
    else {
        return false;
    };
    handles.remove(index);
    push_section(sections, "non_requested_exact_handles");
    true
}

fn trim_section<T>(values: &mut Vec<T>, name: &str, sections: &mut Vec<String>) -> bool {
    if values.pop().is_some() {
        push_section(sections, name);
        return true;
    }
    false
}

fn push_section(sections: &mut Vec<String>, name: &str) {
    if !sections.iter().any(|section| section == name) {
        sections.push(name.to_owned());
    }
}

fn estimate_tokens(packet: &ContextPacketL3) -> Result<usize, EngineError> {
    let mut bytes = 0usize;
    bytes += estimate_serialized_value(&packet.project_id)?;
    bytes += estimate_serialized_value(&packet.at_revision)?;
    bytes += packet.task_id.len();
    bytes += packet.goal.len();
    bytes += estimate_serialized_value(&packet.project_understanding)?;
    bytes += estimate_serialized_slice(&packet.acceptance_items)?;
    bytes += estimate_serialized_slice(&packet.current_truth)?;
    bytes += estimate_serialized_slice(&packet.relevant_verified_claims)?;
    bytes += estimate_serialized_slice(&packet.relevant_supported_claims)?;
    bytes += estimate_serialized_slice(&packet.weak_claims_warning)?;
    bytes += estimate_serialized_slice(&packet.negative_memory)?;
    bytes += estimate_serialized_slice(&packet.recent_failures)?;
    bytes += estimate_serialized_slice(&packet.known_decisions)?;
    bytes += estimate_serialized_slice(&packet.open_questions)?;
    bytes += estimate_serialized_slice(&packet.exact_handles)?;
    bytes += estimate_serialized_slice(&packet.source_receipts)?;
    bytes += estimate_serialized_value(&packet.current_truth_snapshot)?;
    bytes += estimate_serialized_value(&packet.epistemic_state)?;
    bytes += estimate_serialized_slice(&packet.active_plan)?;
    bytes += estimate_serialized_slice(&packet.completed_work)?;
    bytes += estimate_serialized_slice(&packet.killed_paths)?;
    bytes += estimate_serialized_slice(&packet.causal_bridge)?;
    bytes += estimate_serialized_slice(&packet.memory_decisions)?;
    bytes += estimate_serialized_value(&packet.decision_locality_suffix)?;
    bytes += estimate_serialized_value(&packet.memory_applicability)?;
    bytes += estimate_serialized_slice(&packet.historical_memory)?;
    bytes += estimate_serialized_value(&packet.procedural_skills)?;
    if let Some(codecortex) = &packet.codecortex {
        bytes += estimate_serialized_slice(&codecortex.report_refs)?;
        bytes += estimate_serialized_value(&codecortex.git_head)?;
        bytes += estimate_serialized_slice(&codecortex.file_evidence)?;
        bytes += estimate_serialized_slice(&codecortex.symbol_evidence)?;
        bytes += estimate_serialized_slice(&codecortex.diagnostic_evidence)?;
        bytes += estimate_serialized_slice(&codecortex.verifier_map)?;
        bytes += estimate_serialized_value(&codecortex.blast_radius)?;
        bytes += estimate_serialized_slice(&codecortex.unknowns)?;
    }
    bytes += estimate_serialized_value(&packet.token_budget_report)?;
    bytes += estimate_serialized_value(&packet.truncation)?;
    Ok(bytes.div_ceil(4))
}

pub fn refinalize_compiled_packet(
    packet: &mut ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    max_tokens: usize,
    required_handles: &[String],
) -> Result<(), EngineError> {
    enforce_budget(packet, max_tokens, required_handles)?;
    PacketQualityService::finalize(packet, frame)
}

pub fn packet_section_accounting(
    packet: &ContextPacketL3,
) -> Result<BTreeMap<String, usize>, EngineError> {
    let mut sections = BTreeMap::new();
    sections.insert(
        "task_and_acceptance_frame".to_owned(),
        (estimate_serialized_value(&packet.project_id)?
            + estimate_serialized_value(&packet.task_id)?
            + estimate_serialized_value(&packet.goal)?
            + estimate_serialized_value(&packet.task_execution_class)?
            + estimate_serialized_value(&packet.memory_confidence)?
            + estimate_serialized_slice(&packet.acceptance_items)?
            + estimate_serialized_value(&packet.at_revision)?)
        .div_ceil(4),
    );
    sections.insert(
        "project_understanding".to_owned(),
        estimate_serialized_value(&packet.project_understanding)?.div_ceil(4),
    );
    sections.insert(
        "current_truth".to_owned(),
        estimate_serialized_slice(&packet.current_truth)?.div_ceil(4),
    );
    sections.insert(
        "verified_and_supported_claims".to_owned(),
        (estimate_serialized_slice(&packet.relevant_verified_claims)?
            + estimate_serialized_slice(&packet.relevant_supported_claims)?)
        .div_ceil(4),
    );
    sections.insert(
        "warnings_failures_and_questions".to_owned(),
        (estimate_serialized_slice(&packet.weak_claims_warning)?
            + estimate_serialized_slice(&packet.negative_memory)?
            + estimate_serialized_slice(&packet.recent_failures)?
            + estimate_serialized_slice(&packet.known_decisions)?
            + estimate_serialized_slice(&packet.open_questions)?)
        .div_ceil(4),
    );
    sections.insert(
        "exact_handles_and_source_receipts".to_owned(),
        (estimate_serialized_slice(&packet.exact_handles)?
            + estimate_serialized_slice(&packet.source_receipts)?)
        .div_ceil(4),
    );
    sections.insert(
        "truth_snapshot_and_epistemic_state".to_owned(),
        (estimate_serialized_value(&packet.current_truth_snapshot)?
            + estimate_serialized_value(&packet.epistemic_state)?)
        .div_ceil(4),
    );
    sections.insert(
        "decision_locality_suffix".to_owned(),
        estimate_serialized_value(&packet.decision_locality_suffix)?.div_ceil(4),
    );
    sections.insert(
        "codecortex".to_owned(),
        estimate_serialized_value(&packet.codecortex)?.div_ceil(4),
    );
    sections.insert(
        "continuity".to_owned(),
        (estimate_serialized_slice(&packet.active_plan)?
            + estimate_serialized_slice(&packet.completed_work)?
            + estimate_serialized_slice(&packet.killed_paths)?
            + estimate_serialized_slice(&packet.causal_bridge)?)
        .div_ceil(4),
    );
    sections.insert(
        "memory_decisions_experience_and_need".to_owned(),
        (estimate_serialized_slice(&packet.memory_decisions)?
            + estimate_serialized_slice(&packet.experience_priors)?
            + estimate_serialized_value(&packet.memory_need_decision)?)
        .div_ceil(4),
    );
    sections.insert(
        "applicability_and_history".to_owned(),
        (estimate_serialized_value(&packet.memory_applicability)?
            + estimate_serialized_slice(&packet.historical_memory)?)
        .div_ceil(4),
    );
    sections.insert(
        "lifecycle_and_procedural_skills".to_owned(),
        (estimate_serialized_value(&packet.memory_lifecycle)?
            + estimate_serialized_value(&packet.procedural_skills)?)
        .div_ceil(4),
    );
    sections.insert(
        "budget_and_truncation".to_owned(),
        (estimate_serialized_value(&packet.token_budget_report)?
            + estimate_serialized_value(&packet.truncation)?)
        .div_ceil(4),
    );
    sections.insert(
        "identity_and_quality".to_owned(),
        (estimate_serialized_value(&packet.packet_id)?
            + estimate_serialized_value(&packet.packet_quality)?)
        .div_ceil(4),
    );
    sections.insert("whole_packet_estimate".to_owned(), estimate_tokens(packet)?);
    sections.insert(
        "whole_packet_serialized".to_owned(),
        serde_json::to_vec(packet)?.len().div_ceil(4),
    );
    Ok(sections)
}

fn estimate_serialized_slice<T: serde::Serialize>(values: &[T]) -> Result<usize, EngineError> {
    values
        .iter()
        .map(estimate_serialized_value)
        .try_fold(0usize, |total, next| Ok(total + next?))
}

fn estimate_serialized_value<T: serde::Serialize>(value: &T) -> Result<usize, EngineError> {
    Ok(serde_json::to_vec(value)?.len())
}

struct HandleIndex {
    claim_status: HashMap<String, EpistemicStatus>,
    evidence_refs: HashSet<String>,
}

impl HandleIndex {
    fn from_claims_and_evidence(
        claims: &[ClaimCard],
        fetch: &eliot_types::FetchAtomsL2Response,
    ) -> Self {
        let mut claim_status = HashMap::new();
        for claim in claims {
            claim_status.insert(claim.claim_id.to_string(), claim.status);
            claim_status.insert(claim_handle(claim), claim.status);
        }
        let mut evidence_refs = HashSet::new();
        for evidence in &fetch.evidence_atoms {
            evidence_refs.insert(evidence.evidence_id.to_string());
            evidence_refs.insert(format!("evidence:{}", evidence.evidence_id));
        }
        for verification in &fetch.verification_runs {
            evidence_refs.insert(verification.verification_id.to_string());
            evidence_refs.insert(format!("verification:{}", verification.verification_id));
        }
        for failure in &fetch.failure_fingerprints {
            evidence_refs.insert(failure.fingerprint.clone());
            evidence_refs.insert(format!("failure:{}", failure.fingerprint));
        }
        Self {
            claim_status,
            evidence_refs,
        }
    }

    fn claim_status(&self, handle: &str) -> Option<EpistemicStatus> {
        self.claim_status.get(handle).copied()
    }

    fn contains_evidence(&self, handle: &str) -> bool {
        self.evidence_refs.contains(handle)
    }
}

fn weak_truth_status(status: EpistemicStatus) -> bool {
    matches!(
        status,
        EpistemicStatus::Observed
            | EpistemicStatus::Candidate
            | EpistemicStatus::Contested
            | EpistemicStatus::Superseded
            | EpistemicStatus::Stale
            | EpistemicStatus::Rejected
            | EpistemicStatus::Unknown
    )
}

fn unsafe_action(action: &str) -> bool {
    let lowered = action.to_ascii_lowercase();
    [
        "raw sql",
        "raw_sql",
        "run sql",
        "surreal sql",
        "db endpoint",
        "credential",
        "password",
        "secret",
        "qdrant",
        "graphiti",
        "zep",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn read_only_action(action: &str) -> bool {
    let lowered = action.to_ascii_lowercase();
    lowered.contains("read") || lowered.contains("inspect") || lowered.contains("probe")
}

fn code_grounding_error(reason: CognitiveGateReason) -> bool {
    matches!(
        reason,
        CognitiveGateReason::MissingCodeCortexReport
            | CognitiveGateReason::StaleCodeCortexReport
            | CognitiveGateReason::MissingCodeFileRefs
            | CognitiveGateReason::CodeFileNotInReport
            | CognitiveGateReason::MissingCodeCausalBridge
            | CognitiveGateReason::BlastRadiusNotAcknowledged
    )
}

fn validate_skill_grounding(
    proof: &UnderstandingProof,
    errors: &mut BTreeSet<CognitiveGateReason>,
    checked_refs: &mut BTreeSet<String>,
) {
    if proof.skill_refs.is_empty() {
        return;
    }
    for skill_ref in &proof.skill_refs {
        checked_refs.insert(format!("skill:{skill_ref}"));
    }
    if proof.skill_application_rationales.is_empty()
        || proof.skill_anti_scope_acknowledgements.is_empty()
    {
        errors.insert(CognitiveGateReason::SkillNotApplicable);
    }
    if proof.skill_required_inputs.is_empty() {
        errors.insert(CognitiveGateReason::SkillMissingInputs);
    }
    if proof.skill_verifier_plan_refs.is_empty() || proof.expected_verifiers.is_empty() {
        errors.insert(CognitiveGateReason::SkillMissingVerifier);
    }
}

fn skill_grounding_error(reason: CognitiveGateReason) -> bool {
    matches!(
        reason,
        CognitiveGateReason::SkillBadLifecycle
            | CognitiveGateReason::SkillNotApplicable
            | CognitiveGateReason::SkillMissingInputs
            | CognitiveGateReason::SkillMissingVerifier
            | CognitiveGateReason::SkillConflict
            | CognitiveGateReason::SkillKnownFailureActive
            | CognitiveGateReason::SkillExecutionProofMissing
    )
}

#[cfg(test)]
mod current_git_scope_tests {
    use super::*;
    use eliot_types::{
        BlastRadiusView, CausalBridgeHop, ClaimId, ClaimSummary, CodeCortexScopeBinding,
        CodeEvidenceSource, FileEvidence, GovernorConfig, OperationStatus, ReceiptId, WriteId,
        WriteReceiptRef,
    };
    use serde_json::json;

    const BRANCH: &str = "l5-session-b";
    const SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
    const CURRENT_COMMIT: &str = "2222222222222222222222222222222222222222";
    const ARTIFACT: &str = "crates/eliot-engine/src/context.rs";
    const ARTIFACT_HASH: &str = "artifact-hash";

    fn verified_claim(project_id: eliot_types::ProjectId, branch: &str) -> ClaimCard {
        ClaimCard {
            claim_id: ClaimId::new_v7(),
            statement: "governed claim".to_owned(),
            status: EpistemicStatus::Verified,
            payload: json!({
                "evidence_id": "evidence-1",
                "freshness_rule": "client says fresh",
                "source_id": "completion:test",
                "where_applicable": [format!("project:{}", &project_id.to_string()[..8])],
                "lineage": {
                    "branch": branch,
                    "resulting_controller_commit": SOURCE_COMMIT,
                    "verification_ids": ["verification-1"],
                    "controller_receipt_id": "receipt-1",
                    "canonical_artifact_refs": [{
                        "resource_ref": ARTIFACT,
                        "content_hash": ARTIFACT_HASH
                    }]
                }
            }),
        }
    }

    fn packet(project_id: eliot_types::ProjectId, claim: &ClaimCard) -> ContextPacketL3 {
        ContextPacketL3 {
            packet_id: String::new(),
            project_id,
            task_id: "task".to_owned(),
            goal: "resolve current truth".to_owned(),
            task_execution_class: eliot_types::TaskExecutionClass::default(),
            project_understanding: None,
            memory_confidence: eliot_types::MemoryConfidence::None,
            acceptance_items: Vec::new(),
            at_revision: MemoryRevision::new(1),
            current_truth: vec![ClaimSummary {
                claim_id: claim.claim_id,
                statement: claim.statement.clone(),
                status: claim.status,
                memory_revision: MemoryRevision::new(1),
            }],
            relevant_verified_claims: vec![claim.clone()],
            relevant_supported_claims: Vec::new(),
            weak_claims_warning: Vec::new(),
            negative_memory: Vec::new(),
            recent_failures: Vec::new(),
            known_decisions: vec![claim.clone()],
            open_questions: Vec::new(),
            exact_handles: vec![claim_handle(claim)],
            source_receipts: Vec::new(),
            current_truth_snapshot: None,
            epistemic_state: EpistemicPacketState::default(),
            active_plan: Vec::new(),
            completed_work: Vec::new(),
            killed_paths: Vec::new(),
            causal_bridge: Vec::new(),
            memory_decisions: Vec::new(),
            experience_priors: Vec::new(),
            memory_need_decision: None,
            decision_locality_suffix: DecisionLocalitySuffix::default(),
            packet_quality: None,
            memory_applicability: MemoryApplicabilityPacketView::default(),
            historical_memory: Vec::new(),
            codecortex: None,
            memory_lifecycle: MemoryLifecyclePacketView::default(),
            procedural_skills: eliot_types::ProceduralSkillPacketView::default(),
            token_budget_report: TokenBudgetReport {
                max_tokens: 4_000,
                estimated_tokens: 0,
                truncated: false,
                sections_truncated: Vec::new(),
            },
            truncation: TruncationInfo {
                truncated: false,
                limit: 4_000,
                returned: 1,
            },
        }
    }

    fn scope(project_id: eliot_types::ProjectId, commit: &str) -> GovernedGitScope {
        GovernedGitScope {
            project_id,
            branch: BRANCH.to_owned(),
            commit: commit.to_owned(),
            clean: true,
            ancestor_commits: Vec::new(),
            artifact_refs: vec![VerifierArtifactRef {
                resource_ref: ARTIFACT.to_owned(),
                content_hash: ARTIFACT_HASH.to_owned(),
            }],
        }
    }

    fn codecortex_identity_report() -> CodeCortexReport {
        CodeCortexReport {
            project: "eliot-memory-os".to_owned(),
            task: "packet-identity".to_owned(),
            goal: "compile one deterministic packet".to_owned(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            repo_root: "C:/repo".to_owned(),
            git_head: Some(SOURCE_COMMIT.to_owned()),
            dirty: true,
            scope_binding: CodeCortexScopeBinding {
                branch: BRANCH.to_owned(),
                commit: SOURCE_COMMIT.to_owned(),
                dirty_state_hash: "dirty-state-hash".to_owned(),
                adapter_versions: BTreeMap::new(),
                verifier_config_hash: "verifier-config".to_owned(),
            },
            tracked_files: vec![FileEvidence {
                path: ARTIFACT.to_owned(),
                content_hash: Some(ARTIFACT_HASH.to_owned()),
                line_start: Some(1),
                line_end: Some(2),
                excerpt: "packet compiler".to_owned(),
                source: CodeEvidenceSource::Rg,
            }],
            workspace_members: vec!["eliot-engine".to_owned()],
            crates: vec!["eliot-engine".to_owned()],
            targets: Vec::new(),
            file_evidence: Vec::new(),
            symbol_evidence: Vec::new(),
            diagnostic_evidence: Vec::new(),
            verifier_evidence: Vec::new(),
            blast_radius: BlastRadiusView {
                files: vec![ARTIFACT.to_owned()],
                crates: vec!["eliot-engine".to_owned()],
                reasons: vec!["packet identity".to_owned()],
            },
            invariant_cards: Vec::new(),
            evidence_sources: vec![CodeEvidenceSource::Rg],
            adapter_notes: Vec::new(),
            memory_receipt: None,
            operation_status: OperationStatus::OperationCompleted,
        }
    }

    #[test]
    fn codecortex_packet_identity_ignores_persistence_receipt() -> Result<(), serde_json::Error> {
        let project_id = ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let mut before_packet = packet(project_id, &claim);
        let before_report = codecortex_identity_report();
        attach_codecortex_reports(&mut before_packet, std::slice::from_ref(&before_report));

        let mut after_report = before_report.clone();
        after_report.memory_receipt = Some(WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: WriteId::new_v7(),
        });
        let mut after_packet = packet(project_id, &claim);
        attach_codecortex_reports(&mut after_packet, std::slice::from_ref(&after_report));

        assert_eq!(
            codecortex_report_ref(&before_report),
            codecortex_report_ref(&after_report)
        );
        assert!(codecortex_report_ref(&after_report).ends_with(":dirty-state-hash"));
        assert_eq!(
            serde_json::to_vec(&before_packet)?,
            serde_json::to_vec(&after_packet)?
        );
        Ok(())
    }

    #[test]
    fn pre_candidate_scope_uses_codecortex_file_fallback() {
        let request = CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7().to_string(),
            goal: String::new(),
            candidate_handles: Vec::new(),
            max_tokens: 1_800,
        };
        assert_eq!(
            resolve_packet_scope_paths(&request, None, &[codecortex_identity_report()]),
            vec![ARTIFACT.to_owned()]
        );
    }

    #[test]
    fn control_plan_forbids_memory_sources_before_reads() {
        let request = CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7().to_string(),
            goal: "source-only control".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 1_800,
        };
        let mut plan = PacketCompilePlan {
            touched_paths: resolve_packet_scope_paths(&request, None, &[]),
            request,
            session_id: SessionId::new_v7(),
            compile_mode: PacketCompileMode::CertificationControl,
            memory_exposure: MemoryExposureMode::MemoryFreeControl,
            task_contract: None,
            task_receipt_metadata: None,
            previous_packet: None,
            material_frame: None,
            codecortex_reports: Vec::new(),
            current_git_scope: None,
            resolved_cues: PacketResolvedCues::default(),
            pyramid_source: PacketPyramidSource::Forbidden,
            experience_source: PacketExperienceSource::Forbidden,
            budget_policy: PacketBudgetPolicy::governor_default(1_800),
            measurement_view: None,
        };
        assert!(validate_packet_compile_plan(&plan).is_ok());
        plan.resolved_cues
            .concept_refs
            .push("memory:concept".to_owned());
        assert!(validate_packet_compile_plan(&plan).is_err());
    }

    #[tokio::test]
    async fn control_compile_plan_is_zero_read_single_owner_and_budgeted()
    -> Result<(), PacketCompileError> {
        let request = CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7().to_string(),
            goal: "source-only control".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 1_800,
        };
        let plan = PacketCompilePlan {
            touched_paths: resolve_packet_scope_paths(&request, None, &[]),
            request,
            session_id: SessionId::new_v7(),
            compile_mode: PacketCompileMode::CertificationControl,
            memory_exposure: MemoryExposureMode::MemoryFreeControl,
            task_contract: None,
            task_receipt_metadata: None,
            previous_packet: None,
            material_frame: None,
            codecortex_reports: Vec::new(),
            current_git_scope: None,
            resolved_cues: PacketResolvedCues::default(),
            pyramid_source: PacketPyramidSource::Forbidden,
            experience_source: PacketExperienceSource::Forbidden,
            budget_policy: PacketBudgetPolicy::governor_default(1_800),
            measurement_view: Some(PacketMeasurementView {
                task_class: UlTaskClass {
                    action_class: "inspect".to_owned(),
                    subsystem: "packet-compiler".to_owned(),
                    artifact_class: "rust".to_owned(),
                },
                assignment_injection_mode: UlInjectionMode::Payload,
                effective_injection_mode: None,
                config_hash: "test-policy-v1".to_owned(),
            }),
        };
        let config = GovernorConfig::default();
        let compiler = ContextCompiler::new(ReadService::new(eliot_store::CanonicalStore::new(
            config.db.surreal,
        )));

        let result = compiler.compile_plan(plan).await?;

        assert_eq!(result.read_audit, PacketSourceReadAudit::default());
        assert_eq!(
            result.compile_audit.semantic.project_understanding_compiles,
            1
        );
        assert_eq!(result.compile_audit.semantic.budget_renders, 1);
        assert_eq!(result.compile_audit.semantic.identity_finalizations, 1);
        assert_eq!(result.gate.status, PacketGateStatus::Allow);
        assert_eq!(result.admission.status, PacketAdmissionStatus::Admitted);
        assert!(result.packet.memory_need_decision.is_none());
        assert!(result.packet.experience_priors.is_empty());
        assert_eq!(
            result.budget.supplement_tokens,
            serialized_supplement_tokens(&result.response_supplement)?
        );
        assert_eq!(
            result.response_supplement["ul_experiment"]["arm"],
            "control"
        );
        assert_eq!(
            result.response_supplement["ul_experiment"]["assignment_status"],
            "post_commit_measurement"
        );
        assert_eq!(
            result.response_supplement["ul_experiment"]["packet_disposition"],
            "admitted"
        );
        Ok(())
    }

    #[test]
    fn unavailable_non_control_pyramid_is_preserved_and_rejected() -> Result<(), EngineError> {
        let request = CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7().to_string(),
            goal: "compile with revision-fenced understanding".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 1_800,
        };
        let touched_paths = resolve_packet_scope_paths(&request, None, &[]);
        let unavailable_reason = "revision fence changed during pyramid read";
        let plan = PacketCompilePlan {
            request: request.clone(),
            session_id: SessionId::new_v7(),
            compile_mode: PacketCompileMode::Production,
            memory_exposure: MemoryExposureMode::CurrentTruthOnly,
            task_contract: None,
            task_receipt_metadata: None,
            previous_packet: None,
            material_frame: None,
            codecortex_reports: Vec::new(),
            current_git_scope: None,
            touched_paths: touched_paths.clone(),
            resolved_cues: PacketResolvedCues::default(),
            pyramid_source: PacketPyramidSource::Unavailable {
                reason: unavailable_reason.to_owned(),
            },
            experience_source: PacketExperienceSource::Cases(Vec::new()),
            budget_policy: PacketBudgetPolicy::governor_default(1_800),
            measurement_view: Some(PacketMeasurementView {
                task_class: UlTaskClass {
                    action_class: "modify".to_owned(),
                    subsystem: "packet-compiler".to_owned(),
                    artifact_class: "rust".to_owned(),
                },
                assignment_injection_mode: UlInjectionMode::Payload,
                effective_injection_mode: Some(UlInjectionMode::HandlesOnly),
                config_hash: "test-policy-v1".to_owned(),
            }),
        };
        validate_packet_compile_plan(&plan).expect("typed unavailable source is valid input");
        let packet = ContextCompiler::compile_control_unfinalized(&request, &[], None, None).packet;
        let gate = packet_gate_candidate(
            &plan.pyramid_source,
            plan.compile_mode,
            None,
            &touched_paths,
            &packet,
        );
        let admission = packet_admission_decision(&gate, plan.compile_mode);
        let supplement = packet_response_supplement(&plan, &packet, &[], &gate, &admission, 0)?;

        assert_eq!(gate.status, PacketGateStatus::RequirePacketRefresh);
        assert_eq!(gate.reason, Some(PacketGateReason::PyramidUnavailable));
        assert_eq!(admission.status, PacketAdmissionStatus::Rejected);
        assert!(!admission.active_allowed);
        assert_eq!(supplement["ul_meta"]["status"], "unavailable");
        assert_eq!(supplement["ul_meta"]["reason"], unavailable_reason);
        assert_eq!(supplement["ul_gate"]["reason"], "pyramid_unavailable");
        assert_eq!(
            supplement["ul_experiment"]["assignment_status"],
            "not_assigned_rejected"
        );
        assert_eq!(
            supplement["ul_experiment"]["packet_disposition"],
            "rejected"
        );
        Ok(())
    }

    #[test]
    fn prediction_intents_do_not_infer_diagnostics_from_probe_text() {
        let heuristic_only = MaterialPacketFrame {
            expected_observable: "observe the compiler".to_owned(),
            cheapest_discriminative_probes: vec!["diagnostic text".to_owned()],
            ..MaterialPacketFrame::default()
        };
        assert!(packet_prediction_specs(Some(&heuristic_only)).is_empty());

        let explicit = MaterialPacketFrame {
            expected_observable: "verifier:cargo test -p eliot-engine=pass".to_owned(),
            ..MaterialPacketFrame::default()
        };
        assert_eq!(packet_prediction_specs(Some(&explicit)).len(), 1);
        let mut waived = explicit.clone();
        waived.waived_invariants.push(eliot_types::WaivedInvariant {
            invariant_ref: "invariant:preserve-order".to_owned(),
            reason: "bounded fixture waiver".to_owned(),
        });
        assert_eq!(
            packet_prediction_source_frame_hash(&explicit).expect("explicit frame must hash"),
            packet_prediction_source_frame_hash(&waived).expect("waived frame must hash")
        );
    }

    #[test]
    fn shadow_evaluation_is_counterfactual_even_when_gate_allows() {
        let admission = packet_admission_decision(
            &PacketGateCandidate::allow(),
            PacketCompileMode::ShadowEvaluation,
        );
        assert_eq!(admission.status, PacketAdmissionStatus::Counterfactual);
        assert!(admission.counterfactual_only);
        assert!(!admission.active_allowed);
        assert!(!admission.continuity_allowed);
        assert!(!admission.influence_authority_allowed);
    }

    #[test]
    fn exact_scope_enters_verified_now_with_provenance_reason() {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let mut packet = packet(project_id, &claim);

        resolve_memory_applicability(
            &mut packet,
            std::slice::from_ref(&claim),
            &scope(project_id, SOURCE_COMMIT),
        );

        assert_eq!(packet.current_truth.len(), 1);
        assert_eq!(packet.relevant_verified_claims.len(), 1);
        assert!(packet.historical_memory.is_empty());
        assert_eq!(
            packet.memory_applicability.decisions[0].disposition,
            MemoryApplicabilityDisposition::VerifiedNow
        );
        assert!(
            packet.memory_applicability.inclusion_reasons[0]
                .contains("canonical_evidence_exact_git_scope")
        );
    }

    #[test]
    fn descendant_commit_requires_deterministic_artifact_revalidation() {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let mut packet = packet(project_id, &claim);
        let mut current_scope = scope(project_id, CURRENT_COMMIT);
        current_scope
            .ancestor_commits
            .push(SOURCE_COMMIT.to_owned());

        resolve_memory_applicability(&mut packet, std::slice::from_ref(&claim), &current_scope);

        assert_eq!(packet.current_truth.len(), 1);
        assert_eq!(
            packet.memory_applicability.decisions[0].disposition,
            MemoryApplicabilityDisposition::RevalidatedNow
        );
        assert!(
            packet.memory_applicability.revalidation_reasons[0]
                .contains("canonical_evidence_revalidated_on_descendant_commit")
        );
    }

    #[test]
    fn wrong_project_or_branch_is_historical_even_with_freshness_label()
    -> Result<(), Box<dyn std::error::Error>> {
        let project_id = eliot_types::ProjectId::new_v7();
        let wrong_project = "ffffffff-ffff-4fff-8fff-ffffffffffff".parse()?;
        let claim = verified_claim(wrong_project, BRANCH);
        let mut wrong_project_packet = packet(project_id, &claim);

        resolve_memory_applicability(
            &mut wrong_project_packet,
            std::slice::from_ref(&claim),
            &scope(project_id, SOURCE_COMMIT),
        );

        assert!(wrong_project_packet.current_truth.is_empty());
        assert_eq!(wrong_project_packet.historical_memory.len(), 1);
        assert_eq!(
            wrong_project_packet.memory_applicability.decisions[0].reason,
            "project_scope_mismatch"
        );

        let branch_claim = verified_claim(project_id, "other-branch");
        let mut branch_packet = packet(project_id, &branch_claim);
        resolve_memory_applicability(
            &mut branch_packet,
            std::slice::from_ref(&branch_claim),
            &scope(project_id, SOURCE_COMMIT),
        );
        assert!(branch_packet.current_truth.is_empty());
        assert_eq!(
            branch_packet.memory_applicability.decisions[0].reason,
            "branch_scope_mismatch"
        );

        let mut dirty_scope = scope(project_id, SOURCE_COMMIT);
        dirty_scope.clean = false;
        let mut dirty_packet = packet(project_id, &branch_claim);
        resolve_memory_applicability(
            &mut dirty_packet,
            std::slice::from_ref(&branch_claim),
            &dirty_scope,
        );
        assert!(dirty_packet.current_truth.is_empty());
        assert_eq!(
            dirty_packet.memory_applicability.decisions[0].reason,
            "current_git_scope_dirty"
        );
        Ok(())
    }

    #[test]
    fn canonical_evidence_requires_controller_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let project_id = eliot_types::ProjectId::new_v7();
        let mut claim = verified_claim(project_id, BRANCH);
        let lineage = claim.payload["lineage"]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("lineage object missing"))?;
        lineage.remove("controller_receipt_id");
        let mut packet = packet(project_id, &claim);

        resolve_memory_applicability(
            &mut packet,
            std::slice::from_ref(&claim),
            &scope(project_id, SOURCE_COMMIT),
        );

        assert!(packet.current_truth.is_empty());
        assert_eq!(packet.historical_memory.len(), 1);
        assert_eq!(
            packet.memory_applicability.decisions[0].reason,
            "canonical_evidence_incomplete"
        );
        Ok(())
    }

    #[test]
    fn material_packet_has_stable_truth_frame_and_descriptive_quality() -> Result<(), EngineError> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let mut packet = packet(project_id, &claim);
        packet.task_id = TaskId::new_v7().to_string();
        let request = CompilePacketL3Request {
            project_id,
            task_id: packet.task_id.clone(),
            goal: "repair the canonical packet compiler".to_owned(),
            candidate_handles: vec![claim_handle(&claim)],
            max_tokens: 4_000,
        };
        let frame = MaterialPacketFrame {
            acceptance_items: vec!["focused packet test passes".to_owned()],
            environment: vec!["windows-x64".to_owned()],
            causal_bridge: vec![
                CausalBridgeHop {
                    from: "intent".to_owned(),
                    relation: "owned_by".to_owned(),
                    to: "context compiler".to_owned(),
                    evidence_ref: Some("file:context.rs".to_owned()),
                },
                CausalBridgeHop {
                    from: "context compiler".to_owned(),
                    relation: "implements".to_owned(),
                    to: "compile_context".to_owned(),
                    evidence_ref: Some("symbol:compile_context".to_owned()),
                },
                CausalBridgeHop {
                    from: "compile_context".to_owned(),
                    relation: "emits".to_owned(),
                    to: "ContextPacketL3".to_owned(),
                    evidence_ref: Some("type:ContextPacketL3".to_owned()),
                },
                CausalBridgeHop {
                    from: "ContextPacketL3".to_owned(),
                    relation: "verified_by".to_owned(),
                    to: "operator_packet_test".to_owned(),
                    evidence_ref: Some("test:operator_packet_test".to_owned()),
                },
            ],
            negative_memory_checked: true,
            exact_load_bearing_atoms: vec!["symbol:compile_context".to_owned()],
            next_allowed_action: "run focused packet test".to_owned(),
            expected_observable: "quality result is sufficient".to_owned(),
            verifier: "cargo test material_packet".to_owned(),
            stop_condition: "test fails or revision changes".to_owned(),
            tool_schema_bytes_visible: 1_024,
            instruction_hotset_size: 4,
            ..MaterialPacketFrame::default()
        };
        let current_scope = scope(project_id, SOURCE_COMMIT);

        hydrate_material_packet(&mut packet, &request, Some(&current_scope), Some(&frame));
        PacketQualityService::finalize(&mut packet, Some(&frame))?;

        let quality = packet
            .packet_quality
            .as_ref()
            .ok_or_else(|| EngineError::WriteRejected("packet quality missing".to_owned()))?;
        assert_eq!(quality.result, PacketQualityResult::Sufficient);
        assert_eq!(quality.causal_bridge_hops, 4);
        assert!(quality.causal_bridge_missing_hops.is_empty());
        assert_eq!(quality.packet_id, packet.packet_id);
        assert_eq!(
            packet
                .current_truth_snapshot
                .as_ref()
                .map(|snapshot| snapshot.branch.as_str()),
            Some(BRANCH)
        );
        assert_eq!(
            packet.decision_locality_suffix.verifier,
            "cargo test material_packet"
        );
        Ok(())
    }

    #[test]
    fn budget_never_trims_decision_locality_suffix() {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let mut packet = packet(project_id, &claim);
        packet.decision_locality_suffix = DecisionLocalitySuffix {
            exact_load_bearing_atoms: vec!["load-bearing".repeat(128)],
            next_allowed_action: "probe".to_owned(),
            expected_observable: "observable".to_owned(),
            verifier: "verifier".to_owned(),
            stop_condition: "stop".to_owned(),
            ..DecisionLocalitySuffix::default()
        };
        let suffix = packet.decision_locality_suffix.clone();

        let result = enforce_budget(&mut packet, 10, &[]);

        assert_eq!(packet.decision_locality_suffix, suffix);
        assert!(matches!(
            result,
            Err(EngineError::PacketFloorExceedsBudget { max_tokens: 10, .. })
        ));
    }

    #[test]
    fn budget_drops_auto_codecortex_before_requested_handles() -> Result<(), EngineError> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let mut packet = packet(project_id, &claim);
        let floor_tokens = estimate_tokens(&packet)?;
        let report_ref = "codecortex_report:task:head:receipt".to_owned();
        packet.exact_handles.push(report_ref.clone());
        packet.codecortex = Some(CodeCortexPacketView {
            report_refs: vec![report_ref],
            git_head: Some("f".repeat(4_000)),
            scope_binding: CodeCortexScopeBinding {
                branch: "branch".repeat(400),
                commit: "commit".repeat(400),
                dirty_state_hash: "dirty".repeat(400),
                adapter_versions: BTreeMap::from([("rg".to_owned(), "version".repeat(400))]),
                verifier_config_hash: "config".repeat(400),
            },
            file_evidence: vec![FileEvidence {
                path: ARTIFACT.to_owned(),
                content_hash: Some(ARTIFACT_HASH.to_owned()),
                line_start: Some(1),
                line_end: Some(2),
                excerpt: "evidence".repeat(1_000),
                source: CodeEvidenceSource::Rg,
            }],
            symbol_evidence: Vec::new(),
            diagnostic_evidence: Vec::new(),
            verifier_map: Vec::new(),
            blast_radius: BlastRadiusView {
                files: vec![ARTIFACT.to_owned()],
                crates: vec!["eliot-engine".to_owned()],
                reasons: vec!["test pressure".to_owned()],
            },
            unknowns: vec!["unknown".repeat(1_000)],
        });

        let before_budget = packet.clone();
        let tight_result = enforce_budget(
            &mut packet,
            floor_tokens + 8,
            std::slice::from_ref(&required_handle),
        );

        assert!(matches!(
            tight_result,
            Err(EngineError::PacketFloorExceedsBudget { .. })
        ));
        assert_eq!(packet.exact_handles, std::slice::from_ref(&required_handle));
        assert!(packet.codecortex.is_none());
        let expected_known_decisions = serde_json::to_value(&before_budget.known_decisions)?;
        assert_eq!(
            serde_json::to_value(&packet.known_decisions)?,
            expected_known_decisions
        );
        assert!(
            packet
                .token_budget_report
                .sections_truncated
                .iter()
                .all(|section| section.starts_with("codecortex.")),
            "unexpected truncation order: {:?}",
            packet.token_budget_report.sections_truncated
        );
        let exact_cap = packet.token_budget_report.estimated_tokens;
        assert!(exact_cap > floor_tokens + 8);

        let mut exact_packet = before_budget;
        enforce_budget(
            &mut exact_packet,
            exact_cap,
            std::slice::from_ref(&required_handle),
        )?;
        assert_eq!(
            exact_packet.exact_handles,
            std::slice::from_ref(&required_handle)
        );
        assert!(exact_packet.codecortex.is_none());
        assert_eq!(
            serde_json::to_value(&exact_packet.known_decisions)?,
            expected_known_decisions
        );
        assert_eq!(exact_packet.token_budget_report.estimated_tokens, exact_cap);
        Ok(())
    }

    fn final_candidate_floor(
        candidate: &ContextPacketL3,
        required_handle: &String,
    ) -> Result<usize, EngineError> {
        let mut prepared = candidate.clone();
        ProjectContinuityService::restore(&mut prepared, None);
        prepared.project_understanding = Some(ProjectUnderstandingCompiler::compile(
            &prepared,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
        ));
        ProjectContinuityService::restore(&mut prepared, None);
        let required_handles = BTreeSet::from([required_handle]);
        Ok(mandatory_floor(&prepared, &required_handles, 0)?.1)
    }

    fn candidate_with_exact_floor(target: usize) -> Result<(ContextPacketL3, String), EngineError> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let mut candidate = packet(project_id, &claim);
        for _ in 0..20_000 {
            let floor = final_candidate_floor(&candidate, &required_handle)?;
            if floor == target {
                return Ok((candidate, required_handle));
            }
            assert!(floor < target, "floor skipped target {target}: {floor}");
            candidate.decision_locality_suffix.stop_condition.push('x');
        }
        panic!("could not construct exact packet floor {target}")
    }

    #[test]
    fn final_render_compiles_project_understanding_exactly_once() -> Result<(), PacketCompileError>
    {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let candidate = packet(project_id, &claim);

        let outcome = finalize_packet_candidate(
            &candidate,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
            None,
            4_000,
            std::slice::from_ref(&required_handle),
        )?;

        assert_eq!(outcome.audit.project_understanding_compiles, 1);
        assert_eq!(outcome.audit.budget_renders, 1);
        assert_eq!(outcome.audit.identity_finalizations, 1);
        assert_eq!(
            outcome.packet.project_understanding.as_ref(),
            Some(&outcome.project_understanding)
        );
        Ok(())
    }

    #[test]
    fn total_surface_estimate_includes_named_supplements_and_return_metadata()
    -> Result<(), PacketCompileError> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let candidate = packet(project_id, &claim);
        let named_supplements = serde_json::json!({
            "packet_admission": {"status": "admitted", "active_allowed": true},
            "ul_meta": {"coverage": "blind", "recommended_probe": "inspect owner"}
        });
        let supplement_tokens = serialized_supplement_tokens(&named_supplements)?;
        let audit_context = PacketCompileAuditContext {
            stages: vec!["plan_resolved".to_owned(), "admission_decided".to_owned()],
            source_reads: PacketSourceReadAudit {
                current_state_reads: 2,
                l0_reads: 1,
                l2_reads: 1,
            },
            read_counters: BTreeMap::from([
                ("experience".to_owned(), 1),
                ("l0".to_owned(), 1),
                ("l2".to_owned(), 1),
                ("pyramid".to_owned(), 1),
                ("skill".to_owned(), 0),
            ]),
        };

        let outcome = finalize_packet_candidate_with_policy_and_audit_context(
            &candidate,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
            None,
            PacketBudgetPolicy::governor_default(4_000).with_supplement_tokens(supplement_tokens),
            std::slice::from_ref(&required_handle),
            audit_context,
        )?;

        let metadata_tokens =
            packet_return_metadata_tokens(&outcome.budget, &outcome.compile_audit)?;
        assert_eq!(outcome.budget.budget_metadata_tokens, metadata_tokens);
        assert_eq!(
            outcome.budget.estimated_tokens,
            outcome.packet.token_budget_report.estimated_tokens
                + supplement_tokens
                + metadata_tokens
        );
        assert_eq!(
            outcome
                .budget
                .section_tokens
                .get("packet_budget_decision_and_compile_audit"),
            Some(&metadata_tokens)
        );
        assert_eq!(
            outcome
                .compile_audit
                .semantic
                .project_understanding_compiles,
            1
        );
        assert_eq!(outcome.compile_audit.semantic.budget_renders, 1);
        Ok(())
    }

    #[test]
    fn memory_free_control_candidate_performs_zero_memory_reads() {
        let request = CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7().to_string(),
            goal: "provider-free control".to_owned(),
            candidate_handles: vec!["claim:must-not-load".to_owned()],
            max_tokens: 1_200,
        };

        let outcome = ContextCompiler::compile_control_unfinalized(&request, &[], None, None);

        assert_eq!(outcome.read_audit, PacketSourceReadAudit::default());
        assert_eq!(outcome.packet.at_revision, MemoryRevision::new(0));
        assert_eq!(
            outcome.packet.memory_confidence,
            eliot_types::MemoryConfidence::None
        );
        assert!(outcome.packet.current_truth.is_empty());
        assert!(outcome.packet.relevant_verified_claims.is_empty());
        assert!(outcome.packet.relevant_supported_claims.is_empty());
        assert!(outcome.packet.weak_claims_warning.is_empty());
        assert!(outcome.packet.negative_memory.is_empty());
        assert!(outcome.packet.recent_failures.is_empty());
        assert!(outcome.packet.known_decisions.is_empty());
        assert!(outcome.packet.exact_handles.is_empty());
        assert!(outcome.packet.source_receipts.is_empty());
        assert!(outcome.packet.memory_decisions.is_empty());
        assert!(outcome.packet.experience_priors.is_empty());
        assert!(outcome.packet.memory_need_decision.is_none());
    }

    #[test]
    fn repeated_source_snapshot_uses_stable_revision_timestamp() -> Result<(), serde_json::Error> {
        let project_id = ProjectId::new_v7();
        let request = CompilePacketL3Request {
            project_id,
            task_id: TaskId::new_v7().to_string(),
            goal: "stable source snapshot".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 1_500,
        };
        let current_scope = scope(project_id, SOURCE_COMMIT);

        let first =
            ContextCompiler::compile_control_unfinalized(&request, &[], Some(&current_scope), None);
        let second =
            ContextCompiler::compile_control_unfinalized(&request, &[], Some(&current_scope), None);

        assert_eq!(
            serde_json::to_vec(&first.packet)?,
            serde_json::to_vec(&second.packet)?
        );
        assert_eq!(
            first
                .packet
                .current_truth_snapshot
                .as_ref()
                .map(|snapshot| snapshot.captured_at),
            Some(OffsetDateTime::UNIX_EPOCH)
        );
        Ok(())
    }

    #[test]
    fn frozen_final_candidate_has_stable_identity_and_floor()
    -> Result<(), Box<dyn std::error::Error>> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let candidate = packet(project_id, &claim);
        let render = || {
            finalize_packet_candidate(
                &candidate,
                None,
                None,
                &ProjectUnderstandingEvidence::default(),
                None,
                4_000,
                std::slice::from_ref(&required_handle),
            )
        };

        let first = render()?;
        let second = render()?;

        assert_eq!(
            serde_json::to_vec(&first.packet)?,
            serde_json::to_vec(&second.packet)?
        );
        assert_eq!(first.packet.packet_id, second.packet.packet_id);
        assert_eq!(
            first.budget.mandatory_floor_tokens,
            second.budget.mandatory_floor_tokens
        );
        Ok(())
    }

    #[test]
    fn preferred_1200_auto_expands_to_mandatory_floor_1207() -> Result<(), PacketCompileError> {
        let (candidate, required_handle) = candidate_with_exact_floor(1_207)?;

        let outcome = finalize_packet_candidate(
            &candidate,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
            None,
            1_200,
            std::slice::from_ref(&required_handle),
        )?;

        assert_eq!(outcome.budget.packet_mandatory_floor_tokens, 1_207);
        assert!(outcome.budget.mandatory_floor_tokens > 1_207);
        assert_eq!(
            outcome.budget.effective_tokens,
            outcome.budget.mandatory_floor_tokens
        );
        assert_eq!(
            outcome.budget.render_mode,
            PacketRenderMode::PreferredBudgetExceededByMandatoryFloor
        );
        assert_eq!(
            outcome.budget.reason,
            "preferred_budget_exceeded_by_mandatory_floor"
        );
        assert_eq!(
            outcome.packet.token_budget_report.max_tokens,
            outcome.budget.effective_tokens
        );
        Ok(())
    }

    #[test]
    fn hard_ceiling_failure_is_typed_and_does_not_mutate_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let (candidate, required_handle) = candidate_with_exact_floor(1_207)?;
        let before = serde_json::to_vec(&candidate)?;

        let error = finalize_packet_candidate_with_policy(
            &candidate,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
            None,
            PacketBudgetPolicy {
                preferred_tokens: 1_200,
                hard_ceiling_tokens: 1_206,
                supplement_tokens: 0,
            },
            std::slice::from_ref(&required_handle),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("hard ceiling below the mandatory floor must fail"))?;

        let PacketCompileError::HardCeiling(error) = error else {
            panic!("expected typed hard-ceiling error");
        };
        assert_eq!(error.mandatory_floor_tokens, 1_207);
        assert_eq!(error.hard_ceiling_tokens, 1_206);
        assert_eq!(error.expansion_handles, vec![required_handle]);
        assert!(error.section_tokens.contains_key("whole_packet_serialized"));
        assert_eq!(serde_json::to_vec(&candidate)?, before);
        Ok(())
    }

    #[test]
    fn serialized_supplement_reservation_participates_in_hard_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        let project_id = eliot_types::ProjectId::new_v7();
        let claim = verified_claim(project_id, BRANCH);
        let required_handle = claim_handle(&claim);
        let candidate = packet(project_id, &claim);
        let supplement = serde_json::json!({"gate": "x".repeat(20_000)});
        let supplement_tokens = serialized_supplement_tokens(&supplement)?;

        let error = finalize_packet_candidate_with_policy(
            &candidate,
            None,
            None,
            &ProjectUnderstandingEvidence::default(),
            None,
            PacketBudgetPolicy::governor_default(1_500).with_supplement_tokens(supplement_tokens),
            std::slice::from_ref(&required_handle),
        )
        .err()
        .ok_or_else(|| {
            std::io::Error::other("large returned supplements must count against the hard ceiling")
        })?;

        let PacketCompileError::HardCeiling(error) = error else {
            panic!("expected typed hard-ceiling error");
        };
        assert_eq!(
            error.section_tokens.get("returned_supplements"),
            Some(&supplement_tokens)
        );
        Ok(())
    }
}
