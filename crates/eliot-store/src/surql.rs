use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SurqlAccessClass {
    Read,
    Write,
    Admin,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NamedSurqlOp {
    SchemaMigrate,
    SchemaMigrateObservability,
    SchemaMigrateUl,
    SchemaMigrateUlDelivery,
    SchemaMigrateUlArtifacts,
    SchemaMigrateUlPyramid,
    SchemaMigrateUlMeasurement,
    SchemaMigrateUlDependencyActivation,
    SchemaMigrateUlTokenPolicy,
    SchemaMigrateMemorySearch,
    SchemaMigrateMemorySearchFts,
    AssignUlExperimentArm,
    UpsertUlExperimentAssignmentExplicit,
    LoadUlExperimentAssignment,
    LoadUlTaskClassLedgers,
    UpsertUlTaskClassPolicy,
    LoadUlTaskClassPolicy,
    ReplaceUlReverseDependencies,
    ResetUlReverseDependencyProject,
    LoadUlReverseDependents,
    UpsertUlArtifactDirty,
    LoadUlArtifactDirty,
    ClearUlArtifactDirty,
    ResetUlArtifactDirtyProject,
    LoadUlActivationGraph,
    UpsertCueRows,
    DeleteCueRows,
    LoadCueRows,
    LoadCueRecords,
    LoadInjectionReceipts,
    LoadUlArtifacts,
    UpsertUlTaskLedger,
    LoadPredictions,
    LoadUlMetrics,
    LoadUlReadiness,
    ApplyWriteEnvelope,
    ApplyObservability,
    ObservabilityReceiptById,
    ObservabilityRecordsByKind,
    CurrentState,
    LoadRecallCandidates,
    UpsertMemorySearchProjection,
    ResetMemorySearchProjection,
    LoadMemorySearchFtsCandidates,
    ExplainMemorySearchFts,
    EnqueueCognitiveProjectionIntent,
    ClaimCognitiveProjectionProject,
    CompleteCognitiveProjectionThrough,
    FailCognitiveProjectionRetryable,
    BlockCognitiveProjection,
    LoadCognitiveProjectionBacklog,
    LoadCognitiveProjectionProjects,
    PublishCognitiveProjectionFamilyState,
    LoadCognitiveProjectionFamilyStates,
    CutoverLegacyMemorySearchPostings,
    FetchAtomsL2,
    FetchAtomsL2Legacy,
    GraphHealthCapabilities,
    GraphHealth,
    WriterReceipts,
    WriteReceiptById,
    ToolObservationByWriteId,
    LatestAuthorityObservationsByEntity,
    TaskContractById,
    ToolObservationById,
    ToolObservationsByKind,
    ExperiencePatternRevisionsById,
    SemanticRecordsByKind,
    ClaimCardById,
    VerificationRunById,
    CanonicalRecords,
    CanonicalRecordPage,
    CurationRecordPage,
    CanonicalRecordByWriteId,
    CanonicalRecordsBySubjectRef,
    LoadCanonicalMemoryAdmissionChildren,
    LoadCanonicalMemoryL2,
    LoadCanonicalMemoryProjectionSegments,
    CanonicalTraceByTraceRef,
    MetaPolicyActionsByCandidate,
    SleepCandidates,
    BlobReferenceScan,
}

impl NamedSurqlOp {
    pub const fn access_class(self) -> SurqlAccessClass {
        match self {
            Self::SchemaMigrate
            | Self::SchemaMigrateObservability
            | Self::SchemaMigrateUl
            | Self::SchemaMigrateUlDelivery
            | Self::SchemaMigrateUlArtifacts
            | Self::SchemaMigrateUlPyramid
            | Self::SchemaMigrateUlMeasurement
            | Self::SchemaMigrateUlDependencyActivation
            | Self::SchemaMigrateUlTokenPolicy
            | Self::SchemaMigrateMemorySearch
            | Self::SchemaMigrateMemorySearchFts
            | Self::ExplainMemorySearchFts
            | Self::CutoverLegacyMemorySearchPostings
            | Self::GraphHealthCapabilities
            | Self::GraphHealth
            | Self::BlobReferenceScan => SurqlAccessClass::Admin,
            Self::AssignUlExperimentArm
            | Self::UpsertUlExperimentAssignmentExplicit
            | Self::UpsertUlTaskClassPolicy
            | Self::ReplaceUlReverseDependencies
            | Self::ResetUlReverseDependencyProject
            | Self::UpsertUlArtifactDirty
            | Self::ClearUlArtifactDirty
            | Self::ResetUlArtifactDirtyProject
            | Self::UpsertCueRows
            | Self::DeleteCueRows
            | Self::UpsertUlTaskLedger
            | Self::ApplyWriteEnvelope
            | Self::ApplyObservability
            | Self::UpsertMemorySearchProjection
            | Self::ResetMemorySearchProjection
            | Self::EnqueueCognitiveProjectionIntent
            | Self::ClaimCognitiveProjectionProject
            | Self::CompleteCognitiveProjectionThrough
            | Self::FailCognitiveProjectionRetryable
            | Self::BlockCognitiveProjection
            | Self::PublishCognitiveProjectionFamilyState => SurqlAccessClass::Write,
            Self::LoadUlExperimentAssignment
            | Self::LoadUlTaskClassLedgers
            | Self::LoadUlTaskClassPolicy
            | Self::LoadUlReverseDependents
            | Self::LoadUlArtifactDirty
            | Self::LoadUlActivationGraph
            | Self::LoadCueRows
            | Self::LoadCueRecords
            | Self::LoadInjectionReceipts
            | Self::LoadUlArtifacts
            | Self::LoadPredictions
            | Self::LoadUlMetrics
            | Self::LoadUlReadiness
            | Self::ObservabilityReceiptById
            | Self::ObservabilityRecordsByKind
            | Self::CurrentState
            | Self::LoadRecallCandidates
            | Self::LoadMemorySearchFtsCandidates
            | Self::LoadCognitiveProjectionBacklog
            | Self::LoadCognitiveProjectionProjects
            | Self::LoadCognitiveProjectionFamilyStates
            | Self::FetchAtomsL2
            | Self::FetchAtomsL2Legacy
            | Self::WriterReceipts
            | Self::WriteReceiptById
            | Self::ToolObservationByWriteId
            | Self::LatestAuthorityObservationsByEntity
            | Self::TaskContractById
            | Self::ToolObservationById
            | Self::ToolObservationsByKind
            | Self::ExperiencePatternRevisionsById
            | Self::SemanticRecordsByKind
            | Self::ClaimCardById
            | Self::VerificationRunById
            | Self::CanonicalRecords
            | Self::CanonicalRecordPage
            | Self::CurationRecordPage
            | Self::CanonicalRecordByWriteId
            | Self::CanonicalRecordsBySubjectRef
            | Self::LoadCanonicalMemoryAdmissionChildren
            | Self::LoadCanonicalMemoryL2
            | Self::LoadCanonicalMemoryProjectionSegments
            | Self::CanonicalTraceByTraceRef
            | Self::MetaPolicyActionsByCandidate
            | Self::SleepCandidates => SurqlAccessClass::Read,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SchemaMigrate => "000_schema",
            Self::SchemaMigrateObservability => "001_observability",
            Self::SchemaMigrateUl => "002_ul_core",
            Self::SchemaMigrateUlDelivery => "003_ul_delivery",
            Self::SchemaMigrateUlArtifacts => "004_ul_artifacts",
            Self::SchemaMigrateUlPyramid => "005_ul_pyramid",
            Self::SchemaMigrateUlMeasurement => "006_ul_measurement",
            Self::SchemaMigrateUlDependencyActivation => "007_ul_dependency_activation",
            Self::SchemaMigrateUlTokenPolicy => "008_ul_token_policy",
            Self::SchemaMigrateMemorySearch => "009_memory_search",
            Self::SchemaMigrateMemorySearchFts => "010_memory_search_fts",
            Self::AssignUlExperimentArm => "assign_ul_experiment_arm",
            Self::UpsertUlExperimentAssignmentExplicit => {
                "upsert_ul_experiment_assignment_explicit"
            }
            Self::LoadUlExperimentAssignment => "load_ul_experiment_assignment",
            Self::LoadUlTaskClassLedgers => "load_ul_task_class_ledgers",
            Self::UpsertUlTaskClassPolicy => "upsert_ul_task_class_policy",
            Self::LoadUlTaskClassPolicy => "load_ul_task_class_policy",
            Self::ReplaceUlReverseDependencies => "replace_ul_reverse_dependencies",
            Self::ResetUlReverseDependencyProject => "reset_ul_reverse_dependency_project",
            Self::LoadUlReverseDependents => "load_ul_reverse_dependents",
            Self::UpsertUlArtifactDirty => "upsert_ul_artifact_dirty",
            Self::LoadUlArtifactDirty => "load_ul_artifact_dirty",
            Self::ClearUlArtifactDirty => "clear_ul_artifact_dirty",
            Self::ResetUlArtifactDirtyProject => "reset_ul_artifact_dirty_project",
            Self::LoadUlActivationGraph => "load_ul_activation_graph",
            Self::UpsertCueRows => "upsert_cue_rows",
            Self::DeleteCueRows => "delete_cues_for_record",
            Self::LoadCueRows => "load_cue_rows",
            Self::LoadCueRecords => "load_cue_records",
            Self::LoadInjectionReceipts => "load_injection_receipts",
            Self::LoadUlArtifacts => "load_ul_artifacts",
            Self::UpsertUlTaskLedger => "upsert_ul_task_ledger",
            Self::LoadPredictions => "load_predictions",
            Self::LoadUlMetrics => "load_ul_metrics",
            Self::LoadUlReadiness => "load_ul_readiness",
            Self::ApplyWriteEnvelope => "apply_write_envelope",
            Self::ApplyObservability => "apply_observability",
            Self::ObservabilityReceiptById => "observability_receipt_by_id",
            Self::ObservabilityRecordsByKind => "observability_records_by_kind",
            Self::CurrentState => "current_state",
            Self::LoadRecallCandidates => "load_recall_candidates",
            Self::UpsertMemorySearchProjection => "upsert_memory_search_projection",
            Self::ResetMemorySearchProjection => "reset_memory_search_projection",
            Self::LoadMemorySearchFtsCandidates => "load_memory_search_fts_candidates",
            Self::ExplainMemorySearchFts => "explain_memory_search_fts",
            Self::EnqueueCognitiveProjectionIntent => "enqueue_cognitive_projection_intent",
            Self::ClaimCognitiveProjectionProject => "claim_cognitive_projection_project",
            Self::CompleteCognitiveProjectionThrough => "complete_cognitive_projection_through",
            Self::FailCognitiveProjectionRetryable => "fail_cognitive_projection_retryable",
            Self::BlockCognitiveProjection => "block_cognitive_projection",
            Self::LoadCognitiveProjectionBacklog => "load_cognitive_projection_backlog",
            Self::LoadCognitiveProjectionProjects => "load_cognitive_projection_projects",
            Self::PublishCognitiveProjectionFamilyState => {
                "publish_cognitive_projection_family_state"
            }
            Self::LoadCognitiveProjectionFamilyStates => "load_cognitive_projection_family_states",
            Self::CutoverLegacyMemorySearchPostings => "cutover_legacy_memory_search_postings",
            Self::FetchAtomsL2 => "fetch_atoms_l2",
            Self::FetchAtomsL2Legacy => "fetch_atoms_l2_legacy",
            Self::GraphHealthCapabilities => "graph_health_capabilities",
            Self::GraphHealth => "graph_health",
            Self::WriterReceipts => "writer_receipts",
            Self::WriteReceiptById => "write_receipt_by_id",
            Self::ToolObservationByWriteId => "tool_observation_by_write_id",
            Self::LatestAuthorityObservationsByEntity => "latest_authority_observations_by_entity",
            Self::TaskContractById => "task_contract_by_id",
            Self::ToolObservationById => "tool_observation_by_id",
            Self::ToolObservationsByKind => "tool_observations_by_kind",
            Self::ExperiencePatternRevisionsById => "experience_pattern_revisions_by_id",
            Self::SemanticRecordsByKind => "semantic_records_by_kind",
            Self::ClaimCardById => "claim_card_by_id",
            Self::VerificationRunById => "verification_run_by_id",
            Self::CanonicalRecords => "canonical_records",
            Self::CanonicalRecordPage => "canonical_record_page",
            Self::CurationRecordPage => "curation_record_page",
            Self::CanonicalRecordByWriteId => "canonical_record_by_write_id",
            Self::CanonicalRecordsBySubjectRef => "canonical_records_by_subject_ref",
            Self::LoadCanonicalMemoryAdmissionChildren => {
                "load_canonical_memory_admission_children"
            }
            Self::LoadCanonicalMemoryL2 => "load_canonical_memory_l2",
            Self::LoadCanonicalMemoryProjectionSegments => {
                "load_canonical_memory_projection_segments"
            }
            Self::CanonicalTraceByTraceRef => "canonical_trace_by_trace_ref",
            Self::MetaPolicyActionsByCandidate => "meta_policy_actions_by_candidate",
            Self::SleepCandidates => "sleep_candidates",
            Self::BlobReferenceScan => "blob_reference_scan",
        }
    }

    // This exhaustive table deliberately keeps every operation adjacent to its
    // embedded SQL resource; splitting it would weaken the enum-to-template audit.
    #[allow(clippy::too_many_lines)]
    pub const fn template(self) -> &'static str {
        match self {
            Self::SchemaMigrate => include_str!("surql/000_schema.surql"),
            Self::SchemaMigrateObservability => include_str!("surql/001_observability.surql"),
            Self::SchemaMigrateUl => include_str!("surql/002_ul_core.surql"),
            Self::SchemaMigrateUlDelivery => include_str!("surql/003_ul_delivery.surql"),
            Self::SchemaMigrateUlArtifacts => include_str!("surql/004_ul_artifacts.surql"),
            Self::SchemaMigrateUlPyramid => include_str!("surql/005_ul_pyramid.surql"),
            Self::SchemaMigrateUlMeasurement => {
                include_str!("surql/006_ul_measurement.surql")
            }
            Self::SchemaMigrateUlDependencyActivation => {
                include_str!("surql/007_ul_dependency_activation.surql")
            }
            Self::SchemaMigrateUlTokenPolicy => include_str!("surql/008_ul_token_policy.surql"),
            Self::SchemaMigrateMemorySearch => include_str!("surql/009_memory_search.surql"),
            Self::SchemaMigrateMemorySearchFts => {
                include_str!("surql/010_memory_search_fts.surql")
            }
            Self::AssignUlExperimentArm => include_str!("surql/assign_ul_experiment_arm.surql"),
            Self::UpsertUlExperimentAssignmentExplicit => {
                include_str!("surql/upsert_ul_experiment_assignment_explicit.surql")
            }
            Self::LoadUlExperimentAssignment => {
                include_str!("surql/load_ul_experiment_assignment.surql")
            }
            Self::LoadUlTaskClassLedgers => include_str!("surql/load_ul_task_class_ledgers.surql"),
            Self::UpsertUlTaskClassPolicy => {
                include_str!("surql/upsert_ul_task_class_policy.surql")
            }
            Self::LoadUlTaskClassPolicy => include_str!("surql/load_ul_task_class_policy.surql"),
            Self::ReplaceUlReverseDependencies => {
                include_str!("surql/replace_ul_reverse_dependencies.surql")
            }
            Self::ResetUlReverseDependencyProject => {
                include_str!("surql/reset_ul_reverse_dependency_project.surql")
            }
            Self::LoadUlReverseDependents => {
                include_str!("surql/load_ul_reverse_dependents.surql")
            }
            Self::UpsertUlArtifactDirty => include_str!("surql/upsert_ul_artifact_dirty.surql"),
            Self::LoadUlArtifactDirty => include_str!("surql/load_ul_artifact_dirty.surql"),
            Self::ClearUlArtifactDirty => include_str!("surql/clear_ul_artifact_dirty.surql"),
            Self::ResetUlArtifactDirtyProject => {
                include_str!("surql/reset_ul_artifact_dirty_project.surql")
            }
            Self::LoadUlActivationGraph => include_str!("surql/load_ul_activation_graph.surql"),
            Self::UpsertCueRows => include_str!("surql/upsert_cue_rows.surql"),
            Self::DeleteCueRows => include_str!("surql/delete_cues_for_record.surql"),
            Self::LoadCueRows => include_str!("surql/load_cue_rows.surql"),
            Self::LoadCueRecords => include_str!("surql/load_cue_records.surql"),
            Self::LoadInjectionReceipts => {
                include_str!("surql/load_injection_receipts.surql")
            }
            Self::LoadUlArtifacts => include_str!("surql/load_ul_artifacts.surql"),
            Self::UpsertUlTaskLedger => include_str!("surql/upsert_ul_task_ledger.surql"),
            Self::LoadPredictions => include_str!("surql/load_predictions.surql"),
            Self::LoadUlMetrics => include_str!("surql/load_ul_metrics.surql"),
            Self::LoadUlReadiness => include_str!("surql/load_ul_readiness.surql"),
            Self::ApplyWriteEnvelope => include_str!("surql/apply_write_envelope.surql"),
            Self::ApplyObservability => include_str!("surql/apply_observability.surql"),
            Self::ObservabilityReceiptById => {
                include_str!("surql/observability_receipt_by_id.surql")
            }
            Self::ObservabilityRecordsByKind => {
                include_str!("surql/observability_records_by_kind.surql")
            }
            Self::CurrentState => include_str!("surql/current_state.surql"),
            Self::LoadRecallCandidates => include_str!("surql/load_recall_candidates.surql"),
            Self::UpsertMemorySearchProjection => {
                include_str!("surql/upsert_memory_search_projection.surql")
            }
            Self::ResetMemorySearchProjection => {
                include_str!("surql/reset_memory_search_projection.surql")
            }
            Self::LoadMemorySearchFtsCandidates => {
                include_str!("surql/load_memory_search_fts_candidates.surql")
            }
            Self::ExplainMemorySearchFts => {
                include_str!("surql/explain_memory_search_fts.surql")
            }
            Self::EnqueueCognitiveProjectionIntent => {
                include_str!("surql/enqueue_cognitive_projection_intent.surql")
            }
            Self::ClaimCognitiveProjectionProject => {
                include_str!("surql/claim_cognitive_projection_project.surql")
            }
            Self::CompleteCognitiveProjectionThrough => {
                include_str!("surql/complete_cognitive_projection_through.surql")
            }
            Self::FailCognitiveProjectionRetryable => {
                include_str!("surql/fail_cognitive_projection_retryable.surql")
            }
            Self::BlockCognitiveProjection => {
                include_str!("surql/block_cognitive_projection.surql")
            }
            Self::LoadCognitiveProjectionBacklog => {
                include_str!("surql/load_cognitive_projection_backlog.surql")
            }
            Self::LoadCognitiveProjectionProjects => {
                include_str!("surql/load_cognitive_projection_projects.surql")
            }
            Self::PublishCognitiveProjectionFamilyState => {
                include_str!("surql/publish_cognitive_projection_family_state.surql")
            }
            Self::LoadCognitiveProjectionFamilyStates => {
                include_str!("surql/load_cognitive_projection_family_states.surql")
            }
            Self::CutoverLegacyMemorySearchPostings => {
                include_str!("surql/cutover_legacy_memory_search_postings.surql")
            }
            Self::FetchAtomsL2 => include_str!("surql/fetch_atoms_l2.surql"),
            Self::FetchAtomsL2Legacy => include_str!("surql/fetch_atoms_l2_legacy.surql"),
            Self::GraphHealthCapabilities => {
                include_str!("surql/graph_health_capabilities.surql")
            }
            Self::GraphHealth => include_str!("surql/graph_health.surql"),
            Self::WriterReceipts => include_str!("surql/writer_receipts.surql"),
            Self::WriteReceiptById => include_str!("surql/write_receipt_by_id.surql"),
            Self::ToolObservationByWriteId => {
                include_str!("surql/tool_observation_by_write_id.surql")
            }
            Self::LatestAuthorityObservationsByEntity => {
                include_str!("surql/latest_authority_observations_by_entity.surql")
            }
            Self::TaskContractById => include_str!("surql/task_contract_by_id.surql"),
            Self::ToolObservationById => include_str!("surql/tool_observation_by_id.surql"),
            Self::ToolObservationsByKind => {
                include_str!("surql/tool_observations_by_kind.surql")
            }
            Self::ExperiencePatternRevisionsById => {
                include_str!("surql/experience_pattern_revisions_by_id.surql")
            }
            Self::SemanticRecordsByKind => {
                include_str!("surql/semantic_records_by_kind.surql")
            }
            Self::ClaimCardById => include_str!("surql/claim_card_by_id.surql"),
            Self::VerificationRunById => include_str!("surql/verification_run_by_id.surql"),
            Self::CanonicalRecords => include_str!("surql/canonical_records.surql"),
            Self::CanonicalRecordPage => include_str!("surql/canonical_record_page.surql"),
            Self::CurationRecordPage => include_str!("surql/curation_record_page.surql"),
            Self::CanonicalRecordByWriteId => {
                include_str!("surql/canonical_record_by_write_id.surql")
            }
            Self::CanonicalRecordsBySubjectRef => {
                include_str!("surql/canonical_records_by_subject_ref.surql")
            }
            Self::LoadCanonicalMemoryAdmissionChildren => {
                include_str!("surql/load_canonical_memory_admission_children.surql")
            }
            Self::LoadCanonicalMemoryL2 => {
                include_str!("surql/load_canonical_memory_l2.surql")
            }
            Self::LoadCanonicalMemoryProjectionSegments => {
                include_str!("surql/load_canonical_memory_projection_segments.surql")
            }
            Self::CanonicalTraceByTraceRef => {
                include_str!("surql/canonical_trace_by_trace_ref.surql")
            }
            Self::MetaPolicyActionsByCandidate => {
                include_str!("surql/meta_policy_actions_by_candidate.surql")
            }
            Self::SleepCandidates => include_str!("surql/sleep_candidates.surql"),
            Self::BlobReferenceScan => include_str!("surql/blob_reference_scan.surql"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SurqlTemplateRegistry {
    templates: HashMap<NamedSurqlOp, SurqlTemplate>,
}

#[derive(Clone, Debug)]
pub struct SurqlTemplate {
    pub op: NamedSurqlOp,
    pub name: &'static str,
    pub sql: &'static str,
    pub input_schema_name: &'static str,
    pub output_schema_name: &'static str,
    pub max_result_bytes: usize,
    pub timeout_ms: u64,
}

impl Default for SurqlTemplateRegistry {
    fn default() -> Self {
        let templates = foundational_templates()
            .into_iter()
            .chain(canonical_templates())
            .chain(experience_templates())
            .map(|entry| (entry.op, entry))
            .collect();

        Self { templates }
    }
}

#[allow(clippy::too_many_lines)]
fn foundational_templates() -> [SurqlTemplate; 61] {
    [
        template(
            NamedSurqlOp::SchemaMigrate,
            "SchemaMigrateInput",
            "SchemaMigrateOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateObservability,
            "SchemaMigrateObservabilityInput",
            "SchemaMigrateObservabilityOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUl,
            "SchemaMigrateUlInput",
            "SchemaMigrateUlOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlDelivery,
            "SchemaMigrateUlDeliveryInput",
            "SchemaMigrateUlDeliveryOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlArtifacts,
            "SchemaMigrateUlArtifactsInput",
            "SchemaMigrateUlArtifactsOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlPyramid,
            "SchemaMigrateUlPyramidInput",
            "SchemaMigrateUlPyramidOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlMeasurement,
            "SchemaMigrateUlMeasurementInput",
            "SchemaMigrateUlMeasurementOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlDependencyActivation,
            "SchemaMigrateUlDependencyActivationInput",
            "SchemaMigrateUlDependencyActivationOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateUlTokenPolicy,
            "SchemaMigrateUlTokenPolicyInput",
            "SchemaMigrateUlTokenPolicyOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateMemorySearch,
            "SchemaMigrateMemorySearchInput",
            "SchemaMigrateMemorySearchOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::SchemaMigrateMemorySearchFts,
            "SchemaMigrateMemorySearchFtsInput",
            "SchemaMigrateMemorySearchFtsOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::AssignUlExperimentArm,
            "AssignUlExperimentArmInput",
            "AssignUlExperimentArmOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertUlExperimentAssignmentExplicit,
            "UpsertUlExperimentAssignmentExplicitInput",
            "UpsertUlExperimentAssignmentExplicitOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlExperimentAssignment,
            "LoadUlExperimentAssignmentInput",
            "LoadUlExperimentAssignmentOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlTaskClassLedgers,
            "LoadUlTaskClassLedgersInput",
            "LoadUlTaskClassLedgersOutput",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertUlTaskClassPolicy,
            "UpsertUlTaskClassPolicyInput",
            "UpsertUlTaskClassPolicyOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlTaskClassPolicy,
            "LoadUlTaskClassPolicyInput",
            "LoadUlTaskClassPolicyOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::ReplaceUlReverseDependencies,
            "ReplaceUlReverseDependenciesInput",
            "ReplaceUlReverseDependenciesOutput",
            2 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::ResetUlReverseDependencyProject,
            "ResetUlReverseDependencyProjectInput",
            "ResetUlReverseDependencyProjectOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlReverseDependents,
            "LoadUlReverseDependentsInput",
            "LoadUlReverseDependentsOutput",
            4 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertUlArtifactDirty,
            "UpsertUlArtifactDirtyInput",
            "UpsertUlArtifactDirtyOutput",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlArtifactDirty,
            "LoadUlArtifactDirtyInput",
            "LoadUlArtifactDirtyOutput",
            4 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::ClearUlArtifactDirty,
            "ClearUlArtifactDirtyInput",
            "ClearUlArtifactDirtyOutput",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::ResetUlArtifactDirtyProject,
            "ResetUlArtifactDirtyProjectInput",
            "ResetUlArtifactDirtyProjectOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlActivationGraph,
            "LoadUlActivationGraphInput",
            "LoadUlActivationGraphOutput",
            8 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertCueRows,
            "UpsertCueRowsInput",
            "UpsertCueRowsOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::DeleteCueRows,
            "DeleteCueRowsInput",
            "DeleteCueRowsOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCueRows,
            "LoadCueRowsInput",
            "LoadCueRowsOutput",
            4 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCueRecords,
            "LoadCueRecordsInput",
            "LoadCueRecordsOutput",
            8 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::LoadInjectionReceipts,
            "LoadInjectionReceiptsInput",
            "LoadInjectionReceiptsOutput",
            8 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlArtifacts,
            "LoadUlArtifactsInput",
            "LoadUlArtifactsOutput",
            8 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertUlTaskLedger,
            "UpsertUlTaskLedgerInput",
            "UpsertUlTaskLedgerOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadPredictions,
            "LoadPredictionsInput",
            "LoadPredictionsOutput",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlMetrics,
            "LoadUlMetricsInput",
            "LoadUlMetricsOutput",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::LoadUlReadiness,
            "LoadUlReadinessInput",
            "LoadUlReadinessOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::ApplyWriteEnvelope,
            "ApplyWriteEnvelopeInput",
            "ApplyWriteEnvelopeOutput",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::ApplyObservability,
            "ApplyObservabilityInput",
            "ApplyObservabilityOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::ObservabilityReceiptById,
            "ObservabilityReceiptByIdInput",
            "ObservabilityReceiptByIdOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::ObservabilityRecordsByKind,
            "ObservabilityRecordsByKindInput",
            "ObservabilityRecordsByKindOutput",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::CurrentState,
            "CurrentStateRequest",
            "CurrentStateResponse",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::LoadRecallCandidates,
            "LoadRecallCandidatesInput",
            "LoadRecallCandidatesOutput",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::UpsertMemorySearchProjection,
            "UpsertMemorySearchProjectionInput",
            "UpsertMemorySearchProjectionOutput",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::ResetMemorySearchProjection,
            "ResetMemorySearchProjectionInput",
            "ResetMemorySearchProjectionOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadMemorySearchFtsCandidates,
            "LoadMemorySearchFtsCandidatesInput",
            "LoadMemorySearchFtsCandidatesOutput",
            2 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::ExplainMemorySearchFts,
            "ExplainMemorySearchFtsInput",
            "ExplainMemorySearchFtsOutput",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::EnqueueCognitiveProjectionIntent,
            "EnqueueCognitiveProjectionIntentInput",
            "EnqueueCognitiveProjectionIntentOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::ClaimCognitiveProjectionProject,
            "ClaimCognitiveProjectionProjectInput",
            "ClaimCognitiveProjectionProjectOutput",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::CompleteCognitiveProjectionThrough,
            "CompleteCognitiveProjectionThroughInput",
            "CompleteCognitiveProjectionThroughOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::FailCognitiveProjectionRetryable,
            "FailCognitiveProjectionRetryableInput",
            "FailCognitiveProjectionRetryableOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::BlockCognitiveProjection,
            "BlockCognitiveProjectionInput",
            "BlockCognitiveProjectionOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCognitiveProjectionBacklog,
            "LoadCognitiveProjectionBacklogInput",
            "LoadCognitiveProjectionBacklogOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCognitiveProjectionProjects,
            "LoadCognitiveProjectionProjectsInput",
            "LoadCognitiveProjectionProjectsOutput",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::PublishCognitiveProjectionFamilyState,
            "PublishCognitiveProjectionFamilyStateInput",
            "PublishCognitiveProjectionFamilyStateOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCognitiveProjectionFamilyStates,
            "LoadCognitiveProjectionFamilyStatesInput",
            "LoadCognitiveProjectionFamilyStatesOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::CutoverLegacyMemorySearchPostings,
            "CutoverLegacyMemorySearchPostingsInput",
            "CutoverLegacyMemorySearchPostingsOutput",
            64 * 1024,
        ),
        template(
            NamedSurqlOp::FetchAtomsL2,
            "FetchAtomsL2Request",
            "FetchAtomsL2Response",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::FetchAtomsL2Legacy,
            "FetchAtomsL2Request",
            "FetchAtomsL2Response",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::GraphHealthCapabilities,
            "GraphHealthCapabilitiesRequest",
            "GraphHealthCapabilitiesResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::GraphHealth,
            "GraphHealthRequest",
            "GraphHealthResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::WriterReceipts,
            "WriterReceiptsRequest",
            "WriterReceiptsResponse",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::WriteReceiptById,
            "WriteReceiptByIdRequest",
            "WriteReceiptByIdResponse",
            64 * 1024,
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn canonical_templates() -> [SurqlTemplate; 20] {
    [
        template(
            NamedSurqlOp::ToolObservationByWriteId,
            "ToolObservationByWriteIdRequest",
            "ToolObservationByWriteIdResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::LatestAuthorityObservationsByEntity,
            "LatestAuthorityObservationsByEntityRequest",
            "LatestAuthorityObservationsByEntityResponse",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::TaskContractById,
            "TaskContractByIdRequest",
            "TaskContractByIdResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::ToolObservationById,
            "ToolObservationByIdRequest",
            "ToolObservationByIdResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::ToolObservationsByKind,
            "ToolObservationsByKindRequest",
            "ToolObservationsByKindResponse",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::SemanticRecordsByKind,
            "SemanticRecordsByKindRequest",
            "SemanticRecordsByKindResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::ClaimCardById,
            "ClaimCardByIdRequest",
            "ClaimCardByIdResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::VerificationRunById,
            "VerificationRunByIdRequest",
            "VerificationRunByIdResponse",
            128 * 1024,
        ),
        template(
            NamedSurqlOp::CanonicalRecords,
            "CanonicalRecordsRequest",
            "CanonicalRecordsResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::CanonicalRecordPage,
            "CanonicalRecordPageRequest",
            "CanonicalRecordPageResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::CurationRecordPage,
            "CurationRecordPageRequest",
            "CurationRecordPageResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::CanonicalRecordByWriteId,
            "CanonicalRecordByWriteIdRequest",
            "CanonicalRecordByWriteIdResponse",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::CanonicalRecordsBySubjectRef,
            "CanonicalRecordsBySubjectRefRequest",
            "CanonicalRecordsBySubjectRefResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCanonicalMemoryAdmissionChildren,
            "LoadCanonicalMemoryAdmissionChildrenRequest",
            "LoadCanonicalMemoryAdmissionChildrenResponse",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCanonicalMemoryL2,
            "LoadCanonicalMemoryL2Request",
            "LoadCanonicalMemoryL2Response",
            512 * 1024,
        ),
        template(
            NamedSurqlOp::LoadCanonicalMemoryProjectionSegments,
            "LoadCanonicalMemoryProjectionSegmentsRequest",
            "LoadCanonicalMemoryProjectionSegmentsResponse",
            2 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::CanonicalTraceByTraceRef,
            "CanonicalTraceByTraceRefRequest",
            "CanonicalTraceByTraceRefResponse",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::MetaPolicyActionsByCandidate,
            "MetaPolicyActionsByCandidateRequest",
            "MetaPolicyActionsByCandidateResponse",
            256 * 1024,
        ),
        template(
            NamedSurqlOp::SleepCandidates,
            "SleepCandidatesRequest",
            "SleepCandidatesResponse",
            1024 * 1024,
        ),
        template(
            NamedSurqlOp::BlobReferenceScan,
            "BlobReferenceScanRequest",
            "BlobReferenceScanResponse",
            4 * 1024 * 1024,
        ),
    ]
}

fn experience_templates() -> [SurqlTemplate; 1] {
    [template(
        NamedSurqlOp::ExperiencePatternRevisionsById,
        "ExperiencePatternRevisionsByIdRequest",
        "ExperiencePatternRevisionsByIdResponse",
        128 * 1024,
    )]
}

impl SurqlTemplateRegistry {
    pub fn get(&self, op: NamedSurqlOp) -> Option<&SurqlTemplate> {
        self.templates.get(&op)
    }
}

fn template(
    op: NamedSurqlOp,
    input_schema_name: &'static str,
    output_schema_name: &'static str,
    max_result_bytes: usize,
) -> SurqlTemplate {
    SurqlTemplate {
        op,
        name: op.name(),
        sql: op.template(),
        input_schema_name,
        output_schema_name,
        max_result_bytes,
        timeout_ms: 5_000,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{NamedSurqlOp, SurqlAccessClass, SurqlTemplateRegistry};

    #[test]
    fn access_classes_are_exhaustive_and_have_expected_counts() {
        let registry = SurqlTemplateRegistry::default();
        let mut counts = [0_usize; 3];

        for op in registry.templates.keys() {
            match op.access_class() {
                SurqlAccessClass::Read => counts[0] += 1,
                SurqlAccessClass::Write => counts[1] += 1,
                SurqlAccessClass::Admin => counts[2] += 1,
            }
        }

        assert_eq!(registry.templates.len(), 82);
        assert_eq!(counts, [45, 21, 16]);
    }

    #[test]
    fn access_classes_cover_representative_operations() {
        assert_eq!(
            NamedSurqlOp::TaskContractById.access_class(),
            SurqlAccessClass::Read
        );
        assert_eq!(
            NamedSurqlOp::ApplyWriteEnvelope.access_class(),
            SurqlAccessClass::Write
        );
        assert_eq!(
            NamedSurqlOp::SchemaMigrateMemorySearch.access_class(),
            SurqlAccessClass::Admin
        );
        assert_eq!(
            NamedSurqlOp::LoadMemorySearchFtsCandidates.access_class(),
            SurqlAccessClass::Read
        );
        assert_eq!(
            NamedSurqlOp::ExplainMemorySearchFts.access_class(),
            SurqlAccessClass::Admin
        );
        assert_eq!(
            NamedSurqlOp::BlobReferenceScan.access_class(),
            SurqlAccessClass::Admin
        );
    }

    #[test]
    fn ordered_tool_observation_projection_contains_order_fields() {
        let template = NamedSurqlOp::ToolObservationsByKind.template();

        assert!(template.contains("memory_revision, project_sequence"));
        assert!(template.contains("ORDER BY memory_revision ASC, project_sequence ASC"));
    }

    #[test]
    fn experience_pattern_revision_lookup_is_exact_latest_first_and_bounded() {
        let template = NamedSurqlOp::ExperiencePatternRevisionsById.template();

        assert!(template.contains("project_id = $project_id"));
        assert!(template.contains("task_id = $task_id"));
        assert!(template.contains("payload.receipt_kind = 'experience_pattern'"));
        assert!(template.contains("payload.receipt_body.pattern_id = $pattern_id"));
        assert!(template.contains("ORDER BY memory_revision DESC, project_sequence DESC"));
        assert!(template.contains("LIMIT 2"));
    }

    #[test]
    fn l0_candidate_load_is_paged_multi_kind_and_does_not_rank() {
        let template = NamedSurqlOp::LoadRecallCandidates.template();

        assert!(template.contains("FROM claim_card"));
        assert!(template.contains("FROM evidence_atom"));
        assert!(template.contains("FROM verification_run"));
        assert!(template.contains("FROM tool_observation"));
        assert!(template.contains("FROM failure_fingerprint"));
        assert!(template.contains("FROM canonical_record"));
        assert!(template.contains("'module_card'"));
        assert!(template.contains("'subsystem_capsule'"));
        assert!(template.contains("'project_charter'"));
        assert!(template.contains("'system_map'"));
        assert!(template.contains("START $start LIMIT $page_limit_plus_one"));
        assert!(template.contains("array::slice($rows, 0, $limit)"));
        assert!(template.contains("$lifecycle_audit"));
        assert!(!template.contains("LIMIT 257"));
        assert!(!template.contains("LIMIT 129"));
        assert!(!template.contains("array::slice($all_candidates, 0, 512)"));
        assert!(!template.contains("string::words"));
        assert!(!template.contains("string::slug"));
        assert!(!template.contains("relevance_score"));
    }

    #[test]
    fn memory_search_fts_is_versioned_bounded_project_scoped_and_additive() {
        let schema = NamedSurqlOp::SchemaMigrateMemorySearchFts.template();
        assert!(schema.contains("DEFINE ANALYZER IF NOT EXISTS eliot_memory_search_v1"));
        assert!(schema.contains("TOKENIZERS class"));
        assert!(schema.contains("idx_memory_search_projection_fts_v1"));
        assert!(schema.contains("FIELDS search_document"));
        assert!(schema.contains("FULLTEXT ANALYZER eliot_memory_search_v1 BM25"));
        assert!(schema.contains("projection_format: 'fts_v1'"));
        assert!(!schema.contains("OVERWRITE"));
        assert!(!schema.contains("REMOVE"));
        assert!(!schema.contains("memory_search_token"));

        let load = NamedSurqlOp::LoadMemorySearchFtsCandidates.template();
        for binding in [
            "$project_id",
            "$exact_handle_parts",
            "$query_text",
            "$candidate_limit",
        ] {
            assert!(load.contains(binding), "missing FTS binding {binding}");
        }
        assert!(load.contains("search_document @0,OR@ $query_text"));
        assert!(load.contains("math::max(search::score(0)) AS relevance_score"));
        assert!(load.contains("GROUP BY handle"));
        assert!(load.contains("$capped_handles.map"));
        assert!(load.contains("array::flatten($rows_nested)"));
        assert!(!load.contains("array::flatten([$rows_nested])"));
        assert!(load.contains("ORDER BY relevance_score DESC, authority_rank DESC, handle ASC"));
        assert_eq!(load.matches("search::score").count(), 2);
        assert!(load.contains("search::score(0) AS segment_relevance_score"));
        assert!(load.contains("OR search_document @0,OR@ $query_text"));
        assert!(load.contains("segment_relevance_score DESC"));
        let return_shape = load
            .rsplit_once("RETURN {")
            .expect("FTS loader must expose one typed return object")
            .1;
        assert!(!return_shape.contains("relevance_score"));
        assert!(load.contains("project_id = $project_id"));
        assert!(load.contains("$candidate_limit > 256"));
        assert!(load.contains("$bounded_candidate_limit + 1"));
        assert!(load.contains("LIMIT $candidate_limit_plus_one"));
        assert!(load.contains("array::slice($ordered_handles, 0, $bounded_candidate_limit)"));
        assert!(load.contains("array::len($exact_handles) > 0"));
        assert!(load.contains("projection_format"));
        assert!(load.contains("$family_state[0].status = 'published'"));
        assert!(load.contains("$family_state[0].target_revision = $head.memory_revision"));
        assert!(load.contains("$family_state[0].applied_revision = $head.memory_revision"));
        assert!(load.contains("IF $projection_ready AND $exact_handle != ''"));
        assert!(load.contains("IF !$projection_ready"));
        assert!(!load.contains("memory_search_token"));
        assert!(!load.contains("ambient"));

        let explain = NamedSurqlOp::ExplainMemorySearchFts.template();
        assert!(explain.contains("search_document @0,OR@ $query_text"));
        assert!(explain.contains("math::max(search::score(0)) AS relevance_score"));
        assert!(explain.contains("GROUP BY handle"));
        assert!(explain.contains("ORDER BY relevance_score DESC, authority_rank DESC, handle ASC"));
        assert!(explain.contains("project_id = $project_id"));
        assert!(explain.contains("LIMIT $candidate_limit_plus_one"));
        assert!(explain.contains("EXPLAIN FULL"));
        assert!(!explain.contains("memory_search_token"));
    }

    #[test]
    fn memory_search_projection_format_advances_only_when_explicitly_supplied() {
        let upsert = NamedSurqlOp::UpsertMemorySearchProjection.template();

        assert!(upsert.contains("$projection_format == NONE"));
        assert!(upsert.contains("$projection_format == NULL"));
        assert!(upsert.contains("projection_format: $projection_format"));
        assert!(upsert.contains("UPSERT $state_id MERGE"));
        assert!(!upsert.contains("memory_search_outbox"));
        assert!(!upsert.contains("memory_search_token"));
    }

    #[test]
    fn canonical_write_and_projection_intent_are_one_failure_atomic_transaction() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        let Some(transaction) = write.find("BEGIN TRANSACTION;") else {
            panic!("canonical write transaction start is missing");
        };
        let Some(canonical) = write.find("UPSERT type::record('memory_transition'") else {
            panic!("canonical memory transition is missing");
        };
        let Some(failure) = write.find("IF $fail_before_projection_outbox") else {
            panic!("canonical transaction failure injection is missing");
        };
        let Some(outbox) = write.find("UPSERT type::record('memory_search_outbox'") else {
            panic!("cognitive projection outbox write is missing");
        };
        let Some(commit) = write.rfind("COMMIT TRANSACTION;") else {
            panic!("canonical write transaction commit is missing");
        };

        assert!(transaction < canonical);
        assert!(canonical < failure && failure < outbox);
        assert!(outbox < commit);
        assert!(write.contains("families: ['search', 'cue', 'dependency_dirty']"));
        assert!(write.contains("write_id: <string> $envelope.write_id"));
        assert!(!write.contains("'utility']"));
    }

    #[test]
    fn cognitive_projection_claim_is_reclaimable_and_never_crosses_an_older_project_barrier() {
        let claim = NamedSurqlOp::ClaimCognitiveProjectionProject.template();

        assert!(claim.contains("LIMIT 1"));
        assert!(claim.contains("lease_expires_at <= <datetime> $now"));
        assert!(claim.contains("lease_expires_at > <datetime> $now"));
        assert!(claim.contains("AND array::len(("));
        assert!(claim.contains("AND status != 'applied'"));
        assert!(claim.contains("updated_revision < $parent.updated_revision"));
        assert!(claim.contains("created_at < $parent.created_at"));
        assert!(claim.contains("<string> write_id < <string> $parent.write_id"));
        assert!(claim.contains("LET $leased = UPDATE $candidate"));
        assert!(claim.contains("lease_id = $lease_id"));
        assert!(claim.contains("attempt_count = (attempt_count ?? 0) + 1"));
        assert!(claim.contains("write_id: <string> $row.write_id"));

        let enqueue = NamedSurqlOp::EnqueueCognitiveProjectionIntent.template();
        assert!(enqueue.contains("LET $event_id = <string> array::join("));
        assert!(enqueue.contains("$event_id_parts.map(|$fragment| <string> $fragment)"));

        for op in [
            NamedSurqlOp::CompleteCognitiveProjectionThrough,
            NamedSurqlOp::FailCognitiveProjectionRetryable,
            NamedSurqlOp::BlockCognitiveProjection,
        ] {
            let template = op.template();
            assert!(template.contains("LET $owned = SELECT *"));
            assert!(template.contains("lease_id = $lease_id"));
            assert!(template.contains("lease_owner = $lease_owner"));
            assert!(template.contains("<string> $row.write_id IN $bound_write_ids"));
            assert!(template.contains("lease_expires_at > <datetime> $now"));
            assert!(template.contains("LET $owned_rows = $owned ?? []"));
            assert!(template.contains("LET $write_ids = ($write_id_parts ?? []).map(|$parts|"));
            assert!(template.contains("$parts.map(|$fragment| <string> $fragment)"));
            assert!(template.contains(
                "LET $bound_write_ids = ($write_ids ?? []).map(|$write_id| <string> $write_id)"
            ));
            assert!(
                template.contains(
                    "LET $owned_revisions = $owned_rows.map(|$row| $row.updated_revision)"
                )
            );
            assert!(template.contains("math::max($owned_revisions) != $through_revision"));
            assert!(template.contains("$owned_rows.map(|$row| $row.families ?? [])"));
            assert!(template.contains("!($family IN $bound_families)"));
            assert!(template.contains("!($family IN $owned_families)"));
            assert!(template.contains("cognitive_projection_lease_mismatch:owned_count"));
            assert!(template.contains("cognitive_projection_lease_mismatch:row_set"));
            assert!(template.contains("cognitive_projection_lease_mismatch:through_revision"));
            assert!(template.contains("cognitive_projection_lease_mismatch:family_set"));
            assert!(template.contains("THROW $lease_mismatch"));
        }
    }

    #[test]
    fn projection_family_state_is_per_family_revision_fenced_and_utility_can_be_unavailable() {
        let schema = NamedSurqlOp::SchemaMigrateMemorySearch.template();
        let publish = NamedSurqlOp::PublishCognitiveProjectionFamilyState.template();
        let enqueue = NamedSurqlOp::EnqueueCognitiveProjectionIntent.template();
        let complete = NamedSurqlOp::CompleteCognitiveProjectionThrough.template();
        let fail = NamedSurqlOp::FailCognitiveProjectionRetryable.template();
        let block = NamedSurqlOp::BlockCognitiveProjection.template();

        assert!(schema.contains("cognitive_projection_state"));
        assert!(schema.contains("project_id, family UNIQUE"));
        assert!(publish.contains("$target_revision > $existing.target_revision"));
        assert!(publish.contains("$incoming_applied >= $existing_applied"));
        assert!(publish.contains("$effective_status = 'published'"));
        assert!(publish.contains("string::starts_with(<string> write_id, 'dependency-dirty:')"));
        assert!(publish.contains("family: $family"));
        assert!(publish.contains("last_error: $effective_error"));
        assert!(enqueue.contains("IF $mark_dependency_dirty_stale"));
        assert!(enqueue.contains("family: 'dependency_dirty'"));
        assert!(enqueue.contains("'stale'"));
        assert!(complete.contains("LET $remaining = SELECT status, updated_revision"));
        assert!(complete.contains("status: 'published'"));
        assert!(fail.contains("$state.status = 'blocked'"));
        assert!(fail.contains("$state.last_error"));
        assert!(block.contains("status: 'blocked'"));
    }

    #[test]
    fn projection_inventory_is_paged_and_legacy_postings_have_one_explicit_admin_cutover() {
        let backlog = NamedSurqlOp::LoadCognitiveProjectionBacklog.template();
        let inventory = NamedSurqlOp::LoadCognitiveProjectionProjects.template();
        let cutover = NamedSurqlOp::CutoverLegacyMemorySearchPostings.template();

        assert_eq!(backlog.matches("count(id) AS count").count(), 8);
        assert!(!backlog.contains("count() AS count"));
        assert!(inventory.contains("$limit > 100"));
        assert!(inventory.contains("START $start"));
        assert!(inventory.contains("LIMIT $bounded_limit + 1"));
        assert!(inventory.contains("search_applied_revision"));
        assert!(inventory.contains("search_projection_format"));
        assert!(inventory.contains("status = 'pending'"));
        assert!(inventory.contains("status = 'leased'"));
        assert!(inventory.contains("status = 'retryable'"));
        assert!(inventory.contains("status = 'blocked'"));
        assert!(inventory.contains("oldest_pending_created_at"));
        assert_eq!(inventory.matches("count(id) AS count").count(), 4);
        assert!(!inventory.contains("count() AS count"));
        assert_eq!(
            inventory.matches("project_id = $parent.project_id").count(),
            5
        );
        assert!(cutover.contains("projection_format != 'fts_v1'"));
        assert!(cutover.contains("applied_revision != $head.memory_revision"));
        assert!(cutover.contains("REMOVE TABLE IF EXISTS memory_search_token"));
        assert_eq!(
            NamedSurqlOp::CutoverLegacyMemorySearchPostings.access_class(),
            SurqlAccessClass::Admin
        );

        for op in [
            NamedSurqlOp::SchemaMigrateMemorySearch,
            NamedSurqlOp::UpsertMemorySearchProjection,
            NamedSurqlOp::ResetMemorySearchProjection,
            NamedSurqlOp::LoadMemorySearchFtsCandidates,
            NamedSurqlOp::ExplainMemorySearchFts,
        ] {
            assert!(!op.template().contains("memory_search_token"));
        }
    }

    #[test]
    fn cold_projection_resets_are_project_scoped_and_generic_migration_is_non_destructive() {
        for op in [
            NamedSurqlOp::ResetUlReverseDependencyProject,
            NamedSurqlOp::ResetUlArtifactDirtyProject,
        ] {
            let template = op.template();
            assert!(template.contains("WHERE project_id = $project_id"));
            assert!(template.contains("BEGIN TRANSACTION;"));
            assert_eq!(op.access_class(), SurqlAccessClass::Write);
        }
        let cues = NamedSurqlOp::UpsertCueRows.template();
        assert!(cues.contains("IF $replace_project"));
        assert!(cues.contains("DELETE cue_index"));
        assert!(
            !NamedSurqlOp::SchemaMigrateUlArtifacts
                .template()
                .contains("DELETE cue_index")
        );
    }

    #[test]
    fn current_state_resolves_canonical_lifecycle_transitions_with_bounded_reads() {
        let template = NamedSurqlOp::CurrentState.template();

        assert!(template.contains("receipt_kind = 'state_transition'"));
        assert!(template.contains("receipt_body.to_state"));
        assert!(template.contains("LET $resolved = $claims.map"));
        assert!(template.contains("LIMIT 251"));
        assert!(template.contains("array::slice($weak, 0, 50)"));
        assert!(template.contains("lifecycle_state IN ['active', 'restored']"));
        assert!(template.contains("array::len($claims) > 250"));
    }

    #[test]
    fn canonical_queries_are_bounded_and_project_scoped() {
        for op in [
            NamedSurqlOp::CanonicalRecords,
            NamedSurqlOp::CanonicalRecordsBySubjectRef,
            NamedSurqlOp::SleepCandidates,
        ] {
            let template = op.template();
            assert!(template.contains("project_id = $project_id"));
            assert!(template.contains("$limit > 128"));
        }
        let readiness = NamedSurqlOp::LoadUlReadiness.template();
        assert_eq!(readiness.matches("project_id = $project_id").count(), 5);
        for table in [
            "co_change",
            "card_covers",
            "concept_implemented_by",
            "concept_depends_on",
            "capsule_covers",
        ] {
            assert!(readiness.contains(&format!("FROM {table}")));
        }
        assert!(!readiness.contains("type::table"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_capacity_is_parent_last_paged_and_segment_deduplicated() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        for marker in [
            "'memory_blob_segment'",
            "'cue_binding_page'",
            "'memory_blob_manifest'",
            "canonical_capacity_parent_before_complete_segments",
            "canonical_capacity_parent_before_complete_cue_pages",
            "canonical_capacity_immutable_record_conflict",
        ] {
            assert!(write.contains(marker), "missing capacity marker {marker}");
        }
        for exact_child_binding in [
            "receipt_body.logical_kind = $body.logical_kind",
            "receipt_body.segment_count = $body.segment_count",
            "receipt_body.segment_set_hash_blake3 = $body.segment_set_hash_blake3",
            "receipt_body.blob.algorithm = $body.blob.algorithm",
            "receipt_body.blob.digest_hex = $body.blob.digest_hex",
            "receipt_body.blob.size_bytes = $body.blob.size_bytes",
            "receipt_body.blob.relative_path = $body.blob.relative_path",
            "receipt_body.page_count = $body.cue_page_count",
            "receipt_body.page_set_hash_blake3 = $body.cue_page_set_hash_blake3",
        ] {
            assert!(
                write.contains(exact_child_binding),
                "parent admission omitted exact child binding {exact_child_binding}"
            );
        }
        let l2 = NamedSurqlOp::LoadCanonicalMemoryL2.template();
        for marker in [
            "project_id = $project_id",
            "requested_segment_record_id_parts",
            "type::record('canonical_record', $requested_segment_record_id)",
            "subject_ref = $requested_handle",
            "SELECT VALUE receipt_body_json_b64",
            "$requested_is_segment",
            "requested_segment_body_b64",
            "manifest_bodies_b64",
            "ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC",
            "START $start",
            "LIMIT $limit_plus_one",
            "$limit > 1",
            "canonical_l2_segment_body_not_lossless",
            "canonical_l2_manifest_body_not_lossless",
        ] {
            assert!(l2.contains(marker), "normal L2 loader omitted {marker}");
        }
        assert!(!l2.contains("receipt_body."));
        assert!(!l2.contains("search_text"));
        let admission = NamedSurqlOp::LoadCanonicalMemoryAdmissionChildren.template();
        for marker in [
            "$child_kind = 'segment'",
            "$child_kind != 'cue_page'",
            "project_id = $project_id",
            "subject_ref = <string> $memory_handle",
            "SELECT VALUE receipt_body_json_b64",
            "START $start",
            "LIMIT $limit_plus_one",
        ] {
            assert!(
                admission.contains(marker),
                "admission child loader omitted {marker}"
            );
        }
        for forbidden_prefilter in [
            "segment_set_hash_blake3 =",
            "page_set_hash_blake3 =",
            "blob.digest_hex =",
            "segment_count =",
            "page_count =",
            "receipt_body.parent_handle =",
        ] {
            assert!(
                !admission.contains(forbidden_prefilter),
                "admission loader must not hide mismatched children behind {forbidden_prefilter}"
            );
        }
        assert!(admission.contains("canonical_capacity_unknown_child_kind"));
        assert!(admission.contains("canonical_capacity_child_body_not_lossless"));
        assert!(admission.contains("ORDER BY record_id ASC"));
        assert!(!admission.contains("ORDER BY receipt_body"));
        assert!(admission.contains("$limit > 1"));
        assert!(!admission.contains(".filter(|$row| $row != NONE AND $row != NULL)"));
        let capacity_projection = NamedSurqlOp::LoadCanonicalMemoryProjectionSegments.template();
        assert!(capacity_projection.contains("receipt_kind = 'memory_blob_segment'"));
        assert!(capacity_projection.contains("receipt_body.blob.digest_hex = $blob_digest_hex"));
        assert!(
            capacity_projection
                .contains("receipt_body.segment_set_hash_blake3 = $segment_set_hash_blake3")
        );
        assert!(capacity_projection.contains("ORDER BY receipt_body.ordinal ASC"));
        assert!(capacity_projection.contains("START $start"));

        let rebuild = NamedSurqlOp::LoadRecallCandidates.template();
        assert!(rebuild.contains("receipt_kind = 'memory_blob_manifest'"));
        assert!(rebuild.contains("subject_ref = $parent.subject_ref"));
        assert!(rebuild.contains("source_segment_ordinal"));

        let projection = NamedSurqlOp::UpsertMemorySearchProjection.template();
        assert!(projection.contains("source_segment_ordinal"));
        assert!(projection.contains("fts_segment_ordinal"));
        assert!(projection.contains("source_segment_ordinal ?? 0"));
        let load = NamedSurqlOp::LoadMemorySearchFtsCandidates.template();
        assert!(load.contains("GROUP BY handle"));
        assert!(load.contains("$capped_handles.map"));
        assert!(load.contains("array::flatten($rows_nested)"));
    }

    #[test]
    fn ul_artifact_projection_selects_latest_logical_targets_before_pagination() {
        let template = NamedSurqlOp::LoadUlArtifacts.template();
        let latest = template.find("AND record_id = array::first");
        let pagination = template.find("START $bounded_start");
        assert!(latest.is_some(), "latest-per-target predicate");
        assert!(pagination.is_some(), "stable pagination");
        assert!(latest < pagination);
        assert!(template.contains("subject_ref = $parent.subject_ref"));
        assert!(template.contains("receipt_kind = $parent.receipt_kind"));
        assert!(
            template
                .contains("ORDER BY memory_revision DESC, project_sequence DESC, record_id DESC")
        );
        assert!(template.contains("$limit > 256"));
        assert!(!template.contains("$limit > 128"));
    }

    #[test]
    fn canonical_operator_page_has_stable_unbounded_continuation_order() {
        let template = NamedSurqlOp::CanonicalRecordPage.template();
        assert!(template.contains("project_id = $project_id"));
        assert!(
            template.contains("array::len($receipt_kinds) = 0"),
            "an empty kind filter must provide a project-wide canonical scan"
        );
        assert!(
            template.contains("memory_revision <= $at_revision"),
            "canonical scans must support a stable revision fence"
        );
        assert!(
            template.contains("ORDER BY memory_revision ASC, project_sequence ASC, record_id ASC")
        );
        assert!(template.contains("START $start"));
        assert!(template.contains("$limit > 100"));
        assert!(!template.contains("START 0"));
    }

    #[test]
    fn curation_page_is_task_revision_fenced_and_bounded() {
        let template = NamedSurqlOp::CurationRecordPage.template();
        assert!(template.contains("FROM claim_card"));
        assert!(template.contains("<string> project_id = <string> $project_id"));
        assert!(template.contains("<string> task_id = <string> $task_id"));
        assert!(template.contains("memory_revision <= $at_revision"));
        assert!(template.contains("subject_ref: string::concat('claim:'"));
        assert!(template.contains("lifecycle_transitions: SELECT VALUE receipt_body.to_state"));
        assert!(template.contains("$parent.claim_id"));
        assert!(
            template.contains("ORDER BY memory_revision ASC, project_sequence ASC, claim_id ASC")
        );
        assert!(template.contains("START $start"));
        assert!(template.contains("$limit > 100"));
    }

    #[test]
    fn canonical_authority_queries_are_exact_and_bounded() {
        let latest_entity = NamedSurqlOp::LatestAuthorityObservationsByEntity.template();
        assert!(latest_entity.contains("payload.work_lease.work_lease_id = $entity_ref"));
        assert!(latest_entity.contains("payload.worktree_lease.worktree_lease_id = $entity_ref"));
        assert!(latest_entity.contains("ORDER BY memory_revision DESC"));
        assert!(latest_entity.contains("LIMIT 2"));
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        for approval_kind in [
            "autonomy_approval_request",
            "autonomy_approval_decision",
            "autonomy_approval_consumption",
        ] {
            assert!(write.contains(approval_kind));
        }
        let by_write = NamedSurqlOp::CanonicalRecordByWriteId.template();
        assert!(by_write.contains("write_id = $write_id"));
        assert!(by_write.contains("LIMIT 2"));
        let by_subject = NamedSurqlOp::CanonicalRecordsBySubjectRef.template();
        assert!(by_subject.contains("subject_ref = <string> $subject_ref"));
        assert!(by_subject.contains("ORDER BY memory_revision DESC"));
        let terminal = NamedSurqlOp::MetaPolicyActionsByCandidate.template();
        assert!(terminal.contains("candidate_id = <string> $candidate_id"));
        assert!(terminal.contains("canonical_action = <string> $action"));
        assert!(terminal.contains("LIMIT 2"));
        let trace = NamedSurqlOp::CanonicalTraceByTraceRef.template();
        assert!(trace.contains("trace_ref = <string> $trace_ref"));
        assert!(trace.contains("receipt_body.trace_ref = <string> $trace_ref"));
        assert!(trace.contains("LIMIT 2"));
        let schema = NamedSurqlOp::SchemaMigrate.template();
        assert!(schema.contains("SET trace_ref = <string> receipt_body.trace_ref"));
        assert!(schema.contains("candidate_id = <string> receipt_body.candidate_id"));
        assert!(schema.contains("canonical_action = <string> receipt_body.action"));
        assert!(schema.contains("idx_canonical_project_task_trace"));
        assert!(schema.contains("idx_canonical_project_task_candidate_action"));
    }

    #[test]
    fn canonical_projection_preserves_opaque_json_and_exact_subject_filters() {
        let write = NamedSurqlOp::ApplyWriteEnvelope.template();
        let read = NamedSurqlOp::CanonicalRecords.template();

        assert!(write.contains("receipt_body_json_b64"));
        assert!(write.contains("trace_ref: $trace_ref"));
        assert!(write.contains("candidate_id: $candidate_id"));
        assert!(write.contains("canonical_action: $canonical_action"));
        assert!(write.contains("subject_ref_fragments"));
        assert!(write.contains("'operator_control_request'"));
        assert!(read.contains("receipt_body_json_b64"));
        assert!(read.contains("subject_ref = <string> $subject_ref_filter"));
        assert!(
            NamedSurqlOp::SleepCandidates
                .template()
                .contains("receipt_body_json_b64")
        );
    }

    #[test]
    fn sleep_candidates_are_backed_by_canonical_records() {
        let template = NamedSurqlOp::SleepCandidates.template();
        assert!(template.contains("FROM canonical_record"));
        assert!(!template.contains("candidates: []"));
        for kind in [
            "procedure_candidate",
            "forgetting_candidate",
            "test_candidate",
            "replay_case_candidate",
            "dream_candidate",
        ] {
            assert!(template.contains(kind));
        }
    }

    #[test]
    fn m2_integrity_records_are_canonical_write_kinds() {
        let template = NamedSurqlOp::ApplyWriteEnvelope.template();
        for kind in [
            "trace_completeness_contract",
            "replay_set",
            "replay_case",
            "replay_input_snapshot",
            "sealed_replay_run",
            "meta_metric_evidence",
            "meta_isolation_rejection",
            "experimental_policy_candidate",
            "meta_policy_promotion",
            "meta_policy_rollback",
            "procedure_candidate",
            "forgetting_candidate",
            "test_candidate",
            "replay_case_candidate",
            "dream_candidate",
        ] {
            assert!(template.contains(&format!("'{kind}'")));
        }
    }

    #[test]
    fn m3_invocation_request_is_exact_canonical_authority() {
        assert!(
            NamedSurqlOp::ApplyWriteEnvelope
                .template()
                .contains("'agent_invocation_request'")
        );
        let current = NamedSurqlOp::LatestAuthorityObservationsByEntity.template();
        assert!(current.contains("$entity_kind = 'agent_invocation_request'"));
        assert!(current.contains("payload.receipt_kind = 'agent_invocation_request'"));
    }

    #[test]
    fn exact_claim_lookup_is_project_scoped_and_unpaginated() {
        let template = NamedSurqlOp::ClaimCardById.template();

        assert!(template.contains("type::record('claim_card', $claim_id)"));
        assert!(template.contains("project_id = $project_id"));
        assert!(template.contains("LIMIT 1"));
    }
}
