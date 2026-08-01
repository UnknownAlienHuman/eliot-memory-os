use std::collections::HashMap;

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
    AssignUlExperimentArm,
    LoadUlExperimentAssignment,
    LoadUlTaskClassLedgers,
    UpsertUlTaskClassPolicy,
    LoadUlTaskClassPolicy,
    ReplaceUlReverseDependencies,
    LoadUlReverseDependents,
    UpsertUlArtifactDirty,
    LoadUlArtifactDirty,
    ClearUlArtifactDirty,
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
    LoadMemorySearchCandidates,
    ExplainMemorySearchPostings,
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
    CanonicalTraceByTraceRef,
    MetaPolicyActionsByCandidate,
    SleepCandidates,
    BlobReferenceScan,
}

impl NamedSurqlOp {
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
            Self::AssignUlExperimentArm => "assign_ul_experiment_arm",
            Self::LoadUlExperimentAssignment => "load_ul_experiment_assignment",
            Self::LoadUlTaskClassLedgers => "load_ul_task_class_ledgers",
            Self::UpsertUlTaskClassPolicy => "upsert_ul_task_class_policy",
            Self::LoadUlTaskClassPolicy => "load_ul_task_class_policy",
            Self::ReplaceUlReverseDependencies => "replace_ul_reverse_dependencies",
            Self::LoadUlReverseDependents => "load_ul_reverse_dependents",
            Self::UpsertUlArtifactDirty => "upsert_ul_artifact_dirty",
            Self::LoadUlArtifactDirty => "load_ul_artifact_dirty",
            Self::ClearUlArtifactDirty => "clear_ul_artifact_dirty",
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
            Self::LoadMemorySearchCandidates => "load_memory_search_candidates",
            Self::ExplainMemorySearchPostings => "explain_memory_search_postings",
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
            Self::AssignUlExperimentArm => include_str!("surql/assign_ul_experiment_arm.surql"),
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
            Self::LoadUlReverseDependents => {
                include_str!("surql/load_ul_reverse_dependents.surql")
            }
            Self::UpsertUlArtifactDirty => include_str!("surql/upsert_ul_artifact_dirty.surql"),
            Self::LoadUlArtifactDirty => include_str!("surql/load_ul_artifact_dirty.surql"),
            Self::ClearUlArtifactDirty => include_str!("surql/clear_ul_artifact_dirty.surql"),
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
            Self::LoadMemorySearchCandidates => {
                include_str!("surql/load_memory_search_candidates.surql")
            }
            Self::ExplainMemorySearchPostings => {
                include_str!("surql/explain_memory_search_postings.surql")
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
fn foundational_templates() -> [SurqlTemplate; 47] {
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
            NamedSurqlOp::AssignUlExperimentArm,
            "AssignUlExperimentArmInput",
            "AssignUlExperimentArmOutput",
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
            NamedSurqlOp::LoadMemorySearchCandidates,
            "LoadMemorySearchCandidatesInput",
            "LoadMemorySearchCandidatesOutput",
            2 * 1024 * 1024,
        ),
        template(
            NamedSurqlOp::ExplainMemorySearchPostings,
            "ExplainMemorySearchPostingsInput",
            "ExplainMemorySearchPostingsOutput",
            128 * 1024,
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
fn canonical_templates() -> [SurqlTemplate; 17] {
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
mod tests {
    use super::NamedSurqlOp;

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
