//! Architecture `A2.3` (crate-rich/process-sparse facade split; this source child is not a new runtime service or process boundary).
//! Implementation `I1.2` (closed semantic-operation set, raw runtime `SurrealQL` excluded) and `I5.9` (parameterized named queries) under `I5.1`/`I5.3` store-bridge named-operation families.
//! Ownership: this child owns `NamedSurqlOp` and its `access_class`/`name`/`template` table with adjacent `surql/*.surql` resources; parent `surql.rs` remains facade/re-export and retains `SurqlAccessClass`/`SurqlTemplate` re-exports and embedded-resource tests; execution/credential/server lifecycle stays outside.

use super::SurqlAccessClass;

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
    MemoryGrantOfferById,
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
            | Self::MemoryGrantOfferById
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
            Self::MemoryGrantOfferById => "memory_grant_offer_by_id",
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
            Self::SchemaMigrate => include_str!("000_schema.surql"),
            Self::SchemaMigrateObservability => include_str!("001_observability.surql"),
            Self::SchemaMigrateUl => include_str!("002_ul_core.surql"),
            Self::SchemaMigrateUlDelivery => include_str!("003_ul_delivery.surql"),
            Self::SchemaMigrateUlArtifacts => include_str!("004_ul_artifacts.surql"),
            Self::SchemaMigrateUlPyramid => include_str!("005_ul_pyramid.surql"),
            Self::SchemaMigrateUlMeasurement => {
                include_str!("006_ul_measurement.surql")
            }
            Self::SchemaMigrateUlDependencyActivation => {
                include_str!("007_ul_dependency_activation.surql")
            }
            Self::SchemaMigrateUlTokenPolicy => include_str!("008_ul_token_policy.surql"),
            Self::SchemaMigrateMemorySearch => include_str!("009_memory_search.surql"),
            Self::SchemaMigrateMemorySearchFts => {
                include_str!("010_memory_search_fts.surql")
            }
            Self::AssignUlExperimentArm => include_str!("assign_ul_experiment_arm.surql"),
            Self::UpsertUlExperimentAssignmentExplicit => {
                include_str!("upsert_ul_experiment_assignment_explicit.surql")
            }
            Self::LoadUlExperimentAssignment => {
                include_str!("load_ul_experiment_assignment.surql")
            }
            Self::LoadUlTaskClassLedgers => include_str!("load_ul_task_class_ledgers.surql"),
            Self::UpsertUlTaskClassPolicy => {
                include_str!("upsert_ul_task_class_policy.surql")
            }
            Self::LoadUlTaskClassPolicy => include_str!("load_ul_task_class_policy.surql"),
            Self::ReplaceUlReverseDependencies => {
                include_str!("replace_ul_reverse_dependencies.surql")
            }
            Self::ResetUlReverseDependencyProject => {
                include_str!("reset_ul_reverse_dependency_project.surql")
            }
            Self::LoadUlReverseDependents => {
                include_str!("load_ul_reverse_dependents.surql")
            }
            Self::UpsertUlArtifactDirty => include_str!("upsert_ul_artifact_dirty.surql"),
            Self::LoadUlArtifactDirty => include_str!("load_ul_artifact_dirty.surql"),
            Self::ClearUlArtifactDirty => include_str!("clear_ul_artifact_dirty.surql"),
            Self::ResetUlArtifactDirtyProject => {
                include_str!("reset_ul_artifact_dirty_project.surql")
            }
            Self::LoadUlActivationGraph => include_str!("load_ul_activation_graph.surql"),
            Self::UpsertCueRows => include_str!("upsert_cue_rows.surql"),
            Self::DeleteCueRows => include_str!("delete_cues_for_record.surql"),
            Self::LoadCueRows => include_str!("load_cue_rows.surql"),
            Self::LoadCueRecords => include_str!("load_cue_records.surql"),
            Self::LoadInjectionReceipts => {
                include_str!("load_injection_receipts.surql")
            }
            Self::LoadUlArtifacts => include_str!("load_ul_artifacts.surql"),
            Self::UpsertUlTaskLedger => include_str!("upsert_ul_task_ledger.surql"),
            Self::LoadPredictions => include_str!("load_predictions.surql"),
            Self::LoadUlMetrics => include_str!("load_ul_metrics.surql"),
            Self::LoadUlReadiness => include_str!("load_ul_readiness.surql"),
            Self::ApplyWriteEnvelope => include_str!("apply_write_envelope.surql"),
            Self::ApplyObservability => include_str!("apply_observability.surql"),
            Self::ObservabilityReceiptById => {
                include_str!("observability_receipt_by_id.surql")
            }
            Self::ObservabilityRecordsByKind => {
                include_str!("observability_records_by_kind.surql")
            }
            Self::MemoryGrantOfferById => include_str!("memory_grant_offer_by_id.surql"),
            Self::CurrentState => include_str!("current_state.surql"),
            Self::LoadRecallCandidates => include_str!("load_recall_candidates.surql"),
            Self::UpsertMemorySearchProjection => {
                include_str!("upsert_memory_search_projection.surql")
            }
            Self::ResetMemorySearchProjection => {
                include_str!("reset_memory_search_projection.surql")
            }
            Self::LoadMemorySearchFtsCandidates => {
                include_str!("load_memory_search_fts_candidates.surql")
            }
            Self::ExplainMemorySearchFts => {
                include_str!("explain_memory_search_fts.surql")
            }
            Self::EnqueueCognitiveProjectionIntent => {
                include_str!("enqueue_cognitive_projection_intent.surql")
            }
            Self::ClaimCognitiveProjectionProject => {
                include_str!("claim_cognitive_projection_project.surql")
            }
            Self::CompleteCognitiveProjectionThrough => {
                include_str!("complete_cognitive_projection_through.surql")
            }
            Self::FailCognitiveProjectionRetryable => {
                include_str!("fail_cognitive_projection_retryable.surql")
            }
            Self::BlockCognitiveProjection => {
                include_str!("block_cognitive_projection.surql")
            }
            Self::LoadCognitiveProjectionBacklog => {
                include_str!("load_cognitive_projection_backlog.surql")
            }
            Self::LoadCognitiveProjectionProjects => {
                include_str!("load_cognitive_projection_projects.surql")
            }
            Self::PublishCognitiveProjectionFamilyState => {
                include_str!("publish_cognitive_projection_family_state.surql")
            }
            Self::LoadCognitiveProjectionFamilyStates => {
                include_str!("load_cognitive_projection_family_states.surql")
            }
            Self::CutoverLegacyMemorySearchPostings => {
                include_str!("cutover_legacy_memory_search_postings.surql")
            }
            Self::FetchAtomsL2 => include_str!("fetch_atoms_l2.surql"),
            Self::FetchAtomsL2Legacy => include_str!("fetch_atoms_l2_legacy.surql"),
            Self::GraphHealthCapabilities => {
                include_str!("graph_health_capabilities.surql")
            }
            Self::GraphHealth => include_str!("graph_health.surql"),
            Self::WriterReceipts => include_str!("writer_receipts.surql"),
            Self::WriteReceiptById => include_str!("write_receipt_by_id.surql"),
            Self::ToolObservationByWriteId => {
                include_str!("tool_observation_by_write_id.surql")
            }
            Self::LatestAuthorityObservationsByEntity => {
                include_str!("latest_authority_observations_by_entity.surql")
            }
            Self::TaskContractById => include_str!("task_contract_by_id.surql"),
            Self::ToolObservationById => include_str!("tool_observation_by_id.surql"),
            Self::ToolObservationsByKind => {
                include_str!("tool_observations_by_kind.surql")
            }
            Self::ExperiencePatternRevisionsById => {
                include_str!("experience_pattern_revisions_by_id.surql")
            }
            Self::SemanticRecordsByKind => {
                include_str!("semantic_records_by_kind.surql")
            }
            Self::ClaimCardById => include_str!("claim_card_by_id.surql"),
            Self::VerificationRunById => include_str!("verification_run_by_id.surql"),
            Self::CanonicalRecords => include_str!("canonical_records.surql"),
            Self::CanonicalRecordPage => include_str!("canonical_record_page.surql"),
            Self::CurationRecordPage => include_str!("curation_record_page.surql"),
            Self::CanonicalRecordByWriteId => {
                include_str!("canonical_record_by_write_id.surql")
            }
            Self::CanonicalRecordsBySubjectRef => {
                include_str!("canonical_records_by_subject_ref.surql")
            }
            Self::LoadCanonicalMemoryAdmissionChildren => {
                include_str!("load_canonical_memory_admission_children.surql")
            }
            Self::LoadCanonicalMemoryL2 => {
                include_str!("load_canonical_memory_l2.surql")
            }
            Self::LoadCanonicalMemoryProjectionSegments => {
                include_str!("load_canonical_memory_projection_segments.surql")
            }
            Self::CanonicalTraceByTraceRef => {
                include_str!("canonical_trace_by_trace_ref.surql")
            }
            Self::MetaPolicyActionsByCandidate => {
                include_str!("meta_policy_actions_by_candidate.surql")
            }
            Self::SleepCandidates => include_str!("sleep_candidates.surql"),
            Self::BlobReferenceScan => include_str!("blob_reference_scan.surql"),
        }
    }
}
