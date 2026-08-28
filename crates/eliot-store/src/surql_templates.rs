//! Source-backed registry for the closed `SurrealDB` semantic-operation/named-query set and its
//! input/output schema and result-capacity metadata.
//!
//! I1.2 keeps semantic operations closed and excludes raw runtime `SurrealQL`; I1.8 binds
//! `NamedReadCapability` to the exact named query, scope, fence, and caps; and I5.9 requires
//! parameterized named queries.
//!
//! This module owns template metadata only. Raw runtime `SurrealQL` execution and server/credential
//! lifecycle remain outside this module.

use std::collections::HashMap;

use crate::surql::NamedSurqlOp;

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
fn foundational_templates() -> [SurqlTemplate; 62] {
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
            NamedSurqlOp::MemoryGrantOfferById,
            "MemoryGrantOfferByIdInput",
            "MemoryGrantOfferByIdOutput",
            64 * 1024,
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
mod tests {
    use super::SurqlTemplateRegistry;
    use crate::surql::{NamedSurqlOp, SurqlAccessClass};

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

        assert_eq!(registry.templates.len(), 83);
        assert_eq!(counts, [46, 21, 16]);
    }
}
