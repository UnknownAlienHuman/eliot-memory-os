use crate::writer::WriterHandle;
use crate::{CompletionGate, EngineError};
use eliot_bootstrap::{
    BootstrapBoundIdentity, BootstrapCompileError, BootstrapDraftImportReceipt,
    DraftIdentityVerdict,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_types::{
    ClaimCardInput, CommandContext, CompletionStatus, EpistemicStatus, EvidenceAtomInput,
    FailureFingerprintInput, FailureRecordCommand, IdempotencyOptions, LifecycleWriteOptions,
    MemoryWriteEnvelope, OperationId, RelationInput, RelationType, SemanticCommand,
    SourceSnapshotInput, TaskContractInput, TaskContractStatus, ToolObservationInput, UlArtifact,
    VerificationResult, VerificationRunInput, WriteRejectReason, WriteStatus, normalize_bindings,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

const MAX_COMMAND_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Default)]
pub struct WriteAdmissionService;

impl WriteAdmissionService {
    pub fn admit(&self, command: &SemanticCommand) -> Result<MemoryWriteEnvelope, EngineError> {
        self.admit_with_original_preimage(command)
            .map(|(envelope, _)| envelope)
    }

    /// Admits a command and also returns the exact bytes used by the existing
    /// `stable_input_hash` owner. Canonical source owners can retain these
    /// bytes beside their projection so readback can validate the original
    /// receipt hash instead of comparing two copies of that hash.
    pub fn admit_with_original_preimage(
        &self,
        command: &SemanticCommand,
    ) -> Result<(MemoryWriteEnvelope, Vec<u8>), EngineError> {
        let value = serde_json::to_value(command)?;
        let violations = eliot_types::ul::guard::inspect_text_encoding(&value);
        if !violations.is_empty() {
            return Err(EngineError::EncodingRejected { violations });
        }
        validate_command_shape(command)?;
        let (input_hash, input_preimage) = stable_input_hash_and_preimage(command)?;
        let context = command.context().clone();
        validate_context(&context.scope, &context.authority)?;
        let admitted = admit_command(command)?;

        Ok((
            MemoryWriteEnvelope {
                write_id: context.write_id,
                operation_id: OperationId::new_v7(),
                agent_id: context.agent_id,
                session_id: context.session_id,
                project_id: context.project_id,
                task_id: context.task_id,
                command_kind: command.kind(),
                input_hash,
                policy_snapshot_id: None,
                project_sequence_hint: None,
                created_at: OffsetDateTime::now_utc(),
                scope: context.scope,
                authority: context.authority,
                task_contracts: admitted.task_contracts,
                source_snapshots: admitted.source_snapshots,
                evidence_atoms: admitted.evidence_atoms,
                tool_observations: admitted.tool_observations,
                failures: admitted.failures,
                claims: admitted.claims,
                verification_runs: admitted.verification_runs,
                relations: admitted.relations,
                lifecycle: LifecycleWriteOptions {
                    status: context.lifecycle_status,
                    visibility: context.visibility,
                    taint: context.taint,
                },
                idempotency: IdempotencyOptions { allow_replay: true },
            },
            input_preimage,
        ))
    }
}

#[derive(Default)]
struct AdmittedCommand {
    task_contracts: Vec<TaskContractInput>,
    source_snapshots: Vec<SourceSnapshotInput>,
    evidence_atoms: Vec<EvidenceAtomInput>,
    tool_observations: Vec<ToolObservationInput>,
    failures: Vec<FailureFingerprintInput>,
    claims: Vec<ClaimCardInput>,
    verification_runs: Vec<VerificationRunInput>,
    relations: Vec<RelationInput>,
}

fn admit_command(command: &SemanticCommand) -> Result<AdmittedCommand, EngineError> {
    let mut admitted = AdmittedCommand::default();
    match command {
        SemanticCommand::TaskContractWrite(body) => {
            if body.context.task_id != Some(body.contract.task_id) {
                return reject("TaskContract context.task_id must match contract.task_id");
            }
            if body.contract.title.trim().is_empty() {
                return reject("TaskContract title is required");
            }
            if body.contract.acceptance_items.is_empty() {
                return reject("TaskContract requires acceptance items");
            }
            if body.contract.status == TaskContractStatus::DoneVerified {
                let proof = body.contract.completion_proof.as_ref().ok_or_else(|| {
                    EngineError::WriteRejected(
                        "DONE_VERIFIED TaskContract requires CompletionProof".to_owned(),
                    )
                })?;
                if proof.project_id != body.context.project_id
                    || proof.task_id != body.contract.task_id.to_string()
                {
                    return reject("CompletionProof scope must match TaskContract");
                }
                if body.contract.completion_write_id != Some(body.context.write_id) {
                    return reject(
                        "DONE_VERIFIED TaskContract completion_write_id must match write context",
                    );
                }
                let decision = CompletionGate::decide(proof);
                if decision.final_status != CompletionStatus::DoneVerified {
                    return reject("CompletionGate rejected TaskContract DONE_VERIFIED");
                }
            }
            admitted.task_contracts.push(body.contract.clone());
            if let Some(observation) = &body.observation {
                admitted.tool_observations.push(observation.clone());
            }
            if let Some(verification) = &body.verification {
                if verification.result == VerificationResult::Passed
                    && body.context.taint != eliot_types::TaintClass::LocalVerified
                {
                    return reject("passed verification requires LocalVerified authority");
                }
                admitted.verification_runs.push(verification.clone());
            }
        }
        SemanticCommand::EvidenceIngest(body) => {
            admitted.source_snapshots.push(body.source.clone());
            admitted.evidence_atoms.push(body.evidence.clone());
        }
        SemanticCommand::ToolObservationRecord(body) => {
            admitted.tool_observations.push(ToolObservationInput {
                observation_id: body.context.write_id.to_string(),
                tool_name: body.tool_name.clone(),
                observation: body.observation.clone(),
                payload: body.payload.clone(),
            });
        }
        SemanticCommand::ClaimPropose(body) => admit_claim_propose(&mut admitted, body)?,
        SemanticCommand::ClaimSupport(body) => admit_claim_support(&mut admitted, body),
        SemanticCommand::ClaimVerify(body) => admit_claim_verify(&mut admitted, body)?,
        SemanticCommand::FailureRecord(body) => admitted.failures.push(FailureFingerprintInput {
            fingerprint: body.fingerprint.clone(),
            summary: body.summary.clone(),
            payload: body.payload.clone(),
        }),
        SemanticCommand::VerificationRecord(body) => {
            admitted.verification_runs.push(body.verification.clone());
        }
        SemanticCommand::AgentResultRecord(body) => admit_agent_result(&mut admitted, body)?,
        SemanticCommand::UlArtifactBatchRecord(body) => {
            admit_ul_artifact_batch_record(&mut admitted, body)?;
        }
        SemanticCommand::DiagnosticBatchRecord(_)
        | SemanticCommand::ActiveDecisionTransition(_)
        | SemanticCommand::ProbeRecord(_)
        | SemanticCommand::CompletionProofSubmit(_) => {
            return Err(EngineError::WriteRejected(format!(
                "{:?}",
                WriteRejectReason::NotImplemented
            )));
        }
    }
    Ok(admitted)
}

fn admit_ul_artifact_batch_record(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::UlArtifactBatchRecordCommand,
) -> Result<(), EngineError> {
    if body.context.authority != "local-ul-builder" {
        return reject("UL artifacts require local-ul-builder authority");
    }
    if !matches!(
        body.context.taint,
        eliot_types::TaintClass::LocalTool | eliot_types::TaintClass::LocalVerified
    ) {
        return reject("UL artifacts require LocalTool or LocalVerified taint");
    }
    if body.artifacts.is_empty() || body.artifacts.len() > 50 {
        return reject("UL artifact batches must contain 1..=50 artifacts");
    }

    let mut artifact_ids = BTreeSet::new();
    let mut expected_relations = Vec::new();
    for artifact in &body.artifacts {
        let artifact_id = artifact.artifact_id().trim();
        if artifact_id.is_empty() || !artifact_ids.insert(artifact_id.to_owned()) {
            return reject("UL artifact ids must be non-empty and unique inside the batch");
        }
        if artifact.project_id() != body.context.project_id {
            return reject("UL artifact project_id must match command context");
        }
        expected_relations.extend(ul_artifact_relations(artifact)?);
    }

    let mut supplied_relations = BTreeSet::new();
    for relation in &body.relations {
        if relation.from.trim().is_empty() || relation.to.trim().is_empty() {
            return reject("UL artifact relation endpoints must be non-empty");
        }
        if !matches!(
            relation.relation_type,
            RelationType::CoChange
                | RelationType::ConceptImplementedBy
                | RelationType::ConceptDependsOn
                | RelationType::CapsuleCovers
                | RelationType::CardCovers
        ) {
            return reject("relation type is not allowed for UL artifacts");
        }
        if !supplied_relations.insert((
            relation_type_name(relation.relation_type),
            relation.from.clone(),
            relation.to.clone(),
        )) {
            return reject("UL artifact relations must be unique inside the batch");
        }
    }
    if expected_relations.iter().any(|(relation_type, from, to)| {
        body.relations
            .iter()
            .filter(|relation| {
                relation.relation_type == *relation_type
                    && relation.from == *from
                    && relation.to == *to
            })
            .count()
            != 1
    }) || body.relations.iter().any(|relation| {
        relation.relation_type != RelationType::ConceptDependsOn
            && !expected_relations.iter().any(|(relation_type, from, to)| {
                relation.relation_type == *relation_type
                    && relation.from == *from
                    && relation.to == *to
            })
    }) {
        return reject("UL artifact relations do not exactly match their artifact bodies");
    }

    validate_pyramid_build_pairs(&body.artifacts)?;

    for artifact in &body.artifacts {
        admitted.tool_observations.push(ToolObservationInput {
            observation_id: artifact.artifact_id().to_owned(),
            tool_name: "ul_artifact_writer_actor".to_owned(),
            observation: format!("recorded {} artifact", artifact.receipt_kind()),
            payload: json!({
                "receipt_kind": artifact.receipt_kind(),
                "receipt_body": ul_artifact_body(artifact)?,
                "writer_path": "ul_artifact_writer_actor",
            }),
        });
    }
    admitted.relations.extend(body.relations.clone());
    Ok(())
}

fn ul_artifact_relations(
    artifact: &UlArtifact,
) -> Result<Vec<(RelationType, String, String)>, EngineError> {
    match artifact {
        UlArtifact::CoChangeEdge(edge) => {
            if edge.path_a.trim().is_empty()
                || edge.path_b.trim().is_empty()
                || edge.path_a >= edge.path_b
            {
                return reject("co-change paths must be non-empty and lexicographically ordered");
            }
            Ok(vec![(
                RelationType::CoChange,
                format!("file:{}", edge.path_a),
                format!("file:{}", edge.path_b),
            )])
        }
        UlArtifact::ModuleCard(card) => {
            validate_normalized_cue_bindings(&card.cue_bindings)?;
            Ok(vec![(
                RelationType::CardCovers,
                format!("card:{}", card.card_id),
                format!("file:{}", card.path),
            )])
        }
        UlArtifact::ConceptNode(concept) => {
            validate_normalized_cue_bindings(&concept.cue_bindings)?;
            if concept.name.trim().is_empty()
                || concept.purpose.trim().is_empty()
                || concept.boundary_paths.is_empty()
            {
                return reject("concept name, purpose, and boundaries are required");
            }
            Ok(concept
                .boundary_paths
                .iter()
                .map(|path| {
                    (
                        RelationType::ConceptImplementedBy,
                        format!("concept:{}", concept.concept_id),
                        format!("file:{path}"),
                    )
                })
                .collect())
        }
        UlArtifact::ProjectCharter(charter) => {
            validate_normalized_cue_bindings(&charter.cue_bindings)?;
            validate_pyramid_body(
                &charter.body_md,
                &[
                    "WHAT",
                    "FOR WHOM",
                    "TOP INVARIANTS",
                    "NON-GOALS",
                    "VOCABULARY",
                ],
            )?;
            Ok(Vec::new())
        }
        UlArtifact::SystemMap(map) => {
            validate_normalized_cue_bindings(&map.cue_bindings)?;
            validate_pyramid_body(&map.body_md, &["SYSTEMS", "FLOWS"])?;
            Ok(Vec::new())
        }
        UlArtifact::SubsystemCapsule(capsule) => {
            validate_normalized_cue_bindings(&capsule.cue_bindings)?;
            validate_pyramid_body(
                &capsule.body_md,
                &[
                    "PURPOSE",
                    "BOUNDARIES",
                    "KEY ENTRYPOINTS",
                    "INVARIANTS",
                    "DRAGONS",
                    "KEY DECISIONS",
                    "VERIFIERS",
                ],
            )?;
            Ok(vec![(
                RelationType::CapsuleCovers,
                format!("capsule:{}", capsule.capsule_id),
                format!("concept:{}", capsule.concept_id),
            )])
        }
        UlArtifact::CapsuleBuild(build) => {
            if build.status != eliot_types::PyramidBuildStatus::Promoted
                || build.inputs_hash.len() != 64
                || build.token_estimate > build.budget_limit
            {
                return reject("only validated promoted pyramid builds may be written");
            }
            Ok(Vec::new())
        }
        UlArtifact::MiningRun(_) | UlArtifact::HotspotScore(_) => Ok(Vec::new()),
    }
}

fn validate_pyramid_build_pairs(artifacts: &[UlArtifact]) -> Result<(), EngineError> {
    for artifact in artifacts {
        let UlArtifact::CapsuleBuild(build) = artifact else {
            continue;
        };
        let matches_target = artifacts.iter().any(|candidate| match candidate {
            UlArtifact::SubsystemCapsule(value) => {
                build.target_kind == eliot_types::PyramidTargetKind::SubsystemCapsule
                    && value.capsule_id == build.target_id
                    && value.build_id == build.build_id
            }
            UlArtifact::SystemMap(value) => {
                build.target_kind == eliot_types::PyramidTargetKind::SystemMap
                    && value.map_id == build.target_id
                    && value.build_id == build.build_id
            }
            UlArtifact::ProjectCharter(value) => {
                build.target_kind == eliot_types::PyramidTargetKind::ProjectCharter
                    && value.charter_id == build.target_id
                    && value.build_id == build.build_id
            }
            _ => false,
        });
        if !matches_target {
            return reject("promoted pyramid build must share a batch with its exact target");
        }
    }
    Ok(())
}

fn validate_pyramid_body(body: &str, headers: &[&str]) -> Result<(), EngineError> {
    let mut last = None;
    for header in headers {
        if body.lines().filter(|line| line.trim() == *header).count() != 1 {
            return reject("pyramid body must contain each required header exactly once");
        }
        let position = body.find(header).ok_or_else(|| {
            EngineError::WriteRejected("required pyramid header missing".to_owned())
        })?;
        if last.is_some_and(|previous| position <= previous) {
            return reject("pyramid body headers are out of order");
        }
        last = Some(position);
    }
    Ok(())
}

fn validate_normalized_cue_bindings(
    bindings: &[eliot_types::CueBinding],
) -> Result<(), EngineError> {
    let normalized = normalize_bindings(bindings.to_vec(), None)
        .map_err(|error| EngineError::WriteRejected(format!("invalid cue binding: {error}")))?;
    if normalized != bindings {
        return reject("UL artifact cue bindings must already be normalized");
    }
    Ok(())
}

fn ul_artifact_body(artifact: &UlArtifact) -> Result<Value, EngineError> {
    let value = match artifact {
        UlArtifact::MiningRun(value) => serde_json::to_value(value)?,
        UlArtifact::HotspotScore(value) => serde_json::to_value(value)?,
        UlArtifact::CoChangeEdge(value) => serde_json::to_value(value)?,
        UlArtifact::ModuleCard(value) => serde_json::to_value(value)?,
        UlArtifact::ConceptNode(value) => serde_json::to_value(value)?,
        UlArtifact::ProjectCharter(value) => serde_json::to_value(value)?,
        UlArtifact::SystemMap(value) => serde_json::to_value(value)?,
        UlArtifact::SubsystemCapsule(value) => serde_json::to_value(value)?,
        UlArtifact::CapsuleBuild(value) => serde_json::to_value(value)?,
    };
    Ok(value)
}

const fn relation_type_name(relation_type: RelationType) -> &'static str {
    match relation_type {
        RelationType::Supports => "supports",
        RelationType::VerifiedBy => "verified_by",
        RelationType::Contradicts => "contradicts",
        RelationType::Supersedes => "supersedes",
        RelationType::Mentions => "mentions",
        RelationType::BelongsTo => "belongs_to",
        RelationType::Produces => "produces",
        RelationType::InvalidatedBy => "invalidated_by",
        RelationType::CoChange => "co_change",
        RelationType::ConceptImplementedBy => "concept_implemented_by",
        RelationType::ConceptDependsOn => "concept_depends_on",
        RelationType::CapsuleCovers => "capsule_covers",
        RelationType::CardCovers => "card_covers",
    }
}

fn admit_agent_result(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::AgentResultRecordCommand,
) -> Result<(), EngineError> {
    let context = &body.context;
    let lineage = &body.lineage;
    if context.task_id != Some(lineage.task_id) {
        return reject("AgentResultRecord context.task_id must match lineage.task_id");
    }
    if context.session_id != Some(lineage.child_session_id) {
        return reject("AgentResultRecord session must match the child handoff session");
    }
    if context.authority != "daemon-finish-gate"
        || context.taint != eliot_types::TaintClass::LocalVerified
        || context.scope != format!("task:{}", lineage.task_id)
    {
        return reject("AgentResultRecord requires daemon-derived verified authority");
    }
    if lineage.controller_receipt_id.as_uuid() != context.write_id.as_uuid() {
        return reject("AgentResultRecord receipt must be bound to its write_id");
    }
    if lineage.base_commit.trim().is_empty()
        || lineage.resulting_controller_commit.trim().is_empty()
        || lineage.base_commit == lineage.resulting_controller_commit
        || lineage.branch.trim().is_empty()
        || lineage.candidate_artifact_or_diff_ref.trim().is_empty()
        || lineage.accepted_write_set.is_empty()
        || lineage.verification_ids.is_empty()
        || lineage.verification_ids.len() != lineage.verification_receipt_ids.len()
        || lineage.canonical_artifact_refs.is_empty()
        || lineage.canonical_artifact_refs.len() != lineage.accepted_write_set.len()
        || lineage.provenance_set_hash.trim().is_empty()
    {
        return reject("AgentResultRecord requires exact controller handoff lineage");
    }
    if lineage
        .canonical_artifact_refs
        .iter()
        .any(|artifact| !lineage.accepted_write_set.contains(&artifact.resource_ref))
        || lineage
            .verification_ids
            .iter()
            .zip(&lineage.verification_receipt_ids)
            .any(|(verification_id, receipt_id)| verification_id.as_uuid() != receipt_id.as_uuid())
        || lineage.candidate_artifact_or_diff_ref
            != format!(
                "git-diff:{}..{}",
                lineage.base_commit, lineage.resulting_controller_commit
            )
    {
        return reject("AgentResultRecord lineage does not match canonical artifact receipts");
    }

    admitted.tool_observations.push(ToolObservationInput {
        observation_id: context.write_id.to_string(),
        tool_name: "eliot_submit_completion_proof".to_owned(),
        observation: "daemon-derived controller commit handoff".to_owned(),
        payload: json!({
            "lineage": lineage,
            "memory": &body.memory,
        }),
    });

    if let eliot_types::CompletionMemoryAdmission::SaveDecision { decision } = &body.memory {
        if decision.claim.statement.trim().is_empty()
            || decision.claim.status != EpistemicStatus::Verified
            || decision.evidence.source_id != decision.source.source_id
            || decision.where_applicable.is_empty()
            || decision.where_not_applicable.is_empty()
            || decision.freshness_rule.trim().is_empty()
        {
            return reject("saved completion memory is not a bounded verified decision");
        }
        admitted.source_snapshots.push(decision.source.clone());
        admitted.evidence_atoms.push(decision.evidence.clone());
        admitted.claims.push(decision.claim.clone());
        admitted.relations.push(RelationInput {
            relation_type: RelationType::Supports,
            from: decision.claim.claim_id.to_string(),
            to: decision.evidence.evidence_id.to_string(),
        });
        for verification_id in &lineage.verification_ids {
            admitted.relations.push(RelationInput {
                relation_type: RelationType::VerifiedBy,
                from: decision.claim.claim_id.to_string(),
                to: verification_id.to_string(),
            });
        }
        admitted.relations.push(RelationInput {
            relation_type: RelationType::BelongsTo,
            from: decision.claim.claim_id.to_string(),
            to: lineage.task_id.to_string(),
        });
    }
    Ok(())
}

fn admit_claim_propose(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::ClaimProposeCommand,
) -> Result<(), EngineError> {
    if body.claim.status != EpistemicStatus::Candidate {
        return reject("ClaimPropose must use candidate status");
    }
    admitted.claims.push(body.claim.clone());
    if let Some(task_id) = body.context.task_id {
        admitted.relations.push(RelationInput {
            relation_type: RelationType::BelongsTo,
            from: body.claim.claim_id.to_string(),
            to: task_id.to_string(),
        });
    }
    Ok(())
}

fn admit_claim_support(admitted: &mut AdmittedCommand, body: &eliot_types::ClaimSupportCommand) {
    admitted.relations.push(RelationInput {
        relation_type: RelationType::Supports,
        from: body.claim_id.to_string(),
        to: body.evidence_id.to_string(),
    });
    if let Some(statement) = &body.statement {
        admitted.claims.push(ClaimCardInput {
            claim_id: body.claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Supported,
            payload: body.payload.clone(),
        });
    }
}

fn admit_claim_verify(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::ClaimVerifyCommand,
) -> Result<(), EngineError> {
    if body.verification.result != VerificationResult::Passed {
        return reject("ClaimVerify requires a passed verification run");
    }
    admitted.relations.push(RelationInput {
        relation_type: RelationType::VerifiedBy,
        from: body.claim_id.to_string(),
        to: body.verification.verification_id.to_string(),
    });
    admitted.verification_runs.push(body.verification.clone());
    if let Some(statement) = &body.statement {
        admitted.claims.push(ClaimCardInput {
            claim_id: body.claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Verified,
            payload: body.payload.clone(),
        });
    }
    Ok(())
}

fn validate_context(scope: &str, authority: &str) -> Result<(), EngineError> {
    if scope.trim().is_empty() || authority.trim().is_empty() {
        return reject("scope and authority are required");
    }
    Ok(())
}

fn validate_command_shape(command: &SemanticCommand) -> Result<(), EngineError> {
    let bytes = serde_json::to_vec(command)?;
    if bytes.len() > MAX_COMMAND_BYTES {
        return reject("semantic command payload is too large");
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if contains_forbidden_db_surface(&value) {
        return reject("semantic command contains forbidden DB surface");
    }
    Ok(())
}

fn contains_forbidden_db_surface(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "sql" | "surql" | "query" | "endpoint" | "credential" | "credentials" | "password"
            ) || contains_forbidden_db_surface(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_db_surface),
        _ => false,
    }
}

fn stable_input_hash<T>(value: &T) -> Result<String, EngineError>
where
    T: Serialize,
{
    stable_input_hash_and_preimage(value).map(|(hash, _)| hash)
}

fn stable_input_hash_and_preimage<T>(value: &T) -> Result<(String, Vec<u8>), EngineError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    Ok((hash, bytes))
}

fn reject<T>(reason: &str) -> Result<T, EngineError> {
    Err(EngineError::WriteRejected(reason.to_owned()))
}

/// Canonical-import outcome for one published candidate-only bootstrap draft
/// (issue #1854 W2).
///
/// The immutable draft stays `CANDIDATE_ONLY`; this value binds the exact
/// draft content digest to the admitted canonical envelope. A governed import
/// trigger turns the envelope identifiers into an explicit import receipt; a
/// rejection never reaches this path because it performs no canonical write.
#[derive(Clone, Debug)]
pub struct BootstrapDraftImport {
    /// Content digest of the reconciled immutable candidate draft.
    pub draft_digest: String,
    /// Canonical envelope admitted for the draft finding.
    pub envelope: MemoryWriteEnvelope,
}

impl WriteAdmissionService {
    /// Admits one published candidate-only bootstrap draft into canonical memory.
    ///
    /// `draft` is the published draft JSON value. The adapter fails closed
    /// unless the draft carries a `CANDIDATE_ONLY` disposition and a content
    /// digest that recomputes over its own bytes; the admitted `FailureRecord`
    /// fingerprints that exact digest and preserves the finding fields
    /// (source/runtime identity, owning functional cell, observed behavior,
    /// discriminator, affected path, claim status) in its payload.
    /// `context` is supplied by the governed importing owner and is never
    /// invented here.
    pub fn admit_bootstrap_draft(
        &self,
        draft: &Value,
        context: CommandContext,
    ) -> Result<BootstrapDraftImport, EngineError> {
        let material = bootstrap_draft_import_material(draft)?;
        let envelope = self.admit(&SemanticCommand::FailureRecord(FailureRecordCommand {
            context,
            fingerprint: material.fingerprint,
            summary: material.summary,
            payload: material.payload,
        }))?;
        Ok(BootstrapDraftImport {
            draft_digest: material.draft_digest,
            envelope,
        })
    }
}

struct BootstrapDraftImportMaterial {
    draft_digest: String,
    fingerprint: String,
    summary: String,
    payload: Value,
}

fn bootstrap_draft_import_material(
    draft: &Value,
) -> Result<BootstrapDraftImportMaterial, EngineError> {
    let object = draft.as_object().ok_or_else(|| {
        EngineError::WriteRejected("bootstrap draft must be a JSON object".to_owned())
    })?;
    let disposition = object
        .get("import_disposition")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::WriteRejected(
                "bootstrap draft import_disposition must be a string".to_owned(),
            )
        })?;
    if disposition != "CANDIDATE_ONLY" {
        return reject("bootstrap draft import requires a CANDIDATE_ONLY disposition");
    }
    let draft_digest = object
        .get("canonical_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::WriteRejected(
                "bootstrap draft canonical_digest must be a string".to_owned(),
            )
        })?;
    reject_unless_hex_digest(draft_digest, "bootstrap draft canonical_digest")?;
    let mut unsigned = draft.clone();
    let unsigned_object = unsigned.as_object_mut().ok_or_else(|| {
        EngineError::WriteRejected("bootstrap draft must be a JSON object".to_owned())
    })?;
    unsigned_object.insert("canonical_digest".to_owned(), Value::String(String::new()));
    let bytes = canonical_json_bytes(&unsigned)?;
    if sha256_hex(&bytes) != draft_digest {
        return reject("bootstrap draft content digest does not match canonical_digest");
    }
    let finding = object
        .get("finding")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            EngineError::WriteRejected("bootstrap draft finding must be an object".to_owned())
        })?;
    let cell = draft_member_text(finding, "owning_functional_cell")?;
    let behavior = draft_member_text(finding, "observed_behavior")?;
    let discriminator = draft_member_text(finding, "discriminator")?;
    let affected_path = draft_member_text(finding, "affected_path")?;
    let claim_status = draft_member_text(finding, "claim_status")?;
    let runtime = finding
        .get("runtime_identity")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            EngineError::WriteRejected(
                "bootstrap draft runtime_identity must be an object".to_owned(),
            )
        })?;
    let runtime_key = draft_member_text(runtime, "key")?;
    let runtime_value = draft_member_text(runtime, "value")?;
    let runtime_ref = draft_member_text(runtime, "evidence_ref")?;
    let runtime_evaluation = draft_member_text(runtime, "evaluation")?;
    let source_identity = draft_member_text(object, "source_identity")?;
    let work_unit_id = draft_member_text(object, "work_unit_id")?;
    Ok(BootstrapDraftImportMaterial {
        draft_digest: draft_digest.to_owned(),
        fingerprint: draft_digest.to_owned(),
        summary: format!("bootstrap draft {draft_digest} [{cell}] {behavior}"),
        payload: json!({
            "bootstrap_draft": draft_digest,
            "source_identity": source_identity,
            "work_unit_id": work_unit_id,
            "finding": {
                "owning_functional_cell": cell,
                "observed_behavior": behavior,
                "discriminator": discriminator,
                "affected_path": affected_path,
                "claim_status": claim_status,
                "runtime_identity": {
                    "key": runtime_key,
                    "value": runtime_value,
                    "evidence_ref": runtime_ref,
                    "evaluation": runtime_evaluation,
                },
            },
        }),
    })
}

fn draft_member_text(
    object: &serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<String, EngineError> {
    let value = object.get(field).and_then(Value::as_str).ok_or_else(|| {
        EngineError::WriteRejected(format!("bootstrap draft member {field} must be a string"))
    })?;
    if value.trim().is_empty() {
        return Err(EngineError::WriteRejected(format!(
            "bootstrap draft member {field} must be non-blank"
        )));
    }
    Ok(value.to_owned())
}

fn reject_unless_hex_digest(value: &str, field: &str) -> Result<(), EngineError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(EngineError::WriteRejected(format!(
            "{field} must be a lowercase 64-character hex digest"
        )));
    }
    Ok(())
}

/// Governed canonical-import trigger for bootstrap drafts (issue #1854 W2/A2).
///
/// The immutable candidate draft is never mutated or auto-promoted: `import`
/// revalidates its bound identity against the current product identity, admits
/// it through `WriteAdmissionService::admit_bootstrap_draft`, submits the
/// envelope through the canonical writer, and persists the resulting explicit
/// import receipt durably. `reject_draft` records an explicit rejection
/// receipt without any canonical write. Both outcomes are content-addressed,
/// create-new receipts; filename presence alone still promotes nothing.
pub struct BootstrapDraftImportService;

impl BootstrapDraftImportService {
    /// Imports one published candidate-only bootstrap draft into canonical memory.
    ///
    /// `draft` is the published draft JSON value; `current` is the current
    /// product identity freshly captured by the governed caller and is never
    /// invented here; `context` supplies the write identity, scope, and
    /// authority for the admitting write; `receipt_root` is the caller-owned
    /// absolute directory receiving the durable receipt. The import fails
    /// closed when the bound identity no longer matches `current`, when
    /// admission rejects the draft, or when the canonical write does not
    /// commit: no imported receipt is produced unless the write holds.
    pub async fn import(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        draft: &Value,
        current: &BootstrapBoundIdentity,
        context: CommandContext,
        receipt_root: &Path,
    ) -> Result<BootstrapDraftImportReceipt, EngineError> {
        let bound = BootstrapBoundIdentity::from_draft(draft)
            .map_err(|error| bootstrap_rejected(&error))?;
        if bound
            .revalidate_against(current)
            .map_err(|error| bootstrap_rejected(&error))?
            != DraftIdentityVerdict::Current
        {
            return reject(
                "bootstrap draft bound identity no longer matches the current product identity; revalidate before import",
            );
        }
        let import = admission.admit_bootstrap_draft(draft, context)?;
        let input_hash = import.envelope.input_hash.clone();
        let receipt = writer.submit(import.envelope).await?;
        if !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        ) {
            return Err(EngineError::WriteRejected(format!(
                "canonical write {} did not commit: status={:?} reason={:?}",
                receipt.write_id, receipt.status, receipt.rejected_reason
            )));
        }
        let import_receipt = BootstrapDraftImportReceipt::imported(
            &import.draft_digest,
            &input_hash,
            &receipt.write_id.to_string(),
        )
        .map_err(|error| bootstrap_rejected(&error))?;
        persist_bootstrap_import_receipt(receipt_root, &import_receipt)?;
        Ok(import_receipt)
    }

    /// Records the explicit rejection of one published candidate-only draft.
    ///
    /// Rejection performs no canonical write, so no writer, identity, or
    /// context is required; the draft shape is still validated and the
    /// resulting rejection receipt is persisted durably under `receipt_root`.
    pub fn reject_draft(
        draft: &Value,
        reason: &str,
        receipt_root: &Path,
    ) -> Result<BootstrapDraftImportReceipt, EngineError> {
        let material = bootstrap_draft_import_material(draft)?;
        let receipt = BootstrapDraftImportReceipt::rejected(&material.draft_digest, reason)
            .map_err(|error| bootstrap_rejected(&error))?;
        persist_bootstrap_import_receipt(receipt_root, &receipt)?;
        Ok(receipt)
    }
}

fn bootstrap_rejected(error: &BootstrapCompileError) -> EngineError {
    EngineError::WriteRejected(error.to_string())
}

static RECEIPT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn persist_bootstrap_import_receipt(
    receipt_root: &Path,
    receipt: &BootstrapDraftImportReceipt,
) -> Result<PathBuf, EngineError> {
    if !receipt_root.is_absolute() {
        return reject("bootstrap import receipt root must be absolute");
    }
    receipt
        .validate()
        .map_err(|error| bootstrap_rejected(&error))?;
    let digest = receipt.receipt_digest.clone();
    let value = serde_json::to_value(receipt)?;
    let mut bytes = canonical_json_bytes(&value)?;
    bytes.push(b'\n');
    fs::create_dir_all(receipt_root)?;
    let destination = receipt_root.join(format!("{digest}.json"));
    if destination.exists() {
        let existing = fs::read(&destination)?;
        verify_persisted_receipt_bytes(&existing, &bytes, &digest)?;
        return Ok(destination);
    }
    let temporary = receipt_root.join(format!(
        ".{digest}.{}.{}.tmp",
        std::process::id(),
        RECEIPT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let write_result = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(EngineError::from(error));
    }
    // A hard-link publishes the already-synced bytes without replacing an
    // existing destination on either Windows or Unix. `rename` is not a
    // no-clobber primitive on Unix.
    if let Err(error) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        if error.kind() == io::ErrorKind::AlreadyExists {
            let existing = fs::read(&destination)?;
            verify_persisted_receipt_bytes(&existing, &bytes, &digest)?;
            return Ok(destination);
        }
        return Err(EngineError::from(error));
    }
    fs::remove_file(&temporary)?;
    let readback = fs::read(&destination)?;
    verify_persisted_receipt_bytes(&readback, &bytes, &digest)?;
    Ok(destination)
}

fn verify_persisted_receipt_bytes(
    actual: &[u8],
    expected: &[u8],
    digest: &str,
) -> Result<(), EngineError> {
    if actual != expected {
        return Err(EngineError::WriteRejected(format!(
            "existing bootstrap import receipt {digest} differs from canonical bytes"
        )));
    }
    let parsed: Value = serde_json::from_slice(actual)?;
    let embedded = parsed
        .get("receipt_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::WriteRejected("persisted import receipt digest is missing".to_owned())
        })?;
    if embedded != digest {
        return reject("persisted import receipt digest does not match its filename");
    }
    let mut unsigned = parsed.clone();
    unsigned["receipt_digest"] = Value::String(String::new());
    if sha256_hex(&canonical_json_bytes(&unsigned)?) != digest {
        return reject("persisted import receipt content digest is invalid");
    }
    Ok(())
}
