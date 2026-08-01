use crate::project_understanding::ProjectUnderstandingCompiler;
use crate::task_execution::TaskExecutionClassifier;
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
    CandidateDiffStatus, CandidateReviewDecision, ClaimCard, CodeCortexPacketView,
    CodeCortexReport, CognitiveGateDecision, CognitiveGateOutcome, CognitiveGateReason,
    CognitiveGateRequest, CompilePacketL3Request, CompletionGateDecision, CompletionProof,
    CompletionStatus, ContextPacketL3, CurrentStateRequest, CurrentStateResponse,
    CurrentTruthSnapshot, DecisionLocalitySuffix, EpistemicPacketState, EpistemicStatus,
    FetchAtomsL2Request, FetchAtomsL2Response, MaterialPacketFrame, MemoryAdmissionDecision,
    MemoryDecisionReceipt, MemoryLifecyclePacketView, MemoryRevision, PacketQualityReport,
    PacketQualityResult, ProjectId, ReadConsistencyMode, RecallL0Request, RecallL0Response,
    SkillCardV2, TaskId, TokenBudgetReport, TruncationInfo, UnderstandingProof,
    UnderstandingProofReceipt, VerifierArtifactRef, VerifierStatus, WorkItem, WorkItemStatus,
    WorkLease, WorkLeaseState,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct ContextCompiler {
    read: ReadService,
}

impl ContextCompiler {
    pub const fn new(read: ReadService) -> Self {
        Self { read }
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
        let reads = self.read_context(request).await?;
        let scope_claims = reads.fetch.claims.clone();
        let filters = normalized_filter(&request.candidate_handles);
        let buckets = bucket_claims(&reads.fetch.claims, &filters);
        let mut packet = assemble_packet(request, reads, buckets);
        if let Some(scope) = current_git_scope {
            resolve_memory_applicability(&mut packet, &scope_claims, scope);
        }
        packet.task_execution_class =
            TaskExecutionClassifier::classify(request, frame, &[], &packet.exact_handles);
        if TaskExecutionClassifier::should_attach_codecortex(
            request,
            frame,
            &[],
            &packet.task_execution_class,
        ) {
            attach_codecortex_reports(&mut packet, codecortex_reports);
        }
        hydrate_material_packet(&mut packet, request, current_git_scope, frame);
        packet.project_understanding = Some(ProjectUnderstandingCompiler::compile(
            &packet,
            frame,
            None,
            &eliot_types::ProjectUnderstandingEvidence::default(),
        ));
        enforce_budget(&mut packet, request.max_tokens, &request.candidate_handles)?;
        PacketQualityService::finalize(&mut packet, frame)?;
        Ok(packet)
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
    ) -> Result<CompilerReads, EngineError> {
        for attempt in 0..2 {
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
            let recall = self
                .read
                .recall_l0(&RecallL0Request {
                    project_id: request.project_id,
                    query: request.goal.clone(),
                    consistency: ReadConsistencyMode::AtLeastRevision,
                    at_least_revision: Some(revision),
                    lifecycle_audit: false,
                    task_id: request.task_id.parse().ok(),
                    task_class_cues: Vec::new(),
                    scope_refs: Vec::new(),
                    concept_refs: Vec::new(),
                })
                .await?;
            handles.extend(recall.handles.iter().map(|preview| preview.handle.clone()));
            handles.sort();
            handles.dedup();
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
                return Ok(CompilerReads {
                    current_state,
                    recall,
                    fetch,
                });
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
    let truncation = TruncationInfo {
        truncated: reads.recall.truncation.truncated || reads.fetch.truncation.truncated,
        limit: request.max_tokens,
        returned: 0,
    };
    ContextPacketL3 {
        packet_id: String::new(),
        project_id: request.project_id,
        task_id: request.task_id.clone(),
        goal: request.goal.clone(),
        task_execution_class: eliot_types::TaskExecutionClass::default(),
        project_understanding: None,
        memory_confidence: reads.recall.memory_confidence,
        acceptance_items: Vec::new(),
        at_revision: max_revision(reads.current_state.memory_revision, reads.fetch.at_revision),
        current_truth: reads.current_state.verified_now,
        relevant_verified_claims: buckets.relevant_verified_claims,
        relevant_supported_claims: buckets.relevant_supported_claims,
        weak_claims_warning: buckets.weak_claims_warning,
        negative_memory: buckets.negative_memory,
        recent_failures: reads.fetch.failure_fingerprints,
        known_decisions: buckets.known_decisions,
        open_questions: buckets.open_questions,
        exact_handles,
        source_receipts,
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
        truncation,
    }
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
        captured_at: OffsetDateTime::now_utc(),
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
    let receipt = report.memory_receipt.as_ref().map_or_else(
        || "unwritten".to_owned(),
        |receipt| receipt.write_id.to_string(),
    );
    format!("codecortex_report:{}:{}:{}", report.task, git_head, receipt)
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
                section_tokens: section_token_accounting(packet)?,
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
            section_tokens: section_token_accounting(packet)?,
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

fn section_token_accounting(
    packet: &ContextPacketL3,
) -> Result<BTreeMap<String, usize>, EngineError> {
    let mut sections = BTreeMap::new();
    sections.insert(
        "project_understanding".to_owned(),
        estimate_serialized_value(&packet.project_understanding)?.div_ceil(4),
    );
    sections.insert(
        "exact_handles".to_owned(),
        estimate_serialized_slice(&packet.exact_handles)?.div_ceil(4),
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
    sections.insert("whole_packet_estimate".to_owned(), estimate_tokens(packet)?);
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
        CodeEvidenceSource, FileEvidence,
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
}
