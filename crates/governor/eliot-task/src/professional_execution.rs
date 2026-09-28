//! Professional execution contracts and preserved abandonment boundaries.
//!
//! These records are part of the Task Controller's canonical task snapshot.

use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn required_text(value: &str, field: &'static str) -> Result<(), ProfessionalExecutionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProfessionalExecutionError::InvalidField(field));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalRoleOwners {
    pub task_domain_owner: String,
    pub bridge_environment_owner: String,
    pub evaluator_owner: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalRequirementKind {
    Deliverable,
    Verifier,
    WorkflowBoundary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalRequirement {
    pub requirement_ref: String,
    pub kind: ProfessionalRequirementKind,
    pub description: String,
}

/// Complete contract for one professional task's method, environment and evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalExecutionContract {
    pub contract_ref: String,
    pub revision: u64,
    pub owners: ProfessionalRoleOwners,
    pub domain_method: String,
    pub target_software: String,
    pub target_version: String,
    pub input_asset_handles: Vec<String>,
    pub source_reference_handles: Vec<String>,
    pub output_workspace: String,
    pub allowed_write_roots: Vec<String>,
    pub expected_deliverable_manifest: Vec<String>,
    pub allowed_substitutions: Vec<String>,
    pub forbidden_shortcuts: Vec<String>,
    pub reference_visibility: String,
    pub evaluator_isolation: String,
    /// Typed enforcement of the visibility declaration above: every handle
    /// listed here is an immutable source reference visible to the evaluator
    /// only and is excluded from every worker-visible set this contract
    /// derives. This list is the enforced mechanism; the two declaration
    /// strings carry the human-readable policy.
    #[serde(default)]
    pub evaluator_only_reference_handles: Vec<String>,
    pub environment_profile: String,
    pub professional_tool_route: String,
    pub artifact_evaluator: String,
    pub requirements: Vec<ProfessionalRequirement>,
    pub proof_ceiling: String,
    pub checkpoint_conditions: Vec<String>,
    pub abandonment_conditions: Vec<String>,
    pub rollback_conditions: Vec<String>,
    pub delivery_conditions: Vec<String>,
}

impl ProfessionalExecutionContract {
    pub fn validate(&self) -> Result<(), ProfessionalExecutionError> {
        for (value, field) in [
            (&self.contract_ref, "contract_ref"),
            (&self.owners.task_domain_owner, "task_domain_owner"),
            (
                &self.owners.bridge_environment_owner,
                "bridge_environment_owner",
            ),
            (&self.owners.evaluator_owner, "evaluator_owner"),
            (&self.domain_method, "domain_method"),
            (&self.target_software, "target_software"),
            (&self.target_version, "target_version"),
            (&self.output_workspace, "output_workspace"),
            (&self.reference_visibility, "reference_visibility"),
            (&self.evaluator_isolation, "evaluator_isolation"),
            (&self.environment_profile, "environment_profile"),
            (&self.professional_tool_route, "professional_tool_route"),
            (&self.artifact_evaluator, "artifact_evaluator"),
            (&self.proof_ceiling, "proof_ceiling"),
        ] {
            required_text(value, field)?;
        }
        if self.revision == 0 || self.requirements.is_empty() {
            return Err(ProfessionalExecutionError::InvalidField("contract"));
        }
        let owners = [
            &self.owners.task_domain_owner,
            &self.owners.bridge_environment_owner,
            &self.owners.evaluator_owner,
        ];
        if owners
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != owners.len()
        {
            return Err(ProfessionalExecutionError::InvalidField(
                "independent_owners",
            ));
        }
        if !self
            .requirements
            .iter()
            .any(|requirement| requirement.kind == ProfessionalRequirementKind::Verifier)
        {
            return Err(ProfessionalExecutionError::InvalidField(
                "evaluator_requirement",
            ));
        }
        if self.expected_deliverable_manifest.is_empty() {
            return Err(ProfessionalExecutionError::InvalidField(
                "expected_deliverable_manifest",
            ));
        }
        let mut deliverables = std::collections::BTreeSet::new();
        for deliverable in &self.expected_deliverable_manifest {
            required_text(deliverable, "expected_deliverable")?;
            if !deliverables.insert(deliverable) {
                return Err(ProfessionalExecutionError::InvalidField(
                    "expected_deliverable_manifest",
                ));
            }
        }
        let mut refs = std::collections::BTreeSet::new();
        for requirement in &self.requirements {
            required_text(&requirement.requirement_ref, "requirement_ref")?;
            required_text(&requirement.description, "requirement_description")?;
            if !refs.insert(&requirement.requirement_ref) {
                return Err(ProfessionalExecutionError::DuplicateRequirement(
                    requirement.requirement_ref.clone(),
                ));
            }
        }
        Self::validate_handle_sets(self)
    }

    fn validate_handle_sets(
        contract: &ProfessionalExecutionContract,
    ) -> Result<(), ProfessionalExecutionError> {
        Self::validate_handles(
            &contract.input_asset_handles,
            "input_asset_handles",
            "input_asset_handle",
        )?;
        Self::validate_handles(
            &contract.source_reference_handles,
            "source_reference_handles",
            "source_reference_handle",
        )?;
        Self::validate_handles(
            &contract.allowed_write_roots,
            "allowed_write_roots",
            "allowed_write_root",
        )?;
        if contract.allowed_write_roots.is_empty() {
            return Err(ProfessionalExecutionError::InvalidField(
                "allowed_write_roots",
            ));
        }
        if !Self::workspace_in_roots(&contract.output_workspace, &contract.allowed_write_roots) {
            return Err(ProfessionalExecutionError::InvalidField("output_workspace"));
        }
        let declared: std::collections::BTreeSet<_> =
            contract.source_reference_handles.iter().collect();
        let mut hidden = std::collections::BTreeSet::new();
        for handle in &contract.evaluator_only_reference_handles {
            required_text(handle, "evaluator_only_reference_handle")?;
            if !declared.contains(handle) {
                return Err(ProfessionalExecutionError::InvalidField(
                    "evaluator_only_reference_handles",
                ));
            }
            if !hidden.insert(handle) {
                return Err(ProfessionalExecutionError::InvalidField(
                    "evaluator_only_reference_handles",
                ));
            }
        }
        Ok(())
    }

    fn validate_handles(
        handles: &[String],
        set_field: &'static str,
        item_field: &'static str,
    ) -> Result<(), ProfessionalExecutionError> {
        let mut known = std::collections::BTreeSet::new();
        for handle in handles {
            required_text(handle, item_field)?;
            if !known.insert(handle) {
                return Err(ProfessionalExecutionError::InvalidField(set_field));
            }
        }
        Ok(())
    }

    fn workspace_in_roots(workspace: &str, roots: &[String]) -> bool {
        roots.iter().any(|root| {
            let root = root.trim_end_matches('/');
            workspace == root
                || workspace
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// Reports whether a source reference handle is evaluator-only and must
    /// never enter a worker-visible set.
    pub fn is_evaluator_only_reference(&self, handle: &str) -> bool {
        self.evaluator_only_reference_handles
            .iter()
            .any(|hidden| hidden == handle)
    }

    /// Derives the worker-visible reference set: every declared source
    /// reference except the evaluator-only handles, in declaration order.
    pub fn worker_visible_reference_handles(&self) -> Vec<String> {
        self.source_reference_handles
            .iter()
            .filter(|handle| !self.is_evaluator_only_reference(handle))
            .cloned()
            .collect()
    }

    /// Materializes the worker packet, tool/filesystem view and log-safe
    /// handle sets from the permitted immutable handles and declared output
    /// roots only. The contract is revalidated first, so an unadmitted or
    /// corrupted contract cannot yield a packet; evaluator-only references
    /// never enter the returned sets.
    pub fn materialize_worker_packet(
        &self,
    ) -> Result<ProfessionalWorkerPacket, ProfessionalExecutionError> {
        self.validate()?;
        Ok(ProfessionalWorkerPacket {
            contract_ref: self.contract_ref.clone(),
            contract_revision: self.revision,
            asset_handles: self.input_asset_handles.clone(),
            reference_handles: self.worker_visible_reference_handles(),
            allowed_write_roots: self.allowed_write_roots.clone(),
            output_workspace: self.output_workspace.clone(),
            tool_route: self.professional_tool_route.clone(),
            environment_profile: self.environment_profile.clone(),
        })
    }

    /// Redacts every evaluator-only reference handle from worker-destined log
    /// text. The contract is revalidated first so redaction always runs
    /// against the admitted hidden set.
    pub fn redact_evaluator_only_references(
        &self,
        log: &str,
    ) -> Result<String, ProfessionalExecutionError> {
        self.validate()?;
        let mut hidden: Vec<&String> = self.evaluator_only_reference_handles.iter().collect();
        hidden.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        let mut redacted = log.to_owned();
        for handle in hidden {
            redacted = redacted.replace(handle.as_str(), "[withheld evaluator-only reference]");
        }
        Ok(redacted)
    }

    /// Builds the reference-isolation receipt recording which references were
    /// visible to each principal on the declared route. The contract is
    /// revalidated first so the receipt always binds the admitted contract
    /// revision and hidden set.
    pub fn isolation_receipt(
        &self,
    ) -> Result<ProfessionalReferenceIsolationReceipt, ProfessionalExecutionError> {
        self.validate()?;
        let route = ProfessionalIsolationRoute {
            tool_route: self.professional_tool_route.clone(),
            environment_profile: self.environment_profile.clone(),
        };
        let worker = ProfessionalPrincipalVisibility {
            principal: ProfessionalIsolationPrincipal::Worker,
            route: route.clone(),
            visible_asset_handles: self.input_asset_handles.clone(),
            visible_reference_handles: self.worker_visible_reference_handles(),
        };
        let evaluator = ProfessionalPrincipalVisibility {
            principal: ProfessionalIsolationPrincipal::Evaluator,
            route,
            visible_asset_handles: self.input_asset_handles.clone(),
            visible_reference_handles: self.source_reference_handles.clone(),
        };
        Ok(ProfessionalReferenceIsolationReceipt {
            contract_ref: self.contract_ref.clone(),
            contract_revision: self.revision,
            evaluator_only_reference_handles: self.evaluator_only_reference_handles.clone(),
            entries: vec![worker, evaluator],
        })
    }
}

/// Principal dimension of reference visibility: the worker receives only
/// permitted handles, while the evaluator additionally sees hidden
/// evaluator-only references.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalIsolationPrincipal {
    Worker,
    Evaluator,
}

/// Route dimension of reference visibility: the declared professional tool
/// route and environment profile the visibility entries were derived for.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalIsolationRoute {
    pub tool_route: String,
    pub environment_profile: String,
}

/// Per-principal-per-route visibility: the exact asset and reference handles
/// one principal may observe on one route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalPrincipalVisibility {
    pub principal: ProfessionalIsolationPrincipal,
    pub route: ProfessionalIsolationRoute,
    pub visible_asset_handles: Vec<String>,
    pub visible_reference_handles: Vec<String>,
}

/// Reference-isolation receipt bound to one exact contract revision: which
/// references were hidden from the worker and which handles each principal
/// could observe on the declared route.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalReferenceIsolationReceipt {
    pub contract_ref: String,
    pub contract_revision: u64,
    pub evaluator_only_reference_handles: Vec<String>,
    pub entries: Vec<ProfessionalPrincipalVisibility>,
}

impl ProfessionalReferenceIsolationReceipt {
    /// Returns the visibility entry for one principal, if recorded.
    pub fn visibility_for(
        &self,
        principal: ProfessionalIsolationPrincipal,
    ) -> Option<&ProfessionalPrincipalVisibility> {
        self.entries
            .iter()
            .find(|entry| entry.principal == principal)
    }
}

/// Worker packet, tool surface and filesystem view derived only from the
/// contract's permitted immutable handles and declared output roots.
/// Evaluator-only references are structurally absent: no field carries them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalWorkerPacket {
    pub contract_ref: String,
    pub contract_revision: u64,
    pub asset_handles: Vec<String>,
    pub reference_handles: Vec<String>,
    pub allowed_write_roots: Vec<String>,
    pub output_workspace: String,
    pub tool_route: String,
    pub environment_profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalAttempt {
    pub attempt_ref: String,
    pub parent_attempt_ref: Option<String>,
    pub partial_artifact_handles: Vec<String>,
    pub reason: String,
}

/// A caller-provided workspace observation. The Task domain validates its
/// declared fields; it cannot verify filesystem presence or checksum bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalArtifactEntry {
    pub deliverable_ref: String,
    pub observed_presence_handle: String,
    pub checksum_sha256: String,
}

/// Declared artifact evidence for one exact professional contract revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalArtifactManifest {
    pub manifest_ref: String,
    pub contract_ref: String,
    pub contract_revision: u64,
    pub output_workspace: String,
    pub entries: Vec<ProfessionalArtifactEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalEvaluationOutcome {
    Accepted,
    Rejected,
    Inconclusive,
}

/// Caller-provided evaluator metadata linked to a manifest and contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalEvaluatorResult {
    pub manifest_ref: String,
    pub contract_ref: String,
    pub contract_revision: u64,
    pub evaluator_owner_ref: String,
    pub evaluator_ref: String,
    pub result_handle: String,
    pub outcome: ProfessionalEvaluationOutcome,
}

/// Non-authoritative evidence retained in task snapshots until trusted bridge
/// and evaluator provenance can be checked by the owning integration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalCompletionEvidence {
    pub artifact_manifest: ProfessionalArtifactManifest,
    pub evaluator_result: Option<ProfessionalEvaluatorResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProfessionalAttemptOutcome {
    Stopped,
    ReportedSuccess,
    ApproachChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrematureAbandonmentSignal {
    pub signal_ref: String,
    pub task_id: TaskId,
    pub contract_ref: String,
    pub contract_revision: u64,
    pub attempt_ref: String,
    pub attempt_lineage: Vec<String>,
    pub unresolved_requirements: Vec<ProfessionalRequirement>,
    pub state_fence: StateFence,
    pub partial_artifact_handles: Vec<String>,
    pub reason: String,
    pub outcome: ProfessionalAttemptOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalApproachRevision {
    pub revision: u64,
    pub previous_revision: u64,
    pub approach: String,
    pub rationale: String,
    pub acceptance_impact: String,
    pub preserved_partial_artifact_handles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TaskControllerDisposition {
    Reframe { rationale: String },
    Supersede { rationale: String },
    AcceptPartial { acceptance_ref: String },
    RequestHumanInput { question: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalAbandonmentDecision {
    pub signal_ref: String,
    pub disposition: TaskControllerDisposition,
    pub unresolved_requirement_refs: Vec<String>,
    pub preserved_partial_artifact_handles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfessionalExecutionState {
    pub contract: ProfessionalExecutionContract,
    /// Reference-isolation receipt constructed at admission from the admitted
    /// contract; it records per-principal-per-route visibility for the exact
    /// contract revision above. Legacy snapshots predate this field and
    /// deserialize to an empty receipt.
    #[serde(default)]
    pub reference_isolation_receipt: ProfessionalReferenceIsolationReceipt,
    #[serde(default)]
    pub completion_evidence: Vec<ProfessionalCompletionEvidence>,
    pub attempts: Vec<ProfessionalAttempt>,
    pub abandonment_signals: Vec<PrematureAbandonmentSignal>,
    pub approach_revisions: Vec<ProfessionalApproachRevision>,
    pub controller_decisions: Vec<ProfessionalAbandonmentDecision>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProfessionalExecutionError {
    #[error("invalid professional execution field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate professional requirement {0}")]
    DuplicateRequirement(String),
    #[error("unknown professional requirement {0}")]
    UnknownRequirement(String),
    #[error("professional execution contract already exists")]
    ContractAlreadyExists,
    #[error("professional execution contract was not found")]
    ContractNotFound,
    #[error("professional attempt lineage is invalid")]
    InvalidAttemptLineage,
    #[error("professional approach revision is not the next revision")]
    InvalidApproachRevision,
    #[error("professional abandonment signal was not found")]
    SignalNotFound,
    #[error("professional state fence does not match")]
    FenceMismatch,
    #[error("the professional evaluator boundary remains unresolved")]
    EvaluatorBoundaryUnresolved,
}

impl ProfessionalExecutionState {
    pub fn new(
        contract: ProfessionalExecutionContract,
    ) -> Result<Self, ProfessionalExecutionError> {
        contract.validate()?;
        let reference_isolation_receipt = contract.isolation_receipt()?;
        Ok(Self {
            contract,
            reference_isolation_receipt,
            completion_evidence: Vec::new(),
            attempts: Vec::new(),
            abandonment_signals: Vec::new(),
            approach_revisions: Vec::new(),
            controller_decisions: Vec::new(),
        })
    }

    /// Materializes the worker packet for the admitted contract: only
    /// permitted immutable handles and declared output roots, with
    /// evaluator-only references excluded.
    pub fn worker_packet(&self) -> Result<ProfessionalWorkerPacket, ProfessionalExecutionError> {
        self.contract.materialize_worker_packet()
    }

    pub fn record_attempt(
        &mut self,
        task_id: TaskId,
        state_fence: StateFence,
        attempt: ProfessionalAttempt,
        outcome: ProfessionalAttemptOutcome,
        signal_ref: String,
    ) -> Result<Option<PrematureAbandonmentSignal>, ProfessionalExecutionError> {
        required_text(&attempt.attempt_ref, "attempt_ref")?;
        required_text(&attempt.reason, "attempt_reason")?;
        required_text(&signal_ref, "signal_ref")?;
        if self
            .attempts
            .iter()
            .any(|known| known.attempt_ref == attempt.attempt_ref)
        {
            return Err(ProfessionalExecutionError::InvalidAttemptLineage);
        }
        if let Some(parent) = &attempt.parent_attempt_ref {
            if !self
                .attempts
                .iter()
                .any(|known| &known.attempt_ref == parent)
            {
                return Err(ProfessionalExecutionError::InvalidAttemptLineage);
            }
        } else if !self.attempts.is_empty() {
            return Err(ProfessionalExecutionError::InvalidAttemptLineage);
        }
        for handle in &attempt.partial_artifact_handles {
            required_text(handle, "partial_artifact_handle")?;
        }
        let unresolved_requirements = self.contract.requirements.clone();
        let partial_artifact_handles: Vec<_> = self
            .attempts
            .iter()
            .flat_map(|prior| prior.partial_artifact_handles.iter().cloned())
            .chain(attempt.partial_artifact_handles.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let signal = if unresolved_requirements.is_empty() {
            None
        } else {
            if self
                .abandonment_signals
                .iter()
                .any(|known| known.signal_ref == signal_ref)
            {
                return Err(ProfessionalExecutionError::InvalidField("signal_ref"));
            }
            let attempt_lineage = self.lineage_for(&attempt);
            Some(PrematureAbandonmentSignal {
                signal_ref,
                task_id,
                contract_ref: self.contract.contract_ref.clone(),
                contract_revision: self.contract.revision,
                attempt_ref: attempt.attempt_ref.clone(),
                attempt_lineage,
                unresolved_requirements,
                state_fence,
                partial_artifact_handles,
                reason: attempt.reason.clone(),
                outcome,
            })
        };
        self.attempts.push(attempt);
        if let Some(signal) = &signal {
            self.abandonment_signals.push(signal.clone());
        }
        Ok(signal)
    }

    pub fn change_approach(
        &mut self,
        revision: ProfessionalApproachRevision,
        task_id: TaskId,
        state_fence: StateFence,
        attempt: ProfessionalAttempt,
        signal_ref: String,
    ) -> Result<Option<PrematureAbandonmentSignal>, ProfessionalExecutionError> {
        required_text(&revision.approach, "approach")?;
        required_text(&revision.rationale, "rationale")?;
        required_text(&revision.acceptance_impact, "acceptance_impact")?;
        let current = self
            .approach_revisions
            .last()
            .map_or(self.contract.revision, |previous| previous.revision);
        if current.checked_add(1) != Some(revision.revision)
            || revision.previous_revision != current
        {
            return Err(ProfessionalExecutionError::InvalidApproachRevision);
        }
        let known_handles: std::collections::BTreeSet<_> = self
            .attempts
            .iter()
            .flat_map(|prior| prior.partial_artifact_handles.iter().cloned())
            .chain(attempt.partial_artifact_handles.iter().cloned())
            .collect();
        let revised_handles: std::collections::BTreeSet<_> = revision
            .preserved_partial_artifact_handles
            .iter()
            .cloned()
            .collect();
        if revised_handles != known_handles {
            return Err(ProfessionalExecutionError::InvalidField(
                "preserved_partial_artifact_handles",
            ));
        }
        let signal = self.record_attempt(
            task_id,
            state_fence,
            attempt,
            ProfessionalAttemptOutcome::ApproachChanged,
            signal_ref,
        )?;
        self.approach_revisions.push(revision);
        Ok(signal)
    }

    pub fn decide(
        &mut self,
        decision: ProfessionalAbandonmentDecision,
    ) -> Result<(), ProfessionalExecutionError> {
        let signal = self
            .abandonment_signals
            .iter()
            .find(|signal| signal.signal_ref == decision.signal_ref)
            .ok_or(ProfessionalExecutionError::SignalNotFound)?;
        if decision.unresolved_requirement_refs
            != signal
                .unresolved_requirements
                .iter()
                .map(|requirement| requirement.requirement_ref.clone())
                .collect::<Vec<_>>()
            || decision.preserved_partial_artifact_handles != signal.partial_artifact_handles
        {
            return Err(ProfessionalExecutionError::InvalidField(
                "preserved_boundary",
            ));
        }
        match &decision.disposition {
            TaskControllerDisposition::Reframe { rationale }
            | TaskControllerDisposition::Supersede { rationale } => {
                required_text(rationale, "rationale")?;
            }
            TaskControllerDisposition::AcceptPartial { acceptance_ref } => {
                required_text(acceptance_ref, "acceptance_ref")?;
            }
            TaskControllerDisposition::RequestHumanInput { question } => {
                required_text(question, "question")?;
            }
        }
        self.controller_decisions.push(decision);
        Ok(())
    }

    pub fn require_evaluator_result(&self) -> Result<(), ProfessionalExecutionError> {
        if self
            .contract
            .requirements
            .iter()
            .any(|requirement| requirement.kind == ProfessionalRequirementKind::Verifier)
        {
            return Err(ProfessionalExecutionError::EvaluatorBoundaryUnresolved);
        }
        Ok(())
    }

    /// Stores structurally valid evidence without treating caller claims as
    /// proof of filesystem presence or independent evaluation.
    pub fn record_completion_evidence(
        &mut self,
        evidence: ProfessionalCompletionEvidence,
    ) -> Result<(), ProfessionalExecutionError> {
        let manifest = &evidence.artifact_manifest;
        required_text(&manifest.manifest_ref, "manifest_ref")?;
        if manifest.contract_ref != self.contract.contract_ref
            || manifest.contract_revision != self.contract.revision
            || manifest.output_workspace != self.contract.output_workspace
            || manifest.entries.is_empty()
        {
            return Err(ProfessionalExecutionError::InvalidField(
                "artifact_manifest",
            ));
        }
        let mut observed = std::collections::BTreeSet::new();
        for entry in &manifest.entries {
            required_text(&entry.deliverable_ref, "deliverable_ref")?;
            required_text(&entry.observed_presence_handle, "observed_presence_handle")?;
            if entry.checksum_sha256.len() != 64
                || !entry
                    .checksum_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !observed.insert(&entry.deliverable_ref)
            {
                return Err(ProfessionalExecutionError::InvalidField("artifact_entry"));
            }
        }
        let expected: std::collections::BTreeSet<_> =
            self.contract.expected_deliverable_manifest.iter().collect();
        if observed != expected {
            return Err(ProfessionalExecutionError::InvalidField(
                "expected_deliverable_manifest",
            ));
        }
        if let Some(result) = &evidence.evaluator_result {
            required_text(&result.manifest_ref, "evaluator_manifest_ref")?;
            required_text(&result.evaluator_owner_ref, "evaluator_owner_ref")?;
            required_text(&result.evaluator_ref, "evaluator_ref")?;
            required_text(&result.result_handle, "evaluator_result_handle")?;
            if result.manifest_ref != manifest.manifest_ref
                || result.contract_ref != self.contract.contract_ref
                || result.contract_revision != self.contract.revision
                || result.evaluator_owner_ref != self.contract.owners.evaluator_owner
                || result.evaluator_ref != self.contract.artifact_evaluator
            {
                return Err(ProfessionalExecutionError::InvalidField(
                    "evaluator_result_binding",
                ));
            }
        }
        self.completion_evidence.push(evidence);
        Ok(())
    }

    pub fn latest_attempt_stopped_with_signal(&self) -> bool {
        self.attempts.last().is_some_and(|attempt| {
            self.abandonment_signals.iter().any(|signal| {
                signal.attempt_ref == attempt.attempt_ref
                    && signal.outcome == ProfessionalAttemptOutcome::Stopped
            })
        })
    }

    fn lineage_for(&self, attempt: &ProfessionalAttempt) -> Vec<String> {
        let mut lineage = Vec::new();
        let mut parent = attempt.parent_attempt_ref.as_deref();
        while let Some(parent_ref) = parent {
            let Some(known) = self
                .attempts
                .iter()
                .find(|known| known.attempt_ref == parent_ref)
            else {
                break;
            };
            lineage.push(known.attempt_ref.clone());
            parent = known.parent_attempt_ref.as_deref();
        }
        lineage.reverse();
        lineage.push(attempt.attempt_ref.clone());
        lineage
    }
}
