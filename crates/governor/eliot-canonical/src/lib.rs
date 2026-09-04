//! Governor-owned semantic admission and canonical state projections.
//!
//! This crate is the semantic side of the logical Governor described by
//! Architecture 4.5.  It validates a bounded write envelope, derives one
//! immutable [`PreparedTransition`], and delegates persistence to the
//! store-neutral [`CanonicalStoreClient`].  It deliberately does not open a
//! database, own Operational Recovery State, execute effects, or infer
//! completion from a transport receipt.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, OperationId, RequestMetadata, StateFence,
    canonical_json_bytes, contract_identity as foundation_contract_identity,
};
use eliot_store_api::{
    CanonicalStoreClient, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingHead,
    OrderingHeadExpectation, PreparedTransition, ReadConsistency, RevisionHead,
    RevisionHeadExpectation, ScopeId, ScopeRevisionView, SecurityContext, StoreError, StoreHealth,
    TransitionClass, WriteReceipt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this Governor contract surface.
pub const CONTRACT_NAME: &str = "eliot.governor.canonical";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Compatibility spelling used by Governor-facing APIs.
pub type RequestMeta = RequestMetadata;
/// Admission failures are intentionally the same typed boundary as canonical
/// state/transition failures; no second error taxonomy is maintained.
pub type AdmissionError = CanonicalError;

/// Errors returned by semantic admission, state projection, and finish
/// derivation.  Store errors remain distinguishable at the boundary.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// A foundation contract rejected an identity, request, or fence.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// The store-neutral persistence boundary rejected a prepared operation.
    #[error("canonical store: {0}")]
    Store(StoreError),
    /// A required field is blank or otherwise malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Field path in the canonical contract.
        field: &'static str,
        /// Stable reason suitable for a caller directive.
        reason: &'static str,
    },
    /// A required collection was empty.
    #[error("empty field {field}")]
    Empty {
        /// Field path of the empty collection.
        field: &'static str,
    },
    /// A collection contained duplicate semantic identities.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Field path containing duplicates.
        field: &'static str,
    },
    /// The request and transition did not describe one State Fence.
    #[error("state fence mismatch")]
    FenceMismatch,
    /// The request attempted to use a task binding different from its context.
    #[error("task binding mismatch")]
    TaskBindingMismatch,
    /// The requested command family does not match the transition class.
    #[error("semantic command does not match transition class")]
    CommandClassMismatch,
    /// The supplied transition class cannot realize the requested effect.
    #[error("transition class cannot realize requested effect")]
    EffectCeilingExceeded,
    /// A stable identity was changed while retrying an operation.
    #[error("idempotency identity conflict")]
    IdentityConflict,
    /// The caller supplied a state revision different from the current state.
    #[error("stale task revision")]
    StaleTaskRevision,
    /// Finish evidence was insufficient for the requested outcome.
    #[error("finish evidence is insufficient")]
    InsufficientFinishEvidence,
}

impl From<ContractError> for CanonicalError {
    fn from(error: ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<StoreError> for CanonicalError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), CanonicalError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CanonicalError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), CanonicalError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CanonicalError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), CanonicalError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(CanonicalError::Duplicate { field });
    }
    Ok(())
}

/// Canonical command alias.  The closed named-operation catalogue is owned by
/// `eliot-store-api`; this alias prevents a second command schema here.
pub type SemanticCommand = NamedMutationRequest;
/// Canonical command discriminator from the shared named-operation catalogue.
pub type SemanticCommandKind = NamedMutationOperation;

/// A complete semantic write request before Governor admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWriteEnvelope {
    /// Operation identity used for retries and receipt lookup.
    pub operation_id: OperationId,
    /// Authenticated request metadata and the caller's State Fence.
    pub request: RequestMetadata,
    /// Stable logical retry identity.
    pub idempotency_key: String,
    /// `WorkScope` addressed by the transition.
    pub scope_id: ScopeId,
    /// Optional task binding; unbound capture remains cold evidence.
    pub task_id: Option<String>,
    /// Closed transition family selected by Governor admission.
    pub transition_class: TransitionClass,
    /// Effect ceiling requested by the candidate, never an authority grant.
    pub requested_effect_ceiling: EffectClass,
    /// Digest of the admitted semantic contract set.
    pub admission_contract_set_digest: String,
    /// Digest of the named store operation manifest.
    pub operation_manifest_digest: OperationManifestDigest,
    /// Bounded named commands sharing one causal transition.
    pub semantic_commands: Vec<SemanticCommand>,
    /// Event, projection, and typed-relation intents committed atomically.
    pub event_projection_relation_intents: EventProjectionRelationIntents,
    /// Provenance, disclosure, taint, and influence metadata.
    pub security: SecurityContext,
    /// Exact proof or approval handles required by this transition.
    pub required_proof_and_approval_refs: Vec<String>,
    /// Compare-and-swap expectations for affected revision heads.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Compare-and-swap expectations for affected ordering heads.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

impl CanonicalWriteEnvelope {
    /// Validates the semantic envelope without contacting a store.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        self.request.validate()?;
        self.idempotency_key_valid()?;
        self.task_binding_valid()?;
        digest(
            &self.admission_contract_set_digest,
            "admission_contract_set_digest",
        )?;
        if self.semantic_commands.is_empty() {
            return Err(CanonicalError::Empty {
                field: "semantic_commands",
            });
        }
        unique(
            self.semantic_commands
                .iter()
                .map(|command| command.operation),
            "semantic_commands",
        )?;
        for command in &self.semantic_commands {
            command.validate()?;
            if command.operation.transition_class() != self.transition_class {
                return Err(CanonicalError::CommandClassMismatch);
            }
        }
        if !eliot_store_api::effect_is_at_most(
            self.requested_effect_ceiling,
            self.transition_class.maximum_effect(),
        ) {
            return Err(CanonicalError::EffectCeilingExceeded);
        }
        self.event_projection_relation_intents.validate()?;
        unique(
            self.required_proof_and_approval_refs.iter().cloned(),
            "required_proof_and_approval_refs",
        )?;
        for reference in &self.required_proof_and_approval_refs {
            text(reference, "required_proof_and_approval_ref")?;
        }
        unique(
            self.expected_revision_heads
                .iter()
                .map(|head| head.key.clone()),
            "expected_revision_heads",
        )?;
        unique(
            self.expected_ordering_heads
                .iter()
                .map(|head| head.scope.clone()),
            "expected_ordering_heads",
        )?;
        for head in &self.expected_revision_heads {
            head.validate()?;
            if head.state_fence != self.state_fence() {
                return Err(CanonicalError::FenceMismatch);
            }
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
            if head.state_fence != self.state_fence() {
                return Err(CanonicalError::FenceMismatch);
            }
        }
        self.security.validate(&self.state_fence())?;
        Ok(())
    }

    fn idempotency_key_valid(&self) -> Result<(), CanonicalError> {
        text(&self.idempotency_key, "idempotency_key")
    }

    fn task_binding_valid(&self) -> Result<(), CanonicalError> {
        if let Some(task_id) = &self.task_id {
            text(task_id, "task_id")?;
        }
        if let (Some(request_task), Some(envelope_task)) =
            (self.request.task_id.as_ref(), self.task_id.as_ref())
            && request_task.as_str() != envelope_task
        {
            return Err(CanonicalError::TaskBindingMismatch);
        }
        Ok(())
    }

    fn state_fence(&self) -> StateFence {
        self.request.state_fence.clone()
    }

    /// Computes the immutable request hash used by the store's idempotency
    /// boundary.  Expected heads are included, so changing the CAS contract
    /// cannot silently reuse an earlier semantic decision.
    pub fn canonical_request_hash(&self) -> Result<String, CanonicalError> {
        let bytes = canonical_json_bytes(self).map_err(|_| CanonicalError::InvalidField {
            field: "canonical_request",
            reason: "cannot serialize canonical request",
        })?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Converts the admitted envelope to the one shared prepared-transition
    /// contract consumed by Kernel and the canonical store.
    pub fn prepare(&self) -> Result<PreparedTransition, CanonicalError> {
        self.validate()?;
        let transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: self.operation_id.clone(),
                idempotency_key: self.idempotency_key.clone(),
                canonical_request_hash: self.canonical_request_hash()?,
            },
            state_fence: self.state_fence(),
            scope_id: self.scope_id.clone(),
            task_id: self.task_id.clone(),
            ordering_scopes: self
                .expected_ordering_heads
                .iter()
                .map(|head| head.scope.clone())
                .collect(),
            transition_class: self.transition_class,
            requested_effect_ceiling: self.requested_effect_ceiling,
            admission_contract_set_digest: self.admission_contract_set_digest.clone(),
            operation_manifest_digest: self.operation_manifest_digest.clone(),
            named_operations: self.semantic_commands.clone(),
            event_projection_relation_intents: self.event_projection_relation_intents.clone(),
            security: self.security.clone(),
            required_proof_and_approval_refs: self.required_proof_and_approval_refs.clone(),
        };
        transition.validate()?;
        Ok(transition)
    }
}

/// Rebuildable canonical state view for one `WorkScope`.  It is a projection,
/// not a second mutable store or a source of authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalState {
    /// Addressed `WorkScope`.
    pub scope_id: ScopeId,
    /// Coherent revision and ordering projection.
    pub revision_view: ScopeRevisionView,
    /// Store health observation captured with the view.
    pub store_health: StoreHealth,
}

impl CanonicalState {
    /// Builds a state view after validating the store projection.
    pub fn new(
        revision_view: ScopeRevisionView,
        store_health: StoreHealth,
    ) -> Result<Self, CanonicalError> {
        revision_view.validate()?;
        Ok(Self {
            scope_id: revision_view.scope_id.clone(),
            revision_view,
            store_health,
        })
    }

    /// Returns the State Fence captured by this view.
    pub fn state_fence(&self) -> &StateFence {
        &self.revision_view.state_fence
    }

    /// Checks whether a candidate transition was framed against this view.
    pub fn accepts(&self, transition: &PreparedTransition) -> bool {
        transition.scope_id == self.scope_id
            && transition.state_fence == self.revision_view.state_fence
    }

    /// Returns the expected next revision head for a known key.
    pub fn revision_head(&self, key: &str) -> Option<&RevisionHead> {
        self.revision_view
            .revision_heads
            .iter()
            .find(|head| head.key.as_str() == key)
    }

    /// Returns the expected ordering head for a known scope.
    pub fn ordering_head(&self, scope: &str) -> Option<&OrderingHead> {
        self.revision_view
            .ordering_heads
            .iter()
            .find(|head| head.scope.as_str() == scope)
    }
}

/// Read facade owned by the Governor.  It only composes named store reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalReadFacade;

impl CanonicalReadFacade {
    /// Loads a coherent scope state and store-health observation.
    pub async fn state<S: CanonicalStoreClient>(
        &self,
        store: &S,
        scope_id: ScopeId,
    ) -> Result<CanonicalState, CanonicalError> {
        let view = store.scope_revision_view(scope_id).await?;
        let health = store.health().await?;
        CanonicalState::new(view, health)
    }

    /// Executes a closed named read after validating its fence and operation.
    pub async fn named<S: CanonicalStoreClient>(
        &self,
        store: &S,
        request: eliot_store_api::NamedReadRequest,
    ) -> Result<eliot_store_api::NamedReadResponse, CanonicalError> {
        request.validate()?;
        Ok(store.execute_named(request).await?)
    }

    /// Performs one exact-fence read of a scope revision view.
    pub async fn exact_scope<S: CanonicalStoreClient>(
        &self,
        store: &S,
        scope_id: ScopeId,
        expected_fence: &StateFence,
    ) -> Result<ScopeRevisionView, CanonicalError> {
        let view = store.scope_revision_view(scope_id).await?;
        if &view.state_fence != expected_fence {
            return Err(CanonicalError::FenceMismatch);
        }
        Ok(view)
    }
}

/// Governor facade for semantic admission and canonical commit.
#[derive(Debug)]
pub struct CanonicalTransitionOwner<S> {
    store: S,
}

/// Caller response preference.  Staging itself remains a Kernel/ORS concern;
/// this value never changes the semantic transition or its proof ceiling.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteResponseMode {
    /// The caller will wait for a final canonical receipt.
    WaitForCommit,
    /// The caller will receive a durable-stage handle from Kernel/ORS.
    AcceptAfterStage,
}

/// Governor semantic-admission boundary from Appendix P.7.
#[allow(async_fn_in_trait)]
pub trait WriteAdmissionApi: Send + Sync {
    /// Validates an envelope and returns the immutable prepared plan.  This
    /// method never claims that ORS staging or canonical commit occurred.
    async fn prepare(
        &self,
        ctx: &RequestMeta,
        envelope: CanonicalWriteEnvelope,
        mode: WriteResponseMode,
    ) -> Result<PreparedTransition, AdmissionError>;
}

impl<S> CanonicalTransitionOwner<S> {
    /// Creates an owner over a store-neutral client.  The client remains the
    /// sole persistence owner.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrows the configured store adapter for diagnostics or composition.
    pub const fn store(&self) -> &S {
        &self.store
    }
}

impl<S: CanonicalStoreClient> CanonicalTransitionOwner<S> {
    /// Validates and prepares a semantic envelope without writing it.
    pub fn prepare(
        &self,
        envelope: &CanonicalWriteEnvelope,
    ) -> Result<PreparedTransition, CanonicalError> {
        envelope.prepare()
    }

    /// Performs one governed canonical transaction.  The store receives only
    /// the prepared transition and explicit compare-and-swap expectations.
    pub async fn commit(
        &self,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CanonicalError> {
        let transition = envelope.prepare()?;
        Ok(self
            .store
            .apply_prepared(
                &envelope.request,
                transition,
                envelope.expected_revision_heads,
                envelope.expected_ordering_heads,
            )
            .await?)
    }

    /// Reconciles a receipt by operation identity after a timeout or restart.
    pub async fn receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, CanonicalError> {
        Ok(self.store.receipt(operation_id).await?)
    }

    /// Returns a bounded store-health observation; health never grants write
    /// authority or changes the canonical state fence.
    pub async fn health(&self) -> Result<StoreHealth, CanonicalError> {
        Ok(self.store.health().await?)
    }
}

impl<S: CanonicalStoreClient + Send + Sync> WriteAdmissionApi for CanonicalTransitionOwner<S> {
    async fn prepare(
        &self,
        ctx: &RequestMeta,
        envelope: CanonicalWriteEnvelope,
        _mode: WriteResponseMode,
    ) -> Result<PreparedTransition, AdmissionError> {
        ctx.validate()?;
        if ctx != &envelope.request {
            return Err(CanonicalError::FenceMismatch);
        }
        envelope.prepare()
    }
}

/// Caller-requested finish candidate.  It contains no completion proof.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishAttemptDraft {
    /// Task identity selected by the caller.
    pub task_id: String,
    /// Exact current task revision expected by the caller.
    pub expected_task_revision: u64,
    /// Candidate outcome; Governor derives the decision.
    pub requested_outcome: RequestedFinishOutcome,
    /// Immutable artifact handles.
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    /// Observation handles.
    #[serde(default)]
    pub observation_refs: Vec<String>,
    /// Executed verifier-run handles.
    #[serde(default)]
    pub verifier_run_refs: Vec<String>,
    /// Unknowns disclosed by the caller.
    #[serde(default)]
    pub remaining_unknowns_declared_by_caller: Vec<String>,
    /// Public rationale candidate.
    pub rationale_candidate: String,
}

impl FinishAttemptDraft {
    /// Validates strict finish input without treating it as proof.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        text(&self.task_id, "finish.task_id")?;
        if self.expected_task_revision == 0 {
            return Err(CanonicalError::InvalidField {
                field: "finish.expected_task_revision",
                reason: "must be non-zero",
            });
        }
        text(&self.rationale_candidate, "finish.rationale_candidate")?;
        for (values, field) in [
            (&self.artifact_refs, "finish.artifact_refs"),
            (&self.observation_refs, "finish.observation_refs"),
            (&self.verifier_run_refs, "finish.verifier_run_refs"),
            (
                &self.remaining_unknowns_declared_by_caller,
                "finish.remaining_unknowns_declared_by_caller",
            ),
        ] {
            unique(values.iter(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        Ok(())
    }
}

/// Caller-requested finish outcome.  It is never persisted as the decision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedFinishOutcome {
    /// Request evaluation for complete work.
    CompleteCandidate,
    /// Declare partial work.
    Partial,
    /// Declare a blocker.
    Blocked,
    /// Declare a verification failure.
    FailedVerification,
    /// Declare degraded proof.
    DegradedNoProof,
    /// Declare that finishing would be unsafe.
    UnsafeToFinish,
    /// Declare cancellation.
    Cancelled,
    /// Declare supersession.
    Superseded,
}

/// `ELIOT_ARCH_OWNER`: `ARCH-FIN-01`
/// The closed canonical finish decision set from I7.9.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinishDecisionOutcome {
    /// All acceptance items, artifacts, and verifier requirements are proven.
    VerifiedComplete,
    /// Useful work exists but one or more requirements remain uncovered.
    Partial,
    /// A declared dependency or unknown prevents safe continuation.
    Blocked,
    /// A required verifier is absent, stale, or failed.
    FailedVerification,
    /// Work may be described, but proof is not sufficient for completion.
    DegradedNoProof,
    /// Completing would violate a safety or authority boundary.
    UnsafeToFinish,
    /// The caller cancelled the task.
    Cancelled,
    /// The task was replaced by a newer task contract.
    Superseded,
}

/// Evidence coverage for one acceptance item.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCoverage {
    /// Acceptance item identity.
    pub item_id: String,
    /// Whether canonical state marks the item satisfied.
    pub satisfied: bool,
    /// Evidence handles bound to the item.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Verifier handles bound to the item.
    #[serde(default)]
    pub verifier_run_refs: Vec<String>,
    /// Whether this item requires an executed verifier.
    pub requires_verifier: bool,
}

/// Current evidence rehydrated by the finish service.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishEvidence {
    /// Task identity rehydrated from canonical state.
    pub task_id: String,
    /// Current canonical task revision.
    pub current_task_revision: u64,
    /// Per-acceptance evidence and verifier bindings.
    pub acceptance: Vec<AcceptanceCoverage>,
    /// Executed verifier handles in the exact current scope.
    #[serde(default)]
    pub executed_verifier_run_refs: Vec<String>,
    /// Verifier handles known stale or invalid.
    #[serde(default)]
    pub stale_verifier_run_refs: Vec<String>,
    /// Effects not yet reconciled to a terminal outcome.
    #[serde(default)]
    pub unresolved_effect_refs: Vec<String>,
}

impl FinishEvidence {
    /// Validates the rehydrated evidence shape before deriving a decision.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        text(&self.task_id, "finish.evidence.task_id")?;
        if self.current_task_revision == 0 {
            return Err(CanonicalError::InvalidField {
                field: "finish.evidence.current_task_revision",
                reason: "must be non-zero",
            });
        }
        if self.acceptance.is_empty() {
            return Err(CanonicalError::Empty {
                field: "finish.evidence.acceptance",
            });
        }
        unique(
            self.acceptance.iter().map(|item| item.item_id.clone()),
            "finish.evidence.acceptance",
        )?;
        for item in &self.acceptance {
            text(&item.item_id, "finish.evidence.acceptance.item_id")?;
            unique(
                item.evidence_refs.iter(),
                "finish.evidence.acceptance.evidence_refs",
            )?;
            unique(
                item.verifier_run_refs.iter(),
                "finish.evidence.acceptance.verifier_run_refs",
            )?;
            for reference in item.evidence_refs.iter().chain(&item.verifier_run_refs) {
                text(reference, "finish.evidence.reference")?;
            }
            if item.evidence_refs.is_empty() {
                return Err(CanonicalError::InsufficientFinishEvidence);
            }
        }
        unique(
            self.executed_verifier_run_refs.iter(),
            "finish.evidence.executed_verifier_run_refs",
        )?;
        unique(
            self.stale_verifier_run_refs.iter(),
            "finish.evidence.stale_verifier_run_refs",
        )?;
        unique(
            self.unresolved_effect_refs.iter(),
            "finish.evidence.unresolved_effect_refs",
        )?;
        for reference in self
            .executed_verifier_run_refs
            .iter()
            .chain(&self.stale_verifier_run_refs)
            .chain(&self.unresolved_effect_refs)
        {
            text(reference, "finish.evidence.reference")?;
        }
        Ok(())
    }
}

/// Derived proof record.  It is produced by the Governor and cannot be
/// supplied by a caller.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedCompletionProof {
    /// Task and revision covered by the derivation.
    pub task_id: String,
    /// Revision used by the decision.
    pub task_revision: u64,
    /// Acceptance item identities and coverage statuses.
    pub per_acceptance_coverage: Vec<String>,
    /// Artifact/verifier binding handles.
    pub artifact_and_verifier_bindings: Vec<String>,
    /// Checks absent or stale at derivation time.
    pub checks_not_executed_or_stale: Vec<String>,
    /// Unresolved effects and unknowns.
    pub unresolved_effects_and_unknowns: Vec<String>,
    /// Highest proof ceiling supported by this evidence.
    pub proof_ceiling: ProofCeiling,
    /// Digest of the complete derived proof shape.
    pub derivation_digest: String,
}

/// Proof strength derived from exact evidence, not caller confidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCeiling {
    Observation,
    ScopedVerification,
    Completion,
}

/// Typed finish decision with derived proof and continuation information.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishDecision {
    /// Governor-derived terminal disposition.
    pub outcome: FinishDecisionOutcome,
    /// Derived proof; never caller-supplied.
    pub proof: DerivedCompletionProof,
    /// Safe next action or explicit continuation requirement.
    pub next_allowed_action: String,
}

/// Derives the closed finish decision from strict input and rehydrated state.
#[allow(clippy::too_many_lines)]
pub fn derive_finish_decision(
    draft: &FinishAttemptDraft,
    evidence: &FinishEvidence,
) -> Result<FinishDecision, CanonicalError> {
    draft.validate()?;
    evidence.validate()?;
    if draft.task_id != evidence.task_id {
        return Err(CanonicalError::TaskBindingMismatch);
    }
    if draft.expected_task_revision != evidence.current_task_revision {
        return Err(CanonicalError::StaleTaskRevision);
    }

    let mut coverage = Vec::with_capacity(evidence.acceptance.len());
    let mut missing = Vec::new();
    let executed: BTreeSet<&str> = evidence
        .executed_verifier_run_refs
        .iter()
        .map(String::as_str)
        .collect();
    let stale: BTreeSet<&str> = evidence
        .stale_verifier_run_refs
        .iter()
        .map(String::as_str)
        .collect();
    let mut verifier_gap = false;
    let mut all_satisfied = true;
    let mut bindings = draft.artifact_refs.clone();
    bindings.extend(draft.verifier_run_refs.iter().cloned());
    for verifier in &draft.verifier_run_refs {
        if !executed.contains(verifier.as_str()) || stale.contains(verifier.as_str()) {
            verifier_gap = true;
            missing.push(format!("verifier:{verifier}"));
        }
    }
    for item in &evidence.acceptance {
        if !item.satisfied {
            all_satisfied = false;
            missing.push(format!("acceptance:{}", item.item_id));
        }
        coverage.push(format!("{}={}", item.item_id, item.satisfied));
        for verifier in &item.verifier_run_refs {
            bindings.push(verifier.clone());
            if item.requires_verifier
                && (!executed.contains(verifier.as_str()) || stale.contains(verifier.as_str()))
            {
                verifier_gap = true;
                missing.push(format!("verifier:{verifier}"));
            }
        }
        if item.requires_verifier && item.verifier_run_refs.is_empty() {
            verifier_gap = true;
            missing.push(format!("verifier:{}", item.item_id));
        }
    }
    bindings.sort();
    bindings.dedup();
    let mut unresolved = evidence.unresolved_effect_refs.clone();
    unresolved.extend(draft.remaining_unknowns_declared_by_caller.iter().cloned());
    unresolved.sort();
    unresolved.dedup();
    let outcome = match draft.requested_outcome {
        RequestedFinishOutcome::CompleteCandidate
            if all_satisfied && !verifier_gap && unresolved.is_empty() =>
        {
            FinishDecisionOutcome::VerifiedComplete
        }
        RequestedFinishOutcome::CompleteCandidate if verifier_gap => {
            FinishDecisionOutcome::FailedVerification
        }
        RequestedFinishOutcome::CompleteCandidate if !unresolved.is_empty() => {
            FinishDecisionOutcome::Blocked
        }
        RequestedFinishOutcome::CompleteCandidate | RequestedFinishOutcome::DegradedNoProof => {
            FinishDecisionOutcome::DegradedNoProof
        }
        RequestedFinishOutcome::Partial => FinishDecisionOutcome::Partial,
        RequestedFinishOutcome::Blocked => FinishDecisionOutcome::Blocked,
        RequestedFinishOutcome::FailedVerification => FinishDecisionOutcome::FailedVerification,
        RequestedFinishOutcome::UnsafeToFinish => FinishDecisionOutcome::UnsafeToFinish,
        RequestedFinishOutcome::Cancelled => FinishDecisionOutcome::Cancelled,
        RequestedFinishOutcome::Superseded => FinishDecisionOutcome::Superseded,
    };
    let proof_ceiling = if outcome == FinishDecisionOutcome::VerifiedComplete {
        ProofCeiling::Completion
    } else if !bindings.is_empty() {
        ProofCeiling::ScopedVerification
    } else {
        ProofCeiling::Observation
    };
    let mut checks = missing;
    checks.sort();
    checks.dedup();
    let proof_shape = (
        &draft.task_id,
        evidence.current_task_revision,
        &coverage,
        &bindings,
        &checks,
        &unresolved,
        proof_ceiling,
    );
    let proof_bytes =
        canonical_json_bytes(&proof_shape).map_err(|_| CanonicalError::InvalidField {
            field: "finish.derived_proof",
            reason: "cannot serialize derived proof",
        })?;
    let proof = DerivedCompletionProof {
        task_id: draft.task_id.clone(),
        task_revision: evidence.current_task_revision,
        per_acceptance_coverage: coverage,
        artifact_and_verifier_bindings: bindings,
        checks_not_executed_or_stale: checks.clone(),
        unresolved_effects_and_unknowns: unresolved,
        proof_ceiling,
        derivation_digest: eliot_contracts::sha256_hex(&proof_bytes),
    };
    let next_allowed_action = if outcome == FinishDecisionOutcome::VerifiedComplete {
        "record verified completion through the canonical transition".to_owned()
    } else {
        "address the uncovered evidence or declared continuation before retrying finish".to_owned()
    };
    Ok(FinishDecision {
        outcome,
        proof,
        next_allowed_action,
    })
}

/// Returns the content-addressed identity of this contract surface.
pub fn contract_identity() -> Result<ContractIdentity, CanonicalError> {
    foundation_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "canonical_write_envelope": schemars::schema_for!(CanonicalWriteEnvelope),
            "prepared_transition": schemars::schema_for!(PreparedTransition),
            "finish_attempt_draft": schemars::schema_for!(FinishAttemptDraft),
            "finish_decision": schemars::schema_for!(FinishDecision),
            "named_read_consistency": [
                ReadConsistency::Eventual,
                ReadConsistency::AtLeastRevision,
                ReadConsistency::StableScope,
                ReadConsistency::ExactFence,
            ],
        }),
    )
    .map_err(CanonicalError::Foundation)
}
