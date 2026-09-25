//! Provider-neutral contracts for attempts, coordination and anchored review.
//!
//! This crate contains only validated immutable shapes and small state
//! machines.  It does not own scheduling, mailboxes, storage, process
//! execution, transcript capture, hidden reasoning or authority decisions.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current wire revision for the C0-06 contract fragment.
pub const CONTRACT_VERSION: &str = "eliot-agent-contracts/v1";
const MAX_DELTA_BYTES: usize = 64 * 1024;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, JsonSchema, Serialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            /// Constructs a non-blank, non-control identity.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_text(&value, stringify!($name))?;
                Ok(Self(value))
            }

            /// Returns the canonical text.
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl TryFrom<&str> for $name {
            type Error = ContractError;
            fn try_from(value: &str) -> Result<Self, Self::Error> { Self::new(value) }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;
            fn try_from(value: String) -> Result<Self, Self::Error> { Self::new(value) }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self { value.0 }
        }
    };
}

id_type!(AgentAttemptId);
id_type!(RouteId);
id_type!(WorkItemId);
id_type!(SwarmId);
id_type!(MessageId);
id_type!(ReviewItemId);
id_type!(HandoffId);
id_type!(TargetId);
id_type!(AnchorId);
id_type!(EvidenceId);
id_type!(PrincipalId);
id_type!(RevisionId);

/// Validation failures are typed so consumers can fail closed without parsing
/// provider prose.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("{0} must not be blank")]
    Blank(&'static str),
    #[error("{0} contains a control character")]
    ControlCharacter(&'static str),
    #[error("{0} must contain at least one item")]
    EmptyCollection(&'static str),
    #[error("{0} contains a duplicate item")]
    DuplicateItem(&'static str),
    #[error("recipient is not present in the frozen coordination map")]
    InvalidRecipient,
    #[error("sender cannot address itself")]
    SelfRecipient,
    #[error("state transition {from:?} -> {to:?} is not admitted")]
    InvalidTransition { from: String, to: String },
    #[error("state fence is stale for this contract")]
    StaleFence,
    #[error("hidden reasoning is not a public contract field")]
    HiddenReasoning,
    #[error("anchor resolution is ambiguous")]
    AmbiguousAnchor,
    #[error("anchor resolution is stale or unavailable")]
    UnusableAnchor,
    #[error("review rejection requires a reason")]
    MissingRejectionReason,
    #[error("authority cannot be granted by an agent contract")]
    AuthorityViolation,
    #[error("{0} exceeds the bounded payload limit")]
    PayloadTooLarge(&'static str),
    #[error("descendant closure is incomplete")]
    IncompleteDescendantClosure,
    #[error("complete parent cannot have a live or unknown descendant")]
    LiveDescendantOnComplete,
    #[error("reference is invalid")]
    InvalidReference,
    #[error("presenter is not the current lease holder or epoch for {0}")]
    StaleLease(&'static str),
    #[error("caller wrote another owner's fields for {0}")]
    ForeignOwner(&'static str),
    #[error("execution update changes frozen swarm semantics for {0}")]
    SemanticDrift(&'static str),
    #[error("definition/admission/execution ownership link is broken for {0}")]
    BrokenOwnershipLink(&'static str),
    #[error("numeric ceiling is not a positive bound for {0}")]
    InvalidBound(&'static str),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Blank(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::ControlCharacter(field));
    }
    Ok(())
}

fn validate_collection<T>(values: &[T], field: &'static str) -> Result<(), ContractError>
where
    T: Ord,
{
    if values.is_empty() {
        return Err(ContractError::EmptyCollection(field));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(ContractError::DuplicateItem(field));
    }
    Ok(())
}

fn transition_error<F: std::fmt::Debug, T: std::fmt::Debug>(from: F, to: T) -> ContractError {
    ContractError::InvalidTransition {
        from: format!("{from:?}"),
        to: format!("{to:?}"),
    }
}

/// Immutable public reference to an artifact, evidence item or other
/// expansion handle.  It intentionally carries no payload or private text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicReference {
    /// Stable target kind.
    pub kind: String,
    /// Stable target identity.
    pub id: TargetId,
    /// Revision that was actually observed.
    pub revision: RevisionId,
    /// Optional content digest for immutable evidence.
    pub digest: Option<String>,
}

impl PublicReference {
    /// Validates identity-bearing reference fields.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.kind, "reference.kind")?;
        validate_text(self.id.as_str(), "reference.id")?;
        validate_text(self.revision.as_str(), "reference.revision")?;
        if let Some(digest) = &self.digest {
            validate_text(digest, "reference.digest")?;
        }
        Ok(())
    }
}

/// Exact source/provenance reference used by reviews and handoffs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceReference {
    /// Origin category, for example `git`, `verifier` or `mailbox`.
    pub source_kind: String,
    /// Origin identity.
    pub source_id: TargetId,
    /// Source revision.
    pub revision: RevisionId,
    /// Optional digest of the exact observed bytes.
    pub digest: Option<String>,
}

impl ProvenanceReference {
    /// Validates this provenance handle without asserting its semantic truth.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.source_kind, "provenance.source_kind")?;
        validate_text(self.source_id.as_str(), "provenance.source_id")?;
        validate_text(self.revision.as_str(), "provenance.revision")?;
        if let Some(digest) = &self.digest {
            validate_text(digest, "provenance.digest")?;
        }
        Ok(())
    }
}

/// A route fingerprint attached to one attempt.  The contract does not
/// interpret provider/model names or select a fallback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Stable route identity.
    pub route_id: RouteId,
    /// Adapter/runtime identity.
    pub adapter_id: String,
    /// Content-addressed runtime fingerprint.
    pub fingerprint: String,
    /// Continuation mode for this attempt.
    pub continuity: ContinuityKind,
}

impl Route {
    /// Validates route identity without making a provider claim.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.route_id.as_str(), "route.route_id")?;
        validate_text(&self.adapter_id, "route.adapter_id")?;
        validate_text(&self.fingerprint, "route.fingerprint")
    }
}

/// Provider/session continuity semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum ContinuityKind {
    NativeResume,
    NativeFork,
    Replayed,
    Rehydrated,
    Fresh,
}

/// Durable attempt lifecycle.  A stale fence invalidates applicability of an
/// output; it never rewrites what an attempt actually ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentAttemptState {
    Admitted,
    Provisioning,
    Launching,
    Running,
    WaitingTool,
    WaitingHuman,
    WaitingChild,
    Checkpointed,
    Verifying,
    Auditing,
    Completed,
    Partial,
    Failed,
    Cancelled,
    UnknownOutcome,
}

impl AgentAttemptState {
    /// Returns whether the exact lifecycle transition is allowed.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Admitted, Self::Provisioning)
                | (Self::Provisioning, Self::Launching)
                | (Self::Launching, Self::Running)
                | (
                    Self::Running,
                    Self::WaitingTool
                        | Self::WaitingHuman
                        | Self::WaitingChild
                        | Self::Checkpointed
                        | Self::Verifying
                        | Self::Failed
                        | Self::Cancelled
                        | Self::UnknownOutcome
                )
                | (
                    Self::WaitingTool
                        | Self::WaitingHuman
                        | Self::WaitingChild
                        | Self::Checkpointed,
                    Self::Running
                        | Self::Verifying
                        | Self::Failed
                        | Self::Cancelled
                        | Self::UnknownOutcome
                )
                | (
                    Self::Verifying,
                    Self::Auditing
                        | Self::Completed
                        | Self::Partial
                        | Self::Failed
                        | Self::UnknownOutcome
                )
                | (
                    Self::Auditing,
                    Self::Completed | Self::Partial | Self::Failed | Self::UnknownOutcome
                )
        )
    }
}

/// A durable unit of execution, independent of provider personality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentAttempt {
    /// Attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Frozen work item identity.
    pub work_item_id: WorkItemId,
    /// Bound route/session executor.
    pub route: Route,
    /// Current lifecycle state.
    pub state: AgentAttemptState,
    /// Fence at admission/checkpoint.
    pub state_fence: StateFence,
    /// Public evidence handles produced so far.
    pub evidence_refs: Vec<PublicReference>,
    /// Parent attempt, where this is a visible child.
    pub parent_attempt_id: Option<AgentAttemptId>,
}

impl AgentAttempt {
    /// Validates the attempt surface and evidence references.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.attempt_id.as_str(), "attempt_id")?;
        validate_text(self.work_item_id.as_str(), "work_item_id")?;
        self.route.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        for reference in &self.evidence_refs {
            reference.validate()?;
        }
        Ok(())
    }

    /// Applies one lifecycle transition without side effects.
    pub fn transition_to(&mut self, next: AgentAttemptState) -> Result<(), ContractError> {
        if !self.state.can_transition_to(next) {
            return Err(transition_error(self.state, next));
        }
        self.state = next;
        Ok(())
    }
}

/// Work item state used by a frozen plan projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkItemState {
    Planned,
    Ready,
    Assigned,
    Running,
    Blocked,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

/// One immutable work item in a swarm plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    /// Work identity.
    pub work_item_id: WorkItemId,
    /// One-line responsibility, never a hidden prompt/transcript.
    pub responsibility: String,
    /// Frozen plan and wave revisions.
    pub plan_revision: RevisionId,
    pub wave_revision: RevisionId,
    /// Explicit dependency and overlap edges.
    pub dependency_ids: Vec<WorkItemId>,
    pub overlap_ids: Vec<WorkItemId>,
    /// Assigned attempt/role and mailbox handle.
    pub assigned_attempt_id: Option<AgentAttemptId>,
    pub assigned_role: Option<String>,
    pub mailbox_route_handle: Option<String>,
    /// Read projection state only.
    pub state: WorkItemState,
}

impl WorkItem {
    /// Validates bounded work-item identity and graph references.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.work_item_id.as_str(), "work_item_id")?;
        validate_text(&self.responsibility, "responsibility")?;
        validate_text(self.plan_revision.as_str(), "plan_revision")?;
        validate_text(self.wave_revision.as_str(), "wave_revision")?;
        for (items, field) in [
            (&self.dependency_ids, "dependency_ids"),
            (&self.overlap_ids, "overlap_ids"),
        ] {
            if items.iter().any(|id| id == &self.work_item_id) {
                return Err(ContractError::InvalidReference);
            }
            if !items.is_empty() && items.iter().collect::<BTreeSet<_>>().len() != items.len() {
                return Err(ContractError::DuplicateItem(field));
            }
        }
        if let Some(role) = &self.assigned_role {
            validate_text(role, "assigned_role")?;
        }
        if let Some(route) = &self.mailbox_route_handle {
            validate_text(route, "mailbox_route_handle")?;
        }
        Ok(())
    }
}

/// Swarm execution state; plan definition/admission remain separate owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmExecutionState {
    NotStarted,
    Running,
    Paused,
    Reducing,
    Verifying,
    Completed,
    Partial,
    Failed,
    Cancelled,
    UnknownOutcome,
}

/// A frozen, bounded swarm projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Swarm {
    /// Swarm identity.
    pub swarm_id: SwarmId,
    pub plan_revision: RevisionId,
    pub wave_revision: RevisionId,
    pub state: SwarmExecutionState,
    pub work_items: Vec<WorkItem>,
    pub state_fence: StateFence,
}

impl Swarm {
    /// Validates work graph uniqueness and frozen revisions.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.swarm_id.as_str(), "swarm_id")?;
        validate_text(self.plan_revision.as_str(), "plan_revision")?;
        validate_text(self.wave_revision.as_str(), "wave_revision")?;
        validate_collection(
            &self
                .work_items
                .iter()
                .map(|item| item.work_item_id.clone())
                .collect::<Vec<_>>(),
            "work_items",
        )?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        for item in &self.work_items {
            item.validate()?;
        }
        Ok(())
    }
}

/// Addressable recipient from the frozen map.  No semantic subscription is
/// represented by this type.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipientRef {
    /// Explicit attempt recipient, if assigned.
    pub attempt_id: Option<AgentAttemptId>,
    /// Explicit work-item recipient, if not yet assigned.
    pub work_item_id: Option<WorkItemId>,
}

impl RecipientRef {
    /// Creates an attempt recipient.
    pub fn attempt(id: AgentAttemptId) -> Self {
        Self {
            attempt_id: Some(id),
            work_item_id: None,
        }
    }
    /// Creates a work-item recipient.
    pub fn work_item(id: WorkItemId) -> Self {
        Self {
            attempt_id: None,
            work_item_id: Some(id),
        }
    }
    fn validate(&self) -> Result<(), ContractError> {
        if self.attempt_id.is_none() == self.work_item_id.is_none() {
            return Err(ContractError::InvalidRecipient);
        }
        Ok(())
    }
}

/// One entry in the rebuildable coordination map.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationEntry {
    pub work_item_id: WorkItemId,
    pub responsibility: String,
    pub dependency_ids: Vec<WorkItemId>,
    pub overlap_ids: Vec<WorkItemId>,
    pub assigned_attempt_id: Option<AgentAttemptId>,
    pub assigned_role: Option<String>,
    pub mailbox_route_handle: Option<String>,
}

/// Derived recipient-addressing view.  It cannot mutate the plan or grant
/// routing/authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationMapView {
    pub plan_revision: RevisionId,
    pub wave_revision: RevisionId,
    pub entries: Vec<CoordinationEntry>,
}

impl CoordinationMapView {
    /// Validates exact map uniqueness and bounded public fields.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.plan_revision.as_str(), "plan_revision")?;
        validate_text(self.wave_revision.as_str(), "wave_revision")?;
        validate_collection(
            &self
                .entries
                .iter()
                .map(|entry| entry.work_item_id.clone())
                .collect::<Vec<_>>(),
            "coordination_entries",
        )?;
        for entry in &self.entries {
            validate_text(entry.work_item_id.as_str(), "work_item_id")?;
            validate_text(&entry.responsibility, "responsibility")?;
        }
        Ok(())
    }

    /// Returns the exact entry or a typed invalid-recipient failure.
    pub fn resolve_recipient(
        &self,
        recipient: &RecipientRef,
    ) -> Result<&CoordinationEntry, ContractError> {
        recipient.validate()?;
        let found = self.entries.iter().find(|entry| {
            recipient
                .work_item_id
                .as_ref()
                .is_some_and(|id| &entry.work_item_id == id)
                || recipient
                    .attempt_id
                    .as_ref()
                    .is_some_and(|id| entry.assigned_attempt_id.as_ref() == Some(id))
        });
        found.ok_or(ContractError::InvalidRecipient)
    }
}

/// Kind of bounded live delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LivePeerMessageKind {
    RelevantFinding,
    AssumptionInvalidated,
    DependencyDiscovered,
    PlanContradiction,
    Obstacle,
    AbandonedDeadEnd,
}

/// Reaction requested at the next admissible boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestedReaction {
    Inform,
    Revalidate,
    Reply,
    PauseDependentEffect,
}

/// Delivery timing, never an interrupt guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageUrgency {
    Normal,
    BeforeNextDependentEffect,
}

/// Route capability at which a message may be delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum DeliveryPolicy {
    EventIntegrated,
    ToolOnly,
    OfflineWorker,
    Unavailable,
}

/// Mailbox lifecycle. Delivery, acknowledgement, use and helpfulness remain
/// separate observations and are not fields on this lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LivePeerMessageState {
    Draft,
    Admitted,
    Queued,
    Delivered,
    Stale,
    Expired,
    Cancelled,
}

/// Public bounded peer delta.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LivePeerMessage {
    pub message_id: MessageId,
    pub sender_attempt_id: AgentAttemptId,
    pub sender_work_item_id: WorkItemId,
    pub recipients: Vec<RecipientRef>,
    pub plan_revision: RevisionId,
    pub wave_revision: RevisionId,
    pub kind: LivePeerMessageKind,
    pub concise_delta: String,
    pub evidence_refs: Vec<PublicReference>,
    pub requested_reaction: RequestedReaction,
    pub urgency: MessageUrgency,
    pub dedup_key: String,
    pub expires_at: Option<String>,
    pub delivery_policy: DeliveryPolicy,
    pub state: LivePeerMessageState,
    pub state_fence: StateFence,
}

impl LivePeerMessage {
    /// Validates recipients, payload bound, public-only evidence and fence.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.message_id.as_str(), "message_id")?;
        validate_text(self.sender_attempt_id.as_str(), "sender_attempt_id")?;
        validate_text(self.sender_work_item_id.as_str(), "sender_work_item_id")?;
        validate_text(self.plan_revision.as_str(), "plan_revision")?;
        validate_text(self.wave_revision.as_str(), "wave_revision")?;
        validate_text(&self.concise_delta, "concise_delta")?;
        if self.concise_delta.len() > MAX_DELTA_BYTES {
            return Err(ContractError::PayloadTooLarge("concise_delta"));
        }
        validate_text(&self.dedup_key, "dedup_key")?;
        validate_collection(&self.recipients, "recipients")?;
        for recipient in &self.recipients {
            recipient.validate()?;
            if recipient.attempt_id.as_ref() == Some(&self.sender_attempt_id)
                || recipient.work_item_id.as_ref() == Some(&self.sender_work_item_id)
            {
                return Err(ContractError::SelfRecipient);
            }
        }
        for reference in &self.evidence_refs {
            reference.validate()?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        Ok(())
    }

    /// Checks exact recipient and plan/wave identity against a frozen map.
    pub fn validate_against_map(&self, map: &CoordinationMapView) -> Result<(), ContractError> {
        self.validate()?;
        map.validate()?;
        if self.plan_revision != map.plan_revision || self.wave_revision != map.wave_revision {
            return Err(ContractError::StaleFence);
        }
        for recipient in &self.recipients {
            map.resolve_recipient(recipient)?;
        }
        Ok(())
    }
}

/// Review target class. Hidden reasoning has no variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewTargetKind {
    PublicMessage,
    PublicPlan,
    PublicRationale,
    ToolResult,
    Diff,
    Source,
    VerifierResult,
}

/// Exact immutable location in a public target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnchorReference {
    pub target: PublicReference,
    pub anchor_id: AnchorId,
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub context_digest: String,
    pub provenance: Option<ProvenanceReference>,
}

impl AnchorReference {
    /// Validates exact historical identity. It does not resolve current code.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.target.validate()?;
        validate_text(self.anchor_id.as_str(), "anchor_id")?;
        validate_text(&self.context_digest, "context_digest")?;
        if let (Some(start), Some(end)) = (self.line_start, self.line_end)
            && start > end
        {
            return Err(ContractError::InvalidReference);
        }
        if let Some(path) = &self.path {
            validate_text(path, "anchor.path")?;
        }
        if let Some(symbol) = &self.symbol {
            validate_text(symbol, "anchor.symbol")?;
        }
        if let Some(provenance) = &self.provenance {
            provenance.validate()?;
        }
        Ok(())
    }
}

/// Current-location resolution status for an immutable historical anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnchorResolutionStatus {
    Exact,
    Moved,
    Modified,
    Ambiguous,
    Stale,
    Deleted,
    Unavailable,
}

/// Rebuildable resolver result; it never silently selects an ambiguous target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnchorResolution {
    pub anchor_id: AnchorId,
    pub status: AnchorResolutionStatus,
    pub current_reference: Option<AnchorReference>,
    pub candidate_count: u32,
}

impl AnchorResolution {
    /// Returns whether a review may attach to this current location.
    pub fn admissible(&self) -> Result<(), ContractError> {
        match self.status {
            AnchorResolutionStatus::Exact
            | AnchorResolutionStatus::Moved
            | AnchorResolutionStatus::Modified => {
                if self.current_reference.is_some() {
                    Ok(())
                } else {
                    Err(ContractError::UnusableAnchor)
                }
            }
            AnchorResolutionStatus::Ambiguous => Err(ContractError::AmbiguousAnchor),
            AnchorResolutionStatus::Stale
            | AnchorResolutionStatus::Deleted
            | AnchorResolutionStatus::Unavailable => Err(ContractError::UnusableAnchor),
        }
    }
}

/// Review lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewLifecycle {
    Draft,
    PendingDelivery,
    Delivered,
    Answered,
    Resolved,
    RejectedWithReason,
    Stale,
    Superseded,
}

/// Review reason. The target is always public; no hidden reasoning variant is
/// expressible in this enum or in `AnchoredReviewItem`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    Question,
    Correction,
    Objection,
    RequestedChange,
    MissingEvidence,
    ScopeIssue,
    AcceptanceIssue,
}

/// One independently resolvable anchored review obligation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnchoredReviewItem {
    pub review_item_id: ReviewItemId,
    pub author_principal: PrincipalId,
    pub target_kind: ReviewTargetKind,
    pub original_target: AnchorReference,
    pub kind: ReviewKind,
    pub content: String,
    pub state_fence: StateFence,
    pub lifecycle: ReviewLifecycle,
    pub response_refs: Vec<PublicReference>,
    pub rejection_reason: Option<String>,
}

impl AnchoredReviewItem {
    /// Validates public target, immutable anchor and review lifecycle data.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.review_item_id.as_str(), "review_item_id")?;
        validate_text(self.author_principal.as_str(), "author_principal")?;
        self.original_target.validate()?;
        validate_text(&self.content, "content")?;
        if self.content.len() > MAX_DELTA_BYTES {
            return Err(ContractError::PayloadTooLarge("content"));
        }
        if self.lifecycle == ReviewLifecycle::RejectedWithReason {
            let reason = self
                .rejection_reason
                .as_deref()
                .ok_or(ContractError::MissingRejectionReason)?;
            validate_text(reason, "rejection_reason")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        for reference in &self.response_refs {
            reference.validate()?;
        }
        Ok(())
    }

    /// Validates that a rebuildable anchor result is safe to attach.
    pub fn validate_resolution(&self, resolution: &AnchorResolution) -> Result<(), ContractError> {
        self.validate()?;
        if resolution.anchor_id != self.original_target.anchor_id {
            return Err(ContractError::InvalidReference);
        }
        if resolution
            .current_reference
            .as_ref()
            .is_some_and(|reference| reference.target.id != self.original_target.target.id)
        {
            return Err(ContractError::InvalidReference);
        }
        resolution.admissible()
    }

    /// Applies the exact review lifecycle, requiring a rejection reason.
    pub fn transition_to(
        &mut self,
        next: ReviewLifecycle,
        reason: Option<String>,
    ) -> Result<(), ContractError> {
        let allowed = matches!(
            (self.lifecycle, next),
            (ReviewLifecycle::Draft, ReviewLifecycle::PendingDelivery)
                | (
                    ReviewLifecycle::PendingDelivery,
                    ReviewLifecycle::Delivered
                        | ReviewLifecycle::Stale
                        | ReviewLifecycle::Superseded
                )
                | (
                    ReviewLifecycle::Delivered,
                    ReviewLifecycle::Answered
                        | ReviewLifecycle::Stale
                        | ReviewLifecycle::Superseded
                )
                | (
                    ReviewLifecycle::Answered,
                    ReviewLifecycle::Resolved
                        | ReviewLifecycle::RejectedWithReason
                        | ReviewLifecycle::Stale
                        | ReviewLifecycle::Superseded
                )
        );
        if !allowed {
            return Err(transition_error(self.lifecycle, next));
        }
        if next == ReviewLifecycle::RejectedWithReason {
            let value = reason.ok_or(ContractError::MissingRejectionReason)?;
            validate_text(&value, "rejection_reason")?;
            self.rejection_reason = Some(value);
        }
        self.lifecycle = next;
        Ok(())
    }
}

/// Derived batch envelope. It has no lifecycle or authority of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewBatch {
    pub batch_id: TargetId,
    pub review_item_ids: Vec<ReviewItemId>,
    pub plan_revision: RevisionId,
}

impl ReviewBatch {
    /// Validates independent item identity and rejects duplicate obligations.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.batch_id.as_str(), "batch_id")?;
        validate_text(self.plan_revision.as_str(), "plan_revision")?;
        validate_collection(&self.review_item_ids, "review_item_ids")
    }
}

/// Continuity handoff mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum HandoffContinuity {
    NativeResume,
    NativeFork,
    Replayed,
    Rehydrated,
    Fresh,
}

/// Completeness of a causal handoff link.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCompleteness {
    Complete,
    Partial,
    Stale,
    Unknown,
}

/// Explicit public causal link between source and target attempts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCausalLink {
    pub handoff_id: HandoffId,
    pub source_attempt_id: AgentAttemptId,
    pub source_session_ref: PublicReference,
    pub source_state_fence: StateFence,
    pub source_revision: RevisionId,
    pub target_attempt_id: AgentAttemptId,
    pub target_route: Route,
    pub target_revision: RevisionId,
    pub continuity: HandoffContinuity,
    pub checkpoint_ref: PublicReference,
    pub omission_manifest_digest: String,
    pub replay_bundle_ref: Option<PublicReference>,
    pub post_resume_revalidation_ref: Option<PublicReference>,
    pub completeness: HandoffCompleteness,
}

impl HandoffCausalLink {
    /// Validates the non-secret causal handoff envelope.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.handoff_id.as_str(), "handoff_id")?;
        if self.source_attempt_id == self.target_attempt_id {
            return Err(ContractError::InvalidReference);
        }
        self.source_session_ref.validate()?;
        self.source_state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        self.target_route.validate()?;
        self.checkpoint_ref.validate()?;
        validate_text(&self.omission_manifest_digest, "omission_manifest_digest")?;
        if let Some(reference) = &self.replay_bundle_ref {
            reference.validate()?;
        }
        if let Some(reference) = &self.post_resume_revalidation_ref {
            reference.validate()?;
        }
        if self.completeness == HandoffCompleteness::Complete
            && (self.replay_bundle_ref.is_none() || self.post_resume_revalidation_ref.is_none())
        {
            return Err(ContractError::InvalidReference);
        }
        Ok(())
    }
}

/// Visible terminal state for one descendant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DescendantTerminalState {
    Completed,
    Partial,
    Failed,
    Cancelled,
    UnknownOutcome,
    Stale,
    Quarantined,
    Live,
}

/// Parent finish ceiling derived from descendant reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParentFinishCeiling {
    Complete,
    Partial,
    Blocked,
    UnknownOutcome,
}

/// One visible descendant disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescendantDisposition {
    pub attempt_id: AgentAttemptId,
    pub state: DescendantTerminalState,
    pub evidence_refs: Vec<PublicReference>,
}

/// Reconciliation receipt that prevents a parent from finishing with a lost
/// or hidden child.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescendantClosureReceipt {
    pub parent_ref: PublicReference,
    pub admitted_descendant_ids: Vec<AgentAttemptId>,
    pub lineage_revision: RevisionId,
    pub observed_runtime_refs: Vec<PublicReference>,
    pub dispositions: Vec<DescendantDisposition>,
    pub unreachable_or_unknown_ids: Vec<AgentAttemptId>,
    pub observation_coverage_ref: PublicReference,
    pub parent_finish_ceiling: ParentFinishCeiling,
    pub coordinator_evidence_refs: Vec<PublicReference>,
}

impl DescendantClosureReceipt {
    /// Validates no-lost-child closure and the finish ceiling.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.parent_ref.validate()?;
        validate_text(self.lineage_revision.as_str(), "lineage_revision")?;
        self.observation_coverage_ref.validate()?;
        validate_collection(&self.admitted_descendant_ids, "admitted_descendant_ids")?;
        if self
            .dispositions
            .iter()
            .map(|item| item.attempt_id.clone())
            .collect::<BTreeSet<_>>()
            .len()
            != self.dispositions.len()
        {
            return Err(ContractError::DuplicateItem("dispositions"));
        }
        for item in &self.dispositions {
            for reference in &item.evidence_refs {
                reference.validate()?;
            }
        }
        for reference in &self.observed_runtime_refs {
            reference.validate()?;
        }
        for reference in &self.coordinator_evidence_refs {
            reference.validate()?;
        }
        let admitted = self.admitted_descendant_ids.iter().collect::<BTreeSet<_>>();
        let disposed = self
            .dispositions
            .iter()
            .map(|item| &item.attempt_id)
            .collect::<BTreeSet<_>>();
        if !admitted.is_subset(&disposed) {
            return Err(ContractError::IncompleteDescendantClosure);
        }
        if self.parent_finish_ceiling == ParentFinishCeiling::Complete
            && (!self.unreachable_or_unknown_ids.is_empty()
                || self.dispositions.iter().any(|item| {
                    matches!(
                        item.state,
                        DescendantTerminalState::Live | DescendantTerminalState::UnknownOutcome
                    )
                }))
        {
            return Err(ContractError::LiveDescendantOnComplete);
        }
        Ok(())
    }
}

/// Deterministically identifies a contract shape for audit/codec compatibility.
pub fn contract_shape_digest<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes))
}

// ---------------------------------------------------------------------------
// Owner-separated swarm semantic records (I10.15, issue #1702).
//
// Task Controller owns `SwarmPlanDefinition` revisions; Governor owns
// `SwarmPlanAdmission`; AgentCoordinator owns `SwarmExecutionRevision` under
// an exact active admission. Lifecycles are I14.20; none of these records
// owns task truth (task finish remains I7.9). A derived `SwarmPlanView` may
// join them for reads but is never a write authority.
// ---------------------------------------------------------------------------

id_type!(
    /// Identity of one Task-Controller-owned swarm plan definition.
    SwarmDefinitionId
);
id_type!(
    /// Identity of one Governor-owned swarm plan admission.
    SwarmAdmissionId
);
id_type!(
    /// Identity of one coordinator-owned swarm execution revision.
    SwarmExecutionId
);

/// Task Controller lease binding: opaque holder plus epoch.
///
/// Identity only; the authority decision stays with the Task Controller
/// owner. A valid binding never proves its presenter holds the lease: every
/// write boundary rechecks the presenter against the current holder/epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerLease {
    /// Current lease holder identity.
    pub holder: String,
    /// Current lease epoch.
    pub epoch: u64,
}

impl TaskControllerLease {
    /// Validates the holder identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.holder, "task_controller_lease.holder")?;
        Ok(())
    }

    /// Returns whether the presenter is the current holder at the current
    /// epoch. Any mismatch fails closed; a digest or receipt never substitutes
    /// for this check.
    pub fn authorizes(&self, holder: &str, epoch: u64) -> bool {
        self.holder == holder && self.epoch == epoch
    }
}

/// Swarm coordinator lease binding: opaque holder plus epoch.
///
/// Identity only; execution authority stays with the `AgentCoordinator` owner
/// under the exact active admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwarmCoordinatorLease {
    /// Current lease holder identity.
    pub holder: String,
    /// Current lease epoch.
    pub epoch: u64,
}

impl SwarmCoordinatorLease {
    /// Validates the holder identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.holder, "swarm_coordinator_lease.holder")?;
        Ok(())
    }

    /// Returns whether the presenter is the current holder at the current
    /// epoch.
    pub fn authorizes(&self, holder: &str, epoch: u64) -> bool {
        self.holder == holder && self.epoch == epoch
    }
}

/// Admissible ceilings frozen at definition time.
///
/// Cross-owner references stay opaque validated handles: the closed policy
/// spellings live with their owning policy/capability authorities, never as
/// a second enum here. Numeric bounds are positive; zero is not a bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticCeilings {
    /// Privacy class handle pinned by the definition.
    pub privacy_class: String,
    /// Budget envelope handle pinned by the definition.
    pub budget_ref: String,
    /// Admissible route classes; non-empty and unique.
    pub route_classes: Vec<String>,
    /// Maximum orchestration depth; positive.
    pub max_depth: u32,
    /// Maximum fanout; positive.
    pub max_fanout: u32,
    /// Maximum fenced work in progress; positive.
    pub max_wip: u32,
}

impl SemanticCeilings {
    /// Validates handles, route-class uniqueness and positive bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(&self.privacy_class, "ceilings.privacy_class")?;
        validate_text(&self.budget_ref, "ceilings.budget_ref")?;
        validate_collection(&self.route_classes, "ceilings.route_classes")?;
        for class in &self.route_classes {
            validate_text(class, "ceilings.route_class")?;
        }
        if self.max_depth == 0 {
            return Err(ContractError::InvalidBound("ceilings.max_depth"));
        }
        if self.max_fanout == 0 {
            return Err(ContractError::InvalidBound("ceilings.max_fanout"));
        }
        if self.max_wip == 0 {
            return Err(ContractError::InvalidBound("ceilings.max_wip"));
        }
        Ok(())
    }

    /// Returns whether these ceilings narrow, never widen, `outer`.
    ///
    /// Governor may admit equal or narrower ceilings; widening scope, budget,
    /// privacy, routes, depth, fanout or WIP requires a new Task Controller
    /// definition revision instead.
    pub fn narrowed_from(&self, outer: &SemanticCeilings) -> bool {
        if self.privacy_class != outer.privacy_class || self.budget_ref != outer.budget_ref {
            return false;
        }
        if self.max_depth > outer.max_depth
            || self.max_fanout > outer.max_fanout
            || self.max_wip > outer.max_wip
        {
            return false;
        }
        let outer_routes = outer.route_classes.iter().collect::<BTreeSet<_>>();
        self.route_classes
            .iter()
            .all(|class| outer_routes.contains(class))
    }
}

/// I14.20 definition lifecycle: `DRAFT → FROZEN → SUPERSEDED | CANCELLED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmPlanDefinitionLifecycle {
    Draft,
    Frozen,
    Superseded,
    Cancelled,
}

impl SwarmPlanDefinitionLifecycle {
    /// Freezes a draft. Only `DRAFT → FROZEN` is admitted.
    pub fn freeze(self) -> Result<Self, ContractError> {
        match self {
            Self::Draft => Ok(Self::Frozen),
            from => Err(transition_error(from, "freeze")),
        }
    }

    /// Closes a draft or frozen definition. `FROZEN → SUPERSEDED |
    /// CANCELLED` and `DRAFT → CANCELLED` are admitted; terminal states never
    /// exit and a definition is never born superseded or cancelled.
    pub fn close(self, to: Self) -> Result<Self, ContractError> {
        match (self, to) {
            (Self::Draft | Self::Frozen, Self::Cancelled) | (Self::Frozen, Self::Superseded) => {
                Ok(to)
            }
            (from, to) => Err(transition_error(from, to)),
        }
    }
}

/// Explicit old-wave disposition proposed by the Task Controller and admitted
/// by Governor alongside the replacement definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OldWaveDisposition {
    Drain,
    Cancel,
    Supersede,
}

/// Link from a replacement definition to the exact prior revision it
/// replaces. A new definition never mutates a running wave in place; the
/// prior revision stays immutable history with an explicit disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupersessionLink {
    /// Prior definition identity being replaced.
    pub prior_definition_id: SwarmDefinitionId,
    /// Prior definition revision being replaced.
    pub prior_revision: RevisionId,
    /// Admitted disposition of the old wave.
    pub disposition: OldWaveDisposition,
}

/// I10.15 semantic object: immutable orchestration proposal bound to one
/// task/recipe revision.
///
/// Each revision is authored only by the Task Controller holder of
/// [`TaskControllerLease`]. Once frozen the content is immutable; subsequent
/// edits create a new linked revision carrying [`SupersessionLink`] rather
/// than replacing the record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanDefinition {
    /// Definition identity minted by the Task Controller owner.
    pub definition_id: SwarmDefinitionId,
    /// Definition revision within this identity.
    pub definition_revision: RevisionId,
    /// I14.20 lifecycle state.
    pub lifecycle: SwarmPlanDefinitionLifecycle,
    /// Bound task identity, preserved verbatim.
    pub task_id: String,
    /// Bound task revision, preserved verbatim.
    pub task_revision: String,
    /// Opaque versioned recipe manifest identity; no closed vendor enum.
    pub recipe_id: String,
    /// Recipe manifest revision.
    pub recipe_revision: RevisionId,
    /// Authoring Task Controller lease binding.
    pub controller: TaskControllerLease,
    /// Objective reference pinned by the definition.
    pub objective_ref: String,
    /// Acceptance references pinned by the definition; non-empty, unique.
    pub acceptance_refs: Vec<String>,
    /// Immutable shared root handle; a changed root creates a new wave and
    /// descendant revalidation, never an in-place substitution.
    pub root_context_revision: String,
    /// Digest of the immutable work-graph bytes.
    pub work_graph_digest: String,
    /// Digest over the full frozen content, bound at freeze time.
    pub definition_digest: String,
    /// Frozen privacy/budget/route/depth/fanout/WIP ceilings.
    pub ceilings: SemanticCeilings,
    /// Digest of the frozen stop conditions.
    pub stop_conditions_digest: String,
    /// Link to the replaced prior revision, if this is a replacement.
    pub supersedes: Option<SupersessionLink>,
    /// State fence pinned at freeze time.
    pub state_fence: StateFence,
}

#[derive(Serialize)]
struct SwarmDefinitionDigestInput<'a> {
    revision: &'static str,
    definition_id: &'a str,
    definition_revision: &'a str,
    task_id: &'a str,
    task_revision: &'a str,
    recipe_id: &'a str,
    recipe_revision: &'a str,
    controller_holder: &'a str,
    controller_epoch: u64,
    objective_ref: &'a str,
    acceptance_refs: &'a [String],
    root_context_revision: &'a str,
    work_graph_digest: &'a str,
    ceilings: &'a SemanticCeilings,
    stop_conditions_digest: &'a str,
    supersedes: &'a Option<SupersessionLink>,
    state_fence: &'a StateFence,
}

/// Wire revision of the definition-digest input shape.
pub const SWARM_DEFINITION_DIGEST_REVISION: &str = "eliot.swarm.definition-digest.v1";

impl SwarmPlanDefinition {
    /// Recomputes the content digest over the exact frozen fields.
    ///
    /// The lifecycle state is intentionally excluded: freezing advances
    /// `DRAFT → FROZEN` without rewriting content, so the digest stays stable
    /// across the freeze.
    pub fn content_digest(&self) -> Result<String, ContractError> {
        let input = SwarmDefinitionDigestInput {
            revision: SWARM_DEFINITION_DIGEST_REVISION,
            definition_id: self.definition_id.as_str(),
            definition_revision: self.definition_revision.as_str(),
            task_id: &self.task_id,
            task_revision: &self.task_revision,
            recipe_id: &self.recipe_id,
            recipe_revision: self.recipe_revision.as_str(),
            controller_holder: &self.controller.holder,
            controller_epoch: self.controller.epoch,
            objective_ref: &self.objective_ref,
            acceptance_refs: &self.acceptance_refs,
            root_context_revision: &self.root_context_revision,
            work_graph_digest: &self.work_graph_digest,
            ceilings: &self.ceilings,
            stop_conditions_digest: &self.stop_conditions_digest,
            supersedes: &self.supersedes,
            state_fence: &self.state_fence,
        };
        contract_shape_digest(&input)
            .map_err(|_| ContractError::BrokenOwnershipLink("definition_digest"))
    }

    /// Verifies the bound digest equals the recomputed content digest.
    ///
    /// A bare hash with no recoverable content is not accepted: the digest
    /// must recompute from the carried fields. Immutability is by content,
    /// not by label.
    pub fn verify_digest(&self) -> Result<(), ContractError> {
        validate_text(&self.definition_digest, "definition.definition_digest")?;
        let expected = self.content_digest()?;
        if expected != self.definition_digest {
            return Err(ContractError::BrokenOwnershipLink("definition_digest"));
        }
        Ok(())
    }

    /// Validates identity-bearing fields, lease, ceilings, references and the
    /// bound content digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.definition_id.as_str(), "definition.definition_id")?;
        validate_text(
            self.definition_revision.as_str(),
            "definition.definition_revision",
        )?;
        validate_text(&self.task_id, "definition.task_id")?;
        validate_text(&self.task_revision, "definition.task_revision")?;
        validate_text(&self.recipe_id, "definition.recipe_id")?;
        validate_text(self.recipe_revision.as_str(), "definition.recipe_revision")?;
        self.controller.validate()?;
        validate_text(&self.objective_ref, "definition.objective_ref")?;
        validate_collection(&self.acceptance_refs, "definition.acceptance_refs")?;
        for reference in &self.acceptance_refs {
            validate_text(reference, "definition.acceptance_ref")?;
        }
        validate_text(
            &self.root_context_revision,
            "definition.root_context_revision",
        )?;
        validate_text(&self.work_graph_digest, "definition.work_graph_digest")?;
        self.ceilings.validate()?;
        validate_text(
            &self.stop_conditions_digest,
            "definition.stop_conditions_digest",
        )?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        self.verify_digest()?;
        Ok(())
    }
}

/// I14.20 admission lifecycle: `PENDING → ADMITTED | REJECTED | STALE |
/// CANCELLED | SUPERSEDED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmPlanAdmissionDisposition {
    Pending,
    Admitted,
    Rejected,
    Stale,
    Cancelled,
    Superseded,
}

impl SwarmPlanAdmissionDisposition {
    /// Records the Governor disposition of one exact frozen definition.
    pub fn decide(self, to: Self) -> Result<Self, ContractError> {
        match (self, to) {
            (Self::Pending, Self::Admitted | Self::Rejected | Self::Stale | Self::Cancelled)
            | (Self::Admitted, Self::Stale | Self::Cancelled | Self::Superseded) => Ok(to),
            (from, to) => Err(transition_error(from, to)),
        }
    }
}

/// I10.15 semantic object: Governor-owned disposition of one exact frozen
/// [`SwarmPlanDefinition`].
///
/// Records admissible ceilings and a receipt but cannot rewrite the
/// definition or the substantive task choice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanAdmission {
    /// Admission identity minted by the Governor owner.
    pub admission_id: SwarmAdmissionId,
    /// Admitted definition identity.
    pub definition_id: SwarmDefinitionId,
    /// Exact frozen definition digest bound by this admission.
    pub definition_digest: String,
    /// I14.20 disposition state.
    pub disposition: SwarmPlanAdmissionDisposition,
    /// Admissible ceilings: equal to or narrower than the definition, never
    /// wider.
    pub admitted_ceilings: SemanticCeilings,
    /// Opaque Governor receipt handle.
    pub receipt: String,
    /// State fence under which the admission was recorded.
    pub state_fence: StateFence,
}

impl SwarmPlanAdmission {
    /// Validates identity-bearing fields, ceilings, receipt and fence.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.admission_id.as_str(), "admission.admission_id")?;
        validate_text(self.definition_id.as_str(), "admission.definition_id")?;
        validate_text(&self.definition_digest, "admission.definition_digest")?;
        self.admitted_ceilings.validate()?;
        validate_text(&self.receipt, "admission.receipt")?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        Ok(())
    }

    /// Returns whether this admission binds exactly the given definition.
    pub fn binds(&self, definition: &SwarmPlanDefinition) -> bool {
        self.definition_id == definition.definition_id
            && self.definition_digest == definition.definition_digest
    }

    /// Admits one exact frozen definition under equal or narrowed ceilings.
    ///
    /// Governor may admit, reject, narrow admissible execution or request a
    /// revised definition, but cannot rewrite the substantive task choice:
    /// ceilings that widen the definition fail closed here.
    pub fn admit_for(
        definition: &SwarmPlanDefinition,
        admission_id: SwarmAdmissionId,
        admitted_ceilings: SemanticCeilings,
        receipt: String,
        fence: StateFence,
    ) -> Result<Self, ContractError> {
        definition.validate()?;
        admitted_ceilings.validate()?;
        if definition.lifecycle != SwarmPlanDefinitionLifecycle::Frozen {
            return Err(ContractError::BrokenOwnershipLink(
                "only frozen definitions may be admitted",
            ));
        }
        if !admitted_ceilings.narrowed_from(&definition.ceilings) {
            return Err(ContractError::SemanticDrift(
                "admitted ceilings widen definition",
            ));
        }
        validate_text(&receipt, "admission.receipt")?;
        fence.validate().map_err(|_| ContractError::StaleFence)?;
        Ok(Self {
            admission_id,
            definition_id: definition.definition_id.clone(),
            definition_digest: definition.definition_digest.clone(),
            disposition: SwarmPlanAdmissionDisposition::Admitted,
            admitted_ceilings,
            receipt,
            state_fence: fence,
        })
    }
}

/// I10.15 semantic object: coordinator-owned execution/aggregation revision
/// for one admitted definition.
///
/// Owned by `AgentCoordinator` under [`SwarmCoordinatorLease`] and the exact
/// active admission; it advances execution mechanically and can never widen
/// the admitted plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwarmExecutionRevision {
    /// Execution identity minted by the coordinator owner.
    pub execution_id: SwarmExecutionId,
    /// Executed definition identity.
    pub definition_id: SwarmDefinitionId,
    /// Exact frozen definition digest under execution.
    pub definition_digest: String,
    /// Active admission this execution runs under.
    pub admission_id: SwarmAdmissionId,
    /// Current coordinator lease binding.
    pub coordinator: SwarmCoordinatorLease,
    /// Current execution wave.
    pub wave: RevisionId,
    /// Root handle of the current wave, bound to the definition root.
    pub root_context_revision: String,
    /// I14.20 execution lifecycle state, reusing the canonical
    /// [`SwarmExecutionState`] vocabulary.
    pub state: SwarmExecutionState,
    /// Bounded coverage-ledger handle; retained across reassignment, never
    /// reset.
    pub coverage_digest: String,
    /// State fence of the active admission.
    pub state_fence: StateFence,
}

impl SwarmExecutionRevision {
    /// Validates identity-bearing fields, lease, wave, coverage and fence.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.execution_id.as_str(), "execution.execution_id")?;
        validate_text(self.definition_id.as_str(), "execution.definition_id")?;
        validate_text(&self.definition_digest, "execution.definition_digest")?;
        validate_text(self.admission_id.as_str(), "execution.admission_id")?;
        self.coordinator.validate()?;
        validate_text(self.wave.as_str(), "execution.wave")?;
        validate_text(
            &self.root_context_revision,
            "execution.root_context_revision",
        )?;
        validate_text(&self.coverage_digest, "execution.coverage_digest")?;
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        Ok(())
    }

    /// Starts a new execution revision against one exact admitted definition.
    ///
    /// A new overlapping execution never starts until the old ownership is
    /// dispositioned through [`check_supersession`]; this constructor only
    /// binds a fresh execution to its definition and admission.
    pub fn begin(
        definition: &SwarmPlanDefinition,
        admission: &SwarmPlanAdmission,
        execution_id: SwarmExecutionId,
        coordinator: SwarmCoordinatorLease,
        wave: RevisionId,
        coverage_digest: String,
    ) -> Result<Self, ContractError> {
        definition.validate()?;
        admission.validate()?;
        coordinator.validate()?;
        validate_text(wave.as_str(), "execution.wave")?;
        validate_text(&coverage_digest, "execution.coverage_digest")?;
        if definition.lifecycle != SwarmPlanDefinitionLifecycle::Frozen {
            return Err(ContractError::BrokenOwnershipLink(
                "execution requires a frozen definition",
            ));
        }
        if admission.disposition != SwarmPlanAdmissionDisposition::Admitted {
            return Err(ContractError::BrokenOwnershipLink(
                "execution requires an admitted admission",
            ));
        }
        if !admission.binds(definition) {
            return Err(ContractError::BrokenOwnershipLink(
                "admission/definition binding",
            ));
        }
        if admission.state_fence != definition.state_fence {
            return Err(ContractError::StaleFence);
        }
        Ok(Self {
            execution_id,
            definition_id: definition.definition_id.clone(),
            definition_digest: definition.definition_digest.clone(),
            admission_id: admission.admission_id.clone(),
            coordinator,
            wave,
            root_context_revision: definition.root_context_revision.clone(),
            state: SwarmExecutionState::NotStarted,
            coverage_digest,
            state_fence: admission.state_fence.clone(),
        })
    }
}

/// Validates one I14.20 execution transition.
///
/// Exact replay (`from == to`) is not a transition and is admitted: same
/// identity replays exactly, changed content conflicts at the record layer.
pub fn check_execution_transition(
    from: SwarmExecutionState,
    to: SwarmExecutionState,
) -> Result<(), ContractError> {
    use SwarmExecutionState::{
        Cancelled, Completed, Failed, NotStarted, Partial, Paused, Reducing, Running,
        UnknownOutcome, Verifying,
    };
    if from == to {
        return Ok(());
    }
    match (from, to) {
        (NotStarted, Running | Cancelled)
        | (Running, Paused | Reducing | Cancelled | UnknownOutcome)
        | (Paused, Running | Reducing | Cancelled | UnknownOutcome)
        | (Reducing, Verifying | Cancelled | UnknownOutcome)
        | (Verifying, Completed | Partial | Failed | Cancelled | UnknownOutcome) => Ok(()),
        (from, to) => Err(transition_error(from, to)),
    }
}

/// Returns whether the execution state still advances mechanically.
pub fn execution_state_is_active(state: SwarmExecutionState) -> bool {
    use SwarmExecutionState::{Paused, Reducing, Running, Verifying};
    matches!(state, Running | Paused | Reducing | Verifying)
}

/// Mechanical execution update proposed by the coordinator holder.
///
/// Every semantic field is optional: absent means "advance mechanically,
/// change nothing". Present fields must equal the frozen admitted values
/// (ceilings must narrow, never widen); anything else is not an execution
/// update but a new definition revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionUpdateProposal {
    /// Execution being advanced; must equal the stored execution identity.
    pub execution_id: SwarmExecutionId,
    /// Wave being advanced; must equal the current wave. A new wave needs a
    /// new definition, never an in-place wave substitution.
    pub wave: RevisionId,
    /// Proposed work-graph digest, when the update carries one.
    pub work_graph_digest: Option<String>,
    /// Proposed objective reference, when the update carries one.
    pub objective_ref: Option<String>,
    /// Proposed acceptance references, when the update carries them.
    pub acceptance_refs: Option<Vec<String>>,
    /// Proposed ceilings, when the update carries them.
    pub ceilings: Option<SemanticCeilings>,
    /// Proposed stop-conditions digest, when the update carries one.
    pub stop_conditions_digest: Option<String>,
    /// Proposed root handle, when the update carries one.
    pub root_context_revision: Option<String>,
}

impl ExecutionUpdateProposal {
    /// Validates identity-bearing and carried semantic fields.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_text(self.execution_id.as_str(), "update.execution_id")?;
        validate_text(self.wave.as_str(), "update.wave")?;
        if let Some(digest) = &self.work_graph_digest {
            validate_text(digest, "update.work_graph_digest")?;
        }
        if let Some(objective) = &self.objective_ref {
            validate_text(objective, "update.objective_ref")?;
        }
        if let Some(acceptance) = &self.acceptance_refs {
            validate_collection(acceptance, "update.acceptance_refs")?;
            for reference in acceptance {
                validate_text(reference, "update.acceptance_ref")?;
            }
        }
        if let Some(ceilings) = &self.ceilings {
            ceilings.validate()?;
        }
        if let Some(digest) = &self.stop_conditions_digest {
            validate_text(digest, "update.stop_conditions_digest")?;
        }
        if let Some(root) = &self.root_context_revision {
            validate_text(root, "update.root_context_revision")?;
        }
        Ok(())
    }
}

/// Rejects an execution update that changes frozen plan semantics.
///
/// The coordinator may advance only execution fields under the current
/// [`SwarmCoordinatorLease`] and the exact active admission. Changing the
/// work graph, objective, acceptance, budget/privacy/route ceilings, stop
/// conditions, wave or root requires a new Task Controller definition
/// revision plus a new Governor admission; attempting it here fails with
/// [`ContractError::SemanticDrift`]. A stale or foreign coordinator fails
/// with [`ContractError::StaleLease`]; another owner's identity on the
/// update fails with [`ContractError::ForeignOwner`].
pub fn check_execution_update(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
    update: &ExecutionUpdateProposal,
    caller_holder: &str,
    caller_epoch: u64,
) -> Result<(), ContractError> {
    update.validate()?;
    definition.validate()?;
    admission.validate()?;
    execution.validate()?;
    if definition.lifecycle != SwarmPlanDefinitionLifecycle::Frozen {
        return Err(ContractError::BrokenOwnershipLink(
            "update requires a frozen definition",
        ));
    }
    if admission.disposition != SwarmPlanAdmissionDisposition::Admitted {
        return Err(ContractError::BrokenOwnershipLink(
            "update requires an admitted admission",
        ));
    }
    if !admission.binds(definition) {
        return Err(ContractError::BrokenOwnershipLink(
            "admission/definition binding",
        ));
    }
    if execution.definition_id != definition.definition_id
        || execution.definition_digest != definition.definition_digest
        || execution.admission_id != admission.admission_id
    {
        return Err(ContractError::BrokenOwnershipLink("execution binding"));
    }
    if !execution_state_is_active(execution.state) {
        return Err(ContractError::BrokenOwnershipLink(
            "execution is not active",
        ));
    }
    if !execution
        .coordinator
        .authorizes(caller_holder, caller_epoch)
    {
        return Err(ContractError::StaleLease("swarm coordinator"));
    }
    if update.execution_id != execution.execution_id {
        return Err(ContractError::ForeignOwner("update.execution_id"));
    }
    if update.wave != execution.wave {
        return Err(ContractError::SemanticDrift("update.wave"));
    }
    if update
        .work_graph_digest
        .as_ref()
        .is_some_and(|digest| digest != &definition.work_graph_digest)
    {
        return Err(ContractError::SemanticDrift("update.work_graph_digest"));
    }
    if update
        .objective_ref
        .as_ref()
        .is_some_and(|objective| objective != &definition.objective_ref)
    {
        return Err(ContractError::SemanticDrift("update.objective_ref"));
    }
    if update
        .acceptance_refs
        .as_ref()
        .is_some_and(|acceptance| acceptance != &definition.acceptance_refs)
    {
        return Err(ContractError::SemanticDrift("update.acceptance_refs"));
    }
    if update
        .ceilings
        .as_ref()
        .is_some_and(|ceilings| !ceilings.narrowed_from(&admission.admitted_ceilings))
    {
        return Err(ContractError::SemanticDrift("update.ceilings"));
    }
    if update
        .stop_conditions_digest
        .as_ref()
        .is_some_and(|digest| digest != &definition.stop_conditions_digest)
    {
        return Err(ContractError::SemanticDrift(
            "update.stop_conditions_digest",
        ));
    }
    if update.root_context_revision.as_ref().is_some_and(|root| {
        root != &definition.root_context_revision || root != &execution.root_context_revision
    }) {
        return Err(ContractError::SemanticDrift("update.root_context_revision"));
    }
    Ok(())
}

/// Checks that the presenter holds the current Task Controller lease for the
/// definition they author.
///
/// A valid payload digest never proves its author's authority: only an
/// authenticated holder of the current lease can author or freeze a
/// definition revision. Governor and coordinator holders always fail here.
pub fn check_definition_author(
    definition: &SwarmPlanDefinition,
    holder: &str,
    epoch: u64,
) -> Result<(), ContractError> {
    definition.validate()?;
    if definition.controller.authorizes(holder, epoch) {
        Ok(())
    } else {
        Err(ContractError::StaleLease("task controller"))
    }
}

/// Validates that a replacement definition links exactly one frozen prior
/// revision with an explicit old-wave disposition.
///
/// The replacement carries a distinct identity; content must differ (an
/// identical copy is a replay, not a revision); the new record starts
/// `DRAFT` or `FROZEN`, never born superseded or cancelled.
pub fn check_supersession(
    prior: &SwarmPlanDefinition,
    next: &SwarmPlanDefinition,
) -> Result<(), ContractError> {
    prior.validate()?;
    next.validate()?;
    if prior.lifecycle != SwarmPlanDefinitionLifecycle::Frozen {
        return Err(ContractError::BrokenOwnershipLink(
            "supersession requires a frozen prior",
        ));
    }
    let link = next
        .supersedes
        .as_ref()
        .ok_or(ContractError::BrokenOwnershipLink(
            "replacement without supersedes link",
        ))?;
    if link.prior_definition_id != prior.definition_id
        || link.prior_revision != prior.definition_revision
    {
        return Err(ContractError::BrokenOwnershipLink("supersedes link"));
    }
    if next.definition_id == prior.definition_id {
        return Err(ContractError::BrokenOwnershipLink(
            "replacement needs a distinct definition identity",
        ));
    }
    if !matches!(
        next.lifecycle,
        SwarmPlanDefinitionLifecycle::Draft | SwarmPlanDefinitionLifecycle::Frozen
    ) {
        return Err(transition_error(next.lifecycle, "superseding revision"));
    }
    if next.definition_digest == prior.definition_digest {
        return Err(ContractError::BrokenOwnershipLink(
            "replacement identical to prior",
        ));
    }
    Ok(())
}

/// Rebinds retained work to a new coordinator epoch after owner loss.
///
/// Only the affected owner's lease is replaced: the definition, admission,
/// wave, root, state and coverage bindings are preserved verbatim, so spend
/// is never reset and `UNKNOWN_OUTCOME` never becomes a clean failure.
/// History survives; only permission moves.
pub fn reassign_coordinator(
    execution: &SwarmExecutionRevision,
    new_coordinator: &SwarmCoordinatorLease,
) -> Result<SwarmExecutionRevision, ContractError> {
    execution.validate()?;
    new_coordinator.validate()?;
    let mut next = execution.clone();
    next.coordinator = new_coordinator.clone();
    next.validate()?;
    Ok(next)
}

/// Verifies the structural ownership links between stored records.
///
/// Reloads the committed owner records and verifies map-level links: the
/// admission binds exactly the definition, the execution binds exactly the
/// admission and definition, roots agree and fences agree. Lifecycle
/// coherence is NOT checked here: a draining old wave may legitimately rest
/// under a superseded admission, so rest-state structural integrity and
/// live current-authority coherence are separate decisions. Live paths use
/// [`check_owner_join`]; restart recovery uses this function and rehydrates
/// current authority independently afterwards.
pub fn check_stored_links(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
) -> Result<(), ContractError> {
    definition.validate()?;
    admission.validate()?;
    execution.validate()?;
    if !admission.binds(definition) {
        return Err(ContractError::BrokenOwnershipLink(
            "admission/definition binding",
        ));
    }
    if execution.definition_id != definition.definition_id
        || execution.definition_digest != definition.definition_digest
        || execution.admission_id != admission.admission_id
    {
        return Err(ContractError::BrokenOwnershipLink("execution binding"));
    }
    if execution.root_context_revision != definition.root_context_revision {
        return Err(ContractError::BrokenOwnershipLink("root context revision"));
    }
    if execution.state_fence != admission.state_fence {
        return Err(ContractError::BrokenOwnershipLink("execution fence"));
    }
    Ok(())
}

/// Validates the recovered ownership join as strictly as fresh admission.
///
/// Runs [`check_stored_links`] first, then enforces lifecycle coherence: an
/// active execution needs an admitted admission on a frozen definition; a
/// superseded or cancelled definition needs a matching admission
/// disposition. Contradictory snapshots stay an explicit blocked recovery
/// state instead of restoring authority.
pub fn check_owner_join(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
) -> Result<(), ContractError> {
    check_stored_links(definition, admission, execution)?;
    if execution_state_is_active(execution.state)
        && (admission.disposition != SwarmPlanAdmissionDisposition::Admitted
            || definition.lifecycle != SwarmPlanDefinitionLifecycle::Frozen)
    {
        return Err(ContractError::BrokenOwnershipLink(
            "active execution without admitted frozen plan",
        ));
    }
    match definition.lifecycle {
        SwarmPlanDefinitionLifecycle::Superseded => {
            if !matches!(
                admission.disposition,
                SwarmPlanAdmissionDisposition::Superseded
                    | SwarmPlanAdmissionDisposition::Cancelled
            ) {
                return Err(ContractError::BrokenOwnershipLink(
                    "superseded definition without matching admission",
                ));
            }
        }
        SwarmPlanDefinitionLifecycle::Cancelled => {
            if admission.disposition != SwarmPlanAdmissionDisposition::Cancelled {
                return Err(ContractError::BrokenOwnershipLink(
                    "cancelled definition without cancelled admission",
                ));
            }
        }
        SwarmPlanDefinitionLifecycle::Draft | SwarmPlanDefinitionLifecycle::Frozen => {}
    }
    Ok(())
}

/// Read-only joined view over the three owner records.
///
/// Exposes separate current revisions, applicability, a pending replacement
/// and unknown effects. The view is a projection: it owns nothing, authorizes
/// nothing, and joined reads never serve as write authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanView {
    /// Current definition identity.
    pub definition_id: SwarmDefinitionId,
    /// Current definition revision.
    pub definition_revision: RevisionId,
    /// Current definition lifecycle.
    pub definition_lifecycle: SwarmPlanDefinitionLifecycle,
    /// Current admission identity.
    pub admission_id: SwarmAdmissionId,
    /// Current admission disposition.
    pub admission_disposition: SwarmPlanAdmissionDisposition,
    /// Current execution identity.
    pub execution_id: SwarmExecutionId,
    /// Current execution state.
    pub execution_state: SwarmExecutionState,
    /// Pending replacement link, when a superseding revision is proposed.
    pub pending_replacement: Option<SupersessionLink>,
    /// Preserved unknown effects awaiting reconciliation.
    pub unknown_effects: Vec<String>,
}

/// Joins the three validated owner records into a read-only view.
pub fn join_view(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
    pending_replacement: Option<SupersessionLink>,
    unknown_effects: Vec<String>,
) -> Result<SwarmPlanView, ContractError> {
    check_owner_join(definition, admission, execution)?;
    for effect in &unknown_effects {
        validate_text(effect, "view.unknown_effect")?;
    }
    Ok(SwarmPlanView {
        definition_id: definition.definition_id.clone(),
        definition_revision: definition.definition_revision.clone(),
        definition_lifecycle: definition.lifecycle,
        admission_id: admission.admission_id.clone(),
        admission_disposition: admission.disposition,
        execution_id: execution.execution_id.clone(),
        execution_state: execution.state,
        pending_replacement,
        unknown_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
    }
    fn must<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => panic!("unexpected test construction error: {error:?}"),
        }
    }
    fn rev(value: &str) -> RevisionId {
        must(RevisionId::new(value))
    }
    fn attempt(value: &str) -> AgentAttemptId {
        must(AgentAttemptId::new(value))
    }
    fn work(value: &str) -> WorkItemId {
        must(WorkItemId::new(value))
    }
    fn target(value: &str) -> TargetId {
        must(TargetId::new(value))
    }

    fn route() -> Route {
        Route {
            route_id: must(RouteId::new("route")),
            adapter_id: "adapter".into(),
            fingerprint: "fp".into(),
            continuity: ContinuityKind::Fresh,
        }
    }
    fn reference(value: &str) -> PublicReference {
        PublicReference {
            kind: "artifact".into(),
            id: target(value),
            revision: rev("r1"),
            digest: None,
        }
    }

    #[test]
    fn attempt_state_machine_rejects_skip_and_accepts_run_path() -> Result<(), ContractError> {
        let mut value = AgentAttempt {
            attempt_id: attempt("a"),
            work_item_id: work("w"),
            route: route(),
            state: AgentAttemptState::Admitted,
            state_fence: fence(),
            evidence_refs: Vec::new(),
            parent_attempt_id: None,
        };
        assert!(value.transition_to(AgentAttemptState::Running).is_err());
        value.transition_to(AgentAttemptState::Provisioning)?;
        value.transition_to(AgentAttemptState::Launching)?;
        value.transition_to(AgentAttemptState::Running)?;
        value.validate()
    }

    #[test]
    fn invalid_recipient_and_self_recipient_fail_closed() -> Result<(), ContractError> {
        let map = CoordinationMapView {
            plan_revision: rev("p"),
            wave_revision: rev("w"),
            entries: vec![CoordinationEntry {
                work_item_id: work("other"),
                responsibility: "inspect".into(),
                dependency_ids: Vec::new(),
                overlap_ids: Vec::new(),
                assigned_attempt_id: Some(attempt("other-attempt")),
                assigned_role: None,
                mailbox_route_handle: None,
            }],
        };
        let message = LivePeerMessage {
            message_id: MessageId::new("m")?,
            sender_attempt_id: attempt("sender"),
            sender_work_item_id: work("sender-work"),
            recipients: vec![RecipientRef::work_item(work("missing"))],
            plan_revision: rev("p"),
            wave_revision: rev("w"),
            kind: LivePeerMessageKind::Obstacle,
            concise_delta: "x".into(),
            evidence_refs: Vec::new(),
            requested_reaction: RequestedReaction::Inform,
            urgency: MessageUrgency::Normal,
            dedup_key: "d".into(),
            expires_at: None,
            delivery_policy: DeliveryPolicy::OfflineWorker,
            state: LivePeerMessageState::Draft,
            state_fence: fence(),
        };
        assert_eq!(
            message.validate_against_map(&map),
            Err(ContractError::InvalidRecipient)
        );
        let mut self_message = message;
        self_message.recipients = vec![RecipientRef::attempt(attempt("sender"))];
        assert_eq!(self_message.validate(), Err(ContractError::SelfRecipient));
        Ok(())
    }

    #[test]
    fn hidden_reasoning_is_rejected_by_public_review_codec() {
        let input = r#"{"review_item_id":"r","author_principal":"p","target_kind":"public_message","original_target":{},"kind":"question","content":"ok","state_fence":{},"lifecycle":"DRAFT","response_refs":[],"hidden_reasoning":"secret"}"#;
        let decoded = serde_json::from_str::<AnchoredReviewItem>(input);
        assert!(decoded.is_err());
    }

    #[test]
    fn transcript_and_authority_fields_are_rejected_by_public_delta_codec() {
        let input = r#"{"message_id":"m","sender_attempt_id":"a","sender_work_item_id":"w","recipients":[],"plan_revision":"p","wave_revision":"w","kind":"obstacle","concise_delta":"x","evidence_refs":[],"requested_reaction":"inform","urgency":"normal","dedup_key":"d","expires_at":null,"delivery_policy":"OfflineWorker","state":"DRAFT","state_fence":{},"transcript":"private","authority":"finish"}"#;
        let decoded = serde_json::from_str::<LivePeerMessage>(input);
        assert!(decoded.is_err());
    }

    #[test]
    fn ambiguous_anchor_never_attaches() -> Result<(), ContractError> {
        let item = AnchoredReviewItem {
            review_item_id: ReviewItemId::new("review")?,
            author_principal: PrincipalId::new("author")?,
            target_kind: ReviewTargetKind::PublicMessage,
            original_target: AnchorReference {
                target: reference("message"),
                anchor_id: AnchorId::new("anchor")?,
                path: Some("src/lib.rs".into()),
                symbol: None,
                line_start: Some(1),
                line_end: Some(1),
                context_digest: "digest".into(),
                provenance: None,
            },
            kind: ReviewKind::Question,
            content: "check".into(),
            state_fence: fence(),
            lifecycle: ReviewLifecycle::Draft,
            response_refs: Vec::new(),
            rejection_reason: None,
        };
        let resolution = AnchorResolution {
            anchor_id: AnchorId::new("anchor")?,
            status: AnchorResolutionStatus::Ambiguous,
            current_reference: None,
            candidate_count: 2,
        };
        assert_eq!(
            item.validate_resolution(&resolution),
            Err(ContractError::AmbiguousAnchor)
        );
        Ok(())
    }

    #[test]
    fn false_anchor_target_is_rejected() -> Result<(), ContractError> {
        let item = AnchoredReviewItem {
            review_item_id: ReviewItemId::new("review")?,
            author_principal: PrincipalId::new("author")?,
            target_kind: ReviewTargetKind::Diff,
            original_target: AnchorReference {
                target: reference("diff"),
                anchor_id: AnchorId::new("anchor")?,
                path: None,
                symbol: None,
                line_start: None,
                line_end: None,
                context_digest: "digest".into(),
                provenance: None,
            },
            kind: ReviewKind::Correction,
            content: "fix".into(),
            state_fence: fence(),
            lifecycle: ReviewLifecycle::Draft,
            response_refs: Vec::new(),
            rejection_reason: None,
        };
        let resolution = AnchorResolution {
            anchor_id: AnchorId::new("anchor")?,
            status: AnchorResolutionStatus::Moved,
            current_reference: Some(AnchorReference {
                target: reference("other-diff"),
                anchor_id: AnchorId::new("anchor")?,
                path: None,
                symbol: None,
                line_start: None,
                line_end: None,
                context_digest: "digest".into(),
                provenance: None,
            }),
            candidate_count: 1,
        };
        assert_eq!(
            item.validate_resolution(&resolution),
            Err(ContractError::InvalidReference)
        );
        Ok(())
    }

    #[test]
    fn stale_plan_invalidates_live_peer_message() -> Result<(), ContractError> {
        let map = CoordinationMapView {
            plan_revision: rev("p2"),
            wave_revision: rev("w"),
            entries: vec![CoordinationEntry {
                work_item_id: work("other"),
                responsibility: "inspect".into(),
                dependency_ids: Vec::new(),
                overlap_ids: Vec::new(),
                assigned_attempt_id: None,
                assigned_role: None,
                mailbox_route_handle: None,
            }],
        };
        let message = LivePeerMessage {
            message_id: MessageId::new("m")?,
            sender_attempt_id: attempt("sender"),
            sender_work_item_id: work("sender-work"),
            recipients: vec![RecipientRef::work_item(work("other"))],
            plan_revision: rev("p1"),
            wave_revision: rev("w"),
            kind: LivePeerMessageKind::PlanContradiction,
            concise_delta: "revalidate".into(),
            evidence_refs: Vec::new(),
            requested_reaction: RequestedReaction::Revalidate,
            urgency: MessageUrgency::BeforeNextDependentEffect,
            dedup_key: "d".into(),
            expires_at: None,
            delivery_policy: DeliveryPolicy::OfflineWorker,
            state: LivePeerMessageState::Draft,
            state_fence: fence(),
        };
        assert_eq!(
            message.validate_against_map(&map),
            Err(ContractError::StaleFence)
        );
        Ok(())
    }

    #[test]
    fn complete_closure_rejects_live_or_unknown_descendant() {
        let receipt = DescendantClosureReceipt {
            parent_ref: reference("parent"),
            admitted_descendant_ids: vec![attempt("child")],
            lineage_revision: rev("l"),
            observed_runtime_refs: Vec::new(),
            dispositions: vec![DescendantDisposition {
                attempt_id: attempt("child"),
                state: DescendantTerminalState::Live,
                evidence_refs: Vec::new(),
            }],
            unreachable_or_unknown_ids: Vec::new(),
            observation_coverage_ref: reference("coverage"),
            parent_finish_ceiling: ParentFinishCeiling::Complete,
            coordinator_evidence_refs: Vec::new(),
        };
        assert_eq!(
            receipt.validate(),
            Err(ContractError::LiveDescendantOnComplete)
        );
    }

    #[test]
    fn serde_roundtrip_preserves_shape_digest() -> Result<(), Box<dyn std::error::Error>> {
        let route = route();
        let encoded = serde_json::to_string(&route)?;
        let decoded: Route = serde_json::from_str(&encoded)?;
        assert_eq!(
            contract_shape_digest(&route)?,
            contract_shape_digest(&decoded)?
        );
        Ok(())
    }

    #[test]
    fn rejected_review_requires_reason() -> Result<(), ContractError> {
        let item = AnchoredReviewItem {
            review_item_id: ReviewItemId::new("review")?,
            author_principal: PrincipalId::new("author")?,
            target_kind: ReviewTargetKind::Diff,
            original_target: AnchorReference {
                target: reference("diff"),
                anchor_id: AnchorId::new("anchor")?,
                path: None,
                symbol: None,
                line_start: None,
                line_end: None,
                context_digest: "digest".into(),
                provenance: None,
            },
            kind: ReviewKind::Correction,
            content: "fix".into(),
            state_fence: fence(),
            lifecycle: ReviewLifecycle::Answered,
            response_refs: Vec::new(),
            rejection_reason: None,
        };
        let mut item = item;
        assert_eq!(
            item.transition_to(ReviewLifecycle::RejectedWithReason, None),
            Err(ContractError::MissingRejectionReason)
        );
        item.transition_to(
            ReviewLifecycle::RejectedWithReason,
            Some("not applicable".into()),
        )?;
        assert_eq!(item.lifecycle, ReviewLifecycle::RejectedWithReason);
        Ok(())
    }
}
