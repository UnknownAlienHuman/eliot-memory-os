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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
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
