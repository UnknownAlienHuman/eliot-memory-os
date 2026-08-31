//! A-08's provider-neutral `ControlBoard` projection and operator contract.
//!
//! The board owns no canonical state, database, process, scheduler, authority,
//! or review store. It reads one injected canonical snapshot and forwards
//! typed commands to the owners selected by composition. Missing G-11/I-12
//! providers therefore remain an explicit `PLAN_GAP`; this crate never creates
//! a caller-mintable substitute.

#![forbid(unsafe_code)]

mod swarm_read;

pub use swarm_read::*;

use std::collections::BTreeSet;
use std::fmt;

use eliot_evaluation_contracts::ObjectiveStatus;
use eliot_evidence::{EpistemicStatus, EvidenceFreshness};
use eliot_observation_contracts::ObservationKind;
use eliot_receipts::ProofCeiling;
use eliot_security_contracts::{EffectCeiling, PrivacyClass};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable A-08 contract identity.
pub const CONTRACT_NAME: &str = "eliot.surfaces.controlboard/v1";
/// Typed unavailable marker used when an admitted owner is absent.
pub const PLAN_GAP: &str = "PLAN_GAP";

fn text(value: &str, field: &'static str) -> Result<(), ControlBoardError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ControlBoardError::InvalidField(field));
    }
    Ok(())
}

/// A non-zero immutable board revision supplied by the canonical owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ViewRevision(u64);

impl ViewRevision {
    /// Creates a non-zero revision.
    pub const fn new(value: u64) -> Result<Self, ControlBoardError> {
        if value == 0 {
            Err(ControlBoardError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric revision.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ViewRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A state fence carried by every read and command boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFence {
    /// Monotonic authority epoch from the owning state boundary.
    pub authority_epoch: u64,
    /// Revision at which this fence was observed.
    pub revision: ViewRevision,
    /// Opaque owner-issued fence identity.
    pub fence_id: String,
}

impl StateFence {
    /// Creates a validated fence; it does not grant authority.
    pub fn new(
        authority_epoch: u64,
        revision: ViewRevision,
        fence_id: impl Into<String>,
    ) -> Result<Self, ControlBoardError> {
        let fence = Self {
            authority_epoch,
            revision,
            fence_id: fence_id.into(),
        };
        fence.validate()?;
        Ok(fence)
    }

    fn validate(&self) -> Result<(), ControlBoardError> {
        if self.authority_epoch == 0 {
            return Err(ControlBoardError::InvalidField("authority_epoch"));
        }
        text(&self.fence_id, "fence_id")
    }
}

/// Authenticated role resolved by the session owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum Role {
    MainAgent,
    Watchdog,
    Dreamer,
    HumanRequester,
    HumanArchitectureOwner,
    HumanSystemOwner,
    HumanWorkScopeOwner,
    HumanApprover,
    HumanRecoveryPrincipal,
    HumanReadOnlyObserver,
    ReadOnlyApi,
}

/// Explicit action capabilities resolved by the authenticated owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionCapability {
    AcknowledgeAttention,
    ResolveAttention,
    Approve,
    PauseTask,
    CancelTask,
    ReplanTask,
    ChallengeRule,
    StartQuery,
    RecoveryAction,
    AcknowledgeReview,
    AnswerReview,
    ResolveReview,
    RejectReview,
}

/// Visibility selector attached by the canonical owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "role")]
pub enum Visibility {
    Public,
    RoleScoped(Role),
}

impl Visibility {
    fn permits(&self, role: Role) -> bool {
        matches!(self, Self::Public)
            || matches!(self, Self::RoleScoped(allowed) if *allowed == role)
    }
}

/// Inert request context supplied by an authenticated session boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub session_id: String,
    pub connection_id: String,
    pub credential_binding: String,
    pub challenge: String,
    pub request_id: String,
    pub generation: u64,
    /// Optional exact revision the caller is willing to inspect.
    pub expected_revision: Option<ViewRevision>,
    /// Optional exact fence the caller is willing to inspect.
    pub expected_fence: Option<StateFence>,
}

impl ReadRequest {
    /// Creates inert context; it grants no role, scope, privacy, or capability.
    pub fn new(
        session_id: impl Into<String>,
        connection_id: impl Into<String>,
        credential_binding: impl Into<String>,
        challenge: impl Into<String>,
        request_id: impl Into<String>,
        generation: u64,
    ) -> Result<Self, ControlBoardError> {
        let request = Self {
            session_id: session_id.into(),
            connection_id: connection_id.into(),
            credential_binding: credential_binding.into(),
            challenge: challenge.into(),
            request_id: request_id.into(),
            generation,
            expected_revision: None,
            expected_fence: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Pins the read to exact immutable identity.
    #[must_use]
    pub fn pinned(mut self, revision: ViewRevision, fence: StateFence) -> Self {
        self.expected_revision = Some(revision);
        self.expected_fence = Some(fence);
        self
    }

    fn validate(&self) -> Result<(), ControlBoardError> {
        text(&self.session_id, "session_id")?;
        text(&self.connection_id, "connection_id")?;
        text(&self.credential_binding, "credential_binding")?;
        text(&self.challenge, "challenge")?;
        text(&self.request_id, "request_id")?;
        if self.generation == 0 {
            return Err(ControlBoardError::InvalidField("generation"));
        }
        if let Some(fence) = &self.expected_fence {
            fence.validate()?;
        }
        Ok(())
    }
}

/// Authenticated access binding returned by the session/authority owner.
///
/// These fields are provider facts, never caller input. A-08 only consumes
/// this binding and never creates or widens it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessBinding {
    pub principal_id: String,
    pub work_scope: String,
    pub role: Role,
    pub admitted_privacy: Vec<PrivacyClass>,
    pub capabilities: Vec<ActionCapability>,
    pub session_id: String,
    pub connection_id: String,
    pub credential_binding: String,
    pub challenge: String,
    pub request_id: String,
    pub generation: u64,
    /// Provider-observed time bounds for the short-lived binding. These values
    /// are deliberately absent from `ReadRequest`: the caller cannot choose
    /// the clock used to decide freshness.
    pub issued_at_unix_ms: u64,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub access_revision: ViewRevision,
    pub authority_epoch: u64,
    pub access_fence_id: String,
}

impl AccessBinding {
    fn seal_for(&self, request: &ReadRequest) -> Result<ResolvedAccess, ControlBoardError> {
        text(&self.principal_id, "principal_id")?;
        text(&self.work_scope, "work_scope")?;
        text(&self.session_id, "session_id")?;
        text(&self.connection_id, "connection_id")?;
        text(&self.credential_binding, "credential_binding")?;
        text(&self.challenge, "challenge")?;
        text(&self.request_id, "request_id")?;
        text(&self.access_fence_id, "access_fence_id")?;
        if self.session_id != request.session_id
            || self.connection_id != request.connection_id
            || self.credential_binding != request.credential_binding
            || self.challenge != request.challenge
            || self.request_id != request.request_id
            || self.generation != request.generation
            || self.admitted_privacy.is_empty()
            || self.authority_epoch == 0
        {
            return Err(ControlBoardError::Unauthorized);
        }
        if self.issued_at_unix_ms == 0
            || self.observed_at_unix_ms < self.issued_at_unix_ms
            || self.observed_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(ControlBoardError::StaleAccess);
        }
        if request
            .expected_revision
            .is_some_and(|revision| revision != self.access_revision)
            || request.expected_fence.as_ref().is_some_and(|fence| {
                fence.revision != self.access_revision
                    || fence.authority_epoch != self.authority_epoch
                    || fence.fence_id != self.access_fence_id
            })
        {
            return Err(ControlBoardError::StaleAccess);
        }
        let mut privacy = BTreeSet::new();
        for class in &self.admitted_privacy {
            if !privacy.insert(*class as u8) {
                return Err(ControlBoardError::DuplicatePrivacyClass);
            }
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            if !capabilities.insert(*capability as u8) {
                return Err(ControlBoardError::DuplicateCapability);
            }
        }
        let digest = access_digest(self)?;
        Ok(ResolvedAccess {
            binding: self.clone(),
            digest,
        })
    }
}

fn access_digest(access: &AccessBinding) -> Result<String, ControlBoardError> {
    let mut privacy = access.admitted_privacy.clone();
    privacy.sort_by_key(|class| *class as u8);
    let mut capabilities = access.capabilities.clone();
    capabilities.sort_by_key(|capability| *capability as u8);
    let bytes = serde_json::to_vec(&(
        (
            &access.principal_id,
            &access.work_scope,
            access.role,
            privacy,
            capabilities,
        ),
        (
            &access.session_id,
            &access.connection_id,
            &access.credential_binding,
            &access.challenge,
            &access.request_id,
            access.generation,
        ),
        (
            access.issued_at_unix_ms,
            access.observed_at_unix_ms,
            access.expires_at_unix_ms,
            access.access_revision,
            access.authority_epoch,
            &access.access_fence_id,
        ),
    ))
    .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Clone, Debug)]
struct ResolvedAccess {
    binding: AccessBinding,
    digest: String,
}

impl ResolvedAccess {
    fn can(&self, capability: ActionCapability) -> bool {
        self.binding.capabilities.contains(&capability)
    }
}

/// Typed absence reasons for composition-owned providers.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredProvider {
    AccessResolver,
    CanonicalState,
    OperatorCommand,
    SwarmProjection,
    G11ReviewProjection,
    I12ReportProjection,
}

/// Provider failure that cannot be reinterpreted as a successful action.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code", content = "detail")]
pub enum PortError {
    #[error("provider denied the request")]
    Denied,
    #[error("provider unavailable")]
    Unavailable,
    #[error("provider outcome is unknown")]
    Unknown,
    #[error("provider contract is invalid: {0}")]
    Invalid(String),
}

/// A canonical board item. Content is already scoped by the owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardItem {
    pub item_id: String,
    pub kind: BoardItemKind,
    pub visibility: Visibility,
    pub privacy: PrivacyClass,
    pub summary: String,
    pub observation_kind: ObservationKind,
    pub epistemic_status: EpistemicStatus,
    pub evidence_freshness: EvidenceFreshness,
    pub objective_status: ObjectiveStatus,
}

/// Entity kind used to bind each operator action to its intended target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoardItemKind {
    Approval,
    Attention,
    Recovery,
    Rule,
    Task,
}

impl BoardItem {
    fn validate(&self) -> Result<(), ControlBoardError> {
        text(&self.item_id, "item_id")?;
        text(&self.summary, "summary")
    }
}

/// Stable anchor identity; the original target is never rewritten.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAnchor {
    pub target_kind: AnchorTargetKind,
    pub original_revision: ViewRevision,
    pub selector: String,
    pub resolution: AnchorResolution,
}

impl ReviewAnchor {
    fn validate(&self) -> Result<(), ControlBoardError> {
        text(&self.selector, "anchor.selector")
    }
}

/// Public artifact classes that may be reviewed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnchorTargetKind {
    PublicMessage,
    PublicPlan,
    PublicRationale,
    ToolResult,
    Diff,
    Source,
    VerifierResult,
}

/// Deterministic evolving-anchor result; ambiguity never auto-attaches.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnchorResolution {
    Exact,
    Moved,
    Modified,
    Ambiguous,
    Stale,
    Deleted,
    Unavailable,
}

/// Individual review obligation lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

impl ReviewLifecycle {
    /// Validates one lifecycle transition without mutating the source record.
    pub const fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Draft, Self::PendingDelivery | Self::Superseded)
                | (
                    Self::PendingDelivery,
                    Self::Delivered | Self::Stale | Self::Superseded
                )
                | (
                    Self::Delivered,
                    Self::Answered | Self::RejectedWithReason | Self::Stale | Self::Superseded
                )
                | (
                    Self::Answered,
                    Self::Resolved | Self::RejectedWithReason | Self::Stale | Self::Superseded
                )
        )
    }
}

/// A durable review obligation projected from the coordination owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItem {
    pub review_item_id: String,
    pub visibility: Visibility,
    pub privacy: PrivacyClass,
    pub anchor: ReviewAnchor,
    pub lifecycle: ReviewLifecycle,
    pub content: String,
    pub response_change_refs: Vec<String>,
}

impl ReviewItem {
    fn validate(&self) -> Result<(), ControlBoardError> {
        text(&self.review_item_id, "review_item_id")?;
        text(&self.content, "review.content")?;
        self.anchor.validate()?;
        let mut references = BTreeSet::new();
        for reference in &self.response_change_refs {
            text(reference, "review.response_change_ref")?;
            if !references.insert(reference) {
                return Err(ControlBoardError::DuplicateReference);
            }
        }
        Ok(())
    }
}

/// Attribution confidence for a provenance edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Attribution {
    Exact,
    ReceiptLinked,
    Correlated,
    Ambiguous,
    Unknown,
}

/// A rebuildable provenance projection edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEdge {
    pub edge_id: String,
    pub visibility: Visibility,
    pub privacy: PrivacyClass,
    pub from_id: String,
    pub to_id: String,
    pub attribution: Attribution,
    pub receipt_ref: Option<String>,
}

impl ProvenanceEdge {
    fn validate(&self) -> Result<(), ControlBoardError> {
        text(&self.edge_id, "edge_id")?;
        text(&self.from_id, "provenance.from_id")?;
        text(&self.to_id, "provenance.to_id")?;
        if let Some(receipt) = &self.receipt_ref {
            text(receipt, "provenance.receipt_ref")?;
        }
        Ok(())
    }
}

/// The single canonical state snapshot read from the owning provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalState {
    pub revision: ViewRevision,
    pub fence: StateFence,
    pub completeness: ProviderCompleteness,
    pub items: Vec<BoardItem>,
    pub reviews: Vec<ReviewItem>,
    pub provenance: Vec<ProvenanceEdge>,
}

impl CanonicalState {
    /// Validates exact identity and rejects duplicate projection records.
    pub fn validate(&self) -> Result<(), ControlBoardError> {
        if self.fence.revision != self.revision {
            return Err(ControlBoardError::FenceMismatch);
        }
        self.fence.validate()?;
        self.completeness.validate(self.revision, &self.fence)?;
        let mut ids = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !ids.insert(item.item_id.clone()) {
                return Err(ControlBoardError::DuplicateId(item.item_id.clone()));
            }
        }
        let mut review_ids = BTreeSet::new();
        for review in &self.reviews {
            review.validate()?;
            if !review_ids.insert(review.review_item_id.clone()) {
                return Err(ControlBoardError::DuplicateId(
                    review.review_item_id.clone(),
                ));
            }
        }
        let mut edge_ids = BTreeSet::new();
        for edge in &self.provenance {
            edge.validate()?;
            if !edge_ids.insert(edge.edge_id.clone()) {
                return Err(ControlBoardError::DuplicateId(edge.edge_id.clone()));
            }
        }
        Ok(())
    }
}

/// Exact projection-owner bindings required to distinguish empty data from a
/// missing G-11/I-12 projection provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCompleteness {
    pub g11_coordination: ProjectionBinding,
    pub i12_report_projection: ProjectionBinding,
}

impl ProviderCompleteness {
    fn validate(
        &self,
        revision: ViewRevision,
        fence: &StateFence,
    ) -> Result<(), ControlBoardError> {
        self.g11_coordination
            .validate(ProjectionProvider::G11, "G-11", revision, fence)?;
        self.i12_report_projection
            .validate(ProjectionProvider::I12, "I-12", revision, fence)?;
        if self.g11_coordination.binding_id == self.i12_report_projection.binding_id
            || self.g11_coordination.binding_digest == self.i12_report_projection.binding_digest
            || self.g11_coordination.receipt_ref == self.i12_report_projection.receipt_ref
        {
            return Err(ControlBoardError::PlanGap(
                RequiredProvider::G11ReviewProjection,
            ));
        }
        Ok(())
    }
}

/// Provider-issued identity binding for one required projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionBinding {
    pub provider: ProjectionProvider,
    pub work_id: String,
    pub binding_id: String,
    pub binding_revision: ViewRevision,
    pub binding_fence: StateFence,
    pub binding_digest: String,
    pub receipt_ref: String,
}

impl ProjectionBinding {
    fn validate(
        &self,
        expected_provider: ProjectionProvider,
        expected_work: &str,
        revision: ViewRevision,
        fence: &StateFence,
    ) -> Result<(), ControlBoardError> {
        if self.provider != expected_provider
            || self.work_id != expected_work
            || self.binding_revision != revision
            || self.binding_fence != *fence
            || self.binding_id == expected_work
            || self.binding_digest == expected_work
            || self.receipt_ref == expected_work
        {
            return Err(ControlBoardError::PlanGap(match expected_provider {
                ProjectionProvider::G11 => RequiredProvider::G11ReviewProjection,
                ProjectionProvider::I12 => RequiredProvider::I12ReportProjection,
            }));
        }
        let provider = match expected_provider {
            ProjectionProvider::G11 => RequiredProvider::G11ReviewProjection,
            ProjectionProvider::I12 => RequiredProvider::I12ReportProjection,
        };
        text(&self.work_id, "projection.work_id")
            .and_then(|()| text(&self.binding_id, "projection.binding_id"))
            .and_then(|()| text(&self.binding_digest, "projection.binding_digest"))
            .and_then(|()| text(&self.receipt_ref, "projection.receipt_ref"))
            .map_err(|_| ControlBoardError::PlanGap(provider))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionProvider {
    G11,
    I12,
}

/// The role/privacy-filtered immutable public projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardView {
    pub revision: ViewRevision,
    pub fence: StateFence,
    pub items: Vec<BoardItem>,
    pub reviews: Vec<ReviewItem>,
    pub provenance: Vec<ProvenanceEdge>,
}

/// Typed operator actions; no action carries authority or process handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum OperatorAction {
    AcknowledgeAttention {
        item_id: String,
    },
    ResolveAttention {
        item_id: String,
        reason: String,
    },
    Approve {
        item_id: String,
        approval_digest: String,
    },
    PauseTask {
        task_id: String,
    },
    CancelTask {
        task_id: String,
        reason: String,
    },
    ReplanTask {
        task_id: String,
        rationale: String,
    },
    ChallengeRule {
        rule_id: String,
        rationale: String,
    },
    StartQuery {
        query_kind: String,
    },
    RecoveryAction {
        action_id: String,
    },
    AcknowledgeReview {
        review_item_id: String,
    },
    AnswerReview {
        review_item_id: String,
        answer: String,
    },
    ResolveReview {
        review_item_id: String,
        reason: String,
    },
    RejectReview {
        review_item_id: String,
        reason: String,
    },
}

impl OperatorAction {
    fn target_id(&self) -> &str {
        match self {
            Self::AcknowledgeAttention { item_id }
            | Self::ResolveAttention { item_id, .. }
            | Self::Approve { item_id, .. }
            | Self::AcknowledgeReview {
                review_item_id: item_id,
            }
            | Self::AnswerReview {
                review_item_id: item_id,
                ..
            }
            | Self::ResolveReview {
                review_item_id: item_id,
                ..
            }
            | Self::RejectReview {
                review_item_id: item_id,
                ..
            }
            | Self::PauseTask { task_id: item_id }
            | Self::CancelTask {
                task_id: item_id, ..
            }
            | Self::ReplanTask {
                task_id: item_id, ..
            }
            | Self::ChallengeRule {
                rule_id: item_id, ..
            }
            | Self::RecoveryAction { action_id: item_id } => item_id,
            Self::StartQuery { query_kind } => query_kind,
        }
    }

    fn validate(&self) -> Result<(), ControlBoardError> {
        match self {
            Self::AcknowledgeAttention { item_id }
            | Self::ResolveAttention { item_id, .. }
            | Self::Approve { item_id, .. }
            | Self::AcknowledgeReview {
                review_item_id: item_id,
            }
            | Self::AnswerReview {
                review_item_id: item_id,
                ..
            }
            | Self::ResolveReview {
                review_item_id: item_id,
                ..
            }
            | Self::RejectReview {
                review_item_id: item_id,
                ..
            } => text(item_id, "action.target_id")?,
            Self::PauseTask { task_id }
            | Self::CancelTask { task_id, .. }
            | Self::ReplanTask { task_id, .. } => text(task_id, "action.task_id")?,
            Self::ChallengeRule { rule_id, .. } => text(rule_id, "action.rule_id")?,
            Self::StartQuery { query_kind } => text(query_kind, "action.query_kind")?,
            Self::RecoveryAction { action_id } => text(action_id, "action.action_id")?,
        }
        for value in self.textual_reasons() {
            text(value, "action.reason")?;
        }
        Ok(())
    }

    fn textual_reasons(&self) -> Vec<&str> {
        match self {
            Self::ResolveAttention { reason, .. }
            | Self::CancelTask { reason, .. }
            | Self::ResolveReview { reason, .. }
            | Self::RejectReview { reason, .. } => vec![reason],
            Self::ReplanTask { rationale, .. } | Self::ChallengeRule { rationale, .. } => {
                vec![rationale]
            }
            Self::AnswerReview { answer, .. } => vec![answer],
            Self::Approve {
                approval_digest, ..
            } => vec![approval_digest],
            _ => Vec::new(),
        }
    }
}

/// Command request bound to the exact view revision and fence observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub session_id: String,
    /// Set only by A-08 after the resolver seals the access binding.
    pub access_digest: String,
    pub expected_revision: ViewRevision,
    pub expected_fence: StateFence,
    pub action: OperatorAction,
    pub action_digest: String,
    /// Declares the maximum proof interpretation the caller can receive.
    pub proof_ceiling: ProofCeiling,
    /// Declares the effect class; the provider may narrow it further.
    pub effect_ceiling: EffectCeiling,
}

impl CommandRequest {
    /// Creates a request with no implicit authority.
    pub fn new(
        session_id: impl Into<String>,
        revision: ViewRevision,
        fence: StateFence,
        action: OperatorAction,
    ) -> Result<Self, ControlBoardError> {
        if fence.revision != revision {
            return Err(ControlBoardError::FenceMismatch);
        }
        action.validate()?;
        let session_id = session_id.into();
        text(&session_id, "session_id")?;
        let action_digest = action_digest(&action)?;
        Ok(Self {
            session_id,
            access_digest: String::new(),
            expected_revision: revision,
            expected_fence: fence,
            action,
            action_digest,
            proof_ceiling: ProofCeiling::Observation,
            effect_ceiling: EffectCeiling::CandidateOnly,
        })
    }

    fn validate_for(
        &self,
        request: &ReadRequest,
        access: &ResolvedAccess,
    ) -> Result<Self, ControlBoardError> {
        self.expected_fence.validate()?;
        self.action.validate()?;
        if self.session_id != request.session_id
            || self.expected_fence.revision != self.expected_revision
        {
            return Err(ControlBoardError::StaleView);
        }
        if self.proof_ceiling != ProofCeiling::Observation {
            return Err(ControlBoardError::InvalidField("proof_ceiling"));
        }
        if self.effect_ceiling != EffectCeiling::CandidateOnly {
            return Err(ControlBoardError::InvalidField("effect_ceiling"));
        }
        if !self.access_digest.is_empty() && self.access_digest != access.digest {
            return Err(ControlBoardError::ActionBindingMismatch);
        }
        if self.action_digest != action_digest(&self.action)? {
            return Err(ControlBoardError::ActionBindingMismatch);
        }
        let capability = self.action.required_capability();
        if !access.can(capability) {
            return Err(ControlBoardError::Unauthorized);
        }
        match self.action {
            OperatorAction::Approve { .. } if access.binding.role != Role::HumanApprover => {
                return Err(ControlBoardError::Unauthorized);
            }
            OperatorAction::RecoveryAction { .. }
                if access.binding.role != Role::HumanRecoveryPrincipal =>
            {
                return Err(ControlBoardError::Unauthorized);
            }
            _ => {}
        }
        let mut bound = self.clone();
        bound.access_digest.clone_from(&access.digest);
        Ok(bound)
    }
}

fn action_digest(action: &OperatorAction) -> Result<String, ControlBoardError> {
    let bytes = serde_json::to_vec(action)
        .map_err(|error| ControlBoardError::Provider(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Result returned by the owner of a typed operator action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReceipt {
    pub receipt_ref: String,
    pub session_id: String,
    pub access_digest: String,
    pub action_digest: String,
    pub proof_ceiling: ProofCeiling,
    pub effect_ceiling: EffectCeiling,
    pub disposition: CommandDisposition,
    pub observed_revision: ViewRevision,
    pub observed_fence: StateFence,
}

/// Receipt result; it is not task completion or release authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CommandDisposition {
    Accepted,
    Rejected,
    Unknown,
}

impl OperatorAction {
    fn required_capability(&self) -> ActionCapability {
        match self {
            Self::AcknowledgeAttention { .. } => ActionCapability::AcknowledgeAttention,
            Self::ResolveAttention { .. } => ActionCapability::ResolveAttention,
            Self::Approve { .. } => ActionCapability::Approve,
            Self::PauseTask { .. } => ActionCapability::PauseTask,
            Self::CancelTask { .. } => ActionCapability::CancelTask,
            Self::ReplanTask { .. } => ActionCapability::ReplanTask,
            Self::ChallengeRule { .. } => ActionCapability::ChallengeRule,
            Self::StartQuery { .. } => ActionCapability::StartQuery,
            Self::RecoveryAction { .. } => ActionCapability::RecoveryAction,
            Self::AcknowledgeReview { .. } => ActionCapability::AcknowledgeReview,
            Self::AnswerReview { .. } => ActionCapability::AnswerReview,
            Self::ResolveReview { .. } => ActionCapability::ResolveReview,
            Self::RejectReview { .. } => ActionCapability::RejectReview,
        }
    }
}

/// Canonical state owner port. Implementations must return one immutable snapshot.
pub trait CanonicalStatePort: Send {
    /// Reads canonical state for the authenticated request.
    fn read(
        &mut self,
        request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<CanonicalState, PortError>;
}

/// Authenticated session/access owner port. It is the only source of role,
/// scope, privacy, and operator capabilities.
pub trait AccessResolverPort: Send {
    /// Resolves inert request context into provider-owned access facts.
    fn resolve(&mut self, request: &ReadRequest) -> Result<AccessBinding, PortError>;
}

/// Operator command owner port. It is the only route for mutation requests.
pub trait OperatorCommandPort: Send {
    /// Submits one exact-fence typed action to its owning authority path.
    fn submit(&mut self, request: &CommandRequest) -> Result<CommandReceipt, PortError>;
}

/// A-08 surface over sealed provider boundaries.
pub struct ControlBoard {
    access: Option<Box<dyn AccessResolverPort>>,
    state: Option<Box<dyn CanonicalStatePort>>,
    commands: Option<Box<dyn OperatorCommandPort>>,
    swarm_projection: Option<Box<dyn SwarmProjectionPort>>,
}

impl ControlBoard {
    /// Injects the canonical read and command providers selected by composition.
    pub fn new(
        access: Option<Box<dyn AccessResolverPort>>,
        state: Option<Box<dyn CanonicalStatePort>>,
        commands: Option<Box<dyn OperatorCommandPort>>,
    ) -> Self {
        Self {
            access,
            state,
            commands,
            swarm_projection: None,
        }
    }

    /// Returns one role/privacy-filtered view over canonical state.
    pub fn view(&mut self, request: &ReadRequest) -> Result<ControlBoardView, ControlBoardError> {
        request.validate()?;
        let access = self.resolve_access(request)?;
        self.view_with_access(request, &access)
    }

    fn resolve_access(
        &mut self,
        request: &ReadRequest,
    ) -> Result<ResolvedAccess, ControlBoardError> {
        let access = self
            .access
            .as_mut()
            .ok_or(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))?
            .resolve(request)
            .map_err(|error| {
                ControlBoardError::from_port(RequiredProvider::AccessResolver, error)
            })?;
        access.seal_for(request)
    }

    fn view_with_access(
        &mut self,
        request: &ReadRequest,
        access: &ResolvedAccess,
    ) -> Result<ControlBoardView, ControlBoardError> {
        let state = self
            .state
            .as_mut()
            .ok_or(ControlBoardError::PlanGap(RequiredProvider::CanonicalState))?
            .read(request, &access.binding)
            .map_err(|error| {
                ControlBoardError::from_port(RequiredProvider::CanonicalState, error)
            })?;
        state.validate()?;
        if state.revision != access.binding.access_revision
            || state.fence.authority_epoch != access.binding.authority_epoch
            || state.fence.fence_id != access.binding.access_fence_id
        {
            return Err(ControlBoardError::StaleAccess);
        }
        if request
            .expected_revision
            .is_some_and(|expected| expected != state.revision)
            || request
                .expected_fence
                .as_ref()
                .is_some_and(|expected| expected != &state.fence)
        {
            return Err(ControlBoardError::StaleView);
        }
        Ok(filter_view(state, &access.binding))
    }

    /// Sends a typed action after re-reading and checking its exact fence.
    #[allow(clippy::needless_pass_by_value)]
    pub fn submit(
        &mut self,
        request: &ReadRequest,
        command: CommandRequest,
    ) -> Result<CommandReceipt, ControlBoardError> {
        request.validate()?;
        let access = self.resolve_access(request)?;
        let command = command.validate_for(request, &access)?;
        let view = self.view_with_access(
            &request
                .clone()
                .pinned(command.expected_revision, command.expected_fence.clone()),
            &access,
        )?;
        if view.revision != command.expected_revision || view.fence != command.expected_fence {
            return Err(ControlBoardError::StaleView);
        }
        validate_action_target(&view, &command.action)?;
        let receipt = self
            .commands
            .as_mut()
            .ok_or(ControlBoardError::PlanGap(
                RequiredProvider::OperatorCommand,
            ))?
            .submit(&command)
            .map_err(|error| {
                ControlBoardError::from_port(RequiredProvider::OperatorCommand, error)
            })?;
        validate_receipt(&receipt, &command)?;
        Ok(receipt)
    }
}

fn validate_action_target(
    view: &ControlBoardView,
    action: &OperatorAction,
) -> Result<(), ControlBoardError> {
    if matches!(action, OperatorAction::StartQuery { .. }) {
        return Ok(());
    }
    let target = action.target_id();
    let review = view
        .reviews
        .iter()
        .find(|review| review.review_item_id == target);
    let item = view.items.iter().find(|item| item.item_id == target);
    let is_review_action = matches!(
        action,
        OperatorAction::AcknowledgeReview { .. }
            | OperatorAction::AnswerReview { .. }
            | OperatorAction::ResolveReview { .. }
            | OperatorAction::RejectReview { .. }
    );
    if is_review_action && item.is_some() {
        return Err(ControlBoardError::WrongTargetKind);
    }
    if !is_review_action && review.is_some() {
        return Err(ControlBoardError::WrongTargetKind);
    }
    if let Some(review) = review {
        let legal = match action {
            OperatorAction::AcknowledgeReview { .. } => {
                review.lifecycle == ReviewLifecycle::Delivered
            }
            OperatorAction::AnswerReview { .. } => review.lifecycle == ReviewLifecycle::Delivered,
            OperatorAction::ResolveReview { .. } => review.lifecycle == ReviewLifecycle::Answered,
            OperatorAction::RejectReview { .. } => matches!(
                review.lifecycle,
                ReviewLifecycle::Delivered | ReviewLifecycle::Answered
            ),
            _ => true,
        };
        if !legal {
            return Err(ControlBoardError::InvalidReviewTransition);
        }
    } else if let Some(item) = item {
        let expected = match action {
            OperatorAction::AcknowledgeAttention { .. }
            | OperatorAction::ResolveAttention { .. } => BoardItemKind::Attention,
            OperatorAction::Approve { .. } => BoardItemKind::Approval,
            OperatorAction::PauseTask { .. }
            | OperatorAction::CancelTask { .. }
            | OperatorAction::ReplanTask { .. } => BoardItemKind::Task,
            OperatorAction::ChallengeRule { .. } => BoardItemKind::Rule,
            OperatorAction::RecoveryAction { .. } => BoardItemKind::Recovery,
            _ => return Err(ControlBoardError::WrongTargetKind),
        };
        if item.kind != expected {
            return Err(ControlBoardError::WrongTargetKind);
        }
    } else {
        return Err(ControlBoardError::HiddenOrMissingTarget);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &CommandReceipt,
    request: &CommandRequest,
) -> Result<(), ControlBoardError> {
    text(&receipt.receipt_ref, "receipt_ref")?;
    text(&receipt.session_id, "receipt.session_id")?;
    text(&receipt.access_digest, "receipt.access_digest")?;
    if receipt.session_id != request.session_id
        || receipt.access_digest != request.access_digest
        || receipt.action_digest != request.action_digest
        || receipt.observed_revision != request.expected_revision
        || receipt.observed_fence != request.expected_fence
    {
        return Err(ControlBoardError::ReceiptBindingMismatch);
    }
    if !receipt.proof_ceiling.is_at_most(request.proof_ceiling)
        || !effect_is_at_most(receipt.effect_ceiling, request.effect_ceiling)
    {
        return Err(ControlBoardError::ReceiptOverclaim);
    }
    Ok(())
}

fn effect_is_at_most(observed: EffectCeiling, requested: EffectCeiling) -> bool {
    matches!(
        (observed, requested),
        (
            EffectCeiling::ReadOnly,
            EffectCeiling::ReadOnly
                | EffectCeiling::CandidateOnly
                | EffectCeiling::NoExternalEffect
        ) | (
            EffectCeiling::CandidateOnly,
            EffectCeiling::CandidateOnly | EffectCeiling::NoExternalEffect
        ) | (
            EffectCeiling::NoExternalEffect,
            EffectCeiling::NoExternalEffect
        )
    )
}

fn filter_view(state: CanonicalState, access: &AccessBinding) -> ControlBoardView {
    let permitted = |visibility: &Visibility, privacy: PrivacyClass| {
        visibility.permits(access.role) && access.admitted_privacy.contains(&privacy)
    };
    let items: Vec<BoardItem> = state
        .items
        .into_iter()
        .filter(|item| permitted(&item.visibility, item.privacy))
        .collect();
    let visible_ids: BTreeSet<String> = items
        .iter()
        .map(|item: &BoardItem| item.item_id.clone())
        .collect();
    let reviews: Vec<ReviewItem> = state
        .reviews
        .into_iter()
        .filter(|review| permitted(&review.visibility, review.privacy))
        .collect();
    let visible_review_ids: BTreeSet<String> = reviews
        .iter()
        .map(|review: &ReviewItem| review.review_item_id.clone())
        .collect();
    let provenance: Vec<ProvenanceEdge> = state
        .provenance
        .into_iter()
        .filter(|edge| {
            permitted(&edge.visibility, edge.privacy)
                && (visible_ids.contains(&edge.from_id)
                    || visible_review_ids.contains(&edge.from_id))
                && (visible_ids.contains(&edge.to_id) || visible_review_ids.contains(&edge.to_id))
        })
        .collect();
    ControlBoardView {
        revision: state.revision,
        fence: state.fence,
        items,
        reviews,
        provenance,
    }
}

/// Fail-closed A-08 errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlBoardError {
    #[error("PLAN_GAP: required provider unavailable: {0:?}")]
    PlanGap(RequiredProvider),
    #[error("stale or mismatched view revision/fence")]
    StaleView,
    #[error("stale or expired access binding")]
    StaleAccess,
    #[error("state fence does not match its revision")]
    FenceMismatch,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate projection identity: {0}")]
    DuplicateId(String),
    #[error("duplicate admitted privacy class")]
    DuplicatePrivacyClass,
    #[error("duplicate action capability")]
    DuplicateCapability,
    #[error("duplicate reference")]
    DuplicateReference,
    #[error("action binding does not match canonical action bytes")]
    ActionBindingMismatch,
    #[error("Swarm projection source digest does not match canonical bytes")]
    SwarmSourceDigestMismatch,
    #[error("hidden or missing action target")]
    HiddenOrMissingTarget,
    #[error("action target has the wrong entity kind")]
    WrongTargetKind,
    #[error("review lifecycle transition is not permitted")]
    InvalidReviewTransition,
    #[error("command receipt binding or fence mismatch")]
    ReceiptBindingMismatch,
    #[error("command receipt exceeds requested proof/effect ceiling")]
    ReceiptOverclaim,
    #[error("provider denied the operation")]
    Unauthorized,
    #[error("provider outcome is unknown")]
    UnknownOutcome,
    #[error("provider contract failure: {0}")]
    Provider(String),
}

impl ControlBoardError {
    fn from_port(provider: RequiredProvider, error: PortError) -> Self {
        match error {
            PortError::Denied => Self::Unauthorized,
            PortError::Unavailable => Self::PlanGap(provider),
            PortError::Unknown => Self::UnknownOutcome,
            PortError::Invalid(detail) => Self::Provider(detail),
        }
    }
}

impl fmt::Display for RequiredProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessResolver => "ACCESS_RESOLVER",
            Self::CanonicalState => "CANONICAL_STATE",
            Self::OperatorCommand => "OPERATOR_COMMAND",
            Self::SwarmProjection => "SWARM_PROJECTION",
            Self::G11ReviewProjection => "G11_REVIEW_PROJECTION",
            Self::I12ReportProjection => "I12_REPORT_PROJECTION",
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    struct FakeRead {
        state: CanonicalState,
    }

    struct FakeAccess {
        binding: AccessBinding,
    }

    impl AccessResolverPort for FakeAccess {
        fn resolve(&mut self, _request: &ReadRequest) -> Result<AccessBinding, PortError> {
            Ok(self.binding.clone())
        }
    }

    impl CanonicalStatePort for FakeRead {
        fn read(
            &mut self,
            _request: &ReadRequest,
            _access: &AccessBinding,
        ) -> Result<CanonicalState, PortError> {
            Ok(self.state.clone())
        }
    }

    struct FakeCommand;

    impl OperatorCommandPort for FakeCommand {
        fn submit(&mut self, request: &CommandRequest) -> Result<CommandReceipt, PortError> {
            Ok(CommandReceipt {
                receipt_ref: "receipt-1".to_owned(),
                session_id: request.session_id.clone(),
                access_digest: request.access_digest.clone(),
                action_digest: request.action_digest.clone(),
                proof_ceiling: request.proof_ceiling,
                effect_ceiling: request.effect_ceiling,
                disposition: CommandDisposition::Accepted,
                observed_revision: request.expected_revision,
                observed_fence: request.expected_fence.clone(),
            })
        }
    }

    struct BadCommand;

    impl OperatorCommandPort for BadCommand {
        fn submit(&mut self, request: &CommandRequest) -> Result<CommandReceipt, PortError> {
            Ok(CommandReceipt {
                receipt_ref: String::new(),
                session_id: "other-session".to_owned(),
                access_digest: "other-access".to_owned(),
                action_digest: request.action_digest.clone(),
                proof_ceiling: request.proof_ceiling,
                effect_ceiling: request.effect_ceiling,
                disposition: CommandDisposition::Accepted,
                observed_revision: request.expected_revision,
                observed_fence: request.expected_fence.clone(),
            })
        }
    }

    struct WrongAccessCommand;

    impl OperatorCommandPort for WrongAccessCommand {
        fn submit(&mut self, request: &CommandRequest) -> Result<CommandReceipt, PortError> {
            Ok(CommandReceipt {
                receipt_ref: "receipt-wrong-access".to_owned(),
                session_id: request.session_id.clone(),
                access_digest: "not-the-sealed-access".to_owned(),
                action_digest: request.action_digest.clone(),
                proof_ceiling: request.proof_ceiling,
                effect_ceiling: request.effect_ceiling,
                disposition: CommandDisposition::Accepted,
                observed_revision: request.expected_revision,
                observed_fence: request.expected_fence.clone(),
            })
        }
    }

    fn fence() -> StateFence {
        StateFence::new(1, ViewRevision::new(7).expect("revision"), "fence-7").expect("fence")
    }

    fn state() -> CanonicalState {
        CanonicalState {
            revision: ViewRevision::new(7).expect("revision"),
            fence: fence(),
            completeness: ProviderCompleteness {
                g11_coordination: projection_binding(
                    ProjectionProvider::G11,
                    "G-11",
                    "g11-binding",
                    "g11-receipt",
                ),
                i12_report_projection: projection_binding(
                    ProjectionProvider::I12,
                    "I-12",
                    "i12-binding",
                    "i12-receipt",
                ),
            },
            items: vec![
                BoardItem {
                    item_id: "public".to_owned(),
                    kind: BoardItemKind::Task,
                    visibility: Visibility::Public,
                    privacy: PrivacyClass::Public,
                    summary: "public item".to_owned(),
                    observation_kind: ObservationKind::TaskProgress,
                    epistemic_status: EpistemicStatus::Observed,
                    evidence_freshness: EvidenceFreshness::ExactCandidate,
                    objective_status: ObjectiveStatus::Active,
                },
                BoardItem {
                    item_id: "human-only".to_owned(),
                    kind: BoardItemKind::Task,
                    visibility: Visibility::RoleScoped(Role::HumanReadOnlyObserver),
                    privacy: PrivacyClass::Private,
                    summary: "private item".to_owned(),
                    observation_kind: ObservationKind::Security,
                    epistemic_status: EpistemicStatus::Unknown,
                    evidence_freshness: EvidenceFreshness::Unknown,
                    objective_status: ObjectiveStatus::Active,
                },
            ],
            reviews: vec![ReviewItem {
                review_item_id: "review-1".to_owned(),
                visibility: Visibility::Public,
                privacy: PrivacyClass::Public,
                anchor: ReviewAnchor {
                    target_kind: AnchorTargetKind::Diff,
                    original_revision: ViewRevision::new(7).expect("revision"),
                    selector: "src/lib.rs:1".to_owned(),
                    resolution: AnchorResolution::Ambiguous,
                },
                lifecycle: ReviewLifecycle::Delivered,
                content: "inspect this public diff".to_owned(),
                response_change_refs: Vec::new(),
            }],
            provenance: vec![
                ProvenanceEdge {
                    edge_id: "edge-1".to_owned(),
                    visibility: Visibility::Public,
                    privacy: PrivacyClass::Public,
                    from_id: "public".to_owned(),
                    to_id: "review-1".to_owned(),
                    attribution: Attribution::Unknown,
                    receipt_ref: None,
                },
                ProvenanceEdge {
                    edge_id: "hidden-edge".to_owned(),
                    visibility: Visibility::Public,
                    privacy: PrivacyClass::Public,
                    from_id: "public".to_owned(),
                    to_id: "human-only".to_owned(),
                    attribution: Attribution::Unknown,
                    receipt_ref: None,
                },
            ],
        }
    }

    fn read_request(_role: Role) -> ReadRequest {
        ReadRequest::new(
            "session",
            "connection",
            "credential",
            "challenge",
            "request",
            1,
        )
        .expect("request")
    }

    fn projection_binding(
        provider: ProjectionProvider,
        work_id: &str,
        binding_id: &str,
        receipt_ref: &str,
    ) -> ProjectionBinding {
        ProjectionBinding {
            provider,
            work_id: work_id.to_owned(),
            binding_id: binding_id.to_owned(),
            binding_revision: ViewRevision::new(7).expect("revision"),
            binding_fence: fence(),
            binding_digest: format!("{binding_id}-digest"),
            receipt_ref: receipt_ref.to_owned(),
        }
    }

    fn access(
        role: Role,
        capabilities: &[ActionCapability],
        privacy: &[PrivacyClass],
    ) -> FakeAccess {
        FakeAccess {
            binding: AccessBinding {
                principal_id: "principal".to_owned(),
                work_scope: "scope".to_owned(),
                role,
                admitted_privacy: privacy.to_vec(),
                capabilities: capabilities.to_vec(),
                session_id: "session".to_owned(),
                connection_id: "connection".to_owned(),
                credential_binding: "credential".to_owned(),
                challenge: "challenge".to_owned(),
                request_id: "request".to_owned(),
                generation: 1,
                issued_at_unix_ms: 1_000,
                observed_at_unix_ms: 1_100,
                expires_at_unix_ms: 2_000,
                access_revision: ViewRevision::new(7).expect("revision"),
                authority_epoch: 1,
                access_fence_id: "fence-7".to_owned(),
            },
        }
    }

    #[test]
    fn role_and_privacy_filtering_is_fail_closed() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        let view = board.view(&read_request(Role::ReadOnlyApi)).expect("view");
        assert_eq!(view.items.len(), 1);
        assert_eq!(view.items[0].item_id, "public");
        assert_eq!(view.provenance.len(), 1);
        assert_eq!(
            view.reviews[0].anchor.resolution,
            AnchorResolution::Ambiguous
        );
    }

    #[test]
    fn missing_ports_are_typed_plan_gaps() {
        let mut board = ControlBoard::new(None, None, None);
        assert_eq!(
            board.view(&read_request(Role::HumanRequester)),
            Err(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))
        );
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::PauseTask],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::PauseTask {
                task_id: "public".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), command),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::OperatorCommand
            ))
        );
    }

    #[test]
    fn stale_revision_and_fence_are_rejected_before_command() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::AcknowledgeAttention],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let stale =
            StateFence::new(1, ViewRevision::new(6).expect("revision"), "fence-6").expect("fence");
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(6).expect("revision"),
            stale,
            OperatorAction::AcknowledgeAttention {
                item_id: "public".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), command),
            Err(ControlBoardError::StaleView)
        );
    }

    #[test]
    fn typed_command_and_review_lifecycle_do_not_mint_authority() {
        assert!(ReviewLifecycle::Delivered.can_transition(ReviewLifecycle::Answered));
        assert!(!ReviewLifecycle::Resolved.can_transition(ReviewLifecycle::Delivered));
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::AnswerReview],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::AnswerReview {
                review_item_id: "review-1".to_owned(),
                answer: "addressed".to_owned(),
            },
        )
        .expect("command");
        let receipt = board
            .submit(&read_request(Role::HumanRequester), command)
            .expect("receipt");
        assert_eq!(receipt.disposition, CommandDisposition::Accepted);
        assert_eq!(receipt.observed_revision.get(), 7);
    }

    #[test]
    fn duplicate_and_unknown_shape_inputs_fail_closed() {
        let mut duplicate = state();
        duplicate.items.push(duplicate.items[0].clone());
        assert!(matches!(
            duplicate.validate(),
            Err(ControlBoardError::DuplicateId(_))
        ));
        let json = r#"{"revision":7,"fence":{"authority_epoch":1,"revision":7,"fence_id":"f"},"completeness":{"g11_coordination":{"provider":"G11","work_id":"G-11","binding_id":"g11","binding_revision":7,"binding_fence":{"authority_epoch":1,"revision":7,"fence_id":"f"},"binding_digest":"d1","receipt_ref":"r1"},"i12_report_projection":{"provider":"I12","work_id":"I-12","binding_id":"i12","binding_revision":7,"binding_fence":{"authority_epoch":1,"revision":7,"fence_id":"f"},"binding_digest":"d2","receipt_ref":"r2"}},"items":[],"reviews":[],"provenance":[],"extra":true}"#;
        let parsed = serde_json::from_str::<CanonicalState>(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn read_only_roles_cannot_submit_operator_actions() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::PauseTask {
                task_id: "task-1".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::ReadOnlyApi), command),
            Err(ControlBoardError::Unauthorized)
        );
    }

    #[test]
    fn exact_human_roles_and_capabilities_are_required() {
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::Approve {
                item_id: "public".to_owned(),
                approval_digest: "approval".to_owned(),
            },
        )
        .expect("command");
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::Approve],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), command.clone()),
            Err(ControlBoardError::Unauthorized)
        );
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanApprover,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        assert_eq!(
            board.submit(&read_request(Role::HumanApprover), command),
            Err(ControlBoardError::Unauthorized)
        );
    }

    #[test]
    fn hidden_targets_and_illegal_review_transitions_are_rejected() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::ResolveReview],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let hidden = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::ResolveReview {
                review_item_id: "human-only".to_owned(),
                reason: "no".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), hidden),
            Err(ControlBoardError::HiddenOrMissingTarget)
        );
        let illegal = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::ResolveReview {
                review_item_id: "review-1".to_owned(),
                reason: "no".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), illegal),
            Err(ControlBoardError::InvalidReviewTransition)
        );
    }

    #[test]
    fn fabricated_receipts_and_incomplete_projections_fail_closed() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::PauseTask],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(BadCommand)),
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::PauseTask {
                task_id: "public".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), command),
            Err(ControlBoardError::InvalidField("receipt_ref"))
        );
        let mut incomplete = state();
        incomplete.completeness.g11_coordination.binding_id.clear();
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: incomplete })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::G11ReviewProjection
            ))
        );
    }

    #[test]
    fn zero_revision_duplicate_grants_and_references_are_rejected() {
        let zero = r#"{"revision":0,"fence":{"authority_epoch":1,"revision":0,"fence_id":"f"},"completeness":{"g11_coordination":{"provider":"G11","work_id":"G-11","binding_id":"g11","binding_revision":0,"binding_fence":{"authority_epoch":1,"revision":0,"fence_id":"f"},"binding_digest":"d1","receipt_ref":"r1"},"i12_report_projection":{"provider":"I12","work_id":"I-12","binding_id":"i12","binding_revision":0,"binding_fence":{"authority_epoch":1,"revision":0,"fence_id":"f"},"binding_digest":"d2","receipt_ref":"r2"}},"items":[],"reviews":[],"provenance":[]}"#;
        assert!(serde_json::from_str::<CanonicalState>(zero).is_err());
        let mut duplicate_privacy = access(
            Role::ReadOnlyApi,
            &[],
            &[PrivacyClass::Public, PrivacyClass::Public],
        );
        let mut board = ControlBoard::new(
            Some(Box::new(FakeAccess {
                binding: duplicate_privacy.binding.clone(),
            })),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::DuplicatePrivacyClass)
        );
        duplicate_privacy.binding.capabilities =
            vec![ActionCapability::PauseTask, ActionCapability::PauseTask];
        duplicate_privacy.binding.admitted_privacy = vec![PrivacyClass::Public];
        let mut board = ControlBoard::new(
            Some(Box::new(duplicate_privacy)),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::DuplicateCapability)
        );
        let mut bad_refs = state();
        bad_refs.reviews[0].response_change_refs = vec!["ref".to_owned(), "ref".to_owned()];
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: bad_refs })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::DuplicateReference)
        );
    }

    #[test]
    fn replayed_session_on_arbitrary_connection_is_rejected() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        let mut replay = read_request(Role::ReadOnlyApi);
        replay.connection_id = "stolen-connection".to_owned();
        assert_eq!(board.view(&replay), Err(ControlBoardError::Unauthorized));
    }

    #[test]
    fn provider_clock_not_caller_generation_decides_access_freshness() {
        let mut fresh = access(Role::ReadOnlyApi, &[], &[PrivacyClass::Public]);
        fresh.binding.generation = 10_000;
        let mut request = read_request(Role::ReadOnlyApi);
        request.generation = 10_000;
        let mut board = ControlBoard::new(
            Some(Box::new(fresh)),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        assert!(board.view(&request).is_ok());

        let mut expired = access(Role::ReadOnlyApi, &[], &[PrivacyClass::Public]);
        expired.binding.observed_at_unix_ms = expired.binding.expires_at_unix_ms;
        let mut board = ControlBoard::new(
            Some(Box::new(expired)),
            Some(Box::new(FakeRead { state: state() })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::StaleAccess)
        );
    }

    #[test]
    fn command_and_receipt_must_carry_the_sealed_access_binding() {
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::PauseTask],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(WrongAccessCommand)),
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::PauseTask {
                task_id: "public".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), command),
            Err(ControlBoardError::ReceiptBindingMismatch)
        );
    }

    #[test]
    fn action_kinds_and_query_semantics_are_explicit() {
        let mut wrong_kind = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::ChallengeRule],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let wrong = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::ChallengeRule {
                rule_id: "public".to_owned(),
                rationale: "wrong kind".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            wrong_kind.submit(&read_request(Role::HumanRequester), wrong),
            Err(ControlBoardError::WrongTargetKind)
        );

        let approval = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::Approve {
                item_id: "public".to_owned(),
                approval_digest: "critical-action-digest".to_owned(),
            },
        )
        .expect("command");
        let mut task_target = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanApprover,
                &[ActionCapability::Approve],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        assert_eq!(
            task_target.submit(&read_request(Role::HumanApprover), approval.clone()),
            Err(ControlBoardError::WrongTargetKind)
        );
        let mut approval_state = state();
        approval_state.items[0].kind = BoardItemKind::Approval;
        let mut approval_target = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanApprover,
                &[ActionCapability::Approve],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead {
                state: approval_state,
            })),
            Some(Box::new(FakeCommand)),
        );
        assert_eq!(
            approval_target
                .submit(&read_request(Role::HumanApprover), approval)
                .expect("receipt")
                .disposition,
            CommandDisposition::Accepted
        );

        let mut query = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::StartQuery],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            query
                .submit(&read_request(Role::HumanRequester), command)
                .expect("receipt")
                .disposition,
            CommandDisposition::Accepted
        );
    }

    #[test]
    fn deserialized_ceiling_widening_and_unknown_enums_fail_closed() {
        let command = CommandRequest::new(
            "session",
            ViewRevision::new(7).expect("revision"),
            fence(),
            OperatorAction::PauseTask {
                task_id: "public".to_owned(),
            },
        )
        .expect("command");
        let mut widened = serde_json::to_value(&command).expect("json");
        widened["proof_ceiling"] = serde_json::json!("SCOPED_VERIFICATION");
        let widened = serde_json::from_value::<CommandRequest>(widened).expect("command json");
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::HumanRequester,
                &[ActionCapability::PauseTask],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: state() })),
            Some(Box::new(FakeCommand)),
        );
        assert_eq!(
            board.submit(&read_request(Role::HumanRequester), widened),
            Err(ControlBoardError::InvalidField("proof_ceiling"))
        );
        assert!(
            serde_json::from_str::<OperatorAction>(
                r#"{"kind":"PAUSE_TASK","task_id":"public","extra":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<CommandDisposition>(r#"{"kind":"ACCEPTED","extra":true}"#)
                .is_err()
        );
    }

    #[test]
    fn literal_projection_names_are_not_provider_bindings() {
        let mut bogus = state();
        bogus.completeness.g11_coordination.binding_id = "G-11".to_owned();
        let mut board = ControlBoard::new(
            Some(Box::new(access(
                Role::ReadOnlyApi,
                &[],
                &[PrivacyClass::Public],
            ))),
            Some(Box::new(FakeRead { state: bogus })),
            None,
        );
        assert_eq!(
            board.view(&read_request(Role::ReadOnlyApi)),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::G11ReviewProjection
            ))
        );
    }
}
