//! Kernel-owned durable anchored-review surface (issue #1823; I10.18/I10.21).
//!
//! Architecture: I10.18 durable anchored review. Public plans, messages,
//! rationales, code/diffs, sources, tool output, and verifier results must be
//! able to receive durable, revision-safe correction or objection without
//! growing a second approval system: review comments grant no write, effect,
//! goal, or acceptance authority, rejection requires a reason, and an anchor
//! that resolves ambiguously stays ambiguous instead of attaching to a
//! similar fragment.
//!
//! This module is the Kernel-mechanical half of that contract under the
//! existing coordination authority (the [`crate::coordination_mailbox`]
//! owner): the durable record shape ([`AnchoredReviewRecord`]) carrying the
//! exact target kind, the immutable original revision and anchor, the review
//! kind and content, the State Fence, the author, the lifecycle, and the full
//! response/change/verifier reference set; the named idempotent submission
//! ([`submit_review_item`], stable name [`ANCHORED_REVIEW_SUBMIT_NAME`]);
//! the derived batch envelope ([`ReviewBatch`], submitted through
//! [`submit_review_batch`] under [`ANCHORED_REVIEW_BATCH_SUBMIT_NAME`] and
//! observed per item through [`observe_review_batch`]); the seven-status
//! evolving-anchor resolution ([`resolve_review_anchor`]) that is the only
//! resolution path every submission and observation uses; the per-item
//! lifecycle advance ([`advance_review_item`]); the requested-change routing
//! to the normal owner/effect/verifier path ([`route_requested_change`],
//! [`accept_requested_change_effect`], [`verify_requested_change_effect`]);
//! and the blocker classifier with escalation to the existing
//! Problem/Critical-Attention control owner ([`classify_review_blocker`],
//! [`escalate_review_blocker`]).
//!
//! # Production chain
//!
//! The Store bridge slice calls [`submit_review_item`] (or
//! [`submit_review_batch`] for a derived envelope of two or more drafts)
//! before any delivery work starts, passing the already-known records it
//! read back through the Store bridge so a retried submission with a reused
//! identity replays the existing record as [`ReviewSubmission`] with
//! `replayed: true` instead of recording a second effect. Resolution runs
//! exclusively through [`resolve_review_anchor`] inside submission: the
//! caller supplies the current-state candidates it read back through normal
//! observation plus its caller-attested deletion evidence, and the retained
//! [`ReviewResolution`] records exactly one of
//! exact/moved/modified/ambiguous/stale/deleted/unavailable. An ambiguous
//! result is retained as an unattached item (`current: None`); submission
//! refuses nothing silently — every refusal is a typed
//! [`AnchoredReviewError`]. The delivery slice advances each item on its own
//! through [`advance_review_item`]; answering one item never resolves or
//! hides another, and [`observe_review_batch`] reports every item's own
//! lifecycle. A requested change never converts into a write here: the owner
//! slice routes it through [`route_requested_change`], the normal effect
//! owner accepts through [`accept_requested_change_effect`], and the
//! verifier closes it through [`verify_requested_change_effect`]. Only real
//! blockers escalate, through [`escalate_review_blocker`], to the existing
//! control owner named by [`ReviewEscalationOwner::control_class`]. The
//! stable `*_NAME` and `*_SCHEMA_V1` constants are the exact keys those
//! slices register on the Store bridge; they are declared here so the names
//! cannot drift between the Kernel surface and the bridge registration.
//! Durability stays with the canonical Store through the existing Store
//! bridge; this module keeps no rows and owns no lease.
//!
//! # What this deliberately does not do
//!
//! No second approval system: there is no approve/admit/finish transition,
//! and `Resolved` records only that the item's own obligation closed, never
//! an approval of any revision. Reviews grant no write, effect, goal, or
//! acceptance authority: no function here performs a write, admits a
//! candidate, or verifies truth; the requested-change rows name the normal
//! owner, effect, and verifier entries that must still accept and verify.
//! Ambiguous anchors never attach: [`resolve_review_anchor`] returns
//! `current: None` for ambiguous (and stale/deleted/unavailable) results,
//! and no other resolution path exists in this module. Rejection without a
//! reason is refused, never stored.
//!
//! # Relation to the Governor peer-review vocabulary
//!
//! `eliot-coordination` already types the Governor-side peer review channel
//! (peer envelopes, obligations, conflicts, recommendations). That
//! vocabulary is Governor semantics, which the Kernel composition root must
//! not duplicate or interpret (`bins/AGENTS.md`). This surface is the
//! Kernel-mechanical record built only from foundation contracts
//! (`StateFence`) and plain bounded text, following the `blackboard` and
//! `MailboxRouteProfile` precedent: the I10.18 closed vocabularies are
//! spelled 1:1 with independent closed decodes, and the Governor types are
//! never imported here — a `bins` root takes no Governor dependency to name
//! them twice. The Governor peer-conflict owner stays separate and is never
//! re-created here: escalation names only the existing control classes.

use eliot_contracts::{ContractError, StateFence};
use eliot_runtime_contracts::ControlOperationClass;
use serde::{Deserialize, Serialize};

/// Schema identifier for persisted anchored-review records. The Store bridge
/// slice registers this exact key; the Kernel surface never mints a second
/// one.
pub const ANCHORED_REVIEW_SCHEMA_V1: &str = "eliot.coordination.anchored_review.v1";
/// Stable named submission. The Store bridge slice registers this exact name
/// for anchored-review admission.
pub const ANCHORED_REVIEW_SUBMIT_NAME: &str = "SubmitAnchoredReviewItem";
/// Stable named batch submission. The Store bridge slice registers this
/// exact name for derived-envelope batch admission.
pub const ANCHORED_REVIEW_BATCH_SUBMIT_NAME: &str = "SubmitAnchoredReviewBatch";
/// Stable named observation. The observing slice registers this exact name
/// for per-item batch readback.
pub const ANCHORED_REVIEW_OBSERVE_NAME: &str = "ObserveAnchoredReviewBatch";
/// Stable named lifecycle advance. The delivery slice registers this exact
/// name when it advances one item.
pub const ANCHORED_REVIEW_ADVANCE_NAME: &str = "AdvanceAnchoredReviewItem";
/// Stable named requested-change routing. The owner slice registers this
/// exact name when it routes a requested change to the normal path.
pub const ANCHORED_REVIEW_ROUTE_NAME: &str = "RouteRequestedChange";
/// Stable named effect-owner acceptance. The effect slice registers this
/// exact name when the normal effect owner accepts a routed change.
pub const ANCHORED_REVIEW_ACCEPT_NAME: &str = "AcceptRequestedChangeEffect";
/// Stable named verifier observation. The verifier slice registers this
/// exact name when the verifier closes a routed change.
pub const ANCHORED_REVIEW_VERIFY_NAME: &str = "VerifyRequestedChangeEffect";
/// Stable named blocker escalation. The owning slice registers this exact
/// name when it escalates a classified blocker.
pub const ANCHORED_REVIEW_ESCALATE_NAME: &str = "EscalateReviewBlocker";

/// Bound for every identity-shaped field: review, author, target, owner,
/// effect, and verifier text.
pub const MAX_REVIEW_IDENTITY_LEN: usize = 256;
/// Bound for provenance-shaped text: paths and selectors.
pub const MAX_REVIEW_SELECTOR_LEN: usize = 1024;
/// Bound for one review body, in bytes. This is the payload bound shared
/// with the durable mailbox; larger content travels by handle on a later
/// slice, never as an unbounded inline body here.
pub const MAX_REVIEW_CONTENT_BYTES: usize = 65_536;
/// Bound for each reference list. An item carries at most this many
/// response, change, or verifier references; the lists stay bounded evidence
/// handles, never an unbounded import.
pub const MAX_REVIEW_REFS: usize = 16;

/// Typed anchored-review failures. Every rejection names its field and
/// reason; misses, conflicts, and missing reasons name the exact identity.
/// Nothing is refused silently.
#[derive(Clone, Debug)]
pub enum AnchoredReviewError {
    /// A field failed admission bounds. No record was created.
    InvalidField {
        /// Closed field name, never a value.
        field: &'static str,
        /// Stable reason, never a value.
        reason: &'static str,
    },
    /// The review identity is already known for a different draft. No
    /// second record was created and the existing one was not returned,
    /// because the identity no longer names the same logical item.
    IdentityConflict {
        /// Exact identity that collided.
        review_id: String,
    },
    /// No record carries the requested identity.
    NotFound {
        /// Exact identity that was looked up.
        review_id: String,
    },
    /// The batch envelope does not name exactly the submitted items in
    /// order. No item was admitted.
    BatchMismatch {
        /// Exact batch identity that mismatched.
        batch_id: String,
    },
    /// Rejection was requested without a reason. No transition was stored.
    MissingRejectionReason {
        /// Exact identity that was presented.
        review_id: String,
    },
    /// The item is not a requested change. No route was recorded.
    NotRequestedChange {
        /// Exact identity that was presented.
        review_id: String,
    },
    /// The carried State Fence failed its own owner validation.
    Foundation(ContractError),
}

impl std::fmt::Display for AnchoredReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "invalid anchored review field {field}: {reason}")
            }
            Self::IdentityConflict { review_id } => {
                write!(f, "anchored review identity conflict: {review_id}")
            }
            Self::NotFound { review_id } => {
                write!(f, "anchored review not found: {review_id}")
            }
            Self::BatchMismatch { batch_id } => {
                write!(f, "anchored review batch mismatch: {batch_id}")
            }
            Self::MissingRejectionReason { review_id } => {
                write!(
                    f,
                    "anchored review rejection requires a reason: {review_id}"
                )
            }
            Self::NotRequestedChange { review_id } => {
                write!(f, "anchored review is not a requested change: {review_id}")
            }
            Self::Foundation(error) => {
                write!(f, "anchored review foundation contract: {error}")
            }
        }
    }
}

impl std::error::Error for AnchoredReviewError {}

/// Closed review-target vocabulary (I10.18 anchored review). Unknown
/// spellings are rejected by [`ReviewTargetKind::decode`], never coerced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ReviewTargetKind {
    PublicMessage,
    PublicPlan,
    PublicRationale,
    ToolResult,
    Diff,
    Source,
    VerifierResult,
}

impl ReviewTargetKind {
    /// Canonical wire spelling of one target kind.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::PublicMessage => "public_message",
            Self::PublicPlan => "public_plan",
            Self::PublicRationale => "public_rationale",
            Self::ToolResult => "tool_result",
            Self::Diff => "diff",
            Self::Source => "source",
            Self::VerifierResult => "verifier_result",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, AnchoredReviewError> {
        match text {
            "public_message" => Ok(Self::PublicMessage),
            "public_plan" => Ok(Self::PublicPlan),
            "public_rationale" => Ok(Self::PublicRationale),
            "tool_result" => Ok(Self::ToolResult),
            "diff" => Ok(Self::Diff),
            "source" => Ok(Self::Source),
            "verifier_result" => Ok(Self::VerifierResult),
            _ => Err(AnchoredReviewError::InvalidField {
                field: "target_kind",
                reason: "unknown review target kind",
            }),
        }
    }

    /// Exact closed denominator of the target vocabulary.
    #[must_use]
    pub const fn all() -> [&'static str; 7] {
        [
            "public_message",
            "public_plan",
            "public_rationale",
            "tool_result",
            "diff",
            "source",
            "verifier_result",
        ]
    }
}

/// Closed review-kind vocabulary (I10.18 anchored review). A requested
/// change is a candidate only: it takes effect solely through the normal
/// owner, effect, and verifier paths, never through the review record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ReviewKind {
    Question,
    Correction,
    Objection,
    RequestedChange,
    MissingEvidence,
    ScopeIssue,
    AcceptanceIssue,
}

impl ReviewKind {
    /// Canonical wire spelling of one review kind.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::Correction => "correction",
            Self::Objection => "objection",
            Self::RequestedChange => "requested_change",
            Self::MissingEvidence => "missing_evidence",
            Self::ScopeIssue => "scope_issue",
            Self::AcceptanceIssue => "acceptance_issue",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, AnchoredReviewError> {
        match text {
            "question" => Ok(Self::Question),
            "correction" => Ok(Self::Correction),
            "objection" => Ok(Self::Objection),
            "requested_change" => Ok(Self::RequestedChange),
            "missing_evidence" => Ok(Self::MissingEvidence),
            "scope_issue" => Ok(Self::ScopeIssue),
            "acceptance_issue" => Ok(Self::AcceptanceIssue),
            _ => Err(AnchoredReviewError::InvalidField {
                field: "kind",
                reason: "unknown review kind",
            }),
        }
    }

    /// Exact closed denominator of the review-kind vocabulary.
    #[must_use]
    pub const fn all() -> [&'static str; 7] {
        [
            "question",
            "correction",
            "objection",
            "requested_change",
            "missing_evidence",
            "scope_issue",
            "acceptance_issue",
        ]
    }
}

/// Review lifecycle (I10.18). Resolution stays distinct from
/// acknowledgement, and answering one item never moves another: every
/// advance below names exactly one item.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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
    /// Canonical wire spelling of one lifecycle state.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingDelivery => "pending_delivery",
            Self::Delivered => "delivered",
            Self::Answered => "answered",
            Self::Resolved => "resolved",
            Self::RejectedWithReason => "rejected_with_reason",
            Self::Stale => "stale",
            Self::Superseded => "superseded",
        }
    }

    /// Whether this state still holds a live, undisposed obligation.
    /// Terminal states (resolved, rejected, stale, superseded) and states
    /// not yet in the coordination path (draft, pending delivery) never
    /// block: only real blockers escalate.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Delivered | Self::Answered)
    }

    /// Whether this state is terminal: no advance leaves it.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::RejectedWithReason | Self::Stale | Self::Superseded
        )
    }
}

/// Current-location resolution status for an immutable historical anchor
/// (I10.21 evolving anchors). The Kernel-mechanical resolution
/// ([`resolve_review_anchor`]) records exactly one of these seven; nothing
/// else is representable here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum AnchorResolutionStatus {
    Exact,
    Moved,
    Modified,
    Ambiguous,
    Stale,
    Deleted,
    Unavailable,
}

impl AnchorResolutionStatus {
    /// Canonical wire spelling of one resolution status.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Moved => "moved",
            Self::Modified => "modified",
            Self::Ambiguous => "ambiguous",
            Self::Stale => "stale",
            Self::Deleted => "deleted",
            Self::Unavailable => "unavailable",
        }
    }

    /// Closed decode: unknown spellings are rejected, never coerced.
    pub fn decode(text: &str) -> Result<Self, AnchoredReviewError> {
        match text {
            "exact" => Ok(Self::Exact),
            "moved" => Ok(Self::Moved),
            "modified" => Ok(Self::Modified),
            "ambiguous" => Ok(Self::Ambiguous),
            "stale" => Ok(Self::Stale),
            "deleted" => Ok(Self::Deleted),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(AnchoredReviewError::InvalidField {
                field: "resolution_status",
                reason: "unknown anchor resolution status",
            }),
        }
    }

    /// Exact closed denominator of the seven-status vocabulary.
    #[must_use]
    pub const fn all() -> [&'static str; 7] {
        [
            "exact",
            "moved",
            "modified",
            "ambiguous",
            "stale",
            "deleted",
            "unavailable",
        ]
    }

    /// Whether a review may attach to the current location under this
    /// status. Only exact, moved, and modified resolutions attach, and only
    /// with a current location present; an ambiguous, stale, deleted, or
    /// unavailable result stays unattached, never silently bound to a
    /// similar fragment.
    #[must_use]
    pub const fn attaches(&self) -> bool {
        matches!(self, Self::Exact | Self::Moved | Self::Modified)
    }
}

/// Lifecycle advance for one anchored review item
/// (`AdvanceAnchoredReviewItem`). There is no approve/admit/finish
/// transition: this is not an approval system.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ReviewAdvance {
    Deliver,
    ConfirmDelivery,
    Answer,
    Resolve,
    RejectWithReason,
    MarkStale,
    MarkSuperseded,
}

impl ReviewAdvance {
    /// Canonical wire spelling of one advance.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Deliver => "deliver",
            Self::ConfirmDelivery => "confirm_delivery",
            Self::Answer => "answer",
            Self::Resolve => "resolve",
            Self::RejectWithReason => "reject_with_reason",
            Self::MarkStale => "mark_stale",
            Self::MarkSuperseded => "mark_superseded",
        }
    }
}

/// Immutable original anchor: the exact target revision and location the
/// review was written against. Immutable after submission: corrections
/// arrive as new items, never as rewrites of these fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAnchor {
    /// Reviewed target identity exactly as the producing owner spells it.
    pub target_id: String,
    /// Reviewed target revision observed at submit; a later head never
    /// rewrites it.
    pub target_revision: String,
    /// Reviewed target digest bound at that revision.
    pub target_digest: String,
    /// Location path within the target, when the target kind has one.
    /// Plans, messages, and rationales carry none.
    pub path: Option<String>,
    /// Location symbol within the path, when the target kind has one.
    pub symbol: Option<String>,
    /// First location line, when the target kind has lines.
    pub line_start: Option<u64>,
    /// Last location line, when the target kind has lines.
    pub line_end: Option<u64>,
}

/// One current-state candidate the producing lane read back through normal
/// observation. Candidates are inputs to resolution, never its result; this
/// module invents no bytes and reads no store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCandidate {
    /// Candidate anchor in the current state.
    pub anchor: ReviewAnchor,
    /// Content digest of the candidate's exact bytes, when the producing
    /// lane read them back.
    pub content_digest: Option<String>,
    /// Structural digest of the candidate's surroundings, when the
    /// producing lane read them back.
    pub structural_digest: Option<String>,
}

/// The retained seven-status resolution for one item. `current` is present
/// exactly for exact/moved/modified results; ambiguous, stale, deleted, and
/// unavailable results stay unattached (`current: None`) and are retained
/// with that explicit status, never refused and never silently bound.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResolution {
    /// Recorded resolution status.
    pub status: AnchorResolutionStatus,
    /// Current location the item attaches to, present exactly when
    /// [`AnchorResolutionStatus::attaches`] holds.
    pub current: Option<ReviewAnchor>,
    /// Number of candidates examined. Retained so a later reader can tell
    /// an empty search from an unevaluated one.
    pub candidate_count: u32,
}

/// One typed evidence handle carried on a review item. Response references
/// are discussion handles; change references are candidates only; verifier
/// references are evidence handles. All three grant no write, effect, goal,
/// or acceptance authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReference {
    /// Stable target kind spelled by the producing owner.
    pub kind: String,
    /// Stable target identity spelled by the producing owner.
    pub id: String,
    /// Revision that was actually observed.
    pub revision: String,
    /// Digest of the exact observed bytes, when the producing owner bound
    /// one.
    pub digest: Option<String>,
}

/// Unvalidated submission input for one anchored review item. `review_id` is
/// the exact idempotency identity: a retried submission reuses it, and
/// admission replays the existing record instead of recording a second
/// effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredReviewDraft {
    /// Stable identity for the item across retries and redelivery.
    pub review_id: String,
    /// Author principal spelled by the producer and retained as opaque
    /// evidence. Kernel does not authenticate this binding; the admitting
    /// caller binds it to the authenticated session.
    pub author_principal: String,
    /// Exact target kind under review.
    pub target_kind: ReviewTargetKind,
    /// Immutable original revision and anchor the review was written
    /// against.
    pub original: ReviewAnchor,
    /// Bounded review kind.
    pub kind: ReviewKind,
    /// Review body exactly as submitted. Bounded by
    /// [`MAX_REVIEW_CONTENT_BYTES`].
    pub content: String,
    /// Fence at which the item was submitted.
    pub state_fence: StateFence,
    /// Response references bound at submit. Discussion handles only.
    pub response_refs: Vec<ReviewReference>,
    /// Requested-change references bound at submit. Candidates only: a
    /// referenced change takes effect solely through the normal owner,
    /// effect, and verifier paths, never through this record.
    pub change_refs: Vec<ReviewReference>,
    /// Verifier-result references bound at submit. Evidence handles, never
    /// verifier authority.
    pub verifier_refs: Vec<ReviewReference>,
    /// Producer-observed submission time, Unix milliseconds, never zero.
    pub submitted_at_unix_ms: u64,
}

/// The Kernel-owned durable anchored-review record. The original revision,
/// anchor, kind, content, fence, author, and reference sets are immutable
/// after admission; the delivery slice observes them through per-item
/// advances, never by mutation. Every item carries its own lifecycle and
/// disposition: answering one item never resolves or hides another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredReviewRecord {
    /// Stable identity for the item across retries and redelivery.
    pub review_id: String,
    /// Author principal retained as opaque evidence.
    pub author_principal: String,
    /// Exact target kind under review.
    pub target_kind: ReviewTargetKind,
    /// Immutable original revision and anchor.
    pub original: ReviewAnchor,
    /// Bounded review kind.
    pub kind: ReviewKind,
    /// Review body exactly as submitted.
    pub content: String,
    /// Fence at which the item was submitted.
    pub state_fence: StateFence,
    /// Per-item lifecycle. Independent across items in one batch.
    pub lifecycle: ReviewLifecycle,
    /// Retained seven-status resolution. Ambiguous results stay unattached.
    pub resolution: ReviewResolution,
    /// Response references bound at submit.
    pub response_refs: Vec<ReviewReference>,
    /// Requested-change references bound at submit, candidates only.
    pub change_refs: Vec<ReviewReference>,
    /// Verifier-result references bound at submit, evidence only.
    pub verifier_refs: Vec<ReviewReference>,
    /// The reason retained when this item is rejected. Present exactly when
    /// `lifecycle` is [`ReviewLifecycle::RejectedWithReason`].
    pub rejection_reason: Option<String>,
    /// Producer-observed submission time, Unix milliseconds.
    pub submitted_at_unix_ms: u64,
}

/// Admission outcome (`SubmitAnchoredReviewItem`).
///
/// A fresh identity yields the newly admitted record with `replayed: false`.
/// A reused identity with an identical draft yields the already-known
/// record with `replayed: true` and produces no second effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSubmission {
    /// The admitted record, new or replayed.
    pub record: AnchoredReviewRecord,
    /// True when the identity was already known and no new record was
    /// created.
    pub replayed: bool,
}

/// Derived batch envelope. It has no lifecycle, no disposition, and no
/// authority of its own: it only names the items sent together so the
/// delivery slice observes them as one sending without merging their
/// lifecycles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBatch {
    /// Stable identity for the sending across retries.
    pub batch_id: String,
    /// Item identities in send order. Each keeps its own lifecycle.
    pub review_ids: Vec<String>,
    /// Frozen plan revision this sending was derived from.
    pub plan_revision: String,
}

/// One batch member: the draft plus the exact resolution inputs the
/// producing lane read back for it. Resolution inputs are per item because
/// each item anchors to its own original.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchReviewEntry {
    /// Submission input for this member.
    pub draft: AnchoredReviewDraft,
    /// Current-state candidates read back for this member's original.
    pub candidates: Vec<ReviewCandidate>,
    /// Caller-attested deletion evidence for this member's target: true
    /// when the producing lane observed the target deleted. False when
    /// unknown; an unknown deletion is never inferred here.
    pub target_deleted: bool,
}

/// Batch admission outcome (`SubmitAnchoredReviewBatch`). Items admit in
/// batch order with fully independent lifecycles and dispositions; the
/// first invalid entry refuses the whole sending and names its identity,
/// so the caller persists either every item or none.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSubmission {
    /// The derived envelope the items were sent under.
    pub batch: ReviewBatch,
    /// Per-item admission outcomes in batch order.
    pub items: Vec<ReviewSubmission>,
}

/// Per-item observation view (`ObserveAnchoredReviewBatch`). One view per
/// batch member, each carrying its own lifecycle, resolution, and rejection
/// reason: answering one item never resolves or hides another.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemObservation {
    /// Identity of the observed item.
    pub review_id: String,
    /// The item's own lifecycle.
    pub lifecycle: ReviewLifecycle,
    /// The item's own retained resolution status.
    pub resolution_status: AnchorResolutionStatus,
    /// Whether the item attaches to a current location. False exactly for
    /// retained-but-unattached results (ambiguous, stale, deleted,
    /// unavailable).
    pub attached: bool,
    /// The item's own review kind.
    pub kind: ReviewKind,
    /// The item's own target kind.
    pub target_kind: ReviewTargetKind,
    /// The reason retained when this item was rejected, if any.
    pub rejection_reason: Option<String>,
}

/// Requested-change routing row (`RouteRequestedChange`). It binds one
/// retained requested-change item to the normal owner, effect, and verifier
/// entries that must still accept and verify it. Candidate only: this row
/// grants no write, effect, goal, or acceptance authority and performs no
/// write itself; the named owner performs the effect through its own path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedChangeRoute {
    /// Identity of the routed review item.
    pub review_id: String,
    /// Normal owner that must accept the change, spelled by the routing
    /// caller. This module authenticates no ownership; the effect slice
    /// binds the identity.
    pub owner_id: String,
    /// Normal effect entry the owner must invoke. A name, never an
    /// invocation.
    pub effect_entry: String,
    /// Normal verifier entry that must close the change. A name, never a
    /// verdict.
    pub verifier_entry: String,
    /// Requested-change references copied from the retained record.
    /// Candidates only.
    pub change_refs: Vec<ReviewReference>,
    /// Verifier-result references copied from the retained record.
    /// Evidence only.
    pub verifier_refs: Vec<ReviewReference>,
    /// Producer-observed routing time, Unix milliseconds.
    pub routed_at_unix_ms: u64,
}

/// Effect-owner acceptance row (`AcceptRequestedChangeEffect`). The normal
/// effect owner accepted the routed change under its own authority; the
/// change is still unverified until the verifier closes it. This row
/// records the acceptance, it is not the effect itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedChangeEffect {
    /// Identity of the accepted review item.
    pub review_id: String,
    /// Normal owner that accepted, as bound by the accepting slice.
    pub owner_id: String,
    /// Normal effect entry the owner invoked through its own path.
    pub effect_name: String,
    /// Principal that accepted on the owner path, bound by the accepting
    /// caller.
    pub accepted_by: String,
    /// Normal verifier entry that must still close the change.
    pub verifier_entry: String,
    /// Requested-change references carried from the route.
    pub change_refs: Vec<ReviewReference>,
    /// Producer-observed acceptance time, Unix milliseconds.
    pub accepted_at_unix_ms: u64,
}

/// Verifier closure row (`VerifyRequestedChangeEffect`). The verifier
/// observed the accepted effect and bound its result reference. Only this
/// row completes the requested-change path; a requested change produces no
/// direct write until the normal effect owner accepts (the row above) and
/// the verifier verifies (this row).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedChangeVerification {
    /// Identity of the verified review item.
    pub review_id: String,
    /// Normal owner that accepted, carried from the effect row.
    pub owner_id: String,
    /// Normal effect entry that was invoked, carried from the effect row.
    pub effect_name: String,
    /// Verifier identity bound by the verifying caller.
    pub verifier_id: String,
    /// Normal verifier entry that closed the change, carried from the
    /// effect row.
    pub verifier_entry: String,
    /// Verifier-result reference the verifier bound to this closure.
    /// Evidence handle, never verifier authority by itself.
    pub result_ref: ReviewReference,
    /// Producer-observed verification time, Unix milliseconds.
    pub verified_at_unix_ms: u64,
}

/// Closed blocker vocabulary: the only classifications that escalate. Any
/// other item state is explicitly not a blocker and never escalates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ReviewBlockerKind {
    /// A live objection holds an unresolved contest on its target.
    UnresolvedObjection,
    /// A live requested change still lacks effect-owner acceptance and
    /// verifier closure.
    UnverifiedRequestedChange,
    /// A live correction anchors to an ambiguous location, so the
    /// correction cannot land on any current target.
    AmbiguousAnchor,
}

impl ReviewBlockerKind {
    /// Canonical wire spelling of one blocker class.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::UnresolvedObjection => "unresolved_objection",
            Self::UnverifiedRequestedChange => "unverified_requested_change",
            Self::AmbiguousAnchor => "ambiguous_anchor",
        }
    }

    /// Stable reason naming why this class blocks. Reasons name the
    /// obstruction, never a value.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::UnresolvedObjection => "live objection contests the target",
            Self::UnverifiedRequestedChange => {
                "live requested change lacks owner acceptance and verifier closure"
            }
            Self::AmbiguousAnchor => "live correction retains an ambiguous anchor",
        }
    }

    /// Existing owner this blocker class escalates to. Contested
    /// objections need human attention; unverified changes and unlandable
    /// corrections are problem state. The Governor peer-conflict owner
    /// stays separate and is never named here.
    #[must_use]
    pub const fn escalation_owner(&self) -> ReviewEscalationOwner {
        match self {
            Self::UnresolvedObjection => ReviewEscalationOwner::CriticalAttention,
            Self::UnverifiedRequestedChange | Self::AmbiguousAnchor => {
                ReviewEscalationOwner::Problem
            }
        }
    }
}

/// Existing escalation owner for review blockers. These name the already
/// admitted control classes, never a new authority: this module creates no
/// Problem, Conflict, or Critical-Attention owner of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ReviewEscalationOwner {
    Problem,
    CriticalAttention,
}

impl ReviewEscalationOwner {
    /// Canonical wire spelling of one escalation owner.
    #[must_use]
    pub const fn as_wire(&self) -> &'static str {
        match self {
            Self::Problem => "problem",
            Self::CriticalAttention => "critical_attention",
        }
    }

    /// The existing control class that owns the escalation. This is a
    /// reference to the admitted owner, not a new one.
    #[must_use]
    pub const fn control_class(&self) -> ControlOperationClass {
        match self {
            Self::Problem => ControlOperationClass::ProblemTransition,
            Self::CriticalAttention => ControlOperationClass::CriticalAttentionTransition,
        }
    }
}

/// Blocker escalation row (`EscalateReviewBlocker`). It carries the
/// classified blocker, the existing owner it escalates to, and the reason.
/// Only [`classify_review_blocker`] outcomes escalate: anything else is
/// refused with a typed reason, never escalated silently and never dropped
/// silently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBlockerEscalation {
    /// Identity of the escalated item.
    pub review_id: String,
    /// Classified blocker class.
    pub blocker: ReviewBlockerKind,
    /// Existing owner the blocker escalates to.
    pub owner: ReviewEscalationOwner,
    /// Existing control class that owns the escalation.
    pub control_class: ControlOperationClass,
    /// Stable reason naming why this item blocks.
    pub reason: &'static str,
    /// Producer-observed escalation time, Unix milliseconds.
    pub observed_at_unix_ms: u64,
}

/// Resolves one historical anchor to its current location
/// (I10.21 evolving anchors).
///
/// This is the only resolution path in this module: submission and
/// observation call it exclusively, so no caller can resolve around it.
/// Deterministic precedence over the caller-supplied candidates, mirroring
/// the I10.21 order over Kernel-mechanical inputs:
///
/// 1. full-identity match → `exact` (attached);
/// 2. same target revision and digest at a different location → `moved`
///    (attached);
/// 3. same location under the same target identity with a changed revision
///    or digest → `modified` (attached);
/// 4. content-plus-structural fingerprint match → `moved` or `modified` by
///    the same location rule (attached);
/// 5. caller-attested deletion evidence for the target → `deleted`
///    (unattached);
/// 6. no candidates at all → `unavailable` (unattached);
/// 7. anything else → `stale` (unattached).
///
/// More than one match at any attaching tier is `ambiguous` (unattached):
/// ambiguity never silently attaches to the most similar fragment. Statuses
/// that cannot attach carry `current: None`; the retained item keeps that
/// explicit status instead of being refused.
/// Resolves one ordered resolution tier: exactly one match attaches with the
/// tier status, several matches mean ambiguous with no target attached.
fn resolve_tier_match(
    matched: &[usize],
    candidates: &[ReviewCandidate],
    status: AnchorResolutionStatus,
    candidate_count: u32,
) -> Option<ReviewResolution> {
    if matched.len() == 1 {
        return Some(ReviewResolution {
            status,
            current: Some(candidates[matched[0]].anchor.clone()),
            candidate_count,
        });
    }
    if matched.len() > 1 {
        return Some(ReviewResolution {
            status: AnchorResolutionStatus::Ambiguous,
            current: None,
            candidate_count,
        });
    }
    None
}

pub fn resolve_review_anchor(
    original: &ReviewAnchor,
    candidates: &[ReviewCandidate],
    target_deleted: bool,
) -> Result<ReviewResolution, AnchoredReviewError> {
    validate_anchor(original, "original")?;
    for candidate in candidates {
        validate_anchor(&candidate.anchor, "candidate")?;
        validate_optional_text(
            candidate.content_digest.as_deref(),
            "content_digest",
            MAX_REVIEW_IDENTITY_LEN,
        )?;
        validate_optional_text(
            candidate.structural_digest.as_deref(),
            "structural_digest",
            MAX_REVIEW_IDENTITY_LEN,
        )?;
    }
    let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
    let unattached = |status: AnchorResolutionStatus| ReviewResolution {
        status,
        current: None,
        candidate_count,
    };
    // Tier 1: full-identity match.
    let exact: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.anchor == *original)
        .map(|(index, _)| index)
        .collect();
    if let Some(resolution) = resolve_tier_match(
        &exact,
        candidates,
        AnchorResolutionStatus::Exact,
        candidate_count,
    ) {
        return Ok(resolution);
    }
    // Tier 2: same target triple, different location.
    let moved: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            same_target(&candidate.anchor, original) && !same_location(&candidate.anchor, original)
        })
        .map(|(index, _)| index)
        .collect();
    if let Some(resolution) = resolve_tier_match(
        &moved,
        candidates,
        AnchorResolutionStatus::Moved,
        candidate_count,
    ) {
        return Ok(resolution);
    }
    // Tier 3: same location under the same target identity, changed
    // revision or digest.
    let modified: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            candidate.anchor.target_id == original.target_id
                && same_location(&candidate.anchor, original)
                && !same_target(&candidate.anchor, original)
        })
        .map(|(index, _)| index)
        .collect();
    if let Some(resolution) = resolve_tier_match(
        &modified,
        candidates,
        AnchorResolutionStatus::Modified,
        candidate_count,
    ) {
        return Ok(resolution);
    }
    // Tier 4: content-plus-structural fingerprint match.
    let fingerprinted: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            candidate.anchor.target_id == original.target_id
                && candidate
                    .content_digest
                    .as_deref()
                    .is_some_and(|digest| digest == original.target_digest.as_str())
                && candidate
                    .structural_digest
                    .as_deref()
                    .is_some_and(|digest| !digest.trim().is_empty())
        })
        .map(|(index, _)| index)
        .collect();
    if fingerprinted.len() == 1 {
        let current = &candidates[fingerprinted[0]].anchor;
        let status = if same_location(current, original) {
            AnchorResolutionStatus::Modified
        } else {
            AnchorResolutionStatus::Moved
        };
        return Ok(ReviewResolution {
            status,
            current: Some(current.clone()),
            candidate_count,
        });
    }
    if fingerprinted.len() > 1 {
        return Ok(unattached(AnchorResolutionStatus::Ambiguous));
    }
    // Tier 5: caller-attested deletion evidence for the target.
    if target_deleted {
        return Ok(unattached(AnchorResolutionStatus::Deleted));
    }
    // Tier 6: no candidates at all.
    if candidates.is_empty() {
        return Ok(unattached(AnchorResolutionStatus::Unavailable));
    }
    // Tier 7: candidates exist but none matches.
    Ok(unattached(AnchorResolutionStatus::Stale))
}

/// Submits one anchored review item (`SubmitAnchoredReviewItem`).
///
/// Validates the draft, replays the already-known record when `review_id`
/// is already present with an identical draft, and otherwise resolves the
/// current location exclusively through [`resolve_review_anchor`] and
/// retains the record with that exact resolution — including `ambiguous`,
/// which is retained as an unattached item, never refused and never
/// attached. `existing` is the caller-read-back record view (the Store
/// bridge readback in production); this function stores nothing itself.
/// The admitted record starts at [`ReviewLifecycle::Draft`]; every later
/// step is a per-item [`advance_review_item`].
pub fn submit_review_item(
    draft: AnchoredReviewDraft,
    candidates: &[ReviewCandidate],
    target_deleted: bool,
    existing: &[AnchoredReviewRecord],
) -> Result<ReviewSubmission, AnchoredReviewError> {
    validate_draft(&draft)?;
    if let Some(known) = existing
        .iter()
        .find(|record| record.review_id == draft.review_id)
    {
        if !draft_matches_record(&draft, known) {
            return Err(AnchoredReviewError::IdentityConflict {
                review_id: draft.review_id,
            });
        }
        return Ok(ReviewSubmission {
            record: known.clone(),
            replayed: true,
        });
    }
    let resolution = resolve_review_anchor(&draft.original, candidates, target_deleted)?;
    Ok(ReviewSubmission {
        record: AnchoredReviewRecord {
            review_id: draft.review_id,
            author_principal: draft.author_principal,
            target_kind: draft.target_kind,
            original: draft.original,
            kind: draft.kind,
            content: draft.content,
            state_fence: draft.state_fence,
            lifecycle: ReviewLifecycle::Draft,
            resolution,
            response_refs: draft.response_refs,
            change_refs: draft.change_refs,
            verifier_refs: draft.verifier_refs,
            rejection_reason: None,
            submitted_at_unix_ms: draft.submitted_at_unix_ms,
        },
        replayed: false,
    })
}

/// Submits one derived batch envelope (`SubmitAnchoredReviewBatch`).
///
/// The envelope carries no lifecycle of its own: `batch.review_ids` must
/// name exactly the submitted entries in send order, else the whole sending
/// is refused with [`AnchoredReviewError::BatchMismatch`] and no item is
/// admitted. Each entry submits independently through
/// [`submit_review_item`] against the already-known records plus the items
/// admitted earlier in the same sending, so a retried member replays while
/// a conflicting member refuses the sending by name. Admitted items keep
/// fully independent lifecycles: the batch never merges them.
pub fn submit_review_batch(
    batch: &ReviewBatch,
    entries: &[BatchReviewEntry],
    existing: &[AnchoredReviewRecord],
) -> Result<BatchSubmission, AnchoredReviewError> {
    validate_batch(batch)?;
    if batch.review_ids.len() != entries.len()
        || !batch
            .review_ids
            .iter()
            .zip(entries.iter())
            .all(|(id, entry)| *id == entry.draft.review_id)
    {
        return Err(AnchoredReviewError::BatchMismatch {
            batch_id: batch.batch_id.clone(),
        });
    }
    let mut known: Vec<AnchoredReviewRecord> = existing.to_vec();
    let mut items: Vec<ReviewSubmission> = Vec::with_capacity(entries.len());
    for entry in entries {
        let submission = submit_review_item(
            entry.draft.clone(),
            &entry.candidates,
            entry.target_deleted,
            &known,
        )?;
        known.push(submission.record.clone());
        items.push(submission);
    }
    Ok(BatchSubmission {
        batch: batch.clone(),
        items,
    })
}

/// Observes every member of one batch (`ObserveAnchoredReviewBatch`).
///
/// Returns one [`ReviewItemObservation`] per envelope identity in envelope
/// order, each carrying its own lifecycle, resolution status, attachment,
/// and rejection reason. A missing member is a typed
/// [`AnchoredReviewError::NotFound`], never a silent omission: answering
/// one item never resolves or hides another, and observation reports each
/// item exactly as retained.
pub fn observe_review_batch(
    batch: &ReviewBatch,
    records: &[AnchoredReviewRecord],
) -> Result<Vec<ReviewItemObservation>, AnchoredReviewError> {
    validate_batch(batch)?;
    let mut observations: Vec<ReviewItemObservation> = Vec::with_capacity(batch.review_ids.len());
    for review_id in &batch.review_ids {
        let record = records
            .iter()
            .find(|record| record.review_id == *review_id)
            .ok_or_else(|| AnchoredReviewError::NotFound {
                review_id: review_id.clone(),
            })?;
        observations.push(ReviewItemObservation {
            review_id: record.review_id.clone(),
            lifecycle: record.lifecycle,
            resolution_status: record.resolution.status,
            attached: record.resolution.current.is_some(),
            kind: record.kind,
            target_kind: record.target_kind,
            rejection_reason: record.rejection_reason.clone(),
        });
    }
    Ok(observations)
}

/// Advances exactly one item (`AdvanceAnchoredReviewItem`).
///
/// The allowed path is draft → pending delivery → delivered → answered →
/// resolved, with rejection (answered → rejected, reason required),
/// staleness, and supersession as the only exits from a live state; there
/// is no approve/admit/finish transition anywhere on this path. A rejection
/// without a reason is refused with
/// [`AnchoredReviewError::MissingRejectionReason`], never stored; a reason
/// on any other advance is refused as well, so rows stay exact. The
/// original, references, and resolution are never touched by an advance.
/// Returns the advanced record value; the caller persists it through the
/// Store bridge.
pub fn advance_review_item(
    record: &AnchoredReviewRecord,
    advance: ReviewAdvance,
    reason: Option<String>,
) -> Result<AnchoredReviewRecord, AnchoredReviewError> {
    if record.lifecycle == ReviewLifecycle::RejectedWithReason && record.rejection_reason.is_none()
    {
        return Err(AnchoredReviewError::InvalidField {
            field: "rejection_reason",
            reason: "rejected item carries no reason",
        });
    }
    let next = match (record.lifecycle, advance) {
        (ReviewLifecycle::Draft, ReviewAdvance::Deliver) => ReviewLifecycle::PendingDelivery,
        (ReviewLifecycle::PendingDelivery, ReviewAdvance::ConfirmDelivery) => {
            ReviewLifecycle::Delivered
        }
        (ReviewLifecycle::Delivered, ReviewAdvance::Answer) => ReviewLifecycle::Answered,
        (ReviewLifecycle::Answered, ReviewAdvance::Resolve) => ReviewLifecycle::Resolved,
        (ReviewLifecycle::Answered, ReviewAdvance::RejectWithReason) => {
            ReviewLifecycle::RejectedWithReason
        }
        (
            ReviewLifecycle::PendingDelivery
            | ReviewLifecycle::Delivered
            | ReviewLifecycle::Answered,
            ReviewAdvance::MarkStale,
        ) => ReviewLifecycle::Stale,
        (
            ReviewLifecycle::PendingDelivery
            | ReviewLifecycle::Delivered
            | ReviewLifecycle::Answered,
            ReviewAdvance::MarkSuperseded,
        ) => ReviewLifecycle::Superseded,
        _ => {
            return Err(AnchoredReviewError::InvalidField {
                field: "lifecycle",
                reason: "advance not allowed from this lifecycle",
            });
        }
    };
    let rejection_reason = if next == ReviewLifecycle::RejectedWithReason {
        let value = reason.ok_or_else(|| AnchoredReviewError::MissingRejectionReason {
            review_id: record.review_id.clone(),
        })?;
        require_text(&value, "rejection_reason", MAX_REVIEW_IDENTITY_LEN)?;
        Some(value)
    } else {
        if reason.is_some() {
            return Err(AnchoredReviewError::InvalidField {
                field: "reason",
                reason: "only rejection carries a reason",
            });
        }
        None
    };
    let mut advanced = record.clone();
    advanced.lifecycle = next;
    advanced.rejection_reason = rejection_reason;
    Ok(advanced)
}

/// Routes one retained requested change to the normal owner, effect, and
/// verifier path (`RouteRequestedChange`).
///
/// The item must be a [`ReviewKind::RequestedChange`] already past
/// delivery; anything else is refused with
/// [`AnchoredReviewError::NotRequestedChange`] or a typed lifecycle
/// reason. The returned row is a candidate only: it grants no write,
/// effect, goal, or acceptance authority and performs no write itself. The
/// change takes effect solely when the named owner accepts through
/// [`accept_requested_change_effect`] and the named verifier closes through
/// [`verify_requested_change_effect`].
pub fn route_requested_change(
    record: &AnchoredReviewRecord,
    owner_id: &str,
    effect_entry: &str,
    verifier_entry: &str,
    routed_at_unix_ms: u64,
) -> Result<RequestedChangeRoute, AnchoredReviewError> {
    if record.kind != ReviewKind::RequestedChange {
        return Err(AnchoredReviewError::NotRequestedChange {
            review_id: record.review_id.clone(),
        });
    }
    if record.lifecycle != ReviewLifecycle::Delivered
        && record.lifecycle != ReviewLifecycle::Answered
    {
        return Err(AnchoredReviewError::InvalidField {
            field: "lifecycle",
            reason: "requested-change routes only after delivery",
        });
    }
    require_text(owner_id, "owner_id", MAX_REVIEW_IDENTITY_LEN)?;
    require_text(effect_entry, "effect_entry", MAX_REVIEW_IDENTITY_LEN)?;
    require_text(verifier_entry, "verifier_entry", MAX_REVIEW_IDENTITY_LEN)?;
    require_timestamp(routed_at_unix_ms, "routed_at_unix_ms")?;
    Ok(RequestedChangeRoute {
        review_id: record.review_id.clone(),
        owner_id: owner_id.to_owned(),
        effect_entry: effect_entry.to_owned(),
        verifier_entry: verifier_entry.to_owned(),
        change_refs: record.change_refs.clone(),
        verifier_refs: record.verifier_refs.clone(),
        routed_at_unix_ms,
    })
}

/// Records the normal effect owner's acceptance of a routed requested
/// change (`AcceptRequestedChangeEffect`).
///
/// Binds the route to the retained record (a route naming a different item
/// is refused) and to the accepting owner identity bound by the accepting
/// caller. This row records the acceptance; it is not the effect itself,
/// and the change stays unverified until
/// [`verify_requested_change_effect`] closes it. No direct write is
/// produced here or anywhere else in this module.
pub fn accept_requested_change_effect(
    route: &RequestedChangeRoute,
    record: &AnchoredReviewRecord,
    accepted_by: &str,
    effect_name: &str,
    accepted_at_unix_ms: u64,
) -> Result<RequestedChangeEffect, AnchoredReviewError> {
    if route.review_id != record.review_id {
        return Err(AnchoredReviewError::InvalidField {
            field: "route",
            reason: "route names a different review",
        });
    }
    if record.kind != ReviewKind::RequestedChange {
        return Err(AnchoredReviewError::NotRequestedChange {
            review_id: record.review_id.clone(),
        });
    }
    require_text(accepted_by, "accepted_by", MAX_REVIEW_IDENTITY_LEN)?;
    require_text(effect_name, "effect_name", MAX_REVIEW_IDENTITY_LEN)?;
    require_timestamp(accepted_at_unix_ms, "accepted_at_unix_ms")?;
    Ok(RequestedChangeEffect {
        review_id: record.review_id.clone(),
        owner_id: route.owner_id.clone(),
        effect_name: effect_name.to_owned(),
        accepted_by: accepted_by.to_owned(),
        verifier_entry: route.verifier_entry.clone(),
        change_refs: route.change_refs.clone(),
        accepted_at_unix_ms,
    })
}

/// Records the verifier's closure of an accepted requested change
/// (`VerifyRequestedChangeEffect`).
///
/// Only this row completes the requested-change path: a requested change
/// produces no direct write until the normal effect owner accepts (the
/// effect row above) and the verifier verifies (this row). The bound
/// result reference is evidence of the verifier's observation, never
/// verifier authority by itself.
pub fn verify_requested_change_effect(
    effect: &RequestedChangeEffect,
    verifier_id: &str,
    result_ref: ReviewReference,
    verified_at_unix_ms: u64,
) -> Result<RequestedChangeVerification, AnchoredReviewError> {
    require_text(verifier_id, "verifier_id", MAX_REVIEW_IDENTITY_LEN)?;
    validate_reference(&result_ref, "result_ref")?;
    require_timestamp(verified_at_unix_ms, "verified_at_unix_ms")?;
    Ok(RequestedChangeVerification {
        review_id: effect.review_id.clone(),
        owner_id: effect.owner_id.clone(),
        effect_name: effect.effect_name.clone(),
        verifier_id: verifier_id.to_owned(),
        verifier_entry: effect.verifier_entry.clone(),
        result_ref,
        verified_at_unix_ms,
    })
}

/// Classifies whether one retained item is a real blocker.
///
/// Only live, delivered items in the coordination path block: terminal
/// states never block, and items not yet delivered block nothing yet. A
/// live objection holds an unresolved contest; a live requested change
/// still lacks owner acceptance and verifier closure; a live correction on
/// an ambiguous anchor cannot land on any current target. Every other item
/// — questions, evidence or scope notes, unattached discussion, disposed
/// items — is explicitly not a blocker and returns `None`, so only real
/// blockers escalate.
pub fn classify_review_blocker(record: &AnchoredReviewRecord) -> Option<ReviewBlockerKind> {
    if !record.lifecycle.is_live() {
        return None;
    }
    if record.kind == ReviewKind::Objection {
        return Some(ReviewBlockerKind::UnresolvedObjection);
    }
    if record.kind == ReviewKind::RequestedChange {
        return Some(ReviewBlockerKind::UnverifiedRequestedChange);
    }
    if record.kind == ReviewKind::Correction
        && record.resolution.status == AnchorResolutionStatus::Ambiguous
    {
        return Some(ReviewBlockerKind::AmbiguousAnchor);
    }
    None
}

/// Escalates one classified blocker to its existing owner
/// (`EscalateReviewBlocker`).
///
/// Recomputes [`classify_review_blocker`] and refuses when the presented
/// class is not the item's current blocker, so a stale or invented class
/// can neither escalate nor disappear silently. The escalation names the
/// existing Problem or Critical-Attention control owner through
/// [`ReviewEscalationOwner::control_class`]; the Governor peer-conflict
/// owner stays separate and is never named here. The owning slice delivers
/// the returned row to that control path.
pub fn escalate_review_blocker(
    record: &AnchoredReviewRecord,
    blocker: ReviewBlockerKind,
    observed_at_unix_ms: u64,
) -> Result<ReviewBlockerEscalation, AnchoredReviewError> {
    if classify_review_blocker(record) != Some(blocker) {
        return Err(AnchoredReviewError::InvalidField {
            field: "blocker",
            reason: "classifier reports no such blocker for this item",
        });
    }
    require_timestamp(observed_at_unix_ms, "observed_at_unix_ms")?;
    let owner = blocker.escalation_owner();
    Ok(ReviewBlockerEscalation {
        review_id: record.review_id.clone(),
        blocker,
        owner,
        control_class: owner.control_class(),
        reason: blocker.reason(),
        observed_at_unix_ms,
    })
}

/// Whether the target triples name the same revisioned content.
fn same_target(first: &ReviewAnchor, second: &ReviewAnchor) -> bool {
    first.target_id == second.target_id
        && first.target_revision == second.target_revision
        && first.target_digest == second.target_digest
}

/// Whether the location triples name the same place. Absent path, symbol,
/// or lines compare absent against absent only through `Option` equality:
/// a plan anchor never equals a file anchor by accident.
fn same_location(first: &ReviewAnchor, second: &ReviewAnchor) -> bool {
    first.path == second.path
        && first.symbol == second.symbol
        && first.line_start == second.line_start
        && first.line_end == second.line_end
}

/// Validates every draft field: identities, target, original anchor, kind,
/// content, fence, the three reference sets, and timestamp.
fn validate_draft(draft: &AnchoredReviewDraft) -> Result<(), AnchoredReviewError> {
    require_text(&draft.review_id, "review_id", MAX_REVIEW_IDENTITY_LEN)?;
    require_text(
        &draft.author_principal,
        "author_principal",
        MAX_REVIEW_IDENTITY_LEN,
    )?;
    validate_anchor(&draft.original, "original")?;
    require_bounded_body(&draft.content)?;
    draft
        .state_fence
        .validate()
        .map_err(AnchoredReviewError::Foundation)?;
    validate_references(&draft.response_refs, "response_refs")?;
    validate_references(&draft.change_refs, "change_refs")?;
    validate_references(&draft.verifier_refs, "verifier_refs")?;
    require_timestamp(draft.submitted_at_unix_ms, "submitted_at_unix_ms")?;
    Ok(())
}

/// Validates the derived envelope: identity, plan revision, and an exact,
/// non-empty, duplicate-free member list.
fn validate_batch(batch: &ReviewBatch) -> Result<(), AnchoredReviewError> {
    require_text(&batch.batch_id, "batch_id", MAX_REVIEW_IDENTITY_LEN)?;
    require_text(
        &batch.plan_revision,
        "plan_revision",
        MAX_REVIEW_IDENTITY_LEN,
    )?;
    if batch.review_ids.is_empty() {
        return Err(AnchoredReviewError::InvalidField {
            field: "review_ids",
            reason: "batch names no items",
        });
    }
    let mut seen: Vec<&str> = Vec::with_capacity(batch.review_ids.len());
    for review_id in &batch.review_ids {
        require_text(review_id, "review_ids", MAX_REVIEW_IDENTITY_LEN)?;
        if seen.contains(&review_id.as_str()) {
            return Err(AnchoredReviewError::InvalidField {
                field: "review_ids",
                reason: "duplicate item identity",
            });
        }
        seen.push(review_id.as_str());
    }
    Ok(())
}

/// Whether a redrafted submission still names the same logical item as the
/// known record. A reused identity with a different author, target, anchor,
/// kind, content, fence, reference set, or timestamp is an identity
/// conflict, never a silent replay. Lifecycle, resolution, and rejection
/// history belong to the retained record and never join this comparison.
fn draft_matches_record(draft: &AnchoredReviewDraft, record: &AnchoredReviewRecord) -> bool {
    draft.review_id == record.review_id
        && draft.author_principal == record.author_principal
        && draft.target_kind == record.target_kind
        && draft.original == record.original
        && draft.kind == record.kind
        && draft.content == record.content
        && draft.state_fence == record.state_fence
        && draft.response_refs == record.response_refs
        && draft.change_refs == record.change_refs
        && draft.verifier_refs == record.verifier_refs
        && draft.submitted_at_unix_ms == record.submitted_at_unix_ms
}

/// Validates one anchor: exact target identity plus a consistent optional
/// location. Location lines must order sanely when both are present; a
/// half-absent line range is refused rather than guessed.
fn validate_anchor(anchor: &ReviewAnchor, field: &'static str) -> Result<(), AnchoredReviewError> {
    require_text(&anchor.target_id, field, MAX_REVIEW_IDENTITY_LEN)?;
    require_text(&anchor.target_revision, field, MAX_REVIEW_IDENTITY_LEN)?;
    require_text(&anchor.target_digest, field, MAX_REVIEW_IDENTITY_LEN)?;
    validate_optional_text(anchor.path.as_deref(), field, MAX_REVIEW_SELECTOR_LEN)?;
    validate_optional_text(anchor.symbol.as_deref(), field, MAX_REVIEW_IDENTITY_LEN)?;
    match (anchor.line_start, anchor.line_end) {
        (Some(start), Some(end)) => {
            if end == 0 || start > end {
                return Err(AnchoredReviewError::InvalidField {
                    field,
                    reason: "location lines do not order",
                });
            }
        }
        (None, None) => {}
        _ => {
            return Err(AnchoredReviewError::InvalidField {
                field,
                reason: "half-absent location lines",
            });
        }
    }
    Ok(())
}

/// Validates one reference list under its own field name, so response,
/// change, and verifier sets fail separately and explicitly.
fn validate_references(
    references: &[ReviewReference],
    field: &'static str,
) -> Result<(), AnchoredReviewError> {
    if references.len() > MAX_REVIEW_REFS {
        return Err(AnchoredReviewError::InvalidField {
            field,
            reason: "exceeds reference bound",
        });
    }
    for reference in references {
        validate_reference(reference, field)?;
    }
    Ok(())
}

/// Validates one typed evidence handle without asserting its semantic
/// truth: interpretation stays with the owning consumer, never with
/// admission.
fn validate_reference(
    reference: &ReviewReference,
    field: &'static str,
) -> Result<(), AnchoredReviewError> {
    require_text(&reference.kind, field, MAX_REVIEW_IDENTITY_LEN)?;
    require_text(&reference.id, field, MAX_REVIEW_IDENTITY_LEN)?;
    require_text(&reference.revision, field, MAX_REVIEW_IDENTITY_LEN)?;
    validate_optional_text(reference.digest.as_deref(), field, MAX_REVIEW_IDENTITY_LEN)?;
    Ok(())
}

/// Validates one review body: non-blank, bounded, with no control
/// characters, mirroring the Store owner's text rule plus the shared
/// admission payload bound.
fn require_bounded_body(content: &str) -> Result<(), AnchoredReviewError> {
    if content.trim().is_empty() || content.chars().any(char::is_control) {
        return Err(AnchoredReviewError::InvalidField {
            field: "content",
            reason: "blank or control character",
        });
    }
    if content.len() > MAX_REVIEW_CONTENT_BYTES {
        return Err(AnchoredReviewError::InvalidField {
            field: "content",
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires bounded, non-blank text with no control characters, mirroring
/// the Store owner's text rule plus an admission length bound.
fn require_text(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), AnchoredReviewError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(AnchoredReviewError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > max_len {
        return Err(AnchoredReviewError::InvalidField {
            field,
            reason: "exceeds admission bound",
        });
    }
    Ok(())
}

/// Requires bounded, non-blank text when present; absence stays absence.
fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    max_len: usize,
) -> Result<(), AnchoredReviewError> {
    if let Some(text) = value {
        require_text(text, field, max_len)?;
    }
    Ok(())
}

/// Requires a producer-observed time that was actually observed, never zero.
fn require_timestamp(value: u64, field: &'static str) -> Result<(), AnchoredReviewError> {
    if value == 0 {
        return Err(AnchoredReviewError::InvalidField {
            field,
            reason: "must carry the producer-observed time, never zero",
        });
    }
    Ok(())
}
