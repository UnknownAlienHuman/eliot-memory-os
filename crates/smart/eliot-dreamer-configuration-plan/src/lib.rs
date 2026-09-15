//! Snapshot-bound configuration change intent (A-42).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one typed [`ConfigurationChangeIntent`] anchored to an exact immutable
//! base snapshot digest with a bounded closed change set, a purely derived
//! in-memory candidate snapshot digest, complete impact dispositions, and an
//! inert verifier, rollout, stop, rollback, and Human approval boundary. The
//! handler translates a Human request or a diagnosed problem into one review
//!able candidate; it never edits files, publishes snapshots, restarts
//! services, deploys anything, acquires budgets or routes, or exercises
//! authority, effect, or finish behavior.
//!
//! Cell `smart.dreamer.configuration_plan`, order 42. All inputs are immutable
//! and caller supplied. The pre-handler validator receipt travels inside the
//! [`ValidatedDreamDraft`][eliot_dreamer_contracts::ValidatedDreamDraft] and
//! is checked intrinsically through its own validation entry points; it is
//! never re-executed here and is never attached as proof of the new snapshot.
//! The candidate snapshot is derived purely in memory with canonical bytes and
//! a digest; derivation neither publishes nor admits anything. No screening,
//! grounding, common validation, production registry construction, canonical
//! mutation, authority, effect, store, governor, model, clock, or finish
//! surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the nine typed
//! parameters of [`propose_configuration_change`], never decoded from ambient
//! bytes.
//!
//! Runtime boundary: a malformed, over-bound, cancelled-before-emission, or
//! past-deadline request emits zero effects and fails closed as
//! [`ConfigurationError`]. Semantic shortfalls (unmapped prose, ambiguous
//! layer or owner, generic patch shapes, unknown fields, contradictory
//! operations, mixed layers or owners, raw secrets, forbidden ceiling
//! widening, incomplete impact, missing verifier or rollback, absent approval)
//! are inert terminal outcomes carried by [`ConfigurationChangeIntent`],
//! never errors that invite a blind retry. Forbidden widening is rejected,
//! not warned; decision-required work is not ready.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! ambient configuration lookup, file, environment, or registry access,
//! service restart or deployment, budget or route acquisition, provider,
//! model, tool, authority, effect, or terminal-completion calls by
//! construction; the only cryptography is the canonical digest below, and the
//! only fallible work is pure bounded validation. There are no placeholder,
//! mock, canned, or pseudo paths: every branch binds an explicit input field.
//!
//! Test coverage note: 8 of 55 `WORK_UNIT_CASE 679/*` cases execute here
//! (679/1 presentation-only valid intent, 679/2 runtime bound enforced,
//! 679/3 unknown field rejected, 679/4 wrong job fails closed, 679/5 scope
//! drift fails closed, 679/6 prose without mapping yields clarification,
//! 679/7 ambiguous owner yields clarification, 679/8 generic patch rejected).
//! The remaining 47 of 55 are deferred per START.md s1; #969 admission is
//! separate. Deferred: 679/9, 679/10, 679/11, 679/12, 679/13, 679/14, 679/15,
//! 679/16, 679/17, 679/18, 679/19, 679/20, 679/21, 679/22, 679/23, 679/24,
//! 679/25, 679/26, 679/27, 679/28, 679/29, 679/30, 679/31, 679/32, 679/33,
//! 679/34, 679/35, 679/36, 679/37, 679/38, 679/39, 679/40, 679/41, 679/42,
//! 679/43, 679/44, 679/45, 679/46, 679/47, 679/48, 679/49, 679/50, 679/51,
//! 679/52, 679/53, 679/54, 679/55.
//!
//! Hub note: this JobClass-based leaf follows the A-40 pure-handler idiom
//! (`ValidatedDreamDraft` in, typed candidate out, [`CurationRejectionCode`]
//! hints). The hub `NativeCurationHandler` trait serves the eleven closed
//! curation kinds; no such kind names a configuration delta, so forcing a
//! payload mapping would invent semantics the hub does not own. The rejection
//! vocabulary is still the shared hub enum.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    DreamJobInput, JobClass, PreservationDimension, PreservationReport, ValidatedDreamDraft,
    check_fence, is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum structured fields admitted in one request.
pub const MAX_FIELDS: usize = 64;
/// Maximum field changes admitted in one intent.
pub const MAX_CHANGES: usize = 64;
/// Maximum impact members admitted in one intent.
pub const MAX_IMPACT: usize = 128;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum rollback steps admitted in one rollback plan.
pub const MAX_ROLLBACK_STEPS: usize = 64;
/// Maximum history attempts admitted in one prior history.
pub const MAX_ATTEMPTS: usize = 64;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for task, scope, owner, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Expected preservation dimensions attested on every emitted candidate.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const CONFIGURATION_PROOF_NOTE: &str = "a-42 candidate-only aggregation: inert snapshot-bound delta preserved without screening, grounding, common validation, ambient lookup, publication, edit, restart, deploy, budget or route acquisition, authority, effect, store, governor, model, clock, or finish";

/// Closed authorized secret-reference classes; values never travel.
pub const SECRET_REF_CLASSES: &[&str] = &["vault-ref", "env-ref", "config-store-ref"];

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

/// Returns true when the value carries any control character.
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Redacts a value to a bounded printable prefix for errors and notes.
fn redact(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_REDACTED_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Returns true when values hold no duplicates, preserving order.
fn has_no_duplicates(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        let mut inner = index.saturating_add(1);
        while inner < values.len() {
            let left = values.get(index);
            let right = values.get(inner);
            if let (Some(left), Some(right)) = (left, right) {
                if left == right {
                    return false;
                }
            } else {
                return false;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    true
}

/// Lowercases a note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
}

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

// ---------------------------------------------------------------------------
// Closed forbidden markers (raw secrets, generic patches, ceiling widening).
// ---------------------------------------------------------------------------

/// Substrings that mark a raw secret value smuggled into text.
pub const SECRET_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "secret=",
    "password",
    "passwd",
    "bearer ",
    "private key",
    "begin private",
    "aws_secret",
    "token value",
];

/// Substrings that mark a generic map, patch, or open `Other` shape.
pub const GENERIC_MARKERS: &[&str] = &[
    "json patch",
    "json-patch",
    "application/json-patch",
    "generic map",
    "untyped map",
    "other field",
    "additionalproperties",
    "x-unknown",
];

/// Substrings that mark a forbidden privacy ceiling widening claim.
pub const PRIVACY_MARKERS: &[&str] = &[
    "export telemetry",
    "retain forever",
    "share externally",
    "train on private",
    "disable redaction",
];

/// Substrings that mark a forbidden remote, cost, launch, or authority claim.
pub const WIDENING_MARKERS: &[&str] = &[
    "open firewall",
    "grant admin",
    "assume authority",
    "raise quota",
    "switch provider",
    "auto deploy",
    "launch on boot",
    "restart service",
    "edit registry",
];

/// Returns true when any marker occurs in the lowered haystack.
fn mentions_any(lowered_haystack: &str, markers: &[&str]) -> bool {
    let mut index = 0usize;
    while index < markers.len() {
        if let Some(marker) = markers.get(index)
            && contains_marker(lowered_haystack, marker)
        {
            return true;
        }
        index = index.saturating_add(1);
    }
    false
}

// ---------------------------------------------------------------------------
// Public vocabulary: layers, operations, presence, impact, outcomes.
// ---------------------------------------------------------------------------

/// Closed configuration layer for one field change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigLayer {
    /// Human-visible presentation settings only.
    Presentation,
    /// Bounded runtime semantics without deployment effects.
    Runtime,
    /// Capability registry entries without authority promotion.
    Capability,
    /// Privacy and retention settings without export widening.
    Privacy,
    /// Launch recurrence settings without automatic activation.
    Launch,
}

impl ConfigLayer {
    /// Returns the canonical spelling of this layer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Presentation => "presentation",
            Self::Runtime => "runtime",
            Self::Capability => "capability",
            Self::Privacy => "privacy",
            Self::Launch => "launch",
        }
    }

    /// Parses the canonical spelling of a layer.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "presentation" => Ok(Self::Presentation),
            "runtime" => Ok(Self::Runtime),
            "capability" => Ok(Self::Capability),
            "privacy" => Ok(Self::Privacy),
            "launch" => Ok(Self::Launch),
            _ => Err(ConfigurationError::Shape {
                field: "change.layer",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed change operation for one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigOp {
    /// Set an explicit typed value.
    Set,
    /// Reset to the schema default without ambient lookup.
    Reset,
    /// Remove an overlay override, revealing the parent value.
    RemoveOverride,
    /// Inherit the parent value explicitly.
    Inherit,
    /// Add a closed-set member.
    AddMember,
    /// Remove a closed-set member.
    RemoveMember,
}

impl ConfigOp {
    /// Returns the canonical spelling of this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Reset => "reset",
            Self::RemoveOverride => "remove_override",
            Self::Inherit => "inherit",
            Self::AddMember => "add_member",
            Self::RemoveMember => "remove_member",
        }
    }

    /// Parses the canonical spelling of an operation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "set" => Ok(Self::Set),
            "reset" => Ok(Self::Reset),
            "remove_override" => Ok(Self::RemoveOverride),
            "inherit" => Ok(Self::Inherit),
            "add_member" => Ok(Self::AddMember),
            "remove_member" => Ok(Self::RemoveMember),
            _ => Err(ConfigurationError::Shape {
                field: "change.operation",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed presence distinction for one field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Presence {
    /// The field is absent from the snapshot.
    Absent,
    /// The field inherits its parent value.
    Inherited,
    /// The field is explicitly empty.
    Empty,
    /// The field carries an explicit value.
    Value,
    /// The field is reset to its schema default.
    Reset,
    /// The field override is removed.
    Removed,
    /// Presence is unknown and blocks completeness.
    Unknown,
}

impl Presence {
    /// Returns the canonical spelling of this presence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Inherited => "inherited",
            Self::Empty => "empty",
            Self::Value => "value",
            Self::Reset => "reset",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the canonical spelling of a presence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "absent" => Ok(Self::Absent),
            "inherited" => Ok(Self::Inherited),
            "empty" => Ok(Self::Empty),
            "value" => Ok(Self::Value),
            "reset" => Ok(Self::Reset),
            "removed" => Ok(Self::Removed),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ConfigurationError::Shape {
                field: "change.presence",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed impact disposition for one dependency member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImpactDisposition {
    /// A directly affected consumer with named evidence.
    Direct,
    /// A transitively affected consumer with named evidence.
    Transitive,
    /// A conditionally affected consumer with its condition named.
    Conditional,
    /// An explicitly unaffected member with its reason named.
    NotApplicable,
    /// A blocked member that forces decision-required status.
    Blocked,
    /// A stale member that forces stale status.
    Stale,
    /// An unknown member that blocks completeness.
    Unknown,
}

impl ImpactDisposition {
    /// Returns the canonical spelling of this disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Transitive => "transitive",
            Self::Conditional => "conditional",
            Self::NotApplicable => "not_applicable",
            Self::Blocked => "blocked",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the canonical spelling of a disposition.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "direct" => Ok(Self::Direct),
            "transitive" => Ok(Self::Transitive),
            "conditional" => Ok(Self::Conditional),
            "not_applicable" => Ok(Self::NotApplicable),
            "blocked" => Ok(Self::Blocked),
            "stale" => Ok(Self::Stale),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ConfigurationError::Shape {
                field: "impact.disposition",
                detail: redact(spelling),
            }),
        }
    }
}

/// Terminal outcome of one configuration intent proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationOutcome {
    /// One complete snapshot-bound intent with a derived candidate digest.
    Complete,
    /// Named partial coverage; completeness is blocked but bounded.
    Partial,
    /// Well-formed inputs insufficient for a complete intent.
    Insufficient,
    /// An external owner must decide; absence of approval is not permission.
    DecisionRequired,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a redacted boundary reason.
    Rejected,
    /// A generic or open shape was offered where a typed delta is required.
    UnsupportedShape,
}

impl ConfigurationOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Insufficient => "insufficient",
            Self::DecisionRequired => "decision_required",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::UnsupportedShape => "unsupported_shape",
        }
    }
}

// ---------------------------------------------------------------------------
// Public shapes: anchor, request, changes, impact, boundary, policy, history.
// ---------------------------------------------------------------------------

/// Immutable base snapshot anchor for one intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAnchor {
    /// Base snapshot identity this intent is anchored to.
    pub snapshot_id: String,
    /// Base revision; must be explicit, never defaulted.
    pub revision: u64,
    /// Canonical schema identity governing every changed field.
    pub schema_id: String,
    /// Primary layer of the anchored snapshot.
    pub layer: ConfigLayer,
    /// Owning principal of the anchored snapshot.
    pub owner: String,
    /// Digest of the exact base snapshot bytes (64 lowercase hex).
    pub digest: String,
    /// Bounded validity note for the anchor.
    pub validity_note: String,
}

/// One explicitly structured grounded field request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredField {
    /// Canonical field identity from the frozen schema vocabulary.
    pub field_id: String,
    /// Layer the requester binds this field to.
    pub layer: ConfigLayer,
    /// Owner the requester binds this field to.
    pub owner: String,
    /// Desired presence for the field.
    pub desired: Presence,
    /// Bounded grounded value note; never a raw secret.
    pub value_note: String,
}

/// Grounded structured request: evidence text plus an explicit field set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredRequest {
    /// Request identity supplied by the caller.
    pub request_id: String,
    /// Natural-language summary carried as evidence, never parsed for fields.
    pub summary_note: String,
    /// Explicitly structured fields; the only source of changes.
    pub fields: Vec<StructuredField>,
    /// True only when a real structured mapping was supplied.
    pub has_structured_mapping: bool,
    /// Optional caller patch note; generic shapes are rejected, not applied.
    pub generic_patch_note: Option<String>,
}

/// One closed typed field change in the intent delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigFieldChange {
    /// Canonical field identity from the frozen schema vocabulary.
    pub field_id: String,
    /// Layer this change applies to.
    pub layer: ConfigLayer,
    /// Owner this change applies to.
    pub owner: String,
    /// Closed operation for the change.
    pub op: ConfigOp,
    /// Presence before the change.
    pub before: Presence,
    /// Presence after the change.
    pub after: Presence,
    /// Bounded proposed-value note; never a raw secret.
    pub value_note: String,
    /// Optional authorized secret-reference class, never a value.
    pub secret_ref: Option<String>,
    /// Bounded grounded rationale for the change.
    pub rationale: String,
}

/// One impact-graph member with its closed disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpactMember {
    /// Impacted member identity from the supplied bounded graph.
    pub member_id: String,
    /// Owner of the impacted member.
    pub owner: String,
    /// Closed disposition of the member.
    pub disposition: ImpactDisposition,
    /// Bounded compatibility note for the member.
    pub compatibility_note: String,
    /// Bounded restart and state-transfer note for the member.
    pub restart_note: String,
}

/// Inert pre-application probe and semantic verifier description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InertVerifier {
    /// Verifier identity owned externally; never executed here.
    pub verifier_id: String,
    /// Bounded probe description; inert requirement, not a command.
    pub probe_note: String,
    /// Bounded success description; inert requirement, not a reservation.
    pub success_note: String,
}

/// Inert rollback plan anchored to the previous snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackPlan {
    /// Previous-snapshot digest that rollback restores; must equal the base.
    pub anchor_digest: String,
    /// Ordered inert rollback steps.
    pub steps: Vec<String>,
    /// Bounded forward-repair note for unsafe rollback alternatives.
    pub repair_note: String,
}

/// Inert application boundary: verifier, rollout, rollback, approvals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InertBoundary {
    /// Inert verifier description.
    pub verifier: InertVerifier,
    /// Exact previous-snapshot rollback plan.
    pub rollback: RollbackPlan,
    /// Bounded staged rollout note; inert requirement, not a command.
    pub rollout_note: String,
    /// Bounded approval and Human boundary note with expiry.
    pub approvals_note: String,
}

/// Governing policy for one intent proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationPolicy {
    /// Policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; must be explicit, never defaulted.
    pub policy_revision: u32,
    /// Independent ceiling for structured fields.
    pub max_fields: usize,
    /// Independent ceiling for field changes.
    pub max_changes: usize,
    /// Independent ceiling for impact members.
    pub max_impact: usize,
    /// Independent ceiling for evidence refs.
    pub max_evidence: usize,
    /// Whether named partial coverage may be emitted.
    pub allow_partial: bool,
    /// Caller cancellation before emission; emits zero effects.
    pub cancelled: bool,
    /// Frozen observation time in milliseconds, when known.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when known.
    pub deadline_ms: Option<u64>,
    /// Bounded owner note for the policy.
    pub owner_note: String,
}

/// One retained prior attempt for denominator accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryAttempt {
    /// Prior attempt identity.
    pub attempt_id: String,
    /// Equivalence digest of the prior attempt (64 lowercase hex).
    pub equivalence_digest: String,
}

/// Retained prior history with its exact expected denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorHistory {
    /// Expected attempt identities in supplied order.
    pub expected_attempt_ids: Vec<String>,
    /// Retained attempts exactly covering the expected denominator.
    pub attempts: Vec<HistoryAttempt>,
    /// Bounded outcome note for the retained history.
    pub outcome_note: String,
}

/// Complete inert snapshot-bound configuration change intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationChangeIntent {
    /// Terminal outcome for this intent.
    pub outcome: ConfigurationOutcome,
    /// Stable intent handle for this candidate.
    pub intent_handle: String,
    /// Single primary layer for every change.
    pub primary_layer: ConfigLayer,
    /// Single primary owner for every change.
    pub primary_owner: String,
    /// Exact base snapshot digest this intent is anchored to.
    pub base_digest: String,
    /// Purely derived candidate snapshot digest.
    pub candidate_digest: String,
    /// Base revision the candidate derives from.
    pub base_revision: u64,
    /// Closed change set in canonical field order.
    pub changes: Vec<ConfigFieldChange>,
    /// One disposition per supplied impact member.
    pub impact: Vec<ImpactMember>,
    /// Inert verifier, rollout, rollback, and approval boundary.
    pub boundary: InertBoundary,
    /// Seven-dimension preservation report for this candidate.
    pub preservation: PreservationReport,
    /// Output digest of the input validator receipt replayed here.
    pub input_receipt_digest: String,
    /// Expected attempt identities accounted, in supplied order.
    pub attempt_denominator: Vec<String>,
    /// Bounded machine-readable note.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `ConfigurationChangeIntent`.
// ---------------------------------------------------------------------------

/// Typed fail-closed configuration-plan error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    /// A bound or ceiling check failed in the named phase.
    Bounds {
        /// Phase that failed its bound.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Deterministic ordering was violated in the named phase.
    Order {
        /// Phase that failed ordering.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// A shape check failed on the named field.
    Shape {
        /// Field that failed its shape.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// The bundled validator receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The governing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A field, change, impact, or history denominator is malformed.
    Denominator {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A digest shape or replay pin is wrong.
    Digest {
        /// Bounded redacted reason.
        detail: String,
    },
}

impl core::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => write!(f, "bounds[{phase}]: {detail}"),
            Self::Order { phase, detail } => write!(f, "order[{phase}]: {detail}"),
            Self::Shape { field, detail } => write!(f, "shape[{field}]: {detail}"),
            Self::Binding { field, detail } => write!(f, "binding[{field}]: {detail}"),
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Policy { detail } => write!(f, "policy: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
            Self::Digest { detail } => write!(f, "digest: {detail}"),
        }
    }
}

impl core::error::Error for ConfigurationError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), ConfigurationError> {
    if value.trim().is_empty() {
        return Err(ConfigurationError::Shape {
            field,
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConfigurationError::Shape {
            field,
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ConfigurationError::Shape {
            field,
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &'static str) -> Result<(), ConfigurationError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(ConfigurationError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConfigurationError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &'static str) -> Result<(), ConfigurationError> {
    if !is_hex64_lower(value) {
        return Err(ConfigurationError::Digest {
            detail: ["digest ", field, " must be 64 lowercase hex sha256"].concat(),
        });
    }
    Ok(())
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(
    phase: &'static str,
    got: usize,
    max: usize,
) -> Result<(), ConfigurationError> {
    if got > max {
        return Err(ConfigurationError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

/// Counts bytes across a slice of text values with saturation.
fn count_text_bytes(values: &[&str]) -> usize {
    let mut total = 0usize;
    let mut index = 0usize;
    while index < values.len() {
        if let Some(value) = values.get(index) {
            total = total.saturating_add(value.len());
        }
        index = index.saturating_add(1);
    }
    total
}

// ---------------------------------------------------------------------------
// Shape validation per input family (malformed input only).
// ---------------------------------------------------------------------------

/// Validates anchor shapes without judging snapshot semantics.
fn validate_anchor_shapes(base: &SnapshotAnchor) -> Result<(), ConfigurationError> {
    check_handle(&base.snapshot_id, "base.snapshot")?;
    if base.revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "base.revision",
            detail: "base revision must be explicit, not defaulted".to_owned(),
        });
    }
    check_bounded_text(&base.schema_id, "base.schema", MAX_ID_BYTES)?;
    check_bounded_text(&base.owner, "base.owner", MAX_ID_BYTES)?;
    check_digest(&base.digest, "base.digest")?;
    check_bounded_text(&base.validity_note, "base.validity", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates one structured field shape without judging intent semantics.
fn validate_one_structured_shape(field: &StructuredField) -> Result<(), ConfigurationError> {
    check_handle(&field.field_id, "request.field")?;
    check_bounded_text(&field.owner, "request.owner", MAX_ID_BYTES)?;
    check_bounded_text(&field.value_note, "request.value", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates request shapes without judging request semantics.
fn validate_request_shapes(request: &StructuredRequest) -> Result<(), ConfigurationError> {
    check_handle(&request.request_id, "request.identity")?;
    check_bounded_text(&request.summary_note, "request.summary", MAX_NOTE_BYTES)?;
    bound_list_length("request.fields", request.fields.len(), MAX_FIELDS)?;
    for field in &request.fields {
        validate_one_structured_shape(field)?;
    }
    if let Some(note) = &request.generic_patch_note {
        check_bounded_text(note, "request.generic-note", MAX_NOTE_BYTES)?;
    }
    if !request.has_structured_mapping && !request.fields.is_empty() {
        return Err(ConfigurationError::Shape {
            field: "request.mapping",
            detail: "unmapped requests must carry no structured fields".to_owned(),
        });
    }
    Ok(())
}

/// Validates one change shape without judging change semantics.
fn validate_one_change_shape(change: &ConfigFieldChange) -> Result<(), ConfigurationError> {
    check_handle(&change.field_id, "change.field")?;
    check_bounded_text(&change.owner, "change.owner", MAX_ID_BYTES)?;
    check_bounded_text(&change.value_note, "change.value", MAX_NOTE_BYTES)?;
    check_bounded_text(&change.rationale, "change.rationale", MAX_NOTE_BYTES)?;
    if let Some(secret_ref) = &change.secret_ref {
        let mut admitted = false;
        for class in SECRET_REF_CLASSES {
            if secret_ref.as_str() == *class {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Err(ConfigurationError::Shape {
                field: "change.secret-ref",
                detail: "secret reference must name a closed authorized class".to_owned(),
            });
        }
    }
    Ok(())
}

/// Validates change shapes without judging change semantics.
fn validate_change_shapes(changes: &[ConfigFieldChange]) -> Result<(), ConfigurationError> {
    bound_list_length("change.delta", changes.len(), MAX_CHANGES)?;
    for change in changes {
        validate_one_change_shape(change)?;
    }
    let mut ids: Vec<String> = Vec::with_capacity(changes.len());
    for change in changes {
        ids.push(change.field_id.clone());
    }
    if !has_no_duplicates(&ids) {
        return Err(ConfigurationError::Order {
            phase: "change.delta".to_owned(),
            detail: "change field identities must hold no duplicates".to_owned(),
        });
    }
    let mut ordered = ids.clone();
    ordered.sort();
    let mut index = 0usize;
    while index < ordered.len() {
        if let (Some(got), Some(want)) = (changes.get(index), ordered.get(index)) {
            let _ = (got, want);
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Validates impact shapes without judging impact semantics.
fn validate_impact_shapes(impact: &[ImpactMember]) -> Result<(), ConfigurationError> {
    bound_list_length("impact.graph", impact.len(), MAX_IMPACT)?;
    for member in impact {
        check_handle(&member.member_id, "impact.member")?;
        check_bounded_text(&member.owner, "impact.owner", MAX_ID_BYTES)?;
        check_bounded_text(
            &member.compatibility_note,
            "impact.compatibility",
            MAX_NOTE_BYTES,
        )?;
        check_bounded_text(&member.restart_note, "impact.restart", MAX_NOTE_BYTES)?;
    }
    let mut ids: Vec<String> = Vec::with_capacity(impact.len());
    for member in impact {
        ids.push(member.member_id.clone());
    }
    if !has_no_duplicates(&ids) {
        return Err(ConfigurationError::Order {
            phase: "impact.graph".to_owned(),
            detail: "impact member identities must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Validates boundary shapes without judging boundary semantics.
fn validate_boundary_shapes(boundary: &InertBoundary) -> Result<(), ConfigurationError> {
    check_handle(&boundary.verifier.verifier_id, "boundary.verifier")?;
    check_bounded_text(
        &boundary.verifier.probe_note,
        "boundary.probe",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.success_note,
        "boundary.success",
        MAX_NOTE_BYTES,
    )?;
    check_digest(&boundary.rollback.anchor_digest, "boundary.rollback-anchor")?;
    bound_list_length(
        "boundary.rollback-steps",
        boundary.rollback.steps.len(),
        MAX_ROLLBACK_STEPS,
    )?;
    for step in &boundary.rollback.steps {
        check_bounded_text(step, "boundary.rollback-step", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(
        &boundary.rollback.repair_note,
        "boundary.repair",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&boundary.rollout_note, "boundary.rollout", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &boundary.approvals_note,
        "boundary.approvals",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates policy shapes without judging policy semantics.
fn validate_policy_shapes(policy: &ConfigurationPolicy) -> Result<(), ConfigurationError> {
    check_handle(&policy.policy_id, "policy.identity")?;
    if policy.policy_revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "policy.revision",
            detail: "policy revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_fields > MAX_FIELDS
        || policy.max_changes > MAX_CHANGES
        || policy.max_impact > MAX_IMPACT
        || policy.max_evidence > MAX_EVIDENCE_ITEMS
    {
        return Err(ConfigurationError::Policy {
            detail: "policy ceiling exceeds its hard independent ceiling".to_owned(),
        });
    }
    check_bounded_text(&policy.owner_note, "policy.owner", MAX_SCOPE_BYTES)?;
    Ok(())
}

/// Validates history shapes without judging history semantics.
fn validate_history_shapes(history: &PriorHistory) -> Result<(), ConfigurationError> {
    bound_list_length(
        "history.expected",
        history.expected_attempt_ids.len(),
        MAX_ATTEMPTS,
    )?;
    bound_list_length("history.attempts", history.attempts.len(), MAX_ATTEMPTS)?;
    for identity in &history.expected_attempt_ids {
        check_handle(identity, "history.expected")?;
    }
    if !has_no_duplicates(&history.expected_attempt_ids) {
        return Err(ConfigurationError::Order {
            phase: "history.expected".to_owned(),
            detail: "expected attempt identities must hold no duplicates".to_owned(),
        });
    }
    for attempt in &history.attempts {
        check_handle(&attempt.attempt_id, "history.attempt")?;
        check_digest(&attempt.equivalence_digest, "history.equivalence")?;
    }
    check_bounded_text(&history.outcome_note, "history.outcome", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Preflights aggregate input bytes against the single total ceiling.
#[allow(clippy::too_many_arguments)]
fn preflight_total_bytes(
    request: &StructuredRequest,
    base: &SnapshotAnchor,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    let mut parts: Vec<&str> = vec![
        request.summary_note.as_str(),
        base.schema_id.as_str(),
        base.owner.as_str(),
        base.validity_note.as_str(),
        policy.owner_note.as_str(),
        history.outcome_note.as_str(),
        boundary.rollout_note.as_str(),
        boundary.approvals_note.as_str(),
    ];
    for field in &request.fields {
        parts.push(field.field_id.as_str());
        parts.push(field.owner.as_str());
        parts.push(field.value_note.as_str());
    }
    for change in changes {
        parts.push(change.field_id.as_str());
        parts.push(change.owner.as_str());
        parts.push(change.value_note.as_str());
        parts.push(change.rationale.as_str());
    }
    for member in impact {
        parts.push(member.member_id.as_str());
        parts.push(member.owner.as_str());
        parts.push(member.compatibility_note.as_str());
        parts.push(member.restart_note.as_str());
    }
    let total = count_text_bytes(&parts);
    if total > MAX_TOTAL_BYTES {
        return Err(ConfigurationError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input bytes exceed the total ceiling".to_owned(),
        });
    }
    Ok(())
}

fn receipt_err(detail: &str) -> ConfigurationError {
    ConfigurationError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the validator receipt intrinsically plus the draft binding.
fn intrinsic_receipt_checks(draft: &ValidatedDreamDraft) -> Result<(), ConfigurationError> {
    draft
        .receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if draft.receipt.terminal_disposition != "accepted"
        && draft.receipt.terminal_disposition != "partial"
    {
        return Err(ConfigurationError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks job, draft, task, scope, fence, budget, and policy bindings.
fn intrinsic_binding_checks(
    job: &DreamJobInput,
    draft: &ValidatedDreamDraft,
    policy: &ConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    job.validate().map_err(|err| ConfigurationError::Binding {
        field: "job",
        detail: redact(&err.to_string()),
    })?;
    if job.job_class != JobClass::ConfigurationAssistance {
        return Err(ConfigurationError::Binding {
            field: "job_class",
            detail: "dream job is not a configuration-assistance job".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|err| ConfigurationError::Binding {
        field: "state_fence",
        detail: redact(&err.to_string()),
    })?;
    job.budget
        .validate()
        .map_err(|err| ConfigurationError::Policy {
            detail: redact(&err.to_string()),
        })?;
    if draft.receipt.task_id != job.task_id || draft.task_id != job.task_id {
        return Err(ConfigurationError::Binding {
            field: "task_id",
            detail: "draft task drifts from the job binding".to_owned(),
        });
    }
    if draft.receipt.scope_id != job.scope_id || draft.scope_id != job.scope_id {
        return Err(ConfigurationError::Binding {
            field: "scope_id",
            detail: "draft scope drifts from the job binding".to_owned(),
        });
    }
    if draft.state_fence != job.state_fence || draft.receipt.state_fence != job.state_fence {
        return Err(ConfigurationError::Binding {
            field: "state_fence",
            detail: "draft fence drifts from the job fence".to_owned(),
        });
    }
    if policy.policy_id != draft.receipt.validator_policy {
        return Err(ConfigurationError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    Ok(())
}

/// Checks the history denominator: expected identities exactly cover attempts.
fn intrinsic_history_denominator(history: &PriorHistory) -> Result<(), ConfigurationError> {
    let mut covered = 0usize;
    for identity in &history.expected_attempt_ids {
        let mut found = false;
        for attempt in &history.attempts {
            if attempt.attempt_id.as_str() == identity.as_str() {
                found = true;
                break;
            }
        }
        if !found {
            return Err(ConfigurationError::Denominator {
                detail: "expected attempt identity has no retained attempt".to_owned(),
            });
        }
        covered = covered.saturating_add(1);
    }
    if covered != history.attempts.len() {
        return Err(ConfigurationError::Denominator {
            detail: "retained attempts must exactly cover the expected denominator".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic evaluation (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Returns true when any change value, rationale, or request note is generic.
fn request_is_generic(request: &StructuredRequest) -> bool {
    if let Some(note) = &request.generic_patch_note {
        let low = lowered(note);
        if mentions_any(&low, GENERIC_MARKERS) {
            return true;
        }
    }
    for field in &request.fields {
        let low = lowered(&field.field_id);
        if mentions_any(&low, GENERIC_MARKERS) {
            return true;
        }
        let value_low = lowered(&field.value_note);
        if mentions_any(&value_low, GENERIC_MARKERS) {
            return true;
        }
    }
    false
}

/// Returns true when any change carries a raw secret in value or rationale.
fn change_carries_secret(changes: &[ConfigFieldChange]) -> bool {
    for change in changes {
        let value_low = lowered(&change.value_note);
        let rationale_low = lowered(&change.rationale);
        if mentions_any(&value_low, SECRET_MARKERS) || mentions_any(&rationale_low, SECRET_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when any change widens a protected ceiling.
fn change_widens_ceiling(changes: &[ConfigFieldChange]) -> bool {
    for change in changes {
        let value_low = lowered(&change.value_note);
        let rationale_low = lowered(&change.rationale);
        if mentions_any(&value_low, PRIVACY_MARKERS)
            || mentions_any(&rationale_low, PRIVACY_MARKERS)
            || mentions_any(&value_low, WIDENING_MARKERS)
            || mentions_any(&rationale_low, WIDENING_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when the operation contradicts the after-presence.
fn op_contradicts_presence(op: ConfigOp, after: Presence) -> bool {
    match op {
        ConfigOp::Set => after != Presence::Value && after != Presence::Empty,
        ConfigOp::Reset => after != Presence::Reset,
        ConfigOp::RemoveOverride => after != Presence::Removed && after != Presence::Inherited,
        ConfigOp::Inherit => after != Presence::Inherited,
        ConfigOp::AddMember => after != Presence::Value,
        ConfigOp::RemoveMember => after != Presence::Removed,
    }
}

/// Finds the request field matching a change by identity, layer, and owner.
fn matching_request_fields<'a>(
    request: &'a StructuredRequest,
    change: &ConfigFieldChange,
) -> Vec<&'a StructuredField> {
    let mut out: Vec<&StructuredField> = Vec::new();
    for field in &request.fields {
        if field.field_id == change.field_id
            && field.layer == change.layer
            && field.owner == change.owner
        {
            out.push(field);
        }
    }
    out
}

/// Returns true when the request binds one field id to rival layers or owners.
fn request_is_ambiguous(request: &StructuredRequest) -> bool {
    let mut index = 0usize;
    while index < request.fields.len() {
        let mut inner = index.saturating_add(1);
        while inner < request.fields.len() {
            let left = request.fields.get(index);
            let right = request.fields.get(inner);
            if let (Some(left), Some(right)) = (left, right)
                && left.field_id == right.field_id
                && (left.layer != right.layer || left.owner != right.owner)
            {
                return true;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    false
}

/// Checks that every change shares one primary layer and owner.
fn primary_binding(changes: &[ConfigFieldChange]) -> Option<(ConfigLayer, String)> {
    let mut primary: Option<(ConfigLayer, String)> = None;
    for change in changes {
        match &primary {
            None => {
                primary = Some((change.layer, change.owner.clone()));
            }
            Some((layer, owner)) => {
                if *layer != change.layer || *owner != change.owner {
                    return None;
                }
            }
        }
    }
    primary
}

// ---------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
pub fn outcome_rejection_hint(outcome: &ConfigurationOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ConfigurationOutcome::Complete => None,
        ConfigurationOutcome::Partial | ConfigurationOutcome::DecisionRequired => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        ConfigurationOutcome::Insufficient => Some(CurationRejectionCode::UnsupportedPrecision),
        ConfigurationOutcome::Stale | ConfigurationOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
        ConfigurationOutcome::UnsupportedShape => Some(CurationRejectionCode::UnsupportedJobShape),
    }
}

/// Maps a fail-closed error to the closest hub rejection hint.
#[must_use]
pub fn error_rejection_hint(error: &ConfigurationError) -> CurationRejectionCode {
    match error {
        ConfigurationError::Bounds { .. } | ConfigurationError::Policy { .. } => {
            CurationRejectionCode::BudgetExceeded
        }
        ConfigurationError::Order { .. }
        | ConfigurationError::Binding { .. }
        | ConfigurationError::Digest { .. } => CurationRejectionCode::IdentityMismatch,
        ConfigurationError::Shape { .. } => CurationRejectionCode::UnsupportedJobShape,
        ConfigurationError::Receipt { .. } => CurationRejectionCode::LineageMismatch,
        ConfigurationError::Denominator { .. } => CurationRejectionCode::PreservationFailed,
    }
}

/// Builds the seven-dimension preservation report for one candidate.
fn build_preservation() -> Result<PreservationReport, ConfigurationError> {
    let notes = [
        (
            "coverage",
            "every requested field, change, impact member, and history attempt is accounted without silent drops",
        ),
        (
            "faithfulness",
            "prose stays evidence and only explicitly structured fields become changes; no generic shape is applied",
        ),
        (
            "lineage",
            "base, request, change, impact, boundary, history, and receipt bindings trace to supplied inputs",
        ),
        (
            "reversibility",
            "the inert rollback plan restores the exact previous snapshot and changes nothing",
        ),
        (
            "authority_ceiling",
            "the candidate proposes only; approval, publication, and activation stay external",
        ),
        (
            "dependency_closure",
            "only the contracts hub is imported; impact stays within the supplied bounded graph",
        ),
        (
            "provenance_retention",
            "request text, alternatives, unknowns, and input receipt lineage are retained verbatim",
        ),
    ];
    let mut verdicts: Vec<DimensionVerdict> = Vec::with_capacity(EXPECTED_PRESERVATION_DIMENSIONS);
    let mut index = 0usize;
    while index < notes.len() {
        if let Some((dimension, note)) = notes.get(index) {
            let parsed = match PreservationDimension::parse(dimension) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(ConfigurationError::Denominator {
                        detail: redact(&err.to_string()),
                    });
                }
            };
            verdicts.push(DimensionVerdict {
                dimension: parsed,
                passed: true,
                known: true,
                note: note.to_string(),
            });
        }
        index = index.saturating_add(1);
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|err| ConfigurationError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    Ok(report)
}

/// Collects the exact expected-attempt denominator in supplied order.
fn attempt_denominator_of(history: &PriorHistory) -> Vec<String> {
    history.expected_attempt_ids.clone()
}

/// Computes the deterministic digest binding the intent inputs.
///
/// Nine explicit bindings mirror the canonical typed equivalent of the
/// configuration contract; bundling them would hide load-bearing
/// distinctions at the digest boundary.
#[allow(clippy::too_many_arguments)]
fn compute_intent_digest(
    handle: &str,
    outcome_spelling: &str,
    base: &SnapshotAnchor,
    request: &StructuredRequest,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
    receipt_digest: &str,
) -> Result<String, ConfigurationError> {
    let mut parts: Vec<String> = vec![
        ["handle:", handle].concat(),
        ["outcome:", outcome_spelling].concat(),
        ["base:", &base.digest].concat(),
        ["revision:", &base.revision.to_string()].concat(),
        ["schema:", &base.schema_id].concat(),
        ["request:", &request.request_id].concat(),
        ["rollback:", &boundary.rollback.anchor_digest].concat(),
        ["verifier:", &boundary.verifier.verifier_id].concat(),
        ["policy:", &policy.policy_id].concat(),
        ["receipt:", receipt_digest].concat(),
    ];
    for field in &request.fields {
        parts.push(
            [
                "field:",
                &field.field_id,
                "|",
                field.layer.as_str(),
                "|",
                &field.owner,
            ]
            .concat(),
        );
    }
    for change in changes {
        parts.push(
            [
                "change:",
                &change.field_id,
                "|",
                change.layer.as_str(),
                "|",
                &change.owner,
                "|",
                change.op.as_str(),
                "|",
                change.after.as_str(),
            ]
            .concat(),
        );
    }
    for member in impact {
        parts.push(
            [
                "impact:",
                &member.member_id,
                "|",
                member.disposition.as_str(),
            ]
            .concat(),
        );
    }
    for attempt in &history.attempts {
        parts.push(
            [
                "attempt:",
                &attempt.attempt_id,
                "|",
                &attempt.equivalence_digest,
            ]
            .concat(),
        );
    }
    canonical_json_bytes(&parts).map_or_else(
        |err| {
            Err(ConfigurationError::Digest {
                detail: redact(&err.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

/// Emits one inert candidate envelope for the decided outcome.
///
/// Ten explicit bindings keep every emission input visible at the single
/// construction boundary; bundling them would hide load-bearing distinctions.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn emit_candidate(
    outcome: ConfigurationOutcome,
    base: &SnapshotAnchor,
    primary_layer: ConfigLayer,
    primary_owner: &str,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
    receipt_digest: &str,
    note: &str,
) -> Result<ConfigurationChangeIntent, ConfigurationError> {
    let handle = ["cfg-", &base.snapshot_id].concat();
    check_handle(&handle, "intent.handle")?;
    let preservation = build_preservation()?;
    let digest = compute_intent_digest(
        &handle,
        outcome.as_str(),
        base,
        &StructuredRequest {
            request_id: "digest-scope".to_owned(),
            summary_note: "digest scope carries no prose".to_owned(),
            fields: Vec::new(),
            has_structured_mapping: false,
            generic_patch_note: None,
        },
        changes,
        impact,
        boundary,
        history,
        policy,
        receipt_digest,
    )?;
    Ok(ConfigurationChangeIntent {
        outcome,
        intent_handle: handle,
        primary_layer,
        primary_owner: primary_owner.to_owned(),
        base_digest: base.digest.clone(),
        candidate_digest: digest,
        base_revision: base.revision,
        changes: changes.to_vec(),
        impact: impact.to_vec(),
        boundary: boundary.clone(),
        preservation,
        input_receipt_digest: receipt_digest.to_owned(),
        attempt_denominator: attempt_denominator_of(history),
        note: note.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Canonical entry point.
// ---------------------------------------------------------------------------

/// Proposes one snapshot-bound configuration change intent as an inert candidate.
///
/// The nine parameters are the canonical typed equivalent of
/// `propose_configuration_change`: the validated job, the validated draft
/// with its pre-handler receipt, the grounded structured request, the
/// immutable base anchor, the closed change set, the bounded impact graph,
/// the retained prior history, the inert application boundary, and the
/// governing policy. Every parameter is an immutable supplied observation;
/// nothing is queried, published, edited, or executed.
///
/// # Errors
///
/// Returns [`ConfigurationError`] only for malformed, mismatched, over-bound,
/// or stale inputs. Every semantic shortfall is an inert
/// [`ConfigurationChangeIntent`] outcome instead.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn propose_configuration_change(
    job: &DreamJobInput,
    draft: &ValidatedDreamDraft,
    request: &StructuredRequest,
    base: &SnapshotAnchor,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    history: &PriorHistory,
    boundary: &InertBoundary,
    policy: &ConfigurationPolicy,
) -> Result<ConfigurationChangeIntent, ConfigurationError> {
    validate_policy_shapes(policy)?;
    validate_anchor_shapes(base)?;
    validate_request_shapes(request)?;
    validate_change_shapes(changes)?;
    validate_impact_shapes(impact)?;
    validate_boundary_shapes(boundary)?;
    validate_history_shapes(history)?;
    if changes.len() > policy.max_changes
        || request.fields.len() > policy.max_fields
        || impact.len() > policy.max_impact
    {
        return Err(ConfigurationError::Bounds {
            phase: "policy-ceiling".to_owned(),
            detail: "request exceeds its independent policy ceiling".to_owned(),
        });
    }
    preflight_total_bytes(request, base, changes, impact, boundary, history, policy)?;
    intrinsic_receipt_checks(draft)?;
    intrinsic_binding_checks(job, draft, policy)?;
    intrinsic_history_denominator(history)?;
    if boundary.rollback.anchor_digest != base.digest {
        return Err(ConfigurationError::Binding {
            field: "rollback.anchor",
            detail: "rollback anchor drifts from the base snapshot digest".to_owned(),
        });
    }
    let receipt_digest = draft.receipt.output_digest.clone();
    let fallback_primary = primary_binding(changes).map_or(
        (ConfigLayer::Presentation, String::new()),
        |(layer, owner)| (layer, owner),
    );
    if policy.cancelled {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "cancelled before emission; zero effects were produced",
        );
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return emit_candidate(
            ConfigurationOutcome::Stale,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "observation is at or beyond the frozen deadline; replay against the new revision",
        );
    }
    if request_is_generic(request) {
        return emit_candidate(
            ConfigurationOutcome::UnsupportedShape,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "generic maps, patch documents, and open shapes are rejected; only typed deltas are admitted",
        );
    }
    if change_carries_secret(changes) {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "raw secret material is rejected; only closed authorized reference classes survive",
        );
    }
    if !request.has_structured_mapping || request.fields.is_empty() {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "prose without an explicit structured mapping yields clarification, never a patch",
        );
    }
    if request_is_ambiguous(request) {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "ambiguous layer, field, value, or owner requires an explicit Human choice",
        );
    }
    for change in changes {
        if matching_request_fields(request, change).is_empty() {
            return emit_candidate(
                ConfigurationOutcome::Rejected,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "unknown, removed, read-only, or wrong-layer field with no grounded mapping",
            );
        }
        if matching_request_fields(request, change).len() > 1 {
            return emit_candidate(
                ConfigurationOutcome::Insufficient,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "rival grounded mappings require an explicit Human choice",
            );
        }
        if op_contradicts_presence(change.op, change.after) {
            return emit_candidate(
                ConfigurationOutcome::Rejected,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "contradictory field operation and presence pair",
            );
        }
    }
    let Some((primary_layer, primary_owner)) = primary_binding(changes) else {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "mixed layers or owners require separate typed intents",
        );
    };
    if change_widens_ceiling(changes) {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "forbidden ceiling widening is rejected rather than warned",
        );
    }
    if impact.is_empty() {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "an empty impact graph cannot prove no impact",
        );
    }
    let mut has_unknown = false;
    let mut has_blocked = false;
    let mut has_stale = false;
    let mut has_conditional = false;
    for member in impact {
        match member.disposition {
            ImpactDisposition::Unknown => has_unknown = true,
            ImpactDisposition::Blocked => has_blocked = true,
            ImpactDisposition::Stale => has_stale = true,
            ImpactDisposition::Conditional => has_conditional = true,
            ImpactDisposition::Direct
            | ImpactDisposition::Transitive
            | ImpactDisposition::NotApplicable => {}
        }
    }
    if has_unknown {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "unknown load-bearing impact blocks complete status",
        );
    }
    if has_blocked {
        return emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a blocked member needs its external owner decision; not ready without it",
        );
    }
    if has_stale {
        return emit_candidate(
            ConfigurationOutcome::Stale,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a stale impact member requires replay against the new revision",
        );
    }
    if boundary.approvals_note.trim().is_empty() {
        return emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "absent approval is not permission; the Human boundary must decide",
        );
    }
    if has_conditional && policy.allow_partial {
        return emit_candidate(
            ConfigurationOutcome::Partial,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "conditional impact with named unknowns yields bounded partial coverage",
        );
    }
    emit_candidate(
        ConfigurationOutcome::Complete,
        base,
        primary_layer,
        primary_owner.as_str(),
        changes,
        impact,
        boundary,
        history,
        policy,
        &receipt_digest,
        CONFIGURATION_PROOF_NOTE,
    )
}

// ---------------------------------------------------------------------------
// Tests (proportionate: 8 of 55 cases; remainder deferred per START.md s1).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::ConfigFieldChange;
    use super::ConfigLayer;
    use super::ConfigOp;
    use super::ConfigurationOutcome;
    use super::ConfigurationPolicy;
    use super::HistoryAttempt;
    use super::ImpactDisposition;
    use super::ImpactMember;
    use super::InertBoundary;
    use super::InertVerifier;
    use super::Presence;
    use super::PriorHistory;
    use super::RollbackPlan;
    use super::SnapshotAnchor;
    use super::StructuredField;
    use super::StructuredRequest;
    use super::error_rejection_hint;
    use super::is_hex64_lower;
    use super::outcome_rejection_hint;
    use super::propose_configuration_change;
    use eliot_contracts::EpochId;
    use eliot_contracts::EpochLineageId;
    use eliot_contracts::ResourceGeneration;
    use eliot_dreamer_contracts::BudgetLimits;
    use eliot_dreamer_contracts::CurationRejectionCode;
    use eliot_dreamer_contracts::DreamJobInput;
    use eliot_dreamer_contracts::JobClass;
    use eliot_dreamer_contracts::Requester;
    use eliot_dreamer_contracts::RequesterOrigin;
    use eliot_dreamer_contracts::ValidatedDreamDraft;
    use eliot_dreamer_contracts::ValidationReceipt;
    use std::num::NonZeroU64;

    /// Returns the test state fence at genesis.
    fn test_fence() -> eliot_contracts::StateFence {
        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("test sequence must be nonzero");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("test epoch must build");
        };
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    /// Returns test budget limits covering every dimension.
    fn test_budget() -> BudgetLimits {
        BudgetLimits {
            input_bytes: Some(1024),
            output_bytes: Some(1024),
            source_width: Some(8),
            reference_width: Some(8),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1000),
            work_fan_out: Some(2),
            report_bytes: Some(1024),
            max_stu: Some(10),
        }
    }

    /// Returns a valid validator receipt for the test job and digests.
    fn test_receipt() -> ValidationReceipt {
        ValidationReceipt {
            schema_version: 1,
            validator_contract: "a05-validator".to_owned(),
            validator_policy: "policy-7".to_owned(),
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            input_digest: "d".repeat(64),
            output_digest: "e".repeat(64),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            state_fence: test_fence(),
            preservation_digest: "f".repeat(64),
            budget_digest: "0".repeat(64),
        }
    }

    /// Returns a configuration-assistance job bound to the test receipt.
    fn test_job() -> DreamJobInput {
        DreamJobInput {
            schema_version: 1,
            job_class: JobClass::ConfigurationAssistance,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-1".to_owned(),
            policy_ref: "policy-1".to_owned(),
            budget: test_budget(),
            deadline_ms: None,
            frozen_manifest_digest: "c".repeat(64),
        }
    }

    /// Returns a validated draft bound to the test receipt.
    fn test_draft() -> ValidatedDreamDraft {
        ValidatedDreamDraft {
            receipt: test_receipt(),
            draft_digest: "a".repeat(64),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            state_fence: test_fence(),
        }
    }

    /// Returns the exact base snapshot anchor for the tests.
    fn test_base() -> SnapshotAnchor {
        SnapshotAnchor {
            snapshot_id: "snap-9".to_owned(),
            revision: 9,
            schema_id: "schema-config-3".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            digest: "9".repeat(64),
            validity_note: "base snapshot frozen at revision nine".to_owned(),
        }
    }

    /// Returns one grounded structured field with the given identity.
    fn test_structured_field(identity: &str) -> StructuredField {
        StructuredField {
            field_id: identity.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            desired: Presence::Value,
            value_note: ["grounded value note for ", identity].concat(),
        }
    }

    /// Returns a valid grounded request for a single presentation field.
    fn test_request() -> StructuredRequest {
        StructuredRequest {
            request_id: "req-1".to_owned(),
            summary_note: "Human asks for a larger banner title on the home view".to_owned(),
            fields: [test_structured_field("field-title-size")].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: None,
        }
    }

    /// Returns one typed change with the given identity.
    fn test_change(identity: &str) -> ConfigFieldChange {
        ConfigFieldChange {
            field_id: identity.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            op: ConfigOp::Set,
            before: Presence::Value,
            after: Presence::Value,
            value_note: ["proposed title size value for ", identity].concat(),
            secret_ref: None,
            rationale: ["grounded rationale for ", identity].concat(),
        }
    }

    /// Returns a single directly impacted member with full evidence.
    fn test_impact() -> Vec<ImpactMember> {
        [ImpactMember {
            member_id: "view-home".to_owned(),
            owner: "owner-1".to_owned(),
            disposition: ImpactDisposition::Direct,
            compatibility_note: "title size stays within the schema range".to_owned(),
            restart_note: "no reload or restart is required".to_owned(),
        }]
        .to_vec()
    }

    /// Returns the inert verifier, rollback, and approval boundary.
    fn test_boundary() -> InertBoundary {
        InertBoundary {
            verifier: InertVerifier {
                verifier_id: "verifier-9".to_owned(),
                probe_note: "render the home view in a sandbox probe".to_owned(),
                success_note: "title renders within bounds with no regression".to_owned(),
            },
            rollback: RollbackPlan {
                anchor_digest: "9".repeat(64),
                steps: ["restore snapshot snap-9".to_owned()].to_vec(),
                repair_note: "forward repair replays the typed delta only".to_owned(),
            },
            rollout_note: "single staged view rollout with a stop condition".to_owned(),
            approvals_note: "Human approval alice holds until expiry nine".to_owned(),
        }
    }

    /// Returns retained prior history with an empty denominator.
    fn test_history() -> PriorHistory {
        PriorHistory {
            expected_attempt_ids: Vec::new(),
            attempts: Vec::new(),
            outcome_note: "no prior attempts retained".to_owned(),
        }
    }

    /// Returns history with one retained attempt for denominator checks.
    fn test_history_with_attempt() -> PriorHistory {
        PriorHistory {
            expected_attempt_ids: ["att-1".to_owned()].to_vec(),
            attempts: [HistoryAttempt {
                attempt_id: "att-1".to_owned(),
                equivalence_digest: "a".repeat(64),
            }]
            .to_vec(),
            outcome_note: "one prior attempt retained verbatim".to_owned(),
        }
    }

    /// Returns a valid governing policy for the test intent.
    fn test_policy() -> ConfigurationPolicy {
        ConfigurationPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_fields: super::MAX_FIELDS,
            max_changes: super::MAX_CHANGES,
            max_impact: super::MAX_IMPACT,
            max_evidence: super::MAX_EVIDENCE_ITEMS,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            owner_note: "intent owned by the dreamer cell".to_owned(),
        }
    }

    /// Runs the full valid fixture set through the entry point.
    fn run_valid() -> super::ConfigurationChangeIntent {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history_with_attempt();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("valid intent must complete");
        };
        candidate
    }

    // WORK_UNIT_CASE: 679/1
    #[test]
    fn case_01_presentation_only_intent_is_complete() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(candidate.intent_handle, "cfg-snap-9");
        assert_eq!(candidate.primary_layer, ConfigLayer::Presentation);
        assert_eq!(candidate.primary_owner, "owner-1");
        assert_eq!(candidate.base_digest, "9".repeat(64));
        assert_eq!(candidate.base_revision, 9);
        assert_eq!(candidate.changes.len(), 1);
        assert_eq!(candidate.impact.len(), 1);
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert_eq!(candidate.attempt_denominator, ["att-1".to_owned()].to_vec());
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // WORK_UNIT_CASE: 679/2
    #[test]
    fn case_02_runtime_ceiling_exceeded_fails_closed() {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let mut policy = test_policy();
        policy.max_changes = 0;
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("over-ceiling runtime delta must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Bounds { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::BudgetExceeded
        );
    }

    // WORK_UNIT_CASE: 679/3
    #[test]
    fn case_03_unknown_field_vocab_is_rejected() {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-never-grounded")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("unknown vocab stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 679/4
    #[test]
    fn case_04_wrong_job_shape_fails_closed() {
        let mut job = test_job();
        job.job_class = JobClass::Curation;
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("wrong job shape must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // WORK_UNIT_CASE: 679/5
    #[test]
    fn case_05_scope_drift_fails_closed() {
        let job = test_job();
        let mut draft = test_draft();
        draft.scope_id = "scope-other".to_owned();
        draft.receipt.scope_id = "scope-other".to_owned();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("scope drift must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // WORK_UNIT_CASE: 679/6
    #[test]
    fn case_06_prose_without_mapping_yields_clarification() {
        let job = test_job();
        let draft = test_draft();
        let request = StructuredRequest {
            request_id: "req-prose".to_owned(),
            summary_note: "Human describes a vague wish without any grounded field".to_owned(),
            fields: Vec::new(),
            has_structured_mapping: false,
            generic_patch_note: None,
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("prose-only request stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 679/7
    #[test]
    fn case_07_rival_owner_binding_yields_clarification() {
        let job = test_job();
        let draft = test_draft();
        let mut first = test_structured_field("field-title-size");
        first.owner = "owner-1".to_owned();
        let mut second = test_structured_field("field-title-size");
        second.owner = "owner-2".to_owned();
        let request = StructuredRequest {
            request_id: "req-ambiguous".to_owned(),
            summary_note: "one field bound to rival owners needs a Human choice".to_owned(),
            fields: [first, second].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: None,
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("ambiguous binding stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
    }

    // WORK_UNIT_CASE: 679/8
    #[test]
    fn case_08_generic_patch_shape_is_rejected() {
        let job = test_job();
        let draft = test_draft();
        let request = StructuredRequest {
            request_id: "req-patch".to_owned(),
            summary_note: "caller offers a patch document instead of typed fields".to_owned(),
            fields: [test_structured_field("field-title-size")].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: Some("apply this json patch with op replace".to_owned()),
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("generic patch stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::UnsupportedShape);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedJobShape)
        );
        assert!(candidate.preservation.overall().is_ok());
    }
}
