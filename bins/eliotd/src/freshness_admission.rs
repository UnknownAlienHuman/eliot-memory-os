//! Freshness admission and projection-pending publication states (issue #1930).
//!
//! Architecture: I5.6 (Admission and staging); I5.8 (Canonical event and
//! projections); A2.3 (contract → ports → adapters layering); A0.3 hard
//! boundaries stay fail-closed. This cell is the Governor application
//! evaluation owned by `eliotd`: it decides reusable promotion and
//! projection-pending publication state from already-threaded values, never
//! from durable transport success, installed configuration, or a live store
//! read — none of those are inputs here by construction, so none can satisfy
//! this gate.
//!
//! A reusable candidate carries a normalized [`FreshnessAdmission`] over base
//! revision heads, expected post-commit heads, the dependency fence, and the
//! predicate normal form, with one [`FreshnessDisposition`]:
//!
//! - `CURRENT` is the only disposition that permits hot/reusable promotion;
//! - `SELF_INVALIDATING` rejects promotion when the candidate's own expected
//!   post-commit revision moves a scope its predicate depends on;
//! - `EXTERNAL_REVISION_RACE` rejects promotion when a predicate scope the
//!   candidate does not itself advance moved under it between base and
//!   evaluation;
//! - `INCOMPLETE` rejects promotion for unresolved provenance or task
//!   mismatch; the safe raw observation may remain cold/quarantined;
//! - `PROJECTION_PENDING` marks a durably committed candidate whose hot
//!   projection has no matching `ProjectionPublicationRecord` with status
//!   `CURRENT`.
//!
//! `WriteReceipt.status=committed` proves durable transport only. It does not
//! prove novelty, freshness, task compatibility, support, or verification, so
//! a committed candidate fetched by exact handle before its projection
//! publishes resolves to [`CANDIDATE_COMMITTED_PROJECTION_PENDING`]: the
//! record exists and is fetchable, but it cannot fire on the hot path or
//! support a Material decision until a current publication record exists.
//!
//! Delegation boundary (delegate, never copy):
//!
//! - durable commit, projection publication, rebuild (a Doctor recipe), and
//!   Material-decision support stay with their owners; the caller threads the
//!   already-observed candidate, handle list, and publication records per
//!   call, so a refresh surfaces as an exact mismatch instead of silent
//!   divergence;
//! - quarantine, recovery, and re-publication directives stay with their
//!   owners; this cell only names the disposition, it never executes recovery.
//!
//! Canonical publication record (delegate, never re-declare):
//!
//! The durable `ProjectionPublicationRecord` and the fenced publication that
//! carries its projection definition digest and its atomic commit reference
//! are owned by the neutral store contract
//! (`eliot_store_api::canonical_event`, "A composition binary may only
//! re-export this contract; a binary name never creates store or
//! canonical-write ownership"). This cell therefore re-declares no
//! publication mode, publication status, or publication record: it consumes
//! [`FencedProjectionPublication`] and delegates the whole currency decision
//! to the one store predicate [`FencedProjectionPublication::check_current`].
//! That predicate enforces exactly the clauses I5.8 requires of a
//! readable-as-current publication — `CURRENT` status, no split view, the
//! expected source generation, an exact fence-pinned source-head match, a
//! well-formed provenance manifest, the projection definition digest, and the
//! atomic data/provenance commit coupling — so candidate data and provenance
//! become visible atomically or the projection stays unreadable as current.
//! The `I5.8` record vocabulary is exactly the store's own vocabulary:
//! `ProjectionStatus` and `ProjectionMode` serialize as `SCREAMING_SNAKE_CASE`
//! (`PENDING`/`CURRENT`/`STALE`/`FAILED`/`INCONCLUSIVE` and
//! `FULL`/`DELTA`/`REFERENCE_FALLBACK`), so this cell publishes no second
//! spelling of a status or a mode.
//!
//! Residuals of the `I5.8` record block with no field and no producer
//! anywhere in the workspace, reported rather than invented here:
//! `dependency_definition_digest`,
//! `selection_basis_and_whole_DAG_cost`, `full_cost_estimate_and_observed_cost`,
//! `delta_cost_estimate_and_observed_cost`, `semantic_equality_oracle_ref`,
//! `sink_acceptance_and_readback_refs`, `arrival_and_claim_fences`, and
//! `assurance_ceiling`. The dependency definition digest is the only one this
//! gate compares, and it is threaded as a caller-observed value beside the
//! fenced record because the record itself carries no dependency identity; no
//! default, empty string, or recomputed digest stands in for it.
//!
//! Caller integration (exact owner handoff; no runtime path yet):
//!
//! - `evaluate_freshness_admission` is owned for the `eliotd` semantic
//!   admission path that promotes reusable candidates. The owning caller must
//!   thread one [`ReusableCandidateView`] per candidate and grant hot/reusable
//!   promotion only when the verdict carries `CURRENT` with
//!   `reusable_promotion_allowed`; any other disposition refuses promotion
//!   while the permitted safe raw observation stays cold.
//! - `fetch_committed_candidate` is owned for the exact-handle fetch path and
//!   its hot-path / Material-decision gates. The owning caller must thread the
//!   known committed identities plus the observed publications built by
//!   `observed_publication` from the store owner's fenced record, and refuse
//!   hot firing and Material support unless the outcome is `CommittedCurrent`.
//! - Neither function has a production caller in `eliotd`, and this cell adds
//!   none, because no owner produces their required inputs. For
//!   `evaluate_freshness_admission` the live `eliotd` admission edge
//!   (`eliotd::kernel_transition_client::check_identity_binding`) holds no
//!   predicate normal form, no predicate pinned scopes, no expected
//!   post-commit revision heads, no observed source heads, and no resolved
//!   provenance or task-selection standing, and no owner maps a transition
//!   effect ceiling onto [`RequestedEffect`]; evaluation there would be
//!   `INCOMPLETE` for every real request. For `fetch_committed_candidate` the
//!   closed `eliot_store_api::NamedReadOperation` catalogue (27 rows, verified
//!   at `main@941bc3fc`) exposes no projection-publication read and no
//!   candidate-by-handle read, and the one production
//!   `eliot_store_api::CanonicalReadClient` in `eliotd`
//!   (`KernelContextReadClient`) reaches the store only through
//!   `execute_named`, whose closed allowlist admits neither, so no
//!   observed publication can reach this cell at runtime. Until those
//!   producers exist, this cell proves the gate logic only and claims no
//!   runtime admission, persistence, or publication behavior.
//!
//! Like the neighboring admission joins, this helper never mints admission:
//! it evaluates presented values and returns a disposition.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

use eliot_store_api::{
    FencedProjectionPublication, RevisionHead as ObservedStoreRevisionHead, StoreError,
};

/// Wire outcome returned after durable commit when the hot projection is not
/// current (I5.6).
pub const CANDIDATE_COMMITTED_PROJECTION_PENDING: &str = "CANDIDATE_COMMITTED_PROJECTION_PENDING";

/// Fail-closed evaluation error: malformed candidate or publication input.
///
/// Malformed input never admits and never promotes; the caller repairs the
/// input through the owning writer instead of retrying the same value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessError(String);

impl Display for FreshnessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        write!(formatter, "freshness admission: {}", self.0)
    }
}

impl std::error::Error for FreshnessError {}

fn invalid(reason: impl Into<String>) -> FreshnessError {
    FreshnessError(reason.into())
}

fn check_identity(field: &str, value: &str, max_len: usize) -> Result<(), FreshnessError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid(format!("{field} must not be blank")));
    }
    if trimmed != value {
        return Err(invalid(format!(
            "{field} must not carry surrounding whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} must not contain control characters"
        )));
    }
    if value.len() > max_len {
        return Err(invalid(format!("{field} exceeds {max_len} bytes")));
    }
    Ok(())
}

/// One normalized scope revision head (`scope` → `revision`).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RevisionHead {
    /// Revision scope (ordering scope, projection source, or dependency).
    pub scope: String,
    /// Opaque revision at that scope.
    pub revision: String,
}

impl RevisionHead {
    /// Validates one head: non-blank identities without control characters.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        check_identity("revision scope", &self.scope, 256)?;
        check_identity("revision", &self.revision, 256)?;
        Ok(())
    }
}

/// Normalizes heads into scope-sorted, deduplicated order.
///
/// Normalization is structural: the same observed set always yields the same
/// sequence, so admission compares values instead of arrival order. Identical
/// records collapse deterministically; conflicting revisions for one scope are
/// rejected, because a scope with two simultaneous revisions is ambiguous
/// evidence that must fail closed instead of silently overwriting in a
/// scope map.
///
/// # Errors
///
/// Returns [`FreshnessError`] when any head is malformed or when one scope
/// carries two different revisions.
pub fn normalize_heads(heads: &[RevisionHead]) -> Result<Vec<RevisionHead>, FreshnessError> {
    for head in heads {
        head.validate()?;
    }
    let mut normalized: Vec<RevisionHead> = heads.to_vec();
    normalized.sort();
    normalized.dedup();
    let mut prior_scope: Option<&str> = None;
    for head in &normalized {
        if prior_scope == Some(head.scope.as_str()) {
            return Err(invalid(format!(
                "conflicting revisions for scope '{}'",
                head.scope
            )));
        }
        prior_scope = Some(head.scope.as_str());
    }
    Ok(normalized)
}

/// Normalized freshness disposition vocabulary (I5.6 exact set).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessDisposition {
    /// Fresh against base, expected, fence, and predicate: promotable.
    Current,
    /// The candidate's own commit would invalidate its predicate.
    SelfInvalidating,
    /// Committed, but no current publication record for the hot projection.
    ProjectionPending,
    /// A predicate scope moved externally between base and evaluation.
    ExternalRevisionRace,
    /// Provenance unresolved or task mismatched: freshness unestablished.
    Incomplete,
}

impl FreshnessDisposition {
    /// Contract vocabulary for diagnostics and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::SelfInvalidating => "SELF_INVALIDATING",
            Self::ProjectionPending => "PROJECTION_PENDING",
            Self::ExternalRevisionRace => "EXTERNAL_REVISION_RACE",
            Self::Incomplete => "INCOMPLETE",
        }
    }

    /// Only `CURRENT` permits hot/reusable promotion.
    #[must_use]
    pub const fn promotes_reusable(self) -> bool {
        matches!(self, Self::Current)
    }
}

/// Normalized freshness admission carried by a reusable candidate (I5.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessAdmission {
    /// Normalized base revision heads the predicate was evaluated against.
    pub base_revision_heads: Vec<RevisionHead>,
    /// Normalized expected heads after the candidate's own commit.
    pub expected_post_commit_revision_heads: Vec<RevisionHead>,
    /// Dependency fence the predicate was normalized under.
    pub dependency_fence: String,
    /// Canonical predicate normal form.
    pub predicate_normal_form: String,
    /// Exactly one evaluated disposition.
    pub disposition: FreshnessDisposition,
}

/// Provenance standing for the candidate's evidence handles.
///
/// Unresolved provenance never establishes freshness, so it yields
/// `INCOMPLETE` before any revision comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceStanding {
    /// Exact canonical provenance/evidence handles resolved.
    Resolved,
    /// Provenance handles missing or unverified.
    Unresolved,
}

/// Task-selection compatibility for the requesting task.
///
/// A task-mismatched candidate never establishes freshness, so it yields
/// `INCOMPLETE` before any revision comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskCompatibility {
    /// Task-selection evidence compatible with the requesting task.
    Compatible,
    /// Candidate selected for a different task.
    Mismatched,
}

/// Requested effect ceiling: hot/reusable promotion or cold capture only.
///
/// The ceiling bounds what evaluation may grant; it never grants by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedEffect {
    /// Hot/reusable promotion requested; granted only for `CURRENT`.
    ReusablePromotion,
    /// Cold capture only; promotion is refused whatever the disposition.
    ColdCapture,
}

/// Already-observed reusable-candidate view threaded per admission call.
///
/// The durable store owns commit and revision truth; this shape is the exact
/// observed value the caller presents for one evaluation, so a refresh
/// surfaces as an exact mismatch instead of silent divergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusableCandidateView {
    /// Base heads the candidate predicate was evaluated against.
    pub base_revision_heads: Vec<RevisionHead>,
    /// Expected heads after the candidate's own commit.
    pub expected_post_commit_revision_heads: Vec<RevisionHead>,
    /// Scopes the predicate normal form depends on.
    pub predicate_pinned_scopes: Vec<String>,
    /// Canonical predicate normal form.
    pub predicate_normal_form: String,
    /// Dependency fence the predicate was normalized under.
    pub dependency_fence: String,
    /// Provenance standing of the candidate's evidence handles.
    pub provenance: ProvenanceStanding,
    /// Task-selection compatibility with the requesting task.
    pub task: TaskCompatibility,
    /// Currently observed source heads at evaluation time.
    pub observed_source_heads: Vec<RevisionHead>,
    /// Requested effect ceiling bounding what evaluation may grant.
    pub requested_effect: RequestedEffect,
    /// Whether the safe raw observation may remain cold/quarantined.
    pub safe_raw_observation_permitted: bool,
}

/// Admission outcome: the normalized record plus the promotion decision.
///
/// Rejected reusable promotion never fabricates a hot path: `cold_raw_retained`
/// carries only the permitted cold observation, never a promotion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshnessEvaluation {
    /// Normalized admission record with exactly one disposition.
    pub admission: FreshnessAdmission,
    /// True only for `CURRENT` with reusable promotion requested.
    pub reusable_promotion_allowed: bool,
    /// True when the safe raw observation remains cold/quarantined.
    pub cold_raw_retained: bool,
}

fn heads_by_scope(heads: &[RevisionHead]) -> BTreeMap<&str, &str> {
    let mut map = BTreeMap::new();
    for head in heads {
        map.insert(head.scope.as_str(), head.revision.as_str());
    }
    map
}

/// Requires one scope-free, unambiguous view of observed store heads.
///
/// Mirrors [`normalize_heads`] over the store head shape: identical records
/// collapse, and one key carrying two different revisions is ambiguous
/// evidence that fails closed instead of silently overwriting.
fn observed_store_heads_unambiguous(
    heads: &[ObservedStoreRevisionHead],
) -> Result<(), FreshnessError> {
    let mut by_key: BTreeMap<&str, &ObservedStoreRevisionHead> = BTreeMap::new();
    for head in heads {
        match by_key.insert(head.key.as_str(), head) {
            Some(prior) if prior != head => {
                return Err(invalid(format!(
                    "conflicting revisions for revision key '{}'",
                    head.key
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Evaluates normalized freshness admission for one reusable candidate.
///
/// Order is load-bearing and fail-closed: unresolved provenance or task
/// mismatch yields `INCOMPLETE` before any revision comparison; an empty
/// pinned denominator yields `INCOMPLETE` because it cannot prove the
/// predicate is independent of source revisions; a pinned scope without
/// complete unambiguous base, expected, and observed evidence yields
/// `INCOMPLETE` (a missing head is not agreement); a pinned scope moved by
/// the candidate's own commit yields `SELF_INVALIDATING`; a pinned scope the
/// candidate does not advance but observed moved yields
/// `EXTERNAL_REVISION_RACE`; otherwise the candidate is `CURRENT`. Rejected
/// promotion keeps the permitted safe raw observation cold via
/// `cold_raw_retained`.
///
/// The recorded disposition is a function of the observed value set, never of
/// arrival order: the heads are normalized through [`normalize_heads`] and the
/// pinned-scope denominator is sorted and deduplicated with the same
/// discipline, so permuting `predicate_pinned_scopes` cannot change which of
/// the dispositions is written down.
///
/// # Errors
///
/// Returns [`FreshnessError`] when any identity, fence, predicate form, or
/// head is malformed, or when one scope carries conflicting revisions.
/// Malformed input admits nothing and promotes nothing.
pub fn evaluate_freshness_admission(
    candidate: &ReusableCandidateView,
) -> Result<FreshnessEvaluation, FreshnessError> {
    check_identity("dependency fence", &candidate.dependency_fence, 512)?;
    check_identity(
        "predicate normal form",
        &candidate.predicate_normal_form,
        4096,
    )?;
    for scope in &candidate.predicate_pinned_scopes {
        check_identity("predicate pinned scope", scope, 256)?;
    }
    // The pinned-scope denominator is normalized with the same mechanism the
    // heads are, so the recorded disposition is a function of the observed
    // VALUE SET and not of the order the caller happened to present it in.
    // Without this the first scope that trips the loop decides the record:
    // the same candidate presented with a permuted `predicate_pinned_scopes`
    // yields `SELF_INVALIDATING` in one order and `INCOMPLETE` in the other.
    // Both orders refuse promotion, so this is not a promotion bypass; it is
    // the normalization guarantee this module already claims for `normalize_heads`
    // extending to the one list that is not a head list.
    let mut pinned = candidate.predicate_pinned_scopes.clone();
    pinned.sort();
    pinned.dedup();
    let base = normalize_heads(&candidate.base_revision_heads)?;
    let expected = normalize_heads(&candidate.expected_post_commit_revision_heads)?;
    let observed = normalize_heads(&candidate.observed_source_heads)?;

    let disposition = if candidate.provenance != ProvenanceStanding::Resolved
        || candidate.task != TaskCompatibility::Compatible
    {
        FreshnessDisposition::Incomplete
    } else if pinned.is_empty() {
        // No declared pinned dependency can prove the predicate needs none,
        // so freshness is unestablished: vacuous promotion is forbidden.
        FreshnessDisposition::Incomplete
    } else {
        let base_map = heads_by_scope(&base);
        let expected_map = heads_by_scope(&expected);
        let observed_map = heads_by_scope(&observed);
        let mut disposition = FreshnessDisposition::Current;
        for scope in &pinned {
            let scope = scope.as_str();
            let (Some(base_revision), Some(expected_revision), Some(observed_revision)) = (
                base_map.get(scope).copied(),
                expected_map.get(scope).copied(),
                observed_map.get(scope).copied(),
            ) else {
                disposition = FreshnessDisposition::Incomplete;
                break;
            };
            if expected_revision != base_revision {
                disposition = FreshnessDisposition::SelfInvalidating;
                break;
            }
            if observed_revision != base_revision {
                disposition = FreshnessDisposition::ExternalRevisionRace;
                break;
            }
        }
        disposition
    };

    let reusable_promotion_allowed = disposition.promotes_reusable()
        && candidate.requested_effect == RequestedEffect::ReusablePromotion;
    let cold_raw_retained = !reusable_promotion_allowed && candidate.safe_raw_observation_permitted;
    Ok(FreshnessEvaluation {
        admission: FreshnessAdmission {
            base_revision_heads: base,
            expected_post_commit_revision_heads: expected,
            dependency_fence: candidate.dependency_fence.clone(),
            predicate_normal_form: candidate.predicate_normal_form.clone(),
            disposition,
        },
        reusable_promotion_allowed,
        cold_raw_retained,
    })
}

/// One already-observed projection publication presented to this gate.
///
/// This is an observed view, never a contract: it borrows the canonical
/// fenced publication the store owner already read, so a refresh surfaces as
/// an exact mismatch instead of silent divergence and no field is copied,
/// defaulted, or recomputed here. The dependency definition digest is a
/// separate observed value because the canonical record carries no dependency
/// identity; it is supplied by the owner that observed it, and no stand-in
/// value is ever minted for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedPublication<'a> {
    /// Canonical fenced publication, including its durable
    /// `ProjectionPublicationRecord`.
    pub fenced: &'a FencedProjectionPublication,
    /// Dependency-definition digest observed for that same publication.
    pub dependency_definition_digest: &'a str,
}

/// Validates one observed publication before any of its fields is used.
///
/// Runs the store's own validator on the ORIGINAL fenced publication, which
/// validates the durable record, the projection definition digest, and the
/// atomic coupling between the fence's commit reference and the record's
/// atomic data commit. A refusal is never repaired here and never downgraded
/// to "not current": malformed input fails closed.
///
/// # Errors
///
/// Returns [`FreshnessError`] when the store refuses the fenced publication or
/// when the observed dependency definition digest is malformed.
fn validate_observed_publication(
    publication: &ObservedPublication<'_>,
) -> Result<(), FreshnessError> {
    publication.fenced.validate().map_err(|error: StoreError| {
        invalid(format!("projection publication is invalid: {error}"))
    })?;
    check_identity(
        "dependency definition digest",
        publication.dependency_definition_digest,
        512,
    )
}

/// Converts one already-observed store publication into this gate's
/// comparison input.
///
/// This is the only conversion between the canonical durable publication and
/// this cell: it validates the ORIGINAL record through the store's own
/// validator and adds no second schema, no second validator, and no derived
/// digest. The store's fence already carries the projection definition digest
/// and the atomic data/provenance commit the record committed under, which is
/// what makes candidate data and its provenance one atomic commit; the
/// dependency definition digest is threaded beside it because the record has
/// no such field.
///
/// # Errors
///
/// Returns [`FreshnessError`] when the store refuses the fenced publication or
/// when the observed dependency definition digest is malformed.
pub fn observed_publication<'a>(
    fenced: &'a FencedProjectionPublication,
    dependency_definition_digest: &'a str,
) -> Result<ObservedPublication<'a>, FreshnessError> {
    let publication = ObservedPublication {
        fenced,
        dependency_definition_digest,
    };
    validate_observed_publication(&publication)?;
    Ok(publication)
}

/// True when the observed publication makes the candidate's projection current.
///
/// Currency is the store's decision, not this cell's: every clause the durable
/// record can prove is decided by
/// [`FencedProjectionPublication::check_current`], which refuses a non-`CURRENT`
/// status, a split view, a mismatched source generation, a source head that is
/// not fence-pinned to the record, a malformed provenance manifest, a changed
/// projection definition, and a fence whose atomic commit reference disagrees
/// with the record's atomic data commit. The one clause the record cannot
/// prove against itself — that it is the publication whose data the caller is
/// about to serve — stays with the caller, as the store documents, and this
/// function is that caller. It therefore compares the publication's own
/// recorded `atomic_data_commit` against the candidate's own recorded
/// `durability_receipt`, so a publication that shares the candidate's source
/// fence, source heads, source generation, projection kind and definition but
/// was published by a DIFFERENT commit is refused instead of standing in for
/// the candidate's own data. This function adds exactly the four clauses left
/// over: an empty candidate head set is never coverage, the projection kind
/// must match exactly, the observed dependency definition digest must match
/// exactly because a bare definition match is not enough (I5.8), and the
/// durable atomic data commit must be the candidate's own commit.
#[must_use]
pub fn publication_serves_candidate(
    publication: &ObservedPublication<'_>,
    candidate: &CommittedCandidate,
) -> bool {
    if candidate.source_revision_heads.is_empty() {
        return false;
    }
    if publication.fenced.record.projection_kind != candidate.projection_kind {
        return false;
    }
    if publication.dependency_definition_digest != candidate.dependency_definition_digest {
        return false;
    }
    // The store plans one `atomic_data_commit` per publication from the very
    // commit that made the data visible (`plan.rs` builds `commit_id` once and
    // binds it into every record of that transaction), and it documents this
    // clause as the caller's. Comparing the candidate's recorded receipt to
    // the record's recorded commit is the only way a record published for a
    // sibling commit at the same fence can never serve a Material decision on
    // this candidate's data: the equality is by content of the two recorded
    // identities, never by name, by mere presence, or by a recomputed digest.
    if publication.fenced.record.atomic_data_commit.as_str() != candidate.durability_receipt {
        return false;
    }
    publication
        .fenced
        .check_current(
            &candidate.source_revision_heads,
            candidate.source_generation,
            &candidate.projection_definition_digest,
        )
        .is_ok()
}

/// Durably committed candidate awaiting (or covered by) projection
/// publication.
///
/// The store owns the commit; this shape is the already-observed durable
/// identity the caller threads per fetch. Its source heads and source
/// generation are the store's own neutral shapes, so the currency decision
/// runs over the same identities the durable record and the store's
/// readability predicate use instead of a second normalized copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCandidate {
    /// Exact handle the record is fetched by.
    pub handle: String,
    /// Durable commit receipt; proves transport only, never freshness.
    ///
    /// It is not a label: it is compared by content against the
    /// `atomic_data_commit` a publication record itself recorded, so a
    /// publication for a sibling commit at the same fence can never stand in
    /// for this candidate's own data.
    pub durability_receipt: String,
    /// Projection kind whose currency gates hot/proof-bearing use.
    pub projection_kind: String,
    /// Projection definition digest the candidate was committed against.
    pub projection_definition_digest: String,
    /// Digest of the dependency definitions the candidate was committed
    /// against. Currency requires the publication to be built from the same
    /// dependencies (I5.8); a bare definition match is not enough.
    pub dependency_definition_digest: String,
    /// Source generation the candidate was committed at.
    pub source_generation: u64,
    /// Source revision heads the candidate was committed at, each fence-pinned
    /// to the source fence it was observed at.
    pub source_revision_heads: Vec<ObservedStoreRevisionHead>,
}

impl CommittedCandidate {
    /// Validates the committed identity; malformed commits fetch nothing.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError`] when the handle, receipt, kind, digests,
    /// source generation, or any head is malformed, and when one revision key
    /// carries two different observed heads.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        check_identity("candidate handle", &self.handle, 512)?;
        check_identity("durability receipt", &self.durability_receipt, 512)?;
        check_identity("projection kind", &self.projection_kind, 256)?;
        check_identity(
            "projection definition digest",
            &self.projection_definition_digest,
            512,
        )?;
        check_identity(
            "dependency definition digest",
            &self.dependency_definition_digest,
            512,
        )?;
        if self.source_generation == 0 {
            return Err(invalid("source generation must be non-zero"));
        }
        for head in &self.source_revision_heads {
            head.validate().map_err(|error: StoreError| {
                invalid(format!(
                    "committed candidate source head is invalid: {error}"
                ))
            })?;
        }
        observed_store_heads_unambiguous(&self.source_revision_heads)
    }
}

/// Exact-handle fetch outcome for a committed candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateFetchOutcome {
    /// A matching current publication record exists: hot/proof-bearing use
    /// is permitted by the owning gates.
    CommittedCurrent,
    /// Committed before the relevant projection published: fetchable by
    /// exact handle only, never hot, never Material support.
    CommittedProjectionPending,
}

impl CandidateFetchOutcome {
    /// Wire outcome string for the pending case.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommittedCurrent => "CANDIDATE_COMMITTED_CURRENT",
            Self::CommittedProjectionPending => CANDIDATE_COMMITTED_PROJECTION_PENDING,
        }
    }

    /// Only a current publication lets the candidate support a Material
    /// decision.
    #[must_use]
    pub const fn supports_material_decision(self) -> bool {
        matches!(self, Self::CommittedCurrent)
    }

    /// Only a current publication lets the candidate fire on the hot path.
    #[must_use]
    pub const fn hot_path_activatable(self) -> bool {
        matches!(self, Self::CommittedCurrent)
    }
}

/// Fetches one committed candidate by exact handle against the observed
/// publication records.
///
/// A known handle with no matching current publication resolves to
/// `CANDIDATE_COMMITTED_PROJECTION_PENDING`: the record exists and is
/// fetchable, but the owning hot-path and Material gates must refuse it
/// until a current publication record exists. "Current" is decided against
/// the candidate, not by the presence of a publication: the matching
/// publication must carry the candidate's own recorded commit as its
/// `atomic_data_commit`, so a publication issued by a sibling commit at the
/// same fence leaves the candidate pending. Every presented publication is
/// validated through the store's own validator first, so a malformed record
/// fails closed instead of being skipped as if it were absent.
///
/// # Errors
///
/// Returns [`FreshnessError`] for malformed input or for an unknown handle.
/// An unknown handle is never synthesized into a pending outcome.
pub fn fetch_committed_candidate(
    handle: &str,
    committed: &[CommittedCandidate],
    publications: &[ObservedPublication<'_>],
) -> Result<CandidateFetchOutcome, FreshnessError> {
    check_identity("candidate handle", handle, 512)?;
    let candidate = committed
        .iter()
        .find(|candidate| candidate.handle == handle)
        .ok_or_else(|| invalid("unknown candidate handle"))?;
    candidate.validate()?;
    for publication in publications {
        validate_observed_publication(publication)?;
    }
    let current = publications
        .iter()
        .any(|publication| publication_serves_candidate(publication, candidate));
    Ok(if current {
        CandidateFetchOutcome::CommittedCurrent
    } else {
        CandidateFetchOutcome::CommittedProjectionPending
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_store_api::{
        CommitId, FencedProjectionPublication, ProjectionMode, ProjectionPublicationId,
        ProjectionStatus, RevisionKey, SplitView,
    };

    use super::*;

    const TEST_LINEAGE: &str = "9f0d1c62-0a3b-4c9e-9d61-2a5f2b8c7e40";
    const DEFINITION_DIGEST: &str =
        "1f0d1c620a3b4c9e9d612a5f2b8c7e401f0d1c620a3b4c9e9d612a5f2b8c7e40";
    const DEPENDENCY_DIGEST: &str =
        "2b8c7e401f0d1c620a3b4c9e9d612a5f2b8c7e401f0d1c620a3b4c9e9d612a5f";
    const REBUILT_DEPENDENCY_DIGEST: &str =
        "9d612a5f2b8c7e401f0d1c620a3b4c9e9d612a5f2b8c7e401f0d1c620a3b4c9e";

    fn head(scope: &str, revision: &str) -> RevisionHead {
        RevisionHead {
            scope: scope.to_owned(),
            revision: revision.to_owned(),
        }
    }

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(1).expect("non-zero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn store_head(key: &str, revision: u64) -> ObservedStoreRevisionHead {
        ObservedStoreRevisionHead {
            key: RevisionKey::new(key).expect("valid revision key"),
            revision,
            state_fence: test_fence(),
        }
    }

    fn candidate_view() -> ReusableCandidateView {
        ReusableCandidateView {
            base_revision_heads: vec![head("cue-index", "rev-7"), head("context-graph", "rev-3")],
            expected_post_commit_revision_heads: vec![
                head("cue-index", "rev-7"),
                head("context-graph", "rev-3"),
            ],
            predicate_pinned_scopes: vec!["cue-index".to_owned()],
            predicate_normal_form: "(and (scope cue-index) (pinned rev-7))".to_owned(),
            dependency_fence: "fence-epoch-1/gen-1".to_owned(),
            provenance: ProvenanceStanding::Resolved,
            task: TaskCompatibility::Compatible,
            observed_source_heads: vec![head("cue-index", "rev-7"), head("context-graph", "rev-3")],
            requested_effect: RequestedEffect::ReusablePromotion,
            safe_raw_observation_permitted: true,
        }
    }

    fn committed_candidate() -> CommittedCandidate {
        CommittedCandidate {
            handle: "candidate-1".to_owned(),
            durability_receipt: "commit-atomic-1".to_owned(),
            projection_kind: "cue-index".to_owned(),
            projection_definition_digest: DEFINITION_DIGEST.to_owned(),
            dependency_definition_digest: DEPENDENCY_DIGEST.to_owned(),
            source_generation: 4,
            source_revision_heads: vec![store_head("cue-index", 4)],
        }
    }

    fn current_publication() -> FencedProjectionPublication {
        let atomic_data_commit = CommitId::new("commit-atomic-1").expect("valid commit id");
        FencedProjectionPublication {
            record: eliot_store_api::ProjectionPublicationRecord {
                publication_id: ProjectionPublicationId::new("publication-1")
                    .expect("valid publication id"),
                projection_kind: "cue-index".to_owned(),
                projection_generation: 2,
                source_generation: 4,
                source_cursor: 9,
                state_fence: test_fence(),
                mode: ProjectionMode::Full,
                source_revision_heads: vec![store_head("cue-index", 4)],
                atomic_data_commit: atomic_data_commit.clone(),
                provenance_manifest_ref: "manifest-1".to_owned(),
                visible_lag_checkpoint: None,
                split_view: SplitView::None,
                status: ProjectionStatus::Current,
            },
            projection_definition_digest: DEFINITION_DIGEST.to_owned(),
            atomic_commit_ref: atomic_data_commit,
        }
    }

    fn observed<'a>(
        fenced: &'a FencedProjectionPublication,
        dependency_definition_digest: &'a str,
    ) -> ObservedPublication<'a> {
        observed_publication(fenced, dependency_definition_digest)
            .expect("valid observed publication")
    }

    #[test]
    fn self_invalidating_candidate_is_not_promoted_and_raw_stays_cold() -> Result<(), FreshnessError>
    {
        let mut view = candidate_view();
        view.expected_post_commit_revision_heads =
            vec![head("cue-index", "rev-8"), head("context-graph", "rev-3")];
        let evaluation = evaluate_freshness_admission(&view)?;
        assert_eq!(
            evaluation.admission.disposition,
            FreshnessDisposition::SelfInvalidating
        );
        assert_eq!(
            evaluation.admission.disposition.as_str(),
            "SELF_INVALIDATING"
        );
        assert!(!evaluation.reusable_promotion_allowed);
        assert!(evaluation.cold_raw_retained);
        assert_eq!(
            evaluation.admission.base_revision_heads,
            vec![head("context-graph", "rev-3"), head("cue-index", "rev-7")]
        );
        Ok(())
    }

    #[test]
    fn normalize_heads_rejects_conflicting_scope_revisions() -> Result<(), FreshnessError> {
        // Identical records collapse deterministically.
        let normalized = normalize_heads(&[
            head("cue-index", "rev-7"),
            head("context-graph", "rev-3"),
            head("cue-index", "rev-7"),
        ])?;
        assert_eq!(
            normalized,
            vec![head("context-graph", "rev-3"), head("cue-index", "rev-7")]
        );
        // Conflicting revisions for one scope fail closed instead of
        // silently overwriting in a scope map.
        assert!(
            normalize_heads(&[head("cue-index", "rev-7"), head("cue-index", "rev-8")]).is_err()
        );
        Ok(())
    }

    #[test]
    fn missing_pinned_evidence_is_incomplete_without_promotion() -> Result<(), FreshnessError> {
        // Observed head missing for the pinned scope: not agreement, INCOMPLETE.
        let mut view = candidate_view();
        view.observed_source_heads = vec![head("context-graph", "rev-3")];
        let evaluation = evaluate_freshness_admission(&view)?;
        assert_eq!(
            evaluation.admission.disposition,
            FreshnessDisposition::Incomplete
        );
        assert!(!evaluation.reusable_promotion_allowed);
        assert!(evaluation.cold_raw_retained);

        // Base head missing for the pinned scope: INCOMPLETE, never CURRENT.
        let mut view = candidate_view();
        view.base_revision_heads = vec![head("context-graph", "rev-3")];
        let evaluation = evaluate_freshness_admission(&view)?;
        assert_eq!(
            evaluation.admission.disposition,
            FreshnessDisposition::Incomplete
        );
        assert!(!evaluation.reusable_promotion_allowed);

        // Expected head missing for the pinned scope: INCOMPLETE.
        let mut view = candidate_view();
        view.expected_post_commit_revision_heads = vec![head("context-graph", "rev-3")];
        let evaluation = evaluate_freshness_admission(&view)?;
        assert_eq!(
            evaluation.admission.disposition,
            FreshnessDisposition::Incomplete
        );
        assert!(!evaluation.reusable_promotion_allowed);
        Ok(())
    }

    #[test]
    fn empty_pinned_denominator_is_incomplete_not_current() -> Result<(), FreshnessError> {
        // No declared pinned dependency can prove the predicate needs none:
        // vacuous CURRENT is forbidden.
        let mut view = candidate_view();
        view.predicate_pinned_scopes = Vec::new();
        let evaluation = evaluate_freshness_admission(&view)?;
        assert_eq!(
            evaluation.admission.disposition,
            FreshnessDisposition::Incomplete
        );
        assert_eq!(evaluation.admission.disposition.as_str(), "INCOMPLETE");
        assert!(!evaluation.reusable_promotion_allowed);
        assert!(evaluation.cold_raw_retained);
        Ok(())
    }

    #[test]
    fn dependency_digest_mismatch_stays_pending() -> Result<(), FreshnessError> {
        // Definition matches but dependencies were rebuilt: no current or
        // Material support through a bare definition match.
        let committed = vec![committed_candidate()];
        let fenced = current_publication();
        let outcome = fetch_committed_candidate(
            "candidate-1",
            &committed,
            &[observed(&fenced, REBUILT_DEPENDENCY_DIGEST)],
        )?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedProjectionPending);
        assert_eq!(outcome.as_str(), CANDIDATE_COMMITTED_PROJECTION_PENDING);
        assert!(!outcome.supports_material_decision());
        assert!(!outcome.hot_path_activatable());
        Ok(())
    }

    #[test]
    fn empty_or_conflicting_candidate_heads_never_current() -> Result<(), FreshnessError> {
        let fenced = current_publication();
        let publications = vec![observed(&fenced, DEPENDENCY_DIGEST)];
        // Empty head set is not coverage: vacuous all() must not promote.
        let mut candidate = committed_candidate();
        candidate.source_revision_heads = Vec::new();
        let outcome = fetch_committed_candidate("candidate-1", &[candidate], &publications)?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedProjectionPending);
        assert!(!outcome.supports_material_decision());

        // Conflicting candidate heads are malformed evidence: the fetch fails
        // closed with an error, which likewise can never obtain current or
        // Material support.
        let mut candidate = committed_candidate();
        candidate.source_revision_heads =
            vec![store_head("cue-index", 4), store_head("cue-index", 5)];
        assert!(fetch_committed_candidate("candidate-1", &[candidate], &publications).is_err());
        Ok(())
    }
    #[test]
    fn committed_candidate_before_publication_returns_pending_and_cannot_support_material()
    -> Result<(), FreshnessError> {
        let committed = vec![committed_candidate()];
        let outcome = fetch_committed_candidate("candidate-1", &committed, &[])?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedProjectionPending);
        assert_eq!(outcome.as_str(), CANDIDATE_COMMITTED_PROJECTION_PENDING);
        assert!(!outcome.supports_material_decision());
        assert!(!outcome.hot_path_activatable());

        let fenced = current_publication();
        let publications = vec![observed(&fenced, DEPENDENCY_DIGEST)];
        let outcome = fetch_committed_candidate("candidate-1", &committed, &publications)?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedCurrent);
        assert!(outcome.supports_material_decision());
        assert!(outcome.hot_path_activatable());
        Ok(())
    }
}
