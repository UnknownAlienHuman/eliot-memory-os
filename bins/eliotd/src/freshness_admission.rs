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
//!   projection has no matching [`ProjectionPublicationRecord`] with status
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
//! Like the neighboring admission joins, this helper never mints admission:
//! it evaluates presented values and returns a disposition.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

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
/// sequence, so admission compares values instead of arrival order.
pub fn normalize_heads(heads: &[RevisionHead]) -> Result<Vec<RevisionHead>, FreshnessError> {
    for head in heads {
        head.validate()?;
    }
    let mut normalized: Vec<RevisionHead> = heads.to_vec();
    normalized.sort();
    normalized.dedup();
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

/// Evaluates normalized freshness admission for one reusable candidate.
///
/// Order is load-bearing and fail-closed: unresolved provenance or task
/// mismatch yields `INCOMPLETE` before any revision comparison; a pinned
/// scope moved by the candidate's own commit yields `SELF_INVALIDATING`; a
/// pinned scope the candidate does not advance but observed moved yields
/// `EXTERNAL_REVISION_RACE`; otherwise the candidate is `CURRENT`.
///
/// # Errors
///
/// Returns [`FreshnessError`] when any identity, fence, predicate form, or
/// head is malformed. Malformed input admits nothing and promotes nothing.
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
    let base = normalize_heads(&candidate.base_revision_heads)?;
    let expected = normalize_heads(&candidate.expected_post_commit_revision_heads)?;
    let observed = normalize_heads(&candidate.observed_source_heads)?;

    let disposition = if candidate.provenance != ProvenanceStanding::Resolved
        || candidate.task != TaskCompatibility::Compatible
    {
        FreshnessDisposition::Incomplete
    } else {
        let base_map = heads_by_scope(&base);
        let expected_map = heads_by_scope(&expected);
        let observed_map = heads_by_scope(&observed);
        let mut disposition = FreshnessDisposition::Current;
        for scope in &candidate.predicate_pinned_scopes {
            let scope = scope.as_str();
            let base_revision = base_map.get(scope).copied();
            let expected_revision = expected_map.get(scope).copied();
            let observed_revision = observed_map.get(scope).copied();
            if expected_revision != base_revision {
                disposition = FreshnessDisposition::SelfInvalidating;
                break;
            }
            if observed_revision.is_some() && observed_revision != base_revision {
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

/// Projection publication mode (I5.8 exact set).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationMode {
    /// Whole-projection publish from measured whole-dependency cost.
    Full,
    /// Incremental publish against the same-fence equality oracle.
    Delta,
    /// Exact/reference fallback with a deterministic rollback plan.
    ReferenceFallback,
}

impl PublicationMode {
    /// Contract vocabulary for diagnostics and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Delta => "DELTA",
            Self::ReferenceFallback => "REFERENCE_FALLBACK",
        }
    }
}

/// Projection publication status (I5.8 exact set).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionPublicationStatus {
    /// Published but not yet verified current at its source fence.
    Pending,
    /// Verified current: atomic data plus provenance at the source fence.
    Current,
    /// Superseded or diverged from its source fence.
    Stale,
    /// Publication failed closed; never serves reads as current.
    Failed,
    /// Equality oracle could not decide; never serves reads as current.
    Inconclusive,
}

impl ProjectionPublicationStatus {
    /// Contract vocabulary for diagnostics and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Current => "CURRENT",
            Self::Stale => "STALE",
            Self::Failed => "FAILED",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Fenced projection publication record (I5.8).
///
/// The projection owner persists this record; this shape is the
/// already-observed value the caller threads per fetch, so a refresh
/// surfaces as an exact mismatch instead of silent divergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPublicationRecord {
    /// Projection kind and generation under evaluation.
    pub projection_kind: String,
    /// Digest of the projection definition that produced the data.
    pub projection_definition_digest: String,
    /// Digest of the dependency definitions the projection was built from.
    pub dependency_definition_digest: String,
    /// Source fence and cursor the publication was taken at.
    pub source_fence: String,
    /// Normalized source revision heads covered by the publication.
    pub source_revision_heads: Vec<RevisionHead>,
    /// Atomic data-plus-provenance commit reference; both landed together.
    pub atomic_data_provenance_receipt: String,
    /// Publication status; only `CURRENT` serves hot/proof-bearing reads.
    pub status: ProjectionPublicationStatus,
    /// How the projection was published.
    pub publication_mode: PublicationMode,
}

impl ProjectionPublicationRecord {
    /// Validates the record shape; malformed records never serve reads.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError`] when any identity, digest, fence, receipt,
    /// or head is malformed.
    pub fn validate(&self) -> Result<(), FreshnessError> {
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
        check_identity("source fence", &self.source_fence, 512)?;
        check_identity(
            "atomic data/provenance receipt",
            &self.atomic_data_provenance_receipt,
            512,
        )?;
        normalize_heads(&self.source_revision_heads)?;
        Ok(())
    }

    /// True when this record makes the candidate's projection current.
    ///
    /// Currency requires all of: status `CURRENT`, exact projection kind,
    /// exact definition digest, exact source fence, coverage of every
    /// candidate source head at the same revision, and a non-blank atomic
    /// data/provenance receipt. Partial provenance, a stale definition, or a
    /// mismatched fence leaves the projection pending/stale.
    #[must_use]
    pub fn is_current_for(
        &self,
        candidate_kind: &str,
        candidate_definition_digest: &str,
        candidate_source_fence: &str,
        candidate_source_heads: &[RevisionHead],
    ) -> bool {
        if self.status != ProjectionPublicationStatus::Current {
            return false;
        }
        if self.projection_kind != candidate_kind {
            return false;
        }
        if self.projection_definition_digest != candidate_definition_digest {
            return false;
        }
        if self.source_fence != candidate_source_fence {
            return false;
        }
        if self.atomic_data_provenance_receipt.trim().is_empty() {
            return false;
        }
        let published = heads_by_scope(&self.source_revision_heads);
        candidate_source_heads.iter().all(|head| {
            published
                .get(head.scope.as_str())
                .is_some_and(|revision| *revision == head.revision.as_str())
        })
    }
}

/// Durably committed candidate awaiting (or covered by) projection
/// publication.
///
/// The store owns the commit; this shape is the already-observed durable
/// identity the caller threads per fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCandidate {
    /// Exact handle the record is fetched by.
    pub handle: String,
    /// Durable commit receipt; proves transport only, never freshness.
    pub durability_receipt: String,
    /// Projection kind whose currency gates hot/proof-bearing use.
    pub projection_kind: String,
    /// Projection definition digest the candidate was committed against.
    pub projection_definition_digest: String,
    /// Source fence the candidate was committed at.
    pub source_fence: String,
    /// Source revision heads the candidate was committed at.
    pub source_revision_heads: Vec<RevisionHead>,
}

impl CommittedCandidate {
    /// Validates the committed identity; malformed commits fetch nothing.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError`] when the handle, receipt, kind, digest,
    /// fence, or any head is malformed.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        check_identity("candidate handle", &self.handle, 512)?;
        check_identity("durability receipt", &self.durability_receipt, 512)?;
        check_identity("projection kind", &self.projection_kind, 256)?;
        check_identity(
            "projection definition digest",
            &self.projection_definition_digest,
            512,
        )?;
        check_identity("source fence", &self.source_fence, 512)?;
        normalize_heads(&self.source_revision_heads)?;
        Ok(())
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
/// until a current publication record exists.
///
/// # Errors
///
/// Returns [`FreshnessError`] for malformed input or for an unknown handle.
/// An unknown handle is never synthesized into a pending outcome.
pub fn fetch_committed_candidate(
    handle: &str,
    committed: &[CommittedCandidate],
    publications: &[ProjectionPublicationRecord],
) -> Result<CandidateFetchOutcome, FreshnessError> {
    check_identity("candidate handle", handle, 512)?;
    let candidate = committed
        .iter()
        .find(|candidate| candidate.handle == handle)
        .ok_or_else(|| invalid("unknown candidate handle"))?;
    candidate.validate()?;
    for publication in publications {
        publication.validate()?;
    }
    let current = publications.iter().any(|publication| {
        publication.is_current_for(
            &candidate.projection_kind,
            &candidate.projection_definition_digest,
            &candidate.source_fence,
            &candidate.source_revision_heads,
        )
    });
    Ok(if current {
        CandidateFetchOutcome::CommittedCurrent
    } else {
        CandidateFetchOutcome::CommittedProjectionPending
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(scope: &str, revision: &str) -> RevisionHead {
        RevisionHead {
            scope: scope.to_owned(),
            revision: revision.to_owned(),
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
            durability_receipt: "receipt-commit-1".to_owned(),
            projection_kind: "cue-index".to_owned(),
            projection_definition_digest: "def-digest-1".to_owned(),
            source_fence: "fence-epoch-1/gen-1".to_owned(),
            source_revision_heads: vec![head("cue-index", "rev-7")],
        }
    }

    fn current_publication() -> ProjectionPublicationRecord {
        ProjectionPublicationRecord {
            projection_kind: "cue-index".to_owned(),
            projection_definition_digest: "def-digest-1".to_owned(),
            dependency_definition_digest: "dep-digest-1".to_owned(),
            source_fence: "fence-epoch-1/gen-1".to_owned(),
            source_revision_heads: vec![head("cue-index", "rev-7")],
            atomic_data_provenance_receipt: "atomic-receipt-1".to_owned(),
            status: ProjectionPublicationStatus::Current,
            publication_mode: PublicationMode::Full,
        }
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
    fn committed_candidate_before_publication_returns_pending_and_cannot_support_material()
    -> Result<(), FreshnessError> {
        let committed = vec![committed_candidate()];
        let outcome = fetch_committed_candidate("candidate-1", &committed, &[])?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedProjectionPending);
        assert_eq!(outcome.as_str(), CANDIDATE_COMMITTED_PROJECTION_PENDING);
        assert!(!outcome.supports_material_decision());
        assert!(!outcome.hot_path_activatable());

        let publications = vec![current_publication()];
        let outcome = fetch_committed_candidate("candidate-1", &committed, &publications)?;
        assert_eq!(outcome, CandidateFetchOutcome::CommittedCurrent);
        assert!(outcome.supports_material_decision());
        assert!(outcome.hot_path_activatable());
        Ok(())
    }
}
