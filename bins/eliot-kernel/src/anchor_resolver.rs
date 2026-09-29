//! Kernel-owned evolving-anchor resolution join (issue #1824, I10.21/I10.18).
//!
//! I10.21 orders resolution as original artifact/revision plus existing
//! operation/diff identity, then exact file/symbol/AST identity where
//! available, then content fingerprint plus structural-neighborhood
//! fingerprint, then historical range fallback, then an explicit
//! `exact | moved | modified | ambiguous | stale | deleted | unavailable`
//! status. I10.18 consumes that status for anchored review items: the
//! original revision/anchor is immutable history and ambiguous resolution
//! never silently attaches to the most similar fragment.
//!
//! Division of labor: the Governor-owned semantic projection
//! (`EvolvingAnchorResolver` in `eliot-change-monitor` under
//! `crates/governor`) is the canonical resolver over VCS/diff history and
//! code-intelligence evidence. This module is the Kernel-owned join over
//! the evidence the Kernel ledger (`host_request_route::change_monitor`)
//! already carries: governed transition records keyed by operation and
//! diff handle, before/after revisions and content digests, unknown-origin
//! transition digests, and reconciliation links. A `bins` root never
//! depends on Governor crates, so this join takes a ledger-evidence
//! snapshot as a typed input instead of reaching into either crate; it is
//! the missing join, not a second resolver.
//!
//! Evidence rule: the Kernel never invents source bytes, symbols, or
//! neighborhoods. Symbol/AST identity, structural-neighborhood
//! fingerprints, historical-range matches, deletion observations, and
//! human corrections arrive only as validated caller inputs; fields the
//! ledger never recorded stay `None`/false and the tiers that need them
//! simply do not fire. No line/column/span identity exists anywhere here,
//! so no character-permalink behavior is claimed: resolution granularity
//! is resource, path, revision, and digest only.
//!
//! Suppliers without an owner in these paths (STITCH, never faked):
//! - Ledger snapshot: `bins/eliot-kernel/src/change_monitor.rs` needs a
//!   `pub(crate) fn anchor_ledger_evidence() ->
//!   crate::anchor_resolver::AnchorLedgerEvidence` projecting its private
//!   governed/unknown/reconciliation rows. That file is owned by other
//!   lanes and is not touched here.
//! - Symbol/AST, structural neighborhood, historical range, deletion, and
//!   correction inputs: no producer exists in `bins/eliot-kernel` (there
//!   is no `symbol` supplier and no `path.rs::symbol`; deletion readback
//!   explicitly has no producer yet). The code-intelligence, VCS/diff
//!   history, filesystem/Git deletion, and review-correction lanes
//!   populate these inputs; until they do, the corresponding tiers stay
//!   silent and resolution falls through to an explicit terminal status.
//! - Caller: the I10.18 anchored-review current-location resolution path
//!   (`AnchoredReviewItem`, no implementation in `bins/eliot-kernel`
//!   today) calls [`resolve_anchor`].
//! - Delta/operation substrate: none admitted, so no permalink is claimed.

/// Algorithm/version recorded on every resolution produced here.
pub(crate) const KERNEL_ANCHOR_RESOLVER_ALGORITHM_VERSION: &str = "kernel-anchor-resolver/v1";

/// Typed evolving-anchor resolution failures. Every variant is constructed
/// below; there is no stringly error and no silent drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AnchorResolverError {
    /// The immutable original anchor fails shape validation.
    InvalidAnchor,
    /// A current-fragment candidate fails shape validation.
    InvalidCandidate,
    /// A deletion observation fails shape validation.
    InvalidDeletionEvidence,
    /// A human correction names another anchor or contradicts the
    /// original digest it claims to correct from.
    InvalidCorrection,
    /// A ledger-evidence snapshot row fails shape validation.
    InvalidLedgerEvidence,
}

impl std::fmt::Display for AnchorResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidAnchor => "anchor_resolver_invalid_anchor",
            Self::InvalidCandidate => "anchor_resolver_invalid_candidate",
            Self::InvalidDeletionEvidence => "anchor_resolver_invalid_deletion_evidence",
            Self::InvalidCorrection => "anchor_resolver_invalid_correction",
            Self::InvalidLedgerEvidence => "anchor_resolver_invalid_ledger_evidence",
        };
        f.write_str(code)
    }
}

impl std::error::Error for AnchorResolverError {}

fn text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(value: &str) -> bool {
    text(value)
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(':')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn validate_optional_text(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|text_value| text(text_value))
}

fn validate_optional_digest(value: &Option<String>) -> bool {
    value
        .as_ref()
        .is_none_or(|digest| is_sha256_hex(digest))
}

/// Immutable original anchor identity (I10.21 work bullet 4). The value is
/// only ever borrowed and echoed back into the resolution output; a human
/// correction arrives as a separate [`AnchorCorrection`] input and never
/// rewrites this history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelAnchor {
    /// Stable identity of the anchored item (for example a review item id).
    pub anchor_id: String,
    /// Resource carrying the original target (capability-style handle).
    pub resource: String,
    /// Lane-relative file path of the original target.
    pub path: String,
    /// Original revision when the anchoring lane recorded one.
    pub original_revision: Option<String>,
    /// Original content digest (sha256 hex) when recorded.
    pub original_digest: Option<String>,
    /// Originating governed operation identity for the operation/diff tier.
    pub operation: Option<String>,
    /// Originating diff/artifact handle for the operation/diff tier.
    pub diff_handle: Option<String>,
    /// Supplier-admitted symbol/AST identity. No producer exists in these
    /// paths, so in-crate anchors always carry `None`.
    pub symbol: Option<String>,
    /// Supplier-admitted structural-neighborhood baseline. No producer
    /// exists in these paths, so in-crate anchors always carry `None`.
    pub structural_digest: Option<String>,
}

/// One current fragment admitted for comparison. Adapters own discovery;
/// the resolver owns only comparison, so every supplier-owned field is
/// optional evidence, never synthesized here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolveCandidate {
    /// Resource carrying this fragment.
    pub resource: String,
    /// Lane-relative file path of this fragment.
    pub path: String,
    /// Current revision when the supplier recorded one.
    pub revision: Option<String>,
    /// Current content digest (sha256 hex) when recorded.
    pub digest: Option<String>,
    /// Supplier-admitted symbol/AST identity when available.
    pub symbol: Option<String>,
    /// Supplier-admitted structural-neighborhood fingerprint when available.
    pub structural_digest: Option<String>,
    /// Whether a VCS/history supplier matched the original range.
    pub historical_range_match: bool,
}

/// Resolution projection of one governed ledger transition: the exact
/// fields [`resolve_anchor`] compares. The future `change_monitor.rs`
/// snapshot accessor populates this from its private governed rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedTransitionEvidence {
    /// Idempotent governed change identity.
    pub change_id: String,
    /// Changed resource.
    pub resource: String,
    /// Before revision when recorded.
    pub before_revision: Option<String>,
    /// Before content digest (sha256 hex) when recorded.
    pub before_digest: Option<String>,
    /// After revision when recorded.
    pub after_revision: Option<String>,
    /// After content digest (sha256 hex) when recorded.
    pub after_digest: Option<String>,
    /// Tool operation owning this transition.
    pub operation: String,
    /// Diff/artifact handle for this transition.
    pub diff_handle: String,
}

/// Resolution projection of one unknown-origin ledger transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnknownTransitionEvidence {
    /// Unknown-origin change identity.
    pub unknown_change_id: String,
    /// Changed resource.
    pub resource: String,
    /// After content digest (sha256 hex) when recorded.
    pub after_digest: Option<String>,
    /// Digest binding the exact before/after pair.
    pub transition_digest: String,
    /// Whether admitted evidence already reconciled this change.
    pub reconciled: bool,
}

/// One ledger reconciliation link: an unknown-origin change cleared by
/// admitted evidence for the exact same transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReconciliationLink {
    /// Unknown-origin change identity.
    pub unknown_change_id: String,
    /// Evidence change identity that proved the transition.
    pub evidence_change_id: String,
}

/// Ledger evidence the resolution order compares. Populated by the future
/// `change_monitor.rs` snapshot accessor (STITCH); until then callers pass
/// the projection the ledger already carries, field for field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorLedgerEvidence {
    /// Governed transition rows.
    pub governed: Vec<GovernedTransitionEvidence>,
    /// Unknown-origin transition rows.
    pub unknown: Vec<UnknownTransitionEvidence>,
    /// Reconciliation links appending history, never rewriting it.
    pub reconciliations: Vec<ReconciliationLink>,
}

/// Admitted deletion observation naming an original target. There is no
/// in-crate deletion producer (deletion readback explicitly has none), so
/// `deleted` is reported only when a supplier admits one of these.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorDeletionEvidence {
    /// Deleted resource.
    pub resource: String,
    /// Lane-relative file path of the deleted target.
    pub path: String,
    /// Revision observed at deletion when recorded.
    pub revision: Option<String>,
    /// Content digest (sha256 hex) observed at deletion when recorded.
    pub digest: Option<String>,
    /// Digest binding the supplier's observed deletion transition.
    pub transition_digest: String,
}

/// Human correction as a new observation (I10.21 work bullet 6). The
/// original anchor stays untouched in the output; the correction is
/// validated, recorded, and compared like any other admitted evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorCorrection {
    /// Stable correction identity.
    pub correction_id: String,
    /// Anchor this correction attests. Must name the resolved anchor:
    /// a correction for another anchor is refused, never applied.
    pub anchor_id: String,
    /// Attested current resource.
    pub resource: String,
    /// Attested current lane-relative file path.
    pub path: String,
    /// Attested current revision when the human recorded one.
    pub revision: Option<String>,
    /// Attested current content digest (sha256 hex) when recorded.
    pub digest: Option<String>,
    /// Original digest the human corrected from. Must agree with the
    /// anchor's original digest when the anchor carries one.
    pub original_digest: Option<String>,
}

/// Explicit resolution status (I10.21). `Ambiguous` carries no chosen
/// target: false attachment is more harmful than missed resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnchorResolutionStatus {
    /// A current fragment carries the complete original identity.
    Exact,
    /// Identity evidence matched at a different path or resource.
    Moved,
    /// Identity evidence matched at the same path with changed identity.
    Modified,
    /// Identity evidence matched two or more fragments equally.
    Ambiguous,
    /// Fragments exist but no identity evidence matched.
    Stale,
    /// Admitted deletion evidence names the exact original target.
    Deleted,
    /// No current fragment was available at all.
    Unavailable,
}

/// Evidence tier that produced a resolution, in precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnchorResolutionBasis {
    /// The complete immutable original identity matched.
    ExactAnchor,
    /// The anchor's own operation/diff identity bound ledger transitions
    /// whose after-identity a fragment carries.
    OperationDiffIdentity,
    /// Exact file identity, plus symbol/AST identity where available.
    ExactFileSymbol,
    /// Original content digest plus structural-neighborhood fingerprint.
    ContentAndNeighborhood,
    /// A VCS/history supplier matched the original range.
    HistoricalRange,
    /// A human correction attested exactly one current fragment.
    CorrectionAttestation,
    /// Admitted deletion evidence names the exact original target.
    DeletionObservation,
    /// No current fragment was available.
    NoCandidates,
    /// Fragments existed but no identity evidence matched.
    NoMatch,
}

/// Evidence strength for a resolution, not a probability estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnchorResolutionConfidence {
    /// A complete anchor, operation/diff, file/symbol, deletion, or human
    /// attestation identity matched.
    ExactIdentity,
    /// Both independent content and structural-neighborhood digests matched.
    Corroborated,
    /// Only an explicit historical-range match was available.
    HistoricalOnly,
    /// No matching evidence supported a current target.
    Unresolved,
}

/// Resolved current location. Only resource/path/revision/digest: there is
/// no span identity here, so no character-permalink is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedTarget {
    /// Resource carrying the resolved fragment.
    pub resource: String,
    /// Lane-relative file path of the resolved fragment.
    pub path: String,
    /// Resolved revision when recorded.
    pub revision: Option<String>,
    /// Resolved content digest (sha256 hex) when recorded.
    pub digest: Option<String>,
}

impl ResolvedTarget {
    /// Projects the location identity of one matched fragment. Symbol and
    /// structural fingerprints stay in the candidate evidence; the target
    /// carries location identity only.
    fn from_candidate(candidate: &ResolveCandidate) -> Self {
        Self {
            resource: candidate.resource.clone(),
            path: candidate.path.clone(),
            revision: candidate.revision.clone(),
            digest: candidate.digest.clone(),
        }
    }
}

/// Evidence selected by one resolution pass: algorithm/version, inputs,
/// evidence, and confidence (I10.21 work bullet 5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorResolutionEvidence {
    /// First matching tier in the precedence order.
    pub basis: AnchorResolutionBasis,
    /// Indices into the resolution call's candidate inputs that matched.
    pub candidate_indices: Vec<u32>,
    /// Ledger governed change identities used as evidence.
    pub governed_change_ids: Vec<String>,
    /// Reconciled unknown-origin change identities corroborating the
    /// governed evidence.
    pub unknown_change_ids: Vec<String>,
    /// Human correction identities used as evidence.
    pub correction_ids: Vec<String>,
    /// Supplier deletion transition digests used as evidence.
    pub deletion_transition_digests: Vec<String>,
}

/// Rebuildable, evidence-bearing result over an immutable original anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorResolution {
    /// Anchor identity this resolution answers.
    pub anchor_id: String,
    /// Explicit resolution status.
    pub status: AnchorResolutionStatus,
    /// Resolved current location. `None` whenever the status carries no
    /// chosen target: ambiguous, stale, deleted, or unavailable.
    pub current: Option<ResolvedTarget>,
    /// Count of the independent candidate set completeness was judged
    /// against; never silently narrowed.
    pub candidate_count: u32,
    /// Count of admitted human-correction inputs.
    pub correction_count: u32,
    /// Resolver algorithm/version that produced this result.
    pub algorithm_version: String,
    /// Immutable original anchor identity, echoed unchanged.
    pub original_anchor: KernelAnchor,
    /// Selected evidence tier, matched inputs, and ledger identities.
    pub evidence: AnchorResolutionEvidence,
    /// Evidence strength for the selected tier.
    pub confidence: AnchorResolutionConfidence,
}

/// One tier's outcome before it is sealed into an [`AnchorResolution`].
struct TierOutcome {
    status: AnchorResolutionStatus,
    current: Option<ResolvedTarget>,
    basis: AnchorResolutionBasis,
    confidence: AnchorResolutionConfidence,
    candidate_indices: Vec<u32>,
    governed_change_ids: Vec<String>,
    unknown_change_ids: Vec<String>,
    correction_ids: Vec<String>,
    deletion_transition_digests: Vec<String>,
}

fn validate_anchor(anchor: &KernelAnchor) -> Result<(), AnchorResolverError> {
    if !text(&anchor.anchor_id)
        || !text(&anchor.resource)
        || !validate_relative_path(&anchor.path)
        || !validate_optional_text(&anchor.original_revision)
        || !validate_optional_digest(&anchor.original_digest)
        || !validate_optional_text(&anchor.operation)
        || !validate_optional_text(&anchor.diff_handle)
        || !validate_optional_text(&anchor.symbol)
        || !validate_optional_text(&anchor.structural_digest)
    {
        return Err(AnchorResolverError::InvalidAnchor);
    }
    Ok(())
}

fn validate_candidate(candidate: &ResolveCandidate) -> Result<(), AnchorResolverError> {
    if !text(&candidate.resource)
        || !validate_relative_path(&candidate.path)
        || !validate_optional_text(&candidate.revision)
        || !validate_optional_digest(&candidate.digest)
        || !validate_optional_text(&candidate.symbol)
        || !validate_optional_text(&candidate.structural_digest)
    {
        return Err(AnchorResolverError::InvalidCandidate);
    }
    Ok(())
}

fn validate_deletion(deletion: &AnchorDeletionEvidence) -> Result<(), AnchorResolverError> {
    if !text(&deletion.resource)
        || !validate_relative_path(&deletion.path)
        || !validate_optional_text(&deletion.revision)
        || !validate_optional_digest(&deletion.digest)
        || !is_sha256_hex(&deletion.transition_digest)
    {
        return Err(AnchorResolverError::InvalidDeletionEvidence);
    }
    Ok(())
}

fn validate_correction(correction: &AnchorCorrection) -> Result<(), AnchorResolverError> {
    if !text(&correction.correction_id)
        || !text(&correction.anchor_id)
        || !text(&correction.resource)
        || !validate_relative_path(&correction.path)
        || !validate_optional_text(&correction.revision)
        || !validate_optional_digest(&correction.digest)
        || !validate_optional_digest(&correction.original_digest)
    {
        return Err(AnchorResolverError::InvalidCorrection);
    }
    Ok(())
}

fn validate_governed_row(row: &GovernedTransitionEvidence) -> Result<(), AnchorResolverError> {
    if !text(&row.change_id)
        || !text(&row.resource)
        || !validate_optional_text(&row.before_revision)
        || !validate_optional_digest(&row.before_digest)
        || !validate_optional_text(&row.after_revision)
        || !validate_optional_digest(&row.after_digest)
        || !text(&row.operation)
        || !text(&row.diff_handle)
    {
        return Err(AnchorResolverError::InvalidLedgerEvidence);
    }
    Ok(())
}

fn validate_unknown_row(row: &UnknownTransitionEvidence) -> Result<(), AnchorResolverError> {
    if !text(&row.unknown_change_id)
        || !text(&row.resource)
        || !validate_optional_digest(&row.after_digest)
        || !is_sha256_hex(&row.transition_digest)
    {
        return Err(AnchorResolverError::InvalidLedgerEvidence);
    }
    Ok(())
}

fn validate_link(link: &ReconciliationLink) -> Result<(), AnchorResolverError> {
    if !text(&link.unknown_change_id) || !text(&link.evidence_change_id) {
        return Err(AnchorResolverError::InvalidLedgerEvidence);
    }
    Ok(())
}

/// Same resource and path means the fragment stayed in place and changed;
/// any other location means it moved. Text-preserving move/rename may
/// therefore resolve as moved without implying semantic equivalence.
fn location_status(
    original: &KernelAnchor,
    candidate: &ResolveCandidate,
) -> AnchorResolutionStatus {
    if candidate.resource == original.resource && candidate.path == original.path {
        AnchorResolutionStatus::Modified
    } else {
        AnchorResolutionStatus::Moved
    }
}

/// Shared single-vs-multiple match rule: exactly one matched fragment
/// resolves by location; two or more equally matched fragments resolve as
/// ambiguous with recorded evidence and no chosen target.
fn matched_outcome(
    original: &KernelAnchor,
    matched: &[(u32, &ResolveCandidate)],
    basis: AnchorResolutionBasis,
    confidence: AnchorResolutionConfidence,
) -> TierOutcome {
    match matched {
        [(index, candidate)] => TierOutcome {
            status: location_status(original, candidate),
            current: Some(ResolvedTarget::from_candidate(candidate)),
            basis,
            confidence,
            candidate_indices: vec![*index],
            governed_change_ids: Vec::new(),
            unknown_change_ids: Vec::new(),
            correction_ids: Vec::new(),
            deletion_transition_digests: Vec::new(),
        },
        _ => TierOutcome {
            status: AnchorResolutionStatus::Ambiguous,
            current: None,
            basis,
            confidence,
            candidate_indices: matched
                .iter()
                .map(|(index, _)| *index)
                .collect(),
            governed_change_ids: Vec::new(),
            unknown_change_ids: Vec::new(),
            correction_ids: Vec::new(),
            deletion_transition_digests: Vec::new(),
        },
    }
}

fn collect_matches<'a>(
    candidates: &'a [ResolveCandidate],
    mut matches: impl FnMut(&ResolveCandidate) -> bool,
) -> Vec<(u32, &'a ResolveCandidate)> {
    candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| matches(candidate))
        .map(|(index, candidate)| {
            (
                u32::try_from(index).unwrap_or(u32::MAX),
                candidate,
            )
        })
        .collect()
}

/// Original-carried identity fields constrain a match; fields the original
/// never recorded do not block it ("where available").
fn original_field_matches(
    original_field: &Option<String>,
    candidate_field: &Option<String>,
) -> bool {
    original_field
        .as_ref()
        .is_none_or(|original| candidate_field.as_ref() == Some(original))
}

fn candidate_is_exact_original(
    original: &KernelAnchor,
    candidate: &ResolveCandidate,
) -> bool {
    candidate.resource == original.resource
        && candidate.path == original.path
        && original_field_matches(&original.original_revision, &candidate.revision)
        && original_field_matches(&original.original_digest, &candidate.digest)
        && original_field_matches(&original.symbol, &candidate.symbol)
}

/// The bound operation/diff row must prove this anchor's origin: the
/// original-side digest and revision the anchor carries agree with the
/// row's before side wherever both sides recorded a value. A row bound to
/// another operation, another diff handle, or a conflicting origin never
/// matches: one operation's identity is never reused for another.
fn row_proves_anchor_origin(
    row: &GovernedTransitionEvidence,
    anchor: &KernelAnchor,
) -> bool {
    original_field_matches(&anchor.original_digest, &row.before_digest)
        && original_field_matches(&anchor.original_revision, &row.before_revision)
}

fn bound_governed_rows<'a>(
    anchor: &KernelAnchor,
    ledger: &'a AnchorLedgerEvidence,
) -> Vec<&'a GovernedTransitionEvidence> {
    ledger
        .governed
        .iter()
        .filter(|row| {
            let operation_bound = anchor
                .operation
                .as_ref()
                .is_some_and(|operation| &row.operation == operation);
            let diff_bound = anchor
                .diff_handle
                .as_ref()
                .is_some_and(|diff_handle| &row.diff_handle == diff_handle);
            (operation_bound || diff_bound) && row_proves_anchor_origin(row, anchor)
        })
        .collect()
}

/// A fragment carries a bound transition when it names the transition's
/// resource and after-digest, agreeing on the after-revision wherever the
/// ledger recorded one.
fn candidate_matches_transition(
    candidate: &ResolveCandidate,
    row: &GovernedTransitionEvidence,
) -> bool {
    candidate.resource == row.resource
        && row
            .after_digest
            .as_ref()
            .is_some_and(|digest| candidate.digest.as_ref() == Some(digest))
        && original_field_matches(&row.after_revision, &candidate.revision)
}

/// Reconciled unknown-origin transitions proving the exact same
/// resource/after-digest corroborate a bound governed row.
fn corroborating_unknown_ids(
    row: &GovernedTransitionEvidence,
    ledger: &AnchorLedgerEvidence,
) -> Vec<String> {
    ledger
        .unknown
        .iter()
        .filter(|unknown| {
            unknown.reconciled
                && unknown.resource == row.resource
                && unknown.after_digest == row.after_digest
                && ledger.reconciliations.iter().any(|link| {
                    link.unknown_change_id == unknown.unknown_change_id
                        && link.evidence_change_id == row.change_id
                })
        })
        .map(|unknown| unknown.unknown_change_id.clone())
        .collect()
}

fn candidate_matches_attestation(
    candidate: &ResolveCandidate,
    correction: &AnchorCorrection,
) -> bool {
    candidate.resource == correction.resource
        && candidate.path == correction.path
        && original_field_matches(&correction.revision, &candidate.revision)
        && original_field_matches(&correction.digest, &candidate.digest)
}

fn deletion_names_original(
    deletion: &AnchorDeletionEvidence,
    anchor: &KernelAnchor,
) -> bool {
    deletion.resource == anchor.resource
        && deletion.path == anchor.path
        && original_field_matches(&anchor.original_revision, &deletion.revision)
        && original_field_matches(&anchor.original_digest, &deletion.digest)
}

fn validate_inputs(
    original: &KernelAnchor,
    candidates: &[ResolveCandidate],
    deletions: &[AnchorDeletionEvidence],
    corrections: &[AnchorCorrection],
    ledger: &AnchorLedgerEvidence,
) -> Result<(), AnchorResolverError> {
    validate_anchor(original)?;
    for candidate in candidates {
        validate_candidate(candidate)?;
    }
    for deletion in deletions {
        validate_deletion(deletion)?;
    }
    for correction in corrections {
        validate_correction(correction)?;
        if correction.anchor_id != original.anchor_id {
            return Err(AnchorResolverError::InvalidCorrection);
        }
        if !original_field_matches(&original.original_digest, &correction.original_digest) {
            return Err(AnchorResolverError::InvalidCorrection);
        }
    }
    for row in &ledger.governed {
        validate_governed_row(row)?;
    }
    for row in &ledger.unknown {
        validate_unknown_row(row)?;
    }
    for link in &ledger.reconciliations {
        validate_link(link)?;
    }
    Ok(())
}

/// Shared dispatch for the single-predicate tiers: no match falls through,
/// exactly one match resolves by location, several match as ambiguous.
fn tier_outcome(
    original: &KernelAnchor,
    candidates: &[ResolveCandidate],
    matches: impl FnMut(&ResolveCandidate) -> bool,
    basis: AnchorResolutionBasis,
    confidence: AnchorResolutionConfidence,
) -> Option<TierOutcome> {
    let matched = collect_matches(candidates, matches);
    if matched.is_empty() {
        None
    } else {
        Some(matched_outcome(original, &matched, basis, confidence))
    }
}

fn operation_diff_outcome(
    original: &KernelAnchor,
    candidates: &[ResolveCandidate],
    ledger: &AnchorLedgerEvidence,
) -> Option<TierOutcome> {
    let bound_rows = bound_governed_rows(original, ledger);
    if bound_rows.is_empty() {
        return None;
    }
    let transition_matches = collect_matches(candidates, |candidate| {
        bound_rows
            .iter()
            .any(|row| candidate_matches_transition(candidate, row))
    });
    if transition_matches.is_empty() {
        return None;
    }
    let mut outcome = matched_outcome(
        original,
        &transition_matches,
        AnchorResolutionBasis::OperationDiffIdentity,
        AnchorResolutionConfidence::ExactIdentity,
    );
    let mut governed_ids: Vec<String> = Vec::new();
    let mut unknown_ids: Vec<String> = Vec::new();
    for row in &bound_rows {
        let row_used = transition_matches
            .iter()
            .any(|(_, candidate)| candidate_matches_transition(candidate, row));
        if row_used {
            governed_ids.push(row.change_id.clone());
            unknown_ids.extend(corroborating_unknown_ids(row, ledger));
        }
    }
    governed_ids.sort();
    governed_ids.dedup();
    unknown_ids.sort();
    unknown_ids.dedup();
    outcome.governed_change_ids = governed_ids;
    outcome.unknown_change_ids = unknown_ids;
    Some(outcome)
}

fn correction_outcome(
    original: &KernelAnchor,
    candidates: &[ResolveCandidate],
    corrections: &[AnchorCorrection],
) -> Option<TierOutcome> {
    let attested_corrections: Vec<&AnchorCorrection> = corrections
        .iter()
        .filter(|correction| {
            original_field_matches(&original.original_digest, &correction.original_digest)
        })
        .collect();
    if attested_corrections.is_empty() {
        return None;
    }
    let attested = collect_matches(candidates, |candidate| {
        attested_corrections
            .iter()
            .any(|correction| candidate_matches_attestation(candidate, correction))
    });
    if attested.len() != 1 {
        return None;
    }
    let mut outcome = matched_outcome(
        original,
        &attested,
        AnchorResolutionBasis::CorrectionAttestation,
        AnchorResolutionConfidence::ExactIdentity,
    );
    let mut correction_ids: Vec<String> = attested_corrections
        .iter()
        .filter(|correction| {
            attested
                .iter()
                .any(|(_, candidate)| candidate_matches_attestation(candidate, correction))
        })
        .map(|correction| correction.correction_id.clone())
        .collect();
    correction_ids.sort();
    correction_ids.dedup();
    outcome.correction_ids = correction_ids;
    Some(outcome)
}

fn deletion_outcome(
    original: &KernelAnchor,
    deletions: &[AnchorDeletionEvidence],
) -> Option<TierOutcome> {
    let deletion_matches: Vec<&AnchorDeletionEvidence> = deletions
        .iter()
        .filter(|deletion| deletion_names_original(deletion, original))
        .collect();
    if deletion_matches.is_empty() {
        return None;
    }
    let mut transition_digests: Vec<String> = deletion_matches
        .iter()
        .map(|deletion| deletion.transition_digest.clone())
        .collect();
    transition_digests.sort();
    transition_digests.dedup();
    Some(TierOutcome {
        status: AnchorResolutionStatus::Deleted,
        current: None,
        basis: AnchorResolutionBasis::DeletionObservation,
        confidence: AnchorResolutionConfidence::ExactIdentity,
        candidate_indices: Vec::new(),
        governed_change_ids: Vec::new(),
        unknown_change_ids: Vec::new(),
        correction_ids: Vec::new(),
        deletion_transition_digests: transition_digests,
    })
}

fn terminal_outcome(candidates_empty: bool) -> TierOutcome {
    let (status, basis) = if candidates_empty {
        (
            AnchorResolutionStatus::Unavailable,
            AnchorResolutionBasis::NoCandidates,
        )
    } else {
        (AnchorResolutionStatus::Stale, AnchorResolutionBasis::NoMatch)
    };
    TierOutcome {
        status,
        current: None,
        basis,
        confidence: AnchorResolutionConfidence::Unresolved,
        candidate_indices: Vec::new(),
        governed_change_ids: Vec::new(),
        unknown_change_ids: Vec::new(),
        correction_ids: Vec::new(),
        deletion_transition_digests: Vec::new(),
    }
}

fn seal(
    original: &KernelAnchor,
    candidate_count: u32,
    correction_count: u32,
    outcome: TierOutcome,
) -> AnchorResolution {
    AnchorResolution {
        anchor_id: original.anchor_id.clone(),
        status: outcome.status,
        current: outcome.current,
        candidate_count,
        correction_count,
        algorithm_version: KERNEL_ANCHOR_RESOLVER_ALGORITHM_VERSION.to_owned(),
        original_anchor: original.clone(),
        evidence: AnchorResolutionEvidence {
            basis: outcome.basis,
            candidate_indices: outcome.candidate_indices,
            governed_change_ids: outcome.governed_change_ids,
            unknown_change_ids: outcome.unknown_change_ids,
            correction_ids: outcome.correction_ids,
            deletion_transition_digests: outcome.deletion_transition_digests,
        },
        confidence: outcome.confidence,
    }
}

/// Resolves one immutable anchor over admitted ledger evidence and
/// supplier inputs, in I10.21 precedence order: exact original identity,
/// then original operation/diff identity, then exact file/symbol identity
/// where available, then content plus structural-neighborhood fingerprint,
/// then historical range, then human-correction attestation, then admitted
/// deletion evidence, then an explicit terminal status.
///
/// An old anchor matching two fragments equally resolves as `ambiguous`
/// with both indices recorded and no chosen target. A deleted target
/// resolves as `deleted` while staying historically addressable through
/// the echoed original anchor and the recorded deletion transition
/// digests. The original anchor is never mutated: corrections are separate
/// validated inputs whose identities are recorded in the output.
///
/// Callers: the I10.18 anchored-review current-location resolution path
/// (STITCH: no implementation in `bins/eliot-kernel` today).
///
/// # Errors
///
/// Returns a typed [`AnchorResolverError`] when the anchor, a candidate, a
/// deletion observation, a correction, or a ledger-evidence row fails shape
/// validation, or when a correction names another anchor or contradicts the
/// original digest it claims to correct from.
pub(crate) fn resolve_anchor(
    original: &KernelAnchor,
    candidates: &[ResolveCandidate],
    deletions: &[AnchorDeletionEvidence],
    corrections: &[AnchorCorrection],
    ledger: &AnchorLedgerEvidence,
) -> Result<AnchorResolution, AnchorResolverError> {
    validate_inputs(original, candidates, deletions, corrections, ledger)?;

    let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
    let correction_count = u32::try_from(corrections.len()).unwrap_or(u32::MAX);
    let seal_outcome =
        |outcome: TierOutcome| seal(original, candidate_count, correction_count, outcome);

    if let Some(outcome) = tier_outcome(
        original,
        candidates,
        |candidate| candidate_is_exact_original(original, candidate),
        AnchorResolutionBasis::ExactAnchor,
        AnchorResolutionConfidence::ExactIdentity,
    ) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = operation_diff_outcome(original, candidates, ledger) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = tier_outcome(
        original,
        candidates,
        |candidate| {
            candidate.resource == original.resource
                && candidate.path == original.path
                && original_field_matches(&original.symbol, &candidate.symbol)
        },
        AnchorResolutionBasis::ExactFileSymbol,
        AnchorResolutionConfidence::ExactIdentity,
    ) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = tier_outcome(
        original,
        candidates,
        |candidate| {
            original
                .original_digest
                .as_ref()
                .is_some_and(|digest| candidate.digest.as_ref() == Some(digest))
                && original.structural_digest.as_ref().is_some_and(|structural| {
                    candidate.structural_digest.as_ref() == Some(structural)
                })
        },
        AnchorResolutionBasis::ContentAndNeighborhood,
        AnchorResolutionConfidence::Corroborated,
    ) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = tier_outcome(
        original,
        candidates,
        |candidate| candidate.historical_range_match,
        AnchorResolutionBasis::HistoricalRange,
        AnchorResolutionConfidence::HistoricalOnly,
    ) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = correction_outcome(original, candidates, corrections) {
        return Ok(seal_outcome(outcome));
    }

    if let Some(outcome) = deletion_outcome(original, deletions) {
        return Ok(seal_outcome(outcome));
    }

    Ok(seal_outcome(terminal_outcome(candidates.is_empty())))
}
