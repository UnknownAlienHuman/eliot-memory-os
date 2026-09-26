//! Researcher evidence discipline (issue #700).
//!
//! Bounded inquiry records, source vetting, a frozen authorized evidence
//! portfolio, exact coverage accounting and graded handoff audit. This module
//! owns acquisition-side discipline only: it grades, freezes and audits
//! already-structured evidence. It performs no provider dispatch, no network
//! or process execution, no Dreamer synthesis, no epistemic promotion and no
//! canonical write.
//!
//! The canonical four evidence grades and their weakest-first order are owned
//! by A-06e (`eliot-epistemic-contracts`); this module references that ladder
//! by frozen wire name and rank and never redefines it. Coverage vocabulary
//! (exact denominator, one disposition per member, complete-scope-only
//! absence) mirrors the canonical denominator owner link-agnostically: the
//! admission linkage in #829 is open, so this unit builds against the exact
//! frozen spellings and records the residual rather than inventing owners.
//!
//! Digests are lowercase SHA-256 over an explicit length-prefixed canonical
//! preimage with `'\0'`-free validated fields, so arrival order never affects
//! frozen bytes: every set iterates in `BTree` order.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_research_exchange_api::{CompletionDisposition, DisclosureClass, SourceClass};
use serde::{Serialize, Serializer};

/// Stable identity of this discipline surface.
pub const PORTFOLIO_CONTRACT: &str = "eliot.research.evidence-portfolio";
/// Current wire revision of this discipline surface.
pub const PORTFOLIO_VERSION: &str = "1.0.0";

/// Canonical A-06e/I21.2 evidence grades, weakest-first.
///
/// The order is load-bearing: position `i` is strictly less rigorous than
/// position `i + 1`. The single owner of this ladder is
/// `eliot-epistemic-contracts`; the names here are frozen references, not a
/// second enum.
pub const GRADE_ORDER: [&str; 4] = ["ORIENTING", "GROUNDED", "CORROBORATED", "SCIENCE_GRADE"];

/// Reason codes reused from the I7.20 agent-facing registry for terminal
/// portfolio results. No new reason owner is introduced here.
pub const REASON_COVERAGE_PARTIAL: &str = "EVIDENCE_COVERAGE_PARTIAL";
/// Reason codes reused from the I7.20 agent-facing registry for terminal
/// portfolio results. No new reason owner is introduced here.
pub const REASON_DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
/// Reason codes reused from the I7.20 agent-facing registry for terminal
/// portfolio results. No new reason owner is introduced here.
pub const REASON_CANCELLATION_UNCONFIRMED: &str = "CANCELLATION_UNCONFIRMED";
/// Reason codes reused from the I7.20 agent-facing registry for terminal
/// portfolio results. No new reason owner is introduced here.
pub const REASON_UNKNOWN_OUTCOME: &str = "UNKNOWN_OUTCOME";

/// Typed discipline failure. Variants name the failing field only and never
/// echo supplied values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortfolioError {
    /// A required value is empty or whitespace-only.
    Blank {
        /// Failing field path.
        field: &'static str,
    },
    /// A value contains a control character.
    ControlCharacter {
        /// Failing field path.
        field: &'static str,
    },
    /// A digest is not lowercase SHA-256 hex.
    BadDigest {
        /// Failing field path.
        field: &'static str,
    },
    /// A scope/denominator spelling claims coverage without declaring it.
    VagueScope {
        /// Failing field path.
        field: &'static str,
    },
    /// A grade name is not one of the four canonical frozen names.
    UnknownGrade,
    /// A claimed grade exceeds its ceiling.
    CeilingViolation {
        /// Failing field path.
        field: &'static str,
    },
    /// An identity is already bound to different content.
    Duplicate {
        /// Failing field path.
        field: &'static str,
    },
    /// An identity is not part of the frozen set.
    UnknownHandle {
        /// Failing field path.
        field: &'static str,
    },
    /// The same identity arrived with conflicting content.
    Conflict {
        /// Failing field path.
        field: &'static str,
    },
    /// Source citations form a dependence cycle.
    CircularCitation {
        /// Failing field path.
        field: &'static str,
    },
    /// A citation resolves to no recorded source root.
    UnresolvedRoot {
        /// Failing field path.
        field: &'static str,
    },
    /// The denominator is not exact or not fully accounted.
    IncompleteDenominator {
        /// Failing field path.
        field: &'static str,
    },
    /// A reference falls outside the frozen manifest.
    OutsideManifest {
        /// Failing field path.
        field: &'static str,
    },
    /// Asserted precision exceeds what the evidence supports.
    UnsupportedPrecision {
        /// Failing field path.
        field: &'static str,
    },
    /// A terminal result was decoded as complete/finished.
    InvalidTerminal {
        /// Failing field path.
        field: &'static str,
    },
    /// A canonical value could not be encoded into its declared identity domain.
    ///
    /// Identity preimages in this module go through the repository's accepted
    /// canonical serializer ([`eliot_contracts::canonical_json_bytes`]), so an
    /// unencodable value is a real refusal rather than a silent omission: a
    /// digest that skipped a field it could not spell would be exactly the
    /// identity seam this module exists to close.
    Unencodable {
        /// Failing field path.
        field: &'static str,
    },
    /// A recomputed canonical digest disagrees with the frozen one.
    ///
    /// This is the readback/provenance check: a record, inquiry or manifest
    /// whose bytes no longer hash to the digest bound to it has been substituted
    /// or corrupted after the freeze, and constructor-time validation alone
    /// cannot detect that.
    InvalidDigest {
        /// Failing field path.
        field: &'static str,
    },
}

impl std::fmt::Display for PortfolioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blank { field } => write!(f, "{field} must be non-blank"),
            Self::ControlCharacter { field } => {
                write!(f, "{field} contains a control character")
            }
            Self::BadDigest { field } => {
                write!(f, "{field} must be a lowercase SHA-256 digest")
            }
            Self::VagueScope { field } => {
                write!(f, "{field} claims coverage without declaring it")
            }
            Self::UnknownGrade => write!(f, "grade is not a canonical frozen grade name"),
            Self::CeilingViolation { field } => write!(f, "{field} exceeds its evidence ceiling"),
            Self::Duplicate { field } => write!(f, "{field} is already bound"),
            Self::UnknownHandle { field } => write!(f, "{field} is not a frozen member"),
            Self::Conflict { field } => write!(f, "{field} conflicts with frozen content"),
            Self::CircularCitation { field } => write!(f, "{field} forms a citation cycle"),
            Self::UnresolvedRoot { field } => {
                write!(f, "{field} resolves to no recorded source")
            }
            Self::IncompleteDenominator { field } => {
                write!(f, "{field} is not an exact accounted denominator")
            }
            Self::OutsideManifest { field } => {
                write!(f, "{field} falls outside the frozen manifest")
            }
            Self::UnsupportedPrecision { field } => {
                write!(f, "{field} asserts unsupported precision")
            }
            Self::InvalidTerminal { field } => {
                write!(f, "{field} cannot decode as complete")
            }
            Self::Unencodable { field } => {
                write!(f, "{field} cannot be encoded into its canonical domain")
            }
            Self::InvalidDigest { field } => {
                write!(f, "{field} does not match its recomputed canonical digest")
            }
        }
    }
}

impl std::error::Error for PortfolioError {}

/// Bounded-text validator shared by the acquisition-side discipline in this
/// crate. The R6 inquiry-governance domain in [`crate::inquiry_governance`]
/// reuses it rather than declaring a second field-validator recipe, so a
/// "blank or control-bearing" definition exists once per crate.
pub(crate) fn text(value: &str, field: &'static str) -> Result<(), PortfolioError> {
    if value.trim().is_empty() {
        return Err(PortfolioError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(PortfolioError::ControlCharacter { field });
    }
    Ok(())
}

/// Lowercase SHA-256 validator shared inside this crate; see [`text`] for the
/// single-owner rationale.
pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), PortfolioError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PortfolioError::BadDigest { field });
    }
    Ok(())
}

/// Spellings that claim coverage without declaring it. Matching is exact on
/// the trimmed lowercase value, mirroring the canonical denominator owner.
const VAGUE_SCOPE_TEXTS: [&str; 7] = [
    "all",
    "all-relevant",
    "all relevant",
    "everything",
    "*",
    "relevant",
    "unknown",
];

/// Rejects scope/denominator spellings that claim coverage without declaring
/// it. Shared inside this crate; see [`text`].
pub(crate) fn reject_vague(value: &str, field: &'static str) -> Result<(), PortfolioError> {
    if VAGUE_SCOPE_TEXTS.contains(&value.trim().to_lowercase().as_str()) {
        return Err(PortfolioError::VagueScope { field });
    }
    Ok(())
}

/// Appends one length-prefixed field to a canonical preimage. Shared inside
/// this crate so every digest recipe is length-delimited identically; see
/// [`text`].
pub(crate) fn push_field(preimage: &mut String, tag: &str, value: &str) {
    preimage.push_str(tag);
    preimage.push('=');
    preimage.push_str(&value.len().to_string());
    preimage.push(':');
    preimage.push_str(value);
    preimage.push(';');
}

/// Appends one element count to a canonical preimage. Shared inside this
/// crate; see [`text`].
pub(crate) fn push_count(preimage: &mut String, tag: &str, count: usize) {
    use std::fmt::Write as _;
    let _ = write!(preimage, "{tag}={count};");
}

/// Freezes a canonical preimage into its lowercase SHA-256 digest. Shared
/// inside this crate; see [`text`].
pub(crate) fn freeze(preimage: &str) -> String {
    sha256_hex(preimage.as_bytes())
}

/// Returns the canonical weakest-first rank of a frozen grade name.
pub fn grade_rank(name: &str) -> Result<u8, PortfolioError> {
    GRADE_ORDER
        .iter()
        .position(|known| *known == name)
        .and_then(|rank| u8::try_from(rank).ok())
        .ok_or(PortfolioError::UnknownGrade)
}

/// Returns the canonical grade name for a weakest-first rank.
pub fn grade_name(rank: u8) -> Result<&'static str, PortfolioError> {
    GRADE_ORDER
        .get(usize::from(rank))
        .copied()
        .ok_or(PortfolioError::UnknownGrade)
}

/// Weakest-link ceiling over supplied grades: `None` entries are unknown and
/// poison the result to unknown. An empty input is an error; repetition of
/// the strongest grade never raises the minimum.
pub fn weakest_ceiling(grades: &[Option<u8>]) -> Result<Option<u8>, PortfolioError> {
    let mut iter = grades.iter();
    let first = iter
        .next()
        .ok_or(PortfolioError::Blank { field: "grade.set" })?;
    let mut ceiling = *first;
    for grade in iter {
        ceiling = match (ceiling, *grade) {
            (Some(current), Some(candidate)) => Some(current.min(candidate)),
            _ => None,
        };
    }
    Ok(ceiling)
}

/// Validates that a claimed grade does not exceed its ceiling. Quoting never
/// upgrades: a dependent result is bounded by its parent ceiling.
pub fn check_ceiling(claimed: u8, ceiling: u8) -> Result<(), PortfolioError> {
    grade_name(claimed)?;
    grade_name(ceiling)?;
    if claimed > ceiling {
        return Err(PortfolioError::CeilingViolation {
            field: "grade.ceiling",
        });
    }
    Ok(())
}

/// What one acquisition route observed for one expected source: mutually
/// exclusive outcomes. `Exhaustion` records that a budget ended the route and
/// never decodes as completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceDisposition {
    /// The source was acquired with intact evidence.
    Observed,
    /// The source was acquired but truncated or otherwise partial.
    Partial,
    /// The source could not be read; the gap stays explicit.
    Unavailable,
    /// The source was blocked by policy or scope fencing.
    Blocked,
    /// The capture is past its freshness boundary.
    Stale,
    /// The payload failed shape validation; bytes are preserved elsewhere.
    Malformed,
    /// The route budget was exhausted before the source was reached.
    Exhausted,
    /// The outcome cannot be established.
    Unknown,
}

impl SourceDisposition {
    /// Stable wire spelling of this disposition.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Partial => "PARTIAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::Blocked => "BLOCKED",
            Self::Stale => "STALE",
            Self::Malformed => "MALFORMED",
            Self::Exhausted => "EXHAUSTED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Whether this disposition may carry evidentiary weight. Only intact or
    /// explicitly partial acquisition may support a claim; every other outcome
    /// is preserved as an accounted gap.
    pub const fn may_support(self) -> bool {
        matches!(self, Self::Observed | Self::Partial)
    }

    /// Whether this disposition closes its denominator member. Only an intact
    /// observation closes; partial acquisition, exhaustion and every failure
    /// mode stay open.
    pub const fn closes_member(self) -> bool {
        matches!(self, Self::Observed)
    }
}

impl Serialize for SourceDisposition {
    /// Serializes as the same stable wire spelling [`Self::wire_name`] returns.
    ///
    /// The identity preimages must not depend on a Rust variant name, and this
    /// enum must not grow a second spelling: `wire_name` is the single owner and
    /// this impl only projects it. A derived `Serialize` would have emitted the
    /// variant identifier (`Observed`) instead, which is the same defect as
    /// encoding `{:?}` into a digest.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.wire_name())
    }
}

/// Ranked deception/exfiltration/persistence risk for one source (I15.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskState {
    /// The risk was never assessed; assessment stays an open debt.
    Unassessed,
    /// Assessed low under the frozen verifier.
    Low,
    /// Assessed elevated; use is bounded by the recorded verifier.
    Elevated,
    /// Assessed high; the source is quarantined for evidentiary use.
    High,
}

impl RiskState {
    /// Stable wire spelling of this risk state.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unassessed => "UNASSESSED",
            Self::Low => "LOW",
            Self::Elevated => "ELEVATED",
            Self::High => "HIGH",
        }
    }
}

impl Serialize for RiskState {
    /// Serializes as the same stable wire spelling [`Self::wire_name`] returns.
    /// See the [`SourceDisposition`] impl for the single-owner rationale.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.wire_name())
    }
}

/// One exact structured evidence span inside a source payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceSpan {
    /// Stable span identity within the source.
    pub span_id: String,
    /// Anchor locating the span (section, page, symbol path).
    pub anchor: String,
    /// Digest of the exact excerpt bytes.
    pub excerpt_digest: String,
}

impl EvidenceSpan {
    /// Total order used to freeze spans deterministically.
    ///
    /// `evidence_spans` arrives as a `Vec`, so a caller's ordering would
    /// otherwise leak into the record's identity and two records holding the
    /// same spans in a different order would disagree on their digest while
    /// meaning exactly the same thing. Ordering is by the whole span, so a
    /// duplicated `span_id` with different content still sorts deterministically
    /// and both copies stay bound.
    fn canonical_order(&self, other: &Self) -> std::cmp::Ordering {
        self.span_id
            .cmp(&other.span_id)
            .then_with(|| self.anchor.cmp(&other.anchor))
            .then_with(|| self.excerpt_digest.cmp(&other.excerpt_digest))
    }
}

/// A vetted source record. Every I15.5 assurance dimension is an explicit
/// typed field: identity/provenance, integrity, freshness, domain competence,
/// incentives/track record, independence/common lineage, privacy class,
/// instruction-injection risk, deception/exfiltration/persistence risk,
/// allowed epistemic use, allowed effects, and required verifier/quarantine.
///
/// Every field on this struct participates in [`Self::digest`]. The record is
/// serialized whole through the repository's canonical serializer, so a field
/// cannot be added here and left out of the identity: the omission that made a
/// changed freshness boundary, transform verification, allowed effect, verifier,
/// quarantine, counterevidence target, citation edge, excerpt span or data role
/// hash identically is no longer expressible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceRecord {
    /// Canonical source handle; the frozen identity of this record.
    pub handle: String,
    /// Source class from the exchange wire vocabulary.
    pub class: SourceClass,
    /// Human-readable title (data, never authority).
    pub title: String,
    /// Canonical locator (store handle, snapshot id, dossier ref).
    pub locator: String,
    /// Digest of the acquired content bytes.
    pub content_digest: String,
    /// Acquisition operation that produced this record.
    pub operation_id: String,
    /// Raw acquisition receipt handle preserved before any reduction.
    pub receipt_handle: String,
    /// What the acquisition route observed.
    pub acquisition: SourceDisposition,
    /// Known publication time in Unix milliseconds, when known.
    pub published_ms: Option<i64>,
    /// Observation time in Unix milliseconds, when known.
    pub observed_ms: Option<i64>,
    /// Retrieval time in Unix milliseconds, when known.
    pub retrieved_ms: Option<i64>,
    /// Freshness boundary in Unix milliseconds; retrieval past it is stale.
    pub freshness_boundary_ms: Option<i64>,
    /// Raw source this record was transformed from, when derived.
    pub transformed_from: Option<String>,
    /// Whether the raw-to-transformed derivation was verified.
    pub transform_verified: bool,
    /// Canonical grade rank carried by this source, when known.
    pub grade: Option<u8>,
    /// Claim-specific authority domains this source is competent in.
    pub authority_domains: BTreeSet<String>,
    /// Exact common lineage root; `None` preserves unknown independence and
    /// is never treated as a unique root.
    pub lineage_root: Option<String>,
    /// Privacy class carried end to end.
    pub disclosure: DisclosureClass,
    /// Free-text source content stays inert data; flags record that
    /// instruction-like text was observed without granting it standing.
    pub content_flags: BTreeSet<String>,
    /// Incentives and track-record note (bounded prose, data only).
    pub incentives_note: String,
    /// Deception/exfiltration/persistence risk assessment.
    pub deception_risk: RiskState,
    /// Allowed epistemic use of this source.
    pub allowed_use: String,
    /// Allowed effects of acting on this source.
    pub allowed_effects: String,
    /// Required verifier or quarantine condition.
    pub verifier: String,
    /// Quarantine reason; required exactly when risk is high.
    pub quarantine: Option<String>,
    /// Claim identities this source opposes (counterevidence preserved).
    pub counterevidence_of: BTreeSet<String>,
    /// Source-level citation edges for dependence-cycle detection.
    pub cites: Vec<String>,
    /// Exact structured evidence spans.
    pub evidence_spans: Vec<EvidenceSpan>,
    /// Data role this source fills in the inquiry.
    pub data_role: String,
}

/// Named constructor arguments for [`SourceRecord::new`]. Named fields block
/// transposition; text uses concrete `String`.
#[derive(Clone, Debug)]
pub struct SourceRecordParams {
    /// Canonical source handle.
    pub handle: String,
    /// Source class.
    pub class: SourceClass,
    /// Title.
    pub title: String,
    /// Locator.
    pub locator: String,
    /// Content digest.
    pub content_digest: String,
    /// Operation identity.
    pub operation_id: String,
    /// Receipt handle.
    pub receipt_handle: String,
    /// Acquisition outcome.
    pub acquisition: SourceDisposition,
    /// Publication time.
    pub published_ms: Option<i64>,
    /// Observation time.
    pub observed_ms: Option<i64>,
    /// Retrieval time.
    pub retrieved_ms: Option<i64>,
    /// Freshness boundary.
    pub freshness_boundary_ms: Option<i64>,
    /// Raw lineage.
    pub transformed_from: Option<String>,
    /// Transform verification.
    pub transform_verified: bool,
    /// Grade rank.
    pub grade: Option<u8>,
    /// Authority domains.
    pub authority_domains: BTreeSet<String>,
    /// Lineage root.
    pub lineage_root: Option<String>,
    /// Disclosure class.
    pub disclosure: DisclosureClass,
    /// Content flags.
    pub content_flags: BTreeSet<String>,
    /// Incentives note.
    pub incentives_note: String,
    /// Deception risk.
    pub deception_risk: RiskState,
    /// Allowed use.
    pub allowed_use: String,
    /// Allowed effects.
    pub allowed_effects: String,
    /// Verifier.
    pub verifier: String,
    /// Quarantine reason.
    pub quarantine: Option<String>,
    /// Counterevidence targets.
    pub counterevidence_of: BTreeSet<String>,
    /// Citation edges.
    pub cites: Vec<String>,
    /// Evidence spans.
    pub evidence_spans: Vec<EvidenceSpan>,
    /// Data role.
    pub data_role: String,
}

impl SourceRecord {
    /// Vets and freezes one source record. Summaries stay transformation
    /// artifacts: a derived record without verified raw lineage keeps its
    /// transform cap downstream instead of failing here.
    #[allow(clippy::too_many_lines)]
    pub fn new(mut params: SourceRecordParams) -> Result<Self, PortfolioError> {
        text(&params.handle, "source.handle")?;
        text(&params.title, "source.title")?;
        text(&params.locator, "source.locator")?;
        digest(&params.content_digest, "source.content_digest")?;
        text(&params.operation_id, "source.operation_id")?;
        text(&params.receipt_handle, "source.receipt_handle")?;
        if let Some(published) = params.published_ms
            && let Some(observed) = params.observed_ms
            && observed < published
        {
            return Err(PortfolioError::Conflict {
                field: "source.observed_ms",
            });
        }
        if let Some(observed) = params.observed_ms
            && let Some(retrieved) = params.retrieved_ms
            && retrieved < observed
        {
            return Err(PortfolioError::Conflict {
                field: "source.retrieved_ms",
            });
        }
        if let Some(raw) = &params.transformed_from {
            text(raw, "source.transformed_from")?;
            if raw == &params.handle {
                return Err(PortfolioError::CircularCitation {
                    field: "source.transformed_from",
                });
            }
        }
        if let Some(grade) = params.grade {
            grade_name(grade)?;
        }
        if params.authority_domains.is_empty() {
            return Err(PortfolioError::Blank {
                field: "source.authority_domains",
            });
        }
        for domain in &params.authority_domains {
            text(domain, "source.authority_domains")?;
        }
        if let Some(root) = &params.lineage_root {
            text(root, "source.lineage_root")?;
        }
        for flag in &params.content_flags {
            text(flag, "source.content_flags")?;
        }
        text(&params.incentives_note, "source.incentives_note")?;
        text(&params.allowed_use, "source.allowed_use")?;
        text(&params.allowed_effects, "source.allowed_effects")?;
        text(&params.verifier, "source.verifier")?;
        match (&params.quarantine, params.deception_risk) {
            (Some(reason), RiskState::High) => text(reason, "source.quarantine")?,
            (Some(_), _) => {
                return Err(PortfolioError::Conflict {
                    field: "source.quarantine",
                });
            }
            (None, RiskState::High) => {
                return Err(PortfolioError::Blank {
                    field: "source.quarantine",
                });
            }
            (None, _) => {}
        }
        for claim in &params.counterevidence_of {
            text(claim, "source.counterevidence_of")?;
        }
        {
            let mut seen = BTreeSet::new();
            for edge in &params.cites {
                text(edge, "source.cites")?;
                if edge == &params.handle {
                    return Err(PortfolioError::CircularCitation {
                        field: "source.cites",
                    });
                }
                if !seen.insert(edge) {
                    return Err(PortfolioError::Duplicate {
                        field: "source.cites",
                    });
                }
            }
        }
        for span in &params.evidence_spans {
            text(&span.span_id, "source.span_id")?;
            text(&span.anchor, "source.anchor")?;
            digest(&span.excerpt_digest, "source.excerpt_digest")?;
        }
        text(&params.data_role, "source.data_role")?;
        // The two caller-ordered collections are frozen into canonical order
        // here rather than only inside the encoder, so a constructor-built record
        // and its digest agree about what "the same record" means: two records
        // listing the same citation edges or the same evidence spans in a
        // different order are now equal *and* hash equally, instead of comparing
        // unequal while sharing one identity.
        //
        // This is an invariant of the constructor, not of the type: every field is
        // `pub` and the struct is not `#[non_exhaustive]`, so a direct struct
        // literal can still carry an arbitrary order. Such a record is not
        // rejected — it simply hashes to its own distinct identity, and
        // `AuthorizedManifest::binds_source_record` still catches it against the
        // commitment a manifest froze. The claim being made here is the narrow
        // one: `new` normalises, and only `new` is claimed to.
        params.cites.sort();
        params.evidence_spans.sort_by(EvidenceSpan::canonical_order);
        Ok(Self {
            handle: params.handle,
            class: params.class,
            title: params.title,
            locator: params.locator,
            content_digest: params.content_digest,
            operation_id: params.operation_id,
            receipt_handle: params.receipt_handle,
            acquisition: params.acquisition,
            published_ms: params.published_ms,
            observed_ms: params.observed_ms,
            retrieved_ms: params.retrieved_ms,
            freshness_boundary_ms: params.freshness_boundary_ms,
            transformed_from: params.transformed_from,
            transform_verified: params.transform_verified,
            grade: params.grade,
            authority_domains: params.authority_domains,
            lineage_root: params.lineage_root,
            disclosure: params.disclosure,
            content_flags: params.content_flags,
            incentives_note: params.incentives_note,
            deception_risk: params.deception_risk,
            allowed_use: params.allowed_use,
            allowed_effects: params.allowed_effects,
            verifier: params.verifier,
            quarantine: params.quarantine,
            counterevidence_of: params.counterevidence_of,
            cites: params.cites,
            evidence_spans: params.evidence_spans,
            data_role: params.data_role,
        })
    }

    /// Whether this record is stale at `now_ms`: retrieval past the frozen
    /// freshness boundary. A record without a boundary never goes stale by
    /// itself; staleness stays explicit.
    pub fn is_stale_at(&self, now_ms: i64) -> bool {
        match (self.retrieved_ms, self.freshness_boundary_ms) {
            (Some(retrieved), Some(boundary)) => retrieved > boundary || now_ms > boundary,
            _ => self.acquisition == SourceDisposition::Stale,
        }
    }

    /// Whether this record is competent in `domain`.
    pub fn covers_domain(&self, domain: &str) -> bool {
        self.authority_domains.iter().any(|d| d == domain)
    }

    /// Whether this record is competent outside `domain`.
    ///
    /// The negation [`Self::covers_domain`] leaves unnamed, because a caller that
    /// needs the negative test should not have to negate the positive one itself
    /// and risk inverting it at a call site.
    pub fn outside_domain(&self, domain: &str) -> bool {
        !self.covers_domain(domain)
    }

    /// Whether this record carries `span` among its own admitted evidence spans.
    ///
    /// Exact on all three span fields, so a relation cannot quote an excerpt
    /// digest the record does not hold and call it admitted. A record with no
    /// spans admits none, which is the fail-closed answer.
    pub fn binds_span(&self, span: &EvidenceSpan) -> bool {
        self.evidence_spans.iter().any(|held| {
            held.span_id == span.span_id
                && held.anchor == span.anchor
                && held.excerpt_digest == span.excerpt_digest
        })
    }

    /// Deterministic canonical bytes of the whole vetted record.
    ///
    /// This is the one encoder for the declared
    /// [`SOURCE_RECORD_DIGEST_DOMAIN`], and [`Self::digest`] is its only
    /// caller. Object keys are sorted recursively and the domain string is
    /// bound into the bytes, so the same record always produces the same bytes
    /// with no clock, address or map-ordering input.
    ///
    /// The previous encoder was a hand-written field list that named ten of the
    /// record's twenty-nine fields. Anything it did not name was invisible to
    /// the identity, which is the defect this method replaces: the field set is
    /// now the struct's field set, so a field cannot be added to the record and
    /// forgotten here.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&SourceRecordDigestInput {
            domain: SOURCE_RECORD_DIGEST_DOMAIN,
            record: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "source.canonical_body",
        })
    }

    /// Canonical digest of this vetted record.
    ///
    /// Refused rather than defaulted when the record cannot be encoded: a digest
    /// computed over a silently shortened field set would be worse than no
    /// digest, because it would look like provenance.
    pub fn digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with a frozen one.
    ///
    /// This is the readback check the constructor cannot perform. A record
    /// substituted after the freeze still validates as itself — every field it
    /// carries is well-formed — and only a recomputation over the bytes actually
    /// present can say that it is no longer the record that was frozen.
    pub fn verify_identity(&self, frozen_digest: &str) -> Result<(), PortfolioError> {
        if self.digest()? != frozen_digest {
            return Err(PortfolioError::InvalidDigest {
                field: "source.record_digest",
            });
        }
        Ok(())
    }
}

/// Declared identity domain of [`SourceRecord`].
///
/// Bumped `v1` -> `v2` with the complete field set. The `v1` preimage was a
/// length-prefixed string over ten named fields, so a record that changed its
/// freshness boundary, transform verification, allowed use or effects, verifier,
/// quarantine, counterevidence relation, citation edges, excerpt spans or data
/// role hashed identically to its predecessor. The bytes and the field set both
/// changed, so the domain says so instead of letting one name cover two
/// incompatible field sets.
pub const SOURCE_RECORD_DIGEST_DOMAIN: &str = "source-record/v2";

/// The single canonical encoder input for [`SourceRecord`].
///
/// The record is borrowed whole rather than field-by-field: the omission this
/// replaces happened because a hand-written list and a struct can drift apart,
/// and nothing in the compiler objects when they do.
#[derive(Serialize)]
struct SourceRecordDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole vetted record.
    record: &'a SourceRecord,
}

/// One expected source-role slot of the frozen denominator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoleSlot {
    /// Role name admitted by the denominator.
    pub role: String,
    /// Required source class for the role.
    pub class: SourceClass,
    /// How many independent sources the role requires.
    pub required: u64,
    /// Authority domain the role must be competent in.
    pub authority_domain: String,
}

/// Finite budget caps bound into the immutable inquiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BudgetCaps {
    /// Maximum acquisition attempts.
    pub attempts: u64,
    /// Maximum sources.
    pub sources: u64,
    /// Maximum bytes.
    pub bytes: u64,
    /// Maximum search-time units.
    pub stu: u64,
    /// Maximum output units.
    pub output: u64,
    /// Maximum cost units.
    pub cost: u64,
    /// Maximum work units.
    pub work: u64,
    /// Deadline in Unix milliseconds.
    pub deadline_ms: i64,
}

/// An immutable inquiry: schema, protocol, policy, exact question, objective,
/// output contract, requester/task/attempt/scope/fence binding, privacy and
/// disclosure, the finite expected source-role portfolio, authority,
/// independence, freshness and grade requirements, admitted route capability
/// references, independent budgets, stop and partial policy, and the
/// operation/replay identity with its frozen digest.
///
/// Every field participates in [`Self::digest`], and the digest is the only one
/// excluded from its own preimage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrozenInquiry {
    /// Schema identity the inquiry is bound to.
    pub schema: String,
    /// Protocol profile identity (I21.3 selection, frozen).
    pub protocol: String,
    /// Admitting policy identity.
    pub policy: String,
    /// Exact question under inquiry.
    pub question: String,
    /// Objective the answer must serve.
    pub objective: String,
    /// Output contract identity.
    pub output_contract: String,
    /// Requester principal.
    pub requester: String,
    /// Task binding.
    pub task: String,
    /// Attempt identity.
    pub attempt: String,
    /// Inquiry scope (exact; vague spellings rejected).
    pub scope: String,
    /// State fence the inquiry was frozen under.
    pub fence: StateFence,
    /// Privacy class note.
    pub privacy: String,
    /// Disclosure class carried end to end.
    pub disclosure: DisclosureClass,
    /// Expected source-role portfolio in frozen order.
    pub roles: Vec<RoleSlot>,
    /// Admitted route capability references in frozen order.
    pub routes: Vec<String>,
    /// Independent budget caps.
    pub budgets: BudgetCaps,
    /// Stop rule identity.
    pub stop_rule: String,
    /// Partial-result policy identity.
    pub partial_policy: String,
    /// Operation identity of this inquiry.
    pub operation_id: String,
    /// Replay identity of this inquiry.
    pub replay_id: String,
    /// Frozen digest over the whole inquiry shape.
    ///
    /// Excluded from its own preimage by `#[serde(skip)]`, so the digest is the
    /// only field on this struct that is not part of the identity it certifies.
    #[serde(skip)]
    pub digest: String,
}

/// Declared identity domain of [`FrozenInquiry`].
///
/// Bumped `v1` -> `v2` when the State Fence was added to the preimage, and
/// `v2` -> `v3` here for a different reason: the `v2` preimage spelled all five
/// fence components with `{:?}`. Rust `Debug` is a diagnostic rendering, not a
/// versioned wire form — it is not covered by any compatibility promise, it can
/// change with a type wrapper or a derive, and `task_revision`, `policy_revision`
/// and `integration_revision` are three distinct types that were each rendered
/// independently. The fence is now serialized as the typed value it is, through
/// the same canonical serializer as the rest of the inquiry.
///
/// # What this does and does not buy
///
/// It removes the `Debug` dependency, which was unversioned and undocumented. It
/// does **not** make these bytes independent of the fence's field set: the
/// encoder is now bound to `StateFence`'s serde shape in `eliot-contracts`, so a
/// field added there changes `frozen-inquiry/v3` bytes with no bump on this side
/// and nothing here would detect it. That residual is real and is why the field
/// set is a declared contract rather than an implementation detail — but it is a
/// weaker guarantee than a versioned wire form, and this constant's name should
/// not be read as claiming otherwise.
pub const FROZEN_INQUIRY_DIGEST_DOMAIN: &str = "frozen-inquiry/v3";

/// Named constructor arguments for [`FrozenInquiry::freeze`].
#[derive(Clone, Debug)]
pub struct FrozenInquiryParams {
    /// Schema identity.
    pub schema: String,
    /// Protocol identity.
    pub protocol: String,
    /// Policy identity.
    pub policy: String,
    /// Question.
    pub question: String,
    /// Objective.
    pub objective: String,
    /// Output contract.
    pub output_contract: String,
    /// Requester.
    pub requester: String,
    /// Task binding.
    pub task: String,
    /// Attempt identity.
    pub attempt: String,
    /// Scope.
    pub scope: String,
    /// State fence.
    pub fence: StateFence,
    /// Privacy note.
    pub privacy: String,
    /// Disclosure class.
    pub disclosure: DisclosureClass,
    /// Role slots.
    pub roles: Vec<RoleSlot>,
    /// Route capabilities.
    pub routes: Vec<String>,
    /// Budget caps.
    pub budgets: BudgetCaps,
    /// Stop rule.
    pub stop_rule: String,
    /// Partial policy.
    pub partial_policy: String,
    /// Operation identity.
    pub operation_id: String,
    /// Replay identity.
    pub replay_id: String,
}

impl FrozenInquiry {
    /// Validates and freezes one inquiry. Role slots are frozen sorted by
    /// role so declaration order never affects the digest.
    #[allow(clippy::too_many_lines)]
    pub fn freeze(mut params: FrozenInquiryParams) -> Result<Self, PortfolioError> {
        text(&params.schema, "inquiry.schema")?;
        text(&params.protocol, "inquiry.protocol")?;
        text(&params.policy, "inquiry.policy")?;
        text(&params.question, "inquiry.question")?;
        text(&params.objective, "inquiry.objective")?;
        text(&params.output_contract, "inquiry.output_contract")?;
        text(&params.requester, "inquiry.requester")?;
        text(&params.task, "inquiry.task")?;
        text(&params.attempt, "inquiry.attempt")?;
        text(&params.scope, "inquiry.scope")?;
        reject_vague(&params.scope, "inquiry.scope")?;
        params.fence.validate().map_err(|_| PortfolioError::Blank {
            field: "inquiry.fence",
        })?;
        text(&params.privacy, "inquiry.privacy")?;
        if params.roles.is_empty() {
            return Err(PortfolioError::Blank {
                field: "inquiry.roles",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for slot in &params.roles {
                text(&slot.role, "inquiry.role")?;
                text(&slot.authority_domain, "inquiry.authority_domain")?;
                if slot.required == 0 {
                    return Err(PortfolioError::Blank {
                        field: "inquiry.required",
                    });
                }
                if !seen.insert(slot.role.clone()) {
                    return Err(PortfolioError::Duplicate {
                        field: "inquiry.role",
                    });
                }
            }
        }
        if params.routes.is_empty() {
            return Err(PortfolioError::Blank {
                field: "inquiry.routes",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for route in &params.routes {
                text(route, "inquiry.routes")?;
                if !seen.insert(route) {
                    return Err(PortfolioError::Duplicate {
                        field: "inquiry.routes",
                    });
                }
            }
        }
        for (value, field) in [
            (params.budgets.attempts, "inquiry.budgets.attempts"),
            (params.budgets.sources, "inquiry.budgets.sources"),
            (params.budgets.bytes, "inquiry.budgets.bytes"),
            (params.budgets.stu, "inquiry.budgets.stu"),
            (params.budgets.output, "inquiry.budgets.output"),
            (params.budgets.cost, "inquiry.budgets.cost"),
            (params.budgets.work, "inquiry.budgets.work"),
        ] {
            if value == 0 {
                return Err(PortfolioError::Blank { field });
            }
        }
        if params.budgets.deadline_ms <= 0 {
            return Err(PortfolioError::Blank {
                field: "inquiry.budgets.deadline_ms",
            });
        }
        text(&params.stop_rule, "inquiry.stop_rule")?;
        text(&params.partial_policy, "inquiry.partial_policy")?;
        text(&params.operation_id, "inquiry.operation_id")?;
        text(&params.replay_id, "inquiry.replay_id")?;
        params.roles.sort_by(|a, b| a.role.cmp(&b.role));
        params.routes.sort();
        let mut inquiry = Self {
            schema: params.schema,
            protocol: params.protocol,
            policy: params.policy,
            question: params.question,
            objective: params.objective,
            output_contract: params.output_contract,
            requester: params.requester,
            task: params.task,
            attempt: params.attempt,
            scope: params.scope,
            fence: params.fence,
            privacy: params.privacy,
            disclosure: params.disclosure,
            roles: params.roles,
            routes: params.routes,
            budgets: params.budgets,
            stop_rule: params.stop_rule,
            partial_policy: params.partial_policy,
            operation_id: params.operation_id,
            replay_id: params.replay_id,
            digest: String::new(),
        };
        inquiry.digest = inquiry.canonical_digest()?;
        Ok(inquiry)
    }

    /// Deterministic canonical bytes of the whole frozen inquiry, with the
    /// stored digest excluded.
    ///
    /// The State Fence is serialized as the typed value it is, through the same
    /// canonical serializer as every other field, so its five components are
    /// bound by their own contract spellings rather than by whatever `Debug`
    /// happened to print. The digest and the bytes come from this one encoder, so
    /// a stored inquiry can be re-read and re-hashed without reconstructing a
    /// preimage by hand.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&FrozenInquiryDigestInput {
            domain: FROZEN_INQUIRY_DIGEST_DOMAIN,
            inquiry: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "inquiry.canonical_body",
        })
    }

    /// Canonical digest recomputed from this value's own fields.
    pub fn canonical_digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with the frozen one.
    ///
    /// A reloaded inquiry is only the same inquiry if its bytes still hash to
    /// the digest recorded beside them. The fence is inside those bytes, so a
    /// fence rewritten after the freeze is detected here rather than being
    /// accepted as the fence the inquiry was frozen under.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.canonical_digest()? != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "inquiry.digest",
            });
        }
        Ok(())
    }

    /// Exact denominator members: one `role#index` position per required
    /// source. Order carries no meaning; identity is exact.
    pub fn denominator_members(&self) -> BTreeSet<String> {
        let mut members = BTreeSet::new();
        for slot in &self.roles {
            for index in 0..slot.required {
                members.insert(format!("{}#{index}", slot.role));
            }
        }
        members
    }

    /// Number of expected denominator positions.
    pub fn denominator_size(&self) -> usize {
        self.denominator_members().len()
    }

    /// Canonical digest of the exact source-role denominator.
    pub fn denominator_digest(&self) -> String {
        let mut preimage = String::from("denominator/v1;");
        push_field(&mut preimage, "inquiry", &self.digest);
        let members = self.denominator_members();
        push_count(&mut preimage, "members", members.len());
        for member in &members {
            push_field(&mut preimage, "member", member);
        }
        freeze(&preimage)
    }
}

/// The single canonical encoder input for [`FrozenInquiry`].
///
/// The inquiry is borrowed whole; its `digest` field is excluded by
/// `#[serde(skip)]` on the field itself, so the exclusion is declared next to
/// the field it excludes rather than reconstructed at each call site.
#[derive(Serialize)]
struct FrozenInquiryDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole frozen inquiry, minus its own digest.
    inquiry: &'a FrozenInquiry,
}

/// One provider-neutral acquisition request prepared through the existing
/// exchange vocabulary. Carries stable per-attempt operation, source-role,
/// route and deadline identity. No executable path, no credentials, no shell,
/// no network handle and no local provider selection: concrete dispatch
/// remains outside this unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquisitionRequest {
    /// Stable operation identity derived from the frozen inquiry.
    pub operation_id: String,
    /// Stable idempotency key derived from the frozen inquiry.
    pub idempotency_key: String,
    /// Expected denominator member this request fills.
    pub member: String,
    /// Source role this request fills.
    pub source_role: String,
    /// Admitted route capability reference (round-robin assignment, never a
    /// provider selection).
    pub route: String,
    /// Deadline in Unix milliseconds inherited from the inquiry budgets.
    pub deadline_ms: i64,
    /// Digest of the frozen inquiry this request was prepared from.
    pub inquiry_digest: String,
}

/// Prepares finite provider-neutral acquisition requests for every expected
/// denominator member. Deterministic: the same frozen inquiry always yields
/// the same requests in the same order.
pub fn plan_acquisition(inquiry: &FrozenInquiry) -> Vec<AcquisitionRequest> {
    let mut requests = Vec::new();
    for (route_cursor, member) in inquiry.denominator_members().into_iter().enumerate() {
        let role = member.split('#').next().unwrap_or(&member).to_owned();
        let route = inquiry
            .routes
            .get(route_cursor % inquiry.routes.len())
            .cloned()
            .unwrap_or_default();
        let mut op_preimage = String::from("acquisition-op/v1;");
        push_field(&mut op_preimage, "inquiry", &inquiry.digest);
        push_field(&mut op_preimage, "member", &member);
        push_field(&mut op_preimage, "route", &route);
        push_field(
            &mut op_preimage,
            "deadline_ms",
            &inquiry.budgets.deadline_ms.to_string(),
        );
        let operation_id = freeze(&op_preimage);
        let mut key_preimage = String::from("acquisition-key/v1;");
        push_field(&mut key_preimage, "op", &operation_id);
        push_field(&mut key_preimage, "attempt", &inquiry.attempt);
        requests.push(AcquisitionRequest {
            operation_id,
            idempotency_key: freeze(&key_preimage),
            member,
            source_role: role,
            route,
            deadline_ms: inquiry.budgets.deadline_ms,
            inquiry_digest: inquiry.digest.clone(),
        });
    }
    requests
}

/// Exact common-lineage table over ingested handles. Derived copies group
/// under their root; `None` preserves unknown independence and is never
/// merged with anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineageTable {
    entries: BTreeMap<String, Option<String>>,
}

impl LineageTable {
    /// Builds the table from vetted records.
    pub fn build(records: &BTreeMap<String, SourceRecord>) -> Self {
        let mut table = Self::default();
        for (handle, record) in records {
            table
                .entries
                .insert(handle.clone(), record.lineage_root.clone());
        }
        table
    }

    /// Counts distinct known lineage roots among `handles` and separately the
    /// handles with unknown independence. Unknown handles stay preserved and
    /// never inflate the independent count.
    pub fn independent_support(&self, handles: &[String]) -> (usize, usize) {
        let mut roots = BTreeSet::new();
        let mut unknown = 0usize;
        for handle in handles {
            match self.entries.get(handle) {
                Some(Some(root)) => {
                    roots.insert(root.clone());
                }
                _ => unknown += 1,
            }
        }
        (roots.len(), unknown)
    }
}

/// Traversal mark for citation-cycle detection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TraversalMark {
    Visiting,
    Done,
}

/// Validates the source-level citation graph: derived copies group under
/// exact roots, circular citations fail, and edges to unrecorded handles fail
/// as unresolved roots instead of being assumed.
pub fn check_citation_graph(
    records: &BTreeMap<String, SourceRecord>,
) -> Result<(), PortfolioError> {
    for (handle, record) in records {
        for edge in &record.cites {
            if !records.contains_key(edge) {
                return Err(PortfolioError::UnresolvedRoot {
                    field: "source.cites",
                });
            }
            if edge == handle {
                return Err(PortfolioError::CircularCitation {
                    field: "source.cites",
                });
            }
        }
    }
    let mut marks: BTreeMap<&str, TraversalMark> = BTreeMap::new();
    for handle in records.keys() {
        let mut stack: Vec<(&str, bool)> = vec![(handle.as_str(), false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                marks.insert(node, TraversalMark::Done);
                continue;
            }
            match marks.get(node) {
                Some(TraversalMark::Done) => continue,
                Some(TraversalMark::Visiting) => {
                    return Err(PortfolioError::CircularCitation {
                        field: "source.cites",
                    });
                }
                None => {}
            }
            marks.insert(node, TraversalMark::Visiting);
            stack.push((node, true));
            if let Some(record) = records.get(node) {
                for edge in &record.cites {
                    match marks.get(edge.as_str()) {
                        Some(TraversalMark::Done) => {}
                        Some(TraversalMark::Visiting) => {
                            return Err(PortfolioError::CircularCitation {
                                field: "source.cites",
                            });
                        }
                        None => stack.push((edge.as_str(), false)),
                    }
                }
            }
        }
    }
    Ok(())
}

/// Weakest-link grade decision over the cited supporting sources, with every
/// limiting source and condition explained. Repetition and confidence notes
/// are not inputs and can never raise the result: the ceiling is the minimum
/// of the applicable source ranks after domain and staleness caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GradeDecision {
    /// Resulting ceiling rank, or `None` when unknown poisons the ceiling or
    /// no supporting source applies.
    pub ceiling: Option<u8>,
    /// Every limiting source/condition, sorted for stability.
    pub limits: Vec<String>,
}

/// Decides the grade ceiling for one claim domain over cited supporting
/// records at `now_ms`. Sources outside the claim authority domain are
/// excluded with an explanation; stale records cap at `ORIENTING`, partial
/// records cap one rank below their own grade, and unverified transformations
/// cap at `GROUNDED`. Unknown grades poison the ceiling to unknown.
pub fn decide_grade(records: &[&SourceRecord], claim_domain: &str, now_ms: i64) -> GradeDecision {
    if records.is_empty() {
        return GradeDecision {
            ceiling: None,
            limits: vec!["grade: empty evidence set".to_owned()],
        };
    }
    let mut ranks: Vec<Option<u8>> = Vec::new();
    let mut limits: Vec<String> = Vec::new();
    for record in records {
        if !record.covers_domain(claim_domain) {
            limits.push(format!(
                "grade: source {} outside domain {claim_domain}",
                record.handle
            ));
            continue;
        }
        if !record.acquisition.may_support() {
            limits.push(format!(
                "grade: source {} disposition {} carries no weight",
                record.handle,
                record.acquisition.wire_name()
            ));
            continue;
        }
        let Some(own) = record.grade else {
            ranks.push(None);
            limits.push(format!("grade: source {} grade unknown", record.handle));
            continue;
        };
        let mut capped = own;
        if record.is_stale_at(now_ms) {
            capped = 0;
            limits.push(format!(
                "grade: source {} stale caps ORIENTING",
                record.handle
            ));
        }
        if record.acquisition == SourceDisposition::Partial {
            capped = capped.saturating_sub(1);
            limits.push(format!(
                "grade: source {} partial caps one rank below",
                record.handle
            ));
        }
        if record.transformed_from.is_some() && !record.transform_verified {
            capped = capped.min(1);
            limits.push(format!(
                "grade: source {} unverified transform caps GROUNDED",
                record.handle
            ));
        }
        ranks.push(Some(capped));
    }
    if ranks.is_empty() {
        return GradeDecision {
            ceiling: None,
            limits: {
                limits.sort();
                limits
            },
        };
    }
    let ceiling = weakest_ceiling(&ranks).unwrap_or_default();
    if ceiling.is_none() && !limits.iter().any(|l| l.contains("unknown")) {
        limits.push("grade: unknown poisons ceiling".to_owned());
    }
    limits.sort();
    GradeDecision { ceiling, limits }
}

/// One observed candidate the frozen denominator never declared.
///
/// I21.1: a provider result that was never admitted stays visibly outside the
/// frozen scope. The observation keeps its real [`SourceDisposition`], its exact
/// content digest and the admitted operation that produced it, it closes no
/// declared member, and it never becomes part of the declared population. The
/// denominator is never widened to fit an observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedOutsideScope {
    /// Observed source handle, exactly as the acquisition route reported it.
    pub handle: String,
    /// What the acquisition route actually observed.
    pub disposition: SourceDisposition,
    /// Exact digest of the observed content bytes.
    pub content_digest: String,
    /// Admitted operation identity that produced the observation.
    pub operation_id: String,
    /// Digest of the admitted reference manifest the observation fell outside
    /// of.
    pub admitted_manifest_digest: String,
}

impl ObservedOutsideScope {
    /// Closed reason code an observation in this set carries. It is the only
    /// reason the set can hold: an observation is retained here exactly because
    /// the frozen denominator never declared it, and the code is digested so a
    /// reader never has to infer the reason from the schema.
    pub const REASON: &'static str = "observed_outside_frozen_scope";
}

/// Exact coverage accounting over the frozen denominator: every expected
/// member carries exactly one visible disposition, an explicit exclusion, or
/// a budget-frontier note, and every candidate the run actually observed is
/// either bound to one of those members or retained as an observation outside
/// the frozen scope. Complete accounting never implies that all evidence
/// succeeded, and the two populations stay separately visible in every digest
/// so a verified empty scope never reads as an enumeration that never ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageAccount {
    expected: BTreeSet<String>,
    outcomes: BTreeMap<String, (SourceDisposition, Option<String>)>,
    exclusions: BTreeMap<String, String>,
    frontier: Option<String>,
    observed: BTreeMap<String, ObservedOutsideScope>,
}

impl CoverageAccount {
    /// Opens accounting over the exact expected denominator members.
    pub fn open(expected: BTreeSet<String>) -> Result<Self, PortfolioError> {
        if expected.is_empty() {
            return Err(PortfolioError::IncompleteDenominator {
                field: "coverage.expected",
            });
        }
        Ok(Self {
            expected,
            outcomes: BTreeMap::new(),
            exclusions: BTreeMap::new(),
            frontier: None,
            observed: BTreeMap::new(),
        })
    }

    /// Records one disposition for one expected member, with the acquiring
    /// source handle when one exists. A repeated delivery of the identical
    /// member/disposition/handle binding is idempotent; any changed binding
    /// conflicts rather than disappearing behind the same disposition.
    pub fn record(
        &mut self,
        member: &str,
        disposition: SourceDisposition,
        handle: Option<String>,
    ) -> Result<(), PortfolioError> {
        if !self.expected.contains(member) {
            return Err(PortfolioError::UnknownHandle {
                field: "coverage.member",
            });
        }
        if let Some(handle) = &handle {
            text(handle, "coverage.handle")?;
        }
        if self.exclusions.contains_key(member) {
            return Err(PortfolioError::Conflict {
                field: "coverage.member",
            });
        }
        match self.outcomes.get(member) {
            Some((current, current_handle))
                if *current == disposition && *current_handle == handle =>
            {
                Ok(())
            }
            Some(_) => Err(PortfolioError::Conflict {
                field: "coverage.member",
            }),
            None => {
                self.outcomes
                    .insert(member.to_owned(), (disposition, handle));
                Ok(())
            }
        }
    }

    /// Records one observed candidate against the accounting.
    ///
    /// A handle the frozen denominator declared is recorded as that member's
    /// disposition. A handle the denominator never declared is retained as an
    /// [`ObservedOutsideScope`] observation: it keeps its real disposition,
    /// content digest and admitted operation, closes no member, and stays
    /// outside the declared population. A repeated delivery of the identical
    /// binding is idempotent; a changed disposition, content digest or admitted
    /// operation under an already-retained handle conflicts instead of
    /// overwriting the earlier observation.
    pub fn observe(
        &mut self,
        handle: &str,
        disposition: SourceDisposition,
        content_digest: &str,
        operation_id: &str,
        admitted_manifest_digest: &str,
    ) -> Result<(), PortfolioError> {
        text(handle, "coverage.handle")?;
        digest(content_digest, "coverage.content_digest")?;
        text(operation_id, "coverage.operation_id")?;
        digest(
            admitted_manifest_digest,
            "coverage.admitted_manifest_digest",
        )?;
        if self.expected.contains(handle) {
            return self.record(handle, disposition, Some(handle.to_owned()));
        }
        let observation = ObservedOutsideScope {
            handle: handle.to_owned(),
            disposition,
            content_digest: content_digest.to_owned(),
            operation_id: operation_id.to_owned(),
            admitted_manifest_digest: admitted_manifest_digest.to_owned(),
        };
        match self.observed.get(handle) {
            Some(current) if *current == observation => Ok(()),
            Some(_) => Err(PortfolioError::Conflict {
                field: "coverage.observed_handle",
            }),
            None => {
                self.observed.insert(handle.to_owned(), observation);
                Ok(())
            }
        }
    }

    /// Every observed candidate the frozen denominator never declared, in
    /// canonical handle order. These close no declared member and narrow no
    /// denominator: they are retained so an empty eligible scope stays
    /// distinguishable from an enumeration that never ran.
    #[must_use]
    pub fn observed_outside_scope(&self) -> Vec<ObservedOutsideScope> {
        self.observed.values().cloned().collect()
    }

    /// Excludes one member under an explicit permitted reason.
    pub fn exclude(&mut self, member: &str, reason: &str) -> Result<(), PortfolioError> {
        if !self.expected.contains(member) {
            return Err(PortfolioError::UnknownHandle {
                field: "coverage.member",
            });
        }
        if self.outcomes.contains_key(member) {
            return Err(PortfolioError::Conflict {
                field: "coverage.member",
            });
        }
        text(reason, "coverage.exclusion_reason")?;
        self.exclusions.insert(member.to_owned(), reason.to_owned());
        Ok(())
    }

    /// Notes the budget frontier where enumeration stopped. A frontier never
    /// decodes as completeness.
    pub fn note_frontier(&mut self, note: &str) -> Result<(), PortfolioError> {
        text(note, "coverage.frontier")?;
        self.frontier = Some(note.to_owned());
        Ok(())
    }

    /// Whether every expected member is accounted with exactly one visible
    /// disposition or an explicit exclusion.
    pub fn is_accounted(&self) -> bool {
        self.expected
            .iter()
            .all(|m| self.outcomes.contains_key(m) || self.exclusions.contains_key(m))
    }

    /// Counts independently covered members: observed members grouped by
    /// exact lineage root, so dependent copies never inflate coverage.
    /// Returns `(independent_roots, unknown_independence_handles)`.
    pub fn independent_coverage(&self, lineage: &LineageTable) -> (usize, usize) {
        let mut handles = Vec::new();
        for (member, (disposition, handle)) in &self.outcomes {
            if *disposition == SourceDisposition::Observed
                && !self.exclusions.contains_key(member)
                && let Some(handle) = handle
            {
                handles.push(handle.clone());
            }
        }
        lineage.independent_support(&handles)
    }

    /// Number of expected denominator members.
    #[must_use]
    pub fn denominator_size(&self) -> usize {
        self.expected.len()
    }

    /// Expected members that carry neither a recorded disposition nor an
    /// explicit exclusion, in canonical order.
    ///
    /// An open member is not an accounted one: the exact accounting is what
    /// keeps "no result" from decoding as completeness, so callers that need
    /// the unclosed remainder (the R6 inquiry boundary) read it here instead
    /// of inferring it.
    #[must_use]
    pub fn open_members(&self) -> Vec<String> {
        self.expected
            .iter()
            .filter(|member| {
                !self.outcomes.contains_key(*member) && !self.exclusions.contains_key(*member)
            })
            .cloned()
            .collect()
    }

    /// Whether every accounted member closed intact. Complete accounting with
    /// failures still reports `false` here: accounting completeness and
    /// evidence success stay distinct.
    pub fn all_closed(&self) -> bool {
        self.is_accounted()
            && self.expected.iter().all(|m| {
                matches!(
                    self.outcomes.get(m),
                    Some((disposition, _)) if disposition.closes_member()
                )
            })
    }

    fn canonical_into(&self, preimage: &mut String) {
        push_count(preimage, "expected", self.expected.len());
        for member in &self.expected {
            push_field(preimage, "expected", member);
        }
        push_count(preimage, "outcomes", self.outcomes.len());
        for (member, (disposition, handle)) in &self.outcomes {
            push_field(preimage, "member", member);
            push_field(preimage, "disposition", disposition.wire_name());
            if let Some(handle) = handle {
                push_field(preimage, "handle", handle);
            }
        }
        push_count(preimage, "observed", self.observed.len());
        for observation in self.observed.values() {
            push_field(preimage, ObservedOutsideScope::REASON, &observation.handle);
            push_field(
                preimage,
                "observed_disposition",
                observation.disposition.wire_name(),
            );
            push_field(
                preimage,
                "observed_content_digest",
                &observation.content_digest,
            );
            push_field(preimage, "observed_operation_id", &observation.operation_id);
            push_field(
                preimage,
                "observed_manifest_digest",
                &observation.admitted_manifest_digest,
            );
        }
        push_count(preimage, "exclusions", self.exclusions.len());
        for (member, reason) in &self.exclusions {
            push_field(preimage, "excluded", member);
            push_field(preimage, "reason", reason);
        }
        if let Some(frontier) = &self.frontier {
            push_field(preimage, "frontier", frontier);
        }
    }

    /// Canonical digest of the frozen accounting shape.
    pub fn digest(&self) -> String {
        let mut preimage = String::from("coverage/v1;");
        self.canonical_into(&mut preimage);
        freeze(&preimage)
    }
}

/// Absence verdict for one scoped negative claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbsenceVerdict {
    /// Proven: complete denominator, full accounting, current sources and a
    /// bounded predicate evaluation over exactly the closed members.
    Proven,
    /// Unproven: a named retained fact leaves the negative open.
    Unproven {
        /// Bounded reason the absence cannot be claimed.
        reason: String,
    },
    /// Partial: bounded exhaustion stopped the lookup before completeness.
    PartialExhaustion {
        /// Frontier note where enumeration stopped.
        frontier: String,
    },
}

/// One owner-bound, identity-bearing record of a bounded predicate evaluation
/// over a named closed population.
///
/// This is neither a verdict nor a flag: it is the identity of the per-member
/// predicate result. It names the predicate that was evaluated, the frozen
/// scope snapshot and index revision the evaluation was bounded to, and the
/// exact members it found no match for. [`assess_absence`] proves absence only
/// when that member set is exactly the set of declared members the accounting
/// closed intact, so an incomplete evaluation cannot be presented as
/// exhaustive and a ranked index can neither add a member to the denominator
/// of a negative nor remove one from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoMatchEvaluation {
    /// Exact identity of the predicate that was evaluated.
    pub predicate_id: String,
    /// Digest of the frozen scope snapshot the evaluation was bounded to.
    pub frozen_scope_digest: String,
    /// Revision of the source/index the evaluation ran against.
    pub index_revision: String,
    /// Members the predicate found no match for. Normalised into canonical
    /// order by [`AbsencePreconditions::derive`] so arrival order never
    /// affects the comparison against the closed denominator.
    pub no_match_members: Vec<String>,
}

/// The owner-bound preconditions one exact negative claim is assessed against.
///
/// Every field is derived from the exact coverage accounting, the vetted source
/// records behind it and the frozen scope snapshot the claim is scoped to, and
/// every field is private: a precondition set can only be produced by
/// [`AbsencePreconditions::derive`] over a real [`CoverageAccount`], never
/// written by a caller. [`assess_absence`] then re-proves the digest before it
/// reads any of the content and re-checks the bound account digest against the
/// account it is handed, so a set that was not derived over that account is
/// refused instead of believed. A caller supplies evidence and never a verdict.
///
/// The record names which precondition is unmet through the bounded reason
/// [`AbsenceVerdict::Unproven`] retains, and its digest binds the preconditions
/// to that exact evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsencePreconditions {
    /// Digest of the frozen scope snapshot the claim is scoped to.
    frozen_scope_digest: String,
    /// Digest of the exact accounting the preconditions were derived over.
    account_digest: String,
    /// Declared members that were never examined at all.
    unexamined: Vec<String>,
    /// Declared members examined with a disposition that did not close them,
    /// paired with that disposition's stable spelling.
    unclosed: Vec<(String, &'static str)>,
    /// Declared members carrying an explicit exclusion. An exclusion is not a
    /// successful search, so an excluded member can never support a negative.
    excluded: Vec<String>,
    /// Closed members whose source or index is no longer current.
    incompatible: Vec<String>,
    /// Declared members the accounting closed intact.
    closed: Vec<String>,
    /// Candidates observed outside the frozen scope. They are counted so an
    /// empty eligible set stays distinguishable from an enumeration that never
    /// ran; they close no member and narrow no denominator.
    observed_outside_scope: usize,
    /// Frontier where a bounded enumeration stopped, when one applied.
    frontier: Option<String>,
    /// The bounded predicate evaluation bound to the requested query, when one
    /// exists. The research plane records acquisition dispositions, not
    /// per-member query predicate results, so an inquiry record binds none and
    /// the negative stays unproven.
    evaluation: Option<NoMatchEvaluation>,
    /// Digest over the preconditions.
    digest: String,
}

impl AbsencePreconditions {
    /// Derives the preconditions of one exact negative claim from the exact
    /// accounting, the vetted records behind it and the frozen snapshot.
    ///
    /// # Errors
    ///
    /// Returns a digest or field error for a malformed frozen-scope digest or a
    /// malformed evaluation binding, and
    /// [`PortfolioError::IncompleteDenominator`] for an evaluation that names
    /// no member, which no closed population produces.
    pub fn derive(
        account: &CoverageAccount,
        records: &BTreeMap<String, SourceRecord>,
        now_ms: i64,
        frozen_scope_digest: &str,
        evaluation: Option<NoMatchEvaluation>,
    ) -> Result<Self, PortfolioError> {
        digest(frozen_scope_digest, "absence.frozen_scope_digest")?;
        let mut unclosed: Vec<(String, &'static str)> = Vec::new();
        let mut closed: Vec<String> = Vec::new();
        let mut incompatible: Vec<String> = Vec::new();
        for (member, (disposition, handle)) in &account.outcomes {
            if disposition.closes_member() {
                closed.push(member.clone());
                let stale = handle.as_ref().is_some_and(|handle| {
                    records
                        .get(handle)
                        .is_some_and(|record| record.is_stale_at(now_ms))
                });
                if stale {
                    incompatible.push(member.clone());
                }
            } else {
                unclosed.push((member.clone(), disposition.wire_name()));
            }
        }
        let evaluation = match evaluation {
            Some(mut evaluation) => {
                text(&evaluation.predicate_id, "absence.predicate_id")?;
                text(&evaluation.index_revision, "absence.index_revision")?;
                digest(
                    &evaluation.frozen_scope_digest,
                    "absence.evaluation_frozen_scope_digest",
                )?;
                if evaluation.no_match_members.is_empty() {
                    return Err(PortfolioError::IncompleteDenominator {
                        field: "absence.no_match_members",
                    });
                }
                for member in &evaluation.no_match_members {
                    text(member, "absence.no_match_member")?;
                }
                evaluation.no_match_members.sort();
                evaluation.no_match_members.dedup();
                Some(evaluation)
            }
            None => None,
        };
        let mut preconditions = Self {
            frozen_scope_digest: frozen_scope_digest.to_owned(),
            account_digest: account.digest(),
            unexamined: account.open_members(),
            unclosed,
            excluded: account.exclusions.keys().cloned().collect(),
            incompatible,
            closed,
            observed_outside_scope: account.observed.len(),
            frontier: account.frontier.clone(),
            evaluation,
            digest: String::new(),
        };
        preconditions.digest = preconditions.compute_digest();
        Ok(preconditions)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("absence-preconditions/v1;");
        push_field(
            &mut preimage,
            "frozen_scope_digest",
            &self.frozen_scope_digest,
        );
        push_field(&mut preimage, "account_digest", &self.account_digest);
        for (tag, members) in [
            ("unexamined", &self.unexamined),
            ("excluded", &self.excluded),
            ("incompatible", &self.incompatible),
            ("closed", &self.closed),
        ] {
            push_count(&mut preimage, tag, members.len());
            for member in members {
                push_field(&mut preimage, tag, member);
            }
        }
        push_count(&mut preimage, "unclosed", self.unclosed.len());
        for (member, disposition) in &self.unclosed {
            push_field(&mut preimage, "unclosed_member", member);
            push_field(&mut preimage, "unclosed_disposition", disposition);
        }
        push_count(
            &mut preimage,
            "observed_outside_scope",
            self.observed_outside_scope,
        );
        if let Some(frontier) = &self.frontier {
            push_field(&mut preimage, "frontier", frontier);
        }
        match &self.evaluation {
            Some(evaluation) => {
                push_field(&mut preimage, "predicate_id", &evaluation.predicate_id);
                push_field(
                    &mut preimage,
                    "evaluation_frozen_scope_digest",
                    &evaluation.frozen_scope_digest,
                );
                push_field(&mut preimage, "index_revision", &evaluation.index_revision);
                push_count(
                    &mut preimage,
                    "no_match_members",
                    evaluation.no_match_members.len(),
                );
                for member in &evaluation.no_match_members {
                    push_field(&mut preimage, "no_match_member", member);
                }
            }
            None => push_field(&mut preimage, "evaluation", "absent"),
        }
        freeze(&preimage)
    }
}

/// Assesses a scoped absence claim over owner-bound preconditions.
///
/// Only a complete denominator, an exact accounting of every declared member,
/// an intact source/index for each closed member, no exclusion and a bounded
/// predicate evaluation over exactly the closed members proves absence. A
/// bounded enumeration that stopped is partial exhaustion. Every rejected claim
/// names the retained fact that rejected it, so no verdict rests on a
/// caller-supplied flag.
///
/// `account` is the accounting the preconditions are claimed to describe. It is
/// required so the preconditions cannot be re-bound to a different accounting
/// than the one they were derived over, and it is the only trusted account the
/// assessment has. A precondition set that does not re-prove its own digest, or
/// whose bound account digest is not this account's, is refused as
/// [`AbsenceVerdict::Unproven`] before any of its content is read: a claim that
/// cannot be re-proved is not proved.
pub fn assess_absence(
    account: &CoverageAccount,
    preconditions: &AbsencePreconditions,
) -> AbsenceVerdict {
    if preconditions.compute_digest() != preconditions.digest {
        return AbsenceVerdict::Unproven {
            reason: "absence: the preconditions do not re-prove their own digest, so this set is \
                     not owner-bound evidence and proves nothing"
                .to_owned(),
        };
    }
    let account_digest = account.digest();
    if preconditions.account_digest != account_digest {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "absence: the preconditions are bound to coverage account {account_digest}, not to \
                 the account presented with them, so the two cannot be swapped"
            ),
        };
    }
    if let Some(frontier) = &preconditions.frontier {
        return AbsenceVerdict::PartialExhaustion {
            frontier: frontier.clone(),
        };
    }
    if !preconditions.unexamined.is_empty() {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "coverage: {} declared denominator member(s) were never examined: {}",
                preconditions.unexamined.len(),
                preconditions.unexamined.join(",")
            ),
        };
    }
    if !preconditions.excluded.is_empty() {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "coverage: an exclusion is not a successful search; {} member(s) were excluded: {}",
                preconditions.excluded.len(),
                preconditions.excluded.join(",")
            ),
        };
    }
    if !preconditions.unclosed.is_empty() {
        let unclosed = preconditions
            .unclosed
            .iter()
            .map(|(member, disposition)| format!("{member}={disposition}"))
            .collect::<Vec<String>>()
            .join(",");
        return AbsenceVerdict::Unproven {
            reason: format!(
                "coverage: {} examined member(s) did not close their denominator slot: {unclosed}",
                preconditions.unclosed.len()
            ),
        };
    }
    if !preconditions.incompatible.is_empty() {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "coverage: {} closed member(s) are no longer current for the frozen snapshot: {}",
                preconditions.incompatible.len(),
                preconditions.incompatible.join(",")
            ),
        };
    }
    let Some(evaluation) = &preconditions.evaluation else {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "absence: no bounded predicate evaluation is bound to the requested query over \
                 frozen scope snapshot {}; accounting {} declared member(s) closed and observing \
                 {} candidate(s) outside that scope does not prove the query has no match",
                preconditions.frozen_scope_digest,
                preconditions.closed.len(),
                preconditions.observed_outside_scope
            ),
        };
    };
    if evaluation.frozen_scope_digest != preconditions.frozen_scope_digest {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "absence: the predicate evaluation is bounded to frozen scope snapshot {}, not to {}",
                evaluation.frozen_scope_digest, preconditions.frozen_scope_digest
            ),
        };
    }
    if evaluation.no_match_members != preconditions.closed {
        return AbsenceVerdict::Unproven {
            reason: format!(
                "absence: the predicate evaluation covers {} member(s) over index revision {}, \
                 not the {} closed member(s) of the frozen denominator",
                evaluation.no_match_members.len(),
                evaluation.index_revision,
                preconditions.closed.len()
            ),
        };
    }
    AbsenceVerdict::Proven
}

/// Structured precision kinds for already-structured claim/reference records.
/// No prose is parsed: assertions arrive structured and are checked against
/// structured support.
///
/// The set is closed: an assertion kind that is not one of these is not a
/// precision this crate can check, and an unchecked kind is never reported as
/// supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecisionKind {
    /// Quantified numeric assertion with unit and denominator.
    Numeric,
    /// Point-in-time assertion in Unix milliseconds.
    Date,
    /// Exact version assertion.
    Version,
    /// Causal mechanism assertion.
    Causal,
    /// Coordinate/anchor assertion: the claimed anchor precision of a citation.
    ///
    /// I21.7: "A source that supports a file-level or document-level claim does
    /// not automatically support a symbol, line, causal mechanism or
    /// population-wide statement." The coordinate form of that rule is this
    /// kind: a citation may not claim an anchor finer than the support it
    /// actually carries.
    Coordinate,
}

/// One structured precision assertion: what a claim asserts and what the
/// supporting evidence actually supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecisionAssertion {
    /// Precision kind under check.
    pub kind: PrecisionKind,
    /// Asserted value in exact form.
    pub asserted: String,
    /// Highest supported value in exact form.
    pub supported: String,
    /// Coverage basis of the support.
    pub basis: String,
}

/// Typed unsupported-precision residue (I21.7): what was asserted, the
/// highest supported precision, the basis, the false-precision risk, and the
/// probe or narrower wording required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedPrecisionItem {
    /// Asserted reference or coordinate.
    pub asserted: String,
    /// Highest supported precision.
    pub highest_supported: String,
    /// Source and coverage basis.
    pub basis: String,
    /// Risk of false precision.
    pub risk: String,
    /// Required probe or narrower wording.
    pub required_probe: String,
}

/// Coordinate/anchor precision rank on the I21.7 ladder, coarsest first.
///
/// The wire spellings are the ones the exchange contract's
/// `AnchorPrecision` uses, and the order is that type's weakest-first order:
/// `source` is the coarsest anchor and `byte_range` the finest. A spelling this
/// function does not know has no rank, and an unknown rank is never treated as
/// coarse enough to admit a fine anchor.
fn coordinate_rank(name: &str) -> Option<u8> {
    match name {
        "source" => Some(0),
        "document" => Some(1),
        "page" => Some(2),
        "section" => Some(3),
        "paragraph" => Some(4),
        "line" => Some(5),
        "byte_range" => Some(6),
        _ => None,
    }
}

fn decimal_scale(value: &str) -> Option<usize> {
    let digits = value.trim();
    let unsigned = digits.strip_prefix('-').unwrap_or(digits);
    if unsigned.chars().all(|c| c.is_ascii_digit()) {
        return Some(0);
    }
    let (head, tail) = unsigned.split_once('.')?;
    if head.chars().all(|c| c.is_ascii_digit())
        && !tail.is_empty()
        && tail.chars().all(|c| c.is_ascii_digit())
    {
        Some(tail.len())
    } else {
        None
    }
}

fn parse_decimal(value: &str) -> Option<i128> {
    let digits = value.trim();
    let negative = digits.starts_with('-');
    let unsigned = digits.strip_prefix('-').unwrap_or(digits);
    let (head, tail) = match unsigned.split_once('.') {
        Some(parts) => parts,
        None => (unsigned, ""),
    };
    if head.chars().any(|c| !c.is_ascii_digit()) || tail.chars().any(|c| !c.is_ascii_digit()) {
        return None;
    }
    let scale = tail.len();
    let mut scaled: i128 = head
        .parse::<i128>()
        .ok()?
        .checked_mul(10i128.checked_pow(u32::try_from(scale).ok()?)?)?;
    if !tail.is_empty() {
        scaled = scaled.checked_add(tail.parse::<i128>().ok()?)?;
    }
    Some(if negative { -scaled } else { scaled })
}

fn check_numeric(asserted: &str, supported: &str) -> bool {
    if let Some((low, high)) = supported.split_once("..") {
        let (Some(low_v), Some(high_v), Some(point_v)) = (
            parse_decimal(low),
            parse_decimal(high),
            parse_decimal(asserted),
        ) else {
            return false;
        };
        let (Some(low_n), Some(high_n), Some(point_n)) = (
            decimal_scale(low),
            decimal_scale(high),
            decimal_scale(asserted),
        ) else {
            return false;
        };
        let target = low_n.max(high_n).max(point_n);
        let rescale = |value: i128, scale: usize| {
            value.checked_mul(10i128.checked_pow(u32::try_from(target - scale).ok()?)?)
        };
        let (Some(low_s), Some(high_s), Some(point_s)) = (
            rescale(low_v, low_n),
            rescale(high_v, high_n),
            rescale(point_v, point_n),
        ) else {
            return false;
        };
        return low_s <= point_s && point_s <= high_s;
    }
    match (decimal_scale(asserted), decimal_scale(supported)) {
        (Some(ask), Some(have)) => {
            if ask > have {
                return false;
            }
            match (parse_decimal(asserted), parse_decimal(supported)) {
                (Some(a), Some(s)) => {
                    let factor = 10i128
                        .checked_pow(u32::try_from(have - ask).ok().unwrap_or(0))
                        .unwrap_or(1);
                    a.checked_mul(factor).unwrap_or(i128::MAX) == s
                }
                _ => asserted == supported,
            }
        }
        _ => asserted == supported,
    }
}

/// Checks one structured precision assertion. Unsupported precision,
/// outside-manifest-style overreach and insufficient coverage remain typed
/// residue; nothing is inferred.
pub fn check_precision(assertion: &PrecisionAssertion) -> Result<(), UnsupportedPrecisionItem> {
    text(&assertion.asserted, "precision.asserted").map_err(|_| UnsupportedPrecisionItem {
        asserted: assertion.asserted.clone(),
        highest_supported: assertion.supported.clone(),
        basis: assertion.basis.clone(),
        risk: "blank assertion carries no precision".to_owned(),
        required_probe: "restate with an exact asserted value".to_owned(),
    })?;
    let supported = match assertion.kind {
        PrecisionKind::Numeric => check_numeric(&assertion.asserted, &assertion.supported),
        PrecisionKind::Date => match (
            assertion.asserted.parse::<i64>(),
            assertion.supported.split_once(".."),
        ) {
            (Ok(instant), Some((low, high))) => match (low.parse::<i64>(), high.parse::<i64>()) {
                (Ok(low), Ok(high)) => low <= instant && instant <= high,
                _ => false,
            },
            _ => false,
        },
        PrecisionKind::Version => assertion.asserted == assertion.supported,
        PrecisionKind::Causal => assertion
            .supported
            .split('|')
            .any(|mechanism| mechanism.trim() == assertion.asserted.trim()),
        PrecisionKind::Coordinate => match (
            coordinate_rank(assertion.asserted.trim()),
            coordinate_rank(assertion.supported.trim()),
        ) {
            // An unrecognised coordinate spelling is never treated as supported:
            // an unknown rank fails closed rather than falling back to equality.
            (Some(asserted_rank), Some(supported_rank)) => asserted_rank <= supported_rank,
            _ => false,
        },
    };
    if supported {
        Ok(())
    } else {
        let (risk, probe) = match assertion.kind {
            PrecisionKind::Numeric => (
                "false quantification beyond measured resolution",
                "narrow to the measured value, interval or resolution",
            ),
            PrecisionKind::Date => (
                "false dating outside the observed window",
                "narrow to an instant inside the observed window",
            ),
            PrecisionKind::Version => (
                "false version pinning without exact evidence",
                "restate at the evidenced version or declare unknown",
            ),
            PrecisionKind::Causal => (
                "false causal mechanism without evidenced mechanism",
                "name only evidenced mechanisms or declare correlation",
            ),
            PrecisionKind::Coordinate => (
                "a citation at an anchor finer than the admitted support would be unbacked text",
                "narrow the anchor to the supported precision or admit a source that supports it",
            ),
        };
        Err(UnsupportedPrecisionItem {
            asserted: assertion.asserted.clone(),
            highest_supported: assertion.supported.clone(),
            basis: assertion.basis.clone(),
            risk: risk.to_owned(),
            required_probe: probe.to_owned(),
        })
    }
}

/// Whether a claim is material to the inquiry decision.
///
/// Typed rather than a bare `bool` so a frozen claim identity cannot carry an
/// unlabelled truth value into an audit: materiality changes which public audit
/// class a verdict may take, and an unlabelled `false` reads as "not material"
/// whether the author meant that or forgot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ClaimMateriality {
    /// The claim is material to the inquiry decision and must be audited.
    Material,
    /// The claim is supporting colour and is not audited as material.
    NonMaterial,
}

impl ClaimMateriality {
    /// Stable wire spelling of this materiality.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Material => "MATERIAL",
            Self::NonMaterial => "NON_MATERIAL",
        }
    }

    /// Whether a claim of this materiality may be audited as material.
    pub const fn is_material(self) -> bool {
        matches!(self, Self::Material)
    }
}

/// What a statement asserts, as distinct from how strongly it asserts it.
///
/// Modality is part of the frozen claim identity because two claims can share a
/// subject, a population and a source while differing only in modality, and a
/// counterevidence relation that refutes a descriptive claim says nothing about
/// a normative one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ClaimModality {
    /// Describes what is the case.
    Descriptive,
    /// Asserts what will be the case.
    Predictive,
    /// Asserts what ought to be the case.
    Normative,
    /// Asserts that one thing causes another.
    Causal,
}

impl ClaimModality {
    /// Stable wire spelling of this modality.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Descriptive => "DESCRIPTIVE",
            Self::Predictive => "PREDICTIVE",
            Self::Normative => "NORMATIVE",
            Self::Causal => "CAUSAL",
        }
    }
}

/// The scope under which one claim or one counterevidence relation is asserted.
///
/// I21.8 requires a claim to be judged under the population, time, definition and
/// denominator it was actually made under. A source about another population is
/// not a weaker contradiction of a claim about this one; it is a statement about
/// something else, and this record is what keeps the two apart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimConditions {
    /// Population or scope the statement is about.
    pub population_scope: String,
    /// Time window and version the statement is about.
    pub time_version: String,
    /// Definition, unit and denominator the statement is measured in.
    pub definition_unit_denominator: String,
    /// Modality the statement asserts in.
    pub modality: ClaimModality,
}

impl ClaimConditions {
    /// Stable wire spelling of this condition set.
    pub fn wire_name(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.population_scope,
            self.time_version,
            self.definition_unit_denominator,
            self.modality.wire_name()
        )
    }
}

/// One already-structured material-claim record for audit. Claims arrive
/// structured; prose is never parsed into claims and entailment is never
/// inferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedClaim {
    /// Claim identity.
    pub claim_id: String,
    /// Exact statement text (data; digest-bound, never executed).
    pub statement: String,
    /// Whether the claim is material to the inquiry decision.
    pub material: bool,
    /// Authority domain the claim is made in.
    pub domain: String,
    /// Cited source handles.
    pub citations: Vec<String>,
    /// Structured precision assertions for this claim.
    pub precision: Vec<PrecisionAssertion>,
    /// Counterclaim identities preserved against this claim.
    ///
    /// These are **alleged** counterclaims and nothing more. A handle listed here
    /// is eligible to be examined; it is never a contradiction, and a caller
    /// cannot promote one by listing it. `Contradicts` is reachable only from a
    /// [`ClaimOppositionRelation`] that the accepted semantic-evaluation owner
    /// established, so this list is preserved rather than believed.
    pub counterclaim_ids: Vec<String>,
    /// Unknown evidence references that must stay explicit.
    pub unknown_refs: Vec<String>,
    /// Frozen claim identities this claim was frozen under.
    ///
    /// Empty means the claim carries no frozen identity, and the audit then
    /// reports every attached counterclaim as unverifiable rather than assuming
    /// opposition. A claim that cannot state what it is cannot have anything
    /// contradict it.
    pub frozen_identities: Vec<FrozenClaimIdentity>,
    /// Owner-issued claim↔counterevidence relations.
    ///
    /// Each is examined on its own evidence. A relation whose evaluator, span or
    /// source commitment does not verify is reported as unverifiable; it does not
    /// fall back to the weaker same-domain test that produced the original
    /// defect.
    pub opposition_relations: Vec<ClaimOppositionRelation>,
}

impl AuditedClaim {
    /// Named constructor for a claim audited without a frozen identity.
    ///
    /// A claim that carries no [`FrozenClaimIdentity`] cannot be released as
    /// supported, because there is nothing to check its wording and revision
    /// against. This derives the identity a caller would otherwise have to
    /// assemble by hand, so the shape a claim must have before it can be audited
    /// is stated once here rather than left to each caller to remember.
    ///
    /// The derived identity is scoped from the claim's own domain and statement, so
    /// it is the identity this claim currently has — not a claim about anything
    /// broader. A caller holding a real artifact digest or an explicit revision
    /// should freeze its own identity instead of using this.
    ///
    /// # Errors
    ///
    /// Propagates every refusal [`FrozenClaimIdentity::freeze`] raises.
    pub fn freeze_identity(&self) -> Result<FrozenClaimIdentity, PortfolioError> {
        FrozenClaimIdentity::freeze(FrozenClaimIdentity {
            claim_id: self.claim_id.clone(),
            statement: self.statement.clone(),
            materiality: if self.material {
                ClaimMateriality::Material
            } else {
                ClaimMateriality::NonMaterial
            },
            subject: self.domain.clone(),
            conditions: ClaimConditions {
                population_scope: self.domain.clone(),
                time_version: String::new(),
                definition_unit_denominator: String::new(),
                modality: ClaimModality::Descriptive,
            },
            artifact_digest: self.statement_artifact_digest(),
            claim_revision: 1,
            digest: String::new(),
        })
    }

    /// The digest of the statement text this claim carries, as its artifact
    /// identity when no artifact revision was supplied.
    ///
    /// The statement is the released wording, so its digest is the honest artifact
    /// commitment available here. A caller holding a real artifact digest should
    /// freeze the identity explicitly instead of relying on this.
    fn statement_artifact_digest(&self) -> String {
        freeze(&format!("claim-statement/v1;{}", self.statement))
    }
}

/// The five public release audit classes that `#1765` requires.
///
/// I21.8 names exactly five: `SUPPORTED`, `PARTIALLY_SUPPORTED`, `UNSUPPORTED`,
/// `CONTRADICTED`, `NOT_VERIFIABLE_IN_SCOPE`. The internal [`ClaimOutcome`] keeps
/// further values because outside-manifest, stale and incomplete-accounting are
/// real and distinct findings, and collapsing them into one of the five would
/// lose the reason. This enum is the lossless public projection, and
/// [`ClaimVerdict::public_class`] is its only producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicAuditClass {
    /// Every material dimension the release gate requires is established.
    Supported,
    /// Some required dimensions hold and the remainder is preserved as residue.
    PartiallySupported,
    /// The claim is not established as supported, and nothing contradicts it.
    ///
    /// Covers both "no sufficient in-manifest support" and "support that went
    /// stale": I21.8 has no separate public class for staleness, and a stale-limited
    /// claim is not releasable as supported. The distinction is in
    /// [`ClaimVerdict::outcome`] and [`ClaimVerdict::failed_dimensions`].
    Unsupported,
    /// Exact frozen counterevidence refutes the claim under compatible conditions.
    Contradicted,
    /// At least one required dimension is unknown, unevaluable or out of scope.
    ///
    /// This is the fail-closed class: it is never inferred from the absence of a
    /// finding. A dimension nobody could evaluate is unknown, and unknown is not
    /// support.
    NotVerifiableInScope,
}

impl PublicAuditClass {
    /// Every public class, weakest-first, as a frozen ordered list.
    ///
    /// Declared so a release consumer can enumerate the whole public vocabulary
    /// from one owner instead of reconstructing it from the five spellings it
    /// happens to have seen.
    pub const ALL: [Self; 5] = [
        Self::NotVerifiableInScope,
        Self::Unsupported,
        Self::PartiallySupported,
        Self::Supported,
        Self::Contradicted,
    ];

    /// Stable wire spelling of this public class.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::PartiallySupported => "PARTIALLY_SUPPORTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Contradicted => "CONTRADICTED",
            Self::NotVerifiableInScope => "NOT_VERIFIABLE_IN_SCOPE",
        }
    }
}

/// The dimension of a claim a counterevidence relation contests.
///
/// A relation names the dimension it opposes so that agreement on every other
/// dimension is explicit rather than assumed. A source that shares a subject and
/// a population but asserts the opposite time window has not refuted the claim;
/// it has made a different claim, and `OppositionDimension` is how the difference
/// is named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum OppositionDimension {
    /// The asserted proposition itself.
    Proposition,
    /// The polarity of the assertion.
    Polarity,
    /// The subject the assertion is about.
    Subject,
    /// The population or scope the assertion covers.
    Population,
    /// The time window or version the assertion covers.
    TimeVersion,
    /// The modality the assertion is made in.
    ///
    /// Distinct from [`Self::Proposition`]: a descriptive claim and a normative
    /// one can assert the same proposition and still not stand or fall together,
    /// so a modality mismatch is reported as its own dimension rather than folded
    /// into the proposition.
    Modality,
    /// The definition, unit or denominator the assertion is measured in.
    DefinitionUnit,
    /// The intervention the assertion attributes the outcome to.
    Intervention,
    /// The specific excerpt the assertion rests on.
    Excerpt,
}

impl OppositionDimension {
    /// Stable wire spelling of this dimension.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Proposition => "PROPOSITION",
            Self::Polarity => "POLARITY",
            Self::Subject => "SUBJECT",
            Self::Population => "POPULATION",
            Self::TimeVersion => "TIME_VERSION",
            Self::Modality => "MODALITY",
            Self::DefinitionUnit => "DEFINITION_UNIT",
            Self::Intervention => "INTERVENTION",
            Self::Excerpt => "EXCERPT",
        }
    }
}

/// Whether a relation asserts opposition to the claim or agreement with it.
///
/// `Agrees` exists so that "this source supports the claim" is a first-class,
/// refusable statement rather than the absence of a contradiction. A source that
/// agrees cannot become counterevidence through any attachment order, and a
/// relation that claims opposition while evaluating as agreement is a relation
/// that does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum OppositionPolarity {
    /// The source contests the claim on the named dimension.
    Denies,
    /// The source supports the claim on the named dimension.
    Agrees,
}

impl OppositionPolarity {
    /// Stable wire spelling of this polarity.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Denies => "DENIES",
            Self::Agrees => "AGREES",
        }
    }
}

/// What the accepted semantic-evaluation owner concluded about one excerpt.
///
/// #2874 forbids inferring entailment here. There is no substring match, no
/// regex test and no trust in a source's own prose label: the only admissible
/// answer is a receipt from the evaluation owner, and its absence is `Unknown`
/// rather than a negative result computed locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SemanticEvaluationOutcome {
    /// The evaluator established that the excerpt refutes the claim.
    Refutes,
    /// The evaluator established that the excerpt does not speak to the claim.
    Insufficient,
}

impl SemanticEvaluationOutcome {
    /// Stable wire spelling of this outcome.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Refutes => "REFUTES",
            Self::Insufficient => "INSUFFICIENT",
        }
    }
}

/// One owner-issued claim↔counterevidence relation.
///
/// This is the only thing that can make a claim `CONTRADICTED`. It binds the exact
/// claim identity and revision, the exact source record commitment and the exact
/// span the opposition rests on, the dimension and polarity of the opposition, the
/// conditions under which the opposition holds, and an evaluator receipt. A
/// caller that supplies none of this gets `NOT_VERIFIABLE_IN_SCOPE`, which is the
/// correct answer for "we asserted an opposition and cannot show it".
///
/// # What the digest proves, and what it does not
///
/// `digest` and `verify_integrity` prove **tamper-after-issue**: the bytes present
/// are the bytes that were issued. They do **not** prove *authenticity of issue*.
/// Every field here is `pub` on a plain struct with no `#[non_exhaustive]`, and
/// `canonical_digest` is public, so a caller can build a struct literal and
/// compute the matching digest itself. The digest is a checksum, not a signature.
///
/// What stops that from being a caller-writable "proof" is that the relation is
/// only ever *believed* where it agrees with data the caller does not control:
/// the source record commitment is recomputed from the portfolio's own record
/// (`#2873`'s complete field set), the span must be one the record actually
/// admits, and the claim identity must match the claim under audit. Those are the
/// checks that bind an opposition to real evidence. Genuine *authority* over who
/// may issue a relation — an issuer capability, a signature, or a registry lookup —
/// has no owner in this repository, and adding one would mean inventing an
/// authority this crate does not have. See the acceptance note on A4.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimOppositionRelation {
    /// Stable relation identity.
    pub relation_id: String,
    /// Frozen identity of the claim this relation contests.
    ///
    /// Bound whole, including its own `#[serde(skip)]` digest, so a relation cannot
    /// be re-pointed at a different claim revision without changing its bytes.
    pub claim: FrozenClaimIdentity,
    /// Handle of the source alleged to contest the claim.
    pub source_handle: String,
    /// Exact commitment of the source record as frozen.
    ///
    /// This is [`SourceRecord::digest`] under
    /// [`SOURCE_RECORD_DIGEST_DOMAIN`], so a source whose interpretation-relevant
    /// field changed after the relation was issued no longer matches and the
    /// relation does not verify.
    pub source_record_digest: String,
    /// The exact span the opposition rests on.
    pub span: EvidenceSpan,
    /// The dimension of the claim this relation contests.
    pub dimension: OppositionDimension,
    /// Whether the source contests or agrees with the claim.
    pub polarity: OppositionPolarity,
    /// Conditions under which the opposition holds.
    pub compatible_conditions: ClaimConditions,
    /// Identity of the evaluator that reached the outcome.
    pub evaluator_id: String,
    /// Exact evaluator revision the outcome was produced under.
    pub evaluator_revision: String,
    /// What the evaluator concluded.
    pub evaluation: SemanticEvaluationOutcome,
    /// Fraction of the claim the evaluation covered, in millionths.
    ///
    /// A relation that covers only part of the claim cannot silently close all of
    /// it; coverage below one millionth leaves the remainder unaccounted.
    pub coverage_ppm: u32,
    /// Frozen digest over the whole relation shape.
    #[serde(skip)]
    pub digest: String,
}

/// Declared identity domain of [`FrozenClaimIdentity`].
///
/// `v1` is the first declared form. An edited claim's wording, materiality,
/// subject, conditions, artifact digest or revision all move it, which is what
/// makes "the wording changed after the opposition was frozen" detectable rather
/// than a matter of trusting the caller.
pub const FROZEN_CLAIM_IDENTITY_DOMAIN: &str = "frozen-claim-identity/v1";

/// Declared identity domain of [`ClaimOppositionRelation`].
///
/// `v1` is the first declared form. It binds the claim identity, the source record
/// commitment, the span, the dimension, the polarity, the compatible conditions,
/// the evaluator identity and revision, the evaluation outcome and the coverage,
/// so a relation altered in any of those respects stops verifying against itself.
pub const CLAIM_OPPOSITION_RELATION_DOMAIN: &str = "claim-opposition-relation/v1";

/// One frozen claim identity: exactly what was claimed, under what conditions,
/// at which artifact revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrozenClaimIdentity {
    /// Claim identity.
    pub claim_id: String,
    /// Exact final statement wording.
    pub statement: String,
    /// Whether the claim is material.
    pub materiality: ClaimMateriality,
    /// The subject the claim is about.
    pub subject: String,
    /// The exact conditions the claim was made under.
    pub conditions: ClaimConditions,
    /// Digest of the artifact the claim was released in.
    pub artifact_digest: String,
    /// Revision of the claim within its artifact.
    pub claim_revision: u64,
    /// Frozen digest over the whole identity shape.
    #[serde(skip)]
    pub digest: String,
}

/// The single canonical encoder input for [`FrozenClaimIdentity`].
#[derive(Serialize)]
struct FrozenClaimIdentityDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole frozen identity, minus its own digest.
    identity: &'a FrozenClaimIdentity,
}

/// The single canonical encoder input for [`ClaimOppositionRelation`].
#[derive(Serialize)]
struct ClaimOppositionRelationDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole relation, minus its own digest.
    relation: &'a ClaimOppositionRelation,
}

impl FrozenClaimIdentity {
    /// Validates and freezes one claim identity.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity, statement, subject or
    /// condition, a bad artifact digest, or a value that cannot be encoded.
    pub fn freeze(mut identity: Self) -> Result<Self, PortfolioError> {
        text(&identity.claim_id, "claim_identity.claim_id")?;
        text(&identity.statement, "claim_identity.statement")?;
        text(&identity.subject, "claim_identity.subject")?;
        text(
            &identity.conditions.population_scope,
            "claim_identity.population_scope",
        )?;
        text(
            &identity.conditions.time_version,
            "claim_identity.time_version",
        )?;
        text(
            &identity.conditions.definition_unit_denominator,
            "claim_identity.definition_unit_denominator",
        )?;
        digest(&identity.artifact_digest, "claim_identity.artifact_digest")?;
        if identity.claim_revision == 0 {
            return Err(PortfolioError::Blank {
                field: "claim_identity.claim_revision",
            });
        }
        identity.digest = String::new();
        identity.digest = identity.canonical_digest()?;
        Ok(identity)
    }

    /// Deterministic canonical bytes of the frozen identity, digest excluded.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the identity cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&FrozenClaimIdentityDigestInput {
            domain: FROZEN_CLAIM_IDENTITY_DOMAIN,
            identity: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "claim_identity.canonical_body",
        })
    }

    /// Canonical digest recomputed from this value's own fields.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the identity cannot be encoded.
    pub fn canonical_digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with the frozen one.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::InvalidDigest`] when they disagree.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.canonical_digest()? != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "claim_identity.digest",
            });
        }
        Ok(())
    }
}

impl ClaimOppositionRelation {
    /// Validates and freezes one opposition relation.
    ///
    /// # Errors
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank relation, source, span, condition or
    /// evaluator identity, a bad source commitment or excerpt digest, or a
    /// coverage value above one millionth. Also propagates the claim identity's own
    /// refusal, so a relation cannot be issued against an identity that does not
    /// verify.
    pub fn freeze(mut relation: Self) -> Result<Self, PortfolioError> {
        text(&relation.relation_id, "opposition.relation_id")?;
        text(&relation.source_handle, "opposition.source_handle")?;
        digest(
            &relation.source_record_digest,
            "opposition.source_record_digest",
        )?;
        text(&relation.span.span_id, "opposition.span_id")?;
        text(&relation.span.anchor, "opposition.anchor")?;
        digest(&relation.span.excerpt_digest, "opposition.excerpt_digest")?;
        text(
            &relation.compatible_conditions.population_scope,
            "opposition.population_scope",
        )?;
        text(
            &relation.compatible_conditions.time_version,
            "opposition.time_version",
        )?;
        text(
            &relation.compatible_conditions.definition_unit_denominator,
            "opposition.definition_unit_denominator",
        )?;
        text(&relation.evaluator_id, "opposition.evaluator_id")?;
        text(
            &relation.evaluator_revision,
            "opposition.evaluator_revision",
        )?;
        if relation.coverage_ppm > 1_000_000 {
            return Err(PortfolioError::Conflict {
                field: "opposition.coverage_ppm",
            });
        }
        // The relation is only meaningful against a claim identity that verifies,
        // so the claim's own commitment is proved here rather than at each use.
        relation.claim.verify_integrity()?;
        relation.digest = String::new();
        relation.digest = relation.canonical_digest()?;
        Ok(relation)
    }

    /// Deterministic canonical bytes of the relation, digest excluded.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the relation cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&ClaimOppositionRelationDigestInput {
            domain: CLAIM_OPPOSITION_RELATION_DOMAIN,
            relation: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "opposition.canonical_body",
        })
    }

    /// Canonical digest recomputed from this value's own fields.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the relation cannot be encoded.
    pub fn canonical_digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with the frozen one.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::InvalidDigest`] when they disagree.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.canonical_digest()? != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "opposition.digest",
            });
        }
        Ok(())
    }

    /// Named constructor for a relation whose claim identity is already frozen.
    ///
    /// # Errors
    ///
    /// Propagates every refusal [`Self::freeze`] raises, including the frozen
    /// claim identity's own. Building a relation and dropping it establishes
    /// nothing; the audit only ever reads relations attached to
    /// [`AuditedClaim::opposition_relations`].
    ///
    /// # Errors
    ///
    /// See [`Self::freeze`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        relation_id: impl Into<String>,
        claim: FrozenClaimIdentity,
        source_handle: impl Into<String>,
        source_record: &SourceRecord,
        span: EvidenceSpan,
        dimension: OppositionDimension,
        polarity: OppositionPolarity,
        compatible_conditions: ClaimConditions,
        evaluator_id: impl Into<String>,
        evaluator_revision: impl Into<String>,
        evaluation: SemanticEvaluationOutcome,
        coverage_ppm: u32,
    ) -> Result<Self, PortfolioError> {
        let source_record_digest = source_record.digest()?;
        Self::freeze(Self {
            relation_id: relation_id.into(),
            claim,
            source_handle: source_handle.into(),
            source_record_digest,
            span,
            dimension,
            polarity,
            compatible_conditions,
            evaluator_id: evaluator_id.into(),
            evaluator_revision: evaluator_revision.into(),
            evaluation,
            coverage_ppm,
            digest: String::new(),
        })
    }

    /// Whether this relation's own conditions are compatible with the claim's.
    ///
    /// Compatibility is decided field by field and the mismatching fields are
    /// returned, never inferred from the broad authority domain. A partial overlap
    /// is reported as partial: it is not rounded up to agreement, because the
    /// whole defect this replaces was a broad-domain test standing in for an
    /// exact one.
    pub fn condition_compatibility(
        &self,
        claim_conditions: &ClaimConditions,
    ) -> ConditionCompatibility {
        let mut mismatched: Vec<OppositionDimension> = Vec::new();
        if self.compatible_conditions.population_scope != claim_conditions.population_scope {
            mismatched.push(OppositionDimension::Population);
        }
        if self.compatible_conditions.time_version != claim_conditions.time_version {
            mismatched.push(OppositionDimension::TimeVersion);
        }
        if self.compatible_conditions.definition_unit_denominator
            != claim_conditions.definition_unit_denominator
        {
            mismatched.push(OppositionDimension::DefinitionUnit);
        }
        if self.compatible_conditions.modality != claim_conditions.modality {
            mismatched.push(OppositionDimension::Modality);
        }
        if mismatched.is_empty() {
            ConditionCompatibility::Compatible
        } else if mismatched.len() == 4 {
            ConditionCompatibility::Incompatible(mismatched)
        } else {
            ConditionCompatibility::PartiallyOverlapping(mismatched)
        }
    }
}

/// How one relation's conditions relate to the claim's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionCompatibility {
    /// Every condition matches; the opposition is under the same conditions.
    Compatible,
    /// Some conditions match and some do not; both facts are preserved.
    PartiallyOverlapping(Vec<OppositionDimension>),
    /// No condition matches; this is a statement about something else.
    Incompatible(Vec<OppositionDimension>),
}

/// Claim audit outcome for one structured claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Every material citation resolves to supporting in-manifest evidence.
    Supported,
    /// Supported in part; the remainder stays explicit residue.
    PartiallySupported,
    /// No sufficient in-manifest support.
    Unsupported,
    /// Preserved counterevidence contests the claim.
    Contradicted,
    /// An attached counterclaim identity is preserved but cannot be verified as
    /// relevant to this claim's domain under the frozen manifest, so it neither
    /// contradicts nor supports.
    NotVerifiableInScope,
    /// A citation falls outside the frozen manifest.
    OutsideManifest,
    /// Stale material limits the claim without closing it.
    StaleLimited,
    /// Material-claim accounting is incomplete.
    IncompleteAccounting,
}

/// Why one attached counterclaim identity did or did not contradict the claim.
///
/// The audit records this per identity rather than only a verdict, so a consumer
/// never has to recover the reason by matching rendered residue text. Every
/// variant except [`Self::Contradicts`] leaves the identity preserved but
/// unverified in scope: absence of contradiction is never read as support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterclaimDisposition {
    /// Resolved to relevant counterevidence under compatible conditions.
    ///
    /// Reachable only from a verified [`ClaimOppositionRelation`]. Every other
    /// variant below means the opposition was *not* established, and none of them
    /// is ever read as support.
    Contradicts,
    /// The handle is eligible on every axis the manifest, lineage, domain,
    /// freshness and weight checks cover, but nothing establishes that it actually
    /// contests this claim. This is the variant the original defect turned into
    /// `Contradicts`, and it is the honest default for a bare attachment.
    NotVerifiableInScope,
    /// The relation is frozen against a different claim or a different claim
    /// revision, so it says nothing about this claim.
    RelationClaimMismatch,
    /// The claim's wording no longer matches the wording the relation was frozen
    /// against. An edited claim invalidates every verdict reached through it.
    RelationStatementChanged,
    /// The claim carries no frozen identity, so no opposition can be established
    /// against it.
    NoFrozenClaimIdentity,
    /// The relation's bytes no longer hash to the digest frozen beside them.
    RelationDigestMismatch,
    /// The relation rests on a span the admitted source record does not contain.
    SpanNotAdmitted,
    /// The relation is frozen against a source revision that no longer exists.
    RelationSourceRevisionChanged,
    /// The evaluator found the excerpt insufficient to speak to the claim.
    EvaluationInsufficient,
    /// The relation carries no evaluator identity or revision.
    NoEvaluationRoute,
    /// The evaluator established that the source **agrees** with the claim. A
    /// source that supports a claim cannot become counterevidence through any
    /// attachment order.
    AgreesWithClaim,
    /// The opposition is stated under conditions that do not match the claim's on
    /// any dimension, so it is a statement about something else.
    IncompatibleConditions,
    /// The opposition matches the claim's conditions on some dimensions and not
    /// others. Preserved as partial; never rounded up to agreement.
    PartiallyOverlappingConditions,
    /// The opposition covers only part of the claim, leaving the remainder
    /// unaccounted.
    PartialCoverage,
    /// The handle is allowlisted but explicitly revoked, so it cannot be
    /// verified as counterevidence and is not merely absent.
    Revoked,
    /// The handle is outside the frozen manifest.
    OutsideManifest,
    /// No authoritative lineage stands behind the handle.
    UnresolvedLineage,
    /// The record does not cover the claim's authority domain.
    OutsideDomain,
    /// The record is past its frozen freshness boundary at the audit instant, so
    /// it cannot contradict under compatible conditions.
    Stale,
    /// The record's acquisition disposition carries no evidentiary weight.
    CarriesNoWeight,
    /// The same handle is also a material citation of this claim, so it cannot
    /// contest it. The input asserts the source both supports and contests the
    /// claim, which this cell does not resolve in either direction.
    AlsoACitation,
}

impl CounterclaimDisposition {
    /// Stable wire spelling of this disposition.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Contradicts => "CONTRADICTS",
            Self::NotVerifiableInScope => "NOT_VERIFIABLE_IN_SCOPE",
            Self::Revoked => "REVOKED",
            Self::OutsideManifest => "OUTSIDE_MANIFEST",
            Self::UnresolvedLineage => "UNRESOLVED_LINEAGE",
            Self::OutsideDomain => "OUTSIDE_DOMAIN",
            Self::Stale => "STALE",
            Self::CarriesNoWeight => "CARRIES_NO_WEIGHT",
            Self::AlsoACitation => "ALSO_A_CITATION",
            Self::RelationClaimMismatch => "RELATION_CLAIM_MISMATCH",
            Self::RelationStatementChanged => "RELATION_STATEMENT_CHANGED",
            Self::NoFrozenClaimIdentity => "NO_FROZEN_CLAIM_IDENTITY",
            Self::RelationDigestMismatch => "RELATION_DIGEST_MISMATCH",
            Self::SpanNotAdmitted => "SPAN_NOT_ADMITTED",
            Self::RelationSourceRevisionChanged => "RELATION_SOURCE_REVISION_CHANGED",
            Self::EvaluationInsufficient => "EVALUATION_INSUFFICIENT",
            Self::NoEvaluationRoute => "NO_EVALUATION_ROUTE",
            Self::AgreesWithClaim => "AGREES_WITH_CLAIM",
            Self::IncompatibleConditions => "INCOMPATIBLE_CONDITIONS",
            Self::PartiallyOverlappingConditions => "PARTIALLY_OVERLAPPING_CONDITIONS",
            Self::PartialCoverage => "PARTIAL_COVERAGE",
        }
    }

    /// Whether this disposition means the opposition was established.
    ///
    /// The only `true` in this table is [`Self::Contradicts`], and it is the only
    /// one reachable from a verified relation. Everything else — including
    /// [`Self::AgreesWithClaim`] and every eligibility failure — leaves the
    /// opposition unestablished, and none of them is ever read as support.
    pub const fn establishes_opposition(self) -> bool {
        matches!(self, Self::Contradicts)
    }
}

/// One attached counterclaim identity with the disposition the audit gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterclaimResolution {
    /// The attached counterclaim identity, preserved verbatim.
    pub counterclaim_id: String,
    /// Disposition this audit assigned to the identity.
    pub disposition: CounterclaimDisposition,
}

impl ClaimOutcome {
    /// Stable wire spelling of this outcome.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::PartiallySupported => "PARTIALLY_SUPPORTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Contradicted => "CONTRADICTED",
            Self::NotVerifiableInScope => "NOT_VERIFIABLE_IN_SCOPE",
            Self::OutsideManifest => "OUTSIDE_MANIFEST",
            Self::StaleLimited => "STALE_LIMITED",
            Self::IncompleteAccounting => "INCOMPLETE_ACCOUNTING",
        }
    }
}

/// Audit verdict for one structured claim with preserved counterevidence,
/// unknowns and the structured claim-to-evidence map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimVerdict {
    /// Audited claim identity.
    pub claim_id: String,
    /// Outcome of the audit.
    pub outcome: ClaimOutcome,
    /// Typed residue lines (sorted for stability).
    pub residue: Vec<String>,
    /// The over-precise assertions of this claim, as typed items.
    ///
    /// I21.7 requires the `UnsupportedPrecisionItem` to be *recorded*, not only
    /// rendered: a verdict that keeps the item's asserted coordinate, highest
    /// supported precision, basis, false-precision risk and required probe as
    /// one `String` loses the structure a downstream consumer needs to tell a
    /// false line anchor from a false causal mechanism. The rendered
    /// [`Self::residue`] line is still produced, so nothing is lost.
    pub unsupported_precision: Vec<UnsupportedPrecisionItem>,
    /// Preserved counterevidence identities.
    pub counterevidence: Vec<String>,
    /// Per-identity disposition of every attached counterclaim, in sorted-id
    /// order. This is the typed partition the outcome is derived from.
    pub counterclaim_resolutions: Vec<CounterclaimResolution>,
    /// Preserved unknown references.
    pub unknowns: Vec<String>,
    /// Grade ceiling over the supporting records, when computable.
    pub grade_ceiling: Option<u8>,
    /// Evidence handles behind the verdict, sorted.
    pub evidence_map: Vec<String>,
    /// Every dimension the audit examined, whether or not it found a failure.
    ///
    /// This is the record that makes the public projection lossless in the other
    /// direction. A verdict that kept only its terminal outcome would force a
    /// consumer to recover "was this also outside the manifest, and also stale?"
    /// by matching residue prose — the exact mistake the `#1765` repair already
    /// had to undo once. The dimensions are named, not rendered.
    pub dimensions: Vec<AuditDimension>,
    /// Digests of the relations the audit relied on, sorted.
    ///
    /// A verdict is bound to the exact relations that produced it, so a later
    /// reader can tell whether the opposition still verifies rather than trusting
    /// a `CONTRADICTED` label whose evidence has since changed.
    pub relation_digests: Vec<String>,
    /// Digest of the frozen claim identity this verdict was decided under.
    ///
    /// Empty when the claim carried no frozen identity, which is itself a reason
    /// the verdict cannot be `Supported`.
    pub claim_identity_digest: String,
    /// Citations that did not resolve inside the frozen manifest, sorted.
    ///
    /// Recorded as data rather than inferred from the terminal class, so
    /// `ReferenceVerification` can be judged on the citation set itself and a
    /// consumer can see exactly which references failed.
    pub outside_citations: Vec<String>,
    /// Citations whose record resolved but carried no evidentiary weight, sorted.
    ///
    /// The value half of the audit: a citation can be inside the manifest and
    /// still contribute no weight, and that is a different finding from being
    /// outside it.
    pub unweighted_citations: Vec<String>,
}

/// One named dimension the claim audit examined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditDimension {
    /// Every material citation resolved inside the frozen manifest.
    ReferenceVerification,
    /// Every material citation carries evidentiary weight.
    ValueVerification,
    /// The claim is inside the requested specification and scope.
    SpecificationCompliance,
    /// The method and artifact the claim rests on are the ones audited.
    MethodArtifactAlignment,
    /// The claim's wording and revision still match what was frozen.
    ClaimIdentityCurrent,
    /// Every alleged counterclaim was examined.
    CounterevidenceExamined,
    /// Material-claim accounting is complete.
    AccountingComplete,
    /// Every attached counterclaim resolved to exactly one disposition.
    ///
    /// The premise of this dimension is that the partitions agree: a handle cannot
    /// be simultaneously "outside the manifest" on the citation side and "also a
    /// citation" on the counterclaim side. `audit_claim` classifies each handle
    /// once and both partitions read that one answer, so this dimension is the
    /// record that the two did not diverge.
    PartitionCoherence,
}

impl AuditDimension {
    /// Stable wire spelling of this dimension.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ReferenceVerification => "REFERENCE_VERIFICATION",
            Self::ValueVerification => "VALUE_VERIFICATION",
            Self::SpecificationCompliance => "SPECIFICATION_COMPLIANCE",
            Self::MethodArtifactAlignment => "METHOD_ARTIFACT_ALIGNMENT",
            Self::ClaimIdentityCurrent => "CLAIM_IDENTITY_CURRENT",
            Self::CounterevidenceExamined => "COUNTEREVIDENCE_EXAMINED",
            Self::AccountingComplete => "ACCOUNTING_COMPLETE",
            Self::PartitionCoherence => "PARTITION_COHERENCE",
        }
    }
}

impl ClaimVerdict {
    /// The wire spellings of the typed over-precision residue, in the item order
    /// the audit produced them. A binding that hashes this verdict can name the
    /// typed items without depending on their rendered prose.
    #[must_use]
    pub fn unsupported_precision_lines(&self) -> Vec<String> {
        self.unsupported_precision
            .iter()
            .map(|item| {
                format!(
                    "unsupported_precision:{}|{}|{}|{}",
                    item.asserted, item.highest_supported, item.basis, item.required_probe
                )
            })
            .collect()
    }

    /// The public release class for this verdict.
    ///
    /// I21.8 names five public classes and the internal [`ClaimOutcome`] has eight,
    /// so this projection is **many-to-one and therefore not lossless on its own**:
    /// `OutsideManifest`, `NotVerifiableInScope` and `IncompleteAccounting` all
    /// reach [`PublicAuditClass::NotVerifiableInScope`], and `Unsupported` and
    /// `StaleLimited` both reach [`PublicAuditClass::Unsupported`]. The mapping is
    /// total and each arm is individually defensible — the five classes describe
    /// what a release consumer may *do*, and a stale-limited claim is not
    /// `Supported` — but the specific reason lives in
    /// [`Self::outcome`](ClaimVerdict::outcome), [`Self::failed_dimensions`] and the
    /// residue.
    ///
    /// The loss the issue asks for is preserved by keeping those alongside the
    /// class rather than by pretending five classes can express eight findings. A
    /// consumer that needs the distinction reads them; a consumer that only needs
    /// "may this be released as supported" reads this.
    #[must_use]
    pub fn public_class(&self) -> PublicAuditClass {
        match self.outcome {
            ClaimOutcome::Contradicted => PublicAuditClass::Contradicted,
            ClaimOutcome::Supported => PublicAuditClass::Supported,
            ClaimOutcome::PartiallySupported => PublicAuditClass::PartiallySupported,
            ClaimOutcome::Unsupported | ClaimOutcome::StaleLimited => PublicAuditClass::Unsupported,
            ClaimOutcome::OutsideManifest
            | ClaimOutcome::NotVerifiableInScope
            | ClaimOutcome::IncompleteAccounting => PublicAuditClass::NotVerifiableInScope,
        }
    }

    /// Whether every dimension the release gate requires was established.
    ///
    /// This is the "no `SUPPORTED` promotion while a required dimension fails or
    /// is unknown" rule expressed as a question a consumer can ask, rather than
    /// as a precedence chain that decides it silently.
    #[must_use]
    pub fn dimensions_complete(&self) -> bool {
        !self.dimensions.is_empty()
            && self
                .dimensions
                .iter()
                .all(|dimension| self.dimension_passed(*dimension))
    }

    /// Whether one named dimension was examined and found sound.
    ///
    /// Public, and deliberately so. `dimensions_complete` answers "may this be
    /// released", but a release consumer that has to act on a failure needs to
    /// know *which* dimension failed, and the alternative is recovering it from
    /// rendered residue — the exact mistake the `#1765` repair already had to undo
    /// once. An absent dimension did not pass.
    #[must_use]
    pub fn dimension_passed(&self, dimension: AuditDimension) -> bool {
        self.dimensions.contains(&dimension) && !self.dimension_failed(dimension)
    }

    /// The wire spellings of the examined audit dimensions, in sorted order.
    ///
    /// A binding that covers this verdict names the dimensions it examined without
    /// depending on the enum's declaration order or on rendered prose.
    #[must_use]
    pub fn dimension_names(&self) -> Vec<String> {
        self.dimensions
            .iter()
            .map(|dimension| dimension.wire_name().to_owned())
            .collect()
    }

    /// The named dimensions this verdict examined and found unsound.
    ///
    /// The direct answer to "which findings does this verdict carry", so a
    /// consumer never has to infer it from a single boolean or from prose.
    #[must_use]
    pub fn failed_dimensions(&self) -> Vec<AuditDimension> {
        self.dimensions
            .iter()
            .copied()
            .filter(|dimension| self.dimension_failed(*dimension))
            .collect()
    }

    /// Whether one examined dimension failed.
    fn dimension_failed(&self, dimension: AuditDimension) -> bool {
        let failed = match dimension {
            // Reference verification asks whether every citation resolved inside
            // the frozen manifest. It is a question about the citation set, so it
            // is answered from the set and not from the terminal class: reading
            // `outcome` here would make this dimension a restatement of the
            // precedence chain rather than an independent observation, which is
            // what I21.8 asks for.
            AuditDimension::ReferenceVerification => self.outside_citations.is_empty(),
            // Value verification asks whether the resolved citations carried
            // weight. Answered from the recorded set, not from the terminal class.
            AuditDimension::ValueVerification => !self.unweighted_citations.is_empty(),
            AuditDimension::SpecificationCompliance => {
                self.counterclaim_resolutions.iter().any(|entry| {
                    matches!(
                        entry.disposition,
                        CounterclaimDisposition::IncompatibleConditions
                            | CounterclaimDisposition::PartiallyOverlappingConditions
                            | CounterclaimDisposition::OutsideDomain
                    )
                })
            }
            // The claim is aligned with the artifact it was released in when it
            // carries a frozen identity that verifies. An unfrozen claim, or one
            // whose identity was substituted, has no such alignment.
            AuditDimension::MethodArtifactAlignment => self.claim_identity_digest.is_empty(),
            AuditDimension::ClaimIdentityCurrent => {
                // Every disposition that means the claim's own identity no longer
                // describes the claim being audited. The set is deliberately
                // identical to the `identity_current` test in `audit_claim`: a
                // disposition present in one and absent from the other would let a
                // verdict exist *because* a relation was stale while reporting the
                // identity as current.
                self.counterclaim_resolutions.iter().any(|entry| {
                    matches!(
                        entry.disposition,
                        CounterclaimDisposition::RelationStatementChanged
                            | CounterclaimDisposition::RelationClaimMismatch
                            | CounterclaimDisposition::NoFrozenClaimIdentity
                            | CounterclaimDisposition::RelationDigestMismatch
                            | CounterclaimDisposition::RelationSourceRevisionChanged
                    )
                })
            }
            // Every alleged counterclaim resolved to a settled disposition:
            // either a verified contradiction, or a refusal that names why. The
            // dimension is only recorded when there WAS an alleged counterclaim to
            // examine, so its absence already means the question was not asked.
            AuditDimension::CounterevidenceExamined => {
                self.counterclaim_resolutions.iter().any(|entry| {
                    !matches!(
                        entry.disposition,
                        CounterclaimDisposition::Contradicts
                            | CounterclaimDisposition::AlsoACitation
                            | CounterclaimDisposition::NotVerifiableInScope
                    )
                })
            }
            AuditDimension::AccountingComplete => {
                self.outcome == ClaimOutcome::IncompleteAccounting || !self.unknowns.is_empty()
            }
            // Coherence is a property of how this verdict was built rather than of
            // what it found: every handle in `counterclaim_resolutions` carries
            // exactly one disposition, and a handle cannot appear twice with
            // different answers. It fails only if the resolution list contradicts
            // itself, which no current path can produce — which is the point of
            // recording it.
            // Coherence fails when a handle received two different standings: the
            // same handle appearing twice in the resolution list, or appearing as
            // both an outside citation and a settled counterclaim. The second case
            // is the one the issue names, and it is reachable from a caller that
            // lists a handle on both sides.
            AuditDimension::PartitionCoherence => {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                let duplicated = self
                    .counterclaim_resolutions
                    .iter()
                    .any(|entry| !seen.insert(entry.counterclaim_id.as_str()));
                let cross_partition = self.outside_citations.iter().any(|handle| {
                    self.counterclaim_resolutions
                        .iter()
                        .any(|entry| &entry.counterclaim_id == handle)
                });
                duplicated || cross_partition
            }
        };
        !failed
    }
}

/// The frozen evidence portfolio under audit: inquiry identity, vetted source
/// records, exact coverage accounting and the lineage table derived from the
/// records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePortfolio {
    /// Digest of the frozen inquiry this portfolio answers.
    pub inquiry_digest: String,
    /// Vetted source records by canonical handle.
    pub records: BTreeMap<String, SourceRecord>,
    /// Exact coverage accounting over the denominator.
    pub coverage: CoverageAccount,
}

/// Result of ingesting one vetted source record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestResult {
    /// The record was accepted.
    Inserted,
    /// The identical record was already present; no state changed.
    ReplayDuplicate,
}

impl EvidencePortfolio {
    /// Opens a portfolio over a frozen inquiry denominator.
    pub fn open(inquiry: &FrozenInquiry) -> Result<Self, PortfolioError> {
        Ok(Self {
            inquiry_digest: inquiry.digest.clone(),
            records: BTreeMap::new(),
            coverage: CoverageAccount::open(inquiry.denominator_members())?,
        })
    }

    /// Ingests one vetted source record exactly once semantically. A replay
    /// of the identical record is a duplicate without state change; the same
    /// handle with changed content conflicts instead of being silently
    /// replaced. Coverage follows the record disposition.
    pub fn ingest(
        &mut self,
        record: SourceRecord,
        member: &str,
    ) -> Result<IngestResult, PortfolioError> {
        if record.handle.trim().is_empty() {
            return Err(PortfolioError::Blank {
                field: "source.handle",
            });
        }
        match self.records.get(&record.handle) {
            Some(current) if *current == record => return Ok(IngestResult::ReplayDuplicate),
            Some(_) => {
                return Err(PortfolioError::Conflict {
                    field: "source.handle",
                });
            }
            None => {}
        }
        self.coverage
            .record(member, record.acquisition, Some(record.handle.clone()))?;
        self.records.insert(record.handle.clone(), record);
        Ok(IngestResult::Inserted)
    }

    /// Lineage table derived from the ingested records.
    pub fn lineage(&self) -> LineageTable {
        LineageTable::build(&self.records)
    }
}

/// The exact identity one manifest admits for one source.
///
/// A manifest used to bind `handle -> (content_digest, transformed_from)`, which
/// commits the acquired bytes and the raw lineage and nothing else. A source
/// could keep both of those while its freshness boundary, transform
/// verification, allowed use or effects, verifier, quarantine, counterevidence
/// relation, citation edges, excerpt spans or data role all changed, and the
/// manifest rehashed identically while the record an audit reads had become a
/// different object. The record commitment below is what closes that; the other
/// two are kept as explicit subfields because they remain independently
/// meaningful commitments and a consumer should not have to re-derive them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ManifestSource {
    /// The complete canonical commitment of the vetted [`SourceRecord`], over
    /// every identity-relevant field it carries.
    pub record_digest: String,
    /// Digest of the acquired content bytes.
    pub content_digest: String,
    /// Raw source the admitted record was transformed from, when derived.
    pub transformed_from: Option<String>,
}

/// One immutable authorized manifest over the exact inquiry, denominator,
/// source and evidence identities, raw and transform digests, dependence
/// graph, coverage, grade limits, counterevidence, conflicts, unknowns, the
/// reference allowlist, and privacy/expiry bounds. Every collection here is a
/// set in meaning and is frozen sorted by [`Self::freeze`], so the manifest bytes
/// are stable under arrival order while meaningful sequence stays
/// identity-visible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorizedManifest {
    /// Digest of the frozen inquiry.
    pub inquiry_digest: String,
    /// Digest of the exact denominator.
    pub denominator_digest: String,
    /// Exact source identity commitments by canonical handle.
    pub sources: BTreeMap<String, ManifestSource>,
    /// Dependence edges `(from, to)` in frozen order.
    pub dependence_edges: BTreeSet<(String, String)>,
    /// Digest of the frozen coverage accounting.
    pub coverage_digest: String,
    /// Grade limit explanations in frozen order.
    pub grade_limits: Vec<String>,
    /// Preserved counterevidence identities in frozen order.
    pub counterevidence: Vec<String>,
    /// Preserved conflict notes in frozen order.
    pub conflicts: Vec<String>,
    /// Preserved unknown references in frozen order.
    pub unknowns: Vec<String>,
    /// Reference allowlist in frozen order.
    pub allowlist: Vec<String>,
    /// Revoked or stale handles excluded from the allowlist.
    pub revoked: Vec<String>,
    /// Privacy class carried into any handoff.
    pub disclosure: DisclosureClass,
    /// Expiry in Unix milliseconds; audits past it fail closed.
    pub expires_ms: i64,
    /// Manifest revision; a revision invalidates older audits.
    pub revision: u64,
    /// Frozen digest over the whole manifest shape.
    ///
    /// Excluded from its own preimage by `#[serde(skip)]`.
    #[serde(skip)]
    pub digest: String,
}

/// Declared identity domain of [`AuthorizedManifest`].
///
/// Bumped `v1` -> `v2` with the per-source record commitment. The `v1`
/// preimage named two subfields per source where a manifest now names three, so
/// the same name would have covered two different field sets.
pub const AUTHORIZED_MANIFEST_DIGEST_DOMAIN: &str = "authorized-manifest/v2";

/// Named constructor arguments for [`AuthorizedManifest::freeze`].
#[derive(Clone, Debug)]
pub struct AuthorizedManifestParams {
    /// Inquiry digest.
    pub inquiry_digest: String,
    /// Denominator digest.
    pub denominator_digest: String,
    /// Source identities.
    pub sources: BTreeMap<String, ManifestSource>,
    /// Dependence edges.
    pub dependence_edges: BTreeSet<(String, String)>,
    /// Coverage digest.
    pub coverage_digest: String,
    /// Grade limits.
    pub grade_limits: Vec<String>,
    /// Counterevidence.
    pub counterevidence: Vec<String>,
    /// Conflicts.
    pub conflicts: Vec<String>,
    /// Unknowns.
    pub unknowns: Vec<String>,
    /// Allowlist.
    pub allowlist: Vec<String>,
    /// Revoked handles.
    pub revoked: Vec<String>,
    /// Disclosure class.
    pub disclosure: DisclosureClass,
    /// Expiry.
    pub expires_ms: i64,
    /// Revision.
    pub revision: u64,
}

impl AuthorizedManifest {
    /// Validates and freezes one authorized manifest. No new source may enter
    /// a later audit without a new manifest: the allowlist is exactly the
    /// frozen set.
    #[allow(clippy::too_many_lines)]
    pub fn freeze(mut params: AuthorizedManifestParams) -> Result<Self, PortfolioError> {
        digest(&params.inquiry_digest, "manifest.inquiry_digest")?;
        digest(&params.denominator_digest, "manifest.denominator_digest")?;
        digest(&params.coverage_digest, "manifest.coverage_digest")?;
        if params.sources.is_empty() {
            return Err(PortfolioError::Blank {
                field: "manifest.sources",
            });
        }
        for (handle, source) in &params.sources {
            text(handle, "manifest.source")?;
            digest(&source.record_digest, "manifest.source.record_digest")?;
            digest(&source.content_digest, "manifest.content_digest")?;
            if let Some(raw) = &source.transformed_from {
                text(raw, "manifest.raw_lineage")?;
            }
        }
        for (from, to) in &params.dependence_edges {
            if !params.sources.contains_key(from) || !params.sources.contains_key(to) {
                return Err(PortfolioError::UnresolvedRoot {
                    field: "manifest.dependence_edges",
                });
            }
        }
        for limit in &params.grade_limits {
            text(limit, "manifest.grade_limits")?;
        }
        for item in params
            .counterevidence
            .iter()
            .chain(params.conflicts.iter())
            .chain(params.unknowns.iter())
        {
            text(item, "manifest.preserved")?;
        }
        if params.allowlist.is_empty() {
            return Err(PortfolioError::Blank {
                field: "manifest.allowlist",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for handle in &params.allowlist {
                text(handle, "manifest.allowlist")?;
                if !params.sources.contains_key(handle) {
                    return Err(PortfolioError::UnresolvedRoot {
                        field: "manifest.allowlist",
                    });
                }
                if !seen.insert(handle) {
                    return Err(PortfolioError::Duplicate {
                        field: "manifest.allowlist",
                    });
                }
            }
        }
        for handle in &params.revoked {
            text(handle, "manifest.revoked")?;
            if params.allowlist.iter().any(|h| h == handle) {
                return Err(PortfolioError::Conflict {
                    field: "manifest.revoked",
                });
            }
        }
        if params.expires_ms <= 0 {
            return Err(PortfolioError::Blank {
                field: "manifest.expires_ms",
            });
        }
        params.grade_limits.sort();
        params.counterevidence.sort();
        params.conflicts.sort();
        params.unknowns.sort();
        params.allowlist.sort();
        // `revoked` is a set in meaning — it answers membership, never order — so
        // it is sorted with the rest. It was the one canonical collection the
        // freeze left in arrival order, which meant two manifests revoking the
        // same handles in a different order hashed differently under one declared
        // domain: an identity that moved without any authorization moving.
        params.revoked.sort();
        let mut manifest = Self {
            inquiry_digest: params.inquiry_digest,
            denominator_digest: params.denominator_digest,
            sources: params.sources,
            dependence_edges: params.dependence_edges,
            coverage_digest: params.coverage_digest,
            grade_limits: params.grade_limits,
            counterevidence: params.counterevidence,
            conflicts: params.conflicts,
            unknowns: params.unknowns,
            allowlist: params.allowlist,
            revoked: params.revoked,
            disclosure: params.disclosure,
            expires_ms: params.expires_ms,
            revision: params.revision,
            digest: String::new(),
        };
        manifest.digest = manifest.canonical_digest()?;
        Ok(manifest)
    }

    /// Whether `handle` is citable under this manifest: allowlisted and not
    /// revoked or stale.
    pub fn allows(&self, handle: &str) -> bool {
        self.allowlist.iter().any(|h| h == handle) && !self.revoked.iter().any(|h| h == handle)
    }

    /// The exact identity this manifest froze for `handle`, when it froze one.
    pub fn source_commitment(&self, handle: &str) -> Option<&ManifestSource> {
        self.sources.get(handle)
    }

    /// Whether this manifest still commits `record` exactly as it was frozen.
    ///
    /// A substituted record that keeps its handle and its content digest still
    /// changes one of the interpretation-relevant fields, so it changes the
    /// record commitment and fails here. The answer is false for a handle the
    /// manifest never froze, which is the same refusal as a record outside it.
    pub fn binds_source_record(&self, record: &SourceRecord) -> bool {
        self.source_commitment(&record.handle)
            .is_some_and(|source| record.verify_identity(&source.record_digest).is_ok())
    }

    /// Deterministic canonical bytes of the frozen manifest shape, with the
    /// stored digest excluded.
    ///
    /// This is the same encoder [`Self::canonical_digest`] hashes, over the same
    /// declared domain, so a persisted manifest can be re-read and re-hashed
    /// without a second field list that could drift from the first.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&AuthorizedManifestDigestInput {
            domain: AUTHORIZED_MANIFEST_DIGEST_DOMAIN,
            manifest: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "manifest.canonical_body",
        })
    }

    /// Canonical digest recomputed from this value's own fields.
    pub fn canonical_digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with the frozen one.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.canonical_digest()? != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "manifest.digest",
            });
        }
        Ok(())
    }
}

/// The single canonical encoder input for [`AuthorizedManifest`].
///
/// The manifest is borrowed whole; its `digest` field is excluded by
/// `#[serde(skip)]` on the field itself, so the exclusion is declared next to
/// the field it excludes.
#[derive(Serialize)]
struct AuthorizedManifestDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole frozen manifest, minus its own digest.
    manifest: &'a AuthorizedManifest,
}

/// Classifies one attached counterclaim identity against this claim.
///
/// The checks run most-specific first, and each records its own typed residue
/// line, so the reason an identity did not contradict is never lost:
///
/// * a handle that is also a material citation of this claim asserts both
///   support and opposition at once, which this cell does not resolve;
/// * a revoked handle is stronger than an absent one — the evidence was
///   authorized and then withdrawn, so it cannot be verified either way;
/// * a record past its frozen freshness boundary cannot contradict under
///   compatible conditions, even though a time-stale record may still support.
fn resolve_counterclaim(
    counterclaim_id: &str,
    claim: &AuditedClaim,
    portfolio: &EvidencePortfolio,
    manifest: &AuthorizedManifest,
    now_ms: i64,
    residue: &mut Vec<String>,
) -> CounterclaimDisposition {
    if claim.citations.iter().any(|cited| cited == counterclaim_id) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} is also a citation and cannot contest the claim"
        ));
        return CounterclaimDisposition::AlsoACitation;
    }
    if manifest
        .revoked
        .iter()
        .any(|handle| handle == counterclaim_id)
    {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} is revoked and cannot be verified"
        ));
        return CounterclaimDisposition::Revoked;
    }
    if !manifest.allows(counterclaim_id) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} outside frozen manifest"
        ));
        return CounterclaimDisposition::OutsideManifest;
    }
    let Some(record) = portfolio.records.get(counterclaim_id) else {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} has no authoritative lineage"
        ));
        return CounterclaimDisposition::UnresolvedLineage;
    };
    // The manifest froze this handle's complete record commitment, so a record
    // that no longer hashes to it was substituted after the freeze. It is
    // reported as unresolved lineage rather than silently audited as the source
    // the manifest admitted.
    if !manifest.binds_source_record(record) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} does not match the frozen source commitment"
        ));
        return CounterclaimDisposition::UnresolvedLineage;
    }
    if !record.covers_domain(&claim.domain) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} outside claim domain {}",
            claim.domain
        ));
        return CounterclaimDisposition::OutsideDomain;
    }
    if record.is_stale_at(now_ms) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} is stale and cannot contradict"
        ));
        return CounterclaimDisposition::Stale;
    }
    if !record.acquisition.may_support() {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} disposition {} carries no weight",
            record.acquisition.wire_name()
        ));
        return CounterclaimDisposition::CarriesNoWeight;
    }
    // The standing is resolved once, above, and re-read here rather than
    // re-derived: the counterclaim partition and the citation partition must be
    // able to disagree about nothing except the semantic question, never about
    // whether the handle exists, was withdrawn, or was substituted.
    // Everything above is *eligibility*: the handle is authorized, resolves,
    // covers the domain, is fresh and carries weight. None of that is opposition.
    // A source that satisfies all five and agrees with the claim is not a
    // contradiction of it, and the only thing that can establish opposition is a
    // [`ClaimOppositionRelation`] whose claim identity, source commitment, span,
    // conditions and evaluator receipt all verify. An eligible handle with no such
    // relation is reported as not verifiable, never as `Contradicts`.
    //
    // The staleness check above is the eligibility half; `verified_opposition`
    // re-checks it because an opposition is only meaningful for a source that is
    // still fresh at the audit instant, and that is a property of the record
    // rather than of the relation.
    if let Some(disposition) = verified_opposition(counterclaim_id, claim, record, now_ms, residue)
    {
        return disposition;
    }
    residue.push(format!(
        "claim: counterclaim {counterclaim_id} is eligible but no verified opposition relation establishes that it contests this claim"
    ));
    CounterclaimDisposition::NotVerifiableInScope
}

/// The single standing one handle has under one manifest, resolved once.
///
/// Both the citation partition and the counterclaim partition read this, so a
/// handle cannot receive inconsistent typed semantics across the two. The order
/// is fixed and total: revocation is decided before membership, because a revoked
/// handle was authorized and then withdrawn, and reporting it as merely absent
/// would lose that. `OutsideManifest` and `Admitted` are distinct because a
/// handle the manifest never froze and a handle it froze are different facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleStanding {
    /// The handle was authorized and then explicitly withdrawn.
    Revoked,
    /// The handle is not part of the frozen manifest.
    OutsideManifest,
    /// The manifest admits the handle but no authoritative record stands behind it.
    UnresolvedLineage,
    /// The record was substituted after the manifest froze its commitment.
    SubstitutedAfterFreeze,
    /// The record resolves but is past its frozen freshness boundary.
    Stale,
    /// The record resolves and carries no evidentiary weight.
    NoWeight,
    /// The handle is admitted, resolves, matches its frozen commitment and carries
    /// weight. Domain competence is judged per claim and is not part of standing.
    Admitted,
}

impl HandleStanding {
    /// Stable wire spelling of this standing.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Revoked => "REVOKED",
            Self::OutsideManifest => "OUTSIDE_MANIFEST",
            Self::UnresolvedLineage => "UNRESOLVED_LINEAGE",
            Self::SubstitutedAfterFreeze => "SUBSTITUTED_AFTER_FREEZE",
            Self::Stale => "STALE",
            Self::NoWeight => "NO_WEIGHT",
            Self::Admitted => "ADMITTED",
        }
    }

    /// Whether a handle in this standing may be cited as support or as
    /// counterevidence. Everything except [`Self::Admitted`] fails closed.
    pub const fn may_support(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// Resolves the one standing `handle` has under `manifest` and `portfolio`.
///
/// This is the only place either partition decides what a handle is. Both call
/// it, so revocation cannot be hidden behind a later check and a substituted
/// record cannot be admitted on one side and refused on the other.
fn handle_standing(
    handle: &str,
    portfolio: &EvidencePortfolio,
    manifest: &AuthorizedManifest,
) -> HandleStanding {
    if manifest.revoked.iter().any(|revoked| revoked == handle) {
        return HandleStanding::Revoked;
    }
    if !manifest.allows(handle) {
        return HandleStanding::OutsideManifest;
    }
    let Some(record) = portfolio.records.get(handle) else {
        return HandleStanding::UnresolvedLineage;
    };
    if !manifest.binds_source_record(record) {
        return HandleStanding::SubstitutedAfterFreeze;
    }
    if !record.acquisition.may_support() {
        return HandleStanding::NoWeight;
    }
    if record.acquisition == SourceDisposition::Stale {
        return HandleStanding::Stale;
    }
    HandleStanding::Admitted
}

/// Renders one wire name per mismatched condition, in the order the conditions
/// were compared.
///
/// Shared by both mismatch arms so the two cannot drift, and so a consumer
/// reading the residue sees the same vocabulary the typed disposition carries.
fn wire_names(dimensions: &[OppositionDimension]) -> String {
    let names: Vec<&str> = dimensions
        .iter()
        .map(|dimension| dimension.wire_name())
        .collect();
    names.join(",")
}

/// Decides whether one eligible handle is verified counterevidence for this claim.
///
/// Returns `None` when no relation establishes opposition, which the caller
/// reports as `NotVerifiableInScope`. Every failure below is a refusal to believe
/// a relation, and each preserves why: a relation that cannot be proved is not
/// evidence in either direction.
///
/// The checks run most-specific first, and each records its own typed residue
/// line, so the reason an eligible handle did not contradict is never lost:
///
/// * a relation whose own bytes no longer hash to its digest was altered after it
///   was issued;
/// * a relation bound to a different claim identity or a different claim revision
///   says nothing about this claim, and a claim whose wording moved invalidates
///   every verdict reached through it;
/// * a relation whose source commitment no longer matches the record contests a
///   source revision that does not exist any more;
/// * a relation whose span is not one of the record's own evidence spans rests on
///   an excerpt the admitted record does not contain;
/// * a relation that evaluates as agreement is a source that supports the claim,
///   which can never become counterevidence through any attachment order;
/// * a condition mismatch leaves the opposition about a different population,
///   time, unit or modality, and a partial overlap is preserved as partial;
/// * an `Insufficient` evaluation, a missing evaluator identity, or coverage
///   below the whole claim is an unknown, not a negative result.
#[allow(clippy::too_many_lines)]
fn verified_opposition(
    counterclaim_id: &str,
    claim: &AuditedClaim,
    record: &SourceRecord,
    now_ms: i64,
    residue: &mut Vec<String>,
) -> Option<CounterclaimDisposition> {
    let relation = claim
        .opposition_relations
        .iter()
        .find(|relation| relation.source_handle == counterclaim_id)?;
    if relation.claim.claim_id != claim.claim_id {
        residue.push(format!(
            "claim: opposition relation {} contests claim {} not {}",
            relation.relation_id, relation.claim.claim_id, claim.claim_id
        ));
        return Some(CounterclaimDisposition::RelationClaimMismatch);
    }
    if relation.claim.statement != claim.statement {
        residue.push(format!(
            "claim: opposition relation {} is frozen against different statement wording",
            relation.relation_id
        ));
        return Some(CounterclaimDisposition::RelationStatementChanged);
    }
    let Some(identity) = claim
        .frozen_identities
        .iter()
        .find(|identity| identity.claim_id == claim.claim_id)
    else {
        residue.push(
            "claim: no frozen claim identity, so no opposition can be established".to_owned(),
        );
        return Some(CounterclaimDisposition::NoFrozenClaimIdentity);
    };
    if identity.claim_revision != relation.claim.claim_revision {
        residue.push(format!(
            "claim: opposition relation {} is frozen against revision {} not {}",
            relation.relation_id, relation.claim.claim_revision, identity.claim_revision
        ));
        return Some(CounterclaimDisposition::RelationClaimMismatch);
    }
    if identity.verify_integrity().is_err() || relation.verify_integrity().is_err() {
        residue.push(format!(
            "claim: opposition relation {} does not match its own frozen digest",
            relation.relation_id
        ));
        return Some(CounterclaimDisposition::RelationDigestMismatch);
    }
    if !record.binds_span(&relation.span) {
        residue.push(format!(
            "claim: opposition relation {} rests on a span the admitted record does not contain",
            relation.relation_id
        ));
        return Some(CounterclaimDisposition::SpanNotAdmitted);
    }
    if !record
        .digest()
        .is_ok_and(|current| current == relation.source_record_digest)
    {
        residue.push(format!(
            "claim: opposition relation {} is frozen against a different source revision",
            relation.relation_id
        ));
        return Some(CounterclaimDisposition::RelationSourceRevisionChanged);
    }
    if relation.evaluation == SemanticEvaluationOutcome::Insufficient {
        residue.push(format!(
            "claim: evaluator {} found the excerpt {} insufficient",
            relation.evaluator_id, relation.span.span_id
        ));
        return Some(CounterclaimDisposition::EvaluationInsufficient);
    }
    if relation.evaluator_id.trim().is_empty() || relation.evaluator_revision.trim().is_empty() {
        residue.push(format!(
            "claim: opposition relation {} carries no evaluator identity",
            relation.relation_id
        ));
        return Some(CounterclaimDisposition::NoEvaluationRoute);
    }
    if relation.polarity == OppositionPolarity::Agrees {
        residue.push(format!(
            "claim: source {counterclaim_id} is evaluated as agreeing with the claim on {}",
            relation.dimension.wire_name()
        ));
        return Some(CounterclaimDisposition::AgreesWithClaim);
    }
    match relation.condition_compatibility(&identity.conditions) {
        ConditionCompatibility::Incompatible(mismatched) => {
            residue.push(format!(
                "claim: opposition is stated under different conditions ({})",
                wire_names(&mismatched)
            ));
            return Some(CounterclaimDisposition::IncompatibleConditions);
        }
        ConditionCompatibility::PartiallyOverlapping(mismatched) => {
            residue.push(format!(
                "claim: opposition overlaps only partially; mismatched {}",
                wire_names(&mismatched)
            ));
            return Some(CounterclaimDisposition::PartiallyOverlappingConditions);
        }
        ConditionCompatibility::Compatible => {}
    }
    if relation.coverage_ppm < 1_000_000 {
        residue.push(format!(
            "claim: opposition covers {}ppm of the claim; the remainder is unaccounted",
            relation.coverage_ppm
        ));
        return Some(CounterclaimDisposition::PartialCoverage);
    }
    if record.is_stale_at(now_ms) {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} is stale and cannot contradict"
        ));
        return Some(CounterclaimDisposition::Stale);
    }
    Some(CounterclaimDisposition::Contradicts)
}

/// Audits one already-structured claim against the frozen portfolio and
/// manifest: exact membership, authoritative lineage, scope/time/version/
/// quantity/causal/absence compatibility and complete material-claim
/// accounting. Unsupported precision, outside-manifest references and
/// insufficient coverage remain typed residue. Counterevidence and unknowns
/// are preserved, never smoothed.
#[allow(clippy::too_many_lines)]
pub fn audit_claim(
    claim: &AuditedClaim,
    portfolio: &EvidencePortfolio,
    manifest: &AuthorizedManifest,
    now_ms: i64,
) -> ClaimVerdict {
    let mut residue: Vec<String> = Vec::new();
    let mut supporting: Vec<&SourceRecord> = Vec::new();
    let mut evidence_map: Vec<String> = Vec::new();
    let mut unsupported_precision: Vec<UnsupportedPrecisionItem> = Vec::new();
    let mut stale_hit = false;
    // A manifest whose bytes no longer hash to the digest frozen beside them is
    // not the manifest that was authorized: an expiry widened, a revocation
    // cleared or a handle re-admitted after the freeze all leave every field
    // individually well-formed. The audit refuses to derive anything from it,
    // which is a different failure from a citation being individually
    // unverifiable, so it is decided once here rather than per handle.
    let manifest_intact = manifest.verify_integrity().is_ok();
    if !manifest_intact {
        residue.push("claim: manifest does not match its own frozen digest".to_owned());
    }
    // These three are recorded where the condition is actually known rather
    // than recovered later from the rendered residue prose. A residue line is
    // diagnostic text, and matching a substring of it let an unrelated line
    // (a counterclaim outside the manifest, say) flip a citation verdict.
    let mut outside_citation = false;
    // The two citation findings are recorded as data, not as a single boolean, so
    // each audit dimension can be judged on the citation set itself and a consumer
    // can see which references failed rather than inferring it from a class.
    let mut outside_citations: Vec<String> = Vec::new();
    let mut unweighted_citations: Vec<String> = Vec::new();
    // A manifest that fails its own integrity check is the authorization this
    // claim was judged under, so the gap is seeded here rather than per handle:
    // with the manifest unproven, no handle it admits is proven either, and the
    // claim cannot come out `Supported`.
    let mut lineage_gap = !manifest_intact;
    let mut support_gap = false;
    if claim.material && claim.citations.is_empty() {
        residue.push("claim: material claim records no citations".to_owned());
    }
    for handle in &claim.citations {
        // One classification per handle, resolved once and read by both
        // partitions. This is the coherence property the issue asks for: a handle
        // cannot be "outside the manifest" on the citation side and something else
        // on the counterclaim side, because neither side re-derives standing from
        // its own rules.
        let standing = handle_standing(handle, portfolio, manifest);
        let Some(record) = portfolio.records.get(handle) else {
            lineage_gap = true;
            residue.push(format!(
                "claim: citation {handle} has no authoritative lineage"
            ));
            continue;
        };
        if !standing.may_support() {
            match standing {
                HandleStanding::OutsideManifest => {
                    outside_citation = true;
                    outside_citations.push(handle.clone());
                    residue.push(format!("claim: citation {handle} outside frozen manifest"));
                }
                // A record that no longer hashes to the commitment this manifest
                // froze is not the source the manifest admitted. Treating it as a
                // lineage gap keeps the verdict non-supporting without introducing
                // a second terminal class for what is, exactly, an unproven lineage.
                HandleStanding::SubstitutedAfterFreeze => {
                    lineage_gap = true;
                    residue.push(format!(
                        "claim: citation {handle} does not match the frozen source commitment"
                    ));
                }
                HandleStanding::Stale => {
                    stale_hit = true;
                    residue.push(format!("claim: citation {handle} stale limits claim"));
                }
                _ => {
                    support_gap = true;
                    unweighted_citations.push(handle.clone());
                    residue.push(format!(
                        "claim: citation {handle} stands {} and carries no weight",
                        standing.wire_name()
                    ));
                }
            }
            continue;
        }
        if record.outside_domain(&claim.domain) {
            lineage_gap = true;
            residue.push(format!(
                "claim: source {handle} outside claim domain {}",
                claim.domain
            ));
            continue;
        }
        // An admitted handle whose record has passed its own freshness boundary
        // still limits the claim, and that is a staleness finding rather than a
        // weight finding: a time-stale record may support, it just cannot carry a
        // contradiction.
        if record.is_stale_at(now_ms) {
            stale_hit = true;
            residue.push(format!("claim: source {handle} stale limits claim"));
        }
        match record.acquisition {
            SourceDisposition::Observed | SourceDisposition::Partial => {
                supporting.push(record);
                evidence_map.push(handle.clone());
            }
            SourceDisposition::Stale => {
                stale_hit = true;
                // A stale source is an accounted gap, exactly as before this
                // function stopped matching rendered residue prose: the previous
                // `contains("carries no weight")` scan fired on this line too, so
                // omitting the flag here would silently reclassify a stale
                // citation from PartiallySupported to StaleLimited.
                support_gap = true;
                residue.push(format!("claim: source {handle} stale carries no weight"));
            }
            _ => {
                support_gap = true;
                residue.push(format!(
                    "claim: source {handle} disposition {} carries no weight",
                    record.acquisition.wire_name()
                ));
            }
        }
    }
    for assertion in &claim.precision {
        if let Err(item) = check_precision(assertion) {
            // The typed item is retained, not only its rendering: I21.7 records
            // the over-precise assertion itself so a consumer can tell a false
            // line anchor from a false causal mechanism.
            unsupported_precision.push(item.clone());
            residue.push(format!(
                "claim: unsupported precision asserted {} supports {}",
                item.asserted, item.highest_supported
            ));
        }
    }
    // Contradiction is determined from RELEVANT counterevidence under compatible
    // conditions, never from the mere presence of an attached counterclaim
    // identity. An identity is preserved either way, with a typed disposition
    // naming why it did or did not contradict; it contradicts only when it
    // contests this claim, is authorized, resolves to an authoritative record,
    // covers the claim's domain, is inside its frozen freshness boundary at the
    // audit instant, and carries evidentiary weight. Anything else stays explicit
    // as `NotVerifiableInScope` rather than being smoothed into support or
    // silently dropped. Absence of contradiction is never read as support.
    let mut resolutions: Vec<CounterclaimResolution> = Vec::new();
    for counterclaim_id in &claim.counterclaim_ids {
        let disposition = resolve_counterclaim(
            counterclaim_id,
            claim,
            portfolio,
            manifest,
            now_ms,
            &mut residue,
        );
        resolutions.push(CounterclaimResolution {
            counterclaim_id: counterclaim_id.clone(),
            disposition,
        });
    }
    let contradicting: Vec<&CounterclaimResolution> = resolutions
        .iter()
        .filter(|entry| entry.disposition.establishes_opposition())
        .collect();
    let unverifiable: Vec<&CounterclaimResolution> = resolutions
        .iter()
        .filter(|entry| !entry.disposition.establishes_opposition())
        .collect();
    let counterevidence: Vec<String> = claim.counterclaim_ids.clone();
    let unknowns: Vec<String> = claim.unknown_refs.clone();
    let precision_gap = !unsupported_precision.is_empty();
    // The terminal outcome is derived from the named dimensions, and every
    // dimension is recorded whether or not it failed. I21.8 requires the four
    // audit dimensions to be observed separately, and `#1765` requires the
    // precise reasons to survive into the release decision; a single `if/else`
    // chain that returns on the first hit discards exactly the findings a release
    // consumer needs. `dimensions` below is the record, and the chain only names
    // the terminal class.
    let identity_current = !resolutions.iter().any(|entry| {
        matches!(
            entry.disposition,
            CounterclaimDisposition::RelationStatementChanged
                | CounterclaimDisposition::RelationClaimMismatch
                | CounterclaimDisposition::NoFrozenClaimIdentity
                | CounterclaimDisposition::RelationDigestMismatch
                | CounterclaimDisposition::RelationSourceRevisionChanged
        )
    });
    // A material claim needs an identity that verifies, not merely one that is
    // present. `AuditedClaim.frozen_identities` is a caller-writable `Vec` of
    // plain structs, so a caller can push an identity whose `digest` is empty or
    // stale, or one frozen against different wording; checking only for presence
    // would let that self-declared value stand in for a proof. The recorded digest
    // is the recomputed one and is empty unless the identity proves out, so
    // `MethodArtifactAlignment` fails on exactly the same condition.
    //
    // A claim that cannot prove its identity is accounted for as an open material
    // claim rather than a supported one. Routing it through
    // `IncompleteAccounting` rather than a new terminal class keeps the public
    // five-class projection the only thing a release consumer has to read, while
    // the dimension records the real reason.
    // An identity that does not prove out leaves an empty recorded digest, so a
    // caller cannot substitute a self-declared one.
    let claim_identity = claim
        .frozen_identities
        .iter()
        .find(|identity| identity.claim_id == claim.claim_id);
    let claim_identity_verified = claim_identity.is_some_and(|identity| {
        identity.verify_integrity().is_ok() && identity.statement == claim.statement
    });
    let claim_identity_digest = if claim_identity_verified {
        claim_identity.map_or(String::new(), |identity| identity.digest.clone())
    } else {
        String::new()
    };
    let unfrozen_material_claim = claim.material && !claim_identity_verified && !outside_citation;
    // The dimensions the audit actually EXAMINED, recorded per verdict.
    //
    // A constant list of all eight would carry no information: it could not
    // distinguish "examined and passed" from "never examined", which is the whole
    // point of naming them. Each entry below is pushed at the point where the
    // audit genuinely looked at that property, so a consumer can tell a dimension
    // that was checked and found sound from one that was skipped. A dimension the
    // audit could not examine is simply absent, and `dimensions_complete` treats
    // absence as failure.
    let mut dimensions: Vec<AuditDimension> = vec![
        AuditDimension::ClaimIdentityCurrent,
        AuditDimension::MethodArtifactAlignment,
    ];
    // The citation partition examined reference verification for every citation,
    // and value verification for every citation that resolved.
    let mut examined_reference = !claim.citations.is_empty();
    let mut examined_value = false;
    for handle in &claim.citations {
        if manifest_intact && manifest.allows(handle) {
            examined_reference = true;
            if let Some(record) = portfolio.records.get(handle) {
                examined_value = true;
                let _ = record;
            }
        }
    }
    if examined_reference {
        dimensions.push(AuditDimension::ReferenceVerification);
    }
    if examined_value {
        dimensions.push(AuditDimension::ValueVerification);
    }
    // Specification compliance is examined only when there is a claim identity to
    // compare its scope against; without one, the audit has no specification.
    if claim_identity_verified {
        dimensions.push(AuditDimension::SpecificationCompliance);
    }
    // Counterevidence was examined exactly when at least one alleged counterclaim
    // was classified. A claim with none has not had the question asked, and saying
    // otherwise would be the vacuous truth the dimension name warns about.
    if !claim.counterclaim_ids.is_empty() {
        dimensions.push(AuditDimension::CounterevidenceExamined);
    }
    // Partition coherence is examined when both partitions could have seen a
    // handle, which is the only situation where they can disagree.
    if !claim.citations.is_empty() && !claim.counterclaim_ids.is_empty() {
        dimensions.push(AuditDimension::PartitionCoherence);
    }
    // Accounting completeness is examined once the claim's own bookkeeping has
    // been walked: its unknowns and its material/empty-citation state.
    dimensions.push(AuditDimension::AccountingComplete);
    dimensions.sort();
    dimensions.dedup();
    // The terminal outcome is DERIVED from the examined dimensions rather than
    // chosen by a precedence chain, so two independent failures both stay visible:
    // a verified contradiction alongside an outside-manifest citation reports the
    // contradiction, and the outside-manifest finding remains in `dimensions` and
    // in the residue. Reading the first matching arm of an `if/else` chain, by
    // contrast, silently discards whichever finding it did not reach.
    let reference_failed = examined_reference && outside_citation;
    let value_failed = examined_value && support_gap;
    let contradicted = !contradicting.is_empty();
    // One place decides how much support the claim actually has, so the weight,
    // precision and lineage gaps cannot each re-derive a different terminal class
    // and drift apart.
    let support_class = if stale_hit && supporting.is_empty() {
        ClaimOutcome::StaleLimited
    } else if supporting.is_empty() {
        ClaimOutcome::Unsupported
    } else {
        ClaimOutcome::PartiallySupported
    };
    let outcome = if contradicted {
        // A verified contradiction is the strongest finding and is never masked by
        // a weaker one; every other failure stays recorded alongside it.
        ClaimOutcome::Contradicted
    } else if reference_failed {
        ClaimOutcome::OutsideManifest
    } else if !unverifiable.is_empty() {
        ClaimOutcome::NotVerifiableInScope
    } else if value_failed || precision_gap || lineage_gap {
        support_class
    } else if stale_hit {
        ClaimOutcome::StaleLimited
    } else if !unknowns.is_empty()
        || unfrozen_material_claim
        || (claim.material && claim.citations.is_empty() && counterevidence.is_empty())
    {
        // An open material claim, an unfrozen one, or one with preserved unknowns
        // is not supported. This arm sits after the support gaps so a claim that
        // is both unsupported and unfrozen reports the support gap, which is the
        // more specific finding.
        ClaimOutcome::IncompleteAccounting
    } else if !identity_current {
        // A claim whose wording moved after the opposition was frozen cannot be
        // released as supported, and a verdict reached through a stale claim
        // identity is not a verdict about this claim at all. Checked last, because
        // it is the most specific reason and the other findings stay recorded
        // either way.
        ClaimOutcome::NotVerifiableInScope
    } else {
        ClaimOutcome::Supported
    };
    let mut relation_digests: Vec<String> = claim
        .opposition_relations
        .iter()
        .map(|relation| relation.digest.clone())
        .collect();
    relation_digests.sort();
    relation_digests.dedup();
    let grade_ceiling = decide_grade(&supporting, &claim.domain, now_ms).ceiling;
    evidence_map.sort();
    outside_citations.sort();
    outside_citations.dedup();
    unweighted_citations.sort();
    unweighted_citations.dedup();
    residue.sort();
    let mut counter_sorted = counterevidence;
    counter_sorted.sort();
    let mut unknowns_sorted = unknowns;
    unknowns_sorted.sort();
    let mut sorted_resolutions = resolutions;
    sorted_resolutions.sort_by(|left, right| {
        left.counterclaim_id
            .cmp(&right.counterclaim_id)
            .then_with(|| {
                left.disposition
                    .wire_name()
                    .cmp(right.disposition.wire_name())
            })
    });
    ClaimVerdict {
        claim_id: claim.claim_id.clone(),
        outcome,
        residue,
        unsupported_precision,
        counterevidence: counter_sorted,
        counterclaim_resolutions: sorted_resolutions,
        unknowns: unknowns_sorted,
        grade_ceiling,
        evidence_map,
        dimensions,
        relation_digests,
        claim_identity_digest,
        outside_citations,
        unweighted_citations,
    }
}

/// Complete frozen portfolio result: exact partial/exhausted states, typed
/// abstention, cancellation/deadline, unknown/reconcile, and invalid/internal
/// results. No task completion, canonical write, semantic promotion or
/// execution authority is carried here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortfolioOutcome {
    /// Frozen complete portfolio under the manifest digest.
    Complete {
        /// Digest of the authorizing manifest.
        manifest_digest: String,
    },
    /// Exact partial portfolio with omissions.
    Partial {
        /// Accounted omissions in frozen order.
        omissions: Vec<String>,
    },
    /// Exhausted budget frontier with the frontier note.
    Exhausted {
        /// Frontier note where enumeration stopped.
        frontier: String,
    },
    /// Evidence-backed abstention with an I7.20 reason code.
    Abstained {
        /// Reason code for the abstention.
        reason_code: String,
    },
    /// Cancelled operation; reconciliation runs through the original
    /// operation, never a blind retry.
    Cancelled {
        /// Original operation identity.
        operation_id: String,
    },
    /// Unknown outcome requiring reconciliation through the original
    /// operation.
    UnknownOutcome {
        /// Original operation identity.
        reconcile_operation: String,
    },
    /// Typed invalid result with field-named errors.
    Invalid {
        /// Bounded error descriptions.
        errors: Vec<String>,
    },
}

impl PortfolioOutcome {
    /// Whether this outcome is finished work. Only a complete frozen
    /// portfolio is finished: partial, exhausted, abstained, cancelled,
    /// unknown and invalid outcomes never decode as complete.
    pub const fn is_finished(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    /// Maps an exchange completion disposition to its honest portfolio
    /// outcome class. Only dispositions that may close an inquiry map to
    /// completion; every other disposition stays explicitly open.
    pub fn from_disposition(disposition: CompletionDisposition, detail: String) -> Self {
        match disposition {
            CompletionDisposition::AnsweredWithSupportedResult
            | CompletionDisposition::NoMatchInCompleteScope => Self::Complete {
                manifest_digest: detail,
            },
            CompletionDisposition::Cancelled => Self::Cancelled {
                operation_id: detail,
            },
            CompletionDisposition::IncompleteCoverage
            | CompletionDisposition::NoNewUsefulEvidence
            | CompletionDisposition::StaleSourceOrIndex
            | CompletionDisposition::SourceUnavailable
            | CompletionDisposition::PolicyOrDisclosureDenied
            | CompletionDisposition::Inconclusive => Self::Partial {
                omissions: vec![detail],
            },
        }
    }
}

/// Verifies that a terminal outcome never decodes as complete: partial,
/// exhausted, abstained, cancelled, unknown and invalid outcomes fail closed
/// when presented as finished work.
pub fn require_finished(outcome: &PortfolioOutcome) -> Result<&str, PortfolioError> {
    match outcome {
        PortfolioOutcome::Complete { manifest_digest } => Ok(manifest_digest.as_str()),
        _ => Err(PortfolioError::InvalidTerminal {
            field: "portfolio.outcome",
        }),
    }
}
