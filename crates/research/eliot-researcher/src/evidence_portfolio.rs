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
//!
//! Scoped absence is a *cross-checked* verdict, not a bare caller-authored
//! claim. A [`NoMatchEvaluation`] carries the three commitments the frozen owner
//! map of I21.6 names — the scope/denominator owner's snapshot and revision, the
//! source/index owner's record and content commitments, and the
//! query/evaluator owner's exact predicate bytes, identities, receipt, fence and
//! currentness bounds — and [`assess_absence`] re-derives every one of them
//! against the coverage accounting, the vetted records and the authorized
//! manifest it is handed. A member name copied out of the accounting no longer
//! proves anything: a member reaches the closed set only through a complete
//! ordered join onto a real record, a manifest that binds it and a recomputed
//! per-member result identity.
//!
//! What that does **not** buy is owner-boundness in the provenance sense, and
//! this module does not claim it. None of the issuer, evaluator, admission,
//! fence or work-scope identities inside the record is verified against an
//! external authority, because this repository holds no owner registry to verify
//! one against. The record is internally self-consistent and cross-checked
//! against the manifest and the account the caller also supplies; the residual
//! trust boundary is exactly those inputs. See the limitation note on
//! [`NoMatchEvaluation`] for the full statement.
//!
//! The assessor performs no I/O, calls no provider and no index, and the
//! ordinary Researcher route binds no evaluation and no manifest at all, so the
//! negative is `Unproven` until a live owner supplies one. That residual is
//! recorded rather than closed: a fabricated evaluator route would be a second
//! query engine.

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

/// Whether an owner-issued evaluation supports a claim about *now* or only a
/// claim about the past.
///
/// A historical evaluation says what was true at its owner-recorded observation
/// time. Reusing it for a current negative would silently widen a past
/// observation into a present one, so [`assess_absence`] accepts only
/// [`NoMatchApplicability::Current`] and the distinction is carried in the
/// evaluation's own identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoMatchApplicability {
    /// The evaluation describes the past and never grounds a current negative.
    Historical,
    /// The evaluation is current across its declared window and may ground a
    /// scoped negative.
    Current,
}

impl NoMatchApplicability {
    /// Stable wire spelling of this applicability. The identity preimages must
    /// not depend on a Rust variant name; see the [`SourceDisposition`] impl for
    /// the single-owner rationale.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Historical => "HISTORICAL",
            Self::Current => "CURRENT",
        }
    }
}

impl Serialize for NoMatchApplicability {
    /// Serializes as the same stable wire spelling [`Self::wire_name`] returns.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.wire_name())
    }
}

/// The five separately-established facts a scoped negative stands on.
///
/// They are distinct obligations, not a summary: an enumeration that completed is
/// not an acquisition that closed, an acquisition that closed is not a current
/// source, a current source is not an evaluated predicate, and an evaluated
/// predicate is not a predicate that returned no match. I21.6/I21.9 keep them
/// apart for the same reason — an exhausted or partial route never decodes as
/// completeness, and completeness alone never decodes as a negative. None of
/// these five substitutes for another, so [`NoMatchEvaluation`] records them as
/// a set and [`assess_absence`] names each one that is missing.
///
/// That is a claim about *reporting*, not about establishment. Each dimension is
/// one entry in an issuer-supplied set; nothing here re-derives
/// `EnumerationCompleted` from an enumeration attestation, or `SourceIndexCurrent`
/// from an index snapshot, or `PredicateReturnedNoMatch` from anything the
/// evaluator actually returned. Establishing them is the live owner's
/// obligation, and this crate can only require that all five were asserted. See
/// the limitation note on [`NoMatchEvaluation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoMatchDimension {
    /// The finite denominator was enumerated in full, without truncation.
    EnumerationCompleted,
    /// Every member's acquisition closed and each closed member resolves to
    /// exactly one vetted immutable record.
    MemberAcquisitionClosed,
    /// The source and index the predicate ran against are current.
    SourceIndexCurrent,
    /// The named predicate was actually executed against the frozen scope.
    PredicateEvaluated,
    /// The executed predicate returned no match for that member.
    PredicateReturnedNoMatch,
}

impl NoMatchDimension {
    /// Every dimension, in canonical order. A complete scoped negative
    /// establishes all five and substitutes none for another.
    pub const ALL: [Self; 5] = [
        Self::EnumerationCompleted,
        Self::MemberAcquisitionClosed,
        Self::SourceIndexCurrent,
        Self::PredicateEvaluated,
        Self::PredicateReturnedNoMatch,
    ];

    /// Stable wire spelling of this dimension; see
    /// [`NoMatchApplicability`]'s `Serialize` impl for the single-owner
    /// rationale.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EnumerationCompleted => "ENUMERATION_COMPLETED",
            Self::MemberAcquisitionClosed => "MEMBER_ACQUISITION_CLOSED",
            Self::SourceIndexCurrent => "SOURCE_INDEX_CURRENT",
            Self::PredicateEvaluated => "PREDICATE_EVALUATED",
            Self::PredicateReturnedNoMatch => "PREDICATE_RETURNED_NO_MATCH",
        }
    }

    /// The dimensions `established` does not contain, in canonical order. An
    /// empty result means every dimension is in the set the issuer supplied, and
    /// nothing more than that: this is a pure projection of
    /// [`NoMatchEvaluation::established`], which is an issuer-authored set that
    /// no code path in this crate independently establishes. It cannot report
    /// that a caller said so, because saying so is all there is to report; what
    /// it does guarantee is that no dimension silently stands in for another, so
    /// an incomplete set is named dimension by dimension rather than summarised.
    #[must_use]
    pub fn missing(established: &BTreeSet<Self>) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|dimension| !established.contains(dimension))
            .collect()
    }
}

impl Serialize for NoMatchDimension {
    /// Serializes as the same stable wire spelling [`Self::wire_name`] returns.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.wire_name())
    }
}

/// One owner-issued, identity-bearing per-member predicate result.
///
/// A member *name* is not a result. This record names the exact declared member,
/// the canonical commitment of the exact vetted record the predicate read
/// ([`SourceRecord::digest`] under [`SOURCE_RECORD_DIGEST_DOMAIN`]), the digest of
/// the exact content bytes, and the result identity binding all of it to the
/// predicate, index revision and source revision it was produced under.
/// [`NoMatchEvaluation::result_identity`] is the single recipe for that identity,
/// and the record's own shape check recomputes it from the evaluation's
/// commitments on every construction and on every readback through
/// [`AbsencePreconditions::derive`], so a member list copied out of the
/// accounting cannot produce one and neither can a result carried over from
/// another predicate, index revision, source revision or record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemberNoMatchResult {
    /// Declared denominator member this result answers for.
    pub member: String,
    /// Canonical commitment of the exact vetted record the predicate read.
    pub record_digest: String,
    /// Digest of the exact content bytes the predicate read.
    pub content_digest: String,
    /// Identity of this result under the evaluation's own commitments.
    pub result_identity: String,
}

impl MemberNoMatchResult {
    /// Total order used to freeze results deterministically. Ordering is by the
    /// whole result, so a duplicated `member` with different content still sorts
    /// deterministically and both copies stay bound until the duplicate check
    /// rejects them.
    fn canonical_order(&self, other: &Self) -> std::cmp::Ordering {
        self.member
            .cmp(&other.member)
            .then_with(|| self.record_digest.cmp(&other.record_digest))
            .then_with(|| self.content_digest.cmp(&other.content_digest))
            .then_with(|| self.result_identity.cmp(&other.result_identity))
    }
}

/// Declared wire schema of [`NoMatchEvaluation`].
///
/// The `schema_version` field is validated against this constant, so a record
/// from a different revision of the evidence shape is refused instead of being
/// read through field names that may have moved.
pub const NO_MATCH_EVALUATION_SCHEMA_VERSION: &str = "no-match-evaluation/v1";

/// Declared identity domain of [`NoMatchEvaluation`].
///
/// `v1` is the first declared form. It binds the predicate, issuer, evaluator,
/// admission receipt, State Fence, work scope, scope/snapshot/denominator/manifest
/// commitments, index and source revisions, owner-recorded observation and
/// currentness bounds, applicability, the per-member result identities, the
/// established-dimension set and the proof ceiling, so a record altered in any of
/// those respects stops verifying against itself.
pub const NO_MATCH_EVALUATION_DIGEST_DOMAIN: &str = "no-match-evaluation/v1";

/// The single canonical encoder input for [`NoMatchEvaluation`].
///
/// The record is borrowed whole; its `digest` field is excluded by
/// `#[serde(skip)]` on the field itself, so the exclusion is declared next to the
/// field it excludes rather than reconstructed at each call site.
#[derive(Serialize)]
struct NoMatchEvaluationDigestInput<'a> {
    /// Declared identity domain, bound into the bytes.
    domain: &'static str,
    /// The whole owner-issued record, minus its own digest.
    evaluation: &'a NoMatchEvaluation,
}

/// One owner-issued, identity-bearing record of a bounded predicate evaluation
/// over a frozen denominator.
///
/// This is neither a verdict nor a flag: it is the *identity* of a completed
/// evaluation run, and the assessor cross-checks it. The record carries the three
/// commitments the frozen owner map of I21.6 names, and
/// [`AbsenceVerdict::Proven`] requires all three to hold:
///
/// * the **scope/denominator owner** contributes [`Self::scope_digest`],
///   [`Self::scope_revision`], [`Self::denominator_digest`],
///   [`Self::manifest_digest`] and [`Self::manifest_revision`]. What is actually
///   *checked* is narrow and stated here rather than implied: `scope_digest` is
///   joined to the frozen scope digest the assessment was scoped to,
///   `manifest_digest`/`manifest_revision` are joined to the authorized manifest
///   presented alongside, and `denominator_digest` is joined to that manifest's
///   own denominator digest. `scope_revision` is carried and identity-bound but
///   compared to nothing, and none of the four is joined to the accounting's
///   actual member set — `account.digest()` covers the denominator, and no field
///   here is matched against it.
/// * the **source/index owner** contributes [`Self::index_revision`],
///   [`Self::source_revision`], the owner-recorded
///   [`Self::observed_at_ms`]/[`Self::current_until_ms`] bounds and, per member,
///   the [`MemberNoMatchResult`] record and content digests. The per-member
///   commitments are the ones genuinely re-derived against the vetted record;
///   `index_revision` and `source_revision` are bound into the result identities
///   and echoed in diagnostics, but no index snapshot is joined to either.
/// * the **query/evaluator owner** contributes the exact predicate bytes behind
///   [`Self::predicate_id`]/[`Self::predicate_revision`]/[`Self::predicate_form`],
///   the issuer and evaluator identities and revisions, the admitted receipt, the
///   State Fence and work scope, and the five separately-established
///   [`NoMatchDimension`]s in [`Self::established`]. The predicate bytes are
///   re-hashed; the issuer, evaluator, receipt, fence, work scope and the five
///   dimensions are shape-validated and bound into the record's own identity, and
///   nothing further.
///
/// Researcher only validates and derives from it. Nothing here calls a provider,
/// an index or a search engine: the evaluation arrives as a pure input and
/// [`assess_absence`] reads it without performing I/O.
///
/// Copying the closed member IDs into a free-form list cannot produce this
/// record: a [`MemberNoMatchResult`] needs a [`SourceRecord::digest`] that
/// matches the exact vetted record, a content digest that matches that record's
/// bytes, and a result identity recomputed from the predicate, index revision and
/// source revision actually in force.
///
/// # What this does not establish
///
/// This record is internally self-consistent and cross-checked against the
/// manifest and the accounting the caller presents. It is **not** owner-bound in
/// the provenance sense, and this crate cannot make it so, because there is
/// nothing here to bind it to: no issuer registry, no admission ledger, no
/// signature and no externally held reference digest exists in this repository
/// against which [`Self::issuer_id`], [`Self::evaluator_id`],
/// [`Self::admission_receipt_id`] or [`Self::fence`] could be checked.
/// [`StateFence::validate`] confirms a non-zero resource generation and nothing
/// more, and [`Self::verify_integrity`] compares the record against its own
/// bytes.
///
/// The consequence is worth stating as a bound rather than leaving to be
/// discovered: a caller that controls the source records, the authorized
/// manifest and the clock can mint a fully self-consistent evaluation for members
/// it never actually searched, and the assessor will return
/// [`AbsenceVerdict::Proven`]. Every one of those three inputs is a parameter of
/// [`AbsencePreconditions::derive`], so the residual trust boundary is exactly
/// the records, the manifest and `now_ms`.
///
/// Closing that boundary needs infrastructure this repository does not have: an
/// admission owner that holds the issuer identity and the admitted receipt, and
/// a denominator owner that issues the exact finite member set and its snapshot
/// digest as a commitment somebody other than the caller can verify. Until one
/// exists, this record is evidence that a consistent account was presented, not
/// evidence that a predicate was run — the same named-owner-absent residual
/// recorded for #1768/#1948/#1949. Fabricating a stand-in for that owner inside
/// this module would be a second query engine, so the boundary is stated instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NoMatchEvaluation {
    /// Declared wire schema of this evidence shape.
    pub schema_version: String,
    /// Exact identity of the predicate that was evaluated.
    pub predicate_id: String,
    /// Exact revision of that predicate.
    pub predicate_revision: String,
    /// Exact canonical predicate/query bytes the evaluator executed.
    ///
    /// The predicate commitment [`Self::predicate_digest`] is recomputed from
    /// this text and the two identity fields, so the commitment cannot be a
    /// repeated string describing bytes nobody holds.
    pub predicate_form: String,
    /// Owner that issued this record.
    pub issuer_id: String,
    /// Exact identity of the evaluator that executed the predicate.
    pub evaluator_id: String,
    /// Exact evaluator revision the run was produced under.
    pub evaluator_revision: String,
    /// Admitted receipt identity for this evaluation.
    pub admission_receipt_id: String,
    /// State fence the evaluation was admitted under.
    pub fence: StateFence,
    /// Exact work scope the evaluation was bounded to.
    pub work_scope: String,
    /// Digest of the frozen scope/denominator snapshot.
    pub scope_digest: String,
    /// Revision of that scope snapshot.
    pub scope_revision: String,
    /// Canonical denominator digest the member set was frozen from.
    pub denominator_digest: String,
    /// Digest of the authorized manifest covering the frozen members.
    pub manifest_digest: String,
    /// Revision of that authorized manifest.
    pub manifest_revision: u64,
    /// Revision of the source/index the predicate ran against.
    pub index_revision: String,
    /// Revision of the source corpus the predicate ran against.
    pub source_revision: String,
    /// Owner-recorded observation time in Unix milliseconds.
    ///
    /// This is the owner clock, not a caller-supplied `now_ms`.
    /// [`AbsencePreconditions::derive`] requires it to be at or after every
    /// joined record's retrieval time, to be at or before the caller's assessment
    /// time, and to sit inside the declared currentness window.
    pub observed_at_ms: i64,
    /// Owner-declared last instant, in Unix milliseconds, at which this
    /// evaluation was still current.
    pub current_until_ms: i64,
    /// Whether this evaluation grounds a current claim or only a historical one.
    pub applicability: NoMatchApplicability,
    /// Per-member owner-issued no-match results, in canonical member order.
    ///
    /// The coverage this record claims *is* this set: it must equal the set of
    /// members the accounting closed that resolve to a compatible vetted record,
    /// exactly. There is no separate count that could disagree with it.
    pub results: Vec<MemberNoMatchResult>,
    /// The five separately-established facts, none substituting for another.
    pub established: BTreeSet<NoMatchDimension>,
    /// Proof ceiling the negative may not exceed; `None` is unknown coverage,
    /// never unrestricted.
    pub proof_ceiling_grade: Option<u8>,
    /// Frozen digest over the whole record shape.
    ///
    /// Excluded from its own preimage by `#[serde(skip)]`, so the digest is the
    /// only field on this struct that is not part of the identity it certifies.
    #[serde(skip)]
    pub digest: String,
}

/// Named constructor arguments for [`NoMatchEvaluation::issue`]. Named fields
/// block transposition; text uses concrete `String`.
#[derive(Clone, Debug)]
pub struct NoMatchEvaluationParams {
    /// Exact identity of the predicate.
    pub predicate_id: String,
    /// Exact predicate revision.
    pub predicate_revision: String,
    /// Exact canonical predicate bytes.
    pub predicate_form: String,
    /// Issuing owner.
    pub issuer_id: String,
    /// Evaluator identity.
    pub evaluator_id: String,
    /// Evaluator revision.
    pub evaluator_revision: String,
    /// Admitted receipt identity.
    pub admission_receipt_id: String,
    /// Admission State Fence.
    pub fence: StateFence,
    /// Work scope.
    pub work_scope: String,
    /// Frozen scope digest.
    pub scope_digest: String,
    /// Scope snapshot revision.
    pub scope_revision: String,
    /// Denominator digest.
    pub denominator_digest: String,
    /// Authorized manifest digest.
    pub manifest_digest: String,
    /// Authorized manifest revision.
    pub manifest_revision: u64,
    /// Index revision.
    pub index_revision: String,
    /// Source corpus revision.
    pub source_revision: String,
    /// Owner-recorded observation time.
    pub observed_at_ms: i64,
    /// Owner-declared currentness bound.
    pub current_until_ms: i64,
    /// Applicability.
    pub applicability: NoMatchApplicability,
    /// Per-member results.
    pub results: Vec<MemberNoMatchResult>,
    /// Established dimensions.
    pub established: BTreeSet<NoMatchDimension>,
    /// Proof ceiling.
    pub proof_ceiling_grade: Option<u8>,
}

impl NoMatchEvaluation {
    /// Validates and freezes one owner-issued evaluation record.
    ///
    /// Results are frozen into canonical member order here, so arrival order
    /// never affects the identity. Every result identity is recomputed from this
    /// record's own predicate, index revision and source revision and must equal
    /// the value supplied, so the issuer cannot ship a result carried over from
    /// another predicate, index revision or source revision. To produce the values
    /// this constructor checks, call [`Self::predicate_digest_of`] and then
    /// [`Self::result_identity`] for every member.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank or malformed identity, revision, digest,
    /// work scope or result member, [`PortfolioError::Conflict`] for an inverted
    /// currentness window, a stale schema revision or a result identity that is
    /// not the identity this record's own commitments imply,
    /// [`PortfolioError::Duplicate`] for a repeated member,
    /// [`PortfolioError::IncompleteDenominator`] for an empty result set, which no
    /// closed population produces, [`PortfolioError::UnknownGrade`] for a ceiling
    /// outside the canonical ladder, and [`PortfolioError::Unencodable`] when the
    /// record cannot be encoded into its declared identity domain.
    pub fn issue(mut params: NoMatchEvaluationParams) -> Result<Self, PortfolioError> {
        params.results.sort_by(MemberNoMatchResult::canonical_order);
        let mut evaluation = Self {
            schema_version: NO_MATCH_EVALUATION_SCHEMA_VERSION.to_owned(),
            predicate_id: params.predicate_id,
            predicate_revision: params.predicate_revision,
            predicate_form: params.predicate_form,
            issuer_id: params.issuer_id,
            evaluator_id: params.evaluator_id,
            evaluator_revision: params.evaluator_revision,
            admission_receipt_id: params.admission_receipt_id,
            fence: params.fence,
            work_scope: params.work_scope,
            scope_digest: params.scope_digest,
            scope_revision: params.scope_revision,
            denominator_digest: params.denominator_digest,
            manifest_digest: params.manifest_digest,
            manifest_revision: params.manifest_revision,
            index_revision: params.index_revision,
            source_revision: params.source_revision,
            observed_at_ms: params.observed_at_ms,
            current_until_ms: params.current_until_ms,
            applicability: params.applicability,
            results: params.results,
            established: params.established,
            proof_ceiling_grade: params.proof_ceiling_grade,
            digest: String::new(),
        };
        evaluation.validate_shape()?;
        evaluation.digest = evaluation.canonical_digest()?;
        Ok(evaluation)
    }

    /// The one recipe for the predicate commitment, callable before the record
    /// exists.
    ///
    /// An issuer has to compute this commitment *before* it can compute a
    /// [`Self::result_identity`], and therefore before [`Self::issue`] can accept
    /// the result at all. Exposing the recipe as an associated function rather
    /// than only as a method on an already-constructed value is what makes the
    /// issuing sequence expressible; [`Self::predicate_digest`] is the same recipe
    /// applied to a value's own fields, so the issuer's preimage and the
    /// validator's recomputation cannot drift.
    #[must_use]
    pub fn predicate_digest_of(
        predicate_id: &str,
        predicate_revision: &str,
        predicate_form: &str,
    ) -> String {
        let mut preimage = String::from("no-match-predicate/v1;");
        push_field(&mut preimage, "predicate_id", predicate_id);
        push_field(&mut preimage, "predicate_revision", predicate_revision);
        push_field(&mut preimage, "predicate_form", predicate_form);
        freeze(&preimage)
    }

    /// The one recipe for a per-member result identity.
    ///
    /// It binds the exact predicate commitment, the exact member, the canonical
    /// commitment of the exact vetted record, the exact content bytes, the index
    /// revision and the source revision. The evaluator owner calls this to issue a
    /// result; the record's own shape check recomputes it for every result the
    /// record carries, on construction and again on the readback
    /// [`AbsencePreconditions::derive`] performs, so the two cannot drift and a
    /// result cannot be carried across a predicate, revision or record boundary.
    #[must_use]
    pub fn result_identity(
        predicate_digest: &str,
        member: &str,
        record_digest: &str,
        content_digest: &str,
        index_revision: &str,
        source_revision: &str,
    ) -> String {
        let mut preimage = String::from("no-match-result/v1;");
        push_field(&mut preimage, "predicate", predicate_digest);
        push_field(&mut preimage, "member", member);
        push_field(&mut preimage, "record", record_digest);
        push_field(&mut preimage, "content", content_digest);
        push_field(&mut preimage, "index_revision", index_revision);
        push_field(&mut preimage, "source_revision", source_revision);
        freeze(&preimage)
    }

    /// Recomputes this record's predicate commitment from the exact bytes the
    /// evaluator executed, over the declared `no-match-predicate/v1` domain.
    ///
    /// This is a recomputation, not a stored claim: the commitment is never a
    /// field on the record, so it cannot be repeated independently of the
    /// predicate it describes.
    #[must_use]
    pub fn predicate_digest(&self) -> String {
        Self::predicate_digest_of(
            &self.predicate_id,
            &self.predicate_revision,
            &self.predicate_form,
        )
    }

    /// The dimensions this record leaves unestablished, in canonical order.
    #[must_use]
    pub fn missing_dimensions(&self) -> Vec<NoMatchDimension> {
        NoMatchDimension::missing(&self.established)
    }

    /// Whether this record is bound to exactly this scope snapshot.
    #[must_use]
    pub fn covers_scope(&self, frozen_scope_digest: &str) -> bool {
        self.scope_digest == frozen_scope_digest
    }

    /// The members this record carries an owner-issued result for, in canonical
    /// member order.
    #[must_use]
    pub fn evaluated_members(&self) -> Vec<String> {
        self.results
            .iter()
            .map(|result| result.member.clone())
            .collect()
    }

    /// Validates the record's shape, independently of its frozen digest.
    ///
    /// This is the only place the canonical result order is enforced, and it is
    /// enforced here rather than only in [`Self::issue`] because every field on
    /// this struct is public: a struct literal bypasses the constructor, and
    /// [`AbsencePreconditions::derive`] accepts any value of this type. Since the
    /// canonical encoder sorts object keys but preserves array order
    /// (`eliot-contracts::canonical_json_bytes`), two otherwise identical
    /// evaluations whose `results` arrive in different orders would hash
    /// differently, so exact replay would not be byte-stable. Refusing the
    /// unordered shape here is what earns that property rather than inheriting it
    /// from the constructor.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity/revision, a malformed digest or
    /// work scope, a non-positive observation time, an unvalidated State Fence or
    /// an out-of-ladder proof ceiling; [`PortfolioError::Conflict`] for a stale
    /// schema revision, an inverted currentness window, a result identity that
    /// is not the identity this record's own commitments imply, or a `results`
    /// sequence that is not in canonical order;
    /// [`PortfolioError::Duplicate`] for a repeated member; and
    /// [`PortfolioError::IncompleteDenominator`] for an empty result set.
    fn validate_shape(&self) -> Result<(), PortfolioError> {
        if self.schema_version != NO_MATCH_EVALUATION_SCHEMA_VERSION {
            return Err(PortfolioError::Conflict {
                field: "no_match_evaluation.schema_version",
            });
        }
        text(&self.predicate_id, "no_match_evaluation.predicate_id")?;
        text(
            &self.predicate_revision,
            "no_match_evaluation.predicate_revision",
        )?;
        text(&self.predicate_form, "no_match_evaluation.predicate_form")?;
        text(&self.issuer_id, "no_match_evaluation.issuer_id")?;
        text(&self.evaluator_id, "no_match_evaluation.evaluator_id")?;
        text(
            &self.evaluator_revision,
            "no_match_evaluation.evaluator_revision",
        )?;
        text(
            &self.admission_receipt_id,
            "no_match_evaluation.admission_receipt_id",
        )?;
        self.fence.validate().map_err(|_| PortfolioError::Blank {
            field: "no_match_evaluation.fence",
        })?;
        text(&self.work_scope, "no_match_evaluation.work_scope")?;
        reject_vague(&self.work_scope, "no_match_evaluation.work_scope")?;
        digest(&self.scope_digest, "no_match_evaluation.scope_digest")?;
        text(&self.scope_revision, "no_match_evaluation.scope_revision")?;
        digest(
            &self.denominator_digest,
            "no_match_evaluation.denominator_digest",
        )?;
        digest(&self.manifest_digest, "no_match_evaluation.manifest_digest")?;
        text(&self.index_revision, "no_match_evaluation.index_revision")?;
        text(&self.source_revision, "no_match_evaluation.source_revision")?;
        if self.observed_at_ms <= 0 {
            return Err(PortfolioError::Blank {
                field: "no_match_evaluation.observed_at_ms",
            });
        }
        if self.current_until_ms < self.observed_at_ms {
            return Err(PortfolioError::Conflict {
                field: "no_match_evaluation.current_until_ms",
            });
        }
        if self.results.is_empty() {
            return Err(PortfolioError::IncompleteDenominator {
                field: "no_match_evaluation.results",
            });
        }
        let predicate_digest = self.predicate_digest();
        // Canonical order is a shape requirement, not a convenience of the
        // constructor: `results` is public, `derive` accepts any value of this
        // type, and the canonical encoder keeps array order, so an unordered
        // sequence is refused here rather than hashed into a second identity for
        // the same evaluation. A strictly *decreasing* pair is the shape check; an
        // adjacent equal pair is not, so a repeated member still falls through to
        // the duplicate check below and keeps reporting `Duplicate` rather than
        // being reported here as an ordering conflict.
        if self
            .results
            .windows(2)
            .any(|pair| pair[0].canonical_order(&pair[1]).is_gt())
        {
            return Err(PortfolioError::Conflict {
                field: "no_match_evaluation.results",
            });
        }
        let mut seen = BTreeSet::new();
        for result in &self.results {
            text(&result.member, "no_match_result.member")?;
            digest(&result.record_digest, "no_match_result.record_digest")?;
            digest(&result.content_digest, "no_match_result.content_digest")?;
            digest(&result.result_identity, "no_match_result.result_identity")?;
            let expected = Self::result_identity(
                &predicate_digest,
                &result.member,
                &result.record_digest,
                &result.content_digest,
                &self.index_revision,
                &self.source_revision,
            );
            if result.result_identity != expected {
                return Err(PortfolioError::Conflict {
                    field: "no_match_result.result_identity",
                });
            }
            if !seen.insert(result.member.as_str()) {
                return Err(PortfolioError::Duplicate {
                    field: "no_match_result.member",
                });
            }
        }
        if let Some(ceiling) = self.proof_ceiling_grade {
            grade_name(ceiling)?;
        }
        Ok(())
    }

    /// Deterministic canonical bytes of the whole owner-issued record, with the
    /// stored digest excluded.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the record cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PortfolioError> {
        canonical_json_bytes(&NoMatchEvaluationDigestInput {
            domain: NO_MATCH_EVALUATION_DIGEST_DOMAIN,
            evaluation: self,
        })
        .map_err(|_| PortfolioError::Unencodable {
            field: "no_match_evaluation.canonical_body",
        })
    }

    /// Canonical digest recomputed from this value's own fields.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the record cannot be encoded.
    pub fn canonical_digest(&self) -> Result<String, PortfolioError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Recomputes the canonical digest and compares it with the frozen one.
    ///
    /// This is a self-consistency check, not a provenance check, and it is worth
    /// being exact about which one it is. It catches a *partial* rewrite — a
    /// record whose predicate, member result, source revision, evaluator
    /// evidence, fence, scope or ceiling was edited while `digest` was left
    /// alone. It does not and cannot catch a caller who recomputes `digest` to
    /// match the edited bytes, because `digest` is a public field and the
    /// recomputation is over exactly those bytes: a self-consistent rewrite
    /// verifies against itself, and no reference outside this value exists to
    /// say otherwise. What it establishes is that the value in hand is the value
    /// its own bytes describe; what it cannot establish is that any issuer ever
    /// issued it. See the limitation note on [`NoMatchEvaluation`].
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Unencodable`] when the record cannot be encoded
    /// and [`PortfolioError::InvalidDigest`] when the recomputation disagrees.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.canonical_digest()? != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "no_match_evaluation.digest",
            });
        }
        Ok(())
    }
}

/// A member the accounting closed but that cannot support an exact negative:
/// it carries no acquired source handle, so no vetted record can be joined to it.
pub const INCOMPATIBLE_MISSING_HANDLE: &str = "missing_acquired_handle";
/// A closing member names a handle for which no vetted record was supplied.
pub const INCOMPATIBLE_MISSING_RECORD: &str = "missing_vetted_record";
/// The record found under the handle is not itself that handle, so the accounting
/// handle and the record identity are not bound to each other.
pub const INCOMPATIBLE_SUBSTITUTED_RECORD: &str = "record_handle_mismatch";
/// A closing member carries no owner-issued per-member predicate result.
pub const INCOMPATIBLE_RESULT_MISSING: &str = "no_predicate_result";
/// The result's record commitment is not the recomputed commitment of the vetted
/// record the accounting closed with.
pub const INCOMPATIBLE_RESULT_RECORD_MISMATCH: &str = "result_record_digest_mismatch";
/// The result names content bytes the vetted record does not carry.
pub const INCOMPATIBLE_RESULT_CONTENT_MISMATCH: &str = "result_content_digest_mismatch";
/// The vetted record is past its frozen freshness boundary at assessment time.
pub const INCOMPATIBLE_RECORD_STALE: &str = "record_stale_at_assessment";
/// No authorized manifest was presented to cover the frozen members.
pub const INCOMPATIBLE_MANIFEST_ABSENT: &str = "no_authorized_manifest";
/// The authorized manifest does not allowlist the member's handle.
pub const INCOMPATIBLE_MANIFEST_REVOKED: &str = "handle_not_allowed_by_manifest";
/// The authorized manifest does not commit the exact record the accounting closed
/// with.
pub const INCOMPATIBLE_MANIFEST_UNBOUND: &str = "manifest_does_not_bind_record";
/// The authorized manifest presented is not the manifest, revision and denominator
/// the evaluation claims to have run under.
pub const INCOMPATIBLE_MANIFEST_MISMATCH: &str = "evaluation_manifest_mismatch";
/// The evaluation was observed before the record it claims to have read was
/// retrieved, so it cannot have read those bytes.
pub const INCOMPATIBLE_EVALUATION_PRECEDES_RECORD: &str = "evaluation_predates_record";
/// The evaluation's owner-recorded observation time is later than the assessment
/// time, so its currentness is not established.
///
/// This is a route-level condition, not a per-member one: the clock is a property
/// of the evaluation, so every closed member is affected identically.
/// [`AbsencePreconditions::derive`] retains it once and [`assess_absence`]
/// refuses on it as a route, rather than stamping it onto each member and
/// inflating a per-member count with one fault.
pub const INCOMPATIBLE_EVALUATION_NOT_OBSERVED: &str = "evaluation_observed_in_future";
/// The assessment time is past the owner-declared currentness bound of the
/// evaluation.
///
/// Route-level for the same reason as
/// [`INCOMPATIBLE_EVALUATION_NOT_OBSERVED`]: one clock bound, one refusal.
pub const INCOMPATIBLE_EVALUATION_EXPIRED: &str = "evaluation_expired_at_assessment";

/// The owner-bound preconditions one exact negative claim is assessed against.
///
/// Every field is derived from the exact coverage accounting, the vetted source
/// records behind it, the frozen scope snapshot the claim is scoped to, the
/// authorized manifest covering the frozen members and the owner-issued
/// [`NoMatchEvaluation`], and every field is private: a precondition set can only
/// be produced by [`AbsencePreconditions::derive`] over a real
/// [`CoverageAccount`], never written by a caller. [`assess_absence`] then
/// re-proves the digest before it reads any of the content and re-checks the
/// bound account digest against the account it is handed, so a set that was not
/// derived over that account is refused instead of believed. A caller supplies
/// evidence and derives a precondition set from it; it never writes one.
///
/// "Owner-bound" here means every field traces to a supplied input that was
/// itself re-proved or cross-checked — it does **not** mean any supplied input was
/// authorized by an owner. The records, the manifest and the clock are the
/// caller's; see the limitation note on [`NoMatchEvaluation`].
///
/// The record names which precondition is unmet through the bounded reason
/// [`AbsenceVerdict::Unproven`] retains, and its digest binds the preconditions
/// to that exact evidence, including which manifest authorised it. Its identity
/// domain is `absence-preconditions/v2`: `v1` proved only record staleness,
/// admitted a closing member with no handle, no record, a substituted handle or
/// no authorized manifest, and bound a caller-authored member list in place of a
/// result identity. The field set and the bytes both changed, so the domain says
/// so.
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
    /// Members the accounting closed but whose join to a current, owner-issued
    /// predicate result over the exact record behind them is incomplete, each
    /// paired with the specific unmet join. Every reason is one of the per-member
    /// `INCOMPATIBLE_*` constants: a reason here always names a fact about
    /// *this member*, never a fact about the route as a whole.
    incompatible: Vec<(String, &'static str)>,
    /// Route-level conditions the bound evaluation does not meet, in the order
    /// [`AbsencePreconditions::derive`] checks them. These are facts about the
    /// evaluation as a whole rather than about any member, so they are retained
    /// here and refused once, instead of being stamped onto every closed member
    /// and inflating a per-member count with one fault.
    route_incompatible: Vec<&'static str>,
    /// Declared members the accounting closed *and* whose join to a compatible
    /// vetted record, authorized manifest and owner-issued result is complete.
    ///
    /// This is strictly smaller than "the members a closing disposition closed":
    /// a member whose record is stale, absent or substituted reaches
    /// [`Self::incompatible`] and is **not** counted here. [`Self::closed_by_account`]
    /// carries the disposition-only count so nothing has to infer one from the
    /// other.
    closed: Vec<String>,
    /// Declared members a closing disposition closed, before the join above is
    /// applied. Retained separately so a route-level reason can report how many
    /// members the accounting closed without over-reporting the post-join count.
    closed_by_account: usize,
    /// Digest of the authorized manifest the preconditions were derived against,
    /// or `None` when the route presented none. Bound into the preconditions
    /// digest so the retained set records *which* manifest authorised it rather
    /// than only the member classification that manifest happened to produce.
    manifest_digest: Option<String>,
    /// Weakest grade rank over the vetted records behind [`Self::closed`];
    /// `None` when any of them carries no grade, which is unknown rather than
    /// unrestricted.
    closed_grade_ceiling: Option<u8>,
    /// Candidates observed outside the frozen scope. They are counted so an empty
    /// eligible set stays distinguishable from an enumeration that never ran; they
    /// close no member and narrow no denominator.
    observed_outside_scope: usize,
    /// Frontier where a bounded enumeration stopped, when one applied.
    frontier: Option<String>,
    /// The bounded predicate evaluation bound to the requested query, when one
    /// exists. The research plane records acquisition dispositions, not per-member
    /// query predicate results, so an inquiry record binds none and the negative
    /// stays unproven.
    evaluation: Option<NoMatchEvaluation>,
    /// Digest over the preconditions.
    digest: String,
}

impl AbsencePreconditions {
    /// Derives the preconditions of one exact negative claim from the exact
    /// accounting, the vetted records behind it, the authorized manifest covering
    /// them, the frozen snapshot and the owner-issued evaluation.
    ///
    /// A closing member reaches [`Self::closed`] only when every join below
    /// holds, and otherwise lands in [`Self::incompatible`] carrying the specific
    /// reason, in this order: an acquired handle exists; a vetted record exists
    /// under it; that record carries the same handle; an owner-issued per-member
    /// result exists; that result's record commitment is the recomputed commitment
    /// of that record; that result's content digest is that record's content
    /// digest; the record is current at `now_ms`; an authorized manifest was
    /// presented; that manifest is the one the evaluation names; it allowlists the
    /// handle; it binds the exact record; and the evaluation was observed no
    /// earlier than the record was retrieved. All twelve are facts about one
    /// member.
    ///
    /// Which of them need an evaluation is not "from here on": the per-member
    /// result joins and the manifest joins apply only when the route bound an
    /// evaluation, while the handle, record, handle-match and record-currentness
    /// joins apply either way. A route that binds no evaluation therefore still
    /// refuses a member with no handle, no record, a substituted handle or a
    /// stale record, and closes its members on the accounting and the records
    /// alone. Two further conditions — the evaluation observed after `now_ms`, and
    /// the evaluation expired at `now_ms` — are facts about the evaluation rather
    /// than about any member, so they are retained once in
    /// [`Self::route_incompatible`] and not per member.
    ///
    /// A presented manifest is read back before any of its content is used, so a
    /// manifest whose stored digest never matched its own fields cannot
    /// authorise anything here.
    ///
    /// The owner's clock and the caller's `now_ms` are checked against each other
    /// rather than either alone: the evaluation carries its own observation time
    /// and currentness bound, its observation time must be at or after every joined
    /// record's retrieval time and at or before `now_ms`, and `now_ms` must be at
    /// or before that currentness bound.
    ///
    /// # What this does not establish
    ///
    /// `records`, `manifest` and `now_ms` are all parameters here, and nothing in
    /// this function verifies that the records were acquired, that the manifest
    /// was authorized by anything, or that the clock is the owner's. See the
    /// limitation note on [`NoMatchEvaluation`].
    ///
    /// # Errors
    ///
    /// Returns a digest, field or grade error for a malformed frozen-scope digest,
    /// manifest or evaluation, [`PortfolioError::InvalidDigest`] when a supplied
    /// manifest or evaluation no longer re-proves its own identity,
    /// [`PortfolioError::Conflict`] when a result identity is not the identity its
    /// own commitments imply or when a result names a member the accounting never
    /// closed, and [`PortfolioError::IncompleteDenominator`] for an evaluation
    /// that names no member, which no closed population produces.
    pub fn derive(
        account: &CoverageAccount,
        records: &BTreeMap<String, SourceRecord>,
        manifest: Option<&AuthorizedManifest>,
        now_ms: i64,
        frozen_scope_digest: &str,
        evaluation: Option<NoMatchEvaluation>,
    ) -> Result<Self, PortfolioError> {
        digest(frozen_scope_digest, "absence.frozen_scope_digest")?;
        // The manifest is read back on the same footing as the evaluation. Without
        // this, a caller could present a manifest whose stored `digest` never
        // matched its own content, set `evaluation.manifest_digest` to that
        // string, and every manifest join below would be measured against
        // content nobody froze. `AuthorizedManifest::verify_integrity` exists and
        // was not being called from the absence path; it is now.
        if let Some(admitted) = manifest {
            admitted.verify_integrity()?;
        }
        if let Some(evaluation) = &evaluation {
            // Readback first: a record rewritten after it was issued is refused
            // before any of its content is believed, let alone joined.
            evaluation.verify_integrity()?;
            evaluation.validate_shape()?;
            // A no-match verdict over a member the accounting never closed is the
            // evaluator contradicting the run's own accounting, not a gap to
            // retain, so it is refused here rather than becoming a partition entry.
            for result in &evaluation.results {
                let closed_by_account = account
                    .outcomes
                    .get(&result.member)
                    .is_some_and(|(disposition, _)| disposition.closes_member());
                if !closed_by_account {
                    return Err(PortfolioError::Conflict {
                        field: "no_match_result.member",
                    });
                }
            }
        }
        let binding = AbsenceJoinBinding::of(manifest, evaluation.as_ref(), now_ms);
        let results: BTreeMap<&str, &MemberNoMatchResult> = evaluation
            .as_ref()
            .map(|evaluation| {
                evaluation
                    .results
                    .iter()
                    .map(|result| (result.member.as_str(), result))
                    .collect()
            })
            .unwrap_or_default();
        let mut unclosed: Vec<(String, &'static str)> = Vec::new();
        let mut closed: Vec<String> = Vec::new();
        let mut incompatible: Vec<(String, &'static str)> = Vec::new();
        let mut closed_grades: Vec<Option<u8>> = Vec::new();
        // Counted before the join, not after: `closed` below is the post-join set
        // and is strictly smaller, so the disposition-only count has to be taken
        // here or not at all.
        let mut closed_by_account = 0usize;
        for (member, (disposition, handle)) in &account.outcomes {
            if !disposition.closes_member() {
                unclosed.push((member.clone(), disposition.wire_name()));
                continue;
            }
            closed_by_account += 1;
            let record = handle
                .as_ref()
                .and_then(|handle| records.get(handle.as_str()));
            let reason = member_join_reason(
                handle.as_ref(),
                record,
                results.get(member.as_str()).copied(),
                &binding,
            )?;
            // Declared behaviour change relative to the pre-#2893 ladder, and the
            // whole point of the defect-B fix: a member reaching `incompatible`
            // no longer also lands in `closed`. Before, a stale record was pushed
            // to both and `closed` was therefore "the members a closing
            // disposition closed"; it is now "…whose join also completed", so it
            // is strictly smaller. Nothing outside this crate reads the field —
            // it is private and `assess_absence` only compares it against the
            // evaluation's own member list — but the boundary moved, and
            // `closed_by_account` above exists so no caller of the retained
            // reason has to rediscover the old count from the new one.
            if let Some(reason) = reason {
                incompatible.push((member.clone(), reason));
            } else {
                closed.push(member.clone());
                if let Some(record) = record {
                    closed_grades.push(record.grade);
                }
            }
        }
        // The two evaluation-clock conditions are route-level, not per-member, so
        // they are retained once here instead of being stamped onto every closed
        // member by `member_join_reason`. Reporting them per member made one
        // clock fault read as N record faults and inflated the per-member count
        // the reason prints. Order is the order they are checked in.
        let mut route_incompatible: Vec<&'static str> = Vec::new();
        if binding.evaluation_bound {
            if binding.observed_in_future() {
                route_incompatible.push(INCOMPATIBLE_EVALUATION_NOT_OBSERVED);
            }
            if binding.expired() {
                route_incompatible.push(INCOMPATIBLE_EVALUATION_EXPIRED);
            }
        }
        // Weakest-link ceiling over the grades of the records behind the closed
        // members: a member with no grade poisons the result to unknown. The rule
        // itself is not restated here — `weakest_ceiling` is the crate's single
        // owner for it — and a closed set with no member behind it is `unknown`
        // rather than the strongest grade, because `weakest_ceiling` refuses an
        // empty input and that refusal is answered conservatively.
        let closed_grade_ceiling = if closed_grades.is_empty() {
            None
        } else {
            weakest_ceiling(&closed_grades)?
        };
        let mut preconditions = Self {
            frozen_scope_digest: frozen_scope_digest.to_owned(),
            account_digest: account.digest(),
            unexamined: account.open_members(),
            unclosed,
            excluded: account.exclusions.keys().cloned().collect(),
            incompatible,
            route_incompatible,
            closed,
            closed_by_account,
            manifest_digest: manifest.map(|admitted| admitted.digest.clone()),
            closed_grade_ceiling,
            observed_outside_scope: account.observed.len(),
            frontier: account.frontier.clone(),
            evaluation,
            digest: String::new(),
        };
        preconditions.digest = preconditions.compute_digest();
        Ok(preconditions)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("absence-preconditions/v2;");
        push_field(
            &mut preimage,
            "frozen_scope_digest",
            &self.frozen_scope_digest,
        );
        push_field(&mut preimage, "account_digest", &self.account_digest);
        for (tag, members) in [
            ("unexamined", &self.unexamined),
            ("excluded", &self.excluded),
        ] {
            push_count(&mut preimage, tag, members.len());
            for member in members {
                push_field(&mut preimage, tag, member);
            }
        }
        push_count(&mut preimage, "incompatible", self.incompatible.len());
        for (member, reason) in &self.incompatible {
            push_field(&mut preimage, "incompatible_member", member);
            push_field(&mut preimage, "incompatible_reason", reason);
        }
        push_count(
            &mut preimage,
            "route_incompatible",
            self.route_incompatible.len(),
        );
        for reason in &self.route_incompatible {
            push_field(&mut preimage, "route_incompatible_reason", reason);
        }
        push_count(&mut preimage, "closed", self.closed.len());
        for member in &self.closed {
            push_field(&mut preimage, "closed", member);
        }
        // The disposition-only count is bound alongside the post-join set above,
        // so a preconditions set records both and a reader never has to infer the
        // first from the second.
        push_count(&mut preimage, "closed_by_account", self.closed_by_account);
        // Which manifest authorised this set, bound as an identity in its own
        // right. It used to reach the digest only through the member
        // classification it happened to produce, so two derivations that agreed on
        // every member but were checked against different manifests were
        // indistinguishable in the retained record.
        match &self.manifest_digest {
            Some(digest) => push_field(&mut preimage, "manifest", digest),
            None => push_field(&mut preimage, "manifest", "absent"),
        }
        push_count(&mut preimage, "unclosed", self.unclosed.len());
        for (member, disposition) in &self.unclosed {
            push_field(&mut preimage, "unclosed_member", member);
            push_field(&mut preimage, "unclosed_disposition", disposition);
        }
        let grade_ceiling = match self.closed_grade_ceiling {
            Some(ceiling) => ceiling.to_string(),
            None => "unknown".to_owned(),
        };
        push_field(&mut preimage, "closed_grade_ceiling", &grade_ceiling);
        push_count(
            &mut preimage,
            "observed_outside_scope",
            self.observed_outside_scope,
        );
        if let Some(frontier) = &self.frontier {
            push_field(&mut preimage, "frontier", frontier);
        }
        match &self.evaluation {
            // The whole owner-issued record is bound by its own frozen digest
            // rather than re-spelled field by field here, so this set cannot
            // disagree with the record it was derived from and a new evaluation
            // field is picked up without a second field list that could drift from
            // the record's own identity.
            Some(evaluation) => push_field(&mut preimage, "evaluation", &evaluation.digest),
            None => push_field(&mut preimage, "evaluation", "absent"),
        }
        freeze(&preimage)
    }
}

/// The route-level facts every member join is measured against.
///
/// [`AbsencePreconditions::derive`] computes these once from what the route
/// presented, so classifying one member takes that member's handle, the record it
/// resolves to and the result issued for it, plus one reference to this binding;
/// the two route-level evaluation-clock conditions are read off the same binding
/// rather than recomputed per member. The alternative — spelling all six route
/// facts as a parameter list at the call site — is exactly the transposition
/// hazard the named-argument discipline elsewhere in this module exists to
/// remove.
struct AbsenceJoinBinding<'a> {
    /// Authorized manifest covering the frozen members, when one was presented.
    manifest: Option<&'a AuthorizedManifest>,
    /// Whether that manifest is the manifest, revision and denominator the bound
    /// evaluation claims to have run under. Vacuously true when no evaluation was
    /// bound, because no manifest check applies to a route that binds none.
    manifest_binding: bool,
    /// Whether a bounded predicate evaluation was bound at all. Every
    /// per-member-result and manifest join applies only when one was, so a
    /// research-plane route that binds none keeps naming its accounting facts
    /// rather than a per-member result gap.
    evaluation_bound: bool,
    /// Owner-recorded observation time of the bound evaluation; zero when none.
    observed_at_ms: i64,
    /// Owner-declared currentness bound of the bound evaluation; zero when none.
    current_until_ms: i64,
    /// The caller's assessment time.
    now_ms: i64,
}

impl<'a> AbsenceJoinBinding<'a> {
    /// The binding one presented manifest and bound evaluation establish.
    fn of(
        manifest: Option<&'a AuthorizedManifest>,
        evaluation: Option<&NoMatchEvaluation>,
        now_ms: i64,
    ) -> Self {
        let manifest_binding = match (manifest, evaluation) {
            (Some(admitted), Some(evaluation)) => {
                evaluation.manifest_digest == admitted.digest
                    && evaluation.manifest_revision == admitted.revision
                    && evaluation.denominator_digest == admitted.denominator_digest
            }
            // An evaluation with no manifest presented is not covered by one; the
            // per-member check names that as its own reason.
            (None, Some(_)) => false,
            (_, None) => true,
        };
        Self {
            manifest,
            manifest_binding,
            evaluation_bound: evaluation.is_some(),
            observed_at_ms: evaluation.map_or(0, |evaluation| evaluation.observed_at_ms),
            current_until_ms: evaluation.map_or(0, |evaluation| evaluation.current_until_ms),
            now_ms,
        }
    }

    /// Whether the evaluation was observed earlier than the record it claims to
    /// have read was retrieved, so it cannot have read those bytes.
    fn predates_record(&self, record: &SourceRecord) -> bool {
        record
            .retrieved_ms
            .is_some_and(|retrieved| retrieved > self.observed_at_ms)
    }

    /// Whether the evaluation's owner-recorded observation time is later than the
    /// assessment time, so its currentness is not established.
    fn observed_in_future(&self) -> bool {
        self.observed_at_ms > self.now_ms
    }

    /// Whether the assessment time is past the evaluation's owner-declared
    /// currentness bound.
    fn expired(&self) -> bool {
        self.now_ms > self.current_until_ms
    }
}

/// The one ordered join that refuses a closing member, or `None` when every join
/// holds.
///
/// The order is the one [`AbsencePreconditions::derive`] documents, and it is
/// load-bearing: a member that fails several joins at once is reported under its
/// earliest unmet one, so the retained reason is the first thing that would have
/// to be repaired.
///
/// Every reason this function can return is a fact about *this member*. The two
/// evaluation-clock conditions are facts about the route, so they are not
/// computed here: [`AbsencePreconditions::derive`] retains them once in
/// `route_incompatible` and [`assess_absence`] refuses on them as a route. What
/// that leaves is a precise statement about which joins are gated: the
/// per-member-result joins (result present, record commitment, content digest)
/// and the manifest joins apply only when the route bound an evaluation, while
/// the first three joins and the record-currentness join do **not** — a handle,
/// a record, a matching handle and a non-stale record are properties of the
/// accounting and the records, and a route that binds no evaluation still
/// reaches `None` and closes its members on those alone. This is the same
/// scoping [`AbsenceJoinBinding::evaluation_bound`] states.
///
/// # Errors
///
/// Returns the joined record's own digest error when its canonical commitment
/// cannot be recomputed. That is the error the comparison itself raises, and it
/// is a malformed record rather than a refused negative, so it is not one of the
/// `INCOMPATIBLE_*` reasons.
fn member_join_reason(
    handle: Option<&String>,
    record: Option<&SourceRecord>,
    result: Option<&MemberNoMatchResult>,
    binding: &AbsenceJoinBinding<'_>,
) -> Result<Option<&'static str>, PortfolioError> {
    Ok(match (handle, record, result) {
        (None, _, _) => Some(INCOMPATIBLE_MISSING_HANDLE),
        (Some(_), None, _) => Some(INCOMPATIBLE_MISSING_RECORD),
        (Some(handle), Some(record), _) if record.handle != *handle => {
            Some(INCOMPATIBLE_SUBSTITUTED_RECORD)
        }
        (_, _, None) if binding.evaluation_bound => Some(INCOMPATIBLE_RESULT_MISSING),
        (_, Some(record), Some(result)) if result.record_digest != record.digest()? => {
            Some(INCOMPATIBLE_RESULT_RECORD_MISMATCH)
        }
        (_, Some(record), Some(result)) if result.content_digest != record.content_digest => {
            Some(INCOMPATIBLE_RESULT_CONTENT_MISMATCH)
        }
        (_, Some(record), _) if record.is_stale_at(binding.now_ms) => {
            Some(INCOMPATIBLE_RECORD_STALE)
        }
        (_, _, _) if binding.evaluation_bound && binding.manifest.is_none() => {
            Some(INCOMPATIBLE_MANIFEST_ABSENT)
        }
        (_, _, _) if binding.evaluation_bound && !binding.manifest_binding => {
            Some(INCOMPATIBLE_MANIFEST_MISMATCH)
        }
        (_, _, _)
            if binding.evaluation_bound
                && !handle.is_some_and(|handle| {
                    binding
                        .manifest
                        .is_some_and(|admitted| admitted.allows(handle))
                }) =>
        {
            Some(INCOMPATIBLE_MANIFEST_REVOKED)
        }
        (_, Some(record), _)
            if binding.evaluation_bound
                && !binding
                    .manifest
                    .is_some_and(|admitted| admitted.binds_source_record(record)) =>
        {
            Some(INCOMPATIBLE_MANIFEST_UNBOUND)
        }
        (_, Some(record), _) if binding.evaluation_bound && binding.predates_record(record) => {
            Some(INCOMPATIBLE_EVALUATION_PRECEDES_RECORD)
        }
        _ => None,
    })
}

/// Assesses a scoped absence claim over owner-bound preconditions.
///
/// Only a complete denominator, an exact accounting of every declared member, an
/// intact and currently-bound source record for each closed member under an
/// authorized manifest that commits that exact record, an owner-issued per-member
/// predicate result joined to that record and to the exact predicate and
/// revisions, all five separately-established dimensions, a current (not
/// historical) applicability, and a proof ceiling no stronger than the weakest
/// closed member's grade, proves absence. A bounded enumeration that stopped is
/// partial exhaustion. Every rejected claim names the retained fact that rejected
/// it, so no verdict rests on a caller-supplied flag.
///
/// Package-level `Proven` is not publication authority, and it is not
/// owner-bound either: it is the strongest statement this package can make about
/// evidence the caller presented and the assessor was able to cross-check. The
/// residual trust boundary is the records, the authorized manifest and `now_ms`,
/// all three of which are parameters of
/// [`AbsencePreconditions::derive`]; see the limitation note on
/// [`NoMatchEvaluation`] for why no in-crate check can close it. The live
/// composition owner does re-check the retained record: `coverage-receipt/v2`
/// binds both this verdict's class and the reason it carries, and
/// `InquiryGovernance::validate_integrity` re-checks that receipt digest against
/// the evidence freeze and the terminal record. It does **not** re-run this
/// assessment, and it cannot raise the verdict above the proof ceiling carried on
/// the bound evaluation.
///
/// `account` is the accounting the preconditions are claimed to describe. It is
/// required so the preconditions cannot be re-bound to a different accounting
/// than the one they were derived over, and it is the only trusted account the
/// assessment has. A precondition set that does not re-prove its own digest, whose
/// bound account digest is not this account's, or whose bound evaluation no longer
/// re-proves its own identity, is refused as [`AbsenceVerdict::Unproven`] before
/// any of its content is read: a claim that cannot be re-proved is not proved.
///
/// # The ladder, and what is and is not enforced about it
///
/// The ladder below is a sequence of independent refusals, one per retained fact
/// that can block the negative, in the order the retained fact is most
/// fundamental. Each refusal names the fact it retains; none of them can be
/// skipped, reordered or summarised by a caller, and reaching the end is the
/// only way to [`AbsenceVerdict::Proven`].
///
/// Two things about it are worth knowing before editing.
///
/// *It is an `if let` chain, not a `match`.* Nothing about this order is
/// compiler-enforced: the compiler has no way to prove any of these calls
/// unreachable, so a reordering here compiles silently and changes which reason a
/// given input retains. An `unreachable_patterns` error can be produced while
/// *authoring* the ladder as a `match`, but the delivered form is this chain and
/// the property does not survive it. Order is held by review and by the comments
/// on each arm, not by the type system.
///
/// *Three arms are new relative to the pre-#2893 ladder, and they are inserted,
/// not appended.* `rewritten_evaluation` sits third, ahead of every accounting
/// fact, because a rewritten evaluation invalidates the content of every later
/// arm. `historical_evaluation` and `unestablished_dimensions` sit between the
/// scope check and the member-set check, so an evaluation that is both
/// `Historical` and carries the wrong member set now reports the historical
/// reason, where before there was no historical concept and the member-set
/// mismatch was reported. The pre-existing arms keep their relative order among
/// themselves.
pub fn assess_absence(
    account: &CoverageAccount,
    preconditions: &AbsencePreconditions,
) -> AbsenceVerdict {
    if let Some(verdict) = unreproved_preconditions(preconditions) {
        return verdict;
    }
    if let Some(verdict) = rebound_account(preconditions, account) {
        return verdict;
    }
    if let Some(verdict) = rewritten_evaluation(preconditions) {
        return verdict;
    }
    if let Some(verdict) = unmet_route_conditions(preconditions) {
        return verdict;
    }
    if let Some(verdict) = stopped_enumeration(preconditions) {
        return verdict;
    }
    if let Some(verdict) = unexamined_members(preconditions) {
        return verdict;
    }
    if let Some(verdict) = excluded_members(preconditions) {
        return verdict;
    }
    if let Some(verdict) = unclosed_members(preconditions) {
        return verdict;
    }
    if let Some(verdict) = incompatible_members(preconditions) {
        return verdict;
    }
    let Some(evaluation) = &preconditions.evaluation else {
        return AbsenceVerdict::Unproven {
            reason: absent_evaluation_reason(preconditions),
        };
    };
    if let Some(verdict) = foreign_evaluation_scope(evaluation, preconditions) {
        return verdict;
    }
    if let Some(verdict) = historical_evaluation(evaluation) {
        return verdict;
    }
    if let Some(verdict) = unestablished_dimensions(evaluation) {
        return verdict;
    }
    if let Some(verdict) = mismatched_evaluated_members(evaluation, preconditions) {
        return verdict;
    }
    if let Some(verdict) = unchecked_proof_ceiling(evaluation, preconditions) {
        return verdict;
    }
    AbsenceVerdict::Proven
}

/// Refuses a precondition set that no longer re-proves its own digest.
///
/// A set whose fields were rewritten after the freeze still validates field by
/// field, so only a recomputation over the bytes actually present can say it is no
/// longer the owner-bound evidence it claims to be.
fn unreproved_preconditions(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.compute_digest() == preconditions.digest {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: "absence: the preconditions do not re-prove their own digest, so this set is \
                 not owner-bound evidence and proves nothing"
            .to_owned(),
    })
}

/// Refuses a precondition set bound to a different coverage account than the one
/// presented with it.
fn rebound_account(
    preconditions: &AbsencePreconditions,
    account: &CoverageAccount,
) -> Option<AbsenceVerdict> {
    let account_digest = account.digest();
    if preconditions.account_digest == account_digest {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the preconditions are bound to coverage account {account_digest}, not to \
             the account presented with them, so the two cannot be swapped"
        ),
    })
}

/// Refuses a bound predicate evaluation that no longer re-proves its own identity.
///
/// [`AbsencePreconditions::derive`] already refuses such a record, so reaching
/// this means the evaluation was rewritten between derivation and assessment.
fn rewritten_evaluation(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if let Some(evaluation) = &preconditions.evaluation
        && evaluation.verify_integrity().is_err()
    {
        return Some(AbsenceVerdict::Unproven {
            reason: "absence: the bound predicate evaluation does not re-prove its own identity, \
                     so it is not the record the evaluator issued and proves nothing"
                .to_owned(),
        });
    }
    None
}

/// Refuses a bound evaluation whose own clock does not support a current claim.
///
/// These are route-level conditions, so they are reported once here rather than
/// once per closed member. Retaining them per member made a single expired
/// evaluation read as N expired records and printed a per-member count that was
/// really counting one fault N times.
fn unmet_route_conditions(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.route_incompatible.is_empty() {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the bound predicate evaluation does not support a current claim, and the \
             condition applies to the whole route rather than to any one member: {}",
            preconditions.route_incompatible.join(",")
        ),
    })
}

/// Reports bounded exhaustion where a stopped enumeration left the negative
/// partial rather than refused.
fn stopped_enumeration(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    preconditions
        .frontier
        .as_ref()
        .map(|frontier| AbsenceVerdict::PartialExhaustion {
            frontier: frontier.clone(),
        })
}

/// Refuses a denominator with declared members no run ever looked at.
fn unexamined_members(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.unexamined.is_empty() {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "coverage: {} declared denominator member(s) were never examined: {}",
            preconditions.unexamined.len(),
            preconditions.unexamined.join(",")
        ),
    })
}

/// Refuses a denominator holding an explicit exclusion, which is not a
/// successful search.
fn excluded_members(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.excluded.is_empty() {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "coverage: an exclusion is not a successful search; {} member(s) were excluded: {}",
            preconditions.excluded.len(),
            preconditions.excluded.join(",")
        ),
    })
}

/// Refuses members whose disposition did not close their denominator slot.
fn unclosed_members(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.unclosed.is_empty() {
        return None;
    }
    let unclosed = preconditions
        .unclosed
        .iter()
        .map(|(member, disposition)| format!("{member}={disposition}"))
        .collect::<Vec<String>>()
        .join(",");
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "coverage: {} examined member(s) did not close their denominator slot: {unclosed}",
            preconditions.unclosed.len()
        ),
    })
}

/// Refuses closed members that do not join to a current, owner-issued predicate
/// result over the exact record behind them, naming each unmet join.
///
/// # Declared behaviour change
///
/// The reason text is **not** the pre-#2893 text and the count is **not** the
/// pre-#2893 count. Before, this arm printed `"…are no longer current for the
/// frozen snapshot: {}"` over a bare list of member names, because `incompatible`
/// held names and a stale record was the only way into it. It now prints
/// `member=reason` pairs, and `incompatible` can hold twelve distinct reasons
/// rather than one. Both changes are required by the issue: Acceptance says a
/// missing, substituted or stale record "blocks exact absence with the specific
/// member and reason retained", which the old text could not express.
///
/// This arm is reached with a different population than before as well, for the
/// same reason: a member with no handle, no record or a substituted handle used
/// to reach the *absent-evaluation* arm instead, because it never entered
/// `incompatible` at all. No test in this crate asserts this string, so treat it
/// as unblessed by the suite: changing it is a visible change to every receipt
/// that carries the reason, and it moves `coverage-receipt/v2`.
fn incompatible_members(preconditions: &AbsencePreconditions) -> Option<AbsenceVerdict> {
    if preconditions.incompatible.is_empty() {
        return None;
    }
    let incompatible = preconditions
        .incompatible
        .iter()
        .map(|(member, reason)| format!("{member}={reason}"))
        .collect::<Vec<String>>()
        .join(",");
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "coverage: {} closed member(s) do not join to a current, owner-issued predicate \
             result over the exact record behind them: {incompatible}",
            preconditions.incompatible.len()
        ),
    })
}

/// The retained fact behind a route that bound no bounded predicate evaluation.
///
/// This is the ordinary Researcher outcome rather than a defect: the research
/// plane records per-source acquisition dispositions, not per-member query
/// predicate results, and no ordinary route supplies an owner-issued evaluation
/// for the requested query. The reason states that instead of implying the
/// accounting was at fault.
///
/// The count is [`AbsencePreconditions::closed_by_account`], the
/// disposition-only count, not `closed.len()`. `closed` is the post-join set and
/// is strictly smaller, so printing it here would under-report how many members
/// the accounting closed. The two are equal on exactly the inputs that reach
/// this arm — the arm only fires when `incompatible` is empty, which forces
/// `closed == closed_by_account` — but relying on that coincidence would be a
/// trap for the next editor, so the count that means "declared closed" is
/// carried explicitly.
fn absent_evaluation_reason(preconditions: &AbsencePreconditions) -> String {
    format!(
        "absence: no bounded predicate evaluation is bound to the requested query over \
         frozen scope snapshot {}; accounting {} declared member(s) closed and observing \
         {} candidate(s) outside that scope does not prove the query has no match",
        preconditions.frozen_scope_digest,
        preconditions.closed_by_account,
        preconditions.observed_outside_scope
    )
}

/// Refuses an evaluation bounded to a different frozen scope snapshot than the
/// one the claim is scoped to.
fn foreign_evaluation_scope(
    evaluation: &NoMatchEvaluation,
    preconditions: &AbsencePreconditions,
) -> Option<AbsenceVerdict> {
    if evaluation.covers_scope(&preconditions.frozen_scope_digest) {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the predicate evaluation is bounded to frozen scope snapshot {}, not to {}",
            evaluation.scope_digest, preconditions.frozen_scope_digest
        ),
    })
}

/// Refuses a historical evaluation, which grounds a claim about its own
/// observation time only.
fn historical_evaluation(evaluation: &NoMatchEvaluation) -> Option<AbsenceVerdict> {
    if evaluation.applicability == NoMatchApplicability::Current {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the predicate evaluation is {} and grounds a claim about its observation \
             time only, not a current scoped negative",
            evaluation.applicability.wire_name()
        ),
    })
}

/// Refuses an evaluation that left any of the five separately-established facts
/// unestablished, naming each missing dimension.
fn unestablished_dimensions(evaluation: &NoMatchEvaluation) -> Option<AbsenceVerdict> {
    let missing = evaluation.missing_dimensions();
    if missing.is_empty() {
        return None;
    }
    let named = missing
        .iter()
        .copied()
        .map(|dimension| dimension.wire_name().to_owned())
        .collect::<Vec<String>>()
        .join(",");
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the predicate evaluation left {} of the five separately-established \
             facts unestablished, and none substitutes for another: {named}",
            missing.len()
        ),
    })
}

/// Refuses an evaluation whose owner-issued results cover a different member set
/// than the closed members of the frozen denominator.
///
/// # Declared behaviour change
///
/// Two reasons the text differs from the pre-#2893 arm, both from this issue.
///
/// The wording changed: it was `"…covers {} member(s) over index revision {}…"`
/// and now names the source revision too, because the evaluation carries one
/// and a member-set mismatch is a statement about which run produced the
/// results.
///
/// The *set it compares against* changed more quietly, and this is the part worth
/// reading twice. `closed` used to hold every member a closing disposition
/// closed, so a stale member was compared here as an ordinary closed member.
/// It is now the post-join set, so a stale member is not in it and an evaluation
/// that covered exactly the pre-#2893 `closed` set is now a mismatch. Every such
/// input was already `Unproven` — the incompatibility arm runs first — so no
/// input changes from `Proven` to `Unproven` or back. What changes is which
/// reason a caller reads, and it moves `coverage-receipt/v2`. No test in this
/// crate asserts this string.
fn mismatched_evaluated_members(
    evaluation: &NoMatchEvaluation,
    preconditions: &AbsencePreconditions,
) -> Option<AbsenceVerdict> {
    let evaluated = evaluation.evaluated_members();
    if evaluated == preconditions.closed {
        return None;
    }
    Some(AbsenceVerdict::Unproven {
        reason: format!(
            "absence: the predicate evaluation carries an owner-issued result for {} member(s) \
             over index revision {} and source revision {}, not the {} closed member(s) of the \
             frozen denominator",
            evaluated.len(),
            evaluation.index_revision,
            evaluation.source_revision,
            preconditions.closed.len()
        ),
    })
}

/// Refuses a proof ceiling that cannot be checked against the weakest grade
/// behind the closed members.
///
/// Three cases are refused and they are not interchangeable: an absent ceiling is
/// unknown rather than unrestricted, a ceiling above the weakest record grade
/// overclaims what the records carry, and a ceiling asserted while a record's
/// grade is unknown cannot be compared at all.
fn unchecked_proof_ceiling(
    evaluation: &NoMatchEvaluation,
    preconditions: &AbsencePreconditions,
) -> Option<AbsenceVerdict> {
    match (
        evaluation.proof_ceiling_grade,
        preconditions.closed_grade_ceiling,
    ) {
        (None, _) => Some(AbsenceVerdict::Unproven {
            reason: "absence: the predicate evaluation declares no proof ceiling, and an \
                     absent coverage ceiling is unknown rather than unrestricted"
                .to_owned(),
        }),
        // The comparison is delegated to `check_ceiling`, the crate's single
        // owner for the rule, rather than restated as `claimed > ceiling`. Both
        // ranks are already on the canonical ladder by the time this runs —
        // `validate_shape` calls `grade_name` on the claimed ceiling and
        // `closed_grade_ceiling` is `weakest_ceiling` over record grades that
        // `SourceRecord::new` validated the same way — so the only error
        // `check_ceiling` can raise here is `CeilingViolation`, and treating any
        // error as an overclaim here cannot misreport one as the other.
        (Some(claimed), Some(ceiling)) if check_ceiling(claimed, ceiling).is_err() => {
            Some(AbsenceVerdict::Unproven {
                reason: format!(
                    "absence: the predicate evaluation claims proof ceiling grade {claimed}, above \
                     the weakest grade {ceiling} of the {} record(s) behind the closed members",
                    preconditions.closed.len()
                ),
            })
        }
        (Some(_), Some(_)) => None,
        (Some(claimed), None) => Some(AbsenceVerdict::Unproven {
            reason: format!(
                "absence: the predicate evaluation claims proof ceiling grade {claimed}, while \
                 the grade of at least one record behind the closed members is unknown, so no \
                 ceiling can be checked"
            ),
        }),
    }
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
    /// against. This constructor makes that state explicit rather than leaving it
    /// to a caller to remember: it is the shape a claim arrives in before it has
    /// been frozen, and the audit says so instead of guessing.
    ///
    /// # Errors
    ///
    /// Propagates every refusal the frozen identity raises. Returns `Ok(None)`
    /// never — a caller that has no identity uses [`Self::unfrozen`].
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
    /// No sufficient in-manifest support, and nothing contradicts the claim.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClaimOppositionRelation {
    /// Stable relation identity.
    pub relation_id: String,
    /// Frozen identity of the claim this relation contests.
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
    /// Returns a field error for a blank relation, claim, source or evaluator
    /// identity, a bad source commitment or artifact digest, a zero revision, or a
    /// coverage value above one millionth.
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
            mismatched.push(OppositionDimension::Proposition);
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
    /// A material citation is a handle the frozen manifest revoked.
    ///
    /// Distinct from [`Self::OutsideManifest`] because the two findings are: a
    /// revoked handle was authorized and then withdrawn, while an outside
    /// handle was never admitted at all. Reporting a revocation as "outside"
    /// loses the only fact that distinguishes "we withdrew this" from "you
    /// invented this", and it is the same conflation that let the citation and
    /// opposition partitions disagree about one handle. Both project onto the
    /// same public class, because a release consumer may do nothing with either.
    RevokedEvidence,
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

/// The standing one handle holds inside one claim audit, decided once.
///
/// `classify_handle` is the only place this is derived, and both partitions
/// read its answer: the citation loop that decides whether a handle may support
/// the claim, and the opposition loop that decides whether it may contest it.
/// The two used to decide separately, over their own `if` chains, so a handle
/// that was both a citation and revoked came out `OutsideManifest` on the
/// citation side and `AlsoACitation` on the opposition side — one handle, two
/// contradictory typed verdicts, and the revocation reported by neither.
///
/// The order of the arms below is the order of the derivation, and it is
/// load-bearing rather than incidental: revocation is decided **first**, before
/// allowlist membership and before the claim's own citation list, because a
/// withdrawn handle can be neither a citation nor counterevidence whatever else
/// is true of it. [`AuthorizedManifest::freeze`] keeps `allowlist` and `revoked`
/// disjoint, so the first two arms between them reproduce exactly what
/// [`AuthorizedManifest::allows`] answered while keeping the two reasons apart
/// instead of merging them into one boolean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleStanding {
    /// The manifest admitted this handle and then revoked it.
    Revoked,
    /// The manifest never admitted this handle.
    OutsideManifest,
    /// The manifest admits this handle, but the portfolio holds no record for it.
    Unresolved,
    /// The portfolio holds a record for this handle that no longer matches the
    /// commitment the manifest froze for it.
    SubstitutedRecord,
    /// Admitted with a bound record, and also a citation of this same claim.
    ///
    /// The opposition partition reads this as one input asserting both support
    /// and opposition. The citation partition reads it as the ordinary admitted
    /// case, because a handle it is looking at is by construction one of the
    /// claim's citations — which is exactly why the two can no longer answer
    /// differently about it.
    AdmittedCitation,
    /// Admitted with a bound record, and not a citation of this claim.
    Admitted,
}

/// One handle this audit examined, with the one standing both partitions read.
///
/// This is the citation partition's typed record, and it holds the same value
/// the opposition partition derived for the same handle. Reading a handle's
/// standing from a typed field rather than from residue prose is what makes the
/// two partitions comparable: while each decided for itself, both looked
/// internally consistent and still disagreed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleResolution {
    /// The handle examined.
    pub handle: String,
    /// The single standing derived for it by `classify_handle`.
    pub standing: HandleStanding,
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
            Self::RevokedEvidence => "REVOKED_EVIDENCE",
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
    /// The one standing derived for every distinct handle this audit examined,
    /// in sorted handle order.
    ///
    /// One entry per handle across `citations` and `counterclaim_ids`, holding
    /// the single value `classify_handle` returns for it. Both partitions read
    /// that value, so a handle cannot be reported as outside the manifest on one
    /// side and as also a citation on the other, and a revocation cannot be
    /// dropped by whichever partition happens to test its own condition first.
    pub handle_resolutions: Vec<HandleResolution>,
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
    /// Every attached counterclaim resolved to exactly one disposition, and the
    /// two partitions agree about the handle it names.
    ///
    /// The premise of this dimension is that the partitions agree: a handle
    /// cannot be simultaneously "outside the manifest" on the citation side and
    /// "also a citation" on the counterclaim side. `audit_claim` classifies
    /// every handle once through `classify_handle` and both partitions read
    /// that one answer, so this dimension is the record that the two did not
    /// diverge — and it is checkable, because a standing that forces a
    /// disposition can be compared against the disposition actually reported.
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
    /// Lossless by construction: every internal outcome maps to exactly one public
    /// class, and no dimension is discarded to reach it. `OutsideManifest`,
    /// `StaleLimited` and `IncompleteAccounting` are not public classes — I21.8
    /// names five — so they project onto the class that describes what a release
    /// consumer may do with the claim: an outside-manifest or stale claim is not
    /// `Supported`, and an incompletely accounted one is not verifiable.
    #[must_use]
    pub fn public_class(&self) -> PublicAuditClass {
        match self.outcome {
            ClaimOutcome::Contradicted => PublicAuditClass::Contradicted,
            ClaimOutcome::Supported => PublicAuditClass::Supported,
            ClaimOutcome::PartiallySupported => PublicAuditClass::PartiallySupported,
            ClaimOutcome::Unsupported | ClaimOutcome::StaleLimited => PublicAuditClass::Unsupported,
            ClaimOutcome::OutsideManifest
            | ClaimOutcome::RevokedEvidence
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

    /// Whether one named dimension passed. An absent dimension did not pass.
    fn dimension_passed(&self, dimension: AuditDimension) -> bool {
        let failed = match dimension {
            AuditDimension::ReferenceVerification => {
                self.outcome == ClaimOutcome::OutsideManifest
                    || self.outcome == ClaimOutcome::RevokedEvidence
                    || self.evidence_map.is_empty()
            }
            AuditDimension::ValueVerification => {
                self.outcome == ClaimOutcome::Unsupported
                    || self.outcome == ClaimOutcome::StaleLimited
                    || self.outcome == ClaimOutcome::PartiallySupported
            }
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
            AuditDimension::MethodArtifactAlignment => self.claim_identity_digest.is_empty(),
            AuditDimension::ClaimIdentityCurrent => {
                self.counterclaim_resolutions.iter().any(|entry| {
                    matches!(
                        entry.disposition,
                        CounterclaimDisposition::RelationStatementChanged
                            | CounterclaimDisposition::RelationClaimMismatch
                            | CounterclaimDisposition::NoFrozenClaimIdentity
                            | CounterclaimDisposition::RelationDigestMismatch
                    )
                })
            }
            AuditDimension::CounterevidenceExamined => {
                self.counterevidence.is_empty()
                    || self.counterclaim_resolutions.iter().any(|entry| {
                        !matches!(
                            entry.disposition,
                            CounterclaimDisposition::Contradicts
                                | CounterclaimDisposition::AlsoACitation
                        )
                    })
            }
            AuditDimension::AccountingComplete => {
                self.outcome == ClaimOutcome::IncompleteAccounting || !self.unknowns.is_empty()
            }
            // Coherence is the property that the two partitions read one
            // classification instead of deciding their own. It is checked, not
            // asserted: a standing that forces a disposition must be reported
            // under that disposition on the opposition side, and a handle cannot
            // appear twice in the resolution list. The two-partition code this
            // replaced could fail neither half — a revoked citation was
            // `OutsideManifest` on one side and `AlsoACitation` on the other —
            // because the two sides never compared anything.
            AuditDimension::PartitionCoherence => {
                let mut seen: BTreeSet<&str> = BTreeSet::new();
                self.counterclaim_resolutions.iter().any(|entry| {
                    !seen.insert(entry.counterclaim_id.as_str())
                        || self
                            .handle_resolutions
                            .iter()
                            .find(|resolution| resolution.handle == entry.counterclaim_id)
                            .and_then(|resolution| forced_disposition(resolution.standing))
                            .is_some_and(|forced| forced != entry.disposition)
                })
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

/// Derives the one standing `handle` holds inside `claim`'s audit.
///
/// The inputs are exactly the four facts the two partitions used to read
/// separately, which is why they could disagree: whether the frozen manifest
/// revoked the handle, whether its allowlist admits it, whether the portfolio
/// resolves it to a record the manifest still commits, and whether the claim
/// itself lists it as a citation. Nothing here reads freshness, grade,
/// authority domain, evidence weight or the caller's counterclaim list: those
/// are eligibility and evidence questions, they belong to the partition that
/// raises them, and treating any of them as opposition is the inference
/// `#2874` forbids.
///
/// The function is pure, so the citation loop and the opposition loop can each
/// call it and get the same value; that is the whole repair. Revocation is
/// tested before anything else, so a handle the manifest withdrew is reported as
/// revoked by both partitions instead of being "outside" on one side and "also
/// a citation" on the other.
fn classify_handle(
    handle: &str,
    claim: &AuditedClaim,
    portfolio: &EvidencePortfolio,
    manifest: &AuthorizedManifest,
) -> HandleStanding {
    if manifest.revoked.iter().any(|revoked| revoked == handle) {
        return HandleStanding::Revoked;
    }
    if !manifest.allowlist.iter().any(|allowed| allowed == handle) {
        return HandleStanding::OutsideManifest;
    }
    let Some(record) = portfolio.records.get(handle) else {
        return HandleStanding::Unresolved;
    };
    // A record that no longer hashes to the commitment this manifest froze is
    // not the source the manifest admitted, so its handle is not provable even
    // though a record of that name exists.
    if !manifest.binds_source_record(record) {
        return HandleStanding::SubstitutedRecord;
    }
    if claim.citations.iter().any(|cited| cited == handle) {
        return HandleStanding::AdmittedCitation;
    }
    HandleStanding::Admitted
}

/// The disposition a standing forces, for the standings that force one.
///
/// Four of the six standings are decided from the manifest and the record
/// alone, so what the opposition partition reports for them is not a judgement
/// it is free to make: a revoked handle reports `Revoked` whether or not it is
/// also a citation, and a handle with no provable record reports
/// `UnresolvedLineage` whether the record is absent or merely substituted. The
/// two admitted standings force nothing, because whether an admitted handle
/// contradicts is a question about the evidence attached to it, and answering it
/// is what the remaining dispositions are for.
fn forced_disposition(standing: HandleStanding) -> Option<CounterclaimDisposition> {
    match standing {
        HandleStanding::Revoked => Some(CounterclaimDisposition::Revoked),
        HandleStanding::OutsideManifest => Some(CounterclaimDisposition::OutsideManifest),
        HandleStanding::Unresolved | HandleStanding::SubstitutedRecord => {
            Some(CounterclaimDisposition::UnresolvedLineage)
        }
        HandleStanding::Admitted | HandleStanding::AdmittedCitation => None,
    }
}

/// Classifies one attached counterclaim identity against this claim.
///
/// The standing is read from [`classify_handle`] first, and the same function
/// answers for the citation loop, so revocation and unavailable evidence are
/// decided in exactly one place before any opposition-specific question is
/// asked. The remaining checks are eligibility plus one verified relation, and
/// each records its own typed residue line, so the reason an identity did not
/// contradict is never lost:
///
/// * a handle the manifest revoked is withdrawn evidence and can be neither
///   citable nor opposable, whatever else is true of it;
/// * a handle outside the manifest was never admitted;
/// * an admitted handle that is also a citation of this claim asserts both
///   support and opposition at once, which this function does not resolve;
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
    match classify_handle(counterclaim_id, claim, portfolio, manifest) {
        HandleStanding::Revoked => {
            residue.push(format!(
                "claim: counterclaim {counterclaim_id} is revoked and cannot be verified"
            ));
            return CounterclaimDisposition::Revoked;
        }
        HandleStanding::OutsideManifest => {
            residue.push(format!(
                "claim: counterclaim {counterclaim_id} outside frozen manifest"
            ));
            return CounterclaimDisposition::OutsideManifest;
        }
        HandleStanding::Unresolved | HandleStanding::SubstitutedRecord => {
            residue.push(format!(
                "claim: counterclaim {counterclaim_id} has no authoritative lineage"
            ));
            return CounterclaimDisposition::UnresolvedLineage;
        }
        HandleStanding::AdmittedCitation => {
            residue.push(format!(
                "claim: counterclaim {counterclaim_id} is also a citation and cannot contest the claim"
            ));
            return CounterclaimDisposition::AlsoACitation;
        }
        // The two standing values that reach the eligibility checks below. The
        // record is re-read here rather than carried out of `classify_handle` so
        // that the classification stays a single closed enum rather than an enum
        // plus a record; `Admitted` is only returned when a bound record exists,
        // so this lookup cannot fail on this path, and it is written as a typed
        // refusal rather than an unwrap so that a future change to the standing
        // degrades to `UnresolvedLineage` instead of panicking.
        HandleStanding::Admitted => {}
    }
    let Some(record) = portfolio.records.get(counterclaim_id) else {
        residue.push(format!(
            "claim: counterclaim {counterclaim_id} has no authoritative lineage"
        ));
        return CounterclaimDisposition::UnresolvedLineage;
    };
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
///
/// Every handle this claim names — cited or alleged counterevidence alike — is
/// classified once by `classify_handle`, and the citation loop below and
/// [`resolve_counterclaim`] both read that one value. Revocation, non-admission
/// and unavailable evidence are therefore decided in exactly one place and
/// reported the same way on both sides, and the de-duplicated record of it is
/// [`ClaimVerdict::handle_resolutions`].
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
    // Revocation is a distinct finding from non-admission and is recorded as
    // one. The two were merged into a single `manifest.allows` boolean, which
    // reported every revoked citation as "outside frozen manifest" and let the
    // opposition partition report the same handle as "also a citation".
    let mut revoked_citation = false;
    // A manifest that fails its own integrity check is the authorization this
    // claim was judged under, so the gap is seeded here rather than per handle:
    // with the manifest unproven, no handle it admits is proven either, and the
    // claim cannot come out `Supported`.
    let mut lineage_gap = !manifest_intact;
    let mut support_gap = false;
    if claim.material && claim.citations.is_empty() {
        residue.push("claim: material claim records no citations".to_owned());
    }
    // One standing per distinct handle, derived once through the same function
    // the opposition partition calls. This is the de-duplicated record of it in
    // sorted handle order, so a consumer reads each handle's standing from a
    // typed field rather than from the residue prose of whichever partition
    // happened to look at it first.
    let handle_resolutions: Vec<HandleResolution> = claim
        .citations
        .iter()
        .chain(claim.counterclaim_ids.iter())
        .map(String::as_str)
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(|handle| HandleResolution {
            handle: handle.to_owned(),
            standing: classify_handle(handle, claim, portfolio, manifest),
        })
        .collect();
    for handle in &claim.citations {
        match classify_handle(handle, claim, portfolio, manifest) {
            HandleStanding::Revoked => {
                revoked_citation = true;
                residue.push(format!(
                    "claim: citation {handle} is revoked by the frozen manifest and cannot support the claim"
                ));
                continue;
            }
            HandleStanding::OutsideManifest => {
                outside_citation = true;
                residue.push(format!("claim: citation {handle} outside frozen manifest"));
                continue;
            }
            HandleStanding::Unresolved => {
                lineage_gap = true;
                residue.push(format!(
                    "claim: citation {handle} has no authoritative lineage"
                ));
                continue;
            }
            HandleStanding::SubstitutedRecord => {
                lineage_gap = true;
                residue.push(format!(
                    "claim: citation {handle} does not match the frozen source commitment"
                ));
                continue;
            }
            // A handle the citation loop is looking at is by construction one of
            // the claim's citations, so the standing the opposition partition
            // reads as "also a citation" is the ordinary admitted case here.
            HandleStanding::Admitted | HandleStanding::AdmittedCitation => {}
        }
        let Some(record) = portfolio.records.get(handle) else {
            lineage_gap = true;
            residue.push(format!(
                "claim: citation {handle} has no authoritative lineage"
            ));
            continue;
        };
        if !record.covers_domain(&claim.domain) {
            lineage_gap = true;
            residue.push(format!(
                "claim: source {handle} outside claim domain {}",
                claim.domain
            ));
            continue;
        }
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
    // A revoked citation is a separate finding from a non-admitted one, and it
    // sits where a revoked citation used to land: immediately after the
    // identity check and beside the outside-manifest arm, so the precedence
    // order of every other arm is untouched. It reports its own terminal class
    // rather than `OutsideManifest`, because "the manifest withdrew this" and
    // "the manifest never admitted this" are different facts about the same
    // release, and both still project onto `NOT_VERIFIABLE_IN_SCOPE`.
    let unfrozen_material_claim =
        claim.material && !claim_identity_verified && !outside_citation && !revoked_citation;
    let mut dimensions = vec![
        AuditDimension::ReferenceVerification,
        AuditDimension::ValueVerification,
        AuditDimension::SpecificationCompliance,
        AuditDimension::MethodArtifactAlignment,
        AuditDimension::ClaimIdentityCurrent,
        AuditDimension::CounterevidenceExamined,
        AuditDimension::AccountingComplete,
        AuditDimension::PartitionCoherence,
    ];
    dimensions.sort();
    dimensions.dedup();
    let outcome = if !identity_current {
        // A claim whose wording moved after the opposition was frozen cannot be
        // released as supported, and a verdict reached through a stale claim
        // identity is not a verdict about this claim at all. Checked before the
        // citation partition for that reason.
        ClaimOutcome::NotVerifiableInScope
    } else if revoked_citation {
        // Withdrawn evidence. A handle the manifest revoked is not "outside" it —
        // it was inside and then removed — and the residue above names the
        // revocation, so the reason survives the terminal class.
        ClaimOutcome::RevokedEvidence
    } else if outside_citation {
        ClaimOutcome::OutsideManifest
    } else if !contradicting.is_empty() {
        ClaimOutcome::Contradicted
    } else if !unverifiable.is_empty() {
        ClaimOutcome::NotVerifiableInScope
    } else if lineage_gap || precision_gap || support_gap {
        if stale_hit && supporting.is_empty() {
            ClaimOutcome::StaleLimited
        } else if supporting.is_empty() {
            ClaimOutcome::Unsupported
        } else {
            ClaimOutcome::PartiallySupported
        }
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
        handle_resolutions,
        unknowns: unknowns_sorted,
        grade_ceiling,
        evidence_map,
        dimensions,
        relation_digests,
        claim_identity_digest,
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
