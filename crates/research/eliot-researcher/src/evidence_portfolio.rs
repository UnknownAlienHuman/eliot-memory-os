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

use eliot_contracts::{StateFence, sha256_hex};
use eliot_research_exchange_api::{CompletionDisposition, DisclosureClass, SourceClass};

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
pub const GRADE_ORDER: [&str; 4] = [
    "ORIENTING",
    "GROUNDED",
    "CORROBORATED",
    "SCIENCE_GRADE",
];

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
        }
    }
}

impl std::error::Error for PortfolioError {}

fn text(value: &str, field: &'static str) -> Result<(), PortfolioError> {
    if value.trim().is_empty() {
        return Err(PortfolioError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(PortfolioError::ControlCharacter { field });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), PortfolioError> {
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

fn reject_vague(value: &str, field: &'static str) -> Result<(), PortfolioError> {
    if VAGUE_SCOPE_TEXTS.contains(&value.trim().to_lowercase().as_str()) {
        return Err(PortfolioError::VagueScope { field });
    }
    Ok(())
}

fn push_field(preimage: &mut String, tag: &str, value: &str) {
    preimage.push_str(tag);
    preimage.push('=');
    preimage.push_str(&value.len().to_string());
    preimage.push(':');
    preimage.push_str(value);
    preimage.push(';');
}

fn freeze(preimage: &str) -> String {
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

/// One exact structured evidence span inside a source payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSpan {
    /// Stable span identity within the source.
    pub span_id: String,
    /// Anchor locating the span (section, page, symbol path).
    pub anchor: String,
    /// Digest of the exact excerpt bytes.
    pub excerpt_digest: String,
}

/// A vetted source record. Every I15.5 assurance dimension is an explicit
/// typed field: identity/provenance, integrity, freshness, domain competence,
/// incentives/track record, independence/common lineage, privacy class,
/// instruction-injection risk, deception/exfiltration/persistence risk,
/// allowed epistemic use, allowed effects, and required verifier/quarantine.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn new(params: SourceRecordParams) -> Result<Self, PortfolioError> {
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

    /// Canonical digest of this vetted record.
    pub fn digest(&self) -> String {
        let mut preimage = String::from("source-record/v1;");
        self.canonical_into(&mut preimage);
        freeze(&preimage)
    }

    fn canonical_into(&self, preimage: &mut String) {
        push_field(preimage, "handle", &self.handle);
        push_field(preimage, "class", &format!("{:?}", self.class));
        push_field(preimage, "locator", &self.locator);
        push_field(preimage, "content_digest", &self.content_digest);
        push_field(preimage, "operation_id", &self.operation_id);
        push_field(preimage, "receipt_handle", &self.receipt_handle);
        push_field(preimage, "acquisition", self.acquisition.wire_name());
        if let Some(grade) = self.grade {
            push_field(preimage, "grade", &grade.to_string());
        }
        preimage.push_str(&format!("domains={};", self.authority_domains.len()));
        for domain in &self.authority_domains {
            push_field(preimage, "domain", domain);
        }
        if let Some(root) = &self.lineage_root {
            push_field(preimage, "lineage_root", root);
        }
        push_field(preimage, "disclosure", &format!("{:?}", self.disclosure));
        push_field(preimage, "deception_risk", self.deception_risk.wire_name());
    }
}

/// One expected source-role slot of the frozen denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub digest: String,
}

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
        params
            .fence
            .validate()
            .map_err(|_| PortfolioError::Blank {
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
        let mut preimage = String::from("frozen-inquiry/v1;");
        push_field(&mut preimage, "schema", &params.schema);
        push_field(&mut preimage, "protocol", &params.protocol);
        push_field(&mut preimage, "policy", &params.policy);
        push_field(&mut preimage, "question", &params.question);
        push_field(&mut preimage, "objective", &params.objective);
        push_field(&mut preimage, "output_contract", &params.output_contract);
        push_field(&mut preimage, "requester", &params.requester);
        push_field(&mut preimage, "task", &params.task);
        push_field(&mut preimage, "attempt", &params.attempt);
        push_field(&mut preimage, "scope", &params.scope);
        push_field(&mut preimage, "privacy", &params.privacy);
        push_field(
            &mut preimage,
            "disclosure",
            &format!("{:?}", params.disclosure),
        );
        preimage.push_str(&format!("roles={};", params.roles.len()));
        for slot in &params.roles {
            push_field(&mut preimage, "role", &slot.role);
            push_field(&mut preimage, "class", &format!("{:?}", slot.class));
            push_field(&mut preimage, "required", &slot.required.to_string());
            push_field(&mut preimage, "authority_domain", &slot.authority_domain);
        }
        preimage.push_str(&format!("routes={};", params.routes.len()));
        for route in &params.routes {
            push_field(&mut preimage, "route", route);
        }
        for (tag, value) in [
            ("attempts", params.budgets.attempts),
            ("sources", params.budgets.sources),
            ("bytes", params.budgets.bytes),
            ("stu", params.budgets.stu),
            ("output", params.budgets.output),
            ("cost", params.budgets.cost),
            ("work", params.budgets.work),
        ] {
            push_field(&mut preimage, tag, &value.to_string());
        }
        push_field(
            &mut preimage,
            "deadline_ms",
            &params.budgets.deadline_ms.to_string(),
        );
        push_field(&mut preimage, "stop_rule", &params.stop_rule);
        push_field(&mut preimage, "partial_policy", &params.partial_policy);
        push_field(&mut preimage, "operation_id", &params.operation_id);
        push_field(&mut preimage, "replay_id", &params.replay_id);
        Ok(Self {
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
            digest: freeze(&preimage),
        })
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
        preimage.push_str(&format!("members={};", members.len()));
        for member in &members {
            push_field(&mut preimage, "member", member);
        }
        freeze(&preimage)
    }
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
    let mut route_cursor = 0usize;
    for member in inquiry.denominator_members() {
        let role = member.split('#').next().unwrap_or(&member).to_owned();
        let route = inquiry
            .routes
            .get(route_cursor % inquiry.routes.len())
            .cloned()
            .unwrap_or_default();
        route_cursor += 1;
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
            table.entries.insert(handle.clone(), record.lineage_root.clone());
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

/// Validates the source-level citation graph: derived copies group under
/// exact roots, circular citations fail, and edges to unrecorded handles fail
/// as unresolved roots instead of being assumed.
pub fn check_citation_graph(records: &BTreeMap<String, SourceRecord>) -> Result<(), PortfolioError> {
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
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Visiting,
        Done,
    }
    let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();
    for handle in records.keys() {
        let mut stack: Vec<(&str, bool)> = vec![(handle.as_str(), false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                marks.insert(node, Mark::Done);
                continue;
            }
            match marks.get(node) {
                Some(Mark::Done) => continue,
                Some(Mark::Visiting) => {
                    return Err(PortfolioError::CircularCitation {
                        field: "source.cites",
                    });
                }
                None => {}
            }
            marks.insert(node, Mark::Visiting);
            stack.push((node, true));
            if let Some(record) = records.get(node) {
                for edge in &record.cites {
                    match marks.get(edge.as_str()) {
                        Some(Mark::Done) => {}
                        Some(Mark::Visiting) => {
                            return Err(PortfolioError::CircularCitation {
                                field: "source.cites",
                            });
                        }
                        None => stack.push((edge.as_str(), false)),
                    }
                }
            }
        }
        let _ = handle;
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
pub fn decide_grade(
    records: &[&SourceRecord],
    claim_domain: &str,
    now_ms: i64,
) -> GradeDecision {
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
            capped = capped.min(0);
            limits.push(format!("grade: source {} stale caps ORIENTING", record.handle));
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
    let ceiling = match weakest_ceiling(&ranks) {
        Ok(ceiling) => ceiling,
        Err(_) => None,
    };
    if ceiling.is_none() && !limits.iter().any(|l| l.contains("unknown")) {
        limits.push("grade: unknown poisons ceiling".to_owned());
    }
    limits.sort();
    GradeDecision { ceiling, limits }
}

/// Exact coverage accounting over the frozen denominator: every expected
/// member carries exactly one visible disposition, an explicit exclusion, or
/// a budget-frontier note. Complete accounting never implies that all
/// evidence succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageAccount {
    expected: BTreeSet<String>,
    outcomes: BTreeMap<String, (SourceDisposition, Option<String>)>,
    exclusions: BTreeMap<String, String>,
    frontier: Option<String>,
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
        })
    }

    /// Records one disposition for one expected member, with the acquiring
    /// source handle when one exists. Re-recording the same disposition is
    /// idempotent; a changed disposition for the same member conflicts.
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
        if self.exclusions.contains_key(member) {
            return Err(PortfolioError::Conflict {
                field: "coverage.member",
            });
        }
        match self.outcomes.get(member) {
            Some((current, _)) if *current == disposition => Ok(()),
            Some(_) => Err(PortfolioError::Conflict {
                field: "coverage.member",
            }),
            None => {
                if let Some(handle) = &handle {
                    text(handle, "coverage.handle")?;
                }
                self.outcomes
                    .insert(member.to_owned(), (disposition, handle));
                Ok(())
            }
        }
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
            {
                if let Some(handle) = handle {
                    handles.push(handle.clone());
                }
            }
        }
        lineage.independent_support(&handles)
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
        preimage.push_str(&format!("expected={};", self.expected.len()));
        for member in &self.expected {
            push_field(preimage, "expected", member);
        }
        preimage.push_str(&format!("outcomes={};", self.outcomes.len()));
        for (member, (disposition, handle)) in &self.outcomes {
            push_field(preimage, "member", member);
            push_field(preimage, "disposition", disposition.wire_name());
            if let Some(handle) = handle {
                push_field(preimage, "handle", handle);
            }
        }
        preimage.push_str(&format!("exclusions={};", self.exclusions.len()));
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
    /// Proven: complete denominator, full accounting, authoritative lookup.
    Proven,
    /// Unproven: unknown or unavailable material leaves the negative open.
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

/// Assesses a scoped absence claim. Only a complete denominator with full
/// accounting and an authoritative lookup proves absence; unknown or
/// unavailable material is never absence, and bounded exhaustion is partial.
pub fn assess_absence(
    denominator_complete: bool,
    account: &CoverageAccount,
    authoritative_lookup: bool,
) -> AbsenceVerdict {
    if account.frontier.is_some() {
        return AbsenceVerdict::PartialExhaustion {
            frontier: account.frontier.clone().unwrap_or_default(),
        };
    }
    if !denominator_complete {
        return AbsenceVerdict::Unproven {
            reason: "denominator is not a complete scope".to_owned(),
        };
    }
    if !account.is_accounted() {
        return AbsenceVerdict::Unproven {
            reason: "coverage accounting is incomplete".to_owned(),
        };
    }
    if !authoritative_lookup {
        return AbsenceVerdict::Unproven {
            reason: "lookup is not authoritative for this scope".to_owned(),
        };
    }
    let open = account.outcomes.values().any(|(disposition, _)| {
        matches!(
            disposition,
            SourceDisposition::Unknown | SourceDisposition::Unavailable
        )
    });
    if open {
        return AbsenceVerdict::Unproven {
            reason: "unknown or unavailable material leaves the negative open".to_owned(),
        };
    }
    AbsenceVerdict::Proven
}

/// Structured precision kinds for already-structured claim/reference records.
/// No prose is parsed: assertions arrive structured and are checked against
/// structured support.
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
    if head.chars().any(|c| !c.is_ascii_digit())
        || tail.chars().any(|c| !c.is_ascii_digit())
    {
        return None;
    }
    let scale = tail.len();
    let mut scaled: i128 = head.parse::<i128>().ok()?.checked_mul(10i128.checked_pow(
        u32::try_from(scale).ok()?,
    )?)?;
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
pub fn check_precision(
    assertion: &PrecisionAssertion,
) -> Result<(), UnsupportedPrecisionItem> {
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
    pub counterclaim_ids: Vec<String>,
    /// Unknown evidence references that must stay explicit.
    pub unknown_refs: Vec<String>,
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
    /// A citation falls outside the frozen manifest.
    OutsideManifest,
    /// Stale material limits the claim without closing it.
    StaleLimited,
    /// Material-claim accounting is incomplete.
    IncompleteAccounting,
}

impl ClaimOutcome {
    /// Stable wire spelling of this outcome.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::PartiallySupported => "PARTIALLY_SUPPORTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Contradicted => "CONTRADICTED",
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
    /// Preserved counterevidence identities.
    pub counterevidence: Vec<String>,
    /// Preserved unknown references.
    pub unknowns: Vec<String>,
    /// Grade ceiling over the supporting records, when computable.
    pub grade_ceiling: Option<u8>,
    /// Evidence handles behind the verdict, sorted.
    pub evidence_map: Vec<String>,
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

/// One immutable authorized manifest over the exact inquiry, denominator,
/// source and evidence identities, raw and transform digests, dependence
/// graph, coverage, grade limits, counterevidence, conflicts, unknowns, the
/// reference allowlist, and privacy/expiry bounds. Canonical sets are frozen
/// sorted, so the manifest bytes are stable under arrival order while
/// meaningful sequence stays identity-visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedManifest {
    /// Digest of the frozen inquiry.
    pub inquiry_digest: String,
    /// Digest of the exact denominator.
    pub denominator_digest: String,
    /// Source identities to `(content digest, transform lineage)` pairs.
    pub sources: BTreeMap<String, (String, Option<String>)>,
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
    pub digest: String,
}

/// Named constructor arguments for [`AuthorizedManifest::freeze`].
#[derive(Clone, Debug)]
pub struct AuthorizedManifestParams {
    /// Inquiry digest.
    pub inquiry_digest: String,
    /// Denominator digest.
    pub denominator_digest: String,
    /// Source identities.
    pub sources: BTreeMap<String, (String, Option<String>)>,
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
        for (handle, (content, raw)) in &params.sources {
            text(handle, "manifest.source")?;
            digest(content, "manifest.content_digest")?;
            if let Some(raw) = raw {
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
        let mut preimage = String::from("authorized-manifest/v1;");
        push_field(&mut preimage, "inquiry_digest", &params.inquiry_digest);
        push_field(
            &mut preimage,
            "denominator_digest",
            &params.denominator_digest,
        );
        preimage.push_str(&format!("sources={};", params.sources.len()));
        for (handle, (content, raw)) in &params.sources {
            push_field(&mut preimage, "source", handle);
            push_field(&mut preimage, "content", content);
            if let Some(raw) = raw {
                push_field(&mut preimage, "raw", raw);
            }
        }
        preimage.push_str(&format!("edges={};", params.dependence_edges.len()));
        for (from, to) in &params.dependence_edges {
            push_field(&mut preimage, "from", from);
            push_field(&mut preimage, "to", to);
        }
        push_field(&mut preimage, "coverage_digest", &params.coverage_digest);
        for limit in &params.grade_limits {
            push_field(&mut preimage, "grade_limit", limit);
        }
        for item in &params.counterevidence {
            push_field(&mut preimage, "counterevidence", item);
        }
        for item in &params.conflicts {
            push_field(&mut preimage, "conflict", item);
        }
        for item in &params.unknowns {
            push_field(&mut preimage, "unknown", item);
        }
        for handle in &params.allowlist {
            push_field(&mut preimage, "allowed", handle);
        }
        for handle in &params.revoked {
            push_field(&mut preimage, "revoked", handle);
        }
        push_field(
            &mut preimage,
            "disclosure",
            &format!("{:?}", params.disclosure),
        );
        push_field(&mut preimage, "expires_ms", &params.expires_ms.to_string());
        push_field(&mut preimage, "revision", &params.revision.to_string());
        Ok(Self {
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
            digest: freeze(&preimage),
        })
    }

    /// Whether `handle` is citable under this manifest: allowlisted and not
    /// revoked or stale.
    pub fn allows(&self, handle: &str) -> bool {
        self.allowlist.iter().any(|h| h == handle)
            && !self.revoked.iter().any(|h| h == handle)
    }

    /// Canonical bytes of the frozen manifest shape (without the digest
    /// field), stable under arrival order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut preimage = String::from("authorized-manifest/v1;");
        push_field(&mut preimage, "inquiry_digest", &self.inquiry_digest);
        push_field(&mut preimage, "denominator_digest", &self.denominator_digest);
        preimage.push_str(&format!("sources={};", self.sources.len()));
        for (handle, (content, raw)) in &self.sources {
            push_field(&mut preimage, "source", handle);
            push_field(&mut preimage, "content", content);
            if let Some(raw) = raw {
                push_field(&mut preimage, "raw", raw);
            }
        }
        preimage.push_str(&format!("edges={};", self.dependence_edges.len()));
        for (from, to) in &self.dependence_edges {
            push_field(&mut preimage, "from", from);
            push_field(&mut preimage, "to", to);
        }
        push_field(&mut preimage, "coverage_digest", &self.coverage_digest);
        preimage.into_bytes()
    }
}

/// Audits one already-structured claim against the frozen portfolio and
/// manifest: exact membership, authoritative lineage, scope/time/version/
/// quantity/causal/absence compatibility and complete material-claim
/// accounting. Unsupported precision, outside-manifest references and
/// insufficient coverage remain typed residue. Counterevidence and unknowns
/// are preserved, never smoothed.
pub fn audit_claim(
    claim: &AuditedClaim,
    portfolio: &EvidencePortfolio,
    manifest: &AuthorizedManifest,
    now_ms: i64,
) -> ClaimVerdict {
    let mut residue: Vec<String> = Vec::new();
    let mut supporting: Vec<&SourceRecord> = Vec::new();
    let mut evidence_map: Vec<String> = Vec::new();
    let mut stale_hit = false;
    if claim.material && claim.citations.is_empty() {
        residue.push("claim: material claim records no citations".to_owned());
    }
    for handle in &claim.citations {
        if !manifest.allows(handle) {
            residue.push(format!("claim: citation {handle} outside frozen manifest"));
            continue;
        }
        let Some(record) = portfolio.records.get(handle) else {
            residue.push(format!("claim: citation {handle} has no authoritative lineage"));
            continue;
        };
        if !record.covers_domain(&claim.domain) {
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
                residue.push(format!("claim: source {handle} stale carries no weight"));
            }
            _ => {
                residue.push(format!(
                    "claim: source {handle} disposition {} carries no weight",
                    record.acquisition.wire_name()
                ));
            }
        }
    }
    for assertion in &claim.precision {
        if let Err(item) = check_precision(assertion) {
            residue.push(format!(
                "claim: unsupported precision asserted {} supports {}",
                item.asserted, item.highest_supported
            ));
        }
    }
    let counterevidence: Vec<String> = claim.counterclaim_ids.iter().cloned().collect();
    let unknowns: Vec<String> = claim.unknown_refs.iter().cloned().collect();
    let outside = residue.iter().any(|r| r.contains("outside frozen manifest"));
    let precision_gap = residue.iter().any(|r| r.contains("unsupported precision"));
    let lineage_gap = residue
        .iter()
        .any(|r| r.contains("no authoritative lineage") || r.contains("outside claim domain"));
    let support_gap = residue.iter().any(|r| r.contains("carries no weight"));
    let outcome = if outside {
        ClaimOutcome::OutsideManifest
    } else if !counterevidence.is_empty() {
        ClaimOutcome::Contradicted
    } else if !unknowns.is_empty()
        || (claim.material && supporting.is_empty() && counterevidence.is_empty())
    {
        ClaimOutcome::IncompleteAccounting
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
    } else {
        ClaimOutcome::Supported
    };
    let grade_ceiling = decide_grade(&supporting, &claim.domain, now_ms).ceiling;
    evidence_map.sort();
    residue.sort();
    let mut counter_sorted = counterevidence;
    counter_sorted.sort();
    let mut unknowns_sorted = unknowns;
    unknowns_sorted.sort();
    ClaimVerdict {
        claim_id: claim.claim_id.clone(),
        outcome,
        residue,
        counterevidence: counter_sorted,
        unknowns: unknowns_sorted,
        grade_ceiling,
        evidence_map,
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
        if disposition.may_close_inquiry() {
            Self::Complete {
                manifest_digest: detail,
            }
        } else {
            match disposition {
                CompletionDisposition::IncompleteCoverage
                | CompletionDisposition::NoNewUsefulEvidence
                | CompletionDisposition::StaleSourceOrIndex
                | CompletionDisposition::SourceUnavailable
                | CompletionDisposition::PolicyOrDisclosureDenied
                | CompletionDisposition::Inconclusive => Self::Partial {
                    omissions: vec![detail],
                },
                CompletionDisposition::Cancelled => Self::Cancelled {
                    operation_id: detail,
                },
                CompletionDisposition::NoMatchInCompleteScope => Self::Complete {
                    manifest_digest: detail,
                },
                CompletionDisposition::AnsweredWithSupportedResult => Self::Complete {
                    manifest_digest: detail,
                },
            }
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
