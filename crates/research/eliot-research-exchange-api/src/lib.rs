//! Stable, store-neutral contracts for the ELIOT Research federation channel.
//!
//! These records deliberately do not contain provider credentials, arbitrary
//! URLs as authority, or promotion decisions.  A bridge may acquire material,
//! while Governor-owned code remains responsible for admission and lifecycle.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ClockReading, ContractVersion, StateFence, canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.research.exchange-api";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ResearchContractError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("{field} contains a duplicate identity")]
    DuplicateIdentity { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("state fence is not valid or does not match")]
    InvalidFence,
    #[error("citation references a source outside the allowed manifest")]
    CitationNotAllowed,
    #[error("delivered reference handle is outside the allowed manifest")]
    ReferenceNotAdmitted,
    #[error("delivered locator URL is not an admitted url handle")]
    UrlNotAdmitted,
    #[error("citation precision exceeds the declared source anchor")]
    UnsupportedPrecision,
    #[error("bundle disposition is incompatible with its evidence")]
    InvalidDisposition,
    #[error("{field} is not an accepted value for this record")]
    FieldNotAccepted {
        /// Failing field path.
        field: &'static str,
    },
    #[error("{field} cannot be encoded into its canonical preimage")]
    Unencodable {
        /// The record that has no canonical encoding.
        field: &'static str,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ResearchContractError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn texts(values: &[String], field: &'static str) -> Result<(), ResearchContractError> {
    if values.is_empty() {
        return Err(ResearchContractError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ResearchContractError::DuplicateIdentity { field });
    }
    Ok(())
}

/// Validates an allowlist whose empty value is honest and fail-closed: a run
/// that admits no URL, no tool definition, no verifier or no expansion route
/// admits none of them, and an empty list is therefore valid rather than
/// missing. A non-empty list may still not repeat an identity.
fn optional_texts(values: &[String], field: &'static str) -> Result<(), ResearchContractError> {
    for value in values {
        text(value, field)?;
    }
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(ResearchContractError::DuplicateIdentity { field });
    }
    Ok(())
}

/// Disclosure breadth, narrowest first.
///
/// A manifest's disclosure class may be narrower than the request that carries
/// it and never wider, so the comparison needs an explicit breadth: `Private`
/// is the narrowest class and `Public` the widest.
const fn disclosure_breadth(class: DisclosureClass) -> u8 {
    match class {
        DisclosureClass::Private => 0,
        DisclosureClass::ProjectBound => 1,
        DisclosureClass::ExportableRedacted => 2,
        DisclosureClass::Public => 3,
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), ResearchContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Err(ResearchContractError::InvalidDigest { field })
    } else {
        Ok(())
    }
}

/// Locator schemes this repository mints itself, so a locator carrying one is an
/// internal ELIOT reference and not an external URL a run has to admit.
///
/// Measured, not guessed: `git grep -hoE '[A-Za-z][A-Za-z0-9+.-]*://' -- '*.rs'`
/// over this repository yields exactly `canonical`, `connected-session`, `eliot`,
/// `governor`, `http`, `https`, `local`, `rocksdb`, `route`, `runtime`,
/// `surrealkv`, `tcp`, `ws` and `wss`. The five network schemes (`http`,
/// `https`, `ws`, `wss`, `tcp`) address a remote peer and are therefore external
/// by construction and deliberately absent. The other nine are the internal
/// store, session, route and resource identities this repository mints into its
/// own reference and locator fields — `eliot://` is the canonical `ResourceUri`
/// family (`crates/surfaces/eliot-agent-bridge-core/src/resources.rs`),
/// `surrealkv://` the store data URL, `route://` a kernel `route_ref`,
/// `canonical://` a worktree ref, `runtime://` a spool ref, `governor://` a
/// managed tool identity, `local://` and `connected-session://` session uris, and
/// `rocksdb:` the local store spec that `rocksdb://` is explicitly *not*
/// (`crates/eliot-types/src/config.rs`). A scheme absent from this list is not
/// thereby internal: it is unrecognised, and
/// [`AllowedReferenceManifest::admits_url`] decides it.
const INTERNAL_LOCATOR_SCHEMES: [&str; 9] = [
    "canonical",
    "connected-session",
    "eliot",
    "governor",
    "local",
    "rocksdb",
    "route",
    "runtime",
    "surrealkv",
];

/// The scheme token of `locator`, or `None` when it carries none.
///
/// RFC 3986 spells a scheme `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
/// immediately before the first `:`. The scan stops at the first character
/// outside that grammar, so a locator with no `:` at all, and a handle that
/// merely contains a colon in a position that is not a scheme — `src ref:3` —
/// carry no scheme and stay opaque handles. The check reads characters and never
/// resolves, normalises or fetches anything.
fn scheme_token(locator: &str) -> Option<&str> {
    let colon = locator.find(':')?;
    let scheme = &locator[..colon];
    let mut characters = scheme.chars();
    let opens = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic());
    let continues = characters
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'));
    (opens && continues).then_some(scheme)
}

/// Whether a delivered locator presents an absolute external URL.
///
/// The check is deliberately structural and decides on the scheme token rather
/// than on the shape of what follows it, so it stays sound in both directions a
/// `://` substring test is not: an absolute URI that carries no scheme separator
/// (`urn:doi:10.1000/182`, `mailto:`, `data:`) is still external, and an
/// internal ELIOT reference that does carry one is not. A locator with no scheme
/// is an opaque store handle. A `name::id` double-colon spelling is this
/// repository's namespaced handle form (`snapshot::src-a`) and cannot be a URI
/// at all, because a path and an opaque part may not begin with a colon, so it
/// stays a handle. A scheme in [`INTERNAL_LOCATOR_SCHEMES`] is an internal
/// reference. Everything else is external and must be named in `url_handles`, so
/// a scheme this crate cannot classify fails closed through
/// [`AllowedReferenceManifest::admits_url`] instead of being admitted on a
/// guess. That includes a single-letter Windows drive scheme (`C:\…` is
/// formally a URI with scheme `C`): this contract calls such a locator external
/// and requires it to be admitted, which is the fail-closed reading and not a
/// claim that it is a network address.
fn is_absolute_locator(locator: &str) -> bool {
    match scheme_token(locator) {
        None => false,
        Some(scheme) if locator.as_bytes().get(scheme.len()) == Some(&b':') => false,
        Some(scheme) => !INTERNAL_LOCATOR_SCHEMES.contains(&scheme),
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    Paper,
    Documentation,
    Dataset,
    Repository,
    Web,
    Report,
    ServiceDossier,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClass {
    Private,
    ProjectBound,
    ExportableRedacted,
    Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionDisposition {
    AnsweredWithSupportedResult,
    NoMatchInCompleteScope,
    NoNewUsefulEvidence,
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    IncompleteCoverage,
    Inconclusive,
    Cancelled,
}

impl CompletionDisposition {
    #[must_use]
    pub const fn may_close_inquiry(self) -> bool {
        matches!(
            self,
            Self::AnsweredWithSupportedResult | Self::NoMatchInCompleteScope
        )
    }

    #[must_use]
    pub const fn requires_typed_coverage_gaps(self) -> bool {
        matches!(
            self,
            Self::SourceUnavailable | Self::StaleSourceOrIndex | Self::IncompleteCoverage
        )
    }

    /// Stable wire spelling of this disposition, shared by every surface that
    /// reports it. The spelling is the I21.9 disposition name, so a seal, a
    /// record and a log line name the same outcome.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AnsweredWithSupportedResult => "answered_with_supported_result",
            Self::NoMatchInCompleteScope => "no_match_in_complete_scope",
            Self::NoNewUsefulEvidence => "no_new_useful_evidence",
            Self::SourceUnavailable => "source_unavailable",
            Self::StaleSourceOrIndex => "stale_source_or_index",
            Self::PolicyOrDisclosureDenied => "policy_or_disclosure_denied",
            Self::IncompleteCoverage => "incomplete_coverage",
            Self::Inconclusive => "inconclusive",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Typed reason one source contributes no evidence. Timeout, cancellation,
/// crash-adjacent unavailability, stale indexes, policy denial and unknown
/// provider outcomes remain distinct: an unavailable source never decodes as
/// an empty-but-complete scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    BudgetExhausted,
    Timeout,
    Cancelled,
    Unknown,
}

/// One typed coverage gap: an unavailable source identity plus the distinct
/// reason it yields no evidence. Gaps are degradation evidence, not
/// absence/completeness claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub source_handle: String,
    pub kind: CoverageGapKind,
    pub detail: String,
}

impl CoverageGap {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.source_handle, "gap.source_handle")?;
        text(&self.detail, "gap.detail")?;
        Ok(())
    }
}

/// Run-bound reference allowlist for one Researcher / research-exchange job.
///
/// # Ownership decision (issue #1764, audit follow-up)
///
/// This type is the canonical `AllowedReferenceManifest` **for the Researcher
/// and research-exchange job contract**. It is the run-bound input allowlist
/// I21.7 requires, it is the type the issue's declared owner crates consume,
/// and it is the type the live path carries: `ResearchQueryRequest::allowed_references`
/// and `InquiryObservation::reference_manifest` are both this type, and its
/// digest is bound into the profile, coverage receipt, evidence freeze and
/// terminal inquiry record.
///
/// `eliot_dreamer_contracts::grounding::AllowedReferenceManifest` is **not** a
/// duplicate of this type and is deliberately not merged into it. It is the
/// Dreamer grounding ledger's *evaluated preimage* — a different artifact with a
/// different shape (`references: BTreeMap<ArtifactId, AuthorizedReference>`,
/// `source_snapshot`, `coverage_receipts`, `dependence_groups`) and a different
/// consumer set. At the time of writing it has ~30 live call sites across
/// `bins/eliot-dreamer`, `crates/smart/eliot-dreamer-bundle`,
/// `crates/smart/eliot-dreamer-claim-grounding` and their tests, and its crate
/// is outside this issue's declared owner scope. The two are the ledger side
/// and the job-contract side of one I21.7 concept. Do not "fix" this a third
/// time by deleting either definition.
///
/// # What the manifest must carry (I21.7)
///
/// Every field below is inside the digest preimage (see [`Self::canonical_digest`]),
/// so a field that can change what a citation is allowed to say cannot be
/// supplied by a caller. A reference outside this allowlist is unsupported text:
/// it can never become a citable source, a supported citation, a support
/// relation or an evidence edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowedReferenceManifest {
    /// Run identity this allowlist is bound to.
    pub run_id: String,
    /// I21.7: the exact run/job/root context revision this allowlist was
    /// derived from. A citation admitted under one root context revision is not
    /// a citation under another, so the revision is part of the identity.
    pub root_context_revision: String,
    /// The State Fence this allowlist is bound to.
    pub state_fence: StateFence,
    /// Allowed source-record handles.
    pub source_handles: Vec<String>,
    /// Allowed evidence handles.
    pub evidence_handles: Vec<String>,
    /// Allowed artifact handles.
    pub artifact_handles: Vec<String>,
    /// I21.7: allowed URL handles.
    ///
    /// A URL is never authority. An empty list is the honest fail-closed value:
    /// a run that admits no URL admits no locator URL, and any absolute URL a
    /// bridge presents is then untrusted text.
    #[serde(default)]
    pub url_handles: Vec<String>,
    /// I21.7: allowed tool-definition refs a cited support relation may rest on.
    ///
    /// Empty is the honest fail-closed value: a run that admits no tool
    /// definition admits no tool-derived citation.
    #[serde(default)]
    pub tool_refs: Vec<String>,
    /// I21.7: allowed verifier refs a cited support relation may rest on.
    ///
    /// Empty is the honest fail-closed value: a run that admits no verifier
    /// admits no verifier-dependent citation.
    #[serde(default)]
    pub verifier_refs: Vec<String>,
    /// Highest anchor/coordinate precision any citation may claim.
    pub allowed_anchor_precision: AnchorPrecision,
    /// I21.7: the scope class this allowlist is scoped to.
    pub scope_class: String,
    /// I21.7: the disclosure class this allowlist is bound to. A manifest may
    /// never be wider than the request that carries it.
    pub disclosure: DisclosureClass,
    /// I21.7: the retention class this allowlist is bound to.
    pub retention_class: String,
    /// Stale or revoked entries: references this manifest once admitted and
    /// that have since gone stale or been revoked.
    ///
    /// Revocation wins over admission. A handle listed here is refused by
    /// [`Self::allows`] and [`Self::admits_url`] even though it is still listed
    /// in an allowlist above — the overlap is legal, and it is exactly how "this
    /// WAS admitted and has since gone stale or revoked" is expressed, so a
    /// manifest must not treat the pair as a contradiction. Widening an
    /// allowlist never removes a stale entry.
    pub stale_or_revoked_handles: Vec<String>,
    /// I21.7: the routes this manifest may be expanded onto. An empty list means
    /// the manifest travels nowhere else, which is the fail-closed reading.
    #[serde(default)]
    pub expansion_routes: Vec<String>,
    /// Canonical digest over every field above.
    pub digest: String,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AnchorPrecision {
    Source,
    Document,
    Page,
    Section,
    Paragraph,
    Line,
    ByteRange,
}

impl AnchorPrecision {
    fn permits(self, requested: Self) -> bool {
        self >= requested
    }
}

impl AllowedReferenceManifest {
    /// Validates the allowlist and re-proves its digest.
    ///
    /// The digest is computed over every field that can change what a citation
    /// is allowed to say, so a manifest whose content was widened after it was
    /// sealed is refused here instead of being published as a bound allowlist.
    /// This is reached on the live path through
    /// `ResearchQueryRequest::validate`, so a caller cannot present a manifest
    /// whose digest is unrelated to its own content.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.run_id, "manifest.run_id")?;
        text(
            &self.root_context_revision,
            "manifest.root_context_revision",
        )?;
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        texts(&self.source_handles, "manifest.source_handles")?;
        for values in [&self.evidence_handles, &self.artifact_handles] {
            if !values.is_empty() {
                texts(values, "manifest.handles")?;
            }
        }
        for (values, field) in [
            (&self.url_handles, "manifest.url_handles"),
            (&self.tool_refs, "manifest.tool_refs"),
            (&self.verifier_refs, "manifest.verifier_refs"),
            (&self.expansion_routes, "manifest.expansion_routes"),
        ] {
            optional_texts(values, field)?;
        }
        text(&self.scope_class, "manifest.scope_class")?;
        text(&self.retention_class, "manifest.retention_class")?;
        optional_texts(
            &self.stale_or_revoked_handles,
            "manifest.stale_or_revoked_handles",
        )?;
        digest(&self.digest, "manifest.digest")?;
        if self.canonical_digest()? != self.digest {
            return Err(ResearchContractError::InvalidDigest {
                field: "manifest.digest",
            });
        }
        Ok(())
    }

    /// Seals this allowlist by computing its digest over its own content.
    ///
    /// This is the only way to produce a manifest that validates: a caller
    /// supplies content and never supplies the digest.
    pub fn seal(mut self) -> Result<Self, ResearchContractError> {
        self.digest = String::new();
        self.digest = self.canonical_digest()?;
        Ok(self)
    }

    /// Canonical digest over the whole allowlist shape.
    ///
    /// The stored digest is excluded from its own preimage, and every other
    /// field is inside it: identity (`run_id`, `root_context_revision`,
    /// `state_fence`), every allowlist, the precision ceiling, the scope /
    /// disclosure / retention classes, the stale-or-revoked set, the expansion
    /// routes, and the contract version that gave the shape its meaning.
    pub fn canonical_digest(&self) -> Result<String, ResearchContractError> {
        let mut shape = self.clone();
        shape.digest = String::new();
        let bytes =
            canonical_json_bytes(&shape).map_err(|_| ResearchContractError::Unencodable {
                field: "allowed_reference_manifest",
            })?;
        Ok(sha256_hex(&bytes))
    }

    /// Every handle this manifest admits as a *citable reference*, in its
    /// declared order.
    ///
    /// `url_handles` is deliberately absent. A URL is a locator, not a source
    /// identity, and [`Self::admits_url`] is its only admission path; chaining
    /// it here would let a bare URL become a `SourceSnapshot::source_handle`,
    /// an evidence edge and a supporting `ExactCitation::source_handle` with no
    /// source record behind it.
    fn allowed_handles(&self) -> impl Iterator<Item = &str> {
        self.source_handles
            .iter()
            .chain(&self.evidence_handles)
            .chain(&self.artifact_handles)
            .map(String::as_str)
    }

    /// Whether this manifest admits `handle` as a citable reference.
    ///
    /// Only source, evidence and artifact handles are citable reference
    /// identities, so a URL listed in `url_handles` is *not* admitted here and
    /// can never become a source handle, an evidence edge or a supporting
    /// citation. A URL is admitted as a locator by [`Self::admits_url`] alone.
    ///
    /// A handle this manifest admits but also lists as stale or revoked is
    /// never admitted: revocation is applied after membership and on every
    /// call, so the answer does not depend on the order the two lists are read
    /// in.
    #[must_use]
    pub fn allows(&self, handle: &str) -> bool {
        self.allowed_handles().any(|candidate| candidate == handle)
            && !self.stale_or_revoked_handles.iter().any(|x| x == handle)
    }

    /// Whether this manifest admits `url` as a locator URL.
    ///
    /// A URL outside this list is not an authority and not a source: it is
    /// untrusted text that may only be retained as an untrusted candidate.
    #[must_use]
    pub fn admits_url(&self, url: &str) -> bool {
        self.url_handles.iter().any(|candidate| candidate == url)
            && !self.stale_or_revoked_handles.iter().any(|x| x == url)
    }

    /// Whether this manifest may be expanded onto `route`.
    ///
    /// I21.7 lists expansion routes as manifest content, and a result packed for
    /// another route travels on one: an empty list means the result travels
    /// nowhere else, which is the fail-closed reading.
    #[must_use]
    pub fn permits_expansion(&self, route: &str) -> bool {
        self.expansion_routes
            .iter()
            .any(|candidate| candidate == route)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchQueryRequest {
    pub exchange_id: String,
    pub protocol_revision: ContractVersion,
    pub bridge_generation: String,
    pub idempotency_key: String,
    pub requester_principal: String,
    pub state_fence: StateFence,
    pub question: String,
    pub question_scope: String,
    pub expected_decision: String,
    pub source_classes: Vec<SourceClass>,
    pub coverage_goal: String,
    pub allowed_references: AllowedReferenceManifest,
    pub disclosure: DisclosureClass,
    pub retention: String,
    pub license_policy: String,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub required_schema: String,
}

impl ResearchQueryRequest {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "exchange_id"),
            (&self.bridge_generation, "bridge_generation"),
            (&self.idempotency_key, "idempotency_key"),
            (&self.requester_principal, "requester_principal"),
            (&self.question, "question"),
            (&self.question_scope, "question_scope"),
            (&self.expected_decision, "expected_decision"),
            (&self.coverage_goal, "coverage_goal"),
            (&self.retention, "retention"),
            (&self.license_policy, "license_policy"),
            (&self.required_schema, "required_schema"),
        ] {
            text(value, field)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        self.allowed_references.validate()?;
        // A manifest may never be wider than the request that carries it. Each
        // refusal names the field that disagrees, so an operator reading the
        // error is told which declaration to correct instead of inferring it
        // from a disposition error that says nothing about the cause.
        if self.allowed_references.state_fence != self.state_fence {
            return Err(ResearchContractError::FieldNotAccepted {
                field: "allowed_references.state_fence",
            });
        }
        if disclosure_breadth(self.allowed_references.disclosure)
            > disclosure_breadth(self.disclosure)
        {
            return Err(ResearchContractError::FieldNotAccepted {
                field: "allowed_references.disclosure",
            });
        }
        if self.allowed_references.retention_class != self.retention {
            return Err(ResearchContractError::FieldNotAccepted {
                field: "allowed_references.retention_class",
            });
        }
        if self.budget_units == 0 {
            return Err(ResearchContractError::FieldNotAccepted {
                field: "budget_units",
            });
        }
        if self.deadline_ms <= 0 {
            return Err(ResearchContractError::FieldNotAccepted {
                field: "deadline_ms",
            });
        }
        if self.source_classes.is_empty() {
            return Err(ResearchContractError::EmptyCollection {
                field: "source_classes",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    pub source_handle: String,
    pub class: SourceClass,
    pub title: String,
    pub locator: String,
    pub snapshot_digest: String,
    pub captured_at: ClockReading,
    pub coverage: String,
    pub disclosure: DisclosureClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactCitation {
    pub source_handle: String,
    pub anchor: String,
    pub precision: AnchorPrecision,
    pub excerpt: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchClaim {
    pub claim_id: String,
    pub statement: String,
    pub citations: Vec<ExactCitation>,
    pub counterclaim_ids: Vec<String>,
    pub confidence_note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchEvidenceBundle {
    pub exchange_id: String,
    pub job_id: String,
    pub system_generation: String,
    pub immutable_bundle_digest: String,
    pub origin_authentication: String,
    pub state_fence: StateFence,
    pub sources: Vec<SourceSnapshot>,
    pub claims: Vec<ResearchClaim>,
    pub bounded_excerpts: Vec<String>,
    pub artifact_handles: Vec<String>,
    pub coverage_unknowns: Vec<String>,
    pub failed_acquisition: Vec<String>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
    pub disposition: CompletionDisposition,
    pub synthesis_is_candidate: bool,
    pub disclosure: DisclosureClass,
    pub invalidation: Option<String>,
}

impl ResearchEvidenceBundle {
    pub fn validate_against(
        &self,
        request: &ResearchQueryRequest,
    ) -> Result<(), ResearchContractError> {
        if self.exchange_id != request.exchange_id
            || self.state_fence != request.state_fence
            || !self.synthesis_is_candidate
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        digest(
            &self.immutable_bundle_digest,
            "bundle.immutable_bundle_digest",
        )?;
        text(&self.job_id, "bundle.job_id")?;
        text(&self.system_generation, "bundle.system_generation")?;
        text(&self.origin_authentication, "bundle.origin_authentication")?;
        for unknown in &self.coverage_unknowns {
            text(unknown, "bundle.coverage_unknowns")?;
        }
        for failed in &self.failed_acquisition {
            text(failed, "bundle.failed_acquisition")?;
        }
        let mut seen_gaps = BTreeSet::new();
        for gap in &self.coverage_gaps {
            gap.validate()?;
            if !seen_gaps.insert(&gap.source_handle) {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "bundle.coverage_gaps",
                });
            }
            // A typed gap names a source identity, and the handoff seal
            // publishes `coverage_gap_handles` verbatim inside the digest it
            // seals. Without this check a bundle could therefore carry an
            // unadmitted reference — including a bare URL — across a sealed
            // boundary, so a gap handle is gated exactly like a delivered source
            // handle. The duplicate rule above still runs first, so a repeated
            // gap identity is still `DuplicateIdentity` and the gap/source
            // overlap rule below is unchanged.
            if !request.allowed_references.allows(&gap.source_handle) {
                return Err(ResearchContractError::ReferenceNotAdmitted);
            }
        }
        if self.coverage_gaps.iter().any(|gap| {
            self.sources
                .iter()
                .any(|s| s.source_handle == gap.source_handle)
        }) {
            return Err(ResearchContractError::InvalidDisposition);
        }
        if self.disposition == CompletionDisposition::AnsweredWithSupportedResult {
            if self.sources.is_empty() || self.claims.is_empty() {
                return Err(ResearchContractError::InvalidDisposition);
            }
            if !self.coverage_gaps.is_empty()
                || !self.coverage_unknowns.is_empty()
                || !self.failed_acquisition.is_empty()
            {
                return Err(ResearchContractError::InvalidDisposition);
            }
        }
        if self.disposition.requires_typed_coverage_gaps() && self.coverage_gaps.is_empty() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        for source in &self.sources {
            text(&source.source_handle, "source.source_handle")?;
            digest(&source.snapshot_digest, "source.snapshot_digest")?;
            source
                .captured_at
                .validate()
                .map_err(|_| ResearchContractError::InvalidDisposition)?;
            // I21.7 reference firewall, before candidate promotion: a delivered
            // source snapshot is itself a reference. Only a handle the manifest
            // admits may become an evidence edge, so a source identity a bridge
            // mints cannot enter the bundle at all — not as evidence, and not as
            // an exportable source.
            if !request.allowed_references.allows(&source.source_handle) {
                return Err(ResearchContractError::ReferenceNotAdmitted);
            }
            // I21.7: "It cannot mint a valid citation, URL, source ID, line
            // range, artifact handle or support relation through prose." A
            // syntactically valid locator URL the manifest does not list is
            // exactly that, so it is refused here rather than delivered.
            if is_absolute_locator(&source.locator)
                && !request.allowed_references.admits_url(&source.locator)
            {
                return Err(ResearchContractError::UrlNotAdmitted);
            }
        }
        for handle in &self.artifact_handles {
            text(handle, "bundle.artifact_handles")?;
            // The artifact handle is a reference identity of its own, and I21.7
            // lists it beside source/evidence/URL handles. An artifact handle
            // the manifest does not admit never reaches an export.
            if !request.allowed_references.allows(handle) {
                return Err(ResearchContractError::ReferenceNotAdmitted);
            }
        }
        for claim in &self.claims {
            text(&claim.claim_id, "claim.claim_id")?;
            text(&claim.statement, "claim.statement")?;
            text(&claim.confidence_note, "claim.confidence_note")?;
            if claim.citations.is_empty()
                && self.disposition == CompletionDisposition::AnsweredWithSupportedResult
            {
                return Err(ResearchContractError::CitationNotAllowed);
            }
            for citation in &claim.citations {
                if !request.allowed_references.allows(&citation.source_handle)
                    || !request
                        .allowed_references
                        .allowed_anchor_precision
                        .permits(citation.precision)
                    || !self
                        .sources
                        .iter()
                        .any(|s| s.source_handle == citation.source_handle)
                {
                    return Err(ResearchContractError::CitationNotAllowed);
                }
                text(&citation.anchor, "citation.anchor")?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn has_typed_coverage_gaps(&self) -> bool {
        !self.coverage_gaps.is_empty()
    }

    /// Whether the bundle carries an explicit budget-exhaustion gap entry.
    /// A13.11 keeps verified partial work AND the coverage gap on budget
    /// exhaustion; a close that hides exhaustion behind other gap kinds
    /// violates ARCH-RES-04 (degradation visible and local).
    #[must_use]
    pub fn has_budget_exhausted_gap(&self) -> bool {
        self.coverage_gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::BudgetExhausted)
    }

    #[must_use]
    pub fn typed_gap_handles(&self) -> Vec<&str> {
        let mut handles: Vec<&str> = self
            .coverage_gaps
            .iter()
            .map(|gap| gap.source_handle.as_str())
            .collect();
        handles.sort_unstable();
        handles
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchExportBundle {
    pub exchange_id: String,
    pub product_identity: String,
    pub payload_handle: String,
    pub source_handles: Vec<String>,
    pub redactions: Vec<String>,
    pub purpose: String,
    pub allowed_use: String,
    pub retention: String,
    pub return_channel: String,
    pub disclosure_decision: String,
}

impl ResearchExportBundle {
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "export.exchange_id"),
            (&self.product_identity, "export.product_identity"),
            (&self.payload_handle, "export.payload_handle"),
            (&self.purpose, "export.purpose"),
            (&self.allowed_use, "export.allowed_use"),
            (&self.retention, "export.retention"),
            (&self.return_channel, "export.return_channel"),
            (&self.disclosure_decision, "export.disclosure_decision"),
        ] {
            text(value, field)?;
        }
        texts(&self.source_handles, "export.source_handles")
    }
}

// ===========================================================================
// Durable exchange-job lifecycle records (issue #1766).
//
// I21.11: "The federation is asynchronous and durable: jobs expose progress,
// cancellation, partial results, source coverage and terminal disposition" and
// "Pending exports/imports remain durable exchange jobs and resume by
// idempotency identity rather than duplicate transfer." I21.9 types the closure;
// I21.13 forbids an empty answer, an exhausted search, a stopped agent or an
// approaching budget limit from promoting itself to a supported answer.
//
// The records below are store-neutral: they name what a durable job is, not
// where it is stored. The owning ELIOT store implements the persistence
// contract at the end of this section; this crate defines no database, no
// remote-store fallback and no scheduler.
// ===========================================================================

/// Authority binding of one research exchange.
///
/// I21.11: ELIOT Research "is not the Researcher plane or a privileged
/// in-process owner and never shares ELIOT's canonical database or authority
/// lineage", and "Direct remote DB access, shared credentials, implicit
/// bidirectional replication and Research-initiated ELIOT writes are
/// forbidden". The contract therefore admits exactly one binding, so a record
/// can never assert a Research-held authority it was never granted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchAuthorityBinding {
    /// ELIOT-owned external federation boundary. The Research system holds no
    /// canonical database and no authority lineage over this exchange.
    ExternalFederationNoCanonicalAuthority,
}

/// Cancellation state of one exchange job.
///
/// A requested-but-unconfirmed cancellation is never reported as a clean stop:
/// the research owner contract keeps a cancellation that proved nothing as
/// cancellation-unconfirmed, so the durable record distinguishes the two.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CancellationState {
    /// No cancellation was requested.
    NotRequested,
    /// A cancellation was issued and not yet confirmed by the bridge.
    Requested {
        /// Why the cancellation was issued.
        reason: String,
    },
    /// The bridge confirmed the cancellation of this job.
    Confirmed {
        /// Why the cancellation was issued.
        reason: String,
    },
}

impl CancellationState {
    /// Whether the cancellation is confirmed. A requested cancellation that was
    /// never confirmed is not a confirmed stop.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Validates the recorded reason of a cancellation.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        match self {
            Self::NotRequested => Ok(()),
            Self::Requested { reason } | Self::Confirmed { reason } => {
                text(reason, "cancellation.reason")
            }
        }
    }
}

/// Progress of one exchange job against its admitted budget.
///
/// I21.13: "budget exhausted -> checkpoint, partial coverage and next probe are
/// preserved". Exhaustion is therefore a first-class progress state rather
/// than an error, and it is the state that can never close a supported answer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeProgress {
    /// Progress units spent on this job so far.
    pub spent_units: u64,
    /// The admitted budget this job may spend.
    pub budget_units: u64,
}

impl ExchangeProgress {
    /// Whether the admitted budget is spent. A spent budget never closes a
    /// supported answer: I21.13 states that an exhausted search or an
    /// approaching budget limit never promotes itself to
    /// `ANSWERED_WITH_SUPPORTED_RESULT`.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.spent_units >= self.budget_units
    }
}

/// Declared coverage denominator and the limits measured against it.
///
/// I21.9 binds the disposition to its "coverage denominator"; I21.13 records
/// that an unavailable provider means the "declared coverage narrows". A scope
/// counts as complete only when a denominator was declared and nothing is known
/// missing from it: an unavailable source, a failed acquisition, a declared gap
/// or a retained unknown each narrow it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageLimits {
    /// Stable name of the coverage denominator this record measures.
    pub denominator_kind: String,
    /// The requested source-class portfolio that bounds the declared scope.
    pub declared_source_classes: Vec<SourceClass>,
    /// The distinct source classes delivered as evidence so far, in canonical
    /// order.
    pub examined_source_classes: Vec<SourceClass>,
    /// Typed coverage gaps: an unavailable source handle plus the distinct
    /// reason it yields no evidence.
    #[serde(default)]
    pub gaps: Vec<CoverageGap>,
    /// Sources whose acquisition failed on the Research side.
    #[serde(default)]
    pub failed_acquisition: Vec<String>,
    /// Coverage unknowns the delivered evidence still retains.
    #[serde(default)]
    pub unknowns: Vec<String>,
}

impl CoverageLimits {
    /// Declares the coverage denominator of one admitted request. The
    /// requested source-class portfolio bounds the declared scope; an empty
    /// portfolio is already refused by request validation, so the denominator is
    /// never empty here.
    #[must_use]
    pub fn declared(request: &ResearchQueryRequest) -> Self {
        let mut declared_source_classes = request.source_classes.clone();
        declared_source_classes.sort_unstable();
        declared_source_classes.dedup();
        Self {
            denominator_kind: COVERAGE_DENOMINATOR_KIND.to_owned(),
            declared_source_classes,
            examined_source_classes: Vec::new(),
            gaps: Vec::new(),
            failed_acquisition: Vec::new(),
            unknowns: Vec::new(),
        }
    }

    /// Folds the limits of one observed evidence bundle into the measured
    /// coverage.
    ///
    /// A delivered source snapshot resolves an earlier typed gap for the same
    /// handle, a repeated gap for one handle keeps the first observation, and
    /// every list ends in canonical order: the durable record digest must not
    /// depend on the order in which bundles arrived.
    #[must_use]
    pub fn observed(mut self, bundle: &ResearchEvidenceBundle) -> Self {
        let delivered = |handle: &str| {
            bundle
                .sources
                .iter()
                .any(|source| source.source_handle == handle)
        };
        self.gaps.retain(|gap| !delivered(&gap.source_handle));
        for gap in &bundle.coverage_gaps {
            if !delivered(&gap.source_handle)
                && !self
                    .gaps
                    .iter()
                    .any(|existing| existing.source_handle == gap.source_handle)
            {
                self.gaps.push(gap.clone());
            }
        }
        self.gaps
            .sort_by(|left, right| left.source_handle.cmp(&right.source_handle));
        for source in &bundle.sources {
            if let Err(position) = self.examined_source_classes.binary_search(&source.class) {
                self.examined_source_classes.insert(position, source.class);
            }
        }
        for failure in &bundle.failed_acquisition {
            if !self.failed_acquisition.contains(failure) {
                self.failed_acquisition.push(failure.clone());
            }
        }
        for unknown in &bundle.coverage_unknowns {
            if !self.unknowns.contains(unknown) {
                self.unknowns.push(unknown.clone());
            }
        }
        self.failed_acquisition.sort();
        self.unknowns.sort();
        self
    }

    /// Whether the declared scope is complete: a denominator was declared and
    /// nothing is known missing from it.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.declared_source_classes.is_empty()
            && self.gaps.is_empty()
            && self.failed_acquisition.is_empty()
            && self.unknowns.is_empty()
    }

    /// The typed gap handles in canonical sorted order: the exact sources a
    /// dependent inquiry cannot rely on.
    #[must_use]
    pub fn gap_handles(&self) -> Vec<&str> {
        let mut handles: Vec<&str> = self
            .gaps
            .iter()
            .map(|gap| gap.source_handle.as_str())
            .collect();
        handles.sort_unstable();
        handles
    }

    /// Validates the declared denominator and every measured limit.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.denominator_kind, "coverage.denominator_kind")?;
        if self.declared_source_classes.is_empty() {
            return Err(ResearchContractError::EmptyCollection {
                field: "coverage.declared_source_classes",
            });
        }
        for class in &self.declared_source_classes {
            if self
                .declared_source_classes
                .iter()
                .filter(|x| *x == class)
                .count()
                > 1
            {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "coverage.declared_source_classes",
                });
            }
        }
        for class in &self.examined_source_classes {
            if self
                .examined_source_classes
                .iter()
                .filter(|x| *x == class)
                .count()
                > 1
            {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "coverage.examined_source_classes",
                });
            }
        }
        let mut seen = BTreeSet::new();
        for gap in &self.gaps {
            gap.validate()?;
            if !seen.insert(&gap.source_handle) {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "coverage.gaps",
                });
            }
        }
        for failure in &self.failed_acquisition {
            text(failure, "coverage.failed_acquisition")?;
        }
        for unknown in &self.unknowns {
            text(unknown, "coverage.unknowns")?;
        }
        Ok(())
    }
}

/// Whether the disclosure/source generation of Research-held material can still
/// be verified under the admitted State Fence.
///
/// I21.11: "If the required bundle cannot be fetched or its
/// disclosure/source generation cannot be verified, the dependent inquiry
/// returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`." Absence of
/// an observation stays an explicit unknown here: it is never read as a
/// verified generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceGenerationState {
    /// The exact admitted generation was observed and bound to a digest.
    Verified {
        /// The admitted Research source generation.
        generation: String,
        /// Digest of the material observed under that generation.
        observed_digest: String,
    },
    /// A different generation was observed: the material is stale.
    Stale {
        /// The generation the exchange was admitted against.
        admitted: String,
        /// The generation observed at the boundary.
        observed: String,
    },
    /// The generation cannot be verified at all.
    Unverifiable {
        /// Why the generation cannot be verified.
        reason: String,
    },
}

impl SourceGenerationState {
    /// Whether the exact admitted generation was verified.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Validates the recorded generation fields.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        match self {
            Self::Verified {
                generation,
                observed_digest,
            } => {
                text(generation, "source_generation.generation")?;
                digest(observed_digest, "source_generation.observed_digest")
            }
            Self::Stale { admitted, observed } => {
                text(admitted, "source_generation.admitted")?;
                text(observed, "source_generation.observed")
            }
            Self::Unverifiable { reason } => text(reason, "source_generation.reason"),
        }
    }
}

/// Disclosure invalidation of Research-held material: the reason its
/// disclosure or source generation can no longer be verified.
///
/// I21.11: "stale or unqualified evidence blocks only the dependent exchange".
/// The invalidation is recorded against the exact admitted scope, so unrelated
/// local work and other exchanges keep running.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceInvalidation {
    /// The Research material scope whose generation cannot be verified.
    pub scope: String,
    /// The generation the exchange was admitted against.
    pub admitted_generation: String,
    /// The generation observed at the boundary, when it could be read.
    pub observed_generation: Option<String>,
    /// Why the disclosure or source generation cannot be verified.
    pub reason: String,
}

impl SourceInvalidation {
    /// The typed generation state this invalidation establishes. A generation
    /// that was read and differs from the admitted one is stale; a generation
    /// that could not be read at all is unverifiable.
    #[must_use]
    pub fn generation_state(&self) -> SourceGenerationState {
        match &self.observed_generation {
            Some(observed) if observed != &self.admitted_generation => {
                SourceGenerationState::Stale {
                    admitted: self.admitted_generation.clone(),
                    observed: observed.clone(),
                }
            }
            _ => SourceGenerationState::Unverifiable {
                reason: self.reason.clone(),
            },
        }
    }

    /// Validates the recorded invalidation.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.scope, "invalidation.scope")?;
        text(
            &self.admitted_generation,
            "invalidation.admitted_generation",
        )?;
        if let Some(observed) = &self.observed_generation {
            text(observed, "invalidation.observed_generation")?;
        }
        text(&self.reason, "invalidation.reason")
    }
}

/// How a dependent inquiry continues after an outcome that may not close it.
///
/// I21.9: "all other outcomes retain a next probe, narrower claim or explicit
/// unknown". The three are alternatives rather than a list, so a non-closing
/// outcome carries exactly one and can never stay silent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GapContinuation {
    /// The exact probe to run next.
    NextProbe {
        /// The retained next probe.
        probe: String,
    },
    /// The narrower claim the inquiry may assert instead of the blocked one.
    NarrowerClaim {
        /// The retained narrower claim.
        claim: String,
    },
    /// The unknown the inquiry keeps explicitly open.
    ExplicitUnknown {
        /// The retained explicit unknown.
        unknown: String,
    },
}

impl GapContinuation {
    /// The continuation a non-closing outcome retains when the caller named
    /// none: the first explicit unknown the delivered evidence declared, or an
    /// explicit statement that the close reported this disposition without
    /// closable evidence. A close that retained nothing still names what is
    /// unknown instead of staying silent.
    #[must_use]
    pub fn declared_by(bundle: &ResearchEvidenceBundle) -> Self {
        match bundle.coverage_unknowns.first() {
            Some(unknown) => Self::ExplicitUnknown {
                unknown: unknown.clone(),
            },
            None => Self::ExplicitUnknown {
                unknown: format!(
                    "job {} closed as {} without closable evidence",
                    bundle.job_id,
                    bundle.disposition.wire_name()
                ),
            },
        }
    }

    /// The retained text of this continuation.
    #[must_use]
    pub fn retained(&self) -> &str {
        match self {
            Self::NextProbe { probe } => probe,
            Self::NarrowerClaim { claim } => claim,
            Self::ExplicitUnknown { unknown } => unknown,
        }
    }

    /// Validates the retained text.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(self.retained(), "continuation")
    }
}

/// The typed dependent-inquiry outcome of a Research-held source failure.
///
/// The two named outcomes stay distinct, exactly as I21.11 and I21.13 name
/// them: material that cannot be fetched is `RESEARCH_SOURCE_UNAVAILABLE`,
/// while reachable material whose disclosure or source generation cannot be
/// verified is `INCOMPLETE_COVERAGE`. Neither closes the dependent inquiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchSourceGapOutcome {
    /// `RESEARCH_SOURCE_UNAVAILABLE`: the Research-held source cannot be
    /// fetched under its admitted generation.
    ResearchSourceUnavailable,
    /// `INCOMPLETE_COVERAGE`: the source is reachable, but its declared
    /// coverage could not be completed or its generation cannot be verified.
    IncompleteCoverage,
}

impl ResearchSourceGapOutcome {
    /// Stable wire spelling of this outcome.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ResearchSourceUnavailable => "RESEARCH_SOURCE_UNAVAILABLE",
            Self::IncompleteCoverage => "INCOMPLETE_COVERAGE",
        }
    }

    /// The inquiry disposition this outcome reports.
    #[must_use]
    pub const fn disposition(self) -> CompletionDisposition {
        match self {
            Self::ResearchSourceUnavailable => CompletionDisposition::SourceUnavailable,
            Self::IncompleteCoverage => CompletionDisposition::IncompleteCoverage,
        }
    }

    /// The outcome one observed generation state produces. A verified
    /// generation produces no gap at all: a gap may never be reported against
    /// material whose generation was verified.
    pub fn of(state: &SourceGenerationState) -> Result<Self, ResearchContractError> {
        match state {
            SourceGenerationState::Unverifiable { .. } => Ok(Self::ResearchSourceUnavailable),
            SourceGenerationState::Stale { .. } => Ok(Self::IncompleteCoverage),
            SourceGenerationState::Verified { .. } => {
                Err(ResearchContractError::InvalidDisposition)
            }
        }
    }

    /// Whether this outcome is the one the observed generation state produces.
    /// The pairing is what keeps `RESEARCH_SOURCE_UNAVAILABLE` and
    /// `INCOMPLETE_COVERAGE` distinct types instead of one generic code.
    #[must_use]
    pub const fn is_produced_by(&self, state: &SourceGenerationState) -> bool {
        matches!(
            (self, state),
            (
                Self::ResearchSourceUnavailable,
                SourceGenerationState::Unverifiable { .. }
            ) | (
                Self::IncompleteCoverage,
                SourceGenerationState::Stale { .. }
            )
        )
    }
}

/// Proof that one delivered bundle really supports an answer.
///
/// The witness has no public constructor and its fields are private: the only
/// way to obtain one is [`ResearchEvidenceBundle::supported_close`], which
/// refuses an empty exchange, a bundle declaring any coverage gap, failed
/// acquisition, unknown or invalidation, an incomplete declared coverage, and a
/// job whose admitted budget is already spent. A supported answer is therefore
/// unreachable from an exhausted or empty exchange (I21.13).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportedClose {
    bundle_digest: String,
    delivered_source_count: u64,
    delivered_claim_count: u64,
}

impl SupportedClose {
    /// The digest of the bundle that carries this answer.
    #[must_use]
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    /// How many source snapshots were delivered behind the answer.
    #[must_use]
    pub const fn delivered_source_count(&self) -> u64 {
        self.delivered_source_count
    }

    /// How many claims were delivered behind the answer.
    #[must_use]
    pub const fn delivered_claim_count(&self) -> u64 {
        self.delivered_claim_count
    }

    /// Re-checks the witness, including on a record that was read back from a
    /// durable store: an answer witness that carries no delivered source or no
    /// delivered claim is not a supported answer. The published accessors are
    /// the values checked, so the read surface and the invariant cannot drift.
    fn validate(&self) -> Result<(), ResearchContractError> {
        digest(self.bundle_digest(), "supported_close.bundle_digest")?;
        if self.delivered_source_count() == 0 || self.delivered_claim_count() == 0 {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

impl ResearchEvidenceBundle {
    /// The supported-close witness of this bundle for one job's progress and
    /// measured coverage.
    ///
    /// Refuses a disposition that is not `ANSWERED_WITH_SUPPORTED_RESULT`, an
    /// exchange with no delivered source or claim, a claim without a citation,
    /// any declared coverage gap / failed acquisition / unknown /
    /// invalidation, an incomplete declared coverage scope, and a job whose
    /// admitted budget is already spent. I21.13: an empty answer, an exhausted
    /// search, a stopped agent or an approaching budget limit never promotes
    /// itself to `ANSWERED_WITH_SUPPORTED_RESULT`.
    pub fn supported_close(
        &self,
        progress: &ExchangeProgress,
        coverage: &CoverageLimits,
    ) -> Result<SupportedClose, ResearchContractError> {
        if self.disposition != CompletionDisposition::AnsweredWithSupportedResult
            || self.sources.is_empty()
            || self.claims.is_empty()
            || self.claims.iter().any(|claim| claim.citations.is_empty())
            || !self.coverage_gaps.is_empty()
            || !self.failed_acquisition.is_empty()
            || !self.coverage_unknowns.is_empty()
            || self.invalidation.is_some()
            || progress.is_exhausted()
            || !coverage.is_complete()
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let delivered_source_count = u64::try_from(self.sources.len())
            .map_err(|_| ResearchContractError::InvalidDisposition)?;
        let delivered_claim_count = u64::try_from(self.claims.len())
            .map_err(|_| ResearchContractError::InvalidDisposition)?;
        Ok(SupportedClose {
            bundle_digest: self.immutable_bundle_digest.clone(),
            delivered_source_count,
            delivered_claim_count,
        })
    }
}

/// A terminal outcome that may not close its inquiry on the witness of a
/// supported answer, with the way the inquiry continues.
///
/// I21.9: only `ANSWERED_WITH_SUPPORTED_RESULT` and a properly scoped
/// `NO_MATCH_IN_COMPLETE_SCOPE` may close an inquiry; every other outcome
/// preserves a next probe, a narrower claim or an explicit unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalDeclaration {
    /// The typed disposition reported for the close.
    pub disposition: CompletionDisposition,
    /// How the inquiry continues after this outcome.
    pub continuation: GapContinuation,
    /// The measured coverage limits this outcome was declared against.
    pub coverage: CoverageLimits,
    /// Why this outcome is reported.
    pub detail: String,
}

impl TerminalDeclaration {
    /// Declares a terminal outcome that is not a supported answer.
    ///
    /// Refuses a disposition that must carry its own witness, a disposition
    /// that requires typed coverage gaps without any, and a
    /// `NO_MATCH_IN_COMPLETE_SCOPE` that is not scoped to a complete declared
    /// coverage: an unscoped absence is not a completeness claim (I21.9).
    pub fn declared(
        disposition: CompletionDisposition,
        coverage: CoverageLimits,
        continuation: GapContinuation,
        detail: String,
    ) -> Result<Self, ResearchContractError> {
        let declaration = Self {
            disposition,
            continuation,
            coverage,
            detail,
        };
        declaration.validate()?;
        Ok(declaration)
    }

    /// Validates the declared outcome against its own shape.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        if self.disposition == CompletionDisposition::AnsweredWithSupportedResult
            || (self.disposition == CompletionDisposition::NoMatchInCompleteScope
                && !self.coverage.is_complete())
            || (self.disposition.requires_typed_coverage_gaps() && self.coverage.gaps.is_empty())
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.coverage.validate()?;
        self.continuation.validate()?;
        text(&self.detail, "terminal_declaration.detail")
    }
}

/// The terminal typed outcome of one exchange job.
///
/// The shape admits exactly the two legal terminal forms: a supported close
/// carries its [`SupportedClose`] witness, every other close carries a
/// [`TerminalDeclaration`] naming the disposition and the way the inquiry
/// continues. There is no third form, so a terminal outcome always states
/// whether it closed an inquiry and, when it did not, how the inquiry goes on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTerminalOutcome {
    disposition: CompletionDisposition,
    supported: Option<SupportedClose>,
    declaration: Option<TerminalDeclaration>,
    bundle_digest: String,
}

impl ExchangeTerminalOutcome {
    /// The terminal outcome of a supported answer, bound to the delivered
    /// bundle digest.
    pub fn supported(witness: SupportedClose) -> Result<Self, ResearchContractError> {
        let outcome = Self {
            disposition: CompletionDisposition::AnsweredWithSupportedResult,
            bundle_digest: witness.bundle_digest.clone(),
            supported: Some(witness),
            declaration: None,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// The terminal outcome of a close that is not a supported answer, bound to
    /// the delivered bundle digest.
    pub fn declared(
        declaration: TerminalDeclaration,
        bundle_digest: String,
    ) -> Result<Self, ResearchContractError> {
        let outcome = Self {
            disposition: declaration.disposition,
            supported: None,
            declaration: Some(declaration),
            bundle_digest,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// The disposition this close reported.
    #[must_use]
    pub const fn disposition(&self) -> CompletionDisposition {
        self.disposition
    }

    /// Whether this close may close its inquiry. I21.9 allows only
    /// `ANSWERED_WITH_SUPPORTED_RESULT` and a properly scoped
    /// `NO_MATCH_IN_COMPLETE_SCOPE` to do so.
    #[must_use]
    pub const fn may_close_inquiry(&self) -> bool {
        self.disposition.may_close_inquiry()
    }

    /// The supported-close witness of this outcome, when it closed with a
    /// supported answer.
    #[must_use]
    pub const fn witness(&self) -> Option<&SupportedClose> {
        self.supported.as_ref()
    }

    /// The declared non-closing outcome of this close, when it did not close
    /// with a supported answer.
    #[must_use]
    pub const fn declaration(&self) -> Option<&TerminalDeclaration> {
        self.declaration.as_ref()
    }

    /// The immutable digest of the bundle this close was reported from.
    #[must_use]
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }

    /// Re-checks the terminal outcome against its own shape. A record read
    /// back from a durable store is validated, so a forged or drifted terminal
    /// outcome is refused instead of decoded as a finished exchange.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        digest(self.bundle_digest(), "terminal.bundle_digest")?;
        match (&self.supported, &self.declaration) {
            (Some(witness), None) => {
                witness.validate()?;
                if self.disposition() != CompletionDisposition::AnsweredWithSupportedResult {
                    return Err(ResearchContractError::InvalidDisposition);
                }
            }
            (None, Some(declaration)) => {
                declaration.validate()?;
                if declaration.disposition != self.disposition()
                    || declaration.disposition == CompletionDisposition::AnsweredWithSupportedResult
                {
                    return Err(ResearchContractError::InvalidDisposition);
                }
            }
            _ => return Err(ResearchContractError::InvalidDisposition),
        }
        Ok(())
    }
}

/// One partial evidence bundle already transferred under a job.
///
/// I21.11: jobs expose "partial results". A partial keeps the delivered
/// digests, the progress it stood for, the source handles it contributed and
/// its disclosure and invalidation state, so an interrupted exchange reports
/// what it already transferred instead of repeating the transfer. The bundle
/// bytes stay with the evidence owner; this record binds their digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PartialEvidenceBundle {
    /// Job identity this partial was delivered for.
    pub job_id: String,
    /// The exact Research system generation that delivered it.
    pub system_generation: String,
    /// The immutable digest of the delivered bundle.
    pub bundle_digest: String,
    /// Progress units spent when this partial was delivered.
    pub progress_units: u64,
    /// The source handles this partial delivered.
    pub delivered_source_handles: Vec<String>,
    /// The typed coverage gaps this partial already declared.
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
    /// The disclosure class of the delivered material, never widened.
    pub disclosure: DisclosureClass,
    /// The invalidation the partial declared, when it declared one.
    #[serde(default)]
    pub invalidation: Option<String>,
}

impl PartialEvidenceBundle {
    /// Records the partial evidence one delivered bundle stands for.
    #[must_use]
    pub fn of(bundle: &ResearchEvidenceBundle, progress_units: u64) -> Self {
        Self {
            job_id: bundle.job_id.clone(),
            system_generation: bundle.system_generation.clone(),
            bundle_digest: bundle.immutable_bundle_digest.clone(),
            progress_units,
            delivered_source_handles: bundle
                .sources
                .iter()
                .map(|source| source.source_handle.clone())
                .collect(),
            coverage_gaps: bundle.coverage_gaps.clone(),
            disclosure: bundle.disclosure,
            invalidation: bundle.invalidation.clone(),
        }
    }

    /// Validates one recorded partial bundle.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        text(&self.job_id, "partial_bundle.job_id")?;
        text(&self.system_generation, "partial_bundle.system_generation")?;
        digest(&self.bundle_digest, "partial_bundle.bundle_digest")?;
        for handle in &self.delivered_source_handles {
            text(handle, "partial_bundle.delivered_source_handles")?;
        }
        let mut seen = BTreeSet::new();
        for gap in &self.coverage_gaps {
            gap.validate()?;
            if !seen.insert(&gap.source_handle) {
                return Err(ResearchContractError::DuplicateIdentity {
                    field: "partial_bundle.coverage_gaps",
                });
            }
        }
        if let Some(reason) = &self.invalidation {
            text(reason, "partial_bundle.invalidation")?;
        }
        Ok(())
    }
}

/// Stable name of the coverage denominator this contract declares.
const COVERAGE_DENOMINATOR_KIND: &str = "requested-source-class-portfolio";

/// Durable lifecycle record of one research exchange job.
///
/// I21.11: "The federation is asynchronous and durable: jobs expose progress,
/// cancellation, partial results, source coverage and terminal disposition",
/// and "Pending exports/imports remain durable exchange jobs and resume by
/// idempotency identity rather than duplicate transfer". This record is the
/// store-neutral durable form of one job. It binds the exchange, request, job,
/// Research system and protocol identity, the idempotency key, progress,
/// cancellation state, the partial bundles already transferred, the declared
/// coverage and the failed acquisitions measured against it, the disclosure and
/// invalidation state, and the terminal typed outcome. The delivered evidence
/// itself stays with the evidence owner; this record binds its digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeJobLifecycleRecord {
    /// The contract version of this record shape.
    pub contract: ContractVersion,
    /// The authority binding of this exchange.
    pub authority: ResearchAuthorityBinding,
    /// The exchange identity.
    pub exchange_id: String,
    /// The admitted request identity: the canonical digest of the request.
    pub request_digest: String,
    /// The idempotency key this job is bound to. A retry of this identity
    /// resumes this job instead of duplicating the transfer.
    pub idempotency_key: String,
    /// The provider job identity bound to the admitted operation.
    pub job_id: String,
    /// The exact Research system/bridge generation this exchange is bound to.
    pub research_generation: String,
    /// The requesting principal.
    pub requester_principal: String,
    /// The admitted State Fence.
    pub state_fence: StateFence,
    /// The protocol revision the request was admitted under.
    pub protocol_revision: ContractVersion,
    /// The retention contract the request was admitted with.
    pub retention: String,
    /// Progress against the admitted budget.
    pub progress: ExchangeProgress,
    /// Cancellation state.
    pub cancellation: CancellationState,
    /// Partial bundles already transferred under this job.
    #[serde(default)]
    pub partial_bundles: Vec<PartialEvidenceBundle>,
    /// The declared coverage denominator and the limits measured against it.
    pub coverage: CoverageLimits,
    /// The admitted disclosure class, preserved without widening.
    pub disclosure: DisclosureClass,
    /// The disclosure/source generation state of the Research-held material,
    /// when one was observed.
    #[serde(default)]
    pub source_generation: Option<SourceGenerationState>,
    /// The invalidation of the Research-held material, when one applies.
    #[serde(default)]
    pub invalidation: Option<SourceInvalidation>,
    /// The terminal typed outcome, once this job reached one.
    #[serde(default)]
    pub terminal: Option<ExchangeTerminalOutcome>,
    /// The canonical digest over the whole record.
    pub record_digest: String,
}

impl ExchangeJobLifecycleRecord {
    /// Opens the durable record of one accepted job.
    ///
    /// Every field is derived from the admitted request and the bound job
    /// identity, so a record can never assert an identity the request did not
    /// carry.
    pub fn opened(
        request: &ResearchQueryRequest,
        job_id: &str,
    ) -> Result<Self, ResearchContractError> {
        let record = Self {
            contract: CONTRACT_VERSION,
            authority: ResearchAuthorityBinding::ExternalFederationNoCanonicalAuthority,
            exchange_id: request.exchange_id.clone(),
            request_digest: Self::request_digest(request)?,
            idempotency_key: request.idempotency_key.clone(),
            job_id: job_id.to_owned(),
            research_generation: request.bridge_generation.clone(),
            requester_principal: request.requester_principal.clone(),
            state_fence: request.state_fence.clone(),
            protocol_revision: request.protocol_revision,
            retention: request.retention.clone(),
            progress: ExchangeProgress {
                spent_units: 0,
                budget_units: request.budget_units,
            },
            cancellation: CancellationState::NotRequested,
            partial_bundles: Vec::new(),
            coverage: CoverageLimits::declared(request),
            disclosure: request.disclosure,
            source_generation: None,
            invalidation: None,
            terminal: None,
            record_digest: String::new(),
        };
        record.sealed()
    }

    /// The canonical digest of one admitted request: the content identity a
    /// resumed idempotency key is checked against, so the same key bound to
    /// different request content is a conflict rather than a second transfer.
    pub fn request_digest(request: &ResearchQueryRequest) -> Result<String, ResearchContractError> {
        let bytes =
            canonical_json_bytes(request).map_err(|_| ResearchContractError::Unencodable {
                field: "research_query_request",
            })?;
        Ok(sha256_hex(&bytes))
    }

    /// Whether this job already reached a terminal outcome.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.terminal.is_some()
    }

    /// Spends progress against the admitted budget. A job that already reached
    /// a terminal outcome never spends again.
    pub fn advanced(&self, units: u64) -> Result<Self, ResearchContractError> {
        if self.is_terminal() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let mut next = self.clone();
        next.progress.spent_units = self.progress.spent_units.saturating_add(units);
        next.sealed()
    }

    /// Records that a cancellation was issued for this job.
    ///
    /// The requested state is durable before the bridge is contacted, so an
    /// interrupted cancellation stays cancellation-unconfirmed instead of
    /// decoding as a clean stop. A repeated request keeps the first reason, and
    /// a confirmed cancellation is never re-requested.
    pub fn cancellation_requested(&self, reason: &str) -> Result<Self, ResearchContractError> {
        text(reason, "cancellation.reason")?;
        if self.is_terminal() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        match &self.cancellation {
            CancellationState::Confirmed { .. } => Err(ResearchContractError::InvalidDisposition),
            CancellationState::Requested { .. } => Ok(self.clone()),
            CancellationState::NotRequested => {
                let mut next = self.clone();
                next.cancellation = CancellationState::Requested {
                    reason: reason.to_owned(),
                };
                next.sealed()
            }
        }
    }

    /// Records that the bridge confirmed the cancellation of this job.
    pub fn cancellation_confirmed(&self, reason: &str) -> Result<Self, ResearchContractError> {
        text(reason, "cancellation.reason")?;
        if self.is_terminal() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let mut next = self.clone();
        next.cancellation = CancellationState::Confirmed {
            reason: reason.to_owned(),
        };
        next.sealed()
    }

    /// Records verified partial evidence delivered for this job.
    ///
    /// I21.11: jobs expose partial results, so an interrupted exchange keeps
    /// what it already transferred under the bound job identity. A job that
    /// already closed never accepts more evidence.
    pub fn with_partial(
        &self,
        bundle: &ResearchEvidenceBundle,
        units: u64,
    ) -> Result<Self, ResearchContractError> {
        if self.is_terminal() || !self.binds(bundle) {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let mut next = self.advanced(units)?.observed(bundle);
        next.partial_bundles
            .push(PartialEvidenceBundle::of(bundle, next.progress.spent_units));
        next.sealed()
    }

    /// Closes this job with the terminal typed outcome of one delivered bundle.
    ///
    /// A supported answer is reachable only through the bundle's
    /// supported-close witness, which refuses an empty or exhausted exchange;
    /// every other disposition is declared with the way the inquiry continues.
    /// A job whose admitted budget is already spent must carry its explicit
    /// `BudgetExhausted` gap or the close fails closed, so verified partial work
    /// and the coverage limit stay visible together (I21.13).
    pub fn closed(
        &self,
        bundle: &ResearchEvidenceBundle,
        continuation: GapContinuation,
    ) -> Result<Self, ResearchContractError> {
        if self.is_terminal() || !self.binds(bundle) {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let next = self.clone().observed(bundle);
        if next.progress.is_exhausted() && !bundle.has_budget_exhausted_gap() {
            return Err(ResearchContractError::InvalidDisposition);
        }
        let terminal = match bundle.disposition {
            CompletionDisposition::AnsweredWithSupportedResult => {
                ExchangeTerminalOutcome::supported(
                    bundle.supported_close(&next.progress, &next.coverage)?,
                )?
            }
            disposition => ExchangeTerminalOutcome::declared(
                TerminalDeclaration::declared(
                    disposition,
                    next.coverage.clone(),
                    continuation,
                    Self::close_detail(bundle),
                )?,
                bundle.immutable_bundle_digest.clone(),
            )?,
        };
        let mut closed = next;
        closed.terminal = Some(terminal);
        closed.sealed()
    }

    /// The typed dependent-inquiry gap this record's degradation opens for one
    /// dependent current task.
    ///
    /// Returns `None` when this job declares no dependent gap: it closed with a
    /// supported answer or a properly scoped complete-scope absence, or it
    /// never declared an unavailable dependency. Otherwise the gap names the
    /// exact Research-held dependency that cannot be relied on, the distinct
    /// outcome (`RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`), the
    /// measured coverage limits, and the next probe / narrower claim / explicit
    /// unknown the inquiry retains. The record itself is unchanged, so the
    /// degradation stays local to the dependent external-knowledge dependency
    /// and unrelated local work continues (I21.11, I21.13).
    pub fn dependent_inquiry_gap(
        &self,
        inquiry_id: &str,
    ) -> Result<Option<ResearchHeldSourceGap>, ResearchContractError> {
        let Some(terminal) = &self.terminal else {
            return Ok(None);
        };
        if terminal.may_close_inquiry() {
            return Ok(None);
        }
        let dependency = match self.coverage.gap_handles().first() {
            Some(handle) => (*handle).to_owned(),
            None => return Ok(None),
        };
        // The generation state of the failed dependency itself: an invalidated
        // scope is stale or unverifiable, while a dependency that never
        // produced a generation was never observed at all. The two map to the
        // two distinct I21.11 outcomes.
        let source_generation = match &self.invalidation {
            Some(invalidation) => invalidation.generation_state(),
            None => SourceGenerationState::Unverifiable {
                reason: format!(
                    "no admitted source generation was observed for {dependency} on job {}",
                    self.job_id
                ),
            },
        };
        let outcome = ResearchSourceGapOutcome::of(&source_generation)?;
        let gap = ResearchHeldSourceGap {
            inquiry_id: inquiry_id.to_owned(),
            exchange_id: self.exchange_id.clone(),
            dependency_handle: dependency,
            delivered_bundle_digest: terminal.bundle_digest().to_owned(),
            source_generation,
            outcome,
            coverage: self.coverage.clone(),
            continuation: match terminal.declaration() {
                Some(declaration) => declaration.continuation.clone(),
                None => return Ok(None),
            },
            state_fence: self.state_fence.clone(),
        };
        gap.validate()?;
        Ok(Some(gap))
    }

    /// Validates the durable record, including its canonical digest. A record
    /// that does not hash to its stored digest is not the record the store
    /// admitted, and a terminal outcome that contradicts the measured progress
    /// is refused instead of decoded as a finished exchange.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.exchange_id, "lifecycle.exchange_id"),
            (&self.idempotency_key, "lifecycle.idempotency_key"),
            (&self.job_id, "lifecycle.job_id"),
            (&self.research_generation, "lifecycle.research_generation"),
            (&self.requester_principal, "lifecycle.requester_principal"),
            (&self.retention, "lifecycle.retention"),
        ] {
            text(value, field)?;
        }
        digest(&self.request_digest, "lifecycle.request_digest")?;
        digest(&self.record_digest, "lifecycle.record_digest")?;
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        if self.progress.budget_units == 0 {
            return Err(ResearchContractError::InvalidDisposition);
        }
        self.cancellation.validate()?;
        self.coverage.validate()?;
        for partial in &self.partial_bundles {
            partial.validate()?;
        }
        if let Some(generation) = &self.source_generation {
            generation.validate()?;
        }
        if let Some(invalidation) = &self.invalidation {
            invalidation.validate()?;
        }
        if let Some(terminal) = &self.terminal {
            terminal.validate()?;
            if terminal.witness().is_some() && self.progress.is_exhausted() {
                return Err(ResearchContractError::InvalidDisposition);
            }
        }
        if self.canonical_digest()? != self.record_digest {
            return Err(ResearchContractError::InvalidDigest {
                field: "lifecycle.record_digest",
            });
        }
        Ok(())
    }

    /// Whether one delivered bundle binds this record's exchange and job.
    fn binds(&self, bundle: &ResearchEvidenceBundle) -> bool {
        bundle.exchange_id == self.exchange_id && bundle.job_id == self.job_id
    }

    /// Folds the observed evidence of one bundle into the record: the measured
    /// coverage, the disclosure/source generation that was observed, and the
    /// invalidation the bundle declared. A generation is verified only when the
    /// bundle invalidates nothing and delivered the exact admitted generation;
    /// material delivered under any other generation is recorded as stale
    /// rather than admitted.
    fn observed(mut self, bundle: &ResearchEvidenceBundle) -> Self {
        self.coverage = self.coverage.observed(bundle);
        let admitted = self.research_generation.clone();
        let delivered = bundle.system_generation.clone();
        self.invalidation = bundle
            .invalidation
            .as_ref()
            .map(|reason| SourceInvalidation {
                scope: bundle.exchange_id.clone(),
                admitted_generation: admitted.clone(),
                observed_generation: Some(delivered.clone()),
                reason: reason.clone(),
            });
        if self.invalidation.is_none() && delivered != admitted {
            self.invalidation = Some(SourceInvalidation {
                scope: bundle.exchange_id.clone(),
                admitted_generation: admitted,
                observed_generation: Some(delivered.clone()),
                reason: format!(
                    "job {} was answered by generation {delivered} instead of the admitted generation",
                    bundle.job_id
                ),
            });
        }
        self.source_generation = Some(match &self.invalidation {
            Some(invalidation) => invalidation.generation_state(),
            None => SourceGenerationState::Verified {
                generation: delivered,
                observed_digest: bundle.immutable_bundle_digest.clone(),
            },
        });
        self
    }

    /// The declared detail of a non-closing close: the first typed gap detail,
    /// or an explicit statement of the disposition the close reported.
    fn close_detail(bundle: &ResearchEvidenceBundle) -> String {
        bundle.coverage_gaps.first().map_or_else(
            || {
                format!(
                    "job {} closed as {} with no declared coverage gap",
                    bundle.job_id,
                    bundle.disposition.wire_name()
                )
            },
            |gap| gap.detail.clone(),
        )
    }

    /// Recomputes the canonical record digest, so every accepted transition
    /// leaves a tamper-evident durable record.
    fn sealed(mut self) -> Result<Self, ResearchContractError> {
        self.record_digest = self.canonical_digest()?;
        Ok(self)
    }

    /// The canonical digest over the whole record shape. Object keys are
    /// sorted recursively, so an irrelevant ordering difference never changes
    /// the durable identity, and the stored digest is excluded from its own
    /// preimage.
    fn canonical_digest(&self) -> Result<String, ResearchContractError> {
        let mut shape = self.clone();
        shape.record_digest = String::new();
        let bytes =
            canonical_json_bytes(&shape).map_err(|_| ResearchContractError::Unencodable {
                field: "exchange_job_lifecycle_record",
            })?;
        Ok(sha256_hex(&bytes))
    }
}

/// The typed gap a Research-held source failure opens for one dependent current
/// task.
///
/// I21.11: "If the required bundle cannot be fetched or its
/// disclosure/source generation cannot be verified, the dependent inquiry
/// returns `RESEARCH_SOURCE_UNAVAILABLE` or `INCOMPLETE_COVERAGE`, while
/// unrelated local cognitive work continues." The gap therefore names exactly
/// one dependency, one of the two distinct outcomes, the coverage limits the
/// inquiry may still rely on, and the next probe / narrower claim / explicit
/// unknown the inquiry retains. It never closes the inquiry and never widens
/// beyond the dependent external-knowledge dependency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchHeldSourceGap {
    /// The dependent inquiry this gap is reported to.
    pub inquiry_id: String,
    /// The exchange whose Research-held dependency failed.
    pub exchange_id: String,
    /// The exact Research-held source handle the inquiry depended on.
    pub dependency_handle: String,
    /// The immutable digest of the degraded bundle this exchange did deliver.
    /// I21.11 lets a dependent inquiry use "only a still-valid bounded
    /// excerpt/evidence bundle already admitted under its State Fence", so the
    /// gap names the exact handle the inquiry may still reach.
    pub delivered_bundle_digest: String,
    /// The disclosure/source generation state of that material.
    pub source_generation: SourceGenerationState,
    /// The distinct typed outcome of this gap.
    pub outcome: ResearchSourceGapOutcome,
    /// The measured coverage limits the inquiry may still rely on.
    pub coverage: CoverageLimits,
    /// How the dependent inquiry continues.
    pub continuation: GapContinuation,
    /// The admitted State Fence this gap is reported under.
    pub state_fence: StateFence,
}

impl ResearchHeldSourceGap {
    /// The inquiry disposition this gap reports.
    #[must_use]
    pub const fn disposition(&self) -> CompletionDisposition {
        self.outcome.disposition()
    }

    /// Whether this gap may close its inquiry. I21.9: it never may, so an
    /// unavailable or unverifiable Research-held source is reported as a typed
    /// gap instead of a finished answer.
    #[must_use]
    pub const fn may_close_inquiry(&self) -> bool {
        self.disposition().may_close_inquiry()
    }

    /// Validates the gap, including the distinctness of the two named outcomes:
    /// a verified generation is not a gap, each outcome belongs to exactly the
    /// generation state that produces it, the named dependency must be a
    /// declared coverage gap, and the gap may never close its inquiry.
    pub fn validate(&self) -> Result<(), ResearchContractError> {
        for (value, field) in [
            (&self.inquiry_id, "gap.inquiry_id"),
            (&self.exchange_id, "gap.exchange_id"),
            (&self.dependency_handle, "gap.dependency_handle"),
        ] {
            text(value, field)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchContractError::InvalidFence)?;
        digest(&self.delivered_bundle_digest, "gap.delivered_bundle_digest")?;
        self.source_generation.validate()?;
        self.coverage.validate()?;
        self.continuation.validate()?;
        if self.source_generation.is_verified()
            || !self.outcome.is_produced_by(&self.source_generation)
            || !self
                .coverage
                .gap_handles()
                .contains(&self.dependency_handle.as_str())
            || self.may_close_inquiry()
        {
            return Err(ResearchContractError::InvalidDisposition);
        }
        Ok(())
    }
}

/// Durable, store-neutral persistence contract for exchange-job lifecycle
/// records.
///
/// I21.11: "Pending exports/imports remain durable exchange jobs and resume by
/// idempotency identity rather than duplicate transfer", while the Research
/// federation "never shares ELIOT's canonical database". The contract is
/// therefore store-neutral on purpose: the owning ELIOT store implements it
/// against the canonical database, keyed by the record's idempotency key. This
/// crate defines no database, no remote-store fallback and no scheduler, and a
/// record that cannot be persisted is a typed failure rather than a silently
/// lost job.
pub trait ExchangeJobLedger {
    /// The owner-reported storage failure, kept typed by its owner.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Loads the durable record bound to one idempotency identity. `None` means
    /// the identity was never admitted, so a first submit must mint a new job.
    fn load(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<ExchangeJobLifecycleRecord>, Self::Error>;

    /// Stores one durable record under its own idempotency key. A record that
    /// does not validate must be refused rather than stored.
    fn store(&mut self, record: ExchangeJobLifecycleRecord) -> Result<(), Self::Error>;
}
