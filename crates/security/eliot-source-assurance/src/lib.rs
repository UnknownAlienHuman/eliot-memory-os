//! Pure, deterministic source-assurance contracts.
//!
//! This crate owns the Q-01 boundary only: source identity and provenance,
//! independent trust axes, source snapshot/frontier freshness, scope binding,
//! quarantine, and the typed admission result.  It deliberately does not
//! decide influence, disclosure, erasure, or persistence.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The wire/schema revision for the Q-01 source-assurance cell.
pub const SOURCE_ASSURANCE_SCHEMA_VERSION: &str = "eliot-source-assurance-v1";

/// A stable, non-authoritative digest algorithm used by this cell.
pub const SOURCE_ASSURANCE_DIGEST_ALGORITHM: &str = "blake3";

/// A governing source identity authenticated by its exact bytes and origin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GoverningSourceIdentity {
    /// Opaque stable identity for the source member.
    pub source_id: String,
    /// Policy-sized source kind (for example `architecture` or `implementation`).
    pub kind: String,
    /// Canonical reference, never a display-name match.
    pub canonical_ref: String,
    /// Digest of the exact source bytes.
    pub content_digest: String,
    /// Digest or receipt reference authenticating the source origin.
    pub origin_ref: String,
    /// Source revision at which the identity was observed.
    pub revision: String,
}

impl GoverningSourceIdentity {
    fn validate(&self) -> Result<(), SourceAssuranceError> {
        require_field("source_id", &self.source_id)?;
        require_field("kind", &self.kind)?;
        require_field("canonical_ref", &self.canonical_ref)?;
        require_digest("content_digest", &self.content_digest)?;
        require_field("origin_ref", &self.origin_ref)?;
        require_field("revision", &self.revision)
    }
}

/// The complete, ordered-by-identity set of governing sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GoverningSourceSet {
    /// Stable set identity.
    pub set_id: String,
    /// Revision of the set projection.
    pub revision: String,
    /// Exact governing members. Canonicalization sorts by `source_id`.
    pub members: Vec<GoverningSourceIdentity>,
    /// Digest over the canonical member set.
    pub set_digest: String,
}

impl GoverningSourceSet {
    /// Construct and digest a governing source set deterministically.
    pub fn new(
        set_id: impl Into<String>,
        revision: impl Into<String>,
        mut members: Vec<GoverningSourceIdentity>,
    ) -> Result<Self, SourceAssuranceError> {
        let set_id = set_id.into();
        let revision = revision.into();
        require_field("set_id", &set_id)?;
        require_field("revision", &revision)?;
        if members.is_empty() {
            return Err(SourceAssuranceError::MissingField("members"));
        }
        for member in &members {
            member.validate()?;
        }
        members.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let mut ids = BTreeSet::new();
        for member in &members {
            if !ids.insert(member.source_id.as_str()) {
                return Err(SourceAssuranceError::DuplicateSourceId(
                    member.source_id.clone(),
                ));
            }
        }
        let set_digest = digest_json(&SourceSetDigestMaterial {
            set_id: &set_id,
            revision: &revision,
            members: &members,
        })?;
        Ok(Self {
            set_id,
            revision,
            members,
            set_digest,
        })
    }

    fn validate(&self) -> Result<(), SourceAssuranceError> {
        let expected = Self::new(
            self.set_id.clone(),
            self.revision.clone(),
            self.members.clone(),
        )?;
        if expected.set_digest != self.set_digest || expected.members != self.members {
            return Err(SourceAssuranceError::NonCanonicalSourceSet);
        }
        Ok(())
    }
}

/// Independent source-assurance axes. No scalar trust score is permitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceTrustProfile {
    /// Exact integrity verification result.
    pub integrity: AxisStatus,
    /// Whether the observed source is current for the requested frontier.
    pub freshness: AxisStatus,
    /// Domain competence assessment.
    pub competence: AxisStatus,
    /// Incentive/track-record assessment.
    pub incentives: AxisStatus,
    /// Independence/common-lineage assessment.
    pub independence: AxisStatus,
    /// Privacy/sensitivity classification.
    pub privacy: PrivacyClass,
    /// Instruction-taint assessment attached at ingress.
    pub instruction_taint: InstructionTaint,
    /// Deception/exfiltration/persistence risk assessment.
    pub threat: ThreatStatus,
}

/// A status on one independent trust axis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AxisStatus {
    /// The axis has verified supporting evidence.
    Verified,
    /// The axis has a verified negative finding.
    Failed,
    /// The axis cannot be established from current evidence.
    Unknown,
}

/// Privacy boundary attached to source material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClass {
    Public,
    Internal,
    UserPrivate,
    Secret,
    Licensed,
}

/// Ingress instruction-taint state. Taint is never cleared by transformation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstructionTaint {
    /// Authenticated instruction-channel material.
    InstructionChannel,
    /// Untrusted embedded/document/tool data.
    Data,
    /// The ingress channel cannot be established.
    Unknown,
}

/// Deception, exfiltration, or persistence threat state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatStatus {
    NoneObserved,
    Suspected,
    Confirmed,
    Unknown,
}

/// Quarantine is an explicit status, not a hidden boolean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineStatus {
    /// Source can be considered for the requested Q-01 use.
    Clear,
    /// Source remains evidence but is excluded from admission.
    Quarantined { reason: String },
    /// Source lineage or state is incomplete.
    Unknown { reason: String },
}

/// A source snapshot bound to an exact source set and state fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceSnapshotBinding {
    pub snapshot_id: String,
    pub source_set_id: String,
    pub source_set_revision: String,
    pub content_digest: String,
    pub frontier_digest: String,
    pub state_fence: String,
}

/// The current source frontier against which a snapshot is checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceFrontierBinding {
    pub frontier_id: String,
    pub workspace_identity: String,
    pub repository_revision: String,
    pub dirty_state_digest: String,
    pub generation: u64,
}

/// Exact expected/observed scope identity proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ScopeBindingProof {
    pub expected_scope: String,
    pub observed_scope: String,
    pub expected_generation: u64,
    pub observed_generation: u64,
    pub evidence_digest: String,
}

/// Scope disposition used by the typed admission result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeDisposition {
    Matched,
    Stale,
    DifferentInstance,
    Ambiguous,
    Missing,
}

/// The bounded epistemic use requested from Q-01.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissibleUse {
    Evidence,
    Hypothesis,
    ProcedureCandidate,
}

/// Maximum effect a Q-01-admitted source may have. Q-02 is responsible for
/// applying influence/disclosure decisions downstream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectCeiling {
    NoEffect,
    ReadOnlyCandidate,
}

/// Complete Q-01 assurance record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceAssurance {
    pub schema_version: String,
    pub governing_sources: GoverningSourceSet,
    pub provenance: SourceProvenance,
    pub trust: SourceTrustProfile,
    pub quarantine: QuarantineStatus,
    pub snapshot: SourceSnapshotBinding,
    pub frontier: SourceFrontierBinding,
    pub scope: ScopeBindingProof,
    pub requested_use: AdmissibleUse,
    pub effect_ceiling: EffectCeiling,
}

/// Origin and lineage fields for source material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourceProvenance {
    pub producer: String,
    pub acquisition_ref: String,
    pub lineage_digest: String,
    pub authentication_ref: String,
}

/// Expected state used for deterministic admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AdmissionExpectation {
    pub source_set_id: String,
    pub source_set_revision: String,
    pub frontier: SourceFrontierBinding,
    pub scope: ScopeBindingProof,
}

/// Typed source-assurance findings; no generic string authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssuranceFinding {
    MissingSource,
    StaleSnapshot,
    ConflictingSources,
    MissingFrontier,
    StaleFrontier,
    WrongScope,
    AmbiguousScope,
    Quarantined,
    UnknownTrust,
    InstructionTainted,
    InvalidIntegrity,
}

/// Typed admission outcome. Every non-admitted state preserves the reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionOutcome {
    Admitted { assurance_digest: String },
    NeedsRevalidation { findings: Vec<AssuranceFinding> },
    Missing { findings: Vec<AssuranceFinding> },
    Conflicted { findings: Vec<AssuranceFinding> },
    WrongScope { findings: Vec<AssuranceFinding> },
    Quarantined { findings: Vec<AssuranceFinding> },
}

/// Validation or canonicalization failure in the Q-01 contract.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SourceAssuranceError {
    #[error("required field is missing or blank: {0}")]
    MissingField(&'static str),
    #[error("field is not a valid lowercase hexadecimal digest: {0}")]
    InvalidDigest(&'static str),
    #[error("duplicate governing source id: {0}")]
    DuplicateSourceId(String),
    #[error("governing source set is not in canonical order or has a wrong digest")]
    NonCanonicalSourceSet,
    #[error("source assurance schema version is unsupported: {0}")]
    UnsupportedSchema(String),
    #[error("source assurance JSON encoding failed: {0}")]
    Json(String),
}

impl From<serde_json::Error> for SourceAssuranceError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl SourceAssurance {
    /// Validate all immutable identities and return the deterministic digest.
    pub fn validate(&self) -> Result<String, SourceAssuranceError> {
        if self.schema_version != SOURCE_ASSURANCE_SCHEMA_VERSION {
            return Err(SourceAssuranceError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        self.governing_sources.validate()?;
        validate_provenance(&self.provenance)?;
        validate_snapshot(&self.snapshot)?;
        validate_frontier(&self.frontier)?;
        validate_scope(&self.scope)?;
        if matches!(self.quarantine, QuarantineStatus::Quarantined { ref reason } | QuarantineStatus::Unknown { ref reason } if reason.trim().is_empty())
        {
            return Err(SourceAssuranceError::MissingField("quarantine.reason"));
        }
        digest_json(self)
    }

    /// Evaluate the source against a caller-owned current frontier and scope.
    pub fn admit(
        &self,
        expected: &AdmissionExpectation,
    ) -> Result<AdmissionOutcome, SourceAssuranceError> {
        expected.validate()?;
        let digest = self.validate()?;
        let mut findings = Vec::new();
        if self.governing_sources.set_id != expected.source_set_id
            || self.governing_sources.revision != expected.source_set_revision
            || self.snapshot.source_set_id != self.governing_sources.set_id
            || self.snapshot.source_set_revision != self.governing_sources.revision
        {
            findings.push(AssuranceFinding::ConflictingSources);
        }
        if self.snapshot.frontier_digest != digest_frontier(&expected.frontier)? {
            findings.push(AssuranceFinding::StaleSnapshot);
        }
        if self.frontier != expected.frontier {
            findings.push(AssuranceFinding::StaleFrontier);
        }
        let scope_disposition = scope_disposition(&self.scope, &expected.scope);
        match scope_disposition {
            ScopeDisposition::DifferentInstance | ScopeDisposition::Missing => {
                findings.push(AssuranceFinding::WrongScope);
            }
            ScopeDisposition::Ambiguous => findings.push(AssuranceFinding::AmbiguousScope),
            ScopeDisposition::Stale => findings.push(AssuranceFinding::StaleFrontier),
            ScopeDisposition::Matched => {}
        }
        if self.governing_sources.members.is_empty() {
            findings.push(AssuranceFinding::MissingSource);
        }
        if self.trust.integrity != AxisStatus::Verified {
            findings.push(AssuranceFinding::InvalidIntegrity);
        }
        if self.trust.freshness != AxisStatus::Verified {
            findings.push(AssuranceFinding::StaleSnapshot);
        }
        if self.trust.competence == AxisStatus::Unknown
            || self.trust.independence == AxisStatus::Unknown
        {
            findings.push(AssuranceFinding::UnknownTrust);
        }
        if !matches!(
            self.trust.instruction_taint,
            InstructionTaint::InstructionChannel
        ) {
            findings.push(AssuranceFinding::InstructionTainted);
        }
        if matches!(
            self.trust.threat,
            ThreatStatus::Suspected | ThreatStatus::Confirmed
        ) {
            findings.push(AssuranceFinding::Quarantined);
        }
        match &self.quarantine {
            QuarantineStatus::Clear => {}
            QuarantineStatus::Quarantined { .. } | QuarantineStatus::Unknown { .. } => {
                findings.push(AssuranceFinding::Quarantined);
            }
        }
        findings.sort_by_key(finding_key);
        findings.dedup();
        if findings.is_empty() {
            Ok(AdmissionOutcome::Admitted {
                assurance_digest: digest,
            })
        } else if findings
            .iter()
            .any(|finding| matches!(finding, AssuranceFinding::WrongScope))
        {
            Ok(AdmissionOutcome::WrongScope { findings })
        } else if findings
            .iter()
            .any(|finding| matches!(finding, AssuranceFinding::ConflictingSources))
        {
            Ok(AdmissionOutcome::Conflicted { findings })
        } else if findings.iter().any(|finding| {
            matches!(
                finding,
                AssuranceFinding::MissingSource | AssuranceFinding::MissingFrontier
            )
        }) {
            Ok(AdmissionOutcome::Missing { findings })
        } else if findings.iter().any(|finding| {
            matches!(
                finding,
                AssuranceFinding::Quarantined | AssuranceFinding::InvalidIntegrity
            )
        }) {
            Ok(AdmissionOutcome::Quarantined { findings })
        } else {
            Ok(AdmissionOutcome::NeedsRevalidation { findings })
        }
    }

    /// Admit an optional source observation, preserving a typed missing-source
    /// outcome instead of converting absence into an authority-bearing error.
    pub fn admit_optional(
        assurance: Option<&Self>,
        expected: &AdmissionExpectation,
    ) -> Result<AdmissionOutcome, SourceAssuranceError> {
        expected.validate()?;
        match assurance {
            Some(assurance) => assurance.admit(expected),
            None => Ok(AdmissionOutcome::Missing {
                findings: vec![AssuranceFinding::MissingSource],
            }),
        }
    }

    /// Encode using the stable JSON representation used for receipts.
    pub fn to_canonical_json(&self) -> Result<String, SourceAssuranceError> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }
}

/// Return the JSON schema for generated contract publication.
pub fn source_assurance_schema() -> schemars::Schema {
    schemars::schema_for!(SourceAssurance)
}

#[derive(Serialize)]
struct SourceSetDigestMaterial<'a> {
    set_id: &'a str,
    revision: &'a str,
    members: &'a [GoverningSourceIdentity],
}

impl AdmissionExpectation {
    fn validate(&self) -> Result<(), SourceAssuranceError> {
        require_field("expectation.source_set_id", &self.source_set_id)?;
        require_field("expectation.source_set_revision", &self.source_set_revision)?;
        validate_frontier(&self.frontier)?;
        validate_scope(&self.scope)
    }
}

fn validate_provenance(provenance: &SourceProvenance) -> Result<(), SourceAssuranceError> {
    require_field("provenance.producer", &provenance.producer)?;
    require_field("provenance.acquisition_ref", &provenance.acquisition_ref)?;
    require_digest("provenance.lineage_digest", &provenance.lineage_digest)?;
    require_field(
        "provenance.authentication_ref",
        &provenance.authentication_ref,
    )
}

fn validate_snapshot(snapshot: &SourceSnapshotBinding) -> Result<(), SourceAssuranceError> {
    require_field("snapshot.snapshot_id", &snapshot.snapshot_id)?;
    require_field("snapshot.source_set_id", &snapshot.source_set_id)?;
    require_field(
        "snapshot.source_set_revision",
        &snapshot.source_set_revision,
    )?;
    require_digest("snapshot.content_digest", &snapshot.content_digest)?;
    require_digest("snapshot.frontier_digest", &snapshot.frontier_digest)?;
    require_field("snapshot.state_fence", &snapshot.state_fence)
}

fn validate_frontier(frontier: &SourceFrontierBinding) -> Result<(), SourceAssuranceError> {
    require_field("frontier.frontier_id", &frontier.frontier_id)?;
    require_field("frontier.workspace_identity", &frontier.workspace_identity)?;
    require_field(
        "frontier.repository_revision",
        &frontier.repository_revision,
    )?;
    require_digest("frontier.dirty_state_digest", &frontier.dirty_state_digest)
}

fn validate_scope(scope: &ScopeBindingProof) -> Result<(), SourceAssuranceError> {
    require_field("scope.expected_scope", &scope.expected_scope)?;
    require_field("scope.observed_scope", &scope.observed_scope)?;
    require_digest("scope.evidence_digest", &scope.evidence_digest)
}

fn scope_disposition(actual: &ScopeBindingProof, expected: &ScopeBindingProof) -> ScopeDisposition {
    if expected.expected_scope.trim().is_empty() || expected.observed_scope.trim().is_empty() {
        return ScopeDisposition::Missing;
    }
    if actual.expected_scope != expected.expected_scope {
        return ScopeDisposition::DifferentInstance;
    }
    if actual.observed_scope != expected.observed_scope {
        return ScopeDisposition::Ambiguous;
    }
    if actual.expected_generation != expected.expected_generation
        || actual.observed_generation != expected.observed_generation
        || actual.evidence_digest != expected.evidence_digest
    {
        return ScopeDisposition::Stale;
    }
    ScopeDisposition::Matched
}

fn digest_frontier(frontier: &SourceFrontierBinding) -> Result<String, SourceAssuranceError> {
    digest_json(frontier)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, SourceAssuranceError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn require_field(field: &'static str, value: &str) -> Result<(), SourceAssuranceError> {
    if value.trim().is_empty() {
        Err(SourceAssuranceError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_digest(field: &'static str, value: &str) -> Result<(), SourceAssuranceError> {
    require_field(field, value)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SourceAssuranceError::InvalidDigest(field));
    }
    Ok(())
}

fn finding_key(finding: &AssuranceFinding) -> &'static str {
    match finding {
        AssuranceFinding::MissingSource => "missing_source",
        AssuranceFinding::StaleSnapshot => "stale_snapshot",
        AssuranceFinding::ConflictingSources => "conflicting_sources",
        AssuranceFinding::MissingFrontier => "missing_frontier",
        AssuranceFinding::StaleFrontier => "stale_frontier",
        AssuranceFinding::WrongScope => "wrong_scope",
        AssuranceFinding::AmbiguousScope => "ambiguous_scope",
        AssuranceFinding::Quarantined => "quarantined",
        AssuranceFinding::UnknownTrust => "unknown_trust",
        AssuranceFinding::InstructionTainted => "instruction_tainted",
        AssuranceFinding::InvalidIntegrity => "invalid_integrity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> String {
        blake3::hash(seed.as_bytes()).to_hex().to_string()
    }

    fn fixture() -> Result<SourceAssurance, SourceAssuranceError> {
        let member = GoverningSourceIdentity {
            source_id: "architecture".into(),
            kind: "governing".into(),
            canonical_ref: "docs/ELIOT_ARCHITECTURE.md".into(),
            content_digest: digest("architecture"),
            origin_ref: "origin:architecture".into(),
            revision: "rev-1".into(),
        };
        let sources = GoverningSourceSet::new("governing-set", "rev-1", vec![member])?;
        let frontier = SourceFrontierBinding {
            frontier_id: "frontier-1".into(),
            workspace_identity: "workspace-1".into(),
            repository_revision: "commit-1".into(),
            dirty_state_digest: digest("dirty"),
            generation: 1,
        };
        let scope = ScopeBindingProof {
            expected_scope: "scope-1".into(),
            observed_scope: "scope-1".into(),
            expected_generation: 1,
            observed_generation: 1,
            evidence_digest: digest("scope"),
        };
        let snapshot = SourceSnapshotBinding {
            snapshot_id: "snapshot-1".into(),
            source_set_id: "governing-set".into(),
            source_set_revision: "rev-1".into(),
            content_digest: digest("snapshot"),
            frontier_digest: digest_json(&frontier)?,
            state_fence: "fence-1".into(),
        };
        Ok(SourceAssurance {
            schema_version: SOURCE_ASSURANCE_SCHEMA_VERSION.into(),
            governing_sources: sources,
            provenance: SourceProvenance {
                producer: "human".into(),
                acquisition_ref: "capture-1".into(),
                lineage_digest: digest("lineage"),
                authentication_ref: "auth-1".into(),
            },
            trust: SourceTrustProfile {
                integrity: AxisStatus::Verified,
                freshness: AxisStatus::Verified,
                competence: AxisStatus::Verified,
                incentives: AxisStatus::Unknown,
                independence: AxisStatus::Verified,
                privacy: PrivacyClass::Internal,
                instruction_taint: InstructionTaint::Data,
                threat: ThreatStatus::NoneObserved,
            },
            quarantine: QuarantineStatus::Clear,
            snapshot,
            frontier,
            scope,
            requested_use: AdmissibleUse::Evidence,
            effect_ceiling: EffectCeiling::ReadOnlyCandidate,
        })
    }

    #[test]
    fn canonical_roundtrip_is_stable() -> Result<(), SourceAssuranceError> {
        let assurance = fixture()?;
        let json = assurance.to_canonical_json()?;
        let decoded: SourceAssurance = serde_json::from_str(&json)?;
        assert_eq!(decoded, assurance);
        assert_eq!(decoded.to_canonical_json()?, json);
        Ok(())
    }

    #[test]
    fn source_set_rejects_duplicate_and_noncanonical_members() -> Result<(), SourceAssuranceError> {
        let mut member = GoverningSourceIdentity {
            source_id: "same".into(),
            kind: "governing".into(),
            canonical_ref: "a".into(),
            content_digest: digest("a"),
            origin_ref: "origin:a".into(),
            revision: "r".into(),
        };
        let duplicate = member.clone();
        assert!(matches!(
            GoverningSourceSet::new("set", "r", vec![member.clone(), duplicate]),
            Err(SourceAssuranceError::DuplicateSourceId(_))
        ));
        member.source_id = "b".into();
        let set = GoverningSourceSet::new("set", "r", vec![member.clone()])?;
        let mut tampered = set.clone();
        tampered.set_digest = digest("wrong");
        assert!(matches!(
            tampered.validate(),
            Err(SourceAssuranceError::NonCanonicalSourceSet)
        ));
        Ok(())
    }

    #[test]
    fn typed_outcomes_cover_taint_and_wrong_scope() -> Result<(), SourceAssuranceError> {
        let assurance = fixture()?;
        let expected = AdmissionExpectation {
            source_set_id: "governing-set".into(),
            source_set_revision: "rev-1".into(),
            frontier: assurance.frontier.clone(),
            scope: assurance.scope.clone(),
        };
        assert!(matches!(
            assurance.admit(&expected)?,
            AdmissionOutcome::NeedsRevalidation { .. }
        ));
        let mut wrong = expected;
        wrong.scope.expected_scope = "other-scope".into();
        assert!(matches!(
            assurance.admit(&wrong)?,
            AdmissionOutcome::WrongScope { .. }
        ));
        Ok(())
    }

    #[test]
    fn missing_source_is_a_typed_outcome() -> Result<(), SourceAssuranceError> {
        let assurance = fixture()?;
        let expected = AdmissionExpectation {
            source_set_id: "governing-set".into(),
            source_set_revision: "rev-1".into(),
            frontier: assurance.frontier.clone(),
            scope: assurance.scope.clone(),
        };
        assert_eq!(
            SourceAssurance::admit_optional(None, &expected)?,
            AdmissionOutcome::Missing {
                findings: vec![AssuranceFinding::MissingSource]
            }
        );
        Ok(())
    }

    #[test]
    fn stale_and_conflicting_inputs_are_typed() -> Result<(), SourceAssuranceError> {
        let assurance = fixture()?;
        let mut expected = AdmissionExpectation {
            source_set_id: "other-set".into(),
            source_set_revision: "rev-1".into(),
            frontier: assurance.frontier.clone(),
            scope: assurance.scope.clone(),
        };
        assert!(matches!(
            assurance.admit(&expected)?,
            AdmissionOutcome::Conflicted { .. }
        ));
        expected.source_set_id = "governing-set".into();
        expected.frontier.generation = 2;
        assert!(matches!(
            assurance.admit(&expected)?,
            AdmissionOutcome::NeedsRevalidation { .. }
        ));
        Ok(())
    }

    #[test]
    fn confirmed_threat_is_quarantined_and_schema_is_serializable()
    -> Result<(), SourceAssuranceError> {
        let mut assurance = fixture()?;
        assurance.trust.instruction_taint = InstructionTaint::InstructionChannel;
        assurance.trust.threat = ThreatStatus::Confirmed;
        let expected = AdmissionExpectation {
            source_set_id: "governing-set".into(),
            source_set_revision: "rev-1".into(),
            frontier: assurance.frontier.clone(),
            scope: assurance.scope.clone(),
        };
        assert!(matches!(
            assurance.admit(&expected)?,
            AdmissionOutcome::Quarantined { .. }
        ));
        let schema = serde_json::to_string(&source_assurance_schema())?;
        assert!(schema.contains("SourceAssurance"));
        Ok(())
    }
}
