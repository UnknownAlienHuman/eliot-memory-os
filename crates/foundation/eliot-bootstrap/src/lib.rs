//! Pure, deterministic D0 bootstrap compilers.
//!
//! This crate only turns already supplied, immutable source projections into
//! content-addressed bootstrap artifacts.  It never discovers files, starts a
//! process, edits a projection, grants authority, or emits a finish/release
//! verdict.  Source availability is explicit and fail-closed: a partial,
//! missing, or conflicted required source is returned as a typed error rather
//! than being treated as a successful empty result.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_rules::{RuleCatalogue, RuleClass};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable contract name for the C0-09 compiler surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.bootstrap";
/// Wire revision of the C0-09 compiler surface.
pub const CONTRACT_VERSION: u16 = 1;
/// Frozen cell plan identity supplied by the Runtime bundle.
pub const PLAN_ID: &str = "C0-09:plan-v2";

/// Availability of one source projection supplied to a pure compiler.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceStatus {
    /// The source is present, complete, and internally validated by its owner.
    Complete,
    /// The source is present but does not cover the required projection.
    Partial,
    /// No source bytes were supplied.
    Missing,
    /// Independent source projections disagree.
    Conflicted,
    /// The source exists but is not usable in this profile.
    Unsupported,
}

impl SourceStatus {
    fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A source projection with explicit provenance and availability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProjection<T> {
    /// Stable source name or owner handle.
    pub source_id: String,
    /// Immutable source revision supplied by the owner.
    pub revision: String,
    /// Availability of the supplied source.
    pub status: SourceStatus,
    /// Source value, absent when the source is unavailable.
    pub value: Option<T>,
}

impl<T> SourceProjection<T> {
    /// Creates a complete source projection.
    pub fn complete(source_id: impl Into<String>, revision: impl Into<String>, value: T) -> Self {
        Self {
            source_id: source_id.into(),
            revision: revision.into(),
            status: SourceStatus::Complete,
            value: Some(value),
        }
    }

    /// Creates an unavailable source projection without inventing a value.
    pub fn unavailable(
        source_id: impl Into<String>,
        revision: impl Into<String>,
        status: SourceStatus,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            revision: revision.into(),
            status,
            value: None,
        }
    }
}

/// A failure caused by an unavailable or malformed source projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BootstrapCompileError {
    /// A source identity or required text field is invalid.
    #[error("invalid {field} in {source_id}: {reason}")]
    InvalidText {
        /// Source that contains the invalid field.
        source_id: String,
        /// Invalid field name.
        field: &'static str,
        /// Short public reason.
        reason: &'static str,
    },
    /// A required source is not complete.
    #[error("required source {source_id} is {status:?}; {detail}")]
    SourceUnavailable {
        /// Source owner/identity.
        source_id: String,
        /// Observed availability.
        status: SourceStatus,
        /// Public reason for the rejection.
        detail: &'static str,
    },
    /// An exact-array field has duplicate or empty identities.
    #[error("invalid exact array {field} in {source_id}: {detail}")]
    InvalidExactArray {
        /// Source owner/identity.
        source_id: String,
        /// Array field name.
        field: &'static str,
        /// Public reason for the rejection.
        detail: &'static str,
    },
    /// A digest is not a lowercase SHA-256 digest.
    #[error("invalid digest field {field} in {source_id}")]
    InvalidDigest {
        /// Source owner/identity.
        source_id: String,
        /// Digest field name.
        field: &'static str,
    },
    /// Two source records claim one exact identity with different values.
    #[error("conflicting exact identity {identity} in {source_id}")]
    ConflictingIdentity {
        /// Source owner/identity.
        source_id: String,
        /// Conflicting identity.
        identity: String,
    },
    /// Canonical serialization failed for an output artifact.
    #[error("cannot canonicalize {artifact}: {reason}")]
    Canonicalization {
        /// Artifact name.
        artifact: &'static str,
        /// Serialization error text.
        reason: String,
    },
    /// A brief references a source or rule not present in its inputs.
    #[error("brief reference {reference} is not present in {field}")]
    MissingReference {
        /// Missing reference.
        reference: String,
        /// Referencing field.
        field: &'static str,
    },
    /// A provider-owned contract rejected an input projection.
    #[error("provider validation failed for {provider}: {detail}")]
    ProviderValidation {
        /// Provider/source identity.
        provider: &'static str,
        /// Provider error detail.
        detail: String,
    },
    /// An artifact's supplied digest does not match its canonical content.
    #[error("content digest mismatch for {artifact}")]
    DigestMismatch {
        /// Artifact whose digest was invalidated.
        artifact: &'static str,
    },
}

fn text(value: &str, source: String, field: &'static str) -> Result<(), BootstrapCompileError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BootstrapCompileError::InvalidText {
            source_id: source,
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, source: String, field: &'static str) -> Result<(), BootstrapCompileError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BootstrapCompileError::InvalidDigest {
            source_id: source,
            field,
        });
    }
    Ok(())
}

fn exact_strings(
    values: &[String],
    source: &str,
    field: &'static str,
) -> Result<(), BootstrapCompileError> {
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, source.to_owned(), field)?;
        if !seen.insert(value) {
            return Err(BootstrapCompileError::InvalidExactArray {
                source_id: source.to_owned(),
                field,
                detail: "duplicate exact value",
            });
        }
    }
    Ok(())
}

fn require<T>(
    projection: SourceProjection<T>,
) -> Result<(String, String, T), BootstrapCompileError> {
    text(
        &projection.source_id,
        "source-projection".to_owned(),
        "source_id",
    )?;
    text(
        &projection.revision,
        projection.source_id.clone(),
        "revision",
    )?;
    if !projection.status.is_complete() {
        return Err(BootstrapCompileError::SourceUnavailable {
            source_id: projection.source_id,
            status: projection.status,
            detail: "required source must be COMPLETE",
        });
    }
    let Some(value) = projection.value else {
        return Err(BootstrapCompileError::SourceUnavailable {
            source_id: projection.source_id,
            status: SourceStatus::Missing,
            detail: "COMPLETE source supplied no value",
        });
    };
    Ok((projection.source_id, projection.revision, value))
}

/// The frozen normative document identity used by all bootstrap artifacts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativePair {
    /// Architecture document digest.
    pub architecture_sha256: String,
    /// Implementation document digest.
    pub implementation_sha256: String,
    /// Runtime document digest.
    pub runtime_sha256: String,
}

impl NormativePair {
    fn validate(&self, source: &str) -> Result<(), BootstrapCompileError> {
        digest(
            &self.architecture_sha256,
            source.to_owned(),
            "architecture_sha256",
        )?;
        digest(
            &self.implementation_sha256,
            source.to_owned(),
            "implementation_sha256",
        )?;
        digest(&self.runtime_sha256, source.to_owned(), "runtime_sha256")
    }
}

/// One observed current-system fact with an explicit coverage state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    /// Stable domain/field identity.
    pub key: String,
    /// Public observed value; secrets are out of scope for this surface.
    pub value: String,
    /// Evidence owner or capture route.
    pub evidence_ref: String,
    /// Evaluation status of the observation.
    pub evaluation: EvidenceEvaluation,
}

/// Evaluation state of one current-system observation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceEvaluation {
    Raw,
    Screened,
    VerifierBacked,
    Contested,
    Stale,
    Unknown,
    Unavailable,
}

/// Input to the current-system evidence compiler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSystemEvidenceSource {
    /// Normative pair bound to this observation.
    pub normative_pair: NormativePair,
    /// Selected repository root identity, never discovered by this crate.
    pub selected_repository_root: String,
    /// Selected source head identity.
    pub selected_source_head: String,
    /// Dirty-tree evidence artifact, if the source owner captured one.
    pub dirty_delta_artifact_ref: Option<String>,
    /// External state root evidence.
    pub external_state_root: String,
    /// Exact source/runtime/data/integration observation records.
    pub records: Vec<EvidenceRecord>,
    /// Explicitly uncovered domains.
    pub unavailable_domains: Vec<String>,
}

/// Immutable deterministic `CurrentSystemEvidenceSnapshot`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSystemEvidenceSnapshot {
    /// Artifact schema identity.
    pub schema_version: String,
    /// Normative pair used for compilation.
    pub normative_pair: NormativePair,
    /// Source projection identity.
    pub source_projection_ref: String,
    /// Selected repository root.
    pub selected_repository_root: String,
    /// Selected source head.
    pub selected_source_head: String,
    /// Dirty-tree evidence artifact, if captured.
    pub dirty_delta_artifact_ref: Option<String>,
    /// External state root evidence.
    pub external_state_root: String,
    /// Canonically ordered evidence records.
    pub records: Vec<EvidenceRecord>,
    /// Explicitly unavailable domains.
    pub unavailable_domains: Vec<String>,
    /// Content address of all preceding fields.
    pub snapshot_sha256: String,
}

impl CurrentSystemEvidenceSnapshot {
    /// Validates the snapshot without discovering or rereading any source.
    pub fn validate(&self) -> Result<(), BootstrapCompileError> {
        self.normative_pair.validate("snapshot")?;
        text(
            &self.schema_version,
            "snapshot".to_owned(),
            "schema_version",
        )?;
        text(
            &self.source_projection_ref,
            "snapshot".to_owned(),
            "source_projection_ref",
        )?;
        text(
            &self.selected_repository_root,
            "snapshot".to_owned(),
            "selected_repository_root",
        )?;
        text(
            &self.selected_source_head,
            "snapshot".to_owned(),
            "selected_source_head",
        )?;
        text(
            &self.external_state_root,
            "snapshot".to_owned(),
            "external_state_root",
        )?;
        validate_records(&self.records, "snapshot")?;
        exact_strings(&self.unavailable_domains, "snapshot", "unavailable_domains")?;
        digest(
            &self.snapshot_sha256,
            "snapshot".to_owned(),
            "snapshot_sha256",
        )?;
        validate_content_digest(self, "snapshot", &self.snapshot_sha256, |value| {
            value.snapshot_sha256.clear();
        })
    }
}

fn validate_records(records: &[EvidenceRecord], source: &str) -> Result<(), BootstrapCompileError> {
    let mut seen = BTreeSet::new();
    for record in records {
        text(&record.key, source.to_owned(), "record.key")?;
        text(&record.value, source.to_owned(), "record.value")?;
        text(
            &record.evidence_ref,
            source.to_owned(),
            "record.evidence_ref",
        )?;
        if !seen.insert(&record.key) {
            return Err(BootstrapCompileError::ConflictingIdentity {
                source_id: source.to_owned(),
                identity: record.key.clone(),
            });
        }
    }
    Ok(())
}

/// Compiles a deterministic current-system evidence snapshot.
pub fn compile_current_system_evidence_snapshot(
    source: SourceProjection<CurrentSystemEvidenceSource>,
) -> Result<CurrentSystemEvidenceSnapshot, BootstrapCompileError> {
    let (source_id, revision, input) = require(source)?;
    input.normative_pair.validate(&source_id)?;
    text(
        &input.selected_repository_root,
        source_id.clone(),
        "selected_repository_root",
    )?;
    text(
        &input.selected_source_head,
        source_id.clone(),
        "selected_source_head",
    )?;
    text(
        &input.external_state_root,
        source_id.clone(),
        "external_state_root",
    )?;
    if let Some(reference) = &input.dirty_delta_artifact_ref {
        text(reference, source_id.clone(), "dirty_delta_artifact_ref")?;
    }
    exact_strings(
        &input.unavailable_domains,
        &source_id,
        "unavailable_domains",
    )?;
    validate_records(&input.records, &source_id)?;

    let mut records = input.records;
    records.sort_by(|left, right| left.key.cmp(&right.key));
    let mut unavailable_domains = input.unavailable_domains;
    unavailable_domains.sort();
    let mut snapshot = CurrentSystemEvidenceSnapshot {
        schema_version: "eliot-current-system-evidence-snapshot-v1".to_owned(),
        normative_pair: input.normative_pair,
        source_projection_ref: format!("{source_id}@{revision}"),
        selected_repository_root: input.selected_repository_root,
        selected_source_head: input.selected_source_head,
        dirty_delta_artifact_ref: input.dirty_delta_artifact_ref,
        external_state_root: input.external_state_root,
        records,
        unavailable_domains,
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = content_digest(&snapshot, "snapshot", |value| {
        value.snapshot_sha256.clear();
    })?;
    snapshot.validate()?;
    Ok(snapshot)
}

/// Input to the bootstrap rule catalogue compiler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRuleSource {
    /// Normative identity bound to the catalogue.
    pub normative_pair: NormativePair,
    /// Exact generated provider-owned catalogue.
    pub catalogue: RuleCatalogue,
}

/// Immutable deterministic bootstrap rule catalogue.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRuleCatalogue {
    /// Artifact schema identity.
    pub schema_version: String,
    /// Normative pair used for compilation.
    pub normative_pair: NormativePair,
    /// Provider-owned normative catalogue; bootstrap adds no shadow rule model.
    pub catalogue: RuleCatalogue,
    /// Content address of all preceding fields.
    pub catalogue_sha256: String,
}

impl BootstrapRuleCatalogue {
    /// Validates exact identities and the catalogue digest.
    pub fn validate(&self) -> Result<(), BootstrapCompileError> {
        self.normative_pair.validate("rule-catalogue")?;
        text(
            &self.schema_version,
            "rule-catalogue".to_owned(),
            "schema_version",
        )?;
        self.catalogue
            .validate()
            .map_err(|error| BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: error.to_string(),
            })?;
        let mut canonical_entries = self.catalogue.entries.clone();
        canonical_entries.sort_by(|left, right| {
            left.rule_ref
                .rule_id
                .cmp(&right.rule_ref.rule_id)
                .then(left.rule_ref.revision.cmp(&right.rule_ref.revision))
        });
        if canonical_entries != self.catalogue.entries {
            return Err(BootstrapCompileError::InvalidExactArray {
                source_id: "rule-catalogue".to_owned(),
                field: "catalogue.entries",
                detail: "entries must use canonical rule identity order",
            });
        }
        digest(
            &self.catalogue_sha256,
            "rule-catalogue".to_owned(),
            "catalogue_sha256",
        )?;
        validate_content_digest(self, "rule-catalogue", &self.catalogue_sha256, |value| {
            value.catalogue_sha256.clear();
        })
    }
}

/// Compiles a deterministic bootstrap rule catalogue.
pub fn compile_bootstrap_rule_catalogue(
    source: SourceProjection<BootstrapRuleSource>,
) -> Result<BootstrapRuleCatalogue, BootstrapCompileError> {
    let (source_id, _revision, input) = require(source)?;
    input.normative_pair.validate(&source_id)?;
    let mut provider_catalogue = input.catalogue;
    provider_catalogue.entries.sort_by(|left, right| {
        left.rule_ref
            .rule_id
            .cmp(&right.rule_ref.rule_id)
            .then(left.rule_ref.revision.cmp(&right.rule_ref.revision))
    });
    provider_catalogue
        .validate()
        .map_err(|error| BootstrapCompileError::ProviderValidation {
            provider: "eliot-rules",
            detail: error.to_string(),
        })?;
    let mut catalogue = BootstrapRuleCatalogue {
        schema_version: "eliot-bootstrap-rule-catalogue-v1".to_owned(),
        normative_pair: input.normative_pair,
        catalogue: provider_catalogue,
        catalogue_sha256: String::new(),
    };
    catalogue.catalogue_sha256 = content_digest(&catalogue, "rule-catalogue", |value| {
        value.catalogue_sha256.clear();
    })?;
    catalogue.validate()?;
    Ok(catalogue)
}

/// Public profile to which a bootstrap brief is bounded.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BootstrapBriefProfile {
    Control,
    Recovery,
    Development,
}

/// One source command/surface required by a bootstrap profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSurfaceInput {
    /// Exact public command/surface identity.
    pub surface_id: String,
    /// Owning source package or handle.
    pub owner_ref: String,
    /// Whether this surface is available in the supplied source set.
    pub status: SourceStatus,
    /// Explicit public degraded behavior.
    pub degraded_behavior: String,
}

/// Input to the bootstrap brief compiler.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBriefSource {
    /// Profile requested by the caller.
    pub profile: BootstrapBriefProfile,
    /// Snapshot artifact to bind.
    pub snapshot: CurrentSystemEvidenceSnapshot,
    /// Rule catalogue artifact to bind.
    pub catalogue: BootstrapRuleCatalogue,
    /// Profile surfaces and explicit unavailable behavior.
    pub surfaces: Vec<BootstrapSurfaceInput>,
    /// Exact source/rule references used to make the brief.
    pub source_refs: Vec<String>,
}

/// Explicit normative coverage in a bootstrap brief.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapCoverage {
    /// Exact rules included in the profile.
    pub included_rule_ids: Vec<String>,
    /// Exact rules deliberately excluded from this profile.
    pub excluded_rule_ids: Vec<String>,
    /// Surfaces that are unavailable but explicitly represented.
    pub unavailable_surface_ids: Vec<String>,
}

/// Immutable deterministic bootstrap brief.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBrief {
    /// Artifact schema identity.
    pub schema_version: String,
    /// Profile bound by the brief.
    pub profile: BootstrapBriefProfile,
    /// Snapshot identity.
    pub snapshot_sha256: String,
    /// Rule catalogue identity.
    pub catalogue_sha256: String,
    /// Exact source/rule references used in compilation.
    pub source_refs: Vec<String>,
    /// Explicit coverage and unavailable surfaces.
    pub coverage: BootstrapCoverage,
    /// Content address of all preceding fields.
    pub brief_sha256: String,
}

impl BootstrapBrief {
    /// Validates profile references, coverage, and content identity.
    pub fn validate(&self) -> Result<(), BootstrapCompileError> {
        text(&self.schema_version, "brief".to_owned(), "schema_version")?;
        digest(&self.snapshot_sha256, "brief".to_owned(), "snapshot_sha256")?;
        digest(
            &self.catalogue_sha256,
            "brief".to_owned(),
            "catalogue_sha256",
        )?;
        digest(&self.brief_sha256, "brief".to_owned(), "brief_sha256")?;
        exact_strings(&self.source_refs, "brief", "source_refs")?;
        exact_strings(
            &self.coverage.included_rule_ids,
            "brief",
            "included_rule_ids",
        )?;
        exact_strings(
            &self.coverage.excluded_rule_ids,
            "brief",
            "excluded_rule_ids",
        )?;
        exact_strings(
            &self.coverage.unavailable_surface_ids,
            "brief",
            "unavailable_surface_ids",
        )?;
        let mut all = self.coverage.included_rule_ids.clone();
        all.extend(self.coverage.excluded_rule_ids.clone());
        exact_strings(&all, "brief", "rule_coverage")?;
        validate_content_digest(self, "brief", &self.brief_sha256, |value| {
            value.brief_sha256.clear();
        })
    }
}

fn validate_brief_inputs(source: &BootstrapBriefSource) -> Result<(), BootstrapCompileError> {
    source.snapshot.validate()?;
    source.catalogue.validate()?;
    if source.snapshot.normative_pair != source.catalogue.normative_pair {
        return Err(BootstrapCompileError::ConflictingIdentity {
            source_id: "brief".to_owned(),
            identity: "normative_pair".to_owned(),
        });
    }
    exact_strings(&source.source_refs, "brief", "source_refs")?;
    if !source
        .source_refs
        .iter()
        .any(|reference| reference == &source.snapshot.snapshot_sha256)
    {
        return Err(BootstrapCompileError::MissingReference {
            reference: source.snapshot.snapshot_sha256.clone(),
            field: "source_refs",
        });
    }
    if !source
        .source_refs
        .iter()
        .any(|reference| reference == &source.catalogue.catalogue_sha256)
    {
        return Err(BootstrapCompileError::MissingReference {
            reference: source.catalogue.catalogue_sha256.clone(),
            field: "source_refs",
        });
    }
    Ok(())
}

/// Compiles a bootstrap brief from already compiled immutable artifacts.
pub fn compile_bootstrap_brief(
    source: BootstrapBriefSource,
) -> Result<BootstrapBrief, BootstrapCompileError> {
    validate_brief_inputs(&source)?;
    let mut surfaces = BTreeMap::new();
    for surface in source.surfaces {
        text(&surface.surface_id, "brief".to_owned(), "surface_id")?;
        text(&surface.owner_ref, "brief".to_owned(), "owner_ref")?;
        text(
            &surface.degraded_behavior,
            "brief".to_owned(),
            "degraded_behavior",
        )?;
        if surfaces
            .insert(surface.surface_id.clone(), surface)
            .is_some()
        {
            return Err(BootstrapCompileError::ConflictingIdentity {
                source_id: "brief".to_owned(),
                identity: "surface_id".to_owned(),
            });
        }
    }
    let included_rule_ids = source
        .catalogue
        .catalogue
        .entries
        .iter()
        .filter(|rule| {
            matches!(
                rule.class,
                RuleClass::HardBoundary | RuleClass::Contract | RuleClass::Guardrail
            )
        })
        .map(|rule| {
            format!(
                "{}@{}",
                rule.rule_ref.rule_id,
                rule.rule_ref.revision.value()
            )
        })
        .collect::<Vec<_>>();
    let mut excluded_rule_ids = source
        .catalogue
        .catalogue
        .entries
        .iter()
        .filter(|rule| {
            let identity = format!(
                "{}@{}",
                rule.rule_ref.rule_id,
                rule.rule_ref.revision.value()
            );
            !included_rule_ids.contains(&identity)
        })
        .map(|rule| {
            format!(
                "{}@{}",
                rule.rule_ref.rule_id,
                rule.rule_ref.revision.value()
            )
        })
        .collect::<Vec<_>>();
    let mut unavailable_surface_ids = surfaces
        .values()
        .filter(|surface| !surface.status.is_complete())
        .map(|surface| surface.surface_id.clone())
        .collect::<Vec<_>>();
    let mut source_refs = source.source_refs;
    source_refs.sort();
    let mut included_rule_ids = included_rule_ids;
    included_rule_ids.sort();
    excluded_rule_ids.sort();
    unavailable_surface_ids.sort();
    let mut brief = BootstrapBrief {
        schema_version: "eliot-bootstrap-brief-v1".to_owned(),
        profile: source.profile,
        snapshot_sha256: source.snapshot.snapshot_sha256,
        catalogue_sha256: source.catalogue.catalogue_sha256,
        source_refs,
        coverage: BootstrapCoverage {
            included_rule_ids,
            excluded_rule_ids,
            unavailable_surface_ids,
        },
        brief_sha256: String::new(),
    };
    brief.brief_sha256 = content_digest(&brief, "brief", |value| {
        value.brief_sha256.clear();
    })?;
    brief.validate()?;
    Ok(brief)
}

fn content_digest<T: Serialize + Clone>(
    value: &T,
    artifact: &'static str,
    clear_digest: impl FnOnce(&mut T),
) -> Result<String, BootstrapCompileError> {
    let mut canonical_value = value.clone();
    clear_digest(&mut canonical_value);
    canonical_json_bytes(&canonical_value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| BootstrapCompileError::Canonicalization {
            artifact,
            reason: error.to_string(),
        })
}

fn validate_content_digest<T: Serialize + Clone>(
    value: &T,
    artifact: &'static str,
    expected: &str,
    clear_digest: impl FnOnce(&mut T),
) -> Result<(), BootstrapCompileError> {
    let actual = content_digest(value, artifact, clear_digest)?;
    if actual != expected {
        return Err(BootstrapCompileError::DigestMismatch { artifact });
    }
    Ok(())
}

/// Returns the stable contract identity for the bootstrap schema surface.
pub fn contract_identity() -> Result<eliot_contracts::ContractIdentity, BootstrapCompileError> {
    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        eliot_contracts::ContractVersion::new(1, 0, 0),
        &serde_json::json!({
            "source_projection": schemars::schema_for!(SourceProjection<String>),
            "current_system_evidence_snapshot": schemars::schema_for!(CurrentSystemEvidenceSnapshot),
            "bootstrap_rule_catalogue": schemars::schema_for!(BootstrapRuleCatalogue),
            "bootstrap_brief": schemars::schema_for!(BootstrapBrief),
        }),
    )
    .map_err(|error| BootstrapCompileError::Canonicalization {
        artifact: "contract",
        reason: error.to_string(),
    })
}

/// Returns the exact identity of the direct protocol provider used by this cell.
pub fn protocol_provider_identity()
-> Result<eliot_contracts::ContractIdentity, BootstrapCompileError> {
    eliot_protocol::protocol_contract_identity().map_err(|error| {
        BootstrapCompileError::ProviderValidation {
            provider: "eliot-protocol",
            detail: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> NormativePair {
        NormativePair {
            architecture_sha256: "a".repeat(64),
            implementation_sha256: "b".repeat(64),
            runtime_sha256: "c".repeat(64),
        }
    }

    fn evidence_source() -> SourceProjection<CurrentSystemEvidenceSource> {
        SourceProjection::complete(
            "current-system",
            "revision-1",
            CurrentSystemEvidenceSource {
                normative_pair: pair(),
                selected_repository_root: "repo-root".to_owned(),
                selected_source_head: "head-1".to_owned(),
                dirty_delta_artifact_ref: None,
                external_state_root: "state-root".to_owned(),
                records: vec![EvidenceRecord {
                    key: "source.head".to_owned(),
                    value: "head-1".to_owned(),
                    evidence_ref: "capture-1".to_owned(),
                    evaluation: EvidenceEvaluation::Screened,
                }],
                unavailable_domains: vec!["runtime".to_owned()],
            },
        )
    }

    fn rule_source() -> Result<SourceProjection<BootstrapRuleSource>, Box<dyn std::error::Error>> {
        let normative_pair_identity = eliot_contracts::contract_identity(
            "eliot.rules.test",
            eliot_contracts::ContractVersion::new(1, 0, 0),
            &serde_json::json!({"fixture": "rules"}),
        )?;
        let revision = eliot_contracts::Revision::new(1)?;
        let rule_ref = eliot_rules::RuleRef::new("R-1", revision)?;
        Ok(SourceProjection::complete(
            "rules",
            "revision-1",
            BootstrapRuleSource {
                normative_pair: pair(),
                catalogue: RuleCatalogue {
                    normative_pair_identity,
                    catalogue_revision: revision,
                    entries: vec![eliot_rules::RuleCatalogueEntry {
                        rule_ref,
                        class: eliot_rules::RuleClass::Contract,
                        architecture_anchor_or_policy_root: "ARCH-1".to_owned(),
                        owning_implementation_section_and_capability: "I-1".to_owned(),
                        scope_and_applicability: "bootstrap".to_owned(),
                        rationale_and_failure_class: "typed".to_owned(),
                        observable_property_or_decision_changed: "status".to_owned(),
                        enforcement_or_degraded_behavior: "reject".to_owned(),
                        challenge_deviation_or_change_path: "review".to_owned(),
                        invalidation_and_expiry: "revision".to_owned(),
                    }],
                },
            },
        ))
    }

    #[test]
    fn snapshot_is_deterministic_and_sorted() -> Result<(), Box<dyn std::error::Error>> {
        let first = compile_current_system_evidence_snapshot(evidence_source())?;
        let second = compile_current_system_evidence_snapshot(evidence_source())?;
        assert_eq!(first, second);
        assert_eq!(first.records[0].key, "source.head");
        first.validate()?;
        Ok(())
    }

    #[test]
    fn unavailable_source_is_typed_and_not_silently_empty() {
        let source = SourceProjection::<CurrentSystemEvidenceSource>::unavailable(
            "current-system",
            "revision-1",
            SourceStatus::Partial,
        );
        assert!(matches!(
            compile_current_system_evidence_snapshot(source),
            Err(BootstrapCompileError::SourceUnavailable {
                status: SourceStatus::Partial,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_exact_values_are_rejected() {
        let mut source = evidence_source();
        if let Some(value) = source.value.as_mut() {
            value.unavailable_domains.push("runtime".to_owned());
        }
        assert!(matches!(
            compile_current_system_evidence_snapshot(source),
            Err(BootstrapCompileError::InvalidExactArray {
                field: "unavailable_domains",
                ..
            })
        ));
    }

    #[test]
    fn forged_snapshot_digest_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = compile_current_system_evidence_snapshot(evidence_source())?;
        snapshot.snapshot_sha256 = "d".repeat(64);
        assert!(matches!(
            snapshot.validate(),
            Err(BootstrapCompileError::DigestMismatch {
                artifact: "snapshot"
            })
        ));
        Ok(())
    }

    #[test]
    fn rule_catalogue_rejects_duplicate_exact_identity() -> Result<(), Box<dyn std::error::Error>> {
        let mut source = rule_source()?;
        if let Some(value) = source.value.as_mut() {
            let first = value.catalogue.entries.first().cloned();
            if let Some(first) = first {
                value.catalogue.entries.push(first);
            }
        }
        assert!(matches!(
            compile_bootstrap_rule_catalogue(source),
            Err(BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn brief_binds_snapshot_and_catalogue_without_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = compile_current_system_evidence_snapshot(evidence_source())?;
        let catalogue = compile_bootstrap_rule_catalogue(rule_source()?)?;
        let snapshot_ref = snapshot.snapshot_sha256.clone();
        let catalogue_ref = catalogue.catalogue_sha256.clone();
        let brief = compile_bootstrap_brief(BootstrapBriefSource {
            profile: BootstrapBriefProfile::Control,
            snapshot,
            catalogue,
            surfaces: vec![BootstrapSurfaceInput {
                surface_id: "eliot.bootstrap.brief".to_owned(),
                owner_ref: "C0-09".to_owned(),
                status: SourceStatus::Complete,
                degraded_behavior: "UNAVAILABLE".to_owned(),
            }],
            source_refs: vec![snapshot_ref, catalogue_ref],
        })?;
        brief.validate()?;
        assert_eq!(brief.coverage.included_rule_ids, vec!["R-1@1"]);
        Ok(())
    }

    #[test]
    fn brief_requires_exact_artifact_references() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = compile_current_system_evidence_snapshot(evidence_source())?;
        let catalogue = compile_bootstrap_rule_catalogue(rule_source()?)?;
        let error = compile_bootstrap_brief(BootstrapBriefSource {
            profile: BootstrapBriefProfile::Control,
            snapshot,
            catalogue,
            surfaces: Vec::new(),
            source_refs: vec!["unrelated-source".to_owned()],
        });
        assert!(matches!(
            error,
            Err(BootstrapCompileError::MissingReference {
                field: "source_refs",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn contract_schema_is_available() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!contract_identity()?.shape_sha256.is_empty());
        Ok(())
    }
}
