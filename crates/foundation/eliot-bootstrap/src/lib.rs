//! Pure, deterministic D0 bootstrap compilers.
//!
//! This crate only turns already supplied, immutable source projections into
//! content-addressed bootstrap artifacts.  It never discovers files, starts a
//! process, edits a projection, grants authority, or emits a finish/release
//! verdict.  Source availability is explicit and fail-closed: a partial,
//! missing, or conflicted required source is returned as a typed error rather
//! than being treated as a successful empty result.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

#[cfg(test)]
use std::collections::BTreeMap;

use eliot_agent_api::AgentWorkUnitBrief;
use eliot_contracts::{
    ContractIdentity, ContractVersion, Revision, canonical_json_bytes, sha256_hex,
};
#[cfg(test)]
use eliot_rules::{BindingReason, ExcludedRule};
use eliot_rules::{
    NormativeCoverageManifest, PairAndCatalogueRevision, ReasonCodeEntry, ReasonDirectiveRegistry,
    RuleCatalogue,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod capture;

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
        )
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

/// Normative `I:209` compiler for deterministic current-system evidence.
pub struct CurrentSystemEvidenceCompiler;

impl CurrentSystemEvidenceCompiler {
    /// Compiles a deterministic current-system evidence snapshot.
    pub fn compile(
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
            schema_version: "eliot-current-system-evidence-snapshot-v2".to_owned(),
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
        schema_version: "eliot-bootstrap-rule-catalogue-v2".to_owned(),
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

impl BootstrapCoverage {
    /// Derives the public coverage view from the sole disposition authority.
    pub fn from_manifest(manifest: &NormativeCoverageManifest) -> Self {
        let mut included_rule_ids = manifest
            .included_rule_bindings
            .iter()
            .map(|binding| {
                format!(
                    "{}@{}",
                    binding.rule_ref.rule_id,
                    binding.rule_ref.revision.value()
                )
            })
            .collect::<Vec<_>>();
        let mut excluded_rule_ids = manifest
            .excluded_with_reason
            .iter()
            .map(|excluded| {
                format!(
                    "{}@{}",
                    excluded.rule_ref.rule_id,
                    excluded.rule_ref.revision.value()
                )
            })
            .collect::<Vec<_>>();
        let mut unavailable_surface_ids = manifest.not_searched_scopes.clone();
        included_rule_ids.sort();
        excluded_rule_ids.sort();
        unavailable_surface_ids.sort();
        Self {
            included_rule_ids,
            excluded_rule_ids,
            unavailable_surface_ids,
        }
    }

    fn validate_bijective(
        &self,
        manifest: &NormativeCoverageManifest,
    ) -> Result<(), BootstrapCompileError> {
        if *self != Self::from_manifest(manifest) {
            return Err(BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail:
                    "bootstrap coverage is not a bijective projection of the normative manifest"
                        .to_owned(),
            });
        }
        Ok(())
    }
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
    /// Sole normative disposition authority for this brief.
    pub normative_coverage_manifest: NormativeCoverageManifest,
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
        self.coverage
            .validate_bijective(&self.normative_coverage_manifest)?;
        let mut all = self.coverage.included_rule_ids.clone();
        all.extend(self.coverage.excluded_rule_ids.clone());
        exact_strings(&all, "brief", "rule_coverage")?;
        validate_content_digest(self, "brief", &self.brief_sha256, |value| {
            value.brief_sha256.clear();
        })
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn exclusion_manifest_for_catalogue(
    catalogue: &RuleCatalogue,
) -> Result<(NormativeCoverageManifest, ReasonDirectiveRegistry), BootstrapCompileError> {
    let registry = ReasonDirectiveRegistry {
        reasons: vec![ReasonCodeEntry {
            code: "NORMATIVE_COVERAGE_INCOMPLETE".to_owned(),
            description: "The provider-owned normative catalogue is incomplete; no rule is permission to proceed.".to_owned(),
        }],
        directives: Vec::new(),
    };
    let manifest = NormativeCoverageManifest {
        pair_and_catalogue_revision: PairAndCatalogueRevision {
            normative_pair_identity: catalogue.normative_pair_identity.clone(),
            catalogue_revision: catalogue.catalogue_revision,
        },
        searched_rule_scopes: Vec::new(),
        included_rule_bindings: Vec::new(),
        excluded_with_reason: catalogue
            .entries
            .iter()
            .map(|entry| ExcludedRule {
                rule_ref: entry.rule_ref.clone(),
                reason: BindingReason {
                    code: "NORMATIVE_COVERAGE_INCOMPLETE".to_owned(),
                    detail: "Provider coverage is incomplete; this rule is not included."
                        .to_owned(),
                },
            })
            .collect(),
        not_searched_scopes: Vec::new(),
        searched_and_absent_questions: Vec::new(),
        stale_or_conflicting_rules: Vec::new(),
        expansion_handles: Vec::new(),
    };
    manifest
        .validate_against(catalogue, &registry)
        .map_err(|error| BootstrapCompileError::ProviderValidation {
            provider: "eliot-rules",
            detail: error.to_string(),
        })?;
    Ok((manifest, registry))
}

/// Legacy test oracle for the pre-provider compiler shape. Production callers
/// use [`BootstrapBriefCompiler::compile`], which cannot accept a caller catalogue.
#[cfg(test)]
fn compile_bootstrap_brief(
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
    let (mut normative_coverage_manifest, _registry) =
        exclusion_manifest_for_catalogue(&source.catalogue.catalogue)?;
    normative_coverage_manifest.not_searched_scopes = surfaces
        .values()
        .filter(|surface| !surface.status.is_complete())
        .map(|surface| surface.surface_id.clone())
        .collect::<Vec<_>>();
    normative_coverage_manifest.not_searched_scopes.sort();
    let mut source_refs = source.source_refs;
    source_refs.sort();
    let mut brief = BootstrapBrief {
        schema_version: "eliot-bootstrap-brief-v2".to_owned(),
        profile: source.profile,
        snapshot_sha256: source.snapshot.snapshot_sha256,
        catalogue_sha256: source.catalogue.catalogue_sha256,
        source_refs,
        normative_coverage_manifest: normative_coverage_manifest.clone(),
        coverage: BootstrapCoverage::from_manifest(&normative_coverage_manifest),
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
        eliot_contracts::ContractVersion::new(2, 0, 0),
        &serde_json::json!({
            "source_projection": schemars::schema_for!(SourceProjection<String>),
            "current_system_evidence_snapshot": schemars::schema_for!(CurrentSystemEvidenceSnapshot),
            "bootstrap_rule_catalogue": schemars::schema_for!(BootstrapRuleCatalogue),
            "bootstrap_brief": schemars::schema_for!(BootstrapBrief),
            "provider_normative_projection": schemars::schema_for!(ProviderNormativeProjection),
            "bootstrap_failure_draft": schemars::schema_for!(BootstrapFailureDraft),
            "bootstrap_improvement_draft": schemars::schema_for!(BootstrapImprovementDraft),
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

/// Stable provider identity for the first honest bootstrap projection.
pub const NORMATIVE_PROVIDER_ID: &str = "eliot-normative-provider";
/// Stable provider source revision.  It changes whenever this projection
/// policy changes, independently of a caller's work-unit revision.
pub const NORMATIVE_PROVIDER_REVISION: &str = "eliot-normative-provider-v2";
/// Source revision bound to the frozen Architecture/Implementation pair.
pub const NORMATIVE_SOURCE_REVISION: &str = "architecture-implementation-pair-v1";
/// Designated reason for an unavailable generated Contract Catalogue.
pub const NORMATIVE_COVERAGE_INCOMPLETE: &str = "NORMATIVE_COVERAGE_INCOMPLETE";

/// Whether the provider has a complete generated catalogue or an explicit gap.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormativeProjectionStatus {
    Complete,
    Gap,
}

/// Provider-owned normative projection.  There is intentionally no caller
/// catalogue or registry parameter on the constructor: until the canonical
/// generated catalogue is activated, this provider emits a typed GAP.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNormativeProjection {
    pub status: NormativeProjectionStatus,
    pub provider_id: String,
    pub provider_revision: String,
    pub source_revision: String,
    pub normative_pair: NormativePair,
    pub catalogue: RuleCatalogue,
    pub registry: ReasonDirectiveRegistry,
    pub manifest: NormativeCoverageManifest,
    pub catalogue_sha256: String,
    pub registry_sha256: String,
}

fn provider_identity(pair: &NormativePair) -> Result<ContractIdentity, BootstrapCompileError> {
    eliot_contracts::contract_identity(
        NORMATIVE_PROVIDER_ID,
        ContractVersion::new(2, 0, 0),
        &serde_json::json!({
            "source_revision": NORMATIVE_SOURCE_REVISION,
            "normative_pair": pair,
        }),
    )
    .map_err(|error| BootstrapCompileError::Canonicalization {
        artifact: "normative-provider",
        reason: error.to_string(),
    })
}

fn provider_registry() -> ReasonDirectiveRegistry {
    ReasonDirectiveRegistry {
        reasons: vec![ReasonCodeEntry {
            code: NORMATIVE_COVERAGE_INCOMPLETE.to_owned(),
            description: "The generated Contract Catalogue is not activated; no rule is permission to proceed.".to_owned(),
        }],
        directives: Vec::new(),
    }
}

/// Builds the provider-owned GAP projection for the frozen normative pair.
pub fn provider_normative_gap() -> Result<ProviderNormativeProjection, BootstrapCompileError> {
    let normative_pair = capture::current_normative_pair();
    let identity = provider_identity(&normative_pair)?;
    let catalogue = RuleCatalogue {
        normative_pair_identity: identity.clone(),
        catalogue_revision: Revision::new(1).map_err(|error| {
            BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: error.to_string(),
            }
        })?,
        entries: Vec::new(),
    };
    let registry = provider_registry();
    let manifest = NormativeCoverageManifest {
        pair_and_catalogue_revision: PairAndCatalogueRevision {
            normative_pair_identity: identity,
            catalogue_revision: catalogue.catalogue_revision,
        },
        searched_rule_scopes: Vec::new(),
        included_rule_bindings: Vec::new(),
        excluded_with_reason: Vec::new(),
        not_searched_scopes: vec![
            "provider".to_owned(),
            "runtime".to_owned(),
            "store".to_owned(),
            "integrations".to_owned(),
        ],
        searched_and_absent_questions: Vec::new(),
        stale_or_conflicting_rules: Vec::new(),
        expansion_handles: Vec::new(),
    };
    let mut projection = ProviderNormativeProjection {
        status: NormativeProjectionStatus::Gap,
        provider_id: NORMATIVE_PROVIDER_ID.to_owned(),
        provider_revision: NORMATIVE_PROVIDER_REVISION.to_owned(),
        source_revision: NORMATIVE_SOURCE_REVISION.to_owned(),
        normative_pair,
        catalogue,
        registry,
        manifest,
        catalogue_sha256: String::new(),
        registry_sha256: String::new(),
    };
    projection.catalogue_sha256 = canonical_digest(&projection.catalogue, "normative-catalogue")?;
    projection.registry_sha256 = canonical_digest(&projection.registry, "normative-registry")?;
    projection.validate()?;
    Ok(projection)
}

impl ProviderNormativeProjection {
    /// Validates frozen identity, provider provenance, digests and gap shape.
    pub fn validate(&self) -> Result<(), BootstrapCompileError> {
        if self.status != NormativeProjectionStatus::Gap
            || self.provider_id != NORMATIVE_PROVIDER_ID
            || self.provider_revision != NORMATIVE_PROVIDER_REVISION
            || self.source_revision != NORMATIVE_SOURCE_REVISION
            || self.normative_pair != capture::current_normative_pair()
        {
            return Err(BootstrapCompileError::ProviderValidation {
                provider: NORMATIVE_PROVIDER_ID,
                detail: "provider normative identity is not the frozen GAP projection".to_owned(),
            });
        }
        self.normative_pair.validate("normative-provider")?;
        self.catalogue
            .validate()
            .map_err(|error| BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: error.to_string(),
            })?;
        if !self.catalogue.entries.is_empty() {
            return Err(BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: "GAP projection must not contain synthetic rules".to_owned(),
            });
        }
        self.registry
            .validate()
            .map_err(|error| BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: error.to_string(),
            })?;
        if !self
            .registry
            .reasons
            .iter()
            .any(|reason| reason.code == NORMATIVE_COVERAGE_INCOMPLETE)
        {
            return Err(BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: "GAP projection is missing designated reason".to_owned(),
            });
        }
        self.manifest
            .validate_against(&self.catalogue, &self.registry)
            .map_err(|error| BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: error.to_string(),
            })?;
        if !self.manifest.included_rule_bindings.is_empty()
            || !self.manifest.excluded_with_reason.is_empty()
        {
            return Err(BootstrapCompileError::ProviderValidation {
                provider: "eliot-rules",
                detail: "GAP manifest must contain no rule dispositions".to_owned(),
            });
        }
        if canonical_digest(&self.catalogue, "normative-catalogue")? != self.catalogue_sha256
            || canonical_digest(&self.registry, "normative-registry")? != self.registry_sha256
        {
            return Err(BootstrapCompileError::DigestMismatch {
                artifact: "normative-provider",
            });
        }
        Ok(())
    }
}

/// Normative `I:209` compiler for one provider-owned bootstrap brief.
pub struct BootstrapBriefCompiler;

impl BootstrapBriefCompiler {
    /// Builds the provider-owned rule/scope projection for one canonical seed.
    pub fn compile(
        seed: AgentWorkUnitBrief,
        snapshot: &CurrentSystemEvidenceSnapshot,
    ) -> Result<BootstrapBrief, BootstrapCompileError> {
        seed.validate()
            .map_err(|error| BootstrapCompileError::ProviderValidation {
                provider: "eliot-agent-api",
                detail: error.to_string(),
            })?;
        snapshot.validate()?;
        let canonical_pair = capture::current_normative_pair();
        if snapshot.normative_pair != canonical_pair {
            return Err(BootstrapCompileError::ConflictingIdentity {
                source_id: "current-system-evidence".to_owned(),
                identity: "normative_pair".to_owned(),
            });
        }
        let projection = provider_normative_gap()?;
        let snapshot_sha256 = snapshot.snapshot_sha256.clone();
        let catalogue_sha256 = projection.catalogue_sha256.clone();
        let mut source_refs = seed.source_refs;
        source_refs.push(snapshot_sha256.clone());
        source_refs.push(catalogue_sha256.clone());
        source_refs.sort();
        source_refs.dedup();
        let manifest = projection.manifest;
        let mut brief = BootstrapBrief {
            schema_version: "eliot-bootstrap-brief-v2".to_owned(),
            profile: BootstrapBriefProfile::Recovery,
            snapshot_sha256,
            catalogue_sha256,
            source_refs,
            normative_coverage_manifest: manifest.clone(),
            coverage: BootstrapCoverage::from_manifest(&manifest),
            brief_sha256: String::new(),
        };
        brief.brief_sha256 = content_digest(&brief, "brief", |value| value.brief_sha256.clear())?;
        brief.validate()?;
        Ok(brief)
    }
}

/// How a bootstrap draft may be reconciled into the canonical evidence store.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DraftImportDisposition {
    CandidateOnly,
    Imported,
    Rejected,
}

/// Provider-owned inputs shared by the candidate failure and improvement drafts.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDraftInput {
    pub source_identity: String,
    pub normative_pair: NormativePair,
    pub snapshot_ref: String,
    pub catalogue_ref: String,
    pub owner: String,
    pub discriminator: String,
    pub import_disposition: DraftImportDisposition,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapFailureDraft {
    pub source_identity: String,
    pub normative_pair: NormativePair,
    pub snapshot_ref: String,
    pub catalogue_ref: String,
    pub work_unit_id: String,
    pub owner: String,
    pub discriminator: String,
    pub import_disposition: DraftImportDisposition,
    pub canonical_digest: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapImprovementDraft {
    pub source_identity: String,
    pub normative_pair: NormativePair,
    pub snapshot_ref: String,
    pub catalogue_ref: String,
    pub work_unit_id: String,
    pub owner: String,
    pub discriminator: String,
    pub import_disposition: DraftImportDisposition,
    pub canonical_digest: String,
}

macro_rules! draft_impl {
    ($name:ident) => {
        impl $name {
            pub fn new(
                input: BootstrapDraftInput,
                seed: &AgentWorkUnitBrief,
            ) -> Result<Self, BootstrapCompileError> {
                seed.validate()
                    .map_err(|error| BootstrapCompileError::ProviderValidation {
                        provider: "eliot-agent-api",
                        detail: error.to_string(),
                    })?;
                for (value, field) in [
                    (&input.source_identity, "source_identity"),
                    (&input.snapshot_ref, "snapshot_ref"),
                    (&input.catalogue_ref, "catalogue_ref"),
                    (&input.owner, "owner"),
                    (&input.discriminator, "discriminator"),
                ] {
                    text(value, "bootstrap-draft".to_owned(), field)?;
                }
                input.normative_pair.validate("bootstrap-draft")?;
                digest(
                    &input.snapshot_ref,
                    "bootstrap-draft".to_owned(),
                    "snapshot_ref",
                )?;
                digest(
                    &input.catalogue_ref,
                    "bootstrap-draft".to_owned(),
                    "catalogue_ref",
                )?;
                let mut draft = Self {
                    source_identity: input.source_identity,
                    normative_pair: input.normative_pair,
                    snapshot_ref: input.snapshot_ref,
                    catalogue_ref: input.catalogue_ref,
                    work_unit_id: seed.id.clone().into(),
                    owner: input.owner,
                    discriminator: input.discriminator,
                    import_disposition: input.import_disposition,
                    canonical_digest: String::new(),
                };
                draft.canonical_digest = draft_digest(&draft)?;
                Ok(draft)
            }

            pub fn validate(&self) -> Result<(), BootstrapCompileError> {
                text(
                    &self.source_identity,
                    "bootstrap-draft".to_owned(),
                    "source_identity",
                )?;
                text(
                    &self.work_unit_id,
                    "bootstrap-draft".to_owned(),
                    "work_unit_id",
                )?;
                text(&self.owner, "bootstrap-draft".to_owned(), "owner")?;
                text(
                    &self.discriminator,
                    "bootstrap-draft".to_owned(),
                    "discriminator",
                )?;
                self.normative_pair.validate("bootstrap-draft")?;
                digest(
                    &self.snapshot_ref,
                    "bootstrap-draft".to_owned(),
                    "snapshot_ref",
                )?;
                digest(
                    &self.catalogue_ref,
                    "bootstrap-draft".to_owned(),
                    "catalogue_ref",
                )?;
                digest(
                    &self.canonical_digest,
                    "bootstrap-draft".to_owned(),
                    "canonical_digest",
                )?;
                if draft_digest(self)? != self.canonical_digest {
                    return Err(BootstrapCompileError::DigestMismatch {
                        artifact: "bootstrap-draft",
                    });
                }
                Ok(())
            }
        }
    };
}

draft_impl!(BootstrapFailureDraft);
draft_impl!(BootstrapImprovementDraft);

fn canonical_digest<T: Serialize>(
    value: &T,
    artifact: &'static str,
) -> Result<String, BootstrapCompileError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| BootstrapCompileError::Canonicalization {
            artifact,
            reason: error.to_string(),
        })
}

fn draft_digest<T>(value: &T) -> Result<String, BootstrapCompileError>
where
    T: Serialize + Clone + DraftDigestValue,
{
    let mut unsigned = value.clone();
    unsigned.clear_digest();
    canonical_digest(&unsigned, "bootstrap-draft")
}

trait DraftDigestValue {
    fn clear_digest(&mut self);
}

impl DraftDigestValue for BootstrapFailureDraft {
    fn clear_digest(&mut self) {
        self.canonical_digest.clear();
    }
}

impl DraftDigestValue for BootstrapImprovementDraft {
    fn clear_digest(&mut self) {
        self.canonical_digest.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn seed() -> AgentWorkUnitBrief {
        AgentWorkUnitBrief {
            id: match eliot_agent_api::WorkUnitId::new("W0-06") {
                Ok(id) => id,
                Err(error) => panic!("fixture identity must be valid: {error}"),
            },
            objective: "emit an honest bootstrap gap".to_owned(),
            causal_property: "missing normative coverage remains visible".to_owned(),
            scope_ref: "eliot-bootstrap".to_owned(),
            expected_outputs: vec!["BootstrapBrief".to_owned()],
            source_refs: vec!["a".repeat(64)],
            verifier_ref: "unit-test".to_owned(),
            integration_owner: "Luna-A".to_owned(),
            contract_revision: "W0".to_owned(),
            budget: eliot_agent_api::BudgetEnvelope {
                context_tokens: 1,
                wall_time_ms: 1,
                output_bytes: 1,
                cost_microunits: 1,
                max_depth: 1,
                max_descendants: 0,
            },
            effect_ceiling: eliot_agent_api::EffectCeiling {
                scope_ref: "eliot-bootstrap".to_owned(),
                allowed: BTreeSet::from([eliot_agent_api::EffectKind::Observe]),
                max_external_effects: 0,
            },
            stop_condition: "stop after candidate".to_owned(),
        }
    }

    fn pair() -> NormativePair {
        NormativePair {
            architecture_sha256: "a".repeat(64),
            implementation_sha256: "b".repeat(64),
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
            eliot_contracts::ContractVersion::new(2, 0, 0),
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
        let first = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
        let second = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
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
            CurrentSystemEvidenceCompiler::compile(source),
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
            CurrentSystemEvidenceCompiler::compile(source),
            Err(BootstrapCompileError::InvalidExactArray {
                field: "unavailable_domains",
                ..
            })
        ));
    }

    #[test]
    fn forged_snapshot_digest_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
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
        let snapshot = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
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
        assert!(brief.coverage.included_rule_ids.is_empty());
        assert_eq!(brief.coverage.excluded_rule_ids, vec!["R-1@1"]);
        Ok(())
    }

    #[test]
    fn brief_requires_exact_artifact_references() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
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
    fn provider_gap_is_owned_empty_and_byte_stable() -> Result<(), Box<dyn std::error::Error>> {
        let first = provider_normative_gap()?;
        let second = provider_normative_gap()?;
        assert_eq!(first, second);
        assert_eq!(first.status, NormativeProjectionStatus::Gap);
        assert!(first.catalogue.entries.is_empty());
        assert!(first.manifest.included_rule_bindings.is_empty());
        assert!(first.manifest.excluded_with_reason.is_empty());
        assert!(
            first
                .registry
                .reasons
                .iter()
                .any(|reason| { reason.code == NORMATIVE_COVERAGE_INCOMPLETE })
        );
        assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
        Ok(())
    }

    #[test]
    fn provider_gap_rejects_identity_and_reason_tampering() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut identity_tampered = provider_normative_gap()?;
        identity_tampered.source_revision = "caller-revision".to_owned();
        assert!(identity_tampered.validate().is_err());

        let mut reason_tampered = provider_normative_gap()?;
        reason_tampered.registry.reasons.clear();
        assert!(reason_tampered.validate().is_err());
        Ok(())
    }

    #[test]
    fn coverage_is_bijective_projection_of_manifest() -> Result<(), Box<dyn std::error::Error>> {
        let projection = provider_normative_gap()?;
        let coverage = BootstrapCoverage::from_manifest(&projection.manifest);
        coverage.validate_bijective(&projection.manifest)?;
        let mut forged = coverage;
        forged.unavailable_surface_ids.push("fake".to_owned());
        assert!(forged.validate_bijective(&projection.manifest).is_err());
        Ok(())
    }

    #[test]
    fn provider_gap_brief_and_drafts_are_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let mut source = evidence_source();
        let value = source
            .value
            .as_mut()
            .ok_or("complete evidence fixture must carry a value")?;
        value.normative_pair = capture::current_normative_pair();
        let snapshot = CurrentSystemEvidenceCompiler::compile(source)?;
        let snapshot_ref = snapshot.snapshot_sha256.clone();
        let first = BootstrapBriefCompiler::compile(seed(), &snapshot)?;
        let second = BootstrapBriefCompiler::compile(seed(), &snapshot)?;
        assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);

        let pair = current_normative_pair_for_test();
        let failure = BootstrapFailureDraft::new(
            BootstrapDraftInput {
                source_identity: "capture".to_owned(),
                normative_pair: pair.clone(),
                snapshot_ref: snapshot_ref.clone(),
                catalogue_ref: first.catalogue_sha256.clone(),
                owner: "Luna-A".to_owned(),
                discriminator: "missing-catalogue".to_owned(),
                import_disposition: DraftImportDisposition::CandidateOnly,
            },
            &seed(),
        )?;
        let improvement = BootstrapImprovementDraft::new(
            BootstrapDraftInput {
                source_identity: "capture".to_owned(),
                normative_pair: pair,
                snapshot_ref,
                catalogue_ref: first.catalogue_sha256,
                owner: "Luna-A".to_owned(),
                discriminator: "activate-catalogue".to_owned(),
                import_disposition: DraftImportDisposition::CandidateOnly,
            },
            &seed(),
        )?;
        assert_eq!(serde_json::to_vec(&failure)?, serde_json::to_vec(&failure)?);
        failure.validate()?;
        improvement.validate()?;
        Ok(())
    }

    #[test]
    fn provider_gap_brief_rejects_a_noncanonical_snapshot_pair()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = CurrentSystemEvidenceCompiler::compile(evidence_source())?;
        assert!(matches!(
            BootstrapBriefCompiler::compile(seed(), &snapshot),
            Err(BootstrapCompileError::ConflictingIdentity {
                ref source_id,
                ref identity,
            }) if source_id == "current-system-evidence" && identity == "normative_pair"
        ));
        Ok(())
    }

    fn current_normative_pair_for_test() -> NormativePair {
        capture::current_normative_pair()
    }

    #[test]
    fn contract_schema_is_available() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!contract_identity()?.shape_sha256.is_empty());
        Ok(())
    }
}
