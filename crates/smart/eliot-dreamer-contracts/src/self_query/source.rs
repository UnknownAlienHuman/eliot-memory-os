//! Accepted normative-source, anchor and coverage-denominator contracts.

use std::{
    collections::BTreeSet,
    io::{self, Write},
};

use eliot_contracts::{ArtifactId, ReceiptId, SourceId, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::result::SelfQueryContractError;

pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_TEXT_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ANCHORS: usize = 4096;
pub(crate) const MAX_DEPENDENCY_MEMBERS: usize = 8192;
pub(crate) const MAX_REFS: usize = 8192;

pub(crate) fn check_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), SelfQueryContractError> {
    check_text_with_controls(value, field, maximum, false)
}

pub(crate) fn check_id(value: &str, field: &'static str) -> Result<(), SelfQueryContractError> {
    check_text(value, field, 256)
}

pub(crate) fn check_source_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), SelfQueryContractError> {
    check_text_with_controls(value, field, maximum, true)
}

fn check_text_with_controls(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_layout_controls: bool,
) -> Result<(), SelfQueryContractError> {
    if value.trim().is_empty() {
        return Err(SelfQueryContractError::Missing { field });
    }
    let has_forbidden_control = value.chars().any(|character| {
        character.is_control()
            && !(allow_layout_controls && matches!(character, '\n' | '\r' | '\t'))
    });
    if value.len() > maximum || has_forbidden_control {
        return Err(SelfQueryContractError::Bound {
            field,
            maximum,
            actual: value.len(),
        });
    }
    Ok(())
}

pub(crate) fn check_digest(value: &str, field: &'static str) -> Result<(), SelfQueryContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SelfQueryContractError::InvalidDigest { field });
    }
    Ok(())
}

pub(crate) fn check_schema(value: u32, field: &'static str) -> Result<(), SelfQueryContractError> {
    if value != SCHEMA_VERSION {
        return Err(SelfQueryContractError::UnsupportedVersion {
            field,
            expected: SCHEMA_VERSION,
            actual: value,
        });
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, SelfQueryContractError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| SelfQueryContractError::Encoding { field })
}

/// Counts compact JSON bytes without allocating the canonical preimage.
pub(crate) fn canonical_size<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<usize, SelfQueryContractError> {
    struct CountingWriter {
        written: usize,
        maximum: usize,
    }
    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.written.saturating_add(bytes.len()) > self.maximum {
                self.written = self.maximum.saturating_add(1);
                return Err(io::Error::other("canonical preimage bound"));
            }
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = CountingWriter {
        written: 0,
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| SelfQueryContractError::Bound {
        field,
        maximum,
        actual: writer.written,
    })?;
    Ok(writer.written)
}

pub(crate) fn check_canonical_size<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<(), SelfQueryContractError> {
    canonical_size(value, maximum, field).map(|_| ())
}

/// External identity of the accepted Architecture/Implementation pair.
///
/// No neutral pair DTO exists in the current foundation surface, so this
/// owner-neutral identity envelope carries only the two externally supplied
/// document digests and their acceptance lineage. It does not accept source
/// bytes or create a second normative document.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativePairBinding {
    pub architecture_digest: String,
    pub implementation_digest: String,
    pub pair_key: String,
    pub document_set: String,
    pub architecture_revision: String,
    pub implementation_revision: String,
    pub accepted_by: SourceId,
    pub acceptance_receipt: ReceiptId,
}

impl NormativePairBinding {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_digest(&self.architecture_digest, "pair.architecture_digest")?;
        check_digest(&self.implementation_digest, "pair.implementation_digest")?;
        check_id(self.document_set.as_str(), "pair.document_set")?;
        check_id(self.accepted_by.as_str(), "pair.accepted_by")?;
        check_id(self.acceptance_receipt.as_str(), "pair.acceptance_receipt")?;
        if !self.pair_key.starts_with("sha256:") || self.pair_key.len() != 71 {
            return Err(SelfQueryContractError::InvalidDigest { field: "pair_key" });
        }
        check_digest(&self.pair_key[7..], "pair_key")?;
        let mut preimage = b"eliot-normative-pair-v1\0".to_vec();
        preimage.extend_from_slice(self.architecture_digest.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(self.implementation_digest.as_bytes());
        preimage.push(0);
        if format!("sha256:{}", sha256_hex(&preimage)) != self.pair_key {
            return Err(SelfQueryContractError::DigestMismatch { field: "pair_key" });
        }
        check_text(&self.document_set, "document_set", MAX_TEXT_BYTES)?;
        check_text(&self.architecture_revision, "architecture_revision", 256)?;
        check_text(
            &self.implementation_revision,
            "implementation_revision",
            256,
        )?;
        Ok(())
    }
}

/// Lifecycle/acceptance state of a supplied Architecture source snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureSourceStatus {
    Accepted,
    Draft,
    Rejected,
    Superseded,
    Stale,
    Unavailable,
}

/// Immutable source bytes and externally supplied acceptance lineage supplied
/// to A-03. `status` and receipt fields are claims carried for an external
/// acceptance owner; for `Accepted`, `owner` and `pair.accepted_by` name the
/// same external issuer and their receipt IDs must join. This contract checks
/// consistency and never authenticates issuer authority or promotes a caller
/// flag to acceptance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureSourceSnapshot {
    pub schema_version: u32,
    pub source_handle: ArtifactId,
    pub owner: SourceId,
    pub revision: String,
    pub digest: String,
    pub status: ArchitectureSourceStatus,
    pub pair: NormativePairBinding,
    pub acceptance_receipt: Option<ReceiptId>,
    pub bytes: Vec<u8>,
    pub supersedes: Vec<ArtifactId>,
    pub invalidation: Vec<ArtifactId>,
}

impl ArchitectureSourceSnapshot {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "source.schema_version")?;
        check_id(self.source_handle.as_str(), "source.source_handle")?;
        check_id(self.owner.as_str(), "source.owner")?;
        if let Some(receipt) = &self.acceptance_receipt {
            check_id(receipt.as_str(), "source.acceptance_receipt")?;
        }
        check_text(&self.revision, "source.revision", 256)?;
        check_digest(&self.digest, "source.digest")?;
        self.pair.validate()?;
        if self.revision != self.pair.architecture_revision
            || self.digest != self.pair.architecture_digest
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "source.pair_architecture_binding",
            });
        }
        if self.bytes.len() > MAX_SOURCE_BYTES {
            return Err(SelfQueryContractError::Bound {
                field: "source.bytes",
                maximum: MAX_SOURCE_BYTES,
                actual: self.bytes.len(),
            });
        }
        if self.status == ArchitectureSourceStatus::Accepted {
            if self.bytes.is_empty() || self.acceptance_receipt.is_none() {
                return Err(SelfQueryContractError::Missing {
                    field: "source.acceptance_receipt_or_bytes",
                });
            }
            if self.acceptance_receipt.as_ref() != Some(&self.pair.acceptance_receipt) {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "source.acceptance_receipt",
                });
            }
            if self.owner != self.pair.accepted_by {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "source.acceptance_owner",
                });
            }
            if sha256_hex(&self.bytes) != self.digest {
                return Err(SelfQueryContractError::DigestMismatch {
                    field: "source.digest",
                });
            }
        } else if !self.bytes.is_empty() && sha256_hex(&self.bytes) != self.digest {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "source.digest",
            });
        }
        if self.supersedes.len() > MAX_REFS || self.invalidation.len() > MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "source.lineage_refs",
                maximum: MAX_REFS,
                actual: self.supersedes.len().max(self.invalidation.len()),
            });
        }
        let mut lineage = BTreeSet::new();
        for id in self.supersedes.iter().chain(self.invalidation.iter()) {
            check_id(id.as_str(), "source.lineage_ref")?;
            if !lineage.insert(id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "source.lineage_refs",
                });
            }
        }
        if self.supersedes.iter().any(|id| id == &self.source_handle)
            || self.invalidation.iter().any(|id| id == &self.source_handle)
        {
            return Err(SelfQueryContractError::Conflict {
                field: "source.lineage",
            });
        }
        Ok(())
    }
}

/// Closed class of Architecture material retained in a brief.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureAnchorClass {
    Intent,
    Rationale,
    Guarantee,
    HardBoundary,
    Invariant,
    Owner,
    NonGoal,
    OpenQuestion,
    Precedence,
    FailureBehavior,
}

/// Non-authoritative modality retained orthogonally to source anchor class.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureStatementModality {
    Must,
    May,
    Target,
    Empirical,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureApplicabilityState {
    Applicable,
    NotApplicable,
    Conditional,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureApplicabilityBasis {
    Structural,
    Scope,
    Type,
    Dependency,
    ExplicitOwner,
    SimilarityRejected,
}

/// Applicability is an explicit owner/input fact; it is never inferred from
/// text similarity by this contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureApplicability {
    pub state: ArchitectureApplicabilityState,
    pub basis: ArchitectureApplicabilityBasis,
    pub evidence_refs: Vec<ArtifactId>,
    pub reason: String,
}

impl ArchitectureApplicability {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_text(&self.reason, "applicability.reason", MAX_TEXT_BYTES)?;
        if self.evidence_refs.len() > MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "applicability.evidence_refs",
                maximum: MAX_REFS,
                actual: self.evidence_refs.len(),
            });
        }
        let mut evidence_refs = BTreeSet::new();
        for id in &self.evidence_refs {
            check_id(id.as_str(), "applicability.evidence_ref")?;
            if !evidence_refs.insert(id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "applicability.evidence_refs",
                });
            }
        }
        if self.state != ArchitectureApplicabilityState::Unknown && self.evidence_refs.is_empty() {
            return Err(SelfQueryContractError::Missing {
                field: "applicability.evidence_refs",
            });
        }
        Ok(())
    }
}

/// One exact byte-range anchor from the supplied source snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureAnchor {
    pub schema_version: u32,
    pub anchor_id: ArtifactId,
    pub source_handle: ArtifactId,
    pub revision: String,
    pub source_digest: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub class: ArchitectureAnchorClass,
    pub modality: ArchitectureStatementModality,
    pub text: String,
    pub applicability: ArchitectureApplicability,
    /// Referenced dependency anchor IDs (never denominator member IDs).
    pub dependency_refs: Vec<ArtifactId>,
}

impl ArchitectureAnchor {
    pub fn validate_against(
        &self,
        source: &ArchitectureSourceSnapshot,
    ) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "anchor.schema_version")?;
        check_id(self.anchor_id.as_str(), "anchor.anchor_id")?;
        check_id(self.source_handle.as_str(), "anchor.source_handle")?;
        check_text(&self.revision, "anchor.revision", 256)?;
        check_source_text(&self.text, "anchor.text", MAX_TEXT_BYTES)?;
        if self.dependency_refs.len() > MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "anchor.dependency_refs",
                maximum: MAX_REFS,
                actual: self.dependency_refs.len(),
            });
        }
        let mut dependency_refs = BTreeSet::new();
        for id in &self.dependency_refs {
            check_id(id.as_str(), "anchor.dependency_ref")?;
            if !dependency_refs.insert(id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "anchor.dependency_refs",
                });
            }
        }
        self.applicability.validate()?;
        if self.source_handle != source.source_handle
            || self.revision != source.revision
            || self.source_digest != source.digest
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "anchor.source_lineage",
            });
        }
        let start =
            usize::try_from(self.byte_start).map_err(|_| SelfQueryContractError::Range {
                field: "anchor.byte_start",
            })?;
        let end = usize::try_from(self.byte_end).map_err(|_| SelfQueryContractError::Range {
            field: "anchor.byte_end",
        })?;
        if start >= end || end > source.bytes.len() {
            return Err(SelfQueryContractError::Range {
                field: "anchor.byte_range",
            });
        }
        let excerpt = std::str::from_utf8(&source.bytes[start..end]).map_err(|_| {
            SelfQueryContractError::Range {
                field: "anchor.byte_range_utf8",
            }
        })?;
        if excerpt != self.text {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "anchor.text",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArchitectureDependencyKind {
    Interpretation,
    HardBoundary,
    GlobalBoundary,
    Precedence,
    Invalidation,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureDependencyMember {
    /// Stable member identity; dependency joins use `anchor_id` below.
    pub member_id: ArtifactId,
    /// Anchor ID in the supplied source closure.
    pub anchor_id: ArtifactId,
    pub source_handle: ArtifactId,
    pub kind: ArchitectureDependencyKind,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureDependencyDenominator {
    pub schema_version: u32,
    pub denominator_id: ArtifactId,
    pub members: Vec<ArchitectureDependencyMember>,
    pub complete: bool,
    pub digest: String,
}

impl ArchitectureDependencyDenominator {
    pub fn compute_digest(&self) -> Result<String, SelfQueryContractError> {
        if self.members.len() > MAX_DEPENDENCY_MEMBERS {
            return Err(SelfQueryContractError::Bound {
                field: "denominator.members",
                maximum: MAX_DEPENDENCY_MEMBERS,
                actual: self.members.len(),
            });
        }
        canonical_digest(
            &(
                self.schema_version,
                &self.denominator_id,
                &self.members,
                self.complete,
            ),
            "denominator.digest",
        )
    }

    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "denominator.schema_version")?;
        check_id(self.denominator_id.as_str(), "denominator.denominator_id")?;
        check_digest(&self.digest, "denominator.digest")?;
        if self.members.len() > MAX_DEPENDENCY_MEMBERS {
            return Err(SelfQueryContractError::Bound {
                field: "denominator.members",
                maximum: MAX_DEPENDENCY_MEMBERS,
                actual: self.members.len(),
            });
        }
        if self.complete && self.members.is_empty() {
            return Err(SelfQueryContractError::Missing {
                field: "denominator.members",
            });
        }
        let mut ids = BTreeSet::new();
        for member in &self.members {
            check_id(member.member_id.as_str(), "denominator.member_id")?;
            check_id(member.anchor_id.as_str(), "denominator.anchor_id")?;
            check_id(member.source_handle.as_str(), "denominator.source_handle")?;
            if !ids.insert(&member.member_id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "denominator.members",
                });
            }
        }
        if self.digest != self.compute_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "denominator.digest",
            });
        }
        Ok(())
    }
}
