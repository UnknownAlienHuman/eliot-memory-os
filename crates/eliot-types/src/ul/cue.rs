use crate::{BlobRef, ProjectId, inspect_text_encoding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::normalize::{normalize_path, normalize_symbol};

/// Explicit legacy V1 cue vocabulary, frozen for migration (issue #706).
///
/// `LegacyCueKindV1` is the historical `eliot-types` cue-kind enum with its
/// closed historical variants and wire identity preserved byte-for-byte.
/// Valid historical bytes and hashes keep verifying. New code must use the
/// current A-10 vocabulary owned by `smart.cue.contracts`
/// (`eliot-cue-contracts`; revision pinned in
/// [`LegacyCueKindV1MigrationDescriptor`]).
///
/// Migration owners: #831 (internal/root consumers), #832 (context donor),
/// #833 (cues facade), #834 (memory donor). Transitional alias removal: #835.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LegacyCueKindV1 {
    FilePath,
    DirPath,
    Symbol,
    ErrorSignature,
    CommandPattern,
    Dependency,
    ApiSurface,
    TaskClass,
    Subsystem,
    Concept,
}

impl LegacyCueKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilePath => "file_path",
            Self::DirPath => "dir_path",
            Self::Symbol => "symbol",
            Self::ErrorSignature => "error_signature",
            Self::CommandPattern => "command_pattern",
            Self::Dependency => "dependency",
            Self::ApiSurface => "api_surface",
            Self::TaskClass => "task_class",
            Self::Subsystem => "subsystem",
            Self::Concept => "concept",
        }
    }
}

/// Transitional source-compatible alias for frozen consumers (issue #706).
///
/// Only frozen external consumers migrating under #831 (internal/root), #832
/// (context donor), #833 (cues facade) or #834 (memory donor) may use this
/// alias temporarily. Removal issue: #835. New code must use
/// [`LegacyCueKindV1`]. The alias adds no new wire representation or current
/// authority and is unused by `cue.rs` production code.
#[deprecated(
    note = "transitional V1 alias for frozen consumers migrating under #831 (internal/root), #832 (context donor), #833 (cues facade), #834 (memory donor); removal issue #835; new code must use LegacyCueKindV1"
)]
pub type CueKind = LegacyCueKindV1;

/// Inert bounded V1 to A-10 migration descriptor (issue #706).
///
/// Descriptive data only. This lower-level crate neither imports nor constructs
/// the A-10 current vocabulary: equal spelling alone is not semantic or
/// current-type equivalence, and ambiguous, unknown, empty, or legacy-only
/// input must never silently become current. Any change to the pinned target
/// revision or digest invalidates this descriptor; revalidate against
/// `smart.cue.contracts` before any migration use.
pub struct LegacyCueKindV1MigrationDescriptor {
    _sealed: (),
}

impl LegacyCueKindV1MigrationDescriptor {
    /// Exact source schema frozen by this seam.
    pub const SOURCE_SCHEMA: &str = "eliot-types.ul.cue.LegacyCueKindV1";
    /// Source schema generation. Only `v1` is valid in this type.
    pub const SOURCE_GENERATION: &str = "v1";
    /// Base commit whose bytes this seam froze.
    pub const SOURCE_BASE_SHA: &str = "e80611de30878aa6ab521418da23bbfe4570af13";
    /// Owning issue of this legacy seam.
    pub const SOURCE_SEAM_ISSUE: u32 = 706;
    /// Current vocabulary owner module.
    pub const TARGET_MODULE: &str = "smart.cue.contracts";
    /// Current vocabulary owner crate.
    pub const TARGET_CRATE: &str = "eliot-cue-contracts";
    /// Pinned target file carrying the current `CueKind` definition.
    pub const TARGET_FILE: &str = "crates/smart/eliot-cue-contracts/src/normalization.rs";
    /// Pinned target contract revision (`CONTRACT_REVISION` on the base SHA).
    pub const TARGET_REVISION: &str = "2.0.0";
    /// Digest algorithm for [`Self::TARGET_DIGEST`].
    pub const TARGET_DIGEST_ALGO: &str = "blake3";
    /// Pinned digest of the target file on the base SHA. Any change
    /// invalidates this descriptor.
    pub const TARGET_DIGEST: &str =
        "a5412833fde7b3cb1e214774061d04e21ab6773870180ffeff5959a8242ff850";
    /// Exact historical variant count.
    pub const VARIANT_COUNT: usize = 10;
    /// Exact historical wire spellings in variant order.
    pub const WIRE_SPELLINGS: [&str; 10] = [
        "file_path",
        "dir_path",
        "symbol",
        "error_signature",
        "command_pattern",
        "dependency",
        "api_surface",
        "task_class",
        "subsystem",
        "concept",
    ];
    /// Exact safe correspondences as `(v1_spelling, current_spelling)` pairs.
    /// Every safe correspondence is byte-exact; anything else is unsupported.
    pub const EXACT_CORRESPONDENCES: [(&str, &str); 10] = [
        ("file_path", "file_path"),
        ("dir_path", "dir_path"),
        ("symbol", "symbol"),
        ("error_signature", "error_signature"),
        ("command_pattern", "command_pattern"),
        ("dependency", "dependency"),
        ("api_surface", "api_surface"),
        ("task_class", "task_class"),
        ("subsystem", "subsystem"),
        ("concept", "concept"),
    ];
    /// Inputs that must never claim conversion to current.
    pub const UNSUPPORTED_INPUTS: [&str; 12] = [
        "",
        "unknown",
        "FilePath",
        "FILE_PATH",
        "file-path",
        "file path",
        "cue",
        "null",
        "relation_edge",
        "snapshot_member",
        "comparison_key",
        "none",
    ];
    /// Frozen denominator manifest bound to this seam.
    pub const MANIFEST: &str = "crates/eliot-types/tests/data/cue_kind_migration.toml";
    /// Raw and golden fixtures bound to this seam.
    pub const FIXTURE_DIR: &str = "crates/eliot-types/tests/data/cue-kind-legacy";
    /// Boundary oracle proving this seam.
    pub const ORACLE: &str = "crates/eliot-types/tests/cue_kind_legacy_boundary.rs";
    /// Invalidation rule for this descriptor.
    pub const INVALIDATION: &str = "any change to the pinned target revision or digest, or to the frozen variant/spelling/serialization rows, invalidates this descriptor; revalidate against smart.cue.contracts before migration use";
    /// Limited proof bound to this descriptor.
    pub const PROOF: &str = "cue_kind_legacy_boundary 35 WORK_UNIT_CASE 706/1..35 over frozen source, wire, golden, consumer, duplicate and oracle rows";
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CueMatchMode {
    Exact,
    Prefix,
    Signature,
}

impl CueMatchMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Signature => "signature",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CueStrength {
    Primary,
    Secondary,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CueBinding {
    pub cue_kind: LegacyCueKindV1,
    pub cue_value: String,
    pub match_mode: CueMatchMode,
    pub strength: CueStrength,
    /// Optional reuse guidance. Legacy v1 strings deserialize as `Some`;
    /// `None` is emitted only by the capture-first optional-note domain.
    #[serde(default)]
    pub expected_reuse_note: Option<String>,
}

pub const MAX_CUE_BINDINGS_PER_PAGE: usize = 12;
pub const MAX_CUE_BINDING_PAGE_BYTES: usize = 96 * 1024;
pub const CUE_BINDING_PAGE_SCHEMA_VERSION_V1: &str = "eliot-cue-binding-page-v1";
pub const CUE_BINDING_PAGE_SCHEMA_VERSION_V2: &str = "eliot-cue-binding-page-v2";

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CueBindingPage {
    pub schema_version: String,
    pub page_id: String,
    pub parent_handle: String,
    pub blob: BlobRef,
    pub page_ordinal: u64,
    pub page_count: u64,
    pub page_set_hash_blake3: String,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CueBindingError {
    #[error("cue binding collection must contain 1..=12 entries")]
    InvalidCount,
    #[error("cue binding collection must contain at least one primary binding")]
    MissingPrimary,
    #[error("expected_reuse_note must be non-blank when supplied")]
    InvalidReuseNote,
    #[error("cue_value is empty")]
    EmptyValue,
    #[error("cue_value failed the shared encoding guard")]
    InvalidEncoding,
    #[error("cue match mode is invalid for {0}")]
    InvalidMatchMode(&'static str),
    #[error("error signature must be sig: followed by 64 lowercase hex characters")]
    InvalidSignature,
    #[error("cue binding page parent handle is empty or too large")]
    InvalidParentHandle,
    #[error("cue binding page blob digest must be 64 lowercase hex characters")]
    InvalidBlobDigest,
    #[error(
        "one cue binding requires {actual_bytes} transport bytes; the page limit is {limit_bytes}"
    )]
    OversizedBinding {
        actual_bytes: usize,
        limit_bytes: usize,
    },
}

fn unicode_lower(raw: &str) -> String {
    raw.chars().flat_map(char::to_lowercase).collect()
}

pub fn normalize_binding(
    mut binding: CueBinding,
    project_root: Option<&str>,
) -> Result<CueBinding, CueBindingError> {
    if binding
        .expected_reuse_note
        .as_deref()
        .is_some_and(|note| note.trim().is_empty())
    {
        return Err(CueBindingError::InvalidReuseNote);
    }
    if !inspect_text_encoding(&json!(binding.cue_value)).is_empty() {
        return Err(CueBindingError::InvalidEncoding);
    }
    binding.cue_value = match binding.cue_kind {
        LegacyCueKindV1::FilePath => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("file_path"));
            }
            normalize_path(&binding.cue_value, project_root)
        }
        LegacyCueKindV1::DirPath => {
            if binding.match_mode != CueMatchMode::Prefix {
                return Err(CueBindingError::InvalidMatchMode("dir_path"));
            }
            normalize_path(&binding.cue_value, project_root)
        }
        LegacyCueKindV1::Symbol => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("symbol"));
            }
            normalize_symbol(&binding.cue_value)
        }
        LegacyCueKindV1::ErrorSignature => {
            if binding.match_mode != CueMatchMode::Signature
                || binding.cue_value.len() != 68
                || !binding.cue_value.starts_with("sig:")
                || !binding.cue_value[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CueBindingError::InvalidSignature);
            }
            binding.cue_value
        }
        LegacyCueKindV1::CommandPattern => {
            if binding.match_mode != CueMatchMode::Exact {
                return Err(CueBindingError::InvalidMatchMode("command_pattern"));
            }
            unicode_lower(binding.cue_value.trim())
        }
        LegacyCueKindV1::Dependency
        | LegacyCueKindV1::ApiSurface
        | LegacyCueKindV1::TaskClass
        | LegacyCueKindV1::Subsystem
        | LegacyCueKindV1::Concept => unicode_lower(binding.cue_value.trim()),
    };
    if binding.cue_value.is_empty() {
        return Err(CueBindingError::EmptyValue);
    }
    Ok(binding)
}

pub fn normalize_bindings(
    bindings: Vec<CueBinding>,
    project_root: Option<&str>,
) -> Result<Vec<CueBinding>, CueBindingError> {
    if bindings.is_empty() || bindings.len() > 12 {
        return Err(CueBindingError::InvalidCount);
    }
    let mut normalized = BTreeMap::new();
    for binding in bindings {
        let binding = normalize_binding(binding, project_root)?;
        let key = (
            binding.cue_kind,
            binding.cue_value.clone(),
            binding.match_mode,
        );
        normalized
            .entry(key)
            .and_modify(|current: &mut CueBinding| {
                if binding.strength == CueStrength::Primary {
                    *current = binding.clone();
                }
            })
            .or_insert(binding);
    }
    let bindings = normalized.into_values().collect::<Vec<_>>();
    if !bindings
        .iter()
        .any(|binding| binding.strength == CueStrength::Primary)
    {
        return Err(CueBindingError::MissingPrimary);
    }
    Ok(bindings)
}

/// Normalizes and deduplicates an arbitrarily large logical cue collection,
/// then emits deterministic bounded pages. The existing inline validator stays
/// capped at twelve; callers use these pages for overflow instead of dropping
/// valuable bindings.
#[allow(clippy::too_many_lines)]
pub fn normalize_binding_pages(
    parent_handle: &str,
    blob: &BlobRef,
    bindings: Vec<CueBinding>,
    project_root: Option<&str>,
) -> Result<Vec<CueBindingPage>, CueBindingError> {
    let parent_handle = parent_handle.trim();
    if parent_handle.is_empty() || parent_handle.len() > 512 {
        return Err(CueBindingError::InvalidParentHandle);
    }
    if blob.algorithm != "blake3"
        || blob.digest_hex.len() != 64
        || !blob
            .digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CueBindingError::InvalidBlobDigest);
    }
    if bindings.is_empty() {
        return Ok(Vec::new());
    }

    let mut normalized = BTreeMap::new();
    for binding in bindings {
        let binding = normalize_binding(binding, project_root)?;
        let key = (
            binding.cue_kind,
            binding.cue_value.clone(),
            binding.match_mode,
        );
        normalized
            .entry(key)
            .and_modify(|current: &mut CueBinding| {
                if binding.strength == CueStrength::Primary {
                    *current = binding.clone();
                }
            })
            .or_insert(binding);
    }
    let bindings = normalized.into_values().collect::<Vec<_>>();
    if !bindings
        .iter()
        .any(|binding| binding.strength == CueStrength::Primary)
    {
        return Err(CueBindingError::MissingPrimary);
    }

    let mut partitions = Vec::<Vec<CueBinding>>::new();
    let mut current = Vec::new();
    for binding in bindings {
        let mut candidate = current.clone();
        candidate.push(binding.clone());
        let candidate_bytes = cue_binding_page_transport_bytes(parent_handle, blob, &candidate);
        if candidate.len() <= MAX_CUE_BINDINGS_PER_PAGE
            && candidate_bytes <= MAX_CUE_BINDING_PAGE_BYTES
        {
            current = candidate;
            continue;
        }
        if current.is_empty() {
            return Err(CueBindingError::OversizedBinding {
                actual_bytes: candidate_bytes,
                limit_bytes: MAX_CUE_BINDING_PAGE_BYTES,
            });
        }
        partitions.push(std::mem::take(&mut current));
        let single = vec![binding];
        let single_bytes = cue_binding_page_transport_bytes(parent_handle, blob, &single);
        if single_bytes > MAX_CUE_BINDING_PAGE_BYTES {
            return Err(CueBindingError::OversizedBinding {
                actual_bytes: single_bytes,
                limit_bytes: MAX_CUE_BINDING_PAGE_BYTES,
            });
        }
        current = single;
    }
    if !current.is_empty() {
        partitions.push(current);
    }

    let page_count = u64::try_from(partitions.len()).map_err(|_| CueBindingError::InvalidCount)?;
    let mut pages = partitions
        .into_iter()
        .enumerate()
        .map(|(page_ordinal, page_bindings)| {
            let page_ordinal =
                u64::try_from(page_ordinal).map_err(|_| CueBindingError::InvalidCount)?;
            let page_schema_version = if page_bindings
                .iter()
                .any(|binding| binding.expected_reuse_note.is_none())
            {
                CUE_BINDING_PAGE_SCHEMA_VERSION_V2
            } else {
                CUE_BINDING_PAGE_SCHEMA_VERSION_V1
            };
            Ok(CueBindingPage {
                schema_version: page_schema_version.to_owned(),
                page_id: cue_binding_page_id(parent_handle, blob, page_ordinal, &page_bindings),
                parent_handle: parent_handle.to_owned(),
                blob: blob.clone(),
                page_ordinal,
                page_count,
                page_set_hash_blake3: String::new(),
                cue_bindings: page_bindings,
            })
        })
        .collect::<Result<Vec<_>, CueBindingError>>()?;
    let page_set_hash_blake3 = cue_binding_page_set_hash(&pages);
    for page in &mut pages {
        page.page_set_hash_blake3.clone_from(&page_set_hash_blake3);
    }
    Ok(pages)
}

fn cue_binding_page_transport_bytes(
    parent_handle: &str,
    blob: &BlobRef,
    bindings: &[CueBinding],
) -> usize {
    let schema_version = if bindings
        .iter()
        .any(|binding| binding.expected_reuse_note.is_none())
    {
        CUE_BINDING_PAGE_SCHEMA_VERSION_V2
    } else {
        CUE_BINDING_PAGE_SCHEMA_VERSION_V1
    };
    serde_json::to_vec(&CueBindingPage {
        schema_version: schema_version.to_owned(),
        page_id: format!("cue-page:{}", "f".repeat(64)),
        parent_handle: parent_handle.to_owned(),
        blob: blob.clone(),
        page_ordinal: u64::MAX,
        page_count: u64::MAX,
        page_set_hash_blake3: "f".repeat(64),
        cue_bindings: bindings.to_vec(),
    })
    .map_or(usize::MAX, |bytes| bytes.len())
}

#[must_use]
pub fn cue_binding_page_id(
    parent_handle: &str,
    blob: &BlobRef,
    page_ordinal: u64,
    bindings: &[CueBinding],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(parent_handle.as_bytes());
    hasher.update(blob.algorithm.as_bytes());
    hasher.update(blob.digest_hex.as_bytes());
    hasher.update(&blob.size_bytes.to_le_bytes());
    hasher.update(blob.relative_path.as_bytes());
    hasher.update(&page_ordinal.to_le_bytes());
    let optional_note_domain = bindings
        .iter()
        .any(|binding| binding.expected_reuse_note.is_none());
    if optional_note_domain {
        hasher.update(b"eliot-cue-binding-page-v2");
    }
    for binding in bindings {
        hasher.update(binding.cue_kind.as_str().as_bytes());
        hasher.update(binding.cue_value.as_bytes());
        hasher.update(binding.match_mode.as_str().as_bytes());
        hasher.update(match binding.strength {
            CueStrength::Primary => b"primary",
            CueStrength::Secondary => b"secondary",
        });
        if optional_note_domain {
            match &binding.expected_reuse_note {
                Some(note) => {
                    hasher.update(b"some:");
                    hasher.update(note.as_bytes());
                }
                None => {
                    hasher.update(b"none");
                }
            }
        } else {
            // Keep the historical v1 Some(note) hash material byte-identical.
            if let Some(note) = &binding.expected_reuse_note {
                hasher.update(note.as_bytes());
            }
        }
    }
    format!("cue-page:{}", hasher.finalize().to_hex())
}

#[must_use]
pub fn cue_binding_page_set_hash(pages: &[CueBindingPage]) -> String {
    let mut ordered = pages.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|page| page.page_ordinal);
    let mut hasher = blake3::Hasher::new();
    for page in ordered {
        hasher.update(page.page_id.as_bytes());
        hasher.update(&page.page_ordinal.to_le_bytes());
        hasher.update(&page.page_count.to_le_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CueIndexRow {
    pub row_id: String,
    pub project_id: ProjectId,
    pub cue_kind: LegacyCueKindV1,
    pub cue_value_norm: String,
    pub match_mode: CueMatchMode,
    pub record_ref: String,
    pub record_kind: String,
    pub strength: CueStrength,
    pub negative_memory: bool,
    pub lifecycle: String,
    pub token_estimate: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CueRecordSource {
    pub record_ref: String,
    pub record_kind: String,
    pub preview_text: String,
    #[serde(default)]
    pub payload: Option<Value>,
    pub cue_bindings: Vec<CueBinding>,
    pub negative_memory: bool,
    pub lifecycle: String,
}

#[must_use]
pub fn cue_row_id(
    project_id: ProjectId,
    cue_kind: LegacyCueKindV1,
    match_mode: CueMatchMode,
    cue_value: &str,
    record_ref: &str,
) -> String {
    let input = format!(
        "{project_id}|{}|{}|{cue_value}|{record_ref}",
        cue_kind.as_str(),
        match_mode.as_str()
    );
    let digest = blake3::hash(input.as_bytes()).to_hex().to_string();
    format!("cue:{}", &digest[..32])
}

#[must_use]
#[allow(clippy::manual_div_ceil)] // Task 03 fixes this exact conservative estimate formula.
pub fn ul_token_estimate(text: &str) -> u32 {
    (u32::try_from(text.len()).unwrap_or(u32::MAX) + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::{
        CueBinding, CueBindingError, CueMatchMode, CueStrength, LegacyCueKindV1,
        MAX_CUE_BINDING_PAGE_BYTES, cue_row_id, normalize_binding_pages,
    };

    #[test]
    fn cue_capacity_twenty_nine_are_preserved_as_twelve_twelve_five() -> Result<(), CueBindingError>
    {
        let bindings = (0..29)
            .map(|index| CueBinding {
                cue_kind: LegacyCueKindV1::Concept,
                cue_value: format!("concept-{index:02}"),
                match_mode: CueMatchMode::Exact,
                strength: if index == 0 {
                    CueStrength::Primary
                } else {
                    CueStrength::Secondary
                },
                expected_reuse_note: Some("capacity paging test".to_owned()),
            })
            .collect();
        let pages = normalize_binding_pages(
            "memory:capacity-test",
            &crate::BlobRef {
                algorithm: "blake3".to_owned(),
                digest_hex: "a".repeat(64),
                size_bytes: 29,
                relative_path: format!("aa/{}.blob", "a".repeat(62)),
            },
            bindings,
            None,
        )?;

        assert_eq!(
            pages
                .iter()
                .map(|page| page.cue_bindings.len())
                .collect::<Vec<_>>(),
            [12, 12, 5]
        );
        assert!(pages.iter().all(|page| {
            page.parent_handle == "memory:capacity-test"
                && page.page_count == 3
                && page.cue_bindings.len() <= 12
        }));
        assert_eq!(
            pages
                .iter()
                .flat_map(|page| page.cue_bindings.iter())
                .count(),
            29
        );
        Ok(())
    }

    #[test]
    fn cue_capacity_pages_are_transport_bounded_and_oversized_binding_fails()
    -> Result<(), CueBindingError> {
        let blob = crate::BlobRef {
            algorithm: "blake3".to_owned(),
            digest_hex: "b".repeat(64),
            size_bytes: 120_000,
            relative_path: format!("bb/{}.blob", "b".repeat(62)),
        };
        let bindings = [true, false]
            .into_iter()
            .map(|primary| CueBinding {
                cue_kind: LegacyCueKindV1::Concept,
                cue_value: if primary {
                    format!("primary-{}", "x".repeat(60_000))
                } else {
                    format!("secondary-{}", "y".repeat(60_000))
                },
                match_mode: CueMatchMode::Exact,
                strength: if primary {
                    CueStrength::Primary
                } else {
                    CueStrength::Secondary
                },
                expected_reuse_note: Some("transport bound".to_owned()),
            })
            .collect();
        let pages = normalize_binding_pages("memory:byte-bound", &blob, bindings, None)?;
        assert_eq!(pages.len(), 2);
        assert!(pages.iter().all(|page| {
            serde_json::to_vec(page)
                .is_ok_and(|encoded| encoded.len() <= MAX_CUE_BINDING_PAGE_BYTES)
        }));

        let oversized = vec![CueBinding {
            cue_kind: LegacyCueKindV1::Concept,
            cue_value: format!("too-large-{}", "z".repeat(MAX_CUE_BINDING_PAGE_BYTES)),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: Some("must fail explicitly".to_owned()),
        }];
        assert!(matches!(
            normalize_binding_pages("memory:oversized", &blob, oversized, None),
            Err(CueBindingError::OversizedBinding { .. })
        ));
        Ok(())
    }

    #[test]
    fn cue_capacity_row_identity_includes_match_mode() {
        let project_id = crate::ProjectId::new_v7();
        let exact = cue_row_id(
            project_id,
            LegacyCueKindV1::Concept,
            CueMatchMode::Exact,
            "capacity",
            "memory:one",
        );
        let prefix = cue_row_id(
            project_id,
            LegacyCueKindV1::Concept,
            CueMatchMode::Prefix,
            "capacity",
            "memory:one",
        );
        assert_ne!(exact, prefix);
    }
}
