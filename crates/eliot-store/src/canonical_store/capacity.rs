//! Canonical capacity validation/projection cell.
//!
//! Owns the canonical capacity validation and projection primitives extracted
//! from `crates/eliot-store/src/canonical_store.rs`: `capacity_manifests`,
//! `validate_capacity_receipt`, `strongest_retention`, `is_blake3_hex`, and
//! `is_lower_blake3_hex` (parent-required `pub(super)` seams) plus the
//! child-only private helpers `validate_capacity_blob_ref` and
//! `capacity_segment_id`. Validates `CanonicalMemoryManifest`,
//! `CanonicalMemorySegment`, and `CueBindingPage` receipts including
//! `blake3` content addressing (`digest_hex` 64 lower-hex, `relative_path`
//! `{xx}/{rest}.blob`), schema versions
//! (`CANONICAL_MEMORY_SCHEMA_VERSION`, `CUE_BINDING_PAGE_SCHEMA_VERSION_V1/V2`),
//! and deterministic IDs (`memory-segment:*` via `blake3::Hasher`,
//! `cue_binding_page_id`). No recall ranking, replay view, L2 selector,
//! FTS/search, canonical write ownership, atomic-write, or test-only topology
//! lives here.
//!
//! Architecture: P.6 canonical Store — capacity validation/projection boundary;
//! A13.8 Integrity — content-addressed blob receipt validation; parent
//! `canonical_store` retains the store, receipt, and transport boundary.
//! Implementation: I2.23 — extracted capacity module owns only its
//! validation/projection cell; parent remains the sole write/receipt
//! authority. Mechanical split from
//! `crates/eliot-store/src/canonical_store.rs` — behavior preserved.
//! Forbidden: capacity validation/projection only, no recall ranking,
//! replay/integrity view, L2/FTS/search, canonical write ownership, or
//! migration — no new dependencies or broad re-exports.

use crate::StoreError;
use eliot_types::{
    BlobRef, BlobRetentionClass, CanonicalMemoryManifest, CanonicalMemorySegment, CueBindingPage,
    MemoryWriteEnvelope,
};
use serde_json::Value;

pub(super) fn capacity_manifests(
    envelope: &MemoryWriteEnvelope,
) -> Result<Vec<CanonicalMemoryManifest>, StoreError> {
    envelope
        .tool_observations
        .iter()
        .filter(|observation| {
            observation
                .payload
                .get("receipt_kind")
                .and_then(Value::as_str)
                == Some("memory_blob_manifest")
        })
        .map(|observation| {
            let body = observation.payload.get("receipt_body").ok_or_else(|| {
                StoreError::Decode("capacity manifest omitted receipt_body".to_owned())
            })?;
            serde_json::from_value(body.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))
        })
        .collect()
}

pub(super) fn validate_capacity_receipt(
    receipt_kind: Option<&str>,
    body: &Value,
) -> Result<(), StoreError> {
    match receipt_kind {
        Some("memory_blob_manifest") => {
            let manifest: CanonicalMemoryManifest = serde_json::from_value(body.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            if manifest.schema_version != eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION
                || manifest.memory_handle.trim().is_empty()
                || manifest.memory_handle.len() > 512
                || manifest.logical_kind.trim().is_empty()
                || manifest.media_type.trim().is_empty()
                || manifest.segment_count == 0
                || usize::try_from(manifest.segment_target_bytes).ok()
                    != Some(eliot_types::CANONICAL_MEMORY_SEGMENT_TARGET_BYTES)
                || !is_lower_blake3_hex(&manifest.segment_set_hash_blake3)
                || !is_lower_blake3_hex(&manifest.cue_page_set_hash_blake3)
            {
                return Err(StoreError::PolicyViolation(
                    "canonical memory manifest failed typed validation".to_owned(),
                ));
            }
            validate_capacity_blob_ref(&manifest.blob)?;
        }
        Some("memory_blob_segment") => {
            let segment: CanonicalMemorySegment = serde_json::from_value(body.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            validate_capacity_blob_ref(&segment.blob)?;
            let range_len = segment
                .byte_end_exclusive
                .checked_sub(segment.byte_start)
                .ok_or_else(|| {
                    StoreError::PolicyViolation(
                        "canonical memory segment range is reversed".to_owned(),
                    )
                })?;
            let expected_id = capacity_segment_id(&segment);
            if segment.schema_version != eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION
                || segment.parent_handle.trim().is_empty()
                || segment.parent_handle.len() > 512
                || segment.logical_kind.trim().is_empty()
                || segment.segment_count == 0
                || segment.ordinal >= segment.segment_count
                || !is_lower_blake3_hex(&segment.segment_set_hash_blake3)
                || segment.byte_end_exclusive > segment.blob.size_bytes
                || range_len
                    > u64::try_from(eliot_types::CANONICAL_MEMORY_SEGMENT_TARGET_BYTES)
                        .unwrap_or(u64::MAX)
                || segment.search_text.len() > eliot_types::CANONICAL_MEMORY_SEGMENT_TARGET_BYTES
                || segment.preview_text.len() > eliot_types::CANONICAL_MEMORY_SEGMENT_TARGET_BYTES
                || !is_lower_blake3_hex(&segment.segment_hash_blake3)
                || segment.segment_id != expected_id
            {
                return Err(StoreError::PolicyViolation(
                    "canonical memory segment failed typed validation".to_owned(),
                ));
            }
        }
        Some("cue_binding_page") => {
            let page: CueBindingPage = serde_json::from_value(body.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            validate_capacity_blob_ref(&page.blob)?;
            let has_none_note = page
                .cue_bindings
                .iter()
                .any(|binding| binding.expected_reuse_note.is_none());
            let schema_matches_note_domain = (page.schema_version
                == eliot_types::CUE_BINDING_PAGE_SCHEMA_VERSION_V1
                && !has_none_note)
                || (page.schema_version == eliot_types::CUE_BINDING_PAGE_SCHEMA_VERSION_V2
                    && has_none_note);
            if !(page.schema_version == eliot_types::CUE_BINDING_PAGE_SCHEMA_VERSION_V1
                || page.schema_version == eliot_types::CUE_BINDING_PAGE_SCHEMA_VERSION_V2)
                || !schema_matches_note_domain
                || page.parent_handle.trim().is_empty()
                || page.parent_handle.len() > 512
                || page.page_count == 0
                || page.page_ordinal >= page.page_count
                || !is_lower_blake3_hex(&page.page_set_hash_blake3)
                || page.cue_bindings.is_empty()
                || page.cue_bindings.len() > eliot_types::MAX_CUE_BINDINGS_PER_PAGE
                || page.page_id
                    != eliot_types::cue_binding_page_id(
                        &page.parent_handle,
                        &page.blob,
                        page.page_ordinal,
                        &page.cue_bindings,
                    )
            {
                return Err(StoreError::PolicyViolation(
                    "canonical cue binding page failed typed validation".to_owned(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_capacity_blob_ref(blob: &BlobRef) -> Result<(), StoreError> {
    if blob.algorithm != "blake3" || !is_lower_blake3_hex(&blob.digest_hex) {
        return Err(StoreError::PolicyViolation(
            "canonical memory blob reference failed algorithm/digest validation".to_owned(),
        ));
    }
    let expected_path = format!("{}/{}.blob", &blob.digest_hex[..2], &blob.digest_hex[2..]);
    if blob.relative_path.replace('\\', "/") != expected_path {
        return Err(StoreError::PolicyViolation(
            "canonical memory blob reference is not content-addressed".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn strongest_retention(
    left: Option<BlobRetentionClass>,
    right: Option<BlobRetentionClass>,
) -> Option<BlobRetentionClass> {
    [left, right]
        .into_iter()
        .flatten()
        .max_by_key(|class| match class {
            BlobRetentionClass::Standard => 0,
            BlobRetentionClass::AuditRetained => 1,
            BlobRetentionClass::LegalHold => 2,
        })
}

pub(super) fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn is_lower_blake3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn capacity_segment_id(segment: &CanonicalMemorySegment) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(segment.parent_handle.as_bytes());
    hasher.update(segment.blob.digest_hex.as_bytes());
    hasher.update(&segment.ordinal.to_le_bytes());
    hasher.update(&segment.byte_start.to_le_bytes());
    hasher.update(&segment.byte_end_exclusive.to_le_bytes());
    hasher.update(segment.segment_hash_blake3.as_bytes());
    format!("memory-segment:{}", hasher.finalize().to_hex())
}
