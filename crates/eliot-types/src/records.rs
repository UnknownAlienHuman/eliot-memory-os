use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    pub algorithm: String,
    pub digest_hex: String,
    pub size_bytes: u64,
    pub relative_path: String,
}

pub const CANONICAL_MEMORY_SCHEMA_VERSION: &str = "eliot-canonical-memory-v1";
pub const CANONICAL_MEMORY_SEGMENT_TARGET_BYTES: usize = 24 * 1024;

/// The parent record committed only after every child segment and cue page is
/// admitted through the normal writer authority. The raw bytes remain in the
/// content-addressed blob store; this record is the durable reconstruction
/// manifest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMemoryManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub memory_handle: String,
    pub logical_kind: String,
    pub media_type: String,
    pub blob: BlobRef,
    pub segment_count: u64,
    pub segment_target_bytes: u32,
    pub segment_set_hash_blake3: String,
    pub cue_page_count: u64,
    pub cue_page_set_hash_blake3: String,
}

/// A bounded canonical child which carries semantic/indexable structure while
/// retaining an exact range into the immutable parent blob.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMemorySegment {
    pub schema_version: String,
    pub segment_id: String,
    pub parent_handle: String,
    pub logical_kind: String,
    pub blob: BlobRef,
    pub ordinal: u64,
    pub segment_count: u64,
    pub segment_set_hash_blake3: String,
    pub byte_start: u64,
    pub byte_end_exclusive: u64,
    pub segment_hash_blake3: String,
    /// Bounded semantic material for derived search. Exact reconstruction uses
    /// the blob/range/hash fields, never this text.
    pub search_text: String,
    pub preview_text: String,
}

/// Metadata-only exact-L2 expansion. It deliberately omits raw blob bytes and
/// the full search text while preserving every fact needed for verified local
/// expansion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMemorySegmentRef {
    pub segment_id: String,
    pub parent_handle: String,
    pub blob: BlobRef,
    pub ordinal: u64,
    pub segment_count: u64,
    pub segment_set_hash_blake3: String,
    pub byte_start: u64,
    pub byte_end_exclusive: u64,
    pub segment_hash_blake3: String,
    pub preview_text: String,
}

impl From<&CanonicalMemorySegment> for CanonicalMemorySegmentRef {
    fn from(segment: &CanonicalMemorySegment) -> Self {
        Self {
            segment_id: segment.segment_id.clone(),
            parent_handle: segment.parent_handle.clone(),
            blob: segment.blob.clone(),
            ordinal: segment.ordinal,
            segment_count: segment.segment_count,
            segment_set_hash_blake3: segment.segment_set_hash_blake3.clone(),
            byte_start: segment.byte_start,
            byte_end_exclusive: segment.byte_end_exclusive,
            segment_hash_blake3: segment.segment_hash_blake3.clone(),
            preview_text: segment.preview_text.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMemoryL2Page {
    pub requested_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_parent_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_segment_id: Option<String>,
    pub manifest: Option<CanonicalMemoryManifest>,
    pub segments: Vec<CanonicalMemorySegmentRef>,
    pub continuation: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub migration_id: String,
    pub checksum_blake3: String,
    pub applied: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct HealthRecord {
    pub component: String,
    pub status: String,
    pub detail: String,
}
