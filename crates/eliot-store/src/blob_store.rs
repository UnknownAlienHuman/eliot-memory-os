use crate::StoreError;
use eliot_types::secret_boundary::MAX_SECRET_BOUNDARY_BYTES;
use eliot_types::{
    BlobRef, BlobStoreConfig, CANONICAL_MEMORY_SCHEMA_VERSION,
    CANONICAL_MEMORY_SEGMENT_TARGET_BYTES, CanonicalMemoryManifest, CanonicalMemorySegment,
    CommandContext, CueBinding, CueBindingPage, MAX_CUE_BINDING_PAGE_BYTES,
    MAX_CUE_BINDINGS_PER_PAGE, SemanticCommand, ToolObservationRecordCommand, WriteId,
    cue_binding_page_id, cue_binding_page_set_hash, inspect_secret_bytes, normalize_binding_pages,
};
use serde_json::Value;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMemoryStagedRecord {
    Segment(CanonicalMemorySegment),
    CuePage(CueBindingPage),
    Manifest(CanonicalMemoryManifest),
}

impl CanonicalMemoryStagedRecord {
    #[must_use]
    pub const fn receipt_kind(&self) -> &'static str {
        match self {
            Self::Segment(_) => "memory_blob_segment",
            Self::CuePage(_) => "cue_binding_page",
            Self::Manifest(_) => "memory_blob_manifest",
        }
    }

    #[must_use]
    pub fn record_id(&self) -> &str {
        match self {
            Self::Segment(value) => &value.segment_id,
            Self::CuePage(value) => &value.page_id,
            Self::Manifest(value) => &value.manifest_id,
        }
    }

    pub fn receipt_body(&self) -> Result<Value, StoreError> {
        match self {
            Self::Segment(value) => serde_json::to_value(value),
            Self::CuePage(value) => serde_json::to_value(value),
            Self::Manifest(value) => serde_json::to_value(value),
        }
        .map_err(|error| StoreError::Decode(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalMemoryWritePlan {
    pub segments: Vec<CanonicalMemorySegment>,
    pub cue_pages: Vec<CueBindingPage>,
    pub manifest: CanonicalMemoryManifest,
}

pub const CANONICAL_MEMORY_TRANSPORT_MAX_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug)]
pub struct CanonicalMemoryIngressPlan {
    pub write_plan: CanonicalMemoryWritePlan,
    pub commands_in_commit_order: Vec<SemanticCommand>,
}

impl CanonicalMemoryWritePlan {
    /// Child records are always returned before the admitting parent. Callers
    /// submit each bounded record through the existing semantic writer in this
    /// order; a failed sequence therefore leaves only unreachable children.
    #[must_use]
    pub fn records_in_commit_order(&self) -> Vec<CanonicalMemoryStagedRecord> {
        self.segments
            .iter()
            .cloned()
            .map(CanonicalMemoryStagedRecord::Segment)
            .chain(
                self.cue_pages
                    .iter()
                    .cloned()
                    .map(CanonicalMemoryStagedRecord::CuePage),
            )
            .chain(std::iter::once(CanonicalMemoryStagedRecord::Manifest(
                self.manifest.clone(),
            )))
            .collect()
    }

    pub fn semantic_commands_in_commit_order(
        &self,
        context: &CommandContext,
    ) -> Result<Vec<SemanticCommand>, StoreError> {
        let records = self.records_in_commit_order();
        let record_count = records.len();
        records
            .into_iter()
            .enumerate()
            .map(|(index, record)| {
                let mut record_context = context.clone();
                record_context.write_id = if index + 1 == record_count {
                    context.write_id
                } else {
                    WriteId::new_v7()
                };
                let receipt_kind = record.receipt_kind();
                let record_id = record.record_id().to_owned();
                let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
                    context: record_context,
                    tool_name: "eliot_canonical_memory_ingress".to_owned(),
                    observation: format!("canonical memory {receipt_kind} {record_id}"),
                    payload: serde_json::json!({
                        "receipt_kind": receipt_kind,
                        "receipt_body": record.receipt_body()?,
                    }),
                });
                let transport_bytes = serde_json::to_vec(&command)
                    .map_err(|error| StoreError::Decode(error.to_string()))?
                    .len();
                if transport_bytes > CANONICAL_MEMORY_TRANSPORT_MAX_BYTES {
                    return Err(StoreError::PolicyViolation(format!(
                        "canonical memory child {record_id} requires {transport_bytes} transport bytes; limit is {CANONICAL_MEMORY_TRANSPORT_MAX_BYTES}"
                    )));
                }
                Ok(command)
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(config: &BlobStoreConfig) -> Result<Self, StoreError> {
        let root = PathBuf::from(&config.root);
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root: std::fs::canonicalize(root)?,
        })
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<BlobRef, StoreError> {
        inspect_blob_secret_bytes(bytes)?;
        let digest_hex = blake3::hash(bytes).to_hex().to_string();
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| StoreError::BlobTooLarge)?;
        let (prefix, suffix) = digest_hex.split_at(2);
        let relative_path = format!("{prefix}/{suffix}.blob");
        let path = self.root.join(Path::new(&relative_path));

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let blob = BlobRef {
            algorithm: "blake3".to_owned(),
            digest_hex,
            size_bytes,
            relative_path,
        };
        if path.exists() {
            self.read_verified(&blob)?;
            return Ok(blob);
        }

        let temp_path =
            path.with_extension(format!("blob-stage-{}", uuid::Uuid::new_v4().as_simple()));
        let write_result = (|| -> Result<(), std::io::Error> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp_path, &path)
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temp_path);
            if path.exists() {
                self.read_verified(&blob)?;
                return Ok(blob);
            }
            return Err(error.into());
        }
        self.read_verified(&blob)?;
        Ok(blob)
    }

    pub fn blob_path(&self, blob: &BlobRef) -> PathBuf {
        self.root.join(Path::new(&blob.relative_path))
    }

    /// Reads a content-addressed blob only after validating its algorithm,
    /// canonical relative path, root containment, size, and digest.
    pub fn read_verified(&self, blob: &BlobRef) -> Result<Vec<u8>, StoreError> {
        validate_blob_ref(blob)?;
        let expected_path = expected_blob_relative_path(&blob.digest_hex);
        let path = self.root.join(&expected_path);
        let canonical_path = std::fs::canonicalize(&path)?;
        if !canonical_path.starts_with(&self.root) {
            return Err(StoreError::PolicyViolation(
                "blob path escaped the configured content-addressed root".to_owned(),
            ));
        }
        let bytes = std::fs::read(&canonical_path)?;
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| StoreError::BlobTooLarge)?;
        if size_bytes != blob.size_bytes {
            return Err(invalid_blob(format!(
                "blob size mismatch: expected {}, found {size_bytes}",
                blob.size_bytes
            )));
        }
        let digest_hex = blake3::hash(&bytes).to_hex().to_string();
        if digest_hex != blob.digest_hex {
            return Err(invalid_blob("blob digest mismatch"));
        }
        Ok(bytes)
    }

    pub fn read_verified_segment(
        &self,
        segment: &eliot_types::CanonicalMemorySegmentRef,
    ) -> Result<Vec<u8>, StoreError> {
        let bytes = self.read_verified(&segment.blob)?;
        let start = usize::try_from(segment.byte_start)
            .map_err(|_| invalid_blob("canonical memory segment start overflow"))?;
        let end = usize::try_from(segment.byte_end_exclusive)
            .map_err(|_| invalid_blob("canonical memory segment end overflow"))?;
        if end < start || end > bytes.len() {
            return Err(invalid_blob("canonical memory segment range is invalid"));
        }
        let segment_bytes = bytes[start..end].to_vec();
        if blake3::hash(&segment_bytes).to_hex().as_str() != segment.segment_hash_blake3 {
            return Err(invalid_blob("canonical memory segment digest mismatch"));
        }
        Ok(segment_bytes)
    }

    /// Stores the raw payload once and derives bounded, deterministic child
    /// records. No database writes happen here; the returned parent-last plan
    /// must pass through the existing canonical writer authority.
    pub fn stage_canonical_memory(
        &self,
        memory_handle: &str,
        logical_kind: &str,
        media_type: &str,
        bytes: &[u8],
        cue_bindings: Vec<CueBinding>,
        project_root: Option<&str>,
    ) -> Result<CanonicalMemoryWritePlan, StoreError> {
        let memory_handle = bounded_label(memory_handle, "memory_handle", 512)?;
        let logical_kind = bounded_label(logical_kind, "logical_kind", 128)?;
        let media_type = bounded_label(media_type, "media_type", 128)?;
        let blob = self.put_bytes(bytes)?;
        let cue_pages = normalize_binding_pages(memory_handle, &blob, cue_bindings, project_root)
            .map_err(|error| StoreError::PolicyViolation(error.to_string()))?;

        let ranges = canonical_segment_ranges(bytes);
        let segment_count = u64::try_from(ranges.len()).map_err(|_| StoreError::BlobTooLarge)?;
        let utf8 = std::str::from_utf8(bytes).ok();
        let mut segments = ranges
            .into_iter()
            .enumerate()
            .map(|(ordinal, (start, end))| {
                let ordinal = u64::try_from(ordinal).map_err(|_| StoreError::BlobTooLarge)?;
                let slice = &bytes[start..end];
                let search_text = utf8.map_or_else(String::new, |_| {
                    std::str::from_utf8(slice).unwrap_or_default().to_owned()
                });
                let preview_text = search_text.chars().take(512).collect::<String>();
                let byte_start = u64::try_from(start).map_err(|_| StoreError::BlobTooLarge)?;
                let byte_end_exclusive =
                    u64::try_from(end).map_err(|_| StoreError::BlobTooLarge)?;
                let segment_hash_blake3 = blake3::hash(slice).to_hex().to_string();
                let segment_id = canonical_segment_id(
                    memory_handle,
                    &blob.digest_hex,
                    ordinal,
                    byte_start,
                    byte_end_exclusive,
                    &segment_hash_blake3,
                );
                Ok(CanonicalMemorySegment {
                    schema_version: CANONICAL_MEMORY_SCHEMA_VERSION.to_owned(),
                    segment_id,
                    parent_handle: memory_handle.to_owned(),
                    logical_kind: logical_kind.to_owned(),
                    blob: blob.clone(),
                    ordinal,
                    segment_count,
                    segment_set_hash_blake3: String::new(),
                    byte_start,
                    byte_end_exclusive,
                    segment_hash_blake3,
                    search_text,
                    preview_text,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let segment_set_hash_blake3 = canonical_segment_set_hash(&segments);
        for segment in &mut segments {
            segment
                .segment_set_hash_blake3
                .clone_from(&segment_set_hash_blake3);
        }
        let cue_page_set_hash_blake3 = cue_binding_page_set_hash(&cue_pages);
        let mut manifest_hasher = blake3::Hasher::new();
        manifest_hasher.update(memory_handle.as_bytes());
        manifest_hasher.update(logical_kind.as_bytes());
        manifest_hasher.update(media_type.as_bytes());
        manifest_hasher.update(blob.digest_hex.as_bytes());
        manifest_hasher.update(segment_set_hash_blake3.as_bytes());
        manifest_hasher.update(cue_page_set_hash_blake3.as_bytes());
        let manifest = CanonicalMemoryManifest {
            schema_version: CANONICAL_MEMORY_SCHEMA_VERSION.to_owned(),
            manifest_id: format!("memory-manifest:{}", manifest_hasher.finalize().to_hex()),
            memory_handle: memory_handle.to_owned(),
            logical_kind: logical_kind.to_owned(),
            media_type: media_type.to_owned(),
            blob,
            segment_count,
            segment_target_bytes: u32::try_from(CANONICAL_MEMORY_SEGMENT_TARGET_BYTES)
                .map_err(|_| StoreError::BlobTooLarge)?,
            segment_set_hash_blake3,
            cue_page_count: u64::try_from(cue_pages.len()).map_err(|_| StoreError::BlobTooLarge)?,
            cue_page_set_hash_blake3,
        };
        Ok(CanonicalMemoryWritePlan {
            segments,
            cue_pages,
            manifest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_canonical_memory_ingress(
        &self,
        context: &CommandContext,
        memory_handle: &str,
        logical_kind: &str,
        media_type: &str,
        bytes: &[u8],
        cue_bindings: Vec<CueBinding>,
        project_root: Option<&str>,
    ) -> Result<CanonicalMemoryIngressPlan, StoreError> {
        let write_plan = self.stage_canonical_memory(
            memory_handle,
            logical_kind,
            media_type,
            bytes,
            cue_bindings,
            project_root,
        )?;
        let commands_in_commit_order = write_plan.semantic_commands_in_commit_order(context)?;
        Ok(CanonicalMemoryIngressPlan {
            write_plan,
            commands_in_commit_order,
        })
    }

    /// Reconstructs the exact payload and verifies every child range/hash plus
    /// the manifest's complete segment-set digest.
    pub fn reconstruct_canonical_memory(
        &self,
        manifest: &CanonicalMemoryManifest,
        segments: &[CanonicalMemorySegment],
    ) -> Result<Vec<u8>, StoreError> {
        if manifest.schema_version != CANONICAL_MEMORY_SCHEMA_VERSION {
            return Err(StoreError::PolicyViolation(
                "unsupported canonical memory manifest schema".to_owned(),
            ));
        }
        let bytes = self.read_verified(&manifest.blob)?;
        if u64::try_from(segments.len()).map_err(|_| StoreError::BlobTooLarge)?
            != manifest.segment_count
        {
            return Err(invalid_blob("canonical memory segment count mismatch"));
        }
        let mut ordered = segments.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|segment| segment.ordinal);
        let mut cursor = 0usize;
        for (expected_ordinal, segment) in ordered.iter().enumerate() {
            let expected_ordinal =
                u64::try_from(expected_ordinal).map_err(|_| StoreError::BlobTooLarge)?;
            if segment.schema_version != CANONICAL_MEMORY_SCHEMA_VERSION
                || segment.parent_handle != manifest.memory_handle
                || segment.blob != manifest.blob
                || segment.segment_count != manifest.segment_count
                || segment.segment_set_hash_blake3 != manifest.segment_set_hash_blake3
                || segment.ordinal != expected_ordinal
            {
                return Err(invalid_blob("canonical memory segment authority mismatch"));
            }
            let start = usize::try_from(segment.byte_start)
                .map_err(|_| invalid_blob("canonical memory segment start overflow"))?;
            let end = usize::try_from(segment.byte_end_exclusive)
                .map_err(|_| invalid_blob("canonical memory segment end overflow"))?;
            if start != cursor || end < start || end > bytes.len() {
                return Err(invalid_blob(
                    "canonical memory segment range is not contiguous",
                ));
            }
            if blake3::hash(&bytes[start..end]).to_hex().as_str() != segment.segment_hash_blake3 {
                return Err(invalid_blob("canonical memory segment digest mismatch"));
            }
            cursor = end;
        }
        if cursor != bytes.len()
            || canonical_segment_set_hash(segments) != manifest.segment_set_hash_blake3
        {
            return Err(invalid_blob("canonical memory segment set is incomplete"));
        }
        Ok(bytes)
    }
}

fn inspect_blob_secret_bytes(bytes: &[u8]) -> Result<(), StoreError> {
    const OVERLAP: usize = 1024;
    let step = MAX_SECRET_BOUNDARY_BYTES.saturating_sub(OVERLAP).max(1);
    let mut start = 0usize;
    while start < bytes.len() {
        let end = start
            .saturating_add(MAX_SECRET_BOUNDARY_BYTES)
            .min(bytes.len());
        inspect_secret_bytes(&bytes[start..end]).map_err(|violation| {
            StoreError::PolicyViolation(format!(
                "secret boundary rejected blob ingress: {}",
                violation.rule
            ))
        })?;
        if end == bytes.len() {
            break;
        }
        start = start.saturating_add(step);
    }
    if bytes.is_empty() {
        inspect_secret_bytes(bytes).map_err(|violation| {
            StoreError::PolicyViolation(format!(
                "secret boundary rejected blob ingress: {}",
                violation.rule
            ))
        })?;
    }
    Ok(())
}

fn validate_blob_ref(blob: &BlobRef) -> Result<(), StoreError> {
    if blob.algorithm != "blake3"
        || blob.digest_hex.len() != 64
        || !blob
            .digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::PolicyViolation(
            "blob reference algorithm or digest is invalid".to_owned(),
        ));
    }
    let expected = expected_blob_relative_path(&blob.digest_hex);
    if Path::new(&blob.relative_path) != expected {
        return Err(StoreError::PolicyViolation(
            "blob reference path is not the canonical digest path".to_owned(),
        ));
    }
    Ok(())
}

fn expected_blob_relative_path(digest_hex: &str) -> PathBuf {
    let (prefix, suffix) = digest_hex.split_at(2);
    PathBuf::from(prefix).join(format!("{suffix}.blob"))
}

fn invalid_blob(message: impl Into<String>) -> StoreError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn bounded_label<'a>(value: &'a str, label: &str, max_bytes: usize) -> Result<&'a str, StoreError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_bytes {
        return Err(StoreError::PolicyViolation(format!(
            "{label} must contain 1..={max_bytes} UTF-8 bytes"
        )));
    }
    Ok(value)
}

fn canonical_segment_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    if bytes.is_empty() {
        return vec![(0, 0)];
    }
    let utf8 = std::str::from_utf8(bytes).ok();
    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let mut end = start
            .saturating_add(CANONICAL_MEMORY_SEGMENT_TARGET_BYTES)
            .min(bytes.len());
        if let Some(text) = utf8 {
            while end < bytes.len() && !text.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
        }
        ranges.push((start, end));
        start = end;
    }
    ranges
}

fn canonical_segment_id(
    memory_handle: &str,
    blob_digest_hex: &str,
    ordinal: u64,
    byte_start: u64,
    byte_end_exclusive: u64,
    segment_hash_blake3: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory_handle.as_bytes());
    hasher.update(blob_digest_hex.as_bytes());
    hasher.update(&ordinal.to_le_bytes());
    hasher.update(&byte_start.to_le_bytes());
    hasher.update(&byte_end_exclusive.to_le_bytes());
    hasher.update(segment_hash_blake3.as_bytes());
    format!("memory-segment:{}", hasher.finalize().to_hex())
}

pub(crate) fn canonical_segment_set_hash(segments: &[CanonicalMemorySegment]) -> String {
    let mut ordered = segments.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|segment| segment.ordinal);
    let mut hasher = blake3::Hasher::new();
    for segment in ordered {
        hasher.update(segment.segment_id.as_bytes());
        hasher.update(&segment.ordinal.to_le_bytes());
        hasher.update(&segment.byte_start.to_le_bytes());
        hasher.update(&segment.byte_end_exclusive.to_le_bytes());
        hasher.update(segment.segment_hash_blake3.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[allow(clippy::too_many_lines)]
pub(crate) fn verify_canonical_memory_child_set(
    blob_store: Option<&BlobStore>,
    manifest: &CanonicalMemoryManifest,
    segments: &[CanonicalMemorySegment],
    cue_pages: &[CueBindingPage],
) -> Result<(), StoreError> {
    if u64::try_from(segments.len()).map_err(|_| StoreError::BlobTooLarge)?
        != manifest.segment_count
        || u64::try_from(cue_pages.len()).map_err(|_| StoreError::BlobTooLarge)?
            != manifest.cue_page_count
    {
        return Err(invalid_blob(format!(
            "canonical memory child cardinality does not match manifest: segments={}/{}, cue_pages={}/{}",
            segments.len(),
            manifest.segment_count,
            cue_pages.len(),
            manifest.cue_page_count,
        )));
    }
    let verified_blob = blob_store
        .map(|store| store.read_verified(&manifest.blob))
        .transpose()?;
    let mut ordered_segments = segments.iter().collect::<Vec<_>>();
    ordered_segments.sort_by_key(|segment| segment.ordinal);
    let mut cursor = 0u64;
    for (index, segment) in ordered_segments.iter().enumerate() {
        let expected_ordinal = u64::try_from(index).map_err(|_| StoreError::BlobTooLarge)?;
        let mismatch = if segment.schema_version != CANONICAL_MEMORY_SCHEMA_VERSION {
            Some("schema_version".to_owned())
        } else if segment.parent_handle != manifest.memory_handle {
            Some(format!(
                "parent_handle(expected={:?}, actual={:?})",
                manifest.memory_handle, segment.parent_handle
            ))
        } else if segment.logical_kind != manifest.logical_kind {
            Some("logical_kind".to_owned())
        } else if segment.blob != manifest.blob {
            Some("blob".to_owned())
        } else if segment.ordinal != expected_ordinal {
            Some("ordinal".to_owned())
        } else if segment.segment_count != manifest.segment_count {
            Some("segment_count".to_owned())
        } else if segment.segment_set_hash_blake3 != manifest.segment_set_hash_blake3 {
            Some("segment_set_hash_blake3".to_owned())
        } else if segment.byte_start != cursor {
            Some("byte_start".to_owned())
        } else if segment.byte_end_exclusive < segment.byte_start {
            Some("byte_range_order".to_owned())
        } else if segment.byte_end_exclusive > manifest.blob.size_bytes {
            Some("byte_range_bounds".to_owned())
        } else if segment.segment_id
            != canonical_segment_id(
                &segment.parent_handle,
                &segment.blob.digest_hex,
                segment.ordinal,
                segment.byte_start,
                segment.byte_end_exclusive,
                &segment.segment_hash_blake3,
            )
        {
            Some("segment_id".to_owned())
        } else {
            None
        };
        if let Some(field) = mismatch {
            return Err(invalid_blob(format!(
                "canonical memory segment {expected_ordinal} failed exact-set field {field}"
            )));
        }
        if let Some(bytes) = verified_blob.as_ref() {
            let start = usize::try_from(segment.byte_start)
                .map_err(|_| invalid_blob("canonical segment start overflow"))?;
            let end = usize::try_from(segment.byte_end_exclusive)
                .map_err(|_| invalid_blob("canonical segment end overflow"))?;
            if blake3::hash(&bytes[start..end]).to_hex().as_str() != segment.segment_hash_blake3 {
                return Err(invalid_blob(
                    "canonical memory segment hash does not match BlobStore bytes",
                ));
            }
        }
        cursor = segment.byte_end_exclusive;
    }
    if cursor != manifest.blob.size_bytes
        || canonical_segment_set_hash(segments) != manifest.segment_set_hash_blake3
    {
        return Err(invalid_blob(
            "canonical memory segments do not cover the full blob or set hash",
        ));
    }

    let mut ordered_pages = cue_pages.iter().collect::<Vec<_>>();
    ordered_pages.sort_by_key(|page| page.page_ordinal);
    for (index, page) in ordered_pages.iter().enumerate() {
        let expected_ordinal = u64::try_from(index).map_err(|_| StoreError::BlobTooLarge)?;
        if page.schema_version != "eliot-cue-binding-page-v1"
            || page.parent_handle != manifest.memory_handle
            || page.blob != manifest.blob
            || page.page_ordinal != expected_ordinal
            || page.page_count != manifest.cue_page_count
            || page.page_set_hash_blake3 != manifest.cue_page_set_hash_blake3
            || page.cue_bindings.is_empty()
            || page.cue_bindings.len() > MAX_CUE_BINDINGS_PER_PAGE
            || serde_json::to_vec(page)
                .map_or(true, |bytes| bytes.len() > MAX_CUE_BINDING_PAGE_BYTES)
            || page.page_id
                != cue_binding_page_id(
                    &page.parent_handle,
                    &page.blob,
                    page.page_ordinal,
                    &page.cue_bindings,
                )
        {
            return Err(invalid_blob(
                "canonical memory cue page set is not exact or transport bounded",
            ));
        }
    }
    if cue_binding_page_set_hash(cue_pages) != manifest.cue_page_set_hash_blake3 {
        return Err(invalid_blob(
            "canonical memory cue page set hash does not match manifest",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BlobStore, CanonicalMemoryStagedRecord, verify_canonical_memory_child_set};
    use crate::StoreError;
    use eliot_types::{
        AgentId, BlobStoreConfig, CommandContext, CueBinding, CueKind, CueMatchMode, CueStrength,
        LifecycleStatus, ProjectId, SemanticCommand, TaintClass, Visibility, WriteId,
    };

    #[test]
    fn stores_blob_by_content_hash() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir =
            std::env::temp_dir().join(format!("eliot-governor-blob-test-{}", std::process::id()));

        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let blob = store.put_bytes(b"hello")?;
        let bytes = std::fs::read(store.blob_path(&blob))?;

        assert_eq!(bytes, b"hello");

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }

    #[test]
    fn rejects_corrupt_existing_content_addressed_blob() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-governor-corrupt-existing-blob-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let blob = store.put_bytes(b"expected")?;
        let path = store.blob_path(&blob);
        std::fs::write(&path, b"corrupt")?;

        let Err(error) = store.put_bytes(b"expected") else {
            return Err("corrupt blob was accepted".into());
        };
        assert!(matches!(
            error,
            StoreError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData
        ));
        assert_eq!(std::fs::read(path)?, b"corrupt");

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }

    #[test]
    fn rejects_secret_before_hash_or_persistence() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-governor-secret-blob-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let Some(error) = store
            .put_bytes(b"Authorization: Bearer synthetic-token-value-12345")
            .err()
        else {
            return Err(std::io::Error::other("secret-bearing blob was accepted").into());
        };
        assert!(matches!(error, StoreError::PolicyViolation(_)));
        assert!(std::fs::read_dir(&temp_dir)?.next().is_none());
        std::fs::remove_dir(temp_dir)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonical_capacity_is_parent_last_and_fully_reconstructable()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = std::env::temp_dir().join(format!(
            "eliot-canonical-capacity-test-{}",
            uuid::Uuid::new_v4()
        ));
        let store = BlobStore::open(&BlobStoreConfig {
            root: temp_dir.display().to_string(),
        })?;
        let payload = (0..30_000)
            .map(|index| format!("semantic-term-{index:05}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes();
        let cues = (0..29)
            .map(|index| CueBinding {
                cue_kind: CueKind::Concept,
                cue_value: format!("capacity-concept-{index:02}"),
                match_mode: CueMatchMode::Exact,
                strength: if index == 0 {
                    CueStrength::Primary
                } else {
                    CueStrength::Secondary
                },
                expected_reuse_note: "large canonical reconstruction".to_owned(),
            })
            .collect();
        let plan = store.stage_canonical_memory(
            "memory:large-capacity-test",
            "synthetic_evidence",
            "text/plain; charset=utf-8",
            &payload,
            cues,
            None,
        )?;

        assert!(plan.segments.len() > 1);
        assert!(plan.segments.iter().all(|segment| {
            segment.segment_set_hash_blake3 == plan.manifest.segment_set_hash_blake3
        }));
        assert_eq!(
            plan.cue_pages
                .iter()
                .map(|page| page.cue_bindings.len())
                .collect::<Vec<_>>(),
            [12, 12, 5]
        );
        assert!(
            plan.cue_pages.iter().all(|page| {
                page.page_set_hash_blake3 == plan.manifest.cue_page_set_hash_blake3
            })
        );
        assert_eq!(
            store.reconstruct_canonical_memory(&plan.manifest, &plan.segments)?,
            payload
        );
        verify_canonical_memory_child_set(
            Some(&store),
            &plan.manifest,
            &plan.segments,
            &plan.cue_pages,
        )?;
        let mut non_contiguous_set = plan.segments.clone();
        non_contiguous_set[1].byte_start = non_contiguous_set[1].byte_start.saturating_add(1);
        assert!(
            verify_canonical_memory_child_set(
                Some(&store),
                &plan.manifest,
                &non_contiguous_set,
                &plan.cue_pages,
            )
            .is_err()
        );
        let mut missing_plus_surplus_set = plan.segments.clone();
        let mut surplus = missing_plus_surplus_set.remove(0);
        surplus.ordinal = plan.manifest.segment_count;
        missing_plus_surplus_set.push(surplus);
        assert_eq!(missing_plus_surplus_set.len(), plan.segments.len());
        assert!(
            verify_canonical_memory_child_set(
                Some(&store),
                &plan.manifest,
                &missing_plus_surplus_set,
                &plan.cue_pages,
            )
            .is_err(),
            "a same-cardinality set with one missing and one surplus child must be rejected"
        );
        let mut mixed_set = plan.segments.clone();
        mixed_set[0].segment_set_hash_blake3 = "b".repeat(64);
        assert!(
            store
                .reconstruct_canonical_memory(&plan.manifest, &mixed_set)
                .is_err()
        );
        let records = plan.records_in_commit_order();
        assert!(matches!(
            records.last(),
            Some(CanonicalMemoryStagedRecord::Manifest(_))
        ));
        assert!(records[..records.len() - 1].iter().all(|record| {
            !matches!(record, CanonicalMemoryStagedRecord::Manifest(_))
                && record
                    .receipt_body()
                    .and_then(|body| {
                        serde_json::to_vec(&body)
                            .map_err(|error| StoreError::Decode(error.to_string()))
                    })
                    .is_ok_and(|bytes| bytes.len() < 128 * 1024)
        }));
        let ingress_write_id = WriteId::new_v7();
        let commands = plan.semantic_commands_in_commit_order(&CommandContext {
            write_id: ingress_write_id,
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id: ProjectId::new_v7(),
            task_id: None,
            scope: "capacity-ingress".to_owned(),
            authority: "local-capacity-test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        })?;
        assert_eq!(commands.len(), records.len());
        assert!(commands.iter().all(|command| {
            serde_json::to_vec(command)
                .is_ok_and(|bytes| bytes.len() <= super::CANONICAL_MEMORY_TRANSPORT_MAX_BYTES)
        }));
        assert!(matches!(
            commands.last(),
            Some(SemanticCommand::ToolObservationRecord(command))
                if command.context.write_id == ingress_write_id
                    && command.payload["receipt_kind"] == "memory_blob_manifest"
        ));
        let expanded = plan
            .segments
            .iter()
            .map(eliot_types::CanonicalMemorySegmentRef::from)
            .map(|segment| store.read_verified_segment(&segment))
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        assert_eq!(expanded, payload);

        let mut escaped = plan.manifest.blob.clone();
        escaped.relative_path = "../outside.blob".to_owned();
        assert!(matches!(
            store.read_verified(&escaped),
            Err(StoreError::PolicyViolation(_))
        ));
        let mut wrong_algorithm = plan.manifest.blob.clone();
        wrong_algorithm.algorithm = "sha256".to_owned();
        assert!(matches!(
            store.read_verified(&wrong_algorithm),
            Err(StoreError::PolicyViolation(_))
        ));

        std::fs::remove_dir_all(temp_dir)?;
        Ok(())
    }
}
