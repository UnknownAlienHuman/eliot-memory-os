//! Governed source-readback gate for projected citations.
//!
//! Crates-only gate API: the caller supplies the exact admitted readback
//! request plus the bytes reopened through the governed source owner. The
//! gate verifies view, workspace-view revision and state fence, then the
//! full-source digest and byte length, resolves the anchor through exact
//! coordinates or native mapping, and verifies the excerpt digest before any
//! material may appear as support or a citation. Index and vector previews
//! are never cited. This gate authorizes no durable mutation.

use eliot_context_contracts::{ContextError, ProjectedCitation, ReadbackRefusal, ReadbackRequest};
use eliot_contracts::{StateFence, fences_match_exact, sha256_hex};
use eliot_observation_contracts::{SourceAnchorHandle, SourceRevisionHandle};

/// Source bytes reopened through the governed owner under the active view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReopenedSource {
    /// Revision handle the owner claims these bytes belong to.
    pub revision: SourceRevisionHandle,
    /// Source view the owner reopened.
    pub view: eliot_observation_contracts::SourceViewHandle,
    /// Workspace-view revision the owner reopened under.
    pub workspace_revision: eliot_observation_contracts::WorkspaceViewRevisionHandle,
    /// State fence the reopened bytes satisfy.
    pub fence: StateFence,
    /// Complete reopened source bytes.
    pub bytes: Vec<u8>,
}

impl ReopenedSource {
    /// Validate handle shapes and byte bounds without citing anything.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.revision
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.reopened.revision"))?;
        self.view
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.reopened.view"))?;
        self.workspace_revision
            .validate()
            .map_err(|_| ContextError::InvalidField("readback.reopened.workspace_revision"))?;
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.bytes.len() > eliot_context_contracts::MAX_PREVIEW_BYTES {
            return Err(ContextError::Bounds {
                field: "readback.reopened.bytes",
            });
        }
        Ok(())
    }
}

fn unsupported(reason: &'static str) -> ReadbackRefusal {
    ReadbackRefusal::unsupported(reason)
}

fn replan(reason: &'static str) -> ReadbackRefusal {
    ReadbackRefusal::replan(reason)
}

fn gap(reason: &'static str, missing_handle: Option<String>) -> ReadbackRefusal {
    ReadbackRefusal::gap(reason, missing_handle)
}

/// Gate one projected citation on governed source readback.
///
/// Returns the verified excerpt sliced from the reopened revision on success.
/// Returns a typed unsupported, replan or gap refusal instead of citing
/// index-preview or current bytes when the revision, view, fence, mapping,
/// byte length or digest cannot be verified.
pub fn gate_citation(
    request: &ReadbackRequest,
    reopened: &ReopenedSource,
) -> Result<ProjectedCitation, ReadbackRefusal> {
    request
        .validate()
        .map_err(|_| unsupported("readback.request.invalid"))?;
    reopened
        .validate()
        .map_err(|_| unsupported("readback.reopened.invalid"))?;

    // An index/vector preview stays a non-authoritative preview. A preview
    // that claims a revision other than the admitted one describes bytes this
    // gate has not read back, so the read is replanned instead of citing the
    // convenient bytes the preview happens to carry.
    if request.preview.claimed_revision != request.admitted.revision {
        return Err(replan("readback.preview.revision_drift"));
    }

    if request.view != reopened.view {
        return Err(replan("readback.view.mismatch"));
    }
    if request.workspace_revision != reopened.workspace_revision {
        return Err(replan("readback.workspace_revision.drift"));
    }
    if request.view.workspace_instance_id != request.workspace_revision.workspace_instance_id {
        return Err(replan("readback.workspace_revision.instance_mismatch"));
    }
    if !fences_match_exact(&request.fence, &reopened.fence) {
        return Err(replan("readback.fence.mismatch"));
    }
    if request.admitted.source_id != reopened.revision.source_id
        || request.admitted.revision != reopened.revision.revision
    {
        return Err(unsupported("readback.revision.mismatch"));
    }
    if request.admitted.content_sha256 != reopened.revision.content_sha256
        || request.admitted.byte_length != reopened.revision.byte_length
    {
        return Err(gap(
            "readback.revision.digest_mismatch",
            Some(request.admitted.revision.clone()),
        ));
    }

    verify_full_source(&request.admitted, &reopened.bytes)?;
    let (anchor, excerpt) = resolve_anchor(&request.anchor, &reopened.bytes)?;

    let citation = ProjectedCitation {
        source_revision: request.admitted.clone(),
        anchor,
        view: request.view.clone(),
        workspace_revision: request.workspace_revision.clone(),
        fence: request.fence.clone(),
        excerpt_bytes: excerpt,
        excerpt_digest: request.anchor.excerpt_sha256.clone(),
    };
    citation
        .validate()
        .map_err(|_| gap("readback.citation.invalid", None))?;
    Ok(citation)
}

fn verify_full_source(
    admitted: &SourceRevisionHandle,
    bytes: &[u8],
) -> Result<(), ReadbackRefusal> {
    let length =
        u64::try_from(bytes.len()).map_err(|_| gap("readback.source.length_overflow", None))?;
    if length != admitted.byte_length {
        return Err(gap(
            "readback.source.byte_length_mismatch",
            Some(admitted.revision.clone()),
        ));
    }
    if sha256_hex(bytes) != admitted.content_sha256 {
        return Err(gap(
            "readback.source.digest_mismatch",
            Some(admitted.revision.clone()),
        ));
    }
    Ok(())
}

fn resolve_anchor(
    anchor: &SourceAnchorHandle,
    bytes: &[u8],
) -> Result<(SourceAnchorHandle, Vec<u8>), ReadbackRefusal> {
    // An owner that does not use raw byte offsets records the native
    // coordinate mapping on the anchor handle; that mapping — not the
    // uninterpreted raw offset — then decides where the excerpt starts.
    // Either way the excerpt length and digest stay owner-issued and are
    // verified against the reopened bytes below.
    let start = match anchor.native_mapping.as_deref() {
        Some(mapping) => native_mapping_offset(mapping, bytes)?,
        None => usize::try_from(anchor.byte_offset)
            .map_err(|_| unsupported("readback.anchor.offset_overflow"))?,
    };
    let length = usize::try_from(anchor.byte_length)
        .map_err(|_| unsupported("readback.anchor.length_overflow"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| unsupported("readback.anchor.range_overflow"))?;
    if end > bytes.len() {
        return Err(unsupported("readback.anchor.unresolvable"));
    }
    let excerpt = bytes[start..end].to_vec();
    if sha256_hex(&excerpt) != anchor.excerpt_sha256 {
        return Err(gap(
            "readback.excerpt.digest_mismatch",
            Some(anchor.anchor_id.clone()),
        ));
    }
    let resolved = match u64::try_from(start) {
        Ok(resolved_offset) => {
            let mut resolved = anchor.clone();
            resolved.byte_offset = resolved_offset;
            resolved
        }
        Err(_) => anchor.clone(),
    };
    Ok((resolved, excerpt))
}

/// Resolves one closed native coordinate mapping to a byte offset in the
/// reopened bytes.
///
/// The grammar is the owner-facing `line:<n>;column:<n>` pair, both one-based
/// and counted over the reopened bytes' own `LF` line breaks. No other
/// syntax is admitted, and a mapping that does not address a position inside
/// the reopened bytes is a typed refusal, never a silent fall back to the raw
/// offset the owner does not use.
fn native_mapping_offset(mapping: &str, bytes: &[u8]) -> Result<usize, ReadbackRefusal> {
    let (line, column) = parse_native_mapping(mapping)?;
    let line_index = line - 1;
    let mut line_start = 0usize;
    for _ in 0..line_index {
        let next = bytes[line_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| line_start + index + 1)
            .ok_or_else(|| unsupported("readback.anchor.mapping_unresolvable"))?;
        line_start = next;
    }
    if line_start > bytes.len() {
        return Err(unsupported("readback.anchor.mapping_unresolvable"));
    }
    let line_end = bytes[line_start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |index| line_start + index);
    let offset = line_start
        .checked_add(column - 1)
        .filter(|offset| *offset <= line_end)
        .ok_or_else(|| unsupported("readback.anchor.mapping_unresolvable"))?;
    Ok(offset)
}

/// Parses the closed `line:<n>;column:<n>` native coordinate mapping.
fn parse_native_mapping(mapping: &str) -> Result<(usize, usize), ReadbackRefusal> {
    let mut line: Option<usize> = None;
    let mut column: Option<usize> = None;
    for field in mapping.split(';') {
        let (name, value) = field
            .split_once(':')
            .ok_or_else(|| unsupported("readback.anchor.mapping_invalid"))?;
        let parsed = value
            .parse::<usize>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or_else(|| unsupported("readback.anchor.mapping_invalid"))?;
        match name {
            "line" if line.is_none() => line = Some(parsed),
            "column" if column.is_none() => column = Some(parsed),
            _ => return Err(unsupported("readback.anchor.mapping_invalid")),
        }
    }
    match (line, column) {
        (Some(line), Some(column)) => Ok((line, column)),
        _ => Err(unsupported("readback.anchor.mapping_invalid")),
    }
}
