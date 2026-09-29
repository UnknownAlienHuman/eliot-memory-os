//! Governed source-owner readback for the production retrieval-to-projection
//! path (issue #1948).
//!
//! I12.26 requires that a retrieved campaign source may appear as cited
//! support only after the exact admitted source revision has been reopened
//! under the same source view, workspace-view revision and State Fence, and
//! after its digest, byte length and excerpt digest have been verified. This
//! module is the governed source-owner edge that performs that reopen for the
//! live `eliot.packet` route.
//!
//! # Governed owner surface
//!
//! The owner surface is the authenticated `GetCampaignSourceRevision` read
//! that [`crate::campaign_packet`] already performs on this route. The returned
//! [`CampaignSourceRecord`] is owner-issued and Kernel-authenticated by the
//! [`CampaignOwnerReadReceipt`] that `CampaignSourceRevisionRead::validate`
//! requires for every `Current` read. The reopened bytes are the canonical
//! encoding of that owner record's validated typed document — the same bytes
//! whose digest the owner recorded as `CampaignOwnerReadReceipt::document_digest`.
//!
//! Nothing here re-issues a digest. The admitted full-source digest is the
//! ORIGINAL digest the owner recorded in the read receipt, and that receipt is
//! itself proven to bind this exact row by `binds_record` before the gate runs.
//! The citation gate then re-derives `sha256_hex(bytes)` from the reopened bytes
//! and compares by content, so a mutated payload is caught by a comparison, not
//! by re-seeding the claim.
//!
//! # Cited source unit and its exact coordinates
//!
//! The cited unit is the document's typed `body` value. Its coordinates are
//! **located, not assumed**: [`body_coordinates`] finds the canonical encoding
//! of `document.body` as a byte-exact sub-slice of the canonical encoding of
//! `document`, and refuses if it occurs zero or several times. Deriving the
//! offset arithmetically (for example "the body is the trailing `n` bytes")
//! is wrong for this schema: canonical JSON sorts object keys recursively, so
//! `body` sorts first and is followed by the schema envelope — the trailing
//! bytes are the envelope's, not the body's.
//!
//! # Index/vector previews
//!
//! There is no production index or vector retrieval surface in this tree to
//! preview (measured: the store's named-read catalogue declares no vector,
//! embedding or index operation, and `git grep -i -E
//! 'vector_index|embedding_store|vector_store|embed_store'` is empty). The
//! preview carried here is therefore the honest shape — empty bytes, the
//! admitted revision as the only revision it claims, and the non-authoritative
//! authority marker — and `IndexPreview::is_citable()` is `false` by contract.
//! It can never drift into a citation.
//!
//! # Authority
//!
//! This is a read/projection constraint only: it authorizes no durable
//! mutation, implements no second consistency algorithm, and retains no client.
//! The caller passes the already-reopened, already-fence-checked owner record.
//! Every rejection returns the typed [`ReadbackRefusal`] instead of a citation,
//! so a drifted view, a moved fence, a changed revision, a changed byte length
//! or a changed digest yields a narrower outcome and never a citation to the
//! convenient current bytes.

use eliot_context_assembly::{
    IndexPreview, PreviewAuthority, ProjectedCitation, ReadbackRefusal, ReadbackRequest,
    ReopenedSource, project_citation,
};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_observation_contracts::{
    SourceAnchorHandle, SourceRevisionHandle, SourceViewHandle, SourceViewKind,
    WorkspaceViewRevisionHandle,
};
use eliot_store_api::{CampaignOwnerReadReceipt, CampaignSourceRecord};

/// Where the cited document body actually sits inside the reopened source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BodyCoordinates {
    offset: usize,
    length: usize,
}

/// Locates the document body inside the canonical document encoding.
///
/// The canonical encoding sorts every object key recursively, so a struct
/// field's position follows its key and not its declaration order. The body's
/// own canonical encoding is therefore searched for as a byte-exact sub-slice
/// of the document's canonical encoding, and an ambiguous or absent location is
/// a typed gap rather than a guess at a trailing offset.
fn body_coordinates(
    document: &eliot_store_api::CampaignSourceDocument,
) -> Result<BodyCoordinates, ReadbackRefusal> {
    let bytes = canonical_json_bytes(document)
        .map_err(|_| ReadbackRefusal::gap("readback.owner.encoding", None))?;
    let body = canonical_json_bytes(&document.body)
        .map_err(|_| ReadbackRefusal::gap("readback.owner.encoding", None))?;
    let found = find_subslice(&bytes, &body);
    let offset = match found.as_slice() {
        [offset] => *offset,
        [] => return Err(ReadbackRefusal::gap("readback.anchor.unresolvable", None)),
        _ => return Err(ReadbackRefusal::gap("readback.anchor.ambiguous", None)),
    };
    Ok(BodyCoordinates {
        offset,
        length: body.len(),
    })
}

/// Returns the offsets of every exact occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut matches = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return matches;
    }
    let last = haystack.len() - needle.len();
    let mut offset = 0;
    while offset <= last {
        if haystack[offset..=last].starts_with(needle) {
            matches.push(offset);
            offset += needle.len();
            continue;
        }
        offset += 1;
    }
    matches
}

/// Renders one owner-issued identity as a bounded handle string.
///
/// Uses the same canonical JSON encoding the store digest path uses, so the
/// label is the owner's own lossless rendering of the value rather than a
/// hand-built string. A value that cannot be encoded is a typed gap, never a
/// fabricated label.
fn owner_label<T: serde::Serialize>(value: &T) -> Result<String, ReadbackRefusal> {
    let bytes = canonical_json_bytes(value)
        .map_err(|_| ReadbackRefusal::gap("readback.owner.label", None))?;
    String::from_utf8(bytes).map_err(|_| ReadbackRefusal::gap("readback.owner.label", None))
}

/// Reopens the admitted owner record and projects one governed citation.
///
/// The record and its receipt must be the pair produced by the same `Current`
/// authenticated owner read: `binds_record` proves the receipt describes
/// exactly this immutable row at exactly this revision, and the gate proves the
/// reopened bytes still hash to the owner-recorded `document_digest`. The
/// `view` and `workspace_revision` are the caller's active view handles and
/// `fence` the admitted State Fence; all three are cross-checked by the gate
/// against the reopened handle, so a substituted view or a moved fence is a
/// `replan` refusal rather than a citation.
///
/// Returns the verified citation on success, or the typed refusal
/// (`unsupported`, `replan` or `gap`) that must replace it. `project_citation`
/// is invoked with `project` so the consumer sees the citation exactly once and
/// only after the gate has passed.
pub fn project_owner_document_citation(
    record: &CampaignSourceRecord,
    receipt: &CampaignOwnerReadReceipt,
    view: SourceViewHandle,
    workspace_revision: WorkspaceViewRevisionHandle,
    fence: &StateFence,
    project: impl FnOnce(&ProjectedCitation),
) -> Result<ProjectedCitation, ReadbackRefusal> {
    // The owner receipt is the authenticated proof that the returned row is the
    // exact immutable record at the read fence. If it does not bind this row,
    // these bytes are not a proven owner read and the gate refuses.
    if !receipt.binds_record(record) {
        return Err(ReadbackRefusal::gap(
            "readback.owner.receipt_mismatch",
            Some(owner_label(&record.record_id)?),
        ));
    }

    // The reopened bytes are the canonical encoding of the owner document. The
    // admitted full-source digest is the ORIGINAL digest the owner recorded in
    // the read receipt; it is never recomputed here to set the claim.
    let bytes = canonical_json_bytes(&record.document)
        .map_err(|_| ReadbackRefusal::gap("readback.owner.encoding", None))?;
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| ReadbackRefusal::gap("readback.source.length_overflow", None))?;

    // The cited source unit is the document body at its located coordinates.
    let coordinates = body_coordinates(&record.document)?;
    let excerpt_end = coordinates
        .offset
        .checked_add(coordinates.length)
        .ok_or_else(|| ReadbackRefusal::gap("readback.anchor.unresolvable", None))?;
    let excerpt = bytes
        .get(coordinates.offset..excerpt_end)
        .ok_or_else(|| ReadbackRefusal::gap("readback.anchor.unresolvable", None))?;
    let excerpt_length = u64::try_from(coordinates.length)
        .map_err(|_| ReadbackRefusal::gap("readback.source.length_overflow", None))?;
    // The excerpt digest is derived from the reopened slice, so the gate
    // compares two independent encodings of the same owned bytes by content.
    let excerpt_digest = sha256_hex(excerpt);
    let source_id = owner_label(&record.record_id)?;
    let admitted = SourceRevisionHandle {
        source_id: source_id.clone(),
        revision: owner_label(&record.revision)?,
        content_sha256: receipt.document_digest.clone(),
        byte_length,
    };
    let anchor = SourceAnchorHandle {
        anchor_id: source_id,
        byte_offset: u64::try_from(coordinates.offset)
            .map_err(|_| ReadbackRefusal::gap("readback.source.length_overflow", None))?,
        byte_length: excerpt_length,
        excerpt_sha256: excerpt_digest,
        native_mapping: None,
    };
    let request = ReadbackRequest {
        admitted: admitted.clone(),
        view,
        workspace_revision,
        fence: fence.clone(),
        anchor,
        // No production index or vector retrieval surface exists to preview, so
        // the preview carries no bytes and claims no revision other than the
        // admitted one. It can never drift into a citation.
        preview: IndexPreview {
            bytes: Vec::new(),
            claimed_revision: admitted.revision.clone(),
            authority: PreviewAuthority::NonAuthoritativePreview,
        },
    };
    let reopened = ReopenedSource {
        revision: admitted,
        view: request.view.clone(),
        workspace_revision: request.workspace_revision.clone(),
        fence: fence.clone(),
        bytes,
    };
    project_citation(&request, &reopened, project)
}

/// Builds the active `SourceViewHandle` for an owner-read-backed source.
///
/// The source is reopened from a retained owner revision rather than a working
/// tree, so the view is a `RetainedRevision` bound to the owner record identity
/// the read returned. `workspace_instance_id` is the task work scope the packet
/// was admitted under; the view revision and the retained-revision id are the
/// owner-issued revision label, not a constant. The returned handles share the
/// workspace instance so the gate's instance check holds.
pub(crate) fn owner_source_view(
    work_scope_id: &str,
    record: &CampaignSourceRecord,
) -> Option<(SourceViewHandle, WorkspaceViewRevisionHandle)> {
    let view_revision = owner_label(&record.revision).ok()?;
    let retained_revision_id = owner_label(&record.record_id).ok()?;
    let view = SourceViewHandle {
        kind: SourceViewKind::RetainedRevision,
        workspace_instance_id: work_scope_id.to_owned(),
        workspace_view_revision: view_revision.clone(),
        git_commit_oid: None,
        imported_snapshot_id: None,
        retained_revision_id: Some(retained_revision_id),
    };
    let workspace_revision = WorkspaceViewRevisionHandle {
        workspace_instance_id: work_scope_id.to_owned(),
        view_revision,
    };
    Some((view, workspace_revision))
}
