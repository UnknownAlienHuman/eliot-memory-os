//! Governed source owner readback for the production retrieval-to-projection path
//! (issue #1948).
//!
//! I12.26 requires that a retrieved campaign source may appear as cited support
//! only after the exact admitted source revision has been reopened under the
//! same source view, workspace-view revision and State Fence, and after its
//! digest, byte length and excerpt digest have been verified. This module is the
//! governed source owner edge that performs that reopen for the live
//! `eliot.packet` route.
//!
//! # Governed owner surface
//!
//! The owner surface is the authenticated `GetCampaignSourceRevision` read that
//! [`crate::campaign_packet`] already performs on this route. The returned
//! [`CampaignSourceRecord`] is owner-issued and Kernel-authenticated by the
//! `CampaignOwnerReadReceipt` that `CampaignSourceRevisionRead::validate`
//! requires for every `Current` read. The reopened bytes are the canonical
//! encoding of that owner record's validated typed document — the same bytes
//! whose digest the owner recorded as `CampaignOwnerReadReceipt::document_digest`.
//!
//! Nothing here re-issues a digest. The admitted full-source digest is the
//! ORIGINAL digest the owner recorded in the read receipt, and that receipt is
//! itself proven to bind this exact row by `binds_record` before the gate runs.
//! The citation gate then re-derives `sha256_hex(bytes)` from the reopened bytes
//! and compares by content, so a mutated payload is caught.
//!
//! # Cited source unit
//!
//! The cited unit is the document's typed `body` value, LOCATED as a byte-exact
//! sub-slice of the canonical document encoding. It is not derived by
//! arithmetic: `canonical_json_bytes` sorts every object key recursively, so
//! `CampaignSourceDocument { schema, schema_version, body }` encodes as
//! `{"body":{…},"schema":…,"schema_version":1}` and the body is neither a prefix
//! nor a suffix. The anchor therefore carries the exact `byte_offset` /
//! `byte_length` of those owned bytes and the digest of the reopened slice —
//! never a caller-asserted claim, never a hand-picked coordinate, and never an
//! approximate one.
//!
//! # Index/vector preview
//!
//! The retrieval plans the same authenticated owner read returned are the real
//! production index payload on this route, so [`IndexPreview`] is projected from
//! them rather than left as an empty schema with no producer. The preview's
//! `claimed_revision` is the revision the PLAN's own read fence names, never a
//! copy of the admitted revision: a preview that echoed the value it is checked
//! against could not drift, and the gate's `readback.preview.revision_drift`
//! replan would be unreachable. The preview stays non-authoritative and is
//! never cited; only the readback-verified excerpt may be.
//!
//! # Authority
//!
//! This is a read/projection constraint only: it authorizes no durable mutation,
//! implements no second consistency algorithm, and retains no client. The caller
//! passes the already-reopened, already-fence-checked owner record. Every
//! rejection returns the typed [`ReadbackRefusal`] instead of a citation, so a
//! drifted view, a moved fence, a changed revision, a changed byte length or a
//! changed digest yields a narrower outcome and never a citation to the
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
use eliot_store_api::{CampaignOwnerReadReceipt, CampaignOwnerRevision, CampaignSourceRecord};

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
/// The record and its receipt must be the pair produced by the same
/// `Current` authenticated owner read: `binds_record` proves the receipt
/// describes exactly this immutable row at exactly this revision, and the gate
/// proves the reopened bytes still hash to the owner-recorded `document_digest`.
/// The `view` and `workspace_revision` are the caller's active view handles and
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

    // The cited source unit is the document body, LOCATED as a byte-exact
    // sub-slice of the canonical document encoding. It is never derived by
    // arithmetic: `canonical_json_bytes` sorts every object key recursively, so
    // `body` sorts before `schema`, and the body is neither a prefix nor a
    // suffix of the document encoding.
    let body = canonical_json_bytes(&record.document.body)
        .map_err(|_| ReadbackRefusal::gap("readback.owner.encoding", None))?;
    let body_length = body.len();
    let offset = body_coordinates(&bytes, &body)?;

    let admitted = SourceRevisionHandle {
        source_id: owner_label(&record.record_id)?,
        revision: owner_label(&record.revision)?,
        content_sha256: receipt.document_digest.clone(),
        byte_length,
    };
    // The excerpt digest is derived from the LOCATED owned slice, so the gate
    // compares two independent encodings of the same owned bytes by content.
    let anchor = SourceAnchorHandle {
        anchor_id: owner_label(&record.record_id)?,
        byte_offset: bounded_u64(offset)?,
        byte_length: bounded_u64(body_length)?,
        excerpt_sha256: sha256_hex(&bytes[offset..offset + body_length]),
        native_mapping: None,
    };
    let request = ReadbackRequest {
        admitted: admitted.clone(),
        view,
        workspace_revision,
        fence: fence.clone(),
        anchor,
        preview: retrieval_preview(record, &admitted.revision)?,
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

/// Converts a located byte count back to the `u64` an anchor handle carries.
fn bounded_u64(value: usize) -> Result<u64, ReadbackRefusal> {
    u64::try_from(value).map_err(|_| ReadbackRefusal::gap("readback.source.length_overflow", None))
}

/// Builds the non-authoritative index/vector preview for this citation.
///
/// The preview is projected from the retrieval plans the SAME authenticated
/// owner read returned on this record — `CampaignSourceRecord::history_plans`,
/// which the store documents as "existing validated retrieval plans and bounded
/// results returned by the same owner read; plans are never synthesized from
/// task labels". Those plans are the real production index payload in this
/// tree, so this is a projection of real retrieval data rather than an empty
/// stand-in.
///
/// `claimed_revision` is the revision the PLAN's own recorded read fence names,
/// rendered in the same label space as the admitted revision so the gate can
/// compare the two by value. It is deliberately NOT copied from
/// `admitted_revision`: a preview that echoed the value it is checked against
/// could never drift, and the gate's `readback.preview.revision_drift` replan
/// would be unreachable code. Deriving the claim from the plan's fence makes it
/// an INDEPENDENT expected value, so a plan computed against a different
/// revision than the admitted one is detected as drift and the citation is
/// replanned instead of emitted.
///
/// The preview stays non-authoritative in every case: `IndexPreview::is_citable`
/// is `false` by contract, and these bytes are never spliced into the excerpt.
/// When a record carries no retrieval plan, or its plan cannot state which
/// revision it read, there is no index payload that can be shown honestly, so
/// the preview is empty and claims the admitted revision only as the identity it
/// would be shown under. An empty preview describes nothing and therefore has
/// nothing to drift.
fn retrieval_preview(
    record: &CampaignSourceRecord,
    admitted_revision: &str,
) -> Result<IndexPreview, ReadbackRefusal> {
    let Some(plan) = record.history_plans.first() else {
        return Ok(IndexPreview {
            bytes: Vec::new(),
            claimed_revision: admitted_revision.to_owned(),
            authority: PreviewAuthority::NonAuthoritativePreview,
        });
    };
    // A plan whose fence names no task revision cannot state which revision it
    // read. Substituting the admitted revision here would make the drift check
    // compare a value against itself, so no payload is shown at all rather than
    // shown under a fabricated identity. That is not a weakened gate: the
    // citation depends only on the verified readback, and a preview is never
    // cited, so a display artifact must not be able to veto it.
    let Some(observed) = plan.read_state_fence.task_revision else {
        return Ok(IndexPreview {
            bytes: Vec::new(),
            claimed_revision: admitted_revision.to_owned(),
            authority: PreviewAuthority::NonAuthoritativePreview,
        });
    };
    // The preview payload is the plan's own bounded result, canonically
    // encoded. It is a projection of retrieval data, not a substitute for the
    // admitted document, and it is never cited. An oversized preview is a typed
    // gap rather than a silently truncated payload: a truncated preview would
    // describe bytes the retrieval plan never emitted.
    let bytes = canonical_json_bytes(&plan.plan)
        .map_err(|_| ReadbackRefusal::gap("readback.preview.encoding", None))?;
    if bytes.len() > eliot_context_contracts::MAX_PREVIEW_BYTES {
        return Err(ReadbackRefusal::gap("readback.preview.too_large", None));
    }
    Ok(IndexPreview {
        bytes,
        claimed_revision: owner_label(&CampaignOwnerRevision::Task(observed))?,
        authority: PreviewAuthority::NonAuthoritativePreview,
    })
}

/// Locates the cited unit's exact coordinates inside the canonical document.
///
/// The coordinate is FOUND, not computed. `canonical_json_bytes` sorts every
/// object key recursively, so `CampaignSourceDocument { schema, schema_version,
/// body }` encodes as `{"body":{...},"schema":...,"schema_version":1}`: the
/// body is neither a prefix nor a suffix, and subtracting its length from the
/// document length would address the envelope's trailing bytes.
///
/// The body encoding must occur EXACTLY ONCE. Zero occurrences means the
/// encoded document is not the one this body came from (`unresolvable`); more
/// than one means the sub-slice is ambiguous and no unique anchor exists
/// (`ambiguous`). Both are typed gaps: the gate never falls back to an
/// approximate coordinate, because an approximate coordinate is precisely a
/// citation to convenient bytes.
fn body_coordinates(document: &[u8], body: &[u8]) -> Result<usize, ReadbackRefusal> {
    let mut found = None;
    let mut search = document;
    while let Some(index) = find_subslice(search, body) {
        let absolute = document.len() - search.len() + index;
        if found.is_some() {
            return Err(ReadbackRefusal::gap("readback.anchor.ambiguous", None));
        }
        found = Some(absolute);
        search = &search[index + 1..];
    }
    found.ok_or_else(|| ReadbackRefusal::gap("readback.anchor.unresolvable", None))
}

/// Returns the index of the first occurrence of `needle` in `haystack`.
///
/// An empty needle has no meaningful location and reports no match rather than
/// offset zero, so an empty cited unit can never be treated as located.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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
