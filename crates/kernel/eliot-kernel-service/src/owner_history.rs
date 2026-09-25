//! Kernel-served canonical revocation-history projection (issues #2100/#686).
//!
//! Architecture traceability: the Kernel owns Authority Epochs, fencing,
//! and ORS (kernel/AGENTS.md); I6.15 revocation is lazy and
//! reverse-reachable with the fence committed in Kernel/ORS first. This
//! module projects the DURABLE closure-fence state the Kernel already
//! committed — fenced grant-closure rows plus the per-root revision
//! watermark — into the closed `GetAuthorityRevocationHistory` payload the
//! Governor decision edge decodes. No `SurrealDB`, no second history owner,
//! no caller-supplied closure: the store catalogue truthfully still lists
//! the operation unsupported because the store never serves it; the Kernel
//! serves its own fence state over the existing named-read channel.
//!
//! Provenance honesty, enforced in code:
//!
//! - only `Fenced` closure rows project: activation (`Active`) closures
//!   never appear as revocations;
//! - the invalidation reason is always `SourceRevoked`: the Kernel fences
//!   exclusively Governor-enumerated closures, so every served fence is a
//!   revoked source lineage — never an invented cause;
//! - the affected set comes verbatim from the committed closure row (the
//!   complete denominator, never re-derived);
//! - the served rows plus the revision watermark are read under one
//!   durable snapshot as one bounded selected set; a closure newer than
//!   the watermark refuses instead of serving a partial view, and a
//!   selected set larger than the request bound refuses instead of
//!   truncating (overflow is never partial);
//! - an empty matched set with a present watermark attests zero recorded
//!   revocations at that revision; a missing watermark refuses because
//!   absence of history is not evidence.

use eliot_ors::{GrantClosureState, OpaqueLabel, OperationalRecoveryStore};
use eliot_security_contracts::RevocationReason;
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, REVOCATION_HISTORY_MAX_RECORDS,
    REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RevocationHistoryPayload, StoreError,
};

/// Serves one closed revocation-history view from durable Kernel fence
/// state.
///
/// `origin_ref` names a lineage root or one closure target grant;
/// `max_records` bounds the served closures. `session_fence` is the live
/// fence owned by the dispatch site (the authenticated
/// `session.module_generation.state_fence` proven by
/// `validate_store_session_fence` in
/// `bins/eliot-kernel/src/daemon_request_dispatch.rs` before this call):
/// the admitted request fence must agree with it, and the live fence is
/// echoed verbatim into the response; the Governor feed caller re-checks
/// it against its expected fence on decode.
///
/// # Errors
///
/// Returns [`StoreError::InvalidField`] for a malformed selector,
/// [`StoreError::PayloadTooLarge`] for an over-bound request or an
/// overflowing selected set, [`StoreError::FenceMismatch`] for a request
/// fence that disagrees with the live session fence,
/// [`StoreError::InvalidProjection`] for incoherent durable rows,
/// [`StoreError::ReceiptNotFound`] when no history exists for the
/// origin, [`StoreError::Unavailable`] for a transient store failure,
/// and [`StoreError::UnknownOperation`] for any other operation. Store
/// integrity conflicts stay integrity-visible (`InvalidProjection`):
/// they are never reported as transient.
#[allow(
    clippy::too_many_lines,
    reason = "the history projector keeps selectors, scan, filter, currency, overflow, and envelope in one audited sequence"
)]
pub fn serve_authority_revocation_history(
    store: &dyn OperationalRecoveryStore,
    request: &NamedReadRequest,
    session_fence: &eliot_contracts::StateFence,
) -> Result<NamedReadResponse, StoreError> {
    if request.operation != NamedReadOperation::GetAuthorityRevocationHistory {
        return Err(StoreError::UnknownOperation);
    }
    if request.state_fence != *session_fence {
        return Err(StoreError::FenceMismatch);
    }
    let fence = session_fence;
    let origin_ref = request
        .parameters
        .get("origin_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "history read requires a string origin_ref",
        })?;
    if origin_ref.trim().is_empty()
        || origin_ref.chars().any(char::is_control)
        || origin_ref.len() > 1_024
    {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "origin_ref must be a bounded non-blank string",
        });
    }
    let bound_raw = request
        .parameters
        .get("max_records")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "history read requires a string max_records bound",
        })?;
    let max_records: u32 = bound_raw.parse().map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "max_records must be a positive decimal bound",
    })?;
    if max_records == 0 {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must be a positive decimal bound",
        });
    }
    if max_records > REVOCATION_HISTORY_MAX_RECORDS {
        return Err(StoreError::PayloadTooLarge);
    }
    // The whole selected set plus its per-root revision watermark comes
    // from the store under one durable snapshot, so the served view is
    // self-consistent with no paging cursor and no cross-page torn
    // views. The store bound below is the request bound itself: an
    // oversize selected set refuses early instead of decoding a whole
    // lineage only to discard it, and unrelated rows never count
    // against it, so an unrelated lineage can never disable this view.
    let lineage = OpaqueLabel::new(origin_ref).map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "origin_ref must be a bounded non-blank string",
    })?;
    let bound = u16::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)?;
    let (selected, watermark) = store
        .scan_grant_closures_for_lineage(&lineage, bound)
        .map_err(|error| match error {
            eliot_ors::OrsError::IntegrityProblem { .. }
            | eliot_ors::OrsError::DuplicateConflict => StoreError::InvalidProjection,
            eliot_ors::OrsError::ProjectionLimitExceeded => StoreError::PayloadTooLarge,
            _ => StoreError::Unavailable,
        })?;
    let mut matched: Vec<RecordedRevocation> = Vec::new();
    let mut resolved_root: Option<String> = None;
    for projection in &selected {
        let commit = projection.commit();
        let target = commit.declaration.target_grant_id.as_str();
        let root = commit.declaration.authority_root_ref.as_str();
        if target != origin_ref && root != origin_ref {
            continue;
        }
        // Only fenced closures are revocation history. Activation
        // closures share the row kind and must never project as
        // revocations.
        if commit.state != GrantClosureState::Revoked {
            continue;
        }
        match &resolved_root {
            Some(known) if known != root => {
                return Err(StoreError::InvalidProjection);
            }
            Some(_) => {}
            None => resolved_root = Some(root.to_owned()),
        }
        let mut dependents: Vec<String> = commit
            .declaration
            .members
            .iter()
            .map(|member| member.grant_id.clone())
            .collect();
        dependents.sort();
        dependents.dedup();
        let record = RecordedRevocation {
            closure_id: commit.operation_id.as_str().to_owned(),
            root_ref: target.to_owned(),
            dependent_refs: dependents,
            invalidation_reason: RevocationReason::SourceRevoked,
            revision: commit.declaration.grant_graph_revision,
        };
        record.validate()?;
        matched.push(record);
    }
    // The rows and the watermark above share the one snapshot that
    // served the selected set: an empty matched set with a present
    // watermark attests zero recorded revocations at its revision; a
    // missing watermark refuses because absence of history is not
    // evidence.
    let Some(watermark) = watermark else {
        return Err(StoreError::ReceiptNotFound);
    };
    if matched.is_empty() {
        // No fenced closure names this origin (`resolved_root` is set on
        // every pushed match, so an empty set means none matched).
        return history_response(fence, origin_ref, watermark, Vec::new());
    }
    if matched.len() > usize::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)? {
        return Err(StoreError::PayloadTooLarge);
    }
    matched.sort_by(|left, right| left.closure_id.cmp(&right.closure_id));
    // Currency: every served closure must sit at or below the durable
    // per-root watermark; a newer row refuses instead of serving a view
    // whose revision cannot name it.
    for record in &matched {
        if record.revision == 0 || record.revision > watermark {
            return Err(StoreError::InvalidProjection);
        }
    }
    history_response(fence, origin_ref, watermark, matched)
}

/// Renders the closed history payload plus the typed response envelope.
/// The payload revalidates before return so a malformed view can never be
/// served, even if constructed from valid parts.
fn history_response(
    fence: &eliot_contracts::StateFence,
    origin_ref: &str,
    source_revision: u64,
    mut closures: Vec<RecordedRevocation>,
) -> Result<NamedReadResponse, StoreError> {
    closures.sort_by(|left, right| left.closure_id.cmp(&right.closure_id));
    let payload = RevocationHistoryPayload {
        version: REVOCATION_HISTORY_PAYLOAD_VERSION,
        origin_ref: origin_ref.to_owned(),
        source_revision,
        closures,
    };
    payload.validate()?;
    let value = serde_json::to_value(&payload).map_err(|_| StoreError::InvalidField {
        field: "payload",
        reason: "revocation-history payload is not encodable",
    })?;
    Ok(NamedReadResponse {
        operation: NamedReadOperation::GetAuthorityRevocationHistory,
        state_fence: fence.clone(),
        revision_heads: Vec::new(),
        payload: value,
    })
}
