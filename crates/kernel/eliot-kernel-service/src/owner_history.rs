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
//! - the served revision is the durable per-root watermark read under the
//!   same snapshot as the served rows; a closure newer than the watermark
//!   refuses instead of serving a partial view, a watermark change across
//!   pages refuses instead of serving a torn view, and a matched set
//!   larger than the request bound refuses instead of truncating
//!   (overflow is never partial);
//! - an empty matched set with a present watermark attests zero recorded
//!   revocations at that revision; a missing watermark refuses because
//!   absence of history is not evidence.

use eliot_ors::{
    GrantClosureState, OpaqueLabel, OperationalRecoveryStore,
};
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, REVOCATION_HISTORY_MAX_RECORDS,
    REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RevocationHistoryPayload, StoreError,
};
use eliot_security_contracts::RevocationReason;

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
/// overflowing matched set, [`StoreError::FenceMismatch`] for a request
/// fence that disagrees with the live session fence,
/// [`StoreError::InvalidProjection`] for incoherent durable rows,
/// [`StoreError::ReceiptNotFound`] when no history exists for the
/// origin, [`StoreError::Unavailable`] for a concurrent mutation that
/// moves the per-root watermark mid-read, and
/// [`StoreError::UnknownOperation`] for any other operation.
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
    // Rows page per lineage from the store in operation order; every page
    // carries the per-root revision watermark read under the same durable
    // snapshot as its rows, so one page is self-consistent. A watermark
    // change across pages proves a concurrent mutation during the bounded
    // read and refuses instead of serving a torn view; unrelated rows
    // never count against the page bound, so an unrelated lineage can
    // never disable this view.
    let lineage = OpaqueLabel::new(origin_ref).map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "origin_ref must be a bounded non-blank string",
    })?;
    let mut after_order = 0u64;
    let mut matched: Vec<RecordedRevocation> = Vec::new();
    let mut resolved_root: Option<String> = None;
    let mut baseline_revision: Option<Option<u64>> = None;
    loop {
        let (page, watermark) = store
            .scan_grant_closures_for_lineage(&lineage, after_order, eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|_| StoreError::Unavailable)?;
        match baseline_revision {
            Some(baseline) if baseline != watermark => {
                return Err(StoreError::Unavailable);
            }
            Some(_) => {}
            None => baseline_revision = Some(watermark),
        }
        if page.is_empty() {
            break;
        }
        for projection in &page {
            after_order = after_order.max(projection.operation_order());
            let commit = projection.commit();
            let target = commit.target_id.as_str();
            let root = commit.authority_root.as_str();
            if target != origin_ref && root != origin_ref {
                continue;
            }
            // Only fenced closures are revocation history. Activation
            // closures share the row kind and must never project as
            // revocations.
            if commit.state != GrantClosureState::Fenced {
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
                .affected
                .iter()
                .map(|identity| identity.as_str().to_owned())
                .collect();
            dependents.sort();
            dependents.dedup();
            let record = RecordedRevocation {
                closure_id: commit.operation_id.as_str().to_owned(),
                root_ref: target.to_owned(),
                dependent_refs: dependents,
                invalidation_reason: RevocationReason::SourceRevoked,
                revision: commit.revision,
            };
            record.validate()?;
            matched.push(record);
        }
    }
    // The rows and the watermark below share the snapshots that served
    // the pages: an empty matched set with a present watermark attests
    // zero recorded revocations at its revision; a missing watermark
    // refuses because absence of history is not evidence.
    let Some(watermark) = baseline_revision.flatten() else {
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
    let value =
        serde_json::to_value(&payload).map_err(|_| StoreError::InvalidField {
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
