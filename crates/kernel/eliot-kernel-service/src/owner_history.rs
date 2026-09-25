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
//!
//! [`grant_closure_canonical_links`] is the sibling read for the canonical
//! second phase of the same durable rows. The revocation-history payload above
//! is a frozen store contract and deliberately carries no receipt identity, so
//! the completed second phase is projected as its own closed, versioned
//! daemon-facing payload instead of being folded into a shape other owners
//! already froze.

use eliot_ors::{GrantClosureState, OpaqueLabel, OperationalRecoveryStore};
use eliot_receipts::ReceiptIdentity;
use eliot_security_contracts::RevocationReason;
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, REVOCATION_HISTORY_MAX_RECORDS,
    REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RevocationHistoryPayload, StoreError,
};

/// Closed payload version of the canonical second-phase link projection.
///
/// The version is part of the served contract: a reader that does not know
/// this value refuses the view instead of guessing a shape.
pub const GRANT_CLOSURE_CANONICAL_LINKS_VERSION: u32 = 1;

/// Closed selector for one lineage root's completed canonical second phases.
///
/// `state_fence` is a named field rather than a sibling argument because that
/// is the whole hazard this read removes: the selector set and the fence it is
/// served under are one fact about one read, and a caller cannot present a
/// selector for one fence while the Kernel proves another.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureCanonicalLinksQuery {
    /// The exact fence the read must be served and proved under.
    pub state_fence: eliot_contracts::StateFence,
    /// Lineage root whose committed closures are read.
    pub authority_root_ref: String,
    /// Bounded number of committed closures read from one durable snapshot.
    pub max_records: u32,
}

/// One committed canonical second phase, projected from the immutable ORS
/// second-phase record that owns the exact `ReceiptIdentity`.
///
/// The link names the immutable first-phase closure operation; the first-phase
/// commit bytes are never rewritten by the second phase, so the served pair is
/// the only honest durable form of "this closure completed canonical
/// reconciliation".
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureCanonicalLink {
    /// Immutable first-phase closure operation identity.
    pub closure_operation_id: String,
    /// The exact Store-issued canonical receipt identity linked to it.
    pub canonical_receipt: ReceiptIdentity,
}

/// The daemon-facing canonical second-phase view for one authority root.
///
/// An absent link is an explicitly pending second phase, not an empty
/// collection of receipts: the payload carries every committed closure of the
/// root through the durable revision watermark, so a reader can tell "no
/// second phase completed here yet" from "this root has no committed closure
/// state at all".
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureCanonicalLinks {
    /// Payload shape version (see [`GRANT_CLOSURE_CANONICAL_LINKS_VERSION`]).
    pub version: u32,
    /// The exact authority root this view describes.
    pub authority_root_ref: String,
    /// The durable per-root revision watermark the view was read under.
    pub grant_graph_revision: u64,
    /// Completed canonical second phases, ordered by closure operation identity.
    pub links: Vec<GrantClosureCanonicalLink>,
}

impl GrantClosureCanonicalLinks {
    /// Revalidates the closed served shape.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidProjection`] for an unknown version, a
    /// blank root, a zero or non-monotonic revision, a duplicate or
    /// out-of-order closure identity, an unusable operation identity, or a
    /// canonical receipt that fails its own identity contract, and
    /// [`StoreError::PayloadTooLarge`] for an over-bound link set.
    pub fn validate(&self, max_records: u32) -> Result<(), StoreError> {
        if self.version != GRANT_CLOSURE_CANONICAL_LINKS_VERSION
            || self.authority_root_ref.trim().is_empty()
            || self.grant_graph_revision == 0
        {
            return Err(StoreError::InvalidProjection);
        }
        if self.links.len() > usize::try_from(max_records).unwrap_or(usize::MAX) {
            return Err(StoreError::PayloadTooLarge);
        }
        let mut previous: Option<&str> = None;
        for link in &self.links {
            eliot_ors::OperationIdentity::new(&link.closure_operation_id)
                .map_err(|_| StoreError::InvalidProjection)?;
            if !canonical_receipt_identity_is_usable(&link.canonical_receipt) {
                return Err(StoreError::InvalidProjection);
            }
            if previous.is_some_and(|seen| seen >= link.closure_operation_id.as_str()) {
                return Err(StoreError::InvalidProjection);
            }
            previous = Some(&link.closure_operation_id);
        }
        Ok(())
    }
}

/// Reports whether one canonical receipt identity is complete and bounded
/// enough to be served or linked.
///
/// `eliot_receipts` keeps `ReceiptIdentity::validate` crate-private, so the
/// served-shape gate states the same rules here instead of trusting a decoded
/// value: a bounded non-blank receipt id and a lowercase 64-hex canonical
/// digest. The authoritative check stays the ORS link read-back performed by
/// the Kernel owner binding.
fn canonical_receipt_identity_is_usable(receipt: &ReceiptIdentity) -> bool {
    let receipt_id = receipt.receipt_id.as_str();
    !receipt_id.trim().is_empty()
        && !receipt_id.chars().any(char::is_control)
        && receipt.canonical_sha256.len() == 64
        && receipt
            .canonical_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

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

/// Projects the completed canonical second phases of one authority root from
/// the same durable ORS closure state the history projector reads
/// (`#2100`/`R6`).
///
/// This is the read side of the canonical second phase. The Kernel commits the
/// immutable first-phase closure row and the canonical receipt identity into
/// two separate ORS records; the revocation-history projection above cannot
/// carry the second one, so a daemon that never reads it can never complete a
/// second phase and can never learn that one already completed. The projection
/// closes exactly that gap:
///
/// - the whole selected set plus the per-root revision watermark is read under
///   one durable snapshot, so the served links are self-consistent and never
///   cross-page torn;
/// - a missing watermark refuses, because absence of committed closure state
///   is not an empty set of completed second phases;
/// - only committed revocations with a linked second phase project; a pending
///   phase stays absent instead of becoming an invented receipt;
/// - the first-phase `canonical_receipt` cross-reference must agree with the
///   served second phase, so an incoherent pair stays integrity-visible;
/// - the served revision must name every served closure, exactly as the
///   history projector requires.
///
/// `session_fence` is the live fence owned by the dispatch site: the query
/// fence must equal it, and the served watermark is the revision the view was
/// read under. The Kernel owns ORS in its own process; the daemon only reads
/// the projection and never the store.
///
/// # Errors
///
/// Returns the same typed store failures as
/// [`serve_authority_revocation_history`]: [`StoreError::InvalidField`] for a
/// malformed selector, [`StoreError::PayloadTooLarge`] for an over-bound
/// request or an overflowing selected set, [`StoreError::FenceMismatch`] for
/// a query fence that disagrees with the live session fence,
/// [`StoreError::InvalidProjection`] for incoherent durable rows,
/// [`StoreError::ReceiptNotFound`] when no committed closure state exists for
/// the root, and [`StoreError::Unavailable`] for a transient store failure.
pub fn grant_closure_canonical_links(
    store: &dyn OperationalRecoveryStore,
    query: &GrantClosureCanonicalLinksQuery,
    session_fence: &eliot_contracts::StateFence,
) -> Result<GrantClosureCanonicalLinks, StoreError> {
    if query.state_fence != *session_fence {
        return Err(StoreError::FenceMismatch);
    }
    let origin_ref = query.authority_root_ref.as_str();
    if origin_ref.trim().is_empty()
        || origin_ref.chars().any(char::is_control)
        || origin_ref.len() > 1_024
    {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "authority_root_ref must be a bounded non-blank string",
        });
    }
    if query.max_records == 0 || query.max_records > REVOCATION_HISTORY_MAX_RECORDS {
        return Err(StoreError::PayloadTooLarge);
    }
    let label = OpaqueLabel::new(origin_ref).map_err(|_| StoreError::InvalidField {
        field: "operation.parameter",
        reason: "authority_root_ref must be a bounded non-blank string",
    })?;
    let bound = u16::try_from(query.max_records).map_err(|_| StoreError::PayloadTooLarge)?;
    let (selected, watermark) = store
        .scan_grant_closures_for_lineage(&label, bound)
        .map_err(|error| match error {
            eliot_ors::OrsError::IntegrityProblem { .. }
            | eliot_ors::OrsError::DuplicateConflict => StoreError::InvalidProjection,
            eliot_ors::OrsError::ProjectionLimitExceeded => StoreError::PayloadTooLarge,
            _ => StoreError::Unavailable,
        })?;
    // The same rule the history projector applies: a missing watermark refuses
    // instead of serving a view whose revision cannot name its rows.
    let Some(watermark) = watermark else {
        return Err(StoreError::ReceiptNotFound);
    };
    let mut links: Vec<GrantClosureCanonicalLink> = Vec::new();
    for projection in &selected {
        let commit = projection.commit();
        if commit.state != GrantClosureState::Revoked
            || commit.declaration.authority_root_ref.as_str() != origin_ref
        {
            continue;
        }
        if commit.declaration.grant_graph_revision == 0
            || commit.declaration.grant_graph_revision > watermark
        {
            return Err(StoreError::InvalidProjection);
        }
        // A pending second phase is absent, never an invented receipt.
        let Some(canonical_receipt) = projection.second_phase() else {
            continue;
        };
        // The immutable first phase carries the same link; a disagreement is
        // store incoherence, not a recoverable view.
        if commit.canonical_receipt.as_ref() != Some(canonical_receipt) {
            return Err(StoreError::InvalidProjection);
        }
        links.push(GrantClosureCanonicalLink {
            closure_operation_id: commit.operation_id.clone(),
            canonical_receipt: canonical_receipt.clone(),
        });
    }
    links.sort_by(|left, right| left.closure_operation_id.cmp(&right.closure_operation_id));
    let payload = GrantClosureCanonicalLinks {
        version: GRANT_CLOSURE_CANONICAL_LINKS_VERSION,
        authority_root_ref: origin_ref.to_owned(),
        grant_graph_revision: watermark,
        links,
    };
    payload.validate(query.max_records)?;
    Ok(payload)
}
