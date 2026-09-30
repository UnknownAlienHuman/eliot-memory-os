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
//!
//! Issue #2966, step 2: every served row declares the full versioned
//! evidence coordinates, computed here from the durable material through
//! the one shared canonical codec (`eliot_security_contracts`), so the
//! decoding adapter carries them verbatim and recovery recomputes and
//! compares them:
//!
//! - the owner namespace is the committed declaration's own authority
//!   root, never the request selector echoed back;
//! - the bounds are the engine limits the committed membership was proven
//!   under. The Governor emits a declaration only under
//!   `RevocationBounds::default_bounds()` (its complete-verdict gate), so
//!   that standing fact is what this projector declares, pinned by the
//!   wire version: a commit path proven under different bounds needs a new
//!   wire version, never a silent shift;
//! - the disposition is `Complete` with no omissions, because only
//!   honestly-complete committed closures are ever recorded (the N3 gate
//!   refuses a partial verdict, consumes every quarantine binding into a
//!   separate receipt, and keeps quarantined identities out of `members`);
//! - the affected-member count and digest and the canonical request hash
//!   are the content addresses of exactly these served bytes. They bind
//!   the decode-to-restore path: any adapter mistranslation breaks the
//!   digest at validation instead of being re-blessed.
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
//!
//! [`serve_grant_closure_receipt`] and [`commit_grant_closure_canonical_link`]
//! complete that second phase over the front door. The read half answers one
//! exact target grant from the same bound P-07 owner that committed the first
//! phase, and the write half records the link against the same durable ORS
//! first-phase row the read half projects. Neither invents a closure: the read
//! refuses when the owner holds no committed receipt, and the link refuses when
//! the store holds no committed first phase, so an unestablished outcome stays
//! an unestablished outcome instead of an empty or synthesized value.

use eliot_influence::RevocationBounds;
use eliot_kernel_core::GrantActivationPort;
use eliot_ors::{GrantClosureProjection, GrantClosureState, OpaqueLabel, OperationalRecoveryStore};
use eliot_receipts::{GrantClosureReceipt, ReceiptIdentity};
use eliot_security_contracts::{
    InfluenceState, REVOCATION_DISPOSITION_COMPLETE, REVOCATION_HISTORY_EVIDENCE_VERSION,
    RevocationClosureDigestBounds, RevocationClosureDigestInput, RevocationReason,
    revocation_affected_members, revocation_affected_members_digest,
    revocation_closure_canonical_digest,
};
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, REVOCATION_HISTORY_MAX_RECORDS,
    REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RecordedRevocationBounds,
    RecordedRevocationDisposition, RevocationHistoryPayload, StoreError,
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
        // Issue #2966, step 2: the row declares every coordinate the
        // versioned evidence binds, through the one shared canonical
        // codec. The decoding adapter carries them verbatim and recovery
        // recomputes and compares them; an unaddressable membership is
        // unprojectable, never defaulted.
        let affected = revocation_affected_members(target, &dependents);
        let affected_member_digest =
            revocation_affected_members_digest(&affected).ok_or(StoreError::InvalidProjection)?;
        // The Governor emits a declaration only under these engine limits
        // (its complete-verdict gate), so this standing fact is what the
        // row declares. The wire and digest views map it independently, so
        // a mistranslation breaks the digest instead of shifting the
        // bounds silently; a commit path proven under different bounds
        // needs a new wire version.
        let engine_bounds = RevocationBounds::default_bounds();
        let bounds = RecordedRevocationBounds {
            max_nodes: engine_bounds.max_nodes,
            max_edges: engine_bounds.max_edges,
            max_depth: engine_bounds.max_depth,
            max_result: engine_bounds.max_result,
            max_work: engine_bounds.max_work,
            max_frontier: engine_bounds.max_frontier,
            max_time: engine_bounds.max_time,
        };
        let omissions: Vec<String> = Vec::new();
        let closure_id = commit.operation_id.as_str().to_owned();
        let revision = commit.declaration.grant_graph_revision;
        let canonical_request_digest =
            revocation_closure_canonical_digest(&RevocationClosureDigestInput {
                evidence_version: REVOCATION_HISTORY_EVIDENCE_VERSION,
                closure_id: &closure_id,
                owner_namespace: root,
                root_ref: target,
                dependent_refs: &dependents,
                invalidation_reason: Some(RevocationReason::SourceRevoked),
                current_influence: InfluenceState::Revoked,
                state_fence: fence,
                revision,
                bounds: RevocationClosureDigestBounds {
                    max_nodes: engine_bounds.max_nodes,
                    max_edges: engine_bounds.max_edges,
                    max_depth: engine_bounds.max_depth,
                    max_result: engine_bounds.max_result,
                    max_work: engine_bounds.max_work,
                    max_frontier: engine_bounds.max_frontier,
                    max_time: engine_bounds.max_time,
                },
                disposition: REVOCATION_DISPOSITION_COMPLETE,
                omissions: &omissions,
                affected_member_count: affected.len() as u64,
                affected_member_digest: &affected_member_digest,
            })
            .ok_or(StoreError::InvalidProjection)?;
        let record = RecordedRevocation {
            closure_id,
            root_ref: target.to_owned(),
            dependent_refs: dependents,
            invalidation_reason: RevocationReason::SourceRevoked,
            revision,
            owner_namespace: root.to_owned(),
            bounds,
            disposition: RecordedRevocationDisposition::Complete,
            omissions,
            current_influence: InfluenceState::Revoked,
            affected_member_count: affected.len() as u64,
            affected_member_digest,
            canonical_request_digest,
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

/// Closed selector for one target grant's committed closure receipt.
///
/// `state_fence` is a named field for the same reason
/// [`GrantClosureCanonicalLinksQuery`] carries one: the selector and the fence
/// it is served under are one fact about one read, so a caller cannot present a
/// target under a fence the Kernel does not prove.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureReceiptQuery {
    /// The exact fence the read must be served and proved under.
    pub state_fence: eliot_contracts::StateFence,
    /// The exact committed closure target grant whose receipt is read.
    pub target_grant_id: String,
}

/// Closed selector for the canonical second-phase link of one committed
/// closure operation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClosureCanonicalLinkRequest {
    /// The exact fence the link must be committed and proved under.
    pub state_fence: eliot_contracts::StateFence,
    /// Immutable first-phase closure operation identity.
    pub closure_operation_id: String,
    /// The exact canonical receipt identity to link to that first phase.
    pub canonical_receipt: ReceiptIdentity,
}

/// Serves one committed `GrantClosureReceipt` verbatim from the bound P-07
/// owner that committed it (issue #686).
///
/// This is the read half of the canonical closure second phase. The daemon
/// never reads the Kernel's P-07 owner directly, so without this route the
/// revocation ingress on the far side of the transport can never learn whether
/// a first phase committed for the grant it is revoking. The value is resolved
/// through the owner's own committed closure index
/// (`eliot_kernel_core::GrantActivationPort::closure_receipt_for_target`),
/// which restart rehydration repopulates from the durable ORS rows — the same
/// owner the completed-link projection above reads. It is returned exactly as
/// committed: no field is defaulted, inferred, or re-derived, and no digest is
/// recomputed here.
///
/// `session_fence` is the live fence owned by the dispatch site: the query
/// fence must equal it before the owner is consulted at all.
///
/// # Errors
///
/// Returns [`StoreError::FenceMismatch`] for a query fence that disagrees with
/// the live session fence, [`StoreError::InvalidField`] for a malformed target
/// grant identity, [`StoreError::ReceiptNotFound`] when the owner holds no
/// committed closure for that target — an unestablished outcome, never an empty
/// closure — [`StoreError::Receipt`] when the owner's committed value fails its
/// own receipt contract, and [`StoreError::InvalidProjection`] when the
/// committed receipt does not name the presented target.
pub fn serve_grant_closure_receipt(
    owner: &GrantActivationPort,
    query: &GrantClosureReceiptQuery,
    session_fence: &eliot_contracts::StateFence,
) -> Result<GrantClosureReceipt, StoreError> {
    if query.state_fence != *session_fence {
        return Err(StoreError::FenceMismatch);
    }
    let grant_id = query.target_grant_id.as_str();
    if grant_id.trim().is_empty()
        || grant_id.chars().any(char::is_control)
        || grant_id.len() > 1_024
    {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "target_grant_id must be a bounded non-blank string",
        });
    }
    let receipt = owner
        .closure_receipt_for_target(grant_id)
        .ok_or(StoreError::ReceiptNotFound)?;
    // The ORIGINAL recorded value revalidates under its own receipt contract.
    receipt.validate().map_err(StoreError::Receipt)?;
    if receipt.declaration.target_grant_id != grant_id {
        return Err(StoreError::InvalidProjection);
    }
    Ok(receipt)
}

/// Records the canonical second-phase receipt link for one already committed
/// closure operation, against the one durable ORS store that owns the
/// immutable first-phase row (issue #686).
///
/// This is the write half of the same saga. It delegates to
/// `eliot_ors::OperationalRecoveryStore::link_grant_closure_canonical_receipt`
/// — the owner call `eliot_kernel_core`'s durable owner bootstrap already makes
/// when it links an owner bundle — and never rewrites the first-phase commit
/// bytes. The durable read-back then proves the same three facts the far side
/// re-verifies: the returned projection commits the presented operation
/// identity, its durable second phase IS the presented canonical receipt, and
/// the first phase's own optional link never contradicts it. An identical link
/// is idempotent; a different identity is an immutable refusal.
///
/// `session_fence` is the live fence owned by the dispatch site: the request
/// fence must equal it before the store is touched.
///
/// # Errors
///
/// Returns [`StoreError::FenceMismatch`] for a request fence that disagrees
/// with the live session fence, [`StoreError::InvalidField`] for an unusable
/// closure operation or canonical receipt identity,
/// [`StoreError::ReceiptNotFound`] when no first phase committed for that
/// operation, [`StoreError::InvalidProjection`] for an immutable conflict or an
/// incoherent read-back, [`StoreError::PayloadTooLarge`] for an over-bound
/// refusal, [`StoreError::Receipt`] when the committed first phase fails its
/// own receipt contract, and [`StoreError::Unavailable`] for a transient store
/// failure, which stays unestablished instead of being read as a completed
/// link.
pub fn commit_grant_closure_canonical_link(
    store: &dyn OperationalRecoveryStore,
    request: &GrantClosureCanonicalLinkRequest,
    session_fence: &eliot_contracts::StateFence,
) -> Result<GrantClosureProjection, StoreError> {
    if request.state_fence != *session_fence {
        return Err(StoreError::FenceMismatch);
    }
    let operation_id =
        eliot_ors::OperationIdentity::new(&request.closure_operation_id).map_err(|_| {
            StoreError::InvalidField {
                field: "operation.parameter",
                reason: "closure_operation_id must be a bounded non-blank string",
            }
        })?;
    if !canonical_receipt_identity_is_usable(&request.canonical_receipt) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "canonical_receipt must carry a bounded receipt id and a lowercase 64-hex canonical digest",
        });
    }
    let projection = OperationalRecoveryStore::link_grant_closure_canonical_receipt(
        store,
        &operation_id,
        &request.canonical_receipt,
    )
    .map_err(|error| closure_link_store_error(&error))?;
    let commit = projection.commit();
    if commit.operation_id != operation_id.as_str()
        || projection.second_phase() != Some(&request.canonical_receipt)
        || commit
            .canonical_receipt
            .as_ref()
            .is_some_and(|first_phase| first_phase != &request.canonical_receipt)
    {
        return Err(StoreError::InvalidProjection);
    }
    // The ORIGINAL committed first-phase bytes revalidate under their own
    // receipt contract; nothing here recomputes an integrity digest.
    commit.validate().map_err(StoreError::Receipt)?;
    Ok(projection)
}

/// Maps one ORS refusal on the canonical second-phase link to the typed store
/// failure, keeping determinate contract conflicts integrity-visible rather
/// than transient.
fn closure_link_store_error(error: &eliot_ors::OrsError) -> StoreError {
    match error {
        eliot_ors::OrsError::IntegrityProblem { .. }
        | eliot_ors::OrsError::DuplicateConflict
        | eliot_ors::OrsError::ReconciliationMismatch
        | eliot_ors::OrsError::InboxIntegrityMismatch
        | eliot_ors::OrsError::Contract(_) => StoreError::InvalidProjection,
        eliot_ors::OrsError::ReservationNotFound => StoreError::ReceiptNotFound,
        eliot_ors::OrsError::ProjectionLimitExceeded | eliot_ors::OrsError::PayloadTooLarge => {
            StoreError::PayloadTooLarge
        }
        _ => StoreError::Unavailable,
    }
}
