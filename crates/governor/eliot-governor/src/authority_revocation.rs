//! Governor-owned authority-revocation recording and history decoding.
//!
//! Transitive influence revocation (issue #686) is enforced in the shipped
//! authority graph without a second graph, ledger, or authority machine:
//!
//! * recording: the Governor emits the canonical `RecordAuthorityRevocation`
//!   transition through [`authority_revocation_envelope`], following the
//!   `AppendAuditEvent` / `ReconcileRecovery` envelope pattern (closed
//!   owner-approved parameters, `RecoverySchema` / `ReversibleMutation`,
//!   Governor scope, generated-catalogue manifest digest). `eliot-authority`
//!   stays the pure decision owner and never emits transitions.
//! * reading: the Governor reads CURRENT revocation history through the
//!   `GetAuthorityRevocationHistory` named read built by
//!   [`revocation_history_read_request`] and decodes the store reply into
//!   typed evidence with [`decode_revocation_history_evidence`]. Only
//!   actually recorded revocations under the exact response fence are
//!   returned; unknown or partial outcomes can never appear in the decoded
//!   evidence.
//! * restoring: [`AuthorityOwner::from_snapshot_with_revocation_history`]
//!   (in `authority_recovery.rs`) applies that evidence before any grant
//!   becomes effective; missing, stale, or unknown evidence refuses.
//! * reconciling: the two durable boundary traits
//!   [`GrantClosureCanonicalLinkPort`] and [`GrantClosureReceiptPort`] are
//!   implemented below over the owners that already exist in production — the
//!   one ORS store that holds the immutable first-phase closure row, and the
//!   one Kernel P-07 port that committed that row. Neither adapter is a
//!   second Store client, ledger, or authority machine: the link adapter
//!   delegates to the same `eliot_ors::OperationalRecoveryStore` call
//!   `eliot_kernel_core`'s durable owner bootstrap already makes, and the
//!   readback adapter delegates to that Kernel port's own committed-closure
//!   index. Both answer with durable evidence or a typed
//!   [`KernelPortError`]; neither synthesizes a receipt.
//!
//!   Both ports are transport-neutral: every type in their signatures is
//!   reachable from a daemon-side dependency set that holds no in-process ORS.
//!   The link arm therefore stays completable from the process that owns the
//!   revocation decision — over the authenticated transport to the Kernel,
//!   which owns ORS in its own process — instead of being nameable only by a
//!   Kernel-process type.
//!
//! Validation order (fail-closed): admitted [`RequestIdentity`] shape and
//! exact fence agreement first, then non-blank revocation binding fields
//! with nonzero revision/count, then the closed typed parameters. On the
//! return path [`canonical_receipt_identity`] issues a receipt identity only
//! from a write receipt that is itself `Committed` and whose receipt core
//! reports `Success`, so a possible, partial or unknown commit never becomes
//! the recorded revocation. Failure mapping reuses the existing
//! [`CompositionError`] variants (no new variant is introduced so the closed
//! matches elsewhere in this crate keep compiling):
//! identity/fence/response-binding mismatches are [`CompositionError::Provider`];
//! every other deterministic admission refusal is [`CompositionError::Owner`].
//!
//! Honest gaps: `RecordAuthorityRevocation` and
//! `GetAuthorityRevocationHistory` are known-but-unsupported at the store
//! catalogue gate until a store-owned slice activates their rows with
//! proven handlers (see `operation_catalogue`). The envelope therefore
//! binds the generated catalogue set digest so it passes that gate
//! unchanged once the row exists; until then commits fail closed with
//! `UnknownOperation`, never as silent success. The `scope:governor`
//! ordering-head expectation mirrors the operator/recovery precedent (the
//! store enforces the live sequence).

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_kernel_core::GrantActivationPort;
use eliot_ors::{OperationIdentity, OperationalRecoveryStore, OrsError};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    GrantClosureReceipt, GrantClosureState, ReceiptDispositionKind, ReceiptIdentity,
};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, InfluenceDependencyClosure, InfluenceState,
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId,
    ReadConsistency, RecordedRevocationDisposition, RevocationReason, ScopeId, SecurityContext,
    TransitionClass, WriteReceipt, WriteReceiptStatus, generated_operation_manifests,
    operation_manifest_set_digest, parse_revocation_history_payload,
};

use crate::{
    CompositionError, GrantClosureCanonicalLinkPort, GrantClosureReceiptPort,
    GrantClosureSecondPhaseLink, KernelPortError,
};
use eliot_authority::{
    AuthorityRevocationClosureEvidence, GrantRevocationRequest,
    REVOCATION_HISTORY_EVIDENCE_VERSION, RevocationEvidenceDisposition, RevocationHistoryEvidence,
};
use eliot_influence::RevocationBounds;

/// Governor scope reused from the observation/operator precedent; no new
/// scope is introduced for revocation recording.
const GOVERNOR_SCOPE_ID: &str = "governor";
/// Ordering scope reused from the observation/operator precedent.
const GOVERNOR_ORDERING_SCOPE: &str = "scope:governor";
/// Fixed semantic reason recorded after the Kernel has durably fenced a
/// closure and the canonical reconciliation envelope is built.
pub const AUTHORITY_REVOCATION_KERNEL_FIRST_REASON: &str = "KERNEL_REVOCATION_COMMITTED";

fn owner_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn identity_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Provider(detail.into())
}

/// Canonical digest helper for the revocation binding record.
fn canonical_digest(value: &impl serde::Serialize) -> Result<String, CompositionError> {
    let bytes = canonical_json_bytes(value).map_err(|error| {
        CompositionError::Owner(format!("cannot canonicalize revocation binding: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// Binds the generated catalogue set digest into the revocation envelope.
///
/// The digest covers the closed activated-operation table, so the envelope
/// passes the store pre-dispatch gate unchanged once the
/// `RecordAuthorityRevocation` row is activated by its owning slice.
fn catalogue_set_digest() -> Result<OperationManifestDigest, CompositionError> {
    let entries =
        generated_operation_manifests().map_err(|error| owner_refused(error.to_string()))?;
    operation_manifest_set_digest(&entries).map_err(|error| owner_refused(error.to_string()))
}

/// Builds the canonical authority-revocation envelope binding one exact
/// committed influence revocation.
///
/// The envelope reuses the exact identity types the store already keys on
/// (`operation_id`, the request metadata fence, and the idempotency key
/// from the admitted identity), so a later retry resolves through the
/// receipt route instead of re-admitting. The `RecordAuthorityRevocation`
/// parameters record the seven owner-approved revocation fields; ceilings
/// stay fixed at `RecoverySchema` / `ReversibleMutation` by construction.
/// `invalidation_reason` carries the terminal reason in its
/// `SCREAMING_SNAKE_CASE` wire spelling; `closure_revision` and
/// `affected_count` travel as decimal strings, mirroring how
/// `AppendAuditEvent` carries `expected_revision`.
#[allow(
    clippy::too_many_arguments,
    reason = "the envelope binds every recorded revocation identity explicitly; grouping them would hide a binding"
)]
pub fn authority_revocation_envelope(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    origin_ref: &str,
    closure_id: &str,
    closure_revision: u64,
    affected_digest: &str,
    affected_count: u64,
    invalidation_reason: &str,
    fence_digest: &str,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    identity
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    let fence = &identity.request.metadata.state_fence;
    if identity.request.state_fence != *fence {
        return Err(identity_refused(
            "admitted request fence does not match the request binding fence".to_owned(),
        ));
    }
    for (value, field) in [
        (origin_ref, "origin_ref"),
        (closure_id, "closure_id"),
        (affected_digest, "affected_digest"),
        (invalidation_reason, "invalidation_reason"),
        (fence_digest, "fence_digest"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(owner_refused(format!(
                "revocation {field} is blank or contains control characters"
            )));
        }
    }
    if closure_revision == 0 {
        return Err(owner_refused(
            "revocation closure revision must be non-zero".to_owned(),
        ));
    }
    if affected_count == 0 {
        return Err(owner_refused(
            "revocation affected count must be non-zero: the origin itself is always affected"
                .to_owned(),
        ));
    }
    let manifest_digest = catalogue_set_digest()?;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("origin_ref", origin_ref.to_owned()),
        ("closure_id", closure_id.to_owned()),
        ("closure_revision", closure_revision.to_string()),
        ("affected_digest", affected_digest.to_owned()),
        ("affected_count", affected_count.to_string()),
        ("invalidation_reason", invalidation_reason.to_owned()),
        ("fence_digest", fence_digest.to_owned()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        // #1925: this leg's stable intent is the owner-issued revocation
        // closure it commits. It is NOT derived from `operation_id` or from
        // the idempotency key, either of which rotates.
        write_intent_id: crate::write_intent::admission_write_intent(
            "authority-revocation-closure",
            &format!("{closure_id}@{closure_revision}"),
        )
        .ok_or_else(|| {
            owner_refused("revocation closure has no owner-issued subject to declare")
        })?,
        write_envelope_protocol_version:
            crate::write_intent::GOVERNOR_ADMISSION_WRITE_ENVELOPE_PROTOCOL_VERSION,
        scope_id: ScopeId::new(GOVERNOR_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordAuthorityRevocation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Returns the immutable canonical receipt identity produced by the Store
/// receipt envelope. A transport receipt without its reconciliation envelope
/// is not a source for a second-phase link.
///
/// The receipt is only evidence of a recorded revocation when the write it
/// describes actually committed. Two terminal dispositions are therefore
/// compared here, both against the ORIGINAL recorded values, before any
/// [`ReceiptIdentity`] exists:
///
/// * the transport status must be [`WriteReceiptStatus::Committed`]. That is
///   the one disposition the crate's own commit gate already requires
///   (`capability_evidence_commit`, `experience_commit`,
///   `learning_record_commit`) and the rule the Kernel's unknown-commit
///   classifier states: only `Committed` reconciles as committed, every other
///   terminal status is a known non-commit. `WriteReceipt::validate()` places
///   no such invariant — it accepts a reconciliation envelope on a `Rejected`,
///   `DeadLetter` or `Cancelled` receipt — so nothing downstream of this
///   function would refuse a write that never recorded the revocation.
/// * the receipt core's own disposition must be
///   [`ReceiptDispositionKind::Success`]. That is the exact disposition the
///   one store-owned issuer of a committed write's envelope
///   (`eliot_store_api::issue_store_receipt_envelope`) stamps, and the same
///   success-only rule `eliot_authority::effects` applies to a committed
///   effect. `ReceiptEnvelope::validate()` accepts `Partial`, `Failure`,
///   `Unknown` and `Cancelled` as internally well-formed, so a partial or
///   unknown canonical outcome would otherwise be linked to the durable
///   closure row and reported as a completed reconciliation.
///
/// A refusal here leaves the revocation saga's second phase unestablished, so
/// the caller retains the pending canonical handoff and the record stays
/// blocked. A possible commit can therefore never become a no-write, and a
/// non-commit is never re-presented as this operation's recorded result.
pub fn canonical_receipt_identity(
    receipt: &WriteReceipt,
) -> Result<ReceiptIdentity, CompositionError> {
    receipt.validate().map_err(|error| {
        identity_refused(format!("canonical write receipt is invalid: {error}"))
    })?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(identity_refused(format!(
            "canonical write receipt is not committed ({:?}); nothing was recorded under this \
             operation identity",
            receipt.status
        )));
    }
    let envelope = receipt.require_reconciliation_envelope().map_err(|error| {
        identity_refused(format!(
            "canonical write receipt has no exact reconciliation envelope: {error}"
        ))
    })?;
    if envelope.core.operation.operation_id != receipt.operation_id
        || envelope.core.operation.idempotency_key != receipt.idempotency_key
        || envelope.core.request.state_fence != receipt.state_fence
    {
        return Err(identity_refused(
            "canonical receipt envelope does not bind the durable write receipt".to_owned(),
        ));
    }
    if envelope.core.disposition.kind() != ReceiptDispositionKind::Success {
        return Err(identity_refused(format!(
            "canonical receipt envelope reports {:?}, not a committed outcome; a partial or \
             unknown result is not a recorded revocation",
            envelope.core.disposition.kind()
        )));
    }
    Ok(envelope.identity.clone())
}

/// Extends one built revocation envelope with the coordinates the durable
/// closure supplies and the seven-parameter record cannot carry.
///
/// The owner-approved `RecordAuthorityRevocation` parameter set is closed at
/// seven fields, so the bounds, completeness, receipt, and reconciliation
/// coordinates the record must bind travel through the two surfaces the
/// canonical envelope already hash-binds and the store already compares for
/// this exact operation: the typed
/// [`InfluenceDependencyClosure`](eliot_store_api::InfluenceDependencyClosure)
/// in `security`, the typed command parameters, and a proof-reference digest
/// for the remaining durable closure coordinates. These are inside the
/// envelope's canonical request view, so a replay
/// of this operation that presents a different closure conflicts at the store
/// instead of recording a second record under one identity.
///
/// Every coordinate is read from the ORIGINAL durable closure after that
/// closure's own `validate()` accepted it. Nothing is recomputed from
/// process-local state, defaulted, or invented:
///
/// * the typed closure repeats, field for field, what
///   [`RecordedRevocation`](eliot_store_api::RecordedRevocation) serves on the
///   read side — origin, affected set, terminal influence state, reason,
///   durable revision, and the exact State Fence — so the recording and
///   reading halves of this issue name the same closure the same way;
/// * the digest additionally covers the closure's own canonical request
///   digest, the Kernel-issued snapshot, authority epoch, transition receipt
///   identity and committed disposition, the store-issued canonical
///   reconciliation link (or its explicit absence while the second phase is
///   still pending), the declaration's proof ceiling and its preserved
///   alternate paths, and the bounded engine's traversal limits.
///
/// The traversal bounds are the crate's one admitted limit set
/// ([`RevocationBounds::default_bounds`]), validated here through the type's
/// own `validate()`. The durable closure receipt carries no per-closure bound
/// field, so this binds the standing limit set the closure's complete-verdict
/// gate runs under rather than a value supplied per closure.
///
/// Content identity for the durable closure coordinates that do not fit in
/// the closed seven-field revocation command. The digest remains a proof
/// reference in the envelope; the contract-set field is reserved for current
/// receiving-build support.
#[derive(serde::Serialize)]
struct DurableRevocationCoordinates<'a> {
    operation_id: &'a str,
    idempotency_key: &'a str,
    closure_request_digest: &'a str,
    origin_ref: &'a str,
    closure_id: &'a str,
    closure_revision: &'a str,
    affected_digest: &'a str,
    affected_count: &'a str,
    invalidation_reason: &'a str,
    fence_digest: &'a str,
    snapshot_id: &'a str,
    authority_epoch: &'a eliot_contracts::EpochId,
    authority_receipt_id: &'a str,
    authority_receipt_state: GrantClosureState,
    canonical_receipt: Option<&'a ReceiptIdentity>,
    proof_ceiling: eliot_receipts::ProofCeiling,
    declaration_proof_ceiling: eliot_receipts::ProofCeiling,
    preserved: &'a [eliot_receipts::GrantClosureAlternatePath],
    bounds: &'a RevocationBounds,
}
///
/// Proves every owner-approved field the revocation record carries is the
/// durable closure's own recorded value.
///
/// The record is bound to THIS closure, not merely to a closure that happens to
/// name the same operation: each recorded field is compared against the
/// closure it claims to bind, and the expected affected set is the durable
/// declaration read back here rather than a second copy of a caller list. The
/// ORIGINAL closure is validated through its own `validate()`; nothing is
/// recomputed from process-local state.
fn require_recorded_fields_bind_closure(
    envelope: &CanonicalWriteEnvelope,
    closure: &GrantClosureReceipt,
) -> Result<(), CompositionError> {
    closure
        .validate()
        .map_err(|error| owner_refused(format!("durable grant closure is invalid: {error}")))?;
    if closure.state != GrantClosureState::Revoked
        || closure.authority_receipt.state != GrantClosureState::Revoked
    {
        return Err(owner_refused(
            "canonical revocation reconciliation requires a committed revoked closure".to_owned(),
        ));
    }
    let command = envelope
        .semantic_commands
        .first()
        .ok_or_else(|| owner_refused("revocation envelope carries no named command".to_owned()))?;
    let recorded = |name: &str| -> Result<String, CompositionError> {
        command
            .parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                owner_refused(format!(
                    "revocation record carries no {name} binding parameter"
                ))
            })
    };
    let durable_affected = closure.declaration.affected_grants();
    if recorded("origin_ref")? != closure.declaration.authority_root_ref
        || recorded("closure_id")? != closure.operation_id
        || recorded("closure_revision")? != closure.declaration.grant_graph_revision.to_string()
        || recorded("affected_digest")? != canonical_digest(&durable_affected)?
        || recorded("affected_count")? != durable_affected.len().to_string()
        || recorded("fence_digest")? != canonical_digest(&closure.authority.state_fence)?
    {
        return Err(identity_refused(
            "recorded revocation fields do not bind the durable closure they claim".to_owned(),
        ));
    }
    Ok(())
}

fn bind_durable_closure_coordinates(
    envelope: &mut CanonicalWriteEnvelope,
    closure: &GrantClosureReceipt,
) -> Result<(), CompositionError> {
    require_recorded_fields_bind_closure(envelope, closure)?;
    let bounds = RevocationBounds::default_bounds();
    bounds.validate().map_err(|error| {
        owner_refused(format!("revocation traversal bounds are invalid: {error}"))
    })?;
    // The typed closure repeats, field for field, what the recorded history row
    // serves on the read side, so the recording and reading halves name the
    // same closure the same way: origin, affected set, terminal influence
    // state, reason, durable revision, and the exact State Fence.
    let influence_closure = InfluenceDependencyClosure {
        closure_id: closure.operation_id.clone(),
        root_ref: closure.declaration.target_grant_id.clone(),
        dependent_refs: closure.declaration.affected_grants(),
        invalidation_reason: Some(RevocationReason::SourceRevoked),
        current_influence: InfluenceState::Revoked,
        state_fence: closure.authority.state_fence.clone(),
        revision: closure.declaration.grant_graph_revision,
    };
    influence_closure.validate().map_err(|error| {
        owner_refused(format!(
            "durable revocation influence closure is invalid: {error}"
        ))
    })?;
    if influence_closure.state_fence != envelope.request.state_fence {
        return Err(identity_refused(
            "durable closure fence disagrees with the recorded revocation request".to_owned(),
        ));
    }
    let affected = closure.declaration.affected_grants();
    let affected_digest = canonical_digest(&affected)?;
    let fence_digest = canonical_digest(&closure.authority.state_fence)?;
    let closure_revision = closure.declaration.grant_graph_revision.to_string();
    let affected_count = affected.len().to_string();
    let closure_coordinates_digest = canonical_digest(&DurableRevocationCoordinates {
        operation_id: envelope.operation_id.as_str(),
        idempotency_key: envelope.idempotency_key.as_str(),
        closure_request_digest: &closure.idempotency_digest,
        origin_ref: &closure.declaration.authority_root_ref,
        closure_id: &closure.operation_id,
        closure_revision: &closure_revision,
        affected_digest: &affected_digest,
        affected_count: &affected_count,
        invalidation_reason: AUTHORITY_REVOCATION_KERNEL_FIRST_REASON,
        fence_digest: &fence_digest,
        snapshot_id: &closure.authority_receipt.snapshot_id,
        authority_epoch: &closure.authority_receipt.authority_epoch,
        authority_receipt_id: &closure.authority_receipt.receipt_id,
        authority_receipt_state: closure.authority_receipt.state,
        canonical_receipt: closure.canonical_receipt.as_ref(),
        proof_ceiling: closure.proof_ceiling,
        declaration_proof_ceiling: closure.declaration.proof_ceiling,
        preserved: &closure.declaration.preserved,
        bounds: &bounds,
    })?;
    envelope.admission_contract_set_digest =
        eliot_canonical::supported_admission_contract_set_digest()?;
    envelope
        .required_proof_and_approval_refs
        .push(closure_coordinates_digest);
    envelope.security.influence_closure = Some(influence_closure);
    // The envelope was already valid once; the durable binding added fields to
    // two hash-bound surfaces, so it is re-validated rather than trusted.
    envelope.validate()?;
    Ok(())
}

/// Builds the canonical second-phase revocation envelope from one already
/// committed Kernel closure. Every value used for the affected-set digest,
/// revision, root, and fence is read from the durable closure; no closure
/// member, digest, or receipt is synthesized from process-local state. The
/// durable closure additionally supplies the bounds, completeness, receipt,
/// and reconciliation coordinates through
/// [`bind_durable_closure_coordinates`], so the record carries every
/// coordinate the replayability requirement names.
pub fn authority_revocation_envelope_from_closure(
    identity: &RequestIdentity,
    canonical_operation_id: &OperationId,
    closure: &GrantClosureReceipt,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    closure
        .validate()
        .map_err(|error| owner_refused(format!("durable grant closure is invalid: {error}")))?;
    if closure.state != GrantClosureState::Revoked
        || closure.authority_receipt.state != GrantClosureState::Revoked
    {
        return Err(owner_refused(
            "canonical revocation reconciliation requires a committed revoked closure".to_owned(),
        ));
    }
    if closure.authority.state_fence != identity.request.metadata.state_fence {
        return Err(identity_refused(
            "durable closure fence disagrees with the canonical revocation request".to_owned(),
        ));
    }
    let affected = closure.declaration.affected_grants();
    let affected_digest = canonical_digest(&affected)?;
    let fence_digest = canonical_digest(&closure.authority.state_fence)?;
    let mut envelope = authority_revocation_envelope(
        identity,
        canonical_operation_id,
        &closure.declaration.authority_root_ref,
        &closure.operation_id,
        closure.declaration.grant_graph_revision,
        &affected_digest,
        affected.len() as u64,
        AUTHORITY_REVOCATION_KERNEL_FIRST_REASON,
        &fence_digest,
    )?;
    bind_durable_closure_coordinates(&mut envelope, closure)?;
    Ok(envelope)
}

/// Builds the typed `GetAuthorityRevocationHistory` named read for one
/// exact revoked origin.
///
/// The request carries the exact `origin_ref` selector and the explicit
/// `max_records` bound; scope is the Governor scope, mirroring the
/// `GetEvidencePack` scope declaration the future catalogue row follows.
/// The reply must be decoded with
/// [`decode_revocation_history_evidence`]; the request alone proves
/// nothing.
pub fn revocation_history_read_request(
    state_fence: &eliot_contracts::StateFence,
    origin_ref: &str,
    max_records: u32,
) -> Result<NamedReadRequest, CompositionError> {
    state_fence
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    if origin_ref.trim().is_empty() || origin_ref.chars().any(char::is_control) {
        return Err(owner_refused(
            "revocation history origin_ref is blank or contains control characters".to_owned(),
        ));
    }
    if max_records == 0 {
        return Err(owner_refused(
            "revocation history max_records must be a positive decimal bound".to_owned(),
        ));
    }
    if max_records > eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS {
        return Err(owner_refused(
            "revocation history max_records exceeds the advertised bound".to_owned(),
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "origin_ref".to_owned(),
        serde_json::Value::String(origin_ref.to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(max_records.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetAuthorityRevocationHistory,
        scope_id: Some(
            ScopeId::new(GOVERNOR_SCOPE_ID).map_err(|error| owner_refused(error.to_string()))?,
        ),
        consistency: ReadConsistency::Eventual,
        state_fence: state_fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| owner_refused(error.to_string()))?;
    Ok(request)
}

/// Decodes one `GetAuthorityRevocationHistory` reply into typed
/// revocation-history evidence.
///
/// The reply must name the history operation and the exact expected fence;
/// its payload must be a well-formed [`parse_revocation_history_payload`]
/// view. Every recorded row carries the response fence. Currency
/// (CURRENT vs stale/unknown) is enforced at restore by
/// [`AuthorityOwner::from_snapshot_with_revocation_history`](crate::AuthorityOwner::from_snapshot_with_revocation_history),
/// not here.
///
/// #2966 step 2: each row is translated into the authority-specific
/// versioned evidence, not into the shared `eliot-influence` observation
/// DTO. The translation carries every producer-declared coordinate
/// verbatim — owner namespace, bounds, disposition, omissions, influence
/// state, affected-member count and digest, and the canonical request
/// hash — and mints none of them: the durable producer computed them from
/// the served bytes through the one shared canonical codec, and recovery
/// recomputes and compares them, so any mistranslation here breaks the
/// digest at validation instead of being re-blessed. The only value this
/// adapter names is the evidence version, which the v2 wire rows carry
/// field-for-field: filling a newer evidence shape from these rows would
/// fail to compile, never silently upgrade. A v1 payload carries no
/// producer coordinates and is refused at parse, never reinterpreted.
///
/// `expected_origin_ref` is the exact `origin_ref` selector the read was
/// issued for (see [`revocation_history_read_request`]), and the served
/// payload must echo it back. The echoed selector is the ONLY thing that
/// names the origin of an EMPTY closure set, and an empty set at a nonzero
/// `source_revision` is a positive attestation of zero recorded
/// revocations; without this comparison a view served for another origin
/// decodes as this origin's attestation and reads as proof that nothing was
/// revoked. Per-closure `root_ref`/`owner_namespace` comparisons cannot
/// cover that case, because a wrong-origin empty view carries no closure
/// to compare. The selector is therefore bound here, at the one adapter
/// that materializes the view, rather than at each downstream consumer.
pub fn decode_revocation_history_evidence(
    response: &NamedReadResponse,
    expected_fence: &eliot_contracts::StateFence,
    expected_origin_ref: &str,
) -> Result<RevocationHistoryEvidence, CompositionError> {
    if response.operation != NamedReadOperation::GetAuthorityRevocationHistory {
        return Err(owner_refused(
            "revocation history response names a different operation".to_owned(),
        ));
    }
    response
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    if response.state_fence != *expected_fence {
        return Err(identity_refused(
            "revocation history response is not bound to the expected fence".to_owned(),
        ));
    }
    let payload = parse_revocation_history_payload(&response.payload).map_err(|error| {
        owner_refused(format!("revocation history payload is malformed: {error}"))
    })?;
    if payload.origin_ref != expected_origin_ref {
        return Err(identity_refused(
            "revocation history view was served for a different origin".to_owned(),
        ));
    }
    let mut closures = Vec::with_capacity(payload.closures.len());
    for row in payload.closures {
        // The admitted bounds are the bounds the evidence declared: mapped
        // field-for-field from the served row and re-validated, never
        // minted. A mapping slip breaks the canonical digest at restore.
        let bounds = RevocationBounds {
            max_nodes: row.bounds.max_nodes,
            max_edges: row.bounds.max_edges,
            max_depth: row.bounds.max_depth,
            max_result: row.bounds.max_result,
            max_work: row.bounds.max_work,
            max_frontier: row.bounds.max_frontier,
            max_time: row.bounds.max_time,
        };
        bounds.validate().map_err(|error| {
            owner_refused(format!("revocation history bounds are invalid: {error}"))
        })?;
        let disposition = match row.disposition {
            RecordedRevocationDisposition::Complete => RevocationEvidenceDisposition::Complete,
            RecordedRevocationDisposition::Partial => RevocationEvidenceDisposition::Partial,
            RecordedRevocationDisposition::Unknown => RevocationEvidenceDisposition::Unknown,
        };
        closures.push(AuthorityRevocationClosureEvidence {
            evidence_version: REVOCATION_HISTORY_EVIDENCE_VERSION,
            closure_id: row.closure_id,
            owner_namespace: row.owner_namespace,
            root_ref: row.root_ref,
            dependent_refs: row.dependent_refs,
            invalidation_reason: Some(row.invalidation_reason),
            current_influence: row.current_influence,
            state_fence: response.state_fence.clone(),
            commit_state_fence: row.commit_state_fence,
            revision: row.revision,
            bounds,
            disposition,
            omissions: row.omissions,
            affected_member_count: row.affected_member_count,
            affected_member_digest: row.affected_member_digest,
            canonical_request_digest: row.canonical_request_digest,
        });
    }
    Ok(RevocationHistoryEvidence {
        state_fence: response.state_fence.clone(),
        source_revision: payload.source_revision,
        closures,
    })
}

/// Maps one ORS refusal on the canonical second-phase link to the typed
/// Governor port failure, keeping the store's own reason.
///
/// The first-phase closure row is immutable, so a duplicate operation
/// identity carrying a different receipt, a reconciliation that does not
/// exactly bind its evidence, or a broken inbox binding is a determinate
/// contract conflict rather than an unestablished outcome. Every other
/// refusal leaves the outcome unknown at this boundary and is reported as
/// such; it is never read as a completed link and never retried blindly.
fn closure_link_error(error: OrsError) -> KernelPortError {
    let reason = error.to_string();
    match error {
        OrsError::DuplicateConflict
        | OrsError::ReconciliationMismatch
        | OrsError::InboxIntegrityMismatch
        | OrsError::Contract(_) => {
            KernelPortError::Contract(format!("ORS refused the closure link: {reason}"))
        }
        other => KernelPortError::Unknown(format!(
            "canonical closure link outcome is unestablished at the ORS boundary: {other}"
        )),
    }
}

/// Production second-phase link adapter over the one ORS store that owns the
/// immutable first-phase closure row.
///
/// This is the Governor-side implementation of
/// [`GrantClosureCanonicalLinkPort`]. It delegates to
/// `eliot_ors::OperationalRecoveryStore::link_grant_closure_canonical_receipt`
/// — the same owner call `eliot_kernel_core`'s durable owner bootstrap makes
/// when it links an owner bundle — and then proves the read-back before it
/// returns. The proof is the conjunction of that owner-side check and the
/// composition-level saga check: the committed operation identity, the durable
/// second-phase link, and the first-phase receipt's own canonical link must all
/// agree with the presented identity. A store that answers with a different
/// identity or an absent link is a typed [`KernelPortError`], never a success
/// and never a rewritten first phase.
///
/// It returns the neutral [`GrantClosureSecondPhaseLink`] rather than the
/// in-process `eliot_ors::GrantClosureProjection`: the ORS projection's
/// lifecycle phase, operation order and store receipt are operational evidence
/// no Governor proof or caller reads, while the three facts the saga actually
/// proves — the committed `GrantClosureReceipt` and the linked
/// `ReceiptIdentity` — are store-neutral and are copied out verbatim. That is
/// what lets a transport client with no in-process ORS implement the same port
/// from the far side of the authenticated transport.
impl GrantClosureCanonicalLinkPort for Arc<dyn OperationalRecoveryStore> {
    fn link_grant_closure_canonical_receipt(
        &self,
        operation_id: &str,
        canonical_receipt: &ReceiptIdentity,
    ) -> Result<GrantClosureSecondPhaseLink, KernelPortError> {
        // The typed ORS operation identity is rebuilt here, from the ORIGINAL
        // recorded first-phase bytes the caller presents, because this is the
        // boundary that calls the store. `OperationIdentity::new` applies the
        // bounded non-blank/control-character check the neutral port signature
        // cannot express, so the constraint is enforced rather than dropped; an
        // unusable identity is a determinate contract refusal, not a link.
        let operation_id = OperationIdentity::new(operation_id).map_err(|error| {
            KernelPortError::Contract(format!(
                "unusable grant closure operation identity: {error}"
            ))
        })?;
        let projection = OperationalRecoveryStore::link_grant_closure_canonical_receipt(
            self.as_ref(),
            &operation_id,
            canonical_receipt,
        )
        .map_err(closure_link_error)?;
        let commit = projection.commit();
        if commit.operation_id != operation_id.as_str()
            || projection.second_phase() != Some(canonical_receipt)
            || commit
                .canonical_receipt
                .as_ref()
                .is_some_and(|first_phase| first_phase != canonical_receipt)
        {
            return Err(KernelPortError::Contract(
                "canonical closure receipt link read-back disagrees".to_owned(),
            ));
        }
        // The ORIGINAL committed first-phase bytes, copied verbatim out of the
        // owner's own read-back. The first-phase row is not edited here; only
        // the second-phase link was added, above, by the store itself.
        Ok(GrantClosureSecondPhaseLink::new(
            commit.clone(),
            canonical_receipt.clone(),
        ))
    }
}

/// Production closure-readback adapter over the one Kernel P-07 port that
/// committed the first phase.
///
/// This is the Governor-side implementation of [`GrantClosureReceiptPort`].
/// It resolves the request's target grant through that port's own committed
/// closure index (`eliot_kernel_core::GrantActivationPort::closure_receipt_for_target`),
/// which restart rehydration repopulates from the durable ORS rows, and then
/// proves the returned receipt binds the presented request. A grant with no
/// committed closure is an unestablished outcome, and a receipt that names a
/// different target, snapshot, or State Fence is a determinate binding
/// conflict. No closure is ever fabricated, defaulted, or inferred from the
/// request: the only accepted value is the one the port already committed.
impl GrantClosureReceiptPort for GrantActivationPort {
    fn grant_closure_receipt(
        &self,
        request: &GrantRevocationRequest,
    ) -> Result<GrantClosureReceipt, KernelPortError> {
        let closure = self
            .closure_receipt_for_target(request.grant_id.as_str())
            .ok_or_else(|| {
                KernelPortError::Unknown(format!(
                    "no committed grant closure is bound to target grant {}; the first P-07 \
                     phase has not committed for this request",
                    request.grant_id.as_str()
                ))
            })?;
        if closure.declaration.target_grant_id != request.grant_id.as_str()
            || closure.authority_receipt.snapshot_id != request.snapshot_id.as_str()
            || !closure
                .authority_receipt
                .authority_epoch
                .is_same_authority(&request.binding.state_fence.authority_epoch)
            || closure.authority.state_fence != request.binding.state_fence
        {
            return Err(KernelPortError::Contract(
                "committed grant closure does not bind the presented revocation request".to_owned(),
            ));
        }
        Ok(closure)
    }
}

#[cfg(test)]
mod authority_revocation_tests {
    #![allow(clippy::expect_used)]
    use std::num::NonZeroU64;

    use super::*;
    use eliot_authority::{
        AuthoritySet, CapabilityGrant, EffectAuthorizer, GrantGraph, GrantId, GrantStatus,
        LogicalTime, PrincipalRef, RevocationOperationIdentity,
    };
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, ReceiptId, RequestId,
        RequestMetadata, ResourceGeneration, SessionId, SourceId, StateFence, TaskId,
        TransactionSequence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
    use eliot_store_api::{
        REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RevocationHistoryPayload,
    };

    use crate::{AuthorityOwner, AuthorityOwnerSnapshot};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
    }

    /// The admitted revocation operation identity the history-bound restore is
    /// handed alongside its evidence. `AuthorityOwner` holds no plan, scope
    /// binding or Store readback of its own, so it derives none of these five
    /// coordinates; a fixture must hand it one that survives
    /// [`RevocationOperationIdentity::admit`] — every text coordinate non-blank
    /// and a causal `transaction_sequence` present. It reuses this module's own
    /// principal, scope and naming family, and no test asserts anything about
    /// this value.
    fn operation() -> RevocationOperationIdentity {
        RevocationOperationIdentity::admit(
            "principal:root",
            TaskId::new("task:governor-revocation-1").expect("task id"),
            GOVERNOR_ORDERING_SCOPE,
            ReceiptId::new("receipt-revoke-1").expect("receipt id"),
            ClockReading {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_000),
                transaction_sequence: Some(TransactionSequence::genesis()),
                monotonic_ns: None,
            },
        )
        .expect("fixture revocation operation identity is admitted")
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-revoke-1").expect("request id"),
            session_id: Some(SessionId::new("session-revoke-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-revoke-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-revoke-1".to_owned(),
        }
    }

    fn operation_id() -> OperationId {
        OperationId::new("op-revoke-1").expect("operation id")
    }

    fn grant_snapshot(fence: &StateFence) -> eliot_authority::GrantGraphRecoverySnapshot {
        let binding = AuthorityBinding {
            authority_id: ContractId::new("authority:test").expect("contract"),
            authority_owner: "G-01".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        let origin = CapabilityGrant {
            grant_id: GrantId::new("grant:origin").expect("id"),
            parent_grant_id: None,
            authority_root_ref: "root:alpha".to_owned(),
            issuer: PrincipalRef::new("principal:root").expect("issuer"),
            holder: PrincipalRef::new("principal:child").expect("holder"),
            authority: AuthoritySet::new(
                ["read".to_owned(), "write".to_owned()],
                ["resource:a".to_owned(), "resource:b".to_owned()],
                EffectClass::ExternalEffect,
            )
            .expect("authority"),
            inherited_source_ceiling: None,
            binding: binding.clone(),
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        };
        let child = CapabilityGrant {
            grant_id: GrantId::new("grant:child").expect("id"),
            parent_grant_id: Some(GrantId::new("grant:origin").expect("parent")),
            authority_root_ref: "root:alpha".to_owned(),
            issuer: PrincipalRef::new("principal:child").expect("issuer"),
            holder: PrincipalRef::new("principal:leaf").expect("holder"),
            authority: AuthoritySet::new(
                ["read".to_owned()],
                ["resource:a".to_owned()],
                EffectClass::Read,
            )
            .expect("authority"),
            inherited_source_ceiling: None,
            binding,
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        };
        GrantGraph::from_grants([origin, child], 7)
            .expect("graph")
            .recovery_snapshot()
            .expect("snapshot")
    }

    fn owner_snapshot(fence: &StateFence) -> AuthorityOwnerSnapshot {
        let effect_authorizer = EffectAuthorizer::default().snapshot().expect("authorizer");
        AuthorityOwnerSnapshot::new(fence.clone(), grant_snapshot(fence), effect_authorizer)
            .expect("owner snapshot")
    }

    fn param(envelope: &CanonicalWriteEnvelope, name: &str) -> Option<String> {
        envelope
            .semantic_commands
            .first()
            .and_then(|command| command.parameters.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    #[test]
    fn revocation_envelope_carries_the_closed_seven_field_command() {
        let fence = fence();
        let envelope = authority_revocation_envelope(
            &identity(&fence),
            &operation_id(),
            "root:alpha",
            "revocation-686-01",
            9,
            &"a".repeat(64),
            3,
            "SOURCE_REVOKED",
            &"b".repeat(64),
        )
        .expect("envelope builds");
        assert_eq!(envelope.transition_class, TransitionClass::RecoverySchema);
        assert_eq!(
            envelope.requested_effect_ceiling,
            EffectClass::ReversibleMutation
        );
        assert_eq!(envelope.semantic_commands.len(), 1);
        assert_eq!(
            envelope.semantic_commands[0].operation,
            NamedMutationOperation::RecordAuthorityRevocation
        );
        assert_eq!(
            param(&envelope, "origin_ref").as_deref(),
            Some("root:alpha")
        );
        assert_eq!(
            param(&envelope, "closure_id").as_deref(),
            Some("revocation-686-01")
        );
        assert_eq!(param(&envelope, "closure_revision").as_deref(), Some("9"));
        assert_eq!(
            param(&envelope, "affected_digest").as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(param(&envelope, "affected_count").as_deref(), Some("3"));
        assert_eq!(
            param(&envelope, "invalidation_reason").as_deref(),
            Some("SOURCE_REVOKED")
        );
        assert_eq!(
            param(&envelope, "fence_digest").as_deref(),
            Some("b".repeat(64).as_str())
        );
        let entries = generated_operation_manifests().expect("catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest");
        assert_eq!(envelope.operation_manifest_digest, set_digest);
    }

    #[test]
    fn revocation_envelope_refuses_blank_zero_and_drifted_bindings() {
        let fence = fence();
        let identity = identity(&fence);
        let operation = operation_id();
        for (origin, closure, revision, count) in [
            ("", "revocation-686-01", 9, 3),
            ("root:alpha", "", 9, 3),
            ("root:alpha", "revocation-686-01", 0, 3),
            ("root:alpha", "revocation-686-01", 9, 0),
        ] {
            assert!(
                authority_revocation_envelope(
                    &identity,
                    &operation,
                    origin,
                    closure,
                    revision,
                    &"a".repeat(64),
                    count,
                    "SOURCE_REVOKED",
                    &"b".repeat(64),
                )
                .is_err(),
                "blank origin/closure, zero revision, or zero count must refuse"
            );
        }
        let mut drifted = identity.clone();
        drifted.request.state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            authority_revocation_envelope(
                &drifted,
                &operation,
                "root:alpha",
                "revocation-686-01",
                9,
                &"a".repeat(64),
                3,
                "SOURCE_REVOKED",
                &"b".repeat(64),
            )
            .is_err(),
            "fence drift between binding and metadata must refuse"
        );
    }

    #[test]
    fn history_read_request_carries_exact_selectors() {
        let fence = fence();
        let request = revocation_history_read_request(&fence, "root:alpha", 8).expect("request");
        assert_eq!(
            request.operation,
            NamedReadOperation::GetAuthorityRevocationHistory
        );
        assert_eq!(
            request
                .parameters
                .get("origin_ref")
                .and_then(serde_json::Value::as_str),
            Some("root:alpha")
        );
        assert_eq!(
            request
                .parameters
                .get("max_records")
                .and_then(serde_json::Value::as_str),
            Some("8")
        );
        assert!(request.scope_id.is_some());
        assert!(revocation_history_read_request(&fence, "", 8).is_err());
        assert!(revocation_history_read_request(&fence, "root:alpha", 0).is_err());
        assert!(
            revocation_history_read_request(
                &fence,
                "root:alpha",
                eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS + 1
            )
            .is_err()
        );
    }

    /// One recorded closure as the durable history owner would have written
    /// it.
    ///
    /// `RecordedRevocation` carries the full producer-declared coordinate set
    /// (owner namespace, bounds, disposition, omissions, influence state,
    /// affected count/digest and canonical request digest), and recovery
    /// RECOMPUTES and compares the content-addressed ones. A fixture that
    /// omits or stubs them would refuse at decode for a reason unrelated to
    /// the case under test, so this declares every coordinate over the same
    /// membership it reports.
    fn recorded_revocation(root_ref: &str) -> RecordedRevocation {
        let dependent_refs = vec!["grant:child".to_owned(), "grant:origin".to_owned()];
        let affected = eliot_authority::AuthorityRevocationClosureEvidence::members_of(
            root_ref,
            &dependent_refs,
        );
        let affected_member_digest =
            eliot_authority::AuthorityRevocationClosureEvidence::affected_members_digest(&affected)
                .expect("recorded affected membership is addressable");
        let bounds = eliot_influence::RevocationBounds::default_bounds();
        let invalidation_reason = eliot_store_api::RevocationReason::SourceRevoked;
        let disposition = eliot_store_api::RecordedRevocationDisposition::Complete;
        let omissions: Vec<String> = Vec::new();
        let affected_member_count = affected.len() as u64;
        let recorded_bounds = recorded_bounds(&bounds);
        let canonical_request_digest =
            eliot_store_api::canonical_json_bytes(&recorded_revocation_preimage(
                root_ref,
                &dependent_refs,
                invalidation_reason,
                &recorded_bounds,
                disposition,
                &omissions,
                affected_member_count,
                &affected_member_digest,
            ))
            .map(|bytes| eliot_store_api::sha256_hex(&bytes))
            .expect("recorded revocation is addressable");
        RecordedRevocation {
            closure_id: "revocation-686-01".to_owned(),
            root_ref: root_ref.to_owned(),
            dependent_refs,
            invalidation_reason,
            revision: 9,
            commit_state_fence: fence(),
            owner_namespace: root_ref.to_owned(),
            bounds: recorded_bounds,
            disposition,
            omissions,
            current_influence: eliot_security_contracts::InfluenceState::Revoked,
            affected_member_count,
            affected_member_digest,
            canonical_request_digest,
        }
    }

    /// The recorded wire form of the engine's one standing bounds set.
    fn recorded_bounds(
        bounds: &eliot_influence::RevocationBounds,
    ) -> eliot_store_api::RecordedRevocationBounds {
        eliot_store_api::RecordedRevocationBounds {
            max_nodes: bounds.max_nodes,
            max_edges: bounds.max_edges,
            max_depth: bounds.max_depth,
            max_result: bounds.max_result,
            max_work: bounds.max_work,
            max_frontier: bounds.max_frontier,
            max_time: bounds.max_time,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the recorded closure preimage is exactly the producer-declared coordinate set the durable owner hashes"
    )]
    fn recorded_revocation_preimage<'a>(
        root_ref: &'a str,
        dependent_refs: &'a [String],
        invalidation_reason: eliot_store_api::RevocationReason,
        recorded_bounds: &'a eliot_store_api::RecordedRevocationBounds,
        disposition: eliot_store_api::RecordedRevocationDisposition,
        omissions: &'a [String],
        affected_member_count: u64,
        affected_member_digest: &'a str,
    ) -> impl serde::Serialize + 'a {
        #[derive(serde::Serialize)]
        struct Preimage<'a> {
            evidence_version: u16,
            closure_id: &'a str,
            owner_namespace: &'a str,
            root_ref: &'a str,
            dependent_refs: &'a [String],
            invalidation_reason: eliot_store_api::RevocationReason,
            current_influence: eliot_security_contracts::InfluenceState,
            state_fence: eliot_contracts::StateFence,
            commit_state_fence: eliot_contracts::StateFence,
            revision: u64,
            bounds: eliot_store_api::RecordedRevocationBounds,
            disposition: &'a str,
            omissions: &'a [String],
            affected_member_count: u64,
            affected_member_digest: &'a str,
        }
        Preimage {
            evidence_version: REVOCATION_HISTORY_EVIDENCE_VERSION as u16,
            closure_id: "revocation-686-01",
            owner_namespace: root_ref,
            root_ref,
            dependent_refs,
            invalidation_reason,
            current_influence: eliot_security_contracts::InfluenceState::Revoked,
            state_fence: fence(),
            commit_state_fence: fence(),
            revision: 9,
            bounds: eliot_store_api::RecordedRevocationBounds {
                max_nodes: recorded_bounds.max_nodes,
                max_edges: recorded_bounds.max_edges,
                max_depth: recorded_bounds.max_depth,
                max_result: recorded_bounds.max_result,
                max_work: recorded_bounds.max_work,
                max_frontier: recorded_bounds.max_frontier,
                max_time: recorded_bounds.max_time,
            },
            disposition: match disposition {
                eliot_store_api::RecordedRevocationDisposition::Complete => {
                    eliot_security_contracts::REVOCATION_DISPOSITION_COMPLETE
                }
                eliot_store_api::RecordedRevocationDisposition::Partial => {
                    eliot_security_contracts::REVOCATION_DISPOSITION_PARTIAL
                }
                eliot_store_api::RecordedRevocationDisposition::Unknown => {
                    eliot_security_contracts::REVOCATION_DISPOSITION_UNKNOWN
                }
            },
            omissions,
            affected_member_count,
            affected_member_digest,
        }
    }

    fn history_response(fence: &StateFence) -> NamedReadResponse {
        let payload = RevocationHistoryPayload {
            version: REVOCATION_HISTORY_PAYLOAD_VERSION,
            origin_ref: "root:alpha".to_owned(),
            source_revision: 9,
            closures: vec![recorded_revocation("root:alpha")],
        };
        NamedReadResponse {
            operation: NamedReadOperation::GetAuthorityRevocationHistory,
            state_fence: fence.clone(),
            revision_heads: Vec::new(),
            payload: serde_json::to_value(&payload).expect("payload"),
        }
    }

    #[test]
    fn decode_history_then_restore_suppresses_origin_and_child() {
        let fence = fence();
        let evidence =
            decode_revocation_history_evidence(&history_response(&fence), &fence, "root:alpha")
                .expect("decode");
        assert_eq!(evidence.source_revision, 9);
        assert_eq!(evidence.closures.len(), 1);
        let snapshot = owner_snapshot(&fence);
        let outcome = AuthorityOwner::from_snapshot_with_revocation_history(
            &snapshot,
            &fence,
            Some(&evidence),
            &operation(),
        )
        .expect("current evidence restores");
        let suppressed: Vec<&str> = outcome
            .suppressed
            .iter()
            .map(|entry| entry.grant_id.as_str())
            .collect();
        assert_eq!(suppressed, ["grant:child", "grant:origin"]);
        let restored = outcome.owner.snapshot().expect("re-emit");
        assert_eq!(
            restored.grant_graph.revoked,
            ["grant:child".to_owned(), "grant:origin".to_owned()]
        );
    }

    #[test]
    fn decode_rejects_wrong_operation_fence_and_version() {
        let fence = fence();
        let mut wrong_operation = history_response(&fence);
        wrong_operation.operation = NamedReadOperation::GetEvidencePack;
        assert!(
            decode_revocation_history_evidence(&wrong_operation, &fence, "root:alpha").is_err()
        );
        let other_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            decode_revocation_history_evidence(
                &history_response(&fence),
                &other_fence,
                "root:alpha"
            )
            .is_err()
        );
        let mut bad_version = history_response(&fence);
        bad_version.payload["version"] = serde_json::json!(999);
        assert!(decode_revocation_history_evidence(&bad_version, &fence, "root:alpha").is_err());
    }

    #[test]
    fn history_bound_restore_refuses_missing_and_stale_evidence() {
        let fence = fence();
        let snapshot = owner_snapshot(&fence);
        assert!(
            AuthorityOwner::from_snapshot_with_revocation_history(
                &snapshot,
                &fence,
                None,
                &operation()
            )
            .is_err(),
            "missing history blocks restoration"
        );
        let evidence =
            decode_revocation_history_evidence(&history_response(&fence), &fence, "root:alpha")
                .expect("decode");
        let other_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            AuthorityOwner::from_snapshot_with_revocation_history(
                &snapshot,
                &other_fence,
                Some(&evidence),
                &operation()
            )
            .is_err(),
            "stale fence blocks restoration"
        );
    }
}
