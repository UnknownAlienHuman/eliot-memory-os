//! Governor-owned durable capability-evidence commit path (issue #1773, I3.4).
//!
//! Integration seam: the capability-evidence registry is a **Governor-owned
//! view**, and the only way a qualifying record survives a daemon restart is the
//! single named Kernel mutation `RecordCapabilityEvidenceRecord`, invoked
//! through [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical).
//!
//! The closed wire shape (the deterministic `(skill_id, scope_key)` row
//! address, the opaque `record_json` document, the presented `record_digest`,
//! the asserted `expected_canonical_revision` CAS predecessor, and the
//! idempotency key) is owned by the `capability_evidence_store` seam module in
//! `eliot-store-api`
//! (`crates/storage/eliot-store-api/src/capability_evidence_store.rs`); the
//! constructors here build requests only through that seam's builders and never
//! invent a store operation.
//!
//! Envelope field provenance for [`commit_capability_evidence_record`] (every
//! field bound, none synthesized; mirrors `commit_learning_record`):
//!
//! ```text
//! operation_id            derived deterministically as
//!                         `capability-evidence-{skill_id}:{scope_key}:{record_digest}`
//!                         (stable across retries, unique per evidence
//!                         revision: the presented digest is the immutable
//!                         record identity)
//! request                 the caller-supplied request metadata, cloned verbatim
//! idempotency_key         the named request's deterministic key, checked equal
//!                         to the caller identity key
//! scope_id                caller-addressed scope carried into the envelope
//! task_id                 none: an evidence record is scope-addressed, never
//!                         task-bound
//! transition_class        CaptureCandidate; ceiling Candidate
//! admission_contract_set_digest
//!                         the current supported Store API admission contract
//!                         set; the record digest remains bound in the named
//!                         operation parameters and record identity
//! operation_manifest_digest
//!                         computed live from `generated_operation_manifests`
//! semantic_commands       the single named evidence command, guarded by
//!                         `reject_direct_capability_evidence_write` before use
//! event/projection/relation intents
//!                         empty: a durable evidence row is not a projection or
//!                         relation; the registry is a rebuildable view
//! security                default context: the record document travels inside
//!                         the command parameters, not the envelope security
//!                         block
//! required_proof_and_approval_refs
//!                         caller-supplied probe/observation refs, passed through
//! expected revision/ordering heads
//!                         caller-supplied live owner expectations, each bound to
//!                         the request fence
//! ```
//!
//! Owner-issued revision — and exactly where the value comes from.
//!
//! The canonical store arbitrates the evidence row's fenced revision under a
//! compare-and-set and issues `expected + 1`. **This module does not read that
//! value back from the store.** It re-derives the same arithmetic from the
//! predecessor the owner itself asserted, so the value the registry orders by is
//! correct only because it is a **store contract**, not because this module
//! observed the store.
//!
//! The two endpoints of that contract, both of which must issue exactly
//! `expected + 1`:
//!
//! * memory — `crates/storage/eliot-store-memory/src/lib.rs`
//!   `dispatch_apply_capability_evidence`, which refuses a stale predecessor with
//!   `StoreError::RevisionConflict` and then writes
//!   `expected_canonical_revision.checked_add(1)`;
//! * Surreal — `crates/storage/eliot-store-surreal-adapter/src/schema.rs`
//!   `TX_CAPABILITY_EVIDENCE_OWNER`, driven by
//!   `append_capability_evidence_owner_statements` in that crate's
//!   `apply/atomic_write.rs`, which throws `capability_evidence_cas_conflict` on a
//!   stale predecessor and binds `revision` to the same `expected + 1`.
//!
//! A provider that issued anything other than `expected + 1` would therefore
//! break the registry's ordering, and this code would not detect it: the
//! derivation and the store would disagree silently. That coupling is the price
//! of not adding a readback round trip on a path whose every commit is issued
//! from a record the owner itself just derived; it is stated here rather than
//! papered over. The readback half of the leg does exist and does not share this
//! weakness — the paged range read projects the store's own `revision` column,
//! so a hydrated record is ordered by the revision the store actually holds,
//! and the next commit's presented predecessor is that hydrated revision.
//!
//! Fail-closed checks before any commit: the named-operation guard, closed
//! parameter decode, request-identity validity, and idempotency agreement
//! between the caller identity and the named request key.
//!
//! Production caller status: **one, and it is a restriction, not a positive.**
//! The daemon startup attach (`bins/eliotd::daemon_runtime`'s
//! `hydrate_capability_evidence_view` site) applies the installation-scope
//! dependency change the Host admitted about the daemon's own served bytes and
//! then commits every record that change limited, through this path. It mints no
//! `probe_passed` and no `observed` record: a whole-tree search for
//! `RouteScopeFingerprint {` outside `#[cfg(test)]` still returns exactly two
//! sites, the legacy importer (which yields an all-`None` scope and a `declared`
//! status) and `ActualRouteReceipt::current_scope`, which itself needs an
//! `ActualRouteReceipt` that no production path supplies. The positive-minting
//! producer is still absent, and that absence is still recorded rather than
//! worked around.
//!
//! It does not block this leg. [`CapabilityRegistry::apply_scope_change`]'s
//! contract is to *narrow* a record, and narrowing needs no probe: it writes the
//! owner-issued change reference into the affected record's already-declared
//! `limitations_and_negative_evidence`. What that mutation was missing was
//! durability — an un-committed restriction is erased by a restart and the stale
//! evidence it limits can then be re-admitted. Committing it here is what closes
//! that direction, and it commits bytes the owner already had.
//!
//! The readback half of this path is live today: the daemon's complete paged
//! drain runs at startup and rebuilds the registry from whatever the store
//! actually holds, so a restriction committed by this leg is re-derived in a
//! fresh process from the served `limitations_and_negative_evidence` rather than
//! remembered.

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, StateFence};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OrderingHeadExpectation, RevisionHeadExpectation, ScopeId, SecurityContext, TransitionClass,
    WriteReceipt, WriteReceiptStatus, canonical_json_bytes, decode_capability_evidence_mutation,
    decode_instrument_registry_mutation, generated_operation_manifests,
    operation_manifest_set_digest, reject_direct_capability_evidence_write, sha256_hex,
};
use serde_json::Value;

use crate::capability_evidence::{
    CapabilityEvidenceRecord, OwnerEvidenceRevision, is_evidence_ref,
};
use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};

/// The exact wire address of one evidence row: the `(skill_id, scope_key)` row
/// address, the opaque record document, and the presented digest over it.
///
/// One implementation, so the committed `operation_id` and the deterministic
/// commit `idempotency_key` cannot disagree. Two derivations would be free to
/// drift, and a drift would not fail closed anywhere: it would simply address a
/// second row for the same record.
struct CapabilityEvidenceRowAddress {
    scope_key: String,
    record_json: String,
    record_digest: String,
}

/// Builds the exact durable row address of one evidence record.
///
/// The presented `record_digest` is the digest over the exact canonical record
/// bytes, and the same digest is the owner-issued evidence reference the store
/// echoes on readback — so one value binds the committed bytes, the durable row
/// identity, and the revision the Governor registry orders by.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when the skill identity cannot produce a
/// bounded wire shape, or when the record bytes exceed the declared bounded
/// length or are not UTF-8.
fn capability_evidence_row_address(
    record: &CapabilityEvidenceRecord,
) -> Result<CapabilityEvidenceRowAddress, CompositionError> {
    if !eliot_store_api::valid_skill_id(&record.skill_id) {
        return Err(CompositionError::Owner(
            "capability evidence skill identity is not a bounded non-blank identity".to_owned(),
        ));
    }
    let record_bytes = canonical_json_bytes(record).map_err(|error| {
        CompositionError::Owner(format!("capability evidence record bytes: {error}"))
    })?;
    if record_bytes.len() > eliot_store_api::MAX_CAPABILITY_EVIDENCE_RECORD_JSON_BYTES {
        return Err(CompositionError::Owner(
            "capability evidence record document exceeds the bounded length".to_owned(),
        ));
    }
    let record_json = String::from_utf8(record_bytes).map_err(|_| {
        CompositionError::Owner("capability evidence record document is not UTF-8".to_owned())
    })?;
    // The scope key is the owner-issued reference of the exact route-scope
    // fingerprint, so the durable row is addressed by behaviour scope and the
    // store never has to parse a route.
    Ok(CapabilityEvidenceRowAddress {
        scope_key: record.scope_fingerprint.reference_digest(),
        record_digest: sha256_hex(record_json.as_bytes()),
        record_json,
    })
}

/// The single operation text both the committed `operation_id` and the commit
/// `idempotency_key` are derived from.
///
/// `skill_id` + `scope_key` + `record_digest` is exactly the durable row's
/// identity: the presented digest is the immutable record identity, so two
/// different revisions of the same evidence key address two different rows and
/// the SAME revision always addresses the same one. A retry therefore converges
/// at the store instead of appending a second row.
fn capability_evidence_operation_text(
    skill_id: &str,
    scope_key: &str,
    record_digest: &str,
) -> String {
    format!("capability-evidence-{skill_id}-{scope_key}-{record_digest}")
}

/// Derives the deterministic commit idempotency key for one evidence record.
///
/// The key is byte-for-byte the text the committed
/// [`OperationId`] is built from
/// ([`capability_evidence_operation_text`]), so a caller that needs the key
/// before it can build the named request — because the admitted
/// [`RequestIdentity`] must already carry it — derives exactly the value the
/// commit will commit under. That is what makes a retried startup safe: the
/// same record re-presents the same key, and the store's compare-and-set
/// converges instead of creating a second row.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when the record cannot produce a bounded
/// wire address (see [`capability_evidence_row_address`]) or when the derived key
/// exceeds the store's bounded idempotency length.
pub fn capability_evidence_idempotency_key(
    record: &CapabilityEvidenceRecord,
) -> Result<String, CompositionError> {
    let address = capability_evidence_row_address(record)?;
    let key = capability_evidence_operation_text(
        &record.skill_id,
        &address.scope_key,
        &address.record_digest,
    );
    if key.len() > eliot_store_api::MAX_CAPABILITY_EVIDENCE_IDEMPOTENCY_BYTES {
        return Err(CompositionError::Owner(
            "capability evidence idempotency key exceeds the bounded length".to_owned(),
        ));
    }
    Ok(key)
}

/// Builds the closed `RecordCapabilityEvidenceRecord` mutation request for one
/// verified record.
///
/// The presented `record_digest` is the digest over the exact canonical record
/// bytes, and the same digest is the owner-issued evidence reference the store
/// echoes on readback — so one value binds the committed bytes, the durable row
/// identity, and the revision the Governor registry orders by.
///
/// `idempotency_key` must be
/// [`capability_evidence_idempotency_key`] for this same record;
/// [`commit_capability_evidence_record`] refuses any other value, so the two can
/// never silently diverge.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when the skill identity or scope
/// fingerprint cannot produce a bounded wire shape, when the record bytes
/// exceed the declared bounded length, or when the built request fails the
/// closed named-operation guard.
pub fn capability_evidence_mutation_request_for_record(
    record: &CapabilityEvidenceRecord,
    expected_canonical_revision: u64,
    idempotency_key: String,
) -> Result<NamedMutationRequest, CompositionError> {
    let address = capability_evidence_row_address(record)?;
    let request = eliot_store_api::capability_evidence_mutation_request(
        eliot_store_api::capability_evidence_commit_params(
            record.skill_id.clone(),
            address.scope_key,
            address.record_json,
            address.record_digest,
            expected_canonical_revision,
            idempotency_key,
        ),
    );
    reject_direct_capability_evidence_write(&request).map_err(|error| {
        CompositionError::Owner(format!("capability evidence commit guard: {error}"))
    })?;
    Ok(request)
}

/// Reports whether one canonical receipt really committed the named
/// capability-evidence request, with no stale projection reported healthy
/// (issue #223 P2 discipline).
///
/// Identity/fence agreement mirrors the store's own receipt-identity rule and
/// head agreement follows the owner CAS contract. This is the same
/// freshness check the sibling commit paths apply, named for this leg.
fn check_capability_evidence_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
) -> Result<(), CompositionError> {
    receipt.validate().map_err(|error| {
        CompositionError::Owner(format!(
            "capability evidence commit receipt invalid: {error}"
        ))
    })?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt is not committed; stale projection refused"
                .to_owned(),
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt identity does not match the committed envelope"
                .to_owned(),
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(CompositionError::Owner(
            "capability evidence commit receipt fence does not match the committed envelope fence"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Commits one prebuilt named capability-evidence request through the canonical
/// owner and returns the store-issued owner revision of the evidence row.
///
/// Derives the real [`CanonicalWriteEnvelope`] from the caller identity, the
/// decoded closed parameters of the single named evidence command, the
/// caller-addressed scope, proof refs, live head expectations, and the live
/// store manifest digest — then invokes
/// [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical)
/// and checks the returned receipt for freshness.
///
/// Never accepts a caller-created `PreparedTransition` (there is no such
/// parameter), never mints a revision from a local clock, and never reinterprets
/// the receipt.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_capability_evidence_record<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    request: NamedMutationRequest,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<(WriteReceipt, OwnerEvidenceRevision), CompositionError> {
    reject_direct_capability_evidence_write(&request)
        .map_err(|error| CompositionError::Owner(format!("capability evidence guard: {error}")))?;
    let decoded = decode_capability_evidence_mutation(request.operation, &request.parameters)
        .map_err(|error| {
            CompositionError::Owner(format!("capability evidence parameters: {error}"))
        })?;
    identity.validate().map_err(|error| {
        CompositionError::Owner(format!("capability evidence identity invalid: {error}"))
    })?;
    if identity.idempotency_key != decoded.idempotency_key {
        return Err(CompositionError::Owner(
            "capability evidence idempotency key does not match the named request key".to_owned(),
        ));
    }
    if !is_evidence_ref(&decoded.record_digest) {
        return Err(CompositionError::Owner(
            "capability evidence presented digest is not one hex SHA-256 digest".to_owned(),
        ));
    }
    let operation_id = OperationId::new(capability_evidence_operation_text(
        &decoded.skill_id,
        &decoded.scope_key,
        &decoded.record_digest,
    ))
    .map_err(|error| {
        CompositionError::Owner(format!("capability evidence identity invalid: {error}"))
    })?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: decoded.idempotency_key.clone(),
        scope_id,
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![request],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs,
        expected_revision_heads,
        expected_ordering_heads,
    };
    let receipt = composition.commit_canonical(identity, envelope).await?;
    check_capability_evidence_commit_freshness(
        &receipt,
        &operation_id,
        &decoded.idempotency_key,
        &envelope_fence,
    )?;
    // Re-derived, not read back. This is the same `expected + 1` the store
    // issues under its fenced compare-and-set (see this module's docs for both
    // provider endpoints); it is a store contract this function depends on, not
    // an observation of the store. The presented digest is the owner-issued
    // evidence reference the store echoes verbatim on readback.
    let issued =
        decoded
            .expected_canonical_revision
            .checked_add(1)
            .ok_or(CompositionError::Owner(
                "capability evidence revision overflow".to_owned(),
            ))?;
    let revision =
        OwnerEvidenceRevision::issued(issued, &decoded.record_digest).map_err(|error| {
            CompositionError::Owner(format!("capability evidence issued revision: {error}"))
        })?;
    Ok((receipt, revision))
}

/// The single operation text the committed instrument-registry `operation_id`
/// is derived from (issue #1814).
///
/// `instrument-registry-{snapshot_digest}` is exactly the durable snapshot's
/// identity: the presented digest is over the verbatim accepted snapshot
/// bytes, so the SAME registry content always addresses the same operation
/// (a retry converges at the store instead of appending a second head) and
/// ANY spec, receipt, or generation change addresses a different one. A
/// drifted snapshot therefore cannot replay as the admitted one.
fn instrument_registry_operation_text(snapshot_digest: &str) -> String {
    format!("instrument-registry-{snapshot_digest}")
}

/// Whether `value` is a lowercase SHA-256 hex digest.
fn is_registry_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// File name of a canonical executable path, lowercased without an `.exe`
/// suffix.
///
/// This mirrors the runner observation's file-name rule textually (same
/// separators, same case fold, same suffix strip) rather than by shared code:
/// the runner crate is not a dependency here, so the entry-side executable
/// binding agrees with the launch-side one by identical rule text, stated in
/// both places.
fn registry_executable_file_name(canonical_path: &str) -> String {
    let tail = canonical_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(canonical_path);
    let lower = tail.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}

/// Re-runs the admission drift and observation checks entry-side, against the
/// snapshot this entry is about to commit (issue #1814).
///
/// Every presented pin must agree with the snapshot bytes: the snapshot
/// generation equals the admitted generation pin, the admitted kind is still
/// present in the spec table, and the snapshot's own receipt row for the kind
/// carries the admitted spec digest, executable object, and receipt digest —
/// the receipt digest recomputed here over the row fields with the registry's
/// exact digest material, so a substituted row refuses even when its fields
/// look individually plausible. An admission that carried no receipt (empty
/// supply pin) must still carry none in the snapshot. The spec-bytes binding
/// itself stays runner-side (see the entry docs); what refuses here is any
/// pin that disagrees with the committed bytes.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when a pin is malformed, the snapshot
/// is not JSON, or any pin disagrees with the snapshot content.
fn check_registry_commit_admission(
    snapshot_json: &str,
    kind: &str,
    spec_digest: &str,
    supply_digest: &str,
    executable_path: &str,
    content_digest: &str,
    registry_generation: u64,
) -> Result<(), CompositionError> {
    for (field, pin) in [
        ("spec_digest", spec_digest),
        ("content_digest", content_digest),
    ] {
        if !is_registry_digest(pin) {
            return Err(CompositionError::Owner(format!(
                "instrument registry admission pin '{field}' is not a snapshot digest"
            )));
        }
    }
    if !supply_digest.is_empty() && !is_registry_digest(supply_digest) {
        return Err(CompositionError::Owner(
            "instrument registry admission pin 'supply_digest' is not a snapshot digest"
                .to_owned(),
        ));
    }
    let document: Value = serde_json::from_str(snapshot_json).map_err(|error| {
        CompositionError::Owner(format!("instrument registry snapshot is not JSON: {error}"))
    })?;
    let generation = document
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CompositionError::Owner(
                "instrument registry snapshot carries no generation".to_owned(),
            )
        })?;
    if generation != registry_generation {
        return Err(CompositionError::Owner(format!(
            "instrument registry snapshot generation {generation} differs from the admitted generation {registry_generation}"
        )));
    }
    let specs =
        document
            .get("specs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CompositionError::Owner(
                    "instrument registry snapshot carries no spec table".to_owned(),
                )
            })?;
    let spec_present = specs.iter().any(|row| {
        row.get("kind")
            .and_then(|kind_value| kind_value.get("name"))
            .and_then(Value::as_str)
            == Some(kind)
    });
    if !spec_present {
        return Err(CompositionError::Owner(format!(
            "instrument registry snapshot no longer admits kind '{kind}'"
        )));
    }
    let receipts =
        document
            .get("receipts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CompositionError::Owner(
                    "instrument registry snapshot carries no receipt table".to_owned(),
                )
            })?;
    let receipt = receipts
        .iter()
        .find(|row| row.get("instrument").and_then(Value::as_str) == Some(kind));
    match (receipt, supply_digest.is_empty()) {
        (None, true) => Ok(()),
        (Some(_), true) | (None, false) => Err(CompositionError::Owner(
            "instrument registry snapshot receipt presence differs from the admission".to_owned(),
        )),
        (Some(row), false) => {
            let field = |name: &str| {
                row.get(name).and_then(Value::as_str).ok_or_else(|| {
                    CompositionError::Owner(format!(
                        "instrument registry snapshot receipt for '{kind}' carries no '{name}'"
                    ))
                })
            };
            let executable = field("executable")?;
            let row_content = field("content_digest")?;
            let row_spec = field("spec_digest")?;
            let row_generation =
                row.get("generation")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        CompositionError::Owner(format!(
                            "instrument registry snapshot receipt for '{kind}' carries no generation"
                        ))
                    })?;
            let version = row.get("tool_version").and_then(Value::as_str).unwrap_or("");
            // The registry's exact receipt-digest material (same field order,
            // same separators): a substituted row fails here even when every
            // field is individually well-formed.
            let material = format!(
                "{kind}\0{executable}\0{row_content}\0{version}\0{row_spec}\0{row_generation}"
            );
            if eliot_contracts::sha256_hex(material.as_bytes()) != supply_digest {
                return Err(CompositionError::Owner(format!(
                    "instrument registry snapshot receipt for '{kind}' differs from the admitted receipt"
                )));
            }
            if row_content != content_digest {
                return Err(CompositionError::Owner(format!(
                    "instrument registry snapshot receipt for '{kind}' names a different executable object than admitted"
                )));
            }
            if row_spec != spec_digest {
                return Err(CompositionError::Owner(format!(
                    "instrument registry snapshot receipt for '{kind}' is verified against a different spec than admitted"
                )));
            }
            if registry_executable_file_name(executable_path) != executable.to_ascii_lowercase() {
                return Err(CompositionError::Owner(format!(
                    "instrument registry admission names a different executable file than the snapshot receipt for '{kind}'"
                )));
            }
            Ok(())
        }
    }
}

/// Reports whether one canonical receipt really committed the named
/// instrument-registry request, with no stale projection reported healthy
/// (issue #223 P2 discipline).
///
/// Identity/fence agreement mirrors the store's own receipt-identity rule and
/// head agreement follows the owner CAS contract. This is the same freshness
/// check the sibling commit paths apply, named for this leg.
fn check_instrument_registry_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), CompositionError> {
    receipt.validate().map_err(|error| {
        CompositionError::Owner(format!(
            "instrument registry commit receipt invalid: {error}"
        ))
    })?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(CompositionError::Owner(
            "instrument registry commit receipt is not committed; stale projection refused"
                .to_owned(),
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(CompositionError::Owner(
            "instrument registry commit receipt identity does not match the committed envelope"
                .to_owned(),
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(CompositionError::Owner(
            "instrument registry commit receipt fence does not match the committed envelope fence"
                .to_owned(),
        ));
    }
    for expected in expected_revision_heads {
        if let Some(delta) = receipt
            .revision_before_after
            .iter()
            .find(|delta| delta.key == expected.key)
            && delta.before != expected.expected_revision
        {
            return Err(CompositionError::Owner(format!(
                "instrument registry commit receipt revision is stale for {}: expected base {}, observed {}",
                expected.key.as_str(),
                expected.expected_revision,
                delta.before,
            )));
        }
    }
    for expected in expected_ordering_heads {
        if let Some(head) = receipt
            .ordering_sequences
            .iter()
            .find(|head| head.scope == expected.scope)
            && head.sequence <= expected.expected_sequence
        {
            return Err(CompositionError::Owner(format!(
                "instrument registry commit receipt ordering is stale for {}: expected advance past {}, observed {}",
                expected.scope.as_str(),
                expected.expected_sequence,
                head.sequence,
            )));
        }
    }
    Ok(())
}

/// Commits one admitted instrument-registry snapshot through the canonical
/// owner (issue #1814).
///
/// This is the Governor-owned sibling of [`commit_capability_evidence_record`]
/// for the closed `ApplyInstrumentRegistryState` mutation: it carries the
/// admitted snapshot the instrument admission boundary produced to durable
/// storage through canonical-store authority instead of any runner-invented
/// write. The closed mutation parameters are built HERE, from the verified
/// snapshot bytes — never from a caller-supplied parameter map — then the
/// entry derives the real [`CanonicalWriteEnvelope`], invokes
/// [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical),
/// and checks the returned receipt for freshness.
///
/// The boundary takes the admission's closed content (the verbatim snapshot
/// bytes) plus the live-registry pins the admission boundary bound the launch
/// under, as plain snapshot data: the runner's `AdmissionSubmission` lives in
/// a crate this crate must not depend on, so the future Governor-side caller
/// copies each pin from the submission's accessors. Before any commit the
/// entry re-runs the drift and observation checks against the snapshot it is
/// about to commit (see [`check_registry_commit_admission`]): the snapshot
/// generation must equal the admitted generation pin, the admitted kind must
/// still be present, the snapshot's own receipt row for the kind must agree
/// with every presented pin (including a recomputed receipt digest over the
/// row fields, so a substituted row refuses), and the admitted executable
/// object must match the row's recorded object. A snapshot that drifted
/// between admission and commit therefore refuses here instead of committing
/// foreign bytes under an admitted identity.
///
/// Envelope field provenance (every field bound, none synthesized; mirrors
/// `commit_learning_record`):
///
/// ```text
/// operation_id            recomputed entry-side as
///                         `instrument-registry-{snapshot_digest}` over the
///                         decoded snapshot bytes AFTER the pins verify: the
///                         digest is never taken from caller parameters (they
///                         are built here), so the SAME registry content always
///                         addresses the same operation (a retry converges at
///                         the store instead of appending a second head) and
///                         ANY spec, receipt, or generation change addresses a
///                         different one
/// request                 the caller-supplied request metadata, cloned verbatim
/// idempotency_key         the validated request identity's key
///                         (`identity.validate()` runs before any commit):
///                         the envelope rule the sibling commit paths apply,
///                         not a caller-chosen value; convergence across
///                         retries comes from the deterministic operation_id
///                         plus the store's fenced compare-and-set
/// scope_id                caller-addressed scope carried into the envelope
/// task_id                 none: a registry snapshot is scope-addressed, never
///                         task-bound
/// transition_class        InstrumentRegistry; ceiling ReversibleMutation (the
///                         class maximum: a registry snapshot is a durable
///                         owner snapshot, and the memory dispatch refuses any
///                         other class with TransitionClassExceeded)
/// admission_contract_set_digest
///                         the current supported Store API admission contract
///                         set; the snapshot digest remains bound in the named
///                         operation parameters and operation identity
/// operation_manifest_digest
///                         computed live from `generated_operation_manifests`
/// semantic_commands       the single named registry command, built here from
///                         the verified snapshot bytes and refused upstream
///                         unless the pins agree: no caller parameter map is
///                         ever accepted
/// event/projection/relation intents
///                         empty: a durable registry snapshot is not a
///                         projection or relation; the registry is a
///                         rebuildable view
/// security                default context: the snapshot travels inside the
///                         command parameters, not the envelope security block
/// required_proof_and_approval_refs
///                         caller-supplied proof refs, passed through
/// expected revision/ordering heads
///                         caller-supplied live owner expectations, each bound
///                         to the request fence
/// ```
///
/// Fail-closed checks before any commit, in order: caller-identity validity;
/// entry-side admission agreement (generation, kind presence, receipt-row pins
/// with recomputed receipt digest, executable-object binding); the closed
/// parameter decode through the shared snapshot acceptance boundary
/// (unsupported schema/version refuses here, before any apply). The
/// spec-bytes binding itself (spec digest recomputation over the spec
/// definitions) stays runner-side in the submission builder's
/// recover-and-compare: the registry digest functions live in the runner
/// crate, which is not a dependency here, so this entry verifies pin
/// agreement inside the snapshot it commits rather than re-deriving those
/// digests. The machine-observation half (the launched file really is the
/// pinned object) likewise stays at the runner boundary, which hashes the
/// file at use; what this entry refuses on is any pin that disagrees with
/// the committed snapshot bytes.
///
/// Never accepts a caller-created `PreparedTransition` (there is no such
/// parameter) or a caller-built parameter map, never mints a revision from a
/// local clock, never invents a store operation or a catalogue activation,
/// and never reinterprets the receipt: the returned [`WriteReceipt`] is the
/// owner's receipt, unmodified.
///
/// Catalogue state: the generated operation catalogue carries the activated
/// `ApplyInstrumentRegistryState` mutation row
/// (`TransitionClass::InstrumentRegistry`, bulk owner-snapshot bound, closed
/// snapshot validator), so the prepared transition validates at the store
/// gateway. The typed `GetInstrumentRegistryState` read stays
/// known-but-unsupported until its catalogue row and canonical read handlers
/// land with the store owner.
#[allow(
    clippy::too_many_arguments,
    reason = "the commit caller joins every handoff-required envelope input in one typed call"
)]
pub async fn commit_instrument_registry_snapshot<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    snapshot_json: String,
    kind: &str,
    spec_digest: &str,
    supply_digest: &str,
    executable_path: &str,
    content_digest: &str,
    registry_generation: u64,
    registry_digest: &str,
    scope_id: ScopeId,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<WriteReceipt, CompositionError> {
    identity.validate().map_err(|error| {
        CompositionError::Owner(format!("instrument registry identity invalid: {error}"))
    })?;
    check_registry_commit_admission(
        &snapshot_json,
        kind,
        spec_digest,
        supply_digest,
        executable_path,
        content_digest,
        registry_generation,
    )?;
    if !is_registry_digest(registry_digest) {
        return Err(CompositionError::Owner(
            "instrument registry digest pin is not a registry digest".to_owned(),
        ));
    }
    // The closed parameters are built here from the verified snapshot bytes:
    // no caller parameter map is accepted, so the committed digest can never
    // be a caller-supplied value travelling beside different bytes. The
    // registry digest pin above is shape-checked here and enforced for
    // agreement runner-side (`launch_plan_live` refuses a plan compiled
    // against a different live digest); it travels with the pin set so the
    // commit caller's pins stay complete and auditable.
    let parameters = BTreeMap::from([(
        "snapshot_json".to_owned(),
        Value::String(snapshot_json),
    )]);
    let admitted =
        decode_instrument_registry_mutation(&parameters).map_err(|error| {
            CompositionError::Owner(format!("instrument registry parameters: {error}"))
        })?;
    let snapshot_digest = sha256_hex(admitted.as_bytes());
    let operation_id = OperationId::new(instrument_registry_operation_text(&snapshot_digest))
        .map_err(|error| {
            CompositionError::Owner(format!("instrument registry identity invalid: {error}"))
        })?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
    let idempotency_key = identity.idempotency_key.clone();
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            CompositionError::Owner(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| CompositionError::Owner(format!("operation manifest digest: {error}")))?;
    let revision_expectations = expected_revision_heads.clone();
    let ordering_expectations = expected_ordering_heads.clone();
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: idempotency_key.clone(),
        scope_id,
        task_id: None,
        transition_class: TransitionClass::InstrumentRegistry,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyInstrumentRegistryState,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs,
        expected_revision_heads,
        expected_ordering_heads,
    };
    let receipt = composition.commit_canonical(identity, envelope).await?;
    check_instrument_registry_commit_freshness(
        &receipt,
        &operation_id,
        &idempotency_key,
        &envelope_fence,
        &revision_expectations,
        &ordering_expectations,
    )?;
    Ok(receipt)
}
