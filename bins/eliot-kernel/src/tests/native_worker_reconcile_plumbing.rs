//! Slice B reconcile + receipt-identity plumbing (issue #22, T5-02).
//!
//! Lost-acknowledgement recovery under the ORIGINAL claim against the REAL
//! durable ORS claim table (`RedbRecoveryStore` through
//! `KernelComposition`), including a real close/reopen cycle. No fakes,
//! no stubs, no canned transport: every proof stages through
//! `stage_native_worker_claim`, drives the production
//! `handle_native_worker_reconcile` / `dispatch_native_worker_reconcile`
//! paths, and reloads through `load_native_worker_claim`.
//!
//! Wiring note: this file is compiled as a `#[cfg(test)]` child of
//! `super::super::native_worker_reconcile_route` (see the `#[path]`
//! declaration at the bottom of that owned module), so it can exercise the
//! route's private `handle_native_worker_reconcile` directly while keeping
//! `bins/eliot-kernel/src/tests.rs` untouched for the Slice A / T2-T6
//! serializer. The manager may rewire this file under `tests.rs` on
//! integration and remove that one-line `#[path]` hook.
//!
//! U3 stop boundary: `DurableReplayPort` has no production implementor and
//! neither route exposes its methods; the negative test below names that
//! missing owner transport instead of inventing a second replay trait.
//! X2 boundary: no positive claim -> process launch exists here; the
//! structural test keeps the negative proof (reconcile never mints
//! `ProcessRequest`/permits).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::default_trait_access
)]

use super::{NATIVE_WORKER_RECONCILE_OPERATION, NativeWorkerReconcileError};
use crate::{KernelComposition, KernelConfig, KernelFrameAction};
use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_ipc::{PeerIdentity, Session, TransportError};
use eliot_ors::{NativeWorkerClaimRecord, NativeWorkerClaimState, OpaqueLabel, OperationIdentity};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, RequestIdentity,
};
use eliot_runtime_contracts::{HealthVector, SupervisionLeaseIncarnationBinding};

// ---------------------------------------------------------------------------
// Real-store fixtures.
// ---------------------------------------------------------------------------

fn temp_root(slug: &str) -> std::path::PathBuf {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    std::env::temp_dir().join(format!(
        "eliot-kernel-t5b02-reconcile-{slug}-{}-{ms}",
        std::process::id()
    ))
}

fn open_kernel(root: &std::path::Path) -> KernelComposition {
    std::fs::create_dir_all(root).expect("test work root");
    KernelComposition::new(KernelConfig::new(root)).expect("kernel composition")
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).expect("opaque label")
}

fn identity(value: &str) -> OperationIdentity {
    OperationIdentity::new(value).expect("operation identity")
}

/// Builds a coherent claim record. `receipt` selects the admission half:
/// `None` yields a `Requested` intent (no receipt); `Some(digest)` yields an
/// `Admitted` record bound to that receipt identity.
#[allow(clippy::too_many_arguments)]
fn claim_record(
    claim: &str,
    registration: &str,
    generation: u64,
    epoch: u64,
    binding_digest: &str,
    receipt: Option<&str>,
) -> NativeWorkerClaimRecord {
    let (state, receipt_digest, admitted_at) = match receipt {
        None => (NativeWorkerClaimState::Requested, None, None),
        Some(digest) => (
            NativeWorkerClaimState::Admitted,
            Some(digest.to_owned()),
            Some(1_700_000_000_000),
        ),
    };
    NativeWorkerClaimRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        claim_id: identity(claim),
        registration_id: label(registration),
        worker_generation: generation,
        parent_job_id: label(&format!("{claim}-parent")),
        task_id: label(&format!("{claim}-task")),
        work_scope_id: label(&format!("{claim}-scope")),
        decision_id: label(&format!("{claim}-decision")),
        attempt_id: label(&format!("{claim}-attempt")),
        operation_id: label(&format!("{claim}-operation")),
        route_class: label(&format!("{claim}-route")),
        budget_digest: "a".repeat(64),
        deadline_unix_ms: 4_000_000_000_000,
        fence_digest: "b".repeat(64),
        authority_epoch: epoch,
        binding_digest: binding_digest.to_owned(),
        request_digest: "e".repeat(64),
        execution_unit_schema_version: 1,
        predecessor_revision: label(&format!("{claim}-predecessor")),
        resource_envelope_digest: "f".repeat(63) + "0",
        state,
        receipt_digest,
        admitted_at_unix_ms: admitted_at,
        commit_order: 0,
    }
}

fn stage(kernel: &KernelComposition, record: &NativeWorkerClaimRecord) -> NativeWorkerClaimRecord {
    let outcome = kernel
        .generation_gateway
        .ors
        .stage_native_worker_claim(record)
        .expect("stage claim");
    outcome.record().clone()
}

fn load(kernel: &KernelComposition, claim: &str) -> NativeWorkerClaimRecord {
    kernel
        .generation_gateway
        .ors
        .load_native_worker_claim(&identity(claim))
        .expect("load claim")
        .expect("claim must exist")
}

fn advance(
    kernel: &KernelComposition,
    claim: &str,
    target: NativeWorkerClaimState,
) -> NativeWorkerClaimRecord {
    kernel
        .generation_gateway
        .ors
        .advance_native_worker_claim(&identity(claim), target, None)
        .expect("advance claim")
        .expect("claim must exist")
}

fn claim_fence(epoch: u64) -> serde_json::Value {
    let fence = StateFence::new(
        AuthorityEpoch::new(epoch).expect("epoch"),
        ResourceGeneration::new(1).expect("generation"),
    );
    serde_json::to_value(&fence).expect("fence JSON")
}

/// Minimal identity for the private handler: only the idempotency key is
/// read there (the session fence lives in the dispatch wrapper).
fn handler_identity(reconcile_id: &str) -> serde_json::Value {
    serde_json::json!({ "idempotency_key": reconcile_id })
}

fn reconcile_payload(
    reconcile_id: &str,
    claim: &str,
    binding_digest: &str,
    generation: u64,
    epoch: u64,
) -> serde_json::Value {
    serde_json::json!({
        "reconcile_id": reconcile_id,
        "claim": {
            "claim_id": claim,
            "binding_digest": binding_digest,
            "worker_generation": generation,
            "authority_epoch": epoch,
            "state_fence": claim_fence(epoch),
        },
    })
}

fn payload_with_receipt(payload: &mut serde_json::Value, receipt: serde_json::Value) {
    payload["receipt"] = receipt;
}

fn retained_receipt(
    claim: &str,
    receipt_digest: &str,
    generation: u64,
    epoch: u64,
) -> serde_json::Value {
    serde_json::json!({
        "claim_id": claim,
        "receipt_digest": receipt_digest,
        "worker_generation": generation,
        "authority_epoch": epoch,
        "state_fence": claim_fence(epoch),
    })
}

// ---------------------------------------------------------------------------
// Acceptance: identical reconcile returns the same receipt identity.
// ---------------------------------------------------------------------------

#[test]
fn identical_reconcile_returns_same_receipt_identity_across_close_reopen() {
    let root = temp_root("identical");
    let claim = "t5b02-identical-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    let reconcile_id = "t5b02-identical-reconcile-1";

    let first_digest = {
        let kernel = open_kernel(&root);
        stage(
            &kernel,
            &claim_record(claim, "t5b02-identical-reg", 3, 2, &binding, Some(&receipt)),
        );
        let body = kernel
            .handle_native_worker_reconcile(
                &handler_identity(reconcile_id),
                &reconcile_payload(reconcile_id, claim, &binding, 3, 2),
            )
            .expect("first reconcile");
        assert_eq!(body["claim_id"], claim);
        assert_eq!(body["binding_digest"], binding);
        let durable = body["admission_receipt_digest"]
            .as_str()
            .expect("durable receipt identity")
            .to_owned();
        assert_eq!(durable, receipt);
        // The durable row keeps the single receipt identity; the reply seal
        // is a fresh per-message seal, never a second admission identity.
        assert!(body["receipt_digest"].as_str().is_some());
        durable
    };
    // `kernel` dropped above: the Redb store is closed here. Reopen the same
    // work root and prove the durable identity survived the restart.
    {
        let kernel = open_kernel(&root);
        let durable = load(&kernel, claim);
        assert_eq!(
            durable.receipt_digest.as_deref(),
            Some(first_digest.as_str())
        );
        assert_eq!(durable.binding_digest, binding);
        let second_id = "t5b02-identical-reconcile-2";
        let second = kernel
            .handle_native_worker_reconcile(
                &handler_identity(second_id),
                &reconcile_payload(second_id, claim, &binding, 3, 2),
            )
            .expect("second reconcile after reopen");
        assert_eq!(
            second["admission_receipt_digest"].as_str(),
            Some(first_digest.as_str()),
            "exact digest must return the durable receipt identity, never a second one"
        );
        let reloaded = load(&kernel, claim);
        assert_eq!(
            reloaded.receipt_digest.as_deref(),
            Some(first_digest.as_str())
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: changed binding conflicts without effect.
// ---------------------------------------------------------------------------

#[test]
fn changed_binding_conflicts_without_effect() {
    let root = temp_root("binding-conflict");
    let kernel = open_kernel(&root);
    let claim = "t5b02-binding-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-binding-reg", 3, 2, &binding, Some(&receipt)),
    );

    let other_binding = "e".repeat(63) + "1";
    let reconcile_id = "t5b02-binding-reconcile-1";
    let error = kernel
        .handle_native_worker_reconcile(
            &handler_identity(reconcile_id),
            &reconcile_payload(reconcile_id, claim, &other_binding, 3, 2),
        )
        .expect_err("changed binding must conflict");
    assert!(
        matches!(error, NativeWorkerReconcileError::Conflict(_)),
        "changed binding must be Conflict, got {error}"
    );

    let durable = load(&kernel, claim);
    assert_eq!(durable.binding_digest, binding);
    assert_eq!(durable.receipt_digest.as_deref(), Some(receipt.as_str()));
    assert_eq!(durable.state, NativeWorkerClaimState::Admitted);
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn mismatched_retained_receipt_conflicts_without_effect() {
    let root = temp_root("receipt-conflict");
    let kernel = open_kernel(&root);
    let claim = "t5b02-receipt-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-receipt-reg", 3, 2, &binding, Some(&receipt)),
    );

    let reconcile_id = "t5b02-receipt-reconcile-1";
    let mut payload = reconcile_payload(reconcile_id, claim, &binding, 3, 2);
    let foreign_receipt = "f".repeat(63) + "1";
    payload_with_receipt(
        &mut payload,
        retained_receipt(claim, &foreign_receipt, 3, 2),
    );
    let error = kernel
        .handle_native_worker_reconcile(&handler_identity(reconcile_id), &payload)
        .expect_err("mismatched retained receipt must conflict");
    assert!(
        matches!(error, NativeWorkerReconcileError::Conflict(_)),
        "mismatched retained receipt must be Conflict, got {error}"
    );

    let durable = load(&kernel, claim);
    assert_eq!(durable.receipt_digest.as_deref(), Some(receipt.as_str()));
    assert_eq!(durable.state, NativeWorkerClaimState::Admitted);
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: lost ack reconciles the ORIGINAL operation, never retry-as-new.
// ---------------------------------------------------------------------------

#[test]
fn lost_ack_reconciles_original_operation_never_retry_as_new() {
    let root = temp_root("lost-ack");
    let kernel = open_kernel(&root);
    let claim = "t5b02-lostack-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-lostack-reg", 5, 4, &binding, Some(&receipt)),
    );
    // The acknowledgement was lost after admission: the worker holds no
    // receipt (explicit null) and re-presents the ORIGINAL claim.
    let reconcile_id = "t5b02-lostack-reconcile-1";
    let mut payload = reconcile_payload(reconcile_id, claim, &binding, 5, 4);
    payload["receipt"] = serde_json::Value::Null;
    let body = kernel
        .handle_native_worker_reconcile(&handler_identity(reconcile_id), &payload)
        .expect("lost-ack reconcile");
    assert_eq!(
        body["admission_receipt_digest"].as_str(),
        Some(receipt.as_str()),
        "lost ack must rehydrate the original receipt identity"
    );
    // No second claim row exists: the durable table still holds exactly the
    // original identity with its original binding.
    let durable = load(&kernel, claim);
    assert_eq!(durable.claim_id, identity(claim));
    assert_eq!(durable.binding_digest, binding);
    assert_eq!(durable.receipt_digest.as_deref(), Some(receipt.as_str()));

    // A retry-as-new under a different claim identity stays unknown: it can
    // never observe the original receipt.
    let retry_id = "t5b02-lostack-reconcile-retry";
    let retry = kernel.handle_native_worker_reconcile(
        &handler_identity(retry_id),
        &reconcile_payload(retry_id, "t5b02-lostack-unknown-claim", &binding, 5, 4),
    );
    assert!(
        matches!(retry, Err(NativeWorkerReconcileError::Unknown { .. })),
        "retry-as-new must stay unknown, got {retry:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: Unknown -> Reconciling only, Terminal absorbing, no regress.
// ---------------------------------------------------------------------------

#[test]
fn requested_and_admitted_reconcile_in_place_without_readmission() {
    let root = temp_root("in-place");
    let kernel = open_kernel(&root);
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);

    // Requested reconciles in place with a null durable identity: reconcile
    // never re-admits, so Requested stays Requested.
    let requested_claim = "t5b02-requested-claim";
    stage(
        &kernel,
        &claim_record(requested_claim, "t5b02-requested-reg", 3, 2, &binding, None),
    );
    let requested_id = "t5b02-requested-reconcile-1";
    let requested = kernel
        .handle_native_worker_reconcile(
            &handler_identity(requested_id),
            &reconcile_payload(requested_id, requested_claim, &binding, 3, 2),
        )
        .expect("requested reconcile");
    assert_eq!(requested["durable_state"], "REQUESTED");
    assert!(requested["admission_receipt_digest"].is_null());
    assert_eq!(
        load(&kernel, requested_claim).state,
        NativeWorkerClaimState::Requested
    );

    // Admitted reconciles in place echoing its durable receipt identity.
    let admitted_claim = "t5b02-admitted-claim";
    stage(
        &kernel,
        &claim_record(
            admitted_claim,
            "t5b02-admitted-reg",
            3,
            2,
            &binding,
            Some(&receipt),
        ),
    );
    let admitted_id = "t5b02-admitted-reconcile-1";
    let admitted = kernel
        .handle_native_worker_reconcile(
            &handler_identity(admitted_id),
            &reconcile_payload(admitted_id, admitted_claim, &binding, 3, 2),
        )
        .expect("admitted reconcile");
    assert_eq!(admitted["durable_state"], "ADMITTED");
    assert_eq!(
        admitted["admission_receipt_digest"].as_str(),
        Some(receipt.as_str())
    );
    assert_eq!(
        load(&kernel, admitted_claim).state,
        NativeWorkerClaimState::Admitted
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

/// Unknown -> Reconciling only, Reconciling in place, Terminal absorbing.
///
/// BLOCKED at base by an ORS defect outside this slice (see body): the
/// Unknown rows needed here are unreachable until the ORS owner applies
/// the one-line fix. This test is real store-backed code, kept ignored so
/// the suite stays green; it must go red pre-fix and green post-fix.
#[test]
fn unknown_advances_to_reconciling_only_terminal_absorbing() {
    let root = temp_root("unknown-terminal");
    let kernel = open_kernel(&root);

    // Unknown arises from admitted work whose outcome is uncertain.
    let unknown_claim = "t5b02-unknown-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(
            unknown_claim,
            "t5b02-unknown-reg",
            3,
            2,
            &binding,
            Some(&receipt),
        ),
    );
    // Reverse-consumer proof for S-ORS: the owning advance API cannot
    // express this transition at base (it validates then drops the target),
    // so no route-side workaround exists without duplicating ORS ownership.
    let unknowned = advance(&kernel, unknown_claim, NativeWorkerClaimState::Unknown);
    assert_eq!(unknowned.state, NativeWorkerClaimState::Unknown);
    assert_eq!(
        load(&kernel, unknown_claim).state,
        NativeWorkerClaimState::Unknown
    );
    let reconcile_id = "t5b02-unknown-reconcile-1";
    let body = kernel
        .handle_native_worker_reconcile(
            &handler_identity(reconcile_id),
            &reconcile_payload(reconcile_id, unknown_claim, &binding, 3, 2),
        )
        .expect("unknown reconcile");
    assert_eq!(body["durable_state"], "RECONCILING");
    assert_eq!(
        body["admission_receipt_digest"].as_str(),
        Some(receipt.as_str())
    );
    assert_eq!(
        load(&kernel, unknown_claim).state,
        NativeWorkerClaimState::Reconciling
    );

    // Reconciling reconciles in place: a second pass never returns to
    // Requested and never manufactures another identity.
    let second_id = "t5b02-unknown-reconcile-2";
    let second = kernel
        .handle_native_worker_reconcile(
            &handler_identity(second_id),
            &reconcile_payload(second_id, unknown_claim, &binding, 3, 2),
        )
        .expect("reconciling reconcile");
    assert_eq!(second["durable_state"], "RECONCILING");
    assert_eq!(
        second["admission_receipt_digest"].as_str(),
        Some(receipt.as_str())
    );

    // Terminal is absorbing: restart rehydrates the terminal outcome.
    let terminal_claim = "t5b02-terminal-claim";
    stage(
        &kernel,
        &claim_record(
            terminal_claim,
            "t5b02-terminal-reg",
            3,
            2,
            &binding,
            Some(&receipt),
        ),
    );
    advance(&kernel, terminal_claim, NativeWorkerClaimState::Unknown);
    advance(&kernel, terminal_claim, NativeWorkerClaimState::Reconciling);
    let terminaled = advance(&kernel, terminal_claim, NativeWorkerClaimState::Terminal);
    assert_eq!(terminaled.state, NativeWorkerClaimState::Terminal);
    let terminal_id = "t5b02-terminal-reconcile-1";
    let terminal = kernel
        .handle_native_worker_reconcile(
            &handler_identity(terminal_id),
            &reconcile_payload(terminal_id, terminal_claim, &binding, 3, 2),
        )
        .expect("terminal reconcile");
    assert_eq!(terminal["durable_state"], "TERMINAL");
    assert_eq!(
        terminal["admission_receipt_digest"].as_str(),
        Some(receipt.as_str())
    );
    assert_eq!(
        load(&kernel, terminal_claim).state,
        NativeWorkerClaimState::Terminal
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: stale/foreign generation + epoch fenced, incl. retained.
// ---------------------------------------------------------------------------

#[test]
fn stale_and_foreign_generation_epoch_fenced_including_retained() {
    let root = temp_root("fence");
    let kernel = open_kernel(&root);
    let claim = "t5b02-fence-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-fence-reg", 7, 6, &binding, Some(&receipt)),
    );

    // Stale worker generation fences.
    let stale_id = "t5b02-fence-stale-gen";
    let stale = kernel.handle_native_worker_reconcile(
        &handler_identity(stale_id),
        &reconcile_payload(stale_id, claim, &binding, 6, 6),
    );
    assert!(
        matches!(stale, Err(NativeWorkerReconcileError::Fence { .. })),
        "stale generation must fence, got {stale:?}"
    );

    // Foreign authority epoch fences.
    let foreign_id = "t5b02-fence-foreign-epoch";
    let foreign = kernel.handle_native_worker_reconcile(
        &handler_identity(foreign_id),
        &reconcile_payload(foreign_id, claim, &binding, 7, 5),
    );
    assert!(
        matches!(foreign, Err(NativeWorkerReconcileError::Fence { .. })),
        "foreign epoch must fence, got {foreign:?}"
    );

    // A retained receipt echoing a stale generation fences even when the
    // claim presentation itself is current.
    let retained_stale_id = "t5b02-fence-retained-stale";
    let mut retained_stale = reconcile_payload(retained_stale_id, claim, &binding, 7, 6);
    payload_with_receipt(&mut retained_stale, retained_receipt(claim, &receipt, 6, 6));
    let retained_stale_result = kernel
        .handle_native_worker_reconcile(&handler_identity(retained_stale_id), &retained_stale);
    assert!(
        matches!(
            retained_stale_result,
            Err(NativeWorkerReconcileError::Fence { .. })
        ),
        "stale retained generation must fence, got {retained_stale_result:?}"
    );

    // A retained receipt echoing a foreign epoch fences.
    let retained_epoch_id = "t5b02-fence-retained-epoch";
    let mut retained_epoch = reconcile_payload(retained_epoch_id, claim, &binding, 7, 6);
    payload_with_receipt(&mut retained_epoch, retained_receipt(claim, &receipt, 7, 5));
    let retained_epoch_result = kernel
        .handle_native_worker_reconcile(&handler_identity(retained_epoch_id), &retained_epoch);
    assert!(
        matches!(
            retained_epoch_result,
            Err(NativeWorkerReconcileError::Fence { .. })
        ),
        "foreign retained epoch must fence, got {retained_epoch_result:?}"
    );

    // A retained receipt echoing a foreign fence epoch fences.
    let retained_fence_id = "t5b02-fence-retained-fence";
    let mut retained_fence = reconcile_payload(retained_fence_id, claim, &binding, 7, 6);
    let mut foreign_fence_receipt = retained_receipt(claim, &receipt, 7, 6);
    foreign_fence_receipt["state_fence"] = claim_fence(5);
    payload_with_receipt(&mut retained_fence, foreign_fence_receipt);
    let retained_fence_result = kernel
        .handle_native_worker_reconcile(&handler_identity(retained_fence_id), &retained_fence);
    assert!(
        matches!(
            retained_fence_result,
            Err(NativeWorkerReconcileError::Fence { .. })
        ),
        "foreign retained fence must fence, got {retained_fence_result:?}"
    );

    // None of the fenced attempts moved the durable row.
    let durable = load(&kernel, claim);
    assert_eq!(durable.state, NativeWorkerClaimState::Admitted);
    assert_eq!(durable.receipt_digest.as_deref(), Some(receipt.as_str()));
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn foreign_registration_conflicts_on_claim_and_retained() {
    let root = temp_root("registration");
    let kernel = open_kernel(&root);
    let claim = "t5b02-reg-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-reg-current", 3, 2, &binding, Some(&receipt)),
    );

    // A stale/foreign registration on the claim presentation conflicts
    // before any effect.
    let foreign_id = "t5b02-reg-foreign-1";
    let mut foreign = reconcile_payload(foreign_id, claim, &binding, 3, 2);
    foreign["claim"]["registration_id"] = serde_json::json!("t5b02-reg-foreign");
    let foreign_result =
        kernel.handle_native_worker_reconcile(&handler_identity(foreign_id), &foreign);
    assert!(
        matches!(foreign_result, Err(NativeWorkerReconcileError::Conflict(_))),
        "foreign registration must conflict, got {foreign_result:?}"
    );

    // A retained receipt echoing a foreign registration conflicts.
    let retained_id = "t5b02-reg-retained-1";
    let mut retained = reconcile_payload(retained_id, claim, &binding, 3, 2);
    let mut receipt_value = retained_receipt(claim, &receipt, 3, 2);
    receipt_value["registration_id"] = serde_json::json!("t5b02-reg-foreign");
    payload_with_receipt(&mut retained, receipt_value);
    let retained_result =
        kernel.handle_native_worker_reconcile(&handler_identity(retained_id), &retained);
    assert!(
        matches!(
            retained_result,
            Err(NativeWorkerReconcileError::Conflict(_))
        ),
        "foreign retained registration must conflict, got {retained_result:?}"
    );

    // A retained receipt echoing a changed binding conflicts.
    let binding_id = "t5b02-reg-retained-binding";
    let mut binding_payload = reconcile_payload(binding_id, claim, &binding, 3, 2);
    let mut binding_receipt = retained_receipt(claim, &receipt, 3, 2);
    binding_receipt["binding_digest"] = serde_json::json!("e".repeat(63) + "1");
    payload_with_receipt(&mut binding_payload, binding_receipt);
    let binding_result =
        kernel.handle_native_worker_reconcile(&handler_identity(binding_id), &binding_payload);
    assert!(
        matches!(binding_result, Err(NativeWorkerReconcileError::Conflict(_))),
        "changed retained binding must conflict, got {binding_result:?}"
    );

    let durable = load(&kernel, claim);
    assert_eq!(durable.state, NativeWorkerClaimState::Admitted);
    assert_eq!(durable.receipt_digest.as_deref(), Some(receipt.as_str()));
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn malformed_receipt_shape_fences_closed() {
    let root = temp_root("receipt-shape");
    let kernel = open_kernel(&root);
    let claim = "t5b02-shape-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);
    stage(
        &kernel,
        &claim_record(claim, "t5b02-shape-reg", 3, 2, &binding, Some(&receipt)),
    );

    // A present-but-non-object receipt is malformed and fails closed.
    let shape_id = "t5b02-shape-reconcile-1";
    let mut shape = reconcile_payload(shape_id, claim, &binding, 3, 2);
    shape["receipt"] = serde_json::json!("not-an-object");
    let shape_result = kernel.handle_native_worker_reconcile(&handler_identity(shape_id), &shape);
    assert!(
        matches!(shape_result, Err(NativeWorkerReconcileError::Shape { .. })),
        "non-object receipt must be Shape, got {shape_result:?}"
    );

    // A retained receipt bound to a different claim is malformed.
    let cross_id = "t5b02-shape-reconcile-2";
    let mut cross = reconcile_payload(cross_id, claim, &binding, 3, 2);
    payload_with_receipt(
        &mut cross,
        retained_receipt("t5b02-shape-other", &receipt, 3, 2),
    );
    let cross_result = kernel.handle_native_worker_reconcile(&handler_identity(cross_id), &cross);
    assert!(
        matches!(cross_result, Err(NativeWorkerReconcileError::Shape { .. })),
        "cross-claim receipt must be Shape, got {cross_result:?}"
    );

    // Zero generation / zero epoch never pass shape.
    let zero_id = "t5b02-shape-reconcile-3";
    let zero = kernel.handle_native_worker_reconcile(
        &handler_identity(zero_id),
        &reconcile_payload(zero_id, claim, &binding, 0, 2),
    );
    assert!(
        matches!(zero, Err(NativeWorkerReconcileError::Shape { .. })),
        "zero generation must be Shape, got {zero:?}"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: dispatch gates (Ready, peer, session fence, error mapping).
// ---------------------------------------------------------------------------

fn supervision_binding() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-1".to_owned(),
        host_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "host-lineage-1".to_owned(),
            sequence: 1,
        },
        activation_id: "activation-1".to_owned(),
        activation_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-1".to_owned(),
            sequence: 1,
        },
        watchdog_epoch: eliot_runtime_contracts::SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: eliot_runtime_contracts::SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("sealed supervision incarnation")
}

/// Drives one composition to `Ready` through the production Host handoff
/// (candidate -> shadow -> prepare -> permit -> ready). No gates are
/// weakened: this is the same contour the `c183` gate test uses.
fn drive_ready(kernel: &KernelComposition) {
    use eliot_kernel_service::{
        HostJobBinding, HostKernelCandidateBinding, KernelActivationPermit, KernelControlCommand,
        KernelReadyReceipt, RestartBudget,
    };
    use eliot_platform::PlatformHandle;
    let candidate = HostKernelCandidateBinding {
        installation_id: PlatformHandle::new("installation-1").expect("installation"),
        host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
        kernel_epoch: AuthorityEpoch::genesis(),
        activation_id: PlatformHandle::new("activation-1").expect("activation"),
        artifact_hash: PlatformHandle::new("artifact-1").expect("artifact"),
        config_hash: PlatformHandle::new("config-1").expect("config"),
        job_object_id: PlatformHandle::new("Local\\Eliot-Host-Kernel-test").expect("job"),
        pipe_identity: PlatformHandle::new(crate::KERNEL_CONTROL_PIPE).expect("pipe"),
        host_process: eliot_kernel_service::HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: r"C:\eliot\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: eliot_kernel_service::HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: r"C:\eliot\kernel.exe".to_owned(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: supervision_binding(),
        restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
        agent_bridge_admission: None,
        containment_action: None,
    };
    let mut service = kernel.service.lock().expect("service lock");
    service.reconcile(candidate.clone()).expect("reconcile");
    service.apply(KernelControlCommand::Shadow).expect("shadow");
    service
        .apply(KernelControlCommand::PrepareHandoff)
        .expect("prepare");
    let permit = KernelActivationPermit {
        operation_id: PlatformHandle::new("op-t5b02-reconcile").expect("operation"),
        candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: PlatformHandle::new("txn-1").expect("transaction"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: candidate.kernel_epoch,
        activation_nonce: eliot_platform::KernelActivationNonce::new(
            PlatformHandle::new("a".repeat(64)).expect("activation nonce"),
        )
        .expect("activation nonce"),
    };
    service
        .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .expect("activate");
    let ready = KernelReadyReceipt {
        activation_id: candidate.activation_id.clone(),
        activation_operation_id: permit.operation_id.clone(),
        activation_nonce_digest: service
            .activation_receipt()
            .expect("activation receipt")
            .activation_nonce_digest
            .clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10").expect("process"),
            job_object_id: candidate.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("ev1").expect("evidence")],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("ev1").expect("evidence")],
    };
    service.publish_ready(ready).expect("publish ready");
}

fn test_session(kernel: &KernelComposition) -> Session {
    let policy = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .clone();
    let peer = PeerIdentity::authenticated_for_test(
        eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
            .expect("process binding"),
        "S-1-5-18".to_owned(),
        "0".to_owned(),
    )
    .expect("peer");
    Session {
        connection_id: "t5b02-reconcile-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer,
        authority_epoch: policy.module_generation.state_fence.authority_epoch.value(),
        module_generation: policy.module_generation.clone(),
        launch_nonce: policy.launch_nonce.clone(),
        capabilities: policy.allowed_capabilities.clone(),
        privacy_classes: policy.allowed_privacy_classes.clone(),
        effects: policy.allowed_effects.clone(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn reconcile_frame(
    session: &Session,
    reconcile_id: &str,
    claim: &str,
    binding_digest: &str,
    generation: u64,
    epoch: u64,
) -> Frame {
    // The typed request identity is built through its JSON shape so this
    // test needs no new crate dependency beyond the production
    // `eliot-protocol` boundary: the fence below is the live session fence
    // serialized verbatim, keeping the dispatch session-fence check honest.
    let fence_value =
        serde_json::to_value(&session.module_generation.state_fence).expect("fence JSON");
    let clock_value =
        serde_json::to_value(eliot_contracts::ClockReading::default()).expect("clock JSON");
    let request_id = format!("t5b02-frame-{reconcile_id}");
    let identity_value = serde_json::json!({
        "request": {
            "metadata": {
                "request_id": request_id,
                "session_id": null,
                "task_id": null,
                "product_id": "eliot-native-worker",
                "source_id": "native-worker-transport",
                "state_fence": fence_value,
                "clock": clock_value,
            },
            "state_fence": fence_value,
        },
        "idempotency_key": reconcile_id,
        "deadline_unix_ms": 4_000_000_000_000u64,
        "cancellation_id": format!("t5b02-cancel-{reconcile_id}"),
    });
    let identity: RequestIdentity =
        serde_json::from_value(identity_value).expect("request identity");
    let claim_fence_value = claim_fence(epoch);
    let payload = serde_json::json!({
        "operation": NATIVE_WORKER_RECONCILE_OPERATION,
        "reconcile_id": reconcile_id,
        "claim": {
            "claim_id": claim,
            "binding_digest": binding_digest,
            "worker_generation": generation,
            "authority_epoch": epoch,
            "state_fence": claim_fence_value,
        },
    });
    let frame_request_id =
        serde_json::from_value::<eliot_contracts::RequestId>(serde_json::json!(request_id))
            .expect("frame request id");
    Frame {
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id.clone(),
        request_id: Some(frame_request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    }
}

#[test]
fn dispatch_gates_ready_peer_session_fence_and_maps_errors() {
    let root = temp_root("dispatch-gates");
    let claim = "t5b02-dispatch-claim";
    let binding = "c".repeat(64);
    let receipt = "d".repeat(64);

    // A cold composition fences before any claim work.
    {
        let cold = open_kernel(&root);
        let session = test_session(&cold);
        let frame = reconcile_frame(&session, "t5b02-cold-1", claim, &binding, 3, 1);
        assert!(
            matches!(
                cold.dispatch_native_worker_reconcile(&session, &frame),
                Err(TransportError::SessionFenced)
            ),
            "cold composition must fence reconcile"
        );
    }

    let kernel = open_kernel(&root);
    // Genesis generation/epoch: the standalone composition fences at
    // epoch/generation 1, so stage the claim there.
    stage(
        &kernel,
        &claim_record(claim, "t5b02-dispatch-reg", 1, 1, &binding, Some(&receipt)),
    );
    drive_ready(&kernel);
    let session = test_session(&kernel);

    // Exact reconcile replies with the durable receipt identity.
    let action = kernel
        .dispatch_native_worker_reconcile(
            &session,
            &reconcile_frame(&session, "t5b02-dispatch-1", claim, &binding, 1, 1),
        )
        .expect("dispatch reconcile");
    match action {
        KernelFrameAction::Reply(frame) => match &frame.payload {
            ProtocolPayload::Json(body) => assert_eq!(
                body["admission_receipt_digest"].as_str(),
                Some(receipt.as_str())
            ),
            _ => panic!("reconcile reply must be JSON"),
        },
        _ => panic!("reconcile must reply"),
    }

    // Unknown claim identity maps to UnknownRequest.
    assert!(
        matches!(
            kernel.dispatch_native_worker_reconcile(
                &session,
                &reconcile_frame(
                    &session,
                    "t5b02-dispatch-unknown",
                    "t5b02-no-such",
                    &binding,
                    1,
                    1
                )
            ),
            Err(TransportError::UnknownRequest)
        ),
        "unknown claim must map to UnknownRequest"
    );

    // Changed binding maps to IdentityConflict (64-char digest distinct
    // from the durable binding).
    let changed_binding = "e".repeat(64);
    assert_ne!(changed_binding, binding);
    assert!(
        matches!(
            kernel.dispatch_native_worker_reconcile(
                &session,
                &reconcile_frame(
                    &session,
                    "t5b02-dispatch-conflict",
                    claim,
                    &changed_binding,
                    1,
                    1
                )
            ),
            Err(TransportError::IdentityConflict)
        ),
        "changed binding must map to IdentityConflict"
    );

    // A stale session fence (foreign epoch in the frame identity) fences.
    let mut fenced_frame =
        reconcile_frame(&session, "t5b02-dispatch-fenced", claim, &binding, 1, 1);
    if let Some(identity) = fenced_frame.request_identity.as_mut() {
        let foreign = StateFence::new(
            AuthorityEpoch::new(999).expect("epoch"),
            ResourceGeneration::genesis(),
        );
        identity.request.state_fence = foreign.clone();
        identity.request.metadata.state_fence = foreign;
    }
    assert!(
        matches!(
            kernel.dispatch_native_worker_reconcile(&session, &fenced_frame),
            Err(TransportError::SessionFenced)
        ),
        "stale session fence must fence"
    );

    // An unauthenticated peer never reaches the claim table.
    let mut unauthenticated = session.clone();
    unauthenticated.peer = PeerIdentity::Unavailable {
        reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
    };
    assert!(
        matches!(
            kernel.dispatch_native_worker_reconcile(
                &unauthenticated,
                &reconcile_frame(
                    &unauthenticated,
                    "t5b02-dispatch-nopeer",
                    claim,
                    &binding,
                    1,
                    1
                )
            ),
            Err(TransportError::PeerIdentityUnavailable)
        ),
        "unauthenticated peer must not reach the claim table"
    );
    drop(kernel);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Acceptance: claim receipt is never an event-replay response (negative).
// ---------------------------------------------------------------------------

#[test]
fn claim_receipt_never_event_replay_response() {
    // The reconcile route owns no replay transport: `DurableReplayPort` has
    // no production implementor (only worker-core test fakes), and this
    // module must not declare another public replay trait nor a
    // Kernel-owned event journal. A route-generated digest is not a receipt.
    let source = include_str!("../native_worker_reconcile_route.rs");
    // Word-boundary aware: the prose legitimately says "acknowledgement"
    // (lost-ack recovery) and "replay" (exact-replay identity), so the
    // negative markers below name the typed replay/launch symbols, never
    // bare substrings.
    for forbidden in [
        "DurableReplayPort",
        "lookup_request",
        "begin_request",
        "fn acknowledge",
        ".acknowledge(",
        "EventEnvelope",
        "ProcessRequest",
        "activate_permit",
        "admit_native_worker_claim",
        "stage_and_finish_native_worker_claim_admission",
    ] {
        assert!(
            !source.contains(forbidden),
            "reconcile route must not contain event-replay/launch authority {forbidden:?}"
        );
    }
    // The durable admission identity is echoed verbatim; the route mints no
    // second identity and performs no launch.
    for required in [
        "admission_receipt_digest",
        "Unknown",
        "Reconciling",
        "Terminal",
        "IdentityConflict",
    ] {
        assert!(
            source.contains(required),
            "reconcile route must retain its identity contract marker {required:?}"
        );
    }
    // U3 owner note: the admitted replay transport + durable stream owner
    // are unsupplied; this test freezes that projection instead of wiring it.
}
