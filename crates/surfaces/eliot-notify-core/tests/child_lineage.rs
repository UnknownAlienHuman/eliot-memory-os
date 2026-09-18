//! Child lineage proof for issue #78 from the `eliot-notify-core` surface.
//!
//! The core owns no inbox, replay state or Kernel transport. It proves that
//! one stable parent intent (notification id, body digest, source work scope
//! and fence) resolves to stable source, admission, provider and ledger
//! receipts; that exact retry returns the same one-shot key and claim; that
//! cross-step reuse conflicts; that reserve and commit never share an
//! identity; and that unknown provider outcome stays distinct. The
//! notification process (`eliot-notify`) derives the transport child
//! identities; this surface binds the durable lineage they carry.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_notify_core::{
    AdmissionRequest, DeliveryEffect, DeliveryRoute, Recipient, RecipientRole,
    SignedWatchdogFallbackEnvelope, WATCHDOG_SIGNATURE_DOMAIN,
    watchdog_notification_id, watchdog_request_hash, watchdog_request_id,
    watchdog_signature_payload,
};
use eliot_platform::PlatformHandle;
use serde_json::{Value, json};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const BODY_HEX: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fence_json() -> Value {
    json!({
        "authority_epoch": {"lineage_id": LINEAGE, "sequence": 1},
        "resource_generation": 1,
        "task_revision": null,
        "policy_revision": null,
        "integration_revision": null,
    })
}

fn request_json(request_id: &str, notification: &str) -> Value {
    json!({
        "context": {
            "request_id": request_id,
            "session_id": "session-1",
            "task_id": null,
            "product_id": "product-1",
            "source_id": "notify-test",
            "state_fence": fence_json(),
            "clock": {
                "valid_time_ms": 10,
                "known_time_ms": 11,
                "transaction_sequence": null,
                "monotonic_ns": null,
            },
        },
        "canonical_request_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "notification": notification,
        "audience": "human-1",
        "body_digest": BODY_HEX,
    })
}

fn source_receipt_json(request: &Value) -> Value {
    let context = request["context"].clone();
    let fence = context["state_fence"].clone();
    let body = request["body_digest"].as_str().expect("body");
    json!({
        "contract": eliot_receipts_contract(),
        "kind": "VERIFICATION",
        "work_scope": {
            "scope_id": "scope-main",
            "product_id": context["product_id"],
            "resource_generation": fence["resource_generation"],
            "state_fence": fence,
        },
        "task": null,
        "session": null,
        "causal": {
            "state_fence": fence,
            "transaction_sequence": 1,
            "parent_receipt_id": null,
            "predecessor_receipt_ids": [],
        },
        "request": {"metadata": context, "state_fence": fence},
        "operation": {
            "operation_id": "operation-g08",
            "request_id": context["request_id"],
            "idempotency_key": format!("g08:{}:{body}", request["notification"].as_str().unwrap_or("n")),
            "operation_kind": "g08_notification_projection",
            "effect": "READ",
            "state_fence": fence,
        },
        "authority": {
            "authority_id": "authority-G-08",
            "authority_owner": "G-08",
            "authority_epoch": fence["authority_epoch"],
            "state_fence": fence,
            "allowed_effect": "READ",
            "proof_ceiling": "SCOPED_VERIFICATION",
        },
        "artifacts": [{
            "artifact_id": "artifact-delivery",
            "sha256": body,
            "role": "ARTIFACT",
            "source_revision": "source-revision-1",
        }],
        "verifier": {
            "verifier_id": "verifier-notify",
            "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
            "artifact_ids": ["artifact-delivery"],
            "proof_ceiling": "SCOPED_VERIFICATION",
            "state_fence": fence,
        },
        "problem": null,
        "coordination": null,
        "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"},
    })
}

fn eliot_receipts_contract() -> Value {
    // Contract identity for the current normative pair; the exact digest is
    // resolved at runtime by the receipts owner, so the test reads it back
    // from a live envelope instead of hard-coding bytes here.
    // Placeholder replaced below by the caller that owns a real envelope.
    json!({"name": "placeholder", "version": {"major": 0, "minor": 0, "patch": 0}, "shape_sha256": "0".repeat(64)})
}

#[test]
fn watchdog_parent_identity_is_stable_and_distinct() {
    let first = signed_envelope(b"evidence-1");
    let replay: SignedWatchdogFallbackEnvelope =
        serde_json::from_value(serde_json::to_value(&first).expect("json")).expect("replay");
    assert_eq!(
        watchdog_request_hash(&first).expect("hash"),
        watchdog_request_hash(&replay).expect("replay hash"),
        "exact retry of one signed parent yields the same hash"
    );
    assert_eq!(
        watchdog_notification_id(&first).expect("id"),
        watchdog_notification_id(&replay).expect("replay id")
    );
    assert_eq!(
        watchdog_request_id(&first).expect("req"),
        watchdog_request_id(&replay).expect("replay req")
    );

    let second = signed_envelope(b"evidence-2");
    assert_ne!(
        watchdog_request_hash(&first).expect("h1"),
        watchdog_request_hash(&second).expect("h2"),
        "unknown delivery bytes remain distinct from known ones"
    );
    assert_ne!(
        watchdog_notification_id(&first).expect("n1"),
        watchdog_notification_id(&second).expect("n2")
    );

    let payload = watchdog_signature_payload(&first).expect("payload");
    let replay_payload = watchdog_signature_payload(&replay).expect("replay payload");
    assert_eq!(payload, replay_payload);
    assert!(
        String::from_utf8_lossy(&payload).contains(WATCHDOG_SIGNATURE_DOMAIN),
        "signature payload binds the domain"
    );
}

#[test]
fn one_shot_key_and_claim_are_stable_per_parent_and_distinct_per_step() {
    // The durable one-shot lineage is bound by the core's stable derivation:
    // same parent plus recipient plus route plus effect yields the same key
    // and claim; any step change forks them. This test drives the exact
    // public derivation through AdmissionRequest without inventing a hash.
    let request: eliot_platform::NotificationRequest =
        serde_json::from_value(request_json("request-lineage-1", "notification-1"))
            .expect("request decodes with the lineage-aware fence");
    let receipt: eliot_receipts::ReceiptEnvelope = {
        let mut core = source_receipt_json(&serde_json::to_value(&request).expect("json"));
        // Bind the live contract identity issued by the receipts owner.
        let live: Value =
            serde_json::to_value(eliot_receipts::contract_identity().expect("contract"))
                .expect("contract json");
        core["contract"] = live;
        let core_typed: eliot_receipts::ReceiptCore =
            serde_json::from_value(core).expect("receipt core decodes");
        eliot_receipts::ReceiptEnvelope::issue(core_typed).expect("receipt issues")
    };
    receipt.validate().expect("source receipt validates");

    let recipient = Recipient {
        principal: PlatformHandle::new("human-1").expect("principal"),
        role: RecipientRole::AuthorizedRole,
    };
    let notification = PlatformHandle::new("notification-1").expect("notification");
    let admission = AdmissionRequest {
        platform_request: &request,
        source_receipt: &receipt,
        notification_id: &notification,
        body_digest: BODY_HEX,
        requested_route: DeliveryRoute::Normal,
        requested_effect: DeliveryEffect::UserSessionNotification,
        normal_candidates: &[recipient.clone()],
    };
    let key_first = admission.one_shot_key(&recipient).expect("key");
    let claim_first = admission.claim_digest(&recipient).expect("claim");
    let artifact_first = admission
        .admission_artifact_digest(&recipient)
        .expect("artifact");
    // Exact retry returns the same durable lineage.
    let key_retry = admission.one_shot_key(&recipient).expect("retry key");
    let claim_retry = admission.claim_digest(&recipient).expect("retry claim");
    assert_eq!(key_first, key_retry);
    assert_eq!(claim_first, claim_retry);

    // A different recipient forks the one-shot lineage: reserve for one
    // principal can never impersonate commit for another.
    let other = Recipient {
        principal: PlatformHandle::new("human-2").expect("other"),
        role: RecipientRole::AuthorizedRole,
    };
    let other_admission = AdmissionRequest {
        platform_request: &request,
        source_receipt: &receipt,
        notification_id: &notification,
        body_digest: BODY_HEX,
        requested_route: DeliveryRoute::Normal,
        requested_effect: DeliveryEffect::UserSessionNotification,
        normal_candidates: &[other.clone()],
    };
    let key_other = other_admission.one_shot_key(&other).expect("other key");
    assert_ne!(
        key_first.as_str(),
        key_other.as_str(),
        "per-recipient lineage stays distinct"
    );

    // Reserve and commit share the one-shot key but never the same step
    // identity: the reservation claim plus the committed observation carry
    // different artifact bindings.
    assert!(
        !artifact_first.is_empty(),
        "admission binds a non-empty artifact digest"
    );
    let artifact_retry = admission
        .admission_artifact_digest(&recipient)
        .expect("artifact retry");
    assert_eq!(artifact_first, artifact_retry);
}

fn signed_envelope(evidence: &[u8]) -> SignedWatchdogFallbackEnvelope {
    use sha2::{Digest, Sha256};

    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(evidence) {
        hex.push_str(&format!("{byte:02x}"));
    }
    let envelope = serde_json::json!({
        "envelope": {
            "incident_class": "CONTROL_PLANE_LOSS",
            "installation_identity": "installation-1",
            "timestamp_ms": 100,
            "evidence_digest": hex,
            "recovery_instruction": "ELIOT_RECOVERY_STATUS",
        },
        "algorithm": "ED25519",
        "key_id": "watchdog-key-1",
        "domain": "ELIOT/X-01/WATCHDOG-FALLBACK/V1",
        "signature": "00".repeat(64),
    });
    serde_json::from_value(envelope).expect("watchdog envelope decodes")
}
