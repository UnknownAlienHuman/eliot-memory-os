//! Issue #2898 W10/A6 — a lost response or an exact retry reconciles the ONE
//! durable decision against the OWNER's persisted record.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures fail fast on a missing owner row or an unreachable setup step"
)]
//!
//! The seam under test is the production handler
//! [`handle_host_event`], driven over the real bounded HTTP head parser, the
//! real `gate.rs` validators, and the real durable-port contract. The
//! admission port below is a fake that reproduces the ORS bridge-event
//! idempotency exactly as the owner implements it: durable rows are the
//! canonical envelope bytes keyed by `(stream_id, event_id)`, the owner answers
//! `Duplicate` only when the presented bytes equal the stored row, `Conflict`
//! when the identity is known with different content, and fresh otherwise. Its
//! candidate set is the process-local hint a bridge restart empties, never the
//! authority.
//!
//! Two cases, both required by the item: the positive exact retry across a
//! restart, and the determined refusal for the same operation identity
//! carrying changed content.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use eliot_agent_opencode::{
    ActionGate, ActionGateDecision, ActionGateError, ActionGateRequest, CredentialResolver,
    DECISION_ALLOW, EffectDecisionRecord, HOST_EVENTS_PATH, HOST_EVENTS_STREAM_ID,
    HostEventAdmission, HostEventAdmissionError, HostEventAdmissionFailure,
    HostEventAdmissionReceipt, HostEventGap, HostEventPorts, HostEventSubmission, HttpOutcome,
    IntroductionStore, REASON_IDENTITY_CONFLICT, handle_host_event, parse_http_head,
    recompute_effect_digest,
};
use eliot_contracts::{EpochId, EpochLineageId, sha256_hex};
use eliot_process::{Generation, SecretRef};
use eliot_user_broker_core::{
    OPENCODE_BRIDGE_CAPABILITIES, OpenCodeBridgeIntroduction, OpenCodeIntroductionParams,
    OpenCodeProcessBinding, OpenCodeSessionFacts,
};
use secrecy::SecretString;
use serde_json::{Value, json};

const BEARER: &str = "0123456789abcdef0123456789abcdef";
const PORT: u16 = 53_217;
const NOW_MS: u64 = 1_800_000_000_000;
const EVENT_ID: &str =
    "opencode:effect:64d799a6061269b3080cecc529e34d127f492cf794910767c03afd923fee853b:call-1";
const DECISION_STREAM: &str = "opencode.host-events.v1.decisions";
const FENCE_ID: &str = "fence-nonce-1";
const BRIDGE_GENERATION: u64 = 7;
const EPOCH_SEQUENCE: u64 = 3;
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
/// A decision expiry far past the fixed test clock, so the same evaluation is
/// reached on every request and the record stays byte-comparable.
const DECISION_EXPIRY_MS: u64 = 4_102_444_800_000;

/// The OWNER's durable bridge-event rows.
///
/// This is the only state that survives a "restart" in these cases: the row is
/// the canonical envelope bytes the owner persisted, and nothing about the
/// decision can be recovered from anywhere else.
#[derive(Default)]
struct DurableOwner {
    rows: BTreeMap<(String, String), Vec<u8>>,
}

/// The owner's own idempotency answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteAnswer {
    Fresh,
    Duplicate,
    Conflict,
}

impl DurableOwner {
    fn forward(&mut self, stream_id: &str, event_id: &str, bytes: &[u8]) -> RouteAnswer {
        let key = (stream_id.to_owned(), event_id.to_owned());
        match self.rows.get(&key) {
            Some(stored) if stored == bytes => RouteAnswer::Duplicate,
            Some(_) => RouteAnswer::Conflict,
            None => {
                self.rows.insert(key, bytes.to_vec());
                RouteAnswer::Fresh
            }
        }
    }

    fn row(&self, stream_id: &str, event_id: &str) -> Option<Vec<u8>> {
        self.rows
            .get(&(stream_id.to_owned(), event_id.to_owned()))
            .cloned()
    }

    fn row_count(&self, stream_id: &str) -> usize {
        self.rows
            .keys()
            .filter(|(stream, _)| stream == stream_id)
            .count()
    }
}

/// The canonical bytes the owner persists for one retained host event.
fn event_bytes(submission: &HostEventSubmission) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "stream_id": submission.stream_id.clone(),
        "producer_id": submission.producer_id.clone(),
        "event_id": submission.event_id.clone(),
        "sequence": submission.sequence,
        "transport_hash": submission.transport_hash.clone(),
        "payload": submission.envelope_json.clone(),
    }))
    .unwrap_or_default()
}

/// The canonical bytes the owner persists for one effect decision: the closed,
/// versioned record itself, not a digest standing in for it.
fn decision_bytes(record: &EffectDecisionRecord) -> Vec<u8> {
    serde_json::to_vec(&record.to_json()).unwrap_or_default()
}

/// Durable admission over the shared owner rows.
///
/// `candidates` is the process-local hint only: it lets an in-process retry
/// re-present the exact bytes, and a bridge restart empties it. Every stored
/// record still has to come back from the owner's `Duplicate`.
struct DurableRouteAdmission {
    owner: Arc<Mutex<DurableOwner>>,
    candidates: BTreeMap<String, EffectDecisionRecord>,
}

impl DurableRouteAdmission {
    fn new(owner: Arc<Mutex<DurableOwner>>) -> Self {
        Self {
            owner,
            candidates: BTreeMap::new(),
        }
    }
}

impl HostEventAdmission for DurableRouteAdmission {
    fn admit(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        submission: &HostEventSubmission,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        let bytes = event_bytes(submission);
        let envelope_digest = sha256_hex(&bytes);
        let answer = self.owner.lock().map_err(|_| poisoned())?.forward(
            &submission.stream_id,
            &submission.event_id,
            &bytes,
        );
        if answer == RouteAnswer::Conflict {
            // The owner compared the presented bytes against the row it holds
            // for this identity and they differ: a determined refusal.
            return Err(HostEventAdmissionError::of(
                HostEventAdmissionFailure::Conflict,
            ));
        }
        // The durable read-back: a candidate this process holds is re-presented
        // and only the owner's `Duplicate` may report it as persisted.
        let candidate = self.candidates.get(&submission.event_id).cloned();
        let replayed_decision = match candidate {
            Some(candidate) => {
                let replay = self.owner.lock().map_err(|_| poisoned())?.forward(
                    DECISION_STREAM,
                    &candidate.operation_id,
                    &decision_bytes(&candidate),
                );
                match replay {
                    RouteAnswer::Duplicate => Some(candidate),
                    _ => None,
                }
            }
            None => None,
        };
        Ok(receipt(
            &submission.stream_id,
            &submission.event_id,
            answer == RouteAnswer::Duplicate,
            &envelope_digest,
            // The decision read-back is carried, not dropped: it is what lets
            // the handler skip `ActionGate::decide` on an exact retry.
            replayed_decision,
        ))
    }

    fn commit_decision(
        &mut self,
        record: &EffectDecisionRecord,
    ) -> Result<HostEventAdmissionReceipt, HostEventAdmissionError> {
        let answer = self.owner.lock().map_err(|_| poisoned())?.forward(
            DECISION_STREAM,
            &record.operation_id,
            &decision_bytes(record),
        );
        let replayed_decision = match answer {
            RouteAnswer::Conflict => {
                return Err(HostEventAdmissionError::of(
                    HostEventAdmissionFailure::Conflict,
                ));
            }
            RouteAnswer::Duplicate => Some(record.clone()),
            RouteAnswer::Fresh => None,
        };
        self.candidates
            .insert(record.operation_id.clone(), record.clone());
        Ok(HostEventAdmissionReceipt {
            stream_id: DECISION_STREAM.to_owned(),
            event_id: record.operation_id.clone(),
            phase: "DURABLE".to_owned(),
            disposition: if replayed_decision.is_some() {
                "duplicate".to_owned()
            } else {
                "accepted".to_owned()
            },
            envelope_digest: record.decision_receipt.clone(),
            replayed: replayed_decision.is_some(),
            cursor_advanced: false,
            authority_epoch: test_epoch(),
            fence_id: FENCE_ID.to_owned(),
            bridge_generation: BRIDGE_GENERATION,
            replayed_decision,
        })
    }

    fn report_gap(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        _gap: &HostEventGap,
    ) -> Result<(), HostEventAdmissionError> {
        Ok(())
    }
}

fn receipt(
    stream_id: &str,
    event_id: &str,
    replayed: bool,
    envelope_digest: &str,
    replayed_decision: Option<EffectDecisionRecord>,
) -> HostEventAdmissionReceipt {
    HostEventAdmissionReceipt {
        stream_id: stream_id.to_owned(),
        event_id: event_id.to_owned(),
        phase: "DURABLE".to_owned(),
        disposition: if replayed {
            "duplicate".to_owned()
        } else {
            "accepted".to_owned()
        },
        envelope_digest: envelope_digest.to_owned(),
        replayed,
        cursor_advanced: false,
        authority_epoch: test_epoch(),
        fence_id: FENCE_ID.to_owned(),
        bridge_generation: BRIDGE_GENERATION,
        // The persisted decision the owner proved by answering `Duplicate`
        // for those exact bytes, or None when nothing was replayed. This is
        // the read-back the handler branches on, so it must not be dropped
        // here: a receipt that always said None would force a second policy
        // evaluation and the case would prove the opposite of what it claims.
        replayed_decision,
    }
}

/// Counts `ActionGate` consultations. The counter is what proves whether a
/// second policy evaluation of an already-decided operation happened.
struct CountingGate {
    calls: Arc<AtomicUsize>,
}

impl ActionGate for CountingGate {
    fn decide(
        &mut self,
        _introduction: &OpenCodeBridgeIntroduction,
        _receipt: &HostEventAdmissionReceipt,
        request: &ActionGateRequest,
    ) -> Result<ActionGateDecision, ActionGateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ActionGateDecision {
            request_hash: request.request_hash.clone(),
            allow: true,
            policy_revision: "policy-1".to_owned(),
            authority_revision: "authority-1".to_owned(),
            expires_at_ms: DECISION_EXPIRY_MS,
            decision_receipt: format!("governor-receipt-{}", request.request_hash),
            reason_code: None,
        })
    }
}

struct FixedStore {
    introduction: OpenCodeBridgeIntroduction,
    facts: OpenCodeSessionFacts,
}

impl IntroductionStore for FixedStore {
    fn current_introduction(&self) -> Option<OpenCodeBridgeIntroduction> {
        Some(self.introduction.clone())
    }

    fn is_revoked(&self, _revocation_id: &str) -> bool {
        false
    }

    fn session_facts(&self) -> OpenCodeSessionFacts {
        self.facts.clone()
    }

    fn now_ms(&self) -> u64 {
        NOW_MS
    }
}

struct FixedCredential;

impl CredentialResolver for FixedCredential {
    type Error = std::io::Error;

    fn resolve(&self, _handle: &SecretRef) -> Result<SecretString, Self::Error> {
        Ok(SecretString::from(BEARER.to_owned()))
    }
}

type Ports = HostEventPorts<DurableRouteAdmission, CountingGate, FixedStore, FixedCredential>;

fn ports(owner: &Arc<Mutex<DurableOwner>>, calls: Arc<AtomicUsize>) -> Ports {
    Ports {
        // The owner handle is borrowed and cloned here, so the call sites keep
        // their own handle for the assertions that read the same rows.
        admission: DurableRouteAdmission::new(Arc::clone(owner)),
        gate: CountingGate { calls },
        introductions: FixedStore {
            introduction: introduction(),
            facts: facts(),
        },
        credentials: FixedCredential,
    }
}

/// One `POST /v1/host-events` over the real bounded head parser.
fn post(ports: &mut Ports, body: &[u8]) -> HttpOutcome {
    let mut raw = Vec::new();
    for line in [
        format!("POST {HOST_EVENTS_PATH} HTTP/1.1"),
        format!("Host: 127.0.0.1:{PORT}"),
        "Content-Type: application/json".to_owned(),
        format!("Content-Length: {}", body.len()),
        format!("Authorization: Bearer {BEARER}"),
        format!("Idempotency-Key: {EVENT_ID}"),
    ] {
        raw.extend_from_slice(line.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    let head =
        parse_http_head(&raw, PORT).expect("the fixture head is a valid bounded request head");
    handle_host_event(&head, body, PORT, ports)
}

fn gate_payload(argument_digest: &str) -> Value {
    let tool = "bash";
    let argument_keys = vec!["command".to_owned()];
    let effect_digest = recompute_effect_digest(
        tool,
        &argument_keys,
        argument_digest,
        "eliot.opencode.effect.v1",
        "eliot.opencode.arguments.v1",
    )
    .expect("the fixture descriptor is canonicalizable");
    json!({
        "event_id": EVENT_ID,
        "sequence": 1,
        "emitted_at": "2026-09-15T18:14:45.835Z",
        "event_kind": "tool.execute.before",
        "vendor_event_kind": "tool.execute.before",
        "host_session_id": null,
        "task_id": "task-1",
        "work_item_id": null,
        "tool": tool,
        "changed_path": null,
        "argument_keys": argument_keys.clone(),
        "attached_task": true,
        "effect_descriptor": {
            "schema_version": "eliot.opencode.effect.v1",
            "normalization_version": "eliot.opencode.arguments.v1",
            "tool": tool,
            "argument_keys": argument_keys,
            "argument_digest": argument_digest,
        },
        "effect_digest": effect_digest,
    })
}

/// The plugin vector's `bash {command}` argument digest, and a second
/// descriptor over the same operation identity for the refusal case.
const ORIGINAL_ARGUMENT_DIGEST: &str =
    "c0a81a95602d7ae3abbc9f673b3716a22969188b16657bf0429daea2dcb05b00";
const CHANGED_ARGUMENT_DIGEST: &str =
    "b1a81a95602d7ae3abbc9f673b3716a22969188b16657bf0429daea2dcb05b01";

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE).expect("valid lineage"),
        NonZeroU64::new(EPOCH_SEQUENCE).expect("nonzero epoch sequence"),
    )
    .expect("valid epoch")
}

fn facts() -> OpenCodeSessionFacts {
    OpenCodeSessionFacts {
        installation_id: "installation-1".to_owned(),
        windows_sid: "S-1-5-21-1-2-3-1001".to_owned(),
        interactive_session_id: "session-1".to_owned(),
        broker_generation: Generation::new(5).expect("nonzero broker generation"),
        bridge_generation: Generation::new(BRIDGE_GENERATION).expect("nonzero bridge generation"),
        launch_nonce: "launch-nonce-1".to_owned(),
        executable_digest: "c".repeat(64),
    }
}

fn introduction() -> OpenCodeBridgeIntroduction {
    OpenCodeBridgeIntroduction::mint(OpenCodeIntroductionParams {
        installation_id: "installation-1".to_owned(),
        windows_sid: "S-1-5-21-1-2-3-1001".to_owned(),
        interactive_session_id: "session-1".to_owned(),
        broker_generation: Generation::new(5).expect("nonzero broker generation"),
        bridge_generation: Generation::new(BRIDGE_GENERATION).expect("nonzero bridge generation"),
        endpoint: format!("http://127.0.0.1:{PORT}"),
        server_identity: "a".repeat(64),
        bootstrap_channel: None,
        credential: SecretRef::new("opencode-route", "route-credential")
            .expect("valid credential handle"),
        credential_expires_at: NOW_MS + 3_600_000,
        allowed_capabilities: OPENCODE_BRIDGE_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
        authority_epoch: test_epoch(),
        fence_id: FENCE_ID.to_owned(),
        issued_at: NOW_MS - 60_000,
        expires_at: NOW_MS + 3_600_000,
        revocation_id: "revocation-1".to_owned(),
        process_binding: OpenCodeProcessBinding {
            executable_digest: "c".repeat(64),
            launch_nonce: "launch-nonce-1".to_owned(),
            parent_broker_process_id: "4242".to_owned(),
        },
    })
    .expect("the fixture introduction mints")
}

fn poisoned() -> HostEventAdmissionError {
    HostEventAdmissionError::of(HostEventAdmissionFailure::Unavailable)
}

fn text<'a>(body: &'a Value, field: &str) -> &'a str {
    body.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{field} must be a string"))
}

/// **Positive case.** The first request commits one durable event and one
/// durable decision. The response is then lost, the bridge process restarts
/// (a fresh admission object with an empty in-process candidate set over the
/// same owner rows), and the byte-identical retry must reconcile the original
/// decision: `200`, `replayed: true`, the same decision commitment, one
/// durable event row and one durable decision row, and never a `503` that
/// would invite resubmitting settled content.
#[test]
fn exact_retry_after_a_restart_reconciles_the_one_durable_decision() {
    let owner = Arc::new(Mutex::new(DurableOwner::default()));
    let calls = Arc::new(AtomicUsize::new(0));
    let body = serde_json::to_vec(&gate_payload(ORIGINAL_ARGUMENT_DIGEST)).expect("fixture body");

    let mut first_process = ports(&owner, Arc::clone(&calls));
    let first = post(&mut first_process, &body);
    assert_eq!(first.status, 200, "the first gate request must be answered");
    assert_eq!(text(&first.body, "decision"), DECISION_ALLOW);
    assert_eq!(first.body.get("replayed"), Some(&json!(false)));
    let first_decision_receipt = text(&first.body, "decision_receipt").to_owned();
    let first_event_receipt = text(&first.body, "event_receipt").to_owned();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The response is lost. The process restarts: same owner rows, empty
    // candidate set, fresh counter.
    let mut restarted = ports(&owner, Arc::new(AtomicUsize::new(0)));
    assert!(
        restarted.admission.candidates.is_empty(),
        "a restarted bridge must hold no in-process decision candidate"
    );
    let retry = post(&mut restarted, &body);
    assert_eq!(
        retry.status, 200,
        "an exact retry must reconcile the persisted decision, not fail closed"
    );
    assert_eq!(text(&retry.body, "decision"), DECISION_ALLOW);
    assert_eq!(
        retry.body.get("replayed"),
        Some(&json!(true)),
        "the reconciled answer must report the replay of the original decision"
    );
    assert_eq!(
        text(&retry.body, "decision_receipt"),
        first_decision_receipt,
        "the retry must return the one durable decision, not a new one"
    );
    assert_eq!(text(&retry.body, "event_receipt"), first_event_receipt);

    let rows = owner.lock().expect("owner rows");
    assert_eq!(
        rows.row_count(HOST_EVENTS_STREAM_ID),
        1,
        "the retry must not create a second durable host event"
    );
    assert_eq!(
        rows.row_count(DECISION_STREAM),
        1,
        "the retry must not create a second durable decision"
    );
    assert_eq!(
        rows.row(DECISION_STREAM, EVENT_ID),
        Some(
            restarted
                .admission
                .candidates
                .get(EVENT_ID)
                .map(decision_bytes)
                .expect("the retried process must hold the reconciled record")
        ),
        "the persisted decision row must be exactly the record that was reconciled"
    );
    drop(rows);

    // The same process that still holds the candidate re-presents it and takes
    // the replay branch, so the `ActionGate` is not consulted a second time for
    // an operation that already holds a durable decision.
    let same_process = post(&mut first_process, &body);
    assert_eq!(same_process.status, 200);
    assert_eq!(same_process.body.get("replayed"), Some(&json!(true)));
    assert_eq!(
        text(&same_process.body, "decision_receipt"),
        first_decision_receipt
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a replayed operation must never be evaluated by the gate again"
    );
}

/// **Refusal case.** The same operation identity carrying changed content is a
/// determined conflict: not a replay, and never the retryable
/// `UNAVAILABLE_OR_CAPACITY`/`DB_UNAVAILABLE` a lost write would produce.
#[test]
fn changed_content_under_one_operation_identity_is_a_determined_conflict() {
    let owner = Arc::new(Mutex::new(DurableOwner::default()));
    let calls = Arc::new(AtomicUsize::new(0));
    let admitted =
        serde_json::to_vec(&gate_payload(ORIGINAL_ARGUMENT_DIGEST)).expect("fixture body");
    let altered = serde_json::to_vec(&gate_payload(CHANGED_ARGUMENT_DIGEST)).expect("fixture body");

    let mut first_process = ports(&owner, Arc::clone(&calls));
    let first = post(&mut first_process, &admitted);
    assert_eq!(first.status, 200);
    assert_eq!(first.body.get("replayed"), Some(&json!(false)));
    let persisted = owner
        .lock()
        .expect("owner rows")
        .row(DECISION_STREAM, EVENT_ID)
        .expect("the first request persisted its decision");

    // Same operation identity, different command: the owner compares the
    // presented bytes against the row it holds and refuses.
    let mut restarted = ports(&owner, Arc::new(AtomicUsize::new(0)));
    let conflict = post(&mut restarted, &altered);
    assert_eq!(
        conflict.status, 409,
        "changed content under a known identity must be a determined conflict"
    );
    assert_eq!(
        text(&conflict.body, "reason_code"),
        REASON_IDENTITY_CONFLICT
    );
    assert_ne!(
        conflict.body.get("decision"),
        Some(&json!(DECISION_ALLOW)),
        "a conflict must never answer with a permit"
    );

    let rows = owner.lock().expect("owner rows");
    assert_eq!(rows.row_count(HOST_EVENTS_STREAM_ID), 1);
    assert_eq!(rows.row_count(DECISION_STREAM), 1);
    // `persisted` is cloned here because the replay assertion below still
    // compares the settled row against it; only ownership of the bytes differs.
    assert_eq!(
        rows.row(DECISION_STREAM, EVENT_ID),
        Some(persisted.clone()),
        "a determined conflict performs no transition"
    );
    drop(rows);

    // The original content still replays: a conflict for the altered variant
    // must not poison the settled decision.
    let replay = post(&mut restarted, &admitted);
    assert_eq!(replay.status, 200);
    assert_eq!(replay.body.get("replayed"), Some(&json!(true)));
    assert_eq!(
        owner
            .lock()
            .expect("owner rows")
            .row(DECISION_STREAM, EVENT_ID),
        Some(persisted),
        "replaying the original content must not disturb the settled decision"
    );
}
