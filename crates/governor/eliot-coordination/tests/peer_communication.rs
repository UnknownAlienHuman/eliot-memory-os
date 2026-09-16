// Integration proof over 35 cases: every step asserts through `.expect` with a
// message naming the invariant, so failures point at the broken guarantee.
// Threading `Result` through all 35 cases would churn the proof without
// strengthening it. This is the only file-level allow: `unwrap_used` needs
// none (no `.unwrap()` calls exist; the one fallback uses `Option::unwrap_or`
// with a default) and `similar_names` does not fire on this file.
#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_coordination::{
    AdmitArtifactRevision, AnchorResolution, AnchoredReview, ArgumentAcceptability, AssertedEffect,
    BoardCompactionPolicy, ConflictCandidateDraft, CoordinationError, CoordinationOwner,
    EmbeddedMarkerDraft, EmbeddedMarkerKind, EnqueuePeerMessage, ExternalResolutionReceipt,
    LiveDeltaKind, PeerBoardKind, PeerClockPort, PeerConflictDimension, PeerConflictState,
    PeerConflictType, PeerDeliveryAttempt, PeerDeliveryPort, PeerDeliveryTarget, PeerDurability,
    PeerDurabilityAttestation, PeerDurabilityPort, PeerMessageKind, PeerMessageState,
    PeerReviewAdvance, PeerReviewStanding, PeerStreamId, PostBoardEntry, PrivacyClass, RawField,
    RecordPeerConflict, RegisterSession, ReviewCompleteness, ReviewKind, ReviewRecommendation,
    ReviewTargetKind, ReviseBoardEntry, SubmitPeerReview, WorkItem, WorkState,
    decode_peer_envelope,
};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

fn test_epoch(sequence: u64) -> EpochId {
    let lineage = EpochLineageId::new(LINEAGE_A).expect("canonical test lineage");
    EpochId::new(lineage, NonZeroU64::new(sequence).expect("non-zero")).expect("valid test epoch")
}

fn foreign_epoch() -> EpochId {
    let lineage = EpochLineageId::new(LINEAGE_B).expect("foreign test lineage");
    EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("valid foreign epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn fence_for(epoch: EpochId) -> StateFence {
    StateFence::new(epoch, ResourceGeneration::genesis())
}

// ---- finite-fixture JSON subset parser (objects of string/int/string-list) ----

#[derive(Debug, Clone, PartialEq)]
enum JVal {
    Str(String),
    Int(i64),
    Arr(Vec<JVal>),
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonCursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn eat_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn expect_byte(&mut self, want: u8, what: &str) -> Result<(), String> {
        self.eat_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == want {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {what} at offset {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"', "string open")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            if self.pos >= self.bytes.len() {
                return Err("unterminated string".to_owned());
            }
            let byte = self.bytes[self.pos];
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).map_err(|_| "bad utf8".to_owned()),
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        return Err("unterminated escape".to_owned());
                    }
                    let escaped = self.bytes[self.pos];
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        other => {
                            out.push(b'\\');
                            out.push(other);
                        }
                    }
                }
                _ => out.push(byte),
            }
        }
    }

    fn parse_int(&mut self) -> Result<i64, String> {
        self.eat_ws();
        let start = self.pos;
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(format!("expected integer at offset {}", self.pos));
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "bad int utf8".to_owned())?
            .parse::<i64>()
            .map_err(|_| "bad integer".to_owned())
    }

    fn parse_value(&mut self) -> Result<JVal, String> {
        self.eat_ws();
        if self.pos >= self.bytes.len() {
            return Err("unexpected end of fixture".to_owned());
        }
        match self.bytes[self.pos] {
            b'"' => Ok(JVal::Str(self.parse_string()?)),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.eat_ws();
                    if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
                        self.pos += 1;
                        return Ok(JVal::Arr(items));
                    }
                    if self.pos < self.bytes.len() && self.bytes[self.pos] == b'"' {
                        items.push(JVal::Str(self.parse_string()?));
                    } else {
                        items.push(JVal::Int(self.parse_int()?));
                    }
                    self.eat_ws();
                    if self.pos < self.bytes.len() && self.bytes[self.pos] == b',' {
                        self.pos += 1;
                    }
                }
            }
            _ => Ok(JVal::Int(self.parse_int()?)),
        }
    }

    fn parse_object(&mut self) -> Result<BTreeMap<String, JVal>, String> {
        self.expect_byte(b'{', "object open")?;
        let mut map = BTreeMap::new();
        loop {
            self.eat_ws();
            if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
                self.pos += 1;
                return Ok(map);
            }
            let key = self.parse_string()?;
            self.expect_byte(b':', "colon")?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.eat_ws();
            if self.pos < self.bytes.len() && self.bytes[self.pos] == b',' {
                self.pos += 1;
            }
        }
    }
}

fn fixture_map(name: &str) -> BTreeMap<String, JVal> {
    let path = format!(
        "{}/tests/data/peer-communication/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("fixture file is readable");
    let mut cursor = JsonCursor::new(&text);
    cursor.parse_object().expect("fixture file parses")
}

fn get_str(map: &BTreeMap<String, JVal>, key: &str) -> String {
    match map.get(key).expect("fixture key present") {
        JVal::Str(value) => value.clone(),
        _ => panic!("fixture key {key} is a string"),
    }
}

fn get_int(map: &BTreeMap<String, JVal>, key: &str) -> i64 {
    match map.get(key).expect("fixture key present") {
        JVal::Int(value) => *value,
        _ => panic!("fixture key {key} is an integer"),
    }
}

fn get_u64(map: &BTreeMap<String, JVal>, key: &str) -> u64 {
    u64::try_from(get_int(map, key)).expect("non-negative fixture integer")
}

fn get_str_list(map: &BTreeMap<String, JVal>, key: &str) -> Vec<String> {
    match map.get(key).expect("fixture key present") {
        JVal::Arr(items) => items
            .iter()
            .map(|item| match item {
                JVal::Str(value) => value.clone(),
                _ => panic!("fixture list {key} holds strings"),
            })
            .collect(),
        _ => panic!("fixture key {key} is a list"),
    }
}

// ---- injected-port fakes: the only delivery/durability/time path ----

struct FakeClock {
    now: Cell<u64>,
    calls: Cell<u64>,
}

impl FakeClock {
    fn at(now: u64) -> Self {
        Self {
            now: Cell::new(now),
            calls: Cell::new(0),
        }
    }
}

impl PeerClockPort for FakeClock {
    fn now_ms(&self) -> u64 {
        self.calls.set(self.calls.get().saturating_add(1));
        self.now.get()
    }
}

struct FakeDurability {
    receipt: String,
    unavailable: Option<String>,
    calls: Cell<u64>,
}

impl FakeDurability {
    fn durable(receipt: &str) -> Self {
        Self {
            receipt: receipt.to_owned(),
            unavailable: None,
            calls: Cell::new(0),
        }
    }

    fn unavailable(reason: &str) -> Self {
        Self {
            receipt: String::new(),
            unavailable: Some(reason.to_owned()),
            calls: Cell::new(0),
        }
    }
}

impl PeerDurabilityPort for FakeDurability {
    fn attest(&self) -> PeerDurabilityAttestation {
        self.calls.set(self.calls.get().saturating_add(1));
        match &self.unavailable {
            Some(reason) => PeerDurabilityAttestation::Unavailable {
                reason: reason.clone(),
            },
            None => PeerDurabilityAttestation::Durable {
                owner_receipt: self.receipt.clone(),
            },
        }
    }
}

struct RecordingDelivery {
    log: Vec<PeerDeliveryTarget>,
    script: VecDeque<PeerDeliveryAttempt>,
}

impl RecordingDelivery {
    fn auto() -> Self {
        Self {
            log: Vec::new(),
            script: VecDeque::new(),
        }
    }

    fn scripted(outcomes: Vec<PeerDeliveryAttempt>) -> Self {
        Self {
            log: Vec::new(),
            script: outcomes.into_iter().collect(),
        }
    }
}

impl PeerDeliveryPort for RecordingDelivery {
    fn attempt(&mut self, target: &PeerDeliveryTarget) -> PeerDeliveryAttempt {
        self.log.push(target.clone());
        self.script
            .pop_front()
            .unwrap_or(PeerDeliveryAttempt::Delivered {
                endpoint: target.endpoint.clone(),
            })
    }
}

// ---- owner setup ----

struct PeerSetup {
    owner: CoordinationOwner,
    fence: StateFence,
    clock: FakeClock,
    durability: FakeDurability,
    delivery: RecordingDelivery,
}

fn register_session(
    owner: &mut CoordinationOwner,
    fence: &StateFence,
    id: &str,
    now: u64,
    deadline: u64,
) {
    owner
        .register_session(RegisterSession {
            request_id: format!("reg-{id}"),
            session_id: id.to_owned(),
            principal_id: format!("principal-{id}"),
            route_ref: format!("route-{id}"),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            now,
            heartbeat_deadline: deadline,
        })
        .expect("session registers");
}

fn register_work(owner: &mut CoordinationOwner, fence: &StateFence, id: &str) {
    owner
        .register_work(
            WorkItem {
                work_item_id: id.to_owned(),
                task_id: format!("task-{id}"),
                state: WorkState::Ready,
                state_fence: fence.clone(),
                owner_session_id: None,
                lease_id: None,
                attempt: 0,
                checkpoint_ref: None,
                result_ref: None,
            },
            &format!("reg-work-{id}"),
            "principal-session-a",
            eliot_contracts::ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        )
        .expect("work registers");
}

fn peer_setup() -> PeerSetup {
    let fence = fence();
    let mut owner = CoordinationOwner::new();
    register_session(&mut owner, &fence, "session-a", 10, 100_000);
    register_session(&mut owner, &fence, "session-b", 10, 100_000);
    register_session(&mut owner, &fence, "session-c", 10, 100_000);
    register_work(&mut owner, &fence, "work-w1");
    register_work(&mut owner, &fence, "work-w2");
    PeerSetup {
        owner,
        fence,
        clock: FakeClock::at(1000),
        durability: FakeDurability::durable("owner-receipt-1"),
        delivery: RecordingDelivery::auto(),
    }
}

fn base_draft(fence: &StateFence, id: &str, request: &str) -> EnqueuePeerMessage {
    EnqueuePeerMessage {
        request_id: request.to_owned(),
        message_id: id.to_owned(),
        kind: PeerMessageKind::Note,
        delta_kind: None,
        sender_session_id: "session-a".to_owned(),
        recipient_session_id: "session-b".to_owned(),
        scope: "tenant-alpha".to_owned(),
        work_item_id: "work-w1".to_owned(),
        authority_epoch: test_epoch(1),
        state_fence: fence.clone(),
        payload_digest: format!("digest-{id}"),
        payload_bytes: 128,
        payload_handle: None,
        inline_text: None,
        evidence_refs: Vec::new(),
        artifact_refs: Vec::new(),
        privacy: PrivacyClass::Open,
        disclosure_handle: None,
        revision: 1,
        expires_at: None,
        embedded: Vec::new(),
        asserted: None,
    }
}

fn enqueue(
    setup: &mut PeerSetup,
    draft: &EnqueuePeerMessage,
) -> eliot_coordination::PeerEnqueueReceipt {
    setup
        .owner
        .enqueue_peer_message(draft, &setup.clock, &setup.durability)
        .expect("peer message enqueues")
}

fn base_board(fence: &StateFence, id: &str, request: &str, scope: &str) -> PostBoardEntry {
    PostBoardEntry {
        request_id: request.to_owned(),
        entry_id: id.to_owned(),
        scope: scope.to_owned(),
        kind: PeerBoardKind::FindingCandidate,
        author_session_id: "session-a".to_owned(),
        audience_scope: scope.to_owned(),
        source_refs: vec!["source-1".to_owned()],
        anchor: None,
        content_digest: format!("digest-{id}"),
        content_handle: None,
        privacy: PrivacyClass::Open,
        disclosure_handle: None,
        required_evidence: false,
        dissent: false,
        withheld: false,
        lineage: vec!["lineage-board-1".to_owned()],
        authority_epoch: test_epoch(1),
        state_fence: fence.clone(),
    }
}

fn post_board(
    setup: &mut PeerSetup,
    draft: &PostBoardEntry,
) -> eliot_coordination::BoardEntryReceipt {
    setup
        .owner
        .post_board_entry(draft, &setup.clock, &setup.durability)
        .expect("board entry posts")
}

fn base_review(
    fence: &StateFence,
    id: &str,
    request: &str,
    artifact: &str,
    revision: u64,
) -> SubmitPeerReview {
    SubmitPeerReview {
        request_id: request.to_owned(),
        review_id: id.to_owned(),
        artifact_id: artifact.to_owned(),
        artifact_revision: revision,
        reviewer_session_id: "session-a".to_owned(),
        operation: "op-review-1".to_owned(),
        target_kind: ReviewTargetKind::Diff,
        kind: ReviewKind::Correction,
        criteria: vec!["criterion-novelty".to_owned()],
        proof_refs: vec!["proof-ref-1".to_owned()],
        anchor_field: "section-3/paragraph-2".to_owned(),
        anchor_resolution: AnchorResolution::Exact,
        findings: vec!["finding-1".to_owned()],
        evidence_refs: vec!["evidence-1".to_owned()],
        dissent: None,
        uncertainty: None,
        recommendation: ReviewRecommendation::Approve,
        completeness: ReviewCompleteness::Complete,
        expires_at: None,
        authority_epoch: test_epoch(1),
        state_fence: fence.clone(),
    }
}

fn admit_revisions(setup: &mut PeerSetup, artifact: &str, head: u64, digest_prefix: &str) {
    for revision in 1..=head {
        setup
            .owner
            .admit_artifact_revision(
                &AdmitArtifactRevision {
                    artifact_id: artifact.to_owned(),
                    revision,
                    digest: format!("{digest_prefix}-r{revision}"),
                    author_session_id: "session-a".to_owned(),
                    authority_epoch: test_epoch(1),
                    state_fence: setup.fence.clone(),
                },
                &setup.clock,
            )
            .expect("artifact revision admits");
    }
}

// WORK_UNIT_CASE: 696/1
#[test]
fn peer_mailbox_covers_all_normative_kinds() {
    let fixture = fixture_map("mailbox-kinds.json");
    let kinds = get_str_list(&fixture, "message_kinds");
    assert_eq!(get_int(&fixture, "message_kind_count"), 16);
    assert_eq!(kinds, PeerMessageKind::all());
    for name in &kinds {
        assert_eq!(
            PeerMessageKind::decode(name).expect("known kind").as_wire(),
            name
        );
    }
    let board = get_str_list(&fixture, "board_kinds");
    assert_eq!(get_int(&fixture, "board_kind_count"), 9);
    assert_eq!(board, PeerBoardKind::all());
    for name in &board {
        assert_eq!(
            PeerBoardKind::decode(name)
                .expect("known board kind")
                .as_wire(),
            name
        );
    }
    let conflicts = get_str_list(&fixture, "conflict_types");
    assert_eq!(get_int(&fixture, "conflict_type_count"), 8);
    assert_eq!(conflicts, PeerConflictType::all());
    let deltas = get_str_list(&fixture, "delta_kinds");
    assert_eq!(get_int(&fixture, "delta_kind_count"), 6);
    assert_eq!(deltas, LiveDeltaKind::all());

    let mut setup = peer_setup();
    let family = [
        PeerMessageKind::Note,
        PeerMessageKind::Evidence,
        PeerMessageKind::Question,
        PeerMessageKind::Answer,
        PeerMessageKind::Objection,
        PeerMessageKind::ReviewItem,
    ];
    for (index, kind) in family.iter().enumerate() {
        let id = format!("msg-kind-{}", index + 1);
        let mut draft = base_draft(
            &setup.fence.clone(),
            &id,
            &format!("req-kind-{}", index + 1),
        );
        draft.kind = *kind;
        let receipt = enqueue(&mut setup, &draft);
        assert_eq!(receipt.message.kind, *kind);
        assert_eq!(receipt.message.stream_seq, (index + 1) as u64);
        assert_eq!(receipt.message.state, PeerMessageState::Staged);
        assert!(!receipt.replayed);
    }
    let mut delta = base_draft(&setup.fence.clone(), "msg-kind-delta", "req-kind-delta");
    delta.kind = PeerMessageKind::LivePeerDelta;
    delta.delta_kind = Some(LiveDeltaKind::AssumptionInvalidated);
    let receipt = enqueue(&mut setup, &delta);
    assert_eq!(
        receipt.message.delta_kind,
        Some(LiveDeltaKind::AssumptionInvalidated)
    );
}

// WORK_UNIT_CASE: 696/2
#[test]
fn peer_envelope_decoding_is_closed_and_bounded() {
    let fixture = fixture_map("closed-decoding-vectors.json");
    let schema = get_str(&fixture, "schema");
    assert_eq!(schema, eliot_coordination::PEER_MESSAGE_SCHEMA);
    for unknown in get_str_list(&fixture, "unknown_schemas") {
        assert_eq!(
            decode_peer_envelope(&unknown, "note", &[]),
            Err(CoordinationError::UnknownPeerSchema(unknown))
        );
    }
    for unknown in get_str_list(&fixture, "unknown_kinds") {
        assert_eq!(
            decode_peer_envelope(&schema, &unknown, &[]),
            Err(CoordinationError::UnknownPeerKind(unknown))
        );
    }
    let field = |name: &str, value: &str| RawField {
        name: name.to_owned(),
        value: value.to_owned(),
    };
    let valid = vec![
        field("message_id", &get_str(&fixture, "valid_message_id")),
        field("kind", &get_str(&fixture, "valid_kind")),
        field("stream_recipient", "session-b"),
        field("stream_work_item", "work-w1"),
        field("sender", "session-a"),
        field("payload_digest", "digest-closed-1"),
    ];
    let header = decode_peer_envelope(&schema, "note", &valid).expect("valid envelope");
    assert_eq!(header.message_id, "msg-closed-1");
    assert_eq!(header.kind, PeerMessageKind::Note);
    assert_eq!(header.stream_recipient, "session-b");

    let mut extended = valid.clone();
    for unknown in get_str_list(&fixture, "unknown_fields") {
        extended.push(field(&unknown, "x"));
        assert_eq!(
            decode_peer_envelope(&schema, "note", &extended),
            Err(CoordinationError::UnknownPeerField(unknown))
        );
        extended.pop();
    }
    let mut duplicated = valid.clone();
    duplicated.push(field(&get_str(&fixture, "duplicate_key_field"), "evidence"));
    assert_eq!(
        decode_peer_envelope(&schema, "note", &duplicated),
        Err(CoordinationError::DuplicatePeerField(get_str(
            &fixture,
            "duplicate_key_field"
        )))
    );
    let missing: Vec<RawField> = valid
        .iter()
        .filter(|entry| entry.name != "sender")
        .cloned()
        .collect();
    assert_eq!(
        decode_peer_envelope(&schema, "note", &missing),
        Err(CoordinationError::MissingPeerField("sender".to_owned()))
    );
    assert_eq!(
        decode_peer_envelope(&schema, "live_peer_delta", &valid),
        Err(CoordinationError::MissingPeerField("delta_kind".to_owned()))
    );
    let mut with_delta = valid.clone();
    with_delta.push(field("delta_kind", "obstacle"));
    let header =
        decode_peer_envelope(&schema, "live_peer_delta", &with_delta).expect("delta envelope");
    assert_eq!(header.delta_kind, Some(LiveDeltaKind::Obstacle));
}

// WORK_UNIT_CASE: 696/3
#[test]
fn peer_exact_replay_keeps_one_entry_while_changes_conflict() {
    let fixture = fixture_map("replay-conflict-vectors.json");
    let mut setup = peer_setup();
    register_session(
        &mut setup.owner,
        &setup.fence.clone(),
        "session-replay-intruder",
        10,
        100_000,
    );
    let mut draft = base_draft(
        &setup.fence.clone(),
        &get_str(&fixture, "message_id"),
        "req-replay-1",
    );
    draft.payload_digest = get_str(&fixture, "payload_digest");
    draft.scope = get_str(&fixture, "scope");
    draft.revision = get_u64(&fixture, "revision");
    draft.expires_at = Some(get_u64(&fixture, "expiry"));
    let first = enqueue(&mut setup, &draft);
    let sequence = setup.owner.current_sequence();

    let replayed = setup
        .owner
        .enqueue_peer_message(&draft, &setup.clock, &setup.durability)
        .expect("exact replay");
    assert!(replayed.replayed);
    assert_eq!(replayed.message, first.message);
    assert_eq!(replayed.event.sequence, first.event.sequence);
    assert_eq!(setup.owner.current_sequence(), sequence);

    let mut changed = draft.clone();
    changed.request_id = "req-replay-changed-payload".to_owned();
    changed.payload_digest = get_str(&fixture, "changed_payload_digest");
    assert_conflict(&mut setup, &changed);

    let mut changed = draft.clone();
    changed.request_id = "req-replay-changed-scope".to_owned();
    changed.scope = get_str(&fixture, "changed_scope");
    assert_conflict(&mut setup, &changed);

    let mut changed = draft.clone();
    changed.request_id = "req-replay-changed-audience".to_owned();
    changed.recipient_session_id = get_str(&fixture, "changed_recipient");
    assert_conflict(&mut setup, &changed);

    let mut changed = draft.clone();
    changed.request_id = "req-replay-changed-revision".to_owned();
    changed.revision = get_u64(&fixture, "changed_revision");
    assert_conflict(&mut setup, &changed);

    let mut changed = draft;
    changed.request_id = "req-replay-changed-expiry".to_owned();
    changed.expires_at = Some(get_u64(&fixture, "changed_expiry"));
    assert_conflict(&mut setup, &changed);

    let stored = setup
        .owner
        .read_peer_message(&get_str(&fixture, "message_id"))
        .expect("original entry retained");
    assert_eq!(stored.payload_digest, get_str(&fixture, "payload_digest"));
    assert_eq!(setup.owner.current_sequence(), sequence);
}

fn assert_conflict(setup: &mut PeerSetup, draft: &EnqueuePeerMessage) {
    let id = draft.message_id.clone();
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(draft, &setup.clock, &setup.durability),
        Err(CoordinationError::PeerSemanticConflict(id))
    );
}

// WORK_UNIT_CASE: 696/4
#[test]
fn peer_streams_keep_monotonic_order_with_visible_duplicates() {
    let fixture = fixture_map("stream-ordering-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    for (index, id) in get_str_list(&fixture, "stream_a_ids").iter().enumerate() {
        let receipt = enqueue(
            &mut setup,
            &base_draft(&fence, id, &format!("req-a{index}")),
        );
        assert_eq!(receipt.message.stream_seq, (index + 1) as u64);
        assert_eq!(
            receipt.message.predecessor,
            if index == 0 { None } else { Some(index as u64) }
        );
    }
    for (index, id) in get_str_list(&fixture, "stream_b_ids").iter().enumerate() {
        let mut draft = base_draft(&fence, id, &format!("req-b{index}"));
        draft.work_item_id = "work-w2".to_owned();
        let receipt = enqueue(&mut setup, &draft);
        assert_eq!(receipt.message.stream_seq, (index + 1) as u64);
    }
    for id in get_str_list(&fixture, "deliver_order_a") {
        let receipt = setup
            .owner
            .attempt_peer_delivery(&id, "route-peer", &setup.clock, &mut setup.delivery)
            .expect("out-of-order delivery admitted");
        assert!(!receipt.duplicate);
    }
    let duplicate = get_str(&fixture, "duplicate_id");
    let receipt = setup
        .owner
        .attempt_peer_delivery(&duplicate, "route-peer", &setup.clock, &mut setup.delivery)
        .expect("duplicate delivery preserved");
    assert!(receipt.duplicate);
    let stored = setup.owner.read_peer_message(&duplicate).expect("stored");
    assert_eq!(stored.duplicate_deliveries, 1);
    assert_eq!(stored.attempt_history.len(), 2);
    assert!(matches!(stored.state, PeerMessageState::Delivered { .. }));
}

// WORK_UNIT_CASE: 696/5
#[test]
fn peer_gaps_predecessors_and_reconnect_cursors_stay_visible() {
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    for name in ["msg-gap-1", "msg-gap-2", "msg-gap-3"] {
        enqueue(
            &mut setup,
            &base_draft(&fence, name, &format!("req-{name}")),
        );
    }
    let stream = PeerStreamId {
        recipient_session_id: "session-b".to_owned(),
        work_item_id: "work-w1".to_owned(),
    };
    for id in ["msg-gap-1", "msg-gap-3"] {
        setup
            .owner
            .attempt_peer_delivery(id, "route-peer", &setup.clock, &mut setup.delivery)
            .expect("partial delivery");
    }
    assert_eq!(setup.owner.peer_stream_gaps(&stream), vec![2]);
    let first = setup.owner.read_peer_message("msg-gap-1").expect("first");
    assert_eq!(first.predecessor, None);
    let second = setup.owner.read_peer_message("msg-gap-2").expect("second");
    assert_eq!(second.predecessor, Some(1));

    let report = setup
        .owner
        .reconnect_peer_endpoint("session-b", &stream, 2, &setup.clock)
        .expect("reconnect with cursor");
    assert_eq!(
        report.replayed,
        vec!["msg-gap-2".to_owned(), "msg-gap-3".to_owned()]
    );
    assert_eq!(report.gaps, vec![2]);
    assert_eq!(report.cursor.next_expected_seq, 2);
    assert_eq!(
        setup.owner.reconnect_peer_endpoint(
            "session-b",
            &PeerStreamId {
                recipient_session_id: "session-b".to_owned(),
                work_item_id: "work-w1".to_owned(),
            },
            99,
            &setup.clock
        ),
        Err(CoordinationError::InvalidField("next_expected_seq"))
    );
}

// WORK_UNIT_CASE: 696/6
#[test]
fn peer_duplicate_permutations_converge_to_one_canonical_state() {
    let build = |replay_first: bool| {
        let mut setup = peer_setup();
        let fence = setup.fence.clone();
        let ids = ["msg-perm-1", "msg-perm-2", "msg-perm-3"];
        if replay_first {
            for id in ids {
                let draft = base_draft(&fence, id, &format!("req-{id}"));
                enqueue(&mut setup, &draft);
                setup
                    .owner
                    .enqueue_peer_message(&draft, &setup.clock, &setup.durability)
                    .expect("interleaved replay");
            }
        } else {
            for id in ids {
                enqueue(&mut setup, &base_draft(&fence, id, &format!("req-{id}")));
            }
            for id in ids {
                setup
                    .owner
                    .enqueue_peer_message(
                        &base_draft(&fence, id, &format!("req-{id}")),
                        &setup.clock,
                        &setup.durability,
                    )
                    .expect("batched replay");
            }
        }
        setup
    };
    let first = build(true);
    let second = build(false);
    let stream = PeerStreamId {
        recipient_session_id: "session-b".to_owned(),
        work_item_id: "work-w1".to_owned(),
    };
    assert_eq!(
        first.owner.peer_mailbox_digest(&stream),
        second.owner.peer_mailbox_digest(&stream)
    );
    for id in ["msg-perm-1", "msg-perm-2", "msg-perm-3"] {
        assert_eq!(
            first.owner.read_peer_message(id).expect("first entry"),
            second.owner.read_peer_message(id).expect("second entry")
        );
    }
}

// Helpers for 696/7: each bound family asserts through one focused helper so
// the case stays a readable orchestrator; every check from the original case
// is preserved verbatim below.
fn assert_bound_fixtures_agree(fixture: &BTreeMap<String, JVal>) {
    // Bound constants are small compile-time limits; `try_from` documents the
    // i64-range assumption for the JSON-fixture comparison without `as` casts.
    let message_bytes_max = i64::try_from(eliot_coordination::MAX_PEER_MESSAGE_BYTES)
        .expect("message-bytes bound fits in i64");
    let inline_text_max = i64::try_from(eliot_coordination::MAX_PEER_INLINE_TEXT)
        .expect("inline-text bound fits in i64");
    let references_max = i64::try_from(eliot_coordination::MAX_PEER_REFERENCES)
        .expect("references bound fits in i64");
    let stream_depth_max = i64::try_from(eliot_coordination::MAX_PEER_STREAM_DEPTH)
        .expect("stream-depth bound fits in i64");
    let board_entries_max = i64::try_from(eliot_coordination::MAX_BOARD_ENTRIES_PER_SCOPE)
        .expect("board-entries bound fits in i64");
    let board_revisions_max = i64::try_from(eliot_coordination::MAX_BOARD_REVISIONS_PER_ENTRY)
        .expect("board-revisions bound fits in i64");
    assert_eq!(get_int(fixture, "message_bytes_max"), message_bytes_max);
    assert_eq!(get_int(fixture, "inline_text_max"), inline_text_max);
    assert_eq!(get_int(fixture, "references_max"), references_max);
    assert_eq!(get_int(fixture, "stream_depth_max"), stream_depth_max);
    assert_eq!(
        get_int(fixture, "board_entries_per_scope_max"),
        board_entries_max
    );
    assert_eq!(get_int(fixture, "board_revisions_max"), board_revisions_max);
}

fn assert_message_size_bounds(setup: &mut PeerSetup, fence: &StateFence) {
    let mut oversized = base_draft(fence, "msg-big", "req-big");
    oversized.payload_bytes = eliot_coordination::MAX_PEER_MESSAGE_BYTES.saturating_add(1);
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&oversized, &setup.clock, &setup.durability),
        Err(CoordinationError::InvalidField("payload_bytes"))
    );
    let mut wide = base_draft(fence, "msg-wide", "req-wide");
    wide.evidence_refs = (0..17).map(|index| format!("evidence-{index}")).collect();
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&wide, &setup.clock, &setup.durability),
        Err(CoordinationError::InvalidField("peer_references"))
    );
}

fn assert_stream_depth_bound(setup: &mut PeerSetup, fence: &StateFence) {
    for index in 0..eliot_coordination::MAX_PEER_STREAM_DEPTH {
        enqueue(
            setup,
            &base_draft(
                fence,
                &format!("msg-depth-{index}"),
                &format!("req-depth-{index}"),
            ),
        );
    }
    let overflow = setup.owner.enqueue_peer_message(
        &base_draft(fence, "msg-depth-over", "req-depth-over"),
        &setup.clock,
        &setup.durability,
    );
    assert_eq!(
        overflow,
        Err(CoordinationError::PeerBackpressure {
            scope: "session-b:work-w1".to_owned(),
            limit: eliot_coordination::MAX_PEER_STREAM_DEPTH,
        })
    );
}

fn assert_sender_outstanding_bound() {
    let mut sender_bound = peer_setup();
    let fence = sender_bound.fence.clone();
    for name in ["work-o1", "work-o2", "work-o3"] {
        register_work(&mut sender_bound.owner, &fence, name);
    }
    for index in 0..eliot_coordination::MAX_PEER_OUTSTANDING_PER_SENDER {
        let (work, recipient) = if index % 2 == 0 {
            ("work-o1", "session-b")
        } else {
            ("work-o2", "session-c")
        };
        let mut draft = base_draft(
            &fence,
            &format!("msg-out-{index}"),
            &format!("req-out-{index}"),
        );
        work.clone_into(&mut draft.work_item_id);
        recipient.clone_into(&mut draft.recipient_session_id);
        draft.payload_digest = format!("digest-out-{index}");
        sender_bound
            .owner
            .enqueue_peer_message(&draft, &sender_bound.clock, &sender_bound.durability)
            .expect("outstanding admits");
    }
    let mut over = base_draft(&fence, "msg-out-over", "req-out-over");
    "work-o3".clone_into(&mut over.work_item_id);
    assert_eq!(
        sender_bound.owner.enqueue_peer_message(
            &over,
            &sender_bound.clock,
            &sender_bound.durability
        ),
        Err(CoordinationError::PeerBackpressure {
            scope: "session-a".to_owned(),
            limit: eliot_coordination::MAX_PEER_OUTSTANDING_PER_SENDER,
        })
    );
}

fn assert_recipient_outstanding_bound() {
    let mut recipient_bound = peer_setup();
    let fence = recipient_bound.fence.clone();
    for name in ["work-r1", "work-r2", "work-r3"] {
        register_work(&mut recipient_bound.owner, &fence, name);
    }
    for index in 0..eliot_coordination::MAX_PEER_OUTSTANDING_PER_RECIPIENT {
        let (work, sender) = if index % 2 == 0 {
            ("work-r1", "session-a")
        } else {
            ("work-r2", "session-c")
        };
        let mut draft = base_draft(
            &fence,
            &format!("msg-in-{index}"),
            &format!("req-in-{index}"),
        );
        work.clone_into(&mut draft.work_item_id);
        sender.clone_into(&mut draft.sender_session_id);
        draft.payload_digest = format!("digest-in-{index}");
        recipient_bound
            .owner
            .enqueue_peer_message(&draft, &recipient_bound.clock, &recipient_bound.durability)
            .expect("inbound admits");
    }
    let mut over = base_draft(&fence, "msg-in-over", "req-in-over");
    "work-r3".clone_into(&mut over.work_item_id);
    assert_eq!(
        recipient_bound.owner.enqueue_peer_message(
            &over,
            &recipient_bound.clock,
            &recipient_bound.durability
        ),
        Err(CoordinationError::PeerBackpressure {
            scope: "session-b".to_owned(),
            limit: eliot_coordination::MAX_PEER_OUTSTANDING_PER_RECIPIENT,
        })
    );
}

fn assert_board_revision_bound(setup: &mut PeerSetup, fence: &StateFence) {
    let mut revised = post_board(
        setup,
        &base_board(fence, "board-rev-bound", "req-rev-0", "tenant-alpha"),
    );
    for index in 1..eliot_coordination::MAX_BOARD_REVISIONS_PER_ENTRY {
        let receipt = setup
            .owner
            .revise_board_entry(
                &ReviseBoardEntry {
                    request_id: format!("req-rev-{index}"),
                    entry_id: "board-rev-bound".to_owned(),
                    predecessor_revision: index as u64,
                    author_session_id: "session-a".to_owned(),
                    source_refs: vec!["source-1".to_owned()],
                    anchor: None,
                    content_digest: format!("digest-rev-{index}"),
                    content_handle: None,
                    authority_epoch: test_epoch(1),
                    state_fence: fence.clone(),
                },
                &setup.clock,
                &setup.durability,
            )
            .expect("revision admits");
        revised = receipt;
    }
    assert_eq!(
        revised.entry.revision,
        eliot_coordination::MAX_BOARD_REVISIONS_PER_ENTRY as u64
    );
    assert_eq!(
        setup.owner.revise_board_entry(
            &ReviseBoardEntry {
                request_id: "req-rev-over".to_owned(),
                entry_id: "board-rev-bound".to_owned(),
                predecessor_revision: eliot_coordination::MAX_BOARD_REVISIONS_PER_ENTRY as u64,
                author_session_id: "session-a".to_owned(),
                source_refs: vec!["source-1".to_owned()],
                anchor: None,
                content_digest: "digest-rev-over".to_owned(),
                content_handle: None,
                authority_epoch: test_epoch(1),
                state_fence: fence.clone(),
            },
            &setup.clock,
            &setup.durability,
        ),
        Err(CoordinationError::PeerBackpressure {
            scope: "board-rev-bound".to_owned(),
            limit: eliot_coordination::MAX_BOARD_REVISIONS_PER_ENTRY,
        })
    );
}

// WORK_UNIT_CASE: 696/7
#[test]
fn peer_bounds_are_typed_and_independent() {
    assert_bound_fixtures_agree(&fixture_map("bounds-vectors.json"));

    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    assert_message_size_bounds(&mut setup, &fence);
    assert_stream_depth_bound(&mut setup, &fence);

    assert_sender_outstanding_bound();

    assert_recipient_outstanding_bound();

    assert_board_revision_bound(&mut setup, &fence);
}

// WORK_UNIT_CASE: 696/8
#[test]
fn peer_required_evidence_is_never_silently_evicted() {
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let mut required = base_board(&fence, "board-required-0", "req-required-0", "tenant-alpha");
    required.required_evidence = true;
    post_board(&mut setup, &required);
    for index in 1..eliot_coordination::MAX_BOARD_ENTRIES_PER_SCOPE {
        post_board(
            &mut setup,
            &base_board(
                &fence,
                &format!("board-fill-{index}"),
                &format!("req-fill-{index}"),
                "tenant-alpha",
            ),
        );
    }
    assert_eq!(
        setup.owner.post_board_entry(
            &base_board(&fence, "board-fill-over", "req-fill-over", "tenant-alpha"),
            &setup.clock,
            &setup.durability,
        ),
        Err(CoordinationError::PeerBackpressure {
            scope: "tenant-alpha".to_owned(),
            limit: eliot_coordination::MAX_BOARD_ENTRIES_PER_SCOPE,
        })
    );
    let retained = setup
        .owner
        .read_board_revision("board-required-0", 1)
        .expect("required evidence retained");
    assert_eq!(retained.content_digest, "digest-board-required-0");
    assert!(retained.required_evidence);
}

// WORK_UNIT_CASE: 696/9
#[test]
fn peer_backpressure_resolves_only_through_receipted_compaction() {
    let fixture = fixture_map("backpressure-compaction-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let scope = get_str(&fixture, "scope");
    post_board(
        &mut setup,
        &base_board(&fence, "board-compact-keep", "req-keep", &scope),
    );
    let mut dissent = base_board(&fence, "board-compact-dissent", "req-dissent", &scope);
    dissent.dissent = true;
    post_board(&mut setup, &dissent);
    for id in ["board-compact-keep", "board-compact-dissent"] {
        setup
            .owner
            .retract_board_entry(id, "session-a", &setup.clock)
            .expect("author retracts");
    }
    let empty_policy = BoardCompactionPolicy {
        policy_id: String::new(),
        lineage_receipt: get_str(&fixture, "lineage_receipt"),
        retain_dissent: true,
        retain_required_evidence: true,
    };
    assert_eq!(
        setup
            .owner
            .compact_board_scope(&scope, empty_policy, &setup.clock),
        Err(CoordinationError::PeerCompactionRequiresPolicy {
            scope: scope.clone()
        })
    );
    let dropping_policy = BoardCompactionPolicy {
        policy_id: get_str(&fixture, "policy_id"),
        lineage_receipt: get_str(&fixture, "lineage_receipt"),
        retain_dissent: false,
        retain_required_evidence: true,
    };
    assert_eq!(
        setup
            .owner
            .compact_board_scope(&scope, dropping_policy, &setup.clock),
        Err(CoordinationError::PeerCompactionRequiresPolicy {
            scope: scope.clone()
        })
    );
    let receipt = setup
        .owner
        .compact_board_scope(
            &scope,
            BoardCompactionPolicy {
                policy_id: get_str(&fixture, "policy_id"),
                lineage_receipt: get_str(&fixture, "lineage_receipt"),
                retain_dissent: get_int(&fixture, "retain_dissent") == 1,
                retain_required_evidence: true,
            },
            &setup.clock,
        )
        .expect("receipted compaction");
    assert_eq!(receipt.omitted.len(), 1);
    assert_eq!(receipt.omitted[0].entry_id, "board-compact-keep");
    assert_eq!(
        receipt.retained_dissent,
        vec!["board-compact-dissent".to_owned()]
    );
    assert_eq!(receipt.policy_id, get_str(&fixture, "policy_id"));
    let tombstone = setup
        .owner
        .read_board_tombstone("board-compact-keep", 1)
        .expect("omission receipted");
    assert_eq!(
        tombstone.lineage_receipt,
        get_str(&fixture, "lineage_receipt")
    );
    assert!(
        setup
            .owner
            .read_board_revision("board-compact-keep", 1)
            .is_err()
    );
    post_board(
        &mut setup,
        &base_board(&fence, "board-compact-new", "req-new", &scope),
    );
}

// WORK_UNIT_CASE: 696/10
#[test]
fn peer_expiry_uses_the_supplied_clock_boundary() {
    let fixture = fixture_map("expiry-vectors.json");
    let now = get_u64(&fixture, "now");
    let mut setup = peer_setup();
    setup.clock.now.set(now);
    let fence = setup.fence.clone();
    for (id, expiry) in [
        ("msg-expired-past", get_u64(&fixture, "past_expiry")),
        ("msg-expired-edge", get_u64(&fixture, "boundary_expiry")),
    ] {
        let mut draft = base_draft(&fence, id, &format!("req-{id}"));
        draft.expires_at = Some(expiry);
        assert_eq!(
            setup
                .owner
                .enqueue_peer_message(&draft, &setup.clock, &setup.durability),
            Err(CoordinationError::PeerExpired(id.to_owned()))
        );
    }
    let mut live = base_draft(&fence, "msg-live", "req-live");
    live.expires_at = Some(get_u64(&fixture, "live_expiry"));
    enqueue(&mut setup, &live);
    setup.clock.now.set(get_u64(&fixture, "deliver_at"));
    setup
        .owner
        .attempt_peer_delivery("msg-live", "route-peer", &setup.clock, &mut setup.delivery)
        .expect("delivery before expiry");
    setup
        .clock
        .now
        .set(get_u64(&fixture, "ack_after_expiry_at"));
    assert_eq!(
        setup
            .owner
            .acknowledge_peer_message("msg-live", 1, "session-b", &setup.clock),
        Err(CoordinationError::PeerExpired("msg-live".to_owned()))
    );
    let stored = setup.owner.read_peer_message("msg-live").expect("stored");
    assert_eq!(
        stored.state,
        PeerMessageState::Expired {
            at: get_u64(&fixture, "ack_after_expiry_at")
        }
    );
}

// WORK_UNIT_CASE: 696/11
#[test]
fn peer_cancellation_wins_before_delivery_and_loses_after() {
    let fixture = fixture_map("cancel-race-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    enqueue(
        &mut setup,
        &base_draft(
            &fence,
            &get_str(&fixture, "cancel_before_id"),
            "req-cancel-1",
        ),
    );
    let cancelled = setup
        .owner
        .cancel_peer_message(
            &get_str(&fixture, "cancel_before_id"),
            "session-a",
            &setup.clock,
        )
        .expect("cancel before delivery");
    assert!(matches!(
        cancelled.state,
        PeerMessageState::Cancelled { .. }
    ));
    assert_eq!(
        setup.owner.cancel_peer_message(
            &get_str(&fixture, "cancel_before_id"),
            "session-a",
            &setup.clock
        ),
        Err(CoordinationError::InvalidState)
    );

    enqueue(
        &mut setup,
        &base_draft(&fence, &get_str(&fixture, "race_id"), "req-cancel-2"),
    );
    setup
        .owner
        .attempt_peer_delivery(
            &get_str(&fixture, "race_id"),
            &get_str(&fixture, "endpoint"),
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("delivery wins the race");
    assert_eq!(
        setup
            .owner
            .cancel_peer_message(&get_str(&fixture, "race_id"), "session-a", &setup.clock),
        Err(CoordinationError::PeerRetractionRejected(get_str(
            &fixture, "race_id"
        )))
    );
    let stored = setup
        .owner
        .read_peer_message(&get_str(&fixture, "race_id"))
        .expect("stored");
    assert!(matches!(stored.state, PeerMessageState::Delivered { .. }));
    assert_eq!(
        setup
            .owner
            .cancel_peer_message(&get_str(&fixture, "race_id"), "session-b", &setup.clock),
        Err(CoordinationError::LeaseOwnerMismatch {
            holder: "session-a".to_owned()
        })
    );
}

// WORK_UNIT_CASE: 696/12
#[test]
fn peer_unavailable_and_denied_audiences_stay_visible() {
    let mut setup = peer_setup();
    register_session(&mut setup.owner, &setup.fence.clone(), "session-d", 10, 500);
    setup.clock.now.set(1000);
    let fence = setup.fence.clone();
    let mut draft = base_draft(&fence, "msg-unavailable-1", "req-unavailable-1");
    draft.recipient_session_id = "session-d".to_owned();
    let receipt = enqueue(&mut setup, &draft);
    assert!(matches!(
        receipt.message.state,
        PeerMessageState::Unavailable { .. }
    ));
    assert_eq!(receipt.message.stream_seq, 1);

    setup.delivery = RecordingDelivery::scripted(vec![PeerDeliveryAttempt::Unavailable {
        reason: "endpoint down".to_owned(),
    }]);
    let attempt = setup
        .owner
        .attempt_peer_delivery(
            "msg-unavailable-1",
            "route-d",
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("unavailable attempt recorded");
    assert_eq!(setup.delivery.log.len(), 1);
    assert!(matches!(
        attempt.outcome,
        PeerDeliveryAttempt::Unavailable { .. }
    ));
    let stored = setup
        .owner
        .read_peer_message("msg-unavailable-1")
        .expect("retained");
    assert!(matches!(stored.state, PeerMessageState::Unavailable { .. }));

    let mut secret = base_draft(&fence, "msg-secret-1", "req-secret-1");
    secret.privacy = PrivacyClass::Secret;
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&secret, &setup.clock, &setup.durability),
        Err(CoordinationError::PeerPrivacyDenied(
            "msg-secret-1".to_owned()
        ))
    );
    assert!(setup.owner.read_peer_message("msg-secret-1").is_err());
}

// WORK_UNIT_CASE: 696/13
#[test]
fn peer_post_send_disconnect_stays_unknown() {
    let fixture = fixture_map("lifecycle-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    enqueue(
        &mut setup,
        &base_draft(&fence, &get_str(&fixture, "disconnect_id"), "req-life-3"),
    );
    setup
        .owner
        .attempt_peer_delivery(
            &get_str(&fixture, "disconnect_id"),
            &get_str(&fixture, "endpoint"),
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("send before loss");
    let report = setup
        .owner
        .note_peer_endpoint_loss("session-b", "link dropped", &setup.clock)
        .expect("loss recorded");
    assert_eq!(report.session_id, "session-b");
    assert_eq!(
        report.marked_unknown,
        vec![get_str(&fixture, "disconnect_id")]
    );
    let stored = setup
        .owner
        .read_peer_message(&get_str(&fixture, "disconnect_id"))
        .expect("unknown message retained");
    assert!(matches!(stored.state, PeerMessageState::Unknown { .. }));
    assert_eq!(stored.attempts, 1);
    assert_eq!(
        setup.owner.acknowledge_peer_message(
            &get_str(&fixture, "disconnect_id"),
            99,
            "session-b",
            &setup.clock
        ),
        Err(CoordinationError::PeerSemanticConflict(get_str(
            &fixture,
            "disconnect_id"
        )))
    );
    let retained = setup
        .owner
        .read_peer_message(&get_str(&fixture, "disconnect_id"))
        .expect("still retained");
    assert!(matches!(retained.state, PeerMessageState::Unknown { .. }));
}

// WORK_UNIT_CASE: 696/14
#[test]
fn peer_reconnect_replays_without_duplicate_entries() {
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    enqueue(&mut setup, &base_draft(&fence, "msg-re-1", "req-re-1"));
    enqueue(&mut setup, &base_draft(&fence, "msg-re-2", "req-re-2"));
    setup
        .owner
        .attempt_peer_delivery("msg-re-1", "route-peer", &setup.clock, &mut setup.delivery)
        .expect("first delivered");
    setup
        .owner
        .note_peer_endpoint_loss("session-b", "link dropped", &setup.clock)
        .expect("loss recorded");
    let reconciled = setup
        .owner
        .acknowledge_peer_message("msg-re-1", 1, "session-b", &setup.clock)
        .expect("unknown message reconciles by exact acknowledgement");
    assert!(!reconciled.replayed);
    let sequence = setup.owner.current_sequence();
    let before = setup
        .owner
        .read_peer_message("msg-re-1")
        .expect("reconciled entry");
    let report = setup
        .owner
        .reconnect_peer_endpoint(
            "session-b",
            &PeerStreamId {
                recipient_session_id: "session-b".to_owned(),
                work_item_id: "work-w1".to_owned(),
            },
            1,
            &setup.clock,
        )
        .expect("reconnect replays");
    assert_eq!(report.replayed, vec!["msg-re-2".to_owned()]);
    assert_eq!(setup.owner.current_sequence(), sequence);
    let after = setup
        .owner
        .read_peer_message("msg-re-1")
        .expect("same entry");
    assert_eq!(
        before, after,
        "reconnect admits no duplicate semantic entry"
    );
    let ack = setup
        .owner
        .acknowledge_peer_message("msg-re-1", 1, "session-b", &setup.clock)
        .expect("acknowledgement replays");
    assert!(ack.replayed);
    assert_eq!(
        setup
            .owner
            .acknowledge_peer_message("msg-re-1", 1, "session-c", &setup.clock),
        Err(CoordinationError::LeaseOwnerMismatch {
            holder: "session-b".to_owned()
        })
    );
    let fresh = setup
        .owner
        .reconnect_peer_endpoint(
            "session-c",
            &PeerStreamId {
                recipient_session_id: "session-b".to_owned(),
                work_item_id: "work-w1".to_owned(),
            },
            1,
            &setup.clock,
        )
        .expect("new generation gets no foreign entries");
    assert!(fresh.replayed.is_empty());
}

// WORK_UNIT_CASE: 696/15
#[test]
fn peer_acknowledgement_is_not_read_use_or_agreement() {
    let fixture = fixture_map("lifecycle-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    enqueue(
        &mut setup,
        &base_draft(&fence, &get_str(&fixture, "deliver_id"), "req-life-1"),
    );
    assert_eq!(
        setup.owner.acknowledge_peer_message(
            &get_str(&fixture, "deliver_id"),
            1,
            "session-b",
            &setup.clock
        ),
        Err(CoordinationError::InvalidState)
    );
    setup
        .owner
        .attempt_peer_delivery(
            &get_str(&fixture, "deliver_id"),
            &get_str(&fixture, "endpoint"),
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("delivered");
    assert_eq!(
        setup.owner.acknowledge_peer_message(
            &get_str(&fixture, "deliver_id"),
            2,
            "session-b",
            &setup.clock
        ),
        Err(CoordinationError::PeerSemanticConflict(get_str(
            &fixture,
            "deliver_id"
        )))
    );
    let ack = setup
        .owner
        .acknowledge_peer_message(
            &get_str(&fixture, "deliver_id"),
            1,
            "session-b",
            &setup.clock,
        )
        .expect("exact revision acknowledged");
    assert!(!ack.replayed);
    let stored = setup
        .owner
        .read_peer_message(&get_str(&fixture, "deliver_id"))
        .expect("stored");
    assert_eq!(
        stored.state,
        PeerMessageState::Acknowledged {
            revision: 1,
            by_session: "session-b".to_owned(),
        }
    );
    assert_eq!(
        setup.owner.consume_peer_message(
            &get_str(&fixture, "deliver_id"),
            "session-b",
            "",
            &setup.clock
        ),
        Err(CoordinationError::InvalidField("evidence_handle"))
    );
    let consumed = setup
        .owner
        .consume_peer_message(
            &get_str(&fixture, "deliver_id"),
            "session-b",
            "evidence-read-life-1",
            &setup.clock,
        )
        .expect("evidenced read consumes");
    assert_eq!(consumed.evidence_handle, "evidence-read-life-1");
    let again = setup
        .owner
        .acknowledge_peer_message(
            &get_str(&fixture, "deliver_id"),
            1,
            "session-b",
            &setup.clock,
        )
        .expect("ack after consume replays");
    assert!(again.replayed);
}

// WORK_UNIT_CASE: 696/16
#[test]
fn peer_concurrent_board_entries_are_preserved() {
    let fixture = fixture_map("board-revisions.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let scope = get_str(&fixture, "scope");
    post_board(
        &mut setup,
        &base_board(
            &fence,
            &get_str(&fixture, "concurrent_a"),
            "req-par-a",
            &scope,
        ),
    );
    let mut rival = base_board(
        &fence,
        &get_str(&fixture, "concurrent_b"),
        "req-par-b",
        &scope,
    );
    rival.content_digest = "digest-parallel-b".to_owned();
    post_board(&mut setup, &rival);
    let first = setup
        .owner
        .read_board_revision(&get_str(&fixture, "concurrent_a"), 1)
        .expect("first proposal retained");
    let second = setup
        .owner
        .read_board_revision(&get_str(&fixture, "concurrent_b"), 1)
        .expect("second proposal retained");
    assert_ne!(first.content_digest, second.content_digest);
    assert_eq!(first.revision, 1);
    assert_eq!(second.revision, 1);
    let mut clash = base_board(
        &fence,
        &get_str(&fixture, "concurrent_a"),
        "req-par-clash",
        &scope,
    );
    clash.content_digest = "digest-changed".to_owned();
    assert_eq!(
        setup
            .owner
            .post_board_entry(&clash, &setup.clock, &setup.durability),
        Err(CoordinationError::Duplicate(get_str(
            &fixture,
            "concurrent_a"
        )))
    );
}

// WORK_UNIT_CASE: 696/17
#[test]
fn peer_board_update_retains_prior_revisions() {
    let fixture = fixture_map("board-revisions.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let scope = get_str(&fixture, "scope");
    let mut first_post = base_board(
        &fence,
        &get_str(&fixture, "entry_id"),
        "req-board-1",
        &scope,
    );
    first_post.content_digest = get_str(&fixture, "first_digest");
    post_board(&mut setup, &first_post);
    let receipt = base_board(
        &fence,
        &get_str(&fixture, "entry_id"),
        "req-board-2",
        &scope,
    );
    let receipt = setup
        .owner
        .revise_board_entry(
            &ReviseBoardEntry {
                request_id: receipt.request_id.clone(),
                entry_id: receipt.entry_id.clone(),
                predecessor_revision: 1,
                author_session_id: "session-a".to_owned(),
                source_refs: vec!["source-2".to_owned()],
                anchor: None,
                content_digest: get_str(&fixture, "second_digest"),
                content_handle: None,
                authority_epoch: test_epoch(1),
                state_fence: fence.clone(),
            },
            &setup.clock,
            &setup.durability,
        )
        .expect("revision admits");
    assert_eq!(receipt.entry.revision, 2);
    assert_eq!(receipt.entry.predecessor_revision, Some(1));
    assert_eq!(receipt.entry.supersedes, Some(1));
    let prior = setup
        .owner
        .read_board_revision(&get_str(&fixture, "entry_id"), 1)
        .expect("prior revision retained");
    assert_eq!(prior.content_digest, get_str(&fixture, "first_digest"));
    let head = setup
        .owner
        .read_board_revision(&get_str(&fixture, "entry_id"), 2)
        .expect("head readable");
    assert_eq!(head.content_digest, get_str(&fixture, "second_digest"));
    assert_eq!(
        setup.owner.revise_board_entry(
            &ReviseBoardEntry {
                request_id: "req-board-stale".to_owned(),
                entry_id: get_str(&fixture, "entry_id"),
                predecessor_revision: 1,
                author_session_id: "session-a".to_owned(),
                source_refs: vec!["source-3".to_owned()],
                anchor: None,
                content_digest: "digest-stale".to_owned(),
                content_handle: None,
                authority_epoch: test_epoch(1),
                state_fence: fence.clone(),
            },
            &setup.clock,
            &setup.durability,
        ),
        Err(CoordinationError::CausalPredecessorMismatch)
    );
}

// WORK_UNIT_CASE: 696/18
#[test]
fn peer_board_pages_are_frozen_with_denominators() {
    let fixture = fixture_map("board-pages.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let scope = get_str(&fixture, "scope");
    for (index, id) in get_str_list(&fixture, "page_ids").iter().enumerate() {
        post_board(
            &mut setup,
            &base_board(&fence, id, &format!("req-page-{index}"), &scope),
        );
    }
    let frozen = setup.owner.current_sequence();
    for (index, id) in get_str_list(&fixture, "later_ids").iter().enumerate() {
        post_board(
            &mut setup,
            &base_board(&fence, id, &format!("req-later-{index}"), &scope),
        );
    }
    let page = setup
        .owner
        .read_board_page(&scope, 0, 50, frozen)
        .expect("frozen page");
    assert_eq!(page.total, 5);
    assert_eq!(page.visible, 5);
    assert_eq!(page.omitted, 0);
    assert!(page.complete);
    assert_eq!(page.next_cursor, None);
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect::<Vec<_>>(),
        get_str_list(&fixture, "page_ids")
    );
    let first = setup
        .owner
        .read_board_page(&scope, 0, 2, frozen)
        .expect("slice");
    assert!(!first.complete);
    assert_eq!(first.next_cursor, Some(2));
    let second = setup
        .owner
        .read_board_page(&scope, 2, 2, frozen)
        .expect("slice");
    assert_eq!(second.next_cursor, Some(4));
    let third = setup
        .owner
        .read_board_page(&scope, 4, 2, frozen)
        .expect("tail");
    assert!(third.complete);
    assert_eq!(third.entries.len(), 1);
}

// WORK_UNIT_CASE: 696/19
#[test]
fn peer_partial_pages_are_never_complete() {
    let fixture = fixture_map("board-pages.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let scope = get_str(&fixture, "scope");
    for (index, id) in get_str_list(&fixture, "page_ids").iter().enumerate() {
        post_board(
            &mut setup,
            &base_board(&fence, id, &format!("req-p{index}"), &scope),
        );
    }
    let mut withheld = base_board(
        &fence,
        &get_str(&fixture, "withheld_id"),
        "req-withheld",
        &scope,
    );
    withheld.withheld = true;
    post_board(&mut setup, &withheld);
    let frozen = setup.owner.current_sequence();
    let page = setup
        .owner
        .read_board_page(&scope, 0, 50, frozen)
        .expect("page");
    assert_eq!(page.total, 6);
    assert_eq!(page.visible, 5);
    assert_eq!(page.omitted, 1);
    assert!(
        !page.complete,
        "withheld material keeps the page incomplete"
    );
    assert_eq!(page.next_cursor, None);
    assert!(
        page.entries
            .iter()
            .all(|entry| entry.entry_id != get_str(&fixture, "withheld_id"))
    );
    let slice = setup
        .owner
        .read_board_page(&scope, 0, 2, frozen)
        .expect("slice");
    assert!(!slice.complete);
}

// WORK_UNIT_CASE: 696/20
#[test]
fn peer_conflicts_keep_two_sided_and_minority_positions() {
    let fixture = fixture_map("conflict-vectors.json");
    let mut setup = peer_setup();
    let receipt = setup
        .owner
        .record_peer_conflict(
            &RecordPeerConflict {
                request_id: "req-conflict-1".to_owned(),
                conflict_id: get_str(&fixture, "conflict_id"),
                conflict_type: PeerConflictType::Epistemic,
                scope_id: get_str(&fixture, "scope"),
                task_id: get_str(&fixture, "task"),
                candidates: vec![
                    ConflictCandidateDraft {
                        position: get_str(&fixture, "majority_position"),
                        author_session_id: "session-a".to_owned(),
                        evidence_refs: vec!["evidence-a".to_owned()],
                        lineage: get_str_list(&fixture, "majority_lineage"),
                    },
                    ConflictCandidateDraft {
                        position: get_str(&fixture, "minority_position"),
                        author_session_id: "session-b".to_owned(),
                        evidence_refs: vec!["evidence-b".to_owned()],
                        lineage: get_str_list(&fixture, "minority_lineage"),
                    },
                ],
                dimensions: vec![
                    PeerConflictDimension::EvidenceDifference,
                    PeerConflictDimension::TerminologyDifference,
                ],
                authority_owner: "session-a".to_owned(),
                affected_actions: vec!["action-hold".to_owned()],
            },
            &setup.clock,
        )
        .expect("two-sided conflict records");
    assert_eq!(
        receipt.conflict.acceptability,
        ArgumentAcceptability::Contested
    );
    assert_eq!(receipt.conflict.candidates.len(), 2);
    assert!(receipt.conflict.lineage_independent);
    assert!(!receipt.conflict.common_mode_exposure);
    assert!(!receipt.replayed);

    let lone = setup
        .owner
        .record_peer_conflict(
            &RecordPeerConflict {
                request_id: "req-conflict-lone".to_owned(),
                conflict_id: "conflict-lone-1".to_owned(),
                conflict_type: PeerConflictType::Plan,
                scope_id: get_str(&fixture, "scope"),
                task_id: get_str(&fixture, "task"),
                candidates: vec![ConflictCandidateDraft {
                    position: "position-minority-hold".to_owned(),
                    author_session_id: "session-c".to_owned(),
                    evidence_refs: Vec::new(),
                    lineage: vec!["lineage-minority".to_owned()],
                }],
                dimensions: vec![PeerConflictDimension::ScopeDifference],
                authority_owner: "session-c".to_owned(),
                affected_actions: Vec::new(),
            },
            &setup.clock,
        )
        .expect("minority position retained");
    assert_eq!(
        lone.conflict.acceptability,
        ArgumentAcceptability::Undecided
    );
    assert_eq!(
        setup
            .owner
            .resolve_peer_conflict(&get_str(&fixture, "conflict_id"), None, &setup.clock),
        Err(CoordinationError::PeerResolutionRequiresExternal(get_str(
            &fixture,
            "conflict_id"
        )))
    );
    let stored = setup
        .owner
        .read_peer_conflict(&get_str(&fixture, "conflict_id"))
        .expect("conflict stays open");
    assert_eq!(stored.state, PeerConflictState::Open);
}

// WORK_UNIT_CASE: 696/21
#[test]
fn peer_conflict_lineage_separates_independence_from_common_mode() {
    let fixture = fixture_map("conflict-vectors.json");
    let mut setup = peer_setup();
    let shared = get_str_list(&fixture, "shared_lineage");
    let receipt = setup
        .owner
        .record_peer_conflict(
            &RecordPeerConflict {
                request_id: "req-conflict-shared".to_owned(),
                conflict_id: "conflict-shared-1".to_owned(),
                conflict_type: PeerConflictType::Epistemic,
                scope_id: get_str(&fixture, "scope"),
                task_id: get_str(&fixture, "task"),
                candidates: vec![
                    ConflictCandidateDraft {
                        position: "position-shared-a".to_owned(),
                        author_session_id: "session-a".to_owned(),
                        evidence_refs: Vec::new(),
                        lineage: shared.clone(),
                    },
                    ConflictCandidateDraft {
                        position: "position-shared-b".to_owned(),
                        author_session_id: "session-b".to_owned(),
                        evidence_refs: Vec::new(),
                        lineage: shared.clone(),
                    },
                ],
                dimensions: vec![PeerConflictDimension::EvidenceDifference],
                authority_owner: "session-a".to_owned(),
                affected_actions: Vec::new(),
            },
            &setup.clock,
        )
        .expect("shared-lineage conflict records");
    assert!(!receipt.conflict.lineage_independent);
    assert!(receipt.conflict.common_mode_exposure);
    assert_eq!(receipt.conflict.candidates.len(), 2);
}

// WORK_UNIT_CASE: 696/22
#[test]
fn peer_conflict_resolution_requires_an_exact_external_receipt() {
    let mut setup = peer_setup();
    setup
        .owner
        .record_peer_conflict(
            &RecordPeerConflict {
                request_id: "req-conflict-res".to_owned(),
                conflict_id: "conflict-res-1".to_owned(),
                conflict_type: PeerConflictType::State,
                scope_id: "tenant-alpha".to_owned(),
                task_id: "task-w1".to_owned(),
                candidates: vec![
                    ConflictCandidateDraft {
                        position: "position-x".to_owned(),
                        author_session_id: "session-a".to_owned(),
                        evidence_refs: Vec::new(),
                        lineage: vec!["lineage-x".to_owned()],
                    },
                    ConflictCandidateDraft {
                        position: "position-y".to_owned(),
                        author_session_id: "session-b".to_owned(),
                        evidence_refs: Vec::new(),
                        lineage: vec!["lineage-y".to_owned()],
                    },
                ],
                dimensions: vec![PeerConflictDimension::TimeDifference],
                authority_owner: "session-a".to_owned(),
                affected_actions: Vec::new(),
            },
            &setup.clock,
        )
        .expect("conflict records");
    let resolved = setup
        .owner
        .resolve_peer_conflict(
            "conflict-res-1",
            Some(ExternalResolutionReceipt {
                receipt_id: "external-receipt-1".to_owned(),
                issuer: "decision-owner-1".to_owned(),
                detail: "discriminative probe selected".to_owned(),
            }),
            &setup.clock,
        )
        .expect("external receipt resolves");
    assert_eq!(resolved.state, PeerConflictState::Resolved);
    assert_eq!(
        resolved.resolution.expect("receipt bound").receipt_id,
        "external-receipt-1"
    );
    assert_eq!(
        setup.owner.resolve_peer_conflict(
            "conflict-res-1",
            Some(ExternalResolutionReceipt {
                receipt_id: "external-receipt-2".to_owned(),
                issuer: "decision-owner-1".to_owned(),
                detail: "second attempt".to_owned(),
            }),
            &setup.clock
        ),
        Err(CoordinationError::InvalidState)
    );
    assert_eq!(
        setup
            .owner
            .resolve_peer_conflict("conflict-missing", None, &setup.clock),
        Err(CoordinationError::PeerResolutionRequiresExternal(
            "conflict-missing".to_owned()
        ))
    );
}

// WORK_UNIT_CASE: 696/23
#[test]
fn peer_compaction_retains_objection_lineage() {
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    post_board(
        &mut setup,
        &base_board(&fence, "board-plain-1", "req-plain-1", "tenant-alpha"),
    );
    let mut objection = base_board(
        &fence,
        "board-objection-1",
        "req-objection-1",
        "tenant-alpha",
    );
    objection.kind = PeerBoardKind::ConflictNotice;
    objection.dissent = true;
    objection.lineage = vec!["lineage-counterevidence-1".to_owned()];
    post_board(&mut setup, &objection);
    let mut required = base_board(&fence, "board-required-1", "req-required-1", "tenant-alpha");
    required.required_evidence = true;
    post_board(&mut setup, &required);
    for id in ["board-plain-1", "board-objection-1", "board-required-1"] {
        setup
            .owner
            .retract_board_entry(id, "session-a", &setup.clock)
            .expect("retract");
    }
    let receipt = setup
        .owner
        .compact_board_scope(
            "tenant-alpha",
            BoardCompactionPolicy {
                policy_id: "policy-lineage-1".to_owned(),
                lineage_receipt: "lineage-compact-1".to_owned(),
                retain_dissent: true,
                retain_required_evidence: true,
            },
            &setup.clock,
        )
        .expect("compaction receipts");
    assert_eq!(receipt.omitted.len(), 1);
    assert_eq!(receipt.omitted[0].entry_id, "board-plain-1");
    assert_eq!(
        receipt.retained_dissent,
        vec!["board-objection-1".to_owned()]
    );
    assert_eq!(
        receipt.retained_required,
        vec!["board-required-1".to_owned()]
    );
    let dissent = setup
        .owner
        .read_board_revision("board-objection-1", 1)
        .expect("objection lineage retained");
    assert_eq!(
        dissent.lineage,
        vec!["lineage-counterevidence-1".to_owned()]
    );
    let tombstone = setup
        .owner
        .read_board_tombstone("board-plain-1", 1)
        .expect("omission receipted");
    assert_eq!(tombstone.policy_id, "policy-lineage-1");
}

// WORK_UNIT_CASE: 696/24
#[test]
fn peer_review_binds_exact_artifact_revision_and_criteria() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    setup
        .owner
        .expect_peer_reviews(
            &artifact,
            get_u64(&fixture, "expected_reviews"),
            "session-a",
            &test_epoch(1),
            &fence,
            &setup.clock,
        )
        .expect("expectation set");
    let mut draft = base_review(
        &fence,
        "review-bind-1",
        "req-review-bind-1",
        &artifact,
        get_u64(&fixture, "review_revision"),
    );
    draft.criteria = get_str_list(&fixture, "criteria");
    draft.proof_refs = get_str_list(&fixture, "proof_refs");
    let receipt = setup
        .owner
        .submit_peer_review(&draft, &setup.clock, &setup.durability)
        .expect("review submits");
    assert_eq!(
        receipt.review.lifecycle,
        eliot_coordination::PeerReviewLifecycle::PendingDelivery
    );
    assert_eq!(receipt.review.artifact_digest, "digest-artifact-r5");
    assert_eq!(receipt.review.criteria, get_str_list(&fixture, "criteria"));
    assert_eq!(
        receipt.review.anchor_field,
        get_str(&fixture, "anchor_field")
    );
    assert!(!receipt.replayed);
    let mut missing = base_review(&fence, "review-bind-2", "req-review-bind-2", &artifact, 5);
    missing.criteria = Vec::new();
    assert_eq!(
        setup
            .owner
            .submit_peer_review(&missing, &setup.clock, &setup.durability),
        Err(CoordinationError::InvalidField("criteria"))
    );
    let unknown = base_review(
        &fence,
        "review-bind-3",
        "req-review-bind-3",
        "artifact-missing",
        1,
    );
    assert_eq!(
        setup
            .owner
            .submit_peer_review(&unknown, &setup.clock, &setup.durability),
        Err(CoordinationError::NotFound {
            kind: "artifact",
            id: "artifact-missing".to_owned()
        })
    );
}

// WORK_UNIT_CASE: 696/25
#[test]
fn peer_revision_n_review_is_stale_for_n_plus_one() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    let stale = setup
        .owner
        .submit_peer_review(
            &base_review(
                &fence,
                "review-stale-1",
                "req-review-stale-1",
                &artifact,
                get_u64(&fixture, "stale_revision"),
            ),
            &setup.clock,
            &setup.durability,
        )
        .expect("stale review retained");
    assert_eq!(
        stale.review.lifecycle,
        eliot_coordination::PeerReviewLifecycle::Stale
    );
    assert_eq!(
        stale.review.artifact_digest,
        format!("digest-artifact-r{}", get_int(&fixture, "stale_revision"))
    );
    let denominator = setup.owner.peer_review_denominator(&artifact);
    assert_eq!(denominator.stale, 1);
    assert_eq!(
        setup.owner.submit_peer_review(
            &base_review(
                &fence,
                "review-future-1",
                "req-review-future-1",
                &artifact,
                get_u64(&fixture, "future_revision"),
            ),
            &setup.clock,
            &setup.durability,
        ),
        Err(CoordinationError::InvalidField("artifact_revision"))
    );
    assert_eq!(
        setup.owner.advance_peer_review(
            "review-stale-1",
            PeerReviewAdvance::Deliver,
            "session-a",
            None
        ),
        Err(CoordinationError::InvalidState)
    );
}

// WORK_UNIT_CASE: 696/26
#[test]
fn peer_unresolved_anchors_cannot_satisfy_required_review() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    for (index, anchor) in [
        AnchorResolution::Ambiguous,
        AnchorResolution::Stale,
        AnchorResolution::Deleted,
        AnchorResolution::Unavailable,
    ]
    .iter()
    .enumerate()
    {
        let mut draft = base_review(
            &fence,
            &format!("review-anchor-bad-{index}"),
            &format!("req-anchor-bad-{index}"),
            &artifact,
            get_u64(&fixture, "review_revision"),
        );
        draft.anchor_resolution = *anchor;
        assert_eq!(
            setup
                .owner
                .submit_peer_review(&draft, &setup.clock, &setup.durability),
            Err(CoordinationError::PeerReviewAnchorInvalid(format!(
                "review-anchor-bad-{index}"
            )))
        );
    }
    for (index, anchor) in [AnchorResolution::Moved, AnchorResolution::Modified]
        .iter()
        .enumerate()
    {
        let mut draft = base_review(
            &fence,
            &format!("review-anchor-ok-{index}"),
            &format!("req-anchor-ok-{index}"),
            &artifact,
            get_u64(&fixture, "review_revision"),
        );
        draft.anchor_resolution = *anchor;
        let receipt = setup
            .owner
            .submit_peer_review(&draft, &setup.clock, &setup.durability)
            .expect("resolvable anchor accepted");
        assert_eq!(
            receipt.review.lifecycle,
            eliot_coordination::PeerReviewLifecycle::PendingDelivery
        );
    }
}

// WORK_UNIT_CASE: 696/27
#[test]
fn peer_conflicting_reviews_preserve_a_conflict_set() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    let head_revision = get_u64(&fixture, "review_revision");
    setup
        .owner
        .submit_peer_review(
            &base_review(
                &fence,
                "review-duel-approve",
                "req-duel-approve",
                &artifact,
                head_revision,
            ),
            &setup.clock,
            &setup.durability,
        )
        .expect("approval submits");
    let mut rival = base_review(
        &fence,
        "review-duel-reject",
        "req-duel-reject",
        &artifact,
        head_revision,
    );
    rival.reviewer_session_id = "session-b".to_owned();
    rival.recommendation = ReviewRecommendation::RequestChanges;
    let receipt = setup
        .owner
        .submit_peer_review(&rival, &setup.clock, &setup.durability)
        .expect("objection submits");
    let conflict_id = receipt.review.conflict_id.clone().expect("conflict linked");
    let conflict = setup
        .owner
        .read_peer_conflict(&conflict_id)
        .expect("set retained");
    assert_eq!(conflict.conflict_type, PeerConflictType::Epistemic);
    assert_eq!(conflict.state, PeerConflictState::Open);
    assert_eq!(conflict.acceptability, ArgumentAcceptability::Contested);
    assert_eq!(conflict.candidates.len(), 2);
    let first = setup
        .owner
        .read_peer_review("review-duel-approve")
        .expect("approval kept");
    assert_eq!(first.conflict_id, Some(conflict_id));
    assert_eq!(
        first.lifecycle,
        eliot_coordination::PeerReviewLifecycle::PendingDelivery
    );

    let mut abstention = base_review(
        &fence,
        "review-duel-abstain",
        "req-duel-abstain",
        &artifact,
        head_revision,
    );
    abstention.reviewer_session_id = "session-c".to_owned();
    abstention.recommendation = ReviewRecommendation::Abstain;
    let receipt = setup
        .owner
        .submit_peer_review(&abstention, &setup.clock, &setup.durability)
        .expect("abstention submits");
    assert_eq!(receipt.review.conflict_id, None);
}

// Helper for 696/28: submits one review per standing (complete, partial,
// abstained, expired) so the denominator case stays under the line limit; all
// four submissions and their expectations are preserved verbatim.
fn submit_denominator_reviews(
    setup: &mut PeerSetup,
    fence: &StateFence,
    artifact: &str,
    head_revision: u64,
) {
    setup
        .owner
        .submit_peer_review(
            &base_review(
                fence,
                "review-full-1",
                "req-full-1",
                artifact,
                head_revision,
            ),
            &setup.clock,
            &setup.durability,
        )
        .expect("complete submits");
    let mut partial = base_review(
        fence,
        "review-partial-1",
        "req-partial-1",
        artifact,
        head_revision,
    );
    "session-b".clone_into(&mut partial.reviewer_session_id);
    partial.completeness = ReviewCompleteness::Partial;
    setup
        .owner
        .submit_peer_review(&partial, &setup.clock, &setup.durability)
        .expect("partial submits");
    let mut abstained = base_review(
        fence,
        "review-abstain-1",
        "req-abstain-1",
        artifact,
        head_revision,
    );
    "session-c".clone_into(&mut abstained.reviewer_session_id);
    abstained.recommendation = ReviewRecommendation::Abstain;
    abstained.completeness = ReviewCompleteness::Abstain;
    setup
        .owner
        .submit_peer_review(&abstained, &setup.clock, &setup.durability)
        .expect("abstention submits");
    register_session(
        &mut setup.owner,
        &setup.fence.clone(),
        "session-e",
        10,
        100_000,
    );
    let mut expiring = base_review(
        fence,
        "review-expiring-1",
        "req-expiring-1",
        artifact,
        head_revision,
    );
    "session-e".clone_into(&mut expiring.reviewer_session_id);
    expiring.expires_at = Some(1000);
    setup
        .owner
        .submit_peer_review(&expiring, &setup.clock, &setup.durability)
        .expect("expiring submits");
}

// WORK_UNIT_CASE: 696/28
#[test]
fn peer_expected_review_denominator_retains_every_standing() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    setup
        .owner
        .expect_peer_reviews(
            &artifact,
            get_u64(&fixture, "expected_reviews"),
            "session-a",
            &test_epoch(1),
            &fence,
            &setup.clock,
        )
        .expect("expectation set");
    let head_revision = get_u64(&fixture, "review_revision");
    submit_denominator_reviews(&mut setup, &fence, &artifact, head_revision);
    let denominator = setup.owner.peer_review_denominator(&artifact);
    assert_eq!(denominator.expected, 3);
    assert_eq!(denominator.submitted, 4);
    assert_eq!(denominator.complete, 1);
    assert_eq!(denominator.partial, 1);
    assert_eq!(denominator.abstained, 1);
    assert_eq!(denominator.expired, 1);
    for id in [
        "review-full-1",
        "review-partial-1",
        "review-abstain-1",
        "review-expiring-1",
    ] {
        let stored: AnchoredReview = setup.owner.read_peer_review(id).expect("retained");
        assert_eq!(stored.artifact_id, artifact);
    }
    let expiring = setup
        .owner
        .read_peer_review("review-expiring-1")
        .expect("retained");
    assert_eq!(expiring.standing, PeerReviewStanding::Expired);
}

// WORK_UNIT_CASE: 696/29
#[test]
fn peer_review_acknowledgement_merges_admits_and_finishes_nothing() {
    let fixture = fixture_map("review-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let artifact = get_str(&fixture, "artifact_id");
    admit_revisions(
        &mut setup,
        &artifact,
        get_u64(&fixture, "head_revision"),
        "digest-artifact",
    );
    setup
        .owner
        .submit_peer_review(
            &base_review(
                &fence,
                "review-ack-1",
                "req-ack-1",
                &artifact,
                get_u64(&fixture, "review_revision"),
            ),
            &setup.clock,
            &setup.durability,
        )
        .expect("review submits");
    setup
        .owner
        .advance_peer_review(
            "review-ack-1",
            PeerReviewAdvance::Deliver,
            "session-a",
            None,
        )
        .expect("review delivers");
    let sequence = setup.owner.current_sequence();
    let receipt = setup
        .owner
        .acknowledge_peer_review("review-ack-1", "session-b")
        .expect("review acknowledged");
    assert_eq!(
        receipt.lifecycle,
        eliot_coordination::PeerReviewLifecycle::Delivered
    );
    assert!(!receipt.admitted);
    assert!(!receipt.merged);
    assert!(!receipt.finished);
    let stored = setup
        .owner
        .read_peer_review("review-ack-1")
        .expect("unchanged");
    assert_eq!(
        stored.lifecycle,
        eliot_coordination::PeerReviewLifecycle::Delivered
    );
    assert_eq!(setup.owner.current_sequence(), sequence);
    assert!(
        setup
            .owner
            .read_unique_active_work_lease(1000, test_epoch(1), &fence)
            .is_err()
    );
}

// WORK_UNIT_CASE: 696/30
#[test]
fn peer_channel_rejects_stale_epoch_fence_and_session() {
    let mut setup = peer_setup();
    register_session(
        &mut setup.owner,
        &fence_for(test_epoch(2)),
        "session-new",
        10,
        100_000,
    );
    let fence = setup.fence.clone();
    let mut stale_epoch = base_draft(&fence, "msg-stale-epoch", "req-stale-epoch");
    stale_epoch.sender_session_id = "session-new".to_owned();
    stale_epoch.authority_epoch = test_epoch(1);
    stale_epoch.state_fence = fence_for(test_epoch(1));
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&stale_epoch, &setup.clock, &setup.durability),
        Err(CoordinationError::EpochMismatch)
    );
    let mut foreign = base_draft(&fence, "msg-foreign", "req-foreign");
    foreign.authority_epoch = foreign_epoch();
    foreign.state_fence = fence_for(foreign_epoch());
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&foreign, &setup.clock, &setup.durability),
        Err(CoordinationError::EpochMismatch)
    );
    let stale_fence = StateFence::new(
        test_epoch(1),
        ResourceGeneration::new(2).expect("generation"),
    );
    let mut fenced = base_draft(&fence, "msg-stale-fence", "req-stale-fence");
    fenced.state_fence = stale_fence;
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&fenced, &setup.clock, &setup.durability),
        Err(CoordinationError::FenceMismatch)
    );
    let mut ghost = base_draft(&fence, "msg-ghost", "req-ghost");
    ghost.sender_session_id = "session-ghost".to_owned();
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&ghost, &setup.clock, &setup.durability),
        Err(CoordinationError::NotFound {
            kind: "session",
            id: "session-ghost".to_owned()
        })
    );
    register_session(&mut setup.owner, &fence, "session-old", 10, 500);
    setup.clock.now.set(1000);
    let mut expired = base_draft(&fence, "msg-old", "req-old");
    expired.sender_session_id = "session-old".to_owned();
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&expired, &setup.clock, &setup.durability),
        Err(CoordinationError::SessionExpired)
    );
}

// WORK_UNIT_CASE: 696/31
#[test]
fn peer_cross_scope_and_audience_forwarding_is_rejected() {
    let fixture = fixture_map("guard-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let mut draft = base_draft(&fence, "msg-forward-1", "req-forward-1");
    draft.scope = get_str(&fixture, "home_scope");
    let admitted = enqueue(&mut setup, &draft);
    assert_eq!(admitted.message.scope, get_str(&fixture, "home_scope"));

    let replayed = setup
        .owner
        .forward_peer_message(
            "msg-forward-1",
            "req-forward-same",
            "session-b",
            &get_str(&fixture, "home_scope"),
        )
        .expect("same-target forward replays");
    assert_eq!(replayed.message_id, "msg-forward-1");
    assert_eq!(
        setup.owner.forward_peer_message(
            "msg-forward-1",
            "req-forward-foreign",
            "session-b",
            &get_str(&fixture, "foreign_scope")
        ),
        Err(CoordinationError::PeerCrossScopeRejected(
            "msg-forward-1".to_owned()
        ))
    );
    assert_eq!(
        setup.owner.forward_peer_message(
            "msg-forward-1",
            "req-forward-audience",
            "session-c",
            &get_str(&fixture, "home_scope")
        ),
        Err(CoordinationError::PeerSemanticConflict(
            "msg-forward-1".to_owned()
        ))
    );
    let stored = setup
        .owner
        .read_peer_message("msg-forward-1")
        .expect("unmoved");
    assert_eq!(stored.stream.recipient_session_id, "session-b");
    assert_eq!(stored.scope, get_str(&fixture, "home_scope"));
}

// WORK_UNIT_CASE: 696/32
#[test]
fn peer_embedded_commands_tools_and_instructions_stay_inert() {
    let fixture = fixture_map("guard-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let mut draft = base_draft(&fence, "msg-inert-1", "req-inert-1");
    draft.kind = PeerMessageKind::Evidence;
    draft.embedded = vec![
        EmbeddedMarkerDraft {
            marker: EmbeddedMarkerKind::Command,
            detail: get_str(&fixture, "embedded_command"),
        },
        EmbeddedMarkerDraft {
            marker: EmbeddedMarkerKind::ToolCall,
            detail: get_str(&fixture, "embedded_tool"),
        },
        EmbeddedMarkerDraft {
            marker: EmbeddedMarkerKind::Instruction,
            detail: get_str(&fixture, "embedded_instruction"),
        },
    ];
    let sequence = setup.owner.current_sequence();
    let receipt = enqueue(&mut setup, &draft);
    assert_eq!(receipt.message.embedded.len(), 3);
    assert!(
        receipt
            .message
            .embedded
            .iter()
            .all(|marker| marker.disposition == eliot_coordination::MarkerDisposition::Inert)
    );
    setup
        .owner
        .attempt_peer_delivery(
            "msg-inert-1",
            "route-peer",
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("evidence delivers");
    setup
        .owner
        .acknowledge_peer_message("msg-inert-1", 1, "session-b", &setup.clock)
        .expect("evidence acknowledged");
    setup
        .owner
        .consume_peer_message("msg-inert-1", "session-b", "evidence-inert-1", &setup.clock)
        .expect("evidence consumed");
    let stored = setup
        .owner
        .read_peer_message("msg-inert-1")
        .expect("stored");
    assert_eq!(stored.embedded.len(), 3);
    assert!(matches!(stored.state, PeerMessageState::Consumed { .. }));
    assert_eq!(
        setup.owner.current_sequence(),
        sequence.saturating_add(1),
        "live-delivery steps advance no causal event"
    );
    assert!(
        setup
            .owner
            .read_unique_active_work_lease(1000, test_epoch(1), &fence)
            .is_err()
    );
}

// WORK_UNIT_CASE: 696/33
#[test]
fn peer_authority_work_assignment_and_finish_injection_is_rejected() {
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let sequence = setup.owner.current_sequence();
    let injections = [
        AssertedEffect::AssignWork {
            work_item_id: "work-w1".to_owned(),
        },
        AssertedEffect::GrantEffect {
            detail: "effect-grant".to_owned(),
        },
        AssertedEffect::DeclareFinish {
            work_item_id: "work-w1".to_owned(),
        },
        AssertedEffect::DirectCommand {
            detail: "run now".to_owned(),
        },
    ];
    for (index, asserted) in injections.into_iter().enumerate() {
        let mut draft = base_draft(
            &fence,
            &format!("msg-inject-{index}"),
            &format!("req-inject-{index}"),
        );
        draft.asserted = Some(asserted);
        assert_eq!(
            setup
                .owner
                .enqueue_peer_message(&draft, &setup.clock, &setup.durability),
            Err(CoordinationError::PeerAuthorityRejected(format!(
                "msg-inject-{index}"
            )))
        );
    }
    assert_eq!(setup.owner.current_sequence(), sequence);
    assert!(setup.owner.read_peer_message("msg-inject-0").is_err());
    assert!(
        setup
            .owner
            .read_unique_active_work_lease(1000, test_epoch(1), &fence)
            .is_err()
    );
}

// WORK_UNIT_CASE: 696/34
#[test]
fn peer_secret_payloads_are_redacted_through_every_view() {
    let fixture = fixture_map("guard-vectors.json");
    let mut setup = peer_setup();
    let fence = setup.fence.clone();
    let mut secret = base_draft(&fence, "msg-redact-1", "req-redact-1");
    secret.privacy = PrivacyClass::Secret;
    secret.disclosure_handle = Some(get_str(&fixture, "disclosure_handle"));
    secret.inline_text = Some(get_str(&fixture, "secret_inline"));
    secret.payload_digest = get_str(&fixture, "secret_digest");
    let receipt = enqueue(&mut setup, &secret);
    let diagnostic = receipt.message.diagnostic();
    assert!(diagnostic.redacted);
    assert_eq!(diagnostic.inline_text, None);
    assert_eq!(
        diagnostic.payload_digest,
        get_str(&fixture, "secret_digest")
    );
    let rendered = format!("{diagnostic:?}");
    assert!(!rendered.contains("alpha-nine-seven"));

    let mut open = base_draft(&fence, "msg-redact-2", "req-redact-2");
    open.inline_text = Some(get_str(&fixture, "public_inline"));
    let receipt = enqueue(&mut setup, &open);
    let diagnostic = receipt.message.diagnostic();
    assert!(!diagnostic.redacted);
    assert_eq!(
        diagnostic.inline_text,
        Some(get_str(&fixture, "public_inline"))
    );

    setup
        .owner
        .attempt_peer_delivery(
            "msg-redact-1",
            "route-peer",
            &setup.clock,
            &mut setup.delivery,
        )
        .expect("secret delivers by handle");
    let error = setup
        .owner
        .acknowledge_peer_message("msg-redact-1", 99, "session-b", &setup.clock)
        .expect_err("wrong revision fails");
    assert!(!format!("{error}").contains("alpha-nine-seven"));
}

// WORK_UNIT_CASE: 696/35
#[test]
fn peer_channel_runs_only_over_injected_ports() {
    let path = format!("{}/src/peer_communication.rs", env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(&path).expect("channel source is readable");
    for forbidden in [
        "std::net",
        "std::process",
        "std::thread",
        "std::fs",
        "std::os::",
        "std::time::",
        "tokio",
        "async_std",
        "TcpStream",
        "UdpSocket",
        "thread::spawn",
        "SystemTime",
        "Instant::now",
        "Command::",
        "surrealdb",
        "reqwest",
        "hyper",
        "tonic::",
        "socket",
        "scheduler",
        "transport",
    ] {
        assert!(!source.contains(forbidden), "forbidden token {forbidden}");
    }

    let mut setup = peer_setup();
    setup.clock.now.set(1000);
    setup.durability = FakeDurability::unavailable("store offline");
    let fence = setup.fence.clone();
    let mut draft = base_draft(&fence, "msg-ports-1", "req-ports-1");
    draft.expires_at = Some(2000);
    let receipt = setup
        .owner
        .enqueue_peer_message(&draft, &setup.clock, &setup.durability)
        .expect("unavailable durability still records");
    assert_eq!(
        receipt.durability,
        PeerDurability::Unavailable {
            reason: "store offline".to_owned()
        }
    );
    assert_eq!(receipt.message.state, PeerMessageState::Staged);
    assert!(setup.clock.calls.get() >= 1);
    assert!(setup.durability.calls.get() >= 1);

    setup.delivery = RecordingDelivery::scripted(vec![
        PeerDeliveryAttempt::Unavailable {
            reason: "endpoint down".to_owned(),
        },
        PeerDeliveryAttempt::Delivered {
            endpoint: "route-recovered".to_owned(),
        },
    ]);
    let first = setup
        .owner
        .attempt_peer_delivery("msg-ports-1", "route-x", &setup.clock, &mut setup.delivery)
        .expect("first attempt recorded");
    assert!(matches!(
        first.outcome,
        PeerDeliveryAttempt::Unavailable { .. }
    ));
    let second = setup
        .owner
        .attempt_peer_delivery("msg-ports-1", "route-x", &setup.clock, &mut setup.delivery)
        .expect("retry recorded");
    assert!(matches!(
        second.outcome,
        PeerDeliveryAttempt::Delivered { .. }
    ));
    assert_eq!(setup.delivery.log.len(), 2);
    assert_eq!(setup.delivery.log[0].message_id, "msg-ports-1");
    assert_eq!(setup.delivery.log[0].stream_seq, 1);

    let mut expired = base_draft(&fence, "msg-ports-2", "req-ports-2");
    expired.expires_at = Some(1000);
    assert_eq!(
        setup
            .owner
            .enqueue_peer_message(&expired, &setup.clock, &setup.durability),
        Err(CoordinationError::PeerExpired("msg-ports-2".to_owned())),
        "supplied clock alone decides expiry"
    );
}
