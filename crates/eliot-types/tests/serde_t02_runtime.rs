//! Issue #931 (`F-DENY-T02`) — later test phase, checklist item
//! AUD-TEST-PHASE-FIXTURES: raw-byte fixtures for descendant capture evidence
//! at the reap boundary.
//!
//! Audit comment 5932756267 requirement 6 asks for "raw-byte fixtures, not a
//! pre-normalized `Value`": zero descendant PID, duplicate/unsorted PID,
//! empty/oversized path/hash and one positive valid receipt. Every document
//! below is therefore raw JSON text decoded by
//! `serde_json::from_str::<ProcessReapReceipt>`, which is the decoder the
//! durable journal read path actually uses for the receipt
//! (`ProviderInvocationAttempt.process_reap_receipt`). A `Value` fixture could
//! not observe the lexical facts of a repeated object member at all, and it
//! would also be the already-collapsed projection every protected-identity
//! rule is supposed to run against.
//!
//! Attribution: each document is assembled from the same shared head/tail
//! literals, and only the descendant array differs between cases. A refusal is
//! therefore attributable to the member it names, and every case below asserts
//! on the refusal MESSAGE rather than on a bare `is_err()` — a bare `is_err()`
//! is satisfied by any failure anywhere in the record and proves nothing about
//! which rule fired.
//!
//! What the decoder does today, for the record (read, not assumed):
//! `runtime_supervision.rs::DescendantsAtRootExit::deserialize` (line 617)
//! reads the bytes through the private wire mirror and then runs the one
//! existing validator, `DescendantsAtRootExit::validate` (line 716), so a
//! zero PID, an unsorted list, a duplicated PID, an empty path/hash and an
//! oversized path/hash are all refused by the same rule set that
//! `DescendantsAtRootExit::captured` enforces at construction. No decoder
//! defect was found for these four cases; nothing here asserts today's wrong
//! behaviour and no refusal was weakened to make a case pass.
//!
//! Repeated object members are a different boundary and are owned elsewhere:
//! the shared duplicate-rejecting ingress `strict_json_has_no_duplicate_members`
//! is the single lexical decoder in this crate, so the repeated-member case
//! below is routed through it rather than answered with a second
//! duplicate-key scanner inside this file.

#![allow(clippy::expect_used)]

use eliot_types::runtime_supervision::ReapCompleteness;
use eliot_types::{
    MAX_DESCENDANT_IMAGE_PATH_CHARS, MAX_DESCENDANT_IMAGE_SHA256_CHARS, ProcessReapReceipt,
    StrictJsonErrorKind, strict_json_has_no_duplicate_members,
};

/// Fixture `file_identity.volume_serial_number`. A fixture constant, not a
/// measured volume serial.
const VOLUME_SERIAL_NUMBER: u32 = 3_735_928_559;

/// Fixture image path of the first descendant, in JSON-escaped wire form. Not a
/// real installation path.
const IMAGE_PATH_A: &str = r"C:\\Program Files\\Eliot\\eliot-kernel-service.exe";
/// Fixture image path of the second descendant, in JSON-escaped wire form.
const IMAGE_PATH_B: &str = r"C:\\Program Files\\Eliot\\eliot-host-supervisor.exe";
/// Fixture image hash of the first descendant. A synthetic 64-hex value, not a
/// measured digest; only its length and non-emptiness are under test.
const IMAGE_SHA_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// Fixture image hash of the second descendant.
const IMAGE_SHA_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// The receipt document up to and including the descendant array's opening
/// bracket. Shared byte for byte by every case below, so the only difference
/// between two cases is the descendant array each one supplies.
const RECEIPT_HEAD: &str = r#"{
  "operation_id": "op-931-reap-fixture",
  "generation": 7,
  "job_object_name": "job-931-reap-fixture",
  "root_pid": 4242,
  "process_count_before": 3,
  "process_count_after": 0,
  "graceful_attempted": true,
  "forced_termination": true,
  "stdout_closed": true,
  "stderr_closed": true,
  "all_tasks_joined": true,
  "elapsed_ms": 12,
  "terminal_error_codes": [],
  "descendants_at_root_exit": {
    "kind": "captured",
    "schema_version": "eliot-descendants-at-root-exit-v1",
    "root_pid": 4242,
    "root_exit_code": 0,
    "capture_elapsed_ms": 1,
    "descendants": ["#;

/// The descendant array's closing bracket plus the capture and receipt
/// closing braces.
const RECEIPT_TAIL: &str = r#"
    ]
  }
}
"#;

/// One descendant snapshot. `start_ticks` and `file_index` are part of the
/// call so that a case can keep every other byte identical to the positive
/// document.
fn descendant(pid: u32, start_ticks: u64, image_path: &str, file_index: u64, sha: &str) -> String {
    let mut entry = String::new();
    entry.push_str("{\n      \"pid\": ");
    entry.push_str(&pid.to_string());
    entry.push_str(",\n      \"start_ticks\": ");
    entry.push_str(&start_ticks.to_string());
    entry.push_str(",\n      \"image_path\": \"");
    entry.push_str(image_path);
    entry.push_str("\",\n      \"file_identity\": { \"volume_serial_number\": ");
    entry.push_str(&VOLUME_SERIAL_NUMBER.to_string());
    entry.push_str(", \"file_index\": ");
    entry.push_str(&file_index.to_string());
    entry.push_str(" },\n      \"image_sha256\": \"");
    entry.push_str(sha);
    entry.push_str("\"\n    }");
    entry
}

/// The two legitimate descendants of the positive document, in pid order.
fn legitimate_descendants() -> Vec<String> {
    vec![
        descendant(5100, 111, IMAGE_PATH_A, 4096, IMAGE_SHA_A),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]
}

/// One complete receipt document around the supplied descendant entries.
fn captured_receipt(entries: &[String]) -> String {
    let mut document = String::from(RECEIPT_HEAD);
    document.push_str(&entries.join(",\n"));
    document.push_str(RECEIPT_TAIL);
    document
}

/// The refusal message of one decode attempt. A bare `is_err()` would be
/// satisfied by any failure in the whole record, so the caller also reads the
/// message to bind the refusal to the descendant member it names.
fn refusal_message(document: &str) -> String {
    match serde_json::from_str::<ProcessReapReceipt>(document) {
        Ok(_) => panic!("decode must be refused"),
        Err(error) => error.to_string(),
    }
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-01 — the positive valid receipt. It
// must decode through the real receipt decoder AND satisfy the production
// cleanup predicate, so every negative case below differs from it only in the
// descendant member under test and the refusals cannot be blamed on an
// unrelated field.
#[test]
fn legitimate_descendant_set_decodes_and_proves_complete_reap() {
    let document = captured_receipt(&legitimate_descendants());
    let receipt: ProcessReapReceipt = serde_json::from_str(&document)
        .expect("a legitimate descendant set must decode through the receipt decoder");

    let DescendantsAtRootExit::Captured(captured) = &receipt.descendants_at_root_exit else {
        panic!("a captured descendant record must decode as the captured variant");
    };
    assert_eq!(
        captured.root_pid(),
        4242,
        "the capture must keep the root PID it was written with"
    );
    let pids: Vec<u32> = captured.descendants().iter().map(|entry| entry.pid).collect();
    assert_eq!(
        pids.as_slice(),
        [5100u32, 5200].as_slice(),
        "the capture must keep the pid-sorted descendant set it was written with"
    );
    assert_eq!(
        receipt.reap_completeness(),
        ReapCompleteness::Proven,
        "a validated capture over complete process counters is the only shape that \
         may prove a complete reap, so the negative cases below are refused \
         evidence rather than merely stricter copies of an already-refused input"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-02 — zero descendant PID. A zero PID
// is an absent process identity, not a weaker one, so it must be refused by
// the receipt decoder and not decoded into a `DescendantsAtRootExit` value.
#[test]
fn zero_descendant_pid_refused() {
    let document = captured_receipt(&[
        descendant(0, 111, IMAGE_PATH_A, 4096, IMAGE_SHA_A),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("pid must be non-zero"),
        "the refusal must name the zero-descendant-pid invariant; a refusal for any \
         other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-03 — unsorted descendant PID list.
// The list order is load-bearing evidence (it is what makes the duplicate check
// a window check), so an unsorted list must be refused rather than silently
// reordered by the decoder.
#[test]
fn unsorted_descendant_pid_refused() {
    let document = captured_receipt(&[
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
        descendant(5100, 111, IMAGE_PATH_A, 4096, IMAGE_SHA_A),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("descendants must be sorted by pid"),
        "the refusal must name the unsorted-descendant-list invariant; a refusal for \
         any other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-04 — duplicate descendant PID. Two
// entries claiming one PID are not two observations, so the capture must be
// refused and the refusal must name the duplicated PID itself.
#[test]
fn duplicate_descendant_pid_refused() {
    let document = captured_receipt(&[
        descendant(5100, 111, IMAGE_PATH_A, 4096, IMAGE_SHA_A),
        descendant(5100, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("duplicate pid 5100"),
        "the refusal must name the duplicated descendant PID; a refusal for any other \
         field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-05 — empty descendant `image_path`.
// An empty path is an absent image identity, so it must be refused by the
// receipt decoder rather than become the current image of a proven tree.
#[test]
fn empty_descendant_image_path_refused() {
    let document = captured_receipt(&[
        descendant(5100, 111, "", 4096, IMAGE_SHA_A),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("image_path must be non-empty"),
        "the refusal must name the empty-image-path invariant; a refusal for any \
         other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-06 — oversized descendant
// `image_path`, one character past the owner's published bound. The bound is
// read from the owner constant rather than spelled here.
#[test]
fn oversized_descendant_image_path_refused() {
    let oversized = "a".repeat(MAX_DESCENDANT_IMAGE_PATH_CHARS + 1);
    let document = captured_receipt(&[
        descendant(5100, 111, &oversized, 4096, IMAGE_SHA_A),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("image_path overflow"),
        "the refusal must name the oversized-image-path invariant; a refusal for any \
         other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-07 — empty descendant
// `image_sha256`. The hash is optional, so its ABSENCE decodes, but the
// spelled-out-empty spelling of that absence must be refused.
#[test]
fn empty_descendant_image_sha256_refused() {
    let document = captured_receipt(&[
        descendant(5100, 111, IMAGE_PATH_A, 4096, ""),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("image_sha256 must be non-empty"),
        "the refusal must name the empty-image-hash invariant; a refusal for any \
         other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-08 — oversized descendant
// `image_sha256`, one character past the owner's published bound.
#[test]
fn oversized_descendant_image_sha256_refused() {
    let oversized = "b".repeat(MAX_DESCENDANT_IMAGE_SHA256_CHARS + 1);
    let document = captured_receipt(&[
        descendant(5100, 111, IMAGE_PATH_A, 4096, &oversized),
        descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B),
    ]);
    let refusal = refusal_message(&document);
    assert!(
        refusal.contains("invalid descendant capture evidence")
            && refusal.contains("image_sha256 overflow"),
        "the refusal must name the oversized-image-hash invariant; a refusal for any \
         other field would not pin this case: {refusal}"
    );
}

// WORK_UNIT_CASE: 931/audit-5932756267-6-09 — the lexical half of the
// duplicate-PID case: one descendant that spells `pid` twice. The bytes are
// the only place this fact exists; `serde_json::Value` collapses the repeated
// member to last-wins, which is why the fixture is text. The repeated member
// is refused by the crate's single shared duplicate-rejecting ingress, and
// the same document without the repetition passes it, so the ingress is
// discriminating rather than blanket-refusing.
#[test]
fn repeated_descendant_pid_member_refused_at_shared_raw_byte_ingress() {
    let mut repeated = String::from("{\n      \"pid\": 5100,\n      \"pid\": 5300,");
    repeated.push_str("\n      \"start_ticks\": 111,\n      \"image_path\": \"");
    repeated.push_str(IMAGE_PATH_A);
    repeated.push_str("\",\n      \"file_identity\": { \"volume_serial_number\": ");
    repeated.push_str(&VOLUME_SERIAL_NUMBER.to_string());
    repeated.push_str(", \"file_index\": 4096 },\n      \"image_sha256\": \"");
    repeated.push_str(IMAGE_SHA_A);
    repeated.push_str("\"\n    }");
    let mut document = String::from(RECEIPT_HEAD);
    document.push_str(&repeated);
    document.push_str(",\n");
    document.push_str(&descendant(5200, 222, IMAGE_PATH_B, 8192, IMAGE_SHA_B));
    document.push_str(RECEIPT_TAIL);

    let refusal = strict_json_has_no_duplicate_members(document.as_bytes())
        .expect_err("a repeated descendant pid member must be refused at the raw-byte ingress");
    assert_eq!(
        refusal.kind,
        StrictJsonErrorKind::DuplicateKey,
        "the ingress must classify the repeated member as a duplicate key: {refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        StrictJsonErrorKind::DuplicateKey.as_str(),
        "the ingress refusal must stay bounded and redacted: it may not echo the \
         repeated member or the received bytes onto an operator surface: {refusal}"
    );

    let legitimate = captured_receipt(&legitimate_descendants());
    assert!(
        strict_json_has_no_duplicate_members(legitimate.as_bytes()).is_ok(),
        "the same ingress must accept the legitimate document, so the refusal above is \
         attributable to the repeated member and not to the record shape"
    );
}
