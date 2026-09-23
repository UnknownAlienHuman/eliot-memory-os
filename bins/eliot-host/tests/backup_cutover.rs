//! Backup cutover fixture-schema/admission-shape probes (issue #961).
//!
//! Feasibility-probe harness only: `src/backup_cutover.rs` is unregistered
//! (no `mod backup_cutover` in `src/lib.rs`) and its owner imports resolve
//! only after #974 (Cargo edge) and #1751 (retirement barrier) land. These
//! tests therefore assert frozen fixture shape/admission separation with
//! `std` + `serde_json` only and never import `eliot_host::backup_cutover`.
//! Live behavioral cutover proof stays deferred to the Windows phase.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::Value;

const ADMITTED_REQUEST_JSON: &str = include_str!("data/backup-cutover/admitted-request.json");
const REHEARSAL_ENVELOPE_JSON: &str = include_str!("data/backup-cutover/rehearsal-envelope.json");
const RECOVERY_FULL_JSON: &str =
    include_str!("data/backup-cutover/isolated-recovery-evidence-full.json");
const RECOVERY_DEGRADED_JSON: &str =
    include_str!("data/backup-cutover/isolated-recovery-evidence-degraded.json");
const PRIOR_INVALIDATION_JSON: &str =
    include_str!("data/backup-cutover/prior-authority-invalidation.json");
const EXPECTED_PREDECESSOR_JSON: &str =
    include_str!("data/backup-cutover/expected-predecessor.json");

const DEFERRED_NOTE: &str =
    "fixed owner receipt shape for unit dev; live Windows proof deferred (T19 TEST-PHASE)";

fn parse(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture parses as JSON")
}

fn is_hex64(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn str_field<'a>(doc: &'a Value, key: &str) -> &'a str {
    doc.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("fixture carries string field {key}"))
}

// WORK_UNIT_CASE: 961/1
#[test]
fn admitted_request_fixture_tag() {
    let doc = parse(ADMITTED_REQUEST_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("admitted-request")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/2
#[test]
fn admitted_request_is_admitted() {
    let doc = parse(ADMITTED_REQUEST_JSON);
    assert_eq!(doc.get("is_admitted").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        doc.get("rehearsal_passed").and_then(|v| v.as_bool()),
        Some(true)
    );
}

// WORK_UNIT_CASE: 961/3
#[test]
fn admitted_request_digest_shapes() {
    let doc = parse(ADMITTED_REQUEST_JSON);
    assert!(is_hex64(&doc["digest"]), "admitted digest is 64 hex chars");
    assert!(
        is_hex64(&doc["predecessor"]),
        "admitted predecessor is 64 hex chars"
    );
}

// WORK_UNIT_CASE: 961/4
#[test]
fn rehearsal_envelope_fixture_tag() {
    let doc = parse(REHEARSAL_ENVELOPE_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("rehearsal-envelope")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/5
#[test]
fn rehearsal_envelope_never_satisfies_admission() {
    let doc = parse(REHEARSAL_ENVELOPE_JSON);
    assert_eq!(doc.get("is_sealed").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        doc.get("rehearsal_passed").and_then(|v| v.as_bool()),
        Some(false),
        "a rehearsal envelope must not read as admitted cutover authority"
    );
}

// WORK_UNIT_CASE: 961/6
#[test]
fn rehearsal_envelope_digest_shapes() {
    let doc = parse(REHEARSAL_ENVELOPE_JSON);
    assert!(
        is_hex64(&doc["envelope_digest"]),
        "envelope digest is 64 hex chars"
    );
    assert!(
        is_hex64(&doc["predecessor"]),
        "rehearsal predecessor is 64 hex chars"
    );
}

// WORK_UNIT_CASE: 961/7
#[test]
fn recovery_full_fixture_tag() {
    let doc = parse(RECOVERY_FULL_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("isolated-recovery-evidence-full")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/8
#[test]
fn recovery_full_is_verified_isolated() {
    let doc = parse(RECOVERY_FULL_JSON);
    assert_eq!(doc.get("verified").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(doc.get("is_isolated").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        doc.get("is_degraded").and_then(|v| v.as_bool()),
        Some(false)
    );
}

// WORK_UNIT_CASE: 961/9
#[test]
fn recovery_full_digest_shape() {
    let doc = parse(RECOVERY_FULL_JSON);
    assert!(
        is_hex64(&doc["recovery_digest"]),
        "recovery digest is 64 hex chars"
    );
}

// WORK_UNIT_CASE: 961/10
#[test]
fn recovery_degraded_fixture_tag() {
    let doc = parse(RECOVERY_DEGRADED_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("isolated-recovery-evidence-degraded")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/11
#[test]
fn recovery_degraded_is_not_cutover_ready() {
    let doc = parse(RECOVERY_DEGRADED_JSON);
    assert_eq!(doc.get("is_degraded").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(doc.get("verified").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        doc.get("degraded_reason").and_then(|v| v.as_str()),
        Some("snapshot-gap")
    );
}

// WORK_UNIT_CASE: 961/12
#[test]
fn recovery_degraded_stays_isolated() {
    let doc = parse(RECOVERY_DEGRADED_JSON);
    assert_eq!(doc.get("is_isolated").and_then(|v| v.as_bool()), Some(true));
    assert!(
        is_hex64(&doc["recovery_digest"]),
        "degraded digest is 64 hex chars"
    );
}

// WORK_UNIT_CASE: 961/13
#[test]
fn prior_invalidation_fixture_tag() {
    let doc = parse(PRIOR_INVALIDATION_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("prior-authority-invalidation")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/14
#[test]
fn prior_authority_is_invalidated() {
    let doc = parse(PRIOR_INVALIDATION_JSON);
    assert_eq!(
        doc.get("is_invalidated").and_then(|v| v.as_bool()),
        Some(true),
        "old authority never revives after cutover"
    );
}

// WORK_UNIT_CASE: 961/15
#[test]
fn prior_invalidation_digest_shapes() {
    let doc = parse(PRIOR_INVALIDATION_JSON);
    assert!(
        is_hex64(&doc["invalidation_digest"]),
        "invalidation digest is 64 hex chars"
    );
    assert!(
        is_hex64(&doc["prior_authority"]),
        "prior authority is 64 hex chars"
    );
    assert_ne!(
        str_field(&doc, "invalidation_digest"),
        str_field(&doc, "prior_authority"),
        "invalidation handle differs from the retired authority"
    );
}

// WORK_UNIT_CASE: 961/16
#[test]
fn expected_predecessor_fixture_tag() {
    let doc = parse(EXPECTED_PREDECESSOR_JSON);
    assert_eq!(
        doc.get("fixture").and_then(|v| v.as_str()),
        Some("expected-predecessor")
    );
    assert_eq!(doc.get("issue").and_then(|v| v.as_u64()), Some(961));
}

// WORK_UNIT_CASE: 961/17
#[test]
fn expected_predecessor_is_pinned() {
    let doc = parse(EXPECTED_PREDECESSOR_JSON);
    assert_eq!(doc.get("is_pinned").and_then(|v| v.as_bool()), Some(true));
    assert!(is_hex64(&doc["predecessor"]), "predecessor is 64 hex chars");
    assert!(
        is_hex64(&doc["expected_digest"]),
        "expected digest is 64 hex chars"
    );
}

// WORK_UNIT_CASE: 961/18
#[test]
fn admitted_and_rehearsal_handles_differ() {
    let admitted = parse(ADMITTED_REQUEST_JSON);
    let rehearsal = parse(REHEARSAL_ENVELOPE_JSON);
    assert_ne!(
        str_field(&admitted, "digest"),
        str_field(&rehearsal, "envelope_digest"),
        "restore-test envelope derives a different digest-bound handle"
    );
    assert_ne!(
        str_field(&admitted, "predecessor"),
        str_field(&rehearsal, "predecessor"),
        "admitted and rehearsal predecessors are distinct contours"
    );
}

// WORK_UNIT_CASE: 961/19
#[test]
fn recovery_full_and_degraded_digests_differ() {
    let full = parse(RECOVERY_FULL_JSON);
    let degraded = parse(RECOVERY_DEGRADED_JSON);
    assert_ne!(
        str_field(&full, "recovery_digest"),
        str_field(&degraded, "recovery_digest"),
        "degraded recovery never replays the verified digest"
    );
}

// WORK_UNIT_CASE: 961/20
#[test]
fn all_fixtures_carry_deferred_proof_note() {
    for raw in [
        ADMITTED_REQUEST_JSON,
        REHEARSAL_ENVELOPE_JSON,
        RECOVERY_FULL_JSON,
        RECOVERY_DEGRADED_JSON,
        PRIOR_INVALIDATION_JSON,
        EXPECTED_PREDECESSOR_JSON,
    ] {
        let doc = parse(raw);
        assert_eq!(
            doc.get("note").and_then(|v| v.as_str()),
            Some(DEFERRED_NOTE),
            "fixture defers live Windows proof explicitly"
        );
    }
}
