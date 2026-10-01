//! Corpus integrity for the binary-private bounded-decoder proof suite.
//!
//! The decode behavior itself is proven by the binary unit test
//! `bounded_decoder_fixture_covers_accept_skip_and_reject` in
//! `src/main.rs`, which drives this exact file through the production
//! pipeline. This harness proves the corpus it depends on: the versioned
//! profile identity, the finite limit table with exact values, and a
//! case list of at least twenty entries with unique ids and well-formed
//! expectations. It imports no binary-private module.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use serde_json::Value;
use std::collections::BTreeSet;

const PROFILE_ID: &str = "eliot.agent-bridge.request-input.v1";

/// Exact bounded rows: (limit name, expected numeric value).
const BOUNDED_LIMITS: [(&str, u64); 13] = [
    ("max_record_bytes", 1_048_576),
    ("max_buffered_bytes", 2_097_152),
    ("max_json_string_bytes", 524_288),
    ("max_container_items", 4_096),
    ("max_scalar_values", 16_384),
    ("max_nesting_depth", 64),
    ("max_requests_per_process", 65_536),
    ("max_consecutive_invalid_records", 8),
    ("max_oversize_discard_bytes", 4_194_304),
    ("max_output_frame_bytes", 524_288),
    ("max_stop_drain_items", 32),
    ("max_control_name_chars", 64),
    ("stdout_write_timeout_ms", 5_000),
];

fn corpus() -> Value {
    serde_json::from_str(include_str!("data/request_input_cases.json"))
        .expect("decoder corpus must parse")
}

// WORK_UNIT_CASE: 977/1
#[test]
fn corpus_profile_identity_is_versioned() {
    let fixture = corpus();
    assert_eq!(fixture["profile_id"], Value::String(PROFILE_ID.to_owned()));
    assert_eq!(fixture["profile_revision"], Value::String("v1".to_owned()));
}

// WORK_UNIT_CASE: 977/1
// WORK_UNIT_CASE: 977/20
#[test]
fn corpus_limit_table_is_finite_with_exact_bounds() {
    let fixture = corpus();
    let limits = fixture["limits"].as_array().expect("limits must list");
    for (name, value) in BOUNDED_LIMITS {
        let row = limits
            .iter()
            .find(|row| row["name"] == Value::String(name.to_owned()))
            .unwrap_or_else(|| panic!("limit table must declare {name}"));
        assert_eq!(
            row["value"],
            Value::from(value),
            "limit {name} must keep its reviewed value"
        );
    }
    let disposition = limits
        .iter()
        .find(|row| row["name"] == Value::String("oversize_disposition".to_owned()))
        .expect("limit table must declare the oversize disposition");
    assert_eq!(
        disposition["value"],
        Value::String("discard-through-terminator".to_owned())
    );
}

// WORK_UNIT_CASE: 977/19
// WORK_UNIT_CASE: 977/20
#[test]
fn corpus_holds_at_least_twenty_unique_well_formed_cases() {
    let fixture = corpus();
    let cases = fixture["cases"].as_array().expect("cases must list");
    assert!(
        cases.len() >= 20,
        "proof corpus needs at least 20 cases, found {}",
        cases.len()
    );
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut accepts: usize = 0;
    let mut skips: usize = 0;
    let mut rejects: usize = 0;
    for case in cases {
        let id = case["id"].as_str().expect("case needs an id");
        assert!(seen.insert(id), "case id {id} must be unique");
        let expect = case["expect"].as_str().expect("case needs an expect");
        let sources = usize::from(case.get("raw").is_some())
            + usize::from(case.get("raw_is").is_some())
            + usize::from(case.get("raw_bytes").is_some());
        assert_eq!(sources, 1, "case {id} needs exactly one raw source");
        match expect {
            "accept" => {
                assert!(
                    case.get("op").and_then(Value::as_str).is_some(),
                    "accept case {id} must name its operation"
                );
                accepts += 1;
            }
            "skip" => skips += 1,
            "reject" => {
                assert!(
                    case.get("reason").and_then(Value::as_str).is_some(),
                    "reject case {id} must name its reason"
                );
                rejects += 1;
            }
            _ => panic!("case {id} names an unknown expectation"),
        }
    }
    assert!(accepts >= 1, "corpus must prove at least one accept");
    assert!(skips >= 1, "corpus must prove blank-line skipping");
    assert!(rejects >= 10, "corpus must prove the rejection family");
}

// WORK_UNIT_CASE: 977/20
#[test]
fn production_call_chain_has_no_unbounded_bypass_or_cloned_decoder() {
    let main = include_str!("../src/main.rs");
    let decoder = include_str!("../src/request_input.rs");
    // Dispatch decodes only through the bounded profile-bound entry point,
    // and stdin is acquired only through the bounded record reader: the
    // transport is unchanged and no second path exists.
    assert!(
        main.contains("fn decode_bounded_request(text: &str)"),
        "dispatch must keep its single bounded decode entry point"
    );
    assert!(
        main.contains("decode_bounded_request(text)"),
        "the dispatch loop must call the bounded entry point"
    );
    assert!(
        main.contains("read_bounded_record(&mut stdin_lock"),
        "stdin acquisition must stay on the bounded record reader"
    );
    // No unbounded acquisition API survives in the binary.
    for forbidden in [".lines()", "read_line", "read_to_end"] {
        assert!(
            !main.contains(forbidden),
            "binary must not contain unbounded input API {forbidden}"
        );
        assert!(
            !decoder.contains(forbidden),
            "decoder must not contain unbounded input API {forbidden}"
        );
    }
    // The private stdin profile does not claim a blocking-read deadline, but
    // the distinct loopback HTTP transport has an independently enforced,
    // finite read deadline. Keep both scopes explicit in the source proof.
    assert!(
        main.contains("const HTTP_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);"),
        "loopback HTTP must keep its finite thirty-second read deadline"
    );
    let http_handler = main
        .split_once("fn serve_loopback_http_connection(")
        .expect("loopback HTTP connection handler must exist")
        .1
        .split_once("\n/// Applies the same finite socket deadlines")
        .expect("loopback HTTP handler must end before the shared deadline helper")
        .0;
    assert!(
        http_handler.contains("configure_loopback_http_deadlines(&mut stream)?;"),
        "production connection handler must delegate socket deadlines to the shared helper"
    );
    let deadline_helper = main
        .split_once("fn configure_loopback_http_deadlines(")
        .expect("production socket deadline helper must exist")
        .1
        .split_once("\n/// Admits one request through the I7.5 policy")
        .expect("deadline helper must have a bounded body")
        .0;
    assert!(
        deadline_helper.contains(".set_read_timeout(Some(HTTP_REQUEST_READ_TIMEOUT))"),
        "shared production helper must apply the declared HTTP read deadline"
    );
    assert!(
        deadline_helper.contains(".set_write_timeout(Some(STDOUT_WRITE_TIMEOUT))"),
        "shared production helper must retain the bounded response write deadline"
    );
    let deadline_install = http_handler
        .find("configure_loopback_http_deadlines(&mut stream)?;")
        .expect("production handler must install deadlines");
    let first_request_read = http_handler
        .find("read_loopback_http_request(&mut stream)")
        .expect("production handler must read the admitted request");
    assert!(
        deadline_install < first_request_read,
        "production connection handler must install deadlines before its first read"
    );
    assert!(
        !decoder.contains("set_read_timeout"),
        "blocking stdin decoder must not claim an enforced read deadline"
    );
    // No cloned or test-only decoder: typed `Request` construction happens
    // exactly once, inside the bounded entry point, and the pre-scan never
    // converts raw input into an untrusted `Value` tree before the
    // duplicate-sensitive checks run.
    assert!(
        !decoder.contains("serde_json::from_str"),
        "decoder must not host a second typed construction path"
    );
    assert!(
        !decoder.contains("serde_json::Value"),
        "decoder must not parse raw input into Value before checking it"
    );
    // The profile binding is present and honestly scoped: the binary
    // validates the accepted profile before acquisition, and the decoder
    // states that wall-clock rows are declared but not enforced on
    // blocking stdin, so no slow-reader interruption can be claimed.
    assert!(
        main.contains("REQUEST_INPUT_PROFILE"),
        "binary must stay bound to the accepted input profile"
    );
    assert!(
        decoder.contains("NOT enforced"),
        "decoder must keep its declared-not-enforced disclosure"
    );
}
