//! Issue #935: version selection is decided at the decode boundary, not by a
//! caller remembering to ask.
//!
//! The five schema-bearing records (`CognitiveRunContract`,
//! `CognitiveToolObservation`, `CognitiveRunAttempt`, `CognitiveRunTerminal`,
//! `CognitiveRawVerifierEvidence`, `ProjectUnderstandingModel`) each already
//! carried a `validate_schema_version` method, and the audited boundary call
//! sites used it. The gap the audit named was structural: the DERIVED
//! `Deserialize` accepted any `String`, so a record read through a path nobody
//! audited produced current-shaped data from an unsupported version, and the
//! only repo-wide check was `same_seal_request` on the contract.
//!
//! Each case below pins the same property from both sides: an unsupported,
//! misselected or empty version is refused DURING decode, and the same bytes
//! carrying the supported version get past the version gate (so the refusal in
//! the first arm is the version, not the record's shape).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_types::{
    COGNITIVE_RUN_SCHEMA_VERSION, CognitiveRawVerifierEvidence, CognitiveRunAttempt,
    CognitiveRunContract, CognitiveRunTerminal, CognitiveToolObservation,
    PROJECT_UNDERSTANDING_SCHEMA_VERSION, ProjectUnderstandingModel,
};

/// The five cognitive-run records, addressed as erased decoders so one table
/// covers all of them.
fn run_record_decoders() -> Vec<(&'static str, fn(&str) -> Result<(), String>)> {
    vec![
        ("CognitiveRunContract", |raw: &str| {
            serde_json::from_str::<CognitiveRunContract>(raw)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }),
        ("CognitiveToolObservation", |raw: &str| {
            serde_json::from_str::<CognitiveToolObservation>(raw)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }),
        ("CognitiveRunAttempt", |raw: &str| {
            serde_json::from_str::<CognitiveRunAttempt>(raw)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }),
        ("CognitiveRunTerminal", |raw: &str| {
            serde_json::from_str::<CognitiveRunTerminal>(raw)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }),
        ("CognitiveRawVerifierEvidence", |raw: &str| {
            serde_json::from_str::<CognitiveRawVerifierEvidence>(raw)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }),
    ]
}

// WORK_UNIT_CASE: 935/7
#[test]
fn an_unsupported_or_misselected_version_cannot_decode_into_current_data() {
    // The payload carries ONLY `schema_version`, so any error other than the
    // version refusal would be a missing-field error. Every refusal below must
    // therefore be the version gate, decided before the rest of the record.
    for (record, decode) in run_record_decoders() {
        for found in [
            "eliot-cognitive-run-v1",
            "eliot-cognitive-run-v3",
            "ELIOT-COGNITIVE-RUN-V2",
            "",
            " eliot-cognitive-run-v2",
        ] {
            let raw = format!("{{\"schema_version\": \"{found}\"}}");
            let error = decode(&raw)
                .err()
                .unwrap_or_else(|| panic!("{record} accepted schema_version `{found}`"));
            assert!(
                error.contains(found),
                "{record} must refuse `{found}` by version, got {error}"
            );
        }
    }
}

// WORK_UNIT_CASE: 935/8
#[test]
fn the_supported_version_gets_past_the_version_gate_for_every_record() {
    // Same bytes, supported version: the version gate no longer refuses, so the
    // remaining error is the record's own missing fields. This is what makes
    // the case above a version proof rather than a shape proof.
    for (record, decode) in run_record_decoders() {
        let raw = format!("{{\"schema_version\": \"{COGNITIVE_RUN_SCHEMA_VERSION}\"}}");
        let error = decode(&raw).err().unwrap_or_else(|| {
            panic!("{record} decoded from version alone, which must not happen")
        });
        assert!(
            !error.contains("unsupported"),
            "{record} must not refuse the supported version `{COGNITIVE_RUN_SCHEMA_VERSION}`, got {error}"
        );
        assert!(
            error.contains("missing field"),
            "{record} must now fail on its own missing fields, got {error}"
        );
    }
}

/// The project-understanding model behind the same erased signature.
fn decode_project_understanding(raw: &str) -> Result<(), String> {
    serde_json::from_str::<ProjectUnderstandingModel>(raw)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

// WORK_UNIT_CASE: 935/15
#[test]
fn project_understanding_refuses_an_unsupported_version_at_decode_too() {
    for found in ["project-understanding-v0", "project-understanding-v2", ""] {
        let raw = format!("{{\"schema_version\": \"{found}\"}}");
        let error = decode_project_understanding(&raw)
            .err()
            .unwrap_or_else(|| panic!("ProjectUnderstandingModel accepted `{found}`"));
        assert!(
            error.contains("project-understanding"),
            "the refusal must name the unsupported version, got {error}"
        );
    }
    // Non-vacuity: the supported version passes the gate and fails only on the
    // record's own shape.
    let raw = format!("{{\"schema_version\": \"{PROJECT_UNDERSTANDING_SCHEMA_VERSION}\"}}");
    let error = decode_project_understanding(&raw)
        .err()
        .unwrap_or_else(|| panic!("ProjectUnderstandingModel decoded from version alone"));
    assert!(
        error.contains("missing field"),
        "the supported version must reach the record's own missing fields, got {error}"
    );
}
