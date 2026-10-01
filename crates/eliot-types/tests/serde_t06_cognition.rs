//! #935 T06 owner version-selection tests.
//!
//! `deny_unknown_fields` closes record shape but never checks `schema_version`:
//! a foreign or future layout that happens to deserialize into the current fields
//! is still not current data. These tests prove the owner validation step that
//! every real authority/evidence consumer must apply first:
//! `cognitive_run_schema_selection` / `require_current_cognitive_run_schema` for
//! the five schema-bearing cognitive-run records, and
//! `project_understanding_schema_selection` / `ProjectUnderstandingModel::admission`
//! for project understanding.
//!
//! Fixtures live in `tests/data/serde_t06_cognition.json`, one raw positive and one
//! raw foreign-version negative per record type. The negatives decode structurally
//! on purpose: that successful decode IS the reported defect (shape-blindness),
//! and the paired assertion is that the owner validator refuses the decoded value
//! before any authority field may be consumed.
//!
//! Out of scope here, deliberately unproven: lexical duplicate-key rejection and
//! the strict-reader ingress contour (owner path repaired under #2985, kept
//! unchanged by this delivery), the full 16-case acceptance suite (TEST-PHASE),
//! and store-backed decoder wrappers in `eliot-app` / `eliot-engine`, which
//! delegate their whole version decision to the validators proven here.

use eliot_types::cognitive_run::{
    CognitiveRunSchemaVersioned, cognitive_run_schema_selection,
    require_current_cognitive_run_schema,
};
use eliot_types::project_understanding::project_understanding_schema_selection;
use eliot_types::{
    COGNITIVE_RUN_SCHEMA_VERSION, CognitiveRawVerifierEvidence, CognitiveRunAttempt,
    CognitiveRunContract, CognitiveRunTerminal, CognitiveToolObservation,
    PROJECT_UNDERSTANDING_SCHEMA_VERSION, ProjectUnderstandingModel,
};
use serde_json::Value;
use std::path::Path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn corpus() -> Result<Value, Box<dyn std::error::Error>> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/serde_t06_cognition.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn raw_fixture(corpus: &Value, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    corpus
        .get(name)
        .ok_or_else(|| std::io::Error::other(format!("corpus is missing fixture {name}")))
        .and_then(|fixture| serde_json::to_string(fixture).map_err(Into::into))
}

fn require_current<T>(raw: &str) -> Result<&'static str, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned + CognitiveRunSchemaVersioned,
{
    let record: T = serde_json::from_str(raw)?;
    require_current_cognitive_run_schema(&record).map_err(Into::into)
}

// WORK_UNIT_CASE: 935/9
#[test]
fn run_schema_selection_admits_only_the_current_owner_version() -> TestResult {
    assert_eq!(
        cognitive_run_schema_selection(COGNITIVE_RUN_SCHEMA_VERSION),
        Some(COGNITIVE_RUN_SCHEMA_VERSION)
    );
    // No supported legacy is recorded anywhere in the repository: the only
    // emitted literal is `COGNITIVE_RUN_SCHEMA_VERSION`, so even the
    // plausible-looking predecessor name is refused rather than migrated.
    for foreign in [
        "",
        "v2",
        "eliot-cognitive-run-v1",
        "eliot-cognitive-run-v3",
        "ELIOT-COGNITIVE-RUN-V2",
        " eliot-cognitive-run-v2",
    ] {
        assert_eq!(
            cognitive_run_schema_selection(foreign),
            None,
            "owner selection must refuse {foreign:?}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 935/7
#[test]
fn current_run_records_decode_and_pass_owner_selection() -> TestResult {
    let corpus = corpus()?;
    let attempt: CognitiveRunAttempt =
        serde_json::from_str(&raw_fixture(&corpus, "cognitive_run_attempt")?)?;
    assert_eq!(
        require_current_cognitive_run_schema(&attempt)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    let terminal: CognitiveRunTerminal =
        serde_json::from_str(&raw_fixture(&corpus, "cognitive_run_terminal")?)?;
    assert_eq!(
        require_current_cognitive_run_schema(&terminal)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    let observation: CognitiveToolObservation =
        serde_json::from_str(&raw_fixture(&corpus, "cognitive_tool_observation")?)?;
    assert_eq!(
        require_current_cognitive_run_schema(&observation)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    let evidence: CognitiveRawVerifierEvidence = serde_json::from_str(&raw_fixture(
        &corpus,
        "cognitive_raw_verifier_evidence",
    )?)?;
    assert_eq!(
        require_current_cognitive_run_schema(&evidence)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    let contract: CognitiveRunContract =
        serde_json::from_str(&raw_fixture(&corpus, "cognitive_run_contract")?)?;
    assert_eq!(
        require_current_cognitive_run_schema(&contract)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    assert_eq!(
        require_current::<CognitiveRunAttempt>(&raw_fixture(&corpus, "cognitive_run_attempt")?)?,
        COGNITIVE_RUN_SCHEMA_VERSION
    );
    Ok(())
}

// WORK_UNIT_CASE: 935/8
#[test]
fn foreign_run_records_decode_but_fail_owner_selection() -> TestResult {
    let corpus = corpus()?;
    for (name, kind) in [
        ("cognitive_run_contract_foreign_version", "cognitive_run_contract"),
        ("cognitive_run_attempt_foreign_version", "cognitive_run_attempt"),
        ("cognitive_run_terminal_foreign_version", "cognitive_run_terminal"),
        (
            "cognitive_tool_observation_foreign_version",
            "cognitive_tool_observation",
        ),
        (
            "cognitive_raw_verifier_evidence_foreign_version",
            "cognitive_raw_verifier",
        ),
    ] {
        let raw = raw_fixture(&corpus, name)?;
        // Structural decode succeeds: deny_unknown_fields is version-blind.
        // The owner step below is what refuses the record as current data.
        let mismatch = match kind {
            "cognitive_run_contract" => {
                let record: CognitiveRunContract = serde_json::from_str(&raw)?;
                require_current_cognitive_run_schema(&record).unwrap_err()
            }
            "cognitive_run_attempt" => {
                let record: CognitiveRunAttempt = serde_json::from_str(&raw)?;
                require_current_cognitive_run_schema(&record).unwrap_err()
            }
            "cognitive_run_terminal" => {
                let record: CognitiveRunTerminal = serde_json::from_str(&raw)?;
                require_current_cognitive_run_schema(&record).unwrap_err()
            }
            "cognitive_tool_observation" => {
                let record: CognitiveToolObservation = serde_json::from_str(&raw)?;
                require_current_cognitive_run_schema(&record).unwrap_err()
            }
            _ => {
                let record: CognitiveRawVerifierEvidence = serde_json::from_str(&raw)?;
                require_current_cognitive_run_schema(&record).unwrap_err()
            }
        };
        assert_eq!(mismatch.record_kind, kind, "fixture {name}");
        assert_eq!(mismatch.declared_version, "eliot-cognitive-run-v1");
        assert_eq!(mismatch.supported_version, COGNITIVE_RUN_SCHEMA_VERSION);
    }
    Ok(())
}

// WORK_UNIT_CASE: 935/15
#[test]
fn owner_refusal_precedes_any_authority_consumption() -> TestResult {
    let corpus = corpus()?;
    let raw = raw_fixture(&corpus, "cognitive_run_attempt_foreign_version")?;
    let attempt: CognitiveRunAttempt = serde_json::from_str(&raw)?;
    // The candidate-submit path consumes `status`, `capability` and
    // `candidate_write_id` as authority. The refusal must land first: no
    // authority field may be read before this check passes.
    let refusal = require_current_cognitive_run_schema(&attempt).unwrap_err();
    let message = refusal.to_string();
    assert!(
        message.contains("cognitive_run_attempt")
            && message.contains("eliot-cognitive-run-v1")
            && message.contains(COGNITIVE_RUN_SCHEMA_VERSION),
        "refusal must name the kind, the declared version and the supported version: {message}"
    );
    Ok(())
}

// WORK_UNIT_CASE: 935/7
#[test]
fn admitted_project_understanding_passes_owner_admission() -> TestResult {
    let corpus = corpus()?;
    let model: ProjectUnderstandingModel =
        serde_json::from_str(&raw_fixture(&corpus, "project_understanding_model")?)?;
    assert_eq!(
        model.admission(),
        Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
    );
    // Absent acceptance/causal lists are `unknown`, not false claims: the owner
    // boundary refuses claims of satisfaction without a record, not empty
    // knowledge, so the absent-lists fixture is still admitted here while no
    // downstream consumer may read it as completeness.
    let absent: ProjectUnderstandingModel = serde_json::from_str(&raw_fixture(
        &corpus,
        "project_understanding_model_absent_lists",
    )?)?;
    assert_eq!(
        absent.admission(),
        Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
    );
    Ok(())
}

// WORK_UNIT_CASE: 935/8
#[test]
fn unadmitted_project_understanding_fails_owner_admission() -> TestResult {
    let corpus = corpus()?;
    for name in [
        "project_understanding_model_foreign_version",
        "project_understanding_model_empty_verifier_ref",
        "project_understanding_model_verified_hop_without_evidence",
    ] {
        // Each refusal fixture still decodes structurally: shape closure is not
        // semantic selection, so admission must fail on the decoded value.
        let model: ProjectUnderstandingModel =
            serde_json::from_str(&raw_fixture(&corpus, name)?)?;
        assert_eq!(model.admission(), None, "fixture {name} must not be admitted");
    }
    let foreign: ProjectUnderstandingModel = serde_json::from_str(&raw_fixture(
        &corpus,
        "project_understanding_model_foreign_version",
    )?)?;
    assert_eq!(foreign.schema_selection(), None);
    Ok(())
}

// WORK_UNIT_CASE: 935/9
#[test]
fn understanding_selection_admits_only_the_current_owner_version() -> TestResult {
    assert_eq!(
        project_understanding_schema_selection(PROJECT_UNDERSTANDING_SCHEMA_VERSION),
        Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
    );
    for foreign in [
        "",
        "v1",
        "project-understanding-v0",
        "project-understanding-v2",
        "PROJECT-UNDERSTANDING-V1",
    ] {
        assert_eq!(
            project_understanding_schema_selection(foreign),
            None,
            "owner selection must refuse {foreign:?}"
        );
    }
    Ok(())
}
