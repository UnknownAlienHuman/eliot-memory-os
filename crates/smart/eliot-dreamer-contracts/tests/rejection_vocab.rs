//! H2 rejection-vocabulary proof: the eight hub codes round-trip with the
//! exact A-05 wire spellings, stay contract-only (closed enum, `snake_case`,
//! `deny_unknown_fields`), and introduce no A-05 crate dependency.

#![allow(clippy::expect_used)]

use eliot_dreamer_contracts::{ContractViolation, CurationRejectionCode};

#[test]
fn all_eight_codes_round_trip_with_exact_a05_spellings() {
    // Pinned from `eliot-dreamer-candidate-validation/src/error.rs:17-34`
    // (A-05 `RejectionCode`): hub code, A-05 counterpart, shared wire spelling.
    let mapping: [(CurationRejectionCode, &str, &str); 8] = [
        (
            CurationRejectionCode::IdentityMismatch,
            "RejectionCode::IdentityMismatch",
            "identity_mismatch",
        ),
        (
            CurationRejectionCode::LineageMismatch,
            "RejectionCode::LineageMismatch",
            "lineage_mismatch",
        ),
        (
            CurationRejectionCode::UnsupportedPrecision,
            "RejectionCode::UnsupportedPrecision",
            "unsupported_precision",
        ),
        (
            CurationRejectionCode::BudgetExceeded,
            "RejectionCode::BudgetExceeded",
            "budget_exceeded",
        ),
        (
            CurationRejectionCode::DeadlineExceeded,
            "RejectionCode::DeadlineExceeded",
            "deadline_exceeded",
        ),
        (
            CurationRejectionCode::Cancelled,
            "RejectionCode::Cancelled",
            "cancelled",
        ),
        (
            CurationRejectionCode::PreservationFailed,
            "RejectionCode::PreservationFailed",
            "preservation_failed",
        ),
        (
            CurationRejectionCode::UnsupportedJobShape,
            "RejectionCode::UnsupportedJobShape",
            "unsupported_job_shape",
        ),
    ];
    assert_eq!(CurationRejectionCode::ALL.len(), 8);
    for (index, (code, counterpart, spelling)) in mapping.iter().enumerate() {
        assert_eq!(CurationRejectionCode::ALL[index], *code);
        assert_eq!(code.as_str(), *spelling);
        assert_eq!(code.a05_counterpart(), *counterpart);
        assert_eq!(
            CurationRejectionCode::parse(spelling).expect("known spelling"),
            *code
        );
        let wire = serde_json::to_string(code).expect("code serializes");
        assert_eq!(wire, format!("\"{spelling}\""));
        let back: CurationRejectionCode = serde_json::from_str(&wire).expect("code deserializes");
        assert_eq!(back, *code);
    }
    let mut wires: Vec<&str> = mapping.iter().map(|(_, _, spelling)| *spelling).collect();
    wires.sort_unstable();
    wires.dedup();
    assert_eq!(wires.len(), 8, "all eight wire spellings must differ");
}

#[test]
fn unknown_rejection_spellings_fail_closed() {
    for rejected in [
        "other",
        "",
        "IDENTITY_MISMATCH",
        "identity-mismatch",
        "blocked",
    ] {
        let err = CurationRejectionCode::parse(rejected).expect_err("must reject");
        assert_eq!(
            err,
            ContractViolation::UnknownVariant {
                field: "curation_rejection",
                value: rejected.to_owned(),
            }
        );
        let wire = format!("\"{rejected}\"");
        assert!(
            serde_json::from_str::<CurationRejectionCode>(&wire).is_err(),
            "serde must reject {rejected}"
        );
    }
}

#[test]
fn hub_carries_no_candidate_validation_dependency() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("manifest reads");
    for forbidden in [
        "eliot-dreamer-candidate-validation",
        "eliot_dreamer_candidate_validation",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml must not reference {forbidden}"
        );
    }
    for source in ["src/curation_invocation.rs", "src/rejection.rs"] {
        let text = std::fs::read_to_string(root.join(source)).expect("source reads");
        assert!(
            !text.contains("eliot_dreamer_candidate_validation"),
            "{source} must not use the A-05 crate"
        );
        // Doc comments state the exclusion explicitly; only code matters here.
        let code_hits: Vec<&str> = text
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !(trimmed.starts_with("//!") || trimmed.starts_with("//"))
            })
            .filter(|line| line.contains("DurableJob"))
            .collect();
        assert!(
            code_hits.is_empty(),
            "{source} must not reference DurableJob in code: {code_hits:?}"
        );
    }
}
