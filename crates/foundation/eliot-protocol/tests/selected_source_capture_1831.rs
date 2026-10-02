//! Closed-wire acceptance for one-shot selected-source capture requests.
//!
//! This covers protocol serialization and refusal boundaries only; it does
//! not assert that a request passed the original Kernel/Governor owner path.
//!
//! Docs route `sha256:63ff31555e625ef8901dba3e1321c1f9af9e5ef43a9a71fa216486d794c86dd8`,
//! read `sha256:33bb06ee7117e508fbbf976c7457b6174f7d2aac233c1815fe70d36be4391d73`,
//! verified bundle `sha256:3cc9a469fc9937b73a7a10af7b1196bb0fd67a3d51815be202e893aacbfe3d3d`.
//! Matched routes: `generic-source`, `host-kernel`, `instrument-verification`; the
//! full 77-item/19-family required-fragment path and SHA list is in
//! `C:\Development\Rust\projects\eliot-swarm\CS2-1831-R19\.eliot\docs-read-receipt.json`
//! (SHA-256 `eb6c7fcc8d172fc7fddf75e55e4ceef70db8f3905af1bab3ffae8af677c6586e`).
//! I read the verified required items, including I10.8 and I10.10, before edits.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_protocol::{
    SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID, SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION,
    SelectedSourceCaptureInvocation, SelectedSourceCaptureOperation,
};
use serde_json::json;

fn invocation(
    operation: SelectedSourceCaptureOperation,
    selected_relative_path: &str,
    selector: Option<&str>,
) -> SelectedSourceCaptureInvocation {
    SelectedSourceCaptureInvocation {
        wire_id: SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID.to_owned(),
        wire_version: SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION,
        operation,
        selected_relative_path: selected_relative_path.to_owned(),
        selector: selector.map(str::to_owned),
    }
}

#[test]
fn legacy_diagnostics_and_probe_version_keep_the_v1_unit_wire() {
    for (operation, wire) in [
        (
            SelectedSourceCaptureOperation::Diagnostics,
            json!("DIAGNOSTICS"),
        ),
        (
            SelectedSourceCaptureOperation::ProbeVersion,
            json!("PROBE_VERSION"),
        ),
    ] {
        assert_eq!(
            serde_json::to_value(&operation).expect("encode v1 operation"),
            wire
        );
        assert_eq!(
            serde_json::from_value::<SelectedSourceCaptureOperation>(wire)
                .expect("decode v1 operation"),
            operation
        );

        let request = invocation(operation, "src/lib.rs", None);
        let encoded = serde_json::to_value(&request).expect("encode v1 invocation");
        assert_eq!(
            serde_json::from_value::<SelectedSourceCaptureInvocation>(encoded)
                .expect("decode v1 invocation"),
            request
        );
    }
}

#[test]
fn semantic_operation_arguments_round_trip_without_loss() {
    let cases = [
        (
            SelectedSourceCaptureOperation::Definitions {
                symbol: "rust-analyzer cargo probe 0.1.0 crate::definition().".to_owned(),
            },
            json!({
                "DEFINITIONS": {
                    "symbol": "rust-analyzer cargo probe 0.1.0 crate::definition()."
                }
            }),
        ),
        (
            SelectedSourceCaptureOperation::References {
                symbol: "rust-analyzer cargo probe 0.1.0 crate::caller().".to_owned(),
            },
            json!({
                "REFERENCES": {
                    "symbol": "rust-analyzer cargo probe 0.1.0 crate::caller()."
                }
            }),
        ),
        (SelectedSourceCaptureOperation::Symbols, json!("SYMBOLS")),
        (
            SelectedSourceCaptureOperation::RenameCandidate {
                symbol: "rust-analyzer cargo probe 0.1.0 crate::rename_me().".to_owned(),
                new_name: "renamed_symbol".to_owned(),
            },
            json!({
                "RENAME_CANDIDATE": {
                    "symbol": "rust-analyzer cargo probe 0.1.0 crate::rename_me().",
                    "new_name": "renamed_symbol"
                }
            }),
        ),
    ];

    for (operation, expected_wire) in cases {
        let encoded = serde_json::to_value(&operation).expect("encode semantic operation");
        assert_eq!(encoded, expected_wire);
        assert_eq!(
            serde_json::from_value::<SelectedSourceCaptureOperation>(encoded)
                .expect("decode semantic operation"),
            operation
        );

        let request = invocation(operation, "src/lib.rs", Some("selected-candidate-7"));
        let encoded = serde_json::to_value(&request).expect("encode semantic invocation");
        assert_eq!(
            serde_json::from_value::<SelectedSourceCaptureInvocation>(encoded)
                .expect("decode semantic invocation"),
            request
        );
    }
}

#[test]
fn executable_configuration_and_unknown_operation_fields_are_closed_out() {
    let request = invocation(
        SelectedSourceCaptureOperation::Definitions {
            symbol: "crate::meaning".to_owned(),
        },
        "src/lib.rs",
        None,
    );
    let encoded = serde_json::to_value(&request).expect("encode request");
    assert!(encoded.get("executable").is_none());
    assert!(encoded.get("config").is_none());

    for field in ["executable", "config"] {
        let mut injected = encoded.clone();
        injected[field] = json!({"untrusted": true});
        assert!(
            serde_json::from_value::<SelectedSourceCaptureInvocation>(injected).is_err(),
            "top-level {field} injection must be rejected"
        );
    }

    let operation_with_unknown_argument = json!({
        "DEFINITIONS": {
            "symbol": "crate::meaning",
            "workspace_root": "C:/foreign/workspace"
        }
    });
    assert!(
        serde_json::from_value::<SelectedSourceCaptureOperation>(operation_with_unknown_argument)
            .is_err()
    );

    let rename_with_applied_claim = json!({
        "RENAME_CANDIDATE": {
            "symbol": "crate::meaning",
            "new_name": "renamed",
            "applied": true
        }
    });
    assert!(
        serde_json::from_value::<SelectedSourceCaptureOperation>(rename_with_applied_claim)
            .is_err()
    );

    let unknown_operation = json!("APPLY_RENAME");
    assert!(serde_json::from_value::<SelectedSourceCaptureOperation>(unknown_operation).is_err());
}

#[test]
fn selected_path_rejects_traversal_and_foreign_root_forms() {
    for path in [
        "../src/lib.rs",
        "src/../lib.rs",
        "src/./lib.rs",
        "src//lib.rs",
        "/workspace/src/lib.rs",
        "C:\\workspace\\src\\lib.rs",
        "\\\\server\\share\\workspace\\src\\lib.rs",
    ] {
        let request = invocation(SelectedSourceCaptureOperation::Diagnostics, path, None);
        assert!(
            request.validate().is_err(),
            "path should be refused: {path}"
        );
    }

    let normalized = invocation(
        SelectedSourceCaptureOperation::Diagnostics,
        "src/lib.rs",
        Some("selected-candidate-7"),
    );
    assert!(normalized.validate().is_ok());
}

#[test]
fn invocation_identity_and_selector_bounds_are_enforced() {
    let mut request = invocation(SelectedSourceCaptureOperation::Symbols, "src/lib.rs", None);
    request.wire_id = "eliot.protocol.foreign-capture-invocation".to_owned();
    assert!(request.validate().is_err());

    let mut request = invocation(SelectedSourceCaptureOperation::Symbols, "src/lib.rs", None);
    request.wire_version = SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION + 1;
    assert!(request.validate().is_err());

    let request = invocation(
        SelectedSourceCaptureOperation::Symbols,
        "src/lib.rs",
        Some(" "),
    );
    assert!(request.validate().is_err());

    let too_long = "s".repeat(513);
    let request = invocation(
        SelectedSourceCaptureOperation::Symbols,
        "src/lib.rs",
        Some(&too_long),
    );
    assert!(request.validate().is_err());
}
