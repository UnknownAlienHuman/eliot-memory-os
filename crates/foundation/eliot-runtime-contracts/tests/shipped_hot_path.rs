//! Regression proof for the actual declarations embedded by the two services.
//! Loading is not an installed-runtime or hot-path measurement claim (#4042).

use std::error::Error;
use std::path::Path;

use eliot_runtime_contracts::{
    HotPathDegradation, HotPathManifestFileError, HotPathProfileRef, admit_hot_path_manifest,
};

const KERNEL: &str = include_str!("../../../../bins/eliot-kernel/hot-path.toml");
const DAEMON: &str = include_str!("../../../../bins/eliotd/hot-path.toml");
// #2564: the daemon also declares the retained `eliot.state` legs, so the two
// services no longer share one operation set. Each service asserts its own.
const KERNEL_OPERATIONS: [&str; 3] = ["local_read_claim", "local_read", "local_read_result"];
const DAEMON_OPERATIONS: [&str; 5] = [
    "local_read_claim",
    "local_state_claim",
    "local_read",
    "local_read_result",
    "local_state_result",
];

fn assert_shipped_manifest(
    service: &str,
    text: &str,
    items: u64,
    operations: &[&str],
) -> Result<(), Box<dyn Error>> {
    let admitted = admit_hot_path_manifest(Path::new(service), text.as_bytes())?;
    assert_eq!(admitted.set.owning_service, service);
    assert_eq!(
        admitted.manifest_file_digest,
        eliot_contracts::sha256_hex(text.as_bytes())
    );
    assert_eq!(admitted.set.supported_operations.len(), operations.len());
    for operation in operations {
        let operation = *operation;
        let row = admitted.operation(operation)?;
        assert_eq!(row.owning_service, service);
        assert_eq!(row.hot_path_profile_ref, HotPathProfileRef::default());
        assert_eq!(row.queues_and_capacity.len(), 1);
        let bounds = admitted.queue_bounds(operation, operation)?;
        assert_eq!(bounds.max_items, Some(items));
        let expected_bytes = if service == "eliot-kernel" && operation == "local_read_claim" {
            8 * 1024 * 1024
        } else {
            4 * 1024 * 1024
        };
        assert_eq!(bounds.max_bytes, Some(expected_bytes));
        assert_eq!(bounds.max_deadline_ms, Some(30_000));
        assert_eq!(
            bounds.max_in_flight_items,
            (service == "eliotd").then_some(1)
        );
        match operation {
            "local_read" => {
                assert_eq!(row.synchronous_external_calls.len(), 1);
                assert!(
                    matches!(&row.fallback_or_degradation, HotPathDegradation::Handle { handle_ref } if handle_ref == "host_request_result_body")
                );
            }
            "local_read_claim" => {
                assert!(row.synchronous_external_calls.is_empty());
                assert_eq!(row.fallback_or_degradation, HotPathDegradation::Unknown);
            }
            "local_read_result" => {
                assert!(row.synchronous_external_calls.is_empty());
                assert!(
                    matches!(&row.fallback_or_degradation, HotPathDegradation::RecoveryDirective { directive_ref } if directive_ref == "eliot_runtime_contracts::RecoveryDirective")
                );
            }
            // #2564: the state legs are bounded and synchronous-free exactly
            // like their query siblings - one queue, one in-flight item, the
            // 4 MiB byte bound, the 30 s front-door deadline. The claim carries
            // the same `host_request_result_body` handle as the query claim
            // because a partial or unavailable owner verdict is still
            // submitted as a retained record; the result leg carries the same
            // recovery directive as the query result.
            "local_state_claim" => {
                assert!(row.synchronous_external_calls.is_empty());
                assert!(
                    matches!(&row.fallback_or_degradation, HotPathDegradation::Handle { handle_ref } if handle_ref == "host_request_result_body")
                );
            }
            "local_state_result" => {
                assert!(row.synchronous_external_calls.is_empty());
                assert!(
                    matches!(&row.fallback_or_degradation, HotPathDegradation::RecoveryDirective { directive_ref } if directive_ref == "eliot_runtime_contracts::RecoveryDirective")
                );
            }
            _ => unreachable!("closed test operation set"),
        }
    }
    assert_eq!(admitted.set.unsupported_operations.len(), 2);
    Ok(())
}

#[test]
fn shipped_kernel_manifest_loads() -> Result<(), Box<dyn Error>> {
    assert_shipped_manifest("eliot-kernel", KERNEL, 64, &KERNEL_OPERATIONS)?;
    let admitted = admit_hot_path_manifest(Path::new("eliot-kernel"), KERNEL.as_bytes())?;
    let claim = admitted.operation("local_read_claim")?;
    let snapshots = &claim.immutable_snapshot_dependencies;
    assert_eq!(snapshots.len(), 2);
    for dimension in ["authority_epoch", "resource_generation"] {
        let identity = format!("session_state_fence.{dimension}");
        assert!(
            snapshots
                .iter()
                .any(|row| row.snapshot_id == identity && row.revision_key == identity)
        );
    }
    Ok(())
}

#[test]
fn shipped_daemon_manifest_loads() -> Result<(), Box<dyn Error>> {
    assert_shipped_manifest("eliotd", DAEMON, 1, &DAEMON_OPERATIONS)
}

#[test]
fn protected_operation_fields_cannot_be_missing_misnested_or_duplicated()
-> Result<(), Box<dyn Error>> {
    for text in [KERNEL, DAEMON] {
        // Confirm a valid starting point, so a broken fixture cannot pass every refusal.
        admit_hot_path_manifest(Path::new("shipped"), text.as_bytes())?;
        for field in [
            "synchronous_external_calls",
            "fallback_or_degradation",
            "hot_path_profile_ref",
        ] {
            let line = text
                .lines()
                .find(|line| line.starts_with(&format!("{field} = ")))
                .ok_or("the shipped first operation must carry the protected field")?;
            let line = format!("{line}\n");
            let removed = text.replacen(&line, "", 1);
            let marker = "[[supported_operations.queues_and_capacity]]\n";
            assert!(removed.contains(marker));
            let misnested = removed.replacen(marker, &format!("{marker}{line}"), 1);
            let duplicated = text.replacen(&line, &format!("{line}{line}"), 1);
            for malformed in [removed, misnested, duplicated] {
                assert!(
                    matches!(
                        admit_hot_path_manifest(Path::new("mutated"), malformed.as_bytes()),
                        Err(HotPathManifestFileError::Malformed { .. })
                    ),
                    "field={field}"
                );
            }
        }
        let unknown = text.replacen(
            "[[supported_operations]]\n",
            "[[supported_operations]]\nundeclared_authority = true\n",
            1,
        );
        assert!(matches!(
            admit_hot_path_manifest(Path::new("mutated"), unknown.as_bytes()),
            Err(HotPathManifestFileError::Malformed { .. })
        ));
    }
    Ok(())
}

#[test]
fn repeated_snapshot_identity_is_still_rejected() -> Result<(), Box<dyn Error>> {
    admit_hot_path_manifest(Path::new("eliot-kernel"), KERNEL.as_bytes())?;
    let changed = KERNEL.replacen(
        "snapshot_id = \"session_state_fence.resource_generation\"",
        "snapshot_id = \"session_state_fence.authority_epoch\"",
        1,
    );
    assert_ne!(changed, KERNEL);
    assert!(matches!(
        admit_hot_path_manifest(Path::new("mutated"), changed.as_bytes()),
        Err(HotPathManifestFileError::Contract(_))
    ));
    Ok(())
}
