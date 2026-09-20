//! Kernel Blob Store demand-startup acceptance proof (issue #1969, I1.11 step 4).
//!
//! Smallest proof named under acceptance only: startup validates the approved
//! manifest without starting the process; the first large-payload demand
//! starts and probes the approved generation; a failed probe degrades only
//! large-payload capture, preserves inline work, and never fabricates a
//! canonical `BlobRef`. No fixture matrices, no test campaigns.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_kernel::{
    BlobCaptureOutcome, BlobDemand, BlobProbeStatus, BlobProbeSuccess, BlobReadyReceipt,
    BlobStoreManifest, KernelComposition, KernelConfig, BLOB_INLINE_THRESHOLD_DEFAULT_BYTES,
    BLOB_MANIFEST_FORMAT_VERSION,
};

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

fn temp_root(case: u32) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "eliot-1969-case{}-{}-{}",
        case,
        std::process::id(),
        unix_ms_now()
    ));
    std::fs::create_dir_all(dir.join(".eliot")).expect("test root");
    std::fs::create_dir_all(&dir).expect("test root");
    dir
}

fn test_manifest(root: &std::path::Path) -> BlobStoreManifest {
    BlobStoreManifest {
        data_root: root.join("blobs"),
        manifest_digest: "a".repeat(64),
        format_version: BLOB_MANIFEST_FORMAT_VERSION,
        inline_threshold_bytes: BLOB_INLINE_THRESHOLD_DEFAULT_BYTES,
        approved_generation: "blob-gen-approved-1969".to_owned(),
    }
}

fn test_probe() -> BlobProbeSuccess {
    BlobProbeSuccess {
        generation: "blob-gen-approved-1969".to_owned(),
        integrity_digest: "b".repeat(64),
    }
}

fn test_receipt(length: u64) -> BlobReadyReceipt {
    BlobReadyReceipt {
        residency_key_digest: "c".repeat(64),
        content_digest: "d".repeat(64),
        stored_length: length,
        operation_id: "op-1969".to_owned(),
        durable_generation: "blob-gen-approved-1969".to_owned(),
    }
}

fn composition_with_blob(case: u32) -> KernelComposition {
    let root = temp_root(case);
    let manifest = test_manifest(&root);
    let config = KernelConfig::new(root).with_blob_manifest(manifest);
    KernelComposition::new(config).expect("composition with approved blob manifest must build")
}

#[test]
fn startup_validates_manifest_without_starting_blob_process() {
    let kernel = composition_with_blob(1);
    assert!(
        kernel.blob_manifest_validated(),
        "startup must report the approved blob manifest as validated"
    );
    assert!(
        !kernel.blob_process_started(),
        "startup with no non-inline/recovery/GC demand must not start the blob process"
    );
    assert_eq!(
        kernel.blob_probe_status(),
        Some(BlobProbeStatus::ManifestValidated)
    );
}

#[test]
fn first_large_payload_demand_starts_and_probes_approved_generation() {
    let kernel = composition_with_blob(2);
    let status = kernel
        .demand_blob_store(BlobDemand::NonInlineCapture, || Ok(test_probe()))
        .expect("demand with approved manifest must record a probe outcome");
    assert_eq!(
        status,
        BlobProbeStatus::Ready {
            generation: "blob-gen-approved-1969".to_owned()
        }
    );
    assert!(
        kernel.blob_process_started(),
        "first large-payload demand must start the approved generation"
    );
    let large = 64 * 1024;
    let outcome = kernel.capture_blob_payload(large, Some(&test_receipt(large)));
    assert!(
        matches!(outcome, BlobCaptureOutcome::Canonical(_)),
        "ready generation plus durable receipt must yield a canonical BlobRef, got: {outcome:?}"
    );
}

#[test]
fn failed_probe_degrades_large_payload_only_without_fabricated_blobref() {
    let kernel = composition_with_blob(3);
    let status = kernel
        .demand_blob_store(BlobDemand::Recovery, || {
            Err("blob probe transport unavailable".to_owned())
        })
        .expect("failed probe must record degradation, not fail the demand call");
    assert!(
        matches!(status, BlobProbeStatus::Degraded { .. }),
        "failed probe must degrade, got: {status:?}"
    );
    assert!(
        kernel.blob_process_started(),
        "first demand must have started the probe attempt"
    );
    assert!(
        matches!(
            kernel.capture_blob_payload(16, None),
            BlobCaptureOutcome::Inline { length: 16 }
        ),
        "inline work must remain available while degraded"
    );
    let large = 64 * 1024;
    let outcome = kernel.capture_blob_payload(large, Some(&test_receipt(large)));
    assert!(
        matches!(outcome, BlobCaptureOutcome::DegradedLargePayload { .. }),
        "large capture must report degraded availability, got: {outcome:?}"
    );
    assert!(
        kernel.blob_canonical_ref(&test_receipt(large)).is_err(),
        "no response may contain a canonical BlobRef for data not durably accepted"
    );
}
