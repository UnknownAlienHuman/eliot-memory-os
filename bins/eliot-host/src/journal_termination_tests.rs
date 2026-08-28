//! Test-only Host journal termination/evidence oracle.
//!
//! Architecture anchors: A5.5 (verifier/evaluation contract), A13.2 (Host and
//! Kernel failure domains), and A13.8 (integrity anchors and exact identity).
//! Implementation anchors: I1.8 (identity, authority, and fence ownership),
//! I2.16 (focused tests in a complete workset), and I2.23 (cohesive ownership
//! boundaries).
//!
//! This module owns only the test oracle for exact prior-Kernel termination
//! evidence. It has no production, lifecycle, reconciliation, Phase-B, SCM,
//! semantic, or canonical authority; it must not mint authority or mutate
//! canonical state and is not production behavior.

use eliot_contracts::AuthorityEpoch;
use eliot_host_state::KernelJobBinding;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::{HealthVector, ServiceProcessRecord, ServiceProcessState};

use super::{TestResult, exact_termination_binding_matches};

#[test]
fn production_termination_binding_rejects_root_and_authority_substitution() -> TestResult {
    let job = KernelJobBinding {
        job_name: PlatformHandle::new("eliot-kernel-job")?,
        owner: PlatformHandle::new("Kernel")?,
        root_pid: 42,
        root_start_time_100ns: 10,
        root_image_path: PlatformHandle::new("C:\\eliot\\eliot-kernel.exe")?,
        root_volume_serial_number: 7,
        root_file_index: 11,
    };
    let process = ServiceProcessRecord {
        process_id: "pid:42:start:10".to_owned(),
        owner: "Kernel".to_owned(),
        state: ServiceProcessState::Starting,
        health: HealthVector::healthy(),
        authority_epoch: AuthorityEpoch::new(7)?,
    };
    let matches = |process_id, start_time, image, job_name, expected| {
        exact_termination_binding_matches(&job, expected, process_id, start_time, image, job_name)
    };
    assert!(matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        43,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        11,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\substituted.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "substituted-job",
        &process,
    ));

    let mut substituted_authority = process.clone();
    substituted_authority.owner = "Store".to_owned();
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &substituted_authority,
    ));
    let mut substituted_process_id = process.clone();
    substituted_process_id.process_id = "pid:99:start:10".to_owned();
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &substituted_process_id,
    ));
    Ok(())
}
