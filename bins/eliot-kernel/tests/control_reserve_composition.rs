//! Kernel composition control-reserve wiring proofs (issue #1679 W2/A1).
//!
//! Both cases drive the ALREADY LANDED production path and nothing else: a
//! real `KernelComposition::new(KernelConfig::new(&root))`, which compiles the
//! control-reserve profile inside `assemble`
//! (`bins/eliot-kernel/src/composition_bootstrap.rs`) from its resolved
//! Authority Epoch, generation, approved config hash and clock. No compiler
//! function is called directly: the profile under test is the one the running
//! composition retained.
//!
//! Owner adapters publish evidence (`ControlReserve::publish_owner_row`,
//! `OrsReserve::publish_owner_rows`, `StoreReserve::publish_claimed_row`,
//! `IpcReserve::publish_claimed_row`), but no reserve instance exists at
//! assembly, so the composition joins zero records. The closed answers are
//! therefore fifteen explicit `UNKNOWN` rows, never a value described from
//! a neighbouring owner's numbers. A case asserting claimed capacity here
//! would fabricate evidence no live reserve has published at assembly.

use eliot_kernel::{KernelComposition, KernelConfig};
use eliot_runtime_contracts::BottleneckCoverageState;

/// Guard holding the isolated work root; removed when the case ends.
struct TempGuard {
    root: std::path::PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what}: {error}"),
    }
}

/// Builds one isolated `KernelComposition` over its own work root and its own
/// pipe, mirroring the backup suites' `test_kernel_with_pipe`.
///
/// The root is unique per (case, process, nanosecond) so parallel test
/// threads never collide, and the composition is returned alongside the guard
/// so the caller controls when the root disappears.
fn test_kernel_with_pipe(case: &str) -> (KernelComposition, TempGuard) {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let root =
        std::env::temp_dir().join(format!("eliot-1679-{case}-{}-{nanos}", std::process::id()));
    must(std::fs::create_dir_all(&root), "create work root");
    let mut config = KernelConfig::new(&root);
    config.pipe_name = format!(r"\\.\pipe\eliot\kernel-1679-{case}-{}", std::process::id());
    let kernel = must(KernelComposition::new(config), "kernel composition");
    (kernel, TempGuard { root })
}

/// W2/A1: the composition retains exactly the 15-row denominator profile the
/// frozen validator accepts, compiled under its own product identity. With no
/// owner evidence published every row is an explicit `UNKNOWN` with its
/// guarantee named in the lowered set - fail closed, not fabricated.
#[test]
fn composition_compiles_fifteen_unknown_row_profile() {
    let (kernel, _guard) = test_kernel_with_pipe("w2-profile");
    let profile = kernel.control_reserve_profile();
    must(profile.validate(), "retained profile validates");
    assert_eq!(
        profile.bottleneck_rows.len(),
        15,
        "profile carries exactly the frozen 15-row denominator"
    );
    assert!(
        profile
            .bottleneck_rows
            .iter()
            .all(|row| row.coverage_state == BottleneckCoverageState::Unknown),
        "zero owner records joined, so every dimension is an explicit UNKNOWN row"
    );
    assert_eq!(
        profile.unsupported_or_unknown_guarantees.len(),
        15,
        "every lowered guarantee is named"
    );
    assert_eq!(profile.product_identity_ref, "eliot-kernel");
    assert_eq!(profile.profile_id, "eliot-kernel-control-reserve-profile");
}

/// W2: the status projection reads the retained profile - fifteen rows in the
/// profile's own order, every guarantee lowered, carrying the profile's own
/// lowered-guarantee names without re-deriving them.
#[test]
fn composition_projects_bounded_status_snapshot() {
    let (kernel, _guard) = test_kernel_with_pipe("w2-status");
    let profile = kernel.control_reserve_profile();
    let snapshot = must(kernel.control_reserve_status(), "status projection");
    assert_eq!(snapshot.rows.len(), 15);
    assert_eq!(snapshot.rows.len(), profile.bottleneck_rows.len());
    for (row, compiled) in snapshot.rows.iter().zip(profile.bottleneck_rows.iter()) {
        assert_eq!(
            row.row.bottleneck, compiled.bottleneck,
            "status rows follow the profile's own order"
        );
        assert!(
            row.guarantee_lowered,
            "every guarantee is lowered while no owner evidence is published"
        );
    }
    assert_eq!(
        snapshot.lowered_guarantees,
        profile.unsupported_or_unknown_guarantees
    );
    assert_eq!(snapshot.profile_id, profile.profile_id);
    assert_eq!(snapshot.profile_revision, profile.profile_revision);
}

/// W2: the profile carries the composition's own resolved identity
/// scalars - the standalone assembly name when no Host-approved
/// config hash exists, the revision bound to the admitted
/// generation, the composition's own clock reading and the resolved
/// runtime generation ref - never defaults.
#[test]
fn composition_profile_carries_standalone_assembly_identity() {
    let (kernel, _guard) = test_kernel_with_pipe("w2-identity");
    let profile = kernel.control_reserve_profile();
    assert_eq!(
        profile.config_snapshot_ref, "eliot-kernel-standalone",
        "the test config carries no Host-approved hash, so the composition names the standalone assembly"
    );
    assert!(
        profile.profile_revision.contains("generation="),
        "the revision is bound to the admitted generation"
    );
    assert!(
        profile.compiled_at_ms > 0,
        "the composition's own clock reading, never a default"
    );
    assert!(
        !profile.source_build_and_runtime_generation_refs.is_empty(),
        "the resolved runtime generation ref is present"
    );
}
