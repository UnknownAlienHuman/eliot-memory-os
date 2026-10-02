//! Refusal proof for the owned provider kill-on-close Job (#1888, K-STORE).
//!
//! `BATCH.md` acceptance: "A refusal test: assignment fails, so the launch
//! fails with a typed error and no provider is left running."
//!
//! Two tests, both driving real production functions and asserting typed
//! values only — never message strings:
//!
//! 1. [`assign_process_refuses_pid_zero_with_typed_launch_refusal`] drives the
//!    launch path's own assignment step — `ProviderKillDomain::create` then
//!    `ProviderKillDomain::admit`, which is exactly what
//!    `spawn_provider_kill_on_close` reaches through `admit_spawned` — with the
//!    documented pid-0 refusal, and asserts the typed
//!    `AdapterError::LaunchJobAssignmentFailed` carrying
//!    `WindowsAdapterError::InvalidInput`.
//!
//! 2. [`refused_launch_reaps_provider_and_returns_typed_refusal`] drives the
//!    whole real launch path, `spawn_provider_kill_on_close`, against a genuine
//!    spawned `surreal.exe` provider. Admission is refused, and the test proves
//!    both halves of the contract: a typed refusal is returned, and the
//!    already-spawned provider is terminated and reaped by the launch path
//!    itself, so no provider is left running.
//!
//! Why test 1 drives `admit` directly rather than reaching pid 0 through
//! `admit_spawned`: `admit_spawned` filters pid 0 out *before* calling
//! `assign_process` and answers `AdapterError::Config`, so it cannot produce
//! the typed job-admission refusal. `admit` is the step that calls
//! `assign_process`, and `assign_process` is where the documented
//! `InvalidInput` refusal for pid 0 originates
//! (`crates/kernel/eliot-platform-windows/src/process_job.rs:494`).
#![cfg(windows)]

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eliot_platform_windows::{WindowsAdapterError, WindowsPlatform};
use eliot_store_surreal_adapter::{
    AdapterError, ProviderKillDomain, reap_refused_std_child, refusal_cause,
    spawn_provider_kill_on_close,
};

type RefusalResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Interval at which liveness is re-read from the operating system.
const LIVENESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The pinned provider artifact every suite in this crate launches.
const PINNED_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";

/// Copies the pinned `surreal.exe` into a private sandbox so the spawned
/// provider is the genuine provider artifact.
fn provider_image(sandbox: &Path) -> PathBuf {
    let pinned = std::env::var_os("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|| PathBuf::from(PINNED_SURREAL_EXE), PathBuf::from);
    let copied = sandbox.join("surreal.exe");
    std::fs::copy(&pinned, &copied).unwrap_or_else(|error| {
        panic!(
            "pinned provider {} must copy into the sandbox: {error}",
            pinned.display()
        )
    });
    copied
}

/// The argv that keeps the spawned provider serving for the observation window.
///
/// `memory` storage and the default bind keep this proof free of any
/// `SurrealKV` data root, so it claims nothing about storage engine limits.
fn provider_arguments() -> Vec<String> {
    vec![
        "start".to_owned(),
        "--no-banner".to_owned(),
        "--log".to_owned(),
        "error".to_owned(),
        "--deny-all".to_owned(),
        "--deny-net".to_owned(),
        "--".to_owned(),
        "memory".to_owned(),
    ]
}

/// Per-test sandbox directory, removed on drop.
struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "eliot-1888-refusal-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("refusal sandbox must create: {error}"));
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _remove_result = std::fs::remove_dir_all(&self.0);
    }
}

/// True while Windows still reports `process_id` as a live process.
fn provider_is_running(process_id: u32) -> bool {
    let platform = WindowsPlatform::new(std::env::temp_dir())
        .unwrap_or_else(|error| panic!("platform: {error}"));
    platform.process_identity(process_id).is_ok()
}

/// Polls the operating system until it reports `process_id` absent.
///
/// `BATCH.md` acceptance requires the provider pid to be "gone within a bounded
/// wait" but names no number for that bound anywhere in the issue text or the
/// docs, so none is invented: the assertion is exactly "the provider pid is
/// gone, polled until the OS reports it absent". The loop returns only on a
/// positive absence observation.
fn poll_until_absent(process_id: u32) -> bool {
    let platform = WindowsPlatform::new(std::env::temp_dir())
        .unwrap_or_else(|error| panic!("platform: {error}"));
    loop {
        if platform.process_identity(process_id).is_err() {
            return true;
        }
        std::thread::sleep(LIVENESS_POLL_INTERVAL);
    }
}

/// The documented pid-0 `assign_process` refusal surfaces as the typed launch
/// refusal, and admission never yields a usable kill domain.
#[test]
fn assign_process_refuses_pid_zero_with_typed_launch_refusal() -> RefusalResult {
    let refusal = ProviderKillDomain::create()
        .and_then(|domain| domain.admit(0))
        .expect_err("assign_process must refuse process id 0");

    assert_eq!(
        refusal_cause(&refusal),
        Some(WindowsAdapterError::InvalidInput),
        "the refusal cause must be the typed InvalidInput, not prose"
    );
    assert!(
        matches!(refusal, AdapterError::LaunchJobAssignmentFailed { .. }),
        "assignment failure must surface as the typed LaunchJobAssignmentFailed"
    );

    // A refused admission must not yield an admitted kill domain: the launch
    // path has no unassigned fallback to reach for.
    let admitted = ProviderKillDomain::create().and_then(|domain| domain.admit(0));
    assert!(
        admitted.is_err(),
        "admit(0) must never produce a kill domain"
    );
    Ok(())
}

/// A refused launch returns a typed error and leaves no provider running: the
/// launch path reaps the provider it already spawned.
#[test]
fn refused_launch_reaps_provider_and_returns_typed_refusal() -> RefusalResult {
    let sandbox = Sandbox::new("launch-refusal");
    let image = provider_image(sandbox.path());
    let mut command = Command::new(&image);
    // Captured from the live child handle inside the launch path, so the later
    // absence check names that exact process rather than any provider.
    let provider_process_id = Cell::new(0_u32);
    // Liveness observed from inside the launch path, while the spawned provider
    // is still in the launch path's hands. Without this the later absence check
    // could pass vacuously on a provider that had already exited on its own.
    let provider_was_running = Cell::new(false);

    let spawn_result = spawn_provider_kill_on_close(
        || {
            command
                .args(provider_arguments())
                .current_dir(sandbox.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        },
        // The provider is spawned for real, so its process id is captured from
        // the live child handle and the launch path is then told it carries no
        // admissible id. That is the exact unadmittable input `admit_spawned`
        // documents, and it refuses.
        |child: &Child| {
            provider_process_id.set(child.id());
            provider_was_running.set(provider_is_running(child.id()));
            None
        },
        // The shared production reaper, so the launch path's own refusal step
        // is what terminates and waits on the provider.
        |child: &mut Child| reap_refused_std_child(child),
    );

    let refusal = spawn_result.expect_err("an unadmittable provider must refuse the launch");
    assert!(
        matches!(
            refusal,
            AdapterError::Config(_) | AdapterError::LaunchJobAssignmentFailed { .. }
        ),
        "a refused launch must return a typed AdapterError refusal, got {refusal:?}"
    );

    let refused_pid = provider_process_id.get();
    assert_ne!(
        refused_pid, 0,
        "the launch path must have spawned a provider"
    );
    assert!(
        provider_was_running.get(),
        "the spawned provider must have been a live process when the launch path refused it, \
         so its absence is the refusal's doing and not an early exit"
    );
    assert!(
        !provider_is_running(refused_pid),
        "the launch path must have reaped the provider it refused to admit"
    );
    assert!(
        poll_until_absent(refused_pid),
        "the refused launch must leave no provider running (pid {refused_pid})"
    );
    Ok(())
}
