//! Current-user launcher / Task Scheduler registration for `UserMode`
//! (issue #1771, work item AUD4).
//!
//! `UserMode` supervision is a current-user logon task, not an SCM service. The
//! existing adapter that creates it is
//! [`register_current_user_task`](eliot_platform_windows::profile_supervision::register_current_user_task);
//! this module is the *caller* that was missing, and it is deliberately the only
//! production ingress to that adapter.
//!
//! # Why the registration runs here, after Phase-B
//!
//! The adapter refuses any request whose `authority_descriptor_sha256` is not
//! a lowercase 64-hex digest, because it re-pins that descriptor against the
//! retained immutable-binaries root before it lets Task Scheduler commit
//! anything. A `UserMode` candidate manifest legitimately retains the Phase-A
//! pending marker in `runtime_launch.authority_descriptor_digest` — the marker
//! is intentionally not SHA-256-shaped — so the live digest only exists once
//! Host Phase-B has published the real `authority.json` and read it back.
//!
//! This process *is* that Host. `HostComposition` retains the completed Phase-B
//! materialization, so the digest used here is the one Phase-B **observed** on
//! readback, not one recomputed by this module and not the marker. It is joined
//! against the durable committed Phase-B binding in the installation registry,
//! which is the recorded receipt for the same observation, and the two must
//! agree before anything is registered.
//!
//! # What this module never does
//!
//! * It never relaxes [`validate_request_shape`](eliot_platform_windows::profile_supervision::ProfileRootRequest)
//!   or supplies a placeholder digest. Without a live observed digest the
//!   registration is refused, not approximated.
//! * It never registers or removes a task it cannot attribute. Deletion is only
//!   ever reached for the exact receipt this operation obtained from the
//!   adapter, and only when persisting that receipt fails.
//! * It never touches SCM, service accounts, or `ProgramData`. The adapter's
//!   own retained-root proof is what establishes the current-user contour; this
//!   module adds no privileged path of its own.
//!
//! # Idempotency
//!
//! A Host restart must not double-register, and a partial prior registration
//! must never read as success. Restart therefore *inspects* first through the
//! adapter's existing
//! [`inspect_current_user_task`](eliot_platform_windows::profile_supervision::inspect_current_user_task)
//! and joins that observation to a durable receipt persisted under the retained
//! Host state root with the same durable-file mechanics the runtime-restart
//! receipt store already uses (`write_durable_file` + atomic replace + checked
//! directory sync). A `Matching` readback is adopted into a receipt; a
//! `Mismatch` is refused and left untouched; only `Absent` reaches a fresh
//! registration.

use std::path::{Path, PathBuf};

use eliot_installation::{PhaseBDigestState, phase_b_digest_state};
use eliot_platform_windows::profile_supervision::{
    CurrentUserTaskObservation, CurrentUserTaskReceipt, CurrentUserTaskRegistrationError,
    CurrentUserTaskRequest, inspect_current_user_task, register_current_user_task,
};
use sha2::{Digest as _, Sha256};

use super::host_durable_persistence::{sync_dir, write_durable_file};
use super::host_job_launch::profile_root_request;
use super::phase_b_projection::phase_b_manifest_digest;
use super::{HostComposition, HostError, InstallationProfile, PlatformHandle};

/// Sub-directory of the retained Host state root that owns this registration's
/// durable receipt. It sits beside the existing runtime-restart store and never
/// leaves the current user's own state root.
const USER_MODE_LAUNCHER_STORE_DIR: &str = "user-mode-launcher";

/// Bounded ceiling for one serialized registration receipt. The receipt carries
/// the retained root observations of one installation, so this is generous but
/// still bounded: an oversized file is refused rather than parsed.
const MAX_USER_MODE_LAUNCHER_RECEIPT_BYTES: u64 = 64 * 1024;

// F-LOG-HOST (#1771 AUD4) current-user launcher registration observations.
//
// Through the #889 facade only (`super::host_diagnostics::observe_entrypoint_with_detail`);
// the Event Log seam stays typed-Unavailable. Arguments are static literals
// only — never digests, paths, task names, SIDs, or error text — so bounding
// limits size, never sensitivity (I15.4). Sink outcome never alters result,
// order, or cleanup. This cell emits no terminal: the single terminal per
// failed supervisor operation stays with the `run_profile_supervisor` boundary
// in `main.rs`, and these phases correlate by stage order only.
#[cfg(windows)]
fn user_mode_launcher_observe(detail: &str) {
    let _ = super::windows_event_log::event_log_sink_status();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
fn user_mode_launcher_store_dir(host_state_root: &Path) -> PathBuf {
    host_state_root.join(USER_MODE_LAUNCHER_STORE_DIR)
}

/// Deterministic identity of one registration attempt.
///
/// The digest is taken over the complete request, which is itself projected
/// only from recorded approved-generation values and the Phase-B observed
/// digest. Two Host processes that admit the same approved generation with the
/// same observed Phase-B readback therefore compute the same identity and
/// converge on the same receipt file instead of registering twice.
#[cfg(windows)]
fn registration_identity(request: &CurrentUserTaskRequest) -> Result<PlatformHandle, HostError> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    PlatformHandle::new(digest).map_err(|error| HostError::Platform(error.to_string()))
}

#[cfg(windows)]
fn receipt_path(host_state_root: &Path, identity: &PlatformHandle) -> PathBuf {
    user_mode_launcher_store_dir(host_state_root)
        .join(format!("{}.receipt.json", identity.as_str()))
}

#[cfg(windows)]
fn read_bounded_receipt_file(path: &Path, label: &str) -> Result<Vec<u8>, HostError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    let mut limited = file.take(MAX_USER_MODE_LAUNCHER_RECEIPT_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    if bytes.len() as u64 > MAX_USER_MODE_LAUNCHER_RECEIPT_BYTES {
        return Err(HostError::RecoveryRequired(format!(
            "{label} exceeds its bounded size"
        )));
    }
    Ok(bytes)
}

/// Loads this registration's durable receipt, if one was committed.
///
/// An absent receipt is a first registration, never an error. A present but
/// malformed, oversized, or wrongly named record fails closed: it may not be
/// silently replaced, because doing so would let an unreadable prior attempt
/// look like a clean slate.
#[cfg(windows)]
fn load_registration_receipt(
    host_state_root: &Path,
    identity: &PlatformHandle,
) -> Result<Option<CurrentUserTaskReceipt>, HostError> {
    user_mode_launcher_observe("host.user-mode-launcher receipt load requested");
    let path = receipt_path(host_state_root, identity);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            user_mode_launcher_observe("host.user-mode-launcher receipt absent observed");
            return Ok(None);
        }
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "current-user launcher receipt cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() {
        return Err(HostError::RecoveryRequired(
            "current-user launcher receipt path is not a regular file".to_owned(),
        ));
    }
    let bytes = read_bounded_receipt_file(&path, "current-user launcher receipt")?;
    let receipt = serde_json::from_slice::<CurrentUserTaskReceipt>(&bytes).map_err(|error| {
        HostError::RecoveryRequired(format!(
            "current-user launcher receipt is malformed: {error}"
        ))
    })?;
    // The receipt is only this operation's evidence when it re-projects to the
    // same identity from the bytes just read. The digest is recomputed over the
    // decoded request — the recorded request, not an echoed payload — so a
    // receipt cannot be adopted under another registration's identity.
    if &registration_identity(&receipt.request)? != identity {
        return Err(HostError::RecoveryRequired(
            "current-user launcher receipt is bound to a different registration identity"
                .to_owned(),
        ));
    }
    user_mode_launcher_observe("host.user-mode-launcher receipt loaded observed");
    Ok(Some(receipt))
}

/// Publishes the registration receipt durably.
///
/// The bytes are written through a synced handle, atomically moved over the
/// target on the same volume, and committed with the shared checked directory
/// sync. A failed publication never reports success, and the staging file is
/// removed so a crash cannot leave ambiguous evidence behind.
#[cfg(windows)]
fn persist_registration_receipt(
    host_state_root: &Path,
    identity: &PlatformHandle,
    receipt: &CurrentUserTaskReceipt,
) -> Result<(), HostError> {
    user_mode_launcher_observe("host.user-mode-launcher receipt persist requested");
    let dir = user_mode_launcher_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|error| {
        HostError::Platform(format!("launcher store cannot be created: {error}"))
    })?;
    let bytes = serde_json::to_vec(receipt)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if bytes.len() as u64 > MAX_USER_MODE_LAUNCHER_RECEIPT_BYTES {
        return Err(HostError::Platform(
            "current-user launcher receipt exceeds its bounded size".to_owned(),
        ));
    }
    let path = receipt_path(host_state_root, identity);
    let tmp = dir.join(format!(
        ".user-mode-launcher.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let publication = (|| {
        write_durable_file(&tmp, &bytes)?;
        eliot_windows_ipc::atomic_replace_file(&tmp, &path).map_err(|error| {
            HostError::Platform(format!("launcher receipt atomic replace failed: {error}"))
        })?;
        sync_dir(&dir)
    })();
    // The atomic move consumes the staging file on success; on failure it is
    // removed so a crash cannot leave a half-written record that a later start
    // could mistake for a committed receipt. Publication failure stays primary.
    let _ = std::fs::remove_file(&tmp);
    publication?;
    user_mode_launcher_observe("host.user-mode-launcher receipt persist observed");
    Ok(())
}

/// Builds the exact adapter request from the completed Phase-B materialization.
///
/// The projection reuses the existing root-request builder so the four I3.1
/// roles and every runtime state root come from the one owner that already
/// admitted them. Because the descriptor passed in is the Phase-B *live*
/// launch, the request carries the digest Phase-B observed on readback; the
/// immutable Phase-A template is never used here.
#[cfg(windows)]
fn current_user_task_request(host: &HostComposition) -> Result<CurrentUserTaskRequest, HostError> {
    let active = host.registry().active().ok_or_else(|| {
        HostError::RecoveryRequired(
            "current-user launcher registration requires an approved active generation".to_owned(),
        )
    })?;
    if active.manifest.runtime_launch.profile != InstallationProfile::UserMode {
        return Err(HostError::ProcessContour(
            "current-user launcher registration composes only the UserMode profile".to_owned(),
        ));
    }
    let phase_b = host.phase_b_materialization().ok_or_else(|| {
        HostError::RecoveryRequired(
            "current-user launcher registration has no completed Phase-B materialization"
                .to_owned(),
        )
    })?;
    // The observed digest must be a live physical publication. The typed
    // classifier is the installation contract's own, so the pending marker can
    // never be mistaken for a digest here without that contract changing.
    if phase_b_digest_state(
        &phase_b.authority_descriptor_digest,
        "user_mode_launcher.authority_descriptor_digest",
    )
    .map_err(HostError::Installation)?
        != PhaseBDigestState::Live
    {
        return Err(HostError::RecoveryRequired(
            "current-user launcher registration lacks an observed live Phase-B authority digest"
                .to_owned(),
        ));
    }
    let manifest_digest = phase_b_manifest_digest(&active.manifest)?;
    if phase_b.manifest_digest != manifest_digest {
        return Err(HostError::RecoveryRequired(
            "retained Phase-B materialization belongs to a different approved generation"
                .to_owned(),
        ));
    }
    // Join the in-process observation to the durable committed receipt for the
    // same publication. The registry binding is the recorded proof; without it
    // this operation has no durable evidence that Phase-B committed.
    let fence = host
        .registry()
        .last_committed_activation_fence()
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "current-user launcher registration has no committed activation fence".to_owned(),
            )
        })?;
    let binding = fence.phase_b_live_binding.as_ref().ok_or_else(|| {
        HostError::RecoveryRequired(
            "current-user launcher registration has no committed Phase-B live binding".to_owned(),
        )
    })?;
    binding.validate().map_err(HostError::Installation)?;
    if binding.manifest_digest != manifest_digest
        || binding.authority_descriptor_digest != phase_b.authority_descriptor_digest
    {
        return Err(HostError::RecoveryRequired(
            "committed Phase-B binding does not describe the observed authority publication"
                .to_owned(),
        ));
    }
    let launch = &phase_b.launch;
    let roots = profile_root_request(launch)?;
    let immutable_binaries = PathBuf::from(
        roots
            .roots
            .immutable_binaries
            .to_string_lossy()
            .into_owned(),
    );
    // Every bootstrap argument is projected from the request itself, so the
    // task action can never name a descriptor path or digest that the adapter
    // was not also given.
    let bootstrap_arguments = vec![
        "--config-descriptor".to_owned(),
        roots
            .authority_descriptor_path
            .to_string_lossy()
            .into_owned(),
        "--config-descriptor-sha256".to_owned(),
        roots.authority_descriptor_sha256.clone(),
        "--installation-id".to_owned(),
        roots.installation_id.clone(),
        "--tx-plan-generation".to_owned(),
        roots.authority_generation.to_string(),
        "--host-state-root".to_owned(),
        launch
            .runtime_state_roots
            .host_state_root
            .as_str()
            .to_owned(),
    ];
    Ok(CurrentUserTaskRequest {
        // The installation transaction and Phase-B effect identity are the
        // recorded approved values, never a fresh or echoed local value.
        transaction_id: active.approval.transaction_id().as_str().to_owned(),
        effect_id: binding.effect_id.as_str().to_owned(),
        roots,
        executable: PathBuf::from(launch.host_executable_path.as_str()),
        executable_sha256: launch.host_artifact_digest.as_str().to_owned(),
        working_directory: immutable_binaries,
        bootstrap_arguments,
    })
}

/// Registers the current-user launcher exactly once for this approved
/// generation.
///
/// # Errors
///
/// Returns [`HostError`] when the profile is not `UserMode`, when no live
/// observed Phase-B authority digest is available, when a prior task at the
/// planned identity cannot be attributed, or when the adapter rejects the
/// registration or its exact cleanup cannot be confirmed.
#[cfg(windows)]
pub fn register_user_mode_launcher(host: &HostComposition) -> Result<(), HostError> {
    user_mode_launcher_observe("host.user-mode-launcher registration requested");
    let request = current_user_task_request(host)?;
    let identity = registration_identity(&request)?;
    let host_state_root = host.launch_state_root();

    // A committed receipt from an earlier Host process is the idempotency
    // record. Re-inspect against it rather than registering again: `Matching`
    // proves this exact action is still installed, and anything else is a
    // disagreement that a fresh registration must not paper over.
    if let Some(receipt) = load_registration_receipt(host_state_root, &identity)? {
        match inspect_current_user_task(&request, Some(&receipt)) {
            Ok(CurrentUserTaskObservation::Matching { .. }) => {
                user_mode_launcher_observe(
                    "host.user-mode-launcher exact prior registration observed",
                );
                return Ok(());
            }
            Ok(CurrentUserTaskObservation::Absent { .. }) => {
                // The task this operation registered is gone. Re-registering is
                // the convergent action; it is not a second registration,
                // because absence was observed first.
                user_mode_launcher_observe(
                    "host.user-mode-launcher prior registration absent observed",
                );
            }
            Ok(CurrentUserTaskObservation::Mismatch { .. }) => {
                return Err(HostError::RecoveryRequired(
                    "current-user launcher task differs from this operation's committed receipt"
                        .to_owned(),
                ));
            }
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "current-user launcher readback failed: {error}"
                )));
            }
        }
    } else {
        // No receipt. Inspect anyway, so an unattributable task at this identity
        // is adopted only when it matches exactly and refused otherwise. The
        // adapter's own contract is explicit that `Matching` alone does not
        // prove who created the task; the exact-action join below is what makes
        // it this operation's.
        match inspect_current_user_task(&request, None) {
            Ok(CurrentUserTaskObservation::Absent { .. }) => {
                user_mode_launcher_observe("host.user-mode-launcher absence observed");
            }
            Ok(CurrentUserTaskObservation::Matching { receipt, .. }) => {
                let adopted = *receipt;
                persist_registration_receipt(host_state_root, &identity, &adopted)?;
                user_mode_launcher_observe(
                    "host.user-mode-launcher exact prior registration adopted observed",
                );
                return Ok(());
            }
            Ok(CurrentUserTaskObservation::Mismatch { .. }) => {
                return Err(HostError::RecoveryRequired(
                    "a different current-user launcher task already occupies this identity"
                        .to_owned(),
                ));
            }
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "current-user launcher readback failed: {error}"
                )));
            }
        }
    }

    // WORK_UNIT_CASE: 1771/4 — the requested registration is distinct from the
    // Task Scheduler commit the adapter performs below.
    user_mode_launcher_observe("host.user-mode-launcher registration requested commit");
    let receipt = match register_current_user_task(&request) {
        Ok(receipt) => receipt,
        Err(CurrentUserTaskRegistrationError::Rejected(error)) => {
            // The adapter refused before committing anything, so there is
            // nothing to undo and nothing of ours to delete.
            return Err(HostError::RecoveryRequired(format!(
                "current-user launcher registration was rejected: {error}"
            )));
        }
        Err(error) => {
            // `CommittedUnknown` and `CleanupRequired` both mean Task Scheduler
            // may have committed while exact removal could not be confirmed.
            // No receipt is written, so a later start re-inspects and refuses
            // rather than reporting this attempt as a success.
            return Err(HostError::RecoveryRequired(format!(
                "current-user launcher registration needs reconciliation: {error}"
            )));
        }
    };
    if let Err(error) = persist_registration_receipt(host_state_root, &identity, &receipt) {
        // The task exists but its receipt does not, which is exactly the
        // partial state a restart must never read as success. Delete only the
        // exact task this operation just created, using the adapter's own
        // receipt-scoped removal, and never touch anything else.
        let cleanup =
            eliot_platform_windows::profile_supervision::remove_current_user_task(&receipt);
        return Err(match cleanup {
            Ok(()) => HostError::RecoveryRequired(format!(
                "current-user launcher receipt could not be published and the created task was removed: {error}"
            )),
            Err(cleanup_error) => HostError::RecoveryRequired(format!(
                "current-user launcher receipt could not be published and its task could not be removed: {error}; {cleanup_error}"
            )),
        });
    }
    // WORK_UNIT_CASE: 1771/4 — Task Scheduler commit observed by exact readback.
    user_mode_launcher_observe("host.user-mode-launcher registration committed observed");
    Ok(())
}
