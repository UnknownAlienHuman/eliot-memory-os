//! Governed canary-removal CLI entry (issue #1138, lane 2 less wiring).
//!
//! Closed plan/status/apply/recover interface over the installation owner's
//! canary-removal API (`WindowsInstallationCoordinator::plan_canary_removal`,
//! `apply_canary_removal`, `canary_removal_status`, `recover_canary_removal`).
//! Planning is read-only; status is read-only; recover reconciles before any
//! separately admitted retry. No filesystem or SCM mutation happens here:
//! every mutation goes through the installation/Host owner, and the registry
//! is only ever opened when it already exists, never created.
//!
//! The `InstallationCommand::RemoveCanary` enum/dispatch/import wiring in
//! `main.rs` is owned by STITCH. This module exposes only the four entry
//! functions plus their JSON report contract, so the wiring is a thin
//! argument-forwarding arm with no new authority of its own.
//!
//! Reports follow the installation CLI shape (`status`/`code`/`detail`/
//! `completed`/`scope`). A typed owner refusal prints as `ERROR` with a stable
//! `CANARY_REMOVAL_*` code and a nonzero exit; the exit code alone is never
//! proof - the printed stage, blocking effect and next permitted action are.
//! I15.4 secret boundary: no report carries a secret value, credential
//! ciphertext or provider output; owner errors carry none by construction and
//! the request/plan inputs are handled as opaque validated bytes.

use std::path::Path;

use anyhow::Result;
use eliot_installation::{
    CanaryRemovalPlan, CanaryRemovalStage, CanaryRemovalStatus, InstallationError,
    ManagedEnvironmentChangeRequest, PlatformHandle, RedbInstallationRegistry,
    RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    parse_installation_transaction_id,
};
use eliot_platform_windows::ProtectedRootLease;
use serde_json::json;

/// Scope label carried by every canary-removal report, matching the
/// installation CLI contract.
const CANARY_REMOVAL_SCOPE: &str = "bounded_all_effects_or_exact_rollback";

/// Exit code for a refused or incomplete canary-removal command. Mirrors the
/// installation CLI invalid-request exit; STITCH keeps the single value when
/// it wires the dispatch arm.
const CANARY_REMOVAL_INVALID_REQUEST_EXIT: i32 = 2;

/// Prints one typed owner refusal without mutating the machine.
fn write_canary_removal_error(code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "completed": false,
            "scope": CANARY_REMOVAL_SCOPE,
        })
    );
}

/// Maps one typed owner refusal to its stable report code.
///
/// Quiesce, fence, retirement-barrier and deadline refusals all arrive as
/// `IncompleteObservation` naming the exact blocking effect; identity drift
/// arrives as `IdentityConflict` or `CompareAndSaveConflict`. The detail is
/// always the owner's own message, which carries identities and evidence
/// references but never secrets.
fn canary_removal_error_code(error: &InstallationError) -> &'static str {
    match error {
        InstallationError::TransactionNotFound { .. } => "CANARY_REMOVAL_NOT_FOUND",
        InstallationError::MigrationRequired { .. } => "CANARY_REMOVAL_MIGRATION_REQUIRED",
        InstallationError::CompareAndSaveConflict { .. } => "CANARY_REMOVAL_REVISION_CONFLICT",
        InstallationError::IdentityConflict => "CANARY_REMOVAL_IDENTITY_CONFLICT",
        InstallationError::IncompleteObservation(_) => "CANARY_REMOVAL_INCOMPLETE",
        InstallationError::InvalidField { .. }
        | InstallationError::Duplicate { .. }
        | InstallationError::IllegalTransition { .. }
        | InstallationError::UnknownOutcome { .. }
        | InstallationError::RecoveryRequired { .. }
        | InstallationError::ProfileViolation(_)
        | InstallationError::Platform(_)
        | InstallationError::CorruptRegistry { .. } => "CANARY_REMOVAL_INVALID",
    }
}

/// Prints one successful plan report. A plan is read-only, so `completed` is
/// always false here: the plan digest binds the follow-up apply, it does not
/// execute anything.
fn print_canary_removal_plan(plan: &CanaryRemovalPlan) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "OK",
            "code": "CANARY_REMOVAL_PLAN",
            "completed": false,
            "scope": CANARY_REMOVAL_SCOPE,
            "removal_transaction_id": plan.removal_transaction_id.as_str(),
            "install_transaction_id": plan.install_transaction_id.as_str(),
            "generation": plan.generation.as_str(),
            "plan_digest": plan.plan_digest.as_str(),
            "plan": plan,
        }))?
    );
    Ok(())
}

/// Prints one owner status report and returns the matching exit code.
///
/// Exit zero requires the terminal `Completed` stage observed from the
/// resource owners' own readback. Any other stage - including a successful
/// reconcile that still has open rows - exits nonzero with the blocking
/// effect and the next permitted action in the report.
fn print_canary_removal_status(label: &str, status: &CanaryRemovalStatus) -> Result<i32> {
    let completed = status.stage == CanaryRemovalStage::Completed;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "OK",
            "code": label,
            "completed": completed,
            "scope": CANARY_REMOVAL_SCOPE,
            "removal": status,
        }))?
    );
    Ok(if completed {
        0
    } else {
        CANARY_REMOVAL_INVALID_REQUEST_EXIT
    })
}

/// Opens the existing durable transaction store without creating anything.
fn open_canary_removal_store(
    store_path: &Path,
) -> Result<RedbInstallationTransactionStore, (String, String)> {
    RedbInstallationTransactionStore::open_existing_exact_path(store_path).map_err(|error| {
        (
            "CANARY_REMOVAL_UNAVAILABLE".to_owned(),
            format!("durable transaction store could not be opened: {error}"),
        )
    })
}

/// Opens the existing approved-generation registry below one retained
/// per-installation Host root without creating a file or database.
///
/// `None` means only that the fixed registry child is absent; it is refused
/// here rather than created, because removal never provisions owner state.
fn open_canary_removal_registry(
    host_state_root: &Path,
) -> Result<RedbInstallationRegistry, (String, String)> {
    let host_root = ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
        (
            "CANARY_REMOVAL_UNAVAILABLE".to_owned(),
            format!("retained Host state root could not be reopened: {error}"),
        )
    })?;
    RedbInstallationRegistry::open_existing_at(host_root)
        .map_err(|error| {
            (
                "CANARY_REMOVAL_UNAVAILABLE".to_owned(),
                format!("approved-generation registry could not be opened: {error}"),
            )
        })?
        .ok_or_else(|| {
            (
                "CANARY_REMOVAL_NOT_FOUND".to_owned(),
                "approved-generation registry is absent below the retained Host state root"
                    .to_owned(),
            )
        })
}

/// Reads and parses one JSON input file; the owner validates its content.
fn read_canary_removal_json<T>(path: &Path, what: &str) -> Result<T, (String, String)>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = std::fs::read(path).map_err(|error| {
        (
            "CANARY_REMOVAL_INVALID".to_owned(),
            format!("{what} could not be read: {error}"),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        (
            "CANARY_REMOVAL_INVALID".to_owned(),
            format!("{what} is not valid JSON for its typed shape: {error}"),
        )
    })
}

/// Resolves one exact installed canary and prints the frozen, read-only
/// removal plan.
///
/// `request_json_path` carries the explicit canary-removal authorization: the
/// CLI mints no request identity, it only forwards the operator-supplied
/// authorization for the owner to validate. A foreign, ambiguous, replaced,
/// production or last-known-good target is refused before any destructive
/// path exists.
pub fn run_canary_removal_plan(
    store_path: &Path,
    host_state_root: &Path,
    generation: &str,
    request_json_path: &Path,
) -> Result<i32> {
    let generation = match PlatformHandle::new(generation) {
        Ok(generation) => generation,
        Err(error) => {
            write_canary_removal_error(
                "CANARY_REMOVAL_INVALID",
                &format!("generation identity is invalid: {error}"),
            );
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let request: ManagedEnvironmentChangeRequest =
        match read_canary_removal_json(request_json_path, "removal authorization") {
            Ok(request) => request,
            Err((code, detail)) => {
                write_canary_removal_error(&code, &detail);
                return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
            }
        };
    let store = match open_canary_removal_store(store_path) {
        Ok(store) => store,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let registry = match open_canary_removal_registry(host_state_root) {
        Ok(registry) => registry,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.plan_canary_removal(&registry, &request, &generation) {
        Ok(plan) => {
            print_canary_removal_plan(&plan)?;
            Ok(0)
        }
        Err(error) => {
            write_canary_removal_error(canary_removal_error_code(&error), &error.to_string());
            Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT)
        }
    }
}

/// Admits and drives one removal operation for an already frozen plan.
///
/// `plan_json_path` carries the exact plan a previous `plan` call printed.
/// The owner revalidates the plan digest and the current revisions, records
/// the removal intent durably and fences new work before destructive actions;
/// a reused identity with changed inputs conflicts instead of executing.
pub fn run_canary_removal_apply(
    store_path: &Path,
    host_state_root: &Path,
    plan_json_path: &Path,
) -> Result<i32> {
    let plan: CanaryRemovalPlan = match read_canary_removal_json(plan_json_path, "removal plan") {
        Ok(plan) => plan,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    if let Err(error) = plan.validate() {
        write_canary_removal_error(canary_removal_error_code(&error), &error.to_string());
        return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
    }
    let store = match open_canary_removal_store(store_path) {
        Ok(store) => store,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let registry = match open_canary_removal_registry(host_state_root) {
        Ok(registry) => registry,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.apply_canary_removal(&registry, &plan) {
        Ok(status) => print_canary_removal_status("CANARY_REMOVAL_APPLY", &status),
        Err(error) => {
            write_canary_removal_error(canary_removal_error_code(&error), &error.to_string());
            Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT)
        }
    }
}

/// Returns the stable, secret-free disposition of one removal operation.
///
/// Status is read-only: it loads the durable removal record and projects it
/// without touching an external owner, so it needs the store but no registry.
pub fn run_canary_removal_status(
    store_path: &Path,
    raw_removal_transaction_id: &str,
) -> Result<i32> {
    let removal_transaction_id =
        match parse_installation_transaction_id(raw_removal_transaction_id) {
            Ok(identity) => identity,
            Err(error) => {
                write_canary_removal_error("CANARY_REMOVAL_INVALID", &error.to_string());
                return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
            }
        };
    let store = match open_canary_removal_store(store_path) {
        Ok(store) => store,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.canary_removal_status(&removal_transaction_id) {
        Ok(status) => print_canary_removal_status("CANARY_REMOVAL_STATUS", &status),
        Err(error) => {
            write_canary_removal_error(canary_removal_error_code(&error), &error.to_string());
            Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT)
        }
    }
}

/// Reconciles one already admitted removal operation.
///
/// Recovery reuses the same removal operation identity and the same per-row
/// intent digests, reconciles before any further attempt, and never admits a
/// fresh removal identity for an unresolved effect. Deadline expiry preserves
/// the incomplete recovery in the report instead of forcing green.
pub fn run_canary_removal_recover(
    store_path: &Path,
    host_state_root: &Path,
    raw_removal_transaction_id: &str,
) -> Result<i32> {
    let removal_transaction_id =
        match parse_installation_transaction_id(raw_removal_transaction_id) {
            Ok(identity) => identity,
            Err(error) => {
                write_canary_removal_error("CANARY_REMOVAL_INVALID", &error.to_string());
                return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
            }
        };
    let store = match open_canary_removal_store(store_path) {
        Ok(store) => store,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let registry = match open_canary_removal_registry(host_state_root) {
        Ok(registry) => registry,
        Err((code, detail)) => {
            write_canary_removal_error(&code, &detail);
            return Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT);
        }
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.recover_canary_removal(&registry, &removal_transaction_id) {
        Ok(status) => print_canary_removal_status("CANARY_REMOVAL_RECOVER", &status),
        Err(error) => {
            write_canary_removal_error(canary_removal_error_code(&error), &error.to_string());
            Ok(CANARY_REMOVAL_INVALID_REQUEST_EXIT)
        }
    }
}
