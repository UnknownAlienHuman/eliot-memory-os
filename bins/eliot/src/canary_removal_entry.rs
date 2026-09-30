//! Governed canary-removal CLI entry (issue #1138, lane 2).
//!
//! Thin wiring over the installation owner's repaired removal seams
//! (`plan_canary_removal`, `apply_canary_removal`, `canary_removal_status`
//! and `recover_canary_removal` on `WindowsInstallationCoordinator`).
//! Planning is read-only and prints the frozen plan; status is read-only and
//! projects the durable record without touching an external owner; recover
//! reconciles the already admitted operation before any separately admitted
//! retry. Only a plan the owner admits (`Ok`) proceeds past the refusal
//! boundary: foreign, ambiguous, replaced, production and last-known-good
//! targets keep failing with typed `INSTALLATION_REMOVE_CANARY_*` errors.
//! This module performs no filesystem or SCM cleanup and offers no generic
//! uninstall API; every mutation flows through the owner's durable removal
//! operation.

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

use super::{
    INSTALLATION_CONTRACT_VERSION, INSTALLATION_SCOPE, INVALID_REQUEST_EXIT, UNKNOWN_OUTCOME_EXIT,
    load_input, write_installation_error,
};

/// Operation tag for the read-only plan command.
const PLAN_OPERATION: &str = "PLAN";
/// Operation tag for the admitting apply command.
const APPLY_OPERATION: &str = "APPLY";
/// Operation tag for the read-only status command.
const STATUS_OPERATION: &str = "STATUS";
/// Operation tag for the reconciling recover command.
const RECOVER_OPERATION: &str = "RECOVER";

/// Resolves one exact installed canary into its frozen read-only removal plan.
///
/// The store and the registry are opened but never created; the owner refuses
/// unsupported targets before any destructive path exists.
pub fn run_plan_canary_removal(
    store_path: &Path,
    host_state_root: &Path,
    generation: &str,
    request_path: &Path,
) -> Result<i32> {
    let target = match PlatformHandle::new(generation.to_owned()) {
        Ok(handle) => handle,
        Err(error) => {
            return Ok(refuse(
                PLAN_OPERATION,
                &InstallationError::InvalidField {
                    field: "generation".to_owned(),
                    reason: error.to_string(),
                },
            ));
        }
    };
    let request = match load_request(request_path) {
        Ok(request) => request,
        Err(error) => return Ok(refuse(PLAN_OPERATION, &error)),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return Ok(refuse(PLAN_OPERATION, &error)),
    };
    let registry = match open_existing_registry(host_state_root) {
        Ok(registry) => registry,
        Err(error) => return Ok(refuse(PLAN_OPERATION, &error)),
    };
    let coordinator = WindowsInstallationCoordinator::new(store);
    let plan = match coordinator.plan_canary_removal(&registry, &request, &target) {
        Ok(plan) => plan,
        Err(error) => return Ok(refuse(PLAN_OPERATION, &error)),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": "CANARY_REMOVAL_PLAN",
            "completed": true,
            "scope": INSTALLATION_SCOPE,
            "plan": serde_json::to_value(&plan)?,
        }))?
    );
    Ok(0)
}

/// Admits and drives the durable removal operation for one frozen plan.
///
/// The plan JSON is untrusted import: the owner revalidates the exact plan
/// digest and the current revisions before the first destructive call.
pub fn run_apply_canary_removal(
    store_path: &Path,
    host_state_root: &Path,
    plan_path: &Path,
) -> Result<i32> {
    let plan = match load_plan(plan_path) {
        Ok(plan) => plan,
        Err(error) => return Ok(refuse(APPLY_OPERATION, &error)),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return Ok(refuse(APPLY_OPERATION, &error)),
    };
    let registry = match open_existing_registry(host_state_root) {
        Ok(registry) => registry,
        Err(error) => return Ok(refuse(APPLY_OPERATION, &error)),
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.apply_canary_removal(&registry, &plan) {
        Ok(status) => print_removal_status(&status),
        Err(error) => Ok(refuse(APPLY_OPERATION, &error)),
    }
}

/// Projects the stable secret-free disposition of one removal operation.
///
/// Read-only: only the durable store is opened, never the registry and never
/// an external owner.
pub fn run_canary_removal_status(store_path: &Path, raw_removal_id: &str) -> Result<i32> {
    let removal_id = match parse_installation_transaction_id(raw_removal_id) {
        Ok(handle) => handle,
        Err(error) => return Ok(refuse(STATUS_OPERATION, &error)),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return Ok(refuse(STATUS_OPERATION, &error)),
    };
    let coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.canary_removal_status(&removal_id) {
        Ok(status) => print_removal_status(&status),
        Err(error) => Ok(refuse(STATUS_OPERATION, &error)),
    }
}

/// Reconciles one already admitted removal operation.
///
/// Recovery reuses the same operation identity and reconciles before any
/// further attempt; it never admits a fresh removal identity.
pub fn run_recover_canary_removal(
    store_path: &Path,
    host_state_root: &Path,
    raw_removal_id: &str,
) -> Result<i32> {
    let removal_id = match parse_installation_transaction_id(raw_removal_id) {
        Ok(handle) => handle,
        Err(error) => return Ok(refuse(RECOVER_OPERATION, &error)),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return Ok(refuse(RECOVER_OPERATION, &error)),
    };
    let registry = match open_existing_registry(host_state_root) {
        Ok(registry) => registry,
        Err(error) => return Ok(refuse(RECOVER_OPERATION, &error)),
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.recover_canary_removal(&registry, &removal_id) {
        Ok(status) => print_removal_status(&status),
        Err(error) => Ok(refuse(RECOVER_OPERATION, &error)),
    }
}

/// Loads the explicit canary-removal authorization without trusting it.
///
/// Validation stays with the owner: `plan_canary_removal` requires the
/// `Remove` action and the exact target candidate.
fn load_request(
    request_path: &Path,
) -> std::result::Result<ManagedEnvironmentChangeRequest, InstallationError> {
    let bytes = load_input(request_path).map_err(|error| InstallationError::InvalidField {
        field: "request".to_owned(),
        reason: error.to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|error| InstallationError::InvalidField {
        field: "request".to_owned(),
        reason: format!("request is not a ManagedEnvironmentChangeRequest: {error}"),
    })
}

/// Loads one frozen removal plan for admission.
///
/// The digest fence stays with the owner: `apply_canary_removal` revalidates
/// the exact plan digest and current revisions before any destructive call.
fn load_plan(plan_path: &Path) -> std::result::Result<CanaryRemovalPlan, InstallationError> {
    let bytes = load_input(plan_path).map_err(|error| InstallationError::InvalidField {
        field: "plan".to_owned(),
        reason: error.to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|error| InstallationError::InvalidField {
        field: "plan".to_owned(),
        reason: format!("plan is not a CanaryRemovalPlan: {error}"),
    })
}

/// Opens the existing durable transaction store without creating one.
fn open_existing_store(
    store_path: &Path,
) -> std::result::Result<RedbInstallationTransactionStore, InstallationError> {
    RedbInstallationTransactionStore::open_existing_exact_path(store_path)
}

/// Opens the existing installation registry below the retained Host root.
///
/// The root is only a locator: the lease proves the retained OS identity and
/// the owner cross-checks the accepted manifests, so a foreign root yields a
/// typed refusal, never a wrong-target mutation. Nothing is created.
fn open_existing_registry(
    host_state_root: &Path,
) -> std::result::Result<RedbInstallationRegistry, InstallationError> {
    let lease = ProtectedRootLease::open_existing(host_state_root)
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    RedbInstallationRegistry::open_existing_at(lease)?.ok_or_else(|| {
        InstallationError::InvalidField {
            field: "host_state_root".to_owned(),
            reason: "the retained installation registry is absent below the Host root; no installed generation can be resolved"
                .to_owned(),
        }
    })
}

/// Prints the stable removal disposition and exits zero only on `Completed`.
///
/// Exit zero alone is never proof: the `removal` object carries the effect
/// identities, the blocking effect, the retained uncertainty and the next
/// permitted action.
fn print_removal_status(status: &CanaryRemovalStatus) -> Result<i32> {
    let completed = status.stage == CanaryRemovalStage::Completed;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "contract": "eliot.kernel.installation",
            "contract_version": INSTALLATION_CONTRACT_VERSION,
            "status": serde_json::to_value(status.stage)?,
            "completed": completed,
            "scope": INSTALLATION_SCOPE,
            "removal": serde_json::to_value(status)?,
        }))?
    );
    Ok(if completed { 0 } else { INVALID_REQUEST_EXIT })
}

/// Reports a typed refusal: the owner error selects the failure class.
///
/// An unknown outcome keeps its own exit so callers reconcile the same
/// operation instead of retrying blindly.
fn refuse(operation: &str, error: &InstallationError) -> i32 {
    let unknown = matches!(error, InstallationError::UnknownOutcome { .. });
    write_installation_error(&removal_error_code(operation, error), &error.to_string());
    if unknown {
        UNKNOWN_OUTCOME_EXIT
    } else {
        INVALID_REQUEST_EXIT
    }
}

/// Maps one owner error to its closed CLI failure class.
fn removal_error_code(operation: &str, error: &InstallationError) -> String {
    let class = match error {
        InstallationError::InvalidField { .. } => "INVALID",
        InstallationError::Duplicate { .. }
        | InstallationError::IdentityConflict
        | InstallationError::CompareAndSaveConflict { .. } => "CONFLICT",
        InstallationError::IllegalTransition { .. }
        | InstallationError::ProfileViolation(_)
        | InstallationError::IncompleteObservation(_) => "REFUSED",
        InstallationError::UnknownOutcome { .. } => "UNKNOWN",
        InstallationError::RecoveryRequired { .. } => "RECOVERY_REQUIRED",
        InstallationError::Platform(_) => "UNAVAILABLE",
        InstallationError::CorruptRegistry { .. } => "CORRUPT",
        InstallationError::MigrationRequired { .. } => "MIGRATION_REQUIRED",
        InstallationError::TransactionNotFound { .. } => "NOT_FOUND",
    };
    format!("INSTALLATION_REMOVE_CANARY_{operation}_{class}")
}
