//! Governed canary-removal CLI entry (issue #1138, lane 2).
//!
//! Thin wiring over the installation owner's repaired removal seams
//! (`plan_canary_removal`, `apply_canary_removal`, `canary_removal_status`
//! and `recover_canary_removal` on `WindowsInstallationCoordinator`).
//! `remove-canary` is the one owner-backed removal surface: it decodes the
//! explicit `Remove` authorization, lets the owner resolve the frozen plan,
//! lets the owner admit and drive that same plan, and projects the resulting
//! durable disposition. The separate `plan-canary-removal` command prints the
//! versioned `CanaryRemovalPlanEnvelope` that `apply-canary-removal` accepts,
//! so unmodified plan stdout round-trips into apply. Status is read-only and
//! projects the durable record without touching an external owner; recover
//! reconciles the already admitted operation before any separately admitted
//! retry. Every route that needs the registry — the read-only
//! `plan-canary-removal` included — obtains it as the owner's exclusive redb
//! WRITER handle, because the owner's planning seam admits no reader-backed
//! registry type and the installation crate's one read-only entry point returns
//! a projection value instead. redb commits a quick-repair `allocator_state`
//! transaction when that writer handle is dropped, so planning is a bounded
//! write of redb's own bookkeeping and is NOT a byte-preserving read of the
//! owner's registry file. Only a plan the owner admits (`Ok`) proceeds past the
//! refusal boundary: foreign, ambiguous, replaced, production and
//! last-known-good targets keep failing with typed `INSTALLATION_REMOVE_CANARY_*`
//! errors. A frozen plan carrying a required cleanup classified
//! `CanaryRemovalAction::Unsupported` — a transaction-owned resource this owner
//! has no admitted removal path for — is refused with the same typed envelope
//! once a route drives that plan, before any row is: the row keeps its place in
//! the denominator and no removal evidence is minted for it. A surface this
//! owner cannot observe at all is named `CanaryRemovalAction::OutOfScope`
//! instead and is not refused.
//! This module performs no filesystem or SCM cleanup and offers no generic
//! uninstall API; every mutation flows through the owner's durable removal
//! operation.

use std::path::Path;

use eliot_installation::{
    CanaryRemovalPlan, CanaryRemovalPlanEnvelope, CanaryRemovalStage, CanaryRemovalStatus,
    InstallationError, ManagedEnvironmentChangeRequest, PlatformHandle, RedbInstallationRegistry,
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
///
/// `run_remove_canary` publishes the same tag for the plan phase of the public
/// route; `run_remove_canary` states why that overlap is deliberate.
const PLAN_OPERATION: &str = "PLAN";
/// Operation tag for the admitting apply command.
///
/// `run_remove_canary` publishes the same tag for the apply phase of the public
/// route; `run_remove_canary` states why that overlap is deliberate.
const APPLY_OPERATION: &str = "APPLY";
/// Operation tag for the read-only status command.
const STATUS_OPERATION: &str = "STATUS";
/// Operation tag for the reconciling recover command.
const RECOVER_OPERATION: &str = "RECOVER";

/// Resolves one exact installed canary into its frozen read-only removal plan.
///
/// No file, secret, service, reservation or transaction row is created, and the
/// registry revision does not advance. The route is nonetheless not a
/// byte-preserving read: it opens the registry through
/// `open_retained_registry_writer`, because the owner's `plan_canary_removal`
/// seam admits only a redb writer handle, and redb's `Drop for Database` commits
/// a quick-repair `allocator_state` transaction. That is a bounded write of
/// redb's own bookkeeping on every run, so no caller can use identical registry
/// file bytes as this command's oracle. The transaction store beside it IS
/// opened read-only and cannot commit.
///
/// The owner refuses a foreign, ambiguous, replaced, production or
/// last-known-good target before any destructive path exists. The printed
/// document is the versioned `CanaryRemovalPlanEnvelope`: every label except the
/// CLI's own installation scope comes from the owner type, so the same bytes
/// `apply-canary-removal` decodes are exactly the bytes written here.
///
/// The exit code is returned directly rather than wrapped, and so is every route
/// below it. Each step is a typed refusal through `refuse`, including the two
/// rendering steps: `print_removal_status` returns the OWNER error type for a
/// projection it cannot serialize, so no route on this surface has an error left
/// to propagate and a `Result` here would be a wrapper around nothing. That is
/// what makes "no `anyhow::Error` escapes these routes" true by construction
/// rather than by inspection.
pub fn run_plan_canary_removal(
    store_path: &Path,
    host_state_root: &Path,
    generation: &str,
    request_path: &Path,
) -> i32 {
    let (target, request, store, registry) =
        match open_removal_owners(store_path, host_state_root, generation, request_path) {
            Ok(owners) => owners,
            Err(error) => return refuse(PLAN_OPERATION, &error),
        };
    let coordinator = WindowsInstallationCoordinator::new(store);
    let plan = match coordinator.plan_canary_removal(&registry, &request, &target) {
        Ok(plan) => plan,
        Err(error) => return refuse(PLAN_OPERATION, &error),
    };
    let scope = match PlatformHandle::new(INSTALLATION_SCOPE.to_owned()) {
        Ok(handle) => handle,
        Err(error) => {
            return refuse(
                PLAN_OPERATION,
                &InstallationError::InvalidField {
                    field: "scope".to_owned(),
                    reason: error.to_string(),
                },
            );
        }
    };
    // The envelope and its rendering are refusals on this route like every other
    // step: `CanaryRemovalPlanEnvelope::new` re-validates the plan it carries and
    // can refuse it, and a value this surface cannot render is the same typed
    // `InvalidField` refusal the `scope` handle above composes, named on the
    // member that holds it with the cause kept in `detail`.
    let envelope = match CanaryRemovalPlanEnvelope::new(scope, plan) {
        Ok(envelope) => envelope,
        Err(error) => return refuse(PLAN_OPERATION, &error),
    };
    let document = match serde_json::to_string_pretty(&envelope) {
        Ok(document) => document,
        Err(error) => {
            return refuse(
                PLAN_OPERATION,
                &InstallationError::InvalidField {
                    field: "plan".to_owned(),
                    reason: format!("the CanaryRemovalPlanEnvelope cannot be serialized: {error}"),
                },
            );
        }
    };
    println!("{document}");
    0
}

/// Removes one exact installed canary through the installation owner.
///
/// This is the public `remove-canary` surface and it is one owner-backed
/// removal, not a refusal: the same explicit `Remove` authorization is
/// decoded, the owner resolves the frozen plan, and the owner admits and
/// drives that same plan. The durable disposition the owner returns is
/// projected by `project_removal_status`, so the exit code follows the projected
/// stage instead of a hardcoded success. The binary deletes nothing itself and
/// adds no flag vocabulary of its own: both owner calls are the same seams the
/// `plan-canary-removal` and `apply-canary-removal` commands use.
///
/// Every refusal this route composes is tagged with the owner phase it came
/// from: `PLAN` for the input decode and the owner's `plan_canary_removal`, and
/// `APPLY` for `apply_canary_removal`. This route resolves AND drives a plan in
/// one command, so a phase tag names it only partly, and the same tag is also
/// published by the `plan-canary-removal` and `apply-canary-removal` commands.
/// That overlap is deliberate: the codes name the owner phase, not the command
/// that invoked it, because no acceptance clause asks a code to identify its
/// caller and the `detail` member already names the exact cause. A route-tagged
/// alternative was considered and rejected — it renders as
/// `INSTALLATION_REMOVE_CANARY_REMOVE_CANARY_PLAN_INVALID`, and a code that
/// reads like a doubled prefix is worse than an honest overlap.
pub fn run_remove_canary(
    store_path: &Path,
    host_state_root: &Path,
    generation: &str,
    request_path: &Path,
) -> i32 {
    let (target, request, store, registry) =
        match open_removal_owners(store_path, host_state_root, generation, request_path) {
            Ok(owners) => owners,
            Err(error) => return refuse(PLAN_OPERATION, &error),
        };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    let plan = match coordinator.plan_canary_removal(&registry, &request, &target) {
        Ok(plan) => plan,
        Err(error) => return refuse(PLAN_OPERATION, &error),
    };
    match coordinator.apply_canary_removal(&registry, &plan) {
        Ok(status) => project_removal_status(&status, APPLY_OPERATION),
        Err(error) => refuse(APPLY_OPERATION, &error),
    }
}

/// Admits and drives the durable removal operation for one frozen plan.
///
/// The plan JSON is untrusted import: the owner revalidates the exact plan
/// digest and the current revisions before the first destructive call.
pub fn run_apply_canary_removal(
    store_path: &Path,
    host_state_root: &Path,
    plan_path: &Path,
) -> i32 {
    let plan = match load_plan(plan_path) {
        Ok(plan) => plan,
        Err(error) => return refuse(APPLY_OPERATION, &error),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return refuse(APPLY_OPERATION, &error),
    };
    let registry = match open_retained_registry_writer(host_state_root) {
        Ok(registry) => registry,
        Err(error) => return refuse(APPLY_OPERATION, &error),
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.apply_canary_removal(&registry, &plan) {
        Ok(status) => project_removal_status(&status, APPLY_OPERATION),
        Err(error) => refuse(APPLY_OPERATION, &error),
    }
}

/// Projects the stable secret-free disposition of one removal operation.
///
/// Read-only in fact, not only by contract: the registry is never opened at
/// all, the owner's status seam takes no registry argument, and the durable
/// store is opened through `open_existing_store`, which holds only a path and
/// reads through redb's `ReadOnlyDatabase` — a handle with no write path and no
/// committing `Drop`. Nothing is created and no durable byte of the store or of
/// the owner's registry changes. No external owner is touched.
pub fn run_canary_removal_status(store_path: &Path, raw_removal_id: &str) -> i32 {
    let removal_id = match parse_installation_transaction_id(raw_removal_id) {
        Ok(handle) => handle,
        Err(error) => return refuse(STATUS_OPERATION, &error),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return refuse(STATUS_OPERATION, &error),
    };
    let coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.canary_removal_status(&removal_id) {
        Ok(status) => project_removal_status(&status, STATUS_OPERATION),
        Err(error) => refuse(STATUS_OPERATION, &error),
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
) -> i32 {
    let removal_id = match parse_installation_transaction_id(raw_removal_id) {
        Ok(handle) => handle,
        Err(error) => return refuse(RECOVER_OPERATION, &error),
    };
    let store = match open_existing_store(store_path) {
        Ok(store) => store,
        Err(error) => return refuse(RECOVER_OPERATION, &error),
    };
    let registry = match open_retained_registry_writer(host_state_root) {
        Ok(registry) => registry,
        Err(error) => return refuse(RECOVER_OPERATION, &error),
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    match coordinator.recover_canary_removal(&registry, &removal_id) {
        Ok(status) => project_removal_status(&status, RECOVER_OPERATION),
        Err(error) => refuse(RECOVER_OPERATION, &error),
    }
}

/// Decodes the exact removal inputs every canary-removal phase needs.
///
/// The generation becomes a `PlatformHandle`, the request file becomes the
/// explicit authorization, and both owners are opened at their exact existing
/// locations; neither creates a path. The store is opened read-only and the
/// registry is opened as the owner's exclusive redb writer
/// (`open_retained_registry_writer`), so this decode helper is not a
/// byte-preserving read of the owner's registry file even on the plan route. A
/// `PlatformHandle` rejection keeps the same typed `InvalidField` mapping the
/// argument decoders use, so each caller only has to select its own operation
/// tag.
fn open_removal_owners(
    store_path: &Path,
    host_state_root: &Path,
    generation: &str,
    request_path: &Path,
) -> std::result::Result<
    (
        PlatformHandle,
        ManagedEnvironmentChangeRequest,
        RedbInstallationTransactionStore,
        RedbInstallationRegistry,
    ),
    InstallationError,
> {
    let target = PlatformHandle::new(generation.to_owned()).map_err(|error| {
        InstallationError::InvalidField {
            field: "generation".to_owned(),
            reason: error.to_string(),
        }
    })?;
    let request = load_request(request_path)?;
    let store = open_existing_store(store_path)?;
    let registry = open_retained_registry_writer(host_state_root)?;
    Ok((target, request, store, registry))
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
/// The versioned `CanaryRemovalPlanEnvelope` is the only accepted document
/// shape: its fixed contract labels and the embedded plan's own digest are
/// re-validated here by the owner type before the plan leaves this function,
/// and `apply_canary_removal` revalidates that digest and the current
/// revisions again before any destructive call. A bare `CanaryRemovalPlan` is
/// not accepted, because it cannot prove which contract produced it.
fn load_plan(plan_path: &Path) -> std::result::Result<CanaryRemovalPlan, InstallationError> {
    let bytes = load_input(plan_path).map_err(|error| InstallationError::InvalidField {
        field: "plan".to_owned(),
        reason: error.to_string(),
    })?;
    let envelope: CanaryRemovalPlanEnvelope =
        serde_json::from_slice(&bytes).map_err(|error| InstallationError::InvalidField {
            field: "plan".to_owned(),
            reason: format!("plan is not a CanaryRemovalPlanEnvelope: {error}"),
        })?;
    envelope.validate()?;
    Ok(envelope.into_plan())
}

/// Opens the existing durable transaction store without creating one.
///
/// This is the honest counterpart of `open_retained_registry_writer`: the
/// returned store holds only the bound path plus its retained file identity and
/// reads through redb's `ReadOnlyDatabase`, so dropping it commits nothing and
/// the store's bytes are unchanged by any route in this module.
fn open_existing_store(
    store_path: &Path,
) -> std::result::Result<RedbInstallationTransactionStore, InstallationError> {
    RedbInstallationTransactionStore::open_existing_exact_path(store_path)
}

/// Opens the retained installation registry below the Host root as the owner's
/// exclusive redb WRITER handle.
///
/// The handle is a writer, not a reader, and that is a property of the owner
/// seam rather than of this call: `plan_canary_removal` takes the owner's
/// `&RedbInstallationRegistry`, and every constructor of that type holds a redb
/// `Database`. Neither read-only registry entry point the installation crate
/// publishes — `RedbInstallationRegistry::inspect_existing` and
/// `RedbInstallationRegistry::inspect_existing_at` — can be passed to that
/// seam: both return an `ApprovedGenerationRegistry` value rather than the
/// registry handle, so `run_plan_canary_removal` cannot reach either.
///
/// The measured consequence is that opening this handle WRITES to the owner's
/// registry file even when the caller only reads: redb commits a quick-repair
/// transaction that rewrites its own `allocator_state` system table when a
/// `Database` is dropped (redb 4.1.0 `src/db.rs` `impl Drop for Database`). So
/// the read-only routes perform a bounded write of redb's own bookkeeping. It
/// is not a domain mutation: no registry revision advances and no registry row
/// is written. The transaction store is the opposite case and is genuinely
/// non-mutating — `RedbInstallationTransactionStore::open_existing_exact_path`
/// holds only a path and reads through redb's `ReadOnlyDatabase`, whose storage
/// backend has no write path at all.
///
/// Nothing is CREATED here: the registry must already be an existing regular
/// file and an absent child is reported as a typed refusal. The root is only a
/// locator — the lease proves the retained OS identity and the owner
/// cross-checks the accepted manifests, so a foreign root yields a typed
/// refusal, never a wrong-target mutation.
fn open_retained_registry_writer(
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

/// Prints the stable removal disposition through `refuse`, exiting zero only on
/// `Completed`.
///
/// Exit zero alone is never proof: the `removal` object carries the effect
/// identities, the blocking effect, the retained uncertainty and the next
/// permitted action. A projection that cannot be rendered is a typed refusal on
/// `operation`, never a bare `serde_json::Error` escaping through `run()`.
fn project_removal_status(status: &CanaryRemovalStatus, operation: &str) -> i32 {
    match print_removal_status(status, operation) {
        Ok(code) => code,
        Err(error) => refuse(operation, &error),
    }
}

/// Renders one status, or names the member that could not be rendered.
///
/// It returns the owner error type so an unrenderable projection reaches the
/// operator as this route's own `INSTALLATION_REMOVE_CANARY_*` code with a named
/// member, exactly as an unbuildable scope handle does. A bare `serde_json::Error`
/// here would escape through `run()` as anyhow's `Error: ...` with exit 1 and no
/// code at all, which is the one escape hatch these routes must not have.
fn print_removal_status(
    status: &CanaryRemovalStatus,
    operation: &str,
) -> std::result::Result<i32, InstallationError> {
    let completed = status.stage == CanaryRemovalStage::Completed;
    // Each `to_value` is mapped on its own so the refusal names the member that
    // could not be rendered, rather than one opaque error for the whole document.
    let unrenderable = |member: &str, error: serde_json::Error| InstallationError::InvalidField {
        field: format!("removal.{operation}.{member}"),
        reason: format!("the CanaryRemovalStatus projection cannot be serialized: {error}"),
    };
    let stage =
        serde_json::to_value(status.stage).map_err(|error| unrenderable("status", error))?;
    let removal = serde_json::to_value(status).map_err(|error| unrenderable("removal", error))?;
    let document = serde_json::to_string_pretty(&json!({
        "contract": "eliot.kernel.installation",
        "contract_version": INSTALLATION_CONTRACT_VERSION,
        "status": stage,
        "completed": completed,
        "scope": INSTALLATION_SCOPE,
        "removal": removal,
    }))
    .map_err(|error| unrenderable("document", error))?;
    println!("{document}");
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
