//! I3.3/I3.15 ordinary CLI callers of the original installation owner.
//! Request JSON is data. Signed approval, owner/key/root binding and current
//! metadata are independently reopened before admission and every effect.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use eliot_installation::{
    AcceptedCatalogueContext, InstallationTransactionStore, InstallerEffectPlan,
    ManagedChangeOwnerContext, ManagedEnvironmentChangeRequest, ManagedResourceKey,
    RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    WindowsSurveyObservationSource, load_system_owner_initial_snapshot_authority,
    survey_accepted_installation, PlatformHandle,
};

fn platform() -> Result<PlatformHandle> {
    Ok(PlatformHandle::new(format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH))?)
}

fn now_ms() -> Result<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

pub(super) fn survey(store_path: &Path, publication: &str) -> Result<i32> {
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)?;
    let publication = super::parse_installation_transaction_id(publication)?;
    let (anchor, authority) = load_system_owner_initial_snapshot_authority(&store, &publication)?;
    let observed_platform = platform()?;
    let context = AcceptedCatalogueContext {
        store: &store, transaction_id: &publication, anchor: &anchor, authority: &authority,
        observed_platform: &observed_platform, now_ms: now_ms()?,
    };
    let observation = survey_accepted_installation(&context, &WindowsSurveyObservationSource)?;
    println!("{}", serde_json::to_string_pretty(observation.survey())?);
    Ok(0)
}

pub(super) fn change(store_path: &Path, publication: &str, request_path: &Path) -> Result<i32> {
    let request: ManagedEnvironmentChangeRequest = serde_json::from_slice(
        &super::load_input(request_path).context("read the exact managed request")?,
    ).context("decode the strict managed request")?;
    request.validate()?;
    run(store_path, publication, Some(&request), &request.request_id)
}

pub(super) fn resume(store_path: &Path, publication: &str, transaction: &str) -> Result<i32> {
    let transaction = super::parse_installation_transaction_id(transaction)?;
    run(store_path, publication, None, &transaction)
}

fn run(
    store_path: &Path,
    publication: &str,
    request: Option<&ManagedEnvironmentChangeRequest>,
    transaction: &PlatformHandle,
) -> Result<i32> {
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)?;
    let publication = super::parse_installation_transaction_id(publication)?;
    let (anchor, authority) = load_system_owner_initial_snapshot_authority(&store, &publication)?;
    let observed_platform = platform()?;
    let owner = ManagedChangeOwnerContext {
        publication_transaction_id: &publication, anchor: &anchor, authority: &authority,
        observed_platform: &observed_platform,
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store);
    if let Some(request) = request {
        let admitted = coordinator.admit_managed_change(
            &owner, &WindowsSurveyObservationSource, request,
        )?;
        anyhow::ensure!(admitted == *transaction, "the original request identity changed");
    }
    let outcome = coordinator.drive_managed_change_until_blocked(
        &owner, &WindowsSurveyObservationSource, transaction,
    )?;
    println!("{}", serde_json::to_string_pretty(&outcome)?);
    Ok(match outcome {
        eliot_installation::InstallationStepOutcome::Applied { .. } => 0,
        _ => super::INVALID_REQUEST_EXIT,
    })
}

pub(super) fn status(store_path: &Path, transaction: &str) -> Result<i32> {
    let store = RedbInstallationTransactionStore::open_existing_exact_path(store_path)?;
    let transaction_id = super::parse_installation_transaction_id(transaction)?;
    let transaction = store.load(&transaction_id)?.context("original managed transaction absent")?;
    transaction.validate()?;
    let mut requests = transaction.installer_effects.iter().filter_map(|effect| match effect {
        InstallerEffectPlan::ManagedEnvironmentChange { request, .. } => Some(request),
        _ => None,
    });
    let request = requests.next().context("transaction is not a managed change")?;
    anyhow::ensure!(requests.next().is_none(), "managed transaction has conflicting requests");
    let resource = store.managed_resource_projection(&ManagedResourceKey {
        family_id: request.target_family.clone(), exact_candidate: request.exact_candidate.clone(),
    })?;
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "transaction_id": transaction_id,
        "stage": transaction.stage(),
        "resource": resource,
        "pending_external_changes": transaction.pending_external_changes,
        "capability_admission": "requires_current_governor_evidence"
    }))?);
    Ok(0)
}
