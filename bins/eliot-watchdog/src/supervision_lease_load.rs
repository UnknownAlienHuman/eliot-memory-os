//! Fail-closed supervision lease/fence loading for the watchdog composition.
//! Architecture: `A8. Watchdog` (`ELIOT_ARCHITECTURE.md`), `A5.4. Time и State Fence` (`ELIOT_ARCHITECTURE.md`).
//! Implementation: `I8. Watchdog implementation contract` (`ELIOT_IMPLEMENTATION.md`), `I4.5. Generation vector and State Fence` (`ELIOT_IMPLEMENTATION.md`).
//! This module only verifies the current lease against the retained Host journal, Kernel ORS and
//! watchdog publication bundle and re-checks identity/contour after verification. It never mints
//! authority, never selects an alternate current owner, and fails closed on any lease/fence mismatch.

use eliot_installation::RedbInstallationRegistry;
use eliot_platform_windows::{ProtectedRootLease, ProtectedRuntimePathLease, windows_paths_equal};
use eliot_runtime_contracts::{
    SupervisionLeaseIncarnationBinding, SupervisionLeasePredecessorIdentity,
    WATCHDOG_PUBLICATION_DIRECTORY_PREFIX, WATCHDOG_PUBLICATION_RETAINED_LIMIT,
    WatchdogAdmissionTemplate, WatchdogPublicationRetentionPlan,
};

use super::{
    FileWatchdogAdmission, HOST_JOURNAL_FILE_NAME, INSTALLATION_REGISTRY_FILE_NAME, SpoolError,
    VerifiedWatchdogAdmission, WatchdogAdmissionConfig, WatchdogRuntimeBinding, current_unix_ms,
    observe_watchdog_publication, read_manifest_selected_ors_current, scan_watchdog_publications,
    select_runtime_manifest, validate_bound_service_registrations, validate_runtime_binding,
    verify_against_durable_current,
};

fn read_journaled_current_supervision(
    binding: &WatchdogRuntimeBinding,
    template: &WatchdogAdmissionTemplate,
) -> Result<
    (
        SupervisionLeaseIncarnationBinding,
        SupervisionLeasePredecessorIdentity,
    ),
    SpoolError,
> {
    binding
        .host_state_root_lease
        .verify_stable_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Host state root changed: {error}")))?;
    let journal_path = binding.host_state_root().join(HOST_JOURNAL_FILE_NAME);
    let journal_lease = ProtectedRuntimePathLease::open_existing_absolute(&journal_path)
        .map_err(|error| SpoolError::InvalidLease(format!("Host journal open failed: {error}")))?;
    if !windows_paths_equal(journal_lease.path(), &journal_path) {
        return Err(SpoolError::InvalidLease(
            "Host journal path is not the exact retained child".to_owned(),
        ));
    }
    journal_lease
        .verify_stable_identity()
        .and_then(|()| journal_lease.verify_path_identity())
        .map_err(|error| {
            SpoolError::InvalidLease(format!("Host journal identity failed: {error}"))
        })?;
    let inspection = eliot_host_state::RedbJournalBackend::inspect_existing_at(&journal_path)
        .map_err(|error| {
            SpoolError::InvalidLease(format!("Host journal inspection failed: {error}"))
        })?
        .ok_or_else(|| SpoolError::LeaseFenced("Host journal is missing".to_owned()))?;
    let state = eliot_host_state::readonly_project_host_state(&inspection.image)
        .map_err(|error| SpoolError::LeaseFenced(format!("Host journal replay failed: {error}")))?;
    let kernel = state
        .kernel
        .as_ref()
        .filter(|kernel| kernel.state == eliot_runtime_contracts::KernelActivationState::Active)
        .ok_or_else(|| SpoolError::LeaseFenced("Host journal has no active Kernel".to_owned()))?;
    let readiness = state.readiness_observations.last().ok_or_else(|| {
        SpoolError::LeaseFenced("Host journal has no admitted readiness observation".to_owned())
    })?;
    let expected_checksum = eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    )
    .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    if state.prior_kernel_unknown
        || readiness.fence != kernel.fence
        || readiness.active_kernel_record_checksum.as_str() != expected_checksum
    {
        return Err(SpoolError::LeaseFenced(
            "latest readiness is not bound to the current active Kernel".to_owned(),
        ));
    }
    let reconstructed = eliot_host_state::reconstruct_current_supervision_incarnation(
        &state,
        &template.supervision_lease_scope_id,
        &template.observation_scope,
        &template.wake_policy,
    )
    .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    if state.host.installation.as_str()
        != binding
            .selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str()
        || journal_lease.verify_stable_identity().is_err()
        || journal_lease.verify_path_identity().is_err()
        || binding
            .host_state_root_lease
            .verify_stable_identity()
            .is_err()
    {
        return Err(SpoolError::LeaseFenced(
            "Host journal or installation contour changed during read".to_owned(),
        ));
    }
    Ok(reconstructed)
}

#[allow(
    clippy::too_many_lines,
    reason = "the content-addressed admission read keeps registry, Host journal, ORS, publication, signature, retention, and final readback checks ordered"
)]
pub(super) fn load_content_addressed_supervision_lease_bound(
    source: &FileWatchdogAdmission,
    config: &WatchdogAdmissionConfig,
    expected_template_digest: &str,
) -> Result<VerifiedWatchdogAdmission, SpoolError> {
    let binding = &source.binding;
    binding
        .host_state_root_lease
        .verify_stable_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Host state root changed: {error}")))?;
    let expected_registry_path = binding
        .host_state_root()
        .join(INSTALLATION_REGISTRY_FILE_NAME);
    if !windows_paths_equal(&source.registry_path, &expected_registry_path) {
        return Err(SpoolError::InvalidLease(
            "Watchdog registry path is not the exact approved Host child".to_owned(),
        ));
    }
    config
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if config
        .digest()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        != expected_template_digest
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog admission does not match provisioned Phase-B digest".to_owned(),
        ));
    }
    let registry = RedbInstallationRegistry::inspect_existing_at(
        ProtectedRootLease::open_existing(binding.host_state_root()).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root reopen failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let selected_manifest = select_runtime_manifest(&registry, &source.bootstrap)?;
    if selected_manifest != *binding.selected_manifest {
        return Err(SpoolError::InvalidLease(
            "selected runtime contour changed after Watchdog binding".to_owned(),
        ));
    }
    let current_authority = registry
        .provisioned_supervision_authority_for_generation(&selected_manifest.generation)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "selected generation lost its durable supervision authority".to_owned(),
            )
        })?;
    if current_authority != &binding.provisioned_supervision_authority {
        return Err(SpoolError::InvalidLease(
            "selected generation supervision authority changed after binding".to_owned(),
        ));
    }
    let current_template = current_authority
        .watchdog_admission_template()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if &current_template != config
        || current_authority.watchdog_admission_template_digest != expected_template_digest
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog admission is not the durable Phase-B authority projection".to_owned(),
        ));
    }
    validate_bound_service_registrations(
        &registry,
        &selected_manifest,
        &binding.approved_host_registration.request,
        &binding.approved_watchdog_registration,
        &source.bootstrap,
    )?;
    validate_runtime_binding(
        selected_manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str(),
        selected_manifest
            .runtime_launch
            .runtime_state_roots
            .roots_digest
            .as_str(),
        source.installation_id.as_str(),
        source.roots_digest.as_str(),
    )?;
    if config.installation_id != source.installation_id
        || config.approved_generation != selected_manifest.generation.as_str()
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog admission is foreign to the selected generation".to_owned(),
        ));
    }
    let (journaled_incarnation, journaled_supervision) =
        read_journaled_current_supervision(binding, config)?;
    let lease_id =
        eliot_ors::OperationIdentity::new(journaled_supervision.supervision_lease_id.clone())
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let durable_current = read_manifest_selected_ors_current(&selected_manifest, &lease_id)?
        .ok_or_else(|| {
            SpoolError::LeaseFenced("Kernel ORS has no current supervision lease".to_owned())
        })?;
    if durable_current.receipt.receipt_sha256 != journaled_supervision.ors_receipt_sha256 {
        return Err(SpoolError::LeaseFenced(
            "Kernel ORS head is not the exact journaled readiness receipt".to_owned(),
        ));
    }
    let derived_scope_ref = journaled_incarnation
        .derived_scope_ref()
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    let durable_binding = &durable_current.record.binding;
    if durable_current.record.lease_id.as_str() != journaled_incarnation.supervision_lease_id
        || durable_binding.scope_ref.as_str() != derived_scope_ref
        || durable_binding.installation_id.as_str() != journaled_incarnation.installation_id
        || durable_binding.host_epoch.value() != journaled_incarnation.host_epoch.sequence
        || durable_binding.activation_id.as_str() != journaled_incarnation.activation_id
        || durable_binding.activation_generation.value()
            != journaled_incarnation.activation_generation.sequence
        || durable_binding.kernel_epoch.value() != journaled_incarnation.kernel_generation.sequence
        || durable_binding.observation_scope != journaled_incarnation.observation_scope
        || durable_binding.watchdog_epoch.value() != journaled_incarnation.watchdog_epoch.sequence
        || durable_binding.wake_policy != journaled_incarnation.wake_policy
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel ORS head is not bound to the reconstructed Host journal incarnation".to_owned(),
        ));
    }
    let bundle_path = binding.host_state_root().join(format!(
        "{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}",
        durable_current.receipt.receipt_sha256
    ));
    let publication = observe_watchdog_publication(&bundle_path)?;
    if publication.admission != *config
        || publication.lease != durable_current.record.artifact
        || publication.marker.lease_revision != durable_current.record.revision
        || publication.marker.ors_record_id != durable_current.record.record_id.as_str()
        || publication.marker.ors_receipt_sha256 != durable_current.receipt.receipt_sha256
    {
        return Err(SpoolError::LeaseFenced(
            "Watchdog bundle is not the exact current ORS head".to_owned(),
        ));
    }
    let now_ms = current_unix_ms()?;
    let context = durable_current
        .active_verification_context(config.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    let lease = verify_against_durable_current(
        &config.trust_anchor,
        &context,
        &publication.lease,
        Some(durable_current.clone()),
    )?;
    let spool = scan_watchdog_publications(binding.host_state_root())?;
    if spool.len() > WATCHDOG_PUBLICATION_RETAINED_LIMIT {
        return Err(SpoolError::LeaseFenced(
            "Watchdog protected spool exceeds its fixed retention bound".to_owned(),
        ));
    }
    let markers = spool
        .iter()
        .map(|entry| entry.marker.clone())
        .collect::<Vec<_>>();
    let plan = WatchdogPublicationRetentionPlan::for_current(&publication.marker, &markers)
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    if !plan.retired_receipt_digests().is_empty() {
        return Err(SpoolError::LeaseFenced(
            "Watchdog protected spool has unretired non-current bundles".to_owned(),
        ));
    }
    let durable_after = read_manifest_selected_ors_current(&selected_manifest, &lease_id)?;
    let publication_after = observe_watchdog_publication(&bundle_path)?;
    let journaled_after = read_journaled_current_supervision(binding, config)?;
    if durable_after.as_ref() != Some(&durable_current)
        || publication_after != publication
        || journaled_after != (journaled_incarnation, journaled_supervision)
    {
        return Err(SpoolError::LeaseFenced(
            "Watchdog publication or ORS head changed during verification".to_owned(),
        ));
    }
    Ok(VerifiedWatchdogAdmission {
        watchdog_epoch: context.watchdog_epoch,
        lease,
    })
}
