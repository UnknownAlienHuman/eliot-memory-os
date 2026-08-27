//! Supervision evidence verifier — Architecture A13.2/A13.10; Implementation I0.5, bounded FunctionalCapabilityCell/layer-owner-source validation/I16.1.
//! Read-only evidence verification, no lifecycle/SCM/readiness/Store/Kernel authority.

use std::path::{Path, PathBuf};
use std::time::Instant;

use eliot_contracts::sha256_hex;
use eliot_installation::CandidateManifest;
use eliot_runtime_contracts::{
    SUPERVISION_LEASE_FILE_NAME, SignedSupervisionLease, SupervisionLeaseIncarnationBinding,
    SupervisionLeasePredecessorIdentity, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionTrustAnchor, WATCHDOG_ADMISSION_FILE_NAME,
    WATCHDOG_PUBLICATION_DIRECTORY_PREFIX, WATCHDOG_PUBLICATION_FILE_NAME,
    WATCHDOG_PUBLICATION_RETAINED_LIMIT, WatchdogAdmissionTemplate, WatchdogPublicationBundle,
    WatchdogPublicationRetentionPlan,
};

pub(super) fn require_host_monotonic_lease(
    host_state_root: Option<&Path>,
    manifest: Option<&CandidateManifest>,
    now_ms: u64,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("deadline exceeded before monotonic lease verification".to_owned());
    }
    let Some(root) = host_state_root else {
        return Ok(());
    };
    let manifest = manifest.ok_or_else(|| {
        "monotonic lease requires the exact active manifest/Phase-B binding".to_owned()
    })?;
    #[cfg(not(windows))]
    {
        let _ = (root, manifest, now_ms);
        return Err(
            "monotonic lease requires Windows ProtectedRuntimePathLease; wall-clock-only rejected"
                .to_owned(),
        );
    }
    #[cfg(windows)]
    {
        verify_host_supervision_bundle(root, manifest, now_ms, deadline).map(|_| ())
    }
}

#[cfg(windows)]
pub(super) struct VerifiedHostSupervisionBundle {
    pub(super) envelope: SignedSupervisionLease,
    pub(super) trust_anchor: SupervisionTrustAnchor,
    pub(super) context: SupervisionLeaseVerificationContext,
    pub(super) current: eliot_ors::SupervisionLeaseSnapshot,
    incarnation: SupervisionLeaseIncarnationBinding,
    journaled_supervision: SupervisionLeasePredecessorIdentity,
    publication: WatchdogPublicationBundle,
}

#[cfg(windows)]
impl VerifiedHostSupervisionBundle {
    pub(super) fn public_evidence(&self) -> Result<crate::CurrentSupervisionEvidence, String> {
        let incarnation_bytes = serde_json::to_vec(&self.incarnation)
            .map_err(|error| format!("supervision incarnation encoding failed: {error}"))?;
        let context_bytes = serde_json::to_vec(&self.context)
            .map_err(|error| format!("supervision context encoding failed: {error}"))?;
        let publication_bytes = self
            .publication
            .canonical_bytes()
            .map_err(|error| format!("Watchdog publication encoding failed: {error}"))?;
        let evidence = crate::CurrentSupervisionEvidence {
            incarnation: self.incarnation.clone(),
            incarnation_sha256: sha256_hex(&incarnation_bytes),
            ors_state: self.current.record.state,
            ors_projection: self.current.record.projection,
            ors_record_id: self.current.record.record_id.as_str().to_owned(),
            ors_revision: self.current.record.revision,
            ors_receipt_sha256: self.current.receipt.receipt_sha256.clone(),
            lease_payload_sha256: self.current.record.artifact.payload_sha256.clone(),
            lease_envelope_sha256: self
                .current
                .record
                .artifact
                .envelope_digest()
                .map_err(|error| format!("supervision envelope digest failed: {error}"))?,
            trust_anchor_fingerprint: self.trust_anchor.public_key_fingerprint().to_owned(),
            verification_context_sha256: sha256_hex(&context_bytes),
            watchdog_publication_sha256: sha256_hex(&publication_bytes),
        };
        evidence.validate()?;
        if evidence.incarnation.supervision_lease_id
            != self.journaled_supervision.supervision_lease_id
            || evidence.ors_receipt_sha256 != self.journaled_supervision.ors_receipt_sha256
            || evidence.incarnation.supervision_lease_id != self.current.record.lease_id.as_str()
            || evidence.ors_record_id != self.publication.ors_record_id
            || evidence.ors_revision != self.publication.lease_revision
            || evidence.ors_receipt_sha256 != self.publication.ors_receipt_sha256
            || evidence.incarnation.supervision_lease_scope_id
                != self.publication.supervision_lease_scope_id
            || evidence.incarnation.supervision_lease_id != self.publication.supervision_lease_id
        {
            return Err(
                "public supervision evidence does not match journal/ORS/publication".to_owned(),
            );
        }
        Ok(evidence)
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedStatusWatchdogPublication {
    path: PathBuf,
    marker: WatchdogPublicationBundle,
    admission: WatchdogAdmissionTemplate,
    lease: SignedSupervisionLease,
    raw: eliot_platform_windows::OwnedDirectoryObservation,
}

#[cfg(windows)]
fn observe_status_watchdog_publication(
    path: &Path,
) -> Result<ObservedStatusWatchdogPublication, String> {
    let raw = eliot_platform_windows::observe_owned_directory_exact(
        path,
        &[
            WATCHDOG_ADMISSION_FILE_NAME,
            SUPERVISION_LEASE_FILE_NAME,
            WATCHDOG_PUBLICATION_FILE_NAME,
        ],
        crate::WATCHDOG_PUBLICATION_CHILD_LIMIT,
    )
    .map_err(|error| format!("immutable Watchdog publication read failed: {error}"))?;
    let admission_bytes = raw
        .bytes(WATCHDOG_ADMISSION_FILE_NAME)
        .ok_or_else(|| "Watchdog publication has no admission child".to_owned())?;
    let lease_bytes = raw
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| "Watchdog publication has no lease child".to_owned())?;
    let marker_bytes = raw
        .bytes(WATCHDOG_PUBLICATION_FILE_NAME)
        .ok_or_else(|| "Watchdog publication has no marker child".to_owned())?;
    let admission: WatchdogAdmissionTemplate = serde_json::from_slice(admission_bytes)
        .map_err(|error| format!("Watchdog admission parse failed: {error}"))?;
    let lease: SignedSupervisionLease = serde_json::from_slice(lease_bytes)
        .map_err(|error| format!("Watchdog lease parse failed: {error}"))?;
    let marker: WatchdogPublicationBundle = serde_json::from_slice(marker_bytes)
        .map_err(|error| format!("Watchdog marker parse failed: {error}"))?;
    admission
        .validate()
        .map_err(|error| format!("Watchdog admission invalid: {error}"))?;
    lease
        .validate()
        .map_err(|error| format!("Watchdog lease invalid: {error}"))?;
    marker
        .validate()
        .map_err(|error| format!("Watchdog marker invalid: {error}"))?;
    if admission
        .canonical_bytes()
        .map_err(|error| format!("Watchdog admission encoding failed: {error}"))?
        != admission_bytes
        || serde_json::to_vec(&lease)
            .map_err(|error| format!("Watchdog lease encoding failed: {error}"))?
            != lease_bytes
        || marker
            .canonical_bytes()
            .map_err(|error| format!("Watchdog marker encoding failed: {error}"))?
            != marker_bytes
    {
        return Err("Watchdog publication children are not canonical".to_owned());
    }
    marker
        .verify_bytes(admission_bytes, lease_bytes)
        .map_err(|error| format!("Watchdog marker content binding failed: {error}"))?;
    let expected_name = marker
        .directory_name()
        .map_err(|error| format!("Watchdog directory identity invalid: {error}"))?;
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| !name.eq_ignore_ascii_case(&expected_name))
    {
        return Err("Watchdog publication directory is not keyed by its ORS receipt".to_owned());
    }
    Ok(ObservedStatusWatchdogPublication {
        path: path.to_path_buf(),
        marker,
        admission,
        lease,
        raw,
    })
}

#[cfg(windows)]
fn scan_status_watchdog_publications(
    root: &Path,
) -> Result<Vec<ObservedStatusWatchdogPublication>, String> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(root)
        .map_err(|error| format!("Watchdog publication scan failed: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Watchdog publication entry failed: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Watchdog publication child name is not Unicode".to_owned())?;
        if name
            .to_ascii_lowercase()
            .starts_with(WATCHDOG_PUBLICATION_DIRECTORY_PREFIX)
        {
            observed.push(observe_status_watchdog_publication(&entry.path())?);
        }
    }
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(observed)
}

#[cfg(windows)]
fn read_status_journaled_current_supervision(
    root: &Path,
    manifest: &CandidateManifest,
    template: &WatchdogAdmissionTemplate,
) -> Result<
    (
        SupervisionLeaseIncarnationBinding,
        SupervisionLeasePredecessorIdentity,
    ),
    String,
> {
    let journal_path = root.join(crate::HOST_JOURNAL_FILE_NAME);
    let journal_lease =
        eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(&journal_path)
            .map_err(|error| format!("Host journal open failed: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(journal_lease.path(), &journal_path) {
        return Err("Host journal path is not the exact retained child".to_owned());
    }
    journal_lease
        .verify_stable_identity()
        .and_then(|()| journal_lease.verify_path_identity())
        .map_err(|error| format!("Host journal identity failed: {error}"))?;
    let inspection = eliot_host_state::RedbJournalBackend::inspect_existing_at(&journal_path)
        .map_err(|error| format!("Host journal inspection failed: {error}"))?
        .ok_or_else(|| "Host journal is missing".to_owned())?;
    let state = eliot_host_state::readonly_project_host_state(&inspection.image)
        .map_err(|error| format!("Host journal replay failed: {error}"))?;
    let kernel = state
        .kernel
        .as_ref()
        .filter(|kernel| kernel.state == eliot_runtime_contracts::KernelActivationState::Active)
        .ok_or_else(|| "Host journal has no active Kernel".to_owned())?;
    let readiness = state
        .readiness_observations
        .last()
        .ok_or_else(|| "Host journal has no admitted readiness observation".to_owned())?;
    let expected_checksum = eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    )
    .map_err(|error| error.to_string())?;
    if state.prior_kernel_unknown
        || readiness.fence != kernel.fence
        || readiness.active_kernel_record_checksum.as_str() != expected_checksum
        || state.host.installation != manifest.runtime_launch.installation_epoch.installation
    {
        return Err(
            "latest readiness is not bound to the selected current Kernel contour".to_owned(),
        );
    }
    let reconstructed = eliot_host_state::reconstruct_current_supervision_incarnation(
        &state,
        &template.supervision_lease_scope_id,
        &template.observation_scope,
        &template.wake_policy,
    )
    .map_err(|error| error.to_string())?;
    if journal_lease.verify_stable_identity().is_err()
        || journal_lease.verify_path_identity().is_err()
    {
        return Err("Host journal changed during supervision selection".to_owned());
    }
    Ok(reconstructed)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the read-only status verifier keeps registry, Host journal, ORS, publication, signature, retention, and final readback checks ordered"
)]
pub(super) fn verify_host_supervision_bundle(
    root: &Path,
    manifest: &CandidateManifest,
    now_ms: u64,
    deadline: Instant,
) -> Result<VerifiedHostSupervisionBundle, String> {
    if Instant::now() >= deadline {
        return Err("deadline exceeded before supervision bundle verification".to_owned());
    }
    let expected_host_root = Path::new(
        manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    );
    if !eliot_platform_windows::windows_paths_equal(root, expected_host_root) {
        return Err("Host supervision root is not the active manifest root".to_owned());
    }
    let retained_root = eliot_platform_windows::ProtectedRootLease::open_existing(root)
        .map_err(|error| format!("Host supervision root open failed: {error}"))?;
    let canonical_root = retained_root
        .canonical_path()
        .map_err(|error| format!("Host supervision root resolve failed: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(&canonical_root, root) {
        return Err("Host supervision root is not the exact retained root".to_owned());
    }
    retained_root
        .verify_stable_identity()
        .map_err(|error| format!("Host supervision root changed: {error}"))?;

    let registry = eliot_installation::RedbInstallationRegistry::inspect_existing_at(
        eliot_platform_windows::ProtectedRootLease::open_existing(&canonical_root)
            .map_err(|error| format!("Host registry root reopen failed: {error}"))?,
    )
    .map_err(|error| format!("Host registry read failed: {error}"))?
    .ok_or_else(|| "Host registry is missing".to_owned())?;
    registry
        .validate()
        .map_err(|error| format!("Host registry invalid: {error}"))?;
    if !registry
        .generations()
        .iter()
        .any(|generation| generation.manifest == *manifest)
    {
        return Err("requested manifest is not the exact durable registry generation".to_owned());
    }
    let authority = registry
        .provisioned_supervision_authority_for_generation(&manifest.generation)
        .map_err(|error| format!("Phase-B supervision authority invalid: {error}"))?
        .cloned()
        .ok_or_else(|| "generation has no durable provisioned supervision authority".to_owned())?;
    authority
        .validate()
        .map_err(|error| format!("Phase-B supervision authority invalid: {error}"))?;
    let admission = authority
        .watchdog_admission_template()
        .map_err(|error| format!("Phase-B Watchdog admission invalid: {error}"))?;
    if admission
        .digest()
        .map_err(|error| format!("Phase-B Watchdog admission digest failed: {error}"))?
        != authority.watchdog_admission_template_digest
    {
        return Err("Phase-B Watchdog admission digest mismatch".to_owned());
    }

    let ors_path = PathBuf::from(
        manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join("kernel-ors.redb");
    let ors = eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(&ors_path)
        .map_err(|error| format!("manifest-selected ORS unavailable: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(ors.path(), &ors_path) {
        return Err("retained Kernel ORS path is not exact".to_owned());
    }
    ors.verify_stable_identity()
        .and_then(|()| ors.verify_path_identity())
        .map_err(|error| format!("retained Kernel ORS identity failed: {error}"))?;
    let (journaled_incarnation, journaled_supervision) =
        read_status_journaled_current_supervision(&canonical_root, manifest, &admission)?;
    let lease_id =
        eliot_ors::OperationIdentity::new(journaled_supervision.supervision_lease_id.clone())
            .map_err(|error| format!("supervision lease identity invalid: {error}"))?;
    let current = eliot_ors::read_current_supervision_lease_read_only(ors.path(), &lease_id)
        .map_err(|error| format!("current supervision ORS read failed: {error}"))?
        .ok_or_else(|| "current supervision ORS record is missing".to_owned())?;
    current
        .validate()
        .map_err(|error| format!("current supervision ORS snapshot invalid: {error}"))?;
    if current.receipt.receipt_sha256 != journaled_supervision.ors_receipt_sha256 {
        return Err(
            "current supervision ORS head is not the journaled readiness receipt".to_owned(),
        );
    }
    let derived_scope_ref = journaled_incarnation
        .derived_scope_ref()
        .map_err(|error| format!("journaled supervision scope is invalid: {error}"))?;
    let current_binding = &current.record.binding;
    if current.record.lease_id.as_str() != journaled_incarnation.supervision_lease_id
        || current_binding.scope_ref.as_str() != derived_scope_ref
        || current_binding.installation_id.as_str() != journaled_incarnation.installation_id
        || current_binding.host_epoch.value() != journaled_incarnation.host_epoch.sequence
        || current_binding.activation_id.as_str() != journaled_incarnation.activation_id
        || current_binding.activation_generation.value()
            != journaled_incarnation.activation_generation.sequence
        || current_binding.kernel_epoch.value() != journaled_incarnation.kernel_generation.sequence
        || current_binding.observation_scope != journaled_incarnation.observation_scope
        || current_binding.watchdog_epoch.value() != journaled_incarnation.watchdog_epoch.sequence
        || current_binding.wake_policy != journaled_incarnation.wake_policy
    {
        return Err(
            "current supervision ORS head is not bound to the reconstructed Host journal incarnation"
                .to_owned(),
        );
    }

    let publication_path = canonical_root.join(format!(
        "{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}",
        current.receipt.receipt_sha256
    ));
    let publication = observe_status_watchdog_publication(&publication_path)?;
    let lease_bytes = publication
        .raw
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| "Watchdog publication lost its lease child".to_owned())?;
    let expected_marker = WatchdogPublicationBundle::new(
        &admission,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        lease_bytes,
    )
    .map_err(|error| format!("expected Watchdog marker invalid: {error}"))?;
    if publication.admission != admission
        || publication.lease != current.record.artifact
        || publication.marker != expected_marker
    {
        return Err("published Watchdog bundle is not the exact current ORS head".to_owned());
    }

    let context = current
        .active_verification_context(authority.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| format!("current supervision ORS binding invalid: {error}"))?;
    authority
        .trust_anchor
        .verify(&publication.lease, &context)
        .map_err(|error| format!("current supervision signature/freshness failed: {error}"))?;

    let spool = scan_status_watchdog_publications(&canonical_root)?;
    if spool.len() > WATCHDOG_PUBLICATION_RETAINED_LIMIT {
        return Err("Watchdog protected spool exceeds its fixed retention bound".to_owned());
    }
    let markers = spool
        .iter()
        .map(|entry| entry.marker.clone())
        .collect::<Vec<_>>();
    let plan = WatchdogPublicationRetentionPlan::for_current(&publication.marker, &markers)
        .map_err(|error| format!("Watchdog protected spool is invalid: {error}"))?;
    if !plan.retired_receipt_digests().is_empty() {
        return Err("Watchdog protected spool has unretired non-current bundles".to_owned());
    }

    if Instant::now() >= deadline {
        return Err("deadline exceeded during supervision bundle verification".to_owned());
    }
    let registry_after = eliot_installation::RedbInstallationRegistry::inspect_existing_at(
        eliot_platform_windows::ProtectedRootLease::open_existing(&canonical_root)
            .map_err(|error| format!("Host registry final reopen failed: {error}"))?,
    )
    .map_err(|error| format!("Host registry final read failed: {error}"))?
    .ok_or_else(|| "Host registry disappeared during verification".to_owned())?;
    registry_after
        .validate()
        .map_err(|error| format!("Host registry final state invalid: {error}"))?;
    let authority_after = registry_after
        .provisioned_supervision_authority_for_generation(&manifest.generation)
        .map_err(|error| format!("Phase-B authority final read invalid: {error}"))?
        .ok_or_else(|| "Phase-B authority disappeared during verification".to_owned())?;
    let current_after = eliot_ors::read_current_supervision_lease_read_only(ors.path(), &lease_id)
        .map_err(|error| format!("current supervision ORS re-read failed: {error}"))?;
    let publication_after = observe_status_watchdog_publication(&publication_path)?;
    let journaled_after =
        read_status_journaled_current_supervision(&canonical_root, manifest, &admission)?;
    if authority_after != &authority
        || current_after.as_ref() != Some(&current)
        || publication_after != publication
        || journaled_after.0 != journaled_incarnation
        || journaled_after.1 != journaled_supervision
        || retained_root.verify_stable_identity().is_err()
        || ors.verify_stable_identity().is_err()
        || ors.verify_path_identity().is_err()
    {
        return Err("registry, ORS, or immutable publication changed during read".to_owned());
    }

    Ok(VerifiedHostSupervisionBundle {
        envelope: publication.lease,
        trust_anchor: authority.trust_anchor,
        context,
        current,
        incarnation: journaled_incarnation,
        journaled_supervision,
        publication: publication.marker,
    })
}
