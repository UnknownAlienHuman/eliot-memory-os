use super::{
    CandidateManifest, DirectoryPublicationError, DirectoryPublicationOutcome, HostError,
    OperationIdentity, OwnedDirectoryPublication, OwnedDirectoryRetirementOutcome, Path, PathBuf,
    PlatformHandle, ProtectedRuntimePathLease, PublishedSupervisionIdentity, Read,
    SUPERVISION_LEASE_FILE_NAME, Seek, SupervisionLeaseVerifier, SystemTime, UNIX_EPOCH,
    WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_FILE_NAME,
    WATCHDOG_PUBLICATION_RETAINED_LIMIT, WatchdogAdmissionTemplate, WatchdogPublicationBundle,
    WatchdogPublicationRetentionPlan, Write, retire_owned_directory_exact, sha256_json,
    windows_paths_equal,
};

#[cfg(windows)]
mod observation;
#[cfg(windows)]
#[allow(unused_imports)]
pub(super) use observation::{
    HostWatchdogPublicationObservation, observe_host_watchdog_publication,
    verify_exact_current_watchdog_publication,
};
#[cfg(windows)]
use observation::{decode_watchdog_publication_observation, scan_host_watchdog_publications};

// F-LOG-HOST-4 (#979) publication helpers.
//
// Through the #889 facade only
// (`super::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`super::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner through ONE closed typed observation
// (`WatchdogPublicationObservation` + `watchdog_publication_render_bound`,
// which the decoding child also uses, so there is no second emitter and no
// second bounding scheme). Each record carries the exact installation,
// approved generation, supervision lease scope, activation, lease, ORS record,
// ORS receipt, publication digest, lease revision and retained count the owner
// already holds at that boundary; an identity the owner does not hold stays an
// explicit unavailable field rather than a static sentence pretending to be an
// identity, so two concurrent publications can never share one record (I7.20).
// Never a digest over secret-bearing bytes, a raw path, lease/nonce material,
// credential or key material, argv, or arbitrary `Debug`/serde error text, so
// bounding limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache and no
// terminal guard here: the single designated terminal per failed operation
// stays with the outer #891/#893 operation that owns the failure decision;
// these phase observations never emit a terminal. A bare `?` on an
// already-observed inner boundary propagates without a second record.
#[cfg(windows)]
fn watchdog_publication_note_event_log_unavailable() {
    let _ = super::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn watchdog_publication_observe(detail: &str) {
    watchdog_publication_note_event_log_unavailable();
    super::host_diagnostics::observe_entrypoint_with_detail(
        super::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

/// The explicit disposition of one publication identity this boundary does
/// not hold (F-LOG-HOST-4, #979).
///
/// It stays a real slot value in the record: never a fabricated, defaulted,
/// recomputed, or statically-worded stand-in for an identity the owner never
/// produced, so a reader can always tell an absent identity from a present
/// one.
#[cfg(windows)]
const WATCHDOG_PUBLICATION_IDENTITY_UNAVAILABLE: &str = "unavailable";

/// The closed set of nonsecret publication identities this owner may bind to
/// one Watchdog publication observation (F-LOG-HOST-4, #979).
///
/// Every slot is either the exact value the semantic owner already produced
/// for the live admission template, the current ORS supervision head, the
/// decoded publication marker, the observed spool entry, or the projected
/// `PublishedSupervisionIdentity`, or the explicit
/// [`WATCHDOG_PUBLICATION_IDENTITY_UNAVAILABLE`] disposition. Never signed
/// lease bytes, the registration nonce, credential or key material, argv, a
/// raw destination path, or arbitrary `Debug`/serde error text, so bounding
/// limits size, not sensitivity (I15.4). Temporal adjacency alone can never
/// tell two concurrent publications apart, so the identities travel with the
/// label (I7.20 same-operation rule).
#[cfg(windows)]
struct WatchdogPublicationObservation<'a> {
    label: &'static str,
    install: Option<&'a str>,
    generation: Option<&'a str>,
    scope: Option<&'a str>,
    activation: Option<&'a str>,
    lease: Option<&'a str>,
    record: Option<&'a str>,
    receipt: Option<&'a str>,
    publication: Option<&'a str>,
    revision: Option<u64>,
    /// How many publications this owner currently retains, where the boundary
    /// observes a whole set rather than one publication.
    retained: Option<u64>,
}

#[cfg(windows)]
impl<'a> WatchdogPublicationObservation<'a> {
    /// The observation of a boundary reached before this owner holds any
    /// publication identity at all.
    fn unavailable(label: &'static str) -> Self {
        Self {
            label,
            install: None,
            generation: None,
            scope: None,
            activation: None,
            lease: None,
            record: None,
            receipt: None,
            publication: None,
            revision: None,
            retained: None,
        }
    }

    /// Binds how many publications the owner retains, for a boundary that
    /// observes a whole spool rather than one publication.
    fn with_retained(mut self, retained: u64) -> Self {
        self.retained = Some(retained);
        self
    }

    /// Binds the installation and activation identities the live obligation
    /// census was asked about, before any spool entry is decoded.
    fn for_requested(
        label: &'static str,
        installation: &'a PlatformHandle,
        activation: &'a PlatformHandle,
    ) -> Self {
        Self {
            label,
            install: Some(installation.as_str()),
            activation: Some(activation.as_str()),
            ..Self::unavailable(label)
        }
    }

    /// Binds the validated admission template identities.
    fn for_template(label: &'static str, template: &'a WatchdogAdmissionTemplate) -> Self {
        Self {
            install: Some(template.installation_id.as_str()),
            generation: Some(template.approved_generation.as_str()),
            scope: Some(template.supervision_lease_scope_id.as_str()),
            ..Self::unavailable(label)
        }
    }

    /// Binds the approved manifest identities of a read that has not yet
    /// produced an ORS head.
    fn for_manifest(label: &'static str, manifest: &'a CandidateManifest) -> Self {
        Self {
            install: Some(
                manifest
                    .runtime_launch
                    .installation_epoch
                    .installation
                    .as_str(),
            ),
            generation: Some(manifest.generation.as_str()),
            scope: Some(manifest.runtime_launch.supervision_lease_scope_id()),
            ..Self::unavailable(label)
        }
    }

    /// Binds the exact current ORS supervision head the owner already read
    /// and validated. The snapshot's own recorded values are copied; no
    /// digest is recomputed here.
    fn with_current(mut self, current: &'a eliot_ors::SupervisionLeaseSnapshot) -> Self {
        self.lease = Some(current.record.lease_id.as_str());
        self.record = Some(current.record.record_id.as_str());
        self.receipt = Some(current.receipt.receipt_sha256.as_str());
        self.revision = Some(current.record.revision);
        self
    }

    /// Binds the admission template plus the exact current ORS supervision
    /// head, which between them carry every publication identity the owner
    /// holds: the publication digest is a projection over the marker this pair
    /// already produces, never a value this module recomputes.
    fn for_snapshot(
        label: &'static str,
        template: &'a WatchdogAdmissionTemplate,
        current: &'a eliot_ors::SupervisionLeaseSnapshot,
    ) -> Self {
        Self::for_template(label, template).with_current(current)
    }

    /// Binds the content-addressed publication marker the owner holds. The
    /// marker carries no publication digest of its own, so that slot stays
    /// explicitly unavailable instead of being recomputed here.
    fn for_marker(label: &'static str, marker: &'a WatchdogPublicationBundle) -> Self {
        Self {
            install: Some(marker.installation_id.as_str()),
            generation: Some(marker.approved_generation.as_str()),
            scope: Some(marker.supervision_lease_scope_id.as_str()),
            lease: Some(marker.supervision_lease_id.as_str()),
            record: Some(marker.ors_record_id.as_str()),
            receipt: Some(marker.ors_receipt_sha256.as_str()),
            revision: Some(marker.lease_revision),
            ..Self::unavailable(label)
        }
    }

    /// Binds the publication marker plus the exact retained ORS receipt
    /// digest this retirement step targets.
    fn for_retired(
        label: &'static str,
        marker: &'a WatchdogPublicationBundle,
        retired_receipt: &'a str,
    ) -> Self {
        Self {
            receipt: Some(retired_receipt),
            ..Self::for_marker(label, marker)
        }
    }

    /// Binds the requested obligation identities plus the decoded spool
    /// entry's marker, and the lease identity only once the owner has proved
    /// it usable.
    fn for_obligation(
        label: &'static str,
        installation: &'a PlatformHandle,
        activation: &'a PlatformHandle,
        lease: Option<&'a str>,
        observed: &'a HostWatchdogPublicationObservation,
    ) -> Self {
        let mut observation = Self::for_marker(label, &observed.marker);
        observation.install = Some(installation.as_str());
        observation.activation = Some(activation.as_str());
        observation.lease = lease;
        observation
    }

    /// Binds the exact three-identity published supervision record the owner
    /// just projected. Its fields are copied, never re-derived.
    fn for_published(
        label: &'static str,
        identity: &'a PublishedSupervisionIdentity,
    ) -> Self {
        Self {
            lease: Some(identity.lease_id.as_str()),
            receipt: Some(identity.ors_receipt_digest.as_str()),
            publication: Some(identity.publication_digest.as_str()),
            ..Self::unavailable(label)
        }
    }
}

/// Renders one identity-bound Watchdog publication detail and hands it to
/// `emit`.
///
/// The frozen boundary label stays first so label-prefix consumers keep
/// matching; the closed identity slots follow as `key=value` pairs, each
/// individually bounded by the facade helper. An identity the owner does not
/// hold renders the explicit unavailable disposition in its own slot, so no
/// slot can be read as an identity this boundary never produced. The whole
/// detail is bounded by the facade with its truncation honesty record. This is
/// the one bounding scheme for the family: the decoding child renders through
/// it too, so it never introduces a second emitter.
#[cfg(windows)]
fn watchdog_publication_render_bound(
    observation: &WatchdogPublicationObservation<'_>,
    emit: impl FnOnce(&str),
) {
    let mut detail = String::from(observation.label);
    for (key, value) in [
        ("install", observation.install),
        ("gen", observation.generation),
        ("scope", observation.scope),
        ("activation", observation.activation),
        ("lease", observation.lease),
        ("record", observation.record),
        ("receipt", observation.receipt),
        ("pub", observation.publication),
    ] {
        detail.push(' ');
        detail.push_str(key);
        detail.push('=');
        detail.push_str(match value {
            Some(text) => super::host_diagnostics::bound_field(text).text(),
            None => WATCHDOG_PUBLICATION_IDENTITY_UNAVAILABLE,
        });
    }
    for (key, value) in [
        ("rev", observation.revision),
        ("retained", observation.retained),
    ] {
        detail.push(' ');
        detail.push_str(key);
        detail.push('=');
        match value {
            Some(number) => {
                detail.push_str(&number.to_string());
            }
            None => detail.push_str(WATCHDOG_PUBLICATION_IDENTITY_UNAVAILABLE),
        }
    }
    emit(&detail);
}

/// Emits one identity-bound Watchdog publication observation through the
/// #889 facade.
#[cfg(windows)]
fn watchdog_publication_observe_bound(observation: &WatchdogPublicationObservation<'_>) {
    watchdog_publication_render_bound(observation, watchdog_publication_observe);
}

#[cfg(windows)]
const WATCHDOG_PUBLICATION_CHILD_LIMIT: u64 = 1024 * 1024;
#[cfg(windows)]
const KERNEL_ORS_FILE_NAME: &str = "kernel-ors.redb";
#[cfg(windows)]
pub(super) fn write_watchdog_publication_child(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_SHARE_READ,
    };

    if bytes.len() as u64 > WATCHDOG_PUBLICATION_CHILD_LIMIT {
        // WORK_UNIT_CASE: 979/4 — oversize child, bounded identity preserved.
        // The child writer holds no admission, ORS or publication identity of
        // its own, so every slot stays explicitly unavailable.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child oversize rejected",
        ));
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child exceeds the bounded size".to_owned(),
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
        .open(path)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — child create/open boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
                "watchdog.publication child write failed",
            ));
            HostError::RecoveryRequired(error.to_string())
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — child write/sync boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
                "watchdog.publication child write failed",
            ));
            HostError::RecoveryRequired(error.to_string())
        })?;
    let metadata = file.metadata().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child metadata boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child write failed",
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    if !metadata.is_file()
        || metadata.len() != bytes.len() as u64
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        // WORK_UNIT_CASE: 979/4 — invalid child identity, never committed.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child identity rejected",
        ));
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child identity is invalid".to_owned(),
        ));
    }
    file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback seek boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child write failed",
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let mut readback = Vec::with_capacity(bytes.len());
    file.read_to_end(&mut readback).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback read boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child write failed",
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    if readback != bytes {
        // WORK_UNIT_CASE: 979/4 — readback changed, exact identity preserved by rejection.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
            "watchdog.publication child readback changed",
        ));
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child readback changed".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — child written with exact readback identity.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::unavailable(
        "watchdog.publication child committed",
    ));
    Ok(())
}

#[cfg(windows)]
pub(super) fn read_manifest_current_supervision_lease(
    manifest: &CandidateManifest,
    lease_id: &str,
) -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError> {
    let lease_id = OperationIdentity::new(lease_id.to_owned()).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unusable lease identity, never read.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
            "watchdog.publication lease identity rejected",
            manifest,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let ors_path = PathBuf::from(
        manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join(KERNEL_ORS_FILE_NAME);
    let retained =
        ProtectedRuntimePathLease::open_existing_absolute(&ors_path).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unopenable ORS, no head observed.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
                "watchdog.publication ORS open failed",
                manifest,
            ));
            HostError::RecoveryRequired(format!("Kernel ORS open failed: {error}"))
        })?;
    if !windows_paths_equal(retained.path(), &ors_path) {
        // WORK_UNIT_CASE: 979/3 — conflicting ORS selection, never read.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
            "watchdog.publication ORS selection conflicting",
            manifest,
        ));
        return Err(HostError::RecoveryRequired(
            "Kernel ORS path is not the manifest-selected child".to_owned(),
        ));
    }
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed before the read.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
                "watchdog.publication ORS identity changed",
                manifest,
            ));
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    let current = eliot_ors::read_current_supervision_lease_read_only(retained.path(), &lease_id)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unreadable ORS, no head observed.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
                "watchdog.publication ORS read failed",
                manifest,
            ));
            HostError::RecoveryRequired(format!("Kernel ORS read failed: {error}"))
        })?
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent ORS head, never ready/current.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
                "watchdog.publication ORS head absent",
                manifest,
            ));
            HostError::RecoveryRequired("Kernel ORS has no current supervision lease".to_owned())
        })?;
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed across the read.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
                "watchdog.publication ORS identity changed",
                manifest,
            ));
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    current.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid ORS snapshot, never ready/current.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
            "watchdog.publication ORS snapshot validation rejected",
            manifest,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    // WORK_UNIT_CASE: 979/2 — owner-observed exact current ORS supervision head.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_manifest(
        "watchdog.publication ORS head read",
        manifest,
    )
    .with_current(&current));
    Ok(current)
}

/// Returns the exact Kernel-signed supervision lease that still owes coverage
/// for `activation_id`, or `None` when no published lease is live for it.
///
/// I1.5 idle-drain gate: "Idle drain starts only when no `RuntimeLease` remains
/// and no valid `SupervisionLease` requires live sensing/containment". This is
/// the read-only half of the same publisher/decoder pair that commits the
/// publication, so the census never introduces a second reader of a
/// Watchdog-owned file, a second signature policy, or a second copy of the
/// publication schema. Coverage ends honestly at `expires_at_ms`: a lease that
/// cannot prove renewal stops blocking drain instead of blocking it forever,
/// while a terminal (`EXPIRED`/`REVOKED`/`CLOSED`) lease never blocked at all.
#[cfg(windows)]
pub(super) fn live_supervision_obligation(
    host_state_root: &Path,
    installation: &PlatformHandle,
    activation_id: &PlatformHandle,
    now_ms: u64,
) -> Result<Option<PlatformHandle>, HostError> {
    // `?` propagates the already-observed inner scan boundary; no second record.
    for observation in scan_host_watchdog_publications(host_state_root)? {
        let payload = &observation.lease.payload;
        if payload.installation_id != installation.as_str()
            || payload.scope_ref != observation.admission.supervision_lease_scope_id
            || observation.admission.installation_id != payload.installation_id
            || payload.activation_id != activation_id.as_str()
        {
            // A publication bound to a different installation, scope or
            // activation generation is a stale spool entry, never a live
            // obligation for this generation.
            continue;
        }
        if payload.state != eliot_runtime_contracts::LeaseState::Active
            || now_ms >= payload.expires_at_ms
        {
            continue;
        }
        return PlatformHandle::new(payload.lease_id.clone())
            .inspect(|lease| {
                // WORK_UNIT_CASE: 979/2 — live supervision obligation observed.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_obligation(
                    "watchdog.publication live obligation observed",
                    installation,
                    activation_id,
                    Some(lease.as_str()),
                    &observation,
                ));
            })
            .map(Some)
            .map_err(|error| {
                // WORK_UNIT_CASE: 979/4 — unusable live lease identity, never reported.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_obligation(
                    "watchdog.publication lease identity rejected",
                    installation,
                    activation_id,
                    None,
                    &observation,
                ));
                HostError::RecoveryRequired(error.to_string())
            });
    }
    // WORK_UNIT_CASE: 979/2 — no live supervision obligation; stale spool is not coverage.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_requested(
        "watchdog.publication no live obligation",
        installation,
        activation_id,
    ));
    Ok(None)
}

#[cfg(windows)]
pub(super) fn supervision_publication_identity(
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unserializable lease, identity unprojected.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication identity serialization rejected",
            template,
            current,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unbindable marker, identity unprojected.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication identity binding rejected",
            template,
            current,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let identity = PublishedSupervisionIdentity {
        lease_id: PlatformHandle::new(current.record.lease_id.as_str()).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication identity handle rejected",
                template,
                current,
            ));
            HostError::Platform(error.to_string())
        })?,
        ors_receipt_digest: PlatformHandle::new(current.receipt.receipt_sha256.clone()).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                    "watchdog.publication identity handle rejected",
                    template,
                    current,
                ));
                HostError::Platform(error.to_string())
            },
        )?,
        publication_digest: PlatformHandle::new(sha256_json(&marker)?).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication identity handle rejected",
                template,
                current,
            ));
            HostError::Platform(error.to_string())
        })?,
    };
    // WORK_UNIT_CASE: 979/4 — publication identity projected with exact digests.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_published(
        "watchdog.publication identity projected",
        &identity,
    ));
    Ok(identity)
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "immutable Watchdog publication keeps ORS verification, marker-last creation, atomic commit, readback, and bounded retirement ordered"
)]
pub(super) fn publish_current_watchdog_supervision_bundle(
    host_state_root: &Path,
    manifest: &CandidateManifest,
    template: &WatchdogAdmissionTemplate,
    expected_template_digest: &str,
    kernel_snapshot: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    // WORK_UNIT_CASE: 979/2 — publication requested, distinct from owner-observed.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
        "watchdog.publication requested",
        template,
        kernel_snapshot,
    ));
    template.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid template, never published.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_template(
            "watchdog.publication template validation rejected",
            template,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    if template.digest().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — template digest boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_template(
            "watchdog.publication template validation rejected",
            template,
        ));
        HostError::RecoveryRequired(error.to_string())
    })? != expected_template_digest
    {
        // WORK_UNIT_CASE: 979/3 — conflicting provisioned template, never published.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_template(
            "watchdog.publication template digest conflicting",
            template,
        ));
        return Err(HostError::RecoveryRequired(
            "Watchdog admission template does not match the provisioned Phase-B digest".to_owned(),
        ));
    }
    // `?` propagates the already-observed inner ORS-head boundary; no second record.
    let current = read_manifest_current_supervision_lease(
        manifest,
        kernel_snapshot.record.lease_id.as_str(),
    )?;
    if current != *kernel_snapshot {
        // WORK_UNIT_CASE: 979/3 — stale ProbeReady snapshot, never published.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication snapshot stale",
            template,
            &current,
        ));
        return Err(HostError::RecoveryRequired(
            "Kernel ProbeReady supervision snapshot is not the current ORS head".to_owned(),
        ));
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication clock unavailable",
                template,
                &current,
            ));
            HostError::RecoveryRequired(error.to_string())
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication clock unavailable",
                template,
                &current,
            ));
            HostError::RecoveryRequired("system time exceeds u64".to_owned())
        })?;
    let verification_context = current
        .active_verification_context(template.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverifiable snapshot, never published.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication verification context rejected",
                template,
                &current,
            ));
            HostError::RecoveryRequired(error.to_string())
        })?;
    template
        .trust_anchor
        .verify(&current.record.artifact, &verification_context)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverified lease, never published.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication lease verification rejected",
                template,
                &current,
            ));
            HostError::RecoveryRequired(error.to_string())
        })?;
    let admission_bytes = template.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication bundle serialization rejected",
            template,
            &current,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication bundle serialization rejected",
            template,
            &current,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker = WatchdogPublicationBundle::new(
        template,
        current.record.revision,
        current.record.record_id.as_str(),
        current.receipt.receipt_sha256.clone(),
        &lease_bytes,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle binding boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
            "watchdog.publication bundle binding rejected",
            template,
            &current,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker_bytes = marker.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
            "watchdog.publication bundle serialization rejected",
            &marker,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?;
    let destination = host_state_root.join(marker.directory_name().map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — directory name not derivable, identity unproven.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
            "watchdog.publication directory name rejected",
            &marker,
        ));
        HostError::RecoveryRequired(error.to_string())
    })?);

    match OwnedDirectoryPublication::create(&destination) {
        Ok(publication) => {
            let temporary = publication.temporary_path().to_path_buf();
            write_watchdog_publication_child(
                &temporary.join(WATCHDOG_ADMISSION_FILE_NAME),
                &admission_bytes,
            )?;
            write_watchdog_publication_child(
                &temporary.join(SUPERVISION_LEASE_FILE_NAME),
                &lease_bytes,
            )?;
            // Marker is created last inside the still-unpublished directory.
            write_watchdog_publication_child(
                &temporary.join(WATCHDOG_PUBLICATION_FILE_NAME),
                &marker_bytes,
            )?;
            let precommit = eliot_platform_windows::observe_owned_directory_exact(
                &temporary,
                &[
                    WATCHDOG_ADMISSION_FILE_NAME,
                    SUPERVISION_LEASE_FILE_NAME,
                    WATCHDOG_PUBLICATION_FILE_NAME,
                ],
                WATCHDOG_PUBLICATION_CHILD_LIMIT,
            )
            .map_err(|error| {
                // WORK_UNIT_CASE: 979/3 — unreadable precommit directory, never committed.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                    "watchdog.publication precommit unreadable",
                    &marker,
                ));
                HostError::RecoveryRequired(error.to_string())
            })?;
            // `?` propagates the already-observed inner decode/verify boundaries.
            let decoded = decode_watchdog_publication_observation(&temporary, &precommit, false)?;
            verify_exact_current_watchdog_publication(&decoded, template, &current)?;
            if precommit.directory_identity != publication.temporary_identity() {
                // WORK_UNIT_CASE: 979/3 — changed temporary identity, never committed.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                    "watchdog.publication temporary identity changed",
                    &marker,
                ));
                return Err(HostError::RecoveryRequired(
                    "Watchdog publication temporary directory identity changed".to_owned(),
                ));
            }
            // A concurrent exact replay may win the create-new name, and a
            // committed-unknown move may already own it. Neither outcome is
            // authority until the exact retained readback below succeeds.
            match publication.publish(precommit.directory_identity) {
                Ok(DirectoryPublicationOutcome::Published(_)) => {
                    // WORK_UNIT_CASE: 979/2 — directory committed, pending retained readback.
                    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                        "watchdog.publication committed",
                        &marker,
                    ));
                }
                Ok(DirectoryPublicationOutcome::CommittedUnknown(_)) => {
                    // WORK_UNIT_CASE: 979/7 — commit outcome unknown; readback below decides.
                    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                        "watchdog.publication commit unknown",
                        &marker,
                    ));
                }
                Err(DirectoryPublicationError::AlreadyExists) => {
                    // WORK_UNIT_CASE: 979/8 — concurrent exact replay retained, no new publication.
                    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                        "watchdog.publication replay retained",
                        &marker,
                    ));
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 979/1 — directory commit boundary.
                    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                        "watchdog.publication commit rejected",
                        &marker,
                    ));
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog directory publication failed before commit: {error}"
                    )));
                }
            }
        }
        Err(DirectoryPublicationError::AlreadyExists) => {
            // WORK_UNIT_CASE: 979/8 — concurrent exact replay retained, no new publication.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                "watchdog.publication replay retained",
                &marker,
            ));
        }
        Err(error) => {
            // WORK_UNIT_CASE: 979/1 — directory preparation boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                "watchdog.publication preparation failed",
                &marker,
            ));
            return Err(HostError::RecoveryRequired(format!(
                "Watchdog directory preparation failed: {error}"
            )));
        }
    }

    // `?` propagates the already-observed inner readback/verify/reread boundaries.
    let published = observe_host_watchdog_publication(&destination)?;
    verify_exact_current_watchdog_publication(&published, template, &current)?;
    if read_manifest_current_supervision_lease(manifest, kernel_snapshot.record.lease_id.as_str())?
        != current
    {
        // WORK_UNIT_CASE: 979/3 — ORS head changed across publication, never current.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
            "watchdog.publication ORS head changed",
            &marker,
        ));
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed during Watchdog publication".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — retained publication read back as the exact current head.
    watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
        "watchdog.publication observed",
        &published.marker,
    ));

    // Retirement begins only after the new exact current bundle is durable.
    let observed = scan_host_watchdog_publications(host_state_root)?;
    let markers = observed
        .iter()
        .map(|bundle| bundle.marker.clone())
        .collect::<Vec<_>>();
    let plan =
        WatchdogPublicationRetentionPlan::for_current(&marker, &markers).map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — retention plan boundary.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
                "watchdog.publication retention plan rejected",
                &marker,
            ));
            HostError::RecoveryRequired(error.to_string())
        })?;
    for digest in plan.retired_receipt_digests() {
        if digest == &current.receipt.receipt_sha256 {
            // WORK_UNIT_CASE: 979/4 — current bundle protected from retirement.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_retired(
                "watchdog.publication retention current protected",
                &marker,
                digest,
            ));
            return Err(HostError::RecoveryRequired(
                "Watchdog retention attempted to retire the current ORS bundle".to_owned(),
            ));
        }
        let candidate = observed
            .iter()
            .find(|bundle| bundle.marker.ors_receipt_sha256 == *digest)
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/3 — absent retirement candidate, never retired.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_retired(
                    "watchdog.publication retirement candidate absent",
                    &marker,
                    digest,
                ));
                HostError::RecoveryRequired(
                    "Watchdog retirement candidate disappeared before exact retirement".to_owned(),
                )
            })?;
        match retire_owned_directory_exact(&candidate.path, &candidate.retirement).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/1 — exact retirement boundary.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_retired(
                    "watchdog.publication retirement failed",
                    &marker,
                    digest,
                ));
                HostError::RecoveryRequired(error.to_string())
            },
        )? {
            OwnedDirectoryRetirementOutcome::Retired => {
                // WORK_UNIT_CASE: 979/2 — stale bundle retired; replay identity retained.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_retired(
                    "watchdog.publication stale retired",
                    &marker,
                    digest,
                ));
            }
            OwnedDirectoryRetirementOutcome::CommittedUnknown(_) => {
                // WORK_UNIT_CASE: 979/7 — retirement committed unknown; absence unproven.
                watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_retired(
                    "watchdog.publication retirement unknown",
                    &marker,
                    digest,
                ));
                return Err(HostError::RecoveryRequired(
                    "Watchdog spool cleanup committed with unknown final absence".to_owned(),
                ));
            }
        }
    }
    // `?` propagates the already-observed inner scan boundary; no second record.
    let after = scan_host_watchdog_publications(host_state_root)?;
    if after.len() > WATCHDOG_PUBLICATION_RETAINED_LIMIT {
        // WORK_UNIT_CASE: 979/3 — spool above its fixed bound, never accepted.
        watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_marker(
            "watchdog.publication spool above bound",
            &marker,
        ));
        return Err(HostError::RecoveryRequired(
            "Watchdog protected spool remains above its fixed retention bound".to_owned(),
        ));
    }
    let current_after = after
        .iter()
        .find(|bundle| bundle.marker.ors_receipt_sha256 == current.receipt.receipt_sha256)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — current bundle absent after retention, never accepted.
            watchdog_publication_observe_bound(&WatchdogPublicationObservation::for_snapshot(
                "watchdog.publication current absent",
                template,
                &current,
            ));
            HostError::RecoveryRequired(
                "Watchdog current bundle disappeared during retention".to_owned(),
            )
        })?;
    // `?` propagates the already-observed inner verify/identity boundaries.
    verify_exact_current_watchdog_publication(current_after, template, &current)?;
    supervision_publication_identity(template, &current)
}
