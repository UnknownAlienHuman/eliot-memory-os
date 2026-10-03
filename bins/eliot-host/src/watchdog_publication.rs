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
// Through the #889 shared diagnostics facade only: each record is emitted by
// `HostWatchdogObservation::emit` through the re-exported
// `super::host_diagnostics::info!` at the shared `HOST_DIAGNOSTICS_TARGET`,
// with every identity bounded by `super::host_diagnostics::bound_field`, and
// the sink disposition noted through the shared bounded observer
// (`super::host_diagnostics::note_event_log_sink_status`, over #984's landed
// safe port).
//
// Observation-only contract: every boundary here projects facts the semantic
// owner already produced into one typed `HostWatchdogObservation` record. Each
// slot takes an identity the surrounding function ALREADY HOLDS — an
// owner-validated identity label, a digest the owner already computed, or an
// opaque platform handle — so `bound_field` limits size, not sensitivity. Two
// slots are locally composed by this file out of values it already holds, and
// their grammar belongs to this file rather than to any owner-issued handle:
// `state_fence`, the `lineage#sequence/resource_generation` string minted by
// `watchdog_publication_state_fence_identity`, and `publication_child`, the
// closed three-value vocabulary `publication_child_token` selects from the
// destination file name the three publication call sites already join onto.
// No protected file is re-read, no SCM is probed, and nothing is re-hashed or
// re-probed to fill a slot. A slot the boundary does not hold stays `None`
// and renders as an explicit `<slot>_missing = true`: a missing identity is an
// unavailable field, never a static sentence. Every bounded slot also renders
// `<slot>_truncated`, so a value cut at the bound never reads as a whole one.
// Signed lease bytes never leave the owner types, so no slot can carry a
// signature, payload digest, key reference, nonce, credential, raw path or
// arbitrary error text.
//
// Sink outcome never alters result/order/status/cleanup. There is no mutable
// global dedup cache and no terminal guard here: the single designated
// terminal per failed operation stays with the outer #891/#893 operation that
// owns the failure decision; these phase records correlate by the identities
// they carry and by stage order, and never emit a terminal. A bare `?` on an
// already-observed inner boundary propagates without a second record.

/// One closed typed observation record for a Host Watchdog publication
/// boundary.
///
/// Audit 5909923856 defect 1: a boundary speaks through this record instead of
/// a free-form detail sentence. Two concurrent publications correlate by
/// `ors_receipt_digest`, the one publication operation identity, and two
/// retries of that publication deliberately share it and stay separable by
/// `phase` plus `publication_disposition`, so a replay never reads as a second
/// operation. `phase` is the short static token naming WHICH boundary spoke;
/// every identity lives in its own slot.
///
/// Two boundaries remain deliberately non-distinguishing, and the record says
/// so instead of inventing an identity for them: a `publication_child_*`
/// record names WHICH child of a publication spoke but not WHICH publication,
/// so child records of two concurrent publications stay interchangeable; and
/// the one-record-per-call supervision dispositions name the disposition class
/// without naming the spool entry that produced it.
///
/// A `None` slot renders as an explicit `<slot>_missing = true`, never as a
/// sentence standing in for an identity this boundary did not hold.
///
/// `supervision_disposition` is a closed diagnostic vocabulary over one
/// observation — `Absent`, `Foreign`, `StaleActivation`, `Expired`, `Terminal`,
/// `ActiveCurrent` — never a second lease lifecycle: it classifies one
/// observation and transitions into nothing. `lease_state` carries the owner
/// lease state itself in the owner's own rendering, so `Terminal` names the
/// state that made it terminal instead of discarding it; only the dispositions
/// that actually read that state carry it — `Terminal`, `Expired` and
/// `ActiveCurrent` — while `Foreign`, `StaleActivation` and `Absent` leave it
/// explicitly unavailable, because those entries were classified without ever
/// reading a state for them.
///
/// `publication_disposition` is the matching closed vocabulary over one
/// publication operation: `Requested`, `RetainedCandidateReconciliation`,
/// `Committed`, `CommitUnknown`, `CommittedObserved`, `CommittedReplay`,
/// `CommittedNotCurrent` and `CommittedCleanupIncomplete` (the primary effect
/// is committed and reread while post-commit cleanup is not). It never
/// withdraws or re-labels a committed publication.
///
/// `lease_state`, `publication_disposition` and `publication_child` are the
/// only three slots added past the frozen slot list, and only because this
/// file's own audit defects require facts the frozen list has no slot for: the
/// owner lease state behind a `Terminal` disposition (defect 3), the
/// publication/cleanup disposition itself (defect 6), and which of the three
/// publication children a record came from (defect 1). None is a lifecycle, a
/// sink or a second state machine: all three are bounded values on one
/// diagnostic record.
#[cfg(windows)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct HostWatchdogObservation {
    /// Installation identity this boundary holds.
    pub(super) installation: Option<crate::host_diagnostics::BoundedField>,
    /// Activation identity this boundary holds.
    pub(super) activation: Option<crate::host_diagnostics::BoundedField>,
    /// Publication digest the owner already computed over the exact marker.
    pub(super) publication_digest: Option<crate::host_diagnostics::BoundedField>,
    /// Exact current ORS receipt digest: the publication operation identity.
    pub(super) ors_receipt_digest: Option<crate::host_diagnostics::BoundedField>,
    /// Supervision lease identity this boundary holds.
    pub(super) lease_identity: Option<crate::host_diagnostics::BoundedField>,
    /// Exact approved manifest generation this boundary holds.
    pub(super) approved_generation: Option<crate::host_diagnostics::BoundedField>,
    /// Exact State Fence identity this boundary holds.
    pub(super) state_fence: Option<crate::host_diagnostics::BoundedField>,
    /// Canonical service registration identity this boundary holds.
    pub(super) service_identity: Option<crate::host_diagnostics::BoundedField>,
    /// Exact process PID/start-time pair, or an owner-issued digest of it.
    pub(super) process_start: Option<crate::host_diagnostics::BoundedField>,
    /// Approved image identity or digest, never a raw path.
    pub(super) approved_image: Option<crate::host_diagnostics::BoundedField>,
    /// Observed SCM state this boundary holds.
    pub(super) scm_state: Option<crate::host_diagnostics::BoundedField>,
    /// Exact deadline basis this boundary holds.
    pub(super) deadline_basis: Option<crate::host_diagnostics::BoundedField>,
    /// Closed supervision-obligation disposition (defect 3).
    pub(super) supervision_disposition: Option<crate::host_diagnostics::BoundedField>,
    /// Closed start-attempt disposition; only the start boundary fills this.
    /// Relative SCM wait hint this boundary was handed, in milliseconds. Kept
    /// separate from `deadline_basis` because that slot carries an ABSOLUTE
    /// injected-clock deadline: one slot holding a relative hint and an absolute
    /// deadline makes one operation emit two incomparable values under one name.
    pub(super) scm_wait_hint: Option<crate::host_diagnostics::BoundedField>,
    pub(super) start_attempt: Option<crate::host_diagnostics::BoundedField>,
    /// Exact owner lease state behind the dispositions that read it (defect 3).
    pub(super) lease_state: Option<crate::host_diagnostics::BoundedField>,
    /// Closed publication/cleanup disposition (defect 6).
    pub(super) publication_disposition: Option<crate::host_diagnostics::BoundedField>,
    /// Which publication child this record came from: one token of this file's
    /// own closed `admission` / `lease` / `marker` vocabulary (defect 1).
    pub(super) publication_child: Option<crate::host_diagnostics::BoundedField>,
}

#[cfg(windows)]
impl HostWatchdogObservation {
    /// Attaches the installation identity this boundary already holds.
    pub(super) fn set_installation(&mut self, value: &str) -> &mut Self {
        self.installation = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the activation identity this boundary already holds.
    pub(super) fn set_activation(&mut self, value: &str) -> &mut Self {
        self.activation = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches a publication digest the owner already computed.
    pub(super) fn set_publication_digest(&mut self, value: &str) -> &mut Self {
        self.publication_digest = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact ORS receipt digest this boundary already holds.
    pub(super) fn set_ors_receipt_digest(&mut self, value: &str) -> &mut Self {
        self.ors_receipt_digest = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the supervision lease identity this boundary already holds.
    pub(super) fn set_lease_identity(&mut self, value: &str) -> &mut Self {
        self.lease_identity = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact approved manifest generation already held.
    pub(super) fn set_approved_generation(&mut self, value: &str) -> &mut Self {
        self.approved_generation = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact State Fence identity already held.
    pub(super) fn set_state_fence(&mut self, value: &str) -> &mut Self {
        self.state_fence = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the canonical service registration identity already held.
    pub(super) fn set_service_identity(&mut self, value: &str) -> &mut Self {
        self.service_identity = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact process PID/start-time pair already held.
    pub(super) fn set_process_start(&mut self, value: &str) -> &mut Self {
        self.process_start = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the approved image identity or digest already held.
    pub(super) fn set_approved_image(&mut self, value: &str) -> &mut Self {
        self.approved_image = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the observed SCM state already held.
    pub(super) fn set_scm_state(&mut self, value: &str) -> &mut Self {
        self.scm_state = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact deadline basis already held.
    pub(super) fn set_deadline_basis(&mut self, value: &str) -> &mut Self {
        self.deadline_basis = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the closed supervision-obligation disposition token.
    pub(super) fn set_supervision_disposition(&mut self, value: &str) -> &mut Self {
        self.supervision_disposition = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the closed start-attempt disposition token.
    pub(super) fn set_start_attempt(&mut self, value: &str) -> &mut Self {
        self.start_attempt = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the exact owner lease state behind a disposition.
    pub(super) fn set_lease_state(&mut self, value: &str) -> &mut Self {
        self.lease_state = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the closed publication/cleanup disposition token.
    pub(super) fn set_publication_disposition(&mut self, value: &str) -> &mut Self {
        self.publication_disposition = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches which publication child this boundary is writing.
    ///
    /// Only a token of this file's own closed `admission` / `lease` / `marker`
    /// vocabulary is ever passed, never a file name or any other path text:
    /// the destination path itself is not projectable.
    pub(super) fn set_publication_child(&mut self, value: &str) -> &mut Self {
        self.publication_child = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Attaches the relative SCM wait hint this boundary was handed.
    ///
    /// Never the absolute convergence deadline: that is `deadline_basis`, and one
    /// slot must mean one thing.
    pub(super) fn set_scm_wait_hint(&mut self, value: &str) -> &mut Self {
        self.scm_wait_hint = Some(crate::host_diagnostics::bound_field(value));
        self
    }

    /// Emits this one record at the shared diagnostics target.
    ///
    /// `phase` names the boundary and stays a short static token; every
    /// identity rides in its own slot. Sink outcome never reaches the caller:
    /// the shared bounded observer notes the sink disposition and this returns
    /// `()`, so no boundary result, order, status, retry or cleanup can depend
    /// on it.
    pub(super) fn emit(&self, phase: &'static str) {
        use crate::host_diagnostics::BoundedField;
        super::host_diagnostics::note_event_log_sink_status();
        let installation = self.installation.as_ref();
        let activation = self.activation.as_ref();
        let publication_digest = self.publication_digest.as_ref();
        let ors_receipt_digest = self.ors_receipt_digest.as_ref();
        let lease_identity = self.lease_identity.as_ref();
        let approved_generation = self.approved_generation.as_ref();
        let state_fence = self.state_fence.as_ref();
        let service_identity = self.service_identity.as_ref();
        let process_start = self.process_start.as_ref();
        let approved_image = self.approved_image.as_ref();
        let scm_state = self.scm_state.as_ref();
        let deadline_basis = self.deadline_basis.as_ref();
        let scm_wait_hint = self.scm_wait_hint.as_ref();
        let supervision_disposition = self.supervision_disposition.as_ref();
        let start_attempt = self.start_attempt.as_ref();
        let lease_state = self.lease_state.as_ref();
        let publication_disposition = self.publication_disposition.as_ref();
        let publication_child = self.publication_child.as_ref();
        // A `None` slot renders empty WITH its `*_missing` flag true, so a
        // reader checks the flag before the value and an absent identity can
        // never be mistaken for an identity this boundary did not hold. Every
        // bounded slot also renders `<slot>_truncated`: `bound_field` cuts a
        // value at the bound and keeps a prefix, so without that flag a
        // truncated identity would read as a whole one. A slot whose owner
        // validation imposes no length bound (an installation id, an approved
        // generation) can reach this macro long, and its `_missing` flag stays
        // false while `_truncated` is what discloses the cut.
        crate::host_diagnostics::info!(
            target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
            event = "host.watchdog.observation",
            phase = phase,
            installation = installation.map_or("", BoundedField::text),
            installation_truncated = installation.is_some_and(BoundedField::truncated),
            installation_missing = installation.is_none(),
            activation = activation.map_or("", BoundedField::text),
            activation_truncated = activation.is_some_and(BoundedField::truncated),
            activation_missing = activation.is_none(),
            publication_digest = publication_digest.map_or("", BoundedField::text),
            publication_digest_truncated = publication_digest.is_some_and(BoundedField::truncated),
            publication_digest_missing = publication_digest.is_none(),
            ors_receipt_digest = ors_receipt_digest.map_or("", BoundedField::text),
            ors_receipt_digest_truncated = ors_receipt_digest.is_some_and(BoundedField::truncated),
            ors_receipt_digest_missing = ors_receipt_digest.is_none(),
            lease_identity = lease_identity.map_or("", BoundedField::text),
            lease_identity_truncated = lease_identity.is_some_and(BoundedField::truncated),
            lease_identity_missing = lease_identity.is_none(),
            approved_generation = approved_generation.map_or("", BoundedField::text),
            approved_generation_truncated =
                approved_generation.is_some_and(BoundedField::truncated),
            approved_generation_missing = approved_generation.is_none(),
            state_fence = state_fence.map_or("", BoundedField::text),
            state_fence_truncated = state_fence.is_some_and(BoundedField::truncated),
            state_fence_missing = state_fence.is_none(),
            service_identity = service_identity.map_or("", BoundedField::text),
            service_identity_truncated = service_identity.is_some_and(BoundedField::truncated),
            service_identity_missing = service_identity.is_none(),
            process_start = process_start.map_or("", BoundedField::text),
            process_start_truncated = process_start.is_some_and(BoundedField::truncated),
            process_start_missing = process_start.is_none(),
            approved_image = approved_image.map_or("", BoundedField::text),
            approved_image_truncated = approved_image.is_some_and(BoundedField::truncated),
            approved_image_missing = approved_image.is_none(),
            scm_state = scm_state.map_or("", BoundedField::text),
            scm_state_truncated = scm_state.is_some_and(BoundedField::truncated),
            scm_state_missing = scm_state.is_none(),
            deadline_basis = deadline_basis.map_or("", BoundedField::text),
            deadline_basis_truncated = deadline_basis.is_some_and(BoundedField::truncated),
            deadline_basis_missing = deadline_basis.is_none(),
            scm_wait_hint = scm_wait_hint.map_or("", BoundedField::text),
            scm_wait_hint_truncated = scm_wait_hint.is_some_and(BoundedField::truncated),
            scm_wait_hint_missing = scm_wait_hint.is_none(),
            supervision_disposition = supervision_disposition.map_or("", BoundedField::text),
            supervision_disposition_truncated =
                supervision_disposition.is_some_and(BoundedField::truncated),
            supervision_disposition_missing = supervision_disposition.is_none(),
            start_attempt = start_attempt.map_or("", BoundedField::text),
            start_attempt_truncated = start_attempt.is_some_and(BoundedField::truncated),
            start_attempt_missing = start_attempt.is_none(),
            lease_state = lease_state.map_or("", BoundedField::text),
            lease_state_truncated = lease_state.is_some_and(BoundedField::truncated),
            lease_state_missing = lease_state.is_none(),
            publication_disposition = publication_disposition.map_or("", BoundedField::text),
            publication_disposition_truncated =
                publication_disposition.is_some_and(BoundedField::truncated),
            publication_disposition_missing = publication_disposition.is_none(),
            publication_child = publication_child.map_or("", BoundedField::text),
            publication_child_truncated = publication_child.is_some_and(BoundedField::truncated),
            publication_child_missing = publication_child.is_none(),
            "host watchdog observation"
        );
    }
}

/// Projects the exact authority identity of a State Fence the boundary already
/// holds.
///
/// Nothing is read, probed or re-hashed: `StateFence::new`, the only
/// constructor on the supervision path, leaves `task_revision`,
/// `policy_revision` and `integration_revision` absent, so the authority epoch
/// tuple plus the resource generation is the whole fence identity this
/// boundary holds.
///
/// Those two already-held values are formatted here, and the
/// `lineage#sequence/resource_generation` grammar is this file's own local
/// composition, not a canonical text handle any owner issues. A reader must
/// therefore treat the slot as a diagnostic rendering of two owner values
/// rather than as an owner-issued identifier it can look up elsewhere.
#[cfg(windows)]
fn watchdog_publication_state_fence_identity(fence: &eliot_contracts::StateFence) -> String {
    format!(
        "{}#{}/{}",
        fence.authority_epoch.lineage_id.as_str(),
        fence.authority_epoch.sequence.get(),
        fence.resource_generation.value()
    )
}

/// Names which publication child a destination is, in this file's own closed
/// three-value vocabulary.
///
/// The three publication call sites already join exactly these three file-name
/// constants onto the child path, so WHICH child is being written is already
/// decided by the call sites; this helper only maps that closed set onto three
/// static tokens. No path byte is projected: an unmatched destination (a
/// heartbeat descriptor or its staging name, for instance) yields `None`, and
/// the caller then leaves the slot explicitly missing rather than naming a
/// child this vocabulary does not describe.
#[cfg(windows)]
fn publication_child_token(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if name == WATCHDOG_ADMISSION_FILE_NAME {
        Some("admission")
    } else if name == SUPERVISION_LEASE_FILE_NAME {
        Some("lease")
    } else if name == WATCHDOG_PUBLICATION_FILE_NAME {
        Some("marker")
    } else {
        None
    }
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

    // This boundary holds no owner identity: only the destination path, which
    // is never projectable, and the child bytes, which are payload. Every owner
    // slot therefore stays explicitly missing on every record below, and the
    // caller that does hold the publication identity projects it on its own
    // records. The one slot filled here is `publication_child`, this file's own
    // closed three-value vocabulary: without it `publication_child_committed`
    // is byte-identical for the admission, lease and marker children of one
    // publication, so a reader could not say which child committed.
    let child = publication_child_token(path);
    let mut child_observation = HostWatchdogObservation::default();
    if let Some(token) = child {
        child_observation.set_publication_child(token);
    }
    if bytes.len() as u64 > WATCHDOG_PUBLICATION_CHILD_LIMIT {
        // WORK_UNIT_CASE: 979/4 — oversize child, bounded identity preserved.
        child_observation.emit("publication_child_oversize_rejected");
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
            child_observation.emit("publication_child_create_failed");
            HostError::RecoveryRequired(error.to_string())
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — child write/sync boundary.
            child_observation.emit("publication_child_write_failed");
            HostError::RecoveryRequired(error.to_string())
        })?;
    let metadata = file.metadata().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child metadata boundary.
        child_observation.emit("publication_child_metadata_failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if !metadata.is_file()
        || metadata.len() != bytes.len() as u64
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        // WORK_UNIT_CASE: 979/4 — invalid child identity, never committed.
        child_observation.emit("publication_child_identity_rejected");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child identity is invalid".to_owned(),
        ));
    }
    file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback seek boundary.
        child_observation.emit("publication_child_readback_seek_failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let mut readback = Vec::with_capacity(bytes.len());
    file.read_to_end(&mut readback).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — child readback read boundary.
        child_observation.emit("publication_child_readback_read_failed");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if readback != bytes {
        // WORK_UNIT_CASE: 979/4 — readback changed, exact identity preserved by rejection.
        child_observation.emit("publication_child_readback_changed");
        return Err(HostError::RecoveryRequired(
            "Watchdog publication child readback changed".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — child written with exact readback identity.
    child_observation.emit("publication_child_committed");
    Ok(())
}

#[cfg(windows)]
pub(super) fn read_manifest_current_supervision_lease(
    manifest: &CandidateManifest,
    lease_id: &str,
) -> Result<eliot_ors::SupervisionLeaseSnapshot, HostError> {
    let lease_id = OperationIdentity::new(lease_id.to_owned()).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unusable lease identity, never read.
        HostWatchdogObservation::default().emit("ors_lease_identity_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    // Before the read this boundary holds exactly one identity: the requested
    // lease identity, now validated. Every earlier record below carries it and
    // leaves every other slot explicitly missing.
    let mut held = HostWatchdogObservation::default();
    held.set_lease_identity(lease_id.as_str());
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
            held.emit("ors_open_failed");
            HostError::RecoveryRequired(format!("Kernel ORS open failed: {error}"))
        })?;
    if !windows_paths_equal(retained.path(), &ors_path) {
        // WORK_UNIT_CASE: 979/3 — conflicting ORS selection, never read.
        held.emit("ors_selection_conflicting");
        return Err(HostError::RecoveryRequired(
            "Kernel ORS path is not the manifest-selected child".to_owned(),
        ));
    }
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed before the read.
            held.emit("ors_identity_changed_before_read");
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    let current = eliot_ors::read_current_supervision_lease_read_only(retained.path(), &lease_id)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unreadable ORS, no head observed.
            held.emit("ors_read_failed");
            HostError::RecoveryRequired(format!("Kernel ORS read failed: {error}"))
        })?
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent ORS head, never ready/current.
            held.emit("ors_head_absent");
            HostError::RecoveryRequired("Kernel ORS has no current supervision lease".to_owned())
        })?;
    // The owner-observed snapshot is now held, so the remaining records below
    // also carry its own exact identities. Nothing is re-derived here: every
    // value is a field of the snapshot this read returned. The approved
    // manifest generation is deliberately left missing — this boundary holds no
    // admission template, and the ORS lease generation is not that identity.
    held.set_installation(current.record.binding.installation_id.as_str());
    held.set_activation(current.record.binding.activation_id.as_str());
    held.set_ors_receipt_digest(current.receipt.receipt_sha256.as_str());
    held.set_state_fence(&watchdog_publication_state_fence_identity(
        &current.record.binding.state_fence,
    ));
    retained
        .verify_stable_identity()
        .and_then(|()| retained.verify_path_identity())
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — ORS identity changed across the read.
            held.emit("ors_identity_changed_after_read");
            HostError::RecoveryRequired(format!("Kernel ORS changed: {error}"))
        })?;
    current.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid ORS snapshot, never ready/current.
        held.emit("ors_snapshot_validation_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    // WORK_UNIT_CASE: 979/2 — owner-observed exact current ORS supervision head.
    held.emit("ors_head_observed");
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
    // Audit 5909923856 defect 3: project a closed supervision disposition bound
    // to the requested installation/activation. At most one record below fires
    // per call; skipped spool entries stay silent so mixed spool states resolve
    // to a single disposition in severity order
    // terminal > expired > stale activation > foreign > absent. `ActiveCurrent`
    // keeps the existing live-obligation record and stays distinct from the
    // other five. Each disposition is a closed token in
    // `supervision_disposition`, and where the loop actually read the decoded
    // state it rides in `lease_state` in the owner's own rendering, so
    // `Terminal` names the state that made it terminal instead of discarding
    // it. The `Foreign` and `StaleActivation` dispositions are classified
    // before any such read and therefore leave that slot explicitly missing
    // rather than naming a state this boundary did not observe. No signed lease
    // byte leaves the owner types: the slots take only the decoded payload's own
    // identity labels (`installation_id`, `activation_id`, `lease_id`) and its
    // `LeaseState`, never `payload_sha256`, `key_id` or `signature`.
    let requested = {
        let mut requested = HostWatchdogObservation::default();
        requested.set_installation(installation.as_str());
        requested.set_activation(activation_id.as_str());
        requested
    };
    let mut saw_foreign = false;
    let mut saw_stale_activation = false;
    let mut saw_expired = false;
    // `Some` exactly when a scanned entry was in a non-active lease state; the
    // owner state travels with it so the terminal disposition keeps it.
    let mut terminal_state: Option<eliot_runtime_contracts::LeaseState> = None;
    // `Some` exactly when a scanned entry was proven `Active` and then found
    // past its own expiry; the owner state travels with it so the `Expired`
    // disposition renders the value this loop read in the owner's own
    // `Display`, not a second spelling of it.
    let mut expired_state: Option<eliot_runtime_contracts::LeaseState> = None;
    // `?` propagates the already-observed inner scan boundary; no second record.
    for observation in scan_host_watchdog_publications(host_state_root)? {
        let payload = &observation.lease.payload;
        if payload.installation_id != installation.as_str()
            || payload.scope_ref != observation.admission.supervision_lease_scope_id
            || observation.admission.installation_id != payload.installation_id
        {
            // A publication bound to another installation, scope, or admission
            // is foreign to this installation, never its live obligation.
            saw_foreign = true;
            continue;
        }
        if payload.activation_id != activation_id.as_str() {
            // Same installation but another activation generation: a stale
            // spool entry, never live coverage for the requested generation.
            saw_stale_activation = true;
            continue;
        }
        if payload.state != eliot_runtime_contracts::LeaseState::Active {
            // The test here is `!= Active`, not a terminal-state taxonomy:
            // every non-`Active` lease state stops blocking drain, and the
            // exact owner state is recorded below rather than collapsed, so
            // `EXPIRED`/`REVOKED`/`CLOSED` stay the only terminal states.
            terminal_state = Some(payload.state);
            continue;
        }
        if now_ms >= payload.expires_at_ms {
            saw_expired = true;
            // The owner state travels with the flag, exactly as the terminal
            // branch above does, so the record renders the value this loop
            // actually read instead of a second hand-written spelling of it.
            expired_state = Some(payload.state);
            continue;
        }
        let active = {
            let mut active = requested.clone();
            active.set_supervision_disposition("ActiveCurrent");
            active.set_lease_identity(payload.lease_id.as_str());
            active.set_lease_state(&payload.state.to_string());
            active
        };
        let unusable_identity = {
            let mut unusable = requested.clone();
            unusable.set_supervision_disposition("ActiveCurrent");
            unusable.set_lease_state(&payload.state.to_string());
            unusable
        };
        return PlatformHandle::new(payload.lease_id.clone())
            .inspect(|_lease| {
                // WORK_UNIT_CASE: 979/2 — live supervision obligation observed.
                active.emit("supervision_obligation_active_current");
            })
            .map(Some)
            .map_err(|error| {
                // The lease identity slot stays missing here: this boundary holds
                // no identity handle for this lease, because building one is
                // exactly what failed.
                // WORK_UNIT_CASE: 979/4 — unusable live lease identity, never reported.
                unusable_identity.emit("supervision_lease_identity_rejected");
                HostError::RecoveryRequired(error.to_string())
            });
    }
    // Every scanned entry sets exactly one disposition below, so reaching here
    // with none of them means the spool held no publication at all.
    if terminal_state.is_some() {
        let mut terminal = requested.clone();
        terminal.set_supervision_disposition("Terminal");
        if let Some(state) = terminal_state {
            terminal.set_lease_state(&state.to_string());
        }
        // WORK_UNIT_CASE: 979/2 — closed disposition `Terminal`: no live obligation.
        terminal.emit("supervision_obligation_terminal");
    } else if saw_expired {
        let mut expired = requested.clone();
        expired.set_supervision_disposition("Expired");
        // Reached only for an entry the `!= Active` test above already cleared as
        // `Active`, so the recorded value is the owner's own rendering of a
        // state this loop read, never a hand-written literal.
        if let Some(state) = expired_state {
            expired.set_lease_state(&state.to_string());
        }
        // WORK_UNIT_CASE: 979/2 — closed disposition `Expired`: no live obligation.
        expired.emit("supervision_obligation_expired");
    } else if saw_stale_activation {
        let mut stale = requested.clone();
        stale.set_supervision_disposition("StaleActivation");
        // `lease_state` stays missing: the stale-activation test above `continue`d
        // before any read of the decoded state, so this boundary established
        // nothing about it. A hand-written literal here would publish an owner
        // state the code never read, for an entry whose state may be any
        // non-live value.
        // WORK_UNIT_CASE: 979/2 — `StaleActivation`: a stale spool entry is not live coverage.
        stale.emit("supervision_obligation_stale_activation");
    } else if saw_foreign {
        let mut foreign = requested.clone();
        foreign.set_supervision_disposition("Foreign");
        // `lease_state` stays missing for the same reason as the stale
        // activation path: the foreign test classified this entry on
        // installation, scope and admission binding alone, so a foreign entry
        // that is actually expired, revoked or closed must not be reported as
        // carrying a state this boundary never read.
        // WORK_UNIT_CASE: 979/2 — closed disposition `Foreign`: no live obligation.
        foreign.emit("supervision_obligation_foreign");
    } else {
        let mut absent = requested.clone();
        absent.set_supervision_disposition("Absent");
        // No spool entry was ever decoded here, so no owner lease state was
        // observed: the slot stays explicitly missing rather than guessing.
        // WORK_UNIT_CASE: 979/2 — closed disposition `Absent`: no live obligation.
        absent.emit("supervision_obligation_absent");
    }
    Ok(None)
}

#[cfg(windows)]
pub(super) fn supervision_publication_identity(
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<PublishedSupervisionIdentity, HostError> {
    // The requested admission template and the exact current ORS head are both
    // held here, so every record below carries them. Each of the three identity
    // handles is attached only once it exists, and the slot whose own handle
    // construction failed stays explicitly missing rather than carrying a value
    // this boundary could not turn into an identity handle.
    let mut held = HostWatchdogObservation::default();
    held.set_installation(template.installation_id.as_str());
    held.set_activation(current.record.binding.activation_id.as_str());
    held.set_approved_generation(template.approved_generation.as_str());
    held.set_state_fence(&watchdog_publication_state_fence_identity(
        &current.record.binding.state_fence,
    ));
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — unserializable lease, identity unprojected.
        held.emit("publication_identity_serialization_rejected");
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
        held.emit("publication_identity_marker_binding_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let identity = PublishedSupervisionIdentity {
        lease_id: PlatformHandle::new(current.record.lease_id.as_str()).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            held.emit("publication_identity_lease_handle_rejected");
            HostError::Platform(error.to_string())
        })?,
        ors_receipt_digest: PlatformHandle::new(current.receipt.receipt_sha256.clone()).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
                held.emit("publication_identity_receipt_handle_rejected");
                HostError::Platform(error.to_string())
            },
        )?,
        publication_digest: PlatformHandle::new(sha256_json(&marker)?).map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — unusable identity handle, never reported.
            held.emit("publication_identity_digest_handle_rejected");
            HostError::Platform(error.to_string())
        })?,
    };
    held.set_lease_identity(identity.lease_id.as_str());
    held.set_ors_receipt_digest(identity.ors_receipt_digest.as_str());
    held.set_publication_digest(identity.publication_digest.as_str());
    // WORK_UNIT_CASE: 979/4 — publication identity projected with exact digests.
    held.emit("publication_identity_projected");
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
    // Audit 5909923856 defect 6: one operation identity binds request, commit,
    // retained readback and retirement cleanup. `ors_receipt_digest` is that
    // identity: `WatchdogPublicationBundle::directory_name` derives the sole
    // publication directory name from it alone, this boundary already holds it
    // from the request record, and every record below reuses this one value
    // rather than minting a second correlation. No path is recorded.
    //
    // This function never fills `publication_digest`: that content address is
    // computed later, and only `supervision_publication_identity` sets it, on
    // the single `publication_identity_projected` record that function emits as
    // the final step here — after every record below. A reader therefore
    // correlates one publication operation across both functions by
    // `ors_receipt_digest`, and never by a content address, which is absent
    // from every record below.
    let mut operation = HostWatchdogObservation::default();
    operation.set_installation(template.installation_id.as_str());
    operation.set_activation(kernel_snapshot.record.binding.activation_id.as_str());
    operation.set_approved_generation(template.approved_generation.as_str());
    operation.set_lease_identity(kernel_snapshot.record.lease_id.as_str());
    operation.set_ors_receipt_digest(kernel_snapshot.receipt.receipt_sha256.as_str());
    operation.set_state_fence(&watchdog_publication_state_fence_identity(
        &kernel_snapshot.record.binding.state_fence,
    ));
    let mut requested = operation.clone();
    requested.set_publication_disposition("Requested");
    // WORK_UNIT_CASE: 979/2 — publication requested, distinct from owner-observed.
    requested.emit("publication_requested");
    template.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid template, never published.
        operation.emit("publication_template_validation_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    if template.digest().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — template digest boundary.
        operation.emit("publication_template_digest_boundary_rejected");
        HostError::RecoveryRequired(error.to_string())
    })? != expected_template_digest
    {
        // WORK_UNIT_CASE: 979/3 — conflicting provisioned template, never published.
        operation.emit("publication_template_digest_conflicting");
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
        operation.emit("publication_probe_snapshot_stale");
        return Err(HostError::RecoveryRequired(
            "Kernel ProbeReady supervision snapshot is not the current ORS head".to_owned(),
        ));
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            operation.emit("publication_clock_unavailable");
            HostError::RecoveryRequired(error.to_string())
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            // WORK_UNIT_CASE: 979/1 — verification clock boundary.
            operation.emit("publication_clock_value_overflow");
            HostError::RecoveryRequired("system time exceeds u64".to_owned())
        })?;
    let verification_context = current
        .active_verification_context(template.trust_anchor.public_key_fingerprint(), now_ms)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverifiable snapshot, never published.
            operation.emit("publication_verification_context_rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    template
        .trust_anchor
        .verify(&current.record.artifact, &verification_context)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverified lease, never published.
            operation.emit("publication_lease_verification_rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    let admission_bytes = template.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        operation.emit("publication_admission_serialization_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let lease_bytes = serde_json::to_vec(&current.record.artifact).map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        operation.emit("publication_lease_serialization_rejected");
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
        operation.emit("publication_marker_binding_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let marker_bytes = marker.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/1 — bundle serialization boundary.
        operation.emit("publication_marker_serialization_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?;
    let destination = host_state_root.join(marker.directory_name().map_err(|error| {
        // WORK_UNIT_CASE: 979/4 — directory name not derivable, identity unproven.
        operation.emit("publication_directory_name_rejected");
        HostError::RecoveryRequired(error.to_string())
    })?);

    // Audit 5909923856 defect 2: `AlreadyExists` proves only that the name
    // is occupied. The replay fact exists only after the retained readback,
    // exact-current verification, and current-ORS re-read below all pass.
    let mut retained_candidate_requires_reconciliation = false;

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
                operation.emit("publication_precommit_unreadable");
                HostError::RecoveryRequired(error.to_string())
            })?;
            // `?` propagates the already-observed inner decode/verify boundaries.
            let decoded = decode_watchdog_publication_observation(&temporary, &precommit, false)?;
            verify_exact_current_watchdog_publication(&decoded, template, &current)?;
            if precommit.directory_identity != publication.temporary_identity() {
                // WORK_UNIT_CASE: 979/3 — changed temporary identity, never committed.
                operation.emit("publication_temporary_identity_changed");
                return Err(HostError::RecoveryRequired(
                    "Watchdog publication temporary directory identity changed".to_owned(),
                ));
            }
            // A concurrent exact replay may win the create-new name, and a
            // committed-unknown move may already own it. Neither outcome is
            // authority until the exact retained readback below succeeds.
            match publication.publish(precommit.directory_identity) {
                Ok(DirectoryPublicationOutcome::Published(_)) => {
                    operation.set_publication_disposition("Committed");
                    // WORK_UNIT_CASE: 979/2 — directory committed, pending retained readback.
                    operation.emit("publication_directory_committed");
                }
                Ok(DirectoryPublicationOutcome::CommittedUnknown(_)) => {
                    operation.set_publication_disposition("CommitUnknown");
                    // WORK_UNIT_CASE: 979/7 — commit outcome unknown; readback below decides.
                    operation.emit("publication_directory_commit_unknown");
                }
                Err(DirectoryPublicationError::AlreadyExists) => {
                    let mut candidate = operation.clone();
                    candidate.set_publication_disposition("RetainedCandidateReconciliation");
                    // WORK_UNIT_CASE: 979/8 — name already occupied; the
                    // retained candidate requires reconciliation below before
                    // any replay classification.
                    candidate.emit("publication_name_occupied_candidate");
                    retained_candidate_requires_reconciliation = true;
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 979/1 — directory commit boundary.
                    operation.emit("publication_directory_commit_rejected");
                    return Err(HostError::RecoveryRequired(format!(
                        "Watchdog directory publication failed before commit: {error}"
                    )));
                }
            }
        }
        Err(DirectoryPublicationError::AlreadyExists) => {
            let mut candidate = operation.clone();
            candidate.set_publication_disposition("RetainedCandidateReconciliation");
            // WORK_UNIT_CASE: 979/8 — name already occupied; the retained
            // candidate requires reconciliation below before any replay
            // classification.
            candidate.emit("publication_name_occupied_candidate");
            retained_candidate_requires_reconciliation = true;
        }
        Err(error) => {
            // WORK_UNIT_CASE: 979/1 — directory preparation boundary.
            operation.emit("publication_directory_preparation_failed");
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
        let mut moved = operation.clone();
        moved.set_publication_disposition("CommittedNotCurrent");
        // The committed directory is not withdrawn by this record: it stands as
        // a committed publication of a head that has since moved.
        // WORK_UNIT_CASE: 979/3 — ORS head changed across publication, never current.
        moved.emit("publication_ors_head_moved_after_commit");
        return Err(HostError::RecoveryRequired(
            "Kernel ORS head changed during Watchdog publication".to_owned(),
        ));
    }
    let mut observed = operation.clone();
    observed.set_publication_disposition("CommittedObserved");
    // WORK_UNIT_CASE: 979/2 — retained publication read back as the exact current head.
    observed.emit("publication_observed");
    if retained_candidate_requires_reconciliation {
        let mut replay = observed.clone();
        replay.set_publication_disposition("CommittedReplay");
        // WORK_UNIT_CASE: 979/8 — exact replay established only now: the
        // retained destination decoded, canonically validated, its children
        // bound to the marker's recorded digests, compared with the requested
        // template and with the signature-verified current ORS snapshot, and
        // rebound against a re-read current ORS head.
        replay.emit("publication_replay_retained");
    }

    // Audit 5909923856 defect 6, verbatim: "Bind publication request,
    // directory commit/readback and retirement cleanup to one
    // operation/publication identity. Preserve committed publication even when
    // stale-spool cleanup fails; do not retry publication or relabel it
    // absent." The primary effect is committed and reread above, so every
    // cleanup record below reuses the same `operation` identity and states that
    // the committed publication stands while cleanup is incomplete. No cleanup
    // record withdraws, retries or re-classifies the publication.
    let mut cleanup = operation.clone();
    cleanup.set_publication_disposition("CommittedCleanupIncomplete");
    // Retirement begins only after the new exact current bundle is durable.
    let observed_spool = scan_host_watchdog_publications(host_state_root)?;
    let markers = observed_spool
        .iter()
        .map(|bundle| bundle.marker.clone())
        .collect::<Vec<_>>();
    let plan =
        WatchdogPublicationRetentionPlan::for_current(&marker, &markers).map_err(|error| {
            // WORK_UNIT_CASE: 979/1 — retention plan boundary.
            cleanup.emit("publication_retention_plan_rejected");
            HostError::RecoveryRequired(error.to_string())
        })?;
    for digest in plan.retired_receipt_digests() {
        if digest == &current.receipt.receipt_sha256 {
            // WORK_UNIT_CASE: 979/4 — current bundle protected from retirement.
            cleanup.emit("publication_retention_current_bundle_protected");
            return Err(HostError::RecoveryRequired(
                "Watchdog retention attempted to retire the current ORS bundle".to_owned(),
            ));
        }
        let candidate = observed_spool
            .iter()
            .find(|bundle| bundle.marker.ors_receipt_sha256 == *digest)
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/3 — absent retirement candidate, never retired.
                cleanup.emit("publication_retirement_candidate_absent");
                HostError::RecoveryRequired(
                    "Watchdog retirement candidate disappeared before exact retirement".to_owned(),
                )
            })?;
        match retire_owned_directory_exact(&candidate.path, &candidate.retirement).map_err(
            |error| {
                // WORK_UNIT_CASE: 979/1 — exact retirement boundary.
                cleanup.emit("publication_retirement_failed");
                HostError::RecoveryRequired(error.to_string())
            },
        )? {
            OwnedDirectoryRetirementOutcome::Retired => {
                // WORK_UNIT_CASE: 979/2 — stale bundle retired; replay identity retained.
                operation.emit("publication_stale_bundle_retired");
            }
            OwnedDirectoryRetirementOutcome::CommittedUnknown(_) => {
                // WORK_UNIT_CASE: 979/7 — retirement committed unknown; absence unproven.
                cleanup.emit("publication_retirement_commit_unknown");
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
        cleanup.emit("publication_post_commit_spool_above_bound");
        return Err(HostError::RecoveryRequired(
            "Watchdog protected spool remains above its fixed retention bound".to_owned(),
        ));
    }
    let current_after = after
        .iter()
        .find(|bundle| bundle.marker.ors_receipt_sha256 == current.receipt.receipt_sha256)
        .ok_or_else(|| {
            // This is a post-commit cleanup-integrity fact, so it is recorded as
            // an incomplete cleanup of a committed publication and never as the
            // publication being absent.
            // WORK_UNIT_CASE: 979/3 — current bundle absent after retention, never accepted.
            cleanup.emit("publication_post_commit_current_absent");
            HostError::RecoveryRequired(
                "Watchdog current bundle disappeared during retention".to_owned(),
            )
        })?;
    // `?` propagates the already-observed inner verify/identity boundaries.
    verify_exact_current_watchdog_publication(current_after, template, &current)?;
    supervision_publication_identity(template, &current)
}
