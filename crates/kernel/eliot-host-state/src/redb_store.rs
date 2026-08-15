//! Durable redb implementation of the Host-owned operational state port.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{EpochIdentity, EpochTransition, HostInstallationEpoch};
use eliot_platform::{
    HostActivationReceipt, HostActivationTransition, HostEpochBinding, HostInstallationState,
    HostProcessRecoveryBinding, HostRecoveryEvidence, HostShutdownDisposition, HostShutdownMarker,
    HostStateError, HostStateStore, ManagedDependencyReceipt, ManagedDependencyTransition,
    PlatformHandle,
};
use eliot_runtime_contracts::ServiceProcessRecord;
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, TableDefinition};

const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_state_v1");
const INSTALLATION: &str = "installation";
const EPOCH: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_epoch_v1");
const CURRENT_EPOCH: &str = "current";

/// Read-only admission result for one existing Host state database.
///
/// `FirstInstall` is returned only when the database file is absent. An
/// existing file without a clean marker is never treated as a fresh install;
/// it requires an explicit recovery marker before Host may mutate epochs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostAdmissionState {
    FirstInstall,
    Clean,
    RecoveryRequired,
}

/// Exact stale projection returned to an explicit recovery caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRecoverySnapshot {
    pub installation: PlatformHandle,
    pub host_epoch: HostEpochBinding,
    pub active_process: ServiceProcessRecord,
    pub process: HostProcessRecoveryBinding,
    pub disposition: HostShutdownDisposition,
}

/// Host-local state store backed by a redb database.
///
/// The store contains only Host operational state. It is intentionally not a
/// project or semantic database and has no API for arbitrary key/value writes.
pub struct RedbHostStateStore {
    database: Database,
}

impl RedbHostStateStore {
    /// Inspects existing Host state without creating directories, opening a
    /// writable database, advancing an epoch, or mutating activation state.
    pub fn inspect_admission(
        path: impl AsRef<Path>,
        installation: &PlatformHandle,
    ) -> Result<HostAdmissionState, HostStateError> {
        let path = path.as_ref();
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(HostStateError::Unavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(HostAdmissionState::FirstInstall);
            }
            Err(_) => return Err(HostStateError::Unavailable),
        }
        let database = ReadOnlyDatabase::open(path).map_err(|_| HostStateError::Unavailable)?;
        let state = read_state_from(&database)?.ok_or(HostStateError::Unavailable)?;
        validate_admission_state(&state, installation)?;
        if state.active_process.is_some()
            || state.disposition.is_release_pending()
            || (state.last_clean_shutdown.is_none() && state.last_recovery_evidence.is_none())
        {
            Ok(HostAdmissionState::RecoveryRequired)
        } else {
            Ok(HostAdmissionState::Clean)
        }
    }

    /// Reads the exact stale projection without mutation. Missing or
    /// contradictory recovery fields fail closed instead of being inferred.
    pub fn inspect_recovery(
        path: impl AsRef<Path>,
        installation: &PlatformHandle,
    ) -> Result<HostRecoverySnapshot, HostStateError> {
        let path = path.as_ref();
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) | Err(_) => return Err(HostStateError::Unavailable),
        }
        let database = ReadOnlyDatabase::open(path).map_err(|_| HostStateError::Unavailable)?;
        let state = read_state_from(&database)?.ok_or(HostStateError::Unavailable)?;
        validate_admission_state(&state, installation)?;
        let active_process = state
            .active_process
            .clone()
            .ok_or(HostStateError::InvalidRecord)?;
        let process = state
            .active_process_recovery
            .clone()
            .ok_or(HostStateError::InvalidRecord)?;
        let host_epoch = host_epoch_binding(
            read_epoch_from(&database)?
                .as_ref()
                .ok_or(HostStateError::Unavailable)?,
        )?;
        Ok(HostRecoverySnapshot {
            installation: installation.clone(),
            host_epoch,
            active_process,
            process,
            disposition: state.disposition,
        })
    }

    /// Opens an existing Host database for an explicit recovery mutation.
    ///
    /// Unlike [`Self::open`], this never creates a missing file or installs an
    /// initial state record. Recovery callers must first acquire the Host
    /// owner lease and supply exact typed recovery evidence.
    pub fn open_existing(
        path: impl AsRef<Path>,
        installation: &PlatformHandle,
    ) -> Result<Self, HostStateError> {
        let path = path.as_ref();
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) | Err(_) => return Err(HostStateError::Unavailable),
        }
        let database = Database::open(path).map_err(|_| HostStateError::Unavailable)?;
        let store = Self { database };
        let state = store.read_state()?.ok_or(HostStateError::Unavailable)?;
        validate_admission_state(&state, installation)?;
        Ok(store)
    }

    /// Persists the release-pending disposition before the process attempts
    /// to release its cross-process owner lease. The active projection stays
    /// present so a later recovery decision can bind exact stale identity.
    pub fn prepare_release_pending(
        &self,
        marker: HostShutdownMarker,
    ) -> Result<(), HostStateError> {
        marker.validate()?;
        let installation = marker.installation.clone();
        self.mutate(installation.as_str(), |state| {
            if state.active_process.as_ref() != Some(&marker.process)
                || state.active_process_recovery.is_none()
            {
                return Err(HostStateError::InvalidRecord);
            }
            if let Some(process) = state.active_process_recovery.as_mut() {
                process.job = match &process.job {
                    eliot_platform::HostJobDisposition::Assigned { job } => {
                        eliot_platform::HostJobDisposition::Terminated { job: job.clone() }
                    }
                    disposition => disposition.clone(),
                };
            }
            state.disposition = HostShutdownDisposition::ReleasePending { marker };
            state.last_recovery_evidence = None;
            Ok(())
        })
    }

    /// Finalizes clean state only when the exact release-pending marker still
    /// owns the projection. A concurrent recovery mutation therefore cannot
    /// be overwritten by a late post-release finalizer.
    pub fn finalize_clean_shutdown(
        &self,
        marker: HostShutdownMarker,
    ) -> Result<(), HostStateError> {
        marker.validate()?;
        let installation = marker.installation.clone();
        self.mutate(installation.as_str(), |state| {
            if state.active_process.as_ref() != Some(&marker.process)
                || state.active_process_recovery.is_none()
            {
                return Err(HostStateError::InvalidRecord);
            }
            match &state.disposition {
                HostShutdownDisposition::ReleasePending { marker: pending }
                    if pending == &marker => {}
                _ => return Err(HostStateError::InvalidRecord),
            }
            state.active_process = None;
            state.active_process_recovery = None;
            state.disposition = HostShutdownDisposition::Clean;
            state.last_clean_shutdown = Some(marker);
            state.last_recovery_evidence = None;
            Ok(())
        })
    }

    /// Clears a stale projection only when every identity in the typed
    /// evidence matches the current durable state and epoch table.
    pub fn clear_recovery(&self, evidence: HostRecoveryEvidence) -> Result<(), HostStateError> {
        evidence.validate()?;
        let current_epoch = host_epoch_binding(
            self.read_epoch()?
                .as_ref()
                .ok_or(HostStateError::Unavailable)?,
        )?;
        if current_epoch != evidence.host_epoch {
            return Err(HostStateError::InvalidRecord);
        }
        let installation = evidence.installation.clone();
        self.mutate(installation.as_str(), |state| {
            if state.active_process.as_ref() != Some(&evidence.stale_active_process)
                || state.active_process_recovery.as_ref() != Some(&evidence.process)
                || state.disposition != evidence.observed_disposition
            {
                return Err(HostStateError::InvalidRecord);
            }
            state.active_process = None;
            state.active_process_recovery = None;
            state.disposition = HostShutdownDisposition::Clean;
            state.last_recovery_evidence = Some(evidence);
            Ok(())
        })
    }

    /// Attaches the measured process/PID/image/job projection to an already
    /// committed activation. A missing projection is intentionally accepted
    /// only as an incomplete recovery gate, never as healthy admission.
    pub fn record_active_process_recovery(
        &self,
        installation: &PlatformHandle,
        process: HostProcessRecoveryBinding,
    ) -> Result<(), HostStateError> {
        process.validate()?;
        self.mutate(installation.as_str(), |state| {
            if state.active_process.is_none() {
                return Err(HostStateError::InvalidRecord);
            }
            state.active_process_recovery = Some(process);
            Ok(())
        })
    }

    /// Opens or creates a Host state database and installs the initial
    /// installation identity on first use.
    pub fn open(
        path: impl AsRef<Path>,
        initial: HostInstallationState,
    ) -> Result<Self, HostStateError> {
        initial.validate()?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|_| HostStateError::Unavailable)?;
        }
        let database = Database::create(path).map_err(|_| HostStateError::Unavailable)?;
        let store = Self { database };
        match store.read_state()? {
            Some(existing) if existing.installation != initial.installation => {
                Err(HostStateError::InstallationMismatch)
            }
            Some(existing) => {
                existing.validate()?;
                Ok(store)
            }
            None => {
                store.write_state(&initial)?;
                Ok(store)
            }
        }
    }

    /// Opens Host state and advances the durable Host epoch before admitting
    /// the process.  The epoch is persisted independently of the operational
    /// projection so a restart can never reuse the old lineage/sequence or a
    /// fabricated boot nonce.
    pub fn open_epoch(
        path: impl AsRef<Path>,
        installation: PlatformHandle,
    ) -> Result<(Self, HostInstallationEpoch), HostStateError> {
        let initial = HostInstallationState {
            installation: installation.clone(),
            active_process: None,
            managed_dependencies: Vec::new(),
            last_clean_shutdown: None,
            disposition: HostShutdownDisposition::Clean,
            active_process_recovery: None,
            last_recovery_evidence: None,
        };
        initial.validate()?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|_| HostStateError::Unavailable)?;
        }
        let database = Database::create(path).map_err(|_| HostStateError::Unavailable)?;
        let store = Self { database };
        match store.read_state()? {
            Some(existing) if existing.installation != installation => {
                return Err(HostStateError::InstallationMismatch);
            }
            Some(existing) => existing.validate()?,
            None => store.write_state(&initial)?,
        }
        let previous = store.read_epoch()?;
        if previous
            .as_ref()
            .is_some_and(|epoch| epoch.installation != installation)
        {
            return Err(HostStateError::InstallationMismatch);
        }
        let epoch = next_epoch(installation, previous.as_ref())?;
        store.write_epoch(&epoch)?;
        Ok((store, epoch))
    }

    fn read_epoch(&self) -> Result<Option<HostInstallationEpoch>, HostStateError> {
        read_epoch_from(&self.database)
    }

    fn read_state(&self) -> Result<Option<HostInstallationState>, HostStateError> {
        read_state_from(&self.database)
    }

    fn write_state(&self, state: &HostInstallationState) -> Result<(), HostStateError> {
        state.validate()?;
        let bytes = serde_json::to_vec(state).map_err(|_| HostStateError::Unavailable)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| HostStateError::Unavailable)?;
        {
            let mut table = write
                .open_table(STATE)
                .map_err(|_| HostStateError::Unavailable)?;
            table
                .insert(INSTALLATION, bytes.as_slice())
                .map_err(|_| HostStateError::Unavailable)?;
        }
        write.commit().map_err(|_| HostStateError::Unavailable)
    }

    fn write_epoch(&self, epoch: &HostInstallationEpoch) -> Result<(), HostStateError> {
        let bytes = serde_json::to_vec(epoch).map_err(|_| HostStateError::Unavailable)?;
        let write = self
            .database
            .begin_write()
            .map_err(|_| HostStateError::Unavailable)?;
        {
            let mut table = write
                .open_table(EPOCH)
                .map_err(|_| HostStateError::Unavailable)?;
            table
                .insert(CURRENT_EPOCH, bytes.as_slice())
                .map_err(|_| HostStateError::Unavailable)?;
        }
        write.commit().map_err(|_| HostStateError::Unavailable)
    }

    fn mutate<F>(&self, installation: &str, mutation: F) -> Result<(), HostStateError>
    where
        F: FnOnce(&mut HostInstallationState) -> Result<(), HostStateError>,
    {
        let mut state = self.read_state()?.ok_or(HostStateError::Unavailable)?;
        if state.installation.as_str() != installation {
            return Err(HostStateError::InstallationMismatch);
        }
        mutation(&mut state)?;
        self.write_state(&state)
    }
}

fn read_epoch_from<D: ReadableDatabase>(
    database: &D,
) -> Result<Option<HostInstallationEpoch>, HostStateError> {
    let read = database
        .begin_read()
        .map_err(|_| HostStateError::Unavailable)?;
    let table = match read.open_table(EPOCH) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(_) => return Err(HostStateError::Unavailable),
    };
    let Some(value) = table
        .get(CURRENT_EPOCH)
        .map_err(|_| HostStateError::Unavailable)?
    else {
        return Ok(None);
    };
    let epoch: HostInstallationEpoch =
        serde_json::from_slice(value.value()).map_err(|_| HostStateError::Unavailable)?;
    epoch.validate().map_err(|_| HostStateError::Unavailable)?;
    Ok(Some(epoch))
}

fn host_epoch_binding(epoch: &HostInstallationEpoch) -> Result<HostEpochBinding, HostStateError> {
    epoch
        .validate()
        .map_err(|_| HostStateError::InvalidRecord)?;
    let binding = HostEpochBinding {
        installation: epoch.installation.clone(),
        lineage: epoch.epoch.current.lineage.clone(),
        sequence: epoch.epoch.current.sequence,
        nonce: epoch.nonce.clone(),
    };
    binding.validate()?;
    Ok(binding)
}

fn read_state_from<D: ReadableDatabase>(
    database: &D,
) -> Result<Option<HostInstallationState>, HostStateError> {
    let read = database
        .begin_read()
        .map_err(|_| HostStateError::Unavailable)?;
    let table = match read.open_table(STATE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(_) => return Err(HostStateError::Unavailable),
    };
    let Some(value) = table
        .get(INSTALLATION)
        .map_err(|_| HostStateError::Unavailable)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(value.value())
        .map(Some)
        .map_err(|_| HostStateError::Unavailable)
}

fn validate_admission_state(
    state: &HostInstallationState,
    installation: &PlatformHandle,
) -> Result<(), HostStateError> {
    state.validate()?;
    if state.installation != *installation {
        return Err(HostStateError::InstallationMismatch);
    }
    if state
        .last_clean_shutdown
        .as_ref()
        .is_some_and(|marker| marker.installation != *installation)
    {
        return Err(HostStateError::InvalidRecord);
    }
    Ok(())
}

fn next_epoch(
    installation: PlatformHandle,
    previous: Option<&HostInstallationEpoch>,
) -> Result<HostInstallationEpoch, HostStateError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostStateError::Unavailable)?
        .as_nanos();
    let pid = std::process::id();
    let (lineage, sequence, parent) = match previous {
        Some(previous) => {
            let sequence = previous
                .epoch
                .current
                .sequence
                .checked_add(1)
                .ok_or(HostStateError::Unavailable)?;
            (
                previous.epoch.current.lineage.clone(),
                sequence,
                Some(previous.epoch.current.clone()),
            )
        }
        None => (
            PlatformHandle::new(format!("host-lineage-{stamp:x}-{pid:x}"))
                .map_err(|_| HostStateError::Unavailable)?,
            1,
            None,
        ),
    };
    let nonce = PlatformHandle::new(format!("host-boot-{stamp:x}-{pid:x}-{sequence:x}"))
        .map_err(|_| HostStateError::Unavailable)?;
    let epoch = HostInstallationEpoch {
        installation,
        epoch: EpochTransition {
            current: EpochIdentity { lineage, sequence },
            parent,
        },
        nonce,
        recovery: None,
    };
    epoch.validate().map_err(|_| HostStateError::Unavailable)?;
    Ok(epoch)
}

impl HostStateStore for RedbHostStateStore {
    fn load_installation(&self) -> Result<HostInstallationState, HostStateError> {
        self.read_state()?.ok_or(HostStateError::Unavailable)
    }

    fn commit_activation(
        &self,
        transition: HostActivationTransition,
    ) -> Result<HostActivationReceipt, HostStateError> {
        transition
            .process
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)?;
        let receipt = HostActivationReceipt {
            request_id: transition.context.request_id.clone(),
            installation: transition.installation.clone(),
            process: transition.process.clone(),
        };
        self.mutate(transition.installation.as_str(), |state| {
            state.active_process = Some(transition.process);
            state.last_clean_shutdown = None;
            state.last_recovery_evidence = None;
            state.disposition = HostShutdownDisposition::Clean;
            state.active_process_recovery = None;
            Ok(())
        })?;
        Ok(receipt)
    }

    fn record_dependency(
        &self,
        transition: ManagedDependencyTransition,
    ) -> Result<ManagedDependencyReceipt, HostStateError> {
        transition
            .dependency
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)?;
        let receipt = ManagedDependencyReceipt {
            request_id: transition.context.request_id.clone(),
            installation: transition.installation.clone(),
            dependency: transition.dependency.clone(),
        };
        self.mutate(transition.installation.as_str(), |state| {
            if let Some(existing) = state
                .managed_dependencies
                .iter_mut()
                .find(|item| item.process_id == transition.dependency.process_id)
            {
                *existing = transition.dependency;
            } else {
                state.managed_dependencies.push(transition.dependency);
            }
            Ok(())
        })?;
        Ok(receipt)
    }

    fn mark_clean_shutdown(&self, marker: HostShutdownMarker) -> Result<(), HostStateError> {
        marker.validate()?;
        let installation = marker.installation.clone();
        self.mutate(installation.as_str(), |state| {
            state.active_process = None;
            state.active_process_recovery = None;
            state.disposition = HostShutdownDisposition::Clean;
            state.last_clean_shutdown = Some(marker);
            state.last_recovery_evidence = None;
            Ok(())
        })
    }
}
