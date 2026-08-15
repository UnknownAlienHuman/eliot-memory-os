//! Durable redb implementation of the Host-owned operational state port.

use std::fs;
use std::path::Path;

use eliot_platform::{
    HostActivationReceipt, HostActivationTransition, HostInstallationState, HostShutdownMarker,
    HostStateError, HostStateStore, ManagedDependencyReceipt, ManagedDependencyTransition,
};
use redb::{Database, ReadableDatabase, TableDefinition};

const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("eliot_host_state_v1");
const INSTALLATION: &str = "installation";

/// Host-local state store backed by a redb database.
///
/// The store contains only Host operational state. It is intentionally not a
/// project or semantic database and has no API for arbitrary key/value writes.
pub struct RedbHostStateStore {
    database: Database,
}

impl RedbHostStateStore {
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

    fn read_state(&self) -> Result<Option<HostInstallationState>, HostStateError> {
        let read = self
            .database
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
        marker
            .process
            .validate()
            .map_err(|_| HostStateError::InvalidRecord)?;
        let installation = marker.installation.clone();
        self.mutate(installation.as_str(), |state| {
            state.active_process = None;
            state.last_clean_shutdown = Some(marker);
            Ok(())
        })
    }
}
