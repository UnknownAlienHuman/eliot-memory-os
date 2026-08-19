use std::path::Path;

use eliot_platform::{HostInstallationState, HostStateError};

use crate::{HostInstallationEpoch, RedbHostStateStore};

/// Immutable input captured from the retired `host-state.redb` format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyHostStateSnapshot {
    pub state: HostInstallationState,
    pub epoch: HostInstallationEpoch,
}

/// Explicit read-only boundary for an offline legacy-state migration.
///
/// Normal Host startup must not call this importer. It never creates or opens
/// the legacy database for mutation and does not append to the new journal.
pub struct LegacyHostStateImporter;

impl LegacyHostStateImporter {
    pub fn inspect_existing(
        path: impl AsRef<Path>,
    ) -> Result<Option<LegacyHostStateSnapshot>, HostStateError> {
        let Some(inspection) = RedbHostStateStore::inspect_existing(path)? else {
            return Ok(None);
        };
        Ok(Some(LegacyHostStateSnapshot {
            state: inspection.state.clone(),
            epoch: inspection.epoch.clone(),
        }))
    }
}
