//! Exact-fence readback for Kernel-owned runtime leases.
//!
//! Ported from #1751 donor 552ee79a (`crates/kernel/eliot-ors/src/store/lease_census.rs`,
//! M2 integration copy; no authorship change, no duplicate owner).
//!
//! This module reads the canonical current-row table in one redb snapshot. It
//! never reconstructs authority from Host references or caller-provided ids.

use super::{
    OrsError, RUNTIME_LEASE_CURRENT, RedbRecoveryStore, SUPERVISION_LEASE_CURRENT, decode,
    decode_named, storage,
};
use crate::{OperationIdentity, SupervisionLeaseSnapshot};
use eliot_contracts::StateFence;
use eliot_runtime_contracts::RuntimeLease;
use redb::{ReadableDatabase, ReadableTable};

impl RedbRecoveryStore {
    /// Reads every current RuntimeLease whose complete StateFence equals the
    /// requested fence from one durable ORS snapshot.
    ///
    /// The whole current table is decoded and checked so corruption cannot be
    /// silently hidden by a fence filter. Returned rows are ordered by their
    /// canonical lease id, including terminal rows needed for retirement
    /// reconciliation.
    pub fn load_runtime_leases_by_state_fence(
        &self,
        state_fence: &StateFence,
    ) -> Result<Vec<RuntimeLease>, OrsError> {
        self.load_runtime_lease_census_by_state_fence(state_fence, None)
            .map(|(leases, _)| leases)
    }

    /// Reads the exact-fence RuntimeLease rows and the requested current
    /// SupervisionLease row from one durable ORS snapshot.
    ///
    /// `None` is used only by the RuntimeLease-only compatibility projection;
    /// retirement callers supply the exact current supervision lease identity
    /// retained by the Host journal.
    pub fn load_runtime_lease_census_by_state_fence(
        &self,
        state_fence: &StateFence,
        supervision_lease_id: Option<&OperationIdentity>,
    ) -> Result<(Vec<RuntimeLease>, Option<SupervisionLeaseSnapshot>), OrsError> {
        state_fence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let read = self.database.begin_read().map_err(storage)?;
        let table = read
            .open_table(RUNTIME_LEASE_CURRENT)
            .map_err(storage)?;
        let mut leases = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let lease: RuntimeLease = decode(value.value())?;
            lease
                .validate()
                .map_err(|error| OrsError::Contract(error.to_string()))?;
            if lease.lease_id != key.value() {
                return Err(OrsError::IntegrityProblem {
                    record_type: "runtime_lease",
                    reason: "current row key does not match lease identity".to_owned(),
                });
            }
            if lease.state_fence == *state_fence {
                leases.push(lease);
            }
        }
        leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));

        let supervision_lease = if let Some(lease_id) = supervision_lease_id {
            let table = read
                .open_table(SUPERVISION_LEASE_CURRENT)
                .map_err(storage)?;
            table
                .get(lease_id.as_str())
                .map_err(storage)?
                .map(|value| {
                    let snapshot: SupervisionLeaseSnapshot =
                        decode_named(value.value(), "supervision_lease_current")?;
                    snapshot.validate()?;
                    if snapshot.record.lease_id != *lease_id {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "supervision_lease_current",
                            reason: "current key does not match lease identity".to_owned(),
                        });
                    }
                    Ok(snapshot)
                })
                .transpose()?
        } else {
            None
        };

        Ok((leases, supervision_lease))
    }
}
