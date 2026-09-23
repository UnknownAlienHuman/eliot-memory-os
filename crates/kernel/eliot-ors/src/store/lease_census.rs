//! Exact-fence readback for Kernel-owned runtime leases.
//!
//! This module reads the canonical current-row table in one redb snapshot. It
//! never reconstructs authority from Host references or caller-provided ids.

use super::{
    OrsError, RUNTIME_LEASE_CURRENT, RedbRecoveryStore, SUPERVISION_LEASE_CURRENT, decode,
    decode_named, encode, storage,
};
use crate::{OperationIdentity, SupervisionLeaseSnapshot};
use eliot_contracts::StateFence;
use eliot_runtime_contracts::{LeaseState, RuntimeLease};
use redb::{ReadableDatabase, ReadableTable};

impl RedbRecoveryStore {
    /// Recovers one exact Requested lease after the Kernel has re-read its
    /// durable owner. The caller supplies the owner-derived next projection;
    /// this method provides the ORS compare-and-swap and durable readback.
    pub fn resolve_requested_runtime_lease(
        &self,
        expected: &RuntimeLease,
        next: &RuntimeLease,
    ) -> Result<RuntimeLease, OrsError> {
        expected
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        next.validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let legal_state = matches!(
            next.state,
            LeaseState::Active | LeaseState::Released | LeaseState::Expired | LeaseState::Revoked
        );
        let same_owner = expected.lease_id == next.lease_id
            && expected.scope_ref == next.scope_ref
            && expected.authority_epoch == next.authority_epoch
            && expected.state_fence == next.state_fence
            && expected.obligation.holder == next.obligation.holder
            && expected.obligation.reason == next.obligation.reason
            && expected.obligation.required_runtime_branches
                == next.obligation.required_runtime_branches
            && expected.obligation.required_capabilities == next.obligation.required_capabilities
            && expected.obligation.obligation_refs == next.obligation.obligation_refs
            && expected.obligation.issued_at_ms == next.obligation.issued_at_ms
            && expected.obligation.expires_at_ms == next.obligation.expires_at_ms
            && expected.obligation.renew_before_ms == next.obligation.renew_before_ms;
        if expected.state != LeaseState::Requested
            || !legal_state
            || !same_owner
            || next.revision != expected.revision.checked_add(1).unwrap_or_default()
            || expected.transition_to(next.state).is_err()
            || next.obligation.renewal_evidence.is_empty()
            || (next.state == LeaseState::Active && next.obligation.terminal_disposition.is_some())
            || (next.state != LeaseState::Active && next.obligation.terminal_disposition.is_none())
        {
            return Err(OrsError::InvalidTransition);
        }

        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RUNTIME_LEASE_CURRENT).map_err(storage)?;
            let current: RuntimeLease = {
                let current = table
                    .get(expected.lease_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "runtime_lease",
                        reason: "requested recovery target is absent".to_owned(),
                    })?;
                decode(current.value())?
            };
            if current != *expected {
                return Err(OrsError::IntegrityProblem {
                    record_type: "runtime_lease",
                    reason: "requested recovery revision or owner changed".to_owned(),
                });
            }
            let payload = encode(next)?;
            table
                .insert(next.lease_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        let readback = self
            .load_current_runtime_lease(&next.lease_id)?
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "runtime_lease",
                reason: "requested recovery row disappeared before readback".to_owned(),
            })?;
        if readback != *next {
            return Err(OrsError::IntegrityProblem {
                record_type: "runtime_lease",
                reason: "requested recovery readback differs from owner-derived transition"
                    .to_owned(),
            });
        }
        Ok(readback)
    }

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
