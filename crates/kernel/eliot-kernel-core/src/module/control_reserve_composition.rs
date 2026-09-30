//! I14.3 Kernel composition collecting published owner rows into one profile
//! (issue #1679, A1).
//!
//! The frozen contract in
//! `crates/foundation/eliot-runtime-contracts/control-reserve.contract.toml`
//! names this step's owner: "Kernel composition over owner-produced capacity
//! evidence". Each runtime owner enforces and reports its own capacities and
//! publishes one [`BottleneckCapacityProfile`] row per dimension it owns
//! (Kernel front-door partitions, ORS, Store, Host/process, IPC/platform,
//! notification, runtime resources, disk path). This module is the Kernel
//! composition step that collects those published rows and feeds them to the
//! existing [`compile_control_reserve_profile`] as real evidence. It is the
//! caller the compiler's `STITCH` note names: the compiler no longer waits
//! for a composition that does not exist.
//!
//! The composition owns no capacity vocabulary of its own. Wave grouping is
//! organizational only: one `&[BottleneckCapacityProfile]` slice per owner
//! wave, in any order. A row joins the dimension its own `bottleneck` names,
//! matched against the frozen [`frozen_bottleneck_owner_map`] in frozen
//! contract order; no wave position ever selects a dimension, so this module
//! carries no second owner map beside the frozen one.
//!
//! What the composition deliberately does not do:
//!
//! - it allocates nothing beyond the evidence records and the compiled
//!   profile: no queue, no semaphore, no permit, no lease, no cache, no
//!   second capacity store, no scheduler, no ledger, no lock;
//! - it grants no authority and acquires no capacity;
//! - it observes no owner. Every quantity in the result is copied from an
//!   owner-published row; the configuration snapshot and Authority Epoch
//!   bound into the evidence are exactly the composition-resolved identity
//!   values, never defaults read from ambient configuration;
//! - it substitutes no default. A dimension with no published row is left
//!   out of the evidence so the compiler lowers it to an explicit `UNKNOWN`
//!   row; a dimension whose owner declares `UNSUPPORTED` passes through with
//!   the state that owner declared, carrying no capacity claim.
//!
//! Legality checks are reused, never added. Each joined row is accepted only
//! when the existing [`BottleneckCapacityProfile::validate`] accepts it, and
//! the compiled profile is returned only when the existing
//! [`ControlReserveProfile::validate`] accepts it. A row that is not
//! contract-canonical, or two rows that claim one dimension across waves,
//! fail here as the typed [`KernelError::ControlReserveEvidenceContradiction`]
//! rather than joining as a healthy dimension; the frozen owner-match itself
//! stays with the profile compiler, which already refuses a `CLAIMED` row
//! naming an owner the frozen owner map does not bind to that dimension.
//!
//! Consequently this composition entry itself awaits its driver: the Kernel
//! composition root that resolves the configuration snapshot, Authority
//! Epoch, clock reading and the per-wave published rows does not exist in
//! this tree. `STITCH`: the entry is landed without a driver rather than
//! given a manufactured one (no startup hook, no `fn main` call, no
//! discarded-result statement).

use eliot_runtime_contracts::{
    BottleneckCapacityProfile, CapacityBottleneck, ControlReserveProfile,
    frozen_bottleneck_owner_map,
};

use crate::error::{KernelError, KernelResult};
use crate::module::control_reserve_profile_compiler::{
    BottleneckOwnerEvidence, ControlReserveProfileIdentity, compile_control_reserve_profile,
};

/// Collects the owner waves' published rows and compiles the complete current
/// capacity profile.
///
/// `owner_waves` carries one slice of owner-published rows per owner wave
/// (front-door, ORS, Store, Host/process, IPC/platform, notification,
/// runtime resources, disk path), in any order and with absent waves simply
/// left out: a wave that has not published contributes no slice, or an empty
/// one, and its dimensions compile to explicit `UNKNOWN` rows. Grouping is
/// organizational only; every row is matched by its own `bottleneck` against
/// the frozen owner map in frozen contract order, and evidence records are
/// built in that same order.
///
/// The result carries exactly one row per [`CapacityBottleneck`] with current
/// owner evidence or an explicit `UNSUPPORTED`/`UNKNOWN` state, because the
/// existing [`compile_control_reserve_profile`] joins the evidence and the
/// existing [`ControlReserveProfile::validate`] accepts the profile before it
/// is returned. The composition performs no allocation beyond the evidence
/// records and the profile, holds no state across calls, and takes no lock.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when the composition-supplied
/// configuration snapshot reference is blank. Returns
/// [`KernelError::ControlReserveEvidenceContradiction`] when two published
/// rows claim one dimension across waves, or when a published row is not
/// contract-canonical. Returns the existing runtime-contract error when the
/// joined evidence or the identity is not contract-canonical, for example
/// when a profile-level reference set is not canonical.
pub fn compose_control_reserve_profile(
    identity: ControlReserveProfileIdentity,
    owner_waves: &[&[BottleneckCapacityProfile]],
) -> KernelResult<ControlReserveProfile> {
    if identity.config_snapshot_ref.trim().is_empty() {
        return Err(KernelError::InvalidField {
            field: "control_reserve.config_snapshot_ref",
            reason: "must be non-blank",
        });
    }
    let owner_map = frozen_bottleneck_owner_map();
    let mut owner_evidence = Vec::with_capacity(owner_map.len());
    for bound in &owner_map {
        if let Some(row) = evidence_row_for(bound.bottleneck, owner_waves)? {
            row.validate().map_err(|_| {
                contradiction(
                    bound.bottleneck,
                    "NONCANONICAL_OWNER_ROW: a published row is not contract-canonical",
                )
            })?;
            owner_evidence.push(BottleneckOwnerEvidence {
                config_snapshot_ref: identity.config_snapshot_ref.clone(),
                authority_epoch_ref: identity.authority_epoch_ref.clone(),
                row: row.clone(),
            });
        }
    }
    compile_control_reserve_profile(identity, &owner_evidence)
}

/// Finds the single published row for one bottleneck across every owner wave.
///
/// A dimension with no published row yields `None` so the compiler lowers its
/// guarantee to an explicit `UNKNOWN` row instead of receiving a substituted
/// default. Two rows claiming one dimension are a contradiction: one owner's
/// numbers are never picked over another's.
fn evidence_row_for(
    bottleneck: CapacityBottleneck,
    owner_waves: &[&[BottleneckCapacityProfile]],
) -> KernelResult<Option<&BottleneckCapacityProfile>> {
    let mut matches = owner_waves
        .iter()
        .flat_map(|wave| wave.iter())
        .filter(|row| row.bottleneck == bottleneck);
    let row = match matches.next() {
        Some(row) => row,
        None => return Ok(None),
    };
    if matches.next().is_some() {
        return Err(contradiction(
            bottleneck,
            "DUPLICATE_OWNER_EVIDENCE: two owner waves claim one dimension",
        ));
    }
    Ok(Some(row))
}

/// Names the exact dimension whose published owner rows cannot be joined.
fn contradiction(bottleneck: CapacityBottleneck, reason: &'static str) -> KernelError {
    KernelError::ControlReserveEvidenceContradiction {
        bottleneck: bottleneck.as_contract_str(),
        reason,
    }
}
