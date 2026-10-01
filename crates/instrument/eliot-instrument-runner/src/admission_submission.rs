//! Pre-launch admission submission to the canonical instrument registry (issue #1814 W1).
//!
//! [`submit_admission_snapshot`] runs at the shared admission boundary: it
//! carries the admitted [`InstrumentSpec`](crate::profile::InstrumentSpec)
//! plus the executable supply-chain receipt bound to one launch as the
//! `snapshot_json` of the closed `ApplyInstrumentRegistryState` store
//! mutation, runs the shared snapshot acceptance boundary, and reads the
//! same record back through [`InstrumentRegistry::recover`], validating the
//! original recorded values. The receipt binds the exact bytes that launch:
//! the canonicalized path arrives from the owner-observed identity
//! (canonicalize-at-use), the digest is hashed from that same observed
//! object (hash-same-object), and provenance is the admitted spec digest at
//! the admitted registry generation. The bytes travel to durable storage
//! through the Governor write path; this module never writes canonical
//! state itself.

use std::collections::BTreeMap;

use eliot_store_api::{
    NamedMutationOperation, NamedReadOperation, decode_instrument_registry_mutation,
};
use serde_json::Value;

use crate::profile::{AdmittedStage, InstrumentRegistry, ProfileError};
use crate::registry::{ResolvedExecutableIdentity, SupplyChainReceipt};

/// Closed `ApplyInstrumentRegistryState` mutation for one admitted stage launch.
///
/// The snapshot carries every admitted spec and supply-chain receipt at the
/// admitted registry generation, including this operation's spec and
/// receipt; the bound digests pin exactly which record this launch was
/// admitted under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionSubmission {
    snapshot_json: String,
    spec_digest: String,
    supply_digest: String,
    executable_path: String,
    content_digest: String,
}

impl AdmissionSubmission {
    /// Store mutation this submission executes.
    pub fn operation(&self) -> NamedMutationOperation {
        NamedMutationOperation::ApplyInstrumentRegistryState
    }

    /// Store read that returns the same record back.
    pub fn read_operation(&self) -> NamedReadOperation {
        NamedReadOperation::GetInstrumentRegistryState
    }

    /// Verbatim snapshot bytes the store path persists.
    pub fn snapshot_json(&self) -> &str {
        &self.snapshot_json
    }

    /// Mutation parameters: exactly the `snapshot_json` the store decoder accepts.
    pub fn parameters(&self) -> BTreeMap<String, Value> {
        BTreeMap::from([(
            "snapshot_json".to_owned(),
            Value::String(self.snapshot_json.clone()),
        )])
    }

    /// Admitted spec digest this launch was bound under.
    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }

    /// Admitted supply-chain receipt digest this launch was bound under.
    pub fn supply_digest(&self) -> &str {
        &self.supply_digest
    }

    /// Canonicalized executable path of the object that launches.
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// Content digest of the exact executable bytes that launch.
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

/// Submits the admitted spec plus executable supply-chain receipt bound to
/// one pre-launch admission as the `ApplyInstrumentRegistryState` store
/// mutation, and reads the same record back.
///
/// The live registry must still admit the stage's spec digest, and the
/// admitted receipt must still pin that spec digest and the observed
/// executable object; an explicit receipt absence must still be absent.
/// The persisted snapshot then crosses the shared snapshot acceptance
/// boundary and is recovered and compared against the original recorded
/// values, so a replaced spec, receipt, or generation fails closed here
/// instead of launching an unbound child process.
///
/// # Errors
///
/// Returns [`ProfileError::UnknownSpec`] when the live registry no longer
/// admits the stage's spec, or [`ProfileError::Snapshot`] when the spec,
/// receipt, or generation drifted, the observation no longer matches the
/// receipt, or the snapshot fails acceptance or readback.
pub fn submit_admission_snapshot(
    registry: &InstrumentRegistry,
    stage: &AdmittedStage,
    observed: &ResolvedExecutableIdentity,
) -> Result<AdmissionSubmission, ProfileError> {
    let kind = stage.spec.as_str();
    let spec = registry
        .spec(kind)
        .ok_or_else(|| ProfileError::UnknownSpec {
            profile: stage.profile.clone(),
            stage: stage.stage_id.clone(),
            spec: kind.to_owned(),
        })?;
    let spec_digest = spec.digest();
    if spec_digest != stage.spec_digest {
        return Err(ProfileError::Snapshot {
            detail: "admitted spec was replaced since compilation".to_owned(),
        });
    }
    let admitted_supply = stage
        .supply_receipt
        .as_ref()
        .map(SupplyChainReceipt::digest)
        .unwrap_or_default();
    match (&stage.supply_receipt, registry.supply_chain(kind)) {
        (Some(receipt), Some(live)) => {
            receipt
                .check_observation(observed)
                .map_err(|error| ProfileError::Snapshot {
                    detail: error.to_string(),
                })?;
            if receipt.spec_digest != spec_digest || live.digest() != admitted_supply {
                return Err(ProfileError::Snapshot {
                    detail: "admitted supply-chain receipt was replaced since compilation"
                        .to_owned(),
                });
            }
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(ProfileError::Snapshot {
                detail: "admitted supply-chain receipt was replaced since compilation".to_owned(),
            });
        }
    }
    let snapshot_json = registry.persist()?;
    let submission = AdmissionSubmission {
        snapshot_json,
        spec_digest: stage.spec_digest.clone(),
        supply_digest: admitted_supply.clone(),
        executable_path: observed.canonical_path.clone(),
        content_digest: observed.content_digest.clone(),
    };
    // Validate the exact operation content this submission executes: the
    // shared `ApplyInstrumentRegistryState` acceptance boundary runs over
    // `submission.parameters()`, so the compared bytes can never diverge
    // from the executed mutation.
    let admitted_bytes =
        decode_instrument_registry_mutation(&submission.parameters()).map_err(|error| {
            ProfileError::Snapshot {
                detail: error.to_string(),
            }
        })?;
    let recovered = InstrumentRegistry::recover(&admitted_bytes)?;
    let recovered_spec = recovered
        .spec(kind)
        .ok_or_else(|| ProfileError::UnknownSpec {
            profile: stage.profile.clone(),
            stage: stage.stage_id.clone(),
            spec: kind.to_owned(),
        })?;
    if recovered_spec.digest() != stage.spec_digest
        || recovered
            .supply_chain(kind)
            .map(SupplyChainReceipt::digest)
            .unwrap_or_default()
            != admitted_supply
        || recovered.generation() != registry.generation()
    {
        return Err(ProfileError::Snapshot {
            detail: "instrument registry readback differs from the admitted record".to_owned(),
        });
    }
    Ok(submission)
}
