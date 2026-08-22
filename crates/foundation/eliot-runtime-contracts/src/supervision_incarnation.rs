//! Provider-neutral identity for one active supervision-lease incarnation.
//!
//! The installer owns the stable authority scope. `HostStateJournal` owns the
//! current activation lineages. This value joins both without making a
//! filesystem path, process liveness, or a numeric epoch an authority.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{RegisteredActivityWakePolicy, RuntimeContractError, SupervisionObservationScope};

/// Stable domain used when deriving the scope reference for one authority
/// scope and its immutable observation policy.
pub const SUPERVISION_SCOPE_REF_DOMAIN: &str = "eliot.supervision.scope-ref.v1";
/// Stable domain used when deriving the active lease identity.
pub const SUPERVISION_LEASE_ID_DOMAIN: &str = "eliot.supervision.lease-id.v1";
/// Prefix for derived scope references.
pub const SUPERVISION_SCOPE_REF_PREFIX: &str = "eliot-supervision-scope:v1:";
/// Prefix for derived active lease identities.
pub const SUPERVISION_LEASE_ID_PREFIX: &str = "eliot-supervision-lease:v1:";

/// Immutable observation scope selected by the current installer/runtime
/// contour.  Every producer and consumer uses this value rather than
/// reconstructing policy from ambient configuration.
pub fn canonical_observation_scope() -> SupervisionObservationScope {
    SupervisionObservationScope {
        targets: vec!["eliot-kernel".to_owned()],
        sensor_profile: "eliot-runtime-live-v3".to_owned(),
        claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
        governance_axis: "runtime-live-v3".to_owned(),
    }
}

/// Immutable wake policy selected by the current installer/runtime contour.
pub const fn canonical_wake_policy() -> RegisteredActivityWakePolicy {
    RegisteredActivityWakePolicy::Disabled
}

/// One journal-owned epoch identity. Numeric equality without the lineage is
/// never sufficient to identify a current activation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionJournalEpoch {
    /// Stable lineage namespace issued by `HostStateJournal`.
    pub lineage_id: String,
    /// Positive sequence within that lineage.
    pub sequence: u64,
}

impl SupervisionJournalEpoch {
    /// Validates the complete journal identity.
    pub fn validate(&self, field: &'static str) -> Result<(), RuntimeContractError> {
        validate_text(&self.lineage_id, field)?;
        if self.sequence == 0 {
            return Err(RuntimeContractError::Blank { field });
        }
        Ok(())
    }
}

/// Exact predecessor needed to fence an already active ORS lease before a
/// new incarnation is committed. `None` is valid only for the first genesis
/// activation; ORS remains authoritative for the actual terminal transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeasePredecessorIdentity {
    /// Previously derived active lease identity.
    pub supervision_lease_id: String,
    /// Last durable ORS receipt digest observed in the Host journal.
    pub ors_receipt_sha256: String,
}

impl SupervisionLeasePredecessorIdentity {
    /// Validates the journaled predecessor shape.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        validate_text(
            &self.supervision_lease_id,
            "supervision_predecessor.supervision_lease_id",
        )?;
        if !is_sha256_hex(&self.ors_receipt_sha256) {
            return Err(RuntimeContractError::InvalidField {
                field: "supervision_predecessor.ors_receipt_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        Ok(())
    }
}

/// Provider-neutral binding for the exact active Host/Kernel/Watchdog
/// supervision incarnation.
///
/// The stable `supervision_lease_scope_id` comes from the installer Phase-A/Phase-B
/// contract. Every other identity is read from the current Host journal. The
/// derived lease identity therefore changes across a restart or recovered
/// lineage, while the old lease remains an explicit predecessor and can never
/// become current through a directory scan or a copied marker.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionLeaseIncarnationBinding {
    /// Stable installer-owned supervision authority scope.
    pub supervision_lease_scope_id: String,
    /// Deterministic active lease identity derived from this full binding.
    pub supervision_lease_id: String,
    /// Digest of the stable scope and immutable observation/wake policy.
    pub scope_ref_digest: String,
    /// Installation identity owning the journal.
    pub installation_id: String,
    /// Current Host epoch lineage and sequence.
    pub host_epoch: SupervisionJournalEpoch,
    /// Current activation identity from the Host journal.
    pub activation_id: String,
    /// Current activation generation lineage and sequence.
    pub activation_generation: SupervisionJournalEpoch,
    /// Current Kernel generation lineage and sequence.
    pub kernel_generation: SupervisionJournalEpoch,
    /// Current Watchdog epoch lineage and sequence.
    pub watchdog_epoch: SupervisionJournalEpoch,
    /// Canonical observation scope selected for this authority scope.
    pub observation_scope: SupervisionObservationScope,
    /// Canonical wake policy selected for this authority scope.
    pub wake_policy: RegisteredActivityWakePolicy,
    /// Optional exact active predecessor retained in the Host journal.
    pub predecessor: Option<SupervisionLeasePredecessorIdentity>,
}

impl SupervisionLeaseIncarnationBinding {
    /// Current binding contract revision. This is a required candidate field;
    /// callers must bump their enclosing control wire when its shape changes.
    pub const CONTRACT_VERSION: u16 = 1;

    /// Validates the exact typed contour without consulting a filesystem.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        self.validate_shape()?;
        if !is_sha256_hex(&self.scope_ref_digest) {
            return Err(RuntimeContractError::InvalidField {
                field: "supervision.scope_ref_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.scope_ref_digest != self.scope_ref_digest()? {
            return Err(RuntimeContractError::InvalidField {
                field: "supervision.scope_ref_digest",
                reason: "does not match the stable scope and policy",
            });
        }
        if self.supervision_lease_id != self.computed_lease_id()? {
            return Err(RuntimeContractError::InvalidField {
                field: "supervision.supervision_lease_id",
                reason: "does not match the full journal incarnation",
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), RuntimeContractError> {
        for (value, field) in [
            (
                &self.supervision_lease_scope_id,
                "supervision.supervision_lease_scope_id",
            ),
            (&self.installation_id, "supervision.installation_id"),
            (&self.activation_id, "supervision.activation_id"),
        ] {
            validate_text(value, field)?;
        }
        self.host_epoch
            .validate("supervision.host_epoch.lineage_id")?;
        self.activation_generation
            .validate("supervision.activation_generation.lineage_id")?;
        self.kernel_generation
            .validate("supervision.kernel_generation.lineage_id")?;
        self.watchdog_epoch
            .validate("supervision.watchdog_epoch.lineage_id")?;
        self.observation_scope
            .validate()
            .map_err(|_| RuntimeContractError::InvalidField {
                field: "supervision.observation_scope",
                reason: "observation scope is invalid",
            })?;
        self.wake_policy
            .validate()
            .map_err(|_| RuntimeContractError::InvalidField {
                field: "supervision.wake_policy",
                reason: "wake policy is invalid",
            })?;
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        Ok(())
    }

    /// Returns the digest of the stable authority scope plus its immutable
    /// observation and wake policy. Dynamic journal lineages are excluded.
    pub fn scope_ref_digest(&self) -> Result<String, RuntimeContractError> {
        self.validate_shape()?;
        let bytes = canonical_json_bytes(&(
            SUPERVISION_SCOPE_REF_DOMAIN,
            &self.supervision_lease_scope_id,
            &self.observation_scope,
            &self.wake_policy,
        ))
        .map_err(|_| RuntimeContractError::Blank {
            field: "supervision.scope_ref_digest",
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns the canonical ORS `scope_ref` selector.
    pub fn derived_scope_ref(&self) -> Result<String, RuntimeContractError> {
        Ok(format!(
            "{SUPERVISION_SCOPE_REF_PREFIX}{}",
            self.scope_ref_digest()?
        ))
    }

    /// Returns the deterministic active lease ID for this exact journal
    /// incarnation and predecessor fence.
    pub fn computed_lease_id(&self) -> Result<String, RuntimeContractError> {
        self.validate_shape()?;
        let bytes = canonical_json_bytes(&(
            SUPERVISION_LEASE_ID_DOMAIN,
            &self.supervision_lease_scope_id,
            &self.installation_id,
            &self.host_epoch,
            &self.activation_id,
            &self.activation_generation,
            &self.kernel_generation,
            &self.watchdog_epoch,
            &self.observation_scope,
            &self.wake_policy,
            &self.predecessor,
        ))
        .map_err(|_| RuntimeContractError::Blank {
            field: "supervision.lease_id",
        })?;
        Ok(format!(
            "{SUPERVISION_LEASE_ID_PREFIX}{}",
            sha256_hex(&bytes)
        ))
    }

    /// Seals the derived IDs after all journal values have been populated.
    pub fn with_derived_ids(mut self) -> Result<Self, RuntimeContractError> {
        self.validate_shape()?;
        self.scope_ref_digest = self.scope_ref_digest()?;
        self.supervision_lease_id = self.computed_lease_id()?;
        Ok(self)
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), RuntimeContractError> {
    if value.is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        return Err(RuntimeContractError::Blank { field });
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn binding(
        predecessor: Option<SupervisionLeasePredecessorIdentity>,
    ) -> SupervisionLeaseIncarnationBinding {
        SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:generation-1".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-1".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-1".to_owned(),
                sequence: 2,
            },
            activation_id: "activation-1".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-1".to_owned(),
                sequence: 3,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-1".to_owned(),
                sequence: 4,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-1".to_owned(),
                sequence: 5,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor,
        }
    }

    #[test]
    fn derived_identity_binds_all_journal_lineages() {
        let first = binding(None).with_derived_ids().expect("sealed binding");
        let first_id = first.computed_lease_id().expect("lease id");
        let mut changed = first.clone();
        changed.kernel_generation.sequence += 1;
        assert_ne!(first_id, changed.computed_lease_id().expect("lease id"));
        assert_eq!(
            first.scope_ref_digest().expect("scope digest"),
            binding(Some(SupervisionLeasePredecessorIdentity {
                supervision_lease_id: "old-lease".to_owned(),
                ors_receipt_sha256: "a".repeat(64),
            }))
            .scope_ref_digest()
            .expect("scope digest")
        );
    }

    #[test]
    fn scope_digest_excludes_dynamic_lineages() {
        let first = binding(None).with_derived_ids().expect("sealed binding");
        let mut changed = first.clone();
        changed.host_epoch.sequence += 1;
        assert_eq!(
            first.scope_ref_digest().expect("scope digest"),
            changed.scope_ref_digest().expect("scope digest")
        );
    }

    #[test]
    fn invalid_predecessor_and_zero_epoch_are_rejected() {
        let mut invalid = binding(Some(SupervisionLeasePredecessorIdentity {
            supervision_lease_id: "old-lease".to_owned(),
            ors_receipt_sha256: "not-a-digest".to_owned(),
        }));
        assert!(invalid.validate().is_err());
        invalid.predecessor = None;
        invalid.host_epoch.sequence = 0;
        assert!(invalid.validate().is_err());
    }
}
