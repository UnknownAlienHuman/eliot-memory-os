//! Store-local schema bootstrap command, receipt, and binding contract.
//!
//! Architecture: A12.3 One governed write path.
//! Implementation: I5.1 provider-owned store seam, I5.4-I5.8 canonical
//! transition/admission boundaries, and I5.19 exact receipts and outcomes.

use eliot_contracts::StateFence;
use eliot_installation::InstallationProfile;
use eliot_platform::ClockObservation;
use eliot_store_api::StoreError;
use eliot_store_surreal_adapter::{AdapterError, CompiledMigration, MigrationReceipt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{StoreLaunchConfig, validate_digest, validate_launch_text};

/// A bounded, non-wire command for the future transaction-owned
/// `MigrateStoreSchema` operation.
///
/// The command deliberately carries only binding material. It contains no
/// credential and no provider query text; the Store process resolves its
/// configured credential and the adapter owns the sole `SurrealDB` writer.
/// Host/installer IPC is intentionally not part of this seam yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSchemaBootstrapCommand {
    /// Installation lineage that owns the Store launch descriptor.
    pub installation_id: String,
    /// Exact candidate-generation handle from the Host launch descriptor.
    pub generation: String,
    /// Authority generation from the Host launch descriptor.
    pub authority_generation: u64,
    /// Digest of the complete approved Store launch configuration.
    pub approved_config_hash: String,
    /// Authority/state fence copied from the approved launch descriptor.
    pub state_fence: StateFence,
    /// Compiler-approved migration identity.
    pub migration_id: String,
    /// Compiler-derived migration checksum.
    pub migration_checksum_sha256: String,
    /// Explicit P-01 clock observation supplied by the future authority owner.
    pub observed_clock: ClockObservation,
}

/// Authoritative Store-side result of one schema bootstrap attempt.
///
/// The receipt is a complete binding projection, not a generic "success"
/// boolean. An exact replay after a process restart returns the same values
/// after the adapter reads and verifies durable `schema_meta` and fence state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSchemaBootstrapReceipt {
    pub installation_id: String,
    pub generation: String,
    pub authority_generation: u64,
    pub approved_config_hash: String,
    pub state_fence: StateFence,
    pub migration_id: String,
    pub migration_checksum_sha256: String,
    pub generation_after: String,
}

impl StoreSchemaBootstrapReceipt {
    /// Validates the receipt before it is returned across a future control
    /// boundary or retained for an in-process exact replay.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.installation_id, "installation_id")?;
        validate_launch_text(&self.generation, "generation")?;
        validate_launch_text(&self.migration_id, "migration_id")?;
        validate_launch_text(&self.generation_after, "generation_after")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        validate_digest(&self.migration_checksum_sha256, "migration_checksum_sha256")?;
        if self.authority_generation == 0 {
            return Err("authority_generation must be non-zero".to_owned());
        }
        self.state_fence
            .validate()
            .map_err(|error| format!("invalid receipt state_fence: {error}"))
    }
}

/// Error surface for the Store-only schema bootstrap seam.
#[derive(Debug, Error)]
pub enum StoreSchemaBootstrapError {
    /// The command did not match the immutable Store launch binding.
    #[error("schema bootstrap command rejected: {0}")]
    Rejected(String),
    /// The provider crossed the migration effect boundary without a durable
    /// identity that can prove the result.
    #[error("schema bootstrap outcome is unknown for migration {migration_id}")]
    UnknownOutcome { migration_id: String },
    /// The provider returned a partial result that is not safe to interpret
    /// as either committed or absent.
    #[error("schema bootstrap provider outcome is partial; reconcile migration by exact identity")]
    PartialOutcome,
    /// A deterministic Store/API failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

/// Immutable Store-side binding captured at composition time. It is private
/// so callers cannot mint a binding detached from the validated launch config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreSchemaBootstrapBinding {
    pub(super) profile: InstallationProfile,
    installation_id: String,
    generation: String,
    authority_generation: u64,
    approved_config_hash: String,
    state_fence: StateFence,
    schema_generation: String,
}

impl StoreSchemaBootstrapBinding {
    pub(super) fn from_config(config: &StoreLaunchConfig) -> Self {
        Self {
            profile: config.runtime_launch.profile,
            installation_id: config
                .runtime_launch
                .installation_epoch
                .installation
                .as_str()
                .to_owned(),
            generation: config.runtime_launch.generation.as_str().to_owned(),
            authority_generation: config.runtime_launch.authority_generation.value(),
            approved_config_hash: config.approved_config_hash.clone(),
            state_fence: config.runtime_launch.authority_state_fence.clone(),
            schema_generation: config.schema_generation.clone(),
        }
    }

    pub(super) fn validate_command(
        &self,
        command: &StoreSchemaBootstrapCommand,
        migration: &CompiledMigration,
    ) -> Result<(), StoreSchemaBootstrapError> {
        if self.profile != InstallationProfile::SystemService {
            return Err(StoreSchemaBootstrapError::Rejected(
                "schema bootstrap is reserved for the SystemService profile".to_owned(),
            ));
        }
        validate_launch_text(&command.installation_id, "installation_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.generation, "generation")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.migration_id, "migration_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(&command.approved_config_hash, "approved_config_hash")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(
            &command.migration_checksum_sha256,
            "migration_checksum_sha256",
        )
        .map_err(StoreSchemaBootstrapError::Rejected)?;
        if command.authority_generation == 0 {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation must be non-zero".to_owned(),
            ));
        }
        command
            .state_fence
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        command
            .observed_clock
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        if command.observed_clock.valid_time_ms.is_none()
            && command.observed_clock.known_time_ms.is_none()
        {
            return Err(StoreSchemaBootstrapError::Rejected(
                "observed_clock must contain valid_time_ms or known_time_ms".to_owned(),
            ));
        }
        let checks = [
            (
                command.installation_id.as_str(),
                self.installation_id.as_str(),
                "installation_id",
            ),
            (
                command.generation.as_str(),
                self.generation.as_str(),
                "generation",
            ),
            (
                command.approved_config_hash.as_str(),
                self.approved_config_hash.as_str(),
                "approved_config_hash",
            ),
            (
                command.migration_id.as_str(),
                migration.migration_id(),
                "migration_id",
            ),
            (
                command.migration_checksum_sha256.as_str(),
                migration.checksum_sha256(),
                "migration_checksum_sha256",
            ),
        ];
        if let Some((_, _, field)) = checks
            .iter()
            .find(|(provided, expected, _)| provided != expected)
        {
            return Err(StoreSchemaBootstrapError::Rejected(format!(
                "{field} does not match the immutable Store launch/migration binding"
            )));
        }
        if command.authority_generation != self.authority_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if command.state_fence != self.state_fence {
            return Err(StoreSchemaBootstrapError::Rejected(
                "state_fence does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if migration.generation_after().as_str() != self.schema_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "migration generation does not match the configured Store schema generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn receipt(
        &self,
        migration: &MigrationReceipt,
    ) -> Result<StoreSchemaBootstrapReceipt, StoreSchemaBootstrapError> {
        let receipt = StoreSchemaBootstrapReceipt {
            installation_id: self.installation_id.clone(),
            generation: self.generation.clone(),
            authority_generation: self.authority_generation,
            approved_config_hash: self.approved_config_hash.clone(),
            state_fence: self.state_fence.clone(),
            migration_id: migration.migration_id.clone(),
            migration_checksum_sha256: migration.checksum_sha256.clone(),
            generation_after: migration.generation_after.as_str().to_owned(),
        };
        receipt
            .validate()
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        Ok(receipt)
    }

    /// Validates one destination-provision command against the immutable
    /// Store launch binding (issues #952/#975 F3).
    ///
    /// Reserved for the SystemService profile like [`Self::validate_command`]:
    /// only the deployment described by the approved launch descriptor can
    /// provision. Destination fields carry the same text/digest/clock rules
    /// as the schema command; the serving database can never be admitted
    /// as a destination here (the adapter refuses it again at connect).
    pub(super) fn validate_destination_provision(
        &self,
        command: &StoreRestoreDestinationProvisionCommand,
    ) -> Result<(), StoreSchemaBootstrapError> {
        if self.profile != InstallationProfile::SystemService {
            return Err(StoreSchemaBootstrapError::Rejected(
                "destination provisioning is reserved for the SystemService profile".to_owned(),
            ));
        }
        validate_launch_text(&command.installation_id, "installation_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.generation, "generation")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(&command.approved_config_hash, "approved_config_hash")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.dest_store_id, "dest_store_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.dest_installation_id, "dest_installation_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.cutover_authority, "cutover_authority")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        if command.authority_generation == 0 {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation must be non-zero".to_owned(),
            ));
        }
        command
            .state_fence
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        command
            .observed_clock
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        if command.observed_clock.valid_time_ms.is_none()
            && command.observed_clock.known_time_ms.is_none()
        {
            return Err(StoreSchemaBootstrapError::Rejected(
                "observed_clock must contain valid_time_ms or known_time_ms".to_owned(),
            ));
        }
        let checks = [
            (
                command.installation_id.as_str(),
                self.installation_id.as_str(),
                "installation_id",
            ),
            (
                command.generation.as_str(),
                self.generation.as_str(),
                "generation",
            ),
            (
                command.approved_config_hash.as_str(),
                self.approved_config_hash.as_str(),
                "approved_config_hash",
            ),
        ];
        if let Some((_, _, field)) = checks
            .iter()
            .find(|(provided, expected, _)| provided != expected)
        {
            return Err(StoreSchemaBootstrapError::Rejected(format!(
                "{field} does not match the immutable Store launch binding"
            )));
        }
        if command.authority_generation != self.authority_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if command.state_fence != self.state_fence {
            return Err(StoreSchemaBootstrapError::Rejected(
                "state_fence does not match the immutable Store launch binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Projects the destination-provision receipt from the validated
    /// command and the immutable launch binding.
    pub(super) fn destination_provision_receipt(
        &self,
        command: &StoreRestoreDestinationProvisionCommand,
    ) -> Result<StoreRestoreDestinationProvisionReceipt, StoreSchemaBootstrapError> {
        let receipt = StoreRestoreDestinationProvisionReceipt {
            installation_id: self.installation_id.clone(),
            generation: self.generation.clone(),
            authority_generation: self.authority_generation,
            approved_config_hash: self.approved_config_hash.clone(),
            state_fence: self.state_fence.clone(),
            dest_store_id: command.dest_store_id.clone(),
            dest_installation_id: command.dest_installation_id.clone(),
            cutover_authority: command.cutover_authority.clone(),
        };
        receipt
            .validate()
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        Ok(receipt)
    }

    /// Validates one cutover-authority rotation command against the
    /// immutable Store launch binding (issues #952/#975 F5).
    ///
    /// Same deployment-role bar as provisioning: SystemService profile
    /// plus full launch binding match. The expected authority is the
    /// compare-and-set precondition the adapter enforces against the
    /// durable record; the serving flag is immutable in the rotation
    /// statement by construction (see the adapter path).
    pub(super) fn validate_destination_rotate(
        &self,
        command: &StoreRestoreDestinationRotateCommand,
    ) -> Result<(), StoreSchemaBootstrapError> {
        if self.profile != InstallationProfile::SystemService {
            return Err(StoreSchemaBootstrapError::Rejected(
                "destination authority rotation is reserved for the SystemService profile"
                    .to_owned(),
            ));
        }
        validate_launch_text(&command.installation_id, "installation_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.generation, "generation")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(&command.approved_config_hash, "approved_config_hash")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.dest_store_id, "dest_store_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(
            &command.expected_cutover_authority,
            "expected_cutover_authority",
        )
        .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.new_cutover_authority, "new_cutover_authority")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        if command.authority_generation == 0 {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation must be non-zero".to_owned(),
            ));
        }
        command
            .state_fence
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        let checks = [
            (
                command.installation_id.as_str(),
                self.installation_id.as_str(),
                "installation_id",
            ),
            (
                command.generation.as_str(),
                self.generation.as_str(),
                "generation",
            ),
            (
                command.approved_config_hash.as_str(),
                self.approved_config_hash.as_str(),
                "approved_config_hash",
            ),
        ];
        if let Some((_, _, field)) = checks
            .iter()
            .find(|(provided, expected, _)| provided != expected)
        {
            return Err(StoreSchemaBootstrapError::Rejected(format!(
                "{field} does not match the immutable Store launch binding"
            )));
        }
        if command.authority_generation != self.authority_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if command.state_fence != self.state_fence {
            return Err(StoreSchemaBootstrapError::Rejected(
                "state_fence does not match the immutable Store launch binding".to_owned(),
            ));
        }
        Ok(())
    }

    /// Projects the rotation receipt from the validated command and the
    /// immutable launch binding.
    pub(super) fn destination_rotate_receipt(
        &self,
        command: &StoreRestoreDestinationRotateCommand,
    ) -> Result<StoreRestoreDestinationRotateReceipt, StoreSchemaBootstrapError> {
        let receipt = StoreRestoreDestinationRotateReceipt {
            installation_id: self.installation_id.clone(),
            generation: self.generation.clone(),
            authority_generation: self.authority_generation,
            approved_config_hash: self.approved_config_hash.clone(),
            state_fence: self.state_fence.clone(),
            dest_store_id: command.dest_store_id.clone(),
            cutover_authority: command.new_cutover_authority.clone(),
        };
        receipt
            .validate()
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreSchemaBootstrapCache {
    pub(super) command: StoreSchemaBootstrapCommand,
    pub(super) receipt: StoreSchemaBootstrapReceipt,
}

/// Bounded non-wire command provisioning one isolated restore
/// destination (issues #952/#975 R1/F3).
///
/// Like [`StoreSchemaBootstrapCommand`] it carries only binding material:
/// the immutable launch binding plus the destination identity and the
/// separate cutover authority. It contains no credential and no provider
/// query text; the Store process resolves its configured credential and
/// the adapter owns the sole `SurrealDB` writer. This is the production
/// deployment-role path the portable-dev init chain cannot provide:
/// validated against the same immutable launch binding, so only the
/// deployment described by the approved launch descriptor can provision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRestoreDestinationProvisionCommand {
    /// Installation lineage that owns the Store launch descriptor.
    pub installation_id: String,
    /// Exact candidate-generation handle from the Host launch descriptor.
    pub generation: String,
    /// Authority generation from the Host launch descriptor.
    pub authority_generation: u64,
    /// Digest of the complete approved Store launch configuration.
    pub approved_config_hash: String,
    /// Authority/state fence copied from the approved launch descriptor.
    pub state_fence: StateFence,
    /// Explicit P-01 clock observation supplied by the deployment owner.
    pub observed_clock: ClockObservation,
    /// Admitted isolated destination store identity to provision.
    pub dest_store_id: String,
    /// Admitted isolated destination installation identity.
    pub dest_installation_id: String,
    /// Separate cutover authority that alone may accept cutover later.
    pub cutover_authority: String,
}

/// Authoritative Store-side result of one destination provisioning
/// attempt: the provisioned identity projection, not a generic boolean.
/// An identically admitted command replays against the durable
/// destination record; anything else conflicts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRestoreDestinationProvisionReceipt {
    pub installation_id: String,
    pub generation: String,
    pub authority_generation: u64,
    pub approved_config_hash: String,
    pub state_fence: StateFence,
    pub dest_store_id: String,
    pub dest_installation_id: String,
    pub cutover_authority: String,
}

impl StoreRestoreDestinationProvisionReceipt {
    /// Validates the receipt before it is returned across a future control
    /// boundary or retained for an in-process exact replay.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.installation_id, "installation_id")?;
        validate_launch_text(&self.generation, "generation")?;
        validate_launch_text(&self.dest_store_id, "dest_store_id")?;
        validate_launch_text(&self.dest_installation_id, "dest_installation_id")?;
        validate_launch_text(&self.cutover_authority, "cutover_authority")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        if self.authority_generation == 0 {
            return Err("authority_generation must be non-zero".to_owned());
        }
        self.state_fence
            .validate()
            .map_err(|error| format!("invalid receipt state_fence: {error}"))
    }
}

/// Bounded non-wire command rotating one destination's cutover authority
/// (issues #952/#975 F5).
///
/// Owner-controlled transition without out-of-band bypass: the currently
/// recorded authority must be presented exactly (compare-and-set
/// precondition) and only the authority field may change — destination
/// identity, fence, and especially the serving flag are immutable in this
/// statement. Fence changes are never rotated in place: a new shared
/// fence means provisioning a fresh destination. Serving activation
/// (cutover execution) is refused by every path in this lane and belongs
/// to the coordinated cutover owner (#961); this command rotates who may
/// accept it, never performs it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRestoreDestinationRotateCommand {
    /// Installation lineage that owns the Store launch descriptor.
    pub installation_id: String,
    /// Exact candidate-generation handle from the Host launch descriptor.
    pub generation: String,
    /// Authority generation from the Host launch descriptor.
    pub authority_generation: u64,
    /// Digest of the complete approved Store launch configuration.
    pub approved_config_hash: String,
    /// Authority/state fence copied from the approved launch descriptor.
    pub state_fence: StateFence,
    /// Destination whose authority rotates.
    pub dest_store_id: String,
    /// Currently recorded cutover authority (CAS precondition).
    pub expected_cutover_authority: String,
    /// Replacement cutover authority.
    pub new_cutover_authority: String,
}

/// Authoritative Store-side result of one authority rotation: the
/// destination with its new authority. Identical rotation replays;
/// anything else conflicts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRestoreDestinationRotateReceipt {
    pub installation_id: String,
    pub generation: String,
    pub authority_generation: u64,
    pub approved_config_hash: String,
    pub state_fence: StateFence,
    pub dest_store_id: String,
    pub cutover_authority: String,
}

impl StoreRestoreDestinationRotateReceipt {
    /// Validates the receipt before it is returned across a future control
    /// boundary or retained for an in-process exact replay.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.installation_id, "installation_id")?;
        validate_launch_text(&self.generation, "generation")?;
        validate_launch_text(&self.dest_store_id, "dest_store_id")?;
        validate_launch_text(&self.cutover_authority, "cutover_authority")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        if self.authority_generation == 0 {
            return Err("authority_generation must be non-zero".to_owned());
        }
        self.state_fence
            .validate()
            .map_err(|error| format!("invalid receipt state_fence: {error}"))
    }
}

pub(super) fn map_schema_bootstrap_error(error: AdapterError) -> StoreSchemaBootstrapError {
    match error {
        AdapterError::UnknownMigrationOutcome { migration_id } => {
            StoreSchemaBootstrapError::UnknownOutcome { migration_id }
        }
        AdapterError::PartialOutcome => StoreSchemaBootstrapError::PartialOutcome,
        AdapterError::Config(reason) => StoreSchemaBootstrapError::Rejected(format!(
            "provider rejected the admitted schema bootstrap: {reason}"
        )),
        AdapterError::Store(error) => StoreSchemaBootstrapError::Store(error),
        other => StoreSchemaBootstrapError::Store(other.into_store_error()),
    }
}
