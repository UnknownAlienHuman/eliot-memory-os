//! I1.9: the durable current revocation-event and effect-delivery state a
//! generation's effect authority is gated on.
//!
//! I1.9 gates an effect-capable generation on two facts beyond its manifest:
//! "revocation event unacknowledged or delivery gap open -> candidate may start
//! in shadow/no-effect diagnostic mode only". Both are already named in this
//! crate as [`crate::RevocationAcknowledgement`] and
//! [`crate::EffectDeliveryAcknowledgement`], but on this branch they were only
//! ever values a caller typed into a request struct — nothing durable held the
//! current state, so "current" meant "whatever the caller said". That is the
//! read side of issue #1884 external audit comment 5946154380, section 4, which
//! requires ORS to read and check the current revocation and delivery state for
//! one exact leased operation.
//!
//! These two records are that durable state. They are the single writer's
//! (Kernel/ORS's) operational state for one `{lease_id, module_id, generation}`,
//! they bind to the exact operation identity the lease authorized, and they carry
//! no authority of their own: a record here never admits an effect, never revokes
//! one and never restores one.
//!
//! What they do NOT prove:
//!
//! * They do not prove an event was delivered or acknowledged by anything. They
//!   record what ORS was told and by whom; a caller that cannot state the
//!   current state must fail rather than report a fresh-looking one, which is why
//!   both types derive `Deserialize` under `deny_unknown_fields` with no
//!   `#[serde(default)]` and why `validate` refuses a blank identity, a
//!   non-positive clock and — for revocation — a `None` acknowledgement.
//! * They do not replace the lease. The lease's expiry, Authority Epoch,
//!   Catalog/Policy revisions and manifest binding are read from
//!   [`crate::EffectOperationLease`] itself, by
//!   [`crate::authorize_effect_replay`]; nothing here restates or recomputes any
//!   of them.
//! * They are not the escalation. A revoked or gap-open state produces a
//!   [`crate::KernelReconciliationItem`] through the replay gate, and the
//!   generation's own lifecycle record
//!   ([`crate::GenerationLifecycleRecord`]) is what blocks launch, routes and
//!   new leases. These records are the durable state those decisions read.
//!
//! No record here decides anything: [`RevocationEventRecord::validate`] and
//! [`EffectDeliveryRecord::validate`] answer only "is this row well formed".

use eliot_contracts::ResourceGeneration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::execution_manifest::{EffectDeliveryAcknowledgement, RevocationAcknowledgement};
use crate::model::{OperationIdentity, OrsError, validate_text};

/// Durable schema version of the effect current-state records (I1.9).
pub const EFFECT_CURRENT_STATE_SCHEMA_VERSION: u16 = 1;

/// The durable current revocation-event state for one leased operation.
///
/// I1.9 admits an effect-capable generation to shadow/no-effect diagnostics only
/// while a revocation event is unacknowledged or acknowledged, so this row is
/// the current answer to "is a revocation event outstanding for this exact
/// operation". It is bound to the exact lease identity and the exact operation
/// identity that lease authorized, so a record for one operation can never be
/// read as the state of another.
///
/// `RevocationAcknowledgement::None` is NOT valid here: this row exists to record
/// a revocation event's state, so an absent event is the absence of the row, not
/// a value inside it. A generation with no revocation event has no row and is
/// therefore not "cleared" by this record — it is unrecorded, and the issuance
/// path's revocation readback is what must state `None` for it. This is what
/// stops a defaulted `None` from reading as "no revocation outstanding".
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEventRecord {
    /// Durable schema version of this record.
    pub schema_version: u16,
    /// Identity of the effect operation lease this revocation state belongs to.
    pub lease_id: OperationIdentity,
    /// The one exact operation identity that lease authorized.
    pub operation_id: OperationIdentity,
    /// Module identity of the generation the lease was admitted against.
    pub module_id: String,
    /// Generation identity of that module.
    pub generation: ResourceGeneration,
    /// Recorded acknowledgement state of the revocation event.
    pub acknowledgement: RevocationAcknowledgement,
    /// Observation time of the recorded state in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl RevocationEventRecord {
    /// Validates the record's own shape.
    ///
    /// A durable row is re-validated on every readback, so a blank identity, a
    /// non-positive clock or a row that claims no revocation event at all fails
    /// closed as corruption rather than surviving as current state.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != EFFECT_CURRENT_STATE_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        validate_text(self.lease_id.as_str(), "revocation_event_record_lease_id")?;
        validate_text(
            self.operation_id.as_str(),
            "revocation_event_record_operation_id",
        )?;
        validate_text(&self.module_id, "revocation_event_record_module_id")?;
        if matches!(self.acknowledgement, RevocationAcknowledgement::None) {
            return Err(OrsError::InvalidField {
                field: "revocation_event_record_acknowledgement",
                reason: "a recorded revocation event is either acknowledged or unacknowledged",
            });
        }
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "revocation_event_record_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// The durable current delivery acknowledgement for one leased operation's
/// effect.
///
/// I1.9 sends an effect-capable candidate to shadow/no-effect diagnostics while a
/// delivery gap is open, because an open gap means the outcome of the affected
/// effect is not proven. This row is the current answer to that question for one
/// exact leased operation, bound to the same lease and operation identities as
/// [`RevocationEventRecord`], so a delivery state recorded for one operation can
/// never gate or clear another.
///
/// `GapOpen` is a recorded state here, not a refusal: the row records that the
/// outcome is unproven, and the refusal itself is produced by
/// [`crate::authorize_effect_replay`]. `Acknowledged` records that the delivery
/// path is fully acknowledged. Neither value restores an expired, revoked or
/// foreign-epoch lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectDeliveryRecord {
    /// Durable schema version of this record.
    pub schema_version: u16,
    /// Identity of the effect operation lease this delivery state belongs to.
    pub lease_id: OperationIdentity,
    /// The one exact operation identity that lease authorized.
    pub operation_id: OperationIdentity,
    /// Module identity of the generation the lease was admitted against.
    pub module_id: String,
    /// Generation identity of that module.
    pub generation: ResourceGeneration,
    /// Recorded acknowledgement state of the effect's delivery path.
    pub acknowledgement: EffectDeliveryAcknowledgement,
    /// Observation time of the recorded state in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl EffectDeliveryRecord {
    /// Validates the record's own shape.
    ///
    /// As with the revocation row, a durable readback re-runs this, so a blank
    /// identity, a non-positive clock or a decoded row that does not satisfy its
    /// own shape fails closed as corruption instead of becoming current state.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != EFFECT_CURRENT_STATE_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        validate_text(self.lease_id.as_str(), "effect_delivery_record_lease_id")?;
        validate_text(
            self.operation_id.as_str(),
            "effect_delivery_record_operation_id",
        )?;
        validate_text(&self.module_id, "effect_delivery_record_module_id")?;
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "effect_delivery_record_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}
