//! Kernel-side Doctor repair-attempt admission (Slice 2, issue #461).
//!
//! Exactly one Doctor operation in the Kernel authority projection: admit
//! one repair attempt bound to Problem and Diagnostic evidence, the target
//! generation and resource envelope, the registered immutable recipe
//! revision, one registered named effect, budget, deadline, cooldown,
//! approval, and cancellation identity. The shape follows the landed P-04
//! admission, activation-receiver, and host-request cutover patterns in this
//! crate: a versioned wire request, a closed admission gate, a canonical
//! admission receipt, and typed rejection and conflict answers.
//!
//! The operation is unadvertised and inert by default
//! ([`DOCTOR_REPAIR_ADVERTISED`] is `false`): Doctor's closed executor
//! fails closed with `KERNEL_ADMISSION_REQUIRED` until the binary slice
//! wires the front-door dispatch arm through [`route_doctor_repair`].
//! Nothing here executes a repair, stores credentials, models, or shell
//! access, or interprets task semantics: Kernel validates immutable
//! identity, principal, epoch and fence, ordering, transition class,
//! operation manifest, and generation compatibility only.
//!
//! Time plumbing: this crate must not grow a `time` dependency for one
//! contour, so every clock bound travels as Unix nanoseconds (`u64`) while
//! every identity binding still goes through the Slice 1 closed contract.
//! `OffsetDateTime` values are never named here: they are moved out of the
//! deserialized Slice 1 request by type inference, converted to nanos
//! through their accessor methods, and compared against the Kernel integer
//! clock. Nanosecond precision keeps the round trip exact: a deadline or
//! lease expiry converted to nanos and back names the identical instant, so
//! an exact retry rebuilds the identical admission.

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_doctor_core::{
    AttemptIdentityBinding, ClosedRepairRequest, RepairClass, RepairOperationRef, RepairRecipe,
    RepairRecipeIdentity, RepairRecipeManifest, canonical_fence,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptState, DoctorBudgetDecision,
    DoctorBudgetLedger, DoctorEffectRecord, DoctorEffectState, DoctorLedgerError,
    DoctorQuarantineCause, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KernelServiceError, KernelServiceState, validate_text};

/// Stable identity for the Kernel-owned Doctor repair-attempt wire.
pub const DOCTOR_REPAIR_WIRE_ID: &str = "eliot.kernel.doctor-repair-attempt";
/// Current version of the Kernel-owned Doctor repair-attempt wire.
pub const DOCTOR_REPAIR_WIRE_VERSION: u16 = 1;
/// Advertisement for the Doctor repair operation: inert until the binary
/// slice lands. Doctor's closed executor treats `false` as
/// `KERNEL_ADMISSION_REQUIRED` and performs nothing.
pub const DOCTOR_REPAIR_ADVERTISED: bool = false;
/// Owner label minted on every S2 recovery lease. The lease is issued by
/// Kernel admission only; Doctor never supplies lease authority.
pub const DOCTOR_RECOVERY_LEASE_OWNER: &str = "kernel.doctor-recovery";
/// Longest lease a single admission may mint, in nanoseconds (one hour).
/// The admitted lease expiry is the earlier of the presented lease expiry
/// and admission time plus this cap, so a far-future presented lease cannot
/// widen Kernel authority.
pub const DOCTOR_MAX_LEASE_DURATION_NANOS: u64 = 3_600_000_000_000;
/// Largest presented closed-request envelope admitted on this wire, in bytes.
pub const DOCTOR_MAX_ENVELOPE_BYTES: usize = 65_536;
/// Maximum changed-dimension entries admitted in one Doctor conflict report.
pub const DOCTOR_CONFLICT_MAX_FIELDS: usize = 32;

/// Returns whether Kernel currently advertises the Doctor repair operation.
///
/// Always `false` in Slice 2: the tree stays fail-closed until the binary
/// slice wires the front-door dispatch arm.
pub fn advertise_doctor_repair() -> bool {
    DOCTOR_REPAIR_ADVERTISED
}

/// Routes one wire identity to the Doctor repair admission gate.
///
/// Returns `true` only for the exact
/// (`DOCTOR_REPAIR_WIRE_ID`, `DOCTOR_REPAIR_WIRE_VERSION`) pair. The
/// binary-slice front-door arm calls this; every other wire stays inert.
pub fn route_doctor_repair(wire_id: &str, wire_version: u16) -> bool {
    wire_id == DOCTOR_REPAIR_WIRE_ID && wire_version == DOCTOR_REPAIR_WIRE_VERSION
}

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value, field)
}

/// Validates a lowercase SHA-256 wire digest.
fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if !is_lowercase_sha256(value) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Maps a ledger failure to a mechanical Kernel error.
fn doctor_ledger_error(error: &DoctorLedgerError) -> KernelServiceError {
    KernelServiceError::Platform(error.to_string())
}

/// Construction failure for the Kernel-owned immutable recipe registry.
#[derive(Debug, Error)]
pub enum DoctorRegistryError {
    /// The Slice 1 closed contract rejected the manifest or a recipe.
    #[error("doctor closed contract: {0}")]
    Contract(#[from] eliot_doctor_core::DoctorError),
    /// The registry admits no recipe.
    #[error("doctor recipe registry admits no recipe")]
    EmptyRegistry,
    /// Two recipes claim one recipe identity.
    #[error("duplicate doctor recipe {recipe_id} revision {revision}")]
    DuplicateRecipe {
        /// Duplicated recipe identity.
        recipe_id: String,
        /// Duplicated recipe revision.
        revision: u64,
    },
}

/// One registered recipe revision with its bound immutable identity.
#[derive(Clone, Debug)]
pub struct RegisteredDoctorRecipe {
    /// Exact registered recipe contract.
    pub recipe: RepairRecipe,
    /// Immutable identity bound at registration.
    pub identity: RepairRecipeIdentity,
}

/// Kernel-owned immutable registry of admitted repair recipes.
///
/// Built once at composition from the Kernel or Governor supplied manifest
/// revision and recipe set, and never mutated afterwards: there are no
/// `&mut self` methods. Resolution is by exact `(recipe_id, revision)`; a
/// presented recipe must digest-match the registered revision, so Doctor
/// never receives caller-supplied executable authority.
#[derive(Clone, Debug)]
pub struct DoctorRecipeRegistry {
    manifest: RepairRecipeManifest,
    manifest_digest: String,
    recipes: Vec<RegisteredDoctorRecipe>,
}

impl DoctorRecipeRegistry {
    /// Registers one immutable manifest revision with its recipe set.
    ///
    /// Validates the manifest, every recipe, and every bound identity, and
    /// rejects empty sets and duplicate `(recipe_id, revision)` pairs.
    pub fn register(
        manifest: RepairRecipeManifest,
        recipes: Vec<RepairRecipe>,
    ) -> Result<Self, DoctorRegistryError> {
        manifest.validate()?;
        if recipes.is_empty() {
            return Err(DoctorRegistryError::EmptyRegistry);
        }
        let manifest_digest = manifest.digest();
        let mut registered = Vec::with_capacity(recipes.len());
        for recipe in recipes {
            let identity = RepairRecipeIdentity::bind(&recipe)?;
            if registered.iter().any(|entry: &RegisteredDoctorRecipe| {
                entry.recipe.recipe_id == recipe.recipe_id
                    && entry.recipe.revision == recipe.revision
            }) {
                return Err(DoctorRegistryError::DuplicateRecipe {
                    recipe_id: recipe.recipe_id.clone(),
                    revision: recipe.revision,
                });
            }
            registered.push(RegisteredDoctorRecipe { recipe, identity });
        }
        Ok(Self {
            manifest,
            manifest_digest,
            recipes: registered,
        })
    }

    /// Resolves one exact registered recipe revision.
    pub fn resolve_recipe(
        &self,
        recipe_id: &str,
        revision: u64,
    ) -> Option<(&RepairRecipe, &RepairRecipeIdentity)> {
        self.recipes
            .iter()
            .find(|entry| entry.recipe.recipe_id == recipe_id && entry.recipe.revision == revision)
            .map(|entry| (&entry.recipe, &entry.identity))
    }

    /// Returns the admitted manifest revision.
    pub fn manifest(&self) -> &RepairRecipeManifest {
        &self.manifest
    }

    /// Returns the digest of the admitted manifest revision.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Returns the number of registered recipe revisions.
    pub fn recipe_count(&self) -> usize {
        self.recipes.len()
    }
}

/// Explicit Kernel admission inputs for one Doctor repair attempt.
///
/// The binary-slice dispatch arm builds this from live Kernel state; the
/// gate itself takes scalars only, so admission never depends on ambient
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorAdmissionContext {
    /// Live Kernel service state; admission requires `Ready`.
    pub service_state: KernelServiceState,
    /// Live authority epoch; the presented fence must match it exactly.
    pub authority_epoch: u64,
    /// Live resource generation; the presented fence must match it exactly.
    pub generation: u64,
}

impl DoctorAdmissionContext {
    /// Builds the admission context, failing closed on a zero epoch or
    /// generation.
    pub fn new(
        service_state: KernelServiceState,
        authority_epoch: u64,
        generation: u64,
    ) -> Result<Self, KernelServiceError> {
        if authority_epoch == 0 || generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.context",
                reason: "authority epoch and generation must be non-zero",
            });
        }
        Ok(Self {
            service_state,
            authority_epoch,
            generation,
        })
    }
}

/// Wire request presenting one Doctor repair attempt for Kernel admission.
///
/// The closed Slice 1 request travels as an opaque envelope: Kernel parses
/// and validates it, resolves the recipe from its own immutable registry,
/// and never accepts executable authority from the caller. `request_digest`
/// binds the exact envelope bytes, so a byte-different retry under one
/// attempt identity is an identity conflict, not a silent substitution.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepairAttemptRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Attempt identity seed bound into the Slice 1 attempt identity.
    pub attempt_id: String,
    /// Effect sequence distinguishing several effects of one attempt.
    pub effect_seq: u32,
    /// Canonical JSON bytes of the presented Slice 1 closed request.
    pub closed_request_json: String,
    /// Opaque digest of the target resource envelope; compared byte-wise,
    /// never interpreted.
    pub target_resource_digest: String,
    /// Canonical digest over this request envelope.
    pub request_digest: String,
}

impl DoctorRepairAttemptRequest {
    /// Current repair-attempt wire contract version.
    pub const CONTRACT_VERSION: u16 = DOCTOR_REPAIR_WIRE_VERSION;

    /// Computes the canonical digest over the presenting envelope bytes.
    pub fn canonical_request_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            attempt_id: &'a str,
            effect_seq: u32,
            closed_request_json: &'a str,
            target_resource_digest: &'a str,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            attempt_id: &self.attempt_id,
            effect_seq: self.effect_seq,
            closed_request_json: &self.closed_request_json,
            target_resource_digest: &self.target_resource_digest,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "doctor_repair.request_digest",
                reason: "cannot canonicalize request",
            })
    }

    /// Returns this request with its canonical request digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.request_digest = self.canonical_request_digest()?;
        Ok(self)
    }

    /// Validates that the request digest equals the canonical digest.
    pub fn validate_canonical_digest(&self) -> Result<(), KernelServiceError> {
        if self.request_digest != self.canonical_request_digest()? {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "doctor_repair.request_digest",
            });
        }
        Ok(())
    }

    /// Validates the closed wire shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != DOCTOR_REPAIR_WIRE_ID || self.wire_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.wire",
                reason: "unsupported doctor repair wire",
            });
        }
        validate_wire_text(&self.attempt_id, "doctor_repair.attempt_id")?;
        if self.closed_request_json.is_empty()
            || self.closed_request_json.len() > DOCTOR_MAX_ENVELOPE_BYTES
        {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.closed_request_json",
                reason: "closed request envelope is missing or exceeds its bound",
            });
        }
        validate_wire_digest(
            &self.target_resource_digest,
            "doctor_repair.target_resource_digest",
        )?;
        validate_wire_digest(&self.request_digest, "doctor_repair.request_digest")?;
        Ok(())
    }
}

/// Kernel-issued authority projection for one admitted Doctor attempt.
///
/// This is the exact `RecoveryLease` and attempt admission: it carries the
/// minted lease (identity, Kernel owner, nanosecond expiry, allowed named
/// effects), the Slice 1 attempt and effect identity digests, the bound
/// recipe and manifest digests, budget, deadline, approval presence (never
/// the approval value), and cancellation. The admission digest is canonical
/// over every field, so rebuilding with the durable admission time
/// reproduces the exact same admission on replay.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepairAdmission {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Admitted attempt identity seed.
    pub attempt_id: String,
    /// Slice 1 attempt identity digest.
    pub attempt_digest: String,
    /// Slice 1 effect identity digest. `None` for cancelled attempts, which
    /// bind no effect.
    pub effect_digest: Option<String>,
    /// Digest of the exact registered recipe revision.
    pub recipe_digest: String,
    /// Digest of the exact admitted manifest revision.
    pub manifest_digest: String,
    /// Admitted registered named-effect operation.
    pub operation_id: String,
    /// Minted recovery-lease identity, derived from the attempt digest.
    pub lease_id: String,
    /// Recovery-lease owner: always Kernel recovery authority.
    pub lease_owner: String,
    /// Recovery-lease expiry in Unix nanoseconds.
    pub lease_expires_unix_nanos: u64,
    /// Named effects the lease permits: exactly the admitted operation, or
    /// empty for cancelled attempts.
    pub allowed_effects: BTreeSet<String>,
    /// Budget units bound to this attempt.
    pub budget_units: u64,
    /// Attempt deadline in Unix nanoseconds.
    pub deadline_unix_nanos: u64,
    /// Whether a guarded approval was presented and bound (presence only).
    pub approval_present: bool,
    /// Whether the attempt was admitted cancelled; cancelled attempts never
    /// stage an effect intent.
    pub cancelled: bool,
    /// Admission time in Unix nanoseconds.
    pub admitted_at_unix_nanos: u64,
    /// Canonical digest over this admission envelope.
    pub admission_digest: String,
}

impl DoctorRepairAdmission {
    /// Current repair-attempt wire contract version.
    pub const CONTRACT_VERSION: u16 = DOCTOR_REPAIR_WIRE_VERSION;

    /// Computes the canonical admission digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            attempt_id: &'a str,
            attempt_digest: &'a str,
            effect_digest: Option<&'a str>,
            recipe_digest: &'a str,
            manifest_digest: &'a str,
            operation_id: &'a str,
            lease_id: &'a str,
            lease_owner: &'a str,
            lease_expires_unix_nanos: u64,
            allowed_effects: &'a BTreeSet<String>,
            budget_units: u64,
            deadline_unix_nanos: u64,
            approval_present: bool,
            cancelled: bool,
            admitted_at_unix_nanos: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            attempt_id: &self.attempt_id,
            attempt_digest: &self.attempt_digest,
            effect_digest: self.effect_digest.as_deref(),
            recipe_digest: &self.recipe_digest,
            manifest_digest: &self.manifest_digest,
            operation_id: &self.operation_id,
            lease_id: &self.lease_id,
            lease_owner: &self.lease_owner,
            lease_expires_unix_nanos: self.lease_expires_unix_nanos,
            allowed_effects: &self.allowed_effects,
            budget_units: self.budget_units,
            deadline_unix_nanos: self.deadline_unix_nanos,
            approval_present: self.approval_present,
            cancelled: self.cancelled,
            admitted_at_unix_nanos: self.admitted_at_unix_nanos,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "doctor_repair.admission_digest",
                reason: "cannot canonicalize admission",
            })
    }

    /// Returns this admission with its canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.admission_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the admission shape, its canonical digest, and the one
    /// exact operation rule: a live admission permits exactly the admitted
    /// operation, while a cancelled admission permits nothing and binds no
    /// effect.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != DOCTOR_REPAIR_WIRE_ID || self.wire_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.wire",
                reason: "unsupported doctor repair wire",
            });
        }
        for (text, field) in [
            (&self.attempt_id, "doctor_repair.attempt_id"),
            (&self.operation_id, "doctor_repair.operation_id"),
            (&self.lease_id, "doctor_repair.lease_id"),
            (&self.lease_owner, "doctor_repair.lease_owner"),
        ] {
            validate_wire_text(text, field)?;
        }
        for (digest, field) in [
            (&self.attempt_digest, "doctor_repair.attempt_digest"),
            (&self.recipe_digest, "doctor_repair.recipe_digest"),
            (&self.manifest_digest, "doctor_repair.manifest_digest"),
            (&self.admission_digest, "doctor_repair.admission_digest"),
        ] {
            validate_wire_digest(digest, field)?;
        }
        if let Some(effect) = &self.effect_digest {
            validate_wire_digest(effect, "doctor_repair.effect_digest")?;
        }
        for effect in &self.allowed_effects {
            validate_wire_text(effect, "doctor_repair.allowed_effects")?;
        }
        if self.budget_units == 0
            || self.deadline_unix_nanos == 0
            || self.lease_expires_unix_nanos == 0
            || self.admitted_at_unix_nanos == 0
        {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.bounded_fields",
                reason: "budget, deadline, lease expiry, and admission time must be non-zero",
            });
        }
        if self.cancelled {
            if !self.allowed_effects.is_empty() || self.effect_digest.is_some() {
                return Err(KernelServiceError::InvalidField {
                    field: "doctor_repair.cancelled",
                    reason: "a cancelled admission permits no effect and binds none",
                });
            }
        } else if self.allowed_effects.len() != 1
            || !self.allowed_effects.contains(self.operation_id.as_str())
            || self.effect_digest.is_none()
        {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.allowed_effects",
                reason: "a live admission permits exactly the admitted operation",
            });
        }
        if self.compute_digest()? != self.admission_digest {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.admission_digest",
                reason: "admission digest mismatch",
            });
        }
        Ok(())
    }
}

/// Typed reason a Doctor repair attempt was not admitted.
///
/// Every rejection names its cause; a refused attempt takes no effect and
/// consumes no budget.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorRepairRejectionReason {
    /// Unknown repair wire identity or version.
    UnknownWireVersion,
    /// A wire or envelope field failed bounded shape validation.
    InvalidRequestField,
    /// Presented authority epoch disagrees with the live epoch.
    StaleEpoch,
    /// Presented fence is not canonically valid or disagrees with the live
    /// fence.
    StaleFence,
    /// Presented generation disagrees with the live generation.
    StaleGeneration,
    /// Attempt deadline already passed at admission time.
    ExpiredDeadline,
    /// Recovery lease already expired at admission time.
    ExpiredLease,
    /// No registered recipe revision matches the presented recipe.
    RecipeNotRegistered,
    /// Presented recipe does not digest-match the registered revision.
    RecipeDigestMismatch,
    /// Presented recipe does not cover the diagnostic brief.
    RecipeNotApplicable,
    /// The request carries zero or several operations; exactly one
    /// registered operation is admitted per attempt.
    OperationNotAdmitted,
    /// The operation is outside the recipe allow-list or the live lease.
    EffectNotAuthorized,
    /// Guarded repair arrived without an approval.
    ApprovalRequired,
    /// The durable admission count reached the recipe budget.
    BudgetExhausted,
    /// A new attempt arrived inside the recipe cooldown.
    CooldownActive,
    /// The recovery scope is quarantined.
    Quarantined,
}

/// Typed rejection for one refused Doctor repair attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepairRejection {
    /// Refused attempt identity seed, as presented.
    pub attempt_ref: String,
    /// Typed refusal cause.
    pub reason: DoctorRepairRejectionReason,
    /// Bounded detail naming the failing dimension.
    pub detail: String,
    /// Earliest Unix-nanosecond retry time; set only for cooldown.
    pub retry_after_unix_nanos: Option<u64>,
    /// Quarantine cause; set only for quarantine refusals.
    pub quarantine_cause: Option<DoctorQuarantineCause>,
    /// Rejection time in Unix nanoseconds.
    pub rejected_at_unix_nanos: u64,
}

impl DoctorRepairRejection {
    /// Validates the rejection shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.attempt_ref, "doctor_repair.attempt_ref")?;
        validate_wire_text(&self.detail, "doctor_repair.detail")?;
        match (
            &self.reason,
            self.retry_after_unix_nanos,
            &self.quarantine_cause,
        ) {
            (DoctorRepairRejectionReason::CooldownActive, Some(retry_after), None) => {
                if retry_after == 0 {
                    return Err(KernelServiceError::InvalidField {
                        field: "doctor_repair.retry_after_unix_nanos",
                        reason: "retry time must be greater than zero",
                    });
                }
            }
            (DoctorRepairRejectionReason::Quarantined, None, Some(_)) | (_, None, None) => {}
            _ => {
                return Err(KernelServiceError::InvalidField {
                    field: "doctor_repair.rejection",
                    reason: "retry time only for cooldown, quarantine cause only for quarantine",
                });
            }
        }
        if self.rejected_at_unix_nanos == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.rejected_at_unix_nanos",
                reason: "rejection time must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Changed-terms conflict under one Doctor attempt or effect identity.
///
/// Mirrors the native-worker claim conflict report: the same identity was
/// presented with changed request, recipe, or effect terms. The conflicting
/// presentation takes no effect and never overwrites the durable binding.
/// `expected_digest` and `observed_digest` are the durable and presented
/// Slice 1 binding digests; they may agree while `changed_fields` is
/// non-empty, because the durable binding covers more dimensions (manifest
/// revision, evidence, principal, resource, lease, cooldown, cancellation,
/// exact request bytes) than the Slice 1 identity alone.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorRepairConflict {
    /// Attempt identity both bindings were presented under.
    pub attempt_id: String,
    /// Durable binding digest.
    pub expected_digest: String,
    /// Presented binding digest.
    pub observed_digest: String,
    /// Bound dimensions that differ, in canonical field order.
    pub changed_fields: Vec<String>,
}

impl DoctorRepairConflict {
    /// Validates the conflict shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.attempt_id, "doctor_repair.attempt_id")?;
        validate_wire_digest(&self.expected_digest, "doctor_repair.expected_digest")?;
        validate_wire_digest(&self.observed_digest, "doctor_repair.observed_digest")?;
        if self.changed_fields.is_empty() || self.changed_fields.len() > DOCTOR_CONFLICT_MAX_FIELDS
        {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.changed_fields",
                reason: "must name at least one changed dimension within the bound",
            });
        }
        for field in &self.changed_fields {
            validate_wire_text(field, "doctor_repair.changed_fields")?;
        }
        Ok(())
    }
}

/// Kernel answer to one Doctor repair-attempt request.
///
/// Exactly one variant is returned: an admission, a typed rejection, or a
/// changed-terms conflict. A conflicting presentation never produces a
/// second live admission under the same identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum DoctorRepairResponse {
    /// The attempt was admitted; the admission is the authority projection.
    Admitted(Box<DoctorRepairAdmission>),
    /// The attempt was refused for the named typed reason.
    Rejected(DoctorRepairRejection),
    /// The attempt identity conflicts with the durable bound terms.
    Conflict(DoctorRepairConflict),
}

impl DoctorRepairResponse {
    /// Validates the enclosed admission, rejection, or conflict.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::Admitted(admission) => admission.validate(),
            Self::Rejected(rejection) => rejection.validate(),
            Self::Conflict(conflict) => conflict.validate(),
        }
    }
}

/// Refusal channel for Doctor validation helpers.
///
/// Validation helpers have no access to the response-building closure, so
/// they return the typed reason and detail; the gate maps the pair to a
/// `Rejected` response. Nothing is weakened: every refusal path is preserved.
type DoctorRefusal = (DoctorRepairRejectionReason, &'static str);

/// Validated and bound terms for one Doctor repair attempt.
///
/// Owns the parsed envelope; borrows the resolved registry entries. Clock
/// bounds are resolved to nanoseconds; identity binding and durable staging
/// happen downstream.
struct ValidatedDoctorTerms<'a> {
    envelope: ClosedRepairRequest,
    recipe: &'a RepairRecipe,
    registered_identity: &'a RepairRecipeIdentity,
    manifest_digest: &'a str,
    lease_expiry_nanos: u64,
    deadline_nanos: u64,
    cooldown_nanos: u64,
}

/// Returns the exactly one admitted operation of validated terms.
///
/// Safe by construction: [`validate_doctor_terms`] enforces the one-operation
/// rule before any terms value exists.
fn terms_operation<'t>(terms: &'t ValidatedDoctorTerms<'_>) -> &'t RepairOperationRef {
    &terms.envelope.operations[0]
}

/// How a Doctor staging step halts: either a typed response to return, or a
/// mechanical failure to surface.
enum DoctorGateHalt {
    /// Return this typed response (`Rejected` or `Conflict`).
    Respond(DoctorRepairResponse),
    /// Surface this mechanical failure.
    Mechanical(KernelServiceError),
}

/// Bound identities, digests, and staged row for one Doctor attempt.
struct BoundDoctorAttempt {
    staged: DoctorAttemptRecord,
    attempt_digest: String,
    effect_digest: String,
    intent_digest: String,
}

/// Validates the wire envelope and binds the presented closed request.
fn parse_doctor_wire(
    request: &DoctorRepairAttemptRequest,
) -> Result<ClosedRepairRequest, DoctorRefusal> {
    if !route_doctor_repair(&request.wire_id, request.wire_version) {
        return Err((
            DoctorRepairRejectionReason::UnknownWireVersion,
            "doctor_repair.wire",
        ));
    }
    if let Err(error) = request.validate() {
        let reason = match error {
            KernelServiceError::InvalidField {
                field: "doctor_repair.wire",
                ..
            } => DoctorRepairRejectionReason::UnknownWireVersion,
            _ => DoctorRepairRejectionReason::InvalidRequestField,
        };
        return Err((reason, "doctor_repair.wire"));
    }
    if request.validate_canonical_digest().is_err() {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.request_digest",
        ));
    }
    serde_json::from_str(&request.closed_request_json).map_err(|_| {
        (
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.closed_request",
        )
    })
}

/// Resolves the presented recipe against the immutable registry.
///
/// The presented recipe must digest-match the registered revision: Doctor
/// never receives caller-supplied executable authority.
fn resolve_doctor_recipe<'a>(
    registry: &'a DoctorRecipeRegistry,
    envelope: &ClosedRepairRequest,
) -> Result<(&'a RepairRecipe, &'a RepairRecipeIdentity), DoctorRefusal> {
    let Some(resolved) =
        registry.resolve_recipe(&envelope.recipe.recipe_id, envelope.recipe.revision)
    else {
        return Err((
            DoctorRepairRejectionReason::RecipeNotRegistered,
            "doctor_repair.recipe",
        ));
    };
    let Ok(presented) = RepairRecipeIdentity::bind(&envelope.recipe) else {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.recipe",
        ));
    };
    if presented != *resolved.1 || presented != envelope.recipe_identity {
        return Err((
            DoctorRepairRejectionReason::RecipeDigestMismatch,
            "doctor_repair.recipe_digest",
        ));
    }
    if !resolved.0.applies_to(&envelope.brief) {
        return Err((
            DoctorRepairRejectionReason::RecipeNotApplicable,
            "doctor_repair.brief",
        ));
    }
    Ok(resolved)
}

/// Checks the exactly one admitted operation and its transition class.
///
/// Slice 2 admits effect-carrying attempts only: diagnose-only requests
/// carry no operation and therefore bind no effect identity; they need no
/// Kernel effect admission and are refused here instead of admitted
/// half-bound.
fn check_doctor_operation<'e>(
    registry: &DoctorRecipeRegistry,
    recipe: &RepairRecipe,
    envelope: &'e ClosedRepairRequest,
) -> Result<&'e RepairOperationRef, DoctorRefusal> {
    if envelope.operations.len() != 1 {
        return Err((
            DoctorRepairRejectionReason::OperationNotAdmitted,
            "doctor_repair.operations",
        ));
    }
    let operation = &envelope.operations[0];
    if registry.manifest().check_admitted(operation).is_err() {
        return Err((
            DoctorRepairRejectionReason::OperationNotAdmitted,
            "doctor_repair.operation_manifest",
        ));
    }
    if !recipe.allowed_effects.contains(operation.operation_id()) {
        return Err((
            DoctorRepairRejectionReason::EffectNotAuthorized,
            "doctor_repair.allowed_effects",
        ));
    }
    if !envelope.lease.permits(operation.operation_id()) {
        return Err((
            DoctorRepairRejectionReason::EffectNotAuthorized,
            "doctor_repair.lease",
        ));
    }
    if matches!(recipe.repair_class, RepairClass::Guarded)
        && envelope.approval.as_deref().is_none_or(str::is_empty)
    {
        return Err((
            DoctorRepairRejectionReason::ApprovalRequired,
            "doctor_repair.approval",
        ));
    }
    Ok(operation)
}

/// Checks the presented fence against the live epoch and generation.
fn check_doctor_fence(
    context: &DoctorAdmissionContext,
    envelope: &ClosedRepairRequest,
) -> Result<(), DoctorRefusal> {
    if canonical_fence(&envelope.fence).is_err() {
        return Err((
            DoctorRepairRejectionReason::StaleFence,
            "doctor_repair.fence",
        ));
    }
    if envelope.fence.authority_epoch != context.authority_epoch {
        return Err((
            DoctorRepairRejectionReason::StaleEpoch,
            "doctor_repair.authority_epoch",
        ));
    }
    if envelope.fence.generation != context.generation {
        return Err((
            DoctorRepairRejectionReason::StaleGeneration,
            "doctor_repair.generation",
        ));
    }
    Ok(())
}

/// Resolves lease, deadline, budget, and cooldown bounds to nanoseconds.
///
/// The budget ceiling reads the presented recipe, whose digest equality
/// with the registered revision was already proven: the Slice 1 identity
/// binds `attempt_budget`, so equal digests mean equal budgets.
fn resolve_doctor_clocks(
    envelope: &ClosedRepairRequest,
    now_unix_nanos: u64,
) -> Result<(u64, u64, u64), DoctorRefusal> {
    let Ok(lease_expiry_nanos) = u64::try_from(envelope.lease.expires_at.unix_timestamp_nanos())
    else {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.lease",
        ));
    };
    if lease_expiry_nanos <= now_unix_nanos {
        return Err((
            DoctorRepairRejectionReason::ExpiredLease,
            "doctor_repair.lease",
        ));
    }
    let Ok(deadline_nanos) = u64::try_from(envelope.deadline.unix_timestamp_nanos()) else {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.deadline",
        ));
    };
    if deadline_nanos <= now_unix_nanos {
        return Err((
            DoctorRepairRejectionReason::ExpiredDeadline,
            "doctor_repair.deadline",
        ));
    }
    if envelope.budget_units == 0
        || envelope.budget_units > u64::from(envelope.recipe.attempt_budget)
    {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.budget_units",
        ));
    }
    let Ok(cooldown_nanos) = u64::try_from(envelope.recipe.cooldown.whole_nanoseconds()) else {
        return Err((
            DoctorRepairRejectionReason::InvalidRequestField,
            "doctor_repair.cooldown",
        ));
    };
    Ok((lease_expiry_nanos, deadline_nanos, cooldown_nanos))
}

/// Validates one wire request down to bound admission terms.
fn validate_doctor_terms<'a>(
    registry: &'a DoctorRecipeRegistry,
    context: &DoctorAdmissionContext,
    request: &DoctorRepairAttemptRequest,
    now_unix_nanos: u64,
) -> Result<ValidatedDoctorTerms<'a>, DoctorRefusal> {
    let envelope = parse_doctor_wire(request)?;
    let (recipe, registered_identity) = resolve_doctor_recipe(registry, &envelope)?;
    check_doctor_operation(registry, recipe, &envelope)?;
    check_doctor_fence(context, &envelope)?;
    let (lease_expiry_nanos, deadline_nanos, cooldown_nanos) =
        resolve_doctor_clocks(&envelope, now_unix_nanos)?;
    Ok(ValidatedDoctorTerms {
        envelope,
        recipe,
        registered_identity,
        manifest_digest: registry.manifest_digest(),
        lease_expiry_nanos,
        deadline_nanos,
        cooldown_nanos,
    })
}

/// Binds the Slice 1 attempt and effect identities for validated terms.
fn bind_doctor_identities(
    request: &DoctorRepairAttemptRequest,
    terms: &ValidatedDoctorTerms<'_>,
) -> Result<(String, String), KernelServiceError> {
    // The deadline moves out of the deserialized envelope by value, so no
    // `time` type is ever named here; the epoch stays on the echo path
    // (`None`) while the gate enforces exact epoch agreement in
    // `check_doctor_fence`.
    let operation = terms_operation(terms);
    let attempt = eliot_doctor_core::RepairAttemptIdentity::bind(&AttemptIdentityBinding {
        attempt_id: &request.attempt_id,
        brief: &terms.envelope.brief,
        recipe: terms.registered_identity,
        operation,
        fence: &terms.envelope.fence,
        epoch: None,
        approval: terms.envelope.approval.as_deref(),
        budget_units: terms.envelope.budget_units,
        deadline: terms.envelope.deadline,
    })
    .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    let effect =
        eliot_doctor_core::RepairEffectIdentity::bind(&attempt, operation, request.effect_seq)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    Ok((attempt.digest().to_owned(), effect.digest().to_owned()))
}

/// Computes the opaque evidence and intent digests for validated terms.
fn doctor_envelope_digests(
    envelope: &ClosedRepairRequest,
) -> Result<(String, String), KernelServiceError> {
    let evidence = serde_json::to_value(&envelope.brief.evidence)
        .ok()
        .and_then(|value| canonical_json_bytes(&value).ok())
        .ok_or_else(|| {
            KernelServiceError::Platform(
                "doctor evidence envelope cannot be canonicalized".to_owned(),
            )
        })?;
    let intent = serde_json::to_value(envelope)
        .ok()
        .and_then(|value| canonical_json_bytes(&value).ok())
        .ok_or_else(|| {
            KernelServiceError::Platform(
                "doctor intent envelope cannot be canonicalized".to_owned(),
            )
        })?;
    Ok((sha256_hex(&evidence), sha256_hex(&intent)))
}

/// Builds the staged attempt row for bound identities.
fn build_staged_doctor_attempt(
    request: &DoctorRepairAttemptRequest,
    terms: &ValidatedDoctorTerms<'_>,
    session_principal: &str,
    attempt_digest: &str,
    evidence_digest: &str,
) -> Result<DoctorAttemptRecord, KernelServiceError> {
    let operation = terms_operation(terms);
    let staged = DoctorAttemptRecord {
        contract_version: eliot_ors::DOCTOR_RECORD_CONTRACT_VERSION,
        attempt_digest: OperationIdentity::new(attempt_digest)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        recipe_digest: terms.registered_identity.digest().to_owned(),
        manifest_digest: terms.manifest_digest.to_owned(),
        operation_id: OpaqueLabel::new(operation.operation_id())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        operation_definition_digest: operation.definition_digest().to_owned(),
        problem_ref: OpaqueLabel::new(terms.envelope.brief.problem_id.as_str())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        component_ref: OpaqueLabel::new(terms.envelope.brief.component.as_str())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        evidence_digest: evidence_digest.to_owned(),
        principal_ref: OpaqueLabel::new(session_principal)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        fence_digest: terms.envelope.fence.digest.clone(),
        authority_epoch: terms.envelope.fence.authority_epoch,
        generation: terms.envelope.fence.generation,
        epoch_lineage: None,
        target_resource_digest: request.target_resource_digest.clone(),
        approval_digest: terms
            .envelope
            .approval
            .as_deref()
            .map(|approval| sha256_hex(approval.as_bytes())),
        budget_units: terms.envelope.budget_units,
        deadline_unix_nanos: terms.deadline_nanos,
        lease_expires_unix_nanos: terms.lease_expiry_nanos,
        cooldown_nanos: terms.cooldown_nanos,
        cancelled: terms.envelope.cancellation,
        binding_digest: attempt_digest.to_owned(),
        request_digest: request.request_digest.clone(),
        state: DoctorAttemptState::Requested,
        admission_digest: None,
        admitted_at_unix_nanos: None,
        commit_order: 0,
    };
    staged
        .validate()
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    Ok(staged)
}

/// Binds identities for validated terms and stages the attempt row.
///
/// Returns the bound row alongside the durable row the staging resolved to:
/// a fresh intent, or the exact replay of a durably staged one.
fn bind_and_stage_doctor_attempt<L: DoctorRecoveryLedger>(
    ledger: &L,
    request: &DoctorRepairAttemptRequest,
    terms: &ValidatedDoctorTerms<'_>,
    session_principal: &str,
) -> Result<(BoundDoctorAttempt, DoctorAttemptRecord), DoctorGateHalt> {
    let (attempt_digest, effect_digest) =
        bind_doctor_identities(request, terms).map_err(DoctorGateHalt::Mechanical)?;
    let (evidence_digest, intent_digest) =
        doctor_envelope_digests(&terms.envelope).map_err(DoctorGateHalt::Mechanical)?;
    let staged = build_staged_doctor_attempt(
        request,
        terms,
        session_principal,
        &attempt_digest,
        &evidence_digest,
    )
    .map_err(DoctorGateHalt::Mechanical)?;
    let durable = match ledger.stage_doctor_attempt(&staged) {
        Ok(outcome) => {
            if outcome.record().same_binding(&staged) {
                outcome.record().clone()
            } else {
                return Err(DoctorGateHalt::Respond(attempt_conflict(
                    request,
                    outcome.record(),
                    &staged,
                )));
            }
        }
        Err(DoctorLedgerError::AttemptIdentityConflict { .. }) => {
            let durable = ledger
                .load_doctor_attempt(&staged.attempt_digest)
                .map_err(|error| DoctorGateHalt::Mechanical(doctor_ledger_error(&error)))?
                .ok_or_else(|| {
                    DoctorGateHalt::Mechanical(KernelServiceError::Platform(
                        "conflicting doctor attempt disappeared before reconciliation".to_owned(),
                    ))
                })?;
            if durable.same_binding(&staged) {
                durable
            } else {
                return Err(DoctorGateHalt::Respond(attempt_conflict(
                    request, &durable, &staged,
                )));
            }
        }
        Err(error) => {
            return Err(DoctorGateHalt::Mechanical(doctor_ledger_error(&error)));
        }
    };
    Ok((
        BoundDoctorAttempt {
            staged,
            attempt_digest,
            effect_digest,
            intent_digest,
        },
        durable,
    ))
}

/// Admits one Doctor repair attempt against the durable recovery ledger.
///
/// Persist-before-ack: the attempt intent row is staged before any
/// admission is issued, and the effect intent is staged before the
/// admission is returned. An exact replay under the same attempt identity
/// rebuilds the original admission instead of a second admission and never
/// downgrades durable state; changed request, recipe, or effect terms under
/// one identity return `Conflict`; a lost admission race reloads the
/// winner's admission. Budget, cooldown, and quarantine are evaluated from
/// the durable ledger on every fresh admission, so enforcement is identical
/// across restarts. Only mechanical failures (fenced generation, closed
/// admission, ledger storage) surface as `Err`; every typed refusal is an
/// `Ok` response value.
pub fn admit_doctor_repair<L: DoctorRecoveryLedger>(
    ledger: &L,
    registry: &DoctorRecipeRegistry,
    context: &DoctorAdmissionContext,
    session_principal: &str,
    request: &DoctorRepairAttemptRequest,
    now_unix_nanos: u64,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    if context.service_state != KernelServiceState::Ready {
        return Err(KernelServiceError::AdmissionClosed(context.service_state));
    }
    if now_unix_nanos == 0 {
        return Err(KernelServiceError::InvalidField {
            field: "doctor_repair.now",
            reason: "admission time must be non-zero",
        });
    }
    validate_text(session_principal, "doctor_repair.principal")?;
    let rejected = |reason: DoctorRepairRejectionReason, detail: &'static str| {
        DoctorRepairResponse::Rejected(DoctorRepairRejection {
            attempt_ref: request.attempt_id.clone(),
            reason,
            detail: detail.to_owned(),
            retry_after_unix_nanos: None,
            quarantine_cause: None,
            rejected_at_unix_nanos: now_unix_nanos,
        })
    };
    let terms = match validate_doctor_terms(registry, context, request, now_unix_nanos) {
        Ok(terms) => terms,
        Err((reason, detail)) => return Ok(rejected(reason, detail)),
    };
    let operation = terms_operation(&terms);
    let (bound, durable) =
        match bind_and_stage_doctor_attempt(ledger, request, &terms, session_principal) {
            Ok(staged) => staged,
            Err(DoctorGateHalt::Respond(response)) => return Ok(response),
            Err(DoctorGateHalt::Mechanical(error)) => return Err(error),
        };
    if !durable.same_binding(&bound.staged) {
        return Ok(attempt_conflict(request, &durable, &bound.staged));
    }
    if durable.state == DoctorAttemptState::Requested {
        admit_fresh_doctor_attempt(
            ledger,
            &FreshDoctorAdmission {
                request,
                envelope: &terms.envelope,
                operation,
                recipe_digest: terms.registered_identity.digest(),
                manifest_digest: terms.manifest_digest,
                attempt_digest: &bound.attempt_digest,
                effect_digest: &bound.effect_digest,
                intent_digest: &bound.intent_digest,
                staged: &bound.staged,
                attempt_budget: terms.recipe.attempt_budget,
                cooldown_nanos: terms.cooldown_nanos,
                lease_expiry_nanos: terms.lease_expiry_nanos,
                deadline_nanos: terms.deadline_nanos,
                now_unix_nanos,
            },
        )
    } else {
        rebuild_doctor_admission(
            ledger,
            &RebuiltDoctorAdmission {
                request,
                envelope: &terms.envelope,
                operation,
                recipe_digest: terms.registered_identity.digest(),
                manifest_digest: terms.manifest_digest,
                attempt_digest: &bound.attempt_digest,
                effect_digest: &bound.effect_digest,
                intent_digest: &bound.intent_digest,
                durable: &durable,
                lease_expiry_nanos: terms.lease_expiry_nanos,
                deadline_nanos: terms.deadline_nanos,
                now_unix_nanos,
            },
        )
    }
}

/// Bound inputs for one fresh Doctor admission.
///
/// Groups the gate outputs so the fresh-admit and rebuild paths stay under
/// the argument-count lint without weakening any check.
struct FreshDoctorAdmission<'a> {
    request: &'a DoctorRepairAttemptRequest,
    envelope: &'a ClosedRepairRequest,
    operation: &'a RepairOperationRef,
    recipe_digest: &'a str,
    manifest_digest: &'a str,
    attempt_digest: &'a str,
    effect_digest: &'a str,
    intent_digest: &'a str,
    staged: &'a DoctorAttemptRecord,
    attempt_budget: u32,
    cooldown_nanos: u64,
    lease_expiry_nanos: u64,
    deadline_nanos: u64,
    now_unix_nanos: u64,
}

/// Bound inputs for rebuilding one durable Doctor admission.
struct RebuiltDoctorAdmission<'a> {
    request: &'a DoctorRepairAttemptRequest,
    envelope: &'a ClosedRepairRequest,
    operation: &'a RepairOperationRef,
    recipe_digest: &'a str,
    manifest_digest: &'a str,
    attempt_digest: &'a str,
    effect_digest: &'a str,
    intent_digest: &'a str,
    durable: &'a DoctorAttemptRecord,
    lease_expiry_nanos: u64,
    deadline_nanos: u64,
    now_unix_nanos: u64,
}

/// Changed-terms conflict report for one attempt identity.
fn attempt_conflict(
    request: &DoctorRepairAttemptRequest,
    durable: &DoctorAttemptRecord,
    staged: &DoctorAttemptRecord,
) -> DoctorRepairResponse {
    DoctorRepairResponse::Conflict(DoctorRepairConflict {
        attempt_id: request.attempt_id.clone(),
        expected_digest: durable.binding_digest.clone(),
        observed_digest: staged.binding_digest.clone(),
        changed_fields: doctor_attempt_changed_fields(durable, staged),
    })
}

/// Names the bound attempt dimensions that differ, in canonical field order.
fn doctor_attempt_changed_fields(
    durable: &DoctorAttemptRecord,
    staged: &DoctorAttemptRecord,
) -> Vec<String> {
    let mut fields = Vec::new();
    if durable.recipe_digest != staged.recipe_digest {
        fields.push("recipe_digest".to_owned());
    }
    if durable.manifest_digest != staged.manifest_digest {
        fields.push("manifest_digest".to_owned());
    }
    if durable.operation_id != staged.operation_id {
        fields.push("operation_id".to_owned());
    }
    if durable.operation_definition_digest != staged.operation_definition_digest {
        fields.push("operation_definition_digest".to_owned());
    }
    if durable.problem_ref != staged.problem_ref {
        fields.push("problem_ref".to_owned());
    }
    if durable.component_ref != staged.component_ref {
        fields.push("component_ref".to_owned());
    }
    if durable.evidence_digest != staged.evidence_digest {
        fields.push("evidence_digest".to_owned());
    }
    if durable.principal_ref != staged.principal_ref {
        fields.push("principal_ref".to_owned());
    }
    if durable.fence_digest != staged.fence_digest {
        fields.push("fence_digest".to_owned());
    }
    if durable.authority_epoch != staged.authority_epoch {
        fields.push("authority_epoch".to_owned());
    }
    if durable.generation != staged.generation {
        fields.push("generation".to_owned());
    }
    if durable.epoch_lineage != staged.epoch_lineage {
        fields.push("epoch_lineage".to_owned());
    }
    if durable.target_resource_digest != staged.target_resource_digest {
        fields.push("target_resource_digest".to_owned());
    }
    if durable.approval_digest != staged.approval_digest {
        fields.push("approval_digest".to_owned());
    }
    if durable.budget_units != staged.budget_units {
        fields.push("budget_units".to_owned());
    }
    if durable.deadline_unix_nanos != staged.deadline_unix_nanos {
        fields.push("deadline_unix_nanos".to_owned());
    }
    if durable.lease_expires_unix_nanos != staged.lease_expires_unix_nanos {
        fields.push("lease_expires_unix_nanos".to_owned());
    }
    if durable.cooldown_nanos != staged.cooldown_nanos {
        fields.push("cooldown_nanos".to_owned());
    }
    if durable.cancelled != staged.cancelled {
        fields.push("cancelled".to_owned());
    }
    if durable.binding_digest != staged.binding_digest {
        fields.push("binding_digest".to_owned());
    }
    if durable.request_digest != staged.request_digest {
        fields.push("request_bytes".to_owned());
    }
    fields
}

/// Names the bound effect dimensions that differ, in canonical field order.
fn doctor_effect_changed_fields(
    durable: &DoctorEffectRecord,
    staged: &DoctorEffectRecord,
) -> Vec<String> {
    let mut fields = Vec::new();
    if durable.attempt_digest != staged.attempt_digest {
        fields.push("attempt_digest".to_owned());
    }
    if durable.operation_id != staged.operation_id {
        fields.push("operation_id".to_owned());
    }
    if durable.effect_seq != staged.effect_seq {
        fields.push("effect_seq".to_owned());
    }
    if durable.intent_digest != staged.intent_digest {
        fields.push("intent_digest".to_owned());
    }
    fields
}

/// Changed-terms conflict report for one effect identity.
fn effect_conflict(
    request: &DoctorRepairAttemptRequest,
    durable: &DoctorEffectRecord,
    staged: &DoctorEffectRecord,
) -> DoctorRepairConflict {
    DoctorRepairConflict {
        attempt_id: request.attempt_id.clone(),
        expected_digest: durable.intent_digest.clone(),
        observed_digest: staged.intent_digest.clone(),
        changed_fields: doctor_effect_changed_fields(durable, staged),
    }
}

/// Builds one deterministic admission from bound terms and one admission time.
///
/// The lease expiry is the earlier of the presented lease expiry and the
/// admission time plus the lease-duration cap, so rebuilding with the
/// durable admission time reproduces the exact same admission on replay.
/// Inputs for minting one deterministic Doctor admission.
struct MintedDoctorAdmission<'a> {
    request: &'a DoctorRepairAttemptRequest,
    envelope: &'a ClosedRepairRequest,
    operation: &'a RepairOperationRef,
    recipe_digest: &'a str,
    manifest_digest: &'a str,
    attempt_digest: &'a str,
    effect_digest: &'a str,
    lease_expiry_nanos: u64,
    deadline_nanos: u64,
    admitted_at_unix_nanos: u64,
}

fn build_doctor_admission(
    mint: &MintedDoctorAdmission<'_>,
) -> Result<DoctorRepairAdmission, KernelServiceError> {
    let lease_prefix = mint.attempt_digest.get(..16).ok_or_else(|| {
        KernelServiceError::Platform("doctor attempt digest is malformed".to_owned())
    })?;
    let mut allowed_effects = BTreeSet::new();
    if !mint.envelope.cancellation {
        allowed_effects.insert(mint.operation.operation_id().to_owned());
    }
    let admission = DoctorRepairAdmission {
        wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
        wire_version: DoctorRepairAdmission::CONTRACT_VERSION,
        attempt_id: mint.request.attempt_id.clone(),
        attempt_digest: mint.attempt_digest.to_owned(),
        effect_digest: (!mint.envelope.cancellation).then(|| mint.effect_digest.to_owned()),
        recipe_digest: mint.recipe_digest.to_owned(),
        manifest_digest: mint.manifest_digest.to_owned(),
        operation_id: mint.operation.operation_id().to_owned(),
        lease_id: format!("doctor-lease-{lease_prefix}"),
        lease_owner: DOCTOR_RECOVERY_LEASE_OWNER.to_owned(),
        lease_expires_unix_nanos: mint.lease_expiry_nanos.min(
            mint.admitted_at_unix_nanos
                .saturating_add(DOCTOR_MAX_LEASE_DURATION_NANOS),
        ),
        allowed_effects,
        budget_units: mint.envelope.budget_units,
        deadline_unix_nanos: mint.deadline_nanos,
        approval_present: mint
            .envelope
            .approval
            .as_deref()
            .is_some_and(|approval| !approval.is_empty()),
        cancelled: mint.envelope.cancellation,
        admitted_at_unix_nanos: mint.admitted_at_unix_nanos,
        admission_digest: String::new(),
    }
    .with_computed_digest()?;
    admission
        .validate()
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    Ok(admission)
}

/// Stages one effect intent before execution, idempotently.
///
/// An exact replay stages cleanly; changed terms under one effect digest
/// halt with the conflict to report instead of overwriting.
fn ensure_doctor_effect_intent<L: DoctorRecoveryLedger>(
    ledger: &L,
    request: &DoctorRepairAttemptRequest,
    operation: &RepairOperationRef,
    attempt_digest: &str,
    effect_digest: &str,
    intent_digest: &str,
) -> Result<(), DoctorGateHalt> {
    let halt = |error: KernelServiceError| DoctorGateHalt::Mechanical(error);
    let staged = DoctorEffectRecord {
        contract_version: eliot_ors::DOCTOR_RECORD_CONTRACT_VERSION,
        effect_digest: OperationIdentity::new(effect_digest)
            .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?,
        attempt_digest: attempt_digest.to_owned(),
        operation_id: OpaqueLabel::new(operation.operation_id())
            .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?,
        effect_seq: request.effect_seq,
        intent_digest: intent_digest.to_owned(),
        state: DoctorEffectState::Intended,
        outcome_digest: None,
        adapter_receipt_digest: None,
        reconciliation_key: None,
        commit_order: 0,
    };
    staged
        .validate()
        .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?;
    match ledger.stage_doctor_effect(&staged) {
        Ok(outcome) => {
            if outcome.record().same_binding(&staged) {
                Ok(())
            } else {
                Err(DoctorGateHalt::Respond(DoctorRepairResponse::Conflict(
                    effect_conflict(request, outcome.record(), &staged),
                )))
            }
        }
        Err(DoctorLedgerError::EffectIdentityConflict { .. }) => {
            let durable = ledger
                .load_doctor_effect(&staged.effect_digest)
                .map_err(|error| halt(doctor_ledger_error(&error)))?
                .ok_or_else(|| {
                    halt(KernelServiceError::Platform(
                        "conflicting doctor effect disappeared before reconciliation".to_owned(),
                    ))
                })?;
            if durable.same_binding(&staged) {
                Ok(())
            } else {
                Err(DoctorGateHalt::Respond(DoctorRepairResponse::Conflict(
                    effect_conflict(request, &durable, &staged),
                )))
            }
        }
        Err(error) => Err(halt(doctor_ledger_error(&error))),
    }
}

/// Admits one freshly staged attempt: evaluates the durable budget gate,
/// notes the admission, binds the receipt, and stages the effect intent.
///
/// The budget ledger is noted and stored *before* the attempt advances, so
/// a crash between the two writes can only over-count (fail closed), never
/// silently over-admit. Cancelled attempts consume budget uniformly:
/// cancellation is an admission outcome, not a budget bypass.
fn admit_fresh_doctor_attempt<L: DoctorRecoveryLedger>(
    ledger: &L,
    fresh: &FreshDoctorAdmission<'_>,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    if let Err(halt) = gate_doctor_budget(
        ledger,
        &fresh.envelope.brief.component,
        fresh.recipe_digest,
        fresh.attempt_budget,
        fresh.cooldown_nanos,
        fresh.now_unix_nanos,
        &fresh.request.attempt_id,
    ) {
        match halt {
            DoctorGateHalt::Respond(response) => return Ok(response),
            DoctorGateHalt::Mechanical(error) => return Err(error),
        }
    }
    let admission = build_doctor_admission(&MintedDoctorAdmission {
        request: fresh.request,
        envelope: fresh.envelope,
        operation: fresh.operation,
        recipe_digest: fresh.recipe_digest,
        manifest_digest: fresh.manifest_digest,
        attempt_digest: fresh.attempt_digest,
        effect_digest: fresh.effect_digest,
        lease_expiry_nanos: fresh.lease_expiry_nanos,
        deadline_nanos: fresh.deadline_nanos,
        admitted_at_unix_nanos: fresh.now_unix_nanos,
    })?;
    advance_fresh_doctor_attempt(
        ledger,
        AdvanceFreshDoctorAttempt {
            request: fresh.request,
            envelope: fresh.envelope,
            operation: fresh.operation,
            recipe_digest: fresh.recipe_digest,
            manifest_digest: fresh.manifest_digest,
            attempt_digest: fresh.attempt_digest,
            effect_digest: fresh.effect_digest,
            intent_digest: fresh.intent_digest,
            staged: fresh.staged,
            admission,
            lease_expiry_nanos: fresh.lease_expiry_nanos,
            deadline_nanos: fresh.deadline_nanos,
            now_unix_nanos: fresh.now_unix_nanos,
        },
    )
}

/// Evaluates the durable budget gate and notes one admission.
///
/// Returns `Ok(())` once the admission is durably counted; a refusal or a
/// mechanical failure halts through [`DoctorGateHalt`].
fn gate_doctor_budget<L: DoctorRecoveryLedger>(
    ledger: &L,
    component: &str,
    recipe_digest: &str,
    attempt_budget: u32,
    cooldown_nanos: u64,
    now_unix_nanos: u64,
    attempt_ref: &str,
) -> Result<(), DoctorGateHalt> {
    let halt = |error: KernelServiceError| DoctorGateHalt::Mechanical(error);
    let scope_key = OpaqueLabel::new(sha256_hex(
        format!("{component}::{recipe_digest}").as_bytes(),
    ))
    .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?;
    let mut budget = ledger
        .load_doctor_budget(&scope_key)
        .map_err(|error| halt(doctor_ledger_error(&error)))?
        .unwrap_or_else(|| DoctorBudgetLedger::pristine(scope_key.clone()));
    budget
        .validate()
        .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?;
    let refused = |reason: DoctorRepairRejectionReason,
                   detail: &'static str,
                   retry_after: Option<u64>,
                   cause: Option<DoctorQuarantineCause>| {
        DoctorGateHalt::Respond(DoctorRepairResponse::Rejected(DoctorRepairRejection {
            attempt_ref: attempt_ref.to_owned(),
            reason,
            detail: detail.to_owned(),
            retry_after_unix_nanos: retry_after,
            quarantine_cause: cause,
            rejected_at_unix_nanos: now_unix_nanos,
        }))
    };
    match budget.evaluate(attempt_budget, cooldown_nanos, now_unix_nanos) {
        DoctorBudgetDecision::Quarantined { cause } => Err(refused(
            DoctorRepairRejectionReason::Quarantined,
            "doctor_repair.quarantine",
            None,
            Some(cause),
        )),
        DoctorBudgetDecision::BudgetExhausted { .. } => {
            budget
                .record_quarantine(DoctorQuarantineCause::BudgetExhausted, now_unix_nanos, None)
                .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?;
            ledger
                .store_doctor_budget(&budget)
                .map_err(|error| halt(doctor_ledger_error(&error)))?;
            Err(refused(
                DoctorRepairRejectionReason::Quarantined,
                "doctor_repair.quarantine",
                None,
                Some(DoctorQuarantineCause::BudgetExhausted),
            ))
        }
        DoctorBudgetDecision::CooldownActive {
            retry_after_unix_nanos,
        } => Err(refused(
            DoctorRepairRejectionReason::CooldownActive,
            "doctor_repair.cooldown",
            Some(retry_after_unix_nanos),
            None,
        )),
        DoctorBudgetDecision::Admitted { .. } => {
            budget
                .note_admission(now_unix_nanos)
                .map_err(|error| halt(KernelServiceError::Platform(error.to_string())))?;
            ledger
                .store_doctor_budget(&budget)
                .map_err(|error| halt(doctor_ledger_error(&error)))?;
            Ok(())
        }
    }
}

/// Inputs for advancing one freshly staged Doctor attempt.
struct AdvanceFreshDoctorAttempt<'a> {
    request: &'a DoctorRepairAttemptRequest,
    envelope: &'a ClosedRepairRequest,
    operation: &'a RepairOperationRef,
    recipe_digest: &'a str,
    manifest_digest: &'a str,
    attempt_digest: &'a str,
    effect_digest: &'a str,
    intent_digest: &'a str,
    staged: &'a DoctorAttemptRecord,
    admission: DoctorRepairAdmission,
    lease_expiry_nanos: u64,
    deadline_nanos: u64,
    now_unix_nanos: u64,
}

/// Advances one budget-counted attempt, binds its receipt, and stages the
/// effect intent, returning the admission.
fn advance_fresh_doctor_attempt<L: DoctorRecoveryLedger>(
    ledger: &L,
    advance: AdvanceFreshDoctorAttempt<'_>,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    let target = if advance.envelope.cancellation {
        DoctorAttemptState::Cancelled
    } else {
        DoctorAttemptState::Admitted
    };
    let evidence = DoctorAttemptAdmission {
        admission_digest: advance.admission.admission_digest.clone(),
        admitted_at_unix_nanos: advance.now_unix_nanos,
    };
    match ledger.advance_doctor_attempt(&advance.staged.attempt_digest, target, Some(&evidence)) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(KernelServiceError::Platform(
                "admitted doctor attempt disappeared before acknowledgement".to_owned(),
            ));
        }
        Err(DoctorLedgerError::AttemptIdentityConflict { .. }) => {
            // Lost the admission race: another writer bound the receipt
            // first. Reload the durable truth and rebuild the winner's
            // admission instead of a second admission.
            let current = ledger
                .load_doctor_attempt(&advance.staged.attempt_digest)
                .map_err(|error| doctor_ledger_error(&error))?
                .ok_or_else(|| {
                    KernelServiceError::Platform(
                        "admitted doctor attempt disappeared before acknowledgement".to_owned(),
                    )
                })?;
            if !current.same_binding(advance.staged) {
                return Ok(attempt_conflict(advance.request, &current, advance.staged));
            }
            return rebuild_doctor_admission(
                ledger,
                &RebuiltDoctorAdmission {
                    request: advance.request,
                    envelope: advance.envelope,
                    operation: advance.operation,
                    recipe_digest: advance.recipe_digest,
                    manifest_digest: advance.manifest_digest,
                    attempt_digest: advance.attempt_digest,
                    effect_digest: advance.effect_digest,
                    intent_digest: advance.intent_digest,
                    durable: &current,
                    lease_expiry_nanos: advance.lease_expiry_nanos,
                    deadline_nanos: advance.deadline_nanos,
                    now_unix_nanos: advance.now_unix_nanos,
                },
            );
        }
        Err(error) => return Err(doctor_ledger_error(&error)),
    }
    if !advance.envelope.cancellation {
        match ensure_doctor_effect_intent(
            ledger,
            advance.request,
            advance.operation,
            advance.attempt_digest,
            advance.effect_digest,
            advance.intent_digest,
        ) {
            Ok(()) => {}
            Err(DoctorGateHalt::Respond(response)) => return Ok(response),
            Err(DoctorGateHalt::Mechanical(error)) => return Err(error),
        }
    }
    Ok(DoctorRepairResponse::Admitted(Box::new(advance.admission)))
}

/// Rebuilds the original admission for an exact replay.
///
/// Read-only proof: no budget is consumed, no state advances, and the
/// recomputed admission must equal the durable admission digest, otherwise
/// the ledger fails integrity instead of issuing a second admission. An
/// expired attempt has no admission to rebuild and reports expiry. The
/// effect intent is re-ensured so a crash between admission and
/// intent-staging still converges.
fn rebuild_doctor_admission<L: DoctorRecoveryLedger>(
    ledger: &L,
    rebuilt: &RebuiltDoctorAdmission<'_>,
) -> Result<DoctorRepairResponse, KernelServiceError> {
    if rebuilt.durable.state == DoctorAttemptState::Expired {
        return Ok(DoctorRepairResponse::Rejected(DoctorRepairRejection {
            attempt_ref: rebuilt.request.attempt_id.clone(),
            reason: DoctorRepairRejectionReason::ExpiredDeadline,
            detail: "doctor_repair.deadline".to_owned(),
            retry_after_unix_nanos: None,
            quarantine_cause: None,
            rejected_at_unix_nanos: rebuilt.now_unix_nanos,
        }));
    }
    let admitted_at = rebuilt.durable.admitted_at_unix_nanos.ok_or_else(|| {
        KernelServiceError::Platform("durable doctor attempt carries no admission time".to_owned())
    })?;
    let expected = rebuilt.durable.admission_digest.as_deref().ok_or_else(|| {
        KernelServiceError::Platform("durable doctor attempt carries no admission".to_owned())
    })?;
    let admission = build_doctor_admission(&MintedDoctorAdmission {
        request: rebuilt.request,
        envelope: rebuilt.envelope,
        operation: rebuilt.operation,
        recipe_digest: rebuilt.recipe_digest,
        manifest_digest: rebuilt.manifest_digest,
        attempt_digest: rebuilt.attempt_digest,
        effect_digest: rebuilt.effect_digest,
        lease_expiry_nanos: rebuilt.lease_expiry_nanos,
        deadline_nanos: rebuilt.deadline_nanos,
        admitted_at_unix_nanos: admitted_at,
    })?;
    if admission.admission_digest != expected {
        return Err(KernelServiceError::Platform(
            "durable doctor attempt cannot reproduce its admission".to_owned(),
        ));
    }
    if !rebuilt.envelope.cancellation {
        match ensure_doctor_effect_intent(
            ledger,
            rebuilt.request,
            rebuilt.operation,
            rebuilt.attempt_digest,
            rebuilt.effect_digest,
            rebuilt.intent_digest,
        ) {
            Ok(()) => {}
            Err(DoctorGateHalt::Respond(response)) => return Ok(response),
            Err(DoctorGateHalt::Mechanical(error)) => return Err(error),
        }
    }
    Ok(DoctorRepairResponse::Admitted(Box::new(admission)))
}

/// Reconciles an unknown admission delivery without admitting again.
///
/// This pure admission↔request check proves only that a retained admission
/// binds the exact presented envelope: attempt and effect identities are
/// recomputed through the Slice 1 closed contract and must match, and the
/// lease projection must equal the deterministic mint rule. It changes no
/// service state and issues no new authority; an unknown delivery whose
/// durable outcome is still uncertain remains the responsibility of the
/// durable attempt record.
pub fn reconcile_doctor_repair_admission(
    admission: &DoctorRepairAdmission,
    request: &DoctorRepairAttemptRequest,
    envelope: &ClosedRepairRequest,
) -> Result<bool, KernelServiceError> {
    admission.validate()?;
    request.validate()?;
    request.validate_canonical_digest()?;
    let presented = eliot_doctor_core::RepairRecipeIdentity::bind(&envelope.recipe)
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    if presented != envelope.recipe_identity || admission.recipe_digest != presented.digest() {
        return Ok(false);
    }
    if admission.attempt_id != request.attempt_id
        || admission.budget_units != envelope.budget_units
        || admission.cancelled != envelope.cancellation
        || admission.approval_present
            != envelope
                .approval
                .as_deref()
                .is_some_and(|approval| !approval.is_empty())
    {
        return Ok(false);
    }
    let deadline_nanos = u64::try_from(envelope.deadline.unix_timestamp_nanos()).map_err(|_| {
        KernelServiceError::Platform("doctor deadline is not representable".to_owned())
    })?;
    if admission.deadline_unix_nanos != deadline_nanos {
        return Ok(false);
    }
    let Some(operation) = envelope
        .operations
        .iter()
        .find(|operation| operation.operation_id() == admission.operation_id)
    else {
        return Ok(false);
    };
    if operation.manifest_digest() != admission.manifest_digest {
        return Ok(false);
    }
    let attempt = eliot_doctor_core::RepairAttemptIdentity::bind(&AttemptIdentityBinding {
        attempt_id: &request.attempt_id,
        brief: &envelope.brief,
        recipe: &envelope.recipe_identity,
        operation,
        fence: &envelope.fence,
        epoch: None,
        approval: envelope.approval.as_deref(),
        budget_units: envelope.budget_units,
        deadline: envelope.deadline,
    })
    .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
    if attempt.digest() != admission.attempt_digest {
        return Ok(false);
    }
    if !admission.cancelled {
        let effect =
            eliot_doctor_core::RepairEffectIdentity::bind(&attempt, operation, request.effect_seq)
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if admission.effect_digest.as_deref() != Some(effect.digest()) {
            return Ok(false);
        }
    }
    let lease_expiry_nanos = u64::try_from(envelope.lease.expires_at.unix_timestamp_nanos())
        .map_err(|_| {
            KernelServiceError::Platform("doctor lease expiry is not representable".to_owned())
        })?;
    let expected_lease = lease_expiry_nanos.min(
        admission
            .admitted_at_unix_nanos
            .saturating_add(DOCTOR_MAX_LEASE_DURATION_NANOS),
    );
    Ok(admission.lease_expires_unix_nanos == expected_lease
        && admission.lease_owner == DOCTOR_RECOVERY_LEASE_OWNER)
}
