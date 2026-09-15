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
//! The operation is unadvertised and inert without a composed front-door
//! owner ([`DOCTOR_REPAIR_ADVERTISED`] is `false`): Doctor's closed executor
//! fails closed with `KERNEL_ADMISSION_REQUIRED` until the Kernel
//! composition binds the production ledger, the immutable recipe registry,
//! and the principal owner through [`ComposedDoctorFrontDoor`], at which
//! point [`advertise_doctor_repair`] derives `true` from that real composed
//! state. Nothing here executes a repair, stores credentials, models, or shell
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

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_doctor_core::{
    AttemptIdentityBinding, ClosedRepairRequest, RepairClass, RepairOperationRef, RepairRecipe,
    RepairRecipeIdentity, RepairRecipeManifest, canonical_fence, check_fence_against_epoch,
};
use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptState, DoctorBudgetDecision,
    DoctorBudgetLedger, DoctorEffectRecord, DoctorEffectState, DoctorLedgerError,
    DoctorQuarantineCause, DoctorRecoveryLedger, EpochIdentity, EpochLineage, OpaqueLabel,
    OperationIdentity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KernelServiceError, KernelServiceState, validate_text};

/// Stable identity for the Kernel-owned Doctor repair-attempt wire.
pub const DOCTOR_REPAIR_WIRE_ID: &str = "eliot.kernel.doctor-repair-attempt";
/// Current version of the Kernel-owned Doctor repair-attempt wire.
pub const DOCTOR_REPAIR_WIRE_VERSION: u16 = 1;
/// Advertisement for the Doctor repair operation when no front-door owner is
/// composed: inert by default. Doctor's closed executor treats `false` as
/// `KERNEL_ADMISSION_REQUIRED` and performs nothing. The composed
/// advertisement is derived per call from a real
/// [`ComposedDoctorFrontDoor`] through [`advertise_doctor_repair`]; this
/// constant is only the uncomposed fail-closed default, never flipped in
/// place.
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

/// Proof that the Kernel composition bound the production Doctor
/// ledger, the immutable recipe registry, and the principal owner
/// (DISPATCH-CONTOUR-2 Slice B, issues #461 and #22).
///
/// Constructed only through [`Self::compose`], which requires all three at
/// once: a live production ledger reference (possession proves the durable
/// recovery ledger is composed — the store slice implements
/// [`DoctorRecoveryLedger`](eliot_ors::DoctorRecoveryLedger) over redb),
/// a non-empty immutable registry (possession proves the recipe content
/// authority is composed — Kernel-service mints no recipe here), and bounded
/// principal text (the Kernel-owned principal the front-door session binds,
/// never envelope bytes). No authority is minted here: the value only
/// carries references the supplying composition already owns, and every
/// admission, conflict, rejection, and reconciliation answer still comes
/// from the unchanged gate below.
pub struct ComposedDoctorFrontDoor<'a> {
    ledger: &'a dyn DoctorRecoveryLedger,
    registry: &'a DoctorRecipeRegistry,
    principal_ref: &'a str,
}

impl<'a> ComposedDoctorFrontDoor<'a> {
    /// Composes the front-door owner from the production ledger, the
    /// immutable registry, and the Kernel-owned principal reference.
    ///
    /// Fails closed when the principal is not bounded wire text or the
    /// registry admits no recipe revision.
    pub fn compose(
        ledger: &'a dyn DoctorRecoveryLedger,
        registry: &'a DoctorRecipeRegistry,
        principal_ref: &'a str,
    ) -> Result<Self, KernelServiceError> {
        validate_wire_text(principal_ref, "doctor_repair.principal")?;
        if registry.recipe_count() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "doctor_repair.registry",
                reason: "the composed doctor registry admits no recipe",
            });
        }
        Ok(Self {
            ledger,
            registry,
            principal_ref,
        })
    }

    /// Returns true exactly when the composed owner advertises the repair
    /// operation: the immutable registry carries at least one recipe
    /// revision and a Kernel-owned principal is bound.
    ///
    /// Derived from composed state on every call — never a hardcoded
    /// constant. The value can only exist when [`Self::compose`] already
    /// proved all three bindings, so `true` here always names a real
    /// composed owner.
    #[must_use]
    pub fn advertises_repair(&self) -> bool {
        self.registry.recipe_count() > 0 && !self.principal_ref.is_empty()
    }

    /// Returns the composed production ledger.
    #[must_use]
    pub fn ledger(&self) -> &'a dyn DoctorRecoveryLedger {
        self.ledger
    }

    /// Returns the composed immutable recipe registry.
    #[must_use]
    pub fn registry(&self) -> &'a DoctorRecipeRegistry {
        self.registry
    }

    /// Returns the composed Kernel-owned principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &'a str {
        self.principal_ref
    }
}

/// Returns whether Kernel currently advertises the Doctor repair operation
/// through the given composed front-door owner.
///
/// True exactly when a real composition bound the production ledger, a
/// non-empty immutable registry, and the principal owner
/// ([`ComposedDoctorFrontDoor::advertises_repair`]). Without a composed
/// owner the operation stays inert ([`DOCTOR_REPAIR_ADVERTISED`] is `false`)
/// and Doctor's closed executor keeps failing closed with
/// `KERNEL_ADMISSION_REQUIRED`.
pub fn advertise_doctor_repair(owner: &ComposedDoctorFrontDoor<'_>) -> bool {
    owner.advertises_repair()
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
    /// The one-shot composition supplied a recipe outside the
    /// automatic-safe class.
    #[error("doctor one-shot registry admits exactly one automatic-safe recipe")]
    NotAutomaticSafe,
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
    /// Builds the closed one-shot registry from composition-supplied terms.
    ///
    /// Bins composition supplies the exact manifest revision and the one
    /// automatic-safe recipe, and this validates both through
    /// [`Self::register`] unchanged while additionally requiring the single
    /// recipe to be [`RepairClass::AutomaticSafe`] — the class the closed
    /// one-shot effect adapter executes. Content authority stays with the
    /// supplying composition (the Kernel or Governor supplied set named in
    /// the struct docs): Kernel-service mints no recipe, manifest, or
    /// provenance value here, and advertisement stays inert.
    pub fn production_one_shot(
        manifest: RepairRecipeManifest,
        recipe: RepairRecipe,
    ) -> Result<Self, DoctorRegistryError> {
        if !matches!(recipe.repair_class, RepairClass::AutomaticSafe) {
            return Err(DoctorRegistryError::NotAutomaticSafe);
        }
        Self::register(manifest, vec![recipe])
    }

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
/// gate itself takes the live fence only, so admission never depends on ambient
/// authority.
///
/// T6-D1 construction contract (issue #461, owned by the D2 bins
/// front-door slice): `authority_epoch` must be the live Kernel
/// `EpochId` from `KernelService::authority_epoch()`, and `generation`
/// must be the live activation generation, following the
/// `host_request_binding.rs:113-129` pattern (live authority from the
/// Kernel service lineage plus the consumed activation receipt). Neither
/// value is ever taken from the request envelope: the gate proves the
/// presented fence agrees with this context via exact-tuple
/// `is_same_authority` and rejects mismatches before any effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorAdmissionContext {
    /// Live Kernel service state; admission requires `Ready`.
    pub service_state: KernelServiceState,
    /// Live authority epoch; the presented fence must match it exactly.
    pub authority_epoch: EpochId,
    /// Live resource generation; the presented fence must match it exactly.
    pub generation: u64,
}

impl DoctorAdmissionContext {
    /// Builds the admission context, failing closed on a zero generation.
    /// The lineage-aware epoch is always non-zero by construction.
    pub fn new(
        service_state: KernelServiceState,
        authority_epoch: EpochId,
        generation: u64,
    ) -> Result<Self, KernelServiceError> {
        if generation == 0 {
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
    /// Guarded repair presented an approval that is not bound to a live
    /// activation record.
    ///
    /// T6-D1 fail-closed cutover (issue #461): a guarded effect requires
    /// an exact approval digest bound to a live activation record, and no
    /// Doctor approval-to-activation lookup contract is published on this
    /// base — there is no documented rule mapping a Doctor approval string
    /// to an activation owner, and D1 invents none (no new lease/grant
    /// type, no string-to-activation mapping, no non-empty-string
    /// acceptance). Until the owning activation/approval snapshot contract
    /// for Doctor is published, every guarded attempt fails closed here,
    /// even with a well-formed approval present. Owner question for the
    /// follow-up slice: which contract publishes the Doctor
    /// approval-to-activation binding, and what exact digest rule proves a
    /// presented approval is live and unrevoked? (PR-body residual, D1.)
    ApprovalNotActivated,
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

/// Checks the guarded-approval activation binding (T6-D1, issue #461).
///
/// Presence was already proven by [`check_doctor_operation`]
/// (`ApprovalRequired` when missing or blank). A present approval still
/// authorizes nothing here: it must be bound to a live activation record,
/// and no such lookup contract is published for Doctor on this base, so
/// every guarded attempt fails closed with `ApprovalNotActivated`. See the
/// variant docs for the owner question. Automatic-safe attempts never reach
/// this refusal.
fn check_doctor_approval_activation(
    recipe: &RepairRecipe,
    envelope: &ClosedRepairRequest,
) -> Result<(), DoctorRefusal> {
    if !matches!(recipe.repair_class, RepairClass::Guarded) {
        return Ok(());
    }
    if envelope.approval.as_deref().is_none_or(str::is_empty) {
        return Err((
            DoctorRepairRejectionReason::ApprovalRequired,
            "doctor_repair.approval",
        ));
    }
    Err((
        DoctorRepairRejectionReason::ApprovalNotActivated,
        "doctor_repair.approval",
    ))
}

/// Checks the presented fence against the live epoch and generation.
///
/// T6-D1 admission cutover (issue #461): the echo is evaluated through the
/// canonical epoch owner (`check_fence_against_epoch`), so a full fence
/// carrying a foreign lineage is rejected here, before any staging,
/// budget, or effect — never trusted from the envelope, never minted.
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
    if check_fence_against_epoch(&envelope.fence, &context.authority_epoch).is_err() {
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
    check_doctor_approval_activation(recipe, &envelope)?;
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
///
/// T6-D1 admission cutover (issue #461): the identity binds the live
/// context epoch (`Some`), never the echo path (`None`). The gate already
/// proved exact-tuple agreement, so this re-proves lineage at bind time:
/// a foreign lineage fails closed here even if it ever reached binding.
fn bind_doctor_identities(
    request: &DoctorRepairAttemptRequest,
    terms: &ValidatedDoctorTerms<'_>,
    context: &DoctorAdmissionContext,
) -> Result<(String, String), KernelServiceError> {
    // The deadline moves out of the deserialized envelope by value, so no
    // `time` type is ever named here; the epoch is the live Kernel
    // authority from the admission context, never envelope bytes.
    let operation = terms_operation(terms);
    let attempt = eliot_doctor_core::RepairAttemptIdentity::bind(&AttemptIdentityBinding {
        attempt_id: &request.attempt_id,
        brief: &terms.envelope.brief,
        recipe: terms.registered_identity,
        operation,
        fence: &terms.envelope.fence,
        epoch: Some(&context.authority_epoch),
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
///
/// T6-D1 admission cutover (issue #461): the row carries the live lineage
/// from the admission context, never `None`, and the `u64` epoch and
/// generation projections come from the live context — not the envelope —
/// because the gate proved them equal to the presented fence
/// (`is_same_authority` plus generation equality). `fence_digest` stays
/// the opaque echo for exact-replay comparison. The `authority_epoch`
/// column keeps its `u64` sequence projection with `epoch_lineage` as the
/// authority; widening the column type is a migration owned by T6-E4.
fn build_staged_doctor_attempt(
    request: &DoctorRepairAttemptRequest,
    terms: &ValidatedDoctorTerms<'_>,
    session_principal: &str,
    attempt_digest: &str,
    evidence_digest: &str,
    context: &DoctorAdmissionContext,
) -> Result<DoctorAttemptRecord, KernelServiceError> {
    let operation = terms_operation(terms);
    let lineage_id = OpaqueLabel::new(context.authority_epoch.lineage_id.as_str())
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
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
        // Sequence projection of the live context epoch only; the
        // `epoch_lineage` field below is the authority. Gate-proven equal
        // to the presented fence sequence.
        authority_epoch: context.authority_epoch.sequence.get(),
        // Live context generation; gate-proven equal to the presented
        // fence generation.
        generation: context.generation,
        epoch_lineage: Some(EpochLineage {
            current: EpochIdentity {
                lineage_id,
                epoch: context.authority_epoch.sequence.get(),
            },
            predecessor: None,
        }),
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
    context: &DoctorAdmissionContext,
) -> Result<(BoundDoctorAttempt, DoctorAttemptRecord), DoctorGateHalt> {
    let (attempt_digest, effect_digest) =
        bind_doctor_identities(request, terms, context).map_err(DoctorGateHalt::Mechanical)?;
    let (evidence_digest, intent_digest) =
        doctor_envelope_digests(&terms.envelope).map_err(DoctorGateHalt::Mechanical)?;
    let staged = build_staged_doctor_attempt(
        request,
        terms,
        session_principal,
        &attempt_digest,
        &evidence_digest,
        context,
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
        match bind_and_stage_doctor_attempt(ledger, request, &terms, session_principal, context) {
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
        // Presence record only, bound into the admission digest for
        // exact-replay comparison — never authorization. Guarded attempts
        // never reach this mint: the `ApprovalNotActivated` gate refuses
        // them first (T6-D1, issue #461).
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
///
/// T6-D1 admission cutover (issue #461): `authority_epoch` is the live
/// Kernel `EpochId` (from `KernelService::authority_epoch()`, supplied by
/// the D2 dispatch arm — never envelope bytes), and the identity is
/// re-derived against that exact authority, so an admission minted under a
/// different lineage never reconciles as this one.
pub fn reconcile_doctor_repair_admission(
    admission: &DoctorRepairAdmission,
    request: &DoctorRepairAttemptRequest,
    envelope: &ClosedRepairRequest,
    authority_epoch: &EpochId,
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
        epoch: Some(authority_epoch),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    //! DISPATCH-CONTOUR-2 Slice B behaviour checks (issues #461 and #22).
    //!
    //! The ledger below is the same fail-closed in-memory shape used by the
    //! existing doctor integration tests: it implements the exact
    //! `DoctorRecoveryLedger` first-writer-wins contract from its trait docs
    //! (exact replay returns the durable row, changed terms conflict, no row
    //! is ever overwritten). `eliot-ors` ships no reusable in-memory ledger,
    //! so this module reuses the existing doctor-test ledger shape instead
    //! of inventing a new ledger type. Test-only scaffolding, never
    //! authority.
    //!
    //! Proven here: a real composed owner (production ledger reference,
    //! non-empty immutable registry, Kernel-owned principal) advertises
    //! `true` through [`advertise_doctor_repair`] while the uncomposed
    //! default stays `false`; composing with a blank principal fails
    //! closed; an exact replay under one attempt identity rebuilds the
    //! original admission digest (lost-reply rule: no recompute under a new
    //! id); and a foreign-lineage envelope is refused typed, never
    //! admitted.

    use std::collections::HashMap;
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_doctor_core::{
        ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief, EvidenceHandle, RecoveryLease,
        RegisteredOperation, RepairClass, RepairRecipe, RepairRecipeManifest, StateFence,
    };
    use eliot_ors::{
        DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
        DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord,
        DoctorEffectStageOutcome, DoctorEffectState, DoctorLedgerError, DoctorRecoveryLedger,
        OpaqueLabel, OperationIdentity,
    };
    use serde::de::DeserializeOwned;

    use super::*;

    const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const LINEAGE_FOREIGN: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const EPOCH_SEQUENCE: u64 = 4;
    const GENERATION: u64 = 7;
    const NOW_UNIX_NANOS: u64 = 1_700_000_000_000_000_000;

    /// Fail-closed in-memory test ledger. Same shape and contract as the
    /// ledger in the existing doctor integration tests; see the module
    /// header.
    struct TestLedger {
        attempts: Mutex<HashMap<String, DoctorAttemptRecord>>,
        effects: Mutex<HashMap<String, DoctorEffectRecord>>,
        budgets: Mutex<HashMap<String, DoctorBudgetLedger>>,
    }

    impl TestLedger {
        fn new() -> Self {
            Self {
                attempts: Mutex::new(HashMap::new()),
                effects: Mutex::new(HashMap::new()),
                budgets: Mutex::new(HashMap::new()),
            }
        }
    }

    impl DoctorRecoveryLedger for TestLedger {
        fn stage_doctor_attempt(
            &self,
            record: &DoctorAttemptRecord,
        ) -> Result<DoctorAttemptStageOutcome, DoctorLedgerError> {
            let storage = |reason: String| DoctorLedgerError::Storage(reason);
            record
                .validate()
                .map_err(|error| storage(error.to_string()))?;
            let mut attempts = self.attempts.lock().expect("test ledger lock");
            let key = record.record_key();
            if let Some(durable) = attempts.get(&key) {
                if durable.same_binding(record) {
                    return Ok(DoctorAttemptStageOutcome::Existing(durable.clone()));
                }
                return Err(DoctorLedgerError::AttemptIdentityConflict {
                    attempt_digest: key,
                });
            }
            attempts.insert(key, record.clone());
            Ok(DoctorAttemptStageOutcome::Stored(record.clone()))
        }

        fn load_doctor_attempt(
            &self,
            attempt_digest: &OperationIdentity,
        ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
            let attempts = self.attempts.lock().expect("test ledger lock");
            Ok(attempts.get(attempt_digest.as_str()).cloned())
        }

        fn advance_doctor_attempt(
            &self,
            attempt_digest: &OperationIdentity,
            target: DoctorAttemptState,
            admission: Option<&DoctorAttemptAdmission>,
        ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
            let storage = |reason: String| DoctorLedgerError::Storage(reason);
            let mut attempts = self.attempts.lock().expect("test ledger lock");
            let Some(current) = attempts.get_mut(attempt_digest.as_str()) else {
                return Ok(None);
            };
            if current.state == target {
                let replayed = match (
                    &current.admission_digest,
                    current.admitted_at_unix_nanos,
                    admission,
                ) {
                    (Some(digest), Some(at), Some(evidence)) => {
                        evidence.admission_digest == *digest
                            && evidence.admitted_at_unix_nanos == at
                    }
                    (None, None, None) => true,
                    _ => false,
                };
                if !replayed {
                    return Err(DoctorLedgerError::AttemptIdentityConflict {
                        attempt_digest: attempt_digest.as_str().to_owned(),
                    });
                }
                return Ok(Some(current.clone()));
            }
            let from = current.state;
            from.transition_to(target)
                .map_err(|error| storage(error.to_string()))?;
            match (from, target) {
                (
                    DoctorAttemptState::Requested,
                    DoctorAttemptState::Admitted | DoctorAttemptState::Cancelled,
                ) => {
                    let evidence = admission
                        .ok_or_else(|| storage("admission evidence is required".to_owned()))?;
                    evidence
                        .validate()
                        .map_err(|error| storage(error.to_string()))?;
                    current.admission_digest = Some(evidence.admission_digest.clone());
                    current.admitted_at_unix_nanos = Some(evidence.admitted_at_unix_nanos);
                }
                (DoctorAttemptState::Requested, DoctorAttemptState::Expired) => {
                    if admission.is_some() {
                        return Err(storage("an expired intent carries no admission".to_owned()));
                    }
                }
                _ => {
                    if admission.is_some() {
                        return Err(storage(
                            "admission evidence binds only on first admission".to_owned(),
                        ));
                    }
                }
            }
            current.state = target;
            current
                .validate()
                .map_err(|error| storage(error.to_string()))?;
            Ok(Some(current.clone()))
        }

        fn stage_doctor_effect(
            &self,
            record: &DoctorEffectRecord,
        ) -> Result<DoctorEffectStageOutcome, DoctorLedgerError> {
            let storage = |reason: String| DoctorLedgerError::Storage(reason);
            record
                .validate()
                .map_err(|error| storage(error.to_string()))?;
            let mut effects = self.effects.lock().expect("test ledger lock");
            let key = record.record_key();
            if let Some(durable) = effects.get(&key) {
                if durable.same_binding(record) {
                    return Ok(DoctorEffectStageOutcome::Existing(durable.clone()));
                }
                return Err(DoctorLedgerError::EffectIdentityConflict { effect_digest: key });
            }
            effects.insert(key, record.clone());
            Ok(DoctorEffectStageOutcome::Stored(record.clone()))
        }

        fn load_doctor_effect(
            &self,
            effect_digest: &OperationIdentity,
        ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
            let effects = self.effects.lock().expect("test ledger lock");
            Ok(effects.get(effect_digest.as_str()).cloned())
        }

        fn record_doctor_effect_outcome(
            &self,
            effect_digest: &OperationIdentity,
            report: &DoctorEffectOutcomeReport,
        ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
            let storage = |reason: String| DoctorLedgerError::Storage(reason);
            report
                .validate()
                .map_err(|error| storage(error.to_string()))?;
            let mut effects = self.effects.lock().expect("test ledger lock");
            let Some(current) = effects.get_mut(effect_digest.as_str()) else {
                return Ok(None);
            };
            if report.unknown {
                match current.state {
                    DoctorEffectState::Intended => {
                        current.state = DoctorEffectState::Unknown;
                        current.reconciliation_key =
                            Some(current.effect_digest.as_str().to_owned());
                    }
                    DoctorEffectState::Unknown | DoctorEffectState::Reconciling => {}
                    DoctorEffectState::Reported => {
                        return Err(DoctorLedgerError::EffectIdentityConflict {
                            effect_digest: effect_digest.as_str().to_owned(),
                        });
                    }
                }
            } else {
                let outcome = report.outcome_digest.clone().ok_or_else(|| {
                    storage("a known outcome carries its exact digest".to_owned())
                })?;
                match current.state {
                    DoctorEffectState::Intended
                    | DoctorEffectState::Unknown
                    | DoctorEffectState::Reconciling => {
                        current.state = DoctorEffectState::Reported;
                        current.outcome_digest = Some(outcome);
                        current
                            .adapter_receipt_digest
                            .clone_from(&report.adapter_receipt_digest);
                        current.reconciliation_key = None;
                    }
                    DoctorEffectState::Reported => {
                        if current.outcome_digest.as_deref() != Some(outcome.as_str()) {
                            return Err(DoctorLedgerError::EffectIdentityConflict {
                                effect_digest: effect_digest.as_str().to_owned(),
                            });
                        }
                    }
                }
            }
            current
                .validate()
                .map_err(|error| storage(error.to_string()))?;
            Ok(Some(current.clone()))
        }

        fn load_doctor_budget(
            &self,
            scope_key: &OpaqueLabel,
        ) -> Result<Option<DoctorBudgetLedger>, DoctorLedgerError> {
            let budgets = self.budgets.lock().expect("test ledger lock");
            Ok(budgets.get(scope_key.as_str()).cloned())
        }

        fn store_doctor_budget(
            &self,
            ledger: &DoctorBudgetLedger,
        ) -> Result<(), DoctorLedgerError> {
            ledger
                .validate()
                .map_err(|error| DoctorLedgerError::Storage(error.to_string()))?;
            let mut budgets = self.budgets.lock().expect("test ledger lock");
            budgets.insert(ledger.record_key(), ledger.clone());
            Ok(())
        }
    }

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    /// Builds a `time` value from its tuple encoding without naming the
    /// type: this crate must not grow a `time` dependency for one contour,
    /// mirroring the gate itself.
    fn fixture_time<T: DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("fixture time value")
    }

    fn manifest() -> RepairRecipeManifest {
        RepairRecipeManifest {
            manifest_id: "manifest".to_owned(),
            manifest_revision: 1,
            operations: vec![RegisteredOperation {
                operation_id: "restart".to_owned(),
                adapter_id: "adapter".to_owned(),
                description: "restart the component".to_owned(),
                definition_digest: "c".repeat(64),
            }],
        }
    }

    fn auto_recipe() -> RepairRecipe {
        RepairRecipe {
            recipe_id: "restart-disk".to_owned(),
            revision: 3,
            problem_classes: ["disk-failure".to_owned()].into_iter().collect(),
            components: ["disk-0".to_owned()].into_iter().collect(),
            repair_class: RepairClass::AutomaticSafe,
            prerequisites: vec!["precondition".to_owned()],
            required_authority: "kernel.recovery".to_owned(),
            allowed_effects: ["restart".to_owned()].into_iter().collect(),
            operations: vec!["restart".to_owned()],
            expected_observables: vec!["healthy".to_owned()],
            verification_contract: vec!["verify".to_owned()],
            rollback_or_compensation: vec!["rollback".to_owned()],
            attempt_budget: 8,
            cooldown: fixture_time(serde_json::json!([30, 0])),
            stop_conditions: vec!["stop".to_owned()],
        }
    }

    fn production_registry() -> DoctorRecipeRegistry {
        DoctorRecipeRegistry::production_one_shot(manifest(), auto_recipe())
            .expect("valid production one-shot registry")
    }

    fn context() -> DoctorAdmissionContext {
        DoctorAdmissionContext::new(
            KernelServiceState::Ready,
            test_epoch(LINEAGE_A, EPOCH_SEQUENCE),
            GENERATION,
        )
        .expect("valid test context")
    }

    fn brief() -> DiagnosticBrief {
        DiagnosticBrief {
            problem_id: "problem-1".to_owned(),
            component: "disk-0".to_owned(),
            failure_class: "disk-failure".to_owned(),
            symptom: "symptom".to_owned(),
            impact: "impact".to_owned(),
            evidence: vec![EvidenceHandle::new("ev-1", "a".repeat(64)).unwrap()],
            unknowns: Vec::new(),
        }
    }

    fn lease() -> RecoveryLease {
        RecoveryLease {
            lease_id: "lease-1".to_owned(),
            owner: "kernel".to_owned(),
            expires_at: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
            allowed_effects: ["restart".to_owned()].into_iter().collect(),
        }
    }

    fn closed_envelope(recipe: RepairRecipe, epoch: EpochId) -> ClosedRepairRequest {
        let manifest = manifest();
        let operation = manifest.resolve("restart").unwrap();
        ClosedRepairRequest::for_effect(ClosedRequestParams {
            request_id: "job-1".to_owned(),
            brief: brief(),
            recipe,
            operations: vec![operation],
            fence: StateFence::new(epoch, GENERATION, "b".repeat(64)).unwrap(),
            lease: lease(),
            approval: None,
            budget_units: 1,
            deadline: fixture_time(serde_json::json!([2030, 1, 0, 0, 0, 0, 0, 0, 0])),
            cancellation: false,
            escalation_target: "operator".to_owned(),
        })
        .unwrap()
    }

    fn wire_request(
        envelope: &ClosedRepairRequest,
        attempt_id: &str,
    ) -> DoctorRepairAttemptRequest {
        DoctorRepairAttemptRequest {
            wire_id: DOCTOR_REPAIR_WIRE_ID.to_owned(),
            wire_version: DOCTOR_REPAIR_WIRE_VERSION,
            attempt_id: attempt_id.to_owned(),
            effect_seq: 0,
            closed_request_json: serde_json::to_string(envelope).unwrap(),
            target_resource_digest: "1".repeat(64),
            request_digest: String::new(),
        }
        .with_computed_digest()
        .unwrap()
    }

    fn owner<'ledger>(
        ledger: &'ledger TestLedger,
        registry: &'ledger DoctorRecipeRegistry,
    ) -> ComposedDoctorFrontDoor<'ledger> {
        ComposedDoctorFrontDoor::compose(ledger, registry, "kernel.doctor-test-principal")
            .expect("valid composed test owner")
    }

    #[test]
    fn composed_owner_advertises_true_while_uncomposed_default_stays_false() {
        // The bare default is the inert fail-closed advertisement.
        assert!(!DOCTOR_REPAIR_ADVERTISED);
        let ledger = TestLedger::new();
        let registry = production_registry();
        let composed = owner(&ledger, &registry);
        // True derives from the real composed state (non-empty registry
        // plus bound principal), never from a flipped constant.
        assert!(composed.advertises_repair());
        assert!(advertise_doctor_repair(&composed));
        assert_eq!(composed.registry().recipe_count(), 1);
        assert_eq!(composed.principal_ref(), "kernel.doctor-test-principal");
    }

    #[test]
    fn compose_fails_closed_on_blank_principal() {
        let ledger = TestLedger::new();
        let registry = production_registry();
        assert!(
            ComposedDoctorFrontDoor::compose(&ledger, &registry, "   ").is_err(),
            "a blank principal binds no front-door owner"
        );
    }

    #[test]
    fn exact_replay_rebuilds_the_original_admission_digest() {
        // Lost-reply rule: a launched-but-unreconciled attempt reconciles by
        // its original identity — the replay rebuilds the exact same
        // admission instead of minting a second one under a new id.
        let ledger = TestLedger::new();
        let registry = production_registry();
        let context = context();
        let envelope = closed_envelope(auto_recipe(), test_epoch(LINEAGE_A, EPOCH_SEQUENCE));
        let request = wire_request(&envelope, "attempt-replay-1");
        let first = admit_doctor_repair(
            &ledger,
            &registry,
            &context,
            "kernel.doctor-test-principal",
            &request,
            NOW_UNIX_NANOS,
        )
        .expect("first admission");
        let DoctorRepairResponse::Admitted(first_admission) = first else {
            panic!("first presentation must be admitted, got {first:?}");
        };
        // A later retry — even at a later wall-clock time — rebuilds the
        // identical admission bound to the durable admission time.
        let replay = admit_doctor_repair(
            &ledger,
            &registry,
            &context,
            "kernel.doctor-test-principal",
            &request,
            NOW_UNIX_NANOS + 1_000_000,
        )
        .expect("replay admission");
        let DoctorRepairResponse::Admitted(replay_admission) = replay else {
            panic!("exact replay must be admitted, got {replay:?}");
        };
        assert_eq!(
            replay_admission.admission_digest, first_admission.admission_digest,
            "replay must reconcile by the original admission identity"
        );
        assert_eq!(replay_admission.attempt_id, first_admission.attempt_id);
        assert_eq!(
            replay_admission.admitted_at_unix_nanos, first_admission.admitted_at_unix_nanos,
            "replay must not recompute under a new admission time"
        );
    }

    #[test]
    fn foreign_lineage_envelope_is_refused_typed_never_admitted() {
        let ledger = TestLedger::new();
        let registry = production_registry();
        let context = context();
        let foreign = closed_envelope(auto_recipe(), test_epoch(LINEAGE_FOREIGN, EPOCH_SEQUENCE));
        let request = wire_request(&foreign, "attempt-foreign-1");
        let response = admit_doctor_repair(
            &ledger,
            &registry,
            &context,
            "kernel.doctor-test-principal",
            &request,
            NOW_UNIX_NANOS,
        )
        .expect("foreign lineage must answer typed, not fail mechanically");
        let DoctorRepairResponse::Rejected(rejection) = response else {
            panic!("foreign lineage must be refused, got {response:?}");
        };
        assert_eq!(
            rejection.reason,
            DoctorRepairRejectionReason::StaleEpoch,
            "a foreign lineage fails closed as a stale epoch"
        );
    }
}
