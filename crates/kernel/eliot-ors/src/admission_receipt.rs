//! I1.9: the canonical, versioned Governor Module Catalog admission receipt the
//! Generation Registry admits against.
//!
//! Issue #1884 external audit comment 5946154380, section 1, requires the ORS
//! persistence ingress to accept "only sealed/typed projection from the Governor
//! Module Catalog owner, or exact canonical receipt + owner readback
//! identifiers", and to verify operation/idempotency identity, module and
//! generation, the exact Catalog revision, the exact accepted manifest digest,
//! the current State Fence, the lifecycle admission disposition and the Policy
//! revision. It states in the same section that receipt text, non-zero revisions
//! and caller-supplied scopes are not authority.
//!
//! [`GovernorAdmissionReceipt`] is the one mechanically checkable mapping of
//! those owner facts. It is built by [`GovernorAdmissionReceipt::issue`] from
//! exactly the [`crate::GovernorGenerationAdmissionSealParts`] the Governor
//! owner adapter filled in, and its `owner_canonical_sha256` is computed with
//! [`crate::GovernorGenerationAdmissionSeal::canonical_sha256`] — the SAME
//! function the seal uses — so the receipt and the seal cannot drift apart or
//! grow a second spelling of the digest.
//!
//! It deliberately adds no field the owner did not supply: every value is copied
//! from `parts`, and a value `parts` cannot state is not restated here.
//!
//! The receipt carries EVERY fact the seal binds, the admitted restart
//! authorization class, the admitted effect ceiling and the admitted route-scope
//! set among them. Those three are inside the seal's canonical owner digest, so
//! a receipt that left them out would record a digest over a field set it does
//! not hold, and a receipt that restated them in a second spelling would be the
//! second mapping the audit forbids. They are copied from `parts` and compared
//! back in [`GovernorAdmissionReceipt::verify_seal`], so a receipt cannot state
//! a wider bound than the owner sealed.
//!
//! What it does NOT prove:
//!
//! * It does not prove the Governor issued the admission. `canonical_sha256` is
//!   `pub` because the owner adapter lives in another crate, so a dependent
//!   crate can compute a matching digest over fields it chose. Establishing the
//!   issuer needs the Governor accept path and a canonical owner readback of the
//!   receipt; see [`crate::GovernorGenerationAdmissionSeal`] for exactly what is
//!   and is not established.
//! * It does not prove the seal was issued either, when the two agree. A receipt
//!   that matches a seal field for field is two statements of the same owner
//!   facts agreeing with each other, and both statements are reachable from a
//!   dependent crate that chose the fields itself. Agreement is a consistency
//!   answer; the issuer is a separate question this record does not answer.
//! * It does not prove the receipt is current. It records the Catalog and Policy
//!   revisions and the State Fence identity the admission was issued under;
//!   freshness is decided against the caller's own current view elsewhere.
//! * It is not a manifest. It carries no artifact/config/protocol hashes, no
//!   command, no resource limits and no health or readiness contract, and it
//!   authorizes no launch. Carrying the admitted class, the admitted ceiling and
//!   the admitted scope SET states the bound the owner sealed and grants none of
//!   them: a route scope the owner did not admit is a refusal, not a value this
//!   receipt could add.
//!
//! Two digests in this crate must not be confused, and an earlier delivery of
//! this issue confused them:
//!
//! * `owner_canonical_sha256` is the Governor's canonical digest over the
//!   admission facts. It is the same digest the seal carries, computed by the
//!   same function.
//! * [`GovernorAdmissionReceipt::receipt_sha256`] is this receipt's own integrity
//!   digest over the receipt's own field set, which additionally covers the
//!   three admitted bounds, `issued_at_ms` and `owner_canonical_sha256` itself.
//!   It is NOT the seal's digest and NOT a Generation Registry record's
//!   `manifest_sha256`, which covers that seal.
//!
//! `validate` therefore binds `owner_canonical_sha256` by recomputing it through
//! the seal's own digest function, and never by comparing `receipt_sha256`
//! against it: those are different field sets and can never be equal.

use eliot_contracts::{ResourceGeneration, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cutover_ownership::CapabilityRouteScope;
use crate::execution_manifest::{
    GovernorGenerationAdmissionSeal, GovernorGenerationAdmissionSealParts,
    LifecycleAdmissionDisposition, ManifestEffectCeiling, RestartAuthorizationClass,
    validate_unique_scopes,
};
use crate::model::{
    OperationIdentity, OrsError, StateFenceSnapshot, sha256_hex, validate_digest, validate_text,
};

/// Durable schema version of the Governor admission receipt (I1.9).
///
/// Version `2` because the receipt's field set changed: the admitted restart
/// authorization class, the admitted effect ceiling and the admitted route-scope
/// set are now carried by the receipt, so a receipt written under version `1`
/// states a field set the seal's canonical owner digest no longer covers.
///
/// A version bump is the correct repair rather than a migration because no
/// version `1` receipt row can exist. The only writer of a
/// `GOVERNOR_ADMISSION_RECEIPTS` row is
/// `RedbRecoveryStore::persist_governor_admission_receipt`, and the table, that
/// method and this record all arrived in the same issue #1884 delivery, which is
/// not on `origin/main`; that writer's only production call site is the Governor
/// accept chain, whose outermost producer has no in-tree caller, so no store can
/// hold a row this bump would strand. Nothing needs rewriting.
///
/// A receipt row that does carry another version is a refusal:
/// [`GovernorAdmissionReceipt::validate`] returns
/// [`OrsError::UnsupportedContractVersion`] for it. Nothing here is defaulted
/// and no migration exists, because a missing bound must fail closed: inventing
/// the class, the ceiling or the scope set for an older row would fabricate
/// exactly the authority this record exists to bind.
pub const GOVERNOR_ADMISSION_RECEIPT_SCHEMA_VERSION: u16 = 2;

#[derive(Serialize)]
struct GovernorAdmissionReceiptCore<'a> {
    receipt_version: u16,
    operation_id: &'a OperationIdentity,
    idempotency_key: &'a str,
    module_id: &'a str,
    generation: ResourceGeneration,
    catalog_revision: u64,
    policy_revision: u64,
    accepted_manifest_sha256: &'a str,
    state_fence: &'a StateFenceSnapshot,
    lifecycle_disposition: LifecycleAdmissionDisposition,
    restart_authorization_class: RestartAuthorizationClass,
    admitted_effect_ceiling: ManifestEffectCeiling,
    admitted_allowed_scopes: &'a [CapabilityRouteScope],
    owner_canonical_sha256: &'a str,
    issued_at_ms: i64,
}

/// The canonical, versioned Governor Module Catalog admission receipt (I1.9).
///
/// Every field is one fact the owner states, and the whole set is bound by
/// `owner_canonical_sha256`, which is the digest
/// [`GovernorAdmissionReceipt::issue`] computes with the sealed admission
/// projection's own digest function. A caller cannot assemble an admission out
/// of receipt text, a non-zero revision pair and a scope it picked itself: this
/// receipt restates no value it was not given, and [`Self::verify_seal`] compares
/// the sealed admission against it field by field.
///
/// The admitted restart authorization class, the admitted effect ceiling and the
/// admitted route-scope set are carried here as the owner's own admitted values
/// because the sealed projection binds them inside its canonical digest. They
/// are a statement of the bound the owner sealed, never a grant: this receipt
/// confers no restart class, no effect authority and no route scope of its own,
/// and it authorizes no launch.
///
/// This is the Kernel-side receipt record, not the owner contract. The owner
/// contract is `eliot_module_registry::GenerationAdmission` and the single
/// adapter from it is `eliot_module_registry::seal_generation_admission`, so
/// there is one versioned spelling of the mapping. The receipt never re-decides
/// an admission, never repairs one and never re-seals one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorAdmissionReceipt {
    /// Durable schema version of this receipt.
    pub schema_version: u16,
    /// Canonical operation identity the admission was issued under.
    pub operation_id: OperationIdentity,
    /// Canonical idempotency key of that same admission operation.
    pub idempotency_key: String,
    /// Admitted module identity.
    pub module_id: String,
    /// Admitted generation identity.
    pub generation: ResourceGeneration,
    /// Exact accepted Module Catalog revision.
    pub catalog_revision: u64,
    /// Exact Policy revision that was current at admission.
    pub policy_revision: u64,
    /// The Module Catalog owner's recorded accepted-execution-manifest digest.
    ///
    /// It is provenance copied from the owner and is bound by
    /// `owner_canonical_sha256`. It is never recomputed on this side, never
    /// compared against this receipt's own `receipt_sha256`, and never compared
    /// against a Generation Registry record's `manifest_sha256`.
    pub accepted_manifest_sha256: String,
    /// Exact canonical State Fence identity the admission was issued under.
    pub state_fence: StateFenceSnapshot,
    /// Lifecycle disposition the Catalog recorded.
    pub lifecycle_disposition: LifecycleAdmissionDisposition,
    /// Restart authorization class the Catalog admitted.
    ///
    /// The owner's admitted value, copied from the same sealed facts the seal
    /// carries, and inside the canonical owner digest with them. It states the
    /// bound that was admitted; it grants no restart authority by itself.
    pub restart_authorization_class: RestartAuthorizationClass,
    /// Effect ceiling the Catalog admitted.
    ///
    /// The owner's admitted value, copied from the same sealed facts the seal
    /// carries, and inside the canonical owner digest with them. It states the
    /// ceiling that was admitted; it grants no effect authority by itself.
    pub admitted_effect_ceiling: ManifestEffectCeiling,
    /// Route scopes the Catalog admitted, in the exact order the owner stated
    /// them.
    ///
    /// The owner's admitted set, copied from the same sealed facts the seal
    /// carries, and inside the canonical owner digest with them. It states the
    /// scopes that were admitted; it opens no route, and a scope the owner did
    /// not state is a refusal rather than a value this receipt could add.
    pub admitted_allowed_scopes: Vec<CapabilityRouteScope>,
    /// The canonical owner digest over the admission facts above.
    pub owner_canonical_sha256: String,
    /// Issue time in Unix milliseconds.
    pub issued_at_ms: i64,
}

impl GovernorAdmissionReceipt {
    /// Issues the receipt for exactly the owner facts in `parts`.
    ///
    /// Every field is copied from `parts` — including the admitted restart
    /// authorization class, the admitted effect ceiling and the admitted
    /// route-scope set, so the receipt and the sealed projection are issued from
    /// ONE field set and the receipt is not a second mapping that can drift —
    /// and `owner_canonical_sha256` is recomputed with
    /// [`GovernorGenerationAdmissionSeal::canonical_sha256`], the same function
    /// the seal uses, so the receipt and the seal share one digest function and
    /// one version rather than two that can drift. Any value in `parts` that
    /// does not satisfy the typed shape is refused here, and nothing is
    /// defaulted or substituted: a `parts` that cannot state a field is a
    /// refusal, not a partly filled receipt.
    pub fn issue(
        parts: &GovernorGenerationAdmissionSealParts,
        issued_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let receipt = Self {
            schema_version: GOVERNOR_ADMISSION_RECEIPT_SCHEMA_VERSION,
            operation_id: parts.operation_id.clone(),
            idempotency_key: parts.idempotency_key.clone(),
            module_id: parts.module_id.clone(),
            generation: parts.generation,
            catalog_revision: parts.catalog_revision,
            policy_revision: parts.policy_revision,
            accepted_manifest_sha256: parts.accepted_manifest_sha256.clone(),
            state_fence: parts.state_fence.clone(),
            lifecycle_disposition: parts.lifecycle_disposition,
            restart_authorization_class: parts.restart_authorization_class,
            admitted_effect_ceiling: parts.admitted_effect_ceiling,
            admitted_allowed_scopes: parts.admitted_allowed_scopes.clone(),
            owner_canonical_sha256: GovernorGenerationAdmissionSeal::canonical_sha256(parts)?,
            issued_at_ms,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates the receipt's own shape and the binding of its owner digest.
    ///
    /// The admitted route-scope set must be internally well formed as well as
    /// sealed: the same `validate_unique_scopes` rule the sealed projection
    /// applies to its own `admitted_allowed_scopes` is applied here, so a set
    /// naming one route scope twice is refused on both sides by one rule rather
    /// than by two that could disagree.
    ///
    /// The recorded lifecycle disposition is deliberately NOT required to be an
    /// admission here: this function answers "is this receipt internally
    /// consistent", so a withheld admission stays recordable as evidence. The
    /// refusal to admit is raised by the sealed projection's own validation,
    /// where it is typed
    /// ([`crate::KernelReconciliationKind::GovernorAdmissionSealWithheld`]), and
    /// it applies before any ORS mutation either way.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != GOVERNOR_ADMISSION_RECEIPT_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        validate_text(
            self.operation_id.as_str(),
            "governor_admission_receipt_operation_id",
        )?;
        validate_text(
            &self.idempotency_key,
            "governor_admission_receipt_idempotency_key",
        )?;
        validate_text(&self.module_id, "governor_admission_receipt_module_id")?;
        if self.catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_policy_revision",
                reason: "must be greater than zero",
            });
        }
        validate_digest(
            &self.accepted_manifest_sha256,
            "governor_admission_receipt_accepted_manifest_sha256",
        )?;
        self.state_fence.validate()?;
        validate_unique_scopes(
            &self.admitted_allowed_scopes,
            "governor_admission_receipt_admitted_allowed_scopes",
        )?;
        validate_digest(
            &self.owner_canonical_sha256,
            "governor_admission_receipt_owner_canonical_sha256",
        )?;
        if self.issued_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_issued_at_ms",
                reason: "must be greater than zero",
            });
        }
        // The binding is recomputed through the seal's own digest function over
        // this receipt's own sealed fields, all thirteen of them, so a receipt
        // whose recorded owner digest was edited, or whose sealed fields were
        // edited after issuance, is refused instead of carrying a digest that
        // describes something else.
        if GovernorGenerationAdmissionSeal::canonical_sha256(&self.sealed_fields())?
            != self.owner_canonical_sha256
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "governor_admission_receipt",
                reason:
                    "the recorded owner canonical digest does not bind the receipt's own fields"
                        .to_owned(),
            });
        }
        Ok(())
    }

    /// Compares this receipt against the sealed projection, field by field.
    ///
    /// Every difference is an [`OrsError::InvalidField`] naming the differing
    /// field. The receipt is never repaired, the seal is never re-sealed and no
    /// missing value is defaulted, so the check answers only "are these the same
    /// admission". A receipt with no seal, a receipt for another module or
    /// generation, a receipt issued for other Catalog/Policy revisions, a
    /// receipt carrying another State Fence identity, a receipt carrying another
    /// lifecycle disposition, a receipt carrying another admitted restart
    /// authorization class, another admitted effect ceiling, another admitted
    /// route-scope set, and a receipt whose accepted manifest digest differs all
    /// refuse here, before any ORS mutation can observe them.
    ///
    /// Scope stated exactly: this compares all THIRTEEN identities the sealed
    /// admission binds - canonical operation identity, idempotency identity,
    /// module, generation, exact catalog revision, exact policy revision, exact
    /// accepted manifest digest, exact State Fence, lifecycle admission
    /// disposition, admitted restart authorization class, admitted effect
    /// ceiling, admitted route-scope set and the owner's canonical digest - one
    /// named `OrsError::InvalidField` each. Nothing is compared through a digest
    /// argument and nothing is inferred: a difference in any of the thirteen is
    /// that field's own refusal.
    ///
    /// The route-scope set is compared entry for entry and in order, so a set
    /// that is only a permutation of the sealed one is a refusal rather than an
    /// agreement. That order is the owner's own: the receipt is copied from the
    /// sealed facts without being sorted, deduped, widened or narrowed.
    ///
    /// The owner digest is compared as a RECORDED value, not recomputed here.
    /// Recomputing it over the seal's own fields would be a fixed point - the
    /// record's `validate` already proves it recomputes - so it could only ever
    /// agree. It is a named comparison because the receipt is the owner's
    /// separate statement of the same digest, and two statements of one value
    /// can disagree.
    ///
    /// What agreement here does NOT establish is that the Governor issued either
    /// statement: both are reachable from a dependent crate that chose the owner
    /// facts itself. This is a consistency answer, and a consistent pair is not
    /// an issuer proof.
    pub fn verify_seal(&self, seal: &GovernorGenerationAdmissionSeal) -> Result<(), OrsError> {
        self.validate()?;
        if self.operation_id != *seal.operation_id() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_operation_id",
                reason: "must equal the sealed admission's canonical operation identity",
            });
        }
        if self.idempotency_key != seal.idempotency_key() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_idempotency_key",
                reason: "must equal the sealed admission's canonical idempotency key",
            });
        }
        if self.module_id != seal.module_id() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_module_id",
                reason: "must equal the sealed admission's module identity",
            });
        }
        if self.generation != seal.generation() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_generation",
                reason: "must equal the sealed admission's generation identity",
            });
        }
        if self.catalog_revision != seal.catalog_revision() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_catalog_revision",
                reason: "must equal the sealed admission's exact accepted Catalog revision",
            });
        }
        if self.policy_revision != seal.policy_revision() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_policy_revision",
                reason: "must equal the sealed admission's exact Policy revision",
            });
        }
        if self.accepted_manifest_sha256 != seal.accepted_manifest_sha256() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_accepted_manifest_sha256",
                reason: "must equal the sealed admission's accepted-manifest digest",
            });
        }
        if self.state_fence != *seal.state_fence() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_state_fence",
                reason: "must equal the sealed admission's exact State Fence identity",
            });
        }
        if self.lifecycle_disposition != seal.lifecycle_disposition() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_lifecycle_disposition",
                reason: "must equal the sealed admission's lifecycle disposition",
            });
        }
        if self.restart_authorization_class != seal.restart_authorization_class() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_restart_authorization_class",
                reason: "must equal the sealed admission's admitted restart authorization class",
            });
        }
        if self.admitted_effect_ceiling != seal.admitted_effect_ceiling() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_admitted_effect_ceiling",
                reason: "must equal the sealed admission's admitted effect ceiling",
            });
        }
        if self.admitted_allowed_scopes != seal.admitted_allowed_scopes() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_admitted_allowed_scopes",
                reason: "must equal the sealed admission's admitted route-scope set, in order",
            });
        }
        if self.owner_canonical_sha256 != seal.owner_canonical_sha256() {
            return Err(OrsError::InvalidField {
                field: "governor_admission_receipt_owner_canonical_sha256",
                reason: "must equal the owner canonical digest the sealed admission records",
            });
        }
        Ok(())
    }

    /// The canonical digest of this receipt's own fields.
    ///
    /// This is the receipt's own integrity digest, computed with the same
    /// canonical-JSON and SHA-256 helpers this crate already uses. It is NOT a
    /// recomputation of the seal's `owner_canonical_sha256` and NOT a copy of a
    /// Generation Registry record's `manifest_sha256`: the field set is the
    /// receipt's, which additionally covers the admitted restart authorization
    /// class, the admitted effect ceiling, the admitted route-scope set,
    /// `issued_at_ms` and `owner_canonical_sha256` itself. It is stored beside
    /// the record and re-checked on readback, so a receipt row edited after it
    /// was written fails closed as corruption.
    pub fn receipt_sha256(&self) -> Result<String, OrsError> {
        let core = GovernorAdmissionReceiptCore {
            receipt_version: self.schema_version,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            module_id: &self.module_id,
            generation: self.generation,
            catalog_revision: self.catalog_revision,
            policy_revision: self.policy_revision,
            accepted_manifest_sha256: &self.accepted_manifest_sha256,
            state_fence: &self.state_fence,
            lifecycle_disposition: self.lifecycle_disposition,
            restart_authorization_class: self.restart_authorization_class,
            admitted_effect_ceiling: self.admitted_effect_ceiling,
            admitted_allowed_scopes: &self.admitted_allowed_scopes,
            owner_canonical_sha256: &self.owner_canonical_sha256,
            issued_at_ms: self.issued_at_ms,
        };
        let bytes =
            canonical_json_bytes(&core).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// The receipt's own admission facts, in the one shape the seal's canonical
    /// digest function reads and `issue` is handed.
    ///
    /// It restates ALL THIRTEEN fields the sealed projection binds, in the seal's
    /// own order, and it reads every one of them off THIS receipt's own fields:
    /// the admitted restart authorization class, the admitted effect ceiling and
    /// the admitted route-scope set included. That is what keeps `validate` a
    /// fixed point. A recomputation over fewer fields than the digest covers
    /// could never equal the recorded value, so every receipt would be refused
    /// as an integrity problem no matter who issued it; a recomputation over
    /// fields read from anywhere but this receipt would not be checking this
    /// record.
    ///
    /// `owner_canonical_sha256` is copied unchanged rather than recomputed here,
    /// because the caller of this helper is the check that decides whether the
    /// recorded digest binds those facts.
    fn sealed_fields(&self) -> GovernorGenerationAdmissionSealParts {
        GovernorGenerationAdmissionSealParts {
            operation_id: self.operation_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            module_id: self.module_id.clone(),
            generation: self.generation,
            catalog_revision: self.catalog_revision,
            policy_revision: self.policy_revision,
            accepted_manifest_sha256: self.accepted_manifest_sha256.clone(),
            state_fence: self.state_fence.clone(),
            lifecycle_disposition: self.lifecycle_disposition,
            restart_authorization_class: self.restart_authorization_class,
            admitted_effect_ceiling: self.admitted_effect_ceiling,
            admitted_allowed_scopes: self.admitted_allowed_scopes.clone(),
            owner_canonical_sha256: self.owner_canonical_sha256.clone(),
        }
    }
}
