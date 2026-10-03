//! I1.9 + I14.14: the authority/effect operation lease that gates an
//! effect-capable restart or replay.
//!
//! I1.9 admits an effect-capable generation to resume only exact
//! already-authorized operations covered by an unexpired operation lease, and
//! routes every invalid or unavailable authorization state to shadow/no-effect
//! diagnostics. This module is the record those two rules are read from.
//!
//! It is deliberately a separate record from the supervision lease. I1.5
//! defines a `SupervisionLease` as a Kernel-owned observation obligation, and
//! `crate::SupervisionLeaseRecord` binds a lease identity, a lifecycle
//! `SupervisionLeaseOperation`, a `LeaseState` and a signed observation
//! artifact. None of the bindings this record needs is representable there: it
//! binds no execution-manifest identity or digest, no authorized effect
//! operation identity, no effect receipt, no allowed route scope, no admitting
//! Catalog or Policy revision, and no delivery acknowledgement state. Its
//! `operation_id` names an ORS lifecycle transition, not an authorized external
//! effect. Reusing it would overload a supervision obligation with effect
//! authority, so [`EffectOperationLease`] is its own record and this crate
//! offers no conversion between the two.
//!
//! Every denied, expired or unknown replay produces a durable reconciliation
//! item on the decision, and a decision that authorizes nothing carries no
//! lease at all: [`ActiveEffectOperationLease`] is sealed with private fields,
//! has no public constructor and deliberately has no `Deserialize`
//! implementation, so nothing here can turn a shadow/no-effect candidate into
//! an external effect or a canonical write admission.
//!
//! Issuance is gated on the Generation Registry lifecycle observation the
//! refusal path escalates into. A generation ORS already records as degraded or
//! quarantined for a manifest refusal admits no *new* operation lease — it may
//! resume only an exact operation an unexpired lease it already holds covers —
//! and the lifecycle owner's
//! [`crate::ObservedGenerationLifecycle`] is a typed input of
//! [`EffectOperationLease::issue`], not a value the issuer derives for itself.
//! That observation is composed from durable owner data, and the ONE place that
//! constructs an observation variant directly is the store seam
//! `RedbRecoveryStore::load_observed_generation_lifecycle`
//! (`crates/kernel/eliot-ors/src/store.rs`), whose `(Some(record), None)` arm
//! returns a recorded row as `ObservedGenerationLifecycle::Recorded` because a
//! generation with a recorded `Degraded` row and a deleted manifest row has no
//! manifest for `ObservedGenerationLifecycle::compose` to validate that row
//! against, and the weaker "never observed" refusal there would report a
//! generation ORS has recorded as degraded as one it holds no evidence about.
//! Everything else composes through
//! [`ObservedGenerationLifecycle::compose`], and the domain gates below are the
//! only gates that READ an observation, for issuance and for replay. The
//! observation is not optional here: a generation ORS recorded no lifecycle row
//! for but DOES hold an intact admitted manifest for the same
//! `{module_id, generation}` has been positively observed as undegraded, while a
//! generation ORS holds neither fact is refused by the composition itself. There
//! is no second spelling of the disposition in this module; the lifecycle owner
//! keeps the only one. Because that observation can only be composed, the
//! admission [`EffectOperationLease::issue`] takes derives `Serialize` and
//! deliberately no `Deserialize`: nothing can recover an observation from bytes
//! and hand one in as a composition.
//!
//! [`authorize_effect_replay`] is the one classifier here, and it is the entry
//! point the live dispatcher chain reaches:
//! `RedbRecoveryStore::authorize_effect_replay_for_operation`
//! (`crates/kernel/eliot-ors/src/store.rs`) calls it directly with the OBSERVED
//! revocation acknowledgement and delivery acknowledgement its own durable rows
//! record, and with the COMPOSED generation lifecycle observation its own
//! durable readbacks produce — that one is composed, not read back as a row — so
//! no decision here is reached from a lease's own recorded fields alone.
//! [`authorize_effect_operation_lease_replay`] is the store seam for a caller
//! that observes no effect receipt and no route scope of its own; it delegates to
//! the same classifier and currently has no production caller.
//!
//! This module is pure domain logic: it owns no process, store handle, or
//! canonical memory.

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_runtime_contracts::LeaseState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::cutover_ownership::CapabilityRouteScope;
use crate::execution_manifest::{
    CatalogPolicyView, EffectDeliveryAcknowledgement, KernelExecutionManifest,
    KernelReconciliationItem, KernelReconciliationKind, RevocationAcknowledgement,
};
use crate::generation_lifecycle::ObservedGenerationLifecycle;
use crate::model::{OperationIdentity, OrsError, validate_digest, validate_text};

/// Durable schema version of the effect operation lease record (I1.9).
pub const EFFECT_OPERATION_LEASE_SCHEMA_VERSION: u16 = 1;

/// The Governor/Kernel-issued inputs that create one effect operation lease.
///
/// The manifest identity and digest are not inputs: `EffectOperationLease::issue`
/// copies them from the manifest so a lease can never name a different
/// execution manifest than the one it was admitted against.
///
/// Every other input is compared against that manifest or refused. The
/// revocation and delivery inputs are the acknowledgements the issuing path
/// really read back from the durable rows it owns, and `generation_lifecycle`
/// is a COMPOSED [`ObservedGenerationLifecycle`] with no absent case: a
/// generation ORS that recorded no lifecycle row but holds an intact admitted
/// manifest for the same `{module_id, generation}` has been positively observed
/// as undegraded, while a generation ORS that holds neither fact cannot hand an
/// observation over at all, because composing one refuses.
///
/// That is why this type derives `Serialize` and deliberately does NOT derive
/// `Deserialize` under `deny_unknown_fields`: an observation must be composed
/// from durable readbacks and must never be recovered from bytes and presented
/// as something ORS composed, so a decode path here would reintroduce exactly
/// the fabricated current-state value the composed type exists to prevent. The
/// sibling precedents are in this same module — `EffectDispatchAuthority`
/// deliberately has no `Deserialize` implementation, so an ordinary caller can
/// neither assemble an accepted typestate from public fields nor recover one
/// from serialized bytes — and `crate::BoundKernelExecutionManifest` in
/// `crates/kernel/eliot-ors/src/execution_manifest.rs` does the same for a
/// sealed manifest binding. [`ObservedGenerationLifecycle`] has no `Deserialize`
/// implementation either, so no second spelling of this admission exists.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOperationLeaseAdmission {
    /// Lease identity.
    pub lease_id: OperationIdentity,
    /// The one exact operation identity this lease may replay.
    pub operation_id: OperationIdentity,
    /// Digest of the one exact already-authorized effect.
    pub effect_receipt_sha256: String,
    /// The exact route scope the lease cannot widen.
    pub allowed_scope: CapabilityRouteScope,
    /// Authority Epoch the lease is issued under.
    pub authority_epoch: AuthorityEpoch,
    /// Admitting Module Catalog revision. Must be non-zero, and must equal
    /// the manifest's recorded admitting Catalog revision: a lease cannot be
    /// issued against a revision the Governor never admitted for this
    /// manifest (I1.9 lines 24 and 35).
    pub catalog_revision: u64,
    /// Admitting Policy revision. Must be non-zero, and must equal the
    /// manifest's recorded admitting Policy revision, for the same reason.
    pub policy_revision: u64,
    /// The revocation acknowledgement state observed for this exact lease
    /// identity at issuance time.
    ///
    /// `RevocationAcknowledgement::None` is the only value that admits
    /// issuance, and it is no longer assumed: it is the acknowledgement the
    /// issuing path's readback of the durable revocation-event row reported, and
    /// `RevocationAcknowledgement::Acknowledged` (revoked) or `Unacknowledged`
    /// (an outstanding revocation event) refuses before any lease is built. The
    /// source is the ORS revocation-event readback for this exact lease
    /// identity; a source with no such row must refuse the issuance rather than
    /// report `None` on the generation's behalf.
    pub revocation: RevocationAcknowledgement,
    /// The delivery acknowledgement state observed for this exact lease
    /// identity's effect delivery path at issuance time.
    ///
    /// `EffectDeliveryAcknowledgement::Acknowledged` is the only value that
    /// admits issuance, and it is recorded from this input rather than assumed,
    /// so the issued lease states the delivery state its issuer actually
    /// observed. `EffectDeliveryAcknowledgement::GapOpen` refuses before any
    /// lease is built. The source is the ORS delivery readback for this exact
    /// lease identity; a source with no delivery readback must refuse the
    /// issuance rather than report `Acknowledged` on its behalf.
    pub delivery: EffectDeliveryAcknowledgement,
    /// The Generation Registry lifecycle OBSERVATION for the affected
    /// generation, composed from durable owner data for the manifest's own
    /// `{module_id, generation}`.
    ///
    /// This is an OBSERVED composition, not a bare record and not a value this
    /// module derives for itself: it is composed from durable facts by
    /// [`ObservedGenerationLifecycle::compose`], and the ONE exception is the
    /// store seam `RedbRecoveryStore::load_observed_generation_lifecycle`
    /// (`crates/kernel/eliot-ors/src/store.rs`), which constructs
    /// [`ObservedGenerationLifecycle::Recorded`] directly for a generation whose
    /// recorded lifecycle row has no manifest row beside it, because there
    /// `compose` has no manifest to validate that row against. The domain gates
    /// in this module are the only gates that READ an observation — this
    /// issuance gate and the replay gate of `authorize_effect_replay` — and
    /// neither composes one. It names which durable facts it rests on: either a
    /// `GENERATION_LIFECYCLES` row read back for this exact `{module_id,
    /// generation}` that satisfied its own `validate()`, or no such row together
    /// with an admitted, validating `KernelExecutionManifest` row for the SAME
    /// key.
    ///
    /// An observation whose composed disposition is not
    /// [`crate::GenerationDisposition::Undegraded`] is refused with
    /// `OrsError::EffectOperationLeaseGenerationDegraded` and that disposition
    /// named, so a generation ORS has already degraded or quarantined for a
    /// manifest refusal cannot be issued a new operation lease and cannot be
    /// worked around by restarting it. The observation is validated against the
    /// manifest before it is read for a disposition, so a readback taken for
    /// another generation cannot authorize this issuance. The disposition
    /// vocabulary itself is the lifecycle owner's single
    /// [`crate::GenerationDisposition`]; this module states no second one.
    ///
    /// What the composed arm does NOT prove: that a process is running, that
    /// routes are live or drained, or that the generation is healthy. The health
    /// and readiness contract is the recorded manifest's and is observed
    /// elsewhere.
    pub generation_lifecycle: ObservedGenerationLifecycle,
    /// Issue time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// Versioned effect operation lease bound to one exact effect replay.
///
/// The record carries the bindings issue #1885 requires of an operation lease:
/// the manifest identity and hash, the Authority Epoch, the exact operation
/// identity and effect receipt, the allowed scope, the expiry, the admitting
/// Catalog and Policy revisions, and the revocation and delivery
/// acknowledgement state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOperationLease {
    /// Durable schema version of this record.
    pub schema_version: u16,
    /// Lease identity.
    pub lease_id: OperationIdentity,
    /// Module identity of the bound execution manifest.
    pub manifest_module_id: String,
    /// Generation identity of the bound execution manifest.
    pub manifest_generation: ResourceGeneration,
    /// Exact manifest hash the effect was authorized under.
    pub bound_manifest_sha256: String,
    /// Authority Epoch the lease was issued under.
    pub authority_epoch: AuthorityEpoch,
    /// The one exact operation identity this lease may replay.
    pub operation_id: OperationIdentity,
    /// Digest of the one exact already-authorized effect.
    pub effect_receipt_sha256: String,
    /// The exact route scope the lease cannot widen.
    pub allowed_scope: CapabilityRouteScope,
    /// Expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Admitting Module Catalog revision.
    pub catalog_revision: u64,
    /// Admitting Policy revision.
    pub policy_revision: u64,
    /// Lifecycle state of the lease revision.
    pub state: LeaseState,
    /// Recorded acknowledgement state of a revocation event.
    pub revocation: RevocationAcknowledgement,
    /// Recorded acknowledgement state of the effect's delivery path.
    pub delivery: EffectDeliveryAcknowledgement,
    /// Issue time in Unix milliseconds.
    pub issued_at_ms: i64,
}

impl EffectOperationLease {
    /// Issues the one lease an effect-capable manifest may hold for one exact
    /// effect.
    ///
    /// The module identity, generation and manifest hash are copied from
    /// `manifest`, so a lease cannot be admitted against a different manifest.
    /// Issuance is refused for a generation whose composed lifecycle observation
    /// is anything other than undegraded, for a `read_rebuild` manifest, which is
    /// never effect capable, for a scope that is not one of the manifest's
    /// recorded allowed scopes, for an Authority Epoch that differs from the
    /// manifest's own admission epoch, for admitting Catalog/Policy revisions that
    /// differ from the manifest's recorded Governor-admitted revisions, and for
    /// any observed revocation event or open delivery gap. The Kernel side
    /// therefore cannot mint a lease for a generation a manifest refusal already
    /// degraded (I1.9 lines 44-46 and 52), cannot mint one against revisions or an
    /// epoch the Governor never admitted for this manifest, and cannot mint one
    /// while the effect's revocation or delivery state is not proven clear.
    ///
    /// The lifecycle observation is composed by
    /// [`ObservedGenerationLifecycle::compose`] from the caller's durable
    /// readbacks, so a generation whose recorded manifest predates that
    /// composition is admitted on an intact admitted manifest instead of being
    /// refused for the absence of a degradation row it never had.
    ///
    /// The issued record carries the revocation and delivery acknowledgement
    /// state the admission actually stated, and the lifecycle observation is
    /// consumed by the refusal above rather than stored: the lease is a grant for
    /// one exact operation, and the generation's degraded state lives in the
    /// Generation Registry lifecycle row the observation was composed from. The
    /// replay verifier independently requires the same manifest agreement before
    /// any admission, so a lease issued here always carries revisions the gate can
    /// accept.
    pub fn issue(
        manifest: &KernelExecutionManifest,
        admission: EffectOperationLeaseAdmission,
    ) -> Result<Self, OrsError> {
        require_new_effect_lease_generation_lifecycle(manifest, &admission)?;
        manifest.validate()?;
        if !manifest.restart_authorization_class().is_effect_capable() {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_manifest_class",
                reason: "only an effect-capable manifest may admit an effect operation lease",
            });
        }
        if admission.authority_epoch != manifest.admission.authority_epoch {
            return Err(OrsError::EffectOperationLeaseManifestBindingMismatch {
                field: "effect_operation_lease_authority_epoch",
            });
        }
        if admission.catalog_revision != manifest.admission.catalog_revision {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_catalog_revision",
                reason: "must equal the manifest's recorded admitting Catalog revision",
            });
        }
        if admission.policy_revision != manifest.admission.policy_revision {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_policy_revision",
                reason: "must equal the manifest's recorded admitting Policy revision",
            });
        }
        if admission.revocation != RevocationAcknowledgement::None {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_revocation",
                reason: "no revocation event may be outstanding or acknowledged for the affected generation at issuance",
            });
        }
        if admission.delivery != EffectDeliveryAcknowledgement::Acknowledged {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_delivery",
                reason: "no delivery gap may be open for the affected generation at issuance",
            });
        }
        let scope_admitted = manifest
            .allowed_scopes()
            .iter()
            .any(|scope| scope.route_scope_hash == admission.allowed_scope.route_scope_hash);
        if !scope_admitted {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_allowed_scope",
                reason: "the lease scope must be one of the manifest's allowed scopes",
            });
        }
        let lease = Self {
            schema_version: EFFECT_OPERATION_LEASE_SCHEMA_VERSION,
            lease_id: admission.lease_id,
            manifest_module_id: manifest.admission.module_id.clone(),
            manifest_generation: manifest.admission.generation,
            bound_manifest_sha256: manifest.manifest_sha256.clone(),
            authority_epoch: admission.authority_epoch,
            operation_id: admission.operation_id,
            effect_receipt_sha256: admission.effect_receipt_sha256,
            allowed_scope: admission.allowed_scope,
            expires_at_ms: admission.expires_at_ms,
            catalog_revision: admission.catalog_revision,
            policy_revision: admission.policy_revision,
            state: LeaseState::Active,
            revocation: admission.revocation,
            delivery: admission.delivery,
            issued_at_ms: admission.issued_at_ms,
        };
        lease.validate()?;
        Ok(lease)
    }

    /// The module identity of the bound execution manifest.
    pub const fn manifest_module_id(&self) -> &str {
        self.manifest_module_id.as_str()
    }

    /// Validates the record shape, the digest and scope bindings, the revisions
    /// and the expiry window.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != EFFECT_OPERATION_LEASE_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        validate_text(self.lease_id.as_str(), "effect_operation_lease_lease_id")?;
        validate_text(
            &self.manifest_module_id,
            "effect_operation_lease_manifest_module_id",
        )?;
        validate_digest(
            &self.bound_manifest_sha256,
            "effect_operation_lease_bound_manifest_sha256",
        )?;
        validate_text(
            self.operation_id.as_str(),
            "effect_operation_lease_operation_id",
        )?;
        validate_digest(
            &self.effect_receipt_sha256,
            "effect_operation_lease_effect_receipt_sha256",
        )?;
        self.allowed_scope.validate()?;
        if self.catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_policy_revision",
                reason: "must be greater than zero",
            });
        }
        if self.issued_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_issued_at_ms",
                reason: "must be greater than zero",
            });
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        if self.state == LeaseState::Revoked
            && self.revocation != RevocationAcknowledgement::Acknowledged
        {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_revocation",
                reason: "a revoked lease must record an acknowledged revocation",
            });
        }
        Ok(())
    }
}

/// Requires the OBSERVED Generation Registry lifecycle observation that admits
/// a NEW effect operation lease for this manifest's own generation.
///
/// The observation is the composed answer of the lifecycle owner
/// ([`crate::GenerationDisposition`]), and this is the only gate in THIS MODULE
/// that reads it for issuance; this module declares no second spelling of it.
/// The one other reader in this module is `require_replayable_generation_lifecycle`,
/// which reads the same observation for REPLAY, and outside this module the store
/// gate `RedbRecoveryStore::require_undegraded_generation`
/// (`crates/kernel/eliot-ors/src/store.rs`) reads the composed observation for
/// issuance as well as for replay.
/// `RedbRecoveryStore::issue_effect_operation_lease_for_operation` runs that
/// store gate first and then hands this gate the newer observation it composed
/// from its own readbacks
/// (`crates/kernel/eliot-ors/src/store.rs`). There is no absent case here: a
/// generation ORS that holds neither a recorded degradation nor an intact
/// admitted manifest for this key has no observation to hand over at all,
/// because composing one refuses — so an unobservable clearance never arrives
/// here as one, and no caller can supply one from bytes either, because
/// [`ObservedGenerationLifecycle`] has no `Deserialize` implementation. The
/// remaining refusals are typed and fail closed:
///
/// * a recorded row that fails its own `validate()`, or whose own
///   `{module_id, generation}` is not this manifest's, refuses — the latter with
///   `OrsError::EffectOperationLeaseManifestBindingMismatch` naming this
///   admission's own field, so a readback resolved for another generation cannot
///   authorize an issuance for this one;
/// * an observation that does not admit a new lease refuses with
///   `OrsError::EffectOperationLeaseGenerationDegraded` carrying the observed
///   disposition name, so a degraded or quarantined generation is not reported as
///   an opaque field error and cannot be worked around by minting a fresh lease.
///
/// The observation is validated against the manifest through its own
/// `validate_against` before its disposition is read, so the composition and this
/// gate can never disagree about which manifest the observation belongs to.
fn require_new_effect_lease_generation_lifecycle(
    manifest: &KernelExecutionManifest,
    admission: &EffectOperationLeaseAdmission,
) -> Result<(), OrsError> {
    let observation = &admission.generation_lifecycle;
    if let Some(record) = observation.recorded() {
        record.validate()?;
        if record.module_id != manifest.admission.module_id
            || record.generation != manifest.admission.generation
        {
            return Err(OrsError::EffectOperationLeaseManifestBindingMismatch {
                field: "effect_operation_lease_generation_lifecycle",
            });
        }
    }
    observation.validate_against(manifest)?;
    if observation.admits_new_effect_leases() {
        return Ok(());
    }
    Err(OrsError::EffectOperationLeaseGenerationDegraded {
        module_id: manifest.admission.module_id.clone(),
        generation: manifest.admission.generation,
        disposition: format!("{:?}", observation.disposition()),
    })
}

/// Sealed effect-dispatch authority for one admitted replay.
///
/// This is the only value an effect-capable dispatch path may treat as effect
/// authority. It is produced exclusively by `authorize_effect_replay`: its
/// lease field is private, it has no public constructor, and it deliberately
/// has no `Deserialize` implementation, so an ordinary caller can neither
/// assemble an accepted typestate from public fields nor recover one from
/// serialized bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActiveEffectOperationLease {
    lease: EffectOperationLease,
}

impl ActiveEffectOperationLease {
    /// Issues the sealed authority. Only the module's verifier may call it.
    const fn verified(lease: EffectOperationLease) -> Self {
        Self { lease }
    }

    /// The exact durable lease the verifier accepted.
    pub const fn lease(&self) -> &EffectOperationLease {
        &self.lease
    }

    /// Lease identity.
    pub const fn lease_id(&self) -> &OperationIdentity {
        &self.lease.lease_id
    }

    /// The one exact operation identity this authority may replay.
    pub const fn operation_id(&self) -> &OperationIdentity {
        &self.lease.operation_id
    }

    /// Digest of the one exact already-authorized effect.
    pub fn effect_receipt_sha256(&self) -> &str {
        &self.lease.effect_receipt_sha256
    }

    /// The exact route scope hash this authority cannot widen.
    pub fn allowed_scope_hash(&self) -> &str {
        &self.lease.allowed_scope.route_scope_hash
    }

    /// The manifest hash this authority is bound to.
    pub fn bound_manifest_sha256(&self) -> &str {
        &self.lease.bound_manifest_sha256
    }

    /// Authority Epoch this authority was issued under.
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.lease.authority_epoch
    }

    /// Expiry boundary in Unix milliseconds.
    pub const fn expires_at_ms(&self) -> i64 {
        self.lease.expires_at_ms
    }
}

/// The Kernel's current authority view for one effect replay.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorizationView {
    /// Current Authority Epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Current accepted Module Catalog revision.
    pub catalog_revision: u64,
    /// Current Policy revision.
    pub policy_revision: u64,
    /// Availability of the current Module Catalog/Policy view.
    pub catalog_view: CatalogPolicyView,
    /// Acknowledgement state of the latest revocation event.
    pub revocation: RevocationAcknowledgement,
    /// Acknowledgement state of the delivery path.
    pub delivery: EffectDeliveryAcknowledgement,
}

impl EffectAuthorizationView {
    /// Validates the current revisions.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "effect_authorization_view_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "effect_authorization_view_policy_revision",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// One exact effect replay to authorize.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReplayRequest {
    /// The exact operation identity the replay claims.
    pub operation_id: OperationIdentity,
    /// The module identity the replay is bound to.
    pub manifest_module_id: String,
    /// The generation identity the replay is bound to.
    pub manifest_generation: ResourceGeneration,
    /// The manifest hash the replay is bound to.
    pub bound_manifest_sha256: String,
    /// Digest of the exact already-authorized effect being replayed.
    pub effect_receipt_sha256: String,
    /// The exact route scope the replay claims. It cannot exceed the lease's.
    pub allowed_scope: CapabilityRouteScope,
    /// The caller's current authority view.
    pub current: EffectAuthorizationView,
    /// Observation time of the decision in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl EffectReplayRequest {
    /// Validates the request's own identities, digests, scope, view and clock.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.operation_id.as_str(),
            "effect_replay_request_operation_id",
        )?;
        validate_text(
            &self.manifest_module_id,
            "effect_replay_request_manifest_module_id",
        )?;
        validate_digest(
            &self.bound_manifest_sha256,
            "effect_replay_request_bound_manifest_sha256",
        )?;
        validate_digest(
            &self.effect_receipt_sha256,
            "effect_replay_request_effect_receipt_sha256",
        )?;
        self.allowed_scope.validate()?;
        self.current.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "effect_replay_request_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Shadow/no-effect diagnostic context for one denied replay.
///
/// It carries the affected identities so an operator can see which generation
/// and manifest the candidate observed. It carries no lease, no authorizing
/// operation identity and no canonical write admission, and nothing in this
/// crate converts it into one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEffectDiagnostics {
    /// The affected module identity the candidate may still observe.
    pub module_id: String,
    /// The affected generation identity the candidate may still observe.
    pub generation: ResourceGeneration,
    /// The manifest hash the candidate is bound to.
    pub bound_manifest_sha256: String,
}

impl ShadowEffectDiagnostics {
    /// Builds the shadow context for one denied replay.
    fn for_request(request: &EffectReplayRequest) -> Self {
        Self {
            module_id: request.manifest_module_id.clone(),
            generation: request.manifest_generation,
            bound_manifest_sha256: request.bound_manifest_sha256.clone(),
        }
    }
}

/// The dispatch authority one effect replay may act on.
///
/// Exactly one shape is present. A denied, expired, unknown, invalid or
/// unavailable authorization state leaves
/// `authorized_lease()` empty and yields the shadow/no-effect diagnostic
/// context instead, which can expose diagnostics but cannot execute an effect
/// or admit a canonical write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectDispatchAuthority {
    authorized_lease: Option<ActiveEffectOperationLease>,
    shadow: Option<ShadowEffectDiagnostics>,
}

impl EffectDispatchAuthority {
    /// Issues the effect-carrying authority. Only the verifier may call it.
    const fn effect(lease: ActiveEffectOperationLease) -> Self {
        Self {
            authorized_lease: Some(lease),
            shadow: None,
        }
    }

    /// Issues the shadow/no-effect authority. Only the verifier may call it.
    const fn shadow_only(context: ShadowEffectDiagnostics) -> Self {
        Self {
            authorized_lease: None,
            shadow: Some(context),
        }
    }

    /// The sealed lease, or `None` in shadow/no-effect diagnostics mode.
    pub const fn authorized_lease(&self) -> Option<&ActiveEffectOperationLease> {
        self.authorized_lease.as_ref()
    }

    /// The shadow/no-effect diagnostic context, or `None` when a lease is
    /// authorized.
    pub const fn shadow(&self) -> Option<&ShadowEffectDiagnostics> {
        self.shadow.as_ref()
    }
}

/// One effect-replay decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectReplayDecision {
    /// The dispatch authority the caller may act on.
    pub authority: EffectDispatchAuthority,
    /// The durable reconciliation intent. It is absent only for an admitted
    /// replay: every denied, expired or unknown replay carries one, so the
    /// attempt cannot be discarded.
    pub reconciliation: Option<KernelReconciliationItem>,
}

impl EffectReplayDecision {
    /// Builds the decision that authorizes nothing and escalates one defect.
    ///
    /// `recorded_manifest_sha256` is the digest of the manifest row the caller
    /// actually loaded, so the durable escalation names what is recorded beside
    /// the request rather than a digest copied out of the lease it is refusing.
    fn denied(
        kind: KernelReconciliationKind,
        request: &EffectReplayRequest,
        lease: Option<&EffectOperationLease>,
        recorded_manifest_sha256: Option<String>,
    ) -> Self {
        Self {
            authority: EffectDispatchAuthority::shadow_only(ShadowEffectDiagnostics::for_request(
                request,
            )),
            reconciliation: Some(effect_reconciliation_item(
                kind,
                request,
                lease,
                recorded_manifest_sha256,
            )),
        }
    }

    /// Builds the decision that authorizes the exact recorded effect.
    fn admitted(lease: ActiveEffectOperationLease) -> Self {
        Self {
            authority: EffectDispatchAuthority::effect(lease),
            reconciliation: None,
        }
    }
}

/// Authorizes one exact effect replay against its operation lease.
///
/// This is the query every effect-capable restart/replay path performs before
/// dispatching an effect. It mutates no durable state and dispatches nothing.
///
/// The OBSERVED current state its caller read back is what decides. The lease's
/// own recorded fields never decide anything: its recorded revocation and
/// delivery pair is a SECONDARY cross-check that can only ever add a refusal,
/// and that one-directional ordering is deliberate. [`EffectOperationLease::validate`]
/// constrains the recorded revocation state in only one direction — a `Revoked`
/// lease must record an acknowledged revocation, and no other combination is
/// constrained — so a lease row of `{Active, Unacknowledged, GapOpen}` satisfies
/// its own `validate()`, and only that secondary check refuses it, with
/// `KernelReconciliationKind::EffectLeaseRevocationUnacknowledged`. Deleting the
/// check would let such a row replay while the caller's readback reports a clean
/// one, which is why it stays. I1.9's revocation condition is an event that is
/// UNACKNOWLEDGED, so a `RevocationAcknowledgement::None` readback — no
/// revocation event exists at all — refuses nothing here, while an
/// `Acknowledged` readback names a DISCHARGED event: a revocation happened and
/// was acknowledged, which is not the same fact as no revocation happening, and
/// the lease it fenced stays fenced through the recorded-row refusal below.
///
/// # Observed inputs
///
/// * `lease` — the durable [`EffectOperationLease`] row, or `None` for any
///   operation no lease covers;
/// * `manifest` — the durable manifest row read back for the request's own
///   `{module_id, generation}`, or `None` when no row exists;
/// * `generation_lifecycle` — the Generation Registry lifecycle OBSERVATION for
///   that same `{module_id, generation}`, composed by the caller from its durable
///   readbacks through
///   [`ObservedGenerationLifecycle::compose`]. It rests on a recorded lifecycle
///   row for that key, or on no such row plus an intact admitted manifest row for
///   the same key. It is never `None` and never a bare record: a generation ORS
///   holding neither fact has no observation to hand over at all, because
///   composing one refuses before this classifier runs;
/// * `request.current.revocation` and `request.current.delivery` — the
///   acknowledgements the caller's durable revocation-event and delivery rows
///   actually record for this lease identity, not a constant the caller supplies
///   and never a copy of `lease.revocation`/`lease.delivery`.
///
/// A replay is admitted only when all of the following hold, and each content
/// failure returns the shadow/no-effect authority with a durable reconciliation
/// item:
///
/// * the lease exists and satisfies its own shape;
/// * the recorded manifest exists, satisfies its own shape, carries a
///   Governor admission, and is effect capable;
/// * the generation lifecycle observation composes to `Undegraded` for the
///   request's own `{module_id, generation}`, so a generation ORS has degraded for
///   a manifest refusal cannot have its existing lease replayed (this refusal is
///   the typed `OrsError` the store already raised, not a reconciliation item);
/// * the lease's manifest identity and hash equal the recorded manifest's;
/// * the requested operation identity, effect receipt and route scope equal the
///   lease's exactly, so none of them can be changed or widened;
/// * the lease's recorded route scope is one the recorded manifest's own allowed
///   scopes contain, and its Authority Epoch is both the manifest's admitting
///   epoch and the current one, so neither the scope nor the epoch is confirmed
///   by the caller alone;
/// * the admitting Catalog and Policy revisions are the current ones and the
///   Module Catalog/Policy view is current;
/// * the OBSERVED revocation state is not an outstanding unacknowledged event
///   (I1.9's literal condition), and the lease's own recorded revocation state is
///   neither an outstanding unacknowledged event nor an acknowledged revocation —
///   a lease cannot clear itself, and its recorded state can only ever add a
///   refusal;
/// * the OBSERVED delivery state is not an open gap, and the lease's own recorded
///   delivery state is not an open gap either, for the same reason; an
///   `Acknowledged` delivery is refused by neither;
/// * the lease is active and is not expired at `request.observed_at_ms`.
///
/// The request side of each comparison is the caller's own observation, never a
/// copy of the lease's fields. A caller that presents a well-formed lease for a
/// *different* operation, module, generation or manifest therefore fails the
/// matching content check instead of confirming the lease against itself, and a
/// caller that cannot observe an effect receipt or a route scope of its own
/// reaches this same classifier through
/// [`authorize_effect_operation_lease_replay`], which takes both from the
/// durable lease and lets the recorded manifest bound them.
///
/// An operation with no lease — that is, any new operation — is denied, which
/// is what stops an effect-capable generation from resuming a new operation
/// after catalog/policy freshness is lost.
pub fn authorize_effect_replay(
    lease: Option<&EffectOperationLease>,
    manifest: Option<&KernelExecutionManifest>,
    generation_lifecycle: &ObservedGenerationLifecycle,
    request: &EffectReplayRequest,
) -> Result<EffectReplayDecision, OrsError> {
    request.validate()?;
    let recorded_manifest_sha256 = manifest.map(|value| value.manifest_sha256.clone());
    let Some(lease) = lease else {
        return Ok(EffectReplayDecision::denied(
            KernelReconciliationKind::EffectLeaseAbsent,
            request,
            None,
            recorded_manifest_sha256,
        ));
    };
    if let Some(kind) = classify_effect_replay(lease, manifest, generation_lifecycle, request)? {
        return Ok(EffectReplayDecision::denied(
            kind,
            request,
            Some(lease),
            recorded_manifest_sha256,
        ));
    }
    Ok(EffectReplayDecision::admitted(
        ActiveEffectOperationLease::verified(lease.clone()),
    ))
}

/// Requires the OBSERVED lifecycle observation of the replayed generation.
///
/// There is no absent case: a generation ORS that holds neither a recorded
/// lifecycle row nor an intact admitted manifest for this key has no observation
/// to hand over at all, because composing one refuses, so an unobservable
/// clearance never arrives here as one. A recorded row is validated through its
/// own `validate()`, must name the same `{module_id, generation}` the replay is
/// bound to, and its observation is then validated against that manifest through
/// its own `validate_against`; the observation must admit new effect leases,
/// otherwise the replay is refused with the observed disposition named. A degraded
/// or quarantined generation may resume only an exact already-authorized
/// operation an unexpired lease it already holds covers (I1.9 lines 44-46), and
/// even that is refused here while the degradation stands.
fn require_replayable_generation_lifecycle(
    manifest: &KernelExecutionManifest,
    lifecycle: &ObservedGenerationLifecycle,
) -> Result<(), OrsError> {
    let module_id = manifest.admission.module_id.clone();
    let generation = manifest.admission.generation;
    if let Some(record) = lifecycle.recorded() {
        record.validate()?;
        if record.module_id != module_id || record.generation != generation {
            return Err(OrsError::EffectOperationLeaseManifestBindingMismatch {
                field: "effect_replay_generation_lifecycle",
            });
        }
    }
    lifecycle.validate_against(manifest)?;
    if lifecycle.admits_new_effect_leases() {
        return Ok(());
    }
    Err(OrsError::EffectOperationLeaseGenerationDegraded {
        module_id,
        generation,
        disposition: format!("{:?}", lifecycle.disposition()),
    })
}

/// Returns the first blocking defect, or `None` when the replay is admitted.
fn classify_effect_replay(
    lease: &EffectOperationLease,
    manifest: Option<&KernelExecutionManifest>,
    generation_lifecycle: &ObservedGenerationLifecycle,
    request: &EffectReplayRequest,
) -> Result<Option<KernelReconciliationKind>, OrsError> {
    if lease.validate().is_err() {
        return Ok(Some(KernelReconciliationKind::EffectLeaseInvalid));
    }
    let Some(manifest) = manifest else {
        return Ok(Some(KernelReconciliationKind::ManifestAbsent));
    };
    require_replayable_generation_lifecycle(manifest, generation_lifecycle)?;
    Ok(classify_manifest_bound_effect_replay(
        lease, manifest, request,
    ))
}

/// Returns the first blocking defect in the manifest-bound part of the replay,
/// or `None` when every manifest, currency, revocation, delivery and liveness
/// check holds.
///
/// This half assumes the generation lifecycle check already passed: it is the
/// part of the audit's list that the recorded manifest and the observed current
/// state answer — manifest digest, generation, Authority Epoch, the current
/// revocation and delivery acknowledgements, and the lease's expiry and active
/// state. The order is fixed: manifest validity, the manifest-bound lease and
/// request bindings, scope, epoch, catalog currency, the revocation and delivery
/// pair, expiry, then the active flag. The revocation and delivery pair is the
/// extracted `classify_observed_effect_current_state` and runs at the same place
/// in that chain as before.
fn classify_manifest_bound_effect_replay(
    lease: &EffectOperationLease,
    manifest: &KernelExecutionManifest,
    request: &EffectReplayRequest,
) -> Option<KernelReconciliationKind> {
    if !manifest.has_governor_admission() {
        return Some(KernelReconciliationKind::ManifestReceiptless);
    }
    if manifest.validate().is_err() {
        return Some(KernelReconciliationKind::ManifestInvalid);
    }
    if !manifest.restart_authorization_class().is_effect_capable() {
        return Some(KernelReconciliationKind::ManifestNotEffectCapable);
    }
    let manifest_binds_lease = manifest.admission.module_id == lease.manifest_module_id
        && manifest.admission.generation == lease.manifest_generation
        && manifest.manifest_sha256 == lease.bound_manifest_sha256;
    if !manifest_binds_lease {
        return Some(KernelReconciliationKind::EffectManifestMismatch);
    }
    if request.bound_manifest_sha256 != lease.bound_manifest_sha256
        || request.manifest_module_id != lease.manifest_module_id
        || request.manifest_generation != lease.manifest_generation
    {
        return Some(KernelReconciliationKind::EffectManifestMismatch);
    }
    if request.operation_id != lease.operation_id {
        return Some(KernelReconciliationKind::EffectOperationIdentityMismatch);
    }
    if request.effect_receipt_sha256 != lease.effect_receipt_sha256 {
        return Some(KernelReconciliationKind::EffectReceiptMismatch);
    }
    if request.allowed_scope.route_scope_hash != lease.allowed_scope.route_scope_hash {
        return Some(KernelReconciliationKind::EffectScopeMismatch);
    }
    // The lease's recorded scope is the one a caller with no scope of its own
    // cannot check, so the recorded manifest bounds it directly: a scope outside
    // the manifest's own allowed scopes is refused here instead of being
    // confirmed against the lease that recorded it.
    let scope_admitted = manifest
        .allowed_scopes()
        .iter()
        .any(|scope| scope.route_scope_hash == lease.allowed_scope.route_scope_hash);
    if !scope_admitted {
        return Some(KernelReconciliationKind::EffectScopeMismatch);
    }
    // Likewise the epoch: the lease must name the epoch the recorded manifest
    // was admitted under, not merely an epoch the caller also happens to hold.
    if lease.authority_epoch != manifest.admission.authority_epoch {
        return Some(KernelReconciliationKind::EffectEpochMismatch);
    }
    if lease.authority_epoch != request.current.authority_epoch {
        return Some(KernelReconciliationKind::EffectEpochMismatch);
    }
    let catalog_current = request.current.catalog_view == CatalogPolicyView::Current
        && request.current.catalog_revision == lease.catalog_revision
        && request.current.policy_revision == lease.policy_revision;
    if !catalog_current {
        return Some(KernelReconciliationKind::EffectCatalogPolicyStale);
    }
    if let Some(kind) = classify_observed_effect_current_state(lease, request) {
        return Some(kind);
    }
    // The one expiry rule: the lease is expired when the observation has reached
    // its expiry boundary or its own state already says so. Neither the request
    // nor the caller's clock can produce a second boundary here.
    if request.observed_at_ms >= lease.expires_at_ms || lease.state == LeaseState::Expired {
        return Some(KernelReconciliationKind::EffectLeaseExpired);
    }
    match lease.state {
        LeaseState::Active | LeaseState::Expiring => None,
        _ => Some(KernelReconciliationKind::EffectLeaseNotActive),
    }
}

/// Returns the first revocation or delivery defect of one replay, or `None` when
/// both current states are clear.
///
/// The two conditions are decided on the OBSERVED acknowledgements in
/// `request.current`, which the caller read back from the durable revocation-event
/// and delivery rows for this lease identity — never on a constant the caller
/// supplied and never on a copy of the lease's own fields.
///
/// # Revocation
///
/// I1.9 lines 48-49 block on a revocation event that is UNACKNOWLEDGED, and that
/// is the whole revocation condition here, so the three values of
/// [`RevocationAcknowledgement`] are three different facts and are read as three
/// different facts:
///
/// * [`RevocationAcknowledgement::None`] — no revocation event exists at all, so
///   there is nothing outstanding and nothing is refused. A recorded event can
///   never read back as this value, because
///   [`crate::RevocationEventRecord::validate`] refuses it and an absent event is
///   the absence of the row.
/// * [`RevocationAcknowledgement::Unacknowledged`] — a revocation event EXISTS and
///   nobody has acknowledged it, so the authority it affects is unusable until
///   the event is delivered. That is I1.9's literal blocking condition and it is
///   refused as
///   [`KernelReconciliationKind::EffectLeaseRevocationUnacknowledged`].
/// * [`RevocationAcknowledgement::Acknowledged`] — a revocation event exists AND
///   has been acknowledged. What acknowledges it is the delivery of that event to
///   the authority it fenced: acknowledgement DISCHARGES the pending event, it
///   does not cancel the revocation, does not restore the authority and does not
///   mean that no revocation ever happened. The thing the event fenced is this
///   operation lease, and it stays fenced: a lease row that itself records
///   `Acknowledged` is refused here as
///   [`KernelReconciliationKind::EffectLeaseRevoked`], and
///   [`EffectOperationLease::validate`] keeps a `Revoked` lease bound to an
///   acknowledged revocation. That recorded refusal is the fence this crate can
///   state; nothing else in it re-fences an operation whose revocation event was
///   acknowledged after its lease row was written, because a lease row is written
///   once and recording a revocation event changes no lease state. An
///   already-authorized operation is therefore not refused twice for one
///   discharged event.
///
/// # Delivery
///
/// [`EffectDeliveryAcknowledgement`] has exactly two values and both are genuine
/// recordable states, so nothing is refused for the absence of a delivery value:
/// I1.9 blocks on a delivery gap being OPEN, so `GapOpen` is refused as
/// [`KernelReconciliationKind::EffectDeliveryGapOpen`] and an `Acknowledged`
/// delivery is not refused at all.
///
/// # The secondary cross-check
///
/// The lease's OWN recorded pair is a secondary check that can only ever ADD a
/// refusal: the OBSERVED value decides and a recorded pair never clears a
/// refusal. It is not redundant, because
/// [`EffectOperationLease::validate`] constrains the recorded revocation in one
/// direction only — a `Revoked` lease must record an acknowledged revocation, and
/// no other combination is constrained — so a row of
/// `{Active, Unacknowledged, GapOpen}` satisfies its own `validate()`. Deleting
/// this cross-check would let such a row replay on a clean readback, so it stays
/// and it never replaces the observed condition above it.
fn classify_observed_effect_current_state(
    lease: &EffectOperationLease,
    request: &EffectReplayRequest,
) -> Option<KernelReconciliationKind> {
    // The OBSERVED revocation readback is keyed by THIS lease's own identity
    // (`RedbRecoveryStore::observed_lease_acknowledgements` reads
    // `load_revocation_event(&lease.lease_id)`), so an observed `Acknowledged`
    // states that THIS lease's authority was revoked and the event was delivered
    // and took effect. That is I1.9's "revocation event unacknowledged" only for
    // the `Unacknowledged` value; `Acknowledged` is a DISCHARGED event, and a
    // discharged event still names a revoked lease. Refusing it here is what
    // stops a revoked operation from replaying on a clean lease row.
    if request.current.revocation == RevocationAcknowledgement::Acknowledged
        || lease.revocation == RevocationAcknowledgement::Acknowledged
    {
        return Some(KernelReconciliationKind::EffectLeaseRevoked);
    }
    if request.current.revocation == RevocationAcknowledgement::Unacknowledged
        || lease.revocation == RevocationAcknowledgement::Unacknowledged
    {
        return Some(KernelReconciliationKind::EffectLeaseRevocationUnacknowledged);
    }
    if request.current.delivery == EffectDeliveryAcknowledgement::GapOpen
        || lease.delivery == EffectDeliveryAcknowledgement::GapOpen
    {
        return Some(KernelReconciliationKind::EffectDeliveryGapOpen);
    }
    None
}

/// Denies one effect replay that no effect operation lease covers (I1.9).
///
/// A replay whose operation has no recorded lease is a *new* operation, not a
/// replay of an already-authorized one, so it is refused outright. The caller
/// holds no already-authorized effect, no effect receipt and no admitted route
/// scope for it, so this accepts only the identity and clock it genuinely
/// observes: the exact operation identity, the affected module identity and
/// generation, the manifest digest when one was actually read, and the
/// observation time. No digest, epoch or scope is defaulted or invented and no
/// request is fabricated — the decision is built here, in the module that owns
/// the sealed [`EffectDispatchAuthority`] constructors, so the result is still
/// a shadow/no-effect authority carrying a durable reconciliation intent.
///
/// This is the denial an effect-capable dispatch path reaches whenever the
/// store has no lease row for the operation, which is what stops a
/// generation from resuming a new operation after catalog/policy freshness is
/// lost.
#[must_use]
pub fn deny_unleased_effect_replay(
    operation_id: &OperationIdentity,
    module_id: &str,
    generation: ResourceGeneration,
    bound_manifest_sha256: Option<String>,
    observed_at_ms: i64,
) -> EffectReplayDecision {
    EffectReplayDecision {
        authority: EffectDispatchAuthority::shadow_only(ShadowEffectDiagnostics {
            module_id: module_id.to_owned(),
            generation,
            bound_manifest_sha256: bound_manifest_sha256.clone().unwrap_or_default(),
        }),
        reconciliation: Some(KernelReconciliationItem {
            kind: KernelReconciliationKind::EffectLeaseAbsent,
            module_id: module_id.to_owned(),
            generation,
            bound_manifest_sha256,
            recorded_manifest_sha256: None,
            lease_id: None,
            operation_id: Some(operation_id.clone()),
            observed_at_ms,
        }),
    }
}

/// Refuses one replay that has no recorded execution manifest at all.
///
/// A caller that did find a manifest does not come here; it continues into
/// [`authorize_effect_replay`], which applies every lease, binding, currency and
/// liveness check and validates the manifest through its own `validate()`.
/// Nothing is recomputed here, and no manifest is inspected here, because this
/// function answers only the one condition a request built from the durable rows
/// cannot express.
///
/// An absent manifest contributes no accepted Module Catalog revision, so
/// `EffectAuthorizationView::validate` refuses a request built from it with a
/// bare `InvalidField` on the revision field. The caller would then see an
/// opaque field error, with no typed disposition, no preserved evidence and no
/// durable reconciliation item — exactly the discarded refusal I1.9 forbids.
/// This is the denial the same query reaches for an absent lease in
/// [`deny_unleased_effect_replay`], applied to the manifest instead.
///
/// The escalation is built from the lease's own recorded values, so it names the
/// exact operation and the exact manifest binding the lease was issued against
/// rather than a reconstructed pair, and `recorded_manifest_sha256` stays absent
/// because no row was found. The returned authority is the shadow/no-effect one:
/// it carries no lease, so the refused replay can produce no external effect and
/// no canonical write admission.
#[must_use]
pub fn deny_effect_replay_without_manifest(
    lease: &EffectOperationLease,
    observed_at_ms: i64,
) -> EffectReplayDecision {
    EffectReplayDecision {
        authority: EffectDispatchAuthority::shadow_only(ShadowEffectDiagnostics {
            module_id: lease.manifest_module_id.clone(),
            generation: lease.manifest_generation,
            bound_manifest_sha256: lease.bound_manifest_sha256.clone(),
        }),
        reconciliation: Some(KernelReconciliationItem {
            kind: KernelReconciliationKind::ManifestAbsent,
            module_id: lease.manifest_module_id.clone(),
            generation: lease.manifest_generation,
            bound_manifest_sha256: Some(lease.bound_manifest_sha256.clone()),
            recorded_manifest_sha256: None,
            lease_id: Some(lease.lease_id.clone()),
            operation_id: Some(lease.operation_id.clone()),
            observed_at_ms,
        }),
    }
}

/// Builds the reconciliation item for one replay-side defect.
///
/// `recorded_manifest_sha256` is the digest of the manifest row the caller
/// actually loaded and is absent only when no row was found. The lease identity
/// and the recorded operation identity are preserved beside it, so a refused
/// attempt names the lease it claimed, the operation it replayed, the manifest
/// digest it was bound to and the manifest digest that is actually recorded —
/// never a digest copied out of the lease it is refusing.
fn effect_reconciliation_item(
    kind: KernelReconciliationKind,
    request: &EffectReplayRequest,
    lease: Option<&EffectOperationLease>,
    recorded_manifest_sha256: Option<String>,
) -> KernelReconciliationItem {
    KernelReconciliationItem {
        kind,
        module_id: request.manifest_module_id.clone(),
        generation: request.manifest_generation,
        bound_manifest_sha256: Some(request.bound_manifest_sha256.clone()),
        recorded_manifest_sha256,
        lease_id: lease.map(|value| value.lease_id.clone()),
        operation_id: Some(request.operation_id.clone()),
        observed_at_ms: request.observed_at_ms,
    }
}

/// One store-side effect-replay query, carrying no caller-supplied effect
/// ceiling or route scope.
///
/// A dispatcher that holds an already-authorized effect holds no effect receipt
/// digest and no route scope of its own: the receipt and the scope belong to the
/// durable lease, and a query that had to carry them would let a caller confirm
/// a lease against values it copied out of that same lease. This query therefore
/// names only what the caller genuinely observes — the exact operation it is
/// replaying, its own module and generation binding, the recorded manifest
/// digest it loaded, its current authority view and the observation time — and
/// [`authorize_effect_operation_lease_replay`] takes the receipt and the scope
/// from the lease alone.
///
/// Every field is required and none defaults: the type derives `Deserialize`
/// under `deny_unknown_fields` with no `#[serde(default)]`, and
/// `validate` refuses a blank identity, a malformed digest, a zero Catalog or
/// Policy revision and a non-positive clock. A source that cannot state one of
/// these values must therefore fail the call rather than report a fresh-looking
/// one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOperationLeaseReplayQuery {
    /// The exact operation identity the caller is replaying, as it states it —
    /// never a copy of the lease's own field, so a lease that authorizes a
    /// different operation is refused instead of self-confirming.
    pub replayed_operation_id: OperationIdentity,
    /// The caller's own authenticated owner binding for the affected generation.
    pub module_id: String,
    /// The caller's own generation binding.
    pub generation: ResourceGeneration,
    /// The manifest digest the caller read back for its own module and
    /// generation. It is cross-checked against the lease's recorded digest and
    /// against the loaded manifest's own digest, so it must be the ORS manifest
    /// readback rather than a value the lease supplied.
    pub bound_manifest_sha256: String,
    /// The caller's current Authority Epoch, Catalog/Policy revisions and view,
    /// revocation state and delivery state.
    ///
    /// The revocation and delivery values are the acknowledgements the caller's
    /// own durable revocation-event and delivery rows record for this lease
    /// identity, never a constant and never a copy of the lease's own fields.
    pub current: EffectAuthorizationView,
    /// Observation time of the decision in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl EffectOperationLeaseReplayQuery {
    /// Validates the query's own identities, digest, view and clock.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.replayed_operation_id.as_str(),
            "effect_operation_lease_replay_query_replayed_operation_id",
        )?;
        validate_text(
            &self.module_id,
            "effect_operation_lease_replay_query_module_id",
        )?;
        validate_digest(
            &self.bound_manifest_sha256,
            "effect_operation_lease_replay_query_bound_manifest_sha256",
        )?;
        self.current.validate()?;
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_replay_query_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Classifies one effect-replay request against its durable operation lease.
///
/// One decision entry point over the durable lease, the recorded manifest, the
/// observed generation lifecycle observation and an explicit query. It is NOT the
/// entry point the effect dispatcher calls:
/// `RedbRecoveryStore::authorize_effect_replay_for_operation`
/// (`crates/kernel/eliot-ors/src/store.rs`) calls [`authorize_effect_replay`]
/// directly, so on this branch there are two public entry points and no caller of
/// this one. It exists so a store seam can pass the effect receipt and the route
/// scope explicitly instead of leaving them implicit; rewiring the store to it is
/// the remaining step.
///
/// It mutates no durable state, dispatches nothing, and delegates to
/// [`authorize_effect_replay`], the one classifier: every lease, manifest,
/// lifecycle, currency and liveness refusal listed on that function is produced
/// here unchanged, under the same [`KernelReconciliationKind`] or the same typed
/// [`OrsError`].
///
/// The difference from calling [`authorize_effect_replay`] directly is the
/// effect receipt and the route scope. This function has no such fields to
/// receive, so both come from the durable lease and are bounded by the recorded
/// manifest: a lease whose recorded scope is outside the manifest's own allowed
/// scopes, or whose recorded epoch is not the manifest's admitting epoch, is
/// refused. A caller cannot grant replay authority by naming a ceiling or a
/// scope it made up. The revocation and delivery values are the OBSERVED ones
/// the caller read back from its own durable revocation-event and delivery rows
/// for this lease identity; the lifecycle value is the OBSERVED composition the
/// caller derived from its own durable readbacks through
/// [`ObservedGenerationLifecycle::compose`] — composed, not read back as a row.
/// None of the three is taken from the lease under test.
///
/// `manifest` is the manifest row the caller read back for `query`'s own
/// `{module_id, generation}`, and `None` is refused as
/// [`KernelReconciliationKind::ManifestAbsent`] with the durable escalation
/// item, so a deleted or incompatible manifest cannot reach an effect. The
/// refusal is the shadow/no-effect authority, which carries no lease and can
/// produce no external effect and no canonical write admission; a caller that
/// wants that refusal persisted does so through its own reconciliation writer,
/// which is where the durable evidence belongs.
pub fn authorize_effect_operation_lease_replay(
    lease: &EffectOperationLease,
    manifest: Option<&KernelExecutionManifest>,
    generation_lifecycle: &ObservedGenerationLifecycle,
    query: &EffectOperationLeaseReplayQuery,
) -> Result<EffectReplayDecision, OrsError> {
    query.validate()?;
    authorize_effect_replay(
        Some(lease),
        manifest,
        generation_lifecycle,
        &EffectReplayRequest {
            operation_id: query.replayed_operation_id.clone(),
            manifest_module_id: query.module_id.clone(),
            manifest_generation: query.generation,
            bound_manifest_sha256: query.bound_manifest_sha256.clone(),
            // The caller observes no effect receipt and no route scope of its
            // own; these two remain the lease's recorded values, which is
            // exactly what the receipt and scope bindings are for. They are
            // cross-checked against the recorded manifest inside the classifier
            // rather than against this request.
            effect_receipt_sha256: lease.effect_receipt_sha256.clone(),
            allowed_scope: lease.allowed_scope.clone(),
            current: query.current,
            observed_at_ms: query.observed_at_ms,
        },
    )
}
