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
use crate::model::{OperationIdentity, OrsError, validate_digest, validate_text};

/// Durable schema version of the effect operation lease record (I1.9).
pub const EFFECT_OPERATION_LEASE_SCHEMA_VERSION: u16 = 1;

/// The Governor/Kernel-issued inputs that create one effect operation lease.
///
/// The manifest identity and digest are not inputs: `EffectOperationLease::issue`
/// copies them from the manifest so a lease can never name a different
/// execution manifest than the one it was admitted against.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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
    /// manifest (I1.9 line 52).
    pub catalog_revision: u64,
    /// Admitting Policy revision. Must be non-zero, and must equal the
    /// manifest's recorded admitting Policy revision, for the same reason.
    pub policy_revision: u64,
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
    /// Issuance is refused for a `read_rebuild` manifest, which is never effect
    /// capable, for a scope that is not one of the manifest's recorded
    /// allowed scopes, and for admitting Catalog/Policy revisions that differ
    /// from the manifest's recorded Governor-admitted revisions, so the
    /// Kernel side cannot mint a lease against revisions the Governor never
    /// admitted for this manifest (I1.9 line 52). The replay verifier
    /// independently requires the same agreement before any admission, so a
    /// lease issued here always carries revisions the gate can accept.
    pub fn issue(
        manifest: &KernelExecutionManifest,
        admission: EffectOperationLeaseAdmission,
    ) -> Result<Self, OrsError> {
        manifest.validate()?;
        if !manifest.restart_authorization_class().is_effect_capable() {
            return Err(OrsError::InvalidField {
                field: "effect_operation_lease_manifest_class",
                reason: "only an effect-capable manifest may admit an effect operation lease",
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
            revocation: RevocationAcknowledgement::None,
            delivery: EffectDeliveryAcknowledgement::Acknowledged,
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
    fn denied(
        kind: KernelReconciliationKind,
        request: &EffectReplayRequest,
        lease: Option<&EffectOperationLease>,
    ) -> Self {
        Self {
            authority: EffectDispatchAuthority::shadow_only(ShadowEffectDiagnostics::for_request(
                request,
            )),
            reconciliation: Some(effect_reconciliation_item(kind, request, lease)),
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
/// dispatching an effect. It mutates no durable state, dispatches nothing and
/// re-derives the current disposition of the lease it is given.
///
/// A replay is admitted only when all of the following hold, and each failure
/// returns the shadow/no-effect authority with a durable reconciliation item:
///
/// * the lease exists and satisfies its own shape;
/// * the recorded manifest exists, satisfies its own shape, carries a
///   Governor admission, and is effect capable;
/// * the lease's manifest identity and hash equal the recorded manifest's;
/// * the requested operation identity, effect receipt and route scope equal the
///   lease's exactly, so none of them can be changed or widened;
/// * the lease's Authority Epoch is the current one;
/// * the admitting Catalog and Policy revisions are the current ones and the
///   Module Catalog/Policy view is current;
/// * the lease is not revoked, has no unacknowledged revocation, and no
///   revocation is outstanding in the current view;
/// * no delivery gap is open, on the lease or in the current view;
/// * the lease is active and is not expired at `request.observed_at_ms`.
///
/// The request side of each comparison is the caller's own observation, never a
/// copy of the lease's fields. A caller that presents a well-formed lease for a
/// *different* operation, module, generation or manifest therefore fails the
/// matching content check instead of confirming the lease against itself.
///
/// An operation with no lease — that is, any new operation — is denied, which
/// is what stops an effect-capable generation from resuming a new operation
/// after catalog/policy freshness is lost.
pub fn authorize_effect_replay(
    lease: Option<&EffectOperationLease>,
    manifest: Option<&KernelExecutionManifest>,
    request: &EffectReplayRequest,
) -> Result<EffectReplayDecision, OrsError> {
    request.validate()?;
    let Some(lease) = lease else {
        return Ok(EffectReplayDecision::denied(
            KernelReconciliationKind::EffectLeaseAbsent,
            request,
            None,
        ));
    };
    if let Some(kind) = classify_effect_replay(lease, manifest, request) {
        return Ok(EffectReplayDecision::denied(kind, request, Some(lease)));
    }
    Ok(EffectReplayDecision::admitted(
        ActiveEffectOperationLease::verified(lease.clone()),
    ))
}

/// Returns the first blocking defect, or `None` when the replay is admitted.
fn classify_effect_replay(
    lease: &EffectOperationLease,
    manifest: Option<&KernelExecutionManifest>,
    request: &EffectReplayRequest,
) -> Option<KernelReconciliationKind> {
    if lease.validate().is_err() {
        return Some(KernelReconciliationKind::EffectLeaseInvalid);
    }
    let Some(manifest) = manifest else {
        return Some(KernelReconciliationKind::ManifestAbsent);
    };
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
    if lease.authority_epoch != request.current.authority_epoch {
        return Some(KernelReconciliationKind::EffectEpochMismatch);
    }
    let catalog_current = request.current.catalog_view == CatalogPolicyView::Current
        && request.current.catalog_revision == lease.catalog_revision
        && request.current.policy_revision == lease.policy_revision;
    if !catalog_current {
        return Some(KernelReconciliationKind::EffectCatalogPolicyStale);
    }
    if lease.revocation == RevocationAcknowledgement::Acknowledged
        || request.current.revocation == RevocationAcknowledgement::Acknowledged
    {
        return Some(KernelReconciliationKind::EffectLeaseRevoked);
    }
    if lease.revocation == RevocationAcknowledgement::Unacknowledged
        || request.current.revocation == RevocationAcknowledgement::Unacknowledged
    {
        return Some(KernelReconciliationKind::EffectLeaseRevocationUnacknowledged);
    }
    if lease.delivery == EffectDeliveryAcknowledgement::GapOpen
        || request.current.delivery == EffectDeliveryAcknowledgement::GapOpen
    {
        return Some(KernelReconciliationKind::EffectDeliveryGapOpen);
    }
    if request.observed_at_ms >= lease.expires_at_ms || lease.state == LeaseState::Expired {
        return Some(KernelReconciliationKind::EffectLeaseExpired);
    }
    match lease.state {
        LeaseState::Active | LeaseState::Expiring => None,
        _ => Some(KernelReconciliationKind::EffectLeaseNotActive),
    }
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
fn effect_reconciliation_item(
    kind: KernelReconciliationKind,
    request: &EffectReplayRequest,
    lease: Option<&EffectOperationLease>,
) -> KernelReconciliationItem {
    KernelReconciliationItem {
        kind,
        module_id: request.manifest_module_id.clone(),
        generation: request.manifest_generation,
        bound_manifest_sha256: Some(request.bound_manifest_sha256.clone()),
        recorded_manifest_sha256: lease.map(|value| value.bound_manifest_sha256.clone()),
        lease_id: lease.map(|value| value.lease_id.clone()),
        operation_id: Some(request.operation_id.clone()),
        observed_at_ms: request.observed_at_ms,
    }
}
