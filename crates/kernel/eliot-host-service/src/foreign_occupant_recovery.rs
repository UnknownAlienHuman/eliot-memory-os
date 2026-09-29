//! Typed foreign-occupant collision recovery (issue #1775).
//!
//! Implementation `I3.3` requires that an existing `SurrealDB` process which
//! merely occupies the planned endpoint stays an observation or import
//! candidate and never becomes an implicit member of the ELIOT store lineage:
//! "Setup never kills, adopts or reuses an unrelated process merely because its
//! port or binary name matches." `I3.4` fixes the vocabulary implemented here —
//! the classified origin is a typed field, "the same ambiguous origin may permit
//! read-only status, choose an alternate launch port and still forbid
//! shutdown/mutation", and an ownership claim is usable only when bound to one
//! admitted operation. `I7.20` requires the bounded recovery answer to name the
//! disposition, the exact missing evidence and a safe next action with
//! role-filtered references.
//!
//! This module owns that typed answer and its construction. It mints no
//! authority, opens no connection and performs no effect. The read-only half
//! and the destructive half of the operation space are separate types with no
//! conversion between them, and [`ForeignOccupantRecoveryDirective::admit`] is
//! the single conversion from a requested operation to a collision answer, so
//! a read-only observation has no path to a destructive request.

use eliot_platform::{PlatformHandle, ServiceObservation};
use eliot_runtime_contracts::ServiceProcessRecord;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// The complete ordered operation set this contract classifies.
///
/// Completeness is always checked against this list and never against a
/// caller-supplied one, so a directive that omits or invents an operation class
/// cannot validate.
const ALL_REQUESTED_OPERATIONS: [RequestedProcessOperation; 10] = [
    RequestedProcessOperation::ReadOnlyStatus,
    RequestedProcessOperation::ProbeObserve,
    RequestedProcessOperation::ReadOnlyImportInspection,
    RequestedProcessOperation::SelectAlternateEndpoint,
    RequestedProcessOperation::Stop,
    RequestedProcessOperation::Adopt,
    RequestedProcessOperation::Mutate,
    RequestedProcessOperation::AttachCredential,
    RequestedProcessOperation::ReuseForeignListener,
    RequestedProcessOperation::AutomaticDataMigration,
];

/// The complete ownership-evidence set a destructive or adoption-grade class
/// would need before it could ever be admitted against an occupant
/// (`I3.4` `OwnershipChallengeReceipt`).
const ALL_OWNERSHIP_EVIDENCE: [OwnershipEvidenceClass; 7] = [
    OwnershipEvidenceClass::InstallationLineage,
    OwnershipEvidenceClass::PhysicalProcessIdentity,
    OwnershipEvidenceClass::CurrentEpochAndFence,
    OwnershipEvidenceClass::OriginObservation,
    OwnershipEvidenceClass::AdmittedOperationBinding,
    OwnershipEvidenceClass::IssuanceAndExpiry,
    OwnershipEvidenceClass::Invalidation,
];

/// Upper bound on role-filtered references carried by one directive.
const MAX_RECOVERY_REFERENCES: usize = 8;

/// What the platform owner positively observed about managed-tree membership.
///
/// This is the only input that can move [`CollisionOriginClass`] off
/// [`CollisionOriginClass::Unknown`]. A name, port, PID file, image
/// resemblance or endpoint answer is not membership, so a caller with no such
/// observation passes [`Self::Unavailable`] and the origin stays unknown.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManagedTreeObservation {
    /// The owner positively placed the process inside this installation's
    /// managed tree.
    InsideManagedTree,
    /// The owner observed only shared runtime membership, which is never
    /// exclusive ownership.
    SharedSubstrate,
    /// The owner positively placed the process outside the managed tree and
    /// outside the shared substrate.
    OutsideManagedTree,
    /// No managed-tree observation was available. Inability to read process
    /// state is not absence of a collision and is never read as membership.
    Unavailable,
}

/// Classified origin of an observed process (`I3.4`
/// `ProcessOriginEvidence.origin`).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollisionOriginClass {
    /// Proven inside this installation's managed tree.
    InsideManagedTree,
    /// Proven to be shared runtime membership only.
    SharedSubstrate,
    /// Proven outside the managed tree and the shared substrate.
    Elsewhere,
    /// Unclassified. The observation established neither membership nor
    /// exclusion, and this never authorizes a destructive class.
    Unknown,
}

impl fmt::Display for CollisionOriginClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InsideManagedTree => "INSIDE_MANAGED_TREE",
            Self::SharedSubstrate => "SHARED_SUBSTRATE",
            Self::Elsewhere => "ELSEWHERE",
            Self::Unknown => "UNKNOWN",
        })
    }
}

impl ManagedTreeObservation {
    /// Maps a managed-tree observation onto the classified origin.
    ///
    /// Absent evidence maps to [`CollisionOriginClass::Unknown`]; it is never
    /// read as [`CollisionOriginClass::Elsewhere`].
    const fn classified_origin(self) -> CollisionOriginClass {
        match self {
            Self::InsideManagedTree => CollisionOriginClass::InsideManagedTree,
            Self::SharedSubstrate => CollisionOriginClass::SharedSubstrate,
            Self::OutsideManagedTree => CollisionOriginClass::Elsewhere,
            Self::Unavailable => CollisionOriginClass::Unknown,
        }
    }
}

/// The single admitted operation a collision proof is bound to.
///
/// `I3.4` binds an ownership claim to one operation class. Recording the
/// admitted operation is what keeps a proof obtained for one class from being
/// read as permission for another, and it decides which read-only alternatives
/// remain meaningful for this occupant.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmittedCollisionOperation {
    /// Fresh start of an independent Host-managed dependency.
    FreshDependencyStart,
    /// Reconnect to a dependency this installation already owns.
    OwnedReconnect,
    /// Stop or cancel of an admitted managed child.
    StopOrCancel,
    /// Mutation of an admitted managed child.
    Mutation,
    /// Explicit adoption or import of a foreign occupant.
    AdoptionOrImport,
    /// Attachment of a reusable credential to a managed child.
    CredentialAttachment,
    /// Read-only diagnostics.
    ReadOnlyDiagnostics,
}

/// One operation class a caller may name against an observed occupant.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestedProcessOperation {
    /// Read-only status answer.
    ReadOnlyStatus,
    /// Neutral observation probe.
    ProbeObserve,
    /// Explicit read-only inspection of a foreign occupant's existing data.
    ReadOnlyImportInspection,
    /// Selection of a separately admitted alternate endpoint.
    SelectAlternateEndpoint,
    /// Stop the occupant.
    Stop,
    /// Adopt the occupant into managed lineage.
    Adopt,
    /// Mutate the occupant.
    Mutate,
    /// Attach a reusable credential to the occupant.
    AttachCredential,
    /// Reuse the occupant's existing listener or connection.
    ReuseForeignListener,
    /// Move the occupant's data into the ELIOT store lineage.
    AutomaticDataMigration,
}

/// The read-only operations a collision may still permit.
///
/// This type has no destructive variant, and there is no `From`, `Into` or
/// `TryFrom` between it and [`BlockedRecoveryOperation`]. A read-only
/// classification therefore has no representation as a stop, adopt, mutate,
/// credential-attachment, listener-reuse or data-migration request.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermittedRecoveryOperation {
    /// Read-only status answer about the exact observed occupant.
    ReadOnlyStatus,
    /// Neutral observation probe of the exact observed occupant.
    ReadOnlyProcessOriginProbe,
    /// Explicit, separately admitted read-only inspection of legacy data.
    ExplicitReadOnlyImportInspection,
    /// Selection of a separately admitted alternate endpoint.
    SeparatelyAdmittedAlternateEndpoint,
}

/// The operations a foreign-occupant collision blocks.
///
/// This is the destructive half only, disjoint from
/// [`PermittedRecoveryOperation`] by construction.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockedRecoveryOperation {
    /// Stop the occupant.
    Stop,
    /// Adopt the occupant.
    Adopt,
    /// Mutate the occupant.
    Mutate,
    /// Attach a reusable credential to the occupant.
    AttachCredential,
    /// Reuse the occupant's listener or connection.
    ReuseForeignListener,
    /// Move the occupant's data into the ELIOT store lineage.
    AutomaticDataMigration,
}

/// Which half of the operation space one requested class falls in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollisionOperationClass {
    ReadOnly(PermittedRecoveryOperation),
    Destructive(BlockedRecoveryOperation),
}

/// Ownership evidence an ownership claim must bind before a destructive or
/// adoption-grade class could ever be admitted.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnershipEvidenceClass {
    /// Installation and managed-generation lineage.
    InstallationLineage,
    /// Exact physical process identity: PID plus start identity, image and Job.
    PhysicalProcessIdentity,
    /// Current authority epoch and state fence.
    CurrentEpochAndFence,
    /// Neutral origin observation verified against the authoritative owner.
    OriginObservation,
    /// Binding to this one admitted operation.
    AdmittedOperationBinding,
    /// Issuance time and expiry of the challenge or owner token.
    IssuanceAndExpiry,
    /// Invalidation state of the issued proof.
    Invalidation,
}

/// The single safe next step for a foreign-occupant collision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafeNextAction {
    /// Inspect the exact observed occupant read-only.
    InspectOnly,
    /// Wait for the admitted operation's own ownership proof.
    AwaitOwnershipChallenge,
    /// Select a separately admitted alternate endpoint.
    RequestSeparatelyAdmittedAlternateEndpoint,
}

/// The role a reference may be disclosed to.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryReferenceRole {
    /// The installation-owned planned identity that is occupied.
    Installer,
    /// The neutral observation the platform owner produced.
    PlatformObserver,
}

/// One reference carried by a directive, with the role it may be disclosed to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleFilteredReference {
    /// Role this reference may be disclosed to.
    pub role: RecoveryReferenceRole,
    /// Exact reference for that role.
    pub handle: PlatformHandle,
}

/// Why one requested operation class is not admitted for this occupant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollisionRefusal {
    /// The class is read-only but is not a meaningful alternative for the
    /// recorded admitted operation. This names a read-only class only: it is
    /// never reported as, and never convertible into, a destructive block.
    ReadOnlyAlternativeUnavailable {
        /// The read-only class that was asked for.
        requested: RequestedProcessOperation,
    },
    /// A destructive or adoption-grade class is blocked, and every
    /// ownership-evidence class still unproven for this occupant is named. A
    /// proof obtained for one class never reaches another.
    OwnershipEvidenceMissing {
        /// The blocked class.
        operation: BlockedRecoveryOperation,
        /// Ownership-evidence classes still unproven for this occupant.
        missing: Vec<OwnershipEvidenceClass>,
    },
}

/// Typed disposition of one requested operation class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollisionOperationDisposition {
    /// A read-only operation answer. Carries no control capability.
    Permitted(PermittedRecoveryOperation),
    /// The class is not admitted, with its exact typed reason.
    Refused(CollisionRefusal),
}

/// Failure while assembling or checking a collision directive.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ForeignOccupantRecoveryError {
    /// A directive field did not match the complete independent expected set,
    /// or a reference was unusable, blank, over-bound or repeated.
    #[error("collision recovery directive is not valid: {0}")]
    InvalidDirective(&'static str),
}

/// Typed bounded recovery answer for one observed foreign occupant.
///
/// This is the structured `I3.3` / `I7.20` replacement for a free-form recovery
/// string: the admitted operation, the classified origin, the precise permitted
/// and blocked operations, the exact missing ownership evidence, one safe next
/// action and role-filtered references are each a named typed field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignOccupantRecoveryDirective {
    /// The single admitted operation this answer is bound to.
    pub admitted_operation: AdmittedCollisionOperation,
    /// What the neutral observation proved about the occupant's origin.
    pub classified_origin: CollisionOriginClass,
    /// Read-only operations still permitted against this occupant.
    pub permitted: Vec<PermittedRecoveryOperation>,
    /// Destructive and adoption-grade operations blocked for this occupant.
    pub blocked: Vec<BlockedRecoveryOperation>,
    /// Every ownership-evidence class still unproven for this occupant.
    pub missing_ownership_evidence: Vec<OwnershipEvidenceClass>,
    /// The one safe next step.
    pub next_action: SafeNextAction,
    /// References, each with the role it may be disclosed to.
    pub references: Vec<RoleFilteredReference>,
}

impl fmt::Display for ForeignOccupantRecoveryDirective {
    /// A bounded, non-sensitive summary: the classified origin, the admitted
    /// operation and the safe next action. References, endpoints and process
    /// identities stay in the typed fields, never in an error string.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "origin={} admitted_operation={:?} blocked={} missing_evidence={} next_action={:?}",
            self.classified_origin,
            self.admitted_operation,
            self.blocked.len(),
            self.missing_ownership_evidence.len(),
            self.next_action
        )
    }
}

impl ForeignOccupantRecoveryDirective {
    /// Builds the directive for a neutral observation of an occupant that holds
    /// the installation-planned identity.
    ///
    /// The admitted operation is bound first, `permitted` and `blocked` are
    /// derived by folding the complete independent operation set through
    /// [`Self::admit`] rather than by accepting a caller-supplied list, and the
    /// classified origin comes from the caller's managed-tree observation, which
    /// is absent in the general case. No effect is performed and no authority
    /// is minted.
    ///
    /// # Errors
    ///
    /// Returns [`ForeignOccupantRecoveryError::InvalidDirective`] when an
    /// observed reference is not a usable handle.
    pub fn for_observed_occupant(
        admitted_operation: AdmittedCollisionOperation,
        planned_identity: &PlatformHandle,
        observed: &ServiceObservation,
        managed_tree: ManagedTreeObservation,
    ) -> Result<Self, ForeignOccupantRecoveryError> {
        let classified_origin = managed_tree.classified_origin();
        let next_action = safe_next_action(classified_origin);
        let missing_ownership_evidence = unproven_ownership_evidence();
        let references = recovery_references(planned_identity, observed.process.as_ref())?;

        let skeleton = Self {
            admitted_operation,
            classified_origin,
            permitted: Vec::new(),
            blocked: Vec::new(),
            missing_ownership_evidence,
            next_action,
            references,
        };

        let mut permitted = Vec::new();
        let mut blocked = Vec::new();
        for requested in ALL_REQUESTED_OPERATIONS {
            match skeleton.admit(requested) {
                CollisionOperationDisposition::Permitted(operation) => permitted.push(operation),
                CollisionOperationDisposition::Refused(
                    CollisionRefusal::OwnershipEvidenceMissing { operation, .. },
                ) => blocked.push(operation),
                CollisionOperationDisposition::Refused(
                    CollisionRefusal::ReadOnlyAlternativeUnavailable { .. },
                ) => {
                    // A read-only class that is not a meaningful alternative for
                    // the admitted operation belongs in neither set.
                }
            }
        }

        let directive = Self {
            permitted,
            blocked,
            ..skeleton
        };
        directive.validate()?;
        Ok(directive)
    }

    /// Classifies one requested operation class against this directive.
    ///
    /// This is the only conversion from a requested operation to a collision
    /// answer. A read-only class terminates in
    /// [`CollisionOperationDisposition::Permitted`] carrying a
    /// [`PermittedRecoveryOperation`], or in
    /// [`CollisionRefusal::ReadOnlyAlternativeUnavailable`], which also names a
    /// read-only class. A destructive class always terminates in
    /// [`CollisionRefusal::OwnershipEvidenceMissing`]. Neither read-only arm can
    /// produce a [`BlockedRecoveryOperation`], so a read-only status answer
    /// cannot become a Kill request here or anywhere downstream.
    #[must_use]
    pub fn admit(&self, requested: RequestedProcessOperation) -> CollisionOperationDisposition {
        match operation_class(requested) {
            CollisionOperationClass::ReadOnly(operation)
                if permitted_for(self.admitted_operation, requested) =>
            {
                CollisionOperationDisposition::Permitted(operation)
            }
            CollisionOperationClass::ReadOnly(_) => CollisionOperationDisposition::Refused(
                CollisionRefusal::ReadOnlyAlternativeUnavailable { requested },
            ),
            CollisionOperationClass::Destructive(operation) => {
                CollisionOperationDisposition::Refused(CollisionRefusal::OwnershipEvidenceMissing {
                    operation,
                    missing: self.missing_ownership_evidence.clone(),
                })
            }
        }
    }

    /// Returns the references this directive may disclose to `role`.
    pub fn references_for(
        &self,
        role: RecoveryReferenceRole,
    ) -> impl Iterator<Item = &RoleFilteredReference> {
        self.references
            .iter()
            .filter(move |reference| reference.role == role)
    }

    /// Checks the directive against the complete independent expected sets.
    ///
    /// `permitted` and `blocked` are compared against what folding
    /// [`ALL_REQUESTED_OPERATIONS`] produces for the recorded admitted
    /// operation, and `missing_ownership_evidence` against
    /// [`ALL_OWNERSHIP_EVIDENCE`], so a partial or invented set cannot be
    /// presented as a complete one.
    ///
    /// # Errors
    ///
    /// Returns [`ForeignOccupantRecoveryError::InvalidDirective`] when a set is
    /// incomplete, over-complete or reordered, or when the references are
    /// absent, over-bound, blank or repeated within one role.
    pub fn validate(&self) -> Result<(), ForeignOccupantRecoveryError> {
        if self.permitted != expected_permitted(self.admitted_operation) {
            return Err(ForeignOccupantRecoveryError::InvalidDirective(
                "permitted operation set is not the complete expected set",
            ));
        }
        if self.blocked != expected_blocked() {
            return Err(ForeignOccupantRecoveryError::InvalidDirective(
                "blocked operation set is not the complete expected set",
            ));
        }
        if self.missing_ownership_evidence != ALL_OWNERSHIP_EVIDENCE {
            return Err(ForeignOccupantRecoveryError::InvalidDirective(
                "missing ownership evidence is not the complete expected set",
            ));
        }
        if self.references.is_empty() || self.references.len() > MAX_RECOVERY_REFERENCES {
            return Err(ForeignOccupantRecoveryError::InvalidDirective(
                "reference count is out of bounds",
            ));
        }
        if self
            .references_for(RecoveryReferenceRole::Installer)
            .next()
            .is_none()
        {
            return Err(ForeignOccupantRecoveryError::InvalidDirective(
                "the installation-owned occupied identity is not referenced",
            ));
        }
        for (index, reference) in self.references.iter().enumerate() {
            if reference.handle.as_str().trim().is_empty() {
                return Err(ForeignOccupantRecoveryError::InvalidDirective(
                    "reference handle is blank",
                ));
            }
            if self.references[..index]
                .iter()
                .any(|earlier| earlier.role == reference.role && earlier.handle == reference.handle)
            {
                return Err(ForeignOccupantRecoveryError::InvalidDirective(
                    "reference is repeated within one role",
                ));
            }
        }
        Ok(())
    }
}

/// Classifies one requested class into its half of the operation space.
///
/// The read-only arms terminate in [`CollisionOperationClass::ReadOnly`]
/// carrying a [`PermittedRecoveryOperation`]. There is deliberately no arm that
/// reaches [`CollisionOperationClass::Destructive`] from a read-only request,
/// and [`PermittedRecoveryOperation`] has no destructive variant, so a read-only
/// status answer has no representation as a stop, adopt, mutate,
/// credential-attachment, listener-reuse or data-migration request.
const fn operation_class(requested: RequestedProcessOperation) -> CollisionOperationClass {
    match requested {
        RequestedProcessOperation::ReadOnlyStatus => {
            CollisionOperationClass::ReadOnly(PermittedRecoveryOperation::ReadOnlyStatus)
        }
        RequestedProcessOperation::ProbeObserve => CollisionOperationClass::ReadOnly(
            PermittedRecoveryOperation::ReadOnlyProcessOriginProbe,
        ),
        RequestedProcessOperation::ReadOnlyImportInspection => CollisionOperationClass::ReadOnly(
            PermittedRecoveryOperation::ExplicitReadOnlyImportInspection,
        ),
        RequestedProcessOperation::SelectAlternateEndpoint => CollisionOperationClass::ReadOnly(
            PermittedRecoveryOperation::SeparatelyAdmittedAlternateEndpoint,
        ),
        RequestedProcessOperation::Stop => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::Stop)
        }
        RequestedProcessOperation::Adopt => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::Adopt)
        }
        RequestedProcessOperation::Mutate => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::Mutate)
        }
        RequestedProcessOperation::AttachCredential => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::AttachCredential)
        }
        RequestedProcessOperation::ReuseForeignListener => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::ReuseForeignListener)
        }
        RequestedProcessOperation::AutomaticDataMigration => {
            CollisionOperationClass::Destructive(BlockedRecoveryOperation::AutomaticDataMigration)
        }
    }
}

/// Decides whether a read-only class stays permitted for one admitted
/// operation.
///
/// Status and neutral probing answer the same ambiguous origin without acting
/// on it, so they remain permitted for every admitted operation. Read-only
/// import inspection and alternate-endpoint selection are only meaningful where
/// the admitted operation would otherwise have used the occupied endpoint.
const fn permitted_for(
    admitted_operation: AdmittedCollisionOperation,
    requested: RequestedProcessOperation,
) -> bool {
    match requested {
        RequestedProcessOperation::ReadOnlyStatus | RequestedProcessOperation::ProbeObserve => true,
        RequestedProcessOperation::ReadOnlyImportInspection
        | RequestedProcessOperation::SelectAlternateEndpoint => matches!(
            admitted_operation,
            AdmittedCollisionOperation::FreshDependencyStart
                | AdmittedCollisionOperation::OwnedReconnect
                | AdmittedCollisionOperation::CredentialAttachment
        ),
        RequestedProcessOperation::Stop
        | RequestedProcessOperation::Adopt
        | RequestedProcessOperation::Mutate
        | RequestedProcessOperation::AttachCredential
        | RequestedProcessOperation::ReuseForeignListener
        | RequestedProcessOperation::AutomaticDataMigration => false,
    }
}

/// Folds the complete independent operation set into the expected permitted set
/// for one admitted operation.
fn expected_permitted(
    admitted_operation: AdmittedCollisionOperation,
) -> Vec<PermittedRecoveryOperation> {
    ALL_REQUESTED_OPERATIONS
        .into_iter()
        .filter_map(|requested| match operation_class(requested) {
            CollisionOperationClass::ReadOnly(operation)
                if permitted_for(admitted_operation, requested) =>
            {
                Some(operation)
            }
            _ => None,
        })
        .collect()
}

/// Folds the complete independent operation set into the expected blocked set.
///
/// The blocked set is a fact about the occupant, not about the request: a
/// foreign occupant is never stopped, adopted, mutated, credentialed, reused or
/// migrated on the strength of this observation, whatever the caller asked for.
fn expected_blocked() -> Vec<BlockedRecoveryOperation> {
    ALL_REQUESTED_OPERATIONS
        .into_iter()
        .filter_map(|requested| match operation_class(requested) {
            CollisionOperationClass::Destructive(operation) => Some(operation),
            CollisionOperationClass::ReadOnly(_) => None,
        })
        .collect()
}

/// Names the one safe next step for a classified origin.
///
/// A positively classified foreign occupant is only ever inspected or replaced
/// by a separately admitted endpoint; an unclassified one waits for the admitted
/// operation's own ownership proof. Neither step is a destructive control.
const fn safe_next_action(classified_origin: CollisionOriginClass) -> SafeNextAction {
    match classified_origin {
        CollisionOriginClass::InsideManagedTree => SafeNextAction::AwaitOwnershipChallenge,
        CollisionOriginClass::SharedSubstrate
        | CollisionOriginClass::Elsewhere
        | CollisionOriginClass::Unknown => SafeNextAction::InspectOnly,
    }
}

/// Names the ownership evidence this observation could not establish.
///
/// `ServiceProcessRecord` carries a lineage label and an authority epoch but no
/// process start identity, no image digest, no Job identity and no
/// installation/HostState lineage, and this seam holds no issued challenge
/// record, so every class in the independent expected set is unproven here.
fn unproven_ownership_evidence() -> Vec<OwnershipEvidenceClass> {
    ALL_OWNERSHIP_EVIDENCE.to_vec()
}

/// Builds the role-filtered references for one collision.
fn recovery_references(
    planned_identity: &PlatformHandle,
    observed_process: Option<&ServiceProcessRecord>,
) -> Result<Vec<RoleFilteredReference>, ForeignOccupantRecoveryError> {
    let mut references = vec![RoleFilteredReference {
        role: RecoveryReferenceRole::Installer,
        handle: planned_identity.clone(),
    }];
    if let Some(process) = observed_process {
        references.push(RoleFilteredReference {
            role: RecoveryReferenceRole::PlatformObserver,
            handle: PlatformHandle::new(process.process_id.clone()).map_err(|_error| {
                ForeignOccupantRecoveryError::InvalidDirective("observed process lineage")
            })?,
        });
    }
    Ok(references)
}
