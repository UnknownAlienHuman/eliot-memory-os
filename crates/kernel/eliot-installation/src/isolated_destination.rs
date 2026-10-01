//! Admission, allocation and durable evidence for a **new, distinct, isolated
//! destination installation** that is prepared but **not yet activated**
//! (issue #958, A2).
//!
//! Normative basis: I5.13 `restore to isolated root;` and A13.7 `Restore occurs
//! in an isolated area and verifies: schema and format compatibility; ...`,
//! plus the issue clause `Allocate a new distinct isolated installation through
//! existing installation authority and exact protected-root leases, binding
//! source/archive/class/operation/current purge/target schema and proposed
//! restoration requirements. A client-supplied arbitrary path, active/source
//! installation or preexisting foreign owner is rejected.`
//!
//! # Why this is not an `ApprovedGeneration`
//!
//! Every row in [`ApprovedGenerationRegistry::generations`] is an *approved*
//! generation and carries an [`InstallationActivationApproval`], whose only
//! constructor is `pub(crate)` and whose production issuer is the signed
//! activation bridge — the **activation** boundary. It additionally requires a
//! live exclusive installer `HostOwnerEpochCapability` and a stopped SCM
//! contour. Writing such a row during preparation would therefore (a) fabricate
//! owner material this crate forbids forging, and (b) perform an activation,
//! which the same issue forbids ("no automatic source stop", "A later
//! dedicated cutover child alone activates/retire installations"). The crate had
//! no representation at all for "allocated but not approved", so this module
//! adds exactly that representation —
//! [`PreparedDestinationAdmission`] — and the public CAS seam
//! [`RedbInstallationRegistry::record_prepared_isolated_destination`] that
//! inserts it. It is deliberately NOT a second installation representation: it
//! is a bounded, operation-keyed admission record inside the same registry
//! projection, carrying no generation, no approval and no activation authority.
//!
//! # Order: validation before effects
//!
//! [`admit_prepared_isolated_destination`] is pure. It performs no filesystem
//! mutation, opens no registry and issues no lease: it reads the retained
//! [`ProtectedRootLease`] the caller already holds, checks every bound record,
//! and returns either a typed refusal or the exact allocation the installation
//! authority will materialise. Only a caller holding that allocation may then
//! ask the registry to record it, and the registry compares the record it stores
//! against the SAME operation, source, archive, class, purge revision, schema and
//! restoration requirements — existence alone is never acceptance.
//!
//! # The client-supplied path is not an input
//!
//! There is no path parameter. The destination root is *derived* from the
//! owner-declared isolated restore area ([`RuntimeStateRoots::isolated_restore_root`],
//! a sibling of `installations` one leaf below the profile root) joined with the
//! destination installation identity the owner-issued authenticated request
//! identity carries ([`PreparedDestinationFacts::issue_for_admitted_identity`]).
//! A caller
//! cannot present a path, so a client-supplied arbitrary path is refused by
//! construction rather than by a comparison: an installation identity that is not
//! the 64-hex owner installation key format is refused as
//! [`IsolatedDestinationRefusal::ArbitraryDestination`], and an identity equal to
//! the owner-issued source is refused as
//! [`IsolatedDestinationRefusal::SourceInstallationDestination`].
//!
//! # What proves ownership, not naming
//!
//! [`IsolationEvidence`] records what the owner OBSERVED, not what a name
//! suggests: the canonical path resolved from the retained no-follow lease, the
//! lease's own stable file identity, the owner's declaration that the destination
//! leaf did not exist at admission time, and the exact source roots and
//! installation root it is compared against. A predictable name is never
//! ownership, and `IsolationEvidence::validate` re-derives its own digest and
//! compares it, so a hand-written or stale evidence row cannot pass.
//!
//! # The destination is actually created, and the record proves it
//!
//! Admission is pure, so on its own it leaves an admitted-but-absent root.
//! [`materialise_prepared_isolated_destination`] is the effect step: it creates
//! the root through the installation authority's own create-new owned-directory
//! publication, under the retained [`ProtectedRootLease`] the admission was
//! proved against, and returns a [`PreparedDestinationMaterialisation`] that
//! carries the created object's own observed `FileIdentity` and the
//! `admission_digest` of the admission it realises. That second record is what
//! makes "the recorded admission" and "the created root" the same fact rather
//! than two facts a reader has to correlate, and it is stored beside the
//! admission in the same registry projection.

use std::collections::BTreeSet;

use eliot_platform_windows::{
    DirectoryPublicationError, DirectoryPublicationOutcome, OwnedDirectoryPublication,
    ProtectedRootLease,
};
use eliot_protocol::backup::{BackupClassWire, BackupError, BackupRequestIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    CandidateManifest, FileIdentity, InstallationActivationApproval, InstallationError,
    InstallationHostRootClass, PlatformHandle, RuntimeStateRoots, canonical_json_bytes,
    classify_installation_host_root, handle, joined_windows_path, sha256_handle, sha256_hex, text,
    valid_installation_key,
};

/// Durable wire discriminator of one prepared, unactivated destination
/// admission record.
pub const PREPARED_DESTINATION_ADMISSION_WIRE: &str =
    "eliot.installation.prepared-destination-admission.v1";

/// Domain separator of the [`IsolationEvidence`] content digest.
const ISOLATION_EVIDENCE_DOMAIN: &str = "eliot.installation.isolation-evidence.v1";

/// Domain separator of the [`PreparedDestinationAdmission`] binding digest.
const PREPARED_DESTINATION_ADMISSION_DOMAIN: &str =
    "eliot.installation.prepared-destination-admission-binding.v1";

/// Refusal classes of the prepared-destination admission.
///
/// Every variant is a decision the installation authority reached from its own
/// records. There is deliberately no "unknown"/"maybe" arm: an unproved
/// destination is a refusal, never a pass.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IsolatedDestinationRefusal {
    /// The destination identity is not an owner installation key, so no root
    /// can be derived for it inside the owner-declared isolated area.
    ///
    /// This is the client-supplied arbitrary path axis: a caller that presents
    /// free text, a relative path or a path at all cannot reach this seam,
    /// because the seam derives the root. A destination identity that merely
    /// *looks* like a path is refused here rather than being used as one.
    #[error(
        "the destination identity is not an owner installation key, so no root can be derived \
         inside the owner-declared isolated restore area"
    )]
    ArbitraryDestination,

    /// The destination is the source installation itself.
    #[error("the destination is the source installation and is never a restore destination")]
    SourceInstallationDestination,

    /// The destination is nested inside, or contains, the source installation
    /// root, so it is not isolated from the installation being captured.
    #[error("the destination root is not isolated from the source installation root")]
    DestinationOverlapsSource,

    /// The destination is a generation this installation authority already
    /// knows about, so it is an active or previously admitted installation
    /// rather than a new distinct one.
    #[error("the destination installation is already present in this authority's projection")]
    ExistingInstallation,

    /// A path this operation would write into is already a foreign owner's
    /// installation contour, so this operation does not own it.
    ///
    /// This is the "preexisting foreign owner is rejected" clause, decided by
    /// the owner rather than by a name. It fires wherever the owner-declared
    /// layout can be classified: the source's own Host root must BE an
    /// installation Host root (otherwise the source is a foreign directory and
    /// every isolation statement derived from it is a claim), and the isolated
    /// area and the derived destination leaf must NOT be inside any
    /// installation tree. A destination that a foreign installation already owns
    /// at that name is refused here, never reused, and never removed by name.
    #[error(
        "the destination is inside a foreign installation's own contour, so this operation does \
         not own it"
    )]
    ForeignInstallationOwner,

    /// The archive class may never be restored into an isolated installation.
    ///
    /// I5.13: `scope_export` is a `bounded ECXF transfer for one declared scope;
    /// not an installation backup`.
    #[error("the declared archive class is not an installation-backup class")]
    ClassNotRestorable,

    /// A bound owner-issued record names a different destination than the one
    /// under admission.
    #[error("bound owner record {field} does not name this destination")]
    BoundRecordConflict {
        /// Field of the owner record that disagreed.
        field: &'static str,
    },

    /// The owner-declared isolated restore area could not be resolved through
    /// the retained protected-root lease.
    #[error(
        "the owner-declared isolated restore area is not resolvable through its protected-root lease"
    )]
    IsolatedAreaUnproved,

    /// The destination leaf already existed at admission time, so the
    /// allocation is not a NEW distinct installation and this operation does
    /// not own it.
    #[error("the destination leaf already exists and is not owned by this operation")]
    DestinationNotAbsent,
}

/// Durable wire discriminator of one materialised destination root.
pub const PREPARED_DESTINATION_MATERIALISATION_WIRE: &str =
    "eliot.installation.prepared-destination-materialisation.v1";

/// Domain separator of the [`PreparedDestinationMaterialisation`] digest.
const MATERIALISATION_DOMAIN: &str =
    "eliot.installation.prepared-destination-materialisation-binding.v1";

/// Owner-observed proof that the ADMITTED destination root was actually
/// created, and that the object at the admitted name is the object this
/// operation created.
///
/// This is deliberately a SECOND durable record rather than a field of
/// [`IsolationEvidence`]. [`IsolationEvidence::evidence_digest`] is folded into
/// [`PreparedDestinationAdmission::admission_digest`], so folding a
/// post-creation observation into it would change the admission's own digest
/// between the admission write and the materialisation write and turn the
/// exact-replay path into a self-conflict. A separate record keeps the recorded
/// admission byte-identical while still binding the created root to it: this
/// record carries the admission's `admission_digest`, so the created root and
/// the recorded admission are the SAME fact rather than two facts a reader has
/// to correlate.
///
/// What it proves, and what it does not: it records the `FileIdentity` the
/// owner's own reparse-free protected-root lease OBSERVED for the created
/// root, the identity the same lease observed for the isolated area the
/// publication was made under, and the absence/reparse observations. A
/// predictable name proves nothing — a hand-written row naming a real foreign
/// directory fails [`Self::validate`] because the digest is recomputed over the
/// recorded content, and a reader that re-proves the root against
/// [`materialise_prepared_isolated_destination`] compares the lease's live
/// identity with the identity recorded HERE.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDestinationMaterialisation {
    /// Durable wire discriminator.
    pub wire: PlatformHandle,
    /// Operation identity this materialisation belongs to.
    pub operation_id: PlatformHandle,
    /// Destination installation identity.
    pub destination_installation: PlatformHandle,
    /// `admission_digest` of the ORIGINAL retained admission record this
    /// materialisation realises.
    ///
    /// This is a content binding, not a re-derivation: the reader compares it
    /// against the digest the retained admission actually carries, so a
    /// materialisation for a different or edited admission is refused.
    pub admission_digest: PlatformHandle,
    /// Canonical isolated area the publication was made under, as the
    /// publication owner's own retained handles resolved it.
    pub isolated_area_root: String,
    /// Identity the publication owner OBSERVED for the isolated area parent.
    ///
    /// It is compared against the `IsolationEvidence` area identity before
    /// anything is created, so the publication cannot land under a substituted
    /// area object.
    pub isolated_area_identity: FileIdentity,
    /// The owner-derived destination root that was created.
    pub destination_installation_root: String,
    /// Identity the owner's reparse-free lease observed for the created root.
    pub destination_root_identity: FileIdentity,
    /// Whether the owner's lease proved the created root reparse-free.
    pub destination_reparse_free: bool,
    /// Whether the owner observed the destination leaf absent immediately
    /// before the publication.
    pub destination_observed_absent: bool,
    /// SHA-256 over every field except this field.
    pub materialisation_digest: PlatformHandle,
}

impl PreparedDestinationMaterialisation {
    /// Current durable wire.
    pub const WIRE: &'static str = PREPARED_DESTINATION_MATERIALISATION_WIRE;

    /// Recomputes the domain-separated materialisation digest.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        Self::digest_over_fields(
            &self.wire,
            &self.operation_id,
            &self.destination_installation,
            &self.admission_digest,
            &self.isolated_area_root,
            &self.isolated_area_identity,
            &self.destination_installation_root,
            &self.destination_root_identity,
            self.destination_reparse_free,
            self.destination_observed_absent,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the digest covers exactly these fields, and the ISSUER needs them before the record exists"
    )]
    fn digest_over_fields(
        wire: &PlatformHandle,
        operation_id: &PlatformHandle,
        destination_installation: &PlatformHandle,
        admission_digest: &PlatformHandle,
        isolated_area_root: &str,
        isolated_area_identity: &FileIdentity,
        destination_installation_root: &str,
        destination_root_identity: &FileIdentity,
        destination_reparse_free: bool,
        destination_observed_absent: bool,
    ) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            MATERIALISATION_DOMAIN,
            wire.as_str(),
            operation_id.as_str(),
            destination_installation.as_str(),
            admission_digest.as_str(),
            isolated_area_root,
            isolated_area_identity.volume_serial_number,
            isolated_area_identity.file_index,
            destination_installation_root,
            destination_root_identity.volume_serial_number,
            destination_root_identity.file_index,
            destination_reparse_free,
            destination_observed_absent,
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.materialisation.materialisation_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.materialisation.materialisation_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the record against its own digest and the observations it
    /// claims.
    ///
    /// The digest is what makes the row non-forgeable from outside: it is
    /// compared with the digest of the recorded CONTENT, so a hand-written row
    /// naming another destination, another area or a false absence observation
    /// fails here rather than being believed because it exists.
    pub fn validate(&self) -> Result<(), IsolatedDestinationError> {
        handle(&self.wire, "prepared_destination.materialisation.wire")
            .map_err(IsolatedDestinationError::Installation)?;
        if self.wire.as_str() != Self::WIRE {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::MigrationRequired {
                    reason: "prepared-destination materialisation requires an explicit re-stage"
                        .to_owned(),
                },
            ));
        }
        for (value, field) in [
            (
                &self.operation_id,
                "prepared_destination.materialisation.operation_id",
            ),
            (
                &self.destination_installation,
                "prepared_destination.materialisation.destination_installation",
            ),
        ] {
            handle(value, field).map_err(IsolatedDestinationError::Installation)?;
        }
        sha256_handle(
            &self.admission_digest,
            "prepared_destination.materialisation.admission_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.materialisation_digest,
            "prepared_destination.materialisation.materialisation_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        text(
            &self.isolated_area_root,
            "prepared_destination.materialisation.isolated_area_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        text(
            &self.destination_installation_root,
            "prepared_destination.materialisation.destination_installation_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        if self.isolated_area_identity.volume_serial_number == 0
            || self.isolated_area_identity.file_index == 0
            || self.destination_root_identity.volume_serial_number == 0
            || self.destination_root_identity.file_index == 0
        {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the created destination root retained no stable file identity".to_owned(),
                ),
            ));
        }
        if !self.destination_observed_absent {
            return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
        }
        if !self.destination_reparse_free {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the created destination root was not proved reparse-free".to_owned(),
                ),
            ));
        }
        if self.materialisation_digest != self.computed_digest()? {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.materialisation.materialisation_digest".to_owned(),
                    reason: "prepared-destination materialisation digest mismatch".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

/// Typed failure of the prepared-destination admission.
///
/// The three arms keep the three distinct failures distinct across layers: the
/// authority's own refusal, a bound owner record that failed *its own*
/// validation, and the installation authority rejecting the allocation or the
/// durable record.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IsolatedDestinationError {
    /// The installation authority refused this destination.
    #[error("isolated destination refused: {0}")]
    Refused(IsolatedDestinationRefusal),
    /// An owner-issued record bound to this operation failed its own validation.
    #[error("owner-issued backup record is invalid: {0}")]
    BoundRecord(BackupError),
    /// The installation authority rejected the allocation or its durable record.
    #[error("installation authority rejected the prepared destination: {0}")]
    Installation(InstallationError),
}

impl From<IsolatedDestinationRefusal> for IsolatedDestinationError {
    fn from(value: IsolatedDestinationRefusal) -> Self {
        Self::Refused(value)
    }
}

impl From<BackupError> for IsolatedDestinationError {
    fn from(value: BackupError) -> Self {
        Self::BoundRecord(value)
    }
}

impl From<InstallationError> for IsolatedDestinationError {
    fn from(value: InstallationError) -> Self {
        Self::Installation(value)
    }
}

/// Bounded maximum for one isolated restore destination, in bytes.
///
/// It matches the protocol crate's `MAX_BACKUP_PAYLOAD_BYTES` upper bound; the
/// bound is re-checked against the owner-issued request's own value rather than
/// replacing it.
const MAX_DESTINATION_RESTORE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Bounded number of archive classes one destination may ever receive.
const MAX_ADMITTED_RESTORATION_CLASSES: usize = 4;

/// Owner-issued record of what this destination would be allowed to restore.
///
/// This is NOT a caller assertion. It is the installation authority's own
/// statement of the requirements a restore into this isolated installation has to
/// meet, issued by [`Self::issue_for_facts`] from the owner-issued
/// [`PreparedDestinationFacts`], and [`admit_prepared_isolated_destination`]
/// checks it against those facts rather than against anything the caller
/// presented.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedRestorationRequirements {
    /// Durable wire discriminator.
    pub wire: PlatformHandle,
    /// Exact archive classes this isolated installation may ever receive.
    ///
    /// `scope_export` is refused by [`Self::validate`]: I5.13 defines it as a
    /// bounded transfer for one declared scope and explicitly "not an
    /// installation backup", so it can never name an installation destination.
    pub admitted_classes: Vec<BackupClassWire>,
    /// Maximum restore bytes this destination admits.
    pub max_restore_bytes: u64,
    /// Target schema the destination must be able to read (SHA-256).
    pub target_schema_digest: PlatformHandle,
    /// Whether the destination requires source credential/key material to be
    /// re-supplied through protected channels before any restore effect.
    ///
    /// I5.13 forbids assuming the destination owns the key, so this is recorded
    /// rather than inferred; a `full_recovery` class requires it.
    pub requires_source_key_material: bool,
    /// Canonical digest over every field except this field.
    pub requirements_digest: PlatformHandle,
}

impl ProposedRestorationRequirements {
    /// Current durable wire.
    pub const WIRE: &'static str = PREPARED_DESTINATION_ADMISSION_WIRE;

    /// Issues the restoration requirements from the owner-issued facts.
    ///
    /// This is the ISSUER, and it lives in the installation authority rather
    /// than at a call site so the requirements are never caller-authored. Every
    /// value is a function of [`PreparedDestinationFacts`]:
    ///
    /// - `admitted_classes` is exactly the owner-issued archive class, so a
    ///   destination cannot be widened to accept a class the operation was not
    ///   admitted for. `scope_export` is refused outright by
    ///   [`IsolatedDestinationRefusal::ClassNotRestorable`], because I5.13
    ///   defines it as "not an installation backup";
    /// - `target_schema_digest` is the owner-issued admitted schema digest;
    /// - `max_restore_bytes` is the owner-issued admitted restore bound;
    /// - `requires_source_key_material` follows A13.7's portable-key rule: a
    ///   `full_recovery` class cannot assume the destination owns the source key
    ///   ("may not merely copy installation-encrypted blob files and assume the
    ///   destination owns the key"), while a `canonical_only_degraded` archive
    ///   carries no blob set to re-key.
    ///
    /// The digest is computed from those values, so the record is a projection
    /// of owner evidence rather than an assertion the caller signs.
    ///
    /// # Errors
    ///
    /// Returns [`IsolatedDestinationRefusal::ClassNotRestorable`] for a
    /// `scope_export` archive and whatever the facts' own validation raises,
    /// unchanged and typed.
    pub fn issue_for_facts(
        facts: &PreparedDestinationFacts,
        max_restore_bytes: u64,
    ) -> Result<Self, IsolatedDestinationError> {
        facts.validate()?;
        let wire =
            PlatformHandle::new(Self::WIRE).map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination.requirements.wire".to_owned(),
                reason: error.to_string(),
            })?;
        let target_schema_digest = PlatformHandle::new(facts.target_schema_digest.as_str())
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination.requirements.target_schema_digest".to_owned(),
                reason: error.to_string(),
            })?;
        let requires_source_key_material =
            matches!(facts.archive_class, BackupClassWire::FullRecovery);
        let admitted_classes = vec![facts.archive_class];
        // The commitment is computed from the values themselves BEFORE the
        // record exists, so the record is built once with its real digest. A
        // placeholder would have to be a second, weaker value type, and
        // `PlatformHandle` deliberately has no such conversion.
        let requirements_digest = Self::digest_over_fields(
            &admitted_classes,
            max_restore_bytes,
            target_schema_digest.as_str(),
            requires_source_key_material,
        )?;
        let requirements = Self {
            wire,
            admitted_classes,
            max_restore_bytes,
            target_schema_digest,
            requires_source_key_material,
            requirements_digest,
        };
        requirements.validate()?;
        Ok(requirements)
    }

    /// Recomputes the domain-separated requirements digest.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        Self::digest_over_fields(
            &self.admitted_classes,
            self.max_restore_bytes,
            self.target_schema_digest.as_str(),
            self.requires_source_key_material,
        )
    }

    fn digest_over_fields(
        admitted_classes: &[BackupClassWire],
        max_restore_bytes: u64,
        target_schema_digest: &str,
        requires_source_key_material: bool,
    ) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            Self::WIRE,
            admitted_classes,
            max_restore_bytes,
            target_schema_digest,
            requires_source_key_material,
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.requirements.requirements_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.requirements.requirements_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the record against its own digest and the closed class set.
    pub fn validate(&self) -> Result<(), IsolatedDestinationError> {
        handle(&self.wire, "prepared_destination.requirements.wire")
            .map_err(IsolatedDestinationError::Installation)?;
        if self.wire.as_str() != Self::WIRE {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::MigrationRequired {
                    reason: "prepared-destination requirements require an explicit re-stage"
                        .to_owned(),
                },
            ));
        }
        sha256_handle(
            &self.target_schema_digest,
            "prepared_destination.requirements.target_schema_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.requirements_digest,
            "prepared_destination.requirements.requirements_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        if self.admitted_classes.is_empty()
            || self.admitted_classes.len() > MAX_ADMITTED_RESTORATION_CLASSES
        {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.requirements.admitted_classes".to_owned(),
                    reason: "must be non-empty and bounded".to_owned(),
                },
            ));
        }
        let mut seen = BTreeSet::new();
        for class in &self.admitted_classes {
            // `BackupClassWire` is a closed vocabulary that derives `Eq`/`Hash`
            // but deliberately not `Ord`, so identity is taken from its own wire
            // spelling rather than from an invented ordering of the enum.
            if !seen.insert(serde_json::to_string(class).map_err(|error| {
                IsolatedDestinationError::Installation(InstallationError::InvalidField {
                    field: "prepared_destination.requirements.admitted_class".to_owned(),
                    reason: error.to_string(),
                })
            })?) {
                return Err(IsolatedDestinationError::Installation(
                    InstallationError::Duplicate {
                        kind: "prepared-destination restoration class".to_owned(),
                        identity: format!("{class:?}"),
                    },
                ));
            }
            if matches!(class, BackupClassWire::ScopeExport) {
                return Err(IsolatedDestinationRefusal::ClassNotRestorable.into());
            }
        }
        if self.max_restore_bytes == 0 || self.max_restore_bytes > MAX_DESTINATION_RESTORE_BYTES {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.requirements.max_restore_bytes".to_owned(),
                    reason: "must be non-zero and bounded".to_owned(),
                },
            ));
        }
        if self.requirements_digest != self.computed_digest()? {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.requirements.requirements_digest".to_owned(),
                    reason: "requirements digest mismatch".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

/// Owner-observed proof that the admitted destination is DISTINCT from the
/// source installation and ISOLATED inside the owner-declared area.
///
/// Every path here is the path the owner RESOLVED through its retained
/// no-follow lease, never a name the caller spelled. Every identity is the
/// lease's own observed file identity. The `*_absent` flags record what the
/// owner observed about existence at admission time; they are evidence of the
/// observation, not a claim that a predictable name is owned.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationEvidence {
    /// Durable wire discriminator.
    pub wire: PlatformHandle,
    /// Owner-declared isolated restore area, resolved through the retained
    /// protected-root lease.
    pub isolated_area_root: String,
    /// Stable identity the retained lease observed for the isolated area.
    pub isolated_area_identity: FileIdentity,
    /// Owner-derived destination installation root (never caller text).
    pub destination_installation_root: String,
    /// Destination installation key the owner derived the leaf name from.
    pub destination_installation_key: PlatformHandle,
    /// Source installation root the destination is compared against.
    pub source_installation_root: String,
    /// Source Host root the preparation reads from.
    pub source_host_root: String,
    /// Active generation the source installation authority currently holds.
    pub source_active_generation: PlatformHandle,
    /// Whether the destination leaf was observed ABSENT by the owner at
    /// admission time.
    ///
    /// A destination that already existed is not a new distinct allocation, so
    /// this must be `true` for a fresh admission; the flag is stored rather than
    /// assumed so a reader can see the observation, not infer it.
    pub destination_observed_absent: bool,
    /// Whether the retained lease proved the isolated area reparse-free.
    pub isolated_area_reparse_free: bool,
    /// SHA-256 over every field except this field.
    pub evidence_digest: PlatformHandle,
}

impl IsolationEvidence {
    /// Current durable wire.
    pub const WIRE: &'static str = PREPARED_DESTINATION_ADMISSION_WIRE;

    /// Recomputes the domain-separated evidence digest over every other field.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        Self::digest_over_fields(
            &self.wire,
            &self.isolated_area_root,
            &self.isolated_area_identity,
            &self.destination_installation_root,
            &self.destination_installation_key,
            &self.source_installation_root,
            &self.source_host_root,
            &self.source_active_generation,
            self.destination_observed_absent,
            self.isolated_area_reparse_free,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the digest covers exactly these ten fields"
    )]
    fn digest_over_fields(
        wire: &PlatformHandle,
        isolated_area_root: &str,
        isolated_area_identity: &FileIdentity,
        destination_installation_root: &str,
        destination_installation_key: &PlatformHandle,
        source_installation_root: &str,
        source_host_root: &str,
        source_active_generation: &PlatformHandle,
        destination_observed_absent: bool,
        isolated_area_reparse_free: bool,
    ) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            ISOLATION_EVIDENCE_DOMAIN,
            wire.as_str(),
            isolated_area_root,
            isolated_area_identity.volume_serial_number,
            isolated_area_identity.file_index,
            destination_installation_root,
            destination_installation_key.as_str(),
            source_installation_root,
            source_host_root,
            source_active_generation.as_str(),
            destination_observed_absent,
            isolated_area_reparse_free,
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.isolation.evidence_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.isolation.evidence_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the evidence against its own digest and the observations it
    /// claims.
    ///
    /// The digest check is what makes the record non-forgeable from the outside:
    /// a hand-written row that names another source, another destination or a
    /// false absence observation fails here, because the recorded digest is
    /// compared with the digest of the recorded CONTENT rather than the record
    /// merely existing.
    pub fn validate(&self) -> Result<(), IsolatedDestinationError> {
        handle(&self.wire, "prepared_destination.isolation.wire")
            .map_err(IsolatedDestinationError::Installation)?;
        if self.wire.as_str() != Self::WIRE {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::MigrationRequired {
                    reason: "isolation evidence requires an explicit re-stage".to_owned(),
                },
            ));
        }
        text(
            &self.isolated_area_root,
            "prepared_destination.isolation.isolated_area_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        text(
            &self.destination_installation_root,
            "prepared_destination.isolation.destination_installation_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        text(
            &self.source_installation_root,
            "prepared_destination.isolation.source_installation_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        text(
            &self.source_host_root,
            "prepared_destination.isolation.source_host_root",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        handle(
            &self.destination_installation_key,
            "prepared_destination.isolation.destination_installation_key",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        handle(
            &self.source_active_generation,
            "prepared_destination.isolation.source_active_generation",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.evidence_digest,
            "prepared_destination.isolation.evidence_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        if self.isolated_area_identity.volume_serial_number == 0
            || self.isolated_area_identity.file_index == 0
        {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the isolated area retained lease reported no stable file identity".to_owned(),
                ),
            ));
        }
        if !self.destination_observed_absent {
            return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
        }
        if !self.isolated_area_reparse_free {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the isolated area retained lease did not prove a reparse-free contour"
                        .to_owned(),
                ),
            ));
        }
        if self.evidence_digest != self.computed_digest()? {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.isolation.evidence_digest".to_owned(),
                    reason: "isolation evidence digest mismatch".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

/// Owner-issued durable record of one PREPARED, UNACTIVATED isolated destination
/// installation.
///
/// It binds, from owner-issued records only:
/// source installation, archive, class, operation, current purge-ledger
/// revision, target schema and proposed restoration requirements. It carries no
/// generation, no activation approval, no epoch and no SCM grant, so recording
/// it activates nothing and authorizes no effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDestinationAdmission {
    /// Durable wire discriminator.
    pub wire: PlatformHandle,
    /// Operation identity this admission belongs to.
    ///
    /// A repeated request for the SAME operation with different bound values
    /// conflicts rather than allocating a second installation; a different
    /// operation never reuses this record.
    pub operation_id: PlatformHandle,
    /// Source installation identity, read from the owner-issued request.
    pub source_installation: PlatformHandle,
    /// Destination installation identity, read from the owner-issued request.
    pub destination_installation: PlatformHandle,
    /// Bound archive identity.
    pub archive_id: PlatformHandle,
    /// Bound archive digest verified by the verifier owner.
    pub archive_digest: PlatformHandle,
    /// Bound archive class.
    pub archive_class: BackupClassWire,
    /// Current purge-ledger revision the destination must apply, read from the
    /// ORS purge-ledger owner.
    pub current_purge_ledger_revision: u64,
    /// Bound target schema digest.
    pub target_schema_digest: PlatformHandle,
    /// Approved target generation handle (build identity), read from the
    /// installation authority's approved generation.
    pub approved_target_build: PlatformHandle,
    /// Approved target profile token, read from the approved target manifest.
    pub approved_target_profile: PlatformHandle,
    /// Owner-issued restoration requirements for this destination.
    pub restoration_requirements: ProposedRestorationRequirements,
    /// Owner-observed isolation evidence for the allocation.
    pub isolation: IsolationEvidence,
    /// SHA-256 over every field except this field.
    pub admission_digest: PlatformHandle,
}

impl PreparedDestinationAdmission {
    /// Current durable wire.
    pub const WIRE: &'static str = PREPARED_DESTINATION_ADMISSION_WIRE;

    /// Recomputes the domain-separated admission binding digest.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        Self::digest_over_fields(
            &self.wire,
            &self.operation_id,
            &self.source_installation,
            &self.destination_installation,
            &self.archive_id,
            &self.archive_digest,
            self.archive_class,
            self.current_purge_ledger_revision,
            &self.target_schema_digest,
            &self.approved_target_build,
            &self.approved_target_profile,
            &self.restoration_requirements.requirements_digest,
            &self.isolation.evidence_digest,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the digest covers exactly these fields"
    )]
    fn digest_over_fields(
        wire: &PlatformHandle,
        operation_id: &PlatformHandle,
        source_installation: &PlatformHandle,
        destination_installation: &PlatformHandle,
        archive_id: &PlatformHandle,
        archive_digest: &PlatformHandle,
        archive_class: BackupClassWire,
        current_purge_ledger_revision: u64,
        target_schema_digest: &PlatformHandle,
        approved_target_build: &PlatformHandle,
        approved_target_profile: &PlatformHandle,
        requirements_digest: &PlatformHandle,
        evidence_digest: &PlatformHandle,
    ) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            PREPARED_DESTINATION_ADMISSION_DOMAIN,
            wire.as_str(),
            operation_id.as_str(),
            source_installation.as_str(),
            destination_installation.as_str(),
            archive_id.as_str(),
            archive_digest.as_str(),
            archive_class,
            current_purge_ledger_revision,
            target_schema_digest.as_str(),
            approved_target_build.as_str(),
            approved_target_profile.as_str(),
            requirements_digest.as_str(),
            evidence_digest.as_str(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.admission_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.admission_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the record and both of its nested owner records.
    pub fn validate(&self) -> Result<(), IsolatedDestinationError> {
        handle(&self.wire, "prepared_destination.wire")
            .map_err(IsolatedDestinationError::Installation)?;
        if self.wire.as_str() != Self::WIRE {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::MigrationRequired {
                    reason: "prepared-destination admission requires an explicit re-stage"
                        .to_owned(),
                },
            ));
        }
        for (value, field) in [
            (&self.operation_id, "prepared_destination.operation_id"),
            (
                &self.source_installation,
                "prepared_destination.source_installation",
            ),
            (
                &self.destination_installation,
                "prepared_destination.destination_installation",
            ),
            (&self.archive_id, "prepared_destination.archive_id"),
            (
                &self.target_schema_digest,
                "prepared_destination.target_schema_digest",
            ),
            (
                &self.approved_target_build,
                "prepared_destination.approved_target_build",
            ),
            (
                &self.approved_target_profile,
                "prepared_destination.approved_target_profile",
            ),
        ] {
            handle(value, field).map_err(IsolatedDestinationError::Installation)?;
        }
        sha256_handle(&self.archive_digest, "prepared_destination.archive_digest")
            .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.admission_digest,
            "prepared_destination.admission_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        if self.current_purge_ledger_revision == 0 {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the destination admission carries no owner-issued purge-ledger revision"
                        .to_owned(),
                ),
            ));
        }
        if matches!(self.archive_class, BackupClassWire::ScopeExport) {
            return Err(IsolatedDestinationRefusal::ClassNotRestorable.into());
        }
        if self.source_installation == self.destination_installation {
            return Err(IsolatedDestinationRefusal::SourceInstallationDestination.into());
        }
        if !valid_installation_key(self.destination_installation.as_str()) {
            return Err(IsolatedDestinationRefusal::ArbitraryDestination.into());
        }
        self.restoration_requirements.validate()?;
        self.isolation.validate()?;
        if self.restoration_requirements.target_schema_digest != self.target_schema_digest {
            return Err(IsolatedDestinationRefusal::BoundRecordConflict {
                field: "target_schema_digest",
            }
            .into());
        }
        if self.isolation.destination_installation_key != self.destination_installation {
            return Err(IsolatedDestinationRefusal::BoundRecordConflict {
                field: "destination_installation",
            }
            .into());
        }
        if self.admission_digest != self.computed_digest()? {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.admission_digest".to_owned(),
                    reason: "prepared-destination admission digest mismatch".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

/// Owner-issued facts one prepared-destination admission binds.
///
/// Every field names one of the bindings the issue names: source installation,
/// archive, class, operation and target schema. There is no path field and no
/// free-form destination field: the destination installation IDENTITY is read
/// from the owner-issued authenticated request identity by
/// [`Self::issue_for_admitted_identity`], and it must be in the owner
/// installation-key form.
///
/// The facts are validated against their own digest before anything is derived
/// from them, and [`admit_prepared_isolated_destination`] re-checks every field
/// it binds against the owner records it was given.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedDestinationFacts {
    /// Durable wire discriminator.
    pub wire: PlatformHandle,
    /// Operation identity this preparation is for.
    pub operation_id: PlatformHandle,
    /// Source installation identity the preparation reads from.
    pub source_installation: PlatformHandle,
    /// Destination installation identity, read from the owner-issued
    /// authenticated request identity. It is an installation IDENTITY, never a
    /// path: [`Self::issue_for_admitted_identity`] takes it from the owner
    /// record and [`PreparedDestinationFacts::validate`] requires the owner
    /// installation-key form.
    pub destination_installation: PlatformHandle,
    /// Bound archive identity.
    pub archive_id: PlatformHandle,
    /// Bound archive digest.
    pub archive_digest: PlatformHandle,
    /// Bound archive class. `scope_export` is refused: I5.13 defines it as
    /// "not an installation backup".
    pub archive_class: BackupClassWire,
    /// Admitted target schema digest the destination must be able to read.
    pub target_schema_digest: PlatformHandle,
    /// SHA-256 over every field except this field.
    pub facts_digest: PlatformHandle,
}

impl PreparedDestinationFacts {
    /// Current durable wire.
    pub const WIRE: &'static str = PREPARED_DESTINATION_ADMISSION_WIRE;

    /// Issues the facts from one owner-issued authenticated request identity.
    ///
    /// This is the PRODUCER, and it lives in the installation authority so the
    /// binding cannot be authored by a caller. Every value is read out of the
    /// owner record:
    ///
    /// - `source_installation`, `destination_installation`, `archive_id`,
    ///   `archive_digest`, `archive_class` and `target_schema_digest` are that
    ///   identity's own fields, after [`BackupRequestIdentity::validate`] has
    ///   proved it against its contract (its identity digest, its fence, its
    ///   class and its admission reference);
    /// - `operation_id` is the identity's own mutation binding's canonical
    ///   request hash, so a repeated request for the SAME operation reproduces
    ///   the same facts -- which is what lets
    ///   [`RedbInstallationRegistry::record_prepared_isolated_destination`]
    ///   return the same verified destination instead of allocating a second
    ///   installation -- while a changed same-operation input produces different
    ///   facts and therefore conflicts.
    ///
    /// The record itself is then validated, so a caller cannot reach the
    /// admission with facts this owner would not have issued.
    ///
    /// # Errors
    ///
    /// Returns the identity's own [`BackupError`] unchanged and typed when that
    /// owner record does not validate, and
    /// [`IsolatedDestinationRefusal::ArbitraryDestination`] when the admitted
    /// destination identity is not an owner installation key.
    pub fn issue_for_admitted_identity(
        identity: &BackupRequestIdentity,
    ) -> Result<Self, IsolatedDestinationError> {
        identity.validate()?;
        let facts = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "prepared_destination.facts.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            operation_id: PlatformHandle::new(identity.mutation.canonical_request_hash.as_str())
                .map_err(|error| InstallationError::InvalidField {
                    field: "prepared_destination.facts.operation_id".to_owned(),
                    reason: error.to_string(),
                })?,
            source_installation: PlatformHandle::new(identity.source_installation.as_str())
                .map_err(|error| InstallationError::InvalidField {
                    field: "prepared_destination.facts.source_installation".to_owned(),
                    reason: error.to_string(),
                })?,
            destination_installation: PlatformHandle::new(identity.dest_installation.as_str())
                .map_err(|_| IsolatedDestinationRefusal::ArbitraryDestination)?,
            archive_id: PlatformHandle::new(identity.archive_id.as_str()).map_err(|error| {
                InstallationError::InvalidField {
                    field: "prepared_destination.facts.archive_id".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            archive_digest: PlatformHandle::new(identity.archive_digest.as_str()).map_err(
                |error| InstallationError::InvalidField {
                    field: "prepared_destination.facts.archive_digest".to_owned(),
                    reason: error.to_string(),
                },
            )?,
            archive_class: identity.class,
            target_schema_digest: PlatformHandle::new(identity.schema_digest.as_str()).map_err(
                |error| InstallationError::InvalidField {
                    field: "prepared_destination.facts.target_schema_digest".to_owned(),
                    reason: error.to_string(),
                },
            )?,
            facts_digest: PlatformHandle::new(identity.schema_digest.as_str()).map_err(
                |error| InstallationError::InvalidField {
                    field: "prepared_destination.facts.facts_digest".to_owned(),
                    reason: error.to_string(),
                },
            )?,
        };
        if !valid_installation_key(facts.destination_installation.as_str()) {
            return Err(IsolatedDestinationRefusal::ArbitraryDestination.into());
        }
        if facts.source_installation == facts.destination_installation {
            return Err(IsolatedDestinationRefusal::SourceInstallationDestination.into());
        }
        // The commitment is recomputed from the facts' own recorded content and
        // then re-validated, so the value the caller receives is the one the
        // admission will later compare against.
        let mut facts = facts;
        facts.facts_digest = facts.computed_digest()?;
        facts.validate()?;
        Ok(facts)
    }

    /// Recomputes the domain-separated facts digest over every other field.
    fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = canonical_json_bytes(&(
            Self::WIRE,
            self.operation_id.as_str(),
            self.source_installation.as_str(),
            self.destination_installation.as_str(),
            self.archive_id.as_str(),
            self.archive_digest.as_str(),
            self.archive_class,
            self.target_schema_digest.as_str(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.facts.facts_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.facts.facts_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the facts against their own digest and the closed class set.
    ///
    /// # Errors
    ///
    /// Returns [`IsolatedDestinationRefusal::ClassNotRestorable`] for a
    /// `scope_export` archive and
    /// [`IsolatedDestinationError::Installation`] for a shape or digest fault.
    pub fn validate(&self) -> Result<(), IsolatedDestinationError> {
        handle(&self.wire, "prepared_destination.facts.wire")
            .map_err(IsolatedDestinationError::Installation)?;
        if self.wire.as_str() != Self::WIRE {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::MigrationRequired {
                    reason: "prepared-destination facts require an explicit re-stage".to_owned(),
                },
            ));
        }
        for (value, field) in [
            (
                &self.operation_id,
                "prepared_destination.facts.operation_id",
            ),
            (
                &self.source_installation,
                "prepared_destination.facts.source_installation",
            ),
            (
                &self.destination_installation,
                "prepared_destination.facts.destination_installation",
            ),
            (&self.archive_id, "prepared_destination.facts.archive_id"),
            (
                &self.target_schema_digest,
                "prepared_destination.facts.target_schema_digest",
            ),
        ] {
            handle(value, field).map_err(IsolatedDestinationError::Installation)?;
        }
        sha256_handle(
            &self.archive_digest,
            "prepared_destination.facts.archive_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.target_schema_digest,
            "prepared_destination.facts.target_schema_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        sha256_handle(
            &self.facts_digest,
            "prepared_destination.facts.facts_digest",
        )
        .map_err(IsolatedDestinationError::Installation)?;
        if matches!(self.archive_class, BackupClassWire::ScopeExport) {
            return Err(IsolatedDestinationRefusal::ClassNotRestorable.into());
        }
        if !valid_installation_key(self.destination_installation.as_str()) {
            return Err(IsolatedDestinationRefusal::ArbitraryDestination.into());
        }
        if self.source_installation == self.destination_installation {
            return Err(IsolatedDestinationRefusal::SourceInstallationDestination.into());
        }
        if self.facts_digest != self.computed_digest()? {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::InvalidField {
                    field: "prepared_destination.facts.facts_digest".to_owned(),
                    reason: "prepared-destination facts digest mismatch".to_owned(),
                },
            ));
        }
        Ok(())
    }
}

/// The exact allocation the installation authority admitted.
///
/// It is produced before any effect and carries the derived destination root
/// together with the owner-observed [`IsolationEvidence`] that proves the
/// allocation is distinct from the source and isolated inside the owner-declared
/// area.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolatedDestinationAllocation {
    /// Operation identity this allocation belongs to.
    pub operation_id: PlatformHandle,
    /// Destination installation identity.
    pub destination_installation: PlatformHandle,
    /// Owner-derived destination installation root. Never caller text.
    pub destination_installation_root: String,
    /// The durable admission record the registry stores for this allocation.
    pub admission: PreparedDestinationAdmission,
}

/// Owner-issued inputs of one prepared-destination admission.
///
/// Every field is an owner record. There is deliberately no path field and no
/// free-form destination field: the destination root is derived from the
/// owner-declared isolated restore area and the destination installation key the
/// owner-issued request identity carries.
pub struct IsolatedDestinationAdmissionInput<'a> {
    /// Owner-issued, digest-bound facts this admission binds: source
    /// installation, archive, class, operation and target schema.
    pub facts: &'a PreparedDestinationFacts,
    /// Owner-issued admitted restore bound for the bound archive.
    ///
    /// This is an owner-issued value, not a caller-chosen number. A destination
    /// that admits more bytes than the owner admitted for this archive is
    /// refused rather than admitted with a relaxed bound.
    pub max_restore_bytes: u64,
    /// The source installation's own digest-bound root topology.
    pub source_roots: &'a RuntimeStateRoots,
    /// Active generation the source installation authority currently holds.
    pub source_active_generation: &'a PlatformHandle,
    /// Retained, no-follow protected-root lease over the owner-declared
    /// isolated restore area.
    pub isolated_area_lease: &'a ProtectedRootLease,
    /// The approved target manifest: the installation authority's own approved
    /// generation manifest, whose profile and roots digest are the approved
    /// target build/profile.
    pub approved_target_manifest: &'a CandidateManifest,
    /// The installation authority's own activation approval for that manifest.
    ///
    /// This is the proof that the target build/profile is approved, and it is
    /// read out of the owner's `ApprovedGeneration` row rather than supplied by
    /// the caller: its only constructor is crate-private and its production
    /// issuer is the signed activation bridge, so a caller cannot present one.
    pub approved_target_approval: &'a InstallationActivationApproval,
    /// Owner-issued restoration requirements for this destination.
    pub restoration_requirements: &'a ProposedRestorationRequirements,
    /// Current purge-ledger revision read from the ORS purge-ledger owner.
    pub current_purge_ledger_revision: u64,
    /// Installation identities this authority already knows about. Used to
    /// refuse an existing (active or previously admitted) installation as the
    /// destination.
    pub known_installations: &'a [PlatformHandle],
}

/// Admits and allocates a new, distinct, isolated destination installation.
///
/// # Order
///
/// This function is pure and runs **before** any effect: it opens nothing,
/// creates nothing and writes nothing. It only reads the retained lease the
/// caller already holds, validates every bound owner-issued record, and refuses
/// or returns the exact allocation.
///
/// # What it checks, in order
///
/// 1. [`PreparedDestinationFacts::validate`] — the owner-issued binding of
///    source installation, archive identity and digest, class, operation and
///    target schema — is checked against its OWN recorded digest of its OWN
///    recorded content, so neither existence nor shape can stand in for the
///    comparison;
/// 2. the destination installation identity is DERIVED from the owner-issued
///    operation and archive identities and must be an owner installation key,
///    so there is no parameter through which a path could arrive;
/// 3. the destination is not the owner-issued source installation;
/// 4. the destination is not an installation this authority already knows —
///    the active one, any approved generation, or any destination already
///    admitted as prepared — and the approved target is not the source's own
///    active generation over the same root topology, so an active or
///    same-installation contour can never be the destination;
/// 5. the approved target build/profile is proved by the installation
///    authority's own activation approval for the approved manifest, through
///    the crate's existing [`validate_approval_against_manifest`](crate::approved_generation_registry::validate_approval_against_manifest),
///    BEFORE anything is allocated;
/// 6. the owner-declared isolated restore area resolves through its retained
///    no-follow protected-root lease to exactly the declared root, and the
///    destination root derived from it is strictly inside the area and neither
///    contains, is contained by, nor equals the source installation root; the
///    owner's own layout classification additionally requires the source Host
///    root to BE an installation Host root and requires the area and the derived
///    leaf NOT to be inside any installation tree, which is the "preexisting
///    foreign owner" clause decided by the owner rather than by a name;
/// 7. the destination leaf is OBSERVED absent, so the allocation is new and
///    distinct rather than a reuse or a delete by name;
/// 8. the owner-issued restoration requirements admit exactly the bound archive
///    class, exactly the bound target schema, and no fewer bytes than the owner
///    admitted;
/// 9. the owner-issued current purge-ledger revision is non-zero.
///
/// Only then is the durable admission record built, and only that record may
/// later be inserted through
/// [`RedbInstallationRegistry::record_prepared_isolated_destination`].
///
/// # Errors
///
/// Returns [`IsolatedDestinationError::Refused`] for each refusal class in
/// [`IsolatedDestinationRefusal`], [`IsolatedDestinationError::BoundRecord`]
/// when an owner record fails its own contract, and
/// [`IsolatedDestinationError::Installation`] when the installation owner's own
/// roots or manifests cannot produce a value.
pub fn admit_prepared_isolated_destination(
    input: &IsolatedDestinationAdmissionInput<'_>,
) -> Result<IsolatedDestinationAllocation, IsolatedDestinationError> {
    // 1. The owner-issued facts are validated against their OWN digest before
    //    anything is derived from them. This is the binding the issue names --
    //    source, archive, class, operation, target schema -- and it is checked
    //    against the recorded digest of the recorded content, so an existence or
    //    shape check could never stand in for the comparison.
    input.facts.validate()?;

    // 2. The destination installation identity is DERIVED from the owner-issued
    //    operation and archive identities under this crate's own domain
    //    separator. It is not an input at all, which is the whole of the
    //    "client-supplied arbitrary path is rejected" negative: there is no
    //    parameter through which a path could arrive.
    let destination_key = input.facts.destination_installation.clone();
    if !valid_installation_key(destination_key.as_str()) {
        return Err(IsolatedDestinationRefusal::ArbitraryDestination.into());
    }

    // 3. The source installation is never the destination, and the source is the
    //    owner-issued one rather than a claim.
    if input.facts.source_installation == destination_key {
        return Err(IsolatedDestinationRefusal::SourceInstallationDestination.into());
    }

    // 4. An installation this authority already knows is never the destination:
    //    that covers the ACTIVE installation, every previously approved
    //    generation, and every destination already admitted as prepared.
    if input
        .known_installations
        .iter()
        .any(|known| known == &destination_key)
    {
        return Err(IsolatedDestinationRefusal::ExistingInstallation.into());
    }

    // 5. The approved target build/profile is proved BEFORE anything is
    //    allocated. Both records are owner records -- the approved generation's
    //    manifest and the activation approval the installation authority issued
    //    for it -- and they are checked with the crate's own binding validator,
    //    so an unapproved build or profile cannot reach the allocation step. The
    //    approval's only constructor is crate-private and its production issuer
    //    is the signed activation bridge, so no caller can present one.
    input.approved_target_manifest.validate()?;
    input.approved_target_approval.validate()?;
    crate::approved_generation_registry::validate_approval_against_manifest(
        input.approved_target_approval,
        input.approved_target_manifest,
        "prepared_destination.approved_target",
    )?;
    let approved_target_build = input.approved_target_manifest.generation.clone();
    if approved_target_build == *input.source_active_generation
        && input.approved_target_manifest.runtime_state_roots_digest
            == input.source_roots.roots_digest
    {
        // The approved target IS the source's own active generation over the same
        // root topology, so materialising a "distinct" installation from it would
        // not be a new installation at all -- it is the same-installation
        // restart/rebind contour this issue explicitly excludes.
        return Err(IsolatedDestinationRefusal::ExistingInstallation.into());
    }

    // 6, 5b and 7: the owner-declared isolated restore area, proved through the
    //    retained no-follow lease the caller already holds; the destination root
    //    DERIVED from it; and the newness the owner OBSERVES rather than infers.
    //    I5.13's "restore to isolated root" is therefore a position inside an
    //    owner-declared area, never a supplied name.
    let derived = derive_isolated_destination_root(input, &destination_key)?;

    // 8. Restoration requirements are the installation authority's own record,
    //    issued from the owner-issued facts. They are re-validated here and must
    //    admit exactly the bound archive class, the bound target schema and no
    //    fewer bytes than the owner admitted, so a destination cannot be widened.
    validate_restoration_requirements(input)?;

    // 9. The current purge-ledger revision comes from the ORS purge-ledger owner,
    //    never from the caller's assertion, and zero is refused: a destination
    //    bound to no purge revision would restore without applying the current
    //    privacy purge, which A13.7's verification list requires.
    if input.current_purge_ledger_revision == 0 {
        return Err(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the owner issued no current purge-ledger revision for this destination".to_owned(),
            ),
        ));
    }

    build_admission_record(input, &destination_key, &derived, approved_target_build)
}

/// Builds and self-validates the isolation evidence for
/// [`admit_prepared_isolated_destination`].
///
/// Every bound value comes from the owner-resolved geometry in `derived` or from
/// the owner-issued records; none of it is caller text. The evidence digest is
/// computed from those values BEFORE the record exists, so the record is built
/// once with its real digest, and the record is then validated against it.
///
/// This is a pure move of record assembly; it adds no check and removes none.
fn build_isolation_evidence(
    input: &IsolatedDestinationAdmissionInput<'_>,
    destination_key: &PlatformHandle,
    derived: &DerivedIsolation,
) -> Result<IsolationEvidence, IsolatedDestinationError> {
    let DerivedIsolation {
        area_identity,
        resolved_area_text,
        destination_installation_root,
        source_installation_root,
    } = derived;
    let isolation_wire = PlatformHandle::new(IsolationEvidence::WIRE).map_err(|error| {
        InstallationError::InvalidField {
            field: "prepared_destination.isolation.wire".to_owned(),
            reason: error.to_string(),
        }
    })?;
    let source_host_root = input.source_roots.host_state_root.as_str().to_owned();
    let isolation = IsolationEvidence {
        wire: isolation_wire.clone(),
        isolated_area_root: resolved_area_text.clone(),
        isolated_area_identity: *area_identity,
        destination_installation_root: destination_installation_root.clone(),
        destination_installation_key: destination_key.clone(),
        source_installation_root: source_installation_root.clone(),
        source_host_root: source_host_root.clone(),
        source_active_generation: input.source_active_generation.clone(),
        destination_observed_absent: true,
        isolated_area_reparse_free: true,
        evidence_digest: IsolationEvidence::digest_over_fields(
            &isolation_wire,
            resolved_area_text,
            area_identity,
            destination_installation_root,
            destination_key,
            source_installation_root,
            &source_host_root,
            input.source_active_generation,
            true,
            true,
        )?,
    };
    isolation.validate()?;
    Ok(isolation)
}

/// Builds and self-validates the admission record and its allocation for
/// [`admit_prepared_isolated_destination`].
///
/// The isolation evidence and the admission commitments are computed from the
/// values themselves BEFORE each record exists, so both records are built once
/// with their real digests rather than with placeholders. Both are then
/// validated against their own digests before the allocation is returned, so an
/// allocation is never handed back unproved.
///
/// This is a pure move of record assembly; it adds no check and removes none.
fn build_admission_record(
    input: &IsolatedDestinationAdmissionInput<'_>,
    destination_key: &PlatformHandle,
    derived: &DerivedIsolation,
    approved_target_build: PlatformHandle,
) -> Result<IsolatedDestinationAllocation, IsolatedDestinationError> {
    let profile_token = match input.approved_target_manifest.runtime_launch.profile {
        super::InstallationProfile::SystemService => "system_service",
        super::InstallationProfile::UserMode => "user_mode",
        super::InstallationProfile::PortableDev => "portable_dev",
    };
    let approved_target_profile =
        PlatformHandle::new(profile_token).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.approved_target_profile".to_owned(),
            reason: error.to_string(),
        })?;

    let isolation = build_isolation_evidence(input, destination_key, derived)?;

    let wire = PlatformHandle::new(PreparedDestinationAdmission::WIRE).map_err(|error| {
        InstallationError::InvalidField {
            field: "prepared_destination.wire".to_owned(),
            reason: error.to_string(),
        }
    })?;
    let operation_id = input.facts.operation_id.clone();
    let archive_id = input.facts.archive_id.clone();
    let archive_digest = input.facts.archive_digest.clone();
    let target_schema_digest = input.facts.target_schema_digest.clone();
    let admission_digest = PreparedDestinationAdmission::digest_over_fields(
        &wire,
        &operation_id,
        &input.facts.source_installation,
        destination_key,
        &archive_id,
        &archive_digest,
        input.facts.archive_class,
        input.current_purge_ledger_revision,
        &target_schema_digest,
        &approved_target_build,
        &approved_target_profile,
        &input.restoration_requirements.requirements_digest,
        &isolation.evidence_digest,
    )?;
    let admission = PreparedDestinationAdmission {
        wire,
        operation_id,
        source_installation: input.facts.source_installation.clone(),
        destination_installation: destination_key.clone(),
        archive_id,
        archive_digest,
        archive_class: input.facts.archive_class,
        current_purge_ledger_revision: input.current_purge_ledger_revision,
        target_schema_digest,
        approved_target_build,
        approved_target_profile,
        restoration_requirements: input.restoration_requirements.clone(),
        isolation,
        admission_digest,
    };
    admission.validate()?;

    Ok(IsolatedDestinationAllocation {
        operation_id: admission.operation_id.clone(),
        destination_installation: destination_key.clone(),
        destination_installation_root: derived.destination_installation_root.clone(),
        admission,
    })
}

/// The owner-resolved geometry an admitted isolated destination is derived from.
///
/// Every value here comes from the owner's own lease resolution and layout
/// classification; none of it is caller text. It is the single bundle the
/// admission record's isolation evidence is built from.
struct DerivedIsolation {
    /// The area identity the retained lease still holds.
    area_identity: FileIdentity,
    /// The area root the retained lease resolves now.
    resolved_area_text: String,
    /// The destination root DERIVED inside that area, never supplied.
    destination_installation_root: String,
    /// The source installation root, from the owner-issued source roots.
    source_installation_root: String,
}

/// Proves the owner-declared isolated restore area and derives the destination
/// root inside it, for [`admit_prepared_isolated_destination`].
///
/// This carries validation steps 6, 5b and 7 of the admission:
///
/// - the "preexisting foreign owner" clause, decided by the owner against its
///   own declared LAYOUT rather than against a name. The source's Host root must
///   really BE an installation Host root of this layout -- if it is not, the
///   source is a foreign directory and every isolation statement derived from
///   its roots is a claim, not a fact. The isolated area and the derived
///   destination leaf must NOT classify as any part of an installation tree,
///   because a destination that some foreign installation already owns is not a
///   new distinct isolated installation. Both directions are pure layout
///   classification: they observe no filesystem, so existence and reparse
///   freedom stay the protected-root lease's proof, composed on top;
/// - the retained lease must still name the same object, and the area it
///   resolves now must be the declared one;
/// - the destination must be STRICTLY inside the area (the area itself is not a
///   destination) and must neither contain, be contained by, nor equal the
///   source installation root: I5.13's isolated root, A13.7's isolated area;
/// - the allocation must be NEW and DISTINCT, and the owner OBSERVES that
///   rather than inferring it from a name: a leaf that already exists is not
///   owned by this operation, so it is refused -- never reused, and never
///   deleted by path name.
///
/// This is a pure move of those checks; it adds no check and removes none, and
/// the caller runs it at exactly the same point in the validation order.
fn derive_isolated_destination_root(
    input: &IsolatedDestinationAdmissionInput<'_>,
    destination_key: &PlatformHandle,
) -> Result<DerivedIsolation, IsolatedDestinationError> {
    input.source_roots.validate()?;
    if !classify_installation_host_root(std::path::Path::new(
        input.source_roots.host_state_root.as_str(),
    ))
    .is_installation_host_root()
    {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }
    let declared_area = input.source_roots.isolated_restore_root()?;
    if !matches!(
        classify_installation_host_root(std::path::Path::new(declared_area.as_str())),
        InstallationHostRootClass::Unowned
    ) {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }
    let resolved_area = input
        .isolated_area_lease
        .canonical_path()
        .map_err(|_| IsolatedDestinationRefusal::IsolatedAreaUnproved)?;
    if !same_windows_root_text(&resolved_area.to_string_lossy(), declared_area.as_str()) {
        return Err(IsolatedDestinationRefusal::IsolatedAreaUnproved.into());
    }
    // Constructing the lease already pinned the whole contour and refused a
    // reparse component; re-verifying the retained identity proves the handle
    // still names the same object, so a link swapped in afterwards is caught
    // before anything is derived from the area.
    input
        .isolated_area_lease
        .verify_stable_identity()
        .map_err(|_| IsolatedDestinationRefusal::IsolatedAreaUnproved)?;
    let area_identity = input.isolated_area_lease.identity();
    let resolved_area_text = resolved_area.to_string_lossy().into_owned();
    let destination_installation_root =
        joined_windows_path(&resolved_area_text, destination_key.as_str());
    let source_installation_root = input.source_roots.installation_root.as_str().to_owned();

    let strictly_inside_area =
        !same_windows_root_text(&destination_installation_root, &resolved_area_text)
            && path_is_within(&destination_installation_root, &resolved_area_text);
    let disjoint_from_source =
        !same_windows_root_text(&destination_installation_root, &source_installation_root)
            && !path_is_within(&destination_installation_root, &source_installation_root)
            && !path_is_within(&source_installation_root, &destination_installation_root);
    if !(strictly_inside_area && disjoint_from_source) {
        return Err(IsolatedDestinationRefusal::DestinationOverlapsSource.into());
    }
    // The derived leaf is classified against the SAME owner layout before it is
    // observed: a destination that resolves inside some installation's own tree
    // belongs to that installation, whatever this operation intends to write
    // there.
    if !matches!(
        classify_installation_host_root(std::path::Path::new(&destination_installation_root)),
        InstallationHostRootClass::Unowned
    ) {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }

    if std::path::Path::new(&destination_installation_root).exists() {
        return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
    }

    Ok(DerivedIsolation {
        area_identity,
        resolved_area_text,
        destination_installation_root,
        source_installation_root,
    })
}

/// Re-validates the bound restoration requirements for
/// [`admit_prepared_isolated_destination`].
///
/// The requirements are the installation authority's own record, issued from the
/// owner-issued facts. They must admit exactly the bound archive class, the bound
/// target schema and no fewer bytes than the owner admitted, so a destination
/// cannot be widened.
///
/// This is a pure move of those checks; it adds no check and removes none.
fn validate_restoration_requirements(
    input: &IsolatedDestinationAdmissionInput<'_>,
) -> Result<(), IsolatedDestinationError> {
    input.restoration_requirements.validate()?;
    if input.restoration_requirements.admitted_classes != [input.facts.archive_class] {
        return Err(IsolatedDestinationRefusal::BoundRecordConflict {
            field: "admitted_classes",
        }
        .into());
    }
    if input.restoration_requirements.max_restore_bytes < input.max_restore_bytes {
        return Err(IsolatedDestinationRefusal::BoundRecordConflict {
            field: "max_restore_bytes",
        }
        .into());
    }
    if input.restoration_requirements.target_schema_digest != input.facts.target_schema_digest {
        return Err(IsolatedDestinationRefusal::BoundRecordConflict {
            field: "target_schema_digest",
        }
        .into());
    }
    Ok(())
}

/// Materialises the ADMITTED isolated destination root, through the
/// installation authority's own directory publication, under the retained
/// protected-root lease `IsolationEvidence` already proved.
///
/// This is the effect step that [`admit_prepared_isolated_destination`]
/// deliberately does not perform. It is separate so the validation-before-effects
/// order stays intact: admission is pure, and only a caller holding a validated
/// allocation may call this.
///
/// # What "owned by this operation" is proved with
///
/// The destination is created by [`OwnedDirectoryPublication`], the same
/// create-new owned-directory publication `eliot-installation` already uses for
/// its own output bundle. It is not a bare `create_dir`: the owner retains the
/// destination-parent contour by no-follow handles, requires the destination to
/// be ABSENT, creates a same-parent temporary under the retained parent handle,
/// and moves it into place with handle-relative NO-REPLACE semantics. A
/// reparse component anywhere in the contour is refused by the owner, so a
/// junction at the destination name or at any ancestor cannot be written
/// through.
///
/// Four content comparisons, each against a value this operation or the owner
/// produced, and none of them an existence check:
///
/// 1. the retained area lease's LIVE `FileIdentity` is compared with the
///    `FileIdentity` the admission RECORDED in its `IsolationEvidence` -- so the
///    publication happens under the very area object the admission was proved
///    against, and an area swapped for another object between the two steps is
///    refused before anything is created;
/// 2. the area path the lease resolves NOW is compared with the recorded
///    `isolated_area_root`, and the destination root is RE-DERIVED from that
///    resolution and the recorded destination installation key, then compared
///    with the recorded `destination_installation_root` -- a hand-edited
///    admission cannot redirect the creation anywhere else;
/// 3. the `parent_identity` the publication owner measured through its retained
///    parent handle is compared with the lease's live area identity -- a second,
///    independent measurement of the same fact by the creating code path;
/// 4. the identity of the object that now carries the destination name is
///    observed through a fresh reparse-free protected-root lease and RECORDED,
///    so a later reader can compare the live identity with the recorded one.
///
/// The recorded destination name is never used as the ownership argument: the
/// record carries an identity, and re-running this function against a name that
/// a foreign owner now holds is refused at step 1 of
/// [`OwnedDirectoryPublication::create`] rather than adopted.
///
/// # Errors
///
/// [`IsolatedDestinationRefusal::DestinationNotAbsent`] when the owner observes
/// the leaf present or cannot observe it at all,
/// [`IsolatedDestinationRefusal::IsolatedAreaUnproved`] when the retained lease
/// no longer names the area the admission recorded,
/// [`IsolatedDestinationRefusal::BoundRecordConflict`] when the derived root
/// disagrees with the recorded one,
/// [`IsolatedDestinationRefusal::ArbitraryDestination`] when the destination
/// identity is not an owner installation key, and
/// [`IsolatedDestinationError::Installation`] for a failed or unreconcilable
/// publication. A publication that committed but whose identity could not be
/// read back is reported as an installation uncertainty and the created root is
/// PRESERVED: it is never removed by path name, which is what the issue's
/// "preserving unknown state rather than deleting by path name" requires.
pub fn materialise_prepared_isolated_destination(
    admission: &PreparedDestinationAdmission,
    isolated_area_lease: &ProtectedRootLease,
) -> Result<PreparedDestinationMaterialisation, IsolatedDestinationError> {
    // The ORIGINAL retained record is re-validated, so a materialisation can
    // only ever be made for an admission that still validates against its own
    // recorded digests. The commitment is never recomputed here to stand in for
    // owner-issued material.
    admission.validate()?;
    if !valid_installation_key(admission.destination_installation.as_str()) {
        return Err(IsolatedDestinationRefusal::ArbitraryDestination.into());
    }

    // (1) and (2): the retained lease must still be the object and the path the
    // admission was proved against, and the destination root is re-derived from
    // that resolution rather than taken from the record.
    let (observed_area_identity, derived_destination_root) =
        prove_isolated_area_and_derive_destination(admission, isolated_area_lease)?;

    // The owner must observe absence itself, immediately before the create. A
    // name a caller can predict is not evidence that this operation owns it, so
    // a leaf that is present -- including a junction, which `symlink_metadata`
    // reports without following -- is refused, never reused and never removed.
    match std::fs::symlink_metadata(&derived_destination_root) {
        Ok(_) => return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(
                    "the destination leaf could not be observed as absent, so this operation \
                     cannot claim it owns that name"
                        .to_owned(),
                ),
            ));
        }
    }

    // The installation authority's own create-new owned-directory publication.
    let publication = OwnedDirectoryPublication::create(std::path::Path::new(
        &derived_destination_root,
    ))
    .map_err(|error| match error {
        // A destination that already existed by the time the owner
        // created it, including a concurrent create race, is not owned
        // by this operation.
        DirectoryPublicationError::AlreadyExists => {
            IsolatedDestinationRefusal::DestinationNotAbsent.into()
        }
        DirectoryPublicationError::ReparsePoint => {
            IsolatedDestinationRefusal::ForeignInstallationOwner.into()
        }
        other => IsolatedDestinationError::Installation(InstallationError::Platform(format!(
            "the installation authority could not create the isolated destination: {other}"
        ))),
    })?;

    // (3): the creating code path's own independent measurement of the parent
    // object must equal what the retained lease holds.
    if publication.parent_identity() != observed_area_identity {
        return Err(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the destination parent observed while creating the isolated destination is not \
                 the isolated area this admission was proved against"
                    .to_owned(),
            ),
        ));
    }
    let source_identity = publication.temporary_identity();
    let receipt = match publication.publish(source_identity).map_err(|error| {
        IsolatedDestinationError::Installation(InstallationError::Platform(format!(
            "the installation authority could not publish the isolated destination: {error}"
        )))
    })? {
        DirectoryPublicationOutcome::Published(receipt) => receipt,
        // The move COMMITTED. The created root is therefore a real object whose
        // identity this operation could not read back; it is preserved and
        // reported as an uncertainty, never deleted by name.
        DirectoryPublicationOutcome::CommittedUnknown(unknown) => {
            return Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(format!(
                    "the isolated destination was created but its identity could not be read \
                     back ({:?}); the created root is preserved and not removed by path name",
                    unknown.reason
                )),
            ));
        }
    };

    // (4): the object now carrying the admitted name is re-proved through a
    // fresh reparse-free protected-root lease -- the same owner, the same
    // protected-root contour, the same no-follow pin -- and its identity is what
    // gets recorded. A junction swapped in immediately after the move is
    // refused here rather than adopted.
    let destination_root_identity = reprove_created_destination_root(
        admission,
        &derived_destination_root,
        receipt.destination_identity,
    )?;

    build_materialisation_record(
        admission,
        observed_area_identity,
        derived_destination_root,
        destination_root_identity,
    )
}

/// Builds and self-validates the materialisation record for
/// [`materialise_prepared_isolated_destination`].
///
/// The commitment is computed from the values themselves BEFORE the record
/// exists, so the record is built once with its real digest rather than with a
/// placeholder that would have to be a second, weaker value type. The record is
/// then validated against its own digest before it is returned, so a
/// materialisation is never handed back unproved.
///
/// This is a pure move of record assembly; it adds no check and removes none.
fn build_materialisation_record(
    admission: &PreparedDestinationAdmission,
    observed_area_identity: FileIdentity,
    derived_destination_root: String,
    destination_root_identity: FileIdentity,
) -> Result<PreparedDestinationMaterialisation, IsolatedDestinationError> {
    let materialisation_wire = PlatformHandle::new(PreparedDestinationMaterialisation::WIRE)
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.materialisation.wire".to_owned(),
            reason: error.to_string(),
        })?;
    let materialisation_digest = PreparedDestinationMaterialisation::digest_over_fields(
        &materialisation_wire,
        &admission.operation_id,
        &admission.destination_installation,
        &admission.admission_digest,
        &admission.isolation.isolated_area_root,
        &observed_area_identity,
        &derived_destination_root,
        &destination_root_identity,
        true,
        true,
    )?;
    let materialisation = PreparedDestinationMaterialisation {
        wire: materialisation_wire,
        operation_id: admission.operation_id.clone(),
        destination_installation: admission.destination_installation.clone(),
        admission_digest: admission.admission_digest.clone(),
        isolated_area_root: admission.isolation.isolated_area_root.clone(),
        isolated_area_identity: observed_area_identity,
        destination_installation_root: derived_destination_root,
        destination_root_identity,
        destination_reparse_free: true,
        destination_observed_absent: true,
        materialisation_digest,
    };
    materialisation.validate()?;
    Ok(materialisation)
}

/// Re-proves the retained isolated area and re-derives the destination root
/// from that resolution, for
/// [`materialise_prepared_isolated_destination`].
///
/// Returns the area identity the retained lease still holds together with the
/// root derived from the owner's own resolution. The root is derived, never read
/// from the record, and the bound-record check re-proves that the derivation
/// still agrees with what the admission retained.
///
/// This is a pure move of validation steps (1) and (2); it adds no check and
/// removes none, and the caller runs it at exactly the same point in the
/// validation-before-effects order.
fn prove_isolated_area_and_derive_destination(
    admission: &PreparedDestinationAdmission,
    isolated_area_lease: &ProtectedRootLease,
) -> Result<(FileIdentity, String), IsolatedDestinationError> {
    isolated_area_lease
        .verify_stable_identity()
        .map_err(|_| IsolatedDestinationRefusal::IsolatedAreaUnproved)?;
    let observed_area_identity = isolated_area_lease.identity();
    if observed_area_identity != admission.isolation.isolated_area_identity {
        return Err(IsolatedDestinationRefusal::IsolatedAreaUnproved.into());
    }
    let resolved_area = isolated_area_lease
        .canonical_path()
        .map_err(|_| IsolatedDestinationRefusal::IsolatedAreaUnproved)?;
    let resolved_area_text = resolved_area.to_string_lossy().into_owned();
    if !same_windows_root_text(&resolved_area_text, &admission.isolation.isolated_area_root) {
        return Err(IsolatedDestinationRefusal::IsolatedAreaUnproved.into());
    }
    let derived_destination_root = joined_windows_path(
        &resolved_area_text,
        admission.destination_installation.as_str(),
    );
    if !same_windows_root_text(
        &derived_destination_root,
        &admission.isolation.destination_installation_root,
    ) {
        return Err(IsolatedDestinationRefusal::BoundRecordConflict {
            field: "destination_installation_root",
        }
        .into());
    }
    if !matches!(
        classify_installation_host_root(std::path::Path::new(&derived_destination_root)),
        InstallationHostRootClass::Unowned
    ) {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }
    Ok((observed_area_identity, derived_destination_root))
}

/// Re-proves the object now carrying the admitted destination name and returns
/// the identity that gets recorded, for
/// [`materialise_prepared_isolated_destination`].
///
/// `published_identity` is the identity the authority's own publication receipt
/// carries. The created object is re-opened through a fresh no-follow
/// protected-root lease, so a junction swapped in immediately after the move is
/// refused rather than adopted, and the observed identity must equal the
/// published one.
///
/// This is a pure move of check (4); it adds no check and removes none.
fn reprove_created_destination_root(
    admission: &PreparedDestinationAdmission,
    derived_destination_root: &str,
    published_identity: FileIdentity,
) -> Result<FileIdentity, IsolatedDestinationError> {
    let created_lease = ProtectedRootLease::open_existing(std::path::Path::new(
        derived_destination_root,
    ))
    .map_err(|_| {
        IsolatedDestinationError::Installation(InstallationError::IncompleteObservation(
        "the created isolated destination could not be re-proved through a protected-root lease, \
         so its ownership is not established"
            .to_owned(),
    ))
    })?;
    created_lease.verify_stable_identity().map_err(|_| {
        IsolatedDestinationError::Installation(InstallationError::IncompleteObservation(
            "the created isolated destination root did not keep its retained identity".to_owned(),
        ))
    })?;
    let created_path = created_lease.canonical_path().map_err(|_| {
        IsolatedDestinationError::Installation(InstallationError::IncompleteObservation(
            "the created isolated destination root could not be resolved through its retained \
             lease"
                .to_owned(),
        ))
    })?;
    if !same_windows_root_text(
        &created_path.to_string_lossy(),
        &admission.isolation.destination_installation_root,
    ) {
        return Err(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the created isolated destination root does not resolve to the admitted root"
                    .to_owned(),
            ),
        ));
    }
    let destination_root_identity = created_lease.identity();
    if destination_root_identity != published_identity {
        return Err(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the identity observed for the created isolated destination is not the identity \
                 the installation authority published"
                    .to_owned(),
            ),
        ));
    }
    Ok(destination_root_identity)
}

/// Lexical, separator-aware containment over already-resolved Windows paths.
///
/// The inputs are the path the retained lease resolved and the path the owner
/// derived from it, so no comparison is made against caller text.
fn path_is_within(candidate: &str, ancestor: &str) -> bool {
    let candidate_key = candidate.replace('/', "\\").to_lowercase();
    let ancestor_key = ancestor.replace('/', "\\").to_lowercase();
    let prefix = format!("{ancestor_key}\\");
    candidate_key.starts_with(&prefix)
}

/// Separator-aware equality over already-resolved Windows paths.
fn same_windows_root_text(left: &str, right: &str) -> bool {
    left.replace('/', "\\").to_lowercase() == right.replace('/', "\\").to_lowercase()
}
