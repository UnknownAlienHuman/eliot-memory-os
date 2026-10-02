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
//! lease's own stable file identity, the exact result of the owner's own
//! no-follow observation of the destination leaf
//! ([`DestinationLeafObservation`]), and the exact source roots and installation
//! root it is compared against. A predictable name is never ownership.
//!
//! No boolean in either record asserts "absent" or "reparse-free". Such a bit
//! cannot be re-derived by a later reader and would only ever be written `true`
//! by its own issuer, so it is evidence of nothing. What is recorded instead is
//! the observation the owner actually made — [`DestinationLeafObservation`] — and
//! what is re-observed later is compared against THAT recorded value:
//! [`prove_isolated_destination_root`] re-runs the same no-follow observer at
//! materialise time and refuses when the fresh observation disagrees with the
//! recorded one, and the durable store re-observes the created root's identity
//! through a fresh no-follow lease before it retains or hands back a
//! materialisation.
//!
//! `IsolationEvidence::validate` checks INTERNAL CONSISTENCY — shape, non-zero
//! identities, and the content digest recomputed over the recorded content — and
//! deliberately asserts nothing about the filesystem. It is not authenticity:
//! these records are `pub` with `Deserialize`, so an outside writer can
//! recompute a consistent digest over content of its own. Authenticity is the
//! existing owner capability seam — every mutation of this projection requires
//! the live exclusive [`HostOwnerEpochCapability`] this crate already demands of
//! [`RedbInstallationRegistry`] — and no new MAC is introduced here.
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
    ApprovedGeneration, FileIdentity, InstallationError, InstallationHostRootClass, PlatformHandle,
    RuntimeStateRoots, canonical_json_bytes, classify_installation_host_root, handle,
    joined_windows_path, sha256_handle, sha256_hex, text, valid_installation_key,
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

    /// The DESTINATION identity is already an installation this authority holds —
    /// its active installation, one of its approved generations, or a destination
    /// a previous operation already admitted.
    ///
    /// The comparison is destination-against-existing-installations, in that
    /// direction and no other. It is deliberately NOT "the approved target equals
    /// the source's own active generation": a restore into a brand-new distinct
    /// installation is prepared FOR an approved target generation, so that
    /// comparison is one field against itself, it refused every legitimate
    /// destination, and it proved nothing about the destination at all.
    #[error("the destination installation is already present in this authority's projection")]
    ExistingInstallation,

    /// A path this operation would write into is already a foreign owner's
    /// installation contour, so this operation does not own it.
    ///
    /// This is the "preexisting foreign owner is rejected" clause, decided by
    /// the owner against its own DECLARED layout — the installation owner's
    /// `installations_root`, which the owner derives from its validated profile
    /// anchor — and not by the lexical shape of a path. The source's own Host
    /// root must BE an installation Host root of that declared layout (otherwise
    /// the source is a foreign directory and every isolation statement derived
    /// from it is a claim), and the isolated area and the derived destination
    /// leaf must NOT be inside that declared installation contour. A destination
    /// a foreign installation already owns at that name is refused here, never
    /// reused, and never removed by name.
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

/// The owner's own no-follow OBSERVATION of one destination leaf.
///
/// # Why this is an enum and not a boolean
///
/// A `bool` field can only ever be written `true` by the code that constructs
/// the record, so `validate()` comparing it with `true` compares a literal with
/// itself and proves nothing; and no later reader can re-derive it, so it is
/// evidence of nothing either. This enum instead records WHICH observation the
/// owner actually made, from [`observe_destination_leaf`] — the single observer
/// every step of this module uses, which uses `symlink_metadata` so a junction
/// is SEEN rather than followed.
///
/// [`Self::Absent`] is reachable only when that observer ran and reported
/// absence; a record that claims `Present` or `Unobserved` is refused by
/// [`PreparedDestinationMaterialisation::validate`] and
/// [`IsolationEvidence::validate`].
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DestinationLeafObservation {
    /// The leaf was observed to not exist.
    Absent,
    /// The leaf was observed to exist. A junction is reported here too, because
    /// `symlink_metadata` does not follow it.
    Present,
    /// The leaf could not be observed at all, so absence is NOT established.
    Unobserved,
}

impl DestinationLeafObservation {
    /// Current durable wire spelling of this observation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "ABSENT",
            Self::Present => "PRESENT",
            Self::Unobserved => "UNOBSERVED",
        }
    }
}

/// Runs THE single no-follow observation of one destination leaf.
///
/// It is the only place this module looks at the destination leaf's existence,
/// so admission, materialisation and the recorded evidence cannot disagree by
/// construction. `symlink_metadata` does not follow a reparse point, so a
/// junction planted at the destination name is REPORTED as [`Present`] rather
/// than resolved through — a followed link here would be an alias
/// substitution.
///
/// # Errors
///
/// Returns [`InstallationError::IncompleteObservation`] when the leaf cannot be
/// observed at all. That is deliberately distinct from `Absent`: absence of
/// proof is never treated as proof of absence, and a fault here refuses the
/// destination rather than admitting a name nobody could check.
fn observe_destination_leaf(
    destination_root: &str,
) -> Result<DestinationLeafObservation, InstallationError> {
    match std::fs::symlink_metadata(destination_root) {
        Ok(_) => Ok(DestinationLeafObservation::Present),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DestinationLeafObservation::Absent)
        }
        Err(_) => Err(InstallationError::IncompleteObservation(
            "the destination leaf could not be observed, so this operation cannot claim it owns \
             that name"
                .to_owned(),
        )),
    }
}

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
/// owner's own no-follow protected-root lease OBSERVED for the created root,
/// the identity the same lease observed for the isolated area the publication
/// was made under, and the owner's own no-follow observation of the
/// destination leaf immediately before the publication. A predictable name
/// proves nothing — the created object's identity is compared against the
/// publication receipt's own identity before it is recorded, and every reader
/// re-observes it through a fresh no-follow lease before it retains or returns
/// the record, so a row naming a foreign directory fails on the live comparison
/// rather than on its own digest.
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
    /// Identity the owner's no-follow lease observed for the created root.
    ///
    /// This is the load-bearing evidence of ownership, and it is compared by
    /// its consumers: the creation step compares it against the publication
    /// receipt's own `destination_identity`, and
    /// [`crate::RedbInstallationRegistry::read_prepared_isolated_destination_creation`]
    /// plus
    /// [`crate::RedbInstallationRegistry::record_prepared_isolated_destination_creation`]
    /// re-observe it through a fresh no-follow lease before the record is
    /// retained or handed back. A recorded identity that no longer names the
    /// object at the recorded root is refused, not believed.
    pub destination_root_identity: FileIdentity,
    /// The owner's own no-follow observation of the destination leaf taken
    /// immediately before the publication.
    ///
    /// It is a recorded OBSERVATION, not an assertion: the value came from
    /// [`observe_destination_leaf`], the same single observer the pre-effect
    /// proof uses, and [`Self::validate`] requires it to be
    /// [`DestinationLeafObservation::Absent`] — which is only reachable if the
    /// observer ran and said so. See [`DestinationLeafObservation`].
    pub destination_leaf_observation: DestinationLeafObservation,
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
            self.destination_leaf_observation,
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
        destination_leaf_observation: DestinationLeafObservation,
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
            destination_leaf_observation.as_str(),
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

    /// Test-only seam over the private pre-record digest computation.
    ///
    /// A record cannot compute its own digest before it exists, so the ISSUER
    /// path needs [`Self::digest_over_fields`]; a test needs the same value to
    /// build one internally consistent record whose only fault is the field it
    /// varies. This exposes exactly that call and nothing else.
    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the digest covers exactly these fields, and the TEST needs them to build a record"
    )]
    fn computed_digest_for_test(
        wire: &PlatformHandle,
        operation_id: &PlatformHandle,
        destination_installation: &PlatformHandle,
        admission_digest: &PlatformHandle,
        isolated_area_root: &str,
        isolated_area_identity: &FileIdentity,
        destination_installation_root: &str,
        destination_root_identity: &FileIdentity,
        destination_leaf_observation: DestinationLeafObservation,
    ) -> Result<PlatformHandle, InstallationError> {
        Self::digest_over_fields(
            wire,
            operation_id,
            destination_installation,
            admission_digest,
            isolated_area_root,
            isolated_area_identity,
            destination_installation_root,
            destination_root_identity,
            destination_leaf_observation,
        )
    }

    /// Validates the record against its own content and the observation it
    /// claims to have made.
    ///
    /// # What this proves, precisely
    ///
    /// It proves INTERNAL CONSISTENCY: shape, non-zero stable identities, that
    /// the recorded leaf observation really is
    /// [`DestinationLeafObservation::Absent`], and that the recorded digest
    /// equals the digest recomputed over the recorded content. A row that
    /// claims a different destination, a different area, or claims the leaf was
    /// present fails here.
    ///
    /// # What this does NOT prove
    ///
    /// It does not prove AUTHENTICITY. These records are `pub` with
    /// `Deserialize`, so an outside writer can build a row and recompute a
    /// perfectly consistent digest over its own content; that is why the digest
    /// is never described here as making a record non-forgeable. Authenticity is
    /// the existing owner capability seam: only a caller holding the live
    /// exclusive [`HostOwnerEpochCapability`] this crate already requires of
    /// every mutation of this projection may retain or read one, and the readers
    /// re-observe the created root's identity through a fresh no-follow lease.
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
        // The recorded leaf observation is compared against the ONE value that
        // makes this record a creation receipt. `Present` cannot be a creation
        // receipt at all, and `Unobserved` records that the owner never observed
        // the leaf — which is exactly the state a literal `true` used to claim.
        if self.destination_leaf_observation != DestinationLeafObservation::Absent {
            return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
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
/// lease's own observed file identity. The leaf observation records what
/// [`observe_destination_leaf`] actually reported.
///
/// # What a later reader must re-prove
///
/// Three of these fields exist to be COMPARED, and each has a named consumer:
///
/// - [`Self::source_active_generation`] is compared by
///   [`crate::RedbInstallationRegistry::record_prepared_isolated_destination_creation`]
///   against the source installation authority's OWN current active generation.
///   An admission bound to a generation the source has since moved on from is
///   refused as [`crate::InstallationError::IdentityConflict`], which is what
///   stops a stale configuration snapshot from being bound as current.
///
///   The named consumer is the CREATION entry point rather than
///   `record_prepared_isolated_destination` because that is the one production
///   reaches: it delegates to
///   `record_prepared_isolated_destination_unchecked`, which is where the
///   comparison lives. The admission-only wrapper is a real function that
///   performs the same comparison, but nothing outside this crate calls it, so
///   naming it here would name a consumer no reader is served by.
/// - [`Self::source_installation_root`] and [`Self::source_host_root`] are
///   re-compared by [`prove_isolated_destination_root`] at materialise time:
///   the destination is re-proved DISJOINT from the recorded source root, so a
///   source root that was moved under the destination between admission and
///   materialisation is caught before anything is created.
/// - [`Self::destination_leaf_observation`] is re-observed at materialise time
///   by the same [`observe_destination_leaf`] observer and refused when the
///   fresh observation is not [`DestinationLeafObservation::Absent`].
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
    ///
    /// Compared against the authority's own current active generation by
    /// [`crate::RedbInstallationRegistry::record_prepared_isolated_destination_creation`];
    /// a mismatch is refused rather than recorded.
    pub source_active_generation: PlatformHandle,
    /// The owner's own no-follow observation of the destination leaf at
    /// admission time, taken by [`observe_destination_leaf`].
    ///
    /// Re-observed at materialise time by the same observer and refused when it
    /// is not [`DestinationLeafObservation::Absent`].
    pub destination_leaf_observation: DestinationLeafObservation,
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
            self.destination_leaf_observation,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the digest covers exactly these nine fields"
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
        destination_leaf_observation: DestinationLeafObservation,
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
            destination_leaf_observation.as_str(),
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

    /// Validates the evidence against its own content and the observation it
    /// claims to have made.
    ///
    /// # What this proves, precisely
    ///
    /// Shape, non-zero stable identities, that the recorded leaf observation is
    /// [`DestinationLeafObservation::Absent`], and that the recorded digest
    /// equals the digest recomputed over the recorded content. A row that names
    /// another source, another destination, or claims the leaf was present or
    /// unobserved fails here.
    ///
    /// # What this does NOT prove
    ///
    /// It does not prove AUTHENTICITY — these records are `pub` with
    /// `Deserialize`, so an outside writer can recompute a consistent digest over
    /// its own content, which is why this function is never described as making
    /// a record non-forgeable. Authenticity is the existing owner capability
    /// seam, and the fields that can go stale against the live authority
    /// ([`Self::source_active_generation`], [`Self::source_installation_root`],
    /// [`Self::source_host_root`]) are compared by the registry and by
    /// [`prove_isolated_destination_root`] rather than believed here.
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
        if self.destination_leaf_observation != DestinationLeafObservation::Absent {
            return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
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
    /// Every APPROVED generation this installation authority holds, with each
    /// row's own activation approval.
    ///
    /// The approved target is resolved from THIS set rather than handed in as a
    /// loose manifest/approval pair. That is what makes the approved-target
    /// proof non-vacuous: the caller cannot present a manifest and an approval
    /// that merely agree with each other, it can only point at a generation the
    /// authority itself already approved, and the approval is then compared
    /// against the manifest of that very row through the crate's existing
    /// [`validate_approval_against_manifest`](crate::approved_generation_registry::validate_approval_against_manifest).
    ///
    /// The set is the authority's own projection, read by the caller from the
    /// registry it already inspected; an empty set refuses every destination,
    /// because a destination with no approved target build is not admitted.
    pub approved_generations: &'a [ApprovedGeneration],
    /// Approved target generation this destination is being prepared FOR, as a
    /// handle into [`Self::approved_generations`].
    ///
    /// A destination installation does not exist yet, so this authority has no
    /// approved generation FOR it; the build a restore is prepared for is the
    /// currently approved build of the installation that owns the archive. That
    /// handle therefore normally equals [`Self::source_active_generation`], and
    /// no inequality is demanded here — the DESTINCTNESS of the destination is
    /// decided by the destination identity and by the derived root, not by the
    /// approved target differing from the source. A handle that names no row in
    /// the approved set is refused.
    pub approved_target_generation: &'a PlatformHandle,
    /// Owner-issued restoration requirements for this destination.
    pub restoration_requirements: &'a ProposedRestorationRequirements,
    /// Current purge-ledger revision read from the ORS purge-ledger owner.
    pub current_purge_ledger_revision: u64,
    /// Installation identities this authority already holds. Used to refuse an
    /// existing installation as the destination.
    ///
    /// This is the EXISTING-INSTALLATION set, and it is compared against the
    /// destination identity and nothing else.
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
/// 4. the DESTINATION identity is not one of the installation identities this
///    authority already holds — the active installation, every approved
///    generation's installation, or every destination already admitted as
///    prepared. That is the whole of the "existing installation" clause, and it
///    is a comparison in that direction only;
/// 5. the approved target is a generation THIS authority holds in
///    [`IsolatedDestinationAdmissionInput::approved_generations`] — so a caller
///    cannot present a manifest and an approval that merely agree with each other —
///    and that row's own activation approval is compared against that row's own
///    manifest through the crate's existing
///    [`validate_approval_against_manifest`](crate::approved_generation_registry::validate_approval_against_manifest).
///    Distinctness is NOT decided here: the destination installation does not
///    exist yet, so the build it is prepared for legitimately is the currently
///    approved build of the source's own installation, and check 4 plus the
///    derived root are what make the destination a distinct installation;
/// 6. the owner-declared isolated restore area resolves through its retained
///    no-follow protected-root lease to exactly the declared root, and the
///    destination root derived from it is strictly inside the area and neither
///    contains, is contained by, nor equals the source installation root; the
///    owner's own layout classification, decided against its DECLARED
///    `installations_root`, additionally requires the source Host root to BE an
///    installation Host root and requires the area and the derived leaf NOT to be
///    inside that declared installation contour, which is the "preexisting
///    foreign owner" clause decided by the owner rather than by a name;
/// 7. the destination leaf is OBSERVED absent by the single no-follow observer
///    [`observe_destination_leaf`], so the allocation is new and distinct rather
///    than a reuse or a delete by name;
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
#[allow(
    clippy::too_many_lines,
    reason = "the admission keeps the validation-before-effects order in one auditable sequence"
)]
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

    // 4. The DESTINATION identity is compared against the EXISTING-INSTALLATION
    //    set and nothing else. That set covers the ACTIVE installation, every
    //    previously approved generation's installation identity, and every
    //    destination already admitted as prepared. It is the only comparison that
    //    decides "already an installation": comparing the APPROVED TARGET with the
    //    source's own active generation answers a different question, and in the
    //    production shape both values were the same field of the same record, so it
    //    refused every destination while proving nothing about it.
    if input
        .known_installations
        .iter()
        .any(|known| known == &destination_key)
    {
        return Err(IsolatedDestinationRefusal::ExistingInstallation.into());
    }

    // 5. The approved target build/profile is proved BEFORE anything is
    //    allocated, and it is proved against the AUTHORITY'S OWN APPROVED SET.
    //    A loose manifest/approval pair would only prove that two caller-presented
    //    values agree with each other; resolving the target out of the set the
    //    authority retains proves it is a generation this authority approved. The
    //    approval is then compared against THAT row's own manifest with the
    //    crate's existing binding validator, so the row's internal consistency is
    //    established by the same code that established it when it was committed.
    //    The approval's only constructor is crate-private and its production
    //    issuer is the signed activation bridge, so no caller can present one.
    let approved_target = input
        .approved_generations
        .iter()
        .find(|generation| &generation.manifest.generation == input.approved_target_generation)
        .ok_or(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the approved target generation is not one this installation authority approves"
                    .to_owned(),
            ),
        ))?;
    crate::approved_generation_registry::validate_approval_against_manifest(
        &approved_target.approval,
        &approved_target.manifest,
        "prepared_destination.approved_target",
    )?;
    let approved_target_build = approved_target.manifest.generation.clone();
    // The approved target is NOT compared for inequality against the source's
    // active generation. A destination installation does not exist yet, so this
    // authority has no approved generation FOR it: the build a restore is prepared
    // for is the currently approved build of the installation that owns the
    // archive, and that legitimately equals the source's active generation. The
    // DISTINCTNESS of the destination is decided by check 4 — the destination
    // identity against the existing-installation set — and by the derived root
    // being a genuinely different object outside the source installation. The
    // previous form compared `manifest.generation` with the source's active
    // generation, which in the production caller were the same field of the same
    // `ApprovedGeneration`, so it was `a == a`: it refused every destination and
    // proved nothing about the destination.
    //
    // What genuinely is checked here is that the target handle named a row this
    // authority approves, and that the row's own approval binds that row's
    // manifest — a comparison between the authority's retained records and the
    // caller's claim, not a field against itself.

    // 6. The owner-declared isolated restore area, proved through the retained
    //    no-follow lease the caller already holds, and the destination root
    //    DERIVED from it. I5.13's "restore to isolated root" is therefore a
    //    position inside an owner-declared area, never a supplied name.
    input.source_roots.validate()?;
    // 5b. The "preexisting foreign owner" clause, decided by the owner against its
    //     own DECLARED installations root -- the root the owner derives from its
    //     validated profile anchor -- rather than against a path component NAME.
    //     The previous form searched for a component spelled `installations` and
    //     reported `Unowned` for everything else, which made both arms
    //     unreachable: the owner-declared isolated restore area is a SIBLING of
    //     `installations`, so every derived leaf was lexically guaranteed
    //     `Unowned`. Against the declared root, the answer is a property of the
    //     LAYOUT and the arm can fire.
    //
    //     The source's Host root must really BE an installation Host root of that
    //     declared layout -- if it is not, the source is a foreign directory and
    //     every isolation statement derived from its roots is a claim, not a fact.
    //     The isolated area and the derived destination leaf must NOT be inside
    //     that declared installation contour, because a destination some foreign
    //     installation already owns is not a new distinct isolated installation.
    //     The classification is pure layout containment: it observes no
    //     filesystem, so existence and reparse freedom stay the protected-root
    //     lease's proof, composed on top.
    let declared_installations_root = input.source_roots.installations_root()?;
    if !classify_installation_host_root(
        std::path::Path::new(input.source_roots.host_state_root.as_str()),
        &declared_installations_root,
    )?
    .is_installation_host_root()
    {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }
    let declared_area = input.source_roots.isolated_restore_root()?;
    if !matches!(
        classify_installation_host_root(
            std::path::Path::new(declared_area.as_str()),
            &declared_installations_root,
        )?,
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

    // The destination must be STRICTLY inside the area (the area itself is not a
    // destination) and must neither contain, be contained by, nor equal the
    // source installation root: I5.13's isolated root, A13.7's isolated area.
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
    // The derived leaf is classified against the SAME declared installations root
    // before it is observed: a destination that resolves inside some
    // installation's own contour belongs to that installation, whatever this
    // operation intends to write there.
    if !matches!(
        classify_installation_host_root(
            std::path::Path::new(&destination_installation_root),
            &declared_installations_root,
        )?,
        InstallationHostRootClass::Unowned
    ) {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }

    // 7. The allocation must be NEW and DISTINCT, and the owner OBSERVES that
    //    rather than inferring it from a name: a leaf that already exists is not
    //    owned by this operation, so it is refused -- never reused, and never
    //    deleted by path name.
    //
    //    The observation is THE single no-follow observer this module uses, and
    //    its RESULT is what the evidence records. The previous `Path::exists`
    //    check is not equivalent: it FOLLOWS a reparse point, so a junction
    //    planted at the destination name could be resolved through and reported
    //    absent while the record claimed a non-existent name nobody inspected.
    let destination_leaf_observation = observe_destination_leaf(&destination_installation_root)
        .map_err(IsolatedDestinationError::Installation)?;
    if destination_leaf_observation != DestinationLeafObservation::Absent {
        return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
    }

    // 8. Restoration requirements are the installation authority's own record,
    //    issued from the owner-issued facts. They are re-validated here and must
    //    admit exactly the bound archive class, the bound target schema and no
    //    fewer bytes than the owner admitted, so a destination cannot be widened.
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

    // The profile token is read off the APPROVED TARGET's own launch contour --
    // the generation this destination is prepared for -- not off the source, so
    // it changes with the target rather than being a copy of the source's own
    // value.
    let profile_token = match approved_target.manifest.runtime_launch.profile {
        super::InstallationProfile::SystemService => "system_service",
        super::InstallationProfile::UserMode => "user_mode",
        super::InstallationProfile::PortableDev => "portable_dev",
    };
    let approved_target_profile =
        PlatformHandle::new(profile_token).map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.approved_target_profile".to_owned(),
            reason: error.to_string(),
        })?;

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
        isolated_area_identity: area_identity,
        destination_installation_root: destination_installation_root.clone(),
        destination_installation_key: destination_key.clone(),
        source_installation_root: source_installation_root.clone(),
        source_host_root: source_host_root.clone(),
        source_active_generation: input.source_active_generation.clone(),
        destination_leaf_observation,
        evidence_digest: IsolationEvidence::digest_over_fields(
            &isolation_wire,
            &resolved_area_text,
            &area_identity,
            &destination_installation_root,
            &destination_key,
            &source_installation_root,
            &source_host_root,
            input.source_active_generation,
            destination_leaf_observation,
        )?,
    };
    isolation.validate()?;

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
        &destination_key,
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
        destination_installation: destination_key,
        destination_installation_root,
        admission,
    })
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
///    observed through a fresh no-follow protected-root lease, compared with the
///    publication receipt's own `destination_identity`, and RECORDED -- and the
///    durable store re-observes it again through
///    [`RedbInstallationRegistry::record_prepared_isolated_destination_creation`]
///    and
///    [`RedbInstallationRegistry::read_prepared_isolated_destination_creation`]
///    before it retains or hands the record back, so a later reader compares the
///    LIVE identity with the recorded one instead of trusting the row.
///
/// The recorded destination name is never used as the ownership argument: the
/// record carries an identity, and re-running this function against a name that
/// a foreign owner now holds is refused at step 1 of
/// [`OwnedDirectoryPublication::create`] rather than adopted.
///
/// # What else is re-proved here
///
/// The pre-effect proof also re-derives the destination from the retained lease
/// AND re-checks the isolation the admission claimed, so the admission-time
/// geometry is not assumed to still hold:
///
/// - the destination root is RE-DERIVED from the lease's live resolution and
///   compared with the recorded one;
/// - it is re-proved DISJOINT from the recorded source installation root and from
///   the recorded source Host root, so a source root moved under the destination
///   between admission and materialisation is refused before anything is created;
/// - the leaf is RE-OBSERVED by the single no-follow
///   [`observe_destination_leaf`] observer, so a junction planted at the admitted
///   name after admission is SEEN (`Present`) rather than followed, and the fresh
///   observation must be [`DestinationLeafObservation::Absent`].
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

    // Everything before the create is one pre-effect proof of WHAT this
    // operation would own; everything after it is one create-and-re-prove. The
    // split is along the effect boundary, so each half is still one ordered
    // sequence and neither can run without the other.
    let proved = prove_isolated_destination_root(admission, isolated_area_lease)?;
    let derived_destination_root = proved.destination_root;
    let observed_area_identity = proved.isolated_area_identity;
    // The fresh no-follow observation, carried out of the pre-effect proof, is
    // what the materialisation RECORDED. It is the same observer the admission
    // used and the same value class, so the two records cannot disagree by
    // construction and neither can claim a boolean nobody observed.
    let destination_leaf_observation = proved.destination_leaf_observation;

    let destination_root_identity = create_and_reprove_isolated_destination_root(
        &derived_destination_root,
        &admission.isolation.destination_installation_root,
        &observed_area_identity,
    )?;

    let materialisation_wire = PlatformHandle::new(PreparedDestinationMaterialisation::WIRE)
        .map_err(|error| InstallationError::InvalidField {
            field: "prepared_destination.materialisation.wire".to_owned(),
            reason: error.to_string(),
        })?;
    // The commitment is computed from the values themselves BEFORE the record
    // exists, so the record is built once with its real digest rather than with
    // a placeholder that would have to be a second, weaker value type.
    let materialisation_digest = PreparedDestinationMaterialisation::digest_over_fields(
        &materialisation_wire,
        &admission.operation_id,
        &admission.destination_installation,
        &admission.admission_digest,
        &admission.isolation.isolated_area_root,
        &observed_area_identity,
        &derived_destination_root,
        &destination_root_identity,
        destination_leaf_observation,
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
        destination_leaf_observation,
        materialisation_digest,
    };
    materialisation.validate()?;
    Ok(materialisation)
}

/// The root this operation would create, proved BEFORE any directory exists.
///
/// This is the pre-effect half of [`materialise_prepared_isolated_destination`]:
/// it derives the destination root from the retained lease rather than from the
/// caller, checks it against the owner's own recorded root, refuses a foreign
/// installation's contour, and observes the leaf absent itself. It creates
/// nothing, so every refusal it returns is pre-effect and preserves the created
/// root question entirely: there is no created root yet.
struct ProvedIsolatedDestinationRoot {
    /// Owner-derived destination root, never caller text.
    destination_root: String,
    /// Identity the retained lease observed for the isolated area.
    isolated_area_identity: FileIdentity,
    /// The fresh no-follow observation of the destination leaf, which the
    /// materialisation records verbatim.
    destination_leaf_observation: DestinationLeafObservation,
}

/// Proves which root the admission authorises, before anything is created.
///
/// # Errors
///
/// Returns the same refusal classes as
/// [`materialise_prepared_isolated_destination`]'s pre-create sequence, for the
/// same reasons and in the same order; none of them is reclassified, widened or
/// turned into a different refusal by this split.
fn prove_isolated_destination_root(
    admission: &PreparedDestinationAdmission,
    isolated_area_lease: &ProtectedRootLease,
) -> Result<ProvedIsolatedDestinationRoot, IsolatedDestinationError> {
    // (1) and (2): the retained lease must still be the object and the path the
    // admission was proved against, and the destination root is re-derived from
    // that resolution rather than taken from the record.
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
    // The isolation the admission claimed is RE-PROVED here rather than assumed to
    // still hold. `IsolationEvidence::source_installation_root` and
    // `IsolationEvidence::source_host_root` exist to be compared, and this is
    // their consumer: a source root moved under the destination between
    // admission and materialisation is refused before anything is created,
    // rather than discovered later as a restore that read its own source.
    for (recorded_source_root, field) in [
        (
            &admission.isolation.source_installation_root,
            "source_installation_root",
        ),
        (&admission.isolation.source_host_root, "source_host_root"),
    ] {
        if same_windows_root_text(&derived_destination_root, recorded_source_root)
            || path_is_within(&derived_destination_root, recorded_source_root)
            || path_is_within(recorded_source_root, &derived_destination_root)
        {
            return Err(IsolatedDestinationRefusal::BoundRecordConflict { field }.into());
        }
    }
    // The derived leaf is classified against the SAME declared layout, resolved
    // from the source roots the admission recorded, so a destination that a
    // foreign installation owns at that name is refused here and never adopted.
    let declared_installations_root = declared_installations_root_for_recorded_source(admission)?;
    if !matches!(
        classify_installation_host_root(
            std::path::Path::new(&derived_destination_root),
            &declared_installations_root,
        )?,
        InstallationHostRootClass::Unowned
    ) {
        return Err(IsolatedDestinationRefusal::ForeignInstallationOwner.into());
    }

    // The owner must observe absence itself, immediately before the create, with
    // THE single no-follow observer -- the same one the admission used. A name a
    // caller can predict is not evidence that this operation owns it, so a leaf
    // that is present -- including a junction, which `symlink_metadata` reports
    // without following -- is refused, never reused and never removed.
    let destination_leaf_observation = observe_destination_leaf(&derived_destination_root)
        .map_err(IsolatedDestinationError::Installation)?;
    // The fresh observation is compared with the value the admission RECORDED, so
    // the recorded evidence is what the reader re-checks rather than a constant.
    // Both values must be `Absent`: `Absent` is the only observation that makes
    // this a new distinct allocation rather than a reuse of somebody else's name,
    // and a leaf that appeared between admission and materialisation is exactly
    // that case.
    if destination_leaf_observation != admission.isolation.destination_leaf_observation
        || destination_leaf_observation != DestinationLeafObservation::Absent
    {
        return Err(IsolatedDestinationRefusal::DestinationNotAbsent.into());
    }

    Ok(ProvedIsolatedDestinationRoot {
        destination_root: derived_destination_root,
        isolated_area_identity: observed_area_identity,
        destination_leaf_observation,
    })
}

/// Re-derives the owner-declared `installations_root` from the source roots the
/// admission recorded, so the materialise-time layout classification is decided
/// against the SAME declared root the admission used rather than a value the
/// caller supplies again.
///
/// The admission does not serialize the whole `RuntimeStateRoots` — only the two
/// source paths it compares against — so this derives the shared installation
/// area from the recorded source installation root itself: the owner-declared
/// layout is `<installations_root>\<installation key>`, so the parent of a
/// validated installation root IS the declared installations root. That keeps the
/// derivation in the installation authority, out of the durable record, and out
/// of the caller's hands.
///
/// # Errors
///
/// [`InstallationError::IncompleteObservation`] when the recorded source
/// installation root is not a well-formed Windows root, which means the
/// admission cannot be re-classified and therefore must not be materialised.
fn declared_installations_root_for_recorded_source(
    admission: &PreparedDestinationAdmission,
) -> Result<PlatformHandle, IsolatedDestinationError> {
    let recorded = admission.isolation.source_installation_root.clone();
    let parent = std::path::Path::new(recorded.as_str())
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .filter(|parent| !parent.is_empty())
        .ok_or_else(|| {
            IsolatedDestinationError::Installation(InstallationError::IncompleteObservation(
                "the recorded source installation root has no parent, so the declared \
                 installations root cannot be re-derived"
                    .to_owned(),
            ))
        })?;
    PlatformHandle::new(parent).map_err(|error| {
        IsolatedDestinationError::Installation(InstallationError::InvalidField {
            field: "prepared_destination.isolation.source_installation_root".to_owned(),
            reason: error.to_string(),
        })
    })
}

/// Creates the proved root and re-proves the created object, then reports the
/// identity that may be recorded.
///
/// This is the effecting half of [`materialise_prepared_isolated_destination`].
/// It creates through the installation authority's own create-new owned-directory
/// publication -- never a bare `create_dir` -- and re-proves the created object
/// through a fresh reparse-free protected-root lease before returning, so the
/// identity the caller records is the one the owner observed rather than the one
/// the caller expected.
///
/// # Errors
///
/// Returns the same typed failures, in the same order and for the same reasons,
/// as the create-and-re-prove sequence it was split from. A publication that
/// committed but whose identity could not be read back is still reported as an
/// installation uncertainty with the created root PRESERVED: it is never removed
/// by path name.
fn create_and_reprove_isolated_destination_root(
    derived_destination_root: &str,
    admitted_destination_root: &str,
    observed_area_identity: &FileIdentity,
) -> Result<FileIdentity, IsolatedDestinationError> {
    // The installation authority's own create-new owned-directory publication.
    let publication = OwnedDirectoryPublication::create(std::path::Path::new(
        derived_destination_root,
    ))
    // Every arm is ONE typed failure, [`IsolatedDestinationError`]: a refusal
    // class stays a distinct `Refused` variant and is never widened into a
    // message, and the authority's own publication fault stays a typed
    // `Installation` fault. The two types are never returned side by side from
    // one `match`, so the layer boundary has a single error type.
    .map_err(|error| match error {
        // A destination that already existed by the time the owner
        // created it, including a concurrent create race, is not owned
        // by this operation.
        DirectoryPublicationError::AlreadyExists => {
            IsolatedDestinationError::Refused(IsolatedDestinationRefusal::DestinationNotAbsent)
        }
        DirectoryPublicationError::ReparsePoint => {
            IsolatedDestinationError::Refused(IsolatedDestinationRefusal::ForeignInstallationOwner)
        }
        other => IsolatedDestinationError::Installation(InstallationError::Platform(format!(
            "the installation authority could not create the isolated destination: {other}"
        ))),
    })?;

    // (3): the creating code path's own independent measurement of the parent
    // object must equal what the retained lease holds.
    if publication.parent_identity() != *observed_area_identity {
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
    if !same_windows_root_text(&created_path.to_string_lossy(), admitted_destination_root) {
        return Err(IsolatedDestinationError::Installation(
            InstallationError::IncompleteObservation(
                "the created isolated destination root does not resolve to the admitted root"
                    .to_owned(),
            ),
        ));
    }
    let destination_root_identity = created_lease.identity();
    if destination_root_identity != receipt.destination_identity {
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

#[cfg(test)]
mod tests {
    // A test asserts with `assert!`/`assert_eq!` rather than `expect`, so a
    // fixture fault reports as a failure with its own message instead of a
    // panic from a helper. The workspace lint denies `expect_used` outside
    // tests, and this module keeps the same rule inside them.
    #![allow(
        clippy::expect_used,
        reason = "tests assert deliberately and name the fixture fault they rule out"
    )]

    use super::{
        DestinationLeafObservation, IsolatedDestinationError, IsolatedDestinationRefusal,
        PreparedDestinationMaterialisation, observe_destination_leaf,
    };
    use crate::{FileIdentity, InstallationError, PlatformHandle};

    /// A syntactically valid identity, so a refusal under test is the
    /// OBSERVATION arm and never a zero-identity arm.
    fn observed_identity(volume_serial_number: u32, file_index: u64) -> FileIdentity {
        FileIdentity {
            volume_serial_number,
            file_index,
        }
    }

    /// A fixed-shape lowercase hex handle. The test never depends on WHICH
    /// value it is, only that the record under test is well formed.
    fn handle(value: &str) -> PlatformHandle {
        let mut padded = value.to_owned();
        padded.push_str(&"0".repeat(64usize.saturating_sub(value.len())));
        PlatformHandle::new(padded).expect("a 64-character handle is well formed")
    }

    /// One internally consistent materialisation, so only the recorded
    /// OBSERVATION varies between cases and every other arm is satisfied.
    ///
    /// The recorded paths are never read: `validate` checks their SHAPE, and
    /// the filesystem comparison this record exists for happens in the
    /// registry seams that hold a live lease, not here.
    fn consistent_materialisation(
        observation: DestinationLeafObservation,
    ) -> Result<PreparedDestinationMaterialisation, IsolatedDestinationError> {
        // The wire discriminator is the one value `validate` compares against a
        // constant, so the fixture uses the real one and varies nothing else.
        let wire =
            PlatformHandle::new(PreparedDestinationMaterialisation::WIRE).map_err(|error| {
                IsolatedDestinationError::Installation(InstallationError::InvalidField {
                    field: "prepared_destination.materialisation.wire".to_owned(),
                    reason: error.to_string(),
                })
            })?;
        let operation_id = handle("1111");
        let destination_installation = handle("2222");
        let admission_digest = handle("3333");
        let isolated_area_root = r"C:\ProgramData\Eliot\installations-isolated".to_owned();
        let isolated_area_identity = observed_identity(7, 11);
        let destination_root = r"C:\ProgramData\Eliot\installations-isolated\a1b2c3".to_owned();
        let destination_root_identity = observed_identity(7, 13);
        let materialisation_digest = PreparedDestinationMaterialisation::computed_digest_for_test(
            &wire,
            &operation_id,
            &destination_installation,
            &admission_digest,
            &isolated_area_root,
            &isolated_area_identity,
            &destination_root,
            &destination_root_identity,
            observation,
        )?;
        Ok(PreparedDestinationMaterialisation {
            wire,
            operation_id,
            destination_installation,
            admission_digest,
            isolated_area_root,
            isolated_area_identity,
            destination_installation_root: destination_root,
            destination_root_identity,
            destination_leaf_observation: observation,
            materialisation_digest,
        })
    }

    /// The refusal class is reachable at all: without a NON-absent observation
    /// there is nothing for [`IsolatedDestinationRefusal::DestinationNotAbsent`]
    /// to fire on in a materialisation, which is the state a literal `true` left
    /// the record in.
    #[test]
    fn materialisation_refuses_a_present_leaf_with_the_refusal_class() {
        let record = consistent_materialisation(DestinationLeafObservation::Present)
            .expect("the fixture itself is internally consistent");
        assert!(
            matches!(
                record.validate(),
                Err(IsolatedDestinationError::Refused(
                    IsolatedDestinationRefusal::DestinationNotAbsent
                ))
            ),
            "a present leaf is a refusal class, not an installation fault"
        );
    }

    /// A record whose ONLY fault is the recorded leaf observation is accepted
    /// when it is `Absent` and refused for every other value.
    ///
    /// This is exactly the arms a `bool` could never reach: `Present` and
    /// `Unobserved` are distinct recorded values, each of which `validate` must
    /// refuse. A construction that could only ever write `true` had nothing to
    /// refuse here, so the check proved nothing about the row.
    #[test]
    fn materialisation_accepts_only_the_observed_absent_leaf() {
        let absent = consistent_materialisation(DestinationLeafObservation::Absent)
            .expect("an absent observation is a creation receipt");
        assert!(
            absent.validate().is_ok(),
            "an Absent observation with a matching digest is a valid creation receipt"
        );
        for refused in [
            DestinationLeafObservation::Present,
            DestinationLeafObservation::Unobserved,
        ] {
            let record = consistent_materialisation(refused)
                .expect("the fixture itself is internally consistent");
            assert_eq!(
                record.validate(),
                Err(IsolatedDestinationRefusal::DestinationNotAbsent.into()),
                "{refused:?} must be refused as a destination leaf that is not an absent new name"
            );
        }
    }

    /// Every observation is INSIDE the digest, so a record whose content no
    /// longer matches its recorded digest is refused ON THE DIGEST rather than
    /// accepted because the field that happened to be edited has no semantic
    /// arm of its own.
    ///
    /// The edited field is the isolated area ROOT, deliberately: the
    /// observation has its own earlier arm, so editing the observation would be
    /// refused for the reason this test is not about. Editing a field with no
    /// semantic arm leaves the digest as the only possible detector, which is
    /// precisely the claim under test.
    #[test]
    fn materialisation_digest_binds_the_recorded_content() {
        let mut edited = consistent_materialisation(DestinationLeafObservation::Absent)
            .expect("the fixture itself is internally consistent");
        edited.isolated_area_root.push_str("\\swapped");
        match edited.validate() {
            Err(IsolatedDestinationError::Installation(InstallationError::InvalidField {
                field,
                ..
            })) => assert_eq!(
                field, "prepared_destination.materialisation.materialisation_digest",
                "the digest is the only thing that can detect this edit"
            ),
            other => panic!("the digest must be the refusal: {other:?}"),
        }
    }

    /// An observation edited behind the record's back is caught by its OWN arm
    /// and never reaches a digest comparison.
    #[test]
    fn edited_observation_is_refused_by_its_own_arm() {
        let mut edited = consistent_materialisation(DestinationLeafObservation::Absent)
            .expect("the fixture itself is internally consistent");
        edited.destination_leaf_observation = DestinationLeafObservation::Present;
        assert_eq!(
            edited.validate(),
            Err(IsolatedDestinationRefusal::DestinationNotAbsent.into())
        );
    }

    /// Every non-`Absent` observation is distinguishable on the wire, so a
    /// recorded value cannot be silently read back as another one.
    #[test]
    fn leaf_observation_wire_values_are_distinct() {
        let rendered = [
            DestinationLeafObservation::Absent,
            DestinationLeafObservation::Present,
            DestinationLeafObservation::Unobserved,
        ]
        .map(DestinationLeafObservation::as_str);
        assert_eq!(rendered, ["ABSENT", "PRESENT", "UNOBSERVED"]);
        for observation in [
            DestinationLeafObservation::Absent,
            DestinationLeafObservation::Present,
            DestinationLeafObservation::Unobserved,
        ] {
            let encoded = serde_json::to_string(&observation)
                .expect("the observation serializes as a unit variant");
            assert_eq!(encoded, format!("\"{}\"", observation.as_str()));
        }
    }

    /// The observer itself is exercised against a REAL leaf, so the enum is not
    /// only a value the fixtures choose.
    ///
    /// The three arms under test are the ones a caller can actually reach:
    /// a name nobody created, a name that is a real directory, and a name that
    /// is a real FILE. A file matters because `exists()`-style reasoning about
    /// "is this a directory" is not what this observer claims; it claims
    /// whether the NAME is taken at all, and a destination that is a file is
    /// just as much a name this operation does not own.
    #[test]
    fn leaf_observer_reports_absence_and_presence_on_a_real_path() {
        let base = std::env::temp_dir().join(format!(
            "eliot-leaf-observer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&base).expect("the observer fixture root is creatable");
        let absent = base.join("absent-leaf");
        assert_eq!(
            observe_destination_leaf(&absent.to_string_lossy()),
            Ok(DestinationLeafObservation::Absent),
            "a name nobody created is the only observation that admits a new allocation"
        );
        let directory = base.join("directory-leaf");
        std::fs::create_dir(&directory).expect("the directory leaf is creatable");
        assert_eq!(
            observe_destination_leaf(&directory.to_string_lossy()),
            Ok(DestinationLeafObservation::Present)
        );
        let file = base.join("file-leaf");
        std::fs::write(&file, b"occupied").expect("the file leaf is creatable");
        assert_eq!(
            observe_destination_leaf(&file.to_string_lossy()),
            Ok(DestinationLeafObservation::Present),
            "a file at the destination name is still a name this operation does not own"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The owner-declared LAYOUT decides the installation classification, and
    /// the declared root is the one the owner's own root topology derives.
    ///
    /// This is the arm the name-based predecessor could never reach: it asked
    /// whether some component happened to be spelled `installations`, and the
    /// isolated restore area is a SIBLING of that component, so every derived
    /// destination was lexically guaranteed to be outside. Compared against the
    /// declared root, a path that IS inside the installation area is recognised
    /// as such and refused, while the area itself is outside it and admitted —
    /// so both directions of the decision are observable rather than one.
    #[test]
    fn declared_layout_classification_separates_the_area_from_an_installation_contour() {
        use crate::{InstallationHostRootClass, classify_installation_host_root};

        let declared = handle_installations_root();
        let installation_key = "a".repeat(64);
        let area = r"C:\ProgramData\Eliot\isolated-restore";
        let classified = |path: &str| {
            classify_installation_host_root(std::path::Path::new(path), &declared)
                .expect("both paths are comparable Windows roots")
        };

        assert_eq!(
            classified(area),
            InstallationHostRootClass::Unowned,
            "the owner-declared isolated area is a sibling of the installations root, so it is \
             outside every installation contour"
        );
        assert_eq!(
            classified(&format!(r"{area}\\{installation_key}")),
            InstallationHostRootClass::Unowned,
            "the derived destination leaf under the area is likewise outside every installation \
             contour, which is what makes it a legal destination at all"
        );
        assert_eq!(
            classified(&format!(
                r"{}\installations\{installation_key}\host",
                r"C:\ProgramData\Eliot"
            )),
            InstallationHostRootClass::InstallationHostRoot,
            "a real installation Host root of the declared layout is recognised"
        );
        assert_eq!(
            classified(&format!(
                r"{}\installations\{installation_key}",
                r"C:\ProgramData\Eliot"
            )),
            InstallationHostRootClass::InstallationArea,
            "the installation key itself is the installation's own area"
        );
        assert_eq!(
            classified(r"C:\ProgramData\Eliot\installations\not-a-key"),
            InstallationHostRootClass::Unowned,
            "a component that is not an owner installation key names no installation"
        );
        assert_eq!(
            classified(r"C:\ProgramData\Eliot\installations"),
            InstallationHostRootClass::InstallationArea,
            "the declared installations root is the area, not any installation's Host root"
        );
        assert_eq!(
            classified(r"C:\Somewhere\Else\key\host"),
            InstallationHostRootClass::Unowned,
            "a path outside the declared root is outside every installation contour"
        );
    }

    /// A path that cannot be compared at all is a FAULT, never `Unowned`.
    ///
    /// `Unowned` means "the owner looked, and this path is outside the declared
    /// installation area". Returning it for a path the owner could not even
    /// parse would make an unparseable caller input indistinguishable from a
    /// proven-outside one, and the admission would proceed on a name nobody
    /// classified.
    #[test]
    fn declared_layout_classification_refuses_an_uncomparable_path() {
        use crate::{InstallationError, classify_installation_host_root};

        let declared = handle_installations_root();
        for unparseable in ["relative\\path", r"\\?\C:\verbatim", "C:no-root"] {
            assert!(
                matches!(
                    classify_installation_host_root(std::path::Path::new(unparseable), &declared),
                    Err(InstallationError::InvalidField { .. })
                ),
                "{unparseable} is not a comparable Windows root, so it must be a fault"
            );
        }
        assert!(
            matches!(
                classify_installation_host_root(
                    std::path::Path::new(r"C:\ProgramData\Eliot\installations\a\host"),
                    &crate::PlatformHandle::new("relative-installations-root")
                        .expect("a non-blank handle is constructible"),
                ),
                Err(InstallationError::InvalidField { .. })
            ),
            "an unparseable DECLARED root makes every classification unprovable"
        );
    }

    /// The declared installations root is derived, not spelled out twice.
    ///
    /// `RuntimeStateRoots::installations_root` is the owner's own declaration,
    /// and the installer hierarchy publishes exactly that value, so the
    /// admission's classification root and the root the installer creates one
    /// leaf at a time can never drift apart.
    ///
    /// Windows-gated because both fixtures resolve a REAL retained OS contour:
    /// `ProgramData` through `protected_program_data_root` and the portable
    /// root through a `UserOwnedRootReadLease` over a root this operation
    /// creates AND provisions with the user-owned protected DACL that read lease
    /// requires. The DERIVATION under test is platform-independent, but the
    /// contours it is derived from are not, so on another platform there is
    /// nothing to assert and the two `ProfileViolation` arms below are still
    /// covered by the derivation itself refusing `portable_dev` before it
    /// touches the OS.
    #[cfg(windows)]
    #[test]
    fn declared_installations_root_is_derived_and_shared_with_the_hierarchy() {
        use crate::{InstallationProfile, RuntimeStateRoots};

        let system = profiled_system_roots();
        let declared = system
            .installations_root()
            .expect("a profiled root declares an installations root");
        assert_eq!(
            declared.as_str(),
            format!(
                r"{}\Eliot\installations",
                system.profile_anchor_root.as_str()
            ),
            "the declared root is the profile-root-derived installations area"
        );
        assert!(
            system
                .installation_root
                .as_str()
                .starts_with(declared.as_str())
                && system.installation_root.as_str() != declared.as_str(),
            "the declared area strictly CONTAINS this installation root rather than being it"
        );
        let area = system
            .isolated_restore_root()
            .expect("a profiled root declares an isolated restore area");
        assert!(
            !crate::WindowsPathIdentity::parse_root(area.as_str(), "test.area")
                .expect("the area is a comparable Windows root")
                .contains(
                    &crate::WindowsPathIdentity::parse_root(declared.as_str(), "test.declared")
                        .expect("the declared root is a comparable Windows root")
                ),
            "the isolated area is a sibling of the installations root, never inside it"
        );
        let hierarchy = system
            .installer_root_hierarchy()
            .expect("a profiled root has a declared installer hierarchy");
        assert!(
            hierarchy
                .iter()
                .any(|(name, root)| *name == "installations_root" && *root == declared),
            "the installer hierarchy publishes the same derived installations root"
        );
        assert!(
            !hierarchy
                .iter()
                .any(|(name, root)| *name == "installations_root" && *root != declared),
            "there is exactly one declared installations root, so no reader can pick another"
        );

        let portable = portable_roots();
        assert!(
            matches!(
                portable.installations_root(),
                Err(crate::InstallationError::ProfileViolation(_))
            ),
            "portable_dev retains no shared installation area, so it declares no such root"
        );
        assert!(
            matches!(
                RuntimeStateRoots::derive_profiled(
                    InstallationProfile::PortableDev,
                    portable.profile_anchor_root.clone(),
                    &"a".repeat(64),
                ),
                Err(crate::InstallationError::ProfileViolation(_))
            ),
            "portable_dev is not a profiled derivation at all"
        );
    }

    /// A `SystemService` root topology anchored at the OS-resolved
    /// `ProgramData`, which is the contour the production Host runs in.
    #[cfg(windows)]
    fn profiled_system_roots() -> crate::RuntimeStateRoots {
        use crate::{InstallationProfile, RuntimeStateRoots};
        let program_data = crate::protected_program_data_root()
            .expect("ProgramData resolves for the profiled contour");
        RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            crate::PlatformHandle::new(program_data.to_string_lossy().into_owned())
                .expect("the OS-resolved anchor is a valid handle"),
            &"a".repeat(64),
        )
        .expect("the profiled contour derives from its OS-validated anchor")
    }

    /// A retained disposable portable root, which declares no shared area.
    ///
    /// `derive_portable` re-resolves the anchor through a real
    /// `UserOwnedRootReadLease`, so the fixture creates it and is therefore
    /// Windows-gated with its only consumer.
    ///
    /// That read lease is READ-ONLY by name: it compares the anchor's security
    /// descriptor BYTE-FOR-BYTE against the exact user-owned protected DACL and
    /// refuses anything else, including the inherited DACL a plain
    /// `create_dir_all` leaves behind. Creating the directory is therefore not
    /// enough to make the contour provable — the ACL must be provisioned, which
    /// is what the `UserOwnedRootLease` below does before it is dropped.
    ///
    /// This needs no elevation. The anchor is a directory this process's own user
    /// just created and therefore owns, and the lease opens it with
    /// `WRITE_DAC | WRITE_OWNER` precisely so the owner can install that policy.
    /// What the lease writes is the DACL it then verifies; the read lease is what
    /// refuses a root nobody provisioned. Provisioning here is the only way the
    /// derivation under test is reachable from an unelevated test process, and
    /// skipping it would make this fixture assert nothing.
    #[cfg(windows)]
    fn portable_roots() -> crate::RuntimeStateRoots {
        let root = std::env::temp_dir().join(format!(
            "eliot-installations-root-portable-{}-{}",
            std::process::id(),
            NEXT_UNIQUE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the portable fixture root is creatable");
        // A directory this operation just created under its OWN unique name, so
        // the provisioning lease is writing the ACL of a directory it owns and
        // no pre-existing state is being rewritten.
        drop(
            eliot_platform_windows::UserOwnedRootLease::open_existing(&root)
                .expect("the fixture root admits the user-owned protected DACL it owns"),
        );
        crate::RuntimeStateRoots::derive_portable(
            crate::PlatformHandle::new(root.to_string_lossy().into_owned())
                .expect("the fixture root is a valid handle"),
        )
        .expect("the retained portable contour derives")
    }

    /// One `ProgramData`-shaped declared installations root, as a standalone
    /// handle so the classification tests do not need a retained contour.
    fn handle_installations_root() -> crate::PlatformHandle {
        crate::PlatformHandle::new(r"C:\ProgramData\Eliot\installations")
            .expect("a declared installations root is a valid handle")
    }

    /// A per-process sequence so two concurrent fixture roots never collide.
    #[cfg(windows)]
    static NEXT_UNIQUE_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
}
