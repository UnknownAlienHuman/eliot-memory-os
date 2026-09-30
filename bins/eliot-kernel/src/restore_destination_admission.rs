//! The **admitted isolated destination binding** carried from the #958
//! installation-authority owner into the Kernel restore front door
//! (issue #963, external audit `5847488787` defect 1, destination half).
//!
//! # What this closes
//!
//! The restore front door used to resolve its destination from the REQUEST's
//! own `target_id`: `restore_target_shape`
//! (`super::request_dispatch::restore_target_shape`) admitted a bounded
//! caller-chosen string, and
//! [`KernelBackupRestore`](super::backup_restore::KernelBackupRestore)'s
//! `restore_with_owner` passed exactly that string to
//! `KernelIsolatedDestination::open`, which CONSTRUCTS
//! `<work_root>/.eliot/restore-isolated/<label>`. A predictable name is not
//! ownership, and no owner record was consulted to decide where an import
//! lands.
//!
//! The two gates that already existed do not close that hole, and this module
//! does not weaken either of them:
//!
//! - `refuse_destination_outside_isolated_area` (#955) proves WHERE the import
//!   LANDS: the resolved root must still be inside the resolved isolated area
//!   and end in the admitted label. It says nothing about whether that landing
//!   place is the ADMITTED one, because the label it re-checks is the label the
//!   request supplied.
//! - `check_destination_admission` re-verified a pinned admission only when
//!   `RestorePorts::manifest_evidence` was `Some`, and returned `Ok(())` when it
//!   was `None` — which is the production front door's value
//!   (`handle_backup_restore_test` constructs `manifest_evidence: None`). That
//!   `Ok(())` is the production hole, and it is closed here, not papered over.
//!
//! # The owner this binds to, and how the record reaches here
//!
//! The issuer is the installation authority's #958 owner:
//! [`eliot_installation::PreparedDestinationAdmission`] together with the
//! owner-observed [`eliot_installation::IsolationEvidence`] it carries.
//!
//! Nothing here mints, recomputes or synthesises that material. The record is
//! validated through the owner's OWN
//! [`PreparedDestinationAdmission::validate`], which re-derives the owner's
//! `admission_digest` and the nested `IsolationEvidence::evidence_digest` and
//! compares them. A digest computed here to stand in for owner-issued material
//! would be a second opinion, not the owner's record, so none is.
//!
//! HOW the record reaches this crate, stated precisely because it is weaker than
//! a direct registry read and must not be overclaimed: the Kernel holds no
//! `RedbInstallationRegistry` handle and cannot take a `HostOwnerEpochCapability`,
//! so it cannot itself call
//! `RedbInstallationRegistry::read_prepared_isolated_destination`. The record
//! arrives over the ONE channel the #954 seam already freezes for exactly this
//! purpose — the `destination_authorization_hex` member of an admitted backup
//! frame, which `request_dispatch::handle_backup_restore_test` decodes and
//! admits here. That is the frozen interface, not an invented transport.
//!
//! What this buys, honestly: the destination is decided by the OWNER's record
//! and its content is checked against owner-issued values, not by the request's
//! `target_id`. What it does NOT buy, and this module does not claim: proof
//! that the #954 seam's authentication actually vouched for the destination
//! bytes. Making the Kernel read the installation registry directly — so the
//! owner, not the frame, is the source — is the stronger form and is named here
//! as the remaining boundary rather than papered over.
//!
//! # Normative basis
//!
//! I5.13 `restore to isolated root;` and A13.7 `Restore occurs in an isolated
//! area`, plus the #958 issue clause that the destination is derived, never
//! supplied: a client-supplied arbitrary path, an active/source installation
//! and a preexisting foreign owner are all refused by the owner, and this
//! module inherits that by refusing anything the owner did not admit for this
//! installation and archive.
//!
//! Capability cell: Kernel restore ownership (isolated destination admission).
//! Forbidden authority: no installation allocation, no activation, no
//! retirement, no epoch minting, no second installation registry, no path
//! acceptance, and no synthesis of owner-issued destination material.

use std::path::Path;

use eliot_backup::BackupBundle;
use eliot_installation::{IsolationEvidence, PreparedDestinationAdmission};
use eliot_platform::PlatformHandle;

use super::backup_restore_ports::{KernelRestoreError, RestorePorts};

/// Comparisons over the three OWNER-RESOLVED roots the #958 owner recorded in
/// its [`IsolationEvidence`].
///
/// These compare the owner's own recorded values against each other. They do
/// not touch the filesystem, do not re-observe existence, and do not recompute
/// any owner digest: the owner resolved all three roots through its retained
/// no-follow lease before it recorded them, so re-resolving them here would be
/// a second observation rather than a check of the owner's record.
///
/// The separator-aware comparison matches the owner's own rule (the #958 owner's
/// `path_is_within` / `same_windows_root_text`): a resolved Windows root is
/// compared case-insensitively with either separator, and containment requires
/// a separator boundary so a sibling whose name merely starts with the
/// ancestor's is not "inside" it.
mod isolation {
    /// Normalises a resolved root for comparison: one separator, lower case.
    fn key(path: &str) -> String {
        path.replace('/', "\\").to_lowercase()
    }

    /// Exact equality over already-resolved roots.
    fn same_root(left: &str, right: &str) -> bool {
        key(left) == key(right)
    }

    /// Whether `candidate` is strictly inside `ancestor`.
    ///
    /// Strictly inside means: not the ancestor itself, and separated from it by
    /// a separator. `C:\area-evil` is therefore NOT inside `C:\area`, which a
    /// bare prefix test would wrongly admit.
    fn within(candidate: &str, ancestor: &str) -> bool {
        let candidate_key = key(candidate);
        let prefix = format!("{}\\", key(ancestor));
        candidate_key.starts_with(&prefix)
    }

    /// Whether the owner's recorded destination is inside the owner's declared
    /// isolated area and disjoint from the owner's recorded source root.
    ///
    /// All three arguments are the owner's own recorded, lease-resolved roots.
    /// The area and source root are checked in BOTH directions for the source,
    /// because "isolated from" means neither contains the other: a destination
    /// that CONTAINS the source is as unisolated as one nested inside it.
    pub(super) fn isolated_from(
        destination_root: &str,
        isolated_area_root: &str,
        source_installation_root: &str,
    ) -> bool {
        let strictly_inside_area = !same_root(destination_root, isolated_area_root)
            && within(destination_root, isolated_area_root);
        let disjoint_from_source = !same_root(destination_root, source_installation_root)
            && !within(destination_root, source_installation_root)
            && !within(source_installation_root, destination_root);
        strictly_inside_area && disjoint_from_source
    }
}

/// Domain separator for the binding's own content commitment.
///
/// It commits the fields THIS module compares, so the binding is tamper-evident
/// in transit. It is never a substitute for the owner's admission: the owner's
/// own `admission_digest` is validated through
/// [`PreparedDestinationAdmission::validate`] and is separately carried and
/// compared, and nothing here is accepted on the strength of this digest.
const RESTORE_DESTINATION_BINDING_DOMAIN: &str =
    "eliot.kernel.restore-destination-admission-binding.v1";

/// File name of the owner-admitted destination binding inside the isolated root.
///
/// It is a DISTINCT name from `DESTINATION_ADMISSION_FILE` (the pinned
/// Host-manifest evidence written at prepare). The two answer different
/// questions: the pin answers "did this transaction pin owner manifest
/// evidence", and this binding answers "which destination did the installation
/// authority admit for this operation". Collapsing them would let one stand in
/// for the other, which is exactly the substitution this closes.
pub const RESTORE_DESTINATION_BINDING_FILE: &str = "destination-owner-admission.json";

/// Typed refusal classes of the owner-admitted destination binding.
///
/// Every arm means the same operationally: this restore has no owner-issued
/// destination it may write into, so the effect is refused before a single
/// destination byte is staged. There is deliberately no "unknown" or "assume"
/// arm — an unadmitted destination is a refusal, never a pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreDestinationRefusal {
    /// The owner issued no prepared-destination admission for this operation.
    ///
    /// This is the typed absence of an owner capability, not a malformed
    /// value: the installation authority's durable projection retains nothing
    /// for this operation, so no destination of this restore's is admitted and
    /// the import is refused rather than steered to a name the request chose.
    NotAdmitted,

    /// The owner-issued admission does not validate against the owner's own
    /// record.
    ///
    /// The owner record's own `validate()` refused it, so its digests do not
    /// describe its content. A corrupt or hand-edited row cannot be used to
    /// name a destination.
    OwnerRecordInvalid,

    /// The admission belongs to a different installation than the one
    /// restoring.
    ///
    /// The owner admitted this destination for a source installation; the live
    /// composition-owned installation identity is a different value. An
    /// admission for another installation names a destination this process does
    /// not own, so it is refused instead of being reused.
    ForeignInstallation,

    /// The admission's destination is the source installation.
    ///
    /// The owner refuses this class before allocation, and the restore
    /// re-refuses it here rather than trusting that the owner happened to
    /// check: a restore into its own source is never a rehearsal.
    SourceInstallationDestination,

    /// The admitted archive is not the archive being restored.
    DestinationArchiveMismatch,

    /// The admitted archive class is not the class being restored.
    DestinationClassMismatch,

    /// The admitted destination leaf was not observed absent by the owner.
    ///
    /// This is the owner's own recorded OBSERVATION, not a re-observation here:
    /// an admission whose destination already existed is not a new distinct
    /// allocation, and importing into it would write bytes this operation does
    /// not own. The owner's `IsolationEvidence::validate` refuses the record
    /// when `destination_observed_absent` is false, and
    /// [`Self::owner_refusal`] preserves that refusal as THIS class rather than
    /// flattening it into `OwnerRecordInvalid`, so the owner's reason survives
    /// the layer crossing.
    DestinationNotDistinct,

    /// The owner could not prove its isolated restore area's contour.
    ///
    /// The owner's `IsolationEvidence::validate` reports this as an
    /// `IncompleteObservation` in two cases: the retained lease reported no
    /// stable file identity for the area, and the retained lease did not prove
    /// a reparse-free contour. Both are the owner's lease failing to PROVE the
    /// area, and both are kept distinct from `OwnerRecordInvalid` because "the
    /// owner could not prove the contour" and "the owner's record is corrupt"
    /// call for different next actions: the first is retried against a fresh
    /// lease observation, the second escalates as a corrupt owner record.
    IsolatedAreaUnproved,

    /// The owner did not prove the destination is isolated from the source
    /// installation root.
    DestinationOverlapsSource,
}

impl std::fmt::Display for RestoreDestinationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAdmitted => write!(
                formatter,
                "the installation authority retains no prepared isolated destination for this operation"
            ),
            Self::OwnerRecordInvalid => {
                write!(
                    formatter,
                    "the owner-issued destination admission is invalid"
                )
            }
            Self::ForeignInstallation => write!(
                formatter,
                "the owner-issued destination admission belongs to another installation"
            ),
            Self::SourceInstallationDestination => write!(
                formatter,
                "the owner-admitted destination is the source installation"
            ),
            Self::DestinationArchiveMismatch => write!(
                formatter,
                "the owner-issued destination admission is bound to another archive"
            ),
            Self::DestinationClassMismatch => write!(
                formatter,
                "the owner-issued destination admission is bound to another archive class"
            ),
            Self::DestinationNotDistinct => write!(
                formatter,
                "the owner did not observe the admitted destination as a new distinct leaf"
            ),
            Self::IsolatedAreaUnproved => write!(
                formatter,
                "the owner could not prove its isolated restore area's contour"
            ),
            Self::DestinationOverlapsSource => write!(
                formatter,
                "the owner-admitted destination is not isolated from the source installation root"
            ),
        }
    }
}

/// The owner-admitted isolated destination binding, carried into the restore
/// front door.
///
/// This is the value that makes "the import lands in the ADMITTED destination"
/// a checkable property rather than a naming convention. It carries:
///
/// - the owner's own [`PreparedDestinationAdmission`] verbatim, so the owner's
///   record is compared rather than a projection of it;
/// - the owner's own `admission_digest` and `IsolationEvidence::evidence_digest`,
///   compared against the owner's own `validate()` and against the record's own
///   fields, never recomputed here;
/// - the destination leaf name and root the OWNER derived, which is what
///   [`destination_label`](Self::destination_label) returns and therefore what
///   the restore constructs its root from. The request's `target_id` is not an
///   input to any of this and cannot become one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedIsolatedDestination {
    /// The owner-issued admission, exactly as the installation authority
    /// recorded it.
    admission: PreparedDestinationAdmission,
    /// Commitment over the binding's own compared fields. Tamper-evidence for
    /// this struct only; it never admits a destination on its own.
    binding_digest: String,
}

impl AdmittedIsolatedDestination {
    /// Carries one owner-issued admission, refusing it unless it binds THIS
    /// operation, THIS archive and THIS class into a destination the owner
    /// proved new, distinct, isolated and reparse-free.
    ///
    /// # What is compared, and against what
    ///
    /// Every comparison below is against a value the OWNER recorded:
    ///
    /// - `admission.validate()` is the installation authority's OWN validator.
    ///   It re-derives the owner's `admission_digest` and the nested
    ///   `IsolationEvidence::evidence_digest` and refuses a mismatch, so a
    ///   hand-written, truncated or stale row cannot name a destination. This
    ///   module computes no digest to stand in for that material; it calls the
    ///   owner's validator and honours its verdict.
    /// - `admission.source_installation` is compared with `source_installation`,
    ///   the LIVE composition-owned installation identity. Both sides derive it
    ///   from an owner-issued record — the installation authority's own request
    ///   identity on one side, the set-once dispatch contour filled from the
    ///   authenticated Host startup binding on the other — so this is a
    ///   comparison of two owner-issued values on an axis they genuinely share.
    ///   An admission minted for another installation cannot name a destination
    ///   on this one.
    ///
    ///   `admission.operation_id` is deliberately NOT compared here. It is the
    ///   installation authority's own operation identity from the #954
    ///   `PrepareIsolatedRestore` request, which is a different identity scheme
    ///   from the Kernel restore plan's; requiring the two to be equal would
    ///   assert an identity relation no owner established, and would refuse
    ///   every real admission. It is carried on the binding and readable through
    ///   [`operation_id`](Self::operation_id) so a reader can see WHICH
    ///   operation the owner admitted for.
    /// - `admission.archive_id` is compared with the archive's OWN
    ///   `manifest.backup_id` read out of the decoded bundle, never with a
    ///   request field that could disagree with it.
    /// - `admission.archive_class` is compared with the archive's OWN
    ///   `manifest.class`, mapped through this module's one closed spelling
    ///   bridge `declared_wire_class`, which is exhaustive over the archive's
    ///   class so a new class cannot be admitted as an existing one.
    /// - `admission.isolation`'s three recorded ROOTS are compared with each
    ///   other by [`isolation::isolated_from`], because the Kernel constructs
    ///   its destination root from the owner's key and must therefore confirm
    ///   that key's root really is inside the owner's declared area and really
    ///   is disjoint from the source. This compares owner records; it does not
    ///   re-observe the filesystem, because a second observation would be a
    ///   second opinion and the owner's lease-resolved record is the authority.
    /// - `destination_observed_absent` and `isolated_area_reparse_free` are
    ///   required by the owner's OWN `validate()` and are NOT re-checked here.
    ///   Their refusals reach this crate as
    ///   [`DestinationNotDistinct`](RestoreDestinationRefusal::DestinationNotDistinct)
    ///   and [`IsolatedAreaUnproved`](RestoreDestinationRefusal::IsolatedAreaUnproved)
    ///   through [`Self::owner_refusal`], so the owner's verdict is honoured
    ///   without a second rule in a second crate that could drift from the one
    ///   gating the allocation.
    ///
    /// # Errors
    ///
    /// Returns the [`RestoreDestinationRefusal`] the owner's own `validate()`
    /// raised (preserved, not flattened), or the specific arm for each content
    /// disagreement above.
    pub fn bind_owner_admission(
        admission: &PreparedDestinationAdmission,
        source_installation: &str,
        bundle: &BackupBundle,
    ) -> Result<Self, RestoreDestinationRefusal> {
        // The owner's own validator first: it re-derives both of the owner's
        // digests over the owner's own fields. Nothing below can be reached
        // with a record the owner itself would refuse, and the owner's own
        // refusal class is preserved by `Self::owner_refusal` rather than
        // flattened into "invalid".
        admission.validate().map_err(Self::owner_refusal)?;

        // The installation this destination was admitted FOR, against the
        // installation this Kernel is. Both are owner-issued and independent of
        // the request, so an admission for another installation refuses.
        if admission.source_installation.as_str() != source_installation {
            return Err(RestoreDestinationRefusal::ForeignInstallation);
        }
        // The archive's own manifest facts, never a request field.
        if admission.archive_id.as_str() != bundle.manifest.backup_id {
            return Err(RestoreDestinationRefusal::DestinationArchiveMismatch);
        }
        if admission.archive_class != declared_wire_class(bundle) {
            return Err(RestoreDestinationRefusal::DestinationClassMismatch);
        }
        if admission.source_installation == admission.destination_installation {
            return Err(RestoreDestinationRefusal::SourceInstallationDestination);
        }
        // The owner's recorded isolation topology is compared here against the
        // owner's OWN two other recorded roots. This compares owner records; it
        // does not re-observe the filesystem and does not recompute anything:
        // the owner resolved all three roots through its retained no-follow
        // lease before recording them. The reason it is compared again rather
        // than trusted from `validate()` is that the owner's `validate()`
        // re-derives DIGESTS, while the three roots are the values the
        // destination CONSTRUCTION depends on — the Kernel builds its root from
        // the owner's key below, so it must confirm the key's root really is
        // inside the owner's declared area and really is disjoint from the
        // source before it writes there.
        if !isolation.isolated_from(
            &admission.isolation.destination_installation_root,
            &admission.isolation.isolated_area_root,
            &admission.isolation.source_installation_root,
        ) {
            return Err(RestoreDestinationRefusal::DestinationOverlapsSource);
        }

        let binding_digest = Self::commit(
            &admission.admission_digest,
            &admission.isolation.evidence_digest,
            admission.operation_id.as_str(),
            admission.archive_id.as_str(),
            admission.destination_installation.as_str(),
            admission.isolation.destination_installation_root.as_str(),
        )
        .ok_or(RestoreDestinationRefusal::OwnerRecordInvalid)?;

        Ok(Self {
            admission: admission.clone(),
            binding_digest,
        })
    }

    /// Maps the OWNER's own refusal onto this crate's vocabulary, preserving
    /// the owner's reason where this crate names it.
    ///
    /// The owner's class is never discarded: a caller that must decide whether
    /// to re-prepare a destination, escalate to the installation authority, or
    /// treat the record as corrupt needs the owner's reason, not a paraphrase.
    fn owner_refusal(
        error: eliot_installation::IsolatedDestinationError,
    ) -> RestoreDestinationRefusal {
        use eliot_installation::{IsolatedDestinationError, IsolatedDestinationRefusal as Owner};
        match error {
            IsolatedDestinationError::Refused(Owner::DestinationNotAbsent) => {
                RestoreDestinationRefusal::DestinationNotDistinct
            }
            IsolatedDestinationError::Refused(Owner::SourceInstallationDestination) => {
                RestoreDestinationRefusal::SourceInstallationDestination
            }
            IsolatedDestinationError::Refused(Owner::DestinationOverlapsSource) => {
                RestoreDestinationRefusal::DestinationOverlapsSource
            }
            // The owner's `IsolationEvidence::validate` reports a lease that
            // could not prove the area — no stable file identity, or no
            // reparse-free contour — as an `IncompleteObservation` rather than a
            // typed refusal. It is matched here so the class stays distinct
            // from a malformed record, and deliberately NOT by matching the
            // message text: the two facts are separated by the variant the owner
            // chose, not by prose.
            IsolatedDestinationError::Installation(
                eliot_installation::InstallationError::IncompleteObservation(_),
            ) => RestoreDestinationRefusal::IsolatedAreaUnproved,
            _ => RestoreDestinationRefusal::OwnerRecordInvalid,
        }
    }

    /// Commits exactly the fields this binding compares.
    ///
    /// Returns `None` when canonical encoding or the digest itself fails, so a
    /// binding whose commitment cannot be computed is refused rather than
    /// carried with an empty digest standing in for one.
    fn commit(
        admission_digest: &PlatformHandle,
        evidence_digest: &PlatformHandle,
        operation_id: &str,
        archive_id: &str,
        destination_installation: &str,
        destination_root: &str,
    ) -> Option<String> {
        let bytes = eliot_contracts::canonical_json_bytes(&(
            RESTORE_DESTINATION_BINDING_DOMAIN,
            admission_digest.as_str(),
            evidence_digest.as_str(),
            operation_id,
            archive_id,
            destination_installation,
            destination_root,
        ))
        .ok()?;
        Some(eliot_contracts::sha256_hex(&bytes))
    }

    /// Re-validates the binding: the owner's own record validates again, and
    /// this binding's own commitment still describes its fields.
    ///
    /// This is the per-effect re-check, so drift in transit is refused before
    /// the next destination write rather than only at admission.
    pub fn revalidate(&self) -> Result<(), RestoreDestinationRefusal> {
        self.admission.validate().map_err(Self::owner_refusal)?;
        let recomputed = Self::commit(
            &self.admission.admission_digest,
            &self.admission.isolation.evidence_digest,
            self.admission.operation_id.as_str(),
            self.admission.archive_id.as_str(),
            self.admission.destination_installation.as_str(),
            self.admission
                .isolation
                .destination_installation_root
                .as_str(),
        )
        .ok_or(RestoreDestinationRefusal::OwnerRecordInvalid)?;
        if recomputed != self.binding_digest {
            return Err(RestoreDestinationRefusal::OwnerRecordInvalid);
        }
        Ok(())
    }

    /// The destination leaf name the OWNER derived.
    ///
    /// This is what the restore constructs its isolated root from, so it is the
    /// owner's value and not the request's. The owner derived the leaf name from
    /// the destination installation key it admitted (see the #958 owner's
    /// `admit_prepared_isolated_destination`, which has no path parameter at
    /// all), so this is not a name a caller chose.
    ///
    /// The key is the owner's 64-hex installation key, which
    /// [`PreparedDestinationAdmission::validate`] has already proved is a
    /// well-formed handle, and which is bounded to the 64 characters
    /// [`KernelIsolatedDestination::open`](super::backup_restore_ports::KernelIsolatedDestination::open)
    /// accepts as a label. That constructor is still the one that bounds the
    /// label and constructs the canonical root; what changed is which label
    /// reaches it.
    #[must_use]
    pub fn destination_label(&self) -> &str {
        self.admission
            .isolation
            .destination_installation_key
            .as_str()
    }

    /// The destination installation root the OWNER derived and recorded.
    ///
    /// Read by the front door and by any reader that wants to show WHICH
    /// destination the owner admitted rather than only the leaf it was
    /// constructed under. It is the owner's own recorded, lease-resolved root
    /// and is never re-derived here.
    #[must_use]
    pub fn destination_root(&self) -> &str {
        self.admission
            .isolation
            .destination_installation_root
            .as_str()
    }

    /// The owner-declared isolated restore area the owner resolved through its
    /// retained protected-root lease.
    #[must_use]
    pub fn isolated_area_root(&self) -> &str {
        self.admission.isolation.isolated_area_root.as_str()
    }

    /// The owner's own recorded admission digest, carried so a reader can see
    /// WHICH owner record this binding commits to without recomputing one.
    #[must_use]
    pub fn owner_admission_digest(&self) -> &PlatformHandle {
        &self.admission.admission_digest
    }

    /// The owner-observed isolation evidence, exactly as recorded.
    #[must_use]
    pub const fn owner_isolation_evidence(&self) -> &IsolationEvidence {
        &self.admission.isolation
    }

    /// The owner's own admission record, exactly as recorded.
    #[must_use]
    pub const fn owner_admission(&self) -> &PreparedDestinationAdmission {
        &self.admission
    }

    /// The owner's operation identity this destination was admitted for.
    #[must_use]
    pub fn operation_id(&self) -> &PlatformHandle {
        &self.admission.operation_id
    }

    /// Projects the binding into its durable form, for the pin inside the
    /// isolated root.
    ///
    /// The projection is the owner's admission WHOLE plus this binding's own
    /// commitment. It selects no subset of the owner's fields, so a reader
    /// re-runs the owner's `validate()` against exactly what was pinned.
    pub fn to_pinned(&self) -> Result<PinnedDestinationBinding, RestoreDestinationRefusal> {
        // The owner's own record must still validate at pin time, not only at
        // admission: a record that was valid when bound and invalid now would
        // otherwise be pinned as if it were still the owner's.
        self.revalidate()?;
        Ok(PinnedDestinationBinding {
            owner_admission: self.admission.clone(),
            binding_digest: self.binding_digest.clone(),
        })
    }

    /// Reads a binding back off the destination and re-validates it against the
    /// owner's own record.
    ///
    /// A missing file is `NotFound`, deliberately NOT `NotAdmitted`: the caller
    /// decides what an unpinned destination means for its own phase, and a
    /// durable read never collapses a missing file, a permission denial and a
    /// broken path into one silent answer.
    pub fn read_pinned(destination_root: &Path) -> Result<Self, ReadPinnedDestinationError> {
        let path = destination_root.join(RESTORE_DESTINATION_BINDING_FILE);
        let bytes = std::fs::read(&path).map_err(ReadPinnedDestinationError::Io)?;
        let pinned: PinnedDestinationBinding =
            serde_json::from_slice(&bytes).map_err(ReadPinnedDestinationError::Corrupt)?;
        let bound = Self {
            admission: pinned.owner_admission,
            binding_digest: pinned.binding_digest,
        };
        bound
            .revalidate()
            .map_err(ReadPinnedDestinationError::Refused)?;
        Ok(bound)
    }
}

/// The durable form of [`AdmittedIsolatedDestination`] inside the isolated root.
///
/// It carries the owner's admission WHOLE rather than a projection of selected
/// fields, so a reader can re-run the owner's own `validate()` on exactly what
/// was pinned instead of on a summary this module chose.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedDestinationBinding {
    /// The owner-issued admission, verbatim.
    pub owner_admission: PreparedDestinationAdmission,
    /// This binding's own content commitment.
    pub binding_digest: String,
}

/// Failure classes of the durable binding read-back.
///
/// `Io` and `Corrupt` are kept apart from [`RestoreDestinationRefusal`] so a
/// broken or unreadable pin is never reported as a typed owner refusal: an
/// inaccessible record is not evidence that the owner refused.
#[derive(Debug)]
pub enum ReadPinnedDestinationError {
    /// The pin could not be read. Carries the OS cause.
    Io(std::io::Error),
    /// The pin's bytes are not a binding this crate can decode.
    Corrupt,
    /// The pin decoded, and the owner's own record inside it refuses.
    Refused(RestoreDestinationRefusal),
}

impl std::fmt::Display for ReadPinnedDestinationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "pinned destination binding unreadable: {error}"),
            Self::Corrupt => {
                write!(formatter, "pinned destination binding is not decodable")
            }
            Self::Refused(refusal) => write!(formatter, "{refusal}"),
        }
    }
}

impl std::error::Error for ReadPinnedDestinationError {}

/// Maps the archive's own declared class onto the protocol's closed wire class.
///
/// One spelling bridge over two vocabularies that already agree one-for-one,
/// not a second class set: the owner bound `BackupClassWire` and the archive
/// declares `BackupClass`, and this maps the latter onto the former. A class
/// the archive declares that this bridge cannot name is a compile error rather
/// than a silent mismatch.
fn declared_wire_class(bundle: &BackupBundle) -> eliot_protocol::backup::BackupClassWire {
    use eliot_backup::BackupClass;
    use eliot_protocol::backup::BackupClassWire;
    match bundle.manifest.class {
        BackupClass::FullRecovery => BackupClassWire::FullRecovery,
        BackupClass::CanonicalOnlyDegraded => BackupClassWire::CanonicalOnlyDegraded,
        BackupClass::ScopeExport => BackupClassWire::ScopeExport,
    }
}

/// Resolves one admitted destination under the Kernel's canonical work root and
/// proves it is the owner's destination by IDENTITY, before any import.
///
/// The destination root is CONSTRUCTED from the owner's own derived leaf name
/// under the Kernel's isolated restore area — the same area
/// `refuse_destination_outside_isolated_area` then proves by resolved
/// filesystem topology. The request's `target_id` is not consulted here at
/// all: it cannot select this root, because this root's last component is the
/// owner's.
///
/// # Errors
///
/// Returns [`KernelRestoreError::DestinationNotAdmitted`] when the binding no
/// longer validates against the owner's own record, and the destination
/// constructor's own typed error (a work root that is not absolute or not a
/// directory) otherwise. The two are NOT collapsed into one class: "the owner
/// did not admit this" and "the Kernel's work root is unusable" are different
/// facts with different next actions, so each keeps its own typed error.
pub fn admitted_isolated_destination(
    work_root: &Path,
    admitted: &AdmittedIsolatedDestination,
) -> Result<super::backup_restore_ports::KernelIsolatedDestination, KernelRestoreError> {
    admitted
        .revalidate()
        .map_err(|_| KernelRestoreError::DestinationNotAdmitted)?;
    // The Kernel constructs the destination from the OWNER's derived leaf, not
    // from any request field. The `open` constructor is retained because it is
    // the only constructor that bounds a label and constructs the canonical
    // root; what changed is which label reaches it.
    super::backup_restore_ports::KernelIsolatedDestination::open(
        work_root,
        admitted.destination_label(),
    )
}

/// Requires the owner-admitted destination binding on a port bundle.
///
/// This is the typed refusal of the hole the audit names: a bundle with no
/// owner-issued destination admission is a bundle with no destination this
/// restore may write into, and it is refused rather than allowed to import
/// into a name the request chose. The `Option` is kept on
/// [`RestorePorts`] because the bundle is also constructed by the injected-
/// journal seam; this gate is what decides that the absent case is a refusal
/// on the path that reaches it, so the absence cannot read as a pass.
pub fn require_admitted_destination(
    ports: &RestorePorts<'_>,
) -> Result<&AdmittedIsolatedDestination, RestoreDestinationRefusal> {
    ports
        .destination_admission
        .ok_or(RestoreDestinationRefusal::NotAdmitted)
}
