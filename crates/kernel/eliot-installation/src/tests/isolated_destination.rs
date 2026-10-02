//! Isolated-destination admission and durable-evidence proof (issue #958, A2).
//! Normative basis: I5.13 `restore to isolated root;`, A13.7 `Restore occurs in an
//! isolated area and verifies: schema and format compatibility; ...`.
//!
//! These proofs exercise the DURABLE cross-checks the admission records are held
//! to by [`ApprovedGenerationRegistry`]: that a destination is compared against
//! the EXISTING-INSTALLATION identities this authority holds, that a preparation
//! bound to a purge-ledger revision or a source generation that has since moved
//! on is refused, that a materialised root is only ever recorded against the
//! admission it actually realises, and that cleanup forgets a pair as one fact.
//!
//! They are deliberately projection-level: no lease, no directory and no
//! filesystem is involved, so every refusal observed here is a decision this
//! crate's OWN retained records produced. The filesystem half — creating the
//! root and re-observing its identity — is proved by
//! `materialise_prepared_isolated_destination` and the registry read/record
//! seams on the production Host path, which need a retained protected-root
//! lease.
//! Test-oracle-only: no production ownership or activation authority.

use eliot_protocol::backup::BackupClassWire;

use super::{must, registering_transaction, test_activation_approval, test_handle};
use crate::isolated_destination::{
    DestinationLeafObservation, IsolationEvidence, PreparedDestinationAdmission,
    PreparedDestinationMaterialisation, ProposedRestorationRequirements,
};
use crate::{
    ApprovedGeneration, ApprovedGenerationRegistry, CandidateManifest, FileIdentity,
    InstallationActivationApproval, InstallationError, PlatformHandle,
};

/// Purge-ledger revision the ORS owner reports for the admitted preparation.
const LIVE_PURGE_REVISION: u64 = 7;

/// A lowercase 64-hex owner installation key, which is the only destination
/// identity form the admission accepts.
fn installation_key(seed: &str) -> PlatformHandle {
    test_handle(seed.repeat(64 / seed.len()))
}

/// An approval that binds `manifest` exactly, through the crate's own fixture
/// constructor rather than a hand-written value.
fn approval_for(
    manifest: &CandidateManifest,
    approval_ref: &str,
) -> InstallationActivationApproval {
    test_activation_approval(
        manifest,
        test_handle("transaction:958-isolated-destination"),
        test_handle(&"c".repeat(64)),
        test_handle(approval_ref),
    )
}

/// One approved generation whose `installation_epoch.installation` IS a valid
/// owner installation key.
///
/// The portable fixture's own installation identity is free text, so the "a
/// destination is an installation this authority already holds" clause is
/// unreachable unless the approved row's installation identity is itself in the
/// owner key form. Re-keying it here is what makes that clause expressible, and
/// the descriptor digest and the approval are recomputed so the row stays a
/// genuinely VALID approved generation rather than a hand-edited one.
///
/// The generation is renamed too, so the two rows are distinct approved
/// generations rather than one row listed twice. Renaming a `portable_dev`
/// generation is not a free-text edit: I3.1 versions that profile's immutable
/// root BY generation, so the immutable root is re-derived from the new name
/// instead of being left naming the old one. The name is a path leaf, so it
/// carries no `:`.
fn approved_generation(
    installation: &PlatformHandle,
    generation_name: &str,
    active: bool,
) -> ApprovedGeneration {
    let transaction = registering_transaction();
    let mut manifest = transaction.candidate_manifest;
    let portable_root = manifest
        .runtime_launch
        .portable_root
        .clone()
        .expect("the portable fixture retains the root it was derived from");
    manifest.generation = test_handle(generation_name);
    manifest.runtime_launch.generation = manifest.generation.clone();
    manifest
        .runtime_launch
        .profile_governed_roots
        .immutable_binaries = format!(
        r"{}\target\eliot-dev\{generation_name}",
        portable_root.as_str()
    );
    manifest.runtime_launch.installation_epoch.installation = installation.clone();
    manifest.runtime_launch = must(manifest.runtime_launch.with_computed_digest());
    must(manifest.validate());
    ApprovedGeneration {
        approval: approval_for(&manifest, &format!("approval:958-{generation_name}")),
        manifest,
        active,
        last_known_good: false,
    }
}

/// The values a caller binds one admission to, plus the registry under test.
struct Fixture {
    registry: ApprovedGenerationRegistry,
    /// The generation the registry currently has active.
    active_generation: PlatformHandle,
    /// The installation identity of the ACTIVE generation: the source this
    /// preparation reads from.
    source_installation: PlatformHandle,
    /// A DIFFERENT installation identity this authority also approves, which is
    /// the "already an installation" case a destination must be refused for.
    other_installation: PlatformHandle,
}

/// Two approved generations in the owner installation-key form: the active one,
/// which is the source, and an approved but inactive one, which is an existing
/// installation a destination must never be.
///
/// The two rows carry DIFFERENT installation identities. Whether a production
/// registry is ever multi-installation is NOT established here: `Redb
/// InstallationRegistry` is opened per installation Host root and binds the
/// owner capability to ONE installation, so a single-installation registry is
/// the likelier production shape. What matters for these proofs is only that
/// `ApprovedGenerationRegistry::validate` accepts the projection -- it asserts
/// it below -- and that the destination-identity comparison has a member of the
/// existing-installation set to fire against. This fixture supplies that; it is
/// not a claim that production holds two installations at once.
fn fixture() -> Fixture {
    let source_installation = installation_key("1");
    let other_installation = installation_key("2");
    let current = approved_generation(&source_installation, "generation-958-current", true);
    let active_generation = current.manifest.generation.clone();
    let inactive = approved_generation(&other_installation, "generation-958-other", false);
    // The inactive row is retained FIRST so nothing about a refusal may depend
    // on which approved row the projection happens to list first.
    let registry = ApprovedGenerationRegistry {
        active_generation: Some(active_generation.clone()),
        generations: vec![inactive, current],
        ..ApprovedGenerationRegistry::new()
    };
    let fixture = Fixture {
        active_generation,
        registry,
        source_installation,
        other_installation,
    };
    must(fixture.registry.validate());
    fixture
}

/// Records one admission at the purge revision the ORS owner reports now.
///
/// The live revision is an argument at every call site rather than a fixture
/// constant, so a case that varies it is stating the variation instead of
/// editing a shared default.
fn record(
    fixture: &mut Fixture,
    admission: &PreparedDestinationAdmission,
    live_purge_revision: u64,
) -> Result<PreparedDestinationAdmission, InstallationError> {
    fixture
        .registry
        .record_prepared_isolated_destination_unchecked(admission, live_purge_revision)
}

/// Records one admission together with the root created for it, as one fact.
fn record_creation(
    fixture: &mut Fixture,
    admission: &PreparedDestinationAdmission,
    materialisation: &PreparedDestinationMaterialisation,
    live_purge_revision: u64,
) -> Result<PreparedDestinationMaterialisation, InstallationError> {
    fixture
        .registry
        .record_prepared_isolated_destination_creation_unchecked(
            admission,
            materialisation,
            live_purge_revision,
        )
}

/// Forgets one admission and the root created for it, as one fact.
fn forget_creation(
    fixture: &mut Fixture,
    admission: &PreparedDestinationAdmission,
    materialisation: &PreparedDestinationMaterialisation,
) -> Result<(), InstallationError> {
    fixture
        .registry
        .forget_prepared_isolated_destination_creation_unchecked(admission, materialisation)
}

/// Restoration requirements issued from the same owner-issued facts shape the
/// admission binds, so only the field under test varies between cases.
fn requirements(target_schema_digest: &PlatformHandle) -> ProposedRestorationRequirements {
    let mut requirements = ProposedRestorationRequirements {
        wire: test_handle(ProposedRestorationRequirements::WIRE),
        admitted_classes: vec![BackupClassWire::FullRecovery],
        max_restore_bytes: 65_536,
        target_schema_digest: target_schema_digest.clone(),
        requires_source_key_material: true,
        requirements_digest: test_handle(&"0".repeat(64)),
    };
    // The commitment is computed from the values themselves, exactly as the
    // issuer does, so `validate` accepts the record for its own content rather
    // than for a placeholder digest.
    requirements.requirements_digest = must(requirements.computed_digest());
    must(requirements.validate());
    requirements
}

/// Owner-observed isolation evidence for one admitted destination.
fn isolation(
    destination: &PlatformHandle,
    source_active_generation: &PlatformHandle,
    observation: DestinationLeafObservation,
) -> IsolationEvidence {
    let area = r"C:\ProgramData\Eliot\isolated-restore";
    let mut evidence = IsolationEvidence {
        wire: test_handle(IsolationEvidence::WIRE),
        isolated_area_root: area.to_owned(),
        isolated_area_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 11,
        },
        // Derived by the OWNER'S join helper, not by string formatting: this is
        // the exact function `admit_prepared_isolated_destination` derives the
        // destination root with, so the fixture cannot disagree with production
        // about separators. `format!("{}\{}")` would not even parse.
        destination_installation_root: crate::joined_windows_path(area, destination.as_str()),
        destination_installation_key: destination.clone(),
        source_installation_root: r"C:\ProgramData\Eliot\installations\1".to_owned(),
        source_host_root: r"C:\ProgramData\Eliot\installations\1\host".to_owned(),
        source_active_generation: source_active_generation.clone(),
        destination_leaf_observation: observation,
        evidence_digest: test_handle(&"0".repeat(64)),
    };
    evidence.evidence_digest = must(evidence.computed_digest());
    evidence
}

/// A fully valid admission bound to the fixture's own values.
fn admission_for(fixture: &Fixture, destination: &PlatformHandle) -> PreparedDestinationAdmission {
    let target_schema_digest = test_handle(&"a".repeat(64));
    let mut admission = PreparedDestinationAdmission {
        wire: test_handle(PreparedDestinationAdmission::WIRE),
        operation_id: test_handle("operation:958-isolated-destination"),
        source_installation: fixture.source_installation.clone(),
        destination_installation: destination.clone(),
        archive_id: test_handle("archive:958"),
        archive_digest: test_handle(&"b".repeat(64)),
        archive_class: BackupClassWire::FullRecovery,
        current_purge_ledger_revision: LIVE_PURGE_REVISION,
        target_schema_digest: target_schema_digest.clone(),
        approved_target_build: fixture.active_generation.clone(),
        approved_target_profile: test_handle("system_service"),
        restoration_requirements: requirements(&target_schema_digest),
        isolation: isolation(
            destination,
            &fixture.active_generation,
            DestinationLeafObservation::Absent,
        ),
        admission_digest: test_handle(&"0".repeat(64)),
    };
    admission.admission_digest = must(admission.computed_digest());
    must(admission.validate());
    admission
}

/// A materialisation that claims to realise `admission`.
fn materialisation_for(
    admission: &PreparedDestinationAdmission,
) -> PreparedDestinationMaterialisation {
    let evidence = &admission.isolation;
    let mut materialisation = PreparedDestinationMaterialisation {
        wire: test_handle(PreparedDestinationMaterialisation::WIRE),
        operation_id: admission.operation_id.clone(),
        destination_installation: admission.destination_installation.clone(),
        admission_digest: admission.admission_digest.clone(),
        isolated_area_root: evidence.isolated_area_root.clone(),
        isolated_area_identity: evidence.isolated_area_identity,
        destination_installation_root: evidence.destination_installation_root.clone(),
        destination_root_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 13,
        },
        destination_leaf_observation: DestinationLeafObservation::Absent,
        materialisation_digest: test_handle(&"0".repeat(64)),
    };
    materialisation.materialisation_digest = must(materialisation.computed_digest());
    must(materialisation.validate());
    materialisation
}

/// A genuinely NEW distinct destination is admitted, retained, and idempotent.
///
/// This is the positive the admission exists for. The destination identity is
/// compared against the existing-installation set — which here holds TWO approved
/// installation identities — and is in neither, so the record is retained. The
/// predecessor compared the APPROVED TARGET with the source's own active
/// generation; in this production shape both values are the same field of the
/// same approved row, so that comparison was `a == a`: it refused every
/// legitimate destination while proving nothing about the destination itself.
#[test]
fn genuinely_new_destination_is_retained_and_replay_resolves_the_same_record() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &installation_key("3"));

    let recorded = must(record(&mut fixture, &admission, LIVE_PURGE_REVISION));
    assert_eq!(
        recorded, admission,
        "the exact record presented is the record retained"
    );
    assert_eq!(
        fixture.registry.prepared_isolated_destinations().len(),
        1,
        "one operation owns exactly one retained destination"
    );
    let replay = must(record(&mut fixture, &admission, LIVE_PURGE_REVISION));
    assert_eq!(
        replay, admission,
        "an exact replay is idempotent and resolves the same verified destination"
    );
    must(fixture.registry.validate());
}

/// The refusal is keyed on the DESTINATION identity against the
/// existing-installation set, in the installation identity space, and it fires.
#[test]
fn destination_that_is_an_installation_this_authority_approves_is_refused() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &fixture.other_installation);
    assert!(
        matches!(
            record(&mut fixture, &admission, LIVE_PURGE_REVISION),
            Err(InstallationError::Duplicate { ref kind, .. })
                if kind == "known installation offered as an isolated destination"
        ),
        "a destination that is already an installation is not a NEW distinct one"
    );
    assert!(
        fixture.registry.prepared_isolated_destinations().is_empty(),
        "a refused destination is never retained"
    );
}

/// The purge-ledger revision the admission bound is compared against the
/// revision the ORS owner reports NOW.
///
/// The field previously existed and was only ever compared with `0`, so a
/// preparation bound to a stale revision and one bound to the current revision
/// were indistinguishable after admission. A13.7 requires the restore to apply
/// the CURRENT privacy purge, so a disagreeing revision and an ABSENT one (zero,
/// which no owner ever issues) are both refused.
#[test]
fn purge_ledger_revision_is_compared_against_the_live_owner_value() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &installation_key("4"));
    for live in [0, 6, 8] {
        assert!(
            matches!(
                record(&mut fixture, &admission, live),
                Err(InstallationError::IncompleteObservation(_))
            ),
            "live purge revision {live} does not match the bound revision {LIVE_PURGE_REVISION}"
        );
    }
    assert!(fixture.registry.prepared_isolated_destinations().is_empty());
    must(record(&mut fixture, &admission, LIVE_PURGE_REVISION));
}

/// The source generation the admission was prepared against is compared against
/// this projection's OWN current active generation.
///
/// The field existed to be compared and nothing read it, so a preparation bound
/// to a configuration snapshot the source has since moved on from was retained
/// as if it were current.
#[test]
fn stale_source_active_generation_is_refused() {
    let mut fixture = fixture();
    let superseded = fixture
        .registry
        .generations
        .first()
        .map(|generation| generation.manifest.generation.clone())
        .expect("the fixture retains the inactive approved generation");
    let mut admission = admission_for(&fixture, &installation_key("5"));
    // Both the approved TARGET and the SOURCE GENERATION name the retained
    // inactive row, which this authority still approves. Every durable
    // self-consistency check therefore passes, and only the record-time
    // comparison against the CURRENT active generation can refuse this.
    admission.approved_target_build = superseded.clone();
    admission.isolation.source_active_generation = superseded.clone();
    admission.admission_digest = must(admission.computed_digest());
    must(admission.validate());
    let durable = ApprovedGenerationRegistry {
        prepared_isolated_destinations: vec![admission.clone()],
        ..fixture.registry.clone()
    };
    must(durable.validate());

    assert!(
        matches!(
            record(&mut fixture, &admission, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "a preparation bound to a generation the source has moved on from is stale"
    );
    assert!(fixture.registry.prepared_isolated_destinations().is_empty());
}

/// The approved target must be a generation THIS authority approves, checked
/// against the registry's own rows.
///
/// This is a real cross-check against an INDEPENDENT expected set — the
/// registry's approved collection — rather than a caller-presented manifest and
/// approval that merely agree with each other.
#[test]
fn approved_target_must_be_a_generation_this_authority_approves() {
    let mut fixture = fixture();
    let mut admission = admission_for(&fixture, &installation_key("6"));
    admission.approved_target_build = test_handle("generation-not-approved-here");
    admission.admission_digest = must(admission.computed_digest());
    must(admission.validate());
    assert!(
        matches!(
            record(&mut fixture, &admission, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "an approved target this authority does not approve is refused"
    );
    assert!(fixture.registry.prepared_isolated_destinations().is_empty());
}

/// Two operations may never share one destination, and a changed record for the
/// SAME operation is a conflict rather than a second allocation.
#[test]
fn a_destination_is_owned_by_exactly_one_operation() {
    let mut fixture = fixture();
    let destination = installation_key("7");
    let first = admission_for(&fixture, &destination);
    must(record(&mut fixture, &first, LIVE_PURGE_REVISION));

    let mut second = admission_for(&fixture, &destination);
    second.operation_id = test_handle("operation:958-second");
    second.admission_digest = must(second.computed_digest());
    must(second.validate());
    assert!(
        matches!(
            record(&mut fixture, &second, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "two operations may never share one destination"
    );

    let mut changed = first.clone();
    changed.archive_digest = test_handle(&"d".repeat(64));
    changed.admission_digest = must(changed.computed_digest());
    must(changed.validate());
    assert!(
        matches!(
            record(&mut fixture, &changed, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "a changed bound record for the same operation is not an idempotent replay"
    );
    assert_eq!(
        fixture.registry.prepared_isolated_destinations().len(),
        1,
        "the refused records retained nothing"
    );
}

/// A materialised root is recorded ONLY against the admission it realises, and
/// the pair is retained as one fact.
#[test]
fn materialised_root_is_recorded_only_against_the_admission_it_realises() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &installation_key("8"));
    let materialisation = materialisation_for(&admission);
    let recorded = must(record_creation(
        &mut fixture,
        &admission,
        &materialisation,
        LIVE_PURGE_REVISION,
    ));
    assert_eq!(
        recorded, materialisation,
        "the record presented is the created-root record retained"
    );
    assert_eq!(
        fixture
            .registry
            .prepared_destination_materialisations()
            .len(),
        1,
        "the created root is retained exactly once"
    );
    must(fixture.registry.validate());

    let mut foreign = materialisation.clone();
    foreign.destination_installation = installation_key("9");
    foreign.destination_installation_root = crate::joined_windows_path(
        admission.isolation.isolated_area_root.as_str(),
        foreign.destination_installation.as_str(),
    );
    foreign.materialisation_digest = must(foreign.computed_digest());
    must(foreign.validate());
    assert!(
        matches!(
            record_creation(&mut fixture, &admission, &foreign, LIVE_PURGE_REVISION),
            Err(InstallationError::InvalidField { ref field, .. })
                if field == "prepared_destination_materialisation"
        ),
        "a materialisation for a DIFFERENT destination does not realise this admission"
    );

    let mut unrelated = materialisation;
    unrelated.admission_digest = test_handle(&"e".repeat(64));
    unrelated.materialisation_digest = must(unrelated.computed_digest());
    must(unrelated.validate());
    assert!(
        matches!(
            record_creation(&mut fixture, &admission, &unrelated, LIVE_PURGE_REVISION),
            Err(InstallationError::InvalidField { ref field, .. })
                if field == "prepared_destination_materialisation"
        ),
        "a materialisation naming no retained admission does not realise it"
    );
    assert_eq!(
        fixture
            .registry
            .prepared_destination_materialisations()
            .len(),
        1,
        "the refused materialisations retained nothing"
    );
}

/// An exact pair replay is idempotent; a pair whose created root no longer
/// carries the recorded identity is a conflict, not a replay.
#[test]
fn materialisation_replay_is_idempotent_and_a_changed_pair_conflicts() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &installation_key("a"));
    let materialisation = materialisation_for(&admission);
    must(record_creation(
        &mut fixture,
        &admission,
        &materialisation,
        LIVE_PURGE_REVISION,
    ));
    let replay = must(record_creation(
        &mut fixture,
        &admission,
        &materialisation,
        LIVE_PURGE_REVISION,
    ));
    assert_eq!(
        replay, materialisation,
        "an exact pair replay resolves the same verified destination"
    );

    let mut substituted = materialisation;
    substituted.destination_root_identity = FileIdentity {
        volume_serial_number: 7,
        file_index: 99,
    };
    substituted.materialisation_digest = must(substituted.computed_digest());
    must(substituted.validate());
    assert!(
        matches!(
            record_creation(&mut fixture, &admission, &substituted, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "a created root that no longer carries the recorded identity is not an idempotent replay"
    );
}

/// Cleanup forgets the pair as ONE fact, and a root this authority cannot prove
/// it created is preserved rather than removed by name.
#[test]
fn cleanup_forgets_the_pair_together_and_preserves_a_root_it_does_not_hold() {
    let mut fixture = fixture();
    let admission = admission_for(&fixture, &installation_key("b"));
    let materialisation = materialisation_for(&admission);
    must(record_creation(
        &mut fixture,
        &admission,
        &materialisation,
        LIVE_PURGE_REVISION,
    ));

    let mut foreign = materialisation.clone();
    foreign.destination_root_identity = FileIdentity {
        volume_serial_number: 7,
        file_index: 4242,
    };
    foreign.materialisation_digest = must(foreign.computed_digest());
    must(foreign.validate());
    assert!(
        matches!(
            forget_creation(&mut fixture, &admission, &foreign),
            Err(InstallationError::IncompleteObservation(_))
        ),
        "a created root this authority does not hold is preserved, not removed"
    );
    assert_eq!(
        fixture
            .registry
            .prepared_destination_materialisations()
            .len(),
        1,
        "the refused cleanup removed nothing"
    );

    must(forget_creation(&mut fixture, &admission, &materialisation));
    assert!(
        fixture.registry.prepared_isolated_destinations().is_empty()
            && fixture
                .registry
                .prepared_destination_materialisations()
                .is_empty(),
        "the admission and its created root are forgotten as one fact"
    );
    must(fixture.registry.validate());
}

/// A leaf the owner OBSERVED as present, or could not observe at all, is refused
/// by BOTH records, so a destination that is somebody else's directory can never
/// be recorded as a new distinct allocation.
///
/// This is the arm a `bool` could never reach: only the value `Absent` makes
/// either record a creation receipt, and both other values are refused even
/// with a correctly recomputed digest.
#[test]
fn a_non_absent_leaf_observation_is_refused_by_both_records() {
    use crate::{IsolatedDestinationError, IsolatedDestinationRefusal};

    let fixture = fixture();
    let destination = installation_key("c");
    for observation in [
        DestinationLeafObservation::Present,
        DestinationLeafObservation::Unobserved,
    ] {
        let evidence = isolation(&destination, &fixture.active_generation, observation);
        assert!(
            matches!(
                evidence.validate(),
                Err(IsolatedDestinationError::Refused(
                    IsolatedDestinationRefusal::DestinationNotAbsent
                ))
            ),
            "{observation:?} cannot be the recorded observation of a new allocation"
        );

        let mut materialisation = PreparedDestinationMaterialisation {
            wire: test_handle(PreparedDestinationMaterialisation::WIRE),
            operation_id: test_handle("operation:958-observation"),
            destination_installation: destination.clone(),
            admission_digest: test_handle(&"a".repeat(64)),
            isolated_area_root: evidence.isolated_area_root.clone(),
            isolated_area_identity: evidence.isolated_area_identity,
            destination_installation_root: evidence.destination_installation_root.clone(),
            destination_root_identity: FileIdentity {
                volume_serial_number: 7,
                file_index: 13,
            },
            destination_leaf_observation: observation,
            materialisation_digest: test_handle(&"0".repeat(64)),
        };
        materialisation.materialisation_digest = must(materialisation.computed_digest());
        assert!(
            matches!(
                materialisation.validate(),
                Err(IsolatedDestinationError::Refused(
                    IsolatedDestinationRefusal::DestinationNotAbsent
                ))
            ),
            "{observation:?} is not the proof that this operation created that root"
        );
    }
}
