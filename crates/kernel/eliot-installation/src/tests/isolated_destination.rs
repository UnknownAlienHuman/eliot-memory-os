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
//! Most of these are deliberately projection-level: no lease, no directory and
//! no filesystem is involved, so every refusal observed here is a decision this
//! crate's OWN retained records produced. The filesystem half — creating the
//! root and re-observing its identity — is proved by
//! `materialise_prepared_isolated_destination` and the registry read/record
//! seams on the production Host path, which need a retained protected-root
//! lease.
//!
//! The last case in this file is the exception and is deliberately so: it drives
//! that real materialise seam over a real retained protected-root lease in the
//! real `ProgramData` contour and asserts on the FILESYSTEM, because the defect
//! it proves is about what is on disk when a refusal arrives. A boolean the code
//! returned cannot distinguish "refused before creating" from "created, then
//! refused".
//! Test-oracle-only: no production ownership or activation authority.

use eliot_protocol::backup::BackupClassWire;

use super::{must, registering_transaction, test_activation_approval, test_handle};
use crate::isolated_destination::{
    DestinationLeafObservation, IsolationEvidence, PreparedDestinationAdmission,
    PreparedDestinationMaterialisation, ProposedRestorationRequirements,
    resolve_current_approved_target,
};
// The real-filesystem cases below drive the materialise seam itself, which needs
// a retained protected-root lease and therefore a real Windows contour. The
// import is gated with them so it is never an unused import elsewhere.
#[cfg(windows)]
use crate::isolated_destination::materialise_prepared_isolated_destination;
use crate::{
    ApprovedGeneration, ApprovedGenerationRegistry, CandidateManifest, FileIdentity,
    InstallationActivationApproval, InstallationError, IsolatedDestinationError,
    IsolatedDestinationRefusal, PlatformHandle,
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
        test_handle("c".repeat(64)),
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
        registry,
        active_generation,
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
        requirements_digest: test_handle("0".repeat(64)),
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
        evidence_digest: test_handle("0".repeat(64)),
    };
    evidence.evidence_digest = must(evidence.computed_digest());
    evidence
}

/// A fully valid admission bound to the fixture's own values.
fn admission_for(fixture: &Fixture, destination: &PlatformHandle) -> PreparedDestinationAdmission {
    let target_schema_digest = test_handle("a".repeat(64));
    let mut admission = PreparedDestinationAdmission {
        wire: test_handle(PreparedDestinationAdmission::WIRE),
        operation_id: test_handle("operation:958-isolated-destination"),
        source_installation: fixture.source_installation.clone(),
        destination_installation: destination.clone(),
        archive_id: test_handle("archive:958"),
        archive_digest: test_handle("b".repeat(64)),
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
        admission_digest: test_handle("0".repeat(64)),
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
        materialisation_digest: test_handle("0".repeat(64)),
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
    // The isolation evidence digest binds the source generation AND the leaf
    // observation, so editing the evidence invalidates the evidence digest.
    // It is therefore recomputed HERE, after the edit, and only then is the
    // admission digest that folds it in recomputed. Recomputing only the outer
    // digest leaves a record that fails its own `validate` on the evidence, and
    // the case would be proving the digest check rather than the staleness
    // refusal it exists to prove.
    admission.isolation.source_active_generation = superseded.clone();
    admission.isolation.evidence_digest = must(admission.isolation.computed_digest());
    admission.admission_digest = must(admission.computed_digest());
    must(admission.isolation.validate());
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
///
/// # Which refusal actually fires
///
/// This case was originally written to provoke the clause
/// `active_generation == Some(approved_target_build)`, which the predecessor
/// held in the record path. That clause was DELETED, correctly: in the
/// production shape the approved target and the source's active generation are
/// the same field of the same approved row, so it was `a == a` and it refused
/// every legitimate destination. With it gone, this record no longer provokes
/// any pre-write comparison — the source generation it binds still matches the
/// current active generation, and the destination identity is genuinely new.
///
/// Whether the approved target is the build the authority CURRENTLY approves is
/// a different question, and it is decided before the record exists at all, by
/// `resolve_current_approved_target`; the case below proves that site.
///
/// The refusal therefore comes from somewhere else, and the case is written
/// against THAT: `ApprovedGenerationRegistry::validate`, the projection's own
/// self-consistency pass, refuses a retained admission whose approved target
/// names no row in the approved collection. It fires on the way out of the
/// record call, after the write — which is exactly why the record call commits
/// the write only once that pass succeeds and rolls it back when it does not.
/// The `is_empty` assertion below is therefore the load-bearing half of this
/// case: it is what distinguishes a refusal from a refusal-that-left-the-record
/// behind, and it is the half that was wrong before the rollback existed.
#[test]
fn approved_target_must_be_a_generation_this_authority_approves() {
    let mut fixture = fixture();
    let mut admission = admission_for(&fixture, &installation_key("6"));
    admission.approved_target_build = test_handle("generation-not-approved-here");
    admission.admission_digest = must(admission.computed_digest());
    must(admission.validate());
    // The record is durably self-consistent — nothing about it is malformed, and
    // its own digest binds its own content. It is refused only because the
    // authority's approved collection does not contain the target it names.
    let durable = ApprovedGenerationRegistry {
        prepared_isolated_destinations: vec![admission.clone()],
        ..fixture.registry.clone()
    };
    assert!(
        durable.validate().is_err(),
        "a record naming an unapproved target cannot be retained by a valid projection, which is \
         the independent expectation the record call is held to"
    );

    assert!(
        matches!(
            record(&mut fixture, &admission, LIVE_PURGE_REVISION),
            Err(InstallationError::IdentityConflict)
        ),
        "an approved target this authority does not approve is refused"
    );
    assert!(
        fixture.registry.prepared_isolated_destinations().is_empty(),
        "the refused record is rolled back, so the projection does not both refuse the admission \
         and retain it"
    );
    must(fixture.registry.validate());
}

/// The approved target a destination is prepared FOR must be the build this
/// authority CURRENTLY approves, and that is decided where the target is
/// resolved rather than where the record is written.
///
/// # Why this is the site the removed clause belonged at
///
/// The record path used to hold `active_generation == Some(&admission.
/// approved_target_build)`. That clause could fire on exactly one input: the
/// destination's approved target build IS the source's current active
/// generation, which is the production shape — a restore is prepared FOR the
/// currently approved build of the installation that owns the archive. So it
/// refused every legitimate destination, and it never fired for the input it
/// reads as though it were written for, a destination prepared for a SUPERSEDED
/// approved build. Nothing was gained by keeping it where it was, and the
/// guarantee it gestured at is real.
///
/// Here it is a comparison between two values the AUTHORITY owns: the handle is
/// looked up in the approved rows the caller read out of this registry, and the
/// row it names is then compared with that same set's own `active` bit — which
/// `ApprovedGenerationRegistry::validate` keeps equal to `active_generation()`.
/// Both arms are therefore reachable: the currently active row is admitted, and
/// a retained row the authority has moved off is refused as an identity conflict.
///
/// The refusal is pre-effect: the resolver opens nothing, creates nothing and
/// writes nothing, so nothing has to be rolled back.
///
/// Without the currency arm the superseded row below resolves to a row of this
/// authority's own approved collection, so the destination would be admitted for
/// a build the authority has already moved off.
#[test]
fn approved_target_must_be_the_build_this_authority_currently_approves() {
    let fixture = fixture();
    let generations = &fixture.registry.generations;

    let resolved = must(resolve_current_approved_target(
        generations,
        &fixture.active_generation,
    ));
    assert!(
        resolved.active && resolved.manifest.generation == fixture.active_generation,
        "the handle naming the set's own ACTIVE row resolves to that row, which is what the \
         production caller presents"
    );

    let superseded = generations
        .iter()
        .find(|generation| !generation.active)
        .map(|generation| generation.manifest.generation.clone())
        .expect("the fixture retains one approved generation that is not active");
    assert!(
        matches!(
            resolve_current_approved_target(generations, &superseded),
            Err(IsolatedDestinationError::Installation(
                InstallationError::IdentityConflict
            ))
        ),
        "a build this authority still approves but is no longer ON is not a current approved \
         target, however well-formed its approval is"
    );

    assert!(
        matches!(
            resolve_current_approved_target(
                generations,
                &test_handle("generation-this-authority-never-approved")
            ),
            Err(IsolatedDestinationError::Installation(
                InstallationError::IncompleteObservation(_)
            ))
        ),
        "a handle naming no row of the authority's approved set is refused before any comparison \
         against the current row is even possible"
    );
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
    changed.archive_digest = test_handle("d".repeat(64));
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
    unrelated.admission_digest = test_handle("e".repeat(64));
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
            admission_digest: test_handle("a".repeat(64)),
            isolated_area_root: evidence.isolated_area_root.clone(),
            isolated_area_identity: evidence.isolated_area_identity,
            destination_installation_root: evidence.destination_installation_root.clone(),
            destination_root_identity: FileIdentity {
                volume_serial_number: 7,
                file_index: 13,
            },
            destination_leaf_observation: observation,
            materialisation_digest: test_handle("0".repeat(64)),
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

/// A disposable isolated restore area under an owned temp case root, plus
/// the retained no-follow lease over it.
///
/// The protected contour is pinned to the case root through
/// `eliot_platform_windows::test_support::override_protected_root`: the real
/// `ProgramData` contour needs elevation to create into, which test runners do
/// not have, while every proof under test -- containment, retained-handle
/// identity, the publication and its re-proof -- still runs through the real
/// `expected_root()` and `ProtectedRootLease` machinery. It also
/// holds the `PRODUCTION_INSTALLER_TEST_LOCK` serialising the shared temp
/// staging root.
#[cfg(windows)]
struct LiveArea {
    /// The retained no-follow lease over the area. Held for the whole case.
    lease: crate::ProtectedRootLease,
    /// The area path this operation created, used for cleanup and for the
    /// "nothing else was written here" observation.
    path: std::path::PathBuf,
    /// The temp case root the protected contour is overridden to. Held for
    /// the whole case and removed on release.
    staging: std::path::PathBuf,
    /// The serialisation lock for the shared staging root, held for the whole case.
    _serial: std::sync::MutexGuard<'static, ()>,
    /// The thread-local protected-root override. Held for the whole case: the
    /// lease, the publication and every re-proof resolve `expected_root()`
    /// through it.
    _override: eliot_platform_windows::test_support::ProtectedRootOverride,
}

#[cfg(windows)]
impl LiveArea {
    /// The area's own resolved canonical root text.
    fn root_text(&self) -> String {
        self.lease
            .canonical_path()
            .expect("the retained area lease resolves its own canonical root")
            .to_string_lossy()
            .into_owned()
    }

    /// The destination root the owner derives for one destination identity.
    fn destination_root(&self, destination: &PlatformHandle) -> String {
        crate::joined_windows_path(&self.root_text(), destination.as_str())
    }

    /// Drops the retained lease and removes the area and staging root this
    /// operation created.
    ///
    /// Ownership is what makes this legitimate: the path was derived under a name
    /// unique to this case, created by this operation, and holds nothing but what
    /// this operation published. The lease is dropped FIRST because its retained
    /// handles exclude delete sharing and would otherwise block the removal.
    fn release(self) {
        let LiveArea {
            lease,
            path,
            staging,
            _serial,
            _override,
        } = self;
        drop(lease);
        let _ = std::fs::remove_dir_all(path);
        let _ = std::fs::remove_dir_all(staging);
    }
}

#[cfg(windows)]
fn live_isolated_area(name: &str) -> LiveArea {
    let serial = super::PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Owned temp staging root: the real `ProgramData` contour needs elevation to
    // create into, so the protected contour is overridden to this case root and
    // every proof below still runs through the real `expected_root()` machinery.
    let staging = std::env::temp_dir().join("eliot-958-installation-area");
    std::fs::create_dir_all(&staging).expect("the isolated area staging root is creatable");
    let protected = eliot_platform_windows::test_support::override_protected_root(&staging);
    let path = staging.join(name).join(
        super::NEXT_TRANSACTION_ROOT
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .to_string(),
    );
    let _ = std::fs::remove_dir_all(&path);
    // The owner's own protected-directory creator, so the area carries the ACL
    // and reparse-freedom the lease later demands rather than a bare
    // `create_dir_all` the lease would have to accept on trust.
    eliot_platform_windows::prepare_protected_directory(&path)
        .expect("the isolated area fixture is creatable inside the protected root");
    let lease = crate::ProtectedRootLease::open_existing(&path)
        .expect("the isolated area fixture admits a retained protected-root lease");
    LiveArea {
        lease,
        path,
        staging,
        _serial: serial,
        _override: protected,
    }
}

/// The `ProgramData`-shaped source roots the materialise-time layout
/// re-classification is run against, as real paths beside the live area.
///
/// `declared_installations_root_for_recorded_source` derives the declared
/// installations root from the PARENT of the recorded source installation root,
/// so recording a source root one leaf below `<program_data>\Eliot\installations`
/// makes the derived declared root exactly the production shape. The live area is
/// a different leaf under the same profile root, so it — and the destination
/// derived under it — is classified `Unowned` against that declared root, which
/// is the condition the materialise pre-effect proof requires.
#[cfg(windows)]
fn live_source_roots() -> (String, String) {
    let installation = must(crate::protected_program_data_root())
        .join("Eliot")
        .join("installations")
        .join("a".repeat(64));
    let installation_root = installation.to_string_lossy().into_owned();
    let host_root = crate::joined_windows_path(&installation_root, "host");
    (installation_root, host_root)
}

/// One admission bound to the LIVE area lease, so the materialise seam's
/// pre-effect proof passes on its own terms and the generation comparison is the
/// only thing that can refuse it.
///
/// Every recorded value is read back from the live lease or derived with the
/// owner's own join helper — never spelled out — so this fixture cannot disagree
/// with production about separators, identity, or which root is the declared
/// installations area.
#[cfg(windows)]
fn live_admission(
    area: &LiveArea,
    destination: &PlatformHandle,
    source_active_generation: &PlatformHandle,
) -> PreparedDestinationAdmission {
    let (source_installation_root, source_host_root) = live_source_roots();
    let target_schema_digest = test_handle("a".repeat(64));
    let mut admission = PreparedDestinationAdmission {
        wire: test_handle(PreparedDestinationAdmission::WIRE),
        operation_id: test_handle("operation:958-live-materialise"),
        source_installation: test_handle("a".repeat(64)),
        destination_installation: destination.clone(),
        archive_id: test_handle("archive:958-live"),
        archive_digest: test_handle("b".repeat(64)),
        archive_class: BackupClassWire::FullRecovery,
        current_purge_ledger_revision: LIVE_PURGE_REVISION,
        target_schema_digest: target_schema_digest.clone(),
        approved_target_build: source_active_generation.clone(),
        approved_target_profile: test_handle("system_service"),
        restoration_requirements: requirements(&target_schema_digest),
        isolation: IsolationEvidence {
            wire: test_handle(IsolationEvidence::WIRE),
            isolated_area_root: area.root_text(),
            // The lease's OWN observed identity for the area, never a constant: the
            // pre-effect proof compares this recorded value against the live one.
            isolated_area_identity: area.lease.identity(),
            destination_installation_root: area.destination_root(destination),
            destination_installation_key: destination.clone(),
            source_installation_root,
            source_host_root,
            source_active_generation: source_active_generation.clone(),
            destination_leaf_observation: DestinationLeafObservation::Absent,
            evidence_digest: test_handle("0".repeat(64)),
        },
        admission_digest: test_handle("0".repeat(64)),
    };
    admission.isolation.evidence_digest = must(admission.isolation.computed_digest());
    admission.admission_digest = must(admission.computed_digest());
    must(admission.validate());
    admission
}

/// The authority as it reads AFTER a cutover has been committed under it: the
/// superseded generation is RETAINED and still APPROVED, a successor row is
/// approved and ACTIVE, and `active_generation` names the successor.
///
/// This is the shape production reaches when a cutover lands between admission
/// and materialisation. The old regression case could not express it: it passed
/// the same fixture snapshot for the approved set and the handle, so the seam's
/// comparison received the active generation for both arms and could not fail on
/// an input production can construct. Here the two operands come from genuinely
/// different reads — the admission bound the pre-cutover generation, and the
/// approved collection handed to the seam is the post-cutover one.
#[cfg(windows)]
fn committed_cutover(fixture: &Fixture) -> (ApprovedGenerationRegistry, PlatformHandle) {
    let superseded = fixture.active_generation.clone();
    let successor = approved_generation(&installation_key("c"), "generation-958-successor", true);
    let successor_generation = successor.manifest.generation.clone();
    let mut registry = fixture.registry.clone();
    for row in &mut registry.generations {
        if row.manifest.generation == superseded {
            row.active = false;
        }
    }
    registry.generations.push(successor);
    registry.active_generation = Some(successor_generation.clone());
    must(registry.validate());
    (registry, successor_generation)
}

/// The DECISIVE case: a CUTOVER committed between admission and materialisation
/// is refused with NO DIRECTORY CREATED.
///
/// # What is being proved
///
/// `isolation.source_active_generation` used to be compared ONLY at record time,
/// inside `record_prepared_isolated_destination_unchecked`. Production calls
/// `materialise_prepared_isolated_destination` — which performs the real effect,
/// `OwnedDirectoryPublication::create` then `.publish` — BEFORE it calls
/// `record_prepared_isolated_destination_creation`. So a generation the source
/// had moved on from created a directory on disk and was then refused, leaving
/// that created root unrecorded: an orphan the authority does not know about. A
/// check that runs after the effect is not a gate on the effect.
///
/// The assertion is therefore on the FILESYSTEM, not on the returned value: a
/// boolean cannot distinguish "refused before creating" from "created, then
/// refused", and that distinction is the entire defect.
///
/// # Why it fails without the change
///
/// Without the comparison in the seam, `prove_isolated_destination_root` passes —
/// this fixture's area, identity, derived root and disjointness are all live and
/// consistent — and `OwnedDirectoryPublication` commits the directory. The
/// call returns `Ok`, and the leaf exists. The refusal assertion fails AND the
/// filesystem assertion fails, because the root this test requires to be absent
/// is precisely the orphan the old ordering produced. This is therefore the only
/// case here that fails when the guard is removed.
///
/// # Ownership
///
/// See [`LiveArea::release`]: the area and anything published under it are created
/// by THIS operation under a name unique to this case, and removed by that same
/// owned path after the retained lease is dropped.
#[cfg(windows)]
#[test]
fn a_cutover_committed_after_admission_creates_no_destination_directory() {
    let fixture = fixture();
    // A genuinely NEW installation identity: not the active installation, not the
    // other approved one, and a valid owner installation key — so the refusal
    // cannot be attributed to any destination-identity clause.
    let destination = installation_key("9");
    let area = live_isolated_area("cutover-generation");
    let destination_root = area.destination_root(&destination);
    assert!(
        !std::path::Path::new(&destination_root).exists(),
        "the fixture starts from an absent leaf, so any root found below was created by this call"
    );

    // The admission binds the generation that WAS active when the destination was
    // prepared, bound exactly as production binds it — from the first read. Then a
    // cutover is committed and the authority is read again. The approved set and
    // the handle handed to the seam are the SECOND read's CURRENTLY ACTIVE row.
    // Both arms are authority state, taken from reads separated in time, and they
    // disagree — which is exactly the condition that must refuse, and exactly what
    // a forged self-consistent claim cannot produce.
    let admission = live_admission(&area, &destination, &fixture.active_generation);
    let (current, current_generation) = committed_cutover(&fixture);

    let outcome = materialise_prepared_isolated_destination(
        &admission,
        &area.lease,
        &current.generations,
        &current_generation,
    );

    assert!(
        matches!(
            outcome,
            Err(IsolatedDestinationError::Installation(
                InstallationError::IdentityConflict
            ))
        ),
        "a cutover committed after this preparation was admitted leaves it bound to a \
         generation the source has moved on from; the typed class is the same one the \
         record-time clause produced, so one class spans both layers"
    );
    // THE DECISIVE ASSERTION: the filesystem, not the returned value.
    assert!(
        !std::path::Path::new(&destination_root).exists(),
        "the refusal must arrive BEFORE the publication, but {destination_root} exists on disk: \
         the stale preparation created an orphan root the authority never recorded"
    );
    // Nothing else was written either: no same-parent publication temporary was
    // staged, because the create step never ran at all.
    assert_eq!(
        std::fs::read_dir(&area.path)
            .expect("the live area is readable while this operation holds its lease")
            .count(),
        0,
        "a pre-effect refusal leaves the isolated area exactly as it found it"
    );

    area.release();
}

/// The POSITIVE case: the SAME seam and the SAME live fixture, with the authority's
/// current generation supplied, DOES create the destination on disk.
///
/// Without this the refusal case would pass for the wrong reason — a fixture that
/// cannot materialise at all would also "create nothing". This case pins that the
/// fixture is real: the destination root exists on disk afterwards, and the
/// returned record carries the created object's own observed identity rather than a
/// value this test supplied.
#[cfg(windows)]
#[test]
fn a_current_source_generation_materialises_the_destination_on_disk() {
    // A genuinely INDEPENDENT second read, as production performs between
    // admission and materialisation. It carries the same values here, which is
    // the point: this case exists to catch the guard OVER-refusing or INVERTING,
    // which is the regression the deleted `approved_target_build ==
    // active_generation` clause caused. An assertion of `Ok` cannot fail when a
    // correct guard is removed, so all removal-sensitivity belongs to the cutover
    // case and none is faked here.
    let re_read = fixture();
    // Both reads are taken here, ahead of the `fixture` binding below, because
    // that binding shadows the free function of the same name for the rest of
    // this scope.
    let fixture = fixture();
    let destination = installation_key("8");
    let area = live_isolated_area("current-generation");
    let destination_root = area.destination_root(&destination);
    assert!(
        !std::path::Path::new(&destination_root).exists(),
        "the fixture starts from an absent leaf, so the creation below is this operation's"
    );
    let admission = live_admission(&area, &destination, &fixture.active_generation);

    let materialisation = must(materialise_prepared_isolated_destination(
        &admission,
        &area.lease,
        &re_read.registry.generations,
        &re_read.active_generation,
    ));

    assert!(
        std::path::Path::new(&destination_root).is_dir(),
        "the publication created the destination root at {destination_root}"
    );
    assert!(
        materialisation
            .destination_root_identity
            .volume_serial_number
            != 0
            && materialisation.destination_root_identity.file_index != 0,
        "the creation receipt carries a real observed identity for the created object"
    );
    assert_eq!(
        materialisation.destination_installation_root, destination_root,
        "the recorded root is the owner-derived destination, not caller text"
    );
    assert_eq!(
        materialisation.admission_digest, admission.admission_digest,
        "the creation receipt realises this admission and no other"
    );
    assert_eq!(
        materialisation.destination_leaf_observation,
        DestinationLeafObservation::Absent,
        "the receipt records the no-follow observation the create step made"
    );

    area.release();
}
