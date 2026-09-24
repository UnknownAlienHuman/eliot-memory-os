//! Event-range ownership cases 862/1 and 862/13 (issue #862).
//!
//! `eliot-ecxf` is the sole canonical owner of the ECXF `EventRange`;
//! `eliot-backup` consumes that exact Rust type through a reexport and keeps
//! no second definition or validator. Both suites exercise the same fixture
//! corpus (the owner file, referenced here by relative path so the corpus
//! cannot drift between suites) through the same owner validation boundary.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::num::NonZeroU64;

use eliot_backup::{EventRange, ExportFence};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use serde::Deserialize;

type TestResult = Result<(), Box<dyn Error>>;

/// The single shared corpus, owned by `eliot-ecxf`. This suite reads the
/// owner's file directly so both suites always exercise identical bytes.
const CORPUS: &str = include_str!("../../eliot-ecxf/tests/data/event_range_cases.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const ROOT_LOCK: &str = include_str!("../../../../Cargo.lock");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    valid: bool,
    wire: String,
    canonical_wire: String,
}

fn fixtures() -> Result<Vec<Fixture>, Box<dyn Error>> {
    Ok(serde_json::from_str(CORPUS)?)
}

fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    fixtures()?
        .into_iter()
        .find(|case| case.id == id)
        .ok_or_else(|| format!("missing event-range fixture: {id}").into())
}

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid lineage"),
        NonZeroU64::new(1).expect("nonzero sequence"),
    )
    .expect("valid epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn consumer_fence(range: EventRange) -> ExportFence {
    ExportFence {
        export_id: "export-862".to_owned(),
        installation_id: "installation-862".to_owned(),
        schema_generation: "schema-862".to_owned(),
        store_generation: "store-862".to_owned(),
        state_fence: fence(),
        scope_id: None,
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        event_range: range,
        blob_reachability_manifest: Vec::new(),
        consistent: true,
    }
}

/// Compile-time proof that the backup path names the owner's type: an
/// `eliot_backup::EventRange` value is accepted where the
/// `eliot_ecxf::EventRange` owner is required, which is only possible when
/// both names denote one Rust type.
fn accepts_owner(value: eliot_ecxf::EventRange) -> eliot_ecxf::EventRange {
    value
}

// WORK_UNIT_CASE: 862/1
#[test]
fn backup_names_the_single_ecxf_owner_with_manifest_and_lock_handoff() -> TestResult {
    // Pre-change accounting: two independent definitions existed — the backup
    // duplicate (saturating arithmetic that accepted sparse counts) and the
    // ECXF definition. Post-change exactly one remains, reached here through
    // the backup reexport.
    let range = EventRange {
        first_sequence: Some(1),
        last_sequence: Some(2),
        count: 2,
    };
    let owned = accepts_owner(range);
    owned.validate()?;

    // The same value validates through the backup consumer boundary, which
    // now names the owner's fence type directly, so the owner's typed
    // rejection surfaces without a second validator.
    consumer_fence(owned).validate()?;
    let sparse: EventRange = serde_json::from_str(&fixture("sparse")?.wire)?;
    assert!(matches!(
        consumer_fence(sparse).validate(),
        Err(eliot_ecxf::EcxfError::InvalidField { field, .. }) if field == "event_range"
    ));

    // Minimal dependency handoff: backup declares the existing sibling owner.
    assert!(
        MANIFEST.contains("eliot-ecxf"),
        "eliot-backup manifest must declare the eliot-ecxf owner"
    );
    // Minimal lock handoff: the resolved lock records the eliot-backup edge
    // onto the existing eliot-ecxf package, with no new package identity.
    let backup_section = ROOT_LOCK
        .split("[[package]]")
        .find(|section| section.contains("name = \"eliot-backup\""))
        .ok_or("Cargo.lock must contain the eliot-backup package")?;
    assert!(
        backup_section.contains("\"eliot-ecxf\""),
        "Cargo.lock must record the eliot-backup -> eliot-ecxf edge"
    );
    Ok(())
}

// WORK_UNIT_CASE: 862/13
#[test]
fn backup_and_ecxf_agree_on_the_full_shared_corpus() -> TestResult {
    let cases = fixtures()?;
    assert!(!cases.is_empty());
    let mut valid_seen = 0;
    let mut invalid_seen = 0;
    for case in cases {
        // Both names denote one Rust type, so deserializing through either
        // path yields the same value; assert the agreement explicitly.
        let via_backup: EventRange = serde_json::from_str(&case.wire)?;
        let via_owner: eliot_ecxf::EventRange = serde_json::from_str(&case.wire)?;
        assert_eq!(via_backup, via_owner, "{}", case.id);
        assert_eq!(
            via_backup.validate().is_ok(),
            via_owner.validate().is_ok(),
            "{}",
            case.id
        );
        if case.valid {
            via_backup.validate()?;
            assert_eq!(
                serde_json::to_string(&via_backup)?,
                case.wire,
                "{}",
                case.id
            );
            assert_eq!(
                eliot_contracts::canonical_json_bytes(&via_backup)?,
                case.canonical_wire.as_bytes(),
                "{}",
                case.id
            );
            valid_seen += 1;
        } else {
            assert!(via_backup.validate().is_err(), "{}", case.id);
            assert!(matches!(
                via_backup.validate(),
                Err(eliot_ecxf::EcxfError::InvalidField { .. })
            ));
            invalid_seen += 1;
        }
    }
    assert!(valid_seen > 0 && invalid_seen > 0);

    // Consumer-constructor proof on the boundary: a valid corpus wire builds
    // a validating backup fence, while the historically accepted sparse wire
    // is refused at the consumer boundary with the owner's typed reason.
    let contiguous: EventRange = serde_json::from_str(&fixture("contiguous")?.wire)?;
    consumer_fence(contiguous).validate()?;
    let sparse: EventRange = serde_json::from_str(&fixture("sparse")?.wire)?;
    assert!(matches!(
        consumer_fence(sparse).validate(),
        Err(eliot_ecxf::EcxfError::InvalidField {
            field: "event_range",
            reason: "bounds and count do not describe one interval",
        })
    ));
    Ok(())
}
