//! The ECXF/1 interchange fence to the kernel fence bridge (issue #2569, item 2).
//!
//! # WHAT THIS FILE IS
//!
//! This is the FIRST proof the issue's ROOT BATCH names for this producer: "one
//! lawfully obtained complete input converts without losing required fields;
//! wrong bindings are refused." It drives the real conversion,
//! `impl TryFrom<&eliot_ecxf::ExportFence> for eliot_backup::ExportFence`
//! (`crates/storage/eliot-backup/src/ecxf_export.rs`), which is the ONLY producer
//! of the kernel-side `ExportFence` in the repository.
//!
//! # WHY THE CONVERSION USED TO BE TOTAL-REFUSING, AND WHY THAT MATTERS HERE
//!
//! Before this change the bridge refused with `NoTargetMember { member:
//! "schema_generation" }` exactly when `source.schema_generation.is_some()`,
//! because the kernel fence had no member to carry the observation into. That is
//! not a rare edge: `eliot_ecxf::ExportFence::validate` REFUSES a fence that
//! carries no generation observation at all
//! (`crates/storage/eliot-ecxf/src/lib.rs:253`), so EVERY fence the interchange
//! owner will accept carries `Some(...)`. The two rules therefore excluded each
//! other completely: the only fences the bridge accepted were fences the
//! interchange owner rejected, and every fence the interchange owner issued was
//! refused by the bridge. No lawfully obtained fence could ever be converted,
//! which is what left `KernelBackupCapture::capture` with no producer for the
//! `export_fence` its `CaptureRequest` requires and left the `backup.create`
//! front door unable to reach the capture owner.
//!
//! Each test below is load-bearing against a SPECIFIC deletion, and the deletion
//! is named in its own comment so a later reader can check it rather than assume
//! it:
//!
//! * [`lawful_interchange_fence_converts_and_keeps_the_observation`] fails if the
//!   `is_some()` refusal is restored, and also if the observation is flattened to a
//!   bare generation string or a digest of one instead of being carried.
//! * [`absent_generation_observation_is_refused_by_name`] fails if the explicit
//!   `is_none()` guard is deleted, because the refusal would then be reported as a
//!   generic carried-fence failure and the absent member would lose its name.
//! * [`generation_read_at_another_boundary_is_refused`] fails if the
//!   `observed_at != state_fence` comparison in `ExportFence::validate` is
//!   deleted, because a generation read at a DIFFERENT boundary would then cross
//!   as this fence's own observation.
//! * [`populated_residency_reachability_is_still_refused`] fails if the
//!   content-versus-residency refusal is coerced away, which is the substitution
//!   this bridge exists to prevent and the one thing this change must not weaken.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_backup::{EventRange, ExportFence, FenceBridgeRefusal};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ecxf::{BlobReachabilityObservation, SchemaGenerationObservation, SourceObservation};
use eliot_store_api::{OrderingHead, OrderingScopeId, RevisionHead, RevisionKey, ScopeId};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

/// The boundary every fence in this file is read at, and the boundary every
/// observation is expected to have been read at.
fn observed_fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

/// A DIFFERENT valid boundary: same lineage, next authority sequence.
///
/// It is a real, valid state fence and not a corrupted one, because the
/// boundary-mismatch case must isolate the disagreement to the boundary alone. A
/// fence differing only in its authority sequence is a different installation
/// generation, which is exactly the disagreement that refusal is about.
fn other_fence() -> StateFence {
    StateFence::new(test_epoch(2), ResourceGeneration::genesis())
}

/// A 64-hex digest standing in for one observed residency key.
///
/// It is an opaque residency-key digest, never a content digest: that
/// distinction is what the last test proves this change preserves.
fn residency_key() -> String {
    "a".repeat(64)
}

/// The source store's own generation observation, read at `at`.
///
/// Built through the interchange owner's own type, so the fixture cannot drift
/// from what a lawful source store actually emits.
fn observation(at: StateFence) -> SchemaGenerationObservation {
    SchemaGenerationObservation {
        generation: "schema-generation-1".to_owned(),
        observation: SourceObservation {
            observed_by: "store-adapter-under-test".to_owned(),
            observed_at: at,
        },
    }
}

/// One complete interchange fence, built from the interchange owner's own types so
/// the fixture cannot drift from what a lawful source store actually emits.
///
/// This builder performs NO validation of its own, because not every case in this
/// file is a fence the interchange owner would accept: the boundary-mismatch case
/// deliberately is not, and asserting lawfulness here would panic on it. Call
/// [`assert_lawful_interchange_fence`] in each case whose fence is supposed to be
/// lawful, so no test can quietly start asserting a refusal over an input the
/// source owner would itself have refused.
///
/// `reachable` selects whether the source declared any reachable residency key.
/// An OBSERVED EMPTY live set is the convertible case (it is a store statement
/// about zero blobs); a populated one is the refusal case.
fn interchange_fence(
    fence: StateFence,
    generation_at: StateFence,
    reachable: bool,
) -> eliot_ecxf::ExportFence {
    let source = eliot_ecxf::ExportFence {
        export_id: "export-2569-bridge".to_owned(),
        schema_generation: Some(observation(generation_at)),
        store_generation: "store-generation-1".to_owned(),
        state_fence: fence.clone(),
        scope_id: Some(ScopeId::new("scope-2569-bridge").expect("valid scope")),
        revision_heads: vec![RevisionHead {
            key: RevisionKey::new("canonical-events".to_owned()).expect("valid revision key"),
            revision: 7,
            state_fence: fence.clone(),
        }],
        ordering_heads: vec![OrderingHead {
            scope: OrderingScopeId::new("ordering-2569".to_owned()).expect("valid ordering scope"),
            sequence: 11,
            state_fence: fence.clone(),
        }],
        event_range: EventRange {
            first_sequence: Some(1),
            last_sequence: Some(3),
            count: 3,
        },
        blob_reachability_manifest: Some(BlobReachabilityObservation {
            residency_key_digests: if reachable {
                vec![residency_key()]
            } else {
                Vec::new()
            },
            observation: SourceObservation {
                observed_by: "store-adapter-under-test".to_owned(),
                observed_at: fence.clone(),
            },
        }),
        consistent: true,
    };
    source
}

/// Proves one fixture is a fence the interchange owner ITSELF accepts.
///
/// It is called by every case whose fence is meant to be lawful, so a case can
/// never pass by asserting a refusal over an input the source owner would have
/// rejected too. If this ever fails, that case is measuring the wrong thing and
/// would silently stop being about the bridge.
fn assert_lawful_interchange_fence(source: &eliot_ecxf::ExportFence) {
    source
        .validate()
        .expect("fixture is a lawful interchange fence");
}

/// POSITIVE: one lawfully obtained complete input converts, and every required
/// field survives the crossing.
///
/// Load-bearing against TWO deletions, both named:
/// * restoring the `schema_generation.is_some()` refusal in `try_from` makes this
///   return `Err`, which is exactly the pre-change state of the repository;
/// * replacing the carried observation with a bare `String` generation would drop
///   `observed_by`/`observed_at`, and the equality assertions on the whole
///   observation catch that, because the test compares the WHOLE value against
///   the source's, not one field of it.
#[test]
fn lawful_interchange_fence_converts_and_keeps_the_observation() {
    let fence = observed_fence();
    let source = interchange_fence(fence.clone(), fence.clone(), false);
    assert_lawful_interchange_fence(&source);

    let converted = ExportFence::try_from(&source).expect("a lawful fence converts");

    // The observation crosses as the OWNER'S OWN value, not as a bare string and
    // not as a digest of one: I05-10 makes the generation checkable against the
    // source store, and only the observation names which source read it and at
    // which boundary.
    assert_eq!(
        converted.schema_generation.as_ref(),
        source.schema_generation.as_ref(),
        "the generation observation must cross verbatim, provenance included"
    );
    // The rest of the fence is carried by value too, so a converter that quietly
    // dropped or re-derived any member would be caught here rather than at a
    // restore.
    assert_eq!(converted.export_id, source.export_id);
    assert_eq!(converted.store_generation, source.store_generation);
    assert_eq!(converted.state_fence, source.state_fence);
    assert_eq!(converted.scope_id, source.scope_id);
    assert_eq!(converted.revision_heads, source.revision_heads);
    assert_eq!(converted.ordering_heads, source.ordering_heads);
    assert_eq!(converted.event_range, source.event_range);
    assert!(converted.consistent);
    // An OBSERVED EMPTY live set is a store statement about zero blobs, so it
    // crosses as the empty list it is and is not confused with silence.
    assert!(
        converted.blob_reachability_manifest.is_empty(),
        "an observed empty live set converts as the empty list, not as a refusal"
    );
    // The kernel fence's own validator agrees with the crossing.
    converted
        .validate()
        .expect("the converted kernel fence validates");
}

/// REFUSAL: an absent generation observation is refused BY NAME.
///
/// Load-bearing: delete the explicit `if source.schema_generation.is_none()`
/// guard in `try_from` and this no longer sees `SourceMemberAbsent` — the carried
/// fence would be validated instead and the refusal reported as
/// `CarriedFenceRefused`, so the absent member would lose the name an operator
/// and a reader need.
#[test]
fn absent_generation_observation_is_refused_by_name() {
    let fence = observed_fence();
    let mut source = interchange_fence(fence.clone(), fence.clone(), false);
    assert_lawful_interchange_fence(&source);
    // The ONLY departure from lawfulness, and it is the case under test.
    source.schema_generation = None;

    match ExportFence::try_from(&source) {
        Err(FenceBridgeRefusal::SourceMemberAbsent { member }) => {
            assert_eq!(
                member, "schema_generation",
                "the refusal must name the member no source observed"
            );
        }
        other => panic!("expected a named absent-member refusal, got {other:?}"),
    }
}

/// REFUSAL: a generation read at a DIFFERENT boundary does not cross.
///
/// The interchange owner refuses this fence itself, and so must the kernel fence
/// — the observation's `observed_at` is compared with the fence's own
/// `state_fence`, which is the same two-recorded-positions comparison
/// `eliot_ecxf::ExportFence::validate` makes. A generation read at a different
/// moment describes a different store, so it cannot stand in for this fence's.
///
/// Load-bearing: delete `if observed.observation.observed_at != self.state_fence`
/// from `ExportFence::validate` in `crates/storage/eliot-backup/src/lib.rs` and
/// this conversion SUCCEEDS, because the observation would then cross unchallenged
/// under a fence it was never read at.
#[test]
fn generation_read_at_another_boundary_is_refused() {
    let fence = observed_fence();
    // Lawful in every other respect; ONLY the boundary disagrees. This fence is
    // deliberately NOT lawful, and is therefore not passed through
    // `assert_lawful_interchange_fence`: the interchange owner refuses it for
    // exactly the reason the kernel fence must refuse it too, and asserting
    // lawfulness here would panic on the case under test.
    let source = interchange_fence(fence.clone(), other_fence(), false);

    match ExportFence::try_from(&source) {
        Err(FenceBridgeRefusal::CarriedFenceRefused { reason }) => {
            assert!(
                reason.contains("schema_generation"),
                "the refusal must name the generation observation, got {reason:?}"
            );
        }
        other => {
            panic!("expected a carried-fence refusal for the boundary mismatch, got {other:?}")
        }
    }
}

/// REFUSAL: a POPULATED residency-key reachability set is still refused.
///
/// This is the content-versus-residency identity distinction, and it is the one
/// refusal this change must NOT have weakened. The interchange fence's set holds
/// opaque RESIDENCY-key digests (I05-13 forbids merging records whose content
/// digests match), while the kernel member is read as a content-digest bijection.
/// Re-parsing a residency key as a content identity would type-check and would
/// still assert an identity no owner ever proved.
///
/// Load-bearing: coerce this case instead of refusing it — for instance by
/// clearing the list before the emptiness check — and this test fails, because
/// the refusal is the guarantee.
#[test]
fn populated_residency_reachability_is_still_refused() {
    let fence = observed_fence();
    let source = interchange_fence(fence.clone(), fence.clone(), true);
    assert_lawful_interchange_fence(&source);

    match ExportFence::try_from(&source) {
        Err(FenceBridgeRefusal::ResidencyKeyIsNotContentIdentity) => {}
        other => panic!("expected the residency-versus-content refusal, got {other:?}"),
    }
}
