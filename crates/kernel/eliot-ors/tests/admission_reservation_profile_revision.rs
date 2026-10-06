#![cfg(feature = "test-support")]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
//! Control-reserve profile revision binding for admission reservations
//! (issues #1679 W11, #1701 R2-owners).
//!
//! The producer half of the O3/O6 handoff: activation commits the
//! composition-retained CURRENT control-reserve profile revision onto the
//! durable row, and the launch-prerequisite verifier revalidates it before any
//! effect. A reservation activated under a superseded view refuses as the
//! owner's own `STALE_CAPACITY_PROFILE` variant instead of launching on stale
//! capacity. Compiled only with the `test-support` feature, enabled for every
//! `cargo test -p eliot-ors` invocation through the crate's dev-dependency.
//!
//! The canonical commit below is shape-valid fixture evidence in the same sense
//! as the 1884 seal parts: every digest has the digest shape and every identity
//! is non-blank, so the refusals these tests assert come from the REVISION
//! logic under test rather than from malformed owner evidence.

use std::error::Error;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ReceiptId, ResourceGeneration, StateFence};
use eliot_ors::{
    AdmissionReservationActivationRequest, AdmissionReservationCanonicalAdmission,
    AdmissionReservationClaimRef, AdmissionReservationClaims,
    AdmissionReservationLaunchPrerequisite, AdmissionReservationStageRequest, OpaqueLabel,
    OperationIdentity, OperationalRecoveryStore, OrsError, StateFenceSnapshot,
    activate_admission_reservation_from_owner_evidence, stage_admission_reservation_inactive,
    test_support::{KernelRouteStoreFixture, kernel_route_writer_epoch},
    verify_admission_reservation_launch_prerequisite,
};
use eliot_receipts::ReceiptIdentity;

const LINEAGE_1679: &str = "550e8400-e29b-41d4-a716-446655440167";
const EPOCH_SEQUENCE: u64 = 7;
const NOW_MS: i64 = 1_700_000_000_000;
const CURRENT_REVISION: &str = "generation=7:epoch=test-lineage-1679";
const SUPERSEDED_REVISION: &str = "generation=6:epoch=test-lineage-1679";

/// A 64-lowercase-hex placeholder digest. Fixture coordinates, never a computed
/// digest: the only values that carry meaning here are the revision strings.
fn hex_digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn claim_ref(
    name: &str,
    digest_byte: char,
) -> Result<AdmissionReservationClaimRef, Box<dyn Error>> {
    Ok(AdmissionReservationClaimRef {
        reference: OpaqueLabel::new(name)?,
        sha256: hex_digest(digest_byte),
    })
}

fn claims() -> Result<AdmissionReservationClaims, Box<dyn Error>> {
    Ok(AdmissionReservationClaims {
        resources: claim_ref("owner-resources-1679", 'a')?,
        lane: claim_ref("owner-lane-1679", 'b')?,
        environment: claim_ref("owner-environment-1679", 'c')?,
        effects: claim_ref("owner-effects-1679", 'd')?,
        quota_view: claim_ref("owner-quota-view-1679", 'e')?,
    })
}

fn fence_snapshot() -> Result<StateFenceSnapshot, Box<dyn Error>> {
    let lineage = EpochLineageId::new(LINEAGE_1679)?;
    let epoch = EpochId::new(
        lineage,
        NonZeroU64::new(EPOCH_SEQUENCE).ok_or("1679 nonzero")?,
    )?;
    let fence = StateFence::new(epoch, ResourceGeneration::new(EPOCH_SEQUENCE)?);
    Ok(StateFenceSnapshot::capture(&fence, EPOCH_SEQUENCE)?)
}

fn receipt(id: &str, digest_byte: char) -> Result<ReceiptIdentity, Box<dyn Error>> {
    Ok(ReceiptIdentity {
        receipt_id: ReceiptId::new(id).map_err(|error| format!("1679 receipt id: {error}"))?,
        canonical_sha256: hex_digest(digest_byte),
    })
}

/// The retained canonical commit, shape-valid by construction: the launch
/// intent names the same operation as the admission, digests have digest
/// shape, and the bound receipt is the canonical receipt the activation
/// carries, so the row's own join check passes and only the revision logic
/// is under test.
fn canonical_commit(
    canonical_receipt: &ReceiptIdentity,
) -> Result<AdmissionReservationCanonicalAdmission, Box<dyn Error>> {
    Ok(AdmissionReservationCanonicalAdmission {
        operation_id: OperationIdentity::new("canonical-operation-1679")?,
        idempotency_key: "idempotency-1679".to_owned(),
        admission_digest: hex_digest('f'),
        mutation_plan_digest: hex_digest('e'),
        commit_id: "commit-1679".to_owned(),
        launch_outbox_operation_id: OperationIdentity::new("canonical-operation-1679")?,
        launch_outbox_id: "launch-outbox-1679".to_owned(),
        admission_receipt: canonical_receipt.clone(),
        committed_at_marker: NOW_MS.to_string(),
    })
}

fn stage_request(tag: &str) -> Result<AdmissionReservationStageRequest, Box<dyn Error>> {
    Ok(AdmissionReservationStageRequest {
        reservation_id: OperationIdentity::new(format!("reservation-1679-{tag}"))?,
        work_item_id: OperationIdentity::new(format!("work-1679-{tag}"))?,
        proposed_attempt_id: OperationIdentity::new(format!("attempt-1679-{tag}"))?,
        operation_id: OperationIdentity::new(format!("stage-operation-1679-{tag}"))?,
        claims: claims()?,
        authority_epoch: kernel_route_writer_epoch(LINEAGE_1679, EPOCH_SEQUENCE)?,
        state_fence: fence_snapshot()?,
        expires_at_ms: NOW_MS + 3_600_000,
        now_unix_ms: NOW_MS,
    })
}

/// Activates one staged reservation under `revision` through the real owner
/// entry point, returning the durable active snapshot read back from the row.
fn activate_under_revision(
    store: &eliot_ors::RedbRecoveryStore,
    tag: &str,
    revision: &str,
) -> Result<eliot_ors::AdmissionReservationSnapshot, Box<dyn Error>> {
    let staged = stage_admission_reservation_inactive(store, &stage_request(tag)?)?;
    let canonical_receipt = receipt(&format!("canonical-1679-{tag}"), 'a')?;
    let request = AdmissionReservationActivationRequest {
        reservation_id: OperationIdentity::new(format!("reservation-1679-{tag}"))?,
        work_item_id: OperationIdentity::new(format!("work-1679-{tag}"))?,
        proposed_attempt_id: OperationIdentity::new(format!("attempt-1679-{tag}"))?,
        operation_id: OperationIdentity::new(format!("activate-operation-1679-{tag}"))?,
        claims: claims()?,
        canonical_admission_receipt: canonical_receipt.clone(),
        canonical_admission: Some(canonical_commit(&canonical_receipt)?),
        activation_receipt: receipt(&format!("activation-1679-{tag}"), 'b')?,
        capacity_profile_revision: revision.to_owned(),
        expected_current_receipt: staged.snapshot.receipt().clone(),
        authority_epoch: kernel_route_writer_epoch(LINEAGE_1679, EPOCH_SEQUENCE)?,
        state_fence: fence_snapshot()?,
        now_ms: NOW_MS + 1_000,
    };
    let outcome = activate_admission_reservation_from_owner_evidence(store, &request)?;
    Ok(outcome.snapshot)
}

fn verify_inputs(
    tag: &str,
) -> Result<
    (
        OperationIdentity,
        OperationIdentity,
        eliot_ors::EpochLineage,
        StateFenceSnapshot,
    ),
    Box<dyn Error>,
> {
    Ok((
        OperationIdentity::new(format!("work-1679-{tag}"))?,
        OperationIdentity::new(format!("attempt-1679-{tag}"))?,
        kernel_route_writer_epoch(LINEAGE_1679, EPOCH_SEQUENCE)?,
        fence_snapshot()?,
    ))
}

#[test]
fn activation_binds_the_current_profile_revision() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1679-revision-bound")?;
    let store = fixture.store().as_ref();
    let snapshot = activate_under_revision(store, "bound", CURRENT_REVISION)?;
    let record = snapshot.record();
    assert_eq!(
        record.capacity_profile_revision, CURRENT_REVISION,
        "the active row carries the revision the activation bound"
    );
    let evidence = record
        .last_transition
        .as_ref()
        .and_then(|transition| transition.activation.as_ref())
        .ok_or("1679: the activating transition must retain its evidence")?;
    assert_eq!(
        evidence.capacity_profile_revision, CURRENT_REVISION,
        "the retained activation evidence carries the same revision as the row"
    );
    Ok(())
}

#[test]
fn verify_accepts_current_revision_and_exposes_it() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1679-revision-current")?;
    let store = fixture.store().as_ref();
    let snapshot = activate_under_revision(store, "current", CURRENT_REVISION)?;
    let (work, attempt, epoch, fence) = verify_inputs("current")?;
    match verify_admission_reservation_launch_prerequisite(
        Some(&snapshot),
        &work,
        &attempt,
        &epoch,
        &fence,
        CURRENT_REVISION,
        NOW_MS + 2_000,
    )? {
        AdmissionReservationLaunchPrerequisite::Active(active) => {
            assert_eq!(
                active.capacity_profile_revision(),
                CURRENT_REVISION,
                "the sealed active value exposes the committed revision for the consumer"
            );
            active.activation_receipt()?;
            active.canonical_admission_receipt()?;
        }
        other => {
            return Err(format!(
                "a reservation active under the current revision must verify Active, got {other:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn verify_refuses_superseded_revision_by_name() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1679-revision-stale")?;
    let store = fixture.store().as_ref();
    let snapshot = activate_under_revision(store, "stale", SUPERSEDED_REVISION)?;
    let (work, attempt, epoch, fence) = verify_inputs("stale")?;
    match verify_admission_reservation_launch_prerequisite(
        Some(&snapshot),
        &work,
        &attempt,
        &epoch,
        &fence,
        CURRENT_REVISION,
        NOW_MS + 2_000,
    )? {
        AdmissionReservationLaunchPrerequisite::StaleCapacityProfile {
            reservation,
            expected_capacity_profile_revision,
        } => {
            assert_eq!(
                reservation.reservation_id,
                snapshot.record().reservation_id,
                "the refusal names the exact durable row"
            );
            assert_eq!(
                expected_capacity_profile_revision, CURRENT_REVISION,
                "the refusal echoes the current revision the caller verified against"
            );
        }
        other => {
            return Err(format!("a reservation activated under a superseded revision must refuse as STALE_CAPACITY_PROFILE, got {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn verify_refuses_blank_expected_revision() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1679-revision-blank")?;
    let store = fixture.store().as_ref();
    let snapshot = activate_under_revision(store, "blank", CURRENT_REVISION)?;
    let (work, attempt, epoch, fence) = verify_inputs("blank")?;
    for blank in ["", "   "] {
        match verify_admission_reservation_launch_prerequisite(
            Some(&snapshot),
            &work,
            &attempt,
            &epoch,
            &fence,
            blank,
            NOW_MS + 2_000,
        ) {
            Err(OrsError::InvalidField { field, .. }) => assert_eq!(
                field,
                "admission_reservation_launch_prerequisite.expected_capacity_profile_revision",
                "a blank expected revision is a caller-shape refusal, never a state"
            ),
            other => {
                return Err(format!(
                    "a blank expected revision must be refused as InvalidField, got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn activation_refuses_blank_revision_before_any_mutation() -> Result<(), Box<dyn Error>> {
    let fixture = KernelRouteStoreFixture::open("1679-revision-required")?;
    let store = fixture.store().as_ref();
    let staged = stage_admission_reservation_inactive(store, &stage_request("required")?)?;
    let canonical_receipt = receipt("canonical-1679-required", 'a')?;
    for blank in [String::new(), "   ".to_owned()] {
        let request = AdmissionReservationActivationRequest {
            reservation_id: OperationIdentity::new("reservation-1679-required")?,
            work_item_id: OperationIdentity::new("work-1679-required")?,
            proposed_attempt_id: OperationIdentity::new("attempt-1679-required")?,
            operation_id: OperationIdentity::new("activate-operation-1679-required")?,
            claims: claims()?,
            canonical_admission_receipt: canonical_receipt.clone(),
            canonical_admission: Some(canonical_commit(&canonical_receipt)?),
            activation_receipt: receipt("activation-1679-required", 'b')?,
            capacity_profile_revision: blank,
            expected_current_receipt: staged.snapshot.receipt().clone(),
            authority_epoch: kernel_route_writer_epoch(LINEAGE_1679, EPOCH_SEQUENCE)?,
            state_fence: fence_snapshot()?,
            now_ms: NOW_MS + 1_000,
        };
        match activate_admission_reservation_from_owner_evidence(store, &request) {
            Err(OrsError::InvalidField { field, .. }) => assert_eq!(
                field, "admission_reservation_activation.capacity_profile_revision",
                "activation without a bound revision refuses at the required-at-activate coordinate"
            ),
            other => {
                return Err(format!("activation with a blank revision must be refused as InvalidField, got {other:?}").into());
            }
        }
    }
    let reread = store
        .load_kernel_admission_reservation(&OperationIdentity::new("reservation-1679-required")?)?
        .ok_or("1679: the staged row must still exist after the refused activations")?;
    assert_eq!(
        reread.record().state,
        eliot_ors::AdmissionReservationState::StagedInactive,
        "a refused activation writes nothing: the row stays staged"
    );
    Ok(())
}
