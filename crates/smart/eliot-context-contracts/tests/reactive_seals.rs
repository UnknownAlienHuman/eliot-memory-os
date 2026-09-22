//! Production seal proof: owner-assembled projections seal with computed
//! digests; caller digest text is overwritten, never trusted; post-seal
//! mutation fails validation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/reactive.rs"]
mod support;

use eliot_context_contracts::{CriticalAttentionProjection, ReactiveInputError};

fn attention_projection() -> CriticalAttentionProjection {
    CriticalAttentionProjection {
        owner_id: "owner".to_owned(),
        source_revision: "r1".to_owned(),
        snapshot_revision: "r1".to_owned(),
        task_id: support::task(),
        scope_id: support::scope(),
        state_fence: support::fence(),
        members: Vec::new(),
        missing_coverage: Vec::new(),
        projection_digest: String::new(),
    }
}

fn flip_first_hex_byte(digest: &mut String) {
    let replacement = if digest.starts_with('0') { '1' } else { '0' };
    digest.replace_range(0..1, &replacement.to_string());
}

#[test]
fn session_seal_computes_digest_and_validates() {
    let sealed = eliot_context_contracts::SessionDeliverySnapshot::seal(support::empty_snapshot())
        .expect("seal computes the snapshot digest");
    assert_eq!(sealed.snapshot_digest.len(), 64);
    sealed.validate().expect("sealed snapshot validates");
}

#[test]
fn session_seal_overwrites_caller_digest_text() {
    let mut snapshot = support::empty_snapshot();
    snapshot.snapshot_digest = "f".repeat(64);
    let sealed = eliot_context_contracts::SessionDeliverySnapshot::seal(snapshot)
        .expect("caller digest text is overwritten, never trusted");
    sealed.validate().expect("sealed snapshot validates");
}

#[test]
fn mutated_session_digest_rejected_after_seal() {
    let mut sealed =
        eliot_context_contracts::SessionDeliverySnapshot::seal(support::empty_snapshot())
            .expect("seal computes the snapshot digest");
    flip_first_hex_byte(&mut sealed.snapshot_digest);
    assert!(matches!(
        sealed.validate(),
        Err(ReactiveInputError::DigestMismatch { .. })
    ));
}

#[test]
fn attention_seal_computes_digest_and_validates() {
    let sealed = CriticalAttentionProjection::seal(attention_projection())
        .expect("seal computes the projection digest");
    assert_eq!(sealed.projection_digest.len(), 64);
    sealed.validate().expect("sealed projection validates");
}

#[test]
fn mutated_attention_digest_rejected_after_seal() {
    let mut sealed =
        CriticalAttentionProjection::seal(attention_projection()).expect("seal computes digest");
    flip_first_hex_byte(&mut sealed.projection_digest);
    assert!(matches!(
        sealed.validate(),
        Err(ReactiveInputError::DigestMismatch { .. })
    ));
}

#[test]
fn coverage_seal_computes_digest_and_validates() {
    let sealed = eliot_context_contracts::IntegrationCoverageProfile::seal(support::profile())
        .expect("seal computes the profile digest");
    assert_eq!(sealed.profile_digest.len(), 64);
    sealed.validate().expect("sealed profile validates");
}

#[test]
fn mutated_coverage_digest_rejected_after_seal() {
    let mut sealed = eliot_context_contracts::IntegrationCoverageProfile::seal(support::profile())
        .expect("seal computes digest");
    flip_first_hex_byte(&mut sealed.profile_digest);
    assert!(matches!(
        sealed.validate(),
        Err(ReactiveInputError::DigestMismatch { .. })
    ));
}
