//! Cell-declared package proof entrypoint for the explicit lifecycle receipts
//! of `pub mod lifecycle` (`smart.epistemic.position`, implementation
//! `src/lifecycle.rs`).
//!
//! Every assertion below is the assertion already held by the inline
//! `#[cfg(test)] mod tests` in `src/lifecycle.rs`, re-proved through the crate's
//! public surface only (the `eliot_epistemic::lifecycle` module path), so this
//! entrypoint is independently invocable without compiling the cell's
//! implementation module as a test target.
//!
//! `src/lifecycle.rs` is outside this work unit's write scope, so the inline
//! module is deliberately left in place and this entrypoint is an *additional*
//! proof of the same public behaviour rather than a replacement. The duplicated
//! coverage is the honest state until the inline module is removed by that
//! file's own owner; nothing here weakens, widens or reinterprets an assertion.
//!
//! The proofs cover the receipted transitions themselves: one observation
//! yields an inspectable chain, a correction is forward supersession with the
//! original reconstructible, a model paraphrase cannot claim elevated standing
//! without an independent basis, verifier-backed standing names its run for
//! every actor, a refused promotion holds prior standing rather than forking a
//! fresh output, a discontinuous chain is refused, and the wire surface neither
//! launders a tampered digest nor a duplicated input handle.
//!
//! One helper differs from the inline module by necessity, not by weakening:
//! the inline `digest_of` reaches `sha256_hex` through the implementation
//! file's own private `use`; here it calls the same public
//! `eliot_contracts::sha256_hex` over the same label bytes, so the proof
//! digests are identical values.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ClockReading, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    sha256_hex,
};
use eliot_epistemic::lifecycle::{
    ActorIdentity, ActorKind, AdmissionOutcome, LifecycleError, LifecycleReceipt,
    LifecycleReceiptParams, LifecycleRole, QualifyingBasis, SourceAnchor, verify_chain,
};
use eliot_evidence::EpistemicStatus;

fn test_epoch(sequence: u64) -> EpochId {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage-A");
    EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid fixture artifact id")
}

fn source(value: &str) -> SourceId {
    SourceId::new(value).expect("valid fixture source id")
}

fn digest_of(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn actor(kind: ActorKind) -> ActorIdentity {
    ActorIdentity {
        kind,
        identity: "fixture-actor".to_owned(),
        authority_basis: "fixture-grant".to_owned(),
    }
}

fn anchor() -> SourceAnchor {
    SourceAnchor {
        source_id: source("fixture-source"),
        revision: Some("r1".to_owned()),
        raw_handle: Some("raw:fixture:r1".to_owned()),
    }
}

fn clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1),
        known_time_ms: Some(2),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn capture_receipt() -> LifecycleReceipt {
    LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:capture"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::ObservationCandidate,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: actor(ActorKind::DeterministicTransformer),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("obs:raw-1"),
        audit_event_id: None,
        proof_digest: digest_of("capture-proof"),
    })
    .expect("valid capture receipt")
}

#[test]
fn one_observation_yields_inspectable_chain() {
    let capture = capture_receipt()
        .link_audit(id("audit:capture"))
        .expect("audit linkage");
    let promotion = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:claim"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::Claim,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("claim:1"),
        audit_event_id: None,
        proof_digest: digest_of("claim-proof"),
    })
    .expect("valid promotion receipt")
    .link_audit(id("audit:claim"))
    .expect("audit linkage");
    let view = verify_chain(&[capture, promotion]).expect("inspectable chain");
    assert_eq!(view.original_input, id("obs:raw-1"));
    assert_eq!(view.current_output, id("claim:1"));
    assert_eq!(view.ordered.len(), 2);
    assert_eq!(view.ordered[1].proposed_role, LifecycleRole::Claim);
    assert!(view.ordered.iter().all(LifecycleReceipt::is_audit_linked));
}

#[test]
fn correction_is_forward_supersession_with_original_reconstructible() {
    let capture = capture_receipt()
        .link_audit(id("audit:capture"))
        .expect("audit linkage");
    let correction = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:correction"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::ObservationCandidate,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::CorrectedForward,
        qualifying_basis: None,
        supersedes: vec![id("obs:raw-1")],
        output_record_id: id("obs:raw-2"),
        audit_event_id: None,
        proof_digest: digest_of("correction-proof"),
    })
    .expect("valid correction receipt")
    .link_audit(id("audit:correction"))
    .expect("audit linkage");
    assert!(correction.is_correction());
    let view = verify_chain(&[capture.clone(), correction]).expect("forward chain");
    assert_eq!(view.original_input, id("obs:raw-1"));
    assert_eq!(view.current_output, id("obs:raw-2"));
    assert_eq!(view.ordered[0].output_record_id, id("obs:raw-1"));
}

#[test]
fn model_paraphrase_cannot_claim_elevated_standing() {
    let refused = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:paraphrase"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::Proof,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::ModelTransformer),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("proof:1"),
        audit_event_id: None,
        proof_digest: digest_of("paraphrase-proof"),
    });
    assert!(matches!(
        refused,
        Err(LifecycleError::ForbiddenElevation { .. })
    ));
    let qualified = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:paraphrase-q"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::Proof,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::ModelTransformer),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: Some(QualifyingBasis {
            verifier_run_id: Some(id("run:verifier-1")),
            independent_evidence: vec![id("obs:independent-1")],
            authorizing_policy: None,
        }),
        supersedes: Vec::new(),
        output_record_id: id("proof:1"),
        audit_event_id: None,
        proof_digest: digest_of("paraphrase-proof"),
    })
    .expect("independently qualified paraphrase is admitted");
    assert_eq!(qualified.proposed_role, LifecycleRole::Proof);
}

#[test]
fn verifier_backed_standing_requires_a_verifier_run_for_every_actor() {
    let policy_only = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:policy-only"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::VerifierBacked,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: Some(QualifyingBasis {
            verifier_run_id: None,
            independent_evidence: Vec::new(),
            authorizing_policy: Some("policy:r1".to_owned()),
        }),
        supersedes: Vec::new(),
        output_record_id: id("backed:1"),
        audit_event_id: None,
        proof_digest: digest_of("policy-only-proof"),
    });
    assert!(matches!(
        policy_only,
        Err(LifecycleError::VerifierBackedRequiresVerifierRun)
    ));
    let backed = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:backed"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::VerifierBacked,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: Some(QualifyingBasis {
            verifier_run_id: Some(id("run:verifier-1")),
            independent_evidence: Vec::new(),
            authorizing_policy: None,
        }),
        supersedes: Vec::new(),
        output_record_id: id("backed:1"),
        audit_event_id: None,
        proof_digest: digest_of("backed-proof"),
    })
    .expect("verifier-backed standing with a backing run is admitted");
    assert_eq!(backed.proposed_role, LifecycleRole::VerifierBacked);
}

#[test]
fn refused_promotion_cannot_fork_a_fresh_output() {
    let forked = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:forked"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::ObservationCandidate,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::RefusedPromotion,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("obs:fork-1"),
        audit_event_id: None,
        proof_digest: digest_of("forked-proof"),
    });
    assert!(matches!(
        forked,
        Err(LifecycleError::RefusedPromotionMustHold)
    ));
}

#[test]
fn refused_promotion_holds_prior_standing() {
    let changed = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:refused"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::Claim,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::RefusedPromotion,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("obs:raw-1"),
        audit_event_id: None,
        proof_digest: digest_of("refused-proof"),
    });
    assert!(matches!(
        changed,
        Err(LifecycleError::RefusedPromotionMustHold)
    ));
    let held = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:held"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::ObservationCandidate,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::RefusedPromotion,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("obs:raw-1"),
        audit_event_id: None,
        proof_digest: digest_of("held-proof"),
    })
    .expect("refusal holding prior standing is admitted");
    assert_eq!(held.outcome, AdmissionOutcome::RefusedPromotion);
}

#[test]
fn chain_rejects_discontinuous_prior_state() {
    let capture = capture_receipt()
        .link_audit(id("audit:capture"))
        .expect("audit linkage");
    let disjoint = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: id("receipt:disjoint"),
        input_record_ids: vec![id("obs:raw-1")],
        source_anchor: anchor(),
        prior_role: LifecycleRole::Claim,
        proposed_role: LifecycleRole::Claim,
        prior_status: EpistemicStatus::Supported,
        proposed_status: EpistemicStatus::Supported,
        actor: actor(ActorKind::HumanOperator),
        scope: "scope".to_owned(),
        clock: clock(),
        state_fence: fence(),
        evidence_refs: vec![id("obs:raw-1")],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: id("claim:9"),
        audit_event_id: None,
        proof_digest: digest_of("disjoint-proof"),
    })
    .expect("individually valid receipt")
    .link_audit(id("audit:disjoint"))
    .expect("audit linkage");
    assert!(matches!(
        verify_chain(&[capture, disjoint]),
        Err(LifecycleError::BrokenChain { .. })
    ));
}

#[test]
fn serde_round_trip_preserves_valid_receipt() {
    let receipt = capture_receipt()
        .link_audit(id("audit:capture"))
        .expect("audit linkage");
    let json = serde_json::to_string(&receipt).expect("serializable receipt");
    let decoded: LifecycleReceipt =
        serde_json::from_str(&json).expect("wire-valid receipt decodes");
    assert_eq!(decoded, receipt);
}

#[test]
fn serde_rejects_tampered_digest_and_duplicate_inputs() {
    let receipt = capture_receipt();
    let mut tampered = serde_json::to_value(&receipt).expect("serializable receipt");
    tampered["digest"] = serde_json::json!("0".repeat(64));
    assert!(serde_json::from_value::<LifecycleReceipt>(tampered).is_err());
    let mut duplicated = serde_json::to_value(&receipt).expect("serializable receipt");
    duplicated["input_record_ids"]
        .as_array_mut()
        .expect("inputs array")
        .push(serde_json::json!("obs:raw-1"));
    assert!(serde_json::from_value::<LifecycleReceipt>(duplicated).is_err());
}
