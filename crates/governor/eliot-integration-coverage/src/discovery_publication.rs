//! O2 live discovery publication (I7.16, I7.22): typed event producers over
//! live Governor owner state.
//!
//! Ownership (read first):
//! - The Governor (via [`GovernorCoverageDerivation`]) is the sole owner of
//!   [`GovernanceProfile`] revisions. Discovery output (host/adapter
//!   fingerprint observation) produces candidate
//!   ([`IntegrationCoverageProfile`], `verified == false`) profiles only;
//!   exact active-fingerprint production observation promotes them.
//! - This module reads exactly that live owner state: the verified
//!   candidate's per-event facts plus the derivation binding. It mints no
//!   identity, generation, contract, mode, ceiling, receipt, or gap fact.
//!
//! What is live here (per logical event, from the verified candidate):
//! `event`, `disposition`, `ordering`, `completeness`, `proof_ceiling`,
//! `source`, `gaps` — see [`DiscoveryEventRecord`].
//!
//! What has no live owner in-tree (base `8eba4022`, verified by grep):
//! discovery identities (`host_id`, `runtime_id`, `interface_id`,
//! `recipient_id`), the three generations, the covered-surface contract
//! identity, `supported_modes`, the three ceilings, owner-claim event
//! receipts, and owner-declared gaps. Nothing constructs the planner's
//! contract `eliot_context_contracts::IntegrationCoverageProfile` or its
//! `CoverageEvidence` outside tests. [`missing_coverage_identity_facts`]
//! names those facts with the exact D2 `resolve_coverage_envelope`
//! vocabulary so a resolver drops into `serve_live_six_slot` unchanged:
//! envelope first, then the fail-closed inventory, never a forged envelope.
//!
//! Type-difference log (never conflated, no `From` bridges):
//! - Governor `IntegrationCoverageProfile` (fingerprint/verified candidate
//!   vocabulary, this crate) vs planner
//!   `eliot_context_contracts::IntegrationCoverageProfile`
//!   (host/runtime/interface capability vocabulary): shared name, nothing
//!   else. [`DiscoveryEventRecord`] carries the governor vocabulary only.
//! - Governor `EventCoverage.disposition` (`ENFORCED | OBSERVED |
//!   EXPLICIT_OBSERVE | UNAVAILABLE`) is NOT the contract
//!   `supported_modes` (`Vec<ReactiveDeliveryMode>`): a per-event
//!   observation axis never becomes a delivery-mode allow-list.
//! - Governor `EventCoverage.proof_ceiling` (`String`: the observed ceiling
//!   label) is NOT the contract `proof_ceiling` (`ProofCeiling` typed
//!   ceiling): a label never becomes a typed ceiling without the
//!   ceiling-owning authority.
//!
//! Field map (governor fact → contract profile field):
//!
//! ```text
//! candidate.fingerprint            → binds candidate to derivation (equality only)
//! derivation.current().revision    → profile_revision (text form)
//! derivation.current().completeness→ completeness (Complete/Partial/Unknown;
//!                                    NotApplicable has no mapping, fails closed)
//! derivation.current().verified    → verified posture gate (must be true)
//! candidate.gaps                   → gap evidence contribution (carried, never minted)
//! candidate.events[*]              → DiscoveryEventRecord[*] (this module;
//!                                    contract CoverageEvidence needs owner
//!                                    identities + receipts: NO LIVE OWNER)
//! <no live owner>                  → host_id, runtime_id, interface_id,
//!                                    recipient_id, host/runtime/recipient
//!                                    generations, contract, supported_modes,
//!                                    privacy/effect/proof ceilings, owner gaps
//! ```

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    ALL_EVENTS, DispatchOrdering, EventCompleteness, EventCoverage, EventDisposition,
    GovernorCoverageDerivation, IntegrationCoverageProfile, LogicalEvent,
};

/// Fail-closed discovery publication errors.
///
/// Cause vocabulary matches D2's `serve_live_six_slot` resolver order
/// (`coverage.candidate-unverified`, `coverage.candidate_fingerprint`,
/// `governance-profile (no live derivation)`) so a resolver over these
/// producers fails closed with unchanged names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiscoveryPublicationError {
    /// No live derivation exists to bind the candidate against.
    #[error("governance-profile (no live derivation)")]
    NoLiveDerivation,
    /// The candidate is not verified for production claims.
    #[error("coverage.candidate-unverified")]
    CandidateUnverified,
    /// The candidate fingerprint does not match the live derivation.
    #[error("coverage.candidate_fingerprint mismatch")]
    FingerprintMismatch,
    /// The candidate failed its in-tree validation.
    #[error("invalid candidate: {0}")]
    InvalidCandidate(#[from] super::CoverageError),
}

/// One logical event's live discovery facts, read from the verified
/// candidate bound to the live derivation.
///
/// Governor vocabulary throughout: `proof_ceiling`/`source` are the
/// observed labels, never typed contract ceilings or content references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryEventRecord {
    /// Active fingerprint the candidate was verified against.
    pub fingerprint: String,
    /// Which of the ten [`ALL_EVENTS`] logical events this record covers.
    pub event: LogicalEvent,
    /// Live observation/enforcement axis for the event.
    pub disposition: EventDisposition,
    /// Live pre/post-dispatch ordering for the event.
    pub ordering: DispatchOrdering,
    /// Live completeness of the event stream.
    pub completeness: EventCompleteness,
    /// Live observed proof-ceiling label (not a typed contract ceiling).
    pub proof_ceiling: String,
    /// Live source evidence label for the event observation.
    pub source: String,
    /// Live gap evidence for the event (non-empty when partial).
    pub gaps: Vec<String>,
}

/// Publish the live discovery-event set from the verified candidate bound
/// to the live derivation.
///
/// One causal read per call: validates the candidate with its in-tree
/// constructor rules, requires `verified`, binds
/// `candidate.fingerprint` to `derivation.current().fingerprint` by exact
/// equality, then yields one [`DiscoveryEventRecord`] per logical event in
/// [`ALL_EVENTS`] canonical order. Holds no state, mints no digest: the
/// digest owner is the contract-profile assembler (D2 lane), which hashes
/// the assembled profile, never these records alone.
///
/// # Errors
///
/// Returns [`DiscoveryPublicationError`] when no live derivation exists,
/// the candidate is unverified or foreign, or the candidate fails
/// validation. Never synthesizes an event.
pub fn publish_discovery_events(
    candidate: &IntegrationCoverageProfile,
    derivation: &GovernorCoverageDerivation,
) -> Result<Vec<DiscoveryEventRecord>, DiscoveryPublicationError> {
    candidate.validate()?;
    if !candidate.verified {
        return Err(DiscoveryPublicationError::CandidateUnverified);
    }
    let live = derivation
        .current()
        .ok_or(DiscoveryPublicationError::NoLiveDerivation)?;
    if candidate.fingerprint != live.fingerprint {
        return Err(DiscoveryPublicationError::FingerprintMismatch);
    }
    let mut records = Vec::with_capacity(ALL_EVENTS.len());
    for event in ALL_EVENTS {
        let coverage: &EventCoverage = candidate.events.iter().find(|coverage| {
            coverage.event == event
        }).ok_or(DiscoveryPublicationError::InvalidCandidate(
            super::CoverageError::InvalidField("coverage.events.incomplete"),
        ))?;
        records.push(DiscoveryEventRecord {
            fingerprint: candidate.fingerprint.clone(),
            event,
            disposition: coverage.disposition,
            ordering: coverage.ordering,
            completeness: coverage.completeness,
            proof_ceiling: coverage.proof_ceiling.clone(),
            source: coverage.source.clone(),
            gaps: coverage.gaps.clone(),
        });
    }
    Ok(records)
}

/// Exact coverage-envelope facts with no live owner, in D2
/// `resolve_coverage_envelope` order.
///
/// Discovery identities, generations, the covered-surface contract,
/// delivery modes, ceilings, owner-claim events, and owner gaps live with
/// the I7.16 coverage owner, never with the Governor derivation or the
/// bridge. A resolver consumes [`publish_discovery_events`] for the live
/// event facts and fails closed with exactly these names for the rest, so
/// it drops into `serve_live_six_slot` unchanged.
#[must_use]
pub const fn missing_coverage_identity_facts() -> &'static [&'static str] {
    &[
        "coverage.host_id",
        "coverage.runtime_id",
        "coverage.interface_id",
        "coverage.recipient_id",
        "coverage.host_generation",
        "coverage.runtime_generation",
        "coverage.recipient_generation",
        "coverage.contract",
        "coverage.supported_modes",
        "coverage.privacy_ceiling",
        "coverage.effect_ceiling",
        "coverage.proof_ceiling",
        "coverage.events/owner-claims",
        "coverage.owner_gaps",
    ]
}
