//! O2 discovery identity/coverage owner (I7.16, I7.22): actual owner state,
//! authenticated admission, canonical revisions, and the contract-profile
//! assembler.
//!
//! Ownership:
//! - [`DiscoveryOwner`] is the sole holder of [`CoverageOwnerSnapshot`]
//!   revisions: the binding of discovery identities, generations, covered
//!   contract, supported modes, ceilings, owner-claim events (with owner
//!   receipts), and owner gaps under one revision and digest. It owns the
//!   coverage *snapshot*, never the host, runtime, or recipient themselves;
//!   identities are bound copies, fenced and revisioned, per I7.22.
//! - Admission ([`DiscoveryOwner::admit`]) is the only write path. It takes
//!   typed [`CoverageOwnerInputs`] plus the live [`StateFence`] under which
//!   admission happens, validates every field with the in-tree constructors,
//!   and fails closed otherwise. No second write path exists.
//! - [`assemble_contract_coverage`] reads live Governor derivation state,
//!   the verified candidate, and one admitted snapshot, then yields the
//!   planner's contract `IntegrationCoverageProfile` with its computed
//!   digest. Digest and validation use the contract's own
//!   `canonical_digest`/`validate`; nothing is caller-asserted.
//!
//! Fail-closed inventory: when no snapshot was admitted (or it is stale),
//! the resolver reports exactly
//! [`super::discovery_publication::missing_coverage_identity_facts`]
//! — never a forged envelope, never
//! a complete claim over unavailable facts.
//!
//! Admission contract for events: each admitted [`CoverageEvidence`] carries
//! the source revision observed at discovery time. Assembly binds
//! `profile_revision` to the live derivation revision, and the contract's
//! own `validate` requires every event's `source.source_revision` to equal
//! it. Drifted events fail closed at assembly; re-admission under the live
//! revision is the only recovery.
//!
//! Type-difference log (never conflated, no `From` bridges):
//! - [`CoverageOwnerSnapshot`] stores contract-typed ceilings/modes/events
//!   as admitted owner state; the governor candidate vocabulary
//!   (`EventCoverage`, disposition labels) is derivation input only.
//! - `additional_gaps` in [`assemble_contract_coverage`] carries
//!   non-owner gap evidence (e.g. the bridge freshness gap — the bridge
//!   retains no owner claim receipts) first, preserving D2's gap order
//!   `[bridge, candidate, owner]` without storing bridge facts in owner
//!   state.

use eliot_context_contracts::{
    CoverageEvidence, IntegrationCoverageProfile, ReactiveDeliveryMode, ReactiveInputError,
    SnapshotCompleteness,
};
use eliot_contracts::{
    ContractIdentity, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_protocol::ReactiveContextPrivacy;
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{EventCompleteness, GovernorCoverageDerivation, IntegrationCoverageProfile as GovernorCandidate};

/// Fail-closed coverage-owner errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CoverageOwnerError {
    /// A live binding text or scalar was rejected by its validated
    /// constructor. Names the exact field.
    #[error("invalid coverage owner field: {0}")]
    InvalidField(&'static str),
    /// The admission fence failed validation (never admitted under a
    /// zero-generation fence).
    #[error("coverage admission fence rejected")]
    StaleFence,
    /// One admitted event failed its in-tree validation or disagrees with
    /// the admitted identity/fence/contract binding.
    #[error("coverage owner event rejected: {0:?}")]
    InvalidEvent(ReactiveInputError),
    /// One admitted event disagrees with the admitted profile binding.
    /// Same vocabulary as the contract's `coverage.event_profile_binding`.
    #[error("coverage owner event binding mismatch")]
    EventBinding,
    /// The admitted snapshot could not be canonicalized for its digest.
    #[error("coverage snapshot could not be canonicalized")]
    SnapshotDigest,
}

/// Fail-closed contract-assembly errors. Cause vocabulary matches D2's
/// `serve_live_six_slot` resolver order so delegation keeps unchanged
/// names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CoverageJoinError {
    /// No live derivation exists to bind the candidate against.
    #[error("governance-profile (no live derivation)")]
    NoLiveDerivation,
    /// The derivation completeness has no snapshot mapping.
    #[error("derivation.completeness=NotApplicable (no snapshot mapping)")]
    UnmappedCompleteness,
    /// The candidate is not verified for production claims.
    #[error("coverage.candidate-unverified")]
    CandidateUnverified,
    /// The candidate fingerprint does not match the live derivation.
    #[error("coverage.candidate_fingerprint mismatch")]
    FingerprintMismatch,
    /// No snapshot was ever admitted (zero revision is never live).
    #[error("coverage snapshot not admitted")]
    EmptySnapshot,
    /// The admitted snapshot fence does not equal the live fence.
    #[error("coverage snapshot fence is stale")]
    StaleSnapshotFence,
    /// The assembled contract profile failed its in-tree validation or
    /// digest check.
    #[error("assembled contract coverage invalid: {0:?}")]
    Invalid(ReactiveInputError),
}

/// Authenticated admission inputs for one coverage-owner revision: the 14
/// I7.16 envelope facts. No revision, no digest — those are minted at
/// admission, never supplied.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageOwnerInputs {
    /// Host identity from discovery.
    pub host_id: String,
    /// Runtime identity from discovery.
    pub runtime_id: String,
    /// Interface identity from discovery.
    pub interface_id: String,
    /// Recipient identity from discovery.
    pub recipient_id: String,
    /// Host generation from discovery (non-zero).
    pub host_generation: ResourceGeneration,
    /// Runtime generation from discovery (non-zero).
    pub runtime_generation: ResourceGeneration,
    /// Recipient generation from discovery (non-zero).
    pub recipient_generation: ResourceGeneration,
    /// Contract identity of the covered surface.
    pub contract: ContractIdentity,
    /// Supported delivery modes from the coverage owner.
    pub supported_modes: Vec<ReactiveDeliveryMode>,
    /// Privacy ceiling from the coverage owner.
    pub privacy_ceiling: ReactiveContextPrivacy,
    /// Effect ceiling from the coverage owner.
    pub effect_ceiling: EffectClass,
    /// Proof ceiling from the coverage owner.
    pub proof_ceiling: ProofCeiling,
    /// Owner-built lifecycle event evidence (with owner receipts).
    pub events: Vec<CoverageEvidence>,
    /// Owner-declared gaps beyond bridge/candidate gaps.
    pub owner_gaps: Vec<String>,
}

/// One admitted coverage-owner revision: the 14 envelope facts plus the
/// minted revision and snapshot digest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageOwnerSnapshot {
    /// Host identity from discovery.
    pub host_id: String,
    /// Runtime identity from discovery.
    pub runtime_id: String,
    /// Interface identity from discovery.
    pub interface_id: String,
    /// Recipient identity from discovery.
    pub recipient_id: String,
    /// Host generation from discovery (non-zero).
    pub host_generation: ResourceGeneration,
    /// Runtime generation from discovery (non-zero).
    pub runtime_generation: ResourceGeneration,
    /// Recipient generation from discovery (non-zero).
    pub recipient_generation: ResourceGeneration,
    /// Contract identity of the covered surface.
    pub contract: ContractIdentity,
    /// Supported delivery modes from the coverage owner.
    pub supported_modes: Vec<ReactiveDeliveryMode>,
    /// Privacy ceiling from the coverage owner.
    pub privacy_ceiling: ReactiveContextPrivacy,
    /// Effect ceiling from the coverage owner.
    pub effect_ceiling: EffectClass,
    /// Proof ceiling from the coverage owner.
    pub proof_ceiling: ProofCeiling,
    /// Owner-built lifecycle event evidence (with owner receipts).
    pub events: Vec<CoverageEvidence>,
    /// Owner-declared gaps beyond bridge/candidate gaps.
    pub owner_gaps: Vec<String>,
    /// Live attach fence the revision was admitted under.
    pub state_fence: StateFence,
    /// Minted revision (starts at 1, never zero while live).
    pub revision: u64,
    /// `sha256` over the canonical JSON of the facts above.
    pub snapshot_digest: String,
}

/// Canonical digest input: the admitted facts without their stored digest.
#[derive(Serialize)]
struct CanonicalCoverageSnapshot<'a> {
    host_id: &'a str,
    runtime_id: &'a str,
    interface_id: &'a str,
    recipient_id: &'a str,
    host_generation: ResourceGeneration,
    runtime_generation: ResourceGeneration,
    recipient_generation: ResourceGeneration,
    contract: &'a ContractIdentity,
    supported_modes: &'a [ReactiveDeliveryMode],
    privacy_ceiling: ReactiveContextPrivacy,
    effect_ceiling: EffectClass,
    proof_ceiling: ProofCeiling,
    events: &'a [CoverageEvidence],
    owner_gaps: &'a [String],
    state_fence: &'a StateFence,
    revision: u64,
}

/// The discovery identity/coverage owner: sole minter of
/// [`CoverageOwnerSnapshot`] revisions.
#[derive(Clone, Debug)]
pub struct DiscoveryOwner {
    revision: u64,
    current: Option<CoverageOwnerSnapshot>,
}

impl DiscoveryOwner {
    /// Creates an empty owner with no admitted snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0,
            current: None,
        }
    }

    /// Returns the current revision (zero when nothing was admitted).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the live admitted snapshot, if one exists.
    #[must_use]
    pub fn current(&self) -> Option<&CoverageOwnerSnapshot> {
        self.current.as_ref()
    }

    /// Admits one coverage-owner revision under the live fence.
    ///
    /// Validates every input with its in-tree constructor (identities,
    /// non-zero generations, contract, fence, unique non-empty modes, each
    /// event's own validation plus exact identity/fence/contract binding),
    /// mints `revision = previous + 1` (starting at 1), and computes
    /// `snapshot_digest` over the canonical JSON of the admitted facts.
    /// Re-admission supersedes the previous revision; the owner retains
    /// only the live one. Returns the stored live snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageOwnerError`] when the fence, any identity,
    /// generation, contract, mode set, event, or gap is rejected. Nothing
    /// is stored on failure.
    pub fn admit(
        &mut self,
        inputs: CoverageOwnerInputs,
        fence: &StateFence,
    ) -> Result<&CoverageOwnerSnapshot, CoverageOwnerError> {
        fence
            .validate()
            .map_err(|_| CoverageOwnerError::StaleFence)?;
        for (value, field) in [
            (&inputs.host_id, "coverage.host_id"),
            (&inputs.runtime_id, "coverage.runtime_id"),
            (&inputs.interface_id, "coverage.interface_id"),
            (&inputs.recipient_id, "coverage.recipient_id"),
        ] {
            validate_text(value, field)?;
        }
        if inputs.host_generation.value() == 0
            || inputs.runtime_generation.value() == 0
            || inputs.recipient_generation.value() == 0
        {
            return Err(CoverageOwnerError::InvalidField("coverage.generation"));
        }
        inputs
            .contract
            .validate()
            .map_err(|_| CoverageOwnerError::InvalidField("coverage.contract"))?;
        if inputs.supported_modes.is_empty() {
            return Err(CoverageOwnerError::InvalidField(
                "coverage.supported_modes",
            ));
        }
        {
            let mut seen = Vec::with_capacity(inputs.supported_modes.len());
            for mode in &inputs.supported_modes {
                if seen.contains(mode) {
                    return Err(CoverageOwnerError::InvalidField(
                        "coverage.supported_modes",
                    ));
                }
                seen.push(*mode);
            }
        }
        for event in &inputs.events {
            event
                .validate()
                .map_err(CoverageOwnerError::InvalidEvent)?;
            if event.host_id != inputs.host_id
                || event.runtime_id != inputs.runtime_id
                || event.interface_id != inputs.interface_id
                || event.contract != inputs.contract
                || event.recipient_id != inputs.recipient_id
                || event.host_generation != inputs.host_generation
                || event.runtime_generation != inputs.runtime_generation
                || event.recipient_generation != inputs.recipient_generation
                || event.state_fence != *fence
                || event.source.contract != inputs.contract
            {
                return Err(CoverageOwnerError::EventBinding);
            }
        }
        for gap in &inputs.owner_gaps {
            validate_text(gap, "coverage.owner_gaps")?;
        }
        let revision = self.revision.saturating_add(1).max(1);
        let canonical = CanonicalCoverageSnapshot {
            host_id: &inputs.host_id,
            runtime_id: &inputs.runtime_id,
            interface_id: &inputs.interface_id,
            recipient_id: &inputs.recipient_id,
            host_generation: inputs.host_generation,
            runtime_generation: inputs.runtime_generation,
            recipient_generation: inputs.recipient_generation,
            contract: &inputs.contract,
            supported_modes: &inputs.supported_modes,
            privacy_ceiling: inputs.privacy_ceiling,
            effect_ceiling: inputs.effect_ceiling,
            proof_ceiling: inputs.proof_ceiling,
            events: &inputs.events,
            owner_gaps: &inputs.owner_gaps,
            state_fence: fence,
            revision,
        };
        let bytes = canonical_json_bytes(&canonical)
            .map_err(|_| CoverageOwnerError::SnapshotDigest)?;
        let snapshot = CoverageOwnerSnapshot {
            host_id: inputs.host_id,
            runtime_id: inputs.runtime_id,
            interface_id: inputs.interface_id,
            recipient_id: inputs.recipient_id,
            host_generation: inputs.host_generation,
            runtime_generation: inputs.runtime_generation,
            recipient_generation: inputs.recipient_generation,
            contract: inputs.contract,
            supported_modes: inputs.supported_modes,
            privacy_ceiling: inputs.privacy_ceiling,
            effect_ceiling: inputs.effect_ceiling,
            proof_ceiling: inputs.proof_ceiling,
            events: inputs.events,
            owner_gaps: inputs.owner_gaps,
            state_fence: fence.clone(),
            revision,
            snapshot_digest: sha256_hex(&bytes),
        };
        self.revision = revision;
        Ok(self.current.insert(snapshot))
    }
}

/// Assemble the planner's contract `IntegrationCoverageProfile` from live
/// owner state: the Governor derivation posture, its verified candidate,
/// and one admitted [`CoverageOwnerSnapshot`] under the live fence.
///
/// Mirrors D2's `adapt_contract_coverage` derivation exactly (revision →
/// `profile_revision`, mapped completeness, verified candidate bound by
/// exact fingerprint equality, gaps `[additional, candidate, owner]`,
/// digest computed over the assembly and revalidated). `additional_gaps`
/// carries non-owner gap evidence first (the bridge passes its freshness
/// gap here — the bridge retains no owner claim receipts — without
/// storing bridge facts in owner state).
///
/// # Errors
///
/// Fails closed with [`CoverageJoinError`] on missing derivation,
/// unmapped completeness, unverified/foreign candidate, missing or stale
/// snapshot, or a contract validation/digest failure. The resolver maps
/// snapshot failures onto the exact 14 missing-fact names.
#[allow(clippy::too_many_arguments)]
pub fn assemble_contract_coverage(
    derivation: &GovernorCoverageDerivation,
    candidate: &GovernorCandidate,
    snapshot: &CoverageOwnerSnapshot,
    fence: &StateFence,
    additional_gaps: &[String],
) -> Result<IntegrationCoverageProfile, CoverageJoinError> {
    let profile = derivation
        .current()
        .ok_or(CoverageJoinError::NoLiveDerivation)?;
    let completeness = match profile.completeness {
        EventCompleteness::Complete => SnapshotCompleteness::Complete,
        EventCompleteness::Partial => SnapshotCompleteness::Partial,
        EventCompleteness::Unknown => SnapshotCompleteness::Unknown,
        EventCompleteness::NotApplicable => {
            return Err(CoverageJoinError::UnmappedCompleteness);
        }
    };
    if !candidate.verified {
        return Err(CoverageJoinError::CandidateUnverified);
    }
    if candidate.fingerprint != profile.fingerprint {
        return Err(CoverageJoinError::FingerprintMismatch);
    }
    if snapshot.revision == 0 {
        return Err(CoverageJoinError::EmptySnapshot);
    }
    if snapshot.state_fence != *fence {
        return Err(CoverageJoinError::StaleSnapshotFence);
    }
    let mut gaps: Vec<String> = additional_gaps.to_vec();
    gaps.extend(candidate.gaps.clone());
    gaps.extend(snapshot.owner_gaps.clone());
    let mut assembled = IntegrationCoverageProfile {
        host_id: snapshot.host_id.clone(),
        runtime_id: snapshot.runtime_id.clone(),
        interface_id: snapshot.interface_id.clone(),
        contract: snapshot.contract.clone(),
        recipient_id: snapshot.recipient_id.clone(),
        host_generation: snapshot.host_generation,
        runtime_generation: snapshot.runtime_generation,
        recipient_generation: snapshot.recipient_generation,
        profile_revision: profile.revision.to_string(),
        completeness,
        supported_modes: snapshot.supported_modes.clone(),
        privacy_ceiling: snapshot.privacy_ceiling,
        effect_ceiling: snapshot.effect_ceiling,
        proof_ceiling: snapshot.proof_ceiling,
        state_fence: fence.clone(),
        events: snapshot.events.clone(),
        gaps,
        profile_digest: String::new(),
    };
    assembled.profile_digest = assembled
        .canonical_digest()
        .map_err(CoverageJoinError::Invalid)?;
    assembled
        .validate()
        .map_err(CoverageJoinError::Invalid)?;
    Ok(assembled)
}

impl Default for DiscoveryOwner {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CoverageOwnerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoverageOwnerError::InvalidField(field));
    }
    Ok(())
}
