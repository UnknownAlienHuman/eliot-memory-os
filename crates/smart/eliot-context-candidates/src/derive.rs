//! Derivation of whole members from the four bound provider projections.
//!
//! Each supplied attention member, conflict position, epistemic view,
//! activation and evidence envelope/assurance becomes exactly one
//! [`NormalizedMember`] whose content is the canonical serialization of the
//! exact supplied value: whole, lossless and round-trippable. No field is
//! split, summarized, truncated or rewritten; the mapper later binds the
//! content digest to the measurement and source digests, so any tampering
//! fails closed.
//!
//! Derived member identities are stable pure functions of the source
//! identity, so callers can align supplied measurements without guessing.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AtomAvailability, AuthorityClass, ContextError, CriticalAttentionMember, MeasurementRef,
    PrivacyClass, ProofBinding, SourceSnapshot,
};
use eliot_contracts::{ArtifactId, SourceId, canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::TargetHandle;
use eliot_epistemic_contracts::{CurrentEpistemicPosition, Currentness, SourceAssurance};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceEnvelope};

use crate::inputs::{AttentionInput, CueInput, EpistemicInput, EvidenceInput, MemberMeasurement};
use crate::vocabulary::{
    PROVIDER_ATTENTION, PROVIDER_CUE, PROVIDER_EPISTEMIC, PROVIDER_EVIDENCE, kind_rule,
};

/// One normalized whole member ready for mapping.
///
/// For opaque projections this mirrors the supplied [`OpaqueMember`](crate::OpaqueMember);
/// for bound projections it is derived from the exact owner-typed value.
/// `truthful_state` is the member's own availability before the slot-level
/// rollup (stale/unknown overrides); the emitted atom carries the rolled-up
/// slot state while this value is retained in the member disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedMember {
    /// Stable member identity.
    pub member_id: ArtifactId,
    /// Closed member kind.
    pub kind: String,
    /// Complete unit bytes (verbatim opaque bytes or canonical serialization
    /// of the exact supplied bound value).
    pub content: String,
    /// SHA-256 of [`content`](Self::content).
    pub content_sha: String,
    /// Immutable source snapshot lineage.
    pub source: SourceSnapshot,
    /// Exact supplied measurement.
    pub measurement: MeasurementRef,
    /// Interpretation dependencies resolved inside the emitted set.
    pub dependencies: Vec<ArtifactId>,
    /// Protection ceiling.
    pub protected: bool,
    /// Privacy ceiling.
    pub privacy: PrivacyClass,
    /// Authority ceiling from the closed kind rule.
    pub authority: AuthorityClass,
    /// Candidate-stage epistemic status from the closed kind rule, capped
    /// (never promoted) from the source status.
    pub status: EpistemicStatus,
    /// Candidate-stage assertability ceiling (never `Assertable`).
    pub assertability: Assertability,
    /// Evidence/proof ceiling reference.
    pub proof: ProofBinding,
    /// The member's own availability before slot rollup.
    pub truthful_state: AtomAvailability,
}

/// Attention member identity: the attention identity itself, stable and
/// unique per member.
#[must_use]
pub fn attention_member_id(member: &CriticalAttentionMember) -> ArtifactId {
    member.attention_id.clone()
}

/// Conflict position identity: the conflict identity plus the position index
/// in declaration order (positions have no own identity; order is the stable
/// handle).
pub fn conflict_member_id(conflict_id: &str, index: usize) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("{conflict_id}#{index:04}"))
        .map_err(|_| ContextError::InvalidField("conflict.position"))
}

/// Epistemic member identity: bound to the frozen view digest, so a changed
/// view is a different member, never a silent rewrite.
pub fn epistemic_member_id(
    position: &CurrentEpistemicPosition,
) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("epistemic-position-{}", position.digest))
        .map_err(|_| ContextError::InvalidField("epistemic.member"))
}

/// Direct activation member identity: bound to the activated target handle.
pub fn direct_member_id(target: &TargetHandle) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("cue-direct-{}", target.as_str()))
        .map_err(|_| ContextError::InvalidField("cue.direct"))
}

/// Derived activation member identity: bound to the derived target handle.
pub fn derived_member_id(target: &TargetHandle) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("cue-derived-{}", target.as_str()))
        .map_err(|_| ContextError::InvalidField("cue.derived"))
}

/// Evidence envelope member identity: bound to the digest of the exact
/// envelope bytes, so equal envelopes from any order share one identity.
pub fn envelope_member_id(envelope: &EvidenceEnvelope) -> Result<ArtifactId, ContextError> {
    let bytes =
        canonical_json_bytes(envelope).map_err(|_| ContextError::InvalidField("evidence.bytes"))?;
    let digest = sha256_hex(&bytes);
    ArtifactId::new(format!("evidence-{}", &digest[..16]))
        .map_err(|_| ContextError::InvalidField("evidence.member"))
}

/// Source assurance member identity: bound to the assurance integrity digest.
pub fn assurance_member_id(assurance: &SourceAssurance) -> Result<ArtifactId, ContextError> {
    ArtifactId::new(format!("assurance-{}", assurance.integrity_digest))
        .map_err(|_| ContextError::InvalidField("assurance.member"))
}

/// Canonical content bytes of any bound value.
fn canonical_content<T: serde::Serialize>(value: &T) -> Result<(String, String), ContextError> {
    let bytes =
        canonical_json_bytes(value).map_err(|_| ContextError::InvalidField("member.bytes"))?;
    let text =
        String::from_utf8(bytes.clone()).map_err(|_| ContextError::InvalidField("member.bytes"))?;
    let digest = sha256_hex(&bytes);
    Ok((text, digest))
}

/// Index supplied measurements by member identity, rejecting duplicates.
pub fn index_measurements(
    measurements: &[MemberMeasurement],
) -> Result<BTreeMap<ArtifactId, MeasurementRef>, ContextError> {
    let mut out = BTreeMap::new();
    for entry in measurements {
        entry.measurement.validate()?;
        if out
            .insert(entry.member_id.clone(), entry.measurement.clone())
            .is_some()
        {
            return Err(ContextError::Duplicate("measurement.member_id"));
        }
    }
    Ok(out)
}

/// Take the single measurement for a derived member, or fail on absence.
fn take_measurement(
    index: &mut BTreeMap<ArtifactId, MeasurementRef>,
    member_id: &ArtifactId,
) -> Result<MeasurementRef, ContextError> {
    index
        .remove(member_id)
        .ok_or(ContextError::MissingField("member.measurement"))
}

/// Attention kind from member flags: sticky material stays sticky; a member
/// naming missing coverage raises an explicit objection; terminal
/// non-current resolutions are dissent (minority positions arrive via their
/// conflict sets, which own the minority flag).
///
/// The mapping reads only owner-typed flags, never prose.
fn attention_kind(member: &CriticalAttentionMember) -> &'static str {
    use eliot_context_contracts::AttentionResolution as Resolution;
    match member.resolution {
        Resolution::Resolved | Resolution::Waived | Resolution::Superseded => "dissent",
        Resolution::Open | Resolution::Unknown => {
            if member.missing_coverage.is_empty() {
                "sticky"
            } else {
                "objection"
            }
        }
    }
}

/// Derive whole members from the attention projection and conflict sets.
pub fn derive_attention(
    input: &AttentionInput,
    provider: &eliot_context_contracts::ProviderId,
    base_state: AtomAvailability,
) -> Result<Vec<NormalizedMember>, ContextError> {
    input
        .projection
        .validate()
        .map_err(|_| ContextError::InvalidField("attention.projection"))?;
    for conflict in &input.conflicts {
        conflict
            .validate()
            .map_err(|_| ContextError::InvalidField("attention.conflict"))?;
    }
    let mut measurements = index_measurements(&input.measurements)?;
    let mut out = Vec::new();
    for member in &input.projection.members {
        let kind = attention_kind(member);
        let rule = kind_rule(PROVIDER_ATTENTION, kind)
            .ok_or(ContextError::InvalidField("attention.kind"))?;
        let (content, content_sha) = canonical_content(member)?;
        let member_id = attention_member_id(member);
        let measurement = take_measurement(&mut measurements, &member_id)?;
        let source_id = SourceId::new(member.owner_id.clone())
            .map_err(|_| ContextError::InvalidField("attention.owner"))?;
        out.push(NormalizedMember {
            member_id: member_id.clone(),
            kind: kind.to_owned(),
            content,
            content_sha: content_sha.clone(),
            source: SourceSnapshot {
                source_id,
                owner: provider.clone(),
                snapshot_id: member.attention_id.clone(),
                revision: member.source_revision.clone(),
                content_sha256: content_sha,
                predecessor: None,
            },
            measurement,
            dependencies: Vec::new(),
            protected: true,
            privacy: PrivacyClass::Public,
            authority: rule.authority,
            status: rule.status,
            assertability: rule.assertability,
            proof: ProofBinding {
                evidence_id: member_id,
                ceiling: eliot_receipts::ProofCeiling::Observation,
            },
            truthful_state: base_state,
        });
    }
    for conflict in &input.conflicts {
        for (index, position) in conflict.positions.iter().enumerate() {
            let member_id = conflict_member_id(&conflict.conflict_id, index)?;
            let kind = if position.minority {
                "minority"
            } else if position.counters.is_empty() {
                "sticky"
            } else {
                "objection"
            };
            let rule = kind_rule(PROVIDER_ATTENTION, kind)
                .ok_or(ContextError::InvalidField("attention.kind"))?;
            let (content, content_sha) = canonical_content(position)?;
            let measurement = take_measurement(&mut measurements, &member_id)?;
            out.push(NormalizedMember {
                member_id: member_id.clone(),
                kind: kind.to_owned(),
                content,
                content_sha: content_sha.clone(),
                source: SourceSnapshot {
                    source_id: conflict.decision_owner.clone(),
                    owner: provider.clone(),
                    snapshot_id: member_id.clone(),
                    // The conflict set carries no separate revision field;
                    // the receipt digest is its stable lineage handle.
                    revision: conflict.receipt_digest.clone(),
                    content_sha256: content_sha,
                    predecessor: None,
                },
                measurement,
                dependencies: Vec::new(),
                protected: true,
                privacy: PrivacyClass::Public,
                authority: rule.authority,
                status: rule.status,
                assertability: rule.assertability,
                proof: ProofBinding {
                    evidence_id: member_id,
                    ceiling: eliot_receipts::ProofCeiling::Observation,
                },
                truthful_state: base_state,
            });
        }
    }
    if !measurements.is_empty() {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(out)
}

/// Derive the single whole member from the epistemic position view.
pub fn derive_epistemic(
    input: &EpistemicInput,
    provider: &eliot_context_contracts::ProviderId,
    base_state: AtomAvailability,
) -> Result<Vec<NormalizedMember>, ContextError> {
    input
        .position
        .validate()
        .map_err(|_| ContextError::InvalidField("epistemic.position"))?;
    let mut measurements = index_measurements(&input.measurements)?;
    let kind = match input.position.currentness {
        Currentness::Current => "support",
        Currentness::Superseded => "stale",
    };
    let rule =
        kind_rule(PROVIDER_EPISTEMIC, kind).ok_or(ContextError::InvalidField("epistemic.kind"))?;
    let (content, content_sha) = canonical_content(&input.position)?;
    let member_id = epistemic_member_id(&input.position)?;
    let measurement = take_measurement(&mut measurements, &member_id)?;
    if !measurements.is_empty() {
        return Err(ContextError::DenominatorMismatch);
    }
    let truthful_state = if rule.stale_override {
        AtomAvailability::Stale
    } else {
        base_state
    };
    Ok(vec![NormalizedMember {
        member_id: member_id.clone(),
        kind: kind.to_owned(),
        content,
        content_sha: content_sha.clone(),
        source: SourceSnapshot {
            source_id: input.position.admission.owner.clone(),
            owner: provider.clone(),
            snapshot_id: member_id.clone(),
            revision: input.position.admission.revision.clone(),
            content_sha256: content_sha,
            predecessor: None,
        },
        measurement,
        dependencies: Vec::new(),
        protected: true,
        privacy: PrivacyClass::Public,
        authority: rule.authority,
        status: rule.status,
        assertability: rule.assertability,
        proof: ProofBinding {
            evidence_id: member_id,
            ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        truthful_state,
    }])
}

/// Derive whole members from the explicit activation result.
///
/// Reads only: strengths stay score ceilings, paths stay lineage bytes,
/// truncation stays frontier. No traversal, lookup or registry access runs.
/// Content is the canonical serialization of the exact direct or derived
/// activation itself, so callers can recompute identities and measurements
/// without guessing; the kind and member identity keep direct and derived
/// distinct on the wire.
pub fn derive_cue(
    input: &CueInput,
    provider: &eliot_context_contracts::ProviderId,
    base_state: AtomAvailability,
) -> Result<Vec<NormalizedMember>, ContextError> {
    input
        .result
        .validate()
        .map_err(|_| ContextError::InvalidField("cue.result"))?;
    let mut measurements = index_measurements(&input.measurements)?;
    let mut out = Vec::with_capacity(
        input
            .result
            .direct
            .len()
            .saturating_add(input.result.derived.len()),
    );
    let mut direct_ids = BTreeMap::new();
    for direct in &input.result.direct {
        let member_id = direct_member_id(&direct.target)?;
        if direct_ids
            .insert(direct.target.clone(), member_id.clone())
            .is_some()
        {
            return Err(ContextError::Duplicate("cue.direct"));
        }
        let rule =
            kind_rule(PROVIDER_CUE, "direct").ok_or(ContextError::InvalidField("cue.kind"))?;
        let (content, content_sha) = canonical_content(direct)?;
        let measurement = take_measurement(&mut measurements, &member_id)?;
        out.push(NormalizedMember {
            member_id: member_id.clone(),
            kind: "direct".to_owned(),
            content,
            content_sha: content_sha.clone(),
            source: cue_source(input, provider, &content_sha)?,
            measurement,
            dependencies: Vec::new(),
            protected: false,
            privacy: PrivacyClass::Public,
            authority: rule.authority,
            status: rule.status,
            assertability: rule.assertability,
            proof: ProofBinding {
                evidence_id: member_id,
                ceiling: eliot_receipts::ProofCeiling::Observation,
            },
            truthful_state: base_state,
        });
    }
    for derived in &input.result.derived {
        let member_id = derived_member_id(&derived.target)?;
        let rule =
            kind_rule(PROVIDER_CUE, "derived").ok_or(ContextError::InvalidField("cue.kind"))?;
        let (content, content_sha) = canonical_content(derived)?;
        let measurement = take_measurement(&mut measurements, &member_id)?;
        // The derived path must begin at a supplied direct seed: broken
        // lineage is an identity conflict, never a silent drop.
        let seed_atom = direct_ids
            .get(&derived.direct_seed)
            .cloned()
            .ok_or(ContextError::IdentityConflict)?;
        out.push(NormalizedMember {
            member_id: member_id.clone(),
            kind: "derived".to_owned(),
            content,
            content_sha: content_sha.clone(),
            source: cue_source(input, provider, &content_sha)?,
            measurement,
            dependencies: vec![seed_atom],
            protected: false,
            privacy: PrivacyClass::Public,
            authority: rule.authority,
            status: rule.status,
            assertability: rule.assertability,
            proof: ProofBinding {
                evidence_id: member_id,
                ceiling: eliot_receipts::ProofCeiling::Observation,
            },
            truthful_state: base_state,
        });
    }
    if !measurements.is_empty() {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(out)
}

fn cue_source(
    input: &CueInput,
    provider: &eliot_context_contracts::ProviderId,
    content_sha: &str,
) -> Result<SourceSnapshot, ContextError> {
    let snapshot_text = input.result.snapshot_id.as_str();
    Ok(SourceSnapshot {
        source_id: SourceId::new(snapshot_text)
            .map_err(|_| ContextError::InvalidField("cue.snapshot"))?,
        owner: provider.clone(),
        snapshot_id: ArtifactId::new(snapshot_text)
            .map_err(|_| ContextError::InvalidField("cue.snapshot"))?,
        revision: input.result.schema_revision.clone(),
        content_sha256: content_sha.to_owned(),
        predecessor: None,
    })
}

/// Evidence kind from envelope fields only: status and coverage axes, never
/// prose, confidence, recency or preference.
fn envelope_kind(envelope: &EvidenceEnvelope) -> &'static str {
    match envelope.status {
        EpistemicStatus::Unknown => "unknown",
        EpistemicStatus::Contested => "counterevidence",
        EpistemicStatus::Stale | EpistemicStatus::Superseded => "stale-record",
        EpistemicStatus::Rejected => "rejected-record",
        EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified => {
            match envelope.coverage {
                eliot_evidence::EvidenceCoverage::PartialForScope => "coverage",
                eliot_evidence::EvidenceCoverage::CompleteForScope
                | eliot_evidence::EvidenceCoverage::NotApplicable
                | eliot_evidence::EvidenceCoverage::Unknown => "provenance",
            }
        }
    }
}

/// Candidate-stage status cap: the mapper preserves source statuses except
/// `Verified`, which is capped at `Supported` under a non-assertable
/// ceiling. The envelope bytes stay whole; only the candidate-stage claim
/// ceiling refuses to assert truth (no truth promotion, no gap filling).
fn cap_status(status: EpistemicStatus) -> EpistemicStatus {
    match status {
        EpistemicStatus::Verified => EpistemicStatus::Supported,
        other => other,
    }
}

/// Derive whole members from envelopes, assurances and payload bytes.
pub fn derive_evidence(
    input: &EvidenceInput,
    provider: &eliot_context_contracts::ProviderId,
    base_state: AtomAvailability,
) -> Result<Vec<NormalizedMember>, ContextError> {
    for envelope in &input.envelopes {
        envelope
            .validate()
            .map_err(|_| ContextError::InvalidField("evidence.envelope"))?;
    }
    for assurance in &input.assurances {
        assurance
            .validate()
            .map_err(|_| ContextError::InvalidField("evidence.assurance"))?;
    }
    for payload in &input.payloads {
        payload.validate()?;
    }
    let mut measurements = index_measurements(&input.measurements)?;
    let mut out = Vec::new();
    for envelope in &input.envelopes {
        out.push(derive_envelope_member(
            envelope,
            provider,
            take_measurement(&mut measurements, &envelope_member_id(envelope)?)?,
            base_state,
        )?);
    }
    for assurance in &input.assurances {
        out.push(derive_assurance_member(
            assurance,
            provider,
            take_measurement(&mut measurements, &assurance_member_id(assurance)?)?,
            base_state,
        )?);
    }
    if !measurements.is_empty() {
        return Err(ContextError::DenominatorMismatch);
    }
    // Payload bytes (including instruction-like data) keep their declared
    // kind under the evidence slot; content never changes the role.
    let mut seen_payloads = BTreeSet::new();
    for payload in &input.payloads {
        if !seen_payloads.insert(payload.member_id.clone()) {
            return Err(ContextError::Duplicate("evidence.payload"));
        }
        out.push(derive_payload_member(payload, base_state)?);
    }
    Ok(out)
}

/// Derive one whole member from an evidence envelope.
fn derive_envelope_member(
    envelope: &EvidenceEnvelope,
    provider: &eliot_context_contracts::ProviderId,
    measurement: MeasurementRef,
    base_state: AtomAvailability,
) -> Result<NormalizedMember, ContextError> {
    let kind = envelope_kind(envelope);
    let rule =
        kind_rule(PROVIDER_EVIDENCE, kind).ok_or(ContextError::InvalidField("evidence.kind"))?;
    let (content, content_sha) = canonical_content(envelope)?;
    let member_id = envelope_member_id(envelope)?;
    let truthful_state = if rule.stale_override {
        AtomAvailability::Stale
    } else if rule.unknown_override {
        AtomAvailability::Unknown
    } else {
        base_state
    };
    Ok(NormalizedMember {
        member_id: member_id.clone(),
        kind: kind.to_owned(),
        content,
        content_sha: content_sha.clone(),
        source: SourceSnapshot {
            source_id: envelope.provenance.source_id.clone(),
            owner: provider.clone(),
            snapshot_id: member_id.clone(),
            revision: envelope
                .provenance
                .revision
                .clone()
                .unwrap_or_else(|| "unknown-revision".to_owned()),
            content_sha256: content_sha,
            predecessor: None,
        },
        measurement,
        dependencies: Vec::new(),
        protected: true,
        privacy: PrivacyClass::Public,
        authority: rule.authority,
        status: cap_status(rule.status),
        assertability: rule.assertability,
        proof: ProofBinding {
            evidence_id: member_id,
            ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        truthful_state,
    })
}

/// Derive one whole member from a source assurance.
fn derive_assurance_member(
    assurance: &SourceAssurance,
    provider: &eliot_context_contracts::ProviderId,
    measurement: MeasurementRef,
    base_state: AtomAvailability,
) -> Result<NormalizedMember, ContextError> {
    let rule = kind_rule(PROVIDER_EVIDENCE, "assurance")
        .ok_or(ContextError::InvalidField("evidence.kind"))?;
    let (content, content_sha) = canonical_content(assurance)?;
    let member_id = assurance_member_id(assurance)?;
    Ok(NormalizedMember {
        member_id: member_id.clone(),
        kind: "assurance".to_owned(),
        content,
        content_sha: content_sha.clone(),
        source: SourceSnapshot {
            source_id: assurance.source.clone(),
            owner: provider.clone(),
            snapshot_id: member_id.clone(),
            revision: assurance.revision.clone(),
            content_sha256: content_sha,
            predecessor: None,
        },
        measurement,
        dependencies: Vec::new(),
        protected: true,
        privacy: PrivacyClass::Public,
        authority: rule.authority,
        status: rule.status,
        assertability: rule.assertability,
        proof: ProofBinding {
            evidence_id: member_id,
            ceiling: eliot_receipts::ProofCeiling::Observation,
        },
        truthful_state: base_state,
    })
}

/// Derive one whole member from caller-supplied evidence payload bytes.
fn derive_payload_member(
    payload: &crate::OpaqueMember,
    base_state: AtomAvailability,
) -> Result<NormalizedMember, ContextError> {
    let rule = kind_rule(PROVIDER_EVIDENCE, payload.kind.as_str())
        .ok_or(ContextError::InvalidField("evidence.payload.kind"))?;
    if rule.role != eliot_context_contracts::SemanticRole::Evidence {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(NormalizedMember {
        member_id: payload.member_id.clone(),
        kind: payload.kind.clone(),
        content: payload.content.clone(),
        content_sha: sha256_hex(payload.content.as_bytes()),
        source: payload.source.clone(),
        measurement: payload.measurement.clone(),
        dependencies: payload.dependencies.clone(),
        protected: payload.protected,
        privacy: payload.privacy,
        // Source-declared ceilings; the mapper resolves them against the
        // closed rule (capped, never promoted; authority escalation
        // rejected).
        authority: payload.authority,
        status: payload.status,
        assertability: payload.assertability,
        proof: payload.proof.clone(),
        truthful_state: if rule.stale_override {
            AtomAvailability::Stale
        } else if rule.unknown_override {
            AtomAvailability::Unknown
        } else {
            base_state
        },
    })
}
