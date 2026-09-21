//! Read-only owner projections for the first reactive cue path.
//!
//! This module is deliberately a boundary, not another reactive state owner:
//! the Governor's ObservationJournal supplies admitted observations, the A-12
//! cue owner supplies its already-derived CueBindingResult, and the context
//! owner supplies explicit target-to-atom joins. The projection rechecks the
//! A-12 result from its retained inputs before it crosses the boundary. It
//! never parses observed_delta, compares cue targets with atom IDs, mints
//! admission receipts, stores a queue, or seals a new candidate.
//!
//! The target-to-atom join is intentionally represented here with the cue
//! candidate identity plus the atom's source revision and digest. A consumer
//! can map this exact value to its planner-specific binding type; no string
//! equality between the cue namespace and atom namespace is used.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence};
use eliot_cue_binding::{CueBindingResult, derive_cue_binding_candidates};
use eliot_cue_contracts::{BindingCandidateId, Digest, TargetHandle};
use eliot_observation::{
    ObservationAdmissionReceipt, ObservationAdmissionResult, ObservationJournal,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum current admitted observation records projected in one feed read.
pub const MAX_REACTIVE_OWNER_RECORDS: usize = 256;

/// Maximum target-to-atom joins carried by one cue projection.
const MAX_TARGET_ATOM_BINDINGS: usize = 256;

fn valid_text(value: &str, field: &'static str) -> Result<(), ReactiveOwnerProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveOwnerProjectionError::InvalidField(field));
    }
    Ok(())
}

fn valid_digest(value: &str, field: &'static str) -> Result<(), ReactiveOwnerProjectionError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ReactiveOwnerProjectionError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed errors from the owner projection boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveOwnerProjectionError {
    /// The requested scope/fence is malformed.
    #[error("reactive owner projection field is invalid: {0}")]
    InvalidField(&'static str),
    /// The journal contains more current records than the feed bound.
    #[error("reactive owner projection bound exceeded: {0}")]
    Bound(&'static str),
    /// A retained journal entry violates its admission identity.
    #[error("reactive owner projection admission is invalid: {0}")]
    AdmissionInvalid(String),
    /// The journal entry does not agree with its retained receipt.
    #[error("reactive owner projection admission identity is inconsistent")]
    AdmissionIdentityMismatch,
    /// A cue owner did not return a result for an admitted observation.
    #[error("reactive cue owner returned no binding result")]
    CueUnavailable,
    /// The cue owner refused a read.
    #[error("reactive cue owner refused the read: {0}")]
    CueOwnerRejected(String),
    /// The cue result is for a different admitted observation.
    #[error("reactive cue result is not bound to the admitted observation")]
    CueAdmissionMismatch,
    /// Re-running the A-12 owner over its retained inputs changed the result.
    #[error("reactive cue result does not reproduce from its retained owner inputs")]
    CueResultMismatch,
    /// The A-12 owner rejected its retained result inputs.
    #[error("reactive cue result cannot be reproduced: {0}")]
    CueDerivationFailed(String),
    /// The context owner refused a target-to-atom read.
    #[error("reactive target-to-atom owner refused the read: {0}")]
    AtomOwnerRejected(String),
    /// A candidate with no target-to-atom join would become an inferred binding.
    #[error("reactive cue candidate has no complete target-to-atom join")]
    MissingTargetAtomBinding,
    /// A target-to-atom join names a candidate that was not returned by A-12.
    #[error("reactive target-to-atom join names an unknown cue candidate")]
    UnknownCandidate,
    /// A target-to-atom join disagrees with the exact cue candidate.
    #[error("reactive target-to-atom join disagrees with cue candidate: {0}")]
    TargetAtomMismatch(&'static str),
    /// A target-to-atom join is repeated.
    #[error("reactive target-to-atom join is duplicated: {0}")]
    DuplicateTargetAtom(&'static str),
}

/// An explicit cue-candidate to rendered-atom identity supplied by the
/// context owner.
///
/// The candidate ID and digest prove which A-12 candidate is being joined.
/// The atom ID and source fields are copied from the context owner's rendered
/// atom identity; this type does not derive them from the cue target.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveTargetAtomBinding {
    /// Exact A-12 candidate identity being joined.
    pub candidate_id: BindingCandidateId,
    /// Digest of the exact A-12 candidate.
    pub candidate_digest: Digest,
    /// Cue-index target handle from that candidate.
    pub target: TargetHandle,
    /// Exact rendered context atom identity.
    pub atom_id: ArtifactId,
    /// Exact rendered atom source revision.
    pub source_revision: String,
    /// Exact rendered atom source digest.
    pub source_digest: String,
}

impl ReactiveTargetAtomBinding {
    fn validate(&self) -> Result<(), ReactiveOwnerProjectionError> {
        valid_text(self.candidate_id.as_str(), "target_atom.candidate_id")?;
        valid_text(self.target.as_str(), "target_atom.target")?;
        valid_text(self.atom_id.as_str(), "target_atom.atom_id")?;
        valid_text(&self.source_revision, "target_atom.source_revision")?;
        valid_digest(&self.source_digest, "target_atom.source_digest")?;
        if self.candidate_digest.as_str().len() != 64 {
            return Err(ReactiveOwnerProjectionError::InvalidField(
                "target_atom.candidate_digest",
            ));
        }
        Ok(())
    }
}

/// Read-only cue owner port.
///
/// Implementations must return the result retained by the real A-12 owner.
/// They must not construct a caller-shaped result at this boundary.
pub trait ReactiveCueBindingOwner {
    /// Read the owner result for one exact admitted observation.
    fn read_cue_binding(
        &self,
        admission: &ObservationAdmissionReceipt,
    ) -> Result<Option<&CueBindingResult>, String>;
}

/// Read-only context-owner port for explicit cue-target to atom joins.
pub trait ReactiveTargetAtomOwner {
    /// Read the current atom joins for one exact admitted cue result.
    fn read_target_atom_bindings(
        &self,
        admission: &ObservationAdmissionReceipt,
        cue: &CueBindingResult,
    ) -> Result<Vec<ReactiveTargetAtomBinding>, String>;
}

/// One admitted observation and its owner-issued cue projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveObservationCueProjection {
    /// The exact Governor admission receipt retained by the journal.
    pub admission: ObservationAdmissionReceipt,
    /// The exact A-12 result reproduced from its retained inputs.
    pub cue_binding: CueBindingResult,
    /// Explicit target-to-atom joins for the inline A-12 candidates.
    pub target_atom_bindings: Vec<ReactiveTargetAtomBinding>,
}

impl ReactiveObservationCueProjection {
    /// Return the normalized observed cues retained by A-12.
    pub fn observed_cues(&self) -> impl Iterator<Item = &eliot_cue_contracts::NormalizedCue> {
        self.cue_binding
            .touched
            .iter()
            .map(|row| &row.normalization.normalized)
    }
}

/// Stateless current owner projection supplied to the reactive feed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveOwnerProjection {
    /// Projection schema revision.
    pub schema_version: u32,
    /// Fence used to select every admitted observation.
    pub state_fence: StateFence,
    /// Scope used to select every admitted observation.
    pub scope_id: WorkScopeId,
    /// Current admitted observations with their cue owner joins.
    pub observations: Vec<ReactiveObservationCueProjection>,
}

impl ReactiveOwnerProjection {
    /// Validate the already-composed projection without reading an owner.
    pub fn validate(&self) -> Result<(), ReactiveOwnerProjectionError> {
        if self.schema_version != 1 {
            return Err(ReactiveOwnerProjectionError::InvalidField(
                "projection.schema_version",
            ));
        }
        self.state_fence
            .validate()
            .map_err(|_| ReactiveOwnerProjectionError::InvalidField("projection.state_fence"))?;
        valid_text(self.scope_id.as_str(), "projection.scope_id")?;
        if self.observations.len() > MAX_REACTIVE_OWNER_RECORDS {
            return Err(ReactiveOwnerProjectionError::Bound(
                "projection.observations",
            ));
        }
        for projection in &self.observations {
            if projection.admission.state_fence != self.state_fence {
                return Err(ReactiveOwnerProjectionError::AdmissionIdentityMismatch);
            }
            projection.admission.validate().map_err(|error| {
                ReactiveOwnerProjectionError::AdmissionInvalid(error.to_string())
            })?;
            if projection
                .admission
                .record
                .event
                .as_ref()
                .is_some_and(|event| event.affected_scope.work_scope != self.scope_id)
            {
                return Err(ReactiveOwnerProjectionError::AdmissionIdentityMismatch);
            }
            validate_cue_result(
                &projection.admission,
                &projection.cue_binding,
                &self.scope_id,
            )?;
            validate_target_atom_bindings(
                &projection.cue_binding,
                &projection.target_atom_bindings,
            )?;
        }
        Ok(())
    }
}

fn validate_cue_result(
    admission: &ObservationAdmissionReceipt,
    cue: &CueBindingResult,
    scope_id: &WorkScopeId,
) -> Result<(), ReactiveOwnerProjectionError> {
    if cue.admission != *admission
        || cue.state_fence != admission.state_fence
        || cue.profile.scope_id != *scope_id
    {
        return Err(ReactiveOwnerProjectionError::CueAdmissionMismatch);
    }
    let reproduced =
        derive_cue_binding_candidates(admission, &cue.touched, cue.hint.as_ref(), &cue.profile)
            .map_err(|error| {
                ReactiveOwnerProjectionError::CueDerivationFailed(error.to_string())
            })?;
    if reproduced != *cue {
        return Err(ReactiveOwnerProjectionError::CueResultMismatch);
    }
    Ok(())
}

fn validate_target_atom_bindings(
    cue: &CueBindingResult,
    bindings: &[ReactiveTargetAtomBinding],
) -> Result<(), ReactiveOwnerProjectionError> {
    if bindings.len() > MAX_TARGET_ATOM_BINDINGS {
        return Err(ReactiveOwnerProjectionError::Bound("target_atom_bindings"));
    }
    if bindings.len() != cue.candidates.len() {
        return if cue.candidates.is_empty() && bindings.is_empty() {
            Ok(())
        } else {
            Err(ReactiveOwnerProjectionError::MissingTargetAtomBinding)
        };
    }
    let mut candidates = cue
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.binding_candidate_id.clone(),
                (candidate.digest.clone(), candidate.target.clone()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut seen_candidates = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    for binding in bindings {
        binding.validate()?;
        if !seen_candidates.insert(binding.candidate_id.clone()) {
            return Err(ReactiveOwnerProjectionError::DuplicateTargetAtom(
                "candidate_id",
            ));
        }
        if !seen_targets.insert(binding.target.clone()) {
            return Err(ReactiveOwnerProjectionError::DuplicateTargetAtom("target"));
        }
        let Some((candidate_digest, target)) = candidates.remove(&binding.candidate_id) else {
            return Err(ReactiveOwnerProjectionError::UnknownCandidate);
        };
        if binding.candidate_digest != candidate_digest {
            return Err(ReactiveOwnerProjectionError::TargetAtomMismatch(
                "candidate_digest",
            ));
        }
        if binding.target != target {
            return Err(ReactiveOwnerProjectionError::TargetAtomMismatch("target"));
        }
    }
    if !candidates.is_empty() {
        return Err(ReactiveOwnerProjectionError::MissingTargetAtomBinding);
    }
    Ok(())
}

/// Read the current admitted observation records and join their real cue
/// owner results and context-owner target bindings.
///
/// Older-fence observations and non-event journal records are retained by
/// their owners but are outside this current reactive read. A current event
/// without a cue-owner result is an error: it is never converted to an empty
/// cue set.
pub fn project_reactive_owner<C, A>(
    journal: &ObservationJournal,
    scope_id: &WorkScopeId,
    state_fence: &StateFence,
    cue_owner: &C,
    atom_owner: &A,
) -> Result<ReactiveOwnerProjection, ReactiveOwnerProjectionError>
where
    C: ReactiveCueBindingOwner,
    A: ReactiveTargetAtomOwner,
{
    state_fence
        .validate()
        .map_err(|_| ReactiveOwnerProjectionError::InvalidField("projection.state_fence"))?;
    valid_text(scope_id.as_str(), "projection.scope_id")?;

    let mut current = Vec::new();
    for entry in journal.snapshot() {
        let ObservationAdmissionResult::Accepted { receipt } = entry.result else {
            continue;
        };
        if entry.idempotency_key != receipt.idempotency_key
            || entry.request_digest != receipt.request_digest
        {
            return Err(ReactiveOwnerProjectionError::AdmissionIdentityMismatch);
        }
        receipt
            .validate()
            .map_err(|error| ReactiveOwnerProjectionError::AdmissionInvalid(error.to_string()))?;
        if receipt.state_fence != *state_fence {
            continue;
        }
        let Some(event) = receipt.record.event.as_ref() else {
            continue;
        };
        if event.affected_scope.work_scope != *scope_id {
            continue;
        }
        current.push(receipt);
    }
    if current.len() > MAX_REACTIVE_OWNER_RECORDS {
        return Err(ReactiveOwnerProjectionError::Bound(
            "projection.observations",
        ));
    }

    let mut observations = Vec::with_capacity(current.len());
    for admission in current {
        let cue = cue_owner
            .read_cue_binding(&admission)
            .map_err(ReactiveOwnerProjectionError::CueOwnerRejected)?
            .ok_or(ReactiveOwnerProjectionError::CueUnavailable)?;
        validate_cue_result(&admission, cue, scope_id)?;
        let target_atom_bindings = atom_owner
            .read_target_atom_bindings(&admission, cue)
            .map_err(ReactiveOwnerProjectionError::AtomOwnerRejected)?;
        validate_target_atom_bindings(cue, &target_atom_bindings)?;
        observations.push(ReactiveObservationCueProjection {
            admission,
            cue_binding: cue.clone(),
            target_atom_bindings,
        });
    }

    let projection = ReactiveOwnerProjection {
        schema_version: 1,
        state_fence: state_fence.clone(),
        scope_id: scope_id.clone(),
        observations,
    };
    projection.validate()?;
    Ok(projection)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use eliot_change_monitor::{
        Attribution, ChangeKind, ChangeObservation, ChangeOrigin, ObservedChangeRecord,
        ResourceSnapshot,
    };
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ResourceGeneration, SourceId, TaskId,
    };
    use eliot_cue_binding::{
        BindingProfile, BindingRule, ResourceField, TouchedResourceProjection,
    };
    use eliot_cue_contracts::{
        BindingRole, CONTRACT_REVISION, CueContext, CueKind, NormalizationProfile, ObservedCue,
        ObservedCueId, PrivacyClass, SourceHandle,
    };
    use eliot_cue_normalizer::{NormalizationPolicy, NormalizationRule, PolicyRule, capture_cue};
    use eliot_evidence::{
        Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
        EvidenceFreshness, LifecycleState, Provenance,
    };
    use eliot_observation::{
        CaptureRoute, CoverageDisposition, CoverageEvidence, Durability, ObservationEventCore,
        ObservationEventIdentity, ObservationKind, ObservationRecordEnvelope,
        ObservationRecordKind, ObservationScope, ObservationSubmission, ProducerTrace,
        TaskSelectionEvidence,
    };
    use eliot_observation_contracts::PrivacyRetentionDisclosure;

    struct CueOwner {
        result: CueBindingResult,
    }

    impl ReactiveCueBindingOwner for CueOwner {
        fn read_cue_binding(
            &self,
            _admission: &ObservationAdmissionReceipt,
        ) -> Result<Option<&CueBindingResult>, String> {
            Ok(Some(&self.result))
        }
    }

    struct AtomOwner {
        bindings: Vec<ReactiveTargetAtomBinding>,
    }

    impl ReactiveTargetAtomOwner for AtomOwner {
        fn read_target_atom_bindings(
            &self,
            _admission: &ObservationAdmissionReceipt,
            _cue: &CueBindingResult,
        ) -> Result<Vec<ReactiveTargetAtomBinding>, String> {
            Ok(self.bindings.clone())
        }
    }

    fn digest(seed: u8) -> eliot_cue_contracts::Digest {
        eliot_cue_contracts::Digest::new(format!("{seed:02x}").repeat(32)).expect("digest")
    }

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                std::num::NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::genesis(),
        )
    }

    fn admitted_fixture() -> (
        ObservationJournal,
        ObservationAdmissionReceipt,
        Vec<TouchedResourceProjection>,
        BindingProfile,
    ) {
        let state = fence();
        let scope = WorkScopeId::new("scope").expect("scope");
        let a11_profile = NormalizationProfile::new("a11-profile".into(), 1, digest(2));
        let policy = NormalizationPolicy::sealed(
            "owner".into(),
            "policy".into(),
            1,
            a11_profile,
            scope.clone(),
            state.clone(),
            vec![PolicyRule {
                kind: CueKind::FilePath,
                rule: NormalizationRule::Preserve,
            }],
        )
        .expect("policy");
        let target = TargetHandle::new("src/lib.rs").expect("target");
        let source_digest = digest(3);
        let provenance = Provenance {
            source_id: SourceId::new("source-1").expect("source"),
            capture_route: "test".into(),
            scope: "scope".into(),
            raw_handle: Some("raw-1".into()),
            revision: Some("rev-1".into()),
        };
        let observed = ObservedCue::new(
            CONTRACT_REVISION.into(),
            ObservedCueId::new("cue-1").expect("cue"),
            CueKind::FilePath,
            target.as_str().into(),
            SourceHandle::new(target.clone(), source_digest.clone(), provenance.clone()),
            CueContext::new(
                TaskId::new("task-1").expect("task"),
                scope.clone(),
                state.clone(),
                EvidenceEnvelope {
                    authority: EvidenceAuthority::SourceIdentity,
                    freshness: EvidenceFreshness::ExactCandidate,
                    coverage: EvidenceCoverage::CompleteForScope,
                    status: EpistemicStatus::Observed,
                    assertability: Assertability::NonAssertableUnverified,
                    provenance,
                    verification: None,
                    state_fence: state.clone(),
                },
                LifecycleState::Active,
                PrivacyClass::Public,
                eliot_cue_contracts::ProofCeiling::Observation,
            ),
        );
        let normalization = capture_cue(&observed, &policy, &policy.profile).expect("normalize");
        let change = ChangeObservation {
            change_id: "change-1".into(),
            state_fence: state.clone(),
            kind: ChangeKind::Modified,
            before: Some(ResourceSnapshot {
                resource_ref: target.as_str().into(),
                revision: "old-1".into(),
                path: Some(target.as_str().into()),
                symbol: None,
                content_digest: Some(digest(4).as_str().into()),
                structural_digest: None,
            }),
            after: Some(ResourceSnapshot {
                resource_ref: target.as_str().into(),
                revision: "rev-1".into(),
                path: Some(target.as_str().into()),
                symbol: None,
                content_digest: Some(source_digest.as_str().into()),
                structural_digest: None,
            }),
            origin: ChangeOrigin::HostEvent,
            attribution: Attribution::Exact,
            origin_ref: Some("raw-1".into()),
            session_ref: None,
            action_lease_ref: None,
            operation_ref: None,
            diff_or_artifact_ref: None,
            unknown_origin: false,
            invalidations: Vec::new(),
        };
        let row = TouchedResourceProjection {
            target: target.clone(),
            normalization,
            change: ObservedChangeRecord {
                observation_digest: change.digest().expect("change digest"),
                observation: change,
            },
        };
        let submission = ObservationSubmission {
            operation_id: "operation-1".into(),
            idempotency_key: "idempotency-1".into(),
            state_fence: state.clone(),
            record: ObservationRecordEnvelope {
                record_id: "record-1".into(),
                kind: ObservationRecordKind::Change,
                event: Some(ObservationEventCore {
                    event_id_and_time: ObservationEventIdentity {
                        event_id: "event-1".into(),
                        clock: ClockReading::default(),
                    },
                    producer_generation_and_trace: ProducerTrace {
                        producer: "producer".into(),
                        generation: "generation-1".into(),
                        trace_ref: None,
                    },
                    kind: ObservationKind::ToolOrRoute,
                    affected_scope: ObservationScope {
                        work_scope: scope.clone(),
                        task_ref: Some("task-1".into()),
                        attempt_ref: Some("attempt-1".into()),
                        module_or_route_ref: None,
                    },
                    observed_delta: "opaque delta".into(),
                    expected_baseline: None,
                    evidence_and_raw_handles: vec!["raw-1".into()],
                    coverage_and_blind_intervals: CoverageEvidence {
                        disposition: CoverageDisposition::Complete,
                        denominator_source_ref: "denominator".into(),
                        interval: None,
                        blind_intervals: Vec::new(),
                        observed_count: 1,
                    },
                    privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                        privacy_domain_ref: "public".into(),
                        retention_policy_ref: "default".into(),
                        disclosure_class: "internal".into(),
                    },
                    candidate_importance: 1,
                    dedup_key: "event-1".into(),
                }),
                coverage_gap: None,
                journal_control_event: false,
                parent_record_id: None,
            },
            record_v2: None,
            capture_route: CaptureRoute::CanonicalJournal,
            durability: Durability::Durable,
            plan: None,
            task_selection: Some(TaskSelectionEvidence {
                task_ref: "task-1".into(),
                task_revision: 1,
                acceptance_digest: digest(5).as_str().into(),
                work_scope_ref: "scope".into(),
                selection_source_ref: "test-selection".into(),
                evidence_ref: "selection-evidence".into(),
                contamination_flags: Vec::new(),
            }),
            evidence: None,
        };
        let mut journal = ObservationJournal::default();
        let ObservationAdmissionResult::Accepted { receipt } =
            journal.admit(submission).expect("admit")
        else {
            panic!("fixture must be accepted")
        };
        let binding_profile = BindingProfile::sealed(
            "a12-profile".into(),
            1,
            scope,
            state,
            vec![BindingRule {
                cue_kind: CueKind::FilePath,
                change_kind: ChangeKind::Modified,
                role: BindingRole::Touched,
                resource_field: ResourceField::Path,
                rule_ref: "modified-file-path".into(),
            }],
            policy.profile.clone(),
        )
        .expect("binding profile");
        (journal, receipt, vec![row], binding_profile)
    }

    #[test]
    fn projects_admitted_record_through_reproduced_cue_and_explicit_atom_join() {
        let (journal, receipt, rows, profile) = admitted_fixture();
        let cue = derive_cue_binding_candidates(&receipt, &rows, None, &profile).expect("derive");
        let candidate = cue.candidates.first().expect("candidate");
        let atom_owner = AtomOwner {
            bindings: vec![ReactiveTargetAtomBinding {
                candidate_id: candidate.binding_candidate_id.clone(),
                candidate_digest: candidate.digest.clone(),
                target: candidate.target.clone(),
                atom_id: ArtifactId::new("atom-1").expect("atom"),
                source_revision: "rev-1".into(),
                source_digest: digest(3).as_str().into(),
            }],
        };
        let projection = project_reactive_owner(
            &journal,
            &WorkScopeId::new("scope").expect("scope"),
            &fence(),
            &CueOwner { result: cue },
            &atom_owner,
        )
        .expect("projection");
        assert_eq!(projection.observations.len(), 1);
        assert_eq!(projection.observations[0].observed_cues().count(), 1);
        assert_eq!(
            projection.observations[0].target_atom_bindings[0]
                .atom_id
                .as_str(),
            "atom-1"
        );
    }

    #[test]
    fn mismatched_cue_admission_fails_closed() {
        let (journal, receipt, rows, profile) = admitted_fixture();
        let mut cue =
            derive_cue_binding_candidates(&receipt, &rows, None, &profile).expect("derive");
        cue.admission.record_id = "foreign-record".into();
        let result = project_reactive_owner(
            &journal,
            &WorkScopeId::new("scope").expect("scope"),
            &fence(),
            &CueOwner { result: cue },
            &AtomOwner {
                bindings: Vec::new(),
            },
        );
        assert_eq!(
            result,
            Err(ReactiveOwnerProjectionError::CueAdmissionMismatch)
        );
    }

    #[test]
    fn mismatched_target_atom_identity_fails_closed() {
        let (journal, receipt, rows, profile) = admitted_fixture();
        let cue = derive_cue_binding_candidates(&receipt, &rows, None, &profile).expect("derive");
        let candidate = cue.candidates.first().expect("candidate");
        let candidate_id = candidate.binding_candidate_id.clone();
        let candidate_digest = candidate.digest.clone();
        let result = project_reactive_owner(
            &journal,
            &WorkScopeId::new("scope").expect("scope"),
            &fence(),
            &CueOwner { result: cue },
            &AtomOwner {
                bindings: vec![ReactiveTargetAtomBinding {
                    candidate_id,
                    candidate_digest,
                    target: TargetHandle::new("src/other.rs").expect("target"),
                    atom_id: ArtifactId::new("atom-1").expect("atom"),
                    source_revision: "rev-1".into(),
                    source_digest: digest(3).as_str().into(),
                }],
            },
        );
        assert_eq!(
            result,
            Err(ReactiveOwnerProjectionError::TargetAtomMismatch("target"))
        );
    }
}
