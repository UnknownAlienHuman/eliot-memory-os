//! Private semantic assembly of the `ControlBoard` read projection.
//!
//! This module compiles one refresh-consistent [`ControlBoardGovernorSnapshot`]
//! over the existing Governor owners (coordination, problem, observation,
//! task, read scope) plus the Kernel-issued named-read digests retained in
//! recovery. It creates no owner, registry, Store client, authority, or
//! second canonical path: every byte digested here is already owned and
//! fenced by the composition, and the snapshot is only published through
//! [`GovernorComposition::controlboard_snapshot`](crate::composition::GovernorComposition::controlboard_snapshot)
//! after the readiness gate.
//!
//! G-11/I-12 grounding: the composition owns no dedicated report owner (see
//! [`RecoveryOwner::ALL`](crate::composition::RecoveryOwner); there is no
//! report entry among the sixteen owners). The G-11 binding is served by the
//! coordination owner and the I-12 binding by the observation evidence
//! journal, which is the provenance substrate for reports. Both binding
//! digests cover the full joint owner assembly under domain separation, and
//! both receipt references are the exact Kernel-issued named-read value
//! digests for the payload bytes assembled here. Nothing is fabricated: an
//! owner that cannot be read fails the assembly instead of producing a
//! placeholder.
//!
//! The snapshot carries no board items, reviews, or provenance edges. Owner
//! records (tasks, coordination events, journal entries) carry no `ControlBoard`
//! visibility, privacy, or epistemic facts, and inventing them would be a
//! privacy expansion. An empty-items view over real bindings is the honest
//! projection; it is distinct from a missing provider, which stays a typed
//! `PLAN_GAP` at the surface. Command families that need item projections
//! remain deferred until their owners expose the required contract.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_coordination::CoordinationOwner;
use eliot_observation::ObservationJournal;
use eliot_store_api::ScopeRevisionView;
use eliot_task::TaskLifecycleOwner;
use serde::Serialize;
use thiserror::Error;

/// Fail-closed errors for `ControlBoard` projection assembly.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlBoardProjectionError {
    /// The assembly fence is not a valid shared fence.
    #[error("controlboard projection fence is invalid: {0}")]
    Fence(String),
    /// The board revision must be non-zero.
    #[error("controlboard projection read revision must be non-zero")]
    ZeroRevision,
    /// A Kernel-issued receipt digest is not a lowercase SHA-256 value.
    #[error("controlboard projection receipt reference is invalid: {0}")]
    Receipt(String),
    /// Owner state could not be serialized for the binding digest.
    #[error("controlboard projection owner state is invalid: {0}")]
    Owner(String),
}

/// One provider-issued identity binding assembled from a real owner read.
///
/// `binding_id` names the actual Governor owner, `binding_digest` binds the
/// full joint owner assembly at the snapshot fence and revision under domain
/// separation, and `receipt_ref` is the exact Kernel-issued named-read value
/// digest for that owner's payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardOwnerBinding {
    /// Stable identity of the Governor owner serving this binding.
    pub binding_id: String,
    /// Digest over the joint owner assembly for this binding domain.
    pub binding_digest: String,
    /// Kernel-issued named-read value digest for the owner's payload bytes.
    pub receipt_ref: String,
}

/// Refresh-consistent `ControlBoard` snapshot assembled over Governor owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardGovernorSnapshot {
    /// Exact fence every assembled owner was built at.
    pub fence: StateFence,
    /// Read-owner named-read revision this snapshot was taken at.
    pub read_revision: u64,
    /// Live coordination sequence observed during assembly.
    pub coordination_sequence: u64,
    /// G-11 review-projection binding served by the coordination owner.
    pub g11_coordination: ControlBoardOwnerBinding,
    /// I-12 report-projection binding served by the observation journal.
    pub i12_report: ControlBoardOwnerBinding,
}

/// Borrowed assembly inputs. The caller retains every owner; this struct only
/// borrows them for one deterministic compilation.
pub struct ControlBoardProjectionParts<'a> {
    /// Fence all supplied owners were built at.
    pub fence: &'a StateFence,
    /// Read-owner named-read revision bound to this snapshot.
    pub read_revision: u64,
    /// Durable application coordination owner.
    pub coordination: &'a CoordinationOwner,
    /// Durable task lifecycle owner.
    pub task: &'a TaskLifecycleOwner,
    /// Candidate observation journal owner.
    pub observation: &'a ObservationJournal,
    /// Durable problem revision map.
    pub problem_revisions: &'a BTreeMap<String, u64>,
    /// Canonical read scope view.
    pub read_scope: &'a ScopeRevisionView,
    /// Kernel-issued value digest for the coordination payload bytes.
    pub coordination_receipt_digest: &'a str,
    /// Kernel-issued value digest for the observation payload bytes.
    pub observation_receipt_digest: &'a str,
}

/// Stable owner identity bound into the G-11 coordination binding.
pub const G11_OWNER_BINDING_ID: &str = "governor-owner:coordination";
/// Stable owner identity bound into the I-12 report binding.
pub const I12_OWNER_BINDING_ID: &str = "governor-owner:observation";

fn validates_as_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Compiles one deterministic snapshot over the supplied owners.
///
/// The compilation is pure: identical owner state, fence, revision, and
/// receipt digests produce identical bytes. Any unreadable owner state, zero
/// revision, invalid fence, or malformed receipt digest fails closed without
/// a placeholder.
pub fn compile_controlboard_snapshot(
    parts: &ControlBoardProjectionParts<'_>,
) -> Result<ControlBoardGovernorSnapshot, ControlBoardProjectionError> {
    parts
        .fence
        .validate()
        .map_err(|error| ControlBoardProjectionError::Fence(error.to_string()))?;
    if parts.read_revision == 0 {
        return Err(ControlBoardProjectionError::ZeroRevision);
    }
    for (digest, owner) in [
        (parts.coordination_receipt_digest, "coordination"),
        (parts.observation_receipt_digest, "observation"),
    ] {
        if !validates_as_lower_sha256(digest) {
            return Err(ControlBoardProjectionError::Receipt(owner.to_owned()));
        }
    }
    let coordination_bytes = serde_json::to_vec(&(
        parts.coordination.current_sequence(),
        parts.coordination.events(),
    ))
    .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let task_bytes = serde_json::to_vec(&parts.task.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let observation_bytes = serde_json::to_vec(&parts.observation.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let problem_bytes = serde_json::to_vec(&parts.problem_revisions)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let scope_bytes = serde_json::to_vec(&parts.read_scope)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let owner_digests = (
        sha256_hex(&coordination_bytes),
        sha256_hex(&task_bytes),
        sha256_hex(&observation_bytes),
        sha256_hex(&problem_bytes),
        sha256_hex(&scope_bytes),
    );
    let bind = |binding_id: &str, receipt_ref: &str| {
        canonical_json_bytes(&(binding_id, parts.fence, parts.read_revision, &owner_digests))
            .map(|bytes| ControlBoardOwnerBinding {
                binding_id: binding_id.to_owned(),
                binding_digest: sha256_hex(&bytes),
                receipt_ref: receipt_ref.to_owned(),
            })
            .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))
    };
    Ok(ControlBoardGovernorSnapshot {
        fence: parts.fence.clone(),
        read_revision: parts.read_revision,
        coordination_sequence: parts.coordination.current_sequence(),
        g11_coordination: bind(G11_OWNER_BINDING_ID, parts.coordination_receipt_digest)?,
        i12_report: bind(I12_OWNER_BINDING_ID, parts.observation_receipt_digest)?,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_store_api::ScopeId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope(fence: &StateFence) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("scope").expect("scope id"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence.clone(),
        }
    }

    fn parts<'a>(
        fence: &'a StateFence,
        coordination: &'a CoordinationOwner,
        task: &'a TaskLifecycleOwner,
        observation: &'a ObservationJournal,
        problems: &'a BTreeMap<String, u64>,
        read_scope: &'a ScopeRevisionView,
        digests: &'a (String, String),
    ) -> ControlBoardProjectionParts<'a> {
        ControlBoardProjectionParts {
            fence,
            read_revision: 7,
            coordination,
            task,
            observation,
            problem_revisions: problems,
            read_scope,
            coordination_receipt_digest: &digests.0,
            observation_receipt_digest: &digests.1,
        }
    }

    fn digests() -> (String, String) {
        ("a".repeat(64), "b".repeat(64))
    }

    #[test]
    fn empty_owners_assemble_a_deterministic_empty_projection() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        let first = compile_controlboard_snapshot(&input).expect("snapshot");
        let second = compile_controlboard_snapshot(&input).expect("snapshot");
        assert_eq!(first, second);
        assert_eq!(first.fence, fence);
        assert_eq!(first.read_revision, 7);
        assert_eq!(first.g11_coordination.binding_id, G11_OWNER_BINDING_ID);
        assert_eq!(first.i12_report.binding_id, I12_OWNER_BINDING_ID);
        assert_ne!(
            first.g11_coordination.binding_digest,
            first.i12_report.binding_digest
        );
        assert_eq!(first.g11_coordination.receipt_ref, "a".repeat(64));
        assert_eq!(first.i12_report.receipt_ref, "b".repeat(64));
    }

    #[test]
    fn owner_bytes_are_load_bearing_not_canned() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let read_scope = scope(&fence);
        let empty_problems = BTreeMap::new();
        let digests = digests();
        let idle = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &empty_problems,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        let mut one_problem = BTreeMap::new();
        one_problem.insert("problem-1".to_owned(), 2);
        let changed = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &one_problem,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        assert_ne!(
            idle.g11_coordination.binding_digest,
            changed.g11_coordination.binding_digest
        );
        assert_ne!(
            idle.i12_report.binding_digest,
            changed.i12_report.binding_digest
        );
    }

    #[test]
    fn zero_revision_and_malformed_receipts_fail_closed() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.read_revision = 0;
        assert_eq!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::ZeroRevision)
        );
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.coordination_receipt_digest = "not-a-digest";
        assert!(matches!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::Receipt(_))
        ));
    }
}
