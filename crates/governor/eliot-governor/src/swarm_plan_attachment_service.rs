//! Governor-owned canonical swarm plan attachment state and its production store.
//!
//! This module is issue #2017 slice 2 (items 1+5): the Governor-side service
//! owning canonical attachment state, plus the production
//! [`SwarmPlanAttachmentStore`] implementation bound to the canonical-write
//! path. It reuses the slice-1 vended consumer port
//! ([`SwarmPlanAttachmentConsumerPort`]); callers still supply only a vended
//! [`SwarmPlanAttachmentConsumer`] plus the candidate job handle, so plan
//! identity cannot be swapped between acquisition and attach.
//!
//! Binding model: [`CanonicalSwarmPlanAttachmentStore`] holds the Governor
//! canonical owner image plus a monotonic commit version behind one
//! [`std::sync::Mutex`]. `load`/`compare_and_swap` implement the exact
//! conditional-commit contract the durable entry point
//! ([`attach_plan_once_durable`]) requires: a replacement commits if and only
//! if the image is still `expected`, otherwise the attempt reports
//! [`CasOutcome::Contended`] and the caller reloads. No unbound-to-bound
//! success escapes before [`CasOutcome::Committed`].
//!
//! Canonical-write mapping: [`SwarmPlanAttachmentVersion`] maps onto the
//! `CanonicalWriteEnvelope` revision-head protocol through
//! [`CanonicalSwarmPlanAttachmentStore::revision_expectations`] and
//! [`CanonicalSwarmPlanAttachmentStore::ordering_expectations`].
//! The daemon composes those expectations into the envelope's
//! `expected_revision_heads` / `expected_ordering_heads`; a violated
//! revision-head or ordering-head expectation surfaces from the canonical
//! store as [`StoreError::RevisionConflict`] /
//! [`StoreError::OrderingConflict`], which
//! [`CanonicalSwarmPlanAttachmentStore::classify_store_error`]
//! reports as [`CasOutcome::Contended`]. The store performs no I/O itself:
//! cross-process durability comes from the daemon wiring these expectations
//! into a real canonical write, never from this in-process image alone.
//!
//! Ownership domains: process-local singularity holds through this service's
//! single store image (one winner per plan key, second job observes
//! `OwnershipConflict`). Daemon-wide singularity follows once the daemon owns
//! one service instance; host/cross-process durability follows once the
//! daemon wires the mapped expectations into the canonical write path and all
//! writers route through it. That composition wiring (issue items 3+4) is
//! remainder, not claimed here.
//!
//! [`StoreError::RevisionConflict`]: eliot_store_api::StoreError::RevisionConflict
//! [`StoreError::OrderingConflict`]: eliot_store_api::StoreError::OrderingConflict

use std::sync::Mutex;

use eliot_coordination::{
    attach_plan_once_durable, CasOutcome, DurableAttachError, SwarmPlanAttachmentConsumer,
    SwarmPlanAttachmentConsumerPort, SwarmPlanAttachmentError, SwarmPlanAttachmentOwner,
    SwarmPlanAttachmentStore, SwarmPlanAttachmentVersion, SwarmPlanBinding,
};
use eliot_store_api::{
    OrderingHeadExpectation, OrderingScopeId, RevisionHeadExpectation, RevisionKey, StateFence,
    StoreError,
};
use thiserror::Error;

/// Revision dependency key addressing the canonical attachment image.
///
/// The daemon places this key in the envelope's `expected_revision_heads`
/// with the loaded [`SwarmPlanAttachmentVersion`] as the expected revision.
pub const ATTACHMENT_REVISION_KEY: &str = "governor.swarm-plan-attachment.v1";

/// Ordering scope serializing canonical attachment commits.
///
/// The daemon places this scope in the envelope's `expected_ordering_heads`
/// with the loaded [`SwarmPlanAttachmentVersion`] as the expected sequence.
pub const ATTACHMENT_ORDERING_SCOPE: &str = "governor.swarm-plan-attachment.v1";

/// Fail-closed errors from the Governor canonical attachment store.
///
/// The image is validated before any commit: a corrupt replacement is
/// refused rather than persisted. Lock poisoning fails closed for the same
/// reason.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanonicalAttachmentStoreError {
    /// The store mutex is poisoned; no decision is granted on unknown state.
    #[error("swarm plan attachment store lock is poisoned")]
    Poisoned,
    /// The replacement owner image failed revalidation and was not stored.
    #[error("swarm plan attachment replacement image is invalid")]
    InvalidSnapshot,
}

/// Governor-owned production store for canonical attachment state.
///
/// This is the item-5 production [`SwarmPlanAttachmentStore`]: one
/// mutex-guarded canonical owner image plus a monotonic commit version. It
/// performs no I/O; the canonical-write binding is the version-to-head
/// mapping ([`Self::revision_expectations`], [`Self::ordering_expectations`])
/// the daemon composes into a `CanonicalWriteEnvelope`, with head violations
/// classified by [`Self::classify_store_error`].
#[derive(Debug, Default)]
pub struct CanonicalSwarmPlanAttachmentStore {
    state: Mutex<StoreState>,
}

#[derive(Clone, Debug, Default)]
struct StoreState {
    owner: SwarmPlanAttachmentOwner,
    version: SwarmPlanAttachmentVersion,
}

impl CanonicalSwarmPlanAttachmentStore {
    /// Creates an empty Governor attachment store at the initial version.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of canonical bindings in the committed image.
    pub fn len(&self) -> Result<usize, CanonicalAttachmentStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CanonicalAttachmentStoreError::Poisoned)?;
        Ok(state.owner.len())
    }

    /// Returns whether the committed image records no bindings.
    pub fn is_empty(&self) -> Result<bool, CanonicalAttachmentStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CanonicalAttachmentStoreError::Poisoned)?;
        Ok(state.owner.is_empty())
    }

    /// Maps one loaded version onto the envelope's expected revision head.
    ///
    /// The returned expectation is suitable only for an existing committed
    /// attachment image; genesis must instead be represented by a canonical
    /// create-if-absent expectation in the durable canonical-write path.
    pub fn revision_expectations(
        version: SwarmPlanAttachmentVersion,
        fence: &StateFence,
    ) -> Result<Vec<RevisionHeadExpectation>, StoreError> {
        if version == SwarmPlanAttachmentVersion::initial() {
            return Ok(Vec::new());
        }
        Ok(vec![RevisionHeadExpectation {
            key: RevisionKey::new(ATTACHMENT_REVISION_KEY)?,
            expected_revision: version.value(),
            state_fence: fence.clone(),
        }])
    }

    /// Maps one loaded version onto the envelope's expected ordering head.
    ///
    /// The returned expectation is suitable only for an existing committed
    /// attachment image; genesis must instead be represented by a canonical
    /// create-if-absent expectation in the durable canonical-write path.
    pub fn ordering_expectations(
        version: SwarmPlanAttachmentVersion,
        fence: &StateFence,
    ) -> Result<Vec<OrderingHeadExpectation>, StoreError> {
        if version == SwarmPlanAttachmentVersion::initial() {
            return Ok(Vec::new());
        }
        Ok(vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(ATTACHMENT_ORDERING_SCOPE)?,
            expected_sequence: version.value(),
            state_fence: fence.clone(),
        }])
    }

    /// Classifies a canonical-write failure at the attachment head boundary.
    ///
    /// A violated revision-head or ordering-head expectation means another
    /// writer committed first, so the durable loop must reload and retry:
    /// [`CasOutcome::Contended`]. Any other store failure is not contention;
    /// the caller propagates it as a `Store` error instead.
    #[must_use]
    pub const fn classify_store_error(error: &StoreError) -> Option<CasOutcome> {
        match error {
            StoreError::RevisionConflict | StoreError::OrderingConflict => {
                Some(CasOutcome::Contended)
            }
            _ => None,
        }
    }
}

impl SwarmPlanAttachmentStore for CanonicalSwarmPlanAttachmentStore {
    type Error = CanonicalAttachmentStoreError;

    fn load(&self) -> Result<(SwarmPlanAttachmentOwner, SwarmPlanAttachmentVersion), Self::Error> {
        let state = self
            .state
            .lock()
            .map_err(|_| CanonicalAttachmentStoreError::Poisoned)?;
        Ok((state.owner.clone(), state.version))
    }

    fn compare_and_swap(
        &self,
        expected: SwarmPlanAttachmentVersion,
        replacement: &SwarmPlanAttachmentOwner,
    ) -> Result<CasOutcome, Self::Error> {
        // Fail closed on a corrupt replacement before touching stored state.
        SwarmPlanAttachmentOwner::from_snapshot(replacement.clone())
            .map_err(|_| CanonicalAttachmentStoreError::InvalidSnapshot)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| CanonicalAttachmentStoreError::Poisoned)?;
        if expected != state.version {
            return Ok(CasOutcome::Contended);
        }
        state.owner = replacement.clone();
        state.version = state.version.next();
        Ok(CasOutcome::Committed)
    }
}

/// Governor-side service owning canonical attachment state (item 1).
///
/// The service owns one [`CanonicalSwarmPlanAttachmentStore`] and vends
/// opaque [`SwarmPlanAttachmentConsumer`] handles pinned to one
/// `(admission_digest, plan_revision, fence_digest)` tuple. `attach` runs the
/// canonical durable decision through the store, so two independently
/// acquired handles for the same plan converge: the first job commits, an
/// identical replay is idempotent, and a second job observes
/// `OwnershipConflict` naming the canonical winner.
#[derive(Debug, Default)]
pub struct SwarmPlanAttachmentService {
    store: CanonicalSwarmPlanAttachmentStore,
}

impl SwarmPlanAttachmentService {
    /// Creates a service over an empty canonical attachment image.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the underlying production store.
    #[must_use]
    pub const fn store(&self) -> &CanonicalSwarmPlanAttachmentStore {
        &self.store
    }

    /// Vends one opaque consumer handle pinned to the given identities.
    ///
    /// Validation is fail-closed: blank identities are refused and no handle
    /// is issued. Construction runs through the port's vended path, so the
    /// Governor (not the caller) vends the identity-bearing capability.
    pub fn vend_consumer(
        &self,
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
    ) -> Result<SwarmPlanAttachmentConsumer, SwarmPlanAttachmentError> {
        SwarmPlanAttachmentConsumerPort::vend_consumer(
            self,
            admission_digest,
            plan_revision,
            fence_digest,
        )
    }

    /// Attaches one vended consumer plan to one durable job handle.
    pub fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<CanonicalAttachmentStoreError>> {
        attach_plan_once_durable(
            &self.store,
            consumer.admission_digest(),
            consumer.plan_revision(),
            job_handle,
            consumer.fence_digest(),
        )
    }
}

impl SwarmPlanAttachmentConsumerPort for SwarmPlanAttachmentService {
    type Error = CanonicalAttachmentStoreError;

    fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<Self::Error>> {
        Self::attach(self, consumer, job_handle)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::StateFence as Fence;
    use std::sync::{Arc, Barrier};

    const ADMISSION: &str = "admission-digest-1";
    const PLAN: &str = "plan-1";
    const FENCE_DIGEST: &str = "fence-digest-1";

    fn fence() -> Fence {
        serde_json::from_value(serde_json::json!({
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
            "resource_generation": 1,
            "task_revision": 1,
            "policy_revision": null,
            "integration_revision": null
        }))
        .expect("test fence decodes")
    }

    fn consumer_of(service: &SwarmPlanAttachmentService) -> SwarmPlanAttachmentConsumer {
        service
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends")
    }

    #[test]
    fn vend_consumer_rejects_blank_identities() {
        let service = SwarmPlanAttachmentService::new();
        assert_eq!(
            service.vend_consumer("   ", PLAN, FENCE_DIGEST),
            Err(SwarmPlanAttachmentError::InvalidField("admission_digest"))
        );
        assert_eq!(
            service.vend_consumer(ADMISSION, "   ", FENCE_DIGEST),
            Err(SwarmPlanAttachmentError::InvalidField("plan_revision"))
        );
        assert_eq!(
            service.vend_consumer(ADMISSION, PLAN, "   "),
            Err(SwarmPlanAttachmentError::InvalidField("fence_digest"))
        );
        assert!(service.store().is_empty().expect("store state is readable"));
    }

    #[test]
    fn independently_acquired_handles_converge_second_job_conflicts() {
        let service = SwarmPlanAttachmentService::new();
        // Two handles vended independently pin the same identity; neither
        // carries the job, so no swap is possible between acquisition and
        // attach.
        let first_handle = consumer_of(&service);
        let second_handle = consumer_of(&service);
        assert_eq!(first_handle, second_handle);

        let winner = service
            .attach(&first_handle, "job-1")
            .expect("first bind commits");
        assert_eq!(winner.job_handle(), "job-1");

        let replay = service
            .attach(&second_handle, "job-1")
            .expect("identical replay is idempotent");
        assert_eq!(replay, winner);

        match service.attach(&second_handle, "job-2") {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(service.store().len().expect("store state is readable"), 1);
    }

    #[test]
    fn port_trait_converges_through_service_reference() {
        let service = SwarmPlanAttachmentService::new();
        let port: &dyn SwarmPlanAttachmentConsumerPort<Error = CanonicalAttachmentStoreError> =
            &service;
        let first_handle = consumer_of(&service);
        let second_handle = consumer_of(&service);
        let winner = port.attach(&first_handle, "job-1").expect("first binds");
        match port.attach(&second_handle, "job-2") {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_first_bind_has_exactly_one_winner() {
        let service = Arc::new(SwarmPlanAttachmentService::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let service = Arc::clone(&service);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let handle = service
                    .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
                    .expect("consumer vends");
                service.attach(&handle, &format!("job-{index}"))
            }));
        }
        let mut winners = Vec::new();
        let mut conflicts = 0usize;
        for handle in handles {
            match handle.join().expect("thread joins") {
                Ok(binding) => winners.push(binding),
                Err(DurableAttachError::Decision(
                    SwarmPlanAttachmentError::OwnershipConflict { existing: _ },
                )) => conflicts += 1,
                Err(other) => panic!("unexpected attach error: {other:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "exactly one first-bind may succeed");
        assert_eq!(conflicts, 7);
        assert_eq!(service.store().len().expect("store state is readable"), 1);
    }

    #[test]
    fn version_maps_onto_revision_and_ordering_heads() {
        let fence = fence();
        let initial_revision = CanonicalSwarmPlanAttachmentStore::revision_expectations(
            SwarmPlanAttachmentVersion::initial(),
            &fence,
        )
        .expect("initial heads map");
        let initial_ordering = CanonicalSwarmPlanAttachmentStore::ordering_expectations(
            SwarmPlanAttachmentVersion::initial(),
            &fence,
        )
        .expect("initial heads map");
        assert!(initial_revision.is_empty());
        assert!(initial_ordering.is_empty());

        let service = SwarmPlanAttachmentService::new();
        let handle = consumer_of(&service);
        service.attach(&handle, "job-1").expect("bind commits");
        let (_, version) = service.store().load().expect("store loads");
        assert_eq!(version, SwarmPlanAttachmentVersion::new(1));

        let revisions = CanonicalSwarmPlanAttachmentStore::revision_expectations(version, &fence)
            .expect("heads map");
        let orderings = CanonicalSwarmPlanAttachmentStore::ordering_expectations(version, &fence)
            .expect("heads map");
        assert_eq!(revisions.len(), 1);
        assert_eq!(orderings.len(), 1);
        assert_eq!(revisions[0].key.as_str(), ATTACHMENT_REVISION_KEY);
        assert_eq!(revisions[0].expected_revision, 1);
        assert_eq!(revisions[0].state_fence, fence);
        assert_eq!(orderings[0].scope.as_str(), ATTACHMENT_ORDERING_SCOPE);
        assert_eq!(orderings[0].expected_sequence, 1);
        assert_eq!(orderings[0].state_fence, fence);
        revisions[0].validate().expect("revision head validates");
        orderings[0].validate().expect("ordering head validates");
    }

    #[test]
    fn head_violations_classify_as_contended_others_do_not() {
        assert_eq!(
            CanonicalSwarmPlanAttachmentStore::classify_store_error(&StoreError::RevisionConflict),
            Some(CasOutcome::Contended)
        );
        assert_eq!(
            CanonicalSwarmPlanAttachmentStore::classify_store_error(&StoreError::OrderingConflict),
            Some(CasOutcome::Contended)
        );
        for error in [
            StoreError::FenceMismatch,
            StoreError::Unavailable,
            StoreError::IdentityConflict,
        ] {
            assert_eq!(
                CanonicalSwarmPlanAttachmentStore::classify_store_error(&error),
                None,
                "non-head failure must not report contention: {error:?}"
            );
        }
    }

    #[test]
    fn stale_version_commit_reports_contended_without_clobbering() {
        let store = CanonicalSwarmPlanAttachmentStore::new();
        let (image, version) = store.load().expect("store loads");
        let mut first = image;
        first
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE_DIGEST)
            .expect("decision binds");
        store
            .compare_and_swap(version, &first)
            .expect("first commits");
        // A stale writer holding the initial version loses the race.
        let mut stale = SwarmPlanAttachmentOwner::new();
        stale
            .attach_plan_once(ADMISSION, PLAN, "job-2", FENCE_DIGEST)
            .expect("stale decision binds locally");
        assert_eq!(
            store.compare_and_swap(version, &stale),
            Ok(CasOutcome::Contended)
        );
        let (current, _) = store.load().expect("store loads");
        assert_eq!(
            current
                .get(ADMISSION, PLAN)
                .expect("winner retained")
                .job_handle(),
            "job-1"
        );
    }
}
