//! Governor-to-swarm attachment composition (issue #2017 item 4).
//!
//! This module is the single composition root that wires the Governor
//! attachment owner to swarm consumers. The daemon owns one
//! [`SwarmAttachmentComposition`]; every swarm consumer vends its handle from
//! and attaches through that one value, so independently acquired handles
//! converge on one owner: the first job commits, an identical replay is
//! idempotent, and a second job observes `OwnershipConflict` naming the
//! canonical winner.
//!
//! Runtime role: the bounded task runtime executes admitted work; it never
//! decides ownership. Ownership is decided only by the composed
//! [`SwarmPlanAttachmentService`](super::SwarmPlanAttachmentService) through
//! its canonical-write-bound store. A runtime worker that needs a binding
//! presents a vended consumer plus the candidate job handle here; it cannot
//! supply plan identity at attach time and cannot manufacture a second
//! binding.
//!
//! Ownership scope: this composition owns exactly one service instance, so it
//! covers the process domain and the daemon domain once the daemon owns
//! exactly one composition. Host restarts and cross-process durability follow
//! once the daemon composes
//! [`revision_expectations`](super::CanonicalSwarmPlanAttachmentStore::revision_expectations)
//! /
//! [`ordering_expectations`](super::CanonicalSwarmPlanAttachmentStore::ordering_expectations)
//! into a real `CanonicalWriteEnvelope`; that envelope wiring is remainder,
//! not claimed here (see
//! [`swarm_plan_attachment_ownership`](super::swarm_plan_attachment_ownership)).

use eliot_coordination::{
    DurableAttachError, SwarmPlanAttachmentConsumer, SwarmPlanAttachmentConsumerPort,
    SwarmPlanAttachmentError, SwarmPlanBinding,
};
use eliot_store_api::{OrderingHeadExpectation, RevisionHeadExpectation, StateFence, StoreError};

use super::{
    swarm_plan_attachment_ownership::AttachmentOwnershipScope, CanonicalAttachmentStoreError,
    CanonicalSwarmPlanAttachmentStore, SwarmPlanAttachmentService,
};

/// The single Governor-to-swarm attachment composition.
///
/// Owns exactly one [`SwarmPlanAttachmentService`] (hence one canonical store
/// image). Share by reference; never construct a second instance per daemon.
#[derive(Debug)]
pub struct SwarmAttachmentComposition {
    service: SwarmPlanAttachmentService,
}

impl SwarmAttachmentComposition {
    #[must_use]
    pub const fn new(service: SwarmPlanAttachmentService) -> Self {
        Self { service }
    }

    /// Borrows the composed Governor attachment service.
    #[must_use]
    pub const fn service(&self) -> &SwarmPlanAttachmentService {
        &self.service
    }

    /// Borrows the composed production store image.
    #[must_use]
    pub const fn store(&self) -> &CanonicalSwarmPlanAttachmentStore {
        self.service.store()
    }

    /// Returns the ownership scope this composition instance covers: exactly
    /// one service (process domain; daemon domain once the daemon owns
    /// exactly one composition).
    #[must_use]
    pub const fn ownership_scope(&self) -> AttachmentOwnershipScope {
        AttachmentOwnershipScope::single_service()
    }

    /// Vends one opaque swarm consumer handle pinned to the given identities.
    ///
    /// Validation is fail-closed: blank identities are refused and no handle
    /// is issued. The handle carries no job: the caller supplies the candidate
    /// job handle only at [`attach`](Self::attach) time.
    pub fn vend_consumer(
        &self,
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
    ) -> Result<SwarmPlanAttachmentConsumer, SwarmPlanAttachmentError> {
        self.service
            .vend_consumer(admission_digest, plan_revision, fence_digest)
    }

    /// Attaches one vended swarm consumer plan to one durable job handle
    /// through the single composed owner.
    pub fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<CanonicalAttachmentStoreError>> {
        self.service.attach(consumer, job_handle)
    }

    /// Maps one loaded version onto the envelope's `expected_revision_heads`
    /// for the daemon's canonical write.
    ///
    /// Passthrough over the production store mapping; the daemon composes the
    /// returned expectations into the envelope it commits.
    pub fn revision_expectations(
        version: eliot_coordination::SwarmPlanAttachmentVersion,
        fence: &StateFence,
    ) -> Result<Vec<RevisionHeadExpectation>, StoreError> {
        CanonicalSwarmPlanAttachmentStore::revision_expectations(version, fence)
    }

    /// Maps one loaded version onto the envelope's `expected_ordering_heads`
    /// for the daemon's canonical write.
    pub fn ordering_expectations(
        version: eliot_coordination::SwarmPlanAttachmentVersion,
        fence: &StateFence,
    ) -> Result<Vec<OrderingHeadExpectation>, StoreError> {
        CanonicalSwarmPlanAttachmentStore::ordering_expectations(version, fence)
    }
}

impl SwarmPlanAttachmentConsumerPort for SwarmAttachmentComposition {
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
    use eliot_coordination::{SwarmPlanAttachmentStore, SwarmPlanAttachmentVersion};
    use std::sync::{Arc, Barrier};

    const ADMISSION: &str = "admission-digest-1";
    const PLAN: &str = "plan-1";
    const FENCE_DIGEST: &str = "fence-digest-1";

    fn fence() -> StateFence {
        serde_json::from_value(serde_json::json!({
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
            "resource_generation": 1,
            "task_revision": 1,
            "policy_revision": null,
            "integration_revision": null
        }))
        .expect("test fence decodes")
    }

    #[test]
    fn composition_covers_single_service_scope() {
        let composition = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
        assert_eq!(composition.ownership_scope().services(), 1);
        assert!(composition.store().is_empty().expect("store state is readable"));
    }

    #[test]
    fn independently_acquired_handles_converge_second_job_conflicts() {
        let composition = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
        // Two handles vended independently from the one composition pin the
        // same identity; neither carries the job, so no swap is possible
        // between acquisition and attach.
        let first_handle = composition
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends");
        let second_handle = composition
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends");
        assert_eq!(first_handle, second_handle);

        let winner = composition
            .attach(&first_handle, "job-1")
            .expect("first bind commits");
        assert_eq!(winner.job_handle(), "job-1");

        let replay = composition
            .attach(&second_handle, "job-1")
            .expect("identical replay is idempotent");
        assert_eq!(replay, winner);

        match composition.attach(&second_handle, "job-2") {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(composition.store().len().expect("store state is readable"), 1);
    }

    #[test]
    fn port_trait_converges_through_composition_reference() {
        let composition = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
        let port: &dyn SwarmPlanAttachmentConsumerPort<Error = CanonicalAttachmentStoreError> =
            &composition;
        let first_handle = composition
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends");
        let second_handle = composition
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends");
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
        let composition = Arc::new(SwarmAttachmentComposition::new(
            SwarmPlanAttachmentService::new(),
        ));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let composition = Arc::clone(&composition);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let handle = composition
                    .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
                    .expect("consumer vends");
                composition.attach(&handle, &format!("job-{index}"))
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
        assert_eq!(composition.store().len().expect("store state is readable"), 1);
    }

    #[test]
    fn envelope_head_passthrough_matches_store_mapping() {
        let fence = fence();
        let initial = SwarmAttachmentComposition::revision_expectations(
            SwarmPlanAttachmentVersion::initial(),
            &fence,
        )
        .expect("initial heads map");
        assert!(initial.is_empty());

        let composition = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
        let handle = composition
            .vend_consumer(ADMISSION, PLAN, FENCE_DIGEST)
            .expect("consumer vends");
        composition.attach(&handle, "job-1").expect("bind commits");
        let (_, version) = composition.store().load().expect("store loads");
        assert_eq!(version, SwarmPlanAttachmentVersion::new(1));
        let revisions =
            SwarmAttachmentComposition::revision_expectations(version, &fence).expect("heads map");
        let orderings =
            SwarmAttachmentComposition::ordering_expectations(version, &fence).expect("heads map");
        assert_eq!(revisions.len(), 1);
        assert_eq!(orderings.len(), 1);
        revisions[0].validate().expect("revision head validates");
        orderings[0].validate().expect("ordering head validates");
    }

    #[test]
    fn vend_consumer_rejects_blank_identities() {
        let composition = SwarmAttachmentComposition::new(SwarmPlanAttachmentService::new());
        assert_eq!(
            composition.vend_consumer("   ", PLAN, FENCE_DIGEST),
            Err(SwarmPlanAttachmentError::InvalidField("admission_digest"))
        );
        assert!(composition.store().is_empty().expect("store state is readable"));
    }
}
