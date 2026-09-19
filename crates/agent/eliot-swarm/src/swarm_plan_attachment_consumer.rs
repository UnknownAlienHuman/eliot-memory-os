//! Production swarm consumption of Governor-owned plan attachment (issue #2017 item 6).
//!
//! This module is the production swarm consumer path: it acquires opaque
//! consumer handles vended by the Governor attachment owner and attaches them
//! to durable job handles through a Governor-vended
//! [`SwarmPlanAttachmentConsumerPort`]. The swarm layer stays a consumer,
//! never a second owner: plan identity travels only inside the vended handle,
//! so a caller cannot swap the admission digest, plan revision, or fence
//! digest between acquisition and attach. The only caller-supplied value at
//! attach time is the candidate job handle, which the canonical decision then
//! binds or refuses with `OwnershipConflict` naming the canonical winner.
//!
//! Singularity holds within the single owner behind the port the consumer is
//! bound to: independently acquired handles converge (first job commits, an
//! identical replay is idempotent, a second job conflicts). Cross-process
//! durability follows once the port is bound to the canonical write path
//! (see the Governor composition root); this consumer performs no I/O and
//! mints no receipts of its own.
//!
//! The in-crate [`durable_dispatch`](super::durable_dispatch) helper remains
//! the validation-plus-delegation primitive over a caller-supplied ledger; new
//! production callers should prefer this consumer over a Governor-vended port.

use eliot_coordination::{
    DurableAttachError, SwarmPlanAttachmentConsumer, SwarmPlanAttachmentConsumerPort,
    SwarmPlanAttachmentError, SwarmPlanBinding,
};

use super::SwarmError;

/// Fail-closed errors from the production swarm attachment consumer.
///
/// Decision failures reuse the canonical [`SwarmPlanAttachmentError`]
/// unchanged (including the `OwnershipConflict` winner); the store error stays
/// opaque behind `Store` so no provider payload crosses this cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwarmAttachmentError<E> {
    /// The canonical decision refused the bind. A conflict carries the
    /// canonical winner and is final for the plan key: no commit was
    /// attempted and retrying with the same second job cannot succeed.
    Decision(SwarmPlanAttachmentError),
    /// The durable store failed underneath a load or commit attempt.
    Store(E),
    /// Every attempt contended with another committed writer. The bind was
    /// NOT committed; reloading observes the canonical winner.
    ContentionExhausted {
        /// Bounded rounds actually attempted.
        attempts: u32,
    },
}

impl<E> From<DurableAttachError<E>> for SwarmAttachmentError<E> {
    fn from(error: DurableAttachError<E>) -> Self {
        match error {
            DurableAttachError::Decision(decision) => Self::Decision(decision),
            DurableAttachError::Store(store) => Self::Store(store),
            DurableAttachError::ContentionExhausted { attempts } => {
                Self::ContentionExhausted { attempts }
            }
        }
    }
}

impl<E> std::fmt::Display for SwarmAttachmentError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decision(error) => write!(f, "swarm attachment decision failed: {error}"),
            Self::Store(_) => write!(f, "swarm attachment durable store failed"),
            Self::ContentionExhausted { attempts } => {
                write!(
                    f,
                    "swarm attachment commit contended after {attempts} attempts"
                )
            }
        }
    }
}

/// Production swarm consumer over one Governor-vended attachment port.
///
/// The consumer holds one pinned handle acquired through
/// [`acquire`](Self::acquire); every `attach` presents that handle plus the
/// candidate job handle to the same port. Two consumers acquired
/// independently from the same owner converge: they carry equal handles, the
/// first job wins, and a second job yields `OwnershipConflict`.
pub struct SwarmAttachmentConsumer<'a, P: SwarmPlanAttachmentConsumerPort + ?Sized> {
    port: &'a P,
    handle: SwarmPlanAttachmentConsumer,
}

impl<'a, P: SwarmPlanAttachmentConsumerPort + ?Sized> SwarmAttachmentConsumer<'a, P> {
    /// Acquires one opaque consumer handle pinned to the given identities.
    ///
    /// Acquisition is pure validation: blank identities fail closed with
    /// [`SwarmPlanAttachmentError::InvalidField`] and no handle is issued. No
    /// owner state is touched until [`attach`](Self::attach).
    pub fn acquire(
        port: &'a P,
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
    ) -> Result<Self, SwarmPlanAttachmentError> {
        let handle =
            SwarmPlanAttachmentConsumer::new(admission_digest, plan_revision, fence_digest)?;
        Ok(Self { port, handle })
    }

    /// Returns the pinned admission identity.
    #[must_use]
    pub fn admission_digest(&self) -> &str {
        self.handle.admission_digest()
    }

    /// Returns the pinned plan revision.
    #[must_use]
    pub fn plan_revision(&self) -> &str {
        self.handle.plan_revision()
    }

    /// Returns the pinned state-fence digest.
    #[must_use]
    pub fn fence_digest(&self) -> &str {
        self.handle.fence_digest()
    }

    /// Attaches the pinned plan to one durable job handle through the
    /// Governor-vended port.
    ///
    /// The first job commits; an identical replay returns the identical
    /// binding; a second job fails with `Decision(OwnershipConflict)`
    /// carrying the canonical winner.
    pub fn attach(
        &self,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, SwarmAttachmentError<P::Error>> {
        self.port
            .attach(&self.handle, job_handle)
            .map_err(SwarmAttachmentError::from)
    }

    /// Maps a consumer failure onto the cell's fail-closed [`SwarmError`].
    ///
    /// A canonical conflict becomes [`SwarmError::OwnershipConflict`]; every
    /// other failure (invalid input, invalid snapshot, store failure,
    /// exhausted contention) becomes [`SwarmError::Contract`, since the
    /// consumer presented a validated handle to the owner port and the owner
    /// refused it for a reason outside the singularity contract.
    pub fn to_swarm_error(error: &SwarmAttachmentError<P::Error>) -> SwarmError {
        match error {
            SwarmAttachmentError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                ..
            }) => SwarmError::OwnershipConflict,
            SwarmAttachmentError::Decision(_) | SwarmAttachmentError::Store(_) => {
                SwarmError::Contract
            }
            SwarmAttachmentError::ContentionExhausted { .. } => SwarmError::Contract,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_coordination::{
        CasOutcome, SwarmPlanAttachmentDurablePort, SwarmPlanAttachmentLedger,
        SwarmPlanAttachmentOwner, SwarmPlanAttachmentStore, SwarmPlanAttachmentVersion,
    };
    use std::sync::{Arc, Barrier, Mutex};

    const ADMISSION: &str = "admission-digest-1";
    const PLAN: &str = "plan-1";
    const FENCE: &str = "fence-digest-1";

    /// In-memory test-only [`SwarmPlanAttachmentStore`]: one mutex-guarded
    /// owner image plus a version counter. No production store lives in the
    /// swarm cell; the Governor service owns the production image.
    struct TestStore {
        state: Mutex<(SwarmPlanAttachmentOwner, SwarmPlanAttachmentVersion)>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                state: Mutex::new((
                    SwarmPlanAttachmentOwner::new(),
                    SwarmPlanAttachmentVersion::initial(),
                )),
            }
        }

        fn committed_len(&self) -> usize {
            self.state.lock().expect("test store lock holds").0.len()
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestStoreError(&'static str);

    impl SwarmPlanAttachmentStore for TestStore {
        type Error = TestStoreError;

        fn load(
            &self,
        ) -> Result<(SwarmPlanAttachmentOwner, SwarmPlanAttachmentVersion), Self::Error> {
            Ok(self.state.lock().expect("test store lock holds").clone())
        }

        fn compare_and_swap(
            &self,
            expected: SwarmPlanAttachmentVersion,
            replacement: &SwarmPlanAttachmentOwner,
        ) -> Result<CasOutcome, Self::Error> {
            let mut state = self.state.lock().expect("test store lock holds");
            if expected != state.1 {
                return Ok(CasOutcome::Contended);
            }
            state.0 = replacement.clone();
            state.1 = state.1.next();
            Ok(CasOutcome::Committed)
        }
    }

    #[test]
    fn acquire_rejects_blank_identities_before_owner_contact() {
        let ledger = SwarmPlanAttachmentLedger::new();
        assert!(matches!(
            SwarmAttachmentConsumer::acquire(&ledger, "   ", PLAN, FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("admission_digest"))
        ));
        assert!(matches!(
            SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, "   ", FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("plan_revision"))
        ));
        assert!(matches!(
            SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, "   "),
            Err(SwarmPlanAttachmentError::InvalidField("fence_digest"))
        ));
        assert!(ledger.is_empty());
    }

    #[test]
    fn ledger_consumers_converge_second_job_conflicts_with_winner() {
        let ledger = SwarmPlanAttachmentLedger::new();
        // Independently acquired handles pin the same identity; the caller
        // supplies only the job handle at attach time, so no identity swap
        // is possible between acquisition and attach.
        let first = SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, FENCE)
            .expect("first consumer acquires");
        let second = SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, FENCE)
            .expect("second consumer acquires");
        assert_eq!(first.admission_digest(), ADMISSION);
        assert_eq!(second.plan_revision(), PLAN);
        assert_eq!(second.fence_digest(), FENCE);

        let winner = first.attach("job-1").expect("first bind wins");
        assert_eq!(winner.job_handle(), "job-1");

        let replay = second.attach("job-1").expect("identical replay binds");
        assert_eq!(replay, winner);

        match second.attach("job-2") {
            Err(SwarmAttachmentError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn durable_port_consumers_converge_second_job_conflicts_with_winner() {
        let store = TestStore::new();
        let port = SwarmPlanAttachmentDurablePort::new(&store);
        let first = SwarmAttachmentConsumer::acquire(&port, ADMISSION, PLAN, FENCE)
            .expect("first consumer acquires");
        let second = SwarmAttachmentConsumer::acquire(&port, ADMISSION, PLAN, FENCE)
            .expect("second consumer acquires");

        let winner = first.attach("job-1").expect("first bind commits");
        assert_eq!(winner.job_handle(), "job-1");
        let replay = second.attach("job-1").expect("identical replay commits");
        assert_eq!(replay, winner);
        match second.attach("job-2") {
            Err(SwarmAttachmentError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(store.committed_len(), 1);
    }

    #[test]
    fn concurrent_first_bind_has_exactly_one_winner() {
        let ledger = Arc::new(SwarmPlanAttachmentLedger::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let ledger = Arc::clone(&ledger);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let consumer = SwarmAttachmentConsumer::acquire(&*ledger, ADMISSION, PLAN, FENCE)
                    .expect("consumer acquires");
                consumer.attach(&format!("job-{index}"))
            }));
        }
        let mut winners = Vec::new();
        let mut conflicts = 0usize;
        for handle in handles {
            match handle.join().expect("thread joins") {
                Ok(binding) => winners.push(binding),
                Err(SwarmAttachmentError::Decision(
                    SwarmPlanAttachmentError::OwnershipConflict { existing: _ },
                )) => conflicts += 1,
                Err(other) => panic!("unexpected consumer error: {other}"),
            }
        }
        assert_eq!(winners.len(), 1, "exactly one first-bind may succeed");
        assert_eq!(conflicts, 7);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn conflict_maps_to_swarm_ownership_conflict() {
        let ledger = SwarmPlanAttachmentLedger::new();
        let first = SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, FENCE)
            .expect("first consumer acquires");
        let second = SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, FENCE)
            .expect("second consumer acquires");
        first.attach("job-1").expect("first bind wins");
        let conflict = second.attach("job-2").expect_err("second job conflicts");
        assert_eq!(
            SwarmAttachmentConsumer::<SwarmPlanAttachmentLedger>::to_swarm_error(&conflict),
            SwarmError::OwnershipConflict
        );
    }

    #[test]
    fn blank_job_handle_fails_closed_without_binding() {
        let ledger = SwarmPlanAttachmentLedger::new();
        let consumer = SwarmAttachmentConsumer::acquire(&ledger, ADMISSION, PLAN, FENCE)
            .expect("consumer acquires");
        assert_eq!(
            consumer.attach("   "),
            Err(SwarmAttachmentError::Decision(
                SwarmPlanAttachmentError::InvalidField("job_handle")
            ))
        );
        assert!(ledger.is_empty());
    }
}
