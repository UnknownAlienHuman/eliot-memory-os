//! Governor-owned canonical attach-once for swarm plan to durable-job binding.
//!
//! This module is the single durable canon that decides whether a swarm plan
//! revision is unbound, identically bound, or conflicts with an existing
//! different job. It exists to unblock the swarm `durable_dispatch` slice
//! (issue #1126, PR #1127): the swarm layer must remain a consumer, never a
//! second owner, so singularity (one job per admitted plan revision) is
//! decided here, in Governor state, not by a caller-managed comparison.
//!
//! The owner is deliberately small and dependency-light: it takes only opaque
//! validated strings (admission digest, plan revision, job handle, fence
//! digest) and returns an immutable [`SwarmPlanBinding`]. It performs no I/O,
//! mints no receipts, and launches no processes.
//!
//! Durable canon boundary: the in-memory decision alone is not the durable
//! canon across processes or restarts. [`attach_plan_once_durable`] runs the
//! same decision through a caller-provided [`SwarmPlanAttachmentStore`] as
//! load-then-decide-then-versioned-compare-and-swap, and no unbound-to-bound
//! success escapes before the conditional commit reports
//! [`CasOutcome::Committed`]. On [`CasOutcome::Contended`] the operation
//! reloads and retries, returning the canonical winner instead of allowing
//! two first-bind successes. Restart recovery rebuilds the owner from its
//! snapshot via [`SwarmPlanAttachmentOwner::from_snapshot`].
//!
//! The store trait is a contract only: no production store implementation
//! lives in this dependency-light crate. Binding the trait to the real
//! Governor canonical write path (revision-head expectations, surfaced as
//! store revision/ordering conflicts) is queued remainder.
//!
//! Atomicity is structural, not advisory: [`SwarmPlanAttachmentLedger`] holds
//! the owner behind one [`std::sync::Mutex`] and performs lookup plus insert
//! inside a single critical section, so two concurrent `attach_plan_once`
//! calls for the same plan key cannot both create a binding. The single-writer
//! [`SwarmPlanAttachmentOwner::attach_plan_once`] takes `&mut self` for the
//! same reason. There is no check-then-act split across lock boundaries.
//! Cross-process atomicity comes only from [`attach_plan_once_durable`]
//! plus the store's conditional commit, never from the ledger alone.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Revision of the canonical plan-attachment binding wire shape.
pub const SWARM_PLAN_ATTACHMENT_REVISION: &str = "eliot.governor.swarm-plan-attachment.v1";

fn text(value: &str, field: &'static str) -> Result<(), SwarmPlanAttachmentError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SwarmPlanAttachmentError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed errors returned by the canonical attach-once decision.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SwarmPlanAttachmentError {
    /// An input identity was blank or carried a control character.
    #[error("invalid swarm plan attachment field: {0}")]
    InvalidField(&'static str),
    /// The plan key is already bound to a different exact binding. The
    /// payload carries the canonical pre-existing binding that won.
    #[error("swarm plan is already attached to a different durable job")]
    OwnershipConflict {
        /// The canonical binding already recorded for this plan key.
        existing: SwarmPlanBinding,
    },
    /// The owner snapshot image was internally inconsistent.
    #[error("swarm plan attachment snapshot is invalid")]
    InvalidSnapshot,
    /// Canonical serialization of the binding digest failed.
    #[error("swarm plan attachment serialization failed")]
    Serialization,
}

/// One immutable canonical binding of an admitted swarm plan revision to
/// exactly one Governor-owned durable job handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanBinding {
    /// Opaque Governor admission identity (swarm passes the admission
    /// receipt `identity.canonical_sha256`).
    pub admission_digest: String,
    /// Frozen swarm plan revision this binding was sealed against.
    pub plan_revision: String,
    /// Opaque Governor-owned durable job handle.
    pub job_handle: String,
    /// State-fence digest pinned by the attachment.
    pub fence_digest: String,
    /// Canonical digest over the exact binding tuple above.
    pub binding_digest: String,
}

impl SwarmPlanBinding {
    /// Opaque admission identity this binding belongs to.
    #[must_use]
    pub fn admission_digest(&self) -> &str {
        &self.admission_digest
    }

    /// Plan revision this binding belongs to.
    #[must_use]
    pub fn plan_revision(&self) -> &str {
        &self.plan_revision
    }

    /// Durable job handle this plan revision is bound to.
    #[must_use]
    pub fn job_handle(&self) -> &str {
        &self.job_handle
    }

    /// State-fence digest pinned by this binding.
    #[must_use]
    pub fn fence_digest(&self) -> &str {
        &self.fence_digest
    }

    /// Canonical digest of the exact binding tuple.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

#[derive(Serialize)]
struct BindingDigestInput<'a> {
    revision: &'static str,
    admission_digest: &'a str,
    plan_revision: &'a str,
    job_handle: &'a str,
    fence_digest: &'a str,
}

fn binding_digest(
    admission_digest: &str,
    plan_revision: &str,
    job_handle: &str,
    fence_digest: &str,
) -> Result<String, SwarmPlanAttachmentError> {
    let input = BindingDigestInput {
        revision: SWARM_PLAN_ATTACHMENT_REVISION,
        admission_digest,
        plan_revision,
        job_handle,
        fence_digest,
    };
    let bytes =
        canonical_json_bytes(&input).map_err(|_| SwarmPlanAttachmentError::Serialization)?;
    Ok(sha256_hex(&bytes))
}

/// The single in-memory canonical owner for swarm plan to durable-job
/// bindings.
///
/// The map key is `(admission_digest, plan_revision)`: one job per admitted
/// plan revision, with admission identity preventing cross-plan collisions.
/// Values are exact bindings; any difference in job handle or fence digest
/// for an existing key is [`SwarmPlanAttachmentError::OwnershipConflict`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmPlanAttachmentOwner {
    bindings: BTreeMap<(String, String), SwarmPlanBinding>,
}

impl SwarmPlanAttachmentOwner {
    /// Creates an empty canonical owner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of canonical bindings recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Returns whether the owner records no bindings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Reads the canonical binding for one plan key, if any.
    #[must_use]
    pub fn get(&self, admission_digest: &str, plan_revision: &str) -> Option<&SwarmPlanBinding> {
        self.bindings
            .get(&(admission_digest.to_owned(), plan_revision.to_owned()))
    }

    /// Atomically attaches one admitted plan revision to one durable job.
    ///
    /// The decision is made against Governor canonical state in this call:
    /// an unbound key records and returns the new exact binding; an
    /// identically bound key returns the pre-existing binding unchanged
    /// (idempotent replay); a key bound to any different job handle or fence
    /// digest returns [`SwarmPlanAttachmentError::OwnershipConflict`]
    /// carrying the canonical winner. There is no caller-visible window
    /// between the lookup and the insert.
    pub fn attach_plan_once(
        &mut self,
        admission_digest: &str,
        plan_revision: &str,
        job_handle: &str,
        fence_digest: &str,
    ) -> Result<SwarmPlanBinding, SwarmPlanAttachmentError> {
        text(admission_digest, "admission_digest")?;
        text(plan_revision, "plan_revision")?;
        text(job_handle, "job_handle")?;
        text(fence_digest, "fence_digest")?;
        let key = (admission_digest.to_owned(), plan_revision.to_owned());
        if let Some(existing) = self.bindings.get(&key) {
            if existing.job_handle == job_handle && existing.fence_digest == fence_digest {
                return Ok(existing.clone());
            }
            return Err(SwarmPlanAttachmentError::OwnershipConflict {
                existing: existing.clone(),
            });
        }
        let binding = SwarmPlanBinding {
            admission_digest: admission_digest.to_owned(),
            plan_revision: plan_revision.to_owned(),
            job_handle: job_handle.to_owned(),
            fence_digest: fence_digest.to_owned(),
            binding_digest: binding_digest(
                admission_digest,
                plan_revision,
                job_handle,
                fence_digest,
            )?,
        };
        self.bindings.insert(key, binding.clone());
        Ok(binding)
    }

    /// Renders the canonical snapshot image carried through the durable
    /// write path.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Rebuilds one owner from a canonical snapshot image.
    ///
    /// Every binding is revalidated: identities must be non-blank with no
    /// control characters, and each stored digest must equal the digest
    /// recomputed over its exact tuple. A mismatched or malformed image is
    /// rejected instead of silently replacing state.
    pub fn from_snapshot(snapshot: Self) -> Result<Self, SwarmPlanAttachmentError> {
        for ((key_admission, key_plan), binding) in &snapshot.bindings {
            text(&binding.admission_digest, "admission_digest")?;
            text(&binding.plan_revision, "plan_revision")?;
            text(&binding.job_handle, "job_handle")?;
            text(&binding.fence_digest, "fence_digest")?;
            if key_admission != &binding.admission_digest || key_plan != &binding.plan_revision {
                return Err(SwarmPlanAttachmentError::InvalidSnapshot);
            }
            let expected = binding_digest(
                &binding.admission_digest,
                &binding.plan_revision,
                &binding.job_handle,
                &binding.fence_digest,
            )?;
            if expected != binding.binding_digest {
                return Err(SwarmPlanAttachmentError::InvalidSnapshot);
            }
        }
        Ok(snapshot)
    }
}

/// Thread-safe canonical ledger over one [`SwarmPlanAttachmentOwner`].
///
/// All decisions run inside a single [`Mutex`] critical section that covers
/// both the lookup and the insert, so concurrent `attach_plan_once` calls
/// for the same plan key are serialized by the ledger: same plan plus same
/// job returns the identical binding on every thread, while a different job
/// observes [`SwarmPlanAttachmentError::OwnershipConflict`] with the
/// canonical winner. There is no check-then-act split.
#[derive(Debug, Default)]
pub struct SwarmPlanAttachmentLedger {
    inner: Mutex<SwarmPlanAttachmentOwner>,
}

impl SwarmPlanAttachmentLedger {
    /// Creates an empty canonical ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically attaches one admitted plan revision to one durable job.
    ///
    /// See [`SwarmPlanAttachmentOwner::attach_plan_once`] for the decision
    /// contract. Lock poisoning fails closed as an invalid snapshot rather
    /// than granting a binding.
    pub fn attach_plan_once(
        &self,
        admission_digest: &str,
        plan_revision: &str,
        job_handle: &str,
        fence_digest: &str,
    ) -> Result<SwarmPlanBinding, SwarmPlanAttachmentError> {
        let mut owner = self
            .inner
            .lock()
            .map_err(|_| SwarmPlanAttachmentError::InvalidSnapshot)?;
        owner.attach_plan_once(admission_digest, plan_revision, job_handle, fence_digest)
    }

    /// Reads the canonical binding for one plan key, if any.
    #[must_use]
    pub fn get(&self, admission_digest: &str, plan_revision: &str) -> Option<SwarmPlanBinding> {
        self.inner
            .lock()
            .ok()
            .and_then(|owner| owner.get(admission_digest, plan_revision).cloned())
    }

    /// Returns the number of canonical bindings recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |owner| owner.len())
    }

    /// Returns whether the ledger records no bindings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_ok_and(|owner| owner.is_empty())
    }
}

/// Monotonic commit token pairing one loaded owner image with the durable
/// revision it was read at.
///
/// The token only orders `load`/`compare_and_swap` pairs for one store; it
/// carries no wire meaning on its own. The production binding maps it onto
/// the Governor canonical-write revision-head expectations (whose violation
/// the store surfaces as revision/ordering conflicts); that binding is queued
/// remainder, so the token stays a plain counter here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SwarmPlanAttachmentVersion(u64);

impl SwarmPlanAttachmentVersion {
    /// Version of an empty (never-committed) owner image.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Creates a version from a store-assigned counter value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Reads the store-assigned counter value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Successor version recorded alongside a committed replacement image.
    #[must_use]
    pub const fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

/// Outcome of one conditional durable commit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasOutcome {
    /// The replacement image was durably committed over the expected version.
    Committed,
    /// Another writer committed first; the replacement was NOT stored.
    Contended,
}

/// Durable canonical-write boundary for swarm plan attachment state.
///
/// Implementations serialize conditional commits across threads, processes,
/// and restarts: `compare_and_swap` must commit `replacement` if and only if
/// the canonical image is still `expected`, and report [`CasOutcome::Contended`]
/// otherwise. No I/O happens in this crate; the trait only names the contract
/// the production Governor write path must satisfy. There is no production
/// implementation here: binding to the real Governor write path is queued
/// remainder.
pub trait SwarmPlanAttachmentStore {
    /// Opaque store failure.
    type Error;

    /// Loads the current canonical owner image with its commit version.
    fn load(&self) -> Result<(SwarmPlanAttachmentOwner, SwarmPlanAttachmentVersion), Self::Error>;

    /// Commits `replacement` if and only if the canonical image is still
    /// `expected`.
    fn compare_and_swap(
        &self,
        expected: SwarmPlanAttachmentVersion,
        replacement: &SwarmPlanAttachmentOwner,
    ) -> Result<CasOutcome, Self::Error>;
}

/// Failures of [`attach_plan_once_durable`] beyond the in-process decision.
///
/// The store error stays opaque (`Store`) so no provider payload crosses this
/// dependency-light crate; decision failures (including the canonical
/// `OwnershipConflict` winner) pass through as `Decision`.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DurableAttachError<E> {
    /// The canonical decision itself refused the bind. A conflict carries the
    /// canonical winner and reflects append-only per-key state, so it is
    /// final: no commit is attempted.
    #[error("swarm plan attachment decision failed: {0}")]
    Decision(#[from] SwarmPlanAttachmentError),
    /// The durable store failed underneath a load or commit attempt.
    #[error("swarm plan attachment durable store failed")]
    Store(E),
    /// Every attempt contended with another committed writer. The bind was
    /// NOT committed; retrying the whole operation reloads and observes the
    /// canonical winner.
    #[error("swarm plan attachment commit contended after {attempts} attempts")]
    ContentionExhausted {
        /// Bounded rounds actually attempted (always [`MAX_DURABLE_ATTACH_ATTEMPTS`]).
        attempts: u32,
    },
}

/// Upper bound on load/decide/commit rounds inside one
/// [`attach_plan_once_durable`] call.
///
/// Termination is structural: every loop iteration either returns or consumes
/// exactly one attempt on [`CasOutcome::Contended`], so a call performs at
/// most this many loads and commits and always terminates, even under
/// perpetual contention.
pub const MAX_DURABLE_ATTACH_ATTEMPTS: u32 = 8;

/// Attaches one admitted plan revision to one durable job through the
/// canonical conditional-commit boundary.
///
/// Each round loads the durable image, revalidates it with
/// [`SwarmPlanAttachmentOwner::from_snapshot`] (tampered images fail closed
/// before any decision or commit), runs the canonical
/// [`SwarmPlanAttachmentOwner::attach_plan_once`] decision, and commits the
/// resulting image with [`SwarmPlanAttachmentStore::compare_and_swap`]. An
/// unbound-to-bound success is returned only after the commit reports
/// [`CasOutcome::Committed`]; contention reloads and retries, so the loser of
/// a cross-process first-bind race observes the canonical winner as
/// `OwnershipConflict` instead of escaping with a second success. Decision
/// refusals (conflict, invalid input, invalid snapshot) need no commit: the
/// winner binding for one plan key is append-only and immutable, so a
/// conflict read from a validated durable image is already final.
pub fn attach_plan_once_durable<S: SwarmPlanAttachmentStore>(
    store: &S,
    admission_digest: &str,
    plan_revision: &str,
    job_handle: &str,
    fence_digest: &str,
) -> Result<SwarmPlanBinding, DurableAttachError<S::Error>> {
    let mut attempts = 0u32;
    loop {
        let (image, version) = store.load().map_err(DurableAttachError::Store)?;
        let mut owner =
            SwarmPlanAttachmentOwner::from_snapshot(image).map_err(DurableAttachError::Decision)?;
        let binding =
            match owner.attach_plan_once(admission_digest, plan_revision, job_handle, fence_digest)
            {
                Ok(binding) => binding,
                Err(error) => return Err(DurableAttachError::Decision(error)),
            };
        match store
            .compare_and_swap(version, &owner)
            .map_err(DurableAttachError::Store)?
        {
            CasOutcome::Committed => return Ok(binding),
            CasOutcome::Contended => {
                attempts += 1;
                if attempts >= MAX_DURABLE_ATTACH_ATTEMPTS {
                    return Err(DurableAttachError::ContentionExhausted { attempts });
                }
            }
        }
    }
}

/// Opaque consumer identity vended by the Governor attachment owner.
///
/// The three identities are pinned at construction and exposed only through
/// getters: there are no setters and the fields are private, so a caller
/// holding a consumer cannot swap the admission digest, plan revision, or
/// fence digest between acquisition and attach. The only caller-supplied
/// value at attach time is the opaque durable job handle, which the canonical
/// decision then binds or refuses with `OwnershipConflict`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwarmPlanAttachmentConsumer {
    admission_digest: String,
    plan_revision: String,
    fence_digest: String,
}

impl SwarmPlanAttachmentConsumer {
    /// Vends one consumer handle after validating the pinned identities.
    ///
    /// Construction is crate-internal: external callers vend handles through
    /// [`SwarmPlanAttachmentConsumerPort::vend_consumer`].
    pub(crate) fn new(
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
    ) -> Result<Self, SwarmPlanAttachmentError> {
        text(admission_digest, "admission_digest")?;
        text(plan_revision, "plan_revision")?;
        text(fence_digest, "fence_digest")?;
        Ok(Self {
            admission_digest: admission_digest.to_owned(),
            plan_revision: plan_revision.to_owned(),
            fence_digest: fence_digest.to_owned(),
        })
    }

    /// Opaque admission identity pinned by this consumer.
    #[must_use]
    pub fn admission_digest(&self) -> &str {
        &self.admission_digest
    }

    /// Plan revision pinned by this consumer.
    #[must_use]
    pub fn plan_revision(&self) -> &str {
        &self.plan_revision
    }

    /// State-fence digest pinned by this consumer.
    #[must_use]
    pub fn fence_digest(&self) -> &str {
        &self.fence_digest
    }
}

/// Consumer-facing attach port vended by the Governor attachment owner.
///
/// Callers never supply the plan identity at attach time: they present a
/// previously vended [`SwarmPlanAttachmentConsumer`] plus the candidate job
/// handle. The port resolves the pinned `(admission_digest, plan_revision,
/// fence_digest)` tuple itself, so a caller cannot swap identities across
/// calls to manufacture a second binding.
///
/// The port is bound to the canonical-write path: implementations run the
/// canonical [`SwarmPlanAttachmentOwner::attach_plan_once`] decision through
/// the conditional-commit boundary (`load` then versioned
/// `compare_and_swap`, see [`attach_plan_once_durable`]). The production
/// Governor store maps [`SwarmPlanAttachmentVersion`] onto the
/// `CanonicalWriteEnvelope` revision-head protocol
/// (`expected_revision_heads` / `expected_ordering_heads`): a violated
/// revision-head or ordering-head expectation surfaces as a store
/// revision/ordering conflict, which the store reports as
/// [`CasOutcome::Contended`]. Contention reloads and retries, so the loser of
/// a first-bind race observes `OwnershipConflict` naming the canonical
/// winner instead of escaping with a second success. No unbound-to-bound
/// success escapes before [`CasOutcome::Committed`].
pub trait SwarmPlanAttachmentConsumerPort {
    /// Opaque store failure underneath the canonical-write path.
    type Error;

    /// Vends one opaque consumer handle pinned to the given identities.
    ///
    /// This is the only construction path outside the defining crate:
    /// validation is fail-closed (blank identities are refused with
    /// [`SwarmPlanAttachmentError::InvalidField`] and no handle is issued),
    /// so swarm callers cannot mint identity-bearing capabilities themselves.
    /// The default body constructs the handle.
    fn vend_consumer(
        &self,
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
    ) -> Result<SwarmPlanAttachmentConsumer, SwarmPlanAttachmentError> {
        SwarmPlanAttachmentConsumer::new(admission_digest, plan_revision, fence_digest)
    }

    /// Attaches the pinned consumer plan to one durable job handle.
    fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<Self::Error>>;
}

/// Durable consumer port over one [`SwarmPlanAttachmentStore`].
///
/// This is the canonical-write binding of [`SwarmPlanAttachmentConsumerPort`]:
/// every `attach` runs [`attach_plan_once_durable`] against the wrapped
/// store, so cross-process atomicity comes from the store's conditional
/// commit (revision-head CAS), never from the caller. The Governor production
/// store implements the wrapped trait with the `CanonicalWriteEnvelope`
/// `expected_revision_heads` / `expected_ordering_heads` expectations.
pub struct SwarmPlanAttachmentDurablePort<'a, S: SwarmPlanAttachmentStore> {
    store: &'a S,
}

impl<'a, S: SwarmPlanAttachmentStore> SwarmPlanAttachmentDurablePort<'a, S> {
    /// Borrows the canonical-write store behind this consumer port.
    #[must_use]
    pub fn new(store: &'a S) -> Self {
        Self { store }
    }
}

impl<S: SwarmPlanAttachmentStore> SwarmPlanAttachmentConsumerPort
    for SwarmPlanAttachmentDurablePort<'_, S>
{
    type Error = S::Error;

    fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<Self::Error>> {
        attach_plan_once_durable(
            self.store,
            consumer.admission_digest(),
            consumer.plan_revision(),
            job_handle,
            consumer.fence_digest(),
        )
    }
}

impl SwarmPlanAttachmentConsumerPort for SwarmPlanAttachmentLedger {
    type Error = std::convert::Infallible;

    /// Attaches through the in-process canonical ledger.
    ///
    /// Identity still comes only from the vended consumer: the caller
    /// supplies just the job handle. Decision failures (including the
    /// canonical `OwnershipConflict` winner) pass through as `Decision`;
    /// the in-memory ledger never produces a `Store` error.
    fn attach(
        &self,
        consumer: &SwarmPlanAttachmentConsumer,
        job_handle: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<Self::Error>> {
        self.attach_plan_once(
            consumer.admission_digest(),
            consumer.plan_revision(),
            job_handle,
            consumer.fence_digest(),
        )
        .map_err(DurableAttachError::Decision)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    const ADMISSION: &str = "admission-digest-1";
    const PLAN: &str = "plan-1";
    const FENCE: &str = "fence-digest-1";

    #[test]
    fn same_plan_and_job_is_idempotent_with_identical_binding() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        let first = owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("first attach binds");
        let second = owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("same plan plus same job replays");
        assert_eq!(first, second);
        assert_eq!(first.binding_digest(), second.binding_digest());
        assert_eq!(owner.len(), 1);
    }

    #[test]
    fn different_job_for_same_plan_conflicts_with_canonical_winner() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        let winner = owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("first attach binds");
        let conflict = owner.attach_plan_once(ADMISSION, PLAN, "job-2", FENCE);
        match conflict {
            Err(SwarmPlanAttachmentError::OwnershipConflict { existing }) => {
                assert_eq!(existing, winner);
                assert_eq!(existing.job_handle(), "job-1");
            }
            other => panic!("second job must conflict, got {other:?}"),
        }
        assert_eq!(owner.len(), 1);
        assert_eq!(
            owner.get(ADMISSION, PLAN).expect("winner retained"),
            &winner
        );
    }

    #[test]
    fn fence_drift_on_same_job_is_still_conflict() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("first attach binds");
        let conflict = owner.attach_plan_once(ADMISSION, PLAN, "job-1", "fence-digest-2");
        assert!(
            matches!(
                conflict,
                Err(SwarmPlanAttachmentError::OwnershipConflict { .. })
            ),
            "same job with drifted fence must not silently rebind: {conflict:?}"
        );
    }

    #[test]
    fn different_plan_revisions_bind_independently() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        let first = owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("plan-1 binds");
        let second = owner
            .attach_plan_once(ADMISSION, "plan-2", "job-2", FENCE)
            .expect("plan-2 binds independently");
        assert_ne!(first.binding_digest(), second.binding_digest());
        assert_eq!(owner.len(), 2);
    }

    #[test]
    fn blank_identities_fail_closed() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        assert_eq!(
            owner.attach_plan_once("   ", PLAN, "job-1", FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("admission_digest"))
        );
        assert_eq!(
            owner.attach_plan_once(ADMISSION, "   ", "job-1", FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("plan_revision"))
        );
        assert_eq!(
            owner.attach_plan_once(ADMISSION, PLAN, "   ", FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("job_handle"))
        );
        assert_eq!(
            owner.attach_plan_once(ADMISSION, PLAN, "job-1", "   "),
            Err(SwarmPlanAttachmentError::InvalidField("fence_digest"))
        );
        assert!(owner.is_empty());
    }

    #[test]
    fn snapshot_round_trip_preserves_canon_and_rejects_tamper() {
        let mut owner = SwarmPlanAttachmentOwner::new();
        let binding = owner
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("attach binds");
        let recovered = SwarmPlanAttachmentOwner::from_snapshot(owner.snapshot())
            .expect("valid snapshot rebuilds");
        assert_eq!(recovered.get(ADMISSION, PLAN), Some(&binding));

        let mut tampered = recovered.snapshot();
        let key = (ADMISSION.to_owned(), PLAN.to_owned());
        let stored = tampered.bindings.get_mut(&key).expect("binding present");
        stored.job_handle = "job-2".to_owned();
        assert_eq!(
            SwarmPlanAttachmentOwner::from_snapshot(tampered),
            Err(SwarmPlanAttachmentError::InvalidSnapshot)
        );
    }

    #[test]
    fn concurrent_same_plan_same_job_returns_identical_binding() {
        let ledger = Arc::new(SwarmPlanAttachmentLedger::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ledger = Arc::clone(&ledger);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                ledger.attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            }));
        }
        let mut digests = Vec::new();
        for handle in handles {
            let binding = handle
                .join()
                .expect("thread joins")
                .expect("all bind identically");
            digests.push(binding.binding_digest);
        }
        let first = &digests[0];
        assert!(
            digests.iter().all(|digest| digest == first),
            "concurrent identical attaches must agree: {digests:?}"
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn concurrent_second_job_conflicts_with_single_canonical_winner() {
        let ledger = Arc::new(SwarmPlanAttachmentLedger::new());
        ledger
            .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
            .expect("winner binds first");
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let ledger = Arc::clone(&ledger);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                if index % 2 == 0 {
                    ledger.attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
                } else {
                    ledger.attach_plan_once(ADMISSION, PLAN, "job-2", FENCE)
                }
            }));
        }
        let mut identical = 0usize;
        let mut conflicts = 0usize;
        for handle in handles {
            match handle.join().expect("thread joins") {
                Ok(binding) => {
                    assert_eq!(binding.job_handle(), "job-1");
                    identical += 1;
                }
                Err(SwarmPlanAttachmentError::OwnershipConflict { existing }) => {
                    assert_eq!(existing.job_handle(), "job-1");
                    conflicts += 1;
                }
                Err(other) => panic!("unexpected attach error: {other:?}"),
            }
        }
        assert_eq!(identical, 4);
        assert_eq!(conflicts, 4);
        assert_eq!(ledger.len(), 1);
    }

    /// Opaque test-only store failure (never produced by the happy paths).
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestStoreError(&'static str);

    /// In-memory test-only [`SwarmPlanAttachmentStore`]: one mutex-guarded
    /// owner image plus a version counter, with scripted contention and
    /// failure injection. No production store implementation lives in this
    /// crate; binding to the real Governor write path is queued remainder.
    struct TestStore {
        state: Mutex<TestStoreState>,
    }

    struct TestStoreState {
        owner: SwarmPlanAttachmentOwner,
        version: SwarmPlanAttachmentVersion,
        load_calls: usize,
        cas_calls: usize,
        /// When set, the next CAS first commits this external exact binding
        /// (modelling a concurrent writer winning the race) and then reports
        /// `Contended` for our image.
        inject_before_next_cas: Option<(String, String, String, String)>,
        /// When set, every CAS reports `Contended` without committing.
        always_contend: bool,
        load_error: Option<TestStoreError>,
    }

    impl TestStore {
        fn new() -> Self {
            Self {
                state: Mutex::new(TestStoreState {
                    owner: SwarmPlanAttachmentOwner::new(),
                    version: SwarmPlanAttachmentVersion::initial(),
                    load_calls: 0,
                    cas_calls: 0,
                    inject_before_next_cas: None,
                    always_contend: false,
                    load_error: None,
                }),
            }
        }

        fn with_tampered_seed() -> Self {
            let store = Self::new();
            let mut state = state(&store);
            let mut tampered = SwarmPlanAttachmentOwner::new();
            tampered
                .attach_plan_once(ADMISSION, PLAN, "job-1", FENCE)
                .expect("seed binds");
            let key = (ADMISSION.to_owned(), PLAN.to_owned());
            tampered
                .bindings
                .get_mut(&key)
                .expect("binding present")
                .job_handle = "job-2".to_owned();
            state.owner = tampered;
            drop(state);
            store
        }

        fn counts(store: &Self) -> (usize, usize) {
            let state = state(store);
            (state.load_calls, state.cas_calls)
        }

        fn committed_len(store: &Self) -> usize {
            state(store).owner.len()
        }
    }

    fn state(store: &TestStore) -> std::sync::MutexGuard<'_, TestStoreState> {
        store.state.lock().expect("test store lock holds")
    }

    impl SwarmPlanAttachmentStore for TestStore {
        type Error = TestStoreError;

        fn load(
            &self,
        ) -> Result<(SwarmPlanAttachmentOwner, SwarmPlanAttachmentVersion), Self::Error> {
            let mut state = state(self);
            state.load_calls += 1;
            if let Some(error) = &state.load_error {
                return Err(error.clone());
            }
            Ok((state.owner.clone(), state.version))
        }

        fn compare_and_swap(
            &self,
            expected: SwarmPlanAttachmentVersion,
            replacement: &SwarmPlanAttachmentOwner,
        ) -> Result<CasOutcome, Self::Error> {
            let mut state = state(self);
            state.cas_calls += 1;
            if let Some((admission, plan, job, fence)) = state.inject_before_next_cas.take() {
                state
                    .owner
                    .attach_plan_once(&admission, &plan, &job, &fence)
                    .expect("injected external commit is valid");
                state.version = state.version.next();
                return Ok(CasOutcome::Contended);
            }
            if state.always_contend {
                return Ok(CasOutcome::Contended);
            }
            if expected != state.version {
                return Ok(CasOutcome::Contended);
            }
            state.owner = replacement.clone();
            state.version = state.version.next();
            Ok(CasOutcome::Committed)
        }
    }

    fn durable(
        store: &TestStore,
        job: &str,
    ) -> Result<SwarmPlanBinding, DurableAttachError<TestStoreError>> {
        attach_plan_once_durable(store, ADMISSION, PLAN, job, FENCE)
    }

    #[test]
    fn durable_sequential_double_first_bind_has_exactly_one_winner() {
        let store = TestStore::new();
        let winner = durable(&store, "job-1").expect("first bind commits");
        assert_eq!(winner.job_handle(), "job-1");

        let conflict = durable(&store, "job-2");
        match conflict {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second first-bind must lose with the winner, got {other:?}"),
        }
        assert_eq!(TestStore::committed_len(&store), 1);
        // The losing decision needs no commit: exactly one CAS happened.
        assert_eq!(TestStore::counts(&store), (2, 1));
    }

    #[test]
    fn durable_concurrent_first_bind_has_exactly_one_winner() {
        let store = Arc::new(TestStore::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                attach_plan_once_durable(&*store, ADMISSION, PLAN, &format!("job-{index}"), FENCE)
            }));
        }
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.push(handle.join().expect("thread joins"));
        }
        let mut winners = Vec::new();
        let mut existing_seen = Vec::new();
        for outcome in outcomes {
            match outcome {
                Ok(binding) => winners.push(binding),
                Err(DurableAttachError::Decision(
                    SwarmPlanAttachmentError::OwnershipConflict { existing },
                )) => existing_seen.push(existing),
                Err(other) => panic!("unexpected durable attach error: {other:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "exactly one first-bind may succeed");
        assert_eq!(existing_seen.len(), 7);
        let winner = winners.pop().expect("one winner");
        assert!(
            existing_seen.iter().all(|existing| existing == &winner),
            "every loser must name the one canonical winner"
        );
        assert_eq!(TestStore::committed_len(&store), 1);
    }

    #[test]
    fn durable_contended_reload_returns_canonical_winner() {
        let store = TestStore::new();
        // A concurrent writer binds job-2 for our key before our CAS lands.
        state(&store).inject_before_next_cas = Some((
            ADMISSION.to_owned(),
            PLAN.to_owned(),
            "job-2".to_owned(),
            FENCE.to_owned(),
        ));
        let conflict = durable(&store, "job-1");
        match conflict {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing.job_handle(), "job-2"),
            other => panic!("contended loser must see the canonical winner, got {other:?}"),
        }
        assert_eq!(TestStore::committed_len(&store), 1);
        assert_eq!(TestStore::counts(&store), (2, 1));
    }

    #[test]
    fn durable_unrelated_contention_retries_then_commits() {
        let store = TestStore::new();
        // A concurrent writer binds a DIFFERENT plan key before our CAS lands.
        state(&store).inject_before_next_cas = Some((
            ADMISSION.to_owned(),
            "plan-2".to_owned(),
            "job-9".to_owned(),
            FENCE.to_owned(),
        ));
        let binding = durable(&store, "job-1").expect("retry commits after reload");
        assert_eq!(binding.job_handle(), "job-1");
        assert_eq!(TestStore::committed_len(&store), 2);
        assert_eq!(TestStore::counts(&store), (2, 2));
    }

    #[test]
    fn durable_tampered_snapshot_fails_closed_without_commit() {
        let store = TestStore::with_tampered_seed();
        let result = durable(&store, "job-1");
        assert_eq!(
            result,
            Err(DurableAttachError::Decision(
                SwarmPlanAttachmentError::InvalidSnapshot
            )),
            "tampered durable image must fail closed on reload"
        );
        // No decision was made and no commit attempted.
        assert_eq!(TestStore::counts(&store), (1, 0));
    }

    #[test]
    fn durable_perpetual_contention_terminates_bounded() {
        let store = TestStore::new();
        state(&store).always_contend = true;
        let result = durable(&store, "job-1");
        assert_eq!(
            result,
            Err(DurableAttachError::ContentionExhausted {
                attempts: MAX_DURABLE_ATTACH_ATTEMPTS
            }),
            "perpetual contention must terminate at the bound, never spin"
        );
        assert_eq!(TestStore::counts(&store), (8, 8));
        assert_eq!(TestStore::committed_len(&store), 0);
    }

    #[test]
    fn durable_identical_replay_is_idempotent() {
        let store = TestStore::new();
        let first = durable(&store, "job-1").expect("first bind commits");
        let second = durable(&store, "job-1").expect("identical replay commits");
        assert_eq!(first, second);
        assert_eq!(TestStore::committed_len(&store), 1);
    }

    #[test]
    fn durable_invalid_input_never_commits() {
        let store = TestStore::new();
        let result = attach_plan_once_durable(&store, "   ", PLAN, "job-1", FENCE);
        assert_eq!(
            result,
            Err(DurableAttachError::Decision(
                SwarmPlanAttachmentError::InvalidField("admission_digest")
            ))
        );
        assert_eq!(TestStore::counts(&store), (1, 0));
    }

    #[test]
    fn durable_load_failure_propagates_as_store_error() {
        let store = TestStore::new();
        state(&store).load_error = Some(TestStoreError("boom"));
        let result = durable(&store, "job-1");
        assert_eq!(
            result,
            Err(DurableAttachError::Store(TestStoreError("boom")))
        );
        assert_eq!(TestStore::counts(&store), (1, 0));
    }

    fn consumer() -> SwarmPlanAttachmentConsumer {
        SwarmPlanAttachmentConsumer::new(ADMISSION, PLAN, FENCE).expect("consumer vends")
    }

    #[test]
    fn consumer_handle_pins_identity_and_rejects_blanks() {
        let valid = consumer();
        assert_eq!(valid.admission_digest(), ADMISSION);
        assert_eq!(valid.plan_revision(), PLAN);
        assert_eq!(valid.fence_digest(), FENCE);
        assert_eq!(
            SwarmPlanAttachmentConsumer::new("   ", PLAN, FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("admission_digest"))
        );
        assert_eq!(
            SwarmPlanAttachmentConsumer::new(ADMISSION, "   ", FENCE),
            Err(SwarmPlanAttachmentError::InvalidField("plan_revision"))
        );
        assert_eq!(
            SwarmPlanAttachmentConsumer::new(ADMISSION, PLAN, "   "),
            Err(SwarmPlanAttachmentError::InvalidField("fence_digest"))
        );
    }

    #[test]
    fn ledger_port_independently_acquired_handles_converge_second_job_conflicts() {
        let ledger = SwarmPlanAttachmentLedger::new();
        // Independently vended handles carry the same pinned identity; the
        // caller supplies only the job handle, so no identity swap is possible.
        let first_handle = consumer();
        let second_handle = consumer();
        assert_eq!(first_handle, second_handle);
        let winner = SwarmPlanAttachmentConsumerPort::attach(&ledger, &first_handle, "job-1")
            .expect("first bind wins");
        assert_eq!(winner.job_handle(), "job-1");
        let replay = SwarmPlanAttachmentConsumerPort::attach(&ledger, &second_handle, "job-1")
            .expect("identical replay is idempotent");
        assert_eq!(replay, winner);
        match SwarmPlanAttachmentConsumerPort::attach(&ledger, &second_handle, "job-2") {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_port_blank_job_handle_fails_closed() {
        let ledger = SwarmPlanAttachmentLedger::new();
        let handle = consumer();
        assert_eq!(
            SwarmPlanAttachmentConsumerPort::attach(&ledger, &handle, "   "),
            Err(DurableAttachError::Decision(
                SwarmPlanAttachmentError::InvalidField("job_handle")
            ))
        );
        assert!(ledger.is_empty());
    }

    #[test]
    fn durable_port_independently_acquired_handles_converge_second_job_conflicts() {
        let store = TestStore::new();
        let port = SwarmPlanAttachmentDurablePort::new(&store);
        let first_handle = consumer();
        let second_handle = consumer();
        let winner = port
            .attach(&first_handle, "job-1")
            .expect("first bind commits");
        assert_eq!(winner.job_handle(), "job-1");
        let replay = port
            .attach(&second_handle, "job-1")
            .expect("identical replay commits");
        assert_eq!(replay, winner);
        match port.attach(&second_handle, "job-2") {
            Err(DurableAttachError::Decision(SwarmPlanAttachmentError::OwnershipConflict {
                existing,
            })) => assert_eq!(existing, winner),
            other => panic!("second job must conflict with the winner, got {other:?}"),
        }
        assert_eq!(TestStore::committed_len(&store), 1);
    }
}
