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
//! mints no receipts, and launches no processes. Callers persist the returned
//! binding through the canonical write path; restart recovery rebuilds the
//! owner from its snapshot via [`SwarmPlanAttachmentOwner::from_snapshot`].
//!
//! Atomicity is structural, not advisory: [`SwarmPlanAttachmentLedger`] holds
//! the owner behind one [`std::sync::Mutex`] and performs lookup plus insert
//! inside a single critical section, so two concurrent `attach_plan_once`
//! calls for the same plan key cannot both create a binding. The single-writer
//! [`SwarmPlanAttachmentOwner::attach_plan_once`] takes `&mut self` for the
//! same reason. There is no check-then-act split across lock boundaries.

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
}
