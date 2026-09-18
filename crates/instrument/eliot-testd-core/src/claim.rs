//! Deterministic operational claim and recovery helpers for the test daemon.
//!
//! These helpers are pure over durable [`TestJob`](super::TestJob) state: they
//! perform no database access, no filesystem access, and no OS process start.
//! The durable record loaded inside [`TestdStore`](super::TestdStore) methods
//! is the only authority. A caller-owned job value is never accepted as proof
//! of a claim; [`bind_claimed_process_start`](super::TestdStore::bind_claimed_process_start)
//! reloads the record by id before delegating here.
//!
//! Recovery never auto-reruns work: an expired running job reconciles to
//! `Unknown` execution so a later attempt requires a fresh claim, a fresh
//! lease, and a fresh permit binding.

use eliot_contracts::EpochId;
use eliot_instrument_api::ExecutionStatus;
use eliot_process::ProcessLifecycle;

use super::{JobState, Lease, TestJob, TestdError, lease_matches};

/// Stable identity tuple a presented process permit must carry to bind one
/// claimed job to a physical start.
///
/// The per-issuance invocation digest is intentionally not part of this
/// tuple: it covers the one-shot Kernel nonce and permit digest, so a fresh
/// permit issued for a retry attempt can never reproduce the digest stored at
/// submit time. Digest integrity of the presented request itself is enforced
/// separately by `ProcessRequest::validate` at the bind boundary, using the
/// shared native-process dispatch-validation semantics from #100.
#[derive(Clone, Copy, Debug)]
pub struct ClaimBindingExpectation<'a> {
    /// Operation identity the permit was issued for.
    pub operation_id: &'a str,
    /// Process-tree identity the permit was issued for.
    pub process_tree_id: &'a str,
    /// Execution generation the permit fence covers.
    pub generation: u64,
    /// Canonical authority epoch the permit fence carries.
    pub authority_epoch: &'a EpochId,
    /// Instrument invocation identity bound at submit time.
    pub invocation_id: &'a str,
    /// Issuer-selected external execution contour root.
    pub allowed_contour_root: &'a str,
    /// Source/worktree root used as the process working directory.
    pub source_root: &'a str,
    /// Dedicated external Cargo target/build root.
    pub target_root: &'a str,
    /// Cache root, required to equal the canonical target root.
    pub cache_root: &'a str,
}

/// Reconciliation decision for one fence-expired running job.
///
/// The execution projection is always [`ExecutionStatus::Unknown`]: only
/// `finish` with a validated receipt may leave the unknown state, so recovery
/// can never promote an ambiguous attempt to success or failure on its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiredRunningReconciliation {
    /// Durable execution projection to persist (`Unknown`).
    pub execution: ExecutionStatus,
    /// Machine-readable reason retained on the transition event.
    pub reason: &'static str,
}

/// Decides whether a durable job needs expiry reconciliation.
///
/// Returns `Some` only for a `Running` job whose fence no longer holds at
/// `now` (expired lease, or a running job with no fence at all, which is
/// ambiguous durable state). The optional process lifecycle is the
/// process-evidence check: terminal evidence still reconciles to `Unknown`
/// because only a validated finish receipt may resolve an attempt, and live
/// evidence still reconciles because the expired fence already revoked the
/// worker's authority to complete. Evidence only selects the reason string;
/// it never selects success, and a reconciled job never reruns without a
/// fresh claim, lease, and permit binding.
pub fn reconcile_expired_running(
    job: &TestJob,
    now: u64,
    evidence: Option<ProcessLifecycle>,
) -> Option<ExpiredRunningReconciliation> {
    if !matches!(job.state, JobState::Running) {
        return None;
    }
    let expired = match job.lease.as_ref() {
        Some(lease) => lease.expires_at_ms <= now,
        // A running job with no fence is ambiguous, not claimable: recover
        // explicitly rather than leaving the project head blocked forever.
        None => true,
    };
    if !expired {
        return None;
    }
    let reason = match evidence {
        None => "lease-expired-without-process-evidence",
        Some(lifecycle) if lifecycle.is_terminal() => {
            "lease-expired-terminal-process-evidence-requires-receipt"
        }
        Some(_) => "lease-expired-process-still-reported-active",
    };
    Some(ExpiredRunningReconciliation {
        execution: ExecutionStatus::Unknown,
        reason,
    })
}

/// Validates one claim binding against the durable record, fail-closed.
///
/// Rejects with [`TestdError::LeaseRejected`] when the job is not running
/// under exactly the supplied live fence (revoked, cancelled, expired, or
/// foreign owner/token/epoch), and with [`TestdError::InvalidBinding`] when
/// any element of the stable identity tuple disagrees with durable state.
/// The `job` argument must be the record loaded from the durable store; a
/// caller-owned job is never authority.
pub fn validate_claim_binding(
    job: &TestJob,
    lease: &Lease,
    now: u64,
    expected: &ClaimBindingExpectation<'_>,
) -> Result<(), TestdError> {
    if !lease_matches(job, lease, now) {
        return Err(TestdError::LeaseRejected(job.job_id.clone()));
    }
    let invocation_id = job.invocation.request.request_id.as_str();
    let stable = expected.operation_id == job.process.operation_id.as_str()
        && expected.process_tree_id == job.process.process_tree_id.as_str()
        && expected.generation == job.process.generation
        && expected
            .authority_epoch
            .is_same_authority(&job.process.authority_epoch)
        && expected.invocation_id == invocation_id
        && expected.allowed_contour_root == job.target_roots.allowed_contour_root.as_str()
        && expected.source_root == job.target_roots.source_root.as_str()
        && expected.target_root == job.target_roots.target_root.as_str()
        && expected.cache_root == job.target_roots.cache_root.as_str();
    if stable {
        Ok(())
    } else {
        Err(TestdError::InvalidBinding)
    }
}

// Exhaustive binding/recovery matrices (every identity field crossed with
// every lease state) are deferred as disproportionate for this slice; the
// three cases below pin the load-bearing behavior and the full matrix
// remains future work.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_epoch(sequence: u64) -> EpochId {
        use eliot_contracts::{EpochId, EpochLineageId};
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn lease_fixture() -> Lease {
        Lease {
            owner: "worker-a".to_owned(),
            token: "fence-a".to_owned(),
            epoch: 1,
            expires_at_ms: 200,
        }
    }

    fn job_fixture(state: JobState, lease: Option<Lease>) -> TestJob {
        let state_value = match state {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::RetryWait => "retry_wait",
            JobState::Succeeded => "succeeded",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
            JobState::Quarantined => "quarantined",
        };
        let lease_value = lease.map_or(json!(null), |lease| {
            json!({
                "owner": lease.owner,
                "token": lease.token,
                "epoch": lease.epoch,
                "expires_at_ms": lease.expires_at_ms,
            })
        });
        serde_json::from_value(json!({
            "job_id": "job-1",
            "project_id": "project-a",
            "project_sequence": 1,
            "invocation": {
                "request": {
                    "request_id": "operation-1",
                    "session_id": null,
                    "task_id": null,
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": {
                        "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
                        "resource_generation": 1,
                        "task_revision": null,
                        "policy_revision": null,
                        "integration_revision": null
                    },
                    "clock": {
                        "valid_time_ms": 1,
                        "known_time_ms": 1,
                        "transaction_sequence": null,
                        "monotonic_ns": 1
                    }
                },
                "instrument": "eliot.instrument.test",
                "kind": "TEST",
                "profile": "cargo-test",
                "target": "C:\\source",
                "arguments": [],
                "input_artifacts": [],
                "declared_scope": "workspace",
                "requested_at": {
                    "valid_time_ms": 1,
                    "known_time_ms": 1,
                    "transaction_sequence": null,
                    "monotonic_ns": 1
                }
            },
            "process": {
                "job_id": "job-1",
                "operation_id": "operation-1",
                "process_tree_id": "tree-1",
                "generation": 1,
                "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
                "invocation_digest": "digest"
            },
            "target_roots": {
                "allowed_contour_root": "C:\\contour",
                "source_root": "C:\\source",
                "target_root": "C:\\contour\\build",
                "cache_root": "C:\\contour\\build"
            },
            "priority": 0,
            "state": state_value,
            "attempts": 1,
            "not_before_ms": 0,
            "lease": lease_value,
            "execution": null,
            "verification": null,
            "receipt": null,
            "updated_at_ms": 0,
            "payload_digest": "digest"
        }))
        .expect("fixture job decodes")
    }

    fn expectation_fixture(job: &TestJob) -> ClaimBindingExpectation<'_> {
        ClaimBindingExpectation {
            operation_id: job.process.operation_id.as_str(),
            process_tree_id: job.process.process_tree_id.as_str(),
            generation: job.process.generation,
            authority_epoch: &job.process.authority_epoch,
            invocation_id: job.invocation.request.request_id.as_str(),
            allowed_contour_root: job.target_roots.allowed_contour_root.as_str(),
            source_root: job.target_roots.source_root.as_str(),
            target_root: job.target_roots.target_root.as_str(),
            cache_root: job.target_roots.cache_root.as_str(),
        }
    }

    #[test]
    fn expired_running_reconciles_to_unknown_never_succeeded() {
        let job = job_fixture(JobState::Running, Some(lease_fixture()));
        for evidence in [
            None,
            Some(ProcessLifecycle::Running),
            Some(ProcessLifecycle::UnknownOutcome),
            Some(ProcessLifecycle::Exited),
        ] {
            let decision = reconcile_expired_running(&job, 200, evidence)
                .expect("expired running must reconcile");
            assert_eq!(decision.execution, ExecutionStatus::Unknown);
            assert_ne!(
                decision.execution,
                ExecutionStatus::Succeeded,
                "recovery must never promote an ambiguous attempt"
            );
        }
        let live = job_fixture(JobState::Running, Some(lease_fixture()));
        assert!(reconcile_expired_running(&live, 100, None).is_none());
        let queued = job_fixture(JobState::Queued, None);
        assert!(reconcile_expired_running(&queued, 200, None).is_none());
    }

    #[test]
    fn foreign_or_stale_claim_binding_is_rejected() {
        let lease = lease_fixture();
        let job = job_fixture(JobState::Running, Some(lease.clone()));
        let expected = expectation_fixture(&job);
        assert!(validate_claim_binding(&job, &lease, 100, &expected).is_ok());

        let mut foreign = lease.clone();
        foreign.owner = "worker-b".to_owned();
        assert!(matches!(
            validate_claim_binding(&job, &foreign, 100, &expected),
            Err(TestdError::LeaseRejected(_))
        ));

        let mut stale = lease.clone();
        stale.token = "fence-stale".to_owned();
        assert!(matches!(
            validate_claim_binding(&job, &stale, 100, &expected),
            Err(TestdError::LeaseRejected(_))
        ));

        assert!(
            matches!(
                validate_claim_binding(&job, &lease, 200, &expected),
                Err(TestdError::LeaseRejected(_))
            ),
            "an expired fence must not bind"
        );

        let cancelled = job_fixture(JobState::Cancelled, None);
        assert!(
            matches!(
                validate_claim_binding(&cancelled, &lease, 100, &expected),
                Err(TestdError::LeaseRejected(_))
            ),
            "a cancelled job must not bind"
        );

        let expected_foreign_operation = ClaimBindingExpectation {
            operation_id: "operation-foreign",
            ..expected
        };
        assert!(matches!(
            validate_claim_binding(&job, &lease, 100, &expected_foreign_operation),
            Err(TestdError::InvalidBinding)
        ));
    }

    #[test]
    fn bind_claimed_process_start_requires_exact_durable_binding() {
        use crate::{
            KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider,
            KernelProcessAdmissionRequest, ProcessAdmissionPermit, RetryPolicy, TargetRoots,
            TestdStore, issue_process_admission,
        };
        use eliot_process::{
            ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
            EnvironmentProjection, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
            OperationId, PermitIssuance, ProcessIntent, ProcessRequest, ProcessTreeId,
            ResourceLimits, SessionId,
        };
        use std::collections::BTreeMap;
        use std::sync::Mutex;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct FixtureProvider {
            process: Mutex<Option<ProcessRequest>>,
            contour_root: String,
        }

        impl KernelProcessAdmissionProvider for FixtureProvider {
            fn admit(
                &self,
                _request: &KernelProcessAdmissionRequest,
            ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
                let process = self
                    .process
                    .lock()
                    .expect("fixture provider lock")
                    .take()
                    .expect("fixture process is available once");
                Ok(KernelProcessAdmissionEvidence {
                    process,
                    contour_root: self.contour_root.clone(),
                    grant_id: "bind-grant".to_owned(),
                })
            }
        }

        fn invocation_fixture(operation_id: &str) -> eliot_instrument_api::InstrumentInvocation {
            serde_json::from_value(json!({
                "request": {
                    "request_id": operation_id,
                    "session_id": null,
                    "task_id": null,
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": {
                        "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
                        "resource_generation": 1,
                        "task_revision": null,
                        "policy_revision": null,
                        "integration_revision": null
                    },
                    "clock": {
                        "valid_time_ms": 1,
                        "known_time_ms": 1,
                        "transaction_sequence": null,
                        "monotonic_ns": 1
                    }
                },
                "instrument": "eliot.instrument.test",
                "kind": "TEST",
                "profile": "cargo-test",
                "target": "C:\\source",
                "arguments": [],
                "input_artifacts": [],
                "declared_scope": "workspace",
                "requested_at": {
                    "valid_time_ms": 1,
                    "known_time_ms": 1,
                    "transaction_sequence": null,
                    "monotonic_ns": 1
                }
            }))
            .expect("fixture invocation")
        }

        #[allow(clippy::too_many_arguments)]
        fn process_fixture(
            job_id: &str,
            operation_id: &str,
            source_root: &str,
            target_root: &str,
            authority: &mut DispatchPermitAuthority,
        ) -> ProcessRequest {
            let generation = Generation::new(1).expect("fixture generation");
            let intent = ProcessIntent::new(
                OperationId::new(operation_id).expect("fixture operation"),
                ProcessTreeId::new(format!("tree-{job_id}")).expect("fixture tree"),
                JobId::new(job_id).expect("fixture job"),
                ImageId::new("image-1").expect("fixture image"),
                SessionId::new("session-1").expect("fixture session"),
                generation,
                "C:\\tools\\worker.exe",
                "c".repeat(64),
                vec!["--check".to_owned()],
                source_root,
                EnvironmentProjection::new(
                    BTreeMap::from([
                        ("CARGO_TARGET_DIR".to_owned(), target_root.to_owned()),
                        ("CARGO_HOME".to_owned(), target_root.to_owned()),
                    ]),
                    Vec::new(),
                    EnvironmentInheritance::None,
                )
                .expect("fixture environment"),
                ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
                    .expect("fixture limits"),
            )
            .expect("fixture process intent");
            let permit = authority
                .issue(
                    &intent,
                    PermitIssuance::new(
                        ActionLeaseRef::new(format!("lease-{job_id}-{operation_id}"))
                            .expect("fixture lease"),
                        FencingToken::new(
                            test_epoch(7),
                            generation,
                            format!("fence-{job_id}-{operation_id}"),
                        )
                        .expect("fixture fence"),
                        BTreeMap::from([
                            ("authority".to_owned(), "a".repeat(64)),
                            ("state".to_owned(), "b".repeat(64)),
                        ]),
                        1,
                        2,
                        format!("nonce-{job_id}-{operation_id}"),
                    )
                    .expect("fixture issuance"),
                )
                .expect("fixture permit");
            ProcessRequest::new(intent, permit).expect("fixture process request")
        }

        fn authority_fixture() -> DispatchPermitAuthority {
            DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("authority-1").expect("fixture authority"),
                KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("fixture dispatch key"),
            )
        }

        fn admit_fixture(
            job_id: &str,
            operation_id: &str,
            roots: &TargetRoots,
        ) -> ProcessAdmissionPermit {
            let invocation = invocation_fixture(operation_id);
            let process = process_fixture(
                job_id,
                operation_id,
                &roots.source_root,
                &roots.target_root,
                &mut authority_fixture(),
            );
            let provider = FixtureProvider {
                process: Mutex::new(Some(process)),
                contour_root: roots.allowed_contour_root.clone(),
            };
            let request = KernelProcessAdmissionRequest {
                job_id: job_id.to_owned(),
                project_id: "project-a".to_owned(),
                invocation,
                source_root: roots.source_root.clone(),
                target_root: roots.target_root.clone(),
                cache_root: roots.cache_root.clone(),
            };
            issue_process_admission(&provider, &request).expect("fixture admission")
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("eliot-testd-bind-{nonce}.redb"));
        let roots_base = std::env::temp_dir().join(format!("eliot-testd-bind-{nonce}-roots"));
        let contour = roots_base.join("contour");
        let source = roots_base.join("source");
        let target = contour.join("build");
        std::fs::create_dir_all(&target).expect("create contour target");
        std::fs::create_dir_all(&source).expect("create source root");
        let roots = TargetRoots::new(
            contour.to_string_lossy(),
            source.to_string_lossy(),
            target.to_string_lossy(),
            target.to_string_lossy(),
        )
        .expect("valid fixture roots");

        let store = TestdStore::open(&db_path, RetryPolicy::default()).expect("open testd store");
        let operation_id = "operation-job-bind";
        store
            .submit(
                "job-bind",
                "project-a",
                invocation_fixture(operation_id),
                admit_fixture("job-bind", operation_id, &roots),
                roots.clone(),
                0,
                1,
            )
            .expect("submit fixture job");
        let claimed = store
            .claim_next("worker-a", 10, 1_000)
            .expect("claim fixture job")
            .expect("job is claimable");
        let lease = claimed.lease.clone().expect("claim assigns a fence");

        let bound = store
            .bind_claimed_process_start(
                "job-bind",
                &lease,
                20,
                admit_fixture("job-bind", operation_id, &roots),
            )
            .expect("exact binding must return the consuming request");
        assert_eq!(bound.operation_id().as_str(), operation_id);

        let foreign = store.bind_claimed_process_start(
            "job-bind",
            &lease,
            20,
            admit_fixture("job-bind", "operation-foreign", &roots),
        );
        assert!(
            matches!(foreign, Err(TestdError::InvalidBinding)),
            "a foreign operation must not bind"
        );

        let expired = store.bind_claimed_process_start(
            "job-bind",
            &lease,
            5_000,
            admit_fixture("job-bind", operation_id, &roots),
        );
        assert!(
            matches!(expired, Err(TestdError::LeaseRejected(_))),
            "an expired fence must not bind"
        );

        drop(store);
        std::fs::remove_file(&db_path).expect("remove test database");
        std::fs::remove_dir_all(&roots_base).expect("remove fixture roots");
    }
}
