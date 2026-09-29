//! Reactive runtime composition: attach-time restore of durable reactive state.
//!
//! After attach the live [`BridgeRunner`](super::BridgeRunner) holds an empty
//! ledger and registry. This module restores exactly what canonical Store
//! projections hold for the live attach session and fence: the injection
//! ledger bytes via [`BridgeRunner::restore_reactive_ledger`] and caller
//! nominated snapshots via [`BridgeRunner::publish_canonical_resource`].
//! Afterwards the existing bridge machinery owns delivery (host-hook and
//! next-response drains issue receipts).
//!
//! Authority boundaries (the composition invents nothing):
//!
//! ```text
//! bridge owns:  live attach session + fence (binding echoed from attach,
//!               never caller text), ledger mutation, registry, receipts.
//! kernel owns:  session/fence authority, Store reads (same-fence ExactFence
//!               projections, explicit absence), reply echoes.
//! store owns:   durable ledger rows + immutable snapshots behind closed
//!               named reads.
//! caller owns:  NOTHING here: URIs are bounded candidates validated at
//!               publish; a session/fence mismatch with the live binding
//!               refuses before any wire traffic.
//! ```
//!
//! Absence publishes nothing: no durable ledger means an empty restore (current
//! behavior, not an error); a URI the owner does not serve yields no report
//! entry and publishes nothing. Store errors fail the whole call with the
//! runner untouched: no partial restore ever lands.

use eliot_agent_bridge_core::{AttachBinding, BridgeError, ResourceUri};
use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_mcp::{KernelHostRequestPort, PortFailure};
use eliot_protocol::{MAX_RESTORE_URIS, ReactiveLedgerMutationRequest, ReactiveRestoreQuery};

use super::BridgeRunner;

/// Outcome of the ledger leg of one restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerRestoreOutcome {
    /// Durable bytes restored into the live ledger.
    Restored,
    /// No durable ledger exists for the session; the runner stays empty.
    Absent,
}

/// Outcome of one snapshot leg of one restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotRestoreOutcome {
    /// Snapshot published into the live registry.
    Published,
    /// URI not served; nothing was published for it.
    Unserved,
    /// Publish refused the served bytes; nothing was published for it.
    Rejected {
        /// Bounded refusal reason.
        reason: String,
    },
}

/// One completed attach-time restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveRestoreReport {
    /// Ledger leg outcome.
    pub ledger: LedgerRestoreOutcome,
    /// Per-URI snapshot outcomes in request order.
    pub snapshots: Vec<(String, SnapshotRestoreOutcome)>,
    /// Highest owner revision observed across served projections.
    pub revision: u64,
}

/// Render the live attach binding fence as the canonical [`StateFence`] the
/// Store projections are keyed by.
///
/// Mechanical field echo (epoch clone + generation value); revisions stay
/// `None` exactly like the frame fence the pipe already carries. Authority
/// stays with the binding and the serving owners; this echo mints none.
fn live_state_fence(binding: &AttachBinding) -> Result<StateFence, BridgeError> {
    let generation =
        ResourceGeneration::new(binding.state_fence().generation().get()).map_err(|_| {
            BridgeError::InvalidContract {
                field: "attach.state_fence.generation",
                reason: "generation must be non-zero",
            }
        })?;
    Ok(StateFence::new(
        binding.state_fence().authority_epoch().clone(),
        generation,
    ))
}

/// Restore durable reactive state for the live attach session and fence.
///
/// Reads the live session, scope, task, and fence from the runner's own
/// attach binding (never caller text), serves one authenticated restore
/// round-trip through the Kernel port, verifies the reply echoes the exact
/// live binding, then feeds the existing runner calls: ledger bytes into
/// `restore_reactive_ledger`, each served snapshot into
/// `publish_canonical_resource` (canonical grammar + digest binding enforced
/// there). `uris` is the bounded caller-nominated snapshot set; attach
/// passes an empty set. The live binding's own canonical session
/// attention/mailbox, scope state, and task packet addresses
/// (`eliot://session/<live-session>/attention|mailbox`,
/// `eliot://scope/<live-scope>/state`,
/// `eliot://task/<live-task>/packet/<live-revision>`, all derived from the
/// authenticated binding, never caller text) are always requested alongside
/// the caller set so owner-held snapshots flow through the existing publish
/// path when served; a URI the owner does not serve yields no report entry
/// and publishes nothing — never an invented snapshot.
///
/// Fence or session mismatch with the live binding refuses before any wire
/// traffic. A refused reply echo discards the bytes. Store errors leave the
/// runner untouched.
pub fn restore_reactive_runtime(
    runner: &mut BridgeRunner,
    port: &mut dyn KernelHostRequestPort,
    uris: &[String],
) -> Result<ReactiveRestoreReport, BridgeError> {
    let view = runner.attach_view().ok_or(BridgeError::NotAttached)?;
    let live_session = view.binding().session_id().as_str().to_owned();
    let live_scope = view.binding().task_binding().work_scope_id().to_owned();
    let live_task = view.binding().task_binding().task_id().as_str().to_owned();
    let live_task_revision = view.binding().task_binding().task_revision().to_owned();
    let live_fence = live_state_fence(view.binding())?;
    // Live-binding self addresses: the bridge requests only its own session's
    // canonical attention/mailbox URIs, its own scope state, and its own task
    // packet at the authenticated revision (all from the attach binding,
    // validated against the I7.18 grammar here). Remaining families still
    // arrive only via the caller-nominated set; served bytes still flow
    // through `publish_canonical_resource` with digest binding, while a URI
    // the owner does not serve yields no report entry and publishes nothing.
    // No content is invented: the URIs are requests, the bytes come from the
    // owner or not at all.
    let mut requested: Vec<String> = Vec::with_capacity(uris.len().saturating_add(4));
    for candidate in [
        format!("eliot://session/{live_session}/attention"),
        format!("eliot://session/{live_session}/mailbox"),
        format!("eliot://scope/{live_scope}/state"),
        format!("eliot://task/{live_task}/packet/{live_task_revision}"),
    ] {
        if ResourceUri::parse(candidate.clone()).is_ok() && !requested.contains(&candidate) {
            requested.push(candidate);
        }
    }
    for nominated in uris {
        if !requested.contains(nominated) {
            requested.push(nominated.clone());
        }
    }
    if requested.len() > MAX_RESTORE_URIS {
        return Err(BridgeError::InvalidContract {
            field: "restore.uris",
            reason: "exceeds the bounded URI fan-out",
        });
    }
    let query = ReactiveRestoreQuery {
        session_id: live_session.clone(),
        state_fence: live_fence.clone(),
        uris: requested,
    };
    query
        .validate()
        .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
    let reply = port
        .restore_reactive_state(&query)
        .map_err(|error| match error {
            PortFailure::FenceMismatch => BridgeError::StaleAuthority,
            PortFailure::TransportBindingRejected { reason } => {
                BridgeError::ProviderContract(reason)
            }
            PortFailure::Unsupported { reason, .. } => BridgeError::ProviderContract(reason),
            PortFailure::PlanGap { reason, .. } => BridgeError::ProviderContract(reason),
            PortFailure::IdempotencyConflict => BridgeError::InvalidTransition(
                "restore idempotency identity is bound to different request bytes",
            ),
            PortFailure::LegacyCorrelationUnresolved => BridgeError::LegacyCorrelationUnresolved,
            PortFailure::DeadlineExceeded => {
                BridgeError::ProviderContract("restore deadline exceeded".to_owned())
            }
            PortFailure::Cancelled => BridgeError::ProviderContract("restore cancelled".to_owned()),
            PortFailure::AgentResponse { failure } => BridgeError::AgentHostRequestFailure(failure),
        })?;
    reply
        .validate()
        .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
    // Authority binding: served bytes are accepted only for the exact live
    // session and fence that was queried. Anything else is discarded.
    if reply.session_id != live_session {
        return Err(BridgeError::InvalidContract {
            field: "restore_reply.session_id",
            reason: "served session does not match the live attach session",
        });
    }
    if reply.state_fence != live_fence {
        return Err(BridgeError::StaleAuthority);
    }
    let ledger = match &reply.ledger_json {
        Some(json) => {
            runner.restore_reactive_ledger_at_revision(json.as_bytes(), reply.ledger_revision)?;
            LedgerRestoreOutcome::Restored
        }
        None => LedgerRestoreOutcome::Absent,
    };
    let mut snapshots = Vec::with_capacity(reply.snapshots.len());
    for snapshot in &reply.snapshots {
        let outcome = match ResourceUri::parse(snapshot.uri.clone()) {
            Ok(uri) => match runner.publish_canonical_resource(&uri, snapshot.content.clone()) {
                Ok(_) => SnapshotRestoreOutcome::Published,
                Err(error) => SnapshotRestoreOutcome::Rejected {
                    reason: error.to_string(),
                },
            },
            Err(error) => SnapshotRestoreOutcome::Rejected {
                reason: error.to_string(),
            },
        };
        // A refused snapshot must never poison the ledger restore that
        // already landed: record per-URI, keep going.
        snapshots.push((snapshot.uri.clone(), outcome));
    }
    Ok(ReactiveRestoreReport {
        ledger,
        snapshots,
        revision: reply.revision,
    })
}

/// Commits one mutated ledger candidate before installing it in the live
/// runner. Failed, stale, or uncertain Store outcomes leave the runner's
/// current ledger and revision untouched.
pub fn commit_reactive_ledger_candidate(
    runner: &mut BridgeRunner,
    port: &mut dyn KernelHostRequestPort,
    candidate: super::ReactiveInjectionLedger,
) -> Result<u64, BridgeError> {
    let view = runner.attach_view().ok_or(BridgeError::NotAttached)?;
    let session_id = view.binding().session_id().as_str().to_owned();
    let state_fence = live_state_fence(view.binding())?;
    let expected_revision = runner.reactive_ledger_revision();
    let candidate_bytes = candidate
        .to_json_bytes()
        .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
    let ledger_json = String::from_utf8(candidate_bytes).map_err(|_| {
        BridgeError::ProviderContract("reactive ledger candidate was not UTF-8".to_owned())
    })?;
    if runner.reactive_ledger_snapshot()? == ledger_json.as_bytes() {
        return Ok(expected_revision);
    }
    let request = ReactiveLedgerMutationRequest {
        session_id: session_id.clone(),
        state_fence: state_fence.clone(),
        expected_revision,
        ledger_json: ledger_json.clone(),
    };
    request
        .validate()
        .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
    let reply = port
        .commit_reactive_ledger(&request)
        .map_err(map_reactive_mutation_failure)?;
    reply
        .receipt
        .validate()
        .map_err(|error| BridgeError::ProviderContract(error.to_string()))?;
    let expected_after = expected_revision
        .checked_add(1)
        .ok_or(BridgeError::StaleAuthority)?;
    if reply.session_id != session_id
        || reply.state_fence != state_fence
        || reply.ledger_revision != expected_after
        || reply.ledger_json != ledger_json
        || reply.receipt.core.request.metadata.session_id.as_ref()
            != Some(view.binding().session_id())
        || reply.receipt.core.request.state_fence != state_fence
        || reply.receipt.core.operation.state_fence != state_fence
    {
        return Err(BridgeError::ProviderContract(
            "reactive ledger commit did not return the exact Store receipt and candidate"
                .to_owned(),
        ));
    }
    runner.install_committed_reactive_ledger_candidate(
        candidate,
        expected_revision,
        reply.ledger_revision,
    )?;
    Ok(reply.ledger_revision)
}

fn map_reactive_mutation_failure(error: PortFailure) -> BridgeError {
    match error {
        PortFailure::FenceMismatch => BridgeError::StaleAuthority,
        PortFailure::TransportBindingRejected { reason } => BridgeError::ProviderContract(reason),
        PortFailure::Unsupported { reason, .. } | PortFailure::PlanGap { reason, .. } => {
            BridgeError::ProviderContract(reason)
        }
        PortFailure::IdempotencyConflict => BridgeError::InvalidTransition(
            "reactive ledger idempotency identity is bound to different candidate bytes",
        ),
        PortFailure::LegacyCorrelationUnresolved => BridgeError::LegacyCorrelationUnresolved,
        PortFailure::DeadlineExceeded => {
            BridgeError::ProviderContract("reactive ledger commit deadline exceeded".to_owned())
        }
        PortFailure::Cancelled => {
            BridgeError::ProviderContract("reactive ledger commit cancelled".to_owned())
        }
        PortFailure::AgentResponse { failure } => BridgeError::AgentHostRequestFailure(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_agent_bridge_core::{
        ActivationPortOutcome, ActivationPortResult, AttachRequest, DemandId, FencingToken,
        Generation, HostActivationPort, PrincipalId, ProviderFailure, ProviderReadiness, SessionId,
        TaskId, WorkUnitId,
    };
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_mcp::{
        HostCancellationPortOutcome, HostCancellationRequest, HostInvocationPortOutcome,
        HostInvocationRequest,
    };
    use eliot_protocol::{ReactiveRestoreReply, RestoredSnapshot};
    use std::num::NonZeroU64;

    use super::super::{
        AdmissionBasis, ConnectionId, CueOrigin, FiringEvidence, NormalizedCue, Profile,
        ReactiveInjectionLedger, RiskTier, Severity, UseOutcome,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_SESSION: &str = "session-restore-1";
    const TEST_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct StaticActivation {
        result: ActivationPortResult,
    }

    impl HostActivationPort for StaticActivation {
        fn activate(
            &mut self,
            _request: &AttachRequest,
        ) -> Result<ActivationPortOutcome, ProviderFailure> {
            Ok(ActivationPortOutcome::Authenticated(self.result.clone()))
        }
    }

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(3),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn attached_runner() -> BridgeRunner {
        let generation = Generation::new(7).expect("generation");
        let fence =
            FencingToken::new(test_epoch(3), generation, "fence-restore-7").expect("fence token");
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-restore-1").expect("principal"),
            SessionId::new(TEST_SESSION).expect("session"),
            generation,
            fence,
            TaskId::new("task-restore-1").expect("task"),
            WorkUnitId::new("work-unit-restore-1").expect("work unit"),
            "scope-restore-1",
            "task-revision-1",
            "plan-restore-1",
            "plan-revision-1",
        )
        .expect("activation result");
        let mut runner = BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticActivation { result })),
            None,
        )
        .expect("runner composes");
        runner
            .attach(AttachRequest::managed(
                DemandId::new("demand-restore-1").expect("demand"),
                ConnectionId::new("conn-restore-1").expect("connection"),
            ))
            .expect("managed attach admits");
        runner
    }

    fn detached_runner() -> BridgeRunner {
        BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            None,
            None,
        )
        .expect("runner composes")
    }

    /// Real ledger bytes: one admitted critical item plus one delivered
    /// normal, serialized through the real ledger codec.
    fn ledger_bytes(session: &str) -> Vec<u8> {
        fn cue(revision: &str) -> NormalizedCue {
            NormalizedCue {
                cue_id: "cue-restore-1".to_owned(),
                kind: CueOrigin::ToolObservation,
                source: "tool-surface".to_owned(),
                source_revision: revision.to_owned(),
                cue_digest: TEST_DIGEST.to_owned(),
            }
        }
        fn firing() -> FiringEvidence {
            FiringEvidence {
                rule_id: "exact-rule-restore-7".to_owned(),
                cue_id: "cue-restore-1".to_owned(),
                cue_digest: TEST_DIGEST.to_owned(),
            }
        }
        fn admission(severity: Severity) -> AdmissionBasis {
            AdmissionBasis {
                scope_id: "scope-restore-1".to_owned(),
                status: "active".to_owned(),
                risk: RiskTier::Low,
                governance_profile_rev: "gov-restore-3".to_owned(),
                fence_epoch: "epoch-restore-1".to_owned(),
                fence_generation: 2,
                admitted_severity: severity,
            }
        }
        let mut ledger = ReactiveInjectionLedger::new();
        ledger
            .admit(
                session,
                cue("rev-1"),
                Some(firing()),
                vec![],
                admission(Severity::Critical),
            )
            .expect("critical admits");
        ledger.to_json_bytes().expect("ledger serializes").to_vec()
    }

    /// Scripted pipe: returns owner-shaped bytes without a Kernel. The
    /// transport boundary is scripted; every evaluation step below it
    /// (session/fence gates, restore, publish, drains) is real.
    struct ScriptedPort {
        reply: Result<ReactiveRestoreReply, PortFailure>,
        calls: usize,
    }

    impl KernelHostRequestPort for ScriptedPort {
        fn invoke(
            &mut self,
            _request: &HostInvocationRequest,
        ) -> Result<HostInvocationPortOutcome, PortFailure> {
            Err(PortFailure::Unsupported {
                capability: "restore-test".to_owned(),
                reason: "restore tests never invoke tools".to_owned(),
            })
        }

        fn cancel(
            &mut self,
            _request: &HostCancellationRequest,
        ) -> Result<HostCancellationPortOutcome, PortFailure> {
            Err(PortFailure::Unsupported {
                capability: "restore-test".to_owned(),
                reason: "restore tests never cancel".to_owned(),
            })
        }

        fn restore_reactive_state(
            &mut self,
            _query: &ReactiveRestoreQuery,
        ) -> Result<ReactiveRestoreReply, PortFailure> {
            self.calls += 1;
            self.reply.clone()
        }
    }

    fn matching_reply() -> ReactiveRestoreReply {
        ReactiveRestoreReply {
            session_id: TEST_SESSION.to_owned(),
            state_fence: test_fence(),
            ledger_json: Some(
                String::from_utf8(ledger_bytes(TEST_SESSION)).expect("ledger is UTF-8"),
            ),
            ledger_revision: 1,
            snapshots: vec![RestoredSnapshot {
                uri: "eliot://evidence/source-9".to_owned(),
                content: b"snapshot-bytes-9".to_vec(),
            }],
            revision: 4,
        }
    }

    fn live_ids(runner: &BridgeRunner) -> Vec<String> {
        runner
            .reactive_attention()
            .iter()
            .map(|item| item.item_id.clone())
            .collect()
    }

    #[test]
    fn detached_runner_refuses_before_any_wire_traffic() {
        let mut runner = detached_runner();
        let mut port = ScriptedPort {
            reply: Err(PortFailure::Unsupported {
                capability: "reactive-restore".to_owned(),
                reason: "unreachable".to_owned(),
            }),
            calls: 0,
        };
        assert!(matches!(
            restore_reactive_runtime(&mut runner, &mut port, &[]),
            Err(BridgeError::NotAttached)
        ));
        assert_eq!(port.calls, 0, "no wire traffic while detached");
    }

    #[test]
    fn authenticated_read_restores_ledger_and_snapshot_then_drains() {
        let mut runner = attached_runner();
        let mut port = ScriptedPort {
            reply: Ok(matching_reply()),
            calls: 0,
        };
        let report = restore_reactive_runtime(&mut runner, &mut port, &[]).expect("restore");
        assert_eq!(port.calls, 1);
        assert_eq!(report.ledger, LedgerRestoreOutcome::Restored);
        assert_eq!(report.revision, 4);
        // The restored critical item is live in the runner ledger...
        assert_eq!(live_ids(&runner).len(), 1);
        // ...and the served snapshot reached the live registry...
        assert_eq!(runner.resource_registry_len(), 1);
        // ...so the existing drain machinery delivers it.
        let receipts = runner
            .deliver_reactive_pending_via_hook("hook-restore-1")
            .expect("drain delivers restored items");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].use_status, UseOutcome::Unknown);
    }

    #[test]
    fn foreign_session_bytes_are_discarded_with_runner_untouched() {
        let mut runner = attached_runner();
        let mut mismatch = matching_reply();
        mismatch.session_id = "session-foreign-9".to_owned();
        let mut port = ScriptedPort {
            reply: Ok(mismatch),
            calls: 0,
        };
        assert!(matches!(
            restore_reactive_runtime(&mut runner, &mut port, &[]),
            Err(BridgeError::InvalidContract { .. })
        ));
        assert_eq!(port.calls, 1, "wire happened; bytes discarded after");
        assert!(live_ids(&runner).is_empty());
        assert_eq!(runner.resource_registry_len(), 0);
        assert_eq!(runner.reactive_pending_count(), 0);
    }

    #[test]
    fn foreign_fence_refuses_with_runner_untouched() {
        let mut runner = attached_runner();
        let mut rotated = matching_reply();
        rotated.state_fence = StateFence::new(
            test_epoch(9),
            ResourceGeneration::new(7).expect("generation"),
        );
        let mut port = ScriptedPort {
            reply: Ok(rotated),
            calls: 0,
        };
        assert!(matches!(
            restore_reactive_runtime(&mut runner, &mut port, &[]),
            Err(BridgeError::StaleAuthority)
        ));
        assert!(live_ids(&runner).is_empty());
        assert_eq!(runner.resource_registry_len(), 0);
    }

    #[test]
    fn transport_refusal_leaves_runner_untouched() {
        let mut runner = attached_runner();
        let mut port = ScriptedPort {
            reply: Err(PortFailure::TransportBindingRejected {
                reason: "simulated pipe refusal".to_owned(),
            }),
            calls: 0,
        };
        assert!(restore_reactive_runtime(&mut runner, &mut port, &[]).is_err());
        assert_eq!(port.calls, 1);
        assert!(live_ids(&runner).is_empty());
        assert_eq!(runner.resource_registry_len(), 0);
    }

    #[test]
    fn absent_ledger_restores_empty_without_error() {
        let mut runner = attached_runner();
        let mut empty = matching_reply();
        empty.ledger_json = None;
        empty.snapshots = Vec::new();
        let mut port = ScriptedPort {
            reply: Ok(empty),
            calls: 0,
        };
        let report =
            restore_reactive_runtime(&mut runner, &mut port, &[]).expect("absence restores");
        assert_eq!(report.ledger, LedgerRestoreOutcome::Absent);
        assert!(report.snapshots.is_empty());
        assert!(live_ids(&runner).is_empty());
    }

    #[test]
    fn unserved_snapshot_is_recorded_without_poisoning_the_ledger() {
        let mut runner = attached_runner();
        let mut partial = matching_reply();
        partial.snapshots.push(RestoredSnapshot {
            uri: "not-a-canonical-uri".to_owned(),
            content: b"junk".to_vec(),
        });
        let mut port = ScriptedPort {
            reply: Ok(partial),
            calls: 0,
        };
        let report = restore_reactive_runtime(&mut runner, &mut port, &[]).expect("restore");
        assert_eq!(report.ledger, LedgerRestoreOutcome::Restored);
        assert_eq!(report.snapshots.len(), 2);
        assert_eq!(report.snapshots[0].1, SnapshotRestoreOutcome::Published);
        assert!(matches!(
            report.snapshots[1].1,
            SnapshotRestoreOutcome::Rejected { .. }
        ));
        assert_eq!(live_ids(&runner).len(), 1, "ledger restore stands");
        assert_eq!(
            runner.resource_registry_len(),
            1,
            "only the valid snapshot landed"
        );
    }
}
