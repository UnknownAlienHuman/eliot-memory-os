//! Observer memory-handle to ledger-item join (I7.19 use/outcome step, C2).
//!
//! The observe path mints opaque `memory_handle` strings; the bridge ledger
//! addresses items by exact `item_id` (`reactive-item-{seq}`, ledger-scoped)
//! with no defined relation between the two. This module is the bridge-owned
//! half of the exact join, option (a) of the C2 owner contract: the observe
//! owner embeds the bridge identity at delivery time in the canonical form
//!
//! ```text
//! reactive-item-{seq}@{session}
//! ```
//!
//! and the bridge resolves it back by exact ledger lookup. Anything else —
//! wrong shape, unknown item, session mismatch — fails closed and records
//! nothing. The owner-side map alternative (option (b)) needs no bridge
//! change. Use updates themselves still flow through the existing
//! [`ReactiveInjectionLedger::record_use`] gate (delivered items only;
//! `Unknown` rejected as the absence of an update), addressed here by
//! resolved identity so the owning observer can report without a live
//! attach.

use super::{ReactiveInjectionError, UseOutcome};
use super::BridgeRunner;
use eliot_agent_bridge_core::BridgeError;

/// One observer handle resolved to its exact ledger identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMemoryHandle {
    /// Ledger identity (`reactive-item-{seq}`).
    pub item_id: String,
    /// Ledger session the item was admitted under.
    pub session_id: String,
}

/// Parses one canonical observer memory handle.
///
/// The handle must hold exactly one `@`: the left part must be the exact
/// ledger identity shape `reactive-item-{seq}` with a non-empty ASCII-digit
/// sequence, and the right part a non-blank session without `@` or control
/// characters. Existence and session agreement are NOT checked here — only
/// shape. See [`BridgeRunner::record_reactive_use_by_handle`].
pub fn parse_memory_handle(handle: &str) -> Result<ResolvedMemoryHandle, ReactiveInjectionError> {
    const ITEM_PREFIX: &str = "reactive-item-";
    let invalid = |reason: &'static str| ReactiveInjectionError::InvalidField {
        field: "memory_handle",
        reason,
    };
    if handle.chars().any(char::is_control) {
        return Err(invalid("must not contain control characters"));
    }
    let (item_part, session_part) = handle
        .split_once('@')
        .ok_or_else(|| invalid("must hold exactly one session separator"))?;
    if session_part.contains('@') {
        return Err(invalid("must hold exactly one session separator"));
    }
    let sequence = item_part
        .strip_prefix(ITEM_PREFIX)
        .ok_or_else(|| invalid("must name a ledger item identity"))?;
    if sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("must name a ledger item identity"));
    }
    if session_part.trim().is_empty() {
        return Err(invalid("must name a non-blank session"));
    }
    Ok(ResolvedMemoryHandle {
        item_id: item_part.to_owned(),
        session_id: session_part.to_owned(),
    })
}

impl BridgeRunner {
    /// Records an observer use/influence/outcome update addressed by memory
    /// handle (C2 join, option (a)).
    ///
    /// Parses the canonical `reactive-item-{seq}@{session}` handle, verifies
    /// the item exists in the ledger AND its ledger session equals the
    /// handle session, then records through the existing use gate. Any
    /// mismatch fails closed with nothing recorded. Needs no live attach:
    /// observation is addressed by ledger identity, like
    /// [`BridgeRunner::record_reactive_use`]. Returns the resolved item
    /// identity.
    pub fn record_reactive_use_by_handle(
        &mut self,
        memory_handle: &str,
        update: UseOutcome,
    ) -> Result<String, BridgeError> {
        let resolved = parse_memory_handle(memory_handle)
            .map_err(|error| super::reactive_ledger_error(&error))?;
        let ledger_session = self
            .reactive_ledger
            .item_session(&resolved.item_id)
            .ok_or_else(|| {
                super::reactive_ledger_error(&ReactiveInjectionError::UnknownItem)
            })?;
        if ledger_session != resolved.session_id {
            return Err(super::reactive_ledger_error(
                &ReactiveInjectionError::IllegalTransition {
                    reason: "memory handle session does not match ledger session",
                },
            ));
        }
        self.record_reactive_use(&resolved.item_id, update)?;
        Ok(resolved.item_id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::super::{
        AdmissionBasis, BridgeRunner, ConnectionId, CueKind, FiringEvidence, NormalizedCue,
        Profile, RiskTier, Severity, UseOutcome,
    };
    use super::{ResolvedMemoryHandle, parse_memory_handle};
    use eliot_agent_bridge_core::{
        ActivationPortOutcome, ActivationPortResult, AttachRequest, DemandId, FencingToken,
        Generation, HostActivationPort, PrincipalId, ProviderFailure, ProviderReadiness,
        SessionId, TaskId, WorkUnitId,
    };
    use eliot_contracts::{EpochId, EpochLineageId};

    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_SESSION: &str = "session-join-1";
    const TEST_DIGEST: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    fn attached_runner() -> BridgeRunner {
        let generation = Generation::new(7).expect("non-zero test generation");
        let fence = FencingToken::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
                NonZeroU64::new(2).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            generation,
            "fence-join-7",
        )
        .expect("valid test fence");
        let result = ActivationPortResult::authenticated(
            PrincipalId::new("principal-join-1").expect("valid principal"),
            SessionId::new(TEST_SESSION).expect("valid session"),
            generation,
            fence,
            TaskId::new("task-join-1").expect("valid task"),
            WorkUnitId::new("work-unit-join-1").expect("valid work unit"),
            "scope-join-1",
            "task-revision-1",
            "plan-join-1",
            "plan-revision-1",
        )
        .expect("valid activation result");
        let mut runner = BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            Some(Box::new(StaticActivation { result })),
            None,
        )
        .expect("runner composes");
        runner
            .attach(AttachRequest::managed(
                DemandId::new("demand-join-1").expect("valid demand"),
                ConnectionId::new("conn-join-1").expect("valid connection"),
            ))
            .expect("managed attach admits");
        runner
    }

    fn delivered_item(runner: &mut BridgeRunner) -> (String, String) {
        let item = runner
            .admit_reactive_injection(
                NormalizedCue {
                    cue_id: "cue-join-1".to_owned(),
                    kind: CueKind::ToolObservation,
                    source: "tool-surface-1".to_owned(),
                    source_revision: "rev-1".to_owned(),
                    cue_digest: TEST_DIGEST.to_owned(),
                },
                Some(FiringEvidence {
                    rule_id: "exact-rule-join-7".to_owned(),
                    cue_id: "cue-join-1".to_owned(),
                    cue_digest: TEST_DIGEST.to_owned(),
                }),
                vec!["rel-a".to_owned()],
                AdmissionBasis {
                    scope_id: "scope-join-1".to_owned(),
                    status: "active".to_owned(),
                    risk: RiskTier::Low,
                    governance_profile_rev: "gov-1".to_owned(),
                    fence_epoch: "epoch-join-1".to_owned(),
                    fence_generation: 2,
                    admitted_severity: Severity::Normal,
                },
            )
            .expect("admit through the real ledger");
        let receipts = runner
            .deliver_reactive_pending_via_response("resp-join-1")
            .expect("drain");
        assert_eq!(receipts.len(), 1);
        (item, receipts[0].receipt_id.clone())
    }

    #[test]
    fn canonical_handle_parses_to_exact_identity() {
        let resolved = parse_memory_handle("reactive-item-12@session-join-1")
            .expect("canonical handle parses");
        assert_eq!(
            resolved,
            ResolvedMemoryHandle {
                item_id: "reactive-item-12".to_owned(),
                session_id: "session-join-1".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_handles_fail_closed() {
        for handle in [
            "reactive-item-12",
            "reactive-item-12@session-a@extra",
            "item-12@session-join-1",
            "reactive-item-@session-join-1",
            "reactive-item-abc@session-join-1",
            "reactive-item-12@",
            "reactive-item-12@   ",
            "@session-join-1",
            "",
            "reactive-item-1@ses\tsion",
        ] {
            assert!(
                parse_memory_handle(handle).is_err(),
                "malformed handle must fail: {handle:?}"
            );
        }
    }

    #[test]
    fn use_update_flows_by_handle_and_follows_receipt() {
        let mut runner = attached_runner();
        let (item, receipt_id) = delivered_item(&mut runner);
        let handle = format!("{item}@{TEST_SESSION}");
        let returned = runner
            .record_reactive_use_by_handle(
                &handle,
                UseOutcome::ObservedUse {
                    detail: "shaped retry".to_owned(),
                },
            )
            .expect("exact handle records");
        assert_eq!(returned, item);
        let receipt = runner
            .reactive_receipt(&receipt_id)
            .expect("delivery issued a receipt");
        assert!(
            matches!(
                receipt.use_status,
                UseOutcome::ObservedUse { .. }
            ),
            "later use status follows the item"
        );
    }

    #[test]
    fn unknown_item_session_mismatch_and_pending_fail_closed() {
        let mut runner = attached_runner();
        let (item, _) = delivered_item(&mut runner);
        // Unknown ledger identity.
        assert!(
            runner
                .record_reactive_use_by_handle(
                    "reactive-item-999@session-join-1",
                    UseOutcome::ObservedUse {
                        detail: "shaped retry".to_owned(),
                    },
                )
                .is_err()
        );
        // Exact item, wrong session.
        assert!(
            runner
                .record_reactive_use_by_handle(
                    &format!("{item}@session-other-9"),
                    UseOutcome::ObservedUse {
                        detail: "shaped retry".to_owned(),
                    },
                )
                .is_err()
        );
        // Pending (undelivered) items cannot carry use yet.
        let pending = runner
            .admit_reactive_injection(
                NormalizedCue {
                    cue_id: "cue-join-2".to_owned(),
                    kind: CueKind::ToolObservation,
                    source: "tool-surface-2".to_owned(),
                    source_revision: "rev-1".to_owned(),
                    cue_digest: TEST_DIGEST.to_owned(),
                },
                Some(FiringEvidence {
                    rule_id: "exact-rule-join-7".to_owned(),
                    cue_id: "cue-join-2".to_owned(),
                    cue_digest: TEST_DIGEST.to_owned(),
                }),
                Vec::new(),
                AdmissionBasis {
                    scope_id: "scope-join-1".to_owned(),
                    status: "active".to_owned(),
                    risk: RiskTier::Low,
                    governance_profile_rev: "gov-1".to_owned(),
                    fence_epoch: "epoch-join-1".to_owned(),
                    fence_generation: 2,
                    admitted_severity: Severity::Normal,
                },
            )
            .expect("admit second item");
        assert!(
            runner
                .record_reactive_use_by_handle(
                    &format!("{pending}@{TEST_SESSION}"),
                    UseOutcome::ObservedUse {
                        detail: "too early".to_owned(),
                    },
                )
                .is_err()
        );
        // Unknown is the absence of an update, never an update.
        assert!(
            runner
                .record_reactive_use_by_handle(
                    &format!("{item}@{TEST_SESSION}"),
                    UseOutcome::Unknown,
                )
                .is_err()
        );
    }

    #[test]
    fn detached_runner_reports_unknown_not_notattached() {
        let mut runner = attached_runner();
        let _ = delivered_item(&mut runner);
        // A never-attached runner holds no ledger: the error names the
        // unknown item, never a spurious attach complaint, and the method
        // never consults the attach view.
        let mut bare = BridgeRunner::new(
            Profile::SpineFunctional,
            ProviderReadiness::all_admitted(),
            None,
            None,
        )
        .expect("runner composes");
        let error = bare
            .record_reactive_use_by_handle(
                "reactive-item-1@session-join-1",
                UseOutcome::ObservedUse {
                    detail: "shaped retry".to_owned(),
                },
            )
            .expect_err("empty ledger knows no items");
        assert!(
            error.to_string().contains("unknown reactive item"),
            "unexpected error {error:?}"
        );
    }
}
