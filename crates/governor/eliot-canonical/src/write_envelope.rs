//! Versioned canonical write-envelope identity and response-mode semantics.
//!
//! Implements issue #1928 at the daemon/Kernel admission boundary for
//! [`I5.5`](../../../docs/architecture/I05-05-write-envelope.md) (write
//! envelope) and [`I5.6`](../../../docs/architecture/I05-06-admission-and-staging.md)
//! (admission and staging).
//!
//! Every canonical write enters through [`VersionedWriteSubmission::bind`],
//! which requires the versioned envelope identity before admission:
//! `protocol_version`, globally unique `operation_id`, stable
//! `write_intent_id`, `idempotency_key`, exact task/scope/ordering/fence
//! metadata carried by [`CanonicalWriteEnvelope`](super::CanonicalWriteEnvelope),
//! and an allowed agent response mode. The immutable request identity is
//! hashed with the shared provider-neutral
//! [`canonical_request_hash`](super::CanonicalWriteEnvelope::canonical_request_hash)
//! so Governor, Kernel, and store agree byte-for-byte.
//!
//! [`WriteEnvelopeLedger`] is the deterministic idempotency decision function:
//! the same key with the same canonical request hash resolves to the original
//! operation identity without a second canonical transition; the same key
//! with a different hash is rejected with an explicit identity conflict. The
//! caller persists this mapping durably with the staged operation in ORS/redb;
//! this type never opens a database and owns no ORS state.
//!
//! Response modes follow I5.5 exactly: `wait_for_commit` waits only to the
//! caller deadline and then reports `ACCEPTED_PENDING` with the same operation
//! identity when durable staging succeeded (a timeout never fabricates
//! rollback or duplicates the write); `accept_after_stage` returns only after
//! complete ORS staging and publishes a pollable operation identity that the
//! caller must not retry; `internal_fire_and_observe` is a
//! maintenance/system-only service option and is rejected from agent
//! envelopes by [`parse_agent_response_mode`].

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::OperationId;

use super::{CanonicalError, CanonicalWriteEnvelope, WriteResponseMode};

/// Versioned write-envelope protocol handled by this boundary.
///
/// Only version 1 is admitted. A version bump requires a new validator and an
/// explicit migration; unknown versions fail closed.
pub const WRITE_ENVELOPE_PROTOCOL_VERSION: u32 = 1;

/// Canonical text of the `wait_for_commit` agent response mode.
pub const WAIT_FOR_COMMIT_MODE: &str = "wait_for_commit";
/// Canonical text of the `accept_after_stage` agent response mode.
pub const ACCEPT_AFTER_STAGE_MODE: &str = "accept_after_stage";
/// System-only mode text. Never a valid agent envelope value.
pub const INTERNAL_FIRE_AND_OBSERVE_MODE: &str = "internal_fire_and_observe";
/// Result status text reported when a staged `wait_for_commit` exceeds its
/// caller deadline. Request mode and observed result stay distinct fields.
pub const ACCEPTED_PENDING_STATUS: &str = "ACCEPTED_PENDING";

/// Parses an agent-supplied response-mode string.
///
/// Accepts exactly `wait_for_commit` and `accept_after_stage`.
/// `internal_fire_and_observe` is rejected explicitly as a system-only
/// service option; anything else is rejected as unknown.
pub fn parse_agent_response_mode(value: &str) -> Result<WriteResponseMode, CanonicalError> {
    match value {
        WAIT_FOR_COMMIT_MODE => Ok(WriteResponseMode::WaitForCommit),
        ACCEPT_AFTER_STAGE_MODE => Ok(WriteResponseMode::AcceptAfterStage),
        INTERNAL_FIRE_AND_OBSERVE_MODE => Err(CanonicalError::InvalidField {
            field: "response_mode",
            reason: "internal_fire_and_observe is system-only, not an agent envelope value",
        }),
        _ => Err(CanonicalError::InvalidField {
            field: "response_mode",
            reason: "unknown response mode",
        }),
    }
}

/// Validates a stable write-intent identity.
///
/// The intent stays constant across typed correction attempts while each
/// attempt carries its own globally unique `operation_id`.
pub fn validate_write_intent_id(value: &str) -> Result<(), CanonicalError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CanonicalError::InvalidField {
            field: "write_intent_id",
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

/// A versioned, fully validated write submission ready for admission.
///
/// The canonical request hash is computed at bind time over the immutable
/// request identity and stored alongside the idempotency key so retries can
/// be decided without reinterpreting the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedWriteSubmission {
    /// Admitted envelope protocol version (always 1 here).
    pub protocol_version: u32,
    /// Stable user/agent intent across typed correction attempts.
    pub write_intent_id: String,
    /// Validated canonical envelope (task/scope/ordering/fence/authority/
    /// provenance metadata plus semantic commands and CAS expectations).
    pub envelope: CanonicalWriteEnvelope,
    /// Canonical request hash over the immutable request identity.
    pub canonical_request_hash: String,
    /// Allowed agent response mode.
    pub response_mode: WriteResponseMode,
}

impl VersionedWriteSubmission {
    /// Parses and validates a versioned submission before admission.
    ///
    /// Requires `protocol_version == 1`, a non-blank `write_intent_id`, a
    /// fully valid envelope (including a non-empty complete
    /// `ordering_scopes` set via the prepared transition), and the
    /// already-typed agent response mode. Computes the canonical request
    /// hash over the immutable request identity.
    pub fn bind(
        protocol_version: u32,
        write_intent_id: String,
        envelope: CanonicalWriteEnvelope,
        response_mode: WriteResponseMode,
    ) -> Result<Self, CanonicalError> {
        if protocol_version != WRITE_ENVELOPE_PROTOCOL_VERSION {
            return Err(CanonicalError::InvalidField {
                field: "protocol_version",
                reason: "unsupported write envelope version",
            });
        }
        validate_write_intent_id(&write_intent_id)?;
        envelope.validate()?;
        // Require the complete ordering-scope declaration before staging:
        // the prepared transition rejects an empty ordering set.
        let transition = envelope.prepare()?;
        if transition.ordering_scopes.is_empty() {
            return Err(CanonicalError::Empty {
                field: "ordering_scopes",
            });
        }
        let canonical_request_hash = envelope.canonical_request_hash()?;
        Ok(Self {
            protocol_version,
            write_intent_id,
            envelope,
            canonical_request_hash,
            response_mode,
        })
    }

    /// Globally unique operation identity of this submission attempt.
    pub fn operation_id(&self) -> &OperationId {
        &self.envelope.operation_id
    }

    /// Stable idempotency key shared across retries of one logical transition.
    pub fn idempotency_key(&self) -> &str {
        &self.envelope.idempotency_key
    }
}

/// Durable idempotency record persisted with the staged operation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerEntry {
    operation_id: OperationId,
    canonical_request_hash: String,
    write_intent_id: String,
    staged: bool,
}

/// Decision returned by [`WriteEnvelopeLedger::submit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// First admission of this idempotency key. The caller stages the
    /// operation in ORS/redb and persists the mapping with it.
    AcceptedNew {
        /// Operation identity to stage and later reconcile.
        operation_id: OperationId,
    },
    /// Equal-hash retry: resolves to the original submission without
    /// creating a second canonical transition.
    ReplaySame {
        /// Original operation identity.
        operation_id: OperationId,
    },
}

/// Deterministic idempotency decision function for the daemon/Kernel
/// boundary.
///
/// The caller persists each accepted mapping durably with the staged
/// operation (ORS/redb) and consults the same mapping before staging a
/// retry. Equal hash replays the original identity; different hash under a
/// reused key is an identity conflict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteEnvelopeLedger {
    entries: BTreeMap<String, LedgerEntry>,
}

impl WriteEnvelopeLedger {
    /// Creates an empty ledger.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Admits one versioned submission.
    ///
    /// New keys are recorded as staged under their canonical request hash.
    /// A reused key with the same hash returns the original operation
    /// identity; a reused key with a different hash fails with
    /// [`CanonicalError::IdentityConflict`].
    pub fn submit(
        &mut self,
        submission: &VersionedWriteSubmission,
    ) -> Result<SubmitOutcome, CanonicalError> {
        if let Some(entry) = self.entries.get(submission.idempotency_key()) {
            if entry.canonical_request_hash == submission.canonical_request_hash {
                return Ok(SubmitOutcome::ReplaySame {
                    operation_id: entry.operation_id.clone(),
                });
            }
            return Err(CanonicalError::IdentityConflict);
        }
        self.entries.insert(
            submission.idempotency_key().to_owned(),
            LedgerEntry {
                operation_id: submission.operation_id().clone(),
                canonical_request_hash: submission.canonical_request_hash.clone(),
                write_intent_id: submission.write_intent_id.clone(),
                staged: true,
            },
        );
        Ok(SubmitOutcome::AcceptedNew {
            operation_id: submission.operation_id().clone(),
        })
    }

    /// Returns the staged operation identity for an idempotency key.
    pub fn staged_operation(&self, idempotency_key: &str) -> Option<&OperationId> {
        self.entries
            .get(idempotency_key)
            .filter(|entry| entry.staged)
            .map(|entry| &entry.operation_id)
    }

    /// Number of distinct idempotency keys recorded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no idempotency key has been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Terminal resolution of a `wait_for_commit` caller wait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitForCommitResolution {
    /// Durable staging succeeded but the caller deadline expired first.
    /// Carries the same operation identity; the caller reconciles the later
    /// receipt by that identity. Never a rollback or a duplicate write.
    AcceptedPending {
        /// Staged operation identity, unchanged from submission.
        operation_id: OperationId,
        /// Always [`ACCEPTED_PENDING_STATUS`].
        status: &'static str,
    },
    /// The caller wait completed without a staging-timeout conversion.
    Committed {
        /// Operation identity, unchanged from submission.
        operation_id: OperationId,
    },
}

/// Resolves a `wait_for_commit` wait against durable staging state.
///
/// `Committed` is returned only on explicit commit evidence (`commit_evidence`
/// with durable staging); it is never inferred from staging or deadline
/// state. When durable staging succeeded, no commit evidence exists, and the
/// caller deadline expired, the result becomes `ACCEPTED_PENDING` with the
/// same operation identity. Request mode and observed result remain distinct
/// fields. Non-staged states and staged-but-uncommitted states fail closed
/// with distinct [`CanonicalError`]s instead of resolving to `Committed`.
pub fn resolve_wait_for_commit(
    operation_id: &OperationId,
    durably_staged: bool,
    deadline_expired: bool,
    commit_evidence: bool,
) -> Result<WaitForCommitResolution, CanonicalError> {
    if commit_evidence && durably_staged {
        return Ok(WaitForCommitResolution::Committed {
            operation_id: operation_id.clone(),
        });
    }
    if durably_staged && deadline_expired && !commit_evidence {
        return Ok(WaitForCommitResolution::AcceptedPending {
            operation_id: operation_id.clone(),
            status: ACCEPTED_PENDING_STATUS,
        });
    }
    if !durably_staged {
        return Err(CanonicalError::InvalidField {
            field: "durably_staged",
            reason: "wait_for_commit has no commit evidence without durable staging",
        });
    }
    Err(CanonicalError::InsufficientFinishEvidence)
}

/// Pollable handle published for an `accept_after_stage` submission.
///
/// Returned only after complete ORS staging. The caller polls/subscribes by
/// operation identity and must not retry: a retry under the same idempotency
/// key replays the same staged identity instead of creating new work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptAfterStageHandle {
    /// Staged operation identity to poll/subscribe by.
    pub operation_id: OperationId,
    /// Always true: the operation identity is pollable after staging.
    pub pollable: bool,
    /// Always true: the caller must not retry this submission.
    pub must_not_retry: bool,
}

/// Publishes the pollable operation identity for `accept_after_stage`.
///
/// Fails closed when ORS staging did not complete; the caller must wait for
/// staging rather than treating an unstaged request as accepted.
pub fn accept_after_stage_handle(
    operation_id: &OperationId,
    ors_staging_complete: bool,
) -> Result<AcceptAfterStageHandle, CanonicalError> {
    if !ors_staging_complete {
        return Err(CanonicalError::InvalidField {
            field: "response_mode",
            reason: "accept_after_stage requires complete ORS staging",
        });
    }
    Ok(AcceptAfterStageHandle {
        operation_id: operation_id.clone(),
        pollable: true,
        must_not_retry: true,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId, ScopeId,
        SecurityContext, TransitionClass,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new(TEST_LINEAGE).expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn request(fence: &StateFence) -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("request-1928").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1928").expect("product id"),
            source_id: SourceId::new("source-1928").expect("source id"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        }
    }

    fn envelope(fence: &StateFence, operation: &str, idem: &str) -> CanonicalWriteEnvelope {
        CanonicalWriteEnvelope {
            operation_id: OperationId::new(operation).expect("operation id"),
            request: request(fence),
            idempotency_key: idem.to_owned(),
            scope_id: ScopeId::new("scope-1928").expect("scope"),
            task_id: None,
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "c".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest-1928")
                .expect("manifest digest"),
            semantic_commands: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-1928"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
            expected_revision_heads: Vec::new(),
            expected_ordering_heads: vec![OrderingHeadExpectation {
                scope: OrderingScopeId::new("scope-1928").expect("ordering scope"),
                expected_sequence: 1,
                state_fence: fence.clone(),
            }],
        }
    }

    fn submission(
        fence: &StateFence,
        operation: &str,
        idem: &str,
        mode: WriteResponseMode,
    ) -> VersionedWriteSubmission {
        VersionedWriteSubmission::bind(
            WRITE_ENVELOPE_PROTOCOL_VERSION,
            "intent-1928".to_owned(),
            envelope(fence, operation, idem),
            mode,
        )
        .expect("versioned submission binds")
    }

    #[test]
    fn agent_envelope_rejects_system_only_response_mode() {
        assert!(matches!(
            parse_agent_response_mode("wait_for_commit"),
            Ok(WriteResponseMode::WaitForCommit)
        ));
        assert!(matches!(
            parse_agent_response_mode("accept_after_stage"),
            Ok(WriteResponseMode::AcceptAfterStage)
        ));
        assert!(matches!(
            parse_agent_response_mode("internal_fire_and_observe"),
            Err(CanonicalError::InvalidField { field, .. }) if field == "response_mode"
        ));
    }

    #[test]
    fn replay_same_envelope_returns_same_operation_without_second_transition() {
        let fence = fence();
        let first = submission(
            &fence,
            "op-1928-a",
            "idem-1928",
            WriteResponseMode::WaitForCommit,
        );
        let mut ledger = WriteEnvelopeLedger::new();
        let accepted = ledger.submit(&first).expect("first submit accepts");
        let SubmitOutcome::AcceptedNew { operation_id } = accepted else {
            panic!("first submit must accept");
        };
        assert_eq!(operation_id.as_str(), "op-1928-a");
        // Exact replay: same envelope bytes and idempotency key.
        let replay = submission(
            &fence,
            "op-1928-a",
            "idem-1928",
            WriteResponseMode::WaitForCommit,
        );
        assert_eq!(replay.canonical_request_hash, first.canonical_request_hash);
        let outcome = ledger.submit(&replay).expect("replay resolves");
        let SubmitOutcome::ReplaySame { operation_id } = outcome else {
            panic!("replay must resolve to the original submission");
        };
        assert_eq!(operation_id.as_str(), "op-1928-a");
        assert_eq!(
            ledger.len(),
            1,
            "replay must not create a second transition"
        );
        assert_eq!(
            ledger
                .staged_operation("idem-1928")
                .expect("staged identity")
                .as_str(),
            "op-1928-a"
        );
    }

    #[test]
    fn reuse_key_with_changed_hash_is_identity_conflict() {
        let fence = fence();
        let first = submission(
            &fence,
            "op-1928-a",
            "idem-1928",
            WriteResponseMode::WaitForCommit,
        );
        let mut ledger = WriteEnvelopeLedger::new();
        ledger.submit(&first).expect("first submit accepts");
        // Same idempotency key, changed canonical bytes (different operation).
        let changed = submission(
            &fence,
            "op-1928-b",
            "idem-1928",
            WriteResponseMode::WaitForCommit,
        );
        assert_ne!(changed.canonical_request_hash, first.canonical_request_hash);
        assert!(matches!(
            ledger.submit(&changed),
            Err(CanonicalError::IdentityConflict)
        ));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn wait_for_commit_deadline_after_staging_reports_accepted_pending_with_same_identity() {
        let fence = fence();
        let submitted = submission(
            &fence,
            "op-1928-a",
            "idem-1928",
            WriteResponseMode::WaitForCommit,
        );
        let mut ledger = WriteEnvelopeLedger::new();
        let SubmitOutcome::AcceptedNew { operation_id } =
            ledger.submit(&submitted).expect("submit accepts")
        else {
            panic!("submit must accept");
        };
        // Caller deadline expired after durable staging: ACCEPTED_PENDING
        // with the same operation identity.
        let staged = ledger.staged_operation("idem-1928").is_some();
        assert!(staged, "operation must be durably staged");
        let resolution =
            resolve_wait_for_commit(&operation_id, staged, true, false).expect("staged timeout");
        let WaitForCommitResolution::AcceptedPending {
            operation_id: pending_id,
            status,
        } = resolution
        else {
            panic!("staged timeout must report ACCEPTED_PENDING");
        };
        assert_eq!(status, ACCEPTED_PENDING_STATUS);
        assert_eq!(pending_id.as_str(), "op-1928-a");
        // Later receipt resolution uses the same operation ID.
        let receipt_id = ledger
            .staged_operation("idem-1928")
            .expect("staged identity for receipt");
        assert_eq!(receipt_id, &pending_id);
    }

    #[test]
    fn wait_for_commit_committed_requires_explicit_commit_evidence() {
        let operation = OperationId::new("op-1928-a").expect("operation id");
        // Durable staging without commit evidence never reports Committed,
        // even before the caller deadline expires.
        let pending = resolve_wait_for_commit(&operation, true, false, false);
        assert!(
            matches!(pending, Err(CanonicalError::InsufficientFinishEvidence)),
            "staged-but-uncommitted must fail closed, got {pending:?}"
        );
        // Explicit commit evidence with durable staging is the only
        // Committed path.
        let committed = resolve_wait_for_commit(&operation, true, false, true)
            .expect("explicit commit evidence resolves");
        let WaitForCommitResolution::Committed { operation_id } = committed else {
            panic!("explicit commit evidence must resolve to Committed");
        };
        assert_eq!(operation_id.as_str(), "op-1928-a");
    }

    #[test]
    fn wait_for_commit_non_staged_never_resolves_to_committed() {
        let operation = OperationId::new("op-1928-a").expect("operation id");
        for deadline_expired in [false, true] {
            let resolution = resolve_wait_for_commit(&operation, false, deadline_expired, false);
            assert!(
                !matches!(resolution, Ok(WaitForCommitResolution::Committed { .. })),
                "non-staged state must never resolve to Committed"
            );
            assert!(
                matches!(
                    resolution,
                    Err(CanonicalError::InvalidField {
                        field: "durably_staged",
                        ..
                    })
                ),
                "non-staged state must fail closed, got {resolution:?}"
            );
        }
        // Commit evidence without durable staging is inconsistent and must
        // still fail closed rather than report Committed.
        let inconsistent = resolve_wait_for_commit(&operation, false, false, true);
        assert!(
            !matches!(inconsistent, Ok(WaitForCommitResolution::Committed { .. })),
            "commit evidence without staging must never resolve to Committed"
        );
        assert!(
            inconsistent.is_err(),
            "inconsistent evidence must fail closed"
        );
    }

    #[test]
    fn wait_for_commit_staged_but_uncommitted_never_resolves_to_committed() {
        let operation = OperationId::new("op-1928-a").expect("operation id");
        // Staged, deadline open, no commit evidence: still waiting, fail
        // closed instead of fabricating Committed.
        let resolution = resolve_wait_for_commit(&operation, true, false, false);
        assert!(
            !matches!(resolution, Ok(WaitForCommitResolution::Committed { .. })),
            "staged-but-uncommitted state must never resolve to Committed"
        );
        assert!(
            matches!(resolution, Err(CanonicalError::InsufficientFinishEvidence)),
            "staged-but-uncommitted state must fail closed, got {resolution:?}"
        );
    }

    #[test]
    fn accept_after_stage_publishes_pollable_identity_and_forbids_retry() {
        let operation = OperationId::new("op-1928-a").expect("operation id");
        let handle = accept_after_stage_handle(&operation, true).expect("staged handle");
        assert_eq!(handle.operation_id.as_str(), "op-1928-a");
        assert!(handle.pollable);
        assert!(handle.must_not_retry);
        assert!(matches!(
            accept_after_stage_handle(&operation, false),
            Err(CanonicalError::InvalidField { .. })
        ));
    }
}
