//! Owner-approved typed parameter contracts for activated named operations.
//!
//! Slice C1 (issue #19) activates exactly five named reads with proven
//! adapter handlers, parameter shapes, and consumers:
//! `GetRevisionHeads`, `GetOrderingHeads`, `GetScopeRevisionView`,
//! `ResolveWriteReceipt`, and `GetEvidencePack` (see
//! `apply/read_boundary.rs` in the Surreal adapter and `execute_named_sync`
//! in the memory adapter), plus T11.2 `GetCurrentEpistemicPosition` with its
//! `position` selector, plus the four
//! `CaptureObservation` / `AppendAuditEvent` / `ApplyLifecyclePolicy` /
//! `ReconcileRecovery` mutations (AUD-C01: `CaptureObservation` and `AppendAuditEvent` persist
//! `TransitionClass::CaptureCandidate` with the `EffectClass::Candidate`
//! ceiling; `CaptureObservation` carries the owner-shaped `subject` string
//! already used by the adapter receipt/plan fixtures, `AppendAuditEvent`
//! carries the six receipt-bound operator fields emitted by the Governor
//! reconciliation, `ApplyLifecyclePolicy` carries the six lifecycle-policy
//! fields emitted by the Governor skill promotion envelope
//! (`crates/governor/eliot-governor/src/skill_lifecycle.rs`, `skill_envelope`),
//! `ReconcileRecovery` carries the ten problem-leg recovery fields emitted by
//! the Governor doctor verification envelope
//! (`crates/governor/eliot-governor/src/observation_reconciliation.rs`,
//! `recovery_envelope`)) plus the `UpdateTaskState` mutation (AUD-C01:
//! persists `TransitionClass::TaskControl` with the
//! `EffectClass::ReversibleMutation` ceiling and carries the task-control
//! fields and serialized admitted event emitted by the Governor task lifecycle envelope
//! (`crates/governor/eliot-governor/src/task_lifecycle.rs`, `task_envelope`:
//! `task_id`, `event_id`, optional `from`, `to`, `expected_revision`,
//! `actor_ref`, `task_event_json`) plus the `ApplyEpistemicRevision` mutation (T11.2: persists
//! `TransitionClass::Epistemic` with the `EffectClass::Candidate`
//! ceiling and carries the single `revision` epistemic-revision payload),
//! plus T11.3 (issue #18) the four cognitive reads `GetTaskState`
//! (`task_id` + `max_records`), `GetAttentionAndProblems` (optional
//! `problem_id` + `max_records`), `GetUnderstandingProjectionInputs`
//! (`selector` + `max_records`), and `GetCapabilityEvidenceState`
//! (`skill_id` + `max_records`), each scope-addressed and bounded like
//! `GetEvidencePack`, plus issue #223 the two experience range reads
//! `GetExperienceBankRange` / `GetAgentFeedbackRange` (required
//! `max_records` plus the optional opaque `cursor` continuation
//! selector; scope through the typed `scope_id` request field) and the
//! two
//! `CommitExperienceBank` / `CommitAgentFeedback` mutations
//! (`CaptureCandidate` with the `Candidate` ceiling; verbatim record
//! document plus presented digests, decimal owner revision, and
//! idempotency key).
//! Every other [`NamedReadOperation`](crate::NamedReadOperation) variant and
//! every other [`NamedMutationOperation`](crate::NamedMutationOperation)
//! variant stays known-but-unsupported and unadvertised, and no other mutation
//! has an owner-approved typed schema yet.
//!
//! This module is the single source of truth for those contracts: the closed
//! operation-name mapping, the declared parameter list per activated
//! operation, the serializable parameter-schema projection bound into each
//! [`NamedOperationManifest`](crate::NamedOperationManifest), and the
//! pre-dispatch typed validation. There are no parallel YAML/JSON/Rust lists.
//!
//! Validation is control-contract only and issues no authority: scope, role,
//! fence, and expiry enforcement stay in slice C2. An explicitly declared
//! parameter (today `operation_id` for `ResolveWriteReceipt`, `subject`
//! for `CaptureObservation`, the six receipt-bound fields for
//! `AppendAuditEvent`, the six lifecycle-policy fields for
//! `ApplyLifecyclePolicy`, the ten problem-leg recovery fields for
//! `ReconcileRecovery`, the task-control fields and durable event for `UpdateTaskState`
//! (`task_id`, `event_id`, optional `from`, `to`, `expected_revision`,
//! `actor_ref`), and the `subject` / `max_records` evidence-pack
//! selectors for `GetEvidencePack`, the `task_id` / `max_records` selectors
//! for `GetTaskState`, the optional `problem_id` / `max_records` selectors
//! for `GetAttentionAndProblems`, the `selector` / `max_records` selectors
//! for `GetUnderstandingProjectionInputs`, and the `skill_id` /
//! `max_records` selectors for `GetCapabilityEvidenceState`, and the five
//! canonical-erasure fields for `ApplyErasure` (`subject`, `surfaces`,
//! `reason`, `requester`, `erasure_operation_id`)) is
//! owner-approved and therefore supersedes the
//! generic [`CONTROL_FIELD_DENYLIST`](crate::CONTROL_FIELD_DENYLIST) for that
//! exact name; every undeclared control name is still rejected fail-closed.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability_evidence_store::{
    CAPABILITY_EVIDENCE_PARAM_CURSOR, CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION,
    CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY, CAPABILITY_EVIDENCE_PARAM_MAX_RECORDS,
    CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST, CAPABILITY_EVIDENCE_PARAM_RECORD_JSON,
    CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY, CAPABILITY_EVIDENCE_PARAM_SKILL_ID,
};
use crate::learning_store::{
    LEARNING_PARAM_CURSOR, LEARNING_PARAM_FENCE_DIGEST, LEARNING_PARAM_HANDLE,
    LEARNING_PARAM_IDEMPOTENCY_KEY, LEARNING_PARAM_MAX_RECORDS, LEARNING_PARAM_RECORD_DIGEST,
    LEARNING_PARAM_RECORD_JSON, LEARNING_PARAM_RECORD_KIND, LEARNING_PARAM_SCOPE_DIGEST,
};
use crate::{
    CONTROL_FIELD_DENYLIST, NamedMutationOperation, NamedReadOperation, OperationId, StoreError,
    canonical_json_bytes, sha256_hex,
};

/// Closed shape vocabulary for owner-approved named-operation parameters.
///
/// Slice C1 needs exactly two shapes: the `operation_id` string consumed by
/// `ResolveWriteReceipt` (reused for the receipt-bound `AppendAuditEvent`
/// `operation_id` and for the problem-leg `ReconcileRecovery`
/// `observation_operation_id`) and the non-blank text captured by `CaptureObservation`
/// as `subject` (reused for the five remaining receipt-bound
/// `AppendAuditEvent` fields, for the six lifecycle-policy
/// `ApplyLifecyclePolicy` fields, for the nine remaining problem-leg
/// `ReconcileRecovery` fields, for the task-control `UpdateTaskState`
/// fields, and for the two `GetEvidencePack`
/// evidence-pack selectors: the exact captured-observation `subject` and the
/// explicit `max_records` bound carried as its decimal string, mirroring how
/// `AppendAuditEvent` carries `expected_revision` and how `ReconcileRecovery`
/// carries `expected_problem_revision`). The enum is closed so a future parameter kind
/// is a contract change with a new owner-approved arm, never silent `Value`
/// passthrough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterShape {
    /// The closed versioned candidate/transition payload with position CAS.
    EpistemicRevision,
    /// A string that must parse as a store [`OperationId`].
    OperationId,
    /// A non-blank text string: the observation subject captured by
    /// `CaptureObservation`, reused for the non-`operation_id` receipt-bound
    /// `AppendAuditEvent` fields (`idempotency_key`, `session_id`,
    /// `access_digest`, `action_digest`, and `expected_revision` as its
    /// decimal string), for the six lifecycle-policy `ApplyLifecyclePolicy`
    /// fields (`action`, `base_view_digest`, `candidate_digest`,
    /// `candidate_package_digest`, `skill_id`, `verifier_ref`), for the nine
    /// non-`observation_operation_id` problem-leg `ReconcileRecovery` fields
    /// (`problem_id`, `expected_problem_revision` as its decimal string,
    /// `attempt_digest`, `effect_digest`, `operation_manifest_digest`,
    /// `artifact_binding_digest`, `fence_digest`, `observation_record_id`,
    /// and `observation_request_digest`), for the task-control
    /// `UpdateTaskState` fields (`task_id`, `event_id`, `from`, `to`,
    /// `expected_revision` as its decimal string, and `actor_ref`; `from` is
    /// optional because the proposing transition carries no predecessor state),
    /// for the seven authority-revocation `RecordAuthorityRevocation` fields
    /// (`origin_ref`, `closure_id`, `closure_revision` as its decimal string,
    /// `affected_digest`, `affected_count` as its decimal string,
    /// `invalidation_reason`, `fence_digest`), and for the
    /// two `GetEvidencePack` selectors (the exact captured-observation
    /// `subject` and the explicit `max_records` bound as its decimal
    /// string, range-checked against
    /// [`EVIDENCE_PACK_MAX_RECORDS`](crate::operation_catalogue::EVIDENCE_PACK_MAX_RECORDS) by
    /// every handler), and for the two `GetAuthorityRevocationHistory`
    /// selectors (the exact revoked `origin_ref` and the explicit
    /// `max_records` bound as its decimal string, range-checked against
    /// [`REVOCATION_HISTORY_MAX_RECORDS`](crate::REVOCATION_HISTORY_MAX_RECORDS)
    /// by every handler), and for the four `ApplyErasure` text fields (the
    /// exact admitted `subject`, the canonical `surfaces` denominator, the
    /// explicit user `reason`, and the user-initiated `requester` handle).
    /// Length is bounded by the owning manifest entry's
    /// `max_input_bytes` over the canonical parameter bytes (the same
    /// mechanism that bounds the activated reads), so no separate string
    /// length constant exists here.
    Subject,
    /// A closed canonical notification-state payload object (issue #1780):
    /// the canonical record, receipt, delivery-state, or authorization JSON
    /// for the `ApplyNotificationState` legs and the read selectors that
    /// carry structured values. The value must be a JSON object; leg
    /// completeness is enforced by the notification-state contract.
    NotificationState,
    /// Closed exact owner and typed revision selector for issue #1862.
    CampaignSourceLookup,
    /// Closed, owner-bound campaign source publications carried by an
    /// admitted owner transition for issue #1862.
    CampaignSourcePublications,
    /// Closed content-addressed campaign view selector for issue #1862.
    CampaignViewLookup,
    /// Closed owner-separated swarm revision record and complete canonical bytes.
    SwarmOwnerRevision,
    /// Exact task/item identity selector for issue #1822.
    BlackboardItemLookup,
    /// Closed typed blackboard item revision and predecessor CAS for issue #1822.
    BlackboardItemRevision,
    /// Closed typed mailbox admission and stream-head CAS for issue #1820.
    MailboxItemAdmission,
    /// Opaque, versioned `InstrumentRegistry` snapshot emitted by `persist`.
    InstrumentRegistrySnapshot,
    /// Closed canonical Problem candidate record for issue #1759 I2: the
    /// complete candidate `Problem` document the `ApplyProblemOwnerState` leg
    /// commits. The value must be a JSON object; the problem owner-state
    /// contract owns its identity, revision and source-Signal bindings.
    ProblemOwnerState,
    /// Closed owner-issued `TaskContract` acceptance-set record for issue #325
    /// P1, I7.9: the exact task identity, non-zero task revision, the owner's
    /// own recorded acceptance digest, the enumerated obligations, and the
    /// issuing State Fence. The value must be a JSON object; the acceptance
    /// record contract owns its task/revision binding and its obligation list,
    /// and the neutral acceptance-set validator proves the digest against it.
    TaskContractAcceptanceRecord,
    /// Closed Governor-owned work ADMITTED record with its reservation and
    /// exact launch-outbox commitment (#1678, I14.6/I10.15).
    WorkAdmission,
    /// Decimal predecessor for the existing `owner/canonical` CAS used by
    /// the same `AdmitWork` operation.
    WorkAdmissionCanonicalRevision,
    /// Canonical JSON image of the existing owner/canonical snapshot that
    /// carries the admitted semantic revision in the same transaction.
    WorkAdmissionCanonicalSnapshot,
    /// Closed measured-usage attribution row emitted by the current
    /// Governor BudgetLedger owner.
    BudgetConsumption,
    /// Canonical JSON image of the next existing owner/budget snapshot.
    BudgetOwnerSnapshot,
}

impl ParameterShape {
    /// Stable schema code bound into the parameter-schema digest.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EpistemicRevision => "eliot.storage.epistemic-revision.v1",
            Self::OperationId => "operation-id",
            Self::Subject => "subject-text",
            Self::NotificationState => "eliot.notify.state.v1",
            Self::CampaignSourceLookup => "eliot.learning.campaign-source-lookup.v1",
            Self::CampaignSourcePublications => "eliot.learning.campaign-source-publications.v1",
            Self::CampaignViewLookup => "eliot.learning.campaign-view-lookup.v1",
            Self::SwarmOwnerRevision => "eliot.swarm.owner-revision.v1",
            Self::BlackboardItemLookup => "eliot.blackboard.item-lookup.v1",
            Self::BlackboardItemRevision => "eliot.blackboard.item-revision.v1",
            Self::MailboxItemAdmission => "eliot.mailbox.item-admission.v1",
            Self::InstrumentRegistrySnapshot => "eliot.instrument.registry-snapshot@1.0.0",
            Self::ProblemOwnerState => crate::PROBLEM_OWNER_STATE_SCHEMA_V1,
            Self::TaskContractAcceptanceRecord => crate::TASK_CONTRACT_ACCEPTANCE_RECORD_SCHEMA_V1,
            Self::WorkAdmission => crate::WORK_ADMISSION_SCHEMA_V1,
            Self::WorkAdmissionCanonicalRevision => "eliot.storage.canonical-owner-revision.v1",
            Self::WorkAdmissionCanonicalSnapshot => "eliot.storage.canonical-owner-snapshot.v1",
            Self::BudgetConsumption => crate::BUDGET_CONSUMPTION_SCHEMA_V1,
            Self::BudgetOwnerSnapshot => "eliot.storage.budget-owner-snapshot.v1",
        }
    }
}

/// One owner-approved parameter declaration for an activated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterDeclaration {
    /// Exact parameter name. Membership is exact: unknown or extra names fail.
    pub name: &'static str,
    /// Required value shape for this parameter.
    pub shape: ParameterShape,
    /// Whether the parameter must be present.
    pub required: bool,
}

const OPERATION_ID_DECLARATION: ParameterDeclaration = ParameterDeclaration {
    name: "operation_id",
    shape: ParameterShape::OperationId,
    required: true,
};

static RESOLVE_WRITE_RECEIPT_PARAMETERS: [ParameterDeclaration; 1] = [OPERATION_ID_DECLARATION];
static GET_EVIDENCE_PACK_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "subject",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static CAPTURE_OBSERVATION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "subject",
    shape: ParameterShape::Subject,
    required: true,
}];
static APPEND_AUDIT_EVENT_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "operation_id",
        shape: ParameterShape::OperationId,
        required: true,
    },
    ParameterDeclaration {
        name: "idempotency_key",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "session_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "access_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "action_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static APPLY_LIFECYCLE_POLICY_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "action",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "base_view_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "candidate_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "candidate_package_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "skill_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "verifier_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static RECONCILE_RECOVERY_PARAMETERS: [ParameterDeclaration; 10] = [
    ParameterDeclaration {
        name: "problem_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_problem_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "attempt_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "effect_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "operation_manifest_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "artifact_binding_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "fence_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_operation_id",
        shape: ParameterShape::OperationId,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_record_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_request_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
];
/// Owner-approved Problem owner-transition fields (issue #1759 I2, I13.9).
///
/// The six scalar fields are the four bindings every named owner transition
/// carries — the source Signal, the re-proved current authorization digest,
/// the expected record revision and the candidate record digest — plus the
/// Problem identity and the named-transition discriminator. Membership is
/// exact and every one of them is required, so a transition cannot be admitted
/// with a binding missing; `validate_problem_owner_state_params` then closes the
/// verb set, compares the candidate record against them, and gates the optional
/// retained closure record to exactly the two verbs that produce one.
static APPLY_PROBLEM_OWNER_STATE_PARAMETERS: [ParameterDeclaration; 8] = [
    ParameterDeclaration {
        name: "transition",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "problem_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_problem_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "source_signal_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "authorization_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "record_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "record_json",
        shape: ParameterShape::ProblemOwnerState,
        required: true,
    },
    ParameterDeclaration {
        name: "closure_json",
        shape: ParameterShape::ProblemOwnerState,
        required: false,
    },
];
/// Owner-approved Governor finish persistence fields. The receipt remains an
/// opaque canonical JSON document at this boundary; only the fixed
/// `owner/finish` record address and outer revision are storage semantics.
static RECORD_FINISH_DECISION_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: "attempt_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_finish_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "receipt_json",
        shape: ParameterShape::Subject,
        required: true,
    },
];
/// Owner-approved Governor finish-evidence persistence fields. The canonical
/// owner image remains an opaque JSON document at this boundary; the store
/// only arbitrates its fixed owner address and revision.
static RECORD_FINISH_EVIDENCE_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "expected_canonical_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "snapshot_json",
        shape: ParameterShape::Subject,
        required: true,
    },
];
/// The Governor's complete catalog image is opaque here. The store only
/// arbitrates the fixed owner address and outer revision; the Governor proves
/// source-policy agreement and independently reads the committed image back.
static RECORD_MODULE_CATALOG_SNAPSHOT_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "expected_module_registry_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "snapshot_json",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static NO_PARAMETERS: [ParameterDeclaration; 0] = [];
static EPISTEMIC_REVISION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "revision",
    shape: ParameterShape::EpistemicRevision,
    required: true,
}];
static CURRENT_POSITION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "position",
    shape: ParameterShape::Subject,
    required: true,
}];
static GET_TASK_STATE_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "task_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static GET_CAMPAIGN_SOURCE_REVISION_PARAMETERS: [ParameterDeclaration; 1] =
    [ParameterDeclaration {
        name: "lookup",
        shape: ParameterShape::CampaignSourceLookup,
        required: true,
    }];
static GET_CAMPAIGN_LEARNING_STATE_VIEW_PARAMETERS: [ParameterDeclaration; 1] =
    [ParameterDeclaration {
        name: "lookup",
        shape: ParameterShape::CampaignViewLookup,
        required: true,
    }];
static GET_ATTENTION_AND_PROBLEMS_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "problem_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static GET_UNDERSTANDING_PROJECTION_INPUTS_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "selector",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];
/// Closed selectors for `GetCapabilityEvidenceState` (T11.3): the required
/// exact `skill_id` plus the required `max_records` bound, plus the optional
/// opaque `cursor` keyset-continuation selector (issue #1773).
///
/// The cursor is what makes the page honest. Without it the handler had to
/// serve a bare prefix and report `truncated` with no way to continue, so a
/// caller draining the read would re-read the first `limit` rows forever and
/// could never reach exhaustion. An absent cursor still reads from the start, so
/// every existing caller is unaffected; a caller that receives `truncated`
/// presents the issued cursor, and a cursor that does not decode against the
/// current fence and revision heads fails closed.
static GET_CAPABILITY_EVIDENCE_STATE_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: "skill_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_CURSOR,
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Owner-approved authority-revocation fields emitted by the Governor
/// authority-revocation envelope
/// (`crates/governor/eliot-governor/src/authority_revocation.rs`,
/// `authority_revocation_envelope`, issue #686): the revoked `origin_ref`,
/// the recorded `closure_id`, the durable history `closure_revision` as its
/// decimal string (mirroring how `AppendAuditEvent` carries
/// `expected_revision`), the canonical digest of the sorted affected set
/// (`affected_digest`), the affected-set size as its decimal string
/// (`affected_count`), the terminal `invalidation_reason` in its
/// `SCREAMING_SNAKE_CASE` wire spelling, and the `fence_digest` binding the
/// record to its state fence.
static RECORD_AUTHORITY_REVOCATION_PARAMETERS: [ParameterDeclaration; 7] = [
    ParameterDeclaration {
        name: "origin_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "closure_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "closure_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "affected_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "affected_count",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "invalidation_reason",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "fence_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Owner-approved revocation-history selectors for the
/// `GetAuthorityRevocationHistory` named read (issue #686): the exact
/// revoked `origin_ref` and the explicit `max_records` bound carried as its
/// decimal string, mirroring the `GetEvidencePack` `subject` /
/// `max_records` selectors and range-checked against
/// [`REVOCATION_HISTORY_MAX_RECORDS`](crate::REVOCATION_HISTORY_MAX_RECORDS)
/// by every handler.
static GET_AUTHORITY_REVOCATION_HISTORY_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "origin_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Owner-approved canonical-erasure fields for the explicit user-requested
/// `ApplyErasure` named transaction (issue #1712, built by
/// `erasure_admission::admit_erasure_transition`): the exact admitted target
/// `subject`, the exact `payload_ref` and `encryption_key_ref` identities the
/// erasure is bound to, the exact `erasure_deadline_unix_ms` deadline
/// identity, the canonical surface denominator `surfaces` (sorted,
/// comma-joined handler-surface names; closed-enum membership is enforced at
/// dispatch), the explicit user `reason`, the user-initiated `requester`
/// identity handle, and the stable `erasure_operation_id` binding the
/// recorded intent to its execution and receipt. Automatic
/// maintenance/curation/Dreamer/scheduler paths furnish no reason, requester,
/// or approval handles, so they can never satisfy this contract.
static APPLY_ERASURE_PARAMETERS: [ParameterDeclaration; 8] = [
    ParameterDeclaration {
        name: "subject",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "payload_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "encryption_key_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "erasure_deadline_unix_ms",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "surfaces",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "reason",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "requester",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "erasure_operation_id",
        shape: ParameterShape::OperationId,
        required: true,
    },
];

/// Owner-approved canonical notification-state fields (issue #1780): the leg
/// discriminator plus the conditionally-required leg payloads. Leg
/// completeness (which payload each leg requires) is enforced by the
/// notification-state contract; every name here is optional at the
/// declaration level so one closed table serves all four legs.
static APPLY_NOTIFICATION_STATE_PARAMETERS: [ParameterDeclaration; 10] = [
    ParameterDeclaration {
        name: "mutation",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "dedup_key",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "notification_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "record_json",
        shape: ParameterShape::NotificationState,
        required: false,
    },
    ParameterDeclaration {
        name: "source_receipt_json",
        shape: ParameterShape::NotificationState,
        required: false,
    },
    ParameterDeclaration {
        name: "delivery_json",
        shape: ParameterShape::NotificationState,
        required: false,
    },
    ParameterDeclaration {
        name: "channel",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "principal",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "disposition",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "authorization_json",
        shape: ParameterShape::NotificationState,
        required: false,
    },
];

/// Owner-approved notification-state read selectors (issue #1780): the
/// optional record-scope filter, the optional exact dedup-key selector, the
/// optional exact notification-identity selector, the required
/// resolved-row inclusion flag, the required decimal page bound, and the
/// optional opaque cursor.
static GET_NOTIFICATION_STATE_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "scope",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "dedup_key",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "notification_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "include_resolved",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "page_limit",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "cursor",
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Owner-approved reactive-ledger upsert fields (issue #1941 C4): the exact
/// session selector plus the opaque bridge ledger snapshot. Snapshot
/// contract/bounds are enforced by the reactive-state contract.
static APPLY_REACTIVE_LEDGER_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "session_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "ledger_json",
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Owner-approved reactive-ledger read selector (issue #1941 C4): the exact
/// session identity.
static GET_REACTIVE_LEDGER_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "session_id",
    shape: ParameterShape::Subject,
    required: true,
}];

/// Owner-approved resource-snapshot upsert fields (issue #1941 C4): the
/// canonical URI, the content digest, and the base64 bytes. Digest/bytes
/// agreement and URI grammar are enforced by the reactive-state contract.
static APPLY_RESOURCE_SNAPSHOT_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: "uri",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "content_sha256",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "content_base64",
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Owner-approved resource-snapshot read selector (issue #1941 C4): the
/// exact canonical URI.
static GET_RESOURCE_SNAPSHOT_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "uri",
    shape: ParameterShape::Subject,
    required: true,
}];

/// Opaque versioned registry snapshot carried by the unactivated instrument
/// registry mutation. The expected owner revision is bound by the prepared
/// transition's standard revision-head CAS, not duplicated in payload data.
static APPLY_INSTRUMENT_REGISTRY_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "snapshot_json",
    shape: ParameterShape::InstrumentRegistrySnapshot,
    required: true,
}];

/// Owner-approved user-automation mutation fields (issue #1779 and #2865):
/// the leg discriminator, the always-present automation identity, and the
/// conditionally-required leg payloads. Leg completeness (which payload each
/// leg requires) is enforced by the automation-state contract; every name
/// here is optional at the declaration level so one closed table serves all
/// legs.
///
/// `normalization_receipt_json` is the owner-issued schedule normalization
/// envelope a create/edit leg retains beside its own immutable revision, and
/// it is DECLARED here rather than smuggled through as an undeclared name:
/// membership in this table is exact, so an undeclared parameter is refused
/// pre-dispatch. It stays optional at this level for the same reason every
/// other leg payload is — the closed table serves all six legs — and the
/// automation-state contract plus the backends decide its shape and its
/// retention. Absence is never a synthesized receipt: a revision that
/// retained no envelope leaves its compiled occurrence set unadmitted by name
/// downstream. `normalization_request_json` is the original authenticated
/// producer request retained only by the internal normalization leg.
static APPLY_USER_AUTOMATION_PARAMETERS: [ParameterDeclaration; 11] = [
    ParameterDeclaration {
        name: "operation",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "automation_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "revision",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "revision_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "previous_revision",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "configuration_state",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "normalization_receipt_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "normalization_request_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "occurrence_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "invocation_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "failure_json",
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Owner-approved user-automation read selectors (issue #1779; issue #2808
/// adds the continuation): the query discriminator, the optional exact
/// automation selector, the optional exact immutable revision selector for
/// current/history reads, the retired-row inclusion flag, the decimal page
/// bound, the optional exact occurrence selector for invocation reads, and the
/// owner-minted page continuation for the two paged denominator reads.
///
/// Membership is exact, so the continuation is declared here rather than
/// smuggled through as an undeclared name: a cursor the owner never minted, or
/// one presented to a read that does not page, is refused pre-dispatch by
/// `validate_automation_read_params` rather than reaching a backend.
static GET_USER_AUTOMATION_PARAMETERS: [ParameterDeclaration; 7] = [
    ParameterDeclaration {
        name: "query",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "automation_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "revision",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "occurrence_id",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "include_retired",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "cursor",
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Shared closed selector for both experience range reads (issue #223):
/// the required `max_records` bound as its decimal string plus the
/// optional opaque `cursor` continuation selector minted by the
/// store-api audit cursor issuer. Scope arrives through the typed
/// `scope_id` request field, mirroring `GetEvidencePack`.
static GET_EXPERIENCE_RANGE_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "cursor",
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Closed selector for the audit-range read (issue #223): the optional
/// opaque continuation cursor minted by the store-api audit cursor
/// issuer. Absent cursors read from the start with legacy fail-closed
/// overflow; present cursors resume paging after owner verification.
/// The empty-parameter request shape stays valid, so existing planners
/// keep working.
static GET_AUDIT_RANGE_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "cursor",
    shape: ParameterShape::Subject,
    required: false,
}];

/// Closed commit parameters shared by both experience legs (issue #223):
/// the verbatim record document, the presented record/scope/fence
/// digests, the decimal owner revision, and the idempotency key. The
/// family is bound by the operation variant, never by a discriminator
/// parameter.
static COMMIT_EXPERIENCE_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "record_json",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "record_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "record_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "scope_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "fence_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "idempotency_key",
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Closed commit parameters for the learning-record leg (issue #1868):
/// the closed record-kind discriminator, the exact record handle, the
/// verbatim record document, the presented record/scope/fence digests,
/// and the idempotency key. The kind is bound by the discriminator
/// parameter over the closed [`LearningRecordKind`](crate::LearningRecordKind)
/// set, never by a per-kind table.
static COMMIT_LEARNING_PARAMETERS: [ParameterDeclaration; 7] = [
    ParameterDeclaration {
        name: LEARNING_PARAM_RECORD_KIND,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_HANDLE,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_RECORD_JSON,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_RECORD_DIGEST,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_SCOPE_DIGEST,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_FENCE_DIGEST,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_IDEMPOTENCY_KEY,
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Shared closed selector for the learning-record range read (issue
/// #1868): the required `max_records` bound as its decimal string, the
/// optional closed `record_kind` filter, plus the optional opaque
/// `cursor` continuation selector. Scope arrives through the typed
/// `scope_id` request field, mirroring `GetEvidencePack`.
static GET_LEARNING_RANGE_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: LEARNING_PARAM_MAX_RECORDS,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_RECORD_KIND,
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: LEARNING_PARAM_CURSOR,
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Closed capability-evidence commit fields (issue #1773, I3.4): the exact
/// `skill_id` of the evidence key, the owner-issued `scope_key` digest of the
/// exact route-scope fingerprint, the verbatim `record_json` evidence
/// document, the presented `record_digest` of those bytes, the asserted
/// `expected_canonical_revision` CAS predecessor as its decimal string, and the
/// deterministic `idempotency_key`. The store issues
/// `expected + 1` as the owner-issued revision of the evidence row; the
/// document stays opaque and its semantics stay Governor-owned.
static COMMIT_CAPABILITY_EVIDENCE_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_SKILL_ID,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_RECORD_JSON,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY,
        shape: ParameterShape::Subject,
        required: true,
    },
];

/// Closed selector for the paged capability-evidence record read (issue
/// #1773, I3.4): the required `max_records` page bound as its decimal string,
/// the optional exact `skill_id` filter, plus the optional opaque `cursor`
/// keyset-continuation selector. Scope arrives through the typed `scope_id`
/// request field, mirroring `GetEvidencePack`; an absent cursor reads from the
/// start and a malformed cursor fails closed at the cursor decoder, so a
/// complete hydration cannot silently stop at the first page.
static GET_CAPABILITY_EVIDENCE_RECORD_RANGE_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_MAX_RECORDS,
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_SKILL_ID,
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: CAPABILITY_EVIDENCE_PARAM_CURSOR,
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// Owner-approved task-control fields emitted by the Governor task lifecycle
/// envelope (`crates/governor/eliot-governor/src/task_lifecycle.rs`,
/// `task_envelope`): the transitioned `task_id`, the admitted `event_id`, the
/// predecessor state `from` (absent on propose, which has no predecessor),
/// the target state `to`, the owner-checked compare-and-swap base
/// `expected_revision` as its decimal string (`"1"` on propose, the current
/// task revision on apply, mirroring how `AppendAuditEvent` carries
/// `expected_revision`), the admitted `actor_ref`, and `task_event_json` which
/// preserves the complete lifecycle command in task history.
static UPDATE_TASK_STATE_PARAMETERS: [ParameterDeclaration; 10] = [
    ParameterDeclaration {
        name: "task_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "event_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "from",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "to",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "actor_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "task_event_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "campaign_learning_state_recipe_json",
        shape: ParameterShape::Subject,
        required: false,
    },
    ParameterDeclaration {
        name: "campaign_source_publications_json",
        shape: ParameterShape::CampaignSourcePublications,
        required: false,
    },
    ParameterDeclaration {
        name: "campaign_source_matrix_complete",
        shape: ParameterShape::Subject,
        required: false,
    },
];

/// One bounded immutable swarm owner revision.
static APPLY_SWARM_OWNER_REVISION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "record",
    shape: ParameterShape::SwarmOwnerRevision,
    required: true,
}];
/// The single owner-issued `TaskContract` acceptance-set record for
/// `RecordTaskContractAcceptanceSet` (issue #325 P1, I7.9).
///
/// The record travels whole, exactly as the swarm owner revision does: the
/// enumeration and the owner's recorded acceptance digest are only meaningful
/// together, so splitting them across sibling parameters would create a second
/// way to present a set that commits to a different obligation list.
static RECORD_TASK_CONTRACT_ACCEPTANCE_SET_PARAMETERS: [ParameterDeclaration; 1] =
    [ParameterDeclaration {
        name: "record",
        shape: ParameterShape::TaskContractAcceptanceRecord,
        required: true,
    }];
static ADMIT_WORK_PARAMETERS: [ParameterDeclaration; 3] = [
    ParameterDeclaration {
        name: "record",
        shape: ParameterShape::WorkAdmission,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_canonical_revision",
        shape: ParameterShape::WorkAdmissionCanonicalRevision,
        required: true,
    },
    ParameterDeclaration {
        name: "canonical_owner_snapshot_json",
        shape: ParameterShape::WorkAdmissionCanonicalSnapshot,
        required: true,
    },
];
static COMMIT_BUDGET_CONSUMPTION_PARAMETERS: [ParameterDeclaration; 4] = [
    ParameterDeclaration {
        name: "consumption",
        shape: ParameterShape::BudgetConsumption,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_budget_owner_revision",
        shape: ParameterShape::WorkAdmissionCanonicalRevision,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_budget_owner_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "budget_owner_snapshot_json",
        shape: ParameterShape::BudgetOwnerSnapshot,
        required: true,
    },
];
/// Exact owner-acceptance selectors for `GetTaskContractAcceptanceSet`
/// (issue #1741, I7.9).
///
/// The read is addressed by the exact `task_id` plus the exact `task_revision`
/// the caller was admitted against, carried as its decimal string exactly like
/// the other owner-issued revision selectors, so the owner can refuse a
/// denominator the caller was not admitted for instead of serving whatever is
/// current.
static GET_TASK_CONTRACT_ACCEPTANCE_SET_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "task_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "task_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static BLACKBOARD_ITEM_LOOKUP_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "task_id",
        shape: ParameterShape::BlackboardItemLookup,
        required: true,
    },
    ParameterDeclaration {
        name: "item_id",
        shape: ParameterShape::BlackboardItemLookup,
        required: true,
    },
];
static APPLY_BLACKBOARD_ITEM_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "revision",
    shape: ParameterShape::BlackboardItemRevision,
    required: true,
}];
static ADMIT_MAILBOX_ITEM_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "admission",
    shape: ParameterShape::MailboxItemAdmission,
    required: true,
}];

/// Returns the canonical operation name bound into manifests and digests.
///
/// The spelling matches the `PascalCase` serde wire form of each variant, so
/// one closed match is the single name owner for code, manifests, and wire.
#[must_use]
pub const fn named_read_operation_name(operation: NamedReadOperation) -> &'static str {
    match operation {
        NamedReadOperation::GetRevisionHeads => "GetRevisionHeads",
        NamedReadOperation::GetNotificationState => "GetNotificationState",
        NamedReadOperation::GetReactiveInjectionState => "GetReactiveInjectionState",
        NamedReadOperation::GetResourceSnapshot => "GetResourceSnapshot",
        NamedReadOperation::GetUserAutomationState => "GetUserAutomationState",
        NamedReadOperation::GetInstrumentRegistryState => "GetInstrumentRegistryState",
        NamedReadOperation::GetExperienceBankRange => "GetExperienceBankRange",
        NamedReadOperation::GetAgentFeedbackRange => "GetAgentFeedbackRange",
        NamedReadOperation::GetBlackboardItem => "GetBlackboardItem",
        NamedReadOperation::GetLearningRecordRange => "GetLearningRecordRange",
        NamedReadOperation::GetScopeRevisionView => "GetScopeRevisionView",
        NamedReadOperation::GetOrderingHeads => "GetOrderingHeads",
        NamedReadOperation::GetTaskState => "GetTaskState",
        NamedReadOperation::GetCampaignSourceRevision => "GetCampaignSourceRevision",
        NamedReadOperation::GetCampaignLearningStateView => "GetCampaignLearningStateView",
        NamedReadOperation::GetCurrentEpistemicPosition => "GetCurrentEpistemicPosition",
        NamedReadOperation::GetEvidencePack => "GetEvidencePack",
        NamedReadOperation::GetUnderstandingProjectionInputs => "GetUnderstandingProjectionInputs",
        NamedReadOperation::GetAttentionAndProblems => "GetAttentionAndProblems",
        NamedReadOperation::GetModuleCatalogState => "GetModuleCatalogState",
        NamedReadOperation::GetCapabilityEvidenceState => "GetCapabilityEvidenceState",
        NamedReadOperation::GetConformanceState => "GetConformanceState",
        NamedReadOperation::GetMailbox => "GetMailbox",
        NamedReadOperation::GetAuditRange => "GetAuditRange",
        NamedReadOperation::ResolveWriteReceipt => "ResolveWriteReceipt",
        NamedReadOperation::GetAuthorityRevocationHistory => "GetAuthorityRevocationHistory",
        NamedReadOperation::GetCapabilityEvidenceRecordRange => "GetCapabilityEvidenceRecordRange",
        NamedReadOperation::GetTaskContractAcceptanceSet => "GetTaskContractAcceptanceSet",
    }
}

/// Resolves a canonical operation name back to its closed read variant.
#[must_use]
pub const fn named_read_operation_by_name(name: &str) -> Option<NamedReadOperation> {
    // `&str` equality is `const`-compatible; keep this a closed match so a
    // renamed variant is a compile-time event, not a silent miss.
    match name.as_bytes() {
        b"GetRevisionHeads" => Some(NamedReadOperation::GetRevisionHeads),
        b"GetScopeRevisionView" => Some(NamedReadOperation::GetScopeRevisionView),
        b"GetOrderingHeads" => Some(NamedReadOperation::GetOrderingHeads),
        b"GetTaskState" => Some(NamedReadOperation::GetTaskState),
        b"GetCampaignSourceRevision" => Some(NamedReadOperation::GetCampaignSourceRevision),
        b"GetCampaignLearningStateView" => Some(NamedReadOperation::GetCampaignLearningStateView),
        b"GetCurrentEpistemicPosition" => Some(NamedReadOperation::GetCurrentEpistemicPosition),
        b"GetEvidencePack" => Some(NamedReadOperation::GetEvidencePack),
        b"GetUnderstandingProjectionInputs" => {
            Some(NamedReadOperation::GetUnderstandingProjectionInputs)
        }
        b"GetAttentionAndProblems" => Some(NamedReadOperation::GetAttentionAndProblems),
        b"GetModuleCatalogState" => Some(NamedReadOperation::GetModuleCatalogState),
        b"GetCapabilityEvidenceState" => Some(NamedReadOperation::GetCapabilityEvidenceState),
        b"GetConformanceState" => Some(NamedReadOperation::GetConformanceState),
        b"GetMailbox" => Some(NamedReadOperation::GetMailbox),
        b"GetAuditRange" => Some(NamedReadOperation::GetAuditRange),
        b"ResolveWriteReceipt" => Some(NamedReadOperation::ResolveWriteReceipt),
        b"GetAuthorityRevocationHistory" => Some(NamedReadOperation::GetAuthorityRevocationHistory),
        b"GetNotificationState" => Some(NamedReadOperation::GetNotificationState),
        b"GetReactiveInjectionState" => Some(NamedReadOperation::GetReactiveInjectionState),
        b"GetResourceSnapshot" => Some(NamedReadOperation::GetResourceSnapshot),
        b"GetUserAutomationState" => Some(NamedReadOperation::GetUserAutomationState),
        b"GetInstrumentRegistryState" => Some(NamedReadOperation::GetInstrumentRegistryState),
        b"GetExperienceBankRange" => Some(NamedReadOperation::GetExperienceBankRange),
        b"GetAgentFeedbackRange" => Some(NamedReadOperation::GetAgentFeedbackRange),
        b"GetBlackboardItem" => Some(NamedReadOperation::GetBlackboardItem),
        b"GetLearningRecordRange" => Some(NamedReadOperation::GetLearningRecordRange),
        b"GetCapabilityEvidenceRecordRange" => {
            Some(NamedReadOperation::GetCapabilityEvidenceRecordRange)
        }
        b"GetTaskContractAcceptanceSet" => Some(NamedReadOperation::GetTaskContractAcceptanceSet),
        _ => None,
    }
}

/// Returns the canonical operation name for a closed mutation variant.
#[must_use]
pub const fn named_mutation_operation_name(operation: NamedMutationOperation) -> &'static str {
    match operation {
        NamedMutationOperation::CaptureObservation => "CaptureObservation",
        NamedMutationOperation::ApplyEpistemicRevision => "ApplyEpistemicRevision",
        NamedMutationOperation::UpdateTaskState => "UpdateTaskState",
        NamedMutationOperation::ApplySwarmOwnerRevisions => "ApplySwarmOwnerRevisions",
        NamedMutationOperation::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
        NamedMutationOperation::ReconcileRecovery => "ReconcileRecovery",
        NamedMutationOperation::ApplyProblemOwnerState => "ApplyProblemOwnerState",
        NamedMutationOperation::RecordFinishDecision => "RecordFinishDecision",
        NamedMutationOperation::RecordFinishEvidence => "RecordFinishEvidence",
        NamedMutationOperation::RecordModuleCatalogSnapshot => "RecordModuleCatalogSnapshot",
        NamedMutationOperation::CommitBudgetConsumption => "CommitBudgetConsumption",
        NamedMutationOperation::AppendAuditEvent => "AppendAuditEvent",
        NamedMutationOperation::RecordAuthorityRevocation => "RecordAuthorityRevocation",
        NamedMutationOperation::ApplyErasure => "ApplyErasure",
        NamedMutationOperation::ApplyNotificationState => "ApplyNotificationState",
        NamedMutationOperation::ApplyReactiveInjectionState => "ApplyReactiveInjectionState",
        NamedMutationOperation::ApplyResourceSnapshot => "ApplyResourceSnapshot",
        NamedMutationOperation::ApplyUserAutomationState => "ApplyUserAutomationState",
        NamedMutationOperation::ApplyInstrumentRegistryState => "ApplyInstrumentRegistryState",
        NamedMutationOperation::CommitExperienceBank => "CommitExperienceBank",
        NamedMutationOperation::CommitAgentFeedback => "CommitAgentFeedback",
        NamedMutationOperation::ApplyBlackboardItem => "ApplyBlackboardItem",
        NamedMutationOperation::AdmitMailboxMessage => "AdmitMailboxMessage",
        NamedMutationOperation::RecordLearningRecord => "RecordLearningRecord",
        NamedMutationOperation::RecordCapabilityEvidenceRecord => "RecordCapabilityEvidenceRecord",
        NamedMutationOperation::RecordTaskContractAcceptanceSet => {
            "RecordTaskContractAcceptanceSet"
        }
        NamedMutationOperation::AdmitWork => "AdmitWork",
    }
}

/// Resolves a canonical operation name back to its closed mutation variant.
#[must_use]
pub const fn named_mutation_operation_by_name(name: &str) -> Option<NamedMutationOperation> {
    match name.as_bytes() {
        b"CaptureObservation" => Some(NamedMutationOperation::CaptureObservation),
        b"ApplyEpistemicRevision" => Some(NamedMutationOperation::ApplyEpistemicRevision),
        b"UpdateTaskState" => Some(NamedMutationOperation::UpdateTaskState),
        b"ApplySwarmOwnerRevisions" => Some(NamedMutationOperation::ApplySwarmOwnerRevisions),
        b"ApplyLifecyclePolicy" => Some(NamedMutationOperation::ApplyLifecyclePolicy),
        b"ReconcileRecovery" => Some(NamedMutationOperation::ReconcileRecovery),
        b"ApplyProblemOwnerState" => Some(NamedMutationOperation::ApplyProblemOwnerState),
        b"RecordFinishDecision" => Some(NamedMutationOperation::RecordFinishDecision),
        b"RecordFinishEvidence" => Some(NamedMutationOperation::RecordFinishEvidence),
        b"RecordModuleCatalogSnapshot" => Some(NamedMutationOperation::RecordModuleCatalogSnapshot),
        b"CommitBudgetConsumption" => Some(NamedMutationOperation::CommitBudgetConsumption),
        b"AppendAuditEvent" => Some(NamedMutationOperation::AppendAuditEvent),
        b"RecordAuthorityRevocation" => Some(NamedMutationOperation::RecordAuthorityRevocation),
        b"ApplyErasure" => Some(NamedMutationOperation::ApplyErasure),
        b"ApplyNotificationState" => Some(NamedMutationOperation::ApplyNotificationState),
        b"ApplyReactiveInjectionState" => Some(NamedMutationOperation::ApplyReactiveInjectionState),
        b"ApplyResourceSnapshot" => Some(NamedMutationOperation::ApplyResourceSnapshot),
        b"ApplyUserAutomationState" => Some(NamedMutationOperation::ApplyUserAutomationState),
        b"ApplyInstrumentRegistryState" => {
            Some(NamedMutationOperation::ApplyInstrumentRegistryState)
        }
        b"CommitExperienceBank" => Some(NamedMutationOperation::CommitExperienceBank),
        b"CommitAgentFeedback" => Some(NamedMutationOperation::CommitAgentFeedback),
        b"ApplyBlackboardItem" => Some(NamedMutationOperation::ApplyBlackboardItem),
        b"AdmitMailboxMessage" => Some(NamedMutationOperation::AdmitMailboxMessage),
        b"RecordLearningRecord" => Some(NamedMutationOperation::RecordLearningRecord),
        b"RecordCapabilityEvidenceRecord" => {
            Some(NamedMutationOperation::RecordCapabilityEvidenceRecord)
        }
        b"RecordTaskContractAcceptanceSet" => {
            Some(NamedMutationOperation::RecordTaskContractAcceptanceSet)
        }
        b"AdmitWork" => Some(NamedMutationOperation::AdmitWork),
        _ => None,
    }
}

/// Returns the owner-approved parameter declarations for one read operation.
///
/// `ResolveWriteReceipt` declares the required `operation_id` parameter and
/// `GetEvidencePack` declares the required bounded exact selectors (the
/// exact captured-observation `subject` and the explicit `max_records`
/// bound); `GetAuthorityRevocationHistory` declares the required bounded
/// exact selectors (the exact revoked `origin_ref` and the explicit
/// `max_records` bound); `GetCurrentEpistemicPosition` declares the required
/// `position` selector; `GetTaskState` declares the required exact `task_id`
/// plus the explicit `max_records` bound; `GetAttentionAndProblems` declares
/// the optional exact `problem_id` filter plus the required `max_records`
/// bound; `GetUnderstandingProjectionInputs` declares the required exact
/// `selector` plus the required `max_records` bound; `GetCapabilityEvidenceState`
/// declares the required exact `skill_id` plus the required `max_records`
/// bound; `GetNotificationState` declares the optional `scope` filter, the
/// optional exact `dedup_key` selector, the required `include_resolved` flag,
/// the required decimal `page_limit` bound, and the optional opaque `cursor`;
/// `GetReactiveInjectionState` declares the required exact `session_id`
/// selector; `GetResourceSnapshot` declares the required exact `uri`
/// selector; `GetUserAutomationState` declares the required `query`
/// discriminator, the optional exact `automation_id` selector, the required
/// `include_retired` flag, and the required decimal `max_records` bound;
/// `GetExperienceBankRange` and `GetAgentFeedbackRange` declare the required
/// decimal `max_records` bound plus the optional opaque `cursor`
/// continuation selector (issue #223; scope arrives through the typed
/// `scope_id` request field, mirroring `GetEvidencePack`);
/// `GetBlackboardItem` declares the exact `task_id` and `item_id` selectors
/// (issue #1822);
/// `GetLearningRecordRange` declares the required decimal `max_records`
/// bound, the optional closed `record_kind` filter, plus the optional
/// opaque `cursor` continuation selector (issue #1868; scope arrives
/// through the typed `scope_id` request field, mirroring `GetEvidencePack`);
/// `GetAuditRange` declares the optional opaque `cursor` continuation
/// selector (issue #223; absent cursors read from the start);
/// `GetTaskContractAcceptanceSet` declares the exact `task_id` plus the exact
/// `task_revision` the caller was admitted against (issue #1741, I7.9);
/// every other variant declares none, so any supplied parameter fails closed. Variants without a catalogue entry never
/// reach this table: they fail as [`StoreError::UnknownOperation`] first.
#[must_use]
pub const fn declared_read_parameters(
    operation: NamedReadOperation,
) -> &'static [ParameterDeclaration] {
    match operation {
        NamedReadOperation::ResolveWriteReceipt => &RESOLVE_WRITE_RECEIPT_PARAMETERS,
        NamedReadOperation::GetEvidencePack => &GET_EVIDENCE_PACK_PARAMETERS,
        NamedReadOperation::GetAuthorityRevocationHistory => {
            &GET_AUTHORITY_REVOCATION_HISTORY_PARAMETERS
        }
        NamedReadOperation::GetCurrentEpistemicPosition => &CURRENT_POSITION_PARAMETERS,
        NamedReadOperation::GetTaskState => &GET_TASK_STATE_PARAMETERS,
        NamedReadOperation::GetCampaignSourceRevision => &GET_CAMPAIGN_SOURCE_REVISION_PARAMETERS,
        NamedReadOperation::GetCampaignLearningStateView => {
            &GET_CAMPAIGN_LEARNING_STATE_VIEW_PARAMETERS
        }
        NamedReadOperation::GetAttentionAndProblems => &GET_ATTENTION_AND_PROBLEMS_PARAMETERS,
        NamedReadOperation::GetUnderstandingProjectionInputs => {
            &GET_UNDERSTANDING_PROJECTION_INPUTS_PARAMETERS
        }
        NamedReadOperation::GetCapabilityEvidenceState => &GET_CAPABILITY_EVIDENCE_STATE_PARAMETERS,
        NamedReadOperation::GetNotificationState => &GET_NOTIFICATION_STATE_PARAMETERS,
        NamedReadOperation::GetReactiveInjectionState => &GET_REACTIVE_LEDGER_PARAMETERS,
        NamedReadOperation::GetResourceSnapshot => &GET_RESOURCE_SNAPSHOT_PARAMETERS,
        NamedReadOperation::GetUserAutomationState => &GET_USER_AUTOMATION_PARAMETERS,
        NamedReadOperation::GetExperienceBankRange | NamedReadOperation::GetAgentFeedbackRange => {
            &GET_EXPERIENCE_RANGE_PARAMETERS
        }
        NamedReadOperation::GetBlackboardItem => &BLACKBOARD_ITEM_LOOKUP_PARAMETERS,
        NamedReadOperation::GetLearningRecordRange => &GET_LEARNING_RANGE_PARAMETERS,
        NamedReadOperation::GetCapabilityEvidenceRecordRange => {
            &GET_CAPABILITY_EVIDENCE_RECORD_RANGE_PARAMETERS
        }
        NamedReadOperation::GetAuditRange => &GET_AUDIT_RANGE_PARAMETERS,
        NamedReadOperation::GetTaskContractAcceptanceSet => {
            &GET_TASK_CONTRACT_ACCEPTANCE_SET_PARAMETERS
        }
        NamedReadOperation::GetRevisionHeads
        | NamedReadOperation::GetScopeRevisionView
        | NamedReadOperation::GetOrderingHeads
        | NamedReadOperation::GetModuleCatalogState
        | NamedReadOperation::GetConformanceState
        | NamedReadOperation::GetMailbox
        | NamedReadOperation::GetInstrumentRegistryState => &NO_PARAMETERS,
    }
}

/// Returns the owner-approved parameter declarations for one mutation.
///
/// `CaptureObservation` declares the required owner-shaped `subject` string;
/// `AppendAuditEvent` declares the six required receipt-bound fields
/// (`operation_id`, `idempotency_key`, `session_id`, `access_digest`,
/// `action_digest`, `expected_revision`); `ApplyLifecyclePolicy` declares the
/// six required lifecycle-policy fields (`action`, `base_view_digest`,
/// `candidate_digest`, `candidate_package_digest`, `skill_id`,
/// `verifier_ref`); `ReconcileRecovery` declares the ten required
/// problem-leg recovery fields (`problem_id`, `expected_problem_revision`,
/// `attempt_digest`, `effect_digest`, `operation_manifest_digest`,
/// `artifact_binding_digest`, `fence_digest`, `observation_operation_id`,
/// `observation_record_id`, `observation_request_digest`); `UpdateTaskState`
/// declares the six required-except-`from` task-control fields (`task_id`,
/// `event_id`, optional `from`, `to`, `expected_revision`, `actor_ref`);
/// `RecordAuthorityRevocation` declares the seven required
/// authority-revocation fields (`origin_ref`, `closure_id`,
/// `closure_revision`, `affected_digest`, `affected_count`,
/// `invalidation_reason`, `fence_digest`); `ApplyEpistemicRevision` declares
/// the required `revision` epistemic-revision payload; `ApplyErasure`
/// declares the five required canonical-erasure fields (`subject`,
/// `surfaces`, `reason`, `requester`, `erasure_operation_id`);
/// `ApplyNotificationState` declares the leg discriminator, the always-present
/// `dedup_key`, and the conditionally-required leg payloads (`record_json`,
/// `source_receipt_json`, `delivery_json`, `channel`, `notification_id`,
/// `principal`, `disposition`, `authorization_json`; leg completeness is
/// enforced by the notification-state contract);
/// `ApplyReactiveInjectionState` declares the required `session_id` plus the
/// opaque `ledger_json` snapshot (contract/bounds enforced by the
/// reactive-state contract); `ApplyResourceSnapshot` declares the required
/// `uri`, `content_sha256`, and `content_base64` (grammar/digest agreement
/// enforced by the reactive-state contract);
/// `ApplyUserAutomationState` declares the leg discriminator, the
/// always-present `automation_id`, and the conditionally-required leg
/// payloads (`revision`, `revision_json`, `previous_revision`,
/// `configuration_state`, `normalization_receipt_json`, `occurrence_id`,
/// `invocation_json`; leg completeness is enforced by the
/// automation-state contract);
/// `CommitExperienceBank` and `CommitAgentFeedback` declare the six
/// required commit fields (`record_json`, `record_digest`,
/// `record_revision` as its decimal string, `scope_digest`,
/// `fence_digest`, `idempotency_key`; family bound by the operation
/// variant, digest re-proof at the Governor read edge);
/// `ApplyBlackboardItem` declares the required typed `revision` candidate
/// and predecessor CAS (issue #1822);
/// `AdmitMailboxMessage` declares the required typed `admission` message
/// and stream-head CAS (issue #1820);
/// `RecordLearningRecord` declares the seven required commit fields
/// (`record_kind` over the closed learning-kind set, `handle`,
/// `record_json`, `record_digest`, `scope_digest`, `fence_digest`,
/// `idempotency_key`; digest IS the immutable revision identity);
/// `ApplyInstrumentRegistryState` declares the opaque versioned
/// `snapshot_json` string; its expected current revision comes from the
/// prepared transition's revision-head CAS. It remains unadvertised pending
/// canonical store handlers. Every other variant declares none,
/// so any supplied parameter fails closed. Variants without a catalogue entry
/// never reach this table: they fail as [`StoreError::UnknownOperation`] first.
#[must_use]
pub const fn declared_mutation_parameters(
    operation: NamedMutationOperation,
) -> &'static [ParameterDeclaration] {
    match operation {
        NamedMutationOperation::CaptureObservation => &CAPTURE_OBSERVATION_PARAMETERS,
        NamedMutationOperation::AppendAuditEvent => &APPEND_AUDIT_EVENT_PARAMETERS,
        NamedMutationOperation::ApplyLifecyclePolicy => &APPLY_LIFECYCLE_POLICY_PARAMETERS,
        NamedMutationOperation::ReconcileRecovery => &RECONCILE_RECOVERY_PARAMETERS,
        NamedMutationOperation::ApplyProblemOwnerState => &APPLY_PROBLEM_OWNER_STATE_PARAMETERS,
        NamedMutationOperation::RecordFinishDecision => &RECORD_FINISH_DECISION_PARAMETERS,
        NamedMutationOperation::RecordFinishEvidence => &RECORD_FINISH_EVIDENCE_PARAMETERS,
        NamedMutationOperation::RecordModuleCatalogSnapshot => {
            &RECORD_MODULE_CATALOG_SNAPSHOT_PARAMETERS
        }
        NamedMutationOperation::CommitBudgetConsumption => {
            &COMMIT_BUDGET_CONSUMPTION_PARAMETERS
        }
        NamedMutationOperation::UpdateTaskState => &UPDATE_TASK_STATE_PARAMETERS,
        NamedMutationOperation::ApplySwarmOwnerRevisions => &APPLY_SWARM_OWNER_REVISION_PARAMETERS,
        NamedMutationOperation::ApplyBlackboardItem => &APPLY_BLACKBOARD_ITEM_PARAMETERS,
        NamedMutationOperation::AdmitMailboxMessage => &ADMIT_MAILBOX_ITEM_PARAMETERS,
        NamedMutationOperation::RecordAuthorityRevocation => {
            &RECORD_AUTHORITY_REVOCATION_PARAMETERS
        }
        NamedMutationOperation::ApplyErasure => &APPLY_ERASURE_PARAMETERS,
        NamedMutationOperation::ApplyEpistemicRevision => &EPISTEMIC_REVISION_PARAMETERS,
        NamedMutationOperation::ApplyNotificationState => &APPLY_NOTIFICATION_STATE_PARAMETERS,
        NamedMutationOperation::ApplyReactiveInjectionState => &APPLY_REACTIVE_LEDGER_PARAMETERS,
        NamedMutationOperation::ApplyResourceSnapshot => &APPLY_RESOURCE_SNAPSHOT_PARAMETERS,
        NamedMutationOperation::ApplyUserAutomationState => &APPLY_USER_AUTOMATION_PARAMETERS,
        NamedMutationOperation::ApplyInstrumentRegistryState => {
            &APPLY_INSTRUMENT_REGISTRY_PARAMETERS
        }
        NamedMutationOperation::CommitExperienceBank
        | NamedMutationOperation::CommitAgentFeedback => &COMMIT_EXPERIENCE_PARAMETERS,
        NamedMutationOperation::RecordLearningRecord => &COMMIT_LEARNING_PARAMETERS,
        NamedMutationOperation::RecordCapabilityEvidenceRecord => {
            &COMMIT_CAPABILITY_EVIDENCE_PARAMETERS
        }
        NamedMutationOperation::RecordTaskContractAcceptanceSet => {
            &RECORD_TASK_CONTRACT_ACCEPTANCE_SET_PARAMETERS
        }
        NamedMutationOperation::AdmitWork => &ADMIT_WORK_PARAMETERS,
    }
}

/// Serializable parameter-schema projection stored in each manifest entry.
///
/// The stored projection is what [`parameter_schema_digest`] binds, so the
/// entry digest transitively binds the exact owner-approved schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParameterSchemaField {
    /// Exact parameter name.
    pub name: String,
    /// Stable [`ParameterShape`] code.
    pub shape: String,
    /// Whether the parameter must be present.
    pub required: bool,
}

/// Projects the declared parameters of one read into the stored schema form.
#[must_use]
pub fn project_parameter_schema(operation: NamedReadOperation) -> Vec<ParameterSchemaField> {
    declared_read_parameters(operation)
        .iter()
        .map(|declaration| ParameterSchemaField {
            name: declaration.name.to_owned(),
            shape: declaration.shape.code().to_owned(),
            required: declaration.required,
        })
        .collect()
}

/// Projects the declared parameters of one mutation into the stored schema form.
#[must_use]
pub fn project_mutation_parameter_schema(
    operation: NamedMutationOperation,
) -> Vec<ParameterSchemaField> {
    declared_mutation_parameters(operation)
        .iter()
        .map(|declaration| ParameterSchemaField {
            name: declaration.name.to_owned(),
            shape: declaration.shape.code().to_owned(),
            required: declaration.required,
        })
        .collect()
}

/// Computes the schema digest bound into a manifest entry.
///
/// The digest binds the canonical bytes of the stored parameter-schema
/// projection, so any added, removed, or reshaped parameter changes the
/// entry digest and therefore the catalogue set digest.
pub fn parameter_schema_digest(schema: &[ParameterSchemaField]) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(&schema)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Verifies that one owner-approved declaration cannot become a second
/// payload-encoding owner (issue #10).
///
/// Receipt/identifier/control-identity names (every entry of
/// [`CONTROL_FIELD_DENYLIST`]) may supersede the generic deny-list only as
/// scalar identity strings ([`ParameterShape::OperationId`] or
/// [`ParameterShape::Subject`]): a structured shape on such a name would
/// transport arbitrary payloads outside the
/// [`ExactJsonBytes`](crate::ExactJsonBytes) authority. Structured
/// owner-approved shapes stay allowed on non-control names, where their own
/// closed contract (never the receipt path) owns the bytes. Every future
/// shape must be classified in the match below before it can travel any
/// receipt/identifier path; an unclassified shape is a compile error here,
/// not a silent pass.
pub fn verify_declaration_holds_no_payload_encoding(
    declaration: &ParameterDeclaration,
) -> Result<(), StoreError> {
    let structured = match declaration.shape {
        ParameterShape::OperationId
        | ParameterShape::Subject
        | ParameterShape::BlackboardItemLookup => false,
        ParameterShape::EpistemicRevision
        | ParameterShape::NotificationState
        | ParameterShape::CampaignSourceLookup
        | ParameterShape::CampaignSourcePublications
        | ParameterShape::CampaignViewLookup
        | ParameterShape::SwarmOwnerRevision
        | ParameterShape::BlackboardItemRevision
        | ParameterShape::MailboxItemAdmission
        | ParameterShape::InstrumentRegistrySnapshot
        | ParameterShape::ProblemOwnerState
        | ParameterShape::TaskContractAcceptanceRecord
        | ParameterShape::WorkAdmission
        | ParameterShape::WorkAdmissionCanonicalSnapshot => true,
        ParameterShape::BudgetConsumption | ParameterShape::BudgetOwnerSnapshot => true,
        ParameterShape::WorkAdmissionCanonicalRevision => false,
    };
    if structured && CONTROL_FIELD_DENYLIST.contains(&declaration.name) {
        return Err(StoreError::InvalidField {
            field: "payload.control_field",
            reason: "receipt/identifier path must not own a payload encoding",
        });
    }
    Ok(())
}

/// Validates read parameters against the owner-approved typed declaration.
///
/// Membership is exact: an undeclared name fails, with control-denylisted
/// names reported as control substitution and any other undeclared name
/// reported as unknown. Declared values must match their declared shape;
/// required parameters must be present. This runs pre-dispatch and issues
/// no authority.
pub fn validate_typed_read_parameters(
    operation: NamedReadOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let declared = declared_read_parameters(operation);
    for (name, value) in parameters {
        if let Some(declaration) = declared.iter().find(|field| field.name == name.as_str()) {
            verify_declaration_holds_no_payload_encoding(declaration)?;
            check_declared_shape(declaration, value)?;
        } else {
            if CONTROL_FIELD_DENYLIST.contains(&name.as_str()) {
                return Err(StoreError::InvalidField {
                    field: "payload.control_field",
                    reason: "payload must not override a control field",
                });
            }
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "unknown parameter for operation",
            });
        }
    }
    for declaration in declared {
        if declaration.required && !parameters.contains_key(declaration.name) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            });
        }
    }
    Ok(())
}

/// Validates mutation parameters against the owner-approved typed declaration.
///
/// Same closed contract as [`validate_typed_read_parameters`]: exact
/// membership, control-substitution rejection, required presence, and declared
/// shape. Runs pre-dispatch and issues no authority.
pub fn validate_typed_mutation_parameters(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let declared = declared_mutation_parameters(operation);
    for (name, value) in parameters {
        if let Some(declaration) = declared.iter().find(|field| field.name == name.as_str()) {
            verify_declaration_holds_no_payload_encoding(declaration)?;
            check_declared_shape(declaration, value)?;
        } else {
            if CONTROL_FIELD_DENYLIST.contains(&name.as_str()) {
                return Err(StoreError::InvalidField {
                    field: "payload.control_field",
                    reason: "payload must not override a control field",
                });
            }
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "unknown parameter for operation",
            });
        }
    }
    for declaration in declared {
        if declaration.required && !parameters.contains_key(declaration.name) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            });
        }
    }
    Ok(())
}

fn check_declared_shape(
    declaration: &ParameterDeclaration,
    value: &Value,
) -> Result<(), StoreError> {
    match declaration.shape {
        ParameterShape::EpistemicRevision => {
            let payload: crate::epistemic_revision::EpistemicRevisionPayload =
                serde_json::from_value(value.clone())
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
            payload.validate()
        }
        ParameterShape::OperationId => {
            let text = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "operation_id must be a string operation identity",
            })?;
            OperationId::new(text).map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "operation_id must be a valid operation identity",
            })?;
            Ok(())
        }
        ParameterShape::Subject => {
            let text = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "subject must be a non-blank string",
            })?;
            // Same store text rule as every other identifier boundary
            // (non-blank, no control characters); stated inline because the
            // generic text helper lives in the crate root.
            if text.trim().is_empty() || text.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "subject must be a non-blank string",
                });
            }
            Ok(())
        }
        ParameterShape::NotificationState => {
            if !value.is_object() {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "notification-state payload must be a JSON object",
                });
            }
            Ok(())
        }
        ParameterShape::InstrumentRegistrySnapshot => validate_instrument_registry_snapshot(value),
        ParameterShape::CampaignSourceLookup => {
            let lookup: crate::CampaignSourceRevisionLookup = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            lookup.validate()
        }
        ParameterShape::CampaignSourcePublications => validate_campaign_source_publications(value),
        ParameterShape::CampaignViewLookup => {
            let lookup: crate::CampaignLearningStateViewLookup =
                serde_json::from_value(value.clone())
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
            lookup.validate()
        }
        ParameterShape::SwarmOwnerRevision => {
            let record: crate::SwarmOwnerRevision = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            record.validate()
        }
        ParameterShape::BlackboardItemLookup => {
            validate_blackboard_lookup_selector(declaration, value)
        }
        ParameterShape::BlackboardItemRevision => {
            let revision: crate::BlackboardItemRevision = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            revision.validate()
        }
        ParameterShape::MailboxItemAdmission => {
            let admission: crate::MailboxItemAdmission = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            admission.validate()
        }
        ParameterShape::ProblemOwnerState => {
            // The candidate record's own bindings are compared by the
            // problem owner-state contract, which needs the whole parameter map
            // (the record alone cannot see the presented identity, expected
            // revision or source Signal it must agree with). Shape only here.
            if value.is_object() {
                Ok(())
            } else {
                Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "problem owner transition candidate record must be a JSON object",
                })
            }
        }
        ParameterShape::TaskContractAcceptanceRecord => {
            // The record is self-contained: its own task identity, task
            // revision, acceptance digest, obligation list and fence are the
            // whole contract, so the existing closed acceptance-set validator
            // is the complete check. There is no sibling parameter to compare
            // it against, and inventing one would be a second scheme.
            let record: crate::TaskContractAcceptanceRecord = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            record.validate()
        }
        ParameterShape::WorkAdmission => {
            let record: crate::WorkAdmissionRecord = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            record.validate()
        }
        ParameterShape::WorkAdmissionCanonicalRevision => {
            let revision = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "expected_canonical_revision must be a decimal string",
            })?;
            let parsed = revision.parse::<u64>().map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "expected_canonical_revision must be a canonical decimal revision",
            })?;
            if parsed.to_string() != revision {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "expected_canonical_revision must be a canonical decimal revision",
                });
            }
            Ok(())
        }
        ParameterShape::WorkAdmissionCanonicalSnapshot => {
            let snapshot = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "canonical_owner_snapshot_json must be a JSON string",
            })?;
            if snapshot.is_empty() || snapshot.len() > crate::MAX_RECOVERY_RECORD_BYTES {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "canonical_owner_snapshot_json must be non-empty and bounded",
                });
            }
            Ok(())
        }
        ParameterShape::BudgetConsumption => {
            let record: crate::BudgetConsumptionRecord = serde_json::from_value(value.clone())
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            record.validate()
        }
        ParameterShape::BudgetOwnerSnapshot => {
            let snapshot_json = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "budget_owner_snapshot_json must be a canonical JSON string",
            })?;
            if snapshot_json.is_empty() || snapshot_json.len() > crate::MAX_RECOVERY_RECORD_BYTES {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "budget owner snapshot must be non-empty and bounded",
                });
            }
            let snapshot: Value = serde_json::from_str(snapshot_json)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            let bytes = canonical_json_bytes(&snapshot)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            if String::from_utf8(bytes).ok().as_deref() != Some(snapshot_json)
                || snapshot.get("state_fence").is_none()
                || snapshot.get("revision").and_then(Value::as_u64).is_none()
            {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "budget owner snapshot must be canonical and retain its fence/revision",
                });
            }
            Ok(())
        }
    }
}

/// Validates the `campaign_source_publications` parameter.
///
/// Split out of [`check_declared_shape`] because it is the only declared shape
/// whose validation is real work rather than shape dispatch: it decodes the
/// publication list, bounds it, validates every publication, and refuses a
/// repeated `(role, owner, record)` identity. Keeping it named says what it
/// decides; inlining it in the dispatch match buried that under six other arms.
fn validate_campaign_source_publications(value: &Value) -> Result<(), StoreError> {
    let publications: Vec<crate::CampaignSourcePublication> = serde_json::from_value(value.clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if publications.is_empty() || publications.len() > 64 {
        return Err(StoreError::InvalidField {
            field: "campaign_source_publications",
            reason: "must contain between one and 64 publications",
        });
    }
    let mut keys = std::collections::BTreeSet::new();
    for publication in &publications {
        publication.validate()?;
        let key = serde_json::to_string(&(
            publication.record.role,
            &publication.record.owner_id,
            &publication.record.record_id,
        ))
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if !keys.insert(key) {
            return Err(StoreError::Duplicate {
                field: "campaign_source_publications.key",
            });
        }
    }
    Ok(())
}

/// Decodes one validated `ApplyInstrumentRegistryState` parameter map.
///
/// Runs the shared snapshot acceptance boundary first (JSON string with
/// the supported schema/version), then returns the verbatim snapshot
/// bytes. Both store contours share this decoder so neither backend
/// interprets instrument admission on its own.
pub fn decode_instrument_registry_mutation(
    parameters: &BTreeMap<String, Value>,
) -> Result<String, StoreError> {
    let value = parameters
        .get("snapshot_json")
        .ok_or(StoreError::InvalidField {
            field: "instrument_registry.snapshot_json",
            reason: "instrument registry mutation requires snapshot_json",
        })?;
    validate_instrument_registry_snapshot(value)?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(StoreError::InvalidField {
            field: "instrument_registry.snapshot_json",
            reason: "instrument registry snapshot must be a JSON string",
        })
}

fn validate_instrument_registry_snapshot(value: &Value) -> Result<(), StoreError> {
    let snapshot_json = value.as_str().ok_or(StoreError::InvalidField {
        field: "operation.parameter",
        reason: "instrument registry snapshot must be a JSON string",
    })?;
    let snapshot: Value = serde_json::from_str(snapshot_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if snapshot.get("schema").and_then(Value::as_str) != Some("eliot.instrument.registry-snapshot")
        || snapshot.get("version").and_then(Value::as_str) != Some("1.0.0")
    {
        return Err(StoreError::InvalidField {
            field: "instrument_registry.snapshot_json",
            reason: "unsupported instrument registry snapshot schema/version",
        });
    }
    Ok(())
}

fn validate_blackboard_lookup_selector(
    declaration: &ParameterDeclaration,
    value: &Value,
) -> Result<(), StoreError> {
    let text = value.as_str().ok_or(StoreError::InvalidField {
        field: "operation.parameter",
        reason: "blackboard identity selector must be a string",
    })?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "operation.parameter",
            reason: "blackboard identity selector must be non-blank text",
        });
    }
    if declaration.name == "task_id" {
        eliot_contracts::TaskId::new(text).map_err(StoreError::Foundation)?;
    }
    Ok(())
}
