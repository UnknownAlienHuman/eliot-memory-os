//! Generated per-operation store manifest catalogue (slice C1, issue #19).
//!
//! This module owns the single Rust declaration table that generates one
//! [`NamedOperationManifest`](crate::NamedOperationManifest) descriptor per
//! activated operation. The table activates the reads with
//! proven adapter handlers, parameter shapes, and consumers on base
//! (`GetRevisionHeads`, `GetOrderingHeads`, `GetScopeRevisionView`,
//! `ResolveWriteReceipt`, `GetEvidencePack`, `GetCurrentEpistemicPosition`,
//! plus T11.3 `GetTaskState`, `GetAttentionAndProblems`,
//! `GetUnderstandingProjectionInputs`, `GetCapabilityEvidenceState`, plus
//! issue #1780 `GetNotificationState`, plus issue #1941 C4
//! `GetReactiveInjectionState` and `GetResourceSnapshot`, plus issue #1779
//! `GetUserAutomationState`), plus issue #223 the two experience range
//! reads (`GetExperienceBankRange`, `GetAgentFeedbackRange`, scope-addressed
//! with proven adapter handlers in this slice), plus issue #1868 the
//! learning-record range read (`GetLearningRecordRange`, scope-addressed
//! with the closed record-kind filter and proven adapter handlers in this
//! slice), and the activated audit
//! range read (`GetAuditRange`: fence-gated envelope-candidate range over
//! durable capture evidence with proven adapter handlers in this slice), the four `CaptureObservation` /
//! `AppendAuditEvent` / `ApplyLifecyclePolicy` mutations (AUD-C01:
//! `CaptureObservation` and `AppendAuditEvent` persist
//! `TransitionClass::CaptureCandidate` with the `EffectClass::Candidate`
//! ceiling; `ApplyLifecyclePolicy` persists `TransitionClass::LifecyclePolicy`
//! with the `EffectClass::ReversibleMutation` ceiling; all three carry the
//! owner-approved schemas) plus the `ReconcileRecovery` mutation (AUD-C01:
//! persists `TransitionClass::RecoverySchema` with the
//! `EffectClass::ReversibleMutation` ceiling and the owner-approved ten-field
//! problem-leg recovery schema emitted by the Governor doctor verification
//! envelope), plus the `UpdateTaskState` mutation (AUD-C01: persists
//! `TransitionClass::TaskControl` with the `EffectClass::ReversibleMutation`
//! ceiling and the owner-approved six-field task-control schema emitted by
//! the Governor task lifecycle envelope
//! (`crates/governor/eliot-governor/src/task_lifecycle.rs`, `task_envelope`)),
//! plus the `RecordFinishDecision` mutation (issue #325: persists the
//! Governor-owned opaque finish receipt through the existing `RecoverySchema`
//! owner path),
//! plus the `ApplyEpistemicRevision` mutation (T11.2: persists
//! `TransitionClass::Epistemic` with the `EffectClass::Candidate`
//! ceiling and the owner-approved epistemic-revision payload),
//! plus the `ApplyErasure` mutation (issue #1712: persists
//! `TransitionClass::Erasure` with the `EffectClass::ReversibleMutation`
//! ceiling and the owner-approved five-field canonical-erasure payload
//! admitted only for explicit user requests),
//! plus the `ApplyNotificationState` mutation (issue #1780: persists
//! `TransitionClass::NotificationState` with the
//! `EffectClass::ReversibleMutation` ceiling and the owner-approved
//! leg-discriminated notification payload),
//! plus the `ApplyReactiveInjectionState` and `ApplyResourceSnapshot`
//! mutations (issue #1941 C4: persist `TransitionClass::ReactiveState`
//! with the `EffectClass::ReversibleMutation` ceiling and the
//! owner-approved reactive typed parameters),
//! plus the `ApplyUserAutomationState` mutation (issue #1779: persists
//! `TransitionClass::UserAutomation` with the
//! `EffectClass::ReversibleMutation` ceiling and the owner-approved
//! automation typed parameters),
//! plus the `GetReactiveInjectionState` and `GetResourceSnapshot` reads
//! (issue #1941 C4: exact `session_id` / `uri` selectors, no scope),
//! plus the `GetUserAutomationState` read
//! (issue #1779: closed query discriminator with exact selectors, no scope),
//! plus the provider-independent genesis bootstrap entry sourced by
//! [`genesis_manifest`](crate::genesis_manifest). Every other operation stays
//! known-but-unsupported and unadvertised: this includes issue #1814's
//! typed `GetInstrumentRegistryState` / `ApplyInstrumentRegistryState`
//! contract until canonical read/write handlers are available. No other
//! mutation on base has a
//! proven handler, schema, and consumer triple, so C1 advertises no other
//! mutation entry and any transition carrying another named command fails
//! closed against the generated set.
//!
//! Issue #686 notes: `RecordAuthorityRevocation` and
//! `GetAuthorityRevocationHistory` are deliberately known-but-unsupported
//! here. Their typed parameter contracts
//! (`operation_parameters::declared_mutation_parameters` /
//! `declared_read_parameters`) and the Governor decision edge (revocation
//! envelope, history evidence decoding) are already closed, but catalogue
//! activation (row, proven per-backend handlers, consumer triple, and the
//! count-test migration in `tests/operation_manifest_catalogue.rs`) belongs
//! to a store-owned follow-up slice. Until then both operations fail closed
//! with [`StoreError::UnknownOperation`] at this gate.
//!
//! Authority split (one authority, two mechanisms over the same table):
//!
//! * [`generated_operation_manifests`] is the single generator. The genesis
//!   path goes through it, so there are no competing manifest sources.
//! * [`operation_manifest_set_digest`] binds the ordered entry
//!   identities/digests together with the contract, schema, and profile
//!   bindings. Same inputs always produce the same bytes: the digest covers
//!   only declared entry content, never timestamps or mutable evidence.
//! * [`validate_read_against_catalogue`] is the pre-dispatch authority for
//!   named reads: shape, membership, schema digest, scope declaration, and
//!   declared input bounds.
//! * [`validate_transition_against_catalogue`] is the pre-dispatch authority
//!   for prepared transitions. An empty-command plan is the genesis/bootstrap
//!   shape and binds to the genesis entry; a plan carrying named operations
//!   binds to the whole set digest and resolves every command against a
//!   mutation entry. Plan commands are never reordered.
//!
//! Arbitrary user payload keeps [`ExactJsonBytes`](crate::ExactJsonBytes) as
//! its authority; closed validation here is control/parameter contract only.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::operation_parameters::{
    named_mutation_operation_name, named_read_operation_name, project_mutation_parameter_schema,
    project_parameter_schema, validate_typed_mutation_parameters, validate_typed_read_parameters,
};
use crate::{
    CONTRACT_NAME, CONTRACT_VERSION, ContractVersion, EffectClass, GENESIS_MANIFEST_NAME,
    NamedMutationOperation, NamedOperationManifest, NamedReadOperation, NamedReadRequest,
    OperationManifestDigest, OperationManifestSpec, PAYLOAD_AUTHORITY_VERSION, PreparedTransition,
    StoreError, TransitionClass, canonical_json_bytes, sha256_hex,
};

/// Operation identity kind carried by each manifest entry.
///
/// Reads persist no effect and carry no transition class; mutations persist
/// an effect through exactly one transition family. The genesis bootstrap
/// entry is mutation-kind: it seeds state through `RecoverySchema` with a
/// `ReversibleMutation` ceiling.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// A named read. Entries are effect `Read` with no transition classes.
    Read,
    /// A named mutation or the mutation-shaped genesis bootstrap.
    Mutation,
}

/// Catalogue profile bound into the set digest.
///
/// Bumping this identifier is a contract change: every set digest bound to
/// the old profile fails closed afterwards.
pub const OPERATION_CATALOGUE_PROFILE: &str = "eliot.storage.operation-profile.v1";

/// Owning section for activated read entries: command families and
/// activation (only spine-required variants activate with owner, catalogue
/// entry, consumer, and proof).
pub const ACTIVATED_READ_OWNING_SECTION: &str = "I5.17";

/// Owning section for the activated mutation entries: the same command-family
/// activation section that owns the read entries (the proven mutations
/// activate under it).
pub const ACTIVATED_MUTATION_OWNING_SECTION: &str = "I5.17";

/// Owning section for the genesis bootstrap entry: the canonical contract
/// catalogue that owns catalogue identity and bootstrap meaning.
pub const GENESIS_OWNING_SECTION: &str = "I5.15";

/// Owning section stamped on legacy single manifests built through
/// [`NamedOperationManifest::new`](crate::NamedOperationManifest::new), which
/// predate per-operation ownership and are owned by the catalogue mechanism.
pub const SINGLE_MANIFEST_OWNING_SECTION: &str = "I5.15";

/// Scope kind for operations that address no scope.
pub const SCOPE_KIND_NONE: &str = "none";

/// Scope kind for operations that address one store scope.
pub const SCOPE_KIND_SCOPE: &str = "scope";

/// Maximum canonical parameter bytes accepted for an activated typed read.
///
/// Typed read parameters are small closed maps (at most one short string on
/// base); 64 KiB leaves ample headroom while staying far below the
/// 1 MiB [`MAX_EXACT_JSON_BYTES`](crate::MAX_EXACT_JSON_BYTES) authority cap.
pub const READ_MAX_INPUT_BYTES: u32 = 65_536;

/// Maximum output bytes advertised for an activated typed read.
///
/// Matches [`MAX_RECOVERY_PACKET_BYTES`](crate::MAX_RECOVERY_PACKET_BYTES)
/// (3 MiB), the existing bound for bounded canonical snapshots that already
/// caps revision/order head collections.
pub const READ_MAX_OUTPUT_BYTES: u32 = 3_145_728;

/// Timeout advertised for an activated typed read.
///
/// Matches the admitted adapter manifest timeout (30 s), the only proven
/// read timeout on base.
pub const READ_TIMEOUT_MS: u32 = 30_000;

/// Maximum canonical parameter bytes accepted for a bulk-JSON mutation.
///
/// Bulk mutations carry bounded large JSON payloads (a ≤1 MiB ledger
/// snapshot string, ≤1 MiB base64 snapshot content, or ≤256 KiB automation
/// revision/invocation documents): 2 MiB covers the content plus
/// JSON-string escape expansion and the remaining small params while
/// staying fail-closed far below unbounded input. All other mutations
/// keep [`READ_MAX_INPUT_BYTES`].
pub const BULK_MUTATION_MAX_INPUT_BYTES: u32 = 2_097_152;

/// Maximum evidence records one `GetEvidencePack` read may return.
///
/// The bound is explicit per request (`max_records` decimal-string selector)
/// and every handler refuses an over-bound request with
/// [`StoreError::PayloadTooLarge`](crate::StoreError) instead of returning a
/// successful over-bound view. 32 keeps the worst case inside
/// [`READ_MAX_OUTPUT_BYTES`]: each returned record carries one
/// input-bound subject (at most [`READ_MAX_INPUT_BYTES`] canonical parameter
/// bytes, the same bound that limits the stored `CaptureObservation`
/// subjects) plus fixed provenance, so 32 records stay far below the 3 MiB
/// output ceiling while leaving headroom for the envelope.
pub const EVIDENCE_PACK_MAX_RECORDS: u32 = 32;

/// Compile-time guard for the bound above: the worst case (every record
/// carrying a full input-bound subject) stays strictly inside
/// [`READ_MAX_OUTPUT_BYTES`], so any handler enforcing
/// [`EVIDENCE_PACK_MAX_RECORDS`] cannot breach the advertised output byte
/// bound. (The crate root re-export is owned by a follow-up slice; until
/// then handlers pin the same value locally and must stay equal.)
const _: () = assert!(
    (EVIDENCE_PACK_MAX_RECORDS as u64) * (READ_MAX_INPUT_BYTES as u64)
        < (READ_MAX_OUTPUT_BYTES as u64),
    "evidence-pack worst case must fit the read output bound"
);

/// Maximum envelope candidates one audit-range read may carry.
///
/// Mirrors the evidence-pack byte discipline: every candidate arrives as
/// a capture subject bounded by [`READ_MAX_INPUT_BYTES`], so 32 records
/// stay far below [`READ_MAX_OUTPUT_BYTES`] (see the guard below).
/// Reads beyond the bound fail closed with
/// [`StoreError::PayloadTooLarge`](crate::StoreError) instead of
/// truncating silently: a truncated audit range cannot prove journal
/// completeness, so partial success is never reported. Larger journals
/// page forward with the opaque `cursor` selector, bound to the read
/// fence plus the current revision-head set and verified per page; the
/// bound applies per page, unchanged. Any commit advancing any head
/// invalidates outstanding cursors (restart enumeration); append-only
/// captures never disturb already-returned ordinals, so restarts are
/// wasteful but never wrong.
pub const MAX_AUDIT_RANGE_RECORDS: u32 = 32;

/// Compile-time guard for the bound above: the worst case (every
/// candidate carrying a full input-bound subject) stays strictly inside
/// [`READ_MAX_OUTPUT_BYTES`].
const _: () = assert!(
    (MAX_AUDIT_RANGE_RECORDS as u64) * (READ_MAX_INPUT_BYTES as u64)
        < (READ_MAX_OUTPUT_BYTES as u64),
    "audit-range worst case must fit the read output bound"
);

/// Compatibility floor for generated entries: the current contract is the
/// first version carrying per-operation manifests.
pub const MINIMUM_COMPATIBLE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// One activated read row of the declaration table.
struct ActivatedReadDescriptor {
    operation: NamedReadOperation,
    requires_scope_id: bool,
    scope_kind: &'static str,
}

/// The single declaration table for activated reads.
///
/// `GetScopeRevisionView` addresses its scope through the typed `scope_id`
/// request field (proven by both adapter handlers); `GetEvidencePack`
/// addresses its scope the same way (the Governor read facade requires a
/// scope for it) and addresses its evidence through the declared `subject`
/// / `max_records` parameters. The T11.3 cognitive reads address their scope
/// the same way and their records through their declared selectors
/// (`GetTaskState` via exact `task_id` + `max_records`, `GetAttentionAndProblems`
/// via optional exact `problem_id` + `max_records`,
/// `GetUnderstandingProjectionInputs` via exact `selector` + `max_records`,
/// `GetCapabilityEvidenceState` via exact `skill_id` + `max_records`). The
/// head and receipt reads address no scope;
/// the receipt read addresses its receipt through the declared
/// `operation_id` parameter; `GetNotificationState` addresses no scope and
/// filters through the declared `scope`/`include_resolved`/`page_limit`/
/// `cursor` parameters; `GetReactiveInjectionState` addresses no scope and
/// selects through the declared exact `session_id` parameter;
/// `GetResourceSnapshot` addresses no scope and selects through the
/// declared exact `uri` parameter; `GetAuditRange` addresses no scope
/// (issue #223: fence-gated journal-global scan; scope filtering lives
/// consumer-side per I12-26, mirroring the `GetMailbox` split where the
/// Governor facade requires a caller scope while catalogue rows stay
/// scope-free); `GetLearningRecordRange` addresses its scope through the
/// typed `scope_id` request field (issue #1868: proven by both adapter
/// handlers) and filters through the declared optional closed
/// `record_kind` selector plus the `max_records` bound;
/// `GetTaskContractAcceptanceSet` addresses no scope and selects through the
/// declared exact `task_id` and `task_revision` the caller was admitted
/// against (issue #325 P1, I7.9: the obligation set belongs to the task's own
/// contract rather than to a caller's scope, and it must be read at one exact
/// contract revision rather than at whatever happens to be current).
const ACTIVATED_READS: [ActivatedReadDescriptor; 24] = [
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetCurrentEpistemicPosition,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetRevisionHeads,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetOrderingHeads,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetScopeRevisionView,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::ResolveWriteReceipt,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetEvidencePack,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetTaskState,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetAttentionAndProblems,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetUnderstandingProjectionInputs,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetCapabilityEvidenceState,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetNotificationState,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetReactiveInjectionState,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetResourceSnapshot,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetUserAutomationState,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetExperienceBankRange,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetAgentFeedbackRange,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetAuditRange,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetCampaignSourceRevision,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetCampaignLearningStateView,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetBlackboardItem,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetLearningRecordRange,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetCapabilityEvidenceRecordRange,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetTaskContractAcceptanceSet,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetBlobProcessSourceAdmission,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
];

/// Returns the activated read operations in canonical declaration order.
#[must_use]
pub const fn activated_read_operations() -> [NamedReadOperation; 24] {
    [
        ACTIVATED_READS[0].operation,
        ACTIVATED_READS[1].operation,
        ACTIVATED_READS[2].operation,
        ACTIVATED_READS[3].operation,
        ACTIVATED_READS[4].operation,
        ACTIVATED_READS[5].operation,
        ACTIVATED_READS[6].operation,
        ACTIVATED_READS[7].operation,
        ACTIVATED_READS[8].operation,
        ACTIVATED_READS[9].operation,
        ACTIVATED_READS[10].operation,
        ACTIVATED_READS[11].operation,
        ACTIVATED_READS[12].operation,
        ACTIVATED_READS[13].operation,
        ACTIVATED_READS[14].operation,
        ACTIVATED_READS[15].operation,
        ACTIVATED_READS[16].operation,
        ACTIVATED_READS[17].operation,
        ACTIVATED_READS[18].operation,
        ACTIVATED_READS[19].operation,
        ACTIVATED_READS[20].operation,
        ACTIVATED_READS[21].operation,
        ACTIVATED_READS[22].operation,
        ACTIVATED_READS[23].operation,
    ]
}

/// One activated mutation row of the declaration table.
struct ActivatedMutationDescriptor {
    operation: NamedMutationOperation,
    transition_classes: &'static [TransitionClass],
    maximum_effect: EffectClass,
    /// Declared canonical-parameter input bound for this entry.
    max_input_bytes: u32,
}

/// The single declaration table for activated mutations.
///
/// `CaptureObservation` and `AppendAuditEvent` persist the lowest ceiling
/// (`Candidate`) through the `CaptureCandidate` family; `ApplyLifecyclePolicy`
/// persists `ReversibleMutation` through the `LifecyclePolicy` family;
/// `ReconcileRecovery`, `RecordFinishEvidence`, `RecordFinishDecision`, and
/// `RecordModuleCatalogSnapshot` persist `ReversibleMutation` through the
/// `RecoverySchema` family;
/// `UpdateTaskState` persists `ReversibleMutation`
/// through the `TaskControl` family; `ApplyEpistemicRevision` persists
/// `ReversibleMutation` through the `Epistemic` family; `ApplyErasure`
/// persists `ReversibleMutation` through the `Erasure` family (issue #1712:
/// explicit user request ONLY, with the closed five-field erasure typed
/// contract); `ApplyNotificationState` persists `ReversibleMutation` through
/// the `NotificationState` family (issue #1780: Kernel-admitted notification
/// lifecycle with the closed leg-discriminated typed contract);
/// `ApplyReactiveInjectionState` and `ApplyResourceSnapshot` persist
/// `ReversibleMutation` through the `ReactiveState` family (issue #1941 C4:
/// Store-owned durable reactive delivery records and revisioned resource
/// snapshots with the closed reactive typed contract);
/// `CommitExperienceBank` and `CommitAgentFeedback` persist `Candidate`
/// through the `CaptureCandidate` family (issue #223: Store-owned durable
/// experience-bank/feedback rows with the closed experience typed
/// contract); `ApplyBlackboardItem` persists `Candidate` through the same
/// family (issue #1822: a Kernel-admitted typed candidate revision with its
/// closed blackboard contract); `RecordLearningRecord` persists `Candidate`
/// through the `CaptureCandidate` family (issue #1868, I12.24: Store-owned
/// durable learning rows keyed `(record_kind, handle, record_digest)` with the
/// closed learning typed contract; the only Kernel-owned learning surface, so
/// learning crates can never become autonomous persistence systems);
/// `RecordCapabilityEvidenceRecord` persists `Candidate` through the same
/// family (issue #1773, I3.4: Store-owned durable capability-evidence rows
/// keyed `(skill_id, scope_key)` with the closed capability-evidence typed
/// contract; the store issues the fenced row revision the Governor orders
/// same-key evidence by, and the write itself grants no admission, support,
/// influence, or lifecycle change); `ApplySwarmOwnerRevisions` persists
/// `ReversibleMutation` through the `TaskControl` family (issue #1702, I10.15:
/// owner-separated swarm definition/admission/execution revisions with
/// separate owner Ordering Scopes, admitted only when the owner-specific
/// authorization evidence travels with the write and is verified at this
/// boundary — the record's own owner lease, the transition's authority epoch
/// and the authenticated request source; committing a revision grants no
/// admission, dispatch or lifecycle change to anyone);
/// `RecordTaskContractAcceptanceSet` persists `ReversibleMutation` through
/// the `TaskControl` family (issue #325 P1, I7.9: the create-only durable owner
/// record of one `TaskContract` revision's acceptance obligations, keyed by
/// `(task_id, task_revision)` — committing it asserts only what the contract
/// owner already required and grants no coverage, support, admission or
/// completion). All
/// activated mutation rows address no store scope, mirroring the scope-free read
/// descriptors. Every
/// other mutation stays known-but-unsupported.
const ACTIVATED_MUTATIONS: [ActivatedMutationDescriptor; 23] = [
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyEpistemicRevision,
        transition_classes: &[TransitionClass::Epistemic],
        maximum_effect: TransitionClass::Epistemic.maximum_effect(),
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::CaptureObservation,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::AppendAuditEvent,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyLifecyclePolicy,
        transition_classes: &[TransitionClass::LifecyclePolicy],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ReconcileRecovery,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordFinishDecision,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordFinishEvidence,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordModuleCatalogSnapshot,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        // Owner snapshots are bounded at 512 KiB. The existing 2 MiB bulk
        // parameter bound covers canonical JSON string escaping and the
        // remaining fixed parameters without broadening the payload bound.
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordWorkScopeSnapshot,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordPolicySnapshot,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordBlobProcessSourceAdmission,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyProblemOwnerState,
        transition_classes: &[TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        // Problem candidates are bounded like the other owner snapshots: a
        // Problem record is one symptom, its bounded dependency/evidence sets
        // and its retained history, not a bulk payload.
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::UpdateTaskState,
        transition_classes: &[TransitionClass::TaskControl],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplySwarmOwnerRevisions,
        transition_classes: &[TransitionClass::TaskControl],
        // The class maximum, never a wider ceiling: an owner revision is a
        // create-only row plus a compare-and-set head advance, both reversible
        // through the next revision, so it is `ReversibleMutation` exactly as
        // `UpdateTaskState` is. It is never `Candidate` (that would let an
        // owner record be admitted without a live State Fence) and never
        // `ExternalEffect`.
        maximum_effect: EffectClass::ReversibleMutation,
        // The owner record itself is bounded by `MAX_RECOVERY_RECORD_BYTES`
        // (512 KiB) inside `SwarmOwnerRevision::validate`, and the
        // authorization evidence adds a bounded presenter plus a nonzero
        // epoch. The canonical parameter encoding is the record as a JSON
        // STRING inside the parameters object, so escaping and the enclosing
        // structure need headroom over the record's own bound: the 2 MiB bulk
        // parameter bound covers that without broadening the record bound
        // itself. `READ_MAX_INPUT_BYTES` (64 KiB) would refuse a legitimately
        // large-but-valid work-graph digest set, which is why the other
        // bounded owner-snapshot rows (`RecordModuleCatalogSnapshot`,
        // `ApplyProblemOwnerState`) use the bulk bound for the same reason.
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyErasure,
        transition_classes: &[TransitionClass::Erasure],
        maximum_effect: TransitionClass::Erasure.maximum_effect(),
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyNotificationState,
        transition_classes: &[TransitionClass::NotificationState],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: READ_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyReactiveInjectionState,
        transition_classes: &[TransitionClass::ReactiveState],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyResourceSnapshot,
        transition_classes: &[TransitionClass::ReactiveState],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyUserAutomationState,
        transition_classes: &[TransitionClass::UserAutomation],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::CommitExperienceBank,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::CommitAgentFeedback,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::ApplyBlackboardItem,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordLearningRecord,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordCapabilityEvidenceRecord,
        transition_classes: &[TransitionClass::CaptureCandidate],
        maximum_effect: EffectClass::Candidate,
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
    ActivatedMutationDescriptor {
        operation: NamedMutationOperation::RecordTaskContractAcceptanceSet,
        transition_classes: &[TransitionClass::TaskControl],
        // The class maximum, exactly as `UpdateTaskState` and
        // `ApplySwarmOwnerRevisions`: the row is one create-only durable record,
        // so it is `ReversibleMutation` and never `Candidate` — a candidate
        // ceiling would admit an owner obligation set with no live State Fence
        // — and never `ExternalEffect`.
        maximum_effect: EffectClass::ReversibleMutation,
        // One acceptance set is an owner record with a bounded obligation
        // enumeration, not a bulk payload. The parameter travels as canonical
        // JSON inside the parameters object, so the bulk bound covers escaping
        // and the enclosing structure without loosening the record's own
        // closed validator.
        max_input_bytes: BULK_MUTATION_MAX_INPUT_BYTES,
    },
];

fn read_entry_spec(descriptor: &ActivatedReadDescriptor) -> OperationManifestSpec {
    OperationManifestSpec {
        name: named_read_operation_name(descriptor.operation).to_owned(),
        version: CONTRACT_VERSION,
        operation_kind: OperationKind::Read,
        owning_section: ACTIVATED_READ_OWNING_SECTION.to_owned(),
        schema_revision: CONTRACT_VERSION,
        parameter_schema: project_parameter_schema(descriptor.operation),
        requires_scope_id: descriptor.requires_scope_id,
        scope_kind: descriptor.scope_kind.to_owned(),
        minimum_compatible_version: MINIMUM_COMPATIBLE_VERSION,
        transition_classes: Vec::new(),
        maximum_effect: EffectClass::Read,
        max_input_bytes: READ_MAX_INPUT_BYTES,
        max_output_bytes: READ_MAX_OUTPUT_BYTES,
        timeout_ms: READ_TIMEOUT_MS,
    }
}

fn mutation_entry_spec(descriptor: &ActivatedMutationDescriptor) -> OperationManifestSpec {
    OperationManifestSpec {
        name: named_mutation_operation_name(descriptor.operation).to_owned(),
        version: CONTRACT_VERSION,
        operation_kind: OperationKind::Mutation,
        owning_section: ACTIVATED_MUTATION_OWNING_SECTION.to_owned(),
        schema_revision: CONTRACT_VERSION,
        parameter_schema: project_mutation_parameter_schema(descriptor.operation),
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE.to_owned(),
        minimum_compatible_version: MINIMUM_COMPATIBLE_VERSION,
        transition_classes: descriptor.transition_classes.to_vec(),
        maximum_effect: descriptor.maximum_effect,
        max_input_bytes: descriptor.max_input_bytes,
        max_output_bytes: READ_MAX_OUTPUT_BYTES,
        timeout_ms: READ_TIMEOUT_MS,
    }
}

fn genesis_entry_spec() -> OperationManifestSpec {
    // Bounds preserve the exact genesis limits admitted before C1; only the
    // new catalogue bindings are added around them.
    OperationManifestSpec {
        name: GENESIS_MANIFEST_NAME.to_owned(),
        version: CONTRACT_VERSION,
        operation_kind: OperationKind::Mutation,
        owning_section: GENESIS_OWNING_SECTION.to_owned(),
        schema_revision: CONTRACT_VERSION,
        parameter_schema: Vec::new(),
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE.to_owned(),
        minimum_compatible_version: MINIMUM_COMPATIBLE_VERSION,
        transition_classes: vec![TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: 3_145_728,
        max_output_bytes: 3_145_728,
        timeout_ms: 1_000,
    }
}

/// Generates the per-operation manifest descriptors from the declaration table.
///
/// Declaration order is the canonical order: the activated reads, the
/// activated mutations, then the genesis bootstrap entry. Generation is
/// pure over crate constants, so the same source always yields byte-identical
/// entries.
pub fn generated_operation_manifests() -> Result<Vec<NamedOperationManifest>, StoreError> {
    let mut entries = Vec::with_capacity(ACTIVATED_READS.len() + ACTIVATED_MUTATIONS.len() + 1);
    for descriptor in &ACTIVATED_READS {
        entries.push(NamedOperationManifest::from_spec(read_entry_spec(
            descriptor,
        ))?);
    }
    for descriptor in &ACTIVATED_MUTATIONS {
        entries.push(NamedOperationManifest::from_spec(mutation_entry_spec(
            descriptor,
        ))?);
    }
    entries.push(NamedOperationManifest::from_spec(genesis_entry_spec())?);
    let mut names = BTreeSet::new();
    for entry in &entries {
        if !names.insert(entry.name.clone()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    Ok(entries)
}

#[derive(Serialize)]
struct ManifestSetEntryShape<'a> {
    name: &'a str,
    version: ContractVersion,
    operation_kind: OperationKind,
    schema_revision: ContractVersion,
    schema_digest: &'a str,
    digest: &'a str,
}

#[derive(Serialize)]
struct ManifestSetDigestShape<'a> {
    contract_name: &'a str,
    contract_version: ContractVersion,
    payload_authority_version: u16,
    catalogue_profile: &'a str,
    entries: Vec<ManifestSetEntryShape<'a>>,
}

/// Computes the catalogue set digest over ordered entry identities/digests.
///
/// Every entry is validated first. Entries hash without their own digest;
/// the set digest binds, per entry in ascending name order, the name,
/// version, kind, schema revision, schema digest, and entry digest, together
/// with the contract name/version, payload-authority version, and catalogue
/// profile bindings. No timestamps or mutable evidence enter the digest.
pub fn operation_manifest_set_digest(
    entries: &[NamedOperationManifest],
) -> Result<OperationManifestDigest, StoreError> {
    if entries.is_empty() {
        return Err(StoreError::Empty {
            field: "operation_manifest_set",
        });
    }
    for entry in entries {
        entry.validate()?;
    }
    let mut ordered: Vec<&NamedOperationManifest> = entries.iter().collect();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    for entry in &ordered {
        if !names.insert(entry.name.as_str()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    let shape = ManifestSetDigestShape {
        contract_name: CONTRACT_NAME,
        contract_version: CONTRACT_VERSION,
        payload_authority_version: PAYLOAD_AUTHORITY_VERSION,
        catalogue_profile: OPERATION_CATALOGUE_PROFILE,
        entries: ordered
            .iter()
            .map(|entry| ManifestSetEntryShape {
                name: entry.name.as_str(),
                version: entry.version,
                operation_kind: entry.operation_kind,
                schema_revision: entry.schema_revision,
                schema_digest: entry.schema_digest.as_str(),
                digest: entry.digest.as_str(),
            })
            .collect(),
    };
    let bytes = canonical_json_bytes(&shape)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    OperationManifestDigest::new(sha256_hex(&bytes))
}

fn find_entry<'a>(
    entries: &'a [NamedOperationManifest],
    name: &str,
) -> Result<&'a NamedOperationManifest, StoreError> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .ok_or(StoreError::UnknownOperation)
}

/// Validates one named read against a generated catalogue set, pre-dispatch.
///
/// Enforces the generic request shape, catalogue membership (unadvertised
/// operations fail with [`StoreError::UnknownOperation`]), the entry
/// self-digest, the owner-approved typed parameters (unknown, extra, and
/// control-substitution parameters fail here), the scope declaration, and
/// the declared input bound. Issues no authority.
pub fn validate_read_against_catalogue(
    request: &NamedReadRequest,
    entries: &[NamedOperationManifest],
) -> Result<(), StoreError> {
    request.validate()?;
    let entry = find_entry(entries, named_read_operation_name(request.operation))?;
    entry.validate()?;
    if entry.operation_kind != OperationKind::Read {
        return Err(StoreError::ManifestMismatch);
    }
    validate_typed_read_parameters(request.operation, &request.parameters)?;
    match (entry.requires_scope_id, request.scope_id.as_ref()) {
        (true, None) => {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "scope revision read requires scope_id",
            });
        }
        (false, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "operation does not address a scope",
            });
        }
        (true, Some(_)) | (false, None) => {}
    }
    let parameter_bytes = canonical_json_bytes(&request.parameters)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if u64::try_from(parameter_bytes.len())
        .map_or(true, |len| len > u64::from(entry.max_input_bytes))
    {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Validates one prepared transition against a generated catalogue set.
///
/// Every entry is validated, then: an empty-command plan is the
/// genesis/bootstrap shape and must carry exactly the genesis entry digest
/// within its ceiling; a plan carrying named operations must carry exactly
/// the catalogue set digest, resolve every command (in order, never sorted)
/// to a mutation entry, stay within that entry's ceiling, carry only the
/// owner-approved typed parameters for the approved command, and stay within
/// the entry input bound. Only `CaptureObservation`, `AppendAuditEvent`,
/// `ApplyLifecyclePolicy`, `ReconcileRecovery`, `UpdateTaskState`,
/// `ApplyEpistemicRevision`, `ApplyErasure`, `ApplyNotificationState`,
/// `ApplyReactiveInjectionState`, `ApplyResourceSnapshot`,
/// `CommitExperienceBank`, `CommitAgentFeedback`,
/// `RecordLearningRecord`, `RecordCapabilityEvidenceRecord`,
/// `ApplyProblemOwnerState`, and
/// `RecordModuleCatalogSnapshot` have activated
/// mutation entries; any other named
/// command fails closed here until a later slice proves its handler, schema,
/// consumer triple, and semantic owner-authority gate.
/// `ApplySwarmOwnerRevisions` is activated (issue #1702): its owner-specific
/// authorization evidence travels inside the record and is verified by
/// `validate_swarm_owner_revision_transition`, which this gate reaches through
/// `PreparedTransition::validate`, so a cross-owner or stale-lease presentation
/// is refused before any provider I/O. An `Erasure`-class plan additionally admits only the
/// named `ApplyErasure` operation (`ERASURE_STATE_IRREVERSIBLE`, enforced
/// below): no generic reversible-effect executor admits the erasure class
/// through this gate.
pub fn validate_transition_against_catalogue(
    transition: &PreparedTransition,
    entries: &[NamedOperationManifest],
) -> Result<(), StoreError> {
    transition.validate()?;
    for entry in entries {
        entry.validate()?;
    }
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    if transition.named_operations.is_empty() {
        let entry = find_entry(entries, GENESIS_MANIFEST_NAME)?;
        if transition.operation_manifest_digest != entry.digest {
            return Err(StoreError::ManifestMismatch);
        }
        if !entry.admits(
            transition.transition_class,
            transition.requested_effect_ceiling,
        ) {
            return Err(StoreError::TransitionClassExceeded);
        }
        return Ok(());
    }
    validate_named_plan_manifest_and_erasure(transition, entries)?;
    for command in &transition.named_operations {
        let entry = find_entry(entries, named_mutation_operation_name(command.operation))?;
        if entry.operation_kind != OperationKind::Mutation {
            return Err(StoreError::ManifestMismatch);
        }
        if !entry.admits(
            transition.transition_class,
            transition.requested_effect_ceiling,
        ) {
            return Err(StoreError::TransitionClassExceeded);
        }
        match command.operation {
            NamedMutationOperation::CaptureObservation
            | NamedMutationOperation::AppendAuditEvent
            | NamedMutationOperation::ApplyLifecyclePolicy
            | NamedMutationOperation::ReconcileRecovery
            | NamedMutationOperation::RecordFinishDecision
            | NamedMutationOperation::RecordFinishEvidence
            | NamedMutationOperation::RecordModuleCatalogSnapshot
            | NamedMutationOperation::RecordPolicySnapshot
            | NamedMutationOperation::UpdateTaskState
            | NamedMutationOperation::ApplyEpistemicRevision
            | NamedMutationOperation::ApplyErasure
            | NamedMutationOperation::ApplySwarmOwnerRevisions
            | NamedMutationOperation::ApplyInstrumentRegistryState => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                if command.operation == NamedMutationOperation::RecordPolicySnapshot {
                    validate_policy_snapshot_transition(transition, &command.parameters)?;
                }
            }
            NamedMutationOperation::ApplyNotificationState => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::validate_notification_mutation_params(&command.parameters)?;
            }
            NamedMutationOperation::ApplyReactiveInjectionState
            | NamedMutationOperation::ApplyResourceSnapshot => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::validate_reactive_mutation_params(command.operation, &command.parameters)?;
            }
            NamedMutationOperation::ApplyUserAutomationState => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::validate_automation_mutation_params(command.operation, &command.parameters)?;
            }
            NamedMutationOperation::CommitExperienceBank
            | NamedMutationOperation::CommitAgentFeedback => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::validate_experience_mutation_params(command.operation, &command.parameters)?;
            }
            NamedMutationOperation::ApplyBlackboardItem => {
                validate_blackboard_transition(transition, &command.parameters)?;
            }
            NamedMutationOperation::RecordLearningRecord => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::decode_learning_mutation(command.operation, &command.parameters)
                    .map(|_| ())?;
            }
            NamedMutationOperation::RecordCapabilityEvidenceRecord => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::decode_capability_evidence_mutation(command.operation, &command.parameters)
                    .map(|_| ())?;
            }
            NamedMutationOperation::RecordTaskContractAcceptanceSet => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                validate_task_contract_acceptance_transition(transition, &command.parameters)?;
            }
            NamedMutationOperation::RecordAuthorityRevocation => {
                return Err(StoreError::UnknownOperation);
            }
            NamedMutationOperation::ApplyProblemOwnerState => {
                validate_typed_mutation_parameters(command.operation, &command.parameters)?;
                crate::decode_problem_owner_state_mutation(&command.parameters).map(|_| ())?;
            }
        }
        validate_parameter_size(&command.parameters, entry.max_input_bytes)?;
    }
    Ok(())
}

fn validate_policy_snapshot_transition(
    transition: &PreparedTransition,
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), StoreError> {
    let text = |name: &'static str| {
        parameters
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "policy.snapshot",
                reason: "missing required text parameter",
            })
    };
    let expected_revision = text("expected_policy_revision")?
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidField {
            field: "policy.expected_revision",
            reason: "must be the exact non-zero decimal revision returned by the named owner read",
        })?;
    if expected_revision == 0 {
        return Err(StoreError::InvalidField {
            field: "policy.expected_revision",
            reason: "must name the current non-zero Policy owner revision",
        });
    }
    let expected_digest = text("expected_policy_digest")?;
    validate_digest(expected_digest, "policy.expected_digest")?;
    let snapshot_json = text("snapshot_json")?;
    let row: serde_json::Value =
        serde_json::from_str(snapshot_json).map_err(|_| StoreError::InvalidField {
            field: "policy.snapshot_json",
            reason: "must be canonical JSON",
        })?;
    if !row.is_object()
        || canonical_json_bytes(&row)
            .map_err(|error| StoreError::Serialization(error.to_string()))?
            != snapshot_json.as_bytes()
    {
        return Err(StoreError::InvalidField {
            field: "policy.snapshot_json",
            reason: "must be a canonical JSON object",
        });
    }
    let revision = row
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(StoreError::InvalidField {
            field: "policy.revision",
            reason: "must be a positive integer",
        })?;
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or(StoreError::InvalidField {
            field: "policy.revision",
            reason: "revision overflow",
        })?;
    let expected_fence = serde_json::to_value(&transition.state_fence)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if revision != next_revision || row.get("state_fence") != Some(&expected_fence) {
        return Err(StoreError::FenceMismatch);
    }
    let policy = row.get("snapshot").ok_or(StoreError::InvalidField {
        field: "policy.snapshot",
        reason: "complete ConfigPolicySnapshot is required",
    })?;
    let policy_bytes = canonical_json_bytes(policy)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let policy_digest = row
        .get("policy_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "policy.policy_digest",
            reason: "canonical snapshot digest is required",
        })?;
    if sha256_hex(&policy_bytes) != policy_digest {
        return Err(StoreError::InvalidField {
            field: "policy.policy_digest",
            reason: "must bind the exact nested policy snapshot",
        });
    }

    let envelope_json = row
        .get("signed_initial_config_envelope_json")
        .and_then(serde_json::Value::as_str);
    let envelope_sha = row
        .get("signed_initial_config_envelope_sha256")
        .and_then(serde_json::Value::as_str);
    let approval_setting = policy
        .get("settings")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|settings| {
            settings.iter().any(|setting| {
                setting.get("key").and_then(serde_json::Value::as_str)
                    == Some("governing_source.approval")
            })
        });
    match (envelope_json, envelope_sha) {
        (Some(envelope_json), Some(envelope_sha)) => {
            validate_digest(envelope_sha, "policy.initial_config_envelope_sha256")?;
            let envelope: serde_json::Value =
                serde_json::from_str(envelope_json).map_err(|_| StoreError::InvalidField {
                    field: "policy.initial_config_envelope_json",
                    reason: "must be canonical signed-envelope JSON",
                })?;
            if !envelope.is_object()
                || canonical_json_bytes(&envelope)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?
                    != envelope_json.as_bytes()
                || sha256_hex(
                    &canonical_json_bytes(&envelope)
                        .map_err(|error| StoreError::Serialization(error.to_string()))?,
                ) != envelope_sha
                || envelope.pointer("/payload/snapshot") != Some(policy)
            {
                return Err(StoreError::InvalidField {
                    field: "policy.initial_config_envelope_json",
                    reason: "must canonically bind this exact Policy snapshot and digest",
                });
            }
        }
        (None, None) if !approval_setting => {}
        _ => {
            return Err(StoreError::InvalidField {
                field: "policy.initial_config_envelope_json",
                reason: "signed envelope and digest are required together for approved sources",
            });
        }
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

fn validate_named_plan_manifest_and_erasure(
    transition: &PreparedTransition,
    entries: &[NamedOperationManifest],
) -> Result<(), StoreError> {
    let set_digest = operation_manifest_set_digest(entries)?;
    if transition.operation_manifest_digest != set_digest {
        return Err(StoreError::ManifestMismatch);
    }
    // `ERASURE_STATE_IRREVERSIBLE` execution direction (issue #1712): an
    // `Erasure`-class plan executes only the named `ApplyErasure` operation.
    // `PreparedTransition::validate` already aligns each command's family with
    // the plan class, so this arm is defense in depth today: it stays
    // mechanically evaluated on every erasure plan and refuses if a future
    // operation ever maps to the `Erasure` family without travelling the
    // named erasure transaction. No generic reversible-effect executor admits
    // the erasure class through this gate.
    if transition.transition_class == TransitionClass::Erasure
        && transition
            .named_operations
            .iter()
            .any(|command| command.operation != NamedMutationOperation::ApplyErasure)
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    Ok(())
}

fn validate_parameter_size(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
    max_input_bytes: u32,
) -> Result<(), StoreError> {
    let parameter_bytes = canonical_json_bytes(parameters)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if u64::try_from(parameter_bytes.len()).map_or(true, |len| len > u64::from(max_input_bytes)) {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Binds one owner acceptance-set record to the transition that carries it.
///
/// The record is the contract owner's own enumeration, so it must name the
/// transition's task and be issued at the transition's live State Fence. A
/// record bound to another task or another fence is refused here, before any
/// provider I/O, so the durable row and the receipt always describe one task at
/// one fence.
fn validate_task_contract_acceptance_transition(
    transition: &PreparedTransition,
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), StoreError> {
    let record = crate::decode_task_contract_acceptance_record(
        NamedMutationOperation::RecordTaskContractAcceptanceSet,
        parameters,
    )?;
    if record.state_fence != transition.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    if transition.task_id.as_deref() != Some(record.task_id.as_str()) {
        return Err(StoreError::InvalidField {
            field: "task_contract_acceptance.task_id",
            reason: "must match the prepared transition task",
        });
    }
    Ok(())
}

fn validate_blackboard_transition(
    transition: &PreparedTransition,
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), StoreError> {
    let revision =
        crate::decode_blackboard_item(NamedMutationOperation::ApplyBlackboardItem, parameters)?;
    if revision.record.state_fence != transition.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    if transition.task_id.as_deref() != Some(revision.record.task_id.as_str()) {
        return Err(StoreError::InvalidField {
            field: "blackboard.task_id",
            reason: "must match the prepared transition task",
        });
    }
    Ok(())
}
