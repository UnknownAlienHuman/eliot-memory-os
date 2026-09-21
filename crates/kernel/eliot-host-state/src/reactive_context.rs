//! Durable reactive context queue owned by the `HostStateJournal`.
//!
//! The queue stores typed protocol references and lifecycle evidence in the
//! existing Host journal. It deliberately owns no transport, endpoint lookup,
//! Context assembly, acknowledgement policy, or canonical semantic state. A
//! queue mutation is a normal journal record, so its preparation, commit
//! receipt, sequence advancement, replay and recovery use the same atomic path
//! as every other Host-state record.

use std::collections::BTreeMap;

use eliot_platform::PlatformHandle;
use eliot_protocol::{
    AckPhase, EventEnvelope, ReactiveContextAckEvidence, ReactiveContextAckLedger,
    ReactiveContextContentRef, ReactiveContextPayload, ReactiveContextStage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{AppendReceipt, IdempotencyIdentity, JournalError, ReconcileOutcome, RecordFence};

/// The queue record schema is independent of the enclosing Host journal wire
/// revision. Adding fields or a new action requires an explicit migration.
pub const REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION: u16 = 1;
/// Maximum number of retained operation records before backpressure applies.
pub const DEFAULT_REACTIVE_CONTEXT_MAX_ITEMS: usize = 1_024;
/// Maximum canonical payload bytes retained by one queue.
pub const DEFAULT_REACTIVE_CONTEXT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum retained records for one `AgentAttempt`.
pub const DEFAULT_REACTIVE_CONTEXT_MAX_ATTEMPT_ITEMS: usize = 64;
/// Maximum page size exposed by the read port.
pub const DEFAULT_REACTIVE_CONTEXT_MAX_PAGE_ITEMS: usize = 128;
/// Maximum diagnostic/reason text retained in one queue record.
pub const MAX_REACTIVE_CONTEXT_REASON_BYTES: usize = 4 * 1024;

/// Typed failures exposed by the Host-state reactive queue port.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ReactiveContextQueueError {
    /// The enclosing Host journal rejected the operation or could not persist
    /// it. Unknown journal outcomes remain unknown and are never retryable by
    /// this queue layer.
    #[error("host-state journal: {0}")]
    Journal(#[from] JournalError),
    /// The typed protocol payload or queue record is malformed.
    #[error("reactive Context queue invalid: {0}")]
    Invalid(String),
    /// The caller prepared against a stale queue revision.
    #[error("reactive Context queue revision is stale: expected {expected}, actual {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    /// A cursor belongs to an older immutable snapshot.
    #[error("reactive Context queue cursor is stale")]
    StaleCursor,
    /// A stable operation or event identity was reused with different bytes.
    #[error("reactive Context queue identity conflict")]
    IdentityConflict,
    /// The queue cannot admit another operation under its independent bounds.
    #[error("reactive Context queue capacity is exhausted: {dimension}")]
    QueueFull { dimension: &'static str },
    /// A query named no committed operation.
    #[error("reactive Context queue operation was not found")]
    NotFound,
    /// A durable transaction is still unresolved.
    #[error("reactive Context queue operation remains unknown")]
    StillUnknown,
}

/// Independent queue bounds. They are persisted with the queue so a reopen
/// cannot silently adopt a different capacity policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextQueueLimits {
    /// Maximum retained operation entries, including terminal history.
    pub max_items: usize,
    /// Maximum sum of canonical typed payload bytes.
    pub max_bytes: u64,
    /// Maximum entries for one attempt.
    pub max_attempt_items: usize,
    /// Maximum page size returned by a snapshot query.
    pub max_page_items: usize,
}

impl Default for ReactiveContextQueueLimits {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_REACTIVE_CONTEXT_MAX_ITEMS,
            max_bytes: DEFAULT_REACTIVE_CONTEXT_MAX_BYTES,
            max_attempt_items: DEFAULT_REACTIVE_CONTEXT_MAX_ATTEMPT_ITEMS,
            max_page_items: DEFAULT_REACTIVE_CONTEXT_MAX_PAGE_ITEMS,
        }
    }
}

impl ReactiveContextQueueLimits {
    fn validate(&self) -> Result<(), ReactiveContextQueueError> {
        if self.max_items == 0
            || self.max_attempt_items == 0
            || self.max_page_items == 0
            || self.max_bytes == 0
            || self.max_page_items > self.max_items
        {
            return Err(ReactiveContextQueueError::Invalid(
                "queue limits must be non-zero and page size must fit the item bound".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable stream frontier retained after terminal history is compacted or
/// a queue is reopened. The queue currently retains all journal history; this
/// frontier still prevents sequence reset if bounded projection compaction is
/// added later.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextStreamCursor {
    /// Last accepted stream sequence.
    pub sequence: u64,
    /// Last accepted event identity.
    pub event_id: String,
    /// Last source cursor supplied by the producer.
    pub cursor: u64,
    /// Queue generation that accepted the frontier.
    pub queue_generation: u64,
}

/// Durable queue entry. Context content itself remains an owner-produced typed
/// reference in `ReactiveContextPayload`; no arbitrary `Context` bytes are
/// copied into `HostState`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextQueueEntry {
    /// Queue record schema version.
    pub schema_version: u16,
    /// Canonical queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Host installation/activation fence for this entry.
    pub fence: RecordFence,
    /// Exact protocol payload supplied by the Context owner.
    pub payload: ReactiveContextPayload,
    /// Generic event envelope derived from the payload.
    pub envelope: EventEnvelope,
    /// Owner-supplied endpoint reference; it is never resolved here.
    pub endpoint_ref: PlatformHandle,
    /// Canonical payload digest used for conflict/replay checks.
    pub payload_sha256: String,
    /// Current queue lifecycle stage.
    pub stage: ReactiveContextStage,
    /// Stage predecessor for the last accepted transition.
    pub predecessor_stage: Option<ReactiveContextStage>,
    /// Last owner-issued lifecycle receipt, when supplied.
    pub owner_receipt: Option<ReactiveContextContentRef>,
    /// Generic acknowledgement replay ledger owned by the protocol contract.
    pub ack_ledger: ReactiveContextAckLedger,
    /// Accepted typed acknowledgement evidence retained for bounded history.
    pub ack_evidence: Vec<ReactiveContextAckEvidence>,
    /// Transport operation reference, if a transport owner supplied one.
    pub transport_ref: Option<PlatformHandle>,
    /// Cancellation operation reference, if cancellation was requested.
    pub cancellation_ref: Option<PlatformHandle>,
    /// Reconciliation operation reference, if uncertainty was observed.
    pub reconciliation_ref: Option<PlatformHandle>,
    /// Bounded reason for rejection, expiry, cancellation, or fencing.
    pub reason: Option<String>,
    /// Queue generation that admitted this entry.
    pub queue_generation: u64,
    /// Canonical bytes charged against the queue byte bound.
    pub charged_bytes: u64,
    /// Enclosing journal sequence of the last accepted mutation.
    pub last_mutation_sequence: u64,
}

impl Eq for ReactiveContextQueueEntry {}

impl ReactiveContextQueueEntry {
    /// Whether this entry no longer permits a new delivery attempt.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.stage,
            ReactiveContextStage::RejectedNotAttempted
                | ReactiveContextStage::AppliedProjection
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
                | ReactiveContextStage::InvalidAcknowledgement
        )
    }

    fn validate(&self) -> Result<(), ReactiveContextQueueError> {
        if self.schema_version != REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION {
            return Err(ReactiveContextQueueError::Invalid(
                "unsupported reactive queue entry schema".into(),
            ));
        }
        self.operation
            .validate()
            .map_err(ReactiveContextQueueError::Journal)?;
        self.fence
            .validate()
            .map_err(ReactiveContextQueueError::Journal)?;
        self.payload.validate().map_err(protocol_error)?;
        let expected_operation = operation_identity(&self.payload)?;
        if self.operation != expected_operation {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        let expected_envelope = self.payload.to_event_envelope().map_err(protocol_error)?;
        if self.envelope != expected_envelope {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        if self.endpoint_ref.as_str().trim().is_empty()
            || self.endpoint_ref.as_str().chars().any(char::is_control)
        {
            return Err(ReactiveContextQueueError::Invalid(
                "endpoint_ref must be bounded opaque text".into(),
            ));
        }
        let expected_digest = self.payload.payload_sha256().map_err(protocol_error)?;
        if self.payload_sha256 != expected_digest {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        if self.queue_generation == 0 || self.charged_bytes == 0 {
            return Err(ReactiveContextQueueError::Invalid(
                "queue generation and charged bytes must be non-zero".into(),
            ));
        }
        if let Some(receipt) = &self.owner_receipt {
            receipt.validate().map_err(protocol_error)?;
        }
        for value in [
            &self.transport_ref,
            &self.cancellation_ref,
            &self.reconciliation_ref,
        ]
        .into_iter()
        .flatten()
        {
            if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
                return Err(ReactiveContextQueueError::Invalid(
                    "queue operation reference is malformed".into(),
                ));
            }
        }
        if let Some(reason) = &self.reason {
            validate_reason(reason)?;
        }
        if self.ack_evidence.len() > 32 {
            return Err(ReactiveContextQueueError::QueueFull {
                dimension: "ack_history",
            });
        }
        let mut ledger = ReactiveContextAckLedger::new(&self.payload).map_err(protocol_error)?;
        for evidence in &self.ack_evidence {
            ledger
                .record(evidence, &self.payload)
                .map_err(protocol_error)?;
        }
        if ledger != self.ack_ledger {
            return Err(ReactiveContextQueueError::Invalid(
                "ack ledger does not match retained acknowledgement evidence".into(),
            ));
        }
        Ok(())
    }
}

/// Rebuildable durable queue projection held inside `HostState`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextQueueState {
    /// Queue schema version.
    pub schema_version: u16,
    /// Last enclosing journal sequence that changed this queue.
    pub revision: u64,
    /// Monotonic queue generation used to fence stale prepared records.
    pub queue_generation: u64,
    /// Persisted capacity policy.
    pub limits: ReactiveContextQueueLimits,
    /// Operation records keyed by canonical operation identity.
    pub entries: BTreeMap<String, ReactiveContextQueueEntry>,
    /// One event identity per stream sequence.
    pub sequence_index: BTreeMap<String, String>,
    /// Stream frontiers retained across reopen and terminal history pruning.
    pub streams: BTreeMap<String, ReactiveContextStreamCursor>,
    /// Sum of `charged_bytes` across retained entries.
    pub total_bytes: u64,
}

impl Default for ReactiveContextQueueState {
    fn default() -> Self {
        Self::new(ReactiveContextQueueLimits::default())
    }
}

impl ReactiveContextQueueState {
    /// Create an empty queue with explicit independent limits.
    pub fn new(limits: ReactiveContextQueueLimits) -> Self {
        Self {
            schema_version: REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION,
            revision: 0,
            queue_generation: 1,
            limits,
            entries: BTreeMap::new(),
            sequence_index: BTreeMap::new(),
            streams: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    /// Whether the queue has no unresolved operation that would block a clean
    /// Host drain.
    #[must_use]
    pub fn clean_for_drain(&self) -> bool {
        self.entries
            .values()
            .all(ReactiveContextQueueEntry::is_terminal)
    }

    /// Bump the queue generation at an activation cutover while retaining
    /// operation history and stream continuity.
    pub(crate) fn advance_generation(&mut self) -> Result<(), JournalError> {
        self.queue_generation = self
            .queue_generation
            .checked_add(1)
            .ok_or(JournalError::Sequence)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ReactiveContextQueueError> {
        if self.schema_version != REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION
            || self.queue_generation == 0
        {
            return Err(ReactiveContextQueueError::Invalid(
                "unsupported reactive queue state schema or generation".into(),
            ));
        }
        self.limits.validate()?;
        if self.entries.len() > self.limits.max_items {
            return Err(ReactiveContextQueueError::QueueFull { dimension: "items" });
        }
        let mut bytes = 0_u64;
        let mut expected_sequences = BTreeMap::new();
        for (key, entry) in &self.entries {
            entry.validate()?;
            if key != &operation_key(&entry.operation) {
                return Err(ReactiveContextQueueError::Invalid(
                    "queue entry key does not match operation identity".into(),
                ));
            }
            bytes = bytes
                .checked_add(entry.charged_bytes)
                .ok_or(ReactiveContextQueueError::QueueFull { dimension: "bytes" })?;
            let sequence_key = sequence_key(&entry.envelope.stream_id, entry.envelope.sequence);
            if expected_sequences
                .insert(sequence_key, key.clone())
                .is_some()
            {
                return Err(ReactiveContextQueueError::IdentityConflict);
            }
        }
        if bytes != self.total_bytes || bytes > self.limits.max_bytes {
            return Err(ReactiveContextQueueError::QueueFull { dimension: "bytes" });
        }
        if expected_sequences != self.sequence_index {
            return Err(ReactiveContextQueueError::Invalid(
                "queue sequence index is inconsistent".into(),
            ));
        }
        for (stream, cursor) in &self.streams {
            if cursor.sequence == 0
                || cursor.cursor == 0
                || cursor.event_id.trim().is_empty()
                || cursor.queue_generation == 0
                || !self.entries.values().any(|entry| {
                    entry.envelope.stream_id == *stream
                        && entry.envelope.event_id == cursor.event_id
                        && entry.envelope.sequence == cursor.sequence
                })
            {
                return Err(ReactiveContextQueueError::Invalid(
                    "stream frontier does not bind an accepted queue entry".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn committed_entry(
        &self,
        operation: &IdempotencyIdentity,
    ) -> Option<ReactiveContextQueueEntry> {
        self.entries.get(&operation_key(operation)).cloned()
    }

    fn apply_enqueue(
        &mut self,
        expected_revision: u64,
        operation: &IdempotencyIdentity,
        entry: ReactiveContextQueueEntry,
        journal_sequence: u64,
    ) -> Result<(), JournalError> {
        self.validate().map_err(queue_error_to_journal)?;
        if self.revision != expected_revision {
            return Err(queue_error_to_journal(
                ReactiveContextQueueError::StaleRevision {
                    expected: expected_revision,
                    actual: self.revision,
                },
            ));
        }
        if self.entries.contains_key(&operation_key(operation)) {
            return Err(JournalError::IdempotencyConflict);
        }
        if self.entries.len() >= self.limits.max_items {
            return Err(queue_error_to_journal(
                ReactiveContextQueueError::QueueFull { dimension: "items" },
            ));
        }
        if entry.queue_generation != self.queue_generation {
            return Err(JournalError::StaleFence);
        }
        if entry.operation != *operation {
            return Err(JournalError::IdempotencyConflict);
        }
        if self.total_bytes.saturating_add(entry.charged_bytes) > self.limits.max_bytes {
            return Err(queue_error_to_journal(
                ReactiveContextQueueError::QueueFull { dimension: "bytes" },
            ));
        }
        let attempt_count = self
            .entries
            .values()
            .filter(|existing| existing.payload.attempt_id == entry.payload.attempt_id)
            .count();
        if attempt_count >= self.limits.max_attempt_items {
            return Err(queue_error_to_journal(
                ReactiveContextQueueError::QueueFull {
                    dimension: "attempt_items",
                },
            ));
        }
        let stream = entry.envelope.stream_id.clone();
        let sequence = entry.envelope.sequence;
        let sequence_key = sequence_key(&stream, sequence);
        if self.sequence_index.contains_key(&sequence_key) {
            return Err(JournalError::IdempotencyConflict);
        }
        if let Some(frontier) = self.streams.get(&stream) {
            if sequence != frontier.sequence.saturating_add(1)
                || !entry
                    .envelope
                    .causal_predecessor_refs
                    .iter()
                    .any(|item| item == &frontier.event_id)
            {
                return Err(queue_error_to_journal(ReactiveContextQueueError::Invalid(
                    "stream sequence requires the exact immediate predecessor".into(),
                )));
            }
        } else if sequence != 1 || !entry.envelope.causal_predecessor_refs.is_empty() {
            return Err(queue_error_to_journal(ReactiveContextQueueError::Invalid(
                "first stream event must be sequence one without predecessors".into(),
            )));
        }
        let event_id = entry.envelope.event_id.clone();
        let cursor = entry.payload.sequence.cursor;
        self.total_bytes = self
            .total_bytes
            .checked_add(entry.charged_bytes)
            .ok_or(JournalError::Sequence)?;
        self.sequence_index
            .insert(sequence_key, operation_key(operation));
        self.streams.insert(
            stream,
            ReactiveContextStreamCursor {
                sequence,
                event_id,
                cursor,
                queue_generation: self.queue_generation,
            },
        );
        let mut entry = entry;
        entry.last_mutation_sequence = journal_sequence;
        self.entries.insert(operation_key(operation), entry);
        self.revision = journal_sequence;
        self.validate().map_err(queue_error_to_journal)
    }

    fn apply_transition(
        &mut self,
        expected_revision: u64,
        transition: &ReactiveContextTransition,
        journal_sequence: u64,
    ) -> Result<(), JournalError> {
        self.validate().map_err(queue_error_to_journal)?;
        if self.revision != expected_revision {
            return Err(queue_error_to_journal(
                ReactiveContextQueueError::StaleRevision {
                    expected: expected_revision,
                    actual: self.revision,
                },
            ));
        }
        let Some(entry) = self.committed_entry(&transition.target) else {
            return Err(queue_error_to_journal(ReactiveContextQueueError::NotFound));
        };
        if entry.stage != transition.expected_stage {
            return Err(queue_error_to_journal(ReactiveContextQueueError::Invalid(
                "transition predecessor does not match current queue stage".into(),
            )));
        }
        if entry.fence != transition.fence {
            return Err(JournalError::StaleFence);
        }
        validate_stage_transition(
            transition.expected_stage,
            transition.next_stage,
            transition.evidence.ack.as_ref(),
        )?;
        let mut updated = entry;
        apply_transition_evidence(&mut updated, transition)?;
        updated.predecessor_stage = Some(transition.expected_stage);
        updated.stage = transition.next_stage;
        updated.last_mutation_sequence = journal_sequence;
        self.entries
            .insert(operation_key(&transition.target), updated);
        self.revision = journal_sequence;
        self.validate().map_err(queue_error_to_journal)
    }
}

/// A journal mutation that introduces or advances one queue entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextRecord {
    /// Queue record schema version.
    pub schema_version: u16,
    /// Host installation/activation fence.
    pub fence: RecordFence,
    /// Journal idempotency identity for this mutation.
    pub operation: IdempotencyIdentity,
    /// Expected queue revision at the mutation linearization point.
    pub expected_queue_revision: u64,
    /// Durable queue action.
    pub action: ReactiveContextJournalAction,
}

/// The two journal actions needed by the queue. Preparation is deliberately
/// absent: it has no durable representation until Enqueue commits.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ReactiveContextJournalAction {
    /// Commit one new operation and advance its stream frontier atomically.
    Enqueue(ReactiveContextQueueEntry),
    /// Compare the current entry revision/stage and advance it once.
    Transition(ReactiveContextTransition),
}

/// Evidence attached to a compare-and-transition action.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextTransitionEvidence {
    /// Owner-issued immutable lifecycle receipt.
    pub owner_receipt: Option<ReactiveContextContentRef>,
    /// Generic #796 acknowledgement evidence, when the stage is an ack stage.
    pub ack: Option<ReactiveContextAckEvidence>,
    /// Exact transport operation reference, not a socket or endpoint.
    pub transport_ref: Option<PlatformHandle>,
    /// Exact cancellation operation reference.
    pub cancellation_ref: Option<PlatformHandle>,
    /// Exact reconciliation operation reference.
    pub reconciliation_ref: Option<PlatformHandle>,
    /// Bounded owner-supplied reason for a terminal/non-success stage.
    pub reason: Option<String>,
    /// Owner time observation used for expiry/cancellation evidence.
    pub observed_at_unix_ms: Option<u64>,
}

/// Compare-and-transition request. mutation is distinct from the queue
/// operation identity so every accepted transition has its own journal
/// idempotency record while the target operation remains stable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextTransition {
    /// Host fence bound to the target operation.
    pub fence: RecordFence,
    /// New journal mutation identity.
    pub mutation: IdempotencyIdentity,
    /// Existing queue operation being advanced.
    pub target: IdempotencyIdentity,
    /// Expected queue revision.
    pub expected_queue_revision: u64,
    /// Expected current lifecycle stage.
    pub expected_stage: ReactiveContextStage,
    /// New lifecycle stage.
    pub next_stage: ReactiveContextStage,
    /// Typed evidence for the stage change.
    pub evidence: ReactiveContextTransitionEvidence,
}

/// Preparation request. It validates and freezes the typed enqueue intent but
/// does not append a Host journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextPrepareRequest {
    /// Host installation/activation fence.
    pub fence: RecordFence,
    /// Exact typed payload.
    pub payload: ReactiveContextPayload,
    /// Owner-supplied opaque endpoint reference.
    pub endpoint_ref: PlatformHandle,
    /// Optional owner receipt for the enqueue admission.
    pub owner_receipt: Option<ReactiveContextContentRef>,
    /// Queue revision observed before preparation.
    pub expected_queue_revision: u64,
}

/// Durable prepared enqueue token returned by the pure preparation phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextPreparedEnqueue {
    /// Exact record that must be committed unchanged.
    pub record: ReactiveContextRecord,
    /// Record checksum used by the Host journal.
    pub record_checksum: String,
    /// Stable backend transaction identity for response-loss reconciliation.
    pub transaction_id: PlatformHandle,
}

/// Result of preparation: a new immutable token or an exact historical replay.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextPrepareResult {
    /// No durable state changed; caller may commit this exact token.
    Prepared(ReactiveContextPreparedEnqueue),
    /// The same operation/payload was already committed.
    Replay(ReactiveContextQueueEntry),
}

/// Receipt returned after an enqueue append reaches a known journal outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextEnqueueReceipt {
    /// Existing Host journal append receipt.
    pub journal: AppendReceipt,
    /// Exact committed queue entry.
    pub entry: ReactiveContextQueueEntry,
}

/// Receipt returned after a compare-and-transition append reaches a known
/// journal outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextTransitionReceipt {
    /// Existing Host journal append receipt.
    pub journal: AppendReceipt,
    /// Exact post-transition queue entry.
    pub entry: ReactiveContextQueueEntry,
}

/// Operation query by canonical identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextOperationQuery {
    /// Queue operation identity.
    pub operation: IdempotencyIdentity,
}

/// Stable cursor bound to one queue revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextQueueCursor {
    /// Queue revision at which the page was created.
    pub revision: u64,
    /// Stable sorted-entry offset.
    pub offset: usize,
}

/// Bounded snapshot query. A query never writes or advances a cursor.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ReactiveContextQueueQuery {
    /// Optional exact `AgentAttempt` filter.
    pub attempt_id: Option<String>,
    /// Optional exact stream filter.
    pub stream_id: Option<String>,
    /// Include terminal history in the page.
    pub include_terminal: bool,
    /// Requested page size.
    pub limit: usize,
    /// Cursor from the same immutable queue revision.
    pub cursor: Option<ReactiveContextQueueCursor>,
}

/// Immutable queue page and its coverage ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveContextQueueSnapshot {
    /// Queue revision represented by this page.
    pub revision: u64,
    /// Queue generation represented by this page.
    pub queue_generation: u64,
    /// Ordered page entries.
    pub items: Vec<ReactiveContextQueueEntry>,
    /// Cursor for the next page, if one exists.
    pub next_cursor: Option<ReactiveContextQueueCursor>,
    /// True only when the filtered set is known empty at this revision.
    pub known_empty: bool,
    /// True when a continuation exists.
    pub partial: bool,
    /// Digest of the exact page and cursor metadata.
    pub digest: String,
}

/// Reconciliation request for one previously prepared journal mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextReconcileRequest {
    /// Queue operation whose postcondition is being inspected.
    pub operation: IdempotencyIdentity,
    /// Stable Host backend transaction identity from preparation.
    pub transaction_id: PlatformHandle,
}

/// Result of resolving one commit-boundary observation. This is separate from
/// transport delivery: Committed proves journal persistence only.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextReconcileOutcome {
    /// The queue record is durably committed.
    Committed(ReactiveContextQueueEntry),
    /// The mutation was independently shown not to have committed.
    NotApplied,
    /// The backend still cannot distinguish prepared/committed outcome.
    StillUnknown,
}

/// Public port implemented by the production `HostState` journal service.
pub trait ReactiveContextQueuePort {
    /// Prepare or replay one exact typed enqueue.
    fn prepare_or_replay(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError>;
    /// Commit one unchanged prepared enqueue token.
    fn commit_enqueued(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError>;
    /// Apply one revision-checked queue transition.
    fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError>;
    /// Load a bounded immutable queue page.
    fn load_attempt_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError>;
    /// Read one committed operation without mutation.
    fn query_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<ReactiveContextQueueEntry, ReactiveContextQueueError>;
    /// Reconcile one stable Host journal mutation.
    fn reconcile_operation(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError>;
}

/// Validate and apply a durable queue record during journal reduction.
pub(crate) fn apply_record(
    state: &mut Option<ReactiveContextQueueState>,
    record: &ReactiveContextRecord,
    journal_sequence: u64,
) -> Result<(), JournalError> {
    validate_record(record).map_err(queue_error_to_journal)?;
    match &record.action {
        ReactiveContextJournalAction::Enqueue(entry) => {
            let queue = state.get_or_insert_with(ReactiveContextQueueState::default);
            queue.apply_enqueue(
                record.expected_queue_revision,
                &record.operation,
                entry.clone(),
                journal_sequence,
            )
        }
        ReactiveContextJournalAction::Transition(transition) => {
            let Some(queue) = state.as_mut() else {
                return Err(queue_error_to_journal(ReactiveContextQueueError::NotFound));
            };
            if record.operation != transition.mutation {
                return Err(JournalError::IdempotencyConflict);
            }
            if record.expected_queue_revision != transition.expected_queue_revision {
                return Err(queue_error_to_journal(ReactiveContextQueueError::Invalid(
                    "record and transition revisions differ".into(),
                )));
            }
            queue.apply_transition(record.expected_queue_revision, transition, journal_sequence)
        }
    }
}

/// Validate one record without relying on a live journal state.
pub(crate) fn validate_record(
    record: &ReactiveContextRecord,
) -> Result<(), ReactiveContextQueueError> {
    if record.schema_version != REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION {
        return Err(ReactiveContextQueueError::Invalid(
            "unsupported reactive queue record schema".into(),
        ));
    }
    record
        .fence
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    record
        .operation
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    match &record.action {
        ReactiveContextJournalAction::Enqueue(entry) => {
            entry.validate()?;
            if entry.fence != record.fence || entry.operation != record.operation {
                return Err(ReactiveContextQueueError::IdentityConflict);
            }
            if entry.stage != ReactiveContextStage::EnqueuedPersisted
                || entry.predecessor_stage.is_some()
            {
                return Err(ReactiveContextQueueError::Invalid(
                    "enqueue must begin at ENQUEUED_PERSISTED".into(),
                ));
            }
        }
        ReactiveContextJournalAction::Transition(transition) => {
            transition_validate(transition)?;
            if transition.fence != record.fence
                || transition.mutation != record.operation
                || transition.expected_queue_revision != record.expected_queue_revision
            {
                return Err(ReactiveContextQueueError::IdentityConflict);
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_record_for_journal(
    record: &ReactiveContextRecord,
) -> Result<(), JournalError> {
    validate_record(record).map_err(queue_error_to_journal)
}

/// Prepare an exact enqueue against the current queue projection.
pub(crate) fn prepare(
    current: Option<&ReactiveContextQueueState>,
    request: ReactiveContextPrepareRequest,
) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
    request_validate(&request)?;
    let queue = current.cloned().unwrap_or_default();
    queue.validate()?;
    if queue.revision != request.expected_queue_revision {
        return Err(ReactiveContextQueueError::StaleRevision {
            expected: request.expected_queue_revision,
            actual: queue.revision,
        });
    }
    let operation = operation_identity(&request.payload)?;
    if let Some(existing) = queue.committed_entry(&operation) {
        if existing.payload_sha256 == request.payload.payload_sha256().map_err(protocol_error)?
            && existing.endpoint_ref == request.endpoint_ref
            && existing.fence == request.fence
        {
            return Ok(ReactiveContextPrepareResult::Replay(existing));
        }
        return Err(ReactiveContextQueueError::IdentityConflict);
    }
    let entry = build_entry(&request, operation.clone(), queue.queue_generation)?;
    let record = ReactiveContextRecord {
        schema_version: REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION,
        fence: request.fence,
        operation,
        expected_queue_revision: request.expected_queue_revision,
        action: ReactiveContextJournalAction::Enqueue(entry),
    };
    validate_record(&record)?;
    Ok(ReactiveContextPrepareResult::Prepared(prepared_record(
        record,
    )?))
}

fn prepared_record(
    record: ReactiveContextRecord,
) -> Result<ReactiveContextPreparedEnqueue, ReactiveContextQueueError> {
    let host_record = crate::HostStateRecord::ReactiveContext(record.clone());
    let record_checksum = crate::record_checksum(&host_record)?;
    let transaction_id = crate::journal::journal_transaction_id(&host_record, &record_checksum)?;
    Ok(ReactiveContextPreparedEnqueue {
        record,
        record_checksum,
        transaction_id,
    })
}

fn request_validate(
    request: &ReactiveContextPrepareRequest,
) -> Result<(), ReactiveContextQueueError> {
    request
        .fence
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    request.payload.validate().map_err(protocol_error)?;
    let operation = operation_identity(&request.payload)?;
    operation
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    if request.endpoint_ref.as_str().trim().is_empty()
        || request.endpoint_ref.as_str().chars().any(char::is_control)
    {
        return Err(ReactiveContextQueueError::Invalid(
            "endpoint_ref must be bounded opaque text".into(),
        ));
    }
    if let Some(receipt) = &request.owner_receipt {
        receipt.validate().map_err(protocol_error)?;
    }
    Ok(())
}

fn build_entry(
    request: &ReactiveContextPrepareRequest,
    operation: IdempotencyIdentity,
    queue_generation: u64,
) -> Result<ReactiveContextQueueEntry, ReactiveContextQueueError> {
    let payload_sha256 = request.payload.payload_sha256().map_err(protocol_error)?;
    let envelope = request
        .payload
        .to_event_envelope()
        .map_err(protocol_error)?;
    let charged_bytes = u64::try_from(
        request
            .payload
            .canonical_bytes()
            .map_err(protocol_error)?
            .len(),
    )
    .map_err(|_| ReactiveContextQueueError::QueueFull { dimension: "bytes" })?;
    let ack_ledger = ReactiveContextAckLedger::new(&request.payload).map_err(protocol_error)?;
    let entry = ReactiveContextQueueEntry {
        schema_version: REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION,
        operation,
        fence: request.fence.clone(),
        payload: request.payload.clone(),
        envelope,
        endpoint_ref: request.endpoint_ref.clone(),
        payload_sha256,
        stage: ReactiveContextStage::EnqueuedPersisted,
        predecessor_stage: None,
        owner_receipt: request.owner_receipt.clone(),
        ack_ledger,
        ack_evidence: Vec::new(),
        transport_ref: None,
        cancellation_ref: None,
        reconciliation_ref: None,
        reason: None,
        queue_generation,
        charged_bytes,
        last_mutation_sequence: 0,
    };
    entry.validate()?;
    Ok(entry)
}

fn transition_validate(
    transition: &ReactiveContextTransition,
) -> Result<(), ReactiveContextQueueError> {
    transition
        .fence
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    transition
        .mutation
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    transition
        .target
        .validate()
        .map_err(ReactiveContextQueueError::Journal)?;
    if transition.mutation == transition.target {
        return Err(ReactiveContextQueueError::IdentityConflict);
    }
    validate_evidence(&transition.evidence)?;
    Ok(())
}

fn validate_evidence(
    evidence: &ReactiveContextTransitionEvidence,
) -> Result<(), ReactiveContextQueueError> {
    if let Some(receipt) = &evidence.owner_receipt {
        receipt.validate().map_err(protocol_error)?;
    }
    for value in [
        &evidence.transport_ref,
        &evidence.cancellation_ref,
        &evidence.reconciliation_ref,
    ]
    .into_iter()
    .flatten()
    {
        if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
            return Err(ReactiveContextQueueError::Invalid(
                "transition reference is malformed".into(),
            ));
        }
    }
    if let Some(reason) = &evidence.reason {
        validate_reason(reason)?;
    }
    if evidence.observed_at_unix_ms == Some(0) {
        return Err(ReactiveContextQueueError::Invalid(
            "observed_at_unix_ms must be non-zero when supplied".into(),
        ));
    }
    Ok(())
}

fn validate_stage_transition(
    from: ReactiveContextStage,
    to: ReactiveContextStage,
    ack: Option<&ReactiveContextAckEvidence>,
) -> Result<(), JournalError> {
    let duplicate_history = ack.is_some_and(|evidence| {
        evidence.receipt.disposition == eliot_protocol::EventDisposition::Duplicate
            && evidence.disposition
                == eliot_protocol::ReactiveContextAckDisposition::DuplicateHistorical
    });
    if from == to && (duplicate_history || ack.is_some()) {
        return Ok(());
    }
    let legal = match from {
        ReactiveContextStage::EnqueuedPersisted => matches!(
            to,
            ReactiveContextStage::RejectedNotAttempted
                | ReactiveContextStage::DeliveryAttempted
                | ReactiveContextStage::UnknownDelivery
                | ReactiveContextStage::DeliveredToExactEndpoint
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::DeliveryAttempted => matches!(
            to,
            ReactiveContextStage::UnknownDelivery
                | ReactiveContextStage::DeliveredToExactEndpoint
                | ReactiveContextStage::RecipientReceived
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::UnknownDelivery => matches!(
            to,
            ReactiveContextStage::UnknownDelivery
                | ReactiveContextStage::DeliveredToExactEndpoint
                | ReactiveContextStage::RecipientReceived
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::DeliveredToExactEndpoint => matches!(
            to,
            ReactiveContextStage::RecipientReceived
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::ExpiredBeforeAck
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::RecipientReceived => matches!(
            to,
            ReactiveContextStage::RecipientDurable
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::RecipientDurable => matches!(
            to,
            ReactiveContextStage::NormalizedProjection
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::NormalizedProjection => matches!(
            to,
            ReactiveContextStage::AppliedProjection
                | ReactiveContextStage::AcknowledgementUnknown
                | ReactiveContextStage::AcknowledgementRejected
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        ),
        ReactiveContextStage::RejectedNotAttempted
        | ReactiveContextStage::AppliedProjection
        | ReactiveContextStage::AcknowledgementRejected
        | ReactiveContextStage::AcknowledgementUnknown
        | ReactiveContextStage::ExpiredBeforeAck
        | ReactiveContextStage::CancelledRetracted
        | ReactiveContextStage::StaleSuperseded
        | ReactiveContextStage::UnavailableFenced
        | ReactiveContextStage::InvalidAcknowledgement
        | ReactiveContextStage::ValidatedNotEnqueued => false,
    };
    if legal {
        Ok(())
    } else {
        Err(JournalError::IllegalTransition {
            machine: "reactive_context_queue",
            from: format!("{from:?}"),
            to: format!("{to:?}"),
        })
    }
}

fn apply_transition_evidence(
    entry: &mut ReactiveContextQueueEntry,
    transition: &ReactiveContextTransition,
) -> Result<(), JournalError> {
    let evidence = &transition.evidence;
    if let Some(ack) = &evidence.ack {
        let expected_stage = stage_for_ack(ack.observed_phase);
        let disposition = entry
            .ack_ledger
            .record(ack, &entry.payload)
            .map_err(|error| JournalError::ReactiveContext(error.to_string()))?;
        if expected_stage != transition.next_stage
            && disposition != eliot_protocol::ReactiveContextAckDisposition::DuplicateHistorical
        {
            return Err(JournalError::ReactiveContext(
                "ack phase and queue stage do not match".into(),
            ));
        }
        if disposition != eliot_protocol::ReactiveContextAckDisposition::DuplicateHistorical {
            entry.ack_evidence.push(ack.clone());
        }
    } else if matches!(
        transition.next_stage,
        ReactiveContextStage::RecipientReceived
            | ReactiveContextStage::RecipientDurable
            | ReactiveContextStage::NormalizedProjection
            | ReactiveContextStage::AppliedProjection
            | ReactiveContextStage::AcknowledgementRejected
            | ReactiveContextStage::AcknowledgementUnknown
    ) {
        return Err(JournalError::ReactiveContext(
            "acknowledgement stage requires exact #796 evidence".into(),
        ));
    }
    if let Some(receipt) = &evidence.owner_receipt {
        entry.owner_receipt = Some(receipt.clone());
    }
    if let Some(value) = &evidence.transport_ref {
        entry.transport_ref = Some(value.clone());
    }
    if let Some(value) = &evidence.cancellation_ref {
        entry.cancellation_ref = Some(value.clone());
    }
    if let Some(value) = &evidence.reconciliation_ref {
        entry.reconciliation_ref = Some(value.clone());
    }
    if let Some(reason) = &evidence.reason {
        entry.reason = Some(reason.clone());
    }
    if matches!(
        transition.next_stage,
        ReactiveContextStage::UnknownDelivery
            | ReactiveContextStage::AcknowledgementUnknown
            | ReactiveContextStage::InvalidAcknowledgement
    ) && evidence.reconciliation_ref.is_none()
    {
        return Err(JournalError::ReactiveContext(
            "unknown/invalid outcome requires a reconciliation reference".into(),
        ));
    }
    if matches!(
        transition.next_stage,
        ReactiveContextStage::CancelledRetracted
            | ReactiveContextStage::ExpiredBeforeAck
            | ReactiveContextStage::StaleSuperseded
            | ReactiveContextStage::UnavailableFenced
            | ReactiveContextStage::RejectedNotAttempted
    ) && evidence.reason.is_none()
    {
        return Err(JournalError::ReactiveContext(
            "terminal non-success stage requires an explicit bounded reason".into(),
        ));
    }
    Ok(())
}

fn stage_for_ack(phase: AckPhase) -> ReactiveContextStage {
    match phase {
        AckPhase::Received => ReactiveContextStage::RecipientReceived,
        AckPhase::Durable => ReactiveContextStage::RecipientDurable,
        AckPhase::Normalized => ReactiveContextStage::NormalizedProjection,
        AckPhase::Applied => ReactiveContextStage::AppliedProjection,
        AckPhase::Rejected => ReactiveContextStage::AcknowledgementRejected,
        AckPhase::Unknown => ReactiveContextStage::AcknowledgementUnknown,
    }
}

fn operation_identity(
    payload: &ReactiveContextPayload,
) -> Result<IdempotencyIdentity, ReactiveContextQueueError> {
    Ok(IdempotencyIdentity {
        operation_id: PlatformHandle::new(payload.operation_id.as_str().to_owned())
            .map_err(|error| ReactiveContextQueueError::Invalid(error.to_string()))?,
        idempotency_key: PlatformHandle::new(payload.idempotency_key.clone())
            .map_err(|error| ReactiveContextQueueError::Invalid(error.to_string()))?,
    })
}

fn operation_key(operation: &IdempotencyIdentity) -> String {
    format!(
        "{}\u{1f}{}",
        operation.operation_id, operation.idempotency_key
    )
}

fn sequence_key(stream: &str, sequence: u64) -> String {
    format!("{stream}\u{1f}{sequence}")
}

fn protocol_error(error: impl std::fmt::Display) -> ReactiveContextQueueError {
    ReactiveContextQueueError::Invalid(error.to_string())
}

fn validate_reason(reason: &str) -> Result<(), ReactiveContextQueueError> {
    if reason.trim().is_empty()
        || reason.len() > MAX_REACTIVE_CONTEXT_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        return Err(ReactiveContextQueueError::Invalid(
            "queue reason is empty, oversized, or contains control text".into(),
        ));
    }
    Ok(())
}

fn queue_error_to_journal(error: ReactiveContextQueueError) -> JournalError {
    match error {
        ReactiveContextQueueError::Journal(error) => error,
        ReactiveContextQueueError::StaleRevision { expected, actual } => {
            JournalError::ReactiveContext(format!(
                "stale queue revision expected {expected}, actual {actual}"
            ))
        }
        ReactiveContextQueueError::Invalid(reason) => JournalError::ReactiveContext(reason),
        ReactiveContextQueueError::IdentityConflict => JournalError::IdempotencyConflict,
        ReactiveContextQueueError::QueueFull { dimension } => {
            JournalError::ReactiveContext(format!("queue capacity exhausted: {dimension}"))
        }
        ReactiveContextQueueError::NotFound => {
            JournalError::ReactiveContext("queue operation not found".into())
        }
        ReactiveContextQueueError::StaleCursor => {
            JournalError::ReactiveContext("queue cursor is stale".into())
        }
        ReactiveContextQueueError::StillUnknown => {
            JournalError::ReactiveContext("queue operation remains unknown".into())
        }
    }
}

/// Produce one deterministic bounded queue snapshot from a projection.
pub(crate) fn snapshot(
    queue: &ReactiveContextQueueState,
    query: &ReactiveContextQueueQuery,
) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
    queue.validate()?;
    let limit = if query.limit == 0 {
        queue.limits.max_page_items
    } else {
        query.limit
    };
    if limit > queue.limits.max_page_items {
        return Err(ReactiveContextQueueError::QueueFull {
            dimension: "page_items",
        });
    }
    let offset = if let Some(cursor) = &query.cursor {
        if cursor.revision != queue.revision {
            return Err(ReactiveContextQueueError::StaleCursor);
        }
        cursor.offset
    } else {
        0
    };
    let mut filtered = Vec::new();
    for entry in queue.entries.values() {
        if !query.include_terminal && entry.is_terminal() {
            continue;
        }
        if query
            .attempt_id
            .as_ref()
            .is_some_and(|attempt| entry.payload.attempt_id.as_str() != attempt)
        {
            continue;
        }
        if query
            .stream_id
            .as_ref()
            .is_some_and(|stream| entry.envelope.stream_id != *stream)
        {
            continue;
        }
        filtered.push(entry.clone());
    }
    if offset > filtered.len() {
        return Err(ReactiveContextQueueError::StaleCursor);
    }
    let end = offset.saturating_add(limit).min(filtered.len());
    let items = filtered[offset..end].to_vec();
    let next_cursor = (end < filtered.len()).then_some(ReactiveContextQueueCursor {
        revision: queue.revision,
        offset: end,
    });
    let digest_items: Vec<_> = items
        .iter()
        .cloned()
        .map(|mut entry| {
            entry.last_mutation_sequence = 0;
            entry
        })
        .collect();
    let digest_bytes = serde_json::to_vec(&(
        queue.revision,
        queue.queue_generation,
        &digest_items,
        &next_cursor,
    ))
    .map_err(protocol_error)?;
    Ok(ReactiveContextQueueSnapshot {
        revision: queue.revision,
        queue_generation: queue.queue_generation,
        known_empty: filtered.is_empty(),
        partial: next_cursor.is_some(),
        items,
        next_cursor,
        digest: format!("{:x}", Sha256::digest(digest_bytes)),
    })
}

/// Convert a generic Host journal reconciliation result into the queue's
/// transport-independent result shape.
pub(crate) fn map_reconcile(
    outcome: ReconcileOutcome,
    entry: Option<ReactiveContextQueueEntry>,
) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
    match outcome {
        ReconcileOutcome::Committed => entry
            .map(ReactiveContextReconcileOutcome::Committed)
            .ok_or(ReactiveContextQueueError::NotFound),
        ReconcileOutcome::NotCommitted => Ok(ReactiveContextReconcileOutcome::NotApplied),
        ReconcileOutcome::StillUnknown => Ok(ReactiveContextReconcileOutcome::StillUnknown),
    }
}
