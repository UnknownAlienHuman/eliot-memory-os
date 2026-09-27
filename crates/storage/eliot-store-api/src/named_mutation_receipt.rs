//! Named mutation receipts with explicit outcomes and reconciliation.
//!
//! Architecture traceability: `I16.1` (four surfaces — metrics carry bounded
//! labels, durable audit is never sampled), `I16.3` (composite run trace
//! context: State Fence, authority epoch and event sequence are lineage every
//! run/event carries), `I16.4` (required operational events: store
//! transaction/retry/unknown commit), `I16.5` (System metrics: store
//! health/latency/retries) and `I16.11` (no hidden telemetry failure — silent
//! success is forbidden) govern this module, read for issue #1846.
//!
//! Stable mutation identity is NOT a parallel scheme: it reuses the admitted
//! [`OperationId`](crate::OperationId) plus its
//! [`idempotency_key`](crate::WriteReceipt::idempotency_key), exactly as
//! [`WriteReceipt`](crate::WriteReceipt) already binds them.
//!
//! [`MutationOutcome`] is the closed four-arm outcome taxonomy the issue
//! names: committed, rejected, retriable failure, unknown commit. There is no
//! fifth arm, so an unrepresentable outcome is a compile error, not a runtime
//! default.
//!
//! Interrupting a named mutation after request dispatch but before a response
//! can never produce an assumed result: [`MutationAttempt`] records whether
//! the request was dispatched, and [`MutationOutcome::from_dispatch`] maps
//! "dispatched without a response" to [`MutationOutcome::UnknownCommit`] —
//! the only branch a missing response may take. A response receipt, or an
//! explicit pre-dispatch refusal, is required for the other three arms.

use std::fmt;

use eliot_contracts::{EpochId, OperationId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{NamedMutationOperation, StoreError, WriteReceipt};

/// The four explicit outcomes a named mutation attempt may reach.
///
/// This contour is closed on purpose: the issue names exactly these four, and
/// a missing fifth arm keeps an unrepresentable outcome a compile-time event.
/// A retriable failure stays a typed arm — it is never collapsed into a
/// rejection or into a string (issue #204).
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MutationOutcome {
    /// The store returned a committed terminal receipt for this identity.
    Committed,
    /// The store deterministically refused the mutation; it did not apply.
    Rejected,
    /// The mutation did not reach a terminal state and the same identity may
    /// be retried after the named condition clears.
    RetriableFailure,
    /// The request was dispatched but no response was observed. The commit
    /// status is unproven; the mutation stays operational reconciliation
    /// state until an exact reconciliation read resolves it (I16.11: silent
    /// success is forbidden).
    UnknownCommit,
}

impl MutationOutcome {
    /// Stable bounded snake-case identity used as a metric label value and in
    /// receipts. The four names are the issue vocabulary, unchanged.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Rejected => "rejected",
            Self::RetriableFailure => "retriable_failure",
            Self::UnknownCommit => "unknown_commit",
        }
    }

    /// Classifies a dispatched named mutation attempt by whether a response
    /// was observed.
    ///
    /// A dispatched attempt with no response is exactly the acceptance-criteria
    /// case, and it yields [`Self::UnknownCommit`] — the commit status is
    /// unproven, so no other arm is reachable. A dispatched attempt that did
    /// receive a response is classified from its receipt by
    /// [`NamedMutationReceipt::committed`] or
    /// [`NamedMutationReceipt::rejected`], never by this function; an
    /// undispatched request never commits and is re-reported as
    /// [`Self::RetriableFailure`].
    #[must_use]
    pub const fn from_dispatch(dispatched: bool, response_received: bool) -> Self {
        if dispatched && !response_received {
            Self::UnknownCommit
        } else {
            // Undispatched, or dispatched-and-answered. Neither can be
            // silently committed: only a real WriteReceipt can.
            Self::RetriableFailure
        }
    }
}

impl fmt::Display for MutationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Durable handle to the store record or receipt a mutation attempt produced.
///
/// This is the bounded reference an audit record and a metric sample cite
/// instead of repeating content: the value is a non-empty, bounded, control
/// free handle, matching the crate's existing
/// [`StoreEvidenceHandles`](crate::StoreEvidenceHandles) rule
/// ([`MAX_STORE_FAILURE_REFERENCE_LEN`](crate::MAX_STORE_FAILURE_REFERENCE_LEN)).
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct DurableRecordHandle(String);

impl DurableRecordHandle {
    /// Constructs a bounded durable record/receipt handle.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > crate::MAX_STORE_FAILURE_REFERENCE_LEN
            || value.chars().any(char::is_control)
        {
            return Err(StoreError::InvalidField {
                field: "durable_record_handle",
                reason: "must be bounded, non-empty and free of control characters",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DurableRecordHandle {
    type Error = StoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DurableRecordHandle> for String {
    fn from(value: DurableRecordHandle) -> Self {
        value.0
    }
}

impl fmt::Display for DurableRecordHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Monotonic position of one attempt inside the event stream (I16.3
/// "event sequence/cursor").
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct MutationEventSequence(pub u64);

impl MutationEventSequence {
    /// Constructs a non-zero event sequence.
    pub fn new(sequence: u64) -> Result<Self, StoreError> {
        if sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "event_sequence",
                reason: "must be non-zero",
            });
        }
        Ok(Self(sequence))
    }

    /// Returns the sequence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Elapsed wall time of one attempt, in milliseconds.
///
/// The value is the measured duration across the attempt, including any
/// retries already spent; it is bounded to a 32-bit value so a clock or
/// transport defect cannot overflow it into a fabricated latency.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "u64", into = "u64")]
pub struct ElapsedMillis(u64);

impl ElapsedMillis {
    /// Constructs a bounded elapsed measurement.
    pub fn new(millis: u64) -> Result<Self, StoreError> {
        if millis > u64::from(u32::MAX) {
            return Err(StoreError::InvalidField {
                field: "elapsed_ms",
                reason: "elapsed measurement exceeds the bounded range",
            });
        }
        Ok(Self(millis))
    }

    /// Returns the measured milliseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for ElapsedMillis {
    type Error = StoreError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ElapsedMillis> for u64 {
    fn from(value: ElapsedMillis) -> Self {
        value.0
    }
}

/// Durable audit record for one named-mutation attempt and its receipt
/// (issue #1846 "Kernel must audit each attempt and receipt").
///
/// Every field the issue names is required and typed: the State Fence, the
/// authority epoch, the event sequence, the elapsed timing, the retry count,
/// and the durable record/receipt handle. `authority_epoch` is referenced
/// from the owning [`StateFence`] rather than redefined, and is validated
/// equal to it — a receipt cannot be audited under a foreign epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationAuditRecord {
    /// Stable mutation identity: the admitted operation identity.
    pub operation_id: OperationId,
    /// The closed named mutation this attempt ran.
    pub operation: NamedMutationOperation,
    /// The explicit outcome reached by this attempt.
    pub outcome: MutationOutcome,
    /// State Fence the attempt ran under.
    pub state_fence: StateFence,
    /// Authority epoch of the attempt; must equal `state_fence`'s.
    pub authority_epoch: EpochId,
    /// Position of this attempt in the event stream.
    pub event_sequence: MutationEventSequence,
    /// Elapsed wall time for the attempt, retries included.
    pub elapsed: ElapsedMillis,
    /// Number of same-identity retries already spent; `0` is the first try.
    pub retry_count: u32,
    /// Whether the request was dispatched to the store.
    pub dispatched: bool,
    /// Durable store record/receipt handle the attempt produced or awaited.
    pub durable_handle: DurableRecordHandle,
}

/// The required per-attempt lineage the audit record binds (I16.3).
///
/// Grouping keeps the identity/fence/timing/handle axis in one typed value
/// instead of a long positional argument list, so no field can be silently
/// transposed at a call site.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationAuditLineage {
    /// Stable mutation identity: the admitted operation identity.
    pub operation_id: OperationId,
    /// The closed named mutation this attempt ran.
    pub operation: NamedMutationOperation,
    /// State Fence the attempt ran under.
    pub state_fence: StateFence,
    /// Position of this attempt in the event stream.
    pub event_sequence: MutationEventSequence,
    /// Elapsed wall time for the attempt, retries included.
    pub elapsed: ElapsedMillis,
    /// Number of same-identity retries already spent; `0` is the first try.
    pub retry_count: u32,
    /// Durable store record/receipt handle the attempt produced or awaited.
    pub durable_handle: DurableRecordHandle,
}

impl MutationAuditLineage {
    /// Audits one attempt under this lineage, binding the explicit outcome
    /// and the dispatch fact.
    ///
    /// The authority epoch is copied from the lineage's State Fence, so it can
    /// never be a foreign epoch. An undispatched attempt may not claim
    /// [`MutationOutcome::UnknownCommit`]: nothing was sent, so there is no
    /// commit to be unproven about.
    pub fn audit(
        self,
        outcome: MutationOutcome,
        dispatched: bool,
    ) -> Result<MutationAuditRecord, StoreError> {
        let record = MutationAuditRecord {
            operation_id: self.operation_id.clone(),
            operation: self.operation,
            outcome,
            authority_epoch: self.state_fence.authority_epoch.clone(),
            state_fence: self.state_fence,
            event_sequence: self.event_sequence,
            elapsed: self.elapsed,
            retry_count: self.retry_count,
            dispatched,
            durable_handle: self.durable_handle,
        };
        record.validate()?;
        Ok(record)
    }
}

impl MutationAuditRecord {
    /// Rejects an audit record whose lineage contradicts its own fence or
    /// whose dispatch fact contradicts its outcome.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(StoreError::InvalidReceipt);
        }
        if self.outcome == MutationOutcome::UnknownCommit && !self.dispatched {
            return Err(StoreError::InvalidField {
                field: "dispatched",
                reason: "unknown commit requires a dispatched request",
            });
        }
        Ok(())
    }
}

/// One named-mutation receipt: the attempt audit plus its explicit outcome
/// and, when the store answered, the durable write receipt itself.
///
/// The receipt is the single place an operator reads "what happened to this
/// mutation": the identity, the outcome arm, the audit lineage, and the
/// canonical [`WriteReceipt`] that proves the commit. A committed receipt
/// without its [`WriteReceipt`] is refused — commit is never assumed from the
/// outcome label alone.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedMutationReceipt {
    /// Stable mutation identity: the admitted operation identity.
    pub operation_id: OperationId,
    /// The closed named mutation this receipt covers.
    pub operation: NamedMutationOperation,
    /// Same-identity key that makes a resubmission of this identity
    /// idempotent; reused from [`WriteReceipt::idempotency_key`], not a
    /// parallel scheme.
    pub idempotency_key: String,
    /// The explicit outcome.
    pub outcome: MutationOutcome,
    /// Audit lineage of the attempt that produced this receipt.
    pub audit: MutationAuditRecord,
    /// The canonical write receipt, present exactly when the store returned
    /// one.
    pub write_receipt: Option<WriteReceipt>,
}

impl NamedMutationReceipt {
    /// Builds the receipt returned by a committed attempt.
    pub fn committed(
        operation: NamedMutationOperation,
        write_receipt: WriteReceipt,
        audit: MutationAuditRecord,
    ) -> Result<Self, StoreError> {
        write_receipt
            .validate()
            .map_err(|_| StoreError::InvalidReceipt)?;
        if write_receipt.status != crate::WriteReceiptStatus::Committed {
            return Err(StoreError::InvalidReceipt);
        }
        if write_receipt.operation_id != audit.operation_id {
            return Err(StoreError::InvalidReceipt);
        }
        let receipt = Self {
            operation_id: audit.operation_id.clone(),
            operation,
            idempotency_key: write_receipt.idempotency_key.clone(),
            outcome: MutationOutcome::Committed,
            audit,
            write_receipt: Some(write_receipt),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Builds the receipt for a deterministic rejection, carrying the typed
    /// rejection reason and no commit evidence.
    pub fn rejected(
        operation: NamedMutationOperation,
        audit: MutationAuditRecord,
    ) -> Result<Self, StoreError> {
        let receipt = Self {
            operation_id: audit.operation_id.clone(),
            operation,
            idempotency_key: String::new(),
            outcome: MutationOutcome::Rejected,
            audit,
            write_receipt: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Builds the receipt for a retriable failure, carrying the typed failure
    /// and no commit evidence.
    pub fn retriable_failure(
        operation: NamedMutationOperation,
        audit: MutationAuditRecord,
    ) -> Result<Self, StoreError> {
        let receipt = Self {
            operation_id: audit.operation_id.clone(),
            operation,
            idempotency_key: String::new(),
            outcome: MutationOutcome::RetriableFailure,
            audit,
            write_receipt: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Builds the receipt for an attempt interrupted after dispatch but before
    /// a response.
    ///
    /// This is the acceptance-criteria path. The outcome is not a parameter:
    /// it is derived from the dispatch/response facts through
    /// [`MutationOutcome::from_dispatch`], and a dispatched request with no
    /// response can therefore only ever land on
    /// [`MutationOutcome::UnknownCommit`]. Carrying no [`WriteReceipt`] is the
    /// whole point, because no response was observed, so the receipt stands as
    /// operational reconciliation state until a named reconciliation read
    /// resolves it — never as an assumed result. An undispatched attempt is
    /// refused outright: nothing was sent, so there is no commit to be
    /// unproven about.
    pub fn interrupted(
        operation: NamedMutationOperation,
        audit: MutationAuditRecord,
        response_received: bool,
    ) -> Result<Self, StoreError> {
        let dispatched = audit.dispatched;
        let outcome = MutationOutcome::from_dispatch(dispatched, response_received);
        if outcome != MutationOutcome::UnknownCommit {
            return Err(StoreError::InvalidField {
                field: "response_received",
                reason: "an undispatched request cannot have an unknown commit",
            });
        }
        let receipt = Self {
            operation_id: audit.operation_id.clone(),
            operation,
            idempotency_key: String::new(),
            outcome,
            audit,
            write_receipt: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Requires the durable write receipt that proves a committed outcome.
    pub fn require_write_receipt(&self) -> Result<&WriteReceipt, StoreError> {
        self.write_receipt
            .as_ref()
            .ok_or(StoreError::MissingReceiptEnvelope)
    }

    /// Rejects a receipt whose identity, outcome and evidence contradict each
    /// other.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.audit.validate()?;
        if self.audit.operation != self.operation
            || self.audit.operation_id != self.operation_id
            || self.audit.outcome != self.outcome
        {
            return Err(StoreError::InvalidReceipt);
        }
        match self.outcome {
            MutationOutcome::Committed => {
                let receipt = self.require_write_receipt()?;
                if receipt.operation_id != self.operation_id
                    || receipt.idempotency_key != self.idempotency_key
                    || receipt.status != crate::WriteReceiptStatus::Committed
                {
                    return Err(StoreError::InvalidReceipt);
                }
            }
            MutationOutcome::UnknownCommit | MutationOutcome::RetriableFailure => {
                if self.write_receipt.is_some() || !self.idempotency_key.is_empty() {
                    return Err(StoreError::InvalidReceipt);
                }
            }
            MutationOutcome::Rejected => {
                if self.write_receipt.is_some() {
                    return Err(StoreError::InvalidReceipt);
                }
            }
        }
        Ok(())
    }
}

/// Closed terminal result of a reconciliation read.
///
/// `Committed` means the exact durable [`WriteReceipt`] was found; `Absent`
/// means the mutation is proven absent. There is no third arm: a
/// reconciliation read either finds the committed receipt or proves the
/// mutation absent. It never re-opens the mutation and never assumes a result.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MutationResolution {
    /// The mutation committed; the exact write receipt is attached.
    Committed,
    /// The mutation is proven absent: no commit exists for this identity.
    Absent,
}

impl MutationResolution {
    /// Returns the stable bounded identity of this resolution arm.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Absent => "absent",
        }
    }
}

impl fmt::Display for MutationResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The resolution of one reconciliation read plus its commit evidence.
///
/// A committed resolution always carries the exact [`WriteReceipt`]; an
/// absent resolution carries none. A committed resolution without its receipt
/// would re-introduce the assumed result this module exists to prevent, so the
/// pairing is validated, not merely documented.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReconciliation {
    /// The closed result the read reached.
    pub resolution: MutationResolution,
    /// The exact write receipt, present exactly for
    /// [`MutationResolution::Committed`].
    pub write_receipt: Option<WriteReceipt>,
}

impl MutationReconciliation {
    /// Resolves the mutation to committed with its exact write receipt.
    pub fn committed(write_receipt: WriteReceipt) -> Result<Self, StoreError> {
        if write_receipt.status != crate::WriteReceiptStatus::Committed {
            return Err(StoreError::InvalidReceipt);
        }
        write_receipt
            .validate()
            .map_err(|_| StoreError::InvalidReceipt)?;
        let reconciliation = Self {
            resolution: MutationResolution::Committed,
            write_receipt: Some(write_receipt),
        };
        reconciliation.validate()?;
        Ok(reconciliation)
    }

    /// Resolves the mutation to proven-absent with no commit evidence.
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            resolution: MutationResolution::Absent,
            write_receipt: None,
        }
    }

    /// Requires the exact write receipt proving a committed resolution.
    pub fn require_write_receipt(&self) -> Result<&WriteReceipt, StoreError> {
        if self.resolution != MutationResolution::Committed {
            return Err(StoreError::ReceiptNotFound);
        }
        self.write_receipt
            .as_ref()
            .ok_or(StoreError::MissingReceiptEnvelope)
    }

    /// Rejects a resolution whose commit evidence contradicts its arm.
    pub fn validate(&self) -> Result<(), StoreError> {
        match (self.resolution, &self.write_receipt) {
            (MutationResolution::Committed, Some(receipt)) => {
                if receipt.status != crate::WriteReceiptStatus::Committed {
                    return Err(StoreError::InvalidReceipt);
                }
                Ok(())
            }
            (MutationResolution::Absent, None) => Ok(()),
            (MutationResolution::Committed, None) | (MutationResolution::Absent, Some(_)) => {
                Err(StoreError::InvalidReceipt)
            }
        }
    }
}

/// Receipt recording how a reconciliation read resolved a mutation.
///
/// This is the durable evidence that an [`MutationOutcome::UnknownCommit`]
/// was resolved rather than guessed: it names the mutation identity, the
/// fence the read ran under, the event sequence it occupied, and the
/// [`DurableRecordHandle`] of the write receipt it resolved to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationReceipt {
    /// Stable mutation identity that was reconciled.
    pub operation_id: OperationId,
    /// The closed named mutation that was reconciled.
    pub operation: NamedMutationOperation,
    /// The resolution the read reached.
    pub resolution: MutationReconciliation,
    /// State Fence the reconciliation read ran under.
    pub state_fence: StateFence,
    /// Event sequence the reconciliation read occupied.
    pub event_sequence: MutationEventSequence,
    /// Elapsed wall time of the reconciliation read.
    pub elapsed: ElapsedMillis,
    /// Durable record/receipt handle the resolution resolved to.
    pub durable_handle: DurableRecordHandle,
}

impl ReconciliationReceipt {
    /// Builds and validates one resolution receipt.
    pub fn new(
        operation_id: OperationId,
        operation: NamedMutationOperation,
        resolution: MutationReconciliation,
        state_fence: &StateFence,
        event_sequence: MutationEventSequence,
        elapsed: ElapsedMillis,
        durable_handle: DurableRecordHandle,
    ) -> Result<Self, StoreError> {
        let receipt = Self {
            operation_id,
            operation,
            resolution,
            state_fence: state_fence.clone(),
            event_sequence,
            elapsed,
            durable_handle,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Rejects a resolution receipt whose fence is invalid, whose resolution
    /// contradicts its own commit evidence, or whose committed arm carries a
    /// write receipt for another identity.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        self.resolution.validate()?;
        if self.resolution.resolution == MutationResolution::Committed {
            let receipt = self.resolution.require_write_receipt()?;
            if receipt.operation_id != self.operation_id {
                return Err(StoreError::InvalidReceipt);
            }
        }
        Ok(())
    }
}

/// Request for the named reconciliation read (issue #1846).
///
/// The read resolves one stable mutation identity to committed or absent. It
/// carries no semantic authority and cannot mutate; it is the only path that
/// turns an [`MutationOutcome::UnknownCommit`] into a decided result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReconciliationRequest {
    /// Stable mutation identity to reconcile.
    pub operation_id: OperationId,
    /// State Fence the reconciliation read runs under.
    pub state_fence: StateFence,
}

/// Closed response of the named reconciliation read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReconciliationResponse {
    /// Stable mutation identity that was reconciled.
    pub operation_id: OperationId,
    /// The closed named mutation that was reconciled.
    pub operation: NamedMutationOperation,
    /// The durable resolution receipt recording how the read resolved.
    pub receipt: ReconciliationReceipt,
}

/// Bounded store health/latency/retry/unknown-commit metric labels.
///
/// Every label value is drawn from a closed enumeration, so the metrics
/// endpoint can always distinguish retries and unknown commits from ordinary
/// failures while keeping labels bounded: no task ids, no unbounded error
/// strings, and no user content. Per `I16.1` metrics carry bounded labels;
/// per `field_policy` a `MetricSample` family allows low-cardinality opaque
/// values only.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum MutationMetricLabel {
    /// Health of the store edge.
    StoreHealth,
    /// Latency of a store transaction.
    StoreLatency,
    /// A same-identity retry.
    StoreRetry,
    /// An unknown-commit event awaiting reconciliation.
    StoreUnknownCommit,
}

impl MutationMetricLabel {
    /// Stable bounded label key, matching the `I16.4` required-event
    /// vocabulary (`store transaction/retry/unknown commit`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreHealth => "store_health",
            Self::StoreLatency => "store_latency",
            Self::StoreRetry => "store_retry",
            Self::StoreUnknownCommit => "store_unknown_commit",
        }
    }
}

impl fmt::Display for MutationMetricLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One bounded store mutation metric sample.
///
/// The sample carries only closed-enum labels plus the operation identity and
/// the explicit outcome, so the endpoint can answer "was this a retry or an
/// unknown commit?" without any unbounded value crossing the label boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationMetricSample {
    /// The bounded label this sample reports under.
    pub label: MutationMetricLabel,
    /// The named mutation the sample describes.
    pub operation: NamedMutationOperation,
    /// The explicit outcome the sample reports; distinguishes retries and
    /// unknown commits from ordinary failures.
    pub outcome: MutationOutcome,
    /// The measured store latency for the attempt.
    pub latency: ElapsedMillis,
    /// Number of same-identity retries already spent.
    pub retry_count: u32,
    /// Durable record/receipt handle the sample cites.
    pub durable_handle: DurableRecordHandle,
}

impl MutationMetricSample {
    /// Builds one sample from an attempt receipt.
    ///
    /// The label is chosen from the outcome so a retriable failure reports
    /// [`MutationMetricLabel::StoreRetry`] and an interrupted attempt reports
    /// [`MutationMetricLabel::StoreUnknownCommit`], while a committed or
    /// rejected attempt reports
    /// [`MutationMetricLabel::StoreHealth`]/[`MutationMetricLabel::StoreLatency`].
    pub fn from_receipt(receipt: &NamedMutationReceipt) -> Result<Self, StoreError> {
        receipt.validate()?;
        let label = match receipt.outcome {
            MutationOutcome::UnknownCommit => MutationMetricLabel::StoreUnknownCommit,
            MutationOutcome::RetriableFailure => MutationMetricLabel::StoreRetry,
            MutationOutcome::Committed | MutationOutcome::Rejected => {
                MutationMetricLabel::StoreHealth
            }
        };
        Ok(Self {
            label,
            operation: receipt.operation,
            outcome: receipt.outcome,
            latency: receipt.audit.elapsed,
            retry_count: receipt.audit.retry_count,
            durable_handle: receipt.audit.durable_handle.clone(),
        })
    }

    /// Rejects a sample whose label disagrees with the outcome it reports, or
    /// whose bounded handle is unusable.
    pub fn validate(&self) -> Result<(), StoreError> {
        let expected = match self.outcome {
            MutationOutcome::UnknownCommit => MutationMetricLabel::StoreUnknownCommit,
            MutationOutcome::RetriableFailure => MutationMetricLabel::StoreRetry,
            MutationOutcome::Committed | MutationOutcome::Rejected => {
                MutationMetricLabel::StoreHealth
            }
        };
        if self.label != expected {
            return Err(StoreError::InvalidField {
                field: "mutation_metric.label",
                reason: "label must match the reported outcome",
            });
        }
        DurableRecordHandle::new(self.durable_handle.as_str().to_owned())?;
        Ok(())
    }
}
