//! Host-owned orchestration for outbound reactive Context delivery.
//!
//! This module owns the sequencing between the typed #800 HostState queue and
//! an injected transport owner.  It does not assemble Context, select a
//! provider, open a socket, mutate active Context, or infer acknowledgement
//! phases.  The queue remains the only durable operation authority; this
//! service keeps only bounded call-local coordination state.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::sha256_hex;
use eliot_host_state::{
    IdempotencyIdentity, ReactiveContextOperationQuery, ReactiveContextPrepareRequest,
    ReactiveContextPrepareResult, ReactiveContextQueueEntry, ReactiveContextQueueError,
    ReactiveContextQueuePort, ReactiveContextQueueQuery, ReactiveContextTransition,
    ReactiveContextTransitionEvidence, RecordFence,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::reactive_context::{
    ReactiveContextAckDisposition, ReactiveContextAckEvidence, ReactiveContextContentRef,
    ReactiveContextPayload, ReactiveContextRecipient, ReactiveContextValidity,
};
use eliot_protocol::{EventEnvelope, ReactiveContextStage};
use thiserror::Error;

/// Maximum reason bytes retained from an injected transport port.
pub const MAX_DELIVERY_REASON_BYTES: usize = 4 * 1024;
/// Maximum number of queue pages traversed by one bounded operation.
pub const MAX_DELIVERY_QUEUE_PAGES: usize = 1024;

/// A typed source of current Host time used for deadline and expiry checks.
pub trait ReactiveContextClock {
    /// Returns Unix time in milliseconds from the owner clock.
    fn now_unix_ms(&self) -> u64;
}

/// Production clock adapter.  Tests inject a deterministic implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemReactiveContextClock;

impl ReactiveContextClock for SystemReactiveContextClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
    }
}

/// Current Host admission state relevant to a delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDeliveryState {
    /// Host has a current activation and may admit delivery work.
    Active,
    /// Host has committed drain and must admit no new delivery.
    Draining,
    /// Host requires recovery before new delivery may be admitted.
    DegradedRecovery,
    /// Host or its controlling journal is unavailable.
    Unavailable,
}

/// Exact Host and recipient evidence supplied by the owner of those facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDeliveryAdmission {
    /// Current Host activation/installation fence.
    pub fence: RecordFence,
    /// Host activation state at the admission boundary.
    pub state: HostDeliveryState,
    /// Exact recipient identity admitted for this operation.
    pub recipient: ReactiveContextRecipient,
    /// Opaque endpoint reference resolved by the transport owner.
    pub endpoint_ref: PlatformHandle,
    /// Bounded owner receipt for this admission observation.
    pub admission_ref: PlatformHandle,
}

/// Request to admit one typed reactive Context payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextDeliveryRequest {
    /// Fully typed, owner-produced payload.
    pub payload: ReactiveContextPayload,
    /// Optional immutable owner receipt for the enqueue admission.
    pub owner_receipt: Option<ReactiveContextContentRef>,
    /// Whether this operation may consume the reserved control capacity.
    pub control: bool,
}

/// A transport endpoint resolved against one exact admitted recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextResolvedEndpoint {
    /// Exact endpoint reference returned by the transport owner.
    pub endpoint_ref: PlatformHandle,
    /// Recipient identity the endpoint is currently bound to.
    pub recipient: ReactiveContextRecipient,
    /// Stable transport operation identity used for send and reconciliation.
    pub transport_operation: PlatformHandle,
}

/// Result of exact endpoint resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextEndpointResolution {
    /// A current endpoint was resolved for the admitted recipient.
    Exact(ReactiveContextResolvedEndpoint),
    /// No transport operation was attempted and the owner rejected admission.
    NotAttempted {
        /// Bounded rejection reason.
        reason: String,
    },
    /// Resolution itself is uncertain; the service must not send or fallback.
    Unknown {
        /// Stable operation used to reconcile the resolution attempt.
        reconciliation: PlatformHandle,
        /// Bounded uncertainty reason.
        reason: String,
    },
}

/// Typed evidence proving an exact endpoint received this operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextTransportReceipt {
    /// Stable transport operation identity.
    pub operation: PlatformHandle,
    /// Endpoint reference that received the event.
    pub endpoint_ref: PlatformHandle,
    /// Owner receipt proving the exact delivery boundary.
    pub owner_receipt: ReactiveContextContentRef,
}

/// Result returned by the injected send operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextSendOutcome {
    /// The exact event reached the resolved endpoint.
    Delivered(ReactiveContextTransportReceipt),
    /// The operation was proven not to have been attempted.
    NotAttempted {
        /// Bounded owner reason.
        reason: String,
    },
    /// The endpoint rejected the operation without a delivery receipt.
    Rejected {
        /// Bounded owner reason.
        reason: String,
    },
    /// The result may represent delivery and must be reconciled by identity.
    Unknown {
        /// Stable operation used for reconciliation.
        reconciliation: PlatformHandle,
        /// Bounded uncertainty reason.
        reason: String,
    },
}

/// Result returned by a same-operation delivery query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextQueryOutcome {
    /// No delivery was attempted for the stable transport operation.
    NotAttempted {
        /// Bounded owner reason.
        reason: String,
    },
    /// The exact operation has a delivery receipt.
    Delivered(ReactiveContextTransportReceipt),
    /// The operation remains uncertain.
    Unknown {
        /// Stable operation used for later reconciliation.
        reconciliation: PlatformHandle,
        /// Bounded uncertainty reason.
        reason: String,
    },
    /// The owner has a final rejection for this operation.
    Rejected {
        /// Bounded owner reason.
        reason: String,
    },
}

/// Result returned by cancellation of one stable transport operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextCancelOutcome {
    /// Cancellation was observed by the transport owner.
    Cancelled,
    /// No delivery was attempted and cancellation is therefore complete.
    NotAttempted,
    /// Cancellation itself is uncertain and requires reconciliation.
    Unknown {
        /// Stable operation used for reconciliation.
        reconciliation: PlatformHandle,
        /// Bounded uncertainty reason.
        reason: String,
    },
}

/// Result returned when an attempt channel is closed during drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveContextChannelCloseOutcome {
    /// The channel owner proved closure.
    Closed,
    /// The channel outcome is unknown.
    Unknown {
        /// Bounded uncertainty reason.
        reason: String,
    },
}

/// Bounded request sent to endpoint resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextResolveRequest {
    /// Stable queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Exact typed payload to bind to the endpoint.
    pub payload: ReactiveContextPayload,
    /// Endpoint reference admitted by Host.
    pub endpoint_ref: PlatformHandle,
}

/// Bounded request sent to the transport send owner.
#[derive(Clone, Debug, PartialEq)]
pub struct ReactiveContextSendRequest {
    /// Stable queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Exact typed payload.
    pub payload: ReactiveContextPayload,
    /// Exact generic event envelope derived from the payload.
    pub envelope: EventEnvelope,
    /// Exact resolved endpoint.
    pub endpoint: ReactiveContextResolvedEndpoint,
}

/// Bounded request sent to delivery reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextQueryRequest {
    /// Stable queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Stable transport operation identity.
    pub transport_operation: PlatformHandle,
    /// Endpoint reference originally admitted.
    pub endpoint_ref: PlatformHandle,
    /// Exact recipient binding.
    pub recipient: ReactiveContextRecipient,
}

/// Bounded request sent to transport cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextCancelRequest {
    /// Stable queue operation identity.
    pub operation: IdempotencyIdentity,
    /// Stable transport operation identity.
    pub transport_operation: PlatformHandle,
    /// Owner cancellation identity.
    pub cancellation_id: PlatformHandle,
}

/// Bounded request sent to close one attempt channel during drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextCloseChannelRequest {
    /// Agent attempt identity.
    pub attempt_id: String,
    /// All active queue operations observed for this attempt.
    pub operations: Vec<IdempotencyIdentity>,
}

/// Typed transport seam owned by the Host/platform composition owner.
pub trait ReactiveContextTransportPort {
    /// Resolve the exact current endpoint for one admitted recipient.
    fn resolve_endpoint(
        &mut self,
        request: ReactiveContextResolveRequest,
    ) -> Result<ReactiveContextEndpointResolution, ReactiveContextTransportError>;

    /// Send one event on the exact resolved operation.
    fn send_event(
        &mut self,
        request: ReactiveContextSendRequest,
    ) -> Result<ReactiveContextSendOutcome, ReactiveContextTransportError>;

    /// Query the same transport operation after an uncertain result.
    fn query_delivery(
        &mut self,
        request: ReactiveContextQueryRequest,
    ) -> Result<ReactiveContextQueryOutcome, ReactiveContextTransportError>;

    /// Request cancellation of the same transport operation.
    fn cancel_delivery(
        &mut self,
        request: ReactiveContextCancelRequest,
    ) -> Result<ReactiveContextCancelOutcome, ReactiveContextTransportError>;

    /// Close an attempt channel and return direct closure evidence.
    fn close_attempt_channel(
        &mut self,
        request: ReactiveContextCloseChannelRequest,
    ) -> Result<ReactiveContextChannelCloseOutcome, ReactiveContextTransportError>;
}

/// Bounded transport-port failure.  Unknown delivery is represented by the
/// typed outcome variants so the service can preserve the operation identity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveContextTransportError {
    /// The port rejected the typed request before an operation was attempted.
    #[error("transport request invalid: {reason}")]
    Invalid {
        /// Bounded reason.
        reason: String,
    },
    /// The required transport capability is currently unavailable.
    #[error("transport unavailable: {reason}")]
    Unavailable {
        /// Bounded reason.
        reason: String,
    },
}

/// Delivery-stage disposition returned with a queue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryDisposition {
    /// The event was durably queued but not sent in this call.
    Queued,
    /// The exact event reached the endpoint.
    Delivered,
    /// The result remains uncertain and is queryable by the same operation.
    DeliveryUnknown,
    /// The operation was rejected before any possible delivery.
    NotAttempted,
    /// The queue already contained the exact event and no new send was made.
    Replay,
    /// The entry already has an acknowledgement phase.
    AlreadyAcknowledged,
    /// The entry is terminal and cannot be sent again.
    AlreadyTerminal,
}

/// Queue entry and disposition returned by a delivery operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextDeliveryReceipt {
    /// Durable entry after the observed operation.
    pub entry: ReactiveContextQueueEntry,
    /// Bounded interpretation of the observed stage.
    pub disposition: DeliveryDisposition,
}

/// Queue entry and exact acknowledgement disposition returned by #796.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextAcknowledgementReceipt {
    /// Durable entry after acknowledgement persistence.
    pub entry: ReactiveContextQueueEntry,
    /// Generic acknowledgement disposition.
    pub disposition: ReactiveContextAckDisposition,
}

/// Independent service limits.  Queue capacity remains owned by #800.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactiveContextDeliveryLimits {
    /// Maximum simultaneously non-terminal operations admitted by this seam.
    pub max_in_flight: usize,
    /// Maximum operations waiting for recipient acknowledgement.
    pub max_pending_ack: usize,
    /// Maximum same-operation reconciliation queries in one recovery pass.
    pub max_reconciliation_queries: usize,
    /// Maximum active operations inspected by one drain pass.
    pub max_drain_operations: usize,
    /// Additional control capacity reserved above normal in-flight capacity.
    pub reserved_control_capacity: usize,
}

impl Default for ReactiveContextDeliveryLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 64,
            max_pending_ack: 64,
            max_reconciliation_queries: 64,
            max_drain_operations: 256,
            reserved_control_capacity: 4,
        }
    }
}

impl ReactiveContextDeliveryLimits {
    fn validate(&self) -> Result<(), ReactiveContextDeliveryError> {
        if self.max_in_flight == 0
            || self.max_pending_ack == 0
            || self.max_reconciliation_queries == 0
            || self.max_drain_operations == 0
        {
            return Err(ReactiveContextDeliveryError::invalid(
                "limits",
                "delivery limits must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Result of a bounded drain observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainOutcome {
    /// Whether all observed queue and channel work was actually closed.
    pub clean: bool,
    /// Number of attempt channels with direct closure evidence.
    pub closed_attempts: usize,
    /// Attempt identities whose close result was unknown.
    pub unknown_attempts: Vec<String>,
    /// Queue operations that remained non-terminal at observation time.
    pub open_operations: Vec<IdempotencyIdentity>,
}

/// Result of restart reconciliation over durable active queue entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestartReconciliation {
    /// Number of active entries inspected.
    pub inspected: usize,
    /// Number of same-operation transport queries issued.
    pub queries: usize,
    /// Number of entries moved to a known durable result.
    pub reconciled: usize,
    /// Operations that remain delivery-unknown and blocked.
    pub blocked_unknown: Vec<IdempotencyIdentity>,
}

/// Errors returned by the Host delivery orchestrator.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveContextDeliveryError {
    /// A typed input or owner result was malformed.
    #[error("{field} is invalid: {reason}")]
    Invalid {
        /// Stable field path.
        field: &'static str,
        /// Bounded reason.
        reason: String,
    },
    /// The Host admission did not permit this operation.
    #[error("Host admission rejected: {state:?}")]
    HostAdmission {
        /// Observed Host state.
        state: HostDeliveryState,
    },
    /// A queue operation was rejected or remains unresolved.
    #[error("HostState reactive queue: {0}")]
    Queue(#[from] ReactiveContextQueueError),
    /// The transport owner rejected the typed call.
    #[error("reactive Context transport: {0}")]
    Transport(#[from] ReactiveContextTransportError),
    /// The payload deadline has elapsed.
    #[error("reactive Context acknowledgement deadline has elapsed")]
    DeadlineExceeded,
    /// An operation is uncertain and must be reconciled before further work.
    #[error("operation {operation} remains unknown: {reason}")]
    Unknown {
        /// Stable queue operation identity rendered for diagnostics.
        operation: String,
        /// Bounded reason.
        reason: String,
    },
    /// Independent service capacity was reached.
    #[error("reactive Context delivery capacity exhausted: {dimension}")]
    Capacity {
        /// Capacity dimension.
        dimension: &'static str,
    },
    /// The operation is not legal from its current durable stage.
    #[error("operation is not eligible for {action}: {stage:?}")]
    NotEligible {
        /// Requested action.
        action: &'static str,
        /// Current stage.
        stage: ReactiveContextStage,
    },
    /// The supplied generic acknowledgement is not valid for this entry.
    #[error("invalid reactive Context acknowledgement: {reason}")]
    InvalidAcknowledgement {
        /// Bounded validation reason.
        reason: String,
    },
    /// Expiry was requested before the injected owner clock reached the bound.
    #[error("reactive Context operation is not expired")]
    NotExpired,
}

impl ReactiveContextDeliveryError {
    fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}

/// Host-owned reactive Context delivery coordinator.
pub struct ReactiveContextDelivery<Q, T, C = SystemReactiveContextClock> {
    queue: Q,
    transport: T,
    clock: C,
    limits: ReactiveContextDeliveryLimits,
}

impl<Q, T, C> ReactiveContextDelivery<Q, T, C>
where
    Q: ReactiveContextQueuePort,
    T: ReactiveContextTransportPort,
    C: ReactiveContextClock,
{
    /// Construct a coordinator with explicit independent service limits.
    pub fn new(
        queue: Q,
        transport: T,
        clock: C,
        limits: ReactiveContextDeliveryLimits,
    ) -> Result<Self, ReactiveContextDeliveryError> {
        limits.validate()?;
        Ok(Self {
            queue,
            transport,
            clock,
            limits,
        })
    }

    /// Return the injected ports after a bounded proof or test pass.
    pub fn into_parts(self) -> (Q, T, C) {
        (self.queue, self.transport, self.clock)
    }

    /// Admit, persist, and deliver one exact typed reactive Context event.
    pub fn deliver(
        &mut self,
        admission: &HostDeliveryAdmission,
        request: ReactiveContextDeliveryRequest,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        self.validate_admission(admission, &request)?;
        let operation = operation_identity(&request.payload)?;
        let existing = self.find_operation(&operation)?;
        let (entry, replay) = if let Some(entry) = existing {
            if entry.payload != request.payload
                || entry.fence != admission.fence
                || entry.endpoint_ref != admission.endpoint_ref
            {
                return Err(ReactiveContextDeliveryError::Queue(
                    ReactiveContextQueueError::IdentityConflict,
                ));
            }
            (entry, true)
        } else {
            self.enforce_new_capacity(request.control)?;
            let revision = self.queue_revision(&request.payload)?;
            let prepared = self
                .queue
                .prepare_or_replay(ReactiveContextPrepareRequest {
                    fence: admission.fence.clone(),
                    payload: request.payload.clone(),
                    endpoint_ref: admission.endpoint_ref.clone(),
                    owner_receipt: request.owner_receipt.clone(),
                    expected_queue_revision: revision,
                })?;
            match prepared {
                ReactiveContextPrepareResult::Prepared(token) => {
                    (self.queue.commit_enqueued(token)?.entry, false)
                }
                ReactiveContextPrepareResult::Replay(entry) => (entry, true),
            }
        };

        match entry.stage {
            ReactiveContextStage::EnqueuedPersisted => {
                let mut result = self.drive_enqueued(entry)?;
                if replay && result.disposition == DeliveryDisposition::Queued {
                    result.disposition = DeliveryDisposition::Replay;
                }
                Ok(result)
            }
            ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery => {
                self.reconcile_entry(entry)
            }
            stage
                if matches!(
                    stage,
                    ReactiveContextStage::DeliveredToExactEndpoint
                        | ReactiveContextStage::RecipientReceived
                        | ReactiveContextStage::RecipientDurable
                        | ReactiveContextStage::NormalizedProjection
                        | ReactiveContextStage::AppliedProjection
                ) =>
            {
                Ok(ReactiveContextDeliveryReceipt {
                    disposition: if stage == ReactiveContextStage::DeliveredToExactEndpoint {
                        DeliveryDisposition::Delivered
                    } else {
                        DeliveryDisposition::AlreadyAcknowledged
                    },
                    entry,
                })
            }
            _ => Ok(ReactiveContextDeliveryReceipt {
                disposition: DeliveryDisposition::AlreadyTerminal,
                entry,
            }),
        }
    }

    /// Accept and durably record one exact #796 generic acknowledgement.
    pub fn acknowledge(
        &mut self,
        operation: IdempotencyIdentity,
        evidence: ReactiveContextAckEvidence,
    ) -> Result<ReactiveContextAcknowledgementReceipt, ReactiveContextDeliveryError> {
        let entry = self.queue.query_operation(ReactiveContextOperationQuery {
            operation: operation.clone(),
        })?;
        if let Err(error) = evidence.validate_against(&entry.payload) {
            return Err(ReactiveContextDeliveryError::InvalidAcknowledgement {
                reason: bounded_reason(&error.to_string())?,
            });
        }
        let mut replay_ledger = entry.ack_ledger.clone();
        let disposition = match replay_ledger.record(&evidence, &entry.payload) {
            Ok(disposition) => disposition,
            Err(error) => {
                return Err(ReactiveContextDeliveryError::InvalidAcknowledgement {
                    reason: bounded_reason(&error.to_string())?,
                });
            }
        };
        if disposition == ReactiveContextAckDisposition::DuplicateHistorical {
            return Ok(ReactiveContextAcknowledgementReceipt { entry, disposition });
        }
        let next_stage = stage_for_ack(evidence.observed_phase);
        let reconciliation_ref = (evidence.observed_phase == eliot_protocol::AckPhase::Unknown)
            .then(|| make_handle(&format!("ack-reconcile-{}", evidence.proof_sha256)))
            .transpose()?;
        let updated = self.transition(
            &entry,
            next_stage,
            ReactiveContextTransitionEvidence {
                ack: Some(evidence.clone()),
                reconciliation_ref,
                ..ReactiveContextTransitionEvidence::default()
            },
            &format!("ack-{}", evidence.proof_sha256),
        )?;
        Ok(ReactiveContextAcknowledgementReceipt {
            entry: updated,
            disposition,
        })
    }

    /// Reconcile a delivery attempt using the same transport operation.
    pub fn reconcile(
        &mut self,
        operation: IdempotencyIdentity,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let entry = self
            .queue
            .query_operation(ReactiveContextOperationQuery { operation })?;
        match entry.stage {
            ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery => {
                self.reconcile_entry(entry)
            }
            stage if stage == ReactiveContextStage::DeliveredToExactEndpoint => {
                Ok(ReactiveContextDeliveryReceipt {
                    entry,
                    disposition: DeliveryDisposition::Delivered,
                })
            }
            stage
                if matches!(
                    stage,
                    ReactiveContextStage::RecipientReceived
                        | ReactiveContextStage::RecipientDurable
                        | ReactiveContextStage::NormalizedProjection
                        | ReactiveContextStage::AppliedProjection
                ) =>
            {
                Ok(ReactiveContextDeliveryReceipt {
                    entry,
                    disposition: DeliveryDisposition::AlreadyAcknowledged,
                })
            }
            stage => Err(ReactiveContextDeliveryError::NotEligible {
                action: "reconcile",
                stage,
            }),
        }
    }

    /// Expire one operation using the injected owner clock.
    pub fn expire(
        &mut self,
        operation: IdempotencyIdentity,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let mut entry = self
            .queue
            .query_operation(ReactiveContextOperationQuery { operation })?;
        let now = self.clock.now_unix_ms();
        let deadline = entry
            .payload
            .expires_at_unix_ms
            .unwrap_or(entry.payload.acknowledgement_deadline_unix_ms);
        if now < deadline {
            return Err(ReactiveContextDeliveryError::NotExpired);
        }
        if matches!(
            entry.stage,
            ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery
        ) {
            entry = self.reconcile_entry(entry)?.entry;
            if entry.stage == ReactiveContextStage::UnknownDelivery {
                return Err(self.unknown_error(&entry, "expiry is blocked by unknown delivery"));
            }
        }
        if !matches!(
            entry.stage,
            ReactiveContextStage::EnqueuedPersisted
                | ReactiveContextStage::DeliveredToExactEndpoint
        ) {
            return Err(ReactiveContextDeliveryError::NotEligible {
                action: "expire",
                stage: entry.stage,
            });
        }
        let updated = self.transition(
            &entry,
            ReactiveContextStage::ExpiredBeforeAck,
            ReactiveContextTransitionEvidence {
                observed_at_unix_ms: Some(now),
                reason: Some("acknowledgement deadline elapsed".to_owned()),
                ..ReactiveContextTransitionEvidence::default()
            },
            "expire",
        )?;
        Ok(ReactiveContextDeliveryReceipt {
            entry: updated,
            disposition: DeliveryDisposition::AlreadyTerminal,
        })
    }

    /// Cancel one operation, reconciling a possible send before declaring it
    /// cancelled.
    pub fn cancel(
        &mut self,
        operation: IdempotencyIdentity,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let entry = self
            .queue
            .query_operation(ReactiveContextOperationQuery { operation })?;
        let cancellation_ref = make_handle(&format!("cancel-{}", entry.payload.cancellation_id))?;
        if entry.stage == ReactiveContextStage::EnqueuedPersisted {
            let updated = self.transition(
                &entry,
                ReactiveContextStage::CancelledRetracted,
                ReactiveContextTransitionEvidence {
                    cancellation_ref: Some(cancellation_ref),
                    reason: Some("cancelled before any send attempt".to_owned()),
                    ..ReactiveContextTransitionEvidence::default()
                },
                "cancel",
            )?;
            return Ok(ReactiveContextDeliveryReceipt {
                entry: updated,
                disposition: DeliveryDisposition::AlreadyTerminal,
            });
        }
        if !matches!(
            entry.stage,
            ReactiveContextStage::DeliveryAttempted
                | ReactiveContextStage::UnknownDelivery
                | ReactiveContextStage::DeliveredToExactEndpoint
        ) {
            return Err(ReactiveContextDeliveryError::NotEligible {
                action: "cancel",
                stage: entry.stage,
            });
        }
        let transport_operation = entry.transport_ref.clone().ok_or_else(|| {
            ReactiveContextDeliveryError::invalid(
                "transport_ref",
                "possible delivery has no stable transport operation",
            )
        })?;
        let outcome = self
            .transport
            .cancel_delivery(ReactiveContextCancelRequest {
                operation: entry.operation.clone(),
                transport_operation: transport_operation.clone(),
                cancellation_id: cancellation_ref.clone(),
            })?;
        match outcome {
            ReactiveContextCancelOutcome::Cancelled
            | ReactiveContextCancelOutcome::NotAttempted => {
                let updated = self.transition(
                    &entry,
                    ReactiveContextStage::CancelledRetracted,
                    ReactiveContextTransitionEvidence {
                        cancellation_ref: Some(cancellation_ref),
                        transport_ref: Some(transport_operation),
                        reason: Some("transport cancellation observed".to_owned()),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "cancel",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::AlreadyTerminal,
                })
            }
            ReactiveContextCancelOutcome::Unknown {
                reconciliation,
                reason,
            } => {
                let reason = bounded_reason(&reason)?;
                if entry.stage == ReactiveContextStage::DeliveryAttempted {
                    let updated = self.transition(
                        &entry,
                        ReactiveContextStage::UnknownDelivery,
                        ReactiveContextTransitionEvidence {
                            transport_ref: Some(transport_operation),
                            reconciliation_ref: Some(reconciliation),
                            reason: Some(reason),
                            ..ReactiveContextTransitionEvidence::default()
                        },
                        "cancel-unknown",
                    )?;
                    return Ok(ReactiveContextDeliveryReceipt {
                        entry: updated,
                        disposition: DeliveryDisposition::DeliveryUnknown,
                    });
                }
                Err(self.unknown_error(&entry, "cancellation remains unknown"))
            }
        }
    }

    /// Mark an operation stale/superseded without erasing accepted history.
    pub fn supersede(
        &mut self,
        operation: IdempotencyIdentity,
        reason: String,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let reason = bounded_reason(&reason)?;
        let mut entry = self
            .queue
            .query_operation(ReactiveContextOperationQuery { operation })?;
        if matches!(
            entry.stage,
            ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery
        ) {
            entry = self.reconcile_entry(entry)?.entry;
            if entry.stage == ReactiveContextStage::UnknownDelivery {
                return Err(
                    self.unknown_error(&entry, "supersession is blocked by unknown delivery")
                );
            }
        }
        if entry.is_terminal() {
            return Ok(ReactiveContextDeliveryReceipt {
                entry,
                disposition: DeliveryDisposition::AlreadyTerminal,
            });
        }
        let updated = self.transition(
            &entry,
            ReactiveContextStage::StaleSuperseded,
            ReactiveContextTransitionEvidence {
                reason: Some(reason),
                ..ReactiveContextTransitionEvidence::default()
            },
            "supersede",
        )?;
        Ok(ReactiveContextDeliveryReceipt {
            entry: updated,
            disposition: DeliveryDisposition::AlreadyTerminal,
        })
    }

    /// Reconcile all active transport operations after a restart.  No new
    /// send is issued by this method.
    pub fn reconcile_after_restart(
        &mut self,
    ) -> Result<RestartReconciliation, ReactiveContextDeliveryError> {
        let entries = self.load_active_entries(self.limits.max_reconciliation_queries + 1)?;
        let inspected = entries.len();
        let mut queries = 0;
        let mut reconciled = 0;
        let mut blocked_unknown = Vec::new();
        for entry in entries {
            if !matches!(
                entry.stage,
                ReactiveContextStage::DeliveryAttempted | ReactiveContextStage::UnknownDelivery
            ) {
                continue;
            }
            queries += 1;
            if queries > self.limits.max_reconciliation_queries {
                return Err(ReactiveContextDeliveryError::Capacity {
                    dimension: "reconciliation_queries",
                });
            }
            let result = self.reconcile_entry(entry)?;
            if result.entry.stage == ReactiveContextStage::UnknownDelivery {
                blocked_unknown.push(result.entry.operation.clone());
            } else {
                reconciled += 1;
            }
        }
        Ok(RestartReconciliation {
            inspected,
            queries,
            reconciled,
            blocked_unknown,
        })
    }

    /// Close every active attempt channel and report whether the queue is
    /// actually clean.  A closed channel does not by itself terminally settle
    /// a durable queue entry.
    pub fn drain(&mut self) -> Result<DrainOutcome, ReactiveContextDeliveryError> {
        let entries = self.load_active_entries(self.limits.max_drain_operations + 1)?;
        if entries.is_empty() {
            return Ok(DrainOutcome {
                clean: true,
                closed_attempts: 0,
                unknown_attempts: Vec::new(),
                open_operations: Vec::new(),
            });
        }
        let mut by_attempt: BTreeMap<String, Vec<IdempotencyIdentity>> = BTreeMap::new();
        for entry in &entries {
            by_attempt
                .entry(entry.payload.attempt_id.as_str().to_owned())
                .or_default()
                .push(entry.operation.clone());
        }
        let mut closed_attempts = 0;
        let mut unknown_attempts = Vec::new();
        for (attempt_id, operations) in by_attempt {
            match self
                .transport
                .close_attempt_channel(ReactiveContextCloseChannelRequest {
                    attempt_id: attempt_id.clone(),
                    operations,
                })? {
                ReactiveContextChannelCloseOutcome::Closed => closed_attempts += 1,
                ReactiveContextChannelCloseOutcome::Unknown { .. } => {
                    unknown_attempts.push(attempt_id)
                }
            }
        }
        Ok(DrainOutcome {
            clean: false,
            closed_attempts,
            unknown_attempts,
            open_operations: entries.into_iter().map(|entry| entry.operation).collect(),
        })
    }

    fn validate_admission(
        &self,
        admission: &HostDeliveryAdmission,
        request: &ReactiveContextDeliveryRequest,
    ) -> Result<(), ReactiveContextDeliveryError> {
        if admission.state != HostDeliveryState::Active {
            return Err(ReactiveContextDeliveryError::HostAdmission {
                state: admission.state,
            });
        }
        if admission.admission_ref.as_str().trim().is_empty()
            || admission.endpoint_ref.as_str().trim().is_empty()
        {
            return Err(ReactiveContextDeliveryError::invalid(
                "admission",
                "admission and endpoint references must be non-blank",
            ));
        }
        request
            .payload
            .validate()
            .map_err(|error| ReactiveContextDeliveryError::invalid("payload", error.to_string()))?;
        if request.payload.recipient != admission.recipient {
            return Err(ReactiveContextDeliveryError::invalid(
                "recipient",
                "payload recipient differs from current Host admission",
            ));
        }
        if admission.fence.host.epoch.current
            != request.payload.work_scope.state_fence.authority_epoch
        {
            return Err(ReactiveContextDeliveryError::invalid(
                "state_fence",
                "payload authority epoch is not the current Host epoch",
            ));
        }
        if !matches!(request.payload.validity, ReactiveContextValidity::Current) {
            return Err(ReactiveContextDeliveryError::invalid(
                "payload.validity",
                "cancelled, retracted, or superseded Context cannot be admitted",
            ));
        }
        let now = self.clock.now_unix_ms();
        if now == 0 || now >= request.payload.acknowledgement_deadline_unix_ms {
            return Err(ReactiveContextDeliveryError::DeadlineExceeded);
        }
        if request
            .payload
            .expires_at_unix_ms
            .is_some_and(|expiry| now >= expiry)
        {
            return Err(ReactiveContextDeliveryError::DeadlineExceeded);
        }
        if let Some(owner_receipt) = &request.owner_receipt {
            owner_receipt.validate().map_err(|error| {
                ReactiveContextDeliveryError::invalid("owner_receipt", error.to_string())
            })?;
        }
        Ok(())
    }

    fn enforce_new_capacity(&self, control: bool) -> Result<(), ReactiveContextDeliveryError> {
        let ceiling = self.limits.max_in_flight
            + if control {
                self.limits.reserved_control_capacity
            } else {
                0
            };
        let entries = self.load_active_entries(ceiling + 1)?;
        if entries.len() >= ceiling {
            return Err(ReactiveContextDeliveryError::Capacity {
                dimension: "in_flight",
            });
        }
        let pending_ack = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.stage,
                    ReactiveContextStage::DeliveredToExactEndpoint
                        | ReactiveContextStage::RecipientReceived
                        | ReactiveContextStage::RecipientDurable
                        | ReactiveContextStage::NormalizedProjection
                )
            })
            .count();
        if pending_ack >= self.limits.max_pending_ack {
            return Err(ReactiveContextDeliveryError::Capacity {
                dimension: "pending_ack",
            });
        }
        Ok(())
    }

    fn drive_enqueued(
        &mut self,
        entry: ReactiveContextQueueEntry,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let resolution = self
            .transport
            .resolve_endpoint(ReactiveContextResolveRequest {
                operation: entry.operation.clone(),
                payload: entry.payload.clone(),
                endpoint_ref: entry.endpoint_ref.clone(),
            })?;
        let endpoint = match resolution {
            ReactiveContextEndpointResolution::Exact(endpoint) => {
                if endpoint.endpoint_ref != entry.endpoint_ref
                    || endpoint.recipient != entry.payload.recipient
                    || endpoint.transport_operation.as_str().trim().is_empty()
                {
                    return Err(ReactiveContextDeliveryError::invalid(
                        "endpoint",
                        "resolved endpoint is not bound to the admitted recipient and route",
                    ));
                }
                endpoint
            }
            ReactiveContextEndpointResolution::NotAttempted { reason } => {
                let updated = self.transition(
                    &entry,
                    ReactiveContextStage::RejectedNotAttempted,
                    ReactiveContextTransitionEvidence {
                        reason: Some(bounded_reason(&reason)?),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "resolve-rejected",
                )?;
                return Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::NotAttempted,
                });
            }
            ReactiveContextEndpointResolution::Unknown { reason, .. } => {
                return Err(ReactiveContextDeliveryError::Unknown {
                    operation: operation_text(&entry.operation),
                    reason: bounded_reason(&reason)?,
                });
            }
        };
        let attempted = self.transition(
            &entry,
            ReactiveContextStage::DeliveryAttempted,
            ReactiveContextTransitionEvidence {
                transport_ref: Some(endpoint.transport_operation.clone()),
                ..ReactiveContextTransitionEvidence::default()
            },
            "send-intent",
        )?;
        let outcome = self.transport.send_event(ReactiveContextSendRequest {
            operation: attempted.operation.clone(),
            payload: attempted.payload.clone(),
            envelope: attempted.envelope.clone(),
            endpoint: endpoint.clone(),
        })?;
        match outcome {
            ReactiveContextSendOutcome::Delivered(receipt) => {
                let receipt = self.validate_transport_receipt(&attempted, &endpoint, receipt)?;
                let updated = self.transition(
                    &attempted,
                    ReactiveContextStage::DeliveredToExactEndpoint,
                    ReactiveContextTransitionEvidence {
                        owner_receipt: Some(receipt.owner_receipt),
                        transport_ref: Some(receipt.operation),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "delivered",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::Delivered,
                })
            }
            ReactiveContextSendOutcome::NotAttempted { reason }
            | ReactiveContextSendOutcome::Rejected { reason } => {
                let updated = self.transition(
                    &attempted,
                    ReactiveContextStage::UnavailableFenced,
                    ReactiveContextTransitionEvidence {
                        transport_ref: Some(endpoint.transport_operation),
                        reason: Some(bounded_reason(&reason)?),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "send-rejected",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::NotAttempted,
                })
            }
            ReactiveContextSendOutcome::Unknown {
                reconciliation,
                reason,
            } => {
                let updated = self.transition(
                    &attempted,
                    ReactiveContextStage::UnknownDelivery,
                    ReactiveContextTransitionEvidence {
                        transport_ref: Some(endpoint.transport_operation),
                        reconciliation_ref: Some(reconciliation),
                        reason: Some(bounded_reason(&reason)?),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "send-unknown",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::DeliveryUnknown,
                })
            }
        }
    }

    fn reconcile_entry(
        &mut self,
        entry: ReactiveContextQueueEntry,
    ) -> Result<ReactiveContextDeliveryReceipt, ReactiveContextDeliveryError> {
        let transport_operation = entry.transport_ref.clone().ok_or_else(|| {
            ReactiveContextDeliveryError::invalid(
                "transport_ref",
                "delivery attempt has no stable transport operation",
            )
        })?;
        let outcome = self.transport.query_delivery(ReactiveContextQueryRequest {
            operation: entry.operation.clone(),
            transport_operation: transport_operation.clone(),
            endpoint_ref: entry.endpoint_ref.clone(),
            recipient: entry.payload.recipient.clone(),
        })?;
        match outcome {
            ReactiveContextQueryOutcome::Delivered(receipt) => {
                let receipt = self.validate_transport_receipt(
                    &entry,
                    &ReactiveContextResolvedEndpoint {
                        endpoint_ref: entry.endpoint_ref.clone(),
                        recipient: entry.payload.recipient.clone(),
                        transport_operation: transport_operation.clone(),
                    },
                    receipt,
                )?;
                let updated = self.transition(
                    &entry,
                    ReactiveContextStage::DeliveredToExactEndpoint,
                    ReactiveContextTransitionEvidence {
                        owner_receipt: Some(receipt.owner_receipt),
                        transport_ref: Some(receipt.operation),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "reconciled-delivered",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::Delivered,
                })
            }
            ReactiveContextQueryOutcome::NotAttempted { reason }
            | ReactiveContextQueryOutcome::Rejected { reason } => {
                let updated = self.transition(
                    &entry,
                    ReactiveContextStage::UnavailableFenced,
                    ReactiveContextTransitionEvidence {
                        transport_ref: Some(transport_operation),
                        reason: Some(bounded_reason(&reason)?),
                        ..ReactiveContextTransitionEvidence::default()
                    },
                    "reconciled-rejected",
                )?;
                Ok(ReactiveContextDeliveryReceipt {
                    entry: updated,
                    disposition: DeliveryDisposition::NotAttempted,
                })
            }
            ReactiveContextQueryOutcome::Unknown {
                reconciliation,
                reason,
            } => {
                if entry.stage == ReactiveContextStage::DeliveryAttempted {
                    let updated = self.transition(
                        &entry,
                        ReactiveContextStage::UnknownDelivery,
                        ReactiveContextTransitionEvidence {
                            transport_ref: Some(transport_operation),
                            reconciliation_ref: Some(reconciliation),
                            reason: Some(bounded_reason(&reason)?),
                            ..ReactiveContextTransitionEvidence::default()
                        },
                        "reconciled-unknown",
                    )?;
                    return Ok(ReactiveContextDeliveryReceipt {
                        entry: updated,
                        disposition: DeliveryDisposition::DeliveryUnknown,
                    });
                }
                Ok(ReactiveContextDeliveryReceipt {
                    entry,
                    disposition: DeliveryDisposition::DeliveryUnknown,
                })
            }
        }
    }

    fn validate_transport_receipt(
        &self,
        entry: &ReactiveContextQueueEntry,
        endpoint: &ReactiveContextResolvedEndpoint,
        receipt: ReactiveContextTransportReceipt,
    ) -> Result<ReactiveContextTransportReceipt, ReactiveContextDeliveryError> {
        if receipt.operation != endpoint.transport_operation
            || receipt.endpoint_ref != endpoint.endpoint_ref
        {
            return Err(ReactiveContextDeliveryError::invalid(
                "transport_receipt",
                "receipt identity differs from the exact transport operation",
            ));
        }
        receipt.owner_receipt.validate().map_err(|error| {
            ReactiveContextDeliveryError::invalid("transport_receipt", error.to_string())
        })?;
        if entry.payload.recipient != endpoint.recipient {
            return Err(ReactiveContextDeliveryError::invalid(
                "transport_receipt.recipient",
                "receipt endpoint is not bound to the queued recipient",
            ));
        }
        Ok(receipt)
    }

    fn transition(
        &self,
        entry: &ReactiveContextQueueEntry,
        next_stage: ReactiveContextStage,
        evidence: ReactiveContextTransitionEvidence,
        label: &str,
    ) -> Result<ReactiveContextQueueEntry, ReactiveContextDeliveryError> {
        let revision = self.queue_revision(&entry.payload)?;
        let mutation = mutation_identity(&entry.operation, label)?;
        Ok(self
            .queue
            .compare_and_transition(ReactiveContextTransition {
                fence: entry.fence.clone(),
                mutation,
                target: entry.operation.clone(),
                expected_queue_revision: revision,
                expected_stage: entry.stage,
                next_stage,
                evidence,
            })?
            .entry)
    }

    fn queue_revision(
        &self,
        payload: &ReactiveContextPayload,
    ) -> Result<u64, ReactiveContextDeliveryError> {
        Ok(self
            .queue
            .load_attempt_queue(ReactiveContextQueueQuery {
                attempt_id: Some(payload.attempt_id.as_str().to_owned()),
                stream_id: Some(payload.sequence.stream_id.clone()),
                include_terminal: true,
                limit: 1,
                cursor: None,
            })?
            .revision)
    }

    fn find_operation(
        &self,
        operation: &IdempotencyIdentity,
    ) -> Result<Option<ReactiveContextQueueEntry>, ReactiveContextDeliveryError> {
        match self.queue.query_operation(ReactiveContextOperationQuery {
            operation: operation.clone(),
        }) {
            Ok(entry) => Ok(Some(entry)),
            Err(ReactiveContextQueueError::NotFound) => Ok(None),
            Err(error) => Err(ReactiveContextDeliveryError::Queue(error)),
        }
    }

    fn load_active_entries(
        &self,
        max_items: usize,
    ) -> Result<Vec<ReactiveContextQueueEntry>, ReactiveContextDeliveryError> {
        let mut items = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            pages += 1;
            if pages > MAX_DELIVERY_QUEUE_PAGES {
                return Err(ReactiveContextDeliveryError::Capacity {
                    dimension: "queue_pages",
                });
            }
            let snapshot = self.queue.load_attempt_queue(ReactiveContextQueueQuery {
                attempt_id: None,
                stream_id: None,
                include_terminal: false,
                limit: 0,
                cursor,
            })?;
            items.extend(snapshot.items);
            if items.len() > max_items {
                return Err(ReactiveContextDeliveryError::Capacity {
                    dimension: "active_operations",
                });
            }
            if !snapshot.partial {
                break;
            }
            cursor = snapshot.next_cursor;
            if cursor.is_none() {
                return Err(ReactiveContextDeliveryError::invalid(
                    "queue_snapshot",
                    "partial queue snapshot did not provide a continuation cursor",
                ));
            }
        }
        Ok(items)
    }

    fn unknown_error(
        &self,
        entry: &ReactiveContextQueueEntry,
        reason: &str,
    ) -> ReactiveContextDeliveryError {
        ReactiveContextDeliveryError::Unknown {
            operation: operation_text(&entry.operation),
            reason: reason.to_owned(),
        }
    }
}

fn operation_identity(
    payload: &ReactiveContextPayload,
) -> Result<IdempotencyIdentity, ReactiveContextDeliveryError> {
    Ok(IdempotencyIdentity {
        operation_id: make_handle(payload.operation_id.as_str())?,
        idempotency_key: make_handle(&payload.idempotency_key)?,
    })
}

fn operation_text(operation: &IdempotencyIdentity) -> String {
    format!("{}:{}", operation.operation_id, operation.idempotency_key)
}

fn mutation_identity(
    operation: &IdempotencyIdentity,
    label: &str,
) -> Result<IdempotencyIdentity, ReactiveContextDeliveryError> {
    let digest = sha256_hex(
        format!(
            "{}|{}|{label}",
            operation.operation_id, operation.idempotency_key
        )
        .as_bytes(),
    );
    Ok(IdempotencyIdentity {
        operation_id: make_handle(format!("reactive-delivery-{digest}"))?,
        idempotency_key: make_handle(format!("reactive-delivery-key-{digest}"))?,
    })
}

fn make_handle(value: impl Into<String>) -> Result<PlatformHandle, ReactiveContextDeliveryError> {
    PlatformHandle::new(value.into()).map_err(|error| {
        ReactiveContextDeliveryError::invalid("platform_handle", error.to_string())
    })
}

fn bounded_reason(value: &str) -> Result<String, ReactiveContextDeliveryError> {
    if value.trim().is_empty()
        || value.len() > MAX_DELIVERY_REASON_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ReactiveContextDeliveryError::invalid(
            "reason",
            "reason is empty, oversized, or contains control text",
        ));
    }
    Ok(value.to_owned())
}

fn stage_for_ack(phase: eliot_protocol::AckPhase) -> ReactiveContextStage {
    match phase {
        eliot_protocol::AckPhase::Received => ReactiveContextStage::RecipientReceived,
        eliot_protocol::AckPhase::Durable => ReactiveContextStage::RecipientDurable,
        eliot_protocol::AckPhase::Normalized => ReactiveContextStage::NormalizedProjection,
        eliot_protocol::AckPhase::Applied => ReactiveContextStage::AppliedProjection,
        eliot_protocol::AckPhase::Rejected => ReactiveContextStage::AcknowledgementRejected,
        eliot_protocol::AckPhase::Unknown => ReactiveContextStage::AcknowledgementUnknown,
    }
}
