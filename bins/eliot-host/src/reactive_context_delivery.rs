//! Host composition for the durable reactive Context delivery service.
//!
//! The Host owns the live Kernel contour and the authenticated named-pipe
//! transport.  The Host-state journal remains the only queue owner; this file
//! supplies a borrowed queue port and the concrete transport adapter used by
//! [`eliot_host_service::ReactiveContextDelivery`].

use std::path::PathBuf;

use eliot_contracts::sha256_hex;
use eliot_host_service::{
    HostDeliveryAdmission, HostDeliveryState, ReactiveContextCancelOutcome,
    ReactiveContextCancelRequest, ReactiveContextChannelCloseOutcome,
    ReactiveContextCloseChannelRequest, ReactiveContextDelivery, ReactiveContextDeliveryError,
    ReactiveContextDeliveryLimits, ReactiveContextDeliveryReceipt,
    ReactiveContextEndpointResolution, ReactiveContextQueryOutcome, ReactiveContextQueryRequest,
    ReactiveContextResolveRequest, ReactiveContextResolvedEndpoint, ReactiveContextSendOutcome,
    ReactiveContextSendRequest, ReactiveContextTransportError, ReactiveContextTransportPort,
};
use eliot_host_state::{
    ActivationState, IdempotencyIdentity, ProductionHostStateJournal,
    ReactiveContextEnqueueReceipt, ReactiveContextOperationQuery, ReactiveContextPrepareRequest,
    ReactiveContextPrepareResult, ReactiveContextPreparedEnqueue, ReactiveContextQueueError,
    ReactiveContextQueueQuery, ReactiveContextQueueSnapshot, ReactiveContextReconcileOutcome,
    ReactiveContextReconcileRequest, ReactiveContextTransition, ReactiveContextTransitionReceipt,
};
use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
use eliot_kernel_service::HostKernelCandidateBinding;
use eliot_platform::PlatformHandle;
use eliot_platform_windows::ProcessIdentity;
use eliot_protocol::{EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload};
use eliot_runtime_contracts::KernelActivationState;
use thiserror::Error;

use super::{HostComposition, HostError, record_fence};

/// Error returned by the Host-owned reactive Context composition edge.
#[derive(Debug, Error)]
pub enum HostReactiveContextDeliveryError {
    /// The retained Host or Kernel contour could not admit the operation.
    #[error("Host reactive Context contour: {0}")]
    Host(#[from] HostError),
    /// The durable service rejected or fenced the delivery operation.
    #[error("reactive Context delivery: {0}")]
    Delivery(#[from] ReactiveContextDeliveryError),
    /// The local synchronous bridge runtime could not be created.
    #[error("reactive Context transport runtime: {0}")]
    Runtime(String),
    /// The producer handoff did not contain a complete owner-produced request.
    #[error("reactive Context producer: {0}")]
    Producer(#[from] HostReactiveContextProducerError),
}

/// Validation failure at the typed producer-to-Host handoff.
#[derive(Debug, Error)]
pub enum HostReactiveContextProducerError {
    /// The source did not provide the complete closed protocol payload.
    #[error("owner-produced payload is invalid: {0}")]
    InvalidPayload(String),
    /// Host admission evidence must be carried by the authenticated source.
    #[error("authenticated Host admission reference is blank")]
    BlankAdmissionReference,
    /// An optional owner receipt was supplied but is not a valid immutable
    /// content reference.
    #[error("owner admission receipt is invalid: {0}")]
    InvalidOwnerReceipt(String),
}

/// Typed handoff from the owner that produced a complete reactive Context
/// payload into Host.
///
/// A4/A1 must supply the fully assembled [`ReactiveContextDeliveryRequest`]
/// and the owner-issued Host admission reference. An inert planning request,
/// bridge delivery receipt, or locally invented payload cannot be converted
/// into this type. This constructor validates the closed payload and any
/// supplied owner receipt; [`HostComposition`] performs the live Host epoch,
/// recipient, process, image, and retained Kernel-pipe authentication before
/// admitting it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostReactiveContextProducer {
    request: eliot_host_service::ReactiveContextDeliveryRequest,
    admission_ref: PlatformHandle,
}

impl HostReactiveContextProducer {
    /// Accept one complete request from the authenticated upstream producer.
    pub fn from_authenticated_source(
        request: eliot_host_service::ReactiveContextDeliveryRequest,
        admission_ref: PlatformHandle,
    ) -> Result<Self, HostReactiveContextProducerError> {
        request
            .payload
            .validate()
            .map_err(|error| HostReactiveContextProducerError::InvalidPayload(error.to_string()))?;
        if admission_ref.as_str().trim().is_empty() {
            return Err(HostReactiveContextProducerError::BlankAdmissionReference);
        }
        if let Some(receipt) = &request.owner_receipt {
            receipt.validate().map_err(|error| {
                HostReactiveContextProducerError::InvalidOwnerReceipt(error.to_string())
            })?;
        }
        Ok(Self {
            request,
            admission_ref,
        })
    }
}

/// Borrowed view over the existing production journal.
///
/// `ReactiveContextDelivery` owns its queue port, while `HostComposition`
/// must retain ownership of the one `ProductionHostStateJournal`.  Delegating
/// every operation here keeps the service attached to that journal without a
/// second queue, cache, or sidecar authority.
struct ProductionReactiveContextQueue<'a>(&'a ProductionHostStateJournal);

impl eliot_host_state::ReactiveContextQueuePort for ProductionReactiveContextQueue<'_> {
    fn prepare_or_replay(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
        self.0.prepare_reactive_context(request)
    }

    fn commit_enqueued(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
        self.0.commit_reactive_context(prepared)
    }

    fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
        self.0.compare_and_transition(transition)
    }

    fn load_attempt_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
        self.0.load_reactive_context_queue(query)
    }

    fn query_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<eliot_host_state::ReactiveContextQueueEntry, ReactiveContextQueueError> {
        self.0.query_reactive_context_operation(query)
    }

    fn reconcile_operation(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
        self.0.reconcile_reactive_context(request)
    }
}

#[derive(Clone)]
struct HostReactiveContextContour {
    fence: eliot_host_state::RecordFence,
    candidate: HostKernelCandidateBinding,
    process: ProcessIdentity,
    image: PathBuf,
    endpoint_ref: PlatformHandle,
}

/// Concrete Host/platform adapter for one authenticated Kernel front-door
/// delivery session.
///
/// The connection is opened lazily from `resolve_endpoint`, after the durable
/// queue commit and before send-intent. A named-pipe write is transport
/// evidence only; because the current Kernel front door has no reactive
/// application receipt/query wire, every write remains `Unknown` and keeps its
/// stable reconciliation identity.
struct AuthenticatedKernelReactiveTransport {
    runtime: tokio::runtime::Runtime,
    candidate: HostKernelCandidateBinding,
    process: ProcessIdentity,
    image: PathBuf,
    endpoint_ref: PlatformHandle,
    connection_id: String,
    transport: Option<NamedPipeTransport>,
}

impl AuthenticatedKernelReactiveTransport {
    fn new(contour: HostReactiveContextContour) -> Result<Self, HostReactiveContextDeliveryError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| HostReactiveContextDeliveryError::Runtime(error.to_string()))?;
        let connection_digest = sha256_hex(
            format!(
                "eliot-host-reactive-context-connection:v1:{}:{}:{}",
                contour.candidate.activation_id,
                contour.candidate.pipe_identity,
                contour.process.start_time_100ns,
            )
            .as_bytes(),
        );
        Ok(Self {
            runtime,
            candidate: contour.candidate,
            process: contour.process,
            image: contour.image,
            endpoint_ref: contour.endpoint_ref,
            connection_id: format!("host-reactive-context-{connection_digest}"),
            transport: None,
        })
    }

    fn ensure_connected(&mut self) -> Result<(), ReactiveContextTransportError> {
        if self.transport.is_some() {
            return Ok(());
        }
        let transport = self
            .runtime
            .block_on(super::connect_authenticated_kernel_front_door(
                &self.candidate,
                &self.process,
            ))
            .map_err(|_| ReactiveContextTransportError::Unavailable {
                reason: "authenticated Kernel front-door connection is unavailable".to_owned(),
            })?;
        super::validate_authenticated_kernel_peer(
            transport.peer_identity(),
            self.process.process_id,
            self.process.start_time_100ns,
            &self.image,
        )
        .map_err(|_| ReactiveContextTransportError::Unavailable {
            reason: "authenticated Kernel peer no longer matches the retained process".to_owned(),
        })?;
        self.transport = Some(transport);
        Ok(())
    }

    fn transport_operation(
        operation: &IdempotencyIdentity,
    ) -> Result<PlatformHandle, ReactiveContextTransportError> {
        let digest = sha256_hex(
            format!(
                "eliot-host-reactive-context-transport:v1:{}:{}",
                operation.operation_id, operation.idempotency_key,
            )
            .as_bytes(),
        );
        PlatformHandle::new(format!("host-reactive-transport-{digest}")).map_err(|_| {
            ReactiveContextTransportError::Invalid {
                reason: "reactive transport operation identity could not be formed".to_owned(),
            }
        })
    }

    fn reconciliation_operation(
        operation: &IdempotencyIdentity,
    ) -> Result<PlatformHandle, ReactiveContextTransportError> {
        let digest = sha256_hex(
            format!(
                "eliot-host-reactive-context-reconcile:v1:{}:{}",
                operation.operation_id, operation.idempotency_key,
            )
            .as_bytes(),
        );
        PlatformHandle::new(format!("host-reactive-reconcile-{digest}")).map_err(|_| {
            ReactiveContextTransportError::Invalid {
                reason: "reactive reconciliation identity could not be formed".to_owned(),
            }
        })
    }

    fn validate_endpoint(
        &self,
        endpoint: &ReactiveContextResolvedEndpoint,
        operation: &IdempotencyIdentity,
    ) -> Result<PlatformHandle, ReactiveContextTransportError> {
        let expected = Self::transport_operation(operation)?;
        if endpoint.endpoint_ref != self.endpoint_ref || endpoint.transport_operation != expected {
            return Err(ReactiveContextTransportError::Invalid {
                reason: "reactive transport endpoint or operation identity changed".to_owned(),
            });
        }
        Ok(expected)
    }

    fn event_frame(
        &self,
        request: &ReactiveContextSendRequest,
    ) -> Result<Frame, ReactiveContextTransportError> {
        let payload = serde_json::to_value(&request.envelope).map_err(|_| {
            ReactiveContextTransportError::Invalid {
                reason: "reactive event envelope could not be encoded".to_owned(),
            }
        })?;
        let frame = Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: self.connection_id.clone(),
            request_id: None,
            kind: FrameKind::Event,
            message_type: MessageType::Event,
            request_identity: None,
            payload: ProtocolPayload::Json(payload),
            trace_context: std::collections::BTreeMap::new(),
        };
        frame
            .validate()
            .map_err(|_| ReactiveContextTransportError::Invalid {
                reason: "reactive event frame failed protocol validation".to_owned(),
            })?;
        Ok(frame)
    }
}

impl ReactiveContextTransportPort for AuthenticatedKernelReactiveTransport {
    fn resolve_endpoint(
        &mut self,
        request: ReactiveContextResolveRequest,
    ) -> Result<ReactiveContextEndpointResolution, ReactiveContextTransportError> {
        if request.endpoint_ref != self.endpoint_ref {
            return Ok(ReactiveContextEndpointResolution::NotAttempted {
                reason: "admitted endpoint is not the retained authenticated Kernel pipe"
                    .to_owned(),
            });
        }
        let transport_operation = Self::transport_operation(&request.operation)?;
        if let Err(error) = self.ensure_connected() {
            return Ok(ReactiveContextEndpointResolution::NotAttempted {
                reason: error.to_string(),
            });
        }
        Ok(ReactiveContextEndpointResolution::Exact(
            ReactiveContextResolvedEndpoint {
                endpoint_ref: self.endpoint_ref.clone(),
                recipient: request.payload.recipient,
                transport_operation,
            },
        ))
    }

    fn send_event(
        &mut self,
        request: ReactiveContextSendRequest,
    ) -> Result<ReactiveContextSendOutcome, ReactiveContextTransportError> {
        let transport_operation = self.validate_endpoint(&request.endpoint, &request.operation)?;
        let frame = self.event_frame(&request)?;
        let Some(transport) = self.transport.as_mut() else {
            return Ok(ReactiveContextSendOutcome::NotAttempted {
                reason: "authenticated Kernel transport was not retained after resolution"
                    .to_owned(),
            });
        };
        let reconciliation = Self::reconciliation_operation(&request.operation)?;
        let outcome = self
            .runtime
            .block_on(transport.send_frame(&frame, TransportLimits::default()));
        match outcome {
            Ok(DeliveryOutcome::Delivered) => Ok(ReactiveContextSendOutcome::Unknown {
                reconciliation,
                reason: "authenticated Kernel pipe accepted event bytes; no application receipt was observed".to_owned(),
            }),
            Ok(DeliveryOutcome::UnknownOutcome) | Err(_) => {
                Ok(ReactiveContextSendOutcome::Unknown {
                    reconciliation,
                    reason: "authenticated Kernel reactive event outcome is unknown".to_owned(),
                })
            }
        }
        .map(|outcome| {
            let _ = transport_operation;
            outcome
        })
    }

    fn query_delivery(
        &mut self,
        request: ReactiveContextQueryRequest,
    ) -> Result<ReactiveContextQueryOutcome, ReactiveContextTransportError> {
        let expected = Self::transport_operation(&request.operation)?;
        if request.transport_operation != expected || request.endpoint_ref != self.endpoint_ref {
            return Err(ReactiveContextTransportError::Invalid {
                reason: "reactive reconciliation identity changed".to_owned(),
            });
        }
        let reconciliation = Self::reconciliation_operation(&request.operation)?;
        Ok(ReactiveContextQueryOutcome::Unknown {
            reconciliation,
            reason: "current Kernel front door has no same-operation reactive delivery query"
                .to_owned(),
        })
    }

    fn cancel_delivery(
        &mut self,
        request: ReactiveContextCancelRequest,
    ) -> Result<ReactiveContextCancelOutcome, ReactiveContextTransportError> {
        let expected = Self::transport_operation(&request.operation)?;
        if request.transport_operation != expected {
            return Err(ReactiveContextTransportError::Invalid {
                reason: "reactive cancellation identity changed".to_owned(),
            });
        }
        Ok(ReactiveContextCancelOutcome::Unknown {
            reconciliation: Self::reconciliation_operation(&request.operation)?,
            reason: "current Kernel front door has no reactive delivery cancellation wire"
                .to_owned(),
        })
    }

    fn close_attempt_channel(
        &mut self,
        _request: ReactiveContextCloseChannelRequest,
    ) -> Result<ReactiveContextChannelCloseOutcome, ReactiveContextTransportError> {
        self.transport.take();
        Ok(ReactiveContextChannelCloseOutcome::Unknown {
            reason: "local authenticated pipe handle was dropped; peer closure was not observed"
                .to_owned(),
        })
    }
}

impl HostComposition {
    /// Runs the real owner-produced Host call site: derive the recipient from
    /// the complete typed source, admit it against the current authenticated
    /// Host/Kernel contour, then deliver through the durable queue service.
    ///
    /// The endpoint is intentionally taken from the retained candidate rather
    /// than from caller text. A4/A1 remain responsible for supplying the
    /// complete payload and admission reference; this method does not build a
    /// payload from an inert plan or claim an application receipt.
    pub fn deliver_reactive_context_from_producer(
        &self,
        producer: HostReactiveContextProducer,
    ) -> Result<ReactiveContextDeliveryReceipt, HostReactiveContextDeliveryError> {
        let HostReactiveContextProducer {
            request,
            admission_ref,
        } = producer;
        let recipient = request.payload.recipient.clone();
        let contour = self.current_reactive_context_contour(false)?;
        let admission = self.admit_reactive_context(
            recipient,
            contour.candidate.pipe_identity.clone(),
            admission_ref,
        )?;
        self.deliver_reactive_context(admission, request)
    }

    /// Convenience entrypoint for a producer that has not yet wrapped its
    /// request in the typed Host handoff.
    pub fn deliver_reactive_context_from_authenticated_source(
        &self,
        request: eliot_host_service::ReactiveContextDeliveryRequest,
        admission_ref: PlatformHandle,
    ) -> Result<ReactiveContextDeliveryReceipt, HostReactiveContextDeliveryError> {
        let producer =
            HostReactiveContextProducer::from_authenticated_source(request, admission_ref)?;
        self.deliver_reactive_context_from_producer(producer)
    }

    /// Builds an admission from the current Host fence and the caller-owned
    /// recipient/session evidence. The endpoint and admission reference are
    /// supplied by that caller and must match the retained authenticated
    /// Kernel endpoint; no recipient or receipt is synthesized here.
    pub fn admit_reactive_context(
        &self,
        recipient: eliot_protocol::ReactiveContextRecipient,
        endpoint_ref: PlatformHandle,
        admission_ref: PlatformHandle,
    ) -> Result<HostDeliveryAdmission, HostError> {
        recipient
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        let contour = self.current_reactive_context_contour(false)?;
        if contour.endpoint_ref != endpoint_ref {
            return Err(HostError::ProcessContour(
                "reactive Context endpoint is not the retained authenticated Kernel pipe"
                    .to_owned(),
            ));
        }
        let state = self.journal.snapshot()?;
        Ok(HostDeliveryAdmission {
            fence: contour.fence,
            state: current_delivery_state(self, &state),
            recipient,
            endpoint_ref,
            admission_ref,
        })
    }

    /// Runs one Host-owned reactive Context delivery through the existing
    /// durable journal and authenticated Kernel front door.
    pub fn deliver_reactive_context(
        &self,
        admission: HostDeliveryAdmission,
        request: eliot_host_service::ReactiveContextDeliveryRequest,
    ) -> Result<ReactiveContextDeliveryReceipt, HostReactiveContextDeliveryError> {
        let contour = self.current_reactive_context_contour(true)?;
        if admission.fence != contour.fence || admission.endpoint_ref != contour.endpoint_ref {
            return Err(HostError::ProcessContour(
                "reactive Context admission is not bound to the current Host/Kernel contour"
                    .to_owned(),
            )
            .into());
        }
        if admission.state != HostDeliveryState::Active {
            return Err(HostError::ProcessContour(
                "reactive Context admission is not Active at the send boundary".to_owned(),
            )
            .into());
        }
        let transport = AuthenticatedKernelReactiveTransport::new(contour)?;
        let queue = ProductionReactiveContextQueue(&self.journal);
        let mut delivery = ReactiveContextDelivery::new(
            queue,
            transport,
            eliot_host_service::SystemReactiveContextClock,
            ReactiveContextDeliveryLimits::default(),
        )?;
        Ok(delivery.deliver(&admission, request)?)
    }

    fn current_reactive_context_contour(
        &self,
        require_active: bool,
    ) -> Result<HostReactiveContextContour, HostError> {
        if !self.running {
            return Err(HostError::Stopped);
        }
        let state = self.journal.snapshot()?;
        let fence = record_fence(&self.host, &self.activation_id, &self.activation_generation);
        let activation = state.activation.as_ref().ok_or_else(|| {
            HostError::ProcessContour("Host activation record is absent".to_owned())
        })?;
        if activation.fence != fence {
            return Err(HostError::ProcessContour(
                "Host activation fence is not the current retained fence".to_owned(),
            ));
        }
        if require_active && current_delivery_state(self, &state) != HostDeliveryState::Active {
            return Err(HostError::ProcessContour(
                "Host reactive Context contour is not Active".to_owned(),
            ));
        }
        let candidate = self.jobs.kernel_candidate.as_ref().ok_or_else(|| {
            HostError::ProcessContour("retained Kernel candidate binding is absent".to_owned())
        })?;
        candidate
            .validate()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        self.jobs.validate_running_kernel_candidate(candidate)?;
        let kernel = state.kernel.as_ref().ok_or_else(|| {
            HostError::ProcessContour("durable Kernel record is absent".to_owned())
        })?;
        if kernel.fence != fence
            || kernel.state != KernelActivationState::Active
            || kernel.active_pipe_identity.as_ref() != Some(&candidate.pipe_identity)
        {
            return Err(HostError::ProcessContour(
                "durable Kernel record is not the current Active authenticated contour".to_owned(),
            ));
        }
        let process =
            self.jobs.kernel_process().cloned().ok_or_else(|| {
                HostError::ProcessContour("live Kernel process is absent".to_owned())
            })?;
        let image = self.jobs.kernel_executable.clone().ok_or_else(|| {
            HostError::ProcessContour("approved Kernel image is absent".to_owned())
        })?;
        Ok(HostReactiveContextContour {
            fence,
            endpoint_ref: candidate.pipe_identity.clone(),
            candidate: candidate.clone(),
            process,
            image,
        })
    }
}

fn current_delivery_state(
    host: &HostComposition,
    state: &eliot_host_state::HostState,
) -> HostDeliveryState {
    if !host.running {
        return HostDeliveryState::Unavailable;
    }
    match state.activation.as_ref().map(|activation| activation.state) {
        Some(ActivationState::Active)
            if state.kernel.as_ref().is_some_and(|kernel| {
                kernel.state == KernelActivationState::Active
                    && kernel.active_pipe_identity.is_some()
            }) && host.jobs.kernel_process().is_some() =>
        {
            HostDeliveryState::Active
        }
        Some(ActivationState::Draining) => HostDeliveryState::Draining,
        Some(ActivationState::Stopped | ActivationState::StoppedClean) | None => {
            HostDeliveryState::Unavailable
        }
        Some(_) => HostDeliveryState::DegradedRecovery,
    }
}
