//! Composition root for the governed notification process.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_notify_core::{
    A08AdmissionPort, AdmissionRequest, AdmissionResult, DeliveryObservation,
    DeliveryReceiptEvidence, DeliveryReceiptPort, G08NotificationPort, LedgerCommitOutcome,
    LedgerIntent, LedgerReservation, LedgerReserveOutcome, NotificationEnvelope, NotifyCore,
    OneShotLedgerPort, SignedWatchdogFallbackEnvelope, VerificationPorts, WatchdogSignaturePort,
};
use eliot_platform::{
    NotificationRequest, PortError, PortOutcome, ProviderError, ProviderErrorCode, UnknownReason,
};
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub const SERVICE_NAME: &str = "eliot-notify";
pub const PROTOCOL_VERSION: &str = "eliot.notify.v1";

#[derive(Debug)]
pub enum NotifyBuildError {
    Platform(PortError),
    Kernel(String),
}

impl fmt::Display for NotifyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
            Self::Kernel(error) => write!(f, "Kernel verification composition failed: {error}"),
        }
    }
}

impl std::error::Error for NotifyBuildError {}

/// The complete A-10 composition. Verification and replay authority are
/// supplied by the owning control plane; this process owns only the P-01
/// adapter binding and the A-10 coordinator.
pub struct NotificationComposition {
    core: NotifyCore<WindowsPlatform>,
}

impl NotificationComposition {
    /// Binds notification delivery to one validated WorkScope root.
    pub fn new(
        work_root: impl Into<PathBuf>,
        ports: VerificationPorts,
    ) -> Result<Self, NotifyBuildError> {
        let platform = WindowsPlatform::new(work_root).map_err(NotifyBuildError::Platform)?;
        Ok(Self::from_platform(platform, ports))
    }

    /// Composes the production one-shot process from the protected Kernel
    /// application front door. Every verification and replay port is backed
    /// by an authenticated typed operation; absence of the protected client
    /// declaration fails before a notification request is read.
    pub fn from_kernel(work_root: impl Into<PathBuf>) -> Result<Self, NotifyBuildError> {
        let ports = load_kernel_verification_ports()?;
        Self::new(work_root, ports)
    }

    /// Composes A-10 with an already-created platform adapter.
    #[must_use]
    pub fn from_platform(platform: WindowsPlatform, ports: VerificationPorts) -> Self {
        Self {
            core: NotifyCore::new(platform, ports),
        }
    }

    /// Delivers a normal G-08 notification through the governed core.
    pub fn deliver(
        &mut self,
        envelope: &NotificationEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, eliot_notify_core::NotifyError> {
        self.core.deliver(envelope, request)
    }

    /// Delivers the restricted signed Watchdog recovery notification.
    pub fn deliver_watchdog_fallback(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, eliot_notify_core::NotifyError> {
        self.core.deliver_watchdog_fallback(envelope, request)
    }
}

/// Resolves the process WorkScope root from the protected ProgramData contour.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = eliot_platform_windows::protected_program_data_path("Eliot/notify")
        .map_err(std::io::Error::other)?;
    eliot_platform_windows::prepare_protected_directory(&root).map_err(std::io::Error::other)?;
    std::fs::canonicalize(root)
}

const G08_VERIFY_OPERATION: &str = "eliot.notify.g08.verify";
const A08_ADMIT_OPERATION: &str = "eliot.notify.a08.admit";
const WATCHDOG_VERIFY_OPERATION: &str = "eliot.notify.watchdog.verify";
const DELIVERY_VERIFY_OPERATION: &str = "eliot.notify.delivery.verify";
const LEDGER_RESERVE_OPERATION: &str = "eliot.notify.ledger.reserve";
const LEDGER_COMMIT_OPERATION: &str = "eliot.notify.ledger.commit";

/// The exact operation selectors owned by the notification provider bundle.
///
/// Kernel/N4 registers handlers for these selectors. The notification process
/// does not interpret their authority or create a local substitute; it only
/// validates the typed response before handing it to `eliot-notify-core`.
pub const KERNEL_VERIFICATION_OPERATIONS: &[&str] = &[
    G08_VERIFY_OPERATION,
    A08_ADMIT_OPERATION,
    WATCHDOG_VERIFY_OPERATION,
    DELIVERY_VERIFY_OPERATION,
    LEDGER_RESERVE_OPERATION,
    LEDGER_COMMIT_OPERATION,
];

trait NotifyKernelExchange: Send {
    fn transact_for(
        &mut self,
        request: &NotificationRequest,
        operation: &str,
        payload: Value,
    ) -> Result<Value, KernelClientError>;
}

impl NotifyKernelExchange for KernelClient {
    fn transact_for(
        &mut self,
        request: &NotificationRequest,
        operation: &str,
        payload: Value,
    ) -> Result<Value, KernelClientError> {
        self.set_request_identity(request_identity(request)?);
        self.transact_json(operation, payload)
    }
}

fn request_identity(request: &NotificationRequest) -> Result<RequestIdentity, KernelClientError> {
    request
        .validate()
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
    let deadline_unix_ms = request
        .context
        .clock
        .known_time_ms
        .or(request.context.clock.valid_time_ms)
        .filter(|value| *value > 0)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            KernelClientError::Configuration(
                "notification request lacks a positive host deadline observation".to_owned(),
            )
        })?;
    let metadata = request.context.clone();
    let identity = RequestIdentity {
        request: RequestBinding {
            state_fence: metadata.state_fence.clone(),
            metadata,
        },
        idempotency_key: request.canonical_request_hash.as_str().to_owned(),
        deadline_unix_ms,
        cancellation_id: format!("eliot-notify:{}", request.context.request_id.as_str()),
    };
    identity
        .validate()
        .map_err(|error| KernelClientError::Configuration(error.to_string()))?;
    Ok(identity)
}

#[derive(Clone)]
struct KernelPort<E> {
    exchange: Arc<Mutex<E>>,
}

impl<E> KernelPort<E>
where
    E: NotifyKernelExchange,
{
    fn execute_for<T: DeserializeOwned>(
        &self,
        request: &NotificationRequest,
        operation: &str,
        payload: Value,
    ) -> PortOutcome<T> {
        let result = match self.exchange.lock() {
            Ok(mut exchange) => exchange.transact_for(request, operation, payload),
            Err(_) => {
                return PortOutcome::Error(PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                }));
            }
        };
        decode_kernel_outcome(result)
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum KernelPortOutcome<T> {
    Known {
        value: T,
    },
    Partial {
        value: T,
        missing: Vec<eliot_platform::PlatformHandle>,
    },
    Unknown {
        reason: UnknownReason,
    },
    Error {
        code: ProviderErrorCode,
        retryable: bool,
    },
}

fn decode_kernel_outcome<T: DeserializeOwned>(
    result: Result<Value, KernelClientError>,
) -> PortOutcome<T> {
    let value = match result {
        Ok(value) => value,
        Err(KernelClientError::UnknownOutcome(_)) => {
            return PortOutcome::Unknown(UnknownReason::Indeterminate);
        }
        Err(KernelClientError::FrontDoorClosed(_)) => {
            return PortOutcome::Error(PortError::Provider(ProviderError {
                code: ProviderErrorCode::Unavailable,
                retryable: true,
            }));
        }
        Err(KernelClientError::Rejected(_)) => {
            return PortOutcome::Error(PortError::Provider(ProviderError {
                code: ProviderErrorCode::PermissionDenied,
                retryable: false,
            }));
        }
        Err(KernelClientError::Configuration(_) | KernelClientError::MissingRequestIdentity) => {
            return PortOutcome::Error(PortError::Provider(ProviderError {
                code: ProviderErrorCode::InvalidRequest,
                retryable: false,
            }));
        }
    };
    match serde_json::from_value::<KernelPortOutcome<T>>(value) {
        Ok(KernelPortOutcome::Known { value }) => PortOutcome::Known(value),
        Ok(KernelPortOutcome::Partial { value, missing }) => {
            PortOutcome::Partial { value, missing }
        }
        Ok(KernelPortOutcome::Unknown { reason }) => PortOutcome::Unknown(reason),
        Ok(KernelPortOutcome::Error { code, retryable }) => {
            PortOutcome::Error(PortError::Provider(ProviderError { code, retryable }))
        }
        Err(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
    }
}

struct KernelG08<E> {
    port: KernelPort<E>,
}

impl<E> G08NotificationPort for KernelG08<E>
where
    E: NotifyKernelExchange,
{
    fn verify_source(
        &mut self,
        envelope: &NotificationEnvelope,
        request: &NotificationRequest,
    ) -> PortOutcome<eliot_receipts::ReceiptEnvelope> {
        self.port.execute_for(
            request,
            G08_VERIFY_OPERATION,
            json!({"envelope": envelope, "request": request}),
        )
    }
}

struct KernelA08<E> {
    port: KernelPort<E>,
}

impl<E> A08AdmissionPort for KernelA08<E>
where
    E: NotifyKernelExchange,
{
    fn admit(&mut self, request: &AdmissionRequest<'_>) -> PortOutcome<AdmissionResult> {
        self.port.execute_for(
            request.platform_request,
            A08_ADMIT_OPERATION,
            json!({
                "platform_request": request.platform_request,
                "source_receipt": request.source_receipt,
                "notification_id": request.notification_id,
                "body_digest": request.body_digest,
                "requested_route": request.requested_route,
                "requested_effect": request.requested_effect,
                "normal_candidates": request.normal_candidates,
            }),
        )
    }
}

struct KernelWatchdog<E> {
    port: KernelPort<E>,
}

impl<E> WatchdogSignaturePort for KernelWatchdog<E>
where
    E: NotifyKernelExchange,
{
    fn verify_signature(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> PortOutcome<eliot_receipts::ReceiptEnvelope> {
        self.port.execute_for(
            request,
            WATCHDOG_VERIFY_OPERATION,
            json!({"envelope": envelope, "request": request}),
        )
    }
}

struct KernelDeliveryReceipt<E> {
    port: KernelPort<E>,
}

impl<E> DeliveryReceiptPort for KernelDeliveryReceipt<E>
where
    E: NotifyKernelExchange,
{
    fn verify_delivery(
        &mut self,
        evidence: &DeliveryReceiptEvidence<'_>,
    ) -> PortOutcome<eliot_receipts::ReceiptEnvelope> {
        self.port.execute_for(
            evidence.platform_request,
            DELIVERY_VERIFY_OPERATION,
            json!({
                "platform_request": evidence.platform_request,
                "source_receipt": evidence.source_receipt,
                "admission": evidence.admission,
                "one_shot_key": evidence.one_shot_key,
                "claim_digest": evidence.claim_digest,
                "provider_evidence": evidence.provider_evidence,
            }),
        )
    }
}

struct KernelLedger<E> {
    port: KernelPort<E>,
}

impl<E> OneShotLedgerPort for KernelLedger<E>
where
    E: NotifyKernelExchange,
{
    fn reserve(
        &mut self,
        intent: &LedgerIntent,
        request: &NotificationRequest,
    ) -> LedgerReserveOutcome {
        match decode_kernel_outcome(match self.port.exchange.lock() {
            Ok(mut exchange) => exchange.transact_for(
                request,
                LEDGER_RESERVE_OPERATION,
                json!({"intent": intent, "request": request}),
            ),
            Err(_) => Err(KernelClientError::Rejected(
                "Kernel verification exchange mutex is poisoned".to_owned(),
            )),
        }) {
            PortOutcome::Known(value) => value,
            PortOutcome::Partial { .. } | PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
                LedgerReserveOutcome::Unavailable
            }
        }
    }

    fn commit(
        &mut self,
        reservation: &LedgerReservation,
        observation: &DeliveryObservation,
        request: &NotificationRequest,
    ) -> LedgerCommitOutcome {
        match decode_kernel_outcome(match self.port.exchange.lock() {
            Ok(mut exchange) => exchange.transact_for(
                request,
                LEDGER_COMMIT_OPERATION,
                json!({
                    "reservation": reservation,
                    "observation": observation,
                    "request": request,
                }),
            ),
            Err(_) => Err(KernelClientError::Rejected(
                "Kernel verification exchange mutex is poisoned".to_owned(),
            )),
        }) {
            PortOutcome::Known(value) => value,
            PortOutcome::Partial { .. } | PortOutcome::Unknown(_) | PortOutcome::Error(_) => {
                LedgerCommitOutcome::Unavailable
            }
        }
    }
}

fn verification_ports_from_exchange<E>(exchange: E) -> VerificationPorts
where
    E: NotifyKernelExchange + 'static,
{
    let exchange = Arc::new(Mutex::new(exchange));
    VerificationPorts {
        a08: Some(Box::new(KernelA08 {
            port: KernelPort {
                exchange: exchange.clone(),
            },
        })),
        g08: Some(Box::new(KernelG08 {
            port: KernelPort {
                exchange: exchange.clone(),
            },
        })),
        watchdog: Some(Box::new(KernelWatchdog {
            port: KernelPort {
                exchange: exchange.clone(),
            },
        })),
        delivery_receipt: Some(Box::new(KernelDeliveryReceipt {
            port: KernelPort {
                exchange: exchange.clone(),
            },
        })),
        ledger: Some(Box::new(KernelLedger {
            port: KernelPort { exchange },
        })),
    }
}

/// Loads the protected Kernel client and binds every notification provider
/// port to the same authenticated exchange session.
pub fn load_kernel_verification_ports() -> Result<VerificationPorts, NotifyBuildError> {
    let client =
        KernelClient::load().map_err(|error| NotifyBuildError::Kernel(error.to_string()))?;
    Ok(verification_ports_from_exchange(client))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
        SourceId, StateFence,
    };
    use eliot_notify_core::{LedgerIntent, LedgerReserveOutcome, OneShotKey};
    use eliot_platform::{NotificationRequest, PlatformHandle};

    use super::*;

    #[derive(Clone)]
    struct RecordingExchange {
        calls: Arc<Mutex<Vec<(String, RequestId, Value)>>>,
        response: Value,
    }

    impl NotifyKernelExchange for RecordingExchange {
        fn transact_for(
            &mut self,
            request: &NotificationRequest,
            operation: &str,
            payload: Value,
        ) -> Result<Value, KernelClientError> {
            self.calls.lock().unwrap().push((
                operation.to_owned(),
                request.context.request_id.clone(),
                payload,
            ));
            Ok(self.response.clone())
        }
    }

    fn request(id: &str) -> NotificationRequest {
        let request_id = RequestId::new(id).unwrap();
        let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        NotificationRequest {
            context: RequestMetadata {
                request_id,
                session_id: None,
                task_id: None,
                product_id: ProductId::new("notify-test-product").unwrap(),
                source_id: SourceId::new("notify-test-source").unwrap(),
                state_fence: fence,
                clock: ClockReading {
                    known_time_ms: Some(10_000),
                    ..ClockReading::default()
                },
            },
            canonical_request_hash: PlatformHandle::new("a").unwrap(),
            notification: PlatformHandle::new("notification-1").unwrap(),
            audience: PlatformHandle::new("audience-1").unwrap(),
            body_digest: PlatformHandle::new("b").unwrap(),
        }
    }

    fn intent() -> LedgerIntent {
        LedgerIntent {
            one_shot_key: serde_json::from_value::<OneShotKey>(serde_json::json!("one-shot-1"))
                .unwrap(),
            claim_digest: "claim-1".to_owned(),
            request_id: PlatformHandle::new("request-a").unwrap(),
        }
    }

    #[test]
    fn production_bundle_binds_all_verification_ports() {
        let exchange = RecordingExchange {
            calls: Arc::new(Mutex::new(Vec::new())),
            response: serde_json::json!({
                "kind": "UNKNOWN",
                "reason": "INDETERMINATE"
            }),
        };
        let ports = verification_ports_from_exchange(exchange);
        assert!(ports.a08.is_some());
        assert!(ports.g08.is_some());
        assert!(ports.watchdog.is_some());
        assert!(ports.delivery_receipt.is_some());
        assert!(ports.ledger.is_some());
    }

    #[test]
    fn ledger_exchange_binds_each_call_to_the_supplied_request() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let exchange = RecordingExchange {
            calls: Arc::clone(&calls),
            response: serde_json::json!({
                "kind": "UNKNOWN",
                "reason": "INDETERMINATE"
            }),
        };
        let shared = Arc::new(Mutex::new(exchange));
        let mut ledger = KernelLedger {
            port: KernelPort { exchange: shared },
        };
        let first = request("request-a");
        let second = request("request-b");
        assert!(matches!(
            ledger.reserve(&intent(), &first),
            LedgerReserveOutcome::Unavailable
        ));
        assert!(matches!(
            ledger.reserve(&intent(), &second),
            LedgerReserveOutcome::Unavailable
        ));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, LEDGER_RESERVE_OPERATION);
        assert_eq!(calls[0].1.as_str(), "request-a");
        assert_eq!(calls[1].1.as_str(), "request-b");
        assert_eq!(calls[0].2["request"]["context"]["request_id"], "request-a");
        assert_eq!(calls[1].2["request"]["context"]["request_id"], "request-b");
    }

    #[test]
    fn partial_ledger_response_is_unavailable_before_any_platform_effect() {
        let exchange = RecordingExchange {
            calls: Arc::new(Mutex::new(Vec::new())),
            response: serde_json::json!({
                "kind": "PARTIAL",
                "value": {"kind": "UNAVAILABLE"},
                "missing": ["ledger-receipt"]
            }),
        };
        let shared = Arc::new(Mutex::new(exchange));
        let mut ledger = KernelLedger {
            port: KernelPort { exchange: shared },
        };
        assert!(matches!(
            ledger.reserve(&intent(), &request("request-a")),
            LedgerReserveOutcome::Unavailable
        ));
    }
}
