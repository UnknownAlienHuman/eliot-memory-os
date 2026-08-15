//! Composition root for the governed notification process.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SessionId, SourceId, StateFence,
};
use eliot_notify_core::{
    A08AdmissionPort, AdmissionRequest, AdmissionResult, DeliveryObservation,
    DeliveryProviderEvidence, DeliveryReceiptEvidence, DeliveryReceiptPort, G08NotificationPort,
    LedgerCommitOutcome, LedgerIntent, LedgerReservation, LedgerReserveOutcome,
    NotificationEnvelope, NotifyCore, OneShotLedgerPort, SignedWatchdogFallbackEnvelope,
    VerificationPorts, WATCHDOG_PRODUCT_ID, WATCHDOG_SIGNATURE_ALGORITHM,
    WATCHDOG_SIGNATURE_DOMAIN, WATCHDOG_SOURCE_ID, WatchdogSignaturePort, watchdog_notification_id,
    watchdog_request_hash, watchdog_request_id, watchdog_signature_payload,
};
use eliot_platform::{
    NotificationRequest, PlatformHandle, PortError, PortOutcome, ProviderError, ProviderErrorCode,
    UnknownReason, WorkScopePath,
};
use eliot_platform_windows::{
    ProtectedPathLease, PublicationOutcome, WindowsPlatform, protected_program_data_path,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    EffectClass, ProofCeiling, ReceiptEnvelope, RequestBinding, contract_identity,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SERVICE_NAME: &str = "eliot-notify";
pub const PROTOCOL_VERSION: &str = "eliot.notify.v1";

#[derive(Debug)]
pub enum NotifyBuildError {
    Platform(PortError),
    Kernel(String),
    Fallback(String),
}

impl fmt::Display for NotifyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
            Self::Kernel(error) => write!(f, "Kernel verification composition failed: {error}"),
            Self::Fallback(error) => write!(f, "Watchdog fallback composition failed: {error}"),
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

    /// Composes the separately registered Watchdog fallback path. It loads
    /// only installer-pinned local verification material and the protected
    /// one-shot ledger; it never opens the Kernel front door or UserBroker.
    pub fn from_fallback(work_root: impl Into<PathBuf>) -> Result<Self, NotifyBuildError> {
        let work_root = work_root.into();
        let ports = load_fallback_verification_ports(&work_root)?;
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
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            KernelClientError::Configuration("host clock is before Unix epoch".to_owned())
        })?
        .as_millis();
    let now_unix_ms = u64::try_from(now_unix_ms).map_err(|_| {
        KernelClientError::Configuration("host clock exceeds request deadline range".to_owned())
    })?;
    const MAX_CLOCK_SKEW_MS: u64 = 5_000;
    const MAX_CLOCK_AGE_MS: u64 = 60_000;
    for observed in [
        request.context.clock.valid_time_ms,
        request.context.clock.known_time_ms,
    ]
    .into_iter()
    .flatten()
    {
        let observed = u64::try_from(observed).map_err(|_| {
            KernelClientError::Configuration(
                "notification request contains a negative clock observation".to_owned(),
            )
        })?;
        if observed > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || now_unix_ms.saturating_sub(observed) > MAX_CLOCK_AGE_MS
        {
            return Err(KernelClientError::Configuration(
                "notification clock observation is stale or from the future".to_owned(),
            ));
        }
    }
    let deadline_unix_ms = now_unix_ms
        .checked_add(Duration::from_secs(30).as_millis() as u64)
        .ok_or_else(|| KernelClientError::Configuration("request deadline overflow".to_owned()))?;
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

const FALLBACK_VERIFIER_RELATIVE: &str = "Eliot/notify/watchdog-verification.json";
const FALLBACK_LEDGER_RELATIVE: &str = "Eliot/notify/watchdog-ledger.json";
const FALLBACK_ENVELOPE_RELATIVE: &str = "Eliot/notify/watchdog-fallback-envelope.json";
const FALLBACK_BYTES_LIMIT: u64 = 64 * 1024;
const WATCHDOG_OPERATION: &str = "watchdog_fallback_signature";
const WATCHDOG_OWNER: &str = "X-01";
const A08_OPERATION: &str = "a08_notification_admission";
const A08_OWNER: &str = "A-08";
const DELIVERY_OPERATION: &str = "notification_delivery";
const DELIVERY_OWNER: &str = "delivery-receipt-verifier";

/// Installer-pinned public material for the separately registered X-01 route.
/// The private signing key is never persisted here or accepted from the user
/// process. The protected declaration binds the public key to one installation,
/// audience, authority epoch, algorithm, key id and signature domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FallbackVerificationDeclaration {
    installation_identity: eliot_platform::PlatformHandle,
    audience: eliot_platform::PlatformHandle,
    authority_epoch: u64,
    algorithm: String,
    key_id: eliot_platform::PlatformHandle,
    domain: String,
    public_key: String,
}

struct FallbackMaterial {
    declaration: FallbackVerificationDeclaration,
    declaration_digest: String,
    lease: Option<ProtectedPathLease>,
}

impl FallbackMaterial {
    fn validate_live(&self) -> Result<FallbackVerificationDeclaration, PortError> {
        if let Some(lease) = &self.lease {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            let bytes = lease
                .read_bounded(FALLBACK_BYTES_LIMIT)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            if sha256_hex(&bytes) != self.declaration_digest {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
            let declaration: FallbackVerificationDeclaration = serde_json::from_slice(&bytes)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?;
            if declaration != self.declaration
                || eliot_receipts::canonical_json_bytes(&declaration)
                    .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?
                    != bytes
            {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
        }
        Ok(self.declaration.clone())
    }
}

fn fallback_provider_error(code: ProviderErrorCode) -> PortError {
    PortError::Provider(ProviderError {
        code,
        retryable: matches!(
            code,
            ProviderErrorCode::Unavailable | ProviderErrorCode::Timeout
        ),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_hex(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    if value.len() != expected_bytes.checked_mul(2)?
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)? as u8;
            let low = (pair[1] as char).to_digit(16)? as u8;
            Some((high << 4) | low)
        })
        .collect()
}

fn validate_fallback_declaration(
    declaration: &FallbackVerificationDeclaration,
) -> Result<(), String> {
    if declaration.authority_epoch == 0
        || declaration.installation_identity.as_str().trim().is_empty()
        || declaration.audience.as_str().trim().is_empty()
        || declaration.key_id.as_str().trim().is_empty()
        || declaration.algorithm != WATCHDOG_SIGNATURE_ALGORITHM
        || declaration.domain != WATCHDOG_SIGNATURE_DOMAIN
        || declaration.public_key.len() != 64
        || !declaration
            .public_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("watchdog verification declaration is invalid".to_owned());
    }
    let bytes = decode_hex(&declaration.public_key, 32)
        .ok_or_else(|| "watchdog public key is not valid hex".to_owned())?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "watchdog public key has the wrong length".to_owned())?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| format!("watchdog public key is invalid: {error}"))?;
    Ok(())
}

fn load_fallback_material() -> Result<FallbackMaterial, NotifyBuildError> {
    let path = protected_program_data_path(FALLBACK_VERIFIER_RELATIVE)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let lease = ProtectedPathLease::open_existing_absolute(&path)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let bytes = lease
        .read_bounded(FALLBACK_BYTES_LIMIT)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let declaration: FallbackVerificationDeclaration =
        serde_json::from_slice(&bytes).map_err(|error| {
            NotifyBuildError::Fallback(format!("decode verifier material: {error}"))
        })?;
    validate_fallback_declaration(&declaration).map_err(NotifyBuildError::Fallback)?;
    if eliot_receipts::canonical_json_bytes(&declaration).map_err(|error| {
        NotifyBuildError::Fallback(format!("canonicalize verifier material: {error}"))
    })? != bytes
    {
        return Err(NotifyBuildError::Fallback(
            "watchdog verification material is not canonical JSON".to_owned(),
        ));
    }
    Ok(FallbackMaterial {
        declaration,
        declaration_digest: sha256_hex(&bytes),
        lease: Some(lease),
    })
}

/// Loads one autonomous scheduler envelope and derives every request identity
/// from the protected declaration and signed payload. No stdin or caller-owned
/// [`NotificationRequest`] participates in this route.
pub fn load_watchdog_fallback_request()
-> Result<(SignedWatchdogFallbackEnvelope, NotificationRequest), NotifyBuildError> {
    let material = load_fallback_material()?;
    let envelope_path = protected_program_data_path(FALLBACK_ENVELOPE_RELATIVE)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let lease = ProtectedPathLease::open_existing_absolute(&envelope_path)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let bytes = lease
        .read_bounded(FALLBACK_BYTES_LIMIT)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let envelope: SignedWatchdogFallbackEnvelope =
        serde_json::from_slice(&bytes).map_err(|error| {
            NotifyBuildError::Fallback(format!("decode watchdog envelope: {error}"))
        })?;
    if eliot_receipts::canonical_json_bytes(&envelope).map_err(|error| {
        NotifyBuildError::Fallback(format!("canonicalize watchdog envelope: {error}"))
    })? != bytes
    {
        return Err(NotifyBuildError::Fallback(
            "watchdog envelope is not canonical JSON".to_owned(),
        ));
    }
    let request_hash = watchdog_request_hash(&envelope)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let request_id = watchdog_request_id(&envelope)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let notification = watchdog_notification_id(&envelope)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let authority_epoch = AuthorityEpoch::new(material.declaration.authority_epoch)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let session_id = SessionId::new(material.declaration.audience.as_str())
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NotifyBuildError::Fallback("host clock is before Unix epoch".to_owned()))?
        .as_millis();
    let now_ms = i64::try_from(now_ms)
        .map_err(|_| NotifyBuildError::Fallback("host clock exceeds request range".to_owned()))?;
    let request = NotificationRequest {
        context: RequestMetadata {
            request_id: RequestId::new(request_id)
                .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
            session_id: Some(session_id),
            task_id: None,
            product_id: ProductId::new(WATCHDOG_PRODUCT_ID)
                .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
            source_id: SourceId::new(WATCHDOG_SOURCE_ID)
                .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
            state_fence: StateFence::new(authority_epoch, ResourceGeneration::genesis()),
            clock: ClockReading {
                valid_time_ms: Some(now_ms),
                known_time_ms: Some(now_ms),
                ..ClockReading::default()
            },
        },
        canonical_request_hash: PlatformHandle::new(request_hash)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
        notification: PlatformHandle::new(notification)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
        audience: material.declaration.audience,
        body_digest: PlatformHandle::new(envelope.envelope.evidence_digest.clone())
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?,
    };
    Ok((envelope, request))
}

fn request_matches_fallback(
    request: &NotificationRequest,
    declaration: &FallbackVerificationDeclaration,
) -> bool {
    request.audience == declaration.audience
        && request
            .context
            .session_id
            .as_ref()
            .is_some_and(|session| session.as_str() == declaration.audience.as_str())
        && request.context.state_fence.authority_epoch.value() == declaration.authority_epoch
        && request.context.state_fence.resource_generation.value() == 1
        && request.context.product_id.as_str() == eliot_notify_core::WATCHDOG_PRODUCT_ID
        && request.context.source_id.as_str() == eliot_notify_core::WATCHDOG_SOURCE_ID
}

#[derive(Clone, Copy)]
enum FallbackDisposition {
    Success,
    Failure,
    Partial,
    Unknown,
}

fn proof_name(proof: ProofCeiling) -> &'static str {
    match proof {
        ProofCeiling::Observation => "OBSERVATION",
        ProofCeiling::CandidateArtifact => "CANDIDATE_ARTIFACT",
        ProofCeiling::ScopedVerification => "SCOPED_VERIFICATION",
        ProofCeiling::ObservedExternalEffect => "OBSERVED_EXTERNAL_EFFECT",
    }
}

fn effect_name(effect: EffectClass) -> &'static str {
    match effect {
        EffectClass::Read => "READ",
        EffectClass::Candidate => "CANDIDATE",
        EffectClass::ReversibleMutation => "REVERSIBLE_MUTATION",
        EffectClass::ExternalEffect => "EXTERNAL_EFFECT",
    }
}

fn fallback_disposition(disposition: FallbackDisposition, proof: ProofCeiling) -> Value {
    match disposition {
        FallbackDisposition::Success => json!({
            "kind": "SUCCESS",
            "proof": proof_name(proof),
        }),
        FallbackDisposition::Failure => json!({
            "kind": "FAILURE",
            "code": "DELIVERY_FAILED",
            "proof": proof_name(proof),
        }),
        FallbackDisposition::Partial => json!({
            "kind": "PARTIAL",
            "proof": proof_name(proof),
            "unresolved": ["fallback delivery evidence is partial"],
        }),
        FallbackDisposition::Unknown => json!({
            "kind": "UNKNOWN",
            "reason": "fallback delivery outcome is unknown",
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn issue_fallback_receipt(
    request: &NotificationRequest,
    operation_kind: &str,
    idempotency_key: &str,
    authority_owner: &str,
    effect: EffectClass,
    disposition: FallbackDisposition,
    proof: ProofCeiling,
    artifact_digest: &str,
) -> Result<ReceiptEnvelope, PortError> {
    let metadata = &request.context;
    let task = metadata.task_id.as_ref().map(|task_id| {
        json!({
            "task_id": task_id,
            "task_revision": metadata.state_fence.task_revision,
            "state_fence": metadata.state_fence,
        })
    });
    let session = metadata.session_id.as_ref().map(|session_id| {
        json!({
            "session_id": session_id,
            "authority_epoch": metadata.state_fence.authority_epoch,
            "state_fence": metadata.state_fence,
        })
    });
    let core: eliot_receipts::ReceiptCore = serde_json::from_value(json!({
        "contract": contract_identity()
            .map_err(|_| fallback_provider_error(ProviderErrorCode::Failed))?,
        "kind": "VERIFICATION",
        "work_scope": {
            "scope_id": "scope-watchdog-fallback",
            "product_id": metadata.product_id,
            "resource_generation": metadata.state_fence.resource_generation,
            "state_fence": metadata.state_fence,
        },
        "task": task,
        "session": session,
        "causal": {
            "state_fence": metadata.state_fence,
            "transaction_sequence": 1,
            "parent_receipt_id": null,
            "predecessor_receipt_ids": [],
        },
        "request": {
            "metadata": metadata,
            "state_fence": metadata.state_fence,
        },
        "operation": {
            "operation_id": format!("watchdog-fallback-{operation_kind}"),
            "request_id": metadata.request_id,
            "idempotency_key": idempotency_key,
            "operation_kind": operation_kind,
            "effect": effect_name(effect),
            "state_fence": metadata.state_fence,
        },
        "authority": {
            "authority_id": format!("authority-{authority_owner}"),
            "authority_owner": authority_owner,
            "authority_epoch": metadata.state_fence.authority_epoch,
            "state_fence": metadata.state_fence,
            "allowed_effect": effect_name(effect),
            "proof_ceiling": proof_name(proof),
        },
        "artifacts": [{
            "artifact_id": "artifact-watchdog-fallback",
            "sha256": artifact_digest,
            "role": "ARTIFACT",
            "source_revision": "watchdog-fallback-v1",
        }],
        "verifier": {
            "verifier_id": "verifier-watchdog-fallback",
            "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
            "artifact_ids": ["artifact-watchdog-fallback"],
            "proof_ceiling": proof_name(proof),
            "state_fence": metadata.state_fence,
        },
        "problem": null,
        "coordination": null,
        "disposition": fallback_disposition(disposition, proof),
    }))
    .map_err(|_| fallback_provider_error(ProviderErrorCode::Failed))?;
    ReceiptEnvelope::issue(core).map_err(|_| fallback_provider_error(ProviderErrorCode::Failed))
}

struct LocalFallbackWatchdog {
    material: Arc<Mutex<FallbackMaterial>>,
}

impl WatchdogSignaturePort for LocalFallbackWatchdog {
    fn verify_signature(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> PortOutcome<ReceiptEnvelope> {
        let declaration = match self.material.lock() {
            Ok(material) => match material.validate_live() {
                Ok(declaration) => declaration,
                Err(error) => return PortOutcome::Error(error),
            },
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::Failed));
            }
        };
        if envelope.envelope.installation_identity != declaration.installation_identity
            || envelope.algorithm != declaration.algorithm
            || envelope.key_id != declaration.key_id
            || envelope.domain != declaration.domain
            || envelope.envelope.timestamp_ms < 0
            || envelope.envelope.evidence_digest != request.body_digest.as_str()
            || !request_matches_fallback(request, &declaration)
        {
            return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::InvalidRequest));
        }
        let public_key = match decode_hex(&declaration.public_key, 32)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes: [u8; 32]| VerifyingKey::from_bytes(&bytes).ok())
        {
            Some(public_key) => public_key,
            None => {
                return PortOutcome::Error(fallback_provider_error(
                    ProviderErrorCode::InvalidRequest,
                ));
            }
        };
        let signature = match decode_hex(&envelope.signature, 64)
            .and_then(|bytes| bytes.try_into().ok())
            .map(|bytes: [u8; 64]| Signature::from_bytes(&bytes))
        {
            Some(signature) => signature,
            None => {
                return PortOutcome::Error(fallback_provider_error(
                    ProviderErrorCode::InvalidRequest,
                ));
            }
        };
        let payload = match watchdog_signature_payload(envelope) {
            Ok(payload) => payload,
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(
                    ProviderErrorCode::InvalidRequest,
                ));
            }
        };
        if public_key.verify_strict(&payload, &signature).is_err() {
            return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::InvalidRequest));
        }
        match issue_fallback_receipt(
            request,
            WATCHDOG_OPERATION,
            &format!("watchdog:{}", request.body_digest.as_str()),
            WATCHDOG_OWNER,
            EffectClass::Read,
            FallbackDisposition::Success,
            ProofCeiling::ScopedVerification,
            request.body_digest.as_str(),
        ) {
            Ok(receipt) => PortOutcome::Known(receipt),
            Err(error) => PortOutcome::Error(error),
        }
    }
}

struct LocalFallbackAdmission {
    material: Arc<Mutex<FallbackMaterial>>,
}

impl A08AdmissionPort for LocalFallbackAdmission {
    fn admit(&mut self, request: &AdmissionRequest<'_>) -> PortOutcome<AdmissionResult> {
        let declaration = match self.material.lock() {
            Ok(material) => match material.validate_live() {
                Ok(declaration) => declaration,
                Err(error) => return PortOutcome::Error(error),
            },
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::Failed));
            }
        };
        if !request_matches_fallback(request.platform_request, &declaration) {
            return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::InvalidRequest));
        }
        let recipient = eliot_notify_core::Recipient {
            principal: declaration.audience,
            role: eliot_notify_core::RecipientRole::RecoveryPrincipal,
        };
        let one_shot_key = match request.one_shot_key(&recipient) {
            Ok(value) => value,
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(
                    ProviderErrorCode::InvalidRequest,
                ));
            }
        };
        let artifact_digest = match request.admission_artifact_digest(&recipient) {
            Ok(value) => value,
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(
                    ProviderErrorCode::InvalidRequest,
                ));
            }
        };
        let receipt = match issue_fallback_receipt(
            request.platform_request,
            A08_OPERATION,
            one_shot_key.as_str(),
            A08_OWNER,
            EffectClass::ExternalEffect,
            FallbackDisposition::Success,
            ProofCeiling::ScopedVerification,
            &artifact_digest,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return PortOutcome::Error(error),
        };
        PortOutcome::Known(AdmissionResult {
            recipient,
            route: request.requested_route,
            effect: request.requested_effect,
            receipt,
        })
    }
}

struct LocalFallbackReceipt {
    material: Arc<Mutex<FallbackMaterial>>,
}

impl DeliveryReceiptPort for LocalFallbackReceipt {
    fn verify_delivery(
        &mut self,
        evidence: &DeliveryReceiptEvidence<'_>,
    ) -> PortOutcome<ReceiptEnvelope> {
        let declaration = match self.material.lock() {
            Ok(material) => match material.validate_live() {
                Ok(declaration) => declaration,
                Err(error) => return PortOutcome::Error(error),
            },
            Err(_) => {
                return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::Failed));
            }
        };
        if !request_matches_fallback(evidence.platform_request, &declaration) {
            return PortOutcome::Error(fallback_provider_error(ProviderErrorCode::InvalidRequest));
        }
        let (disposition, proof) = match evidence.provider_evidence {
            DeliveryProviderEvidence::Known { delivered: true } => (
                FallbackDisposition::Success,
                ProofCeiling::ObservedExternalEffect,
            ),
            DeliveryProviderEvidence::Known { delivered: false } => (
                FallbackDisposition::Failure,
                ProofCeiling::ObservedExternalEffect,
            ),
            DeliveryProviderEvidence::Partial { .. } => (
                FallbackDisposition::Partial,
                ProofCeiling::ScopedVerification,
            ),
            DeliveryProviderEvidence::Unknown { .. } => {
                (FallbackDisposition::Unknown, ProofCeiling::Observation)
            }
        };
        match issue_fallback_receipt(
            evidence.platform_request,
            DELIVERY_OPERATION,
            evidence.one_shot_key.as_str(),
            DELIVERY_OWNER,
            EffectClass::ExternalEffect,
            disposition,
            proof,
            evidence.platform_request.body_digest.as_str(),
        ) {
            Ok(receipt) => PortOutcome::Known(receipt),
            Err(error) => PortOutcome::Error(error),
        }
    }
}

struct LocalFallbackG08;

impl G08NotificationPort for LocalFallbackG08 {
    fn verify_source(
        &mut self,
        _envelope: &NotificationEnvelope,
        _request: &NotificationRequest,
    ) -> PortOutcome<ReceiptEnvelope> {
        PortOutcome::Error(fallback_provider_error(ProviderErrorCode::Unavailable))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FallbackLedgerSnapshot {
    entries: BTreeMap<String, FallbackLedgerEntry>,
    reservations: BTreeMap<String, String>,
    next_reservation: u64,
    #[serde(default)]
    poisoned_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FallbackLedgerEntry {
    claim_digest: String,
    observation: Option<DeliveryObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LedgerPersistResult {
    Published,
    Reconciled,
    NotPublished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LedgerReconcileDecision {
    PostState,
    NotPublished,
    Poison,
}

fn classify_ledger_reconciliation(
    previous: &FallbackLedgerSnapshot,
    desired: &FallbackLedgerSnapshot,
    current: &FallbackLedgerSnapshot,
    effect_may_have_happened: bool,
) -> LedgerReconcileDecision {
    if current == desired {
        LedgerReconcileDecision::PostState
    } else if current == previous && !effect_may_have_happened {
        LedgerReconcileDecision::NotPublished
    } else {
        LedgerReconcileDecision::Poison
    }
}

fn allocate_reservation_id(counter: &mut u64) -> Option<(String, PlatformHandle)> {
    let next = counter.checked_add(1)?;
    let text = format!("watchdog-reservation-{next}");
    let handle = PlatformHandle::new(text.clone()).ok()?;
    *counter = next;
    Some((text, handle))
}

struct LocalFallbackLedger {
    expected_authority_epoch: u64,
    state: FallbackLedgerSnapshot,
    platform: WindowsPlatform,
    relative: PathBuf,
    lease: Option<ProtectedPathLease>,
}

impl LocalFallbackLedger {
    fn load(root: &Path, expected_authority_epoch: u64) -> Result<Self, NotifyBuildError> {
        let relative = PathBuf::from(FALLBACK_LEDGER_RELATIVE);
        let path = protected_program_data_path(&relative)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
        let lease = ProtectedPathLease::open_or_create(&relative)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
        let bytes = lease
            .read_bounded(FALLBACK_BYTES_LIMIT)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
        let state = if bytes.is_empty() {
            FallbackLedgerSnapshot::default()
        } else {
            serde_json::from_slice(&bytes).map_err(|error| {
                NotifyBuildError::Fallback(format!("decode fallback ledger: {error}"))
            })?
        };
        let platform = WindowsPlatform::new(root)
            .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
        if lease.path() != path {
            return Err(NotifyBuildError::Fallback(
                "fallback ledger lease path mismatch".to_owned(),
            ));
        }
        Ok(Self {
            expected_authority_epoch,
            state,
            platform,
            relative,
            lease: Some(lease),
        })
    }

    fn validate_request(&self, request: &NotificationRequest, intent: &LedgerIntent) -> bool {
        intent.request_id.as_str() == request.context.request_id.as_str()
            && request.context.state_fence.authority_epoch.value() == self.expected_authority_epoch
    }

    fn read_current(&mut self) -> Result<FallbackLedgerSnapshot, PortError> {
        let lease = ProtectedPathLease::open_or_create(&self.relative)
            .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
        lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity())
            .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
        let bytes = lease
            .read_bounded(FALLBACK_BYTES_LIMIT)
            .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
        self.lease = Some(lease);
        if bytes.is_empty() {
            Ok(FallbackLedgerSnapshot::default())
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))
        }
    }

    fn poison_key(&mut self, key: &str) {
        self.state.poisoned_keys.insert(key.to_owned());
    }

    fn persist(
        &mut self,
        previous: &FallbackLedgerSnapshot,
        key: &str,
        effect_may_have_happened: bool,
    ) -> Result<LedgerPersistResult, PortError> {
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| fallback_provider_error(ProviderErrorCode::Failed))?;
        let lease = self
            .lease
            .take()
            .ok_or_else(|| fallback_provider_error(ProviderErrorCode::Unavailable))?;
        let verified = lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity());
        if verified.is_err() {
            self.lease = Some(lease);
            self.poison_key(key);
            return Err(fallback_provider_error(ProviderErrorCode::Unavailable));
        }
        drop(lease);
        let scope = WorkScopePath::new("watchdog-ledger.json")
            .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?;
        let published = matches!(
            self.platform.publish_atomic(&scope, &bytes),
            Ok(PublicationOutcome::Published(_))
        );
        if published {
            self.lease = ProtectedPathLease::open_or_create(&self.relative).ok();
            if self.lease.is_none() {
                self.poison_key(key);
                return Err(fallback_provider_error(ProviderErrorCode::Unavailable));
            }
            return Ok(LedgerPersistResult::Published);
        }

        // A publication error is not proof that the old bytes remain. Re-open
        // through a fresh protected lease and compare the complete snapshot.
        // An exact post-state is safe to acknowledge; anything else is kept
        // unavailable and poisoned so a retry cannot duplicate an effect.
        let current = match self.read_current() {
            Ok(current) => current,
            Err(_) => {
                self.poison_key(key);
                return Err(fallback_provider_error(ProviderErrorCode::Unavailable));
            }
        };
        match classify_ledger_reconciliation(
            previous,
            &self.state,
            &current,
            effect_may_have_happened,
        ) {
            LedgerReconcileDecision::PostState => Ok(LedgerPersistResult::Reconciled),
            LedgerReconcileDecision::NotPublished => {
                self.state = current;
                Ok(LedgerPersistResult::NotPublished)
            }
            LedgerReconcileDecision::Poison => {
                self.poison_key(key);
                Err(fallback_provider_error(ProviderErrorCode::Unavailable))
            }
        }
    }
}

impl OneShotLedgerPort for LocalFallbackLedger {
    fn reserve(
        &mut self,
        intent: &LedgerIntent,
        request: &NotificationRequest,
    ) -> LedgerReserveOutcome {
        if !self.validate_request(request, intent) {
            return LedgerReserveOutcome::Conflict;
        }
        let key = intent.one_shot_key.as_str().to_owned();
        if self.state.poisoned_keys.contains(&key) {
            return LedgerReserveOutcome::Unavailable;
        }
        if let Some(entry) = self.state.entries.get(&key) {
            if entry.claim_digest != intent.claim_digest {
                return LedgerReserveOutcome::Conflict;
            }
            return entry.observation.clone().map_or(
                LedgerReserveOutcome::Conflict,
                |observation| LedgerReserveOutcome::Replay {
                    observation: Box::new(observation),
                },
            );
        }
        let previous = self.state.clone();
        let (reservation_id, reservation_id_handle) =
            match allocate_reservation_id(&mut self.state.next_reservation) {
                Some(value) => value,
                None => return LedgerReserveOutcome::Unavailable,
            };
        self.state.entries.insert(
            key.clone(),
            FallbackLedgerEntry {
                claim_digest: intent.claim_digest.clone(),
                observation: None,
            },
        );
        self.state.reservations.insert(
            reservation_id.clone(),
            request.context.request_id.as_str().to_owned(),
        );
        match self.persist(&previous, &key, false) {
            Ok(LedgerPersistResult::Published | LedgerPersistResult::Reconciled) => {}
            Ok(LedgerPersistResult::NotPublished) | Err(_) => {
                return LedgerReserveOutcome::Unavailable;
            }
        }
        LedgerReserveOutcome::Reserved {
            reservation: LedgerReservation {
                one_shot_key: intent.one_shot_key.clone(),
                claim_digest: intent.claim_digest.clone(),
                reservation_id: reservation_id_handle,
            },
        }
    }

    fn commit(
        &mut self,
        reservation: &LedgerReservation,
        observation: &DeliveryObservation,
        request: &NotificationRequest,
    ) -> LedgerCommitOutcome {
        let reservation_id = reservation.reservation_id.as_str();
        let key = reservation.one_shot_key.as_str();
        if self.state.poisoned_keys.contains(key) {
            return LedgerCommitOutcome::Unavailable;
        }
        if self
            .state
            .reservations
            .get(reservation_id)
            .is_none_or(|request_id| request_id != request.context.request_id.as_str())
        {
            return LedgerCommitOutcome::Conflict;
        }
        let Some(entry) = self.state.entries.get(key) else {
            return LedgerCommitOutcome::Conflict;
        };
        if entry.claim_digest != reservation.claim_digest {
            return LedgerCommitOutcome::Conflict;
        }
        if let Some(previous) = &entry.observation {
            return LedgerCommitOutcome::Replay {
                observation: Box::new(previous.clone()),
            };
        }
        let previous = self.state.clone();
        if let Some(entry) = self.state.entries.get_mut(key) {
            entry.observation = Some(observation.clone());
        } else {
            self.poison_key(key);
            return LedgerCommitOutcome::Unavailable;
        }
        self.state.reservations.remove(reservation_id);
        match self.persist(&previous, key, true) {
            Ok(LedgerPersistResult::Published | LedgerPersistResult::Reconciled) => {}
            Ok(LedgerPersistResult::NotPublished) | Err(_) => {
                // The platform effect already happened. Preserve an explicit
                // durable poison marker when possible; an uncertain marker is
                // never converted into Conflict/Replay on a later attempt.
                self.state = previous.clone();
                self.poison_key(key);
                let _ = self.persist(&previous, key, true);
                return LedgerCommitOutcome::Unavailable;
            }
        }
        LedgerCommitOutcome::Committed
    }
}

fn load_fallback_verification_ports(root: &Path) -> Result<VerificationPorts, NotifyBuildError> {
    let expected_root = protected_program_data_path("Eliot/notify")
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let expected_root = std::fs::canonicalize(expected_root)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let root = std::fs::canonicalize(root)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    if root != expected_root {
        return Err(NotifyBuildError::Fallback(
            "fallback root is not the installer-owned notification contour".to_owned(),
        ));
    }
    let material = load_fallback_material()?;
    let authority_epoch = material.declaration.authority_epoch;
    let material = Arc::new(Mutex::new(material));
    let ledger = LocalFallbackLedger::load(&root, authority_epoch)?;
    Ok(VerificationPorts {
        a08: Some(Box::new(LocalFallbackAdmission {
            material: Arc::clone(&material),
        })),
        g08: Some(Box::new(LocalFallbackG08)),
        watchdog: Some(Box::new(LocalFallbackWatchdog {
            material: Arc::clone(&material),
        })),
        delivery_receipt: Some(Box::new(LocalFallbackReceipt { material })),
        ledger: Some(Box::new(ledger)),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signer, SigningKey};
    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
        SessionId, SourceId, StateFence,
    };
    use eliot_notify_core::{
        DeliveryObservation, LedgerCommitOutcome, LedgerIntent, LedgerReservation,
        LedgerReserveOutcome, OneShotKey, OneShotLedgerPort, ProviderId,
    };
    use eliot_platform::{
        NotificationObservation, NotificationPort, NotificationRequest, PlatformHandle, PortOutcome,
    };

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

    fn fallback_request(
        _request_label: &str,
        evidence: &[u8],
    ) -> (SignedWatchdogFallbackEnvelope, NotificationRequest) {
        let evidence_digest = sha256_hex(evidence);
        let mut envelope = SignedWatchdogFallbackEnvelope {
            envelope: eliot_notify_core::WatchdogFallbackEnvelope {
                incident_class: PlatformHandle::new("CONTROL_PLANE_LOSS").unwrap(),
                installation_identity: PlatformHandle::new("installation-1").unwrap(),
                timestamp_ms: 100,
                evidence_digest: evidence_digest.clone(),
                recovery_instruction: eliot_notify_core::RecoveryInstruction::EliotRecoveryStatus,
            },
            algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
            key_id: PlatformHandle::new("watchdog-key-1").unwrap(),
            domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
            signature: "00".repeat(64),
        };
        let signing_key = test_signing_key();
        envelope.signature = encode_hex(
            &signing_key
                .sign(&watchdog_signature_payload(&envelope).unwrap())
                .to_bytes(),
        );
        let request_hash = watchdog_request_hash(&envelope).unwrap();
        let expected_request_id = watchdog_request_id(&envelope).unwrap();
        let request_id = RequestId::new(expected_request_id).unwrap();
        let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        let request = NotificationRequest {
            context: RequestMetadata {
                request_id,
                session_id: Some(SessionId::new("audience-1").unwrap()),
                task_id: None,
                product_id: ProductId::new(WATCHDOG_PRODUCT_ID).unwrap(),
                source_id: SourceId::new(WATCHDOG_SOURCE_ID).unwrap(),
                state_fence: fence,
                clock: ClockReading::default(),
            },
            canonical_request_hash: PlatformHandle::new(request_hash).unwrap(),
            notification: PlatformHandle::new(watchdog_notification_id(&envelope).unwrap())
                .unwrap(),
            audience: PlatformHandle::new("audience-1").unwrap(),
            body_digest: PlatformHandle::new(evidence_digest).unwrap(),
        };
        (envelope, request)
    }

    fn fallback_material() -> Arc<Mutex<FallbackMaterial>> {
        Arc::new(Mutex::new(FallbackMaterial {
            declaration: FallbackVerificationDeclaration {
                installation_identity: PlatformHandle::new("installation-1").unwrap(),
                audience: PlatformHandle::new("audience-1").unwrap(),
                authority_epoch: 1,
                algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
                key_id: PlatformHandle::new("watchdog-key-1").unwrap(),
                domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
                public_key: encode_hex(&test_signing_key().verifying_key().to_bytes()),
            },
            declaration_digest: "test-material".to_owned(),
            lease: None,
        }))
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn rebound_request(
        request: &NotificationRequest,
        envelope: &SignedWatchdogFallbackEnvelope,
    ) -> NotificationRequest {
        let mut rebound = request.clone();
        rebound.canonical_request_hash =
            PlatformHandle::new(watchdog_request_hash(envelope).unwrap()).unwrap();
        rebound.context.request_id =
            serde_json::from_value(serde_json::json!(watchdog_request_id(envelope).unwrap()))
                .unwrap();
        rebound.notification =
            PlatformHandle::new(watchdog_notification_id(envelope).unwrap()).unwrap();
        rebound.body_digest =
            PlatformHandle::new(envelope.envelope.evidence_digest.clone()).unwrap();
        rebound
    }

    fn watchdog_accepts(
        material: Arc<Mutex<FallbackMaterial>>,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> bool {
        let mut watchdog = LocalFallbackWatchdog { material };
        matches!(
            watchdog.verify_signature(envelope, request),
            PortOutcome::Known(_)
        )
    }

    #[derive(Clone, Default)]
    struct MemoryFallbackLedger {
        state: Arc<Mutex<BTreeMap<String, (String, Option<DeliveryObservation>)>>>,
    }

    impl OneShotLedgerPort for MemoryFallbackLedger {
        fn reserve(
            &mut self,
            intent: &LedgerIntent,
            request: &NotificationRequest,
        ) -> LedgerReserveOutcome {
            if intent.request_id.as_str() != request.context.request_id.as_str() {
                return LedgerReserveOutcome::Conflict;
            }
            let mut state = self.state.lock().unwrap();
            if let Some((claim, observation)) = state.get(&intent.one_shot_key.as_str().to_owned())
            {
                if claim != &intent.claim_digest {
                    return LedgerReserveOutcome::Conflict;
                }
                return observation
                    .clone()
                    .map_or(LedgerReserveOutcome::Conflict, |observation| {
                        LedgerReserveOutcome::Replay {
                            observation: Box::new(observation),
                        }
                    });
            }
            state.insert(
                intent.one_shot_key.as_str().to_owned(),
                (intent.claim_digest.clone(), None),
            );
            LedgerReserveOutcome::Reserved {
                reservation: LedgerReservation {
                    one_shot_key: intent.one_shot_key.clone(),
                    claim_digest: intent.claim_digest.clone(),
                    reservation_id: PlatformHandle::new("memory-reservation").unwrap(),
                },
            }
        }

        fn commit(
            &mut self,
            reservation: &LedgerReservation,
            observation: &DeliveryObservation,
            _request: &NotificationRequest,
        ) -> LedgerCommitOutcome {
            let mut state = self.state.lock().unwrap();
            let Some((claim, stored)) = state.get_mut(reservation.one_shot_key.as_str()) else {
                return LedgerCommitOutcome::Conflict;
            };
            if claim != &reservation.claim_digest {
                return LedgerCommitOutcome::Conflict;
            }
            if let Some(previous) = stored {
                return LedgerCommitOutcome::Replay {
                    observation: Box::new(previous.clone()),
                };
            }
            *stored = Some(observation.clone());
            LedgerCommitOutcome::Committed
        }
    }

    struct UnavailableFallbackLedger;

    impl OneShotLedgerPort for UnavailableFallbackLedger {
        fn reserve(
            &mut self,
            _intent: &LedgerIntent,
            _request: &NotificationRequest,
        ) -> LedgerReserveOutcome {
            LedgerReserveOutcome::Unavailable
        }

        fn commit(
            &mut self,
            _reservation: &LedgerReservation,
            _observation: &DeliveryObservation,
            _request: &NotificationRequest,
        ) -> LedgerCommitOutcome {
            LedgerCommitOutcome::Unavailable
        }
    }

    #[derive(Clone)]
    struct CountingNotification {
        calls: Arc<AtomicUsize>,
    }

    impl NotificationPort for CountingNotification {
        fn deliver(
            &mut self,
            request: &NotificationRequest,
        ) -> PortOutcome<NotificationObservation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            PortOutcome::Known(NotificationObservation {
                notification: request.notification.clone(),
                delivered: true,
            })
        }
    }

    fn fallback_ports(
        material: Arc<Mutex<FallbackMaterial>>,
        ledger: Box<dyn OneShotLedgerPort>,
    ) -> VerificationPorts {
        VerificationPorts {
            a08: Some(Box::new(LocalFallbackAdmission {
                material: Arc::clone(&material),
            })),
            g08: Some(Box::new(LocalFallbackG08)),
            watchdog: Some(Box::new(LocalFallbackWatchdog {
                material: Arc::clone(&material),
            })),
            delivery_receipt: Some(Box::new(LocalFallbackReceipt { material })),
            ledger: Some(ledger),
        }
    }

    #[test]
    fn fallback_invalid_signature_has_zero_platform_effect() {
        let (mut envelope, request) = fallback_request("fallback-invalid", b"evidence");
        envelope.signature = "ff".repeat(64);
        let mut bad_request = request.clone();
        bad_request.canonical_request_hash =
            PlatformHandle::new(watchdog_request_hash(&envelope).unwrap()).unwrap();
        bad_request.context.request_id =
            serde_json::from_value(serde_json::json!(watchdog_request_id(&envelope).unwrap()))
                .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut core = NotifyCore::new(
            CountingNotification {
                calls: Arc::clone(&calls),
            },
            fallback_ports(
                fallback_material(),
                Box::new(MemoryFallbackLedger::default()),
            ),
        );
        let invalid_result = core.deliver_watchdog_fallback(&envelope, &bad_request);
        assert!(matches!(
            invalid_result,
            Err(eliot_notify_core::NotifyError::ProviderFailure {
                provider: ProviderId::WatchdogSignature,
                ..
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_signature_binds_every_field_domain_key_and_installation() {
        let (signed, request) = fallback_request("fallback-tamper", b"evidence");
        assert!(watchdog_accepts(fallback_material(), &signed, &request));

        let mut algorithm = signed.clone();
        algorithm.algorithm = "ED25519-V2".to_owned();
        assert!(!watchdog_accepts(fallback_material(), &algorithm, &request));

        let mut key_id = signed.clone();
        key_id.key_id = PlatformHandle::new("other-key").unwrap();
        assert!(!watchdog_accepts(
            fallback_material(),
            &key_id,
            &rebound_request(&request, &key_id)
        ));

        let mut domain = signed.clone();
        domain.domain = "OTHER/DOMAIN/V1".to_owned();
        assert!(!watchdog_accepts(fallback_material(), &domain, &request));

        let mut incident = signed.clone();
        incident.envelope.incident_class = PlatformHandle::new("OTHER_INCIDENT").unwrap();
        assert!(!watchdog_accepts(
            fallback_material(),
            &incident,
            &rebound_request(&request, &incident)
        ));

        let mut installation = signed.clone();
        installation.envelope.installation_identity =
            PlatformHandle::new("other-installation").unwrap();
        assert!(!watchdog_accepts(
            fallback_material(),
            &installation,
            &rebound_request(&request, &installation)
        ));

        let mut timestamp = signed.clone();
        timestamp.envelope.timestamp_ms += 1;
        assert!(!watchdog_accepts(
            fallback_material(),
            &timestamp,
            &rebound_request(&request, &timestamp)
        ));

        let mut evidence = signed.clone();
        evidence.envelope.evidence_digest = sha256_hex(b"different-evidence");
        assert!(!watchdog_accepts(
            fallback_material(),
            &evidence,
            &rebound_request(&request, &evidence)
        ));

        let mut changed = serde_json::to_value(&signed).unwrap();
        changed["envelope"]["recovery_instruction"] = serde_json::json!("OTHER");
        assert!(serde_json::from_value::<SignedWatchdogFallbackEnvelope>(changed).is_err());

        let (mut different, different_request) = fallback_request("fallback-reuse", b"different");
        different.signature = signed.signature.clone();
        assert!(!watchdog_accepts(
            fallback_material(),
            &different,
            &different_request
        ));

        let wrong_key = fallback_material();
        wrong_key.lock().unwrap().declaration.public_key = encode_hex(
            &SigningKey::from_bytes(&[8_u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(!watchdog_accepts(wrong_key, &signed, &request));
    }

    #[test]
    fn fallback_request_identity_rejects_caller_substitution_before_platform() {
        let (envelope, request) = fallback_request("fallback-binding", b"evidence");
        for mutate in 0..4 {
            let mut changed = request.clone();
            match mutate {
                0 => changed.notification = PlatformHandle::new("caller-notification").unwrap(),
                1 => changed.context.product_id = ProductId::new("caller-product").unwrap(),
                2 => changed.context.source_id = SourceId::new("caller-source").unwrap(),
                3 => {
                    changed.context.request_id = serde_json::from_value(serde_json::json!(
                        "watchdog-replay-under-new-request-id"
                    ))
                    .unwrap()
                }
                _ => unreachable!(),
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let mut core = NotifyCore::new(
                CountingNotification {
                    calls: Arc::clone(&calls),
                },
                fallback_ports(
                    fallback_material(),
                    Box::new(MemoryFallbackLedger::default()),
                ),
            );
            assert!(matches!(
                core.deliver_watchdog_fallback(&envelope, &changed),
                Err(eliot_notify_core::NotifyError::FallbackMismatch)
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn fallback_ledger_reconciles_unknown_publication_and_exhausts_counter() {
        let previous = FallbackLedgerSnapshot::default();
        let mut desired = previous.clone();
        desired.entries.insert(
            "one-shot".to_owned(),
            FallbackLedgerEntry {
                claim_digest: "claim".to_owned(),
                observation: None,
            },
        );
        assert_eq!(
            classify_ledger_reconciliation(&previous, &desired, &previous, false),
            LedgerReconcileDecision::NotPublished
        );
        assert_eq!(
            classify_ledger_reconciliation(&previous, &desired, &previous, true),
            LedgerReconcileDecision::Poison
        );
        let mut mismatched = previous.clone();
        mismatched.next_reservation = 7;
        assert_eq!(
            classify_ledger_reconciliation(&previous, &desired, &mismatched, false),
            LedgerReconcileDecision::Poison
        );

        desired.poisoned_keys.insert("one-shot".to_owned());
        let bytes = serde_json::to_vec(&desired).unwrap();
        let reopened: FallbackLedgerSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert!(reopened.poisoned_keys.contains("one-shot"));

        let mut exhausted = u64::MAX;
        assert!(allocate_reservation_id(&mut exhausted).is_none());
        assert_eq!(exhausted, u64::MAX);
    }

    #[test]
    fn fallback_ledger_unavailable_has_zero_platform_effect() {
        let (envelope, request) = fallback_request("fallback-ledger-gap", b"evidence");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut core = NotifyCore::new(
            CountingNotification {
                calls: Arc::clone(&calls),
            },
            fallback_ports(fallback_material(), Box::new(UnavailableFallbackLedger)),
        );
        assert!(matches!(
            core.deliver_watchdog_fallback(&envelope, &request),
            Err(eliot_notify_core::NotifyError::PlanGap {
                provider: ProviderId::OneShotLedger,
                ..
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_valid_duplicate_is_exactly_once_and_conflict_never_retries_effect() {
        let (envelope, request) = fallback_request("fallback-replay", b"evidence");
        let calls = Arc::new(AtomicUsize::new(0));
        let ledger = MemoryFallbackLedger::default();
        let mut core = NotifyCore::new(
            CountingNotification {
                calls: Arc::clone(&calls),
            },
            fallback_ports(fallback_material(), Box::new(ledger)),
        );
        let first = core.deliver_watchdog_fallback(&envelope, &request).unwrap();
        assert!(!first.deduplicated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let replay = core.deliver_watchdog_fallback(&envelope, &request).unwrap();
        assert!(replay.deduplicated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut conflicting_request = request.clone();
        conflicting_request.context.request_id =
            serde_json::from_value(serde_json::json!("watchdog-replay-under-new-request-id"))
                .unwrap();
        let conflict_result = core.deliver_watchdog_fallback(&envelope, &conflicting_request);
        assert!(matches!(
            conflict_result,
            Err(eliot_notify_core::NotifyError::FallbackMismatch)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
