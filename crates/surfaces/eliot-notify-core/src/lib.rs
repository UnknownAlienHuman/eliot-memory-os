//! A-10 one-shot notification delivery core.
//!
//! This crate owns role-filtered projection and one bounded delivery attempt.
//! It owns no inbox, Problem lifecycle, acknowledgement, task completion,
//! release decision, persistence, Windows adapter, or process-local replay
//! state. Admission, source authenticity, fallback signatures, delivery
//! receipts, and durable one-shot replay are supplied by explicit ports.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

use eliot_platform::{
    NotificationObservation, NotificationPort, NotificationRequest, PlatformHandle, PortError,
    PortOutcome, ProviderError, ProviderErrorCode, UnknownReason,
};
use eliot_receipts::{
    EffectClass, ProofCeiling, ReceiptDisposition, ReceiptDispositionKind, ReceiptEnvelope,
    ReceiptKind, WorkScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SHA256_HEX_LENGTH: usize = 64;
const G08_OPERATION: &str = "g08_notification_projection";
const A08_OPERATION: &str = "a08_notification_admission";
const WATCHDOG_OPERATION: &str = "watchdog_fallback_signature";
const DELIVERY_OPERATION: &str = "notification_delivery";
const G08_OWNER: &str = "G-08";
const A08_OWNER: &str = "A-08";
const WATCHDOG_OWNER: &str = "X-01";
const DELIVERY_RECEIPT_OWNER: &str = "delivery-receipt-verifier";

/// Signature algorithm required for the separately registered X-01 route.
/// The private signing key is held only by Watchdog; A-10 receives only a
/// public verification key through its protected installer declaration.
pub const WATCHDOG_SIGNATURE_ALGORITHM: &str = "ED25519";

/// Domain/version included in the signed canonical payload.
pub const WATCHDOG_SIGNATURE_DOMAIN: &str = "ELIOT/X-01/WATCHDOG-FALLBACK/V1";

/// Fixed product/source identities for the autonomous X-01 route.
pub const WATCHDOG_PRODUCT_ID: &str = "eliot-notify-watchdog";
pub const WATCHDOG_SOURCE_ID: &str = "eliot-watchdog";

/// Provider identities used by typed `PLAN_GAP` and provider-failure results.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderId {
    A08Admission,
    G08Problem,
    WatchdogSignature,
    DeliveryReceipt,
    OneShotLedger,
    P01Platform,
}

/// A recipient role admitted by A-08 for exactly one delivery effect.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecipientRole {
    Requester,
    DomainOwner,
    ArchitectureOwner,
    SystemOwner,
    WorkScopeOwner,
    Approver,
    RecoveryPrincipal,
    AuthorizedRole,
}

/// Typed principal and role preserved through admission and delivery.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub principal: PlatformHandle,
    pub role: RecipientRole,
}

/// Inert normal-path content. Trust is established only when G-08 returns the
/// exact canonical source receipt and A-08 returns an admission receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEnvelope {
    pub notification_id: PlatformHandle,
    pub subject: String,
    pub summary: String,
    pub recipients: Vec<Recipient>,
    pub source_receipt: ReceiptEnvelope,
}

impl NotificationEnvelope {
    fn validate_shape(&self) -> Result<(), NotifyError> {
        validate_text(&self.subject, "subject")?;
        validate_text(&self.summary, "summary")?;
        if self.recipients.is_empty() {
            return Err(NotifyError::InvalidEnvelope("recipients"));
        }
        for recipient in &self.recipients {
            validate_recipient(recipient)?;
        }
        self.source_receipt
            .validate()
            .map_err(|error| receipt_error(ProviderId::G08Problem, error))?;
        Ok(())
    }
}

/// The only recovery instruction representable in the Watchdog fallback body.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryInstruction {
    EliotRecoveryStatus,
}

/// Minimal Watchdog fallback content. Normal notification subject, summary,
/// project content, evidence bytes, and secrets are not representable.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogFallbackEnvelope {
    pub incident_class: PlatformHandle,
    pub installation_identity: PlatformHandle,
    pub timestamp_ms: i64,
    pub evidence_digest: String,
    pub recovery_instruction: RecoveryInstruction,
}

/// Detached signature metadata and bytes for the five-field fallback content.
///
/// The signature covers [`watchdog_signature_payload`], which includes the
/// domain, algorithm, key id, and all five fields of [`WatchdogFallbackEnvelope`].
/// It is encoded as lowercase hexadecimal so the wire contract stays explicit
/// and does not depend on an ambient binary/text encoding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWatchdogFallbackEnvelope {
    pub envelope: WatchdogFallbackEnvelope,
    pub algorithm: String,
    pub key_id: PlatformHandle,
    pub domain: String,
    pub signature: String,
}

impl SignedWatchdogFallbackEnvelope {
    fn validate_metadata_shape(&self) -> Result<(), NotifyError> {
        validate_sha256(&self.envelope.evidence_digest, "evidence_digest")?;
        if self.algorithm != WATCHDOG_SIGNATURE_ALGORITHM {
            return Err(NotifyError::InvalidEnvelope("algorithm"));
        }
        if self.domain != WATCHDOG_SIGNATURE_DOMAIN {
            return Err(NotifyError::InvalidEnvelope("domain"));
        }
        validate_text(self.key_id.as_str(), "key_id")?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), NotifyError> {
        self.validate_metadata_shape()?;
        validate_hex(&self.signature, 128, "signature")
    }
}

/// Returns the canonical bytes signed by Watchdog.
///
/// The detached signature itself is intentionally excluded. The enclosing
/// metadata is included so algorithm, key selection, domain and version are
/// cryptographically bound to the five-field fallback content.
pub fn watchdog_signature_payload(
    signed: &SignedWatchdogFallbackEnvelope,
) -> Result<Vec<u8>, NotifyError> {
    #[derive(Serialize)]
    struct SignaturePayload<'a> {
        domain: &'a str,
        algorithm: &'a str,
        key_id: &'a PlatformHandle,
        envelope: &'a WatchdogFallbackEnvelope,
    }
    signed.validate_metadata_shape()?;
    eliot_receipts::canonical_json_bytes(&SignaturePayload {
        domain: &signed.domain,
        algorithm: &signed.algorithm,
        key_id: &signed.key_id,
        envelope: &signed.envelope,
    })
    .map_err(|error| NotifyError::Decode(error.to_string()))
}

/// Returns the canonical request hash for the signed fallback envelope.
///
/// # Errors
/// Returns an error only if canonical serialization fails.
pub fn watchdog_request_hash(
    envelope: &SignedWatchdogFallbackEnvelope,
) -> Result<String, NotifyError> {
    let bytes = eliot_receipts::canonical_json_bytes(envelope)
        .map_err(|error| NotifyError::Decode(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the deterministic notification identity bound to the signed
/// fallback payload. Callers cannot substitute a different notification
/// handle without invalidating the route before P-01.
pub fn watchdog_notification_id(
    envelope: &SignedWatchdogFallbackEnvelope,
) -> Result<String, NotifyError> {
    let payload = watchdog_signature_payload(envelope)?;
    Ok(sha256_hex(&payload))
}

/// Returns the deterministic request identity for one signed fallback.
pub fn watchdog_request_id(
    envelope: &SignedWatchdogFallbackEnvelope,
) -> Result<String, NotifyError> {
    Ok(format!("watchdog:{}", watchdog_request_hash(envelope)?))
}

/// Delivery route. Fallback is available only through the dedicated method.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryRoute {
    Normal,
    Fallback,
}

/// The sole external effect owned by A-10.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryEffect {
    UserSessionNotification,
}

/// Truthful classification of P-01 evidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryConfidence {
    Known,
    Partial,
    Unknown,
}

/// Origin of the canonical source-verification receipt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliverySourceKind {
    G08,
    WatchdogFallback,
}

/// Stable one-shot identity. It intentionally excludes caller request IDs.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct OneShotKey(String);

impl OneShotKey {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Inert request presented to the injected A-08 admission verifier.
pub struct AdmissionRequest<'a> {
    pub platform_request: &'a NotificationRequest,
    pub source_receipt: &'a ReceiptEnvelope,
    pub notification_id: &'a PlatformHandle,
    pub body_digest: &'a str,
    pub requested_route: DeliveryRoute,
    pub requested_effect: DeliveryEffect,
    pub normal_candidates: &'a [Recipient],
}

impl AdmissionRequest<'_> {
    /// Computes the durable one-shot key for a candidate recipient.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn one_shot_key(&self, recipient: &Recipient) -> Result<OneShotKey, NotifyError> {
        stable_one_shot_key(
            self.notification_id,
            &self.source_receipt.core.work_scope,
            recipient,
            self.requested_effect,
        )
    }

    /// Computes the immutable claim stored under the one-shot key.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn claim_digest(&self, recipient: &Recipient) -> Result<String, NotifyError> {
        stable_claim_digest(
            self.notification_id,
            self.body_digest,
            &self.source_receipt.core,
            recipient,
            self.requested_route,
            self.requested_effect,
        )
    }

    /// Digest an A-08 receipt must bind as its verified artifact.
    ///
    /// # Errors
    /// Returns an error if canonical serialization fails.
    pub fn admission_artifact_digest(&self, recipient: &Recipient) -> Result<String, NotifyError> {
        sha256_serialized(&(
            self.one_shot_key(recipient)?,
            self.claim_digest(recipient)?,
            recipient,
            self.requested_route,
            self.requested_effect,
        ))
    }
}

/// Sealed-by-port A-08 result. Public callers cannot pass this result to the
/// core; only the injected admission port can return it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionResult {
    pub recipient: Recipient,
    pub route: DeliveryRoute,
    pub effect: DeliveryEffect,
    pub receipt: ReceiptEnvelope,
}

/// P-01 evidence forwarded to the injected delivery-receipt verifier.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DeliveryProviderEvidence {
    Known {
        delivered: bool,
    },
    Partial {
        delivered: bool,
        missing: Vec<PlatformHandle>,
    },
    Unknown {
        reason: UnknownReason,
    },
}

impl DeliveryProviderEvidence {
    const fn expected_disposition(&self) -> ReceiptDispositionKind {
        match self {
            Self::Known { delivered: true } => ReceiptDispositionKind::Success,
            Self::Known { delivered: false } => ReceiptDispositionKind::Failure,
            Self::Partial { .. } => ReceiptDispositionKind::Partial,
            Self::Unknown { .. } => ReceiptDispositionKind::Unknown,
        }
    }

    const fn expected_proof(&self) -> ProofCeiling {
        match self {
            Self::Known { .. } => ProofCeiling::ObservedExternalEffect,
            Self::Partial { .. } => ProofCeiling::ScopedVerification,
            Self::Unknown { .. } => ProofCeiling::Observation,
        }
    }
}

/// Exact evidence presented to the delivery receipt verifier.
pub struct DeliveryReceiptEvidence<'a> {
    pub platform_request: &'a NotificationRequest,
    pub source_receipt: &'a ReceiptEnvelope,
    pub admission: &'a AdmissionResult,
    pub one_shot_key: &'a OneShotKey,
    pub claim_digest: &'a str,
    pub provider_evidence: &'a DeliveryProviderEvidence,
}

/// A-08 decides the exact principal, role, route, and effect.
pub trait A08AdmissionPort {
    fn admit(&mut self, request: &AdmissionRequest<'_>) -> PortOutcome<AdmissionResult>;
}

/// G-08 verifies the normal canonical projection and returns its exact receipt.
pub trait G08NotificationPort {
    fn verify_source(
        &mut self,
        envelope: &NotificationEnvelope,
        request: &NotificationRequest,
    ) -> PortOutcome<ReceiptEnvelope>;
}

/// Neutral P-01 delivery seam consumed by A-10.
///
/// An implementation receives the already-admitted [`NotificationRequest`]
/// and may report only the corresponding [`NotificationObservation`]. It
/// must preserve `Partial`, `Unknown`, and provider errors from the underlying
/// user-session delivery mechanism; `Known` is not permission to invent a
/// receipt. The platform crate's existing [`NotificationPort`] is adapted
/// below so a native provider can implement that lower-level neutral port
/// without depending on this surface crate.
pub trait NotificationDeliveryPort {
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation>;
}

impl<T> NotificationDeliveryPort for T
where
    T: NotificationPort + ?Sized,
{
    fn deliver(&mut self, request: &NotificationRequest) -> PortOutcome<NotificationObservation> {
        NotificationPort::deliver(self, request)
    }
}

/// X-01 verifies the minimal fallback signature in a trusted boundary.
pub trait WatchdogSignaturePort {
    fn verify_signature(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> PortOutcome<ReceiptEnvelope>;
}

/// Converts P-01 evidence into a canonical, validated receipt.
pub trait DeliveryReceiptPort {
    fn verify_delivery(
        &mut self,
        evidence: &DeliveryReceiptEvidence<'_>,
    ) -> PortOutcome<ReceiptEnvelope>;
}

/// Durable reservation intent. A different request ID may replay only when the
/// provider establishes the same key and claim digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerIntent {
    pub one_shot_key: OneShotKey,
    pub claim_digest: String,
    pub request_id: PlatformHandle,
}

/// Provider-owned durable reservation token.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerReservation {
    pub one_shot_key: OneShotKey,
    pub claim_digest: String,
    pub reservation_id: PlatformHandle,
}

/// Sealed reserve outcomes from the durable ledger provider.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum LedgerReserveOutcome {
    Reserved {
        reservation: LedgerReservation,
    },
    Replay {
        observation: Box<DeliveryObservation>,
    },
    Conflict,
    Unavailable,
}

/// Sealed commit outcomes from the durable ledger provider.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum LedgerCommitOutcome {
    Committed,
    Replay {
        observation: Box<DeliveryObservation>,
    },
    Conflict,
    Unavailable,
}

/// Durable idempotency/replay owner. A-10 never implements persistence.
pub trait OneShotLedgerPort {
    fn reserve(
        &mut self,
        intent: &LedgerIntent,
        request: &NotificationRequest,
    ) -> LedgerReserveOutcome;

    fn commit(
        &mut self,
        reservation: &LedgerReservation,
        observation: &DeliveryObservation,
        request: &NotificationRequest,
    ) -> LedgerCommitOutcome;
}

/// All verification and durable-state dependencies are explicit and optional
/// only so absence can fail as a typed `PLAN_GAP` before P-01 executes.
pub struct VerificationPorts {
    pub a08: Option<Box<dyn A08AdmissionPort>>,
    pub g08: Option<Box<dyn G08NotificationPort>>,
    pub watchdog: Option<Box<dyn WatchdogSignaturePort>>,
    pub delivery_receipt: Option<Box<dyn DeliveryReceiptPort>>,
    pub ledger: Option<Box<dyn OneShotLedgerPort>>,
}

/// Immutable result of one verified delivery or a durable replay.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryObservation {
    pub notification_id: PlatformHandle,
    pub body_digest: String,
    pub one_shot_key: OneShotKey,
    pub claim_digest: String,
    pub source_kind: DeliverySourceKind,
    pub route: DeliveryRoute,
    pub effect: DeliveryEffect,
    pub recipient: Recipient,
    pub confidence: DeliveryConfidence,
    pub delivered: Option<bool>,
    pub deduplicated: bool,
    pub source_receipt: ReceiptEnvelope,
    pub admission_receipt: ReceiptEnvelope,
    pub delivery_receipt: ReceiptEnvelope,
}

impl DeliveryObservation {
    /// Validates canonical identities, typed context, disposition, proof, and
    /// the delivery-only authority ceiling.
    ///
    /// # Errors
    /// Returns an error when a receipt or cross-receipt binding is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), NotifyError> {
        validate_receipt_internal_context(&self.source_receipt, source_provider(self.source_kind))?;
        let source_expectation = match self.source_kind {
            DeliverySourceKind::G08 => ReceiptExpectation {
                provider: ProviderId::G08Problem,
                operation_kind: G08_OPERATION,
                authority_owner: G08_OWNER,
                idempotency_key: &source_idempotency(&self.notification_id, &self.body_digest),
                effect: EffectClass::Read,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: &self.body_digest,
            },
            DeliverySourceKind::WatchdogFallback => ReceiptExpectation {
                provider: ProviderId::WatchdogSignature,
                operation_kind: WATCHDOG_OPERATION,
                authority_owner: WATCHDOG_OWNER,
                idempotency_key: &watchdog_idempotency(&self.body_digest),
                effect: EffectClass::Read,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: &self.body_digest,
            },
        };
        validate_receipt_structure(
            &self.source_receipt,
            &self.source_receipt,
            &source_expectation,
        )?;

        let expected_key = stable_one_shot_key(
            &self.notification_id,
            &self.source_receipt.core.work_scope,
            &self.recipient,
            self.effect,
        )?;
        let expected_claim = stable_claim_digest(
            &self.notification_id,
            &self.body_digest,
            &self.source_receipt.core,
            &self.recipient,
            self.route,
            self.effect,
        )?;
        if self.one_shot_key != expected_key || self.claim_digest != expected_claim {
            return Err(NotifyError::DeliveryIdentityConflict);
        }

        let admission_artifact = admission_artifact_digest(
            &self.one_shot_key,
            &self.claim_digest,
            &self.recipient,
            self.route,
            self.effect,
        )?;
        validate_receipt_structure(
            &self.admission_receipt,
            &self.source_receipt,
            &ReceiptExpectation {
                provider: ProviderId::A08Admission,
                operation_kind: A08_OPERATION,
                authority_owner: A08_OWNER,
                idempotency_key: self.one_shot_key.as_str(),
                effect: EffectClass::ExternalEffect,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: &admission_artifact,
            },
        )?;

        let (expected_disposition, expected_proof, expected_confidence, expected_delivered) = match (
            self.delivery_receipt.core.disposition.kind(),
            &self.delivery_receipt.core.disposition,
        ) {
            (
                ReceiptDispositionKind::Success,
                ReceiptDisposition::Success {
                    proof: ProofCeiling::ObservedExternalEffect,
                },
            ) => (
                ReceiptDispositionKind::Success,
                ProofCeiling::ObservedExternalEffect,
                DeliveryConfidence::Known,
                Some(true),
            ),
            (
                ReceiptDispositionKind::Failure,
                ReceiptDisposition::Failure {
                    proof: ProofCeiling::ObservedExternalEffect,
                    ..
                },
            ) => (
                ReceiptDispositionKind::Failure,
                ProofCeiling::ObservedExternalEffect,
                DeliveryConfidence::Known,
                Some(false),
            ),
            (
                ReceiptDispositionKind::Partial,
                ReceiptDisposition::Partial {
                    proof: ProofCeiling::ScopedVerification,
                    ..
                },
            ) => (
                ReceiptDispositionKind::Partial,
                ProofCeiling::ScopedVerification,
                DeliveryConfidence::Partial,
                self.delivered,
            ),
            (ReceiptDispositionKind::Unknown, ReceiptDisposition::Unknown { .. }) => (
                ReceiptDispositionKind::Unknown,
                ProofCeiling::Observation,
                DeliveryConfidence::Unknown,
                None,
            ),
            _ => return Err(NotifyError::InvalidReceiptBinding),
        };
        if self.confidence != expected_confidence || self.delivered != expected_delivered {
            return Err(NotifyError::InvalidReceiptBinding);
        }
        validate_receipt_structure(
            &self.delivery_receipt,
            &self.source_receipt,
            &ReceiptExpectation {
                provider: ProviderId::DeliveryReceipt,
                operation_kind: DELIVERY_OPERATION,
                authority_owner: DELIVERY_RECEIPT_OWNER,
                idempotency_key: self.one_shot_key.as_str(),
                effect: EffectClass::ExternalEffect,
                disposition: expected_disposition,
                proof: expected_proof,
                artifact_digest: &self.body_digest,
            },
        )
    }
}

/// Fail-closed JSON decoder for a public delivery observation.
///
/// # Errors
/// Returns an error when JSON decoding or semantic validation fails.
pub fn decode_delivery_observation(bytes: &[u8]) -> Result<DeliveryObservation, NotifyError> {
    let observation: DeliveryObservation =
        serde_json::from_slice(bytes).map_err(|error| NotifyError::Decode(error.to_string()))?;
    observation.validate()?;
    Ok(observation)
}

/// A-10 validation, verification, provider, and durable-ledger failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NotifyError {
    #[error("invalid envelope field: {0}")]
    InvalidEnvelope(&'static str),
    #[error("invalid recipient")]
    InvalidRecipient,
    #[error("no A-08 recipient matches the platform audience")]
    RecipientMismatch,
    #[error("fallback content or platform request does not match")]
    FallbackMismatch,
    #[error("P-01 request does not match the canonical source")]
    RequestEnvelopeMismatch,
    #[error("required provider {provider:?} is unavailable: {reason}")]
    PlanGap {
        provider: ProviderId,
        reason: &'static str,
    },
    #[error("provider {provider:?} returned incomplete verification")]
    VerificationIncomplete { provider: ProviderId },
    #[error("provider {provider:?} returned unknown verification: {reason}")]
    VerificationUnknown {
        provider: ProviderId,
        reason: UnknownReason,
    },
    #[error("provider {provider:?} failed with {code:?}; retryable={retryable}")]
    ProviderFailure {
        provider: ProviderId,
        code: ProviderErrorCode,
        retryable: bool,
    },
    #[error("P-01 port contract error: {0}")]
    Port(PortError),
    #[error("receipt from {provider:?} is invalid: {reason}")]
    ReceiptInvalid {
        provider: ProviderId,
        reason: String,
    },
    #[error("receipt binding, disposition, or proof is invalid")]
    InvalidReceiptBinding,
    #[error("delivery identity conflicts with the durable one-shot claim")]
    DeliveryIdentityConflict,
    #[error("durable ledger reservation conflicts with an existing claim")]
    LedgerConflict,
    #[error("durable ledger commit became unavailable after a verified external effect")]
    LedgerCommitUncertain(Box<DeliveryObservation>),
    #[error("delivery payload could not be decoded: {0}")]
    Decode(String),
}

/// Stateless A-10 coordinator around injected ports.
pub struct NotifyCore<P> {
    platform: P,
    ports: VerificationPorts,
}

impl<P> NotifyCore<P>
where
    P: NotificationDeliveryPort,
{
    #[must_use]
    pub fn new(platform: P, ports: VerificationPorts) -> Self {
        Self { platform, ports }
    }

    /// Returns the P-01 adapter. Verification and ledger providers remain
    /// outside A-10 state ownership.
    pub fn into_platform(self) -> P {
        self.platform
    }

    /// Delivers a normal G-08 projection after injected G-08 and A-08 proof.
    ///
    /// # Errors
    /// Returns a typed `PLAN_GAP`, provider, receipt, identity, or ledger error.
    pub fn deliver(
        &mut self,
        envelope: &NotificationEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, NotifyError> {
        envelope.validate_shape()?;
        validate_platform_request(request)?;
        if request.notification != envelope.notification_id
            || request.canonical_request_hash.as_str() != envelope.source_receipt.canonical_sha256()
        {
            return Err(NotifyError::RequestEnvelopeMismatch);
        }
        validate_source_for_request(&envelope.source_receipt, request, ProviderId::G08Problem)?;
        let source_idempotency =
            source_idempotency(&envelope.notification_id, request.body_digest.as_str());
        validate_receipt_structure(
            &envelope.source_receipt,
            &envelope.source_receipt,
            &ReceiptExpectation {
                provider: ProviderId::G08Problem,
                operation_kind: G08_OPERATION,
                authority_owner: G08_OWNER,
                idempotency_key: &source_idempotency,
                effect: EffectClass::Read,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: request.body_digest.as_str(),
            },
        )?;

        let g08 = self.ports.g08.as_mut().ok_or(NotifyError::PlanGap {
            provider: ProviderId::G08Problem,
            reason: "G-08 verification port is missing",
        })?;
        let verified = require_known(g08.verify_source(envelope, request), ProviderId::G08Problem)?;
        if verified != envelope.source_receipt {
            return Err(NotifyError::InvalidReceiptBinding);
        }

        self.deliver_verified_source(
            DeliverySourceKind::G08,
            &envelope.notification_id,
            request.body_digest.as_str(),
            &verified,
            request,
            &envelope.recipients,
        )
    }

    /// Delivers only the minimal signed Watchdog fallback content.
    ///
    /// # Errors
    /// Returns a typed `PLAN_GAP`, signature, request, receipt, or ledger error.
    pub fn deliver_watchdog_fallback(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, NotifyError> {
        envelope.validate_shape()?;
        validate_platform_request(request)?;
        let expected_hash = watchdog_request_hash(envelope)?;
        let expected_notification = watchdog_notification_id(envelope)?;
        let expected_request_id = watchdog_request_id(envelope)?;
        if request.canonical_request_hash.as_str() != expected_hash
            || request.body_digest.as_str() != envelope.envelope.evidence_digest
            || request.notification.as_str() != expected_notification
            || request.context.request_id.as_str() != expected_request_id
            || request.context.product_id.as_str() != WATCHDOG_PRODUCT_ID
            || request.context.source_id.as_str() != WATCHDOG_SOURCE_ID
            || request
                .context
                .session_id
                .as_ref()
                .is_none_or(|session| session.as_str() != request.audience.as_str())
            || request.context.state_fence.resource_generation.value() != 1
            || request.context.state_fence.task_revision.is_some()
            || request.context.state_fence.policy_revision.is_some()
            || request.context.state_fence.integration_revision.is_some()
        {
            return Err(NotifyError::FallbackMismatch);
        }

        let watchdog = self.ports.watchdog.as_mut().ok_or(NotifyError::PlanGap {
            provider: ProviderId::WatchdogSignature,
            reason: "Watchdog signature verification port is missing",
        })?;
        let verified = require_known(
            watchdog.verify_signature(envelope, request),
            ProviderId::WatchdogSignature,
        )?;
        validate_source_for_request(&verified, request, ProviderId::WatchdogSignature)?;
        let source_idempotency = watchdog_idempotency(request.body_digest.as_str());
        validate_receipt_structure(
            &verified,
            &verified,
            &ReceiptExpectation {
                provider: ProviderId::WatchdogSignature,
                operation_kind: WATCHDOG_OPERATION,
                authority_owner: WATCHDOG_OWNER,
                idempotency_key: &source_idempotency,
                effect: EffectClass::Read,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: request.body_digest.as_str(),
            },
        )?;

        self.deliver_verified_source(
            DeliverySourceKind::WatchdogFallback,
            &request.notification,
            request.body_digest.as_str(),
            &verified,
            request,
            &[],
        )
    }

    #[allow(clippy::too_many_lines)]
    fn deliver_verified_source(
        &mut self,
        source_kind: DeliverySourceKind,
        notification_id: &PlatformHandle,
        body_digest: &str,
        source_receipt: &ReceiptEnvelope,
        request: &NotificationRequest,
        normal_candidates: &[Recipient],
    ) -> Result<DeliveryObservation, NotifyError> {
        let admission_request = AdmissionRequest {
            platform_request: request,
            source_receipt,
            notification_id,
            body_digest,
            requested_route: match source_kind {
                DeliverySourceKind::G08 => DeliveryRoute::Normal,
                DeliverySourceKind::WatchdogFallback => DeliveryRoute::Fallback,
            },
            requested_effect: DeliveryEffect::UserSessionNotification,
            normal_candidates,
        };
        let a08 = self.ports.a08.as_mut().ok_or(NotifyError::PlanGap {
            provider: ProviderId::A08Admission,
            reason: "A-08 admission verification port is missing",
        })?;
        let admission = require_known(a08.admit(&admission_request), ProviderId::A08Admission)?;
        validate_recipient(&admission.recipient)?;
        if admission.route != admission_request.requested_route
            || admission.effect != admission_request.requested_effect
            || admission.recipient.principal != request.audience
            || (!normal_candidates.is_empty() && !normal_candidates.contains(&admission.recipient))
        {
            return Err(NotifyError::RecipientMismatch);
        }

        let one_shot_key = admission_request.one_shot_key(&admission.recipient)?;
        let claim_digest = admission_request.claim_digest(&admission.recipient)?;
        let admission_artifact =
            admission_request.admission_artifact_digest(&admission.recipient)?;
        validate_receipt_structure(
            &admission.receipt,
            source_receipt,
            &ReceiptExpectation {
                provider: ProviderId::A08Admission,
                operation_kind: A08_OPERATION,
                authority_owner: A08_OWNER,
                idempotency_key: one_shot_key.as_str(),
                effect: EffectClass::ExternalEffect,
                disposition: ReceiptDispositionKind::Success,
                proof: ProofCeiling::ScopedVerification,
                artifact_digest: &admission_artifact,
            },
        )?;

        let ledger_intent = LedgerIntent {
            one_shot_key: one_shot_key.clone(),
            claim_digest: claim_digest.clone(),
            request_id: PlatformHandle::new(request.context.request_id.as_str())
                .map_err(NotifyError::Port)?,
        };
        let ledger = self.ports.ledger.as_mut().ok_or(NotifyError::PlanGap {
            provider: ProviderId::OneShotLedger,
            reason: "durable one-shot ledger port is missing",
        })?;
        let reservation = match ledger.reserve(&ledger_intent, request) {
            LedgerReserveOutcome::Reserved { reservation } => {
                if reservation.one_shot_key != one_shot_key
                    || reservation.claim_digest != claim_digest
                {
                    return Err(NotifyError::LedgerConflict);
                }
                reservation
            }
            LedgerReserveOutcome::Replay { mut observation } => {
                observation.validate()?;
                if observation.one_shot_key != one_shot_key
                    || observation.claim_digest != claim_digest
                {
                    return Err(NotifyError::LedgerConflict);
                }
                observation.deduplicated = true;
                return Ok(*observation);
            }
            LedgerReserveOutcome::Conflict => return Err(NotifyError::LedgerConflict),
            LedgerReserveOutcome::Unavailable => {
                return Err(NotifyError::PlanGap {
                    provider: ProviderId::OneShotLedger,
                    reason: "durable one-shot ledger is unavailable",
                });
            }
        };

        let provider_evidence = match self.platform.deliver(request) {
            PortOutcome::Known(value) => {
                validate_provider_notification(notification_id, &value)?;
                DeliveryProviderEvidence::Known {
                    delivered: value.delivered,
                }
            }
            PortOutcome::Partial { value, missing } => {
                validate_provider_notification(notification_id, &value)?;
                DeliveryProviderEvidence::Partial {
                    delivered: value.delivered,
                    missing,
                }
            }
            PortOutcome::Unknown(reason) => DeliveryProviderEvidence::Unknown { reason },
            PortOutcome::Error(PortError::Provider(error)) => {
                return Err(map_provider_error(ProviderId::P01Platform, error));
            }
            PortOutcome::Error(error) => return Err(NotifyError::Port(error)),
        };

        let receipt_evidence = DeliveryReceiptEvidence {
            platform_request: request,
            source_receipt,
            admission: &admission,
            one_shot_key: &one_shot_key,
            claim_digest: &claim_digest,
            provider_evidence: &provider_evidence,
        };
        let receipt_port = self
            .ports
            .delivery_receipt
            .as_mut()
            .ok_or(NotifyError::PlanGap {
                provider: ProviderId::DeliveryReceipt,
                reason: "delivery receipt verification port is missing",
            })?;
        let delivery_receipt = require_known(
            receipt_port.verify_delivery(&receipt_evidence),
            ProviderId::DeliveryReceipt,
        )?;
        validate_receipt_structure(
            &delivery_receipt,
            source_receipt,
            &ReceiptExpectation {
                provider: ProviderId::DeliveryReceipt,
                operation_kind: DELIVERY_OPERATION,
                authority_owner: DELIVERY_RECEIPT_OWNER,
                idempotency_key: one_shot_key.as_str(),
                effect: EffectClass::ExternalEffect,
                disposition: provider_evidence.expected_disposition(),
                proof: provider_evidence.expected_proof(),
                artifact_digest: body_digest,
            },
        )?;

        let (confidence, delivered) = match provider_evidence {
            DeliveryProviderEvidence::Known { delivered } => {
                (DeliveryConfidence::Known, Some(delivered))
            }
            DeliveryProviderEvidence::Partial { delivered, .. } => {
                (DeliveryConfidence::Partial, Some(delivered))
            }
            DeliveryProviderEvidence::Unknown { .. } => (DeliveryConfidence::Unknown, None),
        };
        let observation = DeliveryObservation {
            notification_id: notification_id.clone(),
            body_digest: body_digest.to_owned(),
            one_shot_key,
            claim_digest,
            source_kind,
            route: admission.route,
            effect: admission.effect,
            recipient: admission.recipient,
            confidence,
            delivered,
            deduplicated: false,
            source_receipt: source_receipt.clone(),
            admission_receipt: admission.receipt,
            delivery_receipt,
        };
        observation.validate()?;

        match ledger.commit(&reservation, &observation, request) {
            LedgerCommitOutcome::Committed => Ok(observation),
            LedgerCommitOutcome::Replay {
                observation: mut replay,
            } => {
                replay.validate()?;
                if replay.one_shot_key != observation.one_shot_key
                    || replay.claim_digest != observation.claim_digest
                {
                    return Err(NotifyError::LedgerConflict);
                }
                replay.deduplicated = true;
                Ok(*replay)
            }
            LedgerCommitOutcome::Conflict => Err(NotifyError::LedgerConflict),
            LedgerCommitOutcome::Unavailable => {
                Err(NotifyError::LedgerCommitUncertain(Box::new(observation)))
            }
        }
    }
}

struct ReceiptExpectation<'a> {
    provider: ProviderId,
    operation_kind: &'a str,
    authority_owner: &'a str,
    idempotency_key: &'a str,
    effect: EffectClass,
    disposition: ReceiptDispositionKind,
    proof: ProofCeiling,
    artifact_digest: &'a str,
}

fn validate_source_for_request(
    receipt: &ReceiptEnvelope,
    request: &NotificationRequest,
    provider: ProviderId,
) -> Result<(), NotifyError> {
    validate_receipt_internal_context(receipt, provider)?;
    if receipt.core.request.metadata != request.context {
        return Err(NotifyError::InvalidReceiptBinding);
    }
    Ok(())
}

fn validate_receipt_internal_context(
    receipt: &ReceiptEnvelope,
    provider: ProviderId,
) -> Result<(), NotifyError> {
    receipt
        .validate()
        .map_err(|error| receipt_error(provider, error))?;
    let metadata = &receipt.core.request.metadata;
    let fence = &metadata.state_fence;
    if receipt.core.work_scope.product_id != metadata.product_id
        || receipt.core.work_scope.state_fence != *fence
        || receipt.core.request.state_fence != *fence
    {
        return Err(NotifyError::InvalidReceiptBinding);
    }
    match (&receipt.core.session, &metadata.session_id) {
        (None, None) => {}
        (Some(session), Some(session_id))
            if session.session_id == *session_id
                && session.authority_epoch == fence.authority_epoch
                && session.state_fence == *fence => {}
        _ => return Err(NotifyError::InvalidReceiptBinding),
    }
    match (&receipt.core.task, &metadata.task_id) {
        (None, None) => {}
        (Some(task), Some(task_id))
            if task.task_id == *task_id
                && Some(task.task_revision) == fence.task_revision
                && task.state_fence == *fence => {}
        _ => return Err(NotifyError::InvalidReceiptBinding),
    }
    Ok(())
}

fn validate_receipt_structure(
    receipt: &ReceiptEnvelope,
    source: &ReceiptEnvelope,
    expected: &ReceiptExpectation<'_>,
) -> Result<(), NotifyError> {
    validate_receipt_internal_context(receipt, expected.provider)?;
    if receipt.core.request.metadata != source.core.request.metadata
        || receipt.core.work_scope != source.core.work_scope
        || receipt.core.task != source.core.task
        || receipt.core.session != source.core.session
        || receipt.core.kind != ReceiptKind::Verification
        || receipt.core.operation.request_id != receipt.core.request.metadata.request_id
        || receipt.core.operation.idempotency_key != expected.idempotency_key
        || receipt.core.operation.operation_kind != expected.operation_kind
        || receipt.core.operation.effect != expected.effect
        || receipt.core.authority.authority_owner != expected.authority_owner
        || receipt.core.authority.allowed_effect != expected.effect
        || receipt.core.authority.proof_ceiling != expected.proof
        || receipt.core.disposition.kind() != expected.disposition
        || disposition_proof(&receipt.core.disposition) != expected.proof
    {
        return Err(NotifyError::InvalidReceiptBinding);
    }
    let artifact = receipt
        .core
        .artifacts
        .iter()
        .find(|artifact| artifact.sha256 == expected.artifact_digest)
        .ok_or(NotifyError::InvalidReceiptBinding)?;
    if artifact.role != ReceiptKind::Artifact {
        return Err(NotifyError::InvalidReceiptBinding);
    }
    let verifier = receipt
        .core
        .verifier
        .as_ref()
        .ok_or(NotifyError::InvalidReceiptBinding)?;
    if verifier.proof_ceiling != expected.proof
        || !verifier
            .artifact_ids
            .iter()
            .any(|artifact_id| artifact_id == &artifact.artifact_id)
    {
        return Err(NotifyError::InvalidReceiptBinding);
    }
    Ok(())
}

const fn disposition_proof(disposition: &ReceiptDisposition) -> ProofCeiling {
    match disposition {
        ReceiptDisposition::Success { proof }
        | ReceiptDisposition::Partial { proof, .. }
        | ReceiptDisposition::Failure { proof, .. } => *proof,
        ReceiptDisposition::Unknown { .. } | ReceiptDisposition::Cancelled { .. } => {
            ProofCeiling::Observation
        }
    }
}

fn source_provider(kind: DeliverySourceKind) -> ProviderId {
    match kind {
        DeliverySourceKind::G08 => ProviderId::G08Problem,
        DeliverySourceKind::WatchdogFallback => ProviderId::WatchdogSignature,
    }
}

fn validate_platform_request(request: &NotificationRequest) -> Result<(), NotifyError> {
    request.validate().map_err(NotifyError::Port)?;
    validate_sha256(
        request.canonical_request_hash.as_str(),
        "canonical_request_hash",
    )?;
    validate_sha256(request.body_digest.as_str(), "body_digest")
}

fn validate_provider_notification(
    notification_id: &PlatformHandle,
    observation: &NotificationObservation,
) -> Result<(), NotifyError> {
    if observation.notification == *notification_id {
        Ok(())
    } else {
        Err(NotifyError::RequestEnvelopeMismatch)
    }
}

fn validate_recipient(recipient: &Recipient) -> Result<(), NotifyError> {
    if recipient.principal.as_str().trim().is_empty()
        || recipient.principal.as_str().chars().any(char::is_control)
    {
        Err(NotifyError::InvalidRecipient)
    } else {
        Ok(())
    }
}

fn require_known<T>(outcome: PortOutcome<T>, provider: ProviderId) -> Result<T, NotifyError> {
    match outcome {
        PortOutcome::Known(value) => Ok(value),
        PortOutcome::Partial { .. } => Err(NotifyError::VerificationIncomplete { provider }),
        PortOutcome::Unknown(reason) => Err(NotifyError::VerificationUnknown { provider, reason }),
        PortOutcome::Error(PortError::Provider(error)) => Err(map_provider_error(provider, error)),
        PortOutcome::Error(error) => Err(NotifyError::Port(error)),
    }
}

#[allow(clippy::needless_match)]
fn map_provider_error(provider: ProviderId, error: ProviderError) -> NotifyError {
    let code = match error.code {
        ProviderErrorCode::Unavailable => ProviderErrorCode::Unavailable,
        ProviderErrorCode::PermissionDenied => ProviderErrorCode::PermissionDenied,
        ProviderErrorCode::InvalidRequest => ProviderErrorCode::InvalidRequest,
        ProviderErrorCode::Timeout => ProviderErrorCode::Timeout,
        ProviderErrorCode::Failed => ProviderErrorCode::Failed,
    };
    NotifyError::ProviderFailure {
        provider,
        code,
        retryable: error.retryable,
    }
}

fn stable_one_shot_key(
    notification_id: &PlatformHandle,
    work_scope: &WorkScopeBinding,
    recipient: &Recipient,
    effect: DeliveryEffect,
) -> Result<OneShotKey, NotifyError> {
    Ok(OneShotKey(sha256_serialized(&(
        notification_id,
        &work_scope.scope_id,
        recipient,
        effect,
    ))?))
}

fn stable_claim_digest(
    notification_id: &PlatformHandle,
    body_digest: &str,
    source_core: &eliot_receipts::ReceiptCore,
    recipient: &Recipient,
    route: DeliveryRoute,
    effect: DeliveryEffect,
) -> Result<String, NotifyError> {
    sha256_serialized(&(
        notification_id,
        body_digest,
        &source_core.work_scope,
        &source_core.task,
        &source_core.session,
        &source_core.request.metadata.product_id,
        &source_core.request.metadata.source_id,
        &source_core.request.metadata.state_fence,
        recipient,
        route,
        effect,
    ))
}

fn admission_artifact_digest(
    one_shot_key: &OneShotKey,
    claim_digest: &str,
    recipient: &Recipient,
    route: DeliveryRoute,
    effect: DeliveryEffect,
) -> Result<String, NotifyError> {
    sha256_serialized(&(one_shot_key, claim_digest, recipient, route, effect))
}

fn source_idempotency(notification_id: &PlatformHandle, body_digest: &str) -> String {
    format!("g08:{}:{body_digest}", notification_id.as_str())
}

fn watchdog_idempotency(evidence_digest: &str) -> String {
    format!("watchdog:{evidence_digest}")
}

fn receipt_error(provider: ProviderId, error: impl std::fmt::Display) -> NotifyError {
    NotifyError::ReceiptInvalid {
        provider,
        reason: error.to_string(),
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), NotifyError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(NotifyError::InvalidEnvelope(field))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), NotifyError> {
    if value.len() != SHA256_HEX_LENGTH
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        Err(NotifyError::InvalidEnvelope(field))
    } else {
        Ok(())
    }
}

fn validate_hex(value: &str, length: usize, field: &'static str) -> Result<(), NotifyError> {
    if value.len() != length
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        Err(NotifyError::InvalidEnvelope(field))
    } else {
        Ok(())
    }
}

fn sha256_serialized<T: Serialize>(value: &T) -> Result<String, NotifyError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| NotifyError::Decode(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use eliot_receipts::ReceiptCore;
    use serde_json::{Value, json};

    use super::*;

    #[derive(Clone, Copy)]
    enum DispositionSpec {
        Success,
        Partial,
        Failure,
        Unknown,
    }

    #[derive(Clone, Copy)]
    enum AdmissionMode {
        Good,
        WrongSession,
        WrongTask,
        WrongFence,
        WrongEffect,
        WrongDisposition,
        WrongProof,
    }

    #[derive(Clone, Copy)]
    enum DeliveryReceiptMode {
        Good,
        ForceSuccess,
        Underproof,
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

    fn disposition_value(spec: DispositionSpec, proof: ProofCeiling) -> Value {
        match spec {
            DispositionSpec::Success => json!({
                "kind": "SUCCESS",
                "proof": proof_name(proof),
            }),
            DispositionSpec::Partial => json!({
                "kind": "PARTIAL",
                "proof": proof_name(proof),
                "unresolved": ["provider evidence is partial"],
            }),
            DispositionSpec::Failure => json!({
                "kind": "FAILURE",
                "code": "INTERNAL",
                "proof": proof_name(proof),
            }),
            DispositionSpec::Unknown => json!({
                "kind": "UNKNOWN",
                "reason": "provider outcome is unknown",
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt_for(
        request: &NotificationRequest,
        operation_kind: &str,
        idempotency_key: &str,
        authority_owner: &str,
        effect: EffectClass,
        disposition: DispositionSpec,
        proof: ProofCeiling,
        artifact_digest: &str,
    ) -> ReceiptEnvelope {
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
        let core: ReceiptCore = serde_json::from_value(json!({
            "contract": eliot_receipts::contract_identity().unwrap(),
            "kind": "VERIFICATION",
            "work_scope": {
                "scope_id": "scope-main",
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
                "operation_id": format!("operation-{operation_kind}"),
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
                "artifact_id": "artifact-delivery",
                "sha256": artifact_digest,
                "role": "ARTIFACT",
                "source_revision": "source-revision-1",
            }],
            "verifier": {
                "verifier_id": "verifier-notify",
                "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
                "artifact_ids": ["artifact-delivery"],
                "proof_ceiling": proof_name(proof),
                "state_fence": metadata.state_fence,
            },
            "problem": null,
            "coordination": null,
            "disposition": disposition_value(disposition, proof),
        }))
        .unwrap();
        ReceiptEnvelope::issue(core).unwrap()
    }

    fn make_request(request_id: &str) -> NotificationRequest {
        serde_json::from_value(json!({
            "context": {
                "request_id": request_id,
                "session_id": "session-1",
                "task_id": "task-1",
                "product_id": "product-1",
                "source_id": "notify-test",
                "state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1,
                    "task_revision": 1,
                    "policy_revision": 1,
                    "integration_revision": 1,
                },
                "clock": {
                    "valid_time_ms": 10,
                    "known_time_ms": 11,
                    "transaction_sequence": 1,
                    "monotonic_ns": 12,
                },
            },
            "canonical_request_hash": sha256_hex(b"placeholder"),
            "notification": "notification-1",
            "audience": "human-1",
            "body_digest": sha256_hex(b"body"),
        }))
        .unwrap()
    }

    fn mutate_request(request: &NotificationRequest, mode: AdmissionMode) -> NotificationRequest {
        let mut value = serde_json::to_value(request).unwrap();
        match mode {
            AdmissionMode::WrongSession => {
                value["context"]["session_id"] = json!("session-other");
            }
            AdmissionMode::WrongTask => {
                value["context"]["task_id"] = json!("task-other");
            }
            AdmissionMode::WrongFence => {
                value["context"]["state_fence"]["resource_generation"] = json!(2);
            }
            AdmissionMode::Good
            | AdmissionMode::WrongEffect
            | AdmissionMode::WrongDisposition
            | AdmissionMode::WrongProof => {}
        }
        serde_json::from_value(value).unwrap()
    }

    fn normal_input(request_id: &str) -> (NotificationEnvelope, NotificationRequest) {
        let mut request = make_request(request_id);
        let notification = PlatformHandle::new("notification-1").unwrap();
        let receipt = receipt_for(
            &request,
            G08_OPERATION,
            &source_idempotency(&notification, request.body_digest.as_str()),
            G08_OWNER,
            EffectClass::Read,
            DispositionSpec::Success,
            ProofCeiling::ScopedVerification,
            request.body_digest.as_str(),
        );
        request.canonical_request_hash = PlatformHandle::new(receipt.canonical_sha256()).unwrap();
        (
            NotificationEnvelope {
                notification_id: notification,
                subject: "Attention required".to_owned(),
                summary: "Inspect canonical evidence".to_owned(),
                recipients: vec![Recipient {
                    principal: PlatformHandle::new("human-1").unwrap(),
                    role: RecipientRole::AuthorizedRole,
                }],
                source_receipt: receipt,
            },
            request,
        )
    }

    #[derive(Clone)]
    struct CountingPort {
        calls: Arc<AtomicUsize>,
        outcome: PortOutcome<NotificationObservation>,
    }

    impl NotificationPort for CountingPort {
        fn deliver(
            &mut self,
            _request: &NotificationRequest,
        ) -> PortOutcome<NotificationObservation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    fn counting_platform(
        outcome: PortOutcome<NotificationObservation>,
    ) -> (CountingPort, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            CountingPort {
                calls: Arc::clone(&calls),
                outcome,
            },
            calls,
        )
    }

    struct G08Fake {
        outcome: Option<PortOutcome<ReceiptEnvelope>>,
    }

    impl G08NotificationPort for G08Fake {
        fn verify_source(
            &mut self,
            envelope: &NotificationEnvelope,
            _request: &NotificationRequest,
        ) -> PortOutcome<ReceiptEnvelope> {
            self.outcome
                .clone()
                .unwrap_or_else(|| PortOutcome::Known(envelope.source_receipt.clone()))
        }
    }

    struct A08Fake {
        mode: AdmissionMode,
    }

    impl A08AdmissionPort for A08Fake {
        fn admit(&mut self, request: &AdmissionRequest<'_>) -> PortOutcome<AdmissionResult> {
            let recipient = request
                .normal_candidates
                .first()
                .cloned()
                .unwrap_or_else(|| Recipient {
                    principal: request.platform_request.audience.clone(),
                    role: RecipientRole::RecoveryPrincipal,
                });
            let receipt_request = mutate_request(request.platform_request, self.mode);
            let effect = if matches!(self.mode, AdmissionMode::WrongEffect) {
                EffectClass::Read
            } else {
                EffectClass::ExternalEffect
            };
            let disposition = if matches!(self.mode, AdmissionMode::WrongDisposition) {
                DispositionSpec::Partial
            } else {
                DispositionSpec::Success
            };
            let proof = if matches!(self.mode, AdmissionMode::WrongProof) {
                ProofCeiling::ObservedExternalEffect
            } else {
                ProofCeiling::ScopedVerification
            };
            let receipt = receipt_for(
                &receipt_request,
                A08_OPERATION,
                request.one_shot_key(&recipient).unwrap().as_str(),
                A08_OWNER,
                effect,
                disposition,
                proof,
                &request.admission_artifact_digest(&recipient).unwrap(),
            );
            PortOutcome::Known(AdmissionResult {
                recipient,
                route: request.requested_route,
                effect: request.requested_effect,
                receipt,
            })
        }
    }

    struct WatchdogFake {
        expected_signature: String,
    }

    impl WatchdogSignaturePort for WatchdogFake {
        fn verify_signature(
            &mut self,
            envelope: &SignedWatchdogFallbackEnvelope,
            request: &NotificationRequest,
        ) -> PortOutcome<ReceiptEnvelope> {
            if envelope.signature != self.expected_signature {
                return PortOutcome::Error(PortError::Provider(ProviderError {
                    code: ProviderErrorCode::InvalidRequest,
                    retryable: false,
                }));
            }
            PortOutcome::Known(receipt_for(
                request,
                WATCHDOG_OPERATION,
                &watchdog_idempotency(request.body_digest.as_str()),
                WATCHDOG_OWNER,
                EffectClass::Read,
                DispositionSpec::Success,
                ProofCeiling::ScopedVerification,
                request.body_digest.as_str(),
            ))
        }
    }

    struct DeliveryReceiptFake {
        mode: DeliveryReceiptMode,
    }

    impl DeliveryReceiptPort for DeliveryReceiptFake {
        fn verify_delivery(
            &mut self,
            evidence: &DeliveryReceiptEvidence<'_>,
        ) -> PortOutcome<ReceiptEnvelope> {
            let (mut disposition, mut proof) = match evidence.provider_evidence {
                DeliveryProviderEvidence::Known { delivered: true } => (
                    DispositionSpec::Success,
                    ProofCeiling::ObservedExternalEffect,
                ),
                DeliveryProviderEvidence::Known { delivered: false } => (
                    DispositionSpec::Failure,
                    ProofCeiling::ObservedExternalEffect,
                ),
                DeliveryProviderEvidence::Partial { .. } => {
                    (DispositionSpec::Partial, ProofCeiling::ScopedVerification)
                }
                DeliveryProviderEvidence::Unknown { .. } => {
                    (DispositionSpec::Unknown, ProofCeiling::Observation)
                }
            };
            match self.mode {
                DeliveryReceiptMode::Good => {}
                DeliveryReceiptMode::ForceSuccess => {
                    disposition = DispositionSpec::Success;
                    proof = ProofCeiling::ObservedExternalEffect;
                }
                DeliveryReceiptMode::Underproof => {
                    disposition = DispositionSpec::Success;
                    proof = ProofCeiling::ScopedVerification;
                }
            }
            PortOutcome::Known(receipt_for(
                evidence.platform_request,
                DELIVERY_OPERATION,
                evidence.one_shot_key.as_str(),
                DELIVERY_RECEIPT_OWNER,
                EffectClass::ExternalEffect,
                disposition,
                proof,
                evidence.platform_request.body_digest.as_str(),
            ))
        }
    }

    #[derive(Default)]
    struct LedgerState {
        entries: BTreeMap<OneShotKey, (String, Option<DeliveryObservation>)>,
        sequence: usize,
    }

    #[derive(Clone, Default)]
    struct DurableLedger {
        state: Arc<Mutex<LedgerState>>,
    }

    impl OneShotLedgerPort for DurableLedger {
        fn reserve(
            &mut self,
            intent: &LedgerIntent,
            _request: &NotificationRequest,
        ) -> LedgerReserveOutcome {
            let mut state = self.state.lock().unwrap();
            if let Some((claim, observation)) = state.entries.get(&intent.one_shot_key) {
                if claim != &intent.claim_digest {
                    return LedgerReserveOutcome::Conflict;
                }
                return observation
                    .clone()
                    .map_or(LedgerReserveOutcome::Conflict, |value| {
                        LedgerReserveOutcome::Replay {
                            observation: Box::new(value),
                        }
                    });
            }
            state.sequence += 1;
            let reservation_id =
                PlatformHandle::new(format!("reservation-{}", state.sequence)).unwrap();
            state.entries.insert(
                intent.one_shot_key.clone(),
                (intent.claim_digest.clone(), None),
            );
            LedgerReserveOutcome::Reserved {
                reservation: LedgerReservation {
                    one_shot_key: intent.one_shot_key.clone(),
                    claim_digest: intent.claim_digest.clone(),
                    reservation_id,
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
            let Some((claim, stored)) = state.entries.get_mut(&reservation.one_shot_key) else {
                return LedgerCommitOutcome::Conflict;
            };
            if claim != &reservation.claim_digest {
                return LedgerCommitOutcome::Conflict;
            }
            if let Some(replay) = stored {
                return LedgerCommitOutcome::Replay {
                    observation: Box::new(replay.clone()),
                };
            }
            *stored = Some(observation.clone());
            LedgerCommitOutcome::Committed
        }
    }

    struct UnavailableLedger;

    impl OneShotLedgerPort for UnavailableLedger {
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

    fn ports(
        ledger: Option<DurableLedger>,
        a08_mode: AdmissionMode,
        delivery_mode: DeliveryReceiptMode,
    ) -> VerificationPorts {
        VerificationPorts {
            a08: Some(Box::new(A08Fake { mode: a08_mode })),
            g08: Some(Box::new(G08Fake { outcome: None })),
            watchdog: None,
            delivery_receipt: Some(Box::new(DeliveryReceiptFake {
                mode: delivery_mode,
            })),
            ledger: ledger.map(|value| Box::new(value) as Box<dyn OneShotLedgerPort>),
        }
    }

    fn known_delivery() -> PortOutcome<NotificationObservation> {
        PortOutcome::Known(NotificationObservation {
            notification: PlatformHandle::new("notification-1").unwrap(),
            delivered: true,
        })
    }

    #[test]
    fn caller_minted_source_and_admission_inputs_are_inert_without_providers() {
        let (envelope, request) = normal_input("request-1");
        let (platform, calls) = counting_platform(known_delivery());
        let mut missing_g08 = ports(
            Some(DurableLedger::default()),
            AdmissionMode::Good,
            DeliveryReceiptMode::Good,
        );
        missing_g08.g08 = None;
        let mut core = NotifyCore::new(platform, missing_g08);
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::PlanGap {
                provider: ProviderId::G08Problem,
                reason: "G-08 verification port is missing",
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let (platform, calls) = counting_platform(known_delivery());
        let mut unknown_g08 = ports(
            Some(DurableLedger::default()),
            AdmissionMode::Good,
            DeliveryReceiptMode::Good,
        );
        unknown_g08.g08 = Some(Box::new(G08Fake {
            outcome: Some(PortOutcome::Unknown(UnknownReason::Indeterminate)),
        }));
        let mut core = NotifyCore::new(platform, unknown_g08);
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::VerificationUnknown {
                provider: ProviderId::G08Problem,
                reason: UnknownReason::Indeterminate,
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let (platform, calls) = counting_platform(known_delivery());
        let mut without_a08 = ports(
            Some(DurableLedger::default()),
            AdmissionMode::Good,
            DeliveryReceiptMode::Good,
        );
        without_a08.a08 = None;
        let mut core = NotifyCore::new(platform, without_a08);
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::PlanGap {
                provider: ProviderId::A08Admission,
                reason: "A-08 admission verification port is missing",
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn typed_recipient_context_scope_fence_and_effect_survive_every_receipt() {
        let (envelope, request) = normal_input("request-typed");
        let (platform, _) = counting_platform(known_delivery());
        let mut core = NotifyCore::new(
            platform,
            ports(
                Some(DurableLedger::default()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Good,
            ),
        );
        let result = core.deliver(&envelope, &request).unwrap();
        assert_eq!(result.recipient, envelope.recipients[0]);
        assert_eq!(result.effect, DeliveryEffect::UserSessionNotification);
        assert_eq!(result.source_receipt.core.request.metadata, request.context);
        assert_eq!(
            result.source_receipt.core.work_scope,
            result.admission_receipt.core.work_scope
        );
        assert_eq!(
            result.admission_receipt.core.work_scope,
            result.delivery_receipt.core.work_scope
        );
        assert_eq!(
            result.source_receipt.core.request.metadata.state_fence,
            result.delivery_receipt.core.operation.state_fence
        );
        assert_eq!(
            result.delivery_receipt.core.operation.effect,
            EffectClass::ExternalEffect
        );
        assert_eq!(
            result.delivery_receipt.core.disposition.kind(),
            ReceiptDispositionKind::Success
        );
        assert!(result.validate().is_ok());
    }

    #[test]
    fn wrong_session_task_fence_effect_disposition_and_proof_fail_closed() {
        for mode in [
            AdmissionMode::WrongSession,
            AdmissionMode::WrongTask,
            AdmissionMode::WrongFence,
            AdmissionMode::WrongEffect,
            AdmissionMode::WrongDisposition,
            AdmissionMode::WrongProof,
        ] {
            let (envelope, request) = normal_input("request-negative");
            let (platform, calls) = counting_platform(known_delivery());
            let mut core = NotifyCore::new(
                platform,
                ports(
                    Some(DurableLedger::default()),
                    mode,
                    DeliveryReceiptMode::Good,
                ),
            );
            assert_eq!(
                core.deliver(&envelope, &request),
                Err(NotifyError::InvalidReceiptBinding)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn durable_restart_replay_and_distinct_request_ids_cannot_bypass_one_shot() {
        let ledger = DurableLedger::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let platform = CountingPort {
            calls: Arc::clone(&calls),
            outcome: known_delivery(),
        };
        let (envelope, request) = normal_input("request-first");
        let mut first = NotifyCore::new(
            platform,
            ports(
                Some(ledger.clone()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Good,
            ),
        );
        let initial = first.deliver(&envelope, &request).unwrap();
        assert!(!initial.deduplicated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let platform = CountingPort {
            calls: Arc::clone(&calls),
            outcome: known_delivery(),
        };
        let mut restarted = NotifyCore::new(
            platform,
            ports(
                Some(ledger.clone()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Good,
            ),
        );
        let replay = restarted.deliver(&envelope, &request).unwrap();
        assert!(replay.deduplicated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (second_envelope, second_request) = normal_input("request-second");
        let platform = CountingPort {
            calls: Arc::clone(&calls),
            outcome: known_delivery(),
        };
        let mut distinct_request = NotifyCore::new(
            platform,
            ports(
                Some(ledger.clone()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Good,
            ),
        );
        let replay = distinct_request
            .deliver(&second_envelope, &second_request)
            .unwrap();
        assert!(replay.deduplicated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut changed_request = make_request("request-third");
        let changed_notification = PlatformHandle::new("notification-1").unwrap();
        let mut changed_value = serde_json::to_value(&changed_request).unwrap();
        changed_value["context"]["state_fence"]["resource_generation"] = json!(2);
        changed_request = serde_json::from_value(changed_value).unwrap();
        let changed_receipt = receipt_for(
            &changed_request,
            G08_OPERATION,
            &source_idempotency(&changed_notification, changed_request.body_digest.as_str()),
            G08_OWNER,
            EffectClass::Read,
            DispositionSpec::Success,
            ProofCeiling::ScopedVerification,
            changed_request.body_digest.as_str(),
        );
        changed_request.canonical_request_hash =
            PlatformHandle::new(changed_receipt.canonical_sha256()).unwrap();
        let changed_envelope = NotificationEnvelope {
            notification_id: changed_notification,
            subject: "Attention required".to_owned(),
            summary: "Inspect canonical evidence".to_owned(),
            recipients: envelope.recipients.clone(),
            source_receipt: changed_receipt,
        };
        let platform = CountingPort {
            calls: Arc::clone(&calls),
            outcome: known_delivery(),
        };
        let mut changed_claim = NotifyCore::new(
            platform,
            ports(Some(ledger), AdmissionMode::Good, DeliveryReceiptMode::Good),
        );
        assert_eq!(
            changed_claim.deliver(&changed_envelope, &changed_request),
            Err(NotifyError::LedgerConflict)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_or_unavailable_ledger_is_plan_gap_before_external_effect() {
        let (envelope, request) = normal_input("request-ledger-gap");
        let (platform, calls) = counting_platform(known_delivery());
        let mut core = NotifyCore::new(
            platform,
            ports(None, AdmissionMode::Good, DeliveryReceiptMode::Good),
        );
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::PlanGap {
                provider: ProviderId::OneShotLedger,
                reason: "durable one-shot ledger port is missing",
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let (platform, calls) = counting_platform(known_delivery());
        let mut unavailable = ports(
            Some(DurableLedger::default()),
            AdmissionMode::Good,
            DeliveryReceiptMode::Good,
        );
        unavailable.ledger = Some(Box::new(UnavailableLedger));
        let mut core = NotifyCore::new(platform, unavailable);
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::PlanGap {
                provider: ProviderId::OneShotLedger,
                reason: "durable one-shot ledger is unavailable",
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn fallback_input() -> (SignedWatchdogFallbackEnvelope, NotificationRequest) {
        let signed = SignedWatchdogFallbackEnvelope {
            envelope: WatchdogFallbackEnvelope {
                incident_class: PlatformHandle::new("CONTROL_PLANE_LOSS").unwrap(),
                installation_identity: PlatformHandle::new("installation-1").unwrap(),
                timestamp_ms: 100,
                evidence_digest: sha256_hex(b"watchdog-evidence"),
                recovery_instruction: RecoveryInstruction::EliotRecoveryStatus,
            },
            algorithm: WATCHDOG_SIGNATURE_ALGORITHM.to_owned(),
            key_id: PlatformHandle::new("watchdog-key-1").unwrap(),
            domain: WATCHDOG_SIGNATURE_DOMAIN.to_owned(),
            signature: "00".repeat(64),
        };
        let mut request = make_request("request-fallback");
        request.body_digest = PlatformHandle::new(signed.envelope.evidence_digest.clone()).unwrap();
        request.canonical_request_hash =
            PlatformHandle::new(watchdog_request_hash(&signed).unwrap()).unwrap();
        request.notification =
            PlatformHandle::new(watchdog_notification_id(&signed).unwrap()).unwrap();
        request.context.request_id =
            serde_json::from_value(json!(watchdog_request_id(&signed).unwrap())).unwrap();
        request.context.product_id = serde_json::from_value(json!(WATCHDOG_PRODUCT_ID)).unwrap();
        request.context.source_id = serde_json::from_value(json!(WATCHDOG_SOURCE_ID)).unwrap();
        request.context.session_id =
            Some(serde_json::from_value(json!(request.audience.as_str())).unwrap());
        request.context.task_id = None;
        request.context.state_fence.resource_generation = serde_json::from_value(json!(1)).unwrap();
        request.context.state_fence.task_revision = None;
        request.context.state_fence.policy_revision = None;
        request.context.state_fence.integration_revision = None;
        (signed, request)
    }

    fn fallback_ports(ledger: DurableLedger, expected_signature: String) -> VerificationPorts {
        VerificationPorts {
            a08: Some(Box::new(A08Fake {
                mode: AdmissionMode::Good,
            })),
            g08: None,
            watchdog: Some(Box::new(WatchdogFake { expected_signature })),
            delivery_receipt: Some(Box::new(DeliveryReceiptFake {
                mode: DeliveryReceiptMode::Good,
            })),
            ledger: Some(Box::new(ledger)),
        }
    }

    #[test]
    fn fallback_payload_is_minimal_and_signature_verification_is_injected() {
        let (signed, request) = fallback_input();
        let payload = serde_json::to_value(&signed.envelope).unwrap();
        let keys: Vec<_> = payload.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "evidence_digest",
                "incident_class",
                "installation_identity",
                "recovery_instruction",
                "timestamp_ms",
            ]
        );
        for forbidden in ["subject", "summary", "project", "secret", "problem_id"] {
            assert!(payload.get(forbidden).is_none());
        }

        let (platform, calls) = counting_platform(PortOutcome::Known(NotificationObservation {
            notification: request.notification.clone(),
            delivered: true,
        }));
        let mut bad = signed.clone();
        bad.signature = "11".repeat(64);
        let expected = signed.signature.clone();
        let mut core = NotifyCore::new(
            platform,
            fallback_ports(DurableLedger::default(), expected.clone()),
        );
        let mut bad_request = request.clone();
        bad_request.canonical_request_hash =
            PlatformHandle::new(watchdog_request_hash(&bad).unwrap()).unwrap();
        bad_request.context.request_id =
            serde_json::from_value(json!(watchdog_request_id(&bad).unwrap())).unwrap();
        assert_eq!(
            core.deliver_watchdog_fallback(&bad, &bad_request),
            Err(NotifyError::ProviderFailure {
                provider: ProviderId::WatchdogSignature,
                code: ProviderErrorCode::InvalidRequest,
                retryable: false,
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let (platform, calls) = counting_platform(PortOutcome::Known(NotificationObservation {
            notification: request.notification.clone(),
            delivered: true,
        }));
        let mut core =
            NotifyCore::new(platform, fallback_ports(DurableLedger::default(), expected));
        let result = core.deliver_watchdog_fallback(&signed, &request).unwrap();
        assert_eq!(result.source_kind, DeliverySourceKind::WatchdogFallback);
        assert_eq!(result.route, DeliveryRoute::Fallback);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn p01_errors_preserve_every_code_and_retryability() {
        for (index, code) in [
            ProviderErrorCode::Unavailable,
            ProviderErrorCode::PermissionDenied,
            ProviderErrorCode::InvalidRequest,
            ProviderErrorCode::Timeout,
            ProviderErrorCode::Failed,
        ]
        .into_iter()
        .enumerate()
        {
            let retryable = index % 2 == 0;
            let (envelope, request) = normal_input(&format!("request-error-{index}"));
            let (platform, _) =
                counting_platform(PortOutcome::Error(PortError::Provider(ProviderError {
                    code,
                    retryable,
                })));
            let mut core = NotifyCore::new(
                platform,
                ports(
                    Some(DurableLedger::default()),
                    AdmissionMode::Good,
                    DeliveryReceiptMode::Good,
                ),
            );
            assert_eq!(
                core.deliver(&envelope, &request),
                Err(NotifyError::ProviderFailure {
                    provider: ProviderId::P01Platform,
                    code,
                    retryable,
                })
            );
        }

        let (envelope, request) = normal_input("request-unknown");
        let (platform, _) = counting_platform(PortOutcome::Unknown(UnknownReason::NotObserved));
        let mut core = NotifyCore::new(
            platform,
            ports(
                Some(DurableLedger::default()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Good,
            ),
        );
        let result = core.deliver(&envelope, &request).unwrap();
        assert_eq!(result.confidence, DeliveryConfidence::Unknown);
        assert_eq!(result.delivered, None);
        assert_eq!(
            result.delivery_receipt.core.disposition.kind(),
            ReceiptDispositionKind::Unknown
        );
    }

    #[test]
    fn delivery_receipt_cannot_overclaim_disposition_or_fake_positive_proof() {
        let (envelope, request) = normal_input("request-overclaim");
        let (platform, _) = counting_platform(PortOutcome::Known(NotificationObservation {
            notification: envelope.notification_id.clone(),
            delivered: false,
        }));
        let mut core = NotifyCore::new(
            platform,
            ports(
                Some(DurableLedger::default()),
                AdmissionMode::Good,
                DeliveryReceiptMode::ForceSuccess,
            ),
        );
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::InvalidReceiptBinding)
        );

        let (envelope, request) = normal_input("request-underproof");
        let (platform, _) = counting_platform(known_delivery());
        let mut core = NotifyCore::new(
            platform,
            ports(
                Some(DurableLedger::default()),
                AdmissionMode::Good,
                DeliveryReceiptMode::Underproof,
            ),
        );
        assert_eq!(
            core.deliver(&envelope, &request),
            Err(NotifyError::InvalidReceiptBinding)
        );
    }
}
