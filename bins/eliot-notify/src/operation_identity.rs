//! Per-step Kernel request identity for the notification process.
//!
//! Architecture anchors: I5.5 write envelope (one logical transition owns one
//! identity; the same key with different bytes conflicts), I7.4 lifecycle
//! (every request owns idempotency, deadline and cancellation), A12.2
//! principal/session binding, A13.2 Kernel failure domains. Implementation
//! anchors: I1.3 notification adapter (this process is the P-01/A-10 adapter
//! binding), I5.27 canonical operation identity pattern, #74 user-broker
//! per-operation issuer.
//!
//! One stable parent [`NotificationRequest`] owns the user-visible delivery
//! intent. Every `eliot.notify.*` Kernel transaction owns a fresh versioned
//! child [`RequestIdentity`] bound to the parent hash, the exact operation
//! selector, the canonical payload digest, the parent State Fence, the
//! step effect ceiling, a fresh absolute deadline, per-step cancellation
//! isolation, and the prior receipt digest where the step consumes one.
//! Exact retry of one child reuses its identity; another step or changed
//! payload cannot reuse its idempotency key and fails with
//! [`OperationIdentityError::IdentityConflict`] before any Kernel effect,
//! mirroring I5.5 `identity conflict` and the Kernel `IDENTITY_CONFLICT`
//! disposition.
//!
//! Digest ownership: this module mints no hash. Payload digests reuse the
//! shared workspace helpers [`eliot_contracts::canonical_json_bytes`] plus
//! [`eliot_contracts::sha256_hex`] — the exact helpers owned by the shared
//! executable-request digest in
//! `crates/storage/eliot-store-api/src/request_hash.rs` (issue #63). Every
//! minted identity is constructed and validated through the owning
//! [`RequestIdentity`] validator in `eliot-protocol`; no shape is trusted
//! without that typed validation. Lineage links related operations without
//! collapsing them into one request (issue #64 pattern).
//!
//! This issuer never mints Kernel authority: the fence it carries is the
//! parent notification fence observed from the admitted request. Kernel-side
//! rejection of cross-operation reuse belongs to the Kernel owner in
//! `bins/eliot-kernel/src/notify_operation_identity.rs`; this module provides
//! the full notify side plus local fail-closed guards.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_platform::NotificationRequest;
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use serde_json::Value;

/// Version tag bound into every derived child identity.
pub const NOTIFY_IDENTITY_VERSION: &str = "v1";
/// Fresh absolute transport deadline horizon per child step, in milliseconds.
pub const OPERATION_IDENTITY_TTL_MS: u64 = 30_000;
/// Maximum parent clock skew into the future, in milliseconds.
const MAX_CLOCK_SKEW_MS: u64 = 5_000;
/// Maximum parent clock age, in milliseconds.
const MAX_CLOCK_AGE_MS: u64 = 60_000;

/// Closed notify operation vocabulary for child identity issuance.
///
/// Selectors match the provider bundle in `super::KERNEL_VERIFICATION_OPERATIONS`.
/// Each step owns a fixed effect ceiling: verification steps observe (`READ`);
/// admission, delivery verification and ledger steps decide durable or
/// externally visible outcomes (`EXTERNAL_EFFECT`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NotifyOperation {
    /// `eliot.notify.g08.verify` — G-08 source verification (`READ`).
    G08Verify,
    /// `eliot.notify.a08.admit` — A-08 admission (`EXTERNAL_EFFECT`).
    A08Admit,
    /// `eliot.notify.watchdog.verify` — Watchdog signature verification (`READ`).
    WatchdogVerify,
    /// `eliot.notify.delivery.verify` — delivery receipt verification (`EXTERNAL_EFFECT`).
    DeliveryVerify,
    /// `eliot.notify.ledger.reserve` — one-shot ledger reservation (durable, `EXTERNAL_EFFECT` ceiling).
    LedgerReserve,
    /// `eliot.notify.ledger.commit` — one-shot ledger commit (durable, `EXTERNAL_EFFECT` ceiling).
    LedgerCommit,
}

impl NotifyOperation {
    /// Returns the exact Kernel operation selector for this step.
    #[must_use]
    pub const fn selector(self) -> &'static str {
        match self {
            Self::G08Verify => "eliot.notify.g08.verify",
            Self::A08Admit => "eliot.notify.a08.admit",
            Self::WatchdogVerify => "eliot.notify.watchdog.verify",
            Self::DeliveryVerify => "eliot.notify.delivery.verify",
            Self::LedgerReserve => "eliot.notify.ledger.reserve",
            Self::LedgerCommit => "eliot.notify.ledger.commit",
        }
    }

    /// Returns the short idempotency-namespace tag for this step.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::G08Verify => "g08-verify",
            Self::A08Admit => "a08-admit",
            Self::WatchdogVerify => "watchdog-verify",
            Self::DeliveryVerify => "delivery-verify",
            Self::LedgerReserve => "ledger-reserve",
            Self::LedgerCommit => "ledger-commit",
        }
    }

    /// Returns the fixed effect ceiling bound into this step's lineage.
    #[must_use]
    pub const fn effect_ceiling(self) -> &'static str {
        match self {
            Self::G08Verify | Self::WatchdogVerify => "READ",
            Self::A08Admit
            | Self::DeliveryVerify
            | Self::LedgerReserve
            | Self::LedgerCommit => "EXTERNAL_EFFECT",
        }
    }

    /// All six closed steps in pipeline order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::G08Verify,
            Self::A08Admit,
            Self::WatchdogVerify,
            Self::DeliveryVerify,
            Self::LedgerReserve,
            Self::LedgerCommit,
        ]
    }
}

/// One freshly issued (or exactly retried) child identity.
#[derive(Clone, Debug)]
pub struct IssuedIdentity {
    /// Exact transport identity to install for this single Kernel call.
    pub identity: RequestIdentity,
    /// Step kind that owns this identity.
    pub operation: NotifyOperation,
    /// Lowercase SHA-256 of the canonical payload bytes.
    pub canonical_digest: String,
    /// Text of the derived child request id.
    pub request_id: String,
    /// Stable parent notification request id.
    pub parent_request_id: String,
    /// Stable parent canonical request hash.
    pub parent_hash: String,
}

/// Lineage from one parent notification intent to one child step identity.
///
/// Recorded, never collapsed: the parent intent, the child transport identity
/// and the consumed prior receipt keep distinct identities linked by explicit
/// parent references (issue #64 pattern).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildLineageEntry {
    /// Stable parent notification request id.
    pub parent_request_id: String,
    /// Stable parent canonical request hash.
    pub parent_hash: String,
    /// Derived child transport request id.
    pub child_request_id: String,
    /// Exact Kernel operation selector for this step.
    pub operation: String,
    /// Canonical digest of the exact child payload.
    pub canonical_digest: String,
    /// Transport idempotency key minted for this child.
    pub idempotency_key: String,
    /// Per-step cancellation identity.
    pub cancellation_id: String,
    /// Prior receipt digest consumed by this step, when applicable.
    pub prior_receipt_digest: Option<String>,
}

/// Typed fail-closed issuance failures. No stub or default identity exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationIdentityError {
    /// Parent notification request is missing or malformed.
    InvalidParent(String),
    /// Wall-clock observation is missing or overflows the deadline horizon.
    InvalidClock,
    /// Canonical payload encoding failed.
    Encoding(String),
    /// A minted child identity failed its own validation.
    InvalidIdentity(String),
    /// An idempotency key is already bound to different canonical bytes
    /// (or a different step). No Kernel call was made. Mirrors the Kernel
    /// `IDENTITY_CONFLICT` disposition.
    IdentityConflict(String),
}

impl fmt::Display for OperationIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParent(detail) => write!(f, "parent notification request is invalid: {detail}"),
            Self::InvalidClock => write!(f, "operation clock observation is invalid"),
            Self::Encoding(detail) => write!(f, "operation payload encoding failed: {detail}"),
            Self::InvalidIdentity(detail) => write!(f, "minted child identity is invalid: {detail}"),
            Self::IdentityConflict(detail) => write!(f, "idempotency identity conflict: {detail}"),
        }
    }
}

impl std::error::Error for OperationIdentityError {}

/// Ledger key: one parent hash plus one exact operation selector plus one
/// canonical payload digest plus one prior receipt digest.
type LedgerKey = (String, String, String, String);

#[derive(Clone, Debug)]
struct LedgerEntry {
    identity: RequestIdentity,
    request_id: String,
    parent_request_id: String,
    parent_hash: String,
}

/// Issues fresh per-step child [`RequestIdentity`] values with exact-retry and
/// identity-conflict semantics. All state is notify-process-local: a restart
/// starts from an empty ledger. Deterministic derivation binds the same
/// parent plus step plus payload to the same byte-level identity, so a
/// crash after reserve, provider delivery, delivery verification or commit
/// reconciles at the exact step by re-deriving and replaying that step only.
pub struct NotifyIdentityIssuer {
    ledger: BTreeMap<LedgerKey, LedgerEntry>,
    by_idempotency: BTreeMap<String, LedgerKey>,
    by_request: BTreeMap<String, LedgerKey>,
    by_cancellation: BTreeMap<String, LedgerKey>,
    lineage: Vec<ChildLineageEntry>,
}

/// Shared issuer handle between the composition and its Kernel ports.
pub type IssuerHandle = Arc<Mutex<NotifyIdentityIssuer>>;

impl NotifyIdentityIssuer {
    /// Creates an empty issuer. Parent binding arrives per call from the
    /// admitted notification request; no ambient identity is retained.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ledger: BTreeMap::new(),
            by_idempotency: BTreeMap::new(),
            by_request: BTreeMap::new(),
            by_cancellation: BTreeMap::new(),
            lineage: Vec::new(),
        }
    }

    /// Returns the number of distinct child identities issued.
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.ledger.len()
    }

    /// Returns the parent-to-child lineage log.
    #[must_use]
    pub fn lineage(&self) -> &[ChildLineageEntry] {
        &self.lineage
    }

    /// Issues (or exactly retries) the G-08 source-verification child.
    pub fn issue_g08(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(parent, NotifyOperation::G08Verify, payload, None, now_unix_ms)
    }

    /// Issues (or exactly retries) the A-08 admission child. The prior
    /// digest should be the canonical SHA-256 of the verified source receipt.
    pub fn issue_a08(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        prior_source_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            parent,
            NotifyOperation::A08Admit,
            payload,
            prior_source_digest,
            now_unix_ms,
        )
    }

    /// Issues (or exactly retries) the Watchdog verification child.
    pub fn issue_watchdog(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(parent, NotifyOperation::WatchdogVerify, payload, None, now_unix_ms)
    }

    /// Issues (or exactly retries) the delivery-verification child. The prior
    /// digest should bind the admission receipt.
    pub fn issue_delivery(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        prior_admission_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            parent,
            NotifyOperation::DeliveryVerify,
            payload,
            prior_admission_digest,
            now_unix_ms,
        )
    }

    /// Issues (or exactly retries) the ledger-reservation child. The prior
    /// digest should bind the admission receipt.
    pub fn issue_reserve(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        prior_admission_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            parent,
            NotifyOperation::LedgerReserve,
            payload,
            prior_admission_digest,
            now_unix_ms,
        )
    }

    /// Issues (or exactly retries) the ledger-commit child. The prior digest
    /// should bind the reservation or the verified delivery observation.
    /// Reserve and commit are separate operations tied by the reservation
    /// claim; reserve success is never commit success.
    pub fn issue_commit(
        &mut self,
        parent: &NotificationRequest,
        payload: &Value,
        prior_reservation_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            parent,
            NotifyOperation::LedgerCommit,
            payload,
            prior_reservation_digest,
            now_unix_ms,
        )
    }

    /// Issues with an explicit transport idempotency key. A key already bound
    /// to different canonical bytes (or a different step) fails with identity
    /// conflict; the same key with identical bytes returns the exact prior
    /// identity. This is the single issuance funnel for conflict tests.
    pub fn issue_with_idempotency_key(
        &mut self,
        parent: &NotificationRequest,
        operation: NotifyOperation,
        payload: &Value,
        idempotency_key: &str,
        prior_receipt_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        if idempotency_key.trim().is_empty()
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(OperationIdentityError::InvalidParent(
                "idempotency_key".to_owned(),
            ));
        }
        validate_parent(parent, now_unix_ms)?;
        let canonical_digest = canonical_digest_of(payload)?;
        let parent_hash = parent.canonical_request_hash.as_str().to_owned();
        let parent_request_id = parent.context.request_id.as_str().to_owned();
        let prior = normalize_prior(prior_receipt_digest)?;
        let key = ledger_key(
            &parent_hash,
            operation,
            &canonical_digest,
            prior.as_deref(),
        );
        if let Some(entry) = self.ledger.get(&key) {
            if self
                .by_idempotency
                .get(idempotency_key)
                .is_some_and(|owner| owner != &key)
            {
                return Err(OperationIdentityError::IdentityConflict(format!(
                    "idempotency key is already bound to {} with different canonical bytes",
                    self.by_idempotency[idempotency_key].1
                )));
            }
            return Ok(IssuedIdentity {
                identity: entry.identity.clone(),
                operation,
                canonical_digest,
                request_id: entry.request_id.clone(),
                parent_request_id: entry.parent_request_id.clone(),
                parent_hash: entry.parent_hash.clone(),
            });
        }
        if let Some(owner) = self.by_idempotency.get(idempotency_key)
            && owner != &key
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "idempotency key is already bound to {} with different canonical bytes",
                owner.1
            )));
        }
        self.mint(
            &key,
            parent,
            &parent_hash,
            &parent_request_id,
            operation,
            &canonical_digest,
            idempotency_key,
            prior,
            now_unix_ms,
        )
    }

    fn issue(
        &mut self,
        parent: &NotificationRequest,
        operation: NotifyOperation,
        payload: &Value,
        prior_receipt_digest: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        validate_parent(parent, now_unix_ms)?;
        let canonical_digest = canonical_digest_of(payload)?;
        let parent_hash = parent.canonical_request_hash.as_str().to_owned();
        let idempotency_key = derive_idempotency_key(&parent_hash, operation, &canonical_digest);
        self.issue_with_idempotency_key(
            parent,
            operation,
            payload,
            &idempotency_key,
            prior_receipt_digest,
            now_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mint(
        &mut self,
        key: &LedgerKey,
        parent: &NotificationRequest,
        parent_hash: &str,
        parent_request_id: &str,
        operation: NotifyOperation,
        canonical_digest: &str,
        idempotency_key: &str,
        prior: Option<String>,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        if now_unix_ms == 0 {
            return Err(OperationIdentityError::InvalidClock);
        }
        let deadline_unix_ms = now_unix_ms
            .checked_add(OPERATION_IDENTITY_TTL_MS)
            .filter(|deadline| *deadline > now_unix_ms)
            .ok_or(OperationIdentityError::InvalidClock)?;
        let (child_request_id, cancellation_id) =
            derive_transport_ids(parent_hash, operation, canonical_digest, prior.as_deref());
        if let Some(owner) = self
            .by_request
            .get(&child_request_id)
            .or_else(|| self.by_cancellation.get(&cancellation_id))
            && owner != key
        {
            // Deterministic derivation collided with a different ledger key:
            // fail closed rather than reusing another step's lifecycle.
            return Err(OperationIdentityError::IdentityConflict(format!(
                "derived transport identity is already bound to {} with different canonical bytes",
                owner.1
            )));
        }
        let identity = build_identity(
            parent,
            &child_request_id,
            idempotency_key,
            deadline_unix_ms,
            &cancellation_id,
            now_unix_ms,
        )?;
        self.by_idempotency
            .insert(idempotency_key.to_owned(), key.clone());
        self.by_request
            .insert(child_request_id.clone(), key.clone());
        self.by_cancellation
            .insert(cancellation_id.clone(), key.clone());
        self.ledger.insert(
            key.clone(),
            LedgerEntry {
                identity: identity.clone(),
                request_id: child_request_id.clone(),
                parent_request_id: parent_request_id.to_owned(),
                parent_hash: parent_hash.to_owned(),
            },
        );
        self.lineage.push(ChildLineageEntry {
            parent_request_id: parent_request_id.to_owned(),
            parent_hash: parent_hash.to_owned(),
            child_request_id: child_request_id.clone(),
            operation: operation.selector().to_owned(),
            canonical_digest: canonical_digest.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            cancellation_id,
            prior_receipt_digest: prior,
        });
        Ok(IssuedIdentity {
            identity,
            operation,
            canonical_digest: canonical_digest.to_owned(),
            request_id: child_request_id,
            parent_request_id: parent_request_id.to_owned(),
            parent_hash: parent_hash.to_owned(),
        })
    }
}

impl Default for NotifyIdentityIssuer {
    fn default() -> Self {
        Self::new()
    }
}

fn ledger_key(
    parent_hash: &str,
    operation: NotifyOperation,
    canonical_digest: &str,
    prior: Option<&str>,
) -> LedgerKey {
    (
        parent_hash.to_owned(),
        operation.selector().to_owned(),
        canonical_digest.to_owned(),
        prior.unwrap_or_default().to_owned(),
    )
}

fn normalize_prior(
    prior: Option<&str>,
) -> Result<Option<String>, OperationIdentityError> {
    match prior {
        None => Ok(None),
        Some(digest) => {
            if digest.trim().is_empty() || digest.chars().any(char::is_control) {
                return Err(OperationIdentityError::InvalidParent(
                    "prior_receipt_digest".to_owned(),
                ));
            }
            Ok(Some(digest.to_owned()))
        }
    }
}

/// Computes the lowercase SHA-256 of the canonical payload bytes using the
/// shared workspace helpers owned by the #63 request digest. No
/// notify-specific hash exists.
fn canonical_digest_of(payload: &Value) -> Result<String, OperationIdentityError> {
    let bytes = canonical_json_bytes(payload)
        .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn derive_idempotency_key(
    parent_hash: &str,
    operation: NotifyOperation,
    canonical_digest: &str,
) -> String {
    format!(
        "notify-{}-{}/{}-{}",
        NOTIFY_IDENTITY_VERSION,
        operation.namespace(),
        parent_hash,
        canonical_digest
    )
}

fn derive_transport_ids(
    parent_hash: &str,
    operation: NotifyOperation,
    canonical_digest: &str,
    prior: Option<&str>,
) -> (String, String) {
    let seed = format!(
        "{}|{}|{}|{}|{}|{}",
        NOTIFY_IDENTITY_VERSION,
        parent_hash,
        operation.selector(),
        canonical_digest,
        prior.unwrap_or(""),
        operation.effect_ceiling()
    );
    let request_seed = format!("req|{seed}");
    let cancel_seed = format!("cancel|{seed}");
    let request_id = format!(
        "notify-{}-{}-{}",
        NOTIFY_IDENTITY_VERSION,
        operation.namespace(),
        sha256_hex(request_seed.as_bytes())
    );
    let cancellation_id = format!(
        "notify-cancel-{}-{}-{}",
        NOTIFY_IDENTITY_VERSION,
        operation.namespace(),
        sha256_hex(cancel_seed.as_bytes())
    );
    (request_id, cancellation_id)
}

fn validate_parent(
    parent: &NotificationRequest,
    now_unix_ms: u64,
) -> Result<(), OperationIdentityError> {
    if now_unix_ms == 0 {
        return Err(OperationIdentityError::InvalidClock);
    }
    parent
        .validate()
        .map_err(|error| OperationIdentityError::InvalidParent(error.to_string()))?;
    if parent.canonical_request_hash.as_str().trim().is_empty() {
        return Err(OperationIdentityError::InvalidParent(
            "canonical_request_hash".to_owned(),
        ));
    }
    let now_i64 = i64::try_from(now_unix_ms).map_err(|_| OperationIdentityError::InvalidClock)?;
    for observed in [
        parent.context.clock.valid_time_ms,
        parent.context.clock.known_time_ms,
    ]
    .into_iter()
    .flatten()
    {
        if observed < 0 {
            return Err(OperationIdentityError::InvalidParent(
                "negative clock observation".to_owned(),
            ));
        }
        let observed_u64 = u64::try_from(observed)
            .map_err(|_| OperationIdentityError::InvalidParent("clock range".to_owned()))?;
        if observed_u64 > now_unix_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || now_unix_ms.saturating_sub(observed_u64) > MAX_CLOCK_AGE_MS
        {
            return Err(OperationIdentityError::InvalidParent(
                "stale or future clock observation".to_owned(),
            ));
        }
    }
    let _ = now_i64;
    Ok(())
}

fn build_identity(
    parent: &NotificationRequest,
    child_request_id: &str,
    idempotency_key: &str,
    deadline_unix_ms: u64,
    cancellation_id: &str,
    now_unix_ms: u64,
) -> Result<RequestIdentity, OperationIdentityError> {
    use eliot_contracts::RequestId;

    let now_i64 =
        i64::try_from(now_unix_ms).map_err(|_| OperationIdentityError::InvalidClock)?;
    let child_id = RequestId::new(child_request_id)
        .map_err(|error| OperationIdentityError::InvalidIdentity(error.to_string()))?;
    let mut metadata = parent.context.clone();
    metadata.request_id = child_id;
    metadata.clock.valid_time_ms = Some(now_i64);
    metadata.clock.known_time_ms = Some(now_i64);
    let fence = metadata.state_fence.clone();
    let identity = RequestIdentity {
        request: RequestBinding {
            state_fence: fence,
            metadata,
        },
        idempotency_key: idempotency_key.to_owned(),
        deadline_unix_ms,
        cancellation_id: cancellation_id.to_owned(),
    };
    identity
        .validate()
        .map_err(|error| OperationIdentityError::InvalidIdentity(error.to_string()))?;
    Ok(identity)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_platform::PlatformHandle;
    use serde_json::json;
    use std::num::NonZeroU64;

    const NOW: u64 = 1_786_000_000_000;
    const PARENT_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_fence() -> StateFence {
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        let epoch =
            EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn parent(id: &str) -> NotificationRequest {
        let now_i64 = i64::try_from(NOW).expect("now fits");
        NotificationRequest {
            context: RequestMetadata {
                request_id: RequestId::new(id).expect("request id"),
                session_id: None,
                task_id: None,
                product_id: ProductId::new("notify-test-product").expect("product"),
                source_id: SourceId::new("notify-test-source").expect("source"),
                state_fence: test_fence(),
                clock: ClockReading {
                    valid_time_ms: Some(now_i64),
                    known_time_ms: Some(now_i64),
                    ..ClockReading::default()
                },
            },
            canonical_request_hash: PlatformHandle::new(PARENT_HASH).expect("hash"),
            notification: PlatformHandle::new("notification-1").expect("notification"),
            audience: PlatformHandle::new("audience-1").expect("audience"),
            body_digest: PlatformHandle::new(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .expect("body"),
        }
    }

    fn payload(marker: &str) -> Value {
        json!({"step": marker, "nonce": marker})
    }

    #[test]
    fn six_steps_carry_distinct_versioned_children() {
        let mut issuer = NotifyIdentityIssuer::new();
        let p = parent("parent-1");
        let g08 = issuer.issue_g08(&p, &payload("g08"), NOW).expect("g08");
        let a08 = issuer
            .issue_a08(&p, &payload("a08"), Some("source-digest"), NOW)
            .expect("a08");
        let watchdog = issuer
            .issue_watchdog(&p, &payload("watchdog"), NOW)
            .expect("watchdog");
        let delivery = issuer
            .issue_delivery(&p, &payload("delivery"), Some("admission-digest"), NOW)
            .expect("delivery");
        let reserve = issuer
            .issue_reserve(&p, &payload("reserve"), Some("admission-digest"), NOW)
            .expect("reserve");
        let commit = issuer
            .issue_commit(&p, &payload("commit"), Some("reservation-digest"), NOW)
            .expect("commit");

        let ids = [
            g08.request_id.as_str(),
            a08.request_id.as_str(),
            watchdog.request_id.as_str(),
            delivery.request_id.as_str(),
            reserve.request_id.as_str(),
            commit.request_id.as_str(),
        ];
        let mut distinct = ids.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 6, "every step owns a distinct child");

        let keys = [
            g08.identity.idempotency_key.as_str(),
            a08.identity.idempotency_key.as_str(),
            watchdog.identity.idempotency_key.as_str(),
            delivery.identity.idempotency_key.as_str(),
            reserve.identity.idempotency_key.as_str(),
            commit.identity.idempotency_key.as_str(),
        ];
        let mut distinct_keys = keys.to_vec();
        distinct_keys.sort_unstable();
        distinct_keys.dedup();
        assert_eq!(distinct_keys.len(), 6);

        let cancels = [
            g08.identity.cancellation_id.as_str(),
            a08.identity.cancellation_id.as_str(),
            watchdog.identity.cancellation_id.as_str(),
            delivery.identity.cancellation_id.as_str(),
            reserve.identity.cancellation_id.as_str(),
            commit.identity.cancellation_id.as_str(),
        ];
        let mut distinct_cancels = cancels.to_vec();
        distinct_cancels.sort_unstable();
        distinct_cancels.dedup();
        assert_eq!(distinct_cancels.len(), 6);

        for issued in [&g08, &a08, &delivery, &reserve, &commit] {
            issued.identity.validate().expect("child validates");
            assert_eq!(issued.parent_hash, PARENT_HASH);
            assert_eq!(issued.parent_request_id, "parent-1");
        }
        assert_ne!(reserve.request_id, commit.request_id);
        assert_eq!(issuer.issued_count(), 6);
        assert_eq!(issuer.lineage().len(), 6);
    }

    #[test]
    fn exact_retry_reuses_the_child_identity() {
        let mut issuer = NotifyIdentityIssuer::new();
        let p = parent("parent-retry");
        let first = issuer.issue_g08(&p, &payload("same"), NOW).expect("first");
        let second = issuer
            .issue_g08(&p, &payload("same"), NOW + 500)
            .expect("retry");
        assert_eq!(first.request_id, second.request_id);
        assert_eq!(
            first.identity.idempotency_key,
            second.identity.idempotency_key
        );
        assert_eq!(
            first.identity.cancellation_id,
            second.identity.cancellation_id
        );
        assert_eq!(
            first.identity.deadline_unix_ms,
            second.identity.deadline_unix_ms
        );
    }

    #[test]
    fn cross_step_reuse_conflicts() {
        let mut issuer = NotifyIdentityIssuer::new();
        let p = parent("parent-conflict");
        let g08 = issuer.issue_g08(&p, &payload("g08"), NOW).expect("g08");
        let foreign = g08.identity.idempotency_key.clone();
        let conflict = issuer.issue_with_idempotency_key(
            &p,
            NotifyOperation::LedgerReserve,
            &payload("reserve-other"),
            &foreign,
            None,
            NOW,
        );
        assert!(
            matches!(
                conflict,
                Err(OperationIdentityError::IdentityConflict(_))
            ),
            "cross-step reuse must conflict, got {conflict:?}"
        );
        assert_eq!(issuer.issued_count(), 1);
    }
}
