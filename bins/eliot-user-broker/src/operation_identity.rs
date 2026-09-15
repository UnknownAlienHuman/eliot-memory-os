//! Per-operation Kernel request identity for the A-09 user broker.
//!
//! Architecture anchors: I5.27 canonical operation/effect identity, I6.10
//! authority records (typed epoch lineage, never a scalar epoch), I7.2 frame
//! correlation, I7.3 handshake binding. Implementation anchor: I1.3 broker
//! authentication by installation/SID/session/launch-nonce.
//!
//! A protected launch binding authenticates one stable broker
//! caller/generation. Every `eliot.user-broker.*` Kernel transaction owns a
//! fresh exact [`RequestIdentity`] bound to the operation selector, the
//! canonical payload bytes, the stable binding digest, the current
//! registration/epoch fence, a fresh absolute deadline, and an idempotency
//! rule. Exact retry of one revision reuses its identity; the next revision
//! mints a new one. Reusing an idempotency key for different canonical bytes
//! fails with [`OperationIdentityError::IdentityConflict`] before any Kernel
//! effect, mirroring I5.27 `IDENTITY_CONFLICT`.
//!
//! This issuer never mints Kernel authority: the fence it carries is the
//! installation epoch binding observed from the protected launch declaration
//! and refreshed only from Kernel-issued registration receipts. Scalar
//! authority fields are never copied here (T6-E4 / issue #64 own the epoch
//! migration). Kernel-side rejection of cross-operation reuse belongs to the
//! Kernel owner; this module provides the full broker side plus local
//! fail-closed guards.
//!
//! Dependency note: `Cargo.lock` is owned outside this broker scope, so this
//! module names no foundation contract types directly. Fences and epochs
//! travel as exact JSON values and every minted identity is constructed and
//! validated through the owning [`RequestIdentity`] validator in
//! `eliot-protocol`; no shape is trusted without that typed validation.
//!
//! Launch lineage is recorded, never collapsed: the caller launch request,
//! the authorize-launch transport identity, the Kernel grant, and the
//! process/effect invocation keep distinct identities linked by explicit
//! parent references.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_protocol::RequestIdentity;
use serde_json::Value;
use thiserror::Error;

/// Canonical Kernel operation selectors issued through this broker.
pub(crate) const REGISTER_OPERATION: &str = "eliot.user-broker.register";
/// Canonical Kernel operation selectors issued through this broker.
pub(crate) const HEARTBEAT_OPERATION: &str = "eliot.user-broker.heartbeat";
/// Canonical Kernel operation selectors issued through this broker.
pub(crate) const AUTHORIZE_LAUNCH_OPERATION: &str = "eliot.user-broker.authorize-launch";
/// Canonical Kernel operation selectors issued through this broker.
pub(crate) const FENCE_OPERATION: &str = "eliot.user-broker.fence";

/// Stable broker product/source binding carried by every minted identity.
const BROKER_PRODUCT_ID: &str = "eliot-user-broker";
/// Stable broker product/source binding carried by every minted identity.
const BROKER_SOURCE_ID: &str = "user-broker-transport";

/// Fresh absolute transport deadline horizon per operation, in milliseconds.
pub(crate) const OPERATION_IDENTITY_TTL_MS: u64 = 30_000;

/// Bounded regeneration attempts for a colliding random identity field.
const IDENTITY_REGENERATION_LIMIT: usize = 3;

/// Closed broker operation vocabulary for identity issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) enum BrokerOperation {
    Register,
    HeartbeatRenewal,
    AuthorizeLaunch,
    FenceLogoff,
}

impl BrokerOperation {
    /// Returns the exact Kernel operation selector for this operation kind.
    #[must_use]
    pub(crate) fn selector(self) -> &'static str {
        match self {
            Self::Register => REGISTER_OPERATION,
            Self::HeartbeatRenewal => HEARTBEAT_OPERATION,
            Self::AuthorizeLaunch => AUTHORIZE_LAUNCH_OPERATION,
            Self::FenceLogoff => FENCE_OPERATION,
        }
    }

    /// Returns the short idempotency-namespace tag for this operation kind.
    fn namespace(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::HeartbeatRenewal => "heartbeat",
            Self::AuthorizeLaunch => "authorize-launch",
            Self::FenceLogoff => "fence",
        }
    }
}

/// Caller-side lineage link for one issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CallerLink {
    /// Caller request identity (e.g. `ApprovedLaunch.request_id`).
    pub(crate) caller_request_id: Option<String>,
    /// Caller idempotency key guarded against cross-payload reuse.
    pub(crate) caller_idempotency_key: Option<String>,
}

impl CallerLink {
    /// No caller linkage (register, heartbeat, fence transport identities).
    #[must_use]
    pub(crate) fn none() -> Self {
        Self {
            caller_request_id: None,
            caller_idempotency_key: None,
        }
    }

    /// Launch caller linkage; both fields are required for the guard.
    pub(crate) fn launch(
        caller_request_id: String,
        caller_idempotency_key: String,
    ) -> Result<Self, OperationIdentityError> {
        if caller_request_id.trim().is_empty() || caller_request_id.chars().any(char::is_control) {
            return Err(OperationIdentityError::InvalidCallerBinding(
                "caller_request_id",
            ));
        }
        if caller_idempotency_key.trim().is_empty()
            || caller_idempotency_key.chars().any(char::is_control)
        {
            return Err(OperationIdentityError::InvalidCallerBinding(
                "caller_idempotency_key",
            ));
        }
        Ok(Self {
            caller_request_id: Some(caller_request_id),
            caller_idempotency_key: Some(caller_idempotency_key),
        })
    }
}

/// One freshly issued (or exactly retried) operation identity.
#[derive(Clone, Debug)]
pub(crate) struct IssuedIdentity {
    /// Exact transport identity to install for this single Kernel call.
    pub(crate) identity: RequestIdentity,
    /// Operation kind that owns this identity.
    pub(crate) operation: BrokerOperation,
    /// Lowercase SHA-256 of the canonical payload bytes.
    pub(crate) canonical_digest: String,
    /// Text of the transport request id.
    pub(crate) request_id: String,
    /// Caller request id when a launch caller link was supplied.
    pub(crate) caller_request_id: Option<String>,
}

/// Lineage from a caller launch request to its authorize-launch identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LaunchLineageEntry {
    /// Caller request id (`ApprovedLaunch.request_id`).
    pub(crate) caller_request_id: String,
    /// Transport request id minted for `authorize-launch`.
    pub(crate) authorize_request_id: String,
    /// Transport idempotency key minted for `authorize-launch`.
    pub(crate) authorize_idempotency_key: String,
    /// Canonical digest of the exact authorize payload.
    pub(crate) canonical_digest: String,
}

/// Lineage from an authorization to its process/effect invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLineageEntry {
    /// Caller request id used to join with [`LaunchLineageEntry`].
    pub(crate) caller_request_id: String,
    /// Transport authorize request id when the grant postdates this issuer.
    pub(crate) authorize_request_id: Option<String>,
    /// Kernel grant request digest observed with the grant.
    pub(crate) grant_request_digest: String,
    /// Sealed process invocation digest (effect identity, never collapsed
    /// into the transport identity).
    pub(crate) process_request_digest: String,
}

/// Typed fail-closed issuance failures. No stub or default identity exists.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum OperationIdentityError {
    /// No protected launch binding is composed; issuance is impossible.
    #[error("no protected launch binding is composed")]
    MissingBinding,
    /// No current registration/epoch fence is available.
    #[error("no current registration fence is available")]
    MissingFence,
    /// Wall-clock observation is missing or overflows the deadline horizon.
    #[error("operation clock observation is invalid")]
    InvalidClock,
    /// Canonical payload encoding failed.
    #[error("operation payload encoding failed: {0}")]
    Encoding(String),
    /// A minted identity failed its own validation.
    #[error("minted operation identity is invalid: {0}")]
    InvalidIdentity(String),
    /// A caller binding field is blank or carries control characters.
    #[error("caller launch binding field is invalid: {0}")]
    InvalidCallerBinding(&'static str),
    /// An idempotency key (or caller launch key) is already bound to
    /// different canonical bytes. No Kernel call was made.
    #[error("idempotency identity conflict: {0}")]
    IdentityConflict(String),
    /// Random identity regeneration collided repeatedly.
    #[error("operation identity regeneration collided")]
    IdentityExhausted,
}

/// Ledger key: one exact operation selector plus canonical payload digest.
type LedgerKey = (String, String);

#[derive(Clone, Debug)]
struct LedgerEntry {
    identity: RequestIdentity,
    request_id: String,
    caller_request_id: Option<String>,
}

/// Issues fresh per-operation [`RequestIdentity`] values with exact-retry and
/// identity-conflict semantics. All state is broker-process-local: a restart
/// starts from an empty ledger, so historical request ids are never revived;
/// the next registration carries fresh timestamps and therefore fresh bytes.
///
/// The current fence is held as the exact epoch-binding JSON observed from
/// the protected launch declaration (or refreshed from a Kernel-issued
/// registration epoch below). It is embedded verbatim into each minted
/// identity and always passes through [`RequestIdentity::validate`].
pub(crate) struct OperationIdentityIssuer {
    binding_digest: Option<String>,
    current_fence: Option<Value>,
    ledger: BTreeMap<LedgerKey, LedgerEntry>,
    by_idempotency: BTreeMap<String, LedgerKey>,
    by_request: BTreeMap<String, LedgerKey>,
    by_cancellation: BTreeMap<String, LedgerKey>,
    by_caller_request: BTreeMap<String, LedgerKey>,
    caller_launch_keys: BTreeMap<String, String>,
    launch_lineage: Vec<LaunchLineageEntry>,
    process_lineage: Vec<ProcessLineageEntry>,
}

/// Shared issuer handle between the composition and its authority/process ports.
pub(crate) type IssuerHandle = Arc<Mutex<OperationIdentityIssuer>>;

impl OperationIdentityIssuer {
    /// Creates an issuer bound to one stable launch binding digest and fence.
    /// The fence value is validated before it is retained.
    pub(crate) fn bound(
        binding_digest: String,
        fence: Value,
    ) -> Result<Self, OperationIdentityError> {
        validate_fence_value(&fence)?;
        Ok(Self {
            binding_digest: Some(binding_digest),
            current_fence: Some(fence),
            ledger: BTreeMap::new(),
            by_idempotency: BTreeMap::new(),
            by_request: BTreeMap::new(),
            by_cancellation: BTreeMap::new(),
            by_caller_request: BTreeMap::new(),
            caller_launch_keys: BTreeMap::new(),
            launch_lineage: Vec::new(),
            process_lineage: Vec::new(),
        })
    }

    /// Creates an unbound issuer. Every issuance fails with
    /// [`OperationIdentityError::MissingBinding`] until a launch binding is
    /// composed. This is the fail-closed constructor for binding-less
    /// compositions; production compositions always bind at startup.
    #[cfg(test)]
    pub(crate) fn unbound() -> Self {
        Self {
            binding_digest: None,
            current_fence: None,
            ledger: BTreeMap::new(),
            by_idempotency: BTreeMap::new(),
            by_request: BTreeMap::new(),
            by_cancellation: BTreeMap::new(),
            by_caller_request: BTreeMap::new(),
            caller_launch_keys: BTreeMap::new(),
            launch_lineage: Vec::new(),
            process_lineage: Vec::new(),
        }
    }

    /// Refreshes the carried registration/epoch fence from a Kernel-issued
    /// registration authority epoch, serialized as its exact JSON value.
    /// Only the lineage-aware epoch moves; the installation resource
    /// generation stays stable. The merged fence is revalidated before it is
    /// retained, so a malformed epoch can never poison later identities.
    pub(crate) fn note_authority_epoch(
        &mut self,
        epoch: &Value,
    ) -> Result<(), OperationIdentityError> {
        if !epoch.is_object() {
            return Err(OperationIdentityError::InvalidIdentity(
                "authority epoch must be a JSON object".to_owned(),
            ));
        }
        let fence = self.current_fence.as_mut().ok_or_else(|| {
            if self.binding_digest.is_none() {
                OperationIdentityError::MissingBinding
            } else {
                OperationIdentityError::MissingFence
            }
        })?;
        let mut merged = fence.clone();
        merged
            .as_object_mut()
            .ok_or(OperationIdentityError::MissingFence)?
            .insert("authority_epoch".to_owned(), epoch.clone());
        validate_fence_value(&merged)?;
        *fence = merged;
        Ok(())
    }

    /// Returns the number of distinct operation identities issued.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn issued_count(&self) -> usize {
        self.ledger.len()
    }

    /// Returns the launch lineage log (caller request to transport identity).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn launch_lineage(&self) -> &[LaunchLineageEntry] {
        &self.launch_lineage
    }

    /// Returns the process/effect lineage log (grant to invocation digest).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn process_lineage(&self) -> &[ProcessLineageEntry] {
        &self.process_lineage
    }

    /// Issues (or exactly retries) the register operation identity.
    pub(crate) fn issue_register(
        &mut self,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            BrokerOperation::Register,
            payload,
            now_unix_ms,
            &CallerLink::none(),
        )
    }

    /// Issues (or exactly retries) one heartbeat-revision identity. The same
    /// revision bytes reuse their identity; the next revision mints a new one.
    pub(crate) fn issue_heartbeat(
        &mut self,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            BrokerOperation::HeartbeatRenewal,
            payload,
            now_unix_ms,
            &CallerLink::none(),
        )
    }

    /// Issues (or exactly retries) one authorize-launch identity. The caller
    /// launch idempotency key is guarded: the same key with different launch
    /// bytes fails with [`OperationIdentityError::IdentityConflict`] before
    /// any Kernel call, mirroring the core `ReplayConflict` rule.
    pub(crate) fn issue_authorize_launch(
        &mut self,
        caller_request_id: &str,
        caller_idempotency_key: &str,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        let canonical_digest = canonical_digest_of(payload)?;
        if let Some(known) = self.caller_launch_keys.get(caller_idempotency_key)
            && known != &canonical_digest
        {
            return Err(OperationIdentityError::IdentityConflict(
                "caller launch idempotency key is already bound to different launch bytes"
                    .to_owned(),
            ));
        }
        let link = CallerLink::launch(
            caller_request_id.to_owned(),
            caller_idempotency_key.to_owned(),
        )?;
        let issued = self.issue(
            BrokerOperation::AuthorizeLaunch,
            payload,
            now_unix_ms,
            &link,
        )?;
        self.caller_launch_keys.insert(
            caller_idempotency_key.to_owned(),
            issued.canonical_digest.clone(),
        );
        if let Some(caller) = issued.caller_request_id.clone() {
            self.by_caller_request.insert(
                caller,
                (
                    issued.operation.selector().to_owned(),
                    issued.canonical_digest.clone(),
                ),
            );
            self.launch_lineage.push(LaunchLineageEntry {
                caller_request_id: caller_request_id.to_owned(),
                authorize_request_id: issued.request_id.clone(),
                authorize_idempotency_key: issued.identity.idempotency_key.clone(),
                canonical_digest: issued.canonical_digest.clone(),
            });
        }
        Ok(issued)
    }

    /// Issues (or idempotently retries) the fence/logoff identity. The fence
    /// always owns a fresh transport identity; it never reuses an expired
    /// registration or heartbeat request.
    pub(crate) fn issue_fence(
        &mut self,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            BrokerOperation::FenceLogoff,
            payload,
            now_unix_ms,
            &CallerLink::none(),
        )
    }

    /// Issues with an explicit transport idempotency key. A key already bound
    /// to different canonical bytes fails with identity conflict; the same
    /// key with identical bytes returns the exact prior identity. This is
    /// the single issuance funnel: the typed methods derive their keys and
    /// delegate here.
    pub(crate) fn issue_with_idempotency_key(
        &mut self,
        operation: BrokerOperation,
        payload: &Value,
        idempotency_key: &str,
        now_unix_ms: u64,
        caller: &CallerLink,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        if idempotency_key.trim().is_empty() || idempotency_key.chars().any(char::is_control) {
            return Err(OperationIdentityError::InvalidCallerBinding(
                "idempotency_key",
            ));
        }
        let canonical_digest = canonical_digest_of(payload)?;
        let key = ledger_key(operation, &canonical_digest);
        if let Some(entry) = self.ledger.get(&key) {
            return Ok(IssuedIdentity {
                identity: entry.identity.clone(),
                operation,
                canonical_digest,
                request_id: entry.request_id.clone(),
                caller_request_id: entry.caller_request_id.clone(),
            });
        }
        if let Some(owner) = self.by_idempotency.get(idempotency_key)
            && owner != &key
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "idempotency key is already bound to {} with different canonical bytes",
                owner.0
            )));
        }
        self.mint(
            key,
            operation,
            payload,
            &canonical_digest,
            idempotency_key,
            now_unix_ms,
            caller.caller_request_id.clone(),
        )
    }

    /// Records the process/effect lineage for one prepared grant without
    /// collapsing identities. Bookkeeping never blocks an effect: an unknown
    /// caller link is retained as an orphan entry for reconciliation.
    pub(crate) fn note_process_effect(
        &mut self,
        caller_request_id: &str,
        grant_request_digest: &str,
        process_request_digest: &str,
        noted_at_ms: u64,
    ) {
        let _ = noted_at_ms;
        let authorize_request_id = self
            .by_caller_request
            .get(caller_request_id)
            .and_then(|key| self.ledger.get(key))
            .map(|entry| entry.request_id.clone());
        self.process_lineage.push(ProcessLineageEntry {
            caller_request_id: caller_request_id.to_owned(),
            authorize_request_id,
            grant_request_digest: grant_request_digest.to_owned(),
            process_request_digest: process_request_digest.to_owned(),
        });
    }

    fn issue(
        &mut self,
        operation: BrokerOperation,
        payload: &Value,
        now_unix_ms: u64,
        caller: &CallerLink,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        let canonical_digest = canonical_digest_of(payload)?;
        let idempotency_key = self.derive_idempotency_key(operation, &canonical_digest)?;
        self.issue_with_idempotency_key(operation, payload, &idempotency_key, now_unix_ms, caller)
    }

    fn derive_idempotency_key(
        &self,
        operation: BrokerOperation,
        canonical_digest: &str,
    ) -> Result<String, OperationIdentityError> {
        let binding = self
            .binding_digest
            .as_ref()
            .ok_or(OperationIdentityError::MissingBinding)?;
        let scope: String = binding.chars().take(16).collect();
        Ok(format!(
            "ub-{}/{}-{}",
            operation.namespace(),
            scope,
            canonical_digest
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn mint(
        &mut self,
        key: LedgerKey,
        operation: BrokerOperation,
        payload: &Value,
        canonical_digest: &str,
        idempotency_key: &str,
        now_unix_ms: u64,
        caller_request_id: Option<String>,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        let _ = payload;
        let fence = self.current_fence.clone().ok_or_else(|| {
            if self.binding_digest.is_none() {
                OperationIdentityError::MissingBinding
            } else {
                OperationIdentityError::MissingFence
            }
        })?;
        if now_unix_ms == 0 {
            return Err(OperationIdentityError::InvalidClock);
        }
        let deadline_unix_ms = now_unix_ms
            .checked_add(OPERATION_IDENTITY_TTL_MS)
            .filter(|deadline| *deadline > now_unix_ms)
            .ok_or(OperationIdentityError::InvalidClock)?;
        if self
            .by_idempotency
            .get(idempotency_key)
            .is_some_and(|owner| owner != &key)
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "idempotency key is already bound to {} with different canonical bytes",
                self.by_idempotency[idempotency_key].0
            )));
        }
        for _ in 0..IDENTITY_REGENERATION_LIMIT {
            let request_id = format!("ub-req-{}", uuid::Uuid::new_v4().simple());
            let cancellation_id = format!("ub-cancel-{}", uuid::Uuid::new_v4().simple());
            if self.by_request.contains_key(&request_id)
                || self.by_cancellation.contains_key(&cancellation_id)
            {
                continue;
            }
            let identity = build_identity(
                &request_id,
                idempotency_key,
                deadline_unix_ms,
                &cancellation_id,
                &fence,
                now_unix_ms,
            )?;
            self.by_idempotency
                .insert(idempotency_key.to_owned(), key.clone());
            self.by_request.insert(request_id.clone(), key.clone());
            self.by_cancellation.insert(cancellation_id, key.clone());
            self.ledger.insert(
                key,
                LedgerEntry {
                    identity: identity.clone(),
                    request_id: request_id.clone(),
                    caller_request_id: caller_request_id.clone(),
                },
            );
            return Ok(IssuedIdentity {
                identity,
                operation,
                canonical_digest: canonical_digest.to_owned(),
                request_id,
                caller_request_id,
            });
        }
        Err(OperationIdentityError::IdentityExhausted)
    }
}

impl IssuedIdentity {
    /// Returns the linked caller request id for launch authorizations.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn caller_request_id(&self) -> Option<&str> {
        self.caller_request_id.as_deref()
    }
}

fn ledger_key(operation: BrokerOperation, canonical_digest: &str) -> LedgerKey {
    (operation.selector().to_owned(), canonical_digest.to_owned())
}

fn canonical_digest_of(payload: &Value) -> Result<String, OperationIdentityError> {
    let bytes = serde_json::to_vec(&canonical_json(payload))
        .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Deterministic canonical form: object keys sorted recursively. Arrays keep
/// their order; scalars pass through unchanged.
fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        Value::Object(object) => {
            let mut entries: Vec<(&String, &Value)> = object.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (key, item) in entries {
                sorted.insert(key.clone(), canonical_json(item));
            }
            Value::Object(sorted)
        }
        scalar => scalar.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha2::Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Validates a fence JSON value through the owning [`RequestIdentity`]
/// validator by embedding it in a probe identity. The probe is never issued.
pub(crate) fn validate_fence_value(fence: &Value) -> Result<(), OperationIdentityError> {
    if !fence.is_object() {
        return Err(OperationIdentityError::InvalidIdentity(
            "registration fence must be a JSON object".to_owned(),
        ));
    }
    build_identity(
        "ub-fence-probe",
        "ub-fence-probe-key",
        1_786_000_100_000,
        "ub-fence-probe-cancel",
        fence,
        1_786_000_000_000,
    )?;
    Ok(())
}

fn build_identity(
    request_id: &str,
    idempotency_key: &str,
    deadline_unix_ms: u64,
    cancellation_id: &str,
    fence: &Value,
    now_unix_ms: u64,
) -> Result<RequestIdentity, OperationIdentityError> {
    let now_i64 = i64::try_from(now_unix_ms).map_err(|_| OperationIdentityError::InvalidClock)?;
    let wire = serde_json::json!({
        "request": {
            "metadata": {
                "request_id": request_id,
                "session_id": null,
                "task_id": null,
                "product_id": BROKER_PRODUCT_ID,
                "source_id": BROKER_SOURCE_ID,
                "state_fence": fence,
                "clock": {
                    "valid_time_ms": now_i64,
                    "known_time_ms": now_i64,
                    "transaction_sequence": null,
                    "monotonic_ns": null,
                },
            },
            "state_fence": fence,
        },
        "idempotency_key": idempotency_key,
        "deadline_unix_ms": deadline_unix_ms,
        "cancellation_id": cancellation_id,
    });
    let identity: RequestIdentity = serde_json::from_value(wire)
        .map_err(|error| OperationIdentityError::InvalidIdentity(error.to_string()))?;
    identity
        .validate()
        .map_err(|error| OperationIdentityError::InvalidIdentity(error.to_string()))?;
    Ok(identity)
}

#[cfg(test)]
// Test fixtures panic on setup failure; that panic is the test signal.
// Production code above carries no unwrap/expect.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    const BINDING_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_786_000_000_000;

    fn test_fence() -> Value {
        json!({
            "authority_epoch": {
                "lineage_id": "01234567-89ab-cdef-0123-456789abcdef",
                "sequence": 7,
            },
            "resource_generation": 3,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null,
        })
    }

    fn issuer() -> OperationIdentityIssuer {
        OperationIdentityIssuer::bound(BINDING_DIGEST.to_owned(), test_fence())
            .expect("test issuer")
    }

    fn fence_of(issued: &IssuedIdentity) -> Value {
        serde_json::to_value(&issued.identity)
            .expect("identity value")
            .get("request")
            .expect("request")
            .get("state_fence")
            .expect("fence")
            .clone()
    }

    fn register_payload(nonce: &str) -> Value {
        json!({
            "installation_id": "installation-1",
            "launch_nonce": nonce,
            "observed_at": NOW,
        })
    }

    #[test]
    fn full_operation_sequence_carries_distinct_identities() {
        let mut issuer = issuer();
        let register = issuer
            .issue_register(&register_payload("nonce-1"), NOW)
            .expect("register identity");
        let heartbeat_one = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-1", "observed_at": NOW}),
                NOW,
            )
            .expect("heartbeat one identity");
        let heartbeat_two = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-1", "observed_at": NOW + 1_000}),
                NOW + 1_000,
            )
            .expect("heartbeat two identity");
        let launch_one = issuer
            .issue_authorize_launch(
                "caller-req-1",
                "caller-key-1",
                &json!({"registration_digest": "digest-1", "launch": 1}),
                NOW,
            )
            .expect("launch one identity");
        let launch_two = issuer
            .issue_authorize_launch(
                "caller-req-2",
                "caller-key-2",
                &json!({"registration_digest": "digest-1", "launch": 2}),
                NOW,
            )
            .expect("launch two identity");
        let fence = issuer
            .issue_fence(
                &json!({"registration_digest": "digest-1", "status": "CLOSED"}),
                NOW,
            )
            .expect("fence identity");

        let requests = [
            register.request_id.as_str(),
            heartbeat_one.request_id.as_str(),
            heartbeat_two.request_id.as_str(),
            launch_one.request_id.as_str(),
            launch_two.request_id.as_str(),
            fence.request_id.as_str(),
        ];
        let mut distinct = requests.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            6,
            "every operation owns a distinct request id"
        );

        let cancellations = [
            register.identity.cancellation_id.as_str(),
            heartbeat_one.identity.cancellation_id.as_str(),
            heartbeat_two.identity.cancellation_id.as_str(),
            launch_one.identity.cancellation_id.as_str(),
            launch_two.identity.cancellation_id.as_str(),
            fence.identity.cancellation_id.as_str(),
        ];
        let mut distinct_cancellations = cancellations.to_vec();
        distinct_cancellations.sort_unstable();
        distinct_cancellations.dedup();
        assert_eq!(distinct_cancellations.len(), 6);

        let keys = [
            register.identity.idempotency_key.as_str(),
            heartbeat_one.identity.idempotency_key.as_str(),
            heartbeat_two.identity.idempotency_key.as_str(),
            launch_one.identity.idempotency_key.as_str(),
            launch_two.identity.idempotency_key.as_str(),
            fence.identity.idempotency_key.as_str(),
        ];
        let mut distinct_keys = keys.to_vec();
        distinct_keys.sort_unstable();
        distinct_keys.dedup();
        assert_eq!(distinct_keys.len(), 6);

        for issued in [&register, &heartbeat_one, &launch_one, &fence] {
            issued
                .identity
                .validate()
                .expect("issued identity validates");
            assert!(issued.identity.deadline_unix_ms > NOW);
        }
        assert_eq!(issuer.issued_count(), 6);
    }

    #[test]
    fn exact_retry_reuses_the_operation_identity() {
        let mut issuer = issuer();
        let payload = register_payload("nonce-retry");
        let first = issuer.issue_register(&payload, NOW).expect("first");
        let second = issuer.issue_register(&payload, NOW + 500).expect("retry");
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

        let heartbeat = json!({"registration_digest": "digest-r", "observed_at": NOW});
        let heartbeat_first = issuer.issue_heartbeat(&heartbeat, NOW).expect("hb first");
        let heartbeat_retry = issuer
            .issue_heartbeat(&heartbeat, NOW + 250)
            .expect("hb retry");
        assert_eq!(heartbeat_first.request_id, heartbeat_retry.request_id);

        let fence = json!({"registration_digest": "digest-r", "status": "CLOSED"});
        let fence_first = issuer.issue_fence(&fence, NOW).expect("fence first");
        let fence_retry = issuer.issue_fence(&fence, NOW + 250).expect("fence retry");
        assert_eq!(fence_first.request_id, fence_retry.request_id);
    }

    #[test]
    fn next_heartbeat_revision_mints_a_new_identity() {
        let mut issuer = issuer();
        let first = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-h", "observed_at": NOW}),
                NOW,
            )
            .expect("first revision");
        let second = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-h", "observed_at": NOW + 1_000}),
                NOW + 1_000,
            )
            .expect("next revision");
        assert_ne!(first.request_id, second.request_id);
        assert_ne!(
            first.identity.idempotency_key,
            second.identity.idempotency_key
        );
    }

    #[test]
    fn idempotency_key_reuse_across_operations_conflicts() {
        let mut issuer = issuer();
        let heartbeat = json!({"registration_digest": "digest-c", "observed_at": NOW});
        let heartbeat_issued = issuer.issue_heartbeat(&heartbeat, NOW).expect("heartbeat");
        let foreign_key = heartbeat_issued.identity.idempotency_key.clone();
        let launch_payload = json!({"registration_digest": "digest-c", "launch": 9});
        let conflict = issuer.issue_with_idempotency_key(
            BrokerOperation::AuthorizeLaunch,
            &launch_payload,
            &foreign_key,
            NOW,
            &CallerLink::none(),
        );
        assert!(
            matches!(conflict, Err(OperationIdentityError::IdentityConflict(_))),
            "cross-operation idempotency reuse must conflict, got {conflict:?}"
        );
        // The conflicting attempt minted nothing and changed no ledger state.
        assert_eq!(issuer.issued_count(), 1);
    }

    #[test]
    fn caller_launch_key_reuse_with_different_bytes_conflicts() {
        let mut issuer = issuer();
        issuer
            .issue_authorize_launch(
                "caller-req-a",
                "caller-shared-key",
                &json!({"launch": "a"}),
                NOW,
            )
            .expect("first launch");
        let conflict = issuer.issue_authorize_launch(
            "caller-req-b",
            "caller-shared-key",
            &json!({"launch": "b"}),
            NOW,
        );
        assert!(
            matches!(conflict, Err(OperationIdentityError::IdentityConflict(_))),
            "caller key reuse across launch payloads must conflict, got {conflict:?}"
        );
        // Exact retry of the first launch still resolves to its own identity.
        let retry = issuer
            .issue_authorize_launch(
                "caller-req-a",
                "caller-shared-key",
                &json!({"launch": "a"}),
                NOW + 100,
            )
            .expect("exact launch retry");
        assert_eq!(retry.caller_request_id(), Some("caller-req-a"));
    }

    #[test]
    fn expired_request_never_expires_the_binding() {
        let mut issuer = issuer();
        let first = issuer
            .issue_register(&register_payload("nonce-x"), NOW)
            .expect("first");
        assert!(first.identity.deadline_unix_ms > NOW);
        // A later operation succeeds with a fresh deadline even after the
        // first transport deadline has passed.
        let later = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-x", "observed_at": NOW + OPERATION_IDENTITY_TTL_MS + 1}),
                NOW + OPERATION_IDENTITY_TTL_MS + 1,
            )
            .expect("later operation");
        assert!(later.identity.deadline_unix_ms > NOW + OPERATION_IDENTITY_TTL_MS);
        assert_ne!(first.request_id, later.request_id);
    }

    #[test]
    fn restart_never_revives_a_historical_request_id() {
        let mut first_generation = issuer();
        let first = first_generation
            .issue_register(&register_payload("nonce-old"), NOW)
            .expect("old registration");
        drop(first_generation);

        // A restart starts from an empty ledger with fresh timestamps.
        let mut second_generation = issuer();
        let second = second_generation
            .issue_register(&register_payload("nonce-new"), NOW + 5_000)
            .expect("new registration");
        assert_ne!(first.request_id, second.request_id);
        assert_ne!(
            first.identity.idempotency_key,
            second.identity.idempotency_key
        );
        assert_ne!(
            first.identity.cancellation_id,
            second.identity.cancellation_id
        );
    }

    #[test]
    fn unbound_issuer_fails_closed() {
        let mut issuer = OperationIdentityIssuer::unbound();
        let error = issuer
            .issue_register(&register_payload("nonce-u"), NOW)
            .expect_err("unbound issuance must fail");
        assert_eq!(error, OperationIdentityError::MissingBinding);
        let epoch_error = issuer
            .note_authority_epoch(&json!({
                "lineage_id": "01234567-89ab-cdef-0123-456789abcdef",
                "sequence": 8,
            }))
            .expect_err("unbound epoch sync must fail");
        assert_eq!(epoch_error, OperationIdentityError::MissingBinding);
    }

    #[test]
    fn zero_clock_fails_closed() {
        let mut issuer = issuer();
        let error = issuer
            .issue_register(&register_payload("nonce-z"), 0)
            .expect_err("zero clock must fail");
        assert_eq!(error, OperationIdentityError::InvalidClock);
    }

    #[test]
    fn launch_lineage_links_without_collapsing_identities() {
        let mut issuer = issuer();
        let authorization = issuer
            .issue_authorize_launch(
                "caller-req-lineage",
                "caller-key-lineage",
                &json!({"launch": "lineage"}),
                NOW,
            )
            .expect("launch identity");
        issuer.note_process_effect(
            "caller-req-lineage",
            "grant-digest-1",
            "process-invocation-digest-1",
            NOW + 10,
        );
        let lineage = issuer.launch_lineage();
        assert_eq!(lineage.len(), 1);
        assert_eq!(lineage[0].caller_request_id, "caller-req-lineage");
        assert_eq!(lineage[0].authorize_request_id, authorization.request_id);
        assert_ne!(
            lineage[0].caller_request_id,
            lineage[0].authorize_request_id
        );
        let effects = issuer.process_lineage();
        assert_eq!(effects.len(), 1);
        assert_eq!(
            effects[0].authorize_request_id.as_deref(),
            Some(authorization.request_id.as_str())
        );
        assert_eq!(
            effects[0].process_request_digest,
            "process-invocation-digest-1"
        );
        assert_ne!(
            effects[0].process_request_digest, authorization.request_id,
            "effect identity never collapses into the transport identity"
        );
    }

    #[test]
    fn heartbeat_and_fence_races_reconcile_by_exact_identity() {
        let mut issuer = issuer();
        let heartbeat = json!({"registration_digest": "digest-race", "observed_at": NOW});
        let first_beat = issuer.issue_heartbeat(&heartbeat, NOW).expect("beat");
        // A retried heartbeat (lost reply) reconciles to the exact identity.
        let retried_beat = issuer.issue_heartbeat(&heartbeat, NOW + 50).expect("retry");
        assert_eq!(first_beat.request_id, retried_beat.request_id);
        let fence = json!({"registration_digest": "digest-race", "status": "CLOSED"});
        let fence_issued = issuer.issue_fence(&fence, NOW + 60).expect("fence");
        assert_ne!(first_beat.request_id, fence_issued.request_id);
        // Re-fencing the same closed registration is idempotent.
        let fence_retry = issuer.issue_fence(&fence, NOW + 70).expect("fence retry");
        assert_eq!(fence_issued.request_id, fence_retry.request_id);
    }

    #[test]
    fn authority_epoch_sync_preserves_installation_generation() {
        let mut issuer = issuer();
        let before = issuer
            .issue_register(&register_payload("nonce-e"), NOW)
            .expect("id");
        let next = json!({
            "lineage_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "sequence": 8,
        });
        issuer.note_authority_epoch(&next).expect("epoch sync");
        let after = issuer
            .issue_heartbeat(
                &json!({"registration_digest": "digest-e", "observed_at": NOW + 1}),
                NOW + 1,
            )
            .expect("heartbeat after sync");
        assert_ne!(before.request_id, after.request_id);
        let before_fence = fence_of(&before);
        let after_fence = fence_of(&after);
        assert_eq!(
            after_fence.get("authority_epoch").expect("epoch"),
            &next,
            "carried fence follows the Kernel-issued authority epoch"
        );
        assert_eq!(
            after_fence.get("resource_generation"),
            before_fence.get("resource_generation"),
            "installation resource generation stays stable across epoch sync"
        );
    }

    #[test]
    fn malformed_fence_and_epoch_fail_closed() {
        assert!(
            OperationIdentityIssuer::bound(BINDING_DIGEST.to_owned(), json!({"bogus": true}))
                .is_err()
        );
        let mut issuer = issuer();
        assert!(
            issuer
                .note_authority_epoch(&json!({"lineage_id": "not-a-uuid", "sequence": 0}))
                .is_err()
        );
        // The failed sync poisoned nothing: issuance still works.
        issuer
            .issue_register(&register_payload("nonce-ok"), NOW)
            .expect("issuance after failed sync");
    }
}
