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
//! The spent-identity ledger is durable (issue #74 A4). Every issued identity
//! is projected through [`OperationIdentityIssuer::issued_identities`] into
//! the broker snapshot, and a restarted broker re-seeds this issuer through
//! [`OperationIdentityIssuer::restore_issued`] before any Kernel call can
//! mint. A restart therefore continues from the protected launch/caller
//! identity plus a new registration operation and can never revive a
//! historical request id, cancellation id, or idempotency key: reusing one for
//! a different operation is an [`OperationIdentityError::IdentityConflict`]
//! rather than a fresh mint.
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
use eliot_user_broker_core::{
    ISSUED_OPERATION_CONTROL_BYTE_RESERVE, ISSUED_OPERATION_CONTROL_ENTRY_RESERVE,
    ISSUED_OPERATION_IDENTITY_VERSION, MAX_ISSUED_OPERATION_IDENTITIES,
    MAX_ISSUED_OPERATION_IDENTITY_BYTES, MAX_PROCESS_EFFECT_LINEAGE_BYTES,
    MAX_PROCESS_EFFECT_LINEAGE_ENTRIES, ProcessEffectLineage,
};
use serde::Serialize;
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
/// Canonical read-only Kernel selector for receipt-bound native resource currentness.
pub(crate) const VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION: &str =
    "eliot.user-broker.validate-native-resource-selection-current";

/// Stable broker product/source binding carried by every minted identity.
const BROKER_PRODUCT_ID: &str = "eliot-user-broker";
/// Stable broker product/source binding carried by every minted identity.
const BROKER_SOURCE_ID: &str = "user-broker-transport";

/// Fresh absolute transport deadline horizon per operation, in milliseconds.
pub(crate) const OPERATION_IDENTITY_TTL_MS: u64 = 30_000;

/// Pre-v2 durable identity rows have no original `RequestIdentity` or caller
/// launch idempotency key and can only be restored as tombstones.
const LEGACY_ISSUED_OPERATION_IDENTITY_VERSION: u16 = 1;

/// Bounded regeneration attempts for a colliding random identity field.
const IDENTITY_REGENERATION_LIMIT: usize = 3;

/// Closed broker operation vocabulary for identity issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) enum BrokerOperation {
    Register,
    HeartbeatRenewal,
    AuthorizeLaunch,
    FenceLogoff,
    ValidateNativeResourceSelectionCurrent,
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
            Self::ValidateNativeResourceSelectionCurrent => {
                VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION
            }
        }
    }

    /// Returns the short idempotency-namespace tag for this operation kind.
    fn namespace(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::HeartbeatRenewal => "heartbeat",
            Self::AuthorizeLaunch => "authorize-launch",
            Self::FenceLogoff => "fence",
            Self::ValidateNativeResourceSelectionCurrent => "resource-currentness",
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

/// Lineage from a grant to its exact process/effect invocation.
pub(crate) type ProcessLineageEntry = ProcessEffectLineage;

/// One issued operation identity as it is retained across a broker restart
/// (issue #74 A4).
///
/// Current rows retain the complete original [`RequestIdentity`] and the
/// exact registration digest/epoch that admitted it. Recovery never rebuilds
/// the identity against a newer fence. Legacy version 1 rows lack this proof
/// and are imported only as spent-ID tombstones. Nothing here is authority:
/// the row proves only which request, cancellation, and idempotency strings
/// were already spent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DurableIssuedIdentity {
    /// Explicit durable row schema version. Version 1 rows are imported as
    /// tombstones because they did not preserve the original `RequestIdentity`.
    pub(crate) schema_version: u16,
    /// Closed Kernel operation selector that owns the identity.
    pub(crate) operation: String,
    /// Lowercase SHA-256 of the canonical payload bytes it is bound to.
    pub(crate) canonical_digest: String,
    /// Exact transport request id.
    pub(crate) request_id: String,
    /// Exact transport idempotency key.
    pub(crate) idempotency_key: String,
    /// Exact transport cancellation id.
    pub(crate) cancellation_id: String,
    /// Absolute transport deadline the identity was minted with.
    pub(crate) deadline_unix_ms: u64,
    /// Exact registration generation that admitted this identity, when one
    /// existed at issuance time.
    pub(crate) registration_digest: Option<String>,
    pub(crate) user_broker_epoch: Option<u64>,
    /// Immutable original transport identity; never rebuilt using a later
    /// current fence during recovery.
    pub(crate) request_identity: Option<RequestIdentity>,
    /// Observation instant the identity was minted at.
    pub(crate) issued_at_ms: u64,
    /// Caller request id when a launch caller link owned this issuance.
    pub(crate) caller_request_id: Option<String>,
    /// Caller launch idempotency key, separate from the transport key.
    pub(crate) caller_idempotency_key: Option<String>,
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
    /// The retained anti-reuse or lineage ledger reached its fixed budget.
    #[error("operation identity evidence capacity is exhausted")]
    IdentityCapacityExceeded,
}

/// Ledger key: one exact operation selector plus canonical payload digest.
type LedgerKey = (String, String);

#[derive(Clone, Debug)]
struct LedgerEntry {
    identity: RequestIdentity,
    request_id: String,
    caller_request_id: Option<String>,
    caller_idempotency_key: Option<String>,
}

/// Issues fresh per-operation [`RequestIdentity`] values with exact-retry and
/// identity-conflict semantics. The executable retry map is process-local;
/// recovery rebuilds it only from the exact original identity under the same
/// active registration, fence, and unexpired deadline. Other retained rows
/// remain spent tombstones.
///
/// The current fence is held as the exact epoch-binding JSON observed from
/// the protected launch declaration (or refreshed from a Kernel-issued
/// registration epoch below). It is embedded verbatim into each minted
/// identity and always passes through [`RequestIdentity::validate`].
pub(crate) struct OperationIdentityIssuer {
    binding_digest: Option<String>,
    current_fence: Option<Value>,
    current_registration_digest: Option<String>,
    current_user_broker_epoch: Option<u64>,
    ledger: BTreeMap<LedgerKey, LedgerEntry>,
    by_idempotency: BTreeMap<String, LedgerKey>,
    by_request: BTreeMap<String, LedgerKey>,
    by_cancellation: BTreeMap<String, LedgerKey>,
    by_caller_request: BTreeMap<String, LedgerKey>,
    caller_launch_keys: BTreeMap<String, String>,
    legacy_authorize_launch_tombstone: bool,
    launch_lineage: Vec<LaunchLineageEntry>,
    process_lineage: Vec<ProcessLineageEntry>,
    issued: BTreeMap<LedgerKey, DurableIssuedIdentity>,
    issued_bytes: usize,
    launch_lineage_bytes: usize,
    process_lineage_bytes: usize,
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
            current_registration_digest: None,
            current_user_broker_epoch: None,
            ledger: BTreeMap::new(),
            by_idempotency: BTreeMap::new(),
            by_request: BTreeMap::new(),
            by_cancellation: BTreeMap::new(),
            by_caller_request: BTreeMap::new(),
            caller_launch_keys: BTreeMap::new(),
            legacy_authorize_launch_tombstone: false,
            launch_lineage: Vec::new(),
            process_lineage: Vec::new(),
            issued: BTreeMap::new(),
            issued_bytes: 0,
            launch_lineage_bytes: 0,
            process_lineage_bytes: 0,
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
            current_registration_digest: None,
            current_user_broker_epoch: None,
            ledger: BTreeMap::new(),
            by_idempotency: BTreeMap::new(),
            by_request: BTreeMap::new(),
            by_cancellation: BTreeMap::new(),
            by_caller_request: BTreeMap::new(),
            caller_launch_keys: BTreeMap::new(),
            legacy_authorize_launch_tombstone: false,
            launch_lineage: Vec::new(),
            process_lineage: Vec::new(),
            issued: BTreeMap::new(),
            issued_bytes: 0,
            launch_lineage_bytes: 0,
            process_lineage_bytes: 0,
        }
    }

    /// Binds future identities to one exact Kernel-issued registration.
    ///
    /// The authority epoch is merged into the installation fence without
    /// changing any other fence field. Identities admitted by an older
    /// registration or fence stay in the spent ledger but leave the executable
    /// retry map; they are never rewritten to this registration.
    pub(crate) fn note_registration_binding(
        &mut self,
        registration_digest: &str,
        user_broker_epoch: u64,
        epoch: &Value,
    ) -> Result<(), OperationIdentityError> {
        if !is_lowercase_sha256(registration_digest) || user_broker_epoch == 0 {
            return Err(OperationIdentityError::InvalidIdentity(
                "registration binding is invalid".to_owned(),
            ));
        }
        if !epoch.is_object() {
            return Err(OperationIdentityError::InvalidIdentity(
                "authority epoch must be a JSON object".to_owned(),
            ));
        }
        let missing_fence = if self.binding_digest.is_none() {
            OperationIdentityError::MissingBinding
        } else {
            OperationIdentityError::MissingFence
        };
        let fence = self.current_fence.as_mut().ok_or(missing_fence)?;
        let mut merged = fence.clone();
        merged
            .as_object_mut()
            .ok_or(OperationIdentityError::MissingFence)?
            .insert("authority_epoch".to_owned(), epoch.clone());
        validate_fence_value(&merged)?;
        *fence = merged;
        self.current_registration_digest = Some(registration_digest.to_owned());
        self.current_user_broker_epoch = Some(user_broker_epoch);
        self.retire_replays_outside_current_registration();
        Ok(())
    }

    fn retire_replays_outside_current_registration(&mut self) {
        let Some(current_registration_digest) = self.current_registration_digest.as_deref() else {
            return;
        };
        let Some(current_user_broker_epoch) = self.current_user_broker_epoch else {
            return;
        };
        let Some(current_fence) = self.current_fence.as_ref() else {
            return;
        };
        let stale = self
            .ledger
            .keys()
            .filter(|key| {
                self.issued.get(*key).is_none_or(|issued| {
                    issued.registration_digest.as_deref() != Some(current_registration_digest)
                        || issued.user_broker_epoch != Some(current_user_broker_epoch)
                        || issued.request_identity.as_ref().is_none_or(|identity| {
                            fence_value(&identity.request.state_fence)
                                .is_none_or(|fence| &fence != current_fence)
                        })
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in stale {
            self.ledger.remove(&key);
        }
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

    /// Returns every identity this issuer spent, in a deterministic order.
    ///
    /// This is the durable half of the ledger. It is published into the
    /// broker snapshot together with the registration state, so a restart
    /// re-seeds the same spent request ids, cancellation ids, and idempotency
    /// keys instead of starting from an empty ledger.
    #[must_use]
    pub(crate) fn issued_identities(&self) -> Vec<DurableIssuedIdentity> {
        self.issued.values().cloned().collect()
    }

    /// Returns the most recent identity this issuer spent for one operation
    /// kind.
    ///
    /// This is what a lost acknowledgement is reconciled against: the caller
    /// names the exact transport identity whose outcome is unknown instead of
    /// minting a second one for the same logical operation.
    #[must_use]
    pub(crate) fn last_issued(&self, operation: BrokerOperation) -> Option<DurableIssuedIdentity> {
        self.issued
            .values()
            .filter(|issued| issued.operation == operation.selector())
            .max_by_key(|issued| (issued.issued_at_ms, issued.request_id.clone()))
            .cloned()
    }

    /// Re-seeds one durably retained identity into this issuer (issue #74 A4).
    ///
    /// The historical request id, cancellation id, and idempotency key become
    /// spent before any new issuance. Only an original identity that still
    /// matches the active registration, fence, and deadline can serve an exact
    /// retry; all other rows remain tombstones. A retained row that contradicts
    /// an already-issued identity, or that is internally inconsistent, fails
    /// closed instead of overwriting live state.
    pub(crate) fn restore_issued(
        &mut self,
        retained: &DurableIssuedIdentity,
        restored_at_unix_ms: u64,
    ) -> Result<(), OperationIdentityError> {
        validate_retained_identity(retained)?;
        let key = (
            retained.operation.clone(),
            retained.canonical_digest.clone(),
        );
        if let Some(live) = self.issued.get(&key) {
            return if live == retained {
                Ok(())
            } else {
                Err(OperationIdentityError::IdentityConflict(format!(
                    "retained ledger row for {} contradicts the identity already issued",
                    retained.operation
                )))
            };
        }
        self.ensure_restored_identity_unbound(retained)?;
        let retained_bytes = serde_json::to_vec(retained)
            .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
            .len();
        self.ensure_issued_capacity(retained.operation.as_str(), retained_bytes)?;
        let launch_lineage = self.restored_launch_lineage(retained)?;
        let next_issued_bytes = self
            .issued_bytes
            .checked_add(retained_bytes)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        // Complete every fallible lineage check and insertion before the
        // spent-ID indexes change. A corrupt/conflicting lineage row must
        // leave this issuer exactly as it was so restore can be retried.
        if let Some(launch_lineage) = launch_lineage {
            self.record_launch_lineage(launch_lineage)?;
        }
        if retained.schema_version == LEGACY_ISSUED_OPERATION_IDENTITY_VERSION
            && retained.operation == AUTHORIZE_LAUNCH_OPERATION
        {
            // The old row retained its caller request id but not the caller's
            // idempotency key. Keep issuance closed rather than treating that
            // unknown spent key as available to another launch.
            self.legacy_authorize_launch_tombstone = true;
        }

        // A row is executable only in the exact registration generation and
        // State Fence that admitted its original typed identity, and only
        // while that original deadline remains live. Legacy rows and rows
        // whose binding is historical still reserve every spent identifier,
        // but are not put in the replay ledger.
        let replay_identity = retained.request_identity.as_ref().filter(|identity| {
            retained.schema_version == ISSUED_OPERATION_IDENTITY_VERSION
                && self.current_registration_digest.as_deref()
                    == retained.registration_digest.as_deref()
                && self.current_registration_digest.is_some()
                && self.current_user_broker_epoch == retained.user_broker_epoch
                && self.current_user_broker_epoch.is_some()
                && self.current_fence.as_ref().is_some_and(|current_fence| {
                    fence_value(&identity.request.state_fence)
                        .is_some_and(|original_fence| &original_fence == current_fence)
                })
                && retained.deadline_unix_ms > restored_at_unix_ms
        });

        self.by_idempotency
            .insert(retained.idempotency_key.clone(), key.clone());
        self.by_request
            .insert(retained.request_id.clone(), key.clone());
        self.by_cancellation
            .insert(retained.cancellation_id.clone(), key.clone());
        if let Some(caller) = retained.caller_request_id.clone() {
            self.by_caller_request.insert(caller, key.clone());
        }
        if let Some(caller_key) = retained.caller_idempotency_key.clone() {
            self.caller_launch_keys
                .insert(caller_key, retained.canonical_digest.clone());
        }
        if let Some(identity) = replay_identity {
            self.ledger.insert(
                key.clone(),
                LedgerEntry {
                    identity: identity.clone(),
                    request_id: retained.request_id.clone(),
                    caller_request_id: retained.caller_request_id.clone(),
                    caller_idempotency_key: retained.caller_idempotency_key.clone(),
                },
            );
        }
        self.issued.insert(key, retained.clone());
        self.issued_bytes = next_issued_bytes;
        Ok(())
    }

    fn ensure_restored_identity_unbound(
        &self,
        retained: &DurableIssuedIdentity,
    ) -> Result<(), OperationIdentityError> {
        if self.by_request.contains_key(&retained.request_id)
            || self.by_cancellation.contains_key(&retained.cancellation_id)
            || self.by_idempotency.contains_key(&retained.idempotency_key)
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "retained request/cancellation/idempotency identity of {} is already bound to another operation",
                retained.operation
            )));
        }
        if retained
            .caller_request_id
            .as_deref()
            .is_some_and(|caller| self.by_caller_request.contains_key(caller))
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "retained caller launch binding of {} is already bound to another launch",
                retained.operation
            )));
        }
        if retained
            .caller_idempotency_key
            .as_deref()
            .is_some_and(|caller_key| self.caller_launch_keys.contains_key(caller_key))
        {
            return Err(OperationIdentityError::IdentityConflict(format!(
                "retained caller launch idempotency key of {} is already bound to different bytes",
                retained.operation
            )));
        }
        Ok(())
    }

    fn restored_launch_lineage(
        &self,
        retained: &DurableIssuedIdentity,
    ) -> Result<Option<LaunchLineageEntry>, OperationIdentityError> {
        if retained.operation != AUTHORIZE_LAUNCH_OPERATION
            || retained.schema_version != ISSUED_OPERATION_IDENTITY_VERSION
        {
            return Ok(None);
        }
        let caller_request_id = retained.caller_request_id.as_deref().ok_or_else(|| {
            OperationIdentityError::InvalidIdentity(
                "authorize-launch identity omitted its caller request id".to_owned(),
            )
        })?;
        let caller_idempotency_key =
            retained.caller_idempotency_key.as_deref().ok_or_else(|| {
                OperationIdentityError::InvalidIdentity(
                    "authorize-launch identity omitted its caller idempotency key".to_owned(),
                )
            })?;
        self.ensure_launch_lineage_capacity(
            caller_request_id,
            &retained.request_id,
            caller_idempotency_key,
            &retained.canonical_digest,
        )?;
        Ok(Some(LaunchLineageEntry {
            caller_request_id: caller_request_id.to_owned(),
            authorize_request_id: retained.request_id.clone(),
            authorize_idempotency_key: caller_idempotency_key.to_owned(),
            canonical_digest: retained.canonical_digest.clone(),
        }))
    }

    /// Returns the process/effect lineage log (grant to invocation digest).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn process_lineage(&self) -> &[ProcessLineageEntry] {
        &self.process_lineage
    }

    /// Returns retained process/effect lineage in deterministic order.
    #[must_use]
    pub(crate) fn process_effect_lineage(&self) -> Vec<ProcessEffectLineage> {
        self.process_lineage.clone()
    }

    /// Re-seeds one durable process/effect relation without replacing an
    /// existing binding for the same caller and grant.
    pub(crate) fn restore_process_effect_lineage(
        &mut self,
        retained: &ProcessEffectLineage,
    ) -> Result<(), OperationIdentityError> {
        validate_process_effect_lineage(retained)?;
        if let Some(existing) = self.process_lineage.iter().find(|entry| {
            entry.caller_request_id == retained.caller_request_id
                && entry.grant_request_digest == retained.grant_request_digest
        }) {
            return if existing == retained {
                Ok(())
            } else {
                Err(OperationIdentityError::IdentityConflict(
                    "retained process lineage changed under the same caller and grant".to_owned(),
                ))
            };
        }
        let row_bytes = serde_json::to_vec(retained)
            .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
            .len();
        self.ensure_process_lineage_capacity(row_bytes)?;
        let next_process_lineage_bytes = self
            .process_lineage_bytes
            .checked_add(row_bytes)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        self.process_lineage.push(retained.clone());
        self.process_lineage_bytes = next_process_lineage_bytes;
        Ok(())
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
        if self.legacy_authorize_launch_tombstone {
            return Err(OperationIdentityError::IdentityConflict(
                "legacy authorize-launch history omitted caller idempotency keys; new launches are refused"
                    .to_owned(),
            ));
        }
        let canonical_digest = canonical_digest_of(payload)?;
        if let Some(known) = self.caller_launch_keys.get(caller_idempotency_key)
            && known != &canonical_digest
        {
            return Err(OperationIdentityError::IdentityConflict(
                "caller launch idempotency key is already bound to different launch bytes"
                    .to_owned(),
            ));
        }
        let caller_ledger_key = ledger_key(BrokerOperation::AuthorizeLaunch, &canonical_digest);
        if self
            .by_caller_request
            .get(caller_request_id)
            .is_some_and(|owner| owner != &caller_ledger_key)
        {
            return Err(OperationIdentityError::IdentityConflict(
                "caller launch request id is already bound to another launch".to_owned(),
            ));
        }
        if !self.ledger.contains_key(&caller_ledger_key)
            && !self.issued.contains_key(&caller_ledger_key)
        {
            let request_id_budget = "ub-req-00000000000000000000000000000000";
            self.ensure_launch_lineage_capacity(
                caller_request_id,
                request_id_budget,
                caller_idempotency_key,
                &canonical_digest,
            )?;
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
            self.record_launch_lineage(LaunchLineageEntry {
                caller_request_id: caller_request_id.to_owned(),
                authorize_request_id: issued.request_id.clone(),
                authorize_idempotency_key: issued.identity.idempotency_key.clone(),
                canonical_digest: issued.canonical_digest.clone(),
            })?;
        }
        Ok(issued)
    }

    /// Issues (or exactly retries) a read-only native resource currentness
    /// identity. Its distinct selector and idempotency namespace prevent it
    /// from sharing an identity with registration, launch, heartbeat, or fence
    /// operations. The payload includes the exact receipt, selection, and
    /// caller-observed time that Kernel must revalidate against ORS.
    pub(crate) fn issue_native_resource_selection_currentness(
        &mut self,
        payload: &Value,
        now_unix_ms: u64,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        self.issue(
            BrokerOperation::ValidateNativeResourceSelectionCurrent,
            payload,
            now_unix_ms,
            &CallerLink::none(),
        )
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
        if now_unix_ms == 0 {
            return Err(OperationIdentityError::InvalidClock);
        }
        let canonical_digest = canonical_digest_of(payload)?;
        let key = ledger_key(operation, &canonical_digest);
        if let Some(entry) = self.ledger.get(&key) {
            let retained = self.issued.get(&key).ok_or_else(|| {
                OperationIdentityError::IdentityConflict(
                    "executable operation identity has no durable spent row".to_owned(),
                )
            })?;
            if !self.matches_current_binding(retained) {
                return Err(OperationIdentityError::IdentityConflict(
                    "exact operation replay is outside the current registration or State Fence"
                        .to_owned(),
                ));
            }
            if entry.identity.idempotency_key != idempotency_key
                || entry.caller_request_id != caller.caller_request_id
                || entry.caller_idempotency_key != caller.caller_idempotency_key
            {
                return Err(OperationIdentityError::IdentityConflict(
                    "exact operation replay changed its idempotency or caller binding".to_owned(),
                ));
            }
            if entry.identity.deadline_unix_ms <= now_unix_ms {
                return Err(OperationIdentityError::IdentityConflict(
                    "the original operation identity deadline has expired".to_owned(),
                ));
            }
            return Ok(IssuedIdentity {
                identity: entry.identity.clone(),
                operation,
                canonical_digest,
                request_id: entry.request_id.clone(),
                caller_request_id: entry.caller_request_id.clone(),
            });
        }
        if self.issued.contains_key(&key) {
            return Err(OperationIdentityError::IdentityConflict(
                "historical operation identity is reserved and cannot be replayed or reminted"
                    .to_owned(),
            ));
        }
        if let Some(owner) = self.by_idempotency.get(idempotency_key) {
            let reason = if owner == &key {
                "idempotency key is reserved by a non-replayable historical identity"
            } else {
                "idempotency key is already bound to different canonical operation bytes"
            };
            return Err(OperationIdentityError::IdentityConflict(format!(
                "{reason}: {}",
                owner.0,
            )));
        }
        if caller
            .caller_request_id
            .as_ref()
            .is_some_and(|caller_request_id| {
                self.by_caller_request
                    .get(caller_request_id)
                    .is_some_and(|owner| owner != &key)
            })
        {
            return Err(OperationIdentityError::IdentityConflict(
                "caller launch request id is already bound to different canonical bytes".to_owned(),
            ));
        }
        if caller
            .caller_idempotency_key
            .as_ref()
            .is_some_and(|caller_key| self.caller_launch_keys.contains_key(caller_key))
        {
            return Err(OperationIdentityError::IdentityConflict(
                "caller launch idempotency key is already spent".to_owned(),
            ));
        }
        let estimated_bytes =
            self.estimate_new_identity_bytes(operation, idempotency_key, caller)?;
        self.ensure_issued_capacity(operation.selector(), estimated_bytes)?;
        self.mint(
            key,
            operation,
            &canonical_digest,
            idempotency_key,
            now_unix_ms,
            caller,
        )
    }

    fn matches_current_binding(&self, issued: &DurableIssuedIdentity) -> bool {
        let Some(identity) = issued.request_identity.as_ref() else {
            return false;
        };
        issued.schema_version == ISSUED_OPERATION_IDENTITY_VERSION
            && issued.registration_digest == self.current_registration_digest
            && issued.user_broker_epoch == self.current_user_broker_epoch
            && fence_value(&identity.request.state_fence)
                .zip(self.current_fence.as_ref())
                .is_some_and(|(issued_fence, current_fence)| &issued_fence == current_fence)
    }

    /// Records the process/effect lineage for one prepared grant without
    /// collapsing identities. Bookkeeping never blocks an effect: an unknown
    /// caller link is retained as an orphan entry for reconciliation.
    pub(crate) fn note_process_effect(
        &mut self,
        caller_request_id: &str,
        grant_request_digest: &str,
        process_request_digest: &str,
        _noted_at_ms: u64,
    ) -> Result<(), OperationIdentityError> {
        if caller_request_id.trim().is_empty()
            || caller_request_id.chars().any(char::is_control)
            || !is_lowercase_sha256(grant_request_digest)
            || !is_lowercase_sha256(process_request_digest)
        {
            return Err(OperationIdentityError::InvalidIdentity(
                "process lineage identity fields are invalid".to_owned(),
            ));
        }
        let authorize_request_id = self
            .by_caller_request
            .get(caller_request_id)
            .and_then(|key| self.issued.get(key))
            .map(|entry| entry.request_id.as_str());
        if let Some(existing) = self.process_lineage.iter().find(|entry| {
            entry.caller_request_id == caller_request_id
                && entry.grant_request_digest == grant_request_digest
        }) {
            return if existing.authorize_request_id.as_deref() == authorize_request_id
                && existing.process_request_digest == process_request_digest
            {
                Ok(())
            } else {
                Err(OperationIdentityError::IdentityConflict(
                    "process invocation changed under the same caller and grant identity"
                        .to_owned(),
                ))
            };
        }
        let estimated_bytes = estimate_process_lineage_bytes(
            caller_request_id,
            authorize_request_id,
            grant_request_digest,
            process_request_digest,
        )?;
        self.ensure_process_lineage_capacity(estimated_bytes)?;
        let entry = ProcessLineageEntry {
            caller_request_id: caller_request_id.to_owned(),
            authorize_request_id: authorize_request_id.map(str::to_owned),
            grant_request_digest: grant_request_digest.to_owned(),
            process_request_digest: process_request_digest.to_owned(),
        };
        validate_process_effect_lineage(&entry)?;
        let row_bytes = serde_json::to_vec(&entry)
            .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
            .len();
        self.ensure_process_lineage_capacity(row_bytes)?;
        let next_process_lineage_bytes = self
            .process_lineage_bytes
            .checked_add(row_bytes)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        self.process_lineage.push(entry);
        self.process_lineage_bytes = next_process_lineage_bytes;
        Ok(())
    }

    fn estimate_new_identity_bytes(
        &self,
        operation: BrokerOperation,
        idempotency_key: &str,
        caller: &CallerLink,
    ) -> Result<usize, OperationIdentityError> {
        let fence = self.current_fence.as_ref().ok_or_else(|| {
            if self.binding_digest.is_none() {
                OperationIdentityError::MissingBinding
            } else {
                OperationIdentityError::MissingFence
            }
        })?;
        let fence_bytes = serde_json::to_vec(fence)
            .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
            .len();
        let mut estimate = 2_048_usize
            .checked_add(fence_bytes.saturating_mul(2))
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        for length in [
            operation.selector().len(),
            64,
            "ub-req-".len() + 32,
            idempotency_key.len(),
            "ub-cancel-".len() + 32,
            64,
        ] {
            estimate = estimate
                .checked_add(json_string_upper_bound(length))
                .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        }
        for binding in [
            caller.caller_request_id.as_deref(),
            caller.caller_idempotency_key.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            estimate = estimate
                .checked_add(json_string_upper_bound(binding.len()))
                .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        }
        Ok(estimate)
    }

    fn ensure_issued_capacity(
        &self,
        operation: &str,
        row_bytes: usize,
    ) -> Result<(), OperationIdentityError> {
        let next_entries = self
            .issued
            .len()
            .checked_add(1)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        let next_bytes = self
            .issued_bytes
            .checked_add(row_bytes)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        if next_entries > MAX_ISSUED_OPERATION_IDENTITIES
            || next_bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES
        {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        if operation != FENCE_OPERATION
            && (next_entries
                > MAX_ISSUED_OPERATION_IDENTITIES
                    .saturating_sub(ISSUED_OPERATION_CONTROL_ENTRY_RESERVE)
                || next_bytes
                    > MAX_ISSUED_OPERATION_IDENTITY_BYTES
                        .saturating_sub(ISSUED_OPERATION_CONTROL_BYTE_RESERVE))
        {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        Ok(())
    }

    fn ensure_launch_lineage_capacity(
        &self,
        caller_request_id: &str,
        authorize_request_id: &str,
        authorize_idempotency_key: &str,
        canonical_digest: &str,
    ) -> Result<(), OperationIdentityError> {
        if self.launch_lineage.len() >= MAX_ISSUED_OPERATION_IDENTITIES {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        let estimate = 256_usize
            .checked_add(json_string_upper_bound(caller_request_id.len()))
            .and_then(|total| {
                total.checked_add(json_string_upper_bound(authorize_request_id.len()))
            })
            .and_then(|total| {
                total.checked_add(json_string_upper_bound(authorize_idempotency_key.len()))
            })
            .and_then(|total| total.checked_add(json_string_upper_bound(canonical_digest.len())))
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        if self
            .launch_lineage_bytes
            .checked_add(estimate)
            .is_none_or(|bytes| bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES)
        {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        Ok(())
    }

    fn record_launch_lineage(
        &mut self,
        entry: LaunchLineageEntry,
    ) -> Result<(), OperationIdentityError> {
        for retained in &self.launch_lineage {
            if retained.caller_request_id == entry.caller_request_id
                || retained.authorize_request_id == entry.authorize_request_id
            {
                return if retained == &entry {
                    Ok(())
                } else {
                    Err(OperationIdentityError::IdentityConflict(
                        "launch lineage changed under the same caller or authorize identity"
                            .to_owned(),
                    ))
                };
            }
        }
        self.ensure_launch_lineage_capacity(
            &entry.caller_request_id,
            &entry.authorize_request_id,
            &entry.authorize_idempotency_key,
            &entry.canonical_digest,
        )?;
        let row_bytes = serde_json::to_vec(&entry)
            .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
            .len();
        let next_bytes = self
            .launch_lineage_bytes
            .checked_add(row_bytes)
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
        if next_bytes > MAX_ISSUED_OPERATION_IDENTITY_BYTES {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        self.launch_lineage.push(entry);
        self.launch_lineage_bytes = next_bytes;
        Ok(())
    }

    fn ensure_process_lineage_capacity(
        &self,
        row_bytes: usize,
    ) -> Result<(), OperationIdentityError> {
        if self.process_lineage.len() >= MAX_PROCESS_EFFECT_LINEAGE_ENTRIES
            || self
                .process_lineage_bytes
                .checked_add(row_bytes)
                .is_none_or(|bytes| bytes > MAX_PROCESS_EFFECT_LINEAGE_BYTES)
        {
            return Err(OperationIdentityError::IdentityCapacityExceeded);
        }
        Ok(())
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

    fn mint(
        &mut self,
        key: LedgerKey,
        operation: BrokerOperation,
        canonical_digest: &str,
        idempotency_key: &str,
        now_unix_ms: u64,
        caller: &CallerLink,
    ) -> Result<IssuedIdentity, OperationIdentityError> {
        let caller_request_id = caller.caller_request_id.clone();
        let caller_idempotency_key = caller.caller_idempotency_key.clone();
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
        self.ensure_mint_idempotency_available(&key, idempotency_key)?;
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
            let issued = DurableIssuedIdentity {
                schema_version: ISSUED_OPERATION_IDENTITY_VERSION,
                operation: operation.selector().to_owned(),
                canonical_digest: canonical_digest.to_owned(),
                request_id: request_id.clone(),
                idempotency_key: idempotency_key.to_owned(),
                cancellation_id: identity.cancellation_id.clone(),
                deadline_unix_ms,
                registration_digest: self.current_registration_digest.clone(),
                user_broker_epoch: self.current_user_broker_epoch,
                request_identity: Some(identity.clone()),
                issued_at_ms: now_unix_ms,
                caller_request_id: caller_request_id.clone(),
                caller_idempotency_key: caller_idempotency_key.clone(),
            };
            validate_retained_identity(&issued)?;
            let row_bytes = serde_json::to_vec(&issued)
                .map_err(|error| OperationIdentityError::Encoding(error.to_string()))?
                .len();
            self.ensure_issued_capacity(operation.selector(), row_bytes)?;
            let next_issued_bytes = self
                .issued_bytes
                .checked_add(row_bytes)
                .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
            self.by_idempotency
                .insert(idempotency_key.to_owned(), key.clone());
            self.by_request.insert(request_id.clone(), key.clone());
            self.by_cancellation
                .insert(cancellation_id.clone(), key.clone());
            if let Some(caller_request_id) = caller_request_id.as_ref() {
                self.by_caller_request
                    .insert(caller_request_id.clone(), key.clone());
            }
            if let Some(caller_key) = issued.caller_idempotency_key.as_ref() {
                self.caller_launch_keys
                    .insert(caller_key.clone(), canonical_digest.to_owned());
            }
            self.ledger.insert(
                key.clone(),
                LedgerEntry {
                    identity: identity.clone(),
                    request_id: request_id.clone(),
                    caller_request_id: caller_request_id.clone(),
                    caller_idempotency_key: issued.caller_idempotency_key.clone(),
                },
            );
            self.issued.insert(key, issued);
            self.issued_bytes = next_issued_bytes;
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

    fn ensure_mint_idempotency_available(
        &self,
        key: &LedgerKey,
        idempotency_key: &str,
    ) -> Result<(), OperationIdentityError> {
        let Some(owner) = self.by_idempotency.get(idempotency_key) else {
            return Ok(());
        };
        let reason = if owner == key {
            "idempotency key is already spent by a historical identity"
        } else {
            "idempotency key is already bound to different canonical bytes"
        };
        Err(OperationIdentityError::IdentityConflict(format!(
            "{reason}: {}",
            owner.0,
        )))
    }
}

fn validate_process_effect_lineage(
    relation: &ProcessEffectLineage,
) -> Result<(), OperationIdentityError> {
    if relation.caller_request_id.trim().is_empty()
        || relation.caller_request_id.chars().any(char::is_control)
        || relation
            .authorize_request_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        || !is_lowercase_sha256(&relation.grant_request_digest)
        || !is_lowercase_sha256(&relation.process_request_digest)
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained process lineage row is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn estimate_process_lineage_bytes(
    caller_request_id: &str,
    authorize_request_id: Option<&str>,
    grant_request_digest: &str,
    process_request_digest: &str,
) -> Result<usize, OperationIdentityError> {
    let mut estimate = 256_usize;
    for length in [
        caller_request_id.len(),
        grant_request_digest.len(),
        process_request_digest.len(),
    ] {
        estimate = estimate
            .checked_add(json_string_upper_bound(length))
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
    }
    if let Some(authorize_request_id) = authorize_request_id {
        estimate = estimate
            .checked_add(json_string_upper_bound(authorize_request_id.len()))
            .ok_or(OperationIdentityError::IdentityCapacityExceeded)?;
    }
    Ok(estimate)
}

fn json_string_upper_bound(text_bytes: usize) -> usize {
    text_bytes.saturating_mul(6).saturating_add(2)
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

/// Returns whether a value is a lowercase 64-hex SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates one durably retained identity before it is re-seeded.
///
/// A retained row is written by this issuer, so a row that fails these checks
/// is a corrupt or foreign durable file: it is rejected before any index is
/// touched, so a bad row can never partially bind a historical request id.
fn validate_retained_identity(
    retained: &DurableIssuedIdentity,
) -> Result<(), OperationIdentityError> {
    for value in [
        retained.operation.as_str(),
        retained.request_id.as_str(),
        retained.idempotency_key.as_str(),
        retained.cancellation_id.as_str(),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(OperationIdentityError::InvalidIdentity(
                "retained operation identity field is blank".to_owned(),
            ));
        }
    }
    if !is_lowercase_sha256(&retained.canonical_digest) {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained canonical payload digest is not a lowercase sha-256".to_owned(),
        ));
    }
    if retained.issued_at_ms == 0 || retained.deadline_unix_ms <= retained.issued_at_ms {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained operation identity clock is not exact".to_owned(),
        ));
    }
    validate_retained_caller_and_registration(retained)?;
    match retained.schema_version {
        LEGACY_ISSUED_OPERATION_IDENTITY_VERSION => {
            let selector_admitted = matches!(
                retained.operation.as_str(),
                REGISTER_OPERATION
                    | HEARTBEAT_OPERATION
                    | AUTHORIZE_LAUNCH_OPERATION
                    | FENCE_OPERATION
                    | VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION
                    | "eliot.user-broker.cancel"
                    | "eliot.user-broker.reconcile"
            );
            if retained.request_identity.is_some()
                || retained.registration_digest.is_some()
                || retained.user_broker_epoch.is_some()
                || retained.caller_idempotency_key.is_some()
                || !selector_admitted
                || (retained.operation == AUTHORIZE_LAUNCH_OPERATION)
                    != retained.caller_request_id.is_some()
            {
                return Err(OperationIdentityError::InvalidIdentity(
                    "legacy identity row carries fields unavailable in its schema".to_owned(),
                ));
            }
            // Explicit legacy rows are valid spent-ID tombstones. They do not
            // contain enough information to build a replay identity.
            return Ok(());
        }
        ISSUED_OPERATION_IDENTITY_VERSION => {}
        _ => {
            return Err(OperationIdentityError::InvalidIdentity(
                "retained identity row schema version is unsupported".to_owned(),
            ));
        }
    }
    let is_kernel_operation = matches!(
        retained.operation.as_str(),
        REGISTER_OPERATION
            | HEARTBEAT_OPERATION
            | AUTHORIZE_LAUNCH_OPERATION
            | FENCE_OPERATION
            | VALIDATE_NATIVE_RESOURCE_SELECTION_CURRENT_OPERATION
    );
    let is_control_operation = matches!(
        retained.operation.as_str(),
        "eliot.user-broker.cancel" | "eliot.user-broker.reconcile"
    );
    if is_kernel_operation {
        validate_current_kernel_identity(retained)?;
    } else if is_control_operation {
        if retained.request_identity.is_some()
            || retained.registration_digest.is_none()
            || retained.user_broker_epoch.is_none()
            || retained.caller_request_id.is_some()
            || retained.caller_idempotency_key.is_some()
        {
            return Err(OperationIdentityError::InvalidIdentity(
                "retained broker-control identity binding is incomplete".to_owned(),
            ));
        }
    } else {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained identity operation selector is not admitted".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retained_caller_and_registration(
    retained: &DurableIssuedIdentity,
) -> Result<(), OperationIdentityError> {
    if let Some(caller) = retained.caller_request_id.as_deref()
        && (caller.trim().is_empty() || caller.chars().any(char::is_control))
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained caller request id is blank".to_owned(),
        ));
    }
    if let Some(caller_key) = retained.caller_idempotency_key.as_deref()
        && (caller_key.trim().is_empty() || caller_key.chars().any(char::is_control))
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained caller idempotency key is blank".to_owned(),
        ));
    }
    match (
        retained.registration_digest.as_deref(),
        retained.user_broker_epoch,
    ) {
        (Some(digest), Some(epoch)) if epoch > 0 && is_lowercase_sha256(digest) => Ok(()),
        (None, None) => Ok(()),
        _ => Err(OperationIdentityError::InvalidIdentity(
            "retained registration binding is incomplete".to_owned(),
        )),
    }
}

fn validate_current_kernel_identity(
    retained: &DurableIssuedIdentity,
) -> Result<(), OperationIdentityError> {
    if retained.operation != REGISTER_OPERATION
        && (retained.registration_digest.is_none() || retained.user_broker_epoch.is_none())
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "non-registration identity omitted its registration generation".to_owned(),
        ));
    }
    let identity = retained.request_identity.as_ref().ok_or_else(|| {
        OperationIdentityError::InvalidIdentity(
            "current Kernel identity row omitted its original RequestIdentity".to_owned(),
        )
    })?;
    identity
        .validate()
        .map_err(|error| OperationIdentityError::InvalidIdentity(error.to_string()))?;
    let issued_at_i64 =
        i64::try_from(retained.issued_at_ms).map_err(|_| OperationIdentityError::InvalidClock)?;
    if identity.request.metadata.request_id.as_str() != retained.request_id
        || identity.idempotency_key != retained.idempotency_key
        || identity.cancellation_id != retained.cancellation_id
        || identity.deadline_unix_ms != retained.deadline_unix_ms
        || identity.request.metadata.state_fence != identity.request.state_fence
        || identity.request.metadata.product_id.as_str() != BROKER_PRODUCT_ID
        || identity.request.metadata.source_id.as_str() != BROKER_SOURCE_ID
        || identity.request.metadata.session_id.is_some()
        || identity.request.metadata.task_id.is_some()
        || identity.request.metadata.clock.valid_time_ms != Some(issued_at_i64)
        || identity.request.metadata.clock.known_time_ms != Some(issued_at_i64)
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained RequestIdentity differs from its durable scalar binding".to_owned(),
        ));
    }
    let is_authorize_launch = retained.operation == AUTHORIZE_LAUNCH_OPERATION;
    if retained.caller_request_id.is_some() != is_authorize_launch
        || retained.caller_idempotency_key.is_some() != is_authorize_launch
    {
        return Err(OperationIdentityError::InvalidIdentity(
            "retained caller binding does not match the operation selector".to_owned(),
        ));
    }
    Ok(())
}

fn fence_value(fence: &eliot_contracts::StateFence) -> Option<Value> {
    serde_json::to_value(fence).ok()
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
            .note_registration_binding(
                BINDING_DIGEST,
                1,
                &json!({
                    "lineage_id": "01234567-89ab-cdef-0123-456789abcdef",
                    "sequence": 8,
                }),
            )
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
        issuer
            .note_process_effect(
                "caller-req-lineage",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                NOW + 10,
            )
            .expect("valid process lineage observation");
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
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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
        issuer
            .note_registration_binding(BINDING_DIGEST, 1, &next)
            .expect("registration binding sync");
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
                .note_registration_binding(
                    BINDING_DIGEST,
                    1,
                    &json!({"lineage_id": "not-a-uuid", "sequence": 0}),
                )
                .is_err()
        );
        // The failed sync poisoned nothing: issuance still works.
        issuer
            .issue_register(&register_payload("nonce-ok"), NOW)
            .expect("issuance after failed sync");
    }
}
