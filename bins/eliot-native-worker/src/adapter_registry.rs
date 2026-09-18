//! Private finite immutable four-factory adapter registry (T9-07, WRITER-A).
//!
//! The registry sits behind the admitted consumer and binds one
//! owner-admitted route projection to exactly one named adapter factory. It
//! owns no wire contract, mints no authority, launches nothing, and performs
//! no network or credential I/O.
//!
//! ## Factory identities
//!
//! Exactly one entry exists per factory identity plus revision, using the
//! adapter crate names as canonical identities:
//!
//! ```text
//! eliot-agent-opencode @ 1 (resolution only; no invoke entry, issue #1708)
//! eliot-agent-codex    @ 1 (resolution only; no invoke entry)
//! eliot-agent-acp      @ 1 (resolution only; no invoke entry, issue #1708)
//! eliot-agent-claude   @ 1 (capable; ClaudeSidecarFactory::<E>::new + prepare/admit_with_port seam)
//! ```
//!
//! There is no unified factory trait upstream; only the Claude factory is
//! composed from its real per-adapter public entries in this contour, to the
//! maximum extent reachable without live credentials or live owner records:
//!
//! - claude constructs the real `ClaudeSidecarFactory::<E>::new` over the
//!   forwarded P-03 executor (pure: stores the handle, starts nothing),
//!   validates the inert launch-plan shape at runtime, and pins
//!   `execution::prepare` plus `admit_with_port` with compile-time signature
//!   assertions. `prepare` with the live X4 binding plus agent attempt records
//!   belongs to the agent-plane caller that owns those records, not to this
//!   contour.
//!
//! The other three identities have no invoke entry in this contour:
//!
//! - opencode and acp keep registry entries (identity plus revision) as static
//!   typed resolution metadata consumed by the live admitted seam
//!   (`select_factory_for_admitted`), but neither constructs anything here:
//!   the OpenCode/ACP crates are unreachable and no live caller supplies their
//!   seams, so a construction would record an invocation that never happened
//!   (issue #1708).
//! - codex has no invoke entry in this contour: `CodexAdapter::<E>::new`,
//!   `attach`/`begin_attempt` with live Q-01/A-01 records belong to the
//!   agent-plane caller that owns those records, not to this contour.
//!
//! INTEGRATOR-T9-07 correction (issue #874): Writer A misread the Claude
//! crate as a skeleton with no execution constructor. In fact
//! `crates/agent/eliot-agent-claude/src/execution.rs` supplies
//! `ClaudeFactoryInput` (:208-232), `prepare()` (:352), and
//! `ClaudeSidecarFactory` with `::new` (:919-929), `pub mod execution` is
//! declared (`src/lib.rs:37`), and `admit_with_port` lives at
//! `src/lib.rs:1300`. The Claude entry therefore gets the same
//! signature-pinned, deferred-invocation treatment as the other three; the
//! always-`Incompatible` skeleton refusal is removed.
//!
//! ## Validation order (all fail-closed, all before any factory effect)
//!
//! 1. `ClaimAdmissionRequest::validate_binding` (claim/registration binding);
//! 2. `CapabilityAdmissionRequest::from_claim` (join against the
//!    owner-supplied hello and in-memory process request; covers
//!    task/attempt/operation identity, generation, epoch, fence, limits, and
//!    deadline);
//! 3. `NativeWorkerClaim::require_executable_binding` against the current
//!    owner expectation (wrong/stale/revoked/foreign/expired refused);
//! 4. registry resolution to exactly one named entry (unknown, duplicate,
//!    ambiguous, and incompatible refused);
//! 5. single-start ownership (an already-started operation is refused without
//!    touching any factory).
//!
//! There is no rerank, fallback, or substitution: a resolution failure
//! returns without trying another adapter, and each per-adapter invoke
//! refuses a validated dispatch that resolved to a different identity.
//!
//! ## Hardening
//!
//! No dynamic loading, no raw process spawn, no ambient credentials, and no
//! unbounded buffers: every collection in this module is a fixed-size array
//! or a `Vec` guarded by an explicit `MAX_*` bound, and no credential value
//! or credential reference travels through this contour at all.
//!
//! ## Writer-B drive wiring
//!
//! Resolve once with [`AdapterRegistry::resolve_claim`], validate once with
//! [`validate_admitted_dispatch`], then call [`invoke_claude_factory`] with
//! the validated token and a [`FactoryLedger`]. Retained replay reconciles
//! through the ledger via [`FactoryLedger::contains_operation`]; it never
//! recalls a constructor. Opencode, ACP and Codex have no invoke entry in
//! this contour (see above): nothing here constructs for those identities,
//! and the downstream drive derives process intent generically through the
//! executable gate with no factory effect of its own.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_agent_claude::{ClaudeSidecarError, ClaudeSidecarRequest};
use eliot_agent_codex::CODEX_ADAPTER_ID;
use eliot_agent_opencode::OPENCODE_ADAPTER_ID;
use eliot_native_worker_core::{
    CapabilityAdmissionRequest, ClaimAdmissionRequest, NativeWorkerClaim,
    NativeWorkerExecutableExpectation, WorkerError, WorkerHello,
};
use eliot_process::{ProcessExecutor, ProcessRequest};
use thiserror::Error;

/// Canonical opencode factory identity (adapter crate name).
pub const OPENCODE_FACTORY_ID: &str = OPENCODE_ADAPTER_ID;
/// Canonical codex factory identity (adapter crate name).
pub const CODEX_FACTORY_ID: &str = CODEX_ADAPTER_ID;
/// Canonical ACP factory identity (adapter crate name; the ACP crate exposes
/// no `*_ADAPTER_ID` const, only `ACP_SCHEMA_VERSION`).
pub const ACP_FACTORY_ID: &str = "eliot-agent-acp";
/// Canonical Claude factory identity (adapter crate name).
///
/// Note this differs from `CLAUDE_SIDECAR_ADAPTER_ID`
/// (`"eliot-agent-claude-sidecar"`), which names the sidecar wire family, not
/// the factory owner. The registry keys on the crate/owner name.
pub const CLAUDE_FACTORY_ID: &str = "eliot-agent-claude";
/// Expected adapter revision for every factory entry in this unit.
///
/// Revisions are owner-produced; a bump is an #874 follow-up that changes
/// this constant together with its proof, never a silent local repair.
pub const FACTORY_REVISION: u64 = 1;

/// Maximum factory-call records retained by one [`FactoryLedger`].
pub const MAX_FACTORY_CALLS: usize = 16;
/// Maximum adapter-identity text accepted by the registry boundary.
pub const MAX_ADAPTER_ID_LEN: usize = 128;
/// Maximum error-detail characters carried from third-party validators.
pub const MAX_DETAIL_CHARS: usize = 256;

/// One of the four admitted adapter factories.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdapterIdentity {
    /// `eliot-agent-opencode` HTTP/SSE bridge (capable).
    Opencode,
    /// `eliot-agent-codex` App Server stdio/JSONL bridge (capable).
    Codex,
    /// `eliot-agent-acp` ACP v1 compatibility cell (capable).
    Acp,
    /// `eliot-agent-claude` local sidecar (capable).
    Claude,
}

impl AdapterIdentity {
    /// Returns the canonical crate-name identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opencode => OPENCODE_FACTORY_ID,
            Self::Codex => CODEX_FACTORY_ID,
            Self::Acp => ACP_FACTORY_ID,
            Self::Claude => CLAUDE_FACTORY_ID,
        }
    }

    /// Parses a canonical identity; returns `None` for anything else.
    #[must_use]
    pub const fn parse(value: &str) -> Option<Self> {
        // `const` string equality over bytes; the caller bounds the length.
        if const_eq_str(value, OPENCODE_FACTORY_ID) {
            Some(Self::Opencode)
        } else if const_eq_str(value, CODEX_FACTORY_ID) {
            Some(Self::Codex)
        } else if const_eq_str(value, ACP_FACTORY_ID) {
            Some(Self::Acp)
        } else if const_eq_str(value, CLAUDE_FACTORY_ID) {
            Some(Self::Claude)
        } else {
            None
        }
    }
}

/// Compares two strings by bytes in a `const` context.
const fn const_eq_str(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// One immutable factory entry: an identity plus its expected revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactoryEntry {
    identity: AdapterIdentity,
    revision: u64,
}

impl FactoryEntry {
    /// Builds one entry; returns `None` when the revision is zero.
    #[must_use]
    pub const fn new(identity: AdapterIdentity, revision: u64) -> Option<Self> {
        if revision == 0 {
            return None;
        }
        Some(Self { identity, revision })
    }

    /// Returns the factory identity.
    #[must_use]
    pub const fn identity(self) -> AdapterIdentity {
        self.identity
    }

    /// Returns the expected adapter revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// Typed fail-closed registry failure.
///
/// Reason-code mapping (I07-20): `Unknown` is `ADAPTER_UNAVAILABLE` /
/// `ROUTE_UNAVAILABLE`; a revision mismatch is `ROUTE_MISMATCH`;
/// `Incompatible` is `ADAPTER_INCOMPATIBLE`; `BadClaim` preserves the production
/// [`WorkerError`] dimension (`InvalidRequest`, `StaleEpoch`, `StaleFence`,
/// `DeadlineExpired`, `Revoked`, `UnsupportedVersion`, admission mismatch);
/// `AlreadyStarted` guards single-start ownership.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    /// The adapter identity is not one of the four registered factories.
    #[error("unknown adapter factory: {adapter_id}")]
    Unknown {
        /// Presented identity (bounded, truncated).
        adapter_id: String,
    },
    /// Two entries claim the same identity plus revision.
    #[error("duplicate adapter factory entry: {detail}")]
    Duplicate {
        /// Bounded duplicate description.
        detail: String,
    },
    /// The projection matches more than one entry; no ranking is attempted.
    #[error("ambiguous adapter factory projection: {adapter_id}")]
    Ambiguous {
        /// Presented identity (bounded, truncated).
        adapter_id: String,
    },
    /// The entry is known but cannot serve the admitted contour.
    #[error("incompatible adapter factory {adapter_id}: {reason}")]
    Incompatible {
        /// Canonical identity (bounded, truncated).
        adapter_id: String,
        /// Bounded incompatibility reason.
        reason: String,
    },
    /// Admitted dispatch or claim bindings failed production validation.
    #[error("admitted claim refused pre-factory: {0}")]
    BadClaim(#[from] WorkerError),
    /// A control input failed registry-boundary shape checks.
    #[error("invalid registry input {field}: {detail}")]
    BadInput {
        /// Failing field name.
        field: &'static str,
        /// Bounded detail.
        detail: String,
    },
    /// The operation already constructed its factory; no second constructor.
    #[error("factory already started for operation {operation_id}")]
    AlreadyStarted {
        /// Admitted operation identity.
        operation_id: String,
    },
    /// The resolved factory differs from the invoked one; no substitution.
    #[error("factory substitution refused: resolved {resolved} but invoked {expected}")]
    SubstitutionRefused {
        /// Invoked factory identity.
        expected: String,
        /// Resolved factory identity.
        resolved: String,
    },
    /// The bounded call ledger is full.
    #[error("factory call ledger is full")]
    LedgerFull,
}

/// Private finite immutable four-factory registry.
///
/// The entry array is fixed at construction and exposed only by value or
/// shared reference; there is no `&mut` API and no entry replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterRegistry {
    entries: [FactoryEntry; 4],
}

impl AdapterRegistry {
    /// Builds the canonical four-factory denominator, one entry per
    /// identity plus revision.
    #[must_use]
    pub fn four_factory() -> Self {
        Self {
            entries: [
                FactoryEntry {
                    identity: AdapterIdentity::Opencode,
                    revision: FACTORY_REVISION,
                },
                FactoryEntry {
                    identity: AdapterIdentity::Codex,
                    revision: FACTORY_REVISION,
                },
                FactoryEntry {
                    identity: AdapterIdentity::Acp,
                    revision: FACTORY_REVISION,
                },
                FactoryEntry {
                    identity: AdapterIdentity::Claude,
                    revision: FACTORY_REVISION,
                },
            ],
        }
    }

    /// Builds a registry from four explicit entries.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Duplicate`] when two entries share both
    /// identity and revision. Same-identity entries with distinct revisions
    /// are accepted so ambiguity stays provable (and refused at resolve).
    pub fn from_entries(entries: [FactoryEntry; 4]) -> Result<Self, RegistryError> {
        let mut index = 0;
        while index < entries.len() {
            let mut other = index + 1;
            while other < entries.len() {
                if entries[index] == entries[other] {
                    return Err(RegistryError::Duplicate {
                        detail: truncate_detail(entries[index].identity.as_str()),
                    });
                }
                other += 1;
            }
            index += 1;
        }
        Ok(Self { entries })
    }

    /// Returns the four immutable entries.
    #[must_use]
    pub const fn entries(&self) -> &[FactoryEntry; 4] {
        &self.entries
    }

    /// Returns the denominator size (always 4).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns false; the registry is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolves an identity to its single entry without revision or
    /// capability checks.
    ///
    /// # Errors
    ///
    /// Returns `Unknown` for zero matches and `Ambiguous` for more than one;
    /// no ranking is attempted.
    pub fn resolve_by_identity(&self, adapter_id: &str) -> Result<AdapterIdentity, RegistryError> {
        validate_adapter_id_shape(adapter_id)?;
        let mut first: Option<AdapterIdentity> = None;
        let mut count = 0;
        for entry in &self.entries {
            if entry.identity.as_str() == adapter_id {
                first = Some(entry.identity);
                count += 1;
            }
        }
        match (count, first) {
            (0, _) => Err(RegistryError::Unknown {
                adapter_id: truncate_detail(adapter_id),
            }),
            (1, Some(identity)) => Ok(identity),
            _ => Err(RegistryError::Ambiguous {
                adapter_id: truncate_detail(adapter_id),
            }),
        }
    }

    /// Resolves an identity plus revision to exactly one capable entry.
    ///
    /// # Errors
    ///
    /// Returns `Unknown`/`Ambiguous` from identity resolution and
    /// `Incompatible` for a revision mismatch. No fallback is attempted on
    /// any failure.
    pub fn resolve(
        &self,
        adapter_id: &str,
        adapter_revision: u64,
    ) -> Result<FactoryEntry, RegistryError> {
        let identity = self.resolve_by_identity(adapter_id)?;
        let mut matched: Option<FactoryEntry> = None;
        for entry in &self.entries {
            if entry.identity == identity {
                if matched.is_some() {
                    return Err(RegistryError::Ambiguous {
                        adapter_id: truncate_detail(adapter_id),
                    });
                }
                matched = Some(*entry);
            }
        }
        let Some(entry) = matched else {
            return Err(RegistryError::Unknown {
                adapter_id: truncate_detail(adapter_id),
            });
        };
        if entry.revision != adapter_revision {
            return Err(RegistryError::Incompatible {
                adapter_id: truncate_detail(adapter_id),
                reason: truncate_detail("adapter revision does not match the registered factory"),
            });
        }
        Ok(entry)
    }

    /// Resolves the executable join of one validated claim presentation.
    ///
    /// # Errors
    ///
    /// Returns `BadClaim` when the claim carries no v2 executable join and
    /// otherwise forwards [`AdapterRegistry::resolve`].
    pub fn resolve_claim(&self, claim: &NativeWorkerClaim) -> Result<FactoryEntry, RegistryError> {
        let join = claim
            .executable_binding
            .as_ref()
            .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
        self.resolve(&join.adapter_id, join.adapter_revision)
    }
}

/// Validates the adapter-identity projection shape.
fn validate_adapter_id_shape(adapter_id: &str) -> Result<(), RegistryError> {
    if adapter_id.is_empty() || adapter_id.len() > MAX_ADAPTER_ID_LEN {
        return Err(RegistryError::BadInput {
            field: "adapter_id",
            detail: "adapter identity has an invalid length".to_owned(),
        });
    }
    if adapter_id
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(RegistryError::BadInput {
            field: "adapter_id",
            detail: "adapter identity carries control or whitespace".to_owned(),
        });
    }
    Ok(())
}

/// Bounds third-party error detail carried into typed failures.
fn truncate_detail(detail: &str) -> String {
    detail.chars().take(MAX_DETAIL_CHARS).collect()
}

/// Admitted dispatch validated through every production gate, pre-factory.
///
/// The token carries only validated, bounded identity strings plus the
/// resolved factory projection extracted from the claim itself (never
/// caller-supplied). It is constructible solely via
/// [`validate_admitted_dispatch`]; it carries no secret and no port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatch {
    claim_id: String,
    attempt_id: String,
    operation_id: String,
    task_id: String,
    adapter_id: String,
    adapter_revision: u64,
    worker_generation: u64,
    binding_digest: String,
}

impl ValidatedDispatch {
    /// Returns the admitted claim identity.
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    /// Returns the admitted attempt identity.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns the exact external-effect operation identity.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the governed task identity.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Returns the validated factory identity projection.
    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    /// Returns the validated factory revision projection.
    #[must_use]
    pub const fn adapter_revision(&self) -> u64 {
        self.adapter_revision
    }

    /// Returns the claiming worker generation.
    #[must_use]
    pub const fn worker_generation(&self) -> u64 {
        self.worker_generation
    }

    /// Returns the canonical binding digest.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

/// Validates one admitted dispatch through every production gate.
///
/// Runs `validate_binding`, the `from_claim` join against the owner-supplied
/// hello and in-memory process request, and the executable-binding
/// currentness check against the live owner expectation. Any wrong, stale,
/// revoked, foreign, or expired presentation fails here, before any factory
/// side effect.
///
/// # Errors
///
/// Returns [`RegistryError::BadClaim`] preserving the production
/// [`WorkerError`] dimension, or `BadInput` for a malformed projection.
pub fn validate_admitted_dispatch(
    admission: &ClaimAdmissionRequest,
    hello: &WorkerHello,
    process: &ProcessRequest,
    expected: &NativeWorkerExecutableExpectation,
    now_unix_ms: u64,
) -> Result<ValidatedDispatch, RegistryError> {
    admission
        .validate_binding()
        .map_err(RegistryError::BadClaim)?;
    let _joined = CapabilityAdmissionRequest::from_claim(admission, hello, process)
        .map_err(RegistryError::BadClaim)?;
    let claim = admission.claim();
    claim
        .require_executable_binding(expected, now_unix_ms)
        .map_err(RegistryError::BadClaim)?;
    let join = claim
        .executable_binding
        .as_ref()
        .ok_or(WorkerError::InvalidRequest("executable_binding"))?;
    validate_adapter_id_shape(&join.adapter_id)?;
    Ok(ValidatedDispatch {
        claim_id: claim.claim_id.as_str().to_owned(),
        attempt_id: claim.attempt_id.as_str().to_owned(),
        operation_id: claim.operation_id.as_str().to_owned(),
        task_id: claim.task_id.as_str().to_owned(),
        adapter_id: join.adapter_id.clone(),
        adapter_revision: join.adapter_revision,
        worker_generation: claim.worker_generation,
        binding_digest: claim.binding_digest.clone(),
    })
}

/// One recorded factory construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryCall {
    adapter: AdapterIdentity,
    operation_id: String,
    claim_id: String,
}

impl FactoryCall {
    /// Returns the constructed factory.
    #[must_use]
    pub const fn adapter(&self) -> AdapterIdentity {
        self.adapter
    }

    /// Returns the operation the factory constructed for.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the claim the factory constructed for.
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }
}

/// Call ledger proving exactly-once construction per live operation.
///
/// Bounded at [`MAX_FACTORY_CALLS`] records; every invoke checks the ledger
/// before any factory effect and records only on success.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FactoryLedger {
    calls: Vec<FactoryCall>,
}

impl FactoryLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns recorded factory constructions.
    #[must_use]
    pub fn calls(&self) -> &[FactoryCall] {
        &self.calls
    }

    /// Counts constructions for one factory.
    #[must_use]
    pub fn calls_for(&self, adapter: AdapterIdentity) -> usize {
        self.calls
            .iter()
            .filter(|call| call.adapter == adapter)
            .count()
    }

    /// Returns true once the operation has constructed its factory.
    #[must_use]
    pub fn contains_operation(&self, operation_id: &str) -> bool {
        self.calls
            .iter()
            .any(|call| call.operation_id == operation_id)
    }

    /// Records one successful construction.
    fn record(&mut self, call: FactoryCall) -> Result<(), RegistryError> {
        if self.calls.len() >= MAX_FACTORY_CALLS {
            return Err(RegistryError::LedgerFull);
        }
        self.calls.push(call);
        Ok(())
    }
}

/// Deterministic event entry bound to the admitted attempt stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryEventRecord {
    /// Claim-bound stream identity (`{claim_id}/gen-{generation}`).
    pub stream_id: String,
    /// Deterministic event identity (`{claim_id}/event-1`).
    pub event_id: String,
    /// First sequence number.
    pub sequence: u64,
}

/// Deterministic terminal entry for the constructed attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryTerminalRecord {
    /// Admitted attempt identity.
    pub attempt_id: String,
    /// Closed terminal disposition for a constructed attempt.
    pub disposition: String,
}

/// Deterministic reconciliation receipt bound to the admitted claim.
///
/// Reconciliation rides this retained receipt; it never recalls a factory
/// constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryReconcileReceipt {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Exact operation identity.
    pub operation_id: String,
    /// Canonical binding digest reconciled.
    pub binding_digest: String,
}

/// One deterministic admitted attempt per capable adapter.
///
/// Every field derives from the validated dispatch; equal inputs yield equal
/// attempts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactoryAttempt {
    adapter: AdapterIdentity,
    attempt_id: String,
    operation_id: String,
    claim_id: String,
    event: FactoryEventRecord,
    terminal: FactoryTerminalRecord,
    reconciliation: FactoryReconcileReceipt,
}

impl FactoryAttempt {
    /// Returns the constructed factory.
    #[must_use]
    pub const fn adapter(&self) -> AdapterIdentity {
        self.adapter
    }

    /// Returns the admitted attempt identity.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns the exact operation identity.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the admitted claim identity.
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    /// Returns the deterministic event ledger entry.
    #[must_use]
    pub const fn event(&self) -> &FactoryEventRecord {
        &self.event
    }

    /// Returns the deterministic terminal ledger entry.
    #[must_use]
    pub const fn terminal(&self) -> &FactoryTerminalRecord {
        &self.terminal
    }

    /// Returns the deterministic reconciliation receipt.
    #[must_use]
    pub const fn reconciliation(&self) -> &FactoryReconcileReceipt {
        &self.reconciliation
    }
}

/// Builds the deterministic attempt ledgers from validated dispatch.
fn finish_attempt(adapter: AdapterIdentity, validated: &ValidatedDispatch) -> FactoryAttempt {
    FactoryAttempt {
        adapter,
        attempt_id: validated.attempt_id.clone(),
        operation_id: validated.operation_id.clone(),
        claim_id: validated.claim_id.clone(),
        event: FactoryEventRecord {
            stream_id: format!("{}/gen-{}", validated.claim_id, validated.worker_generation),
            event_id: format!("{}/event-1", validated.claim_id),
            sequence: 1,
        },
        terminal: FactoryTerminalRecord {
            attempt_id: validated.attempt_id.clone(),
            disposition: "constructed".to_owned(),
        },
        reconciliation: FactoryReconcileReceipt {
            claim_id: validated.claim_id.clone(),
            operation_id: validated.operation_id.clone(),
            binding_digest: validated.binding_digest.clone(),
        },
    }
}

/// Shared fail-closed prologue: single-start, resolution, no substitution.
///
/// Checks the ledger before any factory effect, resolves the validated
/// projection to exactly one entry, and refuses when the resolved factory
/// differs from the invoked one.
fn begin_invoke(
    registry: &AdapterRegistry,
    validated: &ValidatedDispatch,
    factory: AdapterIdentity,
    ledger: &FactoryLedger,
) -> Result<FactoryEntry, RegistryError> {
    if ledger.contains_operation(&validated.operation_id) {
        return Err(RegistryError::AlreadyStarted {
            operation_id: validated.operation_id.clone(),
        });
    }
    let entry = registry.resolve(&validated.adapter_id, validated.adapter_revision)?;
    if entry.identity != factory {
        return Err(RegistryError::SubstitutionRefused {
            expected: factory.as_str().to_owned(),
            resolved: entry.identity.as_str().to_owned(),
        });
    }
    Ok(entry)
}

/// Records one successful construction after the factory effect.
fn commit_invoke(
    ledger: &mut FactoryLedger,
    adapter: AdapterIdentity,
    validated: &ValidatedDispatch,
) -> Result<FactoryAttempt, RegistryError> {
    ledger.record(FactoryCall {
        adapter,
        operation_id: validated.operation_id.clone(),
        claim_id: validated.claim_id.clone(),
    })?;
    Ok(finish_attempt(adapter, validated))
}

/// Controlled Claude seams: the forwarded P-03 executor behind `Arc`.
#[derive(Clone, Debug)]
pub struct ClaudeFactorySeams<E> {
    /// Forwarded process executor; construction stores it without starting.
    pub executor: Arc<E>,
}

/// Invokes exactly the named Claude factory.
///
/// Constructs the real `ClaudeSidecarFactory::<E>::new` over the forwarded
/// executor (pure: stores the handle, starts nothing), validates the inert
/// launch-plan shape through its real public entries, and pins
/// `execution::prepare` plus `admit_with_port` by compile-time signature
/// assertion. `prepare` with the live X4 binding plus agent attempt records
/// belongs to the agent-plane caller that owns those records; the drive step
/// performs the single P-03 start.
///
/// # Errors
///
/// Returns ledger, resolution, substitution, and input failures without any
/// factory effect on any failure path.
pub fn invoke_claude_factory<E>(
    registry: &AdapterRegistry,
    validated: &ValidatedDispatch,
    seams: &ClaudeFactorySeams<E>,
    request: &ClaudeSidecarRequest,
    ledger: &mut FactoryLedger,
) -> Result<FactoryAttempt, RegistryError>
where
    E: ProcessExecutor,
{
    let _entry = begin_invoke(registry, validated, AdapterIdentity::Claude, ledger)?;
    assert_claude_entries::<E>();
    let _factory =
        eliot_agent_claude::execution::ClaudeSidecarFactory::new(Arc::clone(&seams.executor));
    request
        .validate()
        .map_err(|error| RegistryError::BadInput {
            field: "claude_request",
            detail: truncate_detail(&error.to_string()),
        })?;
    if let Some(plan) = request.launch_plan.as_ref() {
        plan.validate().map_err(|error| RegistryError::BadInput {
            field: "claude_launch_plan",
            detail: truncate_detail(&error.to_string()),
        })?;
    }
    commit_invoke(ledger, AdapterIdentity::Claude, validated)
}

/// Pins the Claude entries reachable from this contour at build time.
///
/// `prepare` (with the live X4 binding plus agent attempt) and the
/// single-take `launch` run at the Writer-B drive step behind the
/// owner-record boundary; they are pinned here so a signature drift fails
/// the build instead of silently detaching the factory.
fn assert_claude_entries<E>()
where
    E: ProcessExecutor,
{
    let _ = eliot_agent_claude::execution::ClaudeSidecarFactory::<E>::new
        as fn(Arc<E>) -> eliot_agent_claude::execution::ClaudeSidecarFactory<E>;
    let _ = eliot_agent_claude::execution::prepare
        as fn(
            eliot_agent_claude::execution::ClaudeFactoryInput,
        )
            -> Result<eliot_agent_claude::execution::ClaudeFactoryOutcome, ClaudeSidecarError>;
    let _ = eliot_agent_claude::admit_with_port
        as fn(
            &dyn eliot_agent_claude::ClaudeLaunchPort,
            &ClaudeSidecarRequest,
        ) -> Result<eliot_agent_claude::AdmittedHandle, ClaudeSidecarError>;
}
