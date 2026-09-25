//! Kernel-owned research-provider dispatch wire contract (issue #24).
//!
//! Pure types plus validation for the four research-provider front-door
//! operations (`dispatch`, `status`, `cancel`, `reconcile`). The contract
//! carries identity and evidence only: it never names an executable discovered
//! at runtime, never carries a credential, and never carries research
//! semantics. Kernel verifies presentation shape, the presented Authority
//! Epoch against the live one, and the presented State Fence against the
//! session's module-generation fence; it never interprets the inquiry, grades
//! evidence, admits a candidate, or finishes a task.
//!
//! Authority basis, stated explicitly because it is narrower than a durable
//! claim row: this contract is validated against the **live Kernel authority
//! epoch** and the **authenticated session's module-generation State Fence**.
//! `eliot-ors` carries no research-provider row (see the route module's
//! residual), so no durable attempt, job or source-portfolio state is claimed
//! or created here. A dispatch receipt is therefore a *live-admission*
//! receipt, not a durable Governor-owned attempt record; durable Research
//! Job/Attempt and coverage-denominator state remain owned by #15/#18.
//!
//! I21.11: "Endpoint reachability or a successful login proves neither source
//! coverage nor permission to disclose a bundle." Accordingly the receipt
//! echoes no coverage or disclosure claim — it echoes only the exact request
//! digest and the authority binding it was admitted under, and
//! [`ResearchProviderDispatchReceipt::verify_echo`] re-proves that echo
//! against the locally held dispatch before any caller may treat it as
//! admission.
//!
//! I7.20: every non-success disposition carries the exact `reason_code` from
//! the projected registry, spelled here as frozen constants rather than a
//! second local registry. `reason_code` is mandatory and non-empty whenever
//! `disposition != Admitted`, and forbidden to be silently present on an
//! admitted receipt.

use eliot_contracts::{ContractVersion, EpochId, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of the research-provider front-door wire.
pub const RESEARCH_PROVIDER_WIRE_ID: &str = "eliot.kernel.research-provider";
/// Current version of the research-provider dispatch wire. An unknown version
/// is rejected, never promoted.
pub const RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION: &str = "eliot-kernel-research-provider/v1";

/// Closed operation set owned by this route. Each names a contract selector,
/// not a local command authority.
pub const RESEARCH_PROVIDER_DISPATCH_OPERATION: &str = "research_provider.dispatch";
/// Requests the current terminal classification of one admitted operation.
pub const RESEARCH_PROVIDER_STATUS_OPERATION: &str = "research_provider.status";
/// Requests cancellation of one admitted operation by stable identity.
pub const RESEARCH_PROVIDER_CANCEL_OPERATION: &str = "research_provider.cancel";
/// Requests unknown-outcome reconciliation of one admitted operation.
pub const RESEARCH_PROVIDER_RECONCILE_OPERATION: &str = "research_provider.reconcile";

/// Every operation selector owned by the research-provider route.
pub const RESEARCH_PROVIDER_OPERATIONS: [&str; 4] = [
    RESEARCH_PROVIDER_DISPATCH_OPERATION,
    RESEARCH_PROVIDER_STATUS_OPERATION,
    RESEARCH_PROVIDER_CANCEL_OPERATION,
    RESEARCH_PROVIDER_RECONCILE_OPERATION,
];

// I7.20 `reason_code` spellings, reused verbatim from the projected registry
// rather than introducing a research-local code set.
/// The research source or its provider is unavailable in this scope.
pub const REASON_RESEARCH_SOURCE_UNAVAILABLE: &str = "RESEARCH_SOURCE_UNAVAILABLE";
/// No admitted provider capability is registered for this scope.
pub const REASON_CAPABILITY_UNAVAILABLE: &str = "CAPABILITY_UNAVAILABLE";
/// Presented Authority Epoch disagrees with the live Kernel epoch.
pub const REASON_STALE_AUTHORITY_EPOCH: &str = "STALE_AUTHORITY_EPOCH";
/// Presented State Fence is not compatible with the session fence.
pub const REASON_STALE_STATE_FENCE: &str = "STALE_STATE_FENCE";
/// Presented identity disagrees with the admitted identity.
pub const REASON_IDENTITY_CONFLICT: &str = "IDENTITY_CONFLICT";
/// Cancellation was requested but its terminal state is unconfirmed.
pub const REASON_CANCELLATION_UNCONFIRMED: &str = "CANCELLATION_UNCONFIRMED";
/// The external provider outcome is unresolved and needs reconciliation.
pub const REASON_UNKNOWN_OUTCOME: &str = "UNKNOWN_OUTCOME";
/// The presented envelope is not the admitted wire shape.
pub const REASON_INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
/// The presented request is refused by policy or the disclosure boundary.
pub const REASON_POLICY_DENIED: &str = "POLICY_DENIED";
/// The provider spoke a wire the bridge does not admit.
pub const REASON_PROTOCOL_INCOMPATIBLE: &str = "PROTOCOL_INCOMPATIBLE";
/// The bounded run exceeded its admitted deadline.
pub const REASON_DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
/// The provider process or its execution contour failed.
pub const REASON_RUNTIME_FAILED: &str = "RUNTIME_FAILED";
/// The retained evidence is incomplete for the claimed outcome.
pub const REASON_INSTRUMENT_EVIDENCE_INCOMPLETE: &str = "INSTRUMENT_EVIDENCE_INCOMPLETE";

/// Maximum length of a bounded presented identity field, in UTF-8 bytes.
pub const RESEARCH_PROVIDER_MAX_TEXT: usize = 1_024;

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str) -> Result<(), ResearchProviderError> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > RESEARCH_PROVIDER_MAX_TEXT
    {
        return Err(ResearchProviderError::MalformedDispatch);
    }
    Ok(())
}

/// Terminal disposition of one research-provider front-door operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResearchProviderDisposition {
    /// The live Kernel authority admitted exactly this presented binding.
    Admitted,
    /// Presentation shape is not the admitted wire; nothing was admitted.
    Malformed,
    /// The presented Authority Epoch is not the live authority.
    StaleEpoch,
    /// The presented State Fence is not compatible with the session fence.
    StaleFence,
    /// The presented identity conflicts with the admitted identity.
    IdentityConflict,
    /// No provider capability is admitted in this scope.
    Unavailable,
    /// The operation has no current owner; the outcome must be reconciled.
    UnknownOutcome,
}

impl ResearchProviderDisposition {
    /// Returns whether this disposition grants provider admission.
    pub const fn admits(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// Returns the exact I7.20 `reason_code` for a non-success disposition.
    ///
    /// An admitted disposition carries no reason code, and
    /// [`ResearchProviderDispatchReceipt::validate`] refuses an admitted
    /// receipt that has one, so the mapping is only ever consulted for a
    /// non-success disposition. `Admitted` and `Malformed` share the
    /// `INVALID_ARGUMENT` spelling: neither is a refusal with a more specific
    /// cause, and inventing a distinct code for the success case would
    /// advertise a reason for an admission that has none.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Admitted | Self::Malformed => REASON_INVALID_ARGUMENT,
            Self::StaleEpoch => REASON_STALE_AUTHORITY_EPOCH,
            Self::StaleFence => REASON_STALE_STATE_FENCE,
            Self::IdentityConflict => REASON_IDENTITY_CONFLICT,
            Self::Unavailable => REASON_CAPABILITY_UNAVAILABLE,
            Self::UnknownOutcome => REASON_UNKNOWN_OUTCOME,
        }
    }
}

/// Typed reason one research-provider dispatch was refused or returned.
///
/// Every variant names its cause; a stale, foreign, or unknown presentation is
/// rejected, never default-accepted.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResearchProviderError {
    /// The presented envelope is blank, overlong, or structurally invalid.
    #[error("malformed research provider presentation")]
    MalformedDispatch,
    /// The presented wire version differs from the admitted version.
    #[error("research provider wire version mismatch")]
    WireVersionMismatch,
    /// The presented Authority Epoch is not the live Kernel authority.
    #[error("stale research provider authority epoch")]
    StaleEpoch,
    /// The presented State Fence is not compatible with the session fence.
    #[error("stale research provider state fence")]
    StaleFence,
    /// The receipt does not echo the presented binding exactly.
    #[error("research provider receipt does not echo the presented binding")]
    EchoMismatch,
    /// The receipt's own canonical digest does not match its content.
    #[error("research provider receipt digest mismatch")]
    ReceiptDigestMismatch,
    /// A non-success disposition omitted its exact reason code.
    #[error("research provider non-success response has no reason code")]
    MissingReasonCode,
    /// An admitted disposition carried a reason code.
    #[error("research provider admitted response carries a reason code")]
    UnexpectedReasonCode,
}

/// One bounded research-provider dispatch request presented to the Kernel.
///
/// Every field is caller-presented and re-verified; nothing here is trusted by
/// value. The executable path travels as *admitted material* only: it is the
/// Kernel-issued provider generation's exact immutable artifact identity, bound
/// to its content digest, and it is never resolved from ambient environment,
/// task text, or stdin.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchProviderDispatch {
    /// Stable wire identity of this presentation.
    pub wire_id: String,
    /// Exact wire version; must equal [`RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION`].
    pub wire_version: String,
    /// Stable admitted operation identity. It is the only identity cancel,
    /// status, and reconciliation key on; a provider-local job reference is
    /// never an identity.
    pub operation_id: String,
    /// Cancellation identity for this operation's lifecycle.
    pub cancellation_id: String,
    /// Exchange correlation for the bounded inquiry.
    pub exchange_id: String,
    /// Idempotency key for the same logical dispatch across retries.
    pub idempotency_key: String,
    /// Module/Capability Registry evidence reference for the provider.
    pub module_id: String,
    /// Module generation evidence reference for the provider.
    pub module_generation_id: String,
    /// Bridge generation echo the exchange request must carry exactly.
    pub bridge_generation: String,
    /// Exact immutable provider executable admitted by that generation.
    pub executable_path: String,
    /// Content digest of the admitted provider executable.
    pub executable_sha256: String,
    /// Exact admitted provider configuration digest.
    pub config_digest: String,
    /// Exact admitted provider protocol digest.
    pub protocol_digest: String,
    /// Admitted process generation. Zero is never a valid generation.
    pub process_generation: u64,
    /// Authority Epoch the dispatch is presented under.
    pub authority_epoch: EpochId,
    /// State Fence the dispatch is presented under.
    pub state_fence: StateFence,
    /// Privacy/data-class wire name admitted for this dispatch.
    pub disclosure: String,
    /// Admitted budget ceiling in provider units.
    pub budget_units: u64,
    /// Admitted deadline ceiling in milliseconds.
    pub deadline_ms: i64,
    /// Admitted provider protocol revision.
    pub protocol_revision: ContractVersion,
    /// Admitted required result schema.
    pub required_schema: String,
    /// Digest of the frozen Researcher inquiry.
    pub inquiry_digest: String,
    /// Digest of the admitted source portfolio / coverage denominator.
    ///
    /// A coverage or absence claim must name its scope, revision, and the
    /// method by which the denominator can be checked independently (A05.07);
    /// this digest is that independently checkable handle, so a dispatch can
    /// never be admitted against an undeclared denominator.
    pub denominator_digest: String,
}

impl ResearchProviderDispatch {
    /// Validates the closed presentation shape without consulting authority.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchProviderError::WireVersionMismatch`] for a wrong wire
    /// version and [`ResearchProviderError::MalformedDispatch`] for blank,
    /// control-bearing, overlong, non-positive, or malformed-digest material.
    pub fn validate(&self) -> Result<(), ResearchProviderError> {
        if self.wire_id != RESEARCH_PROVIDER_WIRE_ID {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        if self.wire_version != RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION {
            return Err(ResearchProviderError::WireVersionMismatch);
        }
        for text in [
            &self.operation_id,
            &self.cancellation_id,
            &self.exchange_id,
            &self.idempotency_key,
            &self.module_id,
            &self.module_generation_id,
            &self.bridge_generation,
            &self.executable_path,
            &self.disclosure,
            &self.required_schema,
        ] {
            validate_wire_text(text)?;
        }
        for digest in [
            &self.executable_sha256,
            &self.config_digest,
            &self.protocol_digest,
            &self.inquiry_digest,
            &self.denominator_digest,
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(ResearchProviderError::MalformedDispatch);
            }
        }
        if self.process_generation == 0 || self.budget_units == 0 || self.deadline_ms <= 0 {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| ResearchProviderError::MalformedDispatch)?;
        if !self
            .state_fence
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        Ok(())
    }

    /// Returns the canonical SHA-256 digest over the exact presented bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchProviderError::MalformedDispatch`] when the dispatch
    /// cannot be encoded as canonical JSON.
    pub fn canonical_sha256(&self) -> Result<String, ResearchProviderError> {
        let bytes =
            canonical_json_bytes(self).map_err(|_| ResearchProviderError::MalformedDispatch)?;
        Ok(sha256_hex(&bytes))
    }
}

/// Sealed receipt the Kernel issues for one presented research dispatch.
///
/// The receipt proves exactly one thing: the live Kernel authority, on the
/// authenticated session, admitted this precise request digest under this
/// Authority Epoch, generation, and State Fence, at this instant. It proves no
/// source coverage, no disclosure permission for a bundle, no task progress,
/// and no finish.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchProviderDispatchReceipt {
    /// Stable wire identity echoed from the presentation.
    pub wire_id: String,
    /// Exact wire version echoed from the presentation.
    pub wire_version: String,
    /// Closed receipt kind discriminator.
    pub kind: String,
    /// Terminal disposition of the presentation.
    pub disposition: ResearchProviderDisposition,
    /// Exact I7.20 reason code; mandatory and non-empty unless admitted.
    pub reason_code: String,
    /// Stable operation identity echoed from the presentation.
    pub operation_id: String,
    /// Cancellation identity echoed from the presentation.
    pub cancellation_id: String,
    /// Canonical digest of the exact admitted dispatch bytes.
    pub request_sha256: String,
    /// Live authority epoch this receipt was admitted under.
    pub admitted_authority_epoch: EpochId,
    /// Admitted process generation echoed from the presentation.
    pub admitted_generation: u64,
    /// Admitted State Fence echoed from the presentation.
    pub admitted_fence: StateFence,
    /// Admission instant in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Canonical digest over every other field of this receipt.
    pub receipt_digest: String,
}

impl ResearchProviderDispatchReceipt {
    /// Closed receipt kind discriminator.
    pub const RECEIPT_KIND: &'static str = "research_provider_dispatch";

    /// Returns the canonical digest over the receipt content, excluding
    /// `receipt_digest` itself.
    ///
    /// Public because the composition route seals receipts through this owner
    /// primitive rather than re-deriving the digest recipe locally: a second
    /// recipe would be a second contract.
    pub fn compute_digest(&self) -> Result<String, ResearchProviderError> {
        let mut content = self.clone();
        content.receipt_digest = String::new();
        let bytes =
            canonical_json_bytes(&content).map_err(|_| ResearchProviderError::MalformedDispatch)?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates the closed receipt shape and its own canonical digest.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchProviderError::MalformedDispatch`] for blank or
    /// malformed material, [`ResearchProviderError::WireVersionMismatch`] for
    /// a wrong wire version, [`ResearchProviderError::MissingReasonCode`] for a
    /// non-success disposition without an exact reason code,
    /// [`ResearchProviderError::UnexpectedReasonCode`] for an admitted
    /// disposition that carries one, and
    /// [`ResearchProviderError::ReceiptDigestMismatch`] when the sealed digest
    /// does not match the content.
    pub fn validate(&self) -> Result<(), ResearchProviderError> {
        if self.wire_id != RESEARCH_PROVIDER_WIRE_ID {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        if self.wire_version != RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION {
            return Err(ResearchProviderError::WireVersionMismatch);
        }
        if self.kind != Self::RECEIPT_KIND {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        for text in [&self.operation_id, &self.cancellation_id] {
            validate_wire_text(text)?;
        }
        if !is_lowercase_sha256(&self.request_sha256) {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        if self.admitted_generation == 0 || self.admitted_at_unix_ms == 0 {
            return Err(ResearchProviderError::MalformedDispatch);
        }
        self.admitted_fence
            .validate()
            .map_err(|_| ResearchProviderError::MalformedDispatch)?;
        if self.disposition.admits() {
            if !self.reason_code.is_empty() {
                return Err(ResearchProviderError::UnexpectedReasonCode);
            }
        } else if self.reason_code != self.disposition.reason_code() {
            return Err(ResearchProviderError::MissingReasonCode);
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(ResearchProviderError::ReceiptDigestMismatch);
        }
        Ok(())
    }

    /// Re-proves that this receipt admits exactly the held dispatch.
    ///
    /// A caller must run this before the receipt may become an execution
    /// admission: a reachable pipe, a `200`-shaped reply, and a well-formed
    /// digest are each insufficient on their own. The check is exact on
    /// operation identity, cancellation identity, request digest, admitted
    /// generation, State Fence, and Authority Epoch (through
    /// `is_same_authority`, never a raw sequence compare), and it refuses any
    /// non-admitted disposition.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchProviderError::EchoMismatch`] when any echoed binding
    /// disagrees with the held dispatch or the disposition is not `Admitted`,
    /// and any error from [`ResearchProviderDispatchReceipt::validate`].
    pub fn verify_echo(
        &self,
        dispatch: &ResearchProviderDispatch,
    ) -> Result<(), ResearchProviderError> {
        self.validate()?;
        if !self.disposition.admits()
            || self.operation_id != dispatch.operation_id
            || self.cancellation_id != dispatch.cancellation_id
            || self.request_sha256 != dispatch.canonical_sha256()?
            || self.admitted_generation != dispatch.process_generation
            || self.admitted_fence != dispatch.state_fence
            || !self
                .admitted_authority_epoch
                .is_same_authority(&dispatch.authority_epoch)
        {
            return Err(ResearchProviderError::EchoMismatch);
        }
        Ok(())
    }
}
