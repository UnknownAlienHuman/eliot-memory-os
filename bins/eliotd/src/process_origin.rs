//! Governor-owned process-origin evidence view, separate from control authority.
//!
//! Issue #1960: a known path/port/process triple is **observable** but never
//! **controllable** on the strength of observation alone. Observation answers
//! what was seen; control authority is held and evaluated exclusively by the
//! governed Kernel path ([`GovernedKernelAuthority`]).
//!
//! Rework notes (Opus audit of `b4e73def`, PR #2246, CHANGES x2):
//!
//! - Forgeable receipts: [`OwnershipChallengeReceipt`] used to be
//!   caller-constructible (public fields plus an exported digest helper that
//!   recomputed the exact receipt digest), so any caller could mint a
//!   well-formed challenge. Challenges are now Governor/Kernel-issued
//!   capabilities: the struct exposes no public fields, no public
//!   constructor, and no `Deserialize` implementation, so callers can neither
//!   write a struct literal nor rehydrate one from JSON. Minting happens only
//!   through [`OwnershipChallengeIssuer::issue`], which binds a secret-held
//!   issuer tag and records the mint in the issuer-owned store. Verification
//!   ([`OwnershipChallengeIssuer::verify`]) requires that issuer-bound proof:
//!   the tag recomputed with the issuer secret plus a live registry entry.
//!   A reproduced digest alone authorizes nothing.
//! - Parallel authority plane: the old gate decided `ForwardableToKernel`
//!   inside `eliotd`, duplicating the control-authority decision outside the
//!   governed Kernel path. This module is now an evidence view under the
//!   Governor-owned `CapabilityEvidenceRecord` (I03-04, "Capability
//!   evidence"): [`ProcessOriginEvidence::capability_view`] projects an
//!   observation into a [`ProcessCapabilityEvidence`] record, and
//!   [`gate_process_control`] only routes evidence:
//!   [`OperationDisposition::Observed`],
//!   [`OperationDisposition::NeedsKernelDecision`], or
//!   [`OperationDisposition::Denied`]. It never authorizes. The single
//!   authority evaluation lives in
//!   [`GovernedKernelAuthority::decide_forward`] and
//!   [`GovernedKernelAuthority::authorize_shutdown`], which return an opaque
//!   [`KernelAuthorization`] proof token. The `eliotd` side only packages
//!   evidence with [`prepare_kernel_forward`] and forwards it.
//!
//! Daemon flow: [`gate_process_control`] (route evidence) ->
//! [`prepare_kernel_forward`] (attach the challenge; completeness only) ->
//! neutral authenticated Kernel port ->
//! [`GovernedKernelAuthority::decide_forward`] (exclusive authority) ->
//! [`KernelAuthorization`] (proof token for the port call).
//!
//! This module performs no I/O and retains no threads. The issuer and the
//! authority retain only the Governor/Kernel-owned challenge store; receipts
//! themselves stay dumb capabilities validated field-for-field before use.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use eliot_contracts::{StateFence, fences_match_exact, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Capability name projected by [`ProcessOriginEvidence::capability_view`].
///
/// Names the evidence view, not a control right: observation only.
pub const PROCESS_ORIGIN_CAPABILITY: &str = "process-origin-observation";

/// Maximum lifetime of one ownership challenge: one hour in milliseconds.
///
/// Challenges stay short-lived on purpose; longer windows must be re-issued.
const MAX_CHALLENGE_WINDOW_MS: u64 = 3_600_000;

/// Maximum accepted issuer identity length.
const MAX_ISSUER_ID_LEN: usize = 64;

/// Errors raised by the process-origin evidence view and the governed authority.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessOriginError {
    /// An evidence, challenge, or receipt field is malformed.
    #[error("process-origin contract: {0}")]
    Contract(String),
    /// No challenge was attached for an operation that needs authority.
    #[error("process-origin denied: control requires a current matching ownership challenge")]
    ChallengeRequired,
    /// The challenge was not issued by this issuer or does not bind the evidence.
    #[error(
        "process-origin denied: ownership challenge was not issued by this Governor/Kernel issuer or does not match the observed origin"
    )]
    ChallengeMismatch,
    /// The challenge is not current at the presented time.
    #[error("process-origin denied: ownership challenge is not current")]
    ChallengeNotCurrent,
    /// The challenge was revoked after issuance.
    #[error("process-origin denied: ownership challenge was revoked")]
    ChallengeRevoked,
    /// A status/read receipt was presented where control authority is required.
    #[error("process-origin denied: a read status receipt never authorizes shutdown or control")]
    StatusNeverAuthorizes,
    /// The operation is observe-only and must never be forwarded to the Kernel.
    #[error("process-origin denied: probes observe only and are never forwarded")]
    ObserveOnly,
}
/// Governor-owned observation of one process origin.
///
/// Observation only: the known path, port, and process label describe what
/// was seen. They grant no stop, adopt, mutate, or credential-attach
/// authority, and no ownership is inferred from them. The `origin_digest`
/// binds the observed triple plus the admitted fence so an issued challenge
/// can match exactly one observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOriginEvidence {
    /// Observed executable path (known-path probe answer, verbatim).
    pub observed_path: String,
    /// Observed port (known-port probe answer).
    pub observed_port: u16,
    /// Observed process label (human/process-table label, verbatim).
    pub observed_process: String,
    /// Lowercase hex SHA-256 over the canonical observed triple plus fence.
    pub origin_digest: String,
    /// Admitted fence under which the observation was taken.
    pub state_fence: StateFence,
    /// Unix milliseconds at which the observation was taken.
    pub observed_at_unix_ms: u64,
}

/// Control operation requested against an observed process origin.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ProcessControlOperation {
    /// Read-only status probe. Observe only, never forwarded.
    ReadStatus,
    /// General observation probe. Observe only, never forwarded.
    ProbeObserve,
    /// Stop the observed process. Needs a Kernel authority decision.
    Kill,
    /// Mutate the observed process. Needs a Kernel authority decision.
    Mutate,
    /// Adopt the observed process. Needs a Kernel authority decision.
    Adopt,
    /// Attach a credential to the observed process. Needs a Kernel decision.
    AttachCredential,
}

impl ProcessControlOperation {
    /// Returns whether the operation needs a Kernel authority decision backed
    /// by a current matching ownership challenge.
    ///
    /// An operation-class fact consumed by the governed authority, not a
    /// decision: answering `true` authorizes nothing.
    #[must_use]
    pub const fn requires_challenge(self) -> bool {
        match self {
            Self::ReadStatus | Self::ProbeObserve => false,
            Self::Kill | Self::Mutate | Self::Adopt | Self::AttachCredential => true,
        }
    }

    /// Returns whether the operation may ever be forwarded to the Kernel.
    /// Probes and status reads are observe-only.
    ///
    /// An operation-class fact, not a decision.
    #[must_use]
    pub const fn is_forwardable(self) -> bool {
        match self {
            Self::ReadStatus | Self::ProbeObserve => false,
            Self::Kill | Self::Mutate | Self::Adopt | Self::AttachCredential => true,
        }
    }
}

/// Governor/Kernel-issued ownership challenge receipt.
///
/// The single control capability in this module. It authorizes exactly one
/// observed origin (`origin_digest`), under exactly one fence
/// (`state_fence`), while current (`issued_at_unix_ms..=expires_at_unix_ms`
/// contains `now`). Only [`OwnershipChallengeIssuer::issue`] can mint it:
/// all fields are private, there is no public constructor, and there is no
/// `Deserialize` implementation, so callers can neither write a struct
/// literal nor rehydrate one from JSON. The `issuer_tag` binds every field
/// to the issuer secret, and the issuer store records every mint; both are
/// checked by [`OwnershipChallengeIssuer::verify`].
///
/// The `receipt_digest` is a plain content binding (reproducible by design)
/// and carries no authority on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnershipChallengeReceipt {
    /// Issuer-assigned challenge identity (`issuer_id` plus sequence).
    challenge_id: String,
    /// Origin digest this challenge binds (must equal the evidence digest).
    origin_digest: String,
    /// Fence this challenge binds (must match the evidence fence exactly).
    state_fence: StateFence,
    /// Unix milliseconds at which the challenge was issued.
    issued_at_unix_ms: u64,
    /// Unix milliseconds at which the challenge expires (inclusive).
    expires_at_unix_ms: u64,
    /// Lowercase hex SHA-256 over the canonical challenge fields.
    receipt_digest: String,
    /// Secret-bound issuer tag over every field above. Authority lives here.
    issuer_tag: String,
}

impl OwnershipChallengeReceipt {
    /// Returns the issuer-assigned challenge identity.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Returns the bound origin digest.
    #[must_use]
    pub fn origin_digest(&self) -> &str {
        &self.origin_digest
    }

    /// Returns the bound fence.
    #[must_use]
    pub fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the issuance time.
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// Returns the expiry time (inclusive).
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Returns the content binding digest (no authority).
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    /// Returns the secret-bound issuer tag (the authority proof).
    #[must_use]
    pub fn issuer_tag(&self) -> &str {
        &self.issuer_tag
    }

    /// Returns whether the challenge window contains `now_unix_ms`.
    ///
    /// Currency alone, without [`OwnershipChallengeIssuer::verify`], proves
    /// nothing: only the issuer-bound check authorizes.
    #[must_use]
    pub const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.issued_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }

    /// Validates field shapes and the content binding only.
    ///
    /// Completeness for packaging, never authority: no secret, no clock, no
    /// registry. Anything this accepts must still pass
    /// [`OwnershipChallengeIssuer::verify`] before any control effect.
    pub fn validate_shape(&self) -> Result<(), ProcessOriginError> {
        if self.challenge_id.trim().is_empty() || self.challenge_id.len() > 128 {
            return Err(ProcessOriginError::Contract(
                "challenge_id must be a bounded token".to_owned(),
            ));
        }
        let id_ok = self.challenge_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == 35 || byte == 45 || byte == 46 || byte == 95
        });
        if !id_ok {
            return Err(ProcessOriginError::Contract(
                "challenge_id must be a bounded token".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        validate_digest(&self.receipt_digest, "receipt_digest")?;
        validate_digest(&self.issuer_tag, "issuer_tag")?;
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.expires_at_unix_ms < self.issued_at_unix_ms {
            return Err(ProcessOriginError::Contract(
                "expires_at_unix_ms must not precede issued_at_unix_ms".to_owned(),
            ));
        }
        let expected = canonical_challenge_digest(
            &self.challenge_id,
            &self.origin_digest,
            &self.state_fence,
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
        );
        if self.receipt_digest != expected {
            return Err(ProcessOriginError::Contract(
                "receipt_digest does not bind the challenge fields".to_owned(),
            ));
        }
        Ok(())
    }
}
/// Read-only status receipt for an observed process origin.
///
/// Observation answer only: it reports what a status probe saw. It carries
/// no challenge, no issuer tag, and no control capability. There is
/// deliberately **no** constructor or conversion from this type into anything
/// [`prepare_kernel_forward`] or [`GovernedKernelAuthority`] accepts: type
/// shape alone keeps a status receipt from authorizing shutdown or control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStatusReceipt {
    /// Origin digest the status was read from.
    pub origin_digest: String,
    /// Fence echoed from the observation (verbatim, not authority).
    pub state_fence: StateFence,
    /// Bounded status projection (e.g. `"running"`, `"unknown"`).
    pub status: String,
    /// Unix milliseconds at which the status was read.
    pub read_at_unix_ms: u64,
}

impl ProcessStatusReceipt {
    /// Validates the status receipt as an observation answer only.
    pub fn validate(&self) -> Result<(), ProcessOriginError> {
        if self.status.trim().is_empty() || self.status.len() > 64 {
            return Err(ProcessOriginError::Contract(
                "status must be a nonempty bounded projection".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.read_at_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "read_at_unix_ms must be nonzero".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        Ok(())
    }
}

/// Currency of a capability evidence record (I03-04, "Capability evidence").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityEvidenceStatus {
    /// Directly observed and currently held.
    Observed,
    /// Observed, then contradicted or aged by newer evidence.
    Degraded,
    /// No usable observation on the exact fingerprint.
    Unknown,
}

/// Provenance of a capability evidence record (I03-04, "Capability evidence").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityEvidenceSource {
    /// Live production observation (this module only ever emits this).
    ProductionObservation,
}

/// Process-origin observation projected as a `CapabilityEvidenceRecord` view.
///
/// This is the I03-04 evidence shape (`capability`, `status`, `source`,
/// `scope_fingerprint`, limitations, `evidence_refs`, `observed_at`,
/// `expires_at`), narrowed to process attribution. It is a view, not a
/// registry: current availability and admission are derived only by the
/// Governor-owned Capability Registry view, and this record never carries
/// control authority. Staleness is derived there too: `expires_at_unix_ms`
/// echoes the observation time (a point observation), it does not decide
/// currency for control — only a current issuer-verified challenge does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCapabilityEvidence {
    /// Observed capability name (always [`PROCESS_ORIGIN_CAPABILITY`]).
    pub capability: String,
    /// Evidence currency (observations are emitted as `Observed`).
    pub status: CapabilityEvidenceStatus,
    /// Evidence provenance (always `ProductionObservation`).
    pub source: CapabilityEvidenceSource,
    /// Exact scope this evidence speaks for: the bound origin digest.
    pub scope_fingerprint: String,
    /// What this evidence must never be used for (observation only).
    pub limitations: String,
    /// Human-readable evidence references (digest and observation time).
    pub evidence_refs: Vec<String>,
    /// Unix milliseconds at which the observation was taken.
    pub observed_at_unix_ms: u64,
    /// Point-observation marker: echoes `observed_at_unix_ms`.
    pub expires_at_unix_ms: u64,
}

/// Pure policy-step outcome for one gated operation.
///
/// Computed by [`gate_process_control`] from evidence alone, before any
/// Kernel contact. Either the operation was observe-only
/// ([`OperationDisposition::Observed`]), it carries complete evidence for the
/// governed Kernel path to decide
/// ([`OperationDisposition::NeedsKernelDecision`]), or the evidence itself is
/// malformed ([`OperationDisposition::Denied`]). There is deliberately no
/// forwardable/authorized outcome here: authorizing is the exclusive job of
/// [`GovernedKernelAuthority::decide_forward`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationDisposition {
    /// Observe-only outcome: answered from evidence, never forwarded.
    Observed,
    /// Evidence is complete; forward it so the governed Kernel path decides.
    /// Carries the evidence view, never an authorization.
    NeedsKernelDecision {
        /// Capability evidence view bound to the gated observation.
        evidence: ProcessCapabilityEvidence,
    },
    /// Denied with an explicit fail-closed reason (malformed evidence only).
    Denied {
        /// Machine-readable denial reason.
        reason: &'static str,
    },
}

/// Computes the canonical origin digest over the observed triple plus fence.
#[must_use]
pub fn canonical_origin_digest(path: &str, port: u16, process: &str, fence: &StateFence) -> String {
    let fence_bytes = serde_json::to_vec(fence).unwrap_or_default();
    let mut canonical = Vec::with_capacity(path.len() + process.len() + fence_bytes.len() + 16);
    canonical.extend_from_slice(path.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&port.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(process.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&fence_bytes);
    sha256_hex(&canonical)
}

/// Computes the canonical challenge content binding (no authority).
///
/// Private: the binding is reproducible by design and must never be mistaken
/// for issuance proof. Authority comes only from the secret-bound issuer tag
/// plus the issuer store (see [`OwnershipChallengeIssuer::verify`]).
fn canonical_challenge_digest(
    challenge_id: &str,
    origin_digest: &str,
    fence: &StateFence,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> String {
    let fence_bytes = serde_json::to_vec(fence).unwrap_or_default();
    let mut canonical =
        Vec::with_capacity(challenge_id.len() + origin_digest.len() + fence_bytes.len() + 32);
    canonical.extend_from_slice(challenge_id.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(origin_digest.as_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&fence_bytes);
    canonical.push(0);
    canonical.extend_from_slice(&issued_at_unix_ms.to_be_bytes());
    canonical.push(0);
    canonical.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    sha256_hex(&canonical)
}

/// Computes the secret-bound issuer tag: the actual issuance proof.
///
/// Binds the issuer secret to the full canonical challenge content, so only
/// the secret holder (the Governor/Kernel-owned issuer) can mint tags that
/// [`OwnershipChallengeIssuer::verify`] accepts.
fn issuer_tag_for(
    secret: &[u8; 32],
    challenge_id: &str,
    origin_digest: &str,
    fence: &StateFence,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> String {
    let content = canonical_challenge_digest(
        challenge_id,
        origin_digest,
        fence,
        issued_at_unix_ms,
        expires_at_unix_ms,
    );
    let mut material = Vec::with_capacity(32 + 1 + content.len());
    material.extend_from_slice(secret);
    material.push(0);
    material.extend_from_slice(content.as_bytes());
    sha256_hex(&material)
}

fn validate_digest(value: &str, field: &str) -> Result<(), ProcessOriginError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProcessOriginError::Contract(format!(
            "{field} must be lowercase hex sha256"
        )));
    }
    Ok(())
}
impl ProcessOriginEvidence {
    /// Validates the observation record field-for-field.
    ///
    /// Validation proves the record is well-formed; it never proves control
    /// authority. A valid record authorizes observation answers only.
    pub fn validate(&self) -> Result<(), ProcessOriginError> {
        if self.observed_path.trim().is_empty() {
            return Err(ProcessOriginError::Contract(
                "observed_path must not be empty".to_owned(),
            ));
        }
        if self.observed_path.contains("..") {
            return Err(ProcessOriginError::Contract(
                "observed_path must not contain parent traversal".to_owned(),
            ));
        }
        if self.observed_port == 0 {
            return Err(ProcessOriginError::Contract(
                "observed_port must be nonzero".to_owned(),
            ));
        }
        if self.observed_process.trim().is_empty() {
            return Err(ProcessOriginError::Contract(
                "observed_process must not be empty".to_owned(),
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| ProcessOriginError::Contract(format!("state_fence: {error}")))?;
        if self.observed_at_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "observed_at_unix_ms must be nonzero".to_owned(),
            ));
        }
        validate_digest(&self.origin_digest, "origin_digest")?;
        let expected = canonical_origin_digest(
            &self.observed_path,
            self.observed_port,
            &self.observed_process,
            &self.state_fence,
        );
        if self.origin_digest != expected {
            return Err(ProcessOriginError::Contract(
                "origin_digest does not bind the observed triple and fence".to_owned(),
            ));
        }
        Ok(())
    }

    /// Projects this observation into a `CapabilityEvidenceRecord` view.
    ///
    /// The view carries the observation plus its scope and limits; it never
    /// carries control authority. Current availability and admission stay
    /// with the Governor-owned Capability Registry view.
    pub fn capability_view(&self) -> Result<ProcessCapabilityEvidence, ProcessOriginError> {
        self.validate()?;
        let origin_digest = self.origin_digest.clone();
        let observed_at_unix_ms = self.observed_at_unix_ms;
        Ok(ProcessCapabilityEvidence {
            capability: PROCESS_ORIGIN_CAPABILITY.to_owned(),
            status: CapabilityEvidenceStatus::Observed,
            source: CapabilityEvidenceSource::ProductionObservation,
            scope_fingerprint: origin_digest.clone(),
            limitations: "observation only: answers what was seen and never authorizes control; currency and admission are derived by the Governor-owned Capability Registry view".to_owned(),
            evidence_refs: vec![
                format!("origin-digest:{origin_digest}"),
                format!("observed-at:{observed_at_unix_ms}"),
            ],
            observed_at_unix_ms,
            expires_at_unix_ms: observed_at_unix_ms,
        })
    }
}
/// One issuer-recorded mint: the store-bound half of the issuance proof.
#[derive(Clone, Debug, PartialEq, Eq)]
struct IssuedChallenge {
    /// Origin digest the challenge was bound to at mint time.
    origin_digest: String,
    /// Fence the challenge was bound to at mint time.
    state_fence: StateFence,
    /// Mint issuance time.
    issued_at_unix_ms: u64,
    /// Mint expiry time (inclusive).
    expires_at_unix_ms: u64,
    /// Set by revoke; revoked challenges never verify.
    revoked: bool,
}
/// Governor/Kernel-owned ownership-challenge issuer and issuance store.
///
/// The only minter of challenge receipts: issue binds the exact observation,
/// stamps a secret-held issuer tag, and records the mint. Verify re-checks
/// the tag with the secret and requires a live, unrevoked registry entry,
/// so verification needs issuer-bound proof: a reproduced digest alone fails.
/// The secret never leaves this object (Debug redacts it) and the store
/// never leaves Governor/Kernel ownership.
#[derive(Clone)]
pub struct OwnershipChallengeIssuer {
    /// Stable issuer identity, stamped into every challenge identity.
    issuer_id: String,
    /// Issuer secret for the tag. Redacted from Debug, never serialized.
    secret: [u8; 32],
    /// Next mint sequence number.
    next_sequence: u64,
    /// Every mint, keyed by challenge identity.
    issued: HashMap<String, IssuedChallenge>,
}

impl std::fmt::Debug for OwnershipChallengeIssuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .debug_struct("OwnershipChallengeIssuer")
            .field("issuer_id", &self.issuer_id)
            .field("next_sequence", &self.next_sequence)
            .field("issued", &self.issued)
            .field("secret", &"REDACTED")
            .finish()
    }
}
impl OwnershipChallengeIssuer {
    /// Creates an issuer for the given identity holding the given secret.
    ///
    /// Rejects blank or unbounded identities and the all-zero secret, so a
    /// null-secret deployment fails closed at construction.
    pub fn new(issuer_id: String, secret: [u8; 32]) -> Result<Self, ProcessOriginError> {
        let id_ok = !issuer_id.trim().is_empty()
            && issuer_id.len() <= MAX_ISSUER_ID_LEN
            && issuer_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == 45 || byte == 46 || byte == 95);
        if !id_ok {
            return Err(ProcessOriginError::Contract(
                "issuer_id must be a bounded alphanumeric token".to_owned(),
            ));
        }
        if secret == [0_u8; 32] {
            return Err(ProcessOriginError::Contract(
                "issuer secret must not be all zeros".to_owned(),
            ));
        }
        Ok(Self {
            issuer_id,
            secret,
            next_sequence: 1,
            issued: HashMap::new(),
        })
    }

    /// Returns the issuer identity stamped into minted challenges.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Returns how many challenges this issuer has minted.
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }
    /// Mints a challenge bound to exactly one observation.
    ///
    /// Validates the evidence, enforces a sane short-lived window, stamps a
    /// fresh challenge identity with the secret-bound issuer tag, and records
    /// the mint in the issuer store. The returned receipt verifies only
    /// against this issuer: same secret plus a live registry entry.
    pub fn issue(
        &mut self,
        evidence: &ProcessOriginEvidence,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<OwnershipChallengeReceipt, ProcessOriginError> {
        evidence.validate()?;
        if issued_at_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "issued_at_unix_ms must be nonzero".to_owned(),
            ));
        }
        if expires_at_unix_ms < issued_at_unix_ms {
            return Err(ProcessOriginError::Contract(
                "expires_at_unix_ms must not precede issued_at_unix_ms".to_owned(),
            ));
        }
        if expires_at_unix_ms - issued_at_unix_ms > MAX_CHALLENGE_WINDOW_MS {
            return Err(ProcessOriginError::Contract(
                "challenge window must not exceed one hour".to_owned(),
            ));
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            ProcessOriginError::Contract("challenge sequence exhausted".to_owned())
        })?;
        let issuer_id = self.issuer_id.clone();
        let challenge_id = format!("{issuer_id}#{sequence:08x}");
        let origin_digest = evidence.origin_digest.clone();
        let state_fence = evidence.state_fence.clone();
        let receipt_digest = canonical_challenge_digest(
            &challenge_id,
            &origin_digest,
            &state_fence,
            issued_at_unix_ms,
            expires_at_unix_ms,
        );
        let issuer_tag = issuer_tag_for(
            &self.secret,
            &challenge_id,
            &origin_digest,
            &state_fence,
            issued_at_unix_ms,
            expires_at_unix_ms,
        );
        self.issued.insert(
            challenge_id.clone(),
            IssuedChallenge {
                origin_digest: origin_digest.clone(),
                state_fence: state_fence.clone(),
                issued_at_unix_ms,
                expires_at_unix_ms,
                revoked: false,
            },
        );
        Ok(OwnershipChallengeReceipt {
            challenge_id,
            origin_digest,
            state_fence,
            issued_at_unix_ms,
            expires_at_unix_ms,
            receipt_digest,
            issuer_tag,
        })
    }

    /// Revokes a minted challenge: it verifies never again.
    ///
    /// Idempotent for already-revoked identities; unknown identities fail
    /// closed so a typo cannot silently pass as a revocation.
    pub fn revoke(&mut self, challenge_id: &str) -> Result<(), ProcessOriginError> {
        match self.issued.get_mut(challenge_id) {
            Some(entry) => {
                entry.revoked = true;
                Ok(())
            }
            None => Err(ProcessOriginError::Contract(
                "unknown challenge_id".to_owned(),
            )),
        }
    }
    /// Verifies a receipt against issuer-bound proof and the observation.
    ///
    /// Requires all of: well-formed receipt and evidence, a registry entry
    /// minted by this issuer whose recorded fields match the receipt
    /// exactly, no revocation, a tag recomputed with the issuer secret, a
    /// live window at now, and an exact digest plus exact fence bind to the
    /// evidence. A reproduced digest with no mint and no tag fails with a
    /// mismatch.
    pub fn verify(
        &self,
        receipt: &OwnershipChallengeReceipt,
        evidence: &ProcessOriginEvidence,
        now_unix_ms: u64,
    ) -> Result<(), ProcessOriginError> {
        receipt.validate_shape()?;
        evidence.validate()?;
        if now_unix_ms == 0 {
            return Err(ProcessOriginError::Contract(
                "now_unix_ms must be nonzero".to_owned(),
            ));
        }
        let entry = self
            .issued
            .get(receipt.challenge_id())
            .ok_or(ProcessOriginError::ChallengeMismatch)?;
        if entry.revoked {
            return Err(ProcessOriginError::ChallengeRevoked);
        }
        if entry.origin_digest != receipt.origin_digest()
            || !fences_match_exact(&entry.state_fence, receipt.state_fence())
            || entry.issued_at_unix_ms != receipt.issued_at_unix_ms()
            || entry.expires_at_unix_ms != receipt.expires_at_unix_ms()
        {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        let expected_tag = issuer_tag_for(
            &self.secret,
            receipt.challenge_id(),
            receipt.origin_digest(),
            receipt.state_fence(),
            receipt.issued_at_unix_ms(),
            receipt.expires_at_unix_ms(),
        );
        if receipt.issuer_tag() != expected_tag {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        if !(receipt.issued_at_unix_ms()..=receipt.expires_at_unix_ms()).contains(&now_unix_ms) {
            return Err(ProcessOriginError::ChallengeNotCurrent);
        }
        if receipt.origin_digest() != evidence.origin_digest {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        if !fences_match_exact(receipt.state_fence(), &evidence.state_fence) {
            return Err(ProcessOriginError::ChallengeMismatch);
        }
        Ok(())
    }
}
/// Pure policy step: routes one operation against one observed origin.
///
/// Takes evidence and the operation class only: there is deliberately no
/// challenge input, so this step cannot authorize. Read-only operations
/// resolve to [`OperationDisposition::Observed`]; control operations with
/// well-formed evidence resolve to
/// [`OperationDisposition::NeedsKernelDecision`] carrying the evidence view
/// for the governed Kernel path; malformed evidence resolves to
/// [`OperationDisposition::Denied`]. A known path, port, or process label
/// alone never authorizes anything here.
#[must_use]
pub fn gate_process_control(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
) -> OperationDisposition {
    if evidence.validate().is_err() {
        return OperationDisposition::Denied {
            reason: "invalid process-origin evidence",
        };
    }
    if !operation.requires_challenge() {
        return OperationDisposition::Observed;
    }
    match evidence.capability_view() {
        Ok(view) => OperationDisposition::NeedsKernelDecision { evidence: view },
        Err(_) => OperationDisposition::Denied {
            reason: "invalid process-origin evidence",
        },
    }
}

/// Evidence package the eliotd side forwards to the governed Kernel path.
///
/// Built by [`prepare_kernel_forward`] from well-formed evidence, a
/// forwardable operation, and an attached challenge. Packaging checks
/// completeness only; it never evaluates authority. Only
/// [`GovernedKernelAuthority::decide_forward`] turns this into an
/// authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelForwardRequest {
    /// Observed origin the operation targets.
    evidence: ProcessOriginEvidence,
    /// Requested control operation.
    operation: ProcessControlOperation,
    /// Attached challenge, evaluated only by the governed authority.
    challenge: OwnershipChallengeReceipt,
}

impl KernelForwardRequest {
    /// Returns the observed origin.
    #[must_use]
    pub fn evidence(&self) -> &ProcessOriginEvidence {
        &self.evidence
    }

    /// Returns the requested operation.
    #[must_use]
    pub const fn operation(&self) -> ProcessControlOperation {
        self.operation
    }

    /// Returns the attached challenge.
    #[must_use]
    pub fn challenge(&self) -> &OwnershipChallengeReceipt {
        &self.challenge
    }
}

/// Packages one forward: evidence plus the attached challenge.
///
/// The eliotd-side constructor. Checks completeness only: the operation must
/// be forwardable, the evidence well-formed, a challenge attached, and the
/// challenge well-shaped. Match, currency, issuance, and revocation are NOT
/// checked here; they are evaluated exclusively by
/// [`GovernedKernelAuthority::decide_forward`].
pub fn prepare_kernel_forward(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
    challenge: Option<&OwnershipChallengeReceipt>,
) -> Result<KernelForwardRequest, ProcessOriginError> {
    if !operation.is_forwardable() {
        return Err(ProcessOriginError::ObserveOnly);
    }
    evidence.validate()?;
    let Some(receipt) = challenge else {
        return Err(ProcessOriginError::ChallengeRequired);
    };
    receipt.validate_shape()?;
    Ok(KernelForwardRequest {
        evidence: evidence.clone(),
        operation,
        challenge: receipt.clone(),
    })
}

/// Operation-class label used inside authorization proof tokens.
fn operation_name(operation: ProcessControlOperation) -> &'static str {
    match operation {
        ProcessControlOperation::ReadStatus => "read-status",
        ProcessControlOperation::ProbeObserve => "probe-observe",
        ProcessControlOperation::Kill => "kill",
        ProcessControlOperation::Mutate => "mutate",
        ProcessControlOperation::Adopt => "adopt",
        ProcessControlOperation::AttachCredential => "attach-credential",
    }
}
/// Proof token minted only by the governed Kernel authority decision.
///
/// Returned solely by [`GovernedKernelAuthority::decide_forward`] and
/// [`GovernedKernelAuthority::authorize_shutdown`]. The daemon attaches it
/// to the neutral authenticated Kernel port call as proof that the governed
/// path evaluated authority. It is opaque: fields are private, there is no
/// public constructor and no Deserialize, so only a live authority decision
/// can produce one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KernelAuthorization {
    /// Challenge identity the decision evaluated.
    challenge_id: String,
    /// Operation class the decision authorized.
    operation: String,
    /// Unix milliseconds at which the decision was taken.
    decided_at_unix_ms: u64,
    /// Secret-bound decision tag over challenge tag, operation, and time.
    authorization_digest: String,
}

impl KernelAuthorization {
    /// Returns the evaluated challenge identity.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    /// Returns the authorized operation class label.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the decision time.
    #[must_use]
    pub const fn decided_at_unix_ms(&self) -> u64 {
        self.decided_at_unix_ms
    }

    /// Returns the secret-bound decision tag.
    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    /// Mints the token. Private: only the authority decision calls this.
    fn mint(
        secret: &[u8; 32],
        challenge: &OwnershipChallengeReceipt,
        operation: ProcessControlOperation,
        now_unix_ms: u64,
    ) -> Self {
        let operation_label = operation_name(operation).to_owned();
        let mut material = Vec::with_capacity(32 + 1 + 64 + 1 + 16 + 8);
        material.extend_from_slice(secret);
        material.push(0);
        material.extend_from_slice(challenge.issuer_tag().as_bytes());
        material.push(0);
        material.extend_from_slice(operation_label.as_bytes());
        material.push(0);
        material.extend_from_slice(&now_unix_ms.to_be_bytes());
        let authorization_digest = sha256_hex(&material);
        Self {
            challenge_id: challenge.challenge_id().to_owned(),
            operation: operation_label,
            decided_at_unix_ms: now_unix_ms,
            authorization_digest,
        }
    }
}

/// Governed Kernel control-authority path: the exclusive authority evaluator.
///
/// Owns the challenge issuer (mint plus store) and is the ONLY place that
/// evaluates control authority: [`decide_forward`](Self::decide_forward)
/// for forwarded operations and [`authorize_shutdown`](Self::authorize_shutdown)
/// for shutdown. Both re-validate the evidence, require the issuer-bound
/// proof via the owned issuer, and mint a [`KernelAuthorization`] token on
/// success. The eliotd gate and packager never authorize; they only route
/// and package evidence.
///
/// A [`ProcessStatusReceipt`] has no overload here by design: read status
/// can never become a control authorization, no matter how fresh.
pub struct GovernedKernelAuthority {
    /// Kernel-owned issuer: mint, store, and issuer-bound verification.
    issuer: OwnershipChallengeIssuer,
}

impl GovernedKernelAuthority {
    /// Creates the authority over a Kernel-owned issuer.
    #[must_use]
    pub const fn new(issuer: OwnershipChallengeIssuer) -> Self {
        Self { issuer }
    }

    /// Returns the backing issuer identity.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        self.issuer.issuer_id()
    }

    /// Issues a challenge bound to exactly one observation (Kernel-issued).
    pub fn issue_challenge(
        &mut self,
        evidence: &ProcessOriginEvidence,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<OwnershipChallengeReceipt, ProcessOriginError> {
        self.issuer
            .issue(evidence, issued_at_unix_ms, expires_at_unix_ms)
    }

    /// Revokes a minted challenge (Kernel-owned invalidation set).
    pub fn revoke_challenge(&mut self, challenge_id: &str) -> Result<(), ProcessOriginError> {
        self.issuer.revoke(challenge_id)
    }

    /// The exclusive control-authority decision for a forwarded operation.
    ///
    /// Fails closed on observe-only operations, malformed evidence, and any
    /// challenge that is missing issuance, revoked, mismatched, or not
    /// current. On success mints the [`KernelAuthorization`] proof token.
    pub fn decide_forward(
        &self,
        request: &KernelForwardRequest,
        now_unix_ms: u64,
    ) -> Result<KernelAuthorization, ProcessOriginError> {
        if !request.operation.is_forwardable() {
            return Err(ProcessOriginError::ObserveOnly);
        }
        request.evidence.validate()?;
        if !request.operation.requires_challenge() {
            return Err(ProcessOriginError::Contract(
                "forwardable operation requires a challenge-backed decision".to_owned(),
            ));
        }
        self.issuer
            .verify(&request.challenge, &request.evidence, now_unix_ms)?;
        Ok(KernelAuthorization::mint(
            &self.issuer.secret,
            &request.challenge,
            request.operation,
            now_unix_ms,
        ))
    }

    /// Shutdown authorization: only a current issuer-verified challenge.
    ///
    /// Takes the challenge type only. A [`ProcessStatusReceipt`] cannot be
    /// passed here, so a read receipt never authorizes shutdown no matter
    /// how fresh or well-formed it is.
    pub fn authorize_shutdown(
        &self,
        evidence: &ProcessOriginEvidence,
        challenge: &OwnershipChallengeReceipt,
        now_unix_ms: u64,
    ) -> Result<KernelAuthorization, ProcessOriginError> {
        evidence.validate()?;
        self.issuer.verify(challenge, evidence, now_unix_ms)?;
        Ok(KernelAuthorization::mint(
            &self.issuer.secret,
            challenge,
            ProcessControlOperation::Kill,
            now_unix_ms,
        ))
    }
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ISSUED_AT: u64 = 1_700_000_000_000;
    const EXPIRES_AT: u64 = 1_700_000_060_000;
    const NOW: u64 = 1_700_000_030_000;

    fn test_fence(generation: u64) -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(generation).expect("generation"),
        )
    }

    fn evidence(fence: &StateFence) -> ProcessOriginEvidence {
        let origin_digest = canonical_origin_digest("/srv/eliot/worker", 4217, "worker-7", fence);
        ProcessOriginEvidence {
            observed_path: "/srv/eliot/worker".to_owned(),
            observed_port: 4217,
            observed_process: "worker-7".to_owned(),
            origin_digest,
            state_fence: fence.clone(),
            observed_at_unix_ms: 1_700_000_000_000,
        }
    }

    fn test_issuer() -> OwnershipChallengeIssuer {
        OwnershipChallengeIssuer::new("governor-test".to_owned(), [9_u8; 32]).expect("test issuer")
    }

    fn status_receipt(fence: &StateFence, origin_digest: &str) -> ProcessStatusReceipt {
        ProcessStatusReceipt {
            origin_digest: origin_digest.to_owned(),
            state_fence: fence.clone(),
            status: "running".to_owned(),
            read_at_unix_ms: NOW,
        }
    }

    fn control_operations() -> [ProcessControlOperation; 4] {
        use ProcessControlOperation::{Adopt, AttachCredential, Kill, Mutate};
        [Kill, Mutate, Adopt, AttachCredential]
    }

    #[test]
    fn gate_routes_evidence_without_authorizing() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        observed.validate().expect("fixture evidence binds");

        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ReadStatus),
            OperationDisposition::Observed
        );
        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ProbeObserve),
            OperationDisposition::Observed
        );
        // The gate takes no challenge and emits no authorization: control
        // evidence routes to the Kernel path with its evidence view.
        for operation in control_operations() {
            let disposition = gate_process_control(&observed, operation);
            assert!(
                matches!(
                    disposition,
                    OperationDisposition::NeedsKernelDecision { .. }
                ),
                "{operation:?} must route to the Kernel path, never authorize or deny"
            );
            if let OperationDisposition::NeedsKernelDecision { evidence: view } = disposition {
                assert_eq!(view.scope_fingerprint, observed.origin_digest);
            }
            // Packaging without an attached challenge fails on completeness.
            assert!(matches!(
                prepare_kernel_forward(&observed, operation, None),
                Err(ProcessOriginError::ChallengeRequired)
            ));
        }
    }

    #[test]
    fn kernel_authority_alone_decides_control() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let mut authority = GovernedKernelAuthority::new(test_issuer());
        let receipt = authority
            .issue_challenge(&observed, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues the challenge");
        assert_eq!(authority.issuer.issued_count(), 1);

        let expected_label = [
            (ProcessControlOperation::Kill, "kill"),
            (ProcessControlOperation::Mutate, "mutate"),
            (ProcessControlOperation::Adopt, "adopt"),
            (
                ProcessControlOperation::AttachCredential,
                "attach-credential",
            ),
        ];
        for (operation, label) in expected_label {
            let request = prepare_kernel_forward(&observed, operation, Some(&receipt))
                .expect("complete evidence packages");
            let authorization = authority
                .decide_forward(&request, NOW)
                .expect("governed authority decides");
            assert_eq!(authorization.challenge_id(), receipt.challenge_id());
            assert_eq!(authorization.operation(), label);
            assert_eq!(authorization.decided_at_unix_ms(), NOW);
        }
        authority
            .authorize_shutdown(&observed, &receipt, NOW)
            .expect("shutdown authorizes");
    }
    #[test]
    fn reproduced_digest_without_issuance_never_authorizes() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let issuer = test_issuer();
        assert_eq!(issuer.issued_count(), 0);
        let authority = GovernedKernelAuthority::new(issuer);

        // Attacker replays the exact reproducible content binding but cannot
        // mint the secret-bound tag and has no registry entry. In-module
        // struct literal stands in for any out-of-module forgery shape.
        let plausible_id = "governor-test#00000001".to_owned();
        let forged = OwnershipChallengeReceipt {
            challenge_id: plausible_id.clone(),
            origin_digest: observed.origin_digest.clone(),
            state_fence: fence.clone(),
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            receipt_digest: canonical_challenge_digest(
                &plausible_id,
                &observed.origin_digest,
                &fence,
                ISSUED_AT,
                EXPIRES_AT,
            ),
            issuer_tag: "0".repeat(64),
        };
        // Shape and packaging pass: they are completeness, not authority.
        forged.validate_shape().expect("forgery is well-shaped");
        let request =
            prepare_kernel_forward(&observed, ProcessControlOperation::Kill, Some(&forged))
                .expect("packaging checks completeness only");
        // Authority rejects: never issued here, tag not issuer-bound.
        assert!(matches!(
            authority.decide_forward(&request, NOW),
            Err(ProcessOriginError::ChallengeMismatch)
        ));
        assert!(matches!(
            authority.authorize_shutdown(&observed, &forged, NOW),
            Err(ProcessOriginError::ChallengeMismatch)
        ));
    }

    #[test]
    fn cross_issuer_receipts_never_authorize() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let mut first = test_issuer();
        let receipt = first
            .issue(&observed, ISSUED_AT, EXPIRES_AT)
            .expect("first issuer mints");
        let other_issuer = OwnershipChallengeIssuer::new("other-kernel".to_owned(), [4_u8; 32])
            .expect("second issuer");
        let other_authority = GovernedKernelAuthority::new(other_issuer);
        // Same shape, different secret and store: must fail issuer binding.
        assert!(matches!(
            other_authority.issuer.verify(&receipt, &observed, NOW),
            Err(ProcessOriginError::ChallengeMismatch)
        ));
        let request =
            prepare_kernel_forward(&observed, ProcessControlOperation::Adopt, Some(&receipt))
                .expect("packaging checks completeness only");
        assert!(matches!(
            other_authority.decide_forward(&request, NOW),
            Err(ProcessOriginError::ChallengeMismatch)
        ));
    }

    #[test]
    fn stale_mismatched_or_revoked_challenges_never_authorize() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let mut authority = GovernedKernelAuthority::new(test_issuer());
        let receipt = authority
            .issue_challenge(&observed, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues the challenge");
        let request =
            prepare_kernel_forward(&observed, ProcessControlOperation::Kill, Some(&receipt))
                .expect("complete evidence packages");

        assert!(matches!(
            authority.decide_forward(&request, EXPIRES_AT + 1),
            Err(ProcessOriginError::ChallengeNotCurrent)
        ));

        let other_fence = test_fence(2);
        let other = evidence(&other_fence);
        assert!(matches!(
            authority.decide_forward(
                &prepare_kernel_forward(&other, ProcessControlOperation::Mutate, Some(&receipt))
                    .expect("packaging checks completeness only"),
                NOW
            ),
            Err(ProcessOriginError::ChallengeMismatch)
        ));
        assert!(authority.authorize_shutdown(&other, &receipt, NOW).is_err());

        let mut tampered = receipt.clone();
        tampered.origin_digest = "0".repeat(64);
        assert!(matches!(
            prepare_kernel_forward(&observed, ProcessControlOperation::Kill, Some(&tampered)),
            Err(ProcessOriginError::Contract(_))
        ));
        assert!(authority.issuer.verify(&tampered, &observed, NOW).is_err());

        let challenge_id = receipt.challenge_id().to_owned();
        authority
            .revoke_challenge(&challenge_id)
            .expect("revocation records");
        assert!(matches!(
            authority.decide_forward(&request, NOW),
            Err(ProcessOriginError::ChallengeRevoked)
        ));
        assert!(matches!(
            authority.authorize_shutdown(&observed, &receipt, NOW),
            Err(ProcessOriginError::ChallengeRevoked)
        ));
    }
    #[test]
    fn read_status_never_authorizes_and_probes_never_forward() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let mut authority = GovernedKernelAuthority::new(test_issuer());
        let receipt = authority
            .issue_challenge(&observed, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues the challenge");
        let status = status_receipt(&fence, &observed.origin_digest);
        status.validate().expect("fixture status reads");

        // Reads stay observe-only; even a valid challenge changes nothing.
        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ReadStatus),
            OperationDisposition::Observed
        );
        assert!(matches!(
            prepare_kernel_forward(
                &observed,
                ProcessControlOperation::ReadStatus,
                Some(&receipt)
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        assert!(matches!(
            prepare_kernel_forward(
                &observed,
                ProcessControlOperation::ProbeObserve,
                Some(&receipt)
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        // Shutdown takes the challenge type only: no overload accepts the
        // status receipt, so a fresh well-formed status can never substitute
        // for the challenge. The valid challenge itself still authorizes.
        assert!(
            authority
                .authorize_shutdown(&observed, &receipt, NOW)
                .is_ok()
        );
        let status_digest_replay = status.origin_digest.clone();
        assert_eq!(status_digest_replay, observed.origin_digest);
    }

    #[test]
    fn capability_view_is_observation_only() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let view = observed.capability_view().expect("valid evidence projects");
        assert_eq!(view.capability, PROCESS_ORIGIN_CAPABILITY);
        assert_eq!(view.status, CapabilityEvidenceStatus::Observed);
        assert_eq!(view.source, CapabilityEvidenceSource::ProductionObservation);
        assert_eq!(view.scope_fingerprint, observed.origin_digest);
        assert!(view.limitations.contains("never authorizes control"));
        assert_eq!(view.observed_at_unix_ms, observed.observed_at_unix_ms);

        let bad = ProcessOriginEvidence {
            observed_port: 0,
            ..observed.clone()
        };
        assert!(bad.capability_view().is_err());
        assert!(matches!(
            gate_process_control(&bad, ProcessControlOperation::Kill),
            OperationDisposition::Denied { .. }
        ));
    }

    #[test]
    fn issuer_rejects_weak_parameters() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        assert!(OwnershipChallengeIssuer::new(String::new(), [9_u8; 32]).is_err());
        assert!(OwnershipChallengeIssuer::new("bad id!".to_owned(), [9_u8; 32]).is_err());
        assert!(OwnershipChallengeIssuer::new("x".repeat(65), [9_u8; 32]).is_err());
        assert!(OwnershipChallengeIssuer::new("governor-test".to_owned(), [0_u8; 32]).is_err());

        let mut issuer = test_issuer();
        assert!(issuer.issue(&observed, ISSUED_AT, ISSUED_AT - 1).is_err());
        assert!(issuer.issue(&observed, 0, EXPIRES_AT).is_err());
        assert!(
            issuer
                .issue(
                    &observed,
                    ISSUED_AT,
                    ISSUED_AT + MAX_CHALLENGE_WINDOW_MS + 1
                )
                .is_err()
        );
        assert!(issuer.revoke("governor-test#deadbeef").is_err());
        let receipt = issuer
            .issue(&observed, ISSUED_AT, EXPIRES_AT)
            .expect("bounded window issues");
        assert_eq!(issuer.issued_count(), 1);
        issuer
            .revoke(receipt.challenge_id())
            .expect("known identity revokes");
        issuer
            .revoke(receipt.challenge_id())
            .expect("revocation is idempotent");
    }
}
