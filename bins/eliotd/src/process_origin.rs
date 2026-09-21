//! Governor-owned process-origin evidence view, separate from control authority.
//!
//! Issue #1960: a known path/port/process triple is **observable** but never
//! **controllable** on the strength of observation alone. Observation answers
//! what was seen; control authority is owned and evaluated exclusively by the
//! Kernel through [`OriginChallengeAuthority`].
//!
//! Rework notes (prepared PR #2246: `b4e73def`, `076ae935`, `461106aa`):
//! the prepared revision kept a daemon-minted challenge issuer
//! (`KernelChallengeKey` / `OwnershipChallengeIssuer` /
//! `GovernedKernelAuthority`) inside this crate with crate-private mint paths.
//! That made the daemon its own authority: the actual Kernel could not own the
//! issuer, so runtime control was self-granted. The parallel issuer is
//! removed. The only minter and decision point is now the Kernel-owned
//! [`OriginChallengeAuthority`] in the neutral `eliot-process` contract cell
//! (`origin_challenge.rs`), authenticating with the shared [`KernelDispatchKey`]
//! under a disjoint domain. This module keeps the Governor observation,
//! capability projection, and policy gate, and adds the daemon consumer
//! ([`request_origin_control`]) which central Governor code invokes to package
//! a Kernel-bound challenge request.
//!
//! Daemon flow: [`gate_process_control`] (route evidence) ->
//! [`request_origin_control`] (bind observation + OS physical identity +
//! installation into a neutral [`OriginChallengeRequest`]; completeness only)
//! -> neutral authenticated Kernel port ->
//! [`OriginChallengeAuthority::issue`] (Kernel mints) ->
//! [`OriginControlPresentation::new`] (seal request + challenge) ->
//! [`OriginChallengeAuthority::decide`] (exclusive authority, one-shot) ->
//! [`OriginControlGrant`] (proof token for the effect call).
//!
//! This module performs no I/O, holds no key material, and retains no issuer
//! state. [`ProcessStatusReceipt`] has no conversion into anything the
//! authority accepts: type shape alone keeps a status receipt from
//! authorizing control.

#![forbid(unsafe_code)]

use eliot_contracts::{StateFence, sha256_hex};
pub use eliot_process::{
    Generation, OriginChallenge, OriginChallengeAuthority, OriginChallengeRequest,
    OriginControlGrant, OriginControlOperation, OriginControlPresentation, PhysicalProcessBinding,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Capability name projected by [`ProcessOriginEvidence::capability_view`].
///
/// Names the evidence view, not a control right: observation only.
pub const PROCESS_ORIGIN_CAPABILITY: &str = "process-origin-observation";

/// Errors raised by the process-origin evidence view and daemon consumer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessOriginError {
    /// An evidence or request field is malformed, or the neutral contract
    /// rejected packaging.
    #[error("process-origin contract: {0}")]
    Contract(String),
    /// A status/read receipt was presented where control authority is required.
    #[error("process-origin denied: a read status receipt never authorizes shutdown or control")]
    StatusNeverAuthorizes,
    /// The operation is observe-only and must never be packaged for the Kernel.
    #[error("process-origin denied: probes observe only and are never forwarded")]
    ObserveOnly,
}

impl From<eliot_process::ContractError> for ProcessOriginError {
    fn from(error: eliot_process::ContractError) -> Self {
        Self::Contract(error.to_string())
    }
}
/// Governor-owned observation of one process origin.
///
/// Observation only: the known path, port, and process label describe what
/// was seen. They grant no stop, adopt, mutate, or credential-attach
/// authority, and no ownership is inferred from them. The `origin_digest`
/// binds the observed triple plus the admitted fence so a Kernel-issued
/// challenge can match exactly one observation.
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
    /// Read-only status probe. Observe only, never packaged.
    ReadStatus,
    /// General observation probe. Observe only, never packaged.
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
    /// by a current Kernel-issued origin challenge.
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

    /// Returns whether the operation may ever be packaged for the Kernel.
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

impl From<ProcessControlOperation> for OriginControlOperation {
    fn from(operation: ProcessControlOperation) -> Self {
        match operation {
            ProcessControlOperation::Kill => Self::Kill,
            ProcessControlOperation::Mutate => Self::Mutate,
            ProcessControlOperation::Adopt => Self::Adopt,
            ProcessControlOperation::AttachCredential => Self::AttachCredential,
            ProcessControlOperation::ReadStatus | ProcessControlOperation::ProbeObserve => {
                // Unreachable through `request_origin_control`, which rejects
                // observe-only operations first; the mapping defaults
                // fail-closed to the narrowest control class if misused.
                Self::Kill
            }
        }
    }
}

/// Read-only status receipt for an observed process origin.
///
/// Observation answer only: it reports what a status probe saw. It carries
/// no challenge and no control capability. There is deliberately **no**
/// constructor or conversion from this type into anything the Kernel
/// authority accepts: type shape alone keeps a status receipt from
/// authorizing shutdown or control.
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
/// currency for control — only a current Kernel-issued challenge does.
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
/// [`OriginChallengeAuthority::decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationDisposition {
    /// Observe-only outcome: answered from evidence, never packaged.
    Observed,
    /// Evidence is complete; package it so the governed Kernel path decides.
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

/// Packages one Kernel-bound origin-challenge request.
///
/// The daemon-side consumer invoked by central Governor code. Binds the
/// validated Governor observation to the exact OS physical identity
/// ([`PhysicalProcessBinding`]: pid plus process start identity plus image)
/// and the admitted installation identity under the evidence fence, for one
/// control operation class. Checks completeness only: the operation must be
/// forwardable, the evidence well-formed, and the physical identity,
/// installation, fence generation, and nonce well-shaped. Issuance, match,
/// currency, revocation, and the live epoch are NOT checked here; they are
/// evaluated exclusively by the Kernel-owned
/// [`OriginChallengeAuthority::issue`] and [`OriginChallengeAuthority::decide`].
/// This function holds no key and mints nothing.
pub fn request_origin_control(
    evidence: &ProcessOriginEvidence,
    physical: &PhysicalProcessBinding,
    installation_id: &str,
    operation: ProcessControlOperation,
    request_nonce: &str,
) -> Result<OriginChallengeRequest, ProcessOriginError> {
    if !operation.is_forwardable() {
        return Err(ProcessOriginError::ObserveOnly);
    }
    evidence.validate()?;
    let generation = Generation::new(evidence.state_fence.resource_generation.value())?;
    OriginChallengeRequest::new(
        physical.clone(),
        installation_id.to_owned(),
        evidence.origin_digest.clone(),
        generation,
        evidence.state_fence.clone(),
        OriginControlOperation::from(operation),
        request_nonce.to_owned(),
    )
    .map_err(ProcessOriginError::from)
}
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_process::{DispatchAuthorityId, KernelDispatchKey, OriginChallengeAuthority};
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

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch")
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

    fn physical() -> PhysicalProcessBinding {
        PhysicalProcessBinding::new(
            4242,
            133_081_756_927_500_000,
            "C:\\srv\\eliot\\worker.exe",
            "executor-job-1",
        )
        .expect("physical identity")
    }

    /// Test-only Kernel authority: production instances live in the Kernel
    /// service; the daemon never activates one outside tests.
    fn test_authority() -> OriginChallengeAuthority {
        OriginChallengeAuthority::activate(
            DispatchAuthorityId::new("kernel-origin-test").expect("authority id"),
            KernelDispatchKey::from_secret_bytes([7_u8; 32]).expect("kernel key"),
        )
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
        }
    }

    #[test]
    fn request_packages_observation_with_physical_identity() {
        let fence = test_fence(3);
        let observed = evidence(&fence);
        let request = request_origin_control(
            &observed,
            &physical(),
            "installation-7",
            ProcessControlOperation::Kill,
            "nonce-0001",
        )
        .expect("complete evidence packages");
        assert_eq!(request.origin_digest(), observed.origin_digest);
        assert_eq!(request.installation_id(), "installation-7");
        assert_eq!(request.operation(), OriginControlOperation::Kill);
        assert_eq!(request.physical().process_id(), 4242);
        // Observe-only operations are never packaged, even with valid input.
        assert!(matches!(
            request_origin_control(
                &observed,
                &physical(),
                "installation-7",
                ProcessControlOperation::ReadStatus,
                "nonce-0002",
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        assert!(matches!(
            request_origin_control(
                &observed,
                &physical(),
                "installation-7",
                ProcessControlOperation::ProbeObserve,
                "nonce-0003",
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        // Malformed evidence or installation never packages.
        let mut bad = observed.clone();
        bad.observed_port = 0;
        assert!(matches!(
            request_origin_control(
                &bad,
                &physical(),
                "installation-7",
                ProcessControlOperation::Kill,
                "nonce-0004",
            ),
            Err(ProcessOriginError::Contract(_))
        ));
        assert!(matches!(
            request_origin_control(
                &observed,
                &physical(),
                "",
                ProcessControlOperation::Kill,
                "nonce-0005",
            ),
            Err(ProcessOriginError::Contract(_))
        ));
    }

    #[test]
    fn kernel_decide_authorizes_packaged_control() {
        let fence = test_fence(3);
        let observed = evidence(&fence);
        let mut authority = test_authority();
        let request = request_origin_control(
            &observed,
            &physical(),
            "installation-7",
            ProcessControlOperation::Adopt,
            "nonce-0010",
        )
        .expect("complete evidence packages");
        let challenge = authority
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues the challenge");
        let presentation =
            OriginControlPresentation::new(request, challenge).expect("presentation seals");
        let grant = authority
            .decide(&presentation, &test_epoch(), NOW)
            .expect("kernel decides");
        assert_eq!(grant.operation(), OriginControlOperation::Adopt);
        assert_eq!(grant.decided_at_unix_ms(), NOW);
    }

    #[test]
    fn kill_challenge_never_authorizes_adopt() {
        let fence = test_fence(3);
        let observed = evidence(&fence);
        let mut authority = test_authority();
        let request = request_origin_control(
            &observed,
            &physical(),
            "installation-7",
            ProcessControlOperation::Kill,
            "nonce-0020",
        )
        .expect("complete evidence packages");
        let challenge = authority
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("kernel issues kill");
        // Resealing the kill challenge against an adopt request fails at
        // packaging: one challenge allows exactly one operation class.
        let adopt = request_origin_control(
            &observed,
            &physical(),
            "installation-7",
            ProcessControlOperation::Adopt,
            "nonce-0021",
        )
        .expect("adopt packages separately");
        let _ = adopt;
        let mismatched = OriginChallengeRequest::new(
            physical(),
            "installation-7",
            observed.origin_digest.clone(),
            Generation::new(3).expect("generation"),
            fence.clone(),
            OriginControlOperation::Adopt,
            "nonce-0020",
        );
        // Same nonce shape but different class cannot reseal the kill mint.
        assert!(mismatched.is_ok());
        assert!(matches!(
            OriginControlPresentation::new(mismatched.expect("request"), challenge),
            Err(_)
        ));
    }

    #[test]
    fn challenge_from_another_authority_never_decides() {
        let fence = test_fence(3);
        let observed = evidence(&fence);
        let mut other = OriginChallengeAuthority::activate(
            DispatchAuthorityId::new("other-kernel").expect("authority id"),
            KernelDispatchKey::from_secret_bytes([9_u8; 32]).expect("kernel key"),
        );
        let request = request_origin_control(
            &observed,
            &physical(),
            "installation-7",
            ProcessControlOperation::Mutate,
            "nonce-0030",
        )
        .expect("complete evidence packages");
        let challenge = other
            .issue(&request, ISSUED_AT, EXPIRES_AT)
            .expect("other authority issues");
        let presentation = OriginControlPresentation::new(request, challenge).expect("seals");
        let mut authority = test_authority();
        assert!(authority.decide(&presentation, &test_epoch(), NOW).is_err());
    }

    #[test]
    fn read_status_never_authorizes_and_probes_never_package() {
        let fence = test_fence(1);
        let observed = evidence(&fence);
        let status = status_receipt(&fence, &observed.origin_digest);
        status.validate().expect("fixture status reads");

        // Reads stay observe-only; even a valid physical identity changes nothing.
        assert_eq!(
            gate_process_control(&observed, ProcessControlOperation::ReadStatus),
            OperationDisposition::Observed
        );
        assert!(matches!(
            request_origin_control(
                &observed,
                &physical(),
                "installation-7",
                ProcessControlOperation::ReadStatus,
                "nonce-0040",
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        assert!(matches!(
            request_origin_control(
                &observed,
                &physical(),
                "installation-7",
                ProcessControlOperation::ProbeObserve,
                "nonce-0041",
            ),
            Err(ProcessOriginError::ObserveOnly)
        ));
        // The status receipt type cannot enter the authority path: no
        // constructor accepts it, so a fresh well-formed status can never
        // substitute for a Kernel-issued challenge.
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
}
