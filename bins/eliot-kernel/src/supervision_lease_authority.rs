//! Kernel supervision lease authority — Architecture A2.3/A13.2; Implementation I1.8 admission-validation-ORS-receipt/static_native authority/fencing/bounded `FunctionalCapabilityCell`.
//! Boundary owns Kernel mechanical identity/fencing/ORS supervision authority only.
//! No semantic/default authority, no alternate lease, no unbounded restart, no daemon-owned canonical transition.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_contracts::AuthorityEpoch;
use eliot_ors::{
    OperationIdentity, OrsError, RedbRecoveryStore, SupervisionLeaseCommitTicket,
    SupervisionLeaseOperation, SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt,
};
use eliot_platform_windows::{
    InstallerRootPrimitiveSpec, InstallerRootProfile, WindowsSupervisionAuthorityKeyStore,
    protected_program_data_root,
};
use eliot_process::EliotdLiveSupervisionEvidence;
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, LeaseState, ProvisionedSupervisionAuthority, SupervisionLease,
    SupervisionLeaseActiveStateBinding, SupervisionLeaseError, SupervisionLeasePredecessorIdentity,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseTerminalDisposition,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionSealedKeyReference,
    SupervisionTrustAnchor,
};

use crate::KernelBuildError;
#[cfg(windows)]
use crate::SupervisionLeaseAuthorityConfig;
#[cfg(windows)]
use crate::daemon_supervision::DaemonSupervisionContour;

#[cfg(windows)]
use super::sha256_hex;
#[cfg(windows)]
use super::sha256_json;
#[cfg(windows)]
use super::unix_ms;

#[cfg(windows)]
#[derive(Debug)]
pub enum SupervisionLeaseAuthorityError {
    Configuration(String),
    ProtectedKeyUnavailable,
    Contract(String),
    Ors(OrsError),
}

#[cfg(windows)]
impl fmt::Display for SupervisionLeaseAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(reason) => {
                write!(formatter, "invalid supervision authority: {reason}")
            }
            Self::ProtectedKeyUnavailable => {
                formatter.write_str("protected supervision signing key is unavailable")
            }
            Self::Contract(reason) => {
                write!(formatter, "supervision lease contract rejected: {reason}")
            }
            Self::Ors(error) => {
                write!(formatter, "supervision ORS rejected the operation: {error}")
            }
        }
    }
}

#[cfg(windows)]
impl std::error::Error for SupervisionLeaseAuthorityError {}

#[cfg(windows)]
impl From<OrsError> for SupervisionLeaseAuthorityError {
    fn from(error: OrsError) -> Self {
        Self::Ors(error)
    }
}

#[cfg(windows)]
pub struct ProtectedSupervisionLeaseSigner {
    kernel_root: PathBuf,
    key_store: WindowsSupervisionAuthorityKeyStore,
    authority: ProvisionedSupervisionAuthority,
    signer_id: String,
    key_id: String,
    expected_public_key_fingerprint: String,
}

#[cfg(windows)]
impl fmt::Debug for ProtectedSupervisionLeaseSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedSupervisionLeaseSigner")
            .field("signer_id", &self.signer_id)
            .field("key_id", &self.key_id)
            .field(
                "expected_public_key_fingerprint",
                &self.expected_public_key_fingerprint,
            )
            .field("key_provider", &self.authority.key_reference.provider)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl ProtectedSupervisionLeaseSigner {
    pub(super) fn new(
        kernel_root: PathBuf,
        config: &SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, SupervisionLeaseAuthorityError> {
        config
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Configuration)?;
        let signer = Self {
            kernel_root,
            key_store: WindowsSupervisionAuthorityKeyStore::new(),
            authority: config.authority.clone(),
            signer_id: config.authority.trust_anchor.signer_id.clone(),
            key_id: config.authority.trust_anchor.key_id.clone(),
            expected_public_key_fingerprint: config
                .authority
                .trust_anchor
                .public_key_fingerprint
                .clone(),
        };
        signer
            .load_signer()
            .map_err(|_| SupervisionLeaseAuthorityError::ProtectedKeyUnavailable)?;
        Ok(signer)
    }

    fn load_signer(&self) -> Result<Ed25519SupervisionLeaseSigner, SupervisionLeaseError> {
        let spec = supervision_authority_root_spec(&self.kernel_root)?;
        let secret = self
            .key_store
            .unseal_for_kernel(&spec, &self.kernel_root, &self.authority)
            .map_err(|_| {
                SupervisionLeaseError::Signing(
                    "service-SID sealed supervision key unavailable".to_owned(),
                )
            })?;
        if secret.expose().len() != 32 || secret.expose().iter().all(|byte| *byte == 0) {
            return Err(SupervisionLeaseError::Signing(
                "protected key has invalid length or value".to_owned(),
            ));
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(secret.expose());
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
            self.signer_id.clone(),
            self.key_id.clone(),
            key_bytes,
        )?;
        key_bytes.fill(0);
        if sha256_hex(&signer.public_key()) != self.expected_public_key_fingerprint {
            return Err(SupervisionLeaseError::Signing(
                "protected key does not match the installation trust anchor".to_owned(),
            ));
        }
        Ok(signer)
    }

    pub fn key_reference(&self) -> &SupervisionSealedKeyReference {
        &self.authority.key_reference
    }
}

#[cfg(windows)]
pub(super) fn supervision_authority_root_spec(
    kernel_root: &Path,
) -> Result<InstallerRootPrimitiveSpec, SupervisionLeaseError> {
    if !kernel_root.is_absolute()
        || kernel_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(SupervisionLeaseError::Signing(
            "Kernel supervision root must be absolute".to_owned(),
        ));
    }
    let profile_anchor = protected_program_data_root().map_err(|_| {
        SupervisionLeaseError::Signing("protected ProgramData root unavailable".to_owned())
    })?;
    let installation_root = profile_anchor.join("Eliot");
    Ok(InstallerRootPrimitiveSpec {
        root: kernel_root.to_path_buf(),
        installation_root,
        profile_anchor,
        profile: InstallerRootProfile::SystemService,
    })
}

#[cfg(windows)]
impl SupervisionLeaseSigner for ProtectedSupervisionLeaseSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, SupervisionLeaseError> {
        let signer = self.load_signer()?;
        signer.sign(canonical_payload)
    }
}

#[cfg(windows)]
pub struct KernelSupervisionLeaseAuthority {
    ors: Arc<RedbRecoveryStore>,
    signer: ProtectedSupervisionLeaseSigner,
    trust_anchor: SupervisionTrustAnchor,
    supervision_lease_scope_id: String,
}

#[cfg(windows)]
impl fmt::Debug for KernelSupervisionLeaseAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelSupervisionLeaseAuthority")
            .field("trust_anchor", &self.trust_anchor)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl KernelSupervisionLeaseAuthority {
    pub(super) fn new(
        ors: Arc<RedbRecoveryStore>,
        kernel_root: PathBuf,
        config: SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let signer = ProtectedSupervisionLeaseSigner::new(kernel_root, &config)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        Ok(Self {
            ors,
            signer,
            trust_anchor: config.authority.trust_anchor,
            supervision_lease_scope_id: config.authority.supervision_lease_scope_id,
        })
    }

    pub fn trust_anchor(&self) -> &SupervisionTrustAnchor {
        &self.trust_anchor
    }

    pub fn key_reference(&self) -> &SupervisionSealedKeyReference {
        self.signer.key_reference()
    }

    pub fn supervision_lease_scope_id(&self) -> &str {
        &self.supervision_lease_scope_id
    }

    pub fn current_snapshot(
        &self,
        supervision_lease_id: &str,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let lease_id = OperationIdentity::new(supervision_lease_id.to_owned())?;
        self.ors
            .load_current_supervision_lease(&lease_id)
            .map_err(Into::into)
    }

    pub(super) fn staged_snapshot(
        &self,
        supervision_lease_id: &str,
    ) -> Result<Option<SupervisionLeaseStageReceipt>, SupervisionLeaseAuthorityError> {
        let lease_id = OperationIdentity::new(supervision_lease_id.to_owned())?;
        self.ors
            .reconcile_staged_supervision_lease(&lease_id)
            .map_err(Into::into)
    }

    pub(super) fn verify_active_snapshot(
        &self,
        snapshot: &SupervisionLeaseSnapshot,
        supervision_lease_id: &str,
        now_ms: u64,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        snapshot
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if snapshot.record.lease_id.as_str() != supervision_lease_id
            || snapshot.record.state != LeaseState::Active
            || snapshot.record.projection != eliot_ors::SupervisionLeaseProjection::Active
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let context = snapshot
            .active_verification_context(self.trust_anchor.public_key_fingerprint(), now_ms)
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        self.trust_anchor
            .verify(&snapshot.record.artifact, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        Ok(())
    }

    pub(super) fn verify_superseded_replay(
        &self,
        terminal: &SupervisionLeaseSnapshot,
        expected_predecessor: &SupervisionLeasePredecessorIdentity,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        verify_superseded_supervision_replay(
            self.ors.as_ref(),
            &self.trust_anchor,
            terminal,
            expected_predecessor,
        )
    }

    pub fn current_eliotd_live_evidence(
        &self,
        expected_supervision_lease_id: &str,
        expected_generation: u64,
        expected_authority_epoch: u64,
    ) -> Result<EliotdLiveSupervisionEvidence, SupervisionLeaseAuthorityError> {
        self.current_eliotd_live_projection(
            expected_supervision_lease_id,
            expected_generation,
            expected_authority_epoch,
        )
        .map(|(evidence, _)| evidence)
    }

    pub(super) fn current_eliotd_live_projection(
        &self,
        expected_supervision_lease_id: &str,
        expected_generation: u64,
        expected_authority_epoch: u64,
    ) -> Result<(EliotdLiveSupervisionEvidence, u64), SupervisionLeaseAuthorityError> {
        let current = self
            .current_snapshot(expected_supervision_lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        current
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || current.record.lease_id.as_str() != expected_supervision_lease_id
            || current
                .record
                .binding
                .state_fence
                .resource_generation
                .value()
                != expected_generation
            || current.record.binding.state_fence.authority_epoch.value()
                != expected_authority_epoch
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let payload = &current.record.artifact.payload;
        let now_ms = unix_ms();
        if payload.installation_id != self.trust_anchor.installation_id
            || payload.issued_at_ms == 0
            || now_ms < payload.issued_at_ms
            || now_ms >= payload.expires_at_ms
            || payload.ors_mirror.record_id != current.record.record_id.as_str()
            || payload.ors_mirror.lease_revision != current.record.revision
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let context = self.verification_context(payload, now_ms);
        let verified = self
            .trust_anchor
            .verify(&current.record.artifact, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        if verified.payload() != payload {
            return Err(SupervisionLeaseAuthorityError::Contract(
                "verified supervision payload diverged from the durable ORS artifact".to_owned(),
            ));
        }
        let envelope_sha256 = current
            .record
            .artifact
            .envelope_digest()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        Ok((
            EliotdLiveSupervisionEvidence {
                lease_id: current.record.lease_id.as_str().to_owned(),
                record_id: current.record.record_id.as_str().to_owned(),
                revision: current.record.revision,
                receipt_sha256: current.receipt.receipt_sha256.clone(),
                envelope_sha256,
                payload_sha256: current.record.artifact.payload_sha256.clone(),
                public_key_fingerprint: self.trust_anchor.public_key_fingerprint().to_owned(),
            },
            payload.issued_at_ms,
        ))
    }

    fn validate_binding(
        &self,
        binding: &eliot_ors::SupervisionLeaseBinding,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        if binding.installation_id.as_str() != self.trust_anchor.installation_id {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "lease installation identity does not match the trust anchor".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn prepare(
        &self,
        request: SupervisionLeasePrepareRequest,
    ) -> Result<SupervisionLeaseStageReceipt, SupervisionLeaseAuthorityError> {
        self.validate_binding(&request.binding)?;
        self.ors
            .prepare_supervision_lease(request)
            .map_err(Into::into)
    }

    fn verification_context(
        &self,
        payload: &SupervisionLease,
        now_ms: u64,
    ) -> SupervisionLeaseVerificationContext {
        verification_context_for_supervision_payload(&self.trust_anchor, payload, now_ms)
    }

    fn staged_ticket(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<(), SupervisionLeaseAuthorityError> {
        let stage = self
            .ors
            .reconcile_staged_supervision_lease(&ticket.lease_id)?
            .ok_or({
                SupervisionLeaseAuthorityError::Ors(OrsError::SupervisionLeaseTicketNotStaged)
            })?;
        if stage.ticket != *ticket || stage.ticket_sha256 != ticket.ticket_sha256()? {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseTicketConflict,
            ));
        }
        Ok(())
    }

    pub fn commit_active(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        if !matches!(
            ticket.operation,
            SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew
        ) {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "active commit requires COMMIT or RENEW".to_owned(),
            ));
        }
        if let Some(snapshot) = self.ors.replay_supervision_lease_commit(ticket)? {
            return Ok(snapshot);
        }
        self.staged_ticket(ticket)?;
        let payload = ticket
            .expected_payload()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        self.validate_binding(&ticket.binding)?;
        let envelope = payload.sign(&self.signer).map_err(|error| match error {
            SupervisionLeaseError::Signing(_) => {
                SupervisionLeaseAuthorityError::ProtectedKeyUnavailable
            }
            error => SupervisionLeaseAuthorityError::Contract(error.to_string()),
        })?;
        let context = self.verification_context(&payload, unix_ms());
        let verified = self
            .trust_anchor
            .verify(&envelope, &context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        self.ors
            .commit_supervision_lease(ticket, &verified)
            .map_err(Into::into)
    }

    pub fn commit_terminal(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        if matches!(
            ticket.operation,
            SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew
        ) {
            return Err(SupervisionLeaseAuthorityError::Configuration(
                "terminal commit requires a terminal operation".to_owned(),
            ));
        }
        if let Some(snapshot) = self.ors.replay_supervision_lease_commit(ticket)? {
            return Ok(snapshot);
        }
        self.staged_ticket(ticket)?;
        let current = self
            .ors
            .load_current_supervision_lease(&ticket.lease_id)?
            .ok_or(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ))?;
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || ticket.expected_revision != Some(current.record.revision)
            || ticket.previous_receipt_sha256.as_deref()
                != Some(current.receipt.receipt_sha256.as_str())
        {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        self.validate_binding(&ticket.binding)?;
        let prior_context = self.verification_context(
            &current.record.artifact.payload,
            current.record.artifact.payload.issued_at_ms,
        );
        let prior_active = self
            .trust_anchor
            .verify(&current.record.artifact, &prior_context)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        let predecessor = SupervisionLeasePredecessorProof {
            lease_id: current.record.lease_id.as_str().to_owned(),
            record_id: current.record.record_id.as_str().to_owned(),
            lease_revision: current.record.revision,
            receipt_sha256: current.receipt.receipt_sha256.clone(),
            envelope_sha256: current
                .record
                .artifact
                .envelope_digest()
                .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
        };
        let payload = ticket
            .expected_payload()
            .map_err(SupervisionLeaseAuthorityError::Ors)?;
        let envelope = payload.sign(&self.signer).map_err(|error| match error {
            SupervisionLeaseError::Signing(_) => {
                SupervisionLeaseAuthorityError::ProtectedKeyUnavailable
            }
            error => SupervisionLeaseAuthorityError::Contract(error.to_string()),
        })?;
        let verified = self
            .trust_anchor
            .verify_terminal_transition(&prior_active, &envelope, &predecessor)
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
        self.ors
            .commit_terminal_supervision_lease(ticket, &verified)
            .map_err(Into::into)
    }

    pub fn reconcile(
        &self,
        limit: u16,
    ) -> Result<Vec<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let stages = self.ors.reconcile_staged_supervision_leases(limit)?;
        let mut committed = Vec::with_capacity(stages.len());
        for stage in stages {
            let snapshot = match stage.ticket.operation {
                SupervisionLeaseOperation::Commit | SupervisionLeaseOperation::Renew => {
                    self.commit_active(&stage.ticket)?
                }
                SupervisionLeaseOperation::Revoke
                | SupervisionLeaseOperation::Expire
                | SupervisionLeaseOperation::Supersede
                | SupervisionLeaseOperation::Close => self.commit_terminal(&stage.ticket)?,
            };
            committed.push(snapshot);
        }
        Ok(committed)
    }
}

#[cfg(windows)]
pub(super) fn verification_context_for_supervision_payload(
    trust_anchor: &SupervisionTrustAnchor,
    payload: &SupervisionLease,
    now_ms: u64,
) -> SupervisionLeaseVerificationContext {
    SupervisionLeaseVerificationContext {
        now_ms,
        lease_id: payload.lease_id.clone(),
        host_epoch: payload.host_epoch,
        activation_id: payload.activation_id.clone(),
        activation_generation: payload.activation_generation,
        kernel_epoch: payload.kernel_epoch,
        watchdog_epoch: payload.watchdog_epoch,
        state_fence: payload.state_fence.clone(),
        scope_ref: payload.scope_ref.clone(),
        observation_scope: payload.observation_scope.clone(),
        target_id: payload.generation_binding.target_id.clone(),
        module_id: payload.generation_binding.module_id.clone(),
        process_id: payload.generation_binding.process_id.clone(),
        target_generation: payload.generation_binding.target_generation,
        module_generation: payload.generation_binding.module_generation,
        process_generation: payload.generation_binding.process_generation,
        public_key_fingerprint: trust_anchor.public_key_fingerprint.clone(),
        ors_mirror: payload.ors_mirror.clone(),
        active_state: SupervisionLeaseActiveStateBinding {
            state: payload.state,
            revocation_id: payload.revocation_id.clone(),
            revocation_epoch: payload.revocation_epoch,
        },
    }
}

#[cfg(windows)]
pub(super) fn verify_superseded_supervision_replay(
    ors: &RedbRecoveryStore,
    trust_anchor: &SupervisionTrustAnchor,
    terminal: &SupervisionLeaseSnapshot,
    expected_predecessor: &SupervisionLeasePredecessorIdentity,
) -> Result<(), SupervisionLeaseAuthorityError> {
    terminal
        .validate()
        .map_err(SupervisionLeaseAuthorityError::Ors)?;
    expected_predecessor
        .validate()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    if terminal.record.operation != SupervisionLeaseOperation::Supersede
        || terminal.record.state != LeaseState::Superseded
        || terminal.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
        || terminal.record.binding.terminal_disposition
            != Some(SupervisionLeaseTerminalDisposition::Superseded)
        || terminal.record.lease_id.as_str() != expected_predecessor.supervision_lease_id
        || terminal.record.previous_receipt_sha256.as_deref()
            != Some(expected_predecessor.ors_receipt_sha256.as_str())
    {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let lease_id = OperationIdentity::new(expected_predecessor.supervision_lease_id.clone())?;
    let history = ors.load_supervision_lease_history(&lease_id, 2)?;
    if history.len() != 2 || history.first() != Some(terminal) {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let prior = &history[1];
    prior
        .validate()
        .map_err(SupervisionLeaseAuthorityError::Ors)?;
    if prior.record.state != LeaseState::Active
        || prior.record.projection != eliot_ors::SupervisionLeaseProjection::Active
        || prior.record.lease_id != lease_id
        || prior.record.revision.checked_add(1) != Some(terminal.record.revision)
        || prior.receipt.receipt_sha256 != expected_predecessor.ors_receipt_sha256
    {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let prior_context = verification_context_for_supervision_payload(
        trust_anchor,
        &prior.record.artifact.payload,
        prior.record.artifact.payload.issued_at_ms,
    );
    let verified_prior = trust_anchor
        .verify(&prior.record.artifact, &prior_context)
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let predecessor_proof = SupervisionLeasePredecessorProof {
        lease_id: prior.record.lease_id.as_str().to_owned(),
        record_id: prior.record.record_id.as_str().to_owned(),
        lease_revision: prior.record.revision,
        receipt_sha256: prior.receipt.receipt_sha256.clone(),
        envelope_sha256: prior
            .record
            .artifact
            .envelope_digest()
            .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?,
    };
    trust_anchor
        .verify_terminal_transition(
            &verified_prior,
            &terminal.record.artifact,
            &predecessor_proof,
        )
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn supervision_operation_identity(
    kind: &str,
    lease_id: &str,
    predecessor_receipt: Option<&str>,
) -> Result<OperationIdentity, SupervisionLeaseAuthorityError> {
    let digest = sha256_json(&(kind, lease_id, predecessor_receipt))
        .map_err(|error| SupervisionLeaseAuthorityError::Configuration(error.to_string()))?;
    OperationIdentity::new(format!("eliot-supervision:{kind}:{digest}")).map_err(Into::into)
}

#[cfg(windows)]
pub(super) fn supervision_binding_matches_contour(
    binding: &eliot_ors::SupervisionLeaseBinding,
    contour: &DaemonSupervisionContour,
) -> Result<bool, SupervisionLeaseAuthorityError> {
    let incarnation = &contour.incarnation;
    let scope_ref = incarnation
        .derived_scope_ref()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let watchdog_epoch = AuthorityEpoch::new(incarnation.watchdog_epoch.sequence)
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(binding.scope_ref.as_str() == scope_ref
        && binding.observation_scope == incarnation.observation_scope
        && binding.installation_id.as_str() == incarnation.installation_id
        && binding.host_epoch.value() == incarnation.host_epoch.sequence
        && binding.activation_id.as_str() == incarnation.activation_id
        && binding.activation_generation == contour.activation.generation
        && binding.kernel_epoch == contour.activation.authority_epoch
        && binding.watchdog_epoch == watchdog_epoch
        && binding.generation_binding == contour.generation_binding
        && binding.state_fence == contour.state_fence
        && binding.wake_policy == incarnation.wake_policy)
}
