//! Kernel supervision lease authority — Architecture A2.3/A13.2; Implementation I1.8 admission-validation-ORS-receipt/static_native authority/fencing/bounded `FunctionalCapabilityCell`.
//! Boundary owns Kernel mechanical identity/fencing/ORS supervision authority only.
//! No semantic/default authority, no alternate lease, no unbounded restart, no daemon-owned canonical transition.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_contracts::{AuthorityEpoch, StateFence};
#[cfg(windows)]
use eliot_installation::InstallationProfile;
use eliot_ors::{
    OperationIdentity, OrsError, RedbRecoveryStore, SupervisionLeaseCommitTicket,
    SupervisionLeaseOperation, SupervisionLeasePrepareRequest, SupervisionLeaseSnapshot,
    SupervisionLeaseStageReceipt,
};
use eliot_platform_windows::{
    FileIdentity, InstallerRootPrimitiveSpec, InstallerRootProfile,
    WindowsPortableDevSupervisionAuthorityKeyProvider, WindowsSupervisionAuthorityKeyStore,
    WindowsUserModeSupervisionAuthorityCredentialProvider, protected_program_data_root,
};
use eliot_process::EliotdLiveSupervisionEvidence;
#[cfg(windows)]
use eliot_runtime_contracts::SupervisionAuthorityKeyReference;
#[cfg(windows)]
use eliot_runtime_contracts::{
    DaemonSupervisionCurrentState, DaemonSupervisionHeartbeatError,
    DaemonSupervisionRenewalDecision, DaemonSupervisionRenewalOutcome,
    DaemonSupervisionRenewalReceipt,
};
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, LeaseState, ProvisionedSupervisionAuthority, SupervisionLease,
    SupervisionLeaseActiveStateBinding, SupervisionLeaseError, SupervisionLeasePredecessorIdentity,
    SupervisionLeasePredecessorProof, SupervisionLeaseSigner, SupervisionLeaseTerminalDisposition,
    SupervisionLeaseVerificationContext, SupervisionLeaseVerifier, SupervisionTrustAnchor,
};

use crate::KernelBuildError;
#[cfg(windows)]
use crate::SupervisionLeaseAuthorityConfig;
#[cfg(windows)]
use crate::daemon_supervision::DaemonSupervisionContour;
#[cfg(windows)]
use crate::daemon_supervision::DaemonSupervisionProgressState;

/// F-LOG-KERNEL-3 (#901): supervision-lease boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.supervision.*` event
/// names plus a bounded stable outcome, explicitly parented by the owning
/// operation. Identity references are screened and recorded on the span,
/// never repeated as event fields (I15.4).
#[cfg(windows)]
fn observe_supervision_lease(context: &tracing::Span, event: &'static str, outcome: &'static str) {
    use crate::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "supervision lease observation"
    );
}

/// Builds the bounded diagnostic projection from the identity material the
/// lease-ticket owner already holds. `state_fence` contains only the
/// lineage-aware epoch digest and that fence's original resource generation;
/// it is a scope projection, not the full fence or nonce identity.
#[cfg(windows)]
fn supervision_lease_operation_context(ticket: &SupervisionLeaseCommitTicket) -> tracing::Span {
    use crate::kernel_diagnostics::operation_context;

    // A ticket is an ORS-owned value. Its fields are not observation
    // evidence until the original ORS validator accepts the whole ticket.
    if ticket.validate().is_err() {
        return operation_context(None, None, None, None);
    }

    let binding = &ticket.binding;
    let epoch_digest =
        StateFence::canonical_epoch_digest(&binding.state_fence.authority_epoch).ok();
    let generation = binding
        .generation_binding
        .process_generation
        .value()
        .to_string();
    let state_fence = epoch_digest.as_ref().map(|epoch| {
        format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            binding.state_fence.resource_generation.value()
        )
    });
    let context = operation_context(
        Some(ticket.operation_id.as_str()),
        Some(&generation),
        state_fence.as_deref(),
        epoch_digest
            .as_ref()
            .map(eliot_contracts::LowercaseSha256::as_str),
    );
    record_supervision_ticket_context(&context, ticket);
    context
}

#[cfg(windows)]
fn record_supervision_ticket_context(
    context: &tracing::Span,
    ticket: &SupervisionLeaseCommitTicket,
) {
    use crate::kernel_diagnostics::bound_field;

    // A shared caller span can cross more than one lease phase. Clear the
    // previous phase's discriminator before validating the next ticket so an
    // invalid ticket cannot inherit stale diagnostic meaning.
    let unavailable_operation = bound_field("unavailable");
    context.record("lease_operation", unavailable_operation.text());

    // Keep invalid ticket references unavailable even when the caller shares
    // a broader operation span with this authority boundary.
    if ticket.validate().is_err() {
        return;
    }

    let operation_label = match ticket.operation {
        SupervisionLeaseOperation::Commit => "commit",
        SupervisionLeaseOperation::Renew => "renew",
        SupervisionLeaseOperation::Revoke => "revoke",
        SupervisionLeaseOperation::Expire => "expire",
        SupervisionLeaseOperation::Supersede => "supersede",
        SupervisionLeaseOperation::Close => "close",
    };
    let lease_operation = bound_field(operation_label);
    context.record("lease_operation", lease_operation.text());

    let lease = bound_field(ticket.lease_id.as_str());
    context.record("lease", lease.text());
    if let Some(receipt_sha256) = ticket.previous_receipt_sha256.as_deref() {
        let receipt = bound_field(receipt_sha256);
        context.record("receipt", receipt.text());
    }
}

#[cfg(windows)]
fn record_supervision_ticket_operation_context(
    context: &tracing::Span,
    ticket: &SupervisionLeaseCommitTicket,
) {
    use crate::kernel_diagnostics::bound_field;

    if ticket.validate().is_err() {
        return;
    }

    let operation = bound_field(ticket.operation_id.as_str());
    context.record("operation", operation.text());
    context.record(
        "operation_redaction",
        operation.redaction_status().unwrap_or("none"),
    );
    let generation_value = ticket
        .binding
        .generation_binding
        .process_generation
        .value()
        .to_string();
    let generation = bound_field(&generation_value);
    context.record("generation", generation.text());
    context.record(
        "generation_redaction",
        generation.redaction_status().unwrap_or("none"),
    );
    let epoch =
        StateFence::canonical_epoch_digest(&ticket.binding.state_fence.authority_epoch).ok();
    if let Some(epoch) = epoch.as_ref() {
        let authority_epoch = bound_field(epoch.as_str());
        context.record("authority_epoch", authority_epoch.text());
        context.record(
            "authority_epoch_redaction",
            authority_epoch.redaction_status().unwrap_or("none"),
        );
        let state_fence_value = format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            ticket.binding.state_fence.resource_generation.value()
        );
        let state_fence = bound_field(&state_fence_value);
        context.record("state_fence", state_fence.text());
        context.record(
            "state_fence_redaction",
            state_fence.redaction_status().unwrap_or("none"),
        );
    }
}

#[cfg(windows)]
fn supervision_expiry_operation_context(
    supervision_lease_id: &str,
    expected_fence: &StateFence,
) -> tracing::Span {
    use crate::kernel_diagnostics::{bound_field, operation_context};

    let epoch_digest = StateFence::canonical_epoch_digest(&expected_fence.authority_epoch).ok();
    let generation = expected_fence.resource_generation.value().to_string();
    let state_fence = epoch_digest.as_ref().map(|epoch| {
        format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            expected_fence.resource_generation.value()
        )
    });
    let context = operation_context(
        None,
        Some(&generation),
        state_fence.as_deref(),
        epoch_digest
            .as_ref()
            .map(eliot_contracts::LowercaseSha256::as_str),
    );
    let lease = bound_field(supervision_lease_id);
    context.record("lease", lease.text());
    context
}

/// Maps one supervision-lease authority failure to its stable code.
///
/// Only the variant is emitted; any `String` payload or embedded ORS error
/// is never logged.
#[cfg(windows)]
fn supervision_authority_terminal_code(error: &SupervisionLeaseAuthorityError) -> &'static str {
    match error {
        SupervisionLeaseAuthorityError::Configuration(_) => "SUPERVISION_CONFIGURATION",
        SupervisionLeaseAuthorityError::ProtectedKeyUnavailable => "SUPERVISION_KEY_UNAVAILABLE",
        SupervisionLeaseAuthorityError::Contract(_) => "SUPERVISION_CONTRACT",
        SupervisionLeaseAuthorityError::Ors(
            OrsError::DuplicateConflict | OrsError::SupervisionLeaseTicketConflict,
        ) => "SUPERVISION_IDENTITY_CONFLICT",
        SupervisionLeaseAuthorityError::Ors(OrsError::SupervisionLeaseStaleRevision) => {
            "SUPERVISION_STALE_REVISION"
        }
        SupervisionLeaseAuthorityError::Ors(OrsError::SupervisionLeaseTicketExpired) => {
            "SUPERVISION_TICKET_EXPIRED"
        }
        SupervisionLeaseAuthorityError::Ors(_) => "SUPERVISION_ORS",
    }
}

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
    installation_profile: InstallationProfile,
    portable_dev_repository_root: Option<(PathBuf, FileIdentity)>,
    key_store: WindowsSupervisionAuthorityKeyStore,
    user_mode_key_provider: WindowsUserModeSupervisionAuthorityCredentialProvider,
    portable_dev_key_provider: WindowsPortableDevSupervisionAuthorityKeyProvider,
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
            .field("key_provider", &self.authority.key_reference.provider())
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl ProtectedSupervisionLeaseSigner {
    pub(super) fn new_for_profile(
        kernel_root: PathBuf,
        installation_profile: InstallationProfile,
        portable_dev_repository_root: Option<(PathBuf, FileIdentity)>,
        config: &SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, SupervisionLeaseAuthorityError> {
        config
            .validate()
            .map_err(SupervisionLeaseAuthorityError::Configuration)?;
        validate_profile_key_reference(
            installation_profile,
            portable_dev_repository_root.as_ref(),
            &config.authority.key_reference,
        )
        .map_err(SupervisionLeaseAuthorityError::Configuration)?;
        let signer = Self {
            kernel_root,
            installation_profile,
            portable_dev_repository_root,
            key_store: WindowsSupervisionAuthorityKeyStore::new(),
            user_mode_key_provider: WindowsUserModeSupervisionAuthorityCredentialProvider::new(),
            portable_dev_key_provider: WindowsPortableDevSupervisionAuthorityKeyProvider::new(),
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
        let signer = match (&self.installation_profile, &self.authority.key_reference) {
            (
                InstallationProfile::SystemService,
                SupervisionAuthorityKeyReference::SystemService(_),
            ) => {
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
                let signer_result = Ed25519SupervisionLeaseSigner::from_secret_key(
                    self.signer_id.clone(),
                    self.key_id.clone(),
                    key_bytes,
                );
                key_bytes.fill(0);
                signer_result?
            }
            (
                InstallationProfile::UserMode,
                SupervisionAuthorityKeyReference::UserMode(reference),
            ) => self
                .user_mode_key_provider
                .load_signer_for_kernel(reference, &self.authority.trust_anchor)
                .map_err(|_| {
                    SupervisionLeaseError::Signing(
                        "current-user supervision signing key unavailable".to_owned(),
                    )
                })?,
            (
                InstallationProfile::PortableDev,
                SupervisionAuthorityKeyReference::PortableDev(reference),
            ) => {
                let (repository_root, repository_root_identity) =
                    self.portable_dev_repository_root.as_ref().ok_or_else(|| {
                        SupervisionLeaseError::Signing(
                            "PortableDev repository root is unavailable".to_owned(),
                        )
                    })?;
                self.portable_dev_key_provider
                    .load_signer_for_kernel(
                        reference,
                        repository_root,
                        *repository_root_identity,
                        &self.authority.trust_anchor,
                    )
                    .map_err(|_| {
                        SupervisionLeaseError::Signing(
                            "PortableDev supervision signing key unavailable".to_owned(),
                        )
                    })?
            }
            _ => {
                return Err(SupervisionLeaseError::Signing(
                    "installation profile does not match supervision key reference".to_owned(),
                ));
            }
        };
        if signer.signer_id() != self.signer_id
            || signer.key_id() != self.key_id
            || sha256_hex(&signer.public_key()) != self.expected_public_key_fingerprint
        {
            return Err(SupervisionLeaseError::Signing(
                "supervision signing key does not match the installation trust anchor".to_owned(),
            ));
        }
        Ok(signer)
    }

    pub fn key_reference(&self) -> &SupervisionAuthorityKeyReference {
        &self.authority.key_reference
    }
}

#[cfg(windows)]
fn validate_profile_key_reference(
    profile: InstallationProfile,
    portable_dev_repository_root: Option<&(PathBuf, FileIdentity)>,
    key_reference: &SupervisionAuthorityKeyReference,
) -> Result<(), String> {
    let reference_is_valid = match (profile, portable_dev_repository_root, key_reference) {
        (
            InstallationProfile::SystemService,
            None,
            SupervisionAuthorityKeyReference::SystemService(reference),
        ) => reference.validate().is_ok(),
        (
            InstallationProfile::UserMode,
            None,
            SupervisionAuthorityKeyReference::UserMode(reference),
        ) => reference.validate().is_ok(),
        (
            InstallationProfile::PortableDev,
            Some((repository_root, _)),
            SupervisionAuthorityKeyReference::PortableDev(reference),
        ) => {
            repository_root.is_absolute()
                && !repository_root.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
                && reference.validate().is_ok()
        }
        _ => false,
    };
    if reference_is_valid {
        Ok(())
    } else {
        Err(
            "selected installation profile does not match its supervision key reference or root"
                .to_owned(),
        )
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
        installation_profile: InstallationProfile,
        portable_dev_repository_root: Option<(PathBuf, FileIdentity)>,
        config: SupervisionLeaseAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let signer = ProtectedSupervisionLeaseSigner::new_for_profile(
            kernel_root,
            installation_profile,
            portable_dev_repository_root,
            &config,
        )
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

    pub fn key_reference(&self) -> &SupervisionAuthorityKeyReference {
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

    /// Reads the live eliotd supervision evidence for one exact lease id,
    /// generation and authority epoch.
    ///
    /// This is the evidence-only view of `current_eliotd_live_projection`: it
    /// drops the issue timestamp and keeps the validated
    /// [`EliotdLiveSupervisionEvidence`]. Every binding check — active lease
    /// state and projection, exact lease identity, resource generation, and
    /// authority epoch — belongs to that projection, which this method does not
    /// reimplement or relax.
    ///
    /// Live status: no production caller. Measured on this tree, no code in any
    /// crate names this method other than its defining line. The live Kernel
    /// live-receipt path (`bins/eliot-kernel/src/daemon_live_receipt.rs`) calls
    /// `current_eliotd_live_projection` directly, twice — before and after the
    /// launch recheck — because it needs the issued-at timestamp as well as the
    /// evidence to prove neither moved across the launch. So this evidence-only
    /// accessor is the unused projection of that live call, not a second live
    /// route. Whether a consumer needs the evidence without the timestamp or the
    /// accessor is retired is an owner decision; no caller was added to close
    /// the gap.
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
            || current
                .record
                .binding
                .state_fence
                .authority_epoch
                .sequence
                .get()
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
        let context = supervision_lease_operation_context(ticket);
        self.commit_active_in_context(ticket, &context)
    }

    pub(crate) fn commit_active_in_context(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        context: &tracing::Span,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        // F-LOG-KERNEL-3 (#901): lease acquire/renew boundary. Exact replay
        // is read back inside, not recommitted; exactly one terminal is
        // emitted per failed commit and no lease material is logged.
        record_supervision_ticket_context(context, ticket);
        observe_supervision_lease(context, "kernel.supervision.commit_requested", "attempt");
        match self.commit_active_inner(ticket) {
            Ok(snapshot) => {
                observe_supervision_lease(
                    context,
                    "kernel.supervision.commit_committed",
                    "success",
                );
                Ok(snapshot)
            }
            Err(error) => {
                observe_supervision_lease(context, "kernel.supervision.commit_failed", "rejected");
                crate::kernel_diagnostics::observe_terminal_error_in_context(
                    supervision_authority_terminal_code(&error),
                    context,
                );
                Err(error)
            }
        }
    }

    fn commit_active_inner(
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
        let context = supervision_lease_operation_context(ticket);
        let mut terminal_owned = false;
        self.commit_terminal_in_context(ticket, &context, &mut terminal_owned)
    }

    pub(crate) fn commit_terminal_in_context(
        &self,
        ticket: &SupervisionLeaseCommitTicket,
        context: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<SupervisionLeaseSnapshot, SupervisionLeaseAuthorityError> {
        // F-LOG-KERNEL-3 (#901): lease revoke/expire/supersede/close
        // boundary. A terminal disposition stays terminal; exactly one
        // terminal diagnostic is emitted per failed commit.
        record_supervision_ticket_context(context, ticket);
        observe_supervision_lease(context, "kernel.supervision.terminal_requested", "attempt");
        match self.commit_terminal_inner(ticket) {
            Ok(snapshot) => {
                *terminal_owned = false;
                observe_supervision_lease(
                    context,
                    "kernel.supervision.terminal_committed",
                    "success",
                );
                Ok(snapshot)
            }
            Err(error) => {
                observe_supervision_lease(
                    context,
                    "kernel.supervision.terminal_failed",
                    "rejected",
                );
                crate::kernel_diagnostics::observe_terminal_error_in_context(
                    supervision_authority_terminal_code(&error),
                    context,
                );
                *terminal_owned = true;
                Err(error)
            }
        }
    }

    fn commit_terminal_inner(
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

    /// Terminalizes an `Active` supervision lease whose validity interval has
    /// elapsed without a proved renewal.
    ///
    /// I1.5: "If renewal cannot be proved, coverage ends at expiry and is
    /// reported honestly." An expired-but-`Active` durable head still blocks
    /// generation retirement (`RuntimeLeaseCensus::is_fully_retired` admits
    /// only terminal heads), so the expiry must be committed durably rather
    /// than merely refused in memory. The commit reuses the staged-ticket
    /// owner (`prepare`) and the terminal boundary (`commit_terminal`): the
    /// `Expire` ticket is fenced on the exact current revision and receipt,
    /// preserves the current lineage including its timing, and carries no
    /// renewal evidence because none was observed.
    ///
    /// Returns `Ok(None)` when no expiry is due: no head exists, the head is
    /// already non-`Active`, or `now_ms` precedes `expires_at_ms`. The caller
    /// supplies its own tick clock (`now_ms`) and the fence it currently
    /// supervises; a fence mismatch fails closed rather than expiring another
    /// generation's lease. A staged `Expire` ticket for the same predecessor
    /// is resumed by identity; a staged ticket for any other operation is a
    /// typed conflict, never stomped.
    ///
    /// Production callers in `bins/eliot-kernel/src/lib.rs`:
    /// `KernelComposition::renew_current_supervision_with_progress`, on the
    /// renewal-refusal tick for both the progress-submit and probe paths, and
    /// `KernelComposition::renew_daemon_supervision_for_probe_in_context`, on the probe
    /// pre-check where that tick is never reached for a past-due head.
    pub fn expire_past_due_lease(
        &self,
        supervision_lease_id: &str,
        expected_fence: &StateFence,
        now_ms: u64,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        self.expire_past_due_lease_with_context(supervision_lease_id, expected_fence, now_ms, None)
    }

    pub(crate) fn expire_past_due_lease_in_context(
        &self,
        supervision_lease_id: &str,
        expected_fence: &StateFence,
        now_ms: u64,
        context: &tracing::Span,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        self.expire_past_due_lease_with_context(
            supervision_lease_id,
            expected_fence,
            now_ms,
            Some(context),
        )
    }

    fn expire_past_due_lease_with_context(
        &self,
        supervision_lease_id: &str,
        expected_fence: &StateFence,
        now_ms: u64,
        supplied_context: Option<&tracing::Span>,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let owned_context;
        let context = if let Some(context) = supplied_context {
            context
        } else {
            owned_context =
                supervision_expiry_operation_context(supervision_lease_id, expected_fence);
            &owned_context
        };
        let record_ticket_operation = supplied_context.is_none();
        let mut child_terminal_owned = false;
        let result = self.expire_past_due_lease_inner_with_context(
            supervision_lease_id,
            expected_fence,
            now_ms,
            context,
            record_ticket_operation,
            &mut child_terminal_owned,
        );
        if let Err(error) = &result {
            observe_supervision_lease(context, "kernel.supervision.expire_failed", "rejected");
            if !child_terminal_owned {
                crate::kernel_diagnostics::observe_terminal_error_in_context(
                    supervision_authority_terminal_code(error),
                    context,
                );
            }
        }
        result
    }

    fn expire_past_due_lease_inner_with_context(
        &self,
        supervision_lease_id: &str,
        expected_fence: &StateFence,
        now_ms: u64,
        context: &tracing::Span,
        record_ticket_operation: bool,
        child_terminal_owned: &mut bool,
    ) -> Result<Option<SupervisionLeaseSnapshot>, SupervisionLeaseAuthorityError> {
        let Some(current) = self.current_snapshot(supervision_lease_id)? else {
            return Ok(None);
        };
        if current.record.state != LeaseState::Active
            || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
            || now_ms < current.record.binding.expires_at_ms
        {
            return Ok(None);
        }
        observe_supervision_lease(context, "kernel.supervision.expire_requested", "attempt");
        if current.record.binding.state_fence != *expected_fence {
            return Err(SupervisionLeaseAuthorityError::Ors(
                OrsError::SupervisionLeaseBindingMismatch,
            ));
        }
        let mut binding = current.record.binding.clone();
        binding.state = LeaseState::Expired;
        binding.terminal_disposition = Some(SupervisionLeaseTerminalDisposition::Expired);
        let stage = if let Some(stage) = self.staged_snapshot(supervision_lease_id)? {
            if stage.ticket.operation != SupervisionLeaseOperation::Expire
                || stage.ticket.expected_revision != Some(current.record.revision)
                || stage.ticket.previous_receipt_sha256.as_deref()
                    != Some(current.receipt.receipt_sha256.as_str())
                || stage.ticket.binding != binding
            {
                return Err(SupervisionLeaseAuthorityError::Ors(
                    OrsError::SupervisionLeaseTicketConflict,
                ));
            }
            stage
        } else {
            self.prepare(SupervisionLeasePrepareRequest {
                ticket_id: supervision_operation_identity(
                    "expire-ticket",
                    supervision_lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                operation_id: supervision_operation_identity(
                    "expire-operation",
                    supervision_lease_id,
                    Some(&current.receipt.receipt_sha256),
                )?,
                lease_id: OperationIdentity::new(supervision_lease_id.to_owned())?,
                expected_revision: Some(current.record.revision),
                operation: SupervisionLeaseOperation::Expire,
                binding,
            })?
        };
        // F-LOG-KERNEL-3 (#901): lease-expiry boundary. Only an attempted
        // expiry is observed; routine not-due ticks stay unlogged. Exactly one
        // terminal is emitted per failed commit and no lease material is
        // logged.
        record_supervision_ticket_context(context, &stage.ticket);
        if record_ticket_operation {
            record_supervision_ticket_operation_context(context, &stage.ticket);
        }
        match self.commit_terminal_in_context(&stage.ticket, context, child_terminal_owned) {
            Ok(snapshot) => {
                if snapshot.record.state != LeaseState::Expired
                    || snapshot.record.projection != eliot_ors::SupervisionLeaseProjection::Terminal
                {
                    return Err(SupervisionLeaseAuthorityError::Ors(
                        OrsError::SupervisionLeaseBindingMismatch,
                    ));
                }
                observe_supervision_lease(
                    context,
                    "kernel.supervision.expire_committed",
                    "success",
                );
                Ok(Some(snapshot))
            }
            Err(error) => {
                // `commit_terminal_in_context` owns the one terminal. Expiry
                // only observes this propagated failure at its own level.
                Err(error)
            }
        }
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
        kernel_epoch: payload.kernel_epoch.clone(),
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

// ============================================================================
// Wave-2 progress renewal surface (issue #88): typed refusal taxonomy,
// CurrentState built from the exact ORS predecessor, and renewal receipts.
// The pure join (`evaluate_daemon_supervision_renewal`) decides; these
// helpers bind its inputs to durable Kernel authority and assemble its
// outputs without adding a second timing owner or a health-based renewal.

/// Typed progress-renewal failure: durable authority errors stay distinct
/// from contract-join refusals so `ReconciliationRequired` (a decision) and
/// `Expired` / `IDENTITY_CONFLICT` (typed refusals) surface instead of
/// collapsing into strings.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) enum SupervisionProgressRenewalError {
    /// Durable authority, ORS, or configuration failure.
    Authority(SupervisionLeaseAuthorityError),
    /// Contract-join refusal (`Expired`, `IDENTITY_CONFLICT`, predecessor /
    /// lineage / cursor / gap reasons).
    Heartbeat(DaemonSupervisionHeartbeatError),
}

#[cfg(windows)]
impl fmt::Display for SupervisionProgressRenewalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(formatter, "supervision progress authority: {error}"),
            Self::Heartbeat(error) => write!(formatter, "supervision progress refused: {error}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for SupervisionProgressRenewalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Heartbeat(error) => Some(error),
        }
    }
}

#[cfg(windows)]
impl From<OrsError> for SupervisionProgressRenewalError {
    fn from(error: OrsError) -> Self {
        Self::Authority(SupervisionLeaseAuthorityError::from(error))
    }
}

#[cfg(windows)]
impl From<SupervisionLeaseAuthorityError> for SupervisionProgressRenewalError {
    fn from(error: SupervisionLeaseAuthorityError) -> Self {
        Self::Authority(error)
    }
}

#[cfg(windows)]
impl From<DaemonSupervisionHeartbeatError> for SupervisionProgressRenewalError {
    fn from(error: DaemonSupervisionHeartbeatError) -> Self {
        Self::Heartbeat(error)
    }
}

/// Builds the exact renewal-join state from the durable ORS predecessor plus
/// Kernel-owned lineage (contour) and progress continuity (tracker).
///
/// The predecessor proof is the exact current snapshot (lease, record,
/// revision, receipt, envelope digests); the lease window is the durable
/// binding window. A non-active head fails closed here, and an unadmitted
/// boot/session binding is a configuration refusal, never a silent default.
/// `ReconciliationRequired` and `Expired` then surface from the join itself.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "CurrentState assembly must bind every predecessor, lineage, window, and progress field explicitly"
)]
pub(super) fn daemon_supervision_current_state(
    snapshot: &SupervisionLeaseSnapshot,
    contour: &DaemonSupervisionContour,
    progress: &DaemonSupervisionProgressState,
) -> Result<DaemonSupervisionCurrentState, SupervisionLeaseAuthorityError> {
    snapshot
        .validate()
        .map_err(SupervisionLeaseAuthorityError::Ors)?;
    if snapshot.record.state != LeaseState::Active
        || snapshot.record.projection != eliot_ors::SupervisionLeaseProjection::Active
    {
        return Err(SupervisionLeaseAuthorityError::Ors(
            OrsError::SupervisionLeaseBindingMismatch,
        ));
    }
    let envelope_sha256 = snapshot
        .record
        .artifact
        .envelope_digest()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let boot_id = progress.boot_id.clone().ok_or_else(|| {
        SupervisionLeaseAuthorityError::Configuration(
            "daemon progress boot binding is not admitted".to_owned(),
        )
    })?;
    let transport_session_evidence =
        progress.transport_session_evidence.clone().ok_or_else(|| {
            SupervisionLeaseAuthorityError::Configuration(
                "daemon progress transport-session binding is not admitted".to_owned(),
            )
        })?;
    let current = DaemonSupervisionCurrentState {
        predecessor: SupervisionLeasePredecessorProof {
            lease_id: snapshot.record.lease_id.as_str().to_owned(),
            record_id: snapshot.record.record_id.as_str().to_owned(),
            lease_revision: snapshot.record.revision,
            receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
            envelope_sha256,
        },
        installation_id: contour.incarnation.installation_id.clone(),
        activation_id: contour.incarnation.activation_id.clone(),
        activation_generation: contour.activation.generation,
        kernel_epoch: contour.activation.authority_epoch.clone(),
        state_fence: contour.state_fence.clone(),
        generation_binding: contour.generation_binding.clone(),
        boot_id,
        transport_session_evidence,
        lease_issued_at_ms: snapshot.record.binding.issued_at_ms,
        lease_expires_at_ms: snapshot.record.binding.expires_at_ms,
        accepted_cursors: progress.accepted_cursors.clone(),
        admitted_idle_contract: progress.admitted_idle_contract.clone(),
        last_monotonic_ms: progress.last_monotonic_ms,
        last_request_id: progress.last_request_id.clone(),
        last_observation_sha256: progress.last_observation_sha256.clone(),
        last_successor_revision: progress.last_successor_revision,
        reconciliation_pending: progress.reconciliation_pending,
    };
    current
        .validate()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(current)
}

/// Assembles the durable renewal receipt for a join decision.
///
/// A `RENEWED` decision requires the committed successor receipt digest and
/// the published live-receipt digest together; every other outcome carries
/// neither, so a blocked renewal (`DegradedNoRenewal`, `ReconciliationRequired`,
/// `NotDue`, `ExactReplay`) can never be mistaken for advanced authority.
/// The caller supplies the live-receipt digest after publication; wave 3
/// (MGR02) owns that publication step on the `ProbeReady` path.
#[cfg(windows)]
pub(super) fn daemon_renewal_receipt_for_decision(
    decision: &DaemonSupervisionRenewalDecision,
    successor_receipt_sha256: Option<String>,
    live_receipt_sha256: Option<String>,
) -> Result<DaemonSupervisionRenewalReceipt, SupervisionLeaseAuthorityError> {
    decision
        .validate()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    let digests_coherent = match decision.outcome {
        DaemonSupervisionRenewalOutcome::Renewed => {
            successor_receipt_sha256.is_some() && live_receipt_sha256.is_some()
        }
        DaemonSupervisionRenewalOutcome::ExactReplay
        | DaemonSupervisionRenewalOutcome::NotDue
        | DaemonSupervisionRenewalOutcome::DegradedNoRenewal
        | DaemonSupervisionRenewalOutcome::ReconciliationRequired => {
            successor_receipt_sha256.is_none() && live_receipt_sha256.is_none()
        }
    };
    if !digests_coherent {
        return Err(SupervisionLeaseAuthorityError::Configuration(
            "renewal receipt digests do not match the decision outcome".to_owned(),
        ));
    }
    let receipt = DaemonSupervisionRenewalReceipt {
        request_id: decision.request_id.clone(),
        lease_id: decision.lease_id.clone(),
        outcome: decision.outcome,
        predecessor_revision: decision.predecessor_revision,
        successor_revision: decision.successor_revision,
        predecessor_receipt_sha256: decision.predecessor_receipt_sha256.clone(),
        successor_receipt_sha256,
        live_receipt_sha256,
    };
    receipt
        .validate()
        .map_err(|error| SupervisionLeaseAuthorityError::Contract(error.to_string()))?;
    Ok(receipt)
}

#[cfg(all(test, windows))]
mod process_supervision_identity_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    //! Issue #901 `W10`, `W32`, `W28` — process supervision identity, the
    //! descendant-closure boundary, and unavailable-identity projection, proved
    //! in-crate against the production `eliot-kernel` callsites.
    //!
    //! This suite owns no runtime authority, no process ownership and no Store
    //! ownership. It drives only existing production entry points:
    //!
    //! * `process_execution.rs::ProcessExecutionGateway::close_registered_descendant_in_context`
    //!   and `::close_all_registered_descendants` over the production descendant
    //!   registry in `activation_lifecycle.rs`;
    //! * `process_execution.rs::ProcessExecutionGateway::inspect_exact_running_receipt_in_context`
    //!   and `::start_in_context`;
    //! * `process_execution.rs::ProcessStartPorts::{begin, persist_completed}` over a
    //!   real `RedbRecoveryStore`, and `::execute` over the real
    //!   `WindowsProcessExecutor`, which performs one real suspended Windows child
    //!   launch and leaves a real live handle behind;
    //! * `activation_lifecycle.rs::RegisteredDescendant`.
    //!
    //! Nothing here re-implements a production decision. Where a case needs a
    //! receipt production never mints — a receipt whose OS process id equals the
    //! recorded one but whose creation marker does not — that receipt is produced
    //! by re-reading PRODUCTION's own serialized bytes with exactly ONE coordinate
    //! changed, and the case asserts that precisely: the coordinate is the only
    //! difference, both receipts pass production's own `ProcessStartReceipt::validate`,
    //! and the process id is byte-identical.

    use super::*;
    use crate::*;

    use crate::activation_lifecycle::RegisteredDescendant;
    use crate::process_execution::authorize_process_owner_in_context;
    use eliot_kernel_core::{
        AuthoritySnapshotBinding, DispatchSnapshotCodec, KernelAuthorityReplaySnapshot,
        KernelError, KernelResult, SealedAuthoritySnapshot,
    };
    use eliot_ors::{
        EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, ProcessStartReplayRecord,
        ProcessStartReplayState, RecoveryPayload, StateFenceSnapshot,
    };
    use eliot_platform::{ClockObservation, PlatformHandle, SecretReference};
    use eliot_process::{
        ActionLeaseRef, DispatchPermitAuthority, EnvironmentInheritance, EnvironmentProjection,
        FencingToken, Generation, ImageId, JobId, OperationId, PermitIssuance,
        ProcessExecutionView, ProcessExecutor, ProcessIntent, ProcessOwnerBinding, ProcessRequest,
        ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
    };
    use eliot_runtime_contracts::{
        RegisteredActivityWakePolicy, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
        SupervisionObservationScope,
    };
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    // ---------------------------------------------------------------------------
    // Tracing capture seam.
    //
    // The renderer writes exactly one `{` before the whole space-separated
    // `FormattedFields` run, so `{slot="` never occurs; and a recorded value is
    // appended after the declared default, so `span_field` must take the value
    // after the LAST occurrence of `slot="` on the line.
    // ---------------------------------------------------------------------------

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    /// Captures one async run. The `DefaultGuard` is bound for the whole async
    /// body, so the thread-local default stays current across every `.await`.
    ///
    /// It must NOT be `tracing::subscriber::with_default(subscriber, run).await`:
    /// `with_default` is `fn with_default<T>(dispatcher: &Dispatch, f: impl FnOnce()
    /// -> T) -> T` (tracing-core `src/dispatcher.rs:254`), so with an async `run`
    /// the generic `T` is the UN-POLLED future. It is returned, and the guard it
    /// created is dropped at that instant — before the `.await` ever polls the
    /// body. The restored prior default is `None`, `Entered::current()` falls back
    /// to `get_global()`, and this crate installs no global default, so every
    /// `info_span!` built inside the body (`operation_context_for`,
    /// `start_context_for`) would be a DISABLED span on `Dispatch::none()`:
    /// `observe_process_in_context` would emit nothing and every captured string
    /// would come back empty.
    ///
    /// `set_default` is thread-local and re-entrant rather than the process-wide,
    /// set-once global installer, so concurrent tests cannot interfere and no
    /// forbidden vocabulary enters the crate. The guard must be dropped on the
    /// thread that set it, which is why the hold across an await is only sound on
    /// the current-thread runtime that a bare `#[tokio::test]` attribute builds —
    /// hence no `tokio::spawn` anywhere in this file.
    async fn capture_with<F, Fut, T>(run: F) -> (T, String)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        // Named, not `_`-prefixed: the guard IS used - `drop` below orders the
        // unregistration before the sink is read - so the underscore would be a lie.
        let guard = tracing::subscriber::set_default(subscriber);
        let value = run().await;
        drop(guard);
        let bytes = String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned();
        (value, bytes)
    }

    /// Reads the value of one recorded span slot from a captured line.
    ///
    /// Two properties of the real renderer (tracing-subscriber 0.3.23) force this
    /// shape, both measured rather than assumed:
    ///
    /// * `Format::format_event` writes exactly one `{` before the whole
    ///   space-separated `FormattedFields` run, so the needle `{slot="` never
    ///   occurs and must not be used;
    /// * `FmtLayer::on_record` appends through `add_fields`, which pushes a space
    ///   and formats without rewriting the declared slot, so a recorded value
    ///   appears AFTER its declared default and the LAST occurrence is the recorded
    ///   value.
    ///
    /// A slot the owner never recorded occurs exactly once and resolves to its
    /// declared `"unavailable"` default, which is the honest answer for it.
    fn span_field<'a>(logs: &'a str, slot: &str) -> Option<&'a str> {
        let needle = format!("{slot}=\"");
        let start = logs.rfind(&needle)? + needle.len();
        let rest = &logs[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    fn captured_line<'a>(logs: &'a str, needle: &str) -> &'a str {
        logs.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no captured line carries {needle}; captured: {logs}"))
    }

    /// The captured line carrying one `kernel_diagnostics` observation. Each
    /// observation is emitted as the `event` field of its own record, so the event
    /// name is read from that field and never from a message position.
    fn event_line<'a>(logs: &'a str, event: &str) -> &'a str {
        captured_line(logs, &format!("event=\"{event}\""))
    }

    fn event_present(logs: &str, event: &str) -> bool {
        logs.contains(&format!("event=\"{event}\""))
    }

    fn event_count(logs: &str, event: &str) -> usize {
        logs.matches(&format!("event=\"{event}\"")).count()
    }

    fn event_outcome(logs: &str, event: &str) -> String {
        let line = event_line(logs, event);
        line.split_once("outcome=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map_or_else(
                || panic!("no outcome on the {event} line: {line}"),
                |(value, _)| value.to_owned(),
            )
    }

    // ---------------------------------------------------------------------------
    // Local fixtures. Duplicated per file by the crate's house pattern;
    // enclosing #901-owned module gains no production edit beyond this inline
    // `#[cfg(test)]` module, and no shared helper module is created.
    // ---------------------------------------------------------------------------

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_owner(module_id: &str, principal: &str) -> ProcessOwnerBinding {
        ProcessOwnerBinding::new(
            module_id,
            principal.repeat(64),
            test_epoch(1),
            Generation::new(1).expect("generation"),
        )
        .expect("owner")
    }

    /// The production authority snapshot binding the real gateway's dispatch
    /// controller and admission validator both read.
    fn identity_authority_binding(
        authority_id: &eliot_process::DispatchAuthorityId,
    ) -> AuthoritySnapshotBinding {
        let epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new("kernel-901-identity-lineage").expect("lineage"),
                epoch: 1,
            },
            predecessor: None,
        };
        let state_fence =
            StateFenceSnapshot::capture(&serde_json::json!({"authority": "kernel-901"}), 1)
                .expect("state fence");
        AuthoritySnapshotBinding::new(
            authority_id.clone(),
            OperationIdentity::new("kernel-901-identity-authority-record").expect("record id"),
            epoch,
            state_fence,
            1,
            None,
        )
        .expect("authority binding")
    }

    struct IdentitySnapshotCodec;

    impl DispatchSnapshotCodec for IdentitySnapshotCodec {
        fn seal(
            &self,
            snapshot: &KernelAuthorityReplaySnapshot,
            _binding: &AuthoritySnapshotBinding,
        ) -> KernelResult<SealedAuthoritySnapshot> {
            let ciphertext = serde_json::to_vec(snapshot)
                .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
            let key = SecretReference::new("test-provider", "kernel-901-identity-authority")
                .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
            SealedAuthoritySnapshot::new(key, ciphertext)
        }

        fn open(
            &self,
            payload: &RecoveryPayload,
            _binding: &AuthoritySnapshotBinding,
        ) -> KernelResult<KernelAuthorityReplaySnapshot> {
            let RecoveryPayload::Encrypted { ciphertext, .. } = payload else {
                return Err(KernelError::RecoveryUnavailable(
                    "identity fixture payload is not encrypted".to_owned(),
                ));
            };
            serde_json::from_slice(ciphertext)
                .map_err(|error| KernelError::RecoveryUnavailable(error.to_string()))
        }
    }

    /// The bounded window, in milliseconds, that every admission this file builds
    /// is admitted under. It is this fixture's OWN budget, carried forward
    /// unchanged; no production constant supplies it.
    const IDENTITY_ADMISSION_WINDOW_MS: u64 = 120_000;

    /// The bounded window, in milliseconds, that the origin-challenge grant in
    /// `a_grant_minted_for_one_operation_cannot_act_on_a_reused_pid_recorded_under_another`
    /// is minted under. It is the tighter of this file's two budgets, and the only
    /// one production re-checks against its own live clock; see
    /// `authorize_effect_with_grant`.
    const IDENTITY_ORIGIN_CHALLENGE_WINDOW_MS: u64 = 60_000;

    /// The dispatch validation port the production `WindowsProcessExecutor` calls
    /// before it resumes a suspended child. It owns the dispatch permit authority
    /// that issued the permit for the launch this suite performs; it decides
    /// nothing about registration, replay, identity or evidence.
    struct IdentityValidationAuthority {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
        fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        /// The fixture's ONE clock reading, PASSED IN rather than read here so that
        /// it is provably the same value the validation context above is frozen at,
        /// the same value `issue` stamps each permit with, and the same value
        /// `IdentityFixture::now_ms` derives the admission deadline from. See
        /// `IdentityFixture::now_ms` for the two production comparisons that force
        /// one reading, and for why its scope is the fixture rather than the test
        /// binary process.
        issued_at_ms: u64,
    }

    impl IdentityValidationAuthority {
        fn new(now_ms: u64) -> Self {
            let issued_at_ms = now_ms;
            let generation = Generation::new(1).expect("generation");
            let fence = FencingToken::new(test_epoch(1), generation, "kernel-901-identity-fence")
                .expect("test fence");
            let revision_heads = BTreeMap::from([("kernel-901".to_owned(), "a".repeat(64))]);
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                    known_time_ms: Some(i64::try_from(issued_at_ms).expect("clock range")),
                    transaction_sequence: None,
                    monotonic_ns: None,
                },
                fence.clone(),
                test_epoch(1),
                revision_heads.clone(),
                1,
            )
            .expect("test validation context");
            Self {
                authority: Mutex::new(DispatchPermitAuthority::activate(
                    eliot_process::DispatchAuthorityId::new("kernel-901-identity-permit")
                        .expect("permit authority"),
                    eliot_process::KernelDispatchKey::from_secret_bytes([0x41; 32])
                        .expect("identity dispatch key"),
                )),
                context,
                fence,
                revision_heads,
                issued_at_ms,
            }
        }

        /// Issues one permit stamped from the SAME clock reading the validation
        /// context carries, so `validate_and_consume` compares the permit against
        /// the instant it was stamped instead of against a later reading of the
        /// same clock.
        fn issue(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessRequest {
            let issuance = PermitIssuance::new_with_validation_revision(
                admission.action_lease_ref().clone(),
                self.fence.clone(),
                self.revision_heads.clone(),
                self.issued_at_ms,
                admission.deadline_unix_ms(),
                format!("kernel-901:{}", admission.intent().operation_id().as_str()),
                1,
            )
            .expect("permit issuance");
            let permit = self
                .authority
                .lock()
                .expect("identity permit authority lock")
                .issue(admission.intent(), issuance)
                .expect("launch dispatch permit");
            ProcessRequest::new(admission.intent().clone(), permit).expect("launch process request")
        }
    }

    impl DispatchValidationPort for IdentityValidationAuthority {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            self.authority
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable(
                        "identity permit authority lock poisoned".to_owned(),
                    )
                })?
                .validate_and_consume(request, observed, &self.context)
                .map_err(ProcessExecutionError::Contract)
        }
    }

    /// Real-executor cases run inside one process-owned outer Job. Retain its
    /// handle for the test process lifetime: dropping a kill-on-close Job while its
    /// root is still running would terminate the test harness itself. This confines
    /// only this test process and its children, never Cargo or the runner.
    fn identity_outer_binding(owner: &ProcessOwnerBinding) -> HostKernelCandidateBinding {
        use eliot_platform_windows::{
            JobObject, JobObjectIdentity, JobObjectLimits, OuterKillDomain,
        };
        static JOB: std::sync::OnceLock<Mutex<JobObject>> = std::sync::OnceLock::new();
        static BINDING: std::sync::OnceLock<eliot_kernel_service::HostJobBinding> =
            std::sync::OnceLock::new();
        let binding = BINDING
            .get_or_init(|| {
                let executable = std::env::current_exe().expect("test executable");
                let identity = eliot_platform_windows::file_identity_for_path(&executable)
                    .expect("root file identity");
                let job = JOB.get_or_init(|| {
                    let name = format!(
                        "{}kernel-901-identity-{}",
                        OuterKillDomain::Kernel.host_job_name_prefix(),
                        std::process::id()
                    );
                    Mutex::new(
                        JobObject::new_named_outer_kill_on_close_with_limits(
                            OuterKillDomain::Kernel,
                            JobObjectIdentity::new(name).expect("Job name"),
                            JobObjectLimits::default(),
                        )
                        .expect("test outer Job"),
                    )
                });
                let job = job.lock().expect("test outer Job lock");
                let process = job
                    .assign_process(std::process::id())
                    .expect("assign exact test root");
                eliot_kernel_service::HostJobBinding {
                    job: eliot_kernel_service::HostJobIdentity {
                        name: job.identity().name().to_owned(),
                    },
                    root: eliot_kernel_service::HostJobRoot {
                        process: eliot_kernel_service::HostProcessBinding {
                            process_id: process.process_id,
                            start_time_100ns: process.start_time_100ns,
                            image_path: process.image_path,
                        },
                        executable: eliot_kernel_service::HostFileIdentity {
                            volume_serial_number: identity.volume_serial_number,
                            file_index: identity.file_index,
                        },
                    },
                }
            })
            .clone();
        let candidate = HostKernelCandidateBinding {
            installation_id: PlatformHandle::new("installation-1").expect("installation"),
            host_epoch: eliot_contracts::AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: owner.authority_epoch().clone(),
            activation_id: PlatformHandle::new("activation-1").expect("activation"),
            artifact_hash: PlatformHandle::new("kernel-901-identity-artifact").expect("artifact"),
            config_hash: PlatformHandle::new("kernel-901-identity-config").expect("config"),
            job_object_id: PlatformHandle::new(binding.job.name.clone()).expect("Job identity"),
            pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE).expect("pipe identity"),
            host_process: binding.root.process.clone(),
            job_binding: binding,
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-kernel-901-identity-scope".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "installation-1".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "kernel-901-identity-host-lineage".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-1".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-901-identity-activation-lineage".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-901-identity-kernel-lineage".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "kernel-901-identity-watchdog-lineage".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .expect("sealed supervision incarnation"),
            restart_budget: eliot_kernel_service::RestartBudget::new(1, 1).expect("restart budget"),
            agent_bridge_admission: None,
            containment_action: None,
        };
        candidate.validate().expect("valid physical test binding");
        candidate
    }

    /// Owns the fixture's work root and removes it on drop.
    ///
    /// A builder that needs a work root returns this guard alongside its
    /// composition so the composition drops FIRST: Rust drops locals in reverse
    /// declaration order, so the guard must be bound before the value that must
    /// release the directory.
    struct IdentityTempRoot(std::path::PathBuf);

    impl Drop for IdentityTempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One real composition: a real durable ORS, the real production
    /// `ProcessExecutionGateway`, and the real production `WindowsProcessExecutor`.
    struct IdentityFixture {
        gateway: ProcessExecutionGateway,
        store: Arc<RedbRecoveryStore>,
        platform: Arc<WindowsPlatform>,
        validation: Arc<IdentityValidationAuthority>,
        owner: ProcessOwnerBinding,
        /// The ONE wall-clock reading every time-derived value THIS FIXTURE builds
        /// is derived from, taken inside `identity_fixture` and never re-read.
        ///
        /// Its scope is the FIXTURE, not the test-binary process, and TWO measured
        /// production comparisons are what force one reading at that scope. Both
        /// are the real production ones; neither is stubbed anywhere in this file:
        ///
        /// * `DispatchPermitAuthority::validate_and_consume` reads `now` from
        ///   `DispatchValidationContext::now_unix_ms`, which is the FROZEN
        ///   `valid_time_ms` of that context and nothing else
        ///   (`crates/kernel/eliot-process/src/lib.rs:1498-1510`), and refuses the
        ///   permit when `now < permit.issued_at_unix_ms` OR
        ///   `now >= permit.expires_at_unix_ms`
        ///   (`crates/kernel/eliot-process/src/dispatch_permit.rs:386-389`). A
        ///   permit stamped from a SECOND, later `unix_ms()` is therefore born
        ///   already stale however short the gap is, and the gap is not short:
        ///   building this fixture opens the ORS, retains a real path lease onto
        ///   `ping.exe` and SHA-256s its bytes, so the launch would be refused as
        ///   `ExpiredDispatchPermit` before any OS process existed and
        ///   `.expect("production Windows child launch")` would panic. Handing this
        ///   ONE reading to both the validation context and the permit stamp makes
        ///   `now == issued_at_unix_ms` and `now < expires_at_unix_ms` true by
        ///   arithmetic, not by timing luck. That comparison needs nothing wider
        ///   than one agreement: the stamp and the frozen clock only have to be the
        ///   SAME value, which a per-fixture reading already guarantees.
        /// * `run_process_start` compares the admission's `deadline_unix_ms`
        ///   against `ProcessStartPorts::now`, which is `crate::unix_ms()`
        ///   (`src/process_execution.rs:3938-3943`, and the `fn now` body at
        ///   `:4209-4211`) - a LIVE `SystemTime` read
        ///   (`src/lib.rs:1679-1686`) that no fixture can influence. So the
        ///   admission window has to be measured from a reading taken close to the
        ///   start that meets the gate, not from one taken by whichever identity
        ///   fixture this test binary happened to build first.
        ///
        /// The second comparison is exactly why the scope is PER FIXTURE. Freezing
        /// the reading once per test-binary process made every LATER fixture count
        /// its admission window down from a stranger's fixture: libtest schedules
        /// this crate's 297 test attributes across parallel threads, so nothing
        /// puts the identity fixtures first, and any fixture built more than
        /// `IDENTITY_ADMISSION_WINDOW_MS` after the process-wide reading met
        /// `ExpiredDispatchPermit` at that real-clock gate instead of reaching the
        /// boundary the case is about.
        ///
        /// One reading per fixture is also as coarse as the digest needs, and no
        /// coarser: `deadline_unix_ms` is a field of the serialized admission, so
        /// it is a field of `process_admission_digest`, and
        /// `RedbRecoveryStore::persist_process_start` refuses a row whose
        /// `admission_digest` differs from the recorded one as `"identity
        /// replacement rejected"` (`crates/kernel/eliot-ors/src/store.rs:5689-5696`).
        /// A per-admission `unix_ms()` would make two structurally identical
        /// admissions of ONE operation identity into different operations to the
        /// store, so a re-derived or replayed admission would be refused as a
        /// registration conflict instead of on the boundary under test.
        ///
        /// Nothing here is weakened or bypassed. Both comparisons above are
        /// production's own, the stamp is still the real clock, and both windows
        /// are the fixture's own bounded budgets. What changed is only the SCOPE of
        /// the reading: from the test-binary process to the fixture that uses it.
        now_ms: u64,
    }

    fn identity_root(tag: &str) -> std::path::PathBuf {
        // The directory discriminator is a LIVE reading, deliberately NOT
        // `IdentityFixture::now_ms`: work-root uniqueness must not depend on a
        // naming invariant tying two fixtures to one clock value. The `tag` already
        // separates this file's cases on its own (`w32`, `w32-sweep`, `w10`,
        // `w10-repeat`, `w28-receipt`, `w28-admission`, `w10-reuse-grant`), and the
        // process id plus this reading separate repeated runs of any one tag.
        std::env::temp_dir().join(format!(
            "eliot-kernel-901-identity-{tag}-{}-{}",
            std::process::id(),
            unix_ms()
        ))
    }

    fn live_child_executable() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("ping.exe")
    }

    fn identity_fixture(tag: &str) -> (IdentityTempRoot, IdentityFixture) {
        let root = identity_root(tag);
        std::fs::create_dir_all(&root).expect("identity fixture root");
        // The ONE wall-clock reading this fixture is built on, and the only clock
        // read below: it is taken BEFORE the ORS is opened, the containment
        // platform root is built and the dispatch controller is activated, so all
        // of that work spends INSIDE the admission window rather than before it.
        let now_ms = unix_ms();
        let store = Arc::new(
            RedbRecoveryStore::open(root.join("kernel-ors.redb")).expect("identity fixture ORS"),
        );
        let authority_id = eliot_process::DispatchAuthorityId::new("kernel-901-identity-authority")
            .expect("authority");
        let snapshot_binding = identity_authority_binding(&authority_id);
        let authority_store: Arc<dyn OperationalRecoveryStore> = Arc::clone(&store) as Arc<_>;
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(IdentitySnapshotCodec);
        let controller = Arc::new(Mutex::new(ProcessDispatchAuthorityController::activate(
            authority_id,
            eliot_process::KernelDispatchKey::from_secret_bytes([0x3b; 32]).expect("dispatch key"),
            authority_store,
            codec,
        )));
        let platform = Arc::new(
            WindowsPlatform::new(root.join("containment")).expect("identity fixture platform root"),
        );
        let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
        let validation = Arc::new(IdentityValidationAuthority::new(now_ms));
        let validation_port: Arc<dyn DispatchValidationPort> = validation.clone();
        let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
        let mut gateway = ProcessExecutionGateway::new(
            controller,
            Arc::clone(&store),
            snapshot_binding,
            path_admission,
        );
        gateway.executor =
            WindowsProcessExecutor::new_with_launch_admission(validation_port, launch_admission);
        (
            IdentityTempRoot(root),
            IdentityFixture {
                gateway,
                store,
                platform,
                validation,
                owner: test_owner("eliotd", "a"),
                now_ms,
            },
        )
    }

    impl IdentityFixture {
        /// One admitted start whose executable and working directory are the real
        /// child image and its own directory, read from the live filesystem rather
        /// than from fixture state.
        ///
        /// It is a method, not an associated function, because exactly one value
        /// varies with the receiver: the admitted deadline below. That is what
        /// `process_admission_digest` reads, so it is what keeps two structurally
        /// identical admissions of one operation identity ONE admission to the
        /// canonical replay identity. Everything else is a pure function of
        /// `operation` and the real child image.
        fn admission(&self, operation: &str) -> ProcessExecutionAdmissionRequest {
            let generation = Generation::new(1).expect("generation");
            let executable = live_child_executable();
            let working_directory = executable
                .parent()
                .expect("child image directory")
                .to_path_buf();
            let intent = ProcessIntent::new(
                OperationId::new(operation).expect("operation id"),
                ProcessTreeId::new(format!("kernel-901-identity-tree-{operation}"))
                    .expect("process tree"),
                JobId::new(format!("kernel-901-identity-job-{operation}")).expect("logical Job id"),
                ImageId::new(format!("kernel-901-identity-image-{operation}")).expect("image id"),
                SessionId::new(format!("kernel-901-identity-session-{operation}"))
                    .expect("session id"),
                generation,
                executable.to_string_lossy(),
                Self::executable_sha256(),
                vec!["-n".to_owned(), "45".to_owned(), "127.0.0.1".to_owned()],
                working_directory.to_string_lossy(),
                EnvironmentProjection::new(
                    BTreeMap::new(),
                    Vec::new(),
                    EnvironmentInheritance::None,
                )
                .expect("closed child environment"),
                ResourceLimits::new(60_000, Some(45_000), None, 64 * 1024, 64 * 1024, 4)
                    .expect("resource limits"),
            )
            .expect("identity intent");
            ProcessExecutionAdmissionRequest::new(
                ACTIVE_DAEMON_CALLER,
                intent,
                ActionLeaseRef::new(format!("kernel-901-identity-lease-{operation}"))
                    .expect("action lease"),
                FencingToken::new(test_epoch(1), generation, "kernel-901-identity-fence")
                    .expect("state fence"),
                // The admission's own deadline, derived from THIS FIXTURE's one
                // reading and never from a second read, so `process_admission_digest`
                // stays a pure function of the operation name and the real child
                // image. Production compares this value against its own live clock
                // at `src/process_execution.rs:3938-3943`, so the window must open
                // here rather than wherever this test binary first read a clock; see
                // `IdentityFixture::now_ms`.
                self.now_ms.saturating_add(IDENTITY_ADMISSION_WINDOW_MS),
            )
            .expect("identity admission")
        }

        fn executable_sha256() -> String {
            sha256_hex(&std::fs::read(live_child_executable()).expect("child image bytes"))
        }

        /// The real retained path proof the production admission validator and the
        /// production path admission both read.
        fn path_proof(&self, admission: &ProcessExecutionAdmissionRequest) -> ProcessPathProof {
            let executable = std::path::PathBuf::from(admission.intent().executable());
            let working_directory =
                std::path::PathBuf::from(admission.intent().working_directory());
            let lease = self
                .platform
                .retain_process_path_lease(
                    &executable,
                    &working_directory,
                    admission.intent().executable_sha256(),
                )
                .expect("retained identity path proof");
            ProcessPathProof {
                executable,
                working_directory,
                lease: Arc::new(lease),
            }
        }

        fn validation_context(&self) -> DispatchValidationContext {
            self.gateway
                .build_context(
                    ClockObservation {
                        // The SAME reading `IdentityValidationAuthority` froze its
                        // own validation context at, so the retained gateway context
                        // and the permit this launch is issued under are compared
                        // against one instant and not two.
                        valid_time_ms: Some(i64::try_from(self.now_ms).expect("clock range")),
                        known_time_ms: Some(i64::try_from(self.now_ms).expect("clock range")),
                        transaction_sequence: None,
                        monotonic_ns: None,
                    },
                    FencingToken::new(
                        test_epoch(1),
                        Generation::new(1).expect("generation"),
                        "kernel-901-identity-fence",
                    )
                    .expect("store fence"),
                    test_epoch(1),
                    BTreeMap::from([("kernel-901".to_owned(), "a".repeat(64))]),
                    1,
                )
                .expect("identity validation context")
        }

        /// Performs ONE real suspended Windows child launch through the production
        /// gateway and executor, then commits the start through the production
        /// `ProcessStartPorts::persist_completed` seam into the real ORS. The child
        /// stays alive, so the executor retains a real live handle for it.
        async fn launch_and_commit(
            &self,
            admission: &ProcessExecutionAdmissionRequest,
        ) -> ProcessStartReceipt {
            let operation_id = admission.intent().operation_id().clone();
            let context_guard = self
                .gateway
                .insert_context(operation_id.clone(), self.validation_context())
                .expect("retained identity validation context");
            let path_guard = self
                .gateway
                .insert_path(operation_id.clone(), self.path_proof(admission))
                .expect("retained identity path proof");
            let request = self.validation.issue(admission);
            let receipt = self
                .gateway
                .execute(
                    &self.owner,
                    request,
                    Some(&identity_outer_binding(&self.owner)),
                )
                .await
                .expect("production Windows child launch");
            drop(path_guard);
            drop(context_guard);
            let digest = process_admission_digest(admission).expect("admission digest");
            ProcessStartPorts::persist_completed(
                &self.gateway,
                &operation_id,
                &digest,
                &self.owner,
                receipt.clone(),
            )
            .expect("production completed-start commit");
            receipt
        }

        /// Reserves one operation durably through the production seam with no OS
        /// launch behind it, so a closure boundary meets real owner evidence and
        /// real process evidence that is absent.
        fn reserve_without_launch(&self, operation: &str) -> OperationId {
            let admission = self.admission(operation);
            let operation_id = admission.intent().operation_id().clone();
            let digest = process_admission_digest(&admission).expect("admission digest");
            let begun =
                ProcessStartPorts::begin(&self.gateway, &operation_id, &digest, &self.owner)
                    .expect("production start reservation");
            assert_eq!(
                begun,
                ProcessExecutionReplayBegin::Acquired,
                "a fresh operation identity owns its only reservation"
            );
            operation_id
        }

        fn durable_record(&self, operation: &str) -> Option<ProcessStartReplayRecord> {
            self.store
                .load_process_start(&OperationIdentity::new(operation).expect("operation identity"))
                .expect("durable replay read")
        }

        /// The live handle the production executor retains for this operation.
        async fn live_handle(
            &self,
            operation: &str,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            self.gateway
                .executor
                .inspect(OperationId::new(operation).expect("operation id"))
                .await
        }
    }

    /// Registers one descendant through the production registry's own `register`.
    fn register_descendant(gateway: &ProcessExecutionGateway, registration: RegisteredDescendant) {
        gateway
            .descendants
            .lock()
            .expect("descendant registry lock")
            .register(registration)
            .expect("descendant registration");
    }

    /// The production registry's own census, read back unchanged.
    fn registered_ids(gateway: &ProcessExecutionGateway) -> Vec<OperationId> {
        gateway
            .descendants
            .lock()
            .expect("descendant registry lock")
            .registered_operation_ids()
    }

    fn descendant_for(operation_id: &OperationId) -> RegisteredDescendant {
        RegisteredDescendant::new(
            operation_id.clone(),
            "eliotd".to_owned(),
            test_epoch(1),
            Generation::new(1).expect("generation"),
        )
        .expect("registered descendant")
    }

    /// Re-reads a PRODUCTION value's own serialized bytes, replaces exactly ONE
    /// leaf coordinate, and deserializes the result back into the production type.
    ///
    /// The receipt and admission types are minted by production and have no other
    /// constructor, so this is the only way a case can present the identity shapes
    /// `W10` and `W28` are about: production never emits a reused-PID receipt,
    /// because detecting reuse is exactly what the compared callers must do. Each
    /// case re-checks the result with production's own `validate`.
    fn with_one_coordinate<T>(value: &T, path: &[&str], replacement: serde_json::Value) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let pointer = format!("/{}", path.join("/"));
        let mut document = serde_json::to_value(value).expect("production bytes");
        let slot = document
            .pointer_mut(&pointer)
            .unwrap_or_else(|| panic!("coordinate {pointer} is absent from the production bytes"));
        *slot = replacement;
        serde_json::from_value(document).expect("production shape round trip")
    }

    /// The single leaf coordinate of a receipt's physical identity: the OS
    /// creation marker that separates a reused process id from the recorded one.
    const START_MARKER_PATH: [&str; 4] = ["identity", "suspended", "physical", "start_time_100ns"];

    /// Proves the production shape round trips losslessly, so every difference a
    /// case asserts below is a difference this test introduced and nothing else.
    fn assert_lossless_round_trip<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let document = serde_json::to_value(value).expect("production bytes");
        let restored: T = serde_json::from_value(document).expect("production shape round trip");
        assert_eq!(
            &restored, value,
            "the production shape must round trip losslessly before a case changes one coordinate"
        );
    }

    /// The single creation marker this suite varies, taken from a production
    /// receipt's own recorded bytes.
    fn reused_start_marker(exact: &ProcessStartReceipt) -> serde_json::Value {
        serde_json::json!(
            exact
                .identity()
                .physical()
                .start_time_100ns()
                .saturating_add(1_000_000)
        )
    }

    // ---------------------------------------------------------------------------
    // W32 — logging cannot kill, retry, reassign, release a lease or certify a reap
    // absent owner evidence.
    //
    // The recorded blocker for this item was that `DescendantRegistry` and
    // `DescendantClosureReceipt` live in the private `mod activation_lifecycle`
    // (`src/lib.rs:322`) and that no integration test can name the type. This
    // capsule is an inline `#[cfg(all(test, windows))] mod` inside the #901-owned
    // `supervision_lease_authority` module; `src/lib.rs` is deliberately NOT
    // touched, because this issue's exclusive mutable scope excludes it, so the
    // capsule carries no crate-root registration at all. As a crate-internal
    // `#[cfg(test)]` module it still sees straight through that wall:
    // `ProcessExecutionGateway::descendants` is itself
    // `pub(crate)` (`src/process_execution.rs:1761`), and the registry's own
    // `register` and `registered_operation_ids` are `pub(crate)`
    // (`src/activation_lifecycle.rs:97` and `:124`).
    // ---------------------------------------------------------------------------

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one case drives the registration, the reap and the owner reassignment it names are not, and splitting it would split the claim it makes"
    )]
    async fn logging_cannot_certify_a_reap_release_the_registration_or_reassign_its_owner() {
        let (root_guard, fixture) = identity_fixture("w32");
        let owner = fixture.owner.clone();
        let foreign_owner = test_owner("eliot-other", "b");
        let authorized = fixture.reserve_without_launch("kernel-901-w32-authorized");
        let reassigned = fixture.reserve_without_launch("kernel-901-w32-reassigned");
        register_descendant(&fixture.gateway, descendant_for(&authorized));
        register_descendant(&fixture.gateway, descendant_for(&reassigned));

        // Leg zero, on the production owner comparison itself. Its own contract is
        // that it emits a subordinate observation and never a terminal, so the
        // refusal it produces cannot stand in for the caller's single terminal.
        let owner_logs = capture(|| {
            authorize_process_owner_in_context(
                &owner,
                &foreign_owner,
                &ProcessExecutionGateway::operation_context_for(&owner, &authorized),
            )
            .expect_err("a foreign owner is refused by the comparison itself");
        });
        assert_eq!(
            event_outcome(&owner_logs, "kernel.process.owner_rejected"),
            "fenced"
        );
        assert_eq!(
            event_count(&owner_logs, "kernel.terminal_error"),
            0,
            // REGRESSION GUARD (absence). It CAN redden: `authorize_process_owner_in_context`
            // is one line above the refusal, so moving the terminal into it — or any
            // future caller emitting one — makes this 1. The paired positive control is
            // `event_count(&logs, "kernel.terminal_error") == 2` below, measured on a
            // capture that DOES contain two terminals from the same comparison.
            "the subordinate owner comparison owns no terminal: {owner_logs}"
        );

        let (outcomes, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = owner.clone();
            let foreign_owner = foreign_owner.clone();
            let authorized = authorized.clone();
            let reassigned = reassigned.clone();
            async move {
                // Leg one: the exact owner the durable record names. Owner evidence
                // is present, so the boundary is authorized and reaches the live
                // inspect. No OS process exists behind this reservation, so the
                // closure receipt can never be built.
                let admitted = gateway
                    .close_registered_descendant_in_context(
                        &owner,
                        authorized.clone(),
                        &ProcessExecutionGateway::operation_context_for(&owner, &authorized),
                    )
                    .await;
                // Leg two: a different owner on the same boundary. The registration
                // names one owner; a log line cannot move it to another.
                let refused = gateway
                    .close_registered_descendant_in_context(
                        &foreign_owner,
                        reassigned.clone(),
                        &ProcessExecutionGateway::operation_context_for(
                            &foreign_owner,
                            &reassigned,
                        ),
                    )
                    .await;
                (admitted, refused)
            }
        })
        .await;

        let (admitted, refused) = outcomes;
        assert!(
            admitted.is_err(),
            "no reap may be certified without a live process: {admitted:?}"
        );
        assert!(
            matches!(&refused, Err(ProcessExecutionError::Contract(_))),
            "a foreign owner is refused by the owner comparison itself: {refused:?}"
        );
        // Both closes really requested a closure, so the refusals below are the
        // production decision and not an unreachable arm.
        assert_eq!(
            event_count(&logs, "kernel.process.descendant_close_requested"),
            2,
            "both closes requested a closure: {logs}"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.owner_admitted"),
            "success"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.owner_rejected"),
            "fenced"
        );
        // The authorized close reached the live inspect and found nothing there, so
        // it is a failure with its own terminal and never a closure claim.
        assert_eq!(
            event_outcome(&logs, "kernel.process.inspect_failed"),
            "unknown"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.descendant_close_failed"),
            "unknown"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.descendant_close_rejected"),
            "fenced"
        );
        assert_eq!(event_count(&logs, "kernel.terminal_error"), 2);
        // The two observations that would certify a reap are the only producers of
        // the `closed` outcome, and neither ran.
        //
        // REGRESSION GUARD (absence), `outcome="closed"`. It CAN redden: both literals
        // are produced by `close_registered_descendant_in_context` itself at
        // `src/process_execution.rs:3407-3415` (the `Ok` arm's own conditional), so
        // returning a receipt built by a `DescendantClosureReceipt::close` that
        // validates — which needs a live `Running` view this fixture has no way to
        // present — makes this substring appear. The string is read from the rendered
        // record, so it is the production outcome literal and not a fixture constant.
        assert!(
            !logs.contains("outcome=\"closed\""),
            "logging may never certify a reap: {logs}"
        );
        // REGRESSION GUARD (absence), `descendant_close_observed`. It CAN redden: the
        // same `Ok` arm at `src/process_execution.rs:3406-3416` emits exactly this
        // event on every successful close, so any `Ok` from this boundary makes it 1.
        assert!(
            !event_present(&logs, "kernel.process.descendant_close_observed"),
            "an unproven closure is a failure observation, never an observed closure: {logs}"
        );
        // Logging cannot release a registration: production removes the entry only
        // inside `if receipt.all_closed()` after a proven receipt
        // (`src/process_execution.rs:3392`), and no receipt was built.
        assert_eq!(
            registered_ids(&fixture.gateway),
            vec![authorized, reassigned],
            "an unproven closure must retain both registrations"
        );
        drop(fixture);
        drop(root_guard);
    }

    #[tokio::test]
    async fn repeated_shutdown_sweeps_produce_identical_evidence_and_retain_every_registration() {
        let (root_guard, fixture) = identity_fixture("w32-sweep");
        let reserved = vec![
            fixture.reserve_without_launch("kernel-901-w32-sweep-a"),
            fixture.reserve_without_launch("kernel-901-w32-sweep-b"),
        ];
        for operation_id in &reserved {
            register_descendant(&fixture.gateway, descendant_for(operation_id));
        }

        let (outcomes, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            async move { gateway.close_all_registered_descendants().await }
        })
        .await;

        // The shutdown sweep really did iterate. An empty registry would make the
        // loop body unreachable, which is the shape the recorded blocker assumed.
        // Each still-open operation is now its own terminal and none is hidden.
        assert_eq!(
            outcomes.len(),
            reserved.len(),
            "the sweep reaches every registered operation: {outcomes:?}"
        );
        assert!(
            outcomes.iter().all(|(_, outcome)| outcome.is_err()),
            "no unproven closure may be reported as closed: {outcomes:?}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.descendant_close_requested"),
            reserved.len(),
            "each registered operation requested its closure: {logs}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.descendant_close_failed"),
            reserved.len()
        );
        assert_eq!(event_count(&logs, "kernel.terminal_error"), reserved.len());
        // REGRESSION GUARD (absence), `outcome="closed"` over the whole sweep. It CAN
        // redden: the sweep's only producer of that literal is the per-operation `Ok`
        // arm at `src/process_execution.rs:3407-3415`, reached once per registered
        // operation, so one certified closure anywhere in this capture makes it appear.
        assert!(
            !logs.contains("outcome=\"closed\""),
            "the sweep may never certify a reap: {logs}"
        );
        assert_eq!(
            registered_ids(&fixture.gateway),
            reserved,
            "an unproven sweep outcome must retain every registration"
        );

        // A second identical sweep must not manufacture progress: same evidence,
        // same state.
        let (again, second_logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            async move { gateway.close_all_registered_descendants().await }
        })
        .await;
        assert_eq!(
            event_count(&second_logs, "kernel.process.descendant_close_requested"),
            event_count(&logs, "kernel.process.descendant_close_requested"),
            "repeating the sweep changes no observation count: {second_logs}"
        );
        assert_eq!(
            event_count(&second_logs, "kernel.terminal_error"),
            event_count(&logs, "kernel.terminal_error"),
            "repeating the sweep changes no terminal count: {second_logs}"
        );
        assert!(
            again.iter().all(|(_, outcome)| outcome.is_err()),
            "a repeated sweep may not certify anything either: {again:?}"
        );
        // REGRESSION GUARD (absence), `outcome="closed"` on the REPEATED sweep. It CAN
        // redden: the repeated sweep runs the identical production loop, so any change
        // in the first sweep's evidence that let a close succeed is replayed here and
        // this substring appears in `second_logs`.
        assert!(!second_logs.contains("outcome=\"closed\""));
        assert_eq!(
            registered_ids(&fixture.gateway).len(),
            2,
            "the repeated sweep released nothing"
        );
        drop(fixture);
        drop(root_guard);
    }

    // ---------------------------------------------------------------------------
    // W10 — PID alone cannot identify a process after reuse.
    //
    // Measured, not assumed. The comparison production performs is
    // `inspect_exact_running_receipt_in_context` at
    // `src/process_execution.rs:3125-3129`, which requires
    // `record.receipt.as_ref() == Some(receipt)`. The `ProcessStartReceipt`
    // `PartialEq` that decision uses reaches `ProcessIdentity::suspended.physical`,
    // whose `PhysicalProcessBinding` carries `process_id`, `start_time_100ns`,
    // `image_path` and `executor_job_name`
    // (`crates/kernel/eliot-process/src/physical_identity.rs:20-25`). There is no
    // `pid_reused` or `foreign` outcome literal anywhere in the five owned
    // modules: production distinguishes reuse by COMPARING the recorded identity,
    // and the cases below prove that comparison directly.
    //
    // What each case in this section pins, named against the production line:
    //
    // * `pid_alone_cannot_identify_a_process_after_reuse` — the durable arm,
    //   `src/process_execution.rs:3125-3129`, discriminated by the
    //   `inspect_requested` count of one: with the comparison deleted the
    //   substituted receipt reaches `inspect_inner` at `:3130` and the count is
    //   two.
    // * `a_substituted_image_path_job_or_digest_is_refused_exactly_like_a_reused_marker`
    //   — that the SAME whole-value comparison reaches `executable_sha256`,
    //   `physical.image_path` and `physical.executor_job_name` as well as
    //   `physical.start_time_100ns`. Only a positive verdict needs all of them
    //   read, so the `inspect_requested` count of one is the proof each one was
    //   compared.
    //
    // Residual, stated here rather than asserted by a manufactured vector: the
    // live-view comparison at `src/process_execution.rs:3140-3145` is NOT pinned by
    // any case here, and an earlier revision of this comment claimed it was. Its
    // `view.binding()` and `view.identity()` sub-conditions need a LIVE view whose
    // binding or identity differs from the presented receipt while the durable
    // record EQUALS it, and the real store forbids exactly that:
    // `RedbRecoveryStore::persist_process_start` admits a `Completed -> Completed`
    // rewrite only when `*existing == *record`
    // (`crates/kernel/eliot-ors/src/store.rs:5704-5707`), while the only other
    // writable transition, `Reserved -> Completed` at `:5697-5703`, belongs to an
    // operation that never launched and therefore has no executor entry — so its
    // refusal is the `NotFound` arm at `:3135-3137`, not `:3140`. Its
    // `view.lifecycle()` sub-condition needs a child that has stopped, which this
    // fixture's only production way to produce is a real cancel whose resulting tree
    // evidence this file cannot measure without running the suite. Forcing past any
    // of those guards would substitute the production decision this file must not
    // re-implement, so the line is named as unpinned instead.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn pid_alone_cannot_identify_a_process_after_reuse() {
        let (root_guard, fixture) = identity_fixture("w10");
        let operation = "kernel-901-w10";
        let admission = fixture.admission(operation);
        let exact = fixture.launch_and_commit(&admission).await;
        assert_lossless_round_trip(&exact);
        // The live process really is the one the record names.
        let view = fixture
            .live_handle(operation)
            .await
            .expect("the production executor retains the launched handle");
        assert_eq!(view.identity(), Some(exact.identity()));

        // One coordinate differs: the OS creation marker. Every other coordinate,
        // including the process id, is production's own byte.
        let reuse: ProcessStartReceipt =
            with_one_coordinate(&exact, &START_MARKER_PATH, reused_start_marker(&exact));
        assert_eq!(
            reuse.identity().pid(),
            exact.identity().pid(),
            "the reused receipt names the SAME OS process id, so a pid match alone cannot separate them"
        );
        assert_ne!(reuse, exact);
        assert_ne!(
            reuse.identity().physical().start_time_100ns(),
            exact.identity().physical().start_time_100ns(),
            "the creation marker is the one coordinate this test changed"
        );
        assert!(
            reuse.validate().is_ok(),
            "both receipts are well formed; only their identity differs"
        );

        // Both reads run inside ONE capture so the positive control is measured in
        // the same bytes as the refusal: the exact receipt is accepted against the
        // live process, and the reused one is refused BEFORE any live-process
        // lookup, which is what makes the refusal an identity decision rather than
        // an observation that happened to fail.
        let (results, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = fixture.owner.clone();
            let exact = exact.clone();
            let reuse = reuse.clone();
            async move {
                let operation_id = exact.operation_id().clone();
                let context = ProcessExecutionGateway::operation_context_for(&owner, &operation_id);
                let admitted = gateway
                    .inspect_exact_running_receipt_in_context(&exact, &context)
                    .await;
                let refused = gateway
                    .inspect_exact_running_receipt_in_context(&reuse, &context)
                    .await;
                (admitted, refused)
            }
        })
        .await;
        let (admitted, refused) = results;
        assert!(
            admitted.is_ok(),
            "the exact recorded identity is still the running process: {admitted:?}"
        );
        assert!(
            matches!(&refused, Err(ProcessExecutionError::UnknownOutcome)),
            "a pid match with a different creation marker is not this process: {refused:?}"
        );
        assert!(
            event_present(&logs, "kernel.process.inspect_requested"),
            "the exact read did reach the boundary, so the capture is not empty: {logs}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.inspect_requested"),
            1,
            "the refused receipt never reaches a live-process lookup: {logs}"
        );

        // Completeness in the other direction: the durable record was never
        // rewritten to match the presented receipt.
        let durable = fixture
            .durable_record(operation)
            .expect("committed start record");
        assert_eq!(durable.state, ProcessStartReplayState::Completed);
        assert_eq!(durable.receipt.as_ref(), Some(&exact));
        assert_ne!(durable.receipt.as_ref(), Some(&reuse));
        drop(fixture);
        drop(root_guard);
    }

    // The repeated-read case carries its own positive control on the same rendered
    // line; splitting the two apart would hide that the reader is the same one.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_reused_pid_is_refused_identically_and_never_projects_a_physical_identity() {
        let (root_guard, fixture) = identity_fixture("w10-repeat");
        let operation = "kernel-901-w10-repeat";
        let admission = fixture.admission(operation);
        let exact = fixture.launch_and_commit(&admission).await;
        let reuse: ProcessStartReceipt =
            with_one_coordinate(&exact, &START_MARKER_PATH, reused_start_marker(&exact));
        assert!(reuse.validate().is_ok());

        let (results, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = fixture.owner.clone();
            let exact = exact.clone();
            let reuse = reuse.clone();
            async move {
                let operation_id = exact.operation_id().clone();
                let context = ProcessExecutionGateway::operation_context_for(&owner, &operation_id);
                let admitted = gateway
                    .inspect_exact_running_receipt_in_context(&exact, &context)
                    .await;
                let first = gateway
                    .inspect_exact_running_receipt_in_context(&reuse, &context)
                    .await;
                let second = gateway
                    .inspect_exact_running_receipt_in_context(&reuse, &context)
                    .await;
                (admitted, first, second)
            }
        })
        .await;

        let (admitted, first, second) = results;
        assert!(
            admitted.is_ok(),
            "the exact identity is the live process: {admitted:?}"
        );
        for (label, outcome) in [("first", &first), ("second", &second)] {
            assert!(
                matches!(outcome, Err(ProcessExecutionError::UnknownOutcome)),
                "the {label} reused read is refused the same way: {outcome:?}"
            );
        }
        // The capture is non-empty because the exact read observed the boundary.
        // Exactly one read of three reached a live-process lookup and exactly one
        // was authorized an owner, so both refusals are identity decisions rather
        // than failed observations, and repeating the read manufactures no new one.
        assert!(
            event_present(&logs, "kernel.process.inspect_requested"),
            "the exact read reached the boundary: {logs}"
        );
        assert_eq!(event_count(&logs, "kernel.process.inspect_requested"), 1);
        assert_eq!(event_count(&logs, "kernel.process.inspect_reported"), 1);
        assert_eq!(
            event_count(&logs, "kernel.process.owner_admitted"),
            1,
            "only the exact read was authorized an owner, so a repeat changes nothing: {logs}"
        );
        // This boundary records only `process_tree` and `state_fence`; it never
        // projects `process_id`, `process_start_100ns` or `image_sha256`, so a
        // reused pid cannot become a recorded identity even as a guess. Those slots
        // are read on the line production actually rendered, and each must still be
        // its declared default.
        //
        // REGRESSION GUARD (absence), three slots. Each CAN redden, and each on its
        // own production recorder: the declared defaults are the literals at
        // `src/kernel_diagnostics.rs:671-673`, and the only writer of those three
        // slots in this crate is `record_process_start_receipt_identity`
        // (`src/process_execution.rs:192-198`). Calling it anywhere on this path — or
        // reading a receipt's identity in `record_process_context_field` as
        // `:3106-3119` already does for the two slots it does record — fills the slot
        // with a real value and this becomes that value instead of `unavailable`. The
        // positive control is applied immediately below, on this same line, to the
        // two slots this boundary DOES record: they return the receipt's own bytes,
        // so the reader is proven to distinguish a recorded value from a default.
        let line = event_line(&logs, "kernel.process.inspect_requested");
        for slot in ["process_id", "process_start_100ns", "image_sha256"] {
            assert_eq!(
                span_field(line, slot),
                Some("unavailable"),
                "a boundary that records no receipt may not project {slot}: {line}"
            );
        }
        // POSITIVE CONTROL on the same reader and the same rendered line: the two
        // slots `record_process_context_field` writes at
        // `src/process_execution.rs:3106-3119` carry the receipt's OWN values, so the
        // three defaults above are production withholding them rather than this test
        // reading an empty line. Each CAN redden in the other direction: dropping
        // either recording makes the slot `unavailable` and this fails.
        assert_eq!(
            span_field(line, "process_tree"),
            Some(exact.binding().process_tree_id().as_str()),
            "the reader reads a recorded value off this very line: {line}"
        );
        assert_eq!(
            span_field(line, "state_fence"),
            Some(
                exact
                    .binding()
                    .state_fence()
                    .canonical_epoch_digest()
                    .expect("the recorded receipt carries its own fence digest")
                    .as_str()
            ),
            "the reader reads the recorded fence digest off this very line: {line}"
        );
        drop(fixture);
        drop(root_guard);
    }

    #[tokio::test]
    async fn a_malformed_start_receipt_records_no_identity_and_guesses_none() {
        let (root_guard, fixture) = identity_fixture("w28-receipt");
        let operation = "kernel-901-w28-receipt";
        let admission = fixture.admission(operation);
        let exact = fixture.launch_and_commit(&admission).await;
        // PRODUCTION's own validator decides what is malformed: this receipt is
        // refused by `ProcessStartReceipt::validate`, not by a rule written here.
        let malformed: ProcessStartReceipt =
            with_one_coordinate(&exact, &START_MARKER_PATH, serde_json::json!(0));
        assert!(
            malformed.validate().is_err(),
            "an absent creation marker is malformed by production's own definition"
        );
        assert_eq!(malformed.identity().pid(), exact.identity().pid());

        let (results, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = fixture.owner.clone();
            let exact = exact.clone();
            let malformed = malformed.clone();
            async move {
                let operation_id = exact.operation_id().clone();
                let refused = gateway
                    .inspect_exact_running_receipt_in_context(
                        &malformed,
                        &ProcessExecutionGateway::operation_context_for(&owner, &operation_id),
                    )
                    .await;
                let admitted = gateway
                    .inspect_exact_running_receipt_in_context(
                        &exact,
                        &ProcessExecutionGateway::operation_context_for(&owner, &operation_id),
                    )
                    .await;
                (refused, admitted)
            }
        })
        .await;

        let (refused, admitted) = results;
        assert!(
            matches!(&refused, Err(ProcessExecutionError::Contract(_))),
            "the malformed receipt is refused by its own validation: {refused:?}"
        );
        assert!(admitted.is_ok(), "{admitted:?}");
        // The boundary validates before it records, so exactly ONE of the two reads
        // on the SAME operation and the SAME durable record reached the executor:
        // the malformed identity produced no lookup, no tree and no fence.
        assert_eq!(event_count(&logs, "kernel.process.inspect_requested"), 1);
        assert_eq!(event_count(&logs, "kernel.process.inspect_reported"), 1);
        let line = event_line(&logs, "kernel.process.inspect_requested");
        assert_eq!(
            span_field(line, "process_tree"),
            Some(exact.binding().process_tree_id().as_str()),
            "the exact receipt's own tree is the recorded value: {line}"
        );
        // PRECONDITION, stated before the comparison and not by it: a bound slot
        // that is absent from the receipt is absent from the projection too, so an
        // optional expected value could match an absent field and prove nothing.
        let expected_fence = exact
            .binding()
            .state_fence()
            .canonical_epoch_digest()
            .expect("the exact receipt carries its own fence digest");
        assert_eq!(
            span_field(line, "state_fence"),
            Some(expected_fence.as_str()),
            "the exact receipt's own fence digest is the recorded value, never a default or a guess: {line}"
        );
        drop(fixture);
        drop(root_guard);
    }

    // One causal narrative on purpose: a real committed launch, then one coordinate of
    // its receipt zeroed and refused by production's own `validate`, with the exact
    // receipt and the malformed one read inside ONE capture so the four
    // `unavailable` slots are observed to be withheld by production rather than
    // absent from the capture. Splitting it would separate those premises from the
    // assertions that depend on them. Same allowance the crate already uses at
    // `src/daemon_live_receipt.rs:129`.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_malformed_admission_leaves_its_request_identity_unavailable_and_guesses_none() {
        let (root_guard, fixture) = identity_fixture("w28-admission");
        let owner = fixture.owner.clone();
        let good_operation = "kernel-901-w28-good";
        let good = fixture.admission(good_operation);
        let admitted_tree = good.intent().process_tree_id().as_str().to_owned();
        let admitted_lease = good.action_lease_ref().as_str().to_owned();
        let admitted_operation = good.intent().operation_id().as_str().to_owned();
        // PRODUCTION's own validator decides this admission is malformed: its
        // absolute deadline is absent.
        let bad: ProcessExecutionAdmissionRequest =
            with_one_coordinate(&good, &["deadline_unix_ms"], serde_json::json!(0));
        assert!(
            bad.validate().is_err(),
            "an absent deadline is malformed by production's own definition"
        );
        assert_eq!(bad.intent().process_tree_id().as_str(), admitted_tree);

        let (bad_result, bad_logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = owner.clone();
            let platform = Arc::clone(&fixture.platform);
            let bad = bad.clone();
            async move {
                let context = ProcessExecutionGateway::start_context_for(&owner, &bad);
                let proof = retained_identity_path_proof(&platform, &bad);
                gateway
                    .start_in_context(&owner, bad, proof, identity_outer_binding(&owner), &context)
                    .await
            }
        })
        .await;
        assert!(
            bad_result.is_err(),
            "a malformed admission is refused: {bad_result:?}"
        );
        // The request boundary renders its span whatever the admission's shape, so
        // the slot values are readable facts rather than absences.
        //
        // REGRESSION GUARD (absence), four slots. Each CAN redden on its own
        // production guard: all four are written by exactly one function,
        // `record_process_start_request_context`, and the single line that withholds
        // them is its own `if admission.validate().is_err() { return; }`
        // (`src/process_execution.rs:161-163`). Deleting that guard records the
        // malformed admission's operation/tree/lease and its fence digest, and each
        // slot becomes that value. The positive control is the SAME reader, on the
        // SAME fixture and owner, applied to a valid admission at the end of this
        // test, where all four return real bytes.
        let bad_line = event_line(&bad_logs, "kernel.process.start_requested");
        for slot in ["operation", "process_tree", "lease", "state_fence"] {
            assert_eq!(
                span_field(bad_line, slot),
                Some("unavailable"),
                "an unvalidated {slot} stays unavailable, never guessed: {bad_line}"
            );
        }
        // REGRESSION GUARD (absence), the `operation` slot of the SAME malformed
        // read, stated in its strongest available form: the malformed admission
        // carries this operation identity verbatim, so the slot is `unavailable` here
        // ONLY because production withheld it, never because the value was absent from
        // the input. It CAN redden: recording it is the one statement
        // `src/process_execution.rs:167-170` makes, and removing the `:161-163` guard
        // reaches it. Positive control: the same `span_field` reader returns exactly
        // `admitted_operation` for the valid admission below.
        assert_ne!(
            span_field(bad_line, "operation"),
            Some(admitted_operation.as_str())
        );
        // The owner's own authenticated generation and epoch were recorded BEFORE
        // the admission was validated, so they are the real ones and not defaults.
        // This is a POSITIVE CONTROL, not a tautology: the expected string is read
        // back through production's own projection
        // `owner.generation().get().to_string()`
        // (`src/process_execution.rs:151`), not restated as a literal, and it is the
        // admission's INVALIDITY alone that makes the four slots above unavailable
        // while this one stays recorded. It CAN redden: recording the generation
        // before the `admission.validate()` guard is the first statement of
        // `record_process_start_request_context` at `:150-153`, so moving that guard
        // above it turns this into `unavailable` too.
        let owner_generation = owner.generation().get().to_string();
        assert_eq!(
            span_field(bad_line, "generation"),
            Some(owner_generation.as_str())
        );

        let (good_result, good_logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = owner.clone();
            let platform = Arc::clone(&fixture.platform);
            let good = good.clone();
            async move {
                let context = ProcessExecutionGateway::start_context_for(&owner, &good);
                let proof = retained_identity_path_proof(&platform, &good);
                gateway
                    .start_in_context(
                        &owner,
                        good,
                        proof,
                        identity_outer_binding(&owner),
                        &context,
                    )
                    .await
            }
        })
        .await;
        // The valid admission meets ONE measured refusal, and it is not the deadline.
        // `start_in_context` records this admission's own `process_tree` and `lease`
        // above (`src/process_execution.rs:2889-2900`), so its own
        // `admission.validate()` (`:3933`) and `validate_admission` (`:3935`) both
        // passed before `run_process_start` compared its deadline against
        // `ProcessStartPorts::now` - `crate::unix_ms()`, the live SystemTime read at
        // `:4209-4211` (`:3938-3943`) - which this fixture's own clock reading is
        // still inside, because that reading is taken inside `identity_fixture` and
        // this call follows it immediately. The start then takes its reservation
        // (`:3944`) and reaches the first-start authority gate (`:3985-3996`), which
        // refuses before any OS process exists: this fixture's ORS records neither
        // a generation lifecycle row nor an execution manifest for
        // `{module_id: "eliotd", generation: 1}`, so
        // `RedbRecoveryStore::load_observed_generation_lifecycle` returns the store's
        // own `EffectOperationLeaseGenerationUnrecorded`
        // (`crates/kernel/eliot-ors/src/store.rs:28519-28537`) and
        // `current_effect_capability_view` maps it to
        // `ProcessExecutionError::Unavailable` (`src/process_execution.rs:3706-3712`).
        // All three refusal arms of that gate - the unrecorded readback, a
        // non-admitting recorded disposition and an absent manifest
        // (`:3719-3724`, `:3732-3736`) - are that same variant, so this first
        // assertion deliberately does NOT restate a store message that is not this
        // test's to assert. The two observations below then pin WHICH refusal arm
        // class this input actually met.
        assert!(
            matches!(&good_result, Err(ProcessExecutionError::Unavailable(_))),
            "a valid admission whose generation records no execution manifest is refused as unavailable: {good_result:?}"
        );
        // The variant above is shared by several production arms, so the arm is
        // pinned by the ONE observation this crate emits only from that gate's
        // refusal: `require_new_effect_operation_authority`'s own `Err` arm at
        // `src/process_execution.rs:2828-2835`, reached from
        // `run_process_start`'s acquired-reservation arm at `:3985-3996`. Deleting
        // that observation, or admitting the start past it, makes these counts 0 and
        // 2 respectively, so this leg cannot pass on an unrelated `Unavailable`.
        assert_eq!(
            event_count(&good_logs, "kernel.process.effect_operation_lease_refused"),
            1,
            "the valid admission met the first-start authority gate and was refused there: {good_logs}"
        );
        assert_eq!(
            event_outcome(&good_logs, "kernel.process.effect_operation_lease_refused"),
            "refused"
        );
        assert_eq!(
            event_count(&good_logs, "kernel.process.start_registration"),
            1,
            "the reservation was taken before the gate and never became a launch: {good_logs}"
        );
        assert_eq!(
            event_outcome(&good_logs, "kernel.process.start_registration"),
            "acquired",
            "the acquired arm is the only one that reaches the gate at all: {good_logs}"
        );
        // REGRESSION GUARD (absence), the gate's two ADMITTING arms. Both CAN redden:
        // they are the `Ok` arms of the very same match at
        // `src/process_execution.rs:2814-2827`, and this store records neither a
        // current Module Catalog/Policy view nor an execution manifest for
        // `{module_id: "eliotd", generation: 1}`, so any manifest appearing for this
        // fixture — or any readback at `:3706` or `:3725` succeeding — emits one of
        // them and makes this 1. The positive control is the refusal count of one
        // measured on the SAME capture two assertions above: this gate produced an
        // observation, and it was the refusing one.
        for never_admitted in [
            "kernel.process.read_rebuild_manifest_admitted",
            "kernel.process.effect_operation_lease_issued",
        ] {
            assert!(
                !event_present(&good_logs, never_admitted),
                "{never_admitted} would mean the gate admitted a start this generation has no manifest for: {good_logs}"
            );
        }
        // REGRESSION GUARD (absence), any OS process behind this refusal. It CAN
        // redden: `WindowsProcessExecutor::execute` is the only caller that resumes a
        // suspended child, and it is reached only from `run_process_start`'s executor
        // handoff below the gate, so emitting either of these means the gate was
        // passed rather than observed.
        for never_launched in [
            "kernel.process.start_identity_observed",
            "kernel.process.start_committed",
        ] {
            assert!(
                !event_present(&good_logs, never_launched),
                "{never_launched} would mean an OS process was launched behind a refused gate: {good_logs}"
            );
        }
        // Completeness in the other direction, on the SAME fixture and the SAME
        // owner: every slot the malformed admission could not fill is filled with
        // the valid admission's OWN values. The difference between unavailable and
        // recorded is therefore the admission's own validation, nothing else.
        let good_line = event_line(&good_logs, "kernel.process.start_requested");
        assert_eq!(
            span_field(good_line, "operation"),
            Some(admitted_operation.as_str()),
            "the valid admission's own operation is the recorded value: {good_line}"
        );
        assert_eq!(
            span_field(good_line, "process_tree"),
            Some(admitted_tree.as_str()),
            "the valid admission's own tree is the recorded value: {good_line}"
        );
        assert_eq!(
            span_field(good_line, "lease"),
            Some(admitted_lease.as_str()),
            "the valid admission's own lease is the recorded value: {good_line}"
        );
        drop(fixture);
        drop(root_guard);
    }

    /// The real retained path proof one admission needs, read from the real
    /// platform owner.
    fn retained_identity_path_proof(
        platform: &WindowsPlatform,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> ProcessPathProof {
        let executable = std::path::PathBuf::from(admission.intent().executable());
        let working_directory = std::path::PathBuf::from(admission.intent().working_directory());
        let lease = platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .expect("retained identity path proof");
        ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        }
    }

    // ---------------------------------------------------------------------------
    // W10, cross-operation leg — a grant minted for one recorded identity cannot
    // act on a reused process id recorded under a DIFFERENT operation.
    //
    // The comparison that answers "can the workspace separate a reused pid across
    // operations?" is `ProcessExecutionGateway::authorize_effect_with_grant` at
    // `src/process_execution.rs:3625-3636`: it takes the identity the durable
    // record still holds for the operation the effect is about to run on
    // (`:3616-3620` reads that record BY OPERATION ID, never by process id) and
    // hands it to `OriginControlGrant::binds_target_for_operation`, whose target
    // bind is `crates/kernel/eliot-process/src/origin_challenge.rs:630-642`.
    //
    // That bind is one whole-value equality on `PhysicalProcessBinding`
    // (`crates/kernel/eliot-process/src/physical_identity.rs:18-25`), so it covers
    // the OS process id AND the creation marker AND the executor-observed image
    // path AND the executor Job name, and a separate arm covers the generation
    // (`:638`). Its own doc comment states the rule this case measures: "a grant
    // minted for one child, one image, one start time, or one generation cannot
    // authorize a different or substituted target" (`:623-625`).
    //
    // What this case does NOT assert: that the durable store rejects a second
    // operation naming an already-recorded process id. It cannot, and it does not
    // try to — see the negative finding reported alongside this case.
    // ---------------------------------------------------------------------------

    /// The single leaf coordinate of a receipt's operation binding.
    const OPERATION_ID_PATH: [&str; 2] = ["binding", "operation_id"];

    // One collision test carries every coordinate of the pair, so it reads long by
    // construction; splitting it would hide the coordinates it holds together.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_grant_minted_for_one_operation_cannot_act_on_a_reused_pid_recorded_under_another() {
        let (root_guard, fixture) = identity_fixture("w10-reuse-grant");
        let owner = fixture.owner.clone();
        let operation_a = "kernel-901-w10-reuse-grant-a";
        let operation_b = "kernel-901-w10-reuse-grant-b";
        let admission_a = fixture.admission(operation_a);
        // One real suspended Windows child launch, committed by production into the
        // real ORS through the production `ProcessStartPorts::persist_completed`.
        let receipt_a = fixture.launch_and_commit(&admission_a).await;
        assert_lossless_round_trip(&receipt_a);
        assert!(
            receipt_a.validate().is_ok(),
            "the first operation holds a production-valid receipt"
        );

        // The second operation's durable receipt is PRODUCTION's own committed
        // bytes re-read with exactly two leaf coordinates replaced, one call at a
        // time: the operation the binding names, and the OS creation marker. The
        // OS process id, the executor-observed image path, the executor Job name,
        // the executable digest and the generation are production's own bytes,
        // byte-identical to the first operation's. Windows will not actually hand
        // out the same pid twice inside one test process, so the reuse shape is
        // introduced here rather than waited for; production's own validators
        // accept both receipts, which is what the assertions below measure.
        let rebound: ProcessStartReceipt = with_one_coordinate(
            &receipt_a,
            &OPERATION_ID_PATH,
            serde_json::json!(operation_b),
        );
        let reused: ProcessStartReceipt = with_one_coordinate(
            &rebound,
            &START_MARKER_PATH,
            reused_start_marker(&receipt_a),
        );
        assert!(
            reused.validate().is_ok(),
            "the second receipt is well formed by production's own definition"
        );
        assert_eq!(reused.operation_id().as_str(), operation_b);
        assert_ne!(
            receipt_a.operation_id().as_str(),
            reused.operation_id().as_str()
        );

        let identity_a = receipt_a.identity();
        let identity_b = reused.identity();
        // The claim under test, stated before anything is driven: the two recorded
        // identities name the SAME OS process id and differ in the creation marker.
        assert_eq!(
            identity_a.pid(),
            identity_b.pid(),
            "both recorded identities name one OS process id, so a pid match cannot separate them"
        );
        assert_ne!(
            identity_a.physical().start_time_100ns(),
            identity_b.physical().start_time_100ns(),
            "the creation marker is what separates them"
        );
        // The image and Job coordinates the same bind also reads are identical, so
        // the only physical difference this case can be decided by is the marker.
        assert_eq!(
            identity_a.physical().image_path(),
            identity_b.physical().image_path()
        );
        assert_eq!(
            identity_a.physical().executor_job_name(),
            identity_b.physical().executor_job_name()
        );
        assert_eq!(
            identity_a.executable_sha256(),
            identity_b.executable_sha256()
        );
        // Equal generations, so the generation arm of the bind cannot be what
        // refuses: the refusal below is unambiguously the physical identity.
        assert_eq!(identity_a.generation(), identity_b.generation());

        // Both operations now hold their own committed start record, committed
        // through the production seam into the real store.
        let digest_b =
            process_admission_digest(&fixture.admission(operation_b)).expect("admission digest");
        ProcessStartPorts::persist_completed(
            &fixture.gateway,
            &OperationId::new(operation_b).expect("operation id"),
            &digest_b,
            &owner,
            reused.clone(),
        )
        .expect("production completed-start commit");
        let durable_a = fixture
            .durable_record(operation_a)
            .expect("committed start record");
        let durable_b = fixture
            .durable_record(operation_b)
            .expect("committed start record");
        assert_eq!(durable_a.state, ProcessStartReplayState::Completed);
        assert_eq!(durable_b.state, ProcessStartReplayState::Completed);
        assert_eq!(durable_a.receipt.as_ref(), Some(&receipt_a));
        assert_eq!(durable_b.receipt.as_ref(), Some(&reused));
        assert_ne!(durable_b.receipt.as_ref(), Some(&receipt_a));

        // The grant is minted by PRODUCTION's own origin-challenge authority for
        // the FIRST operation's recorded identity: issue, package, verify, decide.
        // Nothing here is fabricated; the key is test-local secret material.
        let mut origin_authority = eliot_process::OriginChallengeAuthority::activate(
            eliot_process::DispatchAuthorityId::new("kernel-901-w10-origin-authority")
                .expect("origin authority id"),
            eliot_process::KernelDispatchKey::from_secret_bytes([0x5c; 32])
                .expect("origin dispatch key"),
        );
        let origin_fence = eliot_contracts::StateFence::new(
            test_epoch(1),
            eliot_contracts::ResourceGeneration::new(1).expect("resource generation"),
        );
        let request_a = eliot_process::OriginChallengeRequest::new(
            identity_a.physical().clone(),
            "installation-1",
            "a".repeat(64),
            identity_a.generation(),
            origin_fence,
            eliot_process::OriginControlOperation::Kill,
            "kernel-901-w10-origin-nonce-a",
            receipt_a.operation_id().clone(),
        )
        .expect("origin challenge request");
        // Stamped from THIS FIXTURE's one clock reading, and handed unchanged to
        // issue, verify and decide, so the challenge window this grant is minted
        // under is the window it was handed.
        //
        // This is the tighter of this file's two budgets, and it is the only one
        // production re-checks against its OWN live clock:
        // `authorize_effect_with_grant` calls `grant.binds_effect_currency(..,
        // super::unix_ms())` (`src/process_execution.rs:3638-3644`), which refuses
        // with `ExpiredDispatchPermit` when `now_unix_ms > expires_at_unix_ms`
        // (`crates/kernel/eliot-process/src/origin_challenge.rs:705-707`). That
        // check is NOT the refusal this case measures - the target bind at
        // `:3630-3636` runs FIRST and is where the `IdentityMismatch` asserted
        // below is raised, so the currency check is never reached - but its margin
        // is real rather than assumed: the reading is taken inside
        // `identity_fixture`, and the only work between it and this call is one
        // real child launch, two commits and two durable re-reads, so a
        // 60-second budget is spent by seconds.
        let issued_at = fixture.now_ms;
        let origin_expires_at = issued_at.saturating_add(IDENTITY_ORIGIN_CHALLENGE_WINDOW_MS);
        let challenge_a = origin_authority
            .issue(&request_a, issued_at, origin_expires_at)
            .expect("origin challenge issuance");
        let presentation_a = eliot_process::OriginControlPresentation::new(request_a, challenge_a)
            .expect("origin control presentation");
        origin_authority
            .verify(&presentation_a, &test_epoch(1), issued_at)
            .expect("the exact recorded identity is admitted by the origin authority");
        let grant = origin_authority
            .decide(&presentation_a, &test_epoch(1), issued_at)
            .expect("origin control grant");

        // Positive control on the very function that refuses below: the grant admits
        // the exact identity it was minted for. Without this, a refusal could be an
        // unreachable arm rather than an identity decision.
        assert!(
            grant
                .binds_target_for_operation(
                    identity_a.physical(),
                    identity_a.generation(),
                    eliot_process::OriginControlOperation::Kill,
                )
                .is_ok(),
            "the minted grant binds its own recorded identity"
        );

        // The refusal. One privileged cancel, one operation span built INSIDE the
        // capture region so it binds the capture dispatcher.
        let (refusal, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = owner.clone();
            let grant = grant;
            let target_id = OperationId::new(operation_b).expect("operation id");
            async move {
                let context = ProcessExecutionGateway::operation_context_for(&owner, &target_id);
                gateway
                    .cancel_with_origin_grant_in_context(&owner, target_id, Some(&grant), &context)
                    .await
            }
        })
        .await;

        // The real typed failure production produced: the target bind's identity
        // arm, mapped by `authorize_effect_with_grant` through
        // `.map_err(ProcessExecutionError::Contract)` (`src/process_execution.rs:3636`).
        // It is specifically NOT `DispatchBindingMismatch`, which is the arm the
        // later operation-class and operation-identity checks use.
        assert!(
            matches!(
                &refusal,
                Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::IdentityMismatch
                ))
            ),
            "a grant minted for another operation's creation marker cannot act on this one: {refusal:?}"
        );

        // The refusal really is this boundary's decision and not a failed
        // observation: one request, one passing owner comparison, one rejection,
        // one terminal.
        assert_eq!(
            event_count(&logs, "kernel.process.cancel_requested"),
            1,
            "the cancel reached the boundary: {logs}"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.cancel_requested"),
            "attempt"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.owner_admitted"),
            1,
            "the durable owner comparison passed, so the refusal is the identity bind: {logs}"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.cancel_rejected"),
            "fenced"
        );
        assert_eq!(
            event_count(&logs, "kernel.terminal_error"),
            1,
            "one refused underlying operation yields exactly one terminal: {logs}"
        );
        assert_eq!(
            span_field(event_line(&logs, "kernel.terminal_error"), "code"),
            Some("process_contract"),
            "the terminal carries the contract code `process_terminal_code` maps: {logs}"
        );
        // The executor was never reached, so no effect observation exists.
        //
        // REGRESSION GUARD (absence), four effect observations. Each CAN redden: all
        // four are emitted from `cancel_with_origin_grant_inner` AFTER the identity
        // bind at `src/process_execution.rs:3218-3231` — `cancel_acknowledged` at
        // `:3321`, `cancel_failed` at `:3300`, `cancel_replayed` at `:3254` and
        // `cancel_unrecorded` at `:3314` — so a bind that admits, or an effect that
        // runs, emits at least one and makes this fail. The positive control is the
        // refusal above: the same boundary DID emit `cancel_requested` and
        // `cancel_rejected` on this exact capture, so the absence is production's
        // ordering and not an empty capture.
        for never_emitted in [
            "kernel.process.cancel_acknowledged",
            "kernel.process.cancel_failed",
            "kernel.process.cancel_replayed",
            "kernel.process.cancel_unrecorded",
        ] {
            assert!(
                !event_present(&logs, never_emitted),
                "{never_emitted} would mean the effect ran: {logs}"
            );
        }

        // No observation in the capture claims any process identity at all, so none
        // can claim the refused identity was the granted one. This boundary records
        // only `operation`, `generation` and `authority_epoch`; the three physical
        // slots stay at their declared `unavailable` default, which is the honest
        // answer for a span that holds no receipt.
        //
        // REGRESSION GUARD (absence), three slots, plus the operation binding below.
        // Each CAN redden: the declared defaults are the literals at
        // `src/kernel_diagnostics.rs:671-673`, and the only writer of those three
        // slots in this crate is `record_process_start_receipt_identity`
        // (`src/process_execution.rs:192-198`) — which the sibling case
        // `pid_alone_cannot_identify_a_process_after_reuse` shows reachable on a real
        // committed receipt. Calling it on the durable record this boundary DOES hold
        // fills all three with the refused identity itself and this fails. The
        // positive control is the `operation` binding asserted immediately after: the
        // same span carries that slot, from `operation_context_for`'s own
        // `process_operation_context` call at `:2847-2852`.
        let line = event_line(&logs, "kernel.process.cancel_requested");
        for slot in ["process_id", "process_start_100ns", "image_sha256"] {
            assert_eq!(
                span_field(line, slot),
                Some("unavailable"),
                "a boundary that records no receipt may not project {slot}: {line}"
            );
        }
        assert!(
            line.contains(&format!("operation=\"{operation_b}\"")),
            "the refused read is bound to its own operation: {line}"
        );
        // REGRESSION GUARD (absence), the granted operation on the refused read's
        // own rendered line. It CAN redden: the two operation identities are
        // structurally identical apart from their final `-a`/`-b` byte, so any span
        // built from `receipt_a.operation_id()` instead of the presented
        // `target_id` at `:1726` puts operation_a's exact bytes here. Positive
        // control: the assertion immediately above reads operation_b's bytes off this
        // same line.
        assert!(
            !line.contains(&format!("operation=\"{operation_a}\"")),
            "no observation may bind the refused read to the operation the grant was minted for: {line}"
        );

        // Completeness in the other direction: the refusal rewrote no durable
        // record, so neither operation's recorded identity moved.
        let after_a = fixture
            .durable_record(operation_a)
            .expect("committed start record");
        let after_b = fixture
            .durable_record(operation_b)
            .expect("committed start record");
        assert_eq!(after_a.receipt.as_ref(), Some(&receipt_a));
        assert_eq!(after_b.receipt.as_ref(), Some(&reused));
        drop(fixture);
        drop(root_guard);
    }

    // ---------------------------------------------------------------------------
    // The creation marker is not the only coordinate the identity comparison reads.
    //
    // The single `record.receipt.as_ref() != Some(receipt)` at
    // `src/process_execution.rs:3126` is a WHOLE-VALUE equality over
    // `ProcessStartReceipt` (`crates/kernel/eliot-process/src/lib.rs:2270`). The
    // case above varies only `identity.suspended.physical.start_time_100ns`, so on
    // its own it proves that ONE coordinate is compared and says nothing about the
    // executor-observed image path, the executor Job name or the image digest, all
    // of which the same single comparison has to reach for a substituted target to
    // be refused.
    //
    // Each receipt below is produced from PRODUCTION's own committed bytes by
    // `with_one_coordinate`, one leaf coordinate at a time, so each is well formed
    // by `ProcessStartReceipt::validate` and differs from the recorded receipt in
    // exactly one coordinate. That is the discriminating fact: a positive verdict
    // needs the live process to match the presented receipt, so if any ONE of these
    // coordinates escaped the comparison at `:3126` the substituted receipt would
    // pass `:3126`, reach the live lookup at `:3130`, find the REAL process whose
    // other coordinates are production's own bytes, and be ACCEPTED. The
    // `inspect_requested` count of one below is that discriminator.
    // ---------------------------------------------------------------------------

    /// The single leaf coordinate of a receipt's executor-observed image digest.
    const IMAGE_SHA256_PATH: [&str; 3] = ["identity", "suspended", "executable_sha256"];

    /// The single leaf coordinate of a receipt's executor-observed image path.
    const IMAGE_PATH_PATH: [&str; 4] = ["identity", "suspended", "physical", "image_path"];

    /// The single leaf coordinate of a receipt's executor-created Job name.
    const JOB_NAME_PATH: [&str; 4] = ["identity", "suspended", "physical", "executor_job_name"];

    // One substitution table per case reads long by construction; splitting it would
    // hide that every coordinate is decided by the same production comparison.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_substituted_image_path_job_or_digest_is_refused_exactly_like_a_reused_marker() {
        let (root_guard, fixture) = identity_fixture("w10-substituted");
        let operation = "kernel-901-w10-substituted";
        let admission = fixture.admission(operation);
        let exact = fixture.launch_and_commit(&admission).await;
        assert_lossless_round_trip(&exact);
        let view = fixture
            .live_handle(operation)
            .await
            .expect("the production executor retains the launched handle");
        assert_eq!(
            view.identity(),
            Some(exact.identity()),
            "the live process is the one the record names, so every coordinate below is production's own byte except the one named"
        );

        // Each entry names its coordinate, is PRODUCTION's own bytes with exactly
        // that one leaf replaced, and is well formed by production's own validator.
        let substitutions: [(&str, ProcessStartReceipt); 3] = [
            (
                "image_sha256",
                with_one_coordinate(
                    &exact,
                    &IMAGE_SHA256_PATH,
                    serde_json::json!("b".repeat(64)),
                ),
            ),
            (
                "image_path",
                with_one_coordinate(
                    &exact,
                    &IMAGE_PATH_PATH,
                    serde_json::json!(format!(
                        "{}-substituted",
                        exact.identity().physical().image_path()
                    )),
                ),
            ),
            (
                "executor_job_name",
                with_one_coordinate(
                    &exact,
                    &JOB_NAME_PATH,
                    serde_json::json!(format!(
                        "{}-substituted",
                        exact.identity().physical().executor_job_name()
                    )),
                ),
            ),
        ];
        for (name, substituted) in &substitutions {
            assert!(
                substituted.validate().is_ok(),
                "the {name} substitution is well formed by production's own definition"
            );
            assert_ne!(
                substituted, &exact,
                "the {name} substitution differs from the recorded receipt at all"
            );
            assert_eq!(
                substituted.identity().pid(),
                exact.identity().pid(),
                "the {name} substitution keeps the recorded OS process id, so a pid match cannot separate them"
            );
        }
        // Each coordinate is the ONLY difference, stated per coordinate so a second
        // silent difference cannot ride along and decide the refusal instead.
        for (name, substituted) in &substitutions {
            let physical = substituted.identity().physical();
            let recorded = exact.identity().physical();
            match *name {
                "image_sha256" => {
                    assert_eq!(physical.start_time_100ns(), recorded.start_time_100ns());
                    assert_eq!(physical.image_path(), recorded.image_path());
                    assert_eq!(physical.executor_job_name(), recorded.executor_job_name());
                }
                "image_path" => {
                    assert_eq!(physical.start_time_100ns(), recorded.start_time_100ns());
                    assert_eq!(physical.executor_job_name(), recorded.executor_job_name());
                }
                "executor_job_name" => {
                    assert_eq!(physical.start_time_100ns(), recorded.start_time_100ns());
                    assert_eq!(physical.image_path(), recorded.image_path());
                }
                other => panic!("no substitution table entry is named {other}"),
            }
        }

        // One capture so the positive control is measured in the same bytes as the
        // refusals: the exact receipt is accepted against the live process, and each
        // substituted receipt is refused.
        let (results, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = fixture.owner.clone();
            let exact = exact.clone();
            let substituted = substitutions.clone();
            async move {
                let operation_id = exact.operation_id().clone();
                let context = ProcessExecutionGateway::operation_context_for(&owner, &operation_id);
                let mut refusals = Vec::with_capacity(substituted.len());
                for (_, receipt) in &substituted {
                    refusals.push(
                        gateway
                            .inspect_exact_running_receipt_in_context(receipt, &context)
                            .await,
                    );
                }
                let admitted = gateway
                    .inspect_exact_running_receipt_in_context(&exact, &context)
                    .await;
                (refusals, admitted)
            }
        })
        .await;

        let (refusals, admitted) = results;
        assert!(
            admitted.is_ok(),
            "the exact recorded identity is still the running process: {admitted:?}"
        );
        for ((name, _), outcome) in substitutions.iter().zip(&refusals) {
            assert!(
                matches!(outcome, Err(ProcessExecutionError::UnknownOutcome)),
                "a substituted {name} is not this process: {outcome:?}"
            );
        }
        // THE DISCRIMINATOR. Four reads, one live-process lookup: each substituted
        // receipt was refused at the durable comparison `src/process_execution.rs:3125-3129`
        // and none reached `inspect_inner` at `:3130`. Had any one of the three
        // coordinates escaped that comparison, its receipt would have reached the
        // live process — whose every other coordinate is byte-identical — and been
        // accepted, making this 2.
        assert_eq!(
            event_count(&logs, "kernel.process.inspect_requested"),
            1,
            "only the exact receipt reached a live-process lookup: {logs}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.inspect_reported"),
            1,
            "the one live read observed the process: {logs}"
        );
        // The refusals rewrote no durable record, so the recorded identity did not
        // move to any substituted coordinate.
        let durable = fixture
            .durable_record(operation)
            .expect("committed start record");
        assert_eq!(durable.state, ProcessStartReplayState::Completed);
        assert_eq!(durable.receipt.as_ref(), Some(&exact));
        for (name, substituted) in &substitutions {
            assert_ne!(
                durable.receipt.as_ref(),
                Some(substituted),
                "the durable record still holds the recorded identity, not the substituted {name}"
            );
        }
        drop(fixture);
        drop(root_guard);
    }

    // ---------------------------------------------------------------------------
    // The generation arm of the target bind is a SEPARATE production decision from
    // the physical arm, and it is separately reachable.
    //
    // `OriginControlGrant::binds_target` (`crates/kernel/eliot-process/src/origin_challenge.rs:630-642`)
    // has exactly two refusals: `self.physical != *physical` at `:635` and
    // `self.generation != generation` at `:638`. The cross-operation case above
    // varies the physical arm and states that the generations are EQUAL, so it
    // proves the physical arm and, by construction, cannot reach the generation arm.
    // A grant minted for a DIFFERENT generation of the SAME physical process is what
    // reaches `:638`, and it must fail with `FenceMismatch` — the exact variant the
    // physical arm never produces — so this case tells the two refusals apart.
    // ---------------------------------------------------------------------------

    /// The single bounded window the origin grant below is minted under. It is this
    /// file's OWN budget, carried forward unchanged; no production constant supplies
    /// it. The grant's currency is rechecked against production's live clock at
    /// `crates/kernel/eliot-process/src/origin_challenge.rs:705-707`, but the
    /// refusal measured here is raised at `:638`, which runs FIRST, so the margin
    /// only has to keep the mint and the decide itself inside it.
    const IDENTITY_GENERATION_GRANT_WINDOW_MS: u64 = 60_000;

    // One grant carries both mint legs and both refusals; splitting them would hide
    // that the two decisions share one identity.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_grant_minted_for_another_generation_is_refused_on_the_generation_arm_alone() {
        let (root_guard, fixture) = identity_fixture("w10-generation");
        let owner = fixture.owner.clone();
        let operation = "kernel-901-w10-generation";
        let admission = fixture.admission(operation);
        let receipt = fixture.launch_and_commit(&admission).await;
        assert_lossless_round_trip(&receipt);
        let identity = receipt.identity();
        let recorded_generation = identity.generation();
        let other_generation = Generation::new(
            recorded_generation
                .get()
                .checked_add(1)
                .expect("a generation above the recorded one"),
        )
        .expect("substituted generation");
        assert_ne!(
            other_generation.get(),
            recorded_generation.get(),
            "the grant below must name a generation the record does not hold"
        );

        // PRODUCTION's own origin-challenge authority mints the grant for the SAME
        // physical identity and a DIFFERENT managed generation. Nothing here is
        // fabricated; the key is test-local secret material and the fence is built
        // to match the requested generation, which is what
        // `OriginChallengeRequest::validate` requires
        // (`crates/kernel/eliot-process/src/origin_challenge.rs:178-180`).
        let mut origin_authority = eliot_process::OriginChallengeAuthority::activate(
            eliot_process::DispatchAuthorityId::new("kernel-901-w10-generation-authority")
                .expect("origin authority id"),
            eliot_process::KernelDispatchKey::from_secret_bytes([0x6d; 32])
                .expect("origin dispatch key"),
        );
        let other_fence = eliot_contracts::StateFence::new(
            test_epoch(1),
            eliot_contracts::ResourceGeneration::new(other_generation.get())
                .expect("resource generation"),
        );
        let request = eliot_process::OriginChallengeRequest::new(
            identity.physical().clone(),
            "installation-1",
            "a".repeat(64),
            other_generation,
            other_fence,
            eliot_process::OriginControlOperation::Kill,
            "kernel-901-w10-generation-nonce",
            receipt.operation_id().clone(),
        )
        .expect("origin challenge request");
        let issued_at = fixture.now_ms;
        let challenge = origin_authority
            .issue(
                &request,
                issued_at,
                issued_at.saturating_add(IDENTITY_GENERATION_GRANT_WINDOW_MS),
            )
            .expect("origin challenge issuance");
        let presentation = eliot_process::OriginControlPresentation::new(request, challenge)
            .expect("origin control presentation");
        origin_authority
            .verify(&presentation, &test_epoch(1), issued_at)
            .expect("the authority admits the challenge it issued");
        let grant = origin_authority
            .decide(&presentation, &test_epoch(1), issued_at)
            .expect("origin control grant");

        // Positive control on the function that refuses below: the grant binds its
        // OWN generation on this exact physical identity, so the refusal cannot be an
        // unreachable arm and cannot be the physical arm — that one is proven equal
        // by this `is_ok`, which requires `self.physical == *physical` at `:635`.
        assert!(
            grant
                .binds_target_for_operation(
                    identity.physical(),
                    other_generation,
                    eliot_process::OriginControlOperation::Kill,
                )
                .is_ok(),
            "the minted grant binds its own recorded identity at its own generation"
        );

        // The refusal, on the SAME operation whose durable record production reads at
        // `src/process_execution.rs:3616-3620`: the presented receipt is byte-for-byte
        // the recorded one, so the physical arm holds and only the generation differs.
        let (refusal, logs) = capture_with(|| {
            let gateway = &fixture.gateway;
            let owner = owner.clone();
            let grant = grant;
            let target_id = OperationId::new(operation).expect("operation id");
            async move {
                let context = ProcessExecutionGateway::operation_context_for(&owner, &target_id);
                gateway
                    .cancel_with_origin_grant_in_context(&owner, target_id, Some(&grant), &context)
                    .await
            }
        })
        .await;

        // `FenceMismatch`, NOT `IdentityMismatch`. That distinction is the whole claim:
        // the two refusals are separate production decisions, and this input reached
        // the generation one at `crates/kernel/eliot-process/src/origin_challenge.rs:638-640`
        // rather than the physical one at `:635-637`.
        assert!(
            matches!(
                &refusal,
                Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::FenceMismatch
                ))
            ),
            "a grant for another generation of the same process cannot act on the recorded one: {refusal:?}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.cancel_requested"),
            1,
            "the cancel reached the boundary: {logs}"
        );
        assert_eq!(
            event_count(&logs, "kernel.process.owner_admitted"),
            1,
            "the durable owner comparison passed, so the refusal is the target bind: {logs}"
        );
        assert_eq!(
            event_outcome(&logs, "kernel.process.cancel_rejected"),
            "fenced"
        );
        assert_eq!(
            event_count(&logs, "kernel.terminal_error"),
            1,
            "one refused underlying operation yields exactly one terminal: {logs}"
        );
        assert_eq!(
            span_field(event_line(&logs, "kernel.terminal_error"), "code"),
            Some("process_contract"),
            "the terminal carries the contract code `process_terminal_code` maps: {logs}"
        );
        // REGRESSION GUARD (absence), the effect observations. Each CAN redden: all
        // four are emitted from `cancel_with_origin_grant_inner` AFTER the target
        // bind at `src/process_execution.rs:3218-3231`, so a bind that admits, or an
        // effect that runs, emits at least one. The positive control is the refusal
        // above: this same capture DID emit `cancel_requested` and `cancel_rejected`.
        for never_emitted in [
            "kernel.process.cancel_acknowledged",
            "kernel.process.cancel_failed",
            "kernel.process.cancel_replayed",
            "kernel.process.cancel_unrecorded",
        ] {
            assert!(
                !event_present(&logs, never_emitted),
                "{never_emitted} would mean the effect ran: {logs}"
            );
        }
        // The refusal rewrote no durable record: the recorded generation is still the
        // one the record holds, so nothing moved the identity to the granted one.
        let durable = fixture
            .durable_record(operation)
            .expect("committed start record");
        assert_eq!(durable.state, ProcessStartReplayState::Completed);
        assert_eq!(durable.receipt.as_ref(), Some(&receipt));
        assert_eq!(
            durable.receipt.as_ref().map(ProcessStartReceipt::identity),
            Some(identity),
            "the recorded identity still carries the recorded generation, not the granted one"
        );
        drop(fixture);
        drop(root_guard);
    }
}
