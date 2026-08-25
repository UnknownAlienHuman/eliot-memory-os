//! LocalService-only Store credential provisioning behind the Host owner epoch.

#![allow(
    clippy::doc_markdown,
    clippy::ignored_unit_patterns,
    clippy::implicit_clone,
    clippy::manual_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match,
    clippy::single_match_else,
    clippy::too_many_lines,
    reason = "the credential state machine keeps fail-closed branches explicit"
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_host_state::{HostInstallationEpoch, host_owner_epoch_digest};
use eliot_installation::{
    CredentialAccessReceipt, CredentialOwnershipMarkerIdentity, HOST_CREDENTIAL_CONTROL_PIPE,
    HostCredentialControlOperation, HostCredentialControlRequest, HostCredentialControlResponse,
    HostPhaseBMaterializationIntent, LOCAL_SERVICE_SID, StoreCredentialAbsentSnapshot,
    credential_absent_response_digest, credential_control_response_frame,
    credential_deleted_response_digest, credential_matching_response_digest,
    decode_credential_control_request_frame,
};
use eliot_ipc::{NamedPipeServer, TransportLimits};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    CredentialSecret, HostCredentialMutationCapability, InstallerRootObjectSnapshot,
    InstallerRootPrimitiveObservation, InstallerRootPrimitiveSpec, InstallerRootProfile,
    WindowsInstallerRootPrimitive, observe_named_pipe_peer_process, protected_program_data_root,
    windows_path_identity_digest, windows_paths_equal,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

const MARKER_LIMIT: u64 = 16 * 1024;
const MAX_PHASE_B_QUEUE_DEPTH: usize = 32;
const PHASE_B_QUEUE_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const ENVELOPE_VERSION: &str = "eliot.store-credential-envelope.v1";
const MARKER_VERSION: &str = "eliot.store-credential-marker.v1";

/// One authenticated Phase-B handoff waiting for the mutable Host owner
/// thread. The credential endpoint never materializes files itself; it only
/// transfers the typed request and a one-shot reply channel to Host.
pub struct HostPhaseBRequest {
    /// The authenticated operation selected by the installer request.
    pub operation: HostCredentialControlOperation,
    /// Exact transaction-bound Phase-B handoff intent.
    pub intent: HostPhaseBMaterializationIntent,
    /// Exact prior LocalService credential receipt admitted by the request.
    pub credential_receipt: CredentialAccessReceipt,
    /// One-shot response path back to the authenticated endpoint.
    pub reply: oneshot::Sender<HostCredentialControlResponse>,
}

/// Bounded queue crossing the authenticated endpoint and mutable Host owner.
pub type HostPhaseBRequestQueue = Arc<Mutex<VecDeque<HostPhaseBRequest>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MarkerPhase {
    Reserved,
    Finalized,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerRecord {
    version: String,
    transaction_id: PlatformHandle,
    effect_id: PlatformHandle,
    effect_binding_digest: PlatformHandle,
    marker: CredentialOwnershipMarkerIdentity,
    phase: MarkerPhase,
    credential_envelope_digest: Option<PlatformHandle>,
    mac: PlatformHandle,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEnvelope {
    version: String,
    transaction_id: PlatformHandle,
    effect_id: PlatformHandle,
    effect_binding_digest: PlatformHandle,
    generation: eliot_contracts::ResourceGeneration,
    config_digest: PlatformHandle,
    target: PlatformHandle,
    principal_sid: PlatformHandle,
    host_owner_epoch: PlatformHandle,
    marker: CredentialOwnershipMarkerIdentity,
    secret: Vec<u8>,
    mac: PlatformHandle,
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

trait CredentialBackend {
    fn principal_sid(&self) -> Result<PlatformHandle, String>;
    fn read(&self, target: &PlatformHandle) -> Result<Option<CredentialSecret>, String>;
    fn generate(&self) -> Result<CredentialSecret, String>;
    fn write_if_absent(
        &self,
        target: &PlatformHandle,
        bytes: Vec<u8>,
    ) -> Result<CredentialSecret, String>;
    fn delete_if_matching(
        &self,
        target: &PlatformHandle,
        expected_digest: &PlatformHandle,
        verify: &mut dyn FnMut(&CredentialSecret) -> bool,
    ) -> Result<(), String>;
}

struct ProductionCredentialBackend(HostCredentialMutationCapability);

impl CredentialBackend for ProductionCredentialBackend {
    fn principal_sid(&self) -> Result<PlatformHandle, String> {
        self.0.principal_sid().map_err(|error| error.to_string())
    }

    fn read(&self, target: &PlatformHandle) -> Result<Option<CredentialSecret>, String> {
        self.0
            .read_optional(target)
            .map_err(|error| error.to_string())
    }

    fn generate(&self) -> Result<CredentialSecret, String> {
        self.0.generate_secret().map_err(|error| error.to_string())
    }

    fn write_if_absent(
        &self,
        target: &PlatformHandle,
        bytes: Vec<u8>,
    ) -> Result<CredentialSecret, String> {
        let secret = CredentialSecret::from_bytes(bytes).map_err(|error| error.to_string())?;
        self.0
            .write_if_absent(target, secret)
            .map_err(|error| error.to_string())
    }

    fn delete_if_matching(
        &self,
        target: &PlatformHandle,
        expected_digest: &PlatformHandle,
        verify: &mut dyn FnMut(&CredentialSecret) -> bool,
    ) -> Result<(), String> {
        self.0
            .delete_if_matching(target, expected_digest, verify)
            .map_err(|error| error.to_string())
    }
}

/// Exact Host-owned credential mutation boundary. Construction requires the
/// already-open durable Host epoch and exact host-state root.
pub struct HostCredentialControl {
    core: HostCredentialControlCore<ProductionCredentialBackend>,
    phase_b_queue: HostPhaseBRequestQueue,
}

struct HostCredentialControlCore<B> {
    _host_epoch: HostInstallationEpoch,
    host_epoch_digest: PlatformHandle,
    host_process_digest: PlatformHandle,
    host_process_image: PathBuf,
    root_spec: InstallerRootPrimitiveSpec,
    primitive: WindowsInstallerRootPrimitive,
    backend: B,
}

impl HostCredentialControl {
    /// Creates the handler after Host owner epoch acquisition.
    pub(super) fn new(
        host_epoch: HostInstallationEpoch,
        host_state_root: PathBuf,
        capability: HostCredentialMutationCapability,
        phase_b_queue: HostPhaseBRequestQueue,
    ) -> Result<Self, String> {
        let installation_root = host_state_root
            .parent()
            .ok_or_else(|| "host_state_root has no installation parent".to_owned())?
            .to_path_buf();
        let profile_anchor = protected_program_data_root().map_err(|error| error.to_string())?;
        // Credential receipts and Phase-B materialization share the exact
        // sequence-bound owner discriminator. A direct-child Host must win
        // the durable recovery CAS before it can issue fresh credential
        // authority; the old receipt is evidence only.
        let host_epoch_digest =
            host_owner_epoch_digest(&host_epoch).map_err(|error| error.to_string())?;
        let process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| error.to_string())?;
        let host_process_digest = handle_digest(process.identity().stable_key().as_bytes())?;
        let host_process_image = PathBuf::from(process.image_path());
        Ok(Self {
            core: HostCredentialControlCore {
                _host_epoch: host_epoch,
                host_epoch_digest,
                host_process_digest,
                host_process_image,
                root_spec: InstallerRootPrimitiveSpec {
                    root: host_state_root,
                    installation_root,
                    profile_anchor,
                    profile: InstallerRootProfile::SystemService,
                },
                primitive: WindowsInstallerRootPrimitive::new(),
                backend: ProductionCredentialBackend(capability),
            },
            phase_b_queue,
        })
    }

    /// Returns the bounded queue consumed by the mutable Host owner thread.
    #[must_use]
    pub fn phase_b_queue(&self) -> HostPhaseBRequestQueue {
        Arc::clone(&self.phase_b_queue)
    }

    /// Handles one already-authenticated request. No secret is returned.
    async fn handle(
        &self,
        request: &HostCredentialControlRequest,
    ) -> HostCredentialControlResponse {
        if matches!(
            request.intent.operation,
            HostCredentialControlOperation::MaterializePhaseB
                | HostCredentialControlOperation::ReconcilePhaseB
        ) {
            return self.enqueue_phase_b(request).await;
        }
        self.core.handle(request)
    }

    async fn enqueue_phase_b(
        &self,
        request: &HostCredentialControlRequest,
    ) -> HostCredentialControlResponse {
        if request.validate().is_err() {
            return unknown(request, "phase-b-request-validation");
        }
        let Some(intent) = request.phase_b.clone() else {
            return unknown(request, "phase-b-request-intent");
        };
        let Some(credential_receipt) = request.expected_receipt.clone() else {
            return unknown(request, "phase-b-request-credential-receipt");
        };
        let (reply, response) = oneshot::channel();
        {
            let Ok(mut queue) = self.phase_b_queue.lock() else {
                return unknown(request, "phase-b-queue-lock");
            };
            if queue.len() >= MAX_PHASE_B_QUEUE_DEPTH {
                return unknown(request, "phase-b-queue-full");
            }
            queue.push_back(HostPhaseBRequest {
                operation: request.intent.operation,
                intent,
                credential_receipt,
                reply,
            });
        }
        match tokio::time::timeout(PHASE_B_QUEUE_RESPONSE_TIMEOUT, response).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => unknown(request, "phase-b-queue-response"),
        }
    }

    /// Serves one bounded request through the existing authenticated EBP
    /// named-pipe transport. The DACL and impersonated client token both
    /// require enabled built-in Administrators membership.
    ///
    /// # Errors
    ///
    /// Returns an error when the authenticated transport or one bounded
    /// request cannot be established.
    pub async fn serve_one(&self, timeout: std::time::Duration) -> Result<(), String> {
        let installer =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|error| error.to_string())?;
        let mut server = NamedPipeServer::create(HOST_CREDENTIAL_CONTROL_PIPE, &installer)
            .map_err(|error| error.to_string())?;
        server
            .wait_for_authenticated_client(timeout, &installer)
            .await
            .map_err(|error| error.to_string())?;
        let limits = TransportLimits::default();
        let frame = server
            .receive_frame(limits)
            .await
            .map_err(|error| error.to_string())?;
        let connection_id = frame.connection_id.clone();
        let request =
            decode_credential_control_request_frame(&frame).map_err(|error| error.to_string())?;
        let response = self.handle(&request).await;
        let response = credential_control_response_frame(connection_id, &response)
            .map_err(|error| error.to_string())?;
        server
            .send_frame(&response, limits)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl<B: CredentialBackend> HostCredentialControlCore<B> {
    fn handle(&self, request: &HostCredentialControlRequest) -> HostCredentialControlResponse {
        if request.validate().is_err()
            || !windows_paths_equal(
                Path::new(request.intent.provision.host_state_root.as_str()),
                &self.root_spec.root,
            )
            || !windows_paths_equal(
                Path::new(request.intent.provision.expected_host_executable.as_str()),
                &self.host_process_image,
            )
            || self
                .backend
                .principal_sid()
                .ok()
                .as_ref()
                .map(PlatformHandle::as_str)
                != Some(LOCAL_SERVICE_SID)
        {
            return unknown(request, "credential-control-admission");
        }
        match request.intent.operation {
            HostCredentialControlOperation::Inspect => self.inspect(request),
            HostCredentialControlOperation::Provision
            | HostCredentialControlOperation::Reconcile => self.provision_or_reconcile(request),
            HostCredentialControlOperation::Delete => self.delete(request),
            HostCredentialControlOperation::MaterializePhaseB
            | HostCredentialControlOperation::ReconcilePhaseB => {
                unknown(request, "phase-b-dispatch")
            }
        }
    }

    fn inspect(&self, request: &HostCredentialControlRequest) -> HostCredentialControlResponse {
        let root = match self.primitive.inspect(&self.root_spec) {
            Ok(InstallerRootPrimitiveObservation::Matching(root)) => root,
            _ => return unknown(request, "credential-host-root"),
        };
        let marker_path = marker_path(&self.root_spec.root, request);
        let marker_absent = match path_absent(&marker_path) {
            Ok(absent) => absent,
            Err(()) => return unknown(request, "credential-marker-absence"),
        };
        let target_absent = match self.backend.read(&request.intent.provision.target) {
            Ok(value) => value.is_none(),
            Err(_) => return unknown(request, "credential-target-absence"),
        };
        if !marker_absent || !target_absent {
            return unknown(request, "credential-preexisting-marker-or-target");
        }
        let snapshot = StoreCredentialAbsentSnapshot {
            host_owner_epoch: self.host_epoch_digest.clone(),
            host_process_identity: self.host_process_digest.clone(),
            host_state_root: marker_identity(&root),
            marker_path_digest: match path_digest(&marker_path) {
                Ok(value) => value,
                Err(_) => return unknown(request, "credential-marker-path"),
            },
            marker_absent: true,
            target_absent: true,
        };
        let response_digest =
            match credential_absent_response_digest(&request.intent.request_digest, &snapshot) {
                Ok(value) => value,
                Err(_) => return unknown(request, "credential-inspect-digest"),
            };
        HostCredentialControlResponse::Absent {
            snapshot,
            response_digest,
        }
    }

    fn provision_or_reconcile(
        &self,
        request: &HostCredentialControlRequest,
    ) -> HostCredentialControlResponse {
        let marker_path = marker_path(&self.root_spec.root, request);
        let key = request.ownership_key.as_slice();
        let marker = match self.primitive.read_local_service_protected_file(
            &self.root_spec,
            &marker_path,
            MARKER_LIMIT,
        ) {
            Ok(readback) => match decode_marker(request, key, &readback.object, &readback.bytes) {
                Ok(marker) => (readback.object, marker),
                Err(()) => return unknown(request, "credential-marker-mac"),
            },
            Err(_) => {
                let target = match self.backend.read(&request.intent.provision.target) {
                    Ok(value) => value,
                    Err(_) => return unknown(request, "credential-target-before-marker-read"),
                };
                if request.intent.operation == HostCredentialControlOperation::Reconcile
                    && request.expected_receipt.is_some()
                {
                    let receipt = request
                        .expected_receipt
                        .as_ref()
                        .unwrap_or_else(|| unreachable!());
                    return if target.is_none() {
                        deleted_response_for_receipt(request, receipt)
                    } else if let Some(target) = target {
                        // A crash may occur after the protected marker delete
                        // and before the response reaches the installer.  An
                        // exact durable receipt is sufficient authority to
                        // clean the matching credential, but never to adopt a
                        // target without that receipt.
                        let marker = marker_snapshot(&receipt.marker);
                        let valid = handle_digest(target.expose()).ok().as_ref()
                            == Some(&receipt.credential_envelope_digest)
                            && decode_envelope(
                                request,
                                key,
                                &receipt.host_owner_epoch,
                                &marker,
                                target.expose(),
                            )
                            .is_ok();
                        if !valid {
                            return unknown(request, "credential-target-without-marker");
                        }
                        let mut verify = |value: &CredentialSecret| {
                            decode_envelope(
                                request,
                                key,
                                &receipt.host_owner_epoch,
                                &marker,
                                value.expose(),
                            )
                            .is_ok()
                        };
                        if self
                            .backend
                            .delete_if_matching(
                                &request.intent.provision.target,
                                &receipt.credential_envelope_digest,
                                &mut verify,
                            )
                            .is_err()
                        {
                            return unknown(request, "credential-target-without-marker-delete");
                        }
                        deleted_response_for_receipt(request, receipt)
                    } else {
                        unknown(request, "credential-target-without-marker")
                    };
                }
                if target.is_some() {
                    return unknown(request, "credential-target-before-marker");
                }
                let created = self.primitive.create_local_service_protected_file(
                    &self.root_spec,
                    &marker_path,
                    |identity| marker_bytes(request, key, identity, MarkerPhase::Reserved, None),
                );
                let identity = match created {
                    Ok(identity) => identity,
                    Err(_) => return unknown(request, "credential-marker-create"),
                };
                let readback = match self.primitive.read_local_service_protected_file(
                    &self.root_spec,
                    &marker_path,
                    MARKER_LIMIT,
                ) {
                    Ok(value) if value.object == identity => value,
                    Ok(_) => return unknown(request, "credential-marker-created-identity"),
                    Err(_) => return unknown(request, "credential-marker-flush-readback"),
                };
                let marker = match decode_marker(request, key, &readback.object, &readback.bytes) {
                    Ok(marker) => marker,
                    Err(()) => return unknown(request, "credential-marker-created-mac"),
                };
                (readback.object, marker)
            }
        };
        if request.expected_receipt.as_ref().is_some_and(|receipt| {
            receipt.marker != marker_identity(&marker.0)
                || receipt.host_owner_epoch != self.host_epoch_digest
        }) {
            return unknown(request, "credential-reconcile-receipt-binding");
        }
        let existing = match self.backend.read(&request.intent.provision.target) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-target-read"),
        };
        let envelope_bytes = if let Some(existing) = existing {
            if decode_envelope(
                request,
                key,
                &self.host_epoch_digest,
                &marker.0,
                existing.expose(),
            )
            .is_err()
            {
                return unknown(request, "credential-target-binding");
            }
            if request.expected_receipt.as_ref().is_some_and(|receipt| {
                handle_digest(existing.expose()).ok().as_ref()
                    != Some(&receipt.credential_envelope_digest)
            }) {
                return unknown(request, "credential-reconcile-envelope-digest");
            }
            existing.expose().to_vec()
        } else {
            if request.expected_receipt.is_some() {
                if self.primitive.delete_file(&marker_path, &marker.0).is_err()
                    || !matches!(path_absent(&marker_path), Ok(true))
                {
                    return unknown(request, "credential-reconcile-marker-delete");
                }
                let receipt = request
                    .expected_receipt
                    .as_ref()
                    .unwrap_or_else(|| unreachable!());
                return deleted_response_for_receipt(request, receipt);
            }
            if matches!(marker.1.phase, MarkerPhase::Finalized) {
                return unknown(request, "credential-final-marker-without-target");
            }
            let generated = match self.backend.generate() {
                Ok(value) => value,
                Err(_) => return unknown(request, "credential-csprng"),
            };
            let bytes = match envelope_bytes(
                request,
                key,
                &self.host_epoch_digest,
                &marker.0,
                generated.expose(),
            ) {
                Ok(value) => value,
                Err(_) => return unknown(request, "credential-envelope"),
            };
            // The capability holds a protected Host-state interlock across
            // the final absence check, CredWriteW and authoritative readback.
            let readback = match write_if_absent(
                &self.backend,
                &request.intent.provision.target,
                bytes.clone(),
            ) {
                Ok(readback) => readback,
                Err(label) => return unknown(request, label),
            };
            if readback.expose() != bytes
                || decode_envelope(
                    request,
                    key,
                    &self.host_epoch_digest,
                    &marker.0,
                    readback.expose(),
                )
                .is_err()
            {
                return unknown(request, "credential-write-mismatch");
            }
            bytes
        };
        let envelope_digest = match handle_digest(&envelope_bytes) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-envelope-digest"),
        };
        let final_bytes = match marker_bytes(
            request,
            key,
            &marker.0,
            MarkerPhase::Finalized,
            Some(&envelope_digest),
        ) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-final-marker"),
        };
        if self
            .primitive
            .rewrite_local_service_protected_file(
                &self.root_spec,
                &marker_path,
                &marker.0,
                &final_bytes,
            )
            .is_err()
        {
            return unknown(request, "credential-final-marker-write");
        }
        let response_digest = match credential_matching_response_digest(
            &request.intent.request_digest,
            &self.host_epoch_digest,
            &self.host_process_digest,
            &marker_identity(&marker.0),
            &envelope_digest,
        ) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-response-digest"),
        };
        let receipt = CredentialAccessReceipt {
            transaction_id: request.intent.transaction_id.clone(),
            effect_id: request.intent.effect_id.clone(),
            generation: request.intent.provision.generation,
            config_digest: request.intent.provision.config_digest.clone(),
            target: request.intent.provision.target.clone(),
            provider: request.intent.provision.provider,
            scope: request.intent.provision.scope,
            principal_sid: request.intent.provision.expected_principal_sid.clone(),
            host_owner_epoch: self.host_epoch_digest.clone(),
            host_process_identity: self.host_process_digest.clone(),
            marker: marker_identity(&marker.0),
            credential_envelope_digest: envelope_digest,
            request_digest: request.intent.request_digest.clone(),
            response_digest,
        };
        HostCredentialControlResponse::Matching { receipt }
    }

    fn delete(&self, request: &HostCredentialControlRequest) -> HostCredentialControlResponse {
        let marker_path = marker_path(&self.root_spec.root, request);
        let readback = match self.primitive.read_local_service_protected_file(
            &self.root_spec,
            &marker_path,
            MARKER_LIMIT,
        ) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-delete-marker"),
        };
        if decode_marker(
            request,
            &request.ownership_key,
            &readback.object,
            &readback.bytes,
        )
        .is_err()
        {
            return unknown(request, "credential-delete-marker-mac");
        }
        let Some(expected_receipt) = request.expected_receipt.as_ref() else {
            return unknown(request, "credential-delete-receipt");
        };
        if expected_receipt.marker != marker_identity(&readback.object)
            || expected_receipt.host_owner_epoch != self.host_epoch_digest
        {
            return unknown(request, "credential-delete-receipt-binding");
        }
        if delete_credential_with_readback(
            &self.backend,
            request,
            &request.ownership_key,
            &self.host_epoch_digest,
            &readback.object,
            expected_receipt,
        )
        .is_err()
            || self
                .primitive
                .delete_file(&marker_path, &readback.object)
                .is_err()
            || !matches!(path_absent(&marker_path), Ok(true))
        {
            return unknown(request, "credential-delete-readback");
        }
        let absence_digest = match credential_deleted_response_digest(
            &request.intent.request_digest,
            &expected_receipt.host_owner_epoch,
            &expected_receipt.host_process_identity,
            &expected_receipt.marker,
        ) {
            Ok(value) => value,
            Err(_) => return unknown(request, "credential-delete-digest"),
        };
        HostCredentialControlResponse::Deleted { absence_digest }
    }
}

fn delete_credential_with_readback<B: CredentialBackend>(
    backend: &B,
    request: &HostCredentialControlRequest,
    ownership_key: &[u8],
    host_epoch: &PlatformHandle,
    marker: &InstallerRootObjectSnapshot,
    expected_receipt: &CredentialAccessReceipt,
) -> Result<(), ()> {
    let mut verify = |target: &CredentialSecret| {
        decode_envelope(request, ownership_key, host_epoch, marker, target.expose()).is_ok()
    };
    backend
        .delete_if_matching(
            &request.intent.provision.target,
            &expected_receipt.credential_envelope_digest,
            &mut verify,
        )
        .map_err(|_| ())
}

fn marker_path(root: &Path, request: &HostCredentialControlRequest) -> PathBuf {
    let digest = sha256_hex(
        format!(
            "{}\0{}\0{}",
            request.intent.transaction_id.as_str(),
            request.intent.effect_id.as_str(),
            request.intent.provision.target.as_str()
        )
        .as_bytes(),
    );
    root.join(format!(".eliot-store-credential-{digest}.owner"))
}

fn marker_identity(value: &InstallerRootObjectSnapshot) -> CredentialOwnershipMarkerIdentity {
    CredentialOwnershipMarkerIdentity {
        canonical_path_digest: PlatformHandle::new(value.canonical_path_digest.clone())
            .unwrap_or_else(|_| unreachable!()),
        volume_serial_number: value.volume_serial_number,
        file_index: value.file_index,
        security_descriptor_digest: PlatformHandle::new(value.security_descriptor_digest.clone())
            .unwrap_or_else(|_| unreachable!()),
    }
}

fn marker_snapshot(value: &CredentialOwnershipMarkerIdentity) -> InstallerRootObjectSnapshot {
    InstallerRootObjectSnapshot {
        canonical_path_digest: value.canonical_path_digest.as_str().to_owned(),
        volume_serial_number: value.volume_serial_number,
        file_index: value.file_index,
        security_descriptor_digest: value.security_descriptor_digest.as_str().to_owned(),
    }
}

fn marker_bytes(
    request: &HostCredentialControlRequest,
    key: &[u8],
    identity: &InstallerRootObjectSnapshot,
    phase: MarkerPhase,
    envelope_digest: Option<&PlatformHandle>,
) -> Result<Vec<u8>, eliot_platform_windows::InstallerRootError> {
    #[derive(Serialize)]
    struct MacInput<'a> {
        version: &'static str,
        transaction_id: &'a PlatformHandle,
        effect_id: &'a PlatformHandle,
        effect_binding_digest: &'a PlatformHandle,
        marker: CredentialOwnershipMarkerIdentity,
        phase: MarkerPhase,
        credential_envelope_digest: Option<&'a PlatformHandle>,
    }
    let input = MacInput {
        version: MARKER_VERSION,
        transaction_id: &request.intent.transaction_id,
        effect_id: &request.intent.effect_id,
        effect_binding_digest: &request.intent.effect_binding_digest,
        marker: marker_identity(identity),
        phase,
        credential_envelope_digest: envelope_digest,
    };
    let mac = PlatformHandle::new(hmac_sha256_hex(
        key,
        &serde_json::to_vec(&input)
            .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)?,
    ))
    .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)?;
    serde_json::to_vec(&MarkerRecord {
        version: MARKER_VERSION.to_owned(),
        transaction_id: request.intent.transaction_id.clone(),
        effect_id: request.intent.effect_id.clone(),
        effect_binding_digest: request.intent.effect_binding_digest.clone(),
        marker: marker_identity(identity),
        phase,
        credential_envelope_digest: envelope_digest.cloned(),
        mac,
    })
    .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)
}

fn decode_marker(
    request: &HostCredentialControlRequest,
    key: &[u8],
    identity: &InstallerRootObjectSnapshot,
    bytes: &[u8],
) -> Result<MarkerRecord, ()> {
    let marker: MarkerRecord = serde_json::from_slice(bytes).map_err(|_| ())?;
    let expected = marker_bytes(
        request,
        key,
        identity,
        marker.phase,
        marker.credential_envelope_digest.as_ref(),
    )
    .map_err(|_| ())?;
    let expected: MarkerRecord = serde_json::from_slice(&expected).map_err(|_| ())?;
    if !constant_time_handle_equal(&marker.mac, &expected.mac)
        || marker.marker != marker_identity(identity)
        || marker.version != MARKER_VERSION
    {
        return Err(());
    }
    Ok(marker)
}

fn envelope_bytes(
    request: &HostCredentialControlRequest,
    key: &[u8],
    host_owner_epoch: &PlatformHandle,
    identity: &InstallerRootObjectSnapshot,
    secret: &[u8],
) -> Result<Vec<u8>, ()> {
    #[derive(Serialize)]
    struct MacInput<'a> {
        version: &'static str,
        transaction_id: &'a PlatformHandle,
        effect_id: &'a PlatformHandle,
        effect_binding_digest: &'a PlatformHandle,
        generation: eliot_contracts::ResourceGeneration,
        config_digest: &'a PlatformHandle,
        target: &'a PlatformHandle,
        principal_sid: &'a PlatformHandle,
        host_owner_epoch: &'a PlatformHandle,
        marker: CredentialOwnershipMarkerIdentity,
        secret: &'a [u8],
    }
    let input = MacInput {
        version: ENVELOPE_VERSION,
        transaction_id: &request.intent.transaction_id,
        effect_id: &request.intent.effect_id,
        effect_binding_digest: &request.intent.effect_binding_digest,
        generation: request.intent.provision.generation,
        config_digest: &request.intent.provision.config_digest,
        target: &request.intent.provision.target,
        principal_sid: &request.intent.provision.expected_principal_sid,
        host_owner_epoch,
        marker: marker_identity(identity),
        secret,
    };
    let mac = PlatformHandle::new(hmac_sha256_hex(
        key,
        &serde_json::to_vec(&input).map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    serde_json::to_vec(&CredentialEnvelope {
        version: ENVELOPE_VERSION.to_owned(),
        transaction_id: request.intent.transaction_id.clone(),
        effect_id: request.intent.effect_id.clone(),
        effect_binding_digest: request.intent.effect_binding_digest.clone(),
        generation: request.intent.provision.generation,
        config_digest: request.intent.provision.config_digest.clone(),
        target: request.intent.provision.target.clone(),
        principal_sid: request.intent.provision.expected_principal_sid.clone(),
        host_owner_epoch: host_owner_epoch.clone(),
        marker: marker_identity(identity),
        secret: secret.to_vec(),
        mac,
    })
    .map_err(|_| ())
}

fn decode_envelope(
    request: &HostCredentialControlRequest,
    key: &[u8],
    host_owner_epoch: &PlatformHandle,
    identity: &InstallerRootObjectSnapshot,
    bytes: &[u8],
) -> Result<(), ()> {
    let envelope: CredentialEnvelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let expected = envelope_bytes(request, key, host_owner_epoch, identity, &envelope.secret)?;
    let expected: CredentialEnvelope = serde_json::from_slice(&expected).map_err(|_| ())?;
    if !constant_time_handle_equal(&envelope.mac, &expected.mac)
        || envelope.marker != marker_identity(identity)
        || envelope.version != ENVELOPE_VERSION
    {
        return Err(());
    }
    Ok(())
}

fn unknown(request: &HostCredentialControlRequest, label: &str) -> HostCredentialControlResponse {
    HostCredentialControlResponse::Unknown {
        pending_ref: PlatformHandle::new(format!(
            "credential-control:operation={:?}:transaction_id={}:effect_id={}:request_digest={}:reason={label}",
            request.intent.operation,
            request.intent.transaction_id.as_str(),
            request.intent.effect_id.as_str(),
            request.intent.request_digest.as_str(),
        ))
        .unwrap_or_else(|_| unreachable!()),
    }
}

fn deleted_response(
    request: &HostCredentialControlRequest,
    host_owner_epoch: &PlatformHandle,
    host_process_identity: &PlatformHandle,
    marker: &CredentialOwnershipMarkerIdentity,
) -> HostCredentialControlResponse {
    match credential_deleted_response_digest(
        &request.intent.request_digest,
        host_owner_epoch,
        host_process_identity,
        marker,
    ) {
        Ok(absence_digest) => HostCredentialControlResponse::Deleted { absence_digest },
        Err(_) => unknown(request, "credential-delete-digest"),
    }
}

fn deleted_response_for_receipt(
    request: &HostCredentialControlRequest,
    receipt: &CredentialAccessReceipt,
) -> HostCredentialControlResponse {
    deleted_response(
        request,
        &receipt.host_owner_epoch,
        &receipt.host_process_identity,
        &receipt.marker,
    )
}

fn path_absent(path: &Path) -> Result<bool, ()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(()),
    }
}

fn write_if_absent<B: CredentialBackend>(
    backend: &B,
    target: &PlatformHandle,
    bytes: Vec<u8>,
) -> Result<CredentialSecret, &'static str> {
    backend.write_if_absent(target, bytes).map_err(|error| {
        if error.contains("already") || error.contains("exists") {
            "credential-target-prewrite-race"
        } else {
            "credential-write"
        }
    })
}

fn path_digest(path: &Path) -> Result<PlatformHandle, String> {
    PlatformHandle::new(windows_path_identity_digest(path)).map_err(|error| error.to_string())
}

fn handle_digest(bytes: &[u8]) -> Result<PlatformHandle, String> {
    PlatformHandle::new(sha256_hex(bytes)).map_err(|error| error.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    normalized.fill(0);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer_pad.fill(0);
    format!("{:x}", outer.finalize())
}

fn constant_time_handle_equal(left: &PlatformHandle, right: &PlatformHandle) -> bool {
    let left = left.as_str().as_bytes();
    let right = right.as_str().as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().min(right.len()) {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use eliot_installation::{
        HostCredentialControlIntent, StoreCredentialProvider, StoreCredentialProvisionPlan,
        StoreCredentialScope,
    };

    use super::*;

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap_or_else(|error| panic!("test handle: {error}"))
    }

    fn provision() -> StoreCredentialProvisionPlan {
        StoreCredentialProvisionPlan {
            host_state_root: handle(r"C:\ProgramData\Eliot\host"),
            expected_host_executable: handle(r"C:\ProgramData\Eliot\eliot-host.exe"),
            target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            expected_principal_sid: handle(LOCAL_SERVICE_SID),
            generation: eliot_contracts::ResourceGeneration::genesis(),
            config_digest: handle("c".repeat(64)),
        }
    }

    fn request(operation: HostCredentialControlOperation) -> HostCredentialControlRequest {
        let intent = HostCredentialControlIntent::new(
            operation,
            handle("tx:test"),
            handle("effect:test"),
            provision(),
            handle("a".repeat(64)),
        )
        .unwrap_or_else(|error| panic!("test intent: {error}"));
        HostCredentialControlRequest {
            intent,
            ownership_key: if operation == HostCredentialControlOperation::Inspect {
                Vec::new()
            } else {
                vec![7; 32]
            },
            expected_receipt: None,
            phase_b: None,
        }
    }

    #[test]
    fn unknown_response_preserves_original_operation_and_request_digest() {
        let request = request(HostCredentialControlOperation::Provision);
        let response = unknown(&request, "injected-failure");
        let HostCredentialControlResponse::Unknown { pending_ref } = response else {
            panic!("expected Unknown response");
        };
        assert!(pending_ref.as_str().contains("Provision"));
        assert!(
            pending_ref
                .as_str()
                .contains(request.intent.transaction_id.as_str())
        );
        assert!(
            pending_ref
                .as_str()
                .contains(request.intent.effect_id.as_str())
        );
        assert!(
            pending_ref
                .as_str()
                .contains(request.intent.request_digest.as_str())
        );
        assert!(pending_ref.as_str().contains("injected-failure"));
        let error_digest = sha256_hex(b"injected-failure");
        assert!(!pending_ref.as_str().contains(&error_digest));
    }

    fn identity() -> InstallerRootObjectSnapshot {
        InstallerRootObjectSnapshot {
            canonical_path_digest: "b".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "d".repeat(64),
        }
    }

    #[test]
    fn marker_and_envelope_reject_key_byte_and_host_epoch_substitution() {
        let request = request(HostCredentialControlOperation::Provision);
        let identity = identity();
        let marker = marker_bytes(
            &request,
            &request.ownership_key,
            &identity,
            MarkerPhase::Reserved,
            None,
        )
        .unwrap_or_else(|error| panic!("marker: {error}"));
        assert!(decode_marker(&request, &request.ownership_key, &identity, &marker).is_ok());
        let mut wrong_key = request.ownership_key.clone();
        wrong_key[0] ^= 1;
        assert!(decode_marker(&request, &wrong_key, &identity, &marker).is_err());
        let mut changed = marker.clone();
        let last = changed.len().saturating_sub(2);
        changed[last] ^= 1;
        assert!(decode_marker(&request, &request.ownership_key, &identity, &changed).is_err());

        let epoch = handle("epoch:one");
        let envelope = envelope_bytes(
            &request,
            &request.ownership_key,
            &epoch,
            &identity,
            &[9; 32],
        )
        .unwrap_or_else(|()| panic!("envelope"));
        assert!(
            decode_envelope(
                &request,
                &request.ownership_key,
                &epoch,
                &identity,
                &envelope,
            )
            .is_ok()
        );
        assert!(
            decode_envelope(
                &request,
                &request.ownership_key,
                &handle("epoch:two"),
                &identity,
                &envelope,
            )
            .is_err()
        );
    }

    #[test]
    fn credential_owner_binding_is_bound_to_exact_child_host_epoch() {
        let installation = handle("installation:test");
        let lineage = handle("lineage:test");
        let parent = HostInstallationEpoch {
            installation: installation.clone(),
            epoch: eliot_host_state::EpochTransition {
                current: eliot_host_state::EpochIdentity {
                    lineage: lineage.clone(),
                    sequence: 1,
                },
                parent: None,
            },
            nonce: handle("nonce:one"),
            recovery: None,
        };
        let child = HostInstallationEpoch {
            installation,
            epoch: eliot_host_state::EpochTransition {
                current: eliot_host_state::EpochIdentity {
                    lineage,
                    sequence: 2,
                },
                parent: Some(parent.epoch.current.clone()),
            },
            nonce: handle("nonce:two"),
            recovery: None,
        };
        assert_ne!(
            host_owner_epoch_digest(&parent)
                .unwrap_or_else(|error| panic!("parent epoch digest: {error}")),
            host_owner_epoch_digest(&child)
                .unwrap_or_else(|error| panic!("child epoch digest: {error}"))
        );
    }

    #[test]
    fn marker_before_credential_crash_is_resumable_and_finalization_is_bound() {
        let request = request(HostCredentialControlOperation::Provision);
        let identity = identity();
        let reserved_bytes = marker_bytes(
            &request,
            &request.ownership_key,
            &identity,
            MarkerPhase::Reserved,
            None,
        )
        .unwrap_or_else(|error| panic!("reserved marker: {error}"));
        let reserved = decode_marker(&request, &request.ownership_key, &identity, &reserved_bytes)
            .unwrap_or_else(|()| panic!("reserved marker readback"));
        assert_eq!(reserved.phase, MarkerPhase::Reserved);
        assert!(reserved.credential_envelope_digest.is_none());

        let envelope = envelope_bytes(
            &request,
            &request.ownership_key,
            &handle("epoch:one"),
            &identity,
            &[9; 32],
        )
        .unwrap_or_else(|()| panic!("envelope"));
        let envelope_digest =
            handle_digest(&envelope).unwrap_or_else(|error| panic!("envelope digest: {error}"));
        let finalized_bytes = marker_bytes(
            &request,
            &request.ownership_key,
            &identity,
            MarkerPhase::Finalized,
            Some(&envelope_digest),
        )
        .unwrap_or_else(|error| panic!("final marker: {error}"));
        let finalized = decode_marker(
            &request,
            &request.ownership_key,
            &identity,
            &finalized_bytes,
        )
        .unwrap_or_else(|()| panic!("final marker readback"));
        assert_eq!(finalized.phase, MarkerPhase::Finalized);
        assert_eq!(finalized.credential_envelope_digest, Some(envelope_digest));
    }

    #[test]
    fn receipt_digest_rejects_host_process_substitution_and_short_key() {
        let request_value = request(HostCredentialControlOperation::Provision);
        let marker = marker_identity(&identity());
        let epoch = handle("epoch:one");
        let process = handle("1".repeat(64));
        let envelope = handle("2".repeat(64));
        let response_digest = credential_matching_response_digest(
            &request_value.intent.request_digest,
            &epoch,
            &process,
            &marker,
            &envelope,
        )
        .unwrap_or_else(|error| panic!("response digest: {error}"));
        let receipt = CredentialAccessReceipt {
            transaction_id: request_value.intent.transaction_id.clone(),
            effect_id: request_value.intent.effect_id.clone(),
            generation: request_value.intent.provision.generation,
            config_digest: request_value.intent.provision.config_digest.clone(),
            target: request_value.intent.provision.target.clone(),
            provider: request_value.intent.provision.provider,
            scope: request_value.intent.provision.scope,
            principal_sid: request_value
                .intent
                .provision
                .expected_principal_sid
                .clone(),
            host_owner_epoch: epoch,
            host_process_identity: process,
            marker,
            credential_envelope_digest: envelope,
            request_digest: request_value.intent.request_digest.clone(),
            response_digest,
        };
        assert!(
            HostCredentialControlResponse::Matching {
                receipt: receipt.clone()
            }
            .validate()
            .is_ok()
        );
        let mut substituted = receipt;
        substituted.host_process_identity = handle("3".repeat(64));
        assert!(
            HostCredentialControlResponse::Matching {
                receipt: substituted
            }
            .validate()
            .is_err()
        );

        let mut short = request(HostCredentialControlOperation::Provision);
        short.ownership_key.pop();
        assert!(short.validate().is_err());
    }

    struct SequenceBackend {
        reads: Mutex<VecDeque<Result<Option<Vec<u8>>, String>>>,
        writes: Mutex<Vec<Vec<u8>>>,
        deletes: Mutex<usize>,
    }

    impl CredentialBackend for SequenceBackend {
        fn principal_sid(&self) -> Result<PlatformHandle, String> {
            Ok(handle(LOCAL_SERVICE_SID))
        }

        fn read(&self, _target: &PlatformHandle) -> Result<Option<CredentialSecret>, String> {
            let value = self
                .reads
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front()
                .unwrap_or(Ok(None))?;
            value
                .map(CredentialSecret::from_bytes)
                .transpose()
                .map_err(|error| error.to_string())
        }

        fn generate(&self) -> Result<CredentialSecret, String> {
            CredentialSecret::from_bytes(vec![3; 32]).map_err(|error| error.to_string())
        }

        fn write_if_absent(
            &self,
            target: &PlatformHandle,
            bytes: Vec<u8>,
        ) -> Result<CredentialSecret, String> {
            match self.read(target)? {
                Some(_) => return Err("credential target already exists".to_owned()),
                None => {}
            }
            // The fake backend models the provider's atomic create-if-absent
            // boundary for the unit race harness; production uses the
            // protected Win32 mutex in HostCredentialMutationCapability.
            match self.read(target)? {
                Some(_) => return Err("credential target already exists".to_owned()),
                None => {}
            }
            self.writes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(bytes.clone());
            self.read(target)?
                .ok_or_else(|| "credential write readback missing".to_owned())
        }

        fn delete_if_matching(
            &self,
            target: &PlatformHandle,
            expected_digest: &PlatformHandle,
            verify: &mut dyn FnMut(&CredentialSecret) -> bool,
        ) -> Result<(), String> {
            if let Some(value) = self.read(target)? {
                if handle_digest(value.expose()).map_err(|error| error.to_string())?
                    != *expected_digest
                    || !verify(&value)
                {
                    return Err("credential identity mismatch".to_owned());
                }
                *self
                    .deletes
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) += 1;
            }
            match self.read(target)? {
                None => Ok(()),
                Some(_) => Err("credential delete readback present".to_owned()),
            }
        }
    }

    #[test]
    fn injected_race_after_second_precheck_never_writes_or_claims_ownership() {
        let backend = SequenceBackend {
            reads: Mutex::new(VecDeque::from([Ok(None), Ok(Some(vec![5; 32]))])),
            writes: Mutex::new(Vec::new()),
            deletes: Mutex::new(0),
        };
        assert!(matches!(backend.read(&provision().target), Ok(None)));
        assert_eq!(
            write_if_absent(&backend, &provision().target, vec![7; 64]).err(),
            Some("credential-target-prewrite-race")
        );
        assert!(
            backend
                .writes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn preexisting_target_is_never_overwritten() {
        let backend = SequenceBackend {
            reads: Mutex::new(VecDeque::from([Ok(Some(vec![5; 32]))])),
            writes: Mutex::new(Vec::new()),
            deletes: Mutex::new(0),
        };
        assert_eq!(
            write_if_absent(&backend, &provision().target, vec![7; 64]).err(),
            Some("credential-target-prewrite-race")
        );
        assert!(
            backend
                .writes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn request_rejects_wrong_sid_and_operation_binding_is_distinct() {
        let provision_intent = request(HostCredentialControlOperation::Provision)
            .intent
            .clone();
        let reconcile_intent = request(HostCredentialControlOperation::Reconcile)
            .intent
            .clone();
        assert_eq!(
            provision_intent.effect_binding_digest,
            reconcile_intent.effect_binding_digest
        );
        assert_ne!(
            provision_intent.request_digest,
            reconcile_intent.request_digest
        );

        let mut wrong = request(HostCredentialControlOperation::Provision);
        wrong.intent.provision.expected_principal_sid = handle("S-1-5-18");
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn delete_restart_after_credential_delete_accepts_only_authoritative_absence() {
        let request = request(HostCredentialControlOperation::Delete);
        let marker = identity();
        let receipt = CredentialAccessReceipt {
            transaction_id: request.intent.transaction_id.clone(),
            effect_id: request.intent.effect_id.clone(),
            generation: request.intent.provision.generation,
            config_digest: request.intent.provision.config_digest.clone(),
            target: request.intent.provision.target.clone(),
            provider: request.intent.provision.provider,
            scope: request.intent.provision.scope,
            principal_sid: request.intent.provision.expected_principal_sid.clone(),
            host_owner_epoch: handle("epoch:one"),
            host_process_identity: handle("1".repeat(64)),
            marker: marker_identity(&marker),
            credential_envelope_digest: handle("2".repeat(64)),
            request_digest: request.intent.request_digest.clone(),
            response_digest: handle("3".repeat(64)),
        };
        let absent = SequenceBackend {
            reads: Mutex::new(VecDeque::from([Ok(None), Ok(None)])),
            writes: Mutex::new(Vec::new()),
            deletes: Mutex::new(0),
        };
        assert_eq!(
            delete_credential_with_readback(
                &absent,
                &request,
                &request.ownership_key,
                &receipt.host_owner_epoch,
                &marker,
                &receipt,
            ),
            Ok(())
        );
        assert_eq!(
            *absent
                .deletes
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            0,
            "a restart after CredDelete must verify absence and must not invent another delete"
        );

        let indeterminate = SequenceBackend {
            reads: Mutex::new(VecDeque::from([Err("cred-read".to_owned())])),
            writes: Mutex::new(Vec::new()),
            deletes: Mutex::new(0),
        };
        assert_eq!(
            delete_credential_with_readback(
                &indeterminate,
                &request,
                &request.ownership_key,
                &receipt.host_owner_epoch,
                &marker,
                &receipt,
            ),
            Err(())
        );
    }
}
