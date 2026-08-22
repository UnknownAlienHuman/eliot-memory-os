//! Secret-free durable contract for `LocalService` Store credential provisioning.

use eliot_contracts::ResourceGeneration;
use eliot_ipc::TransportError;
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_runtime_contracts::ProvisionedSupervisionAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{InstallationError, handle, handles, sha256_handle, sha256_hex};

/// Stable one-shot Host credential-control wire.
///
/// Version two adds the transaction-bound Phase-B handoff operation.  The
/// wire is intentionally bumped instead of accepting a serde-defaulted
/// optional operation on the v1 endpoint.
pub const HOST_CREDENTIAL_CONTROL_WIRE: &str = "eliot.host.store-credential.v2";

/// Static, secret-free Phase-B authority constraint retained by the
/// installation transaction.  Host overlays its live epoch, state fence,
/// process nonce and dispatch-secret reference; the installer never authors
/// the final `ProcessAuthorityHandoffDescriptor` bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseBStaticTemplate {
    /// Explicit template discriminator.
    pub wire: PlatformHandle,
    /// Stable process-authority identity selected for this generation.
    pub authority_id: PlatformHandle,
    /// Stable ORS record identity selected for this generation.
    pub record_id: PlatformHandle,
    /// Revision-policy binding selected by the generation planner.
    pub revision_policy_binding: PlatformHandle,
    /// Static contour references; Host appends its live contour marker.
    pub contour_refs: Vec<PlatformHandle>,
}

impl HostPhaseBStaticTemplate {
    /// Current static template discriminator.
    pub const WIRE: &'static str = "eliot.host.phase-b-template.v1";

    /// Computes the exact digest bound by the Phase-B transaction intent.
    pub fn digest(&self) -> Result<PlatformHandle, InstallationError> {
        digest_json(self, "phase_b.static_template_digest")
    }

    /// Validates the static template and all required non-empty bindings.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "phase_b.static_template.wire".to_owned(),
                reason: "unsupported static template wire".to_owned(),
            });
        }
        handle(&self.authority_id, "phase_b.static_template.authority_id")?;
        handle(&self.record_id, "phase_b.static_template.record_id")?;
        handle(
            &self.revision_policy_binding,
            "phase_b.static_template.revision_policy_binding",
        )?;
        if self.contour_refs.is_empty() {
            return Err(InstallationError::IncompleteObservation(
                "Phase-B static template requires at least one contour reference".to_owned(),
            ));
        }
        handles(
            &self.contour_refs,
            "phase_b.static_template.contour_refs",
            true,
        )
    }
}

/// Produces the deterministic Phase-A authority constraint for one immutable
/// candidate.  This is the only installer-side template producer; Host still
/// supplies every live epoch, state-fence, marker, expiry, and secret
/// reference before serializing the final descriptor.
pub fn phase_b_static_template_for_candidate(
    candidate: &crate::CandidateManifest,
) -> Result<HostPhaseBStaticTemplate, InstallationError> {
    let manifest_digest = candidate.compute_digest()?;
    let handle = |value: String, field: &'static str| {
        PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
    };
    let template = HostPhaseBStaticTemplate {
        wire: PlatformHandle::new(HostPhaseBStaticTemplate::WIRE).map_err(|error| {
            InstallationError::InvalidField {
                field: "phase_b.static_template.wire".to_owned(),
                reason: error.to_string(),
            }
        })?,
        authority_id: handle(
            format!("eliot-authority:{}", candidate.generation),
            "phase_b.static_template.authority_id",
        )?,
        record_id: handle(
            format!("eliot-ors-record:{manifest_digest}"),
            "phase_b.static_template.record_id",
        )?,
        revision_policy_binding: handle(
            format!("eliot-revision-policy:{}", candidate.generation),
            "phase_b.static_template.revision_policy_binding",
        )?,
        contour_refs: vec![handle(
            format!("eliot.phase-b.contour.v1:{}", candidate.generation),
            "phase_b.static_template.contour_refs",
        )?],
    };
    template.validate()?;
    Ok(template)
}

/// Transaction/effect-bound Phase-B handoff request.  All digest fields are
/// independent domains: credential receipt, retained Host root, static
/// template, and Watchdog selector cannot substitute for one another.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseBMaterializationIntent {
    /// Explicit Phase-B operation wire.
    pub wire: PlatformHandle,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Distinct Phase-B materialization effect identity.
    pub effect_id: PlatformHandle,
    /// Prior credential effect whose receipt authorizes this Phase-B effect.
    /// This is deliberately distinct from [`Self::effect_id`].
    pub credential_effect_id: PlatformHandle,
    /// Immutable installer plan digest.
    pub installation_plan_digest: PlatformHandle,
    /// Candidate manifest digest.
    pub candidate_manifest_digest: PlatformHandle,
    /// Secret-free Host credential receipt digest.
    pub credential_receipt_digest: PlatformHandle,
    /// Digest of the retained Host state root identity/path domain.
    pub host_state_root_digest: PlatformHandle,
    /// Static authority constraint, never final dynamic descriptor bytes.
    pub static_template: HostPhaseBStaticTemplate,
    /// Digest of the exact static template.
    pub static_template_digest: PlatformHandle,
    /// Digest of the immutable Watchdog selector domain.
    pub watchdog_selector_digest: PlatformHandle,
    /// Exact public receipt of the installer-owned sealed signing-key effect.
    pub provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    /// Digest of these fields excluding itself.
    pub request_digest: PlatformHandle,
}

impl HostPhaseBMaterializationIntent {
    /// Current Phase-B operation wire.
    pub const WIRE: &'static str = "eliot.host.phase-b.v3";

    /// Creates a fully bound Phase-B request from transaction-owned values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: PlatformHandle,
        effect_id: PlatformHandle,
        credential_effect_id: PlatformHandle,
        installation_plan_digest: PlatformHandle,
        candidate_manifest_digest: PlatformHandle,
        credential_receipt_digest: PlatformHandle,
        host_state_root_digest: PlatformHandle,
        static_template: HostPhaseBStaticTemplate,
        watchdog_selector_digest: PlatformHandle,
        provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    ) -> Result<Self, InstallationError> {
        let static_template_digest = static_template.digest()?;
        let mut value = Self {
            wire: PlatformHandle::new(Self::WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "phase_b.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            transaction_id,
            effect_id,
            credential_effect_id,
            installation_plan_digest,
            candidate_manifest_digest,
            credential_receipt_digest,
            host_state_root_digest,
            static_template,
            static_template_digest,
            watchdog_selector_digest,
            provisioned_supervision_authority,
            request_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "phase_b.request_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.request_digest = digest_json(
            &(
                value.wire.as_str(),
                value.transaction_id.as_str(),
                value.effect_id.as_str(),
                value.credential_effect_id.as_str(),
                value.installation_plan_digest.as_str(),
                value.candidate_manifest_digest.as_str(),
                value.credential_receipt_digest.as_str(),
                value.host_state_root_digest.as_str(),
                &value.static_template,
                value.static_template_digest.as_str(),
                value.watchdog_selector_digest.as_str(),
                &value.provisioned_supervision_authority,
            ),
            "phase_b.request_digest",
        )?;
        value.validate()?;
        Ok(value)
    }

    /// Validates every digest domain and recomputes the request identity.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != Self::WIRE {
            return Err(InstallationError::InvalidField {
                field: "phase_b.wire".to_owned(),
                reason: "unsupported Phase-B wire".to_owned(),
            });
        }
        handle(&self.transaction_id, "phase_b.transaction_id")?;
        handle(&self.effect_id, "phase_b.effect_id")?;
        handle(&self.credential_effect_id, "phase_b.credential_effect_id")?;
        sha256_handle(
            &self.installation_plan_digest,
            "phase_b.installation_plan_digest",
        )?;
        sha256_handle(
            &self.candidate_manifest_digest,
            "phase_b.candidate_manifest_digest",
        )?;
        sha256_handle(
            &self.credential_receipt_digest,
            "phase_b.credential_receipt_digest",
        )?;
        sha256_handle(
            &self.host_state_root_digest,
            "phase_b.host_state_root_digest",
        )?;
        self.static_template.validate()?;
        if self.static_template_digest != self.static_template.digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(
            &self.static_template_digest,
            "phase_b.static_template_digest",
        )?;
        sha256_handle(
            &self.watchdog_selector_digest,
            "phase_b.watchdog_selector_digest",
        )?;
        self.provisioned_supervision_authority
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "phase_b.provisioned_supervision_authority".to_owned(),
                reason: error.to_string(),
            })?;
        sha256_handle(&self.request_digest, "phase_b.request_digest")?;
        let expected = digest_json(
            &(
                self.wire.as_str(),
                self.transaction_id.as_str(),
                self.effect_id.as_str(),
                self.credential_effect_id.as_str(),
                self.installation_plan_digest.as_str(),
                self.candidate_manifest_digest.as_str(),
                self.credential_receipt_digest.as_str(),
                self.host_state_root_digest.as_str(),
                &self.static_template,
                self.static_template_digest.as_str(),
                self.watchdog_selector_digest.as_str(),
                &self.provisioned_supervision_authority,
            ),
            "phase_b.request_digest",
        )?;
        if expected != self.request_digest {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Secret-free Host proof returned after Phase-B publication and live
/// activation handoff.  Dynamic descriptor bytes are never returned over the
/// installer pipe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseBMaterializationReceipt {
    /// Transaction/effect binding.
    pub transaction_id: PlatformHandle,
    /// Credential effect identity.
    pub effect_id: PlatformHandle,
    /// Candidate manifest digest.
    pub candidate_manifest_digest: PlatformHandle,
    /// Exact Phase-B request digest that authorized this receipt.
    pub request_digest: PlatformHandle,
    /// Opaque Host owner epoch challenge.
    pub host_owner_epoch: PlatformHandle,
    /// Opaque Host process identity digest.
    pub host_process_identity: PlatformHandle,
    /// Materialized descriptor/config/bootstrap/eliotd digests.
    pub authority_descriptor_digest: PlatformHandle,
    /// Physical Store configuration file digest.
    pub config_file_digest: PlatformHandle,
    /// Physical Store bootstrap descriptor digest.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Physical eliotd descriptor digest.
    pub eliotd_descriptor_digest: PlatformHandle,
    /// Exact public supervision authority retained by the Host receipt.
    pub provisioned_supervision_authority: ProvisionedSupervisionAuthority,
    /// Digest of the complete Host-owned Phase-B receipt.
    pub receipt_digest: PlatformHandle,
}

impl HostPhaseBMaterializationReceipt {
    /// Computes the receipt digest over every receipt field except the digest.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        digest_json(
            &(
                self.transaction_id.as_str(),
                self.effect_id.as_str(),
                self.candidate_manifest_digest.as_str(),
                self.request_digest.as_str(),
                self.host_owner_epoch.as_str(),
                self.host_process_identity.as_str(),
                self.authority_descriptor_digest.as_str(),
                self.config_file_digest.as_str(),
                self.store_bootstrap_descriptor_digest.as_str(),
                self.eliotd_descriptor_digest.as_str(),
                &self.provisioned_supervision_authority,
            ),
            "phase_b.receipt_digest",
        )
    }

    /// Validates the receipt and recomputes its public digest.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "phase_b_receipt.transaction_id")?;
        handle(&self.effect_id, "phase_b_receipt.effect_id")?;
        sha256_handle(
            &self.candidate_manifest_digest,
            "phase_b_receipt.candidate_manifest_digest",
        )?;
        sha256_handle(&self.request_digest, "phase_b_receipt.request_digest")?;
        handle(&self.host_owner_epoch, "phase_b_receipt.host_owner_epoch")?;
        for (value, field) in [
            (
                &self.host_process_identity,
                "phase_b_receipt.host_process_identity",
            ),
            (
                &self.authority_descriptor_digest,
                "phase_b_receipt.authority_descriptor_digest",
            ),
            (
                &self.config_file_digest,
                "phase_b_receipt.config_file_digest",
            ),
            (
                &self.store_bootstrap_descriptor_digest,
                "phase_b_receipt.store_bootstrap_descriptor_digest",
            ),
            (
                &self.eliotd_descriptor_digest,
                "phase_b_receipt.eliotd_descriptor_digest",
            ),
            (&self.receipt_digest, "phase_b_receipt.receipt_digest"),
        ] {
            sha256_handle(value, field)?;
        }
        self.provisioned_supervision_authority
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "phase_b_receipt.provisioned_supervision_authority".to_owned(),
                reason: error.to_string(),
            })?;
        if self.receipt_digest != self.computed_digest()? {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    /// Returns the exact public authority bound by this receipt.
    pub const fn provisioned_supervision_authority(&self) -> &ProvisionedSupervisionAuthority {
        &self.provisioned_supervision_authority
    }
}

/// Single existing EBP named-pipe family used by Host for one-shot installer
/// credential control. Authority comes from pipe-handle peer proof, not name.
pub const HOST_CREDENTIAL_CONTROL_PIPE: &str = r"\\.\pipe\eliot-host-store-credential-v2";

/// Exact Windows SID of the built-in `LocalService` principal.
pub const LOCAL_SERVICE_SID: &str = "S-1-5-19";

/// Validates the one canonical Credential Manager target admitted for Store.
///
/// The target is an opaque `PlatformHandle` at the wire boundary, but its
/// namespace and unpredictable token are part of the installation authority.
/// Callers must compare the exact validated value; no target may be derived,
/// defaulted or substituted at runtime.
pub fn validate_store_credential_target(value: &str) -> Result<(), String> {
    let target_token = value.strip_prefix("eliot/store/v1/");
    if target_token.is_none_or(|token| {
        token.len() != 32
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err("must be an unpredictable reserved Store credential target".to_owned());
    }
    Ok(())
}

/// Derives the one transaction-owned dispatch-secret locator from the exact
/// Store locator.  It is a distinct digest domain, so a Store config digest,
/// watchdog selector, or destination path cannot be substituted as the
/// Kernel dispatch key.
pub fn dispatch_credential_target_for_store_target(
    store_target: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    validate_store_credential_target(store_target.as_str()).map_err(|reason| {
        InstallationError::InvalidField {
            field: "credential.target".to_owned(),
            reason,
        }
    })?;
    let digest = sha256_hex(
        format!(
            "eliot.dispatch-credential-target.v1\0{}",
            store_target.as_str()
        )
        .as_bytes(),
    );
    PlatformHandle::new(format!("eliot/dispatch/v1/{}", &digest[..32])).map_err(|error| {
        InstallationError::InvalidField {
            field: "credential.dispatch_target".to_owned(),
            reason: error.to_string(),
        }
    })
}

/// Computes the exact Host-state-root binding used by a Phase-B intent.
pub fn phase_b_host_state_root_digest(
    candidate: &crate::CandidateManifest,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            "eliot.phase-b.host-root.v1",
            candidate
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        "phase_b.host_state_root_digest",
    )
}

/// Computes the exact immutable Watchdog selector binding used by a Phase-B
/// intent. It is deliberately a separate digest domain from the Host root.
pub fn phase_b_watchdog_selector_digest(
    candidate: &crate::CandidateManifest,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            "eliot.phase-b.watchdog-selector.v1",
            candidate.generation.as_str(),
            candidate.runtime_launch.watchdog_executable_path.as_str(),
            candidate.runtime_launch.watchdog_artifact_digest.as_str(),
        ),
        "phase_b.watchdog_selector_digest",
    )
}

/// Computes the independent credential-receipt digest bound by a Phase-B
/// intent. A receipt cannot be substituted with a Store config or selector
/// digest.
pub fn phase_b_credential_receipt_digest(
    receipt: &CredentialAccessReceipt,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(receipt, "phase_b.credential_receipt_digest")
}

/// Credential provider admitted for the production Store process.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialProvider {
    /// Current-token Windows Credential Manager.
    WindowsCredentialManager,
}

/// OS principal scope which owns the credential and performs every readback.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialScope {
    /// The built-in `LocalService` account (`S-1-5-19`).
    LocalService,
}

/// Immutable Store credential effect payload retained by the installation plan.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialProvisionPlan {
    /// Exact protected Host state root containing the non-secret ownership marker.
    pub host_state_root: PlatformHandle,
    /// Exact canonical `EliotHost` executable registered with SCM.
    pub expected_host_executable: PlatformHandle,
    /// Unpredictable Credential Manager target; never credential bytes.
    ///
    /// It must remain unavailable to other `LocalService` processes until the
    /// exact authenticated Host request. `WinCred` has no create-only write, so
    /// this non-public target plus the create-new marker is the final race
    /// trust boundary; any observed target is rejected and never overwritten.
    pub target: PlatformHandle,
    /// Exact provider implementation.
    pub provider: StoreCredentialProvider,
    /// Exact token scope.
    pub scope: StoreCredentialScope,
    /// Exact principal SID required at Host and Store readback.
    pub expected_principal_sid: PlatformHandle,
    /// Store generation receiving the credential reference.
    pub generation: ResourceGeneration,
    /// Digest of the exact Store configuration, never its secret.
    pub config_digest: PlatformHandle,
}

impl StoreCredentialProvisionPlan {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.host_state_root, "credential.host_state_root")?;
        handle(
            &self.expected_host_executable,
            "credential.expected_host_executable",
        )?;
        if !std::path::Path::new(self.expected_host_executable.as_str()).is_absolute() {
            return Err(InstallationError::InvalidField {
                field: "credential.expected_host_executable".to_owned(),
                reason: "must be an absolute canonical path".to_owned(),
            });
        }
        handle(&self.target, "credential.target")?;
        if let Err(reason) = validate_store_credential_target(self.target.as_str()) {
            return Err(InstallationError::InvalidField {
                field: "credential.target".to_owned(),
                reason,
            });
        }
        handle(
            &self.expected_principal_sid,
            "credential.expected_principal_sid",
        )?;
        if self.expected_principal_sid.as_str() != LOCAL_SERVICE_SID {
            return Err(InstallationError::ProfileViolation(
                "Store credential provisioning requires exact LocalService SID S-1-5-19".to_owned(),
            ));
        }
        sha256_handle(&self.config_digest, "credential.config_digest")
    }
}

/// Retained identity of the create-new, protected, non-secret ownership marker.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialOwnershipMarkerIdentity {
    /// Digest of the canonical UTF-16 marker path.
    pub canonical_path_digest: PlatformHandle,
    /// NTFS volume serial number.
    pub volume_serial_number: u32,
    /// Stable file index on that volume.
    pub file_index: u64,
    /// Digest of the marker owner, protected DACL and descriptor control.
    pub security_descriptor_digest: PlatformHandle,
}

/// Authoritative Host observation captured before credential intent commit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialAbsentSnapshot {
    /// Exact durable Host owner epoch serving the control endpoint.
    pub host_owner_epoch: PlatformHandle,
    /// Exact live SCM Host PID/start/image identity digest.
    pub host_process_identity: PlatformHandle,
    /// Retained identity of the protected Host state root.
    pub host_state_root: CredentialOwnershipMarkerIdentity,
    /// Canonical path digest of the not-yet-created marker.
    pub marker_path_digest: PlatformHandle,
    /// Explicit marker absence observation.
    pub marker_absent: bool,
    /// Explicit Credential Manager target absence under the same Host token.
    pub target_absent: bool,
}

impl StoreCredentialAbsentSnapshot {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.host_owner_epoch,
            "credential_snapshot.host_owner_epoch",
        )?;
        sha256_handle(
            &self.host_process_identity,
            "credential_snapshot.host_process_identity",
        )?;
        self.host_state_root.validate()?;
        sha256_handle(
            &self.marker_path_digest,
            "credential_snapshot.marker_path_digest",
        )?;
        if !self.marker_absent || !self.target_absent {
            return Err(InstallationError::InvalidField {
                field: "credential_snapshot.absence".to_owned(),
                reason: "marker and credential target must both be authoritatively absent"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl CredentialOwnershipMarkerIdentity {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(
            &self.canonical_path_digest,
            "credential.marker.canonical_path_digest",
        )?;
        if self.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: "credential.marker.file_index".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.security_descriptor_digest,
            "credential.marker.security_descriptor_digest",
        )
    }
}

/// Durable lifecycle of one `LocalService` credential plus its ownership marker.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialLifecycle {
    /// Provision intent exists; no terminal delete intent has been committed.
    Active,
    /// Delete intent was committed before contacting Host.
    DeleteIntentCommitted,
    /// Host acknowledged deletion; authoritative absence is not yet durable.
    DeleteExecuted,
    /// Host proved both target and exact marker absent.
    Deleted,
}

impl StoreCredentialLifecycle {
    pub(crate) const fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::DeleteIntentCommitted)
                | (Self::DeleteIntentCommitted, Self::DeleteExecuted)
                | (Self::DeleteExecuted, Self::Deleted)
        )
    }
}

/// Secret-free receipt issued by the exact authenticated `LocalService` Host.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAccessReceipt {
    /// Installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact credential effect identity.
    pub effect_id: PlatformHandle,
    /// Store generation receiving the credential.
    pub generation: ResourceGeneration,
    /// Store configuration digest.
    pub config_digest: PlatformHandle,
    /// Credential Manager target reference.
    pub target: PlatformHandle,
    /// Exact provider.
    pub provider: StoreCredentialProvider,
    /// Exact `LocalService` scope.
    pub scope: StoreCredentialScope,
    /// Exact `LocalService` SID observed by Host.
    pub principal_sid: PlatformHandle,
    /// Durable Host owner epoch which served the one-shot request.
    pub host_owner_epoch: PlatformHandle,
    /// Exact live SCM Host PID/start/image identity digest.
    pub host_process_identity: PlatformHandle,
    /// Exact create-new marker identity.
    pub marker: CredentialOwnershipMarkerIdentity,
    /// Digest of the complete credential envelope, never credential bytes.
    pub credential_envelope_digest: PlatformHandle,
    /// Digest of the authenticated request.
    pub request_digest: PlatformHandle,
    /// Digest of the response fields excluding this digest.
    pub response_digest: PlatformHandle,
}

impl CredentialAccessReceipt {
    /// Validates the complete secret-free receipt envelope and its response
    /// digest binding. Callers must still compare generation/configuration and
    /// Host epoch fields against their transaction-owned intent.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "credential_receipt.transaction_id")?;
        handle(&self.effect_id, "credential_receipt.effect_id")?;
        sha256_handle(&self.config_digest, "credential_receipt.config_digest")?;
        handle(&self.target, "credential_receipt.target")?;
        if self.provider != StoreCredentialProvider::WindowsCredentialManager {
            return Err(InstallationError::ProfileViolation(
                "credential receipt provider is not Windows Credential Manager".to_owned(),
            ));
        }
        if self.scope != StoreCredentialScope::LocalService {
            return Err(InstallationError::ProfileViolation(
                "credential receipt scope is not LocalService".to_owned(),
            ));
        }
        if self.principal_sid.as_str() != LOCAL_SERVICE_SID {
            return Err(InstallationError::ProfileViolation(
                "credential receipt principal is not LocalService".to_owned(),
            ));
        }
        handle(
            &self.host_owner_epoch,
            "credential_receipt.host_owner_epoch",
        )?;
        sha256_handle(
            &self.host_process_identity,
            "credential_receipt.host_process_identity",
        )?;
        self.marker.validate()?;
        sha256_handle(
            &self.credential_envelope_digest,
            "credential_receipt.credential_envelope_digest",
        )?;
        sha256_handle(&self.request_digest, "credential_receipt.request_digest")?;
        sha256_handle(&self.response_digest, "credential_receipt.response_digest")?;
        let expected = credential_matching_response_digest(
            &self.request_digest,
            &self.host_owner_epoch,
            &self.host_process_identity,
            &self.marker,
            &self.credential_envelope_digest,
        )?;
        if self.response_digest != expected {
            return Err(InstallationError::InvalidField {
                field: "credential_receipt.response_digest".to_owned(),
                reason: "receipt field binding mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns whether this receipt matches the exact credential effect
    /// intent, including provider, scope, generation and target.
    pub fn matches_intent(&self, intent: &HostCredentialControlIntent) -> bool {
        self.transaction_id == intent.transaction_id
            && self.effect_id == intent.effect_id
            && self.generation == intent.provision.generation
            && self.config_digest == intent.provision.config_digest
            && self.target == intent.provision.target
            && self.provider == intent.provision.provider
            && self.scope == intent.provision.scope
            && self.principal_sid == intent.provision.expected_principal_sid
    }
}

/// Durable credential-specific progress owned by one installation effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialProgress {
    /// Intent-before-delete lifecycle.
    pub lifecycle: StoreCredentialLifecycle,
    /// Present only after authenticated Host create/reconcile evidence.
    pub receipt: Option<CredentialAccessReceipt>,
}

/// One Host operation on the credential and its exact ownership marker.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostCredentialControlOperation {
    /// Observe marker/target absence before intent commit.
    Inspect,
    /// Create marker first, then credential, with same-token readback.
    Provision,
    /// Re-read marker and credential after an unknown delivery or restart.
    Reconcile,
    /// Delete credential and marker after durable delete intent.
    Delete,
    /// Materialize the Host-owned Phase-B live overlay after the credential
    /// receipt is durable. This operation never carries final descriptor
    /// bytes or a second transaction identity.
    MaterializePhaseB,
    /// Query-only reconciliation of an already materialized Phase-B contour;
    /// this operation never republishes files or resumes activation.
    ReconcilePhaseB,
}

/// Secret-free part of one authenticated Host credential request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialControlIntent {
    /// Stable wire discriminator.
    pub wire: PlatformHandle,
    /// Requested operation.
    pub operation: HostCredentialControlOperation,
    /// Installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact effect identity.
    pub effect_id: PlatformHandle,
    /// Immutable credential plan.
    pub provision: StoreCredentialProvisionPlan,
    /// Durable installation plan digest.
    pub installation_plan_digest: PlatformHandle,
    /// Operation-independent binding retained by marker and envelope HMACs.
    pub effect_binding_digest: PlatformHandle,
    /// Digest of these fields, excluding itself.
    pub request_digest: PlatformHandle,
}

impl HostCredentialControlIntent {
    /// Creates and binds one exact secret-free Host request.
    pub fn new(
        operation: HostCredentialControlOperation,
        transaction_id: PlatformHandle,
        effect_id: PlatformHandle,
        provision: StoreCredentialProvisionPlan,
        installation_plan_digest: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let effect_binding_digest = digest_json(
            &(
                transaction_id.as_str(),
                effect_id.as_str(),
                &provision,
                installation_plan_digest.as_str(),
            ),
            "host_credential_control.effect_binding_digest",
        )?;
        let mut value = Self {
            wire: PlatformHandle::new(HOST_CREDENTIAL_CONTROL_WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "host_credential_control.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            operation,
            transaction_id,
            effect_id,
            provision,
            installation_plan_digest,
            effect_binding_digest,
            request_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "host_credential_control.request_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.request_digest = PlatformHandle::new(value.computed_digest()?).map_err(|error| {
            InstallationError::InvalidField {
                field: "host_credential_control.request_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        value.validate()?;
        Ok(value)
    }

    fn computed_digest(&self) -> Result<String, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            wire: &'a PlatformHandle,
            operation: HostCredentialControlOperation,
            transaction_id: &'a PlatformHandle,
            effect_id: &'a PlatformHandle,
            provision: &'a StoreCredentialProvisionPlan,
            installation_plan_digest: &'a PlatformHandle,
            effect_binding_digest: &'a PlatformHandle,
        }
        serde_json::to_vec(&DigestInput {
            wire: &self.wire,
            operation: self.operation,
            transaction_id: &self.transaction_id,
            effect_id: &self.effect_id,
            provision: &self.provision,
            installation_plan_digest: &self.installation_plan_digest,
            effect_binding_digest: &self.effect_binding_digest,
        })
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| InstallationError::InvalidField {
            field: "host_credential_control".to_owned(),
            reason: error.to_string(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != HOST_CREDENTIAL_CONTROL_WIRE {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.wire".to_owned(),
                reason: "unsupported wire".to_owned(),
            });
        }
        handle(
            &self.transaction_id,
            "host_credential_control.transaction_id",
        )?;
        handle(&self.effect_id, "host_credential_control.effect_id")?;
        self.provision.validate()?;
        sha256_handle(
            &self.installation_plan_digest,
            "host_credential_control.installation_plan_digest",
        )?;
        sha256_handle(
            &self.effect_binding_digest,
            "host_credential_control.effect_binding_digest",
        )?;
        let expected_binding = digest_json(
            &(
                self.transaction_id.as_str(),
                self.effect_id.as_str(),
                &self.provision,
                self.installation_plan_digest.as_str(),
            ),
            "host_credential_control.effect_binding_digest",
        )?;
        if self.effect_binding_digest != expected_binding {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.effect_binding_digest".to_owned(),
                reason: "effect binding mismatch".to_owned(),
            });
        }
        sha256_handle(
            &self.request_digest,
            "host_credential_control.request_digest",
        )?;
        if self.computed_digest()? != self.request_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.request_digest".to_owned(),
                reason: "request digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

/// Runtime-only one-shot request. `ownership_key` must never be persisted or logged.
///
/// This type deliberately has no `Debug`, `Clone`, `JsonSchema` or durable owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialControlRequest {
    /// Secret-free durable intent.
    pub intent: HostCredentialControlIntent,
    /// 256-bit marker MAC key, present after intent CAS only.
    pub ownership_key: Vec<u8>,
    /// Exact prior receipt required for delete and optionally pinned on retry.
    pub expected_receipt: Option<CredentialAccessReceipt>,
    /// Present only for the transaction-bound Phase-B handoff operation.
    pub phase_b: Option<HostPhaseBMaterializationIntent>,
}

impl HostCredentialControlRequest {
    /// Validates the request without exposing its key.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.intent.validate()?;
        if self.intent.operation == HostCredentialControlOperation::Inspect {
            if !self.ownership_key.is_empty() {
                return Err(InstallationError::InvalidField {
                    field: "host_credential_control.ownership_key".to_owned(),
                    reason: "inspect must not carry ownership key bytes".to_owned(),
                });
            }
        } else if !matches!(
            self.intent.operation,
            HostCredentialControlOperation::MaterializePhaseB
                | HostCredentialControlOperation::ReconcilePhaseB
        ) && self.ownership_key.len() != 32
        {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.ownership_key".to_owned(),
                reason: "mutating/reconcile requests require exactly 256 bits".to_owned(),
            });
        }
        if self.intent.operation == HostCredentialControlOperation::Delete
            && self.expected_receipt.as_ref().is_none_or(|receipt| {
                receipt.validate().is_err() || !receipt.matches_intent(&self.intent)
            })
        {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.expected_receipt".to_owned(),
                reason: "delete requires the exact prior Host receipt".to_owned(),
            });
        }
        if matches!(
            self.intent.operation,
            HostCredentialControlOperation::Inspect | HostCredentialControlOperation::Provision
        ) && self.expected_receipt.is_some()
        {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.expected_receipt".to_owned(),
                reason: "inspect/provision cannot carry a prior receipt".to_owned(),
            });
        }
        if matches!(
            self.intent.operation,
            HostCredentialControlOperation::MaterializePhaseB
                | HostCredentialControlOperation::ReconcilePhaseB
        ) {
            let Some(phase_b) = self.phase_b.as_ref() else {
                return Err(InstallationError::IncompleteObservation(
                    "Phase-B operation requires its typed handoff intent".to_owned(),
                ));
            };
            phase_b.validate()?;
            let credential_receipt_matches =
                self.expected_receipt.as_ref().is_some_and(|receipt| {
                    receipt.validate().is_ok()
                        && receipt.transaction_id == phase_b.transaction_id
                        && receipt.effect_id == phase_b.credential_effect_id
                        && receipt.generation == self.intent.provision.generation
                        && receipt.config_digest == self.intent.provision.config_digest
                        && receipt.target == self.intent.provision.target
                        && receipt.provider == self.intent.provision.provider
                        && receipt.scope == self.intent.provision.scope
                        && receipt.principal_sid == self.intent.provision.expected_principal_sid
                        && phase_b_credential_receipt_digest(receipt)
                            .is_ok_and(|digest| phase_b.credential_receipt_digest == digest)
                });
            if !self.ownership_key.is_empty()
                || !credential_receipt_matches
                || phase_b.transaction_id != self.intent.transaction_id
                || phase_b.effect_id != self.intent.effect_id
                || phase_b.effect_id == phase_b.credential_effect_id
            {
                return Err(InstallationError::IdentityConflict);
            }
        } else if self.phase_b.is_some() {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.phase_b".to_owned(),
                reason: "Phase-B intent is valid only for a Phase-B operation".to_owned(),
            });
        }
        Ok(())
    }
}

impl Drop for HostCredentialControlRequest {
    fn drop(&mut self) {
        self.ownership_key.fill(0);
    }
}

/// Typed response from the authenticated `LocalService` Host endpoint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostCredentialControlResponse {
    /// Marker and target were both absent under the retained Host contour.
    Absent {
        /// Independently observed precondition.
        snapshot: StoreCredentialAbsentSnapshot,
        /// Digest of the exact request and response classification.
        response_digest: PlatformHandle,
    },
    /// Exact marker and credential envelope matched the committed request.
    Matching {
        /// Secret-free exact access receipt.
        receipt: CredentialAccessReceipt,
    },
    /// Host-owned Phase-B publication and activation handoff completed.
    PhaseBReady {
        /// Secret-free dynamic overlay receipt.
        receipt: HostPhaseBMaterializationReceipt,
    },
    /// Credential and marker were both authoritatively absent after delete.
    Deleted {
        /// Digest binding request, Host epoch and both absence observations.
        absence_digest: PlatformHandle,
    },
    /// Host could not safely classify ownership or external state.
    Unknown {
        /// Stable non-secret recovery reference.
        pending_ref: PlatformHandle,
    },
}

impl HostCredentialControlResponse {
    /// Validates typed response fields before the coordinator consumes them.
    pub fn validate(&self) -> Result<(), InstallationError> {
        match self {
            Self::Absent {
                snapshot,
                response_digest,
            } => {
                snapshot.validate()?;
                sha256_handle(response_digest, "host_credential_response.response_digest")
            }
            Self::Matching { receipt } => receipt.validate(),
            Self::PhaseBReady { receipt } => receipt.validate(),
            Self::Deleted { absence_digest } => {
                sha256_handle(absence_digest, "host_credential_response.absence_digest")
            }
            Self::Unknown { pending_ref } => {
                handle(pending_ref, "host_credential_response.pending_ref")
            }
        }
    }
}

/// Binds an absent response to the exact request and independently observed
/// Host snapshot.
pub fn credential_absent_response_digest(
    request_digest: &PlatformHandle,
    snapshot: &StoreCredentialAbsentSnapshot,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(request_digest.as_str(), snapshot, "ABSENT"),
        "credential_absent_response",
    )
}

/// Binds every public matching receipt field that is not already part of the
/// immutable request.
pub fn credential_matching_response_digest(
    request_digest: &PlatformHandle,
    host_owner_epoch: &PlatformHandle,
    host_process_identity: &PlatformHandle,
    marker: &CredentialOwnershipMarkerIdentity,
    credential_envelope_digest: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            request_digest.as_str(),
            host_owner_epoch.as_str(),
            host_process_identity.as_str(),
            marker,
            credential_envelope_digest.as_str(),
            "MATCHING",
        ),
        "credential_matching_response",
    )
}

/// Binds terminal Host absence to the delete request and exact prior marker.
pub fn credential_deleted_response_digest(
    request_digest: &PlatformHandle,
    host_owner_epoch: &PlatformHandle,
    host_process_identity: &PlatformHandle,
    marker: &CredentialOwnershipMarkerIdentity,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            request_digest.as_str(),
            host_owner_epoch.as_str(),
            host_process_identity.as_str(),
            marker,
            "DELETED",
        ),
        "credential_deleted_response",
    )
}

fn digest_json<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| InstallationError::InvalidField {
        field: field.to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: field.to_owned(),
        reason: error.to_string(),
    })
}

/// Encodes one runtime-only credential request after its durable intent exists.
pub fn credential_control_request_frame(
    connection_id: impl Into<String>,
    request: &HostCredentialControlRequest,
) -> Result<Frame, TransportError> {
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    control_frame(
        connection_id.into(),
        MessageType::Start,
        serde_json::to_value(request).map_err(|_| TransportError::SessionFenced)?,
    )
}

/// Decodes one authenticated Host request without logging or cloning its key.
pub fn decode_credential_control_request_frame(
    frame: &Frame,
) -> Result<HostCredentialControlRequest, TransportError> {
    let payload = control_payload(frame, MessageType::Start)?;
    let request: HostCredentialControlRequest =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(request)
}

/// Encodes one secret-free typed Host response.
pub fn credential_control_response_frame(
    connection_id: impl Into<String>,
    response: &HostCredentialControlResponse,
) -> Result<Frame, TransportError> {
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    control_frame(
        connection_id.into(),
        MessageType::Ready,
        serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
    )
}

/// Decodes one authenticated secret-free Host response.
pub fn decode_credential_control_response_frame(
    frame: &Frame,
) -> Result<HostCredentialControlResponse, TransportError> {
    let payload = control_payload(frame, MessageType::Ready)?;
    let response: HostCredentialControlResponse =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(response)
}

fn control_frame(
    connection_id: String,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<Frame, TransportError> {
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id,
        request_id: None,
        kind: FrameKind::Control,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

fn control_payload(
    frame: &Frame,
    message_type: MessageType,
) -> Result<serde_json::Value, TransportError> {
    frame.validate()?;
    if frame.kind != FrameKind::Control
        || frame.message_type != message_type
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(TransportError::SessionFenced);
    };
    Ok(payload.clone())
}

impl StoreCredentialProgress {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
        }
        if self.lifecycle == StoreCredentialLifecycle::Deleted && self.receipt.is_none() {
            return Err(InstallationError::InvalidField {
                field: "credential_progress.receipt".to_owned(),
                reason: "deleted lifecycle requires the exact prior ownership receipt".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn credential_delete_lifecycle_is_strictly_intent_before_effect() {
        assert!(
            StoreCredentialLifecycle::Active
                .can_transition(StoreCredentialLifecycle::DeleteIntentCommitted)
        );
        assert!(
            StoreCredentialLifecycle::DeleteIntentCommitted
                .can_transition(StoreCredentialLifecycle::DeleteExecuted)
        );
        assert!(
            StoreCredentialLifecycle::DeleteExecuted
                .can_transition(StoreCredentialLifecycle::Deleted)
        );
        assert!(
            !StoreCredentialLifecycle::Active
                .can_transition(StoreCredentialLifecycle::DeleteExecuted)
        );
        assert!(
            !StoreCredentialLifecycle::DeleteIntentCommitted
                .can_transition(StoreCredentialLifecycle::Deleted)
        );
        assert!(
            !StoreCredentialLifecycle::Deleted.can_transition(StoreCredentialLifecycle::Active)
        );
    }

    #[test]
    fn phase_b_request_digest_binds_distinct_credential_effect() {
        let template = HostPhaseBStaticTemplate {
            wire: handle(HostPhaseBStaticTemplate::WIRE),
            authority_id: handle("authority:test"),
            record_id: handle("record:test"),
            revision_policy_binding: handle("revision:test"),
            contour_refs: vec![handle("contour:test")],
        };
        let first = HostPhaseBMaterializationIntent::new(
            handle("transaction:test"),
            handle("effect:phase-b"),
            handle("effect:credential-a"),
            handle("a".repeat(64)),
            handle("b".repeat(64)),
            handle("c".repeat(64)),
            handle("d".repeat(64)),
            template.clone(),
            handle("e".repeat(64)),
            crate::test_provisioned_supervision_authority(
                "installation:test",
                "candidate:test",
                ResourceGeneration::genesis(),
            ),
        )
        .unwrap_or_else(|_| unreachable!());
        let second = HostPhaseBMaterializationIntent::new(
            first.transaction_id.clone(),
            first.effect_id.clone(),
            handle("effect:credential-b"),
            first.installation_plan_digest.clone(),
            first.candidate_manifest_digest.clone(),
            first.credential_receipt_digest.clone(),
            first.host_state_root_digest.clone(),
            template,
            first.watchdog_selector_digest.clone(),
            first.provisioned_supervision_authority.clone(),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_ne!(first.credential_effect_id, second.credential_effect_id);
        assert_ne!(first.request_digest, second.request_digest);
        assert!(first.validate().is_ok());
        assert!(second.validate().is_ok());
    }

    #[test]
    fn phase_b_public_receipt_digest_binds_request_and_rejects_stale_digest() {
        let mut receipt = HostPhaseBMaterializationReceipt {
            transaction_id: handle("transaction:test"),
            effect_id: handle("effect:phase-b"),
            candidate_manifest_digest: handle("a".repeat(64)),
            request_digest: handle("b".repeat(64)),
            host_owner_epoch: handle("host-owner:test"),
            host_process_identity: handle("c".repeat(64)),
            authority_descriptor_digest: handle("d".repeat(64)),
            config_file_digest: handle("e".repeat(64)),
            store_bootstrap_descriptor_digest: handle("f".repeat(64)),
            eliotd_descriptor_digest: handle("1".repeat(64)),
            provisioned_supervision_authority: crate::test_provisioned_supervision_authority(
                "installation:test",
                "candidate:test",
                ResourceGeneration::genesis(),
            ),
            receipt_digest: handle("pending"),
        };
        receipt.receipt_digest = receipt.computed_digest().unwrap_or_else(|_| unreachable!());
        assert!(receipt.validate().is_ok());
        receipt.request_digest = handle("2".repeat(64));
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn credential_receipt_validation_rejects_sid_and_response_substitution() {
        let marker = CredentialOwnershipMarkerIdentity {
            canonical_path_digest: handle("a".repeat(64)),
            volume_serial_number: 1,
            file_index: 1,
            security_descriptor_digest: handle("b".repeat(64)),
        };
        let request_digest = handle("c".repeat(64));
        let host_owner_epoch = handle("host-owner:test");
        let host_process_identity = handle("d".repeat(64));
        let credential_envelope_digest = handle("e".repeat(64));
        let response_digest = credential_matching_response_digest(
            &request_digest,
            &host_owner_epoch,
            &host_process_identity,
            &marker,
            &credential_envelope_digest,
        )
        .unwrap_or_else(|_| unreachable!());
        let mut receipt = CredentialAccessReceipt {
            transaction_id: handle("transaction:test"),
            effect_id: handle("effect:credential"),
            generation: ResourceGeneration::genesis(),
            config_digest: handle("f".repeat(64)),
            target: handle("eliot/store/credential/test"),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            principal_sid: handle(LOCAL_SERVICE_SID),
            host_owner_epoch,
            host_process_identity,
            marker,
            credential_envelope_digest,
            request_digest,
            response_digest,
        };
        assert!(receipt.validate().is_ok());
        receipt.principal_sid = handle("S-1-5-18");
        assert!(receipt.validate().is_err());
        receipt.principal_sid = handle(LOCAL_SERVICE_SID);
        receipt.response_digest = handle("1".repeat(64));
        assert!(receipt.validate().is_err());
    }
}
