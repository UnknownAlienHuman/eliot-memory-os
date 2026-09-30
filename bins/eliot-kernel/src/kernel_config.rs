//! Kernel process configuration and its fail-closed builders.
//!
//! Architecture traceability:
//! - `A13.2` (`docs/architecture/A13-02-kernel-and-failure-domains.md`) keeps the
//!   configuration as input to one Kernel lifecycle/failure boundary.
//! - `A13.5` (`docs/architecture/A13-05-bounded-resources-and-control-reserve.md`)
//!   constrains configuration to the existing bounded control/runtime contour.
//! - `I3.9` (`docs/architecture/I03-09-configuration-layers.md`) and
//!   `Appendix C. Default runtime configuration` keep defaults explicit and
//!   layered, with no hidden environment or provider authority in this type.
//! - The R1 Kernel runtime layer
//!   (`docs/architecture/I-PREFACE-04-runtime-layer-model.md`) keeps the
//!   resulting configuration at the Kernel boundary; admission and semantics
//!   remain owned by the existing composition modules.

#[cfg(windows)]
use super::SupervisionLeaseAuthorityConfig;
use super::{
    AgentBridgeAdmissionDescriptor, AuditAnchorBinding, AuditSpoolBinding, BlobStoreManifest,
    DEFAULT_PIPE_NAME, EliotdLaunchDescriptor, EliotdReceiptRootBinding,
    HostStoreBootstrapRequirement, PathBuf,
};
use crate::kernel_diagnostics::{EntrypointStage, observe_entrypoint_with_detail};
#[cfg(windows)]
use eliot_installation::InstallationProfile;
use eliot_observability_runtime::RuntimeProfile;
#[cfg(windows)]
use eliot_platform_windows::FileIdentity;
use eliot_runtime_contracts::RestartPolicyV1;

/// Explicit construction input for the Kernel process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Existing absolute `WorkScope` root bound to the platform adapter.
    pub work_root: PathBuf,
    /// Local pipe selected once by the composition root.
    pub pipe_name: String,
    /// Host-approved canonical-store binding. No store gateway is admitted
    /// until this requirement is injected explicitly.
    pub store_bootstrap: Option<HostStoreBootstrapRequirement>,
    /// Host-approved Blob Store manifest (I1.11 step 4). Validated at
    /// startup without starting the blob generation; `None` keeps large
    /// payloads degraded while inline work stays available.
    pub blob_manifest: Option<BlobStoreManifest>,
    /// Host/installer-approved `eliotd` child launch contour.  Integrated
    /// startup must inject this explicitly; there is no path or argv default.
    pub daemon_launch: Option<EliotdLaunchDescriptor>,
    /// Host/installer-admitted restart policy for the Kernel-supervised
    /// `eliotd` child (I14.10 child restart class, I08.12 restart budgets).
    ///
    /// The whole declaration is the shared versioned contract value
    /// (`eliot_runtime_contracts::RestartPolicyV1`), so the declared class and
    /// every one of the eight `RestartIntensityPolicy` numbers arrive from the
    /// approved config/fault profile the operator admitted.  This type declares
    /// no restart intensity of its own: there is no default window, backoff,
    /// jitter, cooldown, healthy-reset or quarantine threshold here, and a
    /// missing declaration is never read as an unlimited budget.
    ///
    /// `None` is the honest fail-closed default.  An absent or unsupported
    /// declaration means the child performs no automatic restart at all and
    /// keeps exactly the authority it was already admitted with, which is the
    /// disposition `eliot_runtime_contracts::restart_policy::dispose_restart_policy`
    /// already defines; composition validates an admitted value and refuses a
    /// declaration this contract does not admit.
    pub daemon_restart_policy: Option<RestartPolicyV1>,
    /// Independent digest of the Kernel executable advertised in the
    /// daemon's generation snapshot. This is a different artifact domain
    /// from the `eliotd` child executable digest.
    pub kernel_artifact_sha256: Option<String>,
    /// Digest of the exact retained eliotd descriptor file bytes supplied by
    /// Host. This is distinct from the descriptor's internal unsigned digest.
    pub eliotd_descriptor_artifact_sha256: Option<String>,
    /// Independent digest of the approved Doctor image injected by Host.
    /// Missing fails closed once the dispatch contour is required; no
    /// in-memory or test signer is fabricated by the production composition.
    pub doctor_artifact_sha256: Option<String>,
    /// Host-injected absolute Doctor executable path, digest-bound to
    /// `doctor_artifact_sha256`. Missing fails closed once the doctor role
    /// is digested; no path is defaulted. Retained for the contour-owned
    /// trigger call-in; the live image digest is re-proved at spawn.
    pub doctor_executable_path: Option<PathBuf>,
    /// Independent digest of the approved Testd image injected by Host.
    pub testd_artifact_sha256: Option<String>,
    /// Independent digest of the approved native worker image injected by Host.
    pub native_worker_artifact_sha256: Option<String>,
    /// Host-injected absolute User Broker executable path, paired with its
    /// installer-approved artifact digest. Missing keeps the User Broker
    /// role out of the front-door peer set.
    pub user_broker_executable_path: Option<PathBuf>,
    /// Installer-approved digest paired with `user_broker_executable_path`.
    pub user_broker_artifact_sha256: Option<String>,
    /// Independent digest of the approved WASM-host image injected by Host
    /// (#1780). Missing fails closed once the WASM grant route is required;
    /// no in-memory or test signer is fabricated by the production
    /// composition.
    pub wasm_host_artifact_sha256: Option<String>,
    /// Host-injected absolute WASM-host executable path, digest-bound to
    /// `wasm_host_artifact_sha256`. Missing fails closed once the WASM grant
    /// route is required; no path is defaulted. Retained for the grant-arm
    /// host-facts call-in; the live image digest is re-proved at launch.
    pub wasm_host_executable_path: Option<PathBuf>,
    /// Host-owned manifest root where the Kernel must publish the eliotd
    /// receipt. This is intentionally separate from `work_root`: integrated
    /// manifests use distinct Kernel and Host state roots.
    pub eliotd_receipt_binding: Option<EliotdReceiptRootBinding>,
    /// Host-approved immutable agent-bridge admission input.  The descriptor
    /// is inert until the Kernel compares it with a live authenticated peer.
    pub agent_bridge_admission: Option<AgentBridgeAdmissionDescriptor>,
    /// Host-approved protected supervision signing authority.  The absence of
    /// this binding keeps the lease surface unavailable; no in-memory or test
    /// signer is fabricated by the production composition.
    #[cfg(windows)]
    pub supervision_lease_authority: Option<SupervisionLeaseAuthorityConfig>,
    /// Exact profile selected by the protected Host launch descriptor. A
    /// supervision key reference is admitted only when its variant matches.
    #[cfg(windows)]
    pub(super) supervision_installation_profile: Option<InstallationProfile>,
    /// Descriptor-retained repository root used only for `PortableDev` keys.
    /// It is never inferred from the current directory or environment.
    #[cfg(windows)]
    pub(super) portable_dev_repository_root: Option<(PathBuf, FileIdentity)>,
    /// Host-owned Watchdog-failure-domain directory receiving the periodic
    /// audit digest anchors (issue #1837; I16.10). `None` keeps the default
    /// sink below the Kernel work root; the sink is always exactly one
    /// directory and the Kernel never creates the foreign one.
    pub audit_anchor_binding: Option<AuditAnchorBinding>,
    /// Loopback `host:port` the bounded `OpenMetrics` endpoint binds, when the
    /// operator admitted one (issue #1841, I16.2).
    ///
    /// `None` is the honest default: samples are still recorded into the shared
    /// registry, but nothing is served, because the Kernel never invents a port
    /// for an operational surface. A non-loopback value is refused at install
    /// rather than narrowed, so this field cannot turn into an off-box endpoint.
    pub metrics_listen: Option<String>,
    /// Host-owned directory receiving the independently persisted audit
    /// spool records (issue #1840; I16.11). `None` keeps the default spool
    /// below the Kernel work root; the Kernel never creates the foreign one.
    pub audit_spool_binding: Option<AuditSpoolBinding>,
    /// Installation profile driving the audit last-resort rule (issue
    /// #1840; I16.2): `system_service` uses the Windows Event Log,
    /// `user_mode`/portable use the control slot. `None` behaves as
    /// portable (slot only), which is safe on every platform.
    pub audit_fallback_profile: Option<RuntimeProfile>,
    /// Production startup must opt into consuming the exact authority receipt
    /// from the already protected process handoff descriptor. Tests and
    /// library-only process-authority compositions do not silently synthesize
    /// this requirement.
    #[cfg(windows)]
    pub(super) require_descriptor_supervision_authority: bool,
}

impl KernelConfig {
    /// Creates the production configuration using the canonical pipe.
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        // F-LOG-KERNEL-2 (#899): candidate construction observation only.
        // No validation, no readiness, no raw work-root/pipe values.
        observe_entrypoint_with_detail(EntrypointStage::LaunchConfig, "kernel.config.candidate");
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            store_bootstrap: None,
            blob_manifest: None,
            daemon_launch: None,
            daemon_restart_policy: None,
            kernel_artifact_sha256: None,
            eliotd_descriptor_artifact_sha256: None,
            doctor_artifact_sha256: None,
            doctor_executable_path: None,
            testd_artifact_sha256: None,
            native_worker_artifact_sha256: None,
            user_broker_executable_path: None,
            user_broker_artifact_sha256: None,
            wasm_host_artifact_sha256: None,
            wasm_host_executable_path: None,
            eliotd_receipt_binding: None,
            agent_bridge_admission: None,
            #[cfg(windows)]
            supervision_lease_authority: None,
            #[cfg(windows)]
            supervision_installation_profile: None,
            #[cfg(windows)]
            portable_dev_repository_root: None,
            audit_anchor_binding: None,
            metrics_listen: None,
            audit_spool_binding: None,
            audit_fallback_profile: None,
            #[cfg(windows)]
            require_descriptor_supervision_authority: false,
        }
    }

    /// Injects the Host-approved canonical-store bootstrap requirement.
    #[must_use]
    pub fn with_store_bootstrap(mut self, requirement: HostStoreBootstrapRequirement) -> Self {
        // F-LOG-KERNEL-2 (#899): bootstrap-requirement injection observation.
        // The requirement itself is retained verbatim; only a fixed phase
        // label is emitted, never raw pipe/connection/credential material.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.config.store_bootstrap_injected",
        );
        self.store_bootstrap = Some(requirement);
        self
    }

    /// Injects the Host-approved Blob Store manifest (I1.11 step 4).
    /// Validation happens at composition assembly without starting the
    /// blob generation; only fixed phase labels are emitted.
    #[must_use]
    pub fn with_blob_manifest(mut self, manifest: BlobStoreManifest) -> Self {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.config.blob_manifest_injected",
        );
        self.blob_manifest = Some(manifest);
        self
    }

    /// Selects the trusted launch-context control pipe for this Kernel
    /// generation. Production Host launch strips inherited overrides before
    /// injecting this value.
    #[must_use]
    pub fn with_pipe_name(mut self, pipe_name: impl Into<String>) -> Self {
        self.pipe_name = pipe_name.into();
        self
    }

    /// Injects the exact approved `eliotd` child launch descriptor.
    #[must_use]
    pub fn with_daemon_launch(mut self, launch: EliotdLaunchDescriptor) -> Self {
        // F-LOG-KERNEL-2 (#899): daemon-launch injection observation only.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.config.daemon_launch_injected",
        );
        self.daemon_launch = Some(launch);
        self
    }

    /// Injects the admitted restart policy for the Kernel-supervised `eliotd`
    /// child (I14.10, I08.12).
    ///
    /// The declaration is retained verbatim and validated during composition
    /// assembly with the shared contract's own validator, so an inconsistent
    /// intensity window, an unusable group declaration or a policy naming a
    /// different child is refused at startup rather than at the first failed
    /// restart.  Calling this is the only way a restart class reaches the
    /// Kernel: leaving it unset admits no automatic restart for the child.
    #[must_use]
    pub fn with_daemon_restart_policy(mut self, policy: RestartPolicyV1) -> Self {
        self.daemon_restart_policy = Some(policy);
        self
    }

    /// Injects the independently approved Kernel executable digest.
    #[must_use]
    pub fn with_kernel_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.kernel_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the Host-verified digest of the exact eliotd descriptor file.
    #[must_use]
    pub fn with_eliotd_descriptor_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.eliotd_descriptor_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the independently approved Doctor executable digest.
    #[must_use]
    pub fn with_doctor_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.doctor_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the Host-approved absolute Doctor executable path bound to
    /// the digested doctor role. No default; missing fails closed.
    #[must_use]
    pub fn with_doctor_executable_path(mut self, path: PathBuf) -> Self {
        self.doctor_executable_path = Some(path);
        self
    }

    /// Injects the independently approved Testd executable digest.
    #[must_use]
    pub fn with_testd_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.testd_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the independently approved native worker executable digest.
    #[must_use]
    pub fn with_native_worker_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.native_worker_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the exact Host-approved User Broker executable path and digest.
    #[must_use]
    pub fn with_user_broker_artifact_binding(
        mut self,
        path: PathBuf,
        digest: impl Into<String>,
    ) -> Self {
        self.user_broker_executable_path = Some(path);
        self.user_broker_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the independently approved WASM-host executable digest (#1780).
    #[must_use]
    pub fn with_wasm_host_artifact_sha256(mut self, digest: impl Into<String>) -> Self {
        self.wasm_host_artifact_sha256 = Some(digest.into());
        self
    }

    /// Injects the Host-approved absolute WASM-host executable path bound to
    /// the digested WASM-host role. No default; missing fails closed.
    #[must_use]
    pub fn with_wasm_host_executable_path(mut self, path: PathBuf) -> Self {
        self.wasm_host_executable_path = Some(path);
        self
    }

    /// Injects the exact Host-owned manifest root for the durable eliotd
    /// receipt. No environment or current-directory fallback is permitted.
    #[must_use]
    pub fn with_eliotd_receipt_binding(mut self, binding: EliotdReceiptRootBinding) -> Self {
        self.eliotd_receipt_binding = Some(binding);
        self
    }

    /// Injects the exact Host-validated agent-bridge admission descriptor.
    #[must_use]
    pub fn with_agent_bridge_admission(
        mut self,
        admission: AgentBridgeAdmissionDescriptor,
    ) -> Self {
        self.agent_bridge_admission = Some(admission);
        self
    }

    /// Injects the Host-approved protected supervision signer and trust
    /// anchor.  The seed itself is intentionally not part of this config.
    #[cfg(windows)]
    #[must_use]
    pub fn with_supervision_lease_authority(
        mut self,
        authority: SupervisionLeaseAuthorityConfig,
    ) -> Self {
        self.supervision_lease_authority = Some(authority);
        self
    }

    /// Injects the exact profile and optional repository root retained from
    /// the Host-approved launch descriptor. `PortableDev` requires the root;
    /// other profiles reject one during authority composition.
    #[cfg(windows)]
    #[must_use]
    pub fn with_supervision_installation_profile(
        mut self,
        profile: InstallationProfile,
        portable_dev_repository_root: Option<(PathBuf, FileIdentity)>,
    ) -> Self {
        self.supervision_installation_profile = Some(profile);
        self.portable_dev_repository_root = portable_dev_repository_root;
        self
    }

    /// Requires production construction to inject the exact supervision
    /// authority carried by the protected handoff descriptor.
    #[cfg(windows)]
    #[must_use]
    pub fn require_descriptor_supervision_authority(mut self) -> Self {
        self.require_descriptor_supervision_authority = true;
        self
    }

    /// Injects the Host-owned Watchdog-domain anchor sink directory.
    /// No default; `None` keeps the sink below the Kernel work root.
    #[must_use]
    pub fn with_audit_anchor_binding(mut self, binding: AuditAnchorBinding) -> Self {
        self.audit_anchor_binding = Some(binding);
        self
    }

    /// Admits the loopback address the bounded `OpenMetrics` endpoint binds
    /// (issue #1841, I16.2).
    ///
    /// The address is an operator/Host admission, not a Kernel default: the
    /// Kernel refuses to invent a port for an operational surface, and
    /// `install_kernel_execution_metrics` refuses a non-loopback value. Passing
    /// the configuration on without calling this leaves the registry populated
    /// and nothing served, which is the state this builder makes explicit.
    #[must_use]
    pub fn with_metrics_listen(mut self, address: impl Into<String>) -> Self {
        self.metrics_listen = Some(address.into());
        self
    }

    /// Injects the Host-owned audit-spool directory.
    /// No default; `None` keeps the spool below the Kernel work root.
    #[must_use]
    pub fn with_audit_spool_binding(mut self, binding: AuditSpoolBinding) -> Self {
        self.audit_spool_binding = Some(binding);
        self
    }

    /// Injects the installation profile for the audit last-resort rule.
    /// No default; `None` behaves as portable (control slot only).
    #[must_use]
    pub fn with_audit_fallback_profile(mut self, profile: RuntimeProfile) -> Self {
        self.audit_fallback_profile = Some(profile);
        self
    }

    /// Returns the effective audit-fallback profile.
    #[must_use]
    pub fn audit_fallback_profile_or_default(&self) -> RuntimeProfile {
        self.audit_fallback_profile
            .unwrap_or(RuntimeProfile::Portable)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_artifact_digests_are_injected_without_defaults() {
        let config = KernelConfig::new(std::path::PathBuf::from("/tmp/work"));
        assert!(config.doctor_artifact_sha256.is_none());
        assert!(config.doctor_executable_path.is_none());
        assert!(config.testd_artifact_sha256.is_none());
        assert!(config.native_worker_artifact_sha256.is_none());
        let doctor_path = std::path::PathBuf::from("/tmp/eliot-doctor.exe");
        let config = config
            .with_doctor_artifact_sha256("a".repeat(64))
            .with_doctor_executable_path(doctor_path.clone())
            .with_testd_artifact_sha256("b".repeat(64))
            .with_native_worker_artifact_sha256("c".repeat(64));
        assert_eq!(
            config.doctor_artifact_sha256,
            Some("a".repeat(64)),
            "doctor digest must be retained exactly"
        );
        assert_eq!(
            config.doctor_executable_path,
            Some(doctor_path),
            "digest-bound doctor path must be retained exactly"
        );
        assert_eq!(
            config.testd_artifact_sha256,
            Some("b".repeat(64)),
            "testd digest must be retained exactly"
        );
        assert_eq!(
            config.native_worker_artifact_sha256,
            Some("c".repeat(64)),
            "native worker digest must be retained exactly"
        );
    }
}
