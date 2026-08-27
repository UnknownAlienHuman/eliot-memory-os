//! Kernel process configuration and its fail-closed builders.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md :: A13.2. Kernel и failure domains` keeps the
//!   configuration as input to one Kernel lifecycle/failure boundary.
//! - `ELIOT_ARCHITECTURE.md :: A13.5. Bounded resources и Control Reserve`
//!   constrains configuration to the existing bounded control/runtime contour.
//! - `ELIOT_IMPLEMENTATION.md :: I3.9. Configuration layers` and
//!   `Appendix C. Default runtime configuration` keep defaults explicit and
//!   layered, with no hidden environment or provider authority in this type.
//! - `ELIOT_IMPLEMENTATION.md :: P.3. Kernel control boundary` keeps the
//!   resulting configuration at the Kernel boundary; admission and semantics
//!   remain owned by the existing composition modules.

#[cfg(windows)]
use super::SupervisionLeaseAuthorityConfig;
use super::{
    AgentBridgeAdmissionDescriptor, DEFAULT_PIPE_NAME, EliotdLaunchDescriptor,
    EliotdReceiptRootBinding, HostStoreBootstrapRequirement, PathBuf,
};

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
    /// Host/installer-approved `eliotd` child launch contour.  Integrated
    /// startup must inject this explicitly; there is no path or argv default.
    pub daemon_launch: Option<EliotdLaunchDescriptor>,
    /// Independent digest of the Kernel executable advertised in the
    /// daemon's generation snapshot. This is a different artifact domain
    /// from the `eliotd` child executable digest.
    pub kernel_artifact_sha256: Option<String>,
    /// Digest of the exact retained eliotd descriptor file bytes supplied by
    /// Host. This is distinct from the descriptor's internal unsigned digest.
    pub eliotd_descriptor_artifact_sha256: Option<String>,
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
        Self {
            work_root: work_root.into(),
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            store_bootstrap: None,
            daemon_launch: None,
            kernel_artifact_sha256: None,
            eliotd_descriptor_artifact_sha256: None,
            eliotd_receipt_binding: None,
            agent_bridge_admission: None,
            #[cfg(windows)]
            supervision_lease_authority: None,
            #[cfg(windows)]
            require_descriptor_supervision_authority: false,
        }
    }

    /// Injects the Host-approved canonical-store bootstrap requirement.
    #[must_use]
    pub fn with_store_bootstrap(mut self, requirement: HostStoreBootstrapRequirement) -> Self {
        self.store_bootstrap = Some(requirement);
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
        self.daemon_launch = Some(launch);
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

    /// Requires production construction to inject the exact supervision
    /// authority carried by the protected handoff descriptor.
    #[cfg(windows)]
    #[must_use]
    pub fn require_descriptor_supervision_authority(mut self) -> Self {
        self.require_descriptor_supervision_authority = true;
        self
    }
}
