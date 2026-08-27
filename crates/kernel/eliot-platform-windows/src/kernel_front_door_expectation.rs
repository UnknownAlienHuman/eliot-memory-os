//! Inert Kernel front-door expectation and ACL policy.
//!
//! Architecture anchors (eliot-architecture-docs-fa941135): A12.2 and A12.3,
//! with ARCH-AUTH-01, ARCH-SEC-01, and ARCH-SEC-02. This module owns only
//! caller-provided, validated expectation data; it does not create authority,
//! perform a transition, or turn policy text into a semantic result.
//!
//! Implementation anchors (eliot-architecture-docs-fa941135): I2.2, I2.23,
//! I7.5, and I7.14. The constructors preserve the existing fail-closed shape
//! validation for SID, artifact digest, and bounded ACL-mode policy while the
//! connected-pipe proof remains in the root runtime contour.
//!
//! Named-pipe listener/server creation, DACL/ACE construction and validation,
//! handshake/session state, process admission, generic process identity, and
//! tests remain owned by existing root or sibling modules. This module has no
//! Store, Governor, service, or semantic authority.

use crate::{
    NamedPipePeerJobBinding, NamedPipePeerProcessBinding, WindowsAdapterError, valid_sha256_hex,
    valid_sid_text,
};

/// The only DACL contours accepted for the Kernel front door.
///
/// `ServiceOnly` is the exact SY+LS contour used only when the bridge is
/// disabled. `SystemAndLocalServiceWithClient` adds exactly one canonical
/// installed client SID for the dynamic `AgentBridge` process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KernelFrontDoorAclMode {
    ServiceOnly,
    SystemAndLocalServiceWithClient {
        client_sid: String,
    },
    /// Accepts exactly one additional canonical non-service SID.
    SystemAndLocalServiceWithOneClient,
    /// Accepts the bridge-disabled SY+LS contour or exactly one additional
    /// OS-resolved user SID. Eliotd uses this bounded reconnect-safe mode
    /// because it does not own the installed bridge SID.
    SystemAndLocalServiceWithOptionalUserClient,
}
/// Host-carried expectation for proving the live Kernel process at the far
/// end of a client named-pipe connection.
///
/// This is policy input only. The corresponding [`KernelFrontDoorServerProof`]
/// is created from the connected pipe handle and retains the process and
/// executable file handles for the lifetime of the transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelFrontDoorServerExpectation {
    expected_server_sid: String,
    expected_server_session_id: u32,
    expected_kernel_artifact_sha256: String,
    approved_process: Option<NamedPipePeerProcessBinding>,
    approved_job_process: Option<NamedPipePeerJobBinding>,
    acl_mode: KernelFrontDoorAclMode,
}

impl KernelFrontDoorServerExpectation {
    /// Creates an inert front-door server expectation.
    pub fn new(
        expected_server_sid: impl Into<String>,
        expected_server_session_id: u32,
        expected_kernel_artifact_sha256: impl Into<String>,
        acl_mode: KernelFrontDoorAclMode,
    ) -> Result<Self, WindowsAdapterError> {
        let expected_server_sid = expected_server_sid.into();
        let expected_kernel_artifact_sha256 = expected_kernel_artifact_sha256.into();
        if !valid_sid_text(&expected_server_sid)
            || !valid_sha256_hex(&expected_kernel_artifact_sha256)
        {
            return Err(WindowsAdapterError::InvalidInput);
        }
        match &acl_mode {
            KernelFrontDoorAclMode::ServiceOnly
            | KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient
            | KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient => {}
            KernelFrontDoorAclMode::SystemAndLocalServiceWithClient { client_sid } => {
                if !valid_sid_text(client_sid)
                    || matches!(
                        client_sid.as_str(),
                        "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544"
                    )
                {
                    return Err(WindowsAdapterError::InvalidInput);
                }
            }
        }
        Ok(Self {
            expected_server_sid,
            expected_server_session_id,
            expected_kernel_artifact_sha256,
            approved_process: None,
            approved_job_process: None,
            acl_mode,
        })
    }

    /// Adds an exact OS-observed process binding for the Kernel server.
    #[must_use]
    pub fn with_process_binding(mut self, approved_process: NamedPipePeerProcessBinding) -> Self {
        self.approved_process = Some(approved_process);
        self
    }

    /// Adds an exact OS-observed process and Job binding for the Kernel server.
    #[must_use]
    pub fn with_process_and_job_binding(
        mut self,
        approved_process: NamedPipePeerJobBinding,
    ) -> Self {
        self.approved_process = Some(approved_process.process.clone());
        self.approved_job_process = Some(approved_process);
        self
    }

    #[must_use]
    pub fn expected_server_sid(&self) -> &str {
        &self.expected_server_sid
    }

    #[must_use]
    pub const fn expected_server_session_id(&self) -> u32 {
        self.expected_server_session_id
    }

    #[must_use]
    pub fn expected_kernel_artifact_sha256(&self) -> &str {
        &self.expected_kernel_artifact_sha256
    }

    #[must_use]
    pub const fn acl_mode(&self) -> &KernelFrontDoorAclMode {
        &self.acl_mode
    }

    #[must_use]
    pub fn approved_process_binding(&self) -> Option<&NamedPipePeerProcessBinding> {
        self.approved_process.as_ref()
    }

    #[must_use]
    pub fn approved_process_job_binding(&self) -> Option<&NamedPipePeerJobBinding> {
        self.approved_job_process.as_ref()
    }
}
