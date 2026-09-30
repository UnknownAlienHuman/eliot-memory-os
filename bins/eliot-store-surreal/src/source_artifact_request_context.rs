//! Opaque transport provenance retained for owner-side source artifact work.
//!
//! This is a carrier for facts already admitted by the Store EBP session. It
//! does not create a Blob receipt context, a causal sequence, or source/effect
//! authority. Those bindings must come from their original owners.

use eliot_protocol::{
    Frame, ProtocolModuleGeneration, ProtocolVersion, RequestIdentity, RequestId, StateFence,
};
use eliot_store_api::{ExactJsonBytes, Request, decode_request_frame_with_authority};
use std::collections::BTreeSet;

/// Authenticated Store session identity retained after request admission.
///
/// The fields stay private so downstream code cannot replace the transport
/// peer, process generation, or fence after validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedStoreSessionProjection {
    connection_id: String,
    protocol_version: ProtocolVersion,
    module_generation: ProtocolModuleGeneration,
    state_fence: StateFence,
    session_principal_binding: String,
    authenticated_peer_principal_binding: String,
    capabilities: BTreeSet<String>,
}

impl AdmittedStoreSessionProjection {
    /// Captures fields from the live Store session after its peer proof has
    /// been revalidated by the session owner.
    ///
    /// This constructor is crate-private and is not an authority grant.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_store_session_parts(
        connection_id: String,
        protocol_version: ProtocolVersion,
        module_generation: ProtocolModuleGeneration,
        state_fence: StateFence,
        session_principal_binding: String,
        authenticated_peer_principal_binding: String,
        capabilities: BTreeSet<String>,
    ) -> Result<Self, String> {
        if connection_id.trim().is_empty()
            || session_principal_binding.trim().is_empty()
            || authenticated_peer_principal_binding.trim().is_empty()
        {
            return Err("authenticated Store session projection is incomplete".to_owned());
        }
        if module_generation.state_fence != state_fence {
            return Err("Store session projection generation fence mismatch".to_owned());
        }
        Ok(Self {
            connection_id,
            protocol_version,
            module_generation,
            state_fence,
            session_principal_binding,
            authenticated_peer_principal_binding,
            capabilities,
        })
    }

    pub(crate) fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub(crate) const fn module_generation(&self) -> &ProtocolModuleGeneration {
        &self.module_generation
    }

    pub(crate) const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    pub(crate) fn session_principal_binding(&self) -> &str {
        &self.session_principal_binding
    }

    pub(crate) fn authenticated_peer_principal_binding(&self) -> &str {
        &self.authenticated_peer_principal_binding
    }

    /// Reports whether the live session negotiated one exact capability.
    /// This records transport admission only; it does not grant a Blob effect.
    pub(crate) fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(capability)
    }

}

/// Non-serializable proof that this exact request crossed the admitted Store
/// session validator.
///
/// It preserves the original wire identity and opaque authority bytes. It is
/// not itself a Blob authorization, AuthorityBinding, or CausalBinding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedStoreRequestContext {
    request_id: RequestId,
    identity: RequestIdentity,
    payload_authorities: Vec<ExactJsonBytes>,
    session: AdmittedStoreSessionProjection,
}

impl AdmittedStoreRequestContext {
    /// Builds the carrier from the original frame only after the Store
    /// validator has admitted the decoded request and the live session.
    pub(crate) fn from_validated_parts(
        frame: &Frame,
        admitted_request: &Request,
        session: AdmittedStoreSessionProjection,
    ) -> Result<Self, String> {
        let (request_id, identity, decoded_request, payload_authorities) =
            decode_request_frame_with_authority(frame)
                .map_err(|error| format!("re-read validated Store frame: {error}"))?;
        if decoded_request != *admitted_request {
            return Err("validated Store request differs from its original frame".to_owned());
        }
        if identity.request.state_fence != *session.state_fence() {
            return Err("validated Store request fence differs from its session".to_owned());
        }
        if identity.request.metadata.request_id != request_id {
            return Err("validated Store request ID differs from its request metadata".to_owned());
        }
        Ok(Self {
            request_id,
            identity,
            payload_authorities,
            session,
        })
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn identity(&self) -> &RequestIdentity {
        &self.identity
    }

    pub fn payload_authorities(&self) -> &[ExactJsonBytes] {
        &self.payload_authorities
    }

    pub fn session(&self) -> &AdmittedStoreSessionProjection {
        &self.session
    }
}
