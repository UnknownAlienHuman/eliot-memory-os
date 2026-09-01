//! Authenticated Windows named-pipe listener construction for the Kernel.
//!
//! Traceability: Architecture A2.3, A12.2, A12.3, A13.2;
//! principles ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02.
//! Implementation I1.2, I7.1, I7.3, I7.5, I7.14, I15.2, I2.23.
//!
//! This module creates only authenticated listener instances. Peer/session
//! validation remains in `front_door_session`; this module does not dispatch
//! frames, grant peer-owned authority, widen a DACL, or create an
//! unauthenticated pipe. Semantic dispatch, task completion, and semantic
//! authority remain outside this listener boundary.

#[cfg(windows)]
use super::{KernelBuildError, KernelComposition};
#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
#[cfg(windows)]
use eliot_platform_windows::NamedPipePeerSet;

#[cfg(windows)]
impl KernelComposition {
    /// Binds the authenticated local Windows front door to the current
    /// installation principal.  The returned server must be retained by the
    /// service loop for the lifetime of the accepted connection.
    pub fn bind_authenticated_front_door(&self) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipeServer::create(self.ipc.name(), &expectation)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Binds one additional authenticated Windows front-door instance for a
    /// concurrent session while the first instance remains connected.
    pub fn bind_authenticated_front_door_next(&self) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        let expectation = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        NamedPipeServer::create_additional(self.ipc.name(), &expectation)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Binds the first front-door instance using the exact sealed Host,
    /// Eliotd, and promoted bridge peer set.
    pub fn bind_authenticated_front_door_with_peer_set(
        &self,
        peers: &NamedPipePeerSet,
    ) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        NamedPipeServer::create_with_peer_set(self.ipc.name(), peers)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }

    /// Binds one replacement instance using the current immutable peer set.
    pub fn bind_authenticated_front_door_next_with_peer_set(
        &self,
        peers: &NamedPipePeerSet,
    ) -> Result<NamedPipeServer, KernelBuildError> {
        if self
            .generation_poison
            .lock()
            .map_err(|_| KernelBuildError::Principal("generation poison lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Principal(
                "generation gateway fenced; forward recovery is required".to_owned(),
            ));
        }
        NamedPipeServer::create_additional_with_peer_set(self.ipc.name(), peers)
            .map_err(|error| KernelBuildError::Principal(error.to_string()))
    }
}
