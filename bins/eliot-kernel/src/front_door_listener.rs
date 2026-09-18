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
fn observe_listener(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "front-door listener observation"
    );
}

#[cfg(windows)]
fn listener_terminal_code(_: &KernelBuildError) -> &'static str {
    "listener_bind_fenced"
}

#[cfg(windows)]
impl KernelComposition {
    /// Binds the authenticated local Windows front door to the current
    /// installation principal.  The returned server must be retained by the
    /// service loop for the lifetime of the accepted connection.
    pub fn bind_authenticated_front_door(&self) -> Result<NamedPipeServer, KernelBuildError> {
        observe_listener("kernel.front_door_listener_create", "attempt");
        let result: Result<NamedPipeServer, KernelBuildError> = (|| {
            if self
                .generation_poison
                .lock()
                .map_err(|_| {
                    KernelBuildError::Principal("generation poison lock poisoned".to_owned())
                })?
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
        })();
        match &result {
            Ok(_) => {
                observe_listener("kernel.front_door_listener_bind", "success");
                observe_listener("kernel.front_door_listener_accept_ready", "success");
            }
            Err(error) => {
                observe_listener("kernel.front_door_listener_create", "fenced");
                super::kernel_diagnostics::observe_terminal_error(listener_terminal_code(error));
            }
        }
        result
    }

    /// Binds one additional authenticated Windows front-door instance for a
    /// concurrent session while the first instance remains connected.
    pub fn bind_authenticated_front_door_next(&self) -> Result<NamedPipeServer, KernelBuildError> {
        observe_listener("kernel.front_door_listener_rotate", "attempt");
        let result: Result<NamedPipeServer, KernelBuildError> = (|| {
            if self
                .generation_poison
                .lock()
                .map_err(|_| {
                    KernelBuildError::Principal("generation poison lock poisoned".to_owned())
                })?
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
        })();
        match &result {
            Ok(_) => {
                observe_listener("kernel.front_door_listener_rotate", "success");
                observe_listener("kernel.front_door_listener_accept_ready", "success");
            }
            Err(error) => {
                observe_listener("kernel.front_door_listener_rotate", "fenced");
                super::kernel_diagnostics::observe_terminal_error(listener_terminal_code(error));
            }
        }
        result
    }

    /// Binds the first front-door instance using the exact sealed Host,
    /// Eliotd, and promoted bridge peer set.
    pub fn bind_authenticated_front_door_with_peer_set(
        &self,
        peers: &NamedPipePeerSet,
    ) -> Result<NamedPipeServer, KernelBuildError> {
        observe_listener("kernel.front_door_listener_bind", "attempt");
        let result: Result<NamedPipeServer, KernelBuildError> = (|| {
            if self
                .generation_poison
                .lock()
                .map_err(|_| {
                    KernelBuildError::Principal("generation poison lock poisoned".to_owned())
                })?
                .is_some()
            {
                return Err(KernelBuildError::Principal(
                    "generation gateway fenced; forward recovery is required".to_owned(),
                ));
            }
            NamedPipeServer::create_with_peer_set(self.ipc.name(), peers)
                .map_err(|error| KernelBuildError::Principal(error.to_string()))
        })();
        match &result {
            Ok(_) => {
                observe_listener("kernel.front_door_listener_bind", "success");
                observe_listener("kernel.front_door_listener_accept_ready", "success");
            }
            Err(error) => {
                observe_listener("kernel.front_door_listener_bind", "fenced");
                super::kernel_diagnostics::observe_terminal_error(listener_terminal_code(error));
            }
        }
        result
    }

    /// Binds one replacement instance using the current immutable peer set.
    pub fn bind_authenticated_front_door_next_with_peer_set(
        &self,
        peers: &NamedPipePeerSet,
    ) -> Result<NamedPipeServer, KernelBuildError> {
        observe_listener("kernel.front_door_listener_rotate", "attempt");
        let result: Result<NamedPipeServer, KernelBuildError> = (|| {
            if self
                .generation_poison
                .lock()
                .map_err(|_| {
                    KernelBuildError::Principal("generation poison lock poisoned".to_owned())
                })?
                .is_some()
            {
                return Err(KernelBuildError::Principal(
                    "generation gateway fenced; forward recovery is required".to_owned(),
                ));
            }
            NamedPipeServer::create_additional_with_peer_set(self.ipc.name(), peers)
                .map_err(|error| KernelBuildError::Principal(error.to_string()))
        })();
        match &result {
            Ok(_) => {
                observe_listener("kernel.front_door_listener_rotate", "success");
                observe_listener("kernel.front_door_listener_accept_ready", "success");
            }
            Err(error) => {
                observe_listener("kernel.front_door_listener_rotate", "fenced");
                super::kernel_diagnostics::observe_terminal_error(listener_terminal_code(error));
            }
        }
        result
    }
}
