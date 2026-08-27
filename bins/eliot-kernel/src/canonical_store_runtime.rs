//! Kernel canonical-store bootstrap and attachment runtime.
//!
//! Architecture: A12.3 One governed write path; A13.2 Kernel and failure domains; ARCH-SEC-02 Authentication and identity; ARCH-RES-01 Resource lifecycle and ownership.
//! Implementation: I1.2 Obligatory processes; I5.1 Canonical store bootstrap; I5.9 Store client attachment; I5.11 Store gateway ownership; I15.3 Store composition binding.
//! Forbidden authority: must not embed raw `SurrealQL`, must not handle credentials, must not claim semantic ownership, must not create a second store writer — forbidden raw `SurrealQL`, credentials, semantic ownership, second store writer.
//! Ordinary module: I2.2 When capability becomes separate crate; I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition` canonical-store bootstrap/attachment closure plus inseparable helper with zero external users.

use super::HostStoreBootstrapRequirement;
use super::KernelBuildError;
use super::KernelComposition;
use super::STORE_BRIDGE_ROUTE;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(windows)]
use super::CanonicalStoreAttachmentTransaction;
#[cfg(windows)]
use super::KernelStoreGateway;
#[cfg(windows)]
use super::StoreBootstrapHandoff;

#[cfg(windows)]
use eliot_ipc::NamedPipeTransport;
#[cfg(windows)]
use eliot_kernel_core::RouteScope;
#[cfg(windows)]
use eliot_kernel_service::{EbpCanonicalStoreClient, StoreClientError};
#[cfg(windows)]
use eliot_platform_windows::{NamedPipePeerExpectation, observe_named_pipe_peer_process_in_job};

#[cfg(windows)]
pub(crate) fn attach_then_retain_canonical_store<'a, T, Attach>(
    gateway: Arc<T>,
    retained: &'a Mutex<Option<Arc<T>>>,
    attach: Attach,
) -> Result<(), KernelBuildError>
where
    T: Send + Sync + 'static,
    Attach: FnOnce(
            Arc<T>,
        )
            -> Result<Box<dyn CanonicalStoreAttachmentTransaction + 'a>, KernelBuildError>
        + 'a,
{
    let process_attachment = attach(Arc::clone(&gateway))?;
    let mut retained = retained
        .lock()
        .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?;
    if retained.is_some() {
        return Err(KernelBuildError::StoreAlreadyConnected);
    }
    *retained = Some(gateway);
    drop(retained);
    process_attachment.commit();
    Ok(())
}

impl KernelComposition {
    #[must_use]
    pub fn store_bootstrap(&self) -> Option<&HostStoreBootstrapRequirement> {
        self.store_bootstrap.as_ref()
    }

    #[cfg(windows)]
    pub fn install_store_bootstrap(
        &self,
        handoff: StoreBootstrapHandoff,
    ) -> Result<(), KernelBuildError> {
        handoff
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            return Err(KernelBuildError::Service(
                "Store handoff does not match the immutable bootstrap descriptor".to_owned(),
            ));
        }
        let mut retained = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?;
        if let Some(existing) = retained.as_ref() {
            if existing == &handoff {
                return Ok(());
            }
            return Err(KernelBuildError::Service(
                "Store bootstrap handoff substitution rejected".to_owned(),
            ));
        }
        *retained = Some(handoff);
        Ok(())
    }

    #[cfg(windows)]
    pub async fn connect_canonical_store(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        if self.canonical_store_claimed.load(Ordering::Acquire) {
            return self
                .canonical_store_gateway
                .lock()
                .map_err(|_| KernelBuildError::Service("store gateway lock poisoned".to_owned()))?
                .clone()
                .ok_or(KernelBuildError::StoreAlreadyConnected);
        }
        self.claim_canonical_store_slot()?;
        let result = self.connect_canonical_store_inner(timeout).await;
        if result.is_err() {
            self.canonical_store_claimed.store(false, Ordering::Release);
        }
        result
    }

    #[cfg(windows)]
    async fn connect_canonical_store_inner(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        let requirement = self
            .store_bootstrap
            .clone()
            .ok_or(KernelBuildError::StoreBootstrapRequired)?;
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelBuildError::StoreBootstrapRequired)?;
        requirement
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let process = &handoff.process_binding.process;
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            process.process_id,
        )
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        if observed.process_binding().process_id() != process.process_id
            || observed.process_binding().start_time_100ns() != process.start_time_100ns
            || observed.process_binding().image_path() != process.image_path
        {
            return Err(KernelBuildError::Principal(
                "Store process binding changed before pipe admission".to_owned(),
            ));
        }
        let expectation = NamedPipePeerExpectation::new_with_process_and_job_binding(
            requirement.expected_peer_sid.as_str(),
            requirement.expected_peer_session_id,
            observed,
        )
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let transport = NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation,
        )
        .await
        .map_err(KernelBuildError::Transport)?;
        let client = EbpCanonicalStoreClient::connect(transport, requirement.clone())
            .await
            .map_err(|error| match error {
                StoreClientError::Transport(error) | StoreClientError::Contract(error) => {
                    KernelBuildError::Service(error)
                }
                StoreClientError::Store(error) => KernelBuildError::Service(error.to_string()),
            })?;
        let route_scope = RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?
            .clone();
        if route.authority_epoch() != requirement.authority_epoch()
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            return Err(KernelBuildError::Core(
                "store bootstrap does not match the active Kernel store route".to_owned(),
            ));
        }
        let gateway = Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            Arc::new(client),
            route,
        ));
        attach_then_retain_canonical_store(
            Arc::clone(&gateway),
            &self.canonical_store_gateway,
            |gateway| {
                self.process_gateway.as_ref().map_or_else(
                    || {
                        struct NoopAttachment;
                        impl CanonicalStoreAttachmentTransaction for NoopAttachment {
                            fn commit(self: Box<Self>) {}
                        }
                        Ok(Box::new(NoopAttachment)
                            as Box<dyn CanonicalStoreAttachmentTransaction>)
                    },
                    |process_gateway| {
                        process_gateway
                            .attach_canonical_store(gateway)
                            .map(|attachment| {
                                Box::new(attachment) as Box<dyn CanonicalStoreAttachmentTransaction>
                            })
                    },
                )
            },
        )?;
        Ok(gateway)
    }

    pub(crate) fn claim_canonical_store_slot(&self) -> Result<(), KernelBuildError> {
        self.canonical_store_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| KernelBuildError::StoreAlreadyConnected)
    }
}
