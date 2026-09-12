//! Kernel canonical-store bootstrap and attachment runtime.
//!
//! Architecture: A12.3 One governed write path; A13.2 Kernel and failure domains; ARCH-SEC-02 Authentication and identity; ARCH-RES-01 Resource lifecycle and ownership.
//! Implementation: I1.2 Obligatory processes; I5.1 Canonical store bootstrap; I5.9 Store client attachment; I5.11 Store gateway ownership; I15.3 Store composition binding.
//! Forbidden authority: must not embed raw `SurrealQL`, must not handle credentials, must not claim semantic ownership, must not create a second store writer — forbidden raw `SurrealQL`, credentials, semantic ownership, second store writer.
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `KernelComposition` canonical-store bootstrap/attachment closure plus inseparable helper with zero external users.
//! Capability cells (§15 req.1): cell 8 canonical-store attachment runtime plus
//! the pure cell 3/6 store-rebind predicates moved here from `lib` without
//! touching the `rebind_store` transaction body, which stays whole in `lib`.

use super::HostStoreBootstrapRequirement;
use super::KernelBuildError;
use super::KernelComposition;
use super::STORE_BRIDGE_ROUTE;
#[cfg(windows)]
use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
#[cfg(windows)]
use eliot_platform::PlatformHandle;
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
        self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required before canonical Store attachment".to_owned(),
            )
        })?;
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
                        Err(KernelBuildError::Service(
                            "process authority is required before canonical Store attachment"
                                .to_owned(),
                        ))
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

/// Pure cell 3/6 store-rebind predicates over `eliot_ors` replay records and
/// `eliot_kernel_service` handoffs. No `self`, no composition privates; the
/// `rebind_store` transaction body stays whole in `lib`.
#[cfg(windows)]
pub(crate) fn store_rebind_record_matches(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    record.operation_id.as_str() == handoff.operation_id.as_str()
        && record.request_digest == request_digest
        && record.candidate_binding_digest == handoff.candidate_binding_digest
        && record.store_fence == handoff.store_fence
        && record.requirement_digest == requirement_digest
        && record.process_id == handoff.process_binding.process.process_id
        && record.process_start_time_100ns == handoff.process_binding.process.start_time_100ns
        && record.process_image_path == handoff.process_binding.process.image_path
        && record.job_name == handoff.process_binding.job.as_str()
        && record.generation == handoff.generation.value()
        && record.authority_epoch == handoff.authority_epoch.value()
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_committed(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Committed
        && record.receipt.as_deref() == Some(request_digest)
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_pending(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Pending
        && record.receipt.is_none()
}

#[cfg(windows)]
pub(crate) fn store_rebind_receipt_from_ors_record(
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
    if record.state != eliot_ors::StoreRebindReplayState::Committed
        || record.receipt.as_deref() != Some(record.request_digest.as_str())
    {
        return Err(KernelBuildError::Service(
            "ORS Store rebind record is not an exact committed receipt".to_owned(),
        ));
    }
    let receipt = eliot_kernel_service::StoreRebindReceipt {
        operation_id: PlatformHandle::new(record.operation_id.as_str())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        request_digest: record.request_digest.clone(),
        requirement_digest: record.requirement_digest.clone(),
        process_binding: eliot_kernel_service::StoreProcessBinding {
            process: eliot_kernel_service::HostProcessBinding {
                process_id: record.process_id,
                start_time_100ns: record.process_start_time_100ns,
                image_path: record.process_image_path.clone(),
            },
            job: PlatformHandle::new(record.job_name.clone())
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        },
        candidate_binding_digest: record.candidate_binding_digest.clone(),
        generation: ResourceGeneration::new(record.generation)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        authority_epoch: AuthorityEpoch::new(record.authority_epoch)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        store_fence: record.store_fence.clone(),
    };
    receipt
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(receipt)
}

#[cfg(windows)]
#[allow(clippy::unwrap_used)]
pub(crate) fn is_store_rebind_latest_committed(
    ors: &eliot_ors::RedbRecoveryStore,
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<bool, KernelBuildError> {
    let all = ors
        .load_all_store_rebinds()
        .map_err(|e| KernelBuildError::Service(e.to_string()))?;
    let committed: Vec<_> = all
        .iter()
        .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
        .collect();
    if committed.is_empty() {
        return Ok(true);
    }
    let same_lineage_zeros = committed
        .iter()
        .filter(|r| {
            r.commit_order == 0
                && r.requirement_digest == record.requirement_digest
                && r.generation == record.generation
                && r.authority_epoch == record.authority_epoch
        })
        .count();
    if same_lineage_zeros > 1 {
        return Err(KernelBuildError::Service(
            "Store rebind legacy commit order requires migration/recovery".to_owned(),
        ));
    }
    let legacy_zeros = committed.iter().filter(|r| r.commit_order == 0).count();
    if legacy_zeros > 1 && record.commit_order == 0 {
        return Ok(false);
    }
    if record.commit_order == 0 {
        let max_order = committed.iter().map(|r| r.commit_order).max().unwrap_or(0);
        if max_order > 0 {
            return Ok(false);
        }
    }
    let latest = committed
        .iter()
        .max_by_key(|r| {
            (
                r.commit_order,
                r.operation_id.as_str().to_owned(),
                r.request_digest.clone(),
            )
        })
        .unwrap();
    Ok(latest.commit_order == record.commit_order
        && latest.operation_id == record.operation_id
        && latest.request_digest == record.request_digest)
}
