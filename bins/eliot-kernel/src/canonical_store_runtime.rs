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
use crate::kernel_diagnostics::{
    EntrypointStage, observe_entrypoint_with_detail, observe_terminal_error,
};
#[cfg(windows)]
use eliot_contracts::ResourceGeneration;
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

/// Maps one Store bootstrap/build failure to its stable owner-typed code.
///
/// Only the variant name is emitted; any `String` payload is never logged.
#[cfg(windows)]
fn store_build_error_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "PLATFORM",
        KernelBuildError::Transport(_) => "TRANSPORT",
        KernelBuildError::Runtime(_) => "RUNTIME",
        KernelBuildError::Ors(_) => "ORS",
        KernelBuildError::Core(_) => "CORE",
        KernelBuildError::Service(_) => "SERVICE",
        KernelBuildError::StoreBootstrapRequired => "STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

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
        // F-LOG-KERNEL-2 (#899): bootstrap-requirement request observation.
        // Presence/absence only; no requirement material is emitted.
        if self.store_bootstrap.is_some() {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_requested:present",
            );
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_requested:absent",
            );
        }
        self.store_bootstrap.as_ref()
    }

    #[cfg(windows)]
    pub fn install_store_bootstrap(
        &self,
        handoff: StoreBootstrapHandoff,
    ) -> Result<(), KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): bootstrap validation boundary. One terminal
        // per failed install; exact replay is readback, not a new mutation.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.bootstrap_received",
        );
        if let Err(error) = handoff
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:validation",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        if self.store_bootstrap.as_ref() != Some(&handoff.requirement) {
            let error = KernelBuildError::Service(
                "Store handoff does not match the immutable bootstrap descriptor".to_owned(),
            );
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:mismatch",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        let Ok(mut retained) = self.store_handoff.lock() else {
            let error = KernelBuildError::Service("Store handoff lock poisoned".to_owned());
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:lock",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        };
        if let Some(existing) = retained.as_ref() {
            if existing == &handoff {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.bootstrap_validated:replay",
                );
                return Ok(());
            }
            let error = KernelBuildError::Service(
                "Store bootstrap handoff substitution rejected".to_owned(),
            );
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.bootstrap_rejected:substitution",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        *retained = Some(handoff);
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.bootstrap_validated:accepted",
        );
        Ok(())
    }

    #[cfg(windows)]
    pub async fn connect_canonical_store(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): Store connection boundary. Constructed
        // runtime is not ready; a send is not commit. One terminal per failed
        // connect; early rejection proves not-attempted only for the stage
        // whose ledger establishes it.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.connect_requested",
        );
        if self.canonical_store_claimed.load(Ordering::Acquire) {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:already_claimed",
            );
            let Ok(guard) = self.canonical_store_gateway.lock() else {
                let error = KernelBuildError::Service("store gateway lock poisoned".to_owned());
                observe_terminal_error(store_build_error_code(&error));
                return Err(error);
            };
            let gateway = guard.clone();
            if let Some(gateway) = gateway {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_retained:already_connected",
                );
                return Ok(gateway);
            }
            let error = KernelBuildError::StoreAlreadyConnected;
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:already_connected",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        if let Err(error) = self.claim_canonical_store_slot() {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:slot_claim",
            );
            observe_terminal_error(store_build_error_code(&error));
            return Err(error);
        }
        let result = self.connect_canonical_store_inner(timeout).await;
        match &result {
            Ok(_) => {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connected",
                );
            }
            Err(error) => {
                self.canonical_store_claimed.store(false, Ordering::Release);
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_failed",
                );
                observe_terminal_error(store_build_error_code(error));
            }
        }
        result
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "Store connection phases keep exact route/generation checks in one audited gateway"
    )]
    async fn connect_canonical_store_inner(
        &self,
        timeout: Duration,
    ) -> Result<Arc<KernelStoreGateway>, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): inner connection phases only; the outer
        // `connect_canonical_store` owns the single terminal. No pipe/SID/
        // process/credential material is emitted, only fixed phases plus
        // numeric epoch/generation already held for the route check.
        self.process_gateway.as_ref().ok_or_else(|| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:no_process_authority",
            );
            KernelBuildError::Service(
                "process authority is required before canonical Store attachment".to_owned(),
            )
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.process_authority_present",
        );
        let requirement = self.store_bootstrap.clone().ok_or_else(|| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:no_bootstrap",
            );
            KernelBuildError::StoreBootstrapRequired
        })?;
        let handoff = self
            .store_handoff
            .lock()
            .map_err(|_| KernelBuildError::Service("Store handoff lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_rejected:no_handoff",
                );
                KernelBuildError::StoreBootstrapRequired
            })?;
        if let Err(error) = requirement
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:requirement_invalid",
            );
            return Err(error);
        }
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.requirement_validated",
        );
        let process = &handoff.process_binding.process;
        let observed = observe_named_pipe_peer_process_in_job(
            handoff.process_binding.job.as_str(),
            process.process_id,
        )
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_observation",
            );
            KernelBuildError::Principal(error.to_string())
        })?;
        if observed.process_binding().process_id() != process.process_id
            || observed.process_binding().start_time_100ns() != process.start_time_100ns
            || observed.process_binding().image_path() != process.image_path
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_binding_changed",
            );
            return Err(KernelBuildError::Principal(
                "Store process binding changed before pipe admission".to_owned(),
            ));
        }
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.peer_binding_matched",
        );
        let expectation = NamedPipePeerExpectation::new_with_process_and_job_binding(
            requirement.expected_peer_sid.as_str(),
            requirement.expected_peer_session_id,
            observed,
        )
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:peer_expectation",
            );
            KernelBuildError::Principal(error.to_string())
        })?;
        let transport = NamedPipeTransport::connect_authenticated(
            requirement.canonical_pipe_identity.as_str(),
            timeout,
            &expectation,
        )
        .await
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:transport",
            );
            KernelBuildError::Transport(error)
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.transport_connected",
        );
        let client = EbpCanonicalStoreClient::connect(transport, requirement.clone())
            .await
            .map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.store.connect_rejected:client",
                );
                match error {
                    StoreClientError::Transport(error) | StoreClientError::Contract(error) => {
                        KernelBuildError::Service(error)
                    }
                    StoreClientError::Store(error) => KernelBuildError::Service(error.to_string()),
                }
            })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.client_connected",
        );
        let route_scope = RouteScope::new(STORE_BRIDGE_ROUTE)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let routes = self
            .generation_route_snapshot()
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let route = routes
            .route(&route_scope)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?
            .clone();
        if route.authority_epoch().value() != requirement.authority_epoch().sequence.get()
            || route.active_generation() != requirement.store_generation
            || requirement.route_identity.as_str() != STORE_BRIDGE_ROUTE
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:route_mismatch",
            );
            return Err(KernelBuildError::Core(
                "store bootstrap does not match the active Kernel store route".to_owned(),
            ));
        }
        // Exact route/generation match; only numeric epoch/generation plus
        // the fixed bridge name are emitted.
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            &format!(
                "kernel.store.route_matched:store_bridge:epoch={}:generation={}",
                route.authority_epoch().value(),
                route.active_generation().value()
            ),
        );
        let gateway = Arc::new(KernelStoreGateway::new(
            self.service.clone(),
            Arc::new(client),
            route,
            // I14.21 (#1690): the gateway owns unknown-commit recovery
            // against the composition-retained Kernel ORS handle.
            Some(Arc::clone(&self.generation_gateway.ors)),
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
        )
        .inspect_err(|_| {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.connect_rejected:attach",
            );
        })?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.gateway_attached",
        );
        Ok(gateway)
    }

    pub(crate) fn claim_canonical_store_slot(&self) -> Result<(), KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): slot-claim phase only; the outer connect
        // owns the terminal. No gateway/pipe material is emitted.
        if self
            .canonical_store_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.slot_claimed",
            );
            Ok(())
        } else {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.slot_already_claimed",
            );
            Err(KernelBuildError::StoreAlreadyConnected)
        }
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
    // F-LOG-KERNEL-2 (#899): rebind-identity phase only; no operation/
    // digest/process/job material is emitted, only the fixed match outcome.
    let matched = record.operation_id.as_str() == handoff.operation_id.as_str()
        && record.request_digest == request_digest
        && record.candidate_binding_digest == handoff.candidate_binding_digest
        && record.store_fence == handoff.store_fence
        && record.requirement_digest == requirement_digest
        && record.process_id == handoff.process_binding.process.process_id
        && record.process_start_time_100ns == handoff.process_binding.process.start_time_100ns
        && record.process_image_path == handoff.process_binding.process.image_path
        && record.job_name == handoff.process_binding.job.as_str()
        && record.generation == handoff.generation.value()
        && record.authority_epoch == handoff.authority_epoch.sequence.get();
    if matched {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_record_matched",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_record_mismatched",
        );
    }
    matched
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_committed(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    // F-LOG-KERNEL-2 (#899): committed-readback phase only; exact committed
    // replay is readback, not another mutation.
    let committed =
        store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
            && record.state == eliot_ors::StoreRebindReplayState::Committed
            && record.receipt.as_deref() == Some(request_digest);
    if committed {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_committed",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_not_committed",
        );
    }
    committed
}

#[cfg(windows)]
pub(crate) fn store_rebind_record_is_pending(
    record: &eliot_ors::StoreRebindReplayRecord,
    handoff: &eliot_kernel_service::StoreRebindHandoff,
    request_digest: &str,
    requirement_digest: &str,
) -> bool {
    // F-LOG-KERNEL-2 (#899): pending-uncertainty phase only; a timeout after
    // possible submission stays unknown under the same identity.
    let pending = store_rebind_record_matches(record, handoff, request_digest, requirement_digest)
        && record.state == eliot_ors::StoreRebindReplayState::Pending
        && record.receipt.is_none();
    if pending {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_pending_unknown",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_not_pending",
        );
    }
    pending
}

#[cfg(windows)]
pub(crate) fn store_rebind_receipt_from_ors_record(
    record: &eliot_ors::StoreRebindReplayRecord,
    expected_epoch: &eliot_contracts::EpochId,
) -> Result<eliot_kernel_service::StoreRebindReceipt, KernelBuildError> {
    // F-LOG-KERNEL-2 (#899): committed-receipt validation phases only; stale/
    // foreign receipts never emit success. No record material is emitted.
    if record.state != eliot_ors::StoreRebindReplayState::Committed
        || record.receipt.as_deref() != Some(record.request_digest.as_str())
    {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:not_committed",
        );
        return Err(KernelBuildError::Service(
            "ORS Store rebind record is not an exact committed receipt".to_owned(),
        ));
    }
    if record.authority_epoch != expected_epoch.sequence.get() {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:foreign_epoch",
        );
        return Err(KernelBuildError::Service(
            "ORS Store rebind record epoch does not match the expected lineage sequence".to_owned(),
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
        authority_epoch: expected_epoch.clone(),
        store_fence: record.store_fence.clone(),
    };
    receipt.validate().map_err(|error| {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_receipt_rejected:invalid",
        );
        KernelBuildError::Service(error.to_string())
    })?;
    observe_entrypoint_with_detail(
        EntrypointStage::StoreBootstrap,
        "kernel.store.rebind_receipt_validated",
    );
    Ok(receipt)
}

#[cfg(windows)]
#[allow(clippy::unwrap_used)]
pub(crate) fn is_store_rebind_latest_committed(
    ors: &eliot_ors::RedbRecoveryStore,
    record: &eliot_ors::StoreRebindReplayRecord,
) -> Result<bool, KernelBuildError> {
    // F-LOG-KERNEL-2 (#899): latest-commit phases only; superseded commits
    // never emit success. No record material is emitted.
    let all = ors
        .load_all_store_rebinds()
        .map_err(|e| KernelBuildError::Service(e.to_string()))?;
    let committed: Vec<_> = all
        .iter()
        .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
        .collect();
    if committed.is_empty() {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest:sole",
        );
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
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest_rejected:migration",
        );
        return Err(KernelBuildError::Service(
            "Store rebind legacy commit order requires migration/recovery".to_owned(),
        ));
    }
    let legacy_zeros = committed.iter().filter(|r| r.commit_order == 0).count();
    if legacy_zeros > 1 && record.commit_order == 0 {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_superseded",
        );
        return Ok(false);
    }
    if record.commit_order == 0 {
        let max_order = committed.iter().map(|r| r.commit_order).max().unwrap_or(0);
        if max_order > 0 {
            observe_entrypoint_with_detail(
                EntrypointStage::StoreBootstrap,
                "kernel.store.rebind_superseded",
            );
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
    let is_latest = latest.commit_order == record.commit_order
        && latest.operation_id == record.operation_id
        && latest.request_digest == record.request_digest;
    if is_latest {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_latest",
        );
    } else {
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.store.rebind_superseded",
        );
    }
    Ok(is_latest)
}
