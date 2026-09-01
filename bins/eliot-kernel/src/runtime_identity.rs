//! Kernel runtime identity derivation.
//!
//! Immutable runtime and launch identity derivation only. Owns exactly
//! `observed_session_principal_binding`, `eliotd_launch_attempt_identity`,
//! `eliotd_operation_id`, `fresh_eliotd_launch_descriptor`, and
//! `stable_owner_principal_digest`.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01 Kernel identity and session binding; ARCH-SEC-02 Authentication and principal binding; ARCH-RES-01 Resource governance
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I1.8 Exact ownership and call paths; I14.15 Kernel launch and recovery identity; I15.2 Principal and Session binding; I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only runtime identity derivation
//! Forbidden authority: must not mint authority, must not own process lifecycle, must not make semantic decisions.
//! Ownership: immutable runtime and launch identity derivation only.

use crate::KernelBuildError;
#[cfg(windows)]
use crate::sha256_hex;
#[cfg(windows)]
use crate::unix_ms;
#[cfg(windows)]
use eliot_kernel_service::EliotdLaunchDescriptor;
#[cfg(windows)]
use eliot_platform::PlatformHandle;
use eliot_process::Generation;
#[cfg(windows)]
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(windows)]
use eliot_platform_windows::current_process_named_pipe_expectation;

#[cfg(windows)]
pub(crate) fn observed_session_principal_binding() -> Result<String, KernelBuildError> {
    let expectation = current_process_named_pipe_expectation()
        .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
    Ok(format!(
        "sid={};session={}",
        expectation.expected_sid(),
        expectation.expected_session_id()
    ))
}

#[cfg(windows)]
pub(crate) fn eliotd_launch_attempt_identity(
    launch: &EliotdLaunchDescriptor,
    kernel_process_id: u32,
    kernel_start_time_100ns: u64,
    kernel_image_path: &str,
) -> Result<String, KernelBuildError> {
    #[derive(Serialize)]
    struct AttemptBinding<'a> {
        authority_epoch: u64,
        generation: u64,
        launch_nonce: &'a str,
        kernel_process_id: u32,
        kernel_start_time_100ns: u64,
        kernel_image_path: &'a str,
    }

    let bytes = serde_json::to_vec(&AttemptBinding {
        authority_epoch: launch.authority_epoch.value(),
        generation: launch.generation.value(),
        launch_nonce: launch.launch_nonce.as_str(),
        kernel_process_id,
        kernel_start_time_100ns,
        kernel_image_path,
    })
    .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(windows)]
pub(crate) fn eliotd_operation_id(
    generation: Generation,
    launch_attempt_identity: &str,
) -> Result<eliot_process::OperationId, KernelBuildError> {
    let short = launch_attempt_identity.get(..16).ok_or_else(|| {
        KernelBuildError::Service("eliotd launch attempt identity is malformed".to_owned())
    })?;
    eliot_process::OperationId::new(format!("eliotd-launch-{}-{short}", generation.get()))
        .map_err(|error| KernelBuildError::Service(error.to_string()))
}

#[cfg(windows)]
pub(crate) fn fresh_eliotd_launch_descriptor(
    previous: &EliotdLaunchDescriptor,
    recovery_attempt: u64,
) -> Result<EliotdLaunchDescriptor, KernelBuildError> {
    previous
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let nonce_material = format!(
        "{}:{}:{}:{}",
        previous.descriptor_sha256,
        previous.launch_nonce.as_str(),
        recovery_attempt,
        unix_ms(),
    );
    let launch_nonce =
        PlatformHandle::new(format!("eliotd:{}", sha256_hex(nonce_material.as_bytes())))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let mut next = previous.clone();
    next.launch_nonce = launch_nonce.clone();
    if next.arguments.len() != 8 {
        return Err(KernelBuildError::Service(
            "eliotd launch descriptor has a non-canonical argv contour".to_owned(),
        ));
    }
    next.arguments[5] = launch_nonce;
    next.with_computed_digest()
        .map_err(|error| KernelBuildError::Service(error.to_string()))
}

pub(crate) fn stable_owner_principal_digest(
    stable_sid: &str,
    module_id: &str,
    authority_epoch: u64,
    generation: Generation,
) -> String {
    let mut principal = Sha256::new();
    principal.update(stable_sid.as_bytes());
    principal.update(module_id.as_bytes());
    principal.update(authority_epoch.to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    format!("{:x}", Sha256::digest(principal.finalize()))
}
