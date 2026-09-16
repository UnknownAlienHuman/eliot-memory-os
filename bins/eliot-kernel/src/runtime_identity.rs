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
use eliot_contracts::EpochId;
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

/// F-LOG-KERNEL-4 (#903 slice B): runtime-identity derivation observations.
///
/// Observation only, via #895's facade: fixed `kernel.identity.*` event names
/// plus a bounded stable outcome. Never carries SIDs, session identifiers,
/// nonces, image paths, digests, epochs, generations, or owner error strings
/// (I15.4, I15.2, I07.20): only the fact that a derivation boundary was
/// reached and its stable outcome are recorded. Terminal ownership stays with
/// the calling authorities — the composition build, the eliotd launch
/// wrapper, and the daemon lifecycle owners map `KernelBuildError` into their
/// typed terminal codes — so derivation helpers emit no terminal here and one
/// failed operation keeps exactly one terminal record.
fn observe_identity(event: &'static str, outcome: &'static str) {
    use crate::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "runtime identity observation"
    );
}

#[cfg(windows)]
pub(crate) fn observed_session_principal_binding() -> Result<String, KernelBuildError> {
    let expectation = match current_process_named_pipe_expectation() {
        Ok(expectation) => expectation,
        Err(error) => {
            observe_identity("kernel.identity.session_binding_failed", "fenced");
            return Err(KernelBuildError::Principal(error.to_string()));
        }
    };
    observe_identity("kernel.identity.session_binding_observed", "success");
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
        authority_epoch: EpochId,
        generation: u64,
        launch_nonce: &'a str,
        kernel_process_id: u32,
        kernel_start_time_100ns: u64,
        kernel_image_path: &'a str,
    }

    let bytes = match serde_json::to_vec(&AttemptBinding {
        // INTENDED EpochId shape (Split A/B cutover): clone the lineage-aware
        // authority. Integrator resolves order B→A→C.
        authority_epoch: launch.authority_epoch.clone(),
        generation: launch.generation.value(),
        launch_nonce: launch.launch_nonce.as_str(),
        kernel_process_id,
        kernel_start_time_100ns,
        kernel_image_path,
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            observe_identity("kernel.identity.launch_attempt_failed", "rejected");
            return Err(KernelBuildError::Service(error.to_string()));
        }
    };
    observe_identity("kernel.identity.launch_attempt_derived", "success");
    Ok(sha256_hex(&bytes))
}

#[cfg(windows)]
pub(crate) fn eliotd_operation_id(
    generation: Generation,
    launch_attempt_identity: &str,
) -> Result<eliot_process::OperationId, KernelBuildError> {
    let Some(short) = launch_attempt_identity.get(..16) else {
        observe_identity("kernel.identity.operation_rejected", "rejected");
        return Err(KernelBuildError::Service(
            "eliotd launch attempt identity is malformed".to_owned(),
        ));
    };
    match eliot_process::OperationId::new(format!("eliotd-launch-{}-{short}", generation.get())) {
        Ok(operation_id) => {
            observe_identity("kernel.identity.operation_derived", "success");
            Ok(operation_id)
        }
        Err(error) => {
            observe_identity("kernel.identity.operation_rejected", "rejected");
            Err(KernelBuildError::Service(error.to_string()))
        }
    }
}

#[cfg(windows)]
pub(crate) fn fresh_eliotd_launch_descriptor(
    previous: &EliotdLaunchDescriptor,
    recovery_attempt: u64,
) -> Result<EliotdLaunchDescriptor, KernelBuildError> {
    observe_identity("kernel.identity.launch_refresh_requested", "attempt");
    let outcome = fresh_eliotd_launch_descriptor_inner(previous, recovery_attempt);
    if outcome.is_ok() {
        observe_identity("kernel.identity.launch_descriptor_refreshed", "success");
    } else {
        observe_identity("kernel.identity.launch_refresh_failed", "rejected");
    }
    outcome
}

#[cfg(windows)]
fn fresh_eliotd_launch_descriptor_inner(
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
    authority_epoch: &EpochId,
    generation: Generation,
) -> String {
    let mut principal = Sha256::new();
    principal.update(stable_sid.as_bytes());
    principal.update(module_id.as_bytes());
    // Lineage+sequence digest input (T6-E3): canonical lineage spelling plus
    // sequence bytes. No bare-u64 to_le_bytes, no .sequence.get() adapter for
    // comparison, no From<u64>.
    principal.update(authority_epoch.lineage_id.as_str().as_bytes());
    principal.update(authority_epoch.sequence.get().to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    observe_identity("kernel.identity.owner_digest_derived", "success");
    format!("{:x}", Sha256::digest(principal.finalize()))
}

#[cfg(test)]
mod runtime_identity_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903 slice B) focused diagnostics proof: the owner
    //! digest derivation keeps its exact stable output while recording only
    //! a fixed, secret-free observation name.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    fn test_epoch() -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(3).expect("sequence"),
        )
        .expect("epoch")
    }

    #[test]
    fn identity_digest_derivation_is_stable_and_secret_free() {
        // The real derivation runs through the existing caller path: same
        // inputs keep the exact 64-hex digest, distinct principals diverge,
        // and only the fixed event name reaches the sink.
        let generation = Generation::new(1).expect("generation");
        let first = stable_owner_principal_digest(
            "S-1-5-18-sid-canary",
            "testd",
            &test_epoch(),
            generation,
        );
        let second = stable_owner_principal_digest(
            "S-1-5-18-sid-canary",
            "testd",
            &test_epoch(),
            generation,
        );
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "owner digest must stay lowercase hex"
        );
        let other =
            stable_owner_principal_digest("S-1-5-19-other", "testd", &test_epoch(), generation);
        assert_ne!(first, other);

        let text = capture(|| {
            let _ = stable_owner_principal_digest(
                "S-1-5-18-sid-canary",
                "testd",
                &test_epoch(),
                generation,
            );
        });
        assert!(
            text.contains("kernel.identity.owner_digest_derived"),
            "missing diagnostics marker kernel.identity.owner_digest_derived"
        );
        assert!(
            !text.contains("sid-canary"),
            "identity material leaked into diagnostics"
        );
    }
}
