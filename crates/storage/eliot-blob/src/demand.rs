//! Canonical `BlobDemand` producer with generation start-or-reuse probing
//! (issue #1969).
//!
//! This module is the Store-owned typed producer adapter the Kernel
//! demand controller calls through: it classifies first-demand signals
//! from the canonical write/store boundary into the closed demand
//! vocabulary and observes generation readiness, integrity, and durable
//! acceptance over an injected [`BlobStoreClient`] handle. It owns no
//! Kernel controller state, spawns no processes, stages no payloads,
//! mints no canonical references, and interprets no semantic admission:
//! the Kernel `BlobStoreController` records outcomes, the Host owns
//! process/generation lifecycle, and per-demand acceptance receipts flow
//! at capture time through the controller's existing receipt path.
//!
//! The probe is async and runs in the caller's async dispatch context;
//! the controller's sync `FnOnce` closure carries only the already
//! observed outcome value (its documented injection pattern). Probe
//! failures surface as typed errors whose display strings are fixed
//! vocabulary — no blob internals, paths, or digests leak into
//! controller diagnostics.
//!
//! Residuals (documented, not solved here): first-demand durability
//! evidence is the service's own recovery-clean + ready observation — no
//! synthetic probe writes are staged, so a staged-probe write with a
//! governed probe context belongs to a future slice; generation
//! first-construction belongs to bridge composition (the existing
//! `BlobRootOwner` claim path) while this adapter observes the injected
//! handle, i.e. the reuse path; the on-demand `eliot-blob.exe` process
//! generation stays a measured I1.2 option owned by Host.

use eliot_blob_api::BlobStoreClient;
use sha2::{Digest, Sha256};

/// Upper bound mirrored from the Kernel manifest contract: inline
/// thresholds above one MiB would silently pull large-payload work into
/// the inline path, and a zero threshold would force everything through
/// the blob path. Out-of-range thresholds fail closed here instead of
/// misclassifying.
pub const INLINE_THRESHOLD_MAX_BYTES: u64 = 1024 * 1024;

/// First-demand signal classified at the canonical write/store boundary.
///
/// Mirrors the Kernel `BlobDemand` vocabulary one-for-one so the call
/// site maps each variant mechanically; this type carries no Kernel
/// dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreBlobDemand {
    /// A non-inline (large-payload) capture request.
    NonInlineCapture,
    /// A recovery path that must read staged blob payloads.
    Recovery,
    /// A garbage-collection reachability scan over blob references.
    GarbageCollection,
}

/// Classifies one capture payload length against the approved inline
/// threshold: payloads above it need the Blob Store, payloads at or
/// below it stay inline and never start the generation. An out-of-range
/// threshold fails closed instead of misclassifying in either direction.
pub fn classify_capture_payload(
    length: u64,
    inline_threshold_bytes: u64,
) -> Result<Option<StoreBlobDemand>, BlobProbeError> {
    if inline_threshold_bytes == 0 || inline_threshold_bytes > INLINE_THRESHOLD_MAX_BYTES {
        return Err(BlobProbeError::InvalidManifest);
    }
    if length > inline_threshold_bytes {
        Ok(Some(StoreBlobDemand::NonInlineCapture))
    } else {
        Ok(None)
    }
}

/// Names an explicit recovery demand: recovery that reads staged blob
/// payloads. Callers name this leg instead of passing a bare flag.
#[must_use]
pub const fn staged_recovery_demand() -> StoreBlobDemand {
    StoreBlobDemand::Recovery
}

/// Names an explicit garbage-collection demand: a reachability scan over
/// blob references. Callers name this leg instead of passing a bare flag.
#[must_use]
pub const fn garbage_collection_demand() -> StoreBlobDemand {
    StoreBlobDemand::GarbageCollection
}

/// Approved blob view carried into the probe.
///
/// Mirrors the Kernel `BlobStoreManifest` identity fields structurally
/// (generation, manifest digest, inline threshold) without depending on
/// the Kernel binary crate. Values travel from the Kernel-validated
/// manifest; this adapter re-checks shape, never approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedBlobView {
    /// Approved generation identity bound by the Host manifest.
    pub generation: String,
    /// Lowercase hex SHA-256 over the exact approved manifest bytes.
    pub manifest_digest: String,
    /// Inline threshold in bytes from the approved manifest.
    pub inline_threshold_bytes: u64,
}

impl ApprovedBlobView {
    /// Validates the view shape (non-blank generation, hex digest).
    /// Approval itself stays with Kernel startup validation.
    pub fn validate(&self) -> Result<(), BlobProbeError> {
        if self.generation.trim().is_empty()
            || self.generation != self.generation.trim()
            || self.generation.chars().any(char::is_control)
        {
            return Err(BlobProbeError::InvalidManifest);
        }
        if !is_lower_sha256(&self.manifest_digest) {
            return Err(BlobProbeError::InvalidManifest);
        }
        Ok(())
    }
}

/// Observed generation probe outcome: the value the controller records.
///
/// Mirrors the Kernel `BlobProbeSuccess` shape structurally so the call
/// site converts field-for-field with no semantic drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobGenerationProbe {
    /// Approved generation identity that answered the probes.
    pub generation: String,
    /// Lowercase hex SHA-256 over the exact observed health bytes.
    pub integrity_digest: String,
}

impl BlobGenerationProbe {
    /// Validates the probe shape (non-empty generation, hex digest).
    pub fn validate(&self) -> Result<(), BlobProbeError> {
        if self.generation.trim().is_empty()
            || self.generation != self.generation.trim()
            || self.generation.chars().any(char::is_control)
        {
            return Err(BlobProbeError::InvalidProbe);
        }
        if !is_lower_sha256(&self.integrity_digest) {
            return Err(BlobProbeError::InvalidProbe);
        }
        Ok(())
    }
}

/// Typed probe failures with fixed-vocabulary display.
///
/// No blob internals, paths, or digests cross into controller
/// diagnostics: every variant renders a stable degraded reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobProbeError {
    /// The approved manifest view failed shape validation.
    InvalidManifest,
    /// The blob client was unreachable or errored.
    Unavailable,
    /// The health report failed its own contract validation.
    InvalidHealth,
    /// The generation is not ready (dimensions carry the detail
    /// server-side; the reason stays fixed here).
    NotReady,
    /// The observed probe outcome failed shape validation.
    InvalidProbe,
}

impl std::fmt::Display for BlobProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidManifest => "blob manifest view is invalid",
            Self::Unavailable => "blob probe unavailable",
            Self::InvalidHealth => "blob health report is invalid",
            Self::NotReady => "blob generation is not ready",
            Self::InvalidProbe => "blob probe outcome is invalid",
        })
    }
}

impl std::error::Error for BlobProbeError {}

/// Observes generation readiness, integrity, and durable acceptance
/// over an injected blob handle.
///
/// Runs the independent health probe, enforces the health contract
/// (ready plus every ownership/containment/permission/recovery/key
/// dimension with an empty degraded list), and binds the exact observed
/// health bytes into the integrity digest. Returns the outcome value
/// the controller records; any failure maps to a fixed-vocabulary
/// [`BlobProbeError`] that degrades only large-payload capture
/// downstream. Stages nothing and constructs no generation: the handle
/// injection is the reuse path, first-construction belongs to bridge
/// composition.
pub async fn probe_blob_generation(
    view: &ApprovedBlobView,
    blob: &impl BlobStoreClient,
) -> Result<BlobGenerationProbe, BlobProbeError> {
    view.validate()?;
    let health = blob
        .health()
        .await
        .map_err(|_| BlobProbeError::Unavailable)?;
    health
        .validate()
        .map_err(|_| BlobProbeError::InvalidHealth)?;
    if !health.ready {
        return Err(BlobProbeError::NotReady);
    }
    let bytes = serde_json::to_vec(&health).map_err(|_| BlobProbeError::InvalidHealth)?;
    let integrity_digest = sha256_hex(&bytes);
    let probe = BlobGenerationProbe {
        generation: view.generation.clone(),
        integrity_digest,
    };
    probe.validate()?;
    Ok(probe)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_blob_api::{
        BlobFuture, BlobGcReceipt, BlobGcRequest, BlobHealth, BlobReachabilityRequest,
        BlobReachabilityView, BlobReadChunk, BlobReadRequest, BlobReadyReceipt, BlobStageRequest,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    const THRESHOLD: u64 = 32 * 1024;

    /// Spins one ready future to completion (mirrors the crate's test
    /// harness: no runtime dependency, futures resolve without parking).
    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Pin::from(Box::new(future));
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn healthy() -> BlobHealth {
        BlobHealth {
            ready: true,
            owner_matches: true,
            containment_proven: true,
            permissions_proven: true,
            recovery_clean: true,
            active_key_available: true,
            root_generation: 3,
            degraded: Vec::new(),
        }
    }

    fn view() -> ApprovedBlobView {
        ApprovedBlobView {
            generation: "blob-gen-approved-1".to_owned(),
            manifest_digest: "a".repeat(64),
            inline_threshold_bytes: THRESHOLD,
        }
    }

    /// Scripted blob double: canned health only, never storage authority.
    struct FakeBlob {
        health: Result<BlobHealth, String>,
    }

    impl BlobStoreClient for FakeBlob {
        fn stage(&self, _request: BlobStageRequest) -> BlobFuture<'_, BlobReadyReceipt> {
            Box::pin(async { Err(eliot_blob_api::BlobError::ProviderUnavailable("fake")) })
        }

        fn read(&self, _request: BlobReadRequest) -> BlobFuture<'_, BlobReadChunk> {
            Box::pin(async { Err(eliot_blob_api::BlobError::ProviderUnavailable("fake")) })
        }

        fn reachability(
            &self,
            _request: BlobReachabilityRequest,
        ) -> BlobFuture<'_, BlobReachabilityView> {
            Box::pin(async { Err(eliot_blob_api::BlobError::ProviderUnavailable("fake")) })
        }

        fn gc(&self, _request: BlobGcRequest) -> BlobFuture<'_, BlobGcReceipt> {
            Box::pin(async { Err(eliot_blob_api::BlobError::ProviderUnavailable("fake")) })
        }

        fn health(&self) -> BlobFuture<'_, BlobHealth> {
            let result = match &self.health {
                Ok(health) => Ok(health.clone()),
                Err(_) => Err(eliot_blob_api::BlobError::ProviderUnavailable("fake")),
            };
            Box::pin(async move { result })
        }
    }

    #[test]
    fn capture_classification_splits_at_the_threshold() {
        assert_eq!(classify_capture_payload(0, THRESHOLD), Ok(None));
        assert_eq!(classify_capture_payload(THRESHOLD, THRESHOLD), Ok(None));
        assert_eq!(
            classify_capture_payload(THRESHOLD + 1, THRESHOLD),
            Ok(Some(StoreBlobDemand::NonInlineCapture))
        );
        assert_eq!(
            classify_capture_payload(u64::MAX, THRESHOLD),
            Ok(Some(StoreBlobDemand::NonInlineCapture))
        );
        assert_eq!(
            classify_capture_payload(1, 0),
            Err(BlobProbeError::InvalidManifest),
            "zero thresholds fail closed instead of forcing blob use"
        );
        assert_eq!(
            classify_capture_payload(1, INLINE_THRESHOLD_MAX_BYTES + 1),
            Err(BlobProbeError::InvalidManifest),
            "over-max thresholds fail closed instead of inlining silently"
        );
        assert_eq!(staged_recovery_demand(), StoreBlobDemand::Recovery);
        assert_eq!(
            garbage_collection_demand(),
            StoreBlobDemand::GarbageCollection
        );
    }

    #[test]
    fn manifest_view_rejects_malformed_identity() {
        let mut bad = view();
        bad.generation = "  ".to_owned();
        assert_eq!(bad.validate(), Err(BlobProbeError::InvalidManifest));
        let mut bad = view();
        bad.manifest_digest = "zz".to_owned();
        assert_eq!(bad.validate(), Err(BlobProbeError::InvalidManifest));
    }

    #[test]
    fn healthy_generation_probes_ready_with_bound_digest() {
        let probe = block_on(probe_blob_generation(
            &view(),
            &FakeBlob {
                health: Ok(healthy()),
            },
        ))
        .expect("healthy generation probes");
        assert_eq!(probe.generation, "blob-gen-approved-1");
        assert!(is_lower_sha256(&probe.integrity_digest));
        let expected = sha256_hex(&serde_json::to_vec(&healthy()).expect("health serializes"));
        assert_eq!(probe.integrity_digest, expected);
    }

    #[test]
    fn probe_failures_map_to_fixed_vocabulary() {
        assert_eq!(
            block_on(probe_blob_generation(
                &view(),
                &FakeBlob {
                    health: Err("down".to_owned())
                }
            )),
            Err(BlobProbeError::Unavailable)
        );
        let mut unready = healthy();
        unready.ready = false;
        unready
            .degraded
            .push("root inspection failed: /secret/path".to_owned());
        assert_eq!(
            block_on(probe_blob_generation(
                &view(),
                &FakeBlob {
                    health: Ok(unready)
                }
            )),
            Err(BlobProbeError::NotReady)
        );
        // Transport text, paths included, never leaks into reasons.
        for error in [
            BlobProbeError::InvalidManifest,
            BlobProbeError::Unavailable,
            BlobProbeError::InvalidHealth,
            BlobProbeError::NotReady,
            BlobProbeError::InvalidProbe,
        ] {
            let text = error.to_string();
            assert!(!text.is_empty() && !text.chars().any(char::is_control));
        }
        // A health report that fails its own contract fails closed here.
        let mut corrupt = healthy();
        corrupt.ready = true;
        corrupt.degraded.push("x".to_owned());
        assert_eq!(
            block_on(probe_blob_generation(
                &view(),
                &FakeBlob {
                    health: Ok(corrupt)
                }
            )),
            Err(BlobProbeError::InvalidHealth)
        );
    }

    #[test]
    fn probe_outcome_rejects_malformed_shape() {
        let probe = BlobGenerationProbe {
            generation: String::new(),
            integrity_digest: "b".repeat(64),
        };
        assert_eq!(probe.validate(), Err(BlobProbeError::InvalidProbe));
        let probe = BlobGenerationProbe {
            generation: "blob-gen-approved-1".to_owned(),
            integrity_digest: "UPPER".to_owned(),
        };
        assert_eq!(probe.validate(), Err(BlobProbeError::InvalidProbe));
    }
}
