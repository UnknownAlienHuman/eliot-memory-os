//! Kernel Blob Store demand-startup controller (I1.11 step 4; I5.12; I1.2 §6).
//!
//! Architecture: A13.2 Kernel and failure domains (Kernel owns the logical
//! lifecycle of the blob generation); A2.3 micro-modularity (one causal
//! responsibility: demand-gated blob generation lifecycle plus canonical
//! `BlobRef` integrity).
//! Implementation: I1.11 Startup algorithm step 4 (validate the approved Blob
//! Store manifest at startup, start the blob generation only on the first
//! non-inline capture, recovery or GC demand; a failed probe degrades only
//! large-payload capture and never fabricates a canonical `BlobRef`);
//! I5.12 Blob Store (canonical `BlobRef`/`BlobReadyReceipt` only after durable
//! acceptance); I1.2 §6 BlobStore capability (one data-root owner).
//! Health reading: I1.10 (READY only for capabilities whose dimensions pass);
//! failure containment: I14.24 (blob unavailable → limit large capture, small
//! inline work may continue).
//!
//! Ordinary module: I2.23 single-file extraction (<10k LOC) owning only the
//! Kernel-side demand/probe/record state plus the closed `BlobRef` mint. No
//! process is spawned here: the caller injects the approved-generation
//! start-or-reuse plus readiness/integrity probe outcome as a value, and this
//! controller records it. Blob bytes, CAS layout, encryption, GC reachability,
//! and canonical-store semantics stay with their declared owners.
//! Forbidden authority: must not spawn native processes, must not mint a
//! canonical `BlobRef` without a validated Ready generation plus a durable
//! `BlobReadyReceipt`, must not widen inline work or unrelated canonical work
//! on blob failure.
//!
//! Capability cell (§15 req.1): cell 8 process/daemon/store runtime (blob
//! generation lifecycle), read through the cell 7 health view vocabulary.

use std::path::PathBuf;

use crate::kernel_diagnostics::{observe_entrypoint_with_detail, EntrypointStage};

/// Default inline threshold (I5.12): payloads at or below this size stay
/// inline and never require the Blob Store.
pub const BLOB_INLINE_THRESHOLD_DEFAULT_BYTES: u64 = 32 * 1024;

/// Upper bound for an admissible inline threshold: one MiB. A larger value
/// would silently pull large-payload work into the inline path.
pub const BLOB_INLINE_THRESHOLD_MAX_BYTES: u64 = 1024 * 1024;

/// Supported Blob Store manifest format version. Bumped only by an explicit
/// contract change, never by delivery depth.
pub const BLOB_MANIFEST_FORMAT_VERSION: u32 = 1;

/// Approved Blob Store manifest validated at Kernel startup (I1.11 step 4).
///
/// The manifest identifies the one approved data-root owner plus the exact
/// expected manifest digest. Validation proves shape approval only; it never
/// starts the blob generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStoreManifest {
    /// The single approved blob data root (one data-root owner, I1.2 §6).
    pub data_root: PathBuf,
    /// Lowercase hex SHA-256 over the exact approved manifest bytes.
    pub manifest_digest: String,
    /// Manifest format version; must equal [`BLOB_MANIFEST_FORMAT_VERSION`].
    pub format_version: u32,
    /// Inline threshold in bytes; payloads above it are non-inline (I5.12).
    pub inline_threshold_bytes: u64,
    /// Approved generation identity bound by the Host manifest.
    pub approved_generation: String,
}

impl BlobStoreManifest {
    /// Validates the approved manifest shape without starting any process.
    pub fn validate(&self) -> Result<(), String> {
        if !self.data_root.is_absolute()
            || self.data_root.as_os_str().is_empty()
            || self
                .data_root
                .to_string_lossy()
                .chars()
                .any(char::is_control)
        {
            return Err("blob manifest data root must be an absolute control-free path".to_owned());
        }
        if !is_lower_sha256(&self.manifest_digest) {
            return Err("blob manifest digest must be lowercase SHA-256".to_owned());
        }
        if self.format_version != BLOB_MANIFEST_FORMAT_VERSION {
            return Err("blob manifest format version is not supported".to_owned());
        }
        if self.inline_threshold_bytes == 0
            || self.inline_threshold_bytes > BLOB_INLINE_THRESHOLD_MAX_BYTES
        {
            return Err("blob manifest inline threshold is out of range".to_owned());
        }
        if self.approved_generation.trim().is_empty()
            || self.approved_generation != self.approved_generation.trim()
            || self.approved_generation.chars().any(char::is_control)
        {
            return Err(
                "blob manifest approved generation is empty or contains control".to_owned(),
            );
        }
        Ok(())
    }
}

/// Explicit first-demand signal (I1.11 step 4): only non-inline capture,
/// recovery, or GC may start the blob generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobDemand {
    /// A non-inline (large-payload) capture request.
    NonInlineCapture,
    /// A recovery path that must read staged blob payloads.
    Recovery,
    /// A garbage-collection reachability scan over blob references.
    GarbageCollection,
}

/// Readiness plus integrity probe outcome for the approved blob generation.
///
/// The caller performs the independent readiness and integrity probes and
/// passes the outcome value in; this controller only records it. `Ready`
/// proves the approved generation accepted durable storage under the exact
/// manifest identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobProbeSuccess {
    /// Approved generation identity that answered the probes.
    pub generation: String,
    /// Lowercase hex SHA-256 integrity digest reported by the probe.
    pub integrity_digest: String,
}

impl BlobProbeSuccess {
    /// Validates the probe success shape (non-empty generation, hex digest).
    pub fn validate(&self) -> Result<(), String> {
        if self.generation.trim().is_empty()
            || self.generation != self.generation.trim()
            || self.generation.chars().any(char::is_control)
        {
            return Err("blob probe generation is empty or contains control".to_owned());
        }
        if !is_lower_sha256(&self.integrity_digest) {
            return Err("blob probe integrity digest must be lowercase SHA-256".to_owned());
        }
        Ok(())
    }
}

/// Durable-storage acceptance receipt (I5.12): proves the validated blob
/// generation durably accepted the exact payload. Only this receipt plus a
/// `Ready` controller may yield a canonical [`BlobRef`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadyReceipt {
    /// Opaque residency-key digest (lowercase hex SHA-256).
    pub residency_key_digest: String,
    /// Versioned content digest (lowercase hex SHA-256).
    pub content_digest: String,
    /// Exact stored length in bytes; must exceed the inline threshold.
    pub stored_length: u64,
    /// Operation identity that staged the payload.
    pub operation_id: String,
    /// Generation identity that durably accepted the payload.
    pub durable_generation: String,
}

impl BlobReadyReceipt {
    /// Validates receipt shape. Generation match against the Ready probe is
    /// checked by the controller at mint time.
    pub fn validate(&self) -> Result<(), String> {
        if !is_lower_sha256(&self.residency_key_digest) {
            return Err("blob receipt residency digest must be lowercase SHA-256".to_owned());
        }
        if !is_lower_sha256(&self.content_digest) {
            return Err("blob receipt content digest must be lowercase SHA-256".to_owned());
        }
        if self.stored_length == 0 {
            return Err("blob receipt stored length must be non-zero".to_owned());
        }
        if self.operation_id.trim().is_empty()
            || self.operation_id != self.operation_id.trim()
            || self.operation_id.chars().any(char::is_control)
        {
            return Err("blob receipt operation identity is empty or contains control".to_owned());
        }
        if self.durable_generation.trim().is_empty()
            || self.durable_generation != self.durable_generation.trim()
            || self.durable_generation.chars().any(char::is_control)
        {
            return Err("blob receipt durable generation is empty or contains control".to_owned());
        }
        Ok(())
    }
}

/// Canonical blob reference. Constructible only through
/// [`BlobStoreController::canonical_ref_from_receipt`] after the validated
/// generation confirms durable storage; there is no public field-wise
/// constructor, so a canonical-looking value can never be fabricated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRef {
    residency_key_digest: String,
    content_digest: String,
    stored_length: u64,
    operation_id: String,
    durable_generation: String,
}

impl BlobRef {
    /// Returns the residency-key digest bound at durable acceptance.
    #[must_use]
    pub fn residency_key_digest(&self) -> &str {
        &self.residency_key_digest
    }

    /// Returns the versioned content digest bound at durable acceptance.
    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Returns the exact stored length in bytes.
    #[must_use]
    pub fn stored_length(&self) -> u64 {
        self.stored_length
    }

    /// Returns the operation identity that staged the payload.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the generation identity that durably accepted the payload.
    #[must_use]
    pub fn durable_generation(&self) -> &str {
        &self.durable_generation
    }
}

/// Typed capture result: inline payloads always succeed; large payloads
/// either yield a canonical [`BlobRef`] or an explicit degraded result that
/// carries no canonical reference (I14.24).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobCaptureOutcome {
    /// Inline payload handled without the Blob Store (always available).
    Inline { length: u64 },
    /// Large payload durably accepted by the validated Ready generation.
    Canonical(BlobRef),
    /// Large payload cannot be served: probe unavailable or failed. Contains
    /// no canonical `BlobRef` by construction.
    DegradedLargePayload { reason: String },
}

/// Observable probe/health status of the blob generation (I1.10 vocabulary:
/// READY only for capabilities whose required dimensions pass).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobProbeStatus {
    /// Manifest validated at startup; no demand has started the generation.
    ManifestValidated,
    /// The approved generation answered readiness and integrity probes.
    Ready { generation: String },
    /// Probes are unavailable or failed; only large-payload capture degrades.
    Degraded { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BlobLifecycle {
    /// Startup-validated; the process has not been started.
    ManifestValidated,
    /// First demand started/probed the approved generation and it is Ready.
    Ready { generation: String },
    /// Probe unavailable or failed; records the first terminal reason.
    Degraded { reason: String },
}

/// Kernel-owned Blob Store generation controller (I1.11 step 4).
///
/// Startup validates the approved manifest without starting the process.
/// The first [`BlobDemand`] starts-or-reuses the approved generation through
/// the caller-supplied probe closure, performs the record step, and all later
/// demands reuse the recorded result. Canonical [`BlobRef`] minting requires
/// both `Ready` state and a valid [`BlobReadyReceipt`].
pub struct BlobStoreController {
    manifest: BlobStoreManifest,
    state: BlobLifecycle,
    process_started: bool,
}

impl BlobStoreController {
    /// Validates the approved manifest at startup without starting the blob
    /// generation. Reports the manifest as validated; the process stays
    /// stopped until the first explicit demand.
    pub fn new(manifest: BlobStoreManifest) -> Result<Self, String> {
        manifest.validate()?;
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.blob.manifest_validated:process_not_started",
        );
        Ok(Self {
            manifest,
            state: BlobLifecycle::ManifestValidated,
            process_started: false,
        })
    }

    /// Returns the approved manifest retained at startup.
    #[must_use]
    pub fn manifest(&self) -> &BlobStoreManifest {
        &self.manifest
    }

    /// Reports whether the manifest was validated at startup.
    #[must_use]
    pub fn manifest_validated(&self) -> bool {
        true
    }

    /// Reports whether the blob generation process has been started.
    /// False until the first explicit demand.
    #[must_use]
    pub fn process_started(&self) -> bool {
        self.process_started
    }

    /// Returns the current observable probe status (I1.10 reading).
    #[must_use]
    pub fn probe_status(&self) -> BlobProbeStatus {
        match &self.state {
            BlobLifecycle::ManifestValidated => BlobProbeStatus::ManifestValidated,
            BlobLifecycle::Ready { generation } => BlobProbeStatus::Ready {
                generation: generation.clone(),
            },
            BlobLifecycle::Degraded { reason } => BlobProbeStatus::Degraded {
                reason: reason.clone(),
            },
        }
    }

    /// Handles one explicit demand signal. On the first demand, runs the
    /// caller-supplied start-or-reuse plus readiness/integrity probe closure
    /// exactly once and records the result; later demands reuse the recorded
    /// generation outcome without re-probing.
    ///
    /// The closure returns `Ok(success)` when the approved generation is
    /// Ready, or `Err(reason)` when the probe is unavailable or fails. A
    /// failed probe degrades only large-payload capture; inline work and
    /// unrelated canonical work are unaffected.
    pub fn on_demand(
        &mut self,
        demand: BlobDemand,
        start_and_probe: impl FnOnce() -> Result<BlobProbeSuccess, String>,
    ) -> BlobProbeStatus {
        match &self.state {
            BlobLifecycle::Ready { generation } => {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.blob.demand_reused:ready",
                );
                let _ = demand;
                BlobProbeStatus::Ready {
                    generation: generation.clone(),
                }
            }
            BlobLifecycle::Degraded { reason } => {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.blob.demand_reused:degraded",
                );
                let _ = demand;
                BlobProbeStatus::Degraded {
                    reason: reason.clone(),
                }
            }
            BlobLifecycle::ManifestValidated => {
                self.process_started = true;
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    match demand {
                        BlobDemand::NonInlineCapture => "kernel.blob.first_demand:capture",
                        BlobDemand::Recovery => "kernel.blob.first_demand:recovery",
                        BlobDemand::GarbageCollection => "kernel.blob.first_demand:gc",
                    },
                );
                match start_and_probe() {
                    Ok(success) => {
                        if let Err(error) = self.record_ready(success) {
                            return self.record_degraded(error);
                        }
                        observe_entrypoint_with_detail(
                            EntrypointStage::StoreBootstrap,
                            "kernel.blob.probe_ready",
                        );
                    }
                    Err(reason) => {
                        return self.record_degraded(sanitize_reason(&reason));
                    }
                }
                self.probe_status()
            }
        }
    }

    /// Captures one payload. Payloads at or below the inline threshold are
    /// handled inline and stay available even while degraded. Larger payloads
    /// require the Ready generation plus a durable receipt; otherwise a typed
    /// [`BlobCaptureOutcome::DegradedLargePayload`] is returned and no
    /// canonical `BlobRef` is produced.
    #[must_use]
    pub fn capture(&self, length: u64, receipt: Option<&BlobReadyReceipt>) -> BlobCaptureOutcome {
        if length <= self.manifest.inline_threshold_bytes {
            return BlobCaptureOutcome::Inline { length };
        }
        match &self.state {
            BlobLifecycle::Ready { generation } => {
                let Some(receipt) = receipt else {
                    return BlobCaptureOutcome::DegradedLargePayload {
                        reason: "large payload has no durable BlobReadyReceipt".to_owned(),
                    };
                };
                if receipt.validate().is_err()
                    || receipt.stored_length != length
                    || receipt.durable_generation != *generation
                    || receipt.stored_length <= self.manifest.inline_threshold_bytes
                {
                    return BlobCaptureOutcome::DegradedLargePayload {
                        reason: "large payload BlobReadyReceipt is not durably bound".to_owned(),
                    };
                }
                BlobCaptureOutcome::Canonical(BlobRef {
                    residency_key_digest: receipt.residency_key_digest.clone(),
                    content_digest: receipt.content_digest.clone(),
                    stored_length: receipt.stored_length,
                    operation_id: receipt.operation_id.clone(),
                    durable_generation: receipt.durable_generation.clone(),
                })
            }
            BlobLifecycle::ManifestValidated => BlobCaptureOutcome::DegradedLargePayload {
                reason: "blob generation has not been started or probed".to_owned(),
            },
            BlobLifecycle::Degraded { reason } => BlobCaptureOutcome::DegradedLargePayload {
                reason: reason.clone(),
            },
        }
    }

    /// Mints a canonical [`BlobRef`] only after the validated Ready
    /// generation confirms durable storage via `receipt`. Any other state, an
    /// invalid receipt, a generation mismatch, or a non-large length fails
    /// closed with a typed degraded reason and never fabricates a reference.
    pub fn canonical_ref_from_receipt(
        &self,
        receipt: &BlobReadyReceipt,
    ) -> Result<BlobRef, String> {
        let generation = match &self.state {
            BlobLifecycle::Ready { generation } => generation,
            BlobLifecycle::ManifestValidated => {
                return Err("blob generation has not been started or probed".to_owned());
            }
            BlobLifecycle::Degraded { reason } => {
                return Err(reason.clone());
            }
        };
        receipt.validate()?;
        if receipt.durable_generation != *generation {
            return Err("blob receipt generation does not match the Ready probe".to_owned());
        }
        if receipt.stored_length <= self.manifest.inline_threshold_bytes {
            return Err("blob receipt length is inline and has no canonical BlobRef".to_owned());
        }
        Ok(BlobRef {
            residency_key_digest: receipt.residency_key_digest.clone(),
            content_digest: receipt.content_digest.clone(),
            stored_length: receipt.stored_length,
            operation_id: receipt.operation_id.clone(),
            durable_generation: receipt.durable_generation.clone(),
        })
    }

    fn record_ready(&mut self, success: BlobProbeSuccess) -> Result<(), String> {
        success.validate()?;
        if success.generation != self.manifest.approved_generation {
            return Err("blob probe generation does not match the approved manifest".to_owned());
        }
        self.state = BlobLifecycle::Ready {
            generation: success.generation,
        };
        Ok(())
    }

    fn record_degraded(&mut self, reason: String) -> BlobProbeStatus {
        let reason = sanitize_reason(&reason);
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            "kernel.blob.probe_degraded:large_payload_only",
        );
        self.state = BlobLifecycle::Degraded {
            reason: reason.clone(),
        };
        BlobProbeStatus::Degraded { reason }
    }
}

/// Kernel-composition seam over the owned controller (cell 8 runtime, read
/// through the cell 7 health vocabulary). Composition never spawns the blob
/// process here; demand callers inject the approved-generation probe outcome.
impl super::KernelComposition {
    /// Reports whether an approved blob manifest was validated at startup.
    #[must_use]
    pub fn blob_manifest_validated(&self) -> bool {
        self.blob_store
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Reports whether the blob generation process has been started.
    /// False until the first explicit non-inline/recovery/GC demand.
    #[must_use]
    pub fn blob_process_started(&self) -> bool {
        self.blob_store
            .lock()
            .map(|guard| {
                guard
                    .as_ref()
                    .is_some_and(|controller| controller.process_started())
            })
            .unwrap_or(false)
    }

    /// Returns the current blob probe status, or `None` when no approved
    /// manifest was injected (large payloads stay degraded).
    #[must_use]
    pub fn blob_probe_status(&self) -> Option<BlobProbeStatus> {
        self.blob_store
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|controller| controller.probe_status()))
    }

    /// Handles one explicit blob demand. On first demand runs the injected
    /// approved-generation start-or-reuse plus readiness/integrity probe
    /// closure once and records the result; later demands reuse it. Returns
    /// `Err` when no approved manifest was injected.
    pub fn demand_blob_store(
        &self,
        demand: BlobDemand,
        start_and_probe: impl FnOnce() -> Result<BlobProbeSuccess, String>,
    ) -> Result<BlobProbeStatus, String> {
        let mut guard = self
            .blob_store
            .lock()
            .map_err(|_| "blob controller lock poisoned".to_owned())?;
        let Some(controller) = guard.as_mut() else {
            return Err("no approved blob manifest was validated at startup".to_owned());
        };
        Ok(controller.on_demand(demand, start_and_probe))
    }

    /// Captures one payload through the blob demand controller. Inline
    /// payloads stay available in every state; large payloads require Ready
    /// plus a durable receipt. Returns a degraded typed result (never a
    /// fabricated `BlobRef`) when no manifest was injected.
    #[must_use]
    pub fn capture_blob_payload(
        &self,
        length: u64,
        receipt: Option<&BlobReadyReceipt>,
    ) -> BlobCaptureOutcome {
        self.blob_store
            .lock()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()
                    .map(|controller| controller.capture(length, receipt))
            })
            .unwrap_or(BlobCaptureOutcome::DegradedLargePayload {
                reason: "no approved blob manifest was validated at startup".to_owned(),
            })
    }

    /// Mints a canonical [`BlobRef`] only after the validated Ready
    /// generation confirms durable storage. Fails closed otherwise.
    pub fn blob_canonical_ref(&self, receipt: &BlobReadyReceipt) -> Result<BlobRef, String> {
        let guard = self
            .blob_store
            .lock()
            .map_err(|_| "blob controller lock poisoned".to_owned())?;
        let Some(controller) = guard.as_ref() else {
            return Err("no approved blob manifest was validated at startup".to_owned());
        };
        controller.canonical_ref_from_receipt(receipt)
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Bounds a probe-failure reason to fixed safe vocabulary: non-empty,
/// trimmed, control-free, and at most 256 chars. Anything else maps to one
/// stable degraded reason so diagnostics never carry blob internals.
fn sanitize_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return "blob probe unavailable or failed".to_owned();
    }
    let bounded: String = trimmed.chars().take(256).collect();
    if bounded.is_empty() {
        return "blob probe unavailable or failed".to_owned();
    }
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_manifest() -> BlobStoreManifest {
        BlobStoreManifest {
            data_root: PathBuf::from(if cfg!(windows) {
                r"C:\ProgramData\Eliot\blobs"
            } else {
                "/var/lib/eliot/blobs"
            }),
            manifest_digest: "a".repeat(64),
            format_version: BLOB_MANIFEST_FORMAT_VERSION,
            inline_threshold_bytes: BLOB_INLINE_THRESHOLD_DEFAULT_BYTES,
            approved_generation: "blob-gen-approved-1".to_owned(),
        }
    }

    pub(crate) fn test_probe_success() -> BlobProbeSuccess {
        BlobProbeSuccess {
            generation: "blob-gen-approved-1".to_owned(),
            integrity_digest: "b".repeat(64),
        }
    }

    pub(crate) fn test_receipt(length: u64) -> BlobReadyReceipt {
        BlobReadyReceipt {
            residency_key_digest: "c".repeat(64),
            content_digest: "d".repeat(64),
            stored_length: length,
            operation_id: "op-1".to_owned(),
            durable_generation: "blob-gen-approved-1".to_owned(),
        }
    }

    #[test]
    fn startup_validates_manifest_without_starting() {
        let controller =
            BlobStoreController::new(test_manifest()).expect("approved manifest must validate");
        assert!(controller.manifest_validated());
        assert!(!controller.process_started());
        assert_eq!(
            controller.probe_status(),
            BlobProbeStatus::ManifestValidated
        );
    }

    #[test]
    fn invalid_manifest_fails_closed_before_demand() {
        let mut manifest = test_manifest();
        manifest.format_version = 999;
        assert!(BlobStoreController::new(manifest).is_err());
    }

    #[test]
    fn first_demand_starts_and_records_ready() {
        let mut controller =
            BlobStoreController::new(test_manifest()).expect("approved manifest must validate");
        let status =
            controller.on_demand(BlobDemand::NonInlineCapture, || Ok(test_probe_success()));
        assert!(controller.process_started());
        assert_eq!(
            status,
            BlobProbeStatus::Ready {
                generation: "blob-gen-approved-1".to_owned()
            }
        );
    }

    #[test]
    fn failed_probe_degrades_large_payload_only() {
        let mut controller =
            BlobStoreController::new(test_manifest()).expect("approved manifest must validate");
        let status = controller.on_demand(BlobDemand::Recovery, || {
            Err("probe transport unavailable".to_owned())
        });
        assert!(controller.process_started());
        assert!(matches!(status, BlobProbeStatus::Degraded { .. }));
        assert!(matches!(
            controller.capture(16, None),
            BlobCaptureOutcome::Inline { length: 16 }
        ));
        let large = controller.capture(1024 * 1024, None);
        assert!(
            matches!(large, BlobCaptureOutcome::DegradedLargePayload { .. }),
            "large capture must degrade without a canonical BlobRef, got: {large:?}"
        );
        assert!(controller
            .canonical_ref_from_receipt(&test_receipt(1024 * 1024))
            .is_err());
    }

    #[test]
    fn canonical_ref_requires_ready_plus_durable_receipt() {
        let controller =
            BlobStoreController::new(test_manifest()).expect("approved manifest must validate");
        assert!(controller
            .canonical_ref_from_receipt(&test_receipt(1024 * 1024))
            .is_err());
        assert!(matches!(
            controller.capture(1024 * 1024, Some(&test_receipt(1024 * 1024))),
            BlobCaptureOutcome::DegradedLargePayload { .. }
        ));
    }

    #[test]
    fn ready_mints_canonical_ref_only_for_bound_receipt() {
        let mut controller =
            BlobStoreController::new(test_manifest()).expect("approved manifest must validate");
        controller.on_demand(BlobDemand::GarbageCollection, || Ok(test_probe_success()));
        let receipt = test_receipt(64 * 1024);
        let minted = controller
            .canonical_ref_from_receipt(&receipt)
            .expect("bound receipt must mint");
        assert_eq!(minted.content_digest(), &"d".repeat(64));
        assert_eq!(minted.stored_length(), 64 * 1024);
        let outcome = controller.capture(64 * 1024, Some(&receipt));
        assert!(matches!(outcome, BlobCaptureOutcome::Canonical(_)));
        let mut foreign = receipt.clone();
        foreign.durable_generation = "foreign-generation".to_owned();
        assert!(controller.canonical_ref_from_receipt(&foreign).is_err());
    }
}
