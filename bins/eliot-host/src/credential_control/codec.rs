//! Credential marker and envelope wire codec.
//!
//! Architecture: `A2.2` (`docs/architecture/A02-02-roles.md`), `A2.3`
//! (`docs/architecture/A02-03-modular-architecture.md`), `A12.3`
//! (`docs/architecture/A12-03-one-governed-write-path.md`), and `A12.6`
//! (`docs/architecture/A12-06-external-model-routes-and-secrets.md`), plus
//! Decision Anchors
//! `docs/architecture/A16-01-decision-anchors.md` `ARCH-AUTH-01`, `ARCH-SEC-02`,
//! and `ARCH-RES-01`. Implementation: `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`),
//! `I1.4` (`docs/architecture/I01-04-supervision-tree.md`), `I3.12`
//! (`docs/architecture/I03-12-credential-lifecycle.md`), and `I3.15`
//! (`docs/architecture/I03-15-installation-and-update-transaction.md`).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This child owns only canonical marker/envelope bytes and their integrity
//! helpers. It owns no credential authority, filesystem/provider effect,
//! request admission, response mapping, or Host lifecycle; those boundaries
//! remain with the parent credential-control facade.

use eliot_installation::CredentialOwnershipMarkerIdentity;
use eliot_platform::PlatformHandle;
use eliot_platform_windows::InstallerRootObjectSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::HostCredentialControlRequest;

const ENVELOPE_VERSION: &str = "eliot.store-credential-envelope.v1";
const MARKER_VERSION: &str = "eliot.store-credential-marker.v1";

// F-LOG-HOST-5 (#980) inner-phase observations for credential codec.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// sink disposition is observed only through the canonical bounded observer
// `crate::host_diagnostics::note_event_log_sink_status`, which consumes the
// live `crate::windows_event_log::event_log_sink_status` answer. #984's safe
// port is landed, so that answer is `Ok` on Windows (nothing to note) and the
// typed `EventLogUnavailable` elsewhere, where the canonical observer records
// the standing seam state on the shared `tracing` sink. No sink state is read
// or interpreted here.
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Arguments are closed enum variants resolved to `&'static str` only — no
// bytes, digests, keys, identities, `serde` error text, or credential contents
// are formatted, so no secret material can cross (I15.4) and no extra
// evaluation runs on the semantic path. Sink outcome never alters the typed
// `Err(())`, order, or cleanup. No terminal emission here: one terminal per
// failed operation stays with the credential operation guard, while these inner
// phases refine — and never contradict — that terminal's reason code. Rejected
// input keeps its original typed failure with zero byte leakage.
/// Closed reason discriminant for one rejected credential wire record
/// (F-LOG-HOST-5, #980).
///
/// The codec previously emitted the single label `marker malformed retained`
/// / `envelope malformed retained` for five materially different failures
/// (JSON/shape, expected-marker encoding, MAC mismatch, protected marker
/// object mismatch, wire-version mismatch), erasing the contour the parent
/// already distinguishes and contradicting the owner reason that follows.
/// Each variant below is constructed by the exact branch that failed, so the
/// emitted record names the real cause instead of a catch-all.
///
/// Owner mapping (the reason codes `credential_control.rs` mints through
/// `unknown(request, <label>)`, each registered in `eliot_installation`'s
/// `is_credential_unknown_reason`). The codec never mints one of these; the
/// parent's single terminal still carries the code that call site chose:
///
/// - `credential-marker-mac` / `credential-marker-created-mac` /
///   `credential-delete-marker-mac` — every marker variant, whichever
///   `decode_marker` call site rejected;
/// - `credential-target-binding` / `credential-target-without-marker` /
///   `credential-target-without-marker-delete` / `credential-write-mismatch` /
///   `credential-delete-readback` — every envelope variant, whichever
///   `decode_envelope` call site rejected.
///
/// The two sides name different scopes, and neither side is invented here.
/// The contour is the precise one: the exact internal check that rejected
/// this record. The owner code is the coarser one: a call site has one fixed
/// code for its whole `decode_*` result and cannot see which check fired, so
/// it may name a broader contour than the one observed — a wire-version
/// rejection still mints `credential-marker-mac`, and an envelope
/// wire-version rejection still mints `credential-target-binding`. The
/// contour therefore refines the owner code and never contradicts it, but
/// the owner code need not name the contour.
///
/// `marker-expected-mac` / `envelope-expected-mac` name the expected-record
/// ENCODING step (`marker_bytes` / `envelope_bytes` failing to produce
/// comparable bytes), not a MAC comparison; the strings are frozen
/// vocabulary, so the variant docs below carry the accurate wording.
#[derive(Clone, Copy)]
enum CodecRejectReason {
    /// Marker bytes were not a decodable `MarkerRecord` (shape or JSON).
    /// The same contour also covers re-decoding the bytes this codec just
    /// encoded itself, a same-type serde round-trip that cannot fail in
    /// practice, so the label stays broad rather than naming a cause it
    /// cannot reach.
    MarkerRecordShape,
    /// The expected marker record could not be re-encoded for comparison.
    MarkerExpectedMac,
    /// Marker MAC did not match the recomputed expected MAC.
    MarkerMacMismatch,
    /// Marker protected-object identity did not match the served object.
    MarkerProtectedObjectMismatch,
    /// Marker wire version is not the version this codec owns.
    MarkerWireVersionMismatch,
    /// Envelope bytes were not a decodable `CredentialEnvelope` (shape/JSON).
    /// As with `MarkerRecordShape`, this also covers the unreachable
    /// same-type round-trip re-decode of the envelope bytes just encoded.
    EnvelopeRecordShape,
    /// The expected envelope record could not be re-encoded for comparison.
    EnvelopeExpectedMac,
    /// Envelope MAC did not match the recomputed expected MAC.
    EnvelopeMacMismatch,
    /// Envelope protected marker identity did not match the served object.
    EnvelopeProtectedObjectMismatch,
    /// Envelope wire version is not the version this codec owns.
    EnvelopeWireVersionMismatch,
}

impl CodecRejectReason {
    /// Frozen codec boundary label. The frozen label stays first so
    /// label-prefix consumers keep matching.
    const fn boundary(self) -> &'static str {
        match self {
            Self::MarkerRecordShape
            | Self::MarkerExpectedMac
            | Self::MarkerMacMismatch
            | Self::MarkerProtectedObjectMismatch
            | Self::MarkerWireVersionMismatch => "host.credential codec marker rejected",
            Self::EnvelopeRecordShape
            | Self::EnvelopeExpectedMac
            | Self::EnvelopeMacMismatch
            | Self::EnvelopeProtectedObjectMismatch
            | Self::EnvelopeWireVersionMismatch => "host.credential codec envelope rejected",
        }
    }

    /// Bounded, secret-free contour produced by the failing branch itself.
    const fn contour(self) -> &'static str {
        match self {
            Self::MarkerRecordShape => "marker-record-shape",
            Self::MarkerExpectedMac => "marker-expected-mac",
            Self::MarkerMacMismatch => "marker-mac-mismatch",
            Self::MarkerProtectedObjectMismatch => "marker-protected-object-mismatch",
            Self::MarkerWireVersionMismatch => "marker-wire-version-mismatch",
            Self::EnvelopeRecordShape => "envelope-record-shape",
            Self::EnvelopeExpectedMac => "envelope-expected-mac",
            Self::EnvelopeMacMismatch => "envelope-mac-mismatch",
            Self::EnvelopeProtectedObjectMismatch => "envelope-protected-object-mismatch",
            Self::EnvelopeWireVersionMismatch => "envelope-wire-version-mismatch",
        }
    }
}

/// Projects one discriminated codec rejection through the #889 facade.
///
/// The detail is assembled only from the two `&'static str` projections of the
/// supplied discriminant, so no rejected byte, key, or `serde` text can reach
/// the record; `observe_entrypoint_with_detail` bounds the result.
fn credential_codec_observe(reason: CodecRejectReason) {
    // Sink disposition is load-bearing for this record: the canonical bounded
    // observer states where a codec rejection stayed, in the same place in the
    // sequence the discarded status read used to occupy.
    crate::host_diagnostics::note_event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        &format!(
            "{boundary} reason={contour}",
            boundary = reason.boundary(),
            contour = reason.contour(),
        ),
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum MarkerPhase {
    Reserved,
    Finalized,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MarkerRecord {
    pub(super) version: String,
    pub(super) transaction_id: PlatformHandle,
    pub(super) effect_id: PlatformHandle,
    pub(super) effect_binding_digest: PlatformHandle,
    pub(super) marker: CredentialOwnershipMarkerIdentity,
    pub(super) phase: MarkerPhase,
    pub(super) credential_envelope_digest: Option<PlatformHandle>,
    pub(super) mac: PlatformHandle,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEnvelope {
    version: String,
    transaction_id: PlatformHandle,
    effect_id: PlatformHandle,
    effect_binding_digest: PlatformHandle,
    generation: eliot_contracts::ResourceGeneration,
    config_digest: PlatformHandle,
    target: PlatformHandle,
    principal_sid: PlatformHandle,
    host_owner_epoch: PlatformHandle,
    marker: CredentialOwnershipMarkerIdentity,
    secret: Vec<u8>,
    mac: PlatformHandle,
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

pub(super) fn marker_identity(
    value: &InstallerRootObjectSnapshot,
) -> CredentialOwnershipMarkerIdentity {
    CredentialOwnershipMarkerIdentity {
        canonical_path_digest: PlatformHandle::new(value.canonical_path_digest.clone())
            .unwrap_or_else(|_| unreachable!()),
        volume_serial_number: value.volume_serial_number,
        file_index: value.file_index,
        security_descriptor_digest: PlatformHandle::new(value.security_descriptor_digest.clone())
            .unwrap_or_else(|_| unreachable!()),
    }
}

pub(super) fn marker_snapshot(
    value: &CredentialOwnershipMarkerIdentity,
) -> InstallerRootObjectSnapshot {
    InstallerRootObjectSnapshot {
        canonical_path_digest: value.canonical_path_digest.as_str().to_owned(),
        volume_serial_number: value.volume_serial_number,
        file_index: value.file_index,
        security_descriptor_digest: value.security_descriptor_digest.as_str().to_owned(),
    }
}

pub(super) fn marker_bytes(
    request: &HostCredentialControlRequest,
    key: &[u8],
    identity: &InstallerRootObjectSnapshot,
    phase: MarkerPhase,
    envelope_digest: Option<&PlatformHandle>,
) -> Result<Vec<u8>, eliot_platform_windows::InstallerRootError> {
    #[derive(Serialize)]
    struct MacInput<'a> {
        version: &'static str,
        transaction_id: &'a PlatformHandle,
        effect_id: &'a PlatformHandle,
        effect_binding_digest: &'a PlatformHandle,
        marker: CredentialOwnershipMarkerIdentity,
        phase: MarkerPhase,
        credential_envelope_digest: Option<&'a PlatformHandle>,
    }
    let input = MacInput {
        version: MARKER_VERSION,
        transaction_id: &request.intent.transaction_id,
        effect_id: &request.intent.effect_id,
        effect_binding_digest: &request.intent.effect_binding_digest,
        marker: marker_identity(identity),
        phase,
        credential_envelope_digest: envelope_digest,
    };
    let mac = PlatformHandle::new(hmac_sha256_hex(
        key,
        &serde_json::to_vec(&input)
            .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)?,
    ))
    .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)?;
    serde_json::to_vec(&MarkerRecord {
        version: MARKER_VERSION.to_owned(),
        transaction_id: request.intent.transaction_id.clone(),
        effect_id: request.intent.effect_id.clone(),
        effect_binding_digest: request.intent.effect_binding_digest.clone(),
        marker: marker_identity(identity),
        phase,
        credential_envelope_digest: envelope_digest.cloned(),
        mac,
    })
    .map_err(|_| eliot_platform_windows::InstallerRootError::Indeterminate)
}

pub(super) fn decode_marker(
    request: &HostCredentialControlRequest,
    key: &[u8],
    identity: &InstallerRootObjectSnapshot,
    bytes: &[u8],
) -> Result<MarkerRecord, ()> {
    // F-LOG-HOST-5 (#980): each rejection is projected by the branch that
    // actually failed, so the record names the exact cause instead of one
    // collapsed `malformed` label. The typed `Err(())` and the rejection
    // order are unchanged.
    let marker: MarkerRecord = serde_json::from_slice(bytes)
        .map_err(|_| credential_codec_observe(CodecRejectReason::MarkerRecordShape))?;
    let expected = marker_bytes(
        request,
        key,
        identity,
        marker.phase,
        marker.credential_envelope_digest.as_ref(),
    )
    .map_err(|_| credential_codec_observe(CodecRejectReason::MarkerExpectedMac))?;
    let expected: MarkerRecord = serde_json::from_slice(&expected)
        .map_err(|_| credential_codec_observe(CodecRejectReason::MarkerRecordShape))?;
    if !constant_time_handle_equal(&marker.mac, &expected.mac) {
        credential_codec_observe(CodecRejectReason::MarkerMacMismatch);
        return Err(());
    }
    if marker.marker != marker_identity(identity) {
        credential_codec_observe(CodecRejectReason::MarkerProtectedObjectMismatch);
        return Err(());
    }
    if marker.version != MARKER_VERSION {
        credential_codec_observe(CodecRejectReason::MarkerWireVersionMismatch);
        return Err(());
    }
    Ok(marker)
}

pub(super) fn envelope_bytes(
    request: &HostCredentialControlRequest,
    key: &[u8],
    host_owner_epoch: &PlatformHandle,
    identity: &InstallerRootObjectSnapshot,
    secret: &[u8],
) -> Result<Vec<u8>, ()> {
    #[derive(Serialize)]
    struct MacInput<'a> {
        version: &'static str,
        transaction_id: &'a PlatformHandle,
        effect_id: &'a PlatformHandle,
        effect_binding_digest: &'a PlatformHandle,
        generation: eliot_contracts::ResourceGeneration,
        config_digest: &'a PlatformHandle,
        target: &'a PlatformHandle,
        principal_sid: &'a PlatformHandle,
        host_owner_epoch: &'a PlatformHandle,
        marker: CredentialOwnershipMarkerIdentity,
        secret: &'a [u8],
    }
    let input = MacInput {
        version: ENVELOPE_VERSION,
        transaction_id: &request.intent.transaction_id,
        effect_id: &request.intent.effect_id,
        effect_binding_digest: &request.intent.effect_binding_digest,
        generation: request.intent.provision.generation,
        config_digest: &request.intent.provision.config_digest,
        target: &request.intent.provision.target,
        principal_sid: &request.intent.provision.expected_principal_sid,
        host_owner_epoch,
        marker: marker_identity(identity),
        secret,
    };
    let mac = PlatformHandle::new(hmac_sha256_hex(
        key,
        &serde_json::to_vec(&input).map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    serde_json::to_vec(&CredentialEnvelope {
        version: ENVELOPE_VERSION.to_owned(),
        transaction_id: request.intent.transaction_id.clone(),
        effect_id: request.intent.effect_id.clone(),
        effect_binding_digest: request.intent.effect_binding_digest.clone(),
        generation: request.intent.provision.generation,
        config_digest: request.intent.provision.config_digest.clone(),
        target: request.intent.provision.target.clone(),
        principal_sid: request.intent.provision.expected_principal_sid.clone(),
        host_owner_epoch: host_owner_epoch.clone(),
        marker: marker_identity(identity),
        secret: secret.to_vec(),
        mac,
    })
    .map_err(|_| ())
}

pub(super) fn decode_envelope(
    request: &HostCredentialControlRequest,
    key: &[u8],
    host_owner_epoch: &PlatformHandle,
    identity: &InstallerRootObjectSnapshot,
    bytes: &[u8],
) -> Result<(), ()> {
    // F-LOG-HOST-5 (#980): the envelope path collapses to `malformed` too;
    // each rejection is projected by the branch that actually failed.
    let envelope: CredentialEnvelope = serde_json::from_slice(bytes)
        .map_err(|_| credential_codec_observe(CodecRejectReason::EnvelopeRecordShape))?;
    let expected = envelope_bytes(request, key, host_owner_epoch, identity, &envelope.secret)
        .map_err(|_| credential_codec_observe(CodecRejectReason::EnvelopeExpectedMac))?;
    let expected: CredentialEnvelope = serde_json::from_slice(&expected)
        .map_err(|_| credential_codec_observe(CodecRejectReason::EnvelopeRecordShape))?;
    if !constant_time_handle_equal(&envelope.mac, &expected.mac) {
        credential_codec_observe(CodecRejectReason::EnvelopeMacMismatch);
        return Err(());
    }
    if envelope.marker != marker_identity(identity) {
        credential_codec_observe(CodecRejectReason::EnvelopeProtectedObjectMismatch);
        return Err(());
    }
    if envelope.version != ENVELOPE_VERSION {
        credential_codec_observe(CodecRejectReason::EnvelopeWireVersionMismatch);
        return Err(());
    }
    Ok(())
}

pub(super) fn handle_digest(bytes: &[u8]) -> Result<PlatformHandle, String> {
    PlatformHandle::new(sha256_hex(bytes)).map_err(|error| error.to_string())
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    normalized.fill(0);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer_pad.fill(0);
    format!("{:x}", outer.finalize())
}

fn constant_time_handle_equal(left: &PlatformHandle, right: &PlatformHandle) -> bool {
    let left = left.as_str().as_bytes();
    let right = right.as_str().as_bytes();
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().min(right.len()) {
        difference |= usize::from(left[index] ^ right[index]);
    }
    difference == 0
}

// F-LOG-HOST-5 (#980) executed contours of the closed codec reject vocabulary.
//
// Placed at the owner because `decode_marker`/`decode_envelope` and
// `CodecRejectReason` are `pub(super)` inside this private leaf: an integration
// test under `tests/` cannot name them. Each case drives the REAL decoder with
// a genuinely different input and asserts the record the owner emitted for
// exactly that branch, so the five-way split cannot be a catch-all: every other
// contour must be ABSENT from the same captured text.
//
// The capture reuses the crate's existing `tracing` seam: the production record
// is read back out of a real subscriber (`host_diagnostics` emits through
// `tracing::info!`), never manufactured by calling the facade directly.
#[cfg(test)]
mod codec_reject_contour_tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use eliot_installation::{
        HostCredentialControlIntent, HostCredentialControlOperation, LOCAL_SERVICE_SID,
        StoreCredentialProvider, StoreCredentialProvisionPlan, StoreCredentialScope,
        provider_bootstrap_credential_target_for_store_target,
    };

    use super::*;

    /// Every contour of the closed vocabulary. A case that emits one MUST NOT
    /// emit any of the others, so a collapsed catch-all fails the assertion
    /// instead of passing it.
    const ALL_CONTOURS: [&str; 10] = [
        "marker-record-shape",
        "marker-expected-mac",
        "marker-mac-mismatch",
        "marker-protected-object-mismatch",
        "marker-wire-version-mismatch",
        "envelope-record-shape",
        "envelope-expected-mac",
        "envelope-mac-mismatch",
        "envelope-protected-object-mismatch",
        "envelope-wire-version-mismatch",
    ];

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture poisoned"))?
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `body` under a real `tracing` subscriber and returns exactly the
    /// text production emitted while it ran.
    fn capture(body: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer = sink.clone();
        let bytes = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, body);
            sink.bytes
                .lock()
                .unwrap_or_else(|error| {
                    panic!("capture is poisoned only by a panicking writer: {error:?}")
                })
                .clone()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Asserts the single contour that was emitted, and that every OTHER
    /// contour of the closed vocabulary is absent from the same record.
    fn assert_exactly_one_contour(record: &str, expected: &str, boundary: &str) {
        assert!(
            record.contains(&format!("reason={expected}")),
            "expected contour {expected} was not emitted: {record}"
        );
        assert!(
            record.contains(boundary),
            "expected boundary {boundary} was not emitted: {record}"
        );
        for other in ALL_CONTOURS {
            if other != expected {
                assert!(
                    !record.contains(&format!("reason={other}")),
                    "contour {expected} also emitted sibling {other}: {record}"
                );
            }
        }
    }

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap_or_else(|error| panic!("test handle: {error}"))
    }

    fn provision() -> StoreCredentialProvisionPlan {
        let target = handle("eliot/store/v1/0123456789abcdef0123456789abcdef");
        StoreCredentialProvisionPlan {
            host_state_root: handle(r"C:\ProgramData\Eliot\host"),
            expected_host_executable: handle(r"C:\ProgramData\Eliot\eliot-host.exe"),
            target: target.clone(),
            provider_bootstrap_target: Some(
                provider_bootstrap_credential_target_for_store_target(&target)
                    .unwrap_or_else(|error| panic!("test bootstrap target: {error}")),
            ),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            expected_principal_sid: handle(LOCAL_SERVICE_SID),
            generation: eliot_contracts::ResourceGeneration::genesis(),
            config_digest: handle("c".repeat(64)),
        }
    }

    fn request() -> HostCredentialControlRequest {
        let intent = HostCredentialControlIntent::new(
            HostCredentialControlOperation::Provision,
            handle("tx:contour"),
            handle("effect:contour"),
            provision(),
            handle("a".repeat(64)),
        )
        .unwrap_or_else(|error| panic!("test intent: {error}"));
        HostCredentialControlRequest {
            intent,
            ownership_key: vec![7; 32],
            expected_receipt: None,
            phase_b: None,
            phase_b_final: None,
        }
    }

    /// The protected-object identity production will be asked to prove. The
    /// `foreign` variant differs only in the served file index, so the same
    /// record bytes decode against one identity and not the other.
    fn served_identity(file_index: u64) -> InstallerRootObjectSnapshot {
        InstallerRootObjectSnapshot {
            canonical_path_digest: "b".repeat(64),
            volume_serial_number: 7,
            file_index,
            security_descriptor_digest: "d".repeat(64),
        }
    }

    const MARKER_BOUNDARY: &str = "host.credential codec marker rejected";
    const ENVELOPE_BOUNDARY: &str = "host.credential codec envelope rejected";

    fn valid_marker_bytes(
        request: &HostCredentialControlRequest,
        identity: &InstallerRootObjectSnapshot,
    ) -> Vec<u8> {
        marker_bytes(
            request,
            &request.ownership_key,
            identity,
            MarkerPhase::Reserved,
            None,
        )
        .unwrap_or_else(|error| panic!("valid marker bytes: {error}"))
    }

    fn valid_envelope_bytes(
        request: &HostCredentialControlRequest,
        identity: &InstallerRootObjectSnapshot,
        epoch: &PlatformHandle,
    ) -> Vec<u8> {
        envelope_bytes(request, &request.ownership_key, epoch, identity, &[9; 32])
            .unwrap_or_else(|()| panic!("valid envelope bytes"))
    }

    /// Re-serializes a mutated marker record so the owner re-decodes a genuinely
    /// different record rather than a different byte string of the same shape.
    /// The MAC field is left untouched: the owner rebuilds the expected record
    /// from the SAME served identity, so only the edited field can differ.
    fn retag_marker(
        request: &HostCredentialControlRequest,
        identity: &InstallerRootObjectSnapshot,
        edit: impl FnOnce(&mut MarkerRecord),
    ) -> Vec<u8> {
        let mut record: MarkerRecord =
            serde_json::from_slice(&valid_marker_bytes(request, identity))
                .unwrap_or_else(|error| panic!("decode marker for retag: {error}"));
        edit(&mut record);
        serde_json::to_vec(&record)
            .unwrap_or_else(|error| panic!("encode retagged marker: {error}"))
    }

    /// Same, for the envelope record.
    fn retag_envelope(
        request: &HostCredentialControlRequest,
        identity: &InstallerRootObjectSnapshot,
        epoch: &PlatformHandle,
        edit: impl FnOnce(&mut CredentialEnvelope),
    ) -> Vec<u8> {
        let mut record: CredentialEnvelope =
            serde_json::from_slice(&valid_envelope_bytes(request, identity, epoch))
                .unwrap_or_else(|error| panic!("decode envelope for retag: {error}"));
        edit(&mut record);
        serde_json::to_vec(&record)
            .unwrap_or_else(|error| panic!("encode retagged envelope: {error}"))
    }

    // WORK_UNIT_CASE: 980/12 — the marker five-way split is five contours.
    #[test]
    fn marker_rejections_emit_their_own_contour_and_no_sibling() {
        let request = request();
        let identity = served_identity(11);
        let key = request.ownership_key.clone();

        // 1. Genuinely malformed: not JSON at all.
        let malformed = capture(|| {
            assert!(decode_marker(&request, &key, &identity, b"{not json").is_err());
        });
        assert_exactly_one_contour(&malformed, "marker-record-shape", MARKER_BOUNDARY);

        // 2. Genuinely MAC-mismatched: well-formed record, wrong ownership key.
        let bytes = valid_marker_bytes(&request, &identity);
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 1;
        let mac_mismatch = capture(|| {
            assert!(decode_marker(&request, &wrong_key, &identity, &bytes).is_err());
        });
        assert_exactly_one_contour(&mac_mismatch, "marker-mac-mismatch", MARKER_BOUNDARY);

        // 3. Genuinely foreign marker: the record names a different protected
        // object than the one this call serves, while its MAC stays exact.
        let foreign = retag_marker(&request, &identity, |record| {
            record.marker = marker_identity(&served_identity(99));
        });
        let protected = capture(|| {
            assert!(decode_marker(&request, &key, &identity, &foreign).is_err());
        });
        assert_exactly_one_contour(
            &protected,
            "marker-protected-object-mismatch",
            MARKER_BOUNDARY,
        );

        // 4. Genuinely wrong wire version. Only the `version` field is changed:
        // the expected record is always rebuilt with this codec's own version
        // constant, so the recomputed MAC still matches and only the version
        // check can reject the record. Retagging the MAC too would land on
        // `marker-mac-mismatch` instead and prove nothing about the version.
        let wrong_version = retag_marker(&request, &identity, |record| {
            record.version = "eliot.store-credential-marker.v0".to_owned();
        });
        let version = capture(|| {
            assert!(decode_marker(&request, &key, &identity, &wrong_version).is_err());
        });
        assert_exactly_one_contour(&version, "marker-wire-version-mismatch", MARKER_BOUNDARY);

        // 5. The admitted case emits NO reject contour at all, so the four
        // rejections above are real branches and not an always-on label.
        let admitted = capture(|| {
            assert!(decode_marker(&request, &key, &identity, &bytes).is_ok());
        });
        for contour in ALL_CONTOURS {
            assert!(
                !admitted.contains(&format!("reason={contour}")),
                "an admitted marker emitted reject contour {contour}: {admitted}"
            );
        }
    }

    // WORK_UNIT_CASE: 980/13 — the envelope five-way split is five contours.
    #[test]
    fn envelope_rejections_emit_their_own_contour_and_no_sibling() {
        let request = request();
        let identity = served_identity(11);
        let epoch = handle("epoch:one");
        let key = request.ownership_key.clone();

        // 1. Genuinely malformed: not JSON at all.
        let malformed = capture(|| {
            assert!(decode_envelope(&request, &key, &epoch, &identity, b"[1,2,3]").is_err());
        });
        assert_exactly_one_contour(&malformed, "envelope-record-shape", ENVELOPE_BOUNDARY);

        // 2. Genuinely MAC-mismatched: well-formed record, wrong host epoch.
        let bytes = valid_envelope_bytes(&request, &identity, &epoch);
        let mac_mismatch = capture(|| {
            assert!(
                decode_envelope(&request, &key, &handle("epoch:two"), &identity, &bytes).is_err()
            );
        });
        assert_exactly_one_contour(&mac_mismatch, "envelope-mac-mismatch", ENVELOPE_BOUNDARY);

        // 3. Genuinely foreign marker: the record names a different protected
        // object than the one this call serves, while its MAC stays exact.
        let foreign = retag_envelope(&request, &identity, &epoch, |record| {
            record.marker = marker_identity(&served_identity(99));
        });
        let protected = capture(|| {
            assert!(decode_envelope(&request, &key, &epoch, &identity, &foreign).is_err());
        });
        assert_exactly_one_contour(
            &protected,
            "envelope-protected-object-mismatch",
            ENVELOPE_BOUNDARY,
        );

        // 4. Genuinely wrong wire version. Only the `version` field is changed: the
        // expected envelope is always rebuilt with this codec's own version
        // constant, so the recomputed MAC still matches and only the version
        // check can reject the record.
        let wrong_version = retag_envelope(&request, &identity, &epoch, |record| {
            record.version = "eliot.store-credential-envelope.v0".to_owned();
        });
        let version = capture(|| {
            assert!(decode_envelope(&request, &key, &epoch, &identity, &wrong_version).is_err());
        });
        assert_exactly_one_contour(
            &version,
            "envelope-wire-version-mismatch",
            ENVELOPE_BOUNDARY,
        );

        // 5. The admitted case emits NO reject contour at all.
        let admitted = capture(|| {
            assert!(decode_envelope(&request, &key, &epoch, &identity, &bytes).is_ok());
        });
        for contour in ALL_CONTOURS {
            assert!(
                !admitted.contains(&format!("reason={contour}")),
                "an admitted envelope emitted reject contour {contour}: {admitted}"
            );
        }
    }
}
