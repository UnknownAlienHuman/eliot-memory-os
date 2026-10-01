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
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
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
fn credential_codec_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

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
/// `is_credential_unknown_reason`). The codec never mints or claims one of
/// these; the parent's single terminal still carries the exact code, and the
/// contour below only states which check inside this codec rejected the record:
///
/// - `credential-marker-mac` / `credential-marker-created-mac` /
///   `credential-delete-marker-mac` — every marker variant, whichever
///   `decode_marker` call site rejected;
/// - `credential-target-binding` / `credential-target-without-marker` /
///   `credential-target-without-marker-delete` / `credential-write-mismatch` /
///   `credential-delete-readback` — every envelope variant, whichever
///   `decode_envelope` call site rejected.
///
/// The call site, not this codec, selects between those owner codes; the
/// contour is the codec's contribution and cannot disagree with any of them.
#[derive(Clone, Copy)]
enum CodecRejectReason {
    /// Marker bytes were not a decodable `MarkerRecord` (shape or JSON).
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
    credential_codec_note_event_log_unavailable();
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
