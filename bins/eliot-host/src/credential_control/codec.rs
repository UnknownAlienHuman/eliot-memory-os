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
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); Event Log
// sink disposition through the canonical
// (`crate::host_diagnostics::note_event_log_sink_status`) over the landed
// `windows_event_log` port, never probed here.
//
// Observation-only contract (mirrors `host_composition_phase_b.rs:30-41`):
// every call projects a boundary already decided by the semantic owner.
// Arguments are static literals only — no bytes, digests, keys, identities,
// or error text are formatted, so no secret material can cross (I15.4) and no
// extra evaluation runs on the semantic path. Sink outcome never alters the
// typed `Err(())`, order, or cleanup. No terminal emission here: one terminal
// per failed operation stays with the credential operation guard, while these
// inner phases correlate by stage order only. Rejected input keeps its
// original typed failure with zero byte leakage; each rejection branch below
// supplies its exact `CodecRejectReason`, so the five contours stay distinct
// instead of collapsing to one label.
fn credential_codec_observe(detail: &str) {
    crate::host_diagnostics::note_event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::ScmDispatch,
        detail,
    );
}

/// Closed reject-cause discriminant for credential codec observations.
///
/// Audit 5909832545 defect 3: the five rejection contours were all observed
/// as one `malformed retained` label, erasing the distinction the parent
/// already keeps in its reason codes (`credential-marker-mac`,
/// `credential-marker-created-mac`, `credential-target-binding`, and related
/// recovery labels). Each rejection branch supplies its exact variant; the
/// observation projects that variant as a distinct static detail. Variants
/// carry no bytes, keys, digests, or Serde text, so the projection stays
/// secret-free and constant-time integrity checks are untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecRejectReason {
    /// Input is not well-formed JSON of the expected shape.
    Shape,
    /// The locally re-encoded expected record failed to build or re-parse.
    Encoding,
    /// Constant-time MAC comparison failed.
    Mac,
    /// The protected marker object does not match the live identity.
    Binding,
    /// The wire version does not match the expected version.
    Version,
}

/// Projects one marker rejection cause as a static observation detail.
fn marker_reject_detail(reason: CodecRejectReason) -> &'static str {
    match reason {
        CodecRejectReason::Shape => "host.credential codec marker shape retained",
        CodecRejectReason::Encoding => "host.credential codec marker encoding retained",
        CodecRejectReason::Mac => "host.credential codec marker mac retained",
        CodecRejectReason::Binding => "host.credential codec marker binding retained",
        CodecRejectReason::Version => "host.credential codec marker version retained",
    }
}

/// Projects one envelope rejection cause as a static observation detail.
fn envelope_reject_detail(reason: CodecRejectReason) -> &'static str {
    match reason {
        CodecRejectReason::Shape => "host.credential codec envelope shape retained",
        CodecRejectReason::Encoding => "host.credential codec envelope encoding retained",
        CodecRejectReason::Mac => "host.credential codec envelope mac retained",
        CodecRejectReason::Binding => "host.credential codec envelope binding retained",
        CodecRejectReason::Version => "host.credential codec envelope version retained",
    }
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
    let marker: MarkerRecord = serde_json::from_slice(bytes).map_err(|_| {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Shape));
    })?;
    let expected = marker_bytes(
        request,
        key,
        identity,
        marker.phase,
        marker.credential_envelope_digest.as_ref(),
    )
    .map_err(|_| {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Encoding));
    })?;
    let expected: MarkerRecord = serde_json::from_slice(&expected).map_err(|_| {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Encoding));
    })?;
    if !constant_time_handle_equal(&marker.mac, &expected.mac) {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Mac));
        return Err(());
    }
    if marker.marker != marker_identity(identity) {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Binding));
        return Err(());
    }
    if marker.version != MARKER_VERSION {
        credential_codec_observe(marker_reject_detail(CodecRejectReason::Version));
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
    let envelope: CredentialEnvelope = serde_json::from_slice(bytes).map_err(|_| {
        credential_codec_observe(envelope_reject_detail(CodecRejectReason::Shape));
    })?;
    let expected = envelope_bytes(request, key, host_owner_epoch, identity, &envelope.secret)
        .map_err(|_| {
            credential_codec_observe(envelope_reject_detail(CodecRejectReason::Encoding));
        })?;
    let expected: CredentialEnvelope = serde_json::from_slice(&expected).map_err(|_| {
        credential_codec_observe(envelope_reject_detail(CodecRejectReason::Encoding));
    })?;
    if !constant_time_handle_equal(&envelope.mac, &expected.mac) {
        credential_codec_observe(envelope_reject_detail(CodecRejectReason::Mac));
        return Err(());
    }
    if envelope.marker != marker_identity(identity) {
        credential_codec_observe(envelope_reject_detail(CodecRejectReason::Binding));
        return Err(());
    }
    if envelope.version != ENVELOPE_VERSION {
        credential_codec_observe(envelope_reject_detail(CodecRejectReason::Version));
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

#[cfg(test)]
mod codec_reject_cause_tests {
    use eliot_installation::{
        HostCredentialControlIntent, HostCredentialControlOperation, LOCAL_SERVICE_SID,
        StoreCredentialProvider, StoreCredentialProvisionPlan, StoreCredentialScope,
        provider_bootstrap_credential_target_for_store_target,
    };

    use super::*;

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap_or_else(|_| unreachable!())
    }

    fn provision() -> StoreCredentialProvisionPlan {
        let target = handle("eliot/store/v1/0123456789abcdef0123456789abcdef");
        StoreCredentialProvisionPlan {
            host_state_root: handle(r"C:\ProgramData\Eliot\host"),
            expected_host_executable: handle(r"C:\ProgramData\Eliot\eliot-host.exe"),
            target: target.clone(),
            provider_bootstrap_target: Some(
                provider_bootstrap_credential_target_for_store_target(&target)
                    .unwrap_or_else(|_| unreachable!()),
            ),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            expected_principal_sid: handle(LOCAL_SERVICE_SID),
            generation: eliot_contracts::ResourceGeneration::genesis(),
            config_digest: handle("c".repeat(64)),
        }
    }

    fn request_fixture() -> HostCredentialControlRequest {
        let intent = HostCredentialControlIntent::new(
            HostCredentialControlOperation::Provision,
            handle("tx:test"),
            handle("effect:test"),
            provision(),
            handle("a".repeat(64)),
        )
        .unwrap_or_else(|_| unreachable!());
        HostCredentialControlRequest {
            intent,
            ownership_key: vec![7; 32],
            expected_receipt: None,
            phase_b: None,
            phase_b_final: None,
        }
    }

    fn identity_fixture() -> InstallerRootObjectSnapshot {
        InstallerRootObjectSnapshot {
            canonical_path_digest: "b".repeat(64),
            volume_serial_number: 7,
            file_index: 11,
            security_descriptor_digest: "d".repeat(64),
        }
    }

    fn reject_reasons() -> [CodecRejectReason; 5] {
        [
            CodecRejectReason::Shape,
            CodecRejectReason::Encoding,
            CodecRejectReason::Mac,
            CodecRejectReason::Binding,
            CodecRejectReason::Version,
        ]
    }

    /// Audit 5909832545 defect 3, positive: every reject cause projects a
    /// distinct static detail, and the marker and envelope families stay
    /// disjoint.
    #[test]
    fn codec_reject_causes_project_distinct_static_details() {
        let marker: Vec<&'static str> = reject_reasons()
            .iter()
            .map(|reason| marker_reject_detail(*reason))
            .collect();
        let envelope: Vec<&'static str> = reject_reasons()
            .iter()
            .map(|reason| envelope_reject_detail(*reason))
            .collect();
        for (index, detail) in marker.iter().enumerate() {
            assert!(detail.contains("host.credential codec marker"));
            for other in marker.iter().skip(index + 1) {
                assert_ne!(detail, other, "reject causes must not collapse");
            }
        }
        for (index, detail) in envelope.iter().enumerate() {
            assert!(detail.contains("host.credential codec envelope"));
            for other in envelope.iter().skip(index + 1) {
                assert_ne!(detail, other, "reject causes must not collapse");
            }
        }
        for detail in &marker {
            assert!(
                !envelope.contains(detail),
                "marker and envelope families must stay disjoint"
            );
        }
    }

    /// Audit 5909832545 defect 3, refusal: no reject detail reads as the old
    /// collapsed label, and no detail carries anything but static text.
    #[test]
    fn codec_reject_details_never_read_as_collapsed_malformed() {
        for reason in reject_reasons() {
            for detail in [marker_reject_detail(reason), envelope_reject_detail(reason)] {
                assert!(
                    !detail.contains("malformed"),
                    "typed causes must not reuse the collapsed label"
                );
                assert!(
                    detail.contains("retained"),
                    "reject records keep the retained observation kind"
                );
            }
        }
    }

    /// Audit 5909832545 defect 3, positive: an exact marker round trip still
    /// decodes.
    #[test]
    fn decode_marker_accepts_exact_round_trip() {
        let request = request_fixture();
        let identity = identity_fixture();
        let marker = marker_bytes(
            &request,
            &request.ownership_key,
            &identity,
            MarkerPhase::Reserved,
            None,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(decode_marker(&request, &request.ownership_key, &identity, &marker).is_ok());
    }

    /// Audit 5909832545 defect 3, refusal: shape, MAC, binding, and version
    /// contours each refuse without altering the typed `Err(())` contract.
    #[test]
    fn decode_marker_rejects_each_reachable_contour() {
        let request = request_fixture();
        let identity = identity_fixture();
        let marker = marker_bytes(
            &request,
            &request.ownership_key,
            &identity,
            MarkerPhase::Reserved,
            None,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(decode_marker(&request, &request.ownership_key, &identity, b"not json").is_err());
        let mut wrong_key = request.ownership_key.clone();
        wrong_key[0] ^= 1;
        assert!(decode_marker(&request, &wrong_key, &identity, &marker).is_err());
        let mut foreign = identity_fixture();
        foreign.file_index += 1;
        assert!(decode_marker(&request, &request.ownership_key, &foreign, &marker).is_err());
        // The version field is outside the MAC input, so a rewritten wire
        // version reaches the version branch itself with the MAC intact.
        let mut value: serde_json::Value =
            serde_json::from_slice(&marker).unwrap_or_else(|_| unreachable!());
        value["version"] = serde_json::Value::String("tampered-version".to_owned());
        let versioned = serde_json::to_vec(&value).unwrap_or_else(|_| unreachable!());
        assert!(decode_marker(&request, &request.ownership_key, &identity, &versioned).is_err());
    }

    /// Audit 5909832545 defect 3, positive: an exact envelope round trip
    /// still decodes.
    #[test]
    fn decode_envelope_accepts_exact_round_trip() {
        let request = request_fixture();
        let identity = identity_fixture();
        let epoch = handle("epoch:one");
        let envelope = envelope_bytes(&request, &request.ownership_key, &epoch, &identity, &[9; 32])
            .unwrap_or_else(|_| unreachable!());
        assert!(
            decode_envelope(&request, &request.ownership_key, &epoch, &identity, &envelope).is_ok()
        );
    }

    /// Audit 5909832545 defect 3, refusal: shape, epoch-bound MAC, and
    /// version contours each refuse without leaking secret content.
    #[test]
    fn decode_envelope_rejects_each_reachable_contour() {
        let request = request_fixture();
        let identity = identity_fixture();
        let epoch = handle("epoch:one");
        let envelope = envelope_bytes(&request, &request.ownership_key, &epoch, &identity, &[9; 32])
            .unwrap_or_else(|_| unreachable!());
        assert!(
            decode_envelope(&request, &request.ownership_key, &epoch, &identity, b"not json")
                .is_err()
        );
        assert!(
            decode_envelope(
                &request,
                &request.ownership_key,
                &handle("epoch:two"),
                &identity,
                &envelope,
            )
            .is_err()
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&envelope).unwrap_or_else(|_| unreachable!());
        value["version"] = serde_json::Value::String("tampered-version".to_owned());
        let versioned = serde_json::to_vec(&value).unwrap_or_else(|_| unreachable!());
        assert!(
            decode_envelope(&request, &request.ownership_key, &epoch, &identity, &versioned)
                .is_err()
        );
    }
}
