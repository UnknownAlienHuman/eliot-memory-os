//! Credential marker and envelope wire codec.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A2.2`, `A2.3`, `A12.3`,
//!   and `A12.6`.
//! - `docs/architecture/A16-01-decision-anchors.md`: `ARCH-AUTH-01`,
//!   `ARCH-SEC-02`, and `ARCH-RES-01`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I1.2`, `I1.4`, `I3.12`,
//!   and `I3.15`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
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
    let marker: MarkerRecord = serde_json::from_slice(bytes).map_err(|_| ())?;
    let expected = marker_bytes(
        request,
        key,
        identity,
        marker.phase,
        marker.credential_envelope_digest.as_ref(),
    )
    .map_err(|_| ())?;
    let expected: MarkerRecord = serde_json::from_slice(&expected).map_err(|_| ())?;
    if !constant_time_handle_equal(&marker.mac, &expected.mac)
        || marker.marker != marker_identity(identity)
        || marker.version != MARKER_VERSION
    {
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
    let envelope: CredentialEnvelope = serde_json::from_slice(bytes).map_err(|_| ())?;
    let expected = envelope_bytes(request, key, host_owner_epoch, identity, &envelope.secret)?;
    let expected: CredentialEnvelope = serde_json::from_slice(&expected).map_err(|_| ())?;
    if !constant_time_handle_equal(&envelope.mac, &expected.mac)
        || envelope.marker != marker_identity(identity)
        || envelope.version != ENVELOPE_VERSION
    {
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
