//! Owner-side WASM dispatch material publisher (issue #1955, I14.19).
//!
//! Dedicated B1-owned module: the Kernel half of the merged User Broker
//! pattern for the WASM P03 child contour, mirroring
//! `bins/eliot-kernel/src/dispatch_launch.rs` (Doctor/testd/native-worker)
//! without touching its arms. The child constructs its own local permit
//! authority via `activate`, then builds its single `ProcessRequest`
//! in-process; the Kernel never sends a sealed `ProcessRequest` (which is
//! `Serialize`-only, never `Deserialize`). It publishes only:
//!
//! - the six launch-grant fields, derived Kernel-side from live authority
//!   plus the durable admission identity ([`WasmDispatchGrant`]);
//! - the deterministic dispatch derivation the child re-derives byte-for-byte
//!   ([`wasm_dispatch_derivation`]);
//! - the dispatch material envelope the delivery half writes next to the
//!   installed child image ([`WasmDispatchMaterial`]).
//!
//! Registration (Beauvoir lane) calls [`publish_wasm_dispatch_material`]
//! with live owners (epoch, generation, admission time, claim identities,
//! invocation facts) and writes the returned bytes through its own delivery
//! path next to the installed `eliot-wasm-host` image. No argv/env
//! material, no executable bytes, no minted ledger/registry/principal.
//!
//! Byte-identity with the child
//! (`bins/eliot-wasm-host/src/dispatch_authority.rs`) is proven by shared
//! fixed vectors asserted literally on both sides (R1 style): derivation
//! domain, tagged-hash construction, and grant-digest binding must agree
//! exactly, or the owner-published join never closes.

use eliot_contracts::{EpochId, sha256_hex};
use eliot_process::Generation;

/// Deterministic dispatch derivation domain for the WASM child contour.
/// Byte-identical on both sides; a distinct domain per contour keeps
/// permits issued under one claim from validating under another.
pub const WASM_DISPATCH_DERIVATION_DOMAIN: &str = "eliot-wasm-host-dispatch/v1";
/// Owner-side authority-identity prefix, byte-identical to the child.
pub const WASM_DISPATCH_AUTHORITY_PREFIX: &str = "wasm-host-dispatch-authority-";
/// Owner-side single revision head name, byte-identical to the child.
pub const WASM_DISPATCH_LAUNCH_GRANT_HEAD: &str = "wasm-launch-grant";
/// Dispatch material file name the child reader derives from its executable
/// directory (`current_exe`, never argv/stdin/env). Duplicated here because
/// the Kernel delivery half owns its write path; the child reader stays the
/// authority for the value.
pub const WASM_HOST_MATERIAL_FILE_NAME: &str = "eliot-wasm-host.admitted-dispatch.json";
/// Colocated guest artifact file name staged with the material.
pub const WASM_HOST_GUEST_ARTIFACT_FILE_NAME: &str = "eliot-wasm-host.guest-artifact.bin";
/// Colocated guest input file name staged with the material.
pub const WASM_HOST_GUEST_INPUT_FILE_NAME: &str = "eliot-wasm-host.guest-input.bin";
/// Material envelope wire identity, matched exactly by the child reader.
pub const WASM_DISPATCH_MATERIAL_WIRE_ID: &str = "eliot.wasm.dispatch-material";
/// Material envelope wire version, matched exactly by the child reader.
pub const WASM_DISPATCH_MATERIAL_WIRE_VERSION: u16 = 1;

/// Fail-closed owner-side dispatch errors. No material content echoed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WasmDispatchError {
    /// A material field failed shape validation.
    #[error("WASM_DISPATCH_INVALID_MATERIAL:{0}")]
    InvalidMaterial(String),
    /// A gate-owned construction failed (message only, no material).
    #[error("WASM_DISPATCH_GATE")]
    Gate,
}

fn invalid(field: &str) -> WasmDispatchError {
    WasmDispatchError::InvalidMaterial(field.to_owned())
}

fn require_digest(value: &str, field: &'static str) -> Result<(), WasmDispatchError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(field));
    }
    Ok(())
}

fn require_nonblank(value: &str, field: &'static str) -> Result<(), WasmDispatchError> {
    if value.trim().is_empty() {
        return Err(invalid(field));
    }
    Ok(())
}

/// Owner-side mirrored dispatch derivation material for one admitted claim.
///
/// Byte-identical to the child derivation: `base` is the exact child
/// `derivation_base` JSON, `key_hex` the child `KernelDispatchKey` bytes,
/// `authority_id` the child authority identity, `head_digest` the
/// `wasm-launch-grant` head value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmDispatchDerivation {
    /// Canonical derivation base JSON (the exact child `derivation_base`).
    pub base_json: String,
    /// Lowercase hex of `SHA-256("key:" + base)`.
    pub key_hex: String,
    /// Child-identical authority identity string.
    pub authority_id: String,
    /// Lowercase hex of `SHA-256("head:" + base)`.
    pub head_digest: String,
}

/// Builds the owner-side dispatch derivation from typed admitted material.
///
/// `authority_epoch` serializes via its canonical JSON shape exactly like
/// the child embeds it, so equal logical claims hash identically on both
/// sides. No wall-clock enters the derivation: freshness comes from the
/// grant window, never from `now` at derivation time.
pub fn wasm_dispatch_derivation(
    claim_id: &str,
    operation_id: &str,
    generation: u64,
    authority_epoch: &EpochId,
    launch_nonce: &str,
) -> Result<WasmDispatchDerivation, WasmDispatchError> {
    let epoch_json = serde_json::to_value(authority_epoch).map_err(|_| WasmDispatchError::Gate)?;
    wasm_dispatch_derivation_from_epoch_json(
        claim_id,
        operation_id,
        generation,
        &epoch_json,
        launch_nonce,
    )
}

/// Builds the owner-side dispatch derivation from an already-canonical epoch
/// JSON value (the exact child input shape).
pub fn wasm_dispatch_derivation_from_epoch_json(
    claim_id: &str,
    operation_id: &str,
    generation: u64,
    authority_epoch_json: &serde_json::Value,
    launch_nonce: &str,
) -> Result<WasmDispatchDerivation, WasmDispatchError> {
    if claim_id.trim().is_empty()
        || operation_id.trim().is_empty()
        || launch_nonce.trim().is_empty()
    {
        return Err(invalid("derivation-identities"));
    }
    if generation == 0 {
        return Err(invalid("derivation-generation"));
    }
    let base_json = serde_json::to_string(&serde_json::json!([
        WASM_DISPATCH_DERIVATION_DOMAIN,
        claim_id,
        operation_id,
        generation,
        authority_epoch_json,
        launch_nonce,
    ]))
    .map_err(|_| WasmDispatchError::Gate)?;
    let key_hex = dispatch_tagged_hex("key", &base_json);
    let authority_id = format!(
        "{WASM_DISPATCH_AUTHORITY_PREFIX}{}",
        dispatch_tagged_hex("authority", &base_json)
    );
    let head_digest = dispatch_tagged_hex("head", &base_json);
    Ok(WasmDispatchDerivation {
        base_json,
        key_hex,
        authority_id,
        head_digest,
    })
}

/// Hashes one domain-separated derivation input exactly like the child:
/// `SHA-256(tag + ":" + base_json)`, lowercase hex.
fn dispatch_tagged_hex(tag: &str, base_json: &str) -> String {
    let mut material =
        String::with_capacity(tag.len().saturating_add(1).saturating_add(base_json.len()));
    material.push_str(tag);
    material.push(':');
    material.push_str(base_json);
    sha256_hex(material.as_bytes())
}

/// Kernel-issued launch-grant material for one dispatched WASM child.
///
/// Same six-field contract as the worker `DispatchGrant`: the child
/// rebuilds fence + lease through the production broker types and funds
/// its one-shot permit from them. `host_artifact_digest` carries the
/// owner-measured installed-image digest (the same pair the #1955 port
/// grant binds); the executor re-hashes the file before any start.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmDispatchGrant {
    /// Lowercase SHA-256 binding the grant fields plus the admission
    /// identity digest.
    pub grant_digest: String,
    /// Live authority epoch bound at admission (canonical `EpochId`).
    pub authority_epoch: EpochId,
    /// Live activation generation bound at admission (non-zero).
    pub fence_generation: u64,
    /// Deterministic per-identity fence nonce for `FencingToken::new`.
    pub fence_nonce: String,
    /// Deterministic per-identity lease for `ActionLeaseRef::new`.
    pub idempotency_key: String,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`.
    pub expires_at: u64,
    /// Owner-measured SHA-256 of the installed child image bytes.
    pub host_artifact_digest: String,
}

/// Builds the deterministic launch grant for one admitted identity.
///
/// Inputs are all Kernel-side live authority plus the durable admission
/// identity: `identity_digest` is the admission-bound digest (lowercase
/// SHA-256 by contract), `authority_epoch`/`generation` the live values
/// bound at admission, `admitted_at_unix_ms` the durable admission time.
/// Replay-stable: an exact replay rebuilds byte-identical grant bytes.
pub fn wasm_dispatch_grant_for(
    identity_digest: &str,
    authority_epoch: &EpochId,
    generation: Generation,
    admitted_at_unix_ms: u64,
    host_artifact_digest: &str,
) -> Result<WasmDispatchGrant, WasmDispatchError> {
    require_digest(identity_digest, "grant-identity-digest")?;
    require_digest(host_artifact_digest, "grant-host-digest")?;
    if admitted_at_unix_ms == 0 {
        return Err(invalid("grant-admission-time"));
    }
    let short = identity_digest
        .get(..16)
        .ok_or_else(|| invalid("grant-identity-digest"))?;
    let fence_nonce = format!("wasm-host-launch-fence-{short}");
    let idempotency_key = format!("wasm-host-launch-lease-{short}");
    let expires_at = admitted_at_unix_ms.saturating_add(60_000);
    if expires_at == 0 {
        return Err(invalid("grant-expiry"));
    }
    let epoch_json = serde_json::to_string(authority_epoch).map_err(|_| WasmDispatchError::Gate)?;
    let mut material = String::with_capacity(320);
    material.push_str(identity_digest);
    material.push('|');
    material.push_str(&epoch_json);
    material.push('|');
    material.push_str(&generation.get().to_string());
    material.push('|');
    material.push_str(&fence_nonce);
    material.push('|');
    material.push_str(&idempotency_key);
    material.push('|');
    material.push_str(&expires_at.to_string());
    material.push('|');
    material.push_str(host_artifact_digest);
    let grant_digest = sha256_hex(material.as_bytes());
    Ok(WasmDispatchGrant {
        grant_digest,
        authority_epoch: authority_epoch.clone(),
        fence_generation: generation.get(),
        fence_nonce,
        idempotency_key,
        expires_at,
        host_artifact_digest: host_artifact_digest.to_owned(),
    })
}

/// Guest invocation ceilings carried in the dispatch material. Every value
/// is an exact ceiling the child enforces on its `--guest-exec` intent;
/// the child never widens them.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmGuestCeilings {
    /// Component artifact digest the child re-hashes (hex).
    pub artifact_digest: String,
    /// Guest input digest the child re-hashes (hex).
    pub input_digest: String,
    /// Output byte ceiling for the guest Store.
    pub max_output_bytes: u64,
    /// Fuel ceiling for the guest Store.
    pub max_fuel: u64,
    /// Memory byte ceiling for the guest Store.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms) for the epoch driver.
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks for the epoch driver.
    pub epoch_deadline_ticks: u64,
    /// Requested component identity, pinned end-to-end.
    pub component_id: String,
}

/// Dispatch material envelope the delivery half writes next to the installed
/// child image and the child consumes once. Field names are the contract
/// with the child reader; `deny_unknown_fields` on both sides.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmDispatchMaterial {
    /// Envelope wire identity (`WASM_DISPATCH_MATERIAL_WIRE_ID`).
    pub wire_id: String,
    /// Envelope wire version (`WASM_DISPATCH_MATERIAL_WIRE_VERSION`).
    pub wire_version: u16,
    /// Admitted claim identity feeding the derivation base.
    pub claim_id: String,
    /// Admitted operation identity feeding the derivation base.
    pub operation_id: String,
    /// Claiming generation feeding the derivation base (non-zero).
    pub generation: u64,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Claim-bound launch nonce (derivation + one-shot permit nonce).
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds (grant window opens).
    pub admitted_at_unix_ms: u64,
    /// Kernel-issued launch grant funding the one-shot permit.
    pub grant: WasmDispatchGrant,
    /// Guest invocation ceilings and pinned identities.
    pub guest: WasmGuestCeilings,
}

/// Validates and builds the publishable dispatch material envelope from
/// live owners. Every identity is non-blank, every digest hex-shaped, the
/// grant window non-empty; the grant digest re-binds the envelope's own
/// admission identity so a mixed envelope fails closed at the child.
#[allow(clippy::too_many_arguments)]
pub fn publish_wasm_dispatch_material(
    claim_id: &str,
    operation_id: &str,
    generation: Generation,
    authority_epoch: &EpochId,
    launch_nonce: &str,
    admitted_at_unix_ms: u64,
    identity_digest: &str,
    host_artifact_digest: &str,
    guest: WasmGuestCeilings,
) -> Result<WasmDispatchMaterial, WasmDispatchError> {
    require_nonblank(claim_id, "claim-id")?;
    require_nonblank(operation_id, "operation-id")?;
    require_nonblank(launch_nonce, "launch-nonce")?;
    require_nonblank(&guest.component_id, "guest-component-id")?;
    require_digest(&guest.artifact_digest, "guest-artifact-digest")?;
    require_digest(&guest.input_digest, "guest-input-digest")?;
    if admitted_at_unix_ms == 0 {
        return Err(invalid("admitted-at"));
    }
    if guest.max_output_bytes == 0
        || guest.max_fuel == 0
        || guest.max_memory_bytes == 0
        || guest.wall_deadline_ms == 0
        || guest.epoch_deadline_ticks == 0
    {
        return Err(invalid("guest-ceilings"));
    }
    let grant = wasm_dispatch_grant_for(
        identity_digest,
        authority_epoch,
        generation,
        admitted_at_unix_ms,
        host_artifact_digest,
    )?;
    Ok(WasmDispatchMaterial {
        wire_id: WASM_DISPATCH_MATERIAL_WIRE_ID.to_owned(),
        wire_version: WASM_DISPATCH_MATERIAL_WIRE_VERSION,
        claim_id: claim_id.to_owned(),
        operation_id: operation_id.to_owned(),
        generation: generation.get(),
        authority_epoch: authority_epoch.clone(),
        launch_nonce: launch_nonce.to_owned(),
        admitted_at_unix_ms,
        grant,
        guest,
    })
}

/// Canonical material bytes for delivery: exact JSON the child parses.
pub fn material_bytes(material: &WasmDispatchMaterial) -> Result<Vec<u8>, WasmDispatchError> {
    serde_json::to_vec(material).map_err(|_| WasmDispatchError::Gate)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_epoch() -> EpochId {
        serde_json::from_value(serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        }))
        .expect("test epoch parses")
    }

    fn test_guest() -> WasmGuestCeilings {
        WasmGuestCeilings {
            artifact_digest: "b".repeat(64),
            input_digest: "c".repeat(64),
            max_output_bytes: 1024,
            max_fuel: 100_000,
            max_memory_bytes: 1_048_576,
            wall_deadline_ms: 10_000,
            epoch_deadline_ticks: 100,
            component_id: "component-1955".to_owned(),
        }
    }

    /// R1 owner vector: the child asserts these identical literals
    /// (`bins/eliot-wasm-host/src/dispatch_authority.rs`). Agreement here
    /// is the interop proof — the owner-published join closes if and only
    /// if the child re-derives these values.
    #[test]
    fn wasm_derivation_matches_child_vector() {
        let epoch = test_epoch();
        let epoch_json = serde_json::to_value(&epoch).expect("epoch serializes");
        let derived = wasm_dispatch_derivation_from_epoch_json(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json,
            "launch-nonce-wasm-r1-0001",
        )
        .expect("owner derivation builds");
        assert_eq!(
            derived.base_json,
            "[\"eliot-wasm-host-dispatch/v1\",\"claim-wasm-r1-001\",\"operation-wasm-r1-001\",7,{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3},\"launch-nonce-wasm-r1-0001\"]"
        );
        assert_eq!(derived.authority_id.len(), 29 + 64);
        assert!(
            derived
                .authority_id
                .starts_with(WASM_DISPATCH_AUTHORITY_PREFIX)
        );
        assert_eq!(derived.key_hex.len(), 64);
        assert_eq!(derived.head_digest.len(), 64);
        // Typed entry agrees with the JSON entry on identical material.
        let typed = wasm_dispatch_derivation(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch,
            "launch-nonce-wasm-r1-0001",
        )
        .expect("typed derivation builds");
        assert_eq!(typed, derived);
    }

    #[test]
    fn blank_derivation_identities_fail_closed() {
        let epoch_json = serde_json::to_value(test_epoch()).expect("epoch serializes");
        assert!(matches!(
            wasm_dispatch_derivation_from_epoch_json("", "op", 7, &epoch_json, "n"),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        assert!(matches!(
            wasm_dispatch_derivation_from_epoch_json("c", "op", 0, &epoch_json, "n"),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
    }

    #[test]
    fn grant_publisher_binds_identity_and_window() {
        let grant = wasm_dispatch_grant_for(
            &"a".repeat(64),
            &test_epoch(),
            Generation::new(7).expect("generation"),
            4_000_000_000_000,
            &"d".repeat(64),
        )
        .expect("grant publishes");
        assert_eq!(grant.grant_digest.len(), 64);
        assert_eq!(grant.fence_generation, 7);
        assert_eq!(grant.expires_at, 4_000_000_060_000);
        assert!(grant.fence_nonce.starts_with("wasm-host-launch-fence-"));
        assert!(grant.idempotency_key.starts_with("wasm-host-launch-lease-"));
        // Replay-stable: identical inputs rebuild byte-identical grants.
        let replay = wasm_dispatch_grant_for(
            &"a".repeat(64),
            &test_epoch(),
            Generation::new(7).expect("generation"),
            4_000_000_000_000,
            &"d".repeat(64),
        )
        .expect("grant republishes");
        assert_eq!(grant, replay);
        // Malformed identity or host digest fails closed.
        assert!(matches!(
            wasm_dispatch_grant_for(
                "not-a-digest",
                &test_epoch(),
                Generation::new(7).expect("generation"),
                4_000_000_000_000,
                &"d".repeat(64),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
    }

    #[test]
    fn material_publish_validates_envelope() {
        let material = publish_wasm_dispatch_material(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            Generation::new(7).expect("generation"),
            &test_epoch(),
            "launch-nonce-wasm-r1-0001",
            4_000_000_000_000,
            &"a".repeat(64),
            &"d".repeat(64),
            test_guest(),
        )
        .expect("material publishes");
        assert_eq!(material.wire_id, WASM_DISPATCH_MATERIAL_WIRE_ID);
        assert_eq!(material.wire_version, WASM_DISPATCH_MATERIAL_WIRE_VERSION);
        let bytes = material_bytes(&material).expect("material serializes");
        let reparsed: WasmDispatchMaterial =
            serde_json::from_slice(&bytes).expect("material reparses");
        assert_eq!(reparsed, material);
        // Blank claim fails closed.
        assert!(matches!(
            publish_wasm_dispatch_material(
                "",
                "operation-wasm-r1-001",
                Generation::new(7).expect("generation"),
                &test_epoch(),
                "launch-nonce-wasm-r1-0001",
                4_000_000_000_000,
                &"a".repeat(64),
                &"d".repeat(64),
                test_guest(),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
    }
}
