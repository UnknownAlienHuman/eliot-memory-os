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
    /// Table element ceiling for the guest Store.
    pub table_elements: u64,
    /// Instance ceiling for the guest Store.
    pub max_instances: u64,
    /// Artifact-read count ceiling for the guest Store.
    pub artifact_access_reads: u64,
    /// Artifact-read byte ceiling for the guest Store.
    pub artifact_access_bytes: u64,
    /// Requested component identity, pinned end-to-end.
    pub component_id: String,
}

/// Owner-authored component manifest record for one dispatched WASM child.
///
/// Every value is authored by the admitting owner (Governor/module-catalog
/// lane in production); the child re-proves digests against real bytes and
/// enforces the closed-world constants below. Field names mirror the
/// runtime `ComponentManifest` member for member so the child assembles it
/// without translation drift.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmManifestRecord {
    /// Admitted component identity.
    pub component_id: String,
    /// Admitted world name (the child enforces the frozen guest world).
    pub world: String,
    /// Admitted guest target (the child enforces the frozen standard target).
    pub target: String,
    /// Owner-recorded source digest (hex).
    pub source_digest: String,
    /// Owner-recorded state-contract digest (hex).
    pub state_contract_digest: String,
    /// Owner-recorded required verifier (must match the assurance record).
    pub required_verifier: String,
    /// Owner-recorded admitted privacy classes (non-empty).
    pub privacy_classes: Vec<String>,
    /// Declared imports (the child enforces the closed world: empty).
    pub allowed_imports: Vec<String>,
    /// Declared exports (the child enforces exactly `run`).
    pub allowed_exports: Vec<String>,
    /// Granted capabilities (the child enforces none).
    pub capability_grants: Vec<String>,
    /// Owned state class (e.g. `stateless`).
    pub state_class: String,
    /// Versioned state migration contract (e.g. `none`).
    pub migration_contract: String,
    /// Privacy policy binding (e.g. `project_code`).
    pub privacy_policy: String,
    /// Differential comparator binding (e.g. `shadow-exact`).
    pub comparator: String,
    /// Rollback generation binding, when the comparator names one.
    pub rollback_generation: Option<String>,
}

/// Owner-authored work identity record: owner, scope, lease selection,
/// revisions, and determinism seed. Fences and epochs are NOT carried
/// here — the child derives every fence from the dispatch grant and the
/// snapshot, then enforces equality.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmWorkRecord {
    /// Admitted owner identity.
    pub owner: String,
    /// Admitted work-unit identity.
    pub work_unit: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Optional task reference bound into the scope.
    pub task_ref: Option<String>,
    /// Admitted lease identity.
    pub lease_id: String,
    /// Lease scope reference (must equal the work scope).
    pub lease_scope_ref: String,
    /// Lease state marker (`active`; anything else is refused).
    pub lease_state: String,
    /// Generation state marker (`ready` or `active`; anything else refused).
    pub generation_state: String,
    /// Authority revision bound at admission (non-zero).
    pub authority_revision: u64,
    /// Lifecycle revision bound at admission (non-zero).
    pub lifecycle_revision: u64,
    /// Verification revision bound at admission (non-zero).
    pub verification_revision: u64,
    /// Deterministic seed for the guest invocation.
    pub deterministic_seed: u64,
    /// Requested contour (`SHADOW` or `CONFORMANCE`; anything else refused).
    pub contour: String,
    /// Owner-attested generation health dimensions in struct order:
    /// liveness, readiness, freshness, compatibility, integrity, capacity.
    /// Each entry is `UNKNOWN`, `HEALTHY`, `DEGRADED`, or `FAILED`.
    pub generation_health: Vec<String>,
}

/// Owner-authored source-assurance record: the source admission verdict the
/// child carries without re-deciding. Every value is owner-attested; the
/// child enforces shapes plus the verifier agreement with the manifest.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmAssuranceRecord {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement (`VERIFIED`, `UNVERIFIED`, `MODIFIED`, `CONFLICTED`).
    pub integrity: String,
    /// Freshness statement (`CURRENT`, `STALE`, `UNKNOWN`).
    pub freshness: String,
    /// Competence classification (`DOMAIN_VERIFIED`, `ATTRIBUTED`, `UNKNOWN`).
    pub competence: String,
    /// Independence classification (`INDEPENDENT`, `RELATED`, `COMMON_MODE`,
    /// `UNKNOWN`).
    pub independence: String,
    /// Privacy class (`PUBLIC`, `INTERNAL`, `PRIVATE`, `SECRET`, `LICENSED`).
    pub privacy_class: String,
    /// Instruction taint (`CLEARED`, `DATA_ONLY`, `UNTRUSTED`, `COMMAND_LIKE`).
    pub instruction_taint: String,
    /// Permitted epistemic uses (`OBSERVATION`, `ATTRIBUTED_INPUT`,
    /// `CANDIDATE_EVIDENCE`, `VERIFICATION_INPUT`).
    pub epistemic_use: Vec<String>,
    /// Effect ceilings (`READ_ONLY`, `CANDIDATE_ONLY`, `NO_EXTERNAL_EFFECT`).
    pub effect_ceilings: Vec<String>,
    /// Required verifier (must equal the manifest record verifier).
    pub required_verifier: String,
    /// Quarantine state (`NONE`, `REVIEW_REQUIRED`, `QUARANTINED`, `RELEASED`).
    pub quarantine: String,
}

/// Owner-authored promotion oracle record for conformance runs: corpus and
/// oracle digests the future runtime seating enforces differentially. The
/// direct engine path carries these values through without deciding on
/// them; minting oracle knowledge without the oracle is refused by
/// construction (the owner publishes them or the operation does not run).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmPromotionRecord {
    /// Digest of the covered corpus input bytes (hex).
    pub corpus_digest: String,
    /// Digest of the oracle result bytes (hex).
    pub expected_result_digest: String,
    /// Digest of the oracle effect proposals (hex).
    pub expected_effect_digest: String,
    /// Digest of the oracle state delta (hex).
    pub expected_state_delta_digest: String,
}

/// Owner-attested Kernel generation snapshot record: the recovery-state
/// half of the admission. Fence and epoch MUST equal the dispatch grant's
/// (the child enforces equality); the remaining strings bind the channel
/// and the protected snapshot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmSnapshotRecord {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation (must equal the grant fence generation).
    pub generation: u64,
    /// Live authority epoch (must equal the grant epoch).
    pub authority_epoch: EpochId,
    /// SHA-256 of the admitted Kernel artifact (hex).
    pub artifact_digest: String,
    /// SHA-256 of the protected handoff snapshot (hex).
    pub protected_snapshot_digest: String,
    /// Authenticated Kernel principal identity.
    pub principal: String,
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
    /// Composition profile the reaped child runs under
    /// (`D2_OPERATIONAL` or `FULL_COMPOSITION`). The owner selects the
    /// composition; the child requires the spelling and refuses unless the
    /// profile is compiled into its binary. Part of the canonical intent
    /// argv (`--profile <profile>` first), so the owner join derives it
    /// identically.
    pub profile: String,
    /// Owner-authored component manifest record.
    pub manifest: WasmManifestRecord,
    /// Owner-authored work identity record.
    pub work: WasmWorkRecord,
    /// Owner-authored source-assurance record.
    pub assurance: WasmAssuranceRecord,
    /// Owner-authored promotion oracle record.
    pub promotion: WasmPromotionRecord,
    /// Owner-attested Kernel generation snapshot record.
    pub snapshot: WasmSnapshotRecord,
}

/// Validates and builds the publishable dispatch material envelope from
/// live owners. Every identity is non-blank, every digest hex-shaped, every
/// enum spelling drawn from the closed owner sets the child maps
/// identically, the grant window non-empty; the grant digest re-binds the
/// envelope's own admission identity so a mixed envelope fails closed at
/// the child.
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
    profile: &str,
    manifest: WasmManifestRecord,
    work: WasmWorkRecord,
    assurance: WasmAssuranceRecord,
    promotion: WasmPromotionRecord,
    snapshot: WasmSnapshotRecord,
) -> Result<WasmDispatchMaterial, WasmDispatchError> {
    require_nonblank(claim_id, "claim-id")?;
    require_nonblank(operation_id, "operation-id")?;
    require_nonblank(launch_nonce, "launch-nonce")?;
    require_nonblank(&guest.component_id, "guest-component-id")?;
    require_digest(&guest.artifact_digest, "guest-artifact-digest")?;
    require_digest(&guest.input_digest, "guest-input-digest")?;
    if profile != "D2_OPERATIONAL" && profile != "FULL_COMPOSITION" {
        return Err(invalid("profile"));
    }
    if admitted_at_unix_ms == 0 {
        return Err(invalid("admitted-at"));
    }
    if guest.max_output_bytes == 0
        || guest.max_fuel == 0
        || guest.max_memory_bytes == 0
        || guest.wall_deadline_ms == 0
        || guest.epoch_deadline_ticks == 0
        || guest.table_elements == 0
        || guest.max_instances == 0
        || guest.artifact_access_reads == 0
        || guest.artifact_access_bytes == 0
    {
        return Err(invalid("guest-ceilings"));
    }
    validate_manifest_record(&manifest)?;
    validate_work_record(&work)?;
    validate_assurance_record(&assurance)?;
    validate_promotion_record(&promotion)?;
    validate_snapshot_record(&snapshot)?;
    if manifest.required_verifier != assurance.required_verifier {
        return Err(invalid("verifier-agreement"));
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
        profile: profile.to_owned(),
        manifest,
        work,
        assurance,
        promotion,
        snapshot,
    })
}

/// Checks one value against a closed spelling set shared with the child
/// reader (which maps the identical sets and denies anything else).
fn require_spelling(
    value: &str,
    accepted: &[&str],
    field: &'static str,
) -> Result<(), WasmDispatchError> {
    if accepted.iter().any(|spelling| *spelling == value) {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

/// Validates the owner-authored manifest record: non-blank identities,
/// hex digests, non-empty privacy set, entry shapes. Closed-world values
/// (empty imports, exactly `run`, no grants) are enforced by the child;
/// the owner validates shape here so malformed records fail at publish.
fn validate_manifest_record(record: &WasmManifestRecord) -> Result<(), WasmDispatchError> {
    require_nonblank(&record.component_id, "manifest-component-id")?;
    require_nonblank(&record.world, "manifest-world")?;
    require_nonblank(&record.target, "manifest-target")?;
    require_digest(&record.source_digest, "manifest-source-digest")?;
    require_digest(&record.state_contract_digest, "manifest-state-digest")?;
    require_nonblank(&record.required_verifier, "manifest-verifier")?;
    if record.privacy_classes.is_empty() {
        return Err(invalid("manifest-privacy"));
    }
    for value in record
        .privacy_classes
        .iter()
        .chain(record.allowed_imports.iter())
        .chain(record.allowed_exports.iter())
        .chain(record.capability_grants.iter())
    {
        require_nonblank(value, "manifest-entries")?;
    }
    require_nonblank(&record.state_class, "manifest-state-class")?;
    require_nonblank(&record.migration_contract, "manifest-migration")?;
    require_nonblank(&record.privacy_policy, "manifest-privacy-policy")?;
    require_nonblank(&record.comparator, "manifest-comparator")?;
    Ok(())
}

/// Validates the owner-authored work record: identities, state markers
/// drawn from the closed sets, non-zero revisions.
fn validate_work_record(record: &WasmWorkRecord) -> Result<(), WasmDispatchError> {
    require_nonblank(&record.owner, "work-owner")?;
    require_nonblank(&record.work_unit, "work-unit")?;
    require_nonblank(&record.work_scope, "work-scope")?;
    require_nonblank(&record.lease_id, "lease-id")?;
    require_nonblank(&record.lease_scope_ref, "lease-scope")?;
    require_spelling(&record.lease_state, &["active"], "lease-state")?;
    require_spelling(
        &record.generation_state,
        &["ready", "active"],
        "generation-state",
    )?;
    if record.authority_revision == 0
        || record.lifecycle_revision == 0
        || record.verification_revision == 0
    {
        return Err(invalid("work-revisions"));
    }
    require_spelling(&record.contour, &["SHADOW", "CONFORMANCE"], "work-contour")?;
    if record.generation_health.len() != 6 {
        return Err(invalid("work-health"));
    }
    for value in record.generation_health.iter() {
        require_spelling(
            value,
            &["UNKNOWN", "HEALTHY", "DEGRADED", "FAILED"],
            "work-health",
        )?;
    }
    Ok(())
}

/// Validates the owner-authored assurance record: refs plus closed enum
/// spellings shared with the child mapper.
fn validate_assurance_record(record: &WasmAssuranceRecord) -> Result<(), WasmDispatchError> {
    require_nonblank(&record.source_ref, "assurance-source")?;
    require_nonblank(&record.provenance_ref, "assurance-provenance")?;
    require_spelling(
        &record.integrity,
        &["VERIFIED", "UNVERIFIED", "MODIFIED", "CONFLICTED"],
        "assurance-integrity",
    )?;
    require_spelling(
        &record.freshness,
        &["CURRENT", "STALE", "UNKNOWN"],
        "assurance-freshness",
    )?;
    require_spelling(
        &record.competence,
        &["DOMAIN_VERIFIED", "ATTRIBUTED", "UNKNOWN"],
        "assurance-competence",
    )?;
    require_spelling(
        &record.independence,
        &["INDEPENDENT", "RELATED", "COMMON_MODE", "UNKNOWN"],
        "assurance-independence",
    )?;
    require_spelling(
        &record.privacy_class,
        &["PUBLIC", "INTERNAL", "PRIVATE", "SECRET", "LICENSED"],
        "assurance-privacy",
    )?;
    require_spelling(
        &record.instruction_taint,
        &["CLEARED", "DATA_ONLY", "UNTRUSTED", "COMMAND_LIKE"],
        "assurance-taint",
    )?;
    for value in record.epistemic_use.iter() {
        require_spelling(
            value,
            &[
                "OBSERVATION",
                "ATTRIBUTED_INPUT",
                "CANDIDATE_EVIDENCE",
                "VERIFICATION_INPUT",
            ],
            "assurance-epistemic",
        )?;
    }
    for value in record.effect_ceilings.iter() {
        require_spelling(
            value,
            &["READ_ONLY", "CANDIDATE_ONLY", "NO_EXTERNAL_EFFECT"],
            "assurance-effects",
        )?;
    }
    require_nonblank(&record.required_verifier, "assurance-verifier")?;
    require_spelling(
        &record.quarantine,
        &["NONE", "REVIEW_REQUIRED", "QUARANTINED", "RELEASED"],
        "assurance-quarantine",
    )?;
    Ok(())
}

/// Validates the owner-authored promotion oracle record: four hex digests.
fn validate_promotion_record(record: &WasmPromotionRecord) -> Result<(), WasmDispatchError> {
    require_digest(&record.corpus_digest, "promotion-corpus")?;
    require_digest(&record.expected_result_digest, "promotion-result")?;
    require_digest(&record.expected_effect_digest, "promotion-effects")?;
    require_digest(&record.expected_state_delta_digest, "promotion-state-delta")?;
    Ok(())
}

/// Validates the owner-attested snapshot record: channel strings plus hex
/// digests plus a non-zero generation. Fence/epoch agreement with the grant
/// is enforced by the child, which derives every fence from the grant.
fn validate_snapshot_record(record: &WasmSnapshotRecord) -> Result<(), WasmDispatchError> {
    require_nonblank(&record.service, "snapshot-service")?;
    require_nonblank(&record.protocol, "snapshot-protocol")?;
    require_nonblank(&record.principal, "snapshot-principal")?;
    if record.generation == 0 {
        return Err(invalid("snapshot-generation"));
    }
    require_digest(&record.artifact_digest, "snapshot-artifact")?;
    require_digest(&record.protected_snapshot_digest, "snapshot-protected")?;
    Ok(())
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
            table_elements: 64,
            max_instances: 2,
            artifact_access_reads: 2,
            artifact_access_bytes: 131_072,
            component_id: "component-1955".to_owned(),
        }
    }

    fn test_manifest() -> WasmManifestRecord {
        WasmManifestRecord {
            component_id: "component-1955".to_owned(),
            world: "eliot:wasm/guest".to_owned(),
            target: "wasm32-wasip2".to_owned(),
            source_digest: "b".repeat(64),
            state_contract_digest: "f".repeat(64),
            required_verifier: "verifier:a12".to_owned(),
            privacy_classes: vec!["Internal".to_owned()],
            allowed_imports: Vec::new(),
            allowed_exports: vec!["run".to_owned()],
            capability_grants: Vec::new(),
            state_class: "stateless".to_owned(),
            migration_contract: "none".to_owned(),
            privacy_policy: "project_code".to_owned(),
            comparator: "shadow-exact".to_owned(),
            rollback_generation: None,
        }
    }

    fn test_work() -> WasmWorkRecord {
        WasmWorkRecord {
            owner: "owner-1955".to_owned(),
            work_unit: "work-1955".to_owned(),
            work_scope: "scope-1955".to_owned(),
            task_ref: Some("task-1955".to_owned()),
            lease_id: "lease-1955".to_owned(),
            lease_scope_ref: "scope-1955".to_owned(),
            lease_state: "active".to_owned(),
            generation_state: "ready".to_owned(),
            authority_revision: 1,
            lifecycle_revision: 1,
            verification_revision: 1,
            deterministic_seed: 7,
            contour: "CONFORMANCE".to_owned(),
            generation_health: vec![
                "HEALTHY".to_owned(),
                "HEALTHY".to_owned(),
                "HEALTHY".to_owned(),
                "HEALTHY".to_owned(),
                "HEALTHY".to_owned(),
                "HEALTHY".to_owned(),
            ],
        }
    }

    fn test_assurance() -> WasmAssuranceRecord {
        WasmAssuranceRecord {
            source_ref: "source-1955".to_owned(),
            provenance_ref: "provenance-1955".to_owned(),
            integrity: "VERIFIED".to_owned(),
            freshness: "CURRENT".to_owned(),
            competence: "DOMAIN_VERIFIED".to_owned(),
            independence: "INDEPENDENT".to_owned(),
            privacy_class: "INTERNAL".to_owned(),
            instruction_taint: "DATA_ONLY".to_owned(),
            epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
            effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
            required_verifier: "verifier:a12".to_owned(),
            quarantine: "NONE".to_owned(),
        }
    }

    fn test_promotion() -> WasmPromotionRecord {
        WasmPromotionRecord {
            corpus_digest: "0".repeat(64),
            expected_result_digest: "1".repeat(64),
            expected_effect_digest: "2".repeat(64),
            expected_state_delta_digest: "3".repeat(64),
        }
    }

    fn test_snapshot() -> WasmSnapshotRecord {
        WasmSnapshotRecord {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            generation: 7,
            authority_epoch: test_epoch(),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "S-1-5-18".to_owned(),
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
            "D2_OPERATIONAL",
            test_manifest(),
            test_work(),
            test_assurance(),
            test_promotion(),
            test_snapshot(),
        )
        .expect("material publishes");
        assert_eq!(material.wire_id, WASM_DISPATCH_MATERIAL_WIRE_ID);
        assert_eq!(material.wire_version, WASM_DISPATCH_MATERIAL_WIRE_VERSION);
        assert_eq!(material.profile, "D2_OPERATIONAL");
        assert_eq!(material.snapshot.service, "eliot-kernel");
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
                "D2_OPERATIONAL",
                test_manifest(),
                test_work(),
                test_assurance(),
                test_promotion(),
                test_snapshot(),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        // Unknown profile fails closed.
        assert!(matches!(
            publish_wasm_dispatch_material(
                "claim-wasm-r1-001",
                "operation-wasm-r1-001",
                Generation::new(7).expect("generation"),
                &test_epoch(),
                "launch-nonce-wasm-r1-0001",
                4_000_000_000_000,
                &"a".repeat(64),
                &"d".repeat(64),
                test_guest(),
                "FANCY_PROFILE",
                test_manifest(),
                test_work(),
                test_assurance(),
                test_promotion(),
                test_snapshot(),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        // Verifier disagreement between manifest and assurance fails closed.
        let mut assurance = test_assurance();
        assurance.required_verifier = "verifier:other".to_owned();
        assert!(matches!(
            publish_wasm_dispatch_material(
                "claim-wasm-r1-001",
                "operation-wasm-r1-001",
                Generation::new(7).expect("generation"),
                &test_epoch(),
                "launch-nonce-wasm-r1-0001",
                4_000_000_000_000,
                &"a".repeat(64),
                &"d".repeat(64),
                test_guest(),
                "D2_OPERATIONAL",
                test_manifest(),
                test_work(),
                assurance,
                test_promotion(),
                test_snapshot(),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
    }
}
