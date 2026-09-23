//! Owner-side WASM dispatch material publisher (issue #1955, I14.19).
//!
//! The Kernel half of the WASM P03 child contour: the owner publishes the
//! deterministic dispatch derivation the child re-derives byte-for-byte
//! ([`wasm_dispatch_derivation`]), the Kernel-issued launch grant funding
//! the one-shot permit ([`wasm_dispatch_grant_for`]), the dispatch material
//! envelope the delivery half stages next to the installed child image
//! ([`WasmDispatchMaterial`]), the owner-side join gate the live join table
//! closes over ([`wasm_join_gate`]), and the retained one-shot join registry
//! the central dispatch consults before admitting a presented request
//! ([`WasmJoinTable`]).
//!
//! Byte-identity with the child is proven by shared fixed vectors asserted
//! literally on both sides (R1 style): derivation domain, tagged-hash
//! construction, and grant-digest binding must agree exactly, or the
//! owner-published join never closes.
//!
//! Interface boundary (issue #1955 / A3 handoff): the registration lane
//! fills [`WasmOwnerClaim`] from live owners (epoch, generation, admission
//! time, claim identities, invocation facts, guest bytes) and passes the
//! installation-approved host binding —
//! `descriptor.wasm_host_artifact_binding()` values plus the install
//! directory — into [`publish_wasm_dispatch_bundle`]. This module takes the
//! binding as plain values rather than the registry descriptor because
//! `eliot-installation` is not a dependency of this crate; the caller owns
//! the validated accessor. No argv/env material, no executable bytes, no
//! minted ledger/registry/principal. Guest/input bytes cross opaquely:
//! dispatch binds their digests and never screens learning tickets —
//! ticket screening stays with the learning lane's guest gate
//! (`check_guest_tickets` over `AdmissionInput`), which owns those field
//! names; this module invents no second admission surface.

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
/// Grant window: the launch grant funds permits for sixty seconds from the
/// durable admission time. Freshness opens at admission, never at derivation.
pub const WASM_DISPATCH_GRANT_WINDOW_MS: u64 = 60_000;

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
/// owner-measured installed-image digest (the same pair the port grant
/// binds); the executor re-hashes the file before any start.
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
    let expires_at = admitted_at_unix_ms.saturating_add(WASM_DISPATCH_GRANT_WINDOW_MS);
    if expires_at == 0 || expires_at <= admitted_at_unix_ms {
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
/// Every value is authored by the admitting owner; the child re-proves
/// digests against real bytes and enforces the closed world. Field names
/// mirror the host `GenerationManifest` member for member so the child
/// assembles it without translation drift.
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
    /// Artifact digest of the prior conformance-verified run for this
    /// component lineage, when a Shadow operation must prove progression
    /// from it. `None` admits Conformance entry freely; Shadow requires
    /// `Some` exactly equal to the current artifact digest.
    pub prior_conformance_artifact: Option<String>,
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
    prior_conformance_artifact: Option<String>,
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
    if let Some(prior) = &prior_conformance_artifact {
        require_digest(prior, "prior-conformance")?;
    }
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
        prior_conformance_artifact,
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
    if accepted.contains(&value) {
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
    for value in &record.generation_health {
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
    for value in &record.epistemic_use {
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
    for value in &record.effect_ceilings {
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

/// Published join gate record: the owner-side forward issuance digest
/// the Kernel join table binds against the child's admitted request. The
/// child re-derives the identical digest from the same admitted material
/// (R1 interop vectors assert both literals); any drift fails the join
/// gate, never silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmJoinGate {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Child-identical authority identity string.
    pub authority_id: String,
    /// Opaque grant digest carried for correlation.
    pub grant_digest: String,
    /// Forward-issued invocation digest for the join table.
    pub invocation_digest: String,
    /// Grant expiry bounding the join window (Unix milliseconds).
    pub expires_at: u64,
}

/// Computes the owner-side join gate for one admitted claim: the identical
/// forward issuance the child performs in-process (deterministic key from
/// pre-binding admitted material, fence/lease from the grant window,
/// canonical intent, one-shot permit). The owner never issues a live
/// permit here — this pure computation publishes the digest the live
/// join gate closes over.
///
/// `host_executable_path` and `host_artifact_digest` are the
/// installation-approved registry values the registration lane reads
/// through the descriptor's validated `wasm_host_artifact_binding()`
/// accessor; `install_dir` is their parent directory. Paths derive from
/// the registry binding, never from caller strings.
///
/// # Errors
///
/// Returns [`WasmDispatchError`] when any identity, digest, ceiling, or
/// issuance input fails closed.
///
/// The body is one straight-line forward computation by design: both
/// sides must derive the same digest from the same inputs, so the steps
/// stay in issuance order rather than split across helpers.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn wasm_join_gate(
    claim: &WasmOwnerClaim,
    host_executable_path: &str,
    host_artifact_digest: &str,
    install_dir: &std::path::Path,
) -> Result<WasmJoinGate, WasmDispatchError> {
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
        EnvironmentProjection, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
        OperationId, PermitIssuance, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits,
        SessionId,
    };
    use sha2::{Digest as _, Sha256};

    if claim.claim_id.trim().is_empty()
        || claim.operation_id.trim().is_empty()
        || claim.launch_nonce.trim().is_empty()
        || host_executable_path.trim().is_empty()
    {
        return Err(invalid("join-identities"));
    }
    if claim.generation == 0 || claim.admitted_at_unix_ms == 0 {
        return Err(invalid("join-window"));
    }
    require_digest(&claim.identity_digest, "join-identity-digest")?;
    require_digest(host_artifact_digest, "join-host-digest")?;
    // Derivation base identical to the child: the owner publisher runs the
    // identical forward computation so both sides derive the same key,
    // authority identity, and invocation digest.
    let epoch_json =
        serde_json::to_value(&claim.authority_epoch).map_err(|_| WasmDispatchError::Gate)?;
    let derived = wasm_dispatch_derivation_from_epoch_json(
        &claim.claim_id,
        &claim.operation_id,
        claim.generation,
        &epoch_json,
        &claim.launch_nonce,
    )?;
    let key_material = format!("key:{}", derived.base_json);
    let key_digest = Sha256::digest(key_material.as_bytes());
    let mut key_bytes = [0_u8; 32];
    key_bytes.copy_from_slice(&key_digest);
    let key =
        KernelDispatchKey::from_secret_bytes(key_bytes).map_err(|_| WasmDispatchError::Gate)?;
    let authority_id = DispatchAuthorityId::new(derived.authority_id.clone())
        .map_err(|_| WasmDispatchError::Gate)?;
    // Grant identical to the bundle publisher: the join test fixes the
    // same fence/lease derivation the child rebuilds.
    let generation =
        Generation::new(claim.generation).map_err(|_| invalid("join-generation"))?;
    let grant = wasm_dispatch_grant_for(
        &claim.identity_digest,
        &claim.authority_epoch,
        generation,
        claim.admitted_at_unix_ms,
        host_artifact_digest,
    )?;
    let fence = FencingToken::new(
        claim.authority_epoch.clone(),
        Generation::new(claim.generation).map_err(|_| invalid("join-generation"))?,
        grant.fence_nonce.clone(),
    )
    .map_err(|_| WasmDispatchError::Gate)?;
    let lease =
        ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(|_| WasmDispatchError::Gate)?;
    // Canonical intent identical to the child rule: operation/tree/job/
    // image/session/generation/exe/argv/workdir/env/limits, with the tree
    // bound to the work scope exactly like the child derivation.
    let short_host = host_artifact_digest
        .get(..16)
        .ok_or_else(|| invalid("join-host-digest"))?;
    let artifact_path = install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME);
    let input_path = install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME);
    let artifact_text = artifact_path
        .to_str()
        .ok_or_else(|| invalid("join-paths"))?;
    let input_text = input_path.to_str().ok_or_else(|| invalid("join-paths"))?;
    let working_text = install_dir
        .to_str()
        .ok_or_else(|| invalid("join-paths"))?;
    let environment = EnvironmentProjection::new(
        std::collections::BTreeMap::new(),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .map_err(|_| WasmDispatchError::Gate)?;
    let limits = ResourceLimits::new(
        claim.guest.wall_deadline_ms,
        None,
        Some(claim.guest.max_memory_bytes),
        claim.guest.max_output_bytes,
        claim.guest.max_output_bytes,
        1,
    )
    .map_err(|_| WasmDispatchError::Gate)?;
    let intent = ProcessIntent::new(
        OperationId::new(claim.operation_id.clone()).map_err(|_| invalid("join-operation"))?,
        ProcessTreeId::new(claim.work.work_scope.clone()).map_err(|_| invalid("join-tree"))?,
        JobId::new(claim.operation_id.clone()).map_err(|_| invalid("join-job"))?,
        ImageId::new(format!("wasm-host-image-{short_host}")).map_err(|_| invalid("join-image"))?,
        SessionId::new(claim.claim_id.clone()).map_err(|_| invalid("join-session"))?,
        Generation::new(claim.generation).map_err(|_| invalid("join-generation"))?,
        host_executable_path.to_owned(),
        host_artifact_digest.to_owned(),
        vec![
            "--profile".to_owned(),
            claim.profile.clone(),
            "--guest-exec".to_owned(),
            "--guest-exec-artifact".to_owned(),
            artifact_text.to_owned(),
            "--guest-exec-input".to_owned(),
            input_text.to_owned(),
            "--guest-exec-artifact-digest".to_owned(),
            claim.guest.artifact_digest.clone(),
            "--guest-exec-max-output".to_owned(),
            claim.guest.max_output_bytes.to_string(),
            "--guest-exec-max-fuel".to_owned(),
            claim.guest.max_fuel.to_string(),
            "--guest-exec-max-memory".to_owned(),
            claim.guest.max_memory_bytes.to_string(),
            "--guest-exec-wall-ms".to_owned(),
            claim.guest.wall_deadline_ms.to_string(),
            "--guest-exec-epoch-ticks".to_owned(),
            claim.guest.epoch_deadline_ticks.to_string(),
        ],
        working_text.to_owned(),
        environment,
        limits,
    )
    .map_err(|_| WasmDispatchError::Gate)?;
    let issuance = PermitIssuance::new(
        lease,
        fence,
        std::collections::BTreeMap::from([(
            WASM_DISPATCH_LAUNCH_GRANT_HEAD.to_owned(),
            derived.head_digest.clone(),
        )]),
        claim.admitted_at_unix_ms,
        grant.expires_at,
        claim.launch_nonce.clone(),
    )
    .map_err(|_| WasmDispatchError::Gate)?;
    let mut authority = DispatchPermitAuthority::activate(authority_id, key);
    let permit = authority
        .issue(&intent, issuance)
        .map_err(|_| WasmDispatchError::Gate)?;
    let request = ProcessRequest::new(intent, permit).map_err(|_| WasmDispatchError::Gate)?;
    Ok(WasmJoinGate {
        claim_id: claim.claim_id.clone(),
        operation_id: claim.operation_id.clone(),
        authority_id: derived.authority_id,
        grant_digest: grant.grant_digest,
        invocation_digest: request.invocation_digest().to_owned(),
        expires_at: grant.expires_at,
    })
}

/// Owner-side live join table: the retained registry of published joins
/// the central dispatch consults before admitting a presented request.
/// Lookup is by admitted (claim, operation) pair; admission consumes the
/// entry one-shot (replay of a consumed or foreign digest fails closed),
/// and entries carry the grant window so stale joins deny even on digest
/// match. Bounded by [`prune`](WasmJoinTable::prune); removal is explicit,
/// never silent eviction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WasmJoinTable {
    records: std::collections::HashMap<(String, String), WasmJoinRecord>,
}

/// One retained join record: the published digests plus the window and
/// the one-shot consumption flag.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WasmJoinRecord {
    authority_id: String,
    grant_digest: String,
    invocation_digest: String,
    expires_at: u64,
    consumed: bool,
}

/// Join admission denial: stable taxonomy, no digests echoed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JoinDeny {
    /// No join was published for the presented (claim, operation) pair.
    #[error("WASM_JOIN_DENY_MISSING")]
    Missing,
    /// The presented digest does not match the published join.
    #[error("WASM_JOIN_DENY_MISMATCH")]
    Mismatched,
    /// The published join window has passed.
    #[error("WASM_JOIN_DENY_STALE")]
    Stale,
    /// The published join was already consumed (replay refused).
    #[error("WASM_JOIN_DENY_REPLAYED")]
    Replayed,
}

impl WasmJoinTable {
    /// Registers one published join, replacing any prior record for the
    /// same pair (re-publication after a failed drive re-arms the exact
    /// operation; the staged files were just rewritten with it).
    pub fn register(&mut self, join: &WasmJoinGate) {
        self.records.insert(
            (join.claim_id.clone(), join.operation_id.clone()),
            WasmJoinRecord {
                authority_id: join.authority_id.clone(),
                grant_digest: join.grant_digest.clone(),
                invocation_digest: join.invocation_digest.clone(),
                expires_at: join.expires_at,
                consumed: false,
            },
        );
    }

    /// Admits one presented request against the retained join: the pair
    /// must be published and fresh, the digest must match exactly, and a
    /// consumed join never admits twice. Success consumes the entry.
    /// Stale entries are removed on sight so the table cannot fill with
    /// dead joins.
    pub fn admit(
        &mut self,
        claim_id: &str,
        operation_id: &str,
        presented_digest: &str,
        now_ms: u64,
    ) -> Result<(), JoinDeny> {
        let key = (claim_id.to_owned(), operation_id.to_owned());
        let record = self.records.get(&key).ok_or(JoinDeny::Missing)?;
        if record.expires_at <= now_ms {
            self.records.remove(&key);
            return Err(JoinDeny::Stale);
        }
        if record.consumed {
            return Err(JoinDeny::Replayed);
        }
        if record.invocation_digest != presented_digest {
            return Err(JoinDeny::Mismatched);
        }
        if let Some(record) = self.records.get_mut(&key) {
            record.consumed = true;
        }
        Ok(())
    }

    /// Removes expired joins; returns the count removed.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.records.len();
        self.records.retain(|_, record| record.expires_at > now_ms);
        before - self.records.len()
    }

    /// Counts retained joins (published minus pruned).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether no joins are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Canonical material bytes for delivery: exact JSON the child parses.
pub fn material_bytes(material: &WasmDispatchMaterial) -> Result<Vec<u8>, WasmDispatchError> {
    serde_json::to_vec(material).map_err(|_| WasmDispatchError::Gate)
}

/// Owner-authored claim bundle for one dispatch publication: every record
/// the envelope carries plus the guest bytes to stage. The registration
/// lane fills this from live owners; the publisher validates, binds the
/// registry host digest, and stages the delivery set. No file paths enter
/// here — delivery targets derive from the installation-approved host
/// binding passed alongside the claim.
pub struct WasmOwnerClaim {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation (non-zero).
    pub generation: u64,
    /// Live authority epoch bound at admission.
    pub authority_epoch: EpochId,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Admission-bound identity digest (hex).
    pub identity_digest: String,
    /// Guest ceilings and pinned identities.
    pub guest: WasmGuestCeilings,
    /// Owner-selected composition profile.
    pub profile: String,
    /// Owner-authored manifest record.
    pub manifest: WasmManifestRecord,
    /// Owner-authored work record.
    pub work: WasmWorkRecord,
    /// Owner-authored assurance record.
    pub assurance: WasmAssuranceRecord,
    /// Owner-authored promotion record.
    pub promotion: WasmPromotionRecord,
    /// Owner-attested snapshot record.
    pub snapshot: WasmSnapshotRecord,
    /// Artifact digest of the prior conformance-verified run, if the
    /// operation must prove progression from it.
    pub prior_conformance_artifact: Option<String>,
    /// Exact guest artifact bytes to stage.
    pub artifact_bytes: Vec<u8>,
    /// Exact guest input bytes to stage.
    pub input_bytes: Vec<u8>,
}

/// Published delivery set: the envelope plus the exact paths staged in the
/// install directory. Paths derive from the installation-approved host
/// binding, never from caller strings.
pub struct WasmPublishedBundle {
    /// Validated envelope as published.
    pub material: WasmDispatchMaterial,
    /// Owner-side join gate for the live join table.
    pub join: WasmJoinGate,
    /// Staged material file path.
    pub material_path: std::path::PathBuf,
    /// Staged artifact file path.
    pub artifact_path: std::path::PathBuf,
    /// Staged input file path.
    pub input_path: std::path::PathBuf,
}

/// Publishes one dispatch bundle from retained actual owner state plus the
/// installation-approved host binding: validates every record, binds the
/// registry digest into the grant and the envelope, re-hashes the staged
/// bytes against the bound digests, computes the owner-side join gate, and
/// stages the three delivery files in the install directory. No ambient
/// paths, no caller-asserted digests, no minted window: freshness opens at
/// the durable admission time through the grant expiry.
///
/// `host_executable_path` / `host_artifact_digest` are the registry values
/// the registration lane reads through the descriptor's validated
/// `wasm_host_artifact_binding()` accessor (the descriptor self-validates
/// first — an unvalidated registry denies at the caller, never
/// downstream); `install_dir` is their parent directory.
///
/// # Errors
///
/// Returns [`WasmDispatchError`] when any record, the host binding, the
/// byte bindings, or the file staging fails closed.
pub fn publish_wasm_dispatch_bundle(
    host_executable_path: &str,
    host_artifact_digest: &str,
    install_dir: &std::path::Path,
    claim: &WasmOwnerClaim,
    joins: &mut WasmJoinTable,
) -> Result<WasmPublishedBundle, WasmDispatchError> {
    if host_executable_path.trim().is_empty() {
        return Err(invalid("registry-host-path"));
    }
    require_digest(host_artifact_digest, "registry-host-digest")?;
    if claim.artifact_bytes.is_empty() || claim.input_bytes.is_empty() {
        return Err(invalid("guest-bytes"));
    }
    if sha256_hex(&claim.artifact_bytes) != claim.guest.artifact_digest
        || sha256_hex(&claim.input_bytes) != claim.guest.input_digest
    {
        return Err(invalid("guest-bytes-binding"));
    }
    let material = publish_wasm_dispatch_material(
        &claim.claim_id,
        &claim.operation_id,
        eliot_process::Generation::new(claim.generation).map_err(|_| invalid("generation"))?,
        &claim.authority_epoch,
        &claim.launch_nonce,
        claim.admitted_at_unix_ms,
        &claim.identity_digest,
        host_artifact_digest,
        claim.guest.clone(),
        &claim.profile,
        claim.manifest.clone(),
        claim.work.clone(),
        claim.assurance.clone(),
        claim.promotion.clone(),
        claim.snapshot.clone(),
        claim.prior_conformance_artifact.clone(),
    )?;
    let material_path = install_dir.join(WASM_HOST_MATERIAL_FILE_NAME);
    let artifact_path = install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME);
    let input_path = install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME);
    let join = wasm_join_gate(
        claim,
        host_executable_path,
        host_artifact_digest,
        install_dir,
    )?;
    let io_denied = |_| invalid("delivery-io");
    std::fs::write(&material_path, material_bytes(&material)?).map_err(io_denied)?;
    std::fs::write(&artifact_path, &claim.artifact_bytes).map_err(io_denied)?;
    std::fs::write(&input_path, &claim.input_bytes).map_err(io_denied)?;
    // Register only after every file staged: a failed delivery leaves no
    // phantom join behind.
    joins.register(&join);
    Ok(WasmPublishedBundle {
        material,
        join,
        material_path,
        artifact_path,
        input_path,
    })
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

    /// R1 owner vector: the child asserts these identical derivation
    /// literals. The tagged-hash literals below were verified out-of-band
    /// (SHA-256 over the pinned base string); agreement here is the
    /// interop proof — the owner-published join closes if and only if the
    /// child re-derives these values.
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
        assert_eq!(
            derived.key_hex,
            "0193605024e5f08f25d5bc634da68297537812c63a01e5e77c361c2294289cde"
        );
        assert_eq!(
            derived.head_digest,
            "507662ddba16c457d9a45aec2a77ba4a00dc442cf71f4ef44a6b9a1acb3227c1"
        );
        assert_eq!(
            derived.authority_id,
            format!(
                "{WASM_DISPATCH_AUTHORITY_PREFIX}a121624956c2616bddc7a09e6d326443c1afc68daefcfa9e851ad5577d94760e"
            )
        );
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

    /// Grant publisher binds identity and window; the grant digest literal
    /// was verified out-of-band over the pinned material string.
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
        assert_eq!(
            grant.grant_digest,
            "7784765515b9156f2f533f29b93031acca875a97906a2b92bd5f756140871b1d"
        );
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

    fn test_claim() -> WasmOwnerClaim {
        WasmOwnerClaim {
            claim_id: "claim-bundle-001".to_owned(),
            operation_id: "operation-bundle-001".to_owned(),
            generation: 7,
            authority_epoch: test_epoch(),
            launch_nonce: "launch-nonce-bundle-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            identity_digest: "a".repeat(64),
            guest: test_guest(),
            profile: "D2_OPERATIONAL".to_owned(),
            manifest: test_manifest(),
            work: test_work(),
            assurance: test_assurance(),
            promotion: test_promotion(),
            snapshot: test_snapshot(),
            prior_conformance_artifact: None,
            artifact_bytes: b"bundle-artifact-bytes".to_vec(),
            input_bytes: b"bundle-input-bytes".to_vec(),
        }
    }

    fn stage_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).expect("stage dir writable");
        dir
    }

    /// Byte binding fails before any join registers or any file stages:
    /// the claim digests (fixture hex) do not match the staged bytes. The
    /// table stays empty: nothing registers without a staged bundle.
    #[test]
    fn bundle_rejects_mismatched_bytes_without_side_effects() {
        let dir = stage_dir("eliot-wasm-dispatch-2377-mismatch");
        let mut joins = WasmJoinTable::default();
        assert!(matches!(
            publish_wasm_dispatch_bundle(
                "C:\\Kernel\\eliot-wasm-host.exe",
                &"d".repeat(64),
                &dir,
                &test_claim(),
                &mut joins
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        assert!(joins.is_empty());
        assert!(!dir.join(WASM_HOST_MATERIAL_FILE_NAME).exists());
        // Empty bytes fail closed first of all.
        let mut empty = test_claim();
        empty.artifact_bytes.clear();
        assert!(matches!(
            publish_wasm_dispatch_bundle(
                "C:\\Kernel\\eliot-wasm-host.exe",
                &"d".repeat(64),
                &dir,
                &empty,
                &mut joins
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        assert!(joins.is_empty());
    }

    /// A digest-bound claim stages three files and registers exactly one
    /// join; the staged envelope reparses to the published material.
    #[test]
    fn bundle_stages_files_and_registers_join() {
        let dir = stage_dir("eliot-wasm-dispatch-2377-staged");
        let artifact = b"staged-artifact-bytes".to_vec();
        let input = b"staged-input-bytes".to_vec();
        let mut claim = test_claim();
        claim.guest.artifact_digest = sha256_hex(&artifact);
        claim.guest.input_digest = sha256_hex(&input);
        claim.artifact_bytes = artifact;
        claim.input_bytes = input;
        let mut joins = WasmJoinTable::default();
        let bundle = publish_wasm_dispatch_bundle(
            "C:\\Kernel\\eliot-wasm-host.exe",
            &"d".repeat(64),
            &dir,
            &claim,
            &mut joins,
        )
        .expect("bundle publishes");
        assert_eq!(bundle.material_path, dir.join(WASM_HOST_MATERIAL_FILE_NAME));
        assert_eq!(bundle.artifact_path, dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME));
        assert_eq!(bundle.input_path, dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME));
        assert!(bundle.material_path.is_file());
        assert_eq!(joins.len(), 1);
        let bytes = std::fs::read(&bundle.material_path).expect("material readable");
        let reparsed: WasmDispatchMaterial =
            serde_json::from_slice(&bytes).expect("material reparses");
        assert_eq!(reparsed, bundle.material);
        // The registered join admits its own digest once, inside the window.
        assert_eq!(
            joins.admit(
                &claim.claim_id,
                &claim.operation_id,
                &bundle.join.invocation_digest,
                4_000_000_030_000
            ),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live join-table enforcement: hit allows once, then replay denies;
    /// miss, mismatch, and stale deny without effect. Pure registry logic
    /// over retained records — the central dispatch calls exactly this.
    #[test]
    fn join_table_admits_once_then_denies() {
        let gate = WasmJoinGate {
            claim_id: "claim-join-001".to_owned(),
            operation_id: "operation-join-001".to_owned(),
            authority_id: "wasm-host-dispatch-authority-test".to_owned(),
            grant_digest: "e".repeat(64),
            invocation_digest: "f".repeat(64),
            expires_at: 4_000_000_060_000,
        };
        let mut table = WasmJoinTable::default();
        assert!(table.is_empty());
        table.register(&gate);
        assert_eq!(table.len(), 1);
        // Hit: exact digest inside the window allows and consumes.
        assert_eq!(
            table.admit(
                "claim-join-001",
                "operation-join-001",
                &"f".repeat(64),
                4_000_000_030_000
            ),
            Ok(())
        );
        // Replay: the consumed join never admits twice.
        assert_eq!(
            table.admit(
                "claim-join-001",
                "operation-join-001",
                &"f".repeat(64),
                4_000_000_030_000
            ),
            Err(JoinDeny::Replayed)
        );
        // Miss: unknown pair denies.
        assert_eq!(
            table.admit(
                "claim-foreign",
                "operation-join-001",
                &"f".repeat(64),
                4_000_000_030_000
            ),
            Err(JoinDeny::Missing)
        );
        // Mismatch: wrong digest denies; the record is retained (a
        // corrected presentation after re-publication can still close).
        table.register(&gate);
        assert_eq!(
            table.admit(
                "claim-join-001",
                "operation-join-001",
                &"0".repeat(64),
                4_000_000_030_000
            ),
            Err(JoinDeny::Mismatched)
        );
        // Stale: past the window denies and evicts.
        assert_eq!(
            table.admit(
                "claim-join-001",
                "operation-join-001",
                &"f".repeat(64),
                4_000_000_060_000
            ),
            Err(JoinDeny::Stale)
        );
        assert!(table.is_empty());
        // Prune: expired records removed with an exact count.
        table.register(&gate);
        assert_eq!(table.prune(4_000_000_060_000), 1);
        assert!(table.is_empty());
        assert_eq!(table.prune(1), 0);
    }

    /// R1 join vector: fixed claim + registry values produce a stable
    /// owner-side gate. The A3 child lane asserts the identical
    /// invocation digest from the same admitted values
    /// (`bins/eliot-wasm-host/src/dispatch_authority.rs`, join issuance
    /// pin); agreement is the join interop proof — the owner-published
    /// join closes if and only if the child re-derives these values. The
    /// exact-literal pin lands at that integration with test execution;
    /// here the gate shape, window binding, and replay-stability close.
    #[test]
    fn join_gate_computes_stable_owner_vector() {
        fn join_claim() -> WasmOwnerClaim {
            WasmOwnerClaim {
                claim_id: "claim-wasm-join-001".to_owned(),
                operation_id: "operation-wasm-join-001".to_owned(),
                generation: 7,
                authority_epoch: test_epoch(),
                launch_nonce: "launch-nonce-wasm-join-0001".to_owned(),
                admitted_at_unix_ms: 4_000_000_000_000,
                identity_digest: "a".repeat(64),
                guest: WasmGuestCeilings {
                    artifact_digest: sha256_hex(b"join-artifact-bytes"),
                    input_digest: sha256_hex(b"join-input-bytes"),
                    max_output_bytes: 4096,
                    max_fuel: 100_000,
                    max_memory_bytes: 536_870_912,
                    wall_deadline_ms: 30_000,
                    epoch_deadline_ticks: 100,
                    table_elements: 64,
                    max_instances: 2,
                    artifact_access_reads: 2,
                    artifact_access_bytes: 131_072,
                    component_id: "component-join".to_owned(),
                },
                profile: "D2_OPERATIONAL".to_owned(),
                manifest: test_manifest(),
                work: test_work(),
                assurance: test_assurance(),
                promotion: test_promotion(),
                snapshot: test_snapshot(),
                prior_conformance_artifact: None,
                artifact_bytes: b"join-artifact-bytes".to_vec(),
                input_bytes: b"join-input-bytes".to_vec(),
            }
        }
        let join = wasm_join_gate(
            &join_claim(),
            "C:\\Kernel\\eliot-wasm-host.exe",
            &"d".repeat(64),
            std::path::Path::new("C:\\Kernel"),
        )
        .expect("join gate computes");
        assert_eq!(join.claim_id, "claim-wasm-join-001");
        assert_eq!(join.operation_id, "operation-wasm-join-001");
        assert!(join.authority_id.starts_with(WASM_DISPATCH_AUTHORITY_PREFIX));
        assert_eq!(join.invocation_digest.len(), 64);
        assert_eq!(join.expires_at, 4_000_000_060_000);
        // Replay-stable: identical inputs rebuild the identical gate.
        let replay = wasm_join_gate(
            &join_claim(),
            "C:\\Kernel\\eliot-wasm-host.exe",
            &"d".repeat(64),
            std::path::Path::new("C:\\Kernel"),
        )
        .expect("join gate recomputes");
        assert_eq!(join, replay);
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
            None,
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
                None,
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
                "FULL_COMPOSITION",
                test_manifest(),
                test_work(),
                test_assurance(),
                test_promotion(),
                test_snapshot(),
                None,
            ),
            Ok(_)
        ));
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
                "LABORATORY",
                test_manifest(),
                test_work(),
                test_assurance(),
                test_promotion(),
                test_snapshot(),
                None,
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
        // Malformed prior digest fails closed.
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
                test_assurance(),
                test_promotion(),
                test_snapshot(),
                Some("not-a-digest".to_owned()),
            ),
            Err(WasmDispatchError::InvalidMaterial(_))
        ));
    }
}
