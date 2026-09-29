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
/// Versioned delivery-identity wire version (#2786 step 1). The child
/// never parses this (the envelope stays wire v1); slot markers and the
/// owner join table bind it.
pub const WASM_DELIVERY_IDENTITY_VERSION: u16 = 1;
/// Generation-slot parent directory name under the install directory.
/// Each publication stages one immutable slot here before exposing the
/// fixed-name set the child reads.
pub const WASM_DELIVERY_SLOT_DIR_NAME: &str = "eliot-wasm-host.generations";
/// Pending-publication marker file name inside a generation slot.
pub const WASM_DELIVERY_PENDING_FILE_NAME: &str = "PENDING.json";
/// Ready-marker file name inside a generation slot, written last.
pub const WASM_DELIVERY_READY_FILE_NAME: &str = "READY.json";
/// Failed-publication marker file name inside a generation slot.
pub const WASM_DELIVERY_FAILED_FILE_NAME: &str = "FAILED.json";
/// Authoritative per-delivery launch/custody disposition in a generation slot.
pub const WASM_DELIVERY_DISPOSITION_FILE_NAME: &str = "DISPOSITION.json";
/// Child-owned terminal result retained in the same generation slot.
pub const WASM_DELIVERY_RESULT_FILE_NAME: &str = "RESULT.json";
/// Wire version for the durable per-slot owner/child disposition record.
pub const WASM_DELIVERY_DISPOSITION_VERSION: u16 = 1;
/// Bound on unresolved active generation slots per install directory.
/// Terminal and spent dispositions remain in the separately bounded compact
/// history so exact replay and publication revisions survive restart.
pub const MAX_DELIVERY_SLOTS: usize = 8;
/// Bound on one staged guest payload: the transport frame contour
/// (`eliot_protocol::MAX_FRAME_BYTES`). The daemon gates arrivals at
/// this bound; the publisher re-enforces it so an oversized claim can
/// never stage unbounded bytes.
pub const MAX_DELIVERY_PAYLOAD_BYTES: usize = eliot_protocol::MAX_FRAME_BYTES;
/// Bound on directory entries scanned during slot discovery and recovery.
/// Discovery never walks an unbounded directory.
const MAX_SLOT_SCAN_ENTRIES: usize = 64;
/// The slot history remains bounded even when reclaimed payloads leave a
/// compact per-delivery disposition tombstone behind.
const MAX_DELIVERY_HISTORY: usize = MAX_SLOT_SCAN_ENTRIES;
/// A disposition contains identities and receipt digests only, never a
/// result body or guest payload.
const MAX_DELIVERY_DISPOSITION_BYTES: u64 = 64 * 1024;
/// Bound on all retained payload/material bytes and compact slot receipts.
/// Each active slot reserves room for the result stream in addition to the
/// artifact, input, and envelope; spent history retains only its three small
/// publication/disposition records.
pub const MAX_DELIVERY_RETAINED_BYTES: u64 = (MAX_DELIVERY_SLOTS as u64)
    * ((MAX_DELIVERY_PAYLOAD_BYTES as u64) * 4 + MAX_DELIVERY_DISPOSITION_BYTES * 4)
    + (MAX_DELIVERY_HISTORY as u64) * MAX_DELIVERY_DISPOSITION_BYTES * 3;

/// Fail-closed owner-side dispatch errors. No material content echoed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WasmDispatchError {
    /// A material field failed shape validation.
    #[error("WASM_DISPATCH_INVALID_MATERIAL:{0}")]
    InvalidMaterial(String),
    /// A gate-owned construction failed (message only, no material).
    #[error("WASM_DISPATCH_GATE")]
    Gate,
    /// A replacement publication was refused: another delivery owns the
    /// fixed names. Typed bounded backpressure (#2786 step 4): the
    /// caller retries exactly when the carried condition holds, never by
    /// overwriting the live set.
    #[error("WASM_DISPATCH_BACKPRESSURE")]
    Backpressure(WasmDeliveryBackpressure),
    /// The requested logical operation or delivery identity conflicts with
    /// an already retained owner commitment; no launch or replacement occurs.
    #[error("WASM_DISPATCH_DELIVERY_CONFLICT")]
    DeliveryConflict,
    /// Authoritative publication/disposition state is absent, malformed,
    /// incomplete, or could not be read under the installation lock.
    #[error("WASM_DISPATCH_DELIVERY_UNAVAILABLE")]
    DeliveryUnavailable,
}

/// Typed replacement backpressure (#2786 step 4): the protected delivery
/// occupying owner capacity, with its exact retry condition. Carries
/// identities only, never guest bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmDeliveryBackpressure {
    /// Live delivery generation holding the fixed names.
    pub live_generation: u64,
    /// Live delivery operation holding the fixed names.
    pub live_operation_id: String,
    /// Live delivery grant expiry (Unix milliseconds).
    pub live_expires_at: u64,
    /// Exact retry condition, e.g. `current delivery consumed`.
    pub retry_condition: String,
    /// Exact owner recovery locator for the unresolved delivery.
    pub recovery_reference: WasmDeliveryRecoveryReference,
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

/// Owner-issued versioned delivery-set identity (#2786 step 1).
///
/// Binds installation/artifact generation, claim and operation, grant and
/// fence generation, envelope/material-set digest, artifact/input digests,
/// publication incarnation/revision, and supported expiry. The leading
/// fields name the host-side `StagedDeliveryIdentity` claim/ack record
/// member for member (`claim_id`, `operation_id`, `generation`,
/// `launch_nonce`, `grant_digest`, `fence_generation`,
/// `artifact_digest`, `input_digest`, `admitted_at_unix_ms`,
/// `expires_at`, `authority_epoch_json`); the kernel additions
/// (`delivery_version`, `envelope_digest`, `host_artifact_digest`,
/// `publication_incarnation`, `publication_revision`) travel only in
/// slot markers and the owner join table, never in the child-parsed
/// envelope, which stays wire v1 because the child denies unknown
/// fields.
///
/// A directory/path is only a locator: this identity is what claims bind.
/// It reuses the envelope's typed IDs (`Generation`, `EpochId`) and
/// owner receipts, grants no execution beyond the already-issued grant,
/// and is not a [`WasmJoinGate`] replacement — the one-shot join table
/// still admits every launch.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmDeliveryIdentity {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation (non-zero).
    pub generation: u64,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Grant fence generation.
    pub fence_generation: u64,
    /// Re-proven artifact digest (hex).
    pub artifact_digest: String,
    /// Re-proven input digest (hex).
    pub input_digest: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Delivery-identity wire version (`WASM_DELIVERY_IDENTITY_VERSION`).
    pub delivery_version: u16,
    /// Envelope/material-set digest: SHA-256 over the exact staged
    /// envelope bytes (hex).
    pub envelope_digest: String,
    /// Owner-measured SHA-256 of the installed child image bytes (hex):
    /// the installation binding.
    pub host_artifact_digest: String,
    /// Publication incarnation: the durable admission time, stable across
    /// replays of one admission.
    pub publication_incarnation: u64,
    /// Monotonic publication revision allocated under the install-root lock
    /// across the retained owner history.
    pub publication_revision: u64,
}

impl WasmDeliveryIdentity {
    /// Derives the delivery identity from a validated envelope plus the
    /// owner-computed envelope digest, installation binding, and
    /// publication revision. Fails closed on any unbound input.
    ///
    /// # Errors
    ///
    /// Returns [`WasmDispatchError`] when the generation, any digest, the
    /// admission window, or the revision is unbound.
    pub fn from_material(
        material: &WasmDispatchMaterial,
        envelope_digest: &str,
        host_artifact_digest: &str,
        publication_revision: u64,
    ) -> Result<Self, WasmDispatchError> {
        if material.generation == 0 || material.admitted_at_unix_ms == 0 {
            return Err(invalid("delivery-window"));
        }
        if publication_revision == 0 {
            return Err(invalid("delivery-revision"));
        }
        require_digest(envelope_digest, "delivery-envelope-digest")?;
        require_digest(host_artifact_digest, "delivery-host-digest")?;
        require_digest(&material.grant.grant_digest, "delivery-grant-digest")?;
        require_digest(&material.guest.artifact_digest, "delivery-artifact-digest")?;
        require_digest(&material.guest.input_digest, "delivery-input-digest")?;
        if material.grant.expires_at == 0
            || material.grant.expires_at <= material.admitted_at_unix_ms
            || material.grant.host_artifact_digest != host_artifact_digest
        {
            return Err(invalid("delivery-expiry"));
        }
        // Canonical epoch JSON identical to the child's staged
        // `authority_epoch_json`: `EpochId` serializes `lineage_id` before
        // `sequence`, which is also alphabetical order, so the child's
        // parsed-value re-serialization matches byte-for-byte.
        let authority_epoch_json = serde_json::to_string(&material.authority_epoch)
            .map_err(|_| WasmDispatchError::Gate)?;
        Ok(Self {
            claim_id: material.claim_id.clone(),
            operation_id: material.operation_id.clone(),
            generation: material.generation,
            launch_nonce: material.launch_nonce.clone(),
            grant_digest: material.grant.grant_digest.clone(),
            fence_generation: material.grant.fence_generation,
            artifact_digest: material.guest.artifact_digest.clone(),
            input_digest: material.guest.input_digest.clone(),
            admitted_at_unix_ms: material.admitted_at_unix_ms,
            expires_at: material.grant.expires_at,
            authority_epoch_json,
            delivery_version: WASM_DELIVERY_IDENTITY_VERSION,
            envelope_digest: envelope_digest.to_owned(),
            host_artifact_digest: host_artifact_digest.to_owned(),
            publication_incarnation: material.admitted_at_unix_ms,
            publication_revision,
        })
    }

    /// Whether a live envelope still names this exact delivery, including
    /// the grant/artifact/input digests (the preserved #2895 comparison
    /// as a subset) plus the envelope digest. Anything else is a
    /// replacement the caller must leave untouched.
    #[must_use]
    pub fn matches_material(&self, material: &WasmDispatchMaterial) -> bool {
        let envelope_matches =
            material_bytes(material).is_ok_and(|bytes| sha256_hex(&bytes) == self.envelope_digest);
        let authority_epoch_matches = serde_json::to_string(&material.authority_epoch)
            .is_ok_and(|json| json == self.authority_epoch_json);
        envelope_matches
            && authority_epoch_matches
            && self.claim_id == material.claim_id
            && self.operation_id == material.operation_id
            && self.generation == material.generation
            && self.launch_nonce == material.launch_nonce
            && self.grant_digest == material.grant.grant_digest
            && self.host_artifact_digest == material.grant.host_artifact_digest
            && self.fence_generation == material.grant.fence_generation
            && self.artifact_digest == material.guest.artifact_digest
            && self.input_digest == material.guest.input_digest
            && self.admitted_at_unix_ms == material.admitted_at_unix_ms
            && self.publication_incarnation == material.admitted_at_unix_ms
            && self.expires_at == material.grant.expires_at
    }

    /// Whether another identity names the same logical delivery: every
    /// bound field except the publication revision. Same-delivery replay
    /// matches here and returns the retained set, never a second
    /// publication.
    #[must_use]
    pub fn same_delivery(&self, other: &Self) -> bool {
        self.delivery_version == other.delivery_version
            && self.claim_id == other.claim_id
            && self.operation_id == other.operation_id
            && self.generation == other.generation
            && self.launch_nonce == other.launch_nonce
            && self.grant_digest == other.grant_digest
            && self.fence_generation == other.fence_generation
            && self.artifact_digest == other.artifact_digest
            && self.input_digest == other.input_digest
            && self.admitted_at_unix_ms == other.admitted_at_unix_ms
            && self.expires_at == other.expires_at
            && self.authority_epoch_json == other.authority_epoch_json
            && self.envelope_digest == other.envelope_digest
            && self.host_artifact_digest == other.host_artifact_digest
            && self.publication_incarnation == other.publication_incarnation
    }

    /// Immutable slot locator for this delivery: zero-padded generation
    /// plus the envelope digest prefix. The directory is only a locator;
    /// the identity is what claims bind.
    #[must_use]
    pub fn slot_name(&self) -> String {
        let prefix = self
            .envelope_digest
            .get(..16)
            .unwrap_or(&self.envelope_digest);
        format!("{:020}-{prefix}", self.generation)
    }
}

/// Stable recovery locator for one published delivery. It is an opaque
/// value, never a filesystem path or execution capability.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmDeliveryRecoveryReference {
    /// Delivery generation.
    pub generation: u64,
    /// Exact envelope/material-set commitment.
    pub envelope_digest: String,
    /// Durable publication incarnation.
    pub publication_incarnation: u64,
    /// Monotonic publication revision within the installation history.
    pub publication_revision: u64,
}

impl WasmDeliveryRecoveryReference {
    fn from_identity(identity: &WasmDeliveryIdentity) -> Self {
        Self {
            generation: identity.generation,
            envelope_digest: identity.envelope_digest.clone(),
            publication_incarnation: identity.publication_incarnation,
            publication_revision: identity.publication_revision,
        }
    }
}

/// Owner publication state for one generation slot (#2786 step 2):
/// filesystem publication and join registration cannot be atomic, so the
/// slot retains an explicit Pending/Ready/Failed state plus the
/// reconciliation identity. Readers never treat a slot without a Ready
/// marker as a complete set.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WasmPublicationState {
    /// Publication started; the immutable set is not yet complete.
    Pending {
        /// Publishing delivery identity.
        identity: WasmDeliveryIdentity,
    },
    /// Immutable slot set complete; fixed-name exposure is not
    /// implied. Ready is written at slot completion before fixed
    /// exposure, so a crash leaves a Ready slot over unexposed names
    /// until a same-delivery replay re-verifies the fixed payloads and
    /// re-exposes them from the slot. Join registration may still need
    /// replay after a crash between exposure and registration.
    Ready {
        /// Published delivery identity.
        identity: WasmDeliveryIdentity,
    },
    /// Publication failed; the retained identity and reason are recovery
    /// evidence, never a consumable set.
    Failed {
        /// Failed delivery identity.
        identity: WasmDeliveryIdentity,
        /// Stable failure reason (error code, never guest bytes).
        reason: String,
    },
}

impl WasmPublicationState {
    /// Borrows the reconciliation identity carried by this state.
    #[must_use]
    pub fn identity(&self) -> &WasmDeliveryIdentity {
        match self {
            Self::Pending { identity }
            | Self::Ready { identity }
            | Self::Failed { identity, .. } => identity,
        }
    }

    /// Stable code for this state.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "DELIVERY_PENDING",
            Self::Ready { .. } => "DELIVERY_READY",
            Self::Failed { .. } => "DELIVERY_FAILED",
        }
    }

    /// Whether the immutable set is complete.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Complete restart-discovery record for one delivery. A returned snapshot
/// always includes both the immutable publication state and its authoritative
/// execution/custody disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmDeliveryPublicationSnapshot {
    /// Immutable set publication marker.
    pub publication: WasmPublicationState,
    /// Durable launch and result-custody state.
    pub disposition: WasmDeliveryDispositionRecord,
}

/// Typed per-file owner-reclamation outcome (#2786 step 4/8): mirrors the
/// host `ReclaimOutcome` codes member for member. `NotFound`,
/// sharing-violation, and access-denial are distinct outcomes, never
/// success; the caller preserves them as a bounded residual instead of
/// overwriting the primary result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryReclaimOutcome {
    /// The presented file was removed.
    Reclaimed,
    /// No file was present; an already-reclaimed or never-staged path.
    NotFound,
    /// The file is open without delete sharing (Windows
    /// `ERROR_SHARING_VIOLATION`).
    SharingViolation,
    /// Removal was denied by ACL or platform policy.
    AccessDenied,
    /// Removal failed with another platform error kind (kind string only).
    Other(String),
}

impl DeliveryReclaimOutcome {
    /// Whether this outcome removed the presented bytes.
    #[must_use]
    pub const fn reclaimed(&self) -> bool {
        matches!(self, Self::Reclaimed)
    }

    /// Stable code for this outcome, shared with the host claim/ack half.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Reclaimed => "RECLAIM_RECLAIMED",
            Self::NotFound => "RECLAIM_NOT_FOUND",
            Self::SharingViolation => "RECLAIM_SHARING_VIOLATION",
            Self::AccessDenied => "RECLAIM_ACCESS_DENIED",
            Self::Other(_) => "RECLAIM_OTHER",
        }
    }
}

impl std::fmt::Display for DeliveryReclaimOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(kind) => {
                write!(formatter, "RECLAIM_OTHER:{kind}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

/// Per-file owner reclamation detail for one presented delivery. The
/// bounded fixed-name set is removed payloads first and envelope last while
/// the shared root lock and exact terminal disposition remain authoritative.
/// A crash mid-reclaim leaves the envelope identity available for recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmDeliveryReclamation {
    /// Reclaimed delivery identity.
    pub identity: WasmDeliveryIdentity,
    /// Guest artifact file outcome.
    pub artifact: DeliveryReclaimOutcome,
    /// Guest input file outcome.
    pub input: DeliveryReclaimOutcome,
    /// Material envelope file outcome.
    pub material: DeliveryReclaimOutcome,
}

impl WasmDeliveryReclamation {
    /// Whether every presented file was removed. A partial outcome is a
    /// bounded residual/maintenance obligation, never a primary-result
    /// overwrite.
    #[must_use]
    pub fn fully_reclaimed(&self) -> bool {
        self.artifact.reclaimed() && self.input.reclaimed() && self.material.reclaimed()
    }
}

/// Removes one presented staging file, reporting the exact platform
/// outcome. Callers first re-read the owner disposition under the shared
/// root lock and remove only names that disposition owns.
fn reclaim_one(path: &std::path::Path) -> DeliveryReclaimOutcome {
    match std::fs::remove_file(path) {
        Ok(()) => DeliveryReclaimOutcome::Reclaimed,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DeliveryReclaimOutcome::NotFound
        }
        Err(error) if error.raw_os_error() == Some(32) => DeliveryReclaimOutcome::SharingViolation,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            DeliveryReclaimOutcome::AccessDenied
        }
        Err(error) => DeliveryReclaimOutcome::Other(error.kind().to_string()),
    }
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
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Exact join binding retained beside one generation slot. Its wire fields
/// deliberately mirror `WasmJoinGate`; the durable owner record, not the
/// process-local join table, is authoritative after restart.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmJoinBinding {
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

impl From<&WasmJoinGate> for WasmJoinBinding {
    fn from(join: &WasmJoinGate) -> Self {
        Self {
            claim_id: join.claim_id.clone(),
            operation_id: join.operation_id.clone(),
            authority_id: join.authority_id.clone(),
            grant_digest: join.grant_digest.clone(),
            invocation_digest: join.invocation_digest.clone(),
            expires_at: join.expires_at,
        }
    }
}

/// Durable per-slot publication, execution, and result-custody state shared
/// with the WASM host. Every transition is serialized by the approved
/// installation-root lock and bound to the full publication identity.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WasmDeliveryDisposition {
    /// The immutable set is published but no launch reservation was issued.
    Ready {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
    },
    /// First-writer launch reservation committed before process start.
    LaunchReserved {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
        /// Stable identity-scoped launch incarnation, not a process ID.
        launch_incarnation: String,
    },
    /// The child durably claimed this launch before any guest effect.
    InFlight {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
        /// Stable identity-scoped launch incarnation, not a process ID.
        launch_incarnation: String,
        /// Distinct process-local child claimant incarnation.
        claimant_incarnation: String,
        /// Runtime request digest, distinct from the envelope commitment.
        runtime_request_digest: String,
    },
    /// A terminal stream remains in RESULT.json until an exact receiver ACK
    /// and settlement receipts are owner-recorded.
    TerminalUnacknowledged {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
        /// Stable identity-scoped launch incarnation, not a process ID.
        launch_incarnation: String,
        /// Distinct process-local child claimant incarnation.
        claimant_incarnation: String,
        /// Runtime request digest, distinct from the envelope commitment.
        runtime_request_digest: String,
        /// SHA-256 of exact bounded RESULT.json bytes.
        result_digest: String,
        /// Exact terminal event sequence (zero-based as in the retained stream).
        result_sequence: u64,
    },
    /// Future owner-authored terminal disposition. No current production
    /// caller writes this variant; reclamation requires every exact receipt.
    Acknowledged {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
        /// Stable identity-scoped launch incarnation, not a process ID.
        launch_incarnation: String,
        /// Distinct process-local child claimant incarnation.
        claimant_incarnation: String,
        /// Runtime request digest, distinct from the envelope commitment.
        runtime_request_digest: String,
        /// SHA-256 of exact bounded result bytes accepted by the receiver.
        result_digest: String,
        /// Exact terminal event sequence (zero-based as in the retained stream).
        result_sequence: u64,
        /// Exact receiver-side acknowledgement identity.
        receiver_ack_identity: String,
        /// Digest of the exact receiver ACK receipt.
        receiver_ack_digest: String,
        /// Sequence carried by the exact receiver ACK receipt.
        receiver_ack_sequence: u64,
        /// Digest of the existing process-settlement receipt.
        process_settlement_digest: String,
        /// Digest of the exact material-settlement receipt.
        material_settlement_digest: String,
    },
    /// Owner-proven no-effect retirement of a Ready delivery. A reserved,
    /// in-flight, or terminal delivery can never transition here.
    RetiredNoEffect {
        /// Full owner-issued publication identity.
        identity: WasmDeliveryIdentity,
        /// Exact six-field forward join binding.
        join: WasmJoinBinding,
        /// Whole envelope/material-set digest committed by the request.
        request_commitment: String,
        /// Digest of the exact owner retirement transition.
        retirement_digest: String,
    },
}

/// Versioned wrapper around the shared DISPOSITION.json wire record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmDeliveryDispositionRecord {
    /// Closed disposition record version.
    pub record_version: u16,
    /// Durable state and all identity commitments.
    pub disposition: WasmDeliveryDisposition,
}

impl WasmDeliveryDispositionRecord {
    fn ready(identity: &WasmDeliveryIdentity, join: &WasmJoinGate) -> Self {
        Self {
            record_version: WASM_DELIVERY_DISPOSITION_VERSION,
            disposition: WasmDeliveryDisposition::Ready {
                identity: identity.clone(),
                join: WasmJoinBinding::from(join),
                request_commitment: identity.envelope_digest.clone(),
            },
        }
    }

    /// Identity retained by this disposition.
    #[must_use]
    pub fn identity(&self) -> &WasmDeliveryIdentity {
        match &self.disposition {
            WasmDeliveryDisposition::Ready { identity, .. }
            | WasmDeliveryDisposition::LaunchReserved { identity, .. }
            | WasmDeliveryDisposition::InFlight { identity, .. }
            | WasmDeliveryDisposition::TerminalUnacknowledged { identity, .. }
            | WasmDeliveryDisposition::Acknowledged { identity, .. }
            | WasmDeliveryDisposition::RetiredNoEffect { identity, .. } => identity,
        }
    }

    fn join(&self) -> &WasmJoinBinding {
        match &self.disposition {
            WasmDeliveryDisposition::Ready { join, .. }
            | WasmDeliveryDisposition::LaunchReserved { join, .. }
            | WasmDeliveryDisposition::InFlight { join, .. }
            | WasmDeliveryDisposition::TerminalUnacknowledged { join, .. }
            | WasmDeliveryDisposition::Acknowledged { join, .. }
            | WasmDeliveryDisposition::RetiredNoEffect { join, .. } => join,
        }
    }

    fn request_commitment(&self) -> &str {
        match &self.disposition {
            WasmDeliveryDisposition::Ready {
                request_commitment, ..
            }
            | WasmDeliveryDisposition::LaunchReserved {
                request_commitment, ..
            }
            | WasmDeliveryDisposition::InFlight {
                request_commitment, ..
            }
            | WasmDeliveryDisposition::TerminalUnacknowledged {
                request_commitment, ..
            }
            | WasmDeliveryDisposition::Acknowledged {
                request_commitment, ..
            }
            | WasmDeliveryDisposition::RetiredNoEffect {
                request_commitment, ..
            } => request_commitment,
        }
    }
}

/// Closed result of claiming a published delivery. Only `Acquired` may
/// proceed to child launch; the other outcomes retain exact recovery state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum WasmLaunchDisposition {
    /// The caller won the durable first-writer reservation.
    Acquired {
        /// Stable identity-scoped launch incarnation, not a process ID.
        launch_incarnation: String,
    },
    /// The same delivery is already reserved or potentially executing.
    ExistingInFlight {
        /// Exact owner recovery locator; never authorizes a second launch.
        recovery_reference: WasmDeliveryRecoveryReference,
    },
    /// The exact terminal result is retained for receiver reconciliation.
    RetainedResult {
        /// Exact owner recovery locator; never authorizes a second launch.
        recovery_reference: WasmDeliveryRecoveryReference,
    },
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
    let generation = Generation::new(claim.generation).map_err(|_| invalid("join-generation"))?;
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
    let working_text = install_dir.to_str().ok_or_else(|| invalid("join-paths"))?;
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

/// One retained join record: the published digests plus the window,
/// the one-shot consumption flag, and the bound delivery identity.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WasmJoinRecord {
    authority_id: String,
    grant_digest: String,
    invocation_digest: String,
    expires_at: u64,
    consumed: bool,
    /// Bound delivery envelope digest (#2786 step 8): `Some` when the
    /// join was registered with its delivery identity, `None` for
    /// legacy registrations. Material cannot execute without its
    /// matching owner join/grant: delivery-bound admission requires
    /// this binding to match the claimed envelope.
    envelope_digest: Option<String>,
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
                envelope_digest: None,
            },
        );
    }

    /// Registers one published join bound to its delivery identity
    /// (#2786 steps 3 and 8): the join/launch binding of the claim. A
    /// byte-identical re-publication of an already-consumed delivery
    /// preserves the spent record instead of re-arming it, so an exact
    /// replay can never mint a second one-shot admission under the same
    /// authority. Any differing binding replaces the prior record; a
    /// fresh claim, grant, or launch nonce presents different digests,
    /// while a slot revision alone carries no new authority.
    pub fn register_delivery(&mut self, join: &WasmJoinGate, delivery: &WasmDeliveryIdentity) {
        let key = (join.claim_id.clone(), join.operation_id.clone());
        if let Some(record) = self.records.get(&key)
            && record.consumed
            && record.authority_id == join.authority_id
            && record.grant_digest == join.grant_digest
            && record.invocation_digest == join.invocation_digest
            && record.expires_at == join.expires_at
            && record.envelope_digest.as_deref() == Some(delivery.envelope_digest.as_str())
        {
            return;
        }
        self.records.insert(
            key,
            WasmJoinRecord {
                authority_id: join.authority_id.clone(),
                grant_digest: join.grant_digest.clone(),
                invocation_digest: join.invocation_digest.clone(),
                expires_at: join.expires_at,
                consumed: false,
                envelope_digest: Some(delivery.envelope_digest.clone()),
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

    /// Admits one presented claim against the retained delivery-bound
    /// join (#2786 step 8): [`admit`](WasmJoinTable::admit) plus the
    /// claimed envelope digest. The pair must be published and fresh,
    /// both digests must match exactly, and a consumed join never
    /// admits twice. A delivery-bound admission against a legacy
    /// unbound record denies; material cannot execute without its
    /// matching owner join/grant. Success consumes the entry; stale
    /// entries are removed on sight.
    pub fn admit_claim(
        &mut self,
        claim_id: &str,
        operation_id: &str,
        presented_digest: &str,
        envelope_digest: &str,
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
        if record.envelope_digest.as_deref() != Some(envelope_digest) {
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
    /// Owner-issued delivery identity bound to this publication.
    pub delivery: WasmDeliveryIdentity,
    /// Immutable generation slot directory retaining this set.
    pub slot_dir: std::path::PathBuf,
}

/// Requires the install directory to be a real directory: present, not
/// a symlink or reparse point. Exact path checks are owned here; the
/// installer's ACL owns who may write beneath it, and the publisher
/// widens no ACL — staged files inherit the install directory's.
fn require_install_dir(install_dir: &std::path::Path) -> Result<(), WasmDispatchError> {
    let metadata =
        std::fs::symlink_metadata(install_dir).map_err(|_| invalid("delivery-install-dir"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("delivery-install-dir"));
    }
    Ok(())
}

/// Checks a fixed set with no-follow metadata calls. A dangling link,
/// inaccessible name, or other metadata failure is unresolved custody, not
/// an absent slot.
fn fixed_names_present(
    directory: &std::path::Path,
    names: &[&str],
) -> Result<bool, WasmDispatchError> {
    let mut present = false;
    for name in names {
        match std::fs::symlink_metadata(directory.join(name)) {
            Ok(_) => present = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        }
    }
    Ok(present)
}

/// Flushes one staged file so its bytes are durable before any rename
/// names them (the repository's sealed-body contour: durable body
/// before the row that names it).
fn sync_file(path: &std::path::Path) -> Result<(), WasmDispatchError> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid("delivery-io"))
}

/// Flushes a freshly renamed directory entry on platforms with
/// directory `fsync`.
#[cfg(unix)]
fn sync_parent_directory(directory: &std::path::Path) -> Result<(), WasmDispatchError> {
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid("delivery-io"))
}

/// Directory `fsync` has no Windows equivalent; the file flush plus the
/// atomic rename is the owned contour there. Infallible by construction.
#[cfg(not(unix))]
fn sync_parent_directory(_directory: &std::path::Path) {}

/// Private proof that the caller holds the cross-process lock for the
/// approved installation root. The guard is thread-affine and must remain
/// on this synchronous stack until bounded local I/O is complete.
#[cfg(windows)]
struct DeliveryOwnerLock {
    _guard: eliot_windows_ipc::InstallationRootLockGuard,
}

/// Non-Windows builds cannot provide the shared Windows installation lock,
/// so delivery mutation fails closed before touching files.
#[cfg(not(windows))]
struct DeliveryOwnerLock;

fn acquire_delivery_owner_lock(
    install_dir: &std::path::Path,
) -> Result<DeliveryOwnerLock, WasmDispatchError> {
    #[cfg(windows)]
    {
        require_install_dir(install_dir)?;
        let guard = eliot_windows_ipc::acquire_installation_root_lock(install_dir)
            .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        Ok(DeliveryOwnerLock { _guard: guard })
    }
    #[cfg(not(windows))]
    {
        let _ = install_dir;
        Err(WasmDispatchError::DeliveryUnavailable)
    }
}

static NEXT_DELIVERY_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Stages one file atomically through a unique partial file, so a crash can
/// never splice two bodies together; the body is flushed before the rename
/// publishes it.
/// The post-rename path must be a real file, never a symlink or reparse
/// point. `tag` scopes the partial name to this publication so two
/// publishers never share one partial.
fn stage_file_atomic(
    _owner_lock: &DeliveryOwnerLock,
    directory: &std::path::Path,
    file_name: &str,
    tag: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, WasmDispatchError> {
    let path = directory.join(file_name);
    let (partial, mut file) = (0..8)
        .find_map(|_| {
            let sequence = NEXT_DELIVERY_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let partial = directory.join(format!(
                ".{file_name}.{tag}.{}.{}.partial",
                std::process::id(),
                sequence
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
            {
                Ok(file) => Some(Ok((partial, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(_) => Some(Err(invalid("delivery-io"))),
            }
        })
        .ok_or_else(|| invalid("delivery-io"))??;
    use std::io::Write as _;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        let _ = std::fs::remove_file(&partial);
        return Err(invalid("delivery-io"));
    }
    drop(file);
    #[cfg(windows)]
    let replace_result = eliot_windows_ipc::atomic_replace_file(&partial, &path);
    #[cfg(unix)]
    let replace_result = std::fs::rename(&partial, &path);
    #[cfg(not(any(windows, unix)))]
    let replace_result: Result<(), std::io::Error> = Err(std::io::Error::other("unsupported"));
    if replace_result.is_err() {
        let _ = std::fs::remove_file(&partial);
        return Err(invalid("delivery-io"));
    }
    #[cfg(unix)]
    sync_parent_directory(directory)?;
    #[cfg(not(unix))]
    sync_parent_directory(directory);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid("delivery-io"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("delivery-symlink"));
    }
    Ok(path)
}

/// Stages one immutable slot file: an identical existing body is an
/// idempotent replay, a differing one is a slot collision that fails
/// closed. Slot bytes are never overwritten in place.
fn stage_slot_file_atomic(
    owner_lock: &DeliveryOwnerLock,
    slot: &std::path::Path,
    file_name: &str,
    tag: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, WasmDispatchError> {
    let path = slot.join(file_name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let existing = std::fs::read(&path).map_err(|_| invalid("delivery-slot-collision"))?;
            if existing == bytes {
                return Ok(path);
            }
            return Err(invalid("delivery-slot-collision"));
        }
        Ok(_) => return Err(invalid("delivery-slot-collision")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(invalid("delivery-io")),
    }
    stage_file_atomic(owner_lock, slot, file_name, tag, bytes)
}

/// Generation-slot parent directory under the install directory.
fn slots_dir(install_dir: &std::path::Path) -> std::path::PathBuf {
    install_dir.join(WASM_DELIVERY_SLOT_DIR_NAME)
}

fn launch_incarnation(identity: &WasmDeliveryIdentity) -> String {
    format!(
        "wasm-delivery:{}:{}:{}:{}",
        identity.generation,
        identity.envelope_digest,
        identity.publication_incarnation,
        identity.publication_revision
    )
}

fn require_disposition_digest(value: &str) -> Result<(), WasmDispatchError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    Ok(())
}

fn require_disposition_text(value: &str) -> Result<(), WasmDispatchError> {
    if value.trim().is_empty() {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    Ok(())
}

fn validate_disposition_record(
    record: &WasmDeliveryDispositionRecord,
) -> Result<(), WasmDispatchError> {
    if record.record_version != WASM_DELIVERY_DISPOSITION_VERSION {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let identity = record.identity();
    if identity.generation == 0
        || identity.publication_incarnation == 0
        || identity.publication_revision == 0
        || identity.delivery_version != WASM_DELIVERY_IDENTITY_VERSION
        || identity.claim_id.trim().is_empty()
        || identity.operation_id.trim().is_empty()
        || identity.launch_nonce.trim().is_empty()
        || identity.fence_generation == 0
        || identity.admitted_at_unix_ms == 0
        || identity.expires_at <= identity.admitted_at_unix_ms
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    require_disposition_digest(&identity.grant_digest)?;
    require_disposition_digest(&identity.artifact_digest)?;
    require_disposition_digest(&identity.input_digest)?;
    require_disposition_digest(&identity.envelope_digest)?;
    require_disposition_digest(&identity.host_artifact_digest)?;
    require_disposition_text(&identity.authority_epoch_json)?;
    let join = record.join();
    if join.claim_id != identity.claim_id
        || join.operation_id != identity.operation_id
        || join.grant_digest != identity.grant_digest
        || join.expires_at != identity.expires_at
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    require_disposition_text(&join.authority_id)?;
    require_disposition_text(&join.invocation_digest)?;
    if record.request_commitment() != identity.envelope_digest {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    match &record.disposition {
        WasmDeliveryDisposition::Ready { .. } => {}
        WasmDeliveryDisposition::LaunchReserved {
            launch_incarnation: actual,
            ..
        }
        | WasmDeliveryDisposition::InFlight {
            launch_incarnation: actual,
            ..
        }
        | WasmDeliveryDisposition::TerminalUnacknowledged {
            launch_incarnation: actual,
            ..
        }
        | WasmDeliveryDisposition::Acknowledged {
            launch_incarnation: actual,
            ..
        } if actual != &launch_incarnation(identity) => {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        WasmDeliveryDisposition::LaunchReserved { .. } => {}
        WasmDeliveryDisposition::InFlight {
            claimant_incarnation,
            runtime_request_digest,
            ..
        }
        | WasmDeliveryDisposition::TerminalUnacknowledged {
            claimant_incarnation,
            runtime_request_digest,
            ..
        }
        | WasmDeliveryDisposition::Acknowledged {
            claimant_incarnation,
            runtime_request_digest,
            ..
        } => {
            require_disposition_text(claimant_incarnation)?;
            require_disposition_digest(runtime_request_digest)?;
            match &record.disposition {
                WasmDeliveryDisposition::TerminalUnacknowledged { result_digest, .. }
                | WasmDeliveryDisposition::Acknowledged { result_digest, .. } => {
                    require_disposition_digest(result_digest)?
                }
                _ => {}
            }
            if let WasmDeliveryDisposition::Acknowledged {
                receiver_ack_identity,
                receiver_ack_digest,
                process_settlement_digest,
                material_settlement_digest,
                ..
            } = &record.disposition
            {
                require_disposition_text(receiver_ack_identity)?;
                require_disposition_digest(receiver_ack_digest)?;
                require_disposition_digest(process_settlement_digest)?;
                require_disposition_digest(material_settlement_digest)?;
            }
        }
        WasmDeliveryDisposition::RetiredNoEffect {
            retirement_digest, ..
        } => require_disposition_digest(retirement_digest)?,
    }
    Ok(())
}

fn read_disposition(
    slot: &std::path::Path,
) -> Result<WasmDeliveryDispositionRecord, WasmDispatchError> {
    let path = slot.join(WASM_DELIVERY_DISPOSITION_FILE_NAME);
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DELIVERY_DISPOSITION_BYTES
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let bytes = std::fs::read(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    let record: WasmDeliveryDispositionRecord =
        serde_json::from_slice(&bytes).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    validate_disposition_record(&record)?;
    Ok(record)
}

fn write_disposition(
    owner_lock: &DeliveryOwnerLock,
    slot: &std::path::Path,
    identity: &WasmDeliveryIdentity,
    record: &WasmDeliveryDispositionRecord,
) -> Result<(), WasmDispatchError> {
    validate_disposition_record(record)?;
    if record.identity() != identity {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    let bytes = serde_json::to_vec(record).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if bytes.len() as u64 > MAX_DELIVERY_DISPOSITION_BYTES {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let tag = identity.slot_name();
    stage_file_atomic(
        owner_lock,
        slot,
        WASM_DELIVERY_DISPOSITION_FILE_NAME,
        &tag,
        &bytes,
    )?;
    Ok(())
}

/// Reads one slot's retained publication marker, distinguishing absence
/// from unreadable or malformed history. Incomplete history is unavailable;
/// it is never an empty authoritative set.
fn read_slot_state(
    slot: &std::path::Path,
) -> Result<Option<WasmPublicationState>, WasmDispatchError> {
    let mut pending_identity: Option<WasmDeliveryIdentity> = None;
    let mut terminal_state: Option<WasmPublicationState> = None;
    for (file_name, expected) in [
        (WASM_DELIVERY_READY_FILE_NAME, 0_u8),
        (WASM_DELIVERY_FAILED_FILE_NAME, 1_u8),
        (WASM_DELIVERY_PENDING_FILE_NAME, 2_u8),
    ] {
        let path = slot.join(file_name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DELIVERY_DISPOSITION_BYTES
        {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        let bytes = std::fs::read(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        let state: WasmPublicationState =
            serde_json::from_slice(&bytes).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        let matches_marker = matches!(
            (expected, &state),
            (0, WasmPublicationState::Ready { .. })
                | (1, WasmPublicationState::Failed { .. })
                | (2, WasmPublicationState::Pending { .. })
        );
        if !matches_marker {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        match state {
            WasmPublicationState::Pending { identity } => {
                if pending_identity.replace(identity).is_some() {
                    return Err(WasmDispatchError::DeliveryUnavailable);
                }
            }
            terminal @ (WasmPublicationState::Ready { .. }
            | WasmPublicationState::Failed { .. }) => {
                if terminal_state.replace(terminal).is_some() {
                    return Err(WasmDispatchError::DeliveryUnavailable);
                }
            }
        }
    }
    if let Some(terminal) = terminal_state {
        if pending_identity
            .as_ref()
            .is_some_and(|pending| pending != terminal.identity())
        {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        return Ok(Some(terminal));
    }
    Ok(pending_identity.map(|identity| WasmPublicationState::Pending { identity }))
}

fn validate_slot_material(
    slot: &std::path::Path,
    identity: &WasmDeliveryIdentity,
    require_payloads: bool,
) -> Result<(), WasmDispatchError> {
    let envelope_path = slot.join(WASM_HOST_MATERIAL_FILE_NAME);
    match std::fs::symlink_metadata(&envelope_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64
            {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            let envelope = std::fs::read(&envelope_path)
                .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            let material: WasmDispatchMaterial = serde_json::from_slice(&envelope)
                .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            if sha256_hex(&envelope) != identity.envelope_digest
                || !identity.matches_material(&material)
            {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_payloads => {}
        Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
    }
    for (name, digest) in [
        (
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            &identity.artifact_digest,
        ),
        (WASM_HOST_GUEST_INPUT_FILE_NAME, &identity.input_digest),
    ] {
        let path = slot.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            Ok(metadata) if metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64 => {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_payloads => {
                continue;
            }
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        };
        if metadata.len() != bytes.len() as u64
            || bytes.is_empty()
            || bytes.len() > MAX_DELIVERY_PAYLOAD_BYTES
            || sha256_hex(&bytes) != *digest
        {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
    }
    Ok(())
}

fn read_publication_snapshot(
    slot: &std::path::Path,
) -> Result<WasmDeliveryPublicationSnapshot, WasmDispatchError> {
    let metadata =
        std::fs::symlink_metadata(slot).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let publication = read_slot_state(slot)?.ok_or(WasmDispatchError::DeliveryUnavailable)?;
    let disposition = read_disposition(slot)?;
    let expected_slot_name = disposition.identity().slot_name();
    if !matches!(&publication, WasmPublicationState::Ready { .. })
        || publication.identity() != disposition.identity()
        || slot.file_name().and_then(std::ffi::OsStr::to_str) != Some(expected_slot_name.as_str())
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    match &disposition.disposition {
        WasmDeliveryDisposition::Acknowledged { .. }
        | WasmDeliveryDisposition::RetiredNoEffect { .. } => {
            validate_slot_material(slot, disposition.identity(), false)?;
        }
        WasmDeliveryDisposition::Ready { .. }
        | WasmDeliveryDisposition::LaunchReserved { .. }
        | WasmDeliveryDisposition::InFlight { .. }
        | WasmDeliveryDisposition::TerminalUnacknowledged { .. } => {
            validate_slot_material(slot, disposition.identity(), true)?;
        }
    }
    if let WasmDeliveryDisposition::TerminalUnacknowledged { result_digest, .. }
    | WasmDeliveryDisposition::Acknowledged { result_digest, .. } = &disposition.disposition
    {
        let result_path = slot.join(WASM_DELIVERY_RESULT_FILE_NAME);
        match std::fs::symlink_metadata(&result_path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64 =>
            {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            Ok(_) => {
                let bytes = std::fs::read(&result_path)
                    .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
                if sha256_hex(&bytes) != *result_digest {
                    return Err(WasmDispatchError::DeliveryUnavailable);
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && matches!(
                        &disposition.disposition,
                        WasmDeliveryDisposition::Acknowledged { .. }
                    ) => {}
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        }
    }
    Ok(WasmDeliveryPublicationSnapshot {
        publication,
        disposition,
    })
}

fn scan_publication_snapshots(
    slots: &std::path::Path,
) -> Result<
    Vec<(
        String,
        std::path::PathBuf,
        WasmDeliveryPublicationSnapshot,
        u64,
    )>,
    WasmDispatchError,
> {
    let directory_metadata = match std::fs::symlink_metadata(slots) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let entries = match std::fs::read_dir(slots) {
        Ok(entries) => entries,
        Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
    };
    let mut rows = Vec::new();
    let mut retained_bytes = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        if rows.len() >= MAX_DELIVERY_HISTORY {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        let path = entry.path();
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        let snapshot = read_publication_snapshot(&path)?;
        let slot_entries =
            std::fs::read_dir(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        let mut slot_bytes = 0_u64;
        for slot_entry in slot_entries {
            let slot_entry = slot_entry.map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            let slot_path = slot_entry.path();
            let file_metadata = std::fs::symlink_metadata(&slot_path)
                .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            let file_name = slot_entry
                .file_name()
                .into_string()
                .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            if file_name.ends_with(".partial")
                || ![
                    WASM_DELIVERY_PENDING_FILE_NAME,
                    WASM_DELIVERY_READY_FILE_NAME,
                    WASM_DELIVERY_FAILED_FILE_NAME,
                    WASM_DELIVERY_DISPOSITION_FILE_NAME,
                    WASM_DELIVERY_RESULT_FILE_NAME,
                    WASM_HOST_MATERIAL_FILE_NAME,
                    WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
                    WASM_HOST_GUEST_INPUT_FILE_NAME,
                ]
                .contains(&file_name.as_str())
            {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            if file_name == WASM_DELIVERY_RESULT_FILE_NAME
                && file_metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64
            {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            slot_bytes = slot_bytes.saturating_add(file_metadata.len());
        }
        retained_bytes = retained_bytes.saturating_add(slot_bytes);
        if retained_bytes > MAX_DELIVERY_RETAINED_BYTES {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        rows.push((name, path, snapshot, slot_bytes));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

/// Discovers complete per-delivery publication and disposition state for
/// restart recovery. Read errors, malformed/missing owner records, legacy
/// fixed-name state, and scan exhaustion return `DeliveryUnavailable`, not
/// an empty vector.
pub fn discover_delivery_publications(
    install_dir: &std::path::Path,
) -> Result<Vec<WasmDeliveryPublicationSnapshot>, WasmDispatchError> {
    let _owner_lock = acquire_delivery_owner_lock(install_dir)?;
    require_install_dir(install_dir)?;
    let rows = scan_publication_snapshots(&slots_dir(install_dir))?;
    let live = read_live_material(install_dir)?;
    let fixed_payloads = fixed_names_present(
        install_dir,
        &[
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            WASM_HOST_GUEST_INPUT_FILE_NAME,
        ],
    )?;
    if let Some(live) = live {
        let exact = rows
            .iter()
            .filter(|(_, _, snapshot, _)| snapshot.disposition.identity().matches_material(&live));
        let mut matches = exact;
        let Some((_, _, snapshot, _)) = matches.next() else {
            return Err(WasmDispatchError::DeliveryUnavailable);
        };
        if matches.next().is_some()
            || !fixed_payloads_match(install_dir, snapshot.disposition.identity())?
        {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
    } else if fixed_payloads {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let any_fixed = fixed_names_present(
        install_dir,
        &[
            WASM_HOST_MATERIAL_FILE_NAME,
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            WASM_HOST_GUEST_INPUT_FILE_NAME,
        ],
    )?;
    if rows.is_empty() && any_fixed {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    Ok(rows
        .into_iter()
        .map(|(_, _, snapshot, _)| snapshot)
        .collect())
}

/// Reads the currently exposed fixed-name envelope, if any. Absent
/// means free to publish. Present-but-unreadable-or-invalid refuses:
/// the publisher only replaces a set it can identify, never a silent
/// overwrite of unknown bytes.
fn read_live_material(
    install_dir: &std::path::Path,
) -> Result<Option<WasmDispatchMaterial>, WasmDispatchError> {
    let path = install_dir.join(WASM_HOST_MATERIAL_FILE_NAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let bytes = std::fs::read(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let material: WasmDispatchMaterial =
        serde_json::from_slice(&bytes).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if material_bytes(&material)? != bytes {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    Ok(Some(material))
}

/// Reclaims fixed names only after the exact per-slot disposition proves
/// no effect or exact ACK plus settled obligations. The shared installation
/// lock serializes this transition with child claim/cleanup; under that
/// guard the function re-reads the live envelope identity and disposition
/// before removing any fixed name. It does not use hash-before-delete as
/// an ownership test.
fn reclaim_fixed_delivery(
    owner_lock: &DeliveryOwnerLock,
    install_dir: &std::path::Path,
    slot: &std::path::Path,
    presented: &WasmDeliveryIdentity,
    disposition: &WasmDeliveryDispositionRecord,
) -> Result<WasmDeliveryReclamation, WasmDispatchError> {
    let current = read_disposition(slot)?;
    if &current != disposition {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    if disposition.identity() != presented
        || !matches!(
            &disposition.disposition,
            WasmDeliveryDisposition::Acknowledged { .. }
                | WasmDeliveryDisposition::RetiredNoEffect { .. }
        )
    {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    // Re-read the current publication after acquiring the shared guard.
    // A different exact envelope is a successor and its names stay intact.
    let live = read_live_material(install_dir)?;
    let (artifact, input, material) = match live {
        Some(live) if presented.matches_material(&live) => {
            let artifact = reclaim_one(&install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME));
            let input = reclaim_one(&install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME));
            let material = reclaim_one(&install_dir.join(WASM_HOST_MATERIAL_FILE_NAME));
            if matches!(
                artifact,
                DeliveryReclaimOutcome::SharingViolation
                    | DeliveryReclaimOutcome::AccessDenied
                    | DeliveryReclaimOutcome::Other(_)
            ) || matches!(
                input,
                DeliveryReclaimOutcome::SharingViolation
                    | DeliveryReclaimOutcome::AccessDenied
                    | DeliveryReclaimOutcome::Other(_)
            ) || matches!(
                material,
                DeliveryReclaimOutcome::SharingViolation
                    | DeliveryReclaimOutcome::AccessDenied
                    | DeliveryReclaimOutcome::Other(_)
            ) {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            (artifact, input, material)
        }
        Some(_) => (
            DeliveryReclaimOutcome::NotFound,
            DeliveryReclaimOutcome::NotFound,
            DeliveryReclaimOutcome::NotFound,
        ),
        None => {
            let payload_present = fixed_names_present(
                install_dir,
                &[
                    WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
                    WASM_HOST_GUEST_INPUT_FILE_NAME,
                ],
            )?;
            if payload_present {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            (
                DeliveryReclaimOutcome::NotFound,
                DeliveryReclaimOutcome::NotFound,
                DeliveryReclaimOutcome::NotFound,
            )
        }
    };
    Ok(WasmDeliveryReclamation {
        identity: presented.clone(),
        artifact,
        input,
        material,
    })
}

fn retirement_record(
    record: &WasmDeliveryDispositionRecord,
) -> Result<WasmDeliveryDispositionRecord, WasmDispatchError> {
    let WasmDeliveryDisposition::Ready {
        identity,
        join,
        request_commitment,
    } = &record.disposition
    else {
        return Err(WasmDispatchError::DeliveryConflict);
    };
    let evidence = serde_json::to_vec(&(
        "eliot-wasm-retired-no-effect/v1",
        identity,
        join,
        request_commitment,
    ))
    .map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    Ok(WasmDeliveryDispositionRecord {
        record_version: WASM_DELIVERY_DISPOSITION_VERSION,
        disposition: WasmDeliveryDisposition::RetiredNoEffect {
            identity: identity.clone(),
            join: join.clone(),
            request_commitment: request_commitment.clone(),
            retirement_digest: sha256_hex(&evidence),
        },
    })
}

fn is_reclaimable_disposition(record: &WasmDeliveryDispositionRecord) -> bool {
    matches!(
        &record.disposition,
        WasmDeliveryDisposition::Acknowledged { .. }
            | WasmDeliveryDisposition::RetiredNoEffect { .. }
    )
}

fn delivery_backpressure(
    identity: &WasmDeliveryIdentity,
    retry_condition: &str,
) -> WasmDispatchError {
    WasmDispatchError::Backpressure(WasmDeliveryBackpressure {
        live_generation: identity.generation,
        live_operation_id: identity.operation_id.clone(),
        live_expires_at: identity.expires_at,
        retry_condition: retry_condition.to_owned(),
        recovery_reference: WasmDeliveryRecoveryReference::from_identity(identity),
    })
}

/// Frees only immutable bytes whose retained disposition proves no effect or
/// exact ACK plus settlement. The small publication/disposition tombstone is
/// retained so revisions and spent identities cannot be reused after restart.
fn reclaim_slot_payloads(
    owner_lock: &DeliveryOwnerLock,
    slot: &std::path::Path,
    expected: &WasmDeliveryDispositionRecord,
) -> Result<(), WasmDispatchError> {
    if !is_reclaimable_disposition(expected) {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let current = read_disposition(slot)?;
    if &current != expected {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    validate_slot_material(slot, expected.identity(), false)?;
    let result_digest = match &expected.disposition {
        WasmDeliveryDisposition::Acknowledged { result_digest, .. } => Some(result_digest),
        WasmDeliveryDisposition::RetiredNoEffect { .. } => None,
        _ => return Err(WasmDispatchError::DeliveryUnavailable),
    };
    for file_name in [
        WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
        WASM_HOST_GUEST_INPUT_FILE_NAME,
        WASM_HOST_MATERIAL_FILE_NAME,
    ] {
        match reclaim_one(&slot.join(file_name)) {
            DeliveryReclaimOutcome::Reclaimed | DeliveryReclaimOutcome::NotFound => {}
            DeliveryReclaimOutcome::SharingViolation
            | DeliveryReclaimOutcome::AccessDenied
            | DeliveryReclaimOutcome::Other(_) => {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
        }
    }
    let result_path = slot.join(WASM_DELIVERY_RESULT_FILE_NAME);
    match (result_digest, std::fs::symlink_metadata(&result_path)) {
        (Some(expected_digest), Ok(metadata))
            if !metadata.file_type().is_symlink()
                && metadata.is_file()
                && metadata.len() <= MAX_DELIVERY_PAYLOAD_BYTES as u64 =>
        {
            let bytes =
                std::fs::read(&result_path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
            if sha256_hex(&bytes) != *expected_digest {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            match reclaim_one(&result_path) {
                DeliveryReclaimOutcome::Reclaimed | DeliveryReclaimOutcome::NotFound => {}
                DeliveryReclaimOutcome::SharingViolation
                | DeliveryReclaimOutcome::AccessDenied
                | DeliveryReclaimOutcome::Other(_) => {
                    return Err(WasmDispatchError::DeliveryUnavailable);
                }
            }
        }
        (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(WasmDispatchError::DeliveryUnavailable),
    }
    let _ = owner_lock;
    Ok(())
}

fn reconcile_reclaimable_delivery(
    owner_lock: &DeliveryOwnerLock,
    install_dir: &std::path::Path,
    slot: &std::path::Path,
    expected: &WasmDeliveryDispositionRecord,
) -> Result<(), WasmDispatchError> {
    let mut current = read_disposition(slot)?;
    if &current != expected {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    if matches!(&current.disposition, WasmDeliveryDisposition::Ready { .. }) {
        let retired = retirement_record(&current)?;
        write_disposition(owner_lock, slot, current.identity(), &retired)?;
        current = retired;
    }
    if !is_reclaimable_disposition(&current) {
        return Err(delivery_backpressure(
            current.identity(),
            "exact delivery result acknowledgement and settled obligations",
        ));
    }
    match read_live_material(install_dir)? {
        Some(live) if current.identity().matches_material(&live) => {
            reclaim_fixed_delivery(owner_lock, install_dir, slot, current.identity(), &current)?;
        }
        Some(_) => {}
        None => {
            let fixed_payload = fixed_names_present(
                install_dir,
                &[
                    WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
                    WASM_HOST_GUEST_INPUT_FILE_NAME,
                ],
            )?;
            if fixed_payload {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
        }
    }
    reclaim_slot_payloads(owner_lock, slot, &current)
}

/// Consumes the current fixed-name owner state, never expiry alone. A Ready
/// slot proves no launch reservation exists and may be explicitly retired;
/// LaunchReserved, InFlight, terminal-unacknowledged, or incomplete state
/// backpressures with its exact recovery locator.
fn retire_or_backpressure_live(
    owner_lock: &DeliveryOwnerLock,
    live: &WasmDispatchMaterial,
    live_envelope: &[u8],
    install_dir: &std::path::Path,
) -> Result<(), WasmDispatchError> {
    let live_digest = sha256_hex(live_envelope);
    let rows = scan_publication_snapshots(&slots_dir(install_dir))?;
    let matches: Vec<_> = rows
        .iter()
        .filter(|(_, _, snapshot, _)| {
            snapshot.disposition.identity().envelope_digest == live_digest
                && snapshot.disposition.identity().matches_material(live)
        })
        .collect();
    if matches.len() != 1 {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let (_, slot, snapshot, _) = matches[0];
    reconcile_reclaimable_delivery(owner_lock, install_dir, slot, &snapshot.disposition)
}

/// Reserves launch exactly once under the installation-root lock. The
/// durable LaunchReserved transition closes execution before the caller
/// starts the child; expiry closes new launch but never changes unresolved
/// custody into a reclaimable state.
pub fn claim_wasm_dispatch_launch(
    install_dir: &std::path::Path,
    identity: &WasmDeliveryIdentity,
    join: &WasmJoinGate,
    now_ms: u64,
) -> Result<WasmLaunchDisposition, WasmDispatchError> {
    if now_ms == 0 {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let owner_lock = acquire_delivery_owner_lock(install_dir)?;
    require_install_dir(install_dir)?;
    let rows = scan_publication_snapshots(&slots_dir(install_dir))?;
    let matching: Vec<_> = rows
        .iter()
        .filter(|(_, _, snapshot, _)| snapshot.disposition.identity() == identity)
        .collect();
    if matching.len() != 1 {
        if rows.iter().any(|(_, _, snapshot, _)| {
            snapshot.disposition.identity().claim_id == identity.claim_id
                && snapshot.disposition.identity().operation_id == identity.operation_id
        }) {
            return Err(WasmDispatchError::DeliveryConflict);
        }
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    let (_, slot, snapshot, _) = matching[0];
    let record = &snapshot.disposition;
    if record.join() != &WasmJoinBinding::from(join)
        || record.request_commitment() != identity.envelope_digest
    {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    match &record.disposition {
        WasmDeliveryDisposition::Ready { .. } => {
            if identity.expires_at <= now_ms {
                reconcile_reclaimable_delivery(&owner_lock, install_dir, slot, record)?;
                return Err(WasmDispatchError::DeliveryConflict);
            }
            let live =
                read_live_material(install_dir)?.ok_or(WasmDispatchError::DeliveryUnavailable)?;
            if !identity.matches_material(&live) || !fixed_payloads_match(install_dir, identity)? {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            let launch_incarnation = launch_incarnation(identity);
            let reserved = WasmDeliveryDispositionRecord {
                record_version: WASM_DELIVERY_DISPOSITION_VERSION,
                disposition: WasmDeliveryDisposition::LaunchReserved {
                    identity: identity.clone(),
                    join: record.join().clone(),
                    request_commitment: identity.envelope_digest.clone(),
                    launch_incarnation: launch_incarnation.clone(),
                },
            };
            write_disposition(&owner_lock, slot, identity, &reserved)?;
            Ok(WasmLaunchDisposition::Acquired { launch_incarnation })
        }
        WasmDeliveryDisposition::LaunchReserved { .. }
        | WasmDeliveryDisposition::InFlight { .. } => Ok(WasmLaunchDisposition::ExistingInFlight {
            recovery_reference: WasmDeliveryRecoveryReference::from_identity(identity),
        }),
        WasmDeliveryDisposition::TerminalUnacknowledged { .. }
        | WasmDeliveryDisposition::Acknowledged { .. } => {
            Ok(WasmLaunchDisposition::RetainedResult {
                recovery_reference: WasmDeliveryRecoveryReference::from_identity(identity),
            })
        }
        WasmDeliveryDisposition::RetiredNoEffect { .. } => Err(WasmDispatchError::DeliveryConflict),
    }
}

/// Stages the immutable generation slot, then exposes the fixed-name
/// set: payloads first and the envelope last, each file atomic. A
/// publication error inside slot staging never touches the fixed names,
/// so it cannot delete another generation; readers never see a torn
/// generation. Returns the staged envelope path.
fn stage_and_expose_delivery(
    owner_lock: &DeliveryOwnerLock,
    install_dir: &std::path::Path,
    slot: &std::path::Path,
    slot_name: &str,
    identity: &WasmDeliveryIdentity,
    join: &WasmJoinGate,
    envelope: &[u8],
    claim: &WasmOwnerClaim,
) -> Result<std::path::PathBuf, WasmDispatchError> {
    stage_delivery_slot(owner_lock, slot, identity, envelope, claim)?;
    let ready = WasmDeliveryDispositionRecord::ready(identity, join);
    write_disposition(owner_lock, slot, identity, &ready)?;
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
        slot_name,
        &claim.artifact_bytes,
    )?;
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_GUEST_INPUT_FILE_NAME,
        slot_name,
        &claim.input_bytes,
    )?;
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_MATERIAL_FILE_NAME,
        slot_name,
        envelope,
    )
}

/// Stages the immutable generation slot: Pending marker, bounded
/// payloads, envelope copy, then the Ready marker last. A Ready slot
/// for the same delivery is an idempotent replay (Ready covers the slot
/// set only — a crash between slot completion and fixed-name exposure
/// leaves exposure to the replay's re-verification); anything else
/// Ready under this name is a collision. On failure the slot records
/// Failed with the stable reason and the fixed names stay untouched:
/// partial publication is never accepted as a complete set.
fn stage_delivery_slot(
    owner_lock: &DeliveryOwnerLock,
    slot: &std::path::Path,
    identity: &WasmDeliveryIdentity,
    envelope: &[u8],
    claim: &WasmOwnerClaim,
) -> Result<(), WasmDispatchError> {
    match read_slot_state(slot)? {
        Some(WasmPublicationState::Ready { identity: ready }) if ready == *identity => {
            let record = read_disposition(slot)?;
            if record.identity() == identity {
                return Ok(());
            }
            return Err(WasmDispatchError::DeliveryConflict);
        }
        Some(_) => return Err(WasmDispatchError::DeliveryConflict),
        None if std::fs::symlink_metadata(slot).is_ok() => {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        None => {}
    }
    let parent = slot
        .parent()
        .ok_or(WasmDispatchError::DeliveryUnavailable)?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(parent).map_err(|_| invalid("delivery-io"))?;
        }
        _ => return Err(WasmDispatchError::DeliveryUnavailable),
    }
    std::fs::create_dir(slot).map_err(|_| invalid("delivery-io"))?;
    let tag = identity.slot_name();
    let staged: Result<(), WasmDispatchError> = (|| {
        let pending = serde_json::to_vec(&WasmPublicationState::Pending {
            identity: identity.clone(),
        })
        .map_err(|_| WasmDispatchError::Gate)?;
        stage_file_atomic(
            owner_lock,
            slot,
            WASM_DELIVERY_PENDING_FILE_NAME,
            &tag,
            &pending,
        )?;
        stage_slot_file_atomic(
            owner_lock,
            slot,
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            &tag,
            &claim.artifact_bytes,
        )?;
        stage_slot_file_atomic(
            owner_lock,
            slot,
            WASM_HOST_GUEST_INPUT_FILE_NAME,
            &tag,
            &claim.input_bytes,
        )?;
        stage_slot_file_atomic(
            owner_lock,
            slot,
            WASM_HOST_MATERIAL_FILE_NAME,
            &tag,
            envelope,
        )?;
        let ready = serde_json::to_vec(&WasmPublicationState::Ready {
            identity: identity.clone(),
        })
        .map_err(|_| WasmDispatchError::Gate)?;
        stage_slot_file_atomic(
            owner_lock,
            slot,
            WASM_DELIVERY_READY_FILE_NAME,
            &tag,
            &ready,
        )?;
        Ok(())
    })();
    if let Err(error) = &staged {
        let failed = serde_json::to_vec(&WasmPublicationState::Failed {
            identity: identity.clone(),
            reason: error.to_string(),
        });
        if let Ok(failed) = failed {
            let _ = stage_file_atomic(
                owner_lock,
                slot,
                WASM_DELIVERY_FAILED_FILE_NAME,
                &tag,
                &failed,
            );
        }
    }
    staged
}

/// Whether the fixed payloads currently exposed re-hash to the identity
/// digests: both files must exist with byte-exact bodies. A live
/// envelope alone proves nothing — reclaim removes payloads first, so a
/// crash leaves the envelope identity over missing payloads.
fn fixed_payloads_match(
    install_dir: &std::path::Path,
    identity: &WasmDeliveryIdentity,
) -> Result<bool, WasmDispatchError> {
    for (name, digest) in [
        (
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            &identity.artifact_digest,
        ),
        (WASM_HOST_GUEST_INPUT_FILE_NAME, &identity.input_digest),
    ] {
        let path = install_dir.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64
        {
            return Err(WasmDispatchError::DeliveryUnavailable);
        }
        let bytes = std::fs::read(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
        if metadata.len() != bytes.len() as u64 || sha256_hex(&bytes) != *digest {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether a fixed-name file is still absent or contains the exact bytes
/// being re-exposed from its immutable generation slot. A partial exposure
/// is repairable only when every surviving file still belongs to that slot.
fn fixed_file_matches_or_missing(
    install_dir: &std::path::Path,
    file_name: &str,
    expected: &[u8],
) -> Result<bool, WasmDispatchError> {
    let path = install_dir.join(file_name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(_) => return Err(WasmDispatchError::DeliveryUnavailable),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DELIVERY_PAYLOAD_BYTES as u64
        || metadata.len() != expected.len() as u64
    {
        return Ok(false);
    }
    let bytes = std::fs::read(&path).map_err(|_| WasmDispatchError::DeliveryUnavailable)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    Ok(bytes == expected)
}

/// Re-exposes the fixed-name set from the generation slot after a
/// same-delivery replay found the live payloads missing. The slot's payload
/// and envelope copies are re-hashed against the identity digests, then
/// staged payloads-first and envelope-last under the shared installation
/// lock. A successor disposition cannot publish concurrently under that
/// same lock.
fn reexpose_fixed_delivery_from_slot(
    owner_lock: &DeliveryOwnerLock,
    install_dir: &std::path::Path,
    slot: &std::path::Path,
    identity: &WasmDeliveryIdentity,
) -> Result<(), WasmDispatchError> {
    let disposition = read_disposition(slot)?;
    if disposition.identity() != identity
        || !matches!(
            &disposition.disposition,
            WasmDeliveryDisposition::Ready { .. }
        )
    {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    validate_slot_material(slot, identity, true)?;
    let live = read_live_material(install_dir)?;
    if live
        .as_ref()
        .is_some_and(|live| !identity.matches_material(live))
    {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    let artifact = std::fs::read(slot.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME))
        .map_err(|_| invalid("delivery-slot-payload"))?;
    if sha256_hex(&artifact) != identity.artifact_digest {
        return Err(invalid("delivery-slot-payload"));
    }
    let input = std::fs::read(slot.join(WASM_HOST_GUEST_INPUT_FILE_NAME))
        .map_err(|_| invalid("delivery-slot-payload"))?;
    if sha256_hex(&input) != identity.input_digest {
        return Err(invalid("delivery-slot-payload"));
    }
    let slot_envelope = std::fs::read(slot.join(WASM_HOST_MATERIAL_FILE_NAME))
        .map_err(|_| invalid("delivery-slot-payload"))?;
    if sha256_hex(&slot_envelope) != identity.envelope_digest {
        return Err(invalid("delivery-slot-payload"));
    }
    for (name, expected) in [
        (WASM_HOST_GUEST_ARTIFACT_FILE_NAME, artifact.as_slice()),
        (WASM_HOST_GUEST_INPUT_FILE_NAME, input.as_slice()),
        (WASM_HOST_MATERIAL_FILE_NAME, slot_envelope.as_slice()),
    ] {
        if !fixed_file_matches_or_missing(install_dir, name, expected)? {
            return Err(WasmDispatchError::DeliveryConflict);
        }
    }
    let tag = identity.slot_name();
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
        &tag,
        &artifact,
    )?;
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_GUEST_INPUT_FILE_NAME,
        &tag,
        &input,
    )?;
    stage_file_atomic(
        owner_lock,
        install_dir,
        WASM_HOST_MATERIAL_FILE_NAME,
        &tag,
        &slot_envelope,
    )?;
    Ok(())
}

fn delivery_capacity_backpressure(
    rows: &[(
        String,
        std::path::PathBuf,
        WasmDeliveryPublicationSnapshot,
        u64,
    )],
    retry_condition: &str,
) -> WasmDispatchError {
    rows.last().map_or(
        WasmDispatchError::DeliveryUnavailable,
        |(_, _, snapshot, _)| {
            delivery_backpressure(snapshot.disposition.identity(), retry_condition)
        },
    )
}

fn prepare_delivery_publication_space(
    owner_lock: &DeliveryOwnerLock,
    install_dir: &std::path::Path,
    rows: &[(
        String,
        std::path::PathBuf,
        WasmDeliveryPublicationSnapshot,
        u64,
    )],
    preserve: Option<&WasmDeliveryIdentity>,
) -> Result<
    Vec<(
        String,
        std::path::PathBuf,
        WasmDeliveryPublicationSnapshot,
        u64,
    )>,
    WasmDispatchError,
> {
    for (_, slot, snapshot, _) in rows {
        if preserve.is_some_and(|identity| snapshot.disposition.identity() == identity) {
            continue;
        }
        match &snapshot.disposition.disposition {
            WasmDeliveryDisposition::Ready { .. }
            | WasmDeliveryDisposition::Acknowledged { .. }
            | WasmDeliveryDisposition::RetiredNoEffect { .. } => {
                reconcile_reclaimable_delivery(
                    owner_lock,
                    install_dir,
                    slot,
                    &snapshot.disposition,
                )?;
            }
            WasmDeliveryDisposition::LaunchReserved { .. }
            | WasmDeliveryDisposition::InFlight { .. }
            | WasmDeliveryDisposition::TerminalUnacknowledged { .. } => {
                return Err(delivery_backpressure(
                    snapshot.disposition.identity(),
                    "exact delivery result acknowledgement and settled obligations",
                ));
            }
        }
    }
    scan_publication_snapshots(&slots_dir(install_dir))
}

fn find_delivery_row<'a>(
    rows: &'a [(
        String,
        std::path::PathBuf,
        WasmDeliveryPublicationSnapshot,
        u64,
    )],
    identity: &WasmDeliveryIdentity,
) -> Option<&'a (
    String,
    std::path::PathBuf,
    WasmDeliveryPublicationSnapshot,
    u64,
)> {
    rows.iter()
        .find(|(_, _, snapshot, _)| snapshot.disposition.identity() == identity)
}

/// Publishes one dispatch bundle from retained actual owner state plus the
/// installation-approved host binding: validates every record, binds the
/// registry digest into the grant and the envelope, re-hashes the staged
/// bytes against the bound digests, computes the owner-side join gate,
/// stages the generation-bound immutable set, exposes the fixed-name
/// delivery files, and registers the delivery-bound join. No ambient
/// paths, no caller-asserted digests, no minted window: freshness opens at
/// the durable admission time through the grant expiry.
///
/// Publication, launch claim, and fixed-name cleanup share one installation
/// root lock. Exact replay returns its retained revision and disposition;
/// it never re-arms an in-flight or terminal operation. A Ready delivery may
/// be retired only by an owner transition proving no launch reservation was
/// issued. Expiry does not reclaim potentially executing work. Slot history
/// remains bounded and compact tombstones preserve spent identity/revision.
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
/// byte bindings, lock acquisition, or file staging fails closed, or
/// [`WasmDispatchError::Backpressure`] when protected deliveries or bounded
/// retained capacity prevent publication.
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
    if claim.artifact_bytes.len() > MAX_DELIVERY_PAYLOAD_BYTES
        || claim.input_bytes.len() > MAX_DELIVERY_PAYLOAD_BYTES
    {
        return Err(invalid("guest-bytes-bound"));
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
    let join = wasm_join_gate(
        claim,
        host_executable_path,
        host_artifact_digest,
        install_dir,
    )?;
    let envelope = material_bytes(&material)?;
    let envelope_digest = sha256_hex(&envelope);
    let owner_lock = acquire_delivery_owner_lock(install_dir)?;
    require_install_dir(install_dir)?;
    let slots = slots_dir(install_dir);
    let rows = scan_publication_snapshots(&slots)?;
    let exact_indexes: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(index, (_, _, snapshot, _))| {
            (snapshot.disposition.identity().envelope_digest == envelope_digest
                && snapshot.disposition.identity().host_artifact_digest == host_artifact_digest
                && snapshot.disposition.identity().matches_material(&material))
            .then_some(index)
        })
        .collect();
    if exact_indexes.len() > 1 {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    if exact_indexes.is_empty()
        && rows.iter().any(|(_, _, snapshot, _)| {
            snapshot.disposition.identity().claim_id == claim.claim_id
                && snapshot.disposition.identity().operation_id == claim.operation_id
        })
    {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    if let Some(index) = exact_indexes.first().copied() {
        let slot = rows[index].1.clone();
        let snapshot = rows[index].2.clone();
        let identity = snapshot.disposition.identity().clone();
        let expected_join = WasmJoinBinding::from(&join);
        if snapshot.disposition.join() != &expected_join
            || snapshot.disposition.request_commitment() != identity.envelope_digest
        {
            return Err(WasmDispatchError::DeliveryConflict);
        }
        if matches!(
            &snapshot.disposition.disposition,
            WasmDeliveryDisposition::Ready { .. }
        ) {
            let prepared_rows = prepare_delivery_publication_space(
                &owner_lock,
                install_dir,
                &rows,
                Some(&identity),
            )?;
            if find_delivery_row(&prepared_rows, &identity).is_none() {
                return Err(WasmDispatchError::DeliveryUnavailable);
            }
            if let Some(live) = read_live_material(install_dir)?
                && !identity.matches_material(&live)
            {
                let live_envelope = material_bytes(&live)?;
                retire_or_backpressure_live(&owner_lock, &live, &live_envelope, install_dir)?;
            }
            let live = read_live_material(install_dir)?;
            let fixed_matches = match live {
                Some(live) if identity.matches_material(&live) => {
                    fixed_payloads_match(install_dir, &identity)?
                }
                None => false,
                Some(_) => return Err(WasmDispatchError::DeliveryUnavailable),
            };
            if !fixed_matches {
                reexpose_fixed_delivery_from_slot(&owner_lock, install_dir, &slot, &identity)?;
            }
        }
        joins.register_delivery(&join, &identity);
        return Ok(WasmPublishedBundle {
            material,
            join,
            material_path: install_dir.join(WASM_HOST_MATERIAL_FILE_NAME),
            artifact_path: install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
            input_path: install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
            delivery: identity,
            slot_dir: slot,
        });
    }

    let rows = prepare_delivery_publication_space(&owner_lock, install_dir, &rows, None)?;
    if let Some(live) = read_live_material(install_dir)? {
        let live_envelope = material_bytes(&live)?;
        retire_or_backpressure_live(&owner_lock, &live, &live_envelope, install_dir)?;
    }
    if fixed_names_present(
        install_dir,
        &[
            WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
            WASM_HOST_GUEST_INPUT_FILE_NAME,
        ],
    )? {
        return Err(WasmDispatchError::DeliveryUnavailable);
    }
    if rows.len() >= MAX_DELIVERY_HISTORY {
        return Err(delivery_capacity_backpressure(
            &rows,
            "bounded delivery history capacity is available",
        ));
    }
    let active_slots = rows
        .iter()
        .filter(|(_, _, snapshot, _)| {
            matches!(
                &snapshot.disposition.disposition,
                WasmDeliveryDisposition::Ready { .. }
                    | WasmDeliveryDisposition::LaunchReserved { .. }
                    | WasmDeliveryDisposition::InFlight { .. }
                    | WasmDeliveryDisposition::TerminalUnacknowledged { .. }
            )
        })
        .count();
    if active_slots >= MAX_DELIVERY_SLOTS {
        return Err(delivery_capacity_backpressure(
            &rows,
            "a protected delivery slot is acknowledged or retired",
        ));
    }
    let retained_bytes = rows.iter().fold(0_u64, |total, (_, _, _, bytes)| {
        total.saturating_add(*bytes)
    });
    let reservation_bytes = (MAX_DELIVERY_PAYLOAD_BYTES as u64)
        .saturating_mul(4)
        .saturating_add(MAX_DELIVERY_DISPOSITION_BYTES.saturating_mul(4));
    if retained_bytes.saturating_add(reservation_bytes) > MAX_DELIVERY_RETAINED_BYTES {
        return Err(delivery_capacity_backpressure(
            &rows,
            "bounded retained delivery byte capacity is available",
        ));
    }
    let revision = rows
        .iter()
        .map(|(_, _, snapshot, _)| snapshot.disposition.identity().publication_revision)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(WasmDispatchError::DeliveryUnavailable)?;
    let identity = WasmDeliveryIdentity::from_material(
        &material,
        &envelope_digest,
        host_artifact_digest,
        revision,
    )?;
    let slot_name = identity.slot_name();
    let slot = slots.join(&slot_name);
    if std::fs::symlink_metadata(&slot).is_ok() {
        return Err(WasmDispatchError::DeliveryConflict);
    }
    let material_path = stage_and_expose_delivery(
        &owner_lock,
        install_dir,
        &slot,
        &slot_name,
        &identity,
        &join,
        &envelope,
        claim,
    )?;
    // Register only after every file staged: a failed delivery leaves no
    // phantom join behind. The join closes over the delivery identity so
    // Join Ready cannot outlive missing material without an explicit
    // recoverable failed publication.
    joins.register_delivery(&join, &identity);
    Ok(WasmPublishedBundle {
        material,
        join,
        material_path,
        artifact_path: install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
        input_path: install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
        delivery: identity,
        slot_dir: slot,
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
        assert_eq!(
            bundle.artifact_path,
            dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME)
        );
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
    /// (`bins/eliot-wasm-host/src/parent_authority.rs`, join issuance
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
        assert!(
            join.authority_id
                .starts_with(WASM_DISPATCH_AUTHORITY_PREFIX)
        );
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
