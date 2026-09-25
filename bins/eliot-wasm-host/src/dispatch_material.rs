//! Validated dispatch material for the WASM P03 child contour (issue #1955).
//!
//! Session-bound dispatch material validated against itself, plus the
//! colocated guest bytes re-hashed against the bound digests. Carries
//! exactly what the parent drive binds: pre-binding derivation identities,
//! the validated grant funding the one-shot permit, the owner-measured host
//! digest, and the proven guest bytes.
//!
//! Wire contract: the owner publisher (`eliot-kernel-service::
//! wasm_dispatch`) stages the material envelope JSON plus the colocated
//! guest artifact/input files next to the installed image under the file
//! names below. The envelope field names and closed spelling sets are the
//! contract with that publisher; this module parses the staged envelope
//! bytes and enforces the same shapes the publisher enforces, so a mixed
//! or tampered envelope fails here before any authority, permit, or child
//! exists.
//!
//! Learning-ticket note: guest/input bytes cross this module opaquely.
//! Ticket screening is single-owned by the learning lane's guest gate
//! (`check_guest_tickets` over `AdmissionInput` in
//! `work/2376-guest-gate-ticket`); this module binds input digests and
//! never screens tickets, so no second admission surface is invented
//! here. Where the seated path must screen, the drive invokes the
//! caller-provided screen hook (see `dispatch_drive`), which the
//! integration owner wires to that exact screen call.

use eliot_wasm_runtime::Sha256Digest;

use crate::cli_contract::Profile;

/// Dispatch material file name the child reader derives from its executable
/// directory (`current_exe`, never argv/stdin/env). Duplicated here because
/// the host drive half owns its read path; the owner publisher stays the
/// authority for the staged value.
pub const WASM_HOST_MATERIAL_FILE_NAME: &str = "eliot-wasm-host.admitted-dispatch.json";
/// Colocated guest artifact file name staged with the material.
pub const WASM_HOST_GUEST_ARTIFACT_FILE_NAME: &str = "eliot-wasm-host.guest-artifact.bin";
/// Colocated guest input file name staged with the material.
pub const WASM_HOST_GUEST_INPUT_FILE_NAME: &str = "eliot-wasm-host.guest-input.bin";
/// Material envelope wire identity, matched exactly with the publisher.
pub const WASM_DISPATCH_MATERIAL_WIRE_ID: &str = "eliot.wasm.dispatch-material";
/// Material envelope wire version, matched exactly with the publisher.
pub const WASM_DISPATCH_MATERIAL_WIRE_VERSION: u16 = 1;
/// Material staging allocation guard: guest inputs are small framed
/// vectors, never dumps.
pub const DISPATCH_MATERIAL_MAX_BYTES: u64 = 64 * 1024;

/// Fail-closed material errors. Stable codes only — no paths, digests, or
/// payloads echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterialError {
    /// No material was delivered; the caller keeps its fail-closed path.
    Missing,
    /// A staged file exceeds the allocation guard.
    TooLarge,
    /// A staged file could not be read (kind string only).
    Unreadable(String),
    /// The material bytes are not a valid envelope.
    Malformed,
    /// An observed file digest does not match the bound record.
    DigestMismatch,
    /// A record failed shape checks.
    InvalidRecord {
        /// Stable field name.
        field: &'static str,
    },
}

impl MaterialError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "DISPATCH_MATERIAL_MISSING",
            Self::TooLarge => "DISPATCH_MATERIAL_TOO_LARGE",
            Self::Unreadable(_) => "DISPATCH_MATERIAL_UNREADABLE",
            Self::Malformed => "DISPATCH_MATERIAL_MALFORMED",
            Self::DigestMismatch => "DISPATCH_MATERIAL_DIGEST_MISMATCH",
            Self::InvalidRecord { .. } => "DISPATCH_MATERIAL_INVALID_RECORD",
        }
    }
}

impl std::fmt::Display for MaterialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(kind) => {
                write!(formatter, "DISPATCH_MATERIAL_UNREADABLE:{kind}")
            }
            Self::InvalidRecord { field } => {
                write!(formatter, "DISPATCH_MATERIAL_INVALID_RECORD:{field}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for MaterialError {}

fn invalid(field: &'static str) -> MaterialError {
    MaterialError::InvalidRecord { field }
}

fn require_nonblank(value: &str, field: &'static str) -> Result<(), MaterialError> {
    if value.trim().is_empty() {
        return Err(invalid(field));
    }
    Ok(())
}

fn hex_digest(hex: &str, field: &'static str) -> Result<Sha256Digest, MaterialError> {
    Sha256Digest::new(hex.to_owned()).map_err(|_| invalid(field))
}

fn require_spelling(
    value: &str,
    accepted: &[&str],
    field: &'static str,
) -> Result<(), MaterialError> {
    if accepted.contains(&value) {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

/// Validated guest ceilings carried for intent derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuestCeilings {
    /// Pinned component identity.
    pub component_id: String,
    /// Re-proven artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Re-proven input digest.
    pub input_digest: Sha256Digest,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Fuel ceiling.
    pub max_fuel: u64,
    /// Memory byte ceiling.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms).
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks.
    pub epoch_deadline_ticks: u64,
    /// Table element ceiling.
    pub table_elements: u64,
    /// Instance ceiling.
    pub max_instances: u64,
    /// Artifact-read count ceiling.
    pub artifact_access_reads: u64,
    /// Artifact-read byte ceiling.
    pub artifact_access_bytes: u64,
}

/// Validated owner-authored manifest record. Closed-world constants are
/// enforced by the contour admission (`contour::check_activation_imports`
/// over the admitted generation); the owner validates entry shapes here so
/// malformed records fail at binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManifestRecord {
    /// Admitted component identity.
    pub component_id: String,
    /// Admitted world name.
    pub world: String,
    /// Admitted guest target.
    pub target: String,
    /// Owner-recorded source digest.
    pub source_digest: Sha256Digest,
    /// Owner-recorded state-contract digest.
    pub state_contract_digest: Sha256Digest,
    /// Owner-recorded required verifier.
    pub required_verifier: String,
    /// Owner-recorded admitted privacy classes (non-empty).
    pub privacy_classes: Vec<String>,
    /// Owned state class.
    pub state_class: String,
    /// Versioned state migration contract.
    pub migration_contract: String,
    /// Privacy policy binding.
    pub privacy_policy: String,
    /// Differential comparator binding.
    pub comparator: String,
    /// Rollback generation binding, when the comparator names one.
    pub rollback_generation: Option<String>,
}

/// Validated owner-authored work identity record. Enum spellings stay
/// verbatim here; the invocation adapter maps them strictly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkRecord {
    /// Admitted owner identity.
    pub owner: String,
    /// Admitted work-unit identity.
    pub work_unit: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Optional task reference.
    pub task_ref: Option<String>,
    /// Admitted lease identity.
    pub lease_id: String,
    /// Lease scope reference (must equal the work scope).
    pub lease_scope_ref: String,
    /// Lease state marker.
    pub lease_state: String,
    /// Generation state marker.
    pub generation_state: String,
    /// Authority revision bound at admission.
    pub authority_revision: u64,
    /// Lifecycle revision bound at admission.
    pub lifecycle_revision: u64,
    /// Verification revision bound at admission.
    pub verification_revision: u64,
    /// Deterministic seed for the guest invocation.
    pub deterministic_seed: u64,
    /// Requested contour marker.
    pub contour: String,
    /// Owner-attested generation health dimensions in struct order.
    pub generation_health: Vec<String>,
}

/// Validated owner-authored assurance record, spellings verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAssuranceRecord {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement spelling.
    pub integrity: String,
    /// Freshness statement spelling.
    pub freshness: String,
    /// Competence classification spelling.
    pub competence: String,
    /// Independence classification spelling.
    pub independence: String,
    /// Privacy class spelling.
    pub privacy_class: String,
    /// Instruction taint spelling.
    pub instruction_taint: String,
    /// Permitted epistemic use spellings.
    pub epistemic_use: Vec<String>,
    /// Effect ceiling spellings.
    pub effect_ceilings: Vec<String>,
    /// Required verifier (must equal the manifest verifier).
    pub required_verifier: String,
    /// Quarantine state spelling.
    pub quarantine: String,
}

/// Validated owner-authored promotion oracle record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPromotionRecord {
    /// Corpus digest.
    pub corpus_digest: Sha256Digest,
    /// Oracle result digest.
    pub expected_result_digest: Sha256Digest,
    /// Oracle effect digest.
    pub expected_effect_digest: Sha256Digest,
    /// Oracle state-delta digest.
    pub expected_state_delta_digest: Sha256Digest,
}

/// Validated owner-attested snapshot record. Fence/epoch agreement with
/// the dispatch grant is enforced by the authority join, which derives
/// every fence from the grant; the epoch travels here as the canonical
/// JSON the derivation hashes verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSnapshotRecord {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation (must equal the grant fence generation).
    pub generation: u64,
    /// Canonical live-authority-epoch JSON (derivation input, never
    /// interpreted here).
    pub authority_epoch_json: String,
    /// Admitted Kernel artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Protected handoff snapshot digest.
    pub protected_snapshot_digest: Sha256Digest,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

/// Validated dispatch grant funding the one-shot permit: the owner-issued
/// digest plus the fence/lease material the authority join rebuilds into
/// typed broker values. Window order is enforced at binding; liveness
/// against the wall clock stays with the permit issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchGrant {
    /// Owner-issued grant digest binding the admission identity.
    pub grant_digest: Sha256Digest,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Live activation generation bound at admission (non-zero).
    pub fence_generation: u64,
    /// Deterministic per-identity fence nonce.
    pub fence_nonce: String,
    /// Deterministic per-identity lease.
    pub idempotency_key: String,
    /// Durable admission time in Unix milliseconds (window opens).
    pub admitted_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds (window closes).
    pub expires_at: u64,
    /// Owner-measured SHA-256 of the installed child image bytes.
    pub host_artifact_digest: Sha256Digest,
}

/// Session-bound dispatch material validated against itself, plus the
/// colocated file bytes re-hashed against the bound records.
///
/// Carries exactly what the parent drive binds: pre-binding derivation
/// identities, the validated grant funding the one-shot permit, the
/// owner-measured host digest, and the proven guest bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchMaterial {
    /// Admitted claim identity feeding the derivation base.
    pub claim_id: String,
    /// Admitted operation identity feeding the derivation base.
    pub operation_id: String,
    /// Claiming generation feeding the derivation base.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Claim-bound launch nonce (derivation + permit nonce).
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Validated grant funding the one-shot permit.
    pub grant: ValidatedDispatchGrant,
    /// Owner-measured installed-image digest.
    pub host_artifact_digest: Sha256Digest,
    /// Owner-selected composition profile, compiled into this binary.
    pub profile: Profile,
    /// Artifact digest of the prior conformance-verified run, when a
    /// Shadow operation must prove progression from it.
    pub prior_conformance_artifact: Option<Sha256Digest>,
    /// Validated manifest record.
    pub manifest: ValidatedManifestRecord,
    /// Validated work identity record.
    pub work: ValidatedWorkRecord,
    /// Validated assurance record.
    pub assurance: ValidatedAssuranceRecord,
    /// Validated promotion record.
    pub promotion: ValidatedPromotionRecord,
    /// Validated snapshot record.
    pub snapshot: ValidatedSnapshotRecord,
    /// Validated guest ceilings and pinned identities.
    pub ceilings: ValidatedGuestCeilings,
    /// Observed guest artifact bytes matching the bound digest.
    pub artifact_bytes: Vec<u8>,
    /// Observed guest input bytes matching the bound digest.
    pub input_bytes: Vec<u8>,
}

/// Typed material input: the already-parsed envelope records plus the
/// colocated bytes. The execution join produces this from the staged
/// envelope file; the drive binds it without re-parsing anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchMaterialInput {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON.
    pub authority_epoch_json: String,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Grant fence generation.
    pub grant_fence_generation: u64,
    /// Grant fence nonce.
    pub grant_fence_nonce: String,
    /// Grant lease identity.
    pub grant_idempotency_key: String,
    /// Grant expiry in Unix milliseconds.
    pub grant_expires_at: u64,
    /// Owner-measured installed-image digest (hex).
    pub host_artifact_digest: String,
    /// Owner-selected composition profile spelling.
    pub profile: String,
    /// Prior conformance-verified artifact digest (hex), if any.
    pub prior_conformance_artifact: Option<String>,
    /// Guest ceilings record.
    pub ceilings: ValidatedGuestCeilingsInput,
    /// Manifest record.
    pub manifest: ValidatedManifestInput,
    /// Work identity record.
    pub work: ValidatedWorkInput,
    /// Assurance record.
    pub assurance: ValidatedAssuranceInput,
    /// Promotion oracle record (hex digests).
    pub promotion: ValidatedPromotionInput,
    /// Snapshot record.
    pub snapshot: ValidatedSnapshotInput,
    /// Observed guest artifact bytes.
    pub artifact_bytes: Vec<u8>,
    /// Observed guest input bytes.
    pub input_bytes: Vec<u8>,
}

/// Typed guest ceilings input (digests as hex, ceilings as values).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuestCeilingsInput {
    /// Pinned component identity.
    pub component_id: String,
    /// Artifact digest (hex).
    pub artifact_digest: String,
    /// Input digest (hex).
    pub input_digest: String,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Fuel ceiling.
    pub max_fuel: u64,
    /// Memory byte ceiling.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms).
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks.
    pub epoch_deadline_ticks: u64,
    /// Table element ceiling.
    pub table_elements: u64,
    /// Instance ceiling.
    pub max_instances: u64,
    /// Artifact-read count ceiling.
    pub artifact_access_reads: u64,
    /// Artifact-read byte ceiling.
    pub artifact_access_bytes: u64,
}

/// Typed manifest input (digests as hex).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManifestInput {
    /// Admitted component identity.
    pub component_id: String,
    /// Admitted world name.
    pub world: String,
    /// Admitted guest target.
    pub target: String,
    /// Owner-recorded source digest (hex).
    pub source_digest: String,
    /// Owner-recorded state-contract digest (hex).
    pub state_contract_digest: String,
    /// Owner-recorded required verifier.
    pub required_verifier: String,
    /// Owner-recorded admitted privacy classes (non-empty).
    pub privacy_classes: Vec<String>,
    /// Owned state class.
    pub state_class: String,
    /// Versioned state migration contract.
    pub migration_contract: String,
    /// Privacy policy binding.
    pub privacy_policy: String,
    /// Differential comparator binding.
    pub comparator: String,
    /// Rollback generation binding, when the comparator names one.
    pub rollback_generation: Option<String>,
}

/// Typed work identity input (spellings verbatim).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkInput {
    /// Admitted owner identity.
    pub owner: String,
    /// Admitted work-unit identity.
    pub work_unit: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Optional task reference.
    pub task_ref: Option<String>,
    /// Admitted lease identity.
    pub lease_id: String,
    /// Lease scope reference (must equal the work scope).
    pub lease_scope_ref: String,
    /// Lease state marker.
    pub lease_state: String,
    /// Generation state marker.
    pub generation_state: String,
    /// Authority revision bound at admission.
    pub authority_revision: u64,
    /// Lifecycle revision bound at admission.
    pub lifecycle_revision: u64,
    /// Verification revision bound at admission.
    pub verification_revision: u64,
    /// Deterministic seed for the guest invocation.
    pub deterministic_seed: u64,
    /// Requested contour marker.
    pub contour: String,
    /// Owner-attested generation health dimensions (exactly six).
    pub generation_health: Vec<String>,
}

/// Typed assurance input (spellings verbatim).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAssuranceInput {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement spelling.
    pub integrity: String,
    /// Freshness statement spelling.
    pub freshness: String,
    /// Competence classification spelling.
    pub competence: String,
    /// Independence classification spelling.
    pub independence: String,
    /// Privacy class spelling.
    pub privacy_class: String,
    /// Instruction taint spelling.
    pub instruction_taint: String,
    /// Permitted epistemic use spellings.
    pub epistemic_use: Vec<String>,
    /// Effect ceiling spellings.
    pub effect_ceilings: Vec<String>,
    /// Required verifier (must equal the manifest verifier).
    pub required_verifier: String,
    /// Quarantine state spelling.
    pub quarantine: String,
}

/// Typed promotion oracle input (hex digests).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPromotionInput {
    /// Corpus digest (hex).
    pub corpus_digest: String,
    /// Oracle result digest (hex).
    pub expected_result_digest: String,
    /// Oracle effect digest (hex).
    pub expected_effect_digest: String,
    /// Oracle state-delta digest (hex).
    pub expected_state_delta_digest: String,
}

/// Typed snapshot input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSnapshotInput {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON.
    pub authority_epoch_json: String,
    /// Admitted Kernel artifact digest (hex).
    pub artifact_digest: String,
    /// Protected handoff snapshot digest (hex).
    pub protected_snapshot_digest: String,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

/// Derives the material file path from the executable directory.
/// `None` when the loader path is unavailable: no fallback source exists.
#[must_use]
pub fn admitted_material_path() -> Option<std::path::PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(WASM_HOST_MATERIAL_FILE_NAME))
}

/// Reads one staged file under the allocation guard. Returns
/// [`MaterialError::Missing`] for an absent file and [`MaterialError::TooLarge`]
/// before allocating over the ceiling — never a partial read.
pub fn read_staged_bytes(path: &std::path::Path) -> Result<Vec<u8>, MaterialError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            MaterialError::Missing
        } else {
            MaterialError::Unreadable(error.kind().to_string())
        }
    })?;
    if metadata.len() > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    let bytes =
        std::fs::read(path).map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    if bytes.len() as u64 > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    Ok(bytes)
}

/// Removes a consumed staging file. Best-effort by contract: the drive
/// consumes each staged set once, so a leftover is a fresh-drive signal,
/// never silent reuse.
pub fn consume_staged(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Wire mirror of the owner-published grant record, field-for-field with
/// the publisher. The authority epoch travels as canonical JSON and is
/// carried verbatim: fence construction from it belongs to the authority
/// join, never to this reader.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialGrantMirror {
    grant_digest: String,
    authority_epoch: serde_json::Value,
    fence_generation: u64,
    fence_nonce: String,
    idempotency_key: String,
    expires_at: u64,
    host_artifact_digest: String,
}

/// Wire mirror of the guest invocation ceilings record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestCeilingsMirror {
    artifact_digest: String,
    input_digest: String,
    max_output_bytes: u64,
    max_fuel: u64,
    max_memory_bytes: u64,
    wall_deadline_ms: u64,
    epoch_deadline_ticks: u64,
    table_elements: u64,
    max_instances: u64,
    artifact_access_reads: u64,
    artifact_access_bytes: u64,
    component_id: String,
}

/// Wire mirror of the owner-authored manifest record.
///
/// Closed-world declaration lists (`allowed_imports`, `allowed_exports`,
/// `capability_grants`) are parsed and carried for envelope closure but
/// enforced by contour admission, not read here — hence the dead-code
/// allowance on the mirror.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ManifestRecordMirror {
    component_id: String,
    world: String,
    target: String,
    source_digest: String,
    state_contract_digest: String,
    required_verifier: String,
    privacy_classes: Vec<String>,
    allowed_imports: Vec<String>,
    allowed_exports: Vec<String>,
    capability_grants: Vec<String>,
    state_class: String,
    migration_contract: String,
    privacy_policy: String,
    comparator: String,
    rollback_generation: Option<String>,
}

/// Wire mirror of the owner-authored work identity record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRecordMirror {
    owner: String,
    work_unit: String,
    work_scope: String,
    task_ref: Option<String>,
    lease_id: String,
    lease_scope_ref: String,
    lease_state: String,
    generation_state: String,
    authority_revision: u64,
    lifecycle_revision: u64,
    verification_revision: u64,
    deterministic_seed: u64,
    contour: String,
    generation_health: Vec<String>,
}

/// Wire mirror of the owner-authored assurance record. Enum spellings are
/// carried verbatim and mapped strictly by the binder; unknown spellings
/// fail closed there.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AssuranceRecordMirror {
    source_ref: String,
    provenance_ref: String,
    integrity: String,
    freshness: String,
    competence: String,
    independence: String,
    privacy_class: String,
    instruction_taint: String,
    epistemic_use: Vec<String>,
    effect_ceilings: Vec<String>,
    required_verifier: String,
    quarantine: String,
}

/// Wire mirror of the owner-authored promotion oracle record.
///
/// Field names mirror the publisher envelope exactly (hence the shared
/// `digest` postfix); renaming any of them breaks the closed envelope.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct PromotionRecordMirror {
    corpus_digest: String,
    expected_result_digest: String,
    expected_effect_digest: String,
    expected_state_delta_digest: String,
}

/// Wire mirror of the owner-attested snapshot record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRecordMirror {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: serde_json::Value,
    artifact_digest: String,
    protected_snapshot_digest: String,
    principal: String,
}

/// Wire mirror of the dispatch material envelope, field-for-field with the
/// owner publisher (`WasmDispatchMaterial`).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialEnvelopeMirror {
    wire_id: String,
    wire_version: u16,
    claim_id: String,
    operation_id: String,
    generation: u64,
    authority_epoch: serde_json::Value,
    launch_nonce: String,
    admitted_at_unix_ms: u64,
    grant: MaterialGrantMirror,
    guest: GuestCeilingsMirror,
    profile: String,
    prior_conformance_artifact: Option<String>,
    manifest: ManifestRecordMirror,
    work: WorkRecordMirror,
    assurance: AssuranceRecordMirror,
    promotion: PromotionRecordMirror,
    snapshot: SnapshotRecordMirror,
}

/// Canonical epoch JSON carried verbatim. The publisher serializes the
/// canonical `EpochId` shape (`lineage_id` then `sequence`, sorted keys),
/// and this reader re-serializes the parsed value the same way, so the
/// derivation input is byte-stable across the round trip. Never
/// interpreted here: fence construction belongs to the authority join.
fn epoch_json_string(value: &serde_json::Value) -> Result<String, MaterialError> {
    if !value.is_object() {
        return Err(MaterialError::Malformed);
    }
    serde_json::to_string(value).map_err(|_| MaterialError::Malformed)
}

/// Parses staged envelope bytes into a typed material input. The wire
/// identity and version must match exactly; every record then flows
/// through the same typed binder the direct path uses, so a malformed
/// envelope and a malformed record fail with the same typed refusal —
/// never a panic, never a partial bind.
///
/// The body is one straight field mapping by design: envelope order
/// follows publisher order so reviewers can diff them side by side.
#[allow(clippy::too_many_lines)]
fn parse_envelope(bytes: &[u8]) -> Result<DispatchMaterialInput, MaterialError> {
    let envelope: MaterialEnvelopeMirror =
        serde_json::from_slice(bytes).map_err(|_| MaterialError::Malformed)?;
    if envelope.wire_id != WASM_DISPATCH_MATERIAL_WIRE_ID
        || envelope.wire_version != WASM_DISPATCH_MATERIAL_WIRE_VERSION
    {
        return Err(MaterialError::Malformed);
    }
    let authority_epoch_json = epoch_json_string(&envelope.authority_epoch)?;
    let snapshot_epoch_json = epoch_json_string(&envelope.snapshot.authority_epoch)?;
    let grant_epoch_json = epoch_json_string(&envelope.grant.authority_epoch)?;
    if grant_epoch_json != authority_epoch_json || snapshot_epoch_json != authority_epoch_json {
        return Err(invalid("epoch-agreement"));
    }
    Ok(DispatchMaterialInput {
        claim_id: envelope.claim_id,
        operation_id: envelope.operation_id,
        generation: envelope.generation,
        authority_epoch_json,
        launch_nonce: envelope.launch_nonce,
        admitted_at_unix_ms: envelope.admitted_at_unix_ms,
        grant_digest: envelope.grant.grant_digest,
        grant_fence_generation: envelope.grant.fence_generation,
        grant_fence_nonce: envelope.grant.fence_nonce,
        grant_idempotency_key: envelope.grant.idempotency_key,
        grant_expires_at: envelope.grant.expires_at,
        host_artifact_digest: envelope.grant.host_artifact_digest,
        profile: envelope.profile,
        prior_conformance_artifact: envelope.prior_conformance_artifact,
        ceilings: ValidatedGuestCeilingsInput {
            component_id: envelope.guest.component_id,
            artifact_digest: envelope.guest.artifact_digest,
            input_digest: envelope.guest.input_digest,
            max_output_bytes: envelope.guest.max_output_bytes,
            max_fuel: envelope.guest.max_fuel,
            max_memory_bytes: envelope.guest.max_memory_bytes,
            wall_deadline_ms: envelope.guest.wall_deadline_ms,
            epoch_deadline_ticks: envelope.guest.epoch_deadline_ticks,
            table_elements: envelope.guest.table_elements,
            max_instances: envelope.guest.max_instances,
            artifact_access_reads: envelope.guest.artifact_access_reads,
            artifact_access_bytes: envelope.guest.artifact_access_bytes,
        },
        manifest: ValidatedManifestInput {
            component_id: envelope.manifest.component_id,
            world: envelope.manifest.world,
            target: envelope.manifest.target,
            source_digest: envelope.manifest.source_digest,
            state_contract_digest: envelope.manifest.state_contract_digest,
            required_verifier: envelope.manifest.required_verifier,
            privacy_classes: envelope.manifest.privacy_classes,
            state_class: envelope.manifest.state_class,
            migration_contract: envelope.manifest.migration_contract,
            privacy_policy: envelope.manifest.privacy_policy,
            comparator: envelope.manifest.comparator,
            rollback_generation: envelope.manifest.rollback_generation,
        },
        work: ValidatedWorkInput {
            owner: envelope.work.owner,
            work_unit: envelope.work.work_unit,
            work_scope: envelope.work.work_scope,
            task_ref: envelope.work.task_ref,
            lease_id: envelope.work.lease_id,
            lease_scope_ref: envelope.work.lease_scope_ref,
            lease_state: envelope.work.lease_state,
            generation_state: envelope.work.generation_state,
            authority_revision: envelope.work.authority_revision,
            lifecycle_revision: envelope.work.lifecycle_revision,
            verification_revision: envelope.work.verification_revision,
            deterministic_seed: envelope.work.deterministic_seed,
            contour: envelope.work.contour,
            generation_health: envelope.work.generation_health,
        },
        assurance: ValidatedAssuranceInput {
            source_ref: envelope.assurance.source_ref,
            provenance_ref: envelope.assurance.provenance_ref,
            integrity: envelope.assurance.integrity,
            freshness: envelope.assurance.freshness,
            competence: envelope.assurance.competence,
            independence: envelope.assurance.independence,
            privacy_class: envelope.assurance.privacy_class,
            instruction_taint: envelope.assurance.instruction_taint,
            epistemic_use: envelope.assurance.epistemic_use,
            effect_ceilings: envelope.assurance.effect_ceilings,
            required_verifier: envelope.assurance.required_verifier,
            quarantine: envelope.assurance.quarantine,
        },
        promotion: ValidatedPromotionInput {
            corpus_digest: envelope.promotion.corpus_digest,
            expected_result_digest: envelope.promotion.expected_result_digest,
            expected_effect_digest: envelope.promotion.expected_effect_digest,
            expected_state_delta_digest: envelope.promotion.expected_state_delta_digest,
        },
        snapshot: ValidatedSnapshotInput {
            service: envelope.snapshot.service,
            protocol: envelope.snapshot.protocol,
            generation: envelope.snapshot.generation,
            authority_epoch_json: snapshot_epoch_json,
            artifact_digest: envelope.snapshot.artifact_digest,
            protected_snapshot_digest: envelope.snapshot.protected_snapshot_digest,
            principal: envelope.snapshot.principal,
        },
        artifact_bytes: Vec::new(),
        input_bytes: Vec::new(),
    })
}

/// Reads and validates one staged dispatch material set from the install
/// directory: the envelope file parses and binds, then the colocated
/// guest artifact/input files read bounded and re-hash against the bound
/// digests. A missing envelope is `Ok(None)` — the caller keeps its
/// fail-closed path; anything present but invalid fails closed.
///
/// # Errors
///
/// Returns [`MaterialError`] when any staged file is oversized,
/// unreadable, malformed, or fails shape and byte binding.
pub fn read_dispatch_material_from(
    install_dir: &std::path::Path,
) -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    let material_path = install_dir.join(WASM_HOST_MATERIAL_FILE_NAME);
    let envelope_bytes = match read_staged_bytes(&material_path) {
        Err(MaterialError::Missing) => return Ok(None),
        Err(error) => return Err(error),
        Ok(bytes) => bytes,
    };
    let mut input = parse_envelope(&envelope_bytes)?;
    input.artifact_bytes =
        read_staged_bytes(&install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME))?;
    input.input_bytes = read_staged_bytes(&install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME))?;
    bind_dispatch_material(input).map(Some)
}

/// Reads staged dispatch material from the executable directory
/// (`current_exe`, never argv/stdin/env). `None` when no material was
/// delivered or the loader path is unavailable.
///
/// # Errors
///
/// Returns [`MaterialError`] when staged files are present but invalid.
pub fn read_dispatch_material() -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    let Some(path) = admitted_material_path() else {
        return Ok(None);
    };
    let Some(directory) = path.parent() else {
        return Ok(None);
    };
    read_dispatch_material_from(directory)
}

/// Binds one typed material input into validated dispatch material.
///
/// Every identity is non-blank, every digest hex-shaped and re-proven
/// against the colocated bytes, every ceiling non-zero, every enum
/// spelling drawn from the closed owner sets, the manifest and assurance
/// verifiers in agreement, and the grant window ordered. A mixed envelope
/// fails closed here, before any authority, permit, or child exists.
///
/// # Errors
///
/// Returns [`MaterialError`] when any record, digest, ceiling, spelling,
/// or byte binding fails closed.
#[allow(clippy::too_many_lines)]
pub fn bind_dispatch_material(
    input: DispatchMaterialInput,
) -> Result<ValidatedDispatchMaterial, MaterialError> {
    require_nonblank(&input.claim_id, "claim-id")?;
    require_nonblank(&input.operation_id, "operation-id")?;
    require_nonblank(&input.launch_nonce, "launch-nonce")?;
    require_nonblank(&input.authority_epoch_json, "authority-epoch")?;
    if input.generation == 0 {
        return Err(invalid("generation"));
    }
    if input.admitted_at_unix_ms == 0 {
        return Err(invalid("admitted-at"));
    }
    let profile: Profile = input.profile.parse().map_err(|_| invalid("profile"))?;
    if !profile.is_compiled() {
        return Err(invalid("profile"));
    }
    let prior_conformance_artifact = input
        .prior_conformance_artifact
        .as_deref()
        .map(|hex| hex_digest(hex, "prior-conformance"))
        .transpose()?;
    let grant = bind_grant(&input)?;
    let ceilings = bind_ceilings(&input.ceilings)?;
    let manifest = bind_manifest(&input.manifest)?;
    let work = bind_work(&input.work)?;
    let assurance = bind_assurance(&input.assurance)?;
    let promotion = bind_promotion(&input.promotion)?;
    let snapshot = bind_snapshot(&input.snapshot)?;
    if manifest.required_verifier != assurance.required_verifier {
        return Err(invalid("verifier-agreement"));
    }
    if snapshot.generation != grant.fence_generation {
        return Err(invalid("snapshot-generation"));
    }
    if input.generation != grant.fence_generation {
        return Err(invalid("generation-agreement"));
    }
    if input.artifact_bytes.is_empty() || input.input_bytes.is_empty() {
        return Err(invalid("guest-bytes"));
    }
    if Sha256Digest::of_bytes(&input.artifact_bytes) != ceilings.artifact_digest
        || Sha256Digest::of_bytes(&input.input_bytes) != ceilings.input_digest
    {
        return Err(MaterialError::DigestMismatch);
    }
    let host_artifact_digest = hex_digest(&input.host_artifact_digest, "host-digest")?;
    Ok(ValidatedDispatchMaterial {
        claim_id: input.claim_id,
        operation_id: input.operation_id,
        generation: input.generation,
        authority_epoch_json: input.authority_epoch_json,
        launch_nonce: input.launch_nonce,
        admitted_at_unix_ms: input.admitted_at_unix_ms,
        grant,
        host_artifact_digest,
        profile,
        prior_conformance_artifact,
        manifest,
        work,
        assurance,
        promotion,
        snapshot,
        ceilings,
        artifact_bytes: input.artifact_bytes,
        input_bytes: input.input_bytes,
    })
}

fn bind_grant(input: &DispatchMaterialInput) -> Result<ValidatedDispatchGrant, MaterialError> {
    let grant_digest = hex_digest(&input.grant_digest, "grant-digest")?;
    require_nonblank(&input.grant_fence_nonce, "grant-fence-nonce")?;
    require_nonblank(&input.grant_idempotency_key, "grant-lease")?;
    if input.grant_fence_generation == 0 {
        return Err(invalid("grant-generation"));
    }
    if input.admitted_at_unix_ms == 0 {
        return Err(invalid("grant-admission-time"));
    }
    if input.grant_expires_at <= input.admitted_at_unix_ms {
        return Err(invalid("grant-expiry"));
    }
    Ok(ValidatedDispatchGrant {
        grant_digest,
        authority_epoch_json: input.authority_epoch_json.clone(),
        fence_generation: input.grant_fence_generation,
        fence_nonce: input.grant_fence_nonce.clone(),
        idempotency_key: input.grant_idempotency_key.clone(),
        admitted_at_unix_ms: input.admitted_at_unix_ms,
        expires_at: input.grant_expires_at,
        host_artifact_digest: hex_digest(&input.host_artifact_digest, "host-digest")?,
    })
}

fn bind_ceilings(
    ceilings: &ValidatedGuestCeilingsInput,
) -> Result<ValidatedGuestCeilings, MaterialError> {
    require_nonblank(&ceilings.component_id, "guest-component-id")?;
    if ceilings.max_output_bytes == 0
        || ceilings.max_fuel == 0
        || ceilings.max_memory_bytes == 0
        || ceilings.wall_deadline_ms == 0
        || ceilings.epoch_deadline_ticks == 0
        || ceilings.table_elements == 0
        || ceilings.max_instances == 0
        || ceilings.artifact_access_reads == 0
        || ceilings.artifact_access_bytes == 0
    {
        return Err(invalid("guest-ceilings"));
    }
    Ok(ValidatedGuestCeilings {
        component_id: ceilings.component_id.clone(),
        artifact_digest: hex_digest(&ceilings.artifact_digest, "guest-artifact-digest")?,
        input_digest: hex_digest(&ceilings.input_digest, "guest-input-digest")?,
        max_output_bytes: ceilings.max_output_bytes,
        max_fuel: ceilings.max_fuel,
        max_memory_bytes: ceilings.max_memory_bytes,
        wall_deadline_ms: ceilings.wall_deadline_ms,
        epoch_deadline_ticks: ceilings.epoch_deadline_ticks,
        table_elements: ceilings.table_elements,
        max_instances: ceilings.max_instances,
        artifact_access_reads: ceilings.artifact_access_reads,
        artifact_access_bytes: ceilings.artifact_access_bytes,
    })
}

fn bind_manifest(
    manifest: &ValidatedManifestInput,
) -> Result<ValidatedManifestRecord, MaterialError> {
    require_nonblank(&manifest.component_id, "manifest-component-id")?;
    require_nonblank(&manifest.world, "manifest-world")?;
    require_nonblank(&manifest.target, "manifest-target")?;
    if manifest.privacy_classes.is_empty() {
        return Err(invalid("manifest-privacy"));
    }
    for value in &manifest.privacy_classes {
        require_nonblank(value, "manifest-entries")?;
    }
    require_nonblank(&manifest.required_verifier, "manifest-verifier")?;
    require_nonblank(&manifest.state_class, "manifest-state-class")?;
    require_nonblank(&manifest.migration_contract, "manifest-migration")?;
    require_nonblank(&manifest.privacy_policy, "manifest-privacy-policy")?;
    require_nonblank(&manifest.comparator, "manifest-comparator")?;
    Ok(ValidatedManifestRecord {
        component_id: manifest.component_id.clone(),
        world: manifest.world.clone(),
        target: manifest.target.clone(),
        source_digest: hex_digest(&manifest.source_digest, "manifest-source-digest")?,
        state_contract_digest: hex_digest(
            &manifest.state_contract_digest,
            "manifest-state-digest",
        )?,
        required_verifier: manifest.required_verifier.clone(),
        privacy_classes: manifest.privacy_classes.clone(),
        state_class: manifest.state_class.clone(),
        migration_contract: manifest.migration_contract.clone(),
        privacy_policy: manifest.privacy_policy.clone(),
        comparator: manifest.comparator.clone(),
        rollback_generation: manifest.rollback_generation.clone(),
    })
}

fn bind_work(work: &ValidatedWorkInput) -> Result<ValidatedWorkRecord, MaterialError> {
    require_nonblank(&work.owner, "work-owner")?;
    require_nonblank(&work.work_unit, "work-unit")?;
    require_nonblank(&work.work_scope, "work-scope")?;
    require_nonblank(&work.lease_id, "lease-id")?;
    require_nonblank(&work.lease_scope_ref, "lease-scope")?;
    if work.lease_scope_ref != work.work_scope {
        return Err(invalid("lease-scope"));
    }
    require_spelling(&work.lease_state, &["active"], "lease-state")?;
    require_spelling(
        &work.generation_state,
        &["ready", "active"],
        "generation-state",
    )?;
    if work.authority_revision == 0
        || work.lifecycle_revision == 0
        || work.verification_revision == 0
    {
        return Err(invalid("work-revisions"));
    }
    require_spelling(&work.contour, &["SHADOW", "CONFORMANCE"], "work-contour")?;
    if work.generation_health.len() != 6 {
        return Err(invalid("work-health"));
    }
    for value in &work.generation_health {
        require_spelling(
            value,
            &["UNKNOWN", "HEALTHY", "DEGRADED", "FAILED"],
            "work-health",
        )?;
    }
    Ok(ValidatedWorkRecord {
        owner: work.owner.clone(),
        work_unit: work.work_unit.clone(),
        work_scope: work.work_scope.clone(),
        task_ref: work.task_ref.clone(),
        lease_id: work.lease_id.clone(),
        lease_scope_ref: work.lease_scope_ref.clone(),
        lease_state: work.lease_state.clone(),
        generation_state: work.generation_state.clone(),
        authority_revision: work.authority_revision,
        lifecycle_revision: work.lifecycle_revision,
        verification_revision: work.verification_revision,
        deterministic_seed: work.deterministic_seed,
        contour: work.contour.clone(),
        generation_health: work.generation_health.clone(),
    })
}

fn bind_assurance(
    assurance: &ValidatedAssuranceInput,
) -> Result<ValidatedAssuranceRecord, MaterialError> {
    require_nonblank(&assurance.source_ref, "assurance-source")?;
    require_nonblank(&assurance.provenance_ref, "assurance-provenance")?;
    require_spelling(
        &assurance.integrity,
        &["VERIFIED", "UNVERIFIED", "MODIFIED", "CONFLICTED"],
        "assurance-integrity",
    )?;
    require_spelling(
        &assurance.freshness,
        &["CURRENT", "STALE", "UNKNOWN"],
        "assurance-freshness",
    )?;
    require_spelling(
        &assurance.competence,
        &["DOMAIN_VERIFIED", "ATTRIBUTED", "UNKNOWN"],
        "assurance-competence",
    )?;
    require_spelling(
        &assurance.independence,
        &["INDEPENDENT", "RELATED", "COMMON_MODE", "UNKNOWN"],
        "assurance-independence",
    )?;
    require_spelling(
        &assurance.privacy_class,
        &["PUBLIC", "INTERNAL", "PRIVATE", "SECRET", "LICENSED"],
        "assurance-privacy",
    )?;
    require_spelling(
        &assurance.instruction_taint,
        &["CLEARED", "DATA_ONLY", "UNTRUSTED", "COMMAND_LIKE"],
        "assurance-taint",
    )?;
    for value in &assurance.epistemic_use {
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
    for value in &assurance.effect_ceilings {
        require_spelling(
            value,
            &["READ_ONLY", "CANDIDATE_ONLY", "NO_EXTERNAL_EFFECT"],
            "assurance-effects",
        )?;
    }
    require_nonblank(&assurance.required_verifier, "assurance-verifier")?;
    require_spelling(
        &assurance.quarantine,
        &["NONE", "REVIEW_REQUIRED", "QUARANTINED", "RELEASED"],
        "assurance-quarantine",
    )?;
    Ok(ValidatedAssuranceRecord {
        source_ref: assurance.source_ref.clone(),
        provenance_ref: assurance.provenance_ref.clone(),
        integrity: assurance.integrity.clone(),
        freshness: assurance.freshness.clone(),
        competence: assurance.competence.clone(),
        independence: assurance.independence.clone(),
        privacy_class: assurance.privacy_class.clone(),
        instruction_taint: assurance.instruction_taint.clone(),
        epistemic_use: assurance.epistemic_use.clone(),
        effect_ceilings: assurance.effect_ceilings.clone(),
        required_verifier: assurance.required_verifier.clone(),
        quarantine: assurance.quarantine.clone(),
    })
}

fn bind_promotion(
    promotion: &ValidatedPromotionInput,
) -> Result<ValidatedPromotionRecord, MaterialError> {
    Ok(ValidatedPromotionRecord {
        corpus_digest: hex_digest(&promotion.corpus_digest, "promotion-corpus")?,
        expected_result_digest: hex_digest(&promotion.expected_result_digest, "promotion-result")?,
        expected_effect_digest: hex_digest(&promotion.expected_effect_digest, "promotion-effects")?,
        expected_state_delta_digest: hex_digest(
            &promotion.expected_state_delta_digest,
            "promotion-state-delta",
        )?,
    })
}

fn bind_snapshot(
    snapshot: &ValidatedSnapshotInput,
) -> Result<ValidatedSnapshotRecord, MaterialError> {
    require_nonblank(&snapshot.service, "snapshot-service")?;
    require_nonblank(&snapshot.protocol, "snapshot-protocol")?;
    require_nonblank(&snapshot.authority_epoch_json, "snapshot-epoch")?;
    require_nonblank(&snapshot.principal, "snapshot-principal")?;
    if snapshot.generation == 0 {
        return Err(invalid("snapshot-generation"));
    }
    Ok(ValidatedSnapshotRecord {
        service: snapshot.service.clone(),
        protocol: snapshot.protocol.clone(),
        generation: snapshot.generation,
        authority_epoch_json: snapshot.authority_epoch_json.clone(),
        artifact_digest: hex_digest(&snapshot.artifact_digest, "snapshot-artifact")?,
        protected_snapshot_digest: hex_digest(
            &snapshot.protected_snapshot_digest,
            "snapshot-protected",
        )?,
        principal: snapshot.principal.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn digest_of(bytes: &[u8]) -> String {
        Sha256Digest::of_bytes(bytes).as_str().to_owned()
    }

    fn test_input() -> DispatchMaterialInput {
        let artifact = b"material-artifact-bytes".to_vec();
        let input = b"material-input-bytes".to_vec();
        DispatchMaterialInput {
            claim_id: "claim-material-001".to_owned(),
            operation_id: "operation-material-001".to_owned(),
            generation: 7,
            authority_epoch_json:
                "{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3}"
                    .to_owned(),
            launch_nonce: "launch-nonce-material-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant_digest: "e".repeat(64),
            grant_fence_generation: 7,
            grant_fence_nonce: "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
            grant_idempotency_key: "wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned(),
            grant_expires_at: 4_000_000_060_000,
            host_artifact_digest: "d".repeat(64),
            profile: "D2_OPERATIONAL".to_owned(),
            prior_conformance_artifact: None,
            ceilings: ValidatedGuestCeilingsInput {
                component_id: "component-material".to_owned(),
                artifact_digest: digest_of(&artifact),
                input_digest: digest_of(&input),
                max_output_bytes: 4096,
                max_fuel: 100_000,
                max_memory_bytes: 536_870_912,
                wall_deadline_ms: 30_000,
                epoch_deadline_ticks: 100,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            manifest: ValidatedManifestInput {
                component_id: "component-material".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: "b".repeat(64),
                state_contract_digest: "f".repeat(64),
                required_verifier: "verifier:a12".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: ValidatedWorkInput {
                owner: "owner-material".to_owned(),
                work_unit: "work-material".to_owned(),
                work_scope: "scope-material".to_owned(),
                task_ref: Some("task-material".to_owned()),
                lease_id: "lease-material".to_owned(),
                lease_scope_ref: "scope-material".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: ValidatedAssuranceInput {
                source_ref: "source-material".to_owned(),
                provenance_ref: "provenance-material".to_owned(),
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
            },
            promotion: ValidatedPromotionInput {
                corpus_digest: "0".repeat(64),
                expected_result_digest: "1".repeat(64),
                expected_effect_digest: "2".repeat(64),
                expected_state_delta_digest: "3".repeat(64),
            },
            snapshot: ValidatedSnapshotInput {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch_json:
                    "{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3}"
                        .to_owned(),
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "S-1-5-18".to_owned(),
            },
            artifact_bytes: artifact,
            input_bytes: input,
        }
    }

    #[test]
    fn valid_material_binds_with_proven_bytes() {
        let material = bind_dispatch_material(test_input()).expect("material binds");
        assert_eq!(material.claim_id, "claim-material-001");
        assert_eq!(material.operation_id, "operation-material-001");
        assert_eq!(material.generation, 7);
        assert_eq!(material.profile, Profile::D2Operational);
        assert!(material.prior_conformance_artifact.is_none());
        assert_eq!(material.grant.expires_at, 4_000_000_060_000);
        assert_eq!(material.snapshot.service, "eliot-kernel");
        assert_eq!(
            material.ceilings.artifact_digest.as_str(),
            digest_of(b"material-artifact-bytes").as_str()
        );
    }

    #[test]
    fn tampered_bytes_deny_before_any_permit() {
        let mut tampered = test_input();
        tampered.artifact_bytes = b"tampered-artifact".to_vec();
        assert_eq!(
            bind_dispatch_material(tampered),
            Err(MaterialError::DigestMismatch)
        );
    }

    #[test]
    fn malformed_records_fail_closed() {
        // Blank claim.
        let mut blank = test_input();
        blank.claim_id.clear();
        assert_eq!(
            bind_dispatch_material(blank).map(|_| ()),
            Err(MaterialError::InvalidRecord { field: "claim-id" })
        );
        // Unknown profile spelling.
        let mut profile = test_input();
        profile.profile = "LABORATORY".to_owned();
        assert_eq!(
            bind_dispatch_material(profile).map(|_| ()),
            Err(MaterialError::InvalidRecord { field: "profile" })
        );
        // Verifier disagreement between manifest and assurance.
        let mut verifier = test_input();
        verifier.assurance.required_verifier = "verifier:foreign".to_owned();
        assert_eq!(
            bind_dispatch_material(verifier).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "verifier-agreement"
            })
        );
        // Lease scope must equal the work scope.
        let mut scope = test_input();
        scope.work.lease_scope_ref = "scope-foreign".to_owned();
        assert_eq!(
            bind_dispatch_material(scope).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "lease-scope"
            })
        );
        // Malformed prior digest fails closed.
        let mut prior = test_input();
        prior.prior_conformance_artifact = Some("not-a-digest".to_owned());
        assert_eq!(
            bind_dispatch_material(prior).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "prior-conformance"
            })
        );
        // Expired grant window fails closed.
        let mut window = test_input();
        window.grant_expires_at = window.admitted_at_unix_ms;
        assert_eq!(
            bind_dispatch_material(window).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "grant-expiry"
            })
        );
    }

    #[test]
    fn staged_reader_guards_absence_and_size() {
        let missing = std::path::Path::new("definitely-absent-2377-material.json");
        assert_eq!(read_staged_bytes(missing), Err(MaterialError::Missing));
        let path = std::env::temp_dir().join("eliot-2377-oversize-material.bin");
        std::fs::write(&path, vec![0xA5; DISPATCH_MATERIAL_MAX_BYTES as usize + 1])
            .expect("oversize fixture writable");
        assert_eq!(read_staged_bytes(&path), Err(MaterialError::TooLarge));
        let _ = std::fs::remove_file(&path);
    }

    fn test_envelope_json(input: &DispatchMaterialInput) -> Vec<u8> {
        let epoch: serde_json::Value =
            serde_json::from_str(&input.authority_epoch_json).expect("epoch parses");
        serde_json::to_vec(&serde_json::json!({
            "wire_id": WASM_DISPATCH_MATERIAL_WIRE_ID,
            "wire_version": WASM_DISPATCH_MATERIAL_WIRE_VERSION,
            "claim_id": input.claim_id,
            "operation_id": input.operation_id,
            "generation": input.generation,
            "authority_epoch": epoch,
            "launch_nonce": input.launch_nonce,
            "admitted_at_unix_ms": input.admitted_at_unix_ms,
            "grant": {
                "grant_digest": input.grant_digest,
                "authority_epoch": epoch,
                "fence_generation": input.grant_fence_generation,
                "fence_nonce": input.grant_fence_nonce,
                "idempotency_key": input.grant_idempotency_key,
                "expires_at": input.grant_expires_at,
                "host_artifact_digest": input.host_artifact_digest,
            },
            "guest": {
                "artifact_digest": input.ceilings.artifact_digest,
                "input_digest": input.ceilings.input_digest,
                "max_output_bytes": input.ceilings.max_output_bytes,
                "max_fuel": input.ceilings.max_fuel,
                "max_memory_bytes": input.ceilings.max_memory_bytes,
                "wall_deadline_ms": input.ceilings.wall_deadline_ms,
                "epoch_deadline_ticks": input.ceilings.epoch_deadline_ticks,
                "table_elements": input.ceilings.table_elements,
                "max_instances": input.ceilings.max_instances,
                "artifact_access_reads": input.ceilings.artifact_access_reads,
                "artifact_access_bytes": input.ceilings.artifact_access_bytes,
                "component_id": input.ceilings.component_id,
            },
            "profile": input.profile,
            "prior_conformance_artifact": input.prior_conformance_artifact,
            "manifest": {
                "component_id": input.manifest.component_id,
                "world": input.manifest.world,
                "target": input.manifest.target,
                "source_digest": input.manifest.source_digest,
                "state_contract_digest": input.manifest.state_contract_digest,
                "required_verifier": input.manifest.required_verifier,
                "privacy_classes": input.manifest.privacy_classes,
                "allowed_imports": [],
                "allowed_exports": ["run"],
                "capability_grants": [],
                "state_class": input.manifest.state_class,
                "migration_contract": input.manifest.migration_contract,
                "privacy_policy": input.manifest.privacy_policy,
                "comparator": input.manifest.comparator,
                "rollback_generation": input.manifest.rollback_generation,
            },
            "work": {
                "owner": input.work.owner,
                "work_unit": input.work.work_unit,
                "work_scope": input.work.work_scope,
                "task_ref": input.work.task_ref,
                "lease_id": input.work.lease_id,
                "lease_scope_ref": input.work.lease_scope_ref,
                "lease_state": input.work.lease_state,
                "generation_state": input.work.generation_state,
                "authority_revision": input.work.authority_revision,
                "lifecycle_revision": input.work.lifecycle_revision,
                "verification_revision": input.work.verification_revision,
                "deterministic_seed": input.work.deterministic_seed,
                "contour": input.work.contour,
                "generation_health": input.work.generation_health,
            },
            "assurance": {
                "source_ref": input.assurance.source_ref,
                "provenance_ref": input.assurance.provenance_ref,
                "integrity": input.assurance.integrity,
                "freshness": input.assurance.freshness,
                "competence": input.assurance.competence,
                "independence": input.assurance.independence,
                "privacy_class": input.assurance.privacy_class,
                "instruction_taint": input.assurance.instruction_taint,
                "epistemic_use": input.assurance.epistemic_use,
                "effect_ceilings": input.assurance.effect_ceilings,
                "required_verifier": input.assurance.required_verifier,
                "quarantine": input.assurance.quarantine,
            },
            "promotion": {
                "corpus_digest": input.promotion.corpus_digest,
                "expected_result_digest": input.promotion.expected_result_digest,
                "expected_effect_digest": input.promotion.expected_effect_digest,
                "expected_state_delta_digest": input.promotion.expected_state_delta_digest,
            },
            "snapshot": {
                "service": input.snapshot.service,
                "protocol": input.snapshot.protocol,
                "generation": input.snapshot.generation,
                "authority_epoch": epoch,
                "artifact_digest": input.snapshot.artifact_digest,
                "protected_snapshot_digest": input.snapshot.protected_snapshot_digest,
                "principal": input.snapshot.principal,
            },
        }))
        .expect("envelope serializes")
    }

    fn stage_envelope(name: &str, input: &DispatchMaterialInput) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).expect("stage dir writable");
        std::fs::write(
            dir.join(WASM_HOST_MATERIAL_FILE_NAME),
            test_envelope_json(input),
        )
        .expect("envelope writable");
        std::fs::write(
            dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
            &input.artifact_bytes,
        )
        .expect("artifact writable");
        std::fs::write(
            dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
            &input.input_bytes,
        )
        .expect("input writable");
        dir
    }

    /// Staged envelope end-to-end: the publisher-shaped JSON parses,
    /// binds, and re-hashes the colocated bytes; absence stays `None`.
    #[test]
    fn staged_envelope_parses_and_binds() {
        let input = test_input();
        let dir = stage_envelope("eliot-2377-envelope-ok", &input);
        let material = read_dispatch_material_from(&dir)
            .expect("envelope reads")
            .expect("material present");
        assert_eq!(material.claim_id, "claim-material-001");
        assert_eq!(material.profile, Profile::D2Operational);
        assert_eq!(
            material.authority_epoch_json, input.authority_epoch_json,
            "epoch JSON survives the envelope round trip verbatim"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let absent = std::env::temp_dir().join("eliot-2377-envelope-absent");
        std::fs::create_dir_all(&absent).expect("absent dir writable");
        assert_eq!(read_dispatch_material_from(&absent), Ok(None));
        let _ = std::fs::remove_dir_all(&absent);
    }

    /// Envelope refusals are typed and fail closed: malformed JSON, a
    /// foreign wire identity, an unknown field, and epoch disagreement
    /// never bind.
    #[test]
    fn staged_envelope_refusals_fail_closed() {
        let input = test_input();
        // Malformed JSON.
        assert_eq!(
            parse_envelope(b"{not json").map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Foreign wire identity.
        let mut foreign = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&foreign).expect("envelope parses");
        value["wire_id"] = serde_json::Value::String("foreign.envelope".to_owned());
        foreign = serde_json::to_vec(&value).expect("foreign serializes");
        assert_eq!(
            parse_envelope(&foreign).map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Unknown field denied by the closed envelope.
        let mut unknown = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&unknown).expect("envelope parses");
        value["second_admission"] = serde_json::Value::Bool(true);
        unknown = serde_json::to_vec(&value).expect("unknown serializes");
        assert_eq!(
            parse_envelope(&unknown).map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Epoch disagreement between envelope and grant.
        let mut drifted = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&drifted).expect("envelope parses");
        value["grant"]["authority_epoch"] = serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440001",
            "sequence": 3
        });
        drifted = serde_json::to_vec(&value).expect("drifted serializes");
        assert_eq!(
            parse_envelope(&drifted).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "epoch-agreement"
            })
        );
    }
}
