//! Generated per-operation store manifest catalogue (slice C1, issue #19).
//!
//! This module owns the single Rust declaration table that generates one
//! [`NamedOperationManifest`](crate::NamedOperationManifest) descriptor per
//! activated operation. The table activates exactly the four reads with
//! proven adapter handlers, parameter shapes, and consumers on base
//! (`GetRevisionHeads`, `GetOrderingHeads`, `GetScopeRevisionView`,
//! `ResolveWriteReceipt`), plus the provider-independent genesis bootstrap
//! entry sourced by [`genesis_manifest`](crate::genesis_manifest). Every
//! other operation stays known-but-unsupported and unadvertised: no mutation
//! on base has a proven handler, schema, and consumer triple, so C1 advertises
//! no mutation entries and any transition carrying named operations fails
//! closed against the generated set.
//!
//! Authority split (one authority, two mechanisms over the same table):
//!
//! * [`generated_operation_manifests`] is the single generator. The genesis
//!   path goes through it, so there are no competing manifest sources.
//! * [`operation_manifest_set_digest`] binds the ordered entry
//!   identities/digests together with the contract, schema, and profile
//!   bindings. Same inputs always produce the same bytes: the digest covers
//!   only declared entry content, never timestamps or mutable evidence.
//! * [`validate_read_against_catalogue`] is the pre-dispatch authority for
//!   named reads: shape, membership, schema digest, scope declaration, and
//!   declared input bounds.
//! * [`validate_transition_against_catalogue`] is the pre-dispatch authority
//!   for prepared transitions. An empty-command plan is the genesis/bootstrap
//!   shape and binds to the genesis entry; a plan carrying named operations
//!   binds to the whole set digest and resolves every command against a
//!   mutation entry. Plan commands are never reordered.
//!
//! Arbitrary user payload keeps [`ExactJsonBytes`](crate::ExactJsonBytes) as
//! its authority; closed validation here is control/parameter contract only.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::operation_parameters::{
    named_mutation_operation_name, named_read_operation_name, project_parameter_schema,
    validate_typed_read_parameters,
};
use crate::{
    CONTRACT_NAME, CONTRACT_VERSION, ContractVersion, EffectClass, GENESIS_MANIFEST_NAME,
    NamedOperationManifest, NamedReadOperation, NamedReadRequest, OperationManifestDigest,
    OperationManifestSpec, PAYLOAD_AUTHORITY_VERSION, PreparedTransition, StoreError,
    TransitionClass, canonical_json_bytes, sha256_hex,
};

/// Operation identity kind carried by each manifest entry.
///
/// Reads persist no effect and carry no transition class; mutations persist
/// an effect through exactly one transition family. The genesis bootstrap
/// entry is mutation-kind: it seeds state through `RecoverySchema` with a
/// `ReversibleMutation` ceiling.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// A named read. Entries are effect `Read` with no transition classes.
    Read,
    /// A named mutation or the mutation-shaped genesis bootstrap.
    Mutation,
}

/// Catalogue profile bound into the set digest.
///
/// Bumping this identifier is a contract change: every set digest bound to
/// the old profile fails closed afterwards.
pub const OPERATION_CATALOGUE_PROFILE: &str = "eliot.storage.operation-profile.v1";

/// Owning section for activated read entries: command families and
/// activation (only spine-required variants activate with owner, catalogue
/// entry, consumer, and proof).
pub const ACTIVATED_READ_OWNING_SECTION: &str = "I5.17";

/// Owning section for the genesis bootstrap entry: the canonical contract
/// catalogue that owns catalogue identity and bootstrap meaning.
pub const GENESIS_OWNING_SECTION: &str = "I5.15";

/// Owning section stamped on legacy single manifests built through
/// [`NamedOperationManifest::new`](crate::NamedOperationManifest::new), which
/// predate per-operation ownership and are owned by the catalogue mechanism.
pub const SINGLE_MANIFEST_OWNING_SECTION: &str = "I5.15";

/// Scope kind for operations that address no scope.
pub const SCOPE_KIND_NONE: &str = "none";

/// Scope kind for operations that address one store scope.
pub const SCOPE_KIND_SCOPE: &str = "scope";

/// Maximum canonical parameter bytes accepted for an activated typed read.
///
/// Typed read parameters are small closed maps (at most one short string on
/// base); 64 KiB leaves ample headroom while staying far below the
/// 1 MiB [`MAX_EXACT_JSON_BYTES`](crate::MAX_EXACT_JSON_BYTES) authority cap.
pub const READ_MAX_INPUT_BYTES: u32 = 65_536;

/// Maximum output bytes advertised for an activated typed read.
///
/// Matches [`MAX_RECOVERY_PACKET_BYTES`](crate::MAX_RECOVERY_PACKET_BYTES)
/// (3 MiB), the existing bound for bounded canonical snapshots that already
/// caps revision/order head collections.
pub const READ_MAX_OUTPUT_BYTES: u32 = 3_145_728;

/// Timeout advertised for an activated typed read.
///
/// Matches the admitted adapter manifest timeout (30 s), the only proven
/// read timeout on base.
pub const READ_TIMEOUT_MS: u32 = 30_000;

/// Compatibility floor for generated entries: the current contract is the
/// first version carrying per-operation manifests.
pub const MINIMUM_COMPATIBLE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// One activated read row of the declaration table.
struct ActivatedReadDescriptor {
    operation: NamedReadOperation,
    requires_scope_id: bool,
    scope_kind: &'static str,
}

/// The single declaration table for activated reads.
///
/// `GetScopeRevisionView` addresses its scope through the typed `scope_id`
/// request field (proven by both adapter handlers); the head and receipt
/// reads address no scope, and the receipt read addresses its receipt through
/// the declared `operation_id` parameter.
const ACTIVATED_READS: [ActivatedReadDescriptor; 4] = [
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetRevisionHeads,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetOrderingHeads,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::GetScopeRevisionView,
        requires_scope_id: true,
        scope_kind: SCOPE_KIND_SCOPE,
    },
    ActivatedReadDescriptor {
        operation: NamedReadOperation::ResolveWriteReceipt,
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE,
    },
];

/// Returns the activated read operations in canonical declaration order.
#[must_use]
pub const fn activated_read_operations() -> [NamedReadOperation; 4] {
    [
        ACTIVATED_READS[0].operation,
        ACTIVATED_READS[1].operation,
        ACTIVATED_READS[2].operation,
        ACTIVATED_READS[3].operation,
    ]
}

fn read_entry_spec(descriptor: &ActivatedReadDescriptor) -> OperationManifestSpec {
    OperationManifestSpec {
        name: named_read_operation_name(descriptor.operation).to_owned(),
        version: CONTRACT_VERSION,
        operation_kind: OperationKind::Read,
        owning_section: ACTIVATED_READ_OWNING_SECTION.to_owned(),
        schema_revision: CONTRACT_VERSION,
        parameter_schema: project_parameter_schema(descriptor.operation),
        requires_scope_id: descriptor.requires_scope_id,
        scope_kind: descriptor.scope_kind.to_owned(),
        minimum_compatible_version: MINIMUM_COMPATIBLE_VERSION,
        transition_classes: Vec::new(),
        maximum_effect: EffectClass::Read,
        max_input_bytes: READ_MAX_INPUT_BYTES,
        max_output_bytes: READ_MAX_OUTPUT_BYTES,
        timeout_ms: READ_TIMEOUT_MS,
    }
}

fn genesis_entry_spec() -> OperationManifestSpec {
    // Bounds preserve the exact genesis limits admitted before C1; only the
    // new catalogue bindings are added around them.
    OperationManifestSpec {
        name: GENESIS_MANIFEST_NAME.to_owned(),
        version: CONTRACT_VERSION,
        operation_kind: OperationKind::Mutation,
        owning_section: GENESIS_OWNING_SECTION.to_owned(),
        schema_revision: CONTRACT_VERSION,
        parameter_schema: Vec::new(),
        requires_scope_id: false,
        scope_kind: SCOPE_KIND_NONE.to_owned(),
        minimum_compatible_version: MINIMUM_COMPATIBLE_VERSION,
        transition_classes: vec![TransitionClass::RecoverySchema],
        maximum_effect: EffectClass::ReversibleMutation,
        max_input_bytes: 3_145_728,
        max_output_bytes: 3_145_728,
        timeout_ms: 1_000,
    }
}

/// Generates the per-operation manifest descriptors from the declaration table.
///
/// Declaration order is the canonical order: the four activated reads followed
/// by the genesis bootstrap entry. Generation is pure over crate constants,
/// so the same source always yields byte-identical entries.
pub fn generated_operation_manifests() -> Result<Vec<NamedOperationManifest>, StoreError> {
    let mut entries = Vec::with_capacity(ACTIVATED_READS.len() + 1);
    for descriptor in &ACTIVATED_READS {
        entries.push(NamedOperationManifest::from_spec(read_entry_spec(descriptor))?);
    }
    entries.push(NamedOperationManifest::from_spec(genesis_entry_spec())?);
    let mut names = BTreeSet::new();
    for entry in &entries {
        if !names.insert(entry.name.clone()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    Ok(entries)
}

#[derive(Serialize)]
struct ManifestSetEntryShape<'a> {
    name: &'a str,
    version: ContractVersion,
    operation_kind: OperationKind,
    schema_revision: ContractVersion,
    schema_digest: &'a str,
    digest: &'a str,
}

#[derive(Serialize)]
struct ManifestSetDigestShape<'a> {
    contract_name: &'a str,
    contract_version: ContractVersion,
    payload_authority_version: u16,
    catalogue_profile: &'a str,
    entries: Vec<ManifestSetEntryShape<'a>>,
}

/// Computes the catalogue set digest over ordered entry identities/digests.
///
/// Every entry is validated first. Entries hash without their own digest;
/// the set digest binds, per entry in ascending name order, the name,
/// version, kind, schema revision, schema digest, and entry digest, together
/// with the contract name/version, payload-authority version, and catalogue
/// profile bindings. No timestamps or mutable evidence enter the digest.
pub fn operation_manifest_set_digest(
    entries: &[NamedOperationManifest],
) -> Result<OperationManifestDigest, StoreError> {
    if entries.is_empty() {
        return Err(StoreError::Empty {
            field: "operation_manifest_set",
        });
    }
    for entry in entries {
        entry.validate()?;
    }
    let mut ordered: Vec<&NamedOperationManifest> = entries.iter().collect();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    for entry in &ordered {
        if !names.insert(entry.name.as_str()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    let shape = ManifestSetDigestShape {
        contract_name: CONTRACT_NAME,
        contract_version: CONTRACT_VERSION,
        payload_authority_version: PAYLOAD_AUTHORITY_VERSION,
        catalogue_profile: OPERATION_CATALOGUE_PROFILE,
        entries: ordered
            .iter()
            .map(|entry| ManifestSetEntryShape {
                name: entry.name.as_str(),
                version: entry.version,
                operation_kind: entry.operation_kind,
                schema_revision: entry.schema_revision,
                schema_digest: entry.schema_digest.as_str(),
                digest: entry.digest.as_str(),
            })
            .collect(),
    };
    let bytes = canonical_json_bytes(&shape)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    OperationManifestDigest::new(sha256_hex(&bytes))
}

fn find_entry<'a>(
    entries: &'a [NamedOperationManifest],
    name: &str,
) -> Result<&'a NamedOperationManifest, StoreError> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .ok_or(StoreError::UnknownOperation)
}

/// Validates one named read against a generated catalogue set, pre-dispatch.
///
/// Enforces the generic request shape, catalogue membership (unadvertised
/// operations fail with [`StoreError::UnknownOperation`]), the entry
/// self-digest, the owner-approved typed parameters (unknown, extra, and
/// control-substitution parameters fail here), the scope declaration, and
/// the declared input bound. Issues no authority.
pub fn validate_read_against_catalogue(
    request: &NamedReadRequest,
    entries: &[NamedOperationManifest],
) -> Result<(), StoreError> {
    request.validate()?;
    let entry = find_entry(entries, named_read_operation_name(request.operation))?;
    entry.validate()?;
    if entry.operation_kind != OperationKind::Read {
        return Err(StoreError::ManifestMismatch);
    }
    validate_typed_read_parameters(request.operation, &request.parameters)?;
    match (entry.requires_scope_id, request.scope_id.as_ref()) {
        (true, None) => {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "scope revision read requires scope_id",
            });
        }
        (false, Some(_)) => {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "operation does not address a scope",
            });
        }
        (true, Some(_)) | (false, None) => {}
    }
    let parameter_bytes = canonical_json_bytes(&request.parameters)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if u64::try_from(parameter_bytes.len())
        .map_or(true, |len| len > u64::from(entry.max_input_bytes))
    {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Validates one prepared transition against a generated catalogue set.
///
/// Every entry is validated, then: an empty-command plan is the
/// genesis/bootstrap shape and must carry exactly the genesis entry digest
/// within its ceiling; a plan carrying named operations must carry exactly
/// the catalogue set digest, resolve every command (in order, never sorted)
/// to a mutation entry, and stay within that entry's ceiling. C1 advertises
/// no mutation entries, so any named command fails closed here until a later
/// slice proves a handler, schema, and consumer triple.
pub fn validate_transition_against_catalogue(
    transition: &PreparedTransition,
    entries: &[NamedOperationManifest],
) -> Result<(), StoreError> {
    transition.validate()?;
    for entry in entries {
        entry.validate()?;
    }
    let mut names = BTreeSet::new();
    for entry in entries {
        if !names.insert(entry.name.as_str()) {
            return Err(StoreError::Duplicate {
                field: "operation_manifest_set",
            });
        }
    }
    if transition.named_operations.is_empty() {
        let entry = find_entry(entries, GENESIS_MANIFEST_NAME)?;
        if transition.operation_manifest_digest != entry.digest {
            return Err(StoreError::ManifestMismatch);
        }
        if !entry.admits(
            transition.transition_class,
            transition.requested_effect_ceiling,
        ) {
            return Err(StoreError::TransitionClassExceeded);
        }
        return Ok(());
    }
    let set_digest = operation_manifest_set_digest(entries)?;
    if transition.operation_manifest_digest != set_digest {
        return Err(StoreError::ManifestMismatch);
    }
    for command in &transition.named_operations {
        let entry = find_entry(entries, named_mutation_operation_name(command.operation))?;
        if entry.operation_kind != OperationKind::Mutation {
            return Err(StoreError::ManifestMismatch);
        }
        if !entry.admits(
            transition.transition_class,
            transition.requested_effect_ceiling,
        ) {
            return Err(StoreError::TransitionClassExceeded);
        }
    }
    Ok(())
}
