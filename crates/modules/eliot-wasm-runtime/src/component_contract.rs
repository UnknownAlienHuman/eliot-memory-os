//! Neutral typed invocation contracts for the six frozen component worlds.
//!
//! This module owns the single provider-neutral mapping derived from the
//! frozen `eliot:current@0.1.0` WIT set (see
//! `bins/eliot-wasm-host/wit/typed/`): world identity, interface and domain
//! operation names, the canonical `abi-descriptor` field shape, generator
//! identity, supported versions, and the fail-closed typed errors. It
//! contains no engine, linker, or generated binding code; the Wasmtime
//! provider that consumes this contract lives outside this crate. Field
//! names mirror `wit/typed/descriptor.wit` (`world-name`, `package-id`,
//! `abi-revision`, `native-contract`, `native-revision`, `abi-digest`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{EngineBinding, Sha256Digest, validate_text};

/// Frozen typed package identity accepted by every current-world selection.
pub const TYPED_PACKAGE_ID: &str = "eliot:current@0.1.0";
/// Frozen typed package version accepted by every current-world selection.
pub const TYPED_WIT_VERSION: &str = "0.1.0";
/// Frozen ABI revision accepted by every current-world selection.
pub const TYPED_ABI_REVISION: u32 = 1;
/// Legacy package identity that must never satisfy a typed selection.
pub const LEGACY_PACKAGE_ID: &str = "eliot:wasm@1.0.0";
/// Legacy world that must never satisfy a typed selection.
pub const LEGACY_WORLD: &str = "eliot:wasm/guest";
/// Legacy export that marks a legacy/component mismatch.
pub const LEGACY_EXPORT: &str = "run";
/// Neutral generator identity: the single Wasmtime component facility that
/// owns the generated bindings consumed through this contract.
pub const TYPED_GENERATOR: &str = "wasmtime-component-bindgen";
/// Engine implementation pinned by the consuming provider.
pub const TYPED_ENGINE_IMPLEMENTATION: &str = "wasmtime-component";
/// Engine version pinned by the consuming provider.
pub const TYPED_ENGINE_VERSION: &str = "47.0.4";
/// WIT parser version pinning the frozen contract text.
pub const TYPED_WIT_PARSER_VERSION: &str = "0.252.0";
/// Descriptor probe present on every typed interface.
pub const DESCRIBE_FUNC: &str = "describe";

const MAX_TYPED_FIELD_BYTES: usize = 512;
const MAX_TYPED_IDENTITY_BYTES: usize = 128;
/// Decode-only allocation guard. Admission bounds always come from Governor
/// limits; this cap only bounds the envelope parser itself.
const MAX_TYPED_ENVELOPE_BYTES: usize = 1_048_576;

/// The six frozen typed worlds in contract order.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypedWorld {
    ContextAdmission,
    ContextAssembly,
    CueActivation,
    DreamerHandler,
    MemoryCurationScreen,
    DreamerCycle,
}

impl TypedWorld {
    /// All six worlds in contract order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::ContextAdmission,
            Self::ContextAssembly,
            Self::CueActivation,
            Self::DreamerHandler,
            Self::MemoryCurationScreen,
            Self::DreamerCycle,
        ]
    }

    /// Canonical world name as declared in WIT.
    #[must_use]
    pub const fn world_name(self) -> &'static str {
        match self {
            Self::ContextAdmission => "context-admission",
            Self::ContextAssembly => "context-assembly",
            Self::CueActivation => "cue-activation",
            Self::DreamerHandler => "dreamer-handler",
            Self::MemoryCurationScreen => "memory-curation-screen",
            Self::DreamerCycle => "dreamer-cycle",
        }
    }

    /// Exported interface name for this world.
    #[must_use]
    pub const fn interface_name(self) -> &'static str {
        match self {
            Self::ContextAdmission => "admission",
            Self::ContextAssembly => "assembly",
            Self::CueActivation => "activation",
            Self::DreamerHandler => "handler",
            Self::MemoryCurationScreen => "screen",
            Self::DreamerCycle => "cycle",
        }
    }

    /// Domain operation name for this world's interface.
    #[must_use]
    pub const fn domain_func(self) -> &'static str {
        match self {
            Self::ContextAdmission => "admit",
            Self::ContextAssembly => "assemble",
            Self::CueActivation => "activate",
            Self::DreamerHandler => "handle",
            Self::MemoryCurationScreen => "screen",
            Self::DreamerCycle => "step",
        }
    }

    /// Documented native owner reference for this world, taken from the
    /// frozen WIT headers and the checked-in consumer map.
    #[must_use]
    pub const fn native_owner(self) -> &'static str {
        match self {
            Self::ContextAdmission => "#584/#608",
            Self::ContextAssembly => "#584/#626",
            Self::CueActivation => "#804/#600",
            Self::DreamerHandler => "A-03/#578",
            Self::MemoryCurationScreen => "#586/#588",
            Self::DreamerCycle => "#806",
        }
    }

    /// Schema revision admitted for this world's interface. All six frozen
    /// interfaces are at revision 1.
    #[must_use]
    pub const fn schema_revision(self) -> u32 {
        1
    }

    /// Parses an explicit world selection. Unknown spellings are denied and
    /// legacy identities are rejected outright, never auto-probed or
    /// promoted from legacy.
    pub fn parse(value: &str) -> Result<Self, TypedContractError> {
        match value {
            "context-admission" => Ok(Self::ContextAdmission),
            "context-assembly" => Ok(Self::ContextAssembly),
            "cue-activation" => Ok(Self::CueActivation),
            "dreamer-handler" => Ok(Self::DreamerHandler),
            "memory-curation-screen" => Ok(Self::MemoryCurationScreen),
            "dreamer-cycle" => Ok(Self::DreamerCycle),
            LEGACY_WORLD | LEGACY_EXPORT | "guest" => {
                Err(TypedContractError::LegacyRejected(bounded_identity(value)))
            }
            _ => Err(TypedContractError::UnknownWorld(bounded_identity(value))),
        }
    }
}

impl std::fmt::Display for TypedWorld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.world_name())
    }
}

fn bounded_identity(value: &str) -> String {
    value.chars().take(MAX_TYPED_IDENTITY_BYTES).collect()
}

/// Returns true when a component export name identifies the expected
/// interface, accepting both bare (`admission`) and fully qualified
/// (`eliot:current@0.1.0/admission`) spellings. Anything else is a
/// missing or wrong export, never an implicit match.
#[must_use]
pub fn export_matches_interface(export_name: &str, interface: &str) -> bool {
    if export_name == interface {
        return true;
    }
    if let Some((_, tail)) = export_name.rsplit_once('/') {
        if tail == interface {
            return true;
        }
    }
    if let Some((_, tail)) = export_name.rsplit_once(':') {
        if tail == interface {
            return true;
        }
    }
    false
}

/// Closed version triple for one world ABI revision, mirroring the WIT
/// `version` record.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl TypedVersion {
    /// The single supported version triple backing [`TYPED_WIT_VERSION`].
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: 0,
            minor: 1,
            patch: 0,
        }
    }

    /// Parses an exact `major.minor.patch` triple.
    pub fn parse(value: &str) -> Result<Self, TypedContractError> {
        let mut parts = value.split('.');
        let parsed = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next(),
        );
        let version = match parsed {
            (major, minor, patch, None) => Self {
                major: major
                    .parse::<u32>()
                    .map_err(|_| TypedContractError::VersionMismatch {
                        want: TYPED_WIT_VERSION.to_owned(),
                        got: bounded_identity(value),
                    })?,
                minor: minor
                    .parse::<u32>()
                    .map_err(|_| TypedContractError::VersionMismatch {
                        want: TYPED_WIT_VERSION.to_owned(),
                        got: bounded_identity(value),
                    })?,
                patch: patch
                    .parse::<u32>()
                    .map_err(|_| TypedContractError::VersionMismatch {
                        want: TYPED_WIT_VERSION.to_owned(),
                        got: bounded_identity(value),
                    })?,
            },
            _ => {
                return Err(TypedContractError::VersionMismatch {
                    want: TYPED_WIT_VERSION.to_owned(),
                    got: bounded_identity(value),
                });
            }
        };
        if version == Self::current() {
            Ok(version)
        } else {
            Err(TypedContractError::VersionMismatch {
                want: TYPED_WIT_VERSION.to_owned(),
                got: bounded_identity(value),
            })
        }
    }
}

/// Exact world/native/ABI identity mirroring the WIT `abi-descriptor`
/// record. The digest value itself is excluded from every digest computed
/// over descriptors by construction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbiDescriptor {
    pub world_name: String,
    pub package_id: String,
    pub abi_revision: u32,
    pub native_contract: String,
    pub native_revision: String,
    pub abi_digest: Sha256Digest,
}

impl AbiDescriptor {
    /// Creates a validated descriptor for one explicit world.
    pub fn new(
        world: TypedWorld,
        native_contract: String,
        native_revision: String,
        abi_digest: Sha256Digest,
    ) -> Result<Self, TypedContractError> {
        let descriptor = Self {
            world_name: world.world_name().to_owned(),
            package_id: TYPED_PACKAGE_ID.to_owned(),
            abi_revision: TYPED_ABI_REVISION,
            native_contract,
            native_revision,
            abi_digest,
        };
        descriptor.validate_for(world)?;
        Ok(descriptor)
    }

    /// Validates package, world, revision, and bounded native identity for
    /// one explicit world. Unknown or incompatible selections fail closed.
    pub fn validate_for(&self, world: TypedWorld) -> Result<(), TypedContractError> {
        if self.package_id != TYPED_PACKAGE_ID {
            return Err(TypedContractError::PackageMismatch {
                want: TYPED_PACKAGE_ID.to_owned(),
                got: bounded_identity(&self.package_id),
            });
        }
        if self.world_name != world.world_name() {
            return Err(TypedContractError::WorldMismatch {
                want: world.world_name().to_owned(),
                got: bounded_identity(&self.world_name),
            });
        }
        if self.abi_revision != TYPED_ABI_REVISION {
            return Err(TypedContractError::AbiMismatch {
                want: TYPED_ABI_REVISION,
                got: self.abi_revision,
            });
        }
        bounded_field(&self.native_contract, "native-contract")?;
        bounded_field(&self.native_revision, "native-revision")?;
        Ok(())
    }
}

fn bounded_field(value: &str, field: &'static str) -> Result<(), TypedContractError> {
    if value.is_empty()
        || value.len() > MAX_TYPED_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(TypedContractError::DescriptorField(field.to_owned()));
    }
    Ok(())
}

/// Closed completeness states preserved across worlds, mirroring the WIT
/// `completeness` enum.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypedCompleteness {
    Complete,
    Partial,
    Incomplete,
    Unknown,
}

/// Maximum proof a result supports; candidate-only never implies admission.
/// Mirrors the WIT `proof-ceiling` enum.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofCeiling {
    Observation,
    CandidateOnly,
    Admission,
    Assembly,
    Activation,
    Screen,
    Cycle,
    Handler,
}

/// Fail-closed typed contract errors. Causes carry stable identities and
/// bounded field names only, never payloads, paths, or secrets.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code", content = "detail")]
pub enum TypedContractError {
    #[error("unknown typed world: {0}")]
    UnknownWorld(String),
    #[error("legacy identity cannot satisfy a typed operation: {0}")]
    LegacyRejected(String),
    #[error("typed package mismatch: want {want}, got {got}")]
    PackageMismatch {
        want: String,
        got: String,
    },
    #[error("typed world mismatch: want {want}, got {got}")]
    WorldMismatch {
        want: String,
        got: String,
    },
    #[error("typed version mismatch: want {want}, got {got}")]
    VersionMismatch {
        want: String,
        got: String,
    },
    #[error("typed ABI revision mismatch: want {want}, got {got}")]
    AbiMismatch {
        want: u32,
        got: u32,
    },
    #[error("malformed descriptor field: {0}")]
    DescriptorField(String),
    #[error("actual imports disagree with the declared typed contract")]
    ImportMismatch,
    #[error("actual exports disagree with the declared typed contract")]
    ExportMismatch,
    #[error("engine binding disagrees with the typed provider contract")]
    EngineMismatch,
    #[error("artifact disagrees with the typed kit")]
    ArtifactMismatch,
    #[error("interface digest disagrees with the typed kit")]
    InterfaceMismatch,
    #[error("typed policy or resource ceiling denied")]
    LimitDenied,
    #[error("engine report disagrees with its typed invocation envelope")]
    ReportMismatch,
    #[error("typed engine denied the invocation")]
    EngineDenied,
    #[error("typed engine unavailable")]
    EngineUnavailable,
    #[error("typed engine outcome unknown")]
    EngineUnknown,
    #[error("typed envelope exceeds the decode bound")]
    EnvelopeTooLarge,
    #[error("typed kit is invalid: {0}")]
    InvalidKit(String),
    #[error("typed capsule is invalid: {0}")]
    InvalidCapsule(String),
    #[error("canonical typed serialization failed: {0}")]
    Serialization(String),
}

/// Typed invocation for one explicit world. The input carries canonical
/// bounded leaf bytes only; there is no whole-payload value, JSON, string,
/// or byte escape. A legacy opaque selection cannot construct this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedInvocation {
    world: TypedWorld,
    input: Vec<u8>,
}

impl TypedInvocation {
    /// Creates a typed invocation for one explicit world.
    pub fn new(world: TypedWorld, input: Vec<u8>) -> Result<Self, TypedContractError> {
        if input.len() > MAX_TYPED_ENVELOPE_BYTES {
            return Err(TypedContractError::EnvelopeTooLarge);
        }
        Ok(Self { world, input })
    }

    /// Parses an explicit world selection; legacy and unknown spellings
    /// fail closed without probing.
    pub fn from_opaque(world_name: &str, input: Vec<u8>) -> Result<Self, TypedContractError> {
        Self::new(TypedWorld::parse(world_name)?, input)
    }

    /// Returns the selected world.
    #[must_use]
    pub const fn world(&self) -> TypedWorld {
        self.world
    }

    /// Returns the canonical bounded leaf bytes.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Returns the digest of the canonical leaf bytes.
    #[must_use]
    pub fn input_digest(&self) -> Sha256Digest {
        Sha256Digest::of_bytes(&self.input)
    }

    /// Encodes the canonical round-trip form: world name, one NUL
    /// separator, then the leaf bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.world.world_name().as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&self.input);
        bytes
    }

    /// Decodes a canonical envelope produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, TypedContractError> {
        if bytes.len() > MAX_TYPED_ENVELOPE_BYTES {
            return Err(TypedContractError::EnvelopeTooLarge);
        }
        let separator = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(TypedContractError::EnvelopeTooLarge)?;
        let name = std::str::from_utf8(&bytes[..separator])
            .map_err(|_| TypedContractError::UnknownWorld(String::new()))?;
        let world = TypedWorld::parse(name)?;
        Self::new(world, bytes[separator + 1..].to_vec())
    }
}

/// Validates one provider observation against the Governor-admitted
/// expectation: exact package/world/revision/native identity, the pinned
/// engine binding, and exact declared versus actual import/export identity.
/// Typed worlds declare zero ambient imports; any actual import is a
/// mismatch. A legacy export in the observed set is rejected outright.
#[allow(clippy::too_many_arguments)]
pub fn validate_observed(
    expected: &AbiDescriptor,
    observed: &AbiDescriptor,
    binding: &EngineBinding,
    actual_imports: &[String],
    declared_imports: &[String],
    actual_exports: &[String],
    declared_exports: &[String],
) -> Result<(), TypedContractError> {
    if observed.package_id != expected.package_id
        || observed.package_id != TYPED_PACKAGE_ID
        || observed.world_name != expected.world_name
        || observed.abi_revision != expected.abi_revision
        || observed.abi_revision != TYPED_ABI_REVISION
        || observed.native_contract != expected.native_contract
        || observed.native_revision != expected.native_revision
        || observed.abi_digest != expected.abi_digest
    {
        return Err(TypedContractError::ReportMismatch);
    }
    validate_text(&binding.implementation_id, "engine.implementation_id")
        .map_err(|_| TypedContractError::EngineMismatch)?;
    validate_text(&binding.exact_version, "engine.exact_version")
        .map_err(|_| TypedContractError::EngineMismatch)?;
    if binding.implementation_id != TYPED_ENGINE_IMPLEMENTATION
        || binding.exact_version != TYPED_ENGINE_VERSION
    {
        return Err(TypedContractError::EngineMismatch);
    }
    if sorted_names(actual_imports) != sorted_names(declared_imports) {
        return Err(TypedContractError::ImportMismatch);
    }
    for export in actual_exports {
        if *export == LEGACY_EXPORT {
            return Err(TypedContractError::LegacyRejected(bounded_identity(export)));
        }
    }
    if sorted_names(actual_exports) != sorted_names(declared_exports) {
        return Err(TypedContractError::ExportMismatch);
    }
    Ok(())
}

fn sorted_names(values: &[String]) -> Vec<&str> {
    let mut names: Vec<&str> = values.iter().map(String::as_str).collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod typed_contract_tests {
    use super::*;

    fn build_descriptor(world: TypedWorld) -> Result<AbiDescriptor, TypedContractError> {
        AbiDescriptor::new(
            world,
            "native-contract".to_owned(),
            "native-revision".to_owned(),
            Sha256Digest::of_bytes(b"abi"),
        )
    }

    #[test]
    fn six_world_round_trip_with_fail_closed_selection() {
        for world in TypedWorld::all() {
            let invocation = TypedInvocation::new(world, vec![1, 2, 3]);
            assert!(invocation.is_ok());
            if let Ok(invocation) = invocation {
                assert_eq!(invocation.world(), world);
                let decoded = TypedInvocation::decode(&invocation.encode());
                assert_eq!(decoded, Ok(invocation));
            }
            let built = build_descriptor(world);
            assert!(built.is_ok());
            if let Ok(owned) = built {
                assert!(owned.validate_for(world).is_ok());
            }
            assert_eq!(world.schema_revision(), 1);
            assert!(export_matches_interface(
                world.interface_name(),
                world.interface_name()
            ));
        }
        assert!(matches!(
            TypedWorld::parse(LEGACY_WORLD),
            Err(TypedContractError::LegacyRejected(_))
        ));
        assert!(matches!(
            TypedInvocation::from_opaque(LEGACY_WORLD, Vec::new()),
            Err(TypedContractError::LegacyRejected(_))
        ));
        assert!(matches!(
            TypedWorld::parse("not-a-world"),
            Err(TypedContractError::UnknownWorld(_))
        ));
        assert_eq!(TypedVersion::parse(TYPED_WIT_VERSION), Ok(TypedVersion::current()));
        assert!(TypedVersion::parse("9.9.9").is_err());
    }
}
