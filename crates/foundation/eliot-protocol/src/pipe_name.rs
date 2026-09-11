//! Typed, transport-neutral names in the current ELIOT named-pipe namespace.
//!
//! This module only validates and formats identity.  It does not open, list,
//! connect to, delete, or authenticate a named pipe.

use std::{fmt, str::FromStr};

use eliot_contracts::{ContractId, ResourceGeneration, canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Exact current namespace prefix, including its required trailing separator.
pub const ELIOT_PIPE_PREFIX: &str = "\\\\.\\pipe\\eliot\\";
/// Maximum encoded current suffix length accepted by the existing IPC envelope.
pub const MAX_PIPE_SUFFIX_BYTES: usize = 240;
/// Maximum encoded current pipe-name length in bytes, including the prefix.
pub const MAX_PIPE_NAME_BYTES: usize = ELIOT_PIPE_PREFIX.len() + MAX_PIPE_SUFFIX_BYTES;
/// Maximum encoded owner-segment length before the full suffix bound applies.
pub const MAX_PIPE_SEGMENT_BYTES: usize = MAX_PIPE_SUFFIX_BYTES;
/// Wire revision of the current typed namespace contract.
pub const PIPE_NAME_WIRE_REVISION: &str = "v1";
/// Stable contract name for the typed namespace owner.
pub const PIPE_NAME_CONTRACT_NAME: &str = "eliot.foundation.pipe-name";

/// A closed family in the current ELIOT namespace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EliotPipeFamily {
    /// Kernel-owned endpoints, including front door, store and daemon.
    Kernel,
    /// Module-owned generation endpoints.
    Module,
    /// Watchdog-owned signal endpoint.
    Watchdog,
}

impl EliotPipeFamily {
    /// Returns the stable family label used by diagnostics and contract data.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Module => "module",
            Self::Watchdog => "watchdog",
        }
    }
}

impl fmt::Display for EliotPipeFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated lowercase ASCII owner segment.
///
/// The inner value is private so callers cannot bypass the namespace rules.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EliotPipeSegment(String);

impl EliotPipeSegment {
    /// Validates one canonical owner segment.
    pub fn new(value: impl Into<String>) -> Result<Self, EliotPipeNameError> {
        let value = value.into();
        validate_segment(&value, 0, "segment")?;
        Ok(Self(value))
    }

    /// Returns the canonical segment text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the segment and returns its canonical text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for EliotPipeSegment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for EliotPipeSegment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EliotPipeSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl TryFrom<String> for EliotPipeSegment {
    type Error = EliotPipeNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Private endpoint shapes retained beneath the top-level owner family.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum EliotPipeEndpoint {
    /// `\\.\pipe\eliot\kernel\frontdoor`.
    KernelFrontdoor,
    /// `\\.\pipe\eliot\kernel\store`.
    KernelStore,
    /// `\\.\pipe\eliot\kernel\daemon\<generation>`.
    KernelDaemon {
        /// Kernel daemon generation identity.
        generation: ResourceGeneration,
    },
    /// `\\.\pipe\eliot\module\<module_id>\<generation>`.
    Module {
        /// Canonical module identity owned by the runtime contracts crate.
        module_id: ContractId,
        /// Module generation identity owned by the runtime contracts crate.
        generation: ResourceGeneration,
    },
    /// `\\.\pipe\eliot\watchdog\signals`.
    WatchdogSignals,
}

/// A typed current ELIOT named-pipe identity.
///
/// The endpoint representation is private; callers can create values only
/// through the checked constructors or by parsing an exact canonical name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EliotPipeName(EliotPipeEndpoint);

impl EliotPipeName {
    /// Constructs the static Kernel front door identity.
    pub const fn kernel_frontdoor() -> Self {
        Self(EliotPipeEndpoint::KernelFrontdoor)
    }

    /// Constructs the static Kernel store identity.
    pub const fn kernel_store() -> Self {
        Self(EliotPipeEndpoint::KernelStore)
    }

    /// Constructs a generation-specific Kernel daemon identity.
    pub fn kernel_daemon(generation: ResourceGeneration) -> Result<Self, EliotPipeNameError> {
        validate_generation(generation, 0)?;
        Ok(Self(EliotPipeEndpoint::KernelDaemon { generation }))
    }

    /// Constructs a generation-specific module identity.
    pub fn module(
        module_id: ContractId,
        generation: ResourceGeneration,
    ) -> Result<Self, EliotPipeNameError> {
        validate_segment(module_id.as_str(), 0, "module_id")?;
        validate_generation(generation, 0)?;
        let name = Self(EliotPipeEndpoint::Module {
            module_id,
            generation,
        });
        let actual = name.to_string().len();
        if actual > MAX_PIPE_NAME_BYTES {
            return Err(EliotPipeNameError::NameTooLong {
                actual,
                maximum: MAX_PIPE_NAME_BYTES,
            });
        }
        Ok(name)
    }

    /// Constructs the static Watchdog signal identity.
    pub const fn watchdog_signals() -> Self {
        Self(EliotPipeEndpoint::WatchdogSignals)
    }

    /// Returns this identity's closed family.
    pub const fn family(&self) -> EliotPipeFamily {
        match self {
            Self(
                EliotPipeEndpoint::KernelFrontdoor
                | EliotPipeEndpoint::KernelStore
                | EliotPipeEndpoint::KernelDaemon { .. },
            ) => EliotPipeFamily::Kernel,
            Self(EliotPipeEndpoint::Module { .. }) => EliotPipeFamily::Module,
            Self(EliotPipeEndpoint::WatchdogSignals) => EliotPipeFamily::Watchdog,
        }
    }

    /// Returns canonical UTF-8 endpoint bytes.
    ///
    /// A Windows adapter may encode the same logical name as UTF-16 for its
    /// API call; that representation is outside this transport-neutral owner.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }

    /// Returns the canonical versioned wire bytes used for identity hashing.
    pub fn canonical_wire_bytes(&self) -> Vec<u8> {
        match canonical_json_bytes(&EliotPipeNameWire {
            revision: PipeNameWireRevision::V1,
            name: self.to_string(),
        }) {
            Ok(bytes) => bytes,
            Err(error) => unreachable!("pipe-name wire serialization failed: {error}"),
        }
    }

    /// Returns the canonical SHA-256 identity of the versioned wire value.
    pub fn canonical_digest(&self) -> String {
        sha256_hex(&self.canonical_wire_bytes())
    }

    /// Returns the daemon or module generation, when the family has one.
    pub const fn generation(&self) -> Option<ResourceGeneration> {
        match self {
            Self(
                EliotPipeEndpoint::KernelDaemon { generation }
                | EliotPipeEndpoint::Module { generation, .. },
            ) => Some(*generation),
            Self(
                EliotPipeEndpoint::KernelFrontdoor
                | EliotPipeEndpoint::KernelStore
                | EliotPipeEndpoint::WatchdogSignals,
            ) => None,
        }
    }

    /// Returns the module identity, when this is a module endpoint.
    pub fn module_id(&self) -> Option<&ContractId> {
        match self {
            Self(EliotPipeEndpoint::Module { module_id, .. }) => Some(module_id),
            _ => None,
        }
    }

    /// Parses one exact current canonical name.
    pub fn parse(value: &str) -> Result<Self, EliotPipeNameError> {
        if value.len() > MAX_PIPE_NAME_BYTES {
            return Err(EliotPipeNameError::NameTooLong {
                actual: value.len(),
                maximum: MAX_PIPE_NAME_BYTES,
            });
        }
        let Some(rest) = value.strip_prefix(ELIOT_PIPE_PREFIX) else {
            return Err(EliotPipeNameError::InvalidPrefix);
        };
        if rest.is_empty() {
            return Err(EliotPipeNameError::InvalidFamily {
                offset: ELIOT_PIPE_PREFIX.len(),
            });
        }
        let parts: Vec<_> = rest.split('\\').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(EliotPipeNameError::InvalidSegment {
                offset: ELIOT_PIPE_PREFIX.len(),
                field: "segment",
                reason: EliotPipeSegmentReason::Empty,
            });
        }
        if parts.iter().any(|part| part.contains('/')) {
            return Err(EliotPipeNameError::InvalidSegment {
                offset: ELIOT_PIPE_PREFIX.len(),
                field: "segment",
                reason: EliotPipeSegmentReason::Separator,
            });
        }

        match parts.as_slice() {
            ["kernel", "frontdoor"] => Ok(Self::kernel_frontdoor()),
            ["kernel", "store"] => Ok(Self::kernel_store()),
            ["kernel", "daemon", generation] => {
                let generation = parse_generation(generation, ELIOT_PIPE_PREFIX.len() + 14)?;
                Self::kernel_daemon(generation)
            }
            ["module", module_id, generation] => {
                let module_offset = ELIOT_PIPE_PREFIX.len() + "module\\".len();
                validate_segment(module_id, module_offset, "module_id")?;
                let module_id = ContractId::new(module_id.to_owned()).map_err(|_| {
                    EliotPipeNameError::InvalidSegment {
                        offset: module_offset,
                        field: "module_id",
                        reason: EliotPipeSegmentReason::OwnerIdentity,
                    }
                })?;
                let generation =
                    parse_generation(generation, module_offset + module_id.as_str().len() + 1)?;
                Self::module(module_id, generation)
            }
            ["watchdog", "signals"] => Ok(Self::watchdog_signals()),
            _ => Err(EliotPipeNameError::InvalidFamily {
                offset: ELIOT_PIPE_PREFIX.len(),
            }),
        }
    }
}

impl fmt::Display for EliotPipeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(ELIOT_PIPE_PREFIX)?;
        match &self.0 {
            EliotPipeEndpoint::KernelFrontdoor => formatter.write_str("kernel\\frontdoor"),
            EliotPipeEndpoint::KernelStore => formatter.write_str("kernel\\store"),
            EliotPipeEndpoint::KernelDaemon { generation } => {
                write!(formatter, "kernel\\daemon\\{}", generation.value())
            }
            EliotPipeEndpoint::Module {
                module_id,
                generation,
            } => write!(formatter, "module\\{}\\{}", module_id, generation.value()),
            EliotPipeEndpoint::WatchdogSignals => formatter.write_str("watchdog\\signals"),
        }
    }
}

impl FromStr for EliotPipeName {
    type Err = EliotPipeNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for EliotPipeName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EliotPipeNameWire {
            revision: PipeNameWireRevision::V1,
            name: self.to_string(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EliotPipeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let EliotPipeNameWire {
            revision: PipeNameWireRevision::V1,
            name,
        } = EliotPipeNameWire::deserialize(deserializer)?;
        Self::parse(&name).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PipeNameWireRevision {
    V1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EliotPipeNameWire {
    revision: PipeNameWireRevision,
    name: String,
}

/// A recognized historical pipe shape that has no owner-approved current map.
///
/// It is intentionally separate from [`EliotPipeName`].  Callers must obtain
/// an explicit mapping from the actual endpoint owner before using it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LegacyEliotPipeName {
    governor_digest_prefix: String,
}

impl LegacyEliotPipeName {
    /// Parses the inventoried historical `eliot-governor-<20 hex>` shape.
    pub fn parse(value: &str) -> Result<Self, EliotPipeNameError> {
        const PREFIX: &str = "\\\\.\\pipe\\eliot-governor-";
        let Some(suffix) = value.strip_prefix(PREFIX) else {
            return Err(EliotPipeNameError::LegacyUnsupported);
        };
        if suffix.len() != 20
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EliotPipeNameError::LegacyUnsupported);
        }
        Ok(Self {
            governor_digest_prefix: suffix.to_owned(),
        })
    }

    /// Returns the historical digest prefix without exposing a raw wire name.
    pub fn digest_prefix(&self) -> &str {
        &self.governor_digest_prefix
    }

    /// Refuses conversion until the actual endpoint owner supplies a mapping.
    pub const fn map_to_current(&self) -> Result<EliotPipeName, EliotPipeNameError> {
        Err(EliotPipeNameError::LegacyMappingUnavailable)
    }
}

impl FromStr for LegacyEliotPipeName {
    type Err = EliotPipeNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EliotPipeSegmentReason {
    #[error("must not be empty")]
    Empty,
    #[error("must use lowercase ASCII canonical spelling")]
    NonCanonical,
    #[error("must not contain a separator")]
    Separator,
    #[error("must not contain a reserved delimiter")]
    Delimiter,
    #[error("must not contain whitespace")]
    Whitespace,
    #[error("must not contain a control character")]
    Control,
    #[error("must not be a dot segment")]
    DotSegment,
    #[error("must be a canonical owner identity")]
    OwnerIdentity,
}

/// Typed, redacted validation failures for current and legacy names.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EliotPipeNameError {
    /// The exact namespace prefix, including its separator, was absent.
    #[error("named-pipe name has an invalid ELIOT namespace prefix")]
    InvalidPrefix,
    /// The closed family or suffix shape was not admitted.
    #[error("named-pipe name has an unknown or malformed family at byte offset {offset}")]
    InvalidFamily { offset: usize },
    /// A segment failed its canonical validation.
    #[error("named-pipe {field} is invalid at byte offset {offset}: {reason}")]
    InvalidSegment {
        /// Byte offset of the segment in the logical name.
        offset: usize,
        /// Redacted field name.
        field: &'static str,
        /// Shape-only reason.
        reason: EliotPipeSegmentReason,
    },
    /// The generation was zero or not canonical decimal text.
    #[error("named-pipe generation is invalid at byte offset {offset}")]
    InvalidGeneration { offset: usize },
    /// The encoded name exceeds the bounded namespace maximum.
    #[error("named-pipe name exceeds {maximum} bytes (actual {actual})")]
    NameTooLong { actual: usize, maximum: usize },
    /// The recognized old endpoint cannot be used as a current endpoint.
    #[error("legacy named-pipe identity is unsupported at this boundary")]
    LegacyUnsupported,
    /// No owner-approved versioned mapping exists yet.
    #[error("legacy named-pipe identity has no owner-approved current mapping")]
    LegacyMappingUnavailable,
}

fn validate_segment(
    value: &str,
    offset: usize,
    field: &'static str,
) -> Result<(), EliotPipeNameError> {
    if value.is_empty() {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::Empty,
        });
    }
    if value.len() > MAX_PIPE_SEGMENT_BYTES {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::NonCanonical,
        });
    }
    if value == "." || value == ".." || value.ends_with('.') {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::DotSegment,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::Control,
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::Whitespace,
        });
    }
    if value.contains(['\\', '/']) {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::Separator,
        });
    }
    if value.contains(':') {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::Delimiter,
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    }) || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(EliotPipeNameError::InvalidSegment {
            offset,
            field,
            reason: EliotPipeSegmentReason::NonCanonical,
        });
    }
    Ok(())
}

fn validate_generation(
    generation: ResourceGeneration,
    offset: usize,
) -> Result<(), EliotPipeNameError> {
    if generation.value() == 0 {
        Err(EliotPipeNameError::InvalidGeneration { offset })
    } else {
        Ok(())
    }
}

fn parse_generation(value: &str, offset: usize) -> Result<ResourceGeneration, EliotPipeNameError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EliotPipeNameError::InvalidGeneration { offset });
    }
    let numeric = value
        .parse::<u64>()
        .map_err(|_| EliotPipeNameError::InvalidGeneration { offset })?;
    let generation = ResourceGeneration::new(numeric)
        .map_err(|_| EliotPipeNameError::InvalidGeneration { offset })?;
    validate_generation(generation, offset)?;
    Ok(generation)
}
