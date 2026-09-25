//! Typed, transport-neutral names in the current ELIOT named-pipe namespace.
//!
//! This module only validates and formats identity.  It does not open, list,
//! connect to, delete, or authenticate a named pipe.
//!
//! [`EliotPipeOwner`] is the single typed owner enforcing the complete
//! current and legacy namespace; every constructor and parser funnels
//! through it.

use std::{fmt, str::FromStr};

use eliot_contracts::{
    ContractError, ContractId, ContractIdentity, ContractVersion, ResourceGeneration,
    canonical_json_bytes, contract_identity, sha256_hex,
};
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
/// Semantic contract version for the typed pipe-name owner.
pub const PIPE_NAME_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Versioned Unicode profile pinning the admitted owner-segment alphabet.
///
/// Only lowercase ASCII (`[a-z0-9-_.]`) is admitted under this profile.
/// Non-ASCII input (including confusables such as Cyrillic `е`) is refused
/// as [`EliotPipeSegmentReason::NonCanonical`] under this exact profile
/// version; future Unicode admission requires a profile version bump, never
/// silent aliasing or lowercasing of arbitrary Unicode.
pub const PIPE_NAME_UNICODE_PROFILE: &str = "ascii-lowercase-v1";

/// The single typed owner enforcing the complete ELIOT named-pipe namespace.
///
/// Every current parse, segment check, legacy parse, and legacy-mapping
/// decision funnels through this type: [`EliotPipeName::parse`],
/// [`EliotPipeSegment::new`], [`LegacyEliotPipeName::parse`], and
/// [`LegacyEliotPipeName::map_to_current`] all delegate here, and the
/// generation-carrying constructors validate through the same checks. No
/// second enforcement table or unchecked construction path exists. Validity
/// is identity only: it never authenticates a peer, admits an ACL, binds a
/// session, or grants permission to connect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EliotPipeOwner;

impl EliotPipeOwner {
    /// Parses one exact current canonical name.
    ///
    /// This is the single enforcement entry for the complete current
    /// namespace: exact prefix, closed canonical family, family-specific
    /// typed suffix shape, segment count/order, and owner identity.
    pub fn parse_current(value: &str) -> Result<EliotPipeName, EliotPipeNameError> {
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
            ["kernel", "frontdoor"] => Ok(EliotPipeName::kernel_frontdoor()),
            ["kernel", "store"] => Ok(EliotPipeName::kernel_store()),
            ["kernel", "daemon", generation] => {
                let generation = Self::parse_generation(generation, ELIOT_PIPE_PREFIX.len() + 14)?;
                EliotPipeName::kernel_daemon(generation)
            }
            ["module", module_id, generation] => {
                let module_offset = ELIOT_PIPE_PREFIX.len() + "module\\".len();
                Self::validate_segment(module_id, module_offset, "module_id")?;
                let module_id = ContractId::new(module_id.to_owned()).map_err(|_| {
                    EliotPipeNameError::InvalidSegment {
                        offset: module_offset,
                        field: "module_id",
                        reason: EliotPipeSegmentReason::OwnerIdentity,
                    }
                })?;
                let generation = Self::parse_generation(
                    generation,
                    module_offset + module_id.as_str().len() + 1,
                )?;
                EliotPipeName::module(module_id, generation)
            }
            ["watchdog", "signals"] => Ok(EliotPipeName::watchdog_signals()),
            _ => Err(EliotPipeNameError::InvalidFamily {
                offset: ELIOT_PIPE_PREFIX.len(),
            }),
        }
    }

    /// Validates one canonical owner segment.
    pub fn parse_segment(value: &str) -> Result<EliotPipeSegment, EliotPipeNameError> {
        Self::validate_segment(value, 0, "segment")?;
        Ok(EliotPipeSegment(value.to_owned()))
    }

    /// Parses the inventoried historical `eliot-governor-<20 hex>` shape.
    ///
    /// This is the single enforcement entry for legacy identities; unknown
    /// or ambiguous legacy stays refused.
    pub fn parse_legacy(value: &str) -> Result<LegacyEliotPipeName, EliotPipeNameError> {
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
        Ok(LegacyEliotPipeName {
            governor_digest_prefix: suffix.to_owned(),
        })
    }

    /// Refuses conversion until the actual endpoint owner supplies a mapping.
    ///
    /// The single legacy-mapping decision point: only an explicitly
    /// inventoried old identity with an owner-approved versioned mapping may
    /// convert, and no such mapping exists yet.
    pub const fn map_legacy_to_current(
        _legacy: &LegacyEliotPipeName,
    ) -> Result<EliotPipeName, EliotPipeNameError> {
        Err(EliotPipeNameError::LegacyMappingUnavailable)
    }

    /// Validates daemon fields into an owner-approved bundle.
    ///
    /// This is the only constructor of [`ValidatedDaemonFields`]: fallible
    /// edge validation (including the nonzero-generation check) whose output
    /// feeds the infallible [`EliotPipeName::kernel_daemon_from_validated`]
    /// core constructor.
    pub(crate) fn validate_daemon_fields(
        generation: ResourceGeneration,
    ) -> Result<ValidatedDaemonFields, EliotPipeNameError> {
        Self::validate_generation(generation, 0)?;
        Ok(ValidatedDaemonFields { generation })
    }

    /// Validates module fields into an owner-approved bundle.
    ///
    /// This is the only constructor of [`ValidatedModuleFields`]: it carries
    /// the existing checks — owner-segment rules, nonzero generation, and
    /// the joint full-name bound — so the infallible
    /// [`EliotPipeName::module_from_validated`] core constructor cannot fail.
    pub(crate) fn validate_module_fields(
        module_id: ContractId,
        generation: ResourceGeneration,
    ) -> Result<ValidatedModuleFields, EliotPipeNameError> {
        // Validate through the owner segment type so segment and module
        // rules (reserved-device refusal, segment bound) cannot drift; remap
        // the redacted field to the public constructor argument.
        let module_segment =
            EliotPipeSegment::new(module_id.as_str()).map_err(|error| match error {
                EliotPipeNameError::InvalidSegment { reason, .. } => {
                    EliotPipeNameError::InvalidSegment {
                        offset: 0,
                        field: "module_id",
                        reason,
                    }
                }
                other => other,
            })?;
        Self::validate_generation(generation, 0)?;
        let fields = ValidatedModuleFields {
            module_id,
            module_segment,
            generation,
        };
        // Joint full-name bound: render the exact canonical bytes the
        // endpoint Display would emit and measure them, as before.
        let actual = format!(
            "{ELIOT_PIPE_PREFIX}module\\{}\\{}",
            fields.module_id,
            fields.generation.value()
        )
        .len();
        if actual > MAX_PIPE_NAME_BYTES {
            return Err(EliotPipeNameError::NameTooLong {
                actual,
                maximum: MAX_PIPE_NAME_BYTES,
            });
        }
        Ok(fields)
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
                reason: EliotPipeSegmentReason::TooLong,
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
        // Windows device-name policy scoped to this namespace: refuse CON/PRN/
        // AUX/NUL/COM1-9/LPT1-9 (case-insensitive, stem before `.`) before the
        // ASCII-case check so `CON` reports ReservedDevice, not NonCanonical.
        if Self::is_reserved_device_name(value) {
            return Err(EliotPipeNameError::InvalidSegment {
                offset,
                field,
                reason: EliotPipeSegmentReason::ReservedDevice,
            });
        }
        // Admitted alphabet pinned by PIPE_NAME_UNICODE_PROFILE: lowercase ASCII
        // only. Non-ASCII (including confusables) falls here as NonCanonical.
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

    fn is_reserved_device_name(value: &str) -> bool {
        let stem = value.split('.').next().unwrap_or(value);
        matches!(
            stem.to_ascii_lowercase().as_str(),
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        )
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

    fn parse_generation(
        value: &str,
        offset: usize,
    ) -> Result<ResourceGeneration, EliotPipeNameError> {
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
        Self::validate_generation(generation, offset)?;
        Ok(generation)
    }
}

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
    ///
    /// Delegates to the single namespace owner ([`EliotPipeOwner::parse_segment`]).
    pub fn new(value: impl Into<String>) -> Result<Self, EliotPipeNameError> {
        let value = value.into();
        EliotPipeOwner::parse_segment(&value)
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

/// Owner-validated daemon fields accepted by the infallible core constructor.
///
/// Constructible only via [`EliotPipeOwner::validate_daemon_fields`]: the
/// fields are private and that validator is the sole construction site, so
/// [`EliotPipeName::kernel_daemon_from_validated`] cannot observe an
/// unchecked generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedDaemonFields {
    generation: ResourceGeneration,
}

/// Owner-validated module fields accepted by the infallible core constructor.
///
/// Constructible only via [`EliotPipeOwner::validate_module_fields`]: the
/// fields are private and that validator is the sole construction site, so
/// [`EliotPipeName::module_from_validated`] cannot observe an unchecked
/// module identity, generation, or over-long joint name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedModuleFields {
    module_id: ContractId,
    module_segment: EliotPipeSegment,
    generation: ResourceGeneration,
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
        /// Validated owner-segment view of the same module identity.
        ///
        /// Stored alongside `module_id` so the orphan segment type cannot
        /// drift from the module path; both spell the same canonical text.
        module_segment: EliotPipeSegment,
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
    ///
    /// Validated edge: owner validation first, then infallible core
    /// construction. Rejection behavior is unchanged.
    pub fn kernel_daemon(generation: ResourceGeneration) -> Result<Self, EliotPipeNameError> {
        EliotPipeOwner::validate_daemon_fields(generation).map(Self::kernel_daemon_from_validated)
    }

    /// Constructs a Kernel daemon identity from owner-validated fields.
    ///
    /// Infallible core: the bundle exists only after
    /// [`EliotPipeOwner::validate_daemon_fields`] enforced every check.
    pub(crate) fn kernel_daemon_from_validated(fields: ValidatedDaemonFields) -> Self {
        Self(EliotPipeEndpoint::KernelDaemon {
            generation: fields.generation,
        })
    }

    /// Constructs a generation-specific module identity.
    ///
    /// Validated edge: owner validation first, then infallible core
    /// construction. Rejection behavior is unchanged.
    pub fn module(
        module_id: ContractId,
        generation: ResourceGeneration,
    ) -> Result<Self, EliotPipeNameError> {
        EliotPipeOwner::validate_module_fields(module_id, generation)
            .map(Self::module_from_validated)
    }

    /// Constructs a module identity from owner-validated fields.
    ///
    /// Infallible core: the bundle exists only after
    /// [`EliotPipeOwner::validate_module_fields`] enforced every check,
    /// including the joint full-name bound.
    pub(crate) fn module_from_validated(fields: ValidatedModuleFields) -> Self {
        Self(EliotPipeEndpoint::Module {
            module_id: fields.module_id,
            module_segment: fields.module_segment,
            generation: fields.generation,
        })
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

    /// Returns the validated owner-segment view of a module endpoint.
    ///
    /// The segment spells the same canonical text as [`Self::module_id`];
    /// it is stored at construction so the segment type stays wired into
    /// the module path instead of remaining an orphan validator.
    pub fn module_segment(&self) -> Option<&EliotPipeSegment> {
        match self {
            Self(EliotPipeEndpoint::Module { module_segment, .. }) => Some(module_segment),
            _ => None,
        }
    }

    /// Parses one exact current canonical name.
    ///
    /// Delegates to the single namespace owner ([`EliotPipeOwner::parse_current`]).
    pub fn parse(value: &str) -> Result<Self, EliotPipeNameError> {
        EliotPipeOwner::parse_current(value)
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
                ..
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
    ///
    /// Delegates to the single namespace owner ([`EliotPipeOwner::parse_legacy`]).
    pub fn parse(value: &str) -> Result<Self, EliotPipeNameError> {
        EliotPipeOwner::parse_legacy(value)
    }

    /// Returns the historical digest prefix without exposing a raw wire name.
    pub fn digest_prefix(&self) -> &str {
        &self.governor_digest_prefix
    }

    /// Refuses conversion until the actual endpoint owner supplies a mapping.
    ///
    /// Delegates to the single namespace owner
    /// ([`EliotPipeOwner::map_legacy_to_current`]).
    pub const fn map_to_current(&self) -> Result<EliotPipeName, EliotPipeNameError> {
        EliotPipeOwner::map_legacy_to_current(self)
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
    #[error("must not be a reserved device name")]
    ReservedDevice,
    #[error("must not exceed the owner-segment byte bound")]
    TooLong,
}

/// Returns the deterministic identity of the typed pipe-name contract shape.
///
/// The shape pins the namespace prefix, wire revision, Unicode profile, and
/// closed endpoint catalogue. It never changes the v1 name wire bytes or
/// digest; valid-name canonical bytes stay byte-identical.
pub fn pipe_name_contract_identity() -> Result<ContractIdentity, ContractError> {
    let shape = serde_json::json!({
        "contract": PIPE_NAME_CONTRACT_NAME,
        "wire_revision": PIPE_NAME_WIRE_REVISION,
        "unicode_profile": PIPE_NAME_UNICODE_PROFILE,
        "prefix": ELIOT_PIPE_PREFIX,
        "families": ["kernel", "module", "watchdog"],
        "endpoints": [
            "kernel/frontdoor",
            "kernel/store",
            "kernel/daemon/<generation>",
            "module/<module_id>/<generation>",
            "watchdog/signals",
        ],
    });
    contract_identity(PIPE_NAME_CONTRACT_NAME, PIPE_NAME_CONTRACT_VERSION, &shape)
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
