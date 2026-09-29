//! Deterministic typed registry binding admitted instrument profiles to providers.
//!
//! This module owns the closed profile-to-provider closure for issue #1128:
//! one Kernel-admitted typed [`InstrumentInvocation`] resolves through one
//! immutable [`RegistryEntry`] to exactly one adapter, executable identity,
//! environment contract, parser/normalizer/evaluator/verifier binding, and
//! invalidation set. Selection finishes before any process or build allocation
//! and fails closed with [`RegistryError`].
//!
//! The registry composes behind the Testd admission boundary owned by issue
//! #20. It never spawns a process, admits work to Testd, schedules a task,
//! writes canonical state, or decides verification. Raw evidence retention,
//! live dispatch, real fixtures, timeout/cancel/cleanup behavior, and live
//! cache binding are follow-up work owned by later slices; this slice records
//! per-result machine-derived observations through
//! [`ResolvedExecutableIdentity`] and rejects stale, unsupported, missing,
//! duplicate, ambiguous, and identity-mismatched mappings. The registry pins
//! no per-executable digest expectation of its own: the executable digest is
//! compared against the intent-sealed `executable_sha256` before launch by
//! the runner and again at launch (see `eliot-process-executor`), and
//! registry-pinned per-executable digests remain follow-up work with the
//! environment owner (see [`ProviderRegistry::ready`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_contracts::{ContractError, ContractId, ContractVersion};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_instrument_cargo::{
    CONTRACT_NAME as CARGO_CONTRACT_NAME, CONTRACT_VERSION as CARGO_CONTRACT_VERSION,
};
use eliot_instrument_dotnet::{CONTRACT_ID as DOTNET_CONTRACT_ID, DOTNET_EXECUTABLE};
use eliot_instrument_nextest::{MAX_NEXTEST_OUTPUT_BYTES, NEXTEST_INSTRUMENT};
use eliot_instrument_rustc::{MAX_RUSTC_OUTPUT_BYTES, RUSTC_EXECUTABLE, RUSTC_INSTRUMENT};
use eliot_instrument_rustfmt::{MAX_RUSTFMT_OUTPUT_BYTES, RUSTFMT_INSTRUMENT};
use eliot_instrument_scip::{MAX_SCIP_BYTES, SCIP_INSTRUMENT};
use eliot_verifier::CONTRACT_NAME as VERIFIER_CONTRACT_NAME;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Recorded normalizer/parser/evaluator authority for adapters that own no parser.
///
/// Read from `eliot-diagnostic` (`CONTRACT_NAME`, version 1.0.0). The runner
/// takes no dependency on that crate here; the value is recorded, and live
/// dispatch proof remains follow-up work.
const DIAGNOSTIC_CONTRACT: &str = "eliot.instrument.diagnostic";
/// Target scope recorded for process adapters.
///
/// Every process adapter command shape (`RustcCommand`, `RustfmtCommand`,
/// `NextestCommand`, `DotnetMsbuildCommand`) carries an arbitrary admitted
/// worktree `target: String`. The registry records the scope class, never a
/// path; exact worktree binding belongs to admission.
const ADMITTED_WORKTREE: &str = "admitted-worktree";
/// Environment class recorded for adapters that delegate to `P-03`.
const ISOLATED_PROCESS: &str = "isolated-process";
/// Environment class recorded for the decoder-only SCIP entry.
const OFFLINE_DECODE: &str = "offline-decode";
/// Work scope and state fence identity every entry binds.
const ADMITTED_FENCE: &str = "admitted WorkScope State Fence (profile::WorkScope)";
/// Feature identity every entry binds; no caller-selected feature text reaches
/// an executable, so the set is fixed by the profile contract.
const ADMITTED_FEATURES: &str = "admission-pinned feature set from the profile contract";
/// Timeout policy identity every process entry binds.
const ADMITTED_TIMEOUT: &str = "P-03 wall/idle timeout policy for the admitted stage";

/// Failures raised while building or resolving the provider registry.
///
/// Every variant is typed and fail-closed: no stringly-typed catch-all drives
/// control flow. Callers match on the variant, never on the message text.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    /// No entry claims the requested instrument identity.
    #[error("no registry entry for instrument '{instrument}' with kind {kind:?}")]
    Missing {
        /// Requested instrument contract name.
        instrument: String,
        /// Requested instrument class.
        kind: InstrumentKind,
    },
    /// Two entries claim the same instrument/adapter pair at build time.
    #[error("duplicate registry entry for instrument '{instrument}'")]
    Duplicate {
        /// Conflicting instrument contract name.
        instrument: String,
    },
    /// The matched entry is behind the caller-supplied freshness inputs.
    #[error("registry entry for instrument '{instrument}' is stale: {reason}")]
    Stale {
        /// Matched instrument contract name.
        instrument: String,
        /// Exact staleness cause.
        reason: StaleReason,
    },
    /// Two distinct adapters claim the same instrument profile and kind.
    ///
    /// Unreachable for registries assembled by [`ProviderRegistry::build`],
    /// which keys entries by instrument/adapter pair and rejects exact
    /// duplicates; retained fail-closed so a future loader can never resolve
    /// an ownership conflict into an execution.
    #[error("{candidates} registry entries match instrument '{instrument}' with kind {kind:?}")]
    Ambiguous {
        /// Contested instrument contract name.
        instrument: String,
        /// Requested instrument class.
        kind: InstrumentKind,
        /// Number of conflicting entries.
        candidates: usize,
    },
    /// One entry claims the instrument but not the requested kind.
    #[error("adapter '{adapter}' does not support {kind:?} invocations")]
    Unsupported {
        /// Claiming adapter identity.
        adapter: String,
        /// Requested instrument class.
        kind: InstrumentKind,
    },
    /// A registry contract identity failed validation while assembling entries.
    ///
    /// The shipped [`ProviderRegistry::ready`] literals are valid, so this
    /// variant only fires for a corrupted build input; it never degrades into
    /// a successful resolution.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// No machine-derived executable observation is bound to a process entry.
    ///
    /// A process result without a complete [`ResolvedExecutableIdentity`]
    /// can never take authoritative PASS; it stays `UNKNOWN`.
    #[error("no machine-derived executable identity for instrument '{instrument}': {reason}")]
    UnresolvedExecutable {
        /// Instrument contract name of the entry that requires an identity.
        instrument: String,
        /// Exact cause of the missing identity.
        reason: ExecutableIdentityCause,
    },
    /// A machine-derived observation does not match the registry binding.
    ///
    /// A replaced executable (or a decoder-only entry handed a launch
    /// identity) produces a different identity; the earlier result is never
    /// silently rebound and authoritative PASS is refused.
    #[error(
        "executable identity mismatch for instrument '{instrument}': expected '{expected}', observed '{observed}'"
    )]
    ExecutableMismatch {
        /// Instrument contract name of the entry that was checked.
        instrument: String,
        /// Registry-bound expectation.
        expected: String,
        /// Machine-derived observation.
        observed: String,
    },
    /// The instrument package disposition ledger rejected the assembly.
    ///
    /// The typed [`DispositionError`](crate::package_disposition::DispositionError)
    /// is carried across the layer boundary unchanged, so a caller can still
    /// match the exact disposition cause instead of parsing a message.
    #[error(transparent)]
    Disposition(#[from] crate::package_disposition::DispositionError),
    /// One profile identity slot is unbound.
    #[error("{instrument} leaves the {slot} identity slot unbound")]
    IdentitySlotBlank {
        /// Instrument contract identity.
        instrument: String,
        /// The unbound identity slot.
        slot: IdentitySlot,
    },
    /// One profile identity slot disagrees with the entry it is bound to.
    #[error("{instrument} records a {slot} identity that differs from the entry binding")]
    IdentitySlotDrift {
        /// Instrument contract identity.
        instrument: String,
        /// The drifted identity slot.
        slot: IdentitySlot,
    },
}

/// Exact cause of a [`RegistryError::Stale`] rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StaleReason {
    /// The entry generation does not equal the required generation.
    #[error("generation mismatch: entry at {found}, required {expected}")]
    Generation {
        /// Required registry generation.
        expected: u64,
        /// Generation recorded on the matched entry.
        found: u64,
    },
    /// The normative-pair digest does not equal the registry digest.
    #[error("normative-pair digest mismatch")]
    NormativePair,
    /// One invalidation fingerprint moved since the entry was validated.
    #[error("{field} fingerprint mismatch")]
    Fingerprint {
        /// Fingerprint slot that moved.
        field: FingerprintField,
    },
}

/// Exact cause of a missing machine-derived executable identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutableIdentityCause {
    /// No resolved observation was supplied for a process entry.
    #[error("missing resolved executable observation")]
    Missing,
    /// The canonical path is blank or carries control characters.
    #[error("invalid canonical path")]
    InvalidPath,
    /// The content digest is not a lowercase SHA-256 digest.
    #[error("invalid content digest")]
    InvalidDigest,
    /// An invocation argument carries control characters.
    #[error("invalid invocation arguments")]
    InvalidArguments,
    /// No tool version was observed for the executable.
    #[error("missing tool version")]
    MissingVersion,
    /// The environment projection identity is blank or not a digest.
    #[error("unknown environment projection")]
    UnknownEnvironment,
    /// A decoder-only entry was handed an executable observation and must
    /// never launch a process.
    #[error("decoder-only entry must not resolve an executable")]
    DecoderMustNotResolve,
}

/// One slot of the [`InvalidationSet`] that can force a stale rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintField {
    /// Source snapshot fingerprint.
    Source,
    /// Lockfile fingerprint.
    Lock,
    /// Toolchain fingerprint.
    Toolchain,
    /// Environment fingerprint.
    Env,
    /// Executable fingerprint.
    Exe,
    /// Profile fingerprint.
    Profile,
    /// Parser fingerprint.
    Parser,
}

impl fmt::Display for FingerprintField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "source",
            Self::Lock => "lock",
            Self::Toolchain => "toolchain",
            Self::Env => "env",
            Self::Exe => "exe",
            Self::Profile => "profile",
            Self::Parser => "parser",
        })
    }
}

/// Fingerprints an entry was validated against.
///
/// Values are attested by the composition root and passed in; the registry
/// never reads files at runtime. Any slot that moves afterwards makes the
/// entry stale through [`ProviderRegistry::resolve_current`]. A replaced
/// executable yields a different [`ResolvedExecutableIdentity::identity_digest`]
/// between two observations instead of silently rebinding an earlier result,
/// but the registry pins no per-executable digest expectation: exact
/// per-executable digests remain follow-up work with the environment owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationSet {
    /// Source snapshot fingerprint.
    pub source: String,
    /// Lockfile fingerprint.
    pub lock: String,
    /// Toolchain fingerprint.
    pub toolchain: String,
    /// Environment fingerprint.
    pub env: String,
    /// Executable fingerprint.
    pub exe: String,
    /// Profile fingerprint.
    pub profile: String,
    /// Parser fingerprint.
    pub parser: String,
}

impl InvalidationSet {
    /// Returns the first moved slot in deterministic field order, if any.
    ///
    /// Field order is fixed (source, lock, toolchain, env, exe, profile,
    /// parser) so repeated checks report the same cause.
    pub fn mismatch(&self, current: &Self) -> Option<FingerprintField> {
        if self.source != current.source {
            return Some(FingerprintField::Source);
        }
        if self.lock != current.lock {
            return Some(FingerprintField::Lock);
        }
        if self.toolchain != current.toolchain {
            return Some(FingerprintField::Toolchain);
        }
        if self.env != current.env {
            return Some(FingerprintField::Env);
        }
        if self.exe != current.exe {
            return Some(FingerprintField::Exe);
        }
        if self.profile != current.profile {
            return Some(FingerprintField::Profile);
        }
        if self.parser != current.parser {
            return Some(FingerprintField::Parser);
        }
        None
    }

    /// Whether every fingerprint slot still matches.
    pub fn matches(&self, current: &Self) -> bool {
        self.mismatch(current).is_none()
    }
}

/// Executable or decoder identity bound to one registry entry.
///
/// Process adapters record the exact executable name plus the acquisition
/// rule owned by the environment authority. The decoder-only SCIP entry
/// records no executable and instead names its decoder identity; it must
/// never be used to launch a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutableIdentity {
    /// Exact executable name, or `None` for decoder-only entries.
    pub executable: Option<String>,
    /// Acquisition rule owned by the environment/toolchain authority.
    pub acquisition_rule: String,
    /// Decoder identity, set only for decoder-only entries.
    pub decoder: Option<String>,
}

impl ExecutableIdentity {
    /// Binds a process executable to its acquisition rule.
    pub fn process(executable: impl Into<String>, acquisition_rule: impl Into<String>) -> Self {
        Self {
            executable: Some(executable.into()),
            acquisition_rule: acquisition_rule.into(),
            decoder: None,
        }
    }

    /// Binds a decoder-only identity with no executable launch path.
    pub fn decoder(decoder: impl Into<String>, acquisition_rule: impl Into<String>) -> Self {
        Self {
            executable: None,
            acquisition_rule: acquisition_rule.into(),
            decoder: Some(decoder.into()),
        }
    }

    /// Whether this entry launches no process and only decodes artifacts.
    pub fn is_decoder_only(&self) -> bool {
        self.executable.is_none()
    }

    /// The pinned executable name, or the decoder identity for a decoder-only
    /// entry. A decoder-only entry with no recorded decoder returns the empty
    /// string, which no recorded identity can match, so the profile identity
    /// check fails closed instead of skipping the comparison.
    pub fn identity_name(&self) -> &str {
        match self.executable.as_deref() {
            Some(name) => name,
            None => self.decoder.as_deref().unwrap_or_default(),
        }
    }
}

/// One exact identity every registry entry must bind before dispatch.
///
/// The slots are compared against the entry that carries them, so an entry
/// cannot claim an identity its own source, toolchain, environment, resource,
/// cancellation or executable binding contradicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySlot {
    /// Source snapshot identity.
    Source,
    /// Lockfile identity.
    Lock,
    /// Toolchain identity.
    Toolchain,
    /// Executable or decoder identity.
    Executable,
    /// Admitted feature set identity.
    Features,
    /// Environment class identity.
    Environment,
    /// Expected artifact identity.
    Artifact,
    /// Work scope and state fence identity.
    Fence,
    /// Admitted operation identity.
    Operation,
    /// Timeout policy identity.
    Timeout,
    /// Cancellation contract identity.
    Cancellation,
    /// Resource contract identity.
    Resource,
}

impl fmt::Display for IdentitySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "source",
            Self::Lock => "lock",
            Self::Toolchain => "toolchain",
            Self::Executable => "executable",
            Self::Features => "features",
            Self::Environment => "environment",
            Self::Artifact => "artifact",
            Self::Fence => "fence",
            Self::Operation => "operation",
            Self::Timeout => "timeout",
            Self::Cancellation => "cancellation",
            Self::Resource => "resource",
        })
    }
}

/// The exact identities one entry declares for [`REQUIRED_IDENTITY_SLOTS`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileIdentities {
    /// Source snapshot identity.
    pub source: String,
    /// Lockfile identity.
    pub lock: String,
    /// Toolchain identity.
    pub toolchain: String,
    /// Executable or decoder identity.
    pub executable: String,
    /// Admitted feature set identity.
    pub features: String,
    /// Environment class identity.
    pub environment: String,
    /// Expected artifact identity.
    pub artifact: String,
    /// Work scope and state fence identity.
    pub fence: String,
    /// Admitted operation identity.
    pub operation: String,
    /// Timeout policy identity.
    pub timeout: String,
    /// Cancellation contract identity.
    pub cancellation: String,
    /// Resource contract identity.
    pub resource: String,
}

impl ProfileIdentities {
    /// Records one entry's declared identities.
    #[must_use]
    pub fn new(params: ProfileIdentityParams) -> Self {
        Self {
            source: params.source,
            lock: params.lock,
            toolchain: params.toolchain,
            executable: params.executable,
            features: params.features,
            environment: params.environment,
            artifact: params.artifact,
            fence: params.fence,
            operation: params.operation,
            timeout: params.timeout,
            cancellation: params.cancellation,
            resource: params.resource,
        }
    }

    /// The identity recorded for one slot.
    pub fn slot(&self, slot: IdentitySlot) -> &str {
        match slot {
            IdentitySlot::Source => &self.source,
            IdentitySlot::Lock => &self.lock,
            IdentitySlot::Toolchain => &self.toolchain,
            IdentitySlot::Executable => &self.executable,
            IdentitySlot::Features => &self.features,
            IdentitySlot::Environment => &self.environment,
            IdentitySlot::Artifact => &self.artifact,
            IdentitySlot::Fence => &self.fence,
            IdentitySlot::Operation => &self.operation,
            IdentitySlot::Timeout => &self.timeout,
            IdentitySlot::Cancellation => &self.cancellation,
            IdentitySlot::Resource => &self.resource,
        }
    }

    /// Verifies the identities against the entry that carries them.
    ///
    /// Three checks run. The declared slot sets must partition
    /// [`PROFILE_IDENTITY_SLOTS`]. Every entry-owned slot in
    /// [`REQUIRED_IDENTITY_SLOTS`] must then carry a non-blank value, so an
    /// unbound identity fails closed instead of dispatching under a blank
    /// claim. Finally each identity the entry duplicates elsewhere is compared
    /// against that field, so a recorded source, lock, toolchain, environment,
    /// cancellation or resource identity cannot drift from the entry it claims
    /// to describe.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::IdentitySlotBlank`] for a slot outside both
    /// checked sets or an unbound entry-owned slot, or
    /// [`RegistryError::IdentitySlotDrift`] when a recorded identity differs
    /// from the entry field it duplicates.
    pub fn verify(&self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        Self::verify_slot_partition(entry)?;
        for slot in REQUIRED_IDENTITY_SLOTS {
            if self.slot(slot).trim().is_empty() {
                return Err(RegistryError::IdentitySlotBlank {
                    instrument: entry.instrument.as_str().to_owned(),
                    slot,
                });
            }
        }
        self.verify_attested(entry)?;
        self.verify_against(entry, IdentitySlot::Toolchain, &entry.toolchain)?;
        self.verify_against(
            entry,
            IdentitySlot::Executable,
            entry.executable.identity_name(),
        )?;
        self.verify_against(entry, IdentitySlot::Environment, &entry.environment_class)?;
        self.verify_against(
            entry,
            IdentitySlot::Cancellation,
            &entry.cancellation_contract,
        )?;
        self.verify_against(entry, IdentitySlot::Resource, &entry.resource_contract)
    }

    /// Requires the entry-owned and caller-attested slot sets together to
    /// cover every member of the independently declared
    /// [`PROFILE_IDENTITY_SLOTS`] list, so a newly declared slot can never sit
    /// outside both checked sets.
    fn verify_slot_partition(entry: &RegistryEntry) -> Result<(), RegistryError> {
        for slot in PROFILE_IDENTITY_SLOTS {
            if REQUIRED_IDENTITY_SLOTS.contains(&slot) || ATTESTED_IDENTITY_SLOTS.contains(&slot) {
                continue;
            }
            return Err(RegistryError::IdentitySlotBlank {
                instrument: entry.instrument.as_str().to_owned(),
                slot,
            });
        }
        Ok(())
    }

    /// Compares every caller-attested slot against the recorded fingerprint.
    ///
    /// An attested slot this loop cannot read is reported rather than skipped,
    /// so widening [`ATTESTED_IDENTITY_SLOTS`] can never silently drop a
    /// comparison.
    fn verify_attested(&self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        for slot in ATTESTED_IDENTITY_SLOTS {
            let observed: &str = match slot {
                IdentitySlot::Source => &entry.invalidation.source,
                IdentitySlot::Lock => &entry.invalidation.lock,
                unreadable => {
                    return Err(RegistryError::IdentitySlotDrift {
                        instrument: entry.instrument.as_str().to_owned(),
                        slot: unreadable,
                    });
                }
            };
            if self.slot(slot) == observed {
                continue;
            }
            return Err(RegistryError::IdentitySlotDrift {
                instrument: entry.instrument.as_str().to_owned(),
                slot,
            });
        }
        Ok(())
    }

    /// Compares one recorded identity against the entry field it duplicates.
    fn verify_against(
        &self,
        entry: &RegistryEntry,
        slot: IdentitySlot,
        observed: &str,
    ) -> Result<(), RegistryError> {
        if self.slot(slot) == observed {
            return Ok(());
        }
        Err(RegistryError::IdentitySlotDrift {
            instrument: entry.instrument.as_str().to_owned(),
            slot,
        })
    }
}

/// Every identity slot an entry binds, in deterministic order.
///
/// A slot is either entry-owned ([`REQUIRED_IDENTITY_SLOTS`], which must carry
/// a non-blank value) or caller-attested ([`ATTESTED_IDENTITY_SLOTS`], which is
/// compared against the entry's recorded fingerprints). Both kinds are compared
/// against the entry that carries them; neither is taken on trust.
pub const PROFILE_IDENTITY_SLOTS: [IdentitySlot; 12] = [
    IdentitySlot::Source,
    IdentitySlot::Lock,
    IdentitySlot::Toolchain,
    IdentitySlot::Executable,
    IdentitySlot::Features,
    IdentitySlot::Environment,
    IdentitySlot::Artifact,
    IdentitySlot::Fence,
    IdentitySlot::Operation,
    IdentitySlot::Timeout,
    IdentitySlot::Cancellation,
    IdentitySlot::Resource,
];

/// The identity slots the entry itself owns and must bind to a non-blank value.
pub const REQUIRED_IDENTITY_SLOTS: [IdentitySlot; 10] = [
    IdentitySlot::Toolchain,
    IdentitySlot::Executable,
    IdentitySlot::Features,
    IdentitySlot::Environment,
    IdentitySlot::Artifact,
    IdentitySlot::Fence,
    IdentitySlot::Operation,
    IdentitySlot::Timeout,
    IdentitySlot::Cancellation,
    IdentitySlot::Resource,
];

/// The identity slots that are caller-attested fingerprints rather than
/// entry-owned constants.
///
/// They are still compared against the entry's recorded fingerprints, but an
/// empty value is the honest "nothing attested" state the governed build lane
/// already uses, so emptiness is reported as an unattested slot rather than a
/// blank identity that could be mistaken for a bound one.
pub const ATTESTED_IDENTITY_SLOTS: [IdentitySlot; 2] = [IdentitySlot::Source, IdentitySlot::Lock];

/// The declared identity values one entry binds.
///
/// Fields are supplied separately from the [`RegistryEntry`] they will be
/// compared against so the comparison is against recorded content rather than
/// a second copy of the entry's own field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileIdentityParams {
    /// Source snapshot identity.
    pub source: String,
    /// Lockfile identity.
    pub lock: String,
    /// Toolchain identity.
    pub toolchain: String,
    /// Executable or decoder identity.
    pub executable: String,
    /// Admitted feature set identity.
    pub features: String,
    /// Environment class identity.
    pub environment: String,
    /// Expected artifact identity.
    pub artifact: String,
    /// Work scope and state fence identity.
    pub fence: String,
    /// Admitted operation identity.
    pub operation: String,
    /// Timeout policy identity.
    pub timeout: String,
    /// Cancellation contract identity.
    pub cancellation: String,
    /// Resource contract identity.
    pub resource: String,
}

/// Machine-derived executable observation bound to one instrument result.
///
/// Unlike [`ExecutableIdentity`], which records the admission-time
/// acquisition rule, this record carries the launch observation: canonical
/// path, content digest, tool version, environment projection identity, and
/// the exact argv handed to the executable. Only path and content digest are
/// hashed from the machine by the executor; version and environment digest
/// arrive caller-supplied and stay attested, never independently observed.
/// Every governed process result carries one; a process result without a
/// complete observation can never take authoritative PASS (decoder-only
/// entries never launch and legitimately carry none), and a replaced
/// executable yields a different [`ResolvedExecutableIdentity::identity_digest`]
/// so the earlier result is never silently rebound.
///
/// Argument contract: `arguments` is the exact process argv, compared only
/// against argv (the sealed [`ProcessRequest`](eliot_process::ProcessRequest)
/// argv through [`ResolvedExecutableIdentity::binds_argv`]). The admitted
/// [`InstrumentInvocation`](eliot_instrument_api::InstrumentInvocation)
/// arguments are instrument-level filters (e.g. nextest `-E` filters), never
/// argv, and are never compared here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedExecutableIdentity {
    /// Canonical filesystem path of the launched executable.
    pub canonical_path: String,
    /// Lowercase SHA-256 hex over the exact executable bytes.
    pub content_digest: String,
    /// Observed tool version text, or `None` when unobservable.
    pub tool_version: Option<String>,
    /// Lowercase SHA-256 hex over the resolved environment projection.
    pub environment_digest: String,
    /// Exact invocation arguments handed to the executable.
    pub arguments: Vec<String>,
}

impl ResolvedExecutableIdentity {
    /// Records one machine-derived observation, validating every field.
    ///
    /// `instrument` names the registry-bound instrument contract and is
    /// carried into every rejection so errors never render `for instrument
    /// ''`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnresolvedExecutable`] when the instrument
    /// name, path, digest, environment identity, version text, or an argument
    /// is malformed.
    pub fn new(
        instrument: &str,
        canonical_path: String,
        content_digest: String,
        tool_version: Option<String>,
        environment_digest: String,
        arguments: Vec<String>,
    ) -> Result<Self, RegistryError> {
        if instrument.trim().is_empty() || instrument.chars().any(char::is_control) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::Missing,
            });
        }
        if canonical_path.trim().is_empty() || canonical_path.chars().any(char::is_control) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::InvalidPath,
            });
        }
        if !is_lower_hex_digest(&content_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::InvalidDigest,
            });
        }
        if !is_lower_hex_digest(&environment_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::UnknownEnvironment,
            });
        }
        if tool_version.as_ref().is_some_and(|version| {
            version.trim().is_empty() || version.chars().any(char::is_control)
        }) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::MissingVersion,
            });
        }
        if arguments
            .iter()
            .any(|argument| argument.chars().any(char::is_control))
        {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: instrument.to_owned(),
                reason: ExecutableIdentityCause::InvalidArguments,
            });
        }
        Ok(Self {
            canonical_path,
            content_digest,
            tool_version,
            environment_digest,
            arguments,
        })
    }

    /// Whether the observation is complete enough for authoritative PASS.
    ///
    /// Completeness requires a non-blank path, a valid content digest, an
    /// observed (non-blank) tool version, and a valid environment digest.
    /// A missing version keeps the result `UNKNOWN`, never PASS.
    pub fn is_complete(&self) -> bool {
        !self.canonical_path.trim().is_empty()
            && is_lower_hex_digest(&self.content_digest)
            && self
                .tool_version
                .as_ref()
                .is_some_and(|version| !version.trim().is_empty())
            && is_lower_hex_digest(&self.environment_digest)
    }

    /// Deterministic identity over path, digest, version, environment, and
    /// arguments.
    ///
    /// Replacing the tool executable between two otherwise identical
    /// invocations changes the content digest and therefore this identity.
    pub fn identity_digest(&self) -> String {
        let version = self.tool_version.as_deref().unwrap_or("");
        let material = format!(
            "{}\0{}\0{}\0{}\0{}",
            self.canonical_path,
            self.content_digest,
            version,
            self.environment_digest,
            self.arguments.join("\0")
        );
        eliot_contracts::sha256_hex(material.as_bytes())
    }

    /// Whether the observed argv equals the sealed process-request argv.
    ///
    /// Both sides are exact process argv (executable arguments as handed to
    /// the executable). The admitted invocation arguments are
    /// instrument-level filters and are never compared here; comparing argv
    /// to filters would refuse every genuine run.
    pub fn binds_argv(&self, argv: &[String]) -> bool {
        self.arguments == argv
    }

    /// File name of the canonical path, lowercased without an `.exe` suffix.
    pub fn executable_file_name(&self) -> String {
        let tail = self
            .canonical_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(self.canonical_path.as_str());
        let lower = tail.to_ascii_lowercase();
        lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
    }
}

/// Whether `value` is a lowercase SHA-256 hex digest.
fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// One immutable provider binding: profile to adapter, executable,
/// environment, evidence pipeline, and invalidation set.
///
/// The profile identity is the owning adapter contract; the caller-selected
/// profile text on [`InstrumentInvocation`] is admission policy and is
/// fingerprinted through [`InvalidationSet::profile`], not used as a resolve
/// key. Kind support is the exact set each adapter enforces in its launch
/// path (see [`ProviderRegistry::ready`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryEntry {
    /// Owning profile contract identity.
    pub profile: ContractId,
    /// Owning profile contract version.
    pub profile_version: ContractVersion,
    /// Admitted instrument contract identity matched at resolve time.
    pub instrument: ContractId,
    /// Supported instrument classes, sorted and deduplicated at build.
    pub kinds: Vec<InstrumentKind>,
    /// Adapter identity string (owner lives in the provider crate).
    pub adapter: String,
    /// Adapter version.
    pub adapter_version: ContractVersion,
    /// Executable or decoder identity plus acquisition rule.
    pub executable: ExecutableIdentity,
    /// Required toolchain family identity.
    pub toolchain: String,
    /// Supported target scope classes (never concrete paths).
    pub targets: BTreeSet<String>,
    /// Required environment class.
    pub environment_class: String,
    /// Resource contract owned by the process authority.
    pub resource_contract: String,
    /// Cancellation contract owned by the process authority.
    pub cancellation_contract: String,
    /// Parser contract identity.
    pub parser: ContractId,
    /// Normalizer contract identity.
    pub normalizer: ContractId,
    /// Evaluator contract identity.
    pub evaluator: ContractId,
    /// Verifier contract identity.
    pub verifier: ContractId,
    /// Fingerprints this entry was validated against.
    pub invalidation: InvalidationSet,
    /// Exact source, toolchain, feature, environment, artifact, fence,
    /// operation, timeout, cancellation and resource identities this entry
    /// declares. Verified against the entry itself before dispatch.
    pub identities: ProfileIdentities,
    /// Registry generation this entry was validated against.
    pub generation: u64,
}

impl RegistryEntry {
    /// Whether this entry supports the requested instrument class.
    pub fn supports(&self, kind: InstrumentKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// Registry key: the admitted instrument contract name.
    pub fn instrument_key(&self) -> &str {
        self.instrument.as_str()
    }

    /// Verifies that this entry binds every exact profile identity slot and
    /// that the identities duplicating another entry field agree with it.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::IdentitySlotBlank`] for an unbound slot, or
    /// [`RegistryError::IdentitySlotDrift`] when a recorded identity differs
    /// from the entry field it duplicates.
    pub fn verify_profile_identities(&self) -> Result<(), RegistryError> {
        self.identities.verify(self)
    }

    /// Checks a machine-derived observation against this entry before launch.
    ///
    /// Decoder-only entries reject any observation (they must never launch
    /// a process) and accept `None`. Process entries require a complete
    /// observation whose executable file name matches the registry-bound
    /// executable; a missing, incomplete, or renamed executable fails closed
    /// so the result can never take authoritative PASS. This check pins the
    /// executable *name*; the runner additionally binds the content digest
    /// against the intent-sealed `executable_sha256` before launch (and the
    /// executor compares again at launch), and argv is compared against the
    /// sealed request argv by the binding (argv to argv, never argv to
    /// invocation filters).
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnresolvedExecutable`] when the observation
    /// is missing or incomplete, or [`RegistryError::ExecutableMismatch`]
    /// when it names a different executable or reaches a decoder-only entry.
    pub fn check_resolved_executable(
        &self,
        resolved: Option<&ResolvedExecutableIdentity>,
    ) -> Result<(), RegistryError> {
        let instrument = self.instrument.as_str().to_owned();
        if self.executable.is_decoder_only() {
            if let Some(observation) = resolved {
                return Err(RegistryError::ExecutableMismatch {
                    instrument,
                    expected: "decoder-only: no executable".to_owned(),
                    observed: observation.canonical_path.clone(),
                });
            }
            return Ok(());
        }
        let Some(observation) = resolved else {
            return Err(RegistryError::UnresolvedExecutable {
                instrument,
                reason: ExecutableIdentityCause::Missing,
            });
        };
        if !observation.is_complete() {
            let reason = if !is_lower_hex_digest(&observation.content_digest) {
                ExecutableIdentityCause::InvalidDigest
            } else if observation
                .tool_version
                .as_ref()
                .is_none_or(|version| version.trim().is_empty())
            {
                ExecutableIdentityCause::MissingVersion
            } else if !is_lower_hex_digest(&observation.environment_digest) {
                ExecutableIdentityCause::UnknownEnvironment
            } else {
                ExecutableIdentityCause::InvalidPath
            };
            return Err(RegistryError::UnresolvedExecutable { instrument, reason });
        }
        let Some(expected) = self.executable.executable.as_deref() else {
            return Err(RegistryError::UnresolvedExecutable {
                instrument,
                reason: ExecutableIdentityCause::Missing,
            });
        };
        if observation.executable_file_name() != expected.to_ascii_lowercase() {
            return Err(RegistryError::ExecutableMismatch {
                instrument,
                expected: expected.to_owned(),
                observed: observation.canonical_path.clone(),
            });
        }
        Ok(())
    }
}

/// Caller-supplied freshness inputs for [`ProviderRegistry::resolve_current`].
///
/// Everything is passed in; the registry reads no files at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryFreshness<'a> {
    /// Required registry generation.
    pub generation: u64,
    /// Required normative-pair digest.
    pub normative_pair_digest: &'a str,
    /// Required invalidation fingerprints.
    pub fingerprints: &'a InvalidationSet,
}

/// Deterministic registry of ready instrument providers.
///
/// Entries are keyed by instrument/adapter pair in a [`BTreeMap`], so
/// iteration order is sorted and stable. Construction rejects exact
/// duplicates; resolution rejects missing, unsupported, stale, and ambiguous
/// mappings before any process or build allocation.
#[derive(Clone, Debug)]
pub struct ProviderRegistry {
    entries: BTreeMap<(String, String), RegistryEntry>,
    generation: u64,
    normative_pair_digest: String,
}

impl ProviderRegistry {
    /// Assembles a registry from caller-supplied entries.
    ///
    /// Kind lists are sorted and deduplicated so iteration and matching stay
    /// deterministic regardless of caller order. Entry generations are
    /// preserved: an entry whose generation differs from `generation` resolves
    /// as [`RegistryError::Stale`], never as a successful binding.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Duplicate`] when two entries claim the same
    /// instrument/adapter pair, or [`RegistryError::Contract`] when an entry
    /// identity is invalid.
    pub fn build(
        entries: Vec<RegistryEntry>,
        generation: u64,
        normative_pair_digest: String,
    ) -> Result<Self, RegistryError> {
        let mut map = BTreeMap::new();
        for mut entry in entries {
            entry.kinds.sort_by_key(|kind| kind_rank(*kind));
            entry.kinds.dedup();
            let instrument = entry.instrument.as_str().to_owned();
            let key = (instrument.clone(), entry.adapter.clone());
            if map.insert(key, entry).is_some() {
                return Err(RegistryError::Duplicate { instrument });
            }
        }
        Ok(Self {
            entries: map,
            generation,
            normative_pair_digest,
        })
    }

    /// Assembles the six ready provider entries.
    ///
    /// Kind bindings follow each adapter launch path: `rustc` admits only
    /// [`InstrumentKind::Build`] (`RustcAdapter::launch` rejects anything
    /// else with `WrongInstrument`); `rustfmt` admits only
    /// [`InstrumentKind::Format`] (`RustfmtAdapter::launch`); `nextest`
    /// admits only [`InstrumentKind::Test`] (`NextestAdapter::launch`);
    /// `dotnet` admits build, test, verify, and inspect
    /// (`DotnetMsbuildAdapter::validate_invocation`); `cargo` imposes no kind
    /// gate in its bind path and is honestly bound to build plus test; `scip`
    /// is a decoder over emitted index bytes (`ScipIndex::decode`, no
    /// `ProcessExecutor` use) and is bound to inspect with no executable.
    ///
    /// Fingerprints are caller-attested and cloned into every entry; exact
    /// per-executable digests remain follow-up work with the environment owner.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Contract`] when a contract identity fails
    /// validation, or [`RegistryError::Duplicate`] on an internal assembly
    /// conflict (which indicates a programming error, never a caller fault).
    pub fn ready(
        generation: u64,
        normative_pair_digest: String,
        fingerprints: &InvalidationSet,
    ) -> Result<Self, RegistryError> {
        let entries = vec![
            cargo_entry(fingerprints, generation)?,
            rustc_entry(fingerprints, generation)?,
            rustfmt_entry(fingerprints, generation)?,
            nextest_entry(fingerprints, generation)?,
            scip_entry(fingerprints, generation)?,
            dotnet_entry(fingerprints, generation)?,
        ];
        let registry = Self::build(entries, generation, normative_pair_digest)?;
        registry.verify_profile_identities()?;
        crate::package_disposition::verify_disposition_coverage(&registry)?;
        Ok(registry)
    }

    /// Resolves one invocation to exactly one current entry.
    ///
    /// Fails with [`RegistryError::Missing`] when no entry claims the
    /// instrument, [`RegistryError::Unsupported`] when the claiming entry
    /// does not support the kind, [`RegistryError::Ambiguous`] when two
    /// distinct adapters claim the same instrument and kind, and
    /// [`RegistryError::Stale`] when the matched entry generation differs
    /// from the registry generation. No process or build resource is touched
    /// on any path.
    ///
    /// # Errors
    ///
    /// Returns the typed failure described above.
    pub fn resolve<'a>(
        &'a self,
        invocation: &InstrumentInvocation,
    ) -> Result<&'a RegistryEntry, RegistryError> {
        self.resolve_parts(&invocation.instrument, invocation.kind)
    }

    /// Resolves one instrument identity and class without an invocation.
    ///
    /// This is the exact [`ProviderRegistry::resolve`] lookup over the
    /// admitted `(instrument, kind)` pair instead of a full provider-neutral
    /// invocation, so classification-only callers (issue #1813 W4: the
    /// governed describe path records per-stage provider resolution without
    /// execution provisions) never fabricate invocation authority material
    /// such as a State Fence, session, or lease. It performs no freshness
    /// attestation: callers that launch must use
    /// [`ProviderRegistry::resolve_current`] with caller-attested
    /// [`RegistryFreshness`] instead.
    ///
    /// # Errors
    ///
    /// Returns the [`ProviderRegistry::resolve`] failures.
    pub fn resolve_parts(
        &self,
        instrument: &ContractId,
        kind: InstrumentKind,
    ) -> Result<&RegistryEntry, RegistryError> {
        let name = instrument.as_str();
        let mut candidate: Option<&RegistryEntry> = None;
        let mut candidates = 0usize;
        let mut claimant: Option<&RegistryEntry> = None;
        for entry in self.entries.values() {
            if entry.instrument.as_str() != name {
                continue;
            }
            if claimant.is_none() {
                claimant = Some(entry);
            }
            if entry.supports(kind) {
                candidates += 1;
                if candidate.is_none() {
                    candidate = Some(entry);
                }
            }
        }
        match (candidate, claimant) {
            (Some(entry), _) if candidates == 1 => {
                if entry.generation != self.generation {
                    return Err(RegistryError::Stale {
                        instrument: name.to_owned(),
                        reason: StaleReason::Generation {
                            expected: self.generation,
                            found: entry.generation,
                        },
                    });
                }
                Ok(entry)
            }
            (Some(_), _) => Err(RegistryError::Ambiguous {
                instrument: name.to_owned(),
                kind,
                candidates,
            }),
            (None, Some(entry)) => Err(RegistryError::Unsupported {
                adapter: entry.adapter.clone(),
                kind,
            }),
            (None, None) => Err(RegistryError::Missing {
                instrument: name.to_owned(),
                kind,
            }),
        }
    }

    /// Resolves one invocation and pins the result to caller freshness inputs.
    ///
    /// Runs [`ProviderRegistry::resolve`] first, then additionally rejects
    /// the binding when the registry generation, the normative-pair digest,
    /// or any invalidation fingerprint moved relative to `freshness`.
    ///
    /// # Errors
    ///
    /// Returns the [`ProviderRegistry::resolve`] failures plus
    /// [`RegistryError::Stale`] for generation, normative-pair, or
    /// fingerprint drift.
    pub fn resolve_current<'a>(
        &'a self,
        invocation: &InstrumentInvocation,
        freshness: &RegistryFreshness<'_>,
    ) -> Result<&'a RegistryEntry, RegistryError> {
        self.resolve_current_parts(&invocation.instrument, invocation.kind, freshness)
    }

    /// The same freshness-pinned resolution over an admitted
    /// `(instrument, kind)` pair instead of a full invocation.
    ///
    /// Classification-only callers hold no invocation authority material
    /// (no State Fence, session, or lease) and must not fabricate it to ask
    /// whether an entry is current. The closure is byte-for-byte the
    /// [`ProviderRegistry::resolve_current`] one over the same admitted
    /// pair.
    ///
    /// # Errors
    ///
    /// Returns the [`ProviderRegistry::resolve_parts`] failures plus
    /// [`RegistryError::Stale`] for generation, normative-pair, or
    /// fingerprint drift.
    pub fn resolve_current_parts<'a>(
        &'a self,
        instrument: &ContractId,
        kind: InstrumentKind,
        freshness: &RegistryFreshness<'_>,
    ) -> Result<&'a RegistryEntry, RegistryError> {
        let entry = self.resolve_parts(instrument, kind)?;
        let instrument = instrument.as_str().to_owned();
        if self.generation != freshness.generation || entry.generation != freshness.generation {
            return Err(RegistryError::Stale {
                instrument,
                reason: StaleReason::Generation {
                    expected: freshness.generation,
                    found: entry.generation,
                },
            });
        }
        if self.normative_pair_digest != freshness.normative_pair_digest {
            return Err(RegistryError::Stale {
                instrument,
                reason: StaleReason::NormativePair,
            });
        }
        if let Some(field) = entry.invalidation.mismatch(freshness.fingerprints) {
            return Err(RegistryError::Stale {
                instrument,
                reason: StaleReason::Fingerprint { field },
            });
        }
        Ok(entry)
    }

    /// Number of registered entries (denominator proof).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in sorted instrument/adapter key order.
    pub fn iter(&self) -> std::collections::btree_map::Values<'_, (String, String), RegistryEntry> {
        self.entries.values()
    }

    /// Registry generation entries are validated against.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Normative-pair digest this registry was assembled against.
    pub fn normative_pair_digest(&self) -> &str {
        &self.normative_pair_digest
    }

    /// Verifies the declared profile identities of every registered entry.
    ///
    /// `ready` runs this before returning, so a caller that assembles entries
    /// through `build` alone still gets the same guarantee before dispatch.
    ///
    /// # Errors
    ///
    /// Returns the first [`RegistryEntry::verify_profile_identities`] failure.
    pub fn verify_profile_identities(&self) -> Result<(), RegistryError> {
        for entry in self.entries.values() {
            entry.verify_profile_identities()?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a ProviderRegistry {
    type Item = &'a RegistryEntry;
    type IntoIter = std::collections::btree_map::Values<'a, (String, String), RegistryEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Deterministic sort rank for [`InstrumentKind`], following declaration order.
const fn kind_rank(kind: InstrumentKind) -> u8 {
    match kind {
        InstrumentKind::Build => 0,
        InstrumentKind::Test => 1,
        InstrumentKind::Lint => 2,
        InstrumentKind::Inspect => 3,
        InstrumentKind::Verify => 4,
        InstrumentKind::Format => 5,
    }
}

/// Builds a validated contract identity from a static literal.
fn contract_id(value: &'static str) -> Result<ContractId, ContractError> {
    ContractId::new(value)
}

/// Recorded diagnostic contract identity (see [`DIAGNOSTIC_CONTRACT`]).
fn diagnostic_id() -> Result<ContractId, ContractError> {
    contract_id(DIAGNOSTIC_CONTRACT)
}

/// Verifier contract identity bound from the owner crate.
///
/// Reads [`VERIFIER_CONTRACT_NAME`] from `eliot-verifier` instead of
/// duplicating the literal, so the recorded binding cannot drift from the
/// published verifier contract. Recording the identity grants no
/// verification authority to this crate.
fn verifier_id() -> Result<ContractId, ContractError> {
    contract_id(VERIFIER_CONTRACT_NAME)
}

/// Single admitted-worktree target scope shared by process adapters.
fn worktree_targets() -> BTreeSet<String> {
    BTreeSet::from([ADMITTED_WORKTREE.to_owned()])
}

/// Cargo entry: build plus test.
///
/// The cargo adapter performs no kind gate in its bind path, so the registry
/// honestly binds build plus test rather than every class. The adapter
/// defines no executable constant: the `cargo` name records the
/// composition-root contract shared with the `rustfmt`/`nextest` command
/// projections, and the request itself is port-supplied through
/// `CargoProcessRequestPort`. Parser, normalizer, and evaluator bind the
/// recorded diagnostic authority; the crate owns no parser.
fn cargo_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(CARGO_CONTRACT_NAME)?;
    let resource_contract = "composition-root port limits; adapter defines no capture bound";
    let cancellation_contract =
        "P-03 cancel/reconcile through OperationId (CargoInstrumentationAdapter)";
    Ok(RegistryEntry {
        profile: contract_id(CARGO_CONTRACT_NAME)?,
        profile_version: ContractVersion::new(
            CARGO_CONTRACT_VERSION.0,
            CARGO_CONTRACT_VERSION.1,
            CARGO_CONTRACT_VERSION.2,
        ),
        instrument,
        kinds: vec![InstrumentKind::Build, InstrumentKind::Test],
        adapter: CARGO_CONTRACT_NAME.to_owned(),
        adapter_version: ContractVersion::new(
            CARGO_CONTRACT_VERSION.0,
            CARGO_CONTRACT_VERSION.1,
            CARGO_CONTRACT_VERSION.2,
        ),
        executable: ExecutableIdentity::process(
            "cargo",
            "rust-toolchain composition-root port request; adapter defines no executable constant",
        ),
        toolchain: "cargo (rust toolchain)".to_owned(),
        targets: worktree_targets(),
        environment_class: ISOLATED_PROCESS.to_owned(),
        resource_contract: resource_contract.to_owned(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: diagnostic_id()?,
        normalizer: diagnostic_id()?,
        evaluator: diagnostic_id()?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "cargo (rust toolchain)".to_owned(),
            executable: "cargo".to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: ISOLATED_PROCESS.to_owned(),
            artifact: "cargo build/test outputs under the admitted target layout".to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "P-03 OperationId for the admitted cargo stage".to_owned(),
            timeout: ADMITTED_TIMEOUT.to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract.to_owned(),
        }),
        generation,
    })
}

/// Rustc entry: build only.
///
/// Kind and executable follow `RustcAdapter::launch` and `RUSTC_EXECUTABLE`;
/// the parser and evaluator follow the in-adapter `parse_jsonl` projection
/// and `RustcReport::execution_status` algebra.
fn rustc_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(RUSTC_INSTRUMENT)?;
    let resource_contract = format!(
        "raw diagnostic capture bounded at {MAX_RUSTC_OUTPUT_BYTES} bytes (MAX_RUSTC_OUTPUT_BYTES)"
    );
    let cancellation_contract = "P-03 cancel/reconcile through OperationId (RustcAdapter)";
    Ok(RegistryEntry {
        profile: contract_id(RUSTC_INSTRUMENT)?,
        profile_version: ContractVersion::new(1, 0, 0),
        instrument,
        kinds: vec![InstrumentKind::Build],
        adapter: RUSTC_INSTRUMENT.to_owned(),
        adapter_version: ContractVersion::new(1, 0, 0),
        executable: ExecutableIdentity::process(
            RUSTC_EXECUTABLE,
            "rust-toolchain (rustc distribution)",
        ),
        toolchain: "rustc".to_owned(),
        targets: worktree_targets(),
        environment_class: ISOLATED_PROCESS.to_owned(),
        resource_contract: resource_contract.clone(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: contract_id(RUSTC_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(RUSTC_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "rustc".to_owned(),
            executable: RUSTC_EXECUTABLE.to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: ISOLATED_PROCESS.to_owned(),
            artifact: "rustc emits no artifact; diagnostics stream through the raw evidence handle"
                .to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "P-03 OperationId for the admitted rustc stage".to_owned(),
            timeout: ADMITTED_TIMEOUT.to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract,
        }),
        generation,
    })
}

/// Rustfmt entry: format only.
///
/// Kind follows the `RustfmtAdapter::launch` gate; the executable records the
/// exact `cargo fmt --all -- --check` projection built by
/// `RustfmtCommand::check`. The parser and evaluator follow the in-adapter
/// `parse_output` projection and `RustfmtReport::outcome` algebra.
fn rustfmt_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(RUSTFMT_INSTRUMENT)?;
    let resource_contract = format!(
        "raw output capture bounded at {MAX_RUSTFMT_OUTPUT_BYTES} bytes (MAX_RUSTFMT_OUTPUT_BYTES)"
    );
    let cancellation_contract = "P-03 cancel/reconcile through OperationId (RustfmtAdapter)";
    Ok(RegistryEntry {
        profile: contract_id(RUSTFMT_INSTRUMENT)?,
        profile_version: ContractVersion::new(1, 0, 0),
        instrument,
        kinds: vec![InstrumentKind::Format],
        adapter: RUSTFMT_INSTRUMENT.to_owned(),
        adapter_version: ContractVersion::new(1, 0, 0),
        executable: ExecutableIdentity::process(
            "cargo",
            "rust-toolchain with rustfmt component; exact command mirrors RustfmtCommand::check (cargo fmt --all -- --check)",
        ),
        toolchain: "cargo (rust toolchain)".to_owned(),
        targets: worktree_targets(),
        environment_class: ISOLATED_PROCESS.to_owned(),
        resource_contract: resource_contract.clone(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: contract_id(RUSTFMT_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(RUSTFMT_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "cargo (rust toolchain)".to_owned(),
            executable: "cargo".to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: ISOLATED_PROCESS.to_owned(),
            artifact:
                "rustfmt --check emits no artifact; the check outcome streams as raw evidence"
                    .to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "P-03 OperationId for the admitted rustfmt stage".to_owned(),
            timeout: ADMITTED_TIMEOUT.to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract,
        }),
        generation,
    })
}

/// Nextest entry: test only.
///
/// Kind follows the `NextestAdapter::launch` gate; the executable records the
/// exact `cargo nextest run --profile <profile>` projection built by
/// `NextestCommand::run`. The parser and evaluator follow the in-adapter
/// `parse_jsonl` projection and `NextestReport::outcome` algebra.
fn nextest_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(NEXTEST_INSTRUMENT)?;
    let resource_contract = format!(
        "event stream capture bounded at {MAX_NEXTEST_OUTPUT_BYTES} bytes (MAX_NEXTEST_OUTPUT_BYTES)"
    );
    let cancellation_contract = "P-03 cancel/reconcile through OperationId (NextestAdapter)";
    Ok(RegistryEntry {
        profile: contract_id(NEXTEST_INSTRUMENT)?,
        profile_version: ContractVersion::new(1, 0, 0),
        instrument,
        kinds: vec![InstrumentKind::Test],
        adapter: NEXTEST_INSTRUMENT.to_owned(),
        adapter_version: ContractVersion::new(1, 0, 0),
        executable: ExecutableIdentity::process(
            "cargo",
            "rust-toolchain plus nextest binary; exact command mirrors NextestCommand::run (cargo nextest run --profile <profile>)",
        ),
        toolchain: "cargo (rust toolchain)".to_owned(),
        targets: worktree_targets(),
        environment_class: ISOLATED_PROCESS.to_owned(),
        resource_contract: resource_contract.clone(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: contract_id(NEXTEST_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(NEXTEST_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "cargo (rust toolchain)".to_owned(),
            executable: "cargo".to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: ISOLATED_PROCESS.to_owned(),
            artifact: "nextest test binaries under the admitted target layout; the run report is raw evidence".to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "P-03 OperationId for the admitted nextest stage".to_owned(),
            timeout: ADMITTED_TIMEOUT.to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract,
        }),
        generation,
    })
}

/// SCIP entry: inspect only, decoder-only.
///
/// The SCIP crate owns no process path: `ScipIndex::decode` reads emitted
/// index bytes and `graph_result` projects them through the graph contract.
/// The entry therefore binds no executable and must never launch a process.
/// Parser, normalizer, and evaluator bind the in-adapter decode/project
/// pipeline.
fn scip_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(SCIP_INSTRUMENT)?;
    let resource_contract =
        format!("SCIP decode bounded at {MAX_SCIP_BYTES} bytes (MAX_SCIP_BYTES)");
    let cancellation_contract = "not applicable: decoder-only, no operation or fence";
    Ok(RegistryEntry {
        profile: contract_id(SCIP_INSTRUMENT)?,
        profile_version: ContractVersion::new(1, 0, 0),
        instrument,
        kinds: vec![InstrumentKind::Inspect],
        adapter: SCIP_INSTRUMENT.to_owned(),
        adapter_version: ContractVersion::new(1, 0, 0),
        executable: ExecutableIdentity::decoder(
            SCIP_INSTRUMENT,
            "scip-indexer emission; no process launch (ScipIndex::decode only)",
        ),
        toolchain: "scip-indexer".to_owned(),
        targets: BTreeSet::new(),
        environment_class: OFFLINE_DECODE.to_owned(),
        resource_contract: resource_contract.clone(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: contract_id(SCIP_INSTRUMENT)?,
        normalizer: contract_id(SCIP_INSTRUMENT)?,
        evaluator: contract_id(SCIP_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "scip-indexer".to_owned(),
            executable: SCIP_INSTRUMENT.to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: OFFLINE_DECODE.to_owned(),
            artifact: "emitted SCIP index bytes decoded in process; no child process is created"
                .to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "decode-only operation identity; no admitted launch is required".to_owned(),
            timeout: "not applicable: decoder-only, decode is bounded by MAX_SCIP_BYTES".to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract,
        }),
        generation,
    })
}

/// Dotnet entry: build, test, verify, and inspect.
///
/// Kinds follow `DotnetMsbuildAdapter::validate_invocation`, which admits
/// exactly those four classes; the executable follows `DOTNET_EXECUTABLE`
/// with the alternate `msbuild` identity from `DotnetMsbuildConfig`. The
/// crate owns no parser, so parser, normalizer, and evaluator bind the
/// recorded diagnostic authority.
fn dotnet_entry(
    fingerprints: &InvalidationSet,
    generation: u64,
) -> Result<RegistryEntry, ContractError> {
    let instrument = contract_id(DOTNET_CONTRACT_ID)?;
    let resource_contract = "composition-root port limits; adapter defines no capture bound";
    let cancellation_contract =
        "P-03 inspect/cancel/reconcile through OperationId (DotnetMsbuildAdapter)";
    Ok(RegistryEntry {
        profile: contract_id(DOTNET_CONTRACT_ID)?,
        profile_version: ContractVersion::new(1, 0, 0),
        instrument,
        kinds: vec![
            InstrumentKind::Build,
            InstrumentKind::Test,
            InstrumentKind::Verify,
            InstrumentKind::Inspect,
        ],
        adapter: DOTNET_CONTRACT_ID.to_owned(),
        adapter_version: ContractVersion::new(1, 0, 0),
        executable: ExecutableIdentity::process(
            DOTNET_EXECUTABLE,
            "dotnet-sdk distribution; alternate msbuild executable per DotnetMsbuildConfig",
        ),
        toolchain: "dotnet-sdk".to_owned(),
        targets: worktree_targets(),
        environment_class: ISOLATED_PROCESS.to_owned(),
        resource_contract: resource_contract.to_owned(),
        cancellation_contract: cancellation_contract.to_owned(),
        parser: diagnostic_id()?,
        normalizer: diagnostic_id()?,
        evaluator: diagnostic_id()?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        identities: ProfileIdentities::new(ProfileIdentityParams {
            source: fingerprints.source.clone(),
            lock: fingerprints.lock.clone(),
            toolchain: "dotnet-sdk".to_owned(),
            executable: DOTNET_EXECUTABLE.to_owned(),
            features: ADMITTED_FEATURES.to_owned(),
            environment: ISOLATED_PROCESS.to_owned(),
            artifact:
                "msbuild outputs under the admitted target layout; the report is raw evidence"
                    .to_owned(),
            fence: ADMITTED_FENCE.to_owned(),
            operation: "P-03 OperationId for the admitted msbuild stage".to_owned(),
            timeout: ADMITTED_TIMEOUT.to_owned(),
            cancellation: cancellation_contract.to_owned(),
            resource: resource_contract.to_owned(),
        }),
        generation,
    })
}

/// Executable supply-chain receipt admitted for one instrument kind.
///
/// The receipt pins the exact executable file identity, content digest, and
/// tool version an admitted [`InstrumentSpec`](crate::profile::InstrumentSpec)
/// revision was verified against, together with the spec digest and the
/// registry generation of that verification. Receipts are admitted through
/// the canonical registry path alongside specs (see
/// [`SupplyChainTable`]); the pre-launch gate refuses an observed
/// executable whose file, digest, or pinned version drifts from the receipt
/// before any child process is created. Parser and profile generations stay
/// replaceable through ordinary module/daemon cutover: a new generation
/// ships a new receipt, never a Rust DLL ABI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainReceipt {
    /// Instrument contract identity the receipt pins.
    pub instrument: ContractId,
    /// Exact admitted executable file identity (for example `cargo`).
    pub executable: String,
    /// Lowercase SHA-256 hex over the exact executable bytes.
    pub content_digest: String,
    /// Admitted tool version text, when the verification pinned one.
    pub tool_version: Option<String>,
    /// Digest of the admitted spec revision the receipt was verified against.
    pub spec_digest: String,
    /// Registry generation the verification was validated against.
    pub generation: u64,
}

impl SupplyChainReceipt {
    /// Admits one supply-chain receipt, validating every field.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnresolvedExecutable`] when the executable
    /// identity, content digest, spec digest, or version text is malformed.
    pub fn new(
        instrument: ContractId,
        executable: String,
        content_digest: String,
        tool_version: Option<String>,
        spec_digest: String,
        generation: u64,
    ) -> Result<Self, RegistryError> {
        let name = instrument.as_str().to_owned();
        if executable.trim().is_empty() || executable.chars().any(char::is_control) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: name,
                reason: ExecutableIdentityCause::InvalidPath,
            });
        }
        if !is_lower_hex_digest(&content_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: name,
                reason: ExecutableIdentityCause::InvalidDigest,
            });
        }
        if !is_lower_hex_digest(&spec_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: name,
                reason: ExecutableIdentityCause::InvalidDigest,
            });
        }
        if tool_version.as_ref().is_some_and(|version| {
            version.trim().is_empty() || version.chars().any(char::is_control)
        }) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: name,
                reason: ExecutableIdentityCause::MissingVersion,
            });
        }
        Ok(Self {
            instrument,
            executable,
            content_digest,
            tool_version,
            spec_digest,
            generation,
        })
    }

    /// Pins one supply-chain receipt from a machine-derived observation.
    ///
    /// The machine owner observes the admitted executable file, then pins the
    /// observed content digest and tool version against the admitted spec
    /// digest at this generation. An unobserved tool version passes through
    /// as `None`: no version is attested on that path, so none is claimed,
    /// while a pinned version still gates at launch.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnresolvedExecutable`] when the executable
    /// identity, observed digest, spec digest, or version text is malformed.
    pub fn from_observation(
        instrument: ContractId,
        executable: String,
        identity: &ResolvedExecutableIdentity,
        spec_digest: String,
        generation: u64,
    ) -> Result<Self, RegistryError> {
        Self::new(
            instrument,
            executable,
            identity.content_digest.clone(),
            identity.tool_version.clone(),
            spec_digest,
            generation,
        )
    }

    /// Registry key: the admitted instrument contract name.
    pub fn instrument_key(&self) -> &str {
        self.instrument.as_str()
    }

    /// Checks a machine-derived observation against this receipt before launch.
    ///
    /// The observation must name the admitted executable file, carry the
    /// admitted content digest, and — when the receipt pins a version — carry
    /// that exact version. Any drift fails closed so a replaced executable
    /// can never launch under an earlier receipt.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ExecutableMismatch`] when the observation
    /// names a different file, digest, or pinned version.
    pub fn check_observation(
        &self,
        observation: &ResolvedExecutableIdentity,
    ) -> Result<(), RegistryError> {
        let instrument = self.instrument.as_str().to_owned();
        if observation.executable_file_name() != self.executable.to_ascii_lowercase() {
            return Err(RegistryError::ExecutableMismatch {
                instrument,
                expected: self.executable.clone(),
                observed: observation.canonical_path.clone(),
            });
        }
        if observation.content_digest != self.content_digest {
            return Err(RegistryError::ExecutableMismatch {
                instrument,
                expected: self.content_digest.clone(),
                observed: observation.content_digest.clone(),
            });
        }
        if let Some(pinned) = self.tool_version.as_deref()
            && observation.tool_version.as_deref() != Some(pinned)
        {
            return Err(RegistryError::ExecutableMismatch {
                instrument,
                expected: pinned.to_owned(),
                observed: observation
                    .tool_version
                    .clone()
                    .unwrap_or_else(|| "<unobserved>".to_owned()),
            });
        }
        Ok(())
    }

    /// Deterministic identity over every receipt field.
    pub fn digest(&self) -> String {
        let version = self.tool_version.as_deref().unwrap_or("");
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.instrument.as_str(),
            self.executable,
            self.content_digest,
            version,
            self.spec_digest,
            self.generation,
        );
        eliot_contracts::sha256_hex(material.as_bytes())
    }
}

/// Durable supply-chain receipt table on the canonical registry path.
///
/// Receipts are keyed by admitted instrument contract name in a [`BTreeMap`],
/// so iteration order is sorted and stable. The table is admitted together
/// with specs through the owning registry and digested into the registry
/// identity; physical persistence beyond the registry (canonical store,
/// artifact/receipt client) belongs to the Governor write path, which owns
/// canonical-store authority.
#[derive(Clone, Debug, Default)]
pub struct SupplyChainTable {
    receipts: BTreeMap<String, SupplyChainReceipt>,
}

impl SupplyChainTable {
    /// Admits one receipt, rejecting a second receipt for the same instrument.
    ///
    /// Replacement ships as a new registry generation with a new receipt,
    /// never as a silent overwrite: the owning registry rebuilds the table
    /// per generation.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Duplicate`] when the instrument already
    /// carries a receipt in this table.
    pub fn admit(&mut self, receipt: SupplyChainReceipt) -> Result<(), RegistryError> {
        let key = receipt.instrument_key().to_owned();
        if self.receipts.contains_key(&key) {
            return Err(RegistryError::Duplicate { instrument: key });
        }
        self.receipts.insert(key, receipt);
        Ok(())
    }

    /// Looks up the admitted receipt for one instrument contract name.
    pub fn get(&self, instrument: &str) -> Option<&SupplyChainReceipt> {
        self.receipts.get(instrument)
    }

    /// Admitted receipts in sorted instrument-identity order.
    pub fn receipts(&self) -> Vec<&SupplyChainReceipt> {
        self.receipts.values().collect()
    }

    /// Deterministic identity over the admitted receipts.
    pub fn digest(&self) -> String {
        let mut material = String::new();
        for receipt in self.receipts.values() {
            material.push_str(&receipt.digest());
            material.push('\0');
        }
        eliot_contracts::sha256_hex(material.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata, SourceId,
        StateFence,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn unreachable_id<T>(result: Result<T, impl std::fmt::Debug>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => unreachable!(),
        }
    }

    fn test_invocation(
        instrument: &str,
        kind: InstrumentKind,
        arguments: Vec<String>,
    ) -> InstrumentInvocation {
        let lineage = unreachable_id(EpochLineageId::new(TEST_LINEAGE_A));
        let epoch = unreachable_id(EpochId::new(
            lineage,
            NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
        ));
        let clock = ClockReading {
            valid_time_ms: Some(10),
            known_time_ms: Some(11),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        InstrumentInvocation {
            request: RequestMetadata {
                request_id: unreachable_id(RequestId::new("instrument-request-1")),
                session_id: None,
                task_id: None,
                product_id: unreachable_id(ProductId::new("product-1")),
                source_id: unreachable_id(SourceId::new("source-1")),
                state_fence: StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis()),
                clock,
            },
            instrument: unreachable_id(ContractId::new(instrument)),
            kind,
            profile: "dev-fast".to_owned(),
            target: "worktree:a04".to_owned(),
            arguments,
            input_artifacts: Vec::new(),
            declared_scope: "workspace".to_owned(),
            requested_at: clock,
        }
    }

    fn test_fingerprints() -> InvalidationSet {
        InvalidationSet {
            source: "source".to_owned(),
            lock: "lock".to_owned(),
            toolchain: "toolchain".to_owned(),
            env: "env".to_owned(),
            exe: "exe".to_owned(),
            profile: "profile".to_owned(),
            parser: "parser".to_owned(),
        }
    }

    fn rustc_observation(arguments: Vec<String>) -> ResolvedExecutableIdentity {
        unreachable_id(ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            "/usr/bin/rustc".to_owned(),
            "a".repeat(64),
            Some("rustc 1.89.0".to_owned()),
            "b".repeat(64),
            arguments,
        ))
    }

    #[test]
    fn replaced_executable_yields_different_identity() {
        let before = rustc_observation(vec!["--crate-name".to_owned(), "foo".to_owned()]);
        let mut after = before.clone();
        after.content_digest = "c".repeat(64);
        assert_ne!(before.identity_digest(), after.identity_digest());
        assert_eq!(before.identity_digest(), before.clone().identity_digest());
        assert!(before.is_complete());
    }

    #[test]
    fn observation_without_version_is_never_complete() {
        let mut observation = rustc_observation(Vec::new());
        observation.tool_version = None;
        assert!(!observation.is_complete());
        assert_ne!(
            observation.identity_digest(),
            rustc_observation(Vec::new()).identity_digest()
        );
    }

    #[test]
    fn malformed_observations_are_rejected() {
        assert!(
            ResolvedExecutableIdentity::new(
                RUSTC_INSTRUMENT,
                "/usr/bin/rustc".to_owned(),
                "not-a-digest".to_owned(),
                Some("rustc 1.89.0".to_owned()),
                "b".repeat(64),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            ResolvedExecutableIdentity::new(
                RUSTC_INSTRUMENT,
                "/usr/bin/rustc".to_owned(),
                "a".repeat(64),
                Some("rustc 1.89.0".to_owned()),
                String::new(),
                Vec::new(),
            )
            .is_err()
        );
        assert!(matches!(
            ResolvedExecutableIdentity::new(
                RUSTC_INSTRUMENT,
                "/usr/bin/rustc".to_owned(),
                "a".repeat(64),
                Some("rustc 1.89.0".to_owned()),
                "b".repeat(64),
                vec!["--crate-name\u{0}foo".to_owned()],
            ),
            Err(RegistryError::UnresolvedExecutable {
                reason: ExecutableIdentityCause::InvalidArguments,
                ..
            })
        ));
        assert!(matches!(
            ResolvedExecutableIdentity::new(
                "",
                "/usr/bin/rustc".to_owned(),
                "a".repeat(64),
                Some("rustc 1.89.0".to_owned()),
                "b".repeat(64),
                Vec::new(),
            ),
            Err(RegistryError::UnresolvedExecutable { .. })
        ));
    }

    #[test]
    fn process_entry_requires_complete_matching_identity() {
        let fingerprints = test_fingerprints();
        let registry = unreachable_id(ProviderRegistry::ready(
            7,
            "normative".to_owned(),
            &fingerprints,
        ));
        let invocation = test_invocation(
            RUSTC_INSTRUMENT,
            InstrumentKind::Build,
            vec!["--crate-name".to_owned(), "foo".to_owned()],
        );
        let Ok(entry) = registry.resolve(&invocation) else {
            unreachable!()
        };
        assert!(matches!(
            entry.check_resolved_executable(None),
            Err(RegistryError::UnresolvedExecutable {
                reason: ExecutableIdentityCause::Missing,
                ..
            })
        ));
        let mut unversioned = rustc_observation(invocation.arguments.clone());
        unversioned.tool_version = None;
        assert!(matches!(
            entry.check_resolved_executable(Some(&unversioned)),
            Err(RegistryError::UnresolvedExecutable {
                reason: ExecutableIdentityCause::MissingVersion,
                ..
            })
        ));
        let renamed = unreachable_id(ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            "/usr/bin/other-tool".to_owned(),
            "a".repeat(64),
            Some("other 1.0".to_owned()),
            "b".repeat(64),
            invocation.arguments.clone(),
        ));
        assert!(matches!(
            entry.check_resolved_executable(Some(&renamed)),
            Err(RegistryError::ExecutableMismatch { .. })
        ));
        let matching = rustc_observation(invocation.arguments.clone());
        assert!(entry.check_resolved_executable(Some(&matching)).is_ok());
        assert!(matching.binds_argv(&invocation.arguments));
    }

    #[test]
    fn decoder_only_entry_rejects_any_executable() {
        let fingerprints = test_fingerprints();
        let registry = unreachable_id(ProviderRegistry::ready(
            7,
            "normative".to_owned(),
            &fingerprints,
        ));
        let invocation = test_invocation(SCIP_INSTRUMENT, InstrumentKind::Inspect, Vec::new());
        let Ok(entry) = registry.resolve(&invocation) else {
            unreachable!()
        };
        assert!(entry.check_resolved_executable(None).is_ok());
        let observation = rustc_observation(Vec::new());
        assert!(matches!(
            entry.check_resolved_executable(Some(&observation)),
            Err(RegistryError::ExecutableMismatch { .. })
        ));
    }
}
