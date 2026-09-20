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
//! identities, pins machine-derived per-executable observations through
//! [`ResolvedExecutableIdentity`], and rejects stale, unsupported, missing,
//! duplicate, ambiguous, and identity-mismatched mappings.

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
use thiserror::Error;

/// Recorded normalizer/parser/evaluator authority for adapters that own no parser.
///
/// Read from `eliot-diagnostic` (`CONTRACT_NAME`, version 1.0.0). The runner
/// takes no dependency on that crate here; the value is recorded, and live
/// dispatch proof remains follow-up work.
const DIAGNOSTIC_CONTRACT: &str = "eliot.instrument.diagnostic";
/// Recorded verifier authority for every ready entry.
///
/// Read from `eliot-verifier` (`CONTRACT_NAME`, version 1.0.0). Recording the
/// identity grants no verification authority to this crate.
const VERIFIER_CONTRACT: &str = "eliot.instrument.verifier";
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
/// entry stale through [`ProviderRegistry::resolve_current`]. Exact
/// per-executable digests are additionally pinned per result through
/// [`ResolvedExecutableIdentity`], so a replaced executable yields a
/// different identity instead of silently rebinding an earlier result.
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
}

/// Machine-derived executable observation bound to one instrument result.
///
/// Unlike [`ExecutableIdentity`], which records the admission-time
/// acquisition rule, this record is resolved from the machine at launch:
/// canonical path, content digest, tool version, environment projection
/// identity, and exact invocation arguments. Every governed profile result
/// carries one; a result without a complete observation can never take
/// authoritative PASS, and a replaced executable yields a different
/// [`ResolvedExecutableIdentity::identity_digest`] so the earlier result is
/// never silently rebound.
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
    /// # Errors
    ///
    /// Returns [`RegistryError::UnresolvedExecutable`] when the path, digest,
    /// environment identity, version text, or an argument is malformed.
    pub fn new(
        canonical_path: String,
        content_digest: String,
        tool_version: Option<String>,
        environment_digest: String,
        arguments: Vec<String>,
    ) -> Result<Self, RegistryError> {
        if canonical_path.trim().is_empty() || canonical_path.chars().any(char::is_control) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: String::new(),
                reason: ExecutableIdentityCause::InvalidPath,
            });
        }
        if !is_lower_hex_digest(&content_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: String::new(),
                reason: ExecutableIdentityCause::InvalidDigest,
            });
        }
        if !is_lower_hex_digest(&environment_digest) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: String::new(),
                reason: ExecutableIdentityCause::UnknownEnvironment,
            });
        }
        if tool_version.as_ref().is_some_and(|version| {
            version.trim().is_empty() || version.chars().any(char::is_control)
        }) {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: String::new(),
                reason: ExecutableIdentityCause::MissingVersion,
            });
        }
        if arguments
            .iter()
            .any(|argument| argument.chars().any(char::is_control))
        {
            return Err(RegistryError::UnresolvedExecutable {
                instrument: String::new(),
                reason: ExecutableIdentityCause::InvalidPath,
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

    /// Whether the observed arguments equal the admitted invocation arguments.
    pub fn binds_invocation(&self, invocation: &InstrumentInvocation) -> bool {
        self.arguments == invocation.arguments
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

    /// Pins a machine-derived observation to this entry before launch.
    ///
    /// Decoder-only entries reject any observation (they must never launch
    /// a process). Process entries require a complete observation whose
    /// executable file name matches the registry-bound executable; a missing,
    /// incomplete, or renamed executable fails closed so the result can never
    /// take authoritative PASS.
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
        Self::build(entries, generation, normative_pair_digest)
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
        let instrument = invocation.instrument.as_str();
        let mut candidate: Option<&'a RegistryEntry> = None;
        let mut candidates = 0usize;
        let mut claimant: Option<&'a RegistryEntry> = None;
        for entry in self.entries.values() {
            if entry.instrument.as_str() != instrument {
                continue;
            }
            if claimant.is_none() {
                claimant = Some(entry);
            }
            if entry.supports(invocation.kind) {
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
                        instrument: instrument.to_owned(),
                        reason: StaleReason::Generation {
                            expected: self.generation,
                            found: entry.generation,
                        },
                    });
                }
                Ok(entry)
            }
            (Some(_), _) => Err(RegistryError::Ambiguous {
                instrument: instrument.to_owned(),
                kind: invocation.kind,
                candidates,
            }),
            (None, Some(entry)) => Err(RegistryError::Unsupported {
                adapter: entry.adapter.clone(),
                kind: invocation.kind,
            }),
            (None, None) => Err(RegistryError::Missing {
                instrument: instrument.to_owned(),
                kind: invocation.kind,
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
        let entry = self.resolve(invocation)?;
        let instrument = invocation.instrument.as_str().to_owned();
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

/// Recorded verifier contract identity (see [`VERIFIER_CONTRACT`]).
fn verifier_id() -> Result<ContractId, ContractError> {
    contract_id(VERIFIER_CONTRACT)
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
        resource_contract: "composition-root port limits; adapter defines no capture bound"
            .to_owned(),
        cancellation_contract:
            "P-03 cancel/reconcile through OperationId (CargoInstrumentationAdapter)".to_owned(),
        parser: diagnostic_id()?,
        normalizer: diagnostic_id()?,
        evaluator: diagnostic_id()?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
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
        resource_contract: format!(
            "raw diagnostic capture bounded at {MAX_RUSTC_OUTPUT_BYTES} bytes (MAX_RUSTC_OUTPUT_BYTES)"
        ),
        cancellation_contract: "P-03 cancel/reconcile through OperationId (RustcAdapter)"
            .to_owned(),
        parser: contract_id(RUSTC_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(RUSTC_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
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
        resource_contract: format!(
            "raw output capture bounded at {MAX_RUSTFMT_OUTPUT_BYTES} bytes (MAX_RUSTFMT_OUTPUT_BYTES)"
        ),
        cancellation_contract: "P-03 cancel/reconcile through OperationId (RustfmtAdapter)"
            .to_owned(),
        parser: contract_id(RUSTFMT_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(RUSTFMT_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
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
        resource_contract: format!(
            "event stream capture bounded at {MAX_NEXTEST_OUTPUT_BYTES} bytes (MAX_NEXTEST_OUTPUT_BYTES)"
        ),
        cancellation_contract: "P-03 cancel/reconcile through OperationId (NextestAdapter)"
            .to_owned(),
        parser: contract_id(NEXTEST_INSTRUMENT)?,
        normalizer: diagnostic_id()?,
        evaluator: contract_id(NEXTEST_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
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
        resource_contract: format!(
            "SCIP decode bounded at {MAX_SCIP_BYTES} bytes (MAX_SCIP_BYTES)"
        ),
        cancellation_contract: "not applicable: decoder-only, no operation or fence".to_owned(),
        parser: contract_id(SCIP_INSTRUMENT)?,
        normalizer: contract_id(SCIP_INSTRUMENT)?,
        evaluator: contract_id(SCIP_INSTRUMENT)?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
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
        resource_contract: "composition-root port limits; adapter defines no capture bound"
            .to_owned(),
        cancellation_contract:
            "P-03 inspect/cancel/reconcile through OperationId (DotnetMsbuildAdapter)".to_owned(),
        parser: diagnostic_id()?,
        normalizer: diagnostic_id()?,
        evaluator: diagnostic_id()?,
        verifier: verifier_id()?,
        invalidation: fingerprints.clone(),
        generation,
    })
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
                "/usr/bin/rustc".to_owned(),
                "a".repeat(64),
                Some("rustc 1.89.0".to_owned()),
                String::new(),
                Vec::new(),
            )
            .is_err()
        );
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
        assert!(matching.binds_invocation(&invocation));
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
