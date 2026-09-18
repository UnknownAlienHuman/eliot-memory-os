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
//! live dispatch, real fixtures, timeout/cancel/cleanup behavior, live cache
//! binding, and per-executable digest pinning are follow-up work owned by
//! later slices; this slice records identities and rejects stale,
//! unsupported, missing, duplicate, and ambiguous mappings.

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
/// entry stale through [`ProviderRegistry::resolve_current`]. Per-executable
/// digest pinning keeps placeholder values until the owning environment
/// authority publishes exact digests (follow-up work).
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
