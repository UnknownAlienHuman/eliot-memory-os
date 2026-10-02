//! Declared provider denominator, typed availability, and the shared
//! conformance corpus contract (issue #1128).
//!
//! [`ProviderRegistry`](crate::registry::ProviderRegistry) answers *which*
//! adapter one admitted profile resolves to. This module answers the two
//! questions that keep a missing or unsupported provider from disappearing
//! from the record:
//!
//! - **Denominator** — [`ProviderDenominator`] lists every advertised
//!   Instrument contract identity alongside the single registry entry that
//!   owns it. An advertised instrument with no entry is reported as
//!   [`ProviderDisposition::Unmapped`] instead of silently resolving to
//!   nothing, and a registry entry for an unadvertised instrument is
//!   reported as [`ProviderDenominatorError::UnadvertisedEntry`]. Package
//!   presence alone never proves readiness: support is read from the
//!   closed [`ProviderSupport`] table below, never from a crate name.
//!
//! - **Availability** — [`ProviderAvailability`] is the typed, per-entry
//!   result of asking whether one provider can run on *this* host and
//!   *this* registry generation. An unsupported platform or an absent
//!   toolchain yields [`ProviderAvailability::UnsupportedPlatform`] or
//!   [`ProviderAvailability::Unavailable`] carrying a
//!   [`ProviderDisposition`], which keeps the provider inside the declared
//!   denominator and can never be projected as a successful run.
//!
//! - **Conformance** — [`ConformanceCorpus`] and [`ProviderFixtureSet`]
//!   define the product code the shared conformance corpus and the
//!   provider-specific real execution fixtures (work item 8) are written
//!   against. They bind a corpus/fixture to the exact registry generation
//!   and invalidation set it was written for, so a provider change
//!   invalidates reuse instead of letting a stale fixture vouch for a
//!   rebuilt adapter. No test lives in this module; it ships the contract
//!   only.
//!
//! Axes stay separate. Availability is not execution, execution is not
//! parsing, parsing is not evaluation, and none of them is a task
//! acceptance or a Finish. Nothing here writes canonical state, admits a
//! task, or issues `VERIFIED_COMPLETE`: the type surface is a read-only
//! inventory plus a fail-closed predicate.

use std::collections::BTreeMap;
use std::fmt;

use eliot_contracts::ContractId;
use eliot_instrument_api::InstrumentKind;
use thiserror::Error;

use crate::registry::{FingerprintField, InvalidationSet, RegistryEntry, StaleReason};

/// Stable identity of the provider denominator contract.
pub const DENOMINATOR_CONTRACT: &str = "eliot.instrument.provider-denominator";
/// Wire revision of the provider denominator contract.
pub const DENOMINATOR_CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Declared support level of one advertised Instrument identity.
///
/// Support is read from this closed table only. It is never inferred from
/// a crate name, a `Cargo.toml` feature, or the presence of a symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSupport {
    /// The identity is an execution-facing provider with a registered
    /// registry entry that owns an adapter, executable identity, and
    /// evidence pipeline.
    Executable,
    /// The identity is an in-process provider that never launches a
    /// process: it decodes or projects already-produced bytes.
    DecoderOnly,
    /// The identity is an in-process projection that never launches a
    /// process and never parses tool output.
    InProcess,
    /// The identity is advertised by its owning crate but this registry
    /// generation registers no entry for it. It stays in the denominator
    /// and resolves to [`ProviderDisposition::Unmapped`].
    Unmapped,
}

/// One advertised Instrument identity and its closed support declaration.
///
/// `owner` names the crate that publishes the contract constant. It is
/// evidence of ownership for the inventory, never a readiness claim: the
/// authoritative field is [`ProviderSupport::support`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdvertisedInstrument {
    /// The advertised instrument contract identity.
    pub contract: &'static str,
    /// Crate that publishes this identity as its adapter contract.
    pub owner: &'static str,
    /// Declared support for this registry generation.
    pub support: ProviderSupport,
}

impl AdvertisedInstrument {
    const fn new(contract: &'static str, owner: &'static str, support: ProviderSupport) -> Self {
        Self {
            contract,
            owner,
            support,
        }
    }
}

use ProviderSupport::{DecoderOnly, Executable, InProcess, Unmapped};

/// Every Instrument contract identity advertised by the instrument
/// subtree, in sorted contract order.
///
/// The list is the declared denominator: an entry here with no registry
/// mapping is reported, not dropped, and a registry entry with no row here
/// is rejected. Runtime projection crates that own no adapter
/// (`eliot-instrument-api`, `eliot-verifier`, `eliot-diagnostic`,
/// `eliot-artifact`, `eliot-reports`, `eliot-observability`,
/// `eliot-empirical-profile`, `eliot-product-evaluation`) are *not* rows:
/// they publish no provider-neutral `InstrumentKind` invocation surface and
/// have no entry, so listing them would overstate the denominator. The two
/// non-executable in-process projections that do carry a contract identity
/// are listed as [`ProviderSupport::InProcess`] in
/// [`UNMAPPED_IN_PROCESS_INSTRUMENTS`] so their absence of an entry stays
/// visible inside the same declared denominator.
pub const ADVERTISED_INSTRUMENTS: &[AdvertisedInstrument] = &[
    AdvertisedInstrument::new(
        eliot_instrument_cargo::CONTRACT_NAME,
        "eliot-instrument-cargo",
        Executable,
    ),
    AdvertisedInstrument::new(
        eliot_instrument_rustc::RUSTC_INSTRUMENT,
        "eliot-instrument-rustc",
        Executable,
    ),
    AdvertisedInstrument::new(
        eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT,
        "eliot-instrument-rustfmt",
        Executable,
    ),
    AdvertisedInstrument::new(
        eliot_instrument_nextest::NEXTEST_INSTRUMENT,
        "eliot-instrument-nextest",
        Executable,
    ),
    AdvertisedInstrument::new(
        eliot_instrument_scip::SCIP_INSTRUMENT,
        "eliot-instrument-scip",
        DecoderOnly,
    ),
    AdvertisedInstrument::new(
        eliot_instrument_dotnet::CONTRACT_ID,
        "eliot-instrument-dotnet",
        Executable,
    ),
];

/// In-process instrument identities advertised by sibling instrument
/// crates that this registry deliberately does not map.
///
/// They are recorded as literals, not crate references, because
/// `eliot-build-test-graph` and `eliot-test-selection` are workspace members
/// that publish a contract identity but own no adapter entry: adding either
/// as a dependency of the runner would change the locked dependency graph
/// for no behavioural gain. The literals are exact copies of
/// `eliot_build_test_graph::CONTRACT_NAME` and
/// `eliot_test_selection::TEST_SELECTION_INSTRUMENT`; their identities remain
/// visible in the declared denominator without creating compile-time
/// references.
pub const UNMAPPED_IN_PROCESS_INSTRUMENTS: &[AdvertisedInstrument] = &[
    AdvertisedInstrument::new(
        "eliot.instrument.build-test-graph",
        "eliot-build-test-graph",
        InProcess,
    ),
    AdvertisedInstrument::new(
        "eliot.instrument.test-selection",
        "eliot-test-selection",
        InProcess,
    ),
];

/// Every declared instrument row, executable providers first.
///
/// Concatenating the two published slices keeps the mapped executable
/// providers and the deliberately unmapped in-process projections in one
/// declared denominator, so a reader cannot take
/// [`ADVERTISED_INSTRUMENTS`] alone as the full list.
pub fn declared_instruments() -> impl Iterator<Item = &'static AdvertisedInstrument> {
    ADVERTISED_INSTRUMENTS
        .iter()
        .chain(UNMAPPED_IN_PROCESS_INSTRUMENTS.iter())
}

/// Failures building or checking the declared provider denominator.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDenominatorError {
    /// Two advertised rows claim the same instrument contract identity.
    #[error("duplicate advertised instrument '{instrument}'")]
    DuplicateAdvertised {
        /// Conflicting instrument contract name.
        instrument: String,
    },
    /// The registry carries an entry for an identity that no provider crate
    /// advertises. The entry would be unreachable and, worse, could be the
    /// only owner of an executable.
    #[error("registry entry '{instrument}' is claimed by no advertised instrument")]
    UnadvertisedEntry {
        /// Instrument contract name of the orphan entry.
        instrument: String,
    },
}

/// Typed disposition of one advertised provider.
///
/// Every non-executable state is a first-class variant, so an absent or
/// unsupported provider can be counted in the denominator without ever
/// being mistaken for a successful run. No variant means "executed" or
/// "passed": execution is a separate axis owned by
/// [`GovernedInstrumentResult`](crate::GovernedInstrumentResult) and the
/// parser/evaluator/verifier are separate axes owned by their own crates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDisposition {
    /// Exactly one current registry entry owns this instrument.
    Ready,
    /// The identity is advertised but this generation registers no entry.
    Unmapped,
    /// The adapter is registered but this host platform is not supported.
    UnsupportedPlatform {
        /// Platform the entry requires.
        required: String,
        /// Platform this host reports.
        observed: String,
    },
    /// The adapter is registered but its toolchain is not installed.
    Unavailable {
        /// Exact acquisition rule from the entry.
        rule: String,
    },
    /// The matched entry is behind the caller's freshness inputs.
    Stale {
        /// Exact staleness cause.
        reason: StaleReason,
    },
    /// The entry claims the instrument but not the requested class.
    Unsupported {
        /// Claiming adapter identity.
        adapter: String,
        /// Requested instrument class.
        kind: InstrumentKind,
    },
    /// The entry resolved, is current, and is supported on this host, but
    /// live Testd cannot dispatch the requested class.
    UnsupportedByTestd {
        /// Registry-selected adapter identity.
        adapter: String,
        /// Requested instrument class.
        kind: InstrumentKind,
    },
    /// Two entries claim the same instrument and class.
    Ambiguous {
        /// Contested instrument contract name.
        instrument: String,
        /// Requested instrument class.
        kind: InstrumentKind,
        /// Number of conflicting entries.
        candidates: usize,
    },
}

impl ProviderDisposition {
    /// Whether the provider may be dispatched at all.
    ///
    /// Only [`ProviderDisposition::Ready`] may reach execution. Every other
    /// variant keeps the provider visible in the denominator and refuses
    /// the launch; a `Ready` disposition is still not an outcome, and
    /// execution must independently report its own axis.
    pub const fn is_dispatchable(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl fmt::Display for ProviderDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => f.write_str("ready"),
            Self::Unmapped => f.write_str("unmapped"),
            Self::UnsupportedPlatform { required, observed } => write!(
                f,
                "unsupported-platform: requires {required}, host {observed}"
            ),
            Self::Unavailable { rule } => write!(f, "unavailable: {rule}"),
            Self::Stale { reason } => write!(f, "stale: {reason}"),
            Self::Unsupported { adapter, kind } => {
                write!(f, "unsupported: {adapter} does not support {kind:?}")
            }
            Self::UnsupportedByTestd { adapter, kind } => {
                write!(
                    f,
                    "unsupported-by-testd: {adapter} with {kind:?} is not dispatchable via testd"
                )
            }
            Self::Ambiguous {
                instrument,
                kind,
                candidates,
            } => write!(
                f,
                "ambiguous: {candidates} entries match {instrument} with {kind:?}"
            ),
        }
    }
}

/// The declared denominator: every advertised instrument with the single
/// registry entry that owns it, or its typed reason for having none.
///
/// `unmapped` retains the instrument contract name, so an advertised
/// provider without an entry is counted and reported rather than dropped
/// from the denominator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderDenominator {
    generation: u64,
    /// Advertised contract name to the owning entry, when one exists.
    mapped: BTreeMap<String, RegistryEntry>,
    /// Advertised contract name to the owning crate, for every row.
    owners: BTreeMap<String, &'static str>,
    /// Advertised contract names with no current entry, in sorted order.
    unmapped: Vec<String>,
}

impl ProviderDenominator {
    /// Reconciles the advertised instrument list with the current registry.
    ///
    /// Fails closed when the advertised list names one instrument twice or
    /// the registry carries an entry no provider crate advertises; both are
    /// assembly defects that must never resolve into a dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderDenominatorError::DuplicateAdvertised`] or
    /// [`ProviderDenominatorError::UnadvertisedEntry`].
    pub fn current(
        registry: &crate::registry::ProviderRegistry,
    ) -> Result<Self, ProviderDenominatorError> {
        let mut owners = BTreeMap::new();
        let mut mapped = BTreeMap::new();
        let mut unmapped = Vec::new();
        for advertised in declared_instruments() {
            if owners
                .insert(advertised.contract.to_owned(), advertised.owner)
                .is_some()
            {
                return Err(ProviderDenominatorError::DuplicateAdvertised {
                    instrument: advertised.contract.to_owned(),
                });
            }
            let instrument = ContractId::new(advertised.contract).map_err(|_| {
                ProviderDenominatorError::DuplicateAdvertised {
                    instrument: format!("{}: invalid contract identity", advertised.contract),
                }
            })?;
            match owning_entry(registry, &instrument, advertised.support) {
                Ok(entry) => {
                    mapped.insert(advertised.contract.to_owned(), entry);
                }
                Err(Ownership::Unmapped) => {
                    unmapped.push(advertised.contract.to_owned());
                }
                Err(Ownership::Defect(reason)) => {
                    // A declared support level the owning entry does not
                    // implement is an assembly defect, not an absent
                    // provider: refuse the whole inventory instead of
                    // publishing a mapping that cannot dispatch.
                    return Err(ProviderDenominatorError::UnadvertisedEntry {
                        instrument: format!("{}: {reason}", advertised.contract),
                    });
                }
            }
        }
        for entry in registry {
            if !owners.contains_key(entry.instrument_key()) {
                return Err(ProviderDenominatorError::UnadvertisedEntry {
                    instrument: entry.instrument_key().to_owned(),
                });
            }
        }
        unmapped.sort();
        Ok(Self {
            generation: registry.generation(),
            mapped,
            owners,
            unmapped,
        })
    }

    /// Registry generation this inventory was reconciled against.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Declared denominator size: every advertised instrument, mapped or
    /// not. An unsupported or unmapped provider never shrinks this.
    pub fn declared(&self) -> usize {
        self.owners.len()
    }

    /// Number of advertised instruments with a current entry.
    pub fn mapped(&self) -> usize {
        self.mapped.len()
    }

    /// Advertised instruments with no current entry, in sorted order.
    pub fn unmapped(&self) -> &[String] {
        &self.unmapped
    }

    /// The single entry owning `instrument`, if this generation maps it.
    #[must_use]
    pub fn entry(&self, instrument: &str) -> Option<&RegistryEntry> {
        self.mapped.get(instrument)
    }

    /// The crate that advertises `instrument`.
    #[must_use]
    pub fn owner(&self, instrument: &str) -> Option<&'static str> {
        self.owners.get(instrument).copied()
    }

    /// Inventory rows in sorted instrument order.
    pub fn rows(&self) -> Vec<ProviderDenominatorRow<'_>> {
        self.owners
            .iter()
            .map(|(instrument, owner)| ProviderDenominatorRow {
                instrument,
                owner,
                entry: self.mapped.get(instrument),
            })
            .collect()
    }
}

/// One row of the declared denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDenominatorRow<'a> {
    /// Advertised instrument contract name.
    pub instrument: &'a str,
    /// Crate that advertises the identity.
    pub owner: &'a str,
    /// The single owning entry, absent when unmapped.
    pub entry: Option<&'a RegistryEntry>,
}

impl ProviderDenominatorRow<'_> {
    /// The typed reason this row is or is not dispatchable.
    ///
    /// A row without an entry is [`ProviderDisposition::Unmapped`]; it
    /// stays in the denominator and never resolves to an adapter.
    #[must_use]
    pub fn disposition(&self) -> ProviderDisposition {
        self.entry.map_or(ProviderDisposition::Unmapped, |_| {
            ProviderDisposition::Ready
        })
    }
}

/// Why one advertised row resolved or failed to resolve to an entry.
enum Ownership {
    /// No entry claims this instrument at any declared class.
    Unmapped,
    /// The entry exists but contradicts the declared support level.
    Defect(String),
}

/// Every instrument class, in the deterministic order used by
/// [`crate::registry::kind_rank`].
const ALL_KINDS: [InstrumentKind; 6] = [
    InstrumentKind::Build,
    InstrumentKind::Test,
    InstrumentKind::Lint,
    InstrumentKind::Inspect,
    InstrumentKind::Verify,
    InstrumentKind::Format,
];

/// Resolves the single entry owning `instrument` under its declared support.
///
/// Every declared class is probed, not one representative class, so a
/// provider that admits only `FORMAT` (rustfmt) or only `TEST` (nextest)
/// still reconciles instead of being reported unmapped. A single
/// successful class proves the entry exists; a
/// [`ProviderRegistry::Ambiguous`] answer is a defect because it can never
/// reach a dispatch. The returned entry is cloned, so the caller keeps no
/// borrow on the registry.
fn owning_entry(
    registry: &crate::registry::ProviderRegistry,
    instrument: &ContractId,
    support: ProviderSupport,
) -> Result<RegistryEntry, Ownership> {
    let mut owned: Option<RegistryEntry> = None;
    let mut unsupported = Vec::new();
    for kind in ALL_KINDS {
        match registry.resolve_parts(instrument, kind) {
            Ok(entry) => {
                if owned.is_none() {
                    owned = Some(entry.clone());
                }
            }
            Err(crate::registry::RegistryError::Unsupported { .. }) => unsupported.push(kind),
            Err(crate::registry::RegistryError::Missing { .. }) => {}
            Err(other) => return Err(Ownership::Defect(other.to_string())),
        }
    }
    if let Some(entry) = owned {
        return Ok(entry);
    }
    // No class is claimed by an entry. A decoder-only, in-process, or
    // unmapped declaration expects exactly that. An executable declaration
    // with an entry that claims no dispatchable class contradicts the
    // registry; one with no entry at all is still just unmapped.
    match support {
        Executable if !unsupported.is_empty() => Err(Ownership::Defect(format!(
            "entry claims no dispatchable class (unsupported: {unsupported:?})"
        ))),
        DecoderOnly | InProcess | Unmapped | Executable => Err(Ownership::Unmapped),
    }
}

/// Host platform identity used for availability checks.
///
/// Deliberately the OS name only. It is recorded as evidence next to a
/// disposition and never selects an executable or a command.
#[must_use]
pub const fn host_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// The availability of one provider on this host at this generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderAvailability {
    /// Exactly one current entry owns the instrument and this host is
    /// supported. This is a *precondition*, never an outcome: execution
    /// still has to run and report its own axis.
    Ready {
        /// The single owning entry.
        entry: Box<RegistryEntry>,
    },
    /// The provider is registered but cannot run here or cannot be proven
    /// current. It remains in the declared denominator.
    Unavailable {
        /// Exact typed reason.
        disposition: ProviderDisposition,
    },
}

impl ProviderAvailability {
    /// Whether this host may attempt the provider.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// The owning entry, when the provider is available.
    #[must_use]
    pub fn entry(&self) -> Option<&RegistryEntry> {
        match self {
            Self::Ready { entry } => Some(entry),
            Self::Unavailable { .. } => None,
        }
    }

    /// The typed disposition for this provider.
    #[must_use]
    pub fn disposition(&self) -> ProviderDisposition {
        match self {
            Self::Ready { .. } => ProviderDisposition::Ready,
            Self::Unavailable { disposition } => disposition.clone(),
        }
    }
}

/// Freshness inputs for [`ProviderRegistry::availability`].
///
/// Mirrors [`crate::registry::RegistryFreshness`] and additionally carries
/// the host platform actually observed at the call site, so the support
/// check reads a machine value instead of guessing from the build target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityInputs<'a> {
    /// Required registry generation.
    pub generation: u64,
    /// Required normative-pair digest.
    pub normative_pair_digest: &'a str,
    /// Required invalidation fingerprints.
    pub fingerprints: &'a InvalidationSet,
    /// Platform observed on this host.
    pub platform: &'a str,
}

impl crate::registry::ProviderRegistry {
    /// Resolves one invocation to a typed availability result.
    ///
    /// Runs the full pre-execution closure in order: exactly-one-entry
    /// resolution (missing, duplicate, ambiguous, unsupported), generation
    /// and fingerprint freshness, then the host support check. Every
    /// rejection happens before any process or build allocation and returns
    /// [`ProviderAvailability::Unavailable`] with a typed
    /// [`ProviderDisposition`] instead of an error, so an unsupported
    /// provider stays in the denominator and is never silently dropped.
    #[must_use]
    pub fn availability(
        &self,
        invocation: &eliot_instrument_api::InstrumentInvocation,
        inputs: &AvailabilityInputs<'_>,
    ) -> ProviderAvailability {
        self.availability_parts(&invocation.instrument, invocation.kind, inputs)
    }

    /// The same closure as [`ProviderRegistry::availability`] over an
    /// admitted `(instrument, kind)` pair instead of a full invocation.
    ///
    /// Classification-only callers (the governed describe path and the
    /// stage orchestrator) hold no invocation authority material — no State
    /// Fence, session, or lease — and must not fabricate it to ask a
    /// readiness question. The closure is identical: resolution, freshness,
    /// then host support.
    #[must_use]
    pub fn availability_parts(
        &self,
        instrument: &ContractId,
        kind: InstrumentKind,
        inputs: &AvailabilityInputs<'_>,
    ) -> ProviderAvailability {
        let freshness = crate::registry::RegistryFreshness {
            generation: inputs.generation,
            normative_pair_digest: inputs.normative_pair_digest,
            fingerprints: inputs.fingerprints,
        };
        let name = instrument.as_str();
        let entry = match self.resolve_current_parts(instrument, kind, &freshness) {
            Ok(entry) => entry.clone(),
            Err(error) => {
                return ProviderAvailability::Unavailable {
                    disposition: disposition_for_parts(name, kind, &error),
                };
            }
        };
        match support_platform(&entry) {
            Some(required) if required != inputs.platform => ProviderAvailability::Unavailable {
                disposition: ProviderDisposition::UnsupportedPlatform {
                    required: required.to_owned(),
                    observed: inputs.platform.to_owned(),
                },
            },
            _ => ProviderAvailability::Ready {
                entry: Box::new(entry),
            },
        }
    }
}

/// Maps one registry failure to its typed provider disposition.
///
/// Every [`RegistryError`] variant has exactly one disposition, so a
/// missing, duplicate, stale, ambiguous, or unsupported mapping is always
/// reported as a named cause and never collapses into a generic refusal.
/// The match is exhaustive: a future variant fails to compile here rather
/// than defaulting to a silent pass-through.
#[must_use]
pub fn disposition_for_parts(
    instrument: &str,
    kind: InstrumentKind,
    error: &crate::registry::RegistryError,
) -> ProviderDisposition {
    match error {
        // An instrument nobody maps is unmapped, not missing: the provider
        // stays inside the declared denominator either way.
        crate::registry::RegistryError::Missing { .. } => ProviderDisposition::Unmapped,
        crate::registry::RegistryError::Duplicate { instrument } => {
            ProviderDisposition::Ambiguous {
                instrument: instrument.clone(),
                kind,
                candidates: 2,
            }
        }
        crate::registry::RegistryError::Unsupported { adapter, kind } => {
            ProviderDisposition::Unsupported {
                adapter: adapter.clone(),
                kind: *kind,
            }
        }
        crate::registry::RegistryError::Ambiguous {
            instrument,
            kind,
            candidates,
        } => ProviderDisposition::Ambiguous {
            instrument: instrument.clone(),
            kind: *kind,
            candidates: *candidates,
        },
        crate::registry::RegistryError::Stale { reason, .. } => {
            ProviderDisposition::Stale { reason: *reason }
        }
        crate::registry::RegistryError::UnresolvedExecutable { reason, .. } => {
            ProviderDisposition::Unavailable {
                rule: format!("{instrument}: {reason}"),
            }
        }
        crate::registry::RegistryError::ExecutableMismatch { instrument, .. } => {
            ProviderDisposition::Unavailable {
                rule: format!("{instrument}: executable identity mismatch"),
            }
        }
        crate::registry::RegistryError::Contract(inner) => ProviderDisposition::Unavailable {
            rule: format!("registry contract: {inner}"),
        },
        crate::registry::RegistryError::Disposition(inner) => ProviderDisposition::Unavailable {
            rule: format!("registry disposition: {inner}"),
        },
        crate::registry::RegistryError::TestdDispatch(inner) => ProviderDisposition::Unavailable {
            rule: format!("testd dispatch: {inner}"),
        },
        crate::registry::RegistryError::IdentitySlotBlank { instrument, .. }
        | crate::registry::RegistryError::IdentitySlotDrift { instrument, .. } => {
            ProviderDisposition::Unavailable {
                rule: format!("{instrument}: profile identity slot is unbound or drifted"),
            }
        }
    }
}

/// Platform an entry requires, or `None` when it is host-neutral.
///
/// The single governed process plane is the Windows `ProcessExecutor`
/// (I10.8.1: "one Windows `ProcessExecutor` semantics"), so every entry that
/// launches a process is Windows-only. The decoder-only SCIP entry owns no
/// process path and is therefore host-neutral. The value is read from the
/// recorded environment class rather than from a crate name.
fn support_platform(entry: &RegistryEntry) -> Option<&'static str> {
    const GOVERNED_PROCESS_ENVIRONMENT: &str = "isolated-process";
    (entry.environment_class == GOVERNED_PROCESS_ENVIRONMENT).then_some("windows")
}

/// One conformance corpus case bound to an exact provider identity.
///
/// The corpus is shared across providers (work item 8): every case names
/// the provider it exercises, the instrument class it drives, and whether
/// the case is expected to be dispatchable. A case whose provider is
/// unavailable still runs — it must produce an unavailable disposition,
/// never a pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCase {
    /// Stable case identity, unique inside its corpus.
    pub case_id: String,
    /// Provider contract identity the case exercises.
    pub instrument: String,
    /// Instrument class the case drives.
    pub kind: InstrumentKind,
    /// Whether this host is expected to dispatch the provider.
    pub expected_dispatchable: bool,
    /// Whether the case exercises a real installed tool.
    pub real_execution: bool,
}

impl ConformanceCase {
    /// Fails closed on a malformed case identity.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::InvalidText`] when the case identity or
    /// instrument name is blank or carries control characters.
    pub fn validate(&self) -> Result<(), ConformanceError> {
        for (field, value) in [
            ("case_id", self.case_id.as_str()),
            ("instrument", self.instrument.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ConformanceError::InvalidText { field });
            }
        }
        Ok(())
    }
}

/// Failures raised by the conformance and fixture contracts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConformanceError {
    /// A required text value is blank or carries a control character.
    #[error("conformance {field} must be non-blank and control-free")]
    InvalidText {
        /// Offending field.
        field: &'static str,
    },
    /// Two cases claim the same identity inside one corpus.
    #[error("duplicate conformance case '{case_id}'")]
    DuplicateCase {
        /// Conflicting case identity.
        case_id: String,
    },
    /// A case names a provider outside the advertised provider set.
    #[error("conformance case '{case_id}' names unknown provider '{instrument}'")]
    UnknownProvider {
        /// Offending case identity.
        case_id: String,
        /// Unknown instrument contract name.
        instrument: String,
    },
    /// An advertised denominator provider has no case in the common corpus.
    #[error("conformance corpus has no case for advertised provider '{instrument}'")]
    MissingProvider {
        /// Advertised instrument contract name absent from the corpus.
        instrument: String,
    },
    /// A corpus case expects dispatch when its provider/class is unavailable.
    #[error("conformance case expects unavailable provider '{instrument}' to dispatch")]
    UnavailableProvider {
        /// Advertised instrument contract name with no registry entry.
        instrument: String,
    },
    /// The denominator was derived from a different registry identity.
    #[error("conformance denominator does not match registry provider '{instrument}'")]
    RegistryMismatch {
        /// Provider whose mapped entry or declared ownership differs.
        instrument: String,
    },
    /// The corpus dispatch expectation disagrees with current typed availability.
    #[error(
        "conformance case for '{instrument}' expects dispatchable={expected}, current availability is {actual}"
    )]
    DispatchabilityMismatch {
        /// Provider whose expected dispatchability differs.
        instrument: String,
        /// Dispatchability declared by the corpus case.
        expected: bool,
        /// Dispatchability resolved from the registry and current inputs.
        actual: bool,
    },
    /// The corpus or fixture set was written for another registry identity.
    #[error("conformance corpus is bound to generation {expected}, registry is at {found}")]
    StaleGeneration {
        /// Generation the corpus was written for.
        expected: u64,
        /// Generation the current registry reports.
        found: u64,
    },
    /// One invalidation slot moved since the corpus was written.
    #[error("conformance corpus {field} fingerprint moved")]
    StaleFingerprint {
        /// Fingerprint slot that moved.
        field: FingerprintField,
    },
    /// The normative-pair digest moved since the corpus was written.
    #[error("conformance corpus normative-pair digest moved")]
    StaleNormativePair,
}

/// The identity a shared conformance corpus is bound to.
///
/// Reuse is identity-bound (I2.22): a corpus is valid only for the exact
/// provider registry generation and invalidation set it was written
/// against. Moving any slot — source, lock, toolchain, environment,
/// executable, profile, or parser — invalidates it instead of letting a
/// stale corpus vouch for rebuilt adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCorpus {
    /// Corpus identity, unique in the repository.
    pub corpus_id: String,
    /// Registry generation this corpus was written against.
    pub generation: u64,
    /// Normative-pair digest this corpus was written against.
    pub normative_pair_digest: String,
    /// Invalidation fingerprints this corpus was written against.
    pub fingerprints: InvalidationSet,
    /// The shared cases, one per provider identity.
    pub cases: Vec<ConformanceCase>,
}

impl ConformanceCorpus {
    /// Validates the corpus shape and its binding to the current registry.
    ///
    /// Every independently declared provider identity must have a case,
    /// including identities deliberately left unmapped. The supplied
    /// denominator must be exactly the one derived from this registry, and
    /// each case's expected dispatchability must match the current typed
    /// availability for its declared instrument kind.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::InvalidText`],
    /// [`ConformanceError::DuplicateCase`],
    /// [`ConformanceError::UnknownProvider`],
    /// [`ConformanceError::MissingProvider`],
    /// [`ConformanceError::UnavailableProvider`],
    /// [`ConformanceError::RegistryMismatch`],
    /// [`ConformanceError::DispatchabilityMismatch`],
    /// [`ConformanceError::StaleGeneration`],
    /// [`ConformanceError::StaleNormativePair`], or
    /// [`ConformanceError::StaleFingerprint`].
    pub fn validate(
        &self,
        registry: &crate::registry::ProviderRegistry,
        denominator: &ProviderDenominator,
    ) -> Result<(), ConformanceError> {
        const CORPUS_FIELD: &str = "corpus_id";
        if self.corpus_id.trim().is_empty() || self.corpus_id.chars().any(char::is_control) {
            return Err(ConformanceError::InvalidText {
                field: CORPUS_FIELD,
            });
        }
        if self.cases.is_empty() {
            return Err(ConformanceError::InvalidText { field: "cases" });
        }
        if self.generation != registry.generation() {
            return Err(ConformanceError::StaleGeneration {
                expected: self.generation,
                found: registry.generation(),
            });
        }
        if denominator.generation() != registry.generation() {
            return Err(ConformanceError::StaleGeneration {
                expected: self.generation,
                found: denominator.generation(),
            });
        }
        if self.normative_pair_digest != registry.normative_pair_digest() {
            return Err(ConformanceError::StaleNormativePair);
        }
        for entry in registry {
            if let Some(field) = self.fingerprints.mismatch(&entry.invalidation) {
                return Err(ConformanceError::StaleFingerprint { field });
            }
        }
        validate_current_denominator(registry, denominator)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut covered = std::collections::BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !seen.insert(case.case_id.clone()) {
                return Err(ConformanceError::DuplicateCase {
                    case_id: case.case_id.clone(),
                });
            }
            if !declared_instruments().any(|advertised| advertised.contract == case.instrument) {
                return Err(ConformanceError::UnknownProvider {
                    case_id: case.case_id.clone(),
                    instrument: case.instrument.clone(),
                });
            }
            let instrument = denominator
                .entry(&case.instrument)
                .map(|entry| entry.instrument.clone())
                .or_else(|| ContractId::new(&case.instrument).ok());
            let actual_dispatchable = instrument.is_some_and(|instrument| {
                registry
                    .availability_parts(
                        &instrument,
                        case.kind,
                        &AvailabilityInputs {
                            generation: self.generation,
                            normative_pair_digest: &self.normative_pair_digest,
                            fingerprints: &self.fingerprints,
                            platform: host_platform(),
                        },
                    )
                    .is_available()
            });
            if case.expected_dispatchable && !actual_dispatchable {
                return Err(ConformanceError::UnavailableProvider {
                    instrument: case.instrument.clone(),
                });
            }
            if !case.expected_dispatchable && actual_dispatchable {
                return Err(ConformanceError::DispatchabilityMismatch {
                    instrument: case.instrument.clone(),
                    expected: false,
                    actual: true,
                });
            }
            covered.insert(case.instrument.as_str());
        }
        for advertised in declared_instruments() {
            if !covered.contains(advertised.contract) {
                return Err(ConformanceError::MissingProvider {
                    instrument: advertised.contract.to_owned(),
                });
            }
        }
        Ok(())
    }
}

fn validate_current_denominator(
    registry: &crate::registry::ProviderRegistry,
    denominator: &ProviderDenominator,
) -> Result<(), ConformanceError> {
    let current_denominator =
        ProviderDenominator::current(registry).map_err(|_| ConformanceError::RegistryMismatch {
            instrument: "<registry-denominator>".to_owned(),
        })?;
    if denominator != &current_denominator {
        let instrument = declared_instruments()
            .find(|advertised| {
                denominator.entry(advertised.contract)
                    != current_denominator.entry(advertised.contract)
                    || denominator.owner(advertised.contract)
                        != current_denominator.owner(advertised.contract)
            })
            .map_or_else(
                || "<registry-denominator>".to_owned(),
                |row| row.contract.to_owned(),
            );
        return Err(ConformanceError::RegistryMismatch { instrument });
    }
    Ok(())
}

/// Real-execution fixture set bound to one provider identity.
///
/// A provider-specific fixture records the installed executable identity
/// and the exact argv/environment a real run must reproduce. A provider
/// that cannot be observed on this host contributes no fixture, and the
/// provider stays in the declared denominator as
/// [`ProviderDisposition::Unavailable`] rather than disappearing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFixtureSet {
    /// Provider contract identity these fixtures exercise.
    pub instrument: String,
    /// Registry generation the fixtures were captured against.
    pub generation: u64,
    /// Invalidation fingerprints the fixtures were captured against.
    pub fingerprints: InvalidationSet,
    /// Exact real-execution case identifiers for this provider.
    pub real_cases: Vec<String>,
}

impl ProviderFixtureSet {
    /// Validates the fixture set against the owning entry.
    ///
    /// The set must name the entry's own instrument and be bound to its
    /// exact invalidation set, so a moved source, lock, toolchain,
    /// environment, executable, profile, or parser slot invalidates the
    /// fixtures instead of letting them re-certify a changed adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ConformanceError::InvalidText`] for a blank identity or
    /// malformed real case identity, [`ConformanceError::DuplicateCase`] for
    /// repeated real case identities, or
    /// [`ConformanceError::StaleGeneration`] /
    /// [`ConformanceError::StaleFingerprint`] when the binding moved.
    pub fn validate(&self, entry: &RegistryEntry) -> Result<(), ConformanceError> {
        if self.instrument.trim().is_empty() || self.instrument.chars().any(char::is_control) {
            return Err(ConformanceError::InvalidText {
                field: "instrument",
            });
        }
        if entry.instrument.as_str() != self.instrument {
            return Err(ConformanceError::UnknownProvider {
                case_id: self.instrument.clone(),
                instrument: self.instrument.clone(),
            });
        }
        if self.real_cases.is_empty() {
            return Err(ConformanceError::InvalidText {
                field: "real_cases",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for case_id in &self.real_cases {
            if case_id.trim().is_empty() || case_id.chars().any(char::is_control) {
                return Err(ConformanceError::InvalidText { field: "real_case" });
            }
            if !seen.insert(case_id) {
                return Err(ConformanceError::DuplicateCase {
                    case_id: case_id.clone(),
                });
            }
        }
        if self.generation != entry.generation {
            return Err(ConformanceError::StaleGeneration {
                expected: self.generation,
                found: entry.generation,
            });
        }
        if let Some(field) = entry.invalidation.mismatch(&self.fingerprints) {
            return Err(ConformanceError::StaleFingerprint { field });
        }
        Ok(())
    }
}
