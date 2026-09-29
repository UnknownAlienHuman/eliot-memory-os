//! Product-code disposition ledger for the Instrument Plane package family.
//!
//! Issue #1140 requires exactly one disposition for every package named in the
//! Instrument Plane audit: a live Testd profile, a bounded fixture carrying an
//! expiry and a removal condition, or deletion. This module is the single
//! product-code ledger; it grants no execution, parser, verifier, task, budget,
//! or canonical-store authority and creates no process.
//!
//! The completeness check compares the recorded dispositions against
//! [`INSTRUMENT_PACKAGE_FAMILY`], a member list declared in this module, and
//! never against a caller-supplied set or a second copy of the recorded rows.
//! Every other comparison is against content the caller does not control: live
//! profiles are compared against the entries the assembled
//! [`ProviderRegistry`](crate::registry::ProviderRegistry) actually holds, a
//! library surface must *not* be claimed by a registry entry, a non-dispatchable
//! package must not appear in [`TESTD_PROFILE_UNIVERSE`], and a bounded fixture
//! expiry is compared against [`DISPOSITION_REVIEWED_ON`], so a fixture that
//! has passed its recorded review date fails closed.
//!
//! [`ProviderRegistry::ready`](crate::registry::ProviderRegistry::ready) runs
//! [`verify_disposition_coverage`], so no provider registry can be assembled
//! while a family member is unrecorded, a recorded live profile is missing
//! from the registry, a bounded fixture is dispatchable, or a bounded fixture
//! has expired.

use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;

use crate::registry::ProviderRegistry;

/// Independent expected member set for the Instrument Plane package family.
///
/// This is the completeness authority for the ledger: every member must carry
/// exactly one disposition and no disposition may name a package outside this
/// set.
pub const INSTRUMENT_PACKAGE_FAMILY: [&str; 17] = [
    "eliot-artifact",
    "eliot-build-test-graph",
    "eliot-code-cortex",
    "eliot-code-graph",
    "eliot-diagnostic",
    "eliot-empirical-profile",
    "eliot-instrument-cargo",
    "eliot-instrument-dotnet",
    "eliot-instrument-nextest",
    "eliot-instrument-rustc",
    "eliot-instrument-rustfmt",
    "eliot-instrument-scip",
    "eliot-observability",
    "eliot-product-evaluation",
    "eliot-reports",
    "eliot-test-selection",
    "eliot-verifier",
];

/// The closed set of Testd profile identities a retained package may bind.
///
/// A package that is not dispatchable (bounded fixture or deleted) must not
/// name any member of this universe.
pub const TESTD_PROFILE_UNIVERSE: [&str; 12] = [
    "eliot.instrument.build-test-graph",
    "eliot.instrument.cargo",
    "eliot.instrument.diagnostic",
    "eliot.instrument.dotnet.msbuild",
    "eliot.instrument.nextest",
    "eliot.instrument.observability",
    "eliot.instrument.product-evaluation",
    "eliot.instrument.rustc",
    "eliot.instrument.rustfmt",
    "eliot.instrument.scip",
    "eliot.instrument.test-selection",
    "eliot.instrument.verifier",
];

/// The closed set of workspace crates that may hold a live instrument consumer.
pub const CONSUMER_CRATE_UNIVERSE: [&str; 8] = [
    "eliot-engine",
    "eliot-governor",
    "eliot-instrument-runner",
    "eliot-kernel",
    "eliot-lsp-bridge",
    "eliot-testd-core",
    "eliot-verifier",
    "eliotd",
];

/// The closed set of capability owners a retained package may resolve to.
pub const CAPABILITY_OWNER_UNIVERSE: [&str; 6] = [
    "eliot-engine::cached_derivation",
    "eliot-governor::composition",
    "eliot-instrument-runner::cache_lane",
    "eliot-instrument-runner::dev_fast",
    "eliot-instrument-runner::registry",
    "eliotd::maintenance",
];

/// The closed set of state owners, including explicit statelessness.
pub const STATE_OWNER_UNIVERSE: [&str; 3] = [
    "eliot-build-test-graph::DerivedCacheStore",
    "eliot-testd-core::claim",
    "stateless",
];

/// The closed proof-ceiling vocabulary recorded per package.
pub const PROOF_CEILING_UNIVERSE: [&str; 2] = [
    "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
    "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
];

/// The date this ledger was last reviewed against its bounded-fixture expiries.
///
/// Expiries are ISO-8601 dates, so a bounded fixture whose recorded expiry is
/// on or before this date has passed its review and fails closed. Advancing
/// this date is a review action: it never un-expires a fixture silently,
/// because the expiry is recorded per package in
/// [`PACKAGE_DISPOSITIONS`].
pub const DISPOSITION_REVIEWED_ON: &str = "2026-09-29";

/// The one disposition a retained Instrument Plane package may carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageRoute {
    /// Executed through a live Testd profile; the recorded Testd profile must
    /// be claimed by an entry of the assembled provider registry.
    LiveTestdProfile,
    /// Admitted into the Testd execution graph as a library surface; the
    /// recorded Testd profile identifies the lane it serves and must not be
    /// claimed by a registry executable entry.
    LiveLibrarySurface,
    /// Retained only as a bounded fixture: no live consumer, no Testd profile,
    /// and a recorded expiry compared against [`DISPOSITION_REVIEWED_ON`].
    BoundedFixture,
    /// Deleted; the name may appear in no Testd profile and no live consumer.
    Deleted,
}

/// The execution contour a package is permitted to declare.
///
/// A contour is a claim about where a process could be created. It is compared
/// against the route, and for a live Testd profile it is further compared
/// against the decoder-only classification the registry actually holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContour {
    /// The only contour permitted to create a child process, and only through
    /// the governed `ProcessExecutor` owned outside this subtree.
    GovernedProcessExecutor,
    /// Reads emitted artifacts and decodes them; never creates a process.
    DecoderOnly,
    /// Owns no process path at all.
    NoExecution,
}

/// One recorded disposition field, used so a rejected row names the field that
/// failed rather than only the package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispositionField {
    /// The package contract identity.
    Contract,
    /// The Testd profile identity the package binds.
    TestdProfile,
    /// The workspace crate holding the live consumer.
    LiveConsumer,
    /// The `FunctionalCapabilityCell` owner.
    CapabilityOwner,
    /// The mutable-state owner, or explicit statelessness.
    StateOwner,
    /// The proof entrypoint symbol.
    ProofEntrypoint,
    /// The proof ceiling.
    ProofCeiling,
    /// The removal boundary.
    RemovalBoundary,
    /// The bounded-fixture expiry.
    FixtureExpiry,
}

impl fmt::Display for DispositionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Contract => "contract",
            Self::TestdProfile => "testd profile",
            Self::LiveConsumer => "live consumer",
            Self::CapabilityOwner => "capability owner",
            Self::StateOwner => "state owner",
            Self::ProofEntrypoint => "proof entrypoint",
            Self::ProofCeiling => "proof ceiling",
            Self::RemovalBoundary => "removal boundary",
            Self::FixtureExpiry => "fixture expiry",
        })
    }
}

/// One recorded Instrument Plane package disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageDispositionRecord {
    /// Workspace package name, a member of [`INSTRUMENT_PACKAGE_FAMILY`].
    pub package: &'static str,
    /// The single disposition assigned to the package.
    pub route: PackageRoute,
    /// The execution contour the package is permitted to declare.
    pub execution_contour: ExecutionContour,
    /// The Testd profile identity; empty for a non-dispatchable package.
    pub testd_profile: &'static str,
    /// The workspace crate holding the live consumer; empty when none exists.
    pub live_consumer: &'static str,
    /// The `FunctionalCapabilityCell` owner.
    pub capability_owner: &'static str,
    /// The mutable-state owner, or `stateless`.
    pub state_owner: &'static str,
    /// The package contract identity.
    pub contract: &'static str,
    /// The proof entrypoint as a `path.rs::symbol` anchor.
    pub proof_entrypoint: &'static str,
    /// The proof ceiling this disposition can reach.
    pub proof_ceiling: &'static str,
    /// The condition under which the package may be removed.
    pub removal_boundary: &'static str,
    /// Bounded-fixture expiry; present only for [`PackageRoute::BoundedFixture`].
    pub fixture_expiry: Option<&'static str>,
}

/// The recorded disposition of every member of [`INSTRUMENT_PACKAGE_FAMILY`].
///
/// Twelve packages carry a live route: six executable/decoder profiles claimed
/// by the provider registry and six library surfaces admitted into the Testd
/// execution graph. Five packages have no production consumer at all and are
/// retained as bounded fixtures with a recorded expiry and removal condition.
/// No package is deleted in this ledger.
pub const PACKAGE_DISPOSITIONS: [PackageDispositionRecord; 17] = [
    PackageDispositionRecord {
        package: "eliot-build-test-graph",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.build-test-graph",
        live_consumer: "eliot-testd-core",
        capability_owner: "eliot-instrument-runner::cache_lane",
        state_owner: "eliot-build-test-graph::DerivedCacheStore",
        contract: "eliot.instrument.build-test-graph",
        proof_entrypoint:
            "crates/eliot-engine/src/cached_derivation.rs::CachedDerivationService::derive_governed",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after every recorded consumer migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-diagnostic",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.diagnostic",
        live_consumer: "eliot-governor",
        capability_owner: "eliot-governor::composition",
        state_owner: "stateless",
        contract: "eliot.instrument.diagnostic",
        proof_entrypoint: "crates/instrument/eliot-instrument-runner/src/registry.rs::diagnostic_id",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after every recorded consumer migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-cargo",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::GovernedProcessExecutor,
        testd_profile: "eliot.instrument.cargo",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.cargo",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the governed build lane migrates off the cargo port and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-dotnet",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::GovernedProcessExecutor,
        testd_profile: "eliot.instrument.dotnet.msbuild",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.dotnet.msbuild",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the .NET denominator entry is withdrawn from ProviderRegistry::ready and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-nextest",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::GovernedProcessExecutor,
        testd_profile: "eliot.instrument.nextest",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.nextest",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the current verification lane migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-rustc",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::GovernedProcessExecutor,
        testd_profile: "eliot.instrument.rustc",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.rustc",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the governed build lane migrates off the rustc adapter and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-rustfmt",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::GovernedProcessExecutor,
        testd_profile: "eliot.instrument.rustfmt",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.rustfmt",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the format lane migrates off the rustfmt adapter and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-instrument-scip",
        route: PackageRoute::LiveTestdProfile,
        execution_contour: ExecutionContour::DecoderOnly,
        testd_profile: "eliot.instrument.scip",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.scip",
        proof_entrypoint:
            "crates/instrument/eliot-instrument-runner/src/registry.rs::ProviderRegistry::resolve_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the code-intelligence adapter migrates off the decoder and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-observability",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.observability",
        live_consumer: "eliot-engine",
        capability_owner: "eliot-engine::cached_derivation",
        state_owner: "stateless",
        contract: "eliot.instrument.observability",
        proof_entrypoint: "crates/eliot-engine/src/cached_derivation.rs::CachedDerivationService::publish_governed",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after every recorded consumer migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-product-evaluation",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.product-evaluation",
        live_consumer: "eliotd",
        capability_owner: "eliotd::maintenance",
        state_owner: "stateless",
        contract: "eliot.instrument.product-evaluation",
        proof_entrypoint: "bins/eliotd/src/campaign_evaluation_owner.rs::build_product_evaluation_publications",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after the campaign evaluation owner migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-test-selection",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.test-selection",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::dev_fast",
        state_owner: "eliot-testd-core::claim",
        contract: "eliot.instrument.test-selection",
        proof_entrypoint: "crates/instrument/eliot-instrument-runner/src/dev_fast.rs::dev_fast_disposition",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after frozen-selection admission migrates and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-verifier",
        route: PackageRoute::LiveLibrarySurface,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "eliot.instrument.verifier",
        live_consumer: "eliot-instrument-runner",
        capability_owner: "eliot-instrument-runner::registry",
        state_owner: "stateless",
        contract: "eliot.instrument.verifier",
        proof_entrypoint: "crates/eliot-engine/src/verification/current.rs::run_current",
        proof_ceiling: "INSTRUMENT_PROFILE_GRAPH_CANDIDATE",
        removal_boundary:
            "delete only after evaluation migrates to another admitted verifier and no Cargo, feature, route, documentation or test reference remains",
        fixture_expiry: None,
    },
    PackageDispositionRecord {
        package: "eliot-artifact",
        route: PackageRoute::BoundedFixture,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "",
        live_consumer: "",
        capability_owner: "eliot-instrument-runner::cache_lane",
        state_owner: "stateless",
        contract: "eliot.instrument.artifact",
        proof_entrypoint: "NOT_EXECUTED: no live consumer exists for this package",
        proof_ceiling: "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
        removal_boundary: "delete the workspace member on or after the recorded expiry; no consumer migration is required because no consumer exists",
        fixture_expiry: Some("2026-12-31"),
    },
    PackageDispositionRecord {
        package: "eliot-code-cortex",
        route: PackageRoute::BoundedFixture,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "",
        live_consumer: "",
        capability_owner: "eliot-instrument-runner::dev_fast",
        state_owner: "stateless",
        contract: "eliot.instrument.code-cortex",
        proof_entrypoint: "NOT_EXECUTED: no live consumer exists for this package",
        proof_ceiling: "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
        removal_boundary: "delete the workspace member on or after the recorded expiry; no consumer migration is required because no consumer exists",
        fixture_expiry: Some("2026-12-31"),
    },
    PackageDispositionRecord {
        package: "eliot-code-graph",
        route: PackageRoute::BoundedFixture,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "",
        live_consumer: "",
        capability_owner: "eliot-instrument-runner::dev_fast",
        state_owner: "stateless",
        contract: "eliot.instrument.code-graph",
        proof_entrypoint: "NOT_EXECUTED: no live consumer exists for this package",
        proof_ceiling: "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
        removal_boundary: "delete the workspace member on or after the recorded expiry; no consumer migration is required because no consumer exists",
        fixture_expiry: Some("2026-12-31"),
    },
    PackageDispositionRecord {
        package: "eliot-empirical-profile",
        route: PackageRoute::BoundedFixture,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "",
        live_consumer: "",
        capability_owner: "eliot-instrument-runner::dev_fast",
        state_owner: "stateless",
        contract: "eliot.instrument.empirical-profile",
        proof_entrypoint: "NOT_EXECUTED: no live consumer exists for this package",
        proof_ceiling: "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
        removal_boundary: "delete the workspace member on or after the recorded expiry; no consumer migration is required because no consumer exists",
        fixture_expiry: Some("2026-12-31"),
    },
    PackageDispositionRecord {
        package: "eliot-reports",
        route: PackageRoute::BoundedFixture,
        execution_contour: ExecutionContour::NoExecution,
        testd_profile: "",
        live_consumer: "",
        capability_owner: "eliot-instrument-runner::cache_lane",
        state_owner: "stateless",
        contract: "eliot.instrument.reports",
        proof_entrypoint: "NOT_EXECUTED: no live consumer exists for this package",
        proof_ceiling: "CONFIRMED_INSTRUMENT_PACKAGE_CONSUMER_GAP / NOT_EXECUTED",
        removal_boundary: "delete the workspace member on or after the recorded expiry; no consumer migration is required because no consumer exists",
        fixture_expiry: Some("2026-12-31"),
    },
];

/// Why a recorded Instrument Plane disposition was rejected.
///
/// Every variant is typed and fail-closed: no stringly-typed catch-all drives
/// control flow, and no variant reports success.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DispositionError {
    /// A family member carries no recorded disposition.
    #[error("instrument package '{package}' has no recorded disposition")]
    MissingRecord {
        /// Family member with no recorded disposition.
        package: &'static str,
    },
    /// A disposition names a package outside the family.
    #[error("recorded disposition '{package}' is not a member of the instrument package family")]
    UnlistedRecord {
        /// Recorded package name outside the family.
        package: &'static str,
    },
    /// A package carries more than one recorded disposition.
    #[error("instrument package '{package}' carries a duplicate disposition row")]
    DuplicateRecord {
        /// Duplicated package name.
        package: &'static str,
    },
    /// A required field is blank.
    #[error("instrument package '{package}' leaves its {field} blank")]
    BlankField {
        /// Recorded package name.
        package: &'static str,
        /// The field that is blank.
        field: DispositionField,
    },
    /// A field names a value outside its declared closed universe.
    #[error("instrument package '{package}' records {field} '{value}', which is outside the closed universe")]
    FieldOutsideUniverse {
        /// Recorded package name.
        package: &'static str,
        /// The field that failed.
        field: DispositionField,
        /// The rejected value.
        value: &'static str,
    },
    /// A live Testd profile is claimed by no registry entry.
    #[error("instrument package '{package}' is a live testd profile but no registry entry claims '{profile}'")]
    UnregisteredLiveProfile {
        /// Recorded package name.
        package: &'static str,
        /// The unclaimed Testd profile identity.
        profile: &'static str,
    },
    /// A library surface is claimed by a registry executable entry.
    #[error("instrument package '{package}' is a library surface but registry entry '{profile}' claims it as an executable profile")]
    RegisteredLibrarySurface {
        /// Recorded package name.
        package: &'static str,
        /// The claimed Testd profile identity.
        profile: &'static str,
    },
    /// The recorded contour disagrees with the registry entry it binds.
    #[error("instrument package '{package}' records a contour that contradicts registry entry '{profile}'")]
    ContourMismatch {
        /// Recorded package name.
        package: &'static str,
        /// The Testd profile identity whose entry disagrees.
        profile: &'static str,
    },
    /// A live package records a bounded-fixture expiry it may not hold.
    #[error("instrument package '{package}' records a bounded-fixture expiry under a live route")]
    LiveRouteCarriesExpiry {
        /// Recorded package name.
        package: &'static str,
    },
    /// A bounded fixture records no expiry.
    #[error("instrument package '{package}' is a bounded fixture but records no expiry")]
    MissingFixtureExpiry {
        /// Recorded package name.
        package: &'static str,
    },
    /// A bounded fixture passed its recorded review date.
    #[error("instrument package '{package}' expired at {expiry}; ledger reviewed {reviewed_on}")]
    FixtureExpired {
        /// Recorded package name.
        package: &'static str,
        /// The recorded ISO-8601 expiry.
        expiry: &'static str,
        /// The ledger review date the expiry was compared against.
        reviewed_on: &'static str,
    },
    /// A non-dispatchable package names a Testd profile.
    #[error("instrument package '{package}' is not dispatchable but names testd profile '{profile}'")]
    NonDispatchableProfile {
        /// Recorded package name.
        package: &'static str,
        /// The rejected Testd profile identity.
        profile: &'static str,
    },
    /// A bounded fixture or deleted package names a live consumer.
    #[error("instrument package '{package}' is not dispatchable but names live consumer '{consumer}'")]
    UnexpectedLiveConsumer {
        /// Recorded package name.
        package: &'static str,
        /// The rejected consumer crate.
        consumer: &'static str,
    },
    /// The declared contour is not permitted for the declared route.
    #[error("instrument package '{package}' may not declare this contour under route {route:?}")]
    ContourNotPermitted {
        /// Recorded package name.
        package: &'static str,
        /// The recorded route.
        route: PackageRoute,
        /// The rejected execution contour.
        contour: ExecutionContour,
    },
}

/// Verifies the recorded Instrument Plane dispositions against the assembled
/// provider registry.
///
/// The check is deliberately fail-closed and content-comparing: member
/// coverage is compared against [`INSTRUMENT_PACKAGE_FAMILY`], closed-field
/// membership against the declared universes in this module, live and library
/// routes against the entries the registry actually holds, and bounded-fixture
/// expiries against [`DISPOSITION_REVIEWED_ON`].
///
/// # Errors
///
/// Returns the first [`DispositionError`] for an unrecorded family member, a
/// duplicate or unlisted row, a blank or out-of-universe field, a live profile
/// the registry does not claim, a library surface the registry does claim, a
/// contour that contradicts the route or the registry entry, a non-dispatchable
/// package that names a Testd profile or a live consumer, or an expired bounded
/// fixture.
pub fn verify_disposition_coverage(registry: &ProviderRegistry) -> Result<(), DispositionError> {
    verify_member_coverage()?;
    for record in PACKAGE_DISPOSITIONS {
        verify_route(record)?;
        verify_contour(record)?;
    }
    verify_registry_routes(registry)
}

/// Compares the recorded rows against the independently declared family list.
fn verify_member_coverage() -> Result<(), DispositionError> {
    let family: BTreeSet<&'static str> = INSTRUMENT_PACKAGE_FAMILY.into_iter().collect();
    let mut recorded: BTreeSet<&'static str> = BTreeSet::new();
    for record in PACKAGE_DISPOSITIONS {
        if !family.contains(record.package) {
            return Err(DispositionError::UnlistedRecord {
                package: record.package,
            });
        }
        if !recorded.insert(record.package) {
            return Err(DispositionError::DuplicateRecord {
                package: record.package,
            });
        }
    }
    for package in family {
        if !recorded.contains(package) {
            return Err(DispositionError::MissingRecord { package });
        }
    }
    Ok(())
}

/// Dispatches one row to the check its route requires.
fn verify_route(record: PackageDispositionRecord) -> Result<(), DispositionError> {
    match record.route {
        PackageRoute::LiveTestdProfile | PackageRoute::LiveLibrarySurface => {
            verify_live_record(record)
        }
        PackageRoute::BoundedFixture => verify_bounded_fixture(record),
        PackageRoute::Deleted => verify_deleted(record),
    }
}

/// Fields every live route must resolve, compared against the closed universes.
fn verify_live_record(record: PackageDispositionRecord) -> Result<(), DispositionError> {
    if record.fixture_expiry.is_some() {
        return Err(DispositionError::LiveRouteCarriesExpiry {
            package: record.package,
        });
    }
    require_member(
        record.contract,
        &TESTD_PROFILE_UNIVERSE,
        record.package,
        DispositionField::Contract,
    )?;
    require_member(
        record.testd_profile,
        &TESTD_PROFILE_UNIVERSE,
        record.package,
        DispositionField::TestdProfile,
    )?;
    require_member(
        record.live_consumer,
        &CONSUMER_CRATE_UNIVERSE,
        record.package,
        DispositionField::LiveConsumer,
    )?;
    require_member(
        record.capability_owner,
        &CAPABILITY_OWNER_UNIVERSE,
        record.package,
        DispositionField::CapabilityOwner,
    )?;
    require_member(
        record.state_owner,
        &STATE_OWNER_UNIVERSE,
        record.package,
        DispositionField::StateOwner,
    )?;
    require_member(
        record.proof_ceiling,
        &PROOF_CEILING_UNIVERSE,
        record.package,
        DispositionField::ProofCeiling,
    )?;
    require_text(
        record.proof_entrypoint,
        record.package,
        DispositionField::ProofEntrypoint,
    )?;
    require_text(
        record.removal_boundary,
        record.package,
        DispositionField::RemovalBoundary,
    )
}

/// Fields a bounded fixture must satisfy, including the expiry comparison.
fn verify_bounded_fixture(record: PackageDispositionRecord) -> Result<(), DispositionError> {
    if !record.live_consumer.trim().is_empty() {
        return Err(DispositionError::UnexpectedLiveConsumer {
            package: record.package,
            consumer: record.live_consumer,
        });
    }
    if TESTD_PROFILE_UNIVERSE.contains(&record.testd_profile) {
        return Err(DispositionError::NonDispatchableProfile {
            package: record.package,
            profile: record.testd_profile,
        });
    }
    require_member(
        record.proof_ceiling,
        &PROOF_CEILING_UNIVERSE,
        record.package,
        DispositionField::ProofCeiling,
    )?;
    require_text(
        record.removal_boundary,
        record.package,
        DispositionField::RemovalBoundary,
    )?;
    let Some(expiry) = record.fixture_expiry else {
        return Err(DispositionError::MissingFixtureExpiry {
            package: record.package,
        });
    };
    // Expiries and the review date are ISO-8601, so the byte comparison is the
    // date comparison: a fixture whose expiry is on or before the recorded
    // review date has passed and is deleted, never silently extended.
    if expiry <= DISPOSITION_REVIEWED_ON {
        return Err(DispositionError::FixtureExpired {
            package: record.package,
            expiry,
            reviewed_on: DISPOSITION_REVIEWED_ON,
        });
    }
    Ok(())
}

/// Fields a deleted package must satisfy: no profile, no consumer, no expiry.
fn verify_deleted(record: PackageDispositionRecord) -> Result<(), DispositionError> {
    if record.fixture_expiry.is_some() {
        return Err(DispositionError::LiveRouteCarriesExpiry {
            package: record.package,
        });
    }
    if !record.live_consumer.trim().is_empty() {
        return Err(DispositionError::UnexpectedLiveConsumer {
            package: record.package,
            consumer: record.live_consumer,
        });
    }
    if TESTD_PROFILE_UNIVERSE.contains(&record.testd_profile) {
        return Err(DispositionError::NonDispatchableProfile {
            package: record.package,
            profile: record.testd_profile,
        });
    }
    require_text(
        record.removal_boundary,
        record.package,
        DispositionField::RemovalBoundary,
    )
}

/// Compares each route against the contour the route permits.
fn verify_contour(record: PackageDispositionRecord) -> Result<(), DispositionError> {
    let permitted = match record.route {
        PackageRoute::LiveTestdProfile => matches!(
            record.execution_contour,
            ExecutionContour::GovernedProcessExecutor | ExecutionContour::DecoderOnly
        ),
        PackageRoute::LiveLibrarySurface
        | PackageRoute::BoundedFixture
        | PackageRoute::Deleted => record.execution_contour == ExecutionContour::NoExecution,
    };
    if permitted {
        return Ok(());
    }
    Err(DispositionError::ContourNotPermitted {
        package: record.package,
        route: record.route,
        contour: record.execution_contour,
    })
}

/// Compares each live route against the entries the registry actually holds.
fn verify_registry_routes(registry: &ProviderRegistry) -> Result<(), DispositionError> {
    for record in PACKAGE_DISPOSITIONS {
        match record.route {
            PackageRoute::LiveTestdProfile => verify_registered_profile(record, registry)?,
            PackageRoute::LiveLibrarySurface => {
                verify_unclaimed_library_surface(record, registry)?;
            }
            PackageRoute::BoundedFixture | PackageRoute::Deleted => {}
        }
    }
    Ok(())
}

/// Requires a live profile to be claimed by a registry entry whose
/// decoder-only classification matches the recorded contour.
fn verify_registered_profile(
    record: PackageDispositionRecord,
    registry: &ProviderRegistry,
) -> Result<(), DispositionError> {
    let claimed = registry
        .iter()
        .find(|entry| entry.instrument.as_str() == record.testd_profile);
    let Some(entry) = claimed else {
        return Err(DispositionError::UnregisteredLiveProfile {
            package: record.package,
            profile: record.testd_profile,
        });
    };
    if entry.executable.is_decoder_only()
        != matches!(record.execution_contour, ExecutionContour::DecoderOnly)
    {
        return Err(DispositionError::ContourMismatch {
            package: record.package,
            profile: record.testd_profile,
        });
    }
    Ok(())
}

/// Requires a library surface to stay outside the executable registry entries,
/// so promoting one to a launchable profile is an explicit ledger change.
fn verify_unclaimed_library_surface(
    record: PackageDispositionRecord,
    registry: &ProviderRegistry,
) -> Result<(), DispositionError> {
    let claimed = registry
        .iter()
        .any(|entry| entry.instrument.as_str() == record.testd_profile);
    if claimed {
        return Err(DispositionError::RegisteredLibrarySurface {
            package: record.package,
            profile: record.testd_profile,
        });
    }
    Ok(())
}

/// Rejects a blank recorded field.
fn require_text(
    value: &str,
    package: &'static str,
    field: DispositionField,
) -> Result<(), DispositionError> {
    if value.trim().is_empty() {
        return Err(DispositionError::BlankField { package, field });
    }
    Ok(())
}

/// Rejects a field that is blank or outside its declared closed universe.
fn require_member(
    value: &'static str,
    universe: &[&'static str],
    package: &'static str,
    field: DispositionField,
) -> Result<(), DispositionError> {
    require_text(value, package, field)?;
    if !universe.contains(&value) {
        return Err(DispositionError::FieldOutsideUniverse {
            package,
            field,
            value,
        });
    }
    Ok(())
}
