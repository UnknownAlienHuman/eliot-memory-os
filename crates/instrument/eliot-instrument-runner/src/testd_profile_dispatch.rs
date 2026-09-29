//! Closed Testd profile to instrument contract dispatch for the retained
//! Instrument Plane packages.
//!
//! Issue #1140 requires that every retained Instrument package resolves one
//! Testd profile it is actually dispatched under. The provider registry names
//! its entries by *instrument contract* (`eliot.instrument.nextest`), while
//! `eliot-testd-core` names the profiles its worker admits by *dispatch name*
//! (`cargo-nextest`, `cargo-nextest-list`, `cargo-nextest-scoped`,
//! `cargo-test`). Before this module no product code related the two
//! vocabularies, so the recorded "one live Testd profile per package" claim was
//! unfalsifiable: a package could name a contract identity Testd never
//! dispatches and the registry would still assemble.
//!
//! This module closes that gap by binding the two closed vocabularies together
//! in one direction. [`instrument_contract_for_testd_profile`] maps a Testd
//! dispatch name to the single instrument contract the Testd worker executes it
//! as. There is no reverse fallback, no string surgery, and no caller-supplied
//! profile: a profile outside the `eliot-testd-core` admitted set cannot be
//! named.
//!
//! The recorded table is the *expected* set and is declared independently of
//! the package disposition ledger
//! ([`PACKAGE_DISPOSITIONS`](crate::package_disposition::PACKAGE_DISPOSITIONS)),
//! so [`verify_testd_dispatch`] compares two independently declared sources
//! rather than one caller-supplied list against a copy of itself. It runs inside
//! [`ProviderRegistry::ready`](crate::registry::ProviderRegistry::ready), which
//! means a live package naming a profile the Testd worker cannot dispatch, or a
//! profile Testd dispatches that the table leaves unbound, fails registry
//! assembly closed.
//!
//! The check proves *name resolution only*. It grants no execution, admits no
//! task, owns no Finish, and cannot create a verifier verdict: the launch still
//! runs through the governed `ProcessExecutor` contour owned by issue #20/#100,
//! and evaluation still belongs to `eliot-verifier`.

use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_testd_core::{
    TESTD_LIST_PROFILE, TESTD_PRODUCTIVE_PROFILE, TESTD_SCOPED_PROFILE,
};
use thiserror::Error;

use crate::registry::ProviderRegistry;

/// One closed Testd dispatch profile and the instrument contract it runs as.
///
/// The pair is recorded once, in the owners' own vocabulary: the dispatch name
/// is an `eliot-testd-core` constant and the contract name is the owning adapter
/// crate's published contract identity, so neither half can drift from the
/// crate that publishes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestdDispatchBinding {
    /// The Testd dispatch profile name `eliot-testd-core` admits.
    pub testd_profile: &'static str,
    /// The instrument contract identity Testd executes this profile as.
    pub instrument_contract: &'static str,
}

/// Every Testd profile this plane dispatches as a productive run, with the
/// instrument contract each one runs as.
///
/// The three profiles are the `eliot-testd-core` productive nextest profiles:
/// the unscoped run, the list, and the scoped run. All three execute as
/// `eliot.instrument.nextest`, which is why one contract legitimately owns
/// several profiles. The admitted `cargo-test` probe is deliberately *not*
/// bound: it launches the cargo tool for `--version` and produces no test
/// report, so it proves the tool resolved rather than that a package ran.
pub const TESTD_DISPATCH_BINDINGS: [TestdDispatchBinding; 3] = [
    TestdDispatchBinding {
        testd_profile: TESTD_PRODUCTIVE_PROFILE,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TESTD_LIST_PROFILE,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TESTD_SCOPED_PROFILE,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
];

/// The instrument contract the Testd worker executes one admitted profile as.
///
/// # Errors
///
/// Returns [`TestdDispatchError::UndispatchableProfile`] for any profile the
/// recorded table does not bind, so a caller cannot name a profile the Testd
/// worker would refuse at its own admission gate.
pub fn instrument_contract_for_testd_profile(
    profile: &str,
) -> Result<&'static str, TestdDispatchError> {
    TESTD_DISPATCH_BINDINGS
        .iter()
        .find(|binding| binding.testd_profile == profile)
        .map(|binding| binding.instrument_contract)
        .ok_or_else(|| TestdDispatchError::UndispatchableProfile {
            profile: profile.to_owned(),
        })
}

/// The Testd profiles this plane dispatches as productive runs.
///
/// This is the expected denominator the coverage check compares against. The
/// candidate names and the membership test both come from `eliot-testd-core`,
/// the profile admission owner (issue #20), so widening the recorded table to
/// name a profile Testd does not dispatch — or narrowing it to hide one Testd
/// does dispatch — fails closed instead of being silently accepted.
#[must_use]
pub fn dispatched_testd_profiles() -> Vec<&'static str> {
    [TESTD_PRODUCTIVE_PROFILE, TESTD_LIST_PROFILE, TESTD_SCOPED_PROFILE]
        .into_iter()
        .filter(|profile| eliot_testd_core::is_productive_testd_profile(profile))
        .collect()
}

/// Why a Testd dispatch name could not be resolved to an instrument contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TestdDispatchError {
    /// The named profile is not one this plane dispatches.
    #[error("testd dispatches no profile named '{profile}'")]
    UndispatchableProfile {
        /// The refused profile name.
        profile: String,
    },
    /// Two recorded bindings claim the same Testd profile.
    #[error("testd profile '{profile}' is bound twice in the recorded dispatch table")]
    DuplicateTestdProfile {
        /// The duplicated Testd profile name.
        profile: &'static str,
    },
    /// A recorded binding names a profile `eliot-testd-core` does not admit.
    #[error("the dispatch table binds testd profile '{profile}', which testd does not admit")]
    UnadmittedBinding {
        /// The undispatchable recorded profile.
        profile: &'static str,
    },
    /// A profile Testd dispatches is bound to no instrument contract.
    #[error("testd dispatches profile '{profile}' but the dispatch table binds no instrument contract")]
    UnboundDispatchProfile {
        /// The unbound Testd profile name.
        profile: &'static str,
    },
    /// A recorded package names a profile the Testd worker cannot dispatch.
    #[error(
        "instrument package '{package}' records testd dispatch profile '{profile}', which testd cannot dispatch"
    )]
    UndispatchableDisposition {
        /// The package whose recorded profile cannot dispatch.
        package: &'static str,
        /// The undispatchable recorded profile.
        profile: &'static str,
    },
    /// A package records a dispatch profile no registry entry backs.
    #[error(
        "instrument package '{package}' records testd dispatch profile '{profile}' but no registry entry claims '{instrument_contract}'"
    )]
    UnregisteredDispatchContract {
        /// The package whose dispatch profile has no registry entry.
        package: &'static str,
        /// The recorded Testd dispatch profile.
        profile: &'static str,
        /// The instrument contract the profile dispatches.
        instrument_contract: &'static str,
    },
}

/// Verifies the recorded dispatch table against Testd's own admission surface
/// and the assembled provider registry.
///
/// Three independent comparisons run. Every recorded profile must be unique.
/// The recorded table must cover exactly the profiles Testd dispatches as
/// productive runs, compared against [`dispatched_testd_profiles`] rather than
/// against itself. Finally each recorded package dispatch profile must resolve
/// to an instrument contract the assembled registry actually claims.
///
/// # Errors
///
/// Returns [`TestdDispatchError::DuplicateTestdProfile`] for a self-contradictory
/// table, [`TestdDispatchError::UnadmittedBinding`] for a bound profile Testd
/// does not admit, [`TestdDispatchError::UnboundDispatchProfile`] for a profile
/// Testd dispatches that the table leaves unbound,
/// [`TestdDispatchError::UndispatchableDisposition`] for a recorded package
/// naming an undispatchable profile, or
/// [`TestdDispatchError::UnregisteredDispatchContract`] for a recorded dispatch
/// profile whose contract no registry entry claims.
pub fn verify_testd_dispatch(registry: &ProviderRegistry) -> Result<(), TestdDispatchError> {
    verify_binding_uniqueness()?;
    verify_dispatch_denominator()?;
    verify_disposition_profiles(registry)
}

/// Requires every recorded profile to be bound exactly once.
///
/// One instrument contract may legitimately own several profiles — the three
/// nextest profiles all execute as `eliot.instrument.nextest` — so only the
/// profile side is required to be unique. A duplicated contract is instead
/// caught where it would matter, by [`verify_disposition_profiles`] requiring
/// the registry to claim it.
fn verify_binding_uniqueness() -> Result<(), TestdDispatchError> {
    for (index, binding) in TESTD_DISPATCH_BINDINGS.iter().enumerate() {
        for other in &TESTD_DISPATCH_BINDINGS[index + 1..] {
            if binding.testd_profile == other.testd_profile {
                return Err(TestdDispatchError::DuplicateTestdProfile {
                    profile: binding.testd_profile,
                });
            }
        }
    }
    Ok(())
}

/// Requires the recorded table to cover exactly the profiles Testd dispatches.
///
/// The expected set is [`dispatched_testd_profiles`], derived from the
/// `eliot-testd-core` owner predicate, so the table is compared against
/// content the caller does not control rather than against itself. Both
/// directions are checked: a profile Testd dispatches that the table leaves
/// unbound, and a profile the table binds that Testd does not admit.
fn verify_dispatch_denominator() -> Result<(), TestdDispatchError> {
    for profile in dispatched_testd_profiles() {
        if instrument_contract_for_testd_profile(profile).is_ok() {
            continue;
        }
        return Err(TestdDispatchError::UnboundDispatchProfile { profile });
    }
    for binding in TESTD_DISPATCH_BINDINGS {
        if eliot_testd_core::is_productive_testd_profile(binding.testd_profile) {
            continue;
        }
        return Err(TestdDispatchError::UnadmittedBinding {
            profile: binding.testd_profile,
        });
    }
    Ok(())
}

/// Requires each recorded dispatch profile to resolve to a contract the
/// registry actually claims.
fn verify_disposition_profiles(registry: &ProviderRegistry) -> Result<(), TestdDispatchError> {
    for record in crate::package_disposition::PACKAGE_DISPOSITIONS {
        if record.testd_dispatch_profile.trim().is_empty() {
            continue;
        }
        let Ok(instrument_contract) =
            instrument_contract_for_testd_profile(record.testd_dispatch_profile)
        else {
            return Err(TestdDispatchError::UndispatchableDisposition {
                package: record.package,
                profile: record.testd_dispatch_profile,
            });
        };
        if registry
            .iter()
            .any(|entry| entry.instrument.as_str() == instrument_contract)
        {
            continue;
        }
        return Err(TestdDispatchError::UnregisteredDispatchContract {
            package: record.package,
            profile: record.testd_dispatch_profile,
            instrument_contract,
        });
    }
    Ok(())
}
