//! Closed Testd profile-stage to instrument dispatch verification.
//!
//! The runner profiles are DAGs, not one-profile/one-provider aliases. This
//! module binds each admitted stage of each productive Testd runner profile to
//! its owning instrument contract, then verifies the binding against the
//! independently compiled profile registry and the assembled provider
//! registry. The older direct Nextest profile names remain a closed one-stage
//! compatibility surface; they do not stand in for the runner DAGs.

use eliot_instrument_api::InstrumentKind;
use eliot_instrument_cargo::CONTRACT_NAME as CARGO_INSTRUMENT;
use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_instrument_rustc::RUSTC_INSTRUMENT;
use eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT;
use eliot_testd_core::{
    TESTD_LIST_PROFILE, TESTD_PRODUCTIVE_PROFILE, TESTD_SCOPED_PROFILE,
    StageExecutionKind, is_productive_testd_profile,
};
use thiserror::Error;

use crate::{
    profile::{
        BUNDLE_VERIFICATION_ROUTE, COMPILER_PROFILE, InstrumentRegistry, PACKAGE_VERIFICATION_ROUTE,
        ProfileCompiler, TEST_PROFILE, VERIFICATION_REGISTRY_GENERATION,
    },
    registry::ProviderRegistry,
    testd_port::adapter_stage_dispatchable,
};

/// One closed Testd profile stage and the instrument contract it executes as.
///
/// `stage_id` is `None` only for the three legacy direct Nextest profiles,
/// which predate runner DAGs and are admitted by their exact Testd constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestdDispatchBinding {
    /// The Testd dispatch profile name.
    pub testd_profile: &'static str,
    /// Exact stage identity in the compiled runner profile, if it is a DAG.
    pub stage_id: Option<&'static str>,
    /// Instrument contract identity selected by that stage.
    pub instrument_contract: &'static str,
}

/// Complete stage dispatch surface for legacy Nextest and the four admitted
/// runner profiles. This is checked against the compiled DAG, not used as a
/// command or executable map.
pub const TESTD_DISPATCH_BINDINGS: [TestdDispatchBinding; 12] = [
    TestdDispatchBinding {
        testd_profile: TESTD_PRODUCTIVE_PROFILE,
        stage_id: None,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TESTD_LIST_PROFILE,
        stage_id: None,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TESTD_SCOPED_PROFILE,
        stage_id: None,
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: COMPILER_PROFILE,
        stage_id: Some("cargo-metadata"),
        instrument_contract: CARGO_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: COMPILER_PROFILE,
        stage_id: Some("rustc-build"),
        instrument_contract: RUSTC_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TEST_PROFILE,
        stage_id: Some("nextest-list"),
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: TEST_PROFILE,
        stage_id: Some("nextest-run"),
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: PACKAGE_VERIFICATION_ROUTE,
        stage_id: Some("package-compile"),
        instrument_contract: RUSTC_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: PACKAGE_VERIFICATION_ROUTE,
        stage_id: Some("package-test"),
        instrument_contract: NEXTEST_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: PACKAGE_VERIFICATION_ROUTE,
        stage_id: Some("package-format"),
        instrument_contract: RUSTFMT_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: BUNDLE_VERIFICATION_ROUTE,
        stage_id: Some("bundle-compile"),
        instrument_contract: RUSTC_INSTRUMENT,
    },
    TestdDispatchBinding {
        testd_profile: BUNDLE_VERIFICATION_ROUTE,
        stage_id: Some("bundle-test"),
        instrument_contract: NEXTEST_INSTRUMENT,
    },
];

/// Returns every productive Testd profile, including runner profiles whose
/// stage DAGs are compiled by this registry.
#[must_use]
pub fn dispatched_testd_profiles() -> Vec<&'static str> {
    eliot_testd_core::PRODUCTIVE_TESTD_PROFILE_NAMES
        .into_iter()
        .filter(|profile| is_productive_testd_profile(profile))
        .collect()
}

/// Resolves the single instrument contract for a one-provider profile.
///
/// Multi-instrument runner profiles intentionally have no singular contract;
/// use their exact compiled stage identities instead.
pub fn instrument_contract_for_testd_profile(
    profile: &str,
) -> Result<&'static str, TestdDispatchError> {
    let mut contracts = TESTD_DISPATCH_BINDINGS
        .iter()
        .filter(|binding| binding.testd_profile == profile)
        .map(|binding| binding.instrument_contract);
    let first = contracts
        .next()
        .ok_or_else(|| TestdDispatchError::UndispatchableProfile {
            profile: profile.to_owned(),
        })?;
    if contracts.any(|contract| contract != first) {
        return Err(TestdDispatchError::MultiContractProfile {
            profile: profile.to_owned(),
        });
    }
    Ok(first)
}

/// Failure while checking the admitted Testd profile-stage dispatch surface.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TestdDispatchError {
    /// The named profile is not a productive Testd profile.
    #[error("testd dispatches no profile named '{profile}'")]
    UndispatchableProfile { profile: String },
    /// A profile consists of multiple instrument contracts and has no single
    /// profile-level contract answer.
    #[error("testd profile '{profile}' has multiple stage instrument contracts")]
    MultiContractProfile { profile: String },
    /// Two bindings claim the same profile and stage.
    #[error("testd profile '{profile}' stage '{stage_id}' is bound more than once")]
    DuplicateStageBinding {
        profile: &'static str,
        stage_id: &'static str,
    },
    /// A productive profile or one of its compiled stages has no binding.
    #[error("testd profile '{profile}' has no dispatch binding for stage '{stage_id}'")]
    UnboundStage { profile: String, stage_id: String },
    /// A declared binding does not correspond to the compiled runner DAG.
    #[error("testd dispatch binding for '{profile}'/'{stage_id}' differs from the compiled profile")]
    StageBindingMismatch {
        profile: &'static str,
        stage_id: &'static str,
    },
    /// A binding names a profile or stage not found in the independently
    /// compiled runner registry.
    #[error("testd dispatch binding names an uncompiled stage '{profile}'/'{stage_id}'")]
    UnknownStage {
        profile: &'static str,
        stage_id: &'static str,
    },
    /// No ready provider entry supports the bound profile stage.
    #[error("no ready provider entry accepts '{profile}'/'{stage_id}' as '{contract}'")]
    UnsupportedStage {
        profile: &'static str,
        stage_id: &'static str,
        contract: &'static str,
    },
    /// A package disposition names an unsupported Testd dispatch profile.
    #[error("instrument package '{package}' records unsupported Testd profile '{profile}'")]
    UndispatchableDisposition {
        package: &'static str,
        profile: &'static str,
    },
}

/// Verifies profile names, every stage in the compiled DAGs, and the actual
/// selected provider/execution lanes. The compiled registry uses its own
/// fixed generation and complete spec/profile set; the Testd request cannot
/// supply either identity.
pub fn verify_testd_dispatch(registry: &ProviderRegistry) -> Result<(), TestdDispatchError> {
    verify_binding_uniqueness()?;
    let profiles = InstrumentRegistry::with_verification_route_profiles(
        VERIFICATION_REGISTRY_GENERATION,
        Vec::new(),
    )
    .map_err(|_| TestdDispatchError::UnboundStage {
        profile: COMPILER_PROFILE.to_owned(),
        stage_id: "<builtin-registry>".to_owned(),
    })?;
    verify_compiled_stages(registry, &profiles)?;
    verify_dispatch_denominator()?;
    verify_disposition_profiles()
}

fn verify_binding_uniqueness() -> Result<(), TestdDispatchError> {
    for (index, binding) in TESTD_DISPATCH_BINDINGS.iter().enumerate() {
        for other in &TESTD_DISPATCH_BINDINGS[index + 1..] {
            if binding.testd_profile == other.testd_profile && binding.stage_id == other.stage_id {
                return Err(TestdDispatchError::DuplicateStageBinding {
                    profile: binding.testd_profile,
                    stage_id: binding.stage_id.unwrap_or("<legacy>"),
                });
            }
        }
    }
    Ok(())
}

fn verify_dispatch_denominator() -> Result<(), TestdDispatchError> {
    for profile in dispatched_testd_profiles() {
        if TESTD_DISPATCH_BINDINGS
            .iter()
            .any(|binding| binding.testd_profile == profile)
        {
            continue;
        }
        return Err(TestdDispatchError::UndispatchableProfile {
            profile: profile.to_owned(),
        });
    }
    for binding in TESTD_DISPATCH_BINDINGS {
        if !is_productive_testd_profile(binding.testd_profile) {
            return Err(TestdDispatchError::UndispatchableProfile {
                profile: binding.testd_profile.to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_compiled_stages(
    providers: &ProviderRegistry,
    profiles: &InstrumentRegistry,
) -> Result<(), TestdDispatchError> {
    for profile in profiles
        .iter()
        .filter(|profile| is_productive_testd_profile(&profile.name))
    {
        let compiled = ProfileCompiler::new(profiles)
            .compile_exact(&profile.name, profile.revision)
            .map_err(|_| TestdDispatchError::UnboundStage {
                profile: profile.name.clone(),
                stage_id: profile.name.clone(),
            })?;
        for stage in compiled.stages {
            let binding = TESTD_DISPATCH_BINDINGS
                .iter()
                .find(|binding| {
                    binding.testd_profile == profile.name
                        && binding.stage_id.as_deref() == Some(stage.stage_id.as_str())
                });
            let Some(binding) = binding else {
                return Err(TestdDispatchError::UnboundStage {
                    profile: profile.name.clone(),
                    stage_id: stage.stage_id,
                });
            };
            if binding.instrument_contract != stage.spec.as_str() {
                return Err(TestdDispatchError::StageBindingMismatch {
                    profile: binding.testd_profile,
                    stage_id: binding.stage_id.unwrap_or("<legacy>"),
                });
            }
        }
    }
    for binding in TESTD_DISPATCH_BINDINGS {
        let Some(stage_id) = binding.stage_id else {
            let supported = providers.iter().any(|entry| {
                entry.instrument.as_str() == binding.instrument_contract
                    && entry.supports(InstrumentKind::Test)
                    && adapter_stage_dispatchable(
                        &entry.adapter,
                        InstrumentKind::Test,
                        StageExecutionKind::Process,
                    )
            });
            if supported {
                continue;
            }
            return Err(TestdDispatchError::UnsupportedStage {
                profile: binding.testd_profile,
                stage_id: "<legacy>",
                contract: binding.instrument_contract,
            });
        };
        let compiled = ProfileCompiler::new(profiles)
            .compile_exact(binding.testd_profile, 1)
            .map_err(|_| TestdDispatchError::UnknownStage {
                profile: binding.testd_profile,
                stage_id,
            })?;
        let stage = compiled
            .stages
            .iter()
            .find(|stage| stage.stage_id == stage_id)
            .ok_or(TestdDispatchError::UnknownStage {
                profile: binding.testd_profile,
                stage_id,
            })?;
        if stage.spec.as_str() != binding.instrument_contract {
            return Err(TestdDispatchError::StageBindingMismatch {
                profile: binding.testd_profile,
                stage_id,
            });
        }
        let execution = if stage.external {
            StageExecutionKind::Process
        } else {
            StageExecutionKind::DecoderOnly
        };
        let supported = providers.iter().any(|entry| {
            entry.instrument == stage.spec
                && entry.supports(stage.kind)
                && (entry.executable.is_decoder_only()) == (execution == StageExecutionKind::DecoderOnly)
                && adapter_stage_dispatchable(&entry.adapter, stage.kind, execution)
        });
        if !supported {
            return Err(TestdDispatchError::UnsupportedStage {
                profile: binding.testd_profile,
                stage_id,
                contract: binding.instrument_contract,
            });
        }
    }
    Ok(())
}

fn verify_disposition_profiles() -> Result<(), TestdDispatchError> {
    for record in crate::package_disposition::PACKAGE_DISPOSITIONS {
        if record.testd_dispatch_profile.is_empty() {
            continue;
        }
        if !TESTD_DISPATCH_BINDINGS
            .iter()
            .any(|binding| binding.testd_profile == record.testd_dispatch_profile)
        {
            return Err(TestdDispatchError::UndispatchableDisposition {
                package: record.package,
                profile: record.testd_dispatch_profile,
            });
        }
    }
    Ok(())
}
