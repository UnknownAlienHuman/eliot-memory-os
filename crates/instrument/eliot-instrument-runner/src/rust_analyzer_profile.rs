//! Admitted one-shot Rust Analyzer diagnostics, version, and SCIP profile.
//!
//! These helpers return only the original values held by the typed
//! InstrumentSpec and provider registries. Executable discovery, source
//! admission, ProcessExecutor requests, and execution remain owned by their
//! existing composition roots.

use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use thiserror::Error;

use crate::profile::{
    BUILTIN_PROFILE_REVISION, InstrumentClass, InstrumentProfile, InstrumentRegistry,
    InstrumentSpec, LSP_BRIDGE_NORMALIZER_CONTRACT, ProfileError,
    RUST_ANALYZER_DIAGNOSTICS_INSTRUMENT, RUST_ANALYZER_PROFILE,
    RUST_ANALYZER_SCIP_INSTRUMENT, RUST_ANALYZER_VERSION_INSTRUMENT,
    DIAGNOSTIC_PARSER_CONTRACT,
};
use crate::registry::{
    ProviderRegistry, RegistryEntry, RegistryError, RegistryFreshness, ResolvedExecutableIdentity,
};

/// Original admitted records required to launch one Rust Analyzer operation.
///
/// All references point into the caller's original registries or the original
/// environment owner's executable observation; this value creates no new
/// admission, receipt, or authority.
pub struct RustAnalyzerProcessProfile<'a> {
    /// Exact admitted `rust-analyzer-one-shot` profile revision.
    pub profile: &'a InstrumentProfile,
    /// Original admitted operation-specific instrument spec.
    pub spec: &'a InstrumentSpec,
    /// Fresh operation-specific provider entry.
    pub provider: &'a RegistryEntry,
    /// Original environment-owner executable observation.
    pub resolved_executable: &'a ResolvedExecutableIdentity,
}

/// Typed refusal while resolving the original Rust Analyzer profile binding.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RustAnalyzerProfileError {
    /// The invocation did not name the admitted one-shot profile.
    #[error("Rust Analyzer invocation names profile '{observed}', expected '{expected}'")]
    WrongProfile {
        /// Profile label carried by the original invocation.
        observed: String,
        /// Required admitted profile.
        expected: &'static str,
    },
    /// The admitted profile registry moved from the caller's freshness view.
    #[error("Rust Analyzer profile registry is stale: expected generation {expected}, found {found}")]
    StaleProfileRegistry {
        /// Freshness generation supplied by the current owner.
        expected: u64,
        /// Generation pinned by the original profile registry.
        found: u64,
    },
    /// The invocation did not name an admitted Rust Analyzer operation.
    #[error("instrument '{instrument}' is not an admitted Rust Analyzer operation")]
    UnsupportedInstrument {
        /// Original instrument identity.
        instrument: String,
    },
    /// The admitted profile does not contain the exact operation stage.
    #[error("Rust Analyzer profile does not admit '{instrument}' as {kind:?}")]
    MissingProfileStage {
        /// Original instrument identity.
        instrument: String,
        /// Original invocation kind.
        kind: InstrumentKind,
    },
    /// Profile and provider registry parser/normalizer identities disagree.
    #[error("Rust Analyzer profile, spec, and provider parser identities disagree")]
    IdentityMismatch,
    /// The invocation supplied arguments outside the original fixed spec template.
    #[error("Rust Analyzer invocation arguments differ from the admitted instrument spec")]
    ArgumentMismatch,
    /// A nested owner rejected the original profile or provider record.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// A nested provider lookup or executable check rejected the request.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Resolves the current operation-specific Rust Analyzer process profile.
///
/// The caller must pass the original `InstrumentInvocation`, registries,
/// freshness inputs, and executable identity supplied by their owners. No
/// executable name, CLI command, or configuration field is admitted here.
pub fn resolve_current<'a>(
    profiles: &'a InstrumentRegistry,
    providers: &'a ProviderRegistry,
    invocation: &'a InstrumentInvocation,
    freshness: &RegistryFreshness<'_>,
    resolved_executable: &'a ResolvedExecutableIdentity,
) -> Result<RustAnalyzerProcessProfile<'a>, RustAnalyzerProfileError> {
    if invocation.profile != RUST_ANALYZER_PROFILE {
        return Err(RustAnalyzerProfileError::WrongProfile {
            observed: invocation.profile.clone(),
            expected: RUST_ANALYZER_PROFILE,
        });
    }
    if profiles.generation() != freshness.generation {
        return Err(RustAnalyzerProfileError::StaleProfileRegistry {
            expected: freshness.generation,
            found: profiles.generation(),
        });
    }

    let instrument_name = invocation.instrument.as_str();
    let expected_parser = match instrument_name {
        RUST_ANALYZER_DIAGNOSTICS_INSTRUMENT => DIAGNOSTIC_PARSER_CONTRACT,
        RUST_ANALYZER_VERSION_INSTRUMENT => LSP_BRIDGE_NORMALIZER_CONTRACT,
        RUST_ANALYZER_SCIP_INSTRUMENT => LSP_BRIDGE_NORMALIZER_CONTRACT,
        _ => {
            return Err(RustAnalyzerProfileError::UnsupportedInstrument {
                instrument: instrument_name.to_owned(),
            });
        }
    };
    if invocation.kind != InstrumentKind::Inspect {
        return Err(RustAnalyzerProfileError::MissingProfileStage {
            instrument: instrument_name.to_owned(),
            kind: invocation.kind,
        });
    }

    let profile = profiles.admitted(RUST_ANALYZER_PROFILE, BUILTIN_PROFILE_REVISION)?;
    if !profile.admits_kind(invocation.kind)
        || !profile.dag.iter().any(|stage| {
            stage.spec.as_str() == instrument_name && stage.kind == invocation.kind
        })
    {
        return Err(RustAnalyzerProfileError::MissingProfileStage {
            instrument: instrument_name.to_owned(),
            kind: invocation.kind,
        });
    }
    let spec = profiles
        .spec(instrument_name)
        .ok_or_else(|| RustAnalyzerProfileError::UnsupportedInstrument {
            instrument: instrument_name.to_owned(),
        })?;
    if spec.kind.as_str() != instrument_name
        || spec.class != InstrumentClass::SemanticIndex
        || spec.executable != "rust-analyzer"
        || spec.parser.as_str() != expected_parser
    {
        return Err(RustAnalyzerProfileError::IdentityMismatch);
    }
    if invocation.arguments != spec.argument_template {
        return Err(RustAnalyzerProfileError::ArgumentMismatch);
    }

    let provider = providers.resolve_current(invocation, freshness)?;
    if provider.instrument.as_str() != instrument_name
        || provider.parser != spec.parser
        || provider.normalizer.as_str() != LSP_BRIDGE_NORMALIZER_CONTRACT
        || provider.executable.is_decoder_only()
        || provider.executable.executable.as_deref() != Some("rust-analyzer")
    {
        return Err(RustAnalyzerProfileError::IdentityMismatch);
    }
    provider.check_resolved_executable(Some(resolved_executable))?;

    Ok(RustAnalyzerProcessProfile {
        profile,
        spec,
        provider,
        resolved_executable,
    })
}
