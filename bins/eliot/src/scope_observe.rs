//! One-shot mechanical workspace observation for `WorkScope` attach decisions.
//!
//! `eliot scope observe --repo-root <absolute-path> --generation <n>` runs the
//! bootstrap capture-boundary observation and derives the observed scope
//! resources for exactly one explicit root. Output is unattributed source
//! data for attach discrimination (the I4.1 evidence half): it authenticates
//! nothing, admits nothing, selects no candidate, and creates no binding.
//! Resolution, guard checks, and admission run where retained bindings live
//! (Governor/daemon), never here. The root is always explicit; the command
//! never infers a workspace from the current directory, proximity, or
//! recency.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use clap::Subcommand;
use eliot_bootstrap::capture::observe_workspace_instance;
use eliot_contracts::ResourceGeneration;
use eliot_governor::derive_observed_resources;
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Subcommand)]
pub(crate) enum ScopeCommand {
    /// Observe one explicit workspace root and print derived scope resources.
    Observe {
        /// Absolute workspace root; never inferred from the current directory.
        #[arg(long)]
        repo_root: PathBuf,
        /// Current resource generation the observation is bound to.
        #[arg(long)]
        generation: u64,
    },
}

#[derive(Debug, Error)]
pub(crate) enum ScopeObserveError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("workspace observation failed: {0}")]
    ObservationFailed(String),
    #[error("observed resources invalid: {0}")]
    DerivationFailed(String),
}

impl ScopeObserveError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => 2,
            Self::ObservationFailed(_) => 66,
            Self::DerivationFailed(_) => 65,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::ObservationFailed(_) => "OBSERVATION_FAILED",
            Self::DerivationFailed(_) => "DERIVATION_FAILED",
        }
    }

    pub(crate) fn envelope(&self) -> Value {
        json!({
            "status": "error",
            "code": self.code(),
            "detail": self.to_string(),
        })
    }
}

pub(crate) fn execute(repo_root: &Path, generation: u64) -> Result<Value, ScopeObserveError> {
    if !repo_root.is_absolute() {
        return Err(ScopeObserveError::InvalidInput(
            "repo-root must be absolute".to_owned(),
        ));
    }
    let fence_generation = ResourceGeneration::new(generation)
        .map_err(|_| ScopeObserveError::InvalidInput("generation must be non-zero".to_owned()))?;
    let facts = observe_workspace_instance(repo_root).map_err(|error| {
        ScopeObserveError::ObservationFailed(format!("observe explicit workspace root: {error}"))
    })?;
    let observed =
        derive_observed_resources(&facts, fence_generation, None).map_err(|error| {
            ScopeObserveError::DerivationFailed(format!("derive observed resources: {error}"))
        })?;
    let facts_value =
        serde_json::to_value(&facts).map_err(|error| {
            ScopeObserveError::DerivationFailed(format!("encode observed facts: {error}"))
        })?;
    let observed_value =
        serde_json::to_value(&observed).map_err(|error| {
            ScopeObserveError::DerivationFailed(format!("encode observed resources: {error}"))
        })?;
    Ok(json!({
        "status": "observed",
        "facts": facts_value,
        "observed": observed_value,
    }))
}
