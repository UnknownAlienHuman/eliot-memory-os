//! Synthetic Host library root (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: never compiled, never a second Host owner.

use crate::host_diagnostics::{HOST_TERMINAL_CODE_START_RESULT, observe_terminal_error};

pub mod host_console;
pub mod host_diagnostics;
pub mod host_launch_artifact;
pub mod host_launch_options;
pub mod host_receipt;
pub mod host_recovery;
pub mod host_sink;

#[cfg(test)]
mod host_launch_options_tests;

/// Error type owned by the synthetic fixture root.
#[derive(Debug)]
pub enum HostError {
    Platform(String),
}

/// Synthetic launch options parsed by the fixture launch owner.
pub struct HostLaunchOptions {
    installation_id: String,
}

impl HostLaunchOptions {
    /// Parse the synthetic installation identifier.
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        if raw.is_empty() {
            return Err(HostError::Platform("empty installation".to_owned()));
        }
        Ok(Self {
            installation_id: raw.to_owned(),
        })
    }

    /// Installation identity carried by the parsed options.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
}

/// Synthetic start contour reporting its own terminal result.
pub fn start_contour(raw: &str) -> Result<String, HostError> {
    let options = HostLaunchOptions::parse(raw)?;
    observe_terminal_error(HOST_TERMINAL_CODE_START_RESULT);
    Ok(options.installation_id().to_owned())
}
