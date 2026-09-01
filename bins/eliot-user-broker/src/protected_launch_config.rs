//! Protected installation launch declaration and lease retention for the A-09 user broker.
//!
//! Architecture anchors: A9 User Broker protected launch, A13.2 Kernel and failure domains,
//! ARCH-AUTH-01 explicit authority, ARCH-SEC-02 SID/session binding, ARCH-RES-01 bounded startup.
//! Implementation anchors: I1.3 optional and on-demand processes, B.8 Kernel ↔ User Broker,
//! and I2.23 capability-family topology.
//!
//! This cell owns only the protected config bytes, validation, and retained
//! `ProtectedPathLease`. It never mints Kernel authority, never governs canonical
//! store state, and never synthesizes Governor decisions or process evidence.

#![forbid(unsafe_code)]

use std::fs;

use eliot_platform_windows::ProtectedPathLease;
use eliot_protocol::RequestIdentity;
use eliot_user_broker_core::{OperatorArtifact, RegistrationRequest};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::CompositionError;

const LAUNCH_CONFIG_RELATIVE_PATH: &str = "Eliot/user-broker/launch.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerLaunchConfig {
    pub(super) registration: RegistrationRequest,
    pub(super) request_identity: RequestIdentity,
    pub(super) operator_artifact: OperatorArtifactConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorArtifactConfig {
    pub(super) image_id: String,
    pub(super) executable: String,
    pub(super) artifact_digest: String,
}

fn artifact_digest() -> Result<String, CompositionError> {
    let executable = std::env::current_exe().map_err(CompositionError::Durable)?;
    let bytes = fs::read(executable).map_err(CompositionError::Durable)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_launch_config(config: &BrokerLaunchConfig) -> Result<(), CompositionError> {
    config
        .registration
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    config
        .request_identity
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    let expected_pid = std::process::id().to_string();
    if config.registration.broker_process_id != expected_pid {
        return Err(CompositionError::Launch(
            "protected broker process identity does not match current process".to_owned(),
        ));
    }
    if !config
        .registration
        .broker_artifact_digest
        .eq_ignore_ascii_case(&artifact_digest()?)
    {
        return Err(CompositionError::Launch(
            "protected broker artifact digest does not match current executable".to_owned(),
        ));
    }
    OperatorArtifact {
        image_id: config.operator_artifact.image_id.clone(),
        executable: config.operator_artifact.executable.clone(),
        artifact_digest: config.operator_artifact.artifact_digest.clone(),
    }
    .validate()
    .map_err(|error| CompositionError::Launch(error.to_string()))?;
    #[cfg(windows)]
    {
        let identity = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        if config.registration.windows_sid != identity.expected_sid()
            || config.registration.interactive_session_id
                != identity.expected_session_id().to_string()
        {
            return Err(CompositionError::Launch(
                "protected broker SID/session does not match current token".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn load_protected_launch_config()
-> Result<(BrokerLaunchConfig, ProtectedPathLease), CompositionError> {
    #[cfg(not(windows))]
    {
        Err(CompositionError::Kernel(
            "Windows protected broker launch configuration".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        let path = eliot_platform_windows::protected_program_data_path(LAUNCH_CONFIG_RELATIVE_PATH)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let lease = ProtectedPathLease::open_existing_absolute(&path)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let bytes = lease
            .read_bounded(64 * 1024)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let config = serde_json::from_slice(&bytes).map_err(CompositionError::Encoding)?;
        validate_launch_config(&config)?;
        Ok((config, lease))
    }
}
