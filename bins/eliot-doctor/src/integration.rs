#![forbid(unsafe_code)]

//! Integration coverage verification (I3.7).
//!
//! Read-only post-installation check behind `integration <profile>`: it
//! inspects expected file hashes, active registration state, observed hook
//! events, and a handshake result, then reports installation separately from
//! runtime liveness. A successful config installation with no handshake is
//! reported as installed but not live. This module executes no repair, mints
//! no authority, and mutates no store.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Expected integration state for one profile, as recorded by the install
/// preview (Governor integration-record shape consumed as-is).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IntegrationExpectation {
    /// Integration profile name.
    pub profile: String,
    /// Expected lowercase SHA-256 hex per file path.
    #[serde(default)]
    pub expected_file_hashes: BTreeMap<String, String>,
    /// Registrations expected to be active.
    #[serde(default)]
    pub expected_registrations: Vec<String>,
    /// Hook events expected to have been observed.
    #[serde(default)]
    pub expected_hook_events: Vec<String>,
}

/// Observed integration state supplied by the caller for verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IntegrationObservation {
    /// Actual lowercase SHA-256 hex per file path.
    #[serde(default)]
    pub actual_file_hashes: BTreeMap<String, String>,
    /// Registrations currently active.
    #[serde(default)]
    pub active_registrations: Vec<String>,
    /// Hook events observed so far.
    #[serde(default)]
    pub observed_hook_events: Vec<String>,
    /// Whether the runtime handshake was observed.
    #[serde(default)]
    pub handshake_ok: bool,
}

/// Verification verdict. `installed` covers the static install surface;
/// `live` additionally requires the handshake.
#[allow(
    clippy::struct_excessive_bools,
    reason = "I3.7 verdict reports six independent install/liveness flags; grouping them would hide the installed-vs-live contract"
)]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IntegrationReport {
    /// Integration profile name.
    pub profile: String,
    /// Every expected file hash matched.
    pub file_hash_ok: bool,
    /// Files missing or mismatched.
    pub file_hash_gaps: Vec<String>,
    /// Every expected registration is active.
    pub registration_ok: bool,
    /// Expected registrations with no active binding.
    pub registration_gaps: Vec<String>,
    /// Every expected hook event was observed.
    pub hook_events_ok: bool,
    /// Expected hook events with no observation.
    pub hook_event_gaps: Vec<String>,
    /// The runtime handshake was observed.
    pub handshake_ok: bool,
    /// Static install surface is complete.
    pub installed: bool,
    /// Install surface plus live handshake.
    pub live: bool,
    /// `LIVE`, `INSTALLED_NOT_LIVE`, or `NOT_INSTALLED`.
    pub disposition: String,
}

/// Typed verification failure. Input errors only; verification mismatches
/// are reported inside [`IntegrationReport`], never as errors.
#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    /// An input file could not be read.
    #[error("read integration input {path}: {detail}")]
    InputRead {
        /// Input path that failed.
        path: String,
        /// Underlying detail.
        detail: String,
    },
    /// An input file is malformed or violates its contract.
    #[error("invalid integration input: {0}")]
    InputInvalid(String),
    /// The profile argument is missing or empty.
    #[error("integration profile must be non-empty")]
    EmptyProfile,
    /// The expectation record names a different profile than the one
    /// requested. A cross-profile record is a typed input error, never a
    /// live claim for the other profile.
    #[error(
        "integration profile mismatch: requested {requested} but expectation carries {carried}"
    )]
    ProfileMismatch {
        /// Profile requested on the command line.
        requested: String,
        /// Profile carried by the expectation record.
        carried: String,
    },
}

/// Hashes one file with the canonical SHA-256 projection.
pub fn hash_file(path: &Path) -> Result<String, IntegrationError> {
    let bytes = std::fs::read(path).map_err(|error| IntegrationError::InputRead {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

/// Loads an expectation document. The path must be absolute.
pub fn load_expectation(path: &Path) -> Result<IntegrationExpectation, IntegrationError> {
    if !path.is_absolute() {
        return Err(IntegrationError::InputInvalid(
            "expectation path must be absolute".to_owned(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| IntegrationError::InputRead {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let expectation: IntegrationExpectation = serde_json::from_slice(&bytes)
        .map_err(|error| IntegrationError::InputInvalid(error.to_string()))?;
    if expectation.profile.trim().is_empty() {
        return Err(IntegrationError::InputInvalid(
            "expectation profile must be non-empty".to_owned(),
        ));
    }
    Ok(expectation)
}

/// Loads an observation document. The path must be absolute.
pub fn load_observation(path: &Path) -> Result<IntegrationObservation, IntegrationError> {
    if !path.is_absolute() {
        return Err(IntegrationError::InputInvalid(
            "observation path must be absolute".to_owned(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| IntegrationError::InputRead {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| IntegrationError::InputInvalid(error.to_string()))
}

fn missing_subset(expected: &[String], actual: &[String]) -> Vec<String> {
    expected
        .iter()
        .filter(|item| !actual.contains(item))
        .cloned()
        .collect()
}

/// Evaluates one profile: static install checks first, then the liveness
/// handshake. Installed without handshake is not live.
#[must_use]
pub fn evaluate(
    profile: &str,
    expectation: &IntegrationExpectation,
    observation: &IntegrationObservation,
) -> IntegrationReport {
    let mut file_hash_gaps: Vec<String> = Vec::new();
    for (path, expected) in &expectation.expected_file_hashes {
        match observation.actual_file_hashes.get(path) {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            _ => file_hash_gaps.push(path.clone()),
        }
    }
    let file_hash_ok = file_hash_gaps.is_empty();
    let registration_gaps = missing_subset(
        &expectation.expected_registrations,
        &observation.active_registrations,
    );
    let registration_ok = registration_gaps.is_empty();
    let hook_event_gaps = missing_subset(
        &expectation.expected_hook_events,
        &observation.observed_hook_events,
    );
    let hook_events_ok = hook_event_gaps.is_empty();
    let installed = file_hash_ok && registration_ok && hook_events_ok;
    let live = installed && observation.handshake_ok;
    let disposition = if live {
        "LIVE"
    } else if installed {
        "INSTALLED_NOT_LIVE"
    } else {
        "NOT_INSTALLED"
    };
    IntegrationReport {
        profile: profile.to_owned(),
        file_hash_ok,
        file_hash_gaps,
        registration_ok,
        registration_gaps,
        hook_events_ok,
        hook_event_gaps,
        handshake_ok: observation.handshake_ok,
        installed,
        live,
        disposition: disposition.to_owned(),
    }
}

/// Verifies one profile end to end through the single gate shared by every
/// `integration` front door (`eliot-doctor integration` and
/// `eliot doctor integration`): loads the expectation, binds it to the
/// requested profile, loads the observation, and projects the
/// machine-readable contract JSON. Verification mismatches are data inside
/// the returned JSON; only input errors (including a cross-profile
/// expectation record) are `Err`.
pub fn verify_profile(
    profile: &str,
    expectation_path: &Path,
    observation_path: &Path,
) -> Result<serde_json::Value, IntegrationError> {
    if profile.trim().is_empty() {
        return Err(IntegrationError::EmptyProfile);
    }
    let expected = load_expectation(expectation_path)?;
    if expected.profile != profile {
        return Err(IntegrationError::ProfileMismatch {
            requested: profile.to_owned(),
            carried: expected.profile,
        });
    }
    let observed = load_observation(observation_path)?;
    Ok(report_json(&evaluate(profile, &expected, &observed)))
}

/// Projects the report to the machine-readable contract JSON, keeping
/// installed and live as separate fields.
#[must_use]
pub fn report_json(report: &IntegrationReport) -> serde_json::Value {
    serde_json::json!({
        "contract": "eliot.doctor.integration",
        "contract_version": "1.0.0",
        "profile": report.profile,
        "file_hash": {
            "ok": report.file_hash_ok,
            "gaps": report.file_hash_gaps,
        },
        "registration": {
            "ok": report.registration_ok,
            "gaps": report.registration_gaps,
        },
        "hook_events": {
            "ok": report.hook_events_ok,
            "gaps": report.hook_event_gaps,
        },
        "handshake": {
            "ok": report.handshake_ok,
        },
        "installed": report.installed,
        "live": report.live,
        "disposition": report.disposition,
        "note": "installed without handshake is not live",
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "small pure integration tests use explicit fixtures"
)]
mod tests {
    use super::*;

    fn expectation() -> IntegrationExpectation {
        IntegrationExpectation {
            profile: "demo".to_owned(),
            expected_file_hashes: BTreeMap::from([("config.json".to_owned(), "aa".repeat(32))]),
            expected_registrations: vec!["demo-mcp".to_owned()],
            expected_hook_events: vec!["on_task".to_owned()],
        }
    }

    fn observation(handshake_ok: bool) -> IntegrationObservation {
        IntegrationObservation {
            actual_file_hashes: BTreeMap::from([("config.json".to_owned(), "aa".repeat(32))]),
            active_registrations: vec!["demo-mcp".to_owned()],
            observed_hook_events: vec!["on_task".to_owned()],
            handshake_ok,
        }
    }

    #[test]
    fn installed_without_handshake_is_not_live() {
        let report = evaluate("demo", &expectation(), &observation(false));
        assert!(report.file_hash_ok);
        assert!(report.registration_ok);
        assert!(report.hook_events_ok);
        assert!(!report.handshake_ok);
        assert!(report.installed);
        assert!(!report.live);
        assert_eq!(report.disposition, "INSTALLED_NOT_LIVE");
        let value = report_json(&report);
        assert_eq!(value["installed"], true);
        assert_eq!(value["live"], false);
    }

    #[test]
    fn handshake_after_install_reports_live() {
        let report = evaluate("demo", &expectation(), &observation(true));
        assert!(report.installed);
        assert!(report.live);
        assert_eq!(report.disposition, "LIVE");
    }

    #[test]
    fn hash_mismatch_reports_not_installed() {
        let mut observed = observation(true);
        observed.actual_file_hashes = BTreeMap::from([("config.json".to_owned(), "bb".repeat(32))]);
        let report = evaluate("demo", &expectation(), &observed);
        assert!(!report.file_hash_ok);
        assert!(!report.installed);
        assert!(!report.live);
        assert_eq!(report.disposition, "NOT_INSTALLED");
    }

    #[test]
    fn cross_profile_expectation_is_rejected_not_live() {
        let dir = std::env::temp_dir().join("eliot-go19-1964-cross-profile");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let expectation_path = dir.join("expectation.json");
        let observation_path = dir.join("observation.json");
        std::fs::write(
            &expectation_path,
            serde_json::to_vec(&expectation()).expect("write expectation"),
        )
        .expect("write expectation file");
        std::fs::write(
            &observation_path,
            serde_json::to_vec(&observation(true)).expect("write observation"),
        )
        .expect("write observation file");
        let error = verify_profile("other", &expectation_path, &observation_path)
            .expect_err("cross-profile expectation must not verify");
        assert!(matches!(error, IntegrationError::ProfileMismatch { .. }));
        let value = verify_profile("demo", &expectation_path, &observation_path)
            .expect("same-profile expectation verifies");
        assert_eq!(value["live"], true);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_hash_helper_matches_canonical_digest() {
        let dir = std::env::temp_dir().join("eliot-go19-1964-hash");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("probe.txt");
        std::fs::write(&path, b"hello").expect("write probe");
        let digest = hash_file(&path).expect("hash probe");
        assert_eq!(digest, eliot_contracts::sha256_hex(b"hello"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
