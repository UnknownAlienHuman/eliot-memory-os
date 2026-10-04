#![forbid(unsafe_code)]

//! Integration coverage verification (I3.7).
//!
//! Read-only post-installation check behind `integration <profile>`: it
//! inspects expected file hashes, active registration state, observed hook
//! events, and a handshake result, then reports installation separately from
//! runtime liveness. A successful config installation with no handshake is
//! reported as installed but not live. When the expectation is the install
//! receipt, the installation status the delivery itself recorded
//! (`status`/`code`/`completed`) is reported under its own `installation` key
//! and gates `installed`: an install the record says did not complete is
//! `NOT_INSTALLED` even when every target byte matches. An expectation naming
//! no static surface at all — no target file, no registration, no hook event
//! — yields no `installed` claim either: nothing was read back to compare, so
//! the report is `UNVERIFIED_PLAN_GAP` with `installation: null`, never a
//! vacuous success. This module executes no repair, mints no authority, and
//! mutates no store.

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

/// Installation status as the delivery itself recorded it in the install
/// receipt (`status`, `code`, `completed`).
///
/// This is a fact about the install *attempt* — whether the delivery says it
/// ran the installation — and is deliberately a separate fact from the
/// runtime-liveness and capability evidence this crate gathers by readback.
/// Installation success is not runtime liveness (I3.7), and an install that
/// never ran is not an installation whose bytes happen to be on disk.
///
/// The values are the receipt's own fields, read and compared. Nothing here
/// is recomputed, re-derived, or synthesised: a record that carries no
/// install status yields no `InstallStatus` at all, never a filled-in one.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct InstallStatus {
    /// Receipt `status`, verbatim (e.g. `INSTALL_NOT_ATTEMPTED`).
    pub status: String,
    /// Receipt `code`, verbatim (e.g. `PLAN_GAP`).
    pub code: String,
    /// Receipt `completed`: the delivery's own completion flag. This is the
    /// value the `installed` verdict is gated on.
    pub completed: bool,
}

/// An expectation together with the installation status its own source record
/// carried.
///
/// `install_status` is `Some` only for a record carrying the
/// [`INSTALL_RECEIPT_CONTRACT`], and `None` for a plain
/// [`IntegrationExpectation`] record, which states no install status of its
/// own. Absence is carried through to the report as absence
/// (`"installation": null`); it is never filled in with a synthesised status,
/// and it is never read as a failed or a successful installation.
#[derive(Clone, Debug)]
pub struct LoadedExpectation {
    /// The verified expectation the report is computed against.
    pub expectation: IntegrationExpectation,
    /// Installation status read from the install receipt, when the record is
    /// one. `None` when the record states no installation status.
    pub install_status: Option<InstallStatus>,
}

/// Observed integration state supplied by the caller for verification.
///
/// Every field below is a caller claim, not evidence. The verification gate
/// re-hashes the named target files itself and never trusts these values for
/// any verdict; there is no observation port for registrations, hook events,
/// or the handshake in this front door.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IntegrationObservation {
    /// Claimed lowercase SHA-256 hex per file path. Superseded by real
    /// readback inside [`verify_profile`]; never authority.
    #[serde(default)]
    pub actual_file_hashes: BTreeMap<String, String>,
    /// Claimed active registrations. No observation port exists; never
    /// authority.
    #[serde(default)]
    pub active_registrations: Vec<String>,
    /// Claimed observed hook events. No observation port exists; never
    /// authority.
    #[serde(default)]
    pub observed_hook_events: Vec<String>,
    /// Claimed handshake result. No handshake runner exists in this front
    /// door; never authority and never sufficient for a live claim.
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
    /// Installation status recorded by the expectation's own source record, or
    /// `None` when that record states none.
    ///
    /// This is reported beside, and separately from, the read-back evidence
    /// above: it is the delivery's own statement about whether the
    /// installation ran, never this crate's verdict. `installed` is gated on
    /// it, so a receipt recording an install that did not complete can never
    /// yield `installed: true` however well the target bytes happen to match.
    pub installation: Option<InstallStatus>,
    /// Static install surface is complete.
    ///
    /// Requires, in addition to the read-back evidence above, that the
    /// expectation's source record either states no installation status (a
    /// plain expectation) or records a completed installation, and that the
    /// expectation names at least one static target: an expectation with no
    /// target file, registration, or hook event yields no `installed` claim,
    /// because nothing was read back to compare.
    pub installed: bool,
    /// Install surface plus live handshake.
    pub live: bool,
    /// `INSTALLED_NOT_LIVE`, `UNVERIFIED_PLAN_GAP`, or `NOT_INSTALLED`.
    ///
    /// `LIVE` is computed by the explicitly limited [`evaluate`] comparison
    /// only; the authoritative [`verify_profile`] gate never emits it because
    /// the handshake runner is absent (`PLAN_GAP` pending A-06 provider
    /// injection). `INSTALLED_NOT_LIVE` is emitted by [`verify_profile`] when
    /// every read-back file hash matches and the expectation names no
    /// registrations or hook events — the whole static surface is then
    /// evidenced — while no handshake was observed. An expectation naming no
    /// static surface at all reports `UNVERIFIED_PLAN_GAP`: nothing was named
    /// to read back, so nothing can be evidenced.
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

/// Install receipt contract minted by `eliot plugin install`
/// (`bins/eliot/src/plugin_preview.rs::install_with_rollback`). A document
/// carrying this contract is the preview-minted record itself — not a
/// hand-transcribed expectation — and is bound through
/// [`expectation_from_install_receipt`].
const INSTALL_RECEIPT_CONTRACT: &str = "eliot.plugin.install";

/// Loads an expectation document. The path must be absolute.
///
/// Two shapes are admitted: a plain expectation record (the
/// [`IntegrationExpectation`] contract), or the install receipt minted by
/// `eliot plugin install`, whose embedded preview record becomes the
/// expectation after its digest binding is verified. The receipt additionally
/// supplies the installation status it recorded
/// ([`LoadedExpectation::install_status`]); a plain expectation record supplies
/// none, and none is invented for it. Verification mismatches stay data inside
/// the report either way; only malformed inputs are `Err`.
pub fn load_expectation(path: &Path) -> Result<LoadedExpectation, IntegrationError> {
    if !path.is_absolute() {
        return Err(IntegrationError::InputInvalid(
            "expectation path must be absolute".to_owned(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| IntegrationError::InputRead {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| IntegrationError::InputInvalid(error.to_string()))?;
    if document.get("contract").and_then(serde_json::Value::as_str)
        == Some(INSTALL_RECEIPT_CONTRACT)
    {
        return expectation_from_install_receipt(&document);
    }
    let expectation: IntegrationExpectation = serde_json::from_value(document)
        .map_err(|error| IntegrationError::InputInvalid(error.to_string()))?;
    if expectation.profile.trim().is_empty() {
        return Err(IntegrationError::InputInvalid(
            "expectation profile must be non-empty".to_owned(),
        ));
    }
    // A plain expectation record states no installation status, so none is
    // carried. Absence is not read as success and not read as failure: the
    // record makes no claim about whether an install ran, and this front door
    // does not invent one on its behalf.
    Ok(LoadedExpectation {
        expectation,
        install_status: None,
    })
}

/// Extracts the verification expectation from an install receipt, binding
/// post-installation verification to the exact preview record the
/// installation was previewed with.
///
/// Fail-closed input checks only; observation authority is unchanged. The
/// receipt's embedded `preview.expected_coverage_profile` becomes the
/// expectation, and only after two coherence proofs: the embedded `preview`
/// object re-hashes to the receipt's `preview_digest`
/// (`sha256_hex(canonical_json_bytes(preview))`, the same rule the preview
/// front door mints), and the coverage profile names the receipt's own
/// `profile`. A missing digest, a digest mismatch, or a cross-profile chain
/// is a typed input error, never a degraded verification: checking against
/// bytes the preview never minted could promote a forged expectation into an
/// installed claim.
fn expectation_from_install_receipt(
    document: &serde_json::Value,
) -> Result<LoadedExpectation, IntegrationError> {
    let profile = document
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .filter(|profile| !profile.trim().is_empty())
        .ok_or_else(|| {
            IntegrationError::InputInvalid(
                "install receipt carries no non-empty profile".to_owned(),
            )
        })?;
    let preview = document.get("preview").ok_or_else(|| {
        IntegrationError::InputInvalid(
            "install receipt carries no preview record to verify against".to_owned(),
        )
    })?;
    let digest = document
        .get("preview_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IntegrationError::InputInvalid(
                "install receipt carries no preview digest; refusing to verify against an unbound record"
                    .to_owned(),
            )
        })?;
    let recomputed = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(preview)
            .map_err(|error| IntegrationError::InputInvalid(error.to_string()))?,
    );
    if recomputed != digest {
        return Err(IntegrationError::InputInvalid(
            "install receipt preview digest mismatch: the embedded preview record does not match preview_digest; refusing a drifted expectation"
                .to_owned(),
        ));
    }
    let coverage = preview.get("expected_coverage_profile").ok_or_else(|| {
        IntegrationError::InputInvalid(
            "install receipt preview carries no expected coverage profile".to_owned(),
        )
    })?;
    let expectation: IntegrationExpectation = serde_json::from_value(coverage.clone())
        .map_err(|error| IntegrationError::InputInvalid(error.to_string()))?;
    if expectation.profile != profile {
        return Err(IntegrationError::InputInvalid(
            "install receipt coverage profile names a different profile than the receipt"
                .to_owned(),
        ));
    }
    Ok(LoadedExpectation {
        expectation,
        install_status: Some(install_status_from_receipt(document)?),
    })
}

/// Reads the installation status the delivery itself recorded in the install
/// receipt: `status`, `code`, and `completed`.
///
/// These are the receipt's own values, read as recorded — never recomputed
/// from what the read side holds, and never derived from the preview-digest
/// check, which proves only that the embedded preview is un-drifted and says
/// nothing about whether an install ran. A receipt that omits `completed` is
/// a typed input error rather than an assumed success: the one field that
/// decides whether an installation happened cannot be filled in by this front
/// door. `status` and `code` are carried verbatim for reporting, so a
/// `completed: true` receipt whose `status` still says the install was not
/// attempted is reported with both facts visible rather than reconciled away.
fn install_status_from_receipt(
    document: &serde_json::Value,
) -> Result<InstallStatus, IntegrationError> {
    let status = document
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IntegrationError::InputInvalid(
                "install receipt carries no installation status; refusing to report an installation whose outcome the record does not state"
                    .to_owned(),
            )
        })?;
    let code = document
        .get("code")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            IntegrationError::InputInvalid(
                "install receipt carries no installation code; refusing to report an installation whose outcome the record does not state"
                    .to_owned(),
            )
        })?;
    let completed = document
        .get("completed")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            IntegrationError::InputInvalid(
                "install receipt carries no boolean completed flag; refusing to assume an installation happened"
                    .to_owned(),
            )
        })?;
    Ok(InstallStatus {
        status: status.to_owned(),
        code: code.to_owned(),
        completed,
    })
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
///
/// Explicitly limited, non-authoritative pure comparison: both inputs are
/// caller-supplied records, so this function establishes no installation or
/// liveness fact. Only [`verify_profile`] issues verdicts, and only from
/// real file readback plus explicit unverified gaps.
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
        installation: None,
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
///
/// The expectation may be the install receipt minted by `eliot plugin
/// install`: its digest-bound embedded preview then becomes the expectation,
/// so verification checks the installation against the record it was
/// previewed with rather than a retyped copy, and the installation status it
/// recorded is reported separately as `installation` and withholds
/// `installed` when the receipt says the install did not complete. A receipt
/// that omits `status`/`code`/`completed` is a typed input error, never an
/// assumed install.
///
/// Authority rule: file hashes come from real readback — every named target
/// is re-hashed here and the caller-supplied `actual_file_hashes` map never
/// enters the verdict. There is no observation port for registrations, hook
/// events, or the handshake in this front door (`PLAN_GAP` pending A-06
/// provider injection), so caller-supplied lists and booleans stay capped to
/// unverified: any expected registration or hook event withholds `installed`
/// (`UNVERIFIED_PLAN_GAP` when the read-back hashes match, `NOT_INSTALLED`
/// otherwise), an expectation naming no static surface at all withholds it too
/// (nothing was read back to compare), and `live` is never granted. A fully
/// read-back static surface with no registration or hook-event expectation is
/// `INSTALLED_NOT_LIVE`. A forged `handshake_ok: true` can never yield a live
/// verdict.
pub fn verify_profile(
    profile: &str,
    expectation_path: &Path,
    observation_path: &Path,
) -> Result<serde_json::Value, IntegrationError> {
    if profile.trim().is_empty() {
        return Err(IntegrationError::EmptyProfile);
    }
    let loaded = load_expectation(expectation_path)?;
    if loaded.expectation.profile != profile {
        return Err(IntegrationError::ProfileMismatch {
            requested: profile.to_owned(),
            carried: loaded.expectation.profile,
        });
    }
    let expected = &loaded.expectation;
    // Loaded for shape validation only; none of its claims are authority.
    let _supplied = load_observation(observation_path)?;
    // Real readback. Non-absolute targets cannot be observed without
    // inferring from the current directory, and unreadable targets have no
    // evidence: both stay absent from the map, which records them as gaps.
    let mut observed_actuals: BTreeMap<String, String> = BTreeMap::new();
    for path in expected.expected_file_hashes.keys() {
        let target = Path::new(path);
        if !target.is_absolute() {
            continue;
        }
        if let Ok(digest) = hash_file(target) {
            observed_actuals.insert(path.clone(), digest);
        }
    }
    let capped = IntegrationObservation {
        actual_file_hashes: observed_actuals,
        active_registrations: Vec::new(),
        observed_hook_events: Vec::new(),
        handshake_ok: false,
    };
    let mut report = evaluate(profile, expected, &capped);
    // The record's own installation status is reported beside the evidence,
    // never in place of it, and it gates `installed` on its own.
    report.installation.clone_from(&loaded.install_status);
    // Authority cap, scoped to the axes this front door cannot observe.
    // File hashes come from real readback above. Registrations and hook
    // events have no observation port, so any expectation naming them stays
    // unverified and withholds `installed`; the handshake has no runner, so
    // `live` is never granted here. A fully read-back static surface with no
    // registration or hook-event expectation is installed but not live; a
    // forged caller-supplied `handshake_ok: true` can never yield live, and an
    // expectation naming no static surface at all cannot yield `installed`
    // either, because nothing was read back to compare.
    report.live = false;
    let static_unverifiable =
        !expected.expected_registrations.is_empty() || !expected.expected_hook_events.is_empty();
    // An expectation that names no static surface at all — no target file, no
    // registration, no hook event — has nothing to read back: the loop above
    // iterates zero keys, and every comparison over an empty denominator is
    // vacuously true. Granting `installed` from it would certify an
    // installation on evidence that was never gathered, from a record that may
    // state no installation status of its own (`installation: null`). The same
    // guard that withholds `installed` for axes this front door cannot observe
    // therefore also covers an expectation that observes nothing; no new
    // disposition name is introduced, the existing `UNVERIFIED_PLAN_GAP`
    // reports it.
    let names_no_static_surface = expected.expected_file_hashes.is_empty()
        && expected.expected_registrations.is_empty()
        && expected.expected_hook_events.is_empty();
    // An install that the delivery itself recorded as not completed is not an
    // installation, whatever the bytes on disk happen to say. The receipt's
    // `completed` is the delivery's own claim about the install, and it
    // withholds `installed` on its own: a receipt recording a not-attempted,
    // failed, or incomplete install cannot be reported as installed, because
    // matching target bytes are evidence about files, not about an install
    // having run. No disposition is invented for this — an install the record
    // says did not complete is `NOT_INSTALLED`, which is exactly what it is.
    let install_not_completed = loaded
        .install_status
        .as_ref()
        .is_some_and(|status| !status.completed);
    if install_not_completed
        || static_unverifiable
        || names_no_static_surface
        || !report.file_hash_ok
    {
        report.installed = false;
        if report.file_hash_ok && !install_not_completed {
            "UNVERIFIED_PLAN_GAP".clone_into(&mut report.disposition);
        } else {
            "NOT_INSTALLED".clone_into(&mut report.disposition);
        }
    }
    Ok(report_json(&report))
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
        // `null` when the record stated no installation status: absence is
        // reported as absence, never as an assumed or default status.
        "installation": report.installation.as_ref().map_or(
            serde_json::Value::Null,
            |status| serde_json::json!({
                "status": status.status,
                "code": status.code,
                "completed": status.completed,
            }),
        ),
        "installed": report.installed,
        "live": report.live,
        "disposition": report.disposition,
        "note": "installation is the status the install receipt itself recorded (null when the expectation record carries none), reported separately from the evidence below: file hashes re-read from the named targets; registrations, hook events, and the handshake have no observation port (PLAN_GAP pending A-06). installed is granted only when every expected hash matches, the expectation names at least one static target, nothing unverifiable is expected, and the record does not state an incomplete install; live is never granted here",
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
    use std::path::PathBuf;

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

    fn profile_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("eliot-go19-1964-{tag}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_profile_docs(
        dir: &Path,
        expected_hashes: &BTreeMap<String, String>,
        supplied_actuals: &BTreeMap<String, String>,
        handshake_ok: bool,
    ) -> (PathBuf, PathBuf) {
        let expectation = IntegrationExpectation {
            profile: "demo".to_owned(),
            expected_file_hashes: expected_hashes.clone(),
            expected_registrations: vec!["demo-mcp".to_owned()],
            expected_hook_events: vec!["on_task".to_owned()],
        };
        let observation = IntegrationObservation {
            actual_file_hashes: supplied_actuals.clone(),
            active_registrations: vec!["demo-mcp".to_owned()],
            observed_hook_events: vec!["on_task".to_owned()],
            handshake_ok,
        };
        let expectation_path = dir.join("expectation.json");
        let observation_path = dir.join("observation.json");
        std::fs::write(
            &expectation_path,
            serde_json::to_vec(&expectation).expect("write expectation"),
        )
        .expect("write expectation file");
        std::fs::write(
            &observation_path,
            serde_json::to_vec(&observation).expect("write observation"),
        )
        .expect("write observation file");
        (expectation_path, observation_path)
    }

    #[test]
    fn cross_profile_expectation_is_rejected() {
        let dir = profile_dir("profile-mismatch");
        let (expectation_path, observation_path) =
            write_profile_docs(&dir, &BTreeMap::new(), &BTreeMap::new(), true);
        let error = verify_profile("other", &expectation_path, &observation_path)
            .expect_err("cross-profile expectation must not verify");
        assert!(matches!(error, IntegrationError::ProfileMismatch { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_supplied_observation_cannot_yield_live() {
        // Real target exists; every supplied record agrees, including a
        // forged handshake. Readback confirms the bytes, but no authority
        // exists for registrations, hook events, or liveness.
        let dir = profile_dir("forged-live");
        let target = dir.join("config.json");
        std::fs::write(&target, b"{\"bridge\":\"demo\"}").expect("write target");
        let digest = eliot_contracts::sha256_hex(b"{\"bridge\":\"demo\"}");
        let expected = BTreeMap::from([(target.display().to_string(), digest.clone())]);
        let supplied = BTreeMap::from([(target.display().to_string(), digest)]);
        let (expectation_path, observation_path) =
            write_profile_docs(&dir, &expected, &supplied, true);
        let value = verify_profile("demo", &expectation_path, &observation_path)
            .expect("gate runs on well-formed inputs");
        assert_eq!(value["file_hash"]["ok"], true);
        assert_eq!(value["handshake"]["ok"], false);
        assert_eq!(value["installed"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "UNVERIFIED_PLAN_GAP");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn readback_overrides_supplied_hash_claims() {
        // Supplied actuals disagree with reality in both directions: a forged
        // mismatch must not fail a matching file, and an agreeing forgery
        // must not pass a differing file.
        let dir = profile_dir("readback-wins");
        let target = dir.join("config.json");
        std::fs::write(&target, b"real-bytes").expect("write target");
        let real = eliot_contracts::sha256_hex(b"real-bytes");
        let forged = eliot_contracts::sha256_hex(b"forged-bytes");
        let expected = BTreeMap::from([(target.display().to_string(), real)]);
        let supplied = BTreeMap::from([(target.display().to_string(), forged.clone())]);
        let (expectation_path, observation_path) =
            write_profile_docs(&dir, &expected, &supplied, false);
        let value =
            verify_profile("demo", &expectation_path, &observation_path).expect("gate runs");
        assert_eq!(value["file_hash"]["ok"], true);

        let expected_wrong = BTreeMap::from([(target.display().to_string(), forged)]);
        let supplied_agreeing = expected_wrong.clone();
        let (expectation_path, observation_path) =
            write_profile_docs(&dir, &expected_wrong, &supplied_agreeing, true);
        let value =
            verify_profile("demo", &expectation_path, &observation_path).expect("gate runs");
        assert_eq!(value["file_hash"]["ok"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "NOT_INSTALLED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_expected_target_is_a_gap() {
        let dir = profile_dir("unreadable-target");
        let missing = dir.join("absent.json").display().to_string();
        let expected = BTreeMap::from([(missing.clone(), "ab".repeat(32))]);
        let (expectation_path, observation_path) =
            write_profile_docs(&dir, &expected, &BTreeMap::new(), false);
        let value =
            verify_profile("demo", &expectation_path, &observation_path).expect("gate runs");
        assert_eq!(value["file_hash"]["ok"], false);
        assert!(
            value["file_hash"]["gaps"]
                .as_array()
                .expect("gaps array")
                .iter()
                .any(|gap| gap == &missing)
        );
        assert_eq!(value["installed"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "NOT_INSTALLED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_expected_target_cannot_verify() {
        // Same legacy fixture, honest verdict: "config.json" is not absolute,
        // so no readback is possible without inferring from the working
        // directory. It is a gap, and no installed/live claim follows.
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
            .expect("gate runs on well-formed inputs");
        assert_eq!(value["file_hash"]["ok"], false);
        assert_eq!(value["installed"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "NOT_INSTALLED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expectation_naming_no_static_surface_cannot_report_installed() {
        // The defect this guards: a record naming nothing to check makes every
        // comparison vacuously true, so the gate used to certify `installed`
        // without reading back a single byte and while its own record stated
        // no installation status. Both admitted shapes must stay unevidenced.
        let dir = profile_dir("empty-denominator");
        let expectation_path = dir.join("expectation.json");
        let observation_path = dir.join("observation.json");
        std::fs::write(
            &expectation_path,
            serde_json::to_vec(&IntegrationExpectation {
                profile: "demo".to_owned(),
                expected_file_hashes: BTreeMap::new(),
                expected_registrations: Vec::new(),
                expected_hook_events: Vec::new(),
            })
            .expect("write expectation"),
        )
        .expect("write expectation file");
        std::fs::write(&observation_path, b"{}").expect("write observation file");
        let value =
            verify_profile("demo", &expectation_path, &observation_path).expect("gate runs");
        assert_eq!(value["installation"], serde_json::Value::Null);
        assert_eq!(value["installed"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "UNVERIFIED_PLAN_GAP");

        // Same rule on the receipt branch: the delivery's own `completed: true`
        // is reported beside the evidence, but a preview that named no target
        // has nothing to read back and still cannot yield an installed claim.
        let preview = serde_json::json!({
            "expected_coverage_profile": {
                "profile": "demo",
                "expected_file_hashes": {},
                "expected_registrations": [],
                "expected_hook_events": [],
            }
        });
        let digest = eliot_contracts::sha256_hex(
            &eliot_contracts::canonical_json_bytes(&preview).expect("canonical preview bytes"),
        );
        let receipt_path = dir.join("receipt.json");
        std::fs::write(
            &receipt_path,
            serde_json::to_vec(&serde_json::json!({
                "contract": INSTALL_RECEIPT_CONTRACT,
                "profile": "demo",
                "preview": preview,
                "preview_digest": digest,
                "status": "INSTALL_COMPLETED",
                "code": "OK",
                "completed": true,
            }))
            .expect("write receipt"),
        )
        .expect("write receipt file");
        let value = verify_profile("demo", &receipt_path, &observation_path).expect("gate runs");
        assert_eq!(value["installation"]["completed"], true);
        assert_eq!(value["installed"], false);
        assert_eq!(value["live"], false);
        assert_eq!(value["disposition"], "UNVERIFIED_PLAN_GAP");
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
