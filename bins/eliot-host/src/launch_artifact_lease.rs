//! Retained launch-artifact leases and approved-path validation.
//!
//! Canonical ELIOT anchors: `A5.5`
//! (`docs/architecture/A05-05-verifier-and-evaluation-contract.md`) scopes
//! verifier inputs and failure applicability, and `A13.2`
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`) separates Host,
//! Kernel, and Watchdog failure domains. `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`)
//! assigns Host approved-artifact ownership without project semantics, `I1.8`
//! (`docs/architecture/I01-08-exact-ownership-and-call-paths.md`) defines exact
//! ownership and call paths, `I2.23`
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//! requires a bounded extraction closure, and the storage boundary `I5.1`
//! (`docs/architecture/I05-01-storage-boundary.md`) limits Host protocol evidence
//! to immutable artifact/config hashes.
//!
//! This child only opens and validates already-approved immutable launch
//! artifacts and returns lease evidence. It cannot create, replace, or delete
//! artifacts; select generations; perform Host lifecycle, SCM, or Phase-B
//! transaction work; mutate credentials or semantic/canonical state; or own
//! authority.

use std::io;
use std::path::{Path, PathBuf};

use eliot_installation::{
    InstallationProfile, verify_approved_path, verify_file_digest_with_lease,
    verify_file_digest_with_user_lease,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    ProtectedPathLease, UserOwnedPathLease, UserOwnedRootLease, windows_paths_equal,
};

use super::super::HostError;
use super::super::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) launch-artifact observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. A call site passes a static phase token plus a bounded
// `LaunchPhaseCorrelation` built only from an identity handle the owner already
// holds and rendered through `crate::host_diagnostics::bound_field`, so a static
// label classifies the phase while the bounded identity names the artifact it
// concerned. This cell binds no identity of its own beyond one: the only slot
// any seam fills from its own arguments is the owner-supplied expected digest
// handle already in hand at a `verify_launch_digest` outcome, and every other
// identity slot of every record is exactly what the caller's forwarded
// correlation already held - so a locator or lease record can carry an
// `artifact` value this cell never supplied. This cell never re-derives any part
// of that correlation: it forwards it unchanged, and the single slot it sets
// itself is the digest handle chained onto it at a verification outcome, which
// OVERWRITES whatever `artifact` the caller had forwarded rather than merging
// with it. Never bound from anywhere: a
// recomputed, re-verified or re-read digest, artifact bytes (`read_bounded`), or
// arbitrary error `Debug`/`Display` text, so bounding limits size, not
// sensitivity (I15.4).
//
// A retained-artifact lease, locator or approved-path handle is a path, and a
// path is not an identity: `supplied`, the `approved` locator handle and
// `LaunchLease::path` are never bound into a diagnostic field, each proved
// against the records the seam that handles it really emitted and never
// against a locally rendered string: the locator and the approved handle on
// case 978/12's real `approved_locator` execution, `LaunchLease::path` on case
// 978/13's real `open_launch_lease` execution, which on this Windows-only cell
// is the only place that half of the claim is proven. This cell holds no
// `HostLaunchOptions`, owns no operation id, process-start identity, fence or
// typed reason and observes no process and no readiness, so it binds none of
// those identities itself; missing evidence stays explicitly `missing` rather
// than invented (cases 978/1, 978/4).
//
// The caller that already holds those identities forwards them instead of
// having them re-derived here: the locator, lease and digest seams below each
// have a `_with_correlation` twin that renders the caller's own
// `LaunchPhaseCorrelation` into every record the seam emits, so a locator or
// lease phase record names the installation, generation, operation, artifact,
// process-start, fence and reason the caller already held. A DIGEST record is the
// one exception this cell makes: at a verification outcome it chains the
// owner-supplied digest handle onto the forwarded correlation, and because
// `with_*` overwrites a slot rather than merging, that record's `artifact` names
// the digest under validation instead of whatever the caller had forwarded -
// stated here rather than left to be inferred from the builder. The Phase-B
// destination seam deliberately has no twin: its only
// production callers are `host_composition_phase_b.rs`, outside this lane's
// write scope, and it holds no correlation of its own to forward, so every
// record it emits stays uncorrelated and keeps each identity slot explicitly
// missing rather than borrowing an identity it was never given. Forwarding is
// pure — no twin derives, re-computes, re-reads or probes an identity, and the
// only slot any twin fills from its own arguments is the owner-supplied digest
// handle `verify_launch_digest` was already given. The identity-free seams stay
// the honest default: a call site that holds no correlation keeps them through
// the wrappers below, which forward `LaunchPhaseCorrelation::NONE` unchanged.
// Through a twin the "digest requested" record carries the identities the
// caller already held and adds no `artifact` of its own — the owner-supplied
// digest handle is chained on only after that record — so `artifact` is bound
// here exactly at the verification outcome.
//
// Sink outcome never alters result/order/count/handle/cleanup/timeout. There is
// no mutable global dedup cache and no terminal emission here: the designated
// terminal for one failed launch is `lib.rs`'s
// `HostTerminalGuard` on the OUTER contour (`BOUNDARY_OPEN_TERMINAL` on the STARTUP
// path; a cutover-path launch by `BOUNDARY_BACKUP_CUTOVER_TERMINAL`, a phase-B resume by `BOUNDARY_RESUME_PENDING_TERMINAL` instead), and
// the `start_approved` leaf guard is phase-only (#978 audit defect 2), so this cell
// cannot emit a second terminal. Retained identity on
// substitution failure is preserved (case 978/3); digest/descriptor rejections
// stay typed (case 978/2).
fn launch_artifact_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

fn launch_artifact_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    launch_artifact_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        &detail,
    );
}

/// Retained ownership of an approved launch artifact.
pub(crate) enum LaunchLease {
    Protected(ProtectedPathLease),
    Portable(UserOwnedPathLease),
}

impl LaunchLease {
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::Protected(lease) => lease.path(),
            Self::Portable(lease) => lease.path(),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), String> {
        match self {
            Self::Protected(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
            Self::Portable(lease) => lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| error.to_string()),
        }
    }

    pub(crate) fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, String> {
        match self {
            Self::Protected(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
            Self::Portable(lease) => lease.read_bounded(limit).map_err(|error| error.to_string()),
        }
    }
}

pub(crate) fn approved_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — locator requested; no admitted identity is in hand.
    approved_locator_with_correlation(&LaunchPhaseCorrelation::NONE, supplied, approved, profile)
}

/// [`approved_locator`] with the caller's already-held launch correlation
/// forwarded to every record this seam emits.
///
/// Identical body, phase literals, order, returns and error mapping; the only
/// difference is the correlation each observation receives. The forwarded slots
/// are rendered through `crate::host_diagnostics::bound_field` by
/// `LaunchPhaseCorrelation::render`, so this twin re-derives nothing and binds
/// no locator, approved handle or canonical path of its own (I15.4).
pub(crate) fn approved_locator_with_correlation(
    correlation: &LaunchPhaseCorrelation<'_>,
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — locator requested; the caller's already-held
    // identities are forwarded and nothing is derived here.
    launch_artifact_observe("host.launch-artifact locator requested", correlation);
    if profile != InstallationProfile::PortableDev {
        let result =
            verify_approved_path(supplied, approved, "runtime.approved_locator").map_err(|error| {
                // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                launch_artifact_observe("host.launch-artifact substitution preserved", correlation);
                HostError::ProcessContour(error.to_string())
            });
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — locator admitted.
            launch_artifact_observe("host.launch-artifact locator admitted", correlation);
        }
        return result;
    }
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact locator typed rejection", correlation);
        return Err(HostError::ProcessContour(
            "portable locator must be absolute".to_owned(),
        ));
    }
    let canonical_supplied = std::fs::canonicalize(supplied).map_err(|error| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe("host.launch-artifact locator typed rejection", correlation);
        HostError::ProcessContour(error.to_string())
    })?;
    let canonical_approved =
        std::fs::canonicalize(Path::new(approved.as_str())).map_err(|error| {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact locator typed rejection", correlation);
            HostError::ProcessContour(error.to_string())
        })?;
    if canonical_supplied != canonical_approved {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe("host.launch-artifact substitution preserved", correlation);
        return Err(HostError::ProcessContour(
            "portable locator is not the approved canonical path".to_owned(),
        ));
    }
    // The retained portable root lease and every child path must stay in the
    // same declared DOS-path namespace. `std::fs::canonicalize` adds a
    // verbatim prefix on Windows, which would make the exact root-containment
    // proof reject an otherwise identical approved child.
    // WORK_UNIT_CASE: 978/1 — locator admitted.
    launch_artifact_observe("host.launch-artifact locator admitted", correlation);
    Ok(supplied.to_path_buf())
}

pub(crate) fn approved_phase_b_destination_locator(
    supplied: &Path,
    approved: &PlatformHandle,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PathBuf, HostError> {
    // WORK_UNIT_CASE: 978/1 — phase-b destination requested; no admitted identity
    // is in hand.
    launch_artifact_observe(
        "host.launch-artifact phase-b destination requested",
        &LaunchPhaseCorrelation::NONE,
    );
    if profile != InstallationProfile::PortableDev {
        let result = approved_locator(supplied, approved, profile);
        if result.is_ok() {
            // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
            launch_artifact_observe(
                "host.launch-artifact phase-b destination admitted",
                &LaunchPhaseCorrelation::NONE,
            );
        }
        return result;
    }
    let root = portable_root.ok_or_else(|| {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact phase-b destination typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        HostError::ProcessContour("portable root lease is missing".to_owned())
    })?;
    if !supplied.is_absolute() {
        // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
        launch_artifact_observe(
            "host.launch-artifact phase-b destination typed rejection",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator must be absolute".to_owned(),
        ));
    }
    let approved_path = Path::new(approved.as_str());
    if !approved_path.is_absolute() || !windows_paths_equal(supplied, approved_path) {
        // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
        launch_artifact_observe(
            "host.launch-artifact phase-b substitution preserved",
            &LaunchPhaseCorrelation::NONE,
        );
        return Err(HostError::ProcessContour(
            "portable Phase-B destination locator is not the approved path".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(supplied) {
        Ok(_) => {
            let result = approved_locator(supplied, approved, profile);
            if result.is_ok() {
                // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
                launch_artifact_observe(
                    "host.launch-artifact phase-b destination admitted",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
            result
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let result = root
                .validate_child_parent(supplied)
                .map_err(|error| HostError::ProcessContour(error.to_string()));
            match result {
                Ok(()) => {
                    // WORK_UNIT_CASE: 978/1 — phase-b destination admitted.
                    launch_artifact_observe(
                        "host.launch-artifact phase-b destination admitted",
                        &LaunchPhaseCorrelation::NONE,
                    );
                    Ok(supplied.to_path_buf())
                }
                Err(error) => {
                    // WORK_UNIT_CASE: 978/3 — substitution preserved, retained identity only.
                    launch_artifact_observe(
                        "host.launch-artifact phase-b substitution preserved",
                        &LaunchPhaseCorrelation::NONE,
                    );
                    Err(error)
                }
            }
        }
        Err(error) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe(
                "host.launch-artifact phase-b destination typed rejection",
                &LaunchPhaseCorrelation::NONE,
            );
            Err(HostError::RecoveryRequired(format!(
                "Phase-B destination cannot be observed: {error}"
            )))
        }
    }
}

pub(crate) fn open_launch_lease(
    profile: InstallationProfile,
    root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    // WORK_UNIT_CASE: 978/1 — lease requested; a lease handle is a path, so no
    // identity is in hand.
    open_launch_lease_with_correlation(&LaunchPhaseCorrelation::NONE, profile, root, path)
}

/// [`open_launch_lease`] with the caller's already-held launch correlation
/// forwarded to every record this seam emits.
///
/// Identical body, phase literals, order, retained handle, returns and error
/// mapping; the only difference is the correlation each observation receives. A
/// retained lease is a path, so this twin binds no lease path, root or handle —
/// only the forwarded, already-held identities (I15.4).
pub(crate) fn open_launch_lease_with_correlation(
    correlation: &LaunchPhaseCorrelation<'_>,
    profile: InstallationProfile,
    root: Option<&UserOwnedRootLease>,
    path: &Path,
) -> Result<LaunchLease, HostError> {
    // WORK_UNIT_CASE: 978/1 — lease requested; a lease handle is a path, so this
    // seam binds none itself and forwards only what the caller already held.
    launch_artifact_observe("host.launch-artifact lease requested", correlation);
    let result = match profile {
        InstallationProfile::PortableDev => {
            let root = root.ok_or_else(|| {
                HostError::ProcessContour("portable root lease is missing".to_owned())
            })?;
            Ok(LaunchLease::Portable(
                UserOwnedPathLease::open_existing(root, path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
        InstallationProfile::SystemService | InstallationProfile::UserMode => {
            Ok(LaunchLease::Protected(
                ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            ))
        }
    };
    match &result {
        Ok(_) => {
            // WORK_UNIT_CASE: 978/1 — lease admitted, exact handle preserved.
            launch_artifact_observe("host.launch-artifact lease admitted", correlation);
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact lease typed rejection", correlation);
        }
    }
    result
}

pub(crate) fn verify_launch_digest(
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — digest requested; no verification outcome exists
    // yet, so no artifact identity is bound.
    verify_launch_digest_with_correlation(&LaunchPhaseCorrelation::NONE, lease, digest, field)
}

/// [`verify_launch_digest`] with the caller's already-held launch correlation
/// forwarded to every record this seam emits, including the outcome records'
/// artifact slot.
///
/// Identical body, phase literals, order, returns and error mapping. The
/// outcome correlation chains the owner's already-held `digest` handle onto the
/// forwarded one exactly as before, so the record names the identity the owner
/// supplied; nothing is recomputed, re-verified or re-read from the artifact
/// (I15.4).
pub(crate) fn verify_launch_digest_with_correlation(
    correlation: &LaunchPhaseCorrelation<'_>,
    lease: &LaunchLease,
    digest: &PlatformHandle,
    field: &str,
) -> Result<(), HostError> {
    // WORK_UNIT_CASE: 978/1 — digest requested; no verification outcome exists
    // yet, so this record adds no artifact identity of its own and forwards only
    // what the caller already held.
    launch_artifact_observe("host.launch-artifact digest requested", correlation);
    let result = match lease {
        LaunchLease::Protected(lease) => verify_file_digest_with_lease(lease, digest, field),
        LaunchLease::Portable(lease) => verify_file_digest_with_user_lease(lease, digest, field),
    };
    let result = result.map_err(|error| HostError::ProcessContour(error.to_string()));
    // The owner-supplied expected digest handle is already in hand here and is
    // bound verbatim onto the forwarded correlation; it is not recomputed,
    // re-verified or re-read.
    let correlation = correlation.with_artifact(digest.as_str());
    match &result {
        Ok(()) => {
            // WORK_UNIT_CASE: 978/1 — digest admitted.
            launch_artifact_observe("host.launch-artifact digest admitted", &correlation);
        }
        Err(_) => {
            // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted.
            launch_artifact_observe("host.launch-artifact digest typed rejection", &correlation);
        }
    }
    result
}

// F-LOG-HOST-3 (#978) inline proof for this cell's private observation
// contract. Every case below executes the real instrumented functions through
// their existing seams - `approved_locator`, `approved_phase_b_destination_locator`,
// `open_launch_lease` and `verify_launch_digest`, and the three
// `_with_correlation` twins added for the first, third and fourth of those -
// and none of them returns early: an unwritable
// fixture or an unusable handle panics instead of skipping, so a case cannot
// pass without having driven its seam. The cases that assert on emitted
// records read them back out of a scoped `tracing` subscriber over the real
// emission, so no case compares this cell against a string it rendered itself;
// no case widens visibility and none restates locator or digest validation.
// The digest decisions of this cell are executed here in-crate on Windows
// through the same seam the launch owner uses: a real `UserOwnedRootLease`
// from the existing temporary root, the real `open_launch_lease`, and the
// real `verify_launch_digest` (cases 978/2, 978/13) — so only the cross-file
// corpus stays with the integration fixture owner.
#[cfg(test)]
mod tests {
    use super::{
        HostError, LaunchPhaseCorrelation, approved_locator, approved_locator_with_correlation,
        approved_phase_b_destination_locator, open_launch_lease,
        open_launch_lease_with_correlation, verify_launch_digest,
        verify_launch_digest_with_correlation,
    };
    use eliot_installation::InstallationProfile;
    use eliot_platform::PlatformHandle;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;

    const PROFILE: InstallationProfile = InstallationProfile::PortableDev;
    const RELATIVE_CANARY: &str = "978-canary-relative.bin";
    const RELATIVE_REJECTION: &str = "portable locator must be absolute";
    const MISSING_ROOT_REJECTION: &str = "portable root lease is missing";
    const SUBSTITUTION_REJECTION: &str = "portable locator is not the approved canonical path";

    /// The outcome phase tokens this cell really emits, so a case proves the
    /// record it asserts on was emitted by the instrumented seam it names.
    const LOCATOR_REQUESTED_PHASE: &str = "host.launch-artifact locator requested";
    const LOCATOR_REJECTED_PHASE: &str = "host.launch-artifact locator typed rejection";
    const LOCATOR_ADMITTED_PHASE: &str = "host.launch-artifact locator admitted";
    const PHASE_B_REJECTED_PHASE: &str = "host.launch-artifact phase-b destination typed rejection";
    const LEASE_REQUESTED_PHASE: &str = "host.launch-artifact lease requested";
    const LEASE_REJECTED_PHASE: &str = "host.launch-artifact lease typed rejection";
    #[cfg(windows)]
    const DIGEST_REQUESTED_PHASE: &str = "host.launch-artifact digest requested";
    #[cfg(windows)]
    const DIGEST_ADMITTED_PHASE: &str = "host.launch-artifact digest admitted";
    #[cfg(windows)]
    const DIGEST_REJECTED_PHASE: &str = "host.launch-artifact digest typed rejection";
    #[cfg(windows)]
    const LEASE_ADMITTED_PHASE: &str = "host.launch-artifact lease admitted";

    /// The correlation slots this cell can never prove: it holds no launch
    /// options, operation id, process identity, fence or reason of its own.
    const UNPROVEN_SLOTS: [&str; 6] = [
        "installation",
        "generation",
        "operation",
        "process_start",
        "fence",
        "reason",
    ];

    /// The bare file name of the approved artifact, so a case can prove that
    /// even a name fragment never reaches a record.
    const ARTIFACT_FILE_NAME: &str = "978-canary-approved-artifact.bin";
    /// Known bytes the approved artifact holds: a real digest decision is
    /// admitted only for content that hashes to the owner's expected digest,
    /// so the fixture must hold content the owner can name.
    const ARTIFACT_BYTES: &[u8] = b"978 approved launch artifact bytes";
    /// Different known bytes: the substituted content a retained artifact is
    /// proven against while the owner's approved digest stays in hand.
    const SUBSTITUTED_ARTIFACT_BYTES: &[u8] = b"978 substituted launch artifact bytes";

    /// Forwards to the real portable locator request of this cell, so a case
    /// never restates the profile it exercises.
    fn portable_locator(supplied: &Path, approved: &PlatformHandle) -> Result<PathBuf, HostError> {
        approved_locator(supplied, approved, PROFILE)
    }

    /// The typed rejection reason, so a case asserts the exact retained text of
    /// the one error variant this cell produces.
    fn typed_reason(error: &HostError) -> Option<&str> {
        match error {
            HostError::ProcessContour(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    /// Field visitor: keeps the names and values an event really wrote, so a
    /// case asserts on production output and never on its own formatting.
    #[derive(Default)]
    struct EmittedFields {
        entries: Vec<(String, String)>,
    }

    impl Visit for EmittedFields {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.entries
                .push((field.name().to_owned(), value.to_owned()));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.entries
                .push((field.name().to_owned(), value.to_string()));
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.entries
                .push((field.name().to_owned(), value.to_string()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.entries
                .push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    /// One record exactly as this cell's emission path wrote it.
    #[derive(Debug)]
    struct EmittedRecord {
        target: String,
        fields: Vec<(String, String)>,
    }

    impl EmittedRecord {
        /// The bounded structured detail production rendered for one phase.
        fn detail(&self) -> &str {
            self.field("detail").unwrap_or_default()
        }

        /// One emitted field value, by the name production gave it.
        fn field(&self, name: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }

        /// Every emitted value in one haystack, so a canary is proven absent
        /// from the whole record, not only from its detail.
        fn values(&self) -> String {
            let mut values = self.target.clone();
            for (key, value) in &self.fields {
                values.push(' ');
                values.push_str(key);
                values.push('=');
                values.push_str(value);
            }
            values
        }
    }

    /// Records every event the scoped subscriber receives, before any sink
    /// formatting, so a case reads what production actually wrote.
    struct RecordingLayer {
        records: Arc<Mutex<Vec<EmittedRecord>>>,
    }

    impl<S> Layer<S> for RecordingLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut fields = EmittedFields::default();
            event.record(&mut fields);
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(EmittedRecord {
                    target: event.metadata().target().to_owned(),
                    fields: fields.entries,
                });
        }
    }

    /// Runs one production execution under a scoped subscriber and returns its
    /// own outcome beside the records that execution really emitted.
    fn recorded<T>(emit: impl FnOnce() -> T) -> (T, Vec<EmittedRecord>) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(RecordingLayer {
            records: Arc::clone(&records),
        });
        let outcome = tracing::subscriber::with_default(subscriber, emit);
        let mut captured = records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (outcome, std::mem::take(&mut *captured))
    }

    /// Every record whose real emission carries one phase token, in order.
    fn phase_records<'a>(records: &'a [EmittedRecord], phase: &str) -> Vec<&'a EmittedRecord> {
        records
            .iter()
            .filter(|record| record.detail().contains(phase))
            .collect()
    }

    /// The one record whose real emission carries one phase token, so no case
    /// can pass on an outcome the instrumented seam never emitted.
    fn one_phase_record<'a>(records: &'a [EmittedRecord], phase: &str) -> &'a EmittedRecord {
        let matched = phase_records(records, phase);
        assert_eq!(matched.len(), 1, "exactly one record carries {phase}");
        matched[0]
    }

    /// The value one correlation slot carries in a real emission, so a case reads
    /// the field production wrote instead of restating the rendered format.
    fn slot<'a>(detail: &'a str, key: &str) -> Option<&'a str> {
        detail.split(' ').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    /// The distinct path strings this fixture owns, so a canary is proven absent
    /// even when only part of a path could reach a record.
    fn path_canaries(artifact: &ApprovedArtifact) -> Vec<String> {
        let root_name = artifact.root.file_name().unwrap_or_default();
        vec![
            artifact.file.to_string_lossy().into_owned(),
            artifact.root.to_string_lossy().into_owned(),
            ARTIFACT_FILE_NAME.to_owned(),
            root_name.to_string_lossy().into_owned(),
            std::env::temp_dir().to_string_lossy().into_owned(),
        ]
    }

    /// Asserts that no field of any record carries one canary value, so a proof
    /// covers the whole record and not only its detail.
    fn assert_no_record_carries(records: &[EmittedRecord], canaries: &[String], label: &str) {
        for emitted in records {
            let values = emitted.values();
            for canary in canaries {
                assert!(
                    !values.contains(canary.as_str()),
                    "{label} must never reach a record: {values}"
                );
            }
        }
    }

    /// Asserts that no record of one refused execution claims an admission:
    /// every admission phase token this cell emits ends in `admitted`, so one
    /// vocabulary check covers the locator, Phase-B destination, lease and
    /// digest admissions a refused path could wrongly publish.
    fn assert_admits_nothing(records: &[EmittedRecord]) {
        for emitted in records {
            assert!(
                !emitted.detail().contains("admitted"),
                "a refused execution emits no admission record: {}",
                emitted.detail()
            );
        }
    }

    /// Asserts the observation contract of one request record: this cell holds
    /// no `HostLaunchOptions`, no operation id, no process-start identity, no
    /// fence and no typed reason, and a request precedes its own outcome, so
    /// `artifact` and every unproven slot stay the frozen explicit-absence
    /// marker and the record claims no readiness. `request` is the record the
    /// request call site itself emitted.
    fn assert_request_binds_nothing(request: &EmittedRecord) {
        let detail = request.detail();
        assert_eq!(
            slot(detail, "artifact"),
            Some("missing"),
            "a request precedes its own outcome, so it binds no artifact identity: {detail}"
        );
        for unproven in UNPROVEN_SLOTS {
            assert_eq!(
                slot(detail, unproven),
                Some("missing"),
                "this cell owns no {unproven} identity, so a request cannot bind it: {detail}"
            );
        }
        assert!(
            !detail.contains("ready"),
            "a request claims no readiness: {detail}"
        );
    }

    /// Asserts the digest-decision contract against the records a real
    /// verification emitted: one request per decision that binds no identity,
    /// exactly one admitted record and one typed rejection, both carrying the
    /// owner's approved digest and inventing no other identity, and no canary.
    #[cfg(windows)]
    fn assert_digest_decisions(
        records: &[EmittedRecord],
        approved: &str,
        canaries: &[String],
        recomputed: &[String],
    ) {
        let requests = phase_records(records, DIGEST_REQUESTED_PHASE);
        assert_eq!(requests.len(), 2, "each digest decision requests once");
        for each_request in requests {
            assert_eq!(
                slot(each_request.detail(), "artifact"),
                Some("missing"),
                "a request precedes its own outcome: {}",
                each_request.detail()
            );
        }
        let admitted = one_phase_record(records, DIGEST_ADMITTED_PHASE);
        let rejected = one_phase_record(records, DIGEST_REJECTED_PHASE);
        for decision in [admitted, rejected] {
            assert_eq!(
                slot(decision.detail(), "artifact"),
                Some(approved),
                "the retained artifact identity is the owner-supplied approved digest: {}",
                decision.detail()
            );
            for unproven in UNPROVEN_SLOTS {
                assert_eq!(
                    slot(decision.detail(), unproven),
                    Some("missing"),
                    "this cell owns no {unproven} identity: {}",
                    decision.detail()
                );
            }
        }
        for phase in [LEASE_REQUESTED_PHASE, LEASE_ADMITTED_PHASE] {
            assert_eq!(
                phase_records(records, phase).len(),
                1,
                "exactly one record carries {phase}"
            );
        }
        assert_no_record_carries(records, canaries, "a retained path, root or handle");
        assert_no_record_carries(records, recomputed, "a recomputed digest");
    }

    /// One temporary approved artifact, so the portable branch runs its real
    /// `canonicalize` comparison and its real digest decision against an
    /// existing location.
    struct ApprovedArtifact {
        root: PathBuf,
        file: PathBuf,
    }

    impl ApprovedArtifact {
        fn create(label: &str) -> Option<Self> {
            let name = format!("eliot-978-{label}-{}", std::process::id());
            let root = std::env::temp_dir().join(name);
            let file = root.join(ARTIFACT_FILE_NAME);
            if std::fs::create_dir_all(&root).is_err()
                || std::fs::write(&file, ARTIFACT_BYTES).is_err()
            {
                return None;
            }
            Some(Self { root, file })
        }

        /// The approved artifact itself: the identity whose match is admitted.
        fn approved_handle(&self) -> Option<PlatformHandle> {
            PlatformHandle::new(self.file.to_string_lossy().into_owned()).ok()
        }

        /// A different existing location: a substitution, not a missing path.
        fn substituted_handle(&self) -> Option<PlatformHandle> {
            PlatformHandle::new(self.root.to_string_lossy().into_owned()).ok()
        }
    }

    impl Drop for ApprovedArtifact {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.file);
            let _ = std::fs::remove_dir(&self.root);
        }
    }

    // WORK_UNIT_CASE: 978/1 — admission returns the exact retained locator
    #[test]
    fn portable_locator_admits_the_approved_artifact_unchanged() {
        let Some(artifact) = ApprovedArtifact::create("admitted") else {
            panic!("the approved artifact fixture must be writable in this environment");
        };
        let Some(approved) = artifact.approved_handle() else {
            panic!("the approved artifact path must be a valid platform handle");
        };
        let Ok(admitted) = portable_locator(&artifact.file, &approved) else {
            panic!("the approved locator must stay admitted");
        };
        assert_eq!(
            admitted, artifact.file,
            "admission returns the retained locator"
        );
    }

    // WORK_UNIT_CASE: 978/2 — locator rejections stay typed
    #[test]
    fn locator_rejections_stay_typed_and_admit_nothing() {
        let Ok(approved) = PlatformHandle::new("C:\\Eliot\\978-canary-approved.bin") else {
            panic!("the approved canary handle must be a valid platform handle");
        };
        let relative = Path::new(RELATIVE_CANARY);
        // Both refused executions run inside one scoped subscriber, so the
        // "admits nothing" half of this case's name is proved against the
        // records those executions really emitted.
        let (refusals, records) = recorded(|| {
            let locator = portable_locator(relative, &approved);
            let destination =
                approved_phase_b_destination_locator(relative, &approved, PROFILE, None);
            (locator, destination)
        });
        let (locator, destination) = refusals;
        let Err(error) = locator else {
            panic!("a relative portable locator must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(RELATIVE_REJECTION));
        let Err(error) = destination else {
            panic!("a Phase-B destination without the portable root must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(MISSING_ROOT_REJECTION));
        // Each seam really published its own typed rejection, and neither
        // refusal carries an artifact identity, so the admission check below
        // cannot pass on an execution that refused silently or admitted one.
        let locator_rejected = one_phase_record(&records, LOCATOR_REJECTED_PHASE);
        assert_eq!(
            slot(locator_rejected.detail(), "artifact"),
            Some("missing"),
            "a refused locator admitted nothing, so it binds no artifact identity: {}",
            locator_rejected.detail()
        );
        let destination_rejected = one_phase_record(&records, PHASE_B_REJECTED_PHASE);
        assert_eq!(
            slot(destination_rejected.detail(), "artifact"),
            Some("missing"),
            "a refused Phase-B destination admitted nothing, so it binds no artifact identity: {}",
            destination_rejected.detail()
        );
        assert_admits_nothing(&records);
    }

    // WORK_UNIT_CASE: 978/3 — substitution keeps the exact typed rejection
    #[test]
    fn substituted_locator_keeps_the_exact_typed_rejection() {
        let Some(artifact) = ApprovedArtifact::create("substituted") else {
            panic!("the substituted artifact fixture must be writable in this environment");
        };
        let Some(approved) = artifact.substituted_handle() else {
            panic!("the substituted artifact root must be a valid platform handle");
        };
        let Err(error) = portable_locator(&artifact.file, &approved) else {
            panic!("a substituted locator must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(SUBSTITUTION_REJECTION));
    }

    // WORK_UNIT_CASE: 978/4 — a request observes no process and no readiness
    #[test]
    fn a_lease_request_is_not_a_process_start_or_readiness_observation() {
        let (requested, records) =
            recorded(|| open_launch_lease(PROFILE, None, Path::new(RELATIVE_CANARY)));
        let Err(error) = requested else {
            panic!("a lease request without the portable root must stay rejected");
        };
        assert_eq!(typed_reason(&error), Some(MISSING_ROOT_REJECTION));
        // The record that request really emitted, not a string this case
        // rendered itself: every slot this cell can never prove, plus the
        // artifact it does not hold yet, must read as the frozen explicit
        // absence marker.
        assert_request_binds_nothing(one_phase_record(&records, LEASE_REQUESTED_PHASE));
    }

    // WORK_UNIT_CASE: 978/12 — no locator, lease or handle value reaches a record
    #[test]
    fn retained_artifact_records_never_carry_a_locator_or_lease_path() {
        let Some(artifact) = ApprovedArtifact::create("no-path") else {
            panic!("the approved artifact fixture must be writable in this environment");
        };
        let Some(approved) = artifact.approved_handle() else {
            panic!("the approved artifact path must be a valid platform handle");
        };
        // Read back from the records that execution really emitted: a retained
        // lease, a locator and an approved handle are paths, so none of them is
        // bound into any field of any record.
        let (admitted, records) = recorded(|| portable_locator(&artifact.file, &approved));
        let Ok(admitted) = admitted else {
            panic!("the approved locator must stay admitted");
        };
        assert_eq!(
            admitted, artifact.file,
            "admission returns the retained locator"
        );
        let admitted_record = one_phase_record(&records, LOCATOR_ADMITTED_PHASE);
        assert_eq!(
            slot(admitted_record.detail(), "artifact"),
            Some("missing"),
            "a path is not an identity: {}",
            admitted_record.detail()
        );
        assert_no_record_carries(
            &records,
            &path_canaries(&artifact),
            "a retained locator, root or handle",
        );
    }

    // WORK_UNIT_CASE: 978/4 — a requested artifact that is absent is never admitted
    // as an approved locator and never retained as a lease, so the request is not an
    // observation of anything.
    #[test]
    fn an_absent_requested_artifact_is_never_admitted_or_retained() {
        let Some(artifact) = ApprovedArtifact::create("absent") else {
            panic!("the absent-artifact fixture must be writable in this environment");
        };
        let Some(approved) = artifact.approved_handle() else {
            panic!("the approved artifact path must be a valid platform handle");
        };
        // Created only by `ApprovedArtifact`; this locator never exists.
        let absent = artifact.root.join("978-canary-absent-artifact.bin");
        // Both refusals run inside one scoped subscriber, so the typed reason
        // and the observation records below are the ones these real executions
        // produced. Neither refusal text is written by this cell: the locator
        // refuses with the canonicalization error the OS returned for the absent
        // path, and the lease refuses inside the protected-path contour, so the
        // exact variant is the part this cell owns and the text is the
        // producer's.
        let (refusals, records) = recorded(|| {
            let locator = portable_locator(&absent, &approved);
            let lease = open_launch_lease(InstallationProfile::UserMode, None, &absent);
            (locator, lease)
        });
        let (locator, lease) = refusals;
        let Err(error) = locator else {
            panic!("an absent artifact must never be admitted as an approved locator");
        };
        assert!(
            typed_reason(&error).is_some(),
            "an absent locator must stay the typed ProcessContour refusal it returns: {error}"
        );
        let Err(error) = lease else {
            panic!("an absent artifact must never retain a lease handle");
        };
        assert!(
            typed_reason(&error).is_some(),
            "an absent lease must stay the typed ProcessContour refusal it returns: {error}"
        );
        // Each refused seam really emitted its request and its typed rejection,
        // and a refused execution admits nothing at all.
        assert_eq!(
            phase_records(&records, LOCATOR_REJECTED_PHASE).len(),
            1,
            "the refused locator publishes exactly one typed rejection"
        );
        assert_eq!(
            phase_records(&records, LEASE_REJECTED_PHASE).len(),
            1,
            "the refused lease publishes exactly one typed rejection"
        );
        assert_admits_nothing(&records);
        // The request itself observes nothing: both requests this case drove
        // bind no identity at all, so the request is not an observation.
        assert_request_binds_nothing(one_phase_record(&records, LOCATOR_REQUESTED_PHASE));
        assert_request_binds_nothing(one_phase_record(&records, LEASE_REQUESTED_PHASE));
    }

    // WORK_UNIT_CASE: 978/12 — the locator canary reaches neither the typed rejection
    // text nor the record, so a rejected locator is never echoed back to the operator.
    #[test]
    fn typed_locator_rejections_never_echo_the_supplied_locator() {
        let Ok(approved) = PlatformHandle::new("C:\\Eliot\\978-canary-approved.bin") else {
            panic!("the approved canary handle must be a valid platform handle");
        };
        let relative = Path::new(RELATIVE_CANARY);
        let Err(error) = portable_locator(relative, &approved) else {
            panic!("a relative portable locator must stay rejected");
        };
        assert!(
            !error.to_string().contains("978-canary"),
            "a typed rejection must not echo the rejected locator: {error}"
        );

        let Some(artifact) = ApprovedArtifact::create("absent-echo") else {
            panic!("the rejected-locator fixture must be writable in this environment");
        };
        let Some(approved) = artifact.approved_handle() else {
            panic!("the approved artifact path must be a valid platform handle");
        };
        let absent = artifact.root.join("978-canary-absent-artifact.bin");
        let Err(error) = portable_locator(&absent, &approved) else {
            panic!("an absent artifact must stay rejected");
        };
        assert!(
            !error.to_string().contains("978-canary"),
            "a typed rejection must not echo the rejected locator: {error}"
        );
    }

    // WORK_UNIT_CASE: 978/13 — the digest decisions of this cell are executed,
    // and both outcomes carry the owner's approved digest and no retained path
    #[cfg(windows)]
    #[test]
    fn digest_outcomes_bind_the_owner_approved_digest_and_no_retained_path() {
        use eliot_platform_windows::{UserOwnedRootLease, sha256_hex};

        const DIGEST_FIELD: &str = "runtime.kernel_artifact";
        let Some(artifact) = ApprovedArtifact::create("digest") else {
            panic!("the approved artifact fixture must be writable in this environment");
        };
        let Ok(approved_digest) = PlatformHandle::new(sha256_hex(ARTIFACT_BYTES)) else {
            panic!("the approved artifact digest must be a valid platform handle");
        };
        // The existing owner seam: the same portable root lease the launch
        // contour retains, so the artifact below is leased and digested by the
        // real Windows mechanics rather than by anything this case restates.
        let Ok(portable_root) = UserOwnedRootLease::open_existing(&artifact.root) else {
            panic!("the approved temporary root must open as a portable root lease");
        };
        let (lease_path, records) = recorded(|| {
            let Ok(lease) = open_launch_lease(PROFILE, Some(&portable_root), &artifact.file) else {
                panic!("the approved artifact must retain a launch lease");
            };
            let retained = lease.path().to_path_buf();
            let Ok(()) = verify_launch_digest(&lease, &approved_digest, DIGEST_FIELD) else {
                panic!("the owner-supplied approved digest must be admitted");
            };
            // The retained artifact's content is replaced under the live lease,
            // so the very same owner-supplied approved identity is verified once
            // more against substituted bytes.
            assert!(
                std::fs::write(&artifact.file, SUBSTITUTED_ARTIFACT_BYTES).is_ok(),
                "the retained artifact must stay writable for a substitution case"
            );
            let substituted = verify_launch_digest(&lease, &approved_digest, DIGEST_FIELD);
            let Err(denial) = substituted else {
                panic!("a substituted artifact must never be admitted");
            };
            assert!(
                denial.to_string().contains("content digest mismatch"),
                "the substitution must stay a typed digest rejection: {denial}"
            );
            retained
        });
        assert_eq!(
            lease_path, artifact.file,
            "the lease retains the approved locator"
        );
        let recomputed = [sha256_hex(SUBSTITUTED_ARTIFACT_BYTES)];
        assert_digest_decisions(
            &records,
            approved_digest.as_str(),
            &path_canaries(&artifact),
            &recomputed,
        );
    }

    /// The three `_with_correlation` twins render the caller's own
    /// `LaunchPhaseCorrelation` into every record they emit: the installation,
    /// generation and fence that correlation already held reach each record as
    /// real values, the slots this cell owns no source for stay explicitly
    /// missing, and this cell binds no `artifact` before the verification
    /// outcome, where it chains on the owner-supplied digest handle.
    ///
    /// HONEST SCOPE: the three forwarded identities below are this case's own
    /// synthetic, non-secret literals in this module's existing `978-canary`
    /// style — no path, argv, environment value, credential or nonce — so this
    /// case proves the forwarding path and the rendered slots, not any owner's
    /// real installation, generation or fence. All three twins really execute
    /// against the real portable fixture here, and every record is read back out
    /// of a scoped subscriber, so no assertion can pass on a string this case
    /// composed itself.
    #[cfg(windows)]
    #[test]
    fn forwarded_correlations_name_the_callers_own_identities() {
        use eliot_platform_windows::{UserOwnedRootLease, sha256_hex};

        const DIGEST_FIELD: &str = "runtime.kernel_artifact";
        const INSTALLATION: &str = "978-canary-installation";
        const GENERATION: u64 = 978;
        const FENCE: &str = "978-canary-fence";

        let Some(artifact) = ApprovedArtifact::create("forwarded") else {
            panic!("the approved artifact fixture must be writable in this environment");
        };
        let Some(approved) = artifact.approved_handle() else {
            panic!("the approved artifact path must be a valid platform handle");
        };
        let Ok(approved_digest) = PlatformHandle::new(sha256_hex(ARTIFACT_BYTES)) else {
            panic!("the approved artifact digest must be a valid platform handle");
        };
        // The existing owner seam: the same portable root lease the launch
        // contour retains, so the lease and digest below run through the real
        // Windows mechanics rather than through anything this case restates.
        let Ok(portable_root) = UserOwnedRootLease::open_existing(&artifact.root) else {
            panic!("the approved temporary root must open as a portable root lease");
        };
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(INSTALLATION)
            .with_generation(GENERATION)
            .with_fence(FENCE);
        // All three twins really execute against that one correlation inside a
        // single scoped subscriber, so every record asserted on below is one
        // these real executions emitted.
        let (admitted, records) = recorded(|| {
            let Ok(admitted) =
                approved_locator_with_correlation(&correlation, &artifact.file, &approved, PROFILE)
            else {
                panic!("the approved locator must stay admitted");
            };
            let Ok(lease) = open_launch_lease_with_correlation(
                &correlation,
                PROFILE,
                Some(&portable_root),
                &artifact.file,
            ) else {
                panic!("the approved artifact must retain a launch lease");
            };
            let Ok(()) = verify_launch_digest_with_correlation(
                &correlation,
                &lease,
                &approved_digest,
                DIGEST_FIELD,
            ) else {
                panic!("the owner-supplied approved digest must be admitted");
            };
            admitted
        });
        assert_eq!(
            admitted, artifact.file,
            "admission returns the retained locator"
        );
        // Each twin's own request record plus its admitted records: forwarding
        // changes no phase, order or outcome, so every one of these phases is
        // still published exactly once by the seam it names — and the total
        // record count is pinned below, so a twin that emitted an EXTRA record
        // (an admission and a refusal from one call, say) fails here instead of
        // passing unnoticed.
        let generation = GENERATION.to_string();
        let forwarded = [
            (
                one_phase_record(&records, LOCATOR_REQUESTED_PHASE),
                Some("missing"),
            ),
            (
                one_phase_record(&records, LEASE_REQUESTED_PHASE),
                Some("missing"),
            ),
            (
                one_phase_record(&records, DIGEST_REQUESTED_PHASE),
                Some("missing"),
            ),
            (
                one_phase_record(&records, LOCATOR_ADMITTED_PHASE),
                Some("missing"),
            ),
            (
                one_phase_record(&records, LEASE_ADMITTED_PHASE),
                Some("missing"),
            ),
            (
                one_phase_record(&records, DIGEST_ADMITTED_PHASE),
                Some(approved_digest.as_str()),
            ),
        ];
        assert_eq!(
            records.len(),
            forwarded.len(),
            "forwarding must add, drop and duplicate no record: these three admitted calls emit exactly their own request and admitted phases, and the fixture's refusal phases belong to the refused calls this case does not make: {records:?}"
        );
        for (record, artifact_slot) in forwarded {
            assert_forwarded_record_slots(
                record,
                INSTALLATION,
                generation.as_str(),
                FENCE,
                artifact_slot,
            );
        }
    }

    /// Every slot a forwarded twin record must carry: the three identities the
    /// caller held, the slots this cell owns no source for, and the artifact slot
    /// exactly as the caller of that phase left it.
    fn assert_forwarded_record_slots(
        record: &EmittedRecord,
        installation: &str,
        generation: &str,
        fence: &str,
        artifact_slot: Option<&str>,
    ) {
        let detail = record.detail();
        assert_eq!(
            slot(detail, "installation"),
            Some(installation),
            "a forwarded record names the installation the caller already held: {detail}"
        );
        assert_eq!(
            slot(detail, "generation"),
            Some(generation),
            "a forwarded record names the generation the caller already held: {detail}"
        );
        assert_eq!(
            slot(detail, "fence"),
            Some(fence),
            "a forwarded record names the fence the caller already held: {detail}"
        );
        for unproven in ["operation", "process_start", "reason"] {
            assert_eq!(
                slot(detail, unproven),
                Some("missing"),
                "this cell owns no {unproven} source, so the forwarded binding must leave that slot at the explicit absent marker rather than invent one: {detail}"
            );
        }
        assert_eq!(
            slot(detail, "artifact"),
            artifact_slot,
            "the artifact slot is whatever this cell really holds at this tuple: the absent marker before the digest outcome, and the owner-held approved digest once it has one: {detail}"
        );
    }
}
