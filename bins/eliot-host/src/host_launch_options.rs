//! Exact Host launch argv parsing and typed accessors.
//!
//! This cell owns only parsing the already-approved Host launch argv into typed
//! values. It has no start/stop/restart/kill, lifecycle, reconciliation,
//! transaction, SCM mutation, semantic/canonical, credential, or publication
//! authority.
//!
//! Architecture anchors: `A5.5` scopes verifier inputs and failure
//! applicability; `A13.2` separates physical Host lifecycle from Kernel
//! authority; `A13.8` requires explicit integrity and provenance review.
//! Implementation anchors: `I1.2` assigns Host process lifecycle without
//! project semantics; `I1.8` defines exact ownership and `HostState` separation;
//! `I2.19` keeps a module cell's parser boundary narrow; `I18.1` assigns
//! parsers normalization only.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::ELIOT_HOST_SERVICE_NAME;

use super::super::HostError;
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) launch-options observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. A call site passes a static phase token plus a bounded
// `LaunchPhaseCorrelation` built only from values the owner already holds, each
// rendered through `crate::host_diagnostics::bound_field`: a static label
// classifies the phase, while the bounded identities name which installation,
// generation and config-descriptor digest produced it. No field is
// re-derived, probed or recomputed for a record: the bound identities are pure
// borrows of the admitted value (`host_launch_options_admitted_correlation`).
// `config_descriptor_path`, `host_state_root`, argv text and
// `registration_nonce` are never bound — paths, argv and nonce material stay
// out of diagnostics (I15.4, case 978/12) — and no arbitrary error
// `Debug`/`Display` text is rendered, so bounding limits size, not sensitivity
// (I15.4).
//
// Missing evidence stays explicitly missing: an identity the owner does not
// hold at a call site renders as `missing` instead of being invented. That
// is every typed rejection (no admitted options exist there) and the
// `ServiceMain` validation contour (which holds no options at all); this cell
// owns no operation id, process-start identity, fence or typed reason, and it
// observes no process and no readiness, so those slots stay missing (cases
// 978/2, 978/4).
//
// Sink outcome never alters result/order/status/cleanup. There is no mutable
// global dedup cache and no terminal emission here: the designated terminal for
// one failed launch is `lib.rs`'s `HostTerminalGuard` on the OUTER contour - the
// production path arms `BOUNDARY_OPEN_TERMINAL` there - and the `start_approved`
// leaf guard is phase-only (issue #978 audit defect 2), so this cell can never emit a second
// terminal. Typed rejections stay `HostError::Platform` (case 978/2); admitted
// launches are distinct positive observations carrying the exact admitted
// identities (cases 978/1, 978/12).
fn host_launch_options_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

fn host_launch_options_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    host_launch_options_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::LaunchConfig,
        &detail,
    );
}

/// Bounded correlation for one already-admitted [`HostLaunchOptions`].
///
/// Binds only identities the owner holds on the admitted path: the installation
/// id, the transaction-plan generation and the config-descriptor digest handle.
/// A rejected parse has no admitted value, so it binds nothing
/// (`LaunchPhaseCorrelation::NONE`); paths, the state root, argv text and the
/// registration nonce are never bound here (case 978/12).
fn host_launch_options_admitted_correlation(
    options: &HostLaunchOptions,
) -> LaunchPhaseCorrelation<'_> {
    LaunchPhaseCorrelation::NONE
        .with_installation(options.installation().as_str())
        .with_generation(options.transaction_plan_generation())
        .with_artifact(options.config_descriptor_digest.as_str())
}

/// Exact launch authority supplied by the Runtime Live SCM registration.
///
/// `SystemService` Host startup is argv-bound. The service must not recover any
/// of these values from ambient environment or current-directory state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostLaunchOptions {
    pub(crate) config_descriptor_path: PathBuf,
    pub(crate) config_descriptor_digest: PlatformHandle,
    pub(crate) installation: PlatformHandle,
    pub(crate) transaction_plan_generation: u64,
    pub(crate) host_state_root: PathBuf,
    pub(crate) registration_nonce: Option<PlatformHandle>,
}

impl HostLaunchOptions {
    /// Parses the canonical SCM argv after argv[0] (the service name).
    ///
    /// The five authority pairs must appear exactly once and in the order
    /// rendered by [`eliot_platform_windows::ServiceBootstrapArguments`]. The established optional
    /// registration nonce is accepted only as the final pair. That nonce is
    /// effect-scoped SCM readback evidence, not a Host admission binding; the
    /// approved manifest's five authority values remain independently required.
    /// All other flags and all substitutions are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the argv shape or a typed value is
    /// invalid.
    pub fn parse<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — parse requested; no admitted value exists yet.
        host_launch_options_observe(
            "host.launch-options parse requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::parse_inner(args);
        match &result {
            Ok(options) => {
                // WORK_UNIT_CASE: 978/1 — parse admitted, distinct from rejection.
                host_launch_options_observe(
                    "host.launch-options parse admitted",
                    &host_launch_options_admitted_correlation(options),
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options parse typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn parse_inner<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() != 10 && args.len() != 12 {
            return Err(Self::invalid_argv("expected exactly five authority pairs"));
        }
        let flag = |index: usize, expected: &str| {
            args.get(index)
                .and_then(|value| value.to_str())
                .is_some_and(|actual| actual == expected)
        };
        if !flag(0, "--config-descriptor")
            || !flag(2, "--config-descriptor-sha256")
            || !flag(4, "--installation-id")
            || !flag(6, "--tx-plan-generation")
            || !flag(8, "--host-state-root")
        {
            return Err(Self::invalid_argv(
                "authority flags are missing, reordered, or substituted",
            ));
        }
        if args.len() == 12 && !flag(10, "--registration-nonce") {
            return Err(Self::invalid_argv("unknown or substituted trailing flag"));
        }

        let config_descriptor_path = PathBuf::from(&args[1]);
        if !config_descriptor_path.is_absolute()
            || config_descriptor_path.as_os_str().is_empty()
            || !valid_launch_os_path(config_descriptor_path.as_os_str())
        {
            return Err(Self::invalid_argv(
                "config descriptor path must be absolute and valid",
            ));
        }
        let config_descriptor_digest = parse_launch_text(&args[3], "config descriptor digest")?;
        if !valid_sha256_text(&config_descriptor_digest) {
            return Err(Self::invalid_argv(
                "config descriptor digest must be lowercase SHA-256",
            ));
        }
        let installation_value = parse_launch_text(&args[5], "installation id")?;
        if !valid_launch_identity(&installation_value) {
            return Err(Self::invalid_argv("installation id is invalid"));
        }
        let transaction_plan_generation =
            parse_launch_text(&args[7], "transaction plan generation")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| {
                    Self::invalid_argv("transaction plan generation must be non-zero")
                })?;
        let host_state_root = PathBuf::from(&args[9]);
        if !host_state_root.is_absolute()
            || host_state_root.as_os_str().is_empty()
            || !valid_launch_os_path(host_state_root.as_os_str())
        {
            return Err(Self::invalid_argv(
                "Host state root must be an absolute valid OS path",
            ));
        }
        let registration_nonce = if args.len() == 12 {
            let nonce = parse_launch_text(&args[11], "registration nonce")?;
            if !valid_sha256_text(&nonce) {
                return Err(Self::invalid_argv(
                    "registration nonce must be lowercase SHA-256",
                ));
            }
            Some(
                PlatformHandle::new(nonce)
                    .map_err(|error| Self::invalid_argv(&error.to_string()))?,
            )
        } else {
            None
        };
        let installation = PlatformHandle::new(installation_value)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        let config_descriptor_digest = PlatformHandle::new(config_descriptor_digest)
            .map_err(|error| Self::invalid_argv(&error.to_string()))?;
        Ok(Self {
            config_descriptor_path,
            config_descriptor_digest,
            installation,
            transaction_plan_generation,
            host_state_root,
            registration_nonce,
        })
    }

    /// Parses the mandatory argv contract for an installed `SystemService`.
    ///
    /// Installer service effects persist a registration nonce before SCM
    /// mutation, so a live SCM callback must include that final pair. The
    /// nonce remains effect-scoped readback evidence; the four manifest
    /// bindings below are still the Host admission authority.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the canonical argv is malformed or
    /// omits the required registration nonce.
    pub fn parse_system_service<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — system-service admission requested; no admitted
        // value exists yet.
        host_launch_options_observe(
            "host.launch-options system-service requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::parse_system_service_inner(args);
        match &result {
            Ok(options) => {
                // WORK_UNIT_CASE: 978/1 — system-service admitted.
                host_launch_options_observe(
                    "host.launch-options system-service admitted",
                    &host_launch_options_admitted_correlation(options),
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options system-service typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn parse_system_service_inner<I, S>(args: I) -> Result<Self, HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let options = Self::parse(args)?;
        if options.registration_nonce.is_none() {
            return Err(Self::invalid_argv(
                "SystemService requires the registration nonce pair",
            ));
        }
        Ok(options)
    }

    /// Validates the distinct `ServiceMain` callback argv.
    ///
    /// `StartServiceW` is invoked with zero service arguments by the Windows
    /// platform adapter, so SCM supplies the callback with only the canonical
    /// service name. The immutable Host bootstrap is parsed from the process
    /// command line before `StartServiceCtrlDispatcherW` is entered.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Platform`] when the callback vector contains
    /// anything other than the canonical service name.
    pub fn validate_service_main_argv<I, S>(args: I) -> Result<(), HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // WORK_UNIT_CASE: 978/1 — service-main validation requested; this contour
        // holds no options, so no identity can be bound.
        host_launch_options_observe(
            "host.launch-options service-main requested",
            &LaunchPhaseCorrelation::NONE,
        );
        let result = Self::validate_service_main_argv_inner(args);
        match &result {
            Ok(()) => {
                // WORK_UNIT_CASE: 978/1 — service-main admitted; the callback
                // argv carries no admitted options identity.
                host_launch_options_observe(
                    "host.launch-options service-main admitted",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
            Err(_) => {
                // WORK_UNIT_CASE: 978/2 — typed rejection, never admitted; no
                // admitted identities exist here, so every slot stays missing.
                host_launch_options_observe(
                    "host.launch-options service-main typed rejection",
                    &LaunchPhaseCorrelation::NONE,
                );
            }
        }
        result
    }

    fn validate_service_main_argv_inner<I, S>(args: I) -> Result<(), HostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        if args.len() == 1 && args[0].to_str() == Some(ELIOT_HOST_SERVICE_NAME) {
            Ok(())
        } else {
            Err(Self::invalid_argv(
                "ServiceMain argv must contain only EliotHost",
            ))
        }
    }

    // F-LOG-HOST-3 (#978) accessors stay pure borrows: no observation here,
    // so exact return/order/count is preserved and no duplicate evaluation
    // runs on the semantic path. Admission is already observed by
    // `parse`/`parse_system_service` (cases 978/1/978/2); these getters only
    // project already-admitted values.
    //
    // `installation`, `transaction_plan_generation` and
    // `config_descriptor_digest` are the identities the admitted
    // `host_launch_options_admitted_correlation` binds, read exactly once per
    // admitted observation. `config_descriptor_path`, `host_state_root` and
    // `registration_nonce` are read by launch owners but never bound into a
    // diagnostic field (case 978/12).
    #[must_use]
    pub fn config_descriptor_path(&self) -> &Path {
        &self.config_descriptor_path
    }

    #[must_use]
    pub fn config_descriptor_digest(&self) -> &PlatformHandle {
        &self.config_descriptor_digest
    }

    #[must_use]
    pub const fn installation(&self) -> &PlatformHandle {
        &self.installation
    }

    #[must_use]
    pub const fn transaction_plan_generation(&self) -> u64 {
        self.transaction_plan_generation
    }

    /// Returns the exact per-installation Host runtime root selected by the
    /// trusted service bootstrap.
    #[must_use]
    pub fn host_state_root(&self) -> &Path {
        &self.host_state_root
    }

    #[must_use]
    pub fn registration_nonce(&self) -> Option<&PlatformHandle> {
        self.registration_nonce.as_ref()
    }

    fn invalid_argv(reason: &str) -> HostError {
        HostError::Platform(format!("invalid Host launch argv: {reason}"))
    }
}

fn parse_launch_text(value: &OsString, field: &str) -> Result<String, HostError> {
    value
        .to_str()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| HostLaunchOptions::invalid_argv(&format!("{field} is not valid text")))
}

fn valid_launch_os_path(value: &OsStr) -> bool {
    value
        .to_str()
        .is_some_and(|value| !value.is_empty() && !value.chars().any(char::is_control))
}

pub(crate) fn valid_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || matches!(value, b'a'..=b'f'))
}

fn valid_launch_identity(value: &str) -> bool {
    !value.is_empty() && !value.contains('"') && !value.chars().any(char::is_control)
}

// F-LOG-HOST-3 (#978) inline proof for this cell's private observation
// contract. Every case below executes the real instrumented parser through its
// existing seams - `HostLaunchOptions::parse`,
// `HostLaunchOptions::parse_system_service` and
// `HostLaunchOptions::validate_service_main_argv` - under a scoped `tracing`
// subscriber, then reads the emitted `host.entrypoint_stage` records back out
// of that subscriber. No case renders, formats or hand-builds an expected log
// record, and no case asserts on a string it produced itself. Every identity
// assertion names a slot of a record the facade emitted while production code
// ran and compares the value production bound there - the owner's own parsed
// installation, generation and config-descriptor digest, or the frozen
// explicit-absence marker for evidence this cell has none of - so none of them
// can pass on a key order or on a fabricated value. Selecting the record of a
// phase, counting the records of one execution, and the frozen slot vocabulary
// are properties of the renderer's shape, and no case treats one of them as
// evidence of a bound identity. Parsing is never re-implemented, no visibility
// is widened, and no owner identity is invented. The launch-corpus mapping and
// the cross-file cases of the issue matrix stay with the integration fixture
// owner.
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{ELIOT_HOST_SERVICE_NAME, HostError, HostLaunchOptions};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NONCE: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const INSTALLATION: &str = "978-installation-canary";
    const DESCRIPTOR_PATH: &str = "C:\\Eliot\\978-canary-descriptor.json";
    const STATE_ROOT: &str = "C:\\EliotData\\978-canary-state-root";
    const GENERATION: &str = "7";
    /// Canary argv value carrying a quote, so a record that rendered argv text
    /// would carry this marker verbatim.
    const QUOTED_ID: &str = "978\"installation";

    /// The exact typed reason each invalid argv shape must keep.
    const REASON_PAIR_COUNT_MISMATCH: &str =
        "invalid Host launch argv: expected exactly five authority pairs";
    const REASON_FLAG_SHAPE_OR_ORDER: &str =
        "invalid Host launch argv: authority flags are missing, reordered, or substituted";
    const REASON_DESCRIPTOR_PATH_SHAPE: &str =
        "invalid Host launch argv: config descriptor path must be absolute and valid";
    const REASON_DIGEST_NOT_LOWERCASE: &str =
        "invalid Host launch argv: config descriptor digest must be lowercase SHA-256";
    const REASON_INSTALLATION_ID_INVALID: &str =
        "invalid Host launch argv: installation id is invalid";
    const REASON_ZERO_GENERATION: &str =
        "invalid Host launch argv: transaction plan generation must be non-zero";
    const REASON_STATE_ROOT_SHAPE: &str =
        "invalid Host launch argv: Host state root must be an absolute valid OS path";
    const REASON_UNKNOWN_TRAILING_FLAG: &str =
        "invalid Host launch argv: unknown or substituted trailing flag";
    const REASON_NONCE_NOT_LOWERCASE: &str =
        "invalid Host launch argv: registration nonce must be lowercase SHA-256";
    const REASON_NONCE_PAIR_REQUIRED: &str =
        "invalid Host launch argv: SystemService requires the registration nonce pair";
    const REASON_SERVICE_MAIN_ARGV: &str =
        "invalid Host launch argv: ServiceMain argv must contain only EliotHost";

    /// Phase tokens this cell emits, spelled as the production call sites spell
    /// them, so a case can find the record the parser really wrote.
    const PARSE_REQUESTED: &str = "host.launch-options parse requested";
    const PARSE_ADMITTED: &str = "host.launch-options parse admitted";
    const PARSE_REJECTED: &str = "host.launch-options parse typed rejection";
    const SYSTEM_REQUESTED: &str = "host.launch-options system-service requested";
    const SYSTEM_ADMITTED: &str = "host.launch-options system-service admitted";
    const SYSTEM_REJECTED: &str = "host.launch-options system-service typed rejection";
    const MAIN_REQUESTED: &str = "host.launch-options service-main requested";
    const MAIN_ADMITTED: &str = "host.launch-options service-main admitted";
    const MAIN_REJECTED: &str = "host.launch-options service-main typed rejection";

    /// The seven bounded identity slots every emitted phase detail carries, in
    /// the frozen order the renderer writes them.
    const IDENTITY_SLOTS: [&str; 7] = [
        "installation",
        "generation",
        "operation",
        "artifact",
        "process_start",
        "fence",
        "reason",
    ];

    /// The frozen shared spelling of one unproven identity slot: absence stays
    /// explicit and never reads like an observed value.
    const ABSENT_IDENTITY: &str = "missing";

    /// Words no launch-options record may carry. This cell parses argv, observes
    /// no process and publishes no readiness evidence, so any of them in an
    /// emitted record would be an invented claim; `ready` also covers
    /// `readiness`, `store-ready` and `kernel-ready`.
    const READINESS_CLAIMS: [&str; 3] = ["ready", "activated", "alive"];

    /// Values that must never reach a record: both raw paths, the one-use nonce
    /// and every argv flag, plus one argv value carrying a quote.
    const EXCLUDED_CANARIES: [&str; 10] = [
        DESCRIPTOR_PATH,
        STATE_ROOT,
        NONCE,
        QUOTED_ID,
        "--config-descriptor",
        "--config-descriptor-sha256",
        "--host-state-root",
        "--installation-id",
        "--registration-nonce",
        "--tx-plan-generation",
    ];

    /// The canonical admitted argv, with canary material in every slot the
    /// diagnostics must never carry.
    fn canonical_argv() -> Vec<String> {
        vec![
            "--config-descriptor".to_owned(),
            DESCRIPTOR_PATH.to_owned(),
            "--config-descriptor-sha256".to_owned(),
            DIGEST.to_owned(),
            "--installation-id".to_owned(),
            INSTALLATION.to_owned(),
            "--tx-plan-generation".to_owned(),
            GENERATION.to_owned(),
            "--host-state-root".to_owned(),
            STATE_ROOT.to_owned(),
            "--registration-nonce".to_owned(),
            NONCE.to_owned(),
        ]
    }

    /// One invalid launch argv shape, expressed as a single deviation from the
    /// canonical argv, so the executed path is always the real parser and never
    /// a re-implementation of it.
    #[derive(Debug)]
    enum ArgvDefect {
        /// Drop the trailing registration-nonce pair.
        WithoutNoncePair,
        /// Keep only the leading elements, below the exact authority-pair count.
        Truncated { keep: usize },
        /// Replace one zero-based argv element.
        Replaced { index: usize, value: String },
    }

    impl ArgvDefect {
        /// The exact argv this defect hands to the real parser.
        fn argv(&self) -> Vec<String> {
            let mut argv = canonical_argv();
            match self {
                Self::WithoutNoncePair => argv.truncate(10),
                Self::Truncated { keep } => argv.truncate(*keep),
                Self::Replaced { index, value } => argv[*index] = String::from(value.as_str()),
            }
            argv
        }
    }

    /// The canonical argv with only `keep` leading elements.
    fn shortened(keep: usize) -> ArgvDefect {
        ArgvDefect::Truncated { keep }
    }

    /// The canonical argv with the element at `index` replaced by `value`.
    fn replaced(index: usize, value: &str) -> ArgvDefect {
        ArgvDefect::Replaced {
            index,
            value: String::from(value),
        }
    }

    /// In-memory sink that captures facade output without contending for the
    /// process-global subscriber. Same harness the sibling owners' test modules
    /// use; it is a test sink, never a second logging facade.
    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CaptureSink {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CaptureSink {
        /// The captured facade output, exactly as the subscriber formatted it.
        fn text(&self) -> String {
            let bytes = self
                .bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    /// Runs `parse_step` under a scoped `tracing` subscriber and returns both the
    /// captured facade output and exactly what the real production step
    /// produced, so one case reads the emitted records and the real typed
    /// outcome of the same run.
    fn captured<T>(parse_step: impl FnOnce() -> T) -> (String, T) {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer_sink.clone())
            .finish();
        let mut produced = None;
        tracing::subscriber::with_default(subscriber, || {
            produced = Some(parse_step());
        });
        let Some(produced) = produced else {
            panic!("the scoped production step runs exactly once");
        };
        let captured_text = sink.text();
        (captured_text, produced)
    }

    /// Runs the real argv parse under that same scoped subscriber.
    fn captured_parse(argv: Vec<String>) -> (String, Result<HostLaunchOptions, HostError>) {
        captured(|| HostLaunchOptions::parse(argv))
    }

    /// Runs the real `SystemService` argv parse under that same scoped subscriber.
    fn captured_system(argv: Vec<String>) -> (String, Result<HostLaunchOptions, HostError>) {
        captured(|| HostLaunchOptions::parse_system_service(argv))
    }

    /// Runs the real `ServiceMain` argv validation under that same scoped
    /// subscriber.
    fn captured_service_main(argv: &[&str]) -> (String, Result<(), HostError>) {
        let argv = argv.to_vec();
        captured(|| HostLaunchOptions::validate_service_main_argv(argv))
    }

    /// Every captured record line of one window.
    fn captured_lines(records: &str) -> Vec<&str> {
        records
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect()
    }

    /// Whether any emitted record of one window carries `phase` at all.
    fn records_carry(records: &str, phase: &str) -> bool {
        let needle = format!("phase={phase}");
        for line in captured_lines(records) {
            if line.contains(&needle) {
                return true;
            }
        }
        false
    }

    /// The one emitted record of one window whose detail carries `phase`,
    /// refusing to guess when the phase was emitted zero times or more than
    /// once, and confirming it really is a shared-facade launch-config
    /// observation before any case reads its slots.
    fn record_for<'a>(records: &'a str, phase: &str) -> &'a str {
        let needle = format!("phase={phase}");
        let mut found: Option<&str> = None;
        for line in captured_lines(records) {
            if !line.contains(&needle) {
                continue;
            }
            assert!(
                found.is_none(),
                "one underlying operation emits exactly one {phase} record, never two: {line}"
            );
            found = Some(line);
        }
        let Some(record) = found else {
            panic!("no emitted record carries {phase}: {records}");
        };
        assert!(
            record.contains("host.entrypoint_stage"),
            "the phase must be observed as one shared-facade entrypoint record: {record}"
        );
        assert!(
            record.contains("launch_config"),
            "the phase must be observed on the launch-config entry stage: {record}"
        );
        record
    }

    /// One bounded identity slot read back out of one emitted record line: the
    /// value the facade emitted for `key`, `None` when the record carries no
    /// such slot at all, and `Some("")` when the record wrote the slot empty.
    fn emitted_slot<'a>(record: &'a str, key: &str) -> Option<&'a str> {
        let prefix = format!(" {key}=");
        let bound = record.split(&prefix).nth(1)?;
        let end = bound.find(' ').unwrap_or(bound.len());
        Some(bound[..end].trim_end_matches('"'))
    }

    /// Asserts one bounded identity slot of one emitted record carries exactly
    /// `expected`. A slot the record omits and a slot it writes empty both fail
    /// here, so absence can never pass for an observation.
    fn assert_slot(record: &str, key: &str, expected: &str) {
        assert_eq!(
            emitted_slot(record, key),
            Some(expected),
            "the emitted record must bind {key} as {expected}: {record}"
        );
    }

    /// Asserts every bounded identity slot of one emitted record renders the
    /// explicit absent marker: never empty, never a zero, never a placeholder
    /// that could be read as an observed identity.
    fn assert_every_slot_absent(record: &str) {
        for key in IDENTITY_SLOTS {
            assert_eq!(
                emitted_slot(record, key),
                Some(ABSENT_IDENTITY),
                "the emitted record must spell {key} as explicit absence: {record}"
            );
        }
    }

    /// Asserts the three bounded identities one admitted parse must bind, read
    /// back out of the emitted record by slot name and compared against the
    /// options the real parser returned. Binding the owner's own values is what
    /// proves the record carries a real identity; a rendered key order reads the
    /// same for any value, including a fabricated one.
    fn assert_admitted_identities(record: &str, options: &HostLaunchOptions) {
        assert_slot(record, "installation", options.installation().as_str());
        let generation = options.transaction_plan_generation();
        assert_slot(record, "generation", &generation.to_string());
        assert_slot(
            record,
            "artifact",
            options.config_descriptor_digest().as_str(),
        );
    }

    /// Asserts that no record emitted on an executed launch-options path claims
    /// readiness or activation: only the activation owner may, and this cell is
    /// not it.
    fn assert_no_readiness_claim(records: &str) {
        for line in captured_lines(records) {
            for claim in READINESS_CLAIMS {
                assert!(
                    !line.contains(claim),
                    "no launch-options record may claim {claim}, yet it says: {line}"
                );
            }
        }
    }

    /// Asserts one executed refused parse: the typed variant with its exact
    /// production text, the single rejection record the facade emitted with
    /// every bounded identity slot explicitly absent, no admitted record beside
    /// it, and no readiness claim anywhere in that capture.
    fn assert_rejected_parse(defect: &ArgvDefect, expected_reason: &str) {
        let (records, outcome) = captured_parse(defect.argv());
        let Err(HostError::Platform(reason)) = outcome else {
            panic!("{defect:?} must stay a typed rejection");
        };
        assert_eq!(
            reason, expected_reason,
            "{defect:?} must keep the exact typed reason production returns for it"
        );
        assert_eq!(
            captured_lines(&records).len(),
            2,
            "{defect:?} must observe its requested and rejection phases only"
        );
        assert!(
            records_carry(&records, PARSE_REQUESTED),
            "{defect:?} must observe its requested phase before the refusal"
        );
        let rejected = record_for(&records, PARSE_REJECTED);
        assert_every_slot_absent(rejected);
        assert!(
            !records_carry(&records, PARSE_ADMITTED),
            "{defect:?} admits nothing, so it must emit no admitted record"
        );
        assert_no_readiness_claim(&records);
    }

    // WORK_UNIT_CASE: 978/1 - admission binds the held identities
    #[test]
    fn admitted_parse_binds_the_exact_held_identities() {
        let (records, outcome) = captured_parse(canonical_argv());
        let options = match outcome {
            Ok(options) => options,
            Err(error) => panic!("the canonical argv must be admitted: {error}"),
        };
        assert_eq!(
            captured_lines(&records).len(),
            2,
            "an admitted parse observes its requested and admitted phases only: {records}"
        );
        assert!(
            records_carry(&records, PARSE_REQUESTED),
            "an admitted parse must observe its requested phase: {records}"
        );
        let admitted = record_for(&records, PARSE_ADMITTED);
        assert_admitted_identities(admitted, &options);
        assert!(
            !records_carry(&records, PARSE_REJECTED),
            "an admitted parse must observe no rejection record: {records}"
        );
        assert_no_readiness_claim(&records);

        let (records, outcome) = captured_system(canonical_argv());
        let options = match outcome {
            Ok(options) => options,
            Err(error) => panic!("the canonical SystemService argv must be admitted: {error}"),
        };
        let admitted = record_for(&records, SYSTEM_ADMITTED);
        assert_admitted_identities(admitted, &options);
        assert!(
            !records_carry(&records, SYSTEM_REJECTED),
            "an admitted SystemService argv must observe no rejection record: {records}"
        );
        assert_no_readiness_claim(&records);
    }

    // WORK_UNIT_CASE: 978/2 - typed rejection stays typed and binds nothing
    #[test]
    fn rejected_options_retain_typed_rejection_and_admit_nothing() {
        let uppercase_digest = DIGEST.to_uppercase();
        let uppercase_nonce = NONCE.to_uppercase();
        assert_rejected_parse(&shortened(8), REASON_PAIR_COUNT_MISMATCH);
        assert_rejected_parse(&replaced(0, "--config"), REASON_FLAG_SHAPE_OR_ORDER);
        assert_rejected_parse(&replaced(1, "978-descriptor"), REASON_DESCRIPTOR_PATH_SHAPE);
        assert_rejected_parse(&replaced(3, &uppercase_digest), REASON_DIGEST_NOT_LOWERCASE);
        assert_rejected_parse(&replaced(5, QUOTED_ID), REASON_INSTALLATION_ID_INVALID);
        assert_rejected_parse(&replaced(7, "0"), REASON_ZERO_GENERATION);
        assert_rejected_parse(&replaced(9, "978-state-root"), REASON_STATE_ROOT_SHAPE);
        assert_rejected_parse(&replaced(10, "--nonce"), REASON_UNKNOWN_TRAILING_FLAG);
        assert_rejected_parse(&replaced(11, &uppercase_nonce), REASON_NONCE_NOT_LOWERCASE);

        // The nonce pair alone is missing, so the shape itself stays admissible
        // and the refusal comes from the SystemService nonce requirement.
        let (records, outcome) = captured_system(ArgvDefect::WithoutNoncePair.argv());
        let Err(HostError::Platform(reason)) = outcome else {
            panic!("a SystemService argv without the nonce pair must stay typed");
        };
        assert_eq!(
            reason, REASON_NONCE_PAIR_REQUIRED,
            "the SystemService nonce requirement must keep its exact text"
        );
        assert!(
            records_carry(&records, SYSTEM_REQUESTED),
            "the SystemService contour must observe its requested phase: {records}"
        );
        let rejected = record_for(&records, SYSTEM_REJECTED);
        assert_every_slot_absent(rejected);
        assert!(
            !records_carry(&records, SYSTEM_ADMITTED),
            "a refused SystemService argv must observe no admitted record: {records}"
        );
        assert_no_readiness_claim(&records);

        let (records, outcome) = captured_service_main(&[ELIOT_HOST_SERVICE_NAME]);
        assert!(
            outcome.is_ok(),
            "the canonical ServiceMain argv stays admitted"
        );
        assert!(
            records_carry(&records, MAIN_REQUESTED),
            "the ServiceMain contour must observe its requested phase: {records}"
        );
        let admitted = record_for(&records, MAIN_ADMITTED);
        assert_every_slot_absent(admitted);
        assert_no_readiness_claim(&records);

        let (records, outcome) = captured_service_main(&["NotEliotHost"]);
        let Err(HostError::Platform(reason)) = outcome else {
            panic!("a substituted ServiceMain argv must stay a typed rejection");
        };
        assert_eq!(
            reason, REASON_SERVICE_MAIN_ARGV,
            "the ServiceMain argv refusal must keep the exact text production returns"
        );
        let rejected = record_for(&records, MAIN_REJECTED);
        assert_every_slot_absent(rejected);
        assert!(
            !records_carry(&records, MAIN_ADMITTED),
            "a refused ServiceMain argv must observe no admitted record: {records}"
        );
        assert_no_readiness_claim(&records);
    }

    // WORK_UNIT_CASE: 978/4 - parse admission is no process or readiness
    #[test]
    fn parse_admission_is_not_a_process_or_readiness_observation() {
        let (records, outcome) = captured_parse(canonical_argv());
        let options = match outcome {
            Ok(options) => options,
            Err(error) => panic!("the canonical argv must be admitted: {error}"),
        };
        let admitted = record_for(&records, PARSE_ADMITTED);
        // This cell owns no operation id, process-start identity, fence or typed
        // reason on either contour, so those four slots of the emitted record
        // stay explicitly absent and no process identity can be read out of it.
        for key in ["process_start", "operation", "fence", "reason"] {
            assert_slot(admitted, key, ABSENT_IDENTITY);
        }
        // By parsed slot name the emitted record exposes no bare
        // process-identity field either: the shared correlation knows
        // `process_start`, which is explicitly absent above, and publishes no
        // other process-identity key for a launch-options observation to use.
        assert_eq!(
            emitted_slot(admitted, "pid"),
            None,
            "the emitted correlation exposes no bare process-identity slot: {admitted}"
        );
        let artifact = options.config_descriptor_digest();
        assert_slot(admitted, "artifact", artifact.as_str());
        assert_no_readiness_claim(&records);

        let (records, outcome) = captured_parse(replaced(7, "0").argv());
        let Err(HostError::Platform(reason)) = outcome else {
            panic!("a zero transaction-plan generation must stay a typed rejection");
        };
        assert_eq!(
            reason, REASON_ZERO_GENERATION,
            "the zero-generation refusal must keep the exact typed text it returns"
        );
        let rejected = record_for(&records, PARSE_REJECTED);
        for key in ["process_start", "operation", "fence", "reason"] {
            assert_slot(rejected, key, ABSENT_IDENTITY);
        }
        assert_ne!(
            emitted_slot(admitted, "artifact"),
            emitted_slot(rejected, "artifact"),
            "an admitted and a refused parse must not render one artifact slot"
        );
        assert_no_readiness_claim(&records);
    }

    // WORK_UNIT_CASE: 978/12 - no path, argv or nonce value reaches a record
    #[test]
    fn admitted_correlation_excludes_paths_argv_and_nonce_values() {
        let (parse_window, outcome) = captured_parse(canonical_argv());
        let options = match outcome {
            Ok(options) => options,
            Err(error) => panic!("the canonical argv must be admitted: {error}"),
        };
        let (rejected_window, outcome) = captured_parse(replaced(5, QUOTED_ID).argv());
        let Err(HostError::Platform(reason)) = outcome else {
            panic!("a quoted installation value must stay a typed rejection");
        };
        assert_eq!(
            reason, REASON_INSTALLATION_ID_INVALID,
            "the quoted installation refusal must keep its exact text"
        );
        let (system_window, outcome) = captured_system(canonical_argv());
        let system_options = match outcome {
            Ok(options) => options,
            Err(error) => panic!("the canonical SystemService argv must be admitted: {error}"),
        };
        let (main_window, outcome) = captured_service_main(&[ELIOT_HOST_SERVICE_NAME]);
        assert!(
            outcome.is_ok(),
            "the canonical ServiceMain argv stays admitted"
        );

        // Each executed window really carried the records this case reads, so the
        // canary scan below can never pass on an empty capture.
        let artifact = options.config_descriptor_digest();
        let admitted = record_for(&parse_window, PARSE_ADMITTED);
        assert_slot(admitted, "artifact", artifact.as_str());
        assert_every_slot_absent(record_for(&rejected_window, PARSE_REJECTED));
        // The SystemService contour admits the same parsed options through
        // `host_launch_options_admitted_correlation`, so its record binds the
        // owner's own installation, generation and config-descriptor digest
        // exactly as the admitted-parse case reads them off the same record
        // shape. Only the four slots this cell owns no evidence for stay
        // explicitly absent here.
        let system_admitted = record_for(&system_window, SYSTEM_ADMITTED);
        assert_slot(
            system_admitted,
            "installation",
            system_options.installation().as_str(),
        );
        let system_generation = system_options.transaction_plan_generation();
        assert_slot(
            system_admitted,
            "generation",
            &system_generation.to_string(),
        );
        let system_artifact = system_options.config_descriptor_digest();
        assert_slot(system_admitted, "artifact", system_artifact.as_str());
        for key in ["operation", "process_start", "fence", "reason"] {
            assert_slot(system_admitted, key, ABSENT_IDENTITY);
        }
        assert_every_slot_absent(record_for(&main_window, MAIN_ADMITTED));

        let windows = [
            &parse_window,
            &rejected_window,
            &system_window,
            &main_window,
        ];
        for records in windows {
            assert_no_readiness_claim(records);
            for line in captured_lines(records) {
                for canary in EXCLUDED_CANARIES {
                    assert!(
                        !line.contains(canary),
                        "no excluded value may reach an emitted record: {line}"
                    );
                }
            }
        }
    }
}
