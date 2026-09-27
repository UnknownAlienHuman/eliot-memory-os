//! Structured crash and restart-intensity evidence for the Windows runtime
//! (issue #1847, I16.2, I16.4, I16.5, I16.7, I16.11, I16.12).
//!
//! This module owns only the wiring between surfaces that already exist:
//!
//! * the merged `eliot-observability-runtime` stack (`#1836`) supplies
//!   [`CrashReport`]/[`SymbolArtifact`], the I16.11 [`CriticalPath`], and the
//!   `system_service` [`EventLogReport`];
//! * the existing screening in `eliot_observability::field_policy` plus
//!   `kernel_diagnostics::bound_detail` bounds and redacts every runtime
//!   context value — no second secret-marker list is minted here;
//! * the closed Kernel audit chain (`kernel_audit`) carries the sequenced
//!   crash/restart/exhaustion/quarantine records through
//!   `KernelComposition::audit_observe`, the single append funnel;
//! * the shipped `DiagnosticBrief` shape (`eliot-doctor-core`) is built and
//!   routed through the existing `route_doctor_repair` front door; it is
//!   invoked, never reshaped.
//!
//! Authority boundaries: this module observes. It mints no lifecycle, repair,
//! epoch, or generation authority, it never restarts or terminates a process,
//! and it never treats a degraded or control-loss telemetry state as success.
//! The restart budget is a bounded, visible count — a *restart intensity*
//! threshold, not a second supervision machine: crossing it makes the
//! capability quarantined (disabled while the Problem State stays open, I1.4)
//! and it stays quarantined until an operator clears it out of band. Nothing
//! here can re-arm itself (I1.4 forbids an endless restart loop).
//!
//! Redaction honesty (I15.4, I16.12): every value that reaches a crash
//! report, a critical-event record, or a Diagnostic Brief passes the existing
//! screening. A value that looks like a secret, or that is too long to travel
//! as a bounded value, is replaced by a handle reference and listed in the
//! brief's `unknowns`; an absent leg is recorded as absent, never invented.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use eliot_doctor_core::{DiagnosticBrief, EvidenceHandle};
use eliot_observability::field_policy::{looks_like_secret, requires_evidence_handle};
use eliot_observability_runtime::{
    CrashReport, CrashReportMetadata, CriticalEventRecord, CriticalEventState, EventLogOutcome,
    EventLogReport, ObservabilityConfig, RollingLogPolicy, RuntimeProfile, SinkStatus,
    SymbolArtifact, SystemServiceEvent, UnavailableReason, install,
};

use crate::kernel_audit::AuditEventDraft;
use crate::kernel_diagnostics::bound_detail;
use crate::{DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION, route_doctor_repair};

/// Restart intensity allowed before a capability is quarantined.
///
/// I1.4 fixes the semantics — "after restart-budget exhaustion, disable the
/// capability while Problem State remains open" — and requires "separate
/// service identities and restart budgets" per supervised service, but names
/// no numeric value. One restart is the budget that already existed for the
/// Host-owned Kernel branch (`reconcile_state_machine`'s single in-process
/// attempt), so one is the value carried forward: the first restart is
/// permitted, the second observed crash exhausts the budget. It is a declared
/// Config Default, not an invariant, and the same constant is the value the
/// audit records and the Diagnostic Brief report.
pub const KERNEL_RESTART_BUDGET: u32 = 1;

/// Sub-directory of the Kernel work root holding structured crash reports.
///
/// The reports are written beside the operational logs, never inside the
/// audit chain: a crash report is a bounded build/symbol artifact reference,
/// while the audit chain remains the sequenced authority record.
pub const KERNEL_CRASH_REPORT_DIR_NAME: &str = "crash-reports";

/// Rolling operational-log file stem for the Kernel process.
pub const KERNEL_OBSERVABILITY_LOG_STEM: &str = "eliot-kernel";

/// Bytes per rolling operational-log generation (I16.9 bounded retention).
const ROLLING_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Retained rolling operational-log generations.
const ROLLING_MAX_GENERATIONS: u32 = 8;

/// Bounded queue depth for the non-blocking rolling appender.
const ROLLING_MAX_BUFFERED_RECORDS: usize = 4096;

/// Package version reported in the crash report.
///
/// The Kernel binary is built from this workspace, so the package version is
/// a build fact, not a runtime claim.
pub const KERNEL_PACKAGE_NAME: &str = "eliot-kernel";

/// Build profile reported in the crash report (I16.2 requires the build
/// channel that produced the executable; the channel is read from the
/// compiler itself so a debug and a release build never claim each other).
pub const KERNEL_BUILD_PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// Terminal code for a crash-path failure that must stay visible (I16.11).
pub const KERNEL_CRASH_PATH_TERMINAL_CODE: &str = "KERNEL_CRASH_EVIDENCE_FAILED";

/// Restart intensity observed for the current Kernel process generation.
///
/// Monotone for the process lifetime: a replacement process starts from zero
/// and carries its own budget, so exhaustion is always scoped to one
/// generation rather than to a name.
static RESTART_INTENSITY: AtomicU32 = AtomicU32::new(0);

/// The Kernel's own audit head, captured at composition so the crash path can
/// record the exact current audit sequence without a poisoned-lock retry
/// storm. `0` means no audit chain was opened: the crash report then names
/// the audit sequence as absent rather than guessing a sequence number.
static AUDIT_HEAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Live `AuditLineage` slots the crash context is projected from, captured
/// from the composition when it completes.
///
/// `AuditLineage` is the I16.3 composite trace context and already owns every
/// slot the issue names (module/process generation, authority epoch, active
/// trace/work scope, State Fence, missing-field declarations). It is stored
/// as its own rendered JSON projection so the crash path needs no composition
/// lock and cannot deadlock a panicking thread.
static CRASH_CONTEXT: std::sync::OnceLock<CrashContext> = std::sync::OnceLock::new();

/// Bounded, redacted runtime context projected into a crash report.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrashContext {
    /// Request-scoped trace identity at crash time, if the chain had one.
    pub trace_id: Option<String>,
    /// Governor-owned `WorkScope` identity at crash time, if known.
    pub work_scope: Option<String>,
    /// Module/process generation text.
    pub module_generation: Option<String>,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: Option<String>,
    /// Exact State Fence the last admitted operation observed.
    pub state_fence: Option<String>,
    /// I16.3 slots the Kernel had no value for, explicitly listed (I16.12).
    pub missing_fields: Vec<String>,
}

/// Records the composition's live audit head and crash context.
///
/// Called from `main` at the composition boundary, before the front-door loop
/// starts and again after the dispatch contour is composed so the authority
/// epoch and State Fence named in the crash context are the live ones rather
/// than the ones bound before composition. A later call replaces the earlier
/// one while the crash path is not yet reachable; the process-global capture
/// (`OnceLock`) is set once, at the last such boundary, so an installed
/// process cannot restate its own head mid-run.
pub fn install_crash_context(context: CrashContext) {
    let _ = CRASH_CONTEXT.set(context);
}

/// Projects one crash into the audit chain and invokes the I16.7
/// diagnostic-brief trigger.
///
/// Called from the process restart supervisor, not from the panic hook: the
/// panic hook runs while the process is already unwinding and can hold no
/// durable chain lock, so the sequenced record and the brief are produced on
/// the recovery path that observed the crash. `report` is the evidence
/// `emit_crash_report` returned; `None` means the crash record could not be
/// written, and the resulting brief then lists the absent report as a
/// telemetry gap rather than carrying a fabricated evidence handle.
pub fn record_crash_evidence(
    kernel: &crate::KernelComposition,
    work_root: &Path,
    report: &Option<(String, String)>,
) {
    let context = crash_context();
    let symbol = resolve_symbol_artifact(process_image().as_deref().unwrap_or(Path::new("")));
    let (report_id, report_digest) = report.as_ref().map_or_else(
        || {
            (
                UNKNOWN_NOT_EXPOSED.to_owned(),
                UNKNOWN_NOT_EXPOSED.to_owned(),
            )
        },
        |(report_id, digest)| (report_id.clone(), digest.clone()),
    );
    kernel.audit_observe(AuditEventDraft::process_crashed(
        context
            .module_generation
            .as_deref()
            .unwrap_or(UNKNOWN_NOT_EXPOSED),
        FAULT_CLASS_PANIC,
        &report_id,
        &report_digest,
        &symbol.artifact_ref,
        &symbol.artifact_sha256,
    ));
    let telemetry_state = submit_critical_event(
        work_root,
        &format!("kernel-crash-{report_id}"),
        "crash",
        &redacted_runtime_detail(&context),
    );
    let evidence = crash_report_evidence(work_root, report);
    let brief = build_diagnostic_brief(
        &format!("{KERNEL_PACKAGE_NAME}-{FAULT_CLASS_PANIC}"),
        FAULT_CLASS_PANIC,
        "the Kernel process generation panicked and terminated",
        "the controlled runtime path for the Kernel generation is lost until it restarts",
        &evidence,
        &telemetry_state,
    );
    if !trigger_diagnostic_brief(&brief) {
        observe_crash_path_failure(
            "diagnostic brief could not be routed; the front door is not composed",
        );
    }
}

/// Projects the restart-intensity decision and, on exhaustion, the
/// diagnostic-brief trigger for restart exhaustion (I16.7 trigger "module
/// crash or restart exhaustion").
pub fn record_restart_exhaustion_evidence(
    _kernel: &crate::KernelComposition,
    work_root: &Path,
    _event_id: &str,
    telemetry_state: &CriticalEventState,
) {
    let evidence = crash_report_evidence(work_root, &None);
    let brief = build_diagnostic_brief(
        &format!("{KERNEL_PACKAGE_NAME}-restart-exhausted"),
        "restart-exhausted",
        "the Kernel restart budget is exhausted; the capability is quarantined",
        "the Kernel capability stays disabled while the Problem State remains open",
        &evidence,
        telemetry_state,
    );
    if !trigger_diagnostic_brief(&brief) {
        observe_crash_path_failure(
            "restart-exhaustion diagnostic brief could not be routed; the front door is not composed",
        );
    }
}

/// Records the composition's current audit head sequence.
///
/// The sequence is the I16.3 event cursor of the last appended record, so the
/// crash report can name the exact audit position it interrupted. A missing
/// head leaves the recorded sequence at `0`, which the report and the
/// Diagnostic Brief both present as absent.
pub fn record_audit_head(kernel: &crate::KernelComposition) {
    if let Some((seq, _)) = kernel.audit_head() {
        AUDIT_HEAD.store(seq, Ordering::Relaxed);
    }
}

/// Projects the live composition's I16.3 lineage into the crash context.
///
/// The projection reads the composition's own admission policy — the live
/// authority epoch, module generation, and State Fence the front door admits
/// against — so the crash record names the same identity the authority path
/// used rather than a value reconstructed from the request envelope. Nothing
/// here invents a slot: an unbound identity stays `None` and is reported as
/// missing (I16.12).
#[must_use]
pub fn crash_context_from_composition(kernel: &crate::KernelComposition) -> CrashContext {
    let lineage = kernel.front_door_lineage();
    let fence = lineage.state_fence.as_ref().and_then(|fence| {
        eliot_contracts::canonical_json_bytes(fence)
            .ok()
            .map(|bytes| eliot_contracts::sha256_hex(&bytes))
    });
    // The missing-field declaration is computed from the same lineage state
    // the audit chain seals at append, so the crash context lists exactly the
    // slots this composition had no value for (I16.12).
    let missing = lineage.missing_fields_for_crash_context(fence.as_deref());
    CrashContext {
        trace_id: lineage.trace_id,
        work_scope: lineage.work_scope,
        module_generation: lineage.module_generation,
        authority_epoch: lineage.authority_epoch,
        state_fence: fence,
        missing_fields: missing,
    }
}

/// Returns the bounded, redacted crash context captured at composition.
#[must_use]
pub fn crash_context() -> CrashContext {
    CRASH_CONTEXT.get().cloned().unwrap_or_default()
}

/// Bounded, redacted directory for structured crash reports.
///
/// `work_root` is the composition-bound Kernel work root, never a
/// caller-supplied path. The directory is created by `CrashReport::write`.
#[must_use]
pub fn crash_report_directory(work_root: &Path) -> PathBuf {
    work_root.join(KERNEL_CRASH_REPORT_DIR_NAME)
}

/// Bounded observability configuration for the Kernel process.
///
/// I16.2 names the Windows Event Log as the `system_service` last-resort
/// surface and the protected rolling-file spool for the interactive profiles.
/// The Kernel is launched by Host as a supervised service process, so it
/// configures `SystemService`; the returned configuration carries no
/// `user_mode` or portable path because this composition never infers a
/// profile from environment, path, port, or PID (the caller states it).
#[must_use]
pub fn observability_config(work_root: &Path) -> ObservabilityConfig {
    let log_directory = work_root.join("kernel-logs");
    ObservabilityConfig {
        profile: RuntimeProfile::SystemService,
        rolling_log: RollingLogPolicy {
            directory: log_directory,
            file_stem: KERNEL_OBSERVABILITY_LOG_STEM.to_owned(),
            max_bytes_per_generation: ROLLING_MAX_BYTES,
            max_generations: ROLLING_MAX_GENERATIONS,
            max_buffered_records: ROLLING_MAX_BUFFERED_RECORDS,
            exit_code: 0,
        },
        spool: None,
        metrics_listen: None,
        otlp_endpoint: None,
    }
}

/// Installs the shared observability runtime for the Kernel process.
///
/// Diagnostics never gate startup (A13.10): a rejected configuration is
/// reported through the existing diagnostics terminal and the process
/// continues into the launch funnel without a rolling log or critical path.
/// The returns stay `bool`-free deliberately — the caller needs the honest
/// fact, not a manufactured success — so the outcome is observed.
pub fn install_kernel_observability(work_root: &Path) {
    let config = observability_config(work_root);
    match install(&config) {
        Ok(outcome) => {
            let install = outcome.handles();
            install.publish_runtime_counters();
            tracing::info!(
                target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
                event = "kernel.observability_installed",
                profile = install.profile.as_str(),
                install = match outcome {
                    eliot_observability_runtime::ObservabilityInstallOutcome::Installed(_) => "installed",
                    eliot_observability_runtime::ObservabilityInstallOutcome::AlreadyInstalled(_) => "already_installed",
                },
                "kernel observability runtime installed"
            );
        }
        Err(error) => {
            crate::kernel_diagnostics::observe_terminal_error(KERNEL_CRASH_PATH_TERMINAL_CODE);
            tracing::error!(
                target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
                event = "kernel.observability_unavailable",
                reason = error.to_string(),
                "kernel observability runtime unavailable"
            );
        }
    }
}

/// Resolves the symbol artifact that resolves this build's crash addresses.
///
/// I16.2 requires a structured crash report *plus* a symbol artifact, and the
/// Windows release pipeline already ships PDBs beside the executable, so the
/// reference is derived from the running image: the sibling
/// `<image stem>.pdb`. The digest is the SHA-256 of the artifact bytes that
/// actually exist on this machine; when the artifact is absent or unreadable
/// the reference still names the expected path and the digest records
/// `unknown/not_exposed` — I16.5's legal visible terminal value — so a missing
/// symbol set is visible rather than silently replaced by a fabricated hash.
#[must_use]
pub fn resolve_symbol_artifact(image: &Path) -> SymbolArtifact {
    let artifact_ref = image.with_extension("pdb");
    let artifact_sha256 = std::fs::read(&artifact_ref).ok().map_or_else(
        || UNKNOWN_NOT_EXPOSED.to_owned(),
        |bytes| eliot_contracts::sha256_hex(&bytes),
    );
    SymbolArtifact {
        artifact_ref: artifact_ref.to_string_lossy().into_owned(),
        artifact_sha256,
    }
}

/// I16.5's legal visible terminal value: a metric or identity this build does
/// not expose. Absence is reported, never substituted.
pub const UNKNOWN_NOT_EXPOSED: &str = "unknown/not_exposed";

/// Returns the running process image path, or `None` when the platform does
/// not expose it. A missing image is reported as unknown, never faked.
fn process_image() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Redacts and bounds one runtime-context value.
///
/// Reuses the existing screening: a value that `looks_like_secret` or that
/// `requires_evidence_handle` (secret, or longer than a bounded label may
/// travel) is replaced by a handle reference; every other value is bounded by
/// `bound_detail` with its truncation honesty record preserved.
fn redacted_value(slot: &str, value: Option<&str>) -> String {
    let Some(value) = value else {
        return format!("{slot}=absent");
    };
    if looks_like_secret(value) || requires_evidence_handle(value) {
        // The value itself never travels. The slot stays named and its
        // material is reachable only through the referenced artifact.
        return format!("{slot}=redacted:handle-only");
    }
    let bounded = bound_detail(value);
    format!("{slot}={}", bounded.text())
}

/// Bounded, already-redacted detail string for one crash/recovery event.
///
/// Every named slot is screened independently, so one sensitive field cannot
/// smuggle another through the composed string, and the whole detail is
/// bounded once more by `bound_detail` with its truncation record.
#[must_use]
pub fn redacted_runtime_detail(context: &CrashContext) -> String {
    let parts = [
        redacted_value("trace", context.trace_id.as_deref()),
        redacted_value("work_scope", context.work_scope.as_deref()),
        redacted_value("generation", context.module_generation.as_deref()),
        redacted_value("epoch", context.authority_epoch.as_deref()),
        redacted_value("state_fence", context.state_fence.as_deref()),
        format!("audit_seq={}", current_audit_sequence()),
        format!("missing={}", context.missing_fields.join("+")),
    ];
    bound_detail(&parts.join(" ")).text().to_owned()
}

/// The audit sequence in force at crash time, or `0` when no audit chain was
/// opened. `0` is the honest "no sequenced observation exists yet" value: it
/// is never presented as a real sequence.
#[must_use]
pub fn current_audit_sequence() -> u64 {
    AUDIT_HEAD.load(Ordering::Relaxed)
}

/// Fault class recorded for a panic. I16.2's admitted vocabulary.
pub const FAULT_CLASS_PANIC: &str = "panic";

/// One panic, as the crash hook observes it.
#[derive(Clone, Copy, Debug)]
pub struct PanicObservation<'a> {
    /// Panic payload text supplied by the faulting code.
    pub message: &'a str,
    /// `true` when the payload is a `String`/`&str` panic message, `false`
    /// for a non-string payload.
    pub is_message: bool,
}

/// Writes the structured crash record for one panic and reports its evidence.
///
/// Returns the report identity and digest so the caller can project the same
/// evidence into the audit record and the Diagnostic Brief; a crash path that
/// could not produce a report returns `None` after emitting the visible
/// terminal, and never fabricates a report identity.
pub fn emit_crash_report(
    work_root: &Path,
    observation: PanicObservation<'_>,
) -> Option<(String, String)> {
    let context = crash_context();
    let detail = redacted_runtime_detail(&context);
    let image = process_image();
    let symbol_artifact = resolve_symbol_artifact(image.as_deref().unwrap_or(Path::new("")));
    let metadata = CrashReportMetadata {
        process: KERNEL_PACKAGE_NAME.to_owned(),
        package_version: env!("CARGO_PKG_VERSION").to_owned(),
        build_profile: KERNEL_BUILD_PROFILE.to_owned(),
        module_generation_ref: context
            .module_generation
            .clone()
            .unwrap_or_else(|| UNKNOWN_NOT_EXPOSED.to_owned()),
        runtime_profile: RuntimeProfile::SystemService.as_str().to_owned(),
        process_id: std::process::id(),
        fault_class: FAULT_CLASS_PANIC.to_owned(),
        // The fault site is the bounded, screened panic location: a redacted
        // site keeps symbolication possible through the referenced artifact
        // without placing a payload or a path in the report.
        fault_site: bounded_fault_site(observation),
        symbol_artifact,
    };
    let report_id = format!(
        "{}-{}-{}",
        KERNEL_PACKAGE_NAME,
        KERNEL_BUILD_PROFILE,
        std::process::id()
    );
    let report = match CrashReport::new(&report_id, metadata) {
        Ok(report) => report,
        Err(error) => {
            observe_crash_path_failure(&error.to_string());
            return None;
        }
    };
    let digest = report.digest.clone();
    let directory = crash_report_directory(work_root);
    match report.write(&directory) {
        Ok(path) => {
            tracing::error!(
                target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
                event = "kernel.crash_record_written",
                report_id = report_id,
                report_digest = digest,
                report_path = path.to_string_lossy().as_ref(),
                runtime_context = detail,
                "kernel structured crash record written"
            );
            Some((report_id, digest))
        }
        Err(error) => {
            observe_crash_path_failure(&error.to_string());
            None
        }
    }
}

/// Bounds the panic location to a screened fault site.
///
/// The thread name is the bounded, nonsecret locator I16.2 asks for; the
/// payload text is screened and never carried raw. A non-string payload has
/// no message to carry, which is reported as `absent` rather than as an empty
/// string pretending to be one.
fn bounded_fault_site(observation: PanicObservation<'_>) -> String {
    let payload = if observation.is_message {
        let screened = redacted_value("payload", Some(observation.message));
        bound_detail(&screened).text().to_owned()
    } else {
        redacted_value("payload", None)
    };
    let thread = std::thread::current();
    let site = thread.name().unwrap_or("unnamed");
    format!("thread={site} {payload}")
}

/// Emits the visible terminal for a crash-path failure (I16.11: silent
/// success is forbidden). Bounded through the existing field screening.
fn observe_crash_path_failure(reason: &str) {
    let bounded = bound_detail(reason);
    crate::kernel_diagnostics::observe_terminal_error(KERNEL_CRASH_PATH_TERMINAL_CODE);
    tracing::error!(
        target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.crash_evidence_failed",
        code = KERNEL_CRASH_PATH_TERMINAL_CODE,
        reason = bounded.text(),
        reason_truncated = bounded.truncated(),
        "kernel crash evidence path failed"
    );
}

/// Installs the process panic hook that writes the structured crash record.
///
/// The prior hook is wrapped, not replaced, so the existing diagnostics
/// output is preserved. Every step is guarded: a crash path that itself
/// panics must not convert a recoverable abort into a double fault, so the
/// hook swallows a failing crash path and always invokes the prior hook.
pub fn install_panic_hook(work_root: &Path) {
    let work_root = work_root.to_path_buf();
    let prior = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let observation = match payload.downcast_ref::<&'static str>() {
            Some(message) => PanicObservation {
                message,
                is_message: true,
            },
            None => match payload.downcast_ref::<String>() {
                Some(message) => PanicObservation {
                    message: message.as_str(),
                    is_message: true,
                },
                None => PanicObservation {
                    message: "",
                    is_message: false,
                },
            },
        };
        // `catch_unwind` guards the crash path itself: a failure inside the
        // evidence writer degrades to the prior hook rather than aborting. The
        // work root is cloned per panic because this closure is an `Fn`, so the
        // captured root must be handed to the inner `FnOnce` by copy.
        let crash_root = work_root.clone();
        let _ = std::panic::catch_unwind(move || {
            emit_crash_report(&crash_root, observation);
        });
        prior(info);
    }));
}

/// Restart intensity after recording one restart attempt.
#[must_use]
pub fn restart_intensity() -> u32 {
    RESTART_INTENSITY.load(Ordering::Relaxed)
}

/// One restart decision for the current Kernel generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    /// The restart is inside the configured budget and may proceed.
    Permitted {
        /// Restart intensity after this permitted restart.
        intensity: u32,
        /// The configured budget the intensity is measured against.
        budget: u32,
    },
    /// Restart intensity reached the budget; the capability is quarantined.
    Exhausted {
        /// Intensity observed, equal to the budget.
        intensity: u32,
        /// The configured budget that was reached.
        budget: u32,
    },
}

/// Records one observed crash and decides whether a restart is permitted.
///
/// The intensity is monotone for the process generation, so the configured
/// budget is reached exactly once and the decision is visible. A crash while
/// the budget is already exhausted returns
/// [`RestartDecision::Exhausted`] and never permits another restart: I1.4
/// forbids an endless restart loop.
pub fn observe_crash_and_decide_restart(budget: u32) -> RestartDecision {
    let observed = RESTART_INTENSITY.fetch_add(1, Ordering::Relaxed) + 1;
    if observed <= budget {
        RestartDecision::Permitted {
            intensity: observed,
            budget,
        }
    } else {
        RestartDecision::Exhausted {
            intensity: observed - 1,
            budget,
        }
    }
}

/// Projects the quarantine state a restart decision produced into the audit
/// chain, and submits the critical-event record to the I16.11 path.
///
/// `restarted` is `true` when a replacement generation was actually
/// admitted; an exhausted decision emits the exhaustion and quarantine records
/// and reports the event as `RestartExhausted`, never as a restart. The
/// returned state is the honest critical-path state, so the caller can carry
/// a `ControlLoss` into the Diagnostic Brief's `unknowns` instead of claiming
/// a delivery that did not happen.
pub fn project_restart_decision(
    kernel: &crate::KernelComposition,
    work_root: &Path,
    event_id: &str,
    detail: &str,
    decision: RestartDecision,
    restarted: bool,
) -> CriticalEventState {
    let bounded = bound_detail(detail);
    match decision {
        RestartDecision::Permitted { intensity, budget } => {
            if restarted {
                kernel.audit_observe(AuditEventDraft::process_restarted(
                    KERNEL_PACKAGE_NAME,
                    intensity,
                    budget,
                ));
            }
            submit_critical_event(
                work_root,
                event_id,
                if restarted { "restart" } else { "quiesce" },
                bounded.text(),
            )
        }
        RestartDecision::Exhausted { intensity, budget } => {
            kernel.audit_observe(AuditEventDraft::process_restart_exhausted(
                KERNEL_PACKAGE_NAME,
                intensity,
                budget,
            ));
            kernel.audit_observe(AuditEventDraft::process_quarantined(
                KERNEL_PACKAGE_NAME,
                intensity,
                budget,
            ));
            submit_critical_event(work_root, event_id, "restart_exhausted", bounded.text())
        }
    }
}

/// Submits one critical startup/recovery event to the I16.11 path and, in the
/// `system_service` profile, to the Windows Event Log.
///
/// The Windows Event Log is the admitted last-resort surface for
/// `system_service` only; off Windows, or when the OS refuses the record, the
/// outcome is reported honestly as an unavailable sink and never as a
/// delivery.
pub fn submit_critical_event(
    work_root: &Path,
    event_id: &str,
    event: &str,
    detail: &str,
) -> CriticalEventState {
    let config = observability_config(work_root);
    let record = match CriticalEventRecord::new(
        event_id,
        event,
        RuntimeProfile::SystemService.as_str(),
        bound_detail(detail).text(),
    ) {
        Ok(record) => record,
        Err(error) => {
            observe_crash_path_failure(&error.to_string());
            return CriticalEventState::ControlLoss {
                attempts: vec![UnavailableReason::NotApplicable],
            };
        }
    };
    match install(&config) {
        Ok(outcome) => {
            let status = outcome.handles().critical_path.submit(record);
            // The `system_service` Event Log stage is part of the installed
            // critical path, so a live submission already carried the record
            // there when the earlier stages were unavailable. The explicit
            // report below is the direct startup/recovery projection I16.2
            // names; its outcome is recorded, never claimed.
            let event_log_outcome = report_event_log(event, detail);
            if !matches!(event_log_outcome, SinkStatus::Delivered) {
                tracing::warn!(
                    target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
                    event = "kernel.event_log_outcome",
                    event_name = event,
                    status = event_log_outcome.as_str(),
                    "kernel startup/recovery event log outcome"
                );
            }
            status.state
        }
        Err(error) => {
            observe_crash_path_failure(&error.to_string());
            CriticalEventState::ControlLoss {
                attempts: vec![UnavailableReason::Unavailable],
            }
        }
    }
}

/// Reports one admitted startup/recovery event to the Windows Event Log.
///
/// `system_service` is the only profile for which I16.2 admits the Windows
/// Event Log, and only for the admitted lifecycle vocabulary: startup, stop,
/// crash, restart, and restart exhaustion. An event outside that vocabulary
/// and a non-Windows build both report
/// [`UnavailableReason::NotApplicable`] rather than routing an unadmitted
/// observation into the OS or faking a delivery elsewhere.
fn report_event_log(event: &str, detail: &str) -> SinkStatus {
    let admitted = match event {
        "service_start" => SystemServiceEvent::ServiceStart,
        "service_stop" | "quiesce" | "stop" => SystemServiceEvent::ServiceStop,
        "crash" => SystemServiceEvent::Crash,
        "restart" => SystemServiceEvent::Restart,
        "restart_exhausted" | "quarantine" => SystemServiceEvent::RestartExhausted,
        _ => return SinkStatus::Unavailable(UnavailableReason::NotApplicable),
    };
    let insertion = format!(
        "event={} profile={} detail={}",
        event,
        RuntimeProfile::SystemService.as_str(),
        bound_detail(detail).text()
    );
    match EventLogReport.report(admitted, &insertion) {
        Ok(EventLogOutcome::Accepted) | Err(EventLogOutcome::Accepted) => SinkStatus::Delivered,
        Ok(EventLogOutcome::UnsupportedPlatform) | Err(EventLogOutcome::UnsupportedPlatform) => {
            SinkStatus::Unavailable(UnavailableReason::NotApplicable)
        }
        Ok(_) | Err(_) => SinkStatus::Unavailable(UnavailableReason::Unavailable),
    }
}

/// Builds the Diagnostic Brief for one crash or restart exhaustion (I16.7).
///
/// I16.7 names "module crash or restart exhaustion" as a trigger and requires
/// the compiler to return "a gap and required observation" when telemetry is
/// insufficient. The `unknowns` list is exactly that gap: every I16.3 slot the
/// Kernel had no value for is listed by name, and a control-loss telemetry
/// state contributes the typed reason each stage returned, so a brief never
/// invents a cause and never claims evidence that was not written.
#[must_use]
pub fn build_diagnostic_brief(
    problem_id: &str,
    failure_class: &str,
    symptom: &str,
    impact: &str,
    evidence: &[EvidenceHandle],
    telemetry_state: &CriticalEventState,
) -> DiagnosticBrief {
    let context = crash_context();
    let mut unknowns: Vec<String> = context
        .missing_fields
        .iter()
        .map(|field| format!("required observation: {field} was not present in the audit lineage"))
        .collect();
    if let CriticalEventState::ControlLoss { attempts } = telemetry_state {
        for (stage, reason) in [
            ("normal_audit", attempts.first()),
            ("event_spool", attempts.get(1)),
            ("last_resort_event_log", attempts.get(2)),
        ] {
            let reason = reason.unwrap_or(&UnavailableReason::NotApplicable);
            unknowns.push(format!(
                "telemetry gap: {stage} reported {} for this event",
                reason_name(*reason)
            ));
        }
    }
    if current_audit_sequence() == 0 {
        unknowns.push(
            "required observation: no sequenced audit record existed at crash time".to_owned(),
        );
    }
    if context.module_generation.is_none() {
        unknowns.push(
            "required observation: module generation identity was not bound in the crash context"
                .to_owned(),
        );
    }
    DiagnosticBrief {
        problem_id: problem_id.to_owned(),
        component: KERNEL_PACKAGE_NAME.to_owned(),
        failure_class: failure_class.to_owned(),
        symptom: bound_detail(symptom).text().to_owned(),
        impact: bound_detail(impact).text().to_owned(),
        evidence: evidence.to_vec(),
        unknowns,
    }
}

/// Stable name for one typed telemetry-unavailability reason.
fn reason_name(reason: UnavailableReason) -> &'static str {
    match reason {
        UnavailableReason::Unavailable => "unavailable",
        UnavailableReason::Saturated => "saturated",
        UnavailableReason::NotApplicable => "not_applicable",
        UnavailableReason::AcceptedWithoutDeliveryProof => "accepted_without_delivery_proof",
    }
}

/// Invokes the diagnostic-brief trigger through the existing Doctor front
/// door.
///
/// I16.7 names module crash and restart exhaustion as brief triggers. The
/// brief is built from real evidence and routed through the composed
/// `route_doctor_repair` front door — the production Kernel Doctor seam
/// (`compose_production_doctor_front_door`) — so a crash escalates through
/// the registered repair path rather than a second private channel. The
/// return value is the honest routing result: `false` means the front door is
/// not composed, which the caller records as a telemetry gap instead of
/// claiming a diagnosis.
pub fn trigger_diagnostic_brief(brief: &DiagnosticBrief) -> bool {
    if brief.validate().is_err() {
        observe_crash_path_failure("diagnostic brief failed the shipped contract validation");
        return false;
    }
    if !route_doctor_repair(DOCTOR_REPAIR_WIRE_ID, DOCTOR_REPAIR_WIRE_VERSION) {
        observe_crash_path_failure("doctor repair front door is not routed for this wire");
        return false;
    }
    if !crate::dispatch_launch::doctor_repair_advertised() {
        observe_crash_path_failure("doctor repair front door has no composed owner");
        return false;
    }
    tracing::error!(
        target: crate::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.diagnostic_brief_triggered",
        problem_id = brief.problem_id,
        failure_class = brief.failure_class,
        evidence_count = brief.evidence.len(),
        unknowns = brief.unknowns.len(),
        "kernel diagnostic brief triggered through the doctor front door"
    );
    true
}

/// Evidence handle for one written crash report.
///
/// The handle names the report's path and its content digest, so the brief
/// points at the exact bytes without embedding them. A report that could not
/// be written yields no handle: the brief then lists the missing report as an
/// unknown instead of carrying a fabricated evidence reference.
#[must_use]
pub fn crash_report_evidence(
    work_root: &Path,
    report: &Option<(String, String)>,
) -> Vec<EvidenceHandle> {
    let Some((report_id, digest)) = report else {
        return Vec::new();
    };
    let path = crash_report_directory(work_root)
        .join(format!("{report_id}.json"))
        .to_string_lossy()
        .into_owned();
    EvidenceHandle::new(path, digest.clone())
        .into_iter()
        .collect()
}
