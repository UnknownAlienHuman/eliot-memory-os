use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use uuid::Uuid;

use super::{
    HostError, HostInstallationEpoch, HostKernelRestartReceipt, HostRuntimeControlOperation,
    HostRuntimeControlRequest, valid_sha256_text,
};

#[cfg(windows)]
mod pending_codec;
#[cfg(windows)]
use pending_codec::{
    read_runtime_restart_pending_identity, runtime_restart_pending_identity,
    runtime_restart_pending_payload,
};

#[cfg(windows)]
use super::host_durable_persistence::{sync_dir, write_durable_file};

#[cfg(all(test, windows))]
use super::host_durable_persistence::ordering;

#[cfg(all(test, windows))]
mod pending_write_fault {
    use std::cell::Cell;

    thread_local! {
        static WRITE_FAULT: Cell<bool> = const { Cell::new(false) };
    }

    /// Inject a one-shot failure of the next runtime-restart temp-file write.
    /// Thread-local and consumed once, so parallel tests stay isolated.
    pub(super) fn inject_write_fault() {
        WRITE_FAULT.with(|slot| slot.set(true));
    }

    pub(super) fn clear_write_fault() {
        WRITE_FAULT.with(|slot| slot.set(false));
    }

    pub(super) fn take_write_fault() -> bool {
        WRITE_FAULT.with(|slot| slot.replace(false))
    }
}

#[cfg(windows)]
pub(super) fn runtime_restart_store_dir(host_state_root: &Path) -> PathBuf {
    host_state_root.join("runtime-restarts")
}

// F-LOG-HOST-6 (#981) restart-state observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never digests,
// paths, file bytes, or arbitrary error text — so bounding limits size, not
// sensitivity (I15.4). Pending intent, durable receipt, and reconciled
// completion stay distinct: a pending file is never a receipt, and an
// exact-record replay is observed as readback, never as a second commit.
// Publication failure stays primary across tmp cleanup and directory sync;
// cleanup cannot rename it. These primitives own no terminal: a single
// terminal per failed restart operation is enforced by the outermost owner
// boundary, while these phases correlate by stage order only. Sink outcome
// never alters result/order/cleanup.
#[cfg(windows)]
fn host_restart_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[cfg(windows)]
pub(super) fn runtime_restart_receipt_path(host_state_root: &Path, digest: &str) -> PathBuf {
    runtime_restart_store_dir(host_state_root).join(format!("{digest}.receipt.json"))
}

#[cfg(windows)]
pub(super) fn runtime_restart_pending_path(host_state_root: &Path, digest: &str) -> PathBuf {
    runtime_restart_store_dir(host_state_root).join(format!("{digest}.pending.json"))
}

#[cfg(windows)]
pub(super) fn read_bounded_runtime_restart_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, HostError> {
    let file = std::fs::File::open(path)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::RecoveryRequired(format!("{label} cannot be read: {error}")))?;
    if bytes.len() as u64 > max_bytes {
        host_restart_observe("host.restart read too large observed");
        return Err(HostError::RecoveryRequired(format!("{label} is too large")));
    }
    Ok(bytes)
}

/// Notes and reports whether a restart-store entry is the Host-managed
/// episode budget file (issue #1801 W5): read by its own owner
/// (`load_restart_budget`), it is never a restart receipt and therefore
/// never adopted here.
#[cfg(windows)]
fn note_unadopted_restart_budget(file_name: &str) -> bool {
    let skip = file_name == RESTART_BUDGET_FILE_NAME;
    if skip {
        host_restart_observe("host.restart budget not adopted observed");
    }
    skip
}

#[cfg(windows)]
pub(super) fn load_durable_runtime_restarts(
    host_state_root: &Path,
) -> Result<std::collections::HashMap<String, HostKernelRestartReceipt>, HostError> {
    const MAX_RUNTIME_RESTART_RECORD_BYTES: u64 = 16 * 1024;
    const MAX_RUNTIME_RESTART_RECORDS: usize = 1024;
    let mut map = std::collections::HashMap::new();
    host_restart_observe("host.restart load requested");
    let dir = runtime_restart_store_dir(host_state_root);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host_restart_observe("host.restart store absent observed");
            return Ok(map);
        }
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart store cannot be enumerated: {error}"
            )));
        }
    };
    for (entry_index, entry) in entries.enumerate() {
        if entry_index >= MAX_RUNTIME_RESTART_RECORDS {
            return Err(HostError::RecoveryRequired(
                "runtime restart store contains too many records".to_owned(),
            ));
        }
        let entry = entry.map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart store entry cannot be inspected: {error}"
            ))
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart store entry metadata cannot be read: {error}"
            ))
        })?;
        if !metadata.is_file() {
            return Err(HostError::RecoveryRequired(
                "runtime restart store contains a non-file entry".to_owned(),
            ));
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                HostError::RecoveryRequired(
                    "runtime restart store contains a non-text filename".to_owned(),
                )
            })?;
        if note_unadopted_restart_budget(file_name) {
            continue;
        }
        let pending_digest = file_name
            .strip_suffix(".pending.json")
            .filter(|digest| valid_sha256_text(digest));
        if pending_digest.is_some() {
            // Pending records go to the bounded reader below, never the adoption map.
            host_restart_observe("host.restart pending not adopted observed");
            let _ = read_runtime_restart_pending_identity(&path)?;
            continue;
        }
        let receipt_digest = file_name
            .strip_suffix(".receipt.json")
            .filter(|digest| valid_sha256_text(digest))
            .ok_or_else(|| {
                HostError::RecoveryRequired(format!(
                    "runtime restart store contains an unknown or wrongly named record: {file_name}"
                ))
            })?;
        if metadata.len() > MAX_RUNTIME_RESTART_RECORD_BYTES {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is too large"
            )));
        }
        let bytes = read_bounded_runtime_restart_file(
            &path,
            MAX_RUNTIME_RESTART_RECORD_BYTES,
            &format!("runtime restart receipt {file_name}"),
        )?;
        let receipt =
            serde_json::from_slice::<HostKernelRestartReceipt>(&bytes).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "runtime restart receipt {file_name} is malformed: {error}"
                ))
            })?;
        receipt.validate().map_err(|error| {
            HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is invalid: {error}"
            ))
        })?;
        if receipt.mutation_digest.as_str() != receipt_digest {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart receipt {file_name} is bound to the wrong mutation"
            )));
        }
        if map.insert(receipt_digest.to_owned(), receipt).is_some() {
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart store contains duplicate receipt identity {receipt_digest}"
            )));
        }
    }
    host_restart_observe("host.restart load observed");
    Ok(map)
}

// Host-managed restart-episode budget (#1801 W5/A5).
//
// A13.2 requires separate restart budgets whose repeated failure becomes a
// Problem State rather than an endless restart loop, and #1801 Work item 5
// requires the episode/exhaustion state to survive supervisor-process
// replacement. The in-memory `HostJobBranches` counters are zeroed on every
// `HostComposition::open`, so this durable record — owned by the same
// restart-budget store beside the runtime-restart receipts — carries the
// episode attempts and explicit exhaustion flags through the current owner.
// One retained record per installation, bound to the currently admitted
// approved generation: admitting a different approved generation starts a
// new episode (the prior episode record is replaced, since only the live
// contour's budget steers the reconcile branch), while re-admitting the
// same generation — including after a Host crash or SCM restart — inherits
// the retained budget (fail-closed quarantine while the Problem State
// remains open, I1.4). ARCH-MOD-03: exactly one owner (Host,
// through `HostComposition`) reads and publishes this record; the generic
// reconcile machine only consumes the seeded in-memory counters. The
// product's restart budget has no wall-clock cooldown — the bound is
// count-per-episode — so the persisted state is episode attempts plus
// exhaustion flags, and a static read distinguishes the first episode from
// an exhausted one.
#[cfg(windows)]
pub(super) const HOST_RESTART_EPISODE_BOUND: u8 = 1;

#[cfg(windows)]
pub(super) const RESTART_BUDGET_FILE_NAME: &str = "restart-budget.json";

#[cfg(windows)]
const MAX_RESTART_BUDGET_BYTES: u64 = 4096;

#[cfg(windows)]
const RESTART_BUDGET_WIRE: &str = "eliot.host.restart-budget.v1";

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HostRestartBudget {
    wire: String,
    installation: String,
    generation: String,
    kernel_attempts: u32,
    store_attempts: u32,
    kernel_exhausted: bool,
    store_exhausted: bool,
}

#[cfg(windows)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBudgetRecord {
    wire: String,
    installation: String,
    generation: String,
    kernel_attempts: u32,
    store_attempts: u32,
    kernel_exhausted: bool,
    store_exhausted: bool,
}

#[cfg(windows)]
fn restart_budget_shape_valid(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

#[cfg(windows)]
impl HostRestartBudget {
    pub(super) fn for_contour(installation: &str, generation: &str) -> Self {
        Self {
            wire: RESTART_BUDGET_WIRE.to_owned(),
            installation: installation.to_owned(),
            generation: generation.to_owned(),
            kernel_attempts: 0,
            store_attempts: 0,
            kernel_exhausted: false,
            store_exhausted: false,
        }
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.wire != RESTART_BUDGET_WIRE {
            return Err("restart budget wire is not the canonical budget version".to_owned());
        }
        if !restart_budget_shape_valid(&self.installation) {
            return Err("restart budget installation binding is malformed".to_owned());
        }
        if !restart_budget_shape_valid(&self.generation) {
            return Err("restart budget generation binding is malformed".to_owned());
        }
        let bound = u32::from(HOST_RESTART_EPISODE_BOUND);
        if (self.kernel_exhausted && self.kernel_attempts < bound)
            || (self.store_exhausted && self.store_attempts < bound)
        {
            return Err("restart budget exhaustion is set without a spent episode".to_owned());
        }
        Ok(())
    }

    #[must_use]
    pub(super) fn installation(&self) -> &str {
        &self.installation
    }

    #[must_use]
    pub(super) fn generation(&self) -> &str {
        &self.generation
    }

    #[must_use]
    pub(super) fn kernel_attempts(&self) -> u32 {
        self.kernel_attempts
    }

    #[must_use]
    pub(super) fn store_attempts(&self) -> u32 {
        self.store_attempts
    }

    #[must_use]
    pub(super) fn kernel_exhausted(&self) -> bool {
        self.kernel_exhausted
    }

    #[must_use]
    pub(super) fn store_exhausted(&self) -> bool {
        self.store_exhausted
    }

    /// Saturates the durable Kernel attempts into the in-memory `u8` counter
    /// domain. Saturation keeps a corrupt-large value fail-operational toward
    /// refusal (never toward a fresh budget): any value above `u8::MAX` is
    /// already far past the episode bound.
    #[must_use]
    pub(super) fn kernel_attempts_saturated(&self) -> u8 {
        u8::try_from(self.kernel_attempts).unwrap_or(u8::MAX)
    }

    /// Saturates the durable Store attempts into the in-memory `u8` counter
    /// domain; see [`Self::kernel_attempts_saturated`].
    #[must_use]
    pub(super) fn store_attempts_saturated(&self) -> u8 {
        u8::try_from(self.store_attempts).unwrap_or(u8::MAX)
    }

    /// Merges observed in-memory attempts monotonically, then recomputes the
    /// exhaustion flags from the episode bound. The durable counters never
    /// move backward: a zeroed supervisor process cannot erase a spent
    /// episode, and a fresh episode is created only by replacing this record
    /// for a newly admitted generation binding.
    pub(super) fn observe_attempts(&mut self, kernel_attempts: u8, store_attempts: u8) {
        self.kernel_attempts = self.kernel_attempts.max(u32::from(kernel_attempts));
        self.store_attempts = self.store_attempts.max(u32::from(store_attempts));
        let bound = u32::from(HOST_RESTART_EPISODE_BOUND);
        if self.kernel_attempts >= bound {
            self.kernel_exhausted = true;
        }
        if self.store_attempts >= bound {
            self.store_exhausted = true;
        }
    }
}

#[cfg(windows)]
pub(super) fn restart_budget_path(host_state_root: &Path) -> PathBuf {
    runtime_restart_store_dir(host_state_root).join(RESTART_BUDGET_FILE_NAME)
}

#[cfg(windows)]
fn restart_budget_payload(budget: &HostRestartBudget) -> serde_json::Value {
    serde_json::json!({
        "wire": budget.wire,
        "installation": budget.installation,
        "generation": budget.generation,
        "kernel_attempts": budget.kernel_attempts,
        "store_attempts": budget.store_attempts,
        "kernel_exhausted": budget.kernel_exhausted,
        "store_exhausted": budget.store_exhausted,
    })
}

/// Loads the retained Host restart-episode budget, if any. An absent record
/// is a fresh episode, never an error; a present but malformed or invalid
/// record fails closed through the existing `validate()` before any restart
/// decision can consume it.
#[cfg(windows)]
pub(super) fn load_restart_budget(
    host_state_root: &Path,
) -> Result<Option<HostRestartBudget>, HostError> {
    host_restart_observe("host.restart budget load requested");
    let path = restart_budget_path(host_state_root);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host_restart_observe("host.restart budget absent observed");
            return Ok(None);
        }
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "restart budget record cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_RESTART_BUDGET_BYTES {
        return Err(HostError::RecoveryRequired(
            "restart budget record is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(
        &path,
        MAX_RESTART_BUDGET_BYTES,
        "restart budget record",
    )?;
    let record = serde_json::from_slice::<RestartBudgetRecord>(&bytes).map_err(|error| {
        HostError::RecoveryRequired(format!("restart budget record is malformed: {error}"))
    })?;
    let budget = HostRestartBudget {
        wire: record.wire,
        installation: record.installation,
        generation: record.generation,
        kernel_attempts: record.kernel_attempts,
        store_attempts: record.store_attempts,
        kernel_exhausted: record.kernel_exhausted,
        store_exhausted: record.store_exhausted,
    };
    budget.validate().map_err(|error| {
        HostError::RecoveryRequired(format!("restart budget record is invalid: {error}"))
    })?;
    host_restart_observe("host.restart budget loaded observed");
    Ok(Some(budget))
}

/// Publishes the retained Host restart-episode budget durably. The staged
/// bytes are synced, atomically moved over the retained record on the same
/// volume, committed with a directory sync, and proven back by an exact
/// validated reload; a failed publication never reports success and never
/// leaves a half-written record behind.
#[cfg(windows)]
pub(super) fn persist_restart_budget(
    host_state_root: &Path,
    budget: &HostRestartBudget,
) -> Result<(), HostError> {
    host_restart_observe("host.restart budget persist requested");
    budget.validate().map_err(HostError::Platform)?;
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|error| HostError::Platform(error.to_string()))?;
    let bytes = serde_json::to_vec(&restart_budget_payload(budget))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if bytes.len() as u64 > MAX_RESTART_BUDGET_BYTES {
        return Err(HostError::Platform(
            "restart budget record exceeds its bounded size".to_owned(),
        ));
    }
    let path = restart_budget_path(host_state_root);
    let tmp = dir.join(format!(".restart-budget.{}.tmp", Uuid::new_v4().simple()));
    let publication = (|| {
        write_durable_file(&tmp, &bytes)?;
        eliot_windows_ipc::atomic_replace_file(&tmp, &path).map_err(|error| {
            HostError::Platform(format!("restart budget atomic replace failed: {error}"))
        })?;
        sync_runtime_restart_store_dir(&dir)?;
        Ok(())
    })();
    // The atomic move consumes the staging file on success; on failure the
    // staging file is removed so a crash cannot leave ambiguous evidence.
    // Publication failure stays primary across cleanup and its commit.
    let cleanup = std::fs::remove_file(&tmp);
    let sync_after_cleanup = sync_runtime_restart_store_dir(&dir);
    if let Err(publication_error) = publication {
        host_restart_observe("host.restart budget publication failed observed");
        return Err(publication_error);
    }
    match cleanup {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            host_restart_observe("host.restart budget cleanup failed observed");
            return Err(HostError::RecoveryRequired(format!(
                "restart budget temporary cleanup failed: {error}"
            )));
        }
    }
    sync_after_cleanup?;
    let reloaded = load_restart_budget(host_state_root)?.ok_or_else(|| {
        HostError::RecoveryRequired(
            "restart budget record disappeared after publication".to_owned(),
        )
    })?;
    if reloaded != *budget {
        return Err(HostError::RecoveryRequired(
            "restart budget readback differs from the published record".to_owned(),
        ));
    }
    host_restart_observe("host.restart budget persisted observed");
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeRestartPendingPublication {
    Created,
    Replay,
}
#[cfg(windows)]
fn sync_runtime_restart_store_dir(dir: &Path) -> Result<(), HostError> {
    sync_dir(dir)
}

#[cfg(windows)]
fn remove_receipt_confirmed_runtime_restart_pending(
    host_state_root: &Path,
    dir: &Path,
    receipt: &HostKernelRestartReceipt,
) -> Result<(), HostError> {
    // Shared receipt-confirmed pending cleanup for both new publication and
    // exact replay. The exact receipt is already validated by the caller;
    // confirm its directory entry is durable with the existing checked sync
    // before touching pending evidence, then remove only this operation's
    // pending record and commit the cleanup. NotFound is idempotent cleanup;
    // any other removal or directory-commit failure stays an explicit error.
    // The receipt itself is never rewritten and unrelated files are never
    // touched; conflicting pending evidence is left in place and fails
    // closed.
    sync_runtime_restart_store_dir(dir)?;
    let pending = runtime_restart_pending_path(host_state_root, receipt.mutation_digest.as_str());
    let Some(identity) = read_runtime_restart_pending_identity(&pending)? else {
        return Ok(());
    };
    if identity.mutation_digest() != receipt.mutation_digest.as_str() {
        host_restart_observe("host.restart pending conflict preserved observed");
        return Err(HostError::RecoveryRequired(
            "runtime restart pending record conflicts with the durable receipt".to_owned(),
        ));
    }
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_attempt");
    match std::fs::remove_file(&pending) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            host_restart_observe("host.restart pending removal failed observed");
            return Err(HostError::RecoveryRequired(format!(
                "runtime restart pending cleanup failed: {error}"
            )));
        }
    }
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_done");
    sync_runtime_restart_store_dir(dir)?;
    #[cfg(all(test, windows))]
    ordering::record("pending_remove_dir_sync_success");
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
pub(super) fn persist_runtime_restart_pending(
    host_state_root: &Path,
    request: &HostRuntimeControlRequest,
    host: &HostInstallationEpoch,
) -> Result<RuntimeRestartPendingPublication, HostError> {
    host_restart_observe("host.restart pending requested");
    request.validate().map_err(HostError::RecoveryRequired)?;
    if request.operation != HostRuntimeControlOperation::RestartKernel {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending records are reserved for RestartKernel".to_owned(),
        ));
    }
    if host.epoch.current.sequence.get() == 0 {
        return Err(HostError::RecoveryRequired(
            "runtime restart pending records require a non-zero host epoch".to_owned(),
        ));
    }
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let identity = runtime_restart_pending_identity(request, host);
    let path = runtime_restart_pending_path(host_state_root, request.mutation_digest.as_str());
    if let Some(existing) = read_runtime_restart_pending_identity(&path)? {
        if existing == identity {
            // An earlier attempt may have linked this record and then failed its
            // directory sync; confirm the entry is durable before treating it as published.
            sync_runtime_restart_store_dir(&dir)?;
            host_restart_observe("host.restart pending replay observed");
            return Ok(RuntimeRestartPendingPublication::Replay);
        }
        return Err(HostError::RecoveryRequired(
            "runtime restart pending record conflicts with the requested operation".to_owned(),
        ));
    }
    let payload = runtime_restart_pending_payload(&identity)?;
    let bytes = serde_json::to_vec(&payload).map_err(|e| HostError::Platform(e.to_string()))?;
    let tmp = dir.join(format!(
        ".{}.pending.{}.tmp",
        request.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let publication = (|| {
        #[cfg(all(test, windows))]
        {
            if pending_write_fault::take_write_fault() {
                ordering::record("pending_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected runtime restart pending file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("pending_hardlink_attempt");
        // A hard-link publication is atomic and, unlike rename, never replaces
        // a final record that won a concurrent create race.
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("pending_publication_dir_sync_success");
                Ok(RuntimeRestartPendingPublication::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let Some(existing) = read_runtime_restart_pending_identity(&path)? else {
                    return Err(HostError::RecoveryRequired(
                        "runtime restart pending record disappeared during publication".to_owned(),
                    ));
                };
                if existing == identity {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_runtime_restart_store_dir(&dir)?;
                    // F-LOG-HOST-6 (#981) defect 6: no observation here. The
                    // common tail below emits the single terminal phase, which
                    // branches on `Created | Replay` so one replay never reads
                    // as both readback and fresh publication.
                    Ok(RuntimeRestartPendingPublication::Replay)
                } else {
                    Err(HostError::RecoveryRequired(
                        "runtime restart pending record conflicts with the requested operation"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("tmp_cleanup_done");
    let sync_after_cleanup = sync_runtime_restart_store_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("tmp_cleanup_dir_sync_error");
        }
    }
    match publication {
        Err(publication_error) => {
            host_restart_observe("host.restart pending publication failed observed");
            Err(publication_error)
        }
        Ok(value) => {
            match cleanup {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    host_restart_observe("host.restart pending cleanup failed observed");
                    return Err(HostError::RecoveryRequired(format!(
                        "runtime restart pending temporary cleanup failed: {error}"
                    )));
                }
            }
            sync_after_cleanup?;
            #[cfg(all(test, windows))]
            ordering::record("pending_publication_complete");
            // F-LOG-HOST-6 (#981) defect 6: carry the `Created | Replay`
            // disposition through the complete cleanup path. One replay emits
            // one readback terminal, never a fresh publication.
            match value {
                RuntimeRestartPendingPublication::Created => {
                    host_restart_observe("host.restart pending published observed");
                }
                RuntimeRestartPendingPublication::Replay => {
                    host_restart_observe("host.restart pending replay observed");
                }
            }
            Ok(value)
        }
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
pub(super) fn persist_runtime_restart_receipt(
    host_state_root: &Path,
    receipt: &HostKernelRestartReceipt,
) -> Result<(), HostError> {
    host_restart_observe("host.restart receipt requested");
    receipt.validate().map_err(HostError::Platform)?;
    let dir = runtime_restart_store_dir(host_state_root);
    std::fs::create_dir_all(&dir).map_err(|e| HostError::Platform(e.to_string()))?;
    let path = runtime_restart_receipt_path(host_state_root, receipt.mutation_digest.as_str());
    if let Some(existing_bytes) = (|| -> Result<Option<Vec<u8>>, HostError> {
        match std::fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "runtime restart receipt cannot be inspected: {error}"
                )));
            }
        }
        let bytes = read_bounded_runtime_restart_file(&path, 16 * 1024, "runtime restart receipt")?;
        Ok(Some(bytes))
    })()? {
        let existing = serde_json::from_slice::<HostKernelRestartReceipt>(&existing_bytes)
            .map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "existing runtime restart receipt is malformed: {error}"
                ))
            })?;
        existing.validate().map_err(HostError::RecoveryRequired)?;
        if existing == *receipt {
            // An earlier publication may have stranded its pending cleanup
            // (failed removal or interruption after the receipt commit).
            // Resume it through the shared receipt-confirmed path: exact
            // replay re-confirms the directory entry and retries the pending
            // removal instead of reporting success with pending still present.
            remove_receipt_confirmed_runtime_restart_pending(host_state_root, &dir, &existing)?;
            host_restart_observe("host.restart receipt replay observed");
            return Ok(());
        }
        return Err(HostError::RecoveryRequired(
            "existing runtime restart receipt conflicts with reconstructed authority".to_owned(),
        ));
    }
    let tmp = dir.join(format!(
        ".{}.receipt.{}.tmp",
        receipt.mutation_digest.as_str(),
        Uuid::new_v4().simple()
    ));
    let bytes = serde_json::to_vec(receipt).map_err(|e| HostError::Platform(e.to_string()))?;
    let publication = (|| {
        #[cfg(all(test, windows))]
        {
            if pending_write_fault::take_write_fault() {
                ordering::record("receipt_file_write_fault_injected");
                return Err(HostError::Platform(
                    "injected runtime restart receipt file flush failure".to_owned(),
                ));
            }
        }
        write_durable_file(&tmp, &bytes)?;
        #[cfg(all(test, windows))]
        ordering::record("receipt_hardlink_attempt");
        match std::fs::hard_link(&tmp, &path) {
            Ok(()) => {
                sync_runtime_restart_store_dir(&dir)?;
                #[cfg(all(test, windows))]
                ordering::record("receipt_publication_dir_sync_success");
                Ok(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes =
                    read_bounded_runtime_restart_file(&path, 16 * 1024, "runtime restart receipt")?;
                let existing = serde_json::from_slice::<HostKernelRestartReceipt>(&bytes).map_err(
                    |error| {
                        HostError::RecoveryRequired(format!(
                            "existing runtime restart receipt is malformed: {error}"
                        ))
                    },
                )?;
                existing.validate().map_err(HostError::RecoveryRequired)?;
                if existing == *receipt {
                    // An earlier attempt may have linked this record and then failed its
                    // directory sync; confirm the entry is durable before treating it as published.
                    sync_runtime_restart_store_dir(&dir)?;
                    // F-LOG-HOST-6 (#981) defect 6: no observation here. The
                    // tail below emits the single terminal phase so one replay
                    // never reads as both readback and fresh publication.
                    Ok(true)
                } else {
                    Err(HostError::RecoveryRequired(
                        "existing runtime restart receipt conflicts with reconstructed authority"
                            .to_owned(),
                    ))
                }
            }
            Err(error) => Err(HostError::Platform(error.to_string())),
        }
    })();
    #[cfg(all(test, windows))]
    ordering::record("receipt_tmp_cleanup_attempt");
    let cleanup = std::fs::remove_file(&tmp);
    #[cfg(all(test, windows))]
    ordering::record("receipt_tmp_cleanup_done");
    let sync_after_cleanup = sync_runtime_restart_store_dir(&dir);
    #[cfg(all(test, windows))]
    {
        if sync_after_cleanup.is_ok() {
            ordering::record("receipt_tmp_cleanup_dir_sync_success");
        } else {
            ordering::record("receipt_tmp_cleanup_dir_sync_error");
        }
    }
    // Publication failure is primary; cleanup cannot rename it as success.
    // `replayed` carries the create-race `Replay` disposition through the
    // complete cleanup path (F-LOG-HOST-6 #981 defect 6).
    let replayed = match publication {
        Err(error) => return Err(error),
        Ok(replayed) => match cleanup {
            Ok(()) => replayed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => replayed,
            Err(error) => {
                return Err(HostError::RecoveryRequired(format!(
                    "runtime restart receipt temporary cleanup failed: {error}"
                )));
            }
        },
    };
    sync_after_cleanup?;
    #[cfg(all(test, windows))]
    ordering::record("receipt_durable_before_pending_remove");
    if replayed {
        // The receipt predates this call: re-confirm the directory entry and
        // resume receipt-confirmed pending cleanup through the shared path,
        // then report readback only — never a fresh publication.
        if let Err(error) =
            remove_receipt_confirmed_runtime_restart_pending(host_state_root, &dir, receipt)
        {
            host_restart_observe("host.restart receipt cleanup incomplete observed");
            return Err(error);
        }
        host_restart_observe("host.restart receipt replay observed");
        return Ok(());
    }
    // Receipt is durable before pending removal.
    host_restart_observe("host.restart receipt durable observed");
    // After a durable receipt is known, a pending-cleanup failure retains
    // "receipt committed; cleanup incomplete" instead of reading as
    // publication failure or a second commit.
    if let Err(error) =
        remove_receipt_confirmed_runtime_restart_pending(host_state_root, &dir, receipt)
    {
        host_restart_observe("host.restart receipt cleanup incomplete observed");
        return Err(error);
    }
    host_restart_observe("host.restart receipt published observed");
    Ok(())
}

#[cfg(windows)]
pub(super) fn has_runtime_restart_pending(
    host_state_root: &Path,
    digest: &str,
) -> Result<bool, HostError> {
    let path = runtime_restart_pending_path(host_state_root, digest);
    Ok(read_runtime_restart_pending_identity(&path)?
        .is_some_and(|identity| identity.mutation_digest() == digest))
}

#[cfg(windows)]
pub(super) fn rebind_runtime_restart_receipt(
    receipt: &HostKernelRestartReceipt,
    request: &HostRuntimeControlRequest,
) -> Result<HostKernelRestartReceipt, HostError> {
    host_restart_observe("host.restart rebind requested");
    if request.operation != HostRuntimeControlOperation::ReconcileKernelRestart
        || receipt.mutation_digest != request.mutation_digest
    {
        return Err(HostError::RecoveryRequired(
            "runtime restart receipt is not bound to the requested mutation".to_owned(),
        ));
    }
    let mut rebound = receipt.clone();
    rebound.request_digest = request.request_digest.clone();
    rebound.receipt_digest = rebound.computed_digest().map_err(HostError::Platform)?;
    rebound.validate().map_err(HostError::Platform)?;
    host_restart_observe("host.restart rebind observed");
    Ok(rebound)
}

#[cfg(test)]
#[cfg(windows)]
mod durability_repair_tests {
    use super::*;
    use crate::HostKernelRestartReceipt;
    use crate::TestResult;
    use crate::host_durable_persistence::{ordering, test_fault};
    use crate::{HostInstallationEpoch, PlatformHandle};

    fn test_host() -> Result<HostInstallationEpoch, Box<dyn std::error::Error>> {
        Ok(crate::fresh_host_epoch(
            PlatformHandle::new("test-installation")?,
            None,
        )?)
    }

    fn temp_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "eliot-host-durability-{label}-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn make_receipt(
        mutation_digest: &str,
    ) -> Result<HostKernelRestartReceipt, Box<dyn std::error::Error>> {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: PlatformHandle::new(mutation_digest.to_owned())?,
            request_digest: PlatformHandle::new("a".repeat(64))?,
            old_kernel_generation: PlatformHandle::new("a".repeat(64))?,
            new_kernel_generation: PlatformHandle::new("b".repeat(64))?,
            store_fence: PlatformHandle::new("c".repeat(64))?,
            activation_receipt_digest: PlatformHandle::new("d".repeat(64))?,
            ready_receipt_digest: PlatformHandle::new("e".repeat(64))?,
            receipt_digest: PlatformHandle::new("f".repeat(64))?,
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        Ok(receipt)
    }

    fn make_receipt_for_request(
        request: &super::super::HostRuntimeControlRequest,
    ) -> Result<HostKernelRestartReceipt, Box<dyn std::error::Error>> {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: PlatformHandle::new("a".repeat(64))?,
            new_kernel_generation: PlatformHandle::new("b".repeat(64))?,
            store_fence: PlatformHandle::new("c".repeat(64))?,
            activation_receipt_digest: PlatformHandle::new("d".repeat(64))?,
            ready_receipt_digest: PlatformHandle::new("e".repeat(64))?,
            receipt_digest: PlatformHandle::new("0".repeat(64))?,
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        Ok(receipt)
    }

    fn fresh_request(
        label: &str,
        digest: &str,
    ) -> Result<super::super::HostRuntimeControlRequest, Box<dyn std::error::Error>> {
        Ok(
            super::super::HostRuntimeControlRequest::new_with_mutation_digest(
                HostRuntimeControlOperation::RestartKernel,
                PlatformHandle::new(label)?,
                PlatformHandle::new(digest.to_owned())?,
            )?,
        )
    }

    #[test]
    fn runtime_restart_pending_file_flush_failure_is_not_success() -> TestResult {
        let root = temp_root("rr-pending-flush")?;
        let host = test_host()?;
        let digest = "c4".repeat(32);
        let request = fresh_request("rr-pending-flush", &digest)?;
        ordering::clear();
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        pending_write_fault::inject_write_fault();
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(
            result.is_err(),
            "injected file flush failure is not success"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"pending_file_write_fault_injected".to_owned()),
            "fault injection must be visible: {log:?}"
        );
        assert!(
            !runtime_restart_pending_path(&root, &digest).exists(),
            "a failed temp-file write must not publish a pending record"
        );
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        assert_eq!(
            persist_runtime_restart_pending(&root, &request, &host)?,
            RuntimeRestartPendingPublication::Created
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_file_flush_failure_is_not_success() -> TestResult {
        let root = temp_root("rr-receipt-flush")?;
        let host = test_host()?;
        let digest = "d2".repeat(32);
        let request = fresh_request("rr-receipt-flush", &digest)?;
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let receipt = make_receipt(&digest)?;
        ordering::clear();
        pending_write_fault::inject_write_fault();
        let result = persist_runtime_restart_receipt(&root, &receipt);
        assert!(
            result.is_err(),
            "injected file flush failure is not success"
        );
        assert!(
            !runtime_restart_receipt_path(&root, &digest).exists(),
            "a failed temp-file write must not publish a receipt"
        );
        assert!(
            runtime_restart_pending_path(&root, &digest).exists(),
            "pending evidence must remain when the receipt write fails"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"receipt_file_write_fault_injected".to_owned()),
            "fault injection must be visible: {log:?}"
        );
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_exact_record_replays() -> TestResult {
        let root = temp_root("rr-pending-replay")?;
        let host = test_host()?;
        let digest = "c5".repeat(32);
        let request = fresh_request("rr-pending-replay", &digest)?;
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        ordering::clear();
        assert_eq!(
            persist_runtime_restart_pending(&root, &request, &host)?,
            RuntimeRestartPendingPublication::Created
        );
        ordering::clear();
        assert_eq!(
            persist_runtime_restart_pending(&root, &request, &host)?,
            RuntimeRestartPendingPublication::Replay
        );
        let log = ordering::take_log();
        assert!(
            log.iter().any(|e| e == "dir_sync_success"),
            "replay must re-confirm the directory entry: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_conflicting_record_is_fail_closed() -> TestResult {
        let root = temp_root("rr-pending-conflict")?;
        let host = test_host()?;
        let digest = "c6".repeat(32);
        let request = fresh_request("rr-pending-conflict", &digest)?;
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let conflicting = fresh_request("rr-pending-conflict-other", &digest)?;
        let result = persist_runtime_restart_pending(&root, &conflicting, &host);
        assert!(
            matches!(result, Err(crate::HostError::RecoveryRequired(_))),
            "a conflicting pending record must fail closed: {result:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_exact_record_replays() -> TestResult {
        let root = temp_root("rr-receipt-replay")?;
        let host = test_host()?;
        let digest = "d3".repeat(32);
        let request = fresh_request("rr-receipt-replay", &digest)?;
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let receipt = make_receipt(&digest)?;
        persist_runtime_restart_receipt(&root, &receipt)?;
        ordering::clear();
        persist_runtime_restart_receipt(&root, &receipt)?;
        let log = ordering::take_log();
        assert!(
            log.iter().any(|e| e == "dir_sync_success"),
            "receipt replay must re-confirm the directory entry: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_conflicting_record_is_fail_closed() -> TestResult {
        let root = temp_root("rr-receipt-conflict")?;
        let host = test_host()?;
        let digest = "d4".repeat(32);
        let request = fresh_request("rr-receipt-conflict", &digest)?;
        test_fault::clear_sync_fault();
        pending_write_fault::clear_write_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let receipt = make_receipt(&digest)?;
        persist_runtime_restart_receipt(&root, &receipt)?;
        let mut conflicting = receipt.clone();
        conflicting.request_digest = PlatformHandle::new("9".repeat(64))?;
        conflicting.receipt_digest = conflicting.computed_digest()?;
        let result = persist_runtime_restart_receipt(&root, &conflicting);
        assert!(
            matches!(result, Err(crate::HostError::RecoveryRequired(_))),
            "a conflicting receipt must fail closed: {result:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_dir_sync_permission_denied_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-perm")?;
        let host = test_host()?;
        let digest = "c1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-perm")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err(), "PermissionDenied must propagate");
        assert!(
            matches!(&result, Err(crate::HostError::Platform(msg)) if msg.contains("PermissionDenied") || msg.contains("injected")),
            "error must be Platform"
        );
        let log = ordering::take_log();
        assert!(
            log.contains(&"dir_sync_fault_injected".to_owned())
                || log.contains(&"dir_sync_attempt".to_owned())
        );
        // The hard link is published before the directory sync that failed, so
        // the record exists but its durability was never confirmed.
        let pending_path = runtime_restart_pending_path(&root, &digest);
        assert!(
            pending_path.exists(),
            "the link precedes the failed directory sync"
        );
        // A retry must confirm durability instead of replaying the unsynced record.
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        assert!(
            persist_runtime_restart_pending(&root, &request, &host).is_err(),
            "replay must not skip the failed directory sync"
        );
        test_fault::clear_sync_fault();
        assert_eq!(
            persist_runtime_restart_pending(&root, &request, &host)?,
            RuntimeRestartPendingPublication::Replay
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_dir_sync_invalid_input_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-invalid")?;
        let host = test_host()?;
        let digest = "c2".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-invalid")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::InvalidInput);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        let log = ordering::take_log();
        assert!(
            log.iter()
                .any(|e| e.contains("fault") || e.contains("attempt"))
        );
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_pending_dir_sync_unsupported_is_not_swallowed() -> TestResult {
        let root = temp_root("rr-pending-unsupported")?;
        let host = test_host()?;
        let digest = "c3".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-pending-unsupported")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        ordering::clear();
        test_fault::clear_sync_fault();
        test_fault::inject_sync_fault(std::io::ErrorKind::Unsupported);
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::HostError::Platform(_))));
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_dir_sync_failure_keeps_pending_evidence() -> TestResult {
        let root = temp_root("rr-receipt-keep-pending")?;
        let host = test_host()?;
        let digest = "d1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-receipt-keep")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        // First create pending successfully
        test_fault::clear_sync_fault();
        ordering::clear();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let pending_path = runtime_restart_pending_path(&root, &digest);
        assert!(pending_path.exists());
        // Now attempt receipt with injected dir sync failure on publication
        let receipt = make_receipt(&digest)?;
        test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
        ordering::clear();
        let result = persist_runtime_restart_receipt(&root, &receipt);
        assert!(
            result.is_err(),
            "dir sync failure must propagate and not claim durable"
        );
        // Pending evidence must remain (not removed)
        assert!(
            pending_path.exists(),
            "pending evidence must remain after failed receipt dir sync"
        );
        // Receipt may be absent or not durable
        test_fault::clear_sync_fault();
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_ordering_file_sync_before_dir_sync_before_cleanup() -> TestResult {
        let root = temp_root("rr-ordering")?;
        let host = test_host()?;
        let digest = "e1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-ordering")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        test_fault::clear_sync_fault();
        ordering::clear();
        let result = persist_runtime_restart_pending(&root, &request, &host)?;
        assert_eq!(result, RuntimeRestartPendingPublication::Created);
        let log = ordering::take_log();
        let file_idx = log
            .iter()
            .position(|e| e == "file_sync_success")
            .ok_or("file_sync must be logged")?;
        let dir_idx = log
            .iter()
            .position(|e| e == "dir_sync_success" || e == "pending_publication_dir_sync_success")
            .ok_or("dir sync success must be logged")?;
        let cleanup_idx = log
            .iter()
            .position(|e| e == "tmp_cleanup_dir_sync_success")
            .ok_or("cleanup dir sync must be logged")?;
        assert!(
            file_idx < dir_idx,
            "file sync must precede dir sync: {log:?}"
        );
        assert!(
            dir_idx < cleanup_idx,
            "dir sync must precede cleanup dir sync: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn runtime_restart_receipt_ordering_durable_before_pending_removal() -> TestResult {
        let root = temp_root("rr-receipt-ordering")?;
        let host = test_host()?;
        let digest = "f1".repeat(32);
        let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RestartKernel,
            PlatformHandle::new("rr-receipt-order")?,
            PlatformHandle::new(digest.clone())?,
        )?;
        test_fault::clear_sync_fault();
        persist_runtime_restart_pending(&root, &request, &host)?;
        let receipt = make_receipt(&digest)?;
        ordering::clear();
        persist_runtime_restart_receipt(&root, &receipt)?;
        let log = ordering::take_log();
        let durable_idx = log
            .iter()
            .position(|e| e == "receipt_durable_before_pending_remove")
            .ok_or("durable marker missing")?;
        let pending_remove_idx = log
            .iter()
            .position(|e| e == "pending_remove_attempt")
            .ok_or("pending remove attempt missing")?;
        let pending_dir_idx = log
            .iter()
            .position(|e| e == "pending_remove_dir_sync_success")
            .ok_or("pending remove dir sync missing")?;
        assert!(durable_idx < pending_remove_idx);
        assert!(pending_remove_idx < pending_dir_idx);
        // After durable receipt, pending should be gone
        assert!(!runtime_restart_pending_path(&root, &digest).exists());
        assert!(runtime_restart_receipt_path(&root, &digest).exists());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    #[ignore = "child-process target of the abrupt-termination test; returns early unless spawned with its environment"]
    fn durability_child_runtime() -> TestResult {
        if std::env::var("ELIOT_HOST_DURABILITY_CHILD_RUNTIME").is_err() {
            return Ok(());
        }
        let root = PathBuf::from(std::env::var("ELIOT_HOST_CHILD_ROOT")?);
        let digest = std::env::var("ELIOT_HOST_CHILD_DIGEST")?;
        let mode = std::env::var("ELIOT_HOST_CHILD_MODE").unwrap_or_else(|_| "success".to_owned());
        let host = test_host()?;
        if mode == "success" {
            let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
                HostRuntimeControlOperation::RestartKernel,
                PlatformHandle::new("rr-child")?,
                PlatformHandle::new(digest.clone())?,
            )?;
            persist_runtime_restart_pending(&root, &request, &host)?;
            let receipt = make_receipt_for_request(&request)?;
            persist_runtime_restart_receipt(&root, &receipt)?;
            let _ = std::fs::File::open(&root).and_then(|f| f.sync_all());
        } else if mode == "fault" {
            let request = super::super::HostRuntimeControlRequest::new_with_mutation_digest(
                HostRuntimeControlOperation::RestartKernel,
                PlatformHandle::new("rr-child-fault")?,
                PlatformHandle::new(digest.clone())?,
            )?;
            let pending_path = runtime_restart_pending_path(&root, &digest);
            if !pending_path.exists() {
                persist_runtime_restart_pending(&root, &request, &host)?;
            }
            let receipt = make_receipt_for_request(&request)?;
            test_fault::inject_sync_fault(std::io::ErrorKind::PermissionDenied);
            let result = persist_runtime_restart_receipt(&root, &receipt);
            let marker = root.join("child_fault_marker");
            if result.is_err() {
                std::fs::write(&marker, b"fault_propagated")?;
                let _ = std::fs::File::open(&marker).and_then(|f| f.sync_all());
            } else {
                std::fs::write(&marker, b"unexpected_success")?;
            }
        }
        std::process::abort();
    }

    #[test]
    fn runtime_restart_abrupt_child_causal_success_and_fault_reopen() -> TestResult {
        let root = temp_root("rr-abrupt-causal")?;
        let digest = "a1".repeat(32);
        let exe = std::env::current_exe()?;
        let mut child = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime_restart_state::durability_repair_tests::durability_child_runtime")
            .env("ELIOT_HOST_DURABILITY_CHILD_RUNTIME", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest)
            .env("ELIOT_HOST_CHILD_MODE", "success")
            .spawn()?;
        let status = child.wait()?;
        assert!(!status.success(), "child must abort");
        let loaded = load_durable_runtime_restarts(&root)?;
        assert!(loaded.contains_key(&digest), "receipt must survive abort");
        let digest2 = "a2".repeat(32);
        let mut child2 = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime_restart_state::durability_repair_tests::durability_child_runtime")
            .env("ELIOT_HOST_DURABILITY_CHILD_RUNTIME", "1")
            .env("ELIOT_HOST_CHILD_ROOT", &root)
            .env("ELIOT_HOST_CHILD_DIGEST", &digest2)
            .env("ELIOT_HOST_CHILD_MODE", "fault")
            .spawn()?;
        let status2 = child2.wait()?;
        assert!(!status2.success());
        let marker = root.join("child_fault_marker");
        let bytes = std::fs::read(&marker)?;
        assert_eq!(bytes, b"fault_propagated");
        assert!(runtime_restart_pending_path(&root, &digest2).exists());
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
}
