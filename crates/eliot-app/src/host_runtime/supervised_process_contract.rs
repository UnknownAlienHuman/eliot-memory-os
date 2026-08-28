//! Typed supervision contract for host-runtime supervised child processes.
//!
//! Architecture handles: `A2.2` (Roles), `A13.2` (Kernel and failure domains),
//! `A13.3` (Module supervision and Doctor). Implementation handles: `I1.1`
//! (Process principle), `I1.4` (Supervision tree), `I1.8` (Exact ownership and
//! call paths). Canonical sources are the repository-local
//! `docs/architecture/ELIOT_ARCHITECTURE.md` and
//! `docs/architecture/ELIOT_IMPLEMENTATION.md`.
//!
//! This module owns only the contiguous typed process-supervision input/output
//! policy closure extracted from `host_runtime::supervised_process.rs`:
//! `SupervisedChildKind`, `ChildCriticality`, `RestartStrategy`,
//! `ProcessRestartPolicy`, `SupervisedProcessSpec`, and
//! `SupervisedProcessOutput`. It records policy values, restart bounds, and
//! bounded output/receipt facts; it does not implement process launch, SCM,
//! lifecycle, canonical/semantic/write, provider authority, or SurrealDB.
//! Those concerns remain in the parent `supervised_process` worker/runner,
//! `eliot-installation`/SCM, canonical store, and provider/authority surfaces.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use eliot_types::{ProcessReapReceipt, ProviderTimeoutClass, ProviderTimeoutProfile};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the complete child taxonomy is part of the runtime supervision contract"
)]
pub enum SupervisedChildKind {
    McpPreflight,
    Provider,
    TruthAdapter,
    Verifier,
    Maintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "all criticality levels are contract values even before every caller is migrated"
)]
pub enum ChildCriticality {
    Optional,
    InvocationDependency,
    CoreDependency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartStrategy {
    Never,
    OneForOne,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRestartPolicy {
    pub strategy: RestartStrategy,
    pub max_restarts: u32,
    pub restart_window_seconds: u64,
    pub base_backoff_ms: u64,
    pub pre_dispatch_only: bool,
}

#[derive(Clone, Debug)]
pub struct SupervisedProcessSpec {
    pub operation_id: String,
    pub invocation_id: Option<String>,
    pub generation: u64,
    pub child_kind: SupervisedChildKind,
    pub criticality: ChildCriticality,
    pub restart_policy: ProcessRestartPolicy,
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub stdin_payload: Option<Vec<u8>>,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub timeout_profile: ProviderTimeoutProfile,
    pub runtime_contract_sha256: Option<String>,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent receipt facts mirror the runtime supervision contract"
)]
pub struct SupervisedProcessOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub timeout_class: Option<ProviderTimeoutClass>,
    pub cancelled: bool,
    pub worker_error: Option<String>,
    pub observed_processes: Vec<eliot_windows_ipc::ProcessImageIdentity>,
    pub process_started_at: OffsetDateTime,
    pub first_output_at: Option<OffsetDateTime>,
    pub last_output_at: Option<OffsetDateTime>,
    pub process_exit_at: Option<OffsetDateTime>,
    pub cleanup_completed_at: OffsetDateTime,
    pub reap_receipt: ProcessReapReceipt,
}
