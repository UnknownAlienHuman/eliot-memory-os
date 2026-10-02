//! Windows-only live edge proof for the one-shot LSP bridge.
//!
//! This example exercises the installed rust-analyzer through the real
//! `WindowsProcessExecutor`, including its suspended launch and process
//! evidence path. Its local dispatch permit fixture is deliberately limited
//! to this module/edge proof; it is not evidence of the authenticated daemon
//! queue or the original Kernel caller composition. The selected-source
//! owner proof lives with the daemon caller tests.
//!
//! Arguments are explicit: `<rust-analyzer.exe> <scratch-root>
//! <workspace-root> <output-root>`. The manager supplies lane-local roots,
//! `TEMP`/`TMP`, and `CARGO_TARGET_DIR`; the example refuses paths outside
//! those contours and leaves its proof fixture for review and cleanup.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(windows)]
mod live {
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use eliot_contracts::{EpochId, EpochLineageId, sha256_hex};
    use eliot_lsp_bridge::{
        AnalyzerConfig, Coverage, FailureDisposition, Freshness, LspBridge, LspCommand,
        NormalizedResult, SemanticOperation, SourceCandidate, finalize_diagnostics,
        finalize_scip, finalize_version,
    };
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority,
        DispatchValidationContext, DispatchValidationPort, EnvironmentInheritance,
        EnvironmentProjection, EvidenceSinkError, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
        ProcessExecutionError, ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits,
        SessionId, SuspendedProcessIdentity,
    };
    use eliot_process_executor::WindowsProcessExecutor;

    const LANE_SCRATCH_ROOT: &str =
        r"C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\v2\workers\CS2\scratch";
    const LANE_TARGET_ROOT: &str =
        r"C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\v2\targets\CS2";
    const EPOCH_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const STDOUT_LIMIT: u64 = 8 * 1024 * 1024;
    const STDERR_LIMIT: u64 = 2 * 1024 * 1024;
    const WALL_TIMEOUT_MS: u64 = 240_000;

    static NEXT_INVOCATION: AtomicU64 = AtomicU64::new(1);
    const CHILD_ENV_ALLOWLIST: [&str; 8] = [
        "PATH",
        "RUSTUP_HOME",
        "CARGO_HOME",
        "RUSTC",
        "USERPROFILE",
        "SystemRoot",
        "TEMP",
        "TMP",
    ];

    type RunResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct EvidenceSink {
        evidence: Mutex<Vec<ProcessEvidence>>,
    }

    impl ProcessEvidenceSink for EvidenceSink {
        fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
            self.evidence
                .lock()
                .map_err(|_| EvidenceSinkError {
                    message: "live acceptance evidence sink lock poisoned".to_owned(),
                })?
                .push(evidence);
            Ok(())
        }
    }

    /// One-shot local permit issuer used only to drive real Windows process
    /// execution in this example. It never returns synthetic process receipts.
    struct LocalDispatchFixture {
        authority: Mutex<DispatchPermitAuthority>,
        context: Mutex<Option<DispatchValidationContext>>,
        executable: String,
        executable_sha256: String,
        scratch_root: PathBuf,
        cargo_home: PathBuf,
        target_root: PathBuf,
        temp_root: PathBuf,
        tmp_root: PathBuf,
    }

    impl LocalDispatchFixture {
        fn new(
            executable: String,
            executable_sha256: String,
            scratch_root: PathBuf,
            cargo_home: PathBuf,
            target_root: PathBuf,
            temp_root: PathBuf,
            tmp_root: PathBuf,
        ) -> RunResult<Self> {
            let authority = DispatchPermitAuthority::activate(
                DispatchAuthorityId::new("lsp-live-local-fixture")?,
                KernelDispatchKey::from_secret_bytes([0x6c; 32])?,
            );
            Ok(Self {
                authority: Mutex::new(authority),
                context: Mutex::new(None),
                executable,
                executable_sha256,
                scratch_root,
                cargo_home,
                target_root,
                temp_root,
                tmp_root,
            })
        }

        fn request(&self, command: &LspCommand) -> RunResult<ProcessRequest> {
            if command.executable != self.executable {
                return Err("live command changed the pinned executable path".into());
            }
            let sequence = NEXT_INVOCATION.fetch_add(1, Ordering::Relaxed);
            let generation = Generation::new(1)?;
            let executable_bytes = std::fs::read(&command.executable)?;
            let executable_digest = sha256_hex(&executable_bytes);
            if executable_digest != self.executable_sha256 {
                return Err("rust-analyzer bytes changed during the live proof".into());
            }
            let operation = format!("lsp-live-{sequence}");
            let intent = ProcessIntent::new(
                OperationId::new(operation.clone())?,
                ProcessTreeId::new(format!("{operation}-tree"))?,
                JobId::new(format!("{operation}-job"))?,
                ImageId::new(format!("{operation}-image"))?,
                SessionId::new(format!("{operation}-session"))?,
                generation,
                command.executable.clone(),
                executable_digest,
                command.arguments.clone(),
                command.working_directory.clone(),
                self.child_environment()?,
                ResourceLimits::new(
                    WALL_TIMEOUT_MS,
                    Some(WALL_TIMEOUT_MS),
                    Some(4 * 1024 * 1024 * 1024),
                    STDOUT_LIMIT,
                    STDERR_LIMIT,
                    16,
                )?,
            )?;

            let epoch = test_epoch()?;
            let fence = FencingToken::new(
                epoch.clone(),
                generation,
                format!("{operation}-fence"),
            )?;
            let revisions = BTreeMap::from([(
                "lsp-live-fixture".to_owned(),
                sha256_hex(operation.as_bytes()),
            )]);
            let now = unix_ms();
            let issuance = PermitIssuance::new(
                ActionLeaseRef::new(format!("{operation}-lease"))?,
                fence.clone(),
                revisions.clone(),
                now.saturating_sub(1).max(1),
                now.saturating_add(WALL_TIMEOUT_MS),
                format!("{operation}-nonce"),
            )?;
            let permit = self
                .authority
                .lock()
                .map_err(|_| "local dispatch authority lock poisoned")?
                .issue(&intent, issuance)?;
            let context = DispatchValidationContext::new(
                ClockObservation {
                    valid_time_ms: Some(i64::try_from(now)?),
                    known_time_ms: Some(i64::try_from(now)?),
                    transaction_sequence: None,
                    monotonic_ns: Some(1),
                },
                fence,
                epoch,
                revisions,
                sequence,
            )?;
            *self
                .context
                .lock()
                .map_err(|_| "local dispatch context lock poisoned")? = Some(context);
            Ok(ProcessRequest::new(intent, permit)?)
        }

        fn child_environment(&self) -> RunResult<EnvironmentProjection> {
            if !self.cargo_home.starts_with(&self.scratch_root) {
                return Err("CARGO_HOME escaped the explicit scratch root".into());
            }
            let mut values = BTreeMap::new();
            for name in ["PATH", "RUSTUP_HOME", "SystemRoot"] {
                let value = std::env::var(name)
                    .map_err(|_| format!("required child environment variable {name} is missing"))?;
                values.insert(name.to_owned(), value);
            }
            values.insert(
                "CARGO_HOME".to_owned(),
                self.cargo_home.to_string_lossy().into_owned(),
            );
            values.insert(
                "CARGO_TARGET_DIR".to_owned(),
                self.target_root.to_string_lossy().into_owned(),
            );
            values.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
            values.insert("TEMP".to_owned(), self.temp_root.to_string_lossy().into_owned());
            values.insert("TMP".to_owned(), self.tmp_root.to_string_lossy().into_owned());
            Ok(EnvironmentProjection::new(
                values,
                Vec::new(),
                EnvironmentInheritance::None,
            )?)
        }
    }

    impl DispatchValidationPort for LocalDispatchFixture {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<eliot_process::ValidatedDispatch, ProcessExecutionError> {
            let context = self
                .context
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable(
                        "local dispatch context lock poisoned".to_owned(),
                    )
                })?
                .take()
                .ok_or_else(|| {
                    ProcessExecutionError::Unavailable(
                        "local dispatch context is missing".to_owned(),
                    )
                })?;
            self.authority
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable(
                        "local dispatch authority lock poisoned".to_owned(),
                    )
                })?
                .validate_and_consume(request, observed, &context)
                .map_err(ProcessExecutionError::from)
        }
    }

    struct FixtureWorkspace(PathBuf);

    impl FixtureWorkspace {
        fn create(root: PathBuf) -> RunResult<Self> {
            if std::fs::read_dir(&root)?.next().is_some() {
                return Err("workspace root must be empty before the live proof".into());
            }
            std::fs::create_dir_all(root.join("src"))?;
            std::fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"eliot_lsp_live_probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )?;
            std::fs::write(
                root.join("src/lib.rs"),
                "pub fn lsp_live_probe_symbol() -> i32 {\n    7\n}\n\npub fn lsp_live_probe_caller() -> i32 {\n    lsp_live_probe_symbol()\n}\n",
            )?;
            Ok(Self(root))
        }

        fn root(&self) -> &Path {
            &self.0
        }
    }

    fn test_epoch() -> RunResult<EpochId> {
        Ok(EpochId::new(
            EpochLineageId::new(EPOCH_LINEAGE)?,
            NonZeroU64::new(1).ok_or("epoch sequence must be non-zero")?,
        )?)
    }

    fn canonical_directory(path: PathBuf, label: &str) -> RunResult<PathBuf> {
        if !path.is_absolute() {
            return Err(format!("{label} must be an absolute path").into());
        }
        let path = std::fs::canonicalize(path)?;
        if !path.is_dir() {
            return Err(format!("{label} is not a directory").into());
        }
        Ok(path)
    }

    fn canonical_file(path: PathBuf, label: &str) -> RunResult<PathBuf> {
        if !path.is_absolute() {
            return Err(format!("{label} must be an absolute path").into());
        }
        let path = std::fs::canonicalize(path)?;
        if !path.is_file() {
            return Err(format!("{label} is not a file").into());
        }
        Ok(path)
    }

    fn validate_roots(
        scratch: &Path,
        workspace: &Path,
        output: &Path,
        temp: &Path,
        tmp: &Path,
        target: &Path,
    ) -> RunResult<()> {
        let worktree = canonical_directory(std::env::current_dir()?, "current worktree")?;
        let lane_scratch = canonical_directory(PathBuf::from(LANE_SCRATCH_ROOT), "CS2 lane scratch")?;
        let lane_target = canonical_directory(PathBuf::from(LANE_TARGET_ROOT), "CS2 target root")?;
        if !scratch.starts_with(worktree) && !scratch.starts_with(lane_scratch) {
            return Err("scratch root must be within this worktree or CS2 lane scratch".into());
        }
        for (label, path) in [("workspace", workspace), ("output", output), ("TEMP", temp), ("TMP", tmp)] {
            if !path.starts_with(scratch) {
                return Err(format!("{label} must remain below the explicit scratch root").into());
            }
        }
        if !target.starts_with(lane_target) {
            return Err("CARGO_TARGET_DIR must remain under the manager's CS2 target root".into());
        }
        Ok(())
    }

    fn unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => thread::yield_now(),
            }
        }
    }

    fn execute(
        bridge: &LspBridge<WindowsProcessExecutor>,
        authority: &LocalDispatchFixture,
        sink: Arc<dyn ProcessEvidenceSink>,
        command: &LspCommand,
    ) -> RunResult<ProcessEvidence> {
        let request = authority.request(command)?;
        let operation = request.operation_id().clone();
        block_on(bridge.launch(command, request, sink))?;

        let deadline = Instant::now() + Duration::from_millis(WALL_TIMEOUT_MS);
        loop {
            let view = block_on(bridge.inspect(&operation))?;
            if view.lifecycle().is_terminal() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!("{} did not reach a terminal state", operation.as_str()).into());
            }
            thread::sleep(Duration::from_millis(50));
        }

        let evidence = block_on(bridge.reconcile(&operation))?;
        if !LspBridge::<WindowsProcessExecutor>::completed(&evidence) {
            return Err(format!(
                "{} did not complete: {:?}",
                operation.as_str(),
                evidence.view().exit()
            )
            .into());
        }
        if LspBridge::<WindowsProcessExecutor>::stdout_truncated(&evidence)
            || LspBridge::<WindowsProcessExecutor>::stderr_truncated(&evidence)
        {
            return Err(format!("{} output was truncated", operation.as_str()).into());
        }
        Ok(evidence)
    }

    fn run() -> RunResult {
        let mut args = std::env::args_os().skip(1);
        let usage = "usage: live_acceptance <rust-analyzer.exe> <scratch-root> <workspace-root> <output-root>";
        let executable = canonical_file(
            PathBuf::from(args.next().ok_or(usage)?),
            "rust-analyzer",
        )?;
        let scratch = canonical_directory(PathBuf::from(args.next().ok_or(usage)?), "scratch root")?;
        let workspace_root = canonical_directory(PathBuf::from(args.next().ok_or(usage)?), "workspace root")?;
        let output_root = canonical_directory(PathBuf::from(args.next().ok_or(usage)?), "output root")?;
        if args.next().is_some() {
            return Err("unexpected live acceptance arguments".into());
        }
        let temp_root = canonical_directory(
            PathBuf::from(std::env::var_os("TEMP").ok_or("TEMP must be set to lane scratch")?),
            "TEMP",
        )?;
        let tmp_root = canonical_directory(
            PathBuf::from(std::env::var_os("TMP").ok_or("TMP must be set to lane scratch")?),
            "TMP",
        )?;
        let target_root = canonical_directory(
            PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").ok_or(
                "CARGO_TARGET_DIR must be supplied by the CS2 manager",
            )?),
            "CARGO_TARGET_DIR",
        )?;
        validate_roots(
            &scratch,
            &workspace_root,
            &output_root,
            &temp_root,
            &tmp_root,
            &target_root,
        )?;
        if std::fs::read_dir(&output_root)?.next().is_some() {
            return Err("output root must be empty before the live proof".into());
        }
        let cargo_home_path = scratch.join("cargo-home");
        if cargo_home_path.exists() {
            return Err("scratch cargo-home must not already exist".into());
        }
        std::fs::create_dir(cargo_home_path)?;
        let cargo_home = canonical_directory(scratch.join("cargo-home"), "scratch CARGO_HOME")?;
        if !cargo_home.starts_with(&scratch) {
            return Err("scratch CARGO_HOME resolved outside the explicit scratch root".into());
        }
        let workspace = FixtureWorkspace::create(workspace_root.clone())?;
        let executable_text = executable.to_string_lossy().into_owned();
        let executable_sha256 = sha256_hex(&std::fs::read(&executable)?);

        let workspace_root = workspace.root().to_string_lossy().into_owned();
        let candidate = SourceCandidate {
            workspace_root: workspace_root.clone(),
            path: Some("src/lib.rs".to_owned()),
            symbol: None,
        };
        let mut config = AnalyzerConfig::for_workspace(executable_text.clone())?;

        let authority = Arc::new(LocalDispatchFixture::new(
            executable_text.clone(),
            executable_sha256.clone(),
            scratch.clone(),
            cargo_home,
            target_root.clone(),
            temp_root.clone(),
            tmp_root.clone(),
        )?);
        let validation: Arc<dyn DispatchValidationPort> = authority.clone();
        let executor = Arc::new(WindowsProcessExecutor::new(validation));
        let bridge = LspBridge::new(Arc::clone(&executor));
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(EvidenceSink::default());

        // Ask the exact installed binary for its own identity through the
        // shared executor, then bind the version line to the semantic result.
        let version_command = LspCommand::version(&config, &candidate)?;
        let version_evidence = execute(&bridge, &authority, Arc::clone(&sink), &version_command)?;
        let version_stdout = LspBridge::<WindowsProcessExecutor>::stdout_bytes(&version_evidence);
        let version_result = finalize_version(
            &config,
            &candidate,
            version_stdout,
            false,
            LspBridge::<WindowsProcessExecutor>::exit_code(&version_evidence),
            true,
            unix_ms(),
        );
        let NormalizedResult::Version { version, receipt } = version_result else {
            return Err("version request did not produce a version result".into());
        };
        if version.is_empty() || receipt.executable != executable_text {
            return Err("version result lost the exact executable identity".into());
        }

        let diagnostics_command = LspCommand::diagnostics(&config, &candidate)?;
        let diagnostics_evidence = execute(
            &bridge,
            &authority,
            Arc::clone(&sink),
            &diagnostics_command,
        )?;
        let invoked_at = unix_ms();
        let diagnostics = finalize_diagnostics(
            &config,
            &candidate,
            Some(&version),
            LspBridge::<WindowsProcessExecutor>::stdout_bytes(&diagnostics_evidence),
            false,
            LspBridge::<WindowsProcessExecutor>::exit_code(&diagnostics_evidence),
            true,
            invoked_at,
        );
        let NormalizedResult::Diagnostics { receipt, .. } = &diagnostics else {
            return Err("diagnostics request did not produce a normalized result".into());
        };
        if receipt.executable != executable_text
            || receipt.executable_version.as_deref() != Some(version.as_str())
            || receipt.config_hash != config.config_hash()
            || receipt.candidate != candidate.reference()
            || receipt.invoked_at_unix_ms != invoked_at
            || receipt.coverage != (Coverage::Workspace { root: workspace_root.clone() })
            || receipt.disposition != FailureDisposition::Success
        {
            return Err("diagnostics receipt does not match the live request".into());
        }
        let diagnostics_config_hash = receipt.config_hash.clone();
        // The low-level receipt is intentionally stale until an original
        // source owner revalidates this candidate; this executable proves the
        // actual analyzer/process edge and does not claim that owner step.
        if !matches!(&receipt.freshness, Freshness::Stale { .. }) {
            return Err("unowned live edge must not claim source currentness".into());
        }

        let source_path = workspace.root().join("src/lib.rs");
        let source_before = std::fs::read(&source_path)?;
        config.scip_output_path = Some(
            output_root
                .join("live-index.scip")
                .to_string_lossy()
                .into_owned(),
        );
        let scip_command = LspCommand::scip(&config, &candidate)?;
        let scip_evidence = execute(&bridge, &authority, Arc::clone(&sink), &scip_command)?;
        let sidecar_path = config
            .scip_output_path
            .as_deref()
            .ok_or("SCIP path was not configured")?;
        let sidecar = std::fs::read(sidecar_path)?;
        if sidecar.is_empty() {
            return Err("rust-analyzer emitted an empty SCIP index".into());
        }

        let symbol_result = finalize_scip(
            &config,
            &candidate,
            &SemanticOperation::Symbols {
                path_scope: "src/lib.rs".to_owned(),
            },
            &sidecar,
            sidecar_path,
            unix_ms(),
            None,
        );
        let NormalizedResult::Symbols { items, .. } = symbol_result else {
            return Err("SCIP result did not normalize to symbols".into());
        };
        let symbol = items
            .iter()
            .find(|item| item.display_name.as_deref() == Some("lsp_live_probe_symbol"))
            .map(|item| item.symbol.clone())
            .ok_or("live SCIP index did not contain the selected probe symbol")?;

        let rename = finalize_scip(
            &config,
            &candidate,
            &SemanticOperation::Rename {
                symbol,
                new_name: "lsp_live_probe_symbol_renamed".to_owned(),
            },
            &sidecar,
            sidecar_path,
            unix_ms(),
            None,
        );
        let NormalizedResult::Rename { candidate: edits, receipt: rename_receipt } = rename else {
            return Err("rename request did not produce an edit candidate".into());
        };
        let source_after = std::fs::read(&source_path)?;
        if edits.applied
            || edits.edits.is_empty()
            || source_before != source_after
            || rename_receipt.executable != executable_text
            || rename_receipt.config_hash != config.config_hash()
        {
            return Err("rename was applied, incomplete, or lost its request binding".into());
        }

        println!("proof_scope=real_windows_process_executor_module_edge");
        println!("kernel_queue_proof=false");
        println!("scratch_root={}", scratch.display());
        println!("workspace_root={}", workspace_root);
        println!("output_root={}", output_root.display());
        println!("target_root={}", target_root.display());
        println!("temp_root={}", temp_root.display());
        println!("tmp_root={}", tmp_root.display());
        println!("executable={executable_text}");
        if sha256_hex(&std::fs::read(&executable)?) != executable_sha256 {
            return Err("rust-analyzer bytes changed before proof output".into());
        }
        println!("executable_sha256={executable_sha256}");
        println!("version={version}");
        println!("diagnostics_config_hash={diagnostics_config_hash}");
        println!("rename_config_hash={}", config.config_hash());
        println!("candidate={}", candidate.reference());
        println!("diagnostics_invoked_at_unix_ms={invoked_at}");
        println!("diagnostics_freshness={:?}", receipt.freshness);
        println!("diagnostics_coverage={:?}", receipt.coverage);
        println!("diagnostics_exit_code={:?}", receipt.tool_exit_code);
        println!("scip_exit_code={:?}", LspBridge::<WindowsProcessExecutor>::exit_code(&scip_evidence));
        println!("rename_edit_count={}", edits.edits.len());
        println!("rename_applied={}", edits.applied);
        println!("source_bytes_unchanged={}", source_before == source_after);
        println!("normalized_result={}", serde_json::to_string(&diagnostics)?);
        Ok(())
    }

    pub(super) fn main() -> RunResult {
        run()
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    live::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("live rust-analyzer acceptance requires the Windows ProcessExecutor");
}
