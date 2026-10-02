//! Physical fixtures for the admitted builtin provider routes.
//!
//! These tests use an isolated, test-only copy of the physical P-07 fixture
//! authority retained from origin/main so they can exercise the actual Windows
//! executor through low-level runner bindings. Canonical Kernel admission is
//! covered by the resolver's separate owner-issued acceptance fixture.

use self::legacy_main_fixture::{
    DispatchCell, STAGE_STDOUT_BYTES, STAGE_WALL_TIMEOUT_MS, StageExecutor, StagePort, StageRoute,
    await_terminal_view, now_unix_ms, observation_clock, observed_supply_chain, process_epoch,
    resolve_tool, system_nanos,
};
use super::*;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(all(test, windows))]
mod legacy_main_fixture {
    use super::super::*;

    // The physical owner, tool observation, and limits below are the existing
    // origin/main f4c411941 fixture definitions. This namespace keeps them
    // separate from the resolver's Kernel-issued production types; the process
    // intents additionally bind the owner-observed Windows file identity that
    // the current executor requires.

    use std::fmt::Write as _;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence, sha256_hex,
    };
    use eliot_instrument_runner::{
        ADMITTED_SCOPE_CLASS, InstrumentSpec, SupplyChainReceipt, profile::TOOLCHAIN_PATH_ENV,
    };
    use eliot_process::{
        ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
        DispatchValidationContext, EnvironmentInheritance, EnvironmentProjection, ExitDisposition,
        FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
        ProcessExecutionView, ProcessExecutor, ProcessIntent, ProcessRequest, ProcessStartReceipt,
        ProcessTreeId, ResourceLimits, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
    };
    use eliot_process_executor::{
        DispatchValidationPort, ExecutableObservation, WindowsProcessExecutor,
        environment_projection_digest,
    };
    const VALIDATION_REVISION: u64 = 1;

    /// Registry generation the shared verification registry is admitted at.
    const VERIFICATION_REGISTRY_GENERATION: u64 = 1;

    /// Authority epoch lineage of this one-shot resolution process.
    const EPOCH_LINEAGE: &str = "eliot-verification-profile-resolver";

    /// Product identity every stage invocation of this run belongs to.
    const ADMITTED_PRODUCT: &str = "eliot";

    pub(super) const STAGE_STDOUT_BYTES: u64 = 4 * 1024 * 1024;

    /// Wall bound for one admitted stage child, in milliseconds.
    pub(super) const STAGE_WALL_TIMEOUT_MS: u64 = 3_600_000;

    /// Ceiling on descendant processes for one admitted stage child.
    const STAGE_MAX_DESCENDANTS: u32 = 256;

    /// Ceiling on the retained bytes of one observed tool version line.
    ///
    /// Bounded so a tool that answers `--version` with an unbounded stream cannot
    /// turn the version read into unbounded retention. It is far above any real
    /// tool's version line, so an ordinary version is recorded in full and only a
    /// runaway read is refused.
    const MAX_TOOL_VERSION_BYTES: usize = 4096;

    /// Wall bound for the permit-bound `--version` observation child, in milliseconds.
    ///
    /// A version read is a short bounded probe, not a stage: this is deliberately
    /// far below [`STAGE_WALL_TIMEOUT_MS`] so a tool that hangs instead of answering
    /// its version is refused here rather than holding a stage-sized launch open.
    const VERSION_WALL_TIMEOUT_MS: u64 = 60_000;

    /// Per-stream capture ceiling for the permit-bound `--version` observation child.
    ///
    /// Set above [`MAX_TOOL_VERSION_BYTES`] so an ordinary version is captured whole
    /// and still bounds what a runaway tool can write. Because the retained prefix
    /// preview omits any suffix past this ceiling, `observed_tool_version` refuses a
    /// read that hit it instead of reporting a truncated line as the version.
    const VERSION_STDOUT_BYTES: u64 = 64 * 1024;

    /// Ceiling on descendant processes for the permit-bound `--version` child.
    ///
    /// A version read answers with a single line from the tool itself, so a wider
    /// descendant tree than [`STAGE_MAX_DESCENDANTS`] is not a normal observation.
    const VERSION_MAX_DESCENDANTS: u32 = 8;

    /// Bound on waiting for the permit-bound `--version` child to settle.
    ///
    /// Set equal to [`VERSION_WALL_TIMEOUT_MS`], the wall bound that child was
    /// sealed with, because that deadline is what makes the wait finite: the
    /// executor's own operation-bound deadline watcher terminates the version child
    /// at it, so the view reaches a terminal lifecycle at or before this bound and
    /// this constant invents no timing policy of its own. A child still not settled
    /// at the bound is refused, never reported.
    const VERSION_OBSERVE_TIMEOUT: Duration = Duration::from_millis(VERSION_WALL_TIMEOUT_MS);

    /// Cadence for observing the permit-bound `--version` child's lifecycle.
    ///
    /// Reused rather than introduced: the same 25ms bound is the executor's own
    /// terminal-wait poll, and the same cadence the two existing production callers
    /// of a real child already poll [`ProcessExecutor::inspect`] at — the
    /// `RECONCILE_OBSERVE_POLL` of `wasm_p03_adapter.rs` and `BOUND_RUN_POLL` of
    /// `eliot-git-bridge`.
    const VERSION_OBSERVE_POLL: Duration = Duration::from_millis(25);

    pub(super) fn observed_supply_chain(
        specs: &[InstrumentSpec],
        source_root: &str,
    ) -> Result<Vec<SupplyChainReceipt>, CliError> {
        specs
            .iter()
            .map(|spec| {
                let executable = resolve_tool(&spec.executable, source_root)?;
                Ok(SupplyChainReceipt::new(
                    ContractId::new(spec.kind.as_str())?,
                    spec.executable.clone(),
                    file_digest(&executable)?,
                    // No version is attested on this path, so none is claimed; a spec
                    // that pinned a version still gates inside admission.
                    None,
                    spec.digest(),
                    VERIFICATION_REGISTRY_GENERATION,
                )?)
            })
            .collect()
    }

    pub(super) fn resolve_tool(name: &str, source_root: &str) -> Result<PathBuf, CliError> {
        let candidate = Path::new(name);
        if candidate.is_absolute() || candidate.components().count() > 1 {
            return Err(CliError::Contract(format!(
                "admitted executable '{name}' must be a bare tool name resolved through the selected toolchain"
            )));
        }
        let root = selected_toolchain_root(source_root)?;
        for suffix in executable_suffixes() {
            let candidate = root.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate).map_err(|error| {
                    CliError::Contract(format!(
                        "admitted executable {} is unavailable: {error}",
                        candidate.display()
                    ))
                });
            }
        }
        Err(CliError::Contract(format!(
            "admitted executable '{name}' is not a member of the selected toolchain {}; an unpinned tool cannot be receipted",
            root.display()
        )))
    }

    /// The `bin` directory of the ONE toolchain this workspace is verified with.
    ///
    /// Selection reads the owner-published rustup metadata rather than probing for
    /// a directory that happens to contain a `cargo`: the workspace
    /// `rust-toolchain.toml` override names the channel the repo pins, and absent
    /// an override the rustup default is the toolchain the owner selected. Both
    /// are required to name exactly one INSTALLED toolchain — an ambiguous or
    /// absent selection fails closed rather than picking one.
    fn selected_toolchain_root(source_root: &str) -> Result<PathBuf, CliError> {
        let rustup_home = rustup_home()?;
        let source_root = current_source_root(source_root)?;
        let settings = read_bounded_metadata(
            &Path::new(&rustup_home).join("settings.toml"),
            "rustup settings",
        )?;
        let host = toml_string_value(&settings, "default_host_triple");
        let requested = read_toolchain_override(Path::new(&source_root))
        .or_else(|| toml_string_value(&settings, "default_toolchain"))
        .ok_or_else(|| {
            CliError::Contract(format!(
                "no toolchain is selected: {source_root} pins none and {rustup_home} names no default"
            ))
        })?;
        let toolchains = Path::new(&rustup_home).join("toolchains");
        let mut candidates = std::fs::read_dir(&toolchains)
            .map_err(|error| {
                CliError::Contract(format!(
                    "toolchain root {} is unavailable: {error}",
                    toolchains.display()
                ))
            })?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(std::fs::FileType::is_dir)
                    .map(|_| entry.file_name().to_string_lossy().into_owned())
            })
            .filter(|name| name == &requested || name.starts_with(&format!("{requested}-")))
            .collect::<Vec<_>>();
        candidates.sort();
        if let Some(host) = host.as_deref() {
            let host_candidates = candidates
                .iter()
                .filter(|name| name.ends_with(host))
                .cloned()
                .collect::<Vec<_>>();
            if !host_candidates.is_empty() {
                candidates = host_candidates;
            }
        }
        let [selected] = candidates.as_slice() else {
            return Err(CliError::Contract(format!(
                "toolchain '{requested}' is not installed under {}; an unpinned toolchain cannot be receipted",
                toolchains.display()
            )));
        };
        Ok(toolchains.join(selected).join("bin"))
    }

    /// The owner-published rustup home, resolved without inventing a default.
    ///
    /// `RUSTUP_HOME` wins when published; otherwise the per-user `.rustup`
    /// directory. A home that is absent, relative, or not an existing directory is
    /// a refusal: guessing a second location here would be the same
    /// "resolve to whatever exists" fallback this function exists to remove.
    fn rustup_home() -> Result<String, CliError> {
        let candidate = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .or_else(|| std::env::var_os("HOME"))
                    .map(|home| PathBuf::from(home).join(".rustup"))
            })
            .ok_or_else(|| {
                CliError::Contract("toolchain root is unknown: RUSTUP_HOME is unset".to_owned())
            })?;
        if !candidate.is_absolute() || !candidate.is_dir() {
            return Err(CliError::Contract(format!(
                "toolchain root {} is not an existing absolute directory",
                candidate.display()
            )));
        }
        Ok(std::fs::canonicalize(&candidate)
            .map_err(|error| {
                CliError::Contract(format!(
                    "toolchain root {} cannot be canonicalized: {error}",
                    candidate.display()
                ))
            })?
            .to_string_lossy()
            .into_owned())
    }

    /// The workspace this run verifies, as an absolute path.
    ///
    /// The toolchain override is read from the same admitted root the stages run
    /// in rather than from the process working directory, so which toolchain is
    /// selected is a property of the admitted layout and not of wherever the
    /// caller happened to invoke this binary.
    fn current_source_root(source_root: &str) -> Result<String, CliError> {
        let root = PathBuf::from(source_root);
        if !root.is_absolute() || !root.is_dir() {
            return Err(CliError::Contract(format!(
                "admitted source root {} is not an existing absolute directory",
                root.display()
            )));
        }
        Ok(std::fs::canonicalize(&root)
            .map_err(|error| {
                CliError::Contract(format!(
                    "admitted source root {} cannot be canonicalized: {error}",
                    root.display()
                ))
            })?
            .to_string_lossy()
            .into_owned())
    }

    /// The channel the admitted workspace root pins, when it pins one.
    ///
    /// A workspace with no override is not an error: the rustup default is then the
    /// owner's selected toolchain. The same two override file names and the same
    /// `channel` key `eliot-testd` honours are used, so both surfaces select the
    /// same toolchain for the same workspace.
    fn read_toolchain_override(source_root: &Path) -> Option<String> {
        for name in ["rust-toolchain.toml", "rust-toolchain"] {
            let path = source_root.join(name);
            if !path.is_file() {
                continue;
            }
            let text = read_bounded_metadata(&path, "rust-toolchain override").ok()?;
            let value = if name.eq_ignore_ascii_case(".toml") {
                toml_string_value(&text, "channel")
                    .or_else(|| toml_string_value(&text, "toolchain"))
            } else {
                text.lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(ToOwned::to_owned)
            };
            return value
                .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control));
        }
        None
    }

    /// Reads one small owner metadata file under a fixed size bound.
    ///
    /// The bound keeps an unreadable or substituted metadata file from being read
    /// into memory as part of identity selection; a file that is not UTF-8 or is
    /// implausibly large is refused rather than parsed leniently.
    fn read_bounded_metadata(path: &Path, what: &str) -> Result<String, CliError> {
        const MAX_METADATA_BYTES: usize = 64 * 1024;
        let bytes = std::fs::read(path).map_err(|error| {
            CliError::Contract(format!("{what} {} is unreadable: {error}", path.display()))
        })?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(CliError::Contract(format!(
                "{what} {} exceeds the bounded read size",
                path.display()
            )));
        }
        String::from_utf8(bytes)
            .map_err(|_| CliError::Contract(format!("{what} {} is not UTF-8", path.display())))
    }

    /// One top-level `key = "value"` string from a small TOML metadata file.
    ///
    /// This reads only the flat scalar keys the rustup metadata actually publishes
    /// (`default_toolchain`, `default_host_triple`, `channel`). It is a lookup,
    /// not a parser, so an unrecognised file shape yields "absent" and the caller
    /// fails closed on that absence rather than proceeding on a guess.
    fn toml_string_value(text: &str, key: &str) -> Option<String> {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            if name.trim() != key {
                return None;
            }
            let value = value.trim().trim_matches('"');
            (!value.is_empty()).then(|| value.to_owned())
        })
    }

    /// The filename suffixes one bare tool name may resolve to on this host.
    ///
    /// On a non-Windows host the name must already be complete, so only the empty
    /// suffix is admitted; on Windows the shell's own `PATHEXT` list is used when
    /// the host publishes it, so the file this entry pins and executes is the file
    /// the tool invocation would run. `PATHEXT` is a semicolon-separated list of
    /// bare suffixes rather than a path list, so it is split on `;` directly.
    fn executable_suffixes() -> Vec<String> {
        let suffixes = std::env::var("PATHEXT")
            .map(|pathext| {
                pathext
                    .split(';')
                    .filter(|suffix| !suffix.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if suffixes.is_empty() {
            return vec![String::new()];
        }
        suffixes
    }

    /// The SHA-256 over the exact bytes of one file on this machine.
    fn file_digest(path: &Path) -> Result<String, CliError> {
        let bytes = std::fs::read(path).map_err(|error| {
            CliError::Contract(format!(
                "executable {} is unreadable: {error}",
                path.display()
            ))
        })?;
        Ok(sha256_hex(&bytes))
    }

    pub(super) fn await_terminal_view(
        executor: &WindowsProcessExecutor,
        operation: &OperationId,
        executable: &Path,
        timeout: Duration,
    ) -> Result<ProcessExecutionView, CliError> {
        let started = Instant::now();
        loop {
            let view = block_on(executor.inspect(operation.clone()))?;
            if view.lifecycle().is_terminal() {
                return Ok(view);
            }
            if started.elapsed() >= timeout {
                return Err(CliError::Contract(format!(
                    "child for tool {} was still {:?} after {}ms of governed observation; its terminal outcome is unknown",
                    executable.display(),
                    view.lifecycle(),
                    timeout.as_millis()
                )));
            }
            std::thread::sleep(VERSION_OBSERVE_POLL);
        }
    }

    fn observed_tool_version(executable: &Path, epoch: &EpochId) -> Result<String, CliError> {
        // The read gets its own `DispatchCell` because a P-07 dispatch permit is
        // one-shot: the `--version` child is a distinct launch from the stage that
        // follows it, so it can never consume the stage's permit or its stored
        // validation context. It is still the same authority composition, the same
        // epoch, and the same generation, so this run has exactly one epoch.
        let cell = Arc::new(DispatchCell::activate()?);
        // ONE executor for the whole lifecycle of this read. Its registry is an
        // instance field, so the `inspect` below must cross the same instance the
        // `start` registered on; a second executor would read an empty registry and
        // refuse `NotFound`, which says nothing about the operation.
        let executor = StageExecutor::with(&cell);
        let request = seal_version_request(&cell, epoch, executable)?;
        let receipt = block_on(executor.start(
            request,
            Arc::new(RetainedEvidenceSink::default()) as Arc<dyn ProcessEvidenceSink>,
        ))?;
        // Settle first, then read the exit, then reconcile: the exit observation is
        // only meaningful once the tree is closed, and the reconcile is the single
        // terminal call the poll above was waiting to make safe.
        let view = await_terminal_view(
            executor.executor(),
            receipt.operation_id(),
            executable,
            VERSION_OBSERVE_TIMEOUT,
        )?;
        // `ExitDisposition::Completed` is the executor's own observed terminal
        // classification, so this is the governed equivalent of the old
        // `output.status.success()` test: a signalled, resource-limited, cancelled,
        // or unclassifiable tree is refused here exactly as a nonzero exit was.
        let exit = view.exit().ok_or_else(|| {
            CliError::Contract(format!(
                "tool {} reported no exit observation while reading its version",
                executable.display()
            ))
        })?;
        if exit.disposition() != ExitDisposition::Completed {
            return Err(CliError::Contract(format!(
                "tool {} ended {exit:?} while reporting its version",
                executable.display()
            )));
        }
        let evidence = block_on(executor.reconcile(receipt.operation_id().clone()))?;
        // The version text is the stdout this executor really captured for that
        // exact permit-bound operation, read back out of the reconciled evidence's
        // bounded prefix preview. The preview is the transport-level prefix, so a
        // version line longer than the retained bound is still refused below rather
        // than silently truncated into a shorter "version".
        let stdout = evidence.stdout().ok_or_else(|| {
            CliError::Contract(format!(
                "tool {} retained no version output",
                executable.display()
            ))
        })?;
        if !stdout.preview().omitted_ranges().is_empty() {
            return Err(CliError::Contract(format!(
                "tool {} wrote more than the {VERSION_STDOUT_BYTES} byte version bound; its version line was truncated",
                executable.display()
            )));
        }
        let reported = String::from_utf8_lossy(stdout.preview().bytes());
        let version = reported
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| {
                CliError::Contract(format!(
                    "tool {} printed no version line",
                    executable.display()
                ))
            })?;
        if version.len() > MAX_TOOL_VERSION_BYTES {
            return Err(CliError::Contract(format!(
                "tool {} reported a {} byte version line, over the {MAX_TOOL_VERSION_BYTES} byte bound",
                executable.display(),
                version.len()
            )));
        }
        Ok(version.to_owned())
    }

    fn seal_version_request(
        cell: &DispatchCell,
        epoch: &EpochId,
        executable: &Path,
    ) -> Result<ProcessRequest, CliError> {
        let projection = isolated_projection()?;
        let argv = vec!["--version".to_owned()];
        // The operation identity is derived from the same real tool bytes the stage
        // launch pins, so the read and the stage it precedes are bound to one
        // concrete executable rather than to a name that could resolve elsewhere.
        let operation = format!(
            "verification-profile-version-{}",
            &sha256_hex(format!("{}\0{}", executable.display(), argv.join("\u{1}")).as_bytes())
                [..24]
        );
        let intent = ProcessIntent::new(
            OperationId::new(operation.clone())?,
            ProcessTreeId::new(format!("{operation}-tree"))?,
            JobId::new(format!("{operation}-job"))?,
            ImageId::new(format!("{operation}-image"))?,
            SessionId::new(format!("{EPOCH_LINEAGE}-{operation}"))?,
            Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
            executable.to_string_lossy().into_owned(),
            file_digest(executable)?,
            argv.clone(),
            // The tool's own resolved parent, not the admitted source root: this
            // observes the tool where `resolve_tool` pinned it.
            executable
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_string_lossy()
                .into_owned(),
            projection,
            ResourceLimits::new(
                VERSION_WALL_TIMEOUT_MS,
                None,
                None,
                VERSION_STDOUT_BYTES,
                VERSION_STDOUT_BYTES,
                VERSION_MAX_DESCENDANTS,
            )?,
        )?;
        let observed =
            ExecutableObservation::observe_from_intent(&intent, None).map_err(|error| {
                CliError::Contract(format!("version executable observation refused: {error}"))
            })?;
        let file_identity = observed.file_identity.ok_or_else(|| {
            CliError::Contract(format!(
                "version executable {} observation has no owner-observed file identity",
                executable.display()
            ))
        })?;
        let intent = intent.with_executable_file_identity(file_identity)?;
        let fence = FencingToken::new(
            epoch.clone(),
            Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
            format!("{operation}-fence"),
        )?;
        let heads = BTreeMap::from([(
            "verification-profile-version".to_owned(),
            sha256_hex(format!("{operation}\0{}", argv.join("\u{1}")).as_bytes()),
        )]);
        let issued_at = now_unix_ms().max(1);
        cell.issue(
            &intent,
            fence,
            heads,
            issued_at,
            issued_at.saturating_add(VERSION_WALL_TIMEOUT_MS),
            ActionLeaseRef::new(format!("{operation}-lease"))?,
            format!("{operation}-nonce"),
        )
    }

    pub(super) fn process_epoch() -> Result<EpochId, CliError> {
        let mut material = fresh_key_bytes();
        // Fold this process's own identity into the material so two resolutions
        // that happened to draw the same bytes are still distinct. Each source is
        // zero-extended into its own 8-byte lane, so the copy lengths match the
        // destination exactly rather than panicking at runtime.
        material[..8].copy_from_slice(&u64::from(std::process::id()).to_le_bytes());
        material[8..16].copy_from_slice(&system_nanos().to_le_bytes());
        let mut lineage = String::with_capacity(36);
        for (index, byte) in material.iter().take(16).enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                lineage.push('-');
            }
            // `write!` into the same String rather than appending a `format!` result:
            // one formatting call, no intermediate allocation, and no way for the
            // formatted hex to differ from what was pushed.
            write!(lineage, "{byte:02x}")
                .map_err(|_| CliError::Contract("epoch lineage is not formattable".to_owned()))?;
        }
        let lineage = EpochLineageId::new(lineage)?;
        let sequence = NonZeroU64::new(1)
            .ok_or_else(|| CliError::Contract("epoch sequence is not one".to_owned()))?;
        Ok(EpochId::new(lineage, sequence)?)
    }

    /// Machine clock reading in Unix milliseconds, observed now.
    pub(super) fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }

    /// Derives a process-unique nanosecond reading.
    pub(super) fn system_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
            })
    }

    /// Builds one clock observation from an observed millisecond reading.
    ///
    /// The `ClockReading` field is a signed millisecond count, so a reading beyond
    /// `i64::MAX` cannot be represented and is clamped to the maximum rather than
    /// wrapping into a negative instant. `cast_unsigned` states the intended
    /// conversion: the ceiling is a positive constant, so the sign is not lost here.
    pub(super) fn observation_clock(now: u64) -> ClockReading {
        let ceiling = i64::MAX;
        let now = i64::try_from(now.min(ceiling.cast_unsigned())).unwrap_or(i64::MAX);
        ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    /// Generates fresh per-process key bytes without adding a randomness dependency.
    ///
    /// Per-process uniqueness, not unpredictability, is what the one-shot replay
    /// fence needs: the key never leaves this process, is never persisted, and binds
    /// only permits this authority instance issued.
    fn fresh_key_bytes() -> [u8; 32] {
        static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

        fn splitmix64(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        let probe = 0u64;
        let stack = u64::try_from(std::ptr::addr_of!(probe).addr()).unwrap_or(0);
        let pid = u64::from(std::process::id());
        let count = MIXER.fetch_add(1, Ordering::Relaxed);
        let mut state = system_nanos()
            ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9)
            ^ stack.rotate_left(17)
            ^ count.wrapping_mul(0x94D0_49BB_1331_11EB);
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        if out.iter().all(|byte| *byte == 0) {
            out[31] = 1;
        }
        out
    }

    pub(super) struct DispatchCell {
        authority: Mutex<DispatchPermitAuthority>,
        /// One validation context per issued operation identity.
        ///
        /// Behind a mutex because the port that consumes it is shared, and because
        /// a per-request entry is retained for the whole run so the context a
        /// request is validated against is still resolvable after later requests
        /// have been issued.
        contexts: Mutex<BTreeMap<String, DispatchValidationContext>>,
    }

    impl DispatchCell {
        /// Activates one ephemeral authority around fresh in-memory key material.
        pub(super) fn activate() -> Result<Self, CliError> {
            let pid = std::process::id();
            let nanos = system_nanos();
            let authority_id =
                DispatchAuthorityId::new(format!("profile-resolver-dispatch-{pid}-{nanos}"))?;
            let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())?;
            Ok(Self {
                authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
                contexts: Mutex::new(BTreeMap::new()),
            })
        }

        /// Issues the single permit-bound process request for one admitted stage.
        #[allow(clippy::too_many_arguments)]
        pub(super) fn issue(
            &self,
            intent: &ProcessIntent,
            fence: FencingToken,
            heads: BTreeMap<String, String>,
            issued_at_unix_ms: u64,
            expires_at_unix_ms: u64,
            lease: ActionLeaseRef,
            nonce: String,
        ) -> Result<ProcessRequest, CliError> {
            // The heads are cloned out BEFORE the issuance consumes them, and the
            // validation context is built from that clone. This is the same value
            // the permit was issued with, not a second source: the authority builds
            // the permit from this exact `PermitIssuance` and re-proves the two
            // against each other at consume time. `DispatchPermit` exposes no reader
            // for its heads (that is deliberate — it is dispatch authority material),
            // so the run context is pinned from the issuance the authority consumed.
            let pinned_heads = heads.clone();
            let issuance = PermitIssuance::new(
                lease,
                fence.clone(),
                heads,
                issued_at_unix_ms,
                expires_at_unix_ms,
                nonce,
            )?;
            let permit = self
                .authority
                .lock()
                .map_err(|_| CliError::Contract("dispatch authority lock poisoned".to_owned()))?
                .issue(intent, issuance)?;
            // The stored context pins the exact material the permit was issued
            // with — the same fence, its own authority epoch, and the same revision
            // heads — so consume-time validation compares the permit against THIS
            // request's own snapshot rather than against ambient state. It is
            // keyed by the operation identity it was minted for, so the executor
            // can resolve it back from the request being validated.
            let context_epoch = fence.authority_epoch().clone();
            let context = DispatchValidationContext::new(
                observation_clock(issued_at_unix_ms),
                fence,
                context_epoch,
                pinned_heads,
                VALIDATION_REVISION,
            )?;
            self.contexts
                .lock()
                .map_err(|_| CliError::Contract("validation context lock poisoned".to_owned()))?
                .insert(intent.operation_id().as_str().to_owned(), context);
            Ok(ProcessRequest::new(intent.clone(), permit)?)
        }

        /// The validation context belonging to exactly the request being validated.
        ///
        /// The lookup key is the request's own operation identity, which is the same
        /// key [`Self::issue`] stored its context under. A request this cell never
        /// issued a permit for has no context and is refused here, before the
        /// authority is consulted, so an unissued request can never be validated
        /// against another request's material.
        fn context(
            &self,
            request: &ProcessRequest,
        ) -> Result<DispatchValidationContext, ProcessExecutionError> {
            self.contexts
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable("validation context poisoned".to_owned())
                })?
                .get(request.operation_id().as_str())
                .cloned()
                .ok_or_else(|| {
                    ProcessExecutionError::Unavailable(format!(
                        "validation context absent for operation '{}'",
                        request.operation_id().as_str()
                    ))
                })
        }
    }

    impl DispatchValidationPort for DispatchCell {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            // The context is resolved from the request itself, before the permit is
            // consumed, so the one authority below compares the permit against the
            // fence, epoch, and revision heads it was issued with and nothing else.
            let context = self.context(&request)?;
            self.authority
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable("authority lock poisoned".to_owned())
                })?
                .validate_and_consume(request, observed, &context)
                .map_err(ProcessExecutionError::from)
        }
    }

    /// The physical process boundary every admitted stage of this run crosses.
    ///
    /// Each stage really starts a child through the sole [`WindowsProcessExecutor`]
    /// under this run's own dispatch cell, so the identity the receipt records for
    /// that stage is the identity of bytes this process actually executed.
    ///
    /// The permit-bound `--version` read uses this same owner over its own cell, so
    /// every child this entry starts — the version probes and the stages alike —
    /// crosses the one executor composition below.
    pub(super) struct StageExecutor {
        /// The ONE physical executor every lifecycle call of this owner crosses.
        ///
        /// `WindowsProcessExecutor` owns the operation registry as an instance
        /// field, so the registry that records a `start` must be the same instance
        /// a later `inspect`, `cancel` or `reconcile` reads. Constructing one per
        /// call discards the registration with the temporary, and the follow-up
        /// call is then refused as `NotFound` against an empty registry — which is
        /// a true statement about the wrong executor, not about the operation.
        ///
        /// The cell reaches this owner through this one field: the executor holds
        /// the `Arc<dyn DispatchValidationPort>` built from it, so the port the
        /// executor validates against and the cell this owner's caller sealed its
        /// one-shot permits under are the same value.
        pub(super) executor: WindowsProcessExecutor,
    }

    impl StageExecutor {
        pub(super) fn with(cell: &Arc<DispatchCell>) -> Self {
            Self {
                executor: WindowsProcessExecutor::new(
                    Arc::clone(cell) as Arc<dyn DispatchValidationPort>
                ),
            }
        }

        /// The P-07 authority composition every lifecycle call crosses.
        ///
        /// Borrowed by [`await_terminal_view`] so the version probe's bounded
        /// inspect-poll observes THIS executor's registry — the one the `start`
        /// registered on — rather than a second executor that never saw the child.
        pub(super) fn executor(&self) -> &WindowsProcessExecutor {
            &self.executor
        }
    }

    impl ProcessExecutor for StageExecutor {
        async fn start(
            &self,
            request: ProcessRequest,
            sink: Arc<dyn ProcessEvidenceSink>,
        ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
            self.executor().start(request, sink).await
        }

        async fn inspect(
            &self,
            operation_id: OperationId,
        ) -> Result<ProcessExecutionView, ProcessExecutionError> {
            self.executor().inspect(operation_id).await
        }

        async fn cancel(
            &self,
            operation_id: OperationId,
        ) -> Result<CancellationReceipt, ProcessExecutionError> {
            self.executor().cancel(operation_id).await
        }

        async fn reconcile(
            &self,
            operation_id: OperationId,
        ) -> Result<ProcessEvidence, ProcessExecutionError> {
            self.executor().reconcile(operation_id).await
        }
    }

    /// The [`StageLauncher`] that turns one admitted profile plan into launches.
    ///
    /// Nothing here restates a command list. The executable, the argv, the working
    /// directory, the instrument contract, and the stage kind all come from the
    /// admitted plan the shared resolver produced, so a stage this launcher runs is
    /// exactly a stage the shared resolver admitted and no other.
    pub(super) struct StageRoute {
        /// Authority epoch every permit of this run is sealed under.
        pub(super) epoch: EpochId,
        /// Observed admission instant carried by every stage invocation.
        pub(super) clock: ClockReading,
        /// Admitted layout the stage working directory comes from.
        pub(super) layout: TargetLayout,
        /// Admitted stage launch provisions the orchestrator binds each stage
        /// through: the per-stage permit source, the evidence sink, and the exact
        /// sealed request already issued for the stage being launched.
        ///
        /// The sealed request is stored per stage rather than derived inside
        /// `bind` because a dispatch permit is one-shot and the orchestrator asks
        /// for the port before it knows which stage it is binding. [`StageRoute`]
        /// seals one request per planned stage up front, in admitted plan order, so
        /// the port hands each stage the request that was sealed for it and refuses
        /// a bind for any other stage.
        pub(super) port: StagePort,
    }

    /// The per-stage launch provisions the orchestrator binds one stage through.
    ///
    /// The sealed requests are keyed by the exact durable stage identity the
    /// orchestrator walks, so a bind for a stage this run never sealed fails closed
    /// instead of producing a request for whatever stage happens to come next.
    pub(super) struct StagePort {
        /// One sealed, permit-bound request per admitted stage identity.
        ///
        /// Behind a mutex because `bind` takes `&self` (the port is shared) and
        /// because removing the slot is what enforces one seal per stage.
        pub(super) sealed: std::sync::Mutex<BTreeMap<String, ProcessRequest>>,
        /// Evidence sink every stage launch retains through.
        pub(super) sink: Arc<RetainedEvidenceSink>,
    }

    impl StagePort {
        /// Seals one permit-bound request for every stage of the admitted plan.
        ///
        /// Sealing is a per-stage operation because the P-07 dispatch permit is
        /// one-shot: one permit can never launch two children. Each stage's request
        /// is bound to its own one-shot nonce, its own sealed intent, its own fence
        /// nonce, and its own revision heads, and [`DispatchCell::issue`] stores the
        /// matching validation context under that request's operation identity. The
        /// stages of a run share one authority epoch and generation — so one
        /// authority admits them all — but they do NOT share a fence or heads, so
        /// they do not share a validation context either: each request is validated
        /// against the context minted with it, and against no other request's.
        pub(super) fn seal_all(
            cell: &DispatchCell,
            epoch: &EpochId,
            layout: &TargetLayout,
            admitted: &AdmittedProfile,
        ) -> Result<Self, CliError> {
            let plan = StageOrchestrator::plan(admitted);
            let mut sealed = BTreeMap::new();
            for planned in &plan.stages {
                let stage_id = planned.route.stage().stage_id.as_str();
                let argv = stage_argv(planned);
                let operation = operation_identity(stage_id, &argv);
                let request = seal_stage_request(
                    cell,
                    epoch,
                    layout,
                    stage_id,
                    &planned.stage.executable,
                    &argv,
                )?;
                sealed.insert(operation, request);
            }
            Ok(Self {
                sealed: std::sync::Mutex::new(sealed),
                sink: Arc::new(RetainedEvidenceSink::default()),
            })
        }
    }

    fn stage_argv(stage: &PlannedStage) -> Vec<String> {
        stage.stage.verification_command.clone()
    }

    /// Seals the one permit-bound process request for one admitted stage.
    ///
    /// The executable is the one the admitted spec names, resolved to the real file
    /// on this machine, and the digest bound into the sealed intent is the SHA-256
    /// the executor computed over that file's bytes — the same observation
    /// `ExecutableObservation::observe_from_intent` re-derives at launch. The request
    /// is therefore the one the admitted stage runs, and a tool swapped between
    /// sealing and launch fails the executor's own observation check.
    ///
    /// The tool version is observed by really running the tool's own version flag
    /// through [`observed_tool_version`] and keeping the first line that launch
    /// printed. A complete identity requires a non-empty version (`is_complete`
    /// refuses an observation without one), and no version is invented from the file
    /// name: a tool that cannot report one is refused here rather than receipted with
    /// a placeholder. That read is itself a governed launch under its own one-shot
    /// permit, so both children this function causes to exist — the `--version` probe
    /// and the stage itself — cross the single [`WindowsProcessExecutor`] boundary.
    fn seal_stage_request(
        cell: &DispatchCell,
        epoch: &EpochId,
        layout: &TargetLayout,
        stage_id: &str,
        executable_name: &str,
        argv: &[String],
    ) -> Result<ProcessRequest, CliError> {
        let executable = resolve_tool(executable_name, &layout.source_root)?;
        let projection = isolated_projection()?;
        let observed = ExecutableObservation::observe_at_path(
            &executable,
            argv.to_vec(),
            environment_projection_digest(&projection),
            Some(observed_tool_version(&executable, epoch)?),
        )
        .map_err(|error| CliError::Contract(format!("executable observation refused: {error}")))?;
        let file_identity = observed.file_identity.ok_or_else(|| {
            CliError::Contract(format!(
                "executable {} observation has no owner-observed file identity",
                executable.display()
            ))
        })?;
        if !observed.is_complete() {
            return Err(CliError::Contract(format!(
                "executable {} observation is incomplete",
                executable.display()
            )));
        }
        let operation = operation_identity(stage_id, argv);
        let intent = ProcessIntent::new(
            OperationId::new(operation.clone())?,
            ProcessTreeId::new(format!("{operation}-tree"))?,
            JobId::new(format!("{operation}-job"))?,
            ImageId::new(format!("{operation}-image"))?,
            SessionId::new(format!("{EPOCH_LINEAGE}-{operation}"))?,
            Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
            executable.to_string_lossy().into_owned(),
            observed.content_digest.clone(),
            argv.to_vec(),
            layout.source_root.clone(),
            projection,
            ResourceLimits::new(
                STAGE_WALL_TIMEOUT_MS,
                None,
                None,
                STAGE_STDOUT_BYTES,
                STAGE_STDOUT_BYTES,
                STAGE_MAX_DESCENDANTS,
            )?,
        )?
        .with_executable_file_identity(file_identity)?;
        let fence = FencingToken::new(
            epoch.clone(),
            Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
            format!("{operation}-fence"),
        )?;
        let heads = BTreeMap::from([(
            "verification-profile".to_owned(),
            sha256_hex(format!("{stage_id}\0{operation}").as_bytes()),
        )]);
        let issued_at = now_unix_ms().max(1);
        cell.issue(
            &intent,
            fence,
            heads,
            issued_at,
            issued_at.saturating_add(STAGE_WALL_TIMEOUT_MS),
            ActionLeaseRef::new(format!("{operation}-lease"))?,
            format!("{operation}-nonce"),
        )
    }

    fn isolated_projection() -> Result<EnvironmentProjection, CliError> {
        let path = std::env::var(TOOLCHAIN_PATH_ENV).map_err(|error| {
        CliError::Contract(format!(
            "explicitly permitted toolchain environment is unavailable: {TOOLCHAIN_PATH_ENV} is unset ({error})"
        ))
    })?;
        Ok(EnvironmentProjection::new(
            BTreeMap::from([(TOOLCHAIN_PATH_ENV.to_owned(), path)]),
            Vec::new(),
            EnvironmentInheritance::None,
        )?)
    }

    impl InstrumentRequestPort for StagePort {
        /// Hands the stage the exact request this run sealed for it.
        ///
        /// The lookup key is the invocation's own request id, which is derived from
        /// the admitted stage identity and the admitted argv, so a bind names the
        /// stage it is for rather than consuming requests in plan order: a bind for
        /// a stage this run never sealed finds nothing and is refused.
        ///
        /// The sealed slot is TAKEN, not copied. `ProcessRequest` deliberately does
        /// not implement `Clone`: it holds the one-shot P-07 dispatch permit, so a
        /// second bind for the same stage must fail here rather than hand the same
        /// permit to a second child. Consuming the slot is what makes a
        /// one-seal-per-stage run structural instead of a convention the caller has
        /// to remember.
        fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError> {
            self.sealed
                .lock()
                .map_err(|_| RunnerError::Binding("sealed stage map poisoned".to_owned()))?
                .remove(invocation.request.request_id.as_str())
                .ok_or_else(|| {
                    RunnerError::Binding(format!(
                        "no sealed request for invocation '{}'",
                        invocation.request.request_id.as_str()
                    ))
                })
        }
    }

    impl StageLauncher for StageRoute {
        fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError> {
            let stage_id = stage.route.stage().stage_id.as_str();
            let target = format!(
                "worktree:{}",
                &sha256_hex(self.layout.source_root.as_bytes())[..16]
            );
            let request_id = operation_identity(stage_id, &stage_argv(stage));
            let invocation = InstrumentInvocation {
                request: RequestMetadata {
                    request_id: RequestId::new(request_id).map_err(|error| {
                        RunnerError::Binding(format!("stage '{stage_id}' request refused: {error}"))
                    })?,
                    session_id: None,
                    task_id: None,
                    product_id: ProductId::new(ADMITTED_PRODUCT).map_err(|error| {
                        RunnerError::Binding(format!("stage '{stage_id}' product refused: {error}"))
                    })?,
                    source_id: SourceId::new(self.layout.source_root.clone()).map_err(|error| {
                        RunnerError::Binding(format!("stage '{stage_id}' source refused: {error}"))
                    })?,
                    state_fence: StateFence::new(
                        self.epoch.clone(),
                        ResourceGeneration::new(VERIFICATION_REGISTRY_GENERATION).map_err(
                            |error| {
                                RunnerError::Binding(format!(
                                    "stage '{stage_id}' fence refused: {error}"
                                ))
                            },
                        )?,
                    ),
                    clock: self.clock,
                },
                instrument: stage.stage.spec.clone(),
                kind: stage.stage.kind,
                profile: stage.route.stage().profile.clone(),
                target,
                // Instrument-level arguments are never argv: the process argv comes
                // from the admitted argument template in `seal`, so a stage cannot
                // smuggle a command through this field.
                arguments: Vec::new(),
                input_artifacts: Vec::new(),
                declared_scope: ADMITTED_SCOPE_CLASS.to_owned(),
                requested_at: self.clock,
            };
            invocation.validate().map_err(|error| {
                RunnerError::Binding(format!("stage '{stage_id}' invocation refused: {error}"))
            })?;
            Ok(invocation)
        }

        fn port(&self, _stage: &PlannedStage) -> &dyn InstrumentRequestPort {
            // Every stage binds through the one port this run sealed against. The
            // port keys its sealed requests by the admitted operation identity, so
            // handing the same port to every stage cannot make one stage's permit
            // launch another stage's child: the request each stage receives is the
            // one sealed for that stage's own admitted identity.
            &self.port
        }

        fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
            // One sink for the whole run, so every stage's retained records land in
            // the same evidence store rather than in a per-stage buffer that would
            // be dropped as soon as the stage returned.
            Arc::clone(&self.port.sink) as Arc<dyn ProcessEvidenceSink>
        }
    }

    fn operation_identity(stage_id: &str, argv: &[String]) -> String {
        let material = format!("{stage_id}\0{}", argv.join("\u{1}"));
        format!(
            "verification-profile-stage-{}",
            &sha256_hex(material.as_bytes())[..24]
        )
    }
}

use eliot_contracts::{ArtifactId, ContractId};
use eliot_instrument_api::{ExecutionStatus, InstrumentKind};
use eliot_instrument_cargo::CONTRACT_NAME as CARGO_CONTRACT_NAME;
use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_instrument_runner::{
    ADVERTISED_INSTRUMENTS, AvailabilityInputs, ConformanceCase, ConformanceCorpus,
    DENOMINATOR_CONTRACT, ProviderDenominator, ProviderFixtureSet, ProviderRegistry,
    UNMAPPED_IN_PROCESS_INSTRUMENTS, declared_instruments, host_platform,
    profile::{COMPILER_PROFILE, PACKAGE_VERIFICATION_ROUTE, TEST_PROFILE},
    registry::InvalidationSet,
    testd_port::{OmissionReason, RawEvidence},
};
use eliot_instrument_rustc::RUSTC_INSTRUMENT;
use eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT;
use eliot_process::ProcessEvidenceSink;
use eliot_testd_core::{EvidenceCollector, RawArtifact, RawArtifactStream};
const FIXTURE_PACKAGE: &str = "physical-fixture";
const FIXTURE_TEST: &str = "selected_unit";

struct IsolatedRoots {
    root: PathBuf,
    source: PathBuf,
    target: PathBuf,
    cache: PathBuf,
}

impl IsolatedRoots {
    fn create() -> Result<Self, String> {
        let nonce = system_nanos();
        let root = std::env::temp_dir().join(format!(
            "eliot-provider-physical-{}-{nonce}",
            std::process::id()
        ));
        let source = root.join("source");
        let target = root.join("target");
        let cache = root.join("cache");
        fs::create_dir(&root).map_err(|error| {
            format!(
                "could not exclusively create isolated fixture root {}: {error}",
                root.display()
            )
        })?;
        let roots = Self {
            root,
            source,
            target,
            cache,
        };
        for path in [&roots.source, &roots.target, &roots.cache] {
            fs::create_dir(path).map_err(|error| {
                format!(
                    "could not create isolated fixture subroot {}: {error}",
                    path.display()
                )
            })?;
        }
        write_fixture_project(&roots.source)?;
        Ok(roots)
    }

    fn layout(&self) -> Result<TargetLayout, String> {
        TargetLayout::new(
            canonical(&self.source)?,
            canonical(&self.target)?,
            canonical(&self.cache)?,
        )
        .map_err(|error| format!("isolated fixture layout refused: {error}"))
    }

    fn remove(self) -> Result<(), String> {
        self.remove_owned_root()
    }

    fn remove_owned_root(&self) -> Result<(), String> {
        fs::remove_dir_all(&self.root).map_err(|error| {
            format!(
                "isolated fixture root {} was not cleaned: {error}",
                self.root.display()
            )
        })?;
        if self.root.exists() {
            return Err(format!(
                "isolated fixture root {} remains after cleanup",
                self.root.display()
            ));
        }
        Ok(())
    }
}

impl Drop for IsolatedRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PhysicalRun {
    stages: Vec<PhysicalStage>,
    collector: EvidenceCollector,
    raw: Vec<RawEvidence>,
}

struct PhysicalStage {
    stage_id: String,
    evidence: ProcessEvidence,
}

fn write_fixture_project(source: &Path) -> Result<(), String> {
    let manifest = format!(
        "[package]\nname = \"{FIXTURE_PACKAGE}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"
    );
    fs::write(source.join("Cargo.toml"), manifest)
        .map_err(|error| format!("could not write fixture manifest: {error}"))?;
    fs::write(
        source.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"{FIXTURE_PACKAGE}\"\nversion = \"0.0.0\"\n"
        ),
    )
    .map_err(|error| format!("could not write fixture lockfile: {error}"))?;
    let source_root = workspace_root()?;
    let pinned_toolchain = source_root.join("rust-toolchain.toml");
    if pinned_toolchain.is_file() {
        fs::copy(&pinned_toolchain, source.join("rust-toolchain.toml"))
            .map_err(|error| format!("could not copy observed toolchain selection: {error}"))?;
    }
    let source_dir = source.join("src");
    fs::create_dir_all(&source_dir)
        .map_err(|error| format!("could not create fixture source directory: {error}"))?;
    fs::write(
        source_dir.join("lib.rs"),
        format!(
            "pub fn fixture_diagnostic(){{let unused_binding=1;}}\n#[cfg(test)] mod tests {{ #[test] fn {FIXTURE_TEST}() {{ assert_eq!(2 + 2, 4); }} }}\n"
        ),
    )
    .map_err(|error| format!("could not write fixture Rust source: {error}"))
}

fn install_stage_timeout_build_script(source: &Path) -> Result<(), String> {
    let sleep_ms = STAGE_WALL_TIMEOUT_MS
        .checked_add(1)
        .ok_or_else(|| "stage wall timeout cannot be extended for its fixture".to_owned())?;
    fs::write(
        source.join("build.rs"),
        format!(
            "fn main() -> std::io::Result<()> {{ std::fs::write(std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"build-script-entered\"), b\"started\")?; std::thread::sleep(std::time::Duration::from_millis({sleep_ms})); Ok(()) }}\n"
        ),
    )
    .map_err(|error| format!("could not write stage timeout build script: {error}"))
}

fn workspace_root() -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| "runner manifest has no workspace root".to_owned())?;
    fs::canonicalize(root).map_err(|error| format!("workspace root is unavailable: {error}"))
}

fn canonical(path: &Path) -> Result<String, String> {
    fs::canonicalize(path)
        .map(|value| value.to_string_lossy().into_owned())
        .map_err(|error| format!("fixture path {} is unavailable: {error}", path.display()))
}

fn profile_registry(source_root: &str) -> Result<InstrumentRegistry, String> {
    let specs = eliot_instrument_runner::profile::builtin_specs()
        .map_err(|error| format!("builtin provider specs refused: {error}"))?;
    let receipts = observed_supply_chain(&specs, source_root)
        .map_err(|error| format!("toolchain observation refused: {error}"))?;
    InstrumentRegistry::with_verification_route_profiles(VERIFICATION_REGISTRY_GENERATION, receipts)
        .map_err(|error| format!("builtin profile registry refused: {error}"))
}

fn provider_registry() -> Result<(ProviderRegistry, ProviderDenominator), String> {
    let fingerprints = fixture_fingerprints();
    let normative_pair_digest = format!("test:{DENOMINATOR_CONTRACT}");
    let registry = ProviderRegistry::ready(1, normative_pair_digest, &fingerprints)
        .map_err(|error| format!("ready provider registry refused: {error:?}"))?;
    let denominator = ProviderDenominator::current(&registry)
        .map_err(|error| format!("provider denominator refused: {error:?}"))?;
    Ok((registry, denominator))
}

// This fixture keeps the existing main-branch low-level ProcessExecutor proof:
// it launches each planned stage through InstrumentRunner with real process
// evidence, then feeds those bytes to the provider parsers. It deliberately
// does not manufacture a ProfileAggregate or a Kernel admission grant.
fn launch_profile(
    registry: &InstrumentRegistry,
    layout: TargetLayout,
    profile_name: &str,
) -> Result<PhysicalRun, String> {
    let profile = registry
        .admitted_head(profile_name)
        .map_err(|error| format!("profile {profile_name} is not admitted: {error}"))?;
    let admitted = ProfileCompiler::new(registry)
        .compile_exact(&profile.name, profile.revision)
        .map_err(|error| format!("profile {profile_name} did not compile: {error}"))?;
    let epoch = process_epoch().map_err(|error| format!("fixture epoch refused: {error}"))?;
    let clock = observation_clock(now_unix_ms());
    let cell = Arc::new(
        DispatchCell::activate()
            .map_err(|error| format!("P-07 fixture authority refused: {error}"))?,
    );
    let port = StagePort::seal_all(&cell, &epoch, &layout, &admitted)
        .map_err(|error| format!("builtin stage seals refused: {error}"))?;
    let executor = Arc::new(StageExecutor::with(&cell));
    let runner = InstrumentRunner::new(Arc::clone(&executor));
    let launcher = StageRoute {
        epoch,
        clock,
        layout,
        port,
    };
    let plan = StageOrchestrator::plan(&admitted);
    let mut stages = Vec::new();
    let collector = EvidenceCollector::default();
    let mut raw = Vec::new();
    for planned in &plan.stages {
        let stage_id = planned.route.stage().stage_id.as_str();
        let invocation = launcher
            .invocation(planned)
            .map_err(|error| format!("physical stage {stage_id} invocation refused: {error}"))?;
        let port = launcher.port(planned);
        let mut binding = eliot_instrument_runner::InstrumentBinding::bind(invocation, port)
            .map_err(|error| format!("physical stage {stage_id} binding refused: {error}"))?;
        let sink = launcher.sink(planned);
        block_on(runner.launch(&mut binding, sink))
            .map_err(|error| format!("physical stage {stage_id} launch refused: {error}"))?;
        let executable = resolve_tool(&planned.stage.executable, &launcher.layout.source_root)
            .map_err(|error| format!("physical stage {stage_id} executable refused: {error}"))?;
        await_terminal_view(
            executor.executor(),
            binding.operation_id(),
            &executable,
            Duration::from_millis(STAGE_WALL_TIMEOUT_MS),
        )
        .map_err(|error| {
            format!("physical stage {stage_id} did not reach terminal state: {error}")
        })?;
        let evidence = block_on(runner.reconcile(&binding)).map_err(|error| {
            format!("physical stage {stage_id} evidence did not reconcile: {error}")
        })?;
        ProcessEvidenceSink::record(&collector, evidence.clone()).map_err(|error| {
            format!("testd EvidenceCollector refused physical evidence: {error}")
        })?;
        capture_stream(
            &collector,
            &mut raw,
            &evidence,
            evidence.stdout(),
            RawArtifactStream::Stdout,
        )?;
        capture_stream(
            &collector,
            &mut raw,
            &evidence,
            evidence.stderr(),
            RawArtifactStream::Stderr,
        )?;
        stages.push(PhysicalStage {
            stage_id: stage_id.to_owned(),
            evidence,
        });
    }
    executor
        .executor()
        .cleanup_finished()
        .map_err(|error| format!("executor cleanup did not complete: {error}"))?;
    let health = executor.executor().operation_health_summary();
    if health.cleanup_pending_operations != 0 || health.unknown_outcome_operations != 0 {
        return Err(format!("fixture left executor work pending: {health:?}"));
    }
    if collector.snapshot().is_empty() {
        return Err("profile produced no physical ProcessEvidence".to_owned());
    }
    if raw
        .iter()
        .any(|item| item.execution_status() == ExecutionStatus::Succeeded)
    {
        return Err("retention state became successful provider evidence".to_owned());
    }
    Ok(PhysicalRun {
        stages,
        collector,
        raw,
    })
}

fn capture_stream(
    collector: &EvidenceCollector,
    raw: &mut Vec<RawEvidence>,
    evidence: &ProcessEvidence,
    stream: Option<&eliot_process::ProcessStreamEvidence>,
    kind: RawArtifactStream,
) -> Result<(), String> {
    let stream_name = match kind {
        RawArtifactStream::Stdout => "stdout",
        RawArtifactStream::Stderr => "stderr",
        RawArtifactStream::Unknown => return Err("unknown stream cannot be captured".to_owned()),
    };
    let handle = format!("{}-{stream_name}", evidence.operation_id().as_str());
    let Some(stream) = stream else {
        raw.push(RawEvidence::Omitted {
            reason: OmissionReason::Omitted {
                reason: format!("ProcessEvidence carries no {stream_name} stream"),
            },
        });
        return Ok(());
    };
    let preview = stream.preview();
    let bytes = preview.bytes().to_vec();
    if bytes.is_empty() {
        raw.push(RawEvidence::Omitted {
            reason: OmissionReason::Omitted {
                reason: format!("{stream_name} preview is empty"),
            },
        });
        return Ok(());
    }
    collector
        .record_raw_artifact_at(
            handle.clone(),
            "application/octet-stream",
            bytes.clone(),
            preview.is_truncated(),
            kind,
            observation_clock(now_unix_ms()),
        )
        .map_err(|error| format!("testd raw artifact retention refused: {error}"))?;
    if preview.is_truncated() {
        raw.push(RawEvidence::Omitted {
            reason: OmissionReason::Truncated {
                byte_len: preview.retained_bytes(),
                limit_bytes: STAGE_STDOUT_BYTES,
            },
        });
    } else {
        raw.push(RawEvidence::Retained {
            artifact: ArtifactId::new(handle)
                .map_err(|error| format!("raw artifact handle refused: {error}"))?,
            byte_len: preview.retained_bytes(),
        });
    }
    Ok(())
}

fn evidence_for_stage(runs: &[PhysicalRun], stage_id: &str) -> Result<ProcessEvidence, String> {
    runs.iter()
        .flat_map(|run| &run.stages)
        .find(|stage| stage.stage_id == stage_id)
        .map(|stage| stage.evidence.clone())
        .ok_or_else(|| format!("planned stage {stage_id} has no retained ProcessEvidence"))
}

fn require_stage_execution(
    runs: &[PhysicalRun],
    stage_id: &str,
    expected: ExecutionStatus,
) -> Result<(), String> {
    let evidence = evidence_for_stage(runs, stage_id)?;
    let view = evidence.view();
    let Some(exit) = view.exit() else {
        return Err(format!(
            "planned stage {stage_id} did not retain terminal physical process evidence for {expected:?}"
        ));
    };
    if !view.lifecycle().is_terminal()
        || exit.disposition() != eliot_process::ExitDisposition::Completed
    {
        return Err(format!(
            "planned stage {stage_id} did not finish with a terminal Completed process outcome for {expected:?}"
        ));
    }
    let serialized_exit = serde_json::to_value(exit).map_err(|error| {
        format!("planned stage {stage_id} exit observation was unreadable: {error}")
    })?;
    let exit_code = serialized_exit
        .get("code")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("planned stage {stage_id} exit observation has no signed code"))?;
    let expected_success = match expected {
        ExecutionStatus::Succeeded => true,
        ExecutionStatus::Failed => false,
        _ => {
            return Err(format!(
                "planned stage {stage_id} fixture expected unsupported execution status {expected:?}"
            ));
        }
    };
    if (exit_code == 0) != expected_success {
        return Err(format!(
            "planned stage {stage_id} exited with code {exit_code}, inconsistent with {expected:?}"
        ));
    }
    Ok(())
}

fn complete_stdout<'a>(evidence: &'a ProcessEvidence, stage_id: &str) -> Result<&'a [u8], String> {
    let stream = evidence
        .stdout()
        .ok_or_else(|| format!("{stage_id} stdout was omitted before parsing"))?;
    let preview = stream.preview();
    if preview.is_truncated() {
        return Err(format!("{stage_id} stdout was truncated before parsing"));
    }
    if preview.bytes().is_empty() {
        return Err(format!("{stage_id} stdout was empty before parsing"));
    }
    Ok(preview.bytes())
}

fn physical_case(
    contract: &str,
    provider_registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
    runs: &[PhysicalRun],
) -> Result<ConformanceCase, String> {
    let entry = denominator.entry(contract);
    let kind = if let Some(entry) = entry {
        entry
            .verify_profile_identities()
            .map_err(|error| format!("{contract} provider identity refused: {error}"))?;
        if entry.instrument.as_str() != contract
            || entry.identities.executable != entry.executable.identity_name()
        {
            return Err(format!(
                "{contract} provider identity does not match its declared denominator row"
            ));
        }
        *entry
            .kinds
            .first()
            .ok_or_else(|| format!("{contract} has no declared provider kind"))?
    } else {
        if !UNMAPPED_IN_PROCESS_INSTRUMENTS
            .iter()
            .any(|row| row.contract == contract)
        {
            return Err(format!(
                "{contract} is absent from both mapped and unmapped provider entries"
            ));
        }
        InstrumentKind::Inspect
    };
    let instrument = ContractId::new(contract)
        .map_err(|error| format!("declared contract identity refused: {error}"))?;
    let fingerprints = fixture_fingerprints();
    let availability = provider_registry.availability_parts(
        &instrument,
        kind,
        &AvailabilityInputs {
            generation: provider_registry.generation(),
            normative_pair_digest: provider_registry.normative_pair_digest(),
            fingerprints: &fingerprints,
            platform: host_platform(),
        },
    );
    let real_execution = match contract {
        CARGO_CONTRACT_NAME => evidence_for_stage(runs, "cargo-metadata").is_ok(),
        RUSTC_INSTRUMENT => evidence_for_stage(runs, "rustc-build").is_ok(),
        NEXTEST_INSTRUMENT => evidence_for_stage(runs, "nextest-run").is_ok(),
        RUSTFMT_INSTRUMENT => evidence_for_stage(runs, "package-format").is_ok(),
        _ => false,
    };
    Ok(ConformanceCase {
        case_id: contract.to_owned(),
        instrument: contract.to_owned(),
        kind,
        expected_dispatchable: availability.is_available(),
        real_execution,
    })
}

fn assert_dotnet_is_typed_unsupported(
    provider_registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) -> Result<(), String> {
    let dotnet = ADVERTISED_INSTRUMENTS
        .iter()
        .find(|provider| provider.contract == eliot_instrument_dotnet::CONTRACT_ID)
        .ok_or_else(|| ".NET provider disappeared from the declared denominator".to_owned())?;
    let entry = denominator
        .entry(dotnet.contract)
        .ok_or_else(|| ".NET provider entry is absent".to_owned())?;
    let kind = entry
        .kinds
        .first()
        .copied()
        .ok_or_else(|| ".NET provider has no declared kind".to_owned())?;
    let instrument = ContractId::new(dotnet.contract)
        .map_err(|error| format!(".NET contract identity refused: {error}"))?;
    let fingerprints = fixture_fingerprints();
    let outcome = eliot_instrument_runner::compose_provider_dispatch(
        provider_registry,
        &instrument,
        kind,
        &AvailabilityInputs {
            generation: provider_registry.generation(),
            normative_pair_digest: provider_registry.normative_pair_digest(),
            fingerprints: &fingerprints,
            platform: host_platform(),
        },
    );
    if !matches!(
        outcome.disposition(),
        eliot_instrument_runner::ProviderDisposition::UnsupportedByTestd { .. }
    ) || outcome.is_dispatchable()
    {
        return Err(format!(
            ".NET Testd composition was not typed UnsupportedByTestd: {:?}",
            outcome.disposition()
        ));
    }
    Ok(())
}

fn assert_platform_mismatch_stays_typed(
    provider_registry: &ProviderRegistry,
) -> Result<(), String> {
    let contract = ContractId::new(CARGO_CONTRACT_NAME)
        .map_err(|error| format!("Cargo contract identity refused: {error}"))?;
    let fingerprints = fixture_fingerprints();
    let outcome = eliot_instrument_runner::compose_provider_dispatch(
        provider_registry,
        &contract,
        InstrumentKind::Build,
        &AvailabilityInputs {
            generation: provider_registry.generation(),
            normative_pair_digest: provider_registry.normative_pair_digest(),
            fingerprints: &fingerprints,
            platform: "fixture-unsupported-platform",
        },
    );
    if !matches!(
        outcome.disposition(),
        eliot_instrument_runner::ProviderDisposition::UnsupportedPlatform { .. }
    ) || outcome.is_dispatchable()
    {
        return Err(format!(
            "platform mismatch was not typed unsupported: {:?}",
            outcome.disposition()
        ));
    }
    Ok(())
}

fn build_common_corpus(
    provider_registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
    runs: &[PhysicalRun],
) -> Result<ConformanceCorpus, String> {
    let cases = declared_instruments()
        .map(|advertised| physical_case(advertised.contract, provider_registry, denominator, runs))
        .collect::<Result<Vec<_>, _>>()?;
    let corpus = ConformanceCorpus {
        corpus_id: DENOMINATOR_CONTRACT.to_owned(),
        generation: provider_registry.generation(),
        normative_pair_digest: provider_registry.normative_pair_digest().to_owned(),
        fingerprints: fixture_fingerprints(),
        cases,
    };
    if corpus.cases.len() != declared_instruments().count() {
        return Err("common physical corpus omitted a declared provider".to_owned());
    }
    corpus
        .validate(provider_registry, denominator)
        .map_err(|error| format!("common physical provider corpus refused: {error}"))?;
    for unmapped in UNMAPPED_IN_PROCESS_INSTRUMENTS {
        let contract = unmapped.contract;
        let case = corpus
            .cases
            .iter()
            .find(|case| case.instrument == contract)
            .ok_or_else(|| format!("unmapped provider {contract} has no corpus case"))?;
        if case.expected_dispatchable || case.real_execution {
            return Err(format!(
                "unmapped provider {contract} was treated as available or executed"
            ));
        }
    }
    if corpus
        .cases
        .iter()
        .filter(|case| case.real_execution)
        .count()
        != 4
    {
        return Err(
            "physical corpus does not retain exactly four real provider fixtures".to_owned(),
        );
    }
    Ok(corpus)
}

fn assert_scip_decoder_fixture(denominator: &ProviderDenominator) -> Result<(), String> {
    const FIXTURE_CASE: &str = "scip-in-process-decoder-retained-v1";
    let original_bytes = scip_fixture_bytes()?;
    let retained = RawArtifact::from_observation(
        "fixture:scip-decoder-v1:raw-protobuf",
        "application/x-protobuf",
        original_bytes.clone(),
        false,
        RawArtifactStream::Unknown,
        observation_clock(now_unix_ms()),
    )
    .map_err(|error| format!("SCIP raw fixture retention refused: {error}"))?;
    retained
        .validate()
        .map_err(|error| format!("SCIP retained raw fixture failed validation: {error}"))?;
    if retained.bytes != original_bytes {
        return Err("SCIP raw fixture retention changed the authored bytes".to_owned());
    }
    let index = eliot_instrument_scip::ScipIndex::decode(&retained.bytes)
        .map_err(|error| format!("SCIP decoder fixture refused: {error}"))?;
    if index.documents.len() != 1
        || index
            .documents
            .first()
            .is_none_or(|document| document.symbols.len() != 1 || document.occurrences.len() != 1)
    {
        return Err(
            "SCIP decoder fixture did not contain its declared document, symbol, occurrence"
                .to_owned(),
        );
    }
    let instrument = eliot_instrument_scip::SCIP_INSTRUMENT;
    let entry = denominator
        .entry(instrument)
        .ok_or_else(|| "SCIP decoder is absent from the declared denominator".to_owned())?;
    entry
        .verify_profile_identities()
        .map_err(|error| format!("SCIP decoder identity refused: {error}"))?;
    let fixture = ProviderFixtureSet {
        instrument: instrument.to_owned(),
        generation: entry.generation,
        fingerprints: fixture_fingerprints(),
        real_cases: vec![FIXTURE_CASE.to_owned()],
    };
    fixture
        .validate(entry)
        .map_err(|error| format!("SCIP in-process decoder fixture refused: {error}"))?;
    Ok(())
}

fn assert_scip_testd_routing_is_typed_unsupported(
    provider_registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) -> Result<(), String> {
    let instrument = eliot_instrument_scip::SCIP_INSTRUMENT;
    let entry = denominator
        .entry(instrument)
        .ok_or_else(|| "SCIP decoder is absent from the declared denominator".to_owned())?;
    let kind = *entry
        .kinds
        .first()
        .ok_or_else(|| "SCIP decoder has no declared provider kind".to_owned())?;
    let contract = ContractId::new(instrument)
        .map_err(|error| format!("SCIP contract identity refused: {error}"))?;
    let fingerprints = fixture_fingerprints();
    let outcome = eliot_instrument_runner::compose_provider_dispatch(
        provider_registry,
        &contract,
        kind,
        &AvailabilityInputs {
            generation: provider_registry.generation(),
            normative_pair_digest: provider_registry.normative_pair_digest(),
            fingerprints: &fingerprints,
            platform: host_platform(),
        },
    );
    if !matches!(
        outcome.disposition(),
        eliot_instrument_runner::ProviderDisposition::UnsupportedByTestd { .. }
    ) || outcome.is_dispatchable()
    {
        return Err(format!(
            "SCIP Testd routing was not typed UnsupportedByTestd: {:?}",
            outcome.disposition()
        ));
    }
    Ok(())
}

fn parse_cargo_fixture(runs: &[PhysicalRun]) -> Result<(), String> {
    require_stage_execution(runs, "cargo-metadata", ExecutionStatus::Succeeded)?;
    let evidence = evidence_for_stage(runs, "cargo-metadata")?;
    let report = eliot_instrument_cargo::parse_jsonl(complete_stdout(&evidence, "cargo-metadata")?)
        .map_err(|error| format!("Cargo parser refused complete physical output: {error}"))?;
    if report.build_finished != Some(true) || report.artifacts.is_empty() {
        return Err("Cargo build output lacked a completed build or compiled artifact".to_owned());
    }
    Ok(())
}

fn parse_rustc_fixture(runs: &[PhysicalRun]) -> Result<(), String> {
    require_stage_execution(runs, "rustc-build", ExecutionStatus::Succeeded)?;
    let evidence = evidence_for_stage(runs, "rustc-build")?;
    let report =
        eliot_instrument_rustc::parse_clippy_jsonl(complete_stdout(&evidence, "rustc-build")?)
            .map_err(|error| format!("Clippy parser refused complete physical output: {error}"))?;
    if report.warnings == 0 && report.informational == 0 {
        return Err("Clippy fixture produced no diagnostic for its unused binding".to_owned());
    }
    Ok(())
}

fn parse_nextest_fixture(runs: &[PhysicalRun]) -> Result<(), String> {
    for stage_id in ["nextest-list", "nextest-run"] {
        require_stage_execution(runs, stage_id, ExecutionStatus::Succeeded)?;
        let evidence = evidence_for_stage(runs, stage_id)?;
        let report = eliot_instrument_nextest::parse_jsonl(complete_stdout(&evidence, stage_id)?)
            .map_err(|error| {
            format!("{stage_id} parser refused complete physical output: {error}")
        })?;
        if report.started != 1
            || report.completed != 1
            || report.passed != 1
            || report.skipped != 0
            || report.failed != 0
            || report.timed_out != 0
            || report.leaked != 0
            || report.cancelled != 0
            || report.execution_status() != ExecutionStatus::Succeeded
        {
            return Err(format!(
                "{stage_id} did not report exactly one completed, passing, non-skipped test: {report:?}"
            ));
        }
    }
    Ok(())
}

fn parse_rustfmt_fixture(runs: &[PhysicalRun]) -> Result<(), String> {
    require_stage_execution(runs, "package-format", ExecutionStatus::Failed)?;
    let evidence = evidence_for_stage(runs, "package-format")?;
    let report =
        eliot_instrument_rustfmt::parse_output(complete_stdout(&evidence, "package-format")?)
            .map_err(|error| format!("rustfmt parser refused complete physical output: {error}"))?;
    if report.changed_files().is_empty()
        || report.execution_status(None, false) == ExecutionStatus::Succeeded
    {
        return Err(
            "rustfmt did not report the fixture's intentional formatting difference".to_owned(),
        );
    }
    Ok(())
}

fn fixture_fingerprints() -> InvalidationSet {
    // Keep the shared corpus's established test identity fields; runtime
    // process/tool identities are separately derived from the physical run.
    InvalidationSet {
        source: "source".to_owned(),
        lock: "lock".to_owned(),
        toolchain: "toolchain".to_owned(),
        env: "env".to_owned(),
        exe: "exe".to_owned(),
        profile: "profile".to_owned(),
        parser: "parser".to_owned(),
    }
}

#[test]
fn builtin_provider_fixtures_use_the_shared_executor_and_retain_real_evidence() -> Result<(), String>
{
    let roots = IsolatedRoots::create()?;
    let source_root = canonical(&roots.source)?;
    let layout = roots.layout()?;
    let registry = profile_registry(&source_root)?;
    let (provider_registry, denominator) = provider_registry()?;
    assert_eq!(ADVERTISED_INSTRUMENTS.len(), 6);
    assert_eq!(denominator.mapped(), ADVERTISED_INSTRUMENTS.len());
    assert_eq!(
        declared_instruments().count(),
        ADVERTISED_INSTRUMENTS.len() + UNMAPPED_IN_PROCESS_INSTRUMENTS.len()
    );
    assert_eq!(declared_instruments().count(), 8);

    let physical_runs = [
        launch_profile(&registry, layout.clone(), COMPILER_PROFILE)?,
        launch_profile(&registry, layout.clone(), TEST_PROFILE)?,
        launch_profile(&registry, layout, PACKAGE_VERIFICATION_ROUTE)?,
    ];
    let evidence = physical_runs
        .iter()
        .flat_map(|run| run.collector.snapshot())
        .collect::<Vec<_>>();
    let launched_operations = physical_runs
        .iter()
        .flat_map(|run| &run.stages)
        .map(|stage| stage.evidence.operation_id().as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(evidence.len(), launched_operations.len());
    assert_scip_decoder_fixture(&denominator)?;
    assert_scip_testd_routing_is_typed_unsupported(&provider_registry, &denominator)?;
    let corpus = build_common_corpus(&provider_registry, &denominator, &physical_runs)?;
    for case in &corpus.cases {
        if case.real_execution {
            let instrument = case.instrument.as_str();
            let entry = denominator
                .entry(instrument)
                .ok_or_else(|| format!("physical fixture entry {instrument} is absent"))?;
            let fixture = ProviderFixtureSet {
                instrument: case.instrument.clone(),
                generation: entry.generation,
                fingerprints: fixture_fingerprints(),
                real_cases: vec![case.case_id.clone()],
            };
            fixture.validate(entry).map_err(|error| {
                format!("physical provider fixture {instrument} refused: {error}")
            })?;
        }
    }
    assert_dotnet_is_typed_unsupported(&provider_registry, &denominator)?;
    assert_platform_mismatch_stays_typed(&provider_registry)?;
    parse_cargo_fixture(&physical_runs)?;
    parse_rustc_fixture(&physical_runs)?;
    parse_nextest_fixture(&physical_runs)?;
    parse_rustfmt_fixture(&physical_runs)?;

    assert!(
        physical_runs
            .iter()
            .flat_map(|run| &run.raw)
            .all(|item| item.execution_status() != ExecutionStatus::Succeeded)
    );
    roots.remove()
}

fn scip_fixture_bytes() -> Result<Vec<u8>, String> {
    fn varint(mut value: usize) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        while value >= 0x80 {
            let part = u8::try_from(value & 0x7f)
                .map_err(|error| format!("SCIP fixture varint part was invalid: {error}"))?;
            bytes.push(part | 0x80);
            value >>= 7;
        }
        let final_part = u8::try_from(value)
            .map_err(|error| format!("SCIP fixture varint final part was invalid: {error}"))?;
        bytes.push(final_part);
        Ok(bytes)
    }
    fn field(number: u8, value: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = vec![(number << 3) | 2];
        output.extend(varint(value.len())?);
        output.extend_from_slice(value);
        Ok(output)
    }
    let symbol_text = b"fixture-symbol";
    let mut symbol = field(1, symbol_text)?;
    symbol.extend([0x10, 0x01]);
    let mut occurrence = field(1, &[0x00, 0x00])?;
    occurrence.extend(field(2, symbol_text)?);
    let mut document = field(1, b"src/lib.rs")?;
    document.extend(field(3, &symbol)?);
    document.extend(field(4, &occurrence)?);
    field(2, &document)
}

fn retain_non_success_evidence(evidence: &ProcessEvidence, context: &str) -> Result<(), String> {
    let collector = EvidenceCollector::default();
    ProcessEvidenceSink::record(&collector, evidence.clone())
        .map_err(|error| format!("testd collector refused {context} process evidence: {error}"))?;
    let mut raw = Vec::new();
    capture_stream(
        &collector,
        &mut raw,
        evidence,
        evidence.stdout(),
        RawArtifactStream::Stdout,
    )?;
    capture_stream(
        &collector,
        &mut raw,
        evidence,
        evidence.stderr(),
        RawArtifactStream::Stderr,
    )?;
    if collector.snapshot().len() != 1 || raw.len() != 2 {
        return Err(format!(
            "{context} process or raw stream evidence was not retained"
        ));
    }
    if raw
        .iter()
        .any(|item| item.execution_status() == ExecutionStatus::Succeeded)
    {
        return Err(format!(
            "{context} evidence was promoted to successful provider evidence"
        ));
    }
    Ok(())
}

fn cleanup_stage_executor(executor: &StageExecutor, context: &str) -> Result<(), String> {
    executor
        .executor()
        .cleanup_finished()
        .map_err(|error| format!("{context} child cleanup did not complete: {error}"))?;
    let health = executor.executor().operation_health_summary();
    if health.cleanup_pending_operations != 0 || health.unknown_outcome_operations != 0 {
        return Err(format!(
            "{context} fixture left process work pending: {health:?}"
        ));
    }
    Ok(())
}

struct RealRustcStage {
    source_root: String,
    executor: Arc<StageExecutor>,
    runner: InstrumentRunner<StageExecutor>,
    binding: eliot_instrument_runner::InstrumentBinding,
}

fn launch_real_rustc_stage(roots: &IsolatedRoots) -> Result<RealRustcStage, String> {
    let source_root = canonical(&roots.source)?;
    let layout = roots.layout()?;
    let registry = profile_registry(&source_root)?;
    let profile = registry
        .admitted_head(COMPILER_PROFILE)
        .map_err(|error| format!("compiler profile is not admitted: {error}"))?;
    let admitted = ProfileCompiler::new(&registry)
        .compile_exact(&profile.name, profile.revision)
        .map_err(|error| format!("compiler fixture did not compile: {error}"))?;
    let epoch = process_epoch().map_err(|error| format!("fixture epoch refused: {error}"))?;
    let clock = observation_clock(now_unix_ms());
    let cell = Arc::new(
        DispatchCell::activate()
            .map_err(|error| format!("P-07 fixture authority refused: {error}"))?,
    );
    let port = StagePort::seal_all(&cell, &epoch, &layout, &admitted)
        .map_err(|error| format!("compiler stage seals refused: {error}"))?;
    let executor = Arc::new(StageExecutor::with(&cell));
    let runner = InstrumentRunner::new(Arc::clone(&executor));
    let launcher = StageRoute {
        epoch,
        clock,
        layout,
        port,
    };
    let plan = StageOrchestrator::plan(&admitted);
    let stage = plan
        .stages
        .iter()
        .find(|stage| stage.route.stage().stage_id == "rustc-build")
        .ok_or_else(|| "compiler fixture omitted its admitted rustc stage".to_owned())?;
    let invocation = launcher
        .invocation(stage)
        .map_err(|error| format!("rustc fixture invocation refused: {error}"))?;
    let mut binding =
        eliot_instrument_runner::InstrumentBinding::bind(invocation, launcher.port(stage))
            .map_err(|error| format!("rustc fixture request bind refused: {error}"))?;
    let sink = Arc::clone(&launcher.port.sink) as Arc<dyn ProcessEvidenceSink>;
    block_on(runner.launch(&mut binding, sink))
        .map_err(|error| format!("governed rustc fixture launch refused: {error}"))?;
    Ok(RealRustcStage {
        source_root,
        executor,
        runner,
        binding,
    })
}

#[test]
fn sealed_rustc_stage_timeout_reconciles_resource_limit_and_cleans_the_real_child()
-> Result<(), String> {
    let roots = IsolatedRoots::create()?;
    install_stage_timeout_build_script(&roots.source)?;
    let stage = launch_real_rustc_stage(&roots)?;

    // Let the stage's existing ProcessExecutor wall limit elapse before
    // observing the terminal state; the version-probe observation window is not
    // used as a substitute for the stage's own timeout.
    std::thread::sleep(Duration::from_millis(STAGE_WALL_TIMEOUT_MS));
    let executable = resolve_tool("cargo", &stage.source_root)
        .map_err(|error| format!("selected Cargo identity refused: {error}"))?;
    let terminal = await_terminal_view(
        stage.executor.executor(),
        stage.binding.operation_id(),
        &executable,
        Duration::from_millis(STAGE_WALL_TIMEOUT_MS),
    )
    .map_err(|error| format!("timed-out rustc child did not reach a terminal view: {error}"))?;
    if !roots.source.join("build-script-entered").is_file() {
        return Err("Cargo did not execute the timeout fixture build script".to_owned());
    }
    if !terminal.lifecycle().is_terminal()
        || terminal
            .exit()
            .is_none_or(|exit| exit.disposition() != ExitDisposition::ResourceLimit)
    {
        return Err(format!(
            "stage wall limit did not produce terminal ResourceLimit evidence: {terminal:?}"
        ));
    }
    let evidence = block_on(stage.runner.reconcile(&stage.binding))
        .map_err(|error| format!("timed-out rustc child evidence did not reconcile: {error}"))?;
    if !evidence.view().lifecycle().is_terminal()
        || evidence
            .view()
            .exit()
            .is_none_or(|exit| exit.disposition() != ExitDisposition::ResourceLimit)
    {
        return Err(format!(
            "reconciled rustc evidence did not retain terminal ResourceLimit: {:?}",
            evidence.view()
        ));
    }
    retain_non_success_evidence(&evidence, "timeout")?;
    cleanup_stage_executor(&stage.executor, "timed-out")?;
    roots.remove()
}

#[test]
fn isolated_root_cleanup_failure_is_observed_and_reconciled() -> Result<(), String> {
    let roots = IsolatedRoots::create()?;
    let sentinel = roots.root.join("cleanup-sentinel");
    fs::write(&sentinel, b"owned cleanup fixture")
        .map_err(|error| format!("could not write cleanup sentinel: {error}"))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&sentinel)
        .map_err(|error| format!("could not hold cleanup sentinel exclusively: {error}"))?;

    let Err(cleanup_error) = roots.remove_owned_root() else {
        return Err("isolated root cleanup unexpectedly succeeded while locked".to_owned());
    };
    if !roots.root.exists() {
        return Err(format!(
            "failed cleanup did not leave its owned root for reconciliation: {cleanup_error}"
        ));
    }

    drop(lock);
    roots
        .remove_owned_root()
        .map_err(|error| format!("owned root cleanup reconciliation failed: {error}"))?;
    if roots.root.exists() {
        return Err("owned root remained after cleanup reconciliation".to_owned());
    }
    Ok(())
}

#[test]
fn cancellation_of_a_sealed_rustc_stage_reconciles_and_cleans_the_real_child() -> Result<(), String>
{
    let roots = IsolatedRoots::create()?;
    let stage = launch_real_rustc_stage(&roots)?;
    let cancellation = block_on(stage.runner.cancel(&stage.binding))
        .map_err(|error| format!("governed child cancellation refused: {error}"))?;
    if cancellation.status() == eliot_process::CancellationStatus::UnknownOutcome {
        return Err("cancelled rustc fixture has an unknown tree outcome".to_owned());
    }
    let executable = resolve_tool("cargo", &stage.source_root)
        .map_err(|error| format!("selected Cargo identity refused: {error}"))?;
    let terminal = await_terminal_view(
        stage.executor.executor(),
        stage.binding.operation_id(),
        &executable,
        Duration::from_millis(STAGE_WALL_TIMEOUT_MS),
    )
    .map_err(|error| format!("cancelled child did not reach a terminal view: {error}"))?;
    if !terminal.lifecycle().is_terminal() {
        return Err("cancelled child remained nonterminal".to_owned());
    }
    let evidence = block_on(stage.runner.reconcile(&stage.binding))
        .map_err(|error| format!("cancelled child evidence did not reconcile: {error}"))?;
    if evidence.view().exit().is_none() {
        return Err("cancelled child has no terminal exit evidence".to_owned());
    }
    retain_non_success_evidence(&evidence, "cancellation")?;
    cleanup_stage_executor(&stage.executor, "cancelled")?;
    roots.remove()
}
