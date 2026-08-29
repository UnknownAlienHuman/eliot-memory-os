use super::*;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn named_thread_spawn_failure_is_not_silenced() -> TestResult {
    let error = spawn_named_thread_with(
        "eliot-p04-injected",
        || {},
        |_builder, _task| Err(std::io::Error::other("injected spawn failure")),
    )
    .err()
    .ok_or_else(|| std::io::Error::other("spawn failure was silently accepted"))?;
    assert!(matches!(
        error,
        ProcessExecutionError::Unavailable(message)
            if message.contains("eliot-p04-injected spawn failed")
    ));
    Ok(())
}

#[cfg(windows)]
fn wait_until_finished(thread: &JoinHandle<()>) -> Result<(), std::io::Error> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .unwrap_or_else(Instant::now);
    while !thread.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if thread.is_finished() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "test thread did not finish",
        ))
    }
}

#[cfg(windows)]
#[test]
fn owned_thread_panic_is_reported_with_identity() -> TestResult {
    let thread = spawn_named_thread("eliot-p04-panicking", || {
        panic!("injected watcher panic");
    })?;
    wait_until_finished(&thread)?;
    let watcher = DeadlineWatcher::from_thread(thread);
    let error = watcher
        .join()
        .err()
        .ok_or_else(|| std::io::Error::other("watcher panic was silently accepted"))?;
    assert!(matches!(
        error,
        ProcessExecutionError::Unavailable(message)
            if message.contains("panicked before ownership release")
    ));
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use eliot_platform::ClockObservation;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, PermitIssuance, ProcessIntent, ProcessTreeId, ResourceLimits, SessionId,
    };
    use std::future::Future;
    use std::path::PathBuf;
    use std::task::{Context, Poll, Wake, Waker};

    static WINDOWS_EXECUTOR_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestWake;

    impl Wake for TestWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(TestWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => thread::yield_now(),
            }
        }
    }

    struct TestEvidenceSink;

    impl ProcessEvidenceSink for TestEvidenceSink {
        fn record(
            &self,
            _evidence: ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    struct TestAuthority {
        authority: Mutex<DispatchPermitAuthority>,
        context: DispatchValidationContext,
    }

    impl DispatchValidationPort for TestAuthority {
        fn validate_and_consume(
            &self,
            request: ProcessRequest,
            observed: SuspendedProcessIdentity,
        ) -> Result<ValidatedDispatch, ProcessExecutionError> {
            self.authority
                .lock()
                .map_err(|_| unavailable("test authority lock poisoned"))?
                .validate_and_consume(request, observed, &self.context)
                .map_err(ProcessExecutionError::from)
        }
    }

    fn powershell_path() -> Result<PathBuf, std::io::Error> {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| std::io::Error::other("SystemRoot is unavailable"))?;
        let executable = PathBuf::from(system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if executable.is_file() {
            Ok(executable)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("PowerShell executable is missing: {}", executable.display()),
            ))
        }
    }

    fn request_and_authority(
        suffix: &str,
        wall_timeout_ms: u64,
    ) -> TestResult<(ProcessRequest, Arc<TestAuthority>, OperationId)> {
        let executable = powershell_path()?;
        let working_directory = executable
            .parent()
            .ok_or_else(|| std::io::Error::other("PowerShell has no parent directory"))?;
        let generation = Generation::new(1)?;
        let operation_id = OperationId::new(format!("deadline-{suffix}"))?;
        let fence = FencingToken::new(1, generation, format!("fence-{suffix}"))?;
        let revision_heads =
            BTreeMap::from([("store:test".to_owned(), "a".repeat(64))]);
        let intent = ProcessIntent::new(
            operation_id.clone(),
            ProcessTreeId::new(format!("tree-{suffix}"))?,
            JobId::new(format!("job-{suffix}"))?,
            ImageId::new(format!("image-{suffix}"))?,
            SessionId::new(format!("session-{suffix}"))?,
            generation,
            executable.to_string_lossy().into_owned(),
            sha256_file(&executable)?,
            vec![
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                "Start-Sleep -Seconds 30".to_owned(),
            ],
            working_directory.to_string_lossy().into_owned(),
            EnvironmentProjection::new(
                BTreeMap::new(),
                Vec::new(),
                EnvironmentInheritance::None,
            )?,
            ResourceLimits::new(
                wall_timeout_ms,
                None,
                None,
                64 * 1024,
                64 * 1024,
                1,
            )?,
        )?;
        let issued_at = now_ms().max(1);
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new(format!("authority-{suffix}"))?,
            KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
        );
        let permit = authority.issue(
            &intent,
            PermitIssuance::new_with_validation_revision(
                ActionLeaseRef::new(format!("lease-{suffix}"))?,
                fence.clone(),
                revision_heads.clone(),
                issued_at,
                issued_at.saturating_add(60_000),
                format!("nonce-{suffix}"),
                1,
            )?,
        )?;
        let request = ProcessRequest::new(intent, permit)?;
        let observed_at = i64::try_from(issued_at.saturating_add(1)).unwrap_or(i64::MAX);
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(observed_at),
                known_time_ms: Some(observed_at),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            1,
            revision_heads,
            1,
        )?;
        Ok((
            request,
            Arc::new(TestAuthority {
                authority: Mutex::new(authority),
                context,
            }),
            operation_id,
        ))
    }

    fn wait_for_cleanup(
        executor: &WindowsProcessExecutor,
        expected: usize,
    ) -> Result<(), ProcessExecutionError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
        loop {
            let cleaned = executor.cleanup_finished()?;
            if cleaned == expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(unavailable(format!(
                    "cleanup did not remove {expected} operation(s)"
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn watcher_spawn_failure_never_returns_a_start_receipt() -> TestResult {
        let _serial = WINDOWS_EXECUTOR_TEST_LOCK
            .lock()
            .map_err(|_| std::io::Error::other("Windows test lock poisoned"))?;
        let (request, authority, operation_id) =
            request_and_authority("spawn-failure", 30_000)?;
        let executor = WindowsProcessExecutor::new(authority);
        FAIL_NEXT_DEADLINE_WATCHER_SPAWN.store(true, Ordering::Release);
        let result = block_on(executor.start(request, Arc::new(TestEvidenceSink)));
        FAIL_NEXT_DEADLINE_WATCHER_SPAWN.store(false, Ordering::Release);
        assert!(matches!(result, Err(ProcessExecutionError::UnknownOutcome)));
        assert!(!executor.poisoned.load(Ordering::Acquire));

        let operation = executor.operation(&operation_id)?;
        let view = operation
            .lock()
            .map_err(|_| unavailable("operation lock poisoned"))?
            .state
            .view();
        assert_eq!(view.lifecycle(), ProcessLifecycle::UnknownOutcome);
        let descendants = view
            .descendants()
            .ok_or_else(|| std::io::Error::other("descendant evidence is missing"))?;
        assert!(descendants.complete());
        assert!(descendants.tree_terminated());

        let evidence = block_on(executor.reconcile(operation_id.clone()))?;
        assert_eq!(evidence.view().lifecycle(), ProcessLifecycle::Reconciled);
        wait_for_cleanup(&executor, 1)?;
        Ok(())
    }

    #[test]
    fn watcher_enforces_wall_deadline_without_polling() -> TestResult {
        let _serial = WINDOWS_EXECUTOR_TEST_LOCK
            .lock()
            .map_err(|_| std::io::Error::other("Windows test lock poisoned"))?;
        let (request, authority, operation_id) = request_and_authority("no-poll", 100)?;
        let executor = WindowsProcessExecutor::new(authority);
        let receipt = block_on(executor.start(request, Arc::new(TestEvidenceSink)))?;
        assert_eq!(receipt.operation_id(), &operation_id);

        let operation = executor.operation(&operation_id)?;
        let watcher_id = operation
            .lock()
            .map_err(|_| unavailable("operation lock poisoned"))?
            .deadline_watcher
            .as_ref()
            .map(|watcher| watcher.thread_id.clone())
            .ok_or_else(|| std::io::Error::other("deadline watcher owner is missing"))?;
        assert!(!watcher_id.is_empty());

        thread::sleep(Duration::from_millis(500));
        let view = operation
            .lock()
            .map_err(|_| unavailable("operation lock poisoned"))?
            .state
            .view();
        assert_eq!(view.lifecycle(), ProcessLifecycle::Exited);
        assert_eq!(
            view.exit()
                .ok_or_else(|| std::io::Error::other("exit evidence is missing"))?
                .disposition(),
            ExitDisposition::ResourceLimit
        );
        let descendants = view
            .descendants()
            .ok_or_else(|| std::io::Error::other("descendant evidence is missing"))?;
        assert!(descendants.complete());
        assert!(descendants.tree_terminated());
        drop(view);
        drop(operation);

        wait_for_cleanup(&executor, 1)?;
        Ok(())
    }
}
