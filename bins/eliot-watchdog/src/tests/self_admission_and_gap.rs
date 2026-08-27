//! Watchdog self-admission and gap oracle — test surface only.
//! Architecture: A8 (self-admission gate) and A13 (gap/recovery disposition) are observation-only contracts.
//! Implementation: I8 (admission probe/status) and I14 (gap classification/reporting) are exercised via fakes.
//! This module owns no production admission, lifecycle, Kernel, or Store/ORS/spool authority.

use super::*;

#[derive(Default)]
struct SelfAdmissionFixture {
    now_ms: u64,
    inspect_advance_ms: u64,
    current: Option<ProcessIdentity>,
    observations: VecDeque<WatchdogRuntimeReadback>,
    sleeps: Vec<u32>,
}

impl WatchdogSelfAdmissionProbe for SelfAdmissionFixture {
    fn now_ms(&mut self) -> u64 {
        self.now_ms
    }

    fn current_process_identity(&mut self) -> Option<ProcessIdentity> {
        self.current.clone()
    }

    fn inspect(&mut self) -> WatchdogRuntimeReadback {
        self.now_ms = self.now_ms.saturating_add(self.inspect_advance_ms);
        self.observations
            .pop_front()
            .unwrap_or(WatchdogRuntimeReadback::Unknown)
    }

    fn sleep_ms(&mut self, milliseconds: u32) {
        self.sleeps.push(milliseconds);
        self.now_ms = self.now_ms.saturating_add(u64::from(milliseconds));
    }
}

#[derive(Default)]
struct SelfAdmissionStatusFixture {
    reports: Vec<(u32, u32)>,
}

impl WatchdogSelfAdmissionStatus for SelfAdmissionStatusFixture {
    fn report_start_pending(&mut self, checkpoint: u32, wait_hint_ms: u32) {
        self.reports.push((checkpoint, wait_hint_ms));
    }
}

fn self_identity() -> ProcessIdentity {
    ProcessIdentity {
        process_id: 99,
        start_time_100ns: 1234,
        image_path: r"C:\ProgramData\Eliot\eliot-watchdog.exe".to_owned(),
    }
}

fn self_matching(
    state: WatchdogRuntimeState,
    process: Option<ProcessIdentity>,
) -> WatchdogRuntimeReadback {
    WatchdogRuntimeReadback::Matching {
        state,
        process,
        checkpoint: 2,
        wait_hint_ms: 250,
    }
}

#[test]
fn self_admission_accepts_exact_starting_identity_without_start_effect() {
    let identity = self_identity();
    let mut fixture = SelfAdmissionFixture {
        current: Some(identity.clone()),
        observations: VecDeque::from([self_matching(
            WatchdogRuntimeState::Starting,
            Some(identity.clone()),
        )]),
        ..SelfAdmissionFixture::default()
    };
    let mut status = SelfAdmissionStatusFixture::default();
    let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30)
        .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
    assert_eq!(admitted, identity);
    assert!(status.reports.is_empty());
    assert!(fixture.sleeps.is_empty());
}

#[test]
fn self_admission_accepts_exact_running_identity() {
    let identity = self_identity();
    let mut fixture = SelfAdmissionFixture {
        current: Some(identity.clone()),
        observations: VecDeque::from([self_matching(
            WatchdogRuntimeState::Running,
            Some(identity.clone()),
        )]),
        ..SelfAdmissionFixture::default()
    };
    let mut status = SelfAdmissionStatusFixture::default();
    let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30)
        .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
    assert_eq!(admitted, identity);
}

#[test]
fn self_admission_rejects_exact_identity_observed_at_deadline() {
    let identity = self_identity();
    let mut fixture = SelfAdmissionFixture {
        inspect_advance_ms: 30,
        current: Some(identity.clone()),
        observations: VecDeque::from([self_matching(
            WatchdogRuntimeState::Starting,
            Some(identity),
        )]),
        ..SelfAdmissionFixture::default()
    };
    let mut status = SelfAdmissionStatusFixture::default();

    assert_eq!(
        admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30),
        Err(WatchdogSelfAdmissionError::Timeout)
    );
    assert!(status.reports.is_empty());
    assert!(fixture.sleeps.is_empty());
}

#[test]
fn self_admission_rejects_pid_reuse_and_image_substitution() {
    let identity = self_identity();
    for substituted in [
        ProcessIdentity {
            start_time_100ns: identity.start_time_100ns + 1,
            ..identity.clone()
        },
        ProcessIdentity {
            image_path: r"C:\Temp\evil.exe".to_owned(),
            ..identity.clone()
        },
    ] {
        let mut fixture = SelfAdmissionFixture {
            current: Some(identity.clone()),
            observations: VecDeque::from([self_matching(
                WatchdogRuntimeState::Starting,
                Some(substituted),
            )]),
            ..SelfAdmissionFixture::default()
        };
        let mut status = SelfAdmissionStatusFixture::default();
        assert_eq!(
            admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 30),
            Err(WatchdogSelfAdmissionError::RegistrationMismatched)
        );
    }
}

#[test]
fn self_admission_rejects_stopped_service_and_times_out_unknown() {
    let identity = self_identity();
    let mut stopped = SelfAdmissionFixture {
        current: Some(identity.clone()),
        observations: VecDeque::from([self_matching(WatchdogRuntimeState::Stopped, None)]),
        ..SelfAdmissionFixture::default()
    };
    let mut stopped_status = SelfAdmissionStatusFixture::default();
    assert_eq!(
        admit_watchdog_self_start_with_deadline(&mut stopped, &mut stopped_status, 30),
        Err(WatchdogSelfAdmissionError::ServiceStopped)
    );

    let mut unknown = SelfAdmissionFixture {
        current: Some(identity),
        ..SelfAdmissionFixture::default()
    };
    let mut unknown_status = SelfAdmissionStatusFixture::default();
    assert_eq!(
        admit_watchdog_self_start_with_deadline(&mut unknown, &mut unknown_status, 100),
        Err(WatchdogSelfAdmissionError::Timeout)
    );
    assert!(
        unknown.now_ms <= 100,
        "poll must not overshoot the deadline"
    );
    assert!(!unknown_status.reports.is_empty());
    assert!(!unknown.sleeps.is_empty());
    assert!(
        unknown_status.reports.windows(2).all(|window| {
            window[1].0 > window[0].0 && window[1].1 >= SELF_ADMISSION_MIN_POLL_MS
        })
    );
}

#[test]
fn self_admission_retries_missing_starting_identity_then_accepts() {
    let identity = self_identity();
    let mut fixture = SelfAdmissionFixture {
        current: Some(identity.clone()),
        observations: VecDeque::from([
            self_matching(WatchdogRuntimeState::Starting, None),
            self_matching(WatchdogRuntimeState::Running, Some(identity.clone())),
        ]),
        ..SelfAdmissionFixture::default()
    };
    let mut status = SelfAdmissionStatusFixture::default();
    let admitted = admit_watchdog_self_start_with_deadline(&mut fixture, &mut status, 100)
        .unwrap_or_else(|error| panic!("self-admission failed: {error}"));
    assert_eq!(admitted, identity);
    assert_eq!(status.reports.len(), 1);
    assert_eq!(fixture.sleeps.len(), 1);
}

#[test]
fn lease_gap_classification_is_typed_and_rebaseline_is_explicit() {
    assert_eq!(
        admission_gap_reason(&SpoolError::LeaseStale("expired".to_owned())),
        GapRecoveryReason::LeaseStale
    );
    assert_eq!(
        admission_gap_reason(&SpoolError::LeaseFenced("expired".to_owned())),
        GapRecoveryReason::LeaseFenced
    );
    assert_eq!(
        admission_gap_reason(&SpoolError::InvalidLease("expired".to_owned())),
        GapRecoveryReason::LeaseInvalid
    );
    assert_eq!(
        kernel_gap_reason(&KernelWatchdogError::LeaseStale),
        GapRecoveryReason::LeaseStale
    );
    assert_eq!(
        kernel_gap_reason(&KernelWatchdogError::LeaseFenced),
        GapRecoveryReason::LeaseFenced
    );

    let mut monitor = HostIdentityMonitor::new(None);
    let identity = ProcessIdentity {
        process_id: 42,
        start_time_100ns: 100,
        image_path: r"C:\ProgramData\Eliot\eliot-host.exe".to_owned(),
    };
    assert_eq!(
        monitor.observe_process_identity(identity.clone()).state,
        HostObservationState::Running
    );
    monitor.rebaseline();
    assert_eq!(
        monitor.observe_process_identity(identity).state,
        HostObservationState::Running
    );
}

#[test]
fn stale_lease_is_observation_only_and_never_current() {
    assert!(lease_window_is_current(100, 99, 101));
    assert!(!lease_window_is_current(101, 99, 101));
    assert!(!lease_window_is_current(98, 99, 101));
    assert!(
        !HostObservation {
            state: HostObservationState::AbsentOrStopped,
            identity: None,
        }
        .is_running()
    );
}

#[test]
fn host_loss_disposition_is_nonfatal_and_bounded() {
    let observation = HostObservation {
        state: HostObservationState::ImageSubstituted,
        identity: None,
    };
    let disposition = GapRecoveryDisposition {
        record_type: "watchdog_gap",
        service: SERVICE_NAME,
        observed_at_ms: 1,
        reason: observation
            .gap_reason()
            .unwrap_or(GapRecoveryReason::HostUnknown),
        coverage_claimed: false,
    };
    assert_eq!(disposition.service, SERVICE_NAME);
    assert_eq!(disposition.reason, GapRecoveryReason::HostImageSubstituted);
    assert!(!disposition.coverage_claimed);
}

struct FailingGapPort {
    calls: Arc<AtomicUsize>,
}

impl KernelWatchdogPort for FailingGapPort {
    fn supervise<'a>(
        &'a self,
        _lease: &'a VerifiedSupervisionLease,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        Box::pin(async { Err(KernelWatchdogError::Unavailable) })
    }

    fn report_gap<'a>(
        &'a self,
        _disposition: GapRecoveryDisposition,
    ) -> Pin<Box<dyn Future<Output = Result<(), KernelWatchdogError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err(KernelWatchdogError::Failed) })
    }
}

struct AlwaysInvalidAdmission;

impl WatchdogAdmissionSource for AlwaysInvalidAdmission {
    fn reload(&self) -> Result<VerifiedWatchdogAdmission, SpoolError> {
        Err(SpoolError::InvalidLease("lease expired".to_owned()))
    }
}

struct CountingHost {
    calls: Arc<AtomicUsize>,
}

impl HostObservationSource for CountingHost {
    fn observe(&self) -> HostObservation {
        self.calls.fetch_add(1, Ordering::Relaxed);
        HostObservation {
            state: HostObservationState::Running,
            identity: None,
        }
    }
}

#[tokio::test]
async fn host_loss_does_not_terminate_watchdog_when_spool_fails() {
    let calls = Arc::new(AtomicUsize::new(0));
    let port = FailingGapPort {
        calls: calls.clone(),
    };
    report_gap_nonfatal(&port, GapRecoveryReason::HostAbsentOrStopped).await;
    report_gap_nonfatal(&port, GapRecoveryReason::LeaseStale).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn production_loop_survives_lease_and_spool_failures() {
    let calls = Arc::new(AtomicUsize::new(0));
    let host_calls = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let config = WatchdogConfig {
        tick_interval: Duration::from_millis(5),
        ..WatchdogConfig::default()
    };
    let composition = WatchdogComposition::start_with_shutdown_and_host(
        config,
        Arc::new(AlwaysInvalidAdmission),
        Arc::new(FailingGapPort {
            calls: calls.clone(),
        }),
        Arc::new(CountingHost {
            calls: host_calls.clone(),
        }),
        shutdown.clone(),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let readiness = composition.readiness();
    assert_eq!(
        readiness.authority_state,
        WatchdogAuthorityState::RunningNoAuthority
    );
    assert!(!readiness.coverage_claimed);
    tokio::time::sleep(Duration::from_millis(35)).await;
    assert!(calls.load(Ordering::Relaxed) > 0);
    assert!(
        host_calls.load(Ordering::Relaxed) > 0,
        "Host observation must continue while admission is unavailable"
    );
    shutdown.store(true, Ordering::Release);
    composition
        .run_until_shutdown()
        .await
        .unwrap_or_else(|error| panic!("{error:?}"));
}
