//! Finite I8.2 sensor/capability map and per-interval observation coverage.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose), ARCH-WDG-01, ARCH-WDG-02.
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes), I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority), I1.4 (docs/architecture/I01-04-supervision-tree.md#i14-supervision-tree).
//! Issue #1755 items W1 (finite sensor/capability map) and W5 (coverage per interval and channel).
//!
//! The two concerns share one file because they are two halves of a single
//! claim. [`SENSOR_CHANNEL_MAP`] states, per I8.2 channel, the exact target and
//! `WorkScope`, the competent source, the observation classes that source can
//! support, the live/replay mechanism, the platform privilege profile, the
//! declared bound, the coverage limitation, and — from the measured runtime
//! callers of this crate — whether the channel is already wired or still a
//! missing adapter. [`IntervalCoverageReport`] then publishes what this owner
//! actually observed for one interval, per channel, and derives each
//! disposition from that map plus the samples the bounded supervision tick
//! recorded. A disposition is never supplied by a caller.
//!
//! `CONTINUOUS` is therefore reachable only for a channel the map says is
//! wired, only for the interval actually observed live, and only when every
//! class the map supports for that channel was returned. `BLIND` is the
//! measured known absence of a competent source (a missing adapter); `UNKNOWN`
//! is a channel whose competent source exists but produced no establishable
//! sample this interval; `PARTIAL` is a live sample missing a supported class.
//!
//! I8.2 names a fifth disposition, `JOURNAL_REPLAYED`, for a completely
//! replayed supported interval. It is deliberately **absent** here: this crate
//! has no journal-replay adapter — [`ObservationChannel::FilesystemJournal`] is
//! a measured missing adapter — so no value of it could ever be reached by a
//! real replay. Emitting the variant would be a fabricated coverage value, and
//! [`ChannelIntervalCoverage`] rejects a non-zero replayed observation count
//! for the same reason. A future replay adapter adds the variant together with
//! its producer, not before.
//!
//! Three dimensions stay separate by construction: the per-channel
//! [`CoverageDisposition`] is the observation mode; the spool's
//! [`crate::SpoolCoverageDenominator`] is the retained-record denominator, and
//! the fence's `full_coverage_claimed` requires **both**; the health result
//! (absent, PID reuse, image substitution, kernel gap) stays in the existing
//! `HostObservationState` / `GapRecoveryReason` path and is never folded into a
//! disposition. A live sample of an unhealthy subject is `CONTINUOUS` coverage
//! of a bad health result — which is exactly the separation I8.2 requires.
//!
//! Forbidden by construction: lifecycle effects, authority, lease or epoch
//! minting, canonical/ORS/HostStateJournal writes, database access, and any
//! claim that a channel with no competent source observed anything.

use std::sync::Mutex;

use crate::SpoolError;

/// Revision of the sensor/capability map shape itself.
///
/// A map-shape revision, not a digest and not an identity: a future change to
/// the channel set, the class set, or the record shape increments it, and a
/// fence whose retained report carries a different revision fails
/// re-validation instead of being read under the newer meaning.
pub const SENSOR_MAP_REVISION: u16 = 1;

/// One of the eleven Windows sensors I8.2 enumerates.
///
/// The set is closed on purpose: a channel that is not here is not an I8.2
/// channel, and every I8.2 channel is here whether or not this owner can
/// currently observe it. An unsupported channel is therefore a named gap in
/// the coverage denominator, never a silent exclusion from it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObservationChannel {
    /// SCM service state.
    ScmServiceState,
    /// Process handle and exit code.
    ProcessExitIdentity,
    /// Job Object membership/resource counters.
    JobResourceCounters,
    /// Named-pipe availability and handshake.
    NamedPipeHandshake,
    /// Filesystem change journal / watched paths, including persisted USN
    /// cursor replay on wake.
    FilesystemJournal,
    /// Module artifact and config hashes.
    ArtifactConfigIdentity,
    /// Host-managed `SurrealDB` process health from an independent read-only
    /// probe.
    StoreProcessHealth,
    /// Kernel heartbeat.
    KernelHeartbeat,
    /// Agent hook/bridge event cadence.
    HookEventCadence,
    /// Network/listener inventory for registered services.
    ListenerInventory,
    /// Security audit signals from OS and bridges.
    SecurityAudit,
}

impl ObservationChannel {
    /// Every I8.2 channel, in the order I8.2 lists them.
    pub const ALL: [Self; 11] = [
        Self::ScmServiceState,
        Self::ProcessExitIdentity,
        Self::JobResourceCounters,
        Self::NamedPipeHandshake,
        Self::FilesystemJournal,
        Self::ArtifactConfigIdentity,
        Self::StoreProcessHealth,
        Self::KernelHeartbeat,
        Self::HookEventCadence,
        Self::ListenerInventory,
        Self::SecurityAudit,
    ];

    /// Number of I8.2 channels, used to size the fixed per-channel state.
    pub const COUNT: usize = Self::ALL.len();

    /// Returns the stable wire name of this channel.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScmServiceState => "scm_service_state",
            Self::ProcessExitIdentity => "process_exit_identity",
            Self::JobResourceCounters => "job_resource_counters",
            Self::NamedPipeHandshake => "named_pipe_handshake",
            Self::FilesystemJournal => "filesystem_journal",
            Self::ArtifactConfigIdentity => "artifact_config_identity",
            Self::StoreProcessHealth => "store_process_health",
            Self::KernelHeartbeat => "kernel_heartbeat",
            Self::HookEventCadence => "hook_event_cadence",
            Self::ListenerInventory => "listener_inventory",
            Self::SecurityAudit => "security_audit",
        }
    }

    /// Returns the fixed-state index of this channel.
    const fn index(self) -> usize {
        match self {
            Self::ScmServiceState => 0,
            Self::ProcessExitIdentity => 1,
            Self::JobResourceCounters => 2,
            Self::NamedPipeHandshake => 3,
            Self::FilesystemJournal => 4,
            Self::ArtifactConfigIdentity => 5,
            Self::StoreProcessHealth => 6,
            Self::KernelHeartbeat => 7,
            Self::HookEventCadence => 8,
            Self::ListenerInventory => 9,
            Self::SecurityAudit => 10,
        }
    }
}

/// One observation class a competent source can support for a channel.
///
/// A class absent from a channel's `supported_classes` cannot be claimed for
/// that channel at all: the publisher only records classes the map supports,
/// and the fence re-derivation refuses a record carrying any other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClass {
    /// Current SCM service state read back from the service itself.
    ServiceState,
    /// PID plus creation time plus image path of an open process handle.
    ProcessIdentity,
    /// Retained exit code of an exited process.
    ExitIdentity,
    /// Job Object membership and resource counters.
    ResourceCounter,
    /// A pipe endpoint was reachable.
    PipePresence,
    /// The pipe peer was authenticated against an expected identity.
    AuthenticatedPeer,
    /// A watched-path change was observed.
    PathChange,
    /// A module artifact content hash.
    ArtifactDigest,
    /// A service registration/config identity readback.
    ConfigIdentity,
    /// The Kernel fence answered a live heartbeat.
    Liveness,
    /// An approved read-only store probe answered.
    ReadOnlyProbe,
    /// A bridge/hook event arrived within the declared cadence.
    EventCadence,
    /// A registered service owns a listener.
    ListenerBinding,
    /// An OS or bridge security signal was observed.
    AuditSignal,
}

impl ObservationClass {
    /// Returns the stable wire name of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceState => "service_state",
            Self::ProcessIdentity => "process_identity",
            Self::ExitIdentity => "exit_identity",
            Self::ResourceCounter => "resource_counter",
            Self::PipePresence => "pipe_presence",
            Self::AuthenticatedPeer => "authenticated_peer",
            Self::PathChange => "path_change",
            Self::ArtifactDigest => "artifact_digest",
            Self::ConfigIdentity => "config_identity",
            Self::Liveness => "liveness",
            Self::ReadOnlyProbe => "read_only_probe",
            Self::EventCadence => "event_cadence",
            Self::ListenerBinding => "listener_binding",
            Self::AuditSignal => "audit_signal",
        }
    }
}

/// How a channel's evidence reaches this owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorMechanism {
    /// A bounded read performed live by the supervision tick.
    LiveRead,
    /// A bounded page read from an OS/application journal cursor on wake.
    JournalReplay,
}

/// The Windows security profile a channel's competent source runs under.
///
/// Measured from this owner's own registration: `eliot-watchdog` is
/// installer-registered as `ServiceAccount::LocalService` (see the service
/// registration built in `lib.rs`), so every channel it observes itself runs
/// with `LocalService` rights and no `SeDebugPrivilege`. A channel whose source
/// needs more than that is declared `HostAdministrator` and is, by I1.4,
/// observed by the Host-owned owner rather than by this sibling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformPrivilegeProfile {
    /// The Watchdog's own `LocalService` profile: SCM connect/query, registry
    /// read, and its own protected root.
    WatchdogLocalService,
    /// The Host-owned administrator profile for Job Objects and for another
    /// account's process handle.
    HostAdministrator,
}

/// Declared bound on one channel's evidence inside one published interval.
///
/// The bounded supervision tick performs at most one read per channel per
/// interval, and a journal page is one bounded page per wake, so the declared
/// ceiling is one observation of the channel per interval for every channel.
/// A channel with no wired adapter observes zero and is bounded by that fact,
/// not by a larger allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBounds {
    /// Maximum observations of this channel one published interval may carry.
    pub max_observations_per_interval: u32,
}

/// Measured wiring state of one channel in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelWiring {
    /// A production runtime caller in this crate performs the read.
    Wired {
        /// The measured `path::symbol` chain that performs the read.
        runtime_caller: &'static str,
    },
    /// No production runtime caller exists in this crate.
    MissingAdapter {
        /// The measured evidence for the absence, kept verbatim.
        reason: &'static str,
    },
}

impl ChannelWiring {
    /// Returns true when a production runtime caller performs the read.
    #[must_use]
    pub const fn is_wired(self) -> bool {
        matches!(self, Self::Wired { .. })
    }
}

/// One I8.2 channel's finite capability record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelCapability {
    /// The I8.2 channel this record describes.
    pub channel: ObservationChannel,
    /// Exact target and `WorkScope` the channel is competent for.
    pub target_scope: &'static str,
    /// The source competent to observe it, by owner and port.
    pub competent_source: &'static str,
    /// Observation classes this source can support. A class not listed here is
    /// not observable for this channel and can never be claimed.
    pub supported_classes: &'static [ObservationClass],
    /// Whether the evidence arrives live or by journal replay.
    pub mechanism: SensorMechanism,
    /// The Windows security profile the source runs under.
    pub privilege_profile: PlatformPrivilegeProfile,
    /// Declared bound on this channel's evidence per interval.
    pub bounds: ChannelBounds,
    /// What this channel still cannot establish, verbatim.
    pub coverage_limitation: &'static str,
    /// Measured wiring state from this crate's actual runtime callers.
    pub wiring: ChannelWiring,
}

impl ChannelCapability {
    /// True for every I8.2 channel: each one is required for a full-coverage
    /// claim.
    ///
    /// I8.2 lists no optional sensor, and the issue forbids silently excluding
    /// an optional or unsupported channel from the denominator, so an
    /// unsupported channel is a named gap that blocks the claim instead of an
    /// omitted term.
    pub const REQUIRED_FOR_FULL_COVERAGE: bool = true;

    /// True when `class` is one this channel's source can support.
    #[must_use]
    pub fn supports(&self, class: ObservationClass) -> bool {
        self.supported_classes.contains(&class)
    }
}

/// The finite I8.2 sensor/capability map (#1755 W1).
///
/// `Wired`/`MissingAdapter` is the measured state of this crate at
/// `SENSOR_MAP_REVISION`, from `git grep` over `bins/eliot-watchdog/src` for a
/// production runtime caller of each channel's source — not a design intent.
/// Three channels are wired; the other eight are measured missing adapters and
/// are the named gaps that keep a full-coverage claim unavailable.
pub const SENSOR_CHANNEL_MAP: [ChannelCapability; ObservationChannel::COUNT] = [
    ChannelCapability {
        channel: ObservationChannel::ScmServiceState,
        target_scope: "the approved Eliot Host SCM service of the observed installation; \
             the Watchdog is a separate SCM sibling service (I1.4)",
        competent_source: "Windows SCM, read only, through \
             `eliot_platform_windows::WindowsPlatform::inspect_service_registration_runtime`",
        supported_classes: &[ObservationClass::ServiceState],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "Only the approved Host registration is read. No other ELIOT \
             service is observed, and `Starting`/`Stopping` are classified `Unknown`, never \
             absence.",
        wiring: ChannelWiring::Wired {
            runtime_caller: "watchdog_composition::WatchdogComposition::start_with_shutdown_and_host_and_heartbeat \
                 -> host_identity_observation::read_host_registration_runtime -> \
                 eliot_platform_windows::WindowsPlatform::inspect_service_registration_runtime",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::ProcessExitIdentity,
        target_scope: "the Host process behind the approved Host SCM registration; `eliotd` is a \
             Host-owned Kernel Job child, not an SCM service, and has no process owner here",
        competent_source: "the process handle identity (PID, creation time, image path) returned \
             with the SCM readback, compared against the retained approved identity by \
             `host_identity_observation::HostIdentityMonitor::observe_process_identity`",
        supported_classes: &[ObservationClass::ProcessIdentity],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "The exit code is not retained, so `ExitIdentity` is absent from the \
             supported classes and can never be claimed. No `eliotd` process identity is \
             observed by this owner.",
        wiring: ChannelWiring::Wired {
            runtime_caller: "watchdog_composition::WatchdogComposition::start_with_shutdown_and_host_and_heartbeat \
                 -> host_identity_observation::LiveHostObservationSource::observe",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::JobResourceCounters,
        target_scope: "the Host-owned Kernel Job Object and the Host-owned canonical-store Job \
             Object of the observed installation (I1.4)",
        competent_source: "the Job Object ports of `eliot-platform-windows`, opened by the \
             Host-owned Job owner",
        supported_classes: &[ObservationClass::ResourceCounter],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::HostAdministrator,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No membership or counter is observed, so this interval is blind for \
             the Job branch. The Watchdog holds no Job handle and gains none.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -n 'JobObservation\\|job_object' -- bins/eliot-watchdog/src` has no \
                 production hit; the only measured caller of the Job observation port is \
                 `eliot-host/src/host_job_launch.rs`",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::NamedPipeHandshake,
        target_scope: "the named pipes of the registered ELIOT services, including the Host \
             fence pipe this owner writes to",
        competent_source: "a named-pipe client that reads the peer process binding and \
             authenticates it, through `eliot-platform-windows` peer authentication",
        supported_classes: &[
            ObservationClass::PipePresence,
            ObservationClass::AuthenticatedPeer,
        ],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "The fence write in `heartbeat_transport` is this owner producing a \
             heartbeat, not an independent observation of a peer, and it authenticates no peer. \
             `HostIdentityMonitor::observe_identity` is the only peer-binding entry point here and \
             has no production caller.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -n 'observe_identity' -- bins/` returns only the definition at \
                 `bins/eliot-watchdog/src/host_identity_observation.rs`; the peer-authentication \
                 ports have no `eliot-watchdog` caller",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::FilesystemJournal,
        target_scope: "the registered-scope roots of the admitted Windows WorkScopes",
        competent_source: "the NTFS change journal (USN) for the volume holding each registered \
             root, read through a spool-owned cursor in `eliot-platform-windows`",
        supported_classes: &[ObservationClass::PathChange],
        mechanism: SensorMechanism::JournalReplay,
        privilege_profile: PlatformPrivilegeProfile::HostAdministrator,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No journal source, cursor, page, or replay exists in this owner, so \
             file-change coverage is blind and the replay half of I8.2's coverage vocabulary is \
             unreachable.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -rn 'USN\\|UsnJournal\\|usn_journal' -- crates/ bins/` returns no \
                 match: no USN symbol exists anywhere in the workspace, let alone a Watchdog caller",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::ArtifactConfigIdentity,
        target_scope: "the approved module artifacts and the installation configuration of the \
             observed installation",
        competent_source: "a content/identity digest of each approved artifact and configuration \
             file, read under its no-follow protected path lease",
        supported_classes: &[
            ObservationClass::ArtifactDigest,
            ObservationClass::ConfigIdentity,
        ],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "The approved Host image path identity is verified through a \
             `ProtectedPathLease`, but no artifact or configuration hash is computed or recorded, \
             so neither supported class is actually produced and this interval is blind.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -n 'sha256_hex\\|digest' -- bins/eliot-watchdog/src` finds only \
                 spool/backup and admission digests; no module artifact or installation \
                 configuration hash is produced by a runtime caller",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::StoreProcessHealth,
        target_scope: "the Host-managed SurrealDB process of the observed installation (I1.4 \
             canonical-store branch)",
        competent_source: "an approved read-only store probe independent of `eliotd`",
        supported_classes: &[ObservationClass::ReadOnlyProbe],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::HostAdministrator,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No store probe exists, so the canonical-store branch is blind. This \
             owner correctly holds no SurrealDB SDK, database credential, raw SQL, or \
             database-file access, and gains none to close this gap.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -in 'surreal' -- bins/eliot-watchdog/src` finds no store probe; the \
                 only `eliot-store-surreal` owner is `bins/eliot-store-surreal`, reached through \
                 `eliotd`",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::KernelHeartbeat,
        target_scope: "the current Kernel generation of the observed installation, over the \
             Host-issued fence",
        competent_source: "the admitted Kernel watchdog port, which records the heartbeat in this \
             owner's own `watchdog.redb` before any semantic consumer sees it",
        supported_classes: &[ObservationClass::Liveness],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "Liveness only. A live answer is never upgraded to semantic or \
             application readiness, and a refused answer is a health gap, not a coverage loss.",
        wiring: ChannelWiring::Wired {
            runtime_caller: "watchdog_composition::WatchdogComposition::start_with_shutdown_and_host_and_heartbeat \
                 -> IndependentKernelSensor::supervise -> IndependentKernelSensor::record_heartbeat",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::HookEventCadence,
        target_scope: "the agent hook/bridge event stream of the observed installation",
        competent_source: "the installed hook/bridge chain, observed as event cadence by this \
             owner without interpreting the events",
        supported_classes: &[ObservationClass::EventCadence],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No cadence sample is taken, so hook/intent coverage is blind. A \
             complete file-change replay could not close it either: file changes are event \
             evidence, not tool intent.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -n 'hook\\|bridge' -- bins/eliot-watchdog/src` finds no event-cadence \
                 reader; the hook installation chain is owned by #1758",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::ListenerInventory,
        target_scope: "the network listeners of the registered ELIOT services",
        competent_source: "the listener-ownership ports of `eliot-platform-windows`",
        supported_classes: &[ObservationClass::ListenerBinding],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No listener is inventoried, so this interval is blind.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`git grep -n 'TcpListener\\|tcp_listener' -- bins/eliot-watchdog/src` has no \
                 match; the listener ports are used by other roots only",
        },
    },
    ChannelCapability {
        channel: ObservationChannel::SecurityAudit,
        target_scope: "the OS security event stream and the bridge security signals of the \
             observed installation",
        competent_source: "the Windows event log and bridge audit signals, read independently of \
             the daemon that would report its own health",
        supported_classes: &[ObservationClass::AuditSignal],
        mechanism: SensorMechanism::LiveRead,
        privilege_profile: PlatformPrivilegeProfile::WatchdogLocalService,
        bounds: ChannelBounds {
            max_observations_per_interval: 1,
        },
        coverage_limitation: "No security signal is read. This owner's own event-log diagnostic \
             sink is a typed refusal, so the channel is blind rather than silently empty. The \
             service security-descriptor digests computed at registration are configuration, not \
             an audit signal.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "`bins/eliot-watchdog/src/diagnostics.rs` returns \
                 `WatchdogDiagnosticsError::EventLogUnavailable` for \
                 `DiagnosticSink::WindowsEventLog`, and `eliot-platform-windows`'s event-log module \
                 has no `eliot-watchdog` caller",
        },
    },
];

/// Returns the capability record of one I8.2 channel.
///
/// # Panics
///
/// Panics when `channel` is not an I8.2 channel, which the closed enum and
/// this crate's own callers make unreachable.
#[must_use]
pub fn channel_capability(channel: ObservationChannel) -> &'static ChannelCapability {
    &SENSOR_CHANNEL_MAP[channel.index()]
}

/// I8.2 observation coverage of one channel over one interval.
///
/// I8.2 names five dispositions. Four are reachable here. `JOURNAL_REPLAYED`
/// is not, and is absent by construction rather than carried as a value
/// nothing can produce: see the module documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageDisposition {
    /// The sensor observed this channel's interval live.
    Continuous,
    /// Some sources or sequence ranges of the interval are missing.
    Partial,
    /// No competent source covered the interval.
    Blind,
    /// Coverage cannot be established.
    Unknown,
}

impl CoverageDisposition {
    /// Returns the I8.2 wire name of this disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "CONTINUOUS",
            Self::Partial => "PARTIAL",
            Self::Blind => "BLIND",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One named omission that keeps a channel short of full coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageGap {
    /// The I8.2 channel the omission belongs to.
    pub channel: ObservationChannel,
    /// Bounded reason code for the omission.
    pub reason: &'static str,
}

/// Declared observation window of one published interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageInterval {
    /// Owner-clock start of the interval, in milliseconds.
    pub start_ms: u64,
    /// Owner-clock end of the interval, in milliseconds.
    pub end_ms: u64,
}

/// Published coverage of one I8.2 channel over one declared interval.
///
/// Observation mode ([`disposition`](Self::disposition)) is preserved
/// separately from the spool's retained-record denominator and from the
/// subject's health result. A live sample of an absent or degraded subject is
/// `CONTINUOUS` coverage of a bad health result; the health result stays in
/// `HostObservationState` and `GapRecoveryReason`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelIntervalCoverage {
    channel: ObservationChannel,
    expected_source: &'static str,
    expected_classes: &'static [ObservationClass],
    observed_classes: Vec<ObservationClass>,
    observed_replayed_observations: u32,
    disposition: CoverageDisposition,
    gaps: Vec<CoverageGap>,
}

impl ChannelIntervalCoverage {
    /// The I8.2 channel this record covers.
    #[must_use]
    pub const fn channel(&self) -> ObservationChannel {
        self.channel
    }

    /// The competent source I8.2 expects to cover this channel.
    #[must_use]
    pub const fn expected_source(&self) -> &'static str {
        self.expected_source
    }

    /// The observation classes the expected source must support here.
    #[must_use]
    pub const fn expected_classes(&self) -> &'static [ObservationClass] {
        self.expected_classes
    }

    /// The classes actually observed live in this interval.
    #[must_use]
    pub fn observed_classes(&self) -> &[ObservationClass] {
        &self.observed_classes
    }

    /// Portions of the interval actually covered by journal replay.
    ///
    /// Always zero in this increment: no journal-replay adapter exists, and a
    /// non-zero value is refused rather than reported.
    #[must_use]
    pub const fn observed_replayed_observations(&self) -> u32 {
        self.observed_replayed_observations
    }

    /// The observation mode of this channel over this interval.
    #[must_use]
    pub const fn disposition(&self) -> CoverageDisposition {
        self.disposition
    }

    /// The named omissions that keep this channel short of full coverage.
    #[must_use]
    pub fn gaps(&self) -> &[CoverageGap] {
        &self.gaps
    }

    /// Derives the disposition this record must carry.
    ///
    /// This is the single rule the publisher and the fence re-validation share,
    /// so a record whose stored disposition disagrees with its own samples and
    /// the map is corrupt rather than a stronger claim.
    fn derive_disposition(
        capability: &ChannelCapability,
        observed: &[ObservationClass],
        observed_replayed: u32,
    ) -> (CoverageDisposition, Vec<CoverageGap>) {
        let mut gaps = Vec::new();
        if observed_replayed > 0 {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "REPLAYED_WITHOUT_ADAPTER",
            });
            return (CoverageDisposition::Unknown, gaps);
        }
        if !capability.wiring.is_wired() {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "NO_COMPETENT_SOURCE",
            });
            return (CoverageDisposition::Blind, gaps);
        }
        if observed.is_empty() {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "NO_ESTABLISHABLE_SAMPLE",
            });
            return (CoverageDisposition::Unknown, gaps);
        }
        if observed.len() < capability.supported_classes.len() {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "SUPPORTED_CLASS_MISSING",
            });
            return (CoverageDisposition::Partial, gaps);
        }
        (CoverageDisposition::Continuous, gaps)
    }
}

/// Published per-channel coverage of one interval, aggregated across channels.
///
/// [`full_coverage_claimed`](Self::full_coverage_claimed) is a conjunction over
/// every I8.2 channel, not a maximum and not a per-channel verdict: one good
/// channel cannot erase another channel's blind interval, because a single
/// non-`CONTINUOUS` record makes the whole conjunction false and its channel
/// appears in [`blocking_channels`](Self::blocking_channels).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntervalCoverageReport {
    sensor_map_revision: u16,
    interval: CoverageInterval,
    records: Vec<ChannelIntervalCoverage>,
}

impl IntervalCoverageReport {
    /// Publishes the coverage of `interval` for every I8.2 channel.
    ///
    /// `observed` is indexed by [`ObservationChannel`] order and holds the
    /// classes the bounded tick recorded live for that channel. The record set
    /// is always exactly one record per I8.2 channel, in map order, so an
    /// unobserved channel is a named gap rather than a missing term.
    #[must_use]
    pub fn publish(
        interval: CoverageInterval,
        observed: &[Vec<ObservationClass>; ObservationChannel::COUNT],
    ) -> Self {
        let records = SENSOR_CHANNEL_MAP
            .iter()
            .map(|capability| {
                let classes = &observed[capability.channel.index()];
                let (disposition, gaps) =
                    ChannelIntervalCoverage::derive_disposition(capability, classes, 0);
                ChannelIntervalCoverage {
                    channel: capability.channel,
                    expected_source: capability.competent_source,
                    expected_classes: capability.supported_classes,
                    observed_classes: classes.clone(),
                    observed_replayed_observations: 0,
                    disposition,
                    gaps,
                }
            })
            .collect();
        Self {
            sensor_map_revision: SENSOR_MAP_REVISION,
            interval,
            records,
        }
    }

    /// The declared observation window this report covers.
    #[must_use]
    pub const fn interval(&self) -> CoverageInterval {
        self.interval
    }

    /// The sensor map revision these dispositions were derived under.
    #[must_use]
    pub const fn sensor_map_revision(&self) -> u16 {
        self.sensor_map_revision
    }

    /// The per-channel records, in I8.2 map order.
    #[must_use]
    pub fn records(&self) -> &[ChannelIntervalCoverage] {
        &self.records
    }

    /// Returns the record of one channel.
    ///
    /// # Panics
    ///
    /// Panics when `channel` is not an I8.2 channel.
    #[must_use]
    pub fn record(&self, channel: ObservationChannel) -> &ChannelIntervalCoverage {
        &self.records[channel.index()]
    }

    /// The channels that keep this interval short of full coverage.
    #[must_use]
    pub fn blocking_channels(&self) -> Vec<ObservationChannel> {
        self.records
            .iter()
            .filter(|record| {
                ChannelCapability::REQUIRED_FOR_FULL_COVERAGE
                    && record.disposition != CoverageDisposition::Continuous
            })
            .map(|record| record.channel)
            .collect()
    }

    /// Whether this interval may be published as fully covered.
    ///
    /// The conjunction is over **all** I8.2 channels, because every channel is
    /// required. There is no `any` term, no early exit that skips an
    /// unexamined channel, and no per-channel shortcut: a report whose
    /// `Host` and `Kernel` records are both `CONTINUOUS` still returns `false`
    /// while any of the eight measured missing adapters is `BLIND`. `false` is
    /// also returned when no interval has been observed at all, because the
    /// report itself is then absent rather than empty-and-complete.
    #[must_use]
    pub fn full_coverage_claimed(&self) -> bool {
        self.valid() && self.blocking_channels().is_empty()
    }

    /// True when the report is internally consistent.
    ///
    /// Re-derives every record from the map and the record's own samples, so a
    /// stored disposition that disagrees with its evidence is not valid.
    #[must_use]
    pub fn valid(&self) -> bool {
        if self.sensor_map_revision != SENSOR_MAP_REVISION
            || self.records.len() != ObservationChannel::COUNT
            || self.interval.end_ms < self.interval.start_ms
        {
            return false;
        }
        self.records.iter().enumerate().all(|(index, record)| {
            if record.channel != ObservationChannel::ALL[index] {
                return false;
            }
            let capability = channel_capability(record.channel);
            if record.observed_replayed_observations
                > capability.bounds.max_observations_per_interval
                || record.observed_classes.len()
                    > capability.bounds.max_observations_per_interval as usize
                || record
                    .observed_classes
                    .iter()
                    .any(|class| !capability.supports(*class))
            {
                return false;
            }
            let (disposition, gaps) = ChannelIntervalCoverage::derive_disposition(
                capability,
                &record.observed_classes,
                record.observed_replayed_observations,
            );
            record.disposition == disposition && record.gaps == gaps
        })
    }

    /// Re-validates the report, returning the fence owner's typed refusal.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the report is not internally
    /// consistent, so a fence can never hand a reader a channel coverage whose
    /// disposition was not derived from the evidence it carries.
    pub fn validate(&self) -> Result<(), SpoolError> {
        if self.valid() {
            Ok(())
        } else {
            Err(SpoolError::Corrupt(
                "watchdog observation coverage report is not consistent with the sensor map and its own observed classes"
                    .to_owned(),
            ))
        }
    }
}

/// Accumulates one open interval's live samples, per channel.
#[derive(Clone, Debug)]
pub struct IntervalCoveragePublisher {
    start_ms: u64,
    observed: [Vec<ObservationClass>; ObservationChannel::COUNT],
}

impl IntervalCoveragePublisher {
    /// Opens an interval that starts at the owner clock reading `start_ms`.
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            start_ms,
            observed: std::array::from_fn(|_| Vec::new()),
        }
    }

    /// Records one live observation class for one channel.
    ///
    /// A class the map does not support for that channel is not recorded: it
    /// cannot be claimed, so accepting it would let a sample inflate a
    /// disposition it never earned. Recording the same class twice in one
    /// interval is likewise ignored, which is what keeps the observation count
    /// inside the channel's declared bound.
    pub fn record(&mut self, channel: ObservationChannel, class: ObservationClass) {
        let capability = channel_capability(channel);
        if !capability.supports(class) {
            return;
        }
        let classes = &mut self.observed[channel.index()];
        if classes.contains(&class)
            || classes.len() >= capability.bounds.max_observations_per_interval as usize
        {
            return;
        }
        classes.push(class);
    }

    /// Closes the open interval and starts the next one at `end_ms`.
    #[must_use]
    pub fn close(self, end_ms: u64) -> IntervalCoverageReport {
        let interval = CoverageInterval {
            start_ms: self.start_ms,
            end_ms,
        };
        IntervalCoverageReport::publish(interval, &self.observed)
    }
}

/// One closed interval plus whether its blocking channel set changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntervalCoveragePublication {
    report: IntervalCoverageReport,
    blocking_changed: bool,
}

impl IntervalCoveragePublication {
    /// The closed interval's coverage report.
    #[must_use]
    pub const fn report(&self) -> &IntervalCoverageReport {
        &self.report
    }

    /// True when the set of channels blocking full coverage changed.
    ///
    /// Bounded-volume operator evidence: the blind set is a measured property
    /// of this build, so it is reported when it changes rather than on every
    /// tick.
    #[must_use]
    pub const fn blocking_changed(&self) -> bool {
        self.blocking_changed
    }
}

#[derive(Debug)]
struct IntervalCoverageState {
    publisher: IntervalCoveragePublisher,
    published: Option<IntervalCoverageReport>,
    last_blocking: Vec<ObservationChannel>,
}

/// The one shared per-interval coverage cell of this owner.
///
/// One cell is created with the owner-bound backup port and shared by the
/// bounded supervision tick and the fence capture path, so the coverage a
/// capture carries is the coverage the same owner actually published. A
/// poisoned lock never fabricates coverage: recording, closing, and reading all
/// degrade to "no coverage established", which the aggregation reports as
/// unknown rather than as complete.
#[derive(Debug)]
pub struct IntervalCoverageCell {
    state: Mutex<IntervalCoverageState>,
}

impl IntervalCoverageCell {
    /// Opens the cell with an interval that starts at `start_ms`.
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            state: Mutex::new(IntervalCoverageState {
                publisher: IntervalCoveragePublisher::new(start_ms),
                published: None,
                last_blocking: Vec::new(),
            }),
        }
    }

    /// Records one live observation class for one channel.
    pub fn record(&self, channel: ObservationChannel, class: ObservationClass) {
        if let Ok(mut state) = self.state.lock() {
            state.publisher.record(channel, class);
        }
    }

    /// Closes the open interval at `end_ms` and opens the next one there.
    ///
    /// Returns `None` only when the cell's lock is poisoned, which is the
    /// "coverage cannot be established" outcome and never a full-coverage
    /// claim.
    pub fn close_interval(&self, end_ms: u64) -> Option<IntervalCoveragePublication> {
        let mut state = self.state.lock().ok()?;
        let publisher =
            std::mem::replace(&mut state.publisher, IntervalCoveragePublisher::new(end_ms));
        let report = publisher.close(end_ms);
        let blocking = report.blocking_channels();
        let blocking_changed = blocking != state.last_blocking;
        state.last_blocking = blocking;
        state.published = Some(report.clone());
        Some(IntervalCoveragePublication {
            report,
            blocking_changed,
        })
    }

    /// The most recently closed interval's report, if one has been closed.
    #[must_use]
    pub fn latest(&self) -> Option<IntervalCoverageReport> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.published.clone())
    }
}
