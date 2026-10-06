//! Finite I8.2 sensor/capability map and per-interval observation coverage.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose), ARCH-WDG-01, ARCH-WDG-02.
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes), I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority), I1.4 (docs/architecture/I01-04-supervision-tree.md#i14-supervision-tree).
//! Issue #1755 items W1 (finite sensor/capability map) and W5 (coverage per interval and channel).
//!
//! The two concerns share one file because they are two halves of a single
//! claim. [`SENSOR_CHANNEL_MAP`] states, per I8.2 channel, the exact target and
//! `WorkScope`, the competent source, the observation classes that source can
//! support, the live/replay mechanism, the platform privilege profile, the bound
//! on that channel's live evidence inside one published interval (which is
//! derived from those same classes rather than chosen beside them), the coverage
//! limitation, and — from the measured runtime
//! callers of this crate — whether the channel is already wired or still a
//! missing adapter. [`IntervalCoverageReport`] then publishes what this owner
//! actually observed for one interval, per channel, and derives each
//! disposition from that map plus the samples the bounded supervision tick
//! recorded. A disposition is never supplied by a caller.
//!
//! `CONTINUOUS` is therefore reachable only for a channel the map says is
//! wired, only for an interval that reached its own close, and only when every
//! class the map supports for that channel was returned and none of this
//! owner's offers for it had to be dropped. `BLIND` is the measured known
//! absence of a competent source (a missing adapter); `UNKNOWN` is a wired
//! channel whose coverage of the interval cannot be established, either because
//! it produced no establishable sample or because the interval it belongs to
//! never closed; `PARTIAL` is a wired channel with an establishable live sample
//! that does not account for its whole supported class set, because a supported
//! class was not returned or because a repeat of a class the interval already
//! held had to be dropped.
//!
//! One published interval is exactly one supervision tick, opened at the top of
//! the tick and closed when that tick body ends, on the ordinary fall-through
//! and on each `continue` alike, so a sample is never carried across a window
//! it did not cover and an ordinary degraded tick still publishes the evidence
//! it did observe. A window that is still open when the next tick opens its own
//! can only be one whose close did not take effect — a poisoned cell, or a tick
//! that did not finish — and it is not silently replaced:
//! [`IntervalCoverageCell::begin_interval`] publishes it as a named
//! `INTERVAL_NOT_CLOSED` omission. Such a tick is therefore a recorded gap,
//! never a silently discarded publisher and never a reset interval reported as
//! full coverage.
//!
//! I8.2 names a fifth disposition, `JOURNAL_REPLAYED`, for a completely
//! replayed supported interval. It is reachable only through
//! [`IntervalCoveragePublisher::record_replayed`] with exact
//! [`JournalReplayEvidence`] from the journal-replay adapter (W3): the replay
//! covers a contiguous cursor window no live sample covered, so it substitutes
//! a missing live source rather than upgrading one. A replayed window without
//! evidence, or evidence without the replay disposition, is refused at every
//! layer — publisher seam, fence re-validation, and shared contract alike.
//!
//! Three dimensions stay separate by construction: the per-channel
//! [`CoverageDisposition`] is the observation mode; the spool's
//! [`crate::SpoolCoverageDenominator`] is the retained-record denominator, and
//! `WatchdogComposition::readiness` claims coverage only when a closed
//! interval has every channel `CONTINUOUS` or `JOURNAL_REPLAYED`; the health result
//! (absent, PID reuse, image substitution, kernel gap) stays in the existing
//! `HostObservationState` / `GapRecoveryReason` path and is never folded into a
//! disposition. A live sample of an unhealthy subject is `CONTINUOUS` coverage
//! of a bad health result — which is exactly the separation I8.2 requires.
//!
//! Forbidden by construction: lifecycle effects, authority, lease or epoch
//! minting, canonical/ORS/HostStateJournal writes, database access, and any
//! claim that a channel with no competent source observed anything.

use std::sync::Mutex;

use eliot_evaluation_contracts::JournalReplayEvidence;

use crate::SpoolError;

/// Revision of the sensor/capability map shape itself.
///
/// A map-shape revision, not a digest and not an identity: a future change to
/// the channel set, the class set, or the record shape increments it, and
/// [`IntervalCoverageReport::valid`] refuses a report stamped with any other
/// value. It is an in-memory stamp on a report this process just derived: the
/// report has no serialization and no retained or on-disk form, so no artifact,
/// fence, or later reader ever loads an older revision. It is not a guard over a
/// persisted one, and it is deliberately not a digest — there is nothing here to
/// hash and no original recorded value to compare a hash against.
pub const SENSOR_MAP_REVISION: u16 = 2;

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
/// and the fence re-derivation refuses a record carrying any other. A class this
/// owner has no source for is absent from the vocabulary entirely rather than
/// carried as a value nothing can produce: I8.2's process **exit code** has no
/// retained source in this owner (the channel below observes process identity
/// only), so there is no exit-identity class to carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationClass {
    /// Current SCM service state read back from the service itself.
    ServiceState,
    /// PID plus creation time plus image path of an open process handle.
    ProcessIdentity,
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
    /// The Kernel fence read was accepted and the Watchdog recorded the
    /// heartbeat in its own spool.
    ///
    /// Nothing on the far side "answers" this: the source appends a heartbeat
    /// record to the Watchdog's own physically separate spool, and the
    /// acceptance this class reports is that append, not a reply from the
    /// Kernel. A refused append is not this class at all.
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
    /// What this channel still cannot establish, verbatim.
    pub coverage_limitation: &'static str,
    /// Measured wiring state from this crate's actual runtime callers.
    pub wiring: ChannelWiring,
}

impl ChannelCapability {
    /// The bound on this channel's live evidence inside one published
    /// interval.
    ///
    /// Not a chosen number, and deliberately not a per-channel budget: it is
    /// exactly `supported_classes.len()`. One published interval is exactly
    /// one tick of the owner's existing `WatchdogConfig::tick_interval`
    /// cadence, the tick performs at most one read per channel, and a channel
    /// contributes precisely the classes that one read returned. That is where
    /// the observation **rate** is bounded, and it is a rate, not a class
    /// budget — so no class the read did return is ever dropped for being over
    /// budget, and a channel can reach `CONTINUOUS` as soon as its adapter
    /// lands. A budget chosen independently here would silently discard evidence
    /// and would keep binding after the adapter it excludes exists.
    #[must_use]
    pub const fn max_observations_per_interval(&self) -> usize {
        self.supported_classes.len()
    }

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
/// Four channels are wired; the other seven are measured missing adapters and
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
        coverage_limitation: "The exit code is not retained by any source in this owner, so no \
             exit-identity observation class exists here to support and exit identity can never \
             be claimed. No `eliotd` process identity is observed by this owner.",
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
        coverage_limitation: "The approved Host image digest is read live through the retained \
             no-follow lease (bounded, identity-verified before and after the read; bytes \
             hashed, never retained), but no installation configuration identity is read, so \
             only ArtifactDigest is produced and this channel is PARTIAL, never CONTINUOUS, \
             until a config-identity probe lands.",
        wiring: ChannelWiring::Wired {
            runtime_caller: "watchdog_composition::WatchdogComposition::start_with_shutdown_and_host_and_heartbeat \
                 -> HostObservationSource::observe_approved_artifact -> \
                 host_identity_observation::HostIdentityMonitor::observe_approved_artifact -> \
                 independent_sensor::observe_approved_artifact_digest -> \
                 ProtectedPathLease::read_bounded",
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
        coverage_limitation: "No store probe exists, so the canonical-store branch is blind. This \
             owner correctly holds no SurrealDB SDK, database credential, raw SQL, or \
             database-file access, and gains none to close this gap.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "the probe call chain is live (`HostObservationSource::observe_store_endpoint` \
                 -> `store_endpoint_observation::observe_store_endpoint` -> \
                 `observe_loopback_tcp_listener_owner`, exercised every tick and by unit tests), \
                 but binding the owner PID to a handle identity needs a safe PID-to-identity \
                 wrapper that only `eliot-platform-windows` may own; this crate forbids \
                 `unsafe_code`",
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
        coverage_limitation: "No listener is inventoried, so this interval is blind.",
        wiring: ChannelWiring::MissingAdapter {
            reason: "the store-listener probe call chain is live (see the `StoreProcessHealth` \
                 entry), but the owner-PID-to-identity binding it needs is the same missing \
                 `eliot-platform-windows` surface; other registered service listeners have no \
                 owner-held endpoint yet",
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
/// I8.2 names five dispositions. Four are reachable from live samples;
/// `JOURNAL_REPLAYED` is reachable only through [`IntervalCoveragePublisher::record_replayed`]
/// with exact [`JournalReplayEvidence`] from the journal-replay adapter (W3):
/// the replay covers a contiguous cursor window no live sample covered, so it
/// substitutes a missing live source rather than upgrading one.
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
    /// The interval is covered by an exact journal-replay window.
    JournalReplayed,
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
            Self::JournalReplayed => "JOURNAL_REPLAYED",
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
    replayed_evidence: Option<JournalReplayEvidence>,
    dropped_samples: u32,
    /// Whether the tick that opened this interval reached its close.
    ///
    /// The samples in an unclosed interval really were taken live inside its
    /// window, but the window never got an end of its own, so nothing here can
    /// be a claim about a declared interval.
    interval_closed: bool,
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
    /// Always zero until the journal-replay adapter (W3) reports a replayed
    /// window through [`IntervalCoveragePublisher::record_replayed`]; the
    /// count then equals the evidence window length exactly.
    #[must_use]
    pub const fn observed_replayed_observations(&self) -> u32 {
        self.observed_replayed_observations
    }

    /// Exact journal-replay evidence for this record, if the adapter reported
    /// a replayed window.
    #[must_use]
    pub fn replayed_evidence(&self) -> Option<&JournalReplayEvidence> {
        self.replayed_evidence.as_ref()
    }

    /// Live samples this owner offered for this channel and then dropped
    /// because the interval already held them.
    ///
    /// Never silently zero when something was dropped: a non-zero value forces
    /// a named gap and a disposition below `CONTINUOUS`, so discarded evidence
    /// is visible in the publication instead of vanishing.
    #[must_use]
    pub const fn dropped_samples(&self) -> u32 {
        self.dropped_samples
    }

    /// Whether the supervision tick that opened this interval reached its close.
    ///
    /// `false` for an interval a tick opened and did not finish: the samples in
    /// it are real but the window has no declared end, so this record names
    /// `INTERVAL_NOT_CLOSED` and is `UNKNOWN` rather than coverage of anything.
    #[must_use]
    pub const fn interval_closed(&self) -> bool {
        self.interval_closed
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
    /// so a record whose stored disposition disagrees with its own samples, its
    /// own interval-close state, and the map is corrupt rather than a stronger
    /// claim. A replayed window substitutes a missing live source — including
    /// on an unwired channel, which is exactly what a replay is for — but
    /// never upgrades a live observation and never covers an unclosed window.
    fn derive_disposition(
        capability: &ChannelCapability,
        observed: &[ObservationClass],
        replayed: Option<&JournalReplayEvidence>,
        dropped_samples: u32,
        interval_closed: bool,
    ) -> (CoverageDisposition, Vec<CoverageGap>) {
        let mut gaps = Vec::new();
        if replayed.is_some() {
            if !interval_closed {
                gaps.push(CoverageGap {
                    channel: capability.channel,
                    reason: "INTERVAL_NOT_CLOSED",
                });
                return (CoverageDisposition::Unknown, gaps);
            }
            return (CoverageDisposition::JournalReplayed, gaps);
        }
        if !capability.wiring.is_wired() {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "NO_COMPETENT_SOURCE",
            });
            return (CoverageDisposition::Blind, gaps);
        }
        // A blind channel keeps its measured truth above; for a wired one, an
        // interval the tick never closed is checked before its samples, because
        // the samples are only evidence of a window that never got a declared
        // end. `end_ms` here is the instant the next tick observed the
        // omission, not a close the abandoned tick performed.
        if !interval_closed {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "INTERVAL_NOT_CLOSED",
            });
            return (CoverageDisposition::Unknown, gaps);
        }
        if observed.is_empty() {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "NO_ESTABLISHABLE_SAMPLE",
            });
            return (CoverageDisposition::Unknown, gaps);
        }
        if dropped_samples > 0 {
            gaps.push(CoverageGap {
                channel: capability.channel,
                reason: "SAMPLE_DROPPED",
            });
            return (CoverageDisposition::Partial, gaps);
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
    /// classes the bounded tick recorded live for that channel;
    /// `dropped_samples` is indexed the same way and counts the offers that
    /// channel lost. `replayed` is indexed the same way and carries the exact
    /// journal-replay evidence the replay adapter reported for that channel, if
    /// any. `interval_closed` is `false` for a window a tick opened and
    /// did not finish; that window is reported as a named omission on every
    /// wired channel instead of being discarded. The record set is always
    /// exactly one record per I8.2 channel, in map order, so an unobserved
    /// channel is a named gap rather than a missing term.
    #[must_use]
    pub fn publish(
        interval: CoverageInterval,
        observed: &[Vec<ObservationClass>; ObservationChannel::COUNT],
        dropped_samples: &[u32; ObservationChannel::COUNT],
        replayed: &[Option<JournalReplayEvidence>; ObservationChannel::COUNT],
        interval_closed: bool,
    ) -> Self {
        let records = SENSOR_CHANNEL_MAP
            .iter()
            .map(|capability| {
                let index = capability.channel.index();
                let classes = &observed[index];
                let dropped = dropped_samples[index];
                let evidence = &replayed[index];
                let (disposition, gaps) = ChannelIntervalCoverage::derive_disposition(
                    capability,
                    classes,
                    evidence.as_ref(),
                    dropped,
                    interval_closed,
                );
                ChannelIntervalCoverage {
                    channel: capability.channel,
                    expected_source: capability.competent_source,
                    expected_classes: capability.supported_classes,
                    observed_classes: classes.clone(),
                    observed_replayed_observations: evidence.as_ref().map_or(0, |window| {
                        u32::try_from(window.window_len()).unwrap_or(u32::MAX)
                    }),
                    replayed_evidence: evidence.clone(),
                    dropped_samples: dropped,
                    interval_closed,
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

    /// The channels that keep this interval short of full coverage.
    ///
    /// A replay-covered channel does not block: its evidence window is the
    /// coverage, named in the record, so a replayed interval is fully covered
    /// without pretending the samples were live.
    #[must_use]
    pub fn blocking_channels(&self) -> Vec<ObservationChannel> {
        self.records
            .iter()
            .filter(|record| {
                ChannelCapability::REQUIRED_FOR_FULL_COVERAGE
                    && record.disposition != CoverageDisposition::Continuous
                    && record.disposition != CoverageDisposition::JournalReplayed
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
    /// while any of the seven measured missing adapters is `BLIND`. `false` is
    /// also returned when no interval has been observed at all, because the
    /// report itself is then absent rather than empty-and-complete.
    #[must_use]
    pub fn full_coverage_claimed(&self) -> bool {
        self.valid() && self.blocking_channels().is_empty()
    }

    /// True when the report is internally consistent.
    ///
    /// Re-derives every record from the map, the record's own samples, and the
    /// record's own interval-close state, so a stored disposition that
    /// disagrees with its evidence is not valid.
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
            // Every recorded class must be one the map supports, and no class
            // may appear twice: a duplicate is the one thing a record set can
            // carry that the tick never produced, and `SAMPLE_DROPPED` is how
            // a dropped offer is accounted for instead.
            if record
                .observed_classes
                .iter()
                .enumerate()
                .any(|(index, class)| {
                    !capability.supports(*class) || record.observed_classes[..index].contains(class)
                })
            {
                return false;
            }
            let (disposition, gaps) = ChannelIntervalCoverage::derive_disposition(
                capability,
                &record.observed_classes,
                record.replayed_evidence.as_ref(),
                record.dropped_samples,
                record.interval_closed,
            );
            record.disposition == disposition
                && record.gaps == gaps
                && record.observed_replayed_observations
                    == record.replayed_evidence.as_ref().map_or(0, |window| {
                        u32::try_from(window.window_len()).unwrap_or(u32::MAX)
                    })
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

/// What one offered live sample did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOutcome {
    /// The class was recorded for this channel in this interval.
    Recorded,
    /// The class was already recorded in this interval, so the repeat was
    /// dropped. The channel's record carries a `SAMPLE_DROPPED` gap and cannot
    /// reach `CONTINUOUS`.
    DroppedDuplicate,
    /// The map does not support this class for this channel, so the offer is
    /// not evidence for this channel and was not recorded.
    UnsupportedClass,
    /// The offer was not kept: no interval was open to record it into, or the
    /// cell's lock is poisoned. Neither cause leaves a window that could hold
    /// it, so nothing about the channel is claimed.
    NotRecorded,
}

impl RecordOutcome {
    /// Returns the stable wire name of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::DroppedDuplicate => "dropped_duplicate",
            Self::UnsupportedClass => "unsupported_class",
            Self::NotRecorded => "not_recorded",
        }
    }
}

/// Accumulates one open interval's live samples, per channel.
///
/// One publisher holds exactly one supervision tick. The cell opens a fresh
/// publisher at the start of every tick and closes it when that tick body ends,
/// so a sample can never be carried across a window it did not cover; a window
/// whose close did not take effect is handed to
/// [`record_unclosed`](Self::record_unclosed) instead of being dropped.
#[derive(Clone, Debug)]
pub struct IntervalCoveragePublisher {
    start_ms: u64,
    observed: [Vec<ObservationClass>; ObservationChannel::COUNT],
    dropped_samples: [u32; ObservationChannel::COUNT],
    replayed: [Option<JournalReplayEvidence>; ObservationChannel::COUNT],
}

impl IntervalCoveragePublisher {
    /// Opens an interval that starts at the owner clock reading `start_ms`.
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            start_ms,
            observed: std::array::from_fn(|_| Vec::new()),
            dropped_samples: [0; ObservationChannel::COUNT],
            replayed: std::array::from_fn(|_| None),
        }
    }

    /// Records one offered live observation class for one channel.
    ///
    /// A class the map does not support for this channel is not recorded: it
    /// cannot be claimed, so accepting it would let a sample inflate a
    /// disposition it never earned. A repeat of a class the interval already
    /// holds is dropped, and the drop is counted so the published record
    /// carries a `SAMPLE_DROPPED` gap — evidence that was discarded leaves a
    /// named gap rather than vanishing. The bound is
    /// [`ChannelCapability::max_observations_per_interval`], which is the
    /// channel's own `supported_classes` length, so no class the read returned
    /// is ever dropped for being over budget.
    pub fn record(
        &mut self,
        channel: ObservationChannel,
        class: ObservationClass,
    ) -> RecordOutcome {
        let capability = channel_capability(channel);
        if !capability.supports(class) {
            return RecordOutcome::UnsupportedClass;
        }
        let index = channel.index();
        let classes = &mut self.observed[index];
        if classes.contains(&class) || classes.len() >= capability.max_observations_per_interval() {
            self.dropped_samples[index] = self.dropped_samples[index].saturating_add(1);
            return RecordOutcome::DroppedDuplicate;
        }
        classes.push(class);
        RecordOutcome::Recorded
    }

    /// Records one journal-replay window the replay adapter (W3) reported for
    /// one channel.
    ///
    /// The bound is one exact window per channel per interval: a second window
    /// is refused without touching the first, because two windows are two
    /// claims about the same interval and the record can only carry the one
    /// the adapter stands behind. Malformed evidence and windows that cannot
    /// fit the projected count are refused the same way. Every refusal is
    /// traced; `dropped_samples` is untouched because a refused replay is an
    /// adapter-shape refusal, not dropped live evidence.
    pub fn record_replayed(
        &mut self,
        channel: ObservationChannel,
        evidence: JournalReplayEvidence,
    ) -> RecordOutcome {
        let index = channel.index();
        if evidence.validate().is_err()
            || u32::try_from(evidence.window_len()).is_err()
            || self.replayed[index].is_some()
        {
            tracing::debug!(
                event = "watchdog.observation_coverage_replay_not_kept",
                observation = "not_kept",
                channel = channel.as_str(),
                "offered journal-replay window was not kept as evidence for this channel",
            );
            return RecordOutcome::DroppedDuplicate;
        }
        self.replayed[index] = Some(evidence);
        RecordOutcome::Recorded
    }

    /// Closes this interval at `end_ms` by the tick that observed it.
    #[must_use]
    pub fn close(self, end_ms: u64) -> IntervalCoverageReport {
        self.publish_at(end_ms, true)
    }

    /// Records this interval as one no tick ever closed, observed at `end_ms`.
    ///
    /// The samples in it were really taken live inside its window, but nothing
    /// declared an end for it — the cell's lock was poisoned, or a tick did not
    /// finish — so `end_ms` is only the instant a later tick saw the omission,
    /// not a close a tick performed. Every wired channel therefore carries
    /// `INTERVAL_NOT_CLOSED` and none of them is `CONTINUOUS`: an interval that
    /// was not closed is a named omission, never coverage, and it is published
    /// rather than discarded.
    #[must_use]
    pub fn record_unclosed(self, end_ms: u64) -> IntervalCoverageReport {
        self.publish_at(end_ms, false)
    }

    /// Derives this interval's report at `end_ms` with the close state its
    /// disposition must reflect.
    fn publish_at(self, end_ms: u64, interval_closed: bool) -> IntervalCoverageReport {
        let interval = CoverageInterval {
            start_ms: self.start_ms,
            end_ms,
        };
        IntervalCoverageReport::publish(
            interval,
            &self.observed,
            &self.dropped_samples,
            &self.replayed,
            interval_closed,
        )
    }
}

/// One finished coverage interval plus whether its blocking channel set changed.
///
/// "Finished" is not the same as "closed": an interval no tick closed is
/// published through this type too, carrying `INTERVAL_NOT_CLOSED` on every
/// wired channel. That omission is exceptional and is emitted every time it
/// happens, so an unfinished tick reaches the operator on the tick it occurred
/// rather than only when the blocking set happens to move.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntervalCoveragePublication {
    report: IntervalCoverageReport,
    blocking_changed: bool,
}

impl IntervalCoveragePublication {
    /// This finished interval's coverage report.
    #[must_use]
    pub const fn report(&self) -> &IntervalCoverageReport {
        &self.report
    }

    /// True when the set of channels blocking full coverage changed.
    ///
    /// Bounded-volume operator evidence for a **closed** interval: the blind set
    /// is a measured property of this build, so a steady set is reported when
    /// it changes rather than on every tick. It is deliberately not a gate on an
    /// interval that was never closed — an unclosed window is emitted whatever
    /// this returns, because the omission is the exceptional event and is not
    /// per-tick noise.
    #[must_use]
    pub const fn blocking_changed(&self) -> bool {
        self.blocking_changed
    }
}

#[derive(Debug)]
struct IntervalCoverageState {
    /// The interval the next offer of evidence belongs to.
    ///
    /// Replaced by [`IntervalCoverageCell::begin_interval`] and consumed by
    /// [`IntervalCoverageCell::close_interval`], so it is only ever one
    /// supervision tick's window and never an accumulating buffer.
    publisher: IntervalCoveragePublisher,
    /// Whether a supervision tick's interval is open in `publisher`.
    ///
    /// `false` before the first [`IntervalCoverageCell::begin_interval`] and
    /// after a close, which is what lets `begin_interval` tell a window nobody
    /// opened apart from one whose tick did not reach its close.
    interval_open: bool,
    published: Option<IntervalCoverageReport>,
    last_blocking: Vec<ObservationChannel>,
}

impl IntervalCoverageState {
    /// Records one finished interval's report against the blocking set this
    /// owner reports changes of, and reports whether that set changed.
    fn record_publication(
        &mut self,
        report: IntervalCoverageReport,
    ) -> IntervalCoveragePublication {
        let blocking = report.blocking_channels();
        let blocking_changed = blocking != self.last_blocking;
        self.last_blocking = blocking;
        IntervalCoveragePublication {
            report,
            blocking_changed,
        }
    }
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
    /// Opens the cell before any supervision tick has run.
    ///
    /// `start_ms` is the owner clock at construction and seeds the parked
    /// interval only. The cell establishes no coverage here and refuses every
    /// offer of evidence until the first [`begin_interval`](Self::begin_interval)
    /// opens a real tick interval.
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            state: Mutex::new(IntervalCoverageState {
                publisher: IntervalCoveragePublisher::new(start_ms),
                interval_open: false,
                published: None,
                last_blocking: Vec::new(),
            }),
        }
    }

    /// Opens the interval for one supervision tick at `start_ms`.
    ///
    /// The tick body closes the previous interval on every one of its exit
    /// paths, so a publisher still open here means that close did not take
    /// effect — a poisoned cell, or a tick that did not finish. That window is
    /// not silently replaced: it is turned into a report carrying
    /// `INTERVAL_NOT_CLOSED` on every wired channel and returned, so the caller
    /// publishes the omission instead of dropping the interval. `None` means the
    /// previous interval was closed, or no tick had opened one, or the cell's
    /// lock is poisoned.
    ///
    /// The last publication is cleared with the new open interval, so an
    /// unfinished tick invalidates the previous publication instead of silently
    /// widening the window a sample covers, and while an interval is in progress
    /// `latest` is `None`: an interval in progress establishes no coverage.
    pub fn begin_interval(&self, start_ms: u64) -> Option<IntervalCoveragePublication> {
        let mut state = self.state.lock().ok()?;
        let previous = std::mem::replace(
            &mut state.publisher,
            IntervalCoveragePublisher::new(start_ms),
        );
        let unclosed = state.interval_open;
        state.interval_open = true;
        let publication =
            unclosed.then(|| state.record_publication(previous.record_unclosed(start_ms)));
        state.published = None;
        publication
    }

    /// Records one offered live observation class for one channel.
    ///
    /// An offer made while no interval is open, or against a poisoned cell,
    /// returns [`RecordOutcome::NotRecorded`], so a caller that reports a
    /// non-`Recorded` outcome also reports that the evidence was not kept rather
    /// than staying silent.
    pub fn record(&self, channel: ObservationChannel, class: ObservationClass) -> RecordOutcome {
        self.state
            .lock()
            .map_or(RecordOutcome::NotRecorded, |mut state| {
                if !state.interval_open {
                    return RecordOutcome::NotRecorded;
                }
                state.publisher.record(channel, class)
            })
    }

    /// Closes the open interval at `end_ms`.
    ///
    /// Returns `None` when the cell's lock is poisoned or no interval is open,
    /// which is the "coverage cannot be established" outcome and never a
    /// full-coverage claim. Closing an interval a tick opened is what makes its
    /// end declared; a window left open is not closed here, and is reported as
    /// an omission by the next [`begin_interval`](Self::begin_interval) instead.
    pub fn close_interval(&self, end_ms: u64) -> Option<IntervalCoveragePublication> {
        let mut state = self.state.lock().ok()?;
        if !state.interval_open {
            return None;
        }
        state.interval_open = false;
        let publisher =
            std::mem::replace(&mut state.publisher, IntervalCoveragePublisher::new(end_ms));
        let report = publisher.close(end_ms);
        let publication = state.record_publication(report.clone());
        state.published = Some(report);
        Some(publication)
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

#[cfg(test)]
mod replay_disposition_tests {
    use super::*;
    use eliot_evaluation_contracts::JournalReplayEvidence;

    fn window(first: u64, last: u64) -> JournalReplayEvidence {
        JournalReplayEvidence {
            journal_id: "filesystem-usn-journal".to_owned(),
            first_cursor: first,
            last_cursor: last,
        }
    }

    fn journal_record(report: &IntervalCoverageReport) -> &ChannelIntervalCoverage {
        report
            .records()
            .iter()
            .find(|record| record.channel == ObservationChannel::FilesystemJournal)
            .expect("journal record present")
    }

    /// An exact replayed window substitutes the missing live source on the
    /// unwired journal channel: `JOURNAL_REPLAYED` with the count equal to
    /// the evidence window length, no gaps, not blocking, internally valid.
    /// I8.2 (`docs/architecture/I08-02-independent-observation-routes.md:26`).
    #[test]
    fn exact_window_on_unwired_channel_closes_as_journal_replayed() {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(100, 109)),
            RecordOutcome::Recorded
        );
        let report = publisher.close(2_000);
        let record = journal_record(&report);
        assert_eq!(record.disposition(), CoverageDisposition::JournalReplayed);
        assert_eq!(record.observed_replayed_observations(), 10);
        assert_eq!(
            record
                .replayed_evidence()
                .expect("evidence kept")
                .first_cursor,
            100
        );
        assert!(record.gaps().is_empty());
        assert!(
            !report
                .blocking_channels()
                .contains(&ObservationChannel::FilesystemJournal)
        );
        assert!(report.valid());
    }

    /// Two windows are two claims about one interval: the second is refused
    /// and the first stands untouched.
    #[test]
    fn second_window_for_one_channel_is_refused_and_first_stands() {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(100, 109)),
            RecordOutcome::Recorded
        );
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(200, 209)),
            RecordOutcome::DroppedDuplicate
        );
        let report = publisher.close(2_000);
        let record = journal_record(&report);
        assert_eq!(record.disposition(), CoverageDisposition::JournalReplayed);
        assert_eq!(record.observed_replayed_observations(), 10);
        assert_eq!(
            record.replayed_evidence().expect("first kept").first_cursor,
            100
        );
        assert!(report.valid());
    }

    /// Malformed evidence (blank journal, inverted window) is refused like a
    /// duplicate: the channel stays blind with its named gap, never replayed.
    #[test]
    fn malformed_window_is_refused_and_channel_stays_blind() {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        assert_eq!(
            publisher.record_replayed(
                ObservationChannel::FilesystemJournal,
                JournalReplayEvidence {
                    journal_id: String::new(),
                    first_cursor: 100,
                    last_cursor: 109,
                }
            ),
            RecordOutcome::DroppedDuplicate
        );
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(200, 100)),
            RecordOutcome::DroppedDuplicate
        );
        let report = publisher.close(2_000);
        let record = journal_record(&report);
        assert_eq!(record.disposition(), CoverageDisposition::Blind);
        assert!(
            record
                .gaps()
                .iter()
                .any(|gap| gap.reason == "NO_COMPETENT_SOURCE")
        );
        assert!(
            report
                .blocking_channels()
                .contains(&ObservationChannel::FilesystemJournal)
        );
        assert!(report.valid());
    }

    /// A replay never covers a window the tick did not close: the record is
    /// `UNKNOWN` with `INTERVAL_NOT_CLOSED` and still blocks.
    #[test]
    fn replay_on_unclosed_window_is_unknown_not_coverage() {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(100, 109)),
            RecordOutcome::Recorded
        );
        let report = publisher.record_unclosed(2_000);
        let record = journal_record(&report);
        assert_eq!(record.disposition(), CoverageDisposition::Unknown);
        assert!(
            record
                .gaps()
                .iter()
                .any(|gap| gap.reason == "INTERVAL_NOT_CLOSED")
        );
        assert!(
            report
                .blocking_channels()
                .contains(&ObservationChannel::FilesystemJournal)
        );
        assert!(report.valid());
    }

    /// A replay substitutes the missing live source without discarding the
    /// live classes the tick did record: the disposition names the replay
    /// and the live samples stay in the record.
    #[test]
    fn replay_keeps_recorded_live_classes_and_names_the_replay() {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        assert_eq!(
            publisher.record(
                ObservationChannel::FilesystemJournal,
                ObservationClass::PathChange
            ),
            RecordOutcome::Recorded
        );
        assert_eq!(
            publisher.record_replayed(ObservationChannel::FilesystemJournal, window(100, 109)),
            RecordOutcome::Recorded
        );
        let report = publisher.close(2_000);
        let record = journal_record(&report);
        assert_eq!(record.disposition(), CoverageDisposition::JournalReplayed);
        assert_eq!(record.observed_replayed_observations(), 10);
        assert!(
            record
                .observed_classes
                .contains(&ObservationClass::PathChange)
        );
        assert!(report.valid());
    }
}
