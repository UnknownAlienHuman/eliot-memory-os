//! One finite production boundary map for the Store contour (issue #1810,
//! implementation step 1).
//!
//! I15.3 (`docs/architecture/I15-03-least-privilege-processes.md`) and I15.4
//! (`docs/architecture/I15-04-secrets.md`) name the production identities that
//! may hold a database credential or reach the provider endpoint. This module is
//! that finite set as code: a closed set of contours, the credential role each
//! is admitted to hold or consume, the issuer of those references, the owner of
//! the provider endpoint and of the store roots, the named-pipe caller, the
//! maintenance/break-glass caller, and the Watchdog sensor channels — plus
//! whether each row is a source declaration or still requires installed Windows
//! evidence.
//!
//! Three properties are load-bearing and are why this is a map rather than prose:
//!
//! * It is finite and closed. A contour that is not listed here cannot appear
//!   as a database-capable edge of this launch, so a future contour cannot be
//!   added by accident.
//! * Its credential assignment is checked against the launch configuration
//!   actually in hand, not against a second copy of itself.
//!   [`StoreBoundaryMap::validate_against`] requires this launch to resolve to
//!   exactly the assignment the map declares, so a configuration carrying one
//!   reference for both roles, or the wrong contour for one, is refused before
//!   any provider process exists.
//! * It states no installed fact. Every row is a source declaration; the rows
//!   whose enforcement exists only on a provisioned Windows profile carry
//!   [`BoundaryEvidence::RequiresInstalledWindowsEvidence`], so a green
//!   construction is never read as an observed installation. Nothing here is
//!   inferred from a package boundary, and nothing here is inferred from
//!   `SecretString` debug redaction.
//!
//! Every claim in the rows below is anchored to a symbol in this repository.
//! Where an owner is named, it is named by its own module path, not by a
//! remembered capability.

use crate::StoreLaunchConfig;

/// Production contour of the Store/database boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreBoundaryContour {
    /// `eliot-host.exe`: installation, service identities and secret delivery.
    Host,
    /// `eliot-store-surreal.exe`: the closed Store bridge.
    StoreBridge,
    /// `surreal.exe`: the Store-bridge-managed provider child owning the DB
    /// files and the loopback listener.
    ProviderChild,
    /// Kernel/daemon ordinary bridge client over authenticated named IPC.
    BridgeClient,
    /// Maintenance/break-glass caller governed by I15.15.
    MaintenanceCaller,
    /// `eliot-watchdog.exe`: independent sensors and spool, no canonical write.
    Watchdog,
}

/// Which distinct credential role a contour is admitted to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreCredentialRole {
    /// Server bootstrap/admin credential handed only to the provider child.
    ProviderBootstrapAdmin,
    /// Ordinary least-privilege database client credential of the bridge.
    NormalClient,
}

impl StoreCredentialRole {
    const ALL: [Self; 2] = [Self::ProviderBootstrapAdmin, Self::NormalClient];
}

/// Issuer of every credential reference in this boundary (I15.4: Windows
/// Credential Manager/DPAPI-protected `SecretRef` values behind the ELIOT
/// secret-provider facade).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialIssuer {
    /// Windows Credential Manager, read through
    /// `eliot_platform_windows::WindowsPlatform::read_credential` under the
    /// bridge's `LocalService` identity.
    WindowsCredentialManager,
}

/// Whether the row is enforced by this source or still needs installed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryEvidence {
    /// Enforced by current source at this launch.
    SourceDeclaration,
    /// Requires an observation on an installed Windows profile; source cannot
    /// promote it.
    RequiresInstalledWindowsEvidence,
}

/// One contour row of the finite map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContourBoundary {
    /// The contour this row names.
    pub contour: StoreBoundaryContour,
    /// Credential role this contour holds or consumes; `None` means the
    /// contour is admitted to no database credential at all.
    pub credential_role: Option<StoreCredentialRole>,
    /// Issuer of the reference bound to `credential_role`.
    pub issuer: CredentialIssuer,
    /// Whether this contour owns the provider endpoint/listener.
    pub owns_provider_endpoint: bool,
    /// Whether this contour owns the store data/work/temp roots.
    pub owns_store_roots: bool,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// The authenticated named-pipe caller of the Store bridge (I15.2/I15.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedPipeCallerBoundary {
    /// Contour admitted to the Store bridge's named pipe.
    pub contour: StoreBoundaryContour,
    /// Peer the bridge authenticates, taken from `StoreLaunchConfig`'s
    /// `expected_client_sid` / `expected_client_session_id` and enforced by
    /// `eliot_platform_windows::NamedPipePeerExpectation`.
    pub peer_expectation_source: &'static str,
    /// What the caller may reach once authenticated.
    pub admitted_surface: &'static str,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// The maintenance/break-glass caller of a recovery path (I15.15).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceCallerBoundary {
    /// Contour that may invoke the predeclared break-glass path.
    pub contour: StoreBoundaryContour,
    /// Owning module of that path, by repository path.
    pub owner: &'static str,
    /// Whether the caller receives a database credential of this launch.
    /// I15.15 routes recovery through credential/epochs rotation, so the
    /// caller is admitted to no credential of the current launch.
    pub receives_launch_credential: bool,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// One Watchdog sensor channel relevant to the provider endpoint (I8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogSensorBoundary {
    /// Owning map of the channel, by repository path.
    pub owner: &'static str,
    /// Channel name inside that owner's closed channel set.
    pub channel: &'static str,
    /// Measured wiring state in that owner.
    pub wiring: &'static str,
    /// Whether the channel can produce any canonical transition. An independent
    /// observation never can: the Watchdog holds no canonical write (I15.3).
    pub produces_canonical_transition: bool,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

const CANONICAL_ROWS: &[ContourBoundary] = &[
    ContourBoundary {
        contour: StoreBoundaryContour::Host,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        owns_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::StoreBridge,
        credential_role: Some(StoreCredentialRole::NormalClient),
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        owns_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::ProviderChild,
        credential_role: Some(StoreCredentialRole::ProviderBootstrapAdmin),
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: true,
        owns_store_roots: true,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::BridgeClient,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        owns_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::MaintenanceCaller,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        owns_store_roots: false,
        evidence: BoundaryEvidence::RequiresInstalledWindowsEvidence,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::Watchdog,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        owns_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
];

/// The one authenticated named-pipe caller of the Store bridge.
const NAMED_PIPE_CALLER: NamedPipeCallerBoundary = NamedPipeCallerBoundary {
    contour: StoreBoundaryContour::BridgeClient,
    peer_expectation_source: "StoreLaunchConfig::expected_client_sid / expected_client_session_id, enforced by \
         eliot_platform_windows::NamedPipePeerExpectation and checked in \
         bins/eliot-store-surreal/src/main.rs::serve",
    admitted_surface: "closed typed store requests only; the isolated health/admin lane admits exactly \
         store.health and store.readiness (connection_manager::OperationAdmission::bridge_default)",
    evidence: BoundaryEvidence::SourceDeclaration,
};

/// The maintenance/break-glass caller of a recovery path.
const MAINTENANCE_CALLER: MaintenanceCallerBoundary = MaintenanceCallerBoundary {
    contour: StoreBoundaryContour::MaintenanceCaller,
    owner: "crates/governor/eliot-authority/src/break_glass.rs::BreakGlassAuthorization",
    receives_launch_credential: false,
    evidence: BoundaryEvidence::RequiresInstalledWindowsEvidence,
};

/// The Watchdog sensor channels that can observe this contour, with the wiring
/// state their own owner records. The Watchdog holds no store edge in its
/// manifest and no database credential, so these are named gaps today, and the
/// naming is the truthful-coverage half of issue #1810 item 7: the absence of
/// an adapter is recorded, not concealed.
const WATCHDOG_SENSORS: &[WatchdogSensorBoundary] = &[
    WatchdogSensorBoundary {
        owner: "bins/eliot-watchdog/src/observation_coverage.rs::SENSOR_CHANNEL_MAP",
        channel: "store_process_health",
        wiring: "ChannelWiring::MissingAdapter",
        produces_canonical_transition: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    WatchdogSensorBoundary {
        owner: "bins/eliot-watchdog/src/observation_coverage.rs::SENSOR_CHANNEL_MAP",
        channel: "listener_inventory",
        wiring: "ChannelWiring::MissingAdapter",
        produces_canonical_transition: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
];

/// The complete finite Store/database boundary map.
pub struct StoreBoundaryMap {
    rows: &'static [ContourBoundary],
}

impl StoreBoundaryMap {
    /// Returns the one finite canonical map.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            rows: CANONICAL_ROWS,
        }
    }

    /// Returns the finite contour rows of this map.
    #[must_use]
    pub const fn rows(&self) -> &'static [ContourBoundary] {
        self.rows
    }

    /// Returns the one authenticated named-pipe caller boundary.
    #[must_use]
    pub const fn named_pipe_caller(&self) -> &'static NamedPipeCallerBoundary {
        &NAMED_PIPE_CALLER
    }

    /// Returns the maintenance/break-glass caller boundary.
    #[must_use]
    pub const fn maintenance_caller(&self) -> &'static MaintenanceCallerBoundary {
        &MAINTENANCE_CALLER
    }

    /// Returns the Watchdog sensor channels that cover this contour.
    #[must_use]
    pub const fn watchdog_sensors(&self) -> &'static [WatchdogSensorBoundary] {
        WATCHDOG_SENSORS
    }

    /// Checks this launch against the finite map.
    ///
    /// The map itself must be internally consistent — every credential role
    /// named exactly once, exactly one provider endpoint owner, that owner
    /// also the root owner, and no contour admitted to two roles — and the
    /// launch must then resolve to exactly that assignment: two different
    /// credential references, and a provider bootstrap identity that is not
    /// the ordinary client identity.
    pub(crate) fn validate_against(&self, config: &StoreLaunchConfig) -> Result<(), String> {
        for role in StoreCredentialRole::ALL {
            let holders = self
                .rows
                .iter()
                .filter(|row| row.credential_role == Some(role))
                .map(|row| row.contour)
                .collect::<Vec<_>>();
            if holders.len() != 1 {
                return Err(format!(
                    "boundary map must name exactly one holder of the {role:?} credential, found {}",
                    holders.len()
                ));
            }
        }
        if self.holders_of(StoreCredentialRole::NormalClient) != [StoreBoundaryContour::StoreBridge]
        {
            return Err(
                "boundary map does not name the Store bridge as the ordinary client-credential holder"
                    .to_owned(),
            );
        }
        if self.holders_of(StoreCredentialRole::ProviderBootstrapAdmin)
            != [StoreBoundaryContour::ProviderChild]
        {
            return Err(
                "boundary map does not name the provider child as the bootstrap-credential consumer"
                    .to_owned(),
            );
        }
        let owners = |select: fn(&ContourBoundary) -> bool| -> Vec<StoreBoundaryContour> {
            self.rows
                .iter()
                .filter(|row| select(row))
                .map(|row| row.contour)
                .collect()
        };
        if owners(|row| row.owns_provider_endpoint) != [StoreBoundaryContour::ProviderChild] {
            return Err(
                "boundary map must name exactly the provider child as the provider endpoint owner"
                    .to_owned(),
            );
        }
        if owners(|row| row.owns_store_roots) != [StoreBoundaryContour::ProviderChild] {
            return Err(
                "boundary map must name exactly the provider child as the store roots owner"
                    .to_owned(),
            );
        }
        for caller in [NAMED_PIPE_CALLER.contour, MAINTENANCE_CALLER.contour] {
            if caller == MAINTENANCE_CALLER.contour && MAINTENANCE_CALLER.receives_launch_credential
            {
                return Err(
                    "the maintenance/break-glass caller must be admitted to no launch credential"
                        .to_owned(),
                );
            }
            if self
                .rows
                .iter()
                .find(|row| row.contour == caller)
                .and_then(|row| row.credential_role)
                .is_some()
            {
                return Err(format!(
                    "the {caller:?} caller must hold no credential of this launch"
                ));
            }
        }
        if NAMED_PIPE_CALLER.contour == MAINTENANCE_CALLER.contour {
            return Err(
                "the named-pipe caller and the maintenance/break-glass caller must be distinct contours"
                    .to_owned(),
            );
        }
        if config.provider_bootstrap_credential_ref == config.credential_ref {
            return Err(
                "provider bootstrap and ordinary client credential references must differ"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn holders_of(&self, role: StoreCredentialRole) -> Vec<StoreBoundaryContour> {
        self.rows
            .iter()
            .filter(|row| row.credential_role == Some(role))
            .map(|row| row.contour)
            .collect()
    }
}
