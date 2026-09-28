//! One finite production boundary map for the Store/database contour (issue
//! #1810, implementation step 1).
//!
//! I15.3 (`docs/architecture/I15-03-least-privilege-processes.md`) and I15.4
//! (`docs/architecture/I15-04-secrets.md`) are the governing documents: they
//! name the contours that may hold a database credential or reach the provider
//! endpoint, require a fresh child-only environment block for the
//! `surreal.exe` dependency, and require the server bootstrap/admin and normal
//! application credentials to be distinct, independently rotatable references.
//!
//! This module is that finite set as code. It exists so the assignment cannot be
//! restated loosely at each call site:
//!
//! * It is closed. Every DB-capable contour of this launch is a row here. A
//!   contour that is not a row holds no database credential of this launch.
//! * Its credential assignment is enforced against the launch actually in hand
//!   by [`StoreBoundaryMap::validate_against`], which runs first in
//!   [`crate::StoreLaunchConfig::validate`], before any reference is resolved
//!   and before any provider process exists.
//! * It separates source declaration from installed Windows evidence. Every row
//!   carries one [`BoundaryEvidence`] class, so a green construction is never
//!   read as an observed installation.
//! * Nothing here is inferred from a package boundary and nothing here is
//!   inferred from `SecretString` debug redaction. Each named owner is named by
//!   a `path::symbol` that exists in this tree.
//!
//! What this map does NOT state, because the tree does not contain it: there is
//! no firewall, WFP, service-SID or ACL endpoint-policy owner in
//! `crates/kernel/eliot-platform-windows`, `crates/kernel/eliot-installation`,
//! `bins/eliot-host` or `bins/eliot-store-surreal`, and no Watchdog sensor
//! observes the provider process, its listener or the store data root. Those are
//! recorded as gaps with their truthful coverage, not as satisfied properties.

use crate::StoreLaunchConfig;

/// Production contour of the Store/database boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreBoundaryContour {
    /// `eliot-host.exe`: installation, service identities and secret delivery.
    Host,
    /// `eliot-store-surreal.exe`: the closed Store bridge. It composes the
    /// provider child, so it is the process that materializes the child-only
    /// environment block immediately before process creation.
    StoreBridge,
    /// `surreal.exe`: the Store-bridge-managed provider child owning the DB
    /// files and the loopback listener.
    ProviderChild,
    /// Kernel/daemon ordinary bridge client over the authenticated named pipe.
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

/// Issuer of every credential reference in this boundary.
///
/// I15.4: "Windows Credential Manager/DPAPI-protected `SecretRef` values behind
/// the ELIOT secret-provider facade". The reader is
/// `eliot_platform_windows::WindowsPlatform::read_credential`
/// (`crates/kernel/eliot-platform-windows/src/secret_store.rs`); the reference
/// admission owners are
/// `eliot_installation::validate_store_credential_target` and
/// `eliot_installation::validate_provider_bootstrap_credential_target`
/// (`crates/kernel/eliot-installation/src/credential_provision.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialIssuer {
    /// Windows Credential Manager, read inside the Store bridge process.
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
    /// Whether this contour retains the exclusive store-root leases.
    pub leases_store_roots: bool,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// One secret-bearing or DB-capable edge of this launch, with the reference it
/// resolves and the runtime caller that resolves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialReferenceBoundary {
    /// Role this reference is admitted to serve.
    pub role: StoreCredentialRole,
    /// Reserving namespace of the Credential Manager target.
    pub target_namespace: &'static str,
    /// Admission owner of the exact reference value.
    pub validator: &'static str,
    /// Runtime caller that resolves the value.
    pub resolved_by: &'static str,
    /// Process whose environment receives the value.
    pub delivered_to: StoreBoundaryContour,
    /// One-shot delivery channel. Both rows are a fresh child-only environment
    /// block or a private `SecretString` field; neither is argv, a serialized
    /// form, `RuntimeLaunchDescriptor` or `HostStateJournal`.
    pub delivery_channel: &'static str,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// The data/work/temp roots this launch binds, and who binds each one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreRootBoundary {
    /// Runtime-state root field, by its owning symbol.
    pub root: &'static str,
    /// Contour that retains the exclusive lease of this root.
    pub leased_by: StoreBoundaryContour,
    /// How the root reaches the provider child.
    pub provider_binding: &'static str,
    /// Evidence class of this row.
    pub evidence: BoundaryEvidence,
}

/// The authenticated named-pipe caller of the Store bridge (I15.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedPipeCallerBoundary {
    /// Contour admitted to the Store bridge's named pipe.
    pub contour: StoreBoundaryContour,
    /// Peer the bridge authenticates.
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
    /// I15.15 routes recovery through credential/epochs rotation, so the caller
    /// is admitted to no credential of the current launch.
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
    /// Wiring state recorded by that owner for this channel.
    pub wiring: &'static str,
    /// Classes the channel would cover once wired, by that owner's own
    /// `supported_classes`.
    pub covered_classes: &'static str,
    /// Whether the channel can produce any canonical transition. An independent
    /// observation never can: this owner records `ChannelWiring` and writes its
    /// own spool/Signal only.
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
        leases_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::StoreBridge,
        credential_role: Some(StoreCredentialRole::NormalClient),
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        // `StoreComposition::new` retains the exclusive runtime-root leases and
        // passes the three store roots to the provider child in argv.
        leases_store_roots: true,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::ProviderChild,
        credential_role: Some(StoreCredentialRole::ProviderBootstrapAdmin),
        issuer: CredentialIssuer::WindowsCredentialManager,
        // The child is the only listener on `provider_bind_address`, and the
        // bridge proves that ownership before and after it connects.
        owns_provider_endpoint: true,
        leases_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::BridgeClient,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        leases_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::MaintenanceCaller,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        leases_store_roots: false,
        evidence: BoundaryEvidence::RequiresInstalledWindowsEvidence,
    },
    ContourBoundary {
        contour: StoreBoundaryContour::Watchdog,
        credential_role: None,
        issuer: CredentialIssuer::WindowsCredentialManager,
        owns_provider_endpoint: false,
        leases_store_roots: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
];

/// The two secret-bearing edges of this launch.
const CREDENTIAL_REFERENCES: &[CredentialReferenceBoundary] = &[
    CredentialReferenceBoundary {
        role: StoreCredentialRole::NormalClient,
        target_namespace: "eliot/store/v1/<32 hex>",
        validator: "eliot_installation::validate_store_credential_target",
        resolved_by:
            "adapter_materialization::resolve_credential, called by StoreComposition::new",
        delivered_to: StoreBoundaryContour::StoreBridge,
        delivery_channel: "SecretString field SurrealAdapterConfig::password, used only by \
             RpcSession::signin; never written into the provider child's environment block",
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    CredentialReferenceBoundary {
        role: StoreCredentialRole::ProviderBootstrapAdmin,
        target_namespace: "eliot/provider/v1/<32 hex>",
        validator: "eliot_installation::validate_provider_bootstrap_credential_target",
        resolved_by:
            "adapter_materialization::resolve_provider_bootstrap_credential, called by \
             StoreComposition::new",
        delivered_to: StoreBoundaryContour::ProviderChild,
        delivery_channel: "fresh child-only environment block built by \
             provider_owner::provider_environment under the two fixed provider bootstrap names; \
             never argv, never the parent environment, never a serialized form",
        evidence: BoundaryEvidence::SourceDeclaration,
    },
];

/// The data/work/temp roots this launch binds.
const STORE_ROOTS: &[StoreRootBoundary] = &[
    StoreRootBoundary {
        root: "eliot_installation::RuntimeStateRoots::store_data_root",
        leased_by: StoreBoundaryContour::StoreBridge,
        provider_binding: "the surrealkv:// argument of \
             SurrealAdapterConfig::expected_provider_arguments",
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    StoreRootBoundary {
        root: "eliot_installation::RuntimeStateRoots::store_work_root",
        leased_by: StoreBoundaryContour::StoreBridge,
        provider_binding: "the --log-file-path argument of \
             SurrealAdapterConfig::expected_provider_arguments",
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    StoreRootBoundary {
        root: "eliot_installation::RuntimeStateRoots::store_temp_root",
        leased_by: StoreBoundaryContour::StoreBridge,
        provider_binding: "the --temporary-directory argument and the TEMP/TMP entries of the \
             child-only environment block",
        evidence: BoundaryEvidence::SourceDeclaration,
    },
];

/// The one authenticated named-pipe caller of the Store bridge.
const NAMED_PIPE_CALLER: NamedPipeCallerBoundary = NamedPipeCallerBoundary {
    contour: StoreBoundaryContour::BridgeClient,
    peer_expectation_source: "StoreLaunchConfig::expected_client_sid / \
         expected_client_session_id, admitted by \
         eliot_platform_windows::NamedPipePeerExpectation::new in \
         bins/eliot-store-surreal/src/main.rs::serve_handshake_loop and enforced by \
         eliot_platform_windows::NamedPipeServer::create",
    admitted_surface: "closed typed store requests only; the isolated health/admin lane admits \
         exactly store.health and store.readiness \
         (connection_manager::HealthAdminAdmission::bridge_default)",
    evidence: BoundaryEvidence::SourceDeclaration,
};

/// The maintenance/break-glass caller of a recovery path.
const MAINTENANCE_CALLER: MaintenanceCallerBoundary = MaintenanceCallerBoundary {
    contour: StoreBoundaryContour::MaintenanceCaller,
    owner: "crates/governor/eliot-authority/src/break_glass.rs::BreakGlassAuthorization",
    receives_launch_credential: false,
    evidence: BoundaryEvidence::RequiresInstalledWindowsEvidence,
};

/// The Watchdog sensor channels that could observe this contour, carrying the
/// wiring state their own owner records.
///
/// `bins/eliot-watchdog/src/observation_coverage.rs` is the #1755 sensor map
/// (`SENSOR_CHANNEL_MAP`). Both channels below are recorded there as
/// `ChannelWiring::MissingAdapter`, so the honest coverage today is: no
/// independent process, listener or data-root observation exists, and the
/// absence of a sensor is not evidence that no foreign client exists. Naming the
/// gap with its owner is the truthful-coverage half of issue #1810 item 7.
const WATCHDOG_SENSORS: &[WatchdogSensorBoundary] = &[
    WatchdogSensorBoundary {
        owner: "bins/eliot-watchdog/src/observation_coverage.rs::SENSOR_CHANNEL_MAP",
        channel: "store_process_health",
        wiring: "ChannelWiring::MissingAdapter",
        covered_classes: "ObservationClass::ReadOnlyProbe",
        produces_canonical_transition: false,
        evidence: BoundaryEvidence::SourceDeclaration,
    },
    WatchdogSensorBoundary {
        owner: "bins/eliot-watchdog/src/observation_coverage.rs::SENSOR_CHANNEL_MAP",
        channel: "listener_inventory",
        wiring: "ChannelWiring::MissingAdapter",
        covered_classes: "ObservationClass::ListenerBinding",
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

    /// Returns the two secret-bearing edges of this launch.
    #[must_use]
    pub const fn credential_references(&self) -> &'static [CredentialReferenceBoundary] {
        CREDENTIAL_REFERENCES
    }

    /// Returns the data/work/temp roots this launch binds.
    #[must_use]
    pub const fn store_roots(&self) -> &'static [StoreRootBoundary] {
        STORE_ROOTS
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
    /// The map admits each credential role to exactly one contour, and the two
    /// callers that reach the bridge without a database credential — the
    /// named-pipe client and the maintenance/break-glass caller — must be
    /// distinct contours that the map admits to no credential of this launch.
    /// The launch must then bind its two references to two different contours:
    /// one reference for both roles would put one secret in both contours.
    pub(crate) fn validate_against(&self, config: &StoreLaunchConfig) -> Result<(), String> {
        if NAMED_PIPE_CALLER.contour == MAINTENANCE_CALLER.contour {
            return Err(
                "the named-pipe caller and the maintenance/break-glass caller must be distinct contours"
                    .to_owned(),
            );
        }
        if MAINTENANCE_CALLER.receives_launch_credential {
            return Err(
                "the maintenance/break-glass caller must be admitted to no launch credential"
                    .to_owned(),
            );
        }
        for caller in [NAMED_PIPE_CALLER.contour, MAINTENANCE_CALLER.contour] {
            if self.holds_credential(caller) {
                return Err(format!(
                    "the {caller:?} caller must be admitted to no credential of this launch"
                ));
            }
        }
        if config.credential_ref == config.provider_bootstrap_credential_ref {
            return Err(
                "the ordinary client and the provider bootstrap credential references must differ"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Whether the map admits this contour to any credential of this launch.
    fn holds_credential(&self, contour: StoreBoundaryContour) -> bool {
        self.rows
            .iter()
            .any(|row| row.contour == contour && row.credential_role.is_some())
    }
}
