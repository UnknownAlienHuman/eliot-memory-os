//! Composition root for the governed notification process.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;

use eliot_notify_core::{
    DeliveryObservation, NotificationEnvelope, NotifyCore, SignedWatchdogFallbackEnvelope,
    VerificationPorts,
};
use eliot_platform::{NotificationRequest, PortError};
use eliot_platform_windows::WindowsPlatform;

pub const SERVICE_NAME: &str = "eliot-notify";
pub const PROTOCOL_VERSION: &str = "eliot.notify.v1";

#[derive(Debug)]
pub enum NotifyBuildError {
    Platform(PortError),
}

impl fmt::Display for NotifyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
        }
    }
}

impl std::error::Error for NotifyBuildError {}

/// The complete A-10 composition. Verification and replay authority are
/// supplied by the owning control plane; this process owns only the P-01
/// adapter binding and the A-10 coordinator.
pub struct NotificationComposition {
    core: NotifyCore<WindowsPlatform>,
}

impl NotificationComposition {
    /// Binds notification delivery to one validated WorkScope root.
    pub fn new(
        work_root: impl Into<PathBuf>,
        ports: VerificationPorts,
    ) -> Result<Self, NotifyBuildError> {
        let platform = WindowsPlatform::new(work_root).map_err(NotifyBuildError::Platform)?;
        Ok(Self::from_platform(platform, ports))
    }

    /// Composes A-10 with an already-created platform adapter.
    #[must_use]
    pub fn from_platform(platform: WindowsPlatform, ports: VerificationPorts) -> Self {
        Self {
            core: NotifyCore::new(platform, ports),
        }
    }

    /// Delivers a normal G-08 notification through the governed core.
    pub fn deliver(
        &mut self,
        envelope: &NotificationEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, eliot_notify_core::NotifyError> {
        self.core.deliver(envelope, request)
    }

    /// Delivers the restricted signed Watchdog recovery notification.
    pub fn deliver_watchdog_fallback(
        &mut self,
        envelope: &SignedWatchdogFallbackEnvelope,
        request: &NotificationRequest,
    ) -> Result<DeliveryObservation, eliot_notify_core::NotifyError> {
        self.core.deliver_watchdog_fallback(envelope, request)
    }
}

/// Resolves the process WorkScope root from the protected ProgramData contour.
pub fn default_work_root() -> Result<PathBuf, std::io::Error> {
    let root = eliot_platform_windows::protected_program_data_path("Eliot/notify")
        .map_err(std::io::Error::other)?;
    eliot_platform_windows::prepare_protected_directory(&root).map_err(std::io::Error::other)?;
    std::fs::canonicalize(root)
}
