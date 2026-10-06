//! Bound store-endpoint target parsing and listener-owner observations.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose), ARCH-WDG-01.
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes), I1.4.
//!
//! Two I8.2 channels share one probe core: `StoreProcessHealth` (the
//! Host-managed store process, observed through an approved read-only probe
//! independent of `eliotd`) and `ListenerInventory` (the registered loopback
//! listener of the canonical store endpoint). The probe reads only OS state
//! — the loopback listener owner table — against values retained from the
//! registry-selected manifest: the `--bind` loopback socket of
//! `canonical_store_arguments` and `canonical_store_executable_path`. No
//! store SDK, database credential, raw SQL, or database-file access exists
//! here, and none is added to close any gap.
//!
//! Bound closed (#1755 W2-rem): the owner PID the listener table reports is
//! bound to a handle identity (PID, creation time, image path) through the
//! safe `eliot-platform-windows` wrapper `observe_process_identity` (this
//! crate forbids `unsafe_code`), and the observed image must equal the
//! retained approved store image under the platform path comparison. A
//! present listener with an unbindable or mismatched owner yields an explicit
//! `Inaccessible` refusal — never a sample, never health-by-absence — while
//! an absent listener is a real `Absent` observation the tick already
//! exercises. A PID, a port-open result, or a self-reported healthy flag
//! alone can never produce a sample here.
//!
//! Forbidden by construction: lifecycle effects, authority, database access,
//! non-loopback probing, and any claim about a subject with no retained
//! binding or approved image.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use eliot_platform_windows::{
    TcpListenerOwnerError, observe_loopback_tcp_listener_owner, observe_process_identity,
    same_process_image_path,
};

use crate::independent_sensor::{ApprovedSensorBinding, SensorProbeError, SensorReadiness};

/// Installer-approved store endpoint target retained from the
/// registry-selected manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreEndpointTarget {
    installation: String,
    generation: String,
    endpoint: SocketAddr,
    image: PathBuf,
}

impl StoreEndpointTarget {
    /// Returns the approved installation identity this target is bound to.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.installation
    }

    /// Returns the approved target generation this target is bound to.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Returns the approved loopback endpoint of the canonical store.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns the approved canonical store image path.
    #[must_use]
    pub fn image(&self) -> &Path {
        &self.image
    }
}

/// Parses the installer-approved store endpoint target from retained manifest
/// values.
///
/// `arguments` is `canonical_store_arguments` (the sealed twelve-item
/// launch contour whose `--bind` value the seal proves is an exact nonzero
/// loopback socket) and `image` is `canonical_store_executable_path`. The
/// exact contour shape is re-checked here — flag present, value parses as a
/// loopback socket — so a caller can never substitute an endpoint by
/// presenting differently shaped arguments. Returns `None` for anything that
/// is not the approved contour, never a default endpoint.
#[must_use]
pub fn store_endpoint_target(
    binding: &ApprovedSensorBinding,
    arguments: &[&str],
    image: &Path,
) -> Option<StoreEndpointTarget> {
    if arguments.len() != 12
        || arguments[0] != "start"
        || arguments[1] != "--no-banner"
        || arguments[2] != "--bind"
    {
        return None;
    }
    let endpoint = parse_loopback_bind(arguments[3])?;
    if image.as_os_str().is_empty() {
        return None;
    }
    Some(StoreEndpointTarget {
        installation: binding.installation().to_owned(),
        generation: binding.generation().to_owned(),
        endpoint,
        image: image.to_owned(),
    })
}

/// Parses one `--bind` value as an exact nonzero loopback socket.
fn parse_loopback_bind(value: &str) -> Option<SocketAddr> {
    if let Some(port) = value.strip_prefix("127.0.0.1:") {
        let port: u16 = port.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    if let Some(port) = value
        .strip_prefix("[::1]:")
        .or_else(|| value.strip_prefix("::1:"))
    {
        let port: u16 = port.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    }
    None
}

/// One bound store-endpoint observation: the registered loopback listener is
/// owned by the approved store image process.
///
/// The observation carries the installation, the generation, the endpoint,
/// and the owner process identity (PID, creation time, image path) — never
/// file contents, query results, or principal identity. Liveness only:
/// readiness stays explicitly unprobed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreEndpointObservation {
    installation: String,
    generation: String,
    endpoint: SocketAddr,
    process_id: u32,
    start_time_100ns: u64,
    image_path: String,
    readiness: SensorReadiness,
}

impl StoreEndpointObservation {
    /// Returns the approved installation identity this sample was bound to.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.installation
    }

    /// Returns the approved target generation this sample was bound to.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Returns the observed loopback endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns the owning process identifier reported by Windows.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }

    /// Returns the owning process creation time in 100 ns units.
    #[must_use]
    pub const fn start_time_100ns(&self) -> u64 {
        self.start_time_100ns
    }

    /// Returns the owning process image path reported by Windows.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Returns the semantic readiness, always unprobed in this owner.
    #[must_use]
    pub const fn readiness(&self) -> SensorReadiness {
        self.readiness
    }
}

/// Observes the owner of the approved store loopback listener.
///
/// The listener owner table is read first. An absent listener is a real
/// `Absent` observation. A present listener's owner PID is bound to a handle
/// identity through `eliot-platform-windows` (safe wrapper; this crate
/// forbids `unsafe_code`), and the observed image must equal the retained
/// approved store image: a substituted process holding the same port is a
/// refusal, not a sample, and never evidence for a PID the probe did not
/// bind.
///
/// # Errors
///
/// Returns [`SensorProbeError::Absent`] when no listener exists and
/// [`SensorProbeError::Inaccessible`] when the table read is denied,
/// unavailable, the owner identity cannot be established, the approved image
/// is unusable, or the bound image is not the approved store image.
pub fn observe_store_endpoint(
    target: &StoreEndpointTarget,
) -> Result<StoreEndpointObservation, SensorProbeError> {
    if !target.endpoint.ip().is_loopback() {
        return Err(SensorProbeError::Inaccessible(
            "STORE_ENDPOINT_NON_LOOPBACK",
        ));
    }
    let owner =
        observe_loopback_tcp_listener_owner(target.endpoint).map_err(|error| match error {
            TcpListenerOwnerError::Missing => SensorProbeError::Absent("STORE_LISTENER_ABSENT"),
            TcpListenerOwnerError::AccessDenied => {
                SensorProbeError::Inaccessible("STORE_LISTENER_DENIED")
            }
            TcpListenerOwnerError::InvalidEndpoint => {
                SensorProbeError::Inaccessible("STORE_ENDPOINT_INVALID")
            }
            _ => SensorProbeError::Inaccessible("STORE_LISTENER_UNAVAILABLE"),
        })?;
    let identity = observe_process_identity(owner.process_id())
        .map_err(|_| SensorProbeError::Inaccessible("STORE_OWNER_IDENTITY_UNAVAILABLE"))?;
    let Some(approved) = target.image.to_str() else {
        return Err(SensorProbeError::Inaccessible(
            "STORE_APPROVED_IMAGE_INVALID",
        ));
    };
    if !same_process_image_path(&identity.image_path, approved) {
        return Err(SensorProbeError::Inaccessible("STORE_OWNER_IMAGE_MISMATCH"));
    }
    Ok(StoreEndpointObservation {
        installation: target.installation.clone(),
        generation: target.generation.clone(),
        endpoint: target.endpoint,
        process_id: identity.process_id,
        start_time_100ns: identity.start_time_100ns,
        image_path: identity.image_path,
        readiness: SensorReadiness::Unprobed,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the probe tests unwrap the owner's own targets and loopback listeners; a fixture that cannot bind is a test failure"
)]
mod tests {
    use super::*;

    fn test_binding() -> ApprovedSensorBinding {
        ApprovedSensorBinding::new("installation-7", "7").expect("test binding")
    }

    fn contour_arguments(bind: &str) -> Vec<String> {
        vec![
            "start".to_owned(),
            "--no-banner".to_owned(),
            "--bind".to_owned(),
            bind.to_owned(),
            "--temporary-directory".to_owned(),
            r"C:\tmp\store\tmp".to_owned(),
            "--log-file-enabled".to_owned(),
            "--log-file-path".to_owned(),
            r"C:\tmp\store\work".to_owned(),
            "--log-file-name".to_owned(),
            "surrealdb.log".to_owned(),
            "surrealkv://C:/tmp/store/data".to_owned(),
        ]
    }

    #[test]
    fn store_target_parses_the_approved_contour() {
        let arguments = contour_arguments("127.0.0.1:58000");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let target = store_endpoint_target(
            &test_binding(),
            &borrowed,
            Path::new(r"C:\Program Files\Eliot\surreal.exe"),
        )
        .expect("approved contour parses");
        assert_eq!(
            target.endpoint(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 58_000)
        );
        assert_eq!(target.installation(), "installation-7");
        assert_eq!(target.generation(), "7");
    }

    #[test]
    fn store_target_parses_ipv6_loopback() {
        let arguments = contour_arguments("[::1]:58001");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let target = store_endpoint_target(
            &test_binding(),
            &borrowed,
            Path::new(r"C:\Program Files\Eliot\surreal.exe"),
        )
        .expect("ipv6 loopback parses");
        assert_eq!(
            target.endpoint(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 58_001)
        );
    }

    #[test]
    fn store_target_rejects_non_contour_arguments() {
        let image = Path::new(r"C:\Program Files\Eliot\surreal.exe");
        // Wrong length.
        let short = vec!["start", "--no-banner"];
        assert!(store_endpoint_target(&test_binding(), &short, image).is_none());
        // Non-loopback bind.
        let arguments = contour_arguments("192.168.1.10:58000");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        assert!(store_endpoint_target(&test_binding(), &borrowed, image).is_none());
        // Zero port.
        let arguments = contour_arguments("127.0.0.1:0");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        assert!(store_endpoint_target(&test_binding(), &borrowed, image).is_none());
        // Unparseable port.
        let arguments = contour_arguments("127.0.0.1:not-a-port");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        assert!(store_endpoint_target(&test_binding(), &borrowed, image).is_none());
        // Missing --bind flag.
        let mut arguments = contour_arguments("127.0.0.1:58000");
        arguments[2] = "--endpoint".to_owned();
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        assert!(store_endpoint_target(&test_binding(), &borrowed, image).is_none());
        // Empty image.
        let arguments = contour_arguments("127.0.0.1:58000");
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        assert!(store_endpoint_target(&test_binding(), &borrowed, Path::new("")).is_none());
    }

    /// A released loopback port has no listener: absence, not health, not zero.
    ///
    /// This proves the live chain (manifest-shaped target -> OS listener-owner
    /// table -> typed refusal) end to end; a present listener with a matching
    /// image is now a sample, and a mismatched one stays `Inaccessible`.
    #[cfg(windows)]
    #[test]
    fn released_loopback_port_is_absent() {
        let endpoint = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            listener.local_addr().expect("listener address")
        };
        let target = StoreEndpointTarget {
            installation: "installation-7".to_owned(),
            generation: "7".to_owned(),
            endpoint,
            image: std::env::current_exe().expect("test executable path"),
        };
        assert!(matches!(
            observe_store_endpoint(&target),
            Err(SensorProbeError::Absent(_))
        ));
    }

    /// A live loopback listener owned by this test process binds to the test
    /// executable image: a real sample, the first production caller of the
    /// owner-identity surface (#1755 W2-rem).
    #[cfg(windows)]
    #[test]
    fn live_loopback_listener_binds_matching_owner_identity() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let endpoint = listener.local_addr().expect("listener address");
        let target = StoreEndpointTarget {
            installation: "installation-7".to_owned(),
            generation: "7".to_owned(),
            endpoint,
            image: std::env::current_exe().expect("test executable path"),
        };
        let observation = observe_store_endpoint(&target).expect("bound owner is a sample");
        assert_eq!(observation.process_id(), std::process::id());
        assert_eq!(observation.endpoint(), endpoint);
        assert_eq!(observation.installation(), "installation-7");
        assert_eq!(observation.generation(), "7");
        assert!(!observation.image_path().is_empty());
        assert_eq!(observation.readiness().as_str(), "unprobed");
        drop(listener);
    }

    /// A live loopback listener whose retained approved image is not the
    /// owning process image is a refusal: the image binding, not the PID,
    /// admits the sample.
    #[cfg(windows)]
    #[test]
    fn live_loopback_listener_with_foreign_image_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let endpoint = listener.local_addr().expect("listener address");
        let target = StoreEndpointTarget {
            installation: "installation-7".to_owned(),
            generation: "7".to_owned(),
            endpoint,
            image: PathBuf::from(r"C:\Windows\System32\notepad.exe"),
        };
        assert!(matches!(
            observe_store_endpoint(&target),
            Err(SensorProbeError::Inaccessible(_))
        ));
        drop(listener);
    }
}
