//! Kernel startup contour (ROOT inputs, §15 req.1/req.2/req.6).
//!
//! Binary-private parsing, validation, and bounded lease reads for the
//! `eliot-kernel` entry: host-injected `KernelStartupBinding`, the exact
//! 16-value launch contour, neutral store-bootstrap and `eliotd` descriptor
//! preparation, and the authority-contour projection. Zero composition
//! contact: this module never constructs, reads, or drives
//! `KernelComposition`; `main` calls the `pub(crate)` parsers and passes the
//! results into `KernelConfig` wiring. Capability cell: ROOT inputs.

use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_kernel::AuthorityDescriptorContour;
#[cfg(windows)]
use eliot_kernel_service::KERNEL_CONTROL_PIPE;
use eliot_kernel_service::{EliotdLaunchDescriptor, HostStoreBootstrapRequirement};
#[cfg(windows)]
use eliot_platform_windows::{
    NamedPipePeerProcessBinding, ProtectedRuntimePathLease, UserOwnedPathLease, UserOwnedRootLease,
    observe_named_pipe_peer_process,
};

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelStartupBinding {
    pub(crate) control_pipe: String,
    host_process_id: u32,
    host_process_start: u64,
    host_process_image: String,
    pub(crate) receipt_root: PathBuf,
    pub(crate) kernel_ors_root: PathBuf,
    pub(crate) runtime_state_roots_digest: String,
    generation_config_digest: String,
    pub(crate) installation_id: String,
    pub(crate) approved_generation: String,
}

#[cfg(windows)]
impl KernelStartupBinding {
    pub(crate) fn from_environment() -> Result<Self, String> {
        Self::parse(
            std::env::var("ELIOT_KERNEL_CONTROL_PIPE").ok(),
            std::env::var("ELIOT_HOST_PROCESS_ID").ok(),
            std::env::var("ELIOT_HOST_PROCESS_START").ok(),
            std::env::var("ELIOT_HOST_PROCESS_IMAGE").ok(),
            std::env::var("ELIOT_KERNEL_RECEIPT_ROOT").ok(),
            std::env::var("ELIOT_KERNEL_ORS_ROOT").ok(),
            std::env::var("ELIOT_RUNTIME_STATE_ROOTS_DIGEST").ok(),
            std::env::var("ELIOT_GENERATION_CONFIG_DIGEST").ok(),
            std::env::var("ELIOT_HOST_INSTALLATION").ok(),
            std::env::var("ELIOT_APPROVED_GENERATION").ok(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn parse(
        control_pipe: Option<String>,
        host_process_id: Option<String>,
        host_process_start: Option<String>,
        host_process_image: Option<String>,
        receipt_root: Option<String>,
        kernel_ors_root: Option<String>,
        runtime_state_roots_digest: Option<String>,
        generation_config_digest: Option<String>,
        installation_id: Option<String>,
        approved_generation: Option<String>,
    ) -> Result<Self, String> {
        let control_pipe = control_pipe
            .filter(|pipe| pipe == KERNEL_CONTROL_PIPE)
            .ok_or_else(|| {
                "Host launch context did not inject the exact Kernel control pipe".to_owned()
            })?;
        let host_process_id = host_process_id
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                "Host launch context did not inject a valid Host process binding".to_owned()
            })?;
        let host_process_start = host_process_start
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                "Host launch context did not inject a valid Host process start time".to_owned()
            })?;
        let host_process_image = host_process_image
            .filter(|image| {
                !image.trim().is_empty()
                    && image == image.trim()
                    && !image.chars().any(char::is_control)
                    && Path::new(image).is_absolute()
            })
            .ok_or_else(|| {
                "Host launch context did not inject a canonical Host process image".to_owned()
            })?;
        let exact_root = |value: Option<String>, label: &str| {
            value
                .map(PathBuf::from)
                .filter(|root| {
                    root.is_absolute()
                        && !root.as_os_str().is_empty()
                        && !root.to_string_lossy().chars().any(char::is_control)
                })
                .ok_or_else(|| format!("Host launch context did not inject the exact {label}"))
        };
        let receipt_root = exact_root(receipt_root, "Kernel receipt root")?;
        let kernel_ors_root = exact_root(kernel_ors_root, "Kernel ORS root")?;
        let runtime_state_roots_digest = runtime_state_roots_digest
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                "Host launch context did not inject the RuntimeStateRoots digest".to_owned()
            })?;
        let generation_config_digest = generation_config_digest
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                "Host launch context did not inject the approved admission-config digest".to_owned()
            })?;
        let exact_identity = |value: Option<String>, label: &str| {
            value
                .filter(|value| {
                    !value.trim().is_empty()
                        && value == value.trim()
                        && !value.chars().any(char::is_control)
                })
                .ok_or_else(|| format!("Host launch context did not inject the exact {label}"))
        };
        let installation_id = exact_identity(installation_id, "installation identity")?;
        let approved_generation = exact_identity(approved_generation, "approved generation")?;
        Ok(Self {
            control_pipe,
            host_process_id,
            host_process_start,
            host_process_image,
            receipt_root,
            kernel_ors_root,
            runtime_state_roots_digest,
            generation_config_digest,
            installation_id,
            approved_generation,
        })
    }

    pub(crate) fn observe_host(&self) -> Result<NamedPipePeerProcessBinding, String> {
        let observed = observe_named_pipe_peer_process(self.host_process_id)
            .map_err(|error| error.to_string())?;
        if !self.matches_observed(
            observed.process_id(),
            observed.start_time_100ns(),
            observed.image_path(),
        ) {
            return Err("live Host process binding changed before Kernel admission".to_owned());
        }
        Ok(observed)
    }

    fn matches_observed(&self, process_id: u32, start_time_100ns: u64, image_path: &str) -> bool {
        self.host_process_id == process_id
            && self.host_process_start == start_time_100ns
            && self.host_process_image == image_path
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoreConfigLocator {
    NeutralDescriptor(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelLaunchOptions {
    pub(crate) work_root: PathBuf,
    store_config: Option<StoreConfigLocator>,
    store_sha256: String,
    pub(crate) authority_descriptor: PathBuf,
    pub(crate) authority_sha256: String,
    daemon_descriptor: Option<PathBuf>,
    pub(crate) daemon_sha256: Option<String>,
    pub(crate) kernel_artifact_sha256: Option<String>,
}

pub(crate) struct PreparedStoreBootstrap {
    pub(crate) requirement: HostStoreBootstrapRequirement,
}

#[allow(
    clippy::too_many_lines,
    reason = "the ordered startup contract is kept in one parser so production cannot accept partially bound contours"
)]
pub(crate) fn parse_launch_options<I>(args: I) -> Result<KernelLaunchOptions, std::io::Error>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => Err(invalid_input("exact Host launch arguments are required")),
        [
            work_flag,
            work_root,
            store_flag,
            descriptor,
            store_digest_flag,
            store_digest,
            authority_flag,
            authority_path,
            authority_digest_flag,
            authority_digest,
            kernel_artifact_flag,
            kernel_artifact_digest,
            daemon_flag,
            daemon_path,
            daemon_digest_flag,
            daemon_digest,
        ] if work_flag == "--work-root"
            && store_flag == "--store-bootstrap"
            && store_digest_flag == "--store-bootstrap-sha256"
            && authority_flag == "--authority-descriptor"
            && authority_digest_flag == "--authority-descriptor-sha256"
            && kernel_artifact_flag == "--kernel-artifact-sha256"
            && daemon_flag == "--eliotd-descriptor"
            && daemon_digest_flag == "--eliotd-descriptor-sha256" =>
        {
            let store_digest = store_digest.to_string_lossy();
            let authority_digest = authority_digest.to_string_lossy();
            let kernel_artifact_digest = kernel_artifact_digest.to_string_lossy();
            let daemon_digest = daemon_digest.to_string_lossy();
            if !is_lower_sha256(&store_digest)
                || !is_lower_sha256(&authority_digest)
                || !is_lower_sha256(&kernel_artifact_digest)
                || !is_lower_sha256(&daemon_digest)
            {
                return Err(invalid_input(
                    "descriptor digests must be lowercase SHA-256",
                ));
            }
            Ok(KernelLaunchOptions {
                work_root: canonical_directory(work_root)?,
                store_config: Some(StoreConfigLocator::NeutralDescriptor(PathBuf::from(
                    descriptor,
                ))),
                store_sha256: store_digest.into_owned(),
                authority_descriptor: PathBuf::from(authority_path),
                authority_sha256: authority_digest.into_owned(),
                daemon_descriptor: Some(PathBuf::from(daemon_path)),
                daemon_sha256: Some(daemon_digest.into_owned()),
                kernel_artifact_sha256: Some(kernel_artifact_digest.into_owned()),
            })
        }
        _ => Err(invalid_input(
            "expected the exact mandatory 16-value Host launch contour",
        )),
    }
}

fn canonical_directory(value: &std::ffi::OsStr) -> Result<PathBuf, std::io::Error> {
    let path = PathBuf::from(value);
    let canonical = std::fs::canonicalize(&path)?;
    if !canonical.is_dir() {
        return Err(invalid_input(
            "configured root must be an existing directory",
        ));
    }
    Ok(canonical)
}

fn invalid_input(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

pub(crate) fn prepare_store_bootstrap(
    options: &KernelLaunchOptions,
) -> Result<Option<PreparedStoreBootstrap>, String> {
    let Some(locator) = &options.store_config else {
        return Ok(None);
    };
    let StoreConfigLocator::NeutralDescriptor(path) = locator;
    let bytes = read_descriptor_bounded(path, &options.work_root)?;
    let expected_digest = options.store_digest();
    if sha256_hex(&bytes) != expected_digest {
        return Err("neutral Store bootstrap descriptor digest mismatch".to_owned());
    }
    let requirement: HostStoreBootstrapRequirement = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse neutral store bootstrap descriptor: {error}"))?;
    requirement
        .validate()
        .map_err(|error| format!("validate neutral store bootstrap descriptor: {error}"))?;
    Ok(Some(PreparedStoreBootstrap { requirement }))
}

pub(crate) fn prepare_eliotd_launch(
    options: &KernelLaunchOptions,
) -> Result<Option<EliotdLaunchDescriptor>, String> {
    let (Some(path), Some(expected_digest)) = (&options.daemon_descriptor, &options.daemon_sha256)
    else {
        return Ok(None);
    };
    let bytes = read_descriptor_bounded(path, &options.work_root)?;
    if sha256_hex(&bytes) != expected_digest.as_str() {
        return Err("eliotd launch descriptor digest mismatch".to_owned());
    }
    let descriptor: EliotdLaunchDescriptor = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse eliotd launch descriptor: {error}"))?;
    descriptor
        .validate()
        .map_err(|error| format!("validate eliotd launch descriptor: {error}"))?;
    Ok(Some(descriptor))
}

impl KernelLaunchOptions {
    fn store_digest(&self) -> &str {
        &self.store_sha256
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn authority_contour(work_root: &Path, path: &Path) -> AuthorityDescriptorContour {
    if path.starts_with(work_root) {
        AuthorityDescriptorContour::PortableCurrentUser {
            root: work_root.to_path_buf(),
        }
    } else {
        AuthorityDescriptorContour::ProgramData
    }
}

#[cfg(windows)]
fn read_descriptor_bounded(path: &Path, work_root: &Path) -> Result<Vec<u8>, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("descriptor path could not be retained: {error}"))?;
    if canonical.starts_with(work_root) {
        let root = UserOwnedRootLease::open_existing(work_root)
            .map_err(|error| format!("user-owned root unavailable: {error}"))?;
        let file = UserOwnedPathLease::open_existing(&root, &canonical)
            .map_err(|error| format!("user-owned descriptor unavailable: {error}"))?;
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .map_err(|error| format!("user-owned descriptor identity changed: {error}"))?;
        file.read_bounded(1024 * 1024)
            .map_err(|error| format!("bounded descriptor read failed: {error}"))
    } else {
        let file = ProtectedRuntimePathLease::open_existing_absolute(&canonical)
            .map_err(|error| format!("protected descriptor unavailable: {error}"))?;
        file.verify_stable_identity()
            .and_then(|()| file.verify_path_identity())
            .map_err(|error| format!("protected descriptor identity changed: {error}"))?;
        file.read_bounded(1024 * 1024)
            .map_err(|error| format!("bounded descriptor read failed: {error}"))
    }
}

#[cfg(not(windows))]
fn read_descriptor_bounded(_path: &Path, _work_root: &Path) -> Result<Vec<u8>, String> {
    Err("authenticated descriptor reads require Windows protected leases".to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "eliot-kernel-options-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(root.join("work")).expect("create test root");
            Self(root)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn launch_args_reject_legacy_ten_value_contour() {
        let root = TempRoot::new();
        let work = root.0.join("work");
        let descriptor_path = root.0.join("store-bootstrap.json");
        let authority_path = root.0.join("authority.json");
        let digest = "a".repeat(64);
        let result = parse_launch_options([
            "--work-root".into(),
            work.clone().into_os_string(),
            "--store-bootstrap".into(),
            descriptor_path.clone().into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            authority_path.clone().into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
        ]);
        assert!(
            result.is_err(),
            "legacy contour must not bypass eliotd binding"
        );

        let _ = (work, descriptor_path, digest);
    }

    #[test]
    fn launch_args_reject_descriptor_contour_without_kernel_artifact_domain() {
        let root = TempRoot::new();
        let digest = "a".repeat(64);
        let result = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            root.0.join("store-bootstrap.json").into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            root.0.join("authority.json").into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            digest.into(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn launch_args_accept_the_explicit_kernel_and_eliotd_artifact_domains() {
        let root = TempRoot::new();
        let digest = "a".repeat(64);
        let options = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            root.0.join("store-bootstrap.json").into_os_string(),
            "--store-bootstrap-sha256".into(),
            digest.clone().into(),
            "--authority-descriptor".into(),
            root.0.join("authority.json").into_os_string(),
            "--authority-descriptor-sha256".into(),
            digest.clone().into(),
            "--kernel-artifact-sha256".into(),
            digest.clone().into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            digest.clone().into(),
        ])
        .expect("integrated args");
        assert_eq!(options.kernel_artifact_sha256, Some(digest));
        assert_eq!(options.daemon_descriptor, Some(root.0.join("eliotd.json")));
    }

    #[test]
    fn descriptor_args_reject_concrete_store_config_flag() {
        let root = TempRoot::new();
        let result = parse_launch_options([
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-config".into(),
            root.0.join("store.json").into_os_string(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn launch_args_reject_case_variants_duplicates_and_reordering() {
        let root = TempRoot::new();
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        let valid: Vec<std::ffi::OsString> = vec![
            "--work-root".into(),
            root.0.join("work").into_os_string(),
            "--store-bootstrap".into(),
            "store.json".into(),
            "--store-bootstrap-sha256".into(),
            digest_a.into(),
            "--authority-descriptor".into(),
            "authority.json".into(),
            "--authority-descriptor-sha256".into(),
            digest_b.into(),
            "--kernel-artifact-sha256".into(),
            "c".repeat(64).into(),
            "--eliotd-descriptor".into(),
            root.0.join("eliotd.json").into_os_string(),
            "--eliotd-descriptor-sha256".into(),
            "d".repeat(64).into(),
        ];
        let mut case_variant = valid.clone();
        case_variant[0] = "--Work-root".into();
        assert!(parse_launch_options(case_variant).is_err());
        let mut reordered = valid.clone();
        reordered.swap(2, 4);
        assert!(parse_launch_options(reordered).is_err());
        let mut duplicate = valid;
        duplicate[6] = "--store-bootstrap".into();
        assert!(parse_launch_options(duplicate).is_err());
    }

    #[cfg(windows)]
    fn exact_startup_values() -> [Option<String>; 10] {
        [
            Some(KERNEL_CONTROL_PIPE.to_owned()),
            Some("41".to_owned()),
            Some("73".to_owned()),
            Some(r"C:\eliot\eliot-host.exe".to_owned()),
            Some(r"C:\ProgramData\Eliot\installations\a\host".to_owned()),
            Some(r"C:\ProgramData\Eliot\installations\a\kernel\state".to_owned()),
            Some("a".repeat(64)),
            Some("b".repeat(64)),
            Some("installation-a".to_owned()),
            Some("generation-a".to_owned()),
        ]
    }

    #[cfg(windows)]
    fn parse_startup_values(values: &[Option<String>; 10]) -> Result<KernelStartupBinding, String> {
        KernelStartupBinding::parse(
            values[0].clone(),
            values[1].clone(),
            values[2].clone(),
            values[3].clone(),
            values[4].clone(),
            values[5].clone(),
            values[6].clone(),
            values[7].clone(),
            values[8].clone(),
            values[9].clone(),
        )
    }

    #[cfg(windows)]
    fn exact_startup_binding() -> KernelStartupBinding {
        parse_startup_values(&exact_startup_values()).expect("exact startup binding")
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_requires_every_exact_launch_value() {
        let exact = exact_startup_values();
        for missing in 0..exact.len() {
            let mut values = exact.clone();
            values[missing] = None;
            assert!(parse_startup_values(&values).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_rejects_substituted_authority_values() {
        for (index, substitute) in [
            (0, r"\\.\pipe\eliot\kernel\substitute".to_owned()),
            (1, "0".to_owned()),
            (2, "0".to_owned()),
            (3, "eliot-host.exe".to_owned()),
            (4, "relative-host-root".to_owned()),
            (5, "relative-ors-root".to_owned()),
            (6, "A".repeat(64)),
            (7, "B".repeat(64)),
            (8, " substituted-installation".to_owned()),
            (9, "substituted-generation\n".to_owned()),
        ] {
            let mut values = exact_startup_values();
            values[index] = Some(substitute);
            assert!(parse_startup_values(&values).is_err(), "index {index}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn kernel_startup_binding_rejects_pid_reuse_and_image_substitution() {
        let binding = exact_startup_binding();
        assert!(binding.matches_observed(41, 73, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(42, 73, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 74, r"C:\eliot\eliot-host.exe"));
        assert!(!binding.matches_observed(41, 73, r"C:\eliot\replacement.exe"));
    }
}
