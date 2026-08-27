//! Test-oracle-only module for `eliot-platform-windows`.
//! Architecture: Windows platform facade (P-01) — test-oracle topology mirrors production modules in `lib.rs` and siblings (`secret_store`, `protected_path`, `installer_root`, etc.).
//! Implementation: Mechanical extraction of the `#[cfg(test)] mod tests { ... }` closure from `lib.rs` (lines ~9212–12827 at pin 2ecd3da). No production logic moved or altered.
//! Authority: Test-only. Explicitly forbids production, semantic, or authority ownership. Production truth remains in `lib.rs` and sibling modules.
//! Verification: Topology verified via `codebase-memory-mcp` projects `eliot-memory-os-44e8b4b-live` and `eliot-architecture-docs-fa941135` (routing only, stale); exact pinned source is authoritative.
//! Policy: No wildcard imports, no new lint allows; existing test-module import/lint policy moves unchanged.
use super::*;
#[cfg(windows)]
use crate::secret_store::{
    HOST_CREDENTIAL_INTERLOCK_TIMEOUT_MS, classify_host_credential_interlock_wait,
};
use crate::secret_store::{
    INSTALLER_CREDENTIAL_TARGET_PREFIX, STORE_CREDENTIAL_TARGET_PREFIX, credential_delete,
    credential_write, installer_credential_target, require_exact_credential_readback,
    valid_credential_key, valid_installer_credential_target,
};

#[cfg(windows)]
#[test]
fn account_name_resolution_returns_os_sid_and_rejects_unknown_account() {
    let sid = resolve_account_sid("NT AUTHORITY\\LocalService")
        .unwrap_or_else(|error| panic!("LocalService lookup failed: {error}"));
    assert_eq!(sid, "S-1-5-19");
    assert!(resolve_account_sid("ELIOT-ACCOUNT-DOES-NOT-EXIST-9D7C").is_err());
    assert!(resolve_account_sid("S-1-5-19").is_err());
}

#[cfg(windows)]
#[test]
fn known_folder_hresult_preserves_the_unsigned_bit_pattern() {
    assert_eq!(
        known_folder_hresult_error(i32::from_ne_bytes(0x8007_0005_u32.to_ne_bytes())),
        ProtectedPathError::Win32 {
            stage: ProtectedPathStage::KnownFolderPath,
            code: 0x8007_0005,
        }
    );
}

#[test]
fn governor_process_basename_matching_is_exact_and_case_insensitive() {
    assert!(process_basename_matches(
        "eliot-governor.exe",
        "eliot-governor.exe"
    ));
    assert!(process_basename_matches(
        "ELIOT-GOVERNOR.EXE",
        "eliot-governor.exe"
    ));
    assert!(!process_basename_matches(
        "other-eliot-governor.exe",
        "eliot-governor.exe"
    ));
    assert!(!process_basename_matches(
        r"C:\evil\eliot-governor.exe.bak",
        "eliot-governor.exe"
    ));
    assert!(!process_basename_matches(
        "eliot-governor.exe.tmp",
        "eliot-governor.exe"
    ));
}

#[test]
fn process_scan_rejects_path_prefixes() {
    assert_eq!(
        any_running_process_named("nested/eliot-governor.exe"),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[test]
fn credential_write_readback_comparison_requires_exact_bytes() {
    let expected = [0x5a; 32];
    assert_eq!(
        require_exact_credential_readback(&expected, Some(&expected)),
        Ok(())
    );
    assert_eq!(
        require_exact_credential_readback(&expected, None),
        Err(WindowsAdapterError::Unavailable)
    );
    assert_eq!(
        require_exact_credential_readback(&expected, Some(&[0x5a; 31])),
        Err(WindowsAdapterError::IdentityMismatch)
    );
    let mut substituted = [0x5a; 32];
    substituted[31] = 0xa5;
    assert_eq!(
        require_exact_credential_readback(&expected, Some(&substituted)),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn credential_interlock_wait_is_bounded_and_timeout_is_typed() {
    use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};

    assert!(std::hint::black_box(HOST_CREDENTIAL_INTERLOCK_TIMEOUT_MS) < u32::MAX);
    assert_eq!(
        classify_host_credential_interlock_wait(WAIT_OBJECT_0),
        Ok(())
    );
    assert_eq!(
        classify_host_credential_interlock_wait(WAIT_TIMEOUT),
        Err(WindowsAdapterError::Timeout)
    );
    assert_eq!(
        classify_host_credential_interlock_wait(WAIT_ABANDONED),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn missing_known_folder_root_is_provisional_absence() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-local-config-absent-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    let config = root.join("config").join("governor.toml");
    let observed = observe_fixed_local_app_data_config(&root, &config, 4096)?;
    assert!(observed.is_provisional_absent());
    Ok(())
}

#[cfg(windows)]
#[test]
fn missing_known_folder_config_directory_is_provisional_absence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-local-config-parent-absent-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir(&root)?;
    let config = root.join("config").join("governor.toml");
    let observed = observe_fixed_local_app_data_config(&root, &config, 4096)?;
    assert!(observed.is_provisional_absent());
    std::fs::remove_dir(&root)?;
    Ok(())
}

#[cfg(windows)]
static PROCESS_JOB_SPAWN_TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

#[cfg(windows)]
fn process_job_spawn_test_guard() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_JOB_SPAWN_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(windows)]
fn test_lease(
    root: &Path,
    relative: &Path,
    create: bool,
) -> Result<ProtectedPathLease, ProtectedPathError> {
    let components = protected_components(relative)?;
    let parent =
        components[..components.len() - 1]
            .iter()
            .fold(PathBuf::new(), |mut path, component| {
                path.push(component);
                path
            });
    let mut current = root.to_path_buf();
    let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
    for component in parent.components() {
        current.push(component.as_os_str());
        let directory = match pin_directory(&current) {
            Ok(directory) => directory,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|_| ProtectedPathError::Io)?;
                pin_directory(&current).map_err(|_| ProtectedPathError::Io)?
            }
            Err(_) => return Err(ProtectedPathError::Io),
        };
        directories.push(directory);
    }
    let file_path = root.join(relative);
    let file = crate::protected_path::open_protected_file(&file_path, create)?;
    let identity = file_identity_from_handle(&file).map_err(|_| ProtectedPathError::Io)?;
    Ok(ProtectedPathLease {
        path: file_path,
        identity,
        _directories: directories,
        file,
    })
}

#[cfg(windows)]
fn test_root_lease(root: &Path, relative: &Path) -> Result<ProtectedRootLease, ProtectedPathError> {
    let mut current = root.to_path_buf();
    let mut directories = vec![pin_directory(root).map_err(|_| ProtectedPathError::Io)?];
    for component in relative.components() {
        current.push(component.as_os_str());
        directories.push(pin_directory(&current).map_err(|_| ProtectedPathError::Io)?);
    }
    let retained = directories.last().ok_or(ProtectedPathError::InvalidPath)?;
    let identity = file_identity_from_handle(retained).map_err(|_| ProtectedPathError::Io)?;
    Ok(ProtectedRootLease {
        path: current,
        identity,
        directories,
    })
}

#[cfg(windows)]
fn directory_security_descriptor_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    let handle = pin_directory(path).unwrap_or_else(|error| panic!("directory open: {error}"));
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: retained handle is live and descriptor output is a valid local.
        GetSecurityInfo(
            handle.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    assert!(!descriptor.is_null());
    let length = unsafe {
        // SAFETY: descriptor was returned by GetSecurityInfo and is live.
        GetSecurityDescriptorLength(descriptor)
    };
    let length = usize::try_from(length).unwrap_or_else(|_| unreachable!());
    let bytes = unsafe {
        // SAFETY: the reported descriptor length bounds this copied slice.
        std::slice::from_raw_parts(descriptor.cast::<u8>(), length).to_vec()
    };
    unsafe {
        // SAFETY: descriptor is released exactly once after copying.
        LocalFree(descriptor.cast());
    }
    bytes
}

#[test]
fn rejects_relative_and_reparse_roots() {
    assert!(validate_root(Path::new("relative")).is_err());
}

#[test]
fn atomic_suffix_is_nonempty_and_not_secret_derived() {
    assert!(!unique_suffix().is_empty());
}

#[cfg(windows)]
#[test]
fn activation_nonce_has_256_bit_lowercase_hex_shape() {
    let nonce = fresh_activation_nonce().unwrap_or_else(|error| panic!("nonce failed: {error}"));
    let value = nonce.as_str();
    assert!(value.starts_with(ACTIVATION_NONCE_PREFIX));
    assert_eq!(
        value.len(),
        ACTIVATION_NONCE_PREFIX.len() + ACTIVATION_NONCE_HEX_BYTES
    );
    assert_eq!(ACTIVATION_NONCE_RANDOM_BYTES * 8, 256);
    assert!(
        value[ACTIVATION_NONCE_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[cfg(windows)]
#[test]
fn activation_nonce_material_is_exact_canonical_64_hex() {
    let first = fresh_activation_nonce_material()
        .unwrap_or_else(|error| panic!("raw nonce failed: {error}"));
    let second = fresh_activation_nonce_material()
        .unwrap_or_else(|error| panic!("raw nonce failed: {error}"));
    assert_eq!(first.as_str().len(), 64);
    assert!(
        first
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_ne!(first, second);
}

#[cfg(windows)]
#[test]
fn typed_activation_nonce_has_canonical_shape_and_redacted_formatting() {
    let nonce = fresh_kernel_activation_nonce()
        .unwrap_or_else(|error| panic!("typed nonce failed: {error}"));
    let material = nonce.as_handle().as_str();
    assert_eq!(material.len(), 64);
    assert!(
        material
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let debug = format!("{nonce:?}");
    let display = format!("{nonce}");
    assert_eq!(debug, "KernelActivationNonce(<redacted>)");
    assert_eq!(display, "<redacted>");
    assert!(!debug.contains(material));
    assert!(!display.contains(material));
}

#[cfg(windows)]
#[test]
fn final_handle_paths_drop_verbatim_prefixes_before_contract_comparison() {
    assert_eq!(
        normalize_final_windows_path_text(r"\\?\C:\ProgramData\Eliot")
            .unwrap_or_else(|error| panic!("DOS path normalization failed: {error}")),
        PathBuf::from(r"C:\ProgramData\Eliot")
    );
    assert_eq!(
        normalize_final_windows_path_text(r"\\?\UNC\server\share\Eliot")
            .unwrap_or_else(|error| panic!("UNC path normalization failed: {error}")),
        PathBuf::from(r"\\server\share\Eliot")
    );

    let directory = std::env::temp_dir().join("eliot-canonical-contract-path-test");
    std::fs::create_dir_all(&directory)
        .unwrap_or_else(|error| panic!("fixture creation failed: {error}"));
    let canonical = canonical_windows_path(&directory)
        .unwrap_or_else(|error| panic!("canonicalization failed: {error}"));
    assert!(canonical.is_absolute());
    assert!(!canonical.to_string_lossy().starts_with(r"\\?\"));
}

#[cfg(windows)]
#[test]
fn known_folder_anchors_ignore_environment_substitution() {
    let original_program_data = std::env::var_os("ProgramData");
    let original_local_app_data = std::env::var_os("LOCALAPPDATA");
    unsafe {
        // SAFETY: the values are restored before assertions or panics.
        std::env::set_var("ProgramData", r"C:\attacker-selected-program-data");
        std::env::set_var("LOCALAPPDATA", r"C:\attacker-selected-local-app-data");
    }
    let observed_program_data = protected_program_data_root();
    let observed_local_app_data = current_user_local_app_data_root();
    unsafe {
        // SAFETY: restore this process's exact pre-test environment state.
        match original_program_data {
            Some(value) => std::env::set_var("ProgramData", value),
            None => std::env::remove_var("ProgramData"),
        }
        match original_local_app_data {
            Some(value) => std::env::set_var("LOCALAPPDATA", value),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
    }
    let observed_program_data = observed_program_data
        .unwrap_or_else(|error| panic!("ProgramData known-folder lookup failed: {error}"));
    let observed_local_app_data = observed_local_app_data
        .unwrap_or_else(|error| panic!("LocalAppData known-folder lookup failed: {error}"));
    assert_ne!(
        observed_program_data,
        PathBuf::from(r"C:\attacker-selected-program-data")
    );
    assert_ne!(
        observed_local_app_data,
        PathBuf::from(r"C:\attacker-selected-local-app-data")
    );
}

#[cfg(windows)]
#[test]
fn sequential_activation_nonces_are_distinct() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..256 {
        let nonce = fresh_activation_nonce()
            .unwrap_or_else(|error| panic!("nonce issuance failed: {error}"));
        assert!(seen.insert(nonce.as_str().to_owned()));
    }
}

#[cfg(windows)]
#[test]
fn store_targets_have_exact_shape_and_distinctness() {
    let generator = WindowsStoreCredentialTargetGenerator::new();
    let installer = WindowsInstallerSecretProvider::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..256 {
        let target = generator
            .fresh_target()
            .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"));
        assert!(target.as_str().starts_with(STORE_CREDENTIAL_TARGET_PREFIX));
        let token = target
            .as_str()
            .strip_prefix(STORE_CREDENTIAL_TARGET_PREFIX)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(token.len(), 32);
        assert!(
            token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(seen.insert(target.as_str().to_owned()));
    }

    let installer_target = installer
        .fresh_reference()
        .unwrap_or_else(|error| panic!("installer target issuance failed: {error}"));
    assert!(
        installer_target
            .as_str()
            .starts_with(INSTALLER_CREDENTIAL_TARGET_PREFIX)
    );
    assert_ne!(
        installer_target.as_str(),
        generator
            .fresh_target()
            .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"))
            .as_str()
    );
    let activation_target = fresh_activation_nonce()
        .unwrap_or_else(|error| panic!("activation target issuance failed: {error}"));
    assert!(activation_target.as_str().starts_with("eliot-activation-"));
    assert_ne!(
        activation_target.as_str(),
        generator
            .fresh_target()
            .unwrap_or_else(|error| panic!("Store target issuance failed: {error}"))
            .as_str()
    );
}

#[test]
fn rejects_component_traversal_and_control() {
    assert!(validate_component("../outside").is_err());
    assert!(validate_component("state\0.bin").is_err());
    assert!(valid_credential_key("nested/ok-key"));
    assert!(!valid_credential_key("../outside"));
    assert!(installer_credential_target(
        "eliot/installer-root/v1/0123456789abcdef"
    ));
    assert!(valid_installer_credential_target(
        "eliot/installer-root/v1/0123456789abcdef0123456789abcdef"
    ));
    assert!(!valid_installer_credential_target(
        "eliot/installer-root/v1/0123456789ABCDEF0123456789ABCDEF"
    ));
    assert!(!valid_installer_credential_target(
        "eliot/installer-root/v1/short"
    ));
    assert!(!installer_credential_target("runtime/dispatch-key"));
}

#[test]
fn free_space_observation_rejects_relative_path_as_unknown_input() {
    assert_eq!(
        observe_volume_free_space(Path::new("relative")),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn free_space_observation_reads_real_current_volume() {
    let current = std::env::current_dir().unwrap_or_else(|_| unreachable!());
    let available = observe_volume_free_space(&current)
        .unwrap_or_else(|error| panic!("free-space observation failed: {error}"));
    assert!(available > 0);
}

#[test]
fn protected_program_data_path_rejects_substitution_inputs() {
    assert_eq!(
        protected_program_data_path(Path::new("../outside")),
        Err(ProtectedPathError::InvalidPath)
    );
    #[cfg(windows)]
    assert_eq!(
        protected_program_data_path(Path::new("C:/outside")),
        Err(ProtectedPathError::InvalidPath)
    );
    #[cfg(not(windows))]
    assert_eq!(
        protected_program_data_path(Path::new("C:/outside")),
        Err(ProtectedPathError::UnsupportedPlatform)
    );
}

#[cfg(windows)]
#[test]
fn retained_process_lease_rejects_identity_or_digest_substitution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("eliot-process-lease-{}", unique_suffix()));
    let working = root.join("work");
    let executable = root.join("worker.bin");
    std::fs::create_dir_all(&working)?;
    let original = b"original executable bytes";
    std::fs::write(&executable, original)?;
    let platform = WindowsPlatform::new(&root)?;
    let digest = sha256_hex(original);
    let lease = platform.retain_process_path_lease(&executable, &working, &digest)?;

    assert!(std::fs::write(&executable, b"substituted executable bytes").is_err());
    assert!(lease.validate(&executable, &working, &digest).is_ok());
    assert!(
        lease
            .validate(
                &executable,
                &working,
                &sha256_hex(b"substituted executable bytes")
            )
            .is_err()
    );
    assert!(
        lease
            .validate(&executable, &root.join("other"), &digest)
            .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn permission_denied_is_explicit_and_not_retryable() {
    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let provider = provider_from_io(&error);
    assert_eq!(
        provider.code,
        eliot_platform::ProviderErrorCode::PermissionDenied
    );
    assert!(!provider.retryable);
}

#[test]
fn containment_is_component_wise_not_prefix_wise() {
    let root = Path::new("C:/work/root");
    assert!(validate_containment(root, Path::new("C:/work/root/file")).is_ok());
    assert!(validate_containment(root, Path::new("C:/work/root-sibling/file")).is_err());
}

#[test]
fn wrong_session_is_not_observed() {
    assert!(!session_matches(7, 8));
    assert!(session_matches(7, 7));
}

#[test]
fn notification_text_is_bounded_and_nul_terminated() {
    let mut buffer = [0_u16; 8];
    fill_utf16(&mut buffer, "Eliot notification text");
    assert_eq!(buffer[7], 0);
    assert_eq!(String::from_utf16_lossy(&buffer[..7]), "Eliot n");
}

#[cfg(windows)]
#[test]
fn watchdog_task_readback_rejects_structural_substitution() {
    let registration = WatchdogTaskRegistration::new(
        WATCHDOG_FALLBACK_TASK_NAME,
        r"C:\Eliot\eliot-notify.exe",
        r"C:\ProgramData\Eliot\watchdog-verifier.json",
        r"C:\ProgramData\Eliot\watchdog-envelope.json",
        "S-1-5-21-1",
        7,
        "00".repeat(32),
        "11".repeat(32),
    )
    .unwrap_or_else(|_| unreachable!());
    let xml = watchdog_task_xml(&registration);
    assert!(watchdog_task_readback_matches(&registration, &xml));

    let extra_action = xml.replace(
        "</Actions>",
        "<Exec><Command>evil.exe</Command></Exec></Actions>",
    );
    assert!(!watchdog_task_readback_matches(
        &registration,
        &extra_action
    ));

    let extra_trigger = xml.replace(
        "</Triggers>",
        "<TimeTrigger><Enabled>true</Enabled></TimeTrigger></Triggers>",
    );
    assert!(!watchdog_task_readback_matches(
        &registration,
        &extra_trigger
    ));

    let extra_principal = xml.replace(
        "</Principals>",
        "<Principal id=\"Substitute\"><UserId>S-1-5-21-9</UserId></Principal></Principals>",
    );
    assert!(!watchdog_task_readback_matches(
        &registration,
        &extra_principal
    ));

    let extra_setting = xml.replace(
        "</Settings>",
        "<UnknownSetting>true</UnknownSetting></Settings>",
    );
    assert!(!watchdog_task_readback_matches(
        &registration,
        &extra_setting
    ));

    let changed_action = xml.replace(
        "<Arguments>--watchdog-fallback</Arguments>",
        "<Arguments>--changed</Arguments>",
    );
    assert!(!watchdog_task_readback_matches(
        &registration,
        &changed_action
    ));
}

#[test]
fn post_commit_identity_failure_is_typed_unknown() {
    let unknown = PublicationUnknownReceipt {
        reason: PublicationUnknown::PostCommitIdentityUnavailable,
        expected_identity: FileIdentity {
            volume_serial_number: 1,
            file_index: 2,
        },
    };
    assert_eq!(
        PublicationOutcome::Unknown(unknown.clone()),
        PublicationOutcome::Unknown(unknown)
    );
}

#[cfg(windows)]
#[test]
fn test_support_unknown_publication_retains_exact_reopen_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-platform-receipt-root-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&root)?;
    let root_override = test_support::override_protected_root(&root);
    let host = root.join("host");
    prepare_protected_directory(&host)?;
    let path = host.join("eliotd-receipt.json");
    test_support::force_next_owned_runtime_receipt_unknown();
    let PublicationOutcome::Unknown(unknown) =
        publish_atomic_owned_runtime_receipt(&path, b"receipt", None)?
    else {
        panic!("failpoint must preserve unknown outcome");
    };
    let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    assert_eq!(lease.identity(), unknown.expected_identity);
    assert_eq!(lease.read_bounded(64)?, b"receipt");
    drop(lease);
    drop(root_override);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_owned_receipt_publication_enforces_identity_and_content_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-platform-receipt-cas-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&root)?;
    let root_override = test_support::override_protected_root(&root);
    let host = root.join("host");
    prepare_protected_directory(&host)?;
    let path = host.join("eliotd-receipt.json");

    let PublicationOutcome::Published(first) =
        publish_atomic_owned_runtime_receipt(&path, b"receipt-v1", None)?
    else {
        panic!("first publication must be classified");
    };
    let first_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    assert_eq!(first_lease.identity(), first.identity);
    let first_bytes = first_lease.read_bounded(64)?;
    let precondition = PublicationPrecondition::from_bytes(first.identity, &first_bytes);
    drop(first_lease);

    let PublicationOutcome::Published(second) =
        publish_atomic_owned_runtime_receipt(&path, b"receipt-v2", Some(&precondition))?
    else {
        panic!("compare-and-swap publication must be classified");
    };
    assert_ne!(second.identity, first.identity);
    let second_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    assert_eq!(second_lease.identity(), second.identity);
    assert_eq!(second_lease.read_bounded(64)?, b"receipt-v2");
    drop(second_lease);

    let Err(error) =
        publish_atomic_owned_runtime_receipt(&path, b"receipt-v3", Some(&precondition))
    else {
        panic!("stale compare-and-swap must fail closed");
    };
    assert_eq!(error, PortError::IdentityConflict);
    let final_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    assert_eq!(final_lease.read_bounded(64)?, b"receipt-v2");
    drop(final_lease);
    drop(root_override);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn exclusive_runtime_read_lease_blocks_writers() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-platform-exclusive-lease-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&root)?;
    let root_override = test_support::override_protected_root(&root);
    let host = root.join("host");
    prepare_protected_directory(&host)?;
    let path = host.join("generation.json");
    std::fs::write(&path, b"generation")?;

    let lease = ProtectedRuntimePathLease::open_existing_absolute_exclusive(&path)?;
    assert_eq!(lease.read_bounded(64)?, b"generation");
    assert!(
        std::fs::write(&path, b"tampered").is_err(),
        "exclusive lease must deny a competing writer"
    );
    drop(lease);
    drop(root_override);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn concurrent_owned_receipt_create_is_atomic_no_replace() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!(
        "eliot-platform-receipt-create-race-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&root)?;
    let root_override = test_support::override_protected_root(&root);
    let host = root.join("host");
    prepare_protected_directory(&host)?;
    drop(root_override);

    let path = host.join("eliotd-receipt.json");
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for bytes in [b"create-race-a".as_slice(), b"create-race-b".as_slice()] {
        let root = root.clone();
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let bytes = bytes.to_vec();
        threads.push(std::thread::spawn(move || {
            let _root_override = test_support::override_protected_root(&root);
            barrier.wait();
            let outcome = publish_atomic_owned_runtime_receipt(&path, &bytes, None);
            (bytes, outcome)
        }));
    }
    barrier.wait();

    let mut published = 0;
    let mut conflicts = 0;
    let mut published_bytes = None;
    for thread in threads {
        let Ok((bytes, outcome)) = thread.join() else {
            panic!("publisher thread panicked");
        };
        match outcome {
            Ok(PublicationOutcome::Published(_)) => {
                published += 1;
                published_bytes = Some(bytes);
            }
            Err(PortError::IdentityConflict) => conflicts += 1,
            other => panic!("unexpected create-race outcome: {other:?}"),
        }
    }
    assert_eq!(published, 1);
    assert_eq!(conflicts, 1);
    let committed = std::fs::read(&path)?;
    let Some(published_bytes) = published_bytes else {
        panic!("one published value");
    };
    assert_eq!(committed, published_bytes);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn concurrent_owned_receipt_substitution_preserves_exact_predecessor_cas()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "eliot-platform-receipt-replace-race-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    std::fs::create_dir_all(&root)?;
    let root_override = test_support::override_protected_root(&root);
    let host = root.join("host");
    prepare_protected_directory(&host)?;
    let path = host.join("eliotd-receipt.json");
    let PublicationOutcome::Published(initial) =
        publish_atomic_owned_runtime_receipt(&path, b"predecessor", None)?
    else {
        panic!("initial publication must be known");
    };
    let initial_lease = ProtectedRuntimePathLease::open_existing_absolute(&path)?;
    let initial_bytes = initial_lease.read_bounded(64)?;
    let precondition = PublicationPrecondition::from_bytes(initial.identity, &initial_bytes);
    drop(initial_lease);
    drop(root_override);

    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for bytes in [b"replace-race-a".as_slice(), b"replace-race-b".as_slice()] {
        let root = root.clone();
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let precondition = precondition.clone();
        let bytes = bytes.to_vec();
        threads.push(std::thread::spawn(move || {
            let _root_override = test_support::override_protected_root(&root);
            barrier.wait();
            let outcome = publish_atomic_owned_runtime_receipt(&path, &bytes, Some(&precondition));
            (bytes, outcome)
        }));
    }
    barrier.wait();

    let mut published = 0;
    let mut conflicts = 0;
    let mut published_bytes = None;
    for thread in threads {
        let Ok((bytes, outcome)) = thread.join() else {
            panic!("publisher thread panicked");
        };
        match outcome {
            Ok(PublicationOutcome::Published(_)) => {
                published += 1;
                published_bytes = Some(bytes);
            }
            Err(PortError::IdentityConflict) => conflicts += 1,
            other => panic!("unexpected replacement-race outcome: {other:?}"),
        }
    }
    assert_eq!(published, 1);
    assert_eq!(conflicts, 1);
    let committed = std::fs::read(&path)?;
    let Some(published_bytes) = published_bytes else {
        panic!("one published value");
    };
    assert_eq!(committed, published_bytes);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn durable_identity_types_reject_unknown_fields() {
    let result = serde_json::from_str::<FileIdentity>(
        r#"{"volume_serial_number":1,"file_index":2,"extra":3}"#,
    );
    assert!(result.is_err());
    let result = serde_json::from_str::<ProcessIdentity>(
        r#"{"process_id":1,"start_time_100ns":2,"image_path":"x","extra":3}"#,
    );
    assert!(result.is_err());
}

#[test]
fn unsupported_secret_provider_never_routes_to_credential_manager() {
    assert!(!is_windows_secret_provider("arbitrary-provider"));
    assert!(is_windows_secret_provider("windows-credential-manager"));
}

#[test]
fn pipe_expectation_rejects_caller_shaped_non_sid_values() {
    assert_eq!(
        NamedPipePeerExpectation::new("current-user", 1),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[test]
fn agent_bridge_sid_parser_rejects_noncanonical_components() {
    assert!(valid_sid_text("S-1-5-19"));
    assert!(!valid_sid_text("S-1-05-19"));
    assert!(!valid_sid_text("S-1-5--19"));
    assert!(!valid_sid_text("S-1-5-19-"));
    assert!(!valid_sid_text("S-1-5-19-4294967296"));
    assert!(!valid_sid_text("S-1-18446744073709551616"));
    assert!(!valid_service_sid_text("S-1-5-80-01-2-3-4-5"));
}

#[test]
fn named_pipe_expectations_select_ordinary_or_admin_auth_discriminator() {
    let ordinary = NamedPipePeerExpectation::new("S-1-5-19", 1).unwrap_or_else(|_| unreachable!());
    let admin = NamedPipePeerExpectation::new_for_builtin_administrators()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        ordinary.auth_discriminator(),
        NamedPipeAuthDiscriminator::Ordinary
    );
    assert_eq!(
        admin.auth_discriminator(),
        NamedPipeAuthDiscriminator::BuiltinAdministrators
    );
}

#[cfg(windows)]
#[test]
fn current_process_builtin_administrator_membership_is_read_only_observable() {
    assert!(is_process_builtin_administrator().is_ok());
}

#[test]
fn installer_control_pipe_dacl_allows_only_system_admin_and_local_service() {
    for expected in ["S-1-5-19", "S-1-5-32-544"] {
        for observed in ["S-1-5-18", "S-1-5-32-544", "S-1-5-19"] {
            assert!(pipe_dacl_principal_allowed(expected, observed));
        }
        assert!(!pipe_dacl_principal_allowed(expected, "S-1-5-20"));
        assert!(!pipe_dacl_principal_allowed(expected, "S-1-5-21-1000"));
    }
    assert!(!pipe_dacl_principal_allowed("S-1-5-21-1000", "S-1-5-19"));
}

#[test]
fn peer_set_acl_rejects_broad_inherited_non_allow_and_substituted_entries() {
    assert!(validate_peer_set_ace_fields(0, 0, PEER_SET_GENERIC_ALL_MAPPED).is_ok());
    assert!(validate_peer_set_ace_fields(0, 0, 0x0002_0000).is_err());
    assert!(validate_peer_set_ace_fields(0, 0x10, PEER_SET_GENERIC_ALL_MAPPED).is_err());
    assert!(validate_peer_set_ace_fields(1, 0, PEER_SET_GENERIC_ALL_MAPPED).is_err());

    let expected = ["S-1-5-18", "S-1-5-21-1000"];
    let valid = vec!["S-1-5-18".to_owned(), "S-1-5-21-1000".to_owned()];
    assert!(validate_peer_set_sids(&expected, &valid).is_ok());
    assert!(
        validate_peer_set_sids(&expected, &["S-1-5-18".to_owned(), "S-1-5-18".to_owned()]).is_err()
    );
    assert!(
        validate_peer_set_sids(
            &expected,
            &["S-1-5-21-1000".to_owned(), "S-1-5-21-1000".to_owned()]
        )
        .is_err()
    );
    assert!(validate_peer_set_sids(&expected, &["S-1-5-18".to_owned()]).is_err());
    assert!(
        validate_peer_set_sids(
            &expected,
            &[
                "S-1-5-18".to_owned(),
                "S-1-5-21-1000".to_owned(),
                "S-1-5-21-1001".to_owned(),
            ]
        )
        .is_err()
    );
    assert!(
        validate_peer_set_sids(
            &expected,
            &["S-1-5-18".to_owned(), "S-1-5-21-1001".to_owned()]
        )
        .is_err()
    );
}

#[cfg(windows)]
fn test_process_binding() -> NamedPipePeerProcessBinding {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    observe_named_pipe_peer_process(unsafe { GetCurrentProcessId() })
        .unwrap_or_else(|_| unreachable!())
}

#[cfg(windows)]
fn test_process_expectation(binding: NamedPipePeerProcessBinding) -> NamedPipePeerExpectation {
    current_process_named_pipe_expectation()
        .unwrap_or_else(|_| unreachable!())
        .with_process_binding(binding)
        .unwrap_or_else(|_| unreachable!())
}

#[cfg(windows)]
#[test]
fn pipe_expectation_admits_only_sealed_live_process_binding() {
    let binding = test_process_binding();
    let observed = binding.identity().clone();
    let expectation = test_process_expectation(binding.clone());
    assert_eq!(expectation.approved_process_binding(), Some(&binding));
    assert_eq!(
        admit_named_pipe_peer_process(&observed, &expectation),
        Ok(())
    );
}

#[cfg(windows)]
#[test]
fn pipe_job_binding_rejects_process_substitution_and_stale_job() {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    let process = test_process_binding();
    let job = observe_named_pipe_peer_process_in_job(r"Local\Eliot-Missing-Store-Job", unsafe {
        GetCurrentProcessId()
    });
    assert!(job.is_err());

    let sealed =
        NamedPipePeerJobBinding::from_observed(process.clone(), r"Local\Eliot-Missing-Store-Job")
            .unwrap_or_else(|_| unreachable!());
    let expectation = current_process_named_pipe_expectation()
        .unwrap_or_else(|_| unreachable!())
        .with_process_and_job_binding(sealed)
        .unwrap_or_else(|_| unreachable!());
    let mut wrong_start = process.identity().clone();
    wrong_start.start_time_100ns = wrong_start.start_time_100ns.saturating_add(1);
    assert_eq!(
        admit_named_pipe_peer_process(&wrong_start, &expectation),
        Err(WindowsAdapterError::IdentityMismatch)
    );
    assert!(admit_named_pipe_peer_process(process.identity(), &expectation).is_err());
}

#[cfg(windows)]
#[test]
fn pipe_expectation_rejects_wrong_pid() {
    let binding = test_process_binding();
    let approved = binding.identity().clone();
    let observed = ProcessIdentity {
        process_id: approved.process_id + 1,
        ..approved.clone()
    };
    let expectation = test_process_expectation(binding);
    assert_eq!(
        admit_named_pipe_peer_process(&observed, &expectation),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn pipe_expectation_rejects_pid_reuse_by_start_time() {
    let binding = test_process_binding();
    let approved = binding.identity().clone();
    let observed = ProcessIdentity {
        start_time_100ns: approved.start_time_100ns + 1,
        ..approved.clone()
    };
    let expectation = test_process_expectation(binding);
    assert_eq!(
        admit_named_pipe_peer_process(&observed, &expectation),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn pipe_expectation_rejects_wrong_image_identity() {
    let binding = test_process_binding();
    let approved = binding.identity().clone();
    let observed = ProcessIdentity {
        image_path: r"C:\Windows\System32\other.exe".to_owned(),
        ..approved.clone()
    };
    let expectation = test_process_expectation(binding);
    assert_eq!(
        admit_named_pipe_peer_process(&observed, &expectation),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn pipe_identity_accepts_only_equivalent_normalized_windows_paths() {
    let binding = test_process_binding();
    let approved = binding.identity().clone();
    let expectation = test_process_expectation(binding);
    for image_path in [
        approved.image_path.to_ascii_lowercase(),
        approved.image_path.replace('\\', "/"),
    ] {
        let observed = ProcessIdentity {
            image_path,
            ..approved.clone()
        };
        assert!(same_process_identity(&observed, &approved));
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Ok(())
        );
    }
    if approved.image_path.as_bytes().get(1) == Some(&b':') {
        let observed = ProcessIdentity {
            image_path: format!(r"\\?\{}", approved.image_path),
            ..approved.clone()
        };
        assert!(same_process_identity(&observed, &approved));
    }
}

#[cfg(windows)]
#[test]
fn pipe_identity_rejects_malformed_image_paths() {
    let binding = test_process_binding();
    let approved = binding.identity().clone();
    let expectation = test_process_expectation(binding);
    for image_path in ["relative.exe", r"\\.\C:\Windows\System32\device.exe"] {
        let observed = ProcessIdentity {
            image_path: image_path.to_owned(),
            ..approved.clone()
        };
        assert_eq!(
            admit_named_pipe_peer_process(&observed, &expectation),
            Err(WindowsAdapterError::IdentityMismatch)
        );
    }
}

#[cfg(windows)]
#[test]
fn pipe_expectation_preserves_sid_session_only_legacy_behavior() {
    let expectation = current_process_named_pipe_expectation().unwrap_or_else(|_| unreachable!());
    let observed = test_process_binding().identity().clone();
    assert!(expectation.approved_process_binding().is_none());
    assert_eq!(
        admit_named_pipe_peer_process(&observed, &expectation),
        Ok(())
    );
}

#[cfg(any(test, feature = "test-support"))]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one bounded matrix covers role selection and every identity substitution"
)]
fn sealed_peer_set_selects_one_role_and_rejects_substitution_or_ambiguity() {
    let process = ProcessIdentity {
        process_id: 41,
        start_time_100ns: 99,
        image_path: r"C:\Eliot\eliot-agent-bridge.exe".to_owned(),
    };
    let file = FileIdentity {
        volume_serial_number: 7,
        file_index: 11,
    };
    let expectation = NamedPipePeerExpectation::new_for_dynamic_process(
        "S-1-5-21-1000",
        &process.image_path,
        file,
    )
    .unwrap_or_else(|_| unreachable!());
    let bridge = NamedPipePeerProfile::new(
        NamedPipePeerKind::AgentBridge,
        expectation.clone(),
        Some("profile-1".to_owned()),
    )
    .unwrap_or_else(|_| unreachable!());
    let host = NamedPipePeerProfile::new(
        NamedPipePeerKind::Host,
        NamedPipePeerExpectation::new_with_process_binding(
            "S-1-5-19",
            4,
            NamedPipePeerProcessBinding::for_test(process.clone(), Some(file))
                .unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!()),
        None,
    )
    .unwrap_or_else(|_| unreachable!());
    let set = NamedPipePeerSet::new(vec![bridge, host]).unwrap_or_else(|_| unreachable!());
    let evidence = NamedPipePeerEvidence::for_test(
        process.clone(),
        "S-1-5-21-1000",
        4,
        Some(file),
        None,
        false,
        true,
    )
    .unwrap_or_else(|_| unreachable!());
    let selected = set.select(&evidence).unwrap_or_else(|_| unreachable!());
    assert_eq!(selected.kind(), NamedPipePeerKind::AgentBridge);
    assert_eq!(selected.module_id(), "eliot-agent-bridge");
    assert_eq!(selected.profile_id(), Some("profile-1"));

    let wrong_file = NamedPipePeerEvidence::for_test(
        process.clone(),
        "S-1-5-21-1000",
        4,
        Some(FileIdentity {
            volume_serial_number: 7,
            file_index: 12,
        }),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(set.select(&wrong_file).is_err());

    for (sid, session_id, process) in [
        ("S-1-5-21-1001", 4, process.clone()),
        ("S-1-5-21-1000", 5, process.clone()),
        (
            "S-1-5-21-1000",
            4,
            ProcessIdentity {
                process_id: process.process_id.saturating_add(1),
                ..process.clone()
            },
        ),
        (
            "S-1-5-21-1000",
            4,
            ProcessIdentity {
                start_time_100ns: process.start_time_100ns.saturating_add(1),
                ..process.clone()
            },
        ),
        (
            "S-1-5-21-1000",
            4,
            ProcessIdentity {
                image_path: r"C:\Eliot\other.exe".to_owned(),
                ..process.clone()
            },
        ),
    ] {
        let substituted = NamedPipePeerEvidence::for_test(
            process,
            sid,
            session_id,
            Some(file),
            None,
            false,
            false,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(set.select(&substituted).is_err());
    }

    let admin = NamedPipePeerProfile::new(
        NamedPipePeerKind::Host,
        NamedPipePeerExpectation::new_for_builtin_administrators()
            .unwrap_or_else(|_| unreachable!())
            .with_process_binding(
                NamedPipePeerProcessBinding::for_test(process.clone(), Some(file))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!()),
        None,
    )
    .unwrap_or_else(|_| unreachable!());
    let admin_set = NamedPipePeerSet::new(vec![admin]).unwrap_or_else(|_| unreachable!());
    assert!(admin_set.select(&evidence).is_err());
    let admin_evidence =
        NamedPipePeerEvidence::for_test(process, "S-1-5-21-1000", 4, Some(file), None, true, false)
            .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        admin_set
            .select(&admin_evidence)
            .unwrap_or_else(|_| unreachable!())
            .kind(),
        NamedPipePeerKind::Host
    );

    let duplicate = NamedPipePeerSet::new(vec![
        NamedPipePeerProfile::new(
            NamedPipePeerKind::AgentBridge,
            expectation,
            Some("profile-2".to_owned()),
        )
        .unwrap_or_else(|_| unreachable!()),
        NamedPipePeerProfile::new(
            NamedPipePeerKind::AgentBridge,
            NamedPipePeerExpectation::new_for_dynamic_process(
                "S-1-5-21-1000",
                r"C:\Eliot\eliot-agent-bridge.exe",
                file,
            )
            .unwrap_or_else(|_| unreachable!()),
            Some("profile-3".to_owned()),
        )
        .unwrap_or_else(|_| unreachable!()),
    ]);
    assert!(duplicate.is_err());
}

#[cfg(any(test, feature = "test-support"))]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one reconnect matrix covers dynamic and mixed static peer behavior"
)]
fn dynamic_bridge_profile_rebinds_pid_start_and_session_but_pins_sid_image_and_file() {
    let image_path = r"C:\Eliot\eliot-agent-bridge.exe";
    let file = FileIdentity {
        volume_serial_number: 7,
        file_index: 11,
    };
    let expectation =
        NamedPipePeerExpectation::new_for_dynamic_process("S-1-5-21-1000", image_path, file)
            .unwrap_or_else(|_| unreachable!());
    let profile = NamedPipePeerProfile::new(
        NamedPipePeerKind::AgentBridge,
        expectation,
        Some("profile-1".to_owned()),
    )
    .unwrap_or_else(|_| unreachable!());
    let set = NamedPipePeerSet::new(vec![profile]).unwrap_or_else(|_| unreachable!());

    let host_binding = NamedPipePeerProcessBinding::for_test(
        ProcessIdentity {
            process_id: 41,
            start_time_100ns: 99,
            image_path: image_path.to_owned(),
        },
        Some(file),
    )
    .unwrap_or_else(|_| unreachable!());
    let host = NamedPipePeerProfile::new(
        NamedPipePeerKind::Host,
        NamedPipePeerExpectation::new_with_process_binding("S-1-5-19", 0, host_binding)
            .unwrap_or_else(|_| unreachable!()),
        None,
    )
    .unwrap_or_else(|_| unreachable!());
    let mixed = NamedPipePeerSet::new(vec![
        NamedPipePeerProfile::new(
            NamedPipePeerKind::AgentBridge,
            NamedPipePeerExpectation::new_for_dynamic_process("S-1-5-21-1000", image_path, file)
                .unwrap_or_else(|_| unreachable!()),
            Some("profile-mixed".to_owned()),
        )
        .unwrap_or_else(|_| unreachable!()),
        host,
    ])
    .unwrap_or_else(|_| unreachable!());
    let session_zero_host = NamedPipePeerEvidence::for_test(
        ProcessIdentity {
            process_id: 41,
            start_time_100ns: 99,
            image_path: image_path.to_owned(),
        },
        "S-1-5-19",
        0,
        Some(file),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        mixed
            .select(&session_zero_host)
            .unwrap_or_else(|_| unreachable!())
            .kind(),
        NamedPipePeerKind::Host
    );

    for (process_id, start_time_100ns, session_id) in [(41, 99, 4), (77, 101, 9)] {
        let evidence = NamedPipePeerEvidence::for_test(
            ProcessIdentity {
                process_id,
                start_time_100ns,
                image_path: image_path.to_owned(),
            },
            "S-1-5-21-1000",
            session_id,
            Some(file),
            None,
            false,
            true,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            set.select(&evidence)
                .unwrap_or_else(|_| unreachable!())
                .kind(),
            NamedPipePeerKind::AgentBridge
        );
    }

    let disconnected = NamedPipePeerEvidence::for_test(
        ProcessIdentity {
            process_id: 81,
            start_time_100ns: 110,
            image_path: image_path.to_owned(),
        },
        "S-1-5-21-1000",
        9,
        Some(file),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(set.select(&disconnected).is_err());

    let wrong_sid = NamedPipePeerEvidence::for_test(
        ProcessIdentity {
            process_id: 88,
            start_time_100ns: 120,
            image_path: image_path.to_owned(),
        },
        "S-1-5-21-1001",
        9,
        Some(file),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(set.select(&wrong_sid).is_err());
    let wrong_file = NamedPipePeerEvidence::for_test(
        ProcessIdentity {
            process_id: 89,
            start_time_100ns: 121,
            image_path: image_path.to_owned(),
        },
        "S-1-5-21-1000",
        9,
        Some(FileIdentity {
            volume_serial_number: 7,
            file_index: 12,
        }),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(set.select(&wrong_file).is_err());
    let wrong_image = NamedPipePeerEvidence::for_test(
        ProcessIdentity {
            process_id: 90,
            start_time_100ns: 122,
            image_path: r"C:\Eliot\other.exe".to_owned(),
        },
        "S-1-5-21-1000",
        9,
        Some(file),
        None,
        false,
        false,
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(set.select(&wrong_image).is_err());
}

#[test]
fn service_registration_request_rejects_untrusted_shape() {
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    assert_eq!(
        ServiceRegistrationRequest::new(
            "bad/service",
            "ELIOT test",
            &image,
            ServiceStartMode::Demand,
            ServiceAccount::LocalSystem,
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        ServiceRegistrationRequest::new(
            "EliotTest",
            "\n",
            &image,
            ServiceStartMode::Demand,
            ServiceAccount::LocalSystem,
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        ServiceRegistrationRequest::new(
            "EliotTest",
            "ELIOT test",
            PathBuf::from("relative.exe"),
            ServiceStartMode::Demand,
            ServiceAccount::LocalSystem,
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[test]
fn service_registration_plan_accepts_local_service_account() {
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        "Eliot Host",
        image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("LocalService plan failed: {error}"));
    assert_eq!(request.account(), ServiceAccount::LocalService);
    assert_eq!(request.service_sid_type(), ServiceSidType::Unrestricted);

    let watchdog = ServiceRegistrationRequest::new(
        ELIOT_WATCHDOG_SERVICE_NAME,
        ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing")),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("Watchdog LocalService plan failed: {error}"));
    assert_eq!(watchdog.service_sid_type(), ServiceSidType::None);
    assert!(!request.requires_host_service_control_grant());
    assert!(watchdog.requires_host_service_control_grant());
}

#[test]
fn watchdog_host_control_grant_rejects_rights_escalation_and_shape_substitution() {
    let required = 0x0000_0001 | 0x0000_0004 | 0x0000_0010 | 0x0000_0020 | 0x0002_0000;
    let forbidden = 0x0000_0002 | 0x0000_0040 | 0x0000_0100 | 0x0001_0000 | 0x000C_0000;
    assert_eq!(ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK, required);
    assert_eq!(ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK & forbidden, 0);

    let descriptor_digest = watchdog_service_security_descriptor_digest("S-1-5-80-1-2-3-4-5")
        .unwrap_or_else(|error| panic!("descriptor digest failed: {error}"));
    let receipt = ServiceControlGrantReadback::new(
        ELIOT_HOST_SERVICE_NAME,
        "S-1-5-80-1-2-3-4-5",
        ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
        descriptor_digest.clone(),
    )
    .unwrap_or_else(|error| panic!("grant receipt failed: {error}"));
    assert!(receipt.validate().is_ok());
    for (principal, sid, mask, digest) in [
        (
            ELIOT_WATCHDOG_SERVICE_NAME,
            "S-1-5-80-1-2-3-4-5",
            ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
            descriptor_digest.clone(),
        ),
        (
            ELIOT_HOST_SERVICE_NAME,
            "S-1-5-80-1-2-3-4",
            ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
            descriptor_digest.clone(),
        ),
        (
            ELIOT_HOST_SERVICE_NAME,
            "S-1-5-80-1-2-3-4-5",
            ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK | 0x0004_0000,
            descriptor_digest,
        ),
        (
            ELIOT_HOST_SERVICE_NAME,
            "S-1-5-80-1-2-3-4-5",
            ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
            "not-a-digest".to_owned(),
        ),
    ] {
        assert!(ServiceControlGrantReadback::new(principal, sid, mask, digest).is_err());
    }
}

#[cfg(windows)]
#[test]
fn watchdog_installer_mutation_handle_retains_exact_dacl_readback_authority() {
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
    use windows_sys::Win32::System::Services::{
        SERVICE_CHANGE_CONFIG, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    };

    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let host = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        image.clone(),
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("Host request failed: {error}"));
    let watchdog = ServiceRegistrationRequest::new(
        ELIOT_WATCHDOG_SERVICE_NAME,
        ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
        image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("Watchdog request failed: {error}"));

    let readback = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL;
    let host_access = service_registration_mutation_access(&host);
    assert_eq!(host_access & readback, readback);
    assert_ne!(host_access & SERVICE_CHANGE_CONFIG, 0);
    assert_eq!(host_access & WRITE_DAC, 0);

    let watchdog_access = service_registration_mutation_access(&watchdog);
    assert_eq!(watchdog_access & readback, readback);
    assert_ne!(watchdog_access & SERVICE_CHANGE_CONFIG, 0);
    assert_eq!(watchdog_access & WRITE_DAC, WRITE_DAC);
}

#[cfg(windows)]
#[test]
fn watchdog_service_dacl_is_protected_exact_and_sid_bound_without_scm_mutation() {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce};
    use windows_sys::Win32::System::Services::SERVICE_ALL_ACCESS;

    let host_sid = "S-1-5-80-1-2-3-4-5";
    let descriptor = OwnedSecurityDescriptor::for_watchdog_host_control(host_sid)
        .unwrap_or_else(|error| panic!("descriptor failed: {error}"));
    let dacl = descriptor
        .dacl()
        .unwrap_or_else(|error| panic!("DACL failed: {error}"));
    assert_eq!(unsafe { (*dacl).AceCount }, 3);
    let mut observed = Vec::new();
    for index in 0..3_u32 {
        let mut ace = std::ptr::null_mut();
        assert_ne!(unsafe { GetAce(dacl, index, &raw mut ace) }, 0);
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const allowed.SidStart).cast_mut().cast();
        observed.push((
            sid_to_string(sid).unwrap_or_else(|error| panic!("SID failed: {error}")),
            allowed.Mask,
        ));
    }
    assert_eq!(
        observed,
        vec![
            ("S-1-5-18".to_owned(), SERVICE_ALL_ACCESS),
            ("S-1-5-32-544".to_owned(), SERVICE_ALL_ACCESS),
            (host_sid.to_owned(), ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,),
        ]
    );
    let digest = watchdog_service_security_descriptor_digest(host_sid)
        .unwrap_or_else(|error| panic!("digest failed: {error}"));
    let substituted = OwnedSecurityDescriptor::for_watchdog_host_control("S-1-5-80-6-7-8-9-10")
        .unwrap_or_else(|error| panic!("substituted descriptor failed: {error}"));
    assert!(substituted.dacl().is_ok());
    assert_ne!(
        digest,
        watchdog_service_security_descriptor_digest("S-1-5-80-6-7-8-9-10")
            .unwrap_or_else(|error| panic!("substituted digest failed: {error}"))
    );
}

#[test]
fn service_registration_plan_rejects_non_runtime_shape() {
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    for (name, start_mode, account) in [
        (
            "eliot-host",
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        ),
        (
            ELIOT_HOST_SERVICE_NAME,
            ServiceStartMode::Demand,
            ServiceAccount::LocalService,
        ),
        (
            ELIOT_HOST_SERVICE_NAME,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalSystem,
        ),
    ] {
        assert_eq!(
            ServiceRegistrationRequest::new(name, "Eliot Host", &image, start_mode, account,),
            Err(WindowsAdapterError::InvalidInput)
        );
    }
    assert_eq!(
        ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
            &image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn service_bootstrap_arguments_preserve_typed_order_and_substitution() {
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(r"C:\ProgramData\Eliot\generation 7\runtime.json"),
        "a".repeat(64),
        "installation-7",
        7,
        ["--extra".to_owned(), "value with spaces".to_owned()],
    )
    .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
    assert_eq!(
        bootstrap.argv(),
        vec![
            "--config-descriptor".to_owned(),
            r"C:\ProgramData\Eliot\generation 7\runtime.json".to_owned(),
            "--config-descriptor-sha256".to_owned(),
            "a".repeat(64),
            "--installation-id".to_owned(),
            "installation-7".to_owned(),
            "--tx-plan-generation".to_owned(),
            "7".to_owned(),
            "--extra".to_owned(),
            "value with spaces".to_owned(),
        ]
    );
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        &image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap,
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let command = request.binary_command();
    assert!(command.starts_with('"'));
    assert!(command.contains("--config-descriptor"));
    assert!(command.contains("\"value with spaces\""));
    assert!(command.contains("--tx-plan-generation 7"));
}

#[test]
fn service_bootstrap_arguments_reject_substitution_and_reserved_flags() {
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\runtime.json"),
            "A".repeat(64),
            "installation",
            1,
            Vec::<String>::new(),
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\runtime.json"),
            "a".repeat(64),
            "installation",
            1,
            vec!["--installation-id".to_owned()],
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\runtime.json"),
            "a".repeat(64),
            "installation",
            1,
            vec!["--host-state-root".to_owned()],
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn host_bootstrap_root_is_typed_and_ordered_before_effect_nonce() {
    let host_root = PathBuf::from(
        r"C:\ProgramData\Eliot\installations\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\host",
    );
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
        "a".repeat(64),
        "installation",
        7,
        Vec::<String>::new(),
    )
    .and_then(|value| value.with_host_state_root(&host_root))
    .and_then(|value| value.with_registration_nonce("b".repeat(64)))
    .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
    assert_eq!(bootstrap.host_state_root(), Some(host_root.as_path()));
    assert_eq!(
        &bootstrap.argv()[8..],
        [
            "--host-state-root",
            host_root.to_str().unwrap_or_else(|| unreachable!()),
            "--registration-nonce",
            &"b".repeat(64),
        ]
    );
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
            "a".repeat(64),
            "installation",
            7,
            Vec::<String>::new(),
        )
        .and_then(|value| value.with_host_state_root("relative\\host")),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn service_bootstrap_command_preserves_unicode_quotes_and_trailing_slashes() {
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(r"C:\ProgramData\Eliot\╬ö generation\config.json"),
        "b".repeat(64),
        "installation-unicode",
        9,
        [
            "--label=quoted\"value".to_owned(),
            r"C:\ProgramData\Eliot\tail\".to_owned(),
        ],
    )
    .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap,
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let command = request.binary_command();
    assert!(command.contains("╬ö generation"));
    assert!(command.contains("--label=quoted"));
    assert!(command.contains("\\\"value"));
    assert!(command.contains(r"C:\ProgramData\Eliot\tail\"));
    assert_eq!(
        service_configuration_digest(
            &request.binary_command_wide(),
            &utf16_text(request.display_name()),
            &utf16_text("NT AUTHORITY\\LocalService"),
            0x0000_0010,
            0x0000_0002,
            0x0000_0001,
            0,
            &[],
            &[],
            request.service_sid_type().raw(),
        ),
        request.expected_configuration_digest()
    );
}

#[test]
fn service_bootstrap_rejects_nul_and_mutations_require_bootstrap() {
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\runtime.json"),
            "a".repeat(64),
            "installation",
            1,
            vec!["bad\0arg".to_owned()],
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from("C:\\runtime\0.json"),
            "a".repeat(64),
            "installation",
            1,
            Vec::<String>::new(),
        ),
        Err(WindowsAdapterError::InvalidInput)
    );

    #[cfg(windows)]
    {
        let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
        let request = ServiceRegistrationRequest::new(
            ELIOT_HOST_SERVICE_NAME,
            ELIOT_HOST_SERVICE_DISPLAY_NAME,
            image,
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
        )
        .unwrap_or_else(|error| panic!("request failed: {error}"));
        assert_eq!(
            register_service(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            update_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            delete_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            start_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            stop_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );

        let adapter = WindowsPlatform::new(std::env::temp_dir())
            .unwrap_or_else(|error| panic!("temp root failed: {error}"));
        // The public methods repeat the admission guard.  These calls must
        // return before any SCM inspection or mutation can be attempted.
        assert_eq!(
            adapter.start_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
        assert_eq!(
            adapter.stop_service_registration(&request),
            Err(WindowsAdapterError::InvalidInput)
        );
    }
}

#[cfg(windows)]
#[test]
fn service_bootstrap_nonce_is_typed_and_part_of_canonical_argv() {
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
        "a".repeat(64),
        "installation",
        7,
        Vec::<String>::new(),
    )
    .and_then(|bootstrap| bootstrap.with_registration_nonce("b".repeat(64)))
    .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
    assert_eq!(
        bootstrap.registration_nonce(),
        Some("b".repeat(64).as_str())
    );
    assert_eq!(
        bootstrap.argv(),
        vec![
            "--config-descriptor",
            r"C:\ProgramData\Eliot\authority.json",
            "--config-descriptor-sha256",
            &"a".repeat(64),
            "--installation-id",
            "installation",
            "--tx-plan-generation",
            "7",
            "--registration-nonce",
            &"b".repeat(64),
        ]
    );
    assert_eq!(
        ServiceBootstrapArguments::new(
            PathBuf::from(r"C:\ProgramData\Eliot\authority.json"),
            "a".repeat(64),
            "installation",
            7,
            Vec::<String>::new(),
        )
        .and_then(|bootstrap| bootstrap.with_registration_nonce("not-a-digest")),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn service_mutation_requires_expected_current_and_rejects_substitution() {
    let bootstrap = ServiceBootstrapArguments::new(
        PathBuf::from(r"C:\ProgramData\Eliot\config.json"),
        "c".repeat(64),
        "installation",
        1,
        Vec::<String>::new(),
    )
    .unwrap_or_else(|error| panic!("bootstrap failed: {error}"));
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::with_bootstrap(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
        bootstrap,
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    assert_eq!(
        update_service_registration(&request),
        Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation)
    );
    assert_eq!(
        delete_service_registration(&request),
        Ok(ServiceRegistrationOutcome::ExistingRequiresReconciliation)
    );

    let matching = ServiceConfigurationReadback {
        binary: request.binary_command_wide(),
        display: utf16_text(request.display_name()),
        account: utf16_text("NT AUTHORITY\\LocalService"),
        load_order_group: Vec::new(),
        dependencies: Vec::new(),
        service_type: 0x0000_0010,
        start_type: 0x0000_0002,
        error_control: 0x0000_0001,
        tag_id: 0,
        service_sid_type: request.service_sid_type().raw(),
    };
    let expected = ServiceRegistrationCurrent::new(
        ELIOT_HOST_SERVICE_NAME,
        service_configuration_digest(
            &matching.binary,
            &matching.display,
            &matching.account,
            matching.service_type,
            matching.start_type,
            matching.error_control,
            matching.tag_id,
            &matching.load_order_group,
            &matching.dependencies,
            matching.service_sid_type,
        ),
    )
    .unwrap_or_else(|error| panic!("current failed: {error}"));
    assert!(service_current_matches(&request, &expected, &matching));
    let substituted = ServiceConfigurationReadback {
        binary: utf16_text(r#""C:\wrong\eliot-host.exe""#),
        ..matching.clone()
    };
    assert!(!service_current_matches(&request, &expected, &substituted));
    let mut substituted_error_control = matching.clone();
    substituted_error_control.error_control = 0x0000_0002;
    assert!(!service_current_matches(
        &request,
        &expected,
        &substituted_error_control
    ));
    let mut substituted_tag = matching.clone();
    substituted_tag.tag_id = 3;
    assert!(!service_current_matches(
        &request,
        &expected,
        &substituted_tag
    ));
    let mut substituted_load_order_group = matching.clone();
    substituted_load_order_group.load_order_group = utf16_text("EliotGroup");
    assert!(!service_current_matches(
        &request,
        &expected,
        &substituted_load_order_group
    ));
    let mut substituted_dependencies = matching;
    substituted_dependencies.dependencies = vec![utf16_text("Tcpip")];
    assert!(!service_current_matches(
        &request,
        &expected,
        &substituted_dependencies
    ));
}

#[cfg(windows)]
#[test]
fn service_configuration_mismatch_is_not_acceptable() {
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        "Eliot Host",
        &image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let matching = ServiceConfigurationReadback {
        binary: request.binary_command_wide(),
        display: utf16_text("Eliot Host"),
        account: utf16_text("NT AUTHORITY\\LocalService"),
        load_order_group: Vec::new(),
        dependencies: Vec::new(),
        service_type: 0x0000_0010,
        start_type: 0x0000_0002,
        error_control: 0x0000_0001,
        tag_id: 0,
        service_sid_type: request.service_sid_type().raw(),
    };
    assert!(exact_service_configuration_matches(&request, &matching));
    let mut wrong_binary = matching.clone();
    wrong_binary.binary = utf16_text("\"C:\\wrong\\eliot-host.exe\"");
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_binary
    ));
    let mut wrong_account = matching.clone();
    wrong_account.account = utf16_text("LocalSystem");
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_account
    ));
    let mut wrong_type = matching.clone();
    wrong_type.service_type = 0x0000_0011;
    assert!(!exact_service_configuration_matches(&request, &wrong_type));
    let mut wrong_start = matching.clone();
    wrong_start.start_type = 0x0000_0003;
    assert!(!exact_service_configuration_matches(&request, &wrong_start));
    let mut wrong_error_control = matching.clone();
    wrong_error_control.error_control = 0x0000_0002;
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_error_control
    ));
    let mut wrong_tag = matching.clone();
    wrong_tag.tag_id = 7;
    assert!(!exact_service_configuration_matches(&request, &wrong_tag));
    let mut wrong_sid_type = matching.clone();
    wrong_sid_type.service_sid_type = 0;
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_sid_type
    ));
    let mut wrong_load_order_group = matching.clone();
    wrong_load_order_group.load_order_group = utf16_text("EliotGroup");
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_load_order_group
    ));
    let mut wrong_dependencies = matching;
    wrong_dependencies.dependencies = vec![utf16_text("Tcpip")];
    assert!(!exact_service_configuration_matches(
        &request,
        &wrong_dependencies
    ));
}

#[cfg(windows)]
#[test]
fn service_dependency_multisz_readback_is_ordered_and_canonical() {
    let raw = [
        u16::from(b'T'),
        u16::from(b'c'),
        u16::from(b'p'),
        u16::from(b'i'),
        u16::from(b'p'),
        0,
        u16::from(b'D'),
        u16::from(b'n'),
        u16::from(b's'),
        0,
        0,
    ];
    assert_eq!(
        service_config_multi_sz(
            raw.as_ptr(),
            raw.as_ptr().cast(),
            std::mem::size_of_val(&raw),
        ),
        Some(vec![utf16_text("Tcpip"), utf16_text("Dns")])
    );
    assert_eq!(
        service_config_multi_sz(std::ptr::null(), raw.as_ptr().cast(), 0),
        Some(Vec::new())
    );
}

#[cfg(windows)]
#[test]
fn service_configuration_strings_fail_closed_at_query_buffer_boundary() {
    let unterminated = [u16::from(b'E'), u16::from(b'l')];
    let start = unterminated.as_ptr().cast::<u8>();
    let bytes = std::mem::size_of_val(&unterminated);
    assert_eq!(
        service_config_wide(unterminated.as_ptr(), start, bytes),
        None
    );
    assert_eq!(
        service_config_multi_sz(unterminated.as_ptr(), start, bytes),
        None
    );

    let single_terminated = [u16::from(b'E'), 0];
    assert_eq!(
        service_config_multi_sz(
            single_terminated.as_ptr(),
            single_terminated.as_ptr().cast(),
            std::mem::size_of_val(&single_terminated),
        ),
        None
    );

    let empty_multi_sz = [0_u16, 0];
    assert_eq!(
        service_config_multi_sz(
            empty_multi_sz.as_ptr(),
            empty_multi_sz.as_ptr().cast(),
            std::mem::size_of_val(&empty_multi_sz),
        ),
        Some(Vec::new())
    );

    let outside = unsafe { unterminated.as_ptr().add(unterminated.len()) };
    assert_eq!(service_config_wide(outside, start, bytes), None);
}

#[test]
fn post_create_readback_failure_cannot_report_success() {
    let observation = ServiceObservation {
        service: handle(ELIOT_HOST_SERVICE_NAME),
        state: ServiceState::Stopped,
        generation: None,
        process: None,
    };
    assert!(!service_readback_is_acceptable(
        &ServiceRegistrationInspection::Mismatched
    ));
    assert!(!service_readback_is_acceptable(
        &ServiceRegistrationInspection::Unknown
    ));
    assert!(service_readback_is_acceptable(
        &ServiceRegistrationInspection::Matching {
            observation,
            control_grant: None,
        }
    ));
    assert_eq!(
        ServiceRegistrationOutcome::ExistingRequiresReconciliation,
        ServiceRegistrationOutcome::ExistingRequiresReconciliation
    );
}

#[test]
fn scm_post_effect_failure_is_reconciliation_unknown() {
    let failure = PortOutcome::Error(PortError::Provider(provider_failed()));
    assert_eq!(
        reconcile_service_effect(failure),
        PortOutcome::Unknown(UnknownReason::Indeterminate)
    );
    assert_eq!(
        reconcile_service_effect(PortOutcome::Unknown(UnknownReason::NotObserved)),
        PortOutcome::Unknown(UnknownReason::Indeterminate)
    );
}

#[test]
fn partial_service_status_never_maps_to_matching() {
    let observation = ServiceObservation {
        service: handle(ELIOT_HOST_SERVICE_NAME),
        state: ServiceState::Running,
        generation: None,
        process: None,
    };
    assert_eq!(
        service_registration_inspection_from_status(
            PortOutcome::Partial {
                value: observation,
                missing: vec![handle("authority")],
            },
            None
        ),
        ServiceRegistrationInspection::Unknown
    );
}

#[cfg(windows)]
#[test]
fn exact_runtime_service_observation_requires_handle_bound_live_identity() {
    let image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
    let request = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        &image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|_| unreachable!());
    let running = ProcessIdentity {
        process_id: 41,
        start_time_100ns: 99,
        image_path: image.to_string_lossy().into_owned(),
    };

    let ServiceRegistrationRuntimeInspection::Matching { observation } =
        classify_service_runtime_observation(&request, ServiceState::Stopped, 0, 0, 0, None)
    else {
        unreachable!();
    };
    assert_eq!(observation.state(), ServiceState::Stopped);
    assert!(observation.process().is_none());
    assert_eq!(
        observation.configuration_digest(),
        request.expected_configuration_digest()
    );

    let ServiceRegistrationRuntimeInspection::Matching { observation } =
        classify_service_runtime_observation(
            &request,
            ServiceState::Starting,
            3,
            250,
            running.process_id,
            Some(running.clone()),
        )
    else {
        unreachable!();
    };
    assert_eq!(observation.checkpoint(), 3);
    assert_eq!(observation.wait_hint_ms(), 250);
    assert_eq!(observation.process(), Some(&running));

    assert!(matches!(
        classify_service_runtime_observation(
            &request,
            ServiceState::Running,
            0,
            0,
            running.process_id,
            Some(running),
        ),
        ServiceRegistrationRuntimeInspection::Matching { .. }
    ));
    assert_eq!(
        classify_service_runtime_observation(&request, ServiceState::Running, 0, 0, 41, None,),
        ServiceRegistrationRuntimeInspection::Unknown
    );
    assert_eq!(
        classify_service_runtime_observation(
            &request,
            ServiceState::Stopped,
            0,
            0,
            41,
            Some(ProcessIdentity {
                process_id: 41,
                start_time_100ns: 99,
                image_path: image.to_string_lossy().into_owned(),
            }),
        ),
        ServiceRegistrationRuntimeInspection::Unknown
    );
    assert_eq!(
        classify_service_runtime_observation(
            &request,
            ServiceState::Running,
            0,
            0,
            41,
            Some(ProcessIdentity {
                process_id: 41,
                start_time_100ns: 99,
                image_path: image
                    .with_file_name("substituted.exe")
                    .to_string_lossy()
                    .into_owned(),
            }),
        ),
        ServiceRegistrationRuntimeInspection::Mismatched
    );
    assert!(service_runtime_sample_is_stable(4, 41, 4, 41));
    assert!(!service_runtime_sample_is_stable(4, 41, 1, 0));
    assert!(!service_runtime_sample_is_stable(2, 41, 2, 42));
}

#[test]
fn runtime_identity_digest_binds_configuration_pid_start_time_and_image() {
    let image = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("missing"));
    let request = ServiceRegistrationRequest::new(
        ELIOT_HOST_SERVICE_NAME,
        ELIOT_HOST_SERVICE_DISPLAY_NAME,
        &image,
        ServiceStartMode::Automatic,
        ServiceAccount::LocalService,
    )
    .unwrap_or_else(|error| panic!("request failed: {error}"));
    let process = ProcessIdentity {
        process_id: 41,
        start_time_100ns: 99,
        image_path: image.to_string_lossy().into_owned(),
    };
    let observation = ServiceRuntimeObservation {
        service_name: request.service_name().to_owned(),
        configuration_digest: request.expected_configuration_digest(),
        state: ServiceState::Running,
        checkpoint: 0,
        wait_hint_ms: 0,
        process: Some(process.clone()),
    };
    let digest = observation
        .runtime_identity_digest()
        .unwrap_or_else(|| unreachable!());
    assert!(valid_sha256_hex(&digest));
    assert_eq!(
        digest,
        runtime_identity_digest_from_configuration(observation.configuration_digest(), &process,)
    );
    assert_eq!(
        request
            .clone()
            .with_expected_runtime_identity_digest(digest.clone())
            .unwrap_or_else(|error| panic!("digest binding failed: {error}"))
            .expected_runtime_identity_digest(),
        Some(digest.as_str())
    );
    assert_eq!(
        request
            .clone()
            .with_expected_runtime_identity_digest("A".repeat(64)),
        Err(WindowsAdapterError::InvalidInput)
    );
    let mut changed = process;
    changed.start_time_100ns += 1;
    assert_ne!(
        digest,
        runtime_identity_digest_from_configuration(observation.configuration_digest(), &changed,)
    );
}

#[test]
fn scm_mutation_outcomes_never_promote_unknown_readback() {
    let observation = |state| ServiceRuntimeObservation {
        service_name: ELIOT_HOST_SERVICE_NAME.to_owned(),
        configuration_digest: "a".repeat(64),
        state,
        checkpoint: 0,
        wait_hint_ms: 0,
        process: None,
    };
    assert!(matches!(
        start_outcome_from_inspection(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: observation(ServiceState::Running),
            },
            false,
        ),
        ServiceStartOutcome::AlreadyRunning { .. }
    ));
    assert!(matches!(
        start_outcome_from_inspection(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: observation(ServiceState::Starting),
            },
            true,
        ),
        ServiceStartOutcome::Started { .. }
    ));
    assert_eq!(
        start_outcome_from_inspection(ServiceRegistrationRuntimeInspection::Unknown, true,),
        ServiceStartOutcome::EffectUnknown
    );
    assert!(matches!(
        stop_outcome_from_inspection(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: observation(ServiceState::Stopped),
            },
            false,
        ),
        ServiceStopOutcome::AlreadyStopped { .. }
    ));
    assert!(matches!(
        stop_outcome_from_inspection(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: observation(ServiceState::Stopping),
            },
            true,
        ),
        ServiceStopOutcome::Stopped { .. }
    ));
    assert_eq!(
        stop_outcome_from_inspection(ServiceRegistrationRuntimeInspection::Mismatched, true,),
        ServiceStopOutcome::EffectUnknown
    );
}

#[cfg(windows)]
#[test]
fn stopping_runtime_requires_the_expected_identity_digest() {
    let process = ProcessIdentity {
        process_id: 41,
        start_time_100ns: 99,
        image_path: std::env::current_exe()
            .unwrap_or_else(|_| unreachable!())
            .to_string_lossy()
            .into_owned(),
    };
    let observation = ServiceRuntimeObservation {
        service_name: ELIOT_HOST_SERVICE_NAME.to_owned(),
        configuration_digest: "a".repeat(64),
        state: ServiceState::Stopping,
        checkpoint: 1,
        wait_hint_ms: 250,
        process: Some(process.clone()),
    };
    let expected_digest = observation
        .runtime_identity_digest()
        .unwrap_or_else(|| unreachable!());
    assert!(matches!(
        admit_stop_runtime_observation(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: observation.clone(),
            },
            &expected_digest,
        ),
        Err(ServiceStopOutcome::AlreadyStopping { .. })
    ));

    let mismatched = ServiceRuntimeObservation {
        process: Some(ProcessIdentity {
            start_time_100ns: process.start_time_100ns + 1,
            ..process
        }),
        ..observation
    };
    assert_eq!(
        admit_stop_runtime_observation(
            ServiceRegistrationRuntimeInspection::Matching {
                observation: mismatched,
            },
            &expected_digest,
        ),
        Err(ServiceStopOutcome::EffectUnknown)
    );
}

#[test]
fn create_new_does_not_truncate_existing_entry() {
    let root = std::env::temp_dir().join(format!("eliot-p02-create-new-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let path = root.join("entry");
    std::fs::write(&path, b"original").unwrap_or_else(|_| unreachable!());
    let Err(error) = create_new_file(&path, b"replacement") else {
        panic!("must not truncate");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap_or_default(), b"original");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(not(windows))]
#[test]
fn non_windows_service_is_typed_unsupported() {
    assert!(matches!(
        inspect_service("Eliot"),
        PortOutcome::Unknown(UnknownReason::Unsupported)
    ));
}

#[cfg(windows)]
#[test]
fn real_windows_identity_and_atomic_publication_are_safe_and_reproducible() {
    let root = std::env::temp_dir().join(format!("eliot-p02-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
    let first = adapter
        .publish_atomic_receipt(&path, b"first")
        .unwrap_or_else(|_| unreachable!());
    let second = adapter
        .publish_atomic_receipt(&path, b"second")
        .unwrap_or_else(|_| unreachable!());
    assert_ne!(
        first.identity,
        FileIdentity {
            volume_serial_number: 0,
            file_index: 0
        }
    );
    assert_eq!(
        adapter
            .file_identity(&path)
            .unwrap_or_else(|_| unreachable!()),
        second.identity
    );
    assert_eq!(
        std::fs::read(root.join("state/current.bin")).unwrap_or_default(),
        b"second"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn real_windows_dpapi_and_job_object_primitives_are_available() {
    let root = std::env::temp_dir().join(format!("eliot-p02-crypto-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let protected = adapter
        .protect_secret(b"p02-dpapi-roundtrip")
        .unwrap_or_else(|_| unreachable!());
    assert_ne!(protected.as_bytes(), b"p02-dpapi-roundtrip");
    let clear = adapter
        .unprotect_secret(&protected)
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(clear.expose(), b"p02-dpapi-roundtrip");
    let _job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn job_child_process() {
    if std::env::var_os("ELIOT_P02_JOB_CHILD").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

#[cfg(windows)]
fn wait_for_child_exit(child: &mut std::process::Child) -> bool {
    for _ in 0..100 {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[cfg(windows)]
fn spawn_job_child() -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap_or_else(|_| unreachable!()))
        .arg("--exact")
        .arg("tests::job_child_process")
        .arg("--nocapture")
        .env("ELIOT_P02_JOB_CHILD", "1")
        .spawn()
        .unwrap_or_else(|_| unreachable!())
}

#[cfg(windows)]
#[test]
fn suspended_child_process() {
    if let Some(marker) = std::env::var_os("ELIOT_P02_SUSPENDED_MARKER") {
        let _descendant = std::env::var_os("ELIOT_P02_SPAWN_DESCENDANT").map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap_or_else(|_| unreachable!()))
                .arg("--exact")
                .arg("tests::job_child_process")
                .arg("--nocapture")
                .env("ELIOT_P02_JOB_CHILD", "1")
                .spawn()
                .unwrap_or_else(|_| unreachable!())
        });
        let body = format!(
            "cwd={}\nenv={}",
            std::env::current_dir()
                .unwrap_or_else(|_| unreachable!())
                .display(),
            std::env::var("ELIOT_P02_EXACT_ENV").unwrap_or_default()
        );
        std::fs::write(marker, body).unwrap_or_else(|_| unreachable!());
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

#[cfg(windows)]
fn complete_test_environment(
    marker: &Path,
    spawn_descendant: bool,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut environment = std::env::vars_os().collect::<Vec<_>>();
    for name in [
        "ELIOT_P02_SUSPENDED_MARKER",
        "ELIOT_P02_EXACT_ENV",
        "ELIOT_P02_SPAWN_DESCENDANT",
    ] {
        environment.retain(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case(name));
    }
    environment.push((
        "ELIOT_P02_SUSPENDED_MARKER".into(),
        marker.as_os_str().to_owned(),
    ));
    environment.push(("ELIOT_P02_EXACT_ENV".into(), "exact-value".into()));
    if spawn_descendant {
        environment.push(("ELIOT_P02_SPAWN_DESCENDANT".into(), "1".into()));
    }
    environment
}

#[cfg(windows)]
fn suspended_spec(
    marker: &Path,
    working_directory: &Path,
    spawn_descendant: bool,
) -> SuspendedLaunchSpec {
    SuspendedLaunchSpec::new(
        std::env::current_exe().unwrap_or_else(|_| unreachable!()),
        vec![
            "--exact".into(),
            "tests::suspended_child_process".into(),
            "--nocapture".into(),
        ],
        working_directory,
        complete_test_environment(marker, spawn_descendant),
    )
    .unwrap_or_else(|error| panic!("spec failed: {error}"))
}

#[cfg(windows)]
fn spawn_suspended_child(
    marker: &Path,
    working_directory: &Path,
    spawn_descendant: bool,
) -> SuspendedJobChild {
    SuspendedJobChild::spawn(suspended_spec(marker, working_directory, spawn_descendant))
        .unwrap_or_else(|error| panic!("spawn failed: {error}"))
}

#[cfg(windows)]
fn wait_for_process_gone(pid: u32) -> bool {
    for _ in 0..100 {
        if inspect_process_identity(pid).is_err() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[cfg(windows)]
#[test]
fn suspended_launch_does_not_start_before_consuming_validation() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-suspended-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let child = spawn_suspended_child(&marker, &root, true);
    let pid = child.id();
    assert!(!marker.exists(), "child must not run before ResumeThread");
    let terminal = child.terminate(0xE1_05).unwrap_or_else(|_| unreachable!());
    assert_eq!(terminal.process().process_id, pid);
    assert_eq!(terminal.requested_exit_code(), 0xE1_05);
    assert!(terminal.job_empty());
    assert!(terminal.root_reaped());
    assert!(wait_for_process_gone(pid));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn consuming_validation_binds_exact_launch_evidence_before_resume() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-evidence-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let expected_image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
    let child = spawn_suspended_child(&marker, &root, false);
    let expected_pid = child.id();
    let validated =
        child
            .validate::<&'static str, &'static str, _>(|evidence| {
                assert_eq!(evidence.process().process_id, expected_pid);
                assert_ne!(evidence.executable_file_identity().file_index, 0);
                assert_eq!(evidence.job_process_count(), 1);
                assert!(same_windows_path(
                    &evidence.process().image_path,
                    &expected_image.to_string_lossy()
                ));
                assert_eq!(evidence.requested_executable(), expected_image);
                assert_eq!(evidence.working_directory(), root);
                assert_eq!(
                    evidence.arguments(),
                    [
                        std::ffi::OsString::from("--exact"),
                        std::ffi::OsString::from("tests::suspended_child_process"),
                        std::ffi::OsString::from("--nocapture"),
                    ]
                );
                assert!(evidence.environment().iter().any(|(name, value)| {
                    name == "ELIOT_P02_EXACT_ENV" && value == "exact-value"
                }));
                Ok("validated-by-test-policy")
            })
            .unwrap_or_else(|error| panic!("evidence validation failed: {error:?}"));
    assert!(!marker.exists(), "validation must not resume the child");
    assert_eq!(*validated.validation(), "validated-by-test-policy");
    let running = validated.resume().unwrap_or_else(|_| unreachable!());
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(marker.exists(), "child must run after validated resume");
    let marker_body = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(marker_body.contains(&format!("cwd={}", root.display())));
    assert!(marker_body.contains("env=exact-value"));
    let first = running.observe().unwrap_or_else(|_| unreachable!());
    let second = running.observe().unwrap_or_else(|_| unreachable!());
    assert_eq!(first, second, "observation is idempotent");
    running
        .terminate(0xE1_05)
        .unwrap_or_else(|_| unreachable!());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn caller_pid_image_mismatch_rejection_kills_and_reaps_job() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-reject-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let child = spawn_suspended_child(&marker, &root, false);
    let pid = child.id();
    let result = child.validate::<(), &'static str, _>(|evidence| {
        if evidence.process().process_id != pid + 1
            || evidence.process().image_path != "C:\\wrong\\image.exe"
        {
            Err("pid-image-mismatch")
        } else {
            Ok(())
        }
    });
    assert_eq!(
        result.err(),
        Some(SuspendedValidationError::Rejected("pid-image-mismatch"))
    );
    assert!(wait_for_process_gone(pid), "rejected child must not leak");
    assert!(!marker.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn stale_validation_cannot_validate_a_new_process_generation() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-stale-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let first_marker = root.join("first");
    let first = spawn_suspended_child(&first_marker, &root, false);
    let mut old_key = String::new();
    let first = first
        .validate::<(), &'static str, _>(|evidence| {
            old_key = evidence.process().stable_key();
            Ok(())
        })
        .unwrap_or_else(|_| unreachable!());
    first.terminate(0xE1_06).unwrap_or_else(|_| unreachable!());

    let second_marker = root.join("second");
    let second = spawn_suspended_child(&second_marker, &root, false);
    let second_pid = second.id();
    let result = second.validate::<(), &'static str, _>(|evidence| {
        if evidence.process().stable_key() == old_key {
            Ok(())
        } else {
            Err("stale-validation")
        }
    });
    assert_eq!(
        result.err(),
        Some(SuspendedValidationError::Rejected("stale-validation"))
    );
    assert!(wait_for_process_gone(second_pid));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn validator_panic_still_kills_and_reaps_suspended_job() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-panic-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let child = spawn_suspended_child(&marker, &root, false);
    let pid = child.id();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = child.validate::<(), (), _>(|_| panic!("test validator panic"));
    }));
    assert!(panic.is_err());
    assert!(wait_for_process_gone(pid));
    assert!(!marker.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn resumed_tree_termination_is_consuming_and_reaps_every_member() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-p02-tree-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let child = spawn_suspended_child(&marker, &root, true);
    let validated = child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!());
    let running = validated.resume().unwrap_or_else(|_| unreachable!());
    for _ in 0..100 {
        if marker.exists()
            && running
                .job_processes()
                .is_ok_and(|processes| processes.len() >= 2)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let members = running
        .job_processes()
        .unwrap_or_else(|error| panic!("membership failed: {error}"));
    assert!(members.len() >= 2);
    let pids = members
        .iter()
        .map(|process| process.process_id)
        .collect::<Vec<_>>();
    let terminal = running
        .terminate(0xE1_07)
        .unwrap_or_else(|error| panic!("termination failed: {error}"));
    assert_eq!(terminal.requested_exit_code(), 0xE1_07);
    assert!(terminal.job_empty());
    assert!(terminal.root_reaped());
    assert!(pids.into_iter().all(wait_for_process_gone));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn windows_argument_quoting_covers_quotes_and_trailing_backslashes() {
    use std::os::windows::ffi::OsStringExt;
    let quote = |value: &str| {
        let units =
            quote_windows_argument(std::ffi::OsStr::new(value)).unwrap_or_else(|_| unreachable!());
        std::ffi::OsString::from_wide(&units)
            .to_string_lossy()
            .into_owned()
    };
    assert_eq!(quote(""), r#""""#);
    assert_eq!(quote("plain"), r#""plain""#);
    assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
    assert_eq!(quote("a\\"), "\"a\\\\\"");
    assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
}

#[cfg(windows)]
#[test]
fn launch_spec_rejects_ambiguous_environment_and_nul_arguments() {
    let executable = std::env::current_exe().unwrap_or_else(|_| unreachable!());
    let root = std::env::temp_dir();
    assert_eq!(
        SuspendedLaunchSpec::new(
            &executable,
            Vec::new(),
            &root,
            vec![("Path".into(), "a".into()), ("PATH".into(), "b".into())],
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        SuspendedLaunchSpec::new(
            executable,
            vec![std::ffi::OsString::from("bad\0argument")],
            root,
            Vec::new(),
        ),
        Err(WindowsAdapterError::InvalidInput)
    );
}

#[cfg(windows)]
#[test]
fn job_assignment_identity_termination_and_kill_on_close_are_real() {
    let _spawn_guard = process_job_spawn_test_guard();
    let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
    let mut child = spawn_job_child();
    let identity = match job.assign_process(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("job assignment failed: {error}");
        }
    };
    assert_eq!(identity.process_id, child.id());
    assert!(identity.start_time_100ns > 0);
    assert!(!identity.image_path.is_empty());
    job.terminate(0xE102).unwrap_or_else(|_| unreachable!());
    assert!(wait_for_child_exit(&mut child));

    let job = JobObject::new_kill_on_close().unwrap_or_else(|_| unreachable!());
    let mut child = spawn_job_child();
    let identity = match job.assign_process(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("job assignment failed: {error}");
        }
    };
    assert_eq!(identity.process_id, child.id());
    drop(job);
    assert!(wait_for_child_exit(&mut child));
}

#[cfg(windows)]
#[test]
fn dropping_host_owned_running_job_kills_children_and_removes_reopen_path() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!(
        "eliot-host-crash-kill-on-close-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let marker = root.join("started");
    let child = spawn_suspended_child(&marker, &root, false);
    let pid = child.id();
    let running = child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&marker);
    let binding = running.evidence().recoverable_job_binding();
    let mut pids = Vec::new();
    for _ in 0..100 {
        if running.active_process_count().is_ok_and(|count| count >= 2) {
            pids = running
                .job_processes()
                .unwrap_or_else(|_| unreachable!())
                .into_iter()
                .map(|process| process.process_id)
                .collect::<Vec<_>>();
            if pids.len() >= 2 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(pids.len() >= 2, "crash contour must include the descendant");

    // This is the Host crash boundary: dropping the process-owned
    // RunningJobChild closes its KILL_ON_JOB_CLOSE Job handle.  A restart
    // must therefore treat the durable binding as historical evidence,
    // not as a live contour it may commit without a fresh launch proof.
    drop(running);
    assert!(pids.into_iter().all(wait_for_process_gone));
    assert!(wait_for_process_gone(pid));
    assert!(matches!(
        RecoverableJobObject::open(binding),
        Err(WindowsAdapterError::NotFound)
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn real_windows_credential_manager_roundtrip_cleans_up() {
    let root = std::env::temp_dir().join(format!("eliot-p02-cred-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let key = format!("eliot/p02/test/{}", unique_suffix());
    adapter
        .write_credential(&key, b"credential-roundtrip")
        .unwrap_or_else(|_| unreachable!());
    let read = adapter.read_credential(&key);
    let delete = adapter.delete_credential(&key);
    assert_eq!(
        read.unwrap_or_else(|_| unreachable!()).expose(),
        b"credential-roundtrip"
    );
    assert!(delete.is_ok());
    assert_eq!(
        adapter.read_credential(&key).err(),
        Some(WindowsAdapterError::Unavailable)
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn generic_credential_api_cannot_access_installer_authority_namespace() {
    let root = std::env::temp_dir().join(format!("eliot-p02-cred-guard-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let target = format!("{INSTALLER_CREDENTIAL_TARGET_PREFIX}{}", unique_suffix());

    assert_eq!(
        adapter.write_credential(&target, &[0x5a; 32]),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        adapter.read_credential(&target).err(),
        Some(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        adapter.delete_credential(&target),
        Err(WindowsAdapterError::InvalidInput)
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn installer_secret_provider_rejects_missing_and_malformed_keys() {
    let provider = WindowsInstallerSecretProvider::new();
    let missing = provider
        .fresh_reference()
        .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
    assert_eq!(
        provider
            .inspect(&missing)
            .unwrap_or_else(|error| panic!("missing inspect failed: {error}")),
        InstallerSecretObservation::Absent
    );
    assert_eq!(
        provider.read(&missing).err(),
        Some(WindowsAdapterError::Unavailable)
    );

    let malformed = provider
        .fresh_reference()
        .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
    credential_write(malformed.as_str(), b"not-a-256-bit-key")
        .unwrap_or_else(|error| panic!("malformed fixture write failed: {error}"));
    assert_eq!(
        provider.inspect(&malformed),
        Err(WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        provider.read(&malformed).err(),
        Some(WindowsAdapterError::InvalidInput)
    );
    credential_delete(malformed.as_str())
        .unwrap_or_else(|error| panic!("malformed credential cleanup failed: {error}"));
}

#[cfg(windows)]
#[test]
fn concurrent_publication_is_collision_free_and_cleans_failed_staging() {
    use std::sync::Arc;
    let root = std::env::temp_dir().join(format!("eliot-p02-concurrent-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(root.join("state")).unwrap_or_else(|_| unreachable!());
    let adapter = Arc::new(WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!()));
    let path = WorkScopePath::new("state/current.bin").unwrap_or_else(|_| unreachable!());
    let workers = (0..8)
        .map(|index| {
            let adapter = Arc::clone(&adapter);
            let path = path.clone();
            std::thread::spawn(move || {
                adapter.publish_atomic(&path, format!("value-{index}").as_bytes())
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        let outcome = worker
            .join()
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            outcome,
            PublicationOutcome::Published(_) | PublicationOutcome::Unknown(_)
        ));
    }
    assert!(
        matches!(std::fs::read(root.join("state/current.bin")), Ok(bytes) if bytes.starts_with(b"value-"))
    );
    let entries = std::fs::read_dir(root.join("state"))
        .unwrap_or_else(|_| unreachable!())
        .count();
    assert_eq!(
        entries, 1,
        "failed publications must not leave staging files"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn directory_publication_concurrent_destination_race_never_replaces() {
    let root = std::env::temp_dir().join(format!(
        "eliot-directory-publication-race-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
    let destination = root.join("bundle");
    let mut publication = OwnedDirectoryPublication::create(&destination)
        .unwrap_or_else(|error| panic!("prepare publication: {error}"));
    let temporary = publication.temporary_path().to_path_buf();
    std::fs::write(temporary.join("role.bin"), b"candidate")
        .unwrap_or_else(|error| panic!("write candidate: {error}"));
    let identity = publication.temporary_identity();
    let racing_destination = destination.clone();
    let outcome = publication.publish_inner(
        identity,
        move || {
            std::thread::spawn(move || {
                std::fs::create_dir(&racing_destination)
                    .unwrap_or_else(|error| panic!("racing create: {error}"));
                std::fs::write(racing_destination.join("owner.txt"), b"concurrent-owner")
                    .unwrap_or_else(|error| panic!("racing marker: {error}"));
            })
            .join()
            .unwrap_or_else(|_| panic!("racing creator panicked"));
        },
        None,
    );
    assert_eq!(outcome, Err(DirectoryPublicationError::AlreadyExists));
    assert_eq!(
        std::fs::read(destination.join("owner.txt"))
            .unwrap_or_else(|error| panic!("read racing marker: {error}")),
        b"concurrent-owner"
    );
    assert!(temporary.exists(), "pre-commit failure retains owned temp");
    drop(publication);
    assert!(
        temporary.exists(),
        "uncommitted temp is quarantined; Drop must not delete by pathname"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn directory_publication_resumes_recorded_old_process_temporary_by_identity() {
    let root = std::env::temp_dir().join(format!(
        "eliot-directory-publication-resume-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
    let destination = root.join("bundle");
    let publication = OwnedDirectoryPublication::create(&destination)
        .unwrap_or_else(|error| panic!("prepare publication: {error}"));
    let original_temporary = publication.temporary_path().to_path_buf();
    let source_identity = publication.temporary_identity();
    let parent_identity = publication.parent_identity();
    std::fs::write(original_temporary.join("role.bin"), b"candidate")
        .unwrap_or_else(|error| panic!("write candidate: {error}"));
    drop(publication);

    let current_pid = std::process::id();
    let recorded_pid = if current_pid == u32::MAX {
        1
    } else {
        current_pid + 1
    };
    let temporary_name = format!(".bundle.tmp.{recorded_pid}.0");
    let recorded_temporary = root.join(&temporary_name);
    std::fs::rename(&original_temporary, &recorded_temporary)
        .unwrap_or_else(|error| panic!("rename old-process fixture: {error}"));

    let resumed = OwnedDirectoryPublication::resume(
        &destination,
        &recorded_temporary,
        &temporary_name,
        parent_identity,
        source_identity,
    )
    .unwrap_or_else(|error| panic!("resume exact temporary: {error}"));
    assert_eq!(resumed.temporary_identity(), source_identity);
    let outcome = resumed
        .publish(source_identity)
        .unwrap_or_else(|error| panic!("publish resumed temporary: {error}"));
    let DirectoryPublicationOutcome::Published(receipt) = outcome else {
        panic!("resumed publication must be exact");
    };
    assert_eq!(receipt.source_identity, source_identity);
    assert_eq!(receipt.destination_identity, source_identity);
    assert_eq!(
        std::fs::read(destination.join("role.bin"))
            .unwrap_or_else(|error| panic!("read destination: {error}")),
        b"candidate"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn directory_publication_root_cannot_be_substituted_during_writes() {
    let root = std::env::temp_dir().join(format!(
        "eliot-directory-publication-drop-substitution-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
    let destination = root.join("bundle");
    let publication = OwnedDirectoryPublication::create(&destination)
        .unwrap_or_else(|error| panic!("prepare publication: {error}"));
    let temporary = publication.temporary_path().to_path_buf();
    std::fs::write(temporary.join("role.json"), b"owned")
        .unwrap_or_else(|error| panic!("write owned role: {error}"));
    let substituted = root.join("substituted");
    assert!(
        std::fs::rename(&temporary, &substituted).is_err(),
        "retained source handle must block root rename/substitution"
    );

    drop(publication);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn directory_publication_pins_ancestor_and_rejects_junction_substitution() {
    let root = std::env::temp_dir().join(format!(
        "eliot-directory-publication-contour-{}",
        unique_suffix()
    ));
    let parent = root.join("parent");
    let moved_parent = root.join("parent-moved");
    let outside = root.join("outside");
    std::fs::create_dir_all(&parent)
        .unwrap_or_else(|error| panic!("create retained parent: {error}"));
    std::fs::create_dir(&outside).unwrap_or_else(|error| panic!("create junction target: {error}"));
    let publication = OwnedDirectoryPublication::create(&parent.join("bundle"))
        .unwrap_or_else(|error| panic!("prepare retained publication: {error}"));
    assert!(
        std::fs::rename(&parent, &moved_parent).is_err(),
        "retained no-delete-sharing contour must block ancestor rename"
    );
    drop(publication);
    std::fs::rename(&parent, &moved_parent)
        .unwrap_or_else(|error| panic!("rename after lease drop: {error}"));
    let output = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&parent)
        .arg(&outside)
        .output()
        .unwrap_or_else(|error| panic!("launch mklink: {error}"));
    assert!(
        output.status.success(),
        "mklink /J was not exercised: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        OwnedDirectoryPublication::create(&parent.join("bundle")),
        Err(DirectoryPublicationError::ReparsePoint)
    ));
    assert!(!outside.join("bundle").exists());
    std::fs::remove_dir(&parent).unwrap_or_else(|error| panic!("remove junction: {error}"));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn directory_publication_postcommit_failure_is_reconcilable_not_error() {
    let root = std::env::temp_dir().join(format!(
        "eliot-directory-publication-unknown-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create fixture: {error}"));
    let destination = root.join("bundle");
    let mut publication = OwnedDirectoryPublication::create(&destination)
        .unwrap_or_else(|error| panic!("prepare publication: {error}"));
    let temporary = publication.temporary_path().to_path_buf();
    std::fs::write(temporary.join("role.bin"), b"candidate")
        .unwrap_or_else(|error| panic!("write candidate: {error}"));
    let identity = publication.temporary_identity();
    let outcome = publication
        .publish_inner(
            identity,
            || {},
            Some(DirectoryPublicationUnknown::PostCommitReadbackUnavailable),
        )
        .unwrap_or_else(|error| panic!("post-commit outcome returned Err: {error}"));
    let DirectoryPublicationOutcome::CommittedUnknown(receipt) = outcome else {
        panic!("injected post-commit discriminator must withhold receipt");
    };
    assert_eq!(
        receipt.reason,
        DirectoryPublicationUnknown::PostCommitReadbackUnavailable
    );
    assert_eq!(receipt.source_identity, identity);
    assert!(destination.exists());
    assert!(!temporary.exists());
    assert_eq!(
        std::fs::read(destination.join("role.bin"))
            .unwrap_or_else(|error| panic!("read committed role: {error}")),
        b"candidate"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn live_process_identity_binds_pid_to_start_and_image() {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let identity = inspect_process_identity(unsafe { GetCurrentProcessId() })
        .unwrap_or_else(|_| unreachable!());
    assert!(identity.start_time_100ns > 0);
    assert!(!identity.image_path.is_empty());
    let reused = ProcessIdentity {
        start_time_100ns: identity.start_time_100ns.saturating_add(1),
        ..identity.clone()
    };
    assert_ne!(identity.stable_key(), reused.stable_key());
}

#[cfg(windows)]
#[test]
fn reparse_ancestor_is_rejected_without_touching_target() {
    use std::os::windows::fs::symlink_dir;
    let root = std::env::temp_dir().join(format!("eliot-p02-reparse-{}", unique_suffix()));
    let outside = std::env::temp_dir().join(format!("eliot-p02-outside-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    if symlink_dir(&outside, root.join("link")).is_err() {
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let path = WorkScopePath::new("link/target.bin").unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        adapter.publish_atomic(&path, b"must-not-write"),
        Err(PortError::InvalidPath)
    ));
    assert!(!outside.join("target.bin").exists());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[cfg(windows)]
#[test]
fn reparse_destination_is_rejected_and_staging_is_removed() {
    use std::os::windows::fs::symlink_file;
    let root = std::env::temp_dir().join(format!("eliot-p02-destination-{}", unique_suffix()));
    let outside =
        std::env::temp_dir().join(format!("eliot-p02-destination-outside-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    std::fs::write(outside.join("target.bin"), b"original").unwrap_or_else(|_| unreachable!());
    if symlink_file(outside.join("target.bin"), root.join("current.bin")).is_err() {
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    let adapter = WindowsPlatform::new(&root).unwrap_or_else(|_| unreachable!());
    let path = WorkScopePath::new("current.bin").unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        adapter.publish_atomic(&path, b"must-not-write"),
        Err(PortError::InvalidPath)
    ));
    assert_eq!(
        std::fs::read(outside.join("target.bin")).unwrap_or_default(),
        b"original"
    );
    assert_eq!(
        std::fs::read_dir(&root)
            .unwrap_or_else(|_| unreachable!())
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[cfg(windows)]
#[test]
fn protected_path_lease_retains_components_and_reopens_by_identity() {
    let root = std::env::temp_dir().join(format!("eliot-protected-lease-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let relative = Path::new("Eliot/host/lease.redb");
    let path = root.join(relative);
    let lease = test_lease(&root, relative, true)
        .unwrap_or_else(|error| panic!("protected lease open failed: {error}"));
    std::fs::write(&path, b"retained-by-handle").unwrap_or_else(|_| unreachable!());
    lease
        .verify_stable_identity()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        lease.read_bounded(1024).unwrap_or_default(),
        b"retained-by-handle"
    );
    assert!(std::fs::remove_file(&path).is_err());
    assert!(std::fs::rename(root.join("Eliot"), root.join("Eliot-renamed")).is_err());
    let identity = lease.identity();
    drop(lease);
    let reopened = test_lease(&root, relative, false)
        .unwrap_or_else(|error| panic!("protected lease reopen failed: {error}"));
    assert_eq!(reopened.identity(), identity);
    assert_eq!(
        reopened.read_bounded(1024).unwrap_or_default(),
        b"retained-by-handle"
    );
    drop(reopened);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn protected_root_lease_blocks_parent_substitution_until_drop() {
    let root = std::env::temp_dir().join(format!("eliot-protected-root-{}", unique_suffix()));
    let relative = Path::new("Eliot/installations/fixture/host");
    let retained = root.join(relative);
    let substituted = retained.with_file_name("host-substituted");
    std::fs::create_dir_all(&retained).unwrap_or_else(|_| unreachable!());

    let lease = test_root_lease(&root, relative)
        .unwrap_or_else(|error| panic!("protected root lease open failed: {error}"));
    lease
        .verify_stable_identity()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        lease.canonical_path().unwrap_or_else(|_| unreachable!()),
        retained
    );
    assert!(
        std::fs::rename(&retained, &substituted).is_err(),
        "the retained root must reject path substitution"
    );

    drop(lease);
    std::fs::rename(&retained, &substituted)
        .unwrap_or_else(|error| panic!("rename after lease drop failed: {error}"));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn runtime_file_access_is_ba_ls_sy_verify_only_while_legacy_keeps_write_dac() {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetAce};
    use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};

    assert_ne!(
        crate::protected_path::legacy_protected_file_access_mode() & WRITE_DAC,
        0
    );
    for access in [
        runtime_file_access_mode(false),
        runtime_file_access_mode(true),
    ] {
        assert_eq!(access & (WRITE_DAC | WRITE_OWNER), 0);
    }

    let descriptor = OwnedSecurityDescriptor::for_installer_system_object(false)
        .unwrap_or_else(|error| panic!("runtime descriptor failed: {error}"));
    assert_eq!(
        sid_to_string(descriptor.owner().unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|_| unreachable!()),
        "S-1-5-18"
    );
    let dacl = descriptor.dacl().unwrap_or_else(|_| unreachable!());
    let mut principals = std::collections::BTreeSet::new();
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut ace = std::ptr::null_mut();
        assert_ne!(unsafe { GetAce(dacl, index, &raw mut ace) }, 0);
        assert!(!ace.is_null());
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const allowed.SidStart).cast_mut().cast();
        principals.insert(sid_to_string(sid).unwrap_or_else(|_| unreachable!()));
    }
    assert_eq!(
        principals,
        ["S-1-5-18", "S-1-5-19", "S-1-5-32-544"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

#[cfg(windows)]
#[test]
fn protected_path_lease_rejects_directory_and_file_reparse_substitution() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let root = std::env::temp_dir().join(format!("eliot-protected-reparse-{}", unique_suffix()));
    let outside = std::env::temp_dir().join(format!(
        "eliot-protected-reparse-outside-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    let relative = Path::new("Eliot/host/lease.redb");
    if symlink_dir(&outside, root.join("Eliot")).is_err() {
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    assert!(matches!(
        test_lease(&root, relative, true),
        Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir_all(root.join("Eliot/host")).unwrap_or_else(|_| unreachable!());
    std::fs::write(outside.join("lease.redb"), b"outside").unwrap_or_else(|_| unreachable!());
    if symlink_file(outside.join("lease.redb"), root.join(relative)).is_err() {
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    assert!(matches!(
        test_lease(&root, relative, false),
        Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[cfg(windows)]
#[test]
fn user_owned_portable_dev_root_and_path_roundtrip() {
    let root = std::env::temp_dir().join(format!("eliot-user-owned-{}", unique_suffix()));
    let path = root.join("nested/state.bin");
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| unreachable!()))
        .unwrap_or_else(|_| unreachable!());
    std::fs::write(&path, b"portable-dev").unwrap_or_else(|_| unreachable!());

    let root_lease = UserOwnedRootLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("root lease failed: {error}"));
    let file_lease = UserOwnedPathLease::open_existing(&root_lease, &path)
        .unwrap_or_else(|error| panic!("path lease failed: {error}"));
    assert_eq!(
        file_lease.read_bounded(1024).unwrap_or_default(),
        b"portable-dev"
    );
    root_lease
        .verify_stable_identity()
        .unwrap_or_else(|_| unreachable!());
    file_lease
        .verify_stable_identity()
        .unwrap_or_else(|_| unreachable!());
    file_lease
        .verify_path_identity()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(file_lease.current_user_sid(), root_lease.current_user_sid());

    drop(file_lease);
    drop(root_lease);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn read_only_user_root_lease_fails_closed_without_rewriting_security() {
    let root = std::env::temp_dir().join(format!("eliot-user-owned-read-only-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());

    let invalid_before = directory_security_descriptor_bytes(&root);
    assert!(UserOwnedRootReadLease::open_existing(&root).is_err());
    assert_eq!(invalid_before, directory_security_descriptor_bytes(&root));

    drop(
        UserOwnedRootLease::open_existing(&root)
            .unwrap_or_else(|error| panic!("fixture ACL provisioning failed: {error}")),
    );
    let valid_before = directory_security_descriptor_bytes(&root);
    let lease = UserOwnedRootReadLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("read-only lease failed: {error}"));
    assert_eq!(valid_before, directory_security_descriptor_bytes(&root));
    lease
        .verify_stable_identity()
        .unwrap_or_else(|_| unreachable!());

    drop(lease);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn user_owned_portable_dev_rejects_outside_root() {
    let root = std::env::temp_dir().join(format!("eliot-user-owned-root-{}", unique_suffix()));
    let outside =
        std::env::temp_dir().join(format!("eliot-user-owned-outside-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    let outside_file = outside.join("outside.bin");
    std::fs::write(&outside_file, b"outside").unwrap_or_else(|_| unreachable!());
    let root_lease = UserOwnedRootLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("root lease failed: {error}"));
    assert_eq!(
        UserOwnedPathLease::open_existing(&root_lease, &outside_file).err(),
        Some(ProtectedPathError::InvalidPath)
    );
    drop(root_lease);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(windows)]
#[test]
fn user_owned_portable_dev_rejects_reparse_path_when_available() {
    use std::os::windows::fs::symlink_dir;

    let root = std::env::temp_dir().join(format!("eliot-user-owned-reparse-{}", unique_suffix()));
    let outside = std::env::temp_dir().join(format!(
        "eliot-user-owned-reparse-outside-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    if symlink_dir(&outside, root.join("link")).is_err() {
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    let target = root.join("link/state.bin");
    std::fs::write(outside.join("state.bin"), b"must-not-open").unwrap_or_else(|_| unreachable!());
    let root_lease = UserOwnedRootLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("root lease failed: {error}"));
    assert!(matches!(
        UserOwnedPathLease::open_existing(&root_lease, &target),
        Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
    ));
    drop(root_lease);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(windows)]
#[test]
fn user_owned_portable_dev_rejects_file_reparse_without_touching_target() {
    use std::os::windows::fs::symlink_file;

    let root =
        std::env::temp_dir().join(format!("eliot-user-owned-file-reparse-{}", unique_suffix()));
    let outside = std::env::temp_dir().join(format!(
        "eliot-user-owned-file-reparse-outside-{}",
        unique_suffix()
    ));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    std::fs::create_dir(&outside).unwrap_or_else(|_| unreachable!());
    let outside_file = outside.join("state.bin");
    std::fs::write(&outside_file, b"must-not-open-or-mutate").unwrap_or_else(|_| unreachable!());
    let root_lease = UserOwnedRootLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("root lease failed: {error}"));
    let linked = root.join("state.bin");
    if symlink_file(&outside_file, &linked).is_err() {
        drop(root_lease);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }
    assert!(matches!(
        UserOwnedPathLease::open_existing(&root_lease, &linked),
        Err(ProtectedPathError::ReparsePoint | ProtectedPathError::Io)
    ));
    assert_eq!(
        std::fs::read(&outside_file).unwrap_or_default(),
        b"must-not-open-or-mutate"
    );
    drop(root_lease);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(windows)]
#[test]
fn user_owned_portable_dev_bounded_read_rejects_oversize() {
    let root = std::env::temp_dir().join(format!("eliot-user-owned-limit-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let path = root.join("state.bin");
    std::fs::write(&path, b"1234").unwrap_or_else(|_| unreachable!());
    let root_lease = UserOwnedRootLease::open_existing(&root)
        .unwrap_or_else(|error| panic!("root lease failed: {error}"));
    let file_lease = UserOwnedPathLease::open_existing(&root_lease, &path)
        .unwrap_or_else(|error| panic!("path lease failed: {error}"));
    assert_eq!(
        file_lease.read_bounded(3).err(),
        Some(ProtectedPathError::SizeExceeded)
    );
    drop(file_lease);
    drop(root_lease);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
fn wait_for_marker(marker: &Path) {
    for _ in 0..100 {
        if marker.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("child marker did not appear: {}", marker.display());
}

#[cfg(windows)]
#[test]
fn reopened_job_member_uses_exact_job_and_member_termination_preserves_root() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-existing-job-member-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let root_marker = root.join("root");
    let member_marker = root.join("member");
    let root_child = spawn_suspended_child(&root_marker, &root, false);
    let running_root = root_child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&root_marker);
    let binding = running_root.evidence().recoverable_job_binding();
    let recovered = RecoverableJobObject::open(binding)
        .unwrap_or_else(|error| panic!("exact Job reopen failed: {error}"));
    let root_job = running_root.job_identity().clone();
    let member = recovered
        .spawn_member(suspended_spec(&member_marker, &root, false))
        .unwrap_or_else(|error| panic!("member spawn failed: {error}"));
    let member_pid = member.id();
    let validated = member
        .validate::<(), &'static str, _>(|evidence| {
            assert_eq!(evidence.job_identity(), &root_job);
            assert!(evidence.job_process_count() >= 2);
            assert_ne!(
                evidence.process().process_id,
                running_root.evidence().process().process_id
            );
            assert_ne!(evidence.executable_file_identity().file_index, 0);
            Ok(())
        })
        .unwrap_or_else(|_| unreachable!());
    let running_member = validated
        .resume()
        .unwrap_or_else(|error| panic!("member resume failed: {error}"));
    wait_for_marker(&member_marker);
    assert_eq!(running_member.job_identity(), &root_job);
    assert!(matches!(
        running_root.observe().unwrap_or_else(|_| unreachable!()),
        RunningJobObservation::Running { active_processes } if active_processes >= 2
    ));
    let terminal = running_member
        .terminate(0xE1_31)
        .unwrap_or_else(|error| panic!("member termination failed: {error}"));
    assert_eq!(terminal.process().process_id, member_pid);
    assert_eq!(terminal.requested_exit_code(), 0xE1_31);
    assert!(terminal.remaining_job_members() >= 1);
    assert!(wait_for_process_gone(member_pid));
    assert!(matches!(
        running_root.observe().unwrap_or_else(|_| unreachable!()),
        RunningJobObservation::Running { active_processes } if active_processes >= 1
    ));
    running_root
        .terminate(0xE132)
        .unwrap_or_else(|error| panic!("root termination failed: {error}"));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn existing_job_member_rejection_and_validator_panic_preserve_root() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-existing-job-reject-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let root_marker = root.join("root");
    let root_child = spawn_suspended_child(&root_marker, &root, false);
    let running_root = root_child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&root_marker);
    let recovered = RecoverableJobObject::open(running_root.evidence().recoverable_job_binding())
        .unwrap_or_else(|_| unreachable!());

    let rejected_marker = root.join("rejected");
    let rejected = recovered
        .spawn_member(suspended_spec(&rejected_marker, &root, false))
        .unwrap_or_else(|_| unreachable!());
    let rejected_pid = rejected.id();
    let result = rejected.validate::<(), &'static str, _>(|evidence| {
        assert!(evidence.process().start_time_100ns != 0);
        Err("wrong-image-or-policy")
    });
    assert_eq!(
        result.err(),
        Some(SuspendedValidationError::Rejected("wrong-image-or-policy"))
    );
    assert!(wait_for_process_gone(rejected_pid));
    assert!(
        running_root
            .active_process_count()
            .unwrap_or_else(|_| unreachable!())
            >= 1
    );

    let panic_marker = root.join("panic");
    let panicking = recovered
        .spawn_member(suspended_spec(&panic_marker, &root, false))
        .unwrap_or_else(|_| unreachable!());
    let panic_pid = panicking.id();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = panicking.validate::<(), (), _>(|_| panic!("member validator panic"));
    }));
    assert!(panic.is_err());
    assert!(wait_for_process_gone(panic_pid));
    assert!(
        running_root
            .active_process_count()
            .unwrap_or_else(|_| unreachable!())
            >= 1
    );
    assert!(matches!(
        running_root.observe().unwrap_or_else(|_| unreachable!()),
        RunningJobObservation::Running { active_processes } if active_processes >= 1
    ));
    running_root
        .terminate(0xE1_33)
        .unwrap_or_else(|_| unreachable!());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn whole_job_termination_reaps_reopened_member_and_reopen_can_launch_again() {
    let _spawn_guard = process_job_spawn_test_guard();
    let root = std::env::temp_dir().join(format!("eliot-existing-job-reap-{}", unique_suffix()));
    std::fs::create_dir(&root).unwrap_or_else(|_| unreachable!());
    let root_marker = root.join("root");
    let first_marker = root.join("first");
    let second_marker = root.join("second");
    let root_child = spawn_suspended_child(&root_marker, &root, false);
    let running_root = root_child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&root_marker);
    let binding = running_root.evidence().recoverable_job_binding();
    let recovered = RecoverableJobObject::open(binding.clone()).unwrap_or_else(|_| unreachable!());
    let first = recovered
        .spawn_member(suspended_spec(&first_marker, &root, false))
        .unwrap_or_else(|_| unreachable!())
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    let first_pid = first.process().process_id;
    wait_for_marker(&first_marker);
    running_root
        .terminate(0xE1_34)
        .unwrap_or_else(|error| panic!("whole Job termination failed: {error}"));
    assert!(wait_for_process_gone(first_pid));
    assert!(matches!(
        first.observe().unwrap_or_else(|_| unreachable!()),
        ExistingJobMemberObservation::Exited {
            active_processes: 0,
            ..
        }
    ));

    let root_child = spawn_suspended_child(&root_marker, &root, false);
    let replacement_root = root_child
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&root_marker);
    let replacement_recovered =
        RecoverableJobObject::open(replacement_root.evidence().recoverable_job_binding())
            .unwrap_or_else(|_| unreachable!());
    let replacement = replacement_recovered
        .spawn_member(suspended_spec(&second_marker, &root, false))
        .unwrap_or_else(|_| unreachable!())
        .validate::<(), &'static str, _>(|_| Ok(()))
        .unwrap_or_else(|_| unreachable!())
        .resume()
        .unwrap_or_else(|_| unreachable!());
    wait_for_marker(&second_marker);
    replacement
        .terminate(0xE1_35)
        .unwrap_or_else(|_| unreachable!());
    replacement_root
        .terminate(0xE1_36)
        .unwrap_or_else(|_| unreachable!());
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
fn test_owner_lease(authority: Arc<HostLeaseAuthority>) -> HostOwnerLease {
    HostOwnerLease {
        handle: std::ptr::null_mut(),
        owns: true,
        name: "test-host-owner".to_owned(),
        authority,
    }
}

#[cfg(windows)]
#[test]
fn host_epoch_capability_is_revoked_by_release_and_drop() {
    let authority = Arc::new(HostLeaseAuthority::default());
    let mut lease = test_owner_lease(Arc::clone(&authority));
    let capability = lease.activation_capability();
    let guard = capability.live_guard().unwrap_or_else(|_| unreachable!());
    drop(guard);
    lease.release().unwrap_or_else(|_| unreachable!());
    assert_eq!(
        capability.live_guard().err(),
        Some(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn credential_capability_is_revoked_by_release_and_drop() {
    let authority = Arc::new(HostLeaseAuthority::default());
    let mut lease = test_owner_lease(Arc::clone(&authority));
    let capability = lease
        .credential_mutation_capability()
        .unwrap_or_else(|_| unreachable!());
    capability
        .with_authority(|| Ok::<_, WindowsAdapterError>(()))
        .unwrap_or_else(|_| unreachable!());
    lease.release().unwrap_or_else(|_| unreachable!());
    assert_eq!(
        capability.with_authority(|| Ok::<_, WindowsAdapterError>(())),
        Err(WindowsAdapterError::IdentityMismatch)
    );
}

#[cfg(windows)]
#[test]
fn host_epoch_release_waits_for_in_flight_mutation_guard() {
    use std::sync::Barrier;

    let authority = Arc::new(HostLeaseAuthority::default());
    let mut lease = test_owner_lease(Arc::clone(&authority));
    let capability = lease.activation_capability();
    let entered = Arc::new(Barrier::new(2));
    let entered_worker = Arc::clone(&entered);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let _guard = capability.live_guard().unwrap_or_else(|_| unreachable!());
            entered_worker.wait();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        entered.wait();
        let started = std::time::Instant::now();
        lease.release().unwrap_or_else(|_| unreachable!());
        assert!(started.elapsed() >= std::time::Duration::from_millis(75));
    });
}

#[cfg(windows)]
#[test]
fn credential_release_waits_for_in_flight_authority_operation() {
    use std::sync::Barrier;

    let authority = Arc::new(HostLeaseAuthority::default());
    let mut lease = test_owner_lease(Arc::clone(&authority));
    let capability = lease
        .credential_mutation_capability()
        .unwrap_or_else(|_| unreachable!());
    let entered = Arc::new(Barrier::new(2));
    let entered_worker = Arc::clone(&entered);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            capability
                .with_authority(|| {
                    entered_worker.wait();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    Ok::<_, WindowsAdapterError>(())
                })
                .unwrap_or_else(|_| unreachable!());
        });
        entered.wait();
        let started = std::time::Instant::now();
        lease.release().unwrap_or_else(|_| unreachable!());
        assert!(started.elapsed() >= std::time::Duration::from_millis(75));
    });
}

fn front_door_ace(sid: &str, is_user_account: bool) -> KernelFrontDoorAce {
    KernelFrontDoorAce {
        sid: sid.to_owned(),
        mask: 0x001F_01FF,
        ace_type: 0,
        ace_flags: 0,
        is_user_account,
    }
}

#[test]
fn kernel_front_door_expectation_rejects_invalid_hash_and_client_contours() {
    assert!(
        KernelFrontDoorServerExpectation::new(
            "S-1-5-19",
            0,
            "A".repeat(64),
            KernelFrontDoorAclMode::ServiceOnly,
        )
        .is_err()
    );
    assert!(
        KernelFrontDoorServerExpectation::new(
            "S-1-5-19",
            0,
            "a".repeat(64),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: "S-1-5-32-545".to_owned(),
            },
        )
        .is_ok()
    );
    assert!(
        KernelFrontDoorServerExpectation::new(
            "S-1-5-19",
            0,
            "a".repeat(64),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithClient {
                client_sid: "S-1-5-32-544".to_owned(),
            },
        )
        .is_err()
    );
}

#[test]
fn kernel_front_door_acl_optional_zero_one_and_negative_matrix() {
    let mode = KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient;
    let base = || {
        vec![
            front_door_ace("S-1-5-18", false),
            front_door_ace("S-1-5-19", false),
        ]
    };
    assert_eq!(classify_kernel_front_door_acl(&base(), &mode), Ok(None));

    let user_sid = "S-1-5-21-111-222-333-1001";
    let mut one = base();
    one.push(front_door_ace(user_sid, true));
    assert_eq!(
        classify_kernel_front_door_acl(&one, &mode),
        Ok(Some(user_sid.to_owned()))
    );

    let mut two = one.clone();
    two.push(front_door_ace("S-1-5-21-111-222-333-1002", true));
    assert_eq!(
        classify_kernel_front_door_acl(&two, &mode),
        Err(WindowsAdapterError::AclMismatch)
    );

    let mut duplicate = base();
    duplicate.push(front_door_ace("S-1-5-18", false));
    assert_eq!(
        classify_kernel_front_door_acl(&duplicate, &mode),
        Err(WindowsAdapterError::AclMismatch)
    );
    for mutation in [
        {
            let mut value = base();
            value[0].ace_type = 1;
            value
        },
        {
            let mut value = base();
            value[0].mask = 1;
            value
        },
        {
            let mut value = base();
            value.push(front_door_ace("S-1-1-0", true));
            value
        },
        {
            let mut value = base();
            value.push(front_door_ace("S-1-5-32-545", false));
            value
        },
        {
            let mut value = base();
            value.push(front_door_ace("S-1-5-80-123456789", true));
            value
        },
    ] {
        assert_eq!(
            classify_kernel_front_door_acl(&mutation, &mode),
            Err(WindowsAdapterError::AclMismatch)
        );
    }

    assert_eq!(
        classify_kernel_front_door_acl(&one, &KernelFrontDoorAclMode::ServiceOnly),
        Err(WindowsAdapterError::AclMismatch)
    );
    assert_eq!(
        classify_kernel_front_door_acl(
            &one,
            &KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient,
        ),
        Ok(Some(user_sid.to_owned()))
    );
    assert_eq!(
        classify_kernel_front_door_acl(
            &base(),
            &KernelFrontDoorAclMode::SystemAndLocalServiceWithOneClient,
        ),
        Err(WindowsAdapterError::AclMismatch)
    );
}

#[cfg(windows)]
#[test]
fn kernel_front_door_proof_binds_process_image_file_and_artifact() {
    let image = std::env::current_exe().unwrap_or_else(|_| unreachable!());
    let image_text = image.to_string_lossy().into_owned();
    let process = ProcessIdentity {
        process_id: 41,
        start_time_100ns: 99,
        image_path: image_text.clone(),
    };
    let file = file_identity(&image).unwrap_or_else(|_| unreachable!());
    let approved = NamedPipePeerProcessBinding::for_test(process.clone(), Some(file))
        .unwrap_or_else(|_| unreachable!());
    let expectation = KernelFrontDoorServerExpectation::new(
        "S-1-5-19",
        0,
        "a".repeat(64),
        KernelFrontDoorAclMode::ServiceOnly,
    )
    .unwrap_or_else(|_| unreachable!())
    .with_process_binding(approved);
    assert!(validate_kernel_front_door_process_identity(&process, &expectation).is_ok());
    let mut wrong_pid = process.clone();
    wrong_pid.process_id += 1;
    assert!(validate_kernel_front_door_process_identity(&wrong_pid, &expectation).is_err());
    let mut wrong_start = process.clone();
    wrong_start.start_time_100ns += 1;
    assert!(validate_kernel_front_door_process_identity(&wrong_start, &expectation).is_err());
    let mut wrong_image = process.clone();
    wrong_image.image_path.push_str(".substituted");
    assert!(validate_kernel_front_door_process_identity(&wrong_image, &expectation).is_err());
    assert!(
        validate_kernel_front_door_executable_identity(
            &image_text,
            &image_text,
            file,
            &expectation,
        )
        .is_ok()
    );
    let substituted_file = FileIdentity {
        volume_serial_number: file.volume_serial_number,
        file_index: file.file_index.saturating_add(1),
    };
    assert!(
        validate_kernel_front_door_executable_identity(
            &image_text,
            &image_text,
            substituted_file,
            &expectation,
        )
        .is_err()
    );
    assert!(
        validate_kernel_front_door_executable_identity(
            &image_text,
            &format!("{image_text}.substituted"),
            file,
            &expectation,
        )
        .is_err()
    );
    assert!(validate_kernel_front_door_artifact(&"a".repeat(64), &expectation).is_ok());
    assert!(validate_kernel_front_door_artifact(&"b".repeat(64), &expectation).is_err());
    assert_eq!(
        expectation
            .approved_process_binding()
            .and_then(NamedPipePeerProcessBinding::executable_file_identity),
        Some(file)
    );
}
