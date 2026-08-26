use super::*;
use eliot_platform_windows::ServiceBootstrapArguments;

fn valid_bootstrap() -> Result<ServiceBootstrapArguments, TestError> {
    Ok(ServiceBootstrapArguments::new(
        std::env::temp_dir().join("eliot-authority.json"),
        "a".repeat(64),
        "installation-7",
        7,
        std::iter::empty::<String>(),
    )
    .and_then(|bootstrap| {
        bootstrap.with_host_state_root(std::env::temp_dir().join("eliot-host-state"))
    })
    .and_then(|bootstrap| bootstrap.with_registration_nonce("b".repeat(64)))?)
}

fn valid_args() -> Result<Vec<OsString>, TestError> {
    Ok(valid_bootstrap()?
        .argv()
        .into_iter()
        .map(OsString::from)
        .collect())
}

#[test]
fn launch_options_parse_exact_registration_contract() -> TestResult {
    let bootstrap = valid_bootstrap()?;
    let options = HostLaunchOptions::parse(bootstrap.argv())?;
    assert_eq!(
        options.config_descriptor_path(),
        &std::env::temp_dir().join("eliot-authority.json")
    );
    assert_eq!(options.config_descriptor_digest().as_str(), "a".repeat(64));
    assert_eq!(options.installation().as_str(), "installation-7");
    assert_eq!(options.transaction_plan_generation(), 7);
    assert_eq!(
        options.host_state_root(),
        std::env::temp_dir().join("eliot-host-state")
    );
    assert_eq!(
        options.registration_nonce().map(PlatformHandle::as_str),
        Some("b".repeat(64).as_str())
    );
    Ok(())
}

#[test]
fn launch_options_reject_missing_duplicate_reordered_unknown_and_substituted_args() -> TestResult {
    let mut missing = valid_args()?;
    missing.drain(8..10);
    assert!(HostLaunchOptions::parse(missing).is_err());

    let mut duplicate = valid_args()?;
    duplicate[8] = OsString::from("--config-descriptor");
    assert!(HostLaunchOptions::parse(duplicate).is_err());

    let mut reordered = valid_args()?;
    reordered.swap(0, 2);
    reordered.swap(1, 3);
    assert!(HostLaunchOptions::parse(reordered).is_err());

    let mut unknown = valid_args()?;
    unknown[8] = OsString::from("--unknown");
    assert!(HostLaunchOptions::parse(unknown).is_err());

    let mut substituted = valid_args()?;
    substituted[1] = OsString::from("relative-authority.json");
    assert!(HostLaunchOptions::parse(substituted).is_err());
    Ok(())
}

#[test]
fn system_service_launch_options_require_registration_nonce() -> TestResult {
    let mut without_nonce = valid_args()?;
    without_nonce.truncate(10);
    assert!(HostLaunchOptions::parse(without_nonce.clone()).is_ok());
    assert!(HostLaunchOptions::parse_system_service(without_nonce).is_err());
    assert!(HostLaunchOptions::parse_system_service(valid_args()?).is_ok());
    Ok(())
}

#[test]
fn process_and_service_main_argv_have_distinct_contracts() -> TestResult {
    let process_args = valid_args()?;
    assert!(HostLaunchOptions::parse_system_service(process_args.clone()).is_ok());
    assert!(HostLaunchOptions::validate_service_main_argv([OsString::from(SERVICE_NAME)]).is_ok());

    let callback_with_process_args =
        std::iter::once(OsString::from(SERVICE_NAME)).chain(process_args);
    assert!(HostLaunchOptions::validate_service_main_argv(callback_with_process_args).is_err());
    assert!(HostLaunchOptions::validate_service_main_argv(std::iter::empty::<OsString>()).is_err());
    Ok(())
}
