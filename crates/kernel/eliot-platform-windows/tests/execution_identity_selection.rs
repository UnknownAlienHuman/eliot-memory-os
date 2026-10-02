//! Smallest proof for issue #1888 Work item W4: explicit execution identity
//! selection for the two `I1.6` identity names.
//!
//! `I1.6` (`docs/architecture/I01-06-windows-isolation.md`) requires that
//! "`system_service` uses a dedicated low-privilege service identity;
//! `user_mode` runs under the current user without pretending to be an SCM
//! service". This file proves only the selection half of that clause: each
//! declared name selects exactly one mode, the selection is observable and
//! comparable in both directions, and any name outside those two is refused
//! rather than defaulted. Opening the tokens themselves and re-reading the
//! launched child's identity belong to the platform launch path and the later
//! real-Windows acceptance, not to this selection proof.

use eliot_platform_windows::{
    ExecutionIdentityMode, SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME,
    USER_MODE_EXECUTION_IDENTITY_NAME, WindowsAdapterError, execution_identity_mode_name,
    select_execution_identity_mode,
};

#[test]
fn each_declared_identity_name_selects_its_exact_mode() -> Result<(), String> {
    let service = select_execution_identity_mode(SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME)
        .map_err(|error| format!("system_service selection: {error}"))?;
    let user = select_execution_identity_mode(USER_MODE_EXECUTION_IDENTITY_NAME)
        .map_err(|error| format!("user_mode selection: {error}"))?;
    if service != ExecutionIdentityMode::SystemService {
        return Err("system_service must select the SystemService mode".to_owned());
    }
    if user != ExecutionIdentityMode::UserMode {
        return Err("user_mode must select the UserMode mode".to_owned());
    }
    if service == user {
        return Err("the two identity names must not collapse to one mode".to_owned());
    }
    // The selected identity is observable and comparable, not merely branched
    // on: each mode renders back to the exact declared name I1.6 spells.
    if execution_identity_mode_name(service) != "system_service" {
        return Err("SystemService mode must render back to system_service".to_owned());
    }
    if execution_identity_mode_name(user) != "user_mode" {
        return Err("UserMode mode must render back to user_mode".to_owned());
    }
    Ok(())
}

#[test]
fn an_undeclared_identity_name_is_refused_not_defaulted() {
    // `portable_dev` is an installation profile, not one of the two execution
    // identities I1.6 defines. Empty, differently-cased and padded spellings
    // of the two real names are refused for the same reason: the selection is
    // over the exact declared literals, not a lenient parse of them.
    for name in [
        "portable_dev",
        "",
        "SystemService",
        " user_mode",
        "user-mode",
        "local_system",
    ] {
        assert_eq!(
            select_execution_identity_mode(name),
            Err(WindowsAdapterError::InvalidInput),
            "an undeclared execution identity name must be refused, not defaulted"
        );
    }
}

/// The two declared names resolve to two DIFFERENT, named principals.
///
/// This is the positive case for the identity binding: `system_service` is the
/// dedicated low-privilege service account (`S-1-5-19`), while `user_mode` is
/// whatever the current user is. Observing that they differ is what makes the
/// selection a real choice rather than two branches that both reach the same
/// token. When the process running this test happens to BE that service account,
/// `user_mode` is the refusal instead and is proved by the refusal test below.
#[cfg(windows)]
#[test]
fn the_two_names_resolve_to_distinct_named_principals() -> Result<(), String> {
    use eliot_platform_windows::selected_execution_identity_sid;

    let service = selected_execution_identity_sid(SYSTEM_SERVICE_EXECUTION_IDENTITY_NAME)
        .map_err(|error| format!("system_service principal: {error}"))?;
    if service != "S-1-5-19" {
        return Err(format!(
            "system_service must be the LocalService account, got {service}"
        ));
    }
    match selected_execution_identity_sid(USER_MODE_EXECUTION_IDENTITY_NAME) {
        // The ordinary case: this test runs as an interactive user, whose SID
        // is not the service principal, so the two names really did select two
        // different identities.
        Ok(user) if !is_built_in_service_sid(&user) => Ok(()),
        Ok(user) => Err(format!("user_mode returned the service principal {user}")),
        // This test itself runs as the service account, so there is no current
        // user to select; that refusal is proved by the next test, not here.
        Err(WindowsAdapterError::IdentityMismatch) => Ok(()),
        Err(other) => Err(format!("unexpected user_mode failure: {other}")),
    }
}

/// `user_mode` is refused when the launching process is a built-in service
/// account.
///
/// `I1.6` requires `user_mode` to run "under the current user without
/// pretending to be an SCM service". A built-in service account has no current
/// user, so a `user_mode` launch from one must be refused rather than silently
/// run as the service. This runs the same code path the selection uses, so the
/// refusal is the real outcome for a service-account launcher and a successful
/// current-user read otherwise.
#[cfg(windows)]
#[test]
fn user_mode_from_a_service_account_is_refused() -> Result<(), String> {
    use eliot_platform_windows::selected_execution_identity_sid;

    match selected_execution_identity_sid(USER_MODE_EXECUTION_IDENTITY_NAME) {
        Err(WindowsAdapterError::IdentityMismatch) => Ok(()),
        Err(other) => Err(format!("unexpected user_mode failure: {other}")),
        // A non-service current user is the ordinary case: the read succeeds,
        // which is the only correct alternative to the refusal.
        Ok(sid) if !is_built_in_service_sid(&sid) => Ok(()),
        Ok(sid) => Err(format!("user_mode returned a service principal {sid}")),
    }
}

#[cfg(windows)]
fn is_built_in_service_sid(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}
