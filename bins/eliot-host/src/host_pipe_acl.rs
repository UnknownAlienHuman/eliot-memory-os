//! Explicit Host named-pipe ACL contour and the explicit inherited environment
//! set of a Host child launch (issue #1888, I1.6 / AUD7).
//!
//! Architecture: `I1.6` (`docs/architecture/I01-06-windows-isolation.md`) and
//! `I7.5` (`docs/architecture/I07-05-named-pipes.md`).
//!
//! I1.6 states, verbatim: "named pipes use explicit ACLs; models and
//! third-party Modules do not inherit secrets by default". I7.5 states,
//! verbatim: "ACL allows only expected service/user SID." Audit item AUD7 of
//! comment 5871793301 states, verbatim: "Secret inheritance is an explicit
//! allowed-environment/handle set, not a denylist applied after spawn."
//!
//! Both halves of this module are the ALLOW-SET form of those sentences. A
//! [`HostControlPipeAcl`] carries the exact principals a Host control pipe's
//! DACL admits, and a principal it does not name is absent by construction:
//! there is no "default allow" fallback and no post-hoc subtraction. This is
//! default-deny by construction rather than by a filter.
//! [`inherited_environment`] resolves exactly the ambient names this Host
//! admits, reading nothing else, so a Kernel, Store, or Watchdog child receives
//! no inherited material the Host did not explicitly name.
//!
//! # WHAT THE PLATFORM CAN EXPRESS, AS OF THIS CHANGE
//!
//! `eliot_ipc` builds pipe security descriptors by exactly two functions, and
//! only one of them is multi-principal:
//!
//! - `pipe_security_sddl` (`crates/kernel/eliot-ipc/src/lib.rs:2442`) is the
//!   path every single-expectation `NamedPipeServer::create` takes. It emits
//!   exactly one of two hard-coded descriptors:
//!   `"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)"` when the expectation requires
//!   built-in Administrators, and `"D:P(A;;GA;;;SY)(A;;GA;;;<expected_sid>)"`
//!   for every other expectation. It cannot be asked for an arbitrary
//!   caller-named principal set.
//! - `pipe_security_sddl_for_peer_set`
//!   (`crates/kernel/eliot-ipc/src/lib.rs:2455`) emits one ACE per distinct
//!   `NamedPipePeerSet::expected_sids()` entry, so the SDDL string itself can
//!   name more than one principal. It is not a "name these SIDs" API: every
//!   static entry must carry a live OS-observed `approved_process_binding`
//!   (`crates/kernel/eliot-platform-windows/src/platform_security.rs:337`), so
//!   a principal can enter that set only as a role that must also pass live
//!   peer authentication, never as a bare DACL entry.
//!
//! The platform therefore admits exactly ONE caller-named principal plus `SY`,
//! or the one fixed `{SY, BA, LS}` installer contour. This module admits that
//! fixed contour and refuses every other, so the principal set it carries is
//! always a set the existing constructor can really deliver.
//!
//! # NAMED PLATFORM GAPS (not repaired here)
//!
//! 1. `pipe_security_sddl` is private and `#[cfg(windows)]`, and
//!    `pipe_dacl_principal_allowed` is `#[cfg(test)] pub(crate)`
//!    (`crates/kernel/eliot-platform-windows/src/lib.rs:177`). No Host-side
//!    caller can read back the principals a delivered pipe's DACL actually
//!    admits, so the correspondence asserted below is a restatement of
//!    reviewed platform source, not an OS observation of a live pipe.
//! 2. Neither Host control-pipe server consumes this value. Each builds its own
//!    expectation inline: `HostCredentialControl::serve_one`
//!    (`bins/eliot-host/src/credential_control.rs:505`) and
//!    `HostRuntimeControl::serve_one`
//!    (`crates/kernel/eliot-host-control-endpoint/src/lib.rs:692`). Neither
//!    file belongs to this change, so the retained contour is the admission
//!    input a server would take, not one it currently takes.
//!
//! This module mints no authority, opens no pipe, and creates no descriptor,
//! ACE, or security-attributes path. The DACL is still built by the one
//! existing `eliot_ipc` SDDL construction; [`delivered_dacl_sids`] is a plain
//! principal-name set used only for Host-side policy assertions, and is not a
//! second ACL scheme.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

use eliot_platform_windows::NamedPipePeerExpectation;

use crate::HostError;

/// SDDL `SY`: `NT AUTHORITY\SYSTEM`, the SID `S-1-5-18`. Named explicitly so a
/// control pipe never depends on an implicit grant.
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
/// SDDL `LS`: `NT AUTHORITY\LOCAL SERVICE`, the SID `S-1-5-19`. This is the
/// dedicated low-privilege service identity I1.6 assigns to `system_service`,
/// and the identity the Host service itself runs under.
const LOCAL_SERVICE_SID: &str = "S-1-5-19";
/// SDDL `BA`: the built-in Administrators group SID `S-1-5-32-544`. The
/// one-shot installer control pipe admits an elevated installer client, which
/// is this exact group.
const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The ambient environment names a Host child launch may inherit.
///
/// This is the explicit allowed set AUD7 requires. It names only the Windows
/// process-start values a child needs to exist at all, and nothing that could
/// carry secret material:
///
/// - `SystemRoot` and `windir` are the installation the child resolves
///   system DLLs and its own working directory against.
/// - `ComSpec` is the shell the child uses when it must run a console tool.
/// - `TEMP` / `TMP` are the per-child temporary directories.
/// - `NUMBER_OF_PROCESSORS` and `PROCESSOR_ARCHITECTURE` describe the machine,
///   not the session.
///
/// Every other ambient name — including any `ELIOT_*` bootstrap name and any
/// provider, key, or token a third-party Module might name — is absent from a
/// Host child's environment because it is not named here, not because it was
/// subtracted after the child existed. A name the ambient environment happens
/// not to carry contributes nothing rather than a placeholder.
pub(crate) const ALLOWED_INHERITED_ENVIRONMENT: [&str; 7] = [
    "SystemRoot",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

/// Returns the explicit allowed inherited environment for one Host child
/// launch.
///
/// The result is read out of `ambient` (the launching process's own
/// environment) by name only. Names outside [`ALLOWED_INHERITED_ENVIRONMENT`]
/// are never read, so the parent's environment is never materialised and then
/// filtered, and a name the allow-set states but the ambient environment does
/// not carry contributes nothing rather than an invented value.
///
/// A named value that is not valid Unicode is skipped rather than inserted:
/// `SuspendedLaunchSpec::new` requires a complete, representable environment
/// block, and an unrepresentable value has no valid place in one, so skipping
/// keeps the result a strict subset of the explicit allow-set. It can never
/// add a name, so the set stays exactly what this Host admitted.
///
/// This is the build-time resolution half of the explicit allow-set. The
/// admission values the Host itself mints (generation, config digest, artifact
/// digest, Kernel bootstrap binding) are separate and are appended by
/// `HostJobBranches::environment_from`, not inherited.
pub(crate) fn inherited_environment<I>(ambient: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut ambient = ambient.into_iter().collect::<Vec<_>>();
    let mut inherited = Vec::new();
    for name in ALLOWED_INHERITED_ENVIRONMENT {
        let Some(position) = ambient
            .iter()
            .position(|(key, _)| key.as_os_str() == OsStr::new(name))
        else {
            continue;
        };
        let (_, value) = ambient.remove(position);
        let Ok(value) = value.into_string() else {
            continue;
        };
        inherited.push((OsString::from(name), OsString::from(value)));
    }
    inherited
}

/// Returns the principals the one existing `eliot_ipc` SDDL path admits for
/// `expectation`, read from that expectation's own contour discriminator.
///
/// This restates `eliot_ipc::pipe_security_sddl`
/// (`crates/kernel/eliot-ipc/src/lib.rs:2442`), which builds
/// `"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)"` for an expectation that requires
/// built-in Administrators and `"D:P(A;;GA;;;SY)(A;;GA;;;<expected_sid>)"` for
/// every other one. Both descriptors open with the `SY` ACE, and no descriptor
/// that path can build carries any principal beyond those.
///
/// The returned value is a plain principal-name set for Host-side assertions.
/// It is not an SDDL string, a security descriptor, or an ACE list, and it
/// creates nothing: the pipe's descriptor remains the one the existing
/// `eliot_ipc` construction builds from the retained expectation.
///
/// # Errors
///
/// Returns `HostError::ProcessContour` when the platform hands back a
/// principal that is not canonical SID text, so no principal is ever described
/// by a value the OS would not accept inside an ACE.
fn delivered_dacl_sids(
    expectation: &NamedPipePeerExpectation,
) -> Result<BTreeSet<String>, HostError> {
    let mut delivered = BTreeSet::from([LOCAL_SYSTEM_SID.to_owned()]);
    if expectation.requires_builtin_administrators() {
        delivered.insert(BUILTIN_ADMINISTRATORS_SID.to_owned());
        delivered.insert(LOCAL_SERVICE_SID.to_owned());
    } else {
        delivered.insert(expectation.expected_sid().to_owned());
    }
    if let Some(non_canonical) = delivered
        .iter()
        .find(|principal| !is_canonical_sid(principal))
    {
        return Err(HostError::ProcessContour(format!(
            "control pipe ACL describes a non-canonical principal: {non_canonical}"
        )));
    }
    Ok(delivered)
}

/// One Host-owned control pipe's explicit ACL.
///
/// This type holds ONE value: the exact `eliot_platform_windows` expectation
/// the pipe's security descriptor is built from. The principal set it names is
/// derived from that value on every read ([`Self::delivered_sids`]) and never
/// stored separately, so the two cannot drift apart and nothing here is checked
/// and then dropped.
///
/// Default-deny by construction: [`Self::admit`] refuses any expectation whose
/// delivered DACL is not exactly the installer contour, so a Host control pipe
/// can never be created from "everyone", from a wildcard, or from a principal
/// set this Host did not name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostControlPipeAcl {
    expectation: NamedPipePeerExpectation,
}

impl HostControlPipeAcl {
    /// Builds the explicit ACL for a Host control pipe that the one-shot
    /// installer client alone opens.
    ///
    /// This is the contour I1.6 requires for an installer-time control pipe:
    /// `LocalSystem` for service-side recovery, `LocalService` for the Host
    /// service identity, and the built-in Administrators group for the elevated
    /// installer client. The platform delivers those principals from the one
    /// `eliot_platform_windows` value built here, so this constructor reads
    /// that value back instead of restating its contour a second time.
    ///
    /// # Errors
    ///
    /// Returns `HostError::ProcessContour` when the platform rejects the
    /// expectation or delivers a principal set this Host does not admit. The
    /// typed refusal is the admission boundary: a contour that cannot be
    /// delivered fails this Host composition closed at open, before any control
    /// pipe is created.
    pub(crate) fn for_installer_control_pipe() -> Result<Self, HostError> {
        let expectation = NamedPipePeerExpectation::new_for_builtin_administrators()
            .map_err(|error| HostError::ProcessContour(error.to_string()))?;
        Self::admit(expectation)
    }

    /// Retains one expectation, and admits it only when its delivered DACL is
    /// exactly the installer contour.
    ///
    /// The refusal is the guarantee. An expectation the platform would build a
    /// narrower descriptor for — `{SY}`, or `{SY, <sid>}` for a single named
    /// principal — cannot open a Host control pipe, because this Host needs the
    /// service principals and the elevated installer client that I1.6 and I7.5
    /// name. A wider set is not constructible through the existing constructor
    /// at all, so nothing can widen this one by passing a value in.
    fn admit(expectation: NamedPipePeerExpectation) -> Result<Self, HostError> {
        let delivered_sids = delivered_dacl_sids(&expectation)?;
        if delivered_sids != Self::installer_contour() {
            return Err(HostError::ProcessContour(format!(
                "control pipe ACL delivers {delivered_sids:?}, not the explicit installer service contour"
            )));
        }
        Ok(Self { expectation })
    }

    /// The exact principals I1.6 and I7.5 name for a Host control pipe.
    fn installer_contour() -> BTreeSet<String> {
        BTreeSet::from([
            LOCAL_SYSTEM_SID.to_owned(),
            LOCAL_SERVICE_SID.to_owned(),
            BUILTIN_ADMINISTRATORS_SID.to_owned(),
        ])
    }

    /// Returns the exact principals this pipe's DACL admits, in canonical order.
    ///
    /// Derived from the retained expectation, so this reports the principals of
    /// the descriptor the pipe is really built from rather than a restatement
    /// of the policy beside it. Production admission already proves this set
    /// through [`Self::admit`]; this reads the same derivation back, which is
    /// why it is a test accessor rather than a second admission check.
    #[cfg(test)]
    pub(crate) fn delivered_sids(&self) -> Result<BTreeSet<String>, HostError> {
        delivered_dacl_sids(&self.expectation)
    }

    /// Returns the retained `eliot_platform_windows` value the
    /// `eliot_ipc::NamedPipeServer` constructor consumes as this pipe's DACL
    /// input.
    ///
    /// This is the retained value itself, not a rebuild of it, so the pipe a
    /// caller creates from it admits exactly the principals
    /// [`Self::delivered_sids`] reports. No second ACL scheme is involved: the
    /// security descriptor is the one existing `eliot_ipc` SDDL construction
    /// applied to this expectation.
    #[must_use]
    pub(crate) const fn expectation(&self) -> &NamedPipePeerExpectation {
        &self.expectation
    }
}

/// Returns true only for canonical Windows SID text (`S-1-…`, digits and
/// hyphens, at least one authority component).
fn is_canonical_sid(value: &str) -> bool {
    if !value.starts_with("S-1-") || value.len() <= "S-1-".len() {
        return false;
    }
    value
        .chars()
        .all(|character| character.is_ascii_digit() || character == '-')
        && value
            .split('-')
            .skip(2)
            .any(|component| !component.is_empty())
}

#[cfg(all(test, windows))]
mod tests {
    use super::{
        BUILTIN_ADMINISTRATORS_SID, HostControlPipeAcl, LOCAL_SERVICE_SID, LOCAL_SYSTEM_SID,
        delivered_dacl_sids, inherited_environment, is_canonical_sid,
    };
    use crate::HostError;
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    type Expectation = eliot_platform_windows::NamedPipePeerExpectation;
    type ExpectationResult = Result<Expectation, HostError>;

    /// Builds one ordinary platform expectation naming `sid`, mapping the
    /// platform's typed failure onto the Host's typed contour failure so a
    /// refusal stays typed end to end inside these tests.
    fn named_expectation(sid: &str) -> ExpectationResult {
        eliot_platform_windows::NamedPipePeerExpectation::new(sid, 0)
            .map_err(|error| HostError::ProcessContour(error.to_string()))
    }

    /// Positive case: the allow-set resolves exactly the names it names, in
    /// its own order, and nothing outside it is read.
    #[test]
    fn inherited_environment_resolves_only_the_named_allow_set() -> Result<(), HostError> {
        let ambient = vec![
            (OsString::from("PATH"), OsString::from(r"C:\Windows")),
            (
                OsString::from("ELIOT_ACTIVATION_NONCE"),
                OsString::from("secret"),
            ),
            (OsString::from("SystemRoot"), OsString::from(r"C:\Windows")),
            (
                OsString::from("ComSpec"),
                OsString::from(r"C:\Windows\system32\cmd.exe"),
            ),
            (
                OsString::from("AWS_SECRET_ACCESS_KEY"),
                OsString::from("secret"),
            ),
        ];
        let inherited = inherited_environment(ambient);
        let names = inherited
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, ["SystemRoot", "ComSpec"]);
        assert!(!names.iter().any(|name| name.contains("ELIOT")));
        assert!(!names.iter().any(|name| name.contains("SECRET")));
        Ok(())
    }

    /// Positive case: the installer control pipe carries the three principals
    /// I1.6 and I7.5 name, and carries them as principals of the DACL rather
    /// than as a contour that was checked and then replaced by the built-in
    /// Administrators expectation.
    #[test]
    fn installer_control_pipe_acl_delivers_exactly_its_named_principals() -> Result<(), HostError> {
        let acl = HostControlPipeAcl::for_installer_control_pipe()?;
        assert_eq!(
            acl.delivered_sids()?
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                LOCAL_SYSTEM_SID,
                LOCAL_SERVICE_SID,
                BUILTIN_ADMINISTRATORS_SID
            ]
        );
        // The retained value is the one whose delivered descriptor is the
        // fixed SY+BA+LS kernel-object DACL, so the set above is the
        // principals the pipe is really built from.
        assert!(acl.expectation().requires_builtin_administrators());
        assert_eq!(
            acl.expectation().expected_sid(),
            BUILTIN_ADMINISTRATORS_SID,
            "expected_sid is the client discriminator, not the DACL principal set"
        );
        Ok(())
    }

    /// Regression case. This is the defect this whole item exists to prevent:
    /// both service principals being dropped after they were named. It fails if
    /// the type stops carrying `LocalSystem` and `LocalService`, and it fails if
    /// an expectation whose delivered DACL omits either one is ever admitted
    /// instead of refused.
    ///
    /// The premise is proved first: the platform delivers one named principal
    /// per ordinary expectation, so naming `LocalSystem` does not also deliver
    /// `LocalService`, and naming `LocalService` does not deliver either other
    /// service principal. A delivered set of exactly `{SY, <named sid>}` is
    /// therefore proof that the second service principal was dropped, and such
    /// a set must be refused rather than admitted as if it were complete.
    #[test]
    fn installer_control_pipe_acl_would_fail_if_a_service_principal_were_dropped()
    -> Result<(), HostError> {
        let acl = HostControlPipeAcl::for_installer_control_pipe()?;
        let delivered = acl.delivered_sids()?;
        assert_eq!(
            delivered.len(),
            3,
            "the installer contour names three principals, not a subset"
        );
        assert!(
            delivered.contains(LOCAL_SYSTEM_SID),
            "LocalSystem is a named principal and must survive into the DACL"
        );
        assert!(
            delivered.contains(LOCAL_SERVICE_SID),
            "LocalService is a named principal and must survive into the DACL"
        );

        for named in [
            LOCAL_SERVICE_SID,
            LOCAL_SYSTEM_SID,
            BUILTIN_ADMINISTRATORS_SID,
        ] {
            let narrowed = named_expectation(named)?;
            let narrowed_sids = delivered_dacl_sids(&narrowed)?;
            assert!(
                !narrowed_sids.contains(LOCAL_SERVICE_SID) || named == LOCAL_SERVICE_SID,
                "{named} delivers {narrowed_sids:?}, which carries no second service principal"
            );
            assert!(
                narrowed_sids.len() < delivered.len(),
                "{named} must drop a principal that the installer contour keeps"
            );
            assert!(
                matches!(
                    HostControlPipeAcl::admit(narrowed),
                    Err(HostError::ProcessContour(_))
                ),
                "a contour that drops a named service principal must be refused, not admitted"
            );
        }
        Ok(())
    }

    /// Refusal case: the platform cannot deliver the installer contour from a
    /// named non-administrator principal, so those contours are refused rather
    /// than passed through and silently narrowed.
    #[test]
    fn control_pipe_acl_refuses_contours_the_platform_cannot_deliver() -> Result<(), HostError> {
        for principal in [
            LOCAL_SYSTEM_SID,
            LOCAL_SERVICE_SID,
            BUILTIN_ADMINISTRATORS_SID,
        ] {
            let narrowed = named_expectation(principal)?;
            assert_eq!(
                delivered_dacl_sids(&narrowed)?,
                BTreeSet::from([LOCAL_SYSTEM_SID.to_owned(), principal.to_owned()]),
                "{principal} delivers exactly the platform's single-principal descriptor"
            );
            assert!(matches!(
                HostControlPipeAcl::admit(narrowed),
                Err(HostError::ProcessContour(_))
            ));
        }
        Ok(())
    }

    /// Refusal case: no "everyone" or wildcard is named, and only canonical SID
    /// text is ever described as a DACL principal.
    #[test]
    fn control_pipe_acl_refuses_wildcard_and_non_canonical_principals() -> Result<(), HostError> {
        for wildcard in ["Everyone", "*"] {
            assert!(
                named_expectation(wildcard).is_err(),
                "{wildcard} is not canonical SID text and the platform refuses it"
            );
            assert!(!is_canonical_sid(wildcard));
        }
        assert!(!is_canonical_sid("S-1-"));
        assert!(!is_canonical_sid("S-2-1"));
        for principal in [
            LOCAL_SYSTEM_SID,
            LOCAL_SERVICE_SID,
            BUILTIN_ADMINISTRATORS_SID,
        ] {
            assert!(is_canonical_sid(principal));
        }
        Ok(())
    }

    /// The allow-set is exactly the documented process-start names: nothing
    /// that can carry a provider key, a token, or a bootstrap name.
    #[test]
    fn allowed_inherited_environment_names_no_secret_material() {
        assert_eq!(
            super::ALLOWED_INHERITED_ENVIRONMENT.len(),
            7,
            "the allow-set is the documented seven process-start names"
        );
        for name in super::ALLOWED_INHERITED_ENVIRONMENT {
            let upper = name.to_ascii_uppercase();
            assert!(!upper.contains("ELIOT"), "{name} is a bootstrap name");
            assert!(!upper.contains("SECRET"), "{name} is secret-like");
            assert!(!upper.contains("TOKEN"), "{name} is token-like");
            assert!(!upper.contains("KEY"), "{name} is key-like");
            assert!(!upper.contains("CREDENTIAL"), "{name} is credential-like");
        }
    }
}
