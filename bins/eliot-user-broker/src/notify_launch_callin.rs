//! Broker-owned Notify normal-launch call-in staging (issue #1781, W2/A1).
//!
//! Architecture anchors: I11.6:3 (normal `eliot-notify` delivery launches only
//! through the authorized User Broker on a Kernel-authorized grant) and I11.8:3
//! (the broker binding carries the interactive user/session identity plus the
//! Kernel challenge, so a launch staged outside that binding is refused).
//!
//! This module makes the normal Notify invocation originate from the
//! authenticated User Broker only. It stages the grant inputs produced by
//! [`eliot_notify::resolve_notify_launch_inputs`] and binds them to the
//! broker's authenticated session before the composition spawns anything:
//!
//! - The caller performs the single protected lease read at its edge and
//!   injects the declaration BYTES here. This module leases/reads NOTHING
//!   itself (mirrors the `notify_launch` pattern: tests would inject fixture
//!   bytes, production injects protected-lease bytes).
//! - The caller passes the authenticated SID, the interactive session id, and
//!   the Kernel grant token/challenge string it already holds. Empty inputs
//!   fail closed; a declaration whose embedded user/session identity does not
//!   equal the authenticated pair fails closed. The challenge is an opaque
//!   presence-bound token here — grant authenticity itself is enforced by the
//!   Kernel authority port when the staged inputs flow through the existing
//!   `BrokerComposition::launch` path.
//! - The return value is the broker-retained launch authority
//!   ([`BrokerNotifyLaunchAuthority`]): the verified `executable_path`,
//!   `artifact_digest`, and `installation_identity` this broker observed, plus
//!   the staging outcome. The reference is retained, never dropped, because
//!   [`crate::BrokerComposition::launch_notify`] is the only dispatcher that
//!   may spawn the notification adapter and it re-checks every request against
//!   exactly these bytes. There is no `std::process::Command` in this module;
//!   the composition root stays thin per `bins/AGENTS.md` and dispatch happens
//!   on the existing `BrokerComposition` authority/process ports.
//! - The production caller is [`crate::stage_normal_notify_launch`], invoked at
//!   broker startup through [`crate::BrokerComposition::stage_notify_launch`];
//!   the broker's `Ready` channel then reports the retained outcome as stable
//!   codes only.
//!
//! Deterministic launch-input staging lives here (broker-owned launch staging,
//! allowed under `bins/AGENTS.md`); the Notify declaration state machine and
//! installed-binary verification stay owned by `eliot-notify` and are reused,
//! never duplicated. Errors are fail-closed stable codes only: no paths,
//! payloads, digests, SIDs, or challenge material are echoed.

use std::path::{Path, PathBuf};

use eliot_notify::{
    NOTIFY_IMAGE_FILE_NAME, NOTIFY_REQUEST_ARGUMENT, NotifyLaunchError,
    NotifyLaunchRequestReference, VerifiedNotifyLaunch, resolve_notify_launch_inputs,
};

/// Verified Notify launch inputs staged for one broker-bound grant.
///
/// The exact installed executable path plus the digest of the bytes observed
/// at resolution and the installation identity from the validated declaration
/// record. The manager names these same bytes in the `LaunchRequest` it sends
/// through `BrokerComposition::launch`, so a file swapped between staging and
/// launch fails the launch-time re-hash instead of executing unverified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLaunchRef {
    /// Verified installation-approved executable path.
    executable_path: PathBuf,
    /// Lowercase hex SHA-256 of the exact bytes observed at resolution.
    artifact_digest: String,
    /// Installation identity from the validated declaration record.
    installation_identity: String,
}

impl VerifiedLaunchRef {
    /// Returns the verified executable path for the staged grant.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    /// Returns the hex digest of the bytes observed at resolution.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    /// Returns the installation identity from the validated record.
    #[must_use]
    pub fn installation_identity(&self) -> &str {
        &self.installation_identity
    }
}

impl From<VerifiedNotifyLaunch> for VerifiedLaunchRef {
    fn from(resolved: VerifiedNotifyLaunch) -> Self {
        Self {
            executable_path: resolved.executable_path().to_path_buf(),
            artifact_digest: resolved.artifact_digest().as_str().to_owned(),
            installation_identity: resolved.installation_identity().to_owned(),
        }
    }
}

/// Fail-closed broker-bound Notify launch staging errors. Codes only — no
/// paths, payloads, digests, SIDs, or challenge material are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerNotifyError {
    /// The broker has no authenticated launch binding composed (or its
    /// retained protected lease no longer verifies).
    NotAuthenticated,
    /// The caller-supplied authenticated SID, session id, or Kernel
    /// challenge is empty/missing.
    InvalidIdentity,
    /// The declaration's embedded user/session identity does not equal the
    /// broker's authenticated pair.
    IdentityMismatch,
    /// The declaration bytes do not decode, validate, or match canonical
    /// form (includes unreadable embedded identity fields).
    InvalidDeclaration,
    /// The bound installed binary failed verification.
    BindingRejected,
    /// The request does not name the canonical installed Notify image, so it
    /// cannot be admitted on the notify-specific launch path.
    NotNotifyImage,
    /// The request's argv does not carry the notify-specific canonical request
    /// reference, or that reference is not the self-consistent pair the child
    /// would decode.
    InvalidRequestReference,
}

impl BrokerNotifyError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotAuthenticated => "BROKER_NOTIFY_NOT_AUTHENTICATED",
            Self::InvalidIdentity => "BROKER_NOTIFY_INVALID_IDENTITY",
            Self::IdentityMismatch => "BROKER_NOTIFY_IDENTITY_MISMATCH",
            Self::InvalidDeclaration => "BROKER_NOTIFY_INVALID_DECLARATION",
            Self::BindingRejected => "BROKER_NOTIFY_BINDING_REJECTED",
            Self::NotNotifyImage => "BROKER_NOTIFY_IMAGE_REQUIRED",
            Self::InvalidRequestReference => "BROKER_NOTIFY_REQUEST_REFERENCE_REJECTED",
        }
    }
}

impl std::fmt::Display for BrokerNotifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BrokerNotifyError {}

fn map_launch_error(error: &NotifyLaunchError) -> BrokerNotifyError {
    match error {
        NotifyLaunchError::InvalidDeclaration => BrokerNotifyError::InvalidDeclaration,
        NotifyLaunchError::Binding(_) => BrokerNotifyError::BindingRejected,
    }
}

/// Resolves broker-bound Notify launch inputs from caller-injected
/// declaration bytes.
///
/// The caller performs the single protected lease read at its edge and passes
/// the exact bytes plus its authenticated SID, interactive session id, and
/// Kernel grant token/challenge string. Caller identity inputs are checked
/// first (fail-closed, before any declaration work), then the declaration is
/// resolved through `eliot-notify`, then the declaration's embedded
/// `interactive_user_sid` / `interactive_session_id` must equal the
/// authenticated pair.
///
/// # Errors
///
/// Returns [`BrokerNotifyError::InvalidIdentity`] when the SID or challenge
/// is blank or the session id is zero, [`BrokerNotifyError::InvalidDeclaration`]
/// when the bytes do not decode/validate, [`BrokerNotifyError::BindingRejected`]
/// when the installed binary fails verification, and
/// [`BrokerNotifyError::IdentityMismatch`] when the declaration names a
/// different user/session than the authenticated broker session.
pub fn resolve_broker_notify_launch(
    declaration_bytes: &[u8],
    authenticated_sid: &str,
    interactive_session_id: u32,
    kernel_challenge: &str,
) -> Result<VerifiedLaunchRef, BrokerNotifyError> {
    if authenticated_sid.trim().is_empty()
        || kernel_challenge.trim().is_empty()
        || interactive_session_id == 0
    {
        return Err(BrokerNotifyError::InvalidIdentity);
    }
    if declaration_bytes.is_empty() {
        return Err(BrokerNotifyError::InvalidDeclaration);
    }
    let resolved = resolve_notify_launch_inputs(declaration_bytes)
        .map_err(|error| map_launch_error(&error))?;
    let declared: serde_json::Value = serde_json::from_slice(declaration_bytes)
        .map_err(|_| BrokerNotifyError::InvalidDeclaration)?;
    let declared_sid = declared
        .get("interactive_user_sid")
        .and_then(serde_json::Value::as_str)
        .ok_or(BrokerNotifyError::InvalidDeclaration)?;
    let declared_session = declared
        .get("interactive_session_id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(BrokerNotifyError::InvalidDeclaration)?;
    if declared_sid != authenticated_sid || declared_session != u64::from(interactive_session_id) {
        return Err(BrokerNotifyError::IdentityMismatch);
    }
    Ok(VerifiedLaunchRef::from(resolved))
}

/// Installer-published Notify declaration record location, shared with the
/// fallback route (one installed image, one record).
const NOTIFY_DECLARATION_RELATIVE: &str = "Eliot/notify/watchdog-verification.json";

/// Upper bound for the single protected declaration lease read at the broker
/// edge. The record is a small fixed-field JSON document; anything larger
/// fails closed before parsing.
const DECLARATION_BYTES_LIMIT: u64 = 64 * 1024;

/// Best-effort normal-launch staging outcome for the broker `Ready` channel
/// (I11.7: failed delivery remains visible). Staging never spawns. `Staged`
/// means the broker verified it can name the exact installed image AND retains
/// that verified reference for the notify-specific spawn on
/// [`BrokerComposition::launch_notify`](crate::BrokerComposition::launch_notify);
/// the generic launch dispatcher refuses that image outright. Only stable
/// state/reason codes cross this boundary — never paths, digests, SIDs, or
/// payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyLaunchStage {
    /// Normal-launch inputs staged against the published declaration.
    Staged,
    /// No installer-published declaration present; nothing fabricated.
    SkippedNoDeclaration,
    /// Staging failed; retry on the next start. Reason is a stable
    /// variant code, never a path or payload.
    Deferred {
        /// Stable deferral code.
        reason: &'static str,
    },
}

impl NotifyLaunchStage {
    /// Diagnostic projection of the outcome for the broker `Ready` channel.
    #[must_use]
    pub fn status_value(&self) -> serde_json::Value {
        match self {
            Self::Staged => serde_json::json!({"state": "staged"}),
            Self::SkippedNoDeclaration => {
                serde_json::json!({"state": "skipped_no_declaration"})
            }
            Self::Deferred { reason } => {
                serde_json::json!({"state": "deferred", "reason": reason})
            }
        }
    }
}

/// Broker-retained normal Notify launch state.
///
/// The verified launch reference is RETAINED, never discarded: it is the only
/// thing the broker will spawn on the normal route, and
/// [`BrokerComposition::launch_notify`](crate::BrokerComposition::launch_notify)
/// re-checks every request against these exact bytes. A deferred or skipped
/// staging carries no reference at all, so an unverified image can never be
/// launched as a notification adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerNotifyLaunchAuthority {
    launch: Option<VerifiedLaunchRef>,
    stage: NotifyLaunchStage,
}

impl BrokerNotifyLaunchAuthority {
    /// The staging outcome for the broker `Ready` diagnostic.
    #[must_use]
    pub fn stage(&self) -> &NotifyLaunchStage {
        &self.stage
    }

    /// Diagnostic projection of the retained staging outcome, including whether
    /// a notify spawn is currently admissible.
    #[must_use]
    pub fn status_value(&self) -> serde_json::Value {
        let mut value = self.stage.status_value();
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                String::from("admissible"),
                serde_json::Value::Bool(self.launch.is_some()),
            );
        }
        value
    }

    /// Whether the broker currently holds a verified notify launch reference.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        self.launch.is_some()
    }

    /// The retained verified launch reference, if staging succeeded.
    #[must_use]
    pub fn launch_ref(&self) -> Option<&VerifiedLaunchRef> {
        self.launch.as_ref()
    }

    /// Builds an authority that retains no launch reference.
    ///
    /// Only a `Staged` outcome carries a reference; every other outcome is
    /// structurally inadmissible for a notify spawn.
    pub(crate) fn unstaged(stage: NotifyLaunchStage) -> Self {
        Self {
            launch: None,
            stage,
        }
    }
}

/// Admits one request against the broker-retained verified launch reference.
///
/// The canonical image name is reused from the `eliot-notify` binding owner
/// ([`NOTIFY_IMAGE_FILE_NAME`]), so a generic broker request naming that image
/// is refused here and it can be spawned only through the notify-specific,
/// broker-authorized path.
///
/// Four independent bindings must all hold before a notify adapter may be
/// spawned: the request must name the exact verified executable path, its
/// artifact digest must equal the digest of the bytes this broker observed when
/// it resolved the installer-published declaration, and its argv must be exactly
/// the two-argument notify-specific request channel that
/// `admit_notify_request_reference` describes. A file swapped between staging
/// and launch therefore fails the request-time comparison as well as the
/// launch-time re-hash inside the process port, and a launch that names no
/// request the child can authenticate is refused here instead of at the child's
/// own boundary.
///
/// The retained reference itself stays inside the composition: returning it
/// would only re-expose the same verified bytes the request already names, and
/// holding the borrow across the dispatch would tie admission to the very
/// mutable borrow the spawn needs.
///
/// # Errors
///
/// Returns [`BrokerNotifyError::NotAuthenticated`] when the broker retains no
/// verified reference, [`BrokerNotifyError::NotNotifyImage`] when the request
/// does not name the canonical installed Notify image,
/// [`BrokerNotifyError::BindingRejected`] when the executable path or artifact
/// digest diverges from the retained verified bytes, and
/// [`BrokerNotifyError::InvalidRequestReference`] when the argv is not the
/// notify-specific canonical request reference.
pub fn admit_notify_request(
    authority: &BrokerNotifyLaunchAuthority,
    request: &eliot_user_broker_core::LaunchRequest,
) -> Result<(), BrokerNotifyError> {
    let launch = authority
        .launch_ref()
        .ok_or(BrokerNotifyError::NotAuthenticated)?;
    let approved = &request.approved;
    if Path::new(&approved.executable)
        .file_name()
        .and_then(|name| name.to_str())
        != Some(NOTIFY_IMAGE_FILE_NAME)
    {
        return Err(BrokerNotifyError::NotNotifyImage);
    }
    let expected_executable = launch.executable_path().to_string_lossy();
    if approved.executable.as_str() != expected_executable.as_ref()
        || approved.artifact_digest != launch.artifact_digest()
    {
        return Err(BrokerNotifyError::BindingRejected);
    }
    admit_notify_request_reference(&approved.argv)
}

/// Admits the notify-specific argv request channel of one launch request.
///
/// I11.6:3 makes the authorized User Broker the only launcher of a normal
/// `eliot-notify` delivery, and an inherited stdin stream is not a channel the
/// child can authenticate, so the canonical request reference travels on the
/// launch's own argv. The admitted shape is exactly two arguments: the
/// notify-specific flag owned by the binding owner ([`NOTIFY_REQUEST_ARGUMENT`])
/// followed by one canonical request reference — a single JSON object with
/// exactly two keys, `request` (a `NotificationRequest`) and `envelope` (a
/// `NotificationEnvelope`), and nothing else.
///
/// The reference is decoded with the same `deny_unknown_fields` type the child
/// decodes and must satisfy the same self-consistency bindings, so a
/// broker-authorized launch can never carry a request the child would not
/// recognise, and no other broker request shape can reach the notification
/// adapter. The reference names canonical notification state and nothing else:
/// it is not a credential, and it is actionable only after the child proves it
/// against canonical state through the authenticated Kernel read.
fn admit_notify_request_reference(argv: &[String]) -> Result<(), BrokerNotifyError> {
    let mut values = argv.iter();
    let (Some(flag), Some(encoded), None) = (values.next(), values.next(), values.next()) else {
        return Err(BrokerNotifyError::InvalidRequestReference);
    };
    if flag.as_str() != NOTIFY_REQUEST_ARGUMENT
        || encoded.trim().is_empty()
        || encoded.chars().any(char::is_control)
    {
        return Err(BrokerNotifyError::InvalidRequestReference);
    }
    let reference = serde_json::from_str::<NotifyLaunchRequestReference>(encoded)
        .map_err(|_| BrokerNotifyError::InvalidRequestReference)?;
    reference
        .validate()
        .map_err(|_| BrokerNotifyError::InvalidRequestReference)
}

/// Returns whether one generic broker request names the canonical Notify image.
///
/// Used to refuse the generic `Launch` operation for the notification adapter:
/// that image is reachable only through the notify-specific admitted path, so
/// a normal `eliot-notify` invocation cannot be produced by any other broker
/// request shape.
#[must_use]
pub fn request_names_notify_image(request: &eliot_user_broker_core::LaunchRequest) -> bool {
    Path::new(&request.approved.executable)
        .file_name()
        .and_then(|name| name.to_str())
        == Some(NOTIFY_IMAGE_FILE_NAME)
}

/// Stages normal Notify launch inputs at the broker edge and RETAINS the
/// verified launch reference.
///
/// This is the production caller of
/// [`crate::BrokerComposition::resolve_notify_launch`]: it performs the
/// single protected lease read of the installer-published declaration and
/// retains the verified launch inputs that
/// [`crate::BrokerComposition::launch_notify`] later spawns.
/// Best-effort and infallible by design — like the fallback ensure, staging
/// must never fail broker startup. Absence skips explicitly; staging failure
/// defers with a stable code and retains no reference.
pub fn stage_normal_notify_launch(
    composition: &crate::BrokerComposition,
) -> BrokerNotifyLaunchAuthority {
    let Ok(path) = eliot_platform_windows::protected_program_data_path(NOTIFY_DECLARATION_RELATIVE)
    else {
        return BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
            reason: "PROTECTED",
        });
    };
    if !std::path::Path::new(&path).exists() {
        return BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::SkippedNoDeclaration);
    }
    let Ok(lease) = eliot_platform_windows::ProtectedPathLease::open_existing_absolute(&path)
    else {
        return BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
            reason: "PROTECTED",
        });
    };
    let Ok(bytes) = lease.read_bounded(DECLARATION_BYTES_LIMIT) else {
        return BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
            reason: "PROTECTED",
        });
    };
    match composition.resolve_notify_launch(&bytes) {
        Ok(launch) => BrokerNotifyLaunchAuthority {
            launch: Some(launch),
            stage: NotifyLaunchStage::Staged,
        },
        Err(error) => BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
            reason: stage_deferral_code(&error),
        }),
    }
}

fn stage_deferral_code(error: &BrokerNotifyError) -> &'static str {
    match error {
        BrokerNotifyError::NotAuthenticated => "NOT_AUTHENTICATED",
        BrokerNotifyError::InvalidIdentity => "INVALID_IDENTITY",
        BrokerNotifyError::IdentityMismatch => "IDENTITY_MISMATCH",
        BrokerNotifyError::InvalidDeclaration => "INVALID_DECLARATION",
        BrokerNotifyError::BindingRejected => "BINDING_REJECTED",
        BrokerNotifyError::NotNotifyImage => "NOT_NOTIFY_IMAGE",
        BrokerNotifyError::InvalidRequestReference => "INVALID_REQUEST_REFERENCE",
    }
}
