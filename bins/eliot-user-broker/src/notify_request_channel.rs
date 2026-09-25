//! Broker-owned producer of the normal Notify launch request channel
//! (issue #1781, W2/A1).
//!
//! Architecture anchors: I11.6:3 (normal `eliot-notify` delivery launches only
//! through the authorized User Broker) and I1.3 (the broker may "deliver
//! user-session notifications" as one of its few delegated effects, and its
//! children belong to the User Broker Job Object).
//!
//! This module is the producer half of that boundary: the broker, not the
//! caller, decides the notification child's argv. The channel itself — the flag,
//! the two-key reference, its decode, and its canonical encoding — is owned by
//! the binding owner in `eliot-notify`; this module owns only what the broker
//! is uniquely placed to decide, and refuses everything else.
//!
//! Three properties hold on this contour:
//!
//! 1. The broker owns the argv outright. A launch request that arrives with
//!    caller-selected child arguments is refused, never trimmed. A caller whose
//!    model of the boundary is "I choose the child's arguments" therefore gets a
//!    refusal it must see, not a launch whose arguments were quietly replaced.
//! 2. Every element of the channel is owner-issued and owner-proved. The
//!    canonical notification id and the canonical request hash are joined to
//!    their envelope by the binding owner's own validator; the session,
//!    capability, and role reach this process only inside the admitted launch
//!    grant. Nothing on this path synthesises a notification id, a request hash,
//!    an audience, a body digest, a fence, a session, or a default, and a refused
//!    value stays refused.
//! 3. The launch line is bounded before it is requested, so an over-long
//!    reference is an admission refusal rather than an unclassified spawn
//!    failure after the effect was already asked for.
//!
//! What this module deliberately does NOT do: re-join the reference's session
//! to the grant's session. `NotificationRequest.context.session_id` is an
//! `eliot_contracts::SessionId` and `ApprovedLaunch.session_id` is an
//! `eliot_process::SessionId`; no owner has admitted a conversion between them,
//! so comparing their text here would invent a binding, and requiring the
//! canonical request to carry a session at all would invent a contract. The
//! session is instead already bound by its own owners on this exact path:
//! `LaunchRequest::validate` admits the introduced user-session resource and
//! capability ceiling, `UserBroker::launch` admits the durable registration and
//! requires it to be this admitted SID/session/process tuple, and the G-01
//! grant supplies the child session identity.
//!
//! The channel is installed on the grant *before* the launch is dispatched, so
//! the exact argv the broker built is what the G-01 authority provider approves
//! and what the durable operation digest covers. It is not a post-hoc rewrite of
//! an approved launch.
//!
//! Deterministic launch-input construction and admission live here (broker-owned
//! launch staging, allowed under `bins/AGENTS.md`). There is no
//! `std::process::Command` in this module: dispatch stays on the existing
//! `BrokerComposition` authority/process ports. Errors are fail-closed stable
//! codes only — no paths, payloads, digests, sessions, or reference content are
//! echoed.

use eliot_notify::{NotifyLaunchRequestReference, notify_request_arguments};
use eliot_user_broker_core::LaunchRequest;

/// Windows caps one launched command line at 32 767 UTF-16 code units including
/// the terminating NUL (`CreateProcessW`). A line over that cap is an
/// unclassified spawn failure rather than an admission refusal, so the broker
/// proves the line it is about to build fits before it asks for a launch.
const MAX_LAUNCH_LINE_BYTES: usize = 32_767;

/// Fail-closed broker-bound Notify request-channel refusals. Codes only — no
/// paths, payloads, digests, sessions, or reference content are echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyRequestChannelError {
    /// The launch request already carries caller-selected child arguments.
    /// The broker owns the notification child's argv, so a caller that supplies
    /// one is refused instead of being silently overruled.
    CallerArgumentsRejected,
    /// The canonical reference is not one self-consistent canonical request, or
    /// it has no canonical single-line encoding on this channel.
    ReferenceRejected,
    /// The exact command line this broker would build exceeds the platform
    /// launch-line cap.
    LaunchLineTooLarge,
}

impl NotifyRequestChannelError {
    /// Stable code for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CallerArgumentsRejected => "BROKER_NOTIFY_CALLER_ARGUMENTS_REJECTED",
            Self::ReferenceRejected => "BROKER_NOTIFY_REQUEST_REFERENCE_REJECTED",
            Self::LaunchLineTooLarge => "BROKER_NOTIFY_LAUNCH_LINE_TOO_LARGE",
        }
    }
}

impl std::fmt::Display for NotifyRequestChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NotifyRequestChannelError {}

/// Builds the exact argv a broker-authorized normal Notify launch carries.
///
/// The result is EXACTLY two elements: the notify-specific flag owned by the
/// binding owner, and one single-line canonical request reference. It is meant
/// to replace `approved.argv` on the notify-specific launch path only, and
/// before the Kernel grant for that launch is requested, so the approved launch
/// and the durable operation digest both cover it.
///
/// # Errors
///
/// Returns [`NotifyRequestChannelError::CallerArgumentsRejected`] when the
/// request already carries caller-selected child arguments,
/// [`NotifyRequestChannelError::ReferenceRejected`] when the reference is not
/// one canonical self-consistent request, and
/// [`NotifyRequestChannelError::LaunchLineTooLarge`] when the exact launch line
/// exceeds the platform cap.
pub fn build_notify_request_channel(
    request: &LaunchRequest,
    reference: &NotifyLaunchRequestReference,
) -> Result<Vec<String>, NotifyRequestChannelError> {
    if !request.approved.argv.is_empty() {
        return Err(NotifyRequestChannelError::CallerArgumentsRejected);
    }
    let arguments = notify_request_arguments(reference)
        .map_err(|_| NotifyRequestChannelError::ReferenceRejected)?;
    if launch_line_bytes(&request.approved.executable, &arguments) > MAX_LAUNCH_LINE_BYTES {
        return Err(NotifyRequestChannelError::LaunchLineTooLarge);
    }
    Ok(arguments)
}

/// Upper bound on the bytes of the command line this broker would hand to the
/// launcher: the image path and every argument, one pair of quotes around each
/// of them, and one terminator per element including the last.
///
/// Quoting every element and counting UTF-8 bytes can only overstate the real
/// line — a UTF-8 byte count is never below the UTF-16 unit count of the same
/// text — so this bound refuses an over-long line early and never admits one the
/// platform would reject after the effect was already requested.
fn launch_line_bytes(executable: &str, arguments: &[String]) -> usize {
    let quoted = |value: &str| value.len().saturating_add(2);
    let arguments = arguments
        .iter()
        .fold(arguments.len().saturating_add(1), |total, value| {
            total.saturating_add(quoted(value))
        });
    quoted(executable).saturating_add(arguments)
}
