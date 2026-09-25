//! Owner-side encoding of the broker-authorized Notify request channel
//! (issue #1781, W1/A1).
//!
//! Architecture anchors: I11.6:3 (normal `eliot-notify` delivery launches only
//! through the authorized User Broker) and I1.3 (`eliot-notify.exe` is a
//! per-user one-shot adapter whose processes belong to the User Broker Job
//! Object).
//!
//! The channel shape is owned together with the value it carries. The flag, the
//! reference type, its `deny_unknown_fields` decode, its self-consistency
//! validator, and the one encoding that reaches a command line all live in this
//! owner, so the broker that produces the argv and the child that decodes it
//! cannot drift and neither can grow a second spelling of the same request.
//!
//! This is the producer's only serialization authority. A broker never forwards
//! caller bytes: it proves a reference with
//! [`NotifyLaunchRequestReference::validate`] and then emits exactly one
//! canonical encoding of that value, so no caller-controlled spacing, key
//! order, or duplicated key can reach the child. Refusals are typed and carry a
//! stable code only: no content, digest, identity, or path is echoed.

use crate::{NOTIFY_REQUEST_ARGUMENT, NotifyLaunchRequestReference};

/// Fail-closed refusal from encoding one broker-authorized request channel.
///
/// The two causes — a reference that is not one self-consistent canonical
/// request, and a value with no canonical single-line encoding — are the same
/// refusal for the launcher: there is no request this channel can carry, and
/// both are decided by the binding owner rather than by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyRequestChannelError {
    /// The reference is not one canonical, self-consistent, single-line
    /// request reference.
    NotCanonicalReference,
}

impl NotifyRequestChannelError {
    /// Stable code for this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotCanonicalReference => "NOTIFY_REQUEST_REFERENCE_REJECTED",
        }
    }
}

impl std::fmt::Display for NotifyRequestChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NotifyRequestChannelError {}

/// Builds the exact argv of one broker-authorized normal notification launch.
///
/// The returned vector is EXACTLY two elements — [`NOTIFY_REQUEST_ARGUMENT`]
/// and one single-line JSON object — which is the whole launch shape the child's
/// `parse_launch_args` decodes, and the whole shape its `--watchdog-fallback`
/// contour refuses. Nothing else is representable here, so a caller cannot
/// reach a scheduler mode or add an argument through this channel.
///
/// The reference is proved with its own owner validator first, so a value that
/// cannot satisfy the three delivery-core bindings (`request.validate`, the
/// notification-id join, and the canonical request-hash join) is refused before
/// it is put on a command line instead of after the child's Kernel round trip.
///
/// # Errors
///
/// Returns [`NotifyRequestChannelError::NotCanonicalReference`] when the
/// reference is not one self-consistent canonical request or has no canonical
/// single-line encoding.
pub fn notify_request_arguments(
    reference: &NotifyLaunchRequestReference,
) -> Result<Vec<String>, NotifyRequestChannelError> {
    reference
        .validate()
        .map_err(|_| NotifyRequestChannelError::NotCanonicalReference)?;
    // The compact writer emits no insignificant whitespace and escapes every
    // control character inside a string, so the payload can never contain a raw
    // control byte and therefore can never span lines: one argument, one line,
    // and no way for a line-oriented read to be handed a second request.
    let encoded = serde_json::to_string(reference)
        .map_err(|_| NotifyRequestChannelError::NotCanonicalReference)?;
    Ok(vec![NOTIFY_REQUEST_ARGUMENT.to_owned(), encoded])
}
