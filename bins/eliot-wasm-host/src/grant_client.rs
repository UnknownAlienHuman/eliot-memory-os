//! WASM grant client (issue #1955, I14.19).
//!
//! Builds the caller-known grant-request bundle from verified local
//! observations (component identity plus artifact/interface digests
//! recomputed from real bytes) and dispatches it toward the Kernel grant
//! route. No transport is bound yet — that registration span belongs to
//! Beauvoir's lane (see `CONTROL/1955-kernel-grant-handoff.md`) — so
//! dispatch fails closed with [`GrantClientError::NoTransport`]; request
//! BUILDING is real, tested logic, and the dispatch function is its single
//! fill-in point. Transport/session facts (caller principal, connection,
//! fence, epoch) are deliberately absent here: the route binds those at
//! the boundary from Kernel observation, exactly like the host-request
//! connection gate does. Nothing is fabricated to look admitted.

use std::fmt;

use eliot_wasm_runtime::Sha256Digest;

/// Caller-known grant-request bundle: observations this host can verify
/// locally. Digests always recompute from bytes; nonces and deadlines are
/// caller-chosen (uniqueness/freshness), never authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantClientBundle {
    /// Requested component identity.
    pub component_id: String,
    /// SHA-256 of the real component artifact bytes.
    pub artifact_digest: Sha256Digest,
    /// SHA-256 of the real WIT world bytes.
    pub interface_digest: Sha256Digest,
    /// Caller nonce for exactly-once issuance.
    pub nonce: String,
    /// Absolute deadline (unix ms) the grant must not outlive.
    pub deadline_unix_ms: u64,
}

/// Fail-closed grant-client errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantClientError {
    /// A local observation was blank, empty, or otherwise unusable.
    InvalidField {
        /// Stable field name.
        field: &'static str,
    },
    /// No grant transport is bound; Beauvoir's registration span owns it.
    NoTransport,
}

impl fmt::Display for GrantClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(formatter, "GRANT_CLIENT_INVALID:{field}"),
            Self::NoTransport => formatter.write_str("GRANT_CLIENT_NO_TRANSPORT"),
        }
    }
}

impl std::error::Error for GrantClientError {}

/// Builds a grant-request bundle from verified local observations.
/// Empty inputs, blank identities, and zero deadlines fail closed.
pub fn build_grant_bundle(
    component_id: &str,
    artifact_bytes: &[u8],
    wit_bytes: &[u8],
    nonce: &str,
    deadline_unix_ms: u64,
) -> Result<GrantClientBundle, GrantClientError> {
    if component_id.trim().is_empty() {
        return Err(GrantClientError::InvalidField {
            field: "component_id",
        });
    }
    if artifact_bytes.is_empty() || wit_bytes.is_empty() {
        return Err(GrantClientError::InvalidField {
            field: "bytes",
        });
    }
    if nonce.trim().is_empty() {
        return Err(GrantClientError::InvalidField { field: "nonce" });
    }
    if deadline_unix_ms == 0 {
        return Err(GrantClientError::InvalidField {
            field: "deadline_unix_ms",
        });
    }
    Ok(GrantClientBundle {
        component_id: component_id.to_owned(),
        artifact_digest: Sha256Digest::of_bytes(artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(wit_bytes),
        nonce: nonce.to_owned(),
        deadline_unix_ms,
    })
}

/// Dispatches one bundle toward the Kernel grant route.
///
/// Single fill-in point for Beauvoir's registration span: when the route
/// lands, this serializes the bundle into it and awaits the issued grant.
/// Until then it fails closed — a missing transport is never papered over
/// with a fabricated grant.
pub fn request_grant(_bundle: &GrantClientBundle) -> Result<(), GrantClientError> {
    Err(GrantClientError::NoTransport)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bundle_binds_recomputed_digests() {
        let bundle = build_grant_bundle(
            "component-1956",
            b"artifact-bytes",
            b"wit-bytes",
            "nonce-1",
            9_999_999_999_999,
        )
        .expect("bundle");
        assert_eq!(
            bundle.artifact_digest,
            Sha256Digest::of_bytes(b"artifact-bytes")
        );
        assert_eq!(
            bundle.interface_digest,
            Sha256Digest::of_bytes(b"wit-bytes")
        );
    }

    #[test]
    fn blank_inputs_fail_closed() {
        assert!(matches!(
            build_grant_bundle("", b"a", b"w", "n", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"", b"w", "n", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"a", b"w", "", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"a", b"w", "n", 0),
            Err(GrantClientError::InvalidField { .. })
        ));
    }

    #[test]
    fn dispatch_without_transport_fails_closed() {
        let bundle = build_grant_bundle("c", b"a", b"w", "n", 1).expect("bundle");
        assert_eq!(request_grant(&bundle), Err(GrantClientError::NoTransport));
        assert_eq!(
            GrantClientError::NoTransport.to_string(),
            "GRANT_CLIENT_NO_TRANSPORT"
        );
    }
}
