//! Bounded TCP listener and connection peer owner observation/error DTO contract.
//!
//! Local normative anchors: Architecture A5.1 (reality is not stored; ELIOT
//! retains bounded observations and models with capture route and evaluation
//! status), Implementation I1.6 (Windows isolation and the platform-bound
//! observation boundary), and Implementation I2.1 (module/crate membership
//! does not create lifecycle, mutable-state, or authority ownership).
//!
//! This child owns only the bounded TCP owner observation/error DTO contract.
//! The parent Windows adapter owns endpoint validation and OS owner-table
//! query/classification. This child owns no network effect, process lifecycle,
//! or authority.

use std::fmt;
use std::net::SocketAddr;

#[cfg(windows)]
pub(super) struct OwnerTable {
    pub(super) words: Vec<usize>,
    pub(super) byte_len: usize,
}

/// Exact OS observation for one loopback TCP listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpListenerOwnerObservation {
    endpoint: SocketAddr,
    process_id: u32,
}

impl TcpListenerOwnerObservation {
    pub(super) const fn new(endpoint: SocketAddr, process_id: u32) -> Self {
        Self {
            endpoint,
            process_id,
        }
    }

    /// Returns the exact loopback endpoint used for the owner query.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns the unique owning process identifier reported by Windows.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }
}

/// Exact OS observation for the server peer of one established loopback TCP
/// connection, matched by the client's local and peer endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConnectionPeerOwnerObservation {
    client_local_endpoint: SocketAddr,
    peer_endpoint: SocketAddr,
    process_id: u32,
}

impl TcpConnectionPeerOwnerObservation {
    pub(super) const fn new(
        client_local_endpoint: SocketAddr,
        peer_endpoint: SocketAddr,
        process_id: u32,
    ) -> Self {
        Self {
            client_local_endpoint,
            peer_endpoint,
            process_id,
        }
    }

    /// Returns the exact local endpoint of the connected client socket.
    #[must_use]
    pub const fn client_local_endpoint(&self) -> SocketAddr {
        self.client_local_endpoint
    }

    /// Returns the exact peer endpoint of the connected client socket.
    #[must_use]
    pub const fn peer_endpoint(&self) -> SocketAddr {
        self.peer_endpoint
    }

    /// Returns the unique owner PID reported for the reversed server-side row.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.process_id
    }
}

/// Failure to prove a unique owner for one exact loopback listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpListenerOwnerError {
    /// The requested endpoint was not exact IPv4/IPv6 localhost with a port.
    InvalidEndpoint,
    /// No exact listener or established peer row existed.
    Missing,
    /// More than one exact owner row existed, even when PIDs were equal.
    Ambiguous,
    /// Windows denied the ownership observation.
    AccessDenied,
    /// The table size changed between the sizing and retrieval calls.
    SizeRace,
    /// The required allocation exceeded the existing explicit table bound.
    BufferLimitExceeded,
    /// The returned table length, row count, port, or PID was malformed.
    MalformedTable,
    /// The API or address family is unsupported.
    UnsupportedPlatform,
    /// Another Win32 status prevented a trustworthy classification.
    Windows { code: u32 },
}

impl fmt::Display for TcpListenerOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => {
                formatter.write_str("TCP owner endpoint is not exact loopback")
            }
            Self::Missing => formatter.write_str("exact TCP listener owner is missing"),
            Self::Ambiguous => formatter.write_str("exact TCP listener owner is ambiguous"),
            Self::AccessDenied => formatter.write_str("TCP listener owner observation was denied"),
            Self::SizeRace => formatter.write_str("TCP listener table changed during observation"),
            Self::BufferLimitExceeded => {
                formatter.write_str("TCP listener table exceeds the bounded allocation")
            }
            Self::MalformedTable => formatter.write_str("TCP listener table is malformed"),
            Self::UnsupportedPlatform => {
                formatter.write_str("TCP listener ownership observation is unsupported")
            }
            Self::Windows { code } => {
                write!(
                    formatter,
                    "TCP listener owner observation failed with Win32 status {code}"
                )
            }
        }
    }
}

impl std::error::Error for TcpListenerOwnerError {}
