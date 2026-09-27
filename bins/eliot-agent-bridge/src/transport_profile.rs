//! Agent-facing transport profiles and their admission policy (I7.5).
//!
//! The stdio shim is the DEFAULT route: the agent starts a near-stateless
//! bridge which connects to the Kernel front door. Loopback Streamable HTTP
//! is OPTIONAL, disabled by default, and admitted only through
//! [`admit_loopback_http`]. Normal remote MCP/control transport is FORBIDDEN:
//! the local bridge and Kernel control surface are never published remotely.
//!
//! The loopback HTTP profile binds only the literal loopback endpoints
//! `127.0.0.1`/`::1`, requires a scoped short-lived bearer credential issued
//! through local setup, validates `Host` on every request and `Origin` for
//! browser-originated requests against the exact loopback profile, and
//! exposes no admin or database surface. Wildcard, non-loopback, ambiguous,
//! and DNS-rebinding bind forms are rejected, as are remotely presented
//! credentials. Losing the HTTP bridge removes only its transport binding:
//! the profile holds no Kernel or canonical state, and the Kernel session
//! and work state stay intact kernel-side.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime};

/// Maximum lifetime of one loopback HTTP bearer credential: short-lived.
pub const MAX_HTTP_CREDENTIAL_TTL: Duration = Duration::from_mins(5);
/// Default lifetime of one loopback HTTP bearer credential.
pub const DEFAULT_HTTP_CREDENTIAL_TTL: Duration = Duration::from_mins(5);

/// The single request target served on the loopback HTTP profile.
pub const LOOPBACK_HTTP_ROUTE: &str = "/mcp";
/// The only surface the loopback HTTP profile routes: the agent-facing MCP
/// front door. Admin and database surfaces are excluded by routing policy
/// (I7.5); see [`LOOPBACK_HTTP_EXCLUDED_SURFACES`].
pub const LOOPBACK_HTTP_SURFACE: &str = "mcp-agent-surface";

/// Surfaces the loopback HTTP profile must never route (I7.5): the
/// agent-facing bridge exposes only the MCP agent surface. The admin
/// surface (Kernel runtime control, backup, store recovery) stays on its
/// named-pipe owner, and the database surface stays on the Store owner;
/// neither is reachable through the bridge.
pub const LOOPBACK_HTTP_EXCLUDED_SURFACES: &[&str] =
    &["host.runtime-control", "host.backup", "store.database"];

/// Agent-facing transport profile (I7.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportProfile {
    /// DEFAULT: near-stateless stdio shim which connects to the Kernel front
    /// door. This is the only profile exposed by default startup.
    Stdio,
    /// OPTIONAL loopback Streamable HTTP bridge, disabled by default and
    /// admitted only through [`admit_loopback_http`].
    LoopbackHttp(LoopbackHttpProfile),
}

/// One admitted loopback HTTP bridge: the exact literal loopback bind plus
/// the scoped short-lived bearer credential issued for that bridge/session.
///
/// The profile holds transport-scoped configuration only. It owns no Kernel
/// session, no canonical state, and no admin or database surface, so losing
/// the HTTP bridge removes only its transport binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoopbackHttpProfile {
    bind: LoopbackBind,
    credential: LoopbackCredential,
}

/// One exact literal loopback bind endpoint: `127.0.0.1:<port>` or
/// `[::1]:<port>` and nothing else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoopbackBind {
    addr: SocketAddr,
}

impl LoopbackBind {
    fn canonical(self) -> String {
        self.addr.to_string()
    }
}

/// One short-lived bearer credential scoped to the exact loopback endpoint
/// it was issued for. The credential is accepted only when presented on that
/// same endpoint; it is never accepted remotely.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LoopbackCredential {
    token: String,
    expires_at: SystemTime,
    scope: String,
}

/// Typed transport-profile admission rejection (I7.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportAdmissionError {
    /// `0.0.0.0`/`::` or another wildcard bind: forbidden.
    WildcardBind,
    /// A non-loopback interface bind: forbidden.
    NonLoopbackBind,
    /// A bind that is not a literal IP endpoint with an explicit port.
    MalformedBind,
    /// An ambiguous bind form: DNS name, shorthand, mapped, zoned, or
    /// non-canonical encoding. Loopback must be the exact literal
    /// `127.0.0.1`/`::1`; DNS forms are a rebinding risk.
    AmbiguousBind,
    /// A `Host` that does not exactly match the configured literal loopback
    /// endpoint (including a missing `Host`).
    MismatchedHost,
    /// A browser `Origin` that is not the exact approved loopback origin.
    UnapprovedOrigin,
    /// A bearer credential that does not match the issued scoped token.
    CredentialMismatch,
    /// A credential presented for an endpoint other than the exact loopback
    /// endpoint it was issued for: remotely presented, forbidden.
    RemotelyPresentedCredential,
    /// A credential whose short-lived expiry has passed.
    ExpiredCredential,
    /// A credential lifetime longer than the short-lived maximum.
    OverlongCredentialLifetime,
    /// An empty credential token.
    EmptyCredential,
}

impl TransportAdmissionError {
    /// Stable machine-readable rejection code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::WildcardBind => "WILDCARD_BIND_REJECTED",
            Self::NonLoopbackBind => "NON_LOOPBACK_BIND_REJECTED",
            Self::MalformedBind => "MALFORMED_BIND_REJECTED",
            Self::AmbiguousBind => "AMBIGUOUS_BIND_REJECTED",
            Self::MismatchedHost => "MISMATCHED_HOST_REJECTED",
            Self::UnapprovedOrigin => "UNAPPROVED_ORIGIN_REJECTED",
            Self::CredentialMismatch => "CREDENTIAL_MISMATCH_REJECTED",
            Self::RemotelyPresentedCredential => "REMOTELY_PRESENTED_CREDENTIAL_REJECTED",
            Self::ExpiredCredential => "EXPIRED_CREDENTIAL_REJECTED",
            Self::OverlongCredentialLifetime => "OVERLONG_CREDENTIAL_LIFETIME_REJECTED",
            Self::EmptyCredential => "EMPTY_CREDENTIAL_REJECTED",
        }
    }
}

impl fmt::Display for TransportAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Self::WildcardBind => {
                "loopback HTTP binds a literal loopback endpoint, never a wildcard"
            }
            Self::NonLoopbackBind => {
                "loopback HTTP binds only 127.0.0.1 or ::1, never an external interface"
            }
            Self::MalformedBind => {
                "loopback HTTP bind must be a literal IP endpoint with an explicit port"
            }
            Self::AmbiguousBind => {
                "loopback HTTP bind must be the exact literal 127.0.0.1 or ::1; DNS, shorthand, mapped, zoned, and non-canonical forms are rejected"
            }
            Self::MismatchedHost => {
                "Host must exactly match the configured literal loopback endpoint"
            }
            Self::UnapprovedOrigin => "browser Origin must be the exact approved loopback origin",
            Self::CredentialMismatch => "bearer credential does not match the issued scoped token",
            Self::RemotelyPresentedCredential => {
                "the scoped loopback credential is never accepted on another endpoint"
            }
            Self::ExpiredCredential => "the short-lived bearer credential has expired",
            Self::OverlongCredentialLifetime => {
                "the credential lifetime exceeds the short-lived maximum"
            }
            Self::EmptyCredential => "the bearer credential token must not be empty",
        };
        write!(formatter, "{}: {}", self.code(), detail)
    }
}
impl std::error::Error for TransportAdmissionError {}

impl LoopbackHttpProfile {
    /// The exact literal loopback endpoint this profile binds.
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind.addr
    }

    /// The exact endpoint scope the issued credential is valid for.
    pub fn credential_scope(&self) -> &str {
        &self.credential.scope
    }

    /// The exact canonical `Host` forms admitted for this profile's bind:
    /// the literal loopback endpoint and nothing else (I7.5).
    pub fn admitted_host_forms(&self) -> Vec<String> {
        vec![self.bind.canonical()]
    }

    /// The exact browser `Origin` forms approved for this profile's bind
    /// (I7.5).
    pub fn approved_origin_forms(&self) -> Vec<String> {
        vec![format!("http://{}", self.bind.canonical())]
    }
}

/// Admits one loopback HTTP profile: the literal loopback bind plus the
/// scoped short-lived bearer credential issued for that bridge/session.
///
/// This is the single admission entry point for the optional loopback HTTP
/// profile; every rejection category of I7.5 is enforced here before the
/// profile can exist.
pub fn admit_loopback_http(
    bind: &str,
    credential_token: &str,
    credential_ttl: Duration,
) -> Result<LoopbackHttpProfile, TransportAdmissionError> {
    let bind = admit_loop_bind(bind)?;
    let credential = issue_loopback_credential(credential_token, credential_ttl, bind)?;
    Ok(LoopbackHttpProfile { bind, credential })
}

/// Admits one literal loopback bind address.
///
/// The bind must be the exact literal `127.0.0.1:<port>` or `[::1]:<port>`:
/// canonical text only, so shorthand, hexadecimal, decimal, octal,
/// IPv4-mapped, zoned, userinfo-infixed, and DNS-name forms are all rejected
/// before or after parsing. Wildcard binds are rejected as wildcards, and
/// any other loopback-range literal (for example `127.0.0.2`) is rejected as
/// ambiguous because only the exact literals are admitted.
pub(crate) fn admit_loop_bind(value: &str) -> Result<LoopbackBind, TransportAdmissionError> {
    if value.is_empty() {
        return Err(TransportAdmissionError::MalformedBind);
    }
    if value.contains(['@', '%', ' ', '\t']) {
        return Err(TransportAdmissionError::MalformedBind);
    }
    let addr: SocketAddr = value.parse().map_err(|_| classify_bind_form(value))?;
    match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => return Err(TransportAdmissionError::WildcardBind),
        IpAddr::V6(v6) if v6.is_unspecified() => return Err(TransportAdmissionError::WildcardBind),
        IpAddr::V4(v4) if !v4.is_loopback() => {
            return Err(TransportAdmissionError::NonLoopbackBind);
        }
        IpAddr::V6(v6) if !v6.is_loopback() => {
            return Err(TransportAdmissionError::NonLoopbackBind);
        }
        IpAddr::V4(v4) if v4 != Ipv4Addr::LOCALHOST => {
            return Err(TransportAdmissionError::AmbiguousBind);
        }
        IpAddr::V6(v6) if v6 != Ipv6Addr::LOCALHOST => {
            return Err(TransportAdmissionError::AmbiguousBind);
        }
        _ => {}
    }
    if value != addr.to_string() {
        return Err(TransportAdmissionError::AmbiguousBind);
    }
    if addr.port() == 0 {
        return Err(TransportAdmissionError::AmbiguousBind);
    }
    Ok(LoopbackBind { addr })
}

/// Classifies one bind string that failed literal endpoint parsing: a form
/// with alphabetic characters is a DNS name (a DNS-rebinding risk, because
/// loopback must be a literal), and anything else is malformed.
fn classify_bind_form(value: &str) -> TransportAdmissionError {
    if value.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        TransportAdmissionError::AmbiguousBind
    } else {
        TransportAdmissionError::MalformedBind
    }
}

/// Issues one short-lived bearer credential scoped to the exact loopback
/// endpoint it is valid for.
fn issue_loopback_credential(
    token: &str,
    ttl: Duration,
    bind: LoopbackBind,
) -> Result<LoopbackCredential, TransportAdmissionError> {
    if token.is_empty() {
        return Err(TransportAdmissionError::EmptyCredential);
    }
    if ttl > MAX_HTTP_CREDENTIAL_TTL {
        return Err(TransportAdmissionError::OverlongCredentialLifetime);
    }
    let expires_at = SystemTime::now()
        .checked_add(ttl)
        .ok_or(TransportAdmissionError::OverlongCredentialLifetime)?;
    Ok(LoopbackCredential {
        token: token.to_owned(),
        expires_at,
        scope: bind.canonical(),
    })
}

/// Validates the `Host` of one request against the exact loopback profile:
/// the host must be exactly the configured literal loopback endpoint. A
/// missing host, a DNS name, or any other ambiguous or mismatched form is
/// rejected.
pub fn validate_host(
    host: Option<&str>,
    profile: &LoopbackHttpProfile,
) -> Result<(), TransportAdmissionError> {
    let admitted = profile.admitted_host_forms();
    if host.is_some_and(|presented| admitted.iter().any(|form| form == presented)) {
        Ok(())
    } else {
        Err(TransportAdmissionError::MismatchedHost)
    }
}

/// Validates the `Origin` of one browser-originated request against the
/// exact loopback profile: the origin must be exactly the approved loopback
/// origin. A request without an `Origin` is not browser-originated and
/// carries no origin to validate.
pub fn validate_origin(
    origin: Option<&str>,
    profile: &LoopbackHttpProfile,
) -> Result<(), TransportAdmissionError> {
    match origin {
        None => Ok(()),
        Some(presented) => {
            let approved = profile.approved_origin_forms();
            if approved.iter().any(|form| form == presented) {
                Ok(())
            } else {
                Err(TransportAdmissionError::UnapprovedOrigin)
            }
        }
    }
}

/// Validates one presented bearer credential against the issued scoped
/// credential: the token must match in constant time, the presentation must
/// be bound to the exact loopback endpoint the credential was issued for,
/// and the short-lived expiry must not have passed.
pub fn validate_credential(
    presented: &str,
    presentation_scope: &str,
    profile: &LoopbackHttpProfile,
) -> Result<(), TransportAdmissionError> {
    if !constant_time_eq(presented, &profile.credential.token) {
        return Err(TransportAdmissionError::CredentialMismatch);
    }
    if presentation_scope != profile.credential.scope {
        return Err(TransportAdmissionError::RemotelyPresentedCredential);
    }
    if SystemTime::now() >= profile.credential.expires_at {
        return Err(TransportAdmissionError::ExpiredCredential);
    }
    Ok(())
}

/// Admits one request target to the single route the loopback HTTP profile
/// serves. Admin and database surfaces have no route here: the only served
/// surface is the agent-facing MCP front door (I7.5), and the admission
/// re-checks the excluded-surface policy so a route can never be added for
/// an excluded surface without editing this function.
pub fn loopback_http_route(target: &str) -> Option<&'static str> {
    let surface = match target {
        LOOPBACK_HTTP_ROUTE => LOOPBACK_HTTP_SURFACE,
        _ => return None,
    };
    if LOOPBACK_HTTP_EXCLUDED_SURFACES.contains(&surface) {
        return None;
    }
    Some(surface)
}

/// Constant-time equality for bearer token comparison: the comparison work
/// depends only on the length and the accumulated difference, never on the
/// position of the first differing byte.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}
