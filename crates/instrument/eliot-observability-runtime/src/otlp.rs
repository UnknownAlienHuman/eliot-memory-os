//! OTLP bridge module, disabled by default (I16.2).
//!
//! I16.2 specifies an "optional OTLP bridge module, disabled by default". The
//! `otlp` cargo feature is off in the default feature set, so a default
//! startup never links this module's bridge body and never opens a collector
//! connection. [`otlp_enabled`] is the single honest answer to "is the bridge
//! compiled in", and it is `false` in every default build.
//!
//! The bridge is a bridge, not an authority: it never becomes durable audit,
//! never claims downstream delivery, and never turns a metrics sample into proof
//! (I16.1). A configured endpoint with the feature disabled is reported as
//! [`OtlpDisposition::FeatureDisabled`], never as a silent no-op.
//!
//! # The transport, and what it decides
//!
//! The workspace declares no OTLP or HTTP client dependency, so the bridge
//! speaks OTLP/HTTP itself over [`std::net::TcpStream`]: the configured
//! `http://host[:port][/path]` endpoint is split once into a `Host` authority, a
//! connect address and a request target, the record is encoded as one
//! OTLP/JSON `ExportLogsServiceRequest` body, and the request is written and
//! the status line read back on one bounded socket. That keeps the bridge
//! dependency-free and keeps the verdict where the work happens:
//! [`OtlpBridge::export`] returns `Ok(())` **only** when the collector's own
//! status line reports 2xx.
//!
//! Everything else is a typed [`OtlpBridgeError`]: an unparsable endpoint, a
//! scheme this crate cannot speak, a refused connection, a failed write, an
//! absent or incomplete status line, and a non-2xx status. I16.11 forbids
//! silent success, and a recorded success for an unsent record is exactly that.
//! No result is ever inferred from a configured endpoint, a local write, or a
//! caller-supplied flag.
//!
//! `https` is refused rather than silently downgraded. A TLS transport is a
//! dependency decision this item does not make, and sending bounded telemetry
//! in clear text to a collector that asked for TLS would be a lie.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

/// Whether the OTLP bridge body is compiled into this build.
#[must_use]
pub const fn otlp_enabled() -> bool {
    cfg!(feature = "otlp")
}

/// Bounded wait for one collector connect, one request write, and one status
/// line read.
///
/// I16.9 states that telemetry itself consumes the same CPU, memory, I/O and
/// queue resources it observes, so a collector is given a bounded wait rather
/// than an unbounded one. One plain constant, not a configurable limits
/// framework, and not a startup gate: a refused bridge is an error, not a
/// reason to refuse the stack.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest accepted HTTP status line, in bytes. I16.9 again: the read stops
/// after this many bytes, so a collector cannot grow this process's memory by
/// answering at length.
const MAX_STATUS_LINE_BYTES: usize = 64;

/// Port used when the endpoint names a host and no port.
const DEFAULT_HTTP_PORT: &str = "80";

/// Honest state of the OTLP bridge for one process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtlpDisposition {
    /// An endpoint is configured, this build has the `otlp` feature on, and
    /// [`OtlpBridge::new`] accepts the endpoint, so a transport exists and a
    /// record can reach the collector. Reported for exactly those conditions; it
    /// claims nothing about whether a particular export was accepted, which only
    /// the transport's response can decide.
    Enabled,
    /// An endpoint is configured but this build has the `otlp` feature off.
    FeatureDisabled,
    /// An endpoint is configured and the feature is on, but the endpoint is not
    /// a usable `http://` host, port, and path, so no bridge can be built. Kept
    /// distinct from [`Self::Enabled`] so a refused endpoint is never reported
    /// as a working bridge.
    EndpointUnusable,
    /// No endpoint is configured; the bridge stays inert.
    NotConfigured,
}

impl OtlpDisposition {
    /// Stable disposition name for a bounded diagnostic record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::FeatureDisabled => "feature_disabled",
            Self::EndpointUnusable => "endpoint_unusable",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// One bounded operational record handed to the bridge.
///
/// The record carries only bounded, already-redacted material; the bridge
/// performs no additional field policy of its own because the emitting
/// surface already passed the shared policy gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpExport {
    /// Stable event name, carried as the log record's body.
    pub event: &'static str,
    /// Bounded low-cardinality labels.
    pub labels: Vec<(String, String)>,
}

/// The OTLP bridge.
///
/// Constructed only when [`otlp_enabled`] is true. With the feature disabled
/// the type still exists so the bootstrap can report `FeatureDisabled`
/// honestly, but [`OtlpBridge::export`] is unreachable in a default build and
/// no socket is opened.
///
/// A constructed bridge has parsed its endpoint once, so [`Self::export`] never
/// re-derives a target: see [`OtlpDisposition::Enabled`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpBridge {
    endpoint: String,
    host: String,
    connect: String,
    path: String,
}

impl OtlpBridge {
    /// Builds the bridge over a configured collector endpoint.
    ///
    /// Success means the endpoint is configured, usable, and the feature is
    /// built. It does not mean a record has been exported: only
    /// [`Self::export`] and the collector's own response can say that.
    ///
    /// # Errors
    ///
    /// Returns [`OtlpBridgeError::FeatureDisabled`] when this build has the
    /// `otlp` feature off, [`OtlpBridgeError::EndpointNotConfigured`] for
    /// a blank endpoint, [`OtlpBridgeError::SchemeNotSupported`] for any
    /// scheme other than `http`, and [`OtlpBridgeError::EndpointNotParsable`]
    /// for an endpoint that is not a host, an optional port, and a path.
    pub fn new(endpoint: &str) -> Result<Self, OtlpBridgeError> {
        if !otlp_enabled() {
            return Err(OtlpBridgeError::FeatureDisabled);
        }
        if endpoint.trim().is_empty() {
            return Err(OtlpBridgeError::EndpointNotConfigured);
        }
        let (host, connect, path) = parse_endpoint(endpoint)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            host,
            connect,
            path,
        })
    }

    /// The configured collector endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Exports one bounded operational record through the bridge.
    ///
    /// The record is written to the configured collector and its HTTP status
    /// line is read back. `Ok(())` is returned only for a 2xx status: the
    /// verdict is the transport's observed response, compared against the
    /// 2xx range, and no caller can assert it.
    ///
    /// # Errors
    ///
    /// Returns [`OtlpBridgeError::FeatureDisabled`] in a default build, and in
    /// a build with the feature on returns the typed refusal for every way the
    /// export can fail to reach an accepting status:
    /// [`OtlpBridgeError::ConnectionRefused`],
    /// [`OtlpBridgeError::RequestNotSent`],
    /// [`OtlpBridgeError::StatusNotObserved`], and
    /// [`OtlpBridgeError::CollectorRejected`].
    ///
    /// No result is ever fabricated: a refused export stays an error, never a
    /// recorded success. The record is deliberately not consumed, so an unsent
    /// record is never mistaken for a sent one.
    pub fn export(&self, record: &OtlpExport) -> Result<(), OtlpBridgeError> {
        if !otlp_enabled() {
            return Err(OtlpBridgeError::FeatureDisabled);
        }
        let body = otlp_json_body(record);
        let mut stream = connect_bounded(&self.connect)?;
        stream
            .set_write_timeout(Some(EXPORT_TIMEOUT))
            .and_then(|()| stream.set_read_timeout(Some(EXPORT_TIMEOUT)))
            .map_err(|_| OtlpBridgeError::RequestNotSent)?;
        stream
            .write_all(self.request(&body).as_bytes())
            .map_err(|_| OtlpBridgeError::RequestNotSent)?;
        let status = read_status_line(&mut stream)?;
        if (200..=299).contains(&status) {
            Ok(())
        } else {
            Err(OtlpBridgeError::CollectorRejected { status })
        }
    }

    /// Builds the one HTTP/1.1 request this bridge sends.
    fn request(&self, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {length}\r\nConnection: close\r\n\r\n{body}",
            path = self.path,
            host = self.host,
            length = body.len(),
        )
    }
}

/// Opens one collector connection, bounded per resolved address.
fn connect_bounded(connect: &str) -> Result<TcpStream, OtlpBridgeError> {
    let addresses = connect
        .to_socket_addrs()
        .map_err(|_| OtlpBridgeError::ConnectionRefused)?;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, EXPORT_TIMEOUT) {
            return Ok(stream);
        }
    }
    Err(OtlpBridgeError::ConnectionRefused)
}

/// Reads exactly the HTTP status line, bounded in bytes and in time.
fn read_status_line(stream: &mut TcpStream) -> Result<u16, OtlpBridgeError> {
    let mut line = Vec::with_capacity(MAX_STATUS_LINE_BYTES);
    let mut byte = [0_u8; 1];
    while line.len() < MAX_STATUS_LINE_BYTES {
        match stream.read(&mut byte) {
            Ok(1) if byte[0] != b'\n' => line.push(byte[0]),
            Ok(1) => return parse_status_line(&line),
            // A closed socket, a reset, or the read timeout leaves the status
            // line incomplete. That is a refusal, never an acceptance.
            Ok(_) | Err(_) => break,
        }
    }
    Err(OtlpBridgeError::StatusNotObserved)
}

/// Parses the status code out of an HTTP status line.
fn parse_status_line(line: &[u8]) -> Result<u16, OtlpBridgeError> {
    let text = std::str::from_utf8(line).map_err(|_| OtlpBridgeError::StatusNotObserved)?;
    let mut parts = text.split(' ');
    let version = parts.next().ok_or(OtlpBridgeError::StatusNotObserved)?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(OtlpBridgeError::StatusNotObserved);
    }
    let code = parts.next().ok_or(OtlpBridgeError::StatusNotObserved)?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OtlpBridgeError::StatusNotObserved);
    }
    code.parse::<u16>()
        .map_err(|_| OtlpBridgeError::StatusNotObserved)
}

/// Splits an `http://host[:port][/path]` endpoint into the `Host` authority,
/// the connect address, and the request target.
///
/// A space or a control character in the endpoint would end the request line
/// early, and `@` would carry userinfo into the `Host` header, so both are
/// refused rather than written to the socket. I15.4 keeps credential material
/// out of the request and out of logs, and this crate has no secret provider to
/// resolve a value with.
fn parse_endpoint(endpoint: &str) -> Result<(String, String, String), OtlpBridgeError> {
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or(OtlpBridgeError::SchemeNotSupported)?;
    if rest.is_empty() || rest.contains([' ', '\t', '@']) || rest.chars().any(char::is_control) {
        return Err(OtlpBridgeError::EndpointNotParsable);
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = split_port(authority).ok_or(OtlpBridgeError::EndpointNotParsable)?;
    Ok((
        authority.to_owned(),
        format!("{host}:{port}"),
        path.to_owned(),
    ))
}

/// Splits an authority into host and port, keeping an IPv6 literal bracketed and
/// naming [`DEFAULT_HTTP_PORT`] when the authority carries no port.
///
/// An unbracketed IPv6 literal is refused: its last colon would be read as the
/// port separator and yield a connect address the operator never configured.
fn split_port(authority: &str) -> Option<(&str, &str)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (_host, after) = rest.split_once(']')?;
        return match after {
            "" => Some((authority, DEFAULT_HTTP_PORT)),
            port => Some((authority, port.strip_prefix(':')?)),
        };
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => (host, port),
        // "host:" names no port at all, which is a malformed authority rather
        // than the default port.
        Some(_) => return None,
        None => (authority, DEFAULT_HTTP_PORT),
    };
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port))
}

/// Encodes one bounded record as an OTLP/JSON `ExportLogsServiceRequest`.
///
/// The payload is a single log record whose body is the stable event name and
/// whose attributes are the bounded labels, so no unbounded field, content, or
/// secret can reach the wire (I15.4).
fn otlp_json_body(record: &OtlpExport) -> String {
    let attributes: Vec<_> = record
        .labels
        .iter()
        .map(|(key, value)| json!({"key": key, "value": {"stringValue": value}}))
        .collect();
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u128, |elapsed| elapsed.as_nanos());
    json!({
        "resourceLogs": [{
            "scopeLogs": [{
                "logRecords": [{
                    "timeUnixNano": observed.to_string(),
                    "body": {"stringValue": record.event},
                    "attributes": attributes
                }]
            }]
        }]
    })
    .to_string()
}

/// Typed bridge refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OtlpBridgeError {
    /// This build has the `otlp` feature disabled.
    #[error("otlp bridge is disabled by default in this build")]
    FeatureDisabled,
    /// No collector endpoint is configured.
    #[error("otlp bridge has no configured endpoint")]
    EndpointNotConfigured,
    /// The configured endpoint is not a host, an optional port, and a path.
    #[error("otlp collector endpoint is not a parsable host, port, and path")]
    EndpointNotParsable,
    /// The configured endpoint names a scheme this bridge cannot speak.
    #[error("otlp collector endpoint scheme is not supported; this bridge speaks plain http")]
    SchemeNotSupported,
    /// No collector connection could be established.
    #[error("otlp collector connection could not be established")]
    ConnectionRefused,
    /// The request could not be written to the collector.
    #[error("otlp export request could not be written to the collector")]
    RequestNotSent,
    /// The collector returned no complete HTTP status line.
    #[error("otlp collector returned no complete HTTP status line")]
    StatusNotObserved,
    /// The collector answered, and its status is not an acceptance.
    #[error("otlp collector answered with non-2xx HTTP status {status}")]
    CollectorRejected {
        /// Status the collector actually returned.
        status: u16,
    },
}

/// Reports the honest bridge disposition for a configured endpoint.
///
/// The verdict is the constructor's own: an endpoint is reported
/// [`OtlpDisposition::Enabled`] exactly when [`OtlpBridge::new`] would build a
/// bridge from it, so the disposition can never claim a working bridge that the
/// bridge itself refuses.
#[must_use]
pub fn disposition(configured_endpoint: Option<&str>) -> OtlpDisposition {
    let Some(endpoint) = configured_endpoint else {
        return OtlpDisposition::NotConfigured;
    };
    if !otlp_enabled() {
        return OtlpDisposition::FeatureDisabled;
    }
    match OtlpBridge::new(endpoint) {
        Ok(_) => OtlpDisposition::Enabled,
        Err(_) => OtlpDisposition::EndpointUnusable,
    }
}
