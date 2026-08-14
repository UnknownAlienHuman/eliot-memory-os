use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

const HTTP_PREFIX: &str = "http://";
const IPV4_HOST: &str = "127.0.0.1";
const IPV6_HOST: &str = "[::1]";

/// A strictly local `OpenCode` HTTP endpoint.
///
/// The endpoint intentionally accepts only the two canonical textual loopback
/// forms. Keeping the spelling canonical makes the Host header and socket
/// address deterministic and prevents a caller from accidentally widening the
/// route to a hostname, proxy, or non-loopback address.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LoopbackEndpoint {
    url: String,
    host_header: String,
    socket_addr: SocketAddr,
}

impl LoopbackEndpoint {
    /// Parse a canonical loopback endpoint.
    pub fn parse(input: &str) -> Result<Self, LoopbackEndpointError> {
        if input.is_empty() {
            return Err(LoopbackEndpointError::Empty);
        }
        if !input.starts_with(HTTP_PREFIX) {
            return Err(if input.contains("://") {
                LoopbackEndpointError::UnsupportedScheme
            } else {
                LoopbackEndpointError::MissingScheme
            });
        }

        let authority = &input[HTTP_PREFIX.len()..];
        if authority.is_empty() {
            return Err(LoopbackEndpointError::MissingHost);
        }
        if authority.contains('@') {
            return Err(LoopbackEndpointError::UserinfoNotAllowed);
        }
        if authority.contains('?') {
            return Err(LoopbackEndpointError::QueryNotAllowed);
        }
        if authority.contains('#') {
            return Err(LoopbackEndpointError::FragmentNotAllowed);
        }
        if authority.contains('/') {
            return Err(LoopbackEndpointError::PathNotAllowed);
        }
        if authority.chars().any(char::is_whitespace) {
            return Err(LoopbackEndpointError::WhitespaceNotAllowed);
        }

        let (host, port_text, host_header) = if authority.starts_with('[') {
            let closing = authority
                .find(']')
                .ok_or(LoopbackEndpointError::InvalidAuthority)?;
            let host = &authority[..=closing];
            let port_text = authority
                .get(closing + 1..)
                .and_then(|rest| rest.strip_prefix(':'))
                .ok_or(LoopbackEndpointError::MissingPort)?;
            if host != IPV6_HOST {
                return Err(LoopbackEndpointError::NonLoopbackHost);
            }
            (host, port_text, format!("{host}:{port_text}"))
        } else {
            let mut pieces = authority.split(':');
            let host = pieces.next().ok_or(LoopbackEndpointError::MissingHost)?;
            let port_text = pieces.next().ok_or(LoopbackEndpointError::MissingPort)?;
            if pieces.next().is_some() {
                return Err(LoopbackEndpointError::InvalidAuthority);
            }
            if host != IPV4_HOST {
                return Err(LoopbackEndpointError::NonLoopbackHost);
            }
            (host, port_text, format!("{host}:{port_text}"))
        };

        if port_text.is_empty()
            || !port_text
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            return Err(LoopbackEndpointError::InvalidPort);
        }
        let port = port_text
            .parse::<u16>()
            .map_err(|_| LoopbackEndpointError::InvalidPort)?;
        if port == 0 {
            return Err(LoopbackEndpointError::ZeroPort);
        }

        let ip = if host == IPV4_HOST {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        Ok(Self {
            url: format!("{HTTP_PREFIX}{host_header}"),
            host_header,
            socket_addr: SocketAddr::new(ip, port),
        })
    }

    /// The canonical URL, without a trailing slash or path.
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Alias for [`Self::as_str`].
    pub fn url(&self) -> &str {
        self.as_str()
    }

    /// The exact authority to use in an HTTP `Host` header.
    pub fn host_header(&self) -> &str {
        &self.host_header
    }

    /// The exact authority portion of the endpoint.
    pub fn authority(&self) -> &str {
        self.host_header()
    }

    /// The resolved socket address; no DNS lookup is performed.
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    pub fn ip(&self) -> IpAddr {
        self.socket_addr.ip()
    }

    pub fn port(&self) -> u16 {
        self.socket_addr.port()
    }
}

impl AsRef<str> for LoopbackEndpoint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for LoopbackEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for LoopbackEndpoint {
    type Err = LoopbackEndpointError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl TryFrom<&str> for LoopbackEndpoint {
    type Error = LoopbackEndpointError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Self::parse(input)
    }
}

impl TryFrom<String> for LoopbackEndpoint {
    type Error = LoopbackEndpointError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Self::parse(&input)
    }
}

impl Serialize for LoopbackEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LoopbackEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        Self::parse(&input).map_err(de::Error::custom)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LoopbackEndpointError {
    #[error("loopback endpoint is empty")]
    Empty,
    #[error("loopback endpoint must use the http scheme")]
    MissingScheme,
    #[error("loopback endpoint scheme is not http")]
    UnsupportedScheme,
    #[error("loopback endpoint host is missing")]
    MissingHost,
    #[error("loopback endpoint port is missing")]
    MissingPort,
    #[error("loopback endpoint authority is malformed")]
    InvalidAuthority,
    #[error("loopback endpoint must use the canonical loopback host")]
    NonLoopbackHost,
    #[error("loopback endpoint userinfo is not allowed")]
    UserinfoNotAllowed,
    #[error("loopback endpoint query is not allowed")]
    QueryNotAllowed,
    #[error("loopback endpoint fragment is not allowed")]
    FragmentNotAllowed,
    #[error("loopback endpoint path is not allowed")]
    PathNotAllowed,
    #[error("loopback endpoint contains whitespace")]
    WhitespaceNotAllowed,
    #[error("loopback endpoint port is invalid")]
    InvalidPort,
    #[error("loopback endpoint port must be non-zero")]
    ZeroPort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_ipv4_endpoint() -> Result<(), LoopbackEndpointError> {
        let endpoint = LoopbackEndpoint::parse("http://127.0.0.1:4096")?;
        assert_eq!(endpoint.as_str(), "http://127.0.0.1:4096");
        assert_eq!(endpoint.host_header(), "127.0.0.1:4096");
        assert_eq!(
            endpoint.socket_addr(),
            SocketAddr::from(([127, 0, 0, 1], 4096))
        );
        Ok(())
    }

    #[test]
    fn accepts_canonical_ipv6_endpoint() -> Result<(), LoopbackEndpointError> {
        let endpoint = LoopbackEndpoint::parse("http://[::1]:4096")?;
        assert_eq!(endpoint.as_str(), "http://[::1]:4096");
        assert_eq!(endpoint.host_header(), "[::1]:4096");
        assert_eq!(
            endpoint.socket_addr(),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 4096))
        );
        Ok(())
    }

    #[test]
    fn rejects_non_loopback_or_non_canonical_authorities() {
        for (input, expected) in [
            (
                "https://127.0.0.1:4096",
                LoopbackEndpointError::UnsupportedScheme,
            ),
            (
                "http://localhost:4096",
                LoopbackEndpointError::NonLoopbackHost,
            ),
            (
                "http://127.0.0.2:4096",
                LoopbackEndpointError::NonLoopbackHost,
            ),
            (
                "http://127.0.0.1:4096@evil",
                LoopbackEndpointError::UserinfoNotAllowed,
            ),
            (
                "http://user@127.0.0.1:4096",
                LoopbackEndpointError::UserinfoNotAllowed,
            ),
            (
                "http://127.0.0.1:4096?x=1",
                LoopbackEndpointError::QueryNotAllowed,
            ),
            (
                "http://127.0.0.1:4096#x",
                LoopbackEndpointError::FragmentNotAllowed,
            ),
            (
                "http://127.0.0.1:4096/",
                LoopbackEndpointError::PathNotAllowed,
            ),
            ("http://127.0.0.1:0", LoopbackEndpointError::ZeroPort),
        ] {
            assert_eq!(LoopbackEndpoint::parse(input), Err(expected), "{input}");
        }
    }

    #[test]
    fn serde_round_trip_preserves_canonical_identity() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = LoopbackEndpoint::parse("http://[::1]:4096")?;
        let encoded = serde_json::to_string(&endpoint)?;
        let decoded: LoopbackEndpoint = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, endpoint);
        Ok(())
    }
}
