//! WASM-host CLI argument/config contract: deterministic profile/transport parsing and value assembly only.
//! Architecture: A2.3, A9.1, A12.3; ARCH-AUTH-01, ARCH-DRM-01, ARCH-SEC-02.
//! Implementation: I1.3, I2.19, I3.9, I14.19, P.13; no Dreamer, semantic/canonical-write, runtime/provider, policy, retry, or authority ownership.

use std::fmt;

/// The canonical B-12 composition profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// D2's operational component-host composition.
    D2Operational,
    /// The complete admitted component composition.
    FullComposition,
}

impl Profile {
    /// Returns the canonical profile spelling used by the binary surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::D2Operational => "D2_OPERATIONAL",
            Self::FullComposition => "FULL_COMPOSITION",
        }
    }

    /// Returns whether this profile is compiled into the current binary.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::D2Operational => cfg!(feature = "eliot-profile-d2-operational"),
            Self::FullComposition => cfg!(feature = "eliot-profile-full-composition"),
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The local-only transports understood by the binary contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Length-delimited local standard input/output.
    Stdio,
    /// Local loopback, reserved for an injected transport owner.
    Loopback,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "stdio" => Ok(Self::Stdio),
            "loopback" => Ok(Self::Loopback),
            other => Err(CliError::RemoteTransportForbidden(other.to_owned())),
        }
    }
}

/// Fail-closed command-line parsing errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// No profile was supplied.
    MissingProfile,
    /// The profile spelling is not canonical.
    UnsupportedProfile(String),
    /// An argument is malformed or unknown.
    MalformedArgument(String),
    /// A non-local transport was requested.
    RemoteTransportForbidden(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile => formatter.write_str("MISSING_PROFILE"),
            Self::UnsupportedProfile(profile) => write!(formatter, "UNSUPPORTED_PROFILE:{profile}"),
            Self::MalformedArgument(argument) => write!(formatter, "MALFORMED_ARGUMENT:{argument}"),
            Self::RemoteTransportForbidden(transport) => {
                write!(formatter, "REMOTE_TRANSPORT_FORBIDDEN:{transport}")
            }
        }
    }
}

impl std::error::Error for CliError {}

impl std::str::FromStr for Profile {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "D2_OPERATIONAL" => Ok(Self::D2Operational),
            "FULL_COMPOSITION" => Ok(Self::FullComposition),
            other => Err(CliError::UnsupportedProfile(other.to_owned())),
        }
    }
}

/// Parsed profile and local transport selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliConfig {
    /// Selected profile.
    pub profile: Profile,
    /// Selected local transport.
    pub transport: Transport,
}

/// Parses B-12's profile and transport arguments without adding a CLI crate.
pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport = Transport::Stdio;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--profile" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--profile requires a value".to_owned())
                })?;
                profile = Some(value.parse()?);
                index += 2;
            }
            value if value.starts_with("--profile=") => {
                let value = value.trim_start_matches("--profile=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--profile= requires a value".to_owned(),
                    ));
                }
                profile = Some(value.parse()?);
                index += 1;
            }
            "--transport" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--transport requires a value".to_owned())
                })?;
                transport = Transport::parse(value)?;
                index += 2;
            }
            value if value.starts_with("--transport=") => {
                let value = value.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--transport= requires a value".to_owned(),
                    ));
                }
                transport = Transport::parse(value)?;
                index += 1;
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
    })
}
