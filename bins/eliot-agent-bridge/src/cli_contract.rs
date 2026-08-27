//! Agent Bridge CLI contract — deterministic parsing and validation only.
//! Architecture: A13.2 (Kernel and failure domains), ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-01;
//! Agent Bridge interactive-user boundary.
//! Implementation: I1.3 User Broker/Agent Bridge, B.1 and P.3 where applicable, I2.2 and I2.23 topology.
//! Ownership: deterministic CLI profile/transport/declaration-path parsing and validation only;
//! CLI selects declared contour but mints no authority.
//! Non-ownership / forbids: declaration trust/decode, Kernel/activation authority, forwarding,
//! ambient transport, semantic decisions.

use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    SpineFunctional,
    FullComposition,
}

impl Profile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpineFunctional => "SPINE_FUNCTIONAL",
            Self::FullComposition => "FULL_COMPOSITION",
        }
    }
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::SpineFunctional => cfg!(feature = "eliot-profile-spine-functional"),
            Self::FullComposition => cfg!(feature = "eliot-profile-full-composition"),
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    MissingProfile,
    MissingClientDeclaration,
    UnsupportedProfile(String),
    MalformedArgument(String),
    RemoteTransportForbidden(String),
    InvalidClientDeclarationPath(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile => formatter.write_str("MISSING_PROFILE"),
            Self::MissingClientDeclaration => formatter.write_str("MISSING_CLIENT_DECLARATION"),
            Self::UnsupportedProfile(p) => write!(formatter, "UNSUPPORTED_PROFILE:{p}"),
            Self::MalformedArgument(a) => write!(formatter, "MALFORMED_ARGUMENT:{a}"),
            Self::RemoteTransportForbidden(t) => {
                write!(formatter, "REMOTE_TRANSPORT_FORBIDDEN:{t}")
            }
            Self::InvalidClientDeclarationPath(p) => {
                write!(formatter, "INVALID_CLIENT_DECLARATION_PATH:{p}")
            }
        }
    }
}
impl std::error::Error for CliError {}

impl std::str::FromStr for Profile {
    type Err = CliError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SPINE_FUNCTIONAL" => Ok(Self::SpineFunctional),
            "FULL_COMPOSITION" => Ok(Self::FullComposition),
            other => Err(CliError::UnsupportedProfile(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Stdio,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "stdio" => Ok(Self::Stdio),
            other => Err(CliError::RemoteTransportForbidden(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliConfig {
    pub profile: Profile,
    pub transport: Transport,
    pub client_declaration: PathBuf,
}

pub(crate) fn validate_client_declaration_path(path: &Path) -> Result<PathBuf, CliError> {
    if !path.is_absolute() {
        return Err(CliError::InvalidClientDeclarationPath(
            "must be absolute".to_owned(),
        ));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(CliError::InvalidClientDeclarationPath(
            "must be normalized, no parent traversal".to_owned(),
        ));
    }
    if path.file_name().is_none() {
        return Err(CliError::InvalidClientDeclarationPath(
            "must have file name".to_owned(),
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if file_name != "client-declaration-v2.json" {
        return Err(CliError::InvalidClientDeclarationPath(
            "must be client-declaration-v2.json".to_owned(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        CliError::InvalidClientDeclarationPath("must be under agent-bridge".to_owned())
    })?;
    let parent_name = parent
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if parent_name != "agent-bridge" {
        return Err(CliError::InvalidClientDeclarationPath(
            "must be under agent-bridge".to_owned(),
        ));
    }
    Ok(path.to_path_buf())
}

pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport = Transport::Stdio;
    let mut client_declaration: Option<PathBuf> = None;
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
            "--client-declaration" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--client-declaration requires a value".to_owned())
                })?;
                let p = PathBuf::from(value);
                client_declaration = Some(validate_client_declaration_path(&p)?);
                index += 2;
            }
            value if value.starts_with("--client-declaration=") => {
                let value = value.trim_start_matches("--client-declaration=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--client-declaration= requires a value".to_owned(),
                    ));
                }
                let p = PathBuf::from(value);
                client_declaration = Some(validate_client_declaration_path(&p)?);
                index += 1;
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
        client_declaration: client_declaration.ok_or(CliError::MissingClientDeclaration)?,
    })
}
