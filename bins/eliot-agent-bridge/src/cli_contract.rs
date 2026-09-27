//! Agent Bridge CLI contract — deterministic parsing and validation only.
//! Architecture: A13.2 (Kernel and failure domains), ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-01;
//! Agent Bridge interactive-user boundary.
//! Implementation: I1.3 User Broker/Agent Bridge, B.1 and P.3 where applicable, and I2.23 topology.
//! Ownership: deterministic CLI profile/transport/declaration-path parsing and validation only;
//! CLI selects declared contour but mints no authority.
//! Non-ownership / forbids: declaration trust/decode, Kernel/activation authority, forwarding,
//! ambient transport, semantic decisions.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::transport_profile::{
    DEFAULT_HTTP_CREDENTIAL_TTL, TransportProfile, admit_loopback_http,
};

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
    /// One transport-profile admission rejection (I7.5): the detail carries
    /// the stable [`crate::transport_profile::TransportAdmissionError::code`].
    TransportRejected(String),
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
            Self::TransportRejected(code) => {
                write!(formatter, "TRANSPORT_REJECTED:{code}")
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

/// CLI-level transport selection before profile admission.
///
/// `stdio` is the DEFAULT route; `loopback-http` is the OPTIONAL loopback
/// HTTP profile (disabled by default, admitted only with its bind and
/// credential); every other name is a normal remote MCP/control transport,
/// which is FORBIDDEN (I7.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportKind {
    Stdio,
    LoopbackHttp,
}

impl TransportKind {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "stdio" => Ok(Self::Stdio),
            "loopback-http" => Ok(Self::LoopbackHttp),
            other => Err(CliError::RemoteTransportForbidden(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliConfig {
    pub profile: Profile,
    pub transport: TransportProfile,
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

#[allow(
    clippy::too_many_lines,
    reason = "checked CLI contract: one arm per documented argument, then transport admission"
)]
pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport_kind = TransportKind::Stdio;
    let mut client_declaration: Option<PathBuf> = None;
    let mut http_bind: Option<String> = None;
    let mut http_credential: Option<String> = None;
    let mut http_credential_ttl: Option<u64> = None;
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
                transport_kind = TransportKind::parse(value)?;
                index += 2;
            }
            value if value.starts_with("--transport=") => {
                let value = value.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--transport= requires a value".to_owned(),
                    ));
                }
                transport_kind = TransportKind::parse(value)?;
                index += 1;
            }
            "--http-bind" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--http-bind requires a value".to_owned())
                })?;
                http_bind = Some(value.clone());
                index += 2;
            }
            value if value.starts_with("--http-bind=") => {
                let value = value.trim_start_matches("--http-bind=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--http-bind= requires a value".to_owned(),
                    ));
                }
                http_bind = Some(value.to_owned());
                index += 1;
            }
            "--http-credential" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--http-credential requires a value".to_owned())
                })?;
                http_credential = Some(value.clone());
                index += 2;
            }
            value if value.starts_with("--http-credential=") => {
                let value = value.trim_start_matches("--http-credential=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--http-credential= requires a value".to_owned(),
                    ));
                }
                http_credential = Some(value.to_owned());
                index += 1;
            }
            "--http-credential-ttl" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--http-credential-ttl requires a value".to_owned())
                })?;
                let seconds: u64 = value.parse().map_err(|_| {
                    CliError::MalformedArgument(
                        "--http-credential-ttl requires whole seconds".to_owned(),
                    )
                })?;
                if seconds == 0 {
                    return Err(CliError::MalformedArgument(
                        "--http-credential-ttl must be at least 1 second".to_owned(),
                    ));
                }
                http_credential_ttl = Some(seconds);
                index += 2;
            }
            value if value.starts_with("--http-credential-ttl=") => {
                let value = value.trim_start_matches("--http-credential-ttl=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--http-credential-ttl= requires a value".to_owned(),
                    ));
                }
                let seconds: u64 = value.parse().map_err(|_| {
                    CliError::MalformedArgument(
                        "--http-credential-ttl requires whole seconds".to_owned(),
                    )
                })?;
                if seconds == 0 {
                    return Err(CliError::MalformedArgument(
                        "--http-credential-ttl must be at least 1 second".to_owned(),
                    ));
                }
                http_credential_ttl = Some(seconds);
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
    let transport = match transport_kind {
        TransportKind::Stdio => {
            if http_bind.is_some() || http_credential.is_some() || http_credential_ttl.is_some() {
                return Err(CliError::MalformedArgument(
                    "--http-bind, --http-credential, and --http-credential-ttl require \
                     --transport loopback-http"
                        .to_owned(),
                ));
            }
            TransportProfile::Stdio
        }
        TransportKind::LoopbackHttp => {
            let bind = http_bind.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--http-bind is required with --transport loopback-http".to_owned(),
                )
            })?;
            let credential = http_credential.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--http-credential is required with --transport loopback-http".to_owned(),
                )
            })?;
            let ttl = Duration::from_secs(
                http_credential_ttl.unwrap_or_else(|| DEFAULT_HTTP_CREDENTIAL_TTL.as_secs()),
            );
            TransportProfile::LoopbackHttp(
                admit_loopback_http(&bind, &credential, ttl)
                    .map_err(|error| CliError::TransportRejected(error.code().to_owned()))?,
            )
        }
    };
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
        client_declaration: client_declaration.ok_or(CliError::MissingClientDeclaration)?,
    })
}
