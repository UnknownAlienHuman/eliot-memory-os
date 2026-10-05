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

/// Canonical MCP access name of the Codex controller edge (issue #18).
///
/// Ported from `crates/eliot-app/src/mcp_stdio.rs::McpAccessProfile::parse`:
/// there `default` and `codex_controller` both select the controller, but the
/// bridge admits only the explicit spelling. `default` stays
/// [`CliError::UnsupportedProfile`] so a missing profile can never silently
/// become controller authority.
const CODEX_CONTROLLER_PROFILE_NAME: &str = "codex_controller";

/// Scope evidence the Codex controller edge presents (issue #18, names from
/// `mcp_stdio.rs::scoped_host_session_from_env`): either the single-use
/// opaque scope capability or the Governor-bound session plus role lease.
const CODEX_SCOPE_TOKEN_ENV: &str = "ELIOT_CODEX_SCOPE_TOKEN";
const CODEX_AGENT_SESSION_ENV: &str = "ELIOT_AGENT_SESSION_ID";
const CODEX_ROLE_LEASE_ENV: &str = "ELIOT_ROLE_LEASE_ID";

/// Shape of one opaque Codex scope capability
/// (`mcp_stdio.rs::codex_scope_capability_path`): at most 128 bytes starting
/// with the `cs1.` prefix. Shape only; the capability file itself is never
/// opened here.
const CODEX_SCOPE_TOKEN_PREFIX: &str = "cs1.";
const CODEX_SCOPE_TOKEN_MAX_LEN: usize = 128;

/// Typed Codex controller scope/capability admission rejection (issue #18).
///
/// Presence/shape admission only: the bridge mints and verifies no session,
/// lease, or capability. Verification belongs to the session owner on the
/// admitted Kernel path (the declaration digest plus live Kernel challenge
/// behind `kernel_ports_with_declaration`), so this gate can never become a
/// second Governor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodexScopeError {
    /// No scope evidence: neither the opaque capability nor session+lease.
    MissingScope,
    /// Opaque capability mixed with a raw role lease.
    MixedTokenAndLease,
    /// Opaque capability with an invalid shape.
    MalformedToken,
}

impl CodexScopeError {
    /// Stable machine-readable rejection code.
    const fn code(self) -> &'static str {
        match self {
            Self::MissingScope => "CODEX_CONTROLLER_SCOPE_REQUIRED",
            Self::MixedTokenAndLease => "CODEX_SCOPE_TOKEN_MIXED_WITH_ROLE_LEASE",
            Self::MalformedToken => "CODEX_SCOPE_TOKEN_MALFORMED",
        }
    }
}

impl fmt::Display for CodexScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Self::MissingScope => {
                "Codex controller MCP requires an active Governor-bound Session and TaskRoleLease (ELIOT_AGENT_SESSION_ID plus ELIOT_ROLE_LEASE_ID) or a single-use Codex scope capability (ELIOT_CODEX_SCOPE_TOKEN)"
            }
            Self::MixedTokenAndLease => {
                "opaque Codex scope capability cannot be mixed with a raw role lease"
            }
            Self::MalformedToken => "invalid opaque Codex scope token shape",
        };
        write!(formatter, "{}: {}", self.code(), detail)
    }
}
impl std::error::Error for CodexScopeError {}

/// True when the named scope variable carries a non-empty value. An empty
/// value is absent: it admits nothing.
fn scope_var_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// Admits the Codex controller edge: validates the `codex_controller` access
/// name and gates on scope/capability evidence (issue #18, ported from the
/// `mcp_stdio.rs` host-`None` parse arm, `scoped_host_session_from_env`, and
/// the `run` controller scope requirement).
///
/// Returns the admitted serving contour: the Codex edge is served on the
/// admitted `SPINE_FUNCTIONAL` contour, the same contour the delegated
/// Claude/OpenCode host edges use, never on a codex-specific contour or a
/// Governor path. The legacy host-`None` scopeless serve is deliberately not
/// ported: an evidence-free controller invocation fails closed here instead
/// of being served as an anonymous session.
fn admit_codex_controller() -> Result<Profile, CodexScopeError> {
    let token = std::env::var_os(CODEX_SCOPE_TOKEN_ENV).and_then(|value| {
        let text = value.to_string_lossy().into_owned();
        (!text.is_empty()).then_some(text)
    });
    if let Some(token) = token {
        if scope_var_present(CODEX_ROLE_LEASE_ENV) {
            return Err(CodexScopeError::MixedTokenAndLease);
        }
        if token.len() > CODEX_SCOPE_TOKEN_MAX_LEN || !token.starts_with(CODEX_SCOPE_TOKEN_PREFIX) {
            return Err(CodexScopeError::MalformedToken);
        }
        return Ok(Profile::SpineFunctional);
    }
    if !(scope_var_present(CODEX_AGENT_SESSION_ENV) && scope_var_present(CODEX_ROLE_LEASE_ENV)) {
        return Err(CodexScopeError::MissingScope);
    }
    Ok(Profile::SpineFunctional)
}

/// Parses one `--profile` value: a declared contour, or the Codex controller
/// access name through [`admit_codex_controller`]. Any other name stays
/// [`CliError::UnsupportedProfile`]; a scope-gate rejection surfaces as
/// [`CliError::MalformedArgument`] carrying the stable [`CodexScopeError`]
/// code, reusing the frozen error contract the bridge entry point handles.
fn parse_profile_arg(value: &str) -> Result<Profile, CliError> {
    match value.parse::<Profile>() {
        Ok(profile) => Ok(profile),
        Err(CliError::UnsupportedProfile(_)) if value == CODEX_CONTROLLER_PROFILE_NAME => {
            admit_codex_controller().map_err(|error| CliError::MalformedArgument(error.to_string()))
        }
        Err(error) => Err(error),
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
                profile = Some(parse_profile_arg(value)?);
                index += 2;
            }
            value if value.starts_with("--profile=") => {
                let value = value.trim_start_matches("--profile=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--profile= requires a value".to_owned(),
                    ));
                }
                profile = Some(parse_profile_arg(value)?);
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

/// `mcp catalog` selection (issue #18, CATALOG-REFINED): mirrors the facade
/// `McpCommand::Catalog` shape exactly — `--host` (default `claude`),
/// `--surface` (default `desktop`). Rendering lives in the forthcoming
/// `packager_catalog` module; this contract owns argv only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpCatalogArgs {
    pub host: String,
    pub surface: eliot_types::ClaudeSurface,
}

#[allow(
    clippy::too_many_lines,
    reason = "checked CLI contract: one arm per documented catalog argument"
)]
pub fn parse_mcp_catalog_args<I, S>(arguments: I) -> Result<McpCatalogArgs, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut host = "claude".to_owned();
    let mut surface = "desktop".to_owned();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--host" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--host requires a value".to_owned())
                })?;
                host = value.clone();
                index += 2;
            }
            value if value.starts_with("--host=") => {
                let value = value.trim_start_matches("--host=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--host= requires a value".to_owned(),
                    ));
                }
                host = value.to_owned();
                index += 1;
            }
            "--surface" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--surface requires a value".to_owned())
                })?;
                surface = value.clone();
                index += 2;
            }
            value if value.starts_with("--surface=") => {
                let value = value.trim_start_matches("--surface=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--surface= requires a value".to_owned(),
                    ));
                }
                surface = value.to_owned();
                index += 1;
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    if !host.trim().eq_ignore_ascii_case("claude") {
        return Err(CliError::MalformedArgument(
            "only the Claude host family exposes surface catalogs".to_owned(),
        ));
    }
    let surface = eliot_types::ClaudeSurface::parse(&surface).ok_or_else(|| {
        CliError::MalformedArgument(format!(
            "unknown Claude surface {surface}; expected `code` or `desktop`"
        ))
    })?;
    Ok(McpCatalogArgs { host, surface })
}

#[cfg(test)]
mod cli_catalog_tests {
    use super::{CliError, parse_mcp_catalog_args};
    use eliot_types::ClaudeSurface;

    #[test]
    fn catalog_defaults_mirror_facade() {
        let args = parse_mcp_catalog_args(Vec::<String>::new()).expect("defaults parse");
        assert_eq!(args.host, "claude");
        assert_eq!(args.surface, ClaudeSurface::ClaudeDesktopMcpb);
    }

    #[test]
    fn catalog_accepts_code_surface() {
        let args = parse_mcp_catalog_args(["--host", "claude", "--surface", "code"])
            .expect("code surface parses");
        assert_eq!(args.surface, ClaudeSurface::ClaudeCodePlugin);
        let args = parse_mcp_catalog_args(["--surface=desktop"]).expect("equals form parses");
        assert_eq!(args.surface, ClaudeSurface::ClaudeDesktopMcpb);
    }

    #[test]
    fn catalog_rejects_non_claude_host_and_unknown_surface() {
        assert!(matches!(
            parse_mcp_catalog_args(["--host", "codex"]),
            Err(CliError::MalformedArgument(_))
        ));
        assert!(matches!(
            parse_mcp_catalog_args(["--surface", "phone"]),
            Err(CliError::MalformedArgument(_))
        ));
        assert!(matches!(
            parse_mcp_catalog_args(["--profile", "SPINE_FUNCTIONAL"]),
            Err(CliError::MalformedArgument(_))
        ));
    }
}
