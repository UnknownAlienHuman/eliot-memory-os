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
    /// An experimental world was selected without its component artifact.
    MissingExperimentalComponent,
    /// An experimental component was supplied without its world selection.
    MissingExperimentalWorld,
    /// The experimental world spelling is not a frozen typed world.
    UnknownWorld(String),
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
            Self::MissingExperimentalComponent => {
                formatter.write_str("MISSING_EXPERIMENTAL_COMPONENT")
            }
            Self::MissingExperimentalWorld => formatter.write_str("MISSING_EXPERIMENTAL_WORLD"),
            Self::UnknownWorld(world) => write!(formatter, "UNKNOWN_WORLD:{world}"),
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

/// Bounded argument set for one governed grant launch: the dedicated
/// executable consumer path (issue #1955, I14.19).
///
/// Every value is an explicit staged input, validated fail-closed before
/// any transport or filesystem use: front-door channel facts (pipe, Kernel
/// SID/session/artifact, connect timeout), the requested component identity
/// plus its artifact file, the frozen WIT world selection, the live
/// installation descriptor file, and caller freshness (nonce, deadline).
/// Nothing is defaulted, probed, or read from ambient process state: the
/// staging parent supplies each value exactly, like `--guest-exec`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantLaunchArgs {
    /// Local front-door pipe name of the Kernel server.
    pub pipe_name: String,
    /// Expected Kernel server SID.
    pub kernel_sid: String,
    /// Expected Kernel server session id.
    pub kernel_session_id: u32,
    /// Expected Kernel artifact SHA-256 (lowercase hex).
    pub kernel_artifact_sha256: String,
    /// Connect timeout in milliseconds (local policy ceiling applies).
    pub connect_timeout_ms: u64,
    /// Requested component identity (pinned end-to-end to the grant).
    pub component_id: String,
    /// Component artifact file (bounded, preflighted, digest-checked).
    pub artifact_path: std::path::PathBuf,
    /// Frozen WIT world selection (interface digest from real WIT bytes).
    pub world: crate::typed_bindings::TypedWorld,
    /// Live installation descriptor file (JSON, validated on read).
    pub descriptor_path: std::path::PathBuf,
    /// Caller nonce for exactly-once issuance.
    pub nonce: String,
    /// Absolute deadline (unix ms) the grant must not outlive.
    pub deadline_unix_ms: u64,
}

/// Parsed profile, local transport, and optional explicit experimental selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliConfig {
    /// Selected profile.
    pub profile: Profile,
    /// Selected local transport.
    pub transport: Transport,
    /// Explicit bounded local artifact for the non-governed experimental path.
    pub experimental_typed_component: Option<std::path::PathBuf>,
    /// Explicit frozen world selection for the experimental path.
    pub experimental_world: Option<String>,
    /// One-shot P03-admitted guest execution: run the artifact's `run`
    /// export over the input bytes inside this process and emit raw output
    /// bytes on stdout. `None` unless `--guest-exec` is passed with its full
    /// argument set. This is how a reaped child executes an admitted guest:
    /// the parent spawns this binary with these exact arguments through the
    /// P03 staged intent, so every value here is admission-bound, never
    /// ambient.
    pub guest_exec: Option<GuestExecArgs>,
    /// Governed grant launch: authenticated grant request over the Kernel
    /// front-door channel, authorized against the live installation
    /// descriptor, resolved to the installed binary, and staged for the
    /// isolated-child engine. `None` unless at least one `--grant-*` flag
    /// is passed; any partial set fails closed. Mutually exclusive with
    /// `--guest-exec` and the experimental path.
    pub grant_launch: Option<GrantLaunchArgs>,
}

/// Bounded argument set for one-shot admitted guest execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestExecArgs {
    /// Component artifact file (bounded, preflighted, digest-checked).
    pub artifact: std::path::PathBuf,
    /// Raw input file (bounded).
    pub input: std::path::PathBuf,
    /// Expected SHA-256 hex of the artifact bytes (TOCTOU check on read).
    pub artifact_digest: String,
    /// Output byte ceiling enforced by the guest Store.
    pub max_output_bytes: u64,
    /// Fuel ceiling enforced by the guest Store.
    pub max_fuel: u64,
    /// Memory byte ceiling enforced by the guest Store.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms) enforced by the epoch driver.
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks enforced by the epoch driver.
    pub epoch_deadline_ticks: u64,
}

/// Claims the spaced value for one `--flag value` pair: present and
/// non-empty, else malformed. The `--flag=value` form is handled per flag
/// at the call site.
fn take_flag_value(
    flag: &'static str,
    arguments: &[String],
    index: &mut usize,
) -> Result<String, CliError> {
    let value = arguments
        .get(*index + 1)
        .ok_or_else(|| CliError::MalformedArgument(format!("{flag} requires a value")))?;
    if value.is_empty() {
        return Err(CliError::MalformedArgument(format!(
            "{flag} requires a value"
        )));
    }
    *index += 2;
    Ok(value.clone())
}

/// Text conversion for the grant parser: any non-empty value is accepted;
/// shape checks belong to the launch path, not the parser.
fn grant_text_value(text: &str) -> String {
    text.to_owned()
}

/// `u64` conversion for [`grant_flag!`]: malformed numerals fail closed here,
/// range checks belong to the launch path.
fn grant_u64_value(flag: &'static str, text: &str) -> Result<u64, CliError> {
    text.parse()
        .map_err(|_| CliError::MalformedArgument(format!("{flag} requires a u64 value")))
}

/// Path conversion for the grant parser: records the staged path verbatim;
/// existence and bounds are proven by the launch path on read.
fn grant_path_value(text: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(text)
}

/// Claims one `--grant-*` value from either spelling (`--flag value`,
/// `--flag=value`): the inline tail wins when present, else the next
/// argument. Empty and absent values fail closed.
fn claim_grant_value(
    flag: &'static str,
    inline: Option<&str>,
    arguments: &[String],
    index: &mut usize,
) -> Result<String, CliError> {
    if let Some(text) = inline {
        if text.is_empty() {
            return Err(CliError::MalformedArgument(format!(
                "{flag} requires a value"
            )));
        }
        *index += 1;
        return Ok(text.to_owned());
    }
    take_flag_value(flag, arguments, index)
}

/// Parses B-12's profile and transport arguments without adding a CLI crate.
#[allow(clippy::too_many_lines)]
pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport = Transport::Stdio;
    let mut experimental_typed_component: Option<std::path::PathBuf> = None;
    let mut experimental_world: Option<String> = None;
    let mut guest_exec = false;
    let mut guest_artifact: Option<std::path::PathBuf> = None;
    let mut guest_input: Option<std::path::PathBuf> = None;
    let mut guest_artifact_digest: Option<String> = None;
    let mut guest_max_output: Option<u64> = None;
    let mut guest_max_fuel: Option<u64> = None;
    let mut guest_max_memory: Option<u64> = None;
    let mut guest_wall_ms: Option<u64> = None;
    let mut guest_epoch_ticks: Option<u64> = None;
    let mut grant_seen = false;
    let mut grant_pipe: Option<String> = None;
    let mut grant_kernel_sid: Option<String> = None;
    let mut grant_kernel_session: Option<u64> = None;
    let mut grant_kernel_artifact_sha256: Option<String> = None;
    let mut grant_connect_timeout_ms: Option<u64> = None;
    let mut grant_component: Option<String> = None;
    let mut grant_artifact: Option<std::path::PathBuf> = None;
    let mut grant_world: Option<String> = None;
    let mut grant_descriptor: Option<std::path::PathBuf> = None;
    let mut grant_nonce: Option<String> = None;
    let mut grant_deadline_ms: Option<u64> = None;
    let mut index = 0;
    while index < arguments.len() {
        // Grant flags accept both spellings: split `--grant-flag=value`
        // once up front (grant namespace only — every other token keeps its
        // existing arm verbatim).
        let (flag, inline_value): (&str, Option<&str>) = match arguments[index].split_once('=') {
            Some((head, tail)) if head.starts_with("--grant-") => (head, Some(tail)),
            _ => (arguments[index].as_str(), None),
        };
        match flag {
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
            "--experimental-typed-component" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument(
                        "--experimental-typed-component requires a value".to_owned(),
                    )
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--experimental-typed-component requires a value".to_owned(),
                    ));
                }
                experimental_typed_component = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            value if value.starts_with("--experimental-typed-component=") => {
                let value = value.trim_start_matches("--experimental-typed-component=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--experimental-typed-component= requires a value".to_owned(),
                    ));
                }
                experimental_typed_component = Some(std::path::PathBuf::from(value));
                index += 1;
            }
            "--world" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--world requires a value".to_owned())
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--world requires a value".to_owned(),
                    ));
                }
                experimental_world = Some(value.clone());
                index += 2;
            }
            value if value.starts_with("--world=") => {
                let value = value.trim_start_matches("--world=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--world= requires a value".to_owned(),
                    ));
                }
                experimental_world = Some(value.to_owned());
                index += 1;
            }
            "--guest-exec" => {
                guest_exec = true;
                index += 1;
            }
            "--guest-exec-artifact" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--guest-exec-artifact requires a value".to_owned())
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--guest-exec-artifact requires a value".to_owned(),
                    ));
                }
                guest_artifact = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            "--guest-exec-input" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--guest-exec-input requires a value".to_owned())
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--guest-exec-input requires a value".to_owned(),
                    ));
                }
                guest_input = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            "--guest-exec-artifact-digest" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument(
                        "--guest-exec-artifact-digest requires a value".to_owned(),
                    )
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--guest-exec-artifact-digest requires a value".to_owned(),
                    ));
                }
                guest_artifact_digest = Some(value.clone());
                index += 2;
            }
            "--guest-exec-max-output" => {
                guest_max_output = Some(parse_guest_limit(
                    "--guest-exec-max-output",
                    &arguments,
                    &mut index,
                )?);
            }
            "--guest-exec-max-fuel" => {
                guest_max_fuel = Some(parse_guest_limit(
                    "--guest-exec-max-fuel",
                    &arguments,
                    &mut index,
                )?);
            }
            "--guest-exec-max-memory" => {
                guest_max_memory = Some(parse_guest_limit(
                    "--guest-exec-max-memory",
                    &arguments,
                    &mut index,
                )?);
            }
            "--guest-exec-wall-ms" => {
                guest_wall_ms = Some(parse_guest_limit(
                    "--guest-exec-wall-ms",
                    &arguments,
                    &mut index,
                )?);
            }
            "--guest-exec-epoch-ticks" => {
                guest_epoch_ticks = Some(parse_guest_limit(
                    "--guest-exec-epoch-ticks",
                    &arguments,
                    &mut index,
                )?);
            }
            "--grant-pipe" => {
                grant_seen = true;
                let text = claim_grant_value("--grant-pipe", inline_value, &arguments, &mut index)?;
                grant_pipe = Some(grant_text_value(&text));
            }
            "--grant-kernel-sid" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-kernel-sid", inline_value, &arguments, &mut index)?;
                grant_kernel_sid = Some(grant_text_value(&text));
            }
            "--grant-kernel-session" => {
                grant_seen = true;
                let text = claim_grant_value(
                    "--grant-kernel-session",
                    inline_value,
                    &arguments,
                    &mut index,
                )?;
                grant_kernel_session = Some(grant_u64_value("--grant-kernel-session", &text)?);
            }
            "--grant-kernel-artifact-sha256" => {
                grant_seen = true;
                let text = claim_grant_value(
                    "--grant-kernel-artifact-sha256",
                    inline_value,
                    &arguments,
                    &mut index,
                )?;
                grant_kernel_artifact_sha256 = Some(grant_text_value(&text));
            }
            "--grant-connect-timeout-ms" => {
                grant_seen = true;
                let text = claim_grant_value(
                    "--grant-connect-timeout-ms",
                    inline_value,
                    &arguments,
                    &mut index,
                )?;
                grant_connect_timeout_ms =
                    Some(grant_u64_value("--grant-connect-timeout-ms", &text)?);
            }
            "--grant-component" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-component", inline_value, &arguments, &mut index)?;
                grant_component = Some(grant_text_value(&text));
            }
            "--grant-artifact" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-artifact", inline_value, &arguments, &mut index)?;
                grant_artifact = Some(grant_path_value(&text));
            }
            "--grant-world" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-world", inline_value, &arguments, &mut index)?;
                grant_world = Some(grant_text_value(&text));
            }
            "--grant-descriptor" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-descriptor", inline_value, &arguments, &mut index)?;
                grant_descriptor = Some(grant_path_value(&text));
            }
            "--grant-nonce" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-nonce", inline_value, &arguments, &mut index)?;
                grant_nonce = Some(grant_text_value(&text));
            }
            "--grant-deadline-ms" => {
                grant_seen = true;
                let text =
                    claim_grant_value("--grant-deadline-ms", inline_value, &arguments, &mut index)?;
                grant_deadline_ms = Some(grant_u64_value("--grant-deadline-ms", &text)?);
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    match (&experimental_typed_component, &experimental_world) {
        (Some(_), None) => return Err(CliError::MissingExperimentalWorld),
        (None, Some(_)) => return Err(CliError::MissingExperimentalComponent),
        (Some(_), Some(world)) => {
            if crate::typed_bindings::TypedWorld::parse(world).is_none() {
                return Err(CliError::UnknownWorld(world.clone()));
            }
        }
        (None, None) => {}
    }
    let guest_exec = if guest_exec {
        Some(GuestExecArgs {
            artifact: guest_artifact.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-artifact".to_owned(),
                )
            })?,
            input: guest_input.ok_or_else(|| {
                CliError::MalformedArgument("--guest-exec requires --guest-exec-input".to_owned())
            })?,
            artifact_digest: guest_artifact_digest.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-artifact-digest".to_owned(),
                )
            })?,
            max_output_bytes: guest_max_output.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-max-output".to_owned(),
                )
            })?,
            max_fuel: guest_max_fuel.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-max-fuel".to_owned(),
                )
            })?,
            max_memory_bytes: guest_max_memory.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-max-memory".to_owned(),
                )
            })?,
            wall_deadline_ms: guest_wall_ms.ok_or_else(|| {
                CliError::MalformedArgument("--guest-exec requires --guest-exec-wall-ms".to_owned())
            })?,
            epoch_deadline_ticks: guest_epoch_ticks.ok_or_else(|| {
                CliError::MalformedArgument(
                    "--guest-exec requires --guest-exec-epoch-ticks".to_owned(),
                )
            })?,
        })
    } else if guest_artifact.is_some()
        || guest_input.is_some()
        || guest_artifact_digest.is_some()
        || guest_max_output.is_some()
        || guest_max_fuel.is_some()
        || guest_max_memory.is_some()
        || guest_wall_ms.is_some()
        || guest_epoch_ticks.is_some()
    {
        return Err(CliError::MalformedArgument(
            "guest execution arguments require --guest-exec".to_owned(),
        ));
    } else {
        None
    };
    let has_guest_exec = guest_exec.is_some();
    let has_experimental = experimental_typed_component.is_some() || experimental_world.is_some();
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
        experimental_typed_component,
        experimental_world,
        guest_exec,
        grant_launch: assemble_grant_launch(
            grant_seen,
            has_guest_exec,
            has_experimental,
            grant_pipe,
            grant_kernel_sid,
            grant_kernel_session,
            grant_kernel_artifact_sha256,
            grant_connect_timeout_ms,
            grant_component,
            grant_artifact,
            grant_world,
            grant_descriptor,
            grant_nonce,
            grant_deadline_ms,
        )?,
    })
}

/// Assembles the governed grant-launch argument set: all-or-nothing and
/// exclusive with guest execution and the experimental path. Any partial
/// set, mode overlap, unknown world, or out-of-range session fails closed
/// with the offending flag named.
#[allow(clippy::too_many_arguments)]
fn assemble_grant_launch(
    grant_seen: bool,
    has_guest_exec: bool,
    has_experimental: bool,
    grant_pipe: Option<String>,
    grant_kernel_sid: Option<String>,
    grant_kernel_session: Option<u64>,
    grant_kernel_artifact_sha256: Option<String>,
    grant_connect_timeout_ms: Option<u64>,
    grant_component: Option<String>,
    grant_artifact: Option<std::path::PathBuf>,
    grant_world: Option<String>,
    grant_descriptor: Option<std::path::PathBuf>,
    grant_nonce: Option<String>,
    grant_deadline_ms: Option<u64>,
) -> Result<Option<GrantLaunchArgs>, CliError> {
    if !grant_seen {
        return Ok(None);
    }
    if has_guest_exec {
        return Err(CliError::MalformedArgument(
            "grant launch is exclusive with --guest-exec".to_owned(),
        ));
    }
    if has_experimental {
        return Err(CliError::MalformedArgument(
            "grant launch is exclusive with the experimental path".to_owned(),
        ));
    }
    let missing =
        |flag: &'static str| CliError::MalformedArgument(format!("grant launch requires {flag}"));
    let session = grant_kernel_session.ok_or_else(|| missing("--grant-kernel-session"))?;
    let kernel_session_id = u32::try_from(session).map_err(|_| {
        CliError::MalformedArgument("--grant-kernel-session requires a u32 value".to_owned())
    })?;
    let world_name = grant_world.ok_or_else(|| missing("--grant-world"))?;
    let world = crate::typed_bindings::TypedWorld::parse(&world_name)
        .ok_or(CliError::UnknownWorld(world_name))?;
    Ok(Some(GrantLaunchArgs {
        pipe_name: grant_pipe.ok_or_else(|| missing("--grant-pipe"))?,
        kernel_sid: grant_kernel_sid.ok_or_else(|| missing("--grant-kernel-sid"))?,
        kernel_session_id,
        kernel_artifact_sha256: grant_kernel_artifact_sha256
            .ok_or_else(|| missing("--grant-kernel-artifact-sha256"))?,
        connect_timeout_ms: grant_connect_timeout_ms
            .ok_or_else(|| missing("--grant-connect-timeout-ms"))?,
        component_id: grant_component.ok_or_else(|| missing("--grant-component"))?,
        artifact_path: grant_artifact.ok_or_else(|| missing("--grant-artifact"))?,
        world,
        descriptor_path: grant_descriptor.ok_or_else(|| missing("--grant-descriptor"))?,
        nonce: grant_nonce.ok_or_else(|| missing("--grant-nonce"))?,
        deadline_unix_ms: grant_deadline_ms.ok_or_else(|| missing("--grant-deadline-ms"))?,
    }))
}

/// Parses one guest-execution numeric ceiling: present, non-empty, and a
/// valid `u64`. Zero and over-ceiling values are rejected later by
/// guest-execution validation with a process exit code, keeping parse
/// errors (malformed text) distinct from admission errors (bad values).
fn parse_guest_limit(
    flag: &'static str,
    arguments: &[String],
    index: &mut usize,
) -> Result<u64, CliError> {
    let malformed = || CliError::MalformedArgument(format!("{flag} requires a value"));
    let value = arguments.get(*index + 1).ok_or_else(malformed)?;
    if value.is_empty() {
        return Err(malformed());
    }
    let parsed: u64 = value
        .parse()
        .map_err(|_| CliError::MalformedArgument(format!("{flag} requires a u64 value")))?;
    *index += 2;
    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn guest_argv() -> Vec<String> {
        [
            "--profile",
            "D2_OPERATIONAL",
            "--guest-exec",
            "--guest-exec-artifact",
            "artifact.bin",
            "--guest-exec-input",
            "input.bin",
            "--guest-exec-artifact-digest",
            "ab",
            "--guest-exec-max-output",
            "64",
            "--guest-exec-max-fuel",
            "100000",
            "--guest-exec-max-memory",
            "1048576",
            "--guest-exec-wall-ms",
            "10000",
            "--guest-exec-epoch-ticks",
            "100",
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    #[test]
    fn guest_exec_args_parse_with_all_ceilings() {
        let config = parse_args(guest_argv()).expect("guest argv parses");
        let guest = config.guest_exec.expect("guest mode selected");
        assert_eq!(guest.max_output_bytes, 64);
        assert_eq!(guest.max_fuel, 100_000);
        assert_eq!(guest.max_memory_bytes, 1_048_576);
        assert_eq!(guest.wall_deadline_ms, 10000);
        assert_eq!(guest.epoch_deadline_ticks, 100);
        assert_eq!(guest.artifact_digest, "ab");
    }

    fn grant_argv() -> Vec<String> {
        [
            "--profile",
            "D2_OPERATIONAL",
            "--grant-pipe",
            "eliot-kernel-front-door",
            "--grant-kernel-sid",
            "S-1-5-18",
            "--grant-kernel-session",
            "1",
            "--grant-kernel-artifact-sha256",
            &"a".repeat(64),
            "--grant-connect-timeout-ms",
            "250",
            "--grant-component",
            "component-1955",
            "--grant-artifact",
            "component.bin",
            "--grant-world",
            "context-admission",
            "--grant-descriptor",
            "launch.json",
            "--grant-nonce",
            "nonce-1955",
            "--grant-deadline-ms",
            "9999999999999",
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    #[test]
    fn grant_launch_args_parse_complete() {
        let config = parse_args(grant_argv()).expect("grant argv parses");
        let grant = config.grant_launch.expect("grant mode selected");
        assert_eq!(grant.pipe_name, "eliot-kernel-front-door");
        assert_eq!(grant.kernel_sid, "S-1-5-18");
        assert_eq!(grant.kernel_session_id, 1);
        assert_eq!(grant.kernel_artifact_sha256, "a".repeat(64));
        assert_eq!(grant.connect_timeout_ms, 250);
        assert_eq!(grant.component_id, "component-1955");
        assert_eq!(
            grant.artifact_path,
            std::path::PathBuf::from("component.bin")
        );
        assert_eq!(
            grant.world,
            crate::typed_bindings::TypedWorld::ContextAdmission
        );
        assert_eq!(
            grant.descriptor_path,
            std::path::PathBuf::from("launch.json")
        );
        assert_eq!(grant.nonce, "nonce-1955");
        assert_eq!(grant.deadline_unix_ms, 9_999_999_999_999);
    }

    #[test]
    fn grant_launch_args_fail_closed() {
        // Partial set names the missing flag.
        let mut argv = grant_argv();
        argv.drain(20..22);
        assert_eq!(
            parse_args(argv),
            Err(CliError::MalformedArgument(
                "grant launch requires --grant-nonce".to_owned()
            ))
        );
        // Non-numeric session.
        let mut argv = grant_argv();
        argv[7] = "lots".to_owned();
        assert!(matches!(
            parse_args(argv),
            Err(CliError::MalformedArgument(_))
        ));
        // Out-of-range session.
        let mut argv = grant_argv();
        argv[7] = "4294967296".to_owned();
        assert_eq!(
            parse_args(argv),
            Err(CliError::MalformedArgument(
                "--grant-kernel-session requires a u32 value".to_owned()
            ))
        );
        // Unknown world.
        let mut argv = grant_argv();
        argv[17] = "fancy-world".to_owned();
        assert_eq!(
            parse_args(argv),
            Err(CliError::UnknownWorld("fancy-world".to_owned()))
        );
        // Guest mode overlap.
        let mut argv = grant_argv();
        argv.extend(guest_argv().into_iter().skip(2));
        assert!(matches!(
            parse_args(argv),
            Err(CliError::MalformedArgument(_))
        ));
        // No grant flags means no grant mode.
        let config = parse_args(["--profile", "D2_OPERATIONAL"]).expect("plain argv parses");
        assert!(config.grant_launch.is_none());
    }

    #[test]
    fn guest_exec_args_fail_closed() {
        // Missing artifact piece.
        let mut argv = guest_argv();
        argv.drain(3..5);
        assert!(matches!(
            parse_args(argv),
            Err(CliError::MalformedArgument(_))
        ));
        // Non-numeric ceiling.
        let mut argv = guest_argv();
        argv[13] = "lots".to_owned();
        assert!(matches!(
            parse_args(argv),
            Err(CliError::MalformedArgument(_))
        ));
        // Stray guest piece without the mode flag.
        let mut argv = guest_argv();
        argv.remove(2);
        assert!(matches!(
            parse_args(argv),
            Err(CliError::MalformedArgument(_))
        ));
    }
}
