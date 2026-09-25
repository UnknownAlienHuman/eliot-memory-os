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
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
        experimental_typed_component,
        experimental_world,
        guest_exec,
    })
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
