//! WASM-host CLI argument/config contract: deterministic profile/transport parsing and value assembly only.
//! Architecture: A2.3, A9.1, A12.3; ARCH-AUTH-01, ARCH-DRM-01, ARCH-SEC-02.
//! Implementation: I1.3, I2.19, I3.9, I14.19; no Dreamer, semantic/canonical-write, runtime/provider, policy, retry, or authority ownership.

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

/// The local-only transports understood by the binary contract. A selection is
/// parsed and carried in [`CliConfig::transport`]; no in-crate consumer reads
/// it, because the ordinary loop takes its material from the owner-staged
/// delivery set (`request_loop.rs:6166-6169`), never from this choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Local standard input/output spelling. The live result path frames
    /// stdout as one serialized JSON object per line under
    /// `MAX_RESULT_FRAME_BYTES` (`request_loop.rs:3058-3071`), not as a
    /// length-delimited frame.
    Stdio,
    /// Local loopback spelling, accepted and carried exactly like `Stdio`.
    /// There is no injected transport owner in this host to consume it.
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
    /// A governed component was supplied without its world selection.
    MissingGovernedWorld,
    /// The `--world` spelling on a typed lane (experimental or governed) is
    /// not a frozen typed world.
    UnknownWorld(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile => formatter.write_str("MISSING_PROFILE"),
            Self::UnsupportedProfile(_) => formatter.write_str("UNSUPPORTED_PROFILE"),
            Self::MalformedArgument(_) => formatter.write_str("MALFORMED_ARGUMENT"),
            Self::RemoteTransportForbidden(_) => formatter.write_str("REMOTE_TRANSPORT_FORBIDDEN"),
            Self::MissingExperimentalComponent => {
                formatter.write_str("MISSING_EXPERIMENTAL_COMPONENT")
            }
            Self::MissingExperimentalWorld => formatter.write_str("MISSING_EXPERIMENTAL_WORLD"),
            Self::MissingGovernedWorld => formatter.write_str("MISSING_GOVERNED_WORLD"),
            Self::UnknownWorld(_) => formatter.write_str("UNKNOWN_WORLD"),
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

/// Parsed profile, local transport, and the optional explicit selections:
/// one experimental or governed typed artifact (never both), the typed world
/// that artifact needs, and the one-shot guest-execution argument set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliConfig {
    /// Selected profile.
    pub profile: Profile,
    /// Selected local transport.
    pub transport: Transport,
    /// Explicit bounded local artifact for the non-governed experimental path.
    pub experimental_typed_component: Option<std::path::PathBuf>,
    /// Explicit bounded local artifact for a governed typed attempt. The
    /// governed lane binds no Kernel admission channel, so this selection is
    /// denied with the typed admission denial before compilation or
    /// instantiation and never falls back to the experimental path.
    pub governed_typed_component: Option<std::path::PathBuf>,
    /// Explicit frozen world selection for an explicit typed lane (the
    /// experimental path or a governed attempt).
    pub experimental_world: Option<String>,
    /// One-shot P03-admitted guest execution: run the artifact's `run`
    /// export over the input bytes inside this process and emit raw output
    /// bytes on stdout. `None` unless `--guest-exec` is passed with its full
    /// argument set. This is how a reaped child executes an admitted guest:
    /// the parent spawns this binary with these exact arguments through the
    /// P03 staged intent (`wasm_dispatch.rs:1285-1305`), so every value here
    /// is admission-bound, never ambient.
    pub guest_exec: Option<GuestExecArgs>,
}

/// Bounded argument set for one-shot admitted guest execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestExecArgs {
    /// Component artifact file. The child requires an explicit absolute path
    /// for it (`guest_exec.rs:212-214`), then bounds, preflights and
    /// digest-checks the bytes it reads.
    pub artifact: std::path::PathBuf,
    /// Raw input file (bounded), and required to be absolute too
    /// (`guest_exec.rs:223-225`), so no read resolves against the working
    /// directory.
    pub input: std::path::PathBuf,
    /// Expected SHA-256 hex of the artifact bytes (TOCTOU check on read):
    /// re-hashed from the bytes actually read, twice — against the bounded
    /// preflight digest (`guest_exec.rs:219-221`) and against the buffer
    /// handed to validation (`guest_exec.rs:161-164`).
    pub artifact_digest: String,
    /// Output byte ceiling. NOT a Store limiter: the Store's limiter carries
    /// memory, table and instance counts only
    /// (`wasmtime_provider.rs:489-497`), so this ceiling is compared against
    /// the lifted return value after the call, inside
    /// `invoke_component_with_epoch_driver` (`wasmtime_provider.rs:461`): the
    /// guard `value.len() as u64 <= limits.max_output_bytes` at `:561`, and
    /// the `EngineTermination::OutputLimit` refusal it takes at `:565-569`.
    /// That refusal is this in-process provider's only `OutputLimit` site; the
    /// P03 child contour mints its own from a truncated capture
    /// (`child_engine.rs:173-178`). The child also gates its own stdout
    /// emission against the same ceiling (`guest_exec.rs:286-288`).
    pub max_output_bytes: u64,
    /// Fuel ceiling enforced by the guest Store (`wasmtime_provider.rs:514`).
    pub max_fuel: u64,
    /// Memory byte ceiling enforced by the guest Store's limiter
    /// (`wasmtime_provider.rs:490`).
    pub max_memory_bytes: u64,
    /// Wall deadline (ms) enforced by the epoch driver, which carries this
    /// computed instant (`wasmtime_provider.rs:530`) and interrupts through
    /// the Store epoch.
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks: armed on the guest Store with
    /// `set_epoch_deadline` (`wasmtime_provider.rs:519`) and advanced by the
    /// epoch driver, which is what interrupts the guest.
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
    let mut governed_typed_component: Option<std::path::PathBuf> = None;
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
            "--governed-typed-component" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument(
                        "--governed-typed-component requires a value".to_owned(),
                    )
                })?;
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--governed-typed-component requires a value".to_owned(),
                    ));
                }
                governed_typed_component = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            value if value.starts_with("--governed-typed-component=") => {
                let value = value.trim_start_matches("--governed-typed-component=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--governed-typed-component= requires a value".to_owned(),
                    ));
                }
                governed_typed_component = Some(std::path::PathBuf::from(value));
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
    if governed_typed_component.is_some() {
        match &experimental_world {
            None => return Err(CliError::MissingGovernedWorld),
            Some(world) => {
                if crate::typed_bindings::TypedWorld::parse(world).is_none() {
                    return Err(CliError::UnknownWorld(world.clone()));
                }
            }
        }
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
    if guest_exec.is_some() && experimental_typed_component.is_some() {
        return Err(CliError::MalformedArgument(
            "guest execution and typed experimental selection are mutually exclusive".to_owned(),
        ));
    }
    if governed_typed_component.is_some() && experimental_typed_component.is_some() {
        return Err(CliError::MalformedArgument(
            "governed and experimental typed selections are mutually exclusive".to_owned(),
        ));
    }
    if guest_exec.is_some() && governed_typed_component.is_some() {
        return Err(CliError::MalformedArgument(
            "guest execution and governed typed selection are mutually exclusive".to_owned(),
        ));
    }
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
        experimental_typed_component,
        governed_typed_component,
        experimental_world,
        guest_exec,
    })
}

/// Parses one guest-execution numeric ceiling: present, non-empty, and a
/// valid `u64`. Zero and over-ceiling values are rejected later by
/// guest-execution validation with a process exit code — `GUEST_EXEC_BAD_LIMITS`
/// and status `EXIT_DENIED` (1) for a zero ceiling or epoch ticks above
/// `MAX_EPOCH_DEADLINE_TICKS` (`guest_exec.rs:165-175`, `:129-136`) — keeping
/// parse errors (malformed text) distinct from admission errors (bad values).
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
        // Missing artifact piece. Draining the flag and its value leaves every
        // remaining token pairing cleanly as flag/value, so the parse loop
        // cannot refuse on its own: the only reachable refusal is the assembled
        // `--guest-exec` missing-artifact requirement. The exact detail is
        // pinned, for the same reason as the ceiling case below — a refusal
        // raised anywhere else fails here instead of being satisfied by any
        // `MalformedArgument`.
        let mut argv = guest_argv();
        argv.drain(3..5);
        assert_eq!(
            parse_args(argv),
            Err(CliError::MalformedArgument(
                "--guest-exec requires --guest-exec-artifact".to_owned()
            ))
        );
        // Non-numeric ceiling VALUE: `argv[14]` is the `--guest-exec-max-memory`
        // value, so this reaches `parse_guest_limit`'s `u64` parse rather than
        // the unknown-argument arm. The expected detail is bound from the flag
        // name exactly as the production path formats it, so a mutation that
        // drifts back to a flag index fails here instead of being satisfied by
        // any `MalformedArgument`.
        let flag = "--guest-exec-max-memory";
        let expected = format!("{flag} requires a u64 value");
        let mut argv = guest_argv();
        argv[14] = "lots".to_owned();
        assert_eq!(parse_args(argv), Err(CliError::MalformedArgument(expected)));
        // Stray guest piece without the mode flag. Removing `--guest-exec`
        // leaves a complete, individually well-formed guest argument set, so
        // the loop accepts every token and the refusal must come from the
        // assembled guest mode, for the reason the parse names.
        let mut argv = guest_argv();
        argv.remove(2);
        assert_eq!(
            parse_args(argv),
            Err(CliError::MalformedArgument(
                "guest execution arguments require --guest-exec".to_owned()
            ))
        );
    }
}
