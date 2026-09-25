use eliot_agent_api::{AdmittedRouteReceipt, AgentAttempt, ProviderExecutionBinding};
use eliot_agent_opencode::{
    AdmittedAttemptCandidate, AdmittedOpenCodeAttempt, BasicAuth, LoopbackEndpoint, ModelSelection,
    NoAuthorityRunResult, OpenCodeClient, OpenCodeRunError, OpenCodeRunPolicy, ReadOnlyRunRequest,
    RunStatus,
};
use eliot_contracts::{ResourceGeneration, StateFence};
use secrecy::SecretString;
use serde::Deserialize;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

const MAX_PROMPT_BYTES: usize = 8 * 1024 * 1024;
const PROVIDER_ID: &str = "opencode-go";
const MODEL_ID: &str = "deepseek-v4-flash";
const USAGE: &str = "usage: eliot-opencode-bootstrap <loopback-endpoint> <absolute-directory> <prompt-file>\n       eliot-opencode-bootstrap --admitted <loopback-endpoint> <absolute-directory> <prompt-file> <admission-envelope-json-file>\n\noptional admitted-route environment:\n  ELIOT_OPENCODE_EXECUTABLE_FP  expected server executable fingerprint\n  ELIOT_OPENCODE_ENV_ALLOWLIST  comma-separated environment allowlist";

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    endpoint: String,
    directory: PathBuf,
    prompt_file: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct AdmittedCliArgs {
    endpoint: String,
    directory: PathBuf,
    prompt_file: PathBuf,
    envelope_file: PathBuf,
}

/// Typed admission envelope for the supervised admitted-route path.
///
/// Every field is an exact owner type: deserialization failures reject the
/// envelope before any validation or execution, and
/// [`AdmittedOpenCodeAttempt::new`] verifies the full admission agreement
/// (via each owner's `validate()`) before the caller may execute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedEnvelope {
    admission: AdmittedRouteReceipt,
    binding: ProviderExecutionBinding,
    attempt: AgentAttempt,
    current_fence: StateFence,
    runtime_generation: ResourceGeneration,
}

#[derive(Debug)]
enum CliError {
    Usage,
    InvalidArgument(&'static str),
    Environment(&'static str),
    Endpoint(String),
    Authentication(String),
    PromptIo(String),
    PromptTooLarge { limit: usize, observed: usize },
    PromptNotUtf8,
    Model(String),
    Request(String),
    Run(String),
    Envelope(String),
    Output(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::InvalidArgument(message) => formatter.write_str(message),
            Self::Environment(name) => {
                write!(formatter, "required environment variable {name} is missing")
            }
            Self::Endpoint(message) => write!(formatter, "invalid loopback endpoint: {message}"),
            Self::Authentication(message) => write!(formatter, "invalid authentication: {message}"),
            Self::PromptIo(message) => write!(formatter, "cannot read prompt file: {message}"),
            Self::PromptTooLarge { limit, observed } => {
                write!(
                    formatter,
                    "prompt file exceeds {limit} bytes (observed {observed})"
                )
            }
            Self::PromptNotUtf8 => formatter.write_str("prompt file is not valid UTF-8"),
            Self::Model(message) => write!(formatter, "invalid pinned model: {message}"),
            Self::Request(message) => write!(formatter, "invalid read-only request: {message}"),
            Self::Run(message) => write!(formatter, "OpenCode bootstrap failed: {message}"),
            Self::Envelope(message) => write!(formatter, "invalid admission envelope: {message}"),
            Self::Output(message) => write!(formatter, "cannot write result: {message}"),
        }
    }
}

impl std::error::Error for CliError {}

fn parse_args(args: &[OsString]) -> Result<CliArgs, CliError> {
    if args.len() != 4 {
        return Err(CliError::Usage);
    }
    let endpoint = args[1]
        .clone()
        .into_string()
        .map_err(|_| CliError::InvalidArgument("loopback endpoint must be valid UTF-8"))?;
    let directory = PathBuf::from(&args[2]);
    let prompt_file = PathBuf::from(&args[3]);
    if endpoint.is_empty() {
        return Err(CliError::InvalidArgument(
            "loopback endpoint must not be empty",
        ));
    }
    if directory.as_os_str().is_empty() {
        return Err(CliError::InvalidArgument(
            "absolute directory must not be empty",
        ));
    }
    if !directory.is_absolute() {
        return Err(CliError::InvalidArgument(
            "absolute directory must be an absolute path",
        ));
    }
    if prompt_file.as_os_str().is_empty() {
        return Err(CliError::InvalidArgument("prompt file must not be empty"));
    }
    Ok(CliArgs {
        endpoint,
        directory,
        prompt_file,
    })
}

fn parse_admitted_args(args: &[OsString]) -> Result<AdmittedCliArgs, CliError> {
    if args.len() != 6 {
        return Err(CliError::Usage);
    }
    let endpoint = args[2]
        .clone()
        .into_string()
        .map_err(|_| CliError::InvalidArgument("loopback endpoint must be valid UTF-8"))?;
    let directory = PathBuf::from(&args[3]);
    let prompt_file = PathBuf::from(&args[4]);
    let envelope_file = PathBuf::from(&args[5]);
    if endpoint.is_empty() {
        return Err(CliError::InvalidArgument(
            "loopback endpoint must not be empty",
        ));
    }
    if directory.as_os_str().is_empty() {
        return Err(CliError::InvalidArgument(
            "absolute directory must not be empty",
        ));
    }
    if !directory.is_absolute() {
        return Err(CliError::InvalidArgument(
            "absolute directory must be an absolute path",
        ));
    }
    if prompt_file.as_os_str().is_empty() {
        return Err(CliError::InvalidArgument("prompt file must not be empty"));
    }
    if envelope_file.as_os_str().is_empty() {
        return Err(CliError::InvalidArgument(
            "admission envelope file must not be empty",
        ));
    }
    Ok(AdmittedCliArgs {
        endpoint,
        directory,
        prompt_file,
        envelope_file,
    })
}

fn is_admitted_form(args: &[OsString]) -> bool {
    args.len() >= 2
        && args[1]
            .to_str()
            .is_some_and(|argument| argument == "--admitted")
}

fn help_requested(args: &[OsString]) -> bool {
    args.len() == 2
        && args[1]
            .to_str()
            .is_some_and(|argument| matches!(argument, "-h" | "--help"))
}

fn decode_prompt(bytes: Vec<u8>) -> Result<String, CliError> {
    if bytes.len() > MAX_PROMPT_BYTES {
        return Err(CliError::PromptTooLarge {
            limit: MAX_PROMPT_BYTES,
            observed: bytes.len(),
        });
    }
    String::from_utf8(bytes).map_err(|_| CliError::PromptNotUtf8)
}

fn read_prompt(path: &std::path::Path) -> Result<String, CliError> {
    let file = File::open(path).map_err(|error| CliError::PromptIo(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CliError::PromptIo(error.to_string()))?;
    if metadata.len() > MAX_PROMPT_BYTES as u64 {
        let observed = match usize::try_from(metadata.len()) {
            Ok(length) => length,
            Err(_) => MAX_PROMPT_BYTES,
        };
        return Err(CliError::PromptTooLarge {
            limit: MAX_PROMPT_BYTES,
            observed,
        });
    }
    let capacity = usize::try_from(metadata.len())
        .map_or(MAX_PROMPT_BYTES, |length| length.min(MAX_PROMPT_BYTES));
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_PROMPT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::PromptIo(error.to_string()))?;
    decode_prompt(bytes)
}

fn read_envelope(path: &std::path::Path) -> Result<AdmittedEnvelope, CliError> {
    let file = File::open(path).map_err(|error| CliError::Envelope(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CliError::Envelope(error.to_string()))?;
    if metadata.len() > MAX_PROMPT_BYTES as u64 {
        let observed = match usize::try_from(metadata.len()) {
            Ok(length) => length,
            Err(_) => MAX_PROMPT_BYTES,
        };
        return Err(CliError::Envelope(format!(
            "envelope file exceeds {MAX_PROMPT_BYTES} bytes (observed {observed})"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_or(MAX_PROMPT_BYTES, |length| length.min(MAX_PROMPT_BYTES));
    let mut bytes = Vec::with_capacity(capacity);
    file.take((MAX_PROMPT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::Envelope(error.to_string()))?;
    let text = decode_prompt(bytes).map_err(|error| match error {
        CliError::PromptTooLarge { limit, observed } => CliError::Envelope(format!(
            "envelope file exceeds {limit} bytes (observed {observed})"
        )),
        CliError::PromptNotUtf8 => {
            CliError::Envelope("envelope file is not valid UTF-8".to_owned())
        }
        other => other,
    })?;
    serde_json::from_str(&text)
        .map_err(|error| CliError::Envelope(sanitize_error(&error.to_string(), "")))
}

fn sanitize_error(message: &str, secret: &str) -> String {
    let redacted = if secret.is_empty() {
        message.to_owned()
    } else {
        message.replace(secret, "[REDACTED]")
    };
    redacted
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(4096)
        .collect()
}

fn model_selection() -> Result<ModelSelection, CliError> {
    ModelSelection::new(PROVIDER_ID, MODEL_ID)
        .map_err(|error| CliError::Model(sanitize_error(&error.to_string(), "")))
}

async fn run_admitted(args: AdmittedCliArgs) -> Result<(), CliError> {
    let password = std::env::var("OPENCODE_SERVER_PASSWORD")
        .map_err(|_| CliError::Environment("OPENCODE_SERVER_PASSWORD"))?;
    if password.is_empty() {
        return Err(CliError::Environment("OPENCODE_SERVER_PASSWORD"));
    }
    let username = match std::env::var("OPENCODE_SERVER_USERNAME") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "opencode".to_owned(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::InvalidArgument(
                "OPENCODE_SERVER_USERNAME must be valid UTF-8",
            ));
        }
    };
    let endpoint = args
        .endpoint
        .parse::<LoopbackEndpoint>()
        .map_err(|error| CliError::Endpoint(sanitize_error(&error.to_string(), &password)))?;
    let auth = BasicAuth::new(username, SecretString::from(password.clone()))
        .map_err(|error| CliError::Authentication(sanitize_error(&error.to_string(), &password)))?;
    let prompt = read_prompt(&args.prompt_file)?;
    let envelope = read_envelope(&args.envelope_file)?;
    let model = model_selection()?;
    let request = ReadOnlyRunRequest::new(prompt, model.clone())
        .map_err(|error| CliError::Request(sanitize_error(&error.to_string(), &password)))?;
    let mut policy = OpenCodeRunPolicy::new(args.directory)
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    match std::env::var("ELIOT_OPENCODE_EXECUTABLE_FP") {
        Ok(fingerprint) => {
            if fingerprint.trim().is_empty() {
                return Err(CliError::Environment("ELIOT_OPENCODE_EXECUTABLE_FP"));
            }
            policy = policy.with_executable_fingerprint(fingerprint);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::Environment("ELIOT_OPENCODE_EXECUTABLE_FP"));
        }
    }
    match std::env::var("ELIOT_OPENCODE_ENV_ALLOWLIST") {
        Ok(allowlist) => {
            if allowlist.trim().is_empty() {
                return Err(CliError::Environment("ELIOT_OPENCODE_ENV_ALLOWLIST"));
            }
            let entries: Vec<String> = allowlist
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect();
            if entries.is_empty() {
                return Err(CliError::Environment("ELIOT_OPENCODE_ENV_ALLOWLIST"));
            }
            policy = policy.with_environment_allowlist(entries);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::Environment("ELIOT_OPENCODE_ENV_ALLOWLIST"));
        }
    }
    let client = OpenCodeClient::new(endpoint, auth, policy)
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    // Single production caller of the admitted read-only path: construction
    // verifies the full admission agreement (AdmittedOpenCodeAttempt::new
    // runs verify()), and run_admitted_read_only re-verifies, enforces the
    // plan-agent read-only ceiling, and returns a candidate-only seal.
    let admitted_attempt_id = envelope.attempt.id.clone();
    let admitted_route_digest = envelope.admission.self_digest.clone();
    let admitted = AdmittedOpenCodeAttempt::new(
        Some(envelope.admission),
        envelope.binding,
        envelope.attempt,
        model,
        &envelope.current_fence,
        envelope.runtime_generation,
    )
    .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    let outcome = client
        .run_admitted_read_only(
            &admitted,
            &request,
            &envelope.current_fence,
            envelope.runtime_generation,
        )
        .await
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    if outcome.candidate.status != RunStatus::Succeeded {
        return Err(CliError::Run(
            "OpenCode returned a non-successful admitted candidate; nothing was serialized"
                .to_owned(),
        ));
    }
    // The production boundary emits only the sealed candidate artifact:
    // re-sealing the observed run must reproduce the identical seal, and the
    // seal must link the admitted attempt and admission digest carried by
    // this envelope. Anything else is refused, never printed.
    let resealed = AdmittedAttemptCandidate::seal(&admitted, &outcome.run)
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    if resealed != outcome.candidate
        || outcome.candidate.attempt_id != admitted_attempt_id
        || outcome.candidate.admitted_route_digest != admitted_route_digest
    {
        return Err(CliError::Run(
            "OpenCode admitted seal does not match the admitted attempt; nothing was serialized"
                .to_owned(),
        ));
    }
    let encoded = serde_json::to_string(&outcome.candidate)
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    writeln!(writer, "{encoded}")
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    writer
        .flush()
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    Ok(())
}

async fn run() -> Result<(), CliError> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    if help_requested(&raw_args) {
        let stdout = io::stdout();
        let mut writer = io::BufWriter::new(stdout.lock());
        writeln!(writer, "{USAGE}")
            .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), "")))?;
        writer
            .flush()
            .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), "")))?;
        return Ok(());
    }
    if is_admitted_form(&raw_args) {
        let admitted_args = parse_admitted_args(&raw_args)?;
        return run_admitted(admitted_args).await;
    }
    let args = parse_args(&raw_args)?;
    let password = std::env::var("OPENCODE_SERVER_PASSWORD")
        .map_err(|_| CliError::Environment("OPENCODE_SERVER_PASSWORD"))?;
    if password.is_empty() {
        return Err(CliError::Environment("OPENCODE_SERVER_PASSWORD"));
    }
    let username = match std::env::var("OPENCODE_SERVER_USERNAME") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "opencode".to_owned(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::InvalidArgument(
                "OPENCODE_SERVER_USERNAME must be valid UTF-8",
            ));
        }
    };
    let endpoint = args
        .endpoint
        .parse::<LoopbackEndpoint>()
        .map_err(|error| CliError::Endpoint(sanitize_error(&error.to_string(), &password)))?;
    let auth = BasicAuth::new(username, SecretString::from(password.clone()))
        .map_err(|error| CliError::Authentication(sanitize_error(&error.to_string(), &password)))?;
    let prompt = read_prompt(&args.prompt_file)?;
    let model = model_selection()?;
    let request = ReadOnlyRunRequest::new(prompt, model)
        .map_err(|error| CliError::Request(sanitize_error(&error.to_string(), &password)))?;
    let policy = OpenCodeRunPolicy::new(args.directory)
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    let client = OpenCodeClient::new(endpoint, auth, policy)
        .map_err(|error| CliError::Run(sanitize_error(&error.to_string(), &password)))?;
    let result: NoAuthorityRunResult =
        client
            .run_read_only(&request)
            .await
            .map_err(|error: OpenCodeRunError| {
                CliError::Run(sanitize_error(&error.to_string(), &password))
            })?;
    if result.status != RunStatus::Succeeded {
        return Err(CliError::Run(
            "OpenCode returned a non-successful result; nothing was serialized".to_owned(),
        ));
    }
    let encoded = serde_json::to_string(&result)
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    writeln!(writer, "{encoded}")
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    writer
        .flush()
        .map_err(|error| CliError::Output(sanitize_error(&error.to_string(), &password)))?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let stderr = io::stderr();
            let mut writer = io::BufWriter::new(stderr.lock());
            let _ = writeln!(writer, "error: {error}");
            let _ = writer.flush();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CliError, MAX_PROMPT_BYTES, decode_prompt, help_requested, parse_args};
    use std::ffi::OsString;

    #[test]
    fn positional_arguments_require_exactly_three_values() {
        let too_few = vec![
            OsString::from("bootstrap"),
            OsString::from("http://127.0.0.1:4096"),
        ];
        assert!(matches!(parse_args(&too_few), Err(CliError::Usage)));
        let valid = vec![
            OsString::from("bootstrap"),
            OsString::from("http://127.0.0.1:4096"),
            OsString::from(r"C:\Scratch"),
            OsString::from(r"C:\prompt.txt"),
        ];
        assert!(parse_args(&valid).is_ok());
    }

    #[test]
    fn help_is_recognized_only_as_the_sole_argument() {
        for flag in ["-h", "--help"] {
            assert!(help_requested(&[
                OsString::from("bootstrap"),
                OsString::from(flag),
            ]));
        }
        assert!(!help_requested(&[
            OsString::from("bootstrap"),
            OsString::from("--help"),
            OsString::from("unexpected"),
        ]));
    }

    #[test]
    fn prompt_decoder_rejects_only_bytes_over_the_eight_mib_ceiling() {
        let accepted = decode_prompt(vec![b'a'; MAX_PROMPT_BYTES]);
        assert!(accepted.is_ok());
        assert!(matches!(
            decode_prompt(vec![b'a'; MAX_PROMPT_BYTES + 1]),
            Err(CliError::PromptTooLarge { .. })
        ));
        assert!(matches!(
            decode_prompt(vec![0xff]),
            Err(CliError::PromptNotUtf8)
        ));
    }
}
