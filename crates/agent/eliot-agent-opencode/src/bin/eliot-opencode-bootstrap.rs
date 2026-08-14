use eliot_agent_opencode::{
    BasicAuth, LoopbackEndpoint, ModelSelection, NoAuthorityRunResult, OpenCodeClient,
    OpenCodeRunError, OpenCodeRunPolicy, ReadOnlyRunRequest, RunStatus,
};
use secrecy::SecretString;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

const MAX_PROMPT_BYTES: usize = 8 * 1024 * 1024;
const PROVIDER_ID: &str = "opencode-go";
const MODEL_ID: &str = "deepseek-v4-flash";
const USAGE: &str =
    "usage: eliot-opencode-bootstrap <loopback-endpoint> <absolute-directory> <prompt-file>";

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    endpoint: String,
    directory: PathBuf,
    prompt_file: PathBuf,
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

async fn run() -> Result<(), CliError> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
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
    use super::{CliError, MAX_PROMPT_BYTES, decode_prompt, parse_args};
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
