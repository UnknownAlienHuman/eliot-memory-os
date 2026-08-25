//! One-shot, no-authority bootstrap brief execution and evidence publication.

#![forbid(unsafe_code)]

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use eliot_agent_api::AgentWorkUnitBrief;
use eliot_bootstrap::{
    BootstrapBrief, BootstrapBriefCompiler, BootstrapDraftInput, BootstrapImprovementDraft,
    DraftImportDisposition, capture::capture_snapshot,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde_json::{Value, json};
use thiserror::Error;

const DRAFT_DIRECTORY: &str = ".eliot/evidence/bootstrap-drafts";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub(crate) enum BootstrapCommandError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("source unavailable: {0}")]
    SourceUnavailable(String),
    #[error("contract challenge: {0}")]
    ContractChallenge(String),
    #[error("publication/readback is unknown: {0}")]
    UnknownPublication(String),
    #[error("draft digest mismatch: {0}")]
    DigestMismatch(String),
}

impl BootstrapCommandError {
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => 2,
            Self::DigestMismatch(_) => 65,
            Self::SourceUnavailable(_) => 66,
            Self::UnknownPublication(_) => 75,
            Self::ContractChallenge(_) => 78,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::DigestMismatch(_) => "DIGEST_MISMATCH",
            Self::SourceUnavailable(_) => "SOURCE_UNAVAILABLE",
            Self::UnknownPublication(_) => "PUBLICATION_UNKNOWN",
            Self::ContractChallenge(_) => "CONTRACT_CHALLENGE",
        }
    }

    pub(crate) fn envelope(&self) -> Value {
        json!({
            "status": "error",
            "code": self.code(),
            "detail": self.to_string(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct BootstrapCommandSuccess {
    pub(crate) response: Value,
    pub(crate) draft_path: PathBuf,
    pub(crate) draft_sha256: String,
}

pub(crate) fn execute(
    work_unit_path: &Path,
    repo_root: &Path,
) -> Result<BootstrapCommandSuccess, BootstrapCommandError> {
    validate_absolute(work_unit_path, "work-unit")?;
    validate_absolute(repo_root, "repo-root")?;

    let work_unit_bytes = fs::read(work_unit_path).map_err(|error| {
        BootstrapCommandError::SourceUnavailable(format!("read work-unit seed: {error}"))
    })?;
    let work_unit: AgentWorkUnitBrief =
        serde_json::from_slice(&work_unit_bytes).map_err(|error| {
            BootstrapCommandError::InvalidInput(format!("decode AgentWorkUnitBrief: {error}"))
        })?;
    work_unit.validate().map_err(|error| {
        BootstrapCommandError::InvalidInput(format!("validate AgentWorkUnitBrief: {error}"))
    })?;

    let snapshot_artifact = capture_snapshot(repo_root).map_err(|error| {
        BootstrapCommandError::SourceUnavailable(format!("capture explicit repo root: {error}"))
    })?;
    let snapshot = &snapshot_artifact.snapshot;
    let brief = BootstrapBriefCompiler::compile(work_unit.clone(), snapshot)
        .map_err(|error| BootstrapCommandError::ContractChallenge(error.to_string()))?;
    let response = command_response(&brief, work_unit_path, repo_root)?;
    let draft = BootstrapImprovementDraft::new(
        BootstrapDraftInput {
            source_identity: format!(
                "{}@{}",
                snapshot_artifact.receipt.repository_root, snapshot_artifact.receipt.source_head
            ),
            normative_pair: snapshot.normative_pair.clone(),
            snapshot_ref: brief.snapshot_sha256.clone(),
            catalogue_ref: brief.catalogue_sha256.clone(),
            owner: "eliot-cli".to_owned(),
            discriminator: "bootstrap_brief_compiles_and_validates".to_owned(),
            import_disposition: DraftImportDisposition::CandidateOnly,
        },
        &work_unit,
    )
    .map_err(|error| BootstrapCommandError::ContractChallenge(error.to_string()))?;
    let draft_value = serde_json::to_value(draft)
        .map_err(|error| BootstrapCommandError::UnknownPublication(error.to_string()))?;
    let (draft_path, draft_sha256) = publish_draft(repo_root, &draft_value)?;
    Ok(BootstrapCommandSuccess {
        response,
        draft_path,
        draft_sha256,
    })
}

fn command_response(
    brief: &BootstrapBrief,
    work_unit_path: &Path,
    repo_root: &Path,
) -> Result<Value, BootstrapCommandError> {
    let request = json!({
        "request": {
            "request": {
                "metadata": {
                    "request_id": format!("bootstrap-{}", brief.brief_sha256),
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-bootstrap",
                    "source_id": work_unit_path.display().to_string(),
                    "state_fence": {
                        "authority_epoch": 1,
                        "resource_generation": 1,
                        "task_revision": null,
                        "policy_revision": null,
                        "integration_revision": null
                    },
                    "clock": {
                        "valid_time_ms": null,
                        "known_time_ms": null,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                }
            },
            "idempotency_key": format!("bootstrap:{}", brief.brief_sha256),
            "deadline_unix_ms": 1,
            "cancellation_id": format!("bootstrap-cancel:{}", brief.brief_sha256)
        },
        "command": "bootstrap-brief",
        "arguments": {
            "kind": "bootstrap_brief",
            "work_unit": work_unit_path.display().to_string(),
            "repo_root": repo_root.display().to_string()
        }
    });
    let request: eliot_cli::CommandRequest = serde_json::from_value(request)
        .map_err(|error| BootstrapCommandError::ContractChallenge(error.to_string()))?;
    eliot_cli::CommandCatalogue::current()
        .bootstrap_brief_response(&request, brief.clone())
        .and_then(|response| {
            serde_json::to_value(response)
                .map_err(|error| eliot_cli::CliError::Protocol(error.to_string()))
        })
        .map_err(|error| BootstrapCommandError::ContractChallenge(error.to_string()))
}

fn content_digest(value: &Value) -> Result<String, BootstrapCommandError> {
    let mut unsigned = value.clone();
    unsigned["canonical_digest"] = Value::String(String::new());
    let bytes = canonical_json_bytes(&unsigned)
        .map_err(|error| BootstrapCommandError::UnknownPublication(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn publish_draft(
    repo_root: &Path,
    value: &Value,
) -> Result<(PathBuf, String), BootstrapCommandError> {
    let digest = value
        .get("canonical_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BootstrapCommandError::UnknownPublication("draft digest missing".to_owned())
        })?
        .to_owned();
    let actual = content_digest(value)?;
    if actual != digest {
        return Err(BootstrapCommandError::DigestMismatch(
            "new draft digest does not match canonical content".to_owned(),
        ));
    }
    let directory = repo_root.join(DRAFT_DIRECTORY);
    fs::create_dir_all(&directory).map_err(|error| {
        BootstrapCommandError::UnknownPublication(format!("create evidence root: {error}"))
    })?;
    let destination = directory.join(format!("{digest}.json"));
    let mut bytes = canonical_json_bytes(value)
        .map_err(|error| BootstrapCommandError::UnknownPublication(error.to_string()))?;
    bytes.push(b'\n');
    if destination.exists() {
        let existing = fs::read(&destination).map_err(|error| {
            BootstrapCommandError::UnknownPublication(format!("read existing draft: {error}"))
        })?;
        verify_published_bytes(&existing, &bytes, &digest)?;
        return Ok((destination, digest));
    }
    let temporary = directory.join(format!(
        ".{digest}.{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            BootstrapCommandError::UnknownPublication(format!("create draft temp: {error}"))
        })?;
    let write_result = (|| -> io::Result<()> {
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(BootstrapCommandError::UnknownPublication(format!(
            "flush draft temp: {error}"
        )));
    }
    // A hard-link publishes the already-synced bytes without replacing an
    // existing destination on either Windows or Unix. `rename` is not a
    // no-clobber primitive on Unix.
    if let Err(error) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        if error.kind() == io::ErrorKind::AlreadyExists {
            let existing = fs::read(&destination).map_err(|read_error| {
                BootstrapCommandError::UnknownPublication(format!("read raced draft: {read_error}"))
            })?;
            verify_published_bytes(&existing, &bytes, &digest)?;
            return Ok((destination, digest));
        }
        return Err(BootstrapCommandError::UnknownPublication(format!(
            "publish draft: {error}"
        )));
    }
    fs::remove_file(&temporary).map_err(|error| {
        BootstrapCommandError::UnknownPublication(format!("remove published draft temp: {error}"))
    })?;
    let readback = fs::read(&destination).map_err(|error| {
        BootstrapCommandError::UnknownPublication(format!("readback draft: {error}"))
    })?;
    verify_published_bytes(&readback, &bytes, &digest)?;
    Ok((destination, digest))
}

fn verify_published_bytes(
    actual: &[u8],
    expected: &[u8],
    digest: &str,
) -> Result<(), BootstrapCommandError> {
    if actual != expected {
        return Err(BootstrapCommandError::DigestMismatch(format!(
            "existing draft {digest} differs from canonical bytes"
        )));
    }
    let parsed: Value = serde_json::from_slice(actual).map_err(|error| {
        BootstrapCommandError::DigestMismatch(format!("published draft JSON is invalid: {error}"))
    })?;
    let embedded = parsed
        .get("canonical_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BootstrapCommandError::DigestMismatch("published draft digest is missing".to_owned())
        })?;
    if embedded != digest || content_digest(&parsed)? != digest {
        return Err(BootstrapCommandError::DigestMismatch(
            "published draft content digest is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absolute(path: &Path, field: &str) -> Result<(), BootstrapCommandError> {
    if !path.is_absolute() {
        return Err(BootstrapCommandError::InvalidInput(format!(
            "{field} must be absolute"
        )));
    }
    Ok(())
}
