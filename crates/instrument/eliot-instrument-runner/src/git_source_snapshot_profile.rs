//! Closed Git command projection for a selected-source snapshot.
//!
//! This module creates no process authority. It joins one typed Git operation
//! to the current Instrument and Provider registries, then checks that the
//! original environment owner’s executable observation and inert
//! `ProcessIntent` describe exactly that operation. Governor remains the only
//! owner that issues the ActionLease; Kernel/P-03 remains the only process
//! execution owner.

use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_process::{
    EnvironmentProjection, ProcessExecutionAdmissionRequest, ProcessIntent,
};
use eliot_receipts::EffectClass;
use std::path::Path;
use thiserror::Error;

use crate::profile::{InstrumentClass, InstrumentRegistry, InstrumentSpec, ResourceLimits};
use crate::registry::{
    GIT_SOURCE_ARCHIVE_TREE_INSTRUMENT, GIT_SOURCE_CAPTURE_OVERLAY_INSTRUMENT,
    GIT_SOURCE_ENUMERATE_TREE_INSTRUMENT, GIT_SOURCE_INITIALIZE_INDEX_INSTRUMENT,
    GIT_SOURCE_READ_BLOB_INSTRUMENT, GIT_SOURCE_RESOLVE_ROOT_INSTRUMENT,
    GIT_SOURCE_SNAPSHOT_PROFILE, GIT_SOURCE_WRITE_TREE_INSTRUMENT, ProviderRegistry,
    RegistryEntry, RegistryError, RegistryFreshness, ResolvedExecutableIdentity,
};

/// One finite Git command used to capture the current selected-source tree.
/// Object IDs are values returned by prior admitted Git operations and are
/// validated before they can enter argv.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitSourceSnapshotCommand {
    /// Resolve the selected working directory to its canonical repository root.
    ResolveRoot,
    /// Initialize the operation-owned isolated index from `HEAD`.
    InitializeIndex,
    /// Stage the current tracked and untracked overlay into that isolated index.
    CaptureOverlay,
    /// Write the captured index tree and return its object ID.
    WriteTree,
    /// Enumerate every tree entry for the returned tree object ID.
    EnumerateTree(String),
    /// Read the exact blob object returned by the enumerated tree.
    ReadBlob(String),
    /// Archive the exact tree object whose blobs were independently read.
    ArchiveTree(String),
}

impl GitSourceSnapshotCommand {
    /// Exact existing process-spawn/index-operation effect admitted by the
    /// owner’s GrantGraph. Source-artifact publication has its own separate
    /// `ReversibleMutation` admission.
    #[must_use]
    pub const fn effect(&self) -> EffectClass {
        EffectClass::ExternalEffect
    }

    /// Binds the existing Git bridge argv to the original admitted
    /// operation-specific InstrumentInvocation. Only one exact finite argv
    /// shape is accepted for that invocation identity.
    pub fn from_invocation(
        invocation: &InstrumentInvocation,
        argv: &[String],
    ) -> Result<Self, GitSourceSnapshotProfileError> {
        let command = match invocation.instrument.as_str() {
            GIT_SOURCE_RESOLVE_ROOT_INSTRUMENT => Self::ResolveRoot,
            GIT_SOURCE_INITIALIZE_INDEX_INSTRUMENT => Self::InitializeIndex,
            GIT_SOURCE_CAPTURE_OVERLAY_INSTRUMENT => Self::CaptureOverlay,
            GIT_SOURCE_WRITE_TREE_INSTRUMENT => Self::WriteTree,
            GIT_SOURCE_ENUMERATE_TREE_INSTRUMENT => {
                Self::EnumerateTree(terminal_operand(argv)?.to_owned())
            }
            GIT_SOURCE_READ_BLOB_INSTRUMENT => {
                Self::ReadBlob(terminal_operand(argv)?.to_owned())
            }
            GIT_SOURCE_ARCHIVE_TREE_INSTRUMENT => {
                Self::ArchiveTree(terminal_operand(argv)?.to_owned())
            }
            _ => return Err(GitSourceSnapshotProfileError::InvocationMismatch),
        };
        if command.argv()? != argv {
            return Err(GitSourceSnapshotProfileError::InvocationArgumentsMismatch);
        }
        Ok(command)
    }

    /// Original closed Instrument/GrantGraph identity for this command.
    #[must_use]
    pub const fn instrument_id(&self) -> &'static str {
        match self {
            Self::ResolveRoot => GIT_SOURCE_RESOLVE_ROOT_INSTRUMENT,
            Self::InitializeIndex => GIT_SOURCE_INITIALIZE_INDEX_INSTRUMENT,
            Self::CaptureOverlay => GIT_SOURCE_CAPTURE_OVERLAY_INSTRUMENT,
            Self::WriteTree => GIT_SOURCE_WRITE_TREE_INSTRUMENT,
            Self::EnumerateTree(_) => GIT_SOURCE_ENUMERATE_TREE_INSTRUMENT,
            Self::ReadBlob(_) => GIT_SOURCE_READ_BLOB_INSTRUMENT,
            Self::ArchiveTree(_) => GIT_SOURCE_ARCHIVE_TREE_INSTRUMENT,
        }
    }

    /// Fixed admitted command prefix for the exact instrument operation.
    #[must_use]
    pub fn admitted_prefix(&self) -> Vec<String> {
        match self {
            Self::ResolveRoot => vec!["rev-parse".to_owned(), "--show-toplevel".to_owned()],
            Self::InitializeIndex => vec!["read-tree".to_owned(), "HEAD".to_owned()],
            Self::CaptureOverlay => vec![
                "add".to_owned(),
                "--all".to_owned(),
                "--force".to_owned(),
            ],
            Self::WriteTree => vec!["write-tree".to_owned()],
            Self::EnumerateTree(_) => {
                vec!["ls-tree".to_owned(), "-r".to_owned(), "-z".to_owned()]
            }
            Self::ReadBlob(_) => vec!["cat-file".to_owned(), "blob".to_owned()],
            Self::ArchiveTree(_) => {
                vec!["archive".to_owned(), "--format=tar".to_owned()]
            }
        }
    }

    /// Renders only the bridge’s fixed Git argument shapes.
    pub fn argv(&self) -> Result<Vec<String>, GitSourceSnapshotProfileError> {
        let mut arguments = self.admitted_prefix();
        match self {
            Self::ResolveRoot
            | Self::InitializeIndex
            | Self::CaptureOverlay
            | Self::WriteTree => {}
            Self::EnumerateTree(tree_id) => {
                validate_object_id(tree_id)?;
                arguments.push(tree_id.clone());
            }
            Self::ReadBlob(blob_id) => {
                validate_object_id(blob_id)?;
                arguments.push(blob_id.clone());
            }
            Self::ArchiveTree(tree_id) => {
                validate_object_id(tree_id)?;
                arguments.push(tree_id.clone());
            }
        }
        Ok(arguments)
    }
}

/// Non-Serde proposal that retains the exact owner-produced process material
/// while Governor evaluates its original action contract. It is not a lease,
/// permission, or reusable launch token.
pub struct GitSourceSnapshotProcessProfile<'a> {
    pub command: GitSourceSnapshotCommand,
    pub argv: Vec<String>,
    pub spec: &'a InstrumentSpec,
    pub provider: &'a RegistryEntry,
    pub resolved_executable: &'a ResolvedExecutableIdentity,
    pub intent: &'a ProcessIntent,
    /// Canonical selected root supplied by the original `RepoRoot` owner.
    pub canonical_working_directory: &'a str,
    pub environment: &'a EnvironmentProjection,
    /// Existing Governor/P-03 effect class for the process spawn and isolated
    /// Git-index command. Artifact publication is a separate admission.
    pub effect: EffectClass,
    /// Exact owner-provided resources Governor must bind to the original
    /// ActionContract and GrantGraph lease.
    pub resource_targets: GitSourceSnapshotResourceTargets<'a>,
    /// The effective stdout ceiling: the tighter of admitted Instrument and
    /// original ProcessIntent bounds. This is the source archive capture cap.
    pub stdout_ceiling_bytes: u64,
    pub instrument_limits: ResourceLimits,
}

/// Exact process resources retained for original Governor authorization.
/// This value is not itself a permission or a textual resource-reference
/// selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitSourceSnapshotResourceTargets<'a> {
    /// Executable file currently resolved by the original executable owner.
    pub executable_path: &'a str,
    /// Canonical selected-worktree root used as the process working directory.
    pub source_root: &'a str,
    /// Isolated index file owned by the current Git snapshot capture.
    pub isolated_index_file: &'a str,
}

/// Fail-closed refusal while preparing or completing one finite Git process
/// profile.
#[derive(Debug, Error)]
pub enum GitSourceSnapshotProfileError {
    /// Invocation does not select the admitted Git source-snapshot contract.
    #[error("invocation does not select the admitted Git source-snapshot profile")]
    InvocationMismatch,
    /// Existing bridge argv disagrees with its original operation identity.
    #[error("Git bridge argv does not match the original admitted operation identity")]
    InvocationArgumentsMismatch,
    /// Instrument spec does not describe the Git executable and inspect class.
    #[error("instrument spec does not match the admitted Git source-snapshot process")]
    SpecMismatch,
    /// Resolved executable, process intent, environment, or argv drifted.
    #[error("owner-produced Git executable or process intent does not match the typed operation")]
    IntentMismatch,
    /// Original temporary index target is absent or differs from its process environment binding.
    #[error("isolated Git index resource target is not bound to the original process environment")]
    ResourceTargetMismatch,
    /// Tree/blob object identity is not a complete lowercase SHA-1 or SHA-256 ID.
    #[error("Git object ID must be 40 or 64 lowercase hexadecimal characters")]
    InvalidObjectId,
    /// Final P-03 request changed the exact intent after Governor admission.
    #[error("P-03 admission differs from the retained Git process profile")]
    AdmissionMismatch,
    /// Provider currentness or executable binding refused.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Resolves a typed Git source-snapshot command against the caller’s original
/// current registries, executable observation, environment projection and
/// Governor-bound inert `ProcessIntent`.
///
/// Call this before lease issuance with the original `ProcessIntent`; after
/// Governor returns the ActionLease and Kernel seals the P-03 request, call
/// [`validate_git_source_snapshot_admission`] on the same retained proposal.
/// `isolated_index_file` must come directly from the bridge's current
/// operation-owned `GitProcessProfile::index_file()` and match the process
/// EnvironmentProjection.
pub fn prepare_current_git_source_snapshot_profile<'a>(
    profiles: &'a InstrumentRegistry,
    providers: &'a ProviderRegistry,
    invocation: &'a InstrumentInvocation,
    freshness: &RegistryFreshness<'_>,
    resolved_executable: &'a ResolvedExecutableIdentity,
    command: GitSourceSnapshotCommand,
    intent: &'a ProcessIntent,
    canonical_working_directory: &'a str,
    isolated_index_file: &'a Path,
    environment: &'a EnvironmentProjection,
) -> Result<GitSourceSnapshotProcessProfile<'a>, GitSourceSnapshotProfileError> {
    if invocation.instrument.as_str() != command.instrument_id()
        || invocation.kind != InstrumentKind::Inspect
        || invocation.profile != GIT_SOURCE_SNAPSHOT_PROFILE
        || !invocation.arguments.is_empty()
    {
        return Err(GitSourceSnapshotProfileError::InvocationMismatch);
    }

    let spec = profiles
        .spec(command.instrument_id())
        .ok_or(GitSourceSnapshotProfileError::SpecMismatch)?;
    if spec.kind.as_str() != command.instrument_id()
        || spec.class != InstrumentClass::SourceIdentity
        || spec.executable != "git"
        || spec.argument_template.len() != 0
        || spec.verification_command != command.admitted_prefix()
    {
        return Err(GitSourceSnapshotProfileError::SpecMismatch);
    }
    let provider = providers.resolve_current(invocation, freshness)?;
    if provider.adapter != GIT_SOURCE_SNAPSHOT_PROFILE {
        return Err(GitSourceSnapshotProfileError::InvocationMismatch);
    }
    provider.check_resolved_executable(Some(resolved_executable))?;

    let index_file = validate_isolated_index_binding(isolated_index_file, environment)?;
    let argv = command.argv()?;
    if !resolved_executable.binds_argv(&argv)
        || intent.argv() != argv
        || intent.executable() != resolved_executable.canonical_path.as_str()
        || intent.executable_sha256() != resolved_executable.content_digest.as_str()
        || intent.working_directory() != canonical_working_directory
        || intent.environment() != environment
        || environment
            .non_secret()
            .get("GIT_INDEX_FILE")
            .map(String::as_str)
            != Some(index_file)
    {
        return Err(GitSourceSnapshotProfileError::IntentMismatch);
    }
    let process_stdout_ceiling = intent.resource_limits().stdout_bytes();
    let stdout_ceiling_bytes = spec
        .limits
        .max_output_bytes
        .map_or(process_stdout_ceiling, |instrument| {
            instrument.min(process_stdout_ceiling)
        });
    if stdout_ceiling_bytes == 0 {
        return Err(GitSourceSnapshotProfileError::IntentMismatch);
    }
    let effect = command.effect();

    Ok(GitSourceSnapshotProcessProfile {
        command,
        argv,
        spec,
        provider,
        resolved_executable,
        intent,
        canonical_working_directory,
        environment,
        effect,
        resource_targets: GitSourceSnapshotResourceTargets {
            executable_path: &resolved_executable.canonical_path,
            source_root: canonical_working_directory,
            isolated_index_file: index_file,
        },
        stdout_ceiling_bytes,
        instrument_limits: spec.limits,
    })
}

/// Checks the original action-leased P-03 request against the exact intent and
/// environment retained before Governor issued its lease.
pub fn validate_git_source_snapshot_admission(
    profile: &GitSourceSnapshotProcessProfile<'_>,
    admission: &ProcessExecutionAdmissionRequest,
) -> Result<(), GitSourceSnapshotProfileError> {
    admission
        .validate()
        .map_err(|_| GitSourceSnapshotProfileError::AdmissionMismatch)?;
    let intent = admission.intent();
    if intent != profile.intent
        || intent.argv() != profile.argv
        || intent.environment() != profile.environment
        || intent.executable() != profile.resolved_executable.canonical_path.as_str()
        || intent.executable_sha256() != profile.resolved_executable.content_digest.as_str()
        || intent.working_directory() != profile.canonical_working_directory
        || profile.resource_targets.executable_path
            != profile.resolved_executable.canonical_path.as_str()
        || profile.resource_targets.source_root != profile.canonical_working_directory
        || profile
            .environment
            .non_secret()
            .get("GIT_INDEX_FILE")
            .map(String::as_str)
            != Some(profile.resource_targets.isolated_index_file)
        || !profile.resolved_executable.binds_argv(intent.argv())
    {
        return Err(GitSourceSnapshotProfileError::AdmissionMismatch);
    }
    Ok(())
}

fn validate_isolated_index_binding<'a>(
    isolated_index_file: &'a Path,
    environment: &'a EnvironmentProjection,
) -> Result<&'a str, GitSourceSnapshotProfileError> {
    let index_file = isolated_index_file
        .to_str()
        .filter(|path| !path.is_empty() && isolated_index_file.is_absolute())
        .ok_or(GitSourceSnapshotProfileError::ResourceTargetMismatch)?;
    let environment_index = environment
        .non_secret()
        .get("GIT_INDEX_FILE")
        .ok_or(GitSourceSnapshotProfileError::ResourceTargetMismatch)?;
    if environment_index != index_file {
        return Err(GitSourceSnapshotProfileError::ResourceTargetMismatch);
    }
    Ok(index_file)
}

fn validate_object_id(value: &str) -> Result<(), GitSourceSnapshotProfileError> {
    if matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(GitSourceSnapshotProfileError::InvalidObjectId)
    }
}

fn terminal_operand(argv: &[String]) -> Result<&str, GitSourceSnapshotProfileError> {
    argv.last()
        .map(String::as_str)
        .ok_or(GitSourceSnapshotProfileError::InvocationArgumentsMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use std::num::NonZeroU64;

    fn invocation(instrument: &str) -> InstrumentInvocation {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("valid lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero sequence"));
        let clock = ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        InstrumentInvocation {
            request: RequestMetadata {
                request_id: RequestId::new("git-profile-request").expect("request id"),
                session_id: None,
                task_id: None,
                product_id: ProductId::new("eliotd").expect("product id"),
                source_id: SourceId::new("selected-source").expect("source id"),
                state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
                clock,
            },
            instrument: eliot_contracts::ContractId::new(instrument).expect("instrument id"),
            kind: InstrumentKind::Inspect,
            profile: GIT_SOURCE_SNAPSHOT_PROFILE.to_owned(),
            target: "selected-worktree".to_owned(),
            arguments: Vec::new(),
            input_artifacts: Vec::new(),
            declared_scope: "selected-source".to_owned(),
            requested_at: clock,
        }
    }

    #[test]
    fn finite_command_profiles_bind_exact_operation_ids_and_argv() {
        let cases = [
            (
                GIT_SOURCE_RESOLVE_ROOT_INSTRUMENT,
                GitSourceSnapshotCommand::ResolveRoot,
                vec!["rev-parse".to_owned(), "--show-toplevel".to_owned()],
            ),
            (
                GIT_SOURCE_INITIALIZE_INDEX_INSTRUMENT,
                GitSourceSnapshotCommand::InitializeIndex,
                vec!["read-tree".to_owned(), "HEAD".to_owned()],
            ),
            (
                GIT_SOURCE_CAPTURE_OVERLAY_INSTRUMENT,
                GitSourceSnapshotCommand::CaptureOverlay,
                vec!["add".to_owned(), "--all".to_owned(), "--force".to_owned()],
            ),
            (
                GIT_SOURCE_WRITE_TREE_INSTRUMENT,
                GitSourceSnapshotCommand::WriteTree,
                vec!["write-tree".to_owned()],
            ),
            (
                GIT_SOURCE_ENUMERATE_TREE_INSTRUMENT,
                GitSourceSnapshotCommand::EnumerateTree("0123456789abcdef0123456789abcdef01234567".to_owned()),
                vec![
                    "ls-tree".to_owned(),
                    "-r".to_owned(),
                    "-z".to_owned(),
                    "0123456789abcdef0123456789abcdef01234567".to_owned(),
                ],
            ),
            (
                GIT_SOURCE_READ_BLOB_INSTRUMENT,
                GitSourceSnapshotCommand::ReadBlob("0123456789abcdef0123456789abcdef01234567".to_owned()),
                vec![
                    "cat-file".to_owned(),
                    "blob".to_owned(),
                    "0123456789abcdef0123456789abcdef01234567".to_owned(),
                ],
            ),
            (
                GIT_SOURCE_ARCHIVE_TREE_INSTRUMENT,
                GitSourceSnapshotCommand::ArchiveTree("0123456789abcdef0123456789abcdef01234567".to_owned()),
                vec![
                    "archive".to_owned(),
                    "--format=tar".to_owned(),
                    "0123456789abcdef0123456789abcdef01234567".to_owned(),
                ],
            ),
        ];

        for (instrument_id, expected, argv) in cases {
            let invocation = invocation(instrument_id);
            let bound = GitSourceSnapshotCommand::from_invocation(&invocation, &argv)
                .expect("closed command binds to its original instrument identity");
            assert_eq!(bound, expected);
            assert_eq!(bound.instrument_id(), instrument_id);
            assert_eq!(bound.argv().expect("admitted argv"), argv);
            assert_eq!(bound.effect(), EffectClass::ExternalEffect);
        }
    }

    #[test]
    fn command_profile_refuses_wrong_operation_and_malformed_object_id() {
        let wrong_operation = invocation(GIT_SOURCE_WRITE_TREE_INSTRUMENT);
        assert!(matches!(
            GitSourceSnapshotCommand::from_invocation(
                &wrong_operation,
                &["archive".to_owned(), "--format=tar".to_owned()]
            ),
            Err(GitSourceSnapshotProfileError::InvocationArgumentsMismatch)
        ));

        let wrong_object = GitSourceSnapshotCommand::ArchiveTree("not-an-object-id".to_owned());
        assert!(matches!(
            wrong_object.argv(),
            Err(GitSourceSnapshotProfileError::InvalidObjectId)
        ));
    }

    #[test]
    fn isolated_index_resource_requires_exact_original_environment_binding() {
        let environment = EnvironmentProjection::new(
            BTreeMap::from([("GIT_INDEX_FILE".to_owned(), "/tmp/eliot/index".to_owned())]),
            Vec::new(),
            EnvironmentInheritance::None,
        )
        .expect("environment");
        assert_eq!(
            validate_isolated_index_binding(Path::new("/tmp/eliot/index"), &environment)
                .expect("exact owner-bound index"),
            "/tmp/eliot/index"
        );
        assert!(matches!(
            validate_isolated_index_binding(Path::new("/tmp/eliot/other-index"), &environment),
            Err(GitSourceSnapshotProfileError::ResourceTargetMismatch)
        ));
        assert!(matches!(
            validate_isolated_index_binding(Path::new("relative-index"), &environment),
            Err(GitSourceSnapshotProfileError::ResourceTargetMismatch)
        ));
    }
}
