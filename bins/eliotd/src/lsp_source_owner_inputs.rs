//! Live selected-source inputs joined to the original Git and Artifact owners.
//!
//! This module accepts only the non-Serde observation and capabilities minted
//! by the existing owners. It does not resolve a workspace from labels, open
//! the selected path itself, or convert a source Read admission into a write.

use std::future;
use std::path::Path;

use eliot_artifact::{ArtifactError, ArtifactIdentity, ArtifactOwner, ArtifactReference};
use eliot_contracts::{ClockReading, SourceId};
use eliot_git_bridge::{
    AsyncProcessRunner, GitProcessProfile, GitProcessRunError, GitProcessRunFuture,
    GitSnapshotError, RepoRoot,
};
use eliot_governor::{SourceArtifactAdmission, SourceArtifactBlobProfile};
use eliot_lsp_bridge::{BridgeError, LspSourceArtifactProof, SourceCandidate};
use thiserror::Error;

use crate::source_artifact_owner::{
    SourceArtifactOwner, SourceArtifactOwnerError, SourceArtifactStagingTarget,
};
use crate::task_binding_admission::BoundSelectedSourceObservation;
use eliot_instrument_runner::GitSourceSnapshotCommand;

/// Concrete source-capture-only port supplied by the daemon composition.
/// Implementations assemble the original per-command Instrument/GrantGraph
/// and P-03 admission before awaiting Kernel transport; this port carries no
/// generic process authority.
pub(crate) trait CurrentSourceGitSnapshotProcessOwner: Send + Sync {
    fn execute_current_source_git_command<'a>(
        &'a self,
        command: GitSourceSnapshotCommand,
        cwd: &'a Path,
        isolated_index_file: &'a Path,
    ) -> GitProcessRunFuture<'a>;
}

/// Existing Git bridge adapter restricted to its finite source-snapshot
/// commands and the operation-owned isolated index.
pub(crate) struct CurrentSourceGitRunner<'owner> {
    owner: &'owner dyn CurrentSourceGitSnapshotProcessOwner,
}

impl<'owner> CurrentSourceGitRunner<'owner> {
    pub(crate) const fn new(owner: &'owner dyn CurrentSourceGitSnapshotProcessOwner) -> Self {
        Self { owner }
    }
}

impl AsyncProcessRunner for CurrentSourceGitRunner<'_> {
    fn run_profiled<'a>(
        &'a self,
        exe: &'a str,
        args: &'a [&'a str],
        cwd: &'a Path,
        stdin: &'a [u8],
        profile: &'a GitProcessProfile,
    ) -> GitProcessRunFuture<'a> {
        let rejected = |code: &'static str, detail: &'static str| {
            Box::pin(future::ready(Err(GitProcessRunError {
                code: code.to_owned(),
                detail: detail.to_owned(),
            }))) as GitProcessRunFuture<'a>
        };
        if exe != "git" {
            return rejected(
                "SOURCE_GIT_EXECUTABLE_REFUSED",
                "source capture accepts only the admitted Git executable",
            );
        }
        if !stdin.is_empty() {
            return rejected(
                "SOURCE_GIT_STDIN_REFUSED",
                "P-03 source capture has no stdin channel",
            );
        }
        if !cwd.is_absolute() {
            return rejected(
                "SOURCE_GIT_CWD_REFUSED",
                "source capture requires the original absolute repository root",
            );
        }
        let Some(isolated_index_file) = profile.index_file() else {
            return rejected(
                "SOURCE_GIT_INDEX_REFUSED",
                "source capture requires its operation-owned isolated Git index",
            );
        };
        if !isolated_index_file.is_absolute() {
            return rejected(
                "SOURCE_GIT_INDEX_REFUSED",
                "source capture requires an absolute operation-owned Git index",
            );
        }
        let Ok(command) = source_snapshot_command(args) else {
            return rejected(
                "SOURCE_GIT_COMMAND_REFUSED",
                "Git argv is outside the finite current-source snapshot profile",
            );
        };
        self.owner
            .execute_current_source_git_command(command, cwd, isolated_index_file)
    }
}

fn source_snapshot_command(
    args: &[&str],
) -> Result<GitSourceSnapshotCommand, eliot_instrument_runner::GitSourceSnapshotProfileError> {
    let command = match args {
        ["rev-parse", "--show-toplevel"] => GitSourceSnapshotCommand::ResolveRoot,
        ["read-tree", "HEAD"] => GitSourceSnapshotCommand::InitializeIndex,
        ["add", "--all", "--force"] => GitSourceSnapshotCommand::CaptureOverlay,
        ["write-tree"] => GitSourceSnapshotCommand::WriteTree,
        ["ls-tree", "-r", "-z", tree_id] => {
            GitSourceSnapshotCommand::EnumerateTree((*tree_id).to_owned())
        }
        ["cat-file", "blob", blob_id] => GitSourceSnapshotCommand::ReadBlob((*blob_id).to_owned()),
        ["archive", "--format=tar", tree_id] => {
            GitSourceSnapshotCommand::ArchiveTree((*tree_id).to_owned())
        }
        _ => {
            return Err(
                eliot_instrument_runner::GitSourceSnapshotProfileError::InvocationArgumentsMismatch,
            );
        }
    };
    if command
        .argv()?
        .iter()
        .map(String::as_str)
        .ne(args.iter().copied())
    {
        return Err(
            eliot_instrument_runner::GitSourceSnapshotProfileError::InvocationArgumentsMismatch,
        );
    }
    Ok(command)
}

/// Live, non-Serde proof and its original process capability for one selected
/// source. The daemon caller must keep its original WorkScope, task/fence,
/// operation, and Instrument admission beside this carrier for the full call.
pub(crate) struct SelectedSourceArtifactInputs<'runner> {
    pub(crate) source_proof: LspSourceArtifactProof,
    pub(crate) root: RepoRoot,
    pub(crate) runner: &'runner dyn AsyncProcessRunner,
}

/// Exact owner-captured source snapshot retained while the caller obtains a
/// distinct mutation admission for its content digest.
pub(crate) struct ObservedSelectedSourceSnapshot<'runner> {
    snapshot: eliot_git_bridge::SourceTreeSnapshot,
    archive_sha256: String,
    source_id: SourceId,
    captured_at: ClockReading,
    candidate: SourceCandidate,
    root: RepoRoot,
    runner: &'runner dyn AsyncProcessRunner,
}

impl ObservedSelectedSourceSnapshot<'_> {
    /// SHA-256 of the exact bytes retained in this non-Serde snapshot.
    pub(crate) fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    /// Size of the exact bytes retained in this non-Serde snapshot.
    pub(crate) fn archive_size_bytes(&self) -> u64 {
        self.snapshot.archive_bytes().len() as u64
    }

    /// Captured Git tree identity, supplemental to the exact archive digest.
    pub(crate) fn tree_id(&self) -> &str {
        self.snapshot.tree_id()
    }
}

/// Original-owner snapshot staging result held across admission of the
/// separate exact-reference Read. It cannot cross a serde boundary.
pub(crate) struct StagedSelectedSourceSnapshot<'runner> {
    snapshot: eliot_git_bridge::SourceTreeSnapshot,
    reference: ArtifactReference,
    candidate: SourceCandidate,
    root: RepoRoot,
    runner: &'runner dyn AsyncProcessRunner,
}

impl StagedSelectedSourceSnapshot<'_> {
    /// Exact reference minted by the original Blob owner, needed to admit the
    /// separate resource-specific source Read.
    pub(crate) fn artifact_reference(&self) -> &ArtifactReference {
        &self.reference
    }
}

/// Derives the real prospective S-04 target from the exact retained archive
/// and a current Policy profile issued against the original selected-source
/// Read. The profile supplies policy data only; it does not authorize staging.
pub(crate) fn prepare_selected_source_staging_target(
    owner: &SourceArtifactOwner,
    source_read_profile: &SourceArtifactBlobProfile,
    observed: &ObservedSelectedSourceSnapshot,
) -> Result<SourceArtifactStagingTarget, SelectedSourceArtifactInputError> {
    Ok(owner.prepare_source_snapshot_target(
        source_read_profile,
        &observed.source_id,
        observed.snapshot.archive_bytes(),
    )?)
}

/// Failures while joining the current owner-observed source to its stored
/// source archive and original S-04 readback.
#[derive(Debug, Error)]
pub(crate) enum SelectedSourceArtifactInputError {
    #[error("selected-source binding does not match the retained candidate and root")]
    BindingMismatch,
    #[error("selected-source Git capture failed: {0}")]
    Git(#[from] GitSnapshotError),
    #[error("source artifact owner refused the original readback: {0}")]
    ArtifactOwner(#[from] SourceArtifactOwnerError),
    #[error("LSP source proof rejected the owner readback: {0}")]
    Bridge(#[from] BridgeError),
    #[error("artifact identity rejected the owner-bound snapshot: {0}")]
    Artifact(#[from] ArtifactError),
}

/// Captures the selected source snapshot once and retains its exact bytes
/// while the caller obtains the original ReversibleMutation admission bound
/// to this digest. The bytes are not reopened or recaptured before staging.
pub(crate) async fn capture_selected_source_snapshot<'runner>(
    max_archive_bytes: u64,
    source_id: SourceId,
    captured_at: ClockReading,
    candidate: &SourceCandidate,
    selected: &BoundSelectedSourceObservation,
    root: RepoRoot,
    runner: &'runner dyn AsyncProcessRunner,
) -> Result<ObservedSelectedSourceSnapshot<'runner>, SelectedSourceArtifactInputError> {
    if max_archive_bytes == 0 {
        return Err(SelectedSourceArtifactInputError::BindingMismatch);
    }
    let selected_relative_path = selected
        .canonical_candidate
        .strip_prefix(&selected.canonical_root)
        .map_err(|_| SelectedSourceArtifactInputError::BindingMismatch)?;
    let selected_relative_path = selected_relative_path
        .to_str()
        .ok_or(SelectedSourceArtifactInputError::BindingMismatch)?;

    if selected_relative_path.is_empty()
        || candidate.path.as_deref() != Some(selected_relative_path)
        || root.path() != selected.canonical_root
        || Path::new(&candidate.workspace_root) != root.path()
    {
        return Err(SelectedSourceArtifactInputError::BindingMismatch);
    }

    let snapshot = eliot_git_bridge::SourceTreeSnapshot::capture_current_async_for_selected_source(
        &root,
        runner.as_ref(),
        max_archive_bytes,
        selected_relative_path,
        &selected.source_bytes,
    )
    .await?;

    let archive_sha256 = eliot_contracts::sha256_hex(snapshot.archive_bytes());
    Ok(ObservedSelectedSourceSnapshot {
        snapshot,
        archive_sha256,
        source_id,
        captured_at,
        candidate: candidate.clone(),
        root,
        runner,
    })
}

/// Persists the already-captured exact tree bytes under a separate original
/// ReversibleMutation admission bound by the caller to `observed`'s digest.
/// This function never reopens the selected source or recaptures the tree.
pub(crate) fn stage_selected_source_snapshot<'runner>(
    owner: &SourceArtifactOwner,
    mutation_admission: &SourceArtifactAdmission,
    mutation_profile: &SourceArtifactBlobProfile,
    target: &SourceArtifactStagingTarget,
    observed: ObservedSelectedSourceSnapshot<'runner>,
) -> Result<StagedSelectedSourceSnapshot<'runner>, SelectedSourceArtifactInputError> {
    if mutation_admission.request().metadata.source_id != observed.source_id {
        return Err(SelectedSourceArtifactInputError::BindingMismatch);
    }
    let identity = ArtifactIdentity::bind_source_snapshot(
        &mutation_admission.operation().operation_id,
        observed.source_id.clone(),
        observed.snapshot.tree_id(),
        observed.snapshot.archive_bytes(),
        None,
        observed.captured_at.clone(),
    )?;
    let reference = owner.stage_source_snapshot_at_target(
        mutation_admission,
        mutation_profile,
        target,
        identity,
        observed.snapshot.archive_bytes(),
    )?;

    Ok(StagedSelectedSourceSnapshot {
        snapshot: observed.snapshot,
        reference,
        candidate: observed.candidate,
        root: observed.root,
        runner: observed.runner,
    })
}

/// Reads the exact reference produced by `stage_selected_source_snapshot`
/// under its independently admitted source Read and constructs the live LSP
/// proof. The caller creates this admission only after the ready receipt ID is
/// known; no Read authority is reused for staging.
pub(crate) async fn readback_selected_source_snapshot<'runner>(
    owner: &SourceArtifactOwner,
    read_admission: &SourceArtifactAdmission,
    read_profile: &SourceArtifactBlobProfile,
    staged: StagedSelectedSourceSnapshot<'runner>,
) -> Result<SelectedSourceArtifactInputs<'runner>, SelectedSourceArtifactInputError> {
    let artifact_owner = ArtifactOwner::new(staged.snapshot.max_archive_bytes())?;
    let (verified_artifact, read_receipt) = owner
        .read_source_reference(read_admission, read_profile, staged.reference.clone())
        .await?;
    let source_proof = LspSourceArtifactProof::from_owner_readback(
        &artifact_owner,
        staged.snapshot,
        staged.reference,
        verified_artifact,
        read_receipt,
        &staged.candidate,
    )?;

    Ok(SelectedSourceArtifactInputs {
        source_proof,
        root: staged.root,
        runner: staged.runner,
    })
}

#[cfg(test)]
mod source_git_runner_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct RefusedOwner;

    impl CurrentSourceGitSnapshotProcessOwner for RefusedOwner {
        fn execute_current_source_git_command<'a>(
            &'a self,
            _command: GitSourceSnapshotCommand,
            _cwd: &'a Path,
            _isolated_index_file: &'a Path,
        ) -> GitProcessRunFuture<'a> {
            panic!("invalid source Git input reached the original process owner")
        }
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn refusal(
        runner: &CurrentSourceGitRunner<'_>,
        exe: &str,
        args: &[&str],
        stdin: &[u8],
        profile: &GitProcessProfile,
    ) -> GitProcessRunError {
        let cwd = std::env::current_dir().expect("current directory is available");
        let mut future = runner.run_profiled(exe, args, &cwd, stdin, profile);
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(Err(error)) => error,
            Poll::Ready(Ok(_)) => panic!("invalid source Git input was accepted"),
            Poll::Pending => panic!("validation refusal must be immediately ready"),
        }
    }

    #[test]
    fn source_git_runner_maps_the_finite_snapshot_command() {
        assert_eq!(
            source_snapshot_command(&["cat-file", "blob", "a".repeat(40).as_str()])
                .expect("well-shaped blob command is admitted"),
            GitSourceSnapshotCommand::ReadBlob("a".repeat(40)),
        );
        assert!(source_snapshot_command(&["status", "--porcelain"]).is_err());
    }

    #[test]
    fn source_git_runner_refuses_generic_executable_stdin_and_missing_index() {
        let owner = RefusedOwner;
        let runner = CurrentSourceGitRunner::new(&owner);
        let inherited = GitProcessProfile::inherited();
        let args = ["rev-parse", "--show-toplevel"];

        assert_eq!(
            refusal(&runner, "powershell", &args, &[], &inherited).code,
            "SOURCE_GIT_EXECUTABLE_REFUSED"
        );
        assert_eq!(
            refusal(&runner, "git", &args, b"unexpected", &inherited).code,
            "SOURCE_GIT_STDIN_REFUSED"
        );
        assert_eq!(
            refusal(&runner, "git", &args, &[], &inherited).code,
            "SOURCE_GIT_INDEX_REFUSED"
        );
    }
}
