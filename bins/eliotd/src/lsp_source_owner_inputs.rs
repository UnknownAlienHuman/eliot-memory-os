//! Live selected-source inputs joined to the original Git and Artifact owners.
//!
//! This module accepts only the non-Serde observation and capabilities minted
//! by the existing owners. It does not resolve a workspace from labels, open
//! the selected path itself, or convert a source Read admission into a write.

use std::path::Path;
use std::sync::Arc;

use eliot_artifact::{ArtifactError, ArtifactIdentity, ArtifactOwner, ArtifactReference};
use eliot_contracts::{ClockReading, SourceId};
use eliot_governor::{SourceArtifactAdmission, SourceArtifactBlobProfile};
use eliot_git_bridge::{AsyncProcessRunner, GitSnapshotError, RepoRoot};
use eliot_lsp_bridge::{BridgeError, LspSourceArtifactProof, SourceCandidate};
use thiserror::Error;

use crate::source_artifact_owner::{SourceArtifactOwner, SourceArtifactOwnerError};
use crate::task_binding_admission::BoundSelectedSourceObservation;

/// Live, non-Serde proof and its original process capability for one selected
/// source. The daemon caller must keep its original WorkScope, task/fence,
/// operation, and Instrument admission beside this carrier for the full call.
pub(crate) struct SelectedSourceArtifactInputs {
    pub(crate) source_proof: LspSourceArtifactProof,
    pub(crate) root: RepoRoot,
    pub(crate) runner: Arc<dyn AsyncProcessRunner>,
}

/// Original-owner snapshot staging result held across admission of the
/// separate exact-reference Read. It cannot cross a serde boundary.
pub(crate) struct StagedSelectedSourceSnapshot {
    snapshot: eliot_git_bridge::SourceTreeSnapshot,
    reference: ArtifactReference,
    candidate: SourceCandidate,
    root: RepoRoot,
    runner: Arc<dyn AsyncProcessRunner>,
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

/// Captures and publishes the selected source tree under its own original
/// ReversibleMutation admission. A later caller must obtain a distinct Read
/// admission bound to the returned ArtifactReference before readback.
pub(crate) async fn stage_selected_source_snapshot(
    owner: &SourceArtifactOwner,
    mutation_admission: &SourceArtifactAdmission,
    mutation_profile: &SourceArtifactBlobProfile,
    max_archive_bytes: u64,
    source_id: SourceId,
    captured_at: ClockReading,
    candidate: &SourceCandidate,
    selected: &BoundSelectedSourceObservation,
    root: RepoRoot,
    runner: Arc<dyn AsyncProcessRunner>,
) -> Result<StagedSelectedSourceSnapshot, SelectedSourceArtifactInputError> {
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

    let identity = ArtifactIdentity::bind_source_snapshot(
        &mutation_admission.operation().operation_id,
        source_id,
        snapshot.tree_id(),
        snapshot.archive_bytes(),
        None,
        captured_at,
    )?;
    let reference = owner.stage_source_snapshot(
        mutation_admission,
        mutation_profile,
        identity,
        snapshot.archive_bytes(),
    )?;

    Ok(StagedSelectedSourceSnapshot {
        snapshot,
        reference,
        candidate: candidate.clone(),
        root,
        runner,
    })
}

/// Reads the exact reference produced by `stage_selected_source_snapshot`
/// under its independently admitted source Read and constructs the live LSP
/// proof. The caller creates this admission only after the ready receipt ID is
/// known; no Read authority is reused for staging.
pub(crate) async fn readback_selected_source_snapshot(
    owner: &SourceArtifactOwner,
    read_admission: &SourceArtifactAdmission,
    read_profile: &SourceArtifactBlobProfile,
    staged: StagedSelectedSourceSnapshot,
) -> Result<SelectedSourceArtifactInputs, SelectedSourceArtifactInputError> {
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
