//! Live selected-source inputs joined to the original Git and Artifact owners.
//!
//! This module accepts only the non-Serde observation and capabilities minted
//! by the existing owners. It does not resolve a workspace from labels, open
//! the selected path itself, or convert a source Read admission into a write.

use std::path::Path;
use std::sync::Arc;

use eliot_artifact::ArtifactOwner;
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
}

/// Captures the exact current selected file in the original Git owner, then
/// reads the caller-supplied persisted full-tree artifact through the original
/// source Read admission and constructs the live LSP source proof.
///
/// `reference` must already be a real source artifact reference produced by a
/// separately admitted owner mutation. This function deliberately cannot
/// publish an artifact with the source Read admission.
pub(crate) async fn capture_selected_source_artifact_proof(
    owner: &SourceArtifactOwner,
    read_admission: &SourceArtifactAdmission,
    blob_profile: &SourceArtifactBlobProfile,
    reference: eliot_artifact::ArtifactReference,
    candidate: &SourceCandidate,
    selected: &BoundSelectedSourceObservation,
    root: RepoRoot,
    runner: Arc<dyn AsyncProcessRunner>,
) -> Result<SelectedSourceArtifactInputs, SelectedSourceArtifactInputError> {
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
        reference.identity.content.size_bytes.max(1),
        selected_relative_path,
        &selected.source_bytes,
    )
    .await?;

    let artifact_owner = ArtifactOwner::new(snapshot.max_archive_bytes())?;
    let (verified_artifact, read_receipt) = owner
        .read_source_reference(read_admission, blob_profile, reference.clone())
        .await?;
    let source_proof = LspSourceArtifactProof::from_owner_readback(
        &artifact_owner,
        snapshot,
        reference,
        verified_artifact,
        read_receipt,
        candidate,
    )?;

    Ok(SelectedSourceArtifactInputs {
        source_proof,
        root,
        runner,
    })
}
