#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Issue 1948 acceptance: governed source readback before citation.

use eliot_context_assembly::{
    IndexPreview, PreviewAuthority, ProjectedCitation, ReadbackRefusalKind, ReadbackRequest,
    ReopenedSource, gate_citation, project_citation,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(
        test_epoch(),
        ResourceGeneration::new(1).expect("generation"),
    )
}

fn view() -> eliot_observation_contracts::SourceViewHandle {
    eliot_observation_contracts::SourceViewHandle {
        kind: eliot_observation_contracts::SourceViewKind::WorkingTreeCurrent,
        workspace_instance_id: "workspace-1".to_owned(),
        workspace_view_revision: "view-1".to_owned(),
        git_commit_oid: None,
        imported_snapshot_id: None,
        retained_revision_id: None,
    }
}

fn workspace_revision() -> eliot_observation_contracts::WorkspaceViewRevisionHandle {
    eliot_observation_contracts::WorkspaceViewRevisionHandle {
        workspace_instance_id: "workspace-1".to_owned(),
        view_revision: "view-1".to_owned(),
    }
}

fn admitted(bytes: &[u8]) -> eliot_observation_contracts::SourceRevisionHandle {
    eliot_observation_contracts::SourceRevisionHandle {
        source_id: "source-1".to_owned(),
        revision: "revision-1".to_owned(),
        content_sha256: sha256_hex(bytes),
        byte_length: u64::try_from(bytes.len()).expect("length"),
    }
}

fn anchor(
    bytes: &[u8],
    offset: usize,
    length: usize,
) -> eliot_observation_contracts::SourceAnchorHandle {
    let excerpt = &bytes[offset..offset + length];
    eliot_observation_contracts::SourceAnchorHandle {
        anchor_id: "anchor-1".to_owned(),
        byte_offset: u64::try_from(offset).expect("offset"),
        byte_length: u64::try_from(length).expect("length"),
        excerpt_sha256: sha256_hex(excerpt),
        native_mapping: None,
    }
}

fn request(
    admitted_bytes: &[u8],
    preview_bytes: &[u8],
    offset: usize,
    length: usize,
) -> ReadbackRequest {
    ReadbackRequest {
        admitted: admitted(admitted_bytes),
        view: view(),
        workspace_revision: workspace_revision(),
        fence: fence(),
        anchor: anchor(admitted_bytes, offset, length),
        preview: IndexPreview {
            bytes: preview_bytes.to_vec(),
            claimed_revision: "revision-1".to_owned(),
            authority: PreviewAuthority::NonAuthoritativePreview,
        },
    }
}

fn reopened(bytes: &[u8]) -> ReopenedSource {
    ReopenedSource {
        revision: admitted(bytes),
        view: view(),
        workspace_revision: workspace_revision(),
        fence: fence(),
        bytes: bytes.to_vec(),
    }
}

// WORK_UNIT_CASE: 1948/1
#[test]
fn index_preview_diverging_from_admitted_revision_is_never_cited() {
    let admitted_bytes = b"admitted revision bytes v1";
    let current_bytes = b"convenient current bytes v2";
    assert_ne!(sha256_hex(admitted_bytes), sha256_hex(current_bytes));
    let req = request(admitted_bytes, current_bytes, 0, 8);
    assert!(!req.preview.is_citable());
    // Governed owner serves the convenient current bytes instead of the
    // admitted revision: the gate must refuse with a typed outcome.
    let served = ReopenedSource {
        revision: admitted(current_bytes),
        view: view(),
        workspace_revision: workspace_revision(),
        fence: fence(),
        bytes: current_bytes.to_vec(),
    };
    let result = gate_citation(&req, &served);
    match result {
        Ok(citation) => panic!("preview bytes must never be cited, got {citation:?}"),
        Err(refusal) => {
            refusal.validate().expect("typed refusal");
            assert!(
                matches!(
                    refusal.kind,
                    ReadbackRefusalKind::Unsupported
                        | ReadbackRefusalKind::Replan
                        | ReadbackRefusalKind::Gap
                ),
                "typed unsupported/replan/gap, got {:?}",
                refusal.kind
            );
        }
    }
}

// WORK_UNIT_CASE: 1948/2
#[test]
fn matching_revision_with_valid_anchor_exposes_exact_handles() {
    let admitted_bytes = b"admitted revision bytes v1";
    let req = request(admitted_bytes, b"stale preview", 0, 8);
    let served = reopened(admitted_bytes);
    let citation = gate_citation(&req, &served).expect("valid readback cites");
    citation.validate().expect("citation validates");
    assert_eq!(citation.source_revision, req.admitted);
    assert_eq!(citation.anchor, req.anchor);
    assert_eq!(citation.view, req.view);
    assert_eq!(citation.workspace_revision, req.workspace_revision);
    assert_eq!(citation.excerpt_bytes, admitted_bytes[0..8].to_vec());
    assert_eq!(citation.excerpt_digest, req.anchor.excerpt_sha256);
}

// WORK_UNIT_CASE: 1948/3
#[test]
fn caller_never_projects_when_preview_diverges_from_admitted_revision() {
    let admitted_bytes = b"admitted revision bytes v1";
    let current_bytes = b"convenient current bytes v2";
    assert_ne!(sha256_hex(admitted_bytes), sha256_hex(current_bytes));
    let req = request(admitted_bytes, current_bytes, 0, 8);
    assert!(!req.preview.is_citable());
    // Governed owner serves the convenient current bytes instead of the
    // admitted revision: the caller must refuse without projecting.
    let served = ReopenedSource {
        revision: admitted(current_bytes),
        view: view(),
        workspace_revision: workspace_revision(),
        fence: fence(),
        bytes: current_bytes.to_vec(),
    };
    let projected = std::cell::Cell::new(false);
    let result = project_citation(&req, &served, |_| {
        projected.set(true);
    });
    match result {
        Ok(citation) => panic!("preview bytes must never be cited, got {citation:?}"),
        Err(refusal) => {
            refusal.validate().expect("typed refusal");
            assert!(
                matches!(
                    refusal.kind,
                    ReadbackRefusalKind::Unsupported
                        | ReadbackRefusalKind::Replan
                        | ReadbackRefusalKind::Gap
                ),
                "typed unsupported/replan/gap, got {:?}",
                refusal.kind
            );
            let rendered = format!("{refusal:?}");
            assert!(
                !rendered.contains("convenient current bytes"),
                "refusal must not emit current bytes, got {rendered}"
            );
        }
    }
    assert!(!projected.get(), "projection must not run on refusal");
}

// WORK_UNIT_CASE: 1948/4
#[test]
fn caller_projects_exact_handles_on_valid_readback() {
    let admitted_bytes = b"admitted revision bytes v1";
    let req = request(admitted_bytes, b"stale preview", 0, 8);
    let served = reopened(admitted_bytes);
    let seen = std::cell::RefCell::<Option<ProjectedCitation>>::new(None);
    let citation = project_citation(&req, &served, |cited| {
        seen.replace(Some(cited.clone()));
    })
    .expect("valid readback cites");
    citation.validate().expect("citation validates");
    let seen = seen.borrow().clone().expect("projection ran once");
    assert_eq!(seen, citation);
    assert_eq!(citation.source_revision, req.admitted);
    assert_eq!(citation.anchor, req.anchor);
    assert_eq!(citation.view, req.view);
    assert_eq!(citation.workspace_revision, req.workspace_revision);
    assert_eq!(citation.excerpt_bytes, admitted_bytes[0..8].to_vec());
    assert_eq!(citation.excerpt_digest, req.anchor.excerpt_sha256);
}
