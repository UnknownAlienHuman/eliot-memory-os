//! Governed citation caller: projection runs only on verified readback bytes.
//!
//! I12.26 requires governed source readback before a retrieved candidate is
//! projected or cited: the exact admitted source revision is reopened under
//! the same source view, workspace-view revision and state fence; digest and
//! byte length are verified; the anchor is resolved through exact coordinates
//! or native mapping; and the excerpt digest is verified. Index and vector
//! payloads stay non-authoritative previews and are never cited. A missing
//! revision, mapping or digest yields a narrower typed unsupported, replan or
//! gap outcome, never a citation to convenient current bytes. This caller
//! authorizes no durable mutation.

use eliot_context_contracts::{ProjectedCitation, ReadbackRefusal, ReadbackRequest};

use crate::readback::{ReopenedSource, gate_citation};

/// Project one citation only after governed source readback succeeds.
///
/// Runs [`gate_citation`] on the caller-supplied request and reopened bytes,
/// then invokes `project` exactly once with the verified citation. When
/// readback refuses, `project` is never invoked and the typed refusal is
/// returned instead, so neither index-preview bytes nor unverified current
/// bytes can appear as cited support.
pub fn project_citation<F>(
    request: &ReadbackRequest,
    reopened: &ReopenedSource,
    project: F,
) -> Result<ProjectedCitation, ReadbackRefusal>
where
    F: FnOnce(&ProjectedCitation),
{
    let citation = gate_citation(request, reopened)?;
    project(&citation);
    Ok(citation)
}
