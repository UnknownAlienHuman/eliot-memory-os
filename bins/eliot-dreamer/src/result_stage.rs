#![forbid(unsafe_code)]

//! Result projection and JSONL stdout for decided Dreamer jobs (issue #702, Slice 8).
//!
//! After native owner dispatch decides an admitted job, this stage forms the
//! terminal [`JobView`] and renders it as exactly one JSONL line on stdout.
//! The projection is a thin wrapper preserving the
//! [`project_claimed_view`](crate::project_claimed_view) exactness contract:
//! the job id is carried verbatim, every lifecycle state keeps its exact
//! identity (including `Partial`, `Failed`, and `Reconciling`), and a `None`
//! result is honest absence of a proved payload, never promoted to success.
//!
//! Channel split: stdout carries exactly one JSONL object per view via
//! [`emit_jsonl_stdout`] (the shared stdout lock); human and log diagnostics go
//! to stderr via `eprintln!` at call sites, never to stdout. No process is
//! launched and no file is written here.

use crate::{DreamResult, DreamerError, JobState, JobView};

/// Projects the decided result view for one job.
///
/// Thin wrapper: the job id is carried verbatim, the state keeps its exact
/// identity, and the result is carried as given — `None` stays `None`, never
/// rendered as success or absence-masked failure.
pub(crate) fn project_result_view(
    job_id: &str,
    state: JobState,
    result: Option<DreamResult>,
) -> JobView {
    JobView {
        job_id: job_id.to_owned(),
        state,
        result,
    }
}

/// Renders one result view as a single JSONL line.
///
/// [`serde_json::to_string`] emits no literal newlines (control characters
/// inside strings are escaped), so the returned value is exactly one line.
/// Encoding failures refuse fail-closed with [`DreamerError::InvalidAdmission`]
/// under the request-rejected code, never the Kernel-admission code.
pub(crate) fn render_jsonl(view: &JobView) -> Result<String, DreamerError> {
    serde_json::to_string(view)
        .map_err(|_| DreamerError::InvalidAdmission("result encoding failure"))
}

/// Emits one JSONL line for a result view to stdout.
///
/// Stdout carries machine-readable receipt lines only; diagnostics and logs
/// belong on stderr (`eprintln!`) at call sites so a log line can never be
/// mistaken for a receipt. A broken stdout refuses fail-closed under the
/// request-rejected code like an encoding failure. Launches no process and
/// writes no file.
#[allow(
    dead_code,
    reason = "emitted by the binary receipt edge once the Governor-material slice decides payloads; render_jsonl proves the encoding boundary until then"
)]
pub(crate) fn emit_jsonl_stdout(view: &JobView) -> Result<(), DreamerError> {
    use std::io::Write as _;

    let line = render_jsonl(view)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}")
        .map_err(|_| DreamerError::InvalidAdmission("result encoding failure"))
}

#[cfg(test)]
mod slice_8_result_tests {
    use super::*;
    use crate::{CurationCandidate, DreamPacket, Interpretation, SourceCoverage};

    use crate::KERNEL_ADMISSION_REQUIRED;

    fn coverage() -> SourceCoverage {
        SourceCoverage {
            evidence: vec!["evidence-1".to_owned()],
            memory: Vec::new(),
            architecture: Vec::new(),
            implementation: Vec::new(),
            conformance: Vec::new(),
        }
    }

    fn packet(job_id: &str) -> DreamResult {
        DreamResult::Packet(DreamPacket {
            packet_id: format!("{job_id}-packet"),
            job_id: job_id.to_owned(),
            question: "What does ELIOT know about this scope?".to_owned(),
            scope_id: "scope-slice-8".to_owned(),
            state_fence: "fence-slice-8".to_owned(),
            source_coverage: coverage(),
            synthesized_interpretations: vec![Interpretation {
                statement: "Bounded references are available for governed interpretation."
                    .to_owned(),
                support_handles: vec!["evidence-1".to_owned()],
                epistemic_status: "candidate_only".to_owned(),
            }],
            rival_models_and_dissent: vec![
                "Correlated evidence may omit relevant sources.".to_owned(),
            ],
            unknowns_and_gaps: vec!["No explicit conflict set was supplied.".to_owned()],
            recommended_probes_or_next_actions: vec![
                "Ask the owning Governor to admit the next probe.".to_owned(),
            ],
            invalidation_conditions: vec!["Source revocation.".to_owned()],
            provenance: vec!["evidence-1".to_owned()],
        })
    }

    fn curation(job_id: &str) -> DreamResult {
        DreamResult::Curation {
            job_id: job_id.to_owned(),
            candidates: vec![CurationCandidate {
                candidate_id: format!("{job_id}-candidate-1"),
                kind: "review_required".to_owned(),
                source_handles: vec!["evidence-1".to_owned()],
                proposed_transformation: "Inspect provenance; do not alter the source.".to_owned(),
                uncertainty: "No semantic promotion from a handle-only bundle.".to_owned(),
                rollback: "Discard the candidate.".to_owned(),
            }],
            provenance: vec!["evidence-1".to_owned()],
        }
    }

    fn clarification(job_id: &str) -> DreamResult {
        DreamResult::Clarification {
            job_id: job_id.to_owned(),
            question: "Which observation, scope, and outcome apply?".to_owned(),
            why_it_matters: "Fact cannot be distinguished from interpretation without it."
                .to_owned(),
            safe_fallback: "Preserve the source as unresolved.".to_owned(),
        }
    }

    /// The projection is total and exact over the closed lifecycle: every
    /// state projects to its own identity — terminal `Partial` and `Failed`
    /// keep their disposition, `Reconciling` never renders as success — and
    /// the job id is carried verbatim with honest `None` absence.
    #[test]
    fn projection_is_total_and_exact() {
        for state in [
            JobState::Queued,
            JobState::Running,
            JobState::Completed,
            JobState::Cancelled,
            JobState::Rejected,
            JobState::Partial,
            JobState::Failed,
            JobState::Reconciling,
        ] {
            let view = project_result_view("job-slice-8", state, None);
            assert_eq!(view.job_id, "job-slice-8");
            assert_eq!(view.state, state);
            assert_eq!(view.result, None);
        }
    }

    /// A proved payload of any of the three result shapes is carried exactly:
    /// the view clones the payload without promotion, thinning, or rewriting.
    #[test]
    fn result_payload_is_preserved_exactly() {
        for result in [
            packet("job-slice-8"),
            curation("job-slice-8"),
            clarification("job-slice-8"),
        ] {
            let view =
                project_result_view("job-slice-8", JobState::Completed, Some(result.clone()));
            assert_eq!(view.result, Some(result));
        }
    }

    /// Each view renders as exactly one JSONL line that round-trips to the
    /// identical view. Embedded newlines inside payload strings are escaped
    /// by the encoder, so even hostile text cannot smuggle a second line onto
    /// the stdout receipt channel.
    #[test]
    fn jsonl_is_single_line_and_roundtrips() {
        let mut hostile = packet("job-slice-8");
        let DreamResult::Packet(inner) = &mut hostile else {
            panic!("packet fixture must be a packet");
        };
        inner.question = "line one\nline two\r\nline three".to_owned();
        for view in [
            project_result_view("job-slice-8", JobState::Completed, Some(hostile)),
            project_result_view(
                "job-slice-8",
                JobState::Partial,
                Some(curation("job-slice-8")),
            ),
            project_result_view(
                "job-slice-8",
                JobState::Failed,
                Some(clarification("job-slice-8")),
            ),
            project_result_view("job-slice-8", JobState::Reconciling, None),
            project_result_view("job-slice-8", JobState::Queued, None),
        ] {
            let Ok(line) = render_jsonl(&view) else {
                panic!("a proved view must render");
            };
            assert!(
                !line.contains('\n') && !line.contains('\r'),
                "JSONL receipt must be a single line, got {line:?}"
            );
            let Ok(back) = serde_json::from_str::<JobView>(&line) else {
                panic!("JSONL receipt must decode");
            };
            assert_eq!(back, view);
        }
    }

    /// An encoding failure refuses fail-closed with the request-rejected code,
    /// never the Kernel-admission code. (`serde_json::to_string` over the
    /// closed view is infallible in practice, so the closed mapping itself is
    /// the assertion surface.)
    #[test]
    fn encoding_failure_is_closed() {
        let error = DreamerError::InvalidAdmission("result encoding failure");
        assert_eq!(
            format!("{error}"),
            "invalid admission: result encoding failure"
        );
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert_ne!(
            error.code(),
            KERNEL_ADMISSION_REQUIRED,
            "encoding refusal must not borrow the Kernel-admission code"
        );
    }

    /// Emitting a proved view to stdout succeeds, carrying the rendered line
    /// on the machine-readable channel. (Diagnostics stay on stderr at call
    /// sites; this seam launches no process and writes no file.)
    #[test]
    fn emit_stdout_carries_the_receipt_line() {
        let view = project_result_view(
            "job-slice-8",
            JobState::Completed,
            Some(clarification("job-slice-8")),
        );
        assert!(emit_jsonl_stdout(&view).is_ok(), "stdout receipt must emit");
    }
}
