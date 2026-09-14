//! Bounded `CodeCortex` memory writer — mechanical child of `crates/eliot-engine/src/codecortex.rs`.
//!
//! Architecture: A12.3 (docs/architecture/A12-03-one-governed-write-path.md#a123-one-governed-write-path),
//! A10.8 (docs/architecture/A10-08-verification-and-finish.md#a108-verification-and-finish),
//! A5.5 (docs/architecture/A05-05-verifier-and-evaluation-contract.md#a55-verifier-and-evaluation-contract).
//! Implementation: I12.10 (docs/architecture/I12-10-codecortex-implementation.md#i1210-codecortex-implementation),
//! I5.4 (docs/architecture/I05-04-canonical-transition.md#i54-canonical-transition),
//! I5.5 (docs/architecture/I05-05-write-envelope.md#i55-write-envelope),
//! I5.6 (docs/architecture/I05-06-admission-and-staging.md#i56-admission-and-staging),
//! I5.7 (docs/architecture/I05-07-ordering-and-parallelism.md#i57-ordering-and-parallelism),
//! I5.8 (docs/architecture/I05-08-canonical-event-and-projections.md#i58-canonical-event-and-projections),
//! I5.19 (docs/architecture/I05-19-write-submission-execution-and-receipts.md#i519-write-submission-execution-and-receipts),
//! I10.8 (docs/architecture/I10-08-instrument-plane-canonical-verification-and-code-intelligence.md#i108-instrument-plane-canonical-verification-and-code-intelligence).
//! Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! Ownership: this child owns only `CodeCortexMemoryWriter` and its `write_report` / `write_report_scoped` / `write_report_with_scope` seam that submits the already-bounded `ToolObservationRecord` (`codecortex_internal_report`, `codecortex-d1` scope, `Internal`/`LocalVerified`) via `WriteAdmissionService::admit` → `WriterHandle::submit`. All bounded payload projection (`codecortex-memory-projection-v1`, 96 KiB, evidence limit 12, truncation helpers), `codecortex_observation_command` construction, `full_report_digest` (`blake3`), and admission validation remain in the parent `codecortex` module, which retains `CodeCortexService` composition, adapter execution (`git`/`cargo`/`rg`/`sg`), diagnostics, and scope-binding authority.
//!
//! Mechanical split only: no new write authority, no provider/process behavior change, no API change, no other service/helper movement. Keep `super::` seam narrow and do not widen `pub(crate)` visibility.

use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::{CodeCortexReport, ProjectId, SessionId, TaskId, WriteReceiptRef};

pub struct CodeCortexMemoryWriter;

impl CodeCortexMemoryWriter {
    pub async fn write_report(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        report: &mut CodeCortexReport,
    ) -> Result<WriteReceiptRef, EngineError> {
        Self::write_report_with_scope(handle, admission, report, None).await
    }

    pub async fn write_report_scoped(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        report: &mut CodeCortexReport,
        session_id: SessionId,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> Result<WriteReceiptRef, EngineError> {
        Self::write_report_with_scope(
            handle,
            admission,
            report,
            Some((session_id, project_id, task_id)),
        )
        .await
    }

    async fn write_report_with_scope(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        report: &mut CodeCortexReport,
        scope: Option<(SessionId, ProjectId, TaskId)>,
    ) -> Result<WriteReceiptRef, EngineError> {
        let payload = super::bounded_codecortex_memory_payload(report)?;
        let command = super::codecortex_observation_command(report, payload, scope);
        let envelope = admission.admit(&command)?;
        let receipt = handle.submit(envelope).await?;
        let receipt_ref = WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        };
        report.memory_receipt = Some(receipt_ref.clone());
        Ok(receipt_ref)
    }
}
