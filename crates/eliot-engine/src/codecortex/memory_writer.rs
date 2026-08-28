//! Bounded `CodeCortex` memory writer — mechanical child of `crates/eliot-engine/src/codecortex.rs` (canonical base `8e1b66d267633052dc2b9eac7776dff743a6827b`, graph `eliot-memory-os-8e1b66d-live`).
//!
//! Architecture anchors: `A12.3` (governed write path) and `A10.8`/`A5.5` (Instrument Plane / Verifier). Implementation anchors: `I12.10` (`CodeCortex` implementation), `I5.4`–`I5.8` + `I5.19` (canonical transition → write envelope → admission → receipt via `WriterHandle`/`WriteAdmissionService`), and `I10.8` (Instrument Plane adapters).
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
