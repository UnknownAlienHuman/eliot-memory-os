//! Bounded `CodeCortex` memory writer — mechanical child of
//! `crates/eliot-engine/src/codecortex.rs`.
//!
//! Current documentation authority:
//! - `docs/architecture/ELIOT_ARCHITECTURE.md`: `A5.5`, `A10.8`, and `A12.3`.
//! - `docs/architecture/ELIOT_IMPLEMENTATION.md`: `I5.4..I5.8`, `I5.19`,
//!   `I10.8`, and `I12.10`.
//! - precedence: `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This child owns only `CodeCortexMemoryWriter` and its bounded report-write
//! seam through `WriteAdmissionService` and `WriterHandle`. Payload projection,
//! command construction, report digests, admission validation, service
//! composition, adapter execution, diagnostics, and scope-binding authority
//! remain in the parent `codecortex` module.
//!
//! Mechanical split only: no new write authority, provider/process behavior,
//! API, or visibility change.

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
