use crate::EngineError;
use eliot_store::{CanonicalStore, ControlWal};
use eliot_types::WriterStatusResponse;
use time::OffsetDateTime;

pub struct WriterReportService {
    wal: ControlWal,
    store: CanonicalStore,
}

impl WriterReportService {
    pub const fn new(wal: ControlWal, store: CanonicalStore) -> Self {
        Self { wal, store }
    }

    pub async fn status(&self) -> Result<WriterStatusResponse, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let db_version = self.store.writer_receipts().await.map_or_else(
            |error| format!("surrealdb-error: {error}"),
            |_| "surrealdb-ready".to_owned(),
        );
        let finished_at = OffsetDateTime::now_utc();
        let project_heads = self.wal.project_heads()?;
        let latest_project_sequence = project_heads.iter().map(|head| head.project_sequence).max();
        let latest_memory_revision = project_heads.iter().map(|head| head.memory_revision).max();

        Ok(WriterStatusResponse {
            started_at,
            finished_at,
            transport_status: "ready".to_owned(),
            db_version,
            pending_count: self.wal.pending_count()?,
            committed_count: self.wal.committed_count()?,
            failed_retryable_count: 0,
            failed_permanent_count: self.wal.failed_count()?,
            rejected_count: self.wal.rejected_count()?,
            dead_letter_count: self.wal.dead_letter_count()?,
            duplicate_write_count: 0,
            idempotent_replay_count: self.wal.idempotent_replay_count()?,
            idempotency_conflict_count: self.wal.idempotency_conflict_count()?,
            unknown_commit_count: self.wal.unknown_commit_count()?,
            latest_project_sequence,
            latest_memory_revision,
            project_heads,
            last_receipts: self.wal.last_receipts(20)?,
            final_status: "ready".to_owned(),
        })
    }
}
