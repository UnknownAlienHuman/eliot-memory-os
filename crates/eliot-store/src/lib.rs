#![forbid(unsafe_code)]

pub mod blob_store;
mod blob_validation;
mod canonical_activation_graph_models;
mod canonical_cognitive_projection;
mod canonical_meta_integrity_records;
pub mod canonical_projection;
mod canonical_record;
pub mod canonical_store;
pub mod control_wal;
mod db_client_metrics;
pub mod db_client_set;
pub mod error;
pub mod migration;
pub mod surql;
mod surql_templates;
mod surreal_rpc;
pub mod surreal_server;
pub mod surreal_store;

pub use blob_store::{
    BlobStore, CANONICAL_MEMORY_TRANSPORT_MAX_BYTES, CanonicalMemoryIngressPlan,
    CanonicalMemoryStagedRecord, CanonicalMemoryWritePlan,
};
pub use canonical_projection::{
    CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalRecord, CanonicalReplayView,
    CanonicalSleepView, CanonicalTruncation, MAX_CANONICAL_RECORDS, MAX_CURRENT_UL_ARTIFACTS,
    SleepCandidatesResponse, UL_ARTIFACT_PAGE_SIZE,
};
pub use canonical_store::{
    CanonicalClaimCard, CanonicalSecretScanFinding, CanonicalSecretScanReport, CanonicalStore,
    CanonicalToolObservation, CognitiveProjectionBacklog, CognitiveProjectionFamily,
    CognitiveProjectionFamilyCounts, CognitiveProjectionFamilyState,
    CognitiveProjectionIntentReceipt, CognitiveProjectionLease, CognitiveProjectionProject,
    CognitiveProjectionProjectPage, CognitiveProjectionPublicationStatus,
};
pub use control_wal::{
    ControlWal, WalDeadLetter, WalFailedWrite, WalPendingWrite, WalProjectHead, WalWriteState,
};
pub use db_client_set::{DEFAULT_DB_READ_POOL_SIZE, DbClientSet, DbClientSetMetrics};
pub use error::StoreError;
pub use migration::{CompiledMigration, MigrationRunner};
pub use surql::{NamedSurqlOp, SurqlAccessClass, SurqlTemplate, SurqlTemplateRegistry};
pub use surreal_server::{
    CredentialRotationReport, ReadySurrealServer, SurrealServerSupervisor, SurrealShutdown,
};
pub use surreal_store::{SurrealSmokeReport, SurrealStore};
