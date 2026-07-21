#![forbid(unsafe_code)]

pub mod blob_store;
pub mod canonical_projection;
pub mod canonical_store;
pub mod control_wal;
pub mod error;
pub mod migration;
pub mod surql;
mod surreal_rpc;
pub mod surreal_server;
pub mod surreal_store;

pub use blob_store::BlobStore;
pub use canonical_projection::{
    CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalRecord, CanonicalReplayView,
    CanonicalSleepView, CanonicalTruncation, MAX_CANONICAL_RECORDS, SleepCandidatesResponse,
};
pub use canonical_store::{
    CanonicalClaimCard, CanonicalSecretScanFinding, CanonicalSecretScanReport, CanonicalStore,
    CanonicalToolObservation,
};
pub use control_wal::{
    ControlWal, WalDeadLetter, WalFailedWrite, WalPendingWrite, WalProjectHead, WalWriteState,
};
pub use error::StoreError;
pub use migration::{CompiledMigration, MigrationRunner};
pub use surql::{NamedSurqlOp, SurqlTemplate, SurqlTemplateRegistry};
pub use surreal_server::{CredentialRotationReport, ReadySurrealServer, SurrealServerSupervisor};
pub use surreal_store::{SurrealSmokeReport, SurrealStore};
