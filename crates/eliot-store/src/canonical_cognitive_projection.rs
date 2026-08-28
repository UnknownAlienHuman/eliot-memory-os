//! Cognitive-projection data-model cell — derived report/projection handles only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for cognitive outbox, lease, backlog, project page and family state. Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Mechanical extraction from `crates/eliot-store/src/canonical_store.rs` — preserves exact behavior, public API, imports, serde shape, and `CanonicalStore` facade. No semantic redesign and no canonical write-authority change. Excludes provider/handshake/migration/atomic-write, capacity/L2/recall, and Dreamer/Luna semantics.

use eliot_types::{MemoryRevision, ProjectId};
use time::OffsetDateTime;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveProjectionFamily {
    Search,
    Cue,
    DependencyDirty,
    Utility,
}

impl CognitiveProjectionFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Cue => "cue",
            Self::DependencyDirty => "dependency_dirty",
            Self::Utility => "utility",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionIntentReceipt {
    pub event_id: String,
    pub project_id: ProjectId,
    pub updated_revision: MemoryRevision,
    pub families: Vec<CognitiveProjectionFamily>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionLease {
    pub lease_id: String,
    pub lease_owner: String,
    pub project_id: ProjectId,
    pub through_revision: MemoryRevision,
    pub write_ids: Vec<String>,
    pub families: Vec<CognitiveProjectionFamily>,
    pub claimed_rows: usize,
    pub max_attempt_count: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub lease_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionFamilyCounts {
    pub search: u64,
    pub cue: u64,
    pub dependency_dirty: u64,
    pub utility: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionBacklog {
    pub pending: u64,
    pub leased: u64,
    pub retryable: u64,
    pub blocked: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub oldest_created_at: Option<OffsetDateTime>,
    pub family_counts: CognitiveProjectionFamilyCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionProject {
    pub project_id: ProjectId,
    pub head_revision: MemoryRevision,
    pub search_applied_revision: Option<MemoryRevision>,
    pub search_projection_format: Option<String>,
    #[serde(default)]
    pub pending: u64,
    #[serde(default)]
    pub leased: u64,
    #[serde(default)]
    pub retryable: u64,
    #[serde(default)]
    pub blocked: u64,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub oldest_pending_created_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionProjectPage {
    pub projects: Vec<CognitiveProjectionProject>,
    pub truncated: bool,
    pub next_start: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveProjectionPublicationStatus {
    Published,
    Stale,
    Blocked,
    Unavailable,
}

impl CognitiveProjectionPublicationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Stale => "stale",
            Self::Blocked => "blocked",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CognitiveProjectionFamilyState {
    pub project_id: ProjectId,
    pub family: CognitiveProjectionFamily,
    pub target_revision: MemoryRevision,
    pub applied_revision: Option<MemoryRevision>,
    pub status: CognitiveProjectionPublicationStatus,
    pub last_error: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct CognitiveProjectionOutboxRow {
    pub(crate) write_id: String,
    pub(crate) project_id: ProjectId,
    pub(crate) updated_revision: MemoryRevision,
    pub(crate) families: Vec<CognitiveProjectionFamily>,
    pub(crate) attempt_count: u32,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct CognitiveProjectionClaimLoad {
    pub(crate) rows: Vec<CognitiveProjectionOutboxRow>,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct CognitiveProjectionMutationResult {
    pub(crate) rows_updated: usize,
}
