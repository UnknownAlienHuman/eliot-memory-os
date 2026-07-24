use crate::{CueBinding, ProjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const FIX_CLASSIFIER_VERSION: &str = "ul-fixclass-1";

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MiningConfig {
    pub max_commits: usize,
    pub window_months: u32,
    pub author_merge_seconds: i64,
    pub max_files_per_basket: usize,
    pub min_support: u32,
    pub min_confidence: f64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            max_commits: 5_000,
            window_months: 24,
            author_merge_seconds: 1_800,
            max_files_per_basket: 30,
            min_support: 3,
            min_confidence: 0.5,
        }
    }
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MiningRun {
    pub run_id: String,
    pub project_id: ProjectId,
    pub head_commit: String,
    pub config_hash: String,
    pub commits_scanned: u32,
    pub baskets_used: u32,
    pub edges_written: u32,
    pub classifier_version: String,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CoChangeEdge {
    pub edge_id: String,
    pub project_id: ProjectId,
    pub path_a: String,
    pub path_b: String,
    pub support: u32,
    pub confidence_ab: f64,
    pub confidence_ba: f64,
    pub last_cochange_at_unix: i64,
    pub static_edge_exists: Option<bool>,
    pub mining_run_ref: String,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct HotspotScore {
    pub hotspot_id: String,
    pub project_id: ProjectId,
    pub path: String,
    pub touches: u32,
    pub fix_touches: u32,
    pub churn_decayed: f64,
    pub bugfix_density: f64,
    pub failure_density: u32,
    pub score: u8,
    pub mining_run_ref: String,
    pub cue_bindings: Vec<CueBinding>,
}
