use crate::{ProjectId, SessionId, TaskId, VerificationResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PredictionExpectation {
    Pass,
    Fail,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PredictionResolution {
    Hit,
    Miss,
    Unresolvable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PredictionRecord {
    pub prediction_id: String,
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub subsystem_concept_id: Option<String>,
    pub packet_id: String,
    pub verifier: String,
    pub expected: PredictionExpectation,
    pub resolution: Option<PredictionResolution>,
    pub actual: Option<VerificationResult>,
    pub verification_ref: Option<String>,
    pub source_frame_hash: String,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CalibrationScore {
    pub project_id: ProjectId,
    pub subsystem_concept_id: Option<String>,
    pub resolved_predictions: u32,
    pub hits: u32,
    pub misses: u32,
    pub hit_rate: f64,
}
