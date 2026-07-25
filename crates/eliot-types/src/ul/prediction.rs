use crate::{PredictionConfidence, ProjectId, SessionId, TaskId, VerificationResult};
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

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticExpectation {
    Appears,
    Disappears,
    Unchanged,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum UlPrediction {
    VerifierVerdict {
        verifier: String,
        expected: PredictionExpectation,
    },
    DiagnosticDelta {
        signature: String,
        expected: DiagnosticExpectation,
    },
    BlastRadius {
        predicted_paths: Vec<String>,
        predicted_failing_verifiers: Vec<String>,
    },
    ObservableValue {
        probe_ref: String,
        expected_excerpt_or_range: String,
    },
}

#[derive(Clone, Debug, Default, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlPredictionActual {
    #[schemars(with = "Option<String>")]
    pub verifier_result: Option<VerificationResult>,
    #[serde(default)]
    pub diagnostic_before: Vec<String>,
    #[serde(default)]
    pub diagnostic_after: Vec<String>,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub failing_verifiers: Vec<String>,
    #[serde(default)]
    pub observed_value: Option<String>,
}

#[derive(Clone, Debug, Default, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlastScore {
    pub path_precision_num: u32,
    pub path_precision_den: u32,
    pub path_recall_num: u32,
    pub path_recall_den: u32,
    pub verifier_precision_num: u32,
    pub verifier_precision_den: u32,
    pub verifier_recall_num: u32,
    pub verifier_recall_den: u32,
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
    #[serde(default)]
    pub prediction: Option<UlPrediction>,
    #[serde(default)]
    pub confidence: Option<PredictionConfidence>,
    pub resolution: Option<PredictionResolution>,
    pub actual: Option<VerificationResult>,
    #[serde(default)]
    pub actual_detail: Option<UlPredictionActual>,
    #[serde(default)]
    pub blast_score: Option<BlastScore>,
    pub verification_ref: Option<String>,
    pub source_frame_hash: String,
}

#[derive(
    Clone, Copy, Debug, Default, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationTrend {
    Improving,
    Flat,
    Degrading,
    #[default]
    InsufficientData,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CalibrationScore {
    pub project_id: ProjectId,
    pub subsystem_concept_id: Option<String>,
    pub resolved_predictions: u32,
    pub hits: u32,
    pub misses: u32,
    pub hit_rate: f64,
    #[serde(default)]
    pub unresolvable: u32,
    #[serde(default)]
    pub unresolved: u32,
    #[serde(default)]
    pub brier_milli: Option<u32>,
    #[serde(default)]
    pub blast_path_precision_milli: Option<u32>,
    #[serde(default)]
    pub blast_path_recall_milli: Option<u32>,
    #[serde(default)]
    pub blast_verifier_precision_milli: Option<u32>,
    #[serde(default)]
    pub blast_verifier_recall_milli: Option<u32>,
    #[serde(default)]
    pub trend: CalibrationTrend,
}
