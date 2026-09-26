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

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize)]
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

impl<'de> Deserialize<'de> for UlPrediction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(UlPredictionVisitor)
    }
}

const VERIFIER_VERDICT_FIELDS: &[&str] = &["kind", "verifier", "expected"];
const DIAGNOSTIC_DELTA_FIELDS: &[&str] = &["kind", "signature", "expected"];
const BLAST_RADIUS_FIELDS: &[&str] = &["kind", "predicted_paths", "predicted_failing_verifiers"];
const OBSERVABLE_VALUE_FIELDS: &[&str] = &["kind", "probe_ref", "expected_excerpt_or_range"];

struct UlPredictionVisitor;

impl<'de> serde::de::Visitor<'de> for UlPredictionVisitor {
    type Value = UlPrediction;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a UL prediction record")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut kind: Option<String> = None;
        let mut fields = UlPredictionFields::default();

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" => set_once(&mut kind, map.next_value()?, "kind")?,
                "verifier" => set_once(&mut fields.verifier, map.next_value()?, "verifier")?,
                "expected" => set_once(&mut fields.expected, map.next_value()?, "expected")?,
                "signature" => {
                    set_once(&mut fields.signature, map.next_value()?, "signature")?;
                }
                "predicted_paths" => {
                    set_once(
                        &mut fields.predicted_paths,
                        map.next_value()?,
                        "predicted_paths",
                    )?;
                }
                "predicted_failing_verifiers" => {
                    set_once(
                        &mut fields.predicted_failing_verifiers,
                        map.next_value()?,
                        "predicted_failing_verifiers",
                    )?;
                }
                "probe_ref" => {
                    set_once(&mut fields.probe_ref, map.next_value()?, "probe_ref")?;
                }
                "expected_excerpt_or_range" => {
                    set_once(
                        &mut fields.expected_excerpt_or_range,
                        map.next_value()?,
                        "expected_excerpt_or_range",
                    )?;
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        key.as_str(),
                        &[
                            "kind",
                            "verifier",
                            "expected",
                            "signature",
                            "predicted_paths",
                            "predicted_failing_verifiers",
                            "probe_ref",
                            "expected_excerpt_or_range",
                        ],
                    ));
                }
            }
        }

        let kind = required(kind, "kind")?;
        match kind.as_str() {
            "verifier_verdict" => finish_verifier_verdict(fields),
            "diagnostic_delta" => finish_diagnostic_delta(fields),
            "blast_radius" => finish_blast_radius(fields),
            "observable_value" => finish_observable_value(fields),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &[
                    "verifier_verdict",
                    "diagnostic_delta",
                    "blast_radius",
                    "observable_value",
                ],
            )),
        }
    }
}

#[derive(Default)]
struct UlPredictionFields {
    verifier: Option<String>,
    expected: Option<String>,
    signature: Option<String>,
    predicted_paths: Option<Vec<String>>,
    predicted_failing_verifiers: Option<Vec<String>>,
    probe_ref: Option<String>,
    expected_excerpt_or_range: Option<String>,
}

fn finish_verifier_verdict<E>(fields: UlPredictionFields) -> Result<UlPrediction, E>
where
    E: serde::de::Error,
{
    unexpected(
        fields.signature.as_ref(),
        "signature",
        VERIFIER_VERDICT_FIELDS,
    )?;
    unexpected(
        fields.predicted_paths.as_ref(),
        "predicted_paths",
        VERIFIER_VERDICT_FIELDS,
    )?;
    unexpected(
        fields.predicted_failing_verifiers.as_ref(),
        "predicted_failing_verifiers",
        VERIFIER_VERDICT_FIELDS,
    )?;
    unexpected(
        fields.probe_ref.as_ref(),
        "probe_ref",
        VERIFIER_VERDICT_FIELDS,
    )?;
    unexpected(
        fields.expected_excerpt_or_range.as_ref(),
        "expected_excerpt_or_range",
        VERIFIER_VERDICT_FIELDS,
    )?;
    let expected = match required(fields.expected, "expected")?.as_str() {
        "pass" => PredictionExpectation::Pass,
        "fail" => PredictionExpectation::Fail,
        other => {
            return Err(serde::de::Error::unknown_variant(other, &["pass", "fail"]));
        }
    };
    Ok(UlPrediction::VerifierVerdict {
        verifier: required(fields.verifier, "verifier")?,
        expected,
    })
}

fn finish_diagnostic_delta<E>(fields: UlPredictionFields) -> Result<UlPrediction, E>
where
    E: serde::de::Error,
{
    unexpected(
        fields.verifier.as_ref(),
        "verifier",
        DIAGNOSTIC_DELTA_FIELDS,
    )?;
    unexpected(
        fields.predicted_paths.as_ref(),
        "predicted_paths",
        DIAGNOSTIC_DELTA_FIELDS,
    )?;
    unexpected(
        fields.predicted_failing_verifiers.as_ref(),
        "predicted_failing_verifiers",
        DIAGNOSTIC_DELTA_FIELDS,
    )?;
    unexpected(
        fields.probe_ref.as_ref(),
        "probe_ref",
        DIAGNOSTIC_DELTA_FIELDS,
    )?;
    unexpected(
        fields.expected_excerpt_or_range.as_ref(),
        "expected_excerpt_or_range",
        DIAGNOSTIC_DELTA_FIELDS,
    )?;
    let expected = match required(fields.expected, "expected")?.as_str() {
        "appears" => DiagnosticExpectation::Appears,
        "disappears" => DiagnosticExpectation::Disappears,
        "unchanged" => DiagnosticExpectation::Unchanged,
        other => {
            return Err(serde::de::Error::unknown_variant(
                other,
                &["appears", "disappears", "unchanged"],
            ));
        }
    };
    Ok(UlPrediction::DiagnosticDelta {
        signature: required(fields.signature, "signature")?,
        expected,
    })
}

fn finish_blast_radius<E>(fields: UlPredictionFields) -> Result<UlPrediction, E>
where
    E: serde::de::Error,
{
    unexpected(fields.verifier.as_ref(), "verifier", BLAST_RADIUS_FIELDS)?;
    unexpected(fields.expected.as_ref(), "expected", BLAST_RADIUS_FIELDS)?;
    unexpected(fields.signature.as_ref(), "signature", BLAST_RADIUS_FIELDS)?;
    unexpected(fields.probe_ref.as_ref(), "probe_ref", BLAST_RADIUS_FIELDS)?;
    unexpected(
        fields.expected_excerpt_or_range.as_ref(),
        "expected_excerpt_or_range",
        BLAST_RADIUS_FIELDS,
    )?;
    Ok(UlPrediction::BlastRadius {
        predicted_paths: required(fields.predicted_paths, "predicted_paths")?,
        predicted_failing_verifiers: required(
            fields.predicted_failing_verifiers,
            "predicted_failing_verifiers",
        )?,
    })
}

fn finish_observable_value<E>(fields: UlPredictionFields) -> Result<UlPrediction, E>
where
    E: serde::de::Error,
{
    unexpected(
        fields.verifier.as_ref(),
        "verifier",
        OBSERVABLE_VALUE_FIELDS,
    )?;
    unexpected(
        fields.expected.as_ref(),
        "expected",
        OBSERVABLE_VALUE_FIELDS,
    )?;
    unexpected(
        fields.signature.as_ref(),
        "signature",
        OBSERVABLE_VALUE_FIELDS,
    )?;
    unexpected(
        fields.predicted_paths.as_ref(),
        "predicted_paths",
        OBSERVABLE_VALUE_FIELDS,
    )?;
    unexpected(
        fields.predicted_failing_verifiers.as_ref(),
        "predicted_failing_verifiers",
        OBSERVABLE_VALUE_FIELDS,
    )?;
    Ok(UlPrediction::ObservableValue {
        probe_ref: required(fields.probe_ref, "probe_ref")?,
        expected_excerpt_or_range: required(
            fields.expected_excerpt_or_range,
            "expected_excerpt_or_range",
        )?,
    })
}

fn set_once<T, E>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.is_some() {
        return Err(E::duplicate_field(key));
    }
    *slot = Some(value);
    Ok(())
}

fn required<T, E>(value: Option<T>, field: &'static str) -> Result<T, E>
where
    E: serde::de::Error,
{
    value.ok_or_else(|| E::missing_field(field))
}

fn unexpected<T, E>(
    slot: Option<&T>,
    key: &'static str,
    fields: &'static [&'static str],
) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.is_some() {
        return Err(E::unknown_field(key, fields));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
