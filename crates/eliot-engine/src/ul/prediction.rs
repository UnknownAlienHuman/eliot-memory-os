use crate::{EngineError, PacketPredictionIntent, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    BlastScore, DiagnosticExpectation, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteReceipt, PredictionConfidence,
    PredictionExpectation, PredictionRecord, PredictionResolution, ProjectId, SessionId, TaskId,
    UlPrediction, UlPredictionActual, VerificationResult, WriteId, error_signature,
    normalize_observed_path,
};
use std::collections::{BTreeMap, BTreeSet};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PredictionCapture {
    pub prediction_ref: String,
    pub record: PredictionRecord,
    pub receipt: ObservabilityWriteReceipt,
}

#[derive(Clone, Debug)]
pub struct PredictionCaptureInput {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub subsystem_concept_id: Option<String>,
    pub packet_id: String,
    pub expected_observable: String,
    pub source_frame_hash: String,
}

#[derive(Clone, Debug)]
pub struct PredictionFrameCaptureInput {
    pub base: PredictionCaptureInput,
    pub confidence: Option<PredictionConfidence>,
    pub predicted_changed_paths: Vec<String>,
    pub predicted_failing_verifiers: Vec<String>,
    pub diagnostic_prediction: Option<(String, DiagnosticExpectation)>,
}

pub struct PredictionService {
    store: CanonicalStore,
    writer: WriterHandle,
}

pub type PredictionMatcherService = PredictionService;

impl PredictionService {
    #[must_use]
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        Self { store, writer }
    }

    pub async fn capture(
        &self,
        input: PredictionCaptureInput,
    ) -> Result<Option<PredictionCapture>, EngineError> {
        let Some((verifier, expected)) = parse_expected_observable(&input.expected_observable)
        else {
            return Ok(None);
        };
        self.capture_prediction(
            &input,
            UlPrediction::VerifierVerdict { verifier, expected },
            None,
        )
        .await
        .map(Some)
    }

    pub async fn capture_frame(
        &self,
        input: PredictionFrameCaptureInput,
    ) -> Result<Vec<PredictionCapture>, EngineError> {
        let mut captures = Vec::new();
        if let Some((verifier, expected)) =
            parse_expected_observable(&input.base.expected_observable)
        {
            captures.push(
                self.capture_prediction(
                    &input.base,
                    UlPrediction::VerifierVerdict { verifier, expected },
                    input.confidence,
                )
                .await?,
            );
        }
        let predicted_paths = normalize_prediction_paths(&input.predicted_changed_paths);
        let predicted_failing_verifiers =
            normalize_prediction_values(&input.predicted_failing_verifiers);
        if !predicted_paths.is_empty() || !predicted_failing_verifiers.is_empty() {
            captures.push(
                self.capture_prediction(
                    &input.base,
                    UlPrediction::BlastRadius {
                        predicted_paths,
                        predicted_failing_verifiers,
                    },
                    input.confidence,
                )
                .await?,
            );
        }
        if let Some((signature, expected)) = input.diagnostic_prediction {
            let signature = normalize_diagnostic_signature(&signature);
            if !signature.is_empty() {
                captures.push(
                    self.capture_prediction(
                        &input.base,
                        UlPrediction::DiagnosticDelta {
                            signature,
                            expected,
                        },
                        input.confidence,
                    )
                    .await?,
                );
            }
        }
        Ok(captures)
    }

    /// Persists the exact prediction intent already finalized by the packet
    /// compiler. No material-frame fields are reinterpreted here: the
    /// compiler-owned prediction, confidence and source hash are the write
    /// authority. A mismatched reference fails before any write.
    pub async fn capture_packet_intent(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        session_id: SessionId,
        packet_id: &str,
        intent: &PacketPredictionIntent,
    ) -> Result<PredictionCapture, EngineError> {
        let prediction_id = prediction_id_for(
            project_id,
            task_id,
            session_id,
            packet_id,
            &intent.prediction,
            &intent.source_frame_hash,
        );
        let derived_ref = format!("prediction:{prediction_id}");
        if derived_ref != intent.prediction_ref {
            return Err(EngineError::WriteRejected(format!(
                "packet prediction intent ref mismatch: compiled={} derived={derived_ref}",
                intent.prediction_ref
            )));
        }
        self.capture_prediction(
            &PredictionCaptureInput {
                project_id,
                task_id,
                session_id,
                subsystem_concept_id: intent.subsystem_concept_id.clone(),
                packet_id: packet_id.to_owned(),
                expected_observable: String::new(),
                source_frame_hash: intent.source_frame_hash.clone(),
            },
            intent.prediction.clone(),
            intent.confidence,
        )
        .await
    }

    async fn capture_prediction(
        &self,
        input: &PredictionCaptureInput,
        prediction: UlPrediction,
        confidence: Option<PredictionConfidence>,
    ) -> Result<PredictionCapture, EngineError> {
        let prediction_id = prediction_id_for(
            input.project_id,
            input.task_id,
            input.session_id,
            &input.packet_id,
            &prediction,
            &input.source_frame_hash,
        );
        let (verifier, expected) = legacy_verifier_fields(&prediction);
        let record = PredictionRecord {
            prediction_id: prediction_id.clone(),
            project_id: input.project_id,
            task_id: input.task_id,
            session_id: input.session_id,
            subsystem_concept_id: input.subsystem_concept_id.clone(),
            packet_id: input.packet_id.clone(),
            verifier,
            expected,
            prediction: Some(prediction),
            confidence,
            resolution: None,
            actual: None,
            actual_detail: None,
            blast_score: None,
            verification_ref: None,
            source_frame_hash: input.source_frame_hash.clone(),
        };
        let receipt = self
            .write_record(
                deterministic_write_id(&format!("prediction-capture|{prediction_id}")),
                &record,
            )
            .await?;
        Ok(PredictionCapture {
            prediction_ref: format!("prediction:{prediction_id}"),
            record,
            receipt,
        })
    }

    pub async fn resolve(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        verifier: &str,
        actual: VerificationResult,
        verification_ref: &str,
        created_before: OffsetDateTime,
    ) -> Result<Vec<PredictionRecord>, EngineError> {
        self.resolve_verification(
            project_id,
            task_id,
            verifier,
            actual,
            verification_ref,
            created_before,
        )
        .await
    }

    pub async fn resolve_verification(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        verifier: &str,
        actual: VerificationResult,
        verification_ref: &str,
        event_time: OffsetDateTime,
    ) -> Result<Vec<PredictionRecord>, EngineError> {
        let verifier = normalize_verifier(verifier);
        let predictions = newest_matching(
            self.store
                .load_predictions(
                    project_id,
                    Some(task_id),
                    Some(&verifier),
                    true,
                    Some(event_time),
                )
                .await?,
            |prediction| match &prediction.prediction {
                Some(UlPrediction::VerifierVerdict {
                    verifier: predicted,
                    ..
                }) => normalize_verifier(predicted) == verifier,
                None => normalize_verifier(&prediction.verifier) == verifier,
                _ => false,
            },
        );
        let mut resolved = Vec::new();
        for mut prediction in predictions {
            prediction.resolution = Some(resolve_prediction(prediction.expected, actual));
            prediction.actual = Some(actual);
            prediction.actual_detail = Some(UlPredictionActual {
                verifier_result: Some(actual),
                ..UlPredictionActual::default()
            });
            prediction.verification_ref = Some(verification_ref.to_owned());
            self.write_resolution(&prediction, verification_ref).await?;
            resolved.push(prediction);
        }
        Ok(sorted_predictions(resolved))
    }

    pub async fn resolve_diagnostic_delta(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        before_signatures: &[String],
        after_signatures: &[String],
        observation_ref: &str,
        event_time: OffsetDateTime,
    ) -> Result<Vec<PredictionRecord>, EngineError> {
        let before = normalize_diagnostic_signatures(before_signatures);
        let after = normalize_diagnostic_signatures(after_signatures);
        let predictions = newest_matching(
            self.store
                .load_predictions(project_id, Some(task_id), None, true, Some(event_time))
                .await?,
            |prediction| {
                matches!(
                    prediction.prediction,
                    Some(UlPrediction::DiagnosticDelta { .. })
                )
            },
        );
        let mut resolved = Vec::new();
        for mut prediction in predictions {
            let Some(UlPrediction::DiagnosticDelta {
                signature,
                expected,
            }) = &prediction.prediction
            else {
                continue;
            };
            prediction.resolution = Some(
                if diagnostic_expectation_matches(expected, signature, &before, &after) {
                    PredictionResolution::Hit
                } else {
                    PredictionResolution::Miss
                },
            );
            prediction.actual_detail = Some(UlPredictionActual {
                diagnostic_before: before.clone(),
                diagnostic_after: after.clone(),
                ..UlPredictionActual::default()
            });
            prediction.verification_ref = Some(observation_ref.to_owned());
            self.write_resolution(&prediction, observation_ref).await?;
            resolved.push(prediction);
        }
        Ok(sorted_predictions(resolved))
    }

    pub async fn resolve_blast(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        changed_paths: &[String],
        failing_verifiers: &[String],
        observation_ref: &str,
        event_time: OffsetDateTime,
    ) -> Result<Vec<PredictionRecord>, EngineError> {
        let actual_paths = normalize_prediction_paths(changed_paths);
        let actual_verifiers = normalize_prediction_values(failing_verifiers);
        let predictions = newest_matching(
            self.store
                .load_predictions(project_id, Some(task_id), None, true, Some(event_time))
                .await?,
            |prediction| {
                matches!(
                    prediction.prediction,
                    Some(UlPrediction::BlastRadius { .. })
                )
            },
        );
        let mut resolved = Vec::new();
        for mut prediction in predictions {
            let Some(UlPrediction::BlastRadius {
                predicted_paths,
                predicted_failing_verifiers,
            }) = &prediction.prediction
            else {
                continue;
            };
            prediction.blast_score = Some(blast_score(
                predicted_paths,
                &actual_paths,
                predicted_failing_verifiers,
                &actual_verifiers,
            ));
            prediction.resolution = Some(
                if predicted_paths == &actual_paths
                    && predicted_failing_verifiers == &actual_verifiers
                {
                    PredictionResolution::Hit
                } else {
                    PredictionResolution::Miss
                },
            );
            prediction.actual_detail = Some(UlPredictionActual {
                changed_paths: actual_paths.clone(),
                failing_verifiers: actual_verifiers.clone(),
                ..UlPredictionActual::default()
            });
            prediction.verification_ref = Some(observation_ref.to_owned());
            self.write_resolution(&prediction, observation_ref).await?;
            resolved.push(prediction);
        }
        Ok(sorted_predictions(resolved))
    }

    pub async fn sweep_unresolvable(
        &self,
        project_id: ProjectId,
        now: OffsetDateTime,
    ) -> Result<Vec<PredictionRecord>, EngineError> {
        let deadline = now - Duration::hours(24);
        let predictions = newest_matching(
            self.store
                .load_predictions(project_id, None, None, true, Some(deadline))
                .await?,
            |_| true,
        );
        let mut resolved = Vec::new();
        for mut prediction in predictions {
            prediction.resolution = Some(PredictionResolution::Unresolvable);
            prediction.actual = None;
            prediction.actual_detail = None;
            prediction.verification_ref = Some("deadline:24h".to_owned());
            self.write_resolution(&prediction, "deadline:24h").await?;
            resolved.push(prediction);
        }
        Ok(sorted_predictions(resolved))
    }

    async fn write_resolution(
        &self,
        prediction: &PredictionRecord,
        evidence_ref: &str,
    ) -> Result<(), EngineError> {
        self.write_record(
            deterministic_write_id(&format!(
                "prediction-resolution|{}|{}|{:?}",
                prediction.prediction_id, evidence_ref, prediction.resolution
            )),
            prediction,
        )
        .await?;
        Ok(())
    }

    async fn write_record(
        &self,
        write_id: WriteId,
        record: &PredictionRecord,
    ) -> Result<ObservabilityWriteReceipt, EngineError> {
        let payload = serde_json::to_value(record)?;
        let input_hash = blake3::hash(&serde_json::to_vec(&payload)?)
            .to_hex()
            .to_string();
        self.writer
            .submit_observability(ObservabilityWriteEnvelope {
                schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
                write_id,
                project_id: record.project_id,
                task_id: Some(record.task_id),
                session_id: Some(record.session_id),
                kind: ObservabilityKind::PredictionRecord,
                record_id: record.prediction_id.clone(),
                payload,
                input_hash,
                created_at: OffsetDateTime::now_utc(),
            })
            .await
    }
}

#[must_use]
pub fn diagnostic_expectation_matches(
    expected: &DiagnosticExpectation,
    signature: &str,
    before: &[String],
    after: &[String],
) -> bool {
    let signature = normalize_diagnostic_signature(signature);
    let before = before.iter().any(|value| value == &signature);
    let after = after.iter().any(|value| value == &signature);
    match expected {
        DiagnosticExpectation::Appears => !before && after,
        DiagnosticExpectation::Disappears => before && !after,
        DiagnosticExpectation::Unchanged => before == after,
    }
}

#[must_use]
pub fn blast_score(
    predicted_paths: &[String],
    actual_paths: &[String],
    predicted_verifiers: &[String],
    actual_verifiers: &[String],
) -> BlastScore {
    let (path_intersection, predicted_path_count, actual_path_count) =
        set_fraction_parts(predicted_paths, actual_paths);
    let (verifier_intersection, predicted_verifier_count, actual_verifier_count) =
        set_fraction_parts(predicted_verifiers, actual_verifiers);
    BlastScore {
        path_precision_num: path_intersection,
        path_precision_den: predicted_path_count,
        path_recall_num: path_intersection,
        path_recall_den: actual_path_count,
        verifier_precision_num: verifier_intersection,
        verifier_precision_den: predicted_verifier_count,
        verifier_recall_num: verifier_intersection,
        verifier_recall_den: actual_verifier_count,
    }
}

#[must_use]
pub fn blast_fraction_milli(numerator: u32, denominator: u32) -> u32 {
    if denominator == 0 {
        return if numerator == 0 { 1_000 } else { 0 };
    }
    numerator.saturating_mul(1_000) / denominator
}

fn newest_matching(
    predictions: Vec<PredictionRecord>,
    predicate: impl Fn(&PredictionRecord) -> bool,
) -> Vec<PredictionRecord> {
    let mut newest = BTreeMap::<(String, &'static str), PredictionRecord>::new();
    for prediction in predictions.into_iter().filter(predicate) {
        newest.insert(
            (
                prediction.packet_id.clone(),
                prediction_kind(prediction.prediction.as_ref()),
            ),
            prediction,
        );
    }
    newest.into_values().collect()
}

const fn prediction_kind(prediction: Option<&UlPrediction>) -> &'static str {
    match prediction {
        Some(UlPrediction::VerifierVerdict { .. }) | None => "verifier_verdict",
        Some(UlPrediction::DiagnosticDelta { .. }) => "diagnostic_delta",
        Some(UlPrediction::BlastRadius { .. }) => "blast_radius",
        Some(UlPrediction::ObservableValue { .. }) => "observable_value",
    }
}

fn legacy_verifier_fields(prediction: &UlPrediction) -> (String, PredictionExpectation) {
    match prediction {
        UlPrediction::VerifierVerdict { verifier, expected } => (verifier.clone(), *expected),
        _ => (String::new(), PredictionExpectation::Pass),
    }
}

#[must_use]
pub fn parse_expected_observable(value: &str) -> Option<(String, PredictionExpectation)> {
    let value = value.trim();
    let body = value.strip_prefix("verifier:")?;
    let (verifier, expected) = if let Some(verifier) = body.strip_suffix("=pass") {
        (verifier, PredictionExpectation::Pass)
    } else if let Some(verifier) = body.strip_suffix("=fail") {
        (verifier, PredictionExpectation::Fail)
    } else {
        return None;
    };
    let verifier = normalize_verifier(verifier);
    (!verifier.is_empty()).then_some((verifier, expected))
}

#[must_use]
pub fn resolve_prediction(
    expected: PredictionExpectation,
    actual: VerificationResult,
) -> PredictionResolution {
    match actual {
        VerificationResult::Inconclusive => PredictionResolution::Unresolvable,
        VerificationResult::Passed if expected == PredictionExpectation::Pass => {
            PredictionResolution::Hit
        }
        VerificationResult::Failed if expected == PredictionExpectation::Fail => {
            PredictionResolution::Hit
        }
        VerificationResult::Passed | VerificationResult::Failed => PredictionResolution::Miss,
    }
}

#[must_use]
pub fn prediction_id(
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    packet_id: &str,
    verifier: &str,
    expected: PredictionExpectation,
    source_frame_hash: &str,
) -> String {
    prediction_id_for(
        project_id,
        task_id,
        session_id,
        packet_id,
        &UlPrediction::VerifierVerdict {
            verifier: normalize_verifier(verifier),
            expected,
        },
        source_frame_hash,
    )
}

#[must_use]
pub fn prediction_id_for(
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    packet_id: &str,
    prediction: &UlPrediction,
    source_frame_hash: &str,
) -> String {
    let payload = serde_json::to_vec(&(
        project_id,
        task_id,
        session_id,
        packet_id,
        prediction,
        source_frame_hash,
    ))
    .unwrap_or_default();
    let digest = blake3::hash(&payload).to_hex().to_string();
    format!("ul-prediction-{}", &digest[..32])
}

#[must_use]
pub fn normalize_verifier(verifier: &str) -> String {
    verifier.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[must_use]
pub fn normalize_diagnostic_signature(signature: &str) -> String {
    if signature.trim().starts_with("sig:") {
        return signature.trim().to_owned();
    }
    error_signature("ul_prediction", "diagnostic", signature, "", None)
}

#[must_use]
pub fn normalize_diagnostic_signatures(signatures: &[String]) -> Vec<String> {
    let mut signatures = signatures
        .iter()
        .map(|signature| normalize_diagnostic_signature(signature))
        .filter(|signature| !signature.is_empty())
        .collect::<Vec<_>>();
    signatures.sort();
    signatures.dedup();
    signatures
}

fn normalize_prediction_values(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| normalize_verifier(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn normalize_prediction_paths(paths: &[String]) -> Vec<String> {
    let mut paths = paths
        .iter()
        .map(|path| normalize_observed_path(path))
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn set_fraction_parts(predicted: &[String], actual: &[String]) -> (u32, u32, u32) {
    let predicted = predicted.iter().collect::<BTreeSet<_>>();
    let actual = actual.iter().collect::<BTreeSet<_>>();
    (
        u32::try_from(predicted.intersection(&actual).count()).unwrap_or(u32::MAX),
        u32::try_from(predicted.len()).unwrap_or(u32::MAX),
        u32::try_from(actual.len()).unwrap_or(u32::MAX),
    )
}

fn sorted_predictions(mut predictions: Vec<PredictionRecord>) -> Vec<PredictionRecord> {
    predictions.sort_by(|left, right| left.prediction_id.cmp(&right.prediction_id));
    predictions
}

fn deterministic_write_id(seed: &str) -> WriteId {
    let digest = blake3::hash(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}
