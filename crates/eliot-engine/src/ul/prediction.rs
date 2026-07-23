use crate::{EngineError, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind, ObservabilityWriteEnvelope,
    ObservabilityWriteReceipt, PredictionExpectation, PredictionRecord, PredictionResolution,
    ProjectId, SessionId, TaskId, VerificationResult, WriteId,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
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

pub struct PredictionService {
    store: CanonicalStore,
    writer: WriterHandle,
}

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
        let prediction_id = prediction_id(
            input.project_id,
            input.task_id,
            input.session_id,
            &input.packet_id,
            &verifier,
            expected,
            &input.source_frame_hash,
        );
        let record = PredictionRecord {
            prediction_id: prediction_id.clone(),
            project_id: input.project_id,
            task_id: input.task_id,
            session_id: input.session_id,
            subsystem_concept_id: input.subsystem_concept_id,
            packet_id: input.packet_id,
            verifier,
            expected,
            resolution: None,
            actual: None,
            verification_ref: None,
            source_frame_hash: input.source_frame_hash,
        };
        let receipt = self
            .write_record(
                deterministic_write_id(&format!("prediction-capture|{prediction_id}")),
                &record,
            )
            .await?;
        Ok(Some(PredictionCapture {
            prediction_ref: format!("prediction:{prediction_id}"),
            record,
            receipt,
        }))
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
        let verifier = normalize_verifier(verifier);
        let predictions = self
            .store
            .load_predictions(
                project_id,
                Some(task_id),
                Some(&verifier),
                true,
                Some(created_before),
            )
            .await?;
        let mut newest = BTreeMap::<(String, String), PredictionRecord>::new();
        for prediction in predictions {
            newest.insert(
                (prediction.packet_id.clone(), prediction.verifier.clone()),
                prediction,
            );
        }
        let mut resolved = Vec::new();
        for mut prediction in newest.into_values() {
            prediction.resolution = Some(resolve_prediction(prediction.expected, actual));
            prediction.actual = Some(actual);
            prediction.verification_ref = Some(verification_ref.to_owned());
            let write_id = deterministic_write_id(&format!(
                "prediction-resolution|{}|{verification_ref}|{:?}",
                prediction.prediction_id, actual
            ));
            self.write_record(write_id, &prediction).await?;
            resolved.push(prediction);
        }
        resolved.sort_by(|left, right| left.prediction_id.cmp(&right.prediction_id));
        Ok(resolved)
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
    let hit = matches!(
        (expected, actual),
        (PredictionExpectation::Pass, VerificationResult::Passed)
            | (PredictionExpectation::Fail, VerificationResult::Failed)
    );
    if hit {
        PredictionResolution::Hit
    } else {
        PredictionResolution::Miss
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
    let canonical = format!(
        "prediction|{project_id}|{task_id}|{session_id}|{packet_id}|{}|{:?}|{source_frame_hash}",
        normalize_verifier(verifier),
        expected
    );
    let digest = blake3::hash(canonical.as_bytes()).to_hex().to_string();
    format!("ul-prediction-{}", &digest[..32])
}

#[must_use]
pub fn normalize_verifier(verifier: &str) -> String {
    verifier.trim().to_owned()
}

fn deterministic_write_id(seed: &str) -> WriteId {
    let digest = blake3::hash(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}
