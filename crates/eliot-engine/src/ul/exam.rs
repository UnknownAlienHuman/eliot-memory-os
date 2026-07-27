use super::dependency_refs;
use crate::{EngineError, WriterHandle};
use eliot_store::{CanonicalRecord, CanonicalStore};
use eliot_types::{
    CoChangeEdge, ConceptNode, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteStatus, ProjectCharter, ProjectId,
    PyramidTargetKind, SubsystemCapsule, SystemMap, TaskId, UlArtifactDirtyState, UlDependencyKind,
    UlDependencyRef, UlDirtyReason, UlExamAnswer, UlExamGrade, UlExamQuestion, UlExamQuestionKind,
    UlExamRecord, UlReasoningRequest, UlReasoningRoute, WriteId, normalize_observed_path,
    ul_token_estimate,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use time::OffsetDateTime;
use uuid::Uuid;

pub const UL_EXAM_MAX_SUBSYSTEMS: usize = 5;
pub const UL_EXAM_INPUT_BYTES: usize = 4_096;
pub const UL_EXAM_OUTPUT_TOKEN_UNITS: u32 = 800;
pub const UL_EXAM_QUESTION_PASS_MILLI: u16 = 600;
pub const UL_EXAM_DIRTY_MILLI: u16 = 500;
pub const UL_EXAM_WEEKDAY_SUNDAY: u8 = 7;
pub const UL_EXAM_LOCAL_HOUR: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UlReasoningOutcome {
    Completed(Vec<UlExamAnswer>),
    Unavailable(String),
    UnknownOutcome(String),
}

pub type BoxUlReasoningFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UlReasoningOutcome, EngineError>> + Send + 'a>>;

pub trait UlReasoningRunner: Send + Sync {
    fn run<'a>(&'a self, request: &'a UlReasoningRequest) -> BoxUlReasoningFuture<'a>;
}

#[derive(Clone, Debug)]
pub struct UlExamPlan {
    pub exam_id: String,
    pub project_id: ProjectId,
    pub questions: Vec<UlExamQuestion>,
    pub cold_input_refs: Vec<String>,
}

pub struct UlExamService {
    store: CanonicalStore,
    writer: WriterHandle,
}

impl UlExamService {
    #[must_use]
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        Self { store, writer }
    }

    pub async fn run(
        &self,
        project_id: ProjectId,
        route: UlReasoningRoute,
        runner: &dyn UlReasoningRunner,
    ) -> Result<UlExamRecord, EngineError> {
        let already_active = {
            let mut active = active_exam_projects()
                .lock()
                .map_err(|_| EngineError::WriteRejected("UL exam lock is poisoned".to_owned()))?;
            !active.insert(project_id)
        };
        if already_active {
            return self
                .write_skipped(
                    project_id,
                    route,
                    "skipped_overlap",
                    "another exam is active for this project",
                )
                .await;
        }
        let result = self.run_inner(project_id, route, runner).await;
        if let Ok(mut active) = active_exam_projects().lock() {
            active.remove(&project_id);
        }
        result
    }

    #[allow(clippy::too_many_lines)]
    async fn run_inner(
        &self,
        project_id: ProjectId,
        route: UlReasoningRoute,
        runner: &dyn UlReasoningRunner,
    ) -> Result<UlExamRecord, EngineError> {
        let concepts = latest_by(
            self.store
                .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 512)
                .await?,
            |concept| concept.concept_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        let capsules = latest_by(
            self.store
                .load_ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"], 512)
                .await?,
            |capsule| capsule.concept_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        if concepts.len() < 3 || capsules.len() < 3 {
            return self
                .write_skipped(
                    project_id,
                    route,
                    "skipped_insufficient_graph",
                    "weekly exam requires at least three concepts and three capsules",
                )
                .await;
        }
        let edges = latest_by(
            self.store
                .load_ul_artifacts::<CoChangeEdge>(project_id, &["co_change_edge"], 512)
                .await?,
            |edge| edge.edge_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        let previous = self
            .store
            .observability_records_by_kind::<UlExamRecord>(
                project_id,
                None,
                ObservabilityKind::ExamRecord,
            )
            .await?;
        let charter = latest_single(
            self.store
                .load_ul_artifacts::<ProjectCharter>(project_id, &["project_charter"], 128)
                .await?,
        );
        let map = latest_single(
            self.store
                .load_ul_artifacts::<SystemMap>(project_id, &["system_map"], 128)
                .await?,
        );
        let cold_input_refs = [
            charter
                .as_ref()
                .map(|value| format!("charter:{}", value.charter_id)),
            map.as_ref().map(|value| format!("map:{}", value.map_id)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let mut plan = build_exam_plan(
            project_id,
            &concepts,
            &capsules,
            &edges,
            &previous,
            cold_input_refs,
        );
        plan.exam_id = weekly_exam_id(&plan.exam_id);
        let request = build_cold_exam_request(
            &plan,
            route,
            charter.as_ref().map(|value| value.body_md.as_str()),
            map.as_ref().map(|value| value.body_md.as_str()),
        );
        let outcome = invoke_reasoner_once(runner, &request).await?;
        let answers = match outcome {
            UlReasoningOutcome::Completed(answers)
                if ul_token_estimate(&serde_json::to_string(&answers)?)
                    <= UL_EXAM_OUTPUT_TOKEN_UNITS =>
            {
                answers
            }
            UlReasoningOutcome::Completed(_) => {
                return self
                    .write_skipped(
                        project_id,
                        route,
                        "skipped_invalid_output",
                        "host output exceeded 800 token units",
                    )
                    .await;
            }
            UlReasoningOutcome::Unavailable(reason) => {
                return self
                    .write_skipped(project_id, route, "skipped_provider_unavailable", &reason)
                    .await;
            }
            UlReasoningOutcome::UnknownOutcome(reason) => {
                return self
                    .write_skipped(project_id, route, "unknown_outcome", &reason)
                    .await;
            }
        };
        let (grades, subsystem_scores_milli) = grade_exam(&plan, &answers);
        let dirty_capsule_refs = failed_capsule_refs(&subsystem_scores_milli, &capsules);
        let record = UlExamRecord {
            exam_id: plan.exam_id,
            project_id,
            route: route.as_str().to_owned(),
            cold_input_refs: plan.cold_input_refs,
            questions: plan.questions,
            answers,
            grades,
            subsystem_scores_milli,
            dirty_capsule_refs,
        };
        self.write_record(&record).await?;
        self.mark_failed_capsules(
            project_id,
            &record.exam_id,
            &record.subsystem_scores_milli,
            &capsules,
        )
        .await?;
        Ok(record)
    }

    async fn write_skipped(
        &self,
        project_id: ProjectId,
        route: UlReasoningRoute,
        status: &str,
        reason: &str,
    ) -> Result<UlExamRecord, EngineError> {
        let exam_id = deterministic_id(&format!(
            "ul-exam-skipped|{project_id}|{}|{status}|{}",
            route.as_str(),
            current_exam_window()
        ));
        let record = UlExamRecord {
            exam_id,
            project_id,
            route: format!("{status}:{}", route.as_str()),
            cold_input_refs: vec![format!("reason:{reason}")],
            questions: Vec::new(),
            answers: Vec::new(),
            grades: Vec::new(),
            subsystem_scores_milli: Vec::new(),
            dirty_capsule_refs: Vec::new(),
        };
        self.write_record(&record).await?;
        Ok(record)
    }

    async fn write_record(&self, record: &UlExamRecord) -> Result<(), EngineError> {
        let payload = serde_json::to_value(record)?;
        let input_hash = blake3::hash(&serde_json::to_vec(&payload)?)
            .to_hex()
            .to_string();
        let receipt = self
            .writer
            .submit_observability(ObservabilityWriteEnvelope {
                schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
                write_id: deterministic_write_id(&format!("ul-exam|{}", record.exam_id)),
                project_id: record.project_id,
                task_id: None,
                session_id: None,
                kind: ObservabilityKind::ExamRecord,
                record_id: record.exam_id.clone(),
                payload,
                input_hash,
                created_at: OffsetDateTime::now_utc(),
            })
            .await?;
        if receipt.status == ObservabilityWriteStatus::Rejected {
            return Err(EngineError::ObservabilityConflict);
        }
        Ok(())
    }

    async fn mark_failed_capsules(
        &self,
        project_id: ProjectId,
        exam_id: &str,
        scores: &[(String, u16)],
        capsules: &[SubsystemCapsule],
    ) -> Result<Vec<String>, EngineError> {
        let now = OffsetDateTime::now_utc();
        let capsules = capsules
            .iter()
            .map(|capsule| (capsule.concept_id.as_str(), capsule))
            .collect::<BTreeMap<_, _>>();
        let mut dirty_refs = Vec::new();
        for (concept_id, score) in scores {
            if *score >= UL_EXAM_DIRTY_MILLI {
                continue;
            }
            let Some(capsule) = capsules.get(concept_id.as_str()) else {
                continue;
            };
            let report_dependency = UlDependencyRef {
                kind: UlDependencyKind::Report,
                key: format!("exam:{exam_id}"),
            };
            let mut dependencies = dependency_refs(&capsule.dependency_manifest);
            dependencies.push(report_dependency.clone());
            self.store
                .replace_ul_reverse_dependencies(
                    project_id,
                    PyramidTargetKind::SubsystemCapsule,
                    concept_id,
                    &capsule.build_id,
                    &dependencies,
                )
                .await?;
            self.store
                .mark_ul_artifact_dirty(&UlArtifactDirtyState {
                    project_id,
                    target_kind: PyramidTargetKind::SubsystemCapsule,
                    target_id: concept_id.clone(),
                    build_id: capsule.build_id.clone(),
                    dirty: true,
                    reasons: vec![UlDirtyReason {
                        dependency: report_dependency,
                        expected_fingerprint: None,
                        observed_fingerprint: Some(score.to_string()),
                        event_ref: format!("exam:{exam_id}"),
                    }],
                    first_dirty_at: now,
                    updated_at: now,
                })
                .await?;
            dirty_refs.push(format!("capsule:{}", capsule.capsule_id));
        }
        Ok(dirty_refs)
    }
}

fn active_exam_projects() -> &'static Mutex<HashSet<ProjectId>> {
    static ACTIVE_PROJECTS: OnceLock<Mutex<HashSet<ProjectId>>> = OnceLock::new();
    ACTIVE_PROJECTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn current_exam_window() -> String {
    let (year, week, _) = OffsetDateTime::now_utc().date().to_iso_week_date();
    format!("{year}-W{week:02}")
}

fn weekly_exam_id(base_exam_id: &str) -> String {
    deterministic_id(&format!(
        "ul-exam-window|{base_exam_id}|{}",
        current_exam_window()
    ))
}

#[must_use]
pub fn build_exam_plan(
    project_id: ProjectId,
    concepts: &[ConceptNode],
    capsules: &[SubsystemCapsule],
    edges: &[CoChangeEdge],
    previous_exams: &[UlExamRecord],
    cold_input_refs: Vec<String>,
) -> UlExamPlan {
    let capsule_ids = capsules
        .iter()
        .map(|capsule| capsule.concept_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut last_exam = BTreeMap::<String, usize>::new();
    for (index, exam) in previous_exams.iter().enumerate() {
        for question in &exam.questions {
            last_exam.insert(question.subsystem_concept_id.clone(), index + 1);
        }
    }
    let mut concepts = concepts
        .iter()
        .filter(|concept| capsule_ids.contains(concept.concept_id.as_str()))
        .collect::<Vec<_>>();
    concepts.sort_by(|left, right| {
        activity(right)
            .cmp(&activity(left))
            .then_with(|| {
                last_exam
                    .get(&left.concept_id)
                    .copied()
                    .unwrap_or_default()
                    .cmp(
                        &last_exam
                            .get(&right.concept_id)
                            .copied()
                            .unwrap_or_default(),
                    )
            })
            .then_with(|| left.concept_id.cmp(&right.concept_id))
    });
    concepts.truncate(UL_EXAM_MAX_SUBSYSTEMS);
    let mut questions = Vec::new();
    for concept in concepts {
        let blast = blast_ground_truth(concept, capsules, edges);
        let invariants = invariant_ground_truth(concept);
        let entrypoints = normalized_references(&concept.entrypoint_refs);
        for (kind, label, prompt, values, refs) in [
            (
                UlExamQuestionKind::Blast,
                "blast",
                format!(
                    "For subsystem `{}`, list its depth-1 blast radius.",
                    concept.name
                ),
                blast.0,
                blast.1,
            ),
            (
                UlExamQuestionKind::Invariant,
                "invariant",
                format!(
                    "Name the governing invariant for subsystem `{}`.",
                    concept.name
                ),
                invariants.0,
                invariants.1,
            ),
            (
                UlExamQuestionKind::Entrypoint,
                "entrypoint",
                format!(
                    "Name the canonical entrypoint for subsystem `{}`.",
                    concept.name
                ),
                entrypoints.clone(),
                entrypoints,
            ),
        ] {
            questions.push(UlExamQuestion {
                question_id: deterministic_id(&format!(
                    "ul-exam-question|{project_id}|{}|{label}",
                    concept.concept_id
                )),
                project_id,
                subsystem_concept_id: concept.concept_id.clone(),
                kind,
                prompt,
                ground_truth_refs: refs,
                ground_truth_values: values,
            });
        }
    }
    let identity = format!(
        "{project_id}|{}",
        questions
            .iter()
            .map(|question| question.question_id.as_str())
            .collect::<Vec<_>>()
            .join("|")
    );
    UlExamPlan {
        exam_id: deterministic_id(&format!("ul-exam|{identity}")),
        project_id,
        questions,
        cold_input_refs,
    }
}

#[must_use]
pub fn grade_exam(
    plan: &UlExamPlan,
    answers: &[UlExamAnswer],
) -> (Vec<UlExamGrade>, Vec<(String, u16)>) {
    let answers = answers
        .iter()
        .map(|answer| (answer.question_id.as_str(), answer))
        .collect::<BTreeMap<_, _>>();
    let mut grades = Vec::new();
    let mut subsystem = BTreeMap::<String, Vec<u16>>::new();
    for question in &plan.questions {
        let actual = answers
            .get(question.question_id.as_str())
            .map_or_else(Vec::new, |answer| answer.answer_values.clone());
        let grade = precision_recall_f1(
            &question.question_id,
            &actual,
            &question.ground_truth_values,
        );
        subsystem
            .entry(question.subsystem_concept_id.clone())
            .or_default()
            .push(grade.f1_milli);
        grades.push(grade);
    }
    let scores = subsystem
        .into_iter()
        .map(|(concept_id, scores)| {
            let sum = scores.iter().map(|score| u32::from(*score)).sum::<u32>();
            let mean =
                u16::try_from(sum / u32::try_from(scores.len()).unwrap_or(1)).unwrap_or(1_000);
            (concept_id, mean)
        })
        .collect();
    (grades, scores)
}

#[must_use]
pub fn build_cold_exam_request(
    plan: &UlExamPlan,
    route: UlReasoningRoute,
    charter: Option<&str>,
    map: Option<&str>,
) -> UlReasoningRequest {
    let mut request = UlReasoningRequest {
        idempotency_key: plan.exam_id.clone(),
        project_id: plan.project_id,
        task_id: deterministic_task_id(&plan.exam_id),
        route,
        model: None,
        prompt: exam_prompt(charter, map, &plan.questions, UL_EXAM_INPUT_BYTES),
        output_schema: json!({
            "type": "object",
            "required": ["answers"],
            "properties": {
                "answers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["question_id", "answer_values", "cited_refs"]
                    }
                }
            }
        }),
        max_input_bytes: u32::try_from(UL_EXAM_INPUT_BYTES).unwrap_or(u32::MAX),
        max_output_units: UL_EXAM_OUTPUT_TOKEN_UNITS,
        timeout_seconds: 120,
    };
    while serde_json::to_vec(&request).map_or(0, |bytes| bytes.len()) > UL_EXAM_INPUT_BYTES {
        let Some(prefix) = request.prompt.strip_suffix(EXAM_OUTPUT_INSTRUCTION) else {
            break;
        };
        if prefix.is_empty() {
            break;
        }
        let excess = serde_json::to_vec(&request)
            .map_or(1, |bytes| bytes.len().saturating_sub(UL_EXAM_INPUT_BYTES))
            .max(1);
        let mut prefix = prefix.to_owned();
        let retained = prefix.len().saturating_sub(excess);
        truncate_utf8(&mut prefix, retained);
        request.prompt = format!("{prefix}{EXAM_OUTPUT_INSTRUCTION}");
    }
    request
}

pub async fn invoke_reasoner_once(
    runner: &dyn UlReasoningRunner,
    request: &UlReasoningRequest,
) -> Result<UlReasoningOutcome, EngineError> {
    runner.run(request).await
}

#[must_use]
pub fn precision_recall_f1(
    question_id: &str,
    actual: &[String],
    expected: &[String],
) -> UlExamGrade {
    let actual = normalized_set(actual);
    let expected = normalized_set(expected);
    let intersection = u32::try_from(actual.intersection(&expected).count()).unwrap_or(u32::MAX);
    let precision_den = u32::try_from(actual.len()).unwrap_or(u32::MAX);
    let recall_den = u32::try_from(expected.len()).unwrap_or(u32::MAX);
    let (precision_num, recall_num, f1_milli) = if actual.is_empty() && expected.is_empty() {
        (1, 1, 1_000)
    } else {
        let denominator = u64::from(precision_den) * u64::from(intersection)
            + u64::from(recall_den) * u64::from(intersection);
        let numerator = 2 * u64::from(intersection) * u64::from(intersection) * 1_000;
        let f1 =
            u16::try_from(numerator.checked_div(denominator).unwrap_or_default()).unwrap_or(1_000);
        (intersection, intersection, f1)
    };
    UlExamGrade {
        question_id: question_id.to_owned(),
        precision_num,
        precision_den: if actual.is_empty() && expected.is_empty() {
            1
        } else {
            precision_den
        },
        recall_num,
        recall_den: if actual.is_empty() && expected.is_empty() {
            1
        } else {
            recall_den
        },
        f1_milli,
    }
}

#[must_use]
pub fn normalize_exam_reference(value: &str) -> String {
    let value = value.trim().replace('\\', "/");
    if value.contains('/') || value.starts_with("file:") {
        normalize_observed_path(&value)
    } else {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    }
}

#[must_use]
pub const fn weekly_exam_route(iso_week: u8) -> UlReasoningRoute {
    if iso_week.is_multiple_of(2) {
        UlReasoningRoute::Claude
    } else {
        UlReasoningRoute::Antigravity
    }
}

#[must_use]
pub const fn weekly_exam_due(local_weekday: u8, local_hour: u8) -> bool {
    local_weekday == UL_EXAM_WEEKDAY_SUNDAY && local_hour == UL_EXAM_LOCAL_HOUR
}

#[derive(Serialize)]
struct ColdQuestion {
    question_id: String,
    subsystem_concept_id: String,
    kind: UlExamQuestionKind,
    prompt: String,
}

const EXAM_OUTPUT_INSTRUCTION: &str = "\n\nOUTPUT JSON SCHEMA\n{\"answers\":[{\"question_id\":\"...\",\"answer_values\":[\"...\"],\"cited_refs\":[\"...\"]}]}";

fn exam_prompt(
    charter: Option<&str>,
    map: Option<&str>,
    questions: &[UlExamQuestion],
    max_bytes: usize,
) -> String {
    let mut cold_questions = questions
        .iter()
        .map(|question| ColdQuestion {
            question_id: question.question_id.clone(),
            subsystem_concept_id: question.subsystem_concept_id.clone(),
            kind: question.kind,
            prompt: question.prompt.clone(),
        })
        .collect::<Vec<_>>();
    let mut serialized_questions =
        serde_json::to_string(&cold_questions).unwrap_or_else(|_| "[]".to_owned());
    let framing_bytes = "CHARTER\n".len()
        + "\n\nSYSTEM MAP\n".len()
        + "\n\nQUESTIONS\n".len()
        + EXAM_OUTPUT_INSTRUCTION.len();
    while framing_bytes + serialized_questions.len() > max_bytes
        && let Some(question) = cold_questions
            .iter_mut()
            .filter(|question| !question.prompt.is_empty())
            .max_by_key(|question| question.prompt.len())
    {
        let excess = (framing_bytes + serialized_questions.len()).saturating_sub(max_bytes);
        let retained = question.prompt.len().saturating_sub(excess.max(16));
        truncate_utf8(&mut question.prompt, retained);
        serialized_questions =
            serde_json::to_string(&cold_questions).unwrap_or_else(|_| "[]".to_owned());
    }
    let prose_budget = max_bytes.saturating_sub(framing_bytes + serialized_questions.len());
    let mut charter = charter.unwrap_or("unavailable").to_owned();
    let mut map = map.unwrap_or("unavailable").to_owned();
    truncate_utf8(&mut charter, prose_budget / 2);
    truncate_utf8(&mut map, prose_budget.saturating_sub(charter.len()));
    format!(
        "CHARTER\n{charter}\n\nSYSTEM MAP\n{map}\n\nQUESTIONS\n{serialized_questions}{EXAM_OUTPUT_INSTRUCTION}"
    )
}

fn failed_capsule_refs(scores: &[(String, u16)], capsules: &[SubsystemCapsule]) -> Vec<String> {
    let known = capsules
        .iter()
        .map(|capsule| (capsule.concept_id.as_str(), capsule.capsule_id.as_str()))
        .collect::<BTreeMap<_, _>>();
    scores
        .iter()
        .filter_map(|(concept_id, score)| {
            (*score < UL_EXAM_DIRTY_MILLI)
                .then(|| known.get(concept_id.as_str()).copied())
                .flatten()
        })
        .map(|capsule_id| format!("capsule:{capsule_id}"))
        .collect()
}

fn blast_ground_truth(
    concept: &ConceptNode,
    capsules: &[SubsystemCapsule],
    edges: &[CoChangeEdge],
) -> (Vec<String>, Vec<String>) {
    let mut values = concept.boundary_paths.clone();
    let mut refs = Vec::new();
    for edge in edges {
        if concept
            .boundary_paths
            .iter()
            .any(|boundary| eliot_types::path_matches_boundary(&edge.path_a, boundary))
            && edge.confidence_ab >= 0.6
        {
            values.push(edge.path_b.clone());
            refs.push(format!("edge:{}", edge.edge_id));
        }
        if concept
            .boundary_paths
            .iter()
            .any(|boundary| eliot_types::path_matches_boundary(&edge.path_b, boundary))
            && edge.confidence_ba >= 0.6
        {
            values.push(edge.path_a.clone());
            refs.push(format!("edge:{}", edge.edge_id));
        }
    }
    if let Some(capsule) = capsules
        .iter()
        .find(|capsule| capsule.concept_id == concept.concept_id)
    {
        values.extend(
            capsule
                .dependency_manifest
                .file_deps
                .iter()
                .map(|dependency| dependency.path.clone()),
        );
        refs.extend(
            capsule
                .source_refs
                .iter()
                .filter(|reference| reference.contains("verifier"))
                .cloned(),
        );
    }
    (normalized_references(&values), normalized_references(&refs))
}

fn invariant_ground_truth(concept: &ConceptNode) -> (Vec<String>, Vec<String>) {
    let mut values = Vec::new();
    for reference in &concept.invariant_refs {
        if let Some(title) = reference.rsplit([':', '#', '/']).next() {
            values.push(title.to_owned());
        }
    }
    (
        normalized_references(&values),
        normalized_references(&concept.invariant_refs),
    )
}

fn normalized_references(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| normalize_exam_reference(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn normalized_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| normalize_exam_reference(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn activity(concept: &ConceptNode) -> usize {
    concept
        .source_refs
        .len()
        .saturating_add(concept.hotspot_refs.len())
        .saturating_add(concept.boundary_paths.len())
        .saturating_add(concept.entrypoint_refs.len())
}

fn latest_by<T, F>(records: Vec<CanonicalRecord<T>>, key: F) -> BTreeMap<String, T>
where
    F: Fn(&T) -> String,
{
    let mut selected = BTreeMap::<String, CanonicalRecord<T>>::new();
    for record in records {
        let identity = key(&record.receipt_body);
        let revision = record
            .memory_revision
            .map_or(0, eliot_types::MemoryRevision::value);
        if selected.get(&identity).is_none_or(|current| {
            revision
                > current
                    .memory_revision
                    .map_or(0, eliot_types::MemoryRevision::value)
        }) {
            selected.insert(identity, record);
        }
    }
    selected
        .into_iter()
        .map(|(key, record)| (key, record.receipt_body))
        .collect()
}

fn latest_single<T>(records: Vec<CanonicalRecord<T>>) -> Option<T> {
    records
        .into_iter()
        .max_by_key(|record| {
            record
                .memory_revision
                .map_or(0, eliot_types::MemoryRevision::value)
        })
        .map(|record| record.receipt_body)
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
}

fn deterministic_id(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex()[..32].to_owned()
}

fn deterministic_task_id(seed: &str) -> TaskId {
    let digest = blake3::hash(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    TaskId::from_uuid(Uuid::from_bytes(bytes))
}

fn deterministic_write_id(seed: &str) -> WriteId {
    let digest = blake3::hash(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(Uuid::from_bytes(bytes))
}
