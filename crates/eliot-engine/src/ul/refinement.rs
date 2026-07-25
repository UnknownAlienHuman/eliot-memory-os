use super::{UlArtifactWriterService, UlDependencyService};
use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    CapsuleBuild, PyramidBuildStatus, PyramidTargetKind, SubsystemCapsule, TaskId, UlArtifact,
    UlReasoningRequest, UlReasoningRoute, ul_token_estimate,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

pub const UL_REFINEMENT_INPUT_BYTES: usize = 4_096;
pub const UL_REFINEMENT_OUTPUT_TOKEN_UNITS: u32 = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UlRefinementTrigger {
    ExamFailure,
    DegradedProse,
    ExplicitMaintain,
}

impl UlRefinementTrigger {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExamFailure => "exam_failure",
            Self::DegradedProse => "degraded_prose",
            Self::ExplicitMaintain => "explicit_maintain",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UlRefinementAnchor {
    pub anchor_id: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UlRefinementOutcome {
    Completed(String),
    Unavailable(String),
    UnknownOutcome(String),
}

pub type BoxUlRefinementFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UlRefinementOutcome, EngineError>> + Send + 'a>>;

pub trait UlRefinementRunner: Send + Sync {
    fn run<'a>(&'a self, request: &'a UlReasoningRequest) -> BoxUlRefinementFuture<'a>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UlRefinementResult {
    pub capsule: SubsystemCapsule,
    pub build: CapsuleBuild,
    pub used_fallback: bool,
    pub route: UlReasoningRoute,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UlRefinedProse {
    pub purpose: String,
    pub boundaries: String,
}

pub struct UlRefinementService {
    store: CanonicalStore,
    writer: WriterHandle,
}

impl UlRefinementService {
    #[must_use]
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        Self { store, writer }
    }

    pub async fn refine(
        &self,
        capsule: &SubsystemCapsule,
        trigger: UlRefinementTrigger,
        route: UlReasoningRoute,
        anchors: &[UlRefinementAnchor],
        runner: &dyn UlRefinementRunner,
    ) -> Result<UlRefinementResult, EngineError> {
        let request = refinement_request(capsule, trigger, route, anchors)?;
        let outcome = runner.run(&request).await?;
        let (candidate, used_fallback, reason) = match outcome {
            UlRefinementOutcome::Completed(output) => {
                if let Some(candidate) = validate_refinement_candidate(&output, anchors) {
                    (Some(candidate), false, None)
                } else {
                    (
                        None,
                        true,
                        Some("invalid refinement output; deterministic fallback used".to_owned()),
                    )
                }
            }
            UlRefinementOutcome::Unavailable(reason)
            | UlRefinementOutcome::UnknownOutcome(reason) => (None, true, Some(reason)),
        };
        let result = refine_capsule_prose(capsule, trigger, route, anchors, candidate.as_ref())?;
        UlArtifactWriterService
            .write_pyramid_target(
                &self.writer,
                &WriteAdmissionService,
                &format!("ul-refinement-{}", capsule.concept_id),
                UlArtifact::SubsystemCapsule(result.capsule.clone()),
                result.build.clone(),
            )
            .await?;
        UlDependencyService::new(self.store.clone())
            .index_capsule(&result.capsule)
            .await?;
        let dirty = self
            .store
            .load_ul_dirty_artifacts(capsule.project_id, 512)
            .await?
            .into_iter()
            .find(|state| {
                state.target_kind == PyramidTargetKind::SubsystemCapsule
                    && state.target_id == capsule.concept_id
            });
        let prose_only_dirty = dirty.as_ref().is_none_or(|state| {
            state
                .reasons
                .iter()
                .all(|reason| reason.dependency.kind == eliot_types::UlDependencyKind::Report)
        });
        if prose_only_dirty {
            self.store
                .clear_ul_artifact_dirty(
                    capsule.project_id,
                    PyramidTargetKind::SubsystemCapsule,
                    &capsule.concept_id,
                    &result.capsule.build_id,
                )
                .await?;
        }
        Ok(UlRefinementResult {
            used_fallback,
            reason,
            ..result
        })
    }
}

#[must_use]
pub fn refinement_route(build_id: &str) -> UlReasoningRoute {
    let parity = build_id
        .bytes()
        .rev()
        .find_map(|byte| (byte as char).to_digit(16))
        .unwrap_or_default();
    if parity % 2 == 0 {
        UlReasoningRoute::Claude
    } else {
        UlReasoningRoute::Antigravity
    }
}

fn refinement_request(
    capsule: &SubsystemCapsule,
    trigger: UlRefinementTrigger,
    route: UlReasoningRoute,
    anchors: &[UlRefinementAnchor],
) -> Result<UlReasoningRequest, EngineError> {
    let (current_purpose, current_boundaries, deterministic_sections) =
        split_prose_sections(&capsule.body_md)?;
    let mut paths = capsule
        .dependency_manifest
        .file_deps
        .iter()
        .map(|dependency| dependency.path.clone())
        .chain(
            capsule
                .source_refs
                .iter()
                .filter_map(|reference| reference.strip_prefix("file:").map(str::to_owned)),
        )
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths.truncate(15);
    let mut anchors = anchors.to_vec();
    anchors.sort_by(|left, right| left.anchor_id.cmp(&right.anchor_id));
    let anchor_rows = anchors
        .iter()
        .map(|anchor| format!("[a:{}] {}", anchor.anchor_id, anchor.text))
        .collect::<Vec<_>>()
        .join("\n");
    let allowed_anchor_ids = anchors
        .iter()
        .map(|anchor| format!("a:{}", anchor.anchor_id))
        .collect::<Vec<_>>()
        .join(",");
    let suffix = format!(
        "\n\nALLOWED ANCHOR IDS\n{allowed_anchor_ids}\n\nANCHOR EVIDENCE\n{anchor_rows}\n\nReturn exactly one JSON object with no other fields or prose:\n{{\"purpose\":\"...\",\"boundaries\":\"...\"}}"
    );
    let mut prefix = format!(
        "Rewrite only PURPOSE and BOUNDARIES. Use operative statements only. Every load-bearing sentence must cite an allowed [a:<id>].\nTRIGGER {}\nCONCEPT NAME {}\nCONCEPT PURPOSE {}\nPATHS\n{}\n\nCURRENT PURPOSE\n{}\n\nCURRENT BOUNDARIES\n{}\n\nEXISTING DETERMINISTIC SECTIONS\n{}",
        trigger.as_str(),
        capsule.concept_id,
        current_purpose,
        paths.join("\n"),
        current_purpose,
        current_boundaries.join("\n"),
        deterministic_sections,
    );
    truncate_utf8(
        &mut prefix,
        UL_REFINEMENT_INPUT_BYTES.saturating_sub(suffix.len()),
    );
    let prompt = format!("{prefix}{suffix}");
    Ok(UlReasoningRequest {
        idempotency_key: deterministic_id(&format!(
            "ul-refinement|{}|{}|{}|{}",
            capsule.project_id,
            capsule.capsule_id,
            capsule.build_id,
            trigger.as_str()
        )),
        project_id: capsule.project_id,
        task_id: deterministic_task_id(&format!("ul-refinement-{}", capsule.concept_id)),
        route,
        prompt,
        output_schema: json!({
            "type": "object",
            "required": ["purpose", "boundaries"],
            "properties": {
                "purpose": {"type": "string"},
                "boundaries": {"type": "string"}
            },
            "additionalProperties": false
        }),
        max_input_bytes: u32::try_from(UL_REFINEMENT_INPUT_BYTES).unwrap_or(u32::MAX),
        max_output_units: UL_REFINEMENT_OUTPUT_TOKEN_UNITS,
        timeout_seconds: 120,
    })
}

pub fn refine_capsule_prose(
    capsule: &SubsystemCapsule,
    trigger: UlRefinementTrigger,
    route: UlReasoningRoute,
    anchors: &[UlRefinementAnchor],
    candidate: Option<&UlRefinedProse>,
) -> Result<UlRefinementResult, EngineError> {
    let (current_purpose, current_boundaries, suffix) = split_prose_sections(&capsule.body_md)?;
    let fallback = UlRefinedProse {
        purpose: current_purpose,
        boundaries: current_boundaries.join("\n"),
    };
    let candidate = candidate.unwrap_or(&fallback);
    let body_md = format!(
        "PURPOSE\n{}\n\nBOUNDARIES\n{}\n\n{}",
        candidate.purpose.trim(),
        candidate
            .boundaries
            .lines()
            .map(|boundary| {
                let boundary = boundary.trim();
                if boundary.starts_with("- ") {
                    boundary.to_owned()
                } else {
                    format!("- {boundary}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        suffix
    );
    let mut refined = capsule.clone();
    refined.body_md = body_md;
    let anchor_refs = anchors
        .iter()
        .map(|anchor| format!("a:{}", anchor.anchor_id))
        .collect::<Vec<_>>();
    refined
        .dependency_manifest
        .report_deps
        .extend(anchor_refs.clone());
    refined.dependency_manifest.report_deps.sort();
    refined.dependency_manifest.report_deps.dedup();
    let inputs_hash = blake3::hash(
        serde_json::to_string(&(
            capsule.project_id,
            &capsule.capsule_id,
            &refined.body_md,
            &refined.dependency_manifest,
            trigger.as_str(),
            route,
        ))?
        .as_bytes(),
    )
    .to_hex()
    .to_string();
    let build_id = deterministic_id(&format!(
        "ul-refinement-build|{}|{}|{}",
        capsule.project_id, capsule.build_id, inputs_hash
    ));
    refined.build_id.clone_from(&build_id);
    Ok(UlRefinementResult {
        capsule: refined,
        build: CapsuleBuild {
            build_id,
            project_id: capsule.project_id,
            target_kind: PyramidTargetKind::SubsystemCapsule,
            target_id: capsule.capsule_id.clone(),
            inputs_hash,
            anchor_validation: anchor_refs,
            budget_limit: UL_REFINEMENT_OUTPUT_TOKEN_UNITS,
            token_estimate: ul_token_estimate(&candidate.purpose)
                .saturating_add(ul_token_estimate(&candidate.boundaries)),
            status: PyramidBuildStatus::Promoted,
            previous_build_id: Some(capsule.build_id.clone()),
        },
        used_fallback: candidate.purpose == fallback.purpose
            && candidate.boundaries == fallback.boundaries,
        route,
        reason: None,
    })
}

pub fn validate_refinement_candidate(
    output: &str,
    anchors: &[UlRefinementAnchor],
) -> Option<UlRefinedProse> {
    let candidate: UlRefinedProse = serde_json::from_str(output).ok()?;
    if candidate.purpose.trim().is_empty() || candidate.boundaries.trim().is_empty() {
        return None;
    }
    if ul_token_estimate(&candidate.purpose)
        .saturating_add(ul_token_estimate(&candidate.boundaries))
        > UL_REFINEMENT_OUTPUT_TOKEN_UNITS
    {
        return None;
    }
    let allowed = anchors
        .iter()
        .map(|anchor| format!("[a:{}]", anchor.anchor_id))
        .collect::<Vec<_>>();
    let prose = format!("{}\n{}", candidate.purpose, candidate.boundaries);
    if prose
        .split(['.', '!', '?', '\n'])
        .map(str::trim)
        .filter(|claim| !claim.is_empty())
        .any(|claim| !allowed.iter().any(|citation| claim.contains(citation)))
    {
        return None;
    }
    Some(candidate)
}

fn split_prose_sections(body: &str) -> Result<(String, Vec<String>, String), EngineError> {
    let purpose = body
        .strip_prefix("PURPOSE\n")
        .ok_or_else(|| EngineError::WriteRejected("capsule PURPOSE section missing".to_owned()))?;
    let (purpose, remainder) = purpose.split_once("\n\nBOUNDARIES\n").ok_or_else(|| {
        EngineError::WriteRejected("capsule BOUNDARIES section missing".to_owned())
    })?;
    let (boundaries, suffix) = remainder.split_once("\n\nKEY ENTRYPOINTS").ok_or_else(|| {
        EngineError::WriteRejected("capsule KEY ENTRYPOINTS section missing".to_owned())
    })?;
    let mut boundaries = boundaries
        .lines()
        .map(|line| line.trim_start_matches("- ").to_owned())
        .collect::<Vec<_>>();
    boundaries.sort();
    boundaries.dedup();
    Ok((
        purpose.to_owned(),
        boundaries,
        format!("KEY ENTRYPOINTS{suffix}"),
    ))
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
    let digest = blake3::hash(seed.as_bytes()).to_hex().to_string();
    digest[..32].to_owned()
}

fn deterministic_task_id(seed: &str) -> TaskId {
    let digest = blake3::hash(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    TaskId::from_uuid(Uuid::from_bytes(bytes))
}
