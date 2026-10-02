use crate::{MemoryRevision, ProjectId};
use serde::{Deserialize, Serialize};

pub const PROJECT_UNDERSTANDING_SCHEMA_VERSION: &str = "project-understanding-v1";

/// The named legacy `project-understanding` revisions this build still reads, each paired
/// with the current revision its bytes are read under.
///
/// Empty by evidence, not by omission: the only `project-understanding-v*` spelling in the
/// repository is [`PROJECT_UNDERSTANDING_SCHEMA_VERSION`], and it is the only value
/// `ProjectUnderstandingCompiler::compile` ever stamps, so no other revision has ever
/// been written. `I5.22` requires migration identity to be explicit and immutable after
/// release, so a legacy revision this build admits must be added here BY NAME together
/// with the migration that gives it meaning. It must never be inferred from the presence
/// of a `schema_version` string on decoded bytes.
pub const PROJECT_UNDERSTANDING_NAMED_LEGACY_MIGRATIONS: &[(&str, &str)] = &[];

/// Bounded refusal for a project-understanding schema version this build does not own.
///
/// A decoded model is consumed as current project proof: its intent, causal model and
/// predicted state drive packet continuity restore and the memory handles a packet
/// exposes. `deny_unknown_fields` closed only the shape. The message is fixed and never
/// echoes the received version back onto an operator surface, matching the control-wal
/// refusals in `runtime_supervision`.
fn unsupported_project_understanding_schema_version<E>(expected: &str) -> E
where
    E: serde::de::Error,
{
    E::custom(format!("unsupported schema version; expected {expected}"))
}

/// The one owner version-selection step for [`ProjectUnderstandingModel`].
///
/// `ProjectUnderstandingCompiler::compile` stamps
/// [`PROJECT_UNDERSTANDING_SCHEMA_VERSION`] when it CONSTRUCTS a model, but that says
/// nothing about a model read back from bytes. Every `Deserialize` of a model -- as a
/// `ContextPacketL3` field, as a `PacketCompileResult`/`PacketRenderOutcome` member, or
/// from any packet artifact file -- therefore selects the version as CONTENT of the
/// decoded document before the model exists. There is no second scheme and no per-caller
/// copy. A MISSING `schema_version` has no `serde(default)` and is refused by the
/// missing-field path.
fn select_project_understanding_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let declared = String::deserialize(deserializer)?;
    if declared == PROJECT_UNDERSTANDING_SCHEMA_VERSION
        || PROJECT_UNDERSTANDING_NAMED_LEGACY_MIGRATIONS
            .iter()
            .any(|(legacy, _)| *legacy == declared)
    {
        Ok(declared)
    } else {
        Err(unsupported_project_understanding_schema_version(
            PROJECT_UNDERSTANDING_SCHEMA_VERSION,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopKind {
    IntentToConcept,
    ConceptToOwner,
    OwnerToSymbol,
    SymbolToStateOrFlow,
    FlowToObservable,
    ObservableToVerifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopStatus {
    Verified,
    Supported,
    Assumed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalHop {
    pub hop_kind: CausalHopKind,
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_refs: Vec<String>,
    pub status: CausalHopStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingIntent {
    pub exact_user_goal_ref: String,
    pub normalized_goal: String,
    pub desired_state_transition: String,
    pub non_goals: Vec<String>,
    pub acceptance_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingSystem {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalModel {
    pub hops: Vec<ProjectCausalHop>,
    pub unknown_hops: Vec<CausalHopKind>,
    pub required_probes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcceptanceState {
    pub acceptance_ref: String,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityGitState {
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub current_diff_ref: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectContinuityState {
    pub exact_goal: String,
    pub acceptance_state: Vec<ContinuityAcceptanceState>,
    pub completed_items: Vec<String>,
    pub active_plan: Vec<String>,
    pub killed_or_paused_paths: Vec<String>,
    pub current_git: ContinuityGitState,
    pub current_truth_refs: Vec<String>,
    pub used_memory_refs: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub next_action: String,
    pub expected_observable: String,
    pub verifier: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingEvidence {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub invariant_refs: Vec<String>,
    pub danger_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub flow_evidence_refs: Vec<String>,
    pub non_goals: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingModel {
    /// Selected by [`select_project_understanding_schema_version`] at the decoder, so a
    /// model read from a packet artifact is version-checked at its real deserialization
    /// boundary rather than trusted because a `schema_version` string is present.
    #[serde(deserialize_with = "select_project_understanding_schema_version")]
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: String,
    pub revision_fence: MemoryRevision,
    pub intent: ProjectUnderstandingIntent,
    pub system: ProjectUnderstandingSystem,
    pub causal_model: ProjectCausalModel,
    pub invariants: Vec<String>,
    pub danger_and_negative_memory: Vec<String>,
    pub current_truth_refs: Vec<String>,
    pub historical_or_stale_refs: Vec<String>,
    pub memory_refs_used: Vec<String>,
    pub files_to_inspect: Vec<String>,
    pub files_to_change: Vec<String>,
    pub predicted_changed_paths: Vec<String>,
    pub predicted_failing_verifiers: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub stop_condition: String,
}

#[cfg(test)]
mod schema_version_selection {
    use super::*;

    /// One owner producer's exact wire form for a `ProjectUnderstandingModel`, carrying
    /// the current schema version and the evidence a consumer relies on.
    const MODEL: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "task-fixture-001",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/task-fixture-001@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [{
          "hop_kind": "intent_to_concept",
          "from": "intent:task-fixture-001",
          "relation": "scoped_to",
          "to": "concept:core",
          "evidence_refs": ["artifact:fixture-1"],
          "status": "supported"
        }],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    /// Replace only the declared version literal. The refused document is byte-for-byte
    /// otherwise identical and structurally well formed, so the refusal is proven to come
    /// from version selection and not from a shape rejection.
    fn with_version(document: &str, foreign: &str) -> String {
        document.replace(PROJECT_UNDERSTANDING_SCHEMA_VERSION, foreign)
    }

    /// Drop the declared version member entirely, so the refusal is proven to come from
    /// the missing-version path and not from a defaulted empty string.
    fn without_version(document: &str) -> String {
        document
            .lines()
            .filter(|line| !line.contains("\"schema_version\""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    // Positive case: the CURRENT schema version still decodes at the model's real
    // deserialization boundary, whether read directly or as the `project_understanding`
    // member of a `ContextPacketL3`, so current project proof is unchanged.
    #[test]
    fn current_schema_version_still_decodes_and_keeps_its_evidence() {
        let model: ProjectUnderstandingModel = match serde_json::from_str(MODEL) {
            Ok(model) => model,
            Err(error) => panic!("current-version model must decode: {error}"),
        };
        assert_eq!(model.schema_version, PROJECT_UNDERSTANDING_SCHEMA_VERSION);
        assert_eq!(model.task_id, "task-fixture-001");
        assert_eq!(model.intent.acceptance_refs, ["accept:fixture-1"]);
        assert_eq!(model.causal_model.hops.len(), 1);
        assert_eq!(model.causal_model.hops[0].status, CausalHopStatus::Supported);
        // The nested member form is the real ingress: a packet artifact carries the model
        // under `project_understanding`, and it is owner-checked by the same decoder.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PacketMember {
            project_understanding: Option<ProjectUnderstandingModel>,
        }
        let member = format!("{{\"project_understanding\": {MODEL} }}");
        match serde_json::from_str::<PacketMember>(&member) {
            Ok(packet) => assert_eq!(
                packet
                    .project_understanding
                    .map(|model| model.schema_version),
                Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION.to_owned())
            ),
            Err(error) => panic!("a current-version nested model must decode: {error}"),
        }
        assert!(
            serde_json::from_str::<PacketMember>(&format!(
                "{{\"project_understanding\": {}}}",
                with_version(MODEL, "project-understanding-v99")
            ))
            .is_err(),
            "a foreign nested model must not decode inside its owning packet either"
        );
    }

    // Refusal case: a well-formed but WRONG version and a MISSING version are both
    // refused at the decoder, so neither can be consumed as current project proof.
    #[test]
    fn unsupported_and_missing_schema_versions_are_refused_at_the_decoder() {
        let foreign = with_version(MODEL, "project-understanding-v99");
        let error = match serde_json::from_str::<ProjectUnderstandingModel>(&foreign) {
            Ok(_) => panic!("a foreign layout must not decode as current project understanding"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(PROJECT_UNDERSTANDING_SCHEMA_VERSION),
            "refusal must name the version this build owns, got: {error}"
        );
        let missing = without_version(MODEL);
        assert!(
            serde_json::from_str::<ProjectUnderstandingModel>(&missing).is_err(),
            "a missing schema_version must be refused, never defaulted into acceptance"
        );
    }
}
