use crate::{
    ForgettingOperator, MemoryLifecycleState, MemoryRevision, ProjectId, ProjectSequence, TaskId,
    WriteReceiptRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

/// Deserialize a map while refusing a repeated key before insertion.
///
/// Derived map decoding keeps the last entry and silently drops earlier
/// ones, so a lexical duplicate would rewrite a signal or tier count without
/// evidence. Every valid single-key encoding decodes exactly as before.
fn deserialize_strict_btree_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct StrictMapVisitor<K, V>(PhantomData<fn() -> BTreeMap<K, V>>);

    impl<'de, K, V> de::Visitor<'de> for StrictMapVisitor<K, V>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<BTreeMap<K, V>, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some(key) = access.next_key::<K>()? {
                if values.contains_key(&key) {
                    return Err(de::Error::custom("duplicate map key"));
                }
                let value = access.next_value::<V>()?;
                values.insert(key, value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(StrictMapVisitor(PhantomData))
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    Hot,
    Warm,
    Cold,
    ArchivedAudit,
    SuppressedQuarantined,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MemoryUtilitySignalKind {
    InjectionReceipt,
    ExactL2Expansion,
    PacketInclusion,
    UnderstandingProofCitation,
    ActionContractCitation,
    VerificationCitation,
    CompletionProofCitation,
    Influence,
    PreventedRepeatedFailure,
    CorrectVerifierSelection,
    PredictionResolution,
    NegativeTransfer,
    StaleSuppression,
    ScopeSuppression,
    FalseActivation,
    Contradiction,
    RepeatedLowDeltaLoad,
    ContextTokenCost,
    MaintenanceCost,
    RestoreRegret,
    MissingContextRegret,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUtilitySourceRecord {
    pub record_ref: String,
    pub record_kind: String,
    pub target_refs: Vec<String>,
    pub evidence_ref: String,
    pub payload: Value,
    #[schemars(with = "Option<u64>")]
    pub memory_revision: Option<MemoryRevision>,
    #[schemars(with = "Option<u64>")]
    pub project_sequence: Option<ProjectSequence>,
    pub serialized_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUtilityLedgerEntry {
    pub target_ref: String,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub signal_counts: BTreeMap<MemoryUtilitySignalKind, u64>,
    pub beneficial_use_count: u64,
    pub prevented_failure_count: u64,
    pub correct_verifier_selection_count: u64,
    pub verification_success_count: u64,
    pub verification_failure_count: u64,
    pub stale_hits: u64,
    pub scope_suppressions: u64,
    pub false_activation_count: u64,
    pub negative_transfer_count: u64,
    pub contradiction_count: u64,
    pub repeated_low_delta_loads: u64,
    pub context_cost_tokens: u64,
    pub maintenance_cost_units: u64,
    pub restore_regret_count: u64,
    pub missing_context_regret_count: u64,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMemoryUtilityLedger {
    pub project_id: ProjectId,
    #[schemars(with = "u64")]
    pub snapshot_revision: MemoryRevision,
    pub complete: bool,
    pub source_record_count: usize,
    pub entries: Vec<MemoryUtilityLedgerEntry>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationCorpusItem {
    pub record_ref: String,
    pub target_ref: String,
    pub record_kind: String,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub content_hash: String,
    pub normalized_proposition: String,
    pub mechanism: String,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub counterexamples: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    #[schemars(with = "String")]
    pub lifecycle: MemoryLifecycleState,
    pub status: String,
    pub token_units: u64,
    pub current_truth: bool,
    pub negative_memory: bool,
    pub protected: bool,
    pub superseded_by: Option<String>,
    pub exact_scope_contradiction: Option<String>,
    pub obsolete_replacement: Option<String>,
    pub certification_noise: bool,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationCorpusProfile {
    pub physical_records: usize,
    pub logical_items: usize,
    pub total_bytes: u64,
    pub active_bytes: u64,
    #[serde(deserialize_with = "deserialize_strict_btree_map")]
    pub tier_counts: BTreeMap<MemoryTier, usize>,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDistillationFinding {
    ExactDuplicate,
    SemanticDuplicate,
    NearMiss,
    StaleSuperseded,
    WrongScope,
    RepeatedLowDelta,
    HighCostLowValue,
    HarmfulTransfer,
    Poisoned,
    ObsoleteArtifact,
    CompressibleEpisodeGroup,
    ReusablePattern,
    Protected,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDistillationAction {
    KeepHot,
    KeepHandleOnly,
    Demote,
    Suppress,
    Supersede,
    Compress,
    Archive,
    Quarantine,
    Restore,
    ProposePattern,
    ProposeProcedure,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationCandidate {
    pub candidate_id: String,
    pub target_refs: Vec<String>,
    pub finding: MemoryDistillationFinding,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub confidence: u16,
    pub proposed_action: MemoryDistillationAction,
    pub automatic_apply_allowed: bool,
    pub reversible: bool,
    pub restore_conditions: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationPlan {
    pub plan_id: String,
    pub project_id: ProjectId,
    #[schemars(with = "u64")]
    pub snapshot_revision: MemoryRevision,
    pub ruleset_version: String,
    pub complete: bool,
    pub corpus_profile_before: MemoryDistillationCorpusProfile,
    pub candidates: Vec<MemoryDistillationCandidate>,
    pub protected_refs: Vec<String>,
    pub expected_active_bytes_delta: i64,
    pub expected_reconstruction_delta: i64,
    pub unresolved_items: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationInput {
    pub project_id: ProjectId,
    #[schemars(with = "u64")]
    pub snapshot_revision: MemoryRevision,
    pub ruleset_version: String,
    pub complete: bool,
    pub items: Vec<MemoryDistillationCorpusItem>,
    pub utility_ledger: CanonicalMemoryUtilityLedger,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCompressionArtifact {
    pub compression_id: String,
    pub source_refs: Vec<String>,
    pub output_ref: String,
    pub invariant_core: Vec<String>,
    pub preserved_exact_atoms: Vec<String>,
    pub applicability_boundary: Vec<String>,
    pub counterexamples: Vec<String>,
    pub required_probe: String,
    pub verifier_refs: Vec<String>,
    pub input_token_units: u64,
    pub output_token_units: u64,
    pub known_information_loss: Vec<String>,
    pub replay_requirement: String,
    pub candidate_only: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationApplySelection {
    pub candidate_id: String,
    pub target_ref: String,
    #[schemars(with = "String")]
    pub operator: ForgettingOperator,
    pub evidence_refs: Vec<String>,
    pub restore_conditions: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationApplyReceipt {
    pub apply_id: String,
    pub plan_id: String,
    pub project_id: ProjectId,
    #[schemars(with = "u64")]
    pub snapshot_revision: MemoryRevision,
    pub selected: Vec<MemoryDistillationApplySelection>,
    pub rejected_candidate_ids: Vec<String>,
    #[schemars(with = "Vec<String>")]
    pub write_receipts: Vec<WriteReceiptRef>,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDistillationTrigger {
    VerifiedTaskClosure,
    Nightly,
    Idle,
    Manual,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationScheduleRequest {
    pub project_id: ProjectId,
    pub trigger: MemoryDistillationTrigger,
    pub new_evidence_count: u64,
    pub minimum_evidence_count: u64,
    pub interactive_load_active: bool,
    pub cursor: Option<String>,
    pub batch_size: u16,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDistillationCheckpoint {
    pub project_id: ProjectId,
    pub trigger: MemoryDistillationTrigger,
    pub cursor: Option<String>,
    pub batch_size: u16,
    pub paused: bool,
    pub reason: String,
}

pub fn memory_distillation_plan_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(MemoryDistillationPlan))
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

pub fn memory_compression_artifact_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(MemoryCompressionArtifact))
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

pub fn memory_distillation_schedule_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(MemoryDistillationScheduleRequest))
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_roundtrips_and_published_schemas_expose_required_fields()
    -> Result<(), serde_json::Error> {
        let request = MemoryDistillationScheduleRequest {
            project_id: ProjectId::new_v7(),
            trigger: MemoryDistillationTrigger::VerifiedTaskClosure,
            new_evidence_count: 7,
            minimum_evidence_count: 4,
            interactive_load_active: false,
            cursor: Some("cursor:stable".to_owned()),
            batch_size: 100,
        };
        let encoded = serde_json::to_value(&request)?;
        let decoded = serde_json::from_value::<MemoryDistillationScheduleRequest>(encoded)?;
        assert_eq!(decoded, request);
        let plan = memory_distillation_plan_schema().to_string();
        let compression = memory_compression_artifact_schema().to_string();
        let schedule = memory_distillation_schedule_schema().to_string();
        for required in [
            "snapshot_revision",
            "protected_refs",
            "expected_active_bytes_delta",
            "unresolved_items",
        ] {
            assert!(plan.contains(required));
        }
        for required in [
            "preserved_exact_atoms",
            "applicability_boundary",
            "counterexamples",
            "replay_requirement",
            "candidate_only",
        ] {
            assert!(compression.contains(required));
        }
        for required in [
            "minimum_evidence_count",
            "interactive_load_active",
            "batch_size",
        ] {
            assert!(schedule.contains(required));
        }
        Ok(())
    }
}
