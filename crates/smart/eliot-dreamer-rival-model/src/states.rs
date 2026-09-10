//! Closed diagnostic states for bounded rival-model analysis.
//!
//! These values describe where deterministic local work stopped or which
//! bounded omission was recorded. They carry no source authority, truth,
//! admission, ranking, or promotion semantics.

use serde::{Deserialize, Serialize};

/// Concrete stage at which bounded rival analysis performed or stopped work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum WorkStage {
    ModelAssessment,
    MaterialEquivalence,
    MaterialProjectionHash,
    ClaimReference,
    ClaimLookup,
    ClaimOwnerCheck,
    AssumptionReference,
    AssumptionLookup,
    AssumptionOwnerCheck,
    DependencyRetainedCollection,
    DependencyIndexEntry,
    DependencyIndexInsert,
    DependencyEdgeTable,
    DependencyNode,
    DependencyReference,
    DependencyEdge,
    RelatedDependencyScan,
    UnavailableDependencyScan,
    DependencyDfsNode,
    DependencyDfsEdge,
    DependencyLookup,
    RelatedModelLookup,
    RecordDependencyLookup,
    CausalReference,
    CausalLookup,
    PredictionReference,
    PredictionLookup,
    PredictionOwnerCheck,
    PredictionAssumptionLookup,
    PredictionAssumptionOwnerCheck,
    PredictionIndexScan,
    PredictionIndexEntry,
    DiscriminatorPair,
    PredictionLookupCompare,
    DiscriminatorLimit,
    ResultPacking,
}

/// Output section whose bounded work frontier caused an omission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum OutputSection {
    Models,
    AnalysisWork,
    Comparisons,
    SourceDeclarations,
}

/// Closed reason for omitting a model assessment from the work frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ModelOmissionReason {
    AnalysisWorkFrontier,
    ModelFrontierCapacity,
}

/// Closed reason for retaining an assessment with unavailable material input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ModelUnknownReason {
    MaterialInputsUnavailable,
}

/// Closed reason for a model body that was unavailable in the supplied set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ModelUnavailableReason {
    BodyUnavailable,
}
