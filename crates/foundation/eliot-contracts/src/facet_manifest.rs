//! ELIOT-owned typed resource-facet manifests shared by contour projections.
//!
//! The native Execute resource facet is the first active projection of this
//! source. No current WASM TypedWorld or WIT world claims this facet; future
//! projections must consume this same semantic manifest rather than cloning
//! its method profile.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ContractError, ContractIdentity, ContractVersion, contract_identity};

/// ELIOT source identity for the shared native-worker resource facet.
pub const NATIVE_WORKER_RESOURCE_FACET_NAME: &str = "eliot.resource.native-worker-execution";
/// Semantic version of the owner-neutral facet and its method schemas.
pub const NATIVE_WORKER_RESOURCE_FACET_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);
/// Stable semantic resource kind described by the shared manifest.
pub const NATIVE_WORKER_RESOURCE_KIND: &str = "admitted_execution_resource";
/// Maximum number of properties accepted by the Execute input schema.
pub const NATIVE_WORKER_EXECUTE_MAX_PROPERTIES: usize = 128;

/// A portable primitive or semantic type in a resource-facet schema.
///
/// These tags are contract vocabulary, not Rust ABI types. Each contour
/// projects them into its own language while preserving schema identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceFacetValueKind {
    /// Owner-validated attempt identity.
    AttemptIdentity,
    /// Bounded capability or method label.
    CapabilityName,
    /// Bounded text properties keyed by exact property names.
    TextProperties {
        maximum_entries: usize,
    },
    /// Optional candidate effect proposal, bound to the same attempt.
    OptionalProposedEffect,
    /// Boolean semantic result.
    Boolean,
    /// Opaque stable reference.
    ResourceReference { maximum_bytes: usize },
}

/// One named field in an input or output schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetField {
    /// Stable field spelling.
    pub name: String,
    /// Contract-owned semantic value kind.
    pub value_kind: ResourceFacetValueKind,
    /// Whether the serialized field must be present.
    pub required: bool,
}

/// Versioned method input or output schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetSchema {
    /// Stable schema name within the facet.
    pub name: String,
    /// Semantic schema revision.
    pub version: ContractVersion,
    /// Ordered fields; field order is part of the source manifest identity.
    pub fields: Vec<ResourceFacetField>,
}

/// Authority source required to invoke a facet method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetAuthorityClass {
    /// Exact resource and operation must be introduced to the caller.
    IntroducedResourceAndMethod,
}

/// Maximum effect class a method can produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetEffectClass {
    /// The method may return a candidate effect only after a separate owner
    /// admission; it never commits that effect itself.
    CandidateOnlyAfterAdmission,
}

/// Observation class emitted by a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetObservationClass {
    /// Accepted work and candidate outcomes are durable observations.
    DurableObservation,
}

/// Data-disclosure rule for a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetDisclosureRule {
    /// Output disclosure is bounded by the exact introduced resource.
    NoWiderThanIntroducedResource,
}

/// Idempotency identity consumed by a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetIdempotencyClass {
    /// Exact request identity and attempt identity jointly bind replay.
    RequestAndAttempt,
}

/// Simulation semantics of a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetSimulationClass {
    /// Simulation observes the same inputs and never performs an external
    /// effect.
    ObserveWithoutExternalEffects,
}

/// Compensation boundary of a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetCompensationClass {
    /// No effect is performed before admission; a candidate is discarded
    /// when later admission or dispatch fails.
    CandidateDiscardBeforeCommit,
}

/// Replay semantics of a method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetReplayClass {
    /// Only an identical method, source schema, request identity and payload
    /// can replay a prior observation.
    ExactRequestAndSchema,
}

/// Source of the method timeout limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetTimeoutClass {
    /// The request deadline and owner binding expiry are the operative bounds.
    RequestDeadlineAndBindingExpiry,
}

/// Source of the method concurrency limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetConcurrencyClass {
    /// Transport admission provides a finite per-connection bound.
    TransportAdmissionBounded,
}

/// Timeout and bounded-resource profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FacetResourceProfile {
    /// Timeout policy, without inventing a local hard duration.
    pub timeout: FacetTimeoutClass,
    /// Maximum encoded input body in bytes, sourced from the EBP/1 frame cap.
    pub maximum_request_bytes: usize,
    /// Maximum encoded outcome body in bytes, sourced from the EBP hot-response cap.
    pub maximum_response_bytes: usize,
    /// Source of the finite in-flight request bound.
    pub concurrency: FacetConcurrencyClass,
}

/// Exhaustive authority, effect, observation and resource profile for a method.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetMethodProfile {
    /// Exact authority prerequisite.
    pub authority: FacetAuthorityClass,
    /// Maximum effect class.
    pub effect: FacetEffectClass,
    /// Durable observation class.
    pub observation: FacetObservationClass,
    /// Disclosure propagation rule.
    pub disclosure: FacetDisclosureRule,
    /// Idempotency rule.
    pub idempotency: FacetIdempotencyClass,
    /// Simulation rule.
    pub simulation: FacetSimulationClass,
    /// Compensation boundary.
    pub compensation: FacetCompensationClass,
    /// Replay rule.
    pub replay: FacetReplayClass,
    /// Timeout and resource profile.
    pub resources: FacetResourceProfile,
}

/// One method and its typed input/output contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetMethod {
    /// Stable method identifier.
    pub method_id: String,
    /// Input schema.
    pub input: ResourceFacetSchema,
    /// Output schema.
    pub output: ResourceFacetSchema,
    /// Exhaustive I6.15 method profile.
    pub profile: ResourceFacetMethodProfile,
}

impl ResourceFacetMethod {
    /// Computes the content-addressed identity of this method schema/profile.
    pub fn schema_identity(
        &self,
        facet_name: &str,
    ) -> Result<ContractIdentity, ContractError> {
        contract_identity(
            format!("{facet_name}.method.{}", self.method_id),
            self.input.version,
            self,
        )
    }
}

/// Closed collision behavior for method and field names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetCollisionPolicy {
    /// Reject duplicates, reserved names and ambiguous case-folded collisions.
    RejectDuplicateReservedAndCaseFolded,
}

/// Boundary for removing a facet or changing an admitted method schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FacetRemovalBoundary {
    /// Removal or incompatible change requires a new facet version and an
    /// explicit owner migration; no old introduction is silently reinterpreted.
    NewVersionAndOwnerMigration,
}

/// Availability of one projection contour for this semantic facet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FacetContourProjection {
    /// Contour identifier.
    pub contour: String,
    /// Whether the contour currently implements a projection.
    pub current_projection: bool,
    /// Explanation for absent or active projection status.
    pub status: String,
}

/// The serializable source shape whose canonical digest binds every contour.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetShape {
    /// Semantic kind of the resource.
    pub semantic_resource_kind: String,
    /// Lowest implementation version admitted by this contract.
    pub compatible_implementation_minimum: ContractVersion,
    /// Highest implementation version admitted by this contract.
    pub compatible_implementation_maximum: ContractVersion,
    /// Method schemas and profiles.
    pub methods: Vec<ResourceFacetMethod>,
    /// Name collision semantics.
    pub collision_policy: FacetCollisionPolicy,
    /// Reserved method names unavailable to implementations.
    pub reserved_method_names: Vec<String>,
    /// Reserved field names unavailable to schemas.
    pub reserved_field_names: Vec<String>,
    /// Removal/migration boundary.
    pub removal_boundary: FacetRemovalBoundary,
    /// Current contour projections; absence is explicit, not inferred.
    pub contours: Vec<FacetContourProjection>,
}

/// Content-addressed, ELIOT-owned resource-facet source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacetContract {
    /// Stable source identity.
    pub identity: ContractIdentity,
    /// Canonical semantic facet shape.
    pub shape: ResourceFacetShape,
}

/// Invalid common resource-facet source or stale identity.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceFacetError {
    /// Underlying shared identity helper rejected a field.
    #[error("facet contract identity is invalid: {0}")]
    Contract(ContractError),
    /// Recomputed source identity differed from the carried identity.
    #[error("facet source identity does not match its canonical shape")]
    IdentityMismatch,
    /// The method/schema set is structurally incomplete or ambiguous.
    #[error("facet source has an invalid method, schema, name or resource profile")]
    InvalidShape,
}

impl From<ContractError> for ResourceFacetError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl ResourceFacetContract {
    /// Revalidates the source digest, profiles, schema names and uniqueness.
    pub fn validate(&self) -> Result<(), ResourceFacetError> {
        self.identity.validate()?;
        if self.identity
            != contract_identity(
                self.identity.name.as_str(),
                self.identity.version,
                &self.shape,
            )?
            || self.shape.semantic_resource_kind.trim().is_empty()
            || self.shape.compatible_implementation_minimum
                > self.shape.compatible_implementation_maximum
            || self.shape.methods.is_empty()
            || self.shape.reserved_method_names.is_empty()
            || self.shape.reserved_field_names.is_empty()
        {
            return Err(ResourceFacetError::IdentityMismatch);
        }

        let mut methods = BTreeSet::new();
        for method in &self.shape.methods {
            if method.method_id.trim().is_empty()
                || method.method_id.chars().any(char::is_control)
                || self.shape.reserved_method_names.iter().any(|reserved| {
                    reserved.eq_ignore_ascii_case(&method.method_id)
                        || reserved.eq_ignore_ascii_case(&format!("method.{}", method.method_id))
                })
                || !methods.insert(method.method_id.to_ascii_lowercase())
                || !valid_schema(&method.input, &self.shape.reserved_field_names)
                || !valid_schema(&method.output, &self.shape.reserved_field_names)
                || method.profile.resources.maximum_request_bytes == 0
                || method.profile.resources.maximum_response_bytes == 0
            {
                return Err(ResourceFacetError::InvalidShape);
            }
            method.schema_identity(self.identity.name.as_str())?;
        }

        let mut contours = BTreeSet::new();
        if self.shape.contours.iter().any(|projection| {
            projection.contour.trim().is_empty()
                || projection.status.trim().is_empty()
                || !contours.insert(projection.contour.to_ascii_lowercase())
        }) {
            return Err(ResourceFacetError::InvalidShape);
        }
        Ok(())
    }

    /// Returns the canonical owner reference for this exact source digest.
    ///
    /// Producers carry this value instead of opaque, locally formatted
    /// manifest labels so a contour can verify that its generated stub and
    /// admitted facet source are the same contract revision.
    pub fn canonical_ref(&self) -> Result<String, ResourceFacetError> {
        self.validate()?;
        Ok(format!(
            "{}@{}#{}",
            self.identity.name, self.identity.version, self.identity.shape_sha256
        ))
    }

    /// Returns a method by exact stable identifier.
    #[must_use]
    pub fn method(&self, method_id: &str) -> Option<&ResourceFacetMethod> {
        self.shape
            .methods
            .iter()
            .find(|method| method.method_id == method_id)
    }
}

fn valid_schema(schema: &ResourceFacetSchema, reserved_names: &[String]) -> bool {
    if schema.name.trim().is_empty() || schema.fields.is_empty() {
        return false;
    }
    let mut names = BTreeSet::new();
    schema.fields.iter().all(|field| {
        !field.name.trim().is_empty()
            && !field.name.chars().any(char::is_control)
            && !reserved_names
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(&field.name))
            && names.insert(field.name.to_ascii_lowercase())
    })
}

/// Builds the canonical ELIOT-owned native Execute resource facet.
///
/// The projection ledger explicitly records that the current WASM TypedWorld
/// and WIT contracts model different domain facets and do not claim this one.
pub fn native_worker_resource_facet_v1() -> Result<ResourceFacetContract, ResourceFacetError> {
    let input = ResourceFacetSchema {
        name: "native_worker_execute_input".to_owned(),
        version: NATIVE_WORKER_RESOURCE_FACET_VERSION,
        fields: vec![
            ResourceFacetField {
                name: "attempt_id".to_owned(),
                value_kind: ResourceFacetValueKind::AttemptIdentity,
                required: true,
            },
            ResourceFacetField {
                name: "capability".to_owned(),
                value_kind: ResourceFacetValueKind::CapabilityName,
                required: true,
            },
            ResourceFacetField {
                name: "payload".to_owned(),
                value_kind: ResourceFacetValueKind::TextProperties {
                    maximum_entries: NATIVE_WORKER_EXECUTE_MAX_PROPERTIES,
                },
                required: true,
            },
            ResourceFacetField {
                name: "proposed_effect".to_owned(),
                value_kind: ResourceFacetValueKind::OptionalProposedEffect,
                required: false,
            },
        ],
    };
    let output = ResourceFacetSchema {
        name: "native_worker_execute_outcome".to_owned(),
        version: NATIVE_WORKER_RESOURCE_FACET_VERSION,
        fields: vec![
            ResourceFacetField {
                name: "attempt_id".to_owned(),
                value_kind: ResourceFacetValueKind::AttemptIdentity,
                required: true,
            },
            ResourceFacetField {
                name: "accepted".to_owned(),
                value_kind: ResourceFacetValueKind::Boolean,
                required: true,
            },
            ResourceFacetField {
                name: "observation_ref".to_owned(),
                value_kind: ResourceFacetValueKind::ResourceReference {
                    maximum_bytes: 1_024,
                },
                required: true,
            },
        ],
    };
    let shape = ResourceFacetShape {
        semantic_resource_kind: NATIVE_WORKER_RESOURCE_KIND.to_owned(),
        compatible_implementation_minimum: ContractVersion::new(1, 0, 0),
        compatible_implementation_maximum: ContractVersion::new(1, u16::MAX, u16::MAX),
        methods: vec![ResourceFacetMethod {
            method_id: "execute".to_owned(),
            input,
            output,
            profile: ResourceFacetMethodProfile {
                authority: FacetAuthorityClass::IntroducedResourceAndMethod,
                effect: FacetEffectClass::CandidateOnlyAfterAdmission,
                observation: FacetObservationClass::DurableObservation,
                disclosure: FacetDisclosureRule::NoWiderThanIntroducedResource,
                idempotency: FacetIdempotencyClass::RequestAndAttempt,
                simulation: FacetSimulationClass::ObserveWithoutExternalEffects,
                compensation: FacetCompensationClass::CandidateDiscardBeforeCommit,
                replay: FacetReplayClass::ExactRequestAndSchema,
                resources: FacetResourceProfile {
                    timeout: FacetTimeoutClass::RequestDeadlineAndBindingExpiry,
                    maximum_request_bytes: 4 * 1024 * 1024,
                    maximum_response_bytes: 64 * 1024,
                    concurrency: FacetConcurrencyClass::TransportAdmissionBounded,
                },
            },
        }],
        collision_policy: FacetCollisionPolicy::RejectDuplicateReservedAndCaseFolded,
        reserved_method_names: vec!["__system".to_owned(), "eliot.internal".to_owned()],
        reserved_field_names: vec!["__proto__".to_owned(), "prototype".to_owned()],
        removal_boundary: FacetRemovalBoundary::NewVersionAndOwnerMigration,
        contours: vec![
            FacetContourProjection {
                contour: "native_ebp".to_owned(),
                current_projection: true,
                status: "generated from this source by native-worker-core build.rs".to_owned(),
            },
            FacetContourProjection {
                contour: "wasm_typed_world".to_owned(),
                current_projection: false,
                status: "current WASM worlds describe different semantic domain facets".to_owned(),
            },
        ],
    };
    let identity = contract_identity(
        NATIVE_WORKER_RESOURCE_FACET_NAME,
        NATIVE_WORKER_RESOURCE_FACET_VERSION,
        &shape,
    )?;
    let facet = ResourceFacetContract { identity, shape };
    facet.validate()?;
    Ok(facet)
}

/// Returns the canonical versioned and content-addressed native facet ref.
///
/// Governor/Kernel producers should use this helper when populating their
/// executable binding rather than reproducing the wire spelling.
pub fn native_worker_resource_facet_ref_v1() -> Result<String, ResourceFacetError> {
    native_worker_resource_facet_v1()?.canonical_ref()
}
