//! Closed task-controller invocation and result transport contracts.
//!
//! The protocol carries opaque JSON values for domain-owned proposal, command,
//! recipe, and context bodies. The daemon decodes those values at the relevant
//! owner boundary and performs semantic validation; protocol shape validation
//! alone grants no Task Controller authority.

use eliot_contracts::{EpochId, StateFence, TaskId, canonical_json_bytes, epoch_identity_digest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HARD_STRUCTURED_RESPONSE_BYTES, MAX_FRAME_BYTES, ProtocolError};
use crate::dreamer_job::{DurableJobRequest, JobOperation, JobRole, OpaqueContentRef};

/// Stable wire identity for one admitted Task Controller invocation.
pub const TASK_CONTROLLER_INVOCATION_WIRE_ID: &str = "eliot.protocol.task-controller-invocation";
/// Current Task Controller invocation wire version.
///
/// `4` adds the initial owner-publication action. The already-sealed
/// `DREAMER_ORIENTATION` consumer remains on its original version `3` payload.
/// Versions `2` and `3` remain accepted for the existing Propose/Apply actions.
pub const TASK_CONTROLLER_INVOCATION_WIRE_VERSION: u16 = 4;
/// Wire version of the already-sealed Orientation consumer.
pub const TASK_CONTROLLER_INVOCATION_ORIENTATION_WIRE_VERSION: u16 = 3;
/// Previous invocation version retained for existing Propose and Apply claims.
pub const TASK_CONTROLLER_INVOCATION_LEGACY_WIRE_VERSION: u16 = 2;
/// Stable wire identity for the Kernel-issued Task Controller attempt.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_ID: &str = "eliot.protocol.task-controller-attempt";
/// Current Task Controller attempt wire version.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for the Task Controller result body.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_ID: &str = "eliot.protocol.task-controller-result-body";
/// Current Task Controller result-body wire version.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION: u16 = 1;

const MAX_TASK_CONTROLLER_TEXT_BYTES: usize = 512;
const MAX_TASK_CONTROLLER_VALUE_BYTES: usize = MAX_FRAME_BYTES;

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank without surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > MAX_TASK_CONTROLLER_TEXT_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn structured_object(value: &Value, field: &'static str) -> Result<(), ProtocolError> {
    if !value.is_object() {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a JSON object",
        });
    }
    structured_value(value, field)
}

fn structured_value(value: &Value, field: &'static str) -> Result<(), ProtocolError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    if bytes.len() > MAX_TASK_CONTROLLER_VALUE_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded JSON value size",
        });
    }
    Ok(())
}

/// Closed Task Controller operation requested by the authenticated caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskControllerAction {
    /// Admit a new task proposal.
    Propose,
    /// Apply an exact command to an existing task.
    Apply,
    /// Submit one already-sealed Orientation job with its declared semantic source.
    DreamerOrientation,
    /// Admit and publish one new Orientation job from original owner publications.
    PrepareDreamerOrientation,
}

/// Exact original canonical bytes paired with their owner-issued content reference.
///
/// This transport wrapper does not issue an artifact identity or interpret the
/// referenced contract. The daemon checks the declared contract at its native
/// owner boundary and preserves both members unchanged through the initial
/// Orientation publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerCanonicalSourcePublication {
    /// Original owner-issued content reference.
    pub reference: OpaqueContentRef,
    /// Exact canonical bytes named by `reference`.
    pub canonical_bytes: Vec<u8>,
}

impl TaskControllerCanonicalSourcePublication {
    /// Verifies the original reference, exact bytes, and canonical JSON encoding.
    pub fn validate(&self, field: &'static str) -> Result<(), ProtocolError> {
        self.reference
            .validate(field)
            .map_err(|_| ProtocolError::InvalidField {
                field,
                reason: "must carry a valid original content reference",
            })?;
        self.reference
            .validate_original_bytes(&self.canonical_bytes)
            .map_err(|_| ProtocolError::InvalidField {
                field,
                reason: "original bytes do not match the owner-issued reference",
            })?;
        let value: Value = serde_json::from_slice(&self.canonical_bytes).map_err(|_| {
            ProtocolError::InvalidField {
                field,
                reason: "original bytes must contain canonical JSON",
            }
        })?;
        let canonical = canonical_json_bytes(&value).map_err(|error| {
            ProtocolError::Json(error.to_string())
        })?;
        if canonical != self.canonical_bytes || !value.is_object() {
            return Err(ProtocolError::InvalidField {
                field,
                reason: "original bytes must be one canonical JSON object",
            });
        }
        Ok(())
    }
}

/// A source claim carried by an explicit Orientation invocation.
///
/// This is a claim, not authority: the daemon resolves the exact handle through
/// its authenticated named-read owner and checks the returned bytes against
/// the original Durable Job reference before queueing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationSourceClaim {
    /// Exact named-read source handle issued for this publication.
    pub source_handle: String,
    /// Owner-issued SHA-256 for the exact canonical source bytes.
    pub expected_digest: String,
    /// Owner-issued byte length for the exact canonical source bytes.
    pub expected_byte_length: u64,
    /// Closed source privacy class.
    pub privacy_class: String,
    /// Closed source route class.
    pub route_class: String,
}

fn validate_orientation_source_claims(
    semantic: &TaskControllerOrientationSourceClaim,
    schema: &TaskControllerOrientationSourceClaim,
    materials: &[TaskControllerOrientationSourceClaim],
    budget: TaskControllerOrientationMaterialBudget,
    field_prefix: &'static str,
) -> Result<(), ProtocolError> {
    let claims = std::iter::once(semantic)
        .chain(std::iter::once(schema))
        .chain(materials.iter())
        .collect::<Vec<_>>();
    if budget.max_sources == 0
        || budget.max_source_bytes == 0
        || budget.max_total_bytes == 0
        || claims.len() > budget.max_sources as usize
    {
        return Err(ProtocolError::InvalidField {
            field: field_prefix,
            reason: "source count and byte bounds must admit the complete declared set",
        });
    }

    let mut handles = std::collections::HashSet::with_capacity(claims.len());
    let mut total_bytes = 0_u64;
    for claim in claims {
        for (field, value) in [
            ("source_handle", claim.source_handle.as_str()),
            ("privacy_class", claim.privacy_class.as_str()),
            ("route_class", claim.route_class.as_str()),
        ] {
            bounded_text(value, field)?;
        }
        lowercase_sha256(&claim.expected_digest, "source_claim.expected_digest")?;
        if claim.expected_byte_length == 0
            || claim.expected_byte_length > budget.max_source_bytes
            || !handles.insert(claim.source_handle.as_str())
        {
            return Err(ProtocolError::InvalidField {
                field: field_prefix,
                reason: "source claims must be bounded, nonempty, and uniquely named",
            });
        }
        total_bytes = total_bytes
            .checked_add(claim.expected_byte_length)
            .ok_or(ProtocolError::InvalidField {
                field: field_prefix,
                reason: "declared source byte total overflows its bound",
            })?;
        if total_bytes > budget.max_total_bytes {
            return Err(ProtocolError::InvalidField {
                field: field_prefix,
                reason: "declared source bytes exceed the owner-issued total bound",
            });
        }
    }
    Ok(())
}

/// First-profile byte and material bounds for a declared Orientation submit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationMaterialBudget {
    /// Maximum admitted source claims.
    pub max_sources: u32,
    /// Maximum resolved bytes across all claims.
    pub max_total_bytes: u64,
    /// Maximum resolved bytes per claim.
    pub max_source_bytes: u64,
}

/// Exact `OutputSchema` recipe identity admitted by the original job source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationOutputSchemaRecipe {
    /// Immutable schema artifact identity from the original recipe.
    pub schema_id: eliot_contracts::ArtifactId,
    /// Explicit source-owned schema version from the original recipe.
    pub schema_version: u32,
    /// Original schema-byte digest from the recipe.
    pub schema_digest: String,
}

/// Original native inputs for deriving the A-12 cue binding and closed A-10
/// snapshot in the initial Orientation source publisher.
///
/// These values are carried unchanged from their owner into the Governor
/// admission path. The protocol checks only the versioned JSON envelope and
/// bounds; the Governor decodes the native contracts, proves the observation
/// admission is current, and invokes the A-12/A-10 owners. This record grants
/// no cue admission by itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationCueAdmissionInputV1 {
    /// Closed wire version for this original supplier record.
    pub schema_version: u16,
    /// Exact accepted observation admission receipt from the Observation owner.
    pub observation_admission: Value,
    /// Original touched denominator rows supplied to A-12.
    pub touched: Vec<Value>,
    /// Original optional expected-reuse evidence supplied to A-12.
    pub hint: Option<Value>,
    /// Original binding profile supplied to A-12.
    pub binding_profile: Value,
    /// Original snapshot identity supplied to A-10.
    pub snapshot_id: Value,
    /// Exact closure denominator supplied to the closed A-10 builder.
    pub denominator: Value,
    /// Original relation edges supplied to the closed A-10 builder.
    pub relation_edges: Vec<Value>,
    /// Original optional relation-registry revision supplied to A-10.
    pub registry_revision: Option<String>,
    /// Original policy-owned edge weights supplied to the closed A-10 builder.
    pub weights: Vec<Value>,
}

impl TaskControllerOrientationCueAdmissionInputV1 {
    /// Validates the transport shape and encoded-value bounds only.
    ///
    /// Native admission, source currentness, task/scope/fence equality and
    /// A-12/A-10 closure remain the owning Governor's responsibility.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema_version != 1 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.cue.schema_version",
                reason: "must use OrientationCueAdmissionInputV1",
            });
        }
        structured_object(
            &self.observation_admission,
            "task_controller_invocation.orientation.cue.observation_admission",
        )?;
        structured_object(
            &self.binding_profile,
            "task_controller_invocation.orientation.cue.binding_profile",
        )?;
        structured_value(
            &self.snapshot_id,
            "task_controller_invocation.orientation.cue.snapshot_id",
        )?;
        structured_object(
            &self.denominator,
            "task_controller_invocation.orientation.cue.denominator",
        )?;
        if let Some(hint) = &self.hint {
            structured_object(hint, "task_controller_invocation.orientation.cue.hint")?;
        }
        for row in &self.touched {
            structured_object(
                row,
                "task_controller_invocation.orientation.cue.touched",
            )?;
        }
        for (field, values) in [
            (
                "task_controller_invocation.orientation.cue.relation_edges",
                self.relation_edges.as_slice(),
            ),
            (
                "task_controller_invocation.orientation.cue.weights",
                self.weights.as_slice(),
            ),
        ] {
            for value in values {
                structured_object(value, field)?;
            }
        }
        if let Some(revision) = &self.registry_revision {
            bounded_text(
                revision,
                "task_controller_invocation.orientation.cue.registry_revision",
            )?;
        }
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if bytes.len() > MAX_TASK_CONTROLLER_VALUE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.cue",
                reason: "exceeds the bounded JSON value size",
            });
        }
        Ok(())
    }
}

/// Initial Orientation publication inputs before the first Durable Job seal.
///
/// Every content reference and byte string is an original owner publication.
/// The daemon validates each contract at the native boundary, obtains a fresh
/// Governor decision, publishes the independent Orientation owner rows, and
/// only then seals the first Durable Job request. This shape alone grants no
/// admission and cannot be used to rewrite an existing request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationPrepareInputV1 {
    /// Closed wire version for this original source bundle.
    pub schema_version: u16,
    /// Original canonical DreamJobInput reference.
    pub semantic_input: OpaqueContentRef,
    /// Exact canonical DreamJobInput bytes named by `semantic_input`.
    pub semantic_input_bytes: Vec<u8>,
    /// Original canonical DreamJobAdmission reference.
    pub job_admission_ref: OpaqueContentRef,
    /// Exact canonical DreamJobAdmission bytes named by `job_admission_ref`.
    pub job_admission_bytes: Vec<u8>,
    /// Original canonical DreamInputBundle reference.
    pub input_bundle_ref: OpaqueContentRef,
    /// Exact canonical DreamInputBundle bytes named by `input_bundle_ref`.
    pub input_bundle_bytes: Vec<u8>,
    /// Original Orientation owner publication including its frame and evidence.
    pub admitted_orientation_job: TaskControllerCanonicalSourcePublication,
    /// Original K0 job-attempt identity issued for this job publication.
    pub job_attempt_id: eliot_contracts::ArtifactId,
    /// Original Artifact-owner publication of the complete runtime execution input.
    pub runtime_owner_execution_input: TaskControllerCanonicalSourcePublication,
    /// Original admitted WorkScope binding, checked again by Governor.
    pub work_scope: eliot_receipts::WorkScopeBinding,
    /// Original OutputSchema artifact reference from the job recipe.
    pub output_contract: OpaqueContentRef,
    /// Exact original OutputSchema recipe tuple.
    pub output_schema_recipe: TaskControllerOrientationOutputSchemaRecipe,
    /// Original named-read claim for the semantic source.
    pub semantic_source: TaskControllerOrientationSourceClaim,
    /// Original named-read claim for the output schema bytes.
    pub schema_source: TaskControllerOrientationSourceClaim,
    /// Original evidence-material named-read claims.
    pub materials: Vec<TaskControllerOrientationSourceClaim>,
    /// Original bounds admitted for source reads.
    pub budget: TaskControllerOrientationMaterialBudget,
    /// Original authenticated Context reconstruction result.
    pub context_reconstruction_result: crate::HostRequestResultBody,
    /// Original versioned Context compiler supplier profile.
    pub context_compilation_input: Value,
    /// Original current Orientation classification source readback.
    pub orientation_classification_source_readback: Value,
    /// Original A-12/A-10 supplier values for the Governor cue issuer.
    pub cue_admission_input: TaskControllerOrientationCueAdmissionInputV1,
    /// Original provider staffing source publication.
    pub provider_staffing_source: TaskControllerCanonicalSourcePublication,
}

impl TaskControllerOrientationPrepareInputV1 {
    /// Checks transport integrity and original-value pairing only. Native
    /// semantic contracts and live owner admission remain downstream.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema_version != 1 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.schema_version",
                reason: "must use OrientationPrepareInputV1",
            });
        }
        self.validate_original_content()?;
        self.validate_scope_and_output_contract()?;
        self.validate_owner_publications()?;
        validate_orientation_source_claims(
            &self.semantic_source,
            &self.schema_source,
            &self.materials,
            self.budget,
            "task_controller_invocation.orientation_prepare",
        )?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if bytes.len() > MAX_TASK_CONTROLLER_VALUE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare",
                reason: "exceeds the bounded JSON value size",
            });
        }
        Ok(())
    }

    fn validate_original_content(&self) -> Result<(), ProtocolError> {
        self.semantic_input
            .validate("task_controller_invocation.orientation_prepare.semantic_input")
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.semantic_input",
                reason: "must carry a valid original content reference",
            })?;
        self.semantic_input
            .validate_semantic_input_bytes(&self.semantic_input_bytes)
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.semantic_input_bytes",
                reason: "must match the original semantic reference",
            })?;
        validate_original_canonical_object(
            &self.job_admission_ref,
            &self.job_admission_bytes,
            "task_controller_invocation.orientation_prepare.job_admission",
        )?;
        validate_original_canonical_object(
            &self.input_bundle_ref,
            &self.input_bundle_bytes,
            "task_controller_invocation.orientation_prepare.input_bundle",
        )?;
        self.admitted_orientation_job.validate(
            "task_controller_invocation.orientation_prepare.admitted_orientation_job",
        )?;
        Ok(())
    }

    fn validate_scope_and_output_contract(&self) -> Result<(), ProtocolError> {
        if self.work_scope.scope_id.as_str().trim().is_empty()
            || self.work_scope.product_id.as_str().trim().is_empty()
            || self.work_scope.state_fence.resource_generation
                != self.work_scope.resource_generation
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.work_scope",
                reason: "must carry one original, internally bound WorkScope",
            });
        }
        self.work_scope
            .state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        self.output_contract
            .validate("task_controller_invocation.orientation_prepare.output_contract")
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.output_contract",
                reason: "must carry the original OutputSchema artifact reference",
            })?;
        if self.output_schema_recipe.schema_version != 2
            || self.output_schema_recipe.schema_digest != self.output_contract.sha256
            || self.output_contract.artifact_id.as_ref()
                != Some(&self.output_schema_recipe.schema_id)
            || self.semantic_source.expected_digest != self.semantic_input.sha256
            || self.semantic_source.expected_byte_length != self.semantic_input.byte_length
            || self.schema_source.expected_digest != self.output_contract.sha256
            || self.schema_source.expected_byte_length != self.output_contract.byte_length
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.source_binding",
                reason: "source claims must bind the original semantic and OutputSchema references",
            });
        }
        Ok(())
    }

    fn validate_owner_publications(&self) -> Result<(), ProtocolError> {
        self.context_reconstruction_result
            .validate_local_read_submission()?;
        structured_object(
            &self.context_compilation_input,
            "task_controller_invocation.orientation_prepare.context_compilation_input",
        )?;
        if self
            .context_compilation_input
            .get("schema_version")
            .and_then(Value::as_u64)
            != Some(1)
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation_prepare.context_compilation_input",
                reason: "must use ContextCompilerSupplierProfileV1",
            });
        }
        structured_object(
            &self.orientation_classification_source_readback,
            "task_controller_invocation.orientation_prepare.classification_source_readback",
        )?;
        self.cue_admission_input.validate()?;
        self.runtime_owner_execution_input.validate(
            "task_controller_invocation.orientation_prepare.runtime_owner_execution_input",
        )?;
        self.provider_staffing_source
            .validate("task_controller_invocation.orientation_prepare.provider_staffing_source")?;
        Ok(())
    }

    fn validate_runtime_owner_bindings(
        &self,
        invocation: &TaskControllerInvocation,
    ) -> Result<(), ProtocolError> {
        let runtime_owner: Value = serde_json::from_slice(
            &self.runtime_owner_execution_input.canonical_bytes,
        )
        .map_err(|_| ProtocolError::InvalidField {
            field: "task_controller_invocation.orientation_prepare.runtime_owner_execution_input",
            reason: "must decode as its original canonical object",
        })?;
        for (field, expected) in [
            ("task_id", serde_json::json!(invocation.task_id)),
            ("attempt_id", serde_json::json!(self.job_attempt_id)),
            ("work_scope", serde_json::json!(self.work_scope)),
            ("context_input", invocation.context_input.clone()),
            (
                "context_campaign_recipe",
                invocation.context_campaign_recipe.clone(),
            ),
            (
                "context_campaign_recipe_policy",
                invocation.context_campaign_recipe_policy.clone(),
            ),
            (
                "context_reconstruction_result",
                serde_json::json!(self.context_reconstruction_result),
            ),
            (
                "context_compilation_input",
                self.context_compilation_input.clone(),
            ),
            (
                "orientation_classification_source_readback",
                self.orientation_classification_source_readback.clone(),
            ),
            ("semantic_source", serde_json::json!(self.semantic_source)),
            ("output_contract", serde_json::json!(self.output_contract)),
            (
                "output_schema_recipe",
                serde_json::json!(self.output_schema_recipe),
            ),
            ("schema_source", serde_json::json!(self.schema_source)),
            ("materials", serde_json::json!(self.materials)),
            ("budget", serde_json::json!(self.budget)),
            (
                "job_admission_ref",
                serde_json::json!(Some(&self.job_admission_ref)),
            ),
            (
                "job_admission_bytes",
                serde_json::json!(Some(&self.job_admission_bytes)),
            ),
            (
                "input_bundle_ref",
                serde_json::json!(Some(&self.input_bundle_ref)),
            ),
            (
                "input_bundle_bytes",
                serde_json::json!(Some(&self.input_bundle_bytes)),
            ),
            (
                "provider_staffing_source",
                serde_json::json!(Some(&self.provider_staffing_source)),
            ),
            (
                "admitted_orientation_job",
                serde_json::json!(Some(&self.admitted_orientation_job)),
            ),
        ] {
            if runtime_owner.get(field) != Some(&expected) {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.orientation_prepare.runtime_owner_execution_input",
                    reason: "must preserve the exact original owner values and source pairs",
                });
            }
        }
        Ok(())
    }
}

fn validate_original_canonical_object(
    reference: &OpaqueContentRef,
    bytes: &[u8],
    field: &'static str,
) -> Result<(), ProtocolError> {
    reference.validate(field).map_err(|_| ProtocolError::InvalidField {
        field,
        reason: "must carry a valid original content reference",
    })?;
    reference
        .validate_original_bytes(bytes)
        .map_err(|_| ProtocolError::InvalidField {
            field,
            reason: "original bytes do not match the owner-issued reference",
        })?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidField {
        field,
        reason: "original bytes must contain canonical JSON",
    })?;
    if !value.is_object()
        || canonical_json_bytes(&value)
            .map_err(|error| ProtocolError::Json(error.to_string()))?
            != bytes
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "original bytes must be one canonical JSON object",
        });
    }
    Ok(())
}

/// Typed Task Controller payload for the explicit Orientation operation.
///
/// The request is already sealed by its original publisher. Its reference and
/// retained bytes are preserved verbatim; this invocation only carries a
/// separately owner-issued named-read claim so the daemon can verify that
/// publication before forwarding the original request to Kernel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerOrientationInput {
    /// Original K0 request identity, admission reference and semantic bytes.
    pub request: DurableJobRequest,
    /// Exact owner-authenticated result of the original `ContextReconstruction`
    /// query. Its response retains the selector-complete owner publication,
    /// including the original `evidence_subject` and named-read receipts.
    pub context_reconstruction_result: crate::HostRequestResultBody,
    /// Original versioned Context compiler supplier input, separately
    /// authenticated by this Task Controller invocation and copied into the
    /// durable runtime publication without deriving it from `ContextInput`.
    pub context_compilation_input: Value,
    /// Original Governor `CampaignSourceRevisionRead` for the Orientation
    /// classification profile, retained for downstream native validation.
    pub orientation_classification_source_readback: Value,
    /// Original native Observation/A-12 and A-10 inputs for the initial
    /// Orientation source publisher. Existing sealed-v3 consumers may omit
    /// this field; the new publisher refuses when it is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cue_admission_input: Option<TaskControllerOrientationCueAdmissionInputV1>,
    /// Distinct named-read claim for the semantic `DreamJobInput` publication.
    pub semantic_source: TaskControllerOrientationSourceClaim,
    /// Exact original `OutputSchema` role declaration from the job recipe.
    pub output_schema_recipe: TaskControllerOrientationOutputSchemaRecipe,
    /// Owner-admitted named-read claim for the original schema artifact bytes.
    pub schema_source: TaskControllerOrientationSourceClaim,
    /// Owner-admitted source claims used as ordinary evidence materials.
    pub materials: Vec<TaskControllerOrientationSourceClaim>,
    /// Independent source and byte bounds required by the daemon intake.
    pub budget: TaskControllerOrientationMaterialBudget,
}

impl TaskControllerOrientationInput {
    /// Checks the closed request and typed source envelope without granting
    /// admission. The daemon performs task, scope, fence, readback and owner
    /// checks against the authenticated claim before queue submission.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_original_request_binding()?;
        self.validate_source_claims_and_budget()
    }

    fn validate_original_request_binding(&self) -> Result<(), ProtocolError> {
        self.request
            .validate()
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.request",
                reason: "must be a valid already-sealed Durable Job request",
            })?;
        if self.request.role != JobRole::Requester
            || !matches!(&self.request.operation, JobOperation::Submit { .. })
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.request",
                reason: "must be a requester SUBMIT_JOB operation",
            });
        }
        let JobOperation::Submit { submission } = &self.request.operation else {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.request",
                reason: "must be a requester SUBMIT_JOB operation",
            });
        };
        let runtime_input = submission
            .decode_runtime_owner_execution_input()
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.runtime_owner_execution_input",
                reason: "must retain the original runtime owner reference and canonical bytes",
            })?
            .ok_or(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.runtime_owner_execution_input",
                reason: "is required for an explicit Orientation request",
            })?;
        self.context_reconstruction_result
            .validate_local_read_submission()?;
        structured_object(
            &self.context_compilation_input,
            "task_controller_invocation.orientation.context_compilation_input",
        )?;
        if self
            .context_compilation_input
            .get("schema_version")
            .and_then(Value::as_u64)
            != Some(1)
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.context_compilation_input",
                reason: "must use ContextCompilerSupplierProfileV1",
            });
        }
        structured_object(
            &self.orientation_classification_source_readback,
            "task_controller_invocation.orientation.classification_source_readback",
        )?;
        if let Some(cue_input) = &self.cue_admission_input {
            cue_input.validate()?;
        }
        if runtime_input.semantic_source != self.semantic_source
            || runtime_input.output_contract != submission.output_contract
            || runtime_input.context_reconstruction_result
                != self.context_reconstruction_result
            || runtime_input.context_compilation_input != self.context_compilation_input
            || runtime_input.orientation_classification_source_readback
                != self.orientation_classification_source_readback
            || runtime_input.output_schema_recipe != self.output_schema_recipe
            || runtime_input.schema_source != self.schema_source
            || runtime_input.materials != self.materials
            || runtime_input.budget != self.budget
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.runtime_owner_execution_input",
                reason: "must exactly match the original sealed owner publication",
            });
        }
        if self.semantic_source.expected_digest.as_str()
            != submission.semantic_input.sha256.as_str()
            || self.semantic_source.expected_byte_length != submission.semantic_input.byte_length
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.semantic_source",
                reason: "must bind the original semantic input reference",
            });
        }
        if self.output_schema_recipe.schema_version == 0
            || self.output_schema_recipe.schema_digest.as_str()
                != submission.output_contract.sha256.as_str()
            || submission.output_contract.artifact_id.as_ref()
                != Some(&self.output_schema_recipe.schema_id)
            || self.schema_source.expected_digest.as_str()
                != self.output_schema_recipe.schema_digest.as_str()
            || self.schema_source.expected_byte_length != submission.output_contract.byte_length
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.output_schema",
                reason: "must bind the original output-contract artifact and schema source",
            });
        }
        Ok(())
    }

    fn validate_source_claims_and_budget(&self) -> Result<(), ProtocolError> {
        for claim in std::iter::once(&self.semantic_source).chain(self.materials.iter()) {
            if claim.source_handle.trim().is_empty()
                || claim.source_handle.chars().any(char::is_control)
                || claim.privacy_class.trim().is_empty()
                || claim.privacy_class.chars().any(char::is_control)
                || claim.route_class.trim().is_empty()
                || claim.route_class.chars().any(char::is_control)
                || claim.expected_byte_length == 0
            {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.orientation.source_claim",
                    reason: "must carry a complete bounded source claim",
                });
            }
            lowercase_sha256(
                &claim.expected_digest,
                "task_controller_invocation.orientation.source_claim.expected_digest",
            )?;
        }
        let schema_claim = &self.schema_source;
        if schema_claim.source_handle.trim().is_empty()
            || schema_claim.source_handle.chars().any(char::is_control)
            || schema_claim.privacy_class.trim().is_empty()
            || schema_claim.privacy_class.chars().any(char::is_control)
            || schema_claim.route_class.trim().is_empty()
            || schema_claim.route_class.chars().any(char::is_control)
            || schema_claim.expected_byte_length == 0
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.schema_source",
                reason: "must carry a complete bounded source claim",
            });
        }
        lowercase_sha256(
            &schema_claim.expected_digest,
            "task_controller_invocation.orientation.schema_source.expected_digest",
        )?;
        if schema_claim.source_handle.as_str() == self.semantic_source.source_handle.as_str()
            || self.materials.iter().any(|claim| {
                claim.source_handle.as_str() == schema_claim.source_handle.as_str()
                    || claim.source_handle.as_str() == self.semantic_source.source_handle.as_str()
            })
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.source_claims",
                reason: "semantic, schema and evidence source handles must remain distinct",
            });
        }
        let budget = self.budget;
        if budget.max_sources == 0
            || budget.max_total_bytes == 0
            || budget.max_source_bytes == 0
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.orientation.budget",
                reason: "must carry nonzero owner-issued bounds",
            });
        }
        Ok(())
    }
}

/// Owner-native material bundle used only for a complete campaign-owner
/// transition. The protocol keeps each owner body opaque; the daemon decodes
/// it at the owning boundary and rejects missing, detached, or unbound values.
/// An absent bundle selects the ordinary recipe-bearing Task Controller path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerCampaignOwnerMaterials {
    /// Optional selector/body slot for the Context owner. It is never used as
    /// publication authority; the daemon reads the current owner row instead.
    pub prior_delivery: Value,
    /// Optional selector/body slot for the evaluator owner. It is never used
    /// as publication authority; the daemon reads the current owner row instead.
    pub evaluation: Value,
    /// Reserved owner-head selector slot. It must be empty: the daemon reads
    /// current heads through its authenticated Kernel route.
    pub source_heads: Vec<Value>,
    /// Reserved owner-row selector slot. It must be empty: caller rows cannot
    /// become owner evidence.
    pub remaining_owner_inputs: Vec<Value>,
}

/// Authenticated, closed-shape Task Controller invocation.
///
/// Domain objects remain JSON at the protocol layer to avoid a dependency from
/// foundation protocol into governor, smart-context, or learning contracts.
/// The daemon decodes `task_input` as the action-specific native `Task` object,
/// `learning_state_view_recipe` as the native learning recipe,
/// `context_campaign_recipe_policy` as the native `ContextRecipePolicy`,
/// `context_campaign_recipe` as the rich native `ContextRecipe`, and
/// `context_input` as the exact `ContextInput`. It joins the latter three into
/// the typed Context campaign recipe body before owner publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerInvocation {
    /// Invocation wire identity.
    pub wire_id: String,
    /// Invocation wire version.
    pub wire_version: u16,
    /// Create or update operation selected by the admitted caller.
    pub action: TaskControllerAction,
    /// Exact native task identity from the admitted request.
    pub task_id: TaskId,
    /// Exact work scope from the admitted request identity.
    pub work_scope_id: String,
    /// Action-specific typed proposal, command bundle, or Orientation submit.
    pub task_input: Value,
    /// Owner-native `LearningStateViewRecipe` selected for this task route.
    pub learning_state_view_recipe: Value,
    /// Approved reusable `ContextRecipePolicy` the Context recipe was issued
    /// under. The Context owner checks the binding; the protocol only carries it.
    pub context_campaign_recipe_policy: Value,
    /// Rich `ContextRecipe` selected for the current Context admission.
    pub context_campaign_recipe: Value,
    /// Exact `ContextInput` admitted for the current Context compilation.
    pub context_input: Value,
    /// Optional selector for the persisted prior delivery snapshot. This is a
    /// lookup selector only and is never evidence or source authority.
    pub prior_delivery_selector: Option<Value>,
    /// Optional complete owner-material bundle. When present, the daemon must
    /// assemble and validate every declared owner role before committing the
    /// Task Controller transition; it cannot infer any missing owner row.
    #[serde(default)]
    pub campaign_owner_materials: Option<TaskControllerCampaignOwnerMaterials>,
}

impl TaskControllerInvocation {
    /// Validates the transport envelope and bounded JSON object fields.
    /// Semantic field/identity validation remains with the daemon owners.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_wire_and_common_fields()?;
        self.validate_orientation_payload()?;
        self.validate_campaign_owner_materials()
    }

    fn validate_wire_and_common_fields(&self) -> Result<(), ProtocolError> {
        let version_supported = match self.action {
            TaskControllerAction::Propose | TaskControllerAction::Apply => {
                self.wire_version == TASK_CONTROLLER_INVOCATION_LEGACY_WIRE_VERSION
                    || self.wire_version == TASK_CONTROLLER_INVOCATION_ORIENTATION_WIRE_VERSION
                    || self.wire_version == TASK_CONTROLLER_INVOCATION_WIRE_VERSION
            }
            TaskControllerAction::DreamerOrientation => {
                self.wire_version == TASK_CONTROLLER_INVOCATION_ORIENTATION_WIRE_VERSION
            }
            TaskControllerAction::PrepareDreamerOrientation => {
                self.wire_version == TASK_CONTROLLER_INVOCATION_WIRE_VERSION
            }
        };
        if self.wire_id != TASK_CONTROLLER_INVOCATION_WIRE_ID || !version_supported {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.wire",
                reason: "unsupported Task Controller invocation",
            });
        }
        bounded_text(self.task_id.as_str(), "task_controller_invocation.task_id")?;
        bounded_text(
            &self.work_scope_id,
            "task_controller_invocation.work_scope_id",
        )?;
        for (value, field) in [
            (&self.task_input, "task_controller_invocation.task_input"),
            (
                &self.learning_state_view_recipe,
                "task_controller_invocation.learning_state_view_recipe",
            ),
            (
                &self.context_campaign_recipe_policy,
                "task_controller_invocation.context_campaign_recipe_policy",
            ),
            (
                &self.context_campaign_recipe,
                "task_controller_invocation.context_campaign_recipe",
            ),
            (
                &self.context_input,
                "task_controller_invocation.context_input",
            ),
        ] {
            structured_object(value, field)?;
        }
        Ok(())
    }

    fn validate_orientation_payload(&self) -> Result<(), ProtocolError> {
        match self.action {
            TaskControllerAction::DreamerOrientation => self.validate_sealed_orientation_payload(),
            TaskControllerAction::PrepareDreamerOrientation => {
                self.validate_orientation_prepare_payload()
            }
            TaskControllerAction::Propose | TaskControllerAction::Apply => Ok(()),
        }
    }

    fn validate_sealed_orientation_payload(&self) -> Result<(), ProtocolError> {
        let orientation: TaskControllerOrientationInput =
            serde_json::from_value(self.task_input.clone()).map_err(|_| {
                ProtocolError::InvalidField {
                    field: "task_controller_invocation.task_input",
                    reason: "must match the typed Orientation submit contract",
                }
            })?;
        orientation.validate()?;
        let JobOperation::Submit { submission } = &orientation.request.operation else {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.task_input",
                reason: "must carry the original Orientation submit request",
            });
        };
        let runtime_input = submission
            .decode_runtime_owner_execution_input()
            .map_err(|_| ProtocolError::InvalidField {
                field: "task_controller_invocation.runtime_owner_execution_input",
                reason: "must retain the original runtime owner publication",
            })?
            .ok_or(ProtocolError::InvalidField {
                field: "task_controller_invocation.runtime_owner_execution_input",
                reason: "is required for Orientation",
            })?;
        if runtime_input.context_input != self.context_input
            || runtime_input.context_campaign_recipe != self.context_campaign_recipe
            || runtime_input.context_campaign_recipe_policy != self.context_campaign_recipe_policy
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.runtime_owner_execution_input",
                reason: "must preserve exact original Context owner inputs",
            });
        }
        Ok(())
    }

    fn validate_orientation_prepare_payload(&self) -> Result<(), ProtocolError> {
        let input: TaskControllerOrientationPrepareInputV1 =
            serde_json::from_value(self.task_input.clone()).map_err(|_| {
                ProtocolError::InvalidField {
                    field: "task_controller_invocation.task_input",
                    reason: "must match the typed Orientation prepare contract",
                }
            })?;
        input.validate()?;
        if input.work_scope.scope_id.as_str() != self.work_scope_id.as_str() {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.task_input.work_scope",
                reason: "must preserve the exact admitted Task Controller scope",
            });
        }
        input.validate_runtime_owner_bindings(self)?;
        Ok(())
    }

    fn validate_campaign_owner_materials(&self) -> Result<(), ProtocolError> {
        if let Some(selector) = &self.prior_delivery_selector {
            structured_object(
                selector,
                "task_controller_invocation.prior_delivery_selector",
            )?;
        }
        if let Some(materials) = &self.campaign_owner_materials {
            structured_object(
                &materials.prior_delivery,
                "task_controller_invocation.campaign_owner_materials.prior_delivery",
            )?;
            structured_object(
                &materials.evaluation,
                "task_controller_invocation.campaign_owner_materials.evaluation",
            )?;
            if materials.source_heads.len() > 26 {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials.source_heads",
                    reason: "exceeds the closed owner-role denominator",
                });
            }
            for head in &materials.source_heads {
                structured_object(
                    head,
                    "task_controller_invocation.campaign_owner_materials.source_heads",
                )?;
            }
            if !materials.source_heads.is_empty() || !materials.remaining_owner_inputs.is_empty() {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials",
                    reason: "caller-supplied owner heads and rows are not authenticated evidence",
                });
            }
            if materials.remaining_owner_inputs.len() > 26 {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials.remaining_owner_inputs",
                    reason: "exceeds the closed owner-role denominator",
                });
            }
            for input in &materials.remaining_owner_inputs {
                structured_object(
                    input,
                    "task_controller_invocation.campaign_owner_materials.remaining_owner_inputs",
                )?;
            }
        }
        Ok(())
    }
}

/// Kernel-issued fenced attempt bound to one Task Controller operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerAttempt {
    /// Attempt capability wire identity.
    pub wire_id: String,
    /// Attempt capability wire version.
    pub wire_version: u16,
    /// Opaque operation identity derived from the admitted envelope digest.
    pub operation_id: String,
    /// Unique Kernel-issued attempt identity.
    pub attempt_id: String,
    /// Monotonic generation for this operation.
    pub fencing_generation: u64,
    /// Authenticated session bound to this attempt.
    pub session_id: String,
    /// Authority epoch observed when the Kernel issued the attempt.
    pub authority_epoch: EpochId,
    /// Exact admitted work scope.
    pub scope_id: String,
    /// Absolute attempt expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Remaining result submissions permitted by the Kernel.
    pub use_budget: u32,
    /// Exact native task identity bound to the admitted operation.
    pub task_id: TaskId,
    /// Exact state fence admitted for this operation.
    pub state_fence: StateFence,
}

impl TaskControllerAttempt {
    /// Validates the bounded capability shape. Currency is still enforced by
    /// the Kernel's retained attempt record.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_ATTEMPT_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_ATTEMPT_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.wire",
                reason: "unsupported Task Controller attempt",
            });
        }
        validate_operation_id(&self.operation_id, "task_controller_attempt.operation_id")?;
        bounded_text(&self.attempt_id, "task_controller_attempt.attempt_id")?;
        if self.attempt_id == self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.attempt_id",
                reason: "attempt identity must not reuse the operation handle",
            });
        }
        if self.fencing_generation == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.fencing_generation",
                reason: "fencing generation must be positive",
            });
        }
        bounded_text(&self.session_id, "task_controller_attempt.session_id")?;
        epoch_identity_digest(&self.authority_epoch).map_err(|_| ProtocolError::InvalidField {
            field: "task_controller_attempt.authority_epoch",
            reason: "authority epoch is not valid",
        })?;
        bounded_text(&self.scope_id, "task_controller_attempt.scope_id")?;
        bounded_text(self.task_id.as_str(), "task_controller_attempt.task_id")?;
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.authority_epoch",
                reason: "must exactly match the State Fence authority epoch",
            });
        }
        if self.expires_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.expires_at_unix_ms",
                reason: "attempt expiry must be greater than zero",
            });
        }
        if self.use_budget == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.use_budget",
                reason: "attempt use budget must be positive",
            });
        }
        Ok(())
    }
}

/// Exact bounded Task Controller response bound to its invocation and attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerResultBody {
    /// Result body wire identity.
    pub wire_id: String,
    /// Result body wire version.
    pub wire_version: u16,
    /// Opaque operation identity derived from the admitted envelope digest.
    pub operation_id: String,
    /// SHA-256 of the exact admitted request envelope.
    pub request_sha256: String,
    /// Canonical digest over the exact bounded response JSON.
    pub result_digest: String,
    /// Exact Task Controller response payload.
    pub response: Value,
    /// Required current attempt for this result submission.
    pub attempt: TaskControllerAttempt,
}

impl TaskControllerResultBody {
    /// Validates wire identity, bounded result bytes, request binding and the
    /// required current-attempt shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_RESULT_BODY_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.wire",
                reason: "unsupported Task Controller result body",
            });
        }
        validate_operation_id(
            &self.operation_id,
            "task_controller_result_body.operation_id",
        )?;
        lowercase_sha256(
            &self.request_sha256,
            "task_controller_result_body.request_sha256",
        )?;
        let operation_digest =
            self.operation_id
                .strip_prefix("hostreq:")
                .ok_or(ProtocolError::InvalidField {
                    field: "task_controller_result_body.operation_id",
                    reason: "must be the deterministic handle for its request digest",
                })?;
        if operation_digest != self.request_sha256 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.request_sha256",
                reason: "request digest does not match the operation handle",
            });
        }
        lowercase_sha256(
            &self.result_digest,
            "task_controller_result_body.result_digest",
        )?;
        if !self.response.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.response",
                reason: "result body must be a JSON object",
            });
        }
        let bytes = canonical_json_bytes(&self.response)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if bytes.len() > HARD_STRUCTURED_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.response",
                reason: "result body exceeds the bounded response ceiling",
            });
        }
        if eliot_contracts::sha256_hex(&bytes) != self.result_digest {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.result_digest",
                reason: "result digest does not bind the exact response bytes",
            });
        }
        self.attempt.validate()?;
        if self.attempt.operation_id != self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.attempt",
                reason: "attempt does not bind the exact operation handle",
            });
        }
        Ok(())
    }
}

fn validate_operation_id(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    bounded_text(value, field)?;
    if !value.strip_prefix("hostreq:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a hostreq handle containing a lowercase SHA-256 digest",
        });
    }
    Ok(())
}
