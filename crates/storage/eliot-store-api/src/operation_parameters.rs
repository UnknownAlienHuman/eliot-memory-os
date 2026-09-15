//! Owner-approved typed parameter contracts for activated named operations.
//!
//! Slice C1 (issue #19) activates exactly five named reads with proven
//! adapter handlers, parameter shapes, and consumers:
//! `GetRevisionHeads`, `GetOrderingHeads`, `GetScopeRevisionView`,
//! `ResolveWriteReceipt`, and `GetEvidencePack` (see
//! `apply/read_boundary.rs` in the Surreal adapter and `execute_named_sync`
//! in the memory adapter), plus the three
//! `CaptureObservation` / `AppendAuditEvent` / `ApplyLifecyclePolicy` /
//! `ReconcileRecovery` mutations (AUD-C01: `CaptureObservation` and `AppendAuditEvent` persist
//! `TransitionClass::CaptureCandidate` with the `EffectClass::Candidate`
//! ceiling; `CaptureObservation` carries the owner-shaped `subject` string
//! already used by the adapter receipt/plan fixtures, `AppendAuditEvent`
//! carries the six receipt-bound operator fields emitted by the Governor
//! reconciliation, `ApplyLifecyclePolicy` carries the six lifecycle-policy
//! fields emitted by the Governor skill promotion envelope
//! (`crates/governor/eliot-governor/src/skill_lifecycle.rs`, `skill_envelope`),
//! `ReconcileRecovery` carries the ten problem-leg recovery fields emitted by
//! the Governor doctor verification envelope
//! (`crates/governor/eliot-governor/src/observation_reconciliation.rs`,
//! `recovery_envelope`).
//! Every other [`NamedReadOperation`](crate::NamedReadOperation) variant and
//! every other [`NamedMutationOperation`](crate::NamedMutationOperation)
//! variant stays known-but-unsupported and unadvertised, and no other mutation
//! has an owner-approved typed schema yet.
//!
//! This module is the single source of truth for those contracts: the closed
//! operation-name mapping, the declared parameter list per activated
//! operation, the serializable parameter-schema projection bound into each
//! [`NamedOperationManifest`](crate::NamedOperationManifest), and the
//! pre-dispatch typed validation. There are no parallel YAML/JSON/Rust lists.
//!
//! Validation is control-contract only and issues no authority: scope, role,
//! fence, and expiry enforcement stay in slice C2. An explicitly declared
//! parameter (today `operation_id` for `ResolveWriteReceipt`, `subject`
//! for `CaptureObservation`, the six receipt-bound fields for
//! `AppendAuditEvent`, the six lifecycle-policy fields for
//! `ApplyLifecyclePolicy`, the ten problem-leg recovery fields for
//! `ReconcileRecovery`, and the `subject` / `max_records` evidence-pack
//! selectors for `GetEvidencePack`) is owner-approved and therefore supersedes the
//! generic [`CONTROL_FIELD_DENYLIST`](crate::CONTROL_FIELD_DENYLIST) for that
//! exact name; every undeclared control name is still rejected fail-closed.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CONTROL_FIELD_DENYLIST, NamedMutationOperation, NamedReadOperation, OperationId, StoreError,
    canonical_json_bytes, sha256_hex,
};

/// Closed shape vocabulary for owner-approved named-operation parameters.
///
/// Slice C1 needs exactly two shapes: the `operation_id` string consumed by
/// `ResolveWriteReceipt` (reused for the receipt-bound `AppendAuditEvent`
/// `operation_id` and for the problem-leg `ReconcileRecovery`
/// `observation_operation_id`) and the non-blank text captured by `CaptureObservation`
/// as `subject` (reused for the five remaining receipt-bound
/// `AppendAuditEvent` fields, for the six lifecycle-policy
/// `ApplyLifecyclePolicy` fields, for the nine remaining problem-leg
/// `ReconcileRecovery` fields, and for the two `GetEvidencePack`
/// evidence-pack selectors: the exact captured-observation `subject` and the
/// explicit `max_records` bound carried as its decimal string, mirroring how
/// `AppendAuditEvent` carries `expected_revision` and how `ReconcileRecovery`
/// carries `expected_problem_revision`). The enum is closed so a future parameter kind
/// is a contract change with a new owner-approved arm, never silent `Value`
/// passthrough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterShape {
    /// The closed versioned candidate/transition payload with position CAS.
    EpistemicRevision,
    /// A string that must parse as a store [`OperationId`].
    OperationId,
    /// A non-blank text string: the observation subject captured by
    /// `CaptureObservation`, reused for the non-`operation_id` receipt-bound
    /// `AppendAuditEvent` fields (`idempotency_key`, `session_id`,
    /// `access_digest`, `action_digest`, and `expected_revision` as its
    /// decimal string), for the six lifecycle-policy `ApplyLifecyclePolicy`
    /// fields (`action`, `base_view_digest`, `candidate_digest`,
    /// `candidate_package_digest`, `skill_id`, `verifier_ref`), for the nine
    /// non-`observation_operation_id` problem-leg `ReconcileRecovery` fields
    /// (`problem_id`, `expected_problem_revision` as its decimal string,
    /// `attempt_digest`, `effect_digest`, `operation_manifest_digest`,
    /// `artifact_binding_digest`, `fence_digest`, `observation_record_id`,
    /// and `observation_request_digest`), and for the
    /// two `GetEvidencePack` selectors (the exact captured-observation
    /// `subject` and the explicit `max_records` bound as its decimal
    /// string, range-checked against
    /// [`EVIDENCE_PACK_MAX_RECORDS`](crate::operation_catalogue::EVIDENCE_PACK_MAX_RECORDS) by
    /// every handler). Length is bounded by the owning manifest entry's
    /// `max_input_bytes` over the canonical parameter bytes (the same
    /// mechanism that bounds the activated reads), so no separate string
    /// length constant exists here.
    Subject,
}

impl ParameterShape {
    /// Stable schema code bound into the parameter-schema digest.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EpistemicRevision => "eliot.storage.epistemic-revision.v1",
            Self::OperationId => "operation-id",
            Self::Subject => "subject-text",
        }
    }
}

/// One owner-approved parameter declaration for an activated operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterDeclaration {
    /// Exact parameter name. Membership is exact: unknown or extra names fail.
    pub name: &'static str,
    /// Required value shape for this parameter.
    pub shape: ParameterShape,
    /// Whether the parameter must be present.
    pub required: bool,
}

const OPERATION_ID_DECLARATION: ParameterDeclaration = ParameterDeclaration {
    name: "operation_id",
    shape: ParameterShape::OperationId,
    required: true,
};

static RESOLVE_WRITE_RECEIPT_PARAMETERS: [ParameterDeclaration; 1] = [OPERATION_ID_DECLARATION];
static GET_EVIDENCE_PACK_PARAMETERS: [ParameterDeclaration; 2] = [
    ParameterDeclaration {
        name: "subject",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "max_records",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static CAPTURE_OBSERVATION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "subject",
    shape: ParameterShape::Subject,
    required: true,
}];
static APPEND_AUDIT_EVENT_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "operation_id",
        shape: ParameterShape::OperationId,
        required: true,
    },
    ParameterDeclaration {
        name: "idempotency_key",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "session_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "access_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "action_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static APPLY_LIFECYCLE_POLICY_PARAMETERS: [ParameterDeclaration; 6] = [
    ParameterDeclaration {
        name: "action",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "base_view_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "candidate_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "candidate_package_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "skill_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "verifier_ref",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static RECONCILE_RECOVERY_PARAMETERS: [ParameterDeclaration; 10] = [
    ParameterDeclaration {
        name: "problem_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "expected_problem_revision",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "attempt_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "effect_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "operation_manifest_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "artifact_binding_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "fence_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_operation_id",
        shape: ParameterShape::OperationId,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_record_id",
        shape: ParameterShape::Subject,
        required: true,
    },
    ParameterDeclaration {
        name: "observation_request_digest",
        shape: ParameterShape::Subject,
        required: true,
    },
];
static NO_PARAMETERS: [ParameterDeclaration; 0] = [];
static EPISTEMIC_REVISION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "revision",
    shape: ParameterShape::EpistemicRevision,
    required: true,
}];
static CURRENT_POSITION_PARAMETERS: [ParameterDeclaration; 1] = [ParameterDeclaration {
    name: "position",
    shape: ParameterShape::Subject,
    required: true,
}];

/// Returns the canonical operation name bound into manifests and digests.
///
/// The spelling matches the `PascalCase` serde wire form of each variant, so
/// one closed match is the single name owner for code, manifests, and wire.
#[must_use]
pub const fn named_read_operation_name(operation: NamedReadOperation) -> &'static str {
    match operation {
        NamedReadOperation::GetRevisionHeads => "GetRevisionHeads",
        NamedReadOperation::GetScopeRevisionView => "GetScopeRevisionView",
        NamedReadOperation::GetOrderingHeads => "GetOrderingHeads",
        NamedReadOperation::GetTaskState => "GetTaskState",
        NamedReadOperation::GetCurrentEpistemicPosition => "GetCurrentEpistemicPosition",
        NamedReadOperation::GetEvidencePack => "GetEvidencePack",
        NamedReadOperation::GetUnderstandingProjectionInputs => "GetUnderstandingProjectionInputs",
        NamedReadOperation::GetAttentionAndProblems => "GetAttentionAndProblems",
        NamedReadOperation::GetModuleCatalogState => "GetModuleCatalogState",
        NamedReadOperation::GetCapabilityEvidenceState => "GetCapabilityEvidenceState",
        NamedReadOperation::GetConformanceState => "GetConformanceState",
        NamedReadOperation::GetMailbox => "GetMailbox",
        NamedReadOperation::GetAuditRange => "GetAuditRange",
        NamedReadOperation::ResolveWriteReceipt => "ResolveWriteReceipt",
    }
}

/// Resolves a canonical operation name back to its closed read variant.
#[must_use]
pub const fn named_read_operation_by_name(name: &str) -> Option<NamedReadOperation> {
    // `&str` equality is `const`-compatible; keep this a closed match so a
    // renamed variant is a compile-time event, not a silent miss.
    match name.as_bytes() {
        b"GetRevisionHeads" => Some(NamedReadOperation::GetRevisionHeads),
        b"GetScopeRevisionView" => Some(NamedReadOperation::GetScopeRevisionView),
        b"GetOrderingHeads" => Some(NamedReadOperation::GetOrderingHeads),
        b"GetTaskState" => Some(NamedReadOperation::GetTaskState),
        b"GetCurrentEpistemicPosition" => Some(NamedReadOperation::GetCurrentEpistemicPosition),
        b"GetEvidencePack" => Some(NamedReadOperation::GetEvidencePack),
        b"GetUnderstandingProjectionInputs" => {
            Some(NamedReadOperation::GetUnderstandingProjectionInputs)
        }
        b"GetAttentionAndProblems" => Some(NamedReadOperation::GetAttentionAndProblems),
        b"GetModuleCatalogState" => Some(NamedReadOperation::GetModuleCatalogState),
        b"GetCapabilityEvidenceState" => Some(NamedReadOperation::GetCapabilityEvidenceState),
        b"GetConformanceState" => Some(NamedReadOperation::GetConformanceState),
        b"GetMailbox" => Some(NamedReadOperation::GetMailbox),
        b"GetAuditRange" => Some(NamedReadOperation::GetAuditRange),
        b"ResolveWriteReceipt" => Some(NamedReadOperation::ResolveWriteReceipt),
        _ => None,
    }
}

/// Returns the canonical operation name for a closed mutation variant.
#[must_use]
pub const fn named_mutation_operation_name(operation: NamedMutationOperation) -> &'static str {
    match operation {
        NamedMutationOperation::CaptureObservation => "CaptureObservation",
        NamedMutationOperation::ApplyEpistemicRevision => "ApplyEpistemicRevision",
        NamedMutationOperation::UpdateTaskState => "UpdateTaskState",
        NamedMutationOperation::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
        NamedMutationOperation::ReconcileRecovery => "ReconcileRecovery",
        NamedMutationOperation::AppendAuditEvent => "AppendAuditEvent",
    }
}

/// Resolves a canonical operation name back to its closed mutation variant.
#[must_use]
pub const fn named_mutation_operation_by_name(name: &str) -> Option<NamedMutationOperation> {
    match name.as_bytes() {
        b"CaptureObservation" => Some(NamedMutationOperation::CaptureObservation),
        b"ApplyEpistemicRevision" => Some(NamedMutationOperation::ApplyEpistemicRevision),
        b"UpdateTaskState" => Some(NamedMutationOperation::UpdateTaskState),
        b"ApplyLifecyclePolicy" => Some(NamedMutationOperation::ApplyLifecyclePolicy),
        b"ReconcileRecovery" => Some(NamedMutationOperation::ReconcileRecovery),
        b"AppendAuditEvent" => Some(NamedMutationOperation::AppendAuditEvent),
        _ => None,
    }
}

/// Returns the owner-approved parameter declarations for one read operation.
///
/// `ResolveWriteReceipt` declares the required `operation_id` parameter and
/// `GetEvidencePack` declares the required bounded exact selectors (the
/// exact captured-observation `subject` and the explicit `max_records`
/// bound); every other variant declares none, so any supplied parameter
/// fails closed. Variants without a catalogue entry never reach this table:
/// they fail as [`StoreError::UnknownOperation`] first.
#[must_use]
pub const fn declared_read_parameters(
    operation: NamedReadOperation,
) -> &'static [ParameterDeclaration] {
    match operation {
        NamedReadOperation::ResolveWriteReceipt => &RESOLVE_WRITE_RECEIPT_PARAMETERS,
        NamedReadOperation::GetEvidencePack => &GET_EVIDENCE_PACK_PARAMETERS,
        NamedReadOperation::GetCurrentEpistemicPosition => &CURRENT_POSITION_PARAMETERS,
        NamedReadOperation::GetRevisionHeads
        | NamedReadOperation::GetScopeRevisionView
        | NamedReadOperation::GetOrderingHeads
        | NamedReadOperation::GetTaskState
        | NamedReadOperation::GetUnderstandingProjectionInputs
        | NamedReadOperation::GetAttentionAndProblems
        | NamedReadOperation::GetModuleCatalogState
        | NamedReadOperation::GetCapabilityEvidenceState
        | NamedReadOperation::GetConformanceState
        | NamedReadOperation::GetMailbox
        | NamedReadOperation::GetAuditRange => &NO_PARAMETERS,
    }
}

/// Returns the owner-approved parameter declarations for one mutation.
///
/// `CaptureObservation` declares the required owner-shaped `subject` string;
/// `AppendAuditEvent` declares the six required receipt-bound fields
/// (`operation_id`, `idempotency_key`, `session_id`, `access_digest`,
/// `action_digest`, `expected_revision`); `ApplyLifecyclePolicy` declares the
/// six required lifecycle-policy fields (`action`, `base_view_digest`,
/// `candidate_digest`, `candidate_package_digest`, `skill_id`,
/// `verifier_ref`); `ReconcileRecovery` declares the ten required
/// problem-leg recovery fields (`problem_id`, `expected_problem_revision`,
/// `attempt_digest`, `effect_digest`, `operation_manifest_digest`,
/// `artifact_binding_digest`, `fence_digest`, `observation_operation_id`,
/// `observation_record_id`, `observation_request_digest`); every other variant declares none,
/// so any supplied parameter fails closed. Variants without a catalogue entry
/// never reach this table: they fail as [`StoreError::UnknownOperation`] first.
#[must_use]
pub const fn declared_mutation_parameters(
    operation: NamedMutationOperation,
) -> &'static [ParameterDeclaration] {
    match operation {
        NamedMutationOperation::CaptureObservation => &CAPTURE_OBSERVATION_PARAMETERS,
        NamedMutationOperation::AppendAuditEvent => &APPEND_AUDIT_EVENT_PARAMETERS,
        NamedMutationOperation::ApplyLifecyclePolicy => &APPLY_LIFECYCLE_POLICY_PARAMETERS,
        NamedMutationOperation::ReconcileRecovery => &RECONCILE_RECOVERY_PARAMETERS,
        NamedMutationOperation::ApplyEpistemicRevision => &EPISTEMIC_REVISION_PARAMETERS,
        NamedMutationOperation::UpdateTaskState => &NO_PARAMETERS,
    }
}

/// Serializable parameter-schema projection stored in each manifest entry.
///
/// The stored projection is what [`parameter_schema_digest`] binds, so the
/// entry digest transitively binds the exact owner-approved schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParameterSchemaField {
    /// Exact parameter name.
    pub name: String,
    /// Stable [`ParameterShape`] code.
    pub shape: String,
    /// Whether the parameter must be present.
    pub required: bool,
}

/// Projects the declared parameters of one read into the stored schema form.
#[must_use]
pub fn project_parameter_schema(operation: NamedReadOperation) -> Vec<ParameterSchemaField> {
    declared_read_parameters(operation)
        .iter()
        .map(|declaration| ParameterSchemaField {
            name: declaration.name.to_owned(),
            shape: declaration.shape.code().to_owned(),
            required: declaration.required,
        })
        .collect()
}

/// Projects the declared parameters of one mutation into the stored schema form.
#[must_use]
pub fn project_mutation_parameter_schema(
    operation: NamedMutationOperation,
) -> Vec<ParameterSchemaField> {
    declared_mutation_parameters(operation)
        .iter()
        .map(|declaration| ParameterSchemaField {
            name: declaration.name.to_owned(),
            shape: declaration.shape.code().to_owned(),
            required: declaration.required,
        })
        .collect()
}

/// Computes the schema digest bound into a manifest entry.
///
/// The digest binds the canonical bytes of the stored parameter-schema
/// projection, so any added, removed, or reshaped parameter changes the
/// entry digest and therefore the catalogue set digest.
pub fn parameter_schema_digest(schema: &[ParameterSchemaField]) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(&schema)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Validates read parameters against the owner-approved typed declaration.
///
/// Membership is exact: an undeclared name fails, with control-denylisted
/// names reported as control substitution and any other undeclared name
/// reported as unknown. Declared values must match their declared shape;
/// required parameters must be present. This runs pre-dispatch and issues
/// no authority.
pub fn validate_typed_read_parameters(
    operation: NamedReadOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let declared = declared_read_parameters(operation);
    for (name, value) in parameters {
        if let Some(declaration) = declared.iter().find(|field| field.name == name.as_str()) {
            check_declared_shape(declaration, value)?;
        } else {
            if CONTROL_FIELD_DENYLIST.contains(&name.as_str()) {
                return Err(StoreError::InvalidField {
                    field: "payload.control_field",
                    reason: "payload must not override a control field",
                });
            }
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "unknown parameter for operation",
            });
        }
    }
    for declaration in declared {
        if declaration.required && !parameters.contains_key(declaration.name) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            });
        }
    }
    Ok(())
}

/// Validates mutation parameters against the owner-approved typed declaration.
///
/// Same closed contract as [`validate_typed_read_parameters`]: exact
/// membership, control-substitution rejection, required presence, and declared
/// shape. Runs pre-dispatch and issues no authority.
pub fn validate_typed_mutation_parameters(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let declared = declared_mutation_parameters(operation);
    for (name, value) in parameters {
        if let Some(declaration) = declared.iter().find(|field| field.name == name.as_str()) {
            check_declared_shape(declaration, value)?;
        } else {
            if CONTROL_FIELD_DENYLIST.contains(&name.as_str()) {
                return Err(StoreError::InvalidField {
                    field: "payload.control_field",
                    reason: "payload must not override a control field",
                });
            }
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "unknown parameter for operation",
            });
        }
    }
    for declaration in declared {
        if declaration.required && !parameters.contains_key(declaration.name) {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "missing required parameter",
            });
        }
    }
    Ok(())
}

fn check_declared_shape(
    declaration: &ParameterDeclaration,
    value: &Value,
) -> Result<(), StoreError> {
    match declaration.shape {
        ParameterShape::EpistemicRevision => {
            let payload: crate::epistemic_revision::EpistemicRevisionPayload =
                serde_json::from_value(value.clone())
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
            payload.validate()
        }
        ParameterShape::OperationId => {
            let text = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "operation_id must be a string operation identity",
            })?;
            OperationId::new(text).map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "operation_id must be a valid operation identity",
            })?;
            Ok(())
        }
        ParameterShape::Subject => {
            let text = value.as_str().ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "subject must be a non-blank string",
            })?;
            // Same store text rule as every other identifier boundary
            // (non-blank, no control characters); stated inline because the
            // generic text helper lives in the crate root.
            if text.trim().is_empty() || text.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "subject must be a non-blank string",
                });
            }
            Ok(())
        }
    }
}
