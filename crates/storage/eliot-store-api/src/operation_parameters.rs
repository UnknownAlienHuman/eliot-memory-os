//! Owner-approved typed parameter contracts for activated named operations.
//!
//! Slice C1 (issue #19) activates exactly four named reads with proven
//! adapter handlers, parameter shapes, and consumers:
//! `GetRevisionHeads`, `GetOrderingHeads`, `GetScopeRevisionView`, and
//! `ResolveWriteReceipt` (see `apply/read_boundary.rs` in the Surreal adapter
//! and `execute_named_sync` in the memory adapter). Every other
//! [`NamedReadOperation`](crate::NamedReadOperation) variant stays
//! known-but-unsupported and unadvertised, and no mutation has an
//! owner-approved typed schema yet.
//!
//! This module is the single source of truth for those contracts: the closed
//! operation-name mapping, the declared parameter list per activated
//! operation, the serializable parameter-schema projection bound into each
//! [`NamedOperationManifest`](crate::NamedOperationManifest), and the
//! pre-dispatch typed validation. There are no parallel YAML/JSON/Rust lists.
//!
//! Validation is control-contract only and issues no authority: scope, role,
//! fence, and expiry enforcement stay in slice C2. An explicitly declared
//! parameter (today only `operation_id` for `ResolveWriteReceipt`) is
//! owner-approved and therefore supersedes the generic
//! [`CONTROL_FIELD_DENYLIST`](crate::CONTROL_FIELD_DENYLIST) for that exact
//! name; every undeclared control name is still rejected fail-closed.

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
/// Slice C1 needs exactly one shape: the `operation_id` string consumed by
/// `ResolveWriteReceipt`. The enum is closed so a future parameter kind is a
/// contract change with a new owner-approved arm, never silent `Value`
/// passthrough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterShape {
    /// A string that must parse as a store [`OperationId`].
    OperationId,
}

impl ParameterShape {
    /// Stable schema code bound into the parameter-schema digest.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OperationId => "operation-id",
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
static NO_PARAMETERS: [ParameterDeclaration; 0] = [];

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
        NamedReadOperation::GetUnderstandingProjectionInputs => {
            "GetUnderstandingProjectionInputs"
        }
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
/// Only `ResolveWriteReceipt` declares a parameter on base; every other
/// variant declares none, so any supplied parameter fails closed.
#[must_use]
pub const fn declared_read_parameters(
    operation: NamedReadOperation,
) -> &'static [ParameterDeclaration] {
    match operation {
        NamedReadOperation::ResolveWriteReceipt => &RESOLVE_WRITE_RECEIPT_PARAMETERS,
        NamedReadOperation::GetRevisionHeads
        | NamedReadOperation::GetScopeRevisionView
        | NamedReadOperation::GetOrderingHeads
        | NamedReadOperation::GetTaskState
        | NamedReadOperation::GetCurrentEpistemicPosition
        | NamedReadOperation::GetEvidencePack
        | NamedReadOperation::GetUnderstandingProjectionInputs
        | NamedReadOperation::GetAttentionAndProblems
        | NamedReadOperation::GetModuleCatalogState
        | NamedReadOperation::GetCapabilityEvidenceState
        | NamedReadOperation::GetConformanceState
        | NamedReadOperation::GetMailbox
        | NamedReadOperation::GetAuditRange => &NO_PARAMETERS,
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

fn check_declared_shape(
    declaration: &ParameterDeclaration,
    value: &Value,
) -> Result<(), StoreError> {
    match declaration.shape {
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
    }
}
