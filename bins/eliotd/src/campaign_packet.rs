//! Authenticated campaign-packet dispatch for the production daemon.
//!
//! The packet arguments select an optional refresh target and bounded
//! material handles only. The task, scope and fence are derived from the
//! Kernel-admitted envelope and rechecked against the retained Kernel
//! snapshot before any named owner read is made.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context::campaign_publication::{
    ContextCampaignRecipeBody, context_delivery_body_digest, context_recipe_body_digest,
};
use eliot_context_contracts::SessionDeliverySnapshot;
use eliot_contracts::{ArtifactId, StateFence, TaskId, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::{
    CampaignLearningStateView, CampaignOwnerRecordId, CampaignOwnerRevision, CampaignPositionKind,
    CampaignPositionRef, CampaignSourceBinding, CampaignSourceRequirement,
    CampaignSourceResolution, CampaignSourceResolutionStatus, CampaignSourceRevisionRef,
    CampaignSourceRole, CampaignViewRebuildReason, Completeness, LearningStateViewRecipe,
    OwnerDisagreement, OwnerId, TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_learning_state_view::{
    CampaignHistoryPlanInput, CampaignLearningStateCompilationInput,
    compile_campaign_learning_state_view, validate_campaign_learning_state_view_current,
};
use eliot_protocol::{
    HOST_REQUEST_INVOKE_READ_WIRE_ID, HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope,
    HostRequestInvokeReadPayload, HostRequestResultBody, LocalReadAttempt,
    host_request_operation_id,
};
use eliot_reactive_context_plan::RetrievalPlan;
use eliot_store_api::{
    CampaignHistoryPlanRecord, CampaignLearningStateViewLookup,
    CampaignLearningStateViewPublication, CampaignLearningStateViewRead,
    CampaignLearningStateViewReadStatus, CampaignSourceHead, CampaignSourceReadStatus,
    CampaignSourceRecord, CampaignSourceRevisionLookup, CampaignSourceRevisionRead,
    NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::DaemonKernelClient;

/// Maximum distinct material selectors admitted by one campaign packet.
pub const MAX_CAMPAIGN_PACKET_MATERIALS: usize = 256;

/// Whether a claimed tool pair selects the campaign packet compiler.
#[must_use]
pub fn is_campaign_packet_tool(tool: &Value) -> bool {
    tool.as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        == Some("eliot.packet")
}

/// Closed selector set from the public `eliot.packet` contract. These values
/// never supply owner, revision, digest or currentness authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPacketSelectors {
    /// Optional packet refresh selector.
    pub packet_ref: Option<String>,
    /// Bounded material handles requested by the caller.
    pub material_refs: Vec<String>,
}

/// Exact task/scope binding authenticated by the admitted invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignPacketBinding {
    /// Task identity supplied as a selector and validated by Kernel admission.
    pub task_id: String,
    /// Work scope supplied as a selector and validated by Kernel admission.
    pub work_scope_id: String,
    /// Exact fence carried by the admitted request and retained Kernel client.
    pub state_fence: StateFence,
}

/// Closed packet-pair validation failures. Error text never reflects caller
/// payload bytes or owner material.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignPacketError {
    /// The envelope/tool pair is not a valid `eliot.packet` invocation.
    #[error("campaign packet invocation is malformed or not admitted as eliot.packet")]
    InvalidInvocation,
    /// The request is not bound to a task and work scope.
    #[error("campaign packet requires an admitted task and work scope")]
    MissingTaskBinding,
    /// The task-bound request has no exact task revision in its fence.
    #[error("campaign packet requires an exact task revision in its State Fence")]
    MissingTaskRevision,
    /// The request fence does not equal the retained Kernel fence.
    #[error("campaign packet State Fence differs from the retained Kernel fence")]
    FenceMismatch,
    /// The packet argument object is not in its closed selector shape.
    #[error("campaign packet selectors are malformed or exceed their bound")]
    InvalidSelectors,
    /// The packet's previous immutable view could not be resolved exactly.
    #[error("campaign packet reference does not identify a retained view for this task and scope")]
    PriorViewUnavailable,
    /// A named campaign owner read failed closed or returned an invalid body.
    #[error("campaign owner read failed closed")]
    OwnerReadUnavailable,
    /// A current task recipe is missing, stale, or not bound to the admitted task.
    #[error("campaign TaskPlan recipe does not match the admitted task and fence")]
    InvalidTaskPlan,
}

struct ResolvedCampaignSources {
    resolutions: Vec<CampaignSourceResolution>,
    current_records: Vec<CampaignSourceRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CampaignPacketOutcome {
    Compiled,
    Stale,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CampaignPacketGapCode {
    TaskPlanUnavailable,
    PriorViewUnavailable,
    OwnerReadUnavailable,
    HistoryPlanUnavailable,
    RequiredSourceUnavailable,
    ContextRecipeUnavailable,
    ContextDeliveryUnavailable,
    ContextCompilationRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignPacketGap {
    code: CampaignPacketGapCode,
    role: Option<CampaignSourceRole>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignPacketResponse {
    outcome: CampaignPacketOutcome,
    completeness: Completeness,
    #[serde(rename = "campaign_learning_state_view")]
    view: Option<CampaignLearningStateViewPublication>,
    compiled_context: Option<eliot_context::CampaignCompiledContext>,
    gaps: Vec<CampaignPacketGap>,
    missing_roles: Vec<CampaignSourceRole>,
    stale_roles: Vec<CampaignSourceRole>,
    blocked_roles: Vec<CampaignSourceRole>,
    prior_view_reused: bool,
    prior_view_rejected_stale: bool,
}

struct ValidatedHistoryPlans {
    plans: Vec<RetrievalPlan>,
    records: Vec<CampaignHistoryPlanRecord>,
}

impl ValidatedHistoryPlans {
    fn compiler_inputs(&self) -> Vec<CampaignHistoryPlanInput<'_>> {
        self.plans
            .iter()
            .zip(&self.records)
            .map(|(plan, record)| CampaignHistoryPlanInput {
                plan,
                selected_handles: record.selected_handles.clone(),
                summary_digest: record.summary_digest.clone(),
                diff_digests: record.diff_digests.clone(),
                policy_slice_handles: record.policy_slice_handles.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PacketArguments {
    #[serde(default)]
    packet_ref: Option<String>,
    #[serde(default)]
    material_refs: Vec<String>,
}

/// Revalidates the admitted packet pair and extracts only its caller selectors
/// plus the authenticated task/scope/fence binding. It performs no owner read.
pub fn validate_campaign_packet_pair(
    envelope: &HostRequestEnvelope,
    tool: &Value,
    retained_kernel_fence: &StateFence,
) -> Result<(CampaignPacketBinding, CampaignPacketSelectors), CampaignPacketError> {
    HostRequestInvokeReadPayload {
        wire_id: HOST_REQUEST_INVOKE_READ_WIRE_ID.to_owned(),
        wire_version: HostRequestInvokeReadPayload::CONTRACT_VERSION,
        envelope: envelope.clone(),
        tool: tool.clone(),
    }
    .validate()
    .map_err(|_| CampaignPacketError::InvalidInvocation)?;
    if envelope.identity.capability != "eliot.packet"
        || tool
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str)
            != Some("eliot.packet")
    {
        return Err(CampaignPacketError::InvalidInvocation);
    }
    if envelope.state_fence != *retained_kernel_fence {
        return Err(CampaignPacketError::FenceMismatch);
    }
    if envelope.state_fence.task_revision.is_none() {
        return Err(CampaignPacketError::MissingTaskRevision);
    }
    let task_id = envelope
        .identity
        .task_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(CampaignPacketError::MissingTaskBinding)?;
    let work_scope_id = envelope
        .identity
        .work_scope_id
        .as_deref()
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(CampaignPacketError::MissingTaskBinding)?;
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .ok_or(CampaignPacketError::InvalidSelectors)?;
    let arguments: PacketArguments =
        serde_json::from_value(arguments).map_err(|_| CampaignPacketError::InvalidSelectors)?;
    if arguments
        .packet_ref
        .as_deref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        || arguments.material_refs.len() > MAX_CAMPAIGN_PACKET_MATERIALS
    {
        return Err(CampaignPacketError::InvalidSelectors);
    }
    let mut unique_materials = BTreeSet::new();
    for material in &arguments.material_refs {
        if material.trim().is_empty()
            || material.chars().any(char::is_control)
            || !unique_materials.insert(material.as_str())
        {
            return Err(CampaignPacketError::InvalidSelectors);
        }
    }
    Ok((
        CampaignPacketBinding {
            task_id: task_id.to_owned(),
            work_scope_id: work_scope_id.to_owned(),
            state_fence: envelope.state_fence.clone(),
        },
        CampaignPacketSelectors {
            packet_ref: arguments.packet_ref,
            material_refs: arguments.material_refs,
        },
    ))
}

/// Resolves one admitted packet into an immutable view and compiles its
/// decision-local context. The implementation uses only authenticated Kernel
/// named reads; caller selectors are not resolved as authority.
pub async fn serve_campaign_packet_pair(
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let retained_kernel_fence = kernel.kernel_fence();
    let (binding, selectors) =
        validate_campaign_packet_pair(envelope, tool, &retained_kernel_fence)
            .map_err(|error| error.to_string())?;
    attempt
        .validate()
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    if attempt.operation_id != host_request_operation_id(envelope)
        || attempt.scope_id != binding.work_scope_id
        || attempt.authority_epoch != envelope.state_fence.authority_epoch
        || attempt.expires_at_unix_ms != envelope.identity.deadline_unix_ms
        || attempt.facet_method != envelope.identity.capability
    {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    resolve_compile_and_bind_result(kernel, envelope, attempt, binding, selectors).await
}

#[allow(
    clippy::manual_let_else,
    clippy::too_many_lines,
    reason = "the production compiler keeps read admission, source binding, and view publication in one branch"
)]
async fn resolve_compile_and_bind_result(
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    binding: CampaignPacketBinding,
    selectors: CampaignPacketSelectors,
) -> Result<eliot_protocol::HostRequestResultBody, String> {
    let (recipe, task_plan_resolution, task_plan_record) =
        match read_task_plan_recipe(kernel, &binding).await {
            Ok(read) => read,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::TaskPlanUnavailable,
                            role: Some(CampaignSourceRole::TaskPlan),
                        }],
                        missing_roles: vec![CampaignSourceRole::TaskPlan],
                        stale_roles: Vec::new(),
                        blocked_roles: Vec::new(),
                        prior_view_reused: false,
                        prior_view_rejected_stale: false,
                    },
                );
            }
        };
    let prior = if let Some(packet_ref) = selectors.packet_ref.as_deref() {
        match read_prior_campaign_view(kernel, &binding, packet_ref).await {
            Ok(prior) => Some(prior),
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::PriorViewUnavailable,
                            role: None,
                        }],
                        missing_roles: Vec::new(),
                        stale_roles: Vec::new(),
                        blocked_roles: Vec::new(),
                        prior_view_reused: false,
                        prior_view_rejected_stale: false,
                    },
                );
            }
        }
    } else {
        None
    };
    let resolved = match resolve_manifest_sources(
        kernel,
        &binding,
        &recipe,
        task_plan_resolution,
        task_plan_record,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                CampaignPacketResponse {
                    outcome: CampaignPacketOutcome::Blocked,
                    completeness: Completeness::Blocked,
                    view: None,
                    compiled_context: None,
                    gaps: vec![CampaignPacketGap {
                        code: CampaignPacketGapCode::OwnerReadUnavailable,
                        role: None,
                    }],
                    missing_roles: Vec::new(),
                    stale_roles: Vec::new(),
                    blocked_roles: Vec::new(),
                    prior_view_reused: false,
                    prior_view_rejected_stale: false,
                },
            );
        }
    };
    let history_plan_set = match build_history_plan_set(&recipe, &resolved.current_records) {
        Ok(history) => history,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                CampaignPacketResponse {
                    outcome: CampaignPacketOutcome::Blocked,
                    completeness: Completeness::Blocked,
                    view: None,
                    compiled_context: None,
                    gaps: vec![CampaignPacketGap {
                        code: CampaignPacketGapCode::HistoryPlanUnavailable,
                        role: None,
                    }],
                    missing_roles: missing_roles(&resolved.resolutions),
                    stale_roles: stale_roles(&resolved.resolutions),
                    blocked_roles: blocked_roles(&resolved.resolutions),
                    prior_view_reused: false,
                    prior_view_rejected_stale: false,
                },
            );
        }
    };
    let current_history_plans = history_plan_set.compiler_inputs();
    let observed_at_ms = current_unix_ms()?;
    if u64::try_from(observed_at_ms).unwrap_or(u64::MAX) >= attempt.expires_at_unix_ms {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    let prior_covers_materials = prior.as_ref().is_some_and(|publication| {
        selectors.material_refs.iter().all(|selector| {
            ArtifactId::new(selector.clone())
                .is_ok_and(|handle| publication.view.required_references.contains(&handle))
        })
    });
    let prior_is_current = prior_covers_materials
        && prior.as_ref().is_some_and(|publication| {
            validate_campaign_learning_state_view_current(
                &publication.view,
                &recipe,
                &binding.state_fence,
                &resolved.resolutions,
                &current_history_plans,
                observed_at_ms,
            )
            .is_ok()
        });

    let view = if prior_is_current {
        prior
            .as_ref()
            .map(|publication| publication.view.clone())
            .ok_or_else(|| CampaignPacketError::PriorViewUnavailable.to_string())?
    } else {
        let projections = match collect_slot_projections(&recipe, &resolved) {
            Ok(projections) => projections,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: source_gaps(&resolved.resolutions),
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let required_references = match collect_required_references(
            &resolved.current_records,
            &selectors.material_refs,
        ) {
            Ok(references) => references,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::RequiredSourceUnavailable,
                            role: None,
                        }],
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let disagreements = collect_disagreements(&resolved.current_records);
        let positions = collect_positions(&resolved);
        let frozen_anchor_digest = resolved
            .resolutions
            .iter()
            .find(|resolution| resolution.role == CampaignSourceRole::FrozenAnchor)
            .and_then(|resolution| resolution.reference.as_ref())
            .map(|reference| reference.content_digest.as_str())
            .or_else(|| {
                recipe
                    .source_requirements
                    .iter()
                    .find(|requirement| requirement.role == CampaignSourceRole::FrozenAnchor)
                    .and_then(|requirement| requirement.expected_reference.as_ref())
                    .map(|reference| reference.content_digest.as_str())
            })
            .map(str::to_owned);
        let Some(frozen_anchor_digest) = frozen_anchor_digest else {
            return campaign_packet_result_body(
                envelope,
                attempt,
                CampaignPacketResponse {
                    outcome: CampaignPacketOutcome::Blocked,
                    completeness: Completeness::Blocked,
                    view: None,
                    compiled_context: None,
                    gaps: vec![CampaignPacketGap {
                        code: CampaignPacketGapCode::RequiredSourceUnavailable,
                        role: Some(CampaignSourceRole::FrozenAnchor),
                    }],
                    missing_roles: missing_roles(&resolved.resolutions),
                    stale_roles: stale_roles(&resolved.resolutions),
                    blocked_roles: blocked_roles(&resolved.resolutions),
                    prior_view_reused: false,
                    prior_view_rejected_stale: prior.is_some(),
                },
            );
        };
        let rebuild_reason = prior.as_ref().map(|publication| {
            if publication.view.binding.state_fence != binding.state_fence {
                CampaignViewRebuildReason::StateFenceChanged
            } else if publication
                .view
                .provenance
                .expires_at_ms
                .is_some_and(|expires_at| observed_at_ms >= expires_at)
            {
                CampaignViewRebuildReason::Expired
            } else if source_resolutions_differ(
                &publication.view.provenance.source_resolutions,
                &resolved.resolutions,
            ) {
                if policy_source_revision_changed(
                    &publication.view.provenance.source_resolutions,
                    &resolved.resolutions,
                ) {
                    CampaignViewRebuildReason::PolicyChanged
                } else {
                    CampaignViewRebuildReason::OwnerRevisionChanged
                }
            } else {
                CampaignViewRebuildReason::ExplicitRefresh
            }
        });
        match compile_campaign_learning_state_view(CampaignLearningStateCompilationInput {
            recipe: &recipe,
            projections: &projections,
            current_state_fence: &binding.state_fence,
            source_resolutions: &resolved.resolutions,
            required_references: &required_references,
            disagreements: &disagreements,
            positions: &positions,
            frozen_anchor_digest: &frozen_anchor_digest,
            history_plans: &current_history_plans,
            generated_at_ms: observed_at_ms,
            expires_at_ms: None,
            rebuild_reason,
        }) {
            Ok(view) => view,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: source_gaps(&resolved.resolutions),
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        }
    };

    let is_nonusable = matches!(
        view.completeness,
        Completeness::Stale | Completeness::Blocked
    );
    if is_nonusable {
        let publication = match make_view_publication(&binding, view) {
            Ok(publication) => publication,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    CampaignPacketResponse {
                        outcome: CampaignPacketOutcome::Blocked,
                        completeness: Completeness::Blocked,
                        view: None,
                        compiled_context: None,
                        gaps: vec![CampaignPacketGap {
                            code: CampaignPacketGapCode::RequiredSourceUnavailable,
                            role: None,
                        }],
                        missing_roles: missing_roles(&resolved.resolutions),
                        stale_roles: stale_roles(&resolved.resolutions),
                        blocked_roles: blocked_roles(&resolved.resolutions),
                        prior_view_reused: false,
                        prior_view_rejected_stale: prior.is_some(),
                    },
                );
            }
        };
        let completeness = publication.view.completeness;
        return campaign_packet_result_body(
            envelope,
            attempt,
            CampaignPacketResponse {
                outcome: if completeness == Completeness::Stale {
                    CampaignPacketOutcome::Stale
                } else {
                    CampaignPacketOutcome::Blocked
                },
                completeness,
                view: Some(publication),
                compiled_context: None,
                gaps: source_gaps(&resolved.resolutions),
                missing_roles: missing_roles(&resolved.resolutions),
                stale_roles: stale_roles(&resolved.resolutions),
                blocked_roles: blocked_roles(&resolved.resolutions),
                prior_view_reused: false,
                prior_view_rejected_stale: prior.is_some() && !prior_is_current,
            },
        );
    }

    // A stale prior view is never reused. The new immutable projection is
    // validated against a fresh owner-read set before it can influence the
    // decision-local context compiler.
    let publication = make_view_publication(&binding, view.clone())
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let context_recipe_record = match current_record(&resolved, CampaignSourceRole::ContextRecipe) {
        Ok(record) => record,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextRecipeUnavailable,
                    Some(CampaignSourceRole::ContextRecipe),
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    let context_delivery_record =
        match current_record(&resolved, CampaignSourceRole::ContextDelivery) {
            Ok(record) => record,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    context_blocked_response(
                        publication,
                        CampaignPacketGapCode::ContextDeliveryUnavailable,
                        Some(CampaignSourceRole::ContextDelivery),
                        &resolved.resolutions,
                        prior.is_some() && !prior_is_current,
                    ),
                );
            }
        };
    let context_recipe_body: ContextCampaignRecipeBody =
        match serde_json::from_value(context_recipe_record.document.body.clone()) {
            Ok(body) => body,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    context_blocked_response(
                        publication,
                        CampaignPacketGapCode::ContextRecipeUnavailable,
                        Some(CampaignSourceRole::ContextRecipe),
                        &resolved.resolutions,
                        prior.is_some() && !prior_is_current,
                    ),
                );
            }
        };
    let prior_delivery: SessionDeliverySnapshot =
        match serde_json::from_value(context_delivery_record.document.body.clone()) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return campaign_packet_result_body(
                    envelope,
                    attempt,
                    context_blocked_response(
                        publication,
                        CampaignPacketGapCode::ContextDeliveryUnavailable,
                        Some(CampaignSourceRole::ContextDelivery),
                        &resolved.resolutions,
                        prior.is_some() && !prior_is_current,
                    ),
                );
            }
        };
    let context_source_schema_invalid = context_recipe_record.document.schema
        != eliot_store_api::CampaignSourceDocumentSchema::ContextRecipe
        || context_delivery_record.document.schema
            != eliot_store_api::CampaignSourceDocumentSchema::ContextDelivery;
    let context_body_digests_match = context_recipe_body_digest(&context_recipe_body)
        .ok()
        .zip(canonical_body_digest(&context_recipe_record.document.body).ok())
        .is_some_and(|(typed, stored)| typed == stored)
        && context_delivery_body_digest(&prior_delivery)
            .ok()
            .zip(canonical_body_digest(&context_delivery_record.document.body).ok())
            .is_some_and(|(typed, stored)| typed == stored);
    if context_source_schema_invalid || !context_body_digests_match {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::ContextRecipeUnavailable,
                Some(CampaignSourceRole::ContextRecipe),
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }

    // Re-run the Context owner's publication validators at the consumption
    // edge. The packet then consumes the exact compiled result through the
    // downstream delivery adapter; neither step can substitute a transcript or
    // a detached Context row.
    if crate::campaign_context_owner::validate_context_owner_bodies(
        &context_recipe_body,
        prior.as_ref().map(|_| &prior_delivery),
        &binding.state_fence,
    )
    .is_err()
    {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::ContextRecipeUnavailable,
                Some(CampaignSourceRole::ContextRecipe),
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    let compiled = match eliot_context::ContextCompiler::compile_with_campaign_learning_state(
        eliot_context::CampaignLearningStateCompileInput {
            recipe_body: &context_recipe_body,
            prior_delivery: &prior_delivery,
            learning_view: &view,
            learning_recipe: &recipe,
            current_state_fence: &binding.state_fence,
            current_source_resolutions: &resolved.resolutions,
            current_history_plans: &current_history_plans,
            observed_at_ms,
        },
    ) {
        Ok(compiled) => compiled,
        Err(_) => {
            return campaign_packet_result_body(
                envelope,
                attempt,
                context_blocked_response(
                    publication,
                    CampaignPacketGapCode::ContextCompilationRejected,
                    None,
                    &resolved.resolutions,
                    prior.is_some() && !prior_is_current,
                ),
            );
        }
    };
    if crate::campaign_context_owner::consume_compiled_context(
        &compiled,
        &publication.view.view_id,
        &publication.view.canonical_digest,
    )
    .is_err()
    {
        return campaign_packet_result_body(
            envelope,
            attempt,
            context_blocked_response(
                publication,
                CampaignPacketGapCode::ContextCompilationRejected,
                None,
                &resolved.resolutions,
                prior.is_some() && !prior_is_current,
            ),
        );
    }
    campaign_packet_result_body(
        envelope,
        attempt,
        CampaignPacketResponse {
            outcome: CampaignPacketOutcome::Compiled,
            completeness: publication.view.completeness,
            view: Some(publication),
            compiled_context: Some(compiled),
            gaps: source_gaps(&resolved.resolutions),
            missing_roles: missing_roles(&resolved.resolutions),
            stale_roles: stale_roles(&resolved.resolutions),
            blocked_roles: blocked_roles(&resolved.resolutions),
            prior_view_reused: prior_is_current,
            prior_view_rejected_stale: prior.is_some() && !prior_is_current,
        },
    )
}

async fn resolve_manifest_sources(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    recipe: &LearningStateViewRecipe,
    task_plan_resolution: CampaignSourceResolution,
    task_plan_record: CampaignSourceRecord,
) -> Result<ResolvedCampaignSources, String> {
    let mut resolutions = Vec::with_capacity(recipe.source_requirements.len());
    let mut current_records = Vec::new();
    for requirement in &recipe.source_requirements {
        match requirement.source_binding {
            CampaignSourceBinding::AuthenticatedTaskAnchor => {
                if requirement.role != CampaignSourceRole::TaskPlan
                    || requirement.expected_reference.is_some()
                {
                    return Err(CampaignPacketError::InvalidTaskPlan.to_string());
                }
                resolutions.push(task_plan_resolution.clone());
                current_records.push(task_plan_record.clone());
            }
            CampaignSourceBinding::ExplicitlyAbsent => {
                if requirement.expected_reference.is_some() {
                    return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
                }
                resolutions.push(CampaignSourceResolution {
                    role: requirement.role,
                    status: CampaignSourceResolutionStatus::Missing,
                    reference: None,
                    read_state_fence: binding.state_fence.clone(),
                });
            }
            CampaignSourceBinding::ExactReference => {
                let (resolution, source) =
                    match resolve_exact_source_requirement(kernel, binding, requirement).await {
                        Ok(result) => result,
                        Err(_) => (
                            CampaignSourceResolution {
                                role: requirement.role,
                                status: CampaignSourceResolutionStatus::Blocked,
                                reference: None,
                                read_state_fence: binding.state_fence.clone(),
                            },
                            None,
                        ),
                    };
                resolutions.push(resolution);
                if let Some(source) = source {
                    current_records.push(source);
                }
            }
        }
    }
    current_records.sort_by_key(|record| record.role);
    Ok(ResolvedCampaignSources {
        resolutions,
        current_records,
    })
}

async fn resolve_exact_source_requirement(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    requirement: &CampaignSourceRequirement,
) -> Result<(CampaignSourceResolution, Option<CampaignSourceRecord>), String> {
    let expected = requirement
        .expected_reference
        .as_ref()
        .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    if expected.role != requirement.role || expected.owner != requirement.owner {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let lookup = CampaignSourceRevisionLookup {
        role: requirement.role,
        owner_id: requirement.owner.clone(),
        record_id: expected.record_id.clone(),
        expected_revision: Some(expected.revision.clone()),
        expected_content_digest: Some(expected.content_digest.clone()),
    };
    let read = read_campaign_source(kernel, binding, lookup).await?;
    let mut current_source = None;
    let reference = match read.status {
        CampaignSourceReadStatus::Current => {
            let source = read
                .source
                .as_ref()
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            let reference = source_reference_from_record(source);
            if &reference != expected {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            current_source = Some(source.clone());
            Some(reference)
        }
        CampaignSourceReadStatus::Stale => {
            read.current_head.as_ref().map(source_reference_from_head)
        }
        CampaignSourceReadStatus::Blocked | CampaignSourceReadStatus::Missing => None,
    };
    let status = match read.status {
        CampaignSourceReadStatus::Current => CampaignSourceResolutionStatus::Current,
        CampaignSourceReadStatus::Stale => CampaignSourceResolutionStatus::Stale,
        CampaignSourceReadStatus::Blocked => CampaignSourceResolutionStatus::Blocked,
        CampaignSourceReadStatus::Missing => CampaignSourceResolutionStatus::Missing,
    };
    Ok((
        CampaignSourceResolution {
            role: requirement.role,
            status,
            reference,
            read_state_fence: read.read_state_fence,
        },
        current_source,
    ))
}

fn current_record(
    resolved: &ResolvedCampaignSources,
    role: CampaignSourceRole,
) -> Result<&CampaignSourceRecord, String> {
    let matching = resolved
        .current_records
        .iter()
        .filter(|record| record.role == role)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let record = matching[0];
    let resolutions = resolved
        .resolutions
        .iter()
        .filter(|resolution| resolution.role == role)
        .collect::<Vec<_>>();
    let expected_reference = source_reference_from_record(record);
    if resolutions.len() != 1
        || resolutions[0].status != CampaignSourceResolutionStatus::Current
        || resolutions[0].reference.as_ref() != Some(&expected_reference)
    {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    Ok(record)
}

fn source_resolutions_differ(
    previous: &[CampaignSourceResolution],
    current: &[CampaignSourceResolution],
) -> bool {
    let mut previous = previous.to_vec();
    let mut current = current.to_vec();
    previous.sort_by_key(|resolution| resolution.role);
    current.sort_by_key(|resolution| resolution.role);
    previous != current
}

fn policy_source_revision_changed(
    previous: &[CampaignSourceResolution],
    current: &[CampaignSourceResolution],
) -> bool {
    let policy_roles = [
        CampaignSourceRole::GovernorPolicy,
        CampaignSourceRole::ContextToolPolicy,
        CampaignSourceRole::ActiveOverlay,
    ];
    policy_roles.iter().any(|role| {
        let before = previous.iter().find(|resolution| resolution.role == *role);
        let after = current.iter().find(|resolution| resolution.role == *role);
        before != after
    })
}

fn collect_slot_projections(
    recipe: &LearningStateViewRecipe,
    resolved: &ResolvedCampaignSources,
) -> Result<Vec<eliot_learning_contracts::SlotProjection>, String> {
    let mut projections = BTreeMap::new();
    for source in &resolved.current_records {
        let source_ref = source_reference_from_record(source);
        if !resolved.resolutions.iter().any(|resolution| {
            resolution.role == source.role
                && resolution.status == CampaignSourceResolutionStatus::Current
                && resolution.reference.as_ref() == Some(&source_ref)
        }) {
            return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
        }
        for projection in &source.slot_projections {
            let spec = recipe
                .slots
                .iter()
                .find(|slot| slot.slot_id == projection.slot_id)
                .ok_or_else(|| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            if spec.source_role != source.role || spec.owner != source.owner_id {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
            let observed = projection
                .canonical_digest()
                .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            if !source
                .slot_projection_digests
                .iter()
                .any(|digest| digest.slot_id == projection.slot_id && digest.digest == observed)
                || projections
                    .insert(projection.slot_id.as_str().to_owned(), projection.clone())
                    .is_some()
            {
                return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
            }
        }
    }
    Ok(recipe
        .slots
        .iter()
        .filter_map(|slot| projections.remove(slot.slot_id.as_str()))
        .collect())
}

fn collect_required_references(
    current_records: &[CampaignSourceRecord],
    material_refs: &[String],
) -> Result<Vec<ArtifactId>, String> {
    let mut all_owner_handles = BTreeSet::new();
    let mut required = BTreeSet::new();
    for source in current_records {
        required.extend(source.required_references.iter().cloned());
        all_owner_handles.extend(source.required_references.iter().cloned());
        for projection in &source.slot_projections {
            all_owner_handles.extend(projection.evidence.iter().cloned());
            for member in &projection.members {
                all_owner_handles.extend(member.evidence.iter().cloned());
            }
        }
        for history in &source.history_plans {
            all_owner_handles.extend(history.selected_handles.iter().cloned());
            all_owner_handles.extend(history.policy_slice_handles.iter().cloned());
        }
    }
    for selector in material_refs {
        let handle = ArtifactId::new(selector.clone())
            .map_err(|_| CampaignPacketError::InvalidSelectors.to_string())?;
        if !all_owner_handles.contains(&handle) {
            return Err(CampaignPacketError::InvalidSelectors.to_string());
        }
        required.insert(handle);
    }
    Ok(required.into_iter().collect())
}

fn collect_disagreements(current_records: &[CampaignSourceRecord]) -> Vec<OwnerDisagreement> {
    current_records
        .iter()
        .flat_map(|source| source.disagreements.iter().cloned())
        .collect()
}

fn collect_positions(resolved: &ResolvedCampaignSources) -> Vec<CampaignPositionRef> {
    let mut positions = Vec::new();
    for (role, kind) in [
        (
            CampaignSourceRole::CurrentPosition,
            CampaignPositionKind::Current,
        ),
        (
            CampaignSourceRole::ExperiencePosition,
            CampaignPositionKind::Experience,
        ),
        (
            CampaignSourceRole::AdaptationPosition,
            CampaignPositionKind::Adaptation,
        ),
        (
            CampaignSourceRole::EvaluationPosition,
            CampaignPositionKind::Evaluation,
        ),
        (
            CampaignSourceRole::EconomicsProgress,
            CampaignPositionKind::EconomicsProgress,
        ),
    ] {
        if let Some(source) = resolved
            .current_records
            .iter()
            .find(|source| source.role == role)
        {
            positions.push(CampaignPositionRef {
                kind,
                source_role: role,
                record_id: source.record_id.clone(),
                revision: source.revision.clone(),
                source_content_digest: source.content_digest.clone(),
                position_digest: source.content_digest.clone(),
            });
        }
    }
    positions
}

fn build_history_plan_set(
    recipe: &LearningStateViewRecipe,
    current_records: &[CampaignSourceRecord],
) -> Result<ValidatedHistoryPlans, String> {
    let mut records = Vec::new();
    for source in current_records {
        for record in &source.history_plans {
            record
                .validate_for_source(recipe.campaign_id.as_str(), &source.owner_id)
                .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
            records.push(record.clone());
        }
    }
    if records.is_empty() {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    let mut plans = Vec::with_capacity(records.len());
    for record in &records {
        let plan: RetrievalPlan = serde_json::from_value(record.plan.clone())
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        plan.validate()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        let digest = plan
            .canonical_digest()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
        if digest != record.plan_digest {
            return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
        }
        plans.push(plan);
    }
    Ok(ValidatedHistoryPlans { plans, records })
}

fn canonical_body_digest(body: &Value) -> Result<String, String> {
    let bytes = canonical_json_bytes(body)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn current_unix_ms() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let millis = i64::try_from(duration.as_millis())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    if millis <= 0 {
        return Err(CampaignPacketError::InvalidInvocation.to_string());
    }
    Ok(millis)
}

fn source_reference_from_record(source: &CampaignSourceRecord) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: source.role,
        owner: source.owner_id.clone(),
        record_id: source.record_id.clone(),
        revision: source.revision.clone(),
        content_digest: source.content_digest.clone(),
        slot_projection_digests: source.slot_projection_digests.clone(),
        recorded_state_fence: source.recorded_state_fence.clone(),
    }
}

fn source_reference_from_head(head: &CampaignSourceHead) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: head.role,
        owner: head.owner_id.clone(),
        record_id: head.record_id.clone(),
        revision: head.revision.clone(),
        content_digest: head.content_digest.clone(),
        slot_projection_digests: head.slot_projection_digests.clone(),
        recorded_state_fence: head.recorded_state_fence.clone(),
    }
}

async fn read_task_plan_recipe(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
) -> Result<
    (
        LearningStateViewRecipe,
        CampaignSourceResolution,
        CampaignSourceRecord,
    ),
    String,
> {
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let owner_artifact = ArtifactId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID.to_owned())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let owner_id = OwnerId::from_artifact(owner_artifact);
    let lookup = CampaignSourceRevisionLookup {
        role: CampaignSourceRole::TaskPlan,
        owner_id: owner_id.clone(),
        record_id: CampaignOwnerRecordId::Task(task_id.clone()),
        expected_revision: None,
        expected_content_digest: None,
    };
    let read = read_campaign_source(kernel, binding, lookup).await?;
    if read.status != CampaignSourceReadStatus::Current {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let source = read
        .source
        .ok_or_else(|| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let required_revision = binding
        .state_fence
        .task_revision
        .ok_or_else(|| CampaignPacketError::MissingTaskRevision.to_string())?;
    if source.role != CampaignSourceRole::TaskPlan
        || source.owner_id != owner_id
        || source.record_id != CampaignOwnerRecordId::Task(task_id.clone())
        || source.revision != CampaignOwnerRevision::Task(required_revision)
        || source.recorded_state_fence.task_revision != Some(required_revision)
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let recipe: LearningStateViewRecipe = serde_json::from_value(source.document.body.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    recipe
        .validate()
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    if source.document.schema
        != eliot_store_api::CampaignSourceDocumentSchema::LearningStateViewRecipe
        || recipe.binding.task_id.as_str() != binding.task_id
        || recipe.binding.scope.as_str() != binding.work_scope_id
        || recipe.binding.state_fence != binding.state_fence
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let task_plan_requirement = recipe
        .source_requirements
        .iter()
        .find(|requirement| requirement.role == CampaignSourceRole::TaskPlan)
        .ok_or_else(|| CampaignPacketError::InvalidTaskPlan.to_string())?;
    if task_plan_requirement.source_binding != CampaignSourceBinding::AuthenticatedTaskAnchor
        || task_plan_requirement.expected_reference.is_some()
        || task_plan_requirement.owner != owner_id
    {
        return Err(CampaignPacketError::InvalidTaskPlan.to_string());
    }
    let reference = source_reference_from_record(&source);
    reference
        .validate()
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let resolution = CampaignSourceResolution {
        role: CampaignSourceRole::TaskPlan,
        status: CampaignSourceResolutionStatus::Current,
        reference: Some(reference),
        read_state_fence: read.read_state_fence,
    };
    Ok((recipe, resolution, source))
}

fn campaign_read_request(
    binding: &CampaignPacketBinding,
    operation: NamedReadOperation,
    parameters: std::collections::BTreeMap<String, Value>,
) -> Result<NamedReadRequest, String> {
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let request = NamedReadRequest {
        operation,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence: binding.state_fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(request)
}

async fn read_campaign_source(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    lookup: CampaignSourceRevisionLookup,
) -> Result<CampaignSourceRevisionRead, String> {
    let request = campaign_read_request(
        binding,
        NamedReadOperation::GetCampaignSourceRevision,
        lookup
            .named_parameters()
            .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?,
    )?;
    let response =
        crate::kernel_context_read_client::KernelContextReadClient::execute_campaign_read(
            kernel, request,
        )
        .await
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let read = CampaignSourceRevisionRead::from_named_read_response(&response)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    if read.read_state_fence != binding.state_fence
        || read.current_head.as_ref().is_some_and(|head| {
            head.role != lookup.role
                || head.owner_id != lookup.owner_id
                || head.record_id != lookup.record_id
        })
        || read.source.as_ref().is_some_and(|source| {
            source.role != lookup.role
                || source.owner_id != lookup.owner_id
                || source.record_id != lookup.record_id
        })
    {
        return Err(CampaignPacketError::OwnerReadUnavailable.to_string());
    }
    Ok(read)
}

async fn read_prior_campaign_view(
    kernel: &DaemonKernelClient,
    binding: &CampaignPacketBinding,
    view_id: &str,
) -> Result<CampaignLearningStateViewPublication, String> {
    let view_id = ArtifactId::new(view_id.to_owned())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let lookup = CampaignLearningStateViewLookup {
        view_id: view_id.clone(),
        task_id,
        scope_id,
    };
    let request = campaign_read_request(
        binding,
        NamedReadOperation::GetCampaignLearningStateView,
        lookup
            .named_parameters()
            .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?,
    )?;
    let response =
        crate::kernel_context_read_client::KernelContextReadClient::execute_campaign_read(
            kernel, request,
        )
        .await
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    let read = CampaignLearningStateViewRead::from_named_read_response(&response)
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    if read.read_state_fence != binding.state_fence
        || read.status != CampaignLearningStateViewReadStatus::Current
    {
        return Err(CampaignPacketError::PriorViewUnavailable.to_string());
    }
    let publication = read
        .publication
        .ok_or_else(|| CampaignPacketError::PriorViewUnavailable.to_string())?;
    if publication.view_id != view_id
        || publication.task_id.as_str() != binding.task_id
        || publication.scope_id.as_str() != binding.work_scope_id
        || publication.view.view_id != publication.view_id
        || publication.view.binding.task_id.as_str() != binding.task_id
        || publication.view.binding.scope.as_str() != binding.work_scope_id
    {
        return Err(CampaignPacketError::PriorViewUnavailable.to_string());
    }
    publication
        .validate()
        .map_err(|_| CampaignPacketError::PriorViewUnavailable.to_string())?;
    Ok(publication)
}

fn make_view_publication(
    binding: &CampaignPacketBinding,
    view: CampaignLearningStateView,
) -> Result<CampaignLearningStateViewPublication, String> {
    let task_id = TaskId::new(binding.task_id.clone())
        .map_err(|_| CampaignPacketError::InvalidTaskPlan.to_string())?;
    let scope_id = ScopeId::new(binding.work_scope_id.clone())
        .map_err(|_| CampaignPacketError::InvalidInvocation.to_string())?;
    let view_bytes = canonical_json_bytes(&view)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let publication = CampaignLearningStateViewPublication {
        view_id: view.view_id.clone(),
        task_id,
        scope_id,
        state_fence: binding.state_fence.clone(),
        content_digest: sha256_hex(&view_bytes),
        view,
    };
    publication
        .validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(publication)
}

fn context_blocked_response(
    view: CampaignLearningStateViewPublication,
    code: CampaignPacketGapCode,
    role: Option<CampaignSourceRole>,
    resolutions: &[CampaignSourceResolution],
    prior_view_rejected_stale: bool,
) -> CampaignPacketResponse {
    let mut gaps = source_gaps(resolutions);
    gaps.push(CampaignPacketGap { code, role });
    CampaignPacketResponse {
        outcome: CampaignPacketOutcome::Blocked,
        completeness: Completeness::Blocked,
        view: Some(view),
        compiled_context: None,
        gaps,
        missing_roles: missing_roles(resolutions),
        stale_roles: stale_roles(resolutions),
        blocked_roles: blocked_roles(resolutions),
        prior_view_reused: false,
        prior_view_rejected_stale,
    }
}

fn campaign_packet_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    result: CampaignPacketResponse,
) -> Result<HostRequestResultBody, String> {
    let response = serde_json::to_value(result)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let response_bytes = canonical_json_bytes(&response)
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&response_bytes),
        response,
        attempt: Some(attempt.clone()),
    };
    body.validate()
        .map_err(|_| CampaignPacketError::OwnerReadUnavailable.to_string())?;
    Ok(body)
}

fn source_gaps(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignPacketGap> {
    resolutions
        .iter()
        .filter_map(|resolution| {
            let unavailable = matches!(
                resolution.status,
                CampaignSourceResolutionStatus::Missing
                    | CampaignSourceResolutionStatus::Stale
                    | CampaignSourceResolutionStatus::Blocked
            );
            unavailable.then_some(CampaignPacketGap {
                code: CampaignPacketGapCode::RequiredSourceUnavailable,
                role: Some(resolution.role),
            })
        })
        .collect()
}

fn missing_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Missing)
}

fn stale_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Stale)
}

fn blocked_roles(resolutions: &[CampaignSourceResolution]) -> Vec<CampaignSourceRole> {
    roles_with_status(resolutions, CampaignSourceResolutionStatus::Blocked)
}

fn roles_with_status(
    resolutions: &[CampaignSourceResolution],
    status: CampaignSourceResolutionStatus,
) -> Vec<CampaignSourceRole> {
    resolutions
        .iter()
        .filter(|resolution| resolution.status == status)
        .map(|resolution| resolution.role)
        .collect()
}
