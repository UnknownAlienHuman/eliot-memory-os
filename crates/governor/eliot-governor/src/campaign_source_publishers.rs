//! Role-specific campaign source publication builders.
//!
//! A campaign view may consume only owner-issued immutable rows. This module
//! is the narrow Governor-side construction boundary for those rows: it binds
//! the owner, native record identity/revision, State Fence, slot projections,
//! and already-produced bounded history references into one typed publication.
//! It does not read a store, resolve a missing owner, or create a replacement
//! projection from a transcript/current file.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSlotProjectionDigest,
    CampaignSourceBinding, CampaignSourceRevisionRef, CampaignSourceRole, LearningStateViewRecipe,
    OwnerDisagreement, OwnerId, SlotProjection,
};
use eliot_reactive_context_plan::{
    CampaignBudgets, CampaignIntent, CampaignOutputMode, PlanParts, RetrievalRouteKind,
    RouteExecution, RouteExecutionOrder, SourceProjectionFence, compile_retrieval_plan,
};
use eliot_store_api::{
    CampaignHistoryPlanRecord, CampaignHistoryReadResult, CampaignSourceDocument,
    CampaignSourceDocumentSchema, CampaignSourceHead, CampaignSourcePublication,
    CampaignSourcePublisher, CampaignSourceRecord, campaign_source_owner_id,
    campaign_source_schema_for_role,
};
use thiserror::Error;

/// Failure while constructing or admitting a role-specific source row.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CampaignSourcePublisherError {
    /// The owner supplied an invalid or unbound source value.
    #[error("campaign owner source is invalid: {0}")]
    Invalid(String),
    /// The complete bundle does not cover the recipe's closed denominator.
    #[error("campaign source bundle is incomplete: {0}")]
    Incomplete(String),
}

/// One closed production registration for a campaign source role.
///
/// The registry is descriptive only: it does not create data or authority.
/// It is the exact role/publisher/owner/schema denominator used by the owner
/// matrix assembler and by Kernel admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignOwnerSourceRegistration {
    /// Source role being registered.
    pub role: CampaignSourceRole,
    /// Role-specific publisher variant.
    pub publisher: CampaignSourcePublisher,
    /// Canonical owner identity (the Context delivery owner is a validated
    /// dynamic owner, so its registration carries the stable prefix).
    pub owner_id: OwnerId,
    /// Closed native document schema.
    pub schema: CampaignSourceDocumentSchema,
}

/// Return the complete 26-role production owner registry.
#[must_use]
pub fn campaign_owner_source_registry() -> Vec<CampaignOwnerSourceRegistration> {
    CampaignSourceRole::all()
        .into_iter()
        .filter_map(|role| {
            let publisher = CampaignSourcePublisher::for_role(role)?;
            let owner = OwnerId::from_artifact(
                ArtifactId::new(campaign_source_owner_id(role).to_owned()).ok()?,
            );
            Some(CampaignOwnerSourceRegistration {
                role,
                publisher,
                owner_id: owner,
                schema: campaign_source_schema_for_role(role),
            })
        })
        .collect()
}

/// Build the Task Controller's own bounded campaign-history read result.
///
/// This is deliberately owner-specific and crate-private. The Task Controller
/// has the authenticated task-record projection and its exact source handle;
/// it constructs the typed owner read result and then uses the store's
/// `from_owner_read` boundary. No caller-provided handle list, transcript, or
/// current-file substitution can enter campaign history through this helper.
pub(crate) fn build_task_controller_history_record(
    campaign_id: &str,
    owner_id: &str,
    source_snapshot: ArtifactId,
    state_fence: &StateFence,
) -> Result<CampaignHistoryPlanRecord, CampaignSourcePublisherError> {
    if campaign_id.trim().is_empty() || owner_id.trim().is_empty() {
        return Err(CampaignSourcePublisherError::Invalid(
            "campaign history requires owner and campaign identities".to_owned(),
        ));
    }
    state_fence
        .validate()
        .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
    let source = SourceId::new(owner_id.to_owned())
        .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
    let plan = compile_retrieval_plan(PlanParts {
        required_exact_routes: vec![source_snapshot.clone()],
        optional_routes: vec![RetrievalRouteKind::Episode],
        execution: RouteExecution {
            order: RouteExecutionOrder::Sequential,
            reason: "Task Controller owner-issued bounded history read".to_owned(),
        },
        source_projection_fences: vec![SourceProjectionFence {
            source: source.clone(),
            fence: state_fence.clone(),
            expected_revision: None,
        }],
        campaign_experience_query: Some(eliot_reactive_context_plan::CampaignQueryParts {
            scope: campaign_id.to_owned(),
            intent: CampaignIntent::InspectParentLineage,
            handles: vec![source_snapshot.clone()],
            filters: "Task Controller owner-issued exact source handle".to_owned(),
            predicates: "owner-produced read result; no inferred or substituted material"
                .to_owned(),
            temporal_and_lineage_range: "Task Controller owner-retained bounded history".to_owned(),
            output_mode: CampaignOutputMode::SummaryWithHandles,
            budgets: CampaignBudgets {
                max_tokens: 4_096,
                max_bytes: 65_536,
                max_time_ms: 1_000,
            },
            fence: state_fence.clone(),
        }),
        coverage_and_negative_claims: "owner-issued handle and bounded result digest only"
            .to_owned(),
        budget_and_stop_conditions: "stop at the Task Controller owner read result".to_owned(),
        fallback_or_abstention: "abstain when the owner cannot return its source handle".to_owned(),
    })
    .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
    let read_result = CampaignHistoryReadResult::new(
        OwnerId::from_artifact(
            ArtifactId::new(owner_id.to_owned())
                .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?,
        ),
        source,
        campaign_id.to_owned(),
        state_fence.clone(),
        plan,
        vec![source_snapshot.clone()],
        None,
        Vec::new(),
        vec![source_snapshot],
    )
    .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
    CampaignHistoryPlanRecord::from_owner_read(&read_result)
        .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))
}

/// Inputs for one authenticated owner-issued campaign source row.
///
/// There is intentionally no public generic projection constructor. A caller
/// must present an owner-validated native document and the exact read fence;
/// this type computes the content and read digests instead of trusting a
/// caller-supplied projection envelope.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignOwnerSourceInput {
    /// Closed owner-specific publisher selected by the owning transition.
    pub publisher: CampaignSourcePublisher,
    /// Exact source role.
    pub role: CampaignSourceRole,
    /// Exact owner identity.
    pub owner_id: OwnerId,
    /// Exact owner-native record identity.
    pub record_id: CampaignOwnerRecordId,
    /// Exact owner-native revision.
    pub revision: CampaignOwnerRevision,
    /// Fence captured by the owner row.
    pub state_fence: StateFence,
    /// Exact owner document after its native validator ran.
    pub document: CampaignSourceDocument,
    /// Slot projections emitted by the owner.
    pub slot_projections: Vec<SlotProjection>,
    /// Required handles emitted by the owner.
    pub required_references: Vec<ArtifactId>,
    /// Owner disagreements retained verbatim.
    pub disagreements: Vec<OwnerDisagreement>,
    /// Existing owner-produced history records, never synthesized here.
    pub history_plans: Vec<CampaignHistoryPlanRecord>,
    /// Exact current head observed immediately before CAS, if any.
    pub expected_head: Option<CampaignSourceHead>,
    /// Authenticated read fence used to obtain this row.
    pub read_state_fence: StateFence,
}

impl CampaignOwnerSourceInput {
    /// Construct one role-specific input from an owner-validated document and
    /// the authenticated read that returned it.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_read(
        publisher: CampaignSourcePublisher,
        role: CampaignSourceRole,
        owner_id: OwnerId,
        record_id: CampaignOwnerRecordId,
        revision: CampaignOwnerRevision,
        state_fence: StateFence,
        read_state_fence: StateFence,
        document: CampaignSourceDocument,
        slot_projections: Vec<SlotProjection>,
        required_references: Vec<ArtifactId>,
        disagreements: Vec<OwnerDisagreement>,
        history_plans: Vec<CampaignHistoryPlanRecord>,
    ) -> Result<Self, CampaignSourcePublisherError> {
        if publisher.role() != role {
            return Err(CampaignSourcePublisherError::Invalid(
                "publisher variant does not match the source role".to_owned(),
            ));
        }
        if document.schema != campaign_source_schema_for_role(role) {
            return Err(CampaignSourcePublisherError::Invalid(
                "owner document schema does not match its source role".to_owned(),
            ));
        }
        document
            .validate_for_role(role)
            .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        state_fence
            .validate()
            .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        read_state_fence
            .validate()
            .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        for plan in &history_plans {
            plan.validate_for_owner(&owner_id)
                .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        }
        Ok(Self {
            publisher,
            role,
            owner_id,
            record_id,
            revision,
            state_fence,
            document,
            slot_projections,
            required_references,
            disagreements,
            history_plans,
            expected_head: None,
            read_state_fence,
        })
    }

    /// Construct a typed input from an owner-validated document and its
    /// authenticated read fence.  This is the only generic boundary; callers
    /// cannot provide a self-declared digest or projection envelope.
    pub fn from_document(
        publisher: CampaignSourcePublisher,
        role: CampaignSourceRole,
        owner_id: OwnerId,
        record_id: CampaignOwnerRecordId,
        revision: CampaignOwnerRevision,
        state_fence: StateFence,
        read_state_fence: StateFence,
        document: CampaignSourceDocument,
        slot_projections: Vec<SlotProjection>,
        required_references: Vec<ArtifactId>,
        disagreements: Vec<OwnerDisagreement>,
        history_plans: Vec<CampaignHistoryPlanRecord>,
    ) -> Result<Self, CampaignSourcePublisherError> {
        Self::from_authenticated_read(
            publisher,
            role,
            owner_id,
            record_id,
            revision,
            state_fence,
            read_state_fence,
            document,
            slot_projections,
            required_references,
            disagreements,
            history_plans,
        )
    }

    /// Attach the exact head observed by the owner immediately before CAS.
    #[must_use]
    pub fn with_expected_head(mut self, expected_head: CampaignSourceHead) -> Self {
        self.expected_head = Some(expected_head);
        self
    }

    /// Construct and validate one immutable owner publication.
    pub fn into_publication(
        self,
    ) -> Result<CampaignSourcePublication, CampaignSourcePublisherError> {
        let registration = campaign_owner_source_registry()
            .into_iter()
            .find(|registration| registration.role == self.role)
            .ok_or_else(|| {
                CampaignSourcePublisherError::Invalid(
                    "owner role is absent from the production registry".to_owned(),
                )
            })?;
        let owner_matches = if self.role == CampaignSourceRole::ContextDelivery {
            self.owner_id.as_str().starts_with("owner:eliot-context/")
        } else {
            self.owner_id == registration.owner_id
        };
        if self.publisher != registration.publisher
            || !owner_matches
            || self.document.schema != registration.schema
        {
            return Err(CampaignSourcePublisherError::Invalid(
                "owner input does not match its production registry entry".to_owned(),
            ));
        }
        let mut slot_digests = Vec::with_capacity(self.slot_projections.len());
        for projection in &self.slot_projections {
            slot_digests.push(CampaignSlotProjectionDigest {
                slot_id: projection.slot_id.clone(),
                digest: projection
                    .canonical_digest()
                    .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?,
            });
        }
        let record = CampaignSourceRecord::new(
            self.role,
            self.owner_id,
            self.record_id,
            self.revision,
            self.state_fence,
            slot_digests,
            self.slot_projections,
            self.required_references,
            self.disagreements,
            self.history_plans,
            self.document,
        )
        .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        let publication = CampaignSourcePublication::from_observed_head(
            self.publisher,
            record,
            self.expected_head,
            &self.read_state_fence,
        )
        .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        Ok(publication)
    }
}

/// A complete set of owner publications for one recipe/fence.
#[derive(Clone, Debug, Default)]
pub struct CampaignSourcePublicationBundle {
    /// Role-specific immutable source rows.
    pub publications: Vec<CampaignSourcePublication>,
}

impl CampaignSourcePublicationBundle {
    /// Validate all 26 roles, exact recipe references, fences, and history.
    ///
    /// This is an admission check, not a source resolver. A missing role is
    /// reported as incomplete; the caller must obtain it from its owner or
    /// leave the view honestly blocked.
    pub fn validate_complete(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), CampaignSourcePublisherError> {
        recipe
            .validate()
            .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
        let requirements = recipe
            .source_requirements
            .iter()
            .map(|requirement| (requirement.role, requirement))
            .collect::<BTreeMap<_, _>>();
        let expected_roles = CampaignSourceRole::all();
        let required_publications = expected_roles
            .iter()
            .filter(|role| {
                requirements.get(role).is_some_and(|requirement| {
                    requirement.source_binding != CampaignSourceBinding::ExplicitlyAbsent
                })
            })
            .count();
        if self.publications.len() != required_publications {
            return Err(CampaignSourcePublisherError::Incomplete(format!(
                "expected {required_publications} owner publications, observed {}",
                self.publications.len()
            )));
        }

        let mut by_role = BTreeMap::new();
        let mut history_count = 0usize;
        for publication in &self.publications {
            publication
                .validate()
                .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
            for plan in &publication.record.history_plans {
                plan.validate_for_source(recipe.campaign_id.as_str(), &publication.record.owner_id)
                    .map_err(|error| CampaignSourcePublisherError::Invalid(error.to_string()))?;
            }
            let role = publication.record.role;
            let requirement = requirements.get(&role).ok_or_else(|| {
                CampaignSourcePublisherError::Invalid(format!(
                    "publication contains undeclared source role {role:?}"
                ))
            })?;
            if publication.publisher.role() != role {
                return Err(CampaignSourcePublisherError::Invalid(format!(
                    "publisher and source role disagree for {role:?}"
                )));
            }
            if requirement.source_binding == CampaignSourceBinding::ExplicitlyAbsent {
                return Err(CampaignSourcePublisherError::Invalid(format!(
                    "explicitly absent role {role:?} must not have a publication"
                )));
            }
            if by_role.insert(role, publication).is_some() {
                return Err(CampaignSourcePublisherError::Incomplete(format!(
                    "duplicate source role {role:?}"
                )));
            }
            // The row's recorded fence is historical owner lineage.  It is
            // intentionally not compared with the packet's current read
            // fence; only the authenticated read receipt/current resolution
            // can establish currentness.  Task-anchor rows are the one
            // exception: they are minted by this same task transition and
            // must carry its exact fence.
            if matches!(
                role,
                CampaignSourceRole::TaskObjective
                    | CampaignSourceRole::TaskAcceptance
                    | CampaignSourceRole::TaskPlan
                    | CampaignSourceRole::TaskOpenItems
            ) && publication.record.recorded_state_fence != recipe.binding.state_fence
            {
                return Err(CampaignSourcePublisherError::Invalid(format!(
                    "Task Controller source {role:?} is not bound to the recipe State Fence"
                )));
            }
            let owner_matches = if role == CampaignSourceRole::ContextDelivery {
                publication
                    .record
                    .owner_id
                    .as_str()
                    .starts_with("owner:eliot-context/")
                    && publication
                        .record
                        .document
                        .body
                        .get("owner_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(publication.record.owner_id.as_str())
            } else {
                publication.record.owner_id.as_str() == campaign_source_owner_id(role)
            };
            if !owner_matches || requirement.owner != publication.record.owner_id {
                return Err(CampaignSourcePublisherError::Invalid(format!(
                    "source {role:?} has the wrong owner identity"
                )));
            }
            history_count = history_count.saturating_add(publication.record.history_plans.len());
        }

        for role in expected_roles {
            let requirement = requirements.get(&role).ok_or_else(|| {
                CampaignSourcePublisherError::Incomplete(format!(
                    "recipe omits source role {role:?}"
                ))
            })?;
            match requirement.source_binding {
                CampaignSourceBinding::ExplicitlyAbsent => {
                    if requirement.load_bearing {
                        return Err(CampaignSourcePublisherError::Invalid(format!(
                            "explicitly absent role {role:?} cannot be load-bearing"
                        )));
                    }
                    if by_role.contains_key(&role) {
                        return Err(CampaignSourcePublisherError::Invalid(format!(
                            "explicitly absent role {role:?} has a publication"
                        )));
                    }
                }
                CampaignSourceBinding::AuthenticatedTaskAnchor => {
                    let publication = by_role.get(&role).ok_or_else(|| {
                        CampaignSourcePublisherError::Incomplete(format!(
                            "publication bundle omits authenticated role {role:?}"
                        ))
                    })?;
                    if role != CampaignSourceRole::TaskPlan
                        || publication.record.role != CampaignSourceRole::TaskPlan
                        || publication.record.record_id
                            != CampaignOwnerRecordId::Task(recipe.binding.task_id.clone())
                        || publication.record.revision
                            != CampaignOwnerRevision::Task(
                                recipe.binding.state_fence.task_revision.ok_or_else(|| {
                                    CampaignSourcePublisherError::Invalid(
                                        "TaskPlan recipe has no task revision".to_owned(),
                                    )
                                })?,
                            )
                    {
                        return Err(CampaignSourcePublisherError::Invalid(
                            "authenticated task anchor is not the exact TaskPlan row".to_owned(),
                        ));
                    }
                }
                CampaignSourceBinding::ExactReference => {
                    let publication = by_role.get(&role).ok_or_else(|| {
                        CampaignSourcePublisherError::Incomplete(format!(
                            "publication bundle omits exact role {role:?}"
                        ))
                    })?;
                    let expected = requirement.expected_reference.as_ref().ok_or_else(|| {
                        CampaignSourcePublisherError::Invalid(format!(
                            "exact role {role:?} lacks an expected reference"
                        ))
                    })?;
                    if source_revision_ref(&publication.record) != *expected {
                        return Err(CampaignSourcePublisherError::Invalid(format!(
                            "source {role:?} does not bind the recipe reference"
                        )));
                    }
                }
            }
        }

        let task_plan = by_role
            .get(&CampaignSourceRole::TaskPlan)
            .and_then(|publication| {
                serde_json::from_value::<LearningStateViewRecipe>(
                    publication.record.document.body.clone(),
                )
                .ok()
            })
            .ok_or_else(|| {
                CampaignSourcePublisherError::Invalid(
                    "TaskPlan publication is not the typed recipe".to_owned(),
                )
            })?;
        if &task_plan != recipe {
            return Err(CampaignSourcePublisherError::Invalid(
                "TaskPlan publication does not equal the bound recipe".to_owned(),
            ));
        }
        if history_count == 0 {
            return Err(CampaignSourcePublisherError::Incomplete(
                "campaign history requires at least one owner-produced RetrievalPlan record"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate the complete production denominator, not merely the rows
    /// required by a recipe that may contain explicit absences. This is the
    /// gate used by the owner-transition path: every closed role must be
    /// accounted for by either an owner-issued publication or an explicit
    /// recipe absence, and at least one owner-produced history plan is required.
    pub fn validate_complete_denominator(
        &self,
        recipe: &LearningStateViewRecipe,
    ) -> Result<(), CampaignSourcePublisherError> {
        // The denominator is the closed 26-role *accounting* set. An
        // explicitly absent role is accounted for by the recipe and must not
        // be forced to acquire a fabricated publication; every other role
        // still requires one owner-issued row through `validate_complete`.
        self.validate_complete(recipe)?;
        let explicitly_absent = recipe
            .source_requirements
            .iter()
            .filter(|requirement| {
                requirement.source_binding == CampaignSourceBinding::ExplicitlyAbsent
            })
            .count();
        let expected_publications = CampaignSourceRole::all().len() - explicitly_absent;
        if self.publications.len() != expected_publications {
            return Err(CampaignSourcePublisherError::Incomplete(format!(
                "complete owner denominator requires {expected_publications} publications after explicit absences, observed {}",
                self.publications.len()
            )));
        }
        Ok(())
    }
}

/// Assemble the closed 26-role owner matrix from owner-issued inputs.
///
/// The input vector is intentionally the only source of rows. This function
/// does not create a missing owner, fill an omitted role, or accept a caller
/// selected publisher: every input has already been built by its owner and
/// is revalidated against the exact recipe/fence before the bundle is
/// returned to a canonical transition owner.
pub fn assemble_campaign_owner_matrix(
    recipe: &LearningStateViewRecipe,
    inputs: Vec<CampaignOwnerSourceInput>,
) -> Result<CampaignSourcePublicationBundle, CampaignSourcePublisherError> {
    let mut publications = Vec::with_capacity(CampaignSourceRole::all().len());
    for input in inputs {
        publications.push(input.into_publication()?);
    }
    let bundle = CampaignSourcePublicationBundle { publications };
    bundle.validate_complete_denominator(recipe)?;
    Ok(bundle)
}

/// Assemble the complete matrix when the Task Controller has already built
/// its four native rows through the real task transition.
pub fn assemble_task_owner_matrix(
    task_sources: &crate::campaign_task_sources::TaskControllerCampaignSources,
    owner_publications: Vec<CampaignSourcePublication>,
) -> Result<Vec<CampaignSourcePublication>, CampaignSourcePublisherError> {
    if owner_publications.iter().any(|publication| {
        matches!(
            publication.record.role,
            CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskPlan
                | CampaignSourceRole::TaskOpenItems
        )
    }) {
        return Err(CampaignSourcePublisherError::Invalid(
            "owner publications cannot replace any Task Controller source row".to_owned(),
        ));
    }
    let mut publications = owner_publications;
    publications.push(task_sources.objective.clone());
    publications.push(task_sources.plan.clone());
    publications.push(task_sources.acceptance.clone());
    publications.push(task_sources.open_items.clone());
    publications.sort_by_key(|publication| publication.record.role);
    let bundle = CampaignSourcePublicationBundle {
        publications: publications.clone(),
    };
    bundle.validate_complete_denominator(&task_sources.recipe)?;
    Ok(publications)
}

fn source_revision_ref(record: &CampaignSourceRecord) -> CampaignSourceRevisionRef {
    CampaignSourceRevisionRef {
        role: record.role,
        owner: record.owner_id.clone(),
        record_id: record.record_id.clone(),
        revision: record.revision.clone(),
        content_digest: record.content_digest.clone(),
        slot_projection_digests: record.slot_projection_digests.clone(),
        recorded_state_fence: record.recorded_state_fence.clone(),
    }
}

/// Validate the closed source-role matrix without constructing a record.
pub fn validate_campaign_source_role_matrix() {
    let roles = CampaignSourceRole::all();
    let owners: BTreeSet<CampaignSourceRole> = roles.into_iter().collect();
    assert_eq!(owners.len(), 26);
    let registry = campaign_owner_source_registry();
    assert_eq!(registry.len(), 26);
    for registration in registry {
        assert_eq!(registration.publisher.role(), registration.role);
        assert_eq!(
            registration.schema,
            campaign_source_schema_for_role(registration.role)
        );
        assert!(!registration.owner_id.as_str().is_empty());
    }
}
