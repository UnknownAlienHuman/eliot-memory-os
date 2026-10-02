//! I1.9 Capability Registry: the Governor-owned composite capability
//! projection.
//!
//! I1.9 splits "Module Registry" into three owners. This module owns only the
//! Capability Registry, a read-only composite projection assembled from three
//! input classes:
//!
//! * canonical manifests/evidence — the Governor
//!   [`ModuleCatalogEntry`](eliot_module_registry::ModuleCatalogEntry) and the
//!   retained [`CapabilityEvidenceRecord`] evidence;
//! * Kernel generation/health input — the
//!   [`GenerationRegistryRecord`](eliot_ors::GenerationRegistryRecord)
//!   operational state;
//! * policy/supervision input — the current Catalog/Policy view and the
//!   supervision health dimension.
//!
//! The projection records, per `(module_id, generation)`: the current usable
//! installation/route, the evidence recorded for the generation, its
//! limitations and its admission status.
//!
//! Two properties are load bearing and enforced by code rather than by a
//! comment:
//!
//! * The projection has **no lifecycle ownership**. It is assembled from its
//!   inputs and never mutates the Module Catalog or the Generation Registry;
//!   removing a projection record removes only the projection.
//! * Admission is **never inferred from route availability**. A merely running
//!   generation projects as [`CapabilityAdmission::PendingEvidence`] until the
//!   Governor records the required evidence; only recorded, non-restricting
//!   evidence under a current policy view and healthy supervision projects as
//!   [`CapabilityAdmission::Admitted`].
//!
//! This module is pure projection logic: it owns no process, store handle, or
//! canonical memory, and it issues no authority of its own.

use std::collections::BTreeMap;

use eliot_contracts::ResourceGeneration;
use eliot_module_registry::ModuleCatalogEntry;
use eliot_ors::{CatalogPolicyView, GenerationOperationalState, GenerationRegistryRecord};
use eliot_runtime_contracts::HealthDimension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability_evidence::{CapabilityEvidenceRecord, CapabilityStatus};

/// Admission status of one module generation's capability projection (I1.9).
///
/// The status is a projection of recorded evidence and policy/supervision
/// input. It is never inferred from whether the generation is running or its
/// route is available.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAdmission {
    /// The required evidence is recorded under a current policy view and
    /// healthy supervision; the generation is usable as a capability.
    Admitted,
    /// A usable installation exists but the required evidence is not recorded,
    /// the policy view is not current, or supervision is not healthy. A merely
    /// running generation projects here until the Governor records the
    /// required evidence.
    PendingEvidence,
    /// Recorded evidence restricts the generation (broken, unsupported or
    /// degraded), so it is not usable for production work.
    Restricted,
}

impl CapabilityAdmission {
    /// The I1.9 wire spelling of the status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::PendingEvidence => "pending_evidence",
            Self::Restricted => "restricted",
        }
    }

    /// Whether this status admits the generation as a usable capability.
    ///
    /// Only [`CapabilityAdmission::Admitted`] admits. A merely running
    /// generation (`PendingEvidence`) or a restricted one does not.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// Policy/supervision input to one capability projection (I1.9).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySupervisionInput {
    /// Availability of the current Module Catalog/Policy view.
    pub catalog_view: CatalogPolicyView,
    /// Supervision health dimension observed for the generation.
    pub supervision_health: HealthDimension,
}

/// The three input classes assembled into one capability projection (I1.9).
///
/// `JsonSchema` is deliberately not derived here: the canonical
/// [`ModuleCatalogEntry`] input does not implement `JsonSchema`, and the
/// projection's own schema is published through [`CapabilityProjection`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProjectionInput {
    /// Canonical manifest/admission record from the Governor Module Catalog.
    pub catalog: Option<ModuleCatalogEntry>,
    /// Canonical capability evidence records retained for the module.
    pub evidence: Vec<CapabilityEvidenceRecord>,
    /// Kernel generation/health input from the Generation Registry.
    pub generation: Option<GenerationRegistryRecord>,
    /// Policy/supervision input.
    pub policy: PolicySupervisionInput,
}

/// One Capability Registry projection record for one module generation (I1.9).
///
/// The record is a composite projection: it carries the current usable
/// installation/route, the evidence recorded for the generation, its
/// limitations and its admission status. It owns no lifecycle state and infers
/// no process truth or authority from route availability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProjection {
    /// Stable module identity.
    pub module_id: String,
    /// Projected generation identity.
    pub generation: ResourceGeneration,
    /// Current usable installation/route, when one is usable.
    pub usable_route: Option<String>,
    /// Policy view the projection was assembled under.
    pub policy_view: CatalogPolicyView,
    /// Supervision health dimension the projection was assembled under.
    pub supervision_health: HealthDimension,
    /// Evidence references recorded for this generation.
    pub evidence_refs: Vec<String>,
    /// Limitations and negative evidence recorded for this generation.
    pub limitations: Vec<String>,
    /// Whether the latest recorded evidence restricts the generation. A later
    /// positive record supersedes an earlier restriction, matching the I3.4
    /// superseding evidence model.
    pub restricted: bool,
    /// Admission status. Never inferred from route availability.
    pub admission: CapabilityAdmission,
}

impl CapabilityProjection {
    /// Validates the projection shape.
    fn validate(&self) -> Result<(), CapabilityRegistryError> {
        if self.module_id.trim().is_empty() || self.module_id.chars().any(char::is_control) {
            return Err(CapabilityRegistryError::InvalidField {
                field: "capability_projection_module_id",
                reason: "must be non-blank and contain no control characters",
            });
        }
        Ok(())
    }

    /// The admission status of this projection.
    #[must_use]
    pub const fn admission(&self) -> CapabilityAdmission {
        self.admission
    }

    /// Whether this projection admits the generation as a usable capability.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.admission.is_admitted()
    }
}

/// Fail-closed errors for the Capability Registry projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CapabilityRegistryError {
    /// A projection field is invalid.
    #[error("invalid capability registry field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// The projection input does not name a usable installation.
    #[error("capability projection has no usable installation")]
    NoUsableInstallation,
    /// The projection record was not found.
    #[error("capability projection record was not found")]
    ProjectionNotFound,
    /// A supplied input record failed its own owner's `validate`.
    ///
    /// The owner's own refusal text is carried verbatim so the projection
    /// reports the owning registry's cause instead of restating it.
    #[error("capability projection input was refused by its owner: {0}")]
    InputRefused(String),
}

/// Computes the admission status from the recorded evidence and the
/// policy/supervision input (I1.9).
///
/// The order is load bearing:
///
/// * A fresh restriction (`broken`, `unsupported` or `degraded` evidence)
///   restricts the generation regardless of anything else.
/// * With no recorded evidence the generation is `PendingEvidence`: a merely
///   running generation does not appear as admitted capability until the
///   Governor records the required evidence.
/// * Recorded evidence under a stale/unavailable policy view or unhealthy
///   supervision stays `PendingEvidence`, because admission cannot rest on a
///   policy the Governor no longer current or on absent supervision.
/// * Only recorded, non-restricting evidence under a current policy view and
///   healthy supervision is `Admitted`.
const fn evaluate_admission(
    restricted: bool,
    evidence_recorded: bool,
    policy_view: CatalogPolicyView,
    supervision_health: HealthDimension,
) -> CapabilityAdmission {
    if restricted {
        return CapabilityAdmission::Restricted;
    }
    if !evidence_recorded
        || !matches!(policy_view, CatalogPolicyView::Current)
        || !matches!(supervision_health, HealthDimension::Healthy)
    {
        return CapabilityAdmission::PendingEvidence;
    }
    CapabilityAdmission::Admitted
}

/// The route one generation currently serves or is staged to serve (I1.9).
fn usable_route_of(generation: &GenerationRegistryRecord) -> Option<String> {
    match generation.state() {
        GenerationOperationalState::Running => {
            generation.route_state().active_route_scope_hash.clone()
        }
        GenerationOperationalState::Candidate => {
            generation.route_state().candidate_route_scope_hash.clone()
        }
        GenerationOperationalState::Installed => None,
    }
}

/// Assembles one capability projection from the three input classes (I1.9).
///
/// The projection joins the canonical manifest/admission record (the Module
/// Catalog desired-state source), the Kernel generation/health input (the
/// Generation Registry operational record), the retained capability evidence and
/// the policy/supervision input. It records the current usable installation/
/// route, the evidence recorded for the generation, its limitations and its
/// admission status. It never mutates its inputs: the Module Catalog and the
/// Generation Registry are read-only sources, and removing the projection later
/// mutates only this registry.
///
/// The join is an identity join, not a name join: the generation record's
/// module identity must be the catalog entry's module identity, and the
/// generation record must have passed its own `validate`, which binds its
/// recorded key and Authority Epoch to the manifest admission copied out of the
/// Governor. A running generation is therefore only ever projected for the
/// exact admitted generation, never for a same-named substitute.
///
/// # Errors
///
/// Returns [`CapabilityRegistryError::NoUsableInstallation`] when the input
/// names neither a Catalog desired/admission record nor a Generation Registry
/// operational record, or when the operational record belongs to a different
/// module than the catalog, so there is no installation to project. Returns
/// [`CapabilityRegistryError::InputRefused`], carrying the owning registry's own
/// refusal text, when the supplied catalog entry or generation record fails its
/// owner's `validate` — a forged, substituted or self-inconsistent input is
/// refused here rather than projected.
pub fn project_capability(
    input: &CapabilityProjectionInput,
) -> Result<CapabilityProjection, CapabilityRegistryError> {
    let catalog = input
        .catalog
        .as_ref()
        .ok_or(CapabilityRegistryError::NoUsableInstallation)?;
    let generation = input
        .generation
        .as_ref()
        .ok_or(CapabilityRegistryError::NoUsableInstallation)?;
    // Both canonical inputs are checked through their own owner's `validate`,
    // not through a second opinion computed here. The catalog entry is the
    // Governor's own record and the generation record is the Kernel/ORS one;
    // each refuses its own forgery and disagreement causes, and the refusal
    // text is carried verbatim so this function does not restate or mask it.
    catalog
        .validate()
        .map_err(|error| CapabilityRegistryError::InputRefused(error.to_string()))?;
    generation
        .validate()
        .map_err(|error| CapabilityRegistryError::InputRefused(error.to_string()))?;
    if generation.module_id() != catalog.module_id.as_str() {
        return Err(CapabilityRegistryError::NoUsableInstallation);
    }
    let module_id = catalog.module_id.as_str().to_owned();
    let generation_id = generation.generation();
    let usable_route = usable_route_of(generation);
    let evidence_refs = input
        .evidence
        .iter()
        .map(|record| record.skill_id.clone())
        .collect();
    let limitations = input
        .evidence
        .iter()
        .flat_map(|record| record.limitations_and_negative_evidence.clone())
        .collect();
    let restricted = input.evidence.last().is_some_and(|record| {
        matches!(
            record.status,
            CapabilityStatus::Broken | CapabilityStatus::Unsupported | CapabilityStatus::Degraded
        )
    });
    let evidence_recorded = !input.evidence.is_empty();
    let admission = evaluate_admission(
        restricted,
        evidence_recorded,
        input.policy.catalog_view,
        input.policy.supervision_health,
    );
    let projection = CapabilityProjection {
        module_id,
        generation: generation_id,
        usable_route,
        policy_view: input.policy.catalog_view,
        supervision_health: input.policy.supervision_health,
        evidence_refs,
        limitations,
        restricted,
        admission,
    };
    projection.validate()?;
    Ok(projection)
}

/// The Governor-owned Capability Registry projection (I1.9).
///
/// One [`CapabilityProjection`] per `(module_id, generation)`. The registry is
/// a composite projection: it assembles canonical manifests/evidence, Kernel
/// generation/health input and policy/supervision input into an independently
/// inspectable usability/admission view. It has no lifecycle ownership and
/// cannot infer process truth or authority merely from route availability.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityRegistry {
    projections: BTreeMap<(String, ResourceGeneration), CapabilityProjection>,
}

impl CapabilityRegistry {
    /// Creates an empty projection registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Assembles and stores one projection from the three input classes.
    ///
    /// The projection is computed by [`project_capability`] and stored under
    /// its `(module_id, generation)`. Storing a projection mutates only this
    /// registry.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::NoUsableInstallation`] when the
    /// input names no usable installation, and
    /// [`CapabilityRegistryError::InputRefused`] when a supplied canonical input
    /// fails its owning registry's own `validate`.
    pub fn project(
        &mut self,
        input: &CapabilityProjectionInput,
    ) -> Result<CapabilityProjection, CapabilityRegistryError> {
        let projection = project_capability(input)?;
        self.projections.insert(
            (projection.module_id.clone(), projection.generation),
            projection.clone(),
        );
        Ok(projection)
    }

    /// Records one evidence record for a stored projection and recomputes its
    /// admission status.
    ///
    /// The evidence reference and limitations are appended, and the admission
    /// status is re-evaluated from the updated evidence set under the
    /// projection's policy/supervision input. A merely running generation
    /// becomes `Admitted` only once the required evidence is recorded.
    ///
    /// The recomputation runs on a copy of the stored projection and is
    /// committed only when it validates, so a refused update leaves the stored
    /// projection byte-identical rather than carrying appended references with
    /// a stale admission status.
    ///
    /// The admission status is re-evaluated against the policy view and
    /// supervision health already recorded on the stored projection, which are
    /// the values observed when the projection was assembled. This method
    /// observes no clock and reads no policy owner: a projection assembled
    /// under a now-stale view keeps reporting that view, and the Governor that
    /// owns the view re-projects to refresh it.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::ProjectionNotFound`] when no
    /// projection is stored for the `(module_id, generation)`.
    pub fn record_evidence(
        &mut self,
        module_id: &str,
        generation: ResourceGeneration,
        evidence: &CapabilityEvidenceRecord,
    ) -> Result<CapabilityProjection, CapabilityRegistryError> {
        let stored = self
            .projections
            .get(&(module_id.to_owned(), generation))
            .ok_or(CapabilityRegistryError::ProjectionNotFound)?;
        let mut next = stored.clone();
        next.evidence_refs.push(evidence.skill_id.clone());
        next.limitations
            .extend(evidence.limitations_and_negative_evidence.iter().cloned());
        // The latest recorded evidence decides the restriction: a later
        // positive record supersedes an earlier restriction, matching the
        // I3.4 superseding evidence model.
        next.restricted = matches!(
            evidence.status,
            CapabilityStatus::Broken | CapabilityStatus::Unsupported | CapabilityStatus::Degraded
        );
        next.admission = evaluate_admission(
            next.restricted,
            !next.evidence_refs.is_empty(),
            next.policy_view,
            next.supervision_health,
        );
        next.validate()?;
        self.projections
            .insert((module_id.to_owned(), generation), next.clone());
        Ok(next)
    }

    /// Returns the projection for one `(module_id, generation)`, independently
    /// inspectable without reading the Module Catalog or the Generation
    /// Registry.
    #[must_use]
    pub fn get(
        &self,
        module_id: &str,
        generation: ResourceGeneration,
    ) -> Option<&CapabilityProjection> {
        self.projections.get(&(module_id.to_owned(), generation))
    }

    /// Returns true when the stored projection for one `(module_id,
    /// generation)` admits the generation as a usable capability.
    ///
    /// Admission requires recorded evidence; a merely running generation does
    /// not appear as admitted until the Governor projection records the
    /// required evidence.
    #[must_use]
    pub fn is_admitted(&self, module_id: &str, generation: ResourceGeneration) -> bool {
        self.get(module_id, generation)
            .is_some_and(CapabilityProjection::is_admitted)
    }

    /// Removes and returns the projection for one `(module_id, generation)`.
    ///
    /// Removing the projection mutates only this registry. It does not touch
    /// the Module Catalog or the Generation Registry.
    pub fn remove(
        &mut self,
        module_id: &str,
        generation: ResourceGeneration,
    ) -> Result<CapabilityProjection, CapabilityRegistryError> {
        self.projections
            .remove(&(module_id.to_owned(), generation))
            .ok_or(CapabilityRegistryError::ProjectionNotFound)
    }

    /// Returns the number of retained projections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.projections.len()
    }

    /// Returns true when no projections are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.projections.is_empty()
    }

    /// Returns every retained projection, in `(module_id, generation)` order.
    #[must_use]
    pub fn projections(&self) -> Vec<&CapabilityProjection> {
        self.projections.values().collect()
    }
}
