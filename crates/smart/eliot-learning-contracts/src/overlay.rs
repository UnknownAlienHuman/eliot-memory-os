//! Reversible, expiring task-local overlay candidates.

use eliot_contracts::{ArtifactId, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    delta::{ChangeOperation, ChangeSurface, InverseChange, ValueState},
    error::LearningContractError,
    identity::{
        CampaignId, ContractBinding, OverlayId, TargetId, digest_without_field, validate_digest,
    },
};

/// Whether a value came from the immutable base or the proposed overlay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverlayOrigin {
    /// Value is from the exact base revision.
    Base,
    /// Value is introduced by the task-local candidate.
    Overlay,
}

/// One typed reversible surface change in an overlay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverlayChange {
    /// Typed target identity.
    pub target: TargetId,
    /// Closed candidate surface.
    pub surface: ChangeSurface,
    /// Exact value before the overlay.
    pub base: ValueState,
    /// Exact value proposed by the overlay.
    pub proposed: ValueState,
    /// Exact inverse operation retained for discard/rollback.
    pub inverse: InverseChange,
    /// Origin of the proposed value.
    pub origin: OverlayOrigin,
}

impl OverlayChange {
    /// Validate value presence and exact inverse semantics.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        crate::identity::validate_external_id(self.target.as_str(), "overlay_change.target")?;
        self.base.validate("overlay_change.base")?;
        self.proposed.validate("overlay_change.proposed")?;
        if self.base == self.proposed {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay_change",
            });
        }
        if matches!(self.origin, OverlayOrigin::Base) {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay_change.origin",
            });
        }
        self.inverse.validate()?;
        let forward = match (self.base.present, self.proposed.present) {
            (false, true) => ChangeOperation::Add {
                target: self.target.clone(),
                surface: self.surface,
                after: self.proposed.clone(),
            },
            (true, false) => ChangeOperation::Remove {
                target: self.target.clone(),
                surface: self.surface,
                before: self.base.clone(),
            },
            (true, true) => ChangeOperation::Replace {
                target: self.target.clone(),
                surface: self.surface,
                before: self.base.clone(),
                after: self.proposed.clone(),
            },
            (false, false) => {
                return Err(LearningContractError::ScopeMismatch {
                    field: "overlay_change",
                });
            }
        };
        if !self.inverse.is_exact_inverse_of(&forward) {
            return Err(LearningContractError::MissingInverse);
        }
        Ok(())
    }
}

/// Dependency edge between overlay changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverlayDependency {
    /// Change that must be applied first.
    pub prerequisite: TargetId,
    /// Change that depends on it.
    pub dependent: TargetId,
}

impl OverlayDependency {
    /// Validate both dependency identities and reject self-dependencies.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        crate::identity::validate_external_id(
            self.prerequisite.as_str(),
            "dependency.prerequisite",
        )?;
        crate::identity::validate_external_id(self.dependent.as_str(), "dependency.dependent")?;
        if self.prerequisite == self.dependent {
            return Err(LearningContractError::ScopeMismatch {
                field: "dependency",
            });
        }
        Ok(())
    }
}

/// Candidate evaluation layer over an exact immutable base/parent revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignHarnessOverlayCandidate {
    /// Shared task-local scope/fence/source binding.
    pub binding: ContractBinding,
    /// Overlay candidate identity.
    pub overlay_id: OverlayId,
    /// Campaign this overlay is admitted for; cross-campaign reuse is rejected.
    pub campaign_id: CampaignId,
    /// Governor receipt admitting the local overlay effect (`LOCAL_ADMITTED`).
    #[serde(default)]
    pub admission_receipt: Option<ArtifactId>,
    /// Monotonic overlay revision within the campaign, starting at 1.
    #[serde(default = "default_overlay_revision")]
    pub revision: u32,
    /// Previous overlay revision superseded by this candidate, if any.
    #[serde(default)]
    pub supersedes: Option<OverlayId>,
    /// Exact view/base revision being overlaid.
    pub base_view_digest: String,
    /// Parent task revision used for compatibility.
    pub parent_revision: TaskRevision,
    /// Deltas externally admitted for evaluation; this crate does not admit them.
    pub admitted_delta_ids: Vec<ArtifactId>,
    /// Exact candidate digests paired with the admitted delta identities.
    pub admitted_delta_digests: Vec<String>,
    /// Typed candidate changes.
    pub changes: Vec<OverlayChange>,
    /// Dependency DAG edges and application order.
    pub dependencies: Vec<OverlayDependency>,
    /// Target order after dependency resolution.
    pub application_order: Vec<TargetId>,
    /// Protected-surface digest before and after must be equal.
    pub protected_surface_base_digest: String,
    /// Protected-surface digest proposed by the candidate.
    pub protected_surface_proposed_digest: String,
    /// Discriminator fixed before observing the overlay.
    pub fixed_before_observation_discriminator: ArtifactId,
    /// Intended causal mechanism, frozen before any evaluation (S209).
    #[serde(default)]
    pub intended_mechanism: String,
    /// Outcome predicted when the mechanism holds, frozen pre-evaluation.
    #[serde(default)]
    pub prediction: String,
    /// Observable confirming the prediction, frozen pre-evaluation.
    #[serde(default)]
    pub expected_observable: String,
    /// Plausible regressions, frozen pre-evaluation.
    #[serde(default)]
    pub possible_regressions: String,
    /// Known confounders, frozen pre-evaluation.
    #[serde(default)]
    pub confounders: String,
    /// Success that must be preserved, frozen pre-evaluation.
    #[serde(default)]
    pub preserved_success_constraint: String,
    /// Next-discriminator text, frozen pre-evaluation.
    #[serde(default)]
    pub next_discriminator_text: String,
    /// Rollback condition, frozen pre-evaluation.
    #[serde(default)]
    pub rollback_condition: String,
    /// Expiry deadline in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Explicit cancellation/invalidation marker.
    pub invalidated: bool,
    /// Canonical candidate shape digest, excluding this field.
    pub canonical_digest: String,
}

impl CampaignHarnessOverlayCandidate {
    /// Validate reversibility, dependency ordering and candidate-only boundaries.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        self.overlay_id.validate()?;
        self.validate_governed_admission()?;
        validate_digest(&self.base_view_digest, "overlay.base_view_digest")?;
        validate_digest(
            &self.protected_surface_base_digest,
            "overlay.protected_surface_base_digest",
        )?;
        validate_digest(
            &self.protected_surface_proposed_digest,
            "overlay.protected_surface_proposed_digest",
        )?;
        if self.protected_surface_base_digest != self.protected_surface_proposed_digest {
            return Err(LearningContractError::ProtectedSurfaceChanged);
        }
        if self.expires_at_ms == 0 {
            return Err(LearningContractError::Missing {
                field: "overlay.expires_at_ms",
            });
        }
        if self.admitted_delta_ids.is_empty() || self.changes.is_empty() {
            return Err(LearningContractError::Missing {
                field: "overlay.changes",
            });
        }
        ensure_unique(
            self.admitted_delta_ids.iter().map(ArtifactId::as_str),
            "overlay.admitted_delta_ids",
        )?;
        if self.admitted_delta_digests.len() != self.admitted_delta_ids.len() {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay.admitted_delta_digests",
            });
        }
        for digest in &self.admitted_delta_digests {
            validate_digest(digest, "overlay.admitted_delta_digests")?;
        }
        for id in [&self.fixed_before_observation_discriminator] {
            if id.as_str().trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "overlay.discriminator",
                });
            }
        }
        self.validate_frozen_pre_evaluation()?;
        for change in &self.changes {
            change.validate()?;
        }
        ensure_unique(
            self.changes.iter().map(|c| c.target.as_str()),
            "overlay.changes",
        )?;
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        for target in &self.application_order {
            crate::identity::validate_external_id(target.as_str(), "overlay.application_order")?;
        }
        ensure_unique(
            self.application_order.iter().map(TargetId::as_str),
            "overlay.application_order",
        )?;
        if self.application_order.len() != self.changes.len() {
            return Err(LearningContractError::IncompleteCoverage);
        }
        let targets: std::collections::BTreeSet<_> =
            self.changes.iter().map(|c| c.target.as_str()).collect();
        if self
            .application_order
            .iter()
            .any(|target| !targets.contains(target.as_str()))
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay.application_order",
            });
        }
        for edge in &self.dependencies {
            let before = self
                .application_order
                .iter()
                .position(|t| *t == edge.prerequisite);
            let after = self
                .application_order
                .iter()
                .position(|t| *t == edge.dependent);
            if before.is_none() || after.is_none() || before >= after {
                return Err(LearningContractError::ScopeMismatch {
                    field: "overlay.dependencies",
                });
            }
        }
        validate_digest(&self.canonical_digest, "overlay.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "overlay.canonical_digest",
            });
        }
        Ok(())
    }

    /// Validate campaign-local governed admission: campaign identity, revision
    /// clock, receipt handle and supersedes chain head.
    fn validate_governed_admission(&self) -> Result<(), LearningContractError> {
        self.campaign_id.validate()?;
        if self.revision == 0 {
            return Err(LearningContractError::Missing {
                field: "overlay.revision",
            });
        }
        if let Some(receipt) = &self.admission_receipt
            && receipt.as_str().trim().is_empty()
        {
            return Err(LearningContractError::Missing {
                field: "overlay.admission_receipt",
            });
        }
        if let Some(previous) = &self.supersedes {
            previous.validate()?;
            if *previous == self.overlay_id {
                return Err(LearningContractError::ScopeMismatch {
                    field: "overlay.supersedes",
                });
            }
        }
        Ok(())
    }

    /// Validate the pre-evaluation frozen manifest-equivalent fields (S209).
    ///
    /// Every nontrivial revision carries at least one change (enforced above),
    /// so all eight frozen texts must be present and bounded. There is no
    /// trivial revision that may skip the freeze.
    fn validate_frozen_pre_evaluation(&self) -> Result<(), LearningContractError> {
        for (value, field) in [
            (&self.intended_mechanism, "overlay.intended_mechanism"),
            (&self.prediction, "overlay.prediction"),
            (&self.expected_observable, "overlay.expected_observable"),
            (&self.possible_regressions, "overlay.possible_regressions"),
            (&self.confounders, "overlay.confounders"),
            (
                &self.preserved_success_constraint,
                "overlay.preserved_success_constraint",
            ),
            (
                &self.next_discriminator_text,
                "overlay.next_discriminator_text",
            ),
            (&self.rollback_condition, "overlay.rollback_condition"),
        ] {
            if value.trim().is_empty() {
                return Err(LearningContractError::Missing { field });
            }
            if value.chars().count() > 8192 {
                return Err(LearningContractError::Bound { field });
            }
        }
        Ok(())
    }

    /// Populate the canonical overlay digest.
    ///
    /// The digest covers the governed admission shape (`campaign_id`,
    /// `admission_receipt`, `revision`, `supersedes`), the pre-evaluation
    /// frozen fields, together with every other field except
    /// `canonical_digest` itself.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }

    /// Report whether every change carries a complete exact inverse.
    pub fn is_reversible(&self) -> bool {
        self.changes.iter().all(|change| change.validate().is_ok())
    }

    /// Validate exact base lineage and externally admitted delta candidates.
    pub fn validate_against_view_and_deltas(
        &self,
        view: &crate::state_view::CampaignLearningStateView,
        deltas: &[crate::delta::AttemptLearningDeltaCandidate],
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        if self.campaign_id != view.campaign_id {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay.campaign",
            });
        }
        if self.binding != view.binding || self.base_view_digest != view.canonical_digest {
            return Err(LearningContractError::ScopeMismatch {
                field: "overlay.view_lineage",
            });
        }
        for (id, digest) in self
            .admitted_delta_ids
            .iter()
            .zip(&self.admitted_delta_digests)
        {
            let Some(delta) = deltas.iter().find(|candidate| candidate.delta_id == *id) else {
                return Err(LearningContractError::ScopeMismatch {
                    field: "overlay.admitted_delta",
                });
            };
            delta.validate_against_view(view)?;
            if digest != &delta.canonical_digest {
                return Err(LearningContractError::DigestMismatch {
                    field: "overlay.admitted_delta_digests",
                });
            }
        }
        let mut available: Vec<&ChangeOperation> = deltas
            .iter()
            .flat_map(|delta| delta.changes.iter())
            .collect();
        for change in &self.changes {
            let forward = match (change.base.present, change.proposed.present) {
                (false, true) => ChangeOperation::Add {
                    target: change.target.clone(),
                    surface: change.surface,
                    after: change.proposed.clone(),
                },
                (true, false) => ChangeOperation::Remove {
                    target: change.target.clone(),
                    surface: change.surface,
                    before: change.base.clone(),
                },
                (true, true) => ChangeOperation::Replace {
                    target: change.target.clone(),
                    surface: change.surface,
                    before: change.base.clone(),
                    after: change.proposed.clone(),
                },
                (false, false) => {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "overlay.change_lineage",
                    });
                }
            };
            let Some(index) = available
                .iter()
                .position(|candidate| **candidate == forward)
            else {
                return Err(LearningContractError::ScopeMismatch {
                    field: "overlay.change_lineage",
                });
            };
            available.remove(index);
        }
        if !available.is_empty() {
            return Err(LearningContractError::IncompleteCoverage);
        }
        Ok(())
    }
}

fn default_overlay_revision() -> u32 {
    1
}

fn ensure_unique<'a, I>(values: I, field: &'static str) -> Result<(), LearningContractError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(LearningContractError::Duplicate { field });
        }
    }
    Ok(())
}
