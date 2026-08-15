//! P-07 role-filtered, non-semantic recovery state view.
//!
//! The recovery view is a projection, not a second authority or truth owner.
//! It assembles the process, generation and ORS observations that a Human or
//! Doctor needs to choose the next bounded step, and it never interprets
//! project semantics or fabricates a completion.

use eliot_contracts::AuthorityEpoch;
use eliot_ors::{EpochIdentity, OperationalControlProjection};
use eliot_runtime_contracts::{
    HealthDimension, ModuleGeneration, OperationalRecoveryState, RecoveryDirective, RecoveryView,
    ServiceProcessRecord,
};

use crate::error::{KernelError, validate_text};

/// A validated builder for a role-filtered [`RecoveryView`].
///
/// Each source projection is validated independently, and the final view is
/// validated again before it is returned. A malformed component fails the
/// whole build rather than producing a partial, misleading projection.
#[derive(Clone, Debug)]
pub struct RecoveryViewBuilder {
    view_revision: String,
    source_freshness: String,
    processes: Vec<ServiceProcessRecord>,
    generations: Vec<ModuleGeneration>,
    ors: OperationalRecoveryState,
    directives: Vec<RecoveryDirective>,
}

impl RecoveryViewBuilder {
    /// Creates a builder from the two identity fields and the ORS projection.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity field is blank or the ORS projection
    /// is invalid.
    pub fn new(
        view_revision: impl Into<String>,
        source_freshness: impl Into<String>,
        ors: OperationalRecoveryState,
    ) -> Result<Self, KernelError> {
        let view_revision = view_revision.into();
        let source_freshness = source_freshness.into();
        validate_text(&view_revision, "view_revision")?;
        validate_text(&source_freshness, "source_freshness")?;
        ors.validate().map_err(KernelError::RuntimeContract)?;
        Ok(Self {
            view_revision,
            source_freshness,
            processes: Vec::new(),
            generations: Vec::new(),
            ors,
            directives: Vec::new(),
        })
    }

    /// Adds a validated process observation.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is invalid.
    pub fn add_process(mut self, process: ServiceProcessRecord) -> Result<Self, KernelError> {
        process.validate().map_err(KernelError::RuntimeContract)?;
        self.processes.push(process);
        Ok(self)
    }

    /// Adds a validated generation observation.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation is invalid.
    pub fn add_generation(mut self, generation: ModuleGeneration) -> Result<Self, KernelError> {
        generation
            .validate()
            .map_err(KernelError::RuntimeContract)?;
        self.generations.push(generation);
        Ok(self)
    }

    /// Adds a validated recovery directive.
    ///
    /// # Errors
    ///
    /// Returns an error when the directive is invalid.
    pub fn add_directive(mut self, directive: RecoveryDirective) -> Result<Self, KernelError> {
        directive.validate().map_err(KernelError::RuntimeContract)?;
        self.directives.push(directive);
        Ok(self)
    }

    /// Builds and validates the final recovery view.
    ///
    /// # Errors
    ///
    /// Returns an error when the assembled view fails validation.
    pub fn build(self) -> Result<RecoveryView, KernelError> {
        let view = RecoveryView {
            view_revision: self.view_revision,
            source_freshness: self.source_freshness,
            processes: self.processes,
            generations: self.generations,
            ors: self.ors,
            directives: self.directives,
        };
        view.validate().map_err(KernelError::RuntimeContract)?;
        Ok(view)
    }
}

/// Projects a non-authoritative ORS control projection into a bounded
/// [`OperationalRecoveryState`].
///
/// The projection is derived from durable, validated ORS rows; it never reads
/// project semantics and never becomes a second authority owner.
///
/// # Errors
///
/// Returns an error when the authority epoch in the lineage is zero, the
/// resulting operational state fails validation, or the ref-vector bounds are
/// exceeded.
pub fn project_operational_state(
    projection: &OperationalControlProjection,
    integrity: HealthDimension,
) -> Result<OperationalRecoveryState, KernelError> {
    let authority_epoch = authority_epoch_from(&projection.authority_lineage.current)?;
    let state = OperationalRecoveryState {
        ors_revision: "eliot.kernel.ors/v1".to_owned(),
        integrity,
        authority_epoch,
        pending_operation_refs: projection.pending_operation_refs.clone(),
        active_generation_refs: projection.active_generation_refs.clone(),
        recovery_intent_refs: projection.recovery_inbox_refs.clone(),
    };
    state.validate().map_err(KernelError::RuntimeContract)?;
    Ok(state)
}

fn authority_epoch_from(current: &EpochIdentity) -> Result<AuthorityEpoch, KernelError> {
    AuthorityEpoch::new(current.epoch).map_err(KernelError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_validates_each_component_and_the_final_view() -> Result<(), KernelError> {
        let ors = OperationalRecoveryState {
            ors_revision: "eliot.kernel.ors/v1".to_owned(),
            integrity: HealthDimension::Healthy,
            authority_epoch: AuthorityEpoch::genesis(),
            pending_operation_refs: Vec::new(),
            active_generation_refs: Vec::new(),
            recovery_intent_refs: Vec::new(),
        };
        let view = RecoveryViewBuilder::new("r1", "fresh", ors)?
            .add_directive(RecoveryDirective {
                reason: "ors unavailable".to_owned(),
                next_action: "inspect recovery channel".to_owned(),
                required_authority: "recovery_principal".to_owned(),
                evidence_refs: vec!["evidence-1".to_owned()],
            })?
            .build()?;
        assert_eq!(view.view_revision, "r1");
        assert_eq!(view.directives.len(), 1);
        Ok(())
    }

    #[test]
    fn builder_rejects_blank_identity() {
        let ors = OperationalRecoveryState {
            ors_revision: "eliot.kernel.ors/v1".to_owned(),
            integrity: HealthDimension::Healthy,
            authority_epoch: AuthorityEpoch::genesis(),
            pending_operation_refs: Vec::new(),
            active_generation_refs: Vec::new(),
            recovery_intent_refs: Vec::new(),
        };
        assert!(RecoveryViewBuilder::new(" ", "fresh", ors).is_err());
    }

    #[test]
    fn builder_rejects_malformed_directive() {
        let ors = OperationalRecoveryState {
            ors_revision: "eliot.kernel.ors/v1".to_owned(),
            integrity: HealthDimension::Healthy,
            authority_epoch: AuthorityEpoch::genesis(),
            pending_operation_refs: Vec::new(),
            active_generation_refs: Vec::new(),
            recovery_intent_refs: Vec::new(),
        };
        let malformed = RecoveryDirective {
            reason: " ".to_owned(),
            next_action: "inspect".to_owned(),
            required_authority: "recovery_principal".to_owned(),
            evidence_refs: Vec::new(),
        };
        assert!(
            RecoveryViewBuilder::new("r1", "fresh", ors)
                .unwrap()
                .add_directive(malformed)
                .is_err()
        );
    }
}
