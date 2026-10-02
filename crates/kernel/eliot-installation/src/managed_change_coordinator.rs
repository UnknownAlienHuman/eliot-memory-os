//! I3.3.1/I3.15: signed admission and original durable managed-effect dispatch.
//!
//! The receiver supplies the transaction store at every read. Context fields
//! are verification inputs, never caller declarations of permission. The
//! catalogue/approval and fresh physical survey are checked before each step.

use eliot_config::InitialConfigSnapshotTrustAnchor;

use super::{
    AcceptedCatalogueContext, InstallationError, InstallationStepOutcome,
    InstallationTransaction, InstallationTransactionStore, InstallerEffectPlan,
    ManagedChangeAdmissionError, ManagedEnvironmentChangePlan,
    ManagedEnvironmentChangeRequest, ManagedResourceKey, PlatformHandle,
    RedbInstallationTransactionStore, SurveyObservationSource, VerifiedSetupBinding,
    WindowsInstallationCoordinator, admit_installation_survey_and_compile_change,
};

/// Original publication and setup inputs used with the coordinator's own store.
///
/// This group contains no approval bits. Admission independently reads signed
/// bytes from the receiver, verifies the pinned key and exact setup binding,
/// resolves the owner-signed request, and observes the current platform files.
pub struct ManagedChangeOwnerContext<'a> {
    /// Original installation/setup transaction owning the signed publication.
    pub publication_transaction_id: &'a PlatformHandle,
    /// Independently protected owner key trust anchor.
    pub anchor: &'a InitialConfigSnapshotTrustAnchor,
    /// Original verified setup binding, not a caller owner or root string.
    pub authority: &'a VerifiedSetupBinding,
    /// Platform observed by the installation composition.
    pub observed_platform: &'a PlatformHandle,
}

impl<S: InstallationTransactionStore> WindowsInstallationCoordinator<S> {
    pub(super) fn require_core_effect_path(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let transaction = self.inner.store().load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        if transaction.installer_effects.iter().any(|effect| matches!(
            effect, InstallerEffectPlan::ManagedEnvironmentChange { .. }
        )) {
            return Err(InstallationError::ProfileViolation(
                "managed effects require current signed catalogue, approval and survey admission"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl WindowsInstallationCoordinator<RedbInstallationTransactionStore> {
    /// Compiles one approved request and durably inserts its original intent.
    ///
    /// No resource effect occurs here. The existing table writer atomically
    /// checks prior resource/root owners and refuses competing plans.
    ///
    /// # Errors
    ///
    /// Refuses missing, stale, substituted or foreign publication/approval,
    /// changed survey identities, unresolved owners, and same-table conflicts.
    pub fn admit_managed_change(
        &mut self,
        owner: &ManagedChangeOwnerContext<'_>,
        source: &dyn SurveyObservationSource,
        request: &ManagedEnvironmentChangeRequest,
    ) -> Result<PlatformHandle, ManagedChangeAdmissionError> {
        let accepted = {
            let context = self.managed_admission_context(owner);
            admit_installation_survey_and_compile_change(&context, source, request)?
        };
        let anchor = self.inner.store().load(owner.publication_transaction_id)?
            .ok_or(InstallationError::IdentityConflict)?;
        let key = ManagedResourceKey {
            family_id: request.target_family.clone(),
            exact_candidate: request.exact_candidate.clone(),
        };
        let prior = self.inner.store().managed_resource_projection(&key)?;
        let mut prior_receipts = Vec::new();
        if let Some(projection) = &prior {
            for generation in &projection.owned_generations {
                let original = self.inner.store().load(&generation.transaction_id)?
                    .ok_or(InstallationError::IdentityConflict)?;
                original.validate()?;
                let receipt = super::managed_change_execution::resolve_applied_managed_effect(
                    &[original], generation,
                )?.ok_or(InstallationError::IdentityConflict)?;
                prior_receipts.push(receipt);
            }
        }
        let tools = accepted.managed_tools_root();
        let family = tools.join(request.target_family.as_str());
        let installation_root = &anchor.candidate_manifest.runtime_launch.runtime_state_roots
            .installation_root;
        let mut prior_roots = Vec::new();
        for path in [tools, family.as_path()] {
            let root = PlatformHandle::new(path.to_string_lossy().into_owned())
                .map_err(|_| InstallationError::IdentityConflict)?;
            if let Some(proof) = self.inner.store().managed_root_effect_proof(
                owner.publication_transaction_id, installation_root, anchor.profile, &root,
            )? {
                prior_roots.push(proof);
            }
        }
        accepted.revalidate_for_effect(&self.managed_admission_context(owner), source)?;
        let transaction = InstallationTransaction::new_accepted_managed_change(
            &anchor, &accepted, prior, prior_receipts, prior_roots,
        )?;
        let transaction_id = transaction.transaction_id.clone();
        self.inner.store_mut().create_planned(&transaction)?;
        Ok(transaction_id)
    }

    /// Revalidates current authority and drives one exact already-admitted step.
    ///
    /// A drift refusal leaves all previously issued effects and their original
    /// operation identities durable for readback/recovery; it issues no new
    /// effect or replacement request.
    ///
    /// # Errors
    ///
    /// Refuses any difference from the original frozen accepted plan, including
    /// executable, catalogue, approval, root, setup or source-recipe changes.
    pub fn drive_managed_change(
        &mut self,
        owner: &ManagedChangeOwnerContext<'_>,
        source: &dyn SurveyObservationSource,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, ManagedChangeAdmissionError> {
        let transaction = self.inner.store().load(transaction_id)?
            .ok_or(InstallationError::IdentityConflict)?;
        transaction.validate()?;
        let mut managed = transaction.installer_effects.iter().filter_map(|effect| {
            match effect {
                InstallerEffectPlan::ManagedEnvironmentChange {
                    accepted_plan_json, request, ..
                } => Some((accepted_plan_json, request)),
                _ => None,
            }
        });
        let (encoded, request) = managed.next().ok_or(InstallationError::IdentityConflict)?;
        if managed.next().is_some() || request.request_id != *transaction_id {
            return Err(InstallationError::IdentityConflict.into());
        }
        let retained = ManagedEnvironmentChangePlan::from_retained_json(encoded)?;
        let fresh = {
            let context = self.managed_admission_context(owner);
            let fresh = admit_installation_survey_and_compile_change(&context, source, request)?;
            fresh.revalidate_for_effect(&context, source)?;
            fresh
        };
        if fresh.plan() != &retained {
            return Err(InstallationError::IdentityConflict.into());
        }
        Ok(self.inner.drive_effect(transaction_id)?)
    }

    /// Drives the original finite effect list, revalidating before each
    /// pending effect and then committing the exact managed terminal receipt.
    ///
    /// # Errors
    /// Returns typed admission drift, readback, CAS or bounded-drive failures.
    pub fn drive_managed_change_until_blocked(
        &mut self,
        owner: &ManagedChangeOwnerContext<'_>,
        source: &dyn SurveyObservationSource,
        transaction_id: &PlatformHandle,
    ) -> Result<InstallationStepOutcome, ManagedChangeAdmissionError> {
        let transaction = self.inner.store().load(transaction_id)?
            .ok_or(InstallationError::IdentityConflict)?;
        transaction.validate()?;
        let max_steps = transaction.installer_effects.len().checked_add(3)
            .ok_or(InstallationError::IdentityConflict)?;
        for _ in 0..max_steps {
            let current = self.inner.store().load(transaction_id)?
                .ok_or(InstallationError::IdentityConflict)?;
            current.validate()?;
            if current.is_managed_child_transaction() && current.effect_progress.iter().all(|progress| matches!(
                progress.state, super::InstallationEffectProgressState::Applied { .. }
            )) {
                current.require_all_effects_applied()?;
                // All effects in this exact admitted child have already been
                // independently read back and persisted. The terminal CAS
                // completes that same receipt chain; it does not authorize a
                // new effect and therefore does not recompile the survey.
                let outcome = self.inner.drive_effect(transaction_id)?;
                if matches!(
                    &outcome,
                    InstallationStepOutcome::RollbackRequired { .. }
                        | InstallationStepOutcome::Quarantined { .. }
                        | InstallationStepOutcome::Rejected
                ) {
                    return Ok(outcome);
                }
                if !matches!(
                    &outcome,
                    InstallationStepOutcome::Applied {
                        stage: super::InstallationStage::Completed,
                        ..
                    }
                ) {
                    return Err(InstallationError::IncompleteObservation(
                        "managed child terminal dispatch did not return its completed receipt"
                            .to_owned(),
                    ).into());
                }
                let completed = self.inner.store().load(transaction_id)?
                    .ok_or(InstallationError::IdentityConflict)?;
                if completed.stage() != super::InstallationStage::Completed
                    || !completed.is_managed_child_transaction()
                    || completed.transaction_id != current.transaction_id
                    || completed.installer_plan_digest != current.installer_plan_digest
                    || completed.installer_effects != current.installer_effects
                    || completed.effect_progress != current.effect_progress
                {
                    return Err(InstallationError::IncompleteObservation(
                        "managed child effects were applied without reaching their original completed receipt"
                            .to_owned(),
                    ).into());
                }
                completed.validate()?;
                return Ok(outcome);
            }
            let outcome = self.drive_managed_change(owner, source, transaction_id)?;
            if !matches!(outcome, InstallationStepOutcome::Applied { .. }) {
                return Ok(outcome);
            }
        }
        Err(InstallationError::IncompleteObservation(
            "bounded managed effect drive exhausted before the original effects completed"
                .to_owned(),
        ).into())
    }

    fn managed_admission_context<'a>(
        &'a self,
        owner: &'a ManagedChangeOwnerContext<'_>,
    ) -> AcceptedCatalogueContext<'a> {
        AcceptedCatalogueContext {
            store: self.inner.store(),
            transaction_id: owner.publication_transaction_id,
            anchor: owner.anchor,
            authority: owner.authority,
            observed_platform: owner.observed_platform,
            now_ms: super::wall_clock_millis(),
        }
    }
}
