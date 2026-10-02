//! I3.3: one narrow installation survey call through the existing Kernel gateway.

use std::sync::Arc;

use eliot_installation::{
    AcceptedCatalogueContext, InstallationSurveyProbeRequest, InstallationSurveyProbeResult,
    InstallationTransactionStore, ManagedEnvironmentAction, ManagedEnvironmentChangeRequest,
    PlatformHandle, RedbInstallationTransactionStore, WindowsInstallationCoordinator,
    WindowsSurveyObservationSource, admit_installation_survey_and_compile_change,
    load_system_owner_initial_snapshot_authority, survey_accepted_installation,
};
use eliot_ipc::{Session, TransportError};
use eliot_protocol::RequestIdentity;

use super::KernelComposition;

impl KernelComposition {
    /// Reopens every owner binding before the original gateway issues a process.
    #[cfg(windows)]
    pub(crate) async fn installation_survey_probe_operation(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.state_fence != session.module_generation.state_fence
            || identity.deadline_unix_ms <= super::unix_ms()
        {
            return Err(TransportError::SessionFenced);
        }
        let input: InstallationSurveyProbeRequest = serde_json::from_value(
            super::daemon_request_dispatch::without_daemon_routing_key(payload.clone())?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        input
            .request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if requires_completed_change(input.request.action)
            && input.completed_change_transaction_id.is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        if !input.store_path.is_absolute() {
            return Err(TransportError::SessionFenced);
        }
        let store = RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path)
            .map_err(|_| TransportError::SessionFenced)?;
        let coordinator = WindowsInstallationCoordinator::new(store);
        let store = coordinator.transaction_store();
        let (anchor, authority) =
            load_system_owner_initial_snapshot_authority(store, &input.publication_transaction_id)
                .map_err(|_| TransportError::SessionFenced)?;
        let retained = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if authority.installation_id() != retained.installation_id()
            || authority.runtime_state_roots_digest().as_str()
                != retained.runtime_state_roots_digest()
        {
            return Err(TransportError::SessionFenced);
        }
        let original = store
            .load(&input.publication_transaction_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        original
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if original.candidate_manifest.generation.as_str() != retained.approved_generation() {
            return Err(TransportError::SessionFenced);
        }
        let platform = PlatformHandle::new(format!(
            "{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let context = AcceptedCatalogueContext {
            store,
            transaction_id: &input.publication_transaction_id,
            anchor: &anchor,
            authority: &authority,
            observed_platform: &platform,
            now_ms: super::unix_ms(),
        };
        let source = WindowsSurveyObservationSource;
        let (probe_input, mut result, invocation) =
            if let Some(changed_id) = input.completed_change_transaction_id.as_ref() {
                let requalification = eliot_installation::requalify_completed_managed_change(
                    &context,
                    &source,
                    &input.request,
                    changed_id,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                let result = requalification.result().clone();
                let Some(invocation) = requalification.probe().cloned() else {
                    // Keep the owner's live unsupported/declared facts visible;
                    // no missing-probe fallback may execute here.
                    return serde_json::to_value(result).map_err(|_| TransportError::SessionFenced);
                };
                (
                    InstallationSurveyProbeInput::Completed {
                        request: input.request.clone(),
                        completed_transaction_id: changed_id.clone(),
                        expected: requalification,
                    },
                    result,
                    invocation,
                )
            } else {
                let accepted =
                    admit_installation_survey_and_compile_change(&context, &source, &input.request)
                        .map_err(|_| TransportError::SessionFenced)?;
                let invocation = accepted
                    .plan()
                    .target_probe()
                    .cloned()
                    .ok_or(TransportError::SessionFenced)?;
                // The hash comes from the native retained-file observation, never a
                // family ID, recipe string or package-manager exit code.
                let observed = survey_accepted_installation(&context, &source)
                    .map_err(|_| TransportError::SessionFenced)?;
                let executable = observed
                    .executable_observation_for_probe(&invocation)
                    .ok_or(TransportError::SessionFenced)?;
                let version = executable
                    .file_version
                    .as_ref()
                    .ok_or(TransportError::SessionFenced)?;
                let result = InstallationSurveyProbeResult {
                    advertisement: eliot_installation::requalify_managed_capability(
                        &accepted, &context, &source,
                    )
                    .map_err(|_| TransportError::SessionFenced)?,
                    runtime_hash: version.sha256.clone(),
                    previous_runtime_hash: None,
                };
                (
                    InstallationSurveyProbeInput::Accepted(accepted),
                    result,
                    invocation,
                )
            };
        // An unresolved original probe may still hold its temporary admitted
        // ACL. Reconcile that owner's retained lease before opening a fresh
        // root; never create a replacement operation or scope on replay.
        let area = match self
            .retained_survey_probe_working_area(session, identity)
            .map_err(|_| TransportError::SessionFenced)?
        {
            Some(retained) => retained,
            None => Arc::new(
                coordinator
                    .retain_survey_probe_working_area(&input.publication_transaction_id)
                    .map_err(|_| TransportError::SessionFenced)?,
            ),
        };
        let (advertisement, _receipt, _evidence) = self
            .run_installation_survey_probe(
                session,
                identity,
                area,
                &probe_input,
                &context,
                &source,
                &invocation,
            )
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        result.advertisement = advertisement;
        serde_json::to_value(result).map_err(|_| TransportError::SessionFenced)
    }
}

fn requires_completed_change(action: ManagedEnvironmentAction) -> bool {
    action != ManagedEnvironmentAction::Register
}

pub(super) enum InstallationSurveyProbeInput {
    Accepted(eliot_installation::AcceptedManagedChange),
    Completed {
        request: ManagedEnvironmentChangeRequest,
        completed_transaction_id: PlatformHandle,
        expected: eliot_installation::CompletedManagedChangeRequalification,
    },
}

#[cfg(test)]
mod tests {
    use super::requires_completed_change;
    use eliot_installation::ManagedEnvironmentAction;

    #[test]
    fn missing_completed_change_is_required_for_updates_but_not_register_observation() {
        assert!(requires_completed_change(ManagedEnvironmentAction::Update));
        assert!(!requires_completed_change(
            ManagedEnvironmentAction::Register
        ));
    }
}
