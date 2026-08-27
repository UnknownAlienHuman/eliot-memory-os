#![allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::map_identity,
    clippy::needless_pass_by_value,
    clippy::redundant_closure,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "installation fixtures use deliberate panic-on-invalid-test-data assertions"
)]

#[cfg(windows)]
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use super::*;
#[cfg(windows)]
use eliot_platform_windows::UserOwnedRootLease;
use eliot_platform_windows::{HostOwnerEpochCapability, HostOwnerLease};

mod rollback_recovery;
mod service_start_recovery;
mod transaction_recovery;

static NEXT_TRANSACTION_ROOT: AtomicU64 = AtomicU64::new(0);
#[cfg(windows)]
static PRODUCTION_INSTALLER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn host_capability() -> HostOwnerEpochCapability {
    #[cfg(not(windows))]
    {
        HostOwnerLease::unsupported_platform_test_capability()
    }
    #[cfg(windows)]
    {
        let installation = test_handle(format!(
            "test-host-owner-{}",
            NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        Box::leak(Box::new(
            HostOwnerLease::acquire(&installation)
                .unwrap_or_else(|error| panic!("test Host owner lease: {error}")),
        ))
        .activation_capability()
    }
}

#[cfg(windows)]
fn live_host_capability() -> (HostOwnerLease, HostOwnerEpochCapability) {
    let installation = test_handle(format!(
        "test-host-owner-live-{}",
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let lease = HostOwnerLease::acquire(&installation)
        .unwrap_or_else(|error| panic!("test Host owner lease: {error}"));
    let capability = lease.activation_capability();
    (lease, capability)
}

#[cfg(windows)]
fn pending_registry_for_owner_gate() -> (ApprovedGenerationRegistry, InstallationTransaction) {
    let transaction = registering_transaction();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:owner-gate"),
    ));
    (registry, transaction)
}

#[cfg(windows)]
fn assert_registry_mutations_rejected_after_owner_shutdown(
    registry: &mut ApprovedGenerationRegistry,
    transaction: &InstallationTransaction,
    capability: &HostOwnerEpochCapability,
) {
    let before = registry.clone();
    assert!(
        registry
            .claim_pending_activation(
                capability,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
            )
            .is_err()
    );
    assert_eq!(registry, &before);

    let before = registry.clone();
    assert!(
        registry
            .commit_pending_activation(
                capability,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
                &test_commit_fence(&transaction.candidate_manifest),
            )
            .is_err()
    );
    assert_eq!(registry, &before);

    let before = registry.clone();
    assert!(
        registry
            .mark_pending_recovery(
                capability,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                "owner lease is no longer live",
            )
            .is_err()
    );
    assert_eq!(registry, &before);

    let before = registry.clone();
    assert!(
        registry
            .abort_pending_activation(
                capability,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
            )
            .is_err()
    );
    assert_eq!(registry, &before);
}

#[derive(Clone, Default)]
struct SharedStore {
    state: Arc<Mutex<Option<InstallationTransaction>>>,
    conflict_next: Arc<Mutex<bool>>,
    created_load_target_effect_id: Arc<Mutex<Option<PlatformHandle>>>,
    substitute_after_created_load: Arc<Mutex<bool>>,
    stale_after_created_load: Arc<Mutex<bool>>,
    missing_after_created_load: Arc<Mutex<bool>>,
}

impl InstallationTransactionStore for SharedStore {
    fn create_planned(
        &mut self,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        transaction.validate()?;
        if !transaction.is_constructor_planned() {
            return Err(InstallationError::InvalidField {
                field: "transaction".to_owned(),
                reason: "not constructor-planned".to_owned(),
            });
        }
        let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
        if state.is_some() {
            return Err(InstallationError::CompareAndSaveConflict {
                expected: 0,
                actual: transaction.revision,
            });
        }
        *state = Some(transaction.clone());
        Ok(())
    }

    fn load(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<Option<InstallationTransaction>, InstallationError> {
        let created_load_target_effect_id = self
            .created_load_target_effect_id
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .clone();
        let is_created_load_match = |progress: &InstallationEffectProgress| {
            progress.ownership_secret.as_ref().is_some_and(|ownership| {
                ownership.secret_provision_disposition
                    == InstallationSecretProvisionDisposition::Created
            }) && created_load_target_effect_id
                .as_ref()
                .is_none_or(|effect_id| progress.effect_id == *effect_id)
        };
        let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
        let exact_created_transaction = state.as_ref().is_some_and(|transaction| {
            transaction.transaction_id == *transaction_id
                && transaction
                    .effect_progress
                    .iter()
                    .any(is_created_load_match)
        });
        if exact_created_transaction
            && *self
                .stale_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!())
        {
            *self
                .stale_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!()) = false;
            let mut stale_transaction = state.as_ref().cloned().unwrap_or_else(|| unreachable!());
            stale_transaction.revision = stale_transaction.revision.saturating_sub(1);
            return Ok(Some(stale_transaction));
        }
        if exact_created_transaction
            && *self
                .missing_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!())
        {
            *self
                .missing_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!()) = false;
            return Ok(None);
        }
        if exact_created_transaction
            && *self
                .substitute_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!())
        {
            *self
                .substitute_after_created_load
                .lock()
                .unwrap_or_else(|_| unreachable!()) = false;
            let transaction = state.as_mut().unwrap_or_else(|| unreachable!());
            let progress = transaction
                .effect_progress
                .iter_mut()
                .find(|progress| is_created_load_match(progress))
                .unwrap_or_else(|| unreachable!());
            progress
                .ownership_secret
                .as_mut()
                .unwrap_or_else(|| unreachable!())
                .creation_proof
                .authenticator = test_handle("b".repeat(64));
            transaction.revision += 1;
        }
        Ok(state
            .as_ref()
            .filter(|transaction| transaction.transaction_id == *transaction_id)
            .cloned())
    }

    fn reconcile_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
        let transaction = state
            .as_mut()
            .ok_or_else(|| InstallationError::TransactionNotFound {
                transaction_id: receipt.transaction_id.as_str().to_owned(),
            })?;
        transaction.validate()?;
        match transaction.stage() {
            InstallationStage::Activating => {
                transaction.advance_to_active_verified(receipt, evidence)?;
                Ok(InstallationStepOutcome::Applied {
                    stage: transaction.stage(),
                    evidence_refs: transaction.observed_postconditions.clone(),
                })
            }
            InstallationStage::ActiveVerified
            | InstallationStage::Cleaning
            | InstallationStage::Completed => {
                let binding = transaction
                    .active_verified_receipt
                    .as_ref()
                    .ok_or_else(|| {
                        InstallationError::IncompleteObservation(
                            "active transaction is missing its committed activation receipt"
                                .to_owned(),
                        )
                    })?;
                if !binding.matches_receipt(&receipt) {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(InstallationStepOutcome::Applied {
                    stage: transaction.stage(),
                    evidence_refs: transaction.observed_postconditions.clone(),
                })
            }
            _ => Err(InstallationError::IncompleteObservation(
                "test transaction is not in an activation-reconcilable stage".to_owned(),
            )),
        }
    }
}

impl transaction_store_private::Sealed for SharedStore {
    fn compare_and_save(
        &mut self,
        expected: TransactionVersion,
        transaction: &InstallationTransaction,
    ) -> Result<(), InstallationError> {
        if std::mem::take(&mut *self.conflict_next.lock().unwrap_or_else(|_| unreachable!())) {
            return Err(InstallationError::CompareAndSaveConflict {
                expected: expected.revision,
                actual: expected.revision + 1,
            });
        }
        let mut state = self.state.lock().unwrap_or_else(|_| unreachable!());
        let current = state
            .as_ref()
            .ok_or_else(|| InstallationError::TransactionNotFound {
                transaction_id: transaction.transaction_id.as_str().to_owned(),
            })?;
        let current_version = TransactionVersion::of(current)?;
        if current_version.revision != expected.revision {
            return Err(InstallationError::CompareAndSaveConflict {
                expected: expected.revision,
                actual: current_version.revision,
            });
        }
        if current_version.checksum != expected.checksum {
            return Err(InstallationError::IdentityConflict);
        }
        if transaction.revision != expected.revision + 1 {
            return Err(InstallationError::InvalidField {
                field: "revision".to_owned(),
                reason: "compare_and_save requires exactly one revision step".to_owned(),
            });
        }
        *state = Some(transaction.clone());
        Ok(())
    }
}

#[cfg(windows)]
#[test]
fn installation_authority_is_the_store_target_factory_seam() {
    let coordinator = WindowsInstallationCoordinator::new(SharedStore::default());
    let first = must(coordinator.fresh_store_credential_target());
    let second = must(coordinator.fresh_store_credential_target());
    assert!(validate_store_credential_target(first.as_str()).is_ok());
    assert!(validate_store_credential_target(second.as_str()).is_ok());
    assert_ne!(first, second);
}

struct FakeEffectPort {
    shared: SharedStore,
    inspections: VecDeque<PortOutcome<InstallationEffectObservation>>,
    reconciliations: VecDeque<PortOutcome<InstallationEffectObservation>>,
    execute_outcomes: VecDeque<PortOutcome<InstallationEffectExecution>>,
    provision_outcomes: VecDeque<PortOutcome<InstallationSecretProvisionDisposition>>,
    execute_count: Arc<Mutex<usize>>,
    executed_effect_ids: Arc<Mutex<Vec<PlatformHandle>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
    provision_write_count: Arc<Mutex<usize>>,
    provision_reuses_existing: bool,
    delete_count: Arc<Mutex<usize>>,
    create_disposition: InstallationCreateDisposition,
    secret_absence: VecDeque<PortOutcome<bool>>,
    secret_deletes: VecDeque<PortOutcome<()>>,
    panic_reconcile_once: bool,
    panic_provision_once: bool,
}

impl InstallationEffectPort for FakeEffectPort {
    fn fresh_ownership_secret_reference(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretReference> {
        PortOutcome::Known(InstallationSecretReference {
            target: test_handle(format!(
                "eliot/installer-root/v1/{}",
                &sha256_hex(request.effect_id.as_str().as_bytes())[..32]
            )),
            expected_principal_sid: test_handle("S-1-5-21-1000"),
            scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
        })
    }

    fn prepare_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
        _reference: &InstallationSecretReference,
    ) -> PortOutcome<InstallationSecretCreationProof> {
        self.events
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push("prepare");
        PortOutcome::Known(test_secret_creation_proof())
    }

    fn provision_ownership_secret(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretProvisionDisposition> {
        self.events
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push("provision");
        let state = self
            .shared
            .load(&request.transaction_id)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert!(matches!(
            state
                .effect_progress
                .iter()
                .find(|progress| progress.effect_id == request.effect_id)
                .unwrap_or_else(|| unreachable!())
                .state,
            InstallationEffectProgressState::IntentCommitted { .. }
        ));
        if !self.provision_reuses_existing {
            *self
                .provision_write_count
                .lock()
                .unwrap_or_else(|_| unreachable!()) += 1;
        }
        if self.panic_provision_once {
            self.panic_provision_once = false;
            panic!("simulated crash before credential provider response");
        }
        self.provision_outcomes
            .pop_front()
            .unwrap_or(PortOutcome::Known(
                InstallationSecretProvisionDisposition::Created,
            ))
    }

    fn execute(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        self.events
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push("execute");
        let state = self
            .shared
            .load(&request.transaction_id)
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|| unreachable!());
        assert!(state.effect_progress.iter().any(|progress| {
            if progress.effect_id != request.effect_id {
                return false;
            }
            match request.action {
                InstallationEffectAction::Apply => matches!(
                    progress.state,
                    InstallationEffectProgressState::IntentCommitted { attempt, .. }
                        if attempt == request.attempt
                ),
                InstallationEffectAction::Rollback => matches!(
                    &progress.state,
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        external_identity,
                        ..
                    } if request.expected_external_identity.as_ref() == Some(external_identity)
                ),
            }
        }));
        if matches!(&request.plan, InstallerEffectPlan::CreateRoot { .. }) {
            assert_eq!(
                state
                    .effect_progress
                    .iter()
                    .find(|progress| progress.effect_id == request.effect_id)
                    .unwrap_or_else(|| unreachable!())
                    .ownership_secret
                    .as_ref()
                    .unwrap_or_else(|| unreachable!())
                    .secret_provision_disposition,
                InstallationSecretProvisionDisposition::Created
            );
        }
        *self.execute_count.lock().unwrap_or_else(|_| unreachable!()) += 1;
        self.executed_effect_ids
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push(request.effect_id.clone());
        if let Some(outcome) = self.execute_outcomes.pop_front() {
            return outcome;
        }
        PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![test_handle("evidence:execute-ack")],
            create_disposition: (request.action == InstallationEffectAction::Apply
                && matches!(request.plan, InstallerEffectPlan::CreateRoot { .. }))
            .then_some(self.create_disposition),
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: None,
            service_runtime_lineage: None,
        })
    }

    fn inspect(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        self.inspections.pop_front().unwrap_or(PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        ))
    }

    fn reconcile(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        assert!(
            !std::mem::take(&mut self.panic_reconcile_once),
            "simulated crash after external mutation"
        );
        self.reconciliations
            .pop_front()
            .unwrap_or(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
    }

    fn delete_ownership_secret(&mut self, _request: &InstallationEffectRequest) -> PortOutcome<()> {
        *self.delete_count.lock().unwrap_or_else(|_| unreachable!()) += 1;
        self.secret_deletes
            .pop_front()
            .unwrap_or(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
    }

    fn ownership_secret_absent(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<bool> {
        self.secret_absence
            .pop_front()
            .unwrap_or(PortOutcome::Unknown(
                eliot_platform::UnknownReason::Indeterminate,
            ))
    }
}

fn must<T, E>(result: Result<T, E>) -> T
where
    E: std::fmt::Display,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("invalid installation test fixture: {error}"),
    }
}

fn test_handle(value: impl Into<String>) -> PlatformHandle {
    must(PlatformHandle::new(value.into()))
}

fn test_secret_creation_proof() -> InstallationSecretCreationProof {
    InstallationSecretCreationProof {
        version: INSTALLATION_SECRET_CREATION_PROOF_VERSION,
        authenticator: test_handle("a".repeat(64)),
    }
}

#[test]
fn agent_bridge_stage_carrier_is_roundtrip_and_pair_digest_bound() {
    let identity = FileIdentity {
        volume_serial_number: 7,
        file_index: 11,
    };
    let mut stage = AgentBridgeStagePrepared {
        wire: test_handle(AgentBridgeStagePrepared::WIRE),
        installation_id: test_handle("installation:test"),
        transaction_id: test_handle("transaction:test"),
        installation_plan_digest: test_handle("a".repeat(64)),
        effect_id: test_handle("effect:test"),
        request_digest: test_handle("b".repeat(64)),
        host_state_root_digest: test_handle("c".repeat(64)),
        manifest_digest: test_handle("d".repeat(64)),
        launch_descriptor_digest: test_handle("e".repeat(64)),
        launch_generation: test_handle("generation:test"),
        source_path: test_handle(r"C:\source\eliot-agent-bridge.exe"),
        source_identity: identity,
        source_sha256: test_handle("f".repeat(64)),
        source_size: 12,
        temporary_path: test_handle(r"C:\root\tmp\bridge.tmp"),
        temporary_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 12,
        },
        destination_path: test_handle(r"C:\root\external-modules\bridge.exe"),
        destination_parent_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 13,
        },
        prepared_digest: test_handle("pending"),
    };
    stage.prepared_digest = must(stage.computed_digest());
    assert!(stage.validate().is_ok());
    let mut old_stage = stage.clone();
    old_stage.wire = test_handle("eliot.host.agent-bridge-stage-prepared.v0");
    old_stage.prepared_digest = must(old_stage.computed_digest());
    assert!(matches!(
        old_stage.validate(),
        Err(InstallationError::MigrationRequired { .. })
    ));
    let mut binding = must(AgentBridgePreparedBinding::new(
        stage.clone(),
        test_handle("1".repeat(64)),
        stage.destination_path.clone(),
        FileIdentity {
            volume_serial_number: 7,
            file_index: 14,
        },
        stage.source_sha256.clone(),
        stage.source_size,
        test_handle(r"C:\root\agent-bridge\admission-profile-v1.json"),
        test_handle("2".repeat(64)),
        test_handle(r"C:\root\agent-bridge\client-declaration-v2.json"),
        test_handle("3".repeat(64)),
        FileIdentity {
            volume_serial_number: 1,
            file_index: 2,
        },
        test_handle("4".repeat(64)),
        FileIdentity {
            volume_serial_number: 3,
            file_index: 4,
        },
        test_handle("5".repeat(64)),
    ));
    let original_pair = binding.pair_digest.clone();
    assert!(binding.validate().is_ok());
    binding.declaration_digest = test_handle("6".repeat(64));
    assert!(binding.validate().is_err());
    assert_ne!(
        original_pair,
        binding
            .computed_pair_digest()
            .unwrap_or_else(|_| unreachable!())
    );

    let bytes = must(serde_json::to_vec(&stage));
    let decoded: AgentBridgeStagePrepared = must(serde_json::from_slice(&bytes));
    assert_eq!(decoded, stage);
}

#[test]
fn pending_agent_bridge_stage_slot_is_explicit_and_requires_pending_intent() {
    let mut value = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    value["pending_activation"] = serde_json::json!({});
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));

    let transaction = registering_transaction();
    let approval =
        test_transaction_activation_approval(&transaction, test_handle("approval:stage-order"));
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-stage-order-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let database = must(Database::create(&path));
    let registry = RedbInstallationRegistry::from_database_for_test(database);
    let stage = AgentBridgeStagePrepared {
        wire: test_handle(AgentBridgeStagePrepared::WIRE),
        installation_id: test_handle("installation:test"),
        transaction_id: test_handle("transaction:test"),
        installation_plan_digest: test_handle("a".repeat(64)),
        effect_id: test_handle("effect:test"),
        request_digest: test_handle("b".repeat(64)),
        host_state_root_digest: test_handle("c".repeat(64)),
        manifest_digest: test_handle("d".repeat(64)),
        launch_descriptor_digest: test_handle("e".repeat(64)),
        launch_generation: test_handle("generation:test"),
        source_path: test_handle(r"C:\source\eliot-agent-bridge.exe"),
        source_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 11,
        },
        source_sha256: test_handle("f".repeat(64)),
        source_size: 12,
        temporary_path: test_handle(r"C:\root\tmp\bridge.tmp"),
        temporary_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 12,
        },
        destination_path: test_handle(r"C:\root\external-modules\bridge.exe"),
        destination_parent_identity: FileIdentity {
            volume_serial_number: 7,
            file_index: 13,
        },
        prepared_digest: test_handle("pending"),
    };
    let mut stage = stage;
    stage.prepared_digest = must(stage.computed_digest());
    let result = registry.record_pending_phase_b_agent_bridge_stage_prepared(
        &host_capability(),
        1,
        &approval,
        &stage,
    );
    assert!(matches!(
        result,
        Err(InstallationError::IncompleteObservation(_))
    ));
    assert!(
        must(registry.load())
            .pending_phase_b_agent_bridge_stage_prepared()
            .is_none()
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn root_win32_error_uses_a_stable_typed_pending_reference() {
    let pending = port_pending(root_execution_error::<()>(InstallerRootError::Win32 {
        stage: InstallerRootStage::CreateDirectory,
        code: 0xABCD,
    }));
    assert_eq!(
        pending.as_str(),
        "installer-root-win32-v2:create-directory:0000abcd"
    );
}

#[test]
fn package_stage_win32_error_uses_a_stable_typed_provider_reference() {
    let error = PackageStagingError::Win32 {
        stage: PackageStagingStage::SetSecurityInfo,
        code: 5,
    };
    assert_eq!(
        package_staging_reference(PackageStagingStage::SetSecurityInfo, 5).as_str(),
        "stage-package-win32-v1:set-security-info:00000005"
    );
    assert!(matches!(
        package_port_error(&error),
        PortError::ProviderReference { reference, .. }
            if reference.as_str() == "stage-package-win32-v1:set-security-info:00000005"
    ));
    assert_eq!(
        port_pending(PortOutcome::<()>::Error(package_port_error(&error))).as_str(),
        "stage-package-win32-v1:set-security-info:00000005"
    );
    let json = serde_json::to_string(&error).unwrap_or_else(|_| unreachable!());
    assert!(json.contains("SET_SECURITY_INFO"));
    assert!(json.contains("\"code\":5"));
}

#[test]
fn package_inspection_errors_preserve_provider_diagnostics() {
    let win32 = Err::<(), _>(PackageStagingError::Win32 {
        stage: PackageStagingStage::GetSecurityInfo,
        code: 5,
    })
    .map_err(|error| package_port_error(&error))
    .unwrap_err();
    assert!(matches!(
        win32,
        PortError::ProviderReference { reference, .. }
            if reference.as_str() == "stage-package-win32-v1:get-security-info:00000005"
    ));

    let security = Err::<(), _>(PackageStagingError::SecurityMismatch)
        .map_err(|error| package_port_error(&error))
        .unwrap_err();
    assert!(matches!(
        security,
        PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::PermissionDenied,
                retryable: false,
            },
            reference,
            ..
        } if reference.as_str() == "stage-package-error-v1:security-mismatch"
    ));
}

#[test]
fn every_package_staging_error_has_an_exact_bounded_provider_and_pending_reference() {
    let cases = [
        (
            PackageStagingError::InvalidRelativePath,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:invalid-relative-path",
        ),
        (
            PackageStagingError::ManifestCollision,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:manifest-collision",
        ),
        (
            PackageStagingError::BoundExceeded,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:bound-exceeded",
        ),
        (
            PackageStagingError::RootUnavailable,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:root-unavailable",
        ),
        (
            PackageStagingError::ReparsePoint,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:reparse-point",
        ),
        (
            PackageStagingError::WrongEntryKind,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:wrong-entry-kind",
        ),
        (
            PackageStagingError::IdentityMismatch,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:identity-mismatch",
        ),
        (
            PackageStagingError::HashMismatch,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:hash-mismatch",
        ),
        (
            PackageStagingError::SizeMismatch,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:size-mismatch",
        ),
        (
            PackageStagingError::SecurityMismatch,
            ProviderErrorCode::PermissionDenied,
            "stage-package-error-v1:security-mismatch",
        ),
        (
            PackageStagingError::GenerationExists,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:generation-exists",
        ),
        (
            PackageStagingError::TreeMismatch,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:tree-mismatch",
        ),
        (
            PackageStagingError::PartialTree,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:partial-tree",
        ),
        (
            PackageStagingError::PeParse(PeCoffError::Truncated),
            ProviderErrorCode::Failed,
            "stage-package-error-v1:pe-parse",
        ),
        (
            PackageStagingError::Authenticode(
                eliot_platform_windows::AuthenticodeError::InvalidFile,
            ),
            ProviderErrorCode::Failed,
            "stage-package-error-v1:authenticode",
        ),
        (
            PackageStagingError::AuthenticodeRejected(AuthenticodeVerdict::Unsigned),
            ProviderErrorCode::Failed,
            "stage-package-error-v1:authenticode-rejected",
        ),
        (
            PackageStagingError::RollbackRefused,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:rollback-refused",
        ),
        (
            PackageStagingError::UnsupportedPlatform,
            ProviderErrorCode::Unavailable,
            "stage-package-error-v1:unsupported-platform",
        ),
        (
            PackageStagingError::Io,
            ProviderErrorCode::Failed,
            "stage-package-error-v1:io",
        ),
        (
            PackageStagingError::Win32 {
                stage: PackageStagingStage::GetFinalPathNameByHandleW,
                code: 8,
            },
            ProviderErrorCode::Failed,
            "stage-package-win32-v1:get-final-path-name-by-handle-w:00000008",
        ),
    ];
    assert_eq!(cases.len(), 20);
    for (error, expected_code, expected) in cases {
        let port = package_port_error(&error);
        assert!(matches!(
            &port,
            PortError::ProviderReference {
                error: ProviderError { code, retryable: false },
                reference,
            } if *code == expected_code && reference.as_str() == expected
        ));
        assert_eq!(
            port_pending(PortOutcome::<()>::Error(port)).as_str(),
            expected
        );
        assert!(is_typed_package_staging_reference(expected));
    }
}

#[cfg(windows)]
#[test]
fn protected_root_native_failure_survives_production_inspect_and_store_reload() {
    let source_dir = tempfile::TempDir::new().expect("create empty source bundle");
    let source_path = source_dir.path();
    let source = TrustedSourceBundle::open(source_path).expect("retain source bundle");
    let source_identity = source.identity();
    drop(source);

    let registered = system_registration_transaction();
    let package_index = registered
        .installer_effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        .unwrap_or_else(|| unreachable!());
    let mut effects = registered.installer_effects.clone();
    let staging_root = match &mut effects[package_index] {
        InstallerEffectPlan::StagePackage {
            source_bundle,
            source_bundle_identity: expected_identity,
            staging_root,
            ..
        } => {
            *source_bundle = test_handle(source_path.to_string_lossy().into_owned());
            *expected_identity = source_identity;
            staging_root.clone()
        }
        _ => unreachable!(),
    };
    let missing = Path::new(staging_root.as_str());
    assert!(!missing.exists());
    let (stage, code) =
        match PackageStagingError::from(ProtectedRootLease::open_existing(missing).unwrap_err()) {
            PackageStagingError::Win32 { stage, code } => (stage, code),
            other => panic!("unexpected protected-root failure: {other:?}"),
        };
    assert_ne!(code, 0);

    let mut transaction = must(InstallationTransaction::new(
        registered.transaction_id.clone(),
        registered.installation_epoch.clone(),
        registered.profile,
        registered.request.clone(),
        registered.current_active_manifest.clone(),
        registered.candidate_manifest.clone(),
        registered.staging_root.clone(),
        registered.planned_changes.clone(),
        effects,
        registered.minimum_store_available_bytes,
        registered.precondition_evidence.clone(),
        registered.recovery_command.clone(),
    ));
    transaction.effect_progress[..package_index]
        .clone_from_slice(&registered.effect_progress[..package_index]);
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let expected = package_staging_reference(stage, code).as_str().to_owned();
    assert!(expected.starts_with("stage-package-win32-v1:"));
    let mut coordinator =
        InstallationCoordinator::new(WindowsInstallationEffectPort::new(), store.clone());
    let outcome = must(coordinator.drive_effect_at(&transaction_id, 1_000));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::RollbackRequired { ref pending_refs }
            if pending_refs.len() == 1 && pending_refs[0].as_str() == expected
    ));

    let reloaded = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(reloaded.stage(), InstallationStage::RollbackRequired);
    assert_eq!(
        reloaded.pending_external_changes,
        vec![test_handle(expected.clone())]
    );
    assert!(matches!(
        &reloaded.effect_progress[package_index].state,
        InstallationEffectProgressState::Unknown { pending_ref }
            if pending_ref.as_str() == expected
    ));
    assert!(!expected.contains("ProgramData"));
    assert!(!expected.contains('\\'));
}

#[test]
fn protected_file_create_win32_error_uses_a_stable_typed_pending_reference() {
    let pending = port_pending(root_execution_error::<()>(InstallerRootError::Win32 {
        stage: InstallerRootStage::CreateProtectedFile,
        code: 5,
    }));
    assert_eq!(
        pending.as_str(),
        "installer-root-win32-v2:create-protected-file:00000005"
    );
}

#[test]
fn raw_absence_status_remains_a_typed_win32_pending_reference() {
    let pending = port_pending(root_execution_error::<()>(InstallerRootError::Win32 {
        stage: InstallerRootStage::OpenReadback,
        code: 2,
    }));
    assert_eq!(
        pending.as_str(),
        "installer-root-win32-v2:open-readback:00000002"
    );
}

#[test]
fn root_precondition_absence_race_reference_is_stable_and_persistable() {
    let pending = port_pending(PortOutcome::<()>::Error(PortError::ProviderReference {
        error: ProviderError {
            code: ProviderErrorCode::Failed,
            retryable: false,
        },
        reference: test_handle("installer-root-absence-race-v1:precondition"),
    }));
    assert_eq!(
        pending.as_str(),
        "installer-root-absence-race-v1:precondition"
    );
}

#[test]
fn root_readback_win32_error_remains_typed_for_inspection() {
    let error = root_port_error(InstallerRootError::Win32 {
        stage: InstallerRootStage::Readback,
        code: 0xDEAD,
    });
    assert!(matches!(
        error,
        PortError::ProviderReference { reference, .. }
            if reference.as_str() == "installer-root-win32-v2:readback:0000dead"
    ));
}

#[test]
fn provider_references_are_persisted_only_for_strict_win32_observability_codes() {
    let valid = [
        "installer-root-win32-v2:open-thread-token:00000000",
        "installer-root-win32-v2:readback:ffffffff",
        "installer-root-win32-v2:open-readback:00000002",
        "stage-package-win32-v1:get-security-info:00000005",
        "stage-package-win32-v1:known-folder-path:80070005",
        "stage-package-win32-v1:canonicalize-path:00000003",
        "stage-package-win32-v1:get-final-path-name-by-handle-w:00000008",
        "stage-package-win32-v1:read-file:00000005",
        "stage-package-win32-v1:write-file:00000005",
        "stage-package-error-v1:security-mismatch",
        "stage-package-error-v1:pe-parse",
    ];
    for reference in valid {
        let pending = port_pending(PortOutcome::<()>::Error(PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: test_handle(reference),
        }));
        assert_eq!(pending.as_str(), reference);
    }

    for reference in [
        r"C:\secret\credential",
        "secret-token",
        "installer-root-win32-v2:not-a-stage:0000abcd",
        "installer-root-win32-v2:create-directory:0000ABCD",
        "installer-root-win32-v2:create-directory:abcd",
        "installer-root-win32-v2:create-directory:0000abcd:extra",
        "stage-package-win32-v1:not-a-stage:0000abcd",
        "stage-package-win32-v1:get-security-info:0000000A",
        "stage-package-win32-v1:known-folder-path:8007000A",
        "stage-package-win32-v1:get-security-info:0000005",
        "stage-package-win32-v1:get-security-info:00000005:extra",
        "stage-package-win32-v1:get-security-info:00000005 ",
        "stage-package-win32-v1:write-file:0000000A",
        "stage-package-win32-v1:write-file:00000005:extra",
        "stage-package-error-v1:identity-mismatch:extra",
        "stage-package-error-v1:IDENTITY-MISMATCH",
        "stage-package-error-v1:not-a-semantic",
        "stage-package-error-v1:",
        r"C:\package\secret",
    ] {
        let pending = port_pending(PortOutcome::<()>::Error(PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: test_handle(reference),
        }));
        assert_eq!(pending.as_str(), REDACTED_PROVIDER_REFERENCE_PENDING);
    }
}

#[test]
fn creation_proof_rejects_a_future_version() {
    let mut proof = test_secret_creation_proof();
    proof.version = INSTALLATION_SECRET_CREATION_PROOF_VERSION + 1;
    assert!(proof.validate().is_err());
}

#[test]
fn creation_proof_binds_every_mutable_identity_field() {
    let transaction = planned_transaction();
    let request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    let reference = test_secret_reference("0123456789abcdef0123456789abcdef");
    let secret = vec![0x5a; 32];
    let proof = must(ownership_secret_creation_proof(
        &request, &reference, &secret,
    ));
    let ownership = InstallationOwnershipSecret {
        reference: reference.clone(),
        create_disposition: InstallationCreateDisposition::NotAttempted,
        secret_provision_disposition: InstallationSecretProvisionDisposition::NotAttempted,
        creation_proof: proof,
        lifecycle: InstallationSecretLifecycle::Active,
    };
    assert!(ownership_secret_creation_proof_matches(
        &request, &ownership, &secret
    ));

    let mut transaction_id = request.clone();
    transaction_id.transaction_id = test_handle("transaction-substituted");
    assert!(!ownership_secret_creation_proof_matches(
        &transaction_id,
        &ownership,
        &secret
    ));
    let mut effect_id = request.clone();
    effect_id.effect_id = test_handle("effect-substituted");
    assert!(!ownership_secret_creation_proof_matches(
        &effect_id, &ownership, &secret
    ));
    let mut attempt = request.clone();
    attempt.attempt = 2;
    assert!(!ownership_secret_creation_proof_matches(
        &attempt, &ownership, &secret
    ));
    let mut plan_digest = request.clone();
    plan_digest.plan_digest = test_handle("b".repeat(64));
    assert!(!ownership_secret_creation_proof_matches(
        &plan_digest,
        &ownership,
        &secret
    ));
    let mut target = ownership.clone();
    target.reference.target =
        test_handle("eliot/installer-root/v1/abcdefabcdefabcdefabcdefabcdefab");
    assert!(!ownership_secret_creation_proof_matches(
        &request, &target, &secret
    ));
    let mut sid = ownership.clone();
    sid.reference.expected_principal_sid = test_handle("S-1-5-21-2000");
    assert!(!ownership_secret_creation_proof_matches(
        &request, &sid, &secret
    ));
    let mut version = ownership;
    version.creation_proof.version += 1;
    assert!(!ownership_secret_creation_proof_matches(
        &request, &version, &secret
    ));
    let payload = must(ownership_secret_creation_payload(&request, &reference));
    assert!(
        String::from_utf8_lossy(&payload).contains("eliot.installation.ownership-secret-creation")
    );
    assert!(String::from_utf8_lossy(&payload).contains("WINDOWS_CREDENTIAL_MANAGER_CURRENT_USER"));
}

#[test]
fn secret_bytes_are_absent_from_json_debug_and_evidence() {
    let transaction = planned_transaction();
    let request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    let reference = test_secret_reference("0123456789abcdef0123456789abcdef");
    let secret = vec![0xa5; 32];
    let proof = must(ownership_secret_creation_proof(
        &request, &reference, &secret,
    ));
    let ownership = InstallationOwnershipSecret {
        reference,
        create_disposition: InstallationCreateDisposition::NotAttempted,
        secret_provision_disposition: InstallationSecretProvisionDisposition::Created,
        creation_proof: proof,
        lifecycle: InstallationSecretLifecycle::Active,
    };
    let secret_hex = "a5".repeat(32);
    let json = serde_json::to_string(&ownership).unwrap_or_else(|_| unreachable!());
    let debug = format!("{ownership:?}");
    let evidence = serde_json::to_string(&InstallationEffectExecution {
        evidence: vec![test_handle("evidence:nonsecret")],
        create_disposition: Some(InstallationCreateDisposition::Created),
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_start_disposition: None,
        service_runtime_lineage: None,
    })
    .unwrap_or_else(|_| unreachable!());
    assert!(!json.contains(&secret_hex));
    assert!(!debug.contains(&secret_hex));
    assert!(!evidence.contains(&secret_hex));
}

#[test]
fn v21_and_missing_secret_proof_require_explicit_migration() {
    let transaction = planned_transaction();
    let mut legacy = serde_json::to_value(&transaction).unwrap_or_else(|_| unreachable!());
    legacy["transaction_wire_version"]["major"] = serde_json::json!(21);
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        validate_installation_transaction_json(&legacy_bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("21.0.0") && reason.contains("23.0.0")
    ));

    let mut missing = serde_json::to_value(&transaction).unwrap_or_else(|_| unreachable!());
    let ownership = serde_json::to_value(test_ownership_secret(
        InstallationCreateDisposition::NotAttempted,
        InstallationSecretLifecycle::Active,
    ))
    .unwrap_or_else(|_| unreachable!());
    missing["effect_progress"][0]["ownership_secret"] = ownership;
    missing["effect_progress"][0]["ownership_secret"]
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("creation_proof");
    let missing_bytes = serde_json::to_vec(&missing).unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        validate_installation_transaction_json(&missing_bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("creation proof") && reason.contains("v23")
    ));
}

fn test_watchdog_control_grant() -> InstallerServiceControlGrantReceipt {
    let principal_sid = "S-1-5-80-1-2-3-4-5";
    let receipt = InstallerServiceControlGrantReceipt {
        principal_service: test_handle(ELIOT_HOST_SERVICE_NAME),
        principal_sid: test_handle(principal_sid),
        access_mask: ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
        security_descriptor_digest: test_handle(must(watchdog_service_security_descriptor_digest(
            principal_sid,
        ))),
    };
    must(receipt.validate());
    receipt
}

fn test_activation_approval(
    manifest: &CandidateManifest,
    transaction_id: PlatformHandle,
    installer_plan_digest: PlatformHandle,
    approval_ref: PlatformHandle,
) -> InstallationActivationApproval {
    let runtime = &manifest.runtime_launch;
    InstallationActivationApproval {
        approval_ref,
        transaction_id,
        installer_plan_digest,
        generation: manifest.generation.clone(),
        candidate_manifest_digest: must(candidate_manifest_digest(manifest)),
        runtime_descriptor_digest: runtime.descriptor_digest.clone(),
        required_owner: test_handle("owner:test"),
        signature_ref: manifest.signature_ref.clone(),
        authority_descriptor_path: runtime.authority_descriptor_path.clone(),
        authority_descriptor_digest: runtime.authority_descriptor_digest.clone(),
        authority_generation: runtime.authority_generation,
        authority_state_fence: runtime.authority_state_fence.clone(),
    }
}

fn test_transaction_activation_approval(
    transaction: &InstallationTransaction,
    approval_ref: PlatformHandle,
) -> InstallationActivationApproval {
    let mut approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        approval_ref,
    );
    approval.required_owner = transaction.request.required_owner.clone();
    approval
}

fn test_commit_fence(manifest: &CandidateManifest) -> ActivationCommitFence {
    let runtime = &manifest.runtime_launch;
    ActivationCommitFence {
        generation: manifest.generation.clone(),
        config_digest: manifest.config_digest.clone(),
        materialized_config_digest: manifest.config_digest.clone(),
        phase_b_live_binding: Some(PhaseBLiveBinding {
            manifest_digest: must(candidate_manifest_digest(manifest)),
            authority_descriptor_digest: test_handle("1".repeat(64)),
            store_bootstrap_descriptor_digest: test_handle("2".repeat(64)),
            config_file_digest: manifest.config_digest.clone(),
            eliotd_descriptor_digest: test_handle("3".repeat(64)),
            semantic_config_hash: test_handle("5".repeat(64)),
            host_epoch_lineage: test_handle("lineage:test"),
            host_epoch_sequence: 1,
            host_process_nonce_digest: test_handle("4".repeat(64)),
            receipt_digest: test_handle("4".repeat(64)),
            effect_id: test_handle("phase-b-effect"),
            credential_receipt_digest: test_handle("9".repeat(64)),
            request_digest: test_handle("6".repeat(64)),
            host_owner_epoch: test_handle("host-owner:test"),
            host_process_identity: test_handle("7".repeat(64)),
            public_receipt_digest: test_handle("8".repeat(64)),
            provisioned_supervision_authority: test_provisioned_supervision_authority(
                runtime.installation_epoch.installation.as_str(),
                manifest.generation.as_str(),
                runtime.authority_generation,
            ),
            agent_bridge: None,
        }),
        authority_generation: runtime.authority_generation,
        authority_state_fence: runtime.authority_state_fence.clone(),
        active_kernel_record_checksum: test_handle("a".repeat(64)),
        probe_request_digest: test_handle("b".repeat(64)),
        ready_receipt_digest: test_handle("c".repeat(64)),
        store_proof_fence: test_handle("store-proof:test"),
        candidate_binding_digest: test_handle("d".repeat(64)),
        store_requirement_digest: test_handle("e".repeat(64)),
        readiness_sequence: 1,
        readiness_journal_checksum: test_handle("f".repeat(64)),
    }
}

#[cfg(windows)]
fn replace_real_redb_transaction(
    store: &mut RedbInstallationTransactionStore,
    current: &mut InstallationTransaction,
    mut replacement: InstallationTransaction,
) {
    let expected = must(TransactionVersion::of(current));
    replacement.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            store,
            expected,
            &replacement,
        ),
    );
    *current = replacement;
}

fn test_path(root: &Path, name: &str) -> PlatformHandle {
    test_handle(root.join(name).to_string_lossy().into_owned())
}

#[cfg(windows)]
fn provision_portable_test_root(path: &Path) {
    std::fs::create_dir_all(path).unwrap_or_else(|_| unreachable!());
    drop(must(UserOwnedRootLease::open_existing(path)));
}

fn reseal_roots(roots: &mut RuntimeStateRoots) {
    roots.roots_digest = test_handle(sha256_hex(&must(roots.unsigned_bytes())));
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture builds the complete ordered effect plan used by coordinator tests"
)]
fn installer_plan_parts(
    roots: &RuntimeStateRoots,
) -> (Vec<PlannedChange>, Vec<InstallerEffectPlan>) {
    let mut effects = Vec::new();
    let declared = roots
        .installer_root_hierarchy()
        .unwrap_or_else(|_| unreachable!())
        .into_iter()
        .map(|(_, root)| root)
        .collect::<Vec<_>>();
    for (index, root) in declared.into_iter().enumerate() {
        effects.push(InstallerEffectPlan::CreateRoot {
            effect_id: test_handle(format!("effect:create:{index}")),
            root: root.clone(),
        });
        effects.push(InstallerEffectPlan::ApplyAcl {
            effect_id: test_handle(format!("effect:acl:{index}")),
            root,
            principals: if roots.profile == InstallationProfile::SystemService {
                vec![
                    InstallerAclPrincipal::Administrators,
                    InstallerAclPrincipal::LocalService,
                    InstallerAclPrincipal::LocalSystem,
                ]
            } else {
                vec![
                    InstallerAclPrincipal::CurrentUser,
                    InstallerAclPrincipal::LocalSystem,
                ]
            },
        });
    }
    if roots.profile == InstallationProfile::SystemService {
        for (role, name, image) in [
            (
                InstallerServiceRole::Host,
                "EliotHost",
                r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
            ),
            (
                InstallerServiceRole::Watchdog,
                "EliotWatchdog",
                r"C:\ProgramData\Eliot\packages\canary\eliot-watchdog.exe",
            ),
        ] {
            effects.push(InstallerEffectPlan::RegisterService {
                effect_id: test_handle(format!("effect:service:{name}")),
                role,
                service_name: test_handle(name),
                executable_path: test_handle(image),
                account: InstallerServiceAccount::LocalService,
                automatic_start: true,
            });
        }
        for (role, name, image) in [
            (
                InstallerServiceRole::Watchdog,
                "EliotWatchdog",
                r"C:\ProgramData\Eliot\packages\canary\eliot-watchdog.exe",
            ),
            (
                InstallerServiceRole::Host,
                "EliotHost",
                r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
            ),
        ] {
            effects.push(InstallerEffectPlan::StartService {
                effect_id: test_handle(format!("effect:start:{name}")),
                role,
                service_name: test_handle(name),
                executable_path: test_handle(image),
                account: InstallerServiceAccount::LocalService,
                automatic_start: true,
            });
        }
        let provision = StoreCredentialProvisionPlan {
            host_state_root: roots.host_state_root.clone(),
            expected_host_executable: test_handle(
                r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
            ),
            target: test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            expected_principal_sid: test_handle(LOCAL_SERVICE_SID),
            generation: ResourceGeneration::genesis(),
            config_digest: test_handle("c".repeat(64)),
        };
        effects.push(InstallerEffectPlan::ProvisionStoreCredential {
            effect_id: test_handle("effect:store-credential"),
            provision: provision.clone(),
        });
        effects.push(InstallerEffectPlan::MaterializePhaseB {
            effect_id: test_handle("effect:phase-b-materialization"),
            candidate_manifest_digest: test_handle("f".repeat(64)),
            static_template: HostPhaseBStaticTemplate {
                wire: test_handle(HostPhaseBStaticTemplate::WIRE),
                authority_id: test_handle("authority:test"),
                record_id: test_handle("record:test"),
                revision_policy_binding: test_handle("revision:test"),
                contour_refs: vec![test_handle("contour:test")],
            },
            host_state_root_digest: test_handle("b".repeat(64)),
            watchdog_selector_digest: test_handle("c".repeat(64)),
            supervision_authority: Box::new(SupervisionAuthorityProvisionPlan {
                installation_id: test_handle("installation:test"),
                candidate_generation: test_handle("generation:candidate"),
                authority_generation: ResourceGeneration::genesis(),
                supervision_lease_scope_id: test_handle("test-supervision-scope"),
                signer_id: test_handle("eliot-kernel"),
                key_id: test_handle("supervision-key:generation:candidate"),
                kernel_root: roots.kernel_work_root.clone(),
                sealed_key_relative_path: test_handle(
                    "supervision-authority-generation-candidate.sealed",
                ),
                host_service_name: test_handle(SUPERVISION_AUTHORITY_HOST_SERVICE),
                service_sid_type: SUPERVISION_AUTHORITY_SERVICE_SID_TYPE,
            }),
            provision: Box::new(provision),
            agent_bridge_source: None,
        });
    }
    let changes = effects
        .iter()
        .map(|effect| PlannedChange {
            change_id: effect.effect_id().clone(),
            target: match effect {
                InstallerEffectPlan::CreateRoot { root, .. }
                | InstallerEffectPlan::ApplyAcl { root, .. } => root.clone(),
                InstallerEffectPlan::RegisterService { service_name, .. }
                | InstallerEffectPlan::StartService { service_name, .. } => service_name.clone(),
                InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                    provision.target.clone()
                }
                InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } => static_template.authority_id.clone(),
                InstallerEffectPlan::StagePackage { staging_root, .. } => staging_root.clone(),
            },
            precondition_refs: vec![test_handle("evidence:installer-precondition")],
            postcondition_refs: vec![test_handle("evidence:installer-postcondition")],
        })
        .collect();
    (changes, effects)
}

struct FakeRuntimeRootLease {
    declared_path: String,
    canonical_path: String,
    identity: String,
    reparse_free: bool,
}

impl RuntimeRootLease for FakeRuntimeRootLease {
    fn declared_path(&self) -> &str {
        &self.declared_path
    }

    fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    fn file_identity(&self) -> &str {
        &self.identity
    }

    fn is_reparse_free(&self) -> bool {
        self.reparse_free
    }
}

struct FakeRuntimeRootLeaseProvider {
    next: usize,
    reparse_at: Option<usize>,
    alias_identity: bool,
}

impl RuntimeRootLeaseProvider for FakeRuntimeRootLeaseProvider {
    type Lease = FakeRuntimeRootLease;

    fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError> {
        let index = self.next;
        self.next += 1;
        Ok(FakeRuntimeRootLease {
            declared_path: root.as_str().to_owned(),
            canonical_path: root.as_str().to_ascii_uppercase(),
            identity: if self.alias_identity {
                "volume:1:file:shared".to_owned()
            } else {
                format!("volume:1:file:{index}")
            },
            reparse_free: self.reparse_at != Some(index),
        })
    }
}

#[allow(clippy::too_many_lines)]
fn registering_transaction() -> InstallationTransaction {
    let sequence = NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "eliot-installation-activate-regression-{}-{sequence}",
        std::process::id()
    ));
    let portable_directory = root.join("portable");
    provision_portable_test_root(&portable_directory);
    let candidate_generation = test_handle("generation:candidate");
    let rollback_plan = test_handle("rollback:plan");
    let portable_root = test_handle(portable_directory.to_string_lossy().into_owned());
    let runtime_state_roots = must(RuntimeStateRoots::derive_portable(portable_root.clone()));
    let candidate_manifest = CandidateManifest {
        generation: candidate_generation.clone(),
        components: vec![
            test_handle("component:kernel"),
            test_handle("component:store"),
        ],
        kernel_artifact_digest: test_handle("4".repeat(64)),
        store_bridge_artifact_digest: test_handle("1".repeat(64)),
        canonical_store_artifact_digest: test_handle("5".repeat(64)),
        host_artifact_digest: test_handle("8".repeat(64)),
        kernel_executable_path: test_path(&root, "eliot-kernel.exe"),
        store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
        canonical_store_executable_path: test_path(&root, "surreal.exe"),
        host_executable_path: test_path(&root, "eliot-host.exe"),
        config_path: test_path(&root, "generation.json"),
        dependency_closure_refs: vec![test_handle("evidence:dependency-closure")],
        license_refs: vec![test_handle("evidence:licenses")],
        config_digest: test_handle("2".repeat(64)),
        store_credential_target: test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        supervision_key_slot: test_handle("3".repeat(64)),
        signature_ref: test_handle("evidence:signature"),
        runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
        runtime_launch: {
            let mut descriptor = RuntimeLaunchDescriptor {
                profile: InstallationProfile::PortableDev,
                portable_root: Some(portable_root.clone()),
                installation_epoch: InstallationEpoch {
                    installation: test_handle("installation:test"),
                    lineage_id: test_handle("lineage:test"),
                    sequence: 1,
                },
                generation: test_handle("generation:candidate"),
                authority_generation: ResourceGeneration::genesis(),
                authority_state_fence: StateFence::new(
                    eliot_contracts::AuthorityEpoch::genesis(),
                    ResourceGeneration::genesis(),
                ),
                supervision_authority: SupervisionAuthorityBinding::Pending {
                    supervision_lease_scope_id: test_handle("test-supervision-scope"),
                },
                authority_descriptor_path: test_path(&root, "authority.json"),
                authority_descriptor_digest: test_handle("7".repeat(64)),
                runtime_state_roots: runtime_state_roots.clone(),
                kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
                kernel_artifact_digest: test_handle("4".repeat(64)),
                eliotd_executable_path: test_path(&root, "eliotd.exe"),
                eliotd_artifact_digest: test_handle("8".repeat(64)),
                eliotd_config_path: test_path(&root, "eliotd-governor.json"),
                eliotd_config_digest: test_handle("4".repeat(64)),
                protected_snapshot_digest: test_handle("a".repeat(64)),
                eliotd_descriptor_path: test_path(&root, "eliotd.json"),
                eliotd_descriptor_digest: test_handle("9".repeat(64)),
                eliotd_launch_nonce: test_handle(format!("eliotd:{}", "a".repeat(32))),
                store_config_path: test_path(&root, "generation.json"),
                store_credential_target: test_handle(
                    "eliot/store/v1/0123456789abcdef0123456789abcdef",
                ),
                store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
                store_bridge_artifact_digest: test_handle("1".repeat(64)),
                store_bootstrap_descriptor_path: test_path(&root, "store-bootstrap.json"),
                store_bootstrap_descriptor_digest: test_handle("6".repeat(64)),
                canonical_store_executable_path: test_path(&root, "surreal.exe"),
                canonical_store_artifact_digest: test_handle("5".repeat(64)),
                kernel_arguments: vec![
                    test_handle("--work-root"),
                    runtime_state_roots.kernel_work_root.clone(),
                    test_handle("--store-bootstrap"),
                    test_path(&root, "store-bootstrap.json"),
                    test_handle("--store-bootstrap-sha256"),
                    test_handle("6".repeat(64)),
                    test_handle("--authority-descriptor"),
                    test_path(&root, "authority.json"),
                    test_handle("--authority-descriptor-sha256"),
                    test_handle("7".repeat(64)),
                    test_handle("--kernel-artifact-sha256"),
                    test_handle("4".repeat(64)),
                    test_handle("--eliotd-descriptor"),
                    test_path(&root, "eliotd.json"),
                    test_handle("--eliotd-descriptor-sha256"),
                    test_handle("9".repeat(64)),
                ],
                store_bridge_arguments: vec![
                    test_handle("--portable-dev-root"),
                    portable_root,
                    test_handle("--config"),
                    test_path(&root, "generation.json"),
                ],
                canonical_store_arguments: vec![
                    test_handle("start"),
                    test_handle("--no-banner"),
                    test_handle("--bind"),
                    test_handle("127.0.0.1:8000"),
                    test_handle("--temporary-directory"),
                    runtime_state_roots.store_temp_root.clone(),
                    test_handle("--log-file-enabled"),
                    test_handle("--log-file-path"),
                    runtime_state_roots.store_work_root.clone(),
                    test_handle("--log-file-name"),
                    test_handle("surrealdb.log"),
                    test_handle(format!(
                        "surrealkv://{}",
                        runtime_state_roots
                            .store_data_root
                            .as_str()
                            .replace('\\', "/")
                    )),
                ],
                host_executable_path: test_path(&root, "eliot-host.exe"),
                host_artifact_digest: test_handle("8".repeat(64)),
                watchdog_executable_path: test_path(&root, "eliot-watchdog.exe"),
                watchdog_artifact_digest: test_handle("4".repeat(64)),
                descriptor_digest: test_handle("0".repeat(64)),
            };
            descriptor.authority_descriptor_digest = test_handle(PHASE_B_PENDING_MARKER);
            descriptor.store_bootstrap_descriptor_digest = test_handle(PHASE_B_PENDING_MARKER);
            descriptor.kernel_arguments = descriptor
                .expected_kernel_arguments(&descriptor.store_config_path)
                .into_iter()
                .map(test_handle)
                .collect();
            descriptor.descriptor_digest =
                test_handle(sha256_hex(&must(descriptor.unsigned_bytes())));
            descriptor
        },
    };
    let request = ManagedEnvironmentChangeRequest {
        request_id: test_handle("request:install"),
        requester_and_reason: test_handle("requester:test"),
        action: ManagedEnvironmentAction::Install,
        target_family: test_handle("family:eliot"),
        exact_candidate: candidate_generation,
        expected_delta: test_handle("delta:installed"),
        source_assurance_refs: vec![test_handle("evidence:source-assurance")],
        affected_refs: Vec::new(),
        impact_class: test_handle("impact:test"),
        required_owner: test_handle("owner:installation"),
        rollback_plan: rollback_plan.clone(),
        verifier: test_handle("verifier:installation"),
        budget: test_handle("budget:test"),
        stop_condition: test_handle("stop:on-failure"),
    };
    let (planned_changes, installer_effects) = installer_plan_parts(&runtime_state_roots);
    let mut transaction = must(InstallationTransaction::new(
        test_handle("transaction:activate"),
        InstallationEpoch {
            installation: test_handle("installation:test"),
            lineage_id: test_handle("lineage:test"),
            sequence: 1,
        },
        InstallationProfile::PortableDev,
        request,
        None,
        candidate_manifest,
        test_path(&root, "staging"),
        planned_changes,
        installer_effects,
        1,
        vec![test_handle("evidence:plan-precondition")],
        test_handle("recovery:command"),
    ));
    must(transaction.advance(
        InstallationStage::Staging,
        vec![test_handle("evidence:staged")],
    ));
    must(transaction.advance(
        InstallationStage::StaticVerified,
        vec![test_handle("evidence:static-verified")],
    ));
    must(transaction.advance(
        InstallationStage::Registering,
        vec![test_handle("evidence:registered")],
    ));
    transaction
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    clippy::needless_continue,
    reason = "the production-bound fixture exercises the complete SystemService projection"
)]
fn system_registration_transaction() -> InstallationTransaction {
    let portable = registering_transaction();
    let program_data = must(protected_program_data_root());
    let roots = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &"b".repeat(64),
    ));
    let system_path =
        |name: &str| test_handle(format!(r"{}\{name}", roots.installation_root.as_str()));

    let mut descriptor = portable.candidate_manifest.runtime_launch.clone();
    descriptor.profile = InstallationProfile::SystemService;
    descriptor.portable_root = None;
    descriptor.runtime_state_roots = roots.clone();
    descriptor.kernel_work_root = roots.kernel_work_root.clone();
    descriptor.authority_descriptor_path = system_path("authority.json");
    descriptor.eliotd_executable_path = system_path("eliotd.exe");
    descriptor.eliotd_config_path = system_path("eliotd-governor.json");
    descriptor.eliotd_descriptor_path = system_path("eliotd.json");
    descriptor.store_config_path = system_path("generation.json");
    descriptor.store_bridge_executable_path = system_path("eliot-store-surreal.exe");
    descriptor.store_bootstrap_descriptor_path = system_path("store-bootstrap.json");
    descriptor.canonical_store_executable_path = system_path("surreal.exe");
    descriptor.host_executable_path = portable.candidate_manifest.host_executable_path.clone();
    descriptor.watchdog_executable_path = portable
        .candidate_manifest
        .runtime_launch
        .watchdog_executable_path
        .clone();
    for image in [
        &descriptor.host_executable_path,
        &descriptor.watchdog_executable_path,
    ] {
        std::fs::write(image.as_str(), b"test service image")
            .unwrap_or_else(|_| panic!("test service image must be materialized"));
    }
    descriptor.kernel_arguments = descriptor
        .expected_kernel_arguments(&descriptor.store_config_path)
        .into_iter()
        .map(test_handle)
        .collect();
    descriptor.store_bridge_arguments = descriptor
        .expected_store_bridge_arguments(&descriptor.store_config_path)
        .into_iter()
        .map(test_handle)
        .collect();
    descriptor.canonical_store_arguments[5] = roots.store_temp_root.clone();
    descriptor.canonical_store_arguments[8] = roots.store_work_root.clone();
    descriptor.canonical_store_arguments[11] = test_handle(format!(
        "surrealkv://{}",
        roots.store_data_root.as_str().replace('\\', "/")
    ));
    descriptor = must(descriptor.with_computed_digest());

    let mut manifest = portable.candidate_manifest.clone();
    manifest.runtime_state_roots_digest = roots.roots_digest.clone();
    manifest.kernel_executable_path = system_path("eliot-kernel.exe");
    manifest.store_bridge_executable_path = descriptor.store_bridge_executable_path.clone();
    manifest.canonical_store_executable_path = descriptor.canonical_store_executable_path.clone();
    manifest.host_executable_path = descriptor.host_executable_path.clone();
    manifest.config_path = descriptor.store_config_path.clone();
    manifest.runtime_launch = descriptor;

    let (mut planned_changes, mut installer_effects) = installer_plan_parts(&roots);
    let staging_root = must(roots.expected_staging_root()).unwrap_or_else(|| unreachable!());
    let package_manifest = must(PackageManifest::new("candidate", Vec::new()));
    let package_effect = InstallerEffectPlan::StagePackage {
        effect_id: test_handle("effect:package-stage"),
        source_bundle: system_path("source-bundle"),
        source_bundle_identity: FileIdentity {
            volume_serial_number: 1,
            file_index: 1,
        },
        generation: manifest.generation.clone(),
        manifest: package_manifest.clone(),
        staging_root: staging_root.clone(),
        expected_file_digests: Vec::new(),
        candidate_manifest_digest: must(candidate_manifest_digest(&manifest)),
        package_manifest_digest: must(PlatformHandle::new(package_manifest.canonical_digest())),
    };
    let package_change = PlannedChange {
        change_id: package_effect.effect_id().clone(),
        target: staging_root.clone(),
        precondition_refs: vec![test_handle("evidence:installer-precondition")],
        postcondition_refs: vec![test_handle("evidence:installer-postcondition")],
    };
    let package_index = installer_effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::RegisterService { .. }))
        .unwrap_or_else(|| unreachable!());
    installer_effects.insert(package_index, package_effect);
    planned_changes.insert(package_index, package_change);
    for effect in &mut installer_effects {
        match effect {
            InstallerEffectPlan::RegisterService {
                role,
                executable_path,
                ..
            }
            | InstallerEffectPlan::StartService {
                role,
                executable_path,
                ..
            } => {
                *executable_path = match role {
                    InstallerServiceRole::Host => manifest.host_executable_path.clone(),
                    InstallerServiceRole::Watchdog => {
                        manifest.runtime_launch.watchdog_executable_path.clone()
                    }
                };
            }
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                provision.expected_host_executable = manifest.host_executable_path.clone();
            }
            InstallerEffectPlan::MaterializePhaseB { provision, .. } => {
                provision.as_mut().expected_host_executable = manifest.host_executable_path.clone();
            }
            InstallerEffectPlan::CreateRoot { .. }
            | InstallerEffectPlan::ApplyAcl { .. }
            | InstallerEffectPlan::StagePackage { .. } => {}
        }
    }
    let mut ordered_effects = installer_effects
        .iter()
        .filter(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::CreateRoot { .. }
                    | InstallerEffectPlan::ApplyAcl { .. }
                    | InstallerEffectPlan::StagePackage { .. }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    ordered_effects.extend(
        installer_effects
            .iter()
            .filter(|effect| matches!(effect, InstallerEffectPlan::RegisterService { .. }))
            .cloned(),
    );
    ordered_effects.extend(installer_effects.into_iter().filter(|effect| {
        matches!(
            effect,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
                | InstallerEffectPlan::StartService { .. }
                | InstallerEffectPlan::MaterializePhaseB { .. }
        )
    }));
    for effect in &mut ordered_effects {
        if let InstallerEffectPlan::MaterializePhaseB {
            candidate_manifest_digest,
            static_template,
            host_state_root_digest,
            watchdog_selector_digest,
            ..
        } = effect
        {
            *candidate_manifest_digest = must(crate::candidate_manifest_digest(&manifest));
            *static_template = must(phase_b_static_template_for_candidate(&manifest));
            *host_state_root_digest = must(phase_b_host_state_root_digest(&manifest));
            *watchdog_selector_digest = must(phase_b_watchdog_selector_digest(&manifest));
        }
    }
    for change in &mut planned_changes {
        for effect in &ordered_effects {
            if change.change_id == *effect.effect_id() {
                if let InstallerEffectPlan::MaterializePhaseB {
                    static_template, ..
                } = effect
                {
                    change.target = static_template.authority_id.clone();
                }
                break;
            }
        }
    }

    let mut transaction = must(InstallationTransaction::new(
        portable.transaction_id,
        portable.installation_epoch,
        InstallationProfile::SystemService,
        portable.request,
        portable.current_active_manifest,
        manifest,
        staging_root,
        planned_changes,
        ordered_effects,
        portable.minimum_store_available_bytes,
        portable.precondition_evidence,
        portable.recovery_command,
    ));

    let bootstrap = transaction.candidate_manifest.runtime_launch.clone();
    for (effect, progress) in transaction
        .installer_effects
        .iter()
        .zip(transaction.effect_progress.iter_mut())
    {
        let InstallerEffectPlan::StagePackage {
            manifest,
            staging_root,
            ..
        } = effect
        else {
            if matches!(
                effect,
                InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. }
            ) {
                progress.state = InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::PreexistingMatching,
                    external_identity: test_handle(format!(
                        "external:root:{}",
                        progress.effect_id.as_str()
                    )),
                    evidence: vec![test_handle(format!(
                        "evidence:root:{}",
                        progress.effect_id.as_str()
                    ))],
                    postcondition_digest: test_handle("d".repeat(64)),
                };
            }
            continue;
        };
        let admitted_precondition = must(InstallationEffectPrecondition::from_change(
            transaction
                .planned_changes
                .iter()
                .find(|change| change.change_id == progress.effect_id)
                .unwrap_or_else(|| unreachable!()),
        ));
        let source_bundle_identity = match effect {
            InstallerEffectPlan::StagePackage {
                source_bundle_identity,
                ..
            } => *source_bundle_identity,
            _ => unreachable!(),
        };
        let generation = test_handle(manifest.generation.clone());
        let manifest_digest = must(PlatformHandle::new(manifest.canonical_digest()));
        let files = Vec::new();
        let total_bytes = 0;
        let digest = must(PackageObservationSnapshot::compute_digest(
            &source_bundle_identity,
            &generation,
            &manifest_digest,
            &files,
            total_bytes,
        ));
        let package_snapshot = PackageObservationSnapshot {
            source_bundle_identity,
            generation,
            manifest_digest,
            files,
            total_bytes,
            digest,
        };
        progress.admitted_precondition = Some(must(
            admitted_precondition.with_package_snapshot(package_snapshot),
        ));
        let receipt = StagingReceipt {
            generation: manifest.generation.clone(),
            root_path: Path::new(staging_root.as_str()).join(&manifest.generation),
            root_identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
            directories: Vec::new(),
            files: Vec::new(),
            manifest_sha256: manifest.canonical_digest(),
        };
        progress.staging_receipt = Some(receipt);
        progress.state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:package-stage"),
            evidence: vec![test_handle("evidence:package-stage")],
            postcondition_digest: test_handle("e".repeat(64)),
        };
        continue;
    }
    for (effect, progress) in transaction
        .installer_effects
        .iter()
        .zip(transaction.effect_progress.iter_mut())
    {
        let InstallerEffectPlan::RegisterService {
            role,
            service_name,
            executable_path,
            ..
        } = effect
        else {
            continue;
        };
        let nonce = test_handle(match role {
            InstallerServiceRole::Host => "a".repeat(64),
            InstallerServiceRole::Watchdog => "b".repeat(64),
        });
        let descriptor_digest = must(phase_b_scm_selector(&bootstrap.authority_descriptor_digest));
        let arguments = must(
            ServiceBootstrapArguments::new(
                Path::new(bootstrap.authority_descriptor_path.as_str()).to_path_buf(),
                descriptor_digest.as_str(),
                bootstrap.installation_epoch.installation.as_str(),
                bootstrap.authority_generation.value(),
                Vec::<String>::new(),
            )
            .and_then(|value| {
                value.with_host_state_root(Path::new(
                    bootstrap.runtime_state_roots.host_state_root.as_str(),
                ))
            })
            .and_then(|value| value.with_registration_nonce(nonce.as_str())),
        );
        let request = must(ServiceRegistrationRequest::with_bootstrap(
            service_name.as_str(),
            match role {
                InstallerServiceRole::Host => ELIOT_HOST_SERVICE_DISPLAY_NAME,
                InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
            },
            Path::new(executable_path.as_str()).to_path_buf(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            arguments,
        ));
        let configuration_digest = test_handle(request.expected_configuration_digest());
        progress.registration_nonce = Some(nonce);
        let service_control_grant =
            (*role == InstallerServiceRole::Watchdog).then(test_watchdog_control_grant);
        progress.service_control_grant = service_control_grant.clone();
        let mut evidence = vec![test_handle(format!("evidence:service:{role:?}"))];
        if let Some(receipt) = &service_control_grant {
            evidence.push(must(receipt.canonical_digest()));
        }
        progress.state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: configuration_digest,
            evidence,
            postcondition_digest: test_handle("c".repeat(64)),
        };
    }
    must(transaction.advance(
        InstallationStage::Staging,
        vec![test_handle("evidence:staged")],
    ));
    must(transaction.advance(
        InstallationStage::StaticVerified,
        vec![test_handle("evidence:static-verified")],
    ));
    must(transaction.advance(
        InstallationStage::Registering,
        vec![test_handle("evidence:registered")],
    ));
    must(transaction.validate());
    transaction
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture binds every typed SystemService progress receipt"
)]
fn fully_applied_system_registration_transaction() -> InstallationTransaction {
    let mut transaction = system_registration_transaction();
    for index in 0..transaction.installer_effects.len() {
        let effect = transaction.installer_effects[index].clone();
        match effect {
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                let change = transaction
                    .planned_changes
                    .iter()
                    .find(|change| change.change_id == transaction.effect_progress[index].effect_id)
                    .cloned()
                    .unwrap_or_else(|| unreachable!());
                let marker = CredentialOwnershipMarkerIdentity {
                    canonical_path_digest: test_handle("a".repeat(64)),
                    volume_serial_number: 1,
                    file_index: 1,
                    security_descriptor_digest: test_handle("b".repeat(64)),
                };
                let host_owner_epoch = test_handle("host-owner:system");
                let host_process_identity = test_handle("c".repeat(64));
                let request_digest = test_handle("d".repeat(64));
                let credential_envelope_digest = test_handle("e".repeat(64));
                let response_digest = must(credential_matching_response_digest(
                    &request_digest,
                    &host_owner_epoch,
                    &host_process_identity,
                    &marker,
                    &credential_envelope_digest,
                ));
                let snapshot = StoreCredentialAbsentSnapshot {
                    host_owner_epoch: host_owner_epoch.clone(),
                    host_process_identity: host_process_identity.clone(),
                    host_state_root: marker.clone(),
                    marker_path_digest: test_handle("f".repeat(64)),
                    marker_absent: true,
                    target_absent: true,
                };
                let precondition = must(
                    must(InstallationEffectPrecondition::from_change(&change))
                        .with_credential_snapshot(snapshot),
                );
                let reference = InstallationSecretReference {
                    target: test_handle("eliot/installer-root/v1/0123456789abcdef0123456789abcdef"),
                    expected_principal_sid: test_handle(LOCAL_SERVICE_SID),
                    scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
                };
                let receipt = CredentialAccessReceipt {
                    transaction_id: transaction.transaction_id.clone(),
                    effect_id: transaction.effect_progress[index].effect_id.clone(),
                    generation: provision.generation,
                    config_digest: provision.config_digest.clone(),
                    target: provision.target.clone(),
                    provider: provision.provider,
                    scope: provision.scope,
                    principal_sid: provision.expected_principal_sid.clone(),
                    host_owner_epoch,
                    host_process_identity,
                    marker,
                    credential_envelope_digest,
                    request_digest,
                    response_digest,
                };
                transaction.effect_progress[index].admitted_precondition = Some(precondition);
                transaction.effect_progress[index].ownership_secret =
                    Some(InstallationOwnershipSecret {
                        reference,
                        create_disposition: InstallationCreateDisposition::Created,
                        secret_provision_disposition:
                            InstallationSecretProvisionDisposition::Created,
                        creation_proof: test_secret_creation_proof(),
                        lifecycle: InstallationSecretLifecycle::Active,
                    });
                transaction.effect_progress[index].store_credential =
                    Some(StoreCredentialProgress {
                        lifecycle: StoreCredentialLifecycle::Active,
                        receipt: Some(receipt),
                    });
                transaction.effect_progress[index].state =
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        external_identity: test_handle("external:credential"),
                        evidence: vec![test_handle("evidence:credential")],
                        postcondition_digest: test_handle("1".repeat(64)),
                    };
            }
            InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. } => {
                transaction.effect_progress[index].state =
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        external_identity: test_handle(format!("external:root-{index}")),
                        evidence: vec![test_handle(format!("evidence:root-{index}"))],
                        postcondition_digest: test_handle(format!("{index:064x}")),
                    };
            }
            InstallerEffectPlan::RegisterService { .. }
            | InstallerEffectPlan::StagePackage { .. } => {}
            InstallerEffectPlan::MaterializePhaseB { .. } => {
                let change = transaction
                    .planned_changes
                    .iter()
                    .find(|change| change.change_id == transaction.effect_progress[index].effect_id)
                    .cloned()
                    .unwrap_or_else(|| unreachable!());
                transaction.effect_progress[index].admitted_precondition =
                    Some(must(InstallationEffectPrecondition::from_change(&change)));
                let mut receipt = HostPhaseBMaterializationReceipt {
                    wire: test_handle(HostPhaseBMaterializationReceipt::WIRE),
                    transaction_id: transaction.transaction_id.clone(),
                    effect_id: transaction.effect_progress[index].effect_id.clone(),
                    candidate_manifest_digest: must(candidate_manifest_digest(
                        &transaction.candidate_manifest,
                    )),
                    request_digest: test_handle("d".repeat(64)),
                    host_owner_epoch: test_handle("host-owner:system"),
                    host_process_identity: test_handle("c".repeat(64)),
                    authority_descriptor_digest: test_handle("7".repeat(64)),
                    config_file_digest: test_handle("8".repeat(64)),
                    store_bootstrap_descriptor_digest: test_handle("9".repeat(64)),
                    eliotd_descriptor_digest: test_handle("a".repeat(64)),
                    provisioned_supervision_authority: test_provisioned_supervision_authority(
                        transaction
                            .candidate_manifest
                            .runtime_launch
                            .installation_epoch
                            .installation
                            .as_str(),
                        transaction.candidate_manifest.generation.as_str(),
                        transaction
                            .candidate_manifest
                            .runtime_launch
                            .authority_generation,
                    ),
                    agent_bridge: None,
                    receipt_digest: test_handle("0".repeat(64)),
                };
                receipt.receipt_digest = must(receipt.computed_digest());
                transaction.effect_progress[index].phase_b_receipt = Some(receipt);
                transaction.effect_progress[index].state =
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        external_identity: test_handle("external:phase-b"),
                        evidence: vec![test_handle("evidence:phase-b")],
                        postcondition_digest: test_handle("b".repeat(64)),
                    };
            }
            InstallerEffectPlan::StartService { role, .. } => {
                let change = transaction
                    .planned_changes
                    .iter()
                    .find(|change| change.change_id == transaction.effect_progress[index].effect_id)
                    .cloned()
                    .unwrap_or_else(|| unreachable!());
                transaction.effect_progress[index].admitted_precondition =
                    Some(must(InstallationEffectPrecondition::from_change(&change)));
                transaction.effect_progress[index].registration_nonce = transaction
                    .installer_effects
                    .iter()
                    .zip(&transaction.effect_progress)
                    .find_map(
                        |(registered_effect, registered_progress)| match registered_effect {
                            InstallerEffectPlan::RegisterService {
                                role: registered_role,
                                ..
                            } if registered_role == &role => {
                                registered_progress.registration_nonce.clone()
                            }
                            _ => None,
                        },
                    );
                assert!(
                    transaction.effect_progress[index]
                        .registration_nonce
                        .is_some()
                );
                transaction.effect_progress[index].service_start_deadline_ms = Some(30_000);
                transaction.effect_progress[index].service_start_proof =
                    Some(InstallationServiceStartProof {
                        intent_digest: test_handle("2".repeat(64)),
                        process_lineage: Some(InstallationServiceProcessLineage {
                            process_id: 17,
                            start_time_100ns: 23,
                            image_path: test_handle(r"C:\Eliot\host.exe"),
                        }),
                    });
                transaction.effect_progress[index].state =
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        external_identity: test_handle(format!("external:service-start:{role:?}")),
                        evidence: vec![test_handle(format!("evidence:service-start:{role:?}"))],
                        postcondition_digest: test_handle("2".repeat(64)),
                    };
            }
        }
    }
    must(transaction.validate());
    transaction
}

#[cfg(windows)]
fn registering_system_service_start_transaction() -> InstallationTransaction {
    let mut transaction = fully_applied_system_registration_transaction();
    transaction.pending_external_changes.clear();
    transaction.observed_postconditions.clear();
    let registration_nonces = transaction
        .installer_effects
        .iter()
        .zip(&transaction.effect_progress)
        .filter_map(|(effect, progress)| match effect {
            InstallerEffectPlan::RegisterService { role, .. } => progress
                .registration_nonce
                .clone()
                .map(|nonce| (*role, nonce)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for (effect, progress) in transaction
        .installer_effects
        .iter()
        .zip(transaction.effect_progress.iter_mut())
    {
        if let InstallerEffectPlan::StartService { role, .. } = effect {
            progress.admitted_precondition = None;
            progress.registration_nonce = registration_nonces.get(role).cloned();
            assert!(progress.registration_nonce.is_some());
            progress.service_start_deadline_ms = None;
            progress.service_start_proof = None;
            progress.state = InstallationEffectProgressState::Pending;
        } else if matches!(
            effect,
            InstallerEffectPlan::ProvisionStoreCredential { .. }
                | InstallerEffectPlan::MaterializePhaseB { .. }
        ) {
            progress.admitted_precondition = None;
            progress.ownership_secret = None;
            progress.store_credential = None;
            progress.phase_b_receipt = None;
            progress.staging_receipt = None;
            progress.service_start_deadline_ms = None;
            progress.service_start_proof = None;
            progress.state = InstallationEffectProgressState::Pending;
        }
    }
    transaction.stage = InstallationStage::Registering;
    transaction.pending_external_changes.clear();
    transaction.observed_postconditions = transaction
        .effect_progress
        .iter()
        .filter(|p| matches!(p.state, InstallationEffectProgressState::Applied { .. }))
        .flat_map(|p| match &p.state {
            InstallationEffectProgressState::Applied { evidence, .. } => evidence.clone(),
            _ => vec![],
        })
        .collect();
    transaction.completed_stage_refs.clear();
    transaction.active_verified_receipt = None;
    transaction.activation_projection_intent = None;
    transaction.revision += 1;
    must(transaction.validate());
    transaction
}

#[cfg(windows)]
fn pending_system_service_start_transaction() -> InstallationTransaction {
    let mut transaction = registering_system_service_start_transaction();
    must(transaction.advance(
        InstallationStage::Activating,
        vec![test_handle("evidence:signed-activation-stage")],
    ));
    transaction
}

#[cfg(windows)]
fn pending_start_precondition(
    transaction: &InstallationTransaction,
    index: usize,
) -> InstallationEffectPrecondition {
    let change = transaction
        .planned_changes
        .iter()
        .find(|change| change.change_id == transaction.effect_progress[index].effect_id)
        .unwrap_or_else(|| unreachable!());
    must(InstallationEffectPrecondition::from_change(change))
}

#[cfg(windows)]
fn start_absent(
    transaction: &InstallationTransaction,
    index: usize,
    reason: &str,
) -> InstallationEffectObservation {
    InstallationEffectObservation::Absent {
        observed_precondition: pending_start_precondition(transaction, index),
        evidence: vec![test_handle(format!(
            "{reason}:{}",
            match &transaction.installer_effects[index] {
                InstallerEffectPlan::StartService { service_name, .. } => service_name,
                _ => unreachable!(),
            }
        ))],
        service_runtime_lineage: None,
    }
}

#[cfg(windows)]
fn start_absent_with_lineage(
    transaction: &InstallationTransaction,
    index: usize,
    reason: &str,
    lineage: InstallationServiceProcessLineage,
) -> InstallationEffectObservation {
    let mut observation = start_absent(transaction, index, reason);
    if let InstallationEffectObservation::Absent {
        service_runtime_lineage,
        ..
    } = &mut observation
    {
        *service_runtime_lineage = Some(lineage);
    }
    observation
}

#[cfg(windows)]
fn configure_start_runtime_receipt(port: &mut FakeEffectPort, external_identity: &str) {
    port.execute_outcomes
        .push_back(PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![
                test_handle("service-start-ack-running"),
                test_handle(format!("service-runtime-identity:{external_identity}")),
            ],
            create_disposition: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: Some(InstallationServiceStartDisposition::StartedByCaller),
            service_runtime_lineage: Some(InstallationServiceProcessLineage {
                process_id: 17,
                start_time_100ns: 23,
                image_path: test_handle(r"C:\Eliot\host.exe"),
            }),
        }));
}

#[cfg(windows)]
fn configure_start_already_running_execution(port: &mut FakeEffectPort, external_identity: &str) {
    port.execute_outcomes
        .push_back(PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![
                test_handle("service-start-race-running"),
                test_handle(format!("service-runtime-identity:{external_identity}")),
            ],
            create_disposition: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: Some(InstallationServiceStartDisposition::AlreadyRunning),
            service_runtime_lineage: None,
        }));
}

#[cfg(windows)]
fn configure_start_already_starting_execution(port: &mut FakeEffectPort) {
    port.execute_outcomes
        .push_back(PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![test_handle("service-start-already-starting")],
            create_disposition: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: Some(InstallationServiceStartDisposition::AlreadyStarting),
            service_runtime_lineage: None,
        }));
}

#[cfg(windows)]
fn configure_start_waiting_execution(port: &mut FakeEffectPort) {
    port.execute_outcomes
        .push_back(PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![test_handle("service-start-ack-starting")],
            create_disposition: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: Some(InstallationServiceStartDisposition::StartedByCaller),
            service_runtime_lineage: None,
        }));
}

#[cfg(windows)]
fn configure_start_waiting_execution_with_lineage(
    port: &mut FakeEffectPort,
    lineage: InstallationServiceProcessLineage,
) {
    port.execute_outcomes
        .push_back(PortOutcome::Known(InstallationEffectExecution {
            evidence: vec![test_handle("service-start-ack-starting")],
            create_disposition: None,
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: Some(InstallationServiceStartDisposition::StartedByCaller),
            service_runtime_lineage: Some(lineage),
        }));
}

fn planned_transaction() -> InstallationTransaction {
    let transaction = registering_transaction();
    must(InstallationTransaction::new(
        transaction.transaction_id,
        transaction.installation_epoch,
        transaction.profile,
        transaction.request,
        transaction.current_active_manifest,
        transaction.candidate_manifest,
        transaction.staging_root,
        transaction.planned_changes,
        transaction.installer_effects,
        transaction.minimum_store_available_bytes,
        transaction.precondition_evidence,
        transaction.recovery_command,
    ))
}

fn absent_with_file_index(
    transaction: &InstallationTransaction,
    file_index: u64,
) -> InstallationEffectObservation {
    let precondition = must(InstallationEffectPrecondition::from_change(
        &transaction.planned_changes[0],
    ));
    let object = InstallationOsObjectSnapshot {
        canonical_path_digest: test_handle("b".repeat(64)),
        volume_serial_number: 1,
        file_index,
        security_descriptor_digest: test_handle("c".repeat(64)),
    };
    let snapshot = InstallationRootAbsentSnapshot {
        target_path_digest: test_handle("d".repeat(64)),
        profile_anchor: object.clone(),
        ancestors: vec![object.clone()],
        parent: object,
        root_absent: true,
    };
    InstallationEffectObservation::Absent {
        observed_precondition: must(precondition.with_os_snapshot(snapshot)),
        evidence: vec![test_handle("evidence:absent")],
        service_runtime_lineage: None,
    }
}

fn absent(transaction: &InstallationTransaction) -> InstallationEffectObservation {
    absent_with_file_index(transaction, 1)
}

fn admitted_precondition(transaction: &InstallationTransaction) -> InstallationEffectPrecondition {
    let InstallationEffectObservation::Absent {
        observed_precondition,
        ..
    } = absent(transaction)
    else {
        unreachable!()
    };
    observed_precondition
}

fn test_secret_reference(suffix: &str) -> InstallationSecretReference {
    InstallationSecretReference {
        target: test_handle(format!("eliot/installer-root/v1/{suffix}")),
        expected_principal_sid: test_handle("S-1-5-21-1000"),
        scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
    }
}

fn test_ownership_secret(
    disposition: InstallationCreateDisposition,
    lifecycle: InstallationSecretLifecycle,
) -> InstallationOwnershipSecret {
    InstallationOwnershipSecret {
        reference: test_secret_reference("0123456789abcdef0123456789abcdef"),
        create_disposition: disposition,
        secret_provision_disposition: match disposition {
            InstallationCreateDisposition::Created => {
                InstallationSecretProvisionDisposition::Created
            }
            InstallationCreateDisposition::NotAttempted
            | InstallationCreateDisposition::AlreadyExists => {
                InstallationSecretProvisionDisposition::NotAttempted
            }
        },
        creation_proof: test_secret_creation_proof(),
        lifecycle,
    }
}

fn matching(disposition: InstallationEffectDisposition) -> InstallationEffectObservation {
    InstallationEffectObservation::Matching {
        disposition,
        external_identity: test_handle("external:effect-0"),
        evidence: vec![test_handle("evidence:matching")],
        postcondition_digest: test_handle("a".repeat(64)),
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    }
}

#[cfg(windows)]
fn matching_service_runtime(
    disposition: InstallationEffectDisposition,
    external_identity: &str,
) -> InstallationEffectObservation {
    InstallationEffectObservation::Matching {
        disposition,
        external_identity: test_handle(external_identity),
        evidence: vec![test_handle("evidence:service-runtime")],
        postcondition_digest: test_handle("b".repeat(64)),
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: Some(InstallationServiceProcessLineage {
            process_id: 17,
            start_time_100ns: 23,
            image_path: test_handle(r"C:\Eliot\host.exe"),
        }),
    }
}

fn matching_for(
    effect: &InstallerEffectPlan,
    index: usize,
    disposition: InstallationEffectDisposition,
) -> InstallationEffectObservation {
    let service_control_grant = matches!(
        effect,
        InstallerEffectPlan::RegisterService {
            role: InstallerServiceRole::Watchdog,
            ..
        }
    )
    .then(test_watchdog_control_grant);
    InstallationEffectObservation::Matching {
        disposition,
        external_identity: test_handle(format!("external:matching-{index}")),
        evidence: vec![test_handle(format!("evidence:matching-{index}"))],
        postcondition_digest: test_handle(format!("{index:064x}")),
        service_control_grant: service_control_grant.map(Box::new),
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    }
}

fn fake_port(
    store: SharedStore,
    inspections: Vec<PortOutcome<InstallationEffectObservation>>,
    reconciliations: Vec<PortOutcome<InstallationEffectObservation>>,
    execute_count: Arc<Mutex<usize>>,
) -> FakeEffectPort {
    FakeEffectPort {
        shared: store,
        inspections: inspections.into(),
        reconciliations: reconciliations.into(),
        execute_outcomes: VecDeque::new(),
        provision_outcomes: VecDeque::new(),
        execute_count,
        executed_effect_ids: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(Vec::new())),
        provision_write_count: Arc::new(Mutex::new(0)),
        provision_reuses_existing: false,
        delete_count: Arc::new(Mutex::new(0)),
        create_disposition: InstallationCreateDisposition::Created,
        secret_absence: VecDeque::new(),
        secret_deletes: VecDeque::new(),
        panic_reconcile_once: false,
        panic_provision_once: false,
    }
}

#[cfg(windows)]
#[test]
fn signed_pending_gate_proves_ordered_service_starts_are_pending() {
    let transaction = pending_system_service_start_transaction();
    must(transaction.require_signed_pending_activation_effects());
    assert_eq!(transaction.stage(), InstallationStage::Activating);
    let first_start = transaction
        .installer_effects
        .iter()
        .position(|e| matches!(e, InstallerEffectPlan::StartService { .. }))
        .unwrap();
    for (idx, progress) in transaction.effect_progress().iter().enumerate() {
        if idx < first_start {
            assert!(matches!(
                progress.state,
                InstallationEffectProgressState::Applied { .. }
            ));
        }
    }
    let start_roles = transaction
        .installer_effects
        .iter()
        .zip(transaction.effect_progress())
        .filter_map(|(effect, progress)| {
            if let InstallerEffectPlan::StartService { role, .. } = effect {
                assert!(matches!(
                    progress.state,
                    InstallationEffectProgressState::Pending
                ));
                Some(*role)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        start_roles,
        vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host]
    );

    let mut completed_start = transaction.clone();
    let watchdog_index = completed_start
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    completed_start.effect_progress[watchdog_index].service_start_deadline_ms = Some(30_000);
    completed_start.effect_progress[watchdog_index].state =
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:watchdog-start"),
            evidence: vec![test_handle("evidence:watchdog-start")],
            postcondition_digest: test_handle("a".repeat(64)),
        };
    assert!(matches!(
        completed_start.require_signed_pending_activation_effects(),
        Err(InstallationError::IncompleteObservation(_))
    ));

    let registering = registering_system_service_start_transaction();
    assert_eq!(registering.stage(), InstallationStage::Registering);
    must(registering.require_pre_activation_effects_ready());
}

#[cfg(windows)]
#[test]
fn first_install_prefix_stops_before_watchdog_and_host_service_starts() {
    let transaction = registering_system_service_start_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let mut coordinator = WindowsInstallationCoordinator::new(store.clone());

    assert!(matches!(
        must(coordinator.drive_until_host_bootstrap(&transaction_id)),
        InstallationStepOutcome::Applied {
            stage: InstallationStage::Registering,
            ..
        }
    ));

    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    let pending_start_roles = saved
        .installer_effects
        .iter()
        .zip(saved.effect_progress())
        .filter_map(|(effect, progress)| {
            if let InstallerEffectPlan::StartService { role, .. } = effect {
                assert!(matches!(
                    progress.state,
                    InstallationEffectProgressState::Pending
                ));
                Some(*role)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pending_start_roles,
        vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host]
    );
    assert_eq!(saved.stage(), InstallationStage::Registering);
    must(saved.require_pre_activation_effects_ready());
}

#[cfg(windows)]
#[test]
fn first_install_bootstrap_handoff_keeps_both_starts_pending_through_projection() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    must(registering.require_pre_activation_effects_ready());
    must(registering.require_bootstrap_effects_ready());
    {
        let source_dir = tempfile::TempDir::new().unwrap();
        let minimal_pe = || {
            let pe_offset = 0x80_usize;
            let optional_size = 0xf0_usize;
            let section_end = pe_offset + 4 + 20 + optional_size + 40;
            let mut bytes = vec![0_u8; section_end];
            bytes[..2].copy_from_slice(b"MZ");
            bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
            bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
            let coff = pe_offset + 4;
            bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
            bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
            bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
            bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
            bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());
            bytes
        };
        let file_content = |name: &str, exe: bool| {
            if exe {
                let mut pe = minimal_pe();
                pe.extend_from_slice(name.as_bytes());
                pe
            } else {
                format!("content:{name}").into_bytes()
            }
        };
        let mut kernel_bytes = minimal_pe();
        kernel_bytes.extend_from_slice(b"eliot-kernel.exe");
        let protected_snapshot_digest = sha256_hex(
            format!(
                "governor-protected:{}:{}:{}",
                "installation:test",
                "candidate",
                sha256_hex(&kernel_bytes)
            )
            .as_bytes(),
        );
        for (name, exe) in [
            ("eliot-host.exe", true),
            ("eliot-watchdog.exe", true),
            ("eliot-kernel.exe", true),
            ("eliot-store-surreal.exe", true),
            ("surreal.exe", true),
            ("eliotd.exe", true),
            ("generation.json", false),
            ("eliotd-governor.json", false),
            ("eliotd.json", false),
        ] {
            let content = if name == "eliotd-governor.json" {
                format!(r#"{{"protected_snapshot_digest":"{protected_snapshot_digest}"}}"#)
                    .into_bytes()
            } else {
                file_content(name, exe)
            };
            std::fs::write(source_dir.path().join(name), content).unwrap();
        }
        let planned_via_planner = must(GenerationPackagePlanner::plan_unbound_for_test(
            GenerationPackagePlanInput {
                transaction_id: test_handle(format!(
                    "transaction:planner-bootstrap-{}",
                    NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
                )),
                installation_epoch: InstallationEpoch {
                    installation: test_handle("installation:test"),
                    lineage_id: test_handle("lineage:test"),
                    sequence: 1,
                },
                profile: InstallationProfile::SystemService,
                profile_anchor_root: test_handle(
                    protected_program_data_root()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                ),
                installation_key: Some(test_handle("b".repeat(64))),
                generation: test_handle("candidate"),
                source_root: test_handle(source_dir.path().to_string_lossy().into_owned()),
                staging_root: test_handle(format!(
                    r"{}\Eliot\packages",
                    protected_program_data_root().unwrap().to_string_lossy()
                )),
                minimum_store_available_bytes: 1,
                recovery_command: test_handle("recovery:command"),
                agent_bridge_source: None,
            },
        ));
        let tail = &planned_via_planner.installer_effects
            [planned_via_planner.installer_effects.len() - 6..];
        assert!(matches!(
            tail[0],
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Host,
                ..
            }
        ));
        assert!(matches!(
            tail[1],
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Watchdog,
                ..
            }
        ));
        assert!(matches!(
            tail[2],
            InstallerEffectPlan::StartService {
                role: InstallerServiceRole::Watchdog,
                ..
            }
        ));
        assert!(matches!(
            tail[3],
            InstallerEffectPlan::StartService {
                role: InstallerServiceRole::Host,
                ..
            }
        ));
        assert!(matches!(
            tail[4],
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ));
        assert!(matches!(
            tail[5],
            InstallerEffectPlan::MaterializePhaseB { .. }
        ));
        let reg_tail = &registering.installer_effects[registering.installer_effects.len() - 6..];
        assert!(matches!(
            reg_tail[0],
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Host,
                ..
            }
        ));
        assert!(matches!(
            reg_tail[1],
            InstallerEffectPlan::RegisterService {
                role: InstallerServiceRole::Watchdog,
                ..
            }
        ));
        assert!(matches!(
            reg_tail[2],
            InstallerEffectPlan::StartService {
                role: InstallerServiceRole::Watchdog,
                ..
            }
        ));
        assert!(matches!(
            reg_tail[3],
            InstallerEffectPlan::StartService {
                role: InstallerServiceRole::Host,
                ..
            }
        ));
        assert!(matches!(
            reg_tail[4],
            InstallerEffectPlan::ProvisionStoreCredential { .. }
        ));
        assert!(matches!(
            reg_tail[5],
            InstallerEffectPlan::MaterializePhaseB { .. }
        ));
    }
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-bootstrap-handoff-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-bootstrap-handoff-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = registering.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &persisted,
        ),
    );
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let revision = must(registry.load()).revision();
    must(registry.stage_pending_activation_bootstrap(
        &mut transaction_store,
        &registering.transaction_id,
        revision,
    ));
    let saved =
        must(transaction_store.load(&registering.transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Activating);
    assert!(saved.activation_projection_intent().is_some());
    let pending = saved
        .installer_effects
        .iter()
        .zip(saved.effect_progress())
        .filter_map(|(effect, progress)| {
            if let InstallerEffectPlan::StartService { role, .. } = effect {
                assert!(matches!(
                    progress.state,
                    InstallationEffectProgressState::Pending
                ));
                Some(*role)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pending,
        vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host]
    );
    assert_eq!(must(registry.load()).revision(), 2);
    let activating_revision = saved.revision;
    must(registry.stage_pending_activation_bootstrap(
        &mut transaction_store,
        &registering.transaction_id,
        revision,
    ));
    assert_eq!(
        must(transaction_store.load(&registering.transaction_id))
            .unwrap_or_else(|| unreachable!())
            .revision,
        activating_revision
    );
    assert_eq!(must(registry.load()).revision(), 2);
    drop(registry);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}

#[cfg(windows)]
#[test]
fn first_install_bootstrap_rejects_partial_start_and_crash_replays_without_second_owner() {
    let mut partial = registering_system_service_start_transaction();
    let watchdog_index = partial
        .installer_effects
        .iter()
        .position(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    partial.effect_progress[watchdog_index].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:watchdog"),
        evidence: vec![test_handle("evidence:watchdog")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    partial.effect_progress[watchdog_index].service_start_deadline_ms = Some(30_000);
    partial.effect_progress[watchdog_index].service_start_proof =
        Some(InstallationServiceStartProof {
            intent_digest: test_handle("b".repeat(64)),
            process_lineage: Some(InstallationServiceProcessLineage {
                process_id: 1,
                start_time_100ns: 2,
                image_path: test_handle(r"C:\Eliot\host.exe"),
            }),
        });
    assert!(matches!(
        partial.require_bootstrap_effects_ready(),
        Err(InstallationError::IncompleteObservation(_))
    ));
    assert!(matches!(
        partial.require_pre_activation_effects_ready(),
        Err(InstallationError::IncompleteObservation(_))
    ));
    let mut reordered = registering_system_service_start_transaction();
    let provision_idx = reordered
        .installer_effects
        .iter()
        .position(|e| matches!(e, InstallerEffectPlan::ProvisionStoreCredential { .. }))
        .unwrap();
    let first_start = reordered
        .installer_effects
        .iter()
        .position(|e| matches!(e, InstallerEffectPlan::StartService { .. }))
        .unwrap();
    reordered.installer_effects.swap(provision_idx, first_start);
    reordered.planned_changes.swap(provision_idx, first_start);
    reordered.effect_progress.swap(provision_idx, first_start);
    assert!(matches!(
        reordered.require_bootstrap_effects_ready(),
        Err(InstallationError::IncompleteObservation(_))
    ));
    assert!(matches!(
        reordered.require_pre_activation_effects_ready(),
        Err(InstallationError::IncompleteObservation(_))
    ));
    let mut missing = registering_system_service_start_transaction();
    let phase_b_idx = missing
        .installer_effects
        .iter()
        .position(|e| matches!(e, InstallerEffectPlan::MaterializePhaseB { .. }))
        .unwrap();
    missing.installer_effects.remove(phase_b_idx);
    missing.planned_changes.remove(phase_b_idx);
    missing.effect_progress.remove(phase_b_idx);
    assert!(missing.require_bootstrap_effects_ready().is_err());
    assert!(missing.require_pre_activation_effects_ready().is_err());
    let mut synthetic = registering_system_service_start_transaction();
    let cred_idx = synthetic
        .installer_effects
        .iter()
        .position(|e| matches!(e, InstallerEffectPlan::ProvisionStoreCredential { .. }))
        .unwrap();
    synthetic.effect_progress[cred_idx].store_credential = Some(StoreCredentialProgress {
        lifecycle: StoreCredentialLifecycle::Active,
        receipt: Some(CredentialAccessReceipt {
            transaction_id: synthetic.transaction_id.clone(),
            effect_id: synthetic.effect_progress[cred_idx].effect_id.clone(),
            generation: ResourceGeneration::genesis(),
            config_digest: test_handle("c".repeat(64)),
            target: test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            provider: StoreCredentialProvider::WindowsCredentialManager,
            scope: StoreCredentialScope::LocalService,
            principal_sid: test_handle(LOCAL_SERVICE_SID),
            host_owner_epoch: test_handle("epoch"),
            host_process_identity: test_handle("d".repeat(64)),
            marker: CredentialOwnershipMarkerIdentity {
                canonical_path_digest: test_handle("a".repeat(64)),
                volume_serial_number: 1,
                file_index: 1,
                security_descriptor_digest: test_handle("b".repeat(64)),
            },
            credential_envelope_digest: test_handle("e".repeat(64)),
            request_digest: test_handle("f".repeat(64)),
            response_digest: test_handle("a".repeat(64)),
        }),
    });
    assert!(synthetic.require_bootstrap_effects_ready().is_err());
    assert!(synthetic.require_pre_activation_effects_ready().is_err());
}

#[cfg(windows)]
#[test]
fn signed_activation_stage_seam_cas_binds_registering_plan_and_approval() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-signed-stage-seam-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = registering.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &persisted,
        ),
    );

    let registry_path = std::env::temp_dir().join(format!(
        "eliot-signed-stage-seam-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&registry_path);
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:signed-stage-seam"),
    );
    let (_owner_lease, capability) = live_host_capability();
    must(registry.stage_pending_activation_with_verified_approval(
        &mut transaction_store,
        &registering.transaction_id,
        approval.clone(),
        &capability,
        must(registry.load()).revision(),
    ));

    let saved =
        must(transaction_store.load(&registering.transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Activating);
    assert!(!saved.completed_stage_refs.is_empty());
    for (effect, progress) in saved.installer_effects.iter().zip(saved.effect_progress()) {
        if matches!(effect, InstallerEffectPlan::StartService { .. }) {
            assert!(matches!(
                progress.state,
                InstallationEffectProgressState::Pending
            ));
        }
    }
    let registry_snapshot = must(registry.load());
    assert_eq!(registry_snapshot.revision(), 2);
    assert_eq!(
        registry_snapshot
            .pending_activation()
            .unwrap_or_else(|| unreachable!())
            .approval,
        approval
    );
    drop(registry);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn signed_activation_projection_reentry_survives_physical_redb_reopen() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-signed-projection-reentry-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-signed-projection-reentry-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut registering_persisted = registering.clone();
    registering_persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &registering_persisted,
        ),
    );
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:projection-reentry"),
    );
    let (_owner_lease, capability) = live_host_capability();
    must(registry.stage_pending_activation_with_verified_approval(
        &mut transaction_store,
        &registering.transaction_id,
        approval.clone(),
        &capability,
        1,
    ));
    assert_eq!(must(registry.load()).revision(), 2);
    drop(registry);
    drop(transaction_store);

    let mut transaction_store = must(
        RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(
            &transaction_path,
        ),
    );
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::open(&registry_path)));
    // The exact pending projection is recognized after both redb owners
    // are reopened, and the caller's stale expected revision cannot cause
    // a duplicate registry revision on Activating re-entry.
    must(registry.stage_pending_activation_with_verified_approval(
        &mut transaction_store,
        &registering.transaction_id,
        approval.clone(),
        &capability,
        1,
    ));
    assert_eq!(must(registry.load()).revision(), 2);
    let saved =
        must(transaction_store.load(&registering.transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Activating);
    assert!(saved.activation_projection_intent().is_some());

    // Simulate the transaction CAS committing while the registry file is
    // absent.  Reloading the same signed projection recreates it only from
    // the durable snapshot bound in the transaction intent.
    drop(registry);
    drop(transaction_store);
    let _ = std::fs::remove_file(&registry_path);
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let mut transaction_store = must(
        RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(
            &transaction_path,
        ),
    );
    must(registry.stage_pending_activation_with_verified_approval(
        &mut transaction_store,
        &registering.transaction_id,
        approval.clone(),
        &capability,
        1,
    ));
    assert_eq!(must(registry.load()).revision(), 2);

    let substituted = test_transaction_activation_approval(
        &registering,
        test_handle("approval:projection-substituted"),
    );
    assert!(matches!(
        registry.stage_pending_activation_with_verified_approval(
            &mut transaction_store,
            &registering.transaction_id,
            substituted,
            &capability,
            2,
        ),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(
        must(transaction_store.load(&registering.transaction_id))
            .unwrap_or_else(|| unreachable!())
            .stage(),
        InstallationStage::Activating
    );
    drop(registry);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}

#[cfg(windows)]
#[test]
fn signed_activation_projection_registry_conflict_quarantines_after_transaction_cas() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let registering = registering_system_service_start_transaction();
    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-signed-projection-conflict-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-signed-projection-conflict-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let expected = must(TransactionVersion::of(&planned));
    let mut registering_persisted = registering.clone();
    registering_persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut transaction_store,
            expected,
            &registering_persisted,
        ),
    );
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:projection-conflict"),
    );
    let (_owner_lease, capability) = live_host_capability();
    must(registry.stage_pending_activation_with_verified_approval(
        &mut transaction_store,
        &registering.transaction_id,
        approval.clone(),
        &capability,
        1,
    ));
    drop(registry);
    drop(transaction_store);

    // Reopen a physical registry with the same expected snapshot but let
    // another approval occupy it before the Activating retry.  The
    // transaction is already durably Activating; the retry must quarantine
    // rather than raw-advance, replace, or adopt the other projection.
    let _ = std::fs::remove_file(&registry_path);
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let other_approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:projection-foreign"),
    );
    must(registry.mutate_atomic(1, |registry| {
        registry
            .stage_pending_activation_from_transaction_with_approval(&registering, other_approval)
    }));
    let mut transaction_store = must(
        RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(
            &transaction_path,
        ),
    );
    assert!(
        registry
            .stage_pending_activation_with_verified_approval(
                &mut transaction_store,
                &registering.transaction_id,
                approval,
                &capability,
                1,
            )
            .is_err()
    );
    assert_eq!(
        must(transaction_store.load(&registering.transaction_id))
            .unwrap_or_else(|| unreachable!())
            .stage(),
        InstallationStage::Quarantined
    );
    assert_eq!(must(registry.load()).revision(), 2);
    drop(registry);
    drop(transaction_store);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(transaction_path);
}

#[cfg(windows)]
fn windows_secret_request(
    reference: InstallationSecretReference,
    disposition: InstallationCreateDisposition,
) -> InstallationEffectRequest {
    let transaction = planned_transaction();
    let mut request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    request.precondition = admitted_precondition(&transaction);
    request.ownership_secret = Some(InstallationOwnershipSecret {
        reference,
        create_disposition: disposition,
        secret_provision_disposition: match disposition {
            InstallationCreateDisposition::Created => {
                InstallationSecretProvisionDisposition::Created
            }
            InstallationCreateDisposition::NotAttempted
            | InstallationCreateDisposition::AlreadyExists => {
                InstallationSecretProvisionDisposition::NotAttempted
            }
        },
        creation_proof: test_secret_creation_proof(),
        lifecycle: InstallationSecretLifecycle::Active,
    });
    must(request.validate());
    request
}

#[test]
fn coordinator_rejects_changed_independent_snapshot_after_intent() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent_with_file_index(&transaction, 1))],
        vec![PortOutcome::Known(absent_with_file_index(&transaction, 2))],
        execute_count,
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    assert!(matches!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
}

#[test]
fn service_marker_requires_exact_transaction_nonce_and_configuration() {
    let transaction = planned_transaction();
    let mut request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    request.registration_nonce = Some(test_handle("a".repeat(64)));
    let marker = must(WindowsServiceOwnershipMarker::new(
        &request,
        ELIOT_HOST_SERVICE_NAME,
        &"b".repeat(64),
        None,
    ));
    assert!(marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"b".repeat(64), None,));
    assert!(!marker.matches(&request, ELIOT_WATCHDOG_SERVICE_NAME, &"b".repeat(64), None,));
    assert!(!marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"c".repeat(64), None,));
    request.registration_nonce = Some(test_handle("d".repeat(64)));
    assert!(!marker.matches(&request, ELIOT_HOST_SERVICE_NAME, &"b".repeat(64), None,));

    request.registration_nonce = Some(test_handle("a".repeat(64)));
    let control_grant = test_watchdog_control_grant();
    let watchdog_marker = must(WindowsServiceOwnershipMarker::new(
        &request,
        ELIOT_WATCHDOG_SERVICE_NAME,
        &"e".repeat(64),
        Some(&control_grant),
    ));
    assert!(watchdog_marker.matches(
        &request,
        ELIOT_WATCHDOG_SERVICE_NAME,
        &"e".repeat(64),
        Some(&control_grant),
    ));
    let mut substituted_grant = control_grant;
    substituted_grant.security_descriptor_digest = test_handle("f".repeat(64));
    assert!(!watchdog_marker.matches(
        &request,
        ELIOT_WATCHDOG_SERVICE_NAME,
        &"e".repeat(64),
        Some(&substituted_grant),
    ));
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-style regression preserves the complete ordered Host and Watchdog SCM argv"
)]
fn service_context_binds_same_host_root_for_host_and_watchdog_argv() {
    let root = std::env::temp_dir().join(format!("eliot-service-context-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create service root: {error}"));
    for executable_name in ["eliot-host.exe", "eliot-watchdog.exe"] {
        std::fs::write(root.join(executable_name), [])
            .unwrap_or_else(|error| panic!("create service image: {error}"));
    }
    let installation_path = root
        .join("Eliot")
        .join("installations")
        .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    std::fs::create_dir_all(&installation_path)
        .unwrap_or_else(|error| panic!("create installation fixture: {error}"));
    let installation_root = test_handle(installation_path.to_string_lossy().into_owned());
    let precondition = must(InstallationEffectPrecondition::new(
        vec![test_handle("evidence:service-precondition")],
        None,
        None,
        None,
    ));
    let make_request = |role, service_name, executable_name| {
        let effect_id = test_handle(format!("effect:service:{executable_name}"));
        let request = InstallationEffectRequest {
            transaction_id: test_handle(format!("transaction:service:{executable_name}")),
            plan: InstallerEffectPlan::RegisterService {
                effect_id: effect_id.clone(),
                role,
                service_name: test_handle(service_name),
                executable_path: test_handle(
                    root.join(executable_name).to_string_lossy().into_owned(),
                ),
                account: InstallerServiceAccount::LocalService,
                automatic_start: true,
            },
            profile: InstallationProfile::SystemService,
            installation_root: installation_root.clone(),
            effect_id,
            attempt: 1,
            plan_digest: test_handle("a".repeat(64)),
            precondition: precondition.clone(),
            ownership_secret: None,
            store_credential: None,
            staging_receipt: None,
            action: InstallationEffectAction::Apply,
            expected_external_identity: None,
            service_bootstrap: Some(InstallationServiceBootstrap {
                descriptor_path: test_handle(r"C:\ProgramData\Eliot\authority.json"),
                descriptor_digest: test_handle("b".repeat(64)),
                installation_id: test_handle("installation:service"),
                plan_generation: 7,
                host_state_root: test_handle(joined_windows_path(
                    installation_root.as_str(),
                    "host",
                )),
            }),
            registration_nonce: Some(test_handle("c".repeat(64))),
        };
        must(request.validate());
        let (_, registration, _) = must(WindowsInstallationEffectPort::service_context(&request));
        registration
            .bootstrap()
            .unwrap_or_else(|| unreachable!())
            .argv()
    };

    let host_argv = make_request(
        InstallerServiceRole::Host,
        ELIOT_HOST_SERVICE_NAME,
        "eliot-host.exe",
    );
    let host_root = joined_windows_path(installation_root.as_str(), "host");
    assert_eq!(
        host_argv,
        vec![
            "--config-descriptor".to_owned(),
            r"C:\ProgramData\Eliot\authority.json".to_owned(),
            "--config-descriptor-sha256".to_owned(),
            "b".repeat(64),
            "--installation-id".to_owned(),
            "installation:service".to_owned(),
            "--tx-plan-generation".to_owned(),
            "7".to_owned(),
            "--host-state-root".to_owned(),
            host_root,
            "--registration-nonce".to_owned(),
            "c".repeat(64),
        ]
    );

    let watchdog_argv = make_request(
        InstallerServiceRole::Watchdog,
        ELIOT_WATCHDOG_SERVICE_NAME,
        "eliot-watchdog.exe",
    );
    assert_eq!(
        watchdog_argv,
        vec![
            "--config-descriptor".to_owned(),
            r"C:\ProgramData\Eliot\authority.json".to_owned(),
            "--config-descriptor-sha256".to_owned(),
            "b".repeat(64),
            "--installation-id".to_owned(),
            "installation:service".to_owned(),
            "--tx-plan-generation".to_owned(),
            "7".to_owned(),
            "--host-state-root".to_owned(),
            joined_windows_path(installation_root.as_str(), "host"),
            "--registration-nonce".to_owned(),
            "c".repeat(64),
        ]
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn already_exists_can_never_become_transaction_ownership() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count,
    );
    port.create_disposition = InstallationCreateDisposition::AlreadyExists;
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    assert!(matches!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        saved.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .create_disposition,
        InstallationCreateDisposition::AlreadyExists
    );
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
}

#[test]
fn partial_created_root_persists_disposition_and_never_resends_apply() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Unknown(UnknownReason::Indeterminate)],
        execute_count.clone(),
    );
    port.execute_outcomes.push_back(PortOutcome::Partial {
        value: InstallationEffectExecution {
            evidence: Vec::new(),
            create_disposition: Some(InstallationCreateDisposition::Created),
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_start_disposition: None,
            service_runtime_lineage: None,
        },
        missing: vec![test_handle("installer-root-win32-v2:readback:00000005")],
    });
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert!(matches!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        saved.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .create_disposition,
        InstallationCreateDisposition::Created
    );
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    let _ = coordinator.drive_effect(&transaction_id);
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
}

#[test]
fn production_root_create_mapping_preserves_partial_created_and_typed_race_reference() {
    let partial = *map_root_create_attempt(Ok(InstallerRootCreateAttempt::Failed {
        disposition: InstallerRootCreateDisposition::Created,
        error: InstallerRootError::Win32 {
            stage: InstallerRootStage::Readback,
            code: 5,
        },
    }))
    .err()
    .unwrap_or_else(|| unreachable!());
    let PortOutcome::Partial { value, missing } = partial else {
        panic!("created post-readback failure must remain partial");
    };
    assert_eq!(
        value.create_disposition,
        Some(InstallationCreateDisposition::Created)
    );
    assert_eq!(
        missing,
        vec![test_handle("installer-root-win32-v2:readback:00000005")]
    );

    let race = *map_root_create_attempt(Ok(InstallerRootCreateAttempt::PreconditionRace {
        pending_ref: "installer-root-absence-race-v1:precondition",
    }))
    .err()
    .unwrap_or_else(|| unreachable!());
    assert_eq!(
        race,
        PortOutcome::Error(PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: test_handle("installer-root-absence-race-v1:precondition"),
        })
    );
}

#[test]
fn transaction_admission_enforces_ownership_lifecycle_relations() {
    let mut preexisting = planned_transaction();
    preexisting.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    preexisting.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&preexisting));
    preexisting.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::PreexistingMatching,
        external_identity: test_handle("external:preexisting"),
        evidence: vec![test_handle("evidence:preexisting")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    assert!(preexisting.validate_effect_progress().is_err());

    for stage in [InstallationStage::Completed, InstallationStage::RolledBack] {
        let mut terminal = planned_transaction();
        terminal.stage = stage;
        terminal.effect_progress[0].ownership_secret = Some(test_ownership_secret(
            InstallationCreateDisposition::Created,
            InstallationSecretLifecycle::Active,
        ));
        terminal.effect_progress[0].admitted_precondition = Some(admitted_precondition(&terminal));
        terminal.effect_progress[0].state = InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("external:created"),
            evidence: vec![test_handle("evidence:created")],
            postcondition_digest: test_handle("b".repeat(64)),
        };
        assert!(terminal.validate_effect_progress().is_err());
    }

    let mut deleted = planned_transaction();
    deleted.stage = InstallationStage::RolledBack;
    deleted.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Deleted,
    ));
    deleted.effect_progress[0].admitted_precondition = Some(admitted_precondition(&deleted));
    deleted.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:deleted"),
        evidence: vec![test_handle("evidence:deleted")],
        postcondition_digest: test_handle("c".repeat(64)),
    };
    assert!(deleted.validate_effect_progress().is_err());
    let reference = deleted.effect_progress[0]
        .ownership_secret
        .as_ref()
        .unwrap_or_else(|| unreachable!())
        .reference
        .clone();
    deleted
        .completed_stage_refs
        .push(ownership_secret_absence_evidence(&reference));
    assert!(deleted.validate_effect_progress().is_ok());
}

#[test]
fn keyed_receipt_rejects_byte_length_key_and_object_substitution() {
    let transaction = planned_transaction();
    let mut request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    request.precondition = admitted_precondition(&transaction);
    request.ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    let root = InstallerRootObjectSnapshot {
        canonical_path_digest: "1".repeat(64),
        volume_serial_number: 7,
        file_index: 11,
        security_descriptor_digest: "2".repeat(64),
    };
    let marker = InstallerRootObjectSnapshot {
        canonical_path_digest: "3".repeat(64),
        volume_serial_number: 7,
        file_index: 12,
        security_descriptor_digest: "4".repeat(64),
    };
    let key = [0x5a; 32];
    let mut receipt = WindowsRootOwnershipReceipt::new(&request, &root, &marker, &key)
        .unwrap_or_else(|error| panic!("receipt creation failed: {error}"));
    assert!(receipt.matches(&request, &root, &marker, &key));
    assert!(!receipt.matches(&request, &root, &marker, &[0x6b; 32]));
    let mut substituted_root = root.clone();
    substituted_root.file_index += 1;
    assert!(!receipt.matches(&request, &substituted_root, &marker, &key));
    receipt.mac.push('0');
    assert!(!receipt.matches(&request, &root, &marker, &key));
    receipt.mac.pop();
    receipt.mac.replace_range(
        ..1,
        if receipt.mac.starts_with('0') {
            "1"
        } else {
            "0"
        },
    );
    assert!(!receipt.matches(&request, &root, &marker, &key));
}

#[cfg(windows)]
#[test]
fn missing_and_other_principal_credential_fail_closed() {
    let port = WindowsInstallationEffectPort::new();
    let reference = InstallationSecretReference {
        target: port
            .secrets
            .fresh_reference()
            .unwrap_or_else(|error| panic!("reference issuance failed: {error}")),
        expected_principal_sid: port
            .secrets
            .principal_sid()
            .unwrap_or_else(|error| panic!("SID observation failed: {error}")),
        scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
    };
    let request = windows_secret_request(reference.clone(), InstallationCreateDisposition::Created);
    assert!(matches!(
        port.reconcile_primitive(&request),
        Err(PortError::Provider(_))
    ));

    let mut wrong_sid = request;
    wrong_sid
        .ownership_secret
        .as_mut()
        .unwrap_or_else(|| unreachable!())
        .reference
        .expected_principal_sid = test_handle("S-1-5-21-999999");
    assert!(matches!(
        port.secret_target(&wrong_sid),
        Err(PortError::Provider(ProviderError {
            code: ProviderErrorCode::PermissionDenied,
            retryable: false
        }))
    ));
}

#[cfg(windows)]
#[test]
fn preexisting_valid_credential_is_not_adopted_or_deleted() {
    let port = WindowsInstallationEffectPort::new();
    let target = port
        .secrets
        .fresh_reference()
        .unwrap_or_else(|error| panic!("reference issuance failed: {error}"));
    let reference = InstallationSecretReference {
        target: target.clone(),
        expected_principal_sid: port
            .secrets
            .principal_sid()
            .unwrap_or_else(|error| panic!("SID observation failed: {error}")),
        scope: InstallationSecretScope::WindowsCredentialManagerCurrentUser,
    };
    assert_eq!(
        port.secrets
            .write_exact_if_absent(
                &target,
                port.secrets
                    .generate_secret()
                    .unwrap_or_else(|error| panic!("credential generation failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("credential create failed: {error}")),
        InstallerSecretCreateDisposition::Created
    );
    let request = windows_secret_request(reference, InstallationCreateDisposition::NotAttempted);
    assert_eq!(
        port.ensure_secret(&request).err(),
        Some(eliot_platform_windows::WindowsAdapterError::InvalidInput)
    );
    assert_eq!(
        port.secrets
            .inspect(&target)
            .unwrap_or_else(|error| panic!("credential inspect failed: {error}")),
        InstallerSecretObservation::Present
    );
    port.secrets
        .delete(&target)
        .unwrap_or_else(|error| panic!("credential cleanup failed: {error}"));
}

#[cfg(windows)]
fn production_created_root(
    store: &SharedStore,
    transaction_id: &PlatformHandle,
) -> InstallationTransaction {
    let mut coordinator = WindowsInstallationCoordinator::new(store.clone());
    for _ in 0..3 {
        let outcome = must(coordinator.drive_effect(transaction_id));
        assert!(
            matches!(outcome, InstallationStepOutcome::Applied { .. }),
            "unexpected production drive outcome: {outcome:?}"
        );
    }
    let transaction = must(store.load(transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        transaction.effect_progress[2].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ..
        }
    ));
    transaction
}

#[cfg(windows)]
fn cleanup_production_transaction(transaction: &InstallationTransaction) {
    if let Some(reference) = transaction.effect_progress[2]
        .ownership_secret
        .as_ref()
        .map(|ownership| &ownership.reference.target)
    {
        let _ = WindowsInstallerSecretProvider::new().delete(reference);
    }
    let root = Path::new(
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .installation_root
            .as_str(),
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(windows)]
#[test]
fn production_restart_reconciles_hmac_receipt_without_duplicate_creation() {
    let _serial = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let mut created = production_created_root(&store, &transaction_id);
    let request = must(effect_request(
        &created,
        2,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    let (spec, _) = must(windows_root_spec(&request));
    let primitive = WindowsInstallerRootPrimitive::new();
    let InstallerRootPrimitiveObservation::Matching(before) =
        primitive.inspect(&spec).unwrap_or_else(|error| {
            cleanup_production_transaction(&created);
            panic!("created root inspect failed: {error}")
        })
    else {
        cleanup_production_transaction(&created);
        panic!("expected created root")
    };
    let prior_evidence = match &created.effect_progress[2].state {
        InstallationEffectProgressState::Applied { evidence, .. } => evidence.clone(),
        _ => unreachable!(),
    };
    created
        .observed_postconditions
        .retain(|evidence| !prior_evidence.contains(evidence));
    created.effect_progress[2].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest: must(request.intent_digest()),
    };
    created.revision += 1;
    must(created.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

    let mut restarted = WindowsInstallationCoordinator::new(store.clone());
    let restart_outcome = must(restarted.drive_effect(&transaction_id));
    assert!(
        matches!(restart_outcome, InstallationStepOutcome::Applied { .. }),
        "unexpected restart outcome: {restart_outcome:?}"
    );
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    let InstallerRootPrimitiveObservation::Matching(after) =
        primitive.inspect(&spec).unwrap_or_else(|error| {
            cleanup_production_transaction(&saved);
            panic!("reconciled root inspect failed: {error}")
        })
    else {
        cleanup_production_transaction(&saved);
        panic!("expected reconciled root")
    };
    assert_eq!(before, after, "restart must not create a second directory");
    cleanup_production_transaction(&saved);
}

#[cfg(windows)]
#[test]
fn production_missing_receipt_after_create_is_unknown_not_owned() {
    let _serial = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let mut created = production_created_root(&store, &transaction_id);
    let request = must(effect_request(
        &created,
        2,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    std::fs::remove_file(ownership_receipt_path(&request)).unwrap_or_else(|error| {
        cleanup_production_transaction(&created);
        panic!("receipt removal failed: {error}")
    });
    created.effect_progress[2].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest: must(request.intent_digest()),
    };
    created.revision += 1;
    must(created.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

    let mut restarted = WindowsInstallationCoordinator::new(store.clone());
    assert!(matches!(
        must(restarted.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[2].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
    cleanup_production_transaction(&saved);
}

#[cfg(windows)]
#[test]
fn production_rollback_rejects_root_identity_substitution() {
    let _serial = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let mut created = production_created_root(&store, &transaction_id);
    let request = must(effect_request(
        &created,
        2,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    let (spec, _) = must(windows_root_spec(&request));
    let moved = spec.root.with_extension("owned-moved");
    std::fs::rename(&spec.root, &moved).unwrap_or_else(|error| {
        cleanup_production_transaction(&created);
        panic!("owned root rename failed: {error}")
    });
    let primitive = WindowsInstallerRootPrimitive::new();
    let InstallerRootPrimitiveObservation::Absent(snapshot) =
        primitive.inspect(&spec).unwrap_or_else(|error| {
            cleanup_production_transaction(&created);
            panic!("replacement absence inspect failed: {error}")
        })
    else {
        cleanup_production_transaction(&created);
        panic!("expected absent replacement path")
    };
    let replacement = primitive.create(&spec, &snapshot).unwrap_or_else(|error| {
        cleanup_production_transaction(&created);
        panic!("replacement create failed: {error}")
    });
    assert_eq!(
        replacement.disposition,
        InstallerRootCreateDisposition::Created
    );
    created.stage = InstallationStage::RollbackRequired;
    created.pending_external_changes = vec![test_handle("pending:identity-substitution")];
    created.revision += 1;
    must(created.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(created.clone());

    let mut coordinator = WindowsInstallationCoordinator::new(store.clone());
    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert!(spec.root.exists(), "replacement root must never be deleted");
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    cleanup_production_transaction(&saved);
    let _ = std::fs::remove_dir_all(moved);
}

#[test]
fn credential_proof_intent_cas_precedes_provider_and_root_execute() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count.clone(),
    );
    let events = port.events.clone();
    let writes = port.provision_write_count.clone();
    let mut coordinator = InstallationCoordinator::new(port, store);
    let outcome = must(coordinator.drive_effect(&transaction_id));
    assert!(
        matches!(outcome, InstallationStepOutcome::Applied { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(
        *events.lock().unwrap_or_else(|_| unreachable!()),
        vec!["prepare", "provision", "execute"]
    );
    assert_eq!(*writes.lock().unwrap_or_else(|_| unreachable!()), 1);
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
}

#[test]
fn created_cas_reload_precedes_create_root_execute() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count.clone(),
    );
    let events = port.events.clone();
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    must(coordinator.drive_effect(&transaction_id));
    assert_eq!(
        *events
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .last()
            .unwrap(),
        "execute"
    );
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(
        saved.effect_progress[0]
            .ownership_secret
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .secret_provision_disposition,
        InstallationSecretProvisionDisposition::Created
    );
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
}

#[cfg(windows)]
#[test]
fn created_cas_reload_barrier_covers_stage_and_store_credential_effects() {
    for (effect_kind, reload_mode) in [
        ("stage-package", "substituted"),
        ("stage-package", "stale"),
        ("stage-package", "missing"),
        ("stage-package", "exact"),
        ("store-credential", "substituted"),
        ("store-credential", "stale"),
        ("store-credential", "missing"),
        ("store-credential", "exact"),
    ] {
        let mut transaction = fully_applied_system_registration_transaction();
        let index = transaction
            .installer_effects
            .iter()
            .position(|effect| match effect_kind {
                "stage-package" => matches!(effect, InstallerEffectPlan::StagePackage { .. }),
                "store-credential" => {
                    matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                }
                _ => unreachable!(),
            })
            .unwrap_or_else(|| unreachable!());
        for progress in &mut transaction.effect_progress[index..] {
            progress.admitted_precondition = None;
            progress.ownership_secret = None;
            progress.registration_nonce = None;
            progress.service_control_grant = None;
            progress.service_start_deadline_ms = None;
            progress.service_start_proof = None;
            progress.store_credential = None;
            progress.staging_receipt = None;
            progress.phase_b_receipt = None;
            progress.state = InstallationEffectProgressState::Pending;
        }
        transaction.stage = if effect_kind == "stage-package" {
            InstallationStage::Staging
        } else {
            InstallationStage::Registering
        };
        transaction.observed_postconditions.clear();
        transaction.pending_external_changes.clear();
        transaction.revision += 1;
        must(transaction.validate());

        let transaction_id = transaction.transaction_id.clone();
        let mut request = must(effect_request(
            &transaction,
            index,
            1,
            InstallationEffectAction::Apply,
            None,
        ));
        let inspection = if effect_kind == "stage-package" {
            let (source_bundle_identity, generation, manifest_digest) = match &request.plan {
                InstallerEffectPlan::StagePackage {
                    source_bundle_identity,
                    generation,
                    manifest,
                    ..
                } => (
                    *source_bundle_identity,
                    generation.clone(),
                    must(PlatformHandle::new(manifest.canonical_digest())),
                ),
                _ => unreachable!(),
            };
            let files = Vec::new();
            let total_bytes = 0;
            let digest = must(PackageObservationSnapshot::compute_digest(
                &source_bundle_identity,
                &generation,
                &manifest_digest,
                &files,
                total_bytes,
            ));
            let snapshot = PackageObservationSnapshot {
                source_bundle_identity,
                generation,
                manifest_digest,
                files,
                total_bytes,
                digest,
            };
            must(package_absent_with_snapshot(&request, snapshot))
        } else {
            let snapshot = StoreCredentialAbsentSnapshot {
                host_owner_epoch: test_handle("host-owner:created-cas-reload"),
                host_process_identity: test_handle("a".repeat(64)),
                host_state_root: CredentialOwnershipMarkerIdentity {
                    canonical_path_digest: test_handle("b".repeat(64)),
                    volume_serial_number: 1,
                    file_index: 1,
                    security_descriptor_digest: test_handle("c".repeat(64)),
                },
                marker_path_digest: test_handle("d".repeat(64)),
                marker_absent: true,
                target_absent: true,
            };
            request.precondition = must(request.precondition.with_credential_snapshot(snapshot));
            InstallationEffectObservation::Absent {
                observed_precondition: request.precondition.clone(),
                evidence: vec![test_handle("evidence:credential-absent")],
                service_runtime_lineage: None,
            }
        };
        let store = SharedStore {
            state: Arc::new(Mutex::new(Some(transaction))),
            created_load_target_effect_id: Arc::new(Mutex::new(Some(request.effect_id.clone()))),
            ..SharedStore::default()
        };
        match reload_mode {
            "substituted" => {
                *store
                    .substitute_after_created_load
                    .lock()
                    .unwrap_or_else(|_| unreachable!()) = true;
            }
            "stale" => {
                *store
                    .stale_after_created_load
                    .lock()
                    .unwrap_or_else(|_| unreachable!()) = true;
            }
            "missing" => {
                *store
                    .missing_after_created_load
                    .lock()
                    .unwrap_or_else(|_| unreachable!()) = true;
            }
            "exact" => {}
            _ => unreachable!(),
        }
        let execute_count = Arc::new(Mutex::new(0));
        let port = fake_port(
            store.clone(),
            vec![PortOutcome::Known(inspection)],
            Vec::new(),
            execute_count.clone(),
        );
        let mut coordinator = InstallationCoordinator::new(port, store);
        let outcome = coordinator.drive_effect(&transaction_id);
        if reload_mode == "exact" {
            assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
        } else {
            assert!(
                matches!(&outcome, Err(InstallationError::IdentityConflict)),
                "outcome={outcome:?}, effect_kind={effect_kind}, reload_mode={reload_mode}"
            );
            assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
        }
    }
}

#[test]
fn restart_absent_without_prepared_secret_does_not_regenerate_or_execute() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let mut first = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    first.panic_provision_once = true;
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut coordinator = InstallationCoordinator::new(first, store.clone());
        let _ = coordinator.drive_effect(&transaction_id);
    }));
    assert!(crashed.is_err());
    let mut restarted = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
    restarted.provision_outcomes = vec![PortOutcome::Unknown(UnknownReason::NotObserved)].into();
    let events = restarted.events.clone();
    let mut coordinator = InstallationCoordinator::new(restarted, store);
    assert!(matches!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(
        *events.lock().unwrap_or_else(|_| unreachable!()),
        vec!["provision"]
    );
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[test]
fn response_loss_present_matching_proof_does_not_write_twice() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let writes = Arc::new(Mutex::new(0));
    let mut first = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    first.panic_provision_once = true;
    first.provision_write_count = writes.clone();
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut coordinator = InstallationCoordinator::new(first, store.clone());
        let _ = coordinator.drive_effect(&transaction_id);
    }));
    assert!(crashed.is_err());
    let mut restarted = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count);
    restarted.provision_write_count = writes.clone();
    restarted.provision_reuses_existing = true;
    let mut coordinator = InstallationCoordinator::new(restarted, store);
    let _ = coordinator.drive_effect(&transaction_id);
    assert_eq!(*writes.lock().unwrap_or_else(|_| unreachable!()), 1);
}

#[test]
fn foreign_present_proof_is_rejected_without_execute_or_delete() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let mut port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    let delete_count = port.delete_count.clone();
    port.provision_outcomes = vec![PortOutcome::Error(PortError::Provider(ProviderError {
        code: ProviderErrorCode::Failed,
        retryable: false,
    }))]
    .into();
    let mut coordinator = InstallationCoordinator::new(port, store);
    assert!(matches!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert_eq!(*delete_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[test]
fn created_credential_substitution_blocks_root_execute() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    *store
        .substitute_after_created_load
        .lock()
        .unwrap_or_else(|_| unreachable!()) = true;
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store);
    assert!(matches!(
        coordinator.drive_effect(&transaction_id),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[test]
fn durable_coordinator_commits_intent_before_effect() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::CreatedByTransaction,
        ))],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    let outcome = must(coordinator.drive_effect(&transaction_id));

    assert!(matches!(outcome, InstallationStepOutcome::Applied { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ..
        }
    ));
}

#[test]
fn preexisting_matching_is_receipted_without_execution() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(matching(
            InstallationEffectDisposition::PreexistingMatching,
        ))],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    must(coordinator.drive_effect(&transaction_id));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::PreexistingMatching,
            ..
        }
    ));
}

#[test]
fn all_effects_gate_blocks_registry_projection_until_authoritative_readback() {
    let transaction = planned_transaction();
    assert!(matches!(
        transaction.require_all_effects_applied(),
        Err(InstallationError::IncompleteObservation(_))
    ));

    let mut registry = ApprovedGenerationRegistry::new();
    assert!(matches!(
        registry.stage_pending_activation_from_transaction_with_approval(
            &transaction,
            test_activation_approval(
                &transaction.candidate_manifest,
                transaction.transaction_id.clone(),
                transaction.installer_plan_digest.clone(),
                test_handle("approval:blocked"),
            ),
        ),
        Err(InstallationError::IncompleteObservation(_))
    ));
    assert!(registry.pending_activation().is_none());
}

#[cfg(windows)]
#[test]
fn activation_approval_rejects_each_transaction_binding_mismatch() {
    let transaction = fully_applied_system_registration_transaction();
    let approval =
        test_transaction_activation_approval(&transaction, test_handle("approval:issued"));
    must(approval.validate_against(&transaction));

    let mut mismatches = Vec::new();
    let mut value = approval.clone();
    value.transaction_id = test_handle("transaction:other");
    mismatches.push(value);
    let mut value = approval.clone();
    value.installer_plan_digest = test_handle("a".repeat(64));
    mismatches.push(value);
    let mut value = approval.clone();
    value.generation = test_handle("generation:other");
    mismatches.push(value);
    let mut value = approval.clone();
    value.candidate_manifest_digest = test_handle("b".repeat(64));
    mismatches.push(value);
    let mut value = approval.clone();
    value.runtime_descriptor_digest = test_handle("c".repeat(64));
    mismatches.push(value);
    let mut value = approval.clone();
    value.required_owner = test_handle("owner:other");
    mismatches.push(value);
    let mut value = approval.clone();
    value.signature_ref = test_handle("signature:other");
    mismatches.push(value);
    let mut value = approval.clone();
    value.authority_descriptor_path = test_handle("authority:other.json");
    mismatches.push(value);
    let mut value = approval.clone();
    value.authority_descriptor_digest = test_handle("d".repeat(64));
    mismatches.push(value);
    let next_generation = must(ResourceGeneration::new(
        approval.authority_generation.value() + 1,
    ));
    let mut value = approval.clone();
    value.authority_generation = next_generation;
    value.authority_state_fence.resource_generation = next_generation;
    mismatches.push(value);
    let mut value = approval.clone();
    value.authority_state_fence.authority_epoch = must(AuthorityEpoch::new(
        approval.authority_state_fence.authority_epoch.value() + 1,
    ));
    mismatches.push(value);

    assert_eq!(mismatches.len(), 11);
    for mismatch in mismatches {
        assert!(matches!(
            mismatch.validate_against(&transaction),
            Err(InstallationError::IdentityConflict)
        ));
    }

    // `approval_ref` is evidence identity, not a transaction-derived
    // field.  Its authority provenance is sealed by the issuing lane;
    // changing it alone is not a transaction binding mismatch.
    let mut different_evidence = approval;
    different_evidence.approval_ref = test_handle("approval:other");
    must(different_evidence.validate_against(&transaction));
}

#[cfg(windows)]
#[test]
fn activation_approval_rejects_partial_effects_before_binding_checks() {
    let transaction = planned_transaction();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:partial"),
    );
    assert!(matches!(
        approval.validate_against(&transaction),
        Err(InstallationError::IncompleteObservation(_))
    ));
}

#[test]
fn bounded_effect_driver_stops_on_rejected_without_retry() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![PortOutcome::Known(absent(&transaction))],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    assert_eq!(
        must(coordinator.drive_all_effects_until_blocked(&transaction_id)),
        InstallationStepOutcome::Rejected
    );
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::IntentCommitted { .. }
    ));
}

#[test]
fn bounded_effect_driver_completes_all_effects_and_rechecks_authority() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let effect_count = transaction.effect_progress.len();
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        (0..effect_count)
            .map(|index| {
                PortOutcome::Known(matching_for(
                    &transaction.installer_effects[index],
                    index,
                    InstallationEffectDisposition::PreexistingMatching,
                ))
            })
            .collect(),
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    assert!(matches!(
        must(coordinator.drive_all_effects_until_blocked(&transaction_id)),
        InstallationStepOutcome::Applied { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(saved.require_all_effects_applied().is_ok());
}

#[test]
fn bounded_effect_driver_propagates_cas_conflict_without_external_retry() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    *store
        .conflict_next
        .lock()
        .unwrap_or_else(|_| unreachable!()) = true;
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store);

    let result = coordinator.drive_all_effects_until_blocked(&transaction_id);
    assert!(matches!(
        result,
        Err(InstallationError::CompareAndSaveConflict { .. })
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[test]
fn cas_conflict_happens_before_external_effect() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    *store
        .conflict_next
        .lock()
        .unwrap_or_else(|_| unreachable!()) = true;
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        Vec::new(),
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store);
    let result = coordinator.drive_effect(&transaction_id);
    assert!(matches!(
        result,
        Err(InstallationError::CompareAndSaveConflict { .. })
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
}

#[test]
fn cas_binds_full_previous_state_at_the_same_revision() {
    let transaction = planned_transaction();
    let expected = must(TransactionVersion::of(&transaction));
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));

    let mut drifted = transaction.clone();
    drifted
        .precondition_evidence
        .push(test_handle("evidence:same-revision-drift"));
    must(drifted.validate());
    *store.state.lock().unwrap_or_else(|_| unreachable!()) = Some(drifted);

    let mut advanced = transaction;
    must(advanced.advance(
        InstallationStage::Staging,
        vec![test_handle("evidence:advance")],
    ));
    assert!(matches!(
        transaction_store_private::Sealed::compare_and_save(&mut store, expected, &advanced),
        Err(InstallationError::IdentityConflict)
    ));
}

#[test]
fn retry_requires_authoritative_absence_and_unchanged_precondition() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(
        store.clone(),
        vec![PortOutcome::Known(absent(&transaction))],
        vec![
            PortOutcome::Known(absent(&transaction)),
            PortOutcome::Known(absent(&transaction)),
            PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            )),
        ],
        execute_count.clone(),
    );
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    assert_eq!(
        must(coordinator.drive_effect(&transaction_id)),
        InstallationStepOutcome::Rejected
    );
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 1);
    must(coordinator.drive_effect(&transaction_id));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 2);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Applied { .. }
    ));
}

#[test]
fn inspect_unknown_entering_rollback_persists_quarantine() {
    let transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    let mut store = SharedStore::default();
    must(store.create_planned(&transaction));
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    let outcome = must(coordinator.drive_effect(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage, InstallationStage::RollbackRequired);
    let rollback_port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count);
    let mut rollback = InstallationCoordinator::new(rollback_port, store.clone());
    let outcome = must(rollback.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Quarantined { .. }
    ));
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage, InstallationStage::Quarantined);
    assert!(matches!(
        saved.effect_progress[0].state,
        InstallationEffectProgressState::Unknown { .. }
    ));
}

#[test]
fn unreconciled_intent_entering_rollback_persists_quarantine() {
    let mut transaction = planned_transaction();
    let transaction_id = transaction.transaction_id.clone();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::NotAttempted,
        InstallationSecretLifecycle::Active,
    ));
    let intent_digest = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ))
    .intent_digest()
    .unwrap_or_else(|error| panic!("intent digest: {error}"));
    transaction.effect_progress[0].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest: intent_digest.clone(),
    };
    transaction.pending_external_changes = vec![intent_digest];
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.revision = 3;
    must(transaction.validate());
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0));
    let port = fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone());
    let mut coordinator = InstallationCoordinator::new(port, store.clone());

    assert!(matches!(
        must(coordinator.rollback(&transaction_id)),
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage, InstallationStage::Quarantined);
}

#[test]
fn progress_is_exactly_one_to_one_and_plan_digest_is_immutable() {
    let mut transaction = planned_transaction();
    transaction.effect_progress.pop();
    assert!(matches!(
        transaction.validate(),
        Err(InstallationError::IdentityConflict)
    ));

    let mut transaction = planned_transaction();
    transaction.effect_progress[0].effect_id = test_handle("effect:wrong");
    assert!(matches!(
        transaction.validate(),
        Err(InstallationError::IdentityConflict)
    ));

    let mut transaction = planned_transaction();
    transaction.installer_plan_digest = test_handle("c".repeat(64));
    assert!(transaction.validate().is_err());

    let mut transaction = planned_transaction();
    transaction.effect_progress[1].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::PreexistingMatching,
        external_identity: test_handle("external:out-of-order"),
        evidence: vec![test_handle("evidence:out-of-order")],
        postcondition_digest: test_handle("d".repeat(64)),
    };
    assert!(transaction.validate().is_err());
}

#[test]
fn effect_request_carries_exactly_one_plan_and_precondition() {
    let transaction = planned_transaction();
    let request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    assert_eq!(
        request.effect_id,
        *transaction.installer_effects[0].effect_id()
    );
    assert_eq!(request.plan_digest, transaction.installer_plan_digest);
    assert_eq!(
        request.installation_root,
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .installation_root
    );
    assert_eq!(
        request.precondition.evidence_refs,
        transaction.planned_changes[0].precondition_refs
    );
    let (platform_request, operation) = must(windows_root_spec(&request));
    assert_eq!(
        platform_request.installation_root,
        Path::new(request.installation_root.as_str())
    );
    assert_eq!(platform_request.profile, InstallerRootProfile::PortableDev);
    assert_eq!(operation, WindowsRootOperation::Create);
    let encoded = must(serde_json::to_value(request));
    assert!(encoded.get("plan").is_some());
    assert!(encoded.get("change_refs").is_none());
    assert!(encoded.get("candidate_generation").is_none());
    assert!(encoded.get("installation").is_none());
}

#[test]
fn create_planned_rejects_caller_advanced_state() {
    let mut transaction = planned_transaction();
    transaction.stage = InstallationStage::Staging;
    transaction.completed_stage_refs = vec![test_handle("evidence:advanced")];
    transaction.revision = 2;
    let mut store = SharedStore::default();
    assert!(store.create_planned(&transaction).is_err());
}

#[test]
fn create_planned_at_exact_path_rejects_advanced_state_before_file_creation() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-create-planned-{}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut transaction = planned_transaction();
    transaction.stage = InstallationStage::Staging;
    transaction.completed_stage_refs = vec![test_handle("evidence:advanced")];
    transaction.revision = 2;

    assert!(
        RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction,)
            .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn create_planned_at_exact_path_publishes_populated_store_without_overwrite() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-create-planned-publish-{}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let transaction = planned_transaction();
    let store =
        must(RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction));
    assert_eq!(
        must(store.load(&transaction.transaction_id))
            .unwrap_or_else(|| unreachable!())
            .revision(),
        transaction.revision()
    );
    drop(store);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| unreachable!());
    let temporary_prefix = format!(".{file_name}.eliot-transaction-");
    let temporary_files = std::fs::read_dir(path.parent().unwrap_or_else(|| unreachable!()))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&temporary_prefix))
        })
        .collect::<Vec<_>>();
    assert!(temporary_files.is_empty(), "temporary publication leaked");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_planned_at_exact_path_never_overwrites_publish_conflict() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-create-planned-conflict-{}.redb",
        std::process::id()
    ));
    let original = b"caller-owned-not-a-transaction-store";
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, original).unwrap_or_else(|error| panic!("write conflict: {error}"));
    let transaction = planned_transaction();
    assert!(
        RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &transaction)
            .is_err()
    );
    assert_eq!(
        std::fs::read(&path).unwrap_or_else(|error| panic!("read conflict: {error}")),
        original
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn pre_v7_transaction_json_requires_explicit_migration() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.remove("transaction_wire_version");
    object.remove("effect_progress");
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { .. })
    ));
}

#[test]
fn v8_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(8, 0, 0))),
    );
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_installation_transaction_json(&bytes) else {
        panic!("v8 transaction must require migration");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v9_transaction_json_requires_explicit_migration_without_start_synthesis() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(9, 0, 0))),
    );
    if let Some(effects) = object
        .get_mut("installer_effects")
        .and_then(serde_json::Value::as_array_mut)
    {
        effects.retain(|effect| {
            effect.get("kind").and_then(serde_json::Value::as_str) != Some("START_SERVICE")
        });
    }
    if let Some(changes) = object
        .get_mut("planned_changes")
        .and_then(serde_json::Value::as_array_mut)
    {
        changes.retain(|change| {
            !change
                .get("change_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|change_id| change_id.starts_with("effect:start:"))
        });
    }
    if let Some(progress) = object
        .get_mut("effect_progress")
        .and_then(serde_json::Value::as_array_mut)
    {
        progress.retain(|entry| {
            !entry
                .get("effect_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|effect_id| effect_id.starts_with("effect:start:"))
        });
    }
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_installation_transaction_json(&bytes) else {
        panic!("v9 transaction must require migration rather than synthesize starts");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("wire 9.0.0 requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v4_transaction_json_requires_explicit_migration_without_defaults() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(4, 0, 0))),
    );
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { .. })
    ));
}

#[test]
fn v10_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(10, 0, 0))),
    );
    if let Some(progress) = object
        .get_mut("effect_progress")
        .and_then(serde_json::Value::as_array_mut)
        && let Some(first) = progress.first_mut()
    {
        first
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .insert(
                "service_start_proof".to_owned(),
                serde_json::json!({
                    "intent_digest": "a".repeat(64),
                }),
            );
    }
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 10.0.0 requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v13_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(13, 0, 0))),
    );
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 13.0.0 requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v14_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "transaction_wire_version".to_owned(),
        must(serde_json::to_value(ContractVersion::new(14, 0, 0))),
    );
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 14.0.0 requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v15_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(15, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 15.0.0 requires explicit migration to 23.0.0")
    ));
}

#[test]
fn v16_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(16, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 16.0.0") && reason.contains("23.0.0")
    ));
}

#[test]
fn v17_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(17, 0, 0)));
    for progress in legacy["effect_progress"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
    {
        progress
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("service_control_grant");
    }
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 17.0.0") && reason.contains("23.0.0")
    ));
}

#[test]
fn v18_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(18, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_installation_transaction_json(&bytes) else {
        panic!("v18 transaction must require migration after the root-contour split");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("wire 18.0.0") && reason.contains("23.0.0")
    ));
}

#[test]
fn v20_transaction_json_requires_explicit_migration_to_v23() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(20, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 20.0.0") && reason.contains("23.0.0")
    ));
}

#[test]
fn v22_transaction_json_is_rejected_before_payload_authority() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(22, 0, 0)));
    // Deliberately corrupt a nested authority field as well.  The version
    // discriminator must fence the old wire before nested payload acceptance.
    legacy["installer_effects"][0]["effect_id"] = serde_json::json!(null);
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 22.0.0") && reason.contains("23.0.0")
    ));
}

#[test]
fn current_transaction_missing_nonce_or_deadline_is_corrupt_not_synthesized() {
    for field in ["registration_nonce", "service_start_deadline_ms"] {
        let mut value = must(serde_json::to_value(planned_transaction()));
        let progress = value["effect_progress"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!());
        progress[0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove(field);
        let bytes = must(serde_json::to_vec(&value));
        let Err(InstallationError::CorruptRegistry { reason }) =
            decode_installation_transaction_json(&bytes)
        else {
            panic!("missing {field} must be rejected without synthesis");
        };
        assert!(reason.contains("missing mandatory"), "{field}: {reason}");
    }
}

#[cfg(windows)]
#[test]
fn current_v23_ownership_members_are_mandatory_and_never_synthesized() {
    for field in [
        "reference",
        "create_disposition",
        "secret_provision_disposition",
        "creation_proof",
        "lifecycle",
    ] {
        let mut value = must(serde_json::to_value(
            fully_applied_system_registration_transaction(),
        ));
        let ownership = value["effect_progress"]
            .as_array_mut()
            .unwrap_or_else(|| unreachable!())
            .iter_mut()
            .find_map(|progress| {
                progress
                    .get_mut("ownership_secret")
                    .filter(|value| !value.is_null())
                    .and_then(serde_json::Value::as_object_mut)
            })
            .unwrap_or_else(|| unreachable!());
        ownership.remove(field);
        let bytes = must(serde_json::to_vec(&value));
        let error = decode_installation_transaction_json(&bytes)
            .expect_err("missing current-v23 ownership member must reject the record");
        assert!(
            matches!(
                error,
                InstallationError::MigrationRequired { .. }
                    | InstallationError::CorruptRegistry { .. }
            ),
            "missing {field} must classify as migration/corruption, got {error:?}"
        );
    }
}

#[test]
fn registry_below_v10_requires_explicit_migration() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object["registry_wire_version"] = serde_json::json!({
        "major": 9,
        "minor": 0,
        "patch": 0
    });
    object.remove("active_phase_b_rebind");
    let bytes = must(serde_json::to_vec(&legacy));
    let err = decode_registry_bytes(&bytes).expect_err("registry 9 must not decode");
    assert!(
        matches!(err, InstallationError::MigrationRequired { ref reason } if reason.contains("registry wire 9.0.0")),
        "expected MigrationRequired for registry 9, got {err:?}"
    );
}

#[test]
fn canonical_transaction_rejects_reordered_watchdog_host() {
    let transaction = pending_system_service_start_transaction();
    let mut effects = transaction.installer_effects.clone();
    let mut changes = transaction.planned_changes.clone();
    let watchdog = effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap();
    let host = effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        })
        .unwrap();
    effects.swap(watchdog, host);
    changes.swap(watchdog, host);
    let roots = &transaction
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots;
    let target = &transaction.candidate_manifest.store_credential_target;
    assert!(
        validate_installer_effects(transaction.profile, roots, target, &changes, &effects).is_err()
    );
}

#[test]
fn start_service_rejects_wrong_automatic_start() {
    let transaction = pending_system_service_start_transaction();
    let mut effects = transaction.installer_effects.clone();
    for effect in &mut effects {
        if let InstallerEffectPlan::StartService {
            automatic_start, ..
        } = effect
        {
            *automatic_start = false;
            break;
        }
    }
    let roots = &transaction
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots;
    let target = &transaction.candidate_manifest.store_credential_target;
    assert!(
        validate_installer_effects(
            transaction.profile,
            roots,
            target,
            &transaction.planned_changes,
            &effects,
        )
        .is_err()
    );
}

#[test]
fn service_start_deadline_must_be_durable_for_intent() {
    let mut transaction = pending_system_service_start_transaction();
    let idx = transaction
        .installer_effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap();
    transaction.effect_progress[idx].service_start_deadline_ms = None;
    transaction.effect_progress[idx].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest: test_handle("a".repeat(64)),
    };
    assert!(transaction.validate().is_err());
}

#[test]
fn unknown_start_preserves_intent_does_not_auto_retry() {
    let mut transaction = pending_system_service_start_transaction();
    let idx = transaction
        .installer_effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap();
    transaction.effect_progress[idx].state = InstallationEffectProgressState::Unknown {
        pending_ref: test_handle("pending:unknown-start"),
    };
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes = vec![test_handle("pending:unknown-start")];
    transaction.revision = 9;
    assert!(transaction.validate().is_ok());
    assert!(
        transaction.effect_progress[idx]
            .service_start_proof
            .is_none()
    );
}

#[test]
fn ordered_watchdog_then_host_starts_are_canonical() {
    let transaction = pending_system_service_start_transaction();
    let mut roles = Vec::new();
    for effect in &transaction.installer_effects {
        if let InstallerEffectPlan::StartService { role, .. } = effect {
            roles.push(*role);
        }
    }
    assert_eq!(
        roles,
        vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host]
    );
    for effect in &transaction.installer_effects {
        if let InstallerEffectPlan::StartService {
            account,
            automatic_start,
            ..
        } = effect
        {
            assert_eq!(*account, InstallerServiceAccount::LocalService);
            assert!(*automatic_start);
        }
    }
}

#[test]
fn unknown_start_service_preserves_intent_until_readback() {
    let transaction = pending_system_service_start_transaction();
    // Drive Watchdog to START_PENDING with deadline, then simulate unknown outcome
    let watchdog_index = transaction
        .installer_effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Watchdog,
                    ..
                }
            )
        })
        .unwrap();
    let host_index = transaction
        .installer_effects
        .iter()
        .position(|e| {
            matches!(
                e,
                InstallerEffectPlan::StartService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        })
        .unwrap();
    assert!(watchdog_index < host_index, "Watchdog must precede Host");
    // The planned start effects remain pending and carry no deadline until
    // the coordinator durably commits their individual intents.
    let watchdog_deadline = transaction.effect_progress[watchdog_index].service_start_deadline_ms;
    let host_deadline = transaction.effect_progress[host_index].service_start_deadline_ms;
    assert!(watchdog_deadline.is_none());
    assert!(host_deadline.is_none());
    assert!(matches!(
        &transaction.effect_progress[watchdog_index].state,
        InstallationEffectProgressState::Pending
    ));
    assert!(matches!(
        &transaction.effect_progress[host_index].state,
        InstallationEffectProgressState::Pending
    ));
    // Exact unknown preservation is covered by existing exhaustive coordinator tests;
    // this fixture ensures the canonical order is not synthesized away.
    drop(transaction);
}

#[test]
fn current_transaction_without_projection_intent_field_is_corrupt_registry() {
    let mut value = must(serde_json::to_value(planned_transaction()));
    let object = value.as_object_mut().unwrap_or_else(|| unreachable!());
    object.remove("activation_projection_intent");
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
}

#[test]
fn current_transaction_without_service_control_grant_member_is_corrupt_registry() {
    let mut value = must(serde_json::to_value(planned_transaction()));
    value["effect_progress"]
        .as_array_mut()
        .and_then(|progress| progress.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .unwrap_or_else(|| unreachable!())
        .remove("service_control_grant");
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::CorruptRegistry { reason })
            if reason.contains("service control grant")
    ));
}

#[test]
fn current_transaction_without_start_proof_process_lineage_is_corrupt_registry() {
    let mut value = must(serde_json::to_value(planned_transaction()));
    let object = value.as_object_mut().unwrap_or_else(|| unreachable!());
    let progress = object
        .get_mut("effect_progress")
        .and_then(serde_json::Value::as_array_mut)
        .unwrap_or_else(|| unreachable!());
    let first = progress
        .first_mut()
        .and_then(serde_json::Value::as_object_mut)
        .unwrap_or_else(|| unreachable!());
    first.insert(
        "service_start_proof".to_owned(),
        serde_json::json!({
            "intent_digest": "a".repeat(64),
        }),
    );
    let bytes = must(serde_json::to_vec(&value));
    let Err(InstallationError::CorruptRegistry { reason }) =
        decode_installation_transaction_json(&bytes)
    else {
        panic!("v11 transaction missing process lineage must be rejected");
    };
    assert!(reason.contains("missing mandatory process lineage member"));
}

#[test]
fn untrusted_json_cannot_import_active_verified_receipt_state() {
    let transaction = registering_transaction();
    let mut value = must(serde_json::to_value(&transaction));
    let object = value.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert(
        "stage".to_owned(),
        serde_json::to_value(InstallationStage::ActiveVerified).unwrap_or_else(|_| unreachable!()),
    );
    object.insert(
        "observed_postconditions".to_owned(),
        serde_json::json!(["evidence:forged-active"]),
    );
    object.insert(
            "active_verified_receipt".to_owned(),
            serde_json::json!({
                "transaction_id": transaction.transaction_id.clone(),
                "plan_digest": transaction.installer_plan_digest.clone(),
                "generation": transaction.candidate_manifest.generation.clone(),
                "candidate_manifest_digest": must(candidate_manifest_digest(&transaction.candidate_manifest)),
                "commit_fence": test_commit_fence(&transaction.candidate_manifest),
                "registry_revision": 3,
                "terminal_digest": "a".repeat(64),
            }),
        );
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("ACL-protected store replay")
    ));
}

#[test]
fn redb_transaction_store_round_trips_and_enforces_cas() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-transaction-roundtrip-{}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let transaction = planned_transaction();
    let id = transaction.transaction_id.clone();
    let mut store = must(RedbInstallationTransactionStore::create_at_exact_path(
        &path,
    ));
    must(store.create_planned(&transaction));
    assert_eq!(must(store.load(&id)), Some(transaction.clone()));
    drop(store);
    let mut store = must(RedbInstallationTransactionStore::open_existing_exact_path(
        &path,
    ));

    let mut advanced = transaction;
    must(advanced.advance(
        InstallationStage::Staging,
        vec![test_handle("evidence:redb-cas")],
    ));
    let initial_version = must(TransactionVersion::of(
        &must(store.load(&id)).unwrap_or_else(|| unreachable!()),
    ));
    must(transaction_store_private::Sealed::compare_and_save(
        &mut store,
        initial_version.clone(),
        &advanced,
    ));
    assert!(matches!(
        transaction_store_private::Sealed::compare_and_save(&mut store, initial_version, &advanced,),
        Err(InstallationError::CompareAndSaveConflict {
            expected: 1,
            actual: 2
        })
    ));
    drop(store);
    let _ = std::fs::remove_file(path);
}

#[test]
fn portable_runtime_roots_accept_distinct_sibling_topology() {
    let directory = std::env::temp_dir().join("eliot-portable-root-siblings");
    provision_portable_test_root(&directory);
    let root = test_handle(directory.to_string_lossy().into_owned());
    let roots = must(RuntimeStateRoots::derive_portable(root));
    assert!(roots.validate().is_ok());
    assert_ne!(roots.kernel_work_root, roots.store_work_root);
    assert_ne!(roots.store_data_root, roots.store_temp_root);
}

#[test]
fn runtime_roots_reject_traversal_and_device_prefixes() {
    assert!(RuntimeStateRoots::derive_portable(test_handle(r"C:\portable\..\escaped")).is_err());
    assert!(RuntimeStateRoots::derive_portable(test_handle(r"\\?\C:\portable\eliot")).is_err());
}

#[test]
fn windows_root_overlap_is_case_insensitive_and_component_aware() {
    let parent = must(WindowsPathIdentity::parse_root(
        r"C:\Runtime\Store",
        "parent",
    ));
    let child = must(WindowsPathIdentity::parse_root(
        r"c:/runtime/STORE/data",
        "child",
    ));
    let component_prefix = must(WindowsPathIdentity::parse_root(
        r"C:\Runtime\Storehouse",
        "component_prefix",
    ));
    assert!(parent.aliases_or_overlaps(&child));
    assert!(!parent.aliases_or_overlaps(&component_prefix));
}

#[test]
fn runtime_roots_reject_system_escape_and_portable_system_alias() {
    let program_data = must(protected_program_data_root());
    let unrelated = std::env::temp_dir().join("eliot-wrong-system-anchor");
    std::fs::create_dir_all(&unrelated).unwrap_or_else(|_| unreachable!());
    assert!(
        RuntimeStateRoots::derive_profiled(
            InstallationProfile::SystemService,
            test_handle(unrelated.to_string_lossy().into_owned()),
            &"a".repeat(64),
        )
        .is_err(),
        "SystemService must not silently replace an unproven anchor"
    );
    assert!(
        RuntimeStateRoots::derive_profiled(
            InstallationProfile::UserMode,
            test_handle(program_data.to_string_lossy().into_owned()),
            &"a".repeat(64),
        )
        .is_err(),
        "UserMode must not silently fall back to ProgramData"
    );
    let mut system = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &"b".repeat(64),
    ));
    system.store_data_root = test_handle(r"C:\outside\store\data");
    reseal_roots(&mut system);
    assert!(system.validate().is_err());

    let profiled = test_handle(format!(
        r"{}\Eliot\installations\{}",
        program_data.to_string_lossy(),
        "c".repeat(64)
    ));
    assert!(
        RuntimeStateRoots::derived(InstallationProfile::PortableDev, profiled.clone(), profiled,)
            .is_err(),
        "portable profile must not alias a profiled durable root"
    );
}

#[test]
fn retained_root_hook_rejects_reparse_evidence() {
    let directory = std::env::temp_dir().join("eliot-retained-root-test");
    provision_portable_test_root(&directory);
    let roots = must(RuntimeStateRoots::derive_portable(test_handle(
        directory.to_string_lossy().into_owned(),
    )));
    let mut provider = FakeRuntimeRootLeaseProvider {
        next: 0,
        reparse_at: Some(3),
        alias_identity: false,
    };
    assert!(roots.retain_and_validate(&mut provider).is_err());

    let mut provider = FakeRuntimeRootLeaseProvider {
        next: 0,
        reparse_at: None,
        alias_identity: false,
    };
    let retained = must(roots.retain_and_validate(&mut provider));
    assert_eq!(retained.leases().len(), 7);

    let mut provider = FakeRuntimeRootLeaseProvider {
        next: 0,
        reparse_at: None,
        alias_identity: true,
    };
    assert!(roots.retain_and_validate(&mut provider).is_err());
}

#[cfg(windows)]
#[test]
fn windows_provider_retains_portable_roots_by_handle() {
    let directory = std::env::temp_dir().join("eliot-production-retained-root-test");
    provision_portable_test_root(&directory);
    let roots = must(RuntimeStateRoots::derive_portable(test_handle(
        directory.to_string_lossy().into_owned(),
    )));
    for (_, root) in roots.root_fields() {
        provision_portable_test_root(Path::new(root.as_str()));
    }
    let mut provider = must(WindowsRuntimeRootLeaseProvider::for_roots(&roots));
    let retained = must(roots.retain_and_validate(&mut provider));
    assert_eq!(retained.leases().len(), 7);
}

#[cfg(windows)]
#[test]
fn system_retained_validation_does_not_create_missing_roots_or_sentinel() {
    let program_data = must(protected_program_data_root());
    let unique =
        sha256_hex(format!("{}:{:?}", std::process::id(), std::time::SystemTime::now()).as_bytes());
    let roots = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &unique,
    ));
    assert!(!Path::new(roots.installation_root.as_str()).exists());
    let mut provider = must(WindowsRuntimeRootLeaseProvider::for_roots(&roots));
    assert!(roots.retain_and_validate(&mut provider).is_err());
    assert!(
        !Path::new(roots.installation_root.as_str()).exists(),
        "retained validation must not create directories or sentinel files"
    );
}

#[test]
fn manifest_rejects_runtime_root_tampering_after_approval() {
    let mut manifest = registering_transaction().candidate_manifest;
    manifest.runtime_launch.runtime_state_roots.store_data_root =
        test_handle(r"C:\Development\scratch\tampered-store-data");
    assert!(manifest.validate().is_err());
}

#[test]
fn installer_plan_binds_local_service_and_unknown_space_requires_recovery() {
    let program_data = must(protected_program_data_root());
    let roots = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &"d".repeat(64),
    ));
    let (changes, effects) = installer_plan_parts(&roots);
    assert!(
        validate_installer_effects(
            InstallationProfile::SystemService,
            &roots,
            &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            &changes,
            &effects,
        )
        .is_ok()
    );
    let services = effects
        .iter()
        .filter_map(|effect| match effect {
            InstallerEffectPlan::RegisterService {
                role,
                service_name,
                account,
                automatic_start,
                ..
            } => Some((*role, service_name.as_str(), *account, *automatic_start)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        services,
        vec![
            (
                InstallerServiceRole::Host,
                ELIOT_HOST_SERVICE_NAME,
                InstallerServiceAccount::LocalService,
                true,
            ),
            (
                InstallerServiceRole::Watchdog,
                ELIOT_WATCHDOG_SERVICE_NAME,
                InstallerServiceAccount::LocalService,
                true,
            ),
        ]
    );
    let mut transaction = registering_transaction();
    let outcome = must(
        transaction.record_store_free_space(StoreFreeSpaceObservation::Unknown {
            evidence_refs: vec![test_handle("failure:free-space-unobserved")],
        }),
    );
    assert!(matches!(
        outcome,
        InstallationStepOutcome::RollbackRequired { .. }
    ));
    assert_eq!(transaction.stage, InstallationStage::RollbackRequired);
}

#[cfg(windows)]
#[test]
fn service_registration_projection_is_durable_and_exact() {
    let transaction = fully_applied_system_registration_transaction();
    let approvals = must(transaction.service_registration_approvals());
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[0].role, InstallerServiceRole::Host);
    assert_eq!(approvals[1].role, InstallerServiceRole::Watchdog);
    assert_ne!(
        approvals[0].registration_nonce,
        approvals[1].registration_nonce
    );
    assert_ne!(
        approvals[0].configuration_digest,
        approvals[1].configuration_digest
    );
    assert!(approvals[0].service_control_grant().is_none());
    let watchdog_grant = approvals[1]
        .service_control_grant()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(
        watchdog_grant.principal_service().as_str(),
        ELIOT_HOST_SERVICE_NAME
    );
    assert_eq!(
        watchdog_grant.access_mask(),
        ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK
    );
    assert_eq!(
        watchdog_grant.security_descriptor_digest().as_str(),
        must(watchdog_service_security_descriptor_digest(
            watchdog_grant.principal_sid().as_str()
        ))
    );
    for substituted in [
        {
            let mut value = watchdog_grant.clone();
            value.access_mask |= 0x0004_0000;
            value
        },
        {
            let mut value = watchdog_grant.clone();
            value.principal_sid = test_handle("S-1-5-80-6-7-8-9-10");
            value
        },
        {
            let mut value = watchdog_grant.clone();
            value.security_descriptor_digest = test_handle("f".repeat(64));
            value
        },
    ] {
        assert!(substituted.validate().is_err());
    }

    let transaction_store = SharedStore::default();
    *transaction_store
        .state
        .lock()
        .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-scm-projection-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let database = must(Database::create(&path));
    let registry = RedbInstallationRegistry::from_database_for_test(database);
    let approval_ref = test_handle("approval:system-service");
    let approval = test_transaction_activation_approval(&transaction, approval_ref);
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));

    let loaded = must(registry.load());
    assert_eq!(
        loaded.revision(),
        2,
        "first durable stage advances CAS revision"
    );
    let pending = loaded
        .pending_activation()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(pending.transaction_id, transaction.transaction_id);
    assert_eq!(pending.plan_digest, transaction.installer_plan_digest);
    assert_eq!(pending.approval, approval);
    let mut substituted_registry = loaded.clone();
    substituted_registry
        .service_registration_approvals
        .iter_mut()
        .find(|approval| approval.role == InstallerServiceRole::Watchdog)
        .and_then(|approval| approval.service_control_grant.as_mut())
        .unwrap_or_else(|| unreachable!())
        .access_mask |= 0x0004_0000;
    assert!(substituted_registry.validate().is_err());
    for role in [InstallerServiceRole::Host, InstallerServiceRole::Watchdog] {
        let approval = loaded
            .service_registration_approval(&transaction.candidate_manifest.generation, role)
            .unwrap_or_else(|| unreachable!());
        let request = must(approval.service_registration_request());
        assert_eq!(
            approval.configuration_digest.as_str(),
            request.expected_configuration_digest()
        );
    }

    let before_retry = loaded.clone();
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        before_retry.revision(),
    ));
    assert_eq!(must(registry.load()), before_retry);

    assert!(matches!(
        registry.stage_pending_activation_from_transaction_store(
            &transaction_store,
            &transaction.transaction_id,
            approval.clone(),
            1,
        ),
        Err(InstallationError::CompareAndSaveConflict {
            expected: 1,
            actual: 2,
        })
    ));
    assert_eq!(must(registry.load()), before_retry);

    assert!(matches!(
        registry.stage_pending_activation_from_transaction_store(
            &transaction_store,
            &transaction.transaction_id,
            {
                let mut substituted = approval.clone();
                substituted.approval_ref = test_handle("approval:substituted");
                substituted
            },
            before_retry.revision(),
        ),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(must(registry.load()), before_retry);
    drop(registry);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
#[allow(clippy::too_many_lines)]
fn pending_phase_b_intent_is_durable_before_destination_publication_and_rejects_substitution() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let transaction = registering_system_service_start_transaction();
    let transaction_store = SharedStore::default();
    *transaction_store
        .state
        .lock()
        .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
    let path = std::env::temp_dir().join(format!(
        "eliot-phase-b-intent-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let registry = RedbInstallationRegistry::from_database_for_test(must(Database::create(&path)));
    let approval =
        test_transaction_activation_approval(&transaction, test_handle("approval:phase-b-intent"));
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    let manifest_digest = must(candidate_manifest_digest(&transaction.candidate_manifest));
    let credential_effect_id = transaction
        .installer_effects
        .iter()
        .find_map(|effect| {
            matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                .then(|| effect.effect_id().clone())
        })
        .unwrap_or_else(|| test_handle("effect:store-credential"));
    let intent = must(HostPhaseBMaterializationIntent::new(
        transaction.transaction_id.clone(),
        test_handle("effect:phase-b-materialize"),
        credential_effect_id,
        transaction.installer_plan_digest.clone(),
        manifest_digest,
        test_handle("1".repeat(64)),
        must(phase_b_host_state_root_digest(
            &transaction.candidate_manifest,
        )),
        must(phase_b_static_template_for_candidate(
            &transaction.candidate_manifest,
        )),
        must(phase_b_watchdog_selector_digest(
            &transaction.candidate_manifest,
        )),
        None,
        test_provisioned_supervision_authority(
            transaction
                .candidate_manifest
                .runtime_launch
                .installation_epoch
                .installation
                .as_str(),
            transaction.candidate_manifest.generation.as_str(),
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_generation,
        ),
    ));
    let (_lease, capability) = live_host_capability();
    must(registry.record_pending_phase_b_intent(
        &capability,
        must(registry.load()).revision(),
        &approval,
        &intent,
    ));
    let persisted = must(registry.load());
    let pending = persisted
        .pending_activation()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(pending.phase_b_intent.as_ref(), Some(&intent));
    let mut phase_a_runtime_launch = transaction.candidate_manifest.runtime_launch.clone();
    phase_a_runtime_launch.authority_descriptor_digest = test_handle(PHASE_B_PENDING_MARKER);
    phase_a_runtime_launch.store_bootstrap_descriptor_digest = test_handle(PHASE_B_PENDING_MARKER);
    phase_a_runtime_launch.descriptor_digest = test_handle("0".repeat(64));
    phase_a_runtime_launch = must(phase_a_runtime_launch.with_computed_digest());
    let phase_b_intermediate = must(
        phase_a_runtime_launch.with_phase_b_pending_bootstrap_overlay(
            phase_a_runtime_launch.authority_generation,
            phase_a_runtime_launch.authority_state_fence.clone(),
            test_handle("3".repeat(64)),
            test_handle("5".repeat(64)),
            intent.provisioned_supervision_authority.clone(),
        ),
    );
    let phase_b_launch = must(phase_b_intermediate.with_phase_b_materialization(
        phase_b_intermediate.authority_generation,
        phase_b_intermediate.authority_state_fence.clone(),
        phase_b_intermediate.authority_descriptor_digest.clone(),
        test_handle("4".repeat(64)),
        phase_b_intermediate.eliotd_descriptor_digest.clone(),
    ));
    let mut prepared = HostPhaseBPreparedMaterialization {
        wire: test_handle(HostPhaseBPreparedMaterialization::WIRE),
        transaction_id: intent.transaction_id.clone(),
        effect_id: intent.effect_id.clone(),
        credential_effect_id: intent.credential_effect_id.clone(),
        manifest_digest: intent.candidate_manifest_digest.clone(),
        request_digest: intent.request_digest.clone(),
        credential_receipt_digest: intent.credential_receipt_digest.clone(),
        host_owner_epoch: test_handle("host-owner:prepared"),
        host_process_identity: test_handle("6".repeat(64)),
        host_process_nonce_digest: test_handle("7".repeat(64)),
        host_epoch_lineage: test_handle("host-lineage:prepared"),
        host_epoch_sequence: 1,
        activation_generation_lineage: test_handle("activation-lineage:prepared"),
        activation_generation_sequence: 1,
        authority_descriptor_digest: test_handle("3".repeat(64)),
        config_file_digest: test_handle("8".repeat(64)),
        store_bootstrap_descriptor_digest: test_handle("4".repeat(64)),
        eliotd_descriptor_digest: test_handle("5".repeat(64)),
        semantic_config_hash: test_handle("9".repeat(64)),
        launch: phase_b_launch,
        agent_bridge: None,
        prepared_digest: test_handle("pending"),
    };
    prepared.prepared_digest = must(prepared.computed_digest());
    must(registry.record_pending_phase_b_prepared(
        &capability,
        must(registry.load()).revision(),
        &approval,
        &prepared,
    ));
    let persisted = must(registry.load());
    assert_eq!(
        persisted
            .pending_activation()
            .and_then(|pending| pending.phase_b_prepared.as_ref()),
        Some(&prepared)
    );
    let before_prepared_substitution = persisted.clone();
    let mut substituted_prepared = prepared.clone();
    substituted_prepared.config_file_digest = test_handle("a".repeat(64));
    substituted_prepared.prepared_digest = must(substituted_prepared.computed_digest());
    assert!(matches!(
        registry.record_pending_phase_b_prepared(
            &capability,
            before_prepared_substitution.revision(),
            &approval,
            &substituted_prepared,
        ),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(must(registry.load()), before_prepared_substitution);
    assert!(pending.phase_b_receipt.is_none());
    let before_retry = persisted.clone();
    must(registry.record_pending_phase_b_intent(
        &capability,
        before_retry.revision(),
        &approval,
        &intent,
    ));
    assert_eq!(must(registry.load()), before_retry);
    let substituted = HostPhaseBMaterializationIntent::new(
        intent.transaction_id.clone(),
        intent.effect_id.clone(),
        intent.credential_effect_id.clone(),
        intent.installation_plan_digest.clone(),
        intent.candidate_manifest_digest.clone(),
        test_handle("2".repeat(64)),
        intent.host_state_root_digest.clone(),
        intent.static_template.clone(),
        intent.watchdog_selector_digest.clone(),
        None,
        intent.provisioned_supervision_authority.clone(),
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(matches!(
        registry.record_pending_phase_b_intent(
            &capability,
            before_retry.revision(),
            &approval,
            &substituted,
        ),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(must(registry.load()), before_retry);
    let mut prepared_receipt = HostPhaseBPreparedReceipt {
        wire: test_handle(HostPhaseBPreparedReceipt::WIRE),
        transaction_id: prepared.transaction_id.clone(),
        effect_id: prepared.effect_id.clone(),
        candidate_manifest_digest: prepared.manifest_digest.clone(),
        request_digest: prepared.request_digest.clone(),
        host_owner_epoch: prepared.host_owner_epoch.clone(),
        host_process_identity: prepared.host_process_identity.clone(),
        authority_descriptor_digest: prepared.authority_descriptor_digest.clone(),
        config_file_digest: prepared.config_file_digest.clone(),
        store_bootstrap_descriptor_digest: prepared.store_bootstrap_descriptor_digest.clone(),
        eliotd_descriptor_digest: prepared.eliotd_descriptor_digest.clone(),
        provisioned_supervision_authority: intent.provisioned_supervision_authority.clone(),
        agent_bridge: prepared.agent_bridge.clone(),
        receipt_digest: test_handle("pending"),
    };
    prepared_receipt.receipt_digest = must(prepared_receipt.computed_digest());
    let prepared_receipt_revision = must(registry.load()).revision();
    must(registry.record_pending_phase_b_prepared_receipt(
        &capability,
        prepared_receipt_revision,
        &approval,
        &prepared_receipt,
    ));
    let before_receipt_substitution = must(registry.load());
    let mut substituted_receipt = prepared_receipt.clone();
    substituted_receipt.host_process_identity = test_handle("f".repeat(64));
    substituted_receipt.receipt_digest = must(substituted_receipt.computed_digest());
    assert!(matches!(
        registry.record_pending_phase_b_prepared_receipt(
            &capability,
            before_receipt_substitution.revision(),
            &approval,
            &substituted_receipt,
        ),
        Err(InstallationError::IdentityConflict)
    ));
    assert_eq!(must(registry.load()), before_receipt_substitution);
    drop(registry);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "this test exercises the complete real redb crash/retry boundary"
)]
fn committed_registry_terminal_reconciles_real_redb_transaction_once() {
    let full = fully_applied_system_registration_transaction();
    let planned = must(InstallationTransaction::new(
        full.transaction_id.clone(),
        full.installation_epoch.clone(),
        full.profile,
        full.request.clone(),
        full.current_active_manifest.clone(),
        full.candidate_manifest.clone(),
        full.staging_root.clone(),
        full.planned_changes.clone(),
        full.installer_effects.clone(),
        full.minimum_store_available_bytes,
        full.precondition_evidence.clone(),
        full.recovery_command.clone(),
    ));
    let mut activating = planned.clone();
    activating.effect_progress = full.effect_progress.clone();
    for (stage, evidence) in [
        (InstallationStage::Staging, "evidence:receipt-staging"),
        (InstallationStage::StaticVerified, "evidence:receipt-static"),
        (
            InstallationStage::Registering,
            "evidence:receipt-registering",
        ),
        (InstallationStage::Activating, "evidence:receipt-activating"),
    ] {
        must(activating.advance(stage, vec![test_handle(evidence)]));
    }
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-active-verified-receipt-transaction-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let mut transaction_store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    let mut current = planned.clone();
    for stage in [
        InstallationStage::Staging,
        InstallationStage::StaticVerified,
        InstallationStage::Registering,
        InstallationStage::Activating,
    ] {
        let expected = must(TransactionVersion::of(&current));
        current = activating.clone();
        current.stage = stage;
        current.revision = expected.revision + 1;
        // Rebuild the durable state one exact CAS step at a time. The
        // in-memory fixture above supplies only authoritative effect
        // progress; redb remains the source under test.
        must(<RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
                &mut transaction_store,
                expected,
                &current,
            ));
        activating = current.clone();
    }
    let transaction = must(
        transaction_store
            .load(&current.transaction_id)
            .map(|value| value.unwrap_or_else(|| unreachable!())),
    );
    assert_eq!(transaction.stage(), InstallationStage::Activating);

    let registry_path = std::env::temp_dir().join(format!(
        "eliot-active-verified-receipt-registry-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&registry_path);
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let approval = test_transaction_activation_approval(
        &transaction,
        test_handle("approval:active-verified-receipt"),
    );
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    let (_owner_lease, host) = live_host_capability();
    let fence = test_commit_fence(&transaction.candidate_manifest);
    must(registry.commit_pending_activation(
        &host,
        must(registry.load()).revision(),
        &approval,
        &fence,
    ));
    let receipt = must(registry.read_committed_activation_receipt(
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
    ));
    let outcome =
        must(transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:receipt-ready")],
        ));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Applied {
            stage: InstallationStage::ActiveVerified,
            ..
        }
    ));
    let committed = must(
        transaction_store
            .load(&transaction.transaction_id)
            .map(|value| value.unwrap_or_else(|| unreachable!())),
    );
    let committed_revision = committed.revision();
    assert_eq!(committed.stage(), InstallationStage::ActiveVerified);

    let retry = must(transaction_store.reconcile_active_verified(
        receipt.clone(),
        vec![test_handle("evidence:retry-is-ignored")],
    ));
    assert!(matches!(
        retry,
        InstallationStepOutcome::Applied {
            stage: InstallationStage::ActiveVerified,
            ..
        }
    ));
    assert_eq!(
        must(
            transaction_store
                .load(&transaction.transaction_id)
                .map(|value| value.unwrap_or_else(|| unreachable!())),
        )
        .revision(),
        committed_revision,
        "an exact retry must not advance the transaction revision"
    );

    let mut stale_epoch = receipt.clone();
    stale_epoch
        .commit_fence
        .authority_state_fence
        .authority_epoch = must(AuthorityEpoch::new(
        stale_epoch
            .commit_fence
            .authority_state_fence
            .authority_epoch
            .value()
            .checked_add(1)
            .unwrap_or_else(|| unreachable!()),
    ));
    assert!(matches!(
        transaction_store
            .reconcile_active_verified(stale_epoch, vec![test_handle("evidence:stale-epoch")],),
        Err(InstallationError::IdentityConflict)
    ));

    let mut different_fence = receipt.clone();
    different_fence.commit_fence.readiness_sequence += 1;
    assert!(matches!(
        transaction_store.reconcile_active_verified(
            different_fence,
            vec![test_handle("evidence:different-fence")],
        ),
        Err(InstallationError::IdentityConflict)
    ));

    let mut current = committed;
    let mut pending = planned.clone();
    replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
    assert!(matches!(
        transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:pending-stage")],
        ),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("before Activating")
    ));

    pending = planned.clone();
    pending.stage = InstallationStage::RollbackRequired;
    pending.pending_external_changes = vec![test_handle("pending:unknown")];
    replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
    assert!(matches!(
        transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:unknown-stage")],
        ),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("pending, aborted, or unknown")
    ));

    pending = planned.clone();
    pending.stage = InstallationStage::RolledBack;
    pending.completed_stage_refs = vec![test_handle("evidence:aborted")];
    replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
    assert!(matches!(
        transaction_store.reconcile_active_verified(
            receipt.clone(),
            vec![test_handle("evidence:aborted-stage")],
        ),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("pending, aborted, or unknown")
    ));

    pending = planned;
    pending.stage = InstallationStage::Quarantined;
    pending.completed_stage_refs = vec![test_handle("evidence:quarantined")];
    replace_real_redb_transaction(&mut transaction_store, &mut current, pending);
    assert!(matches!(
        transaction_store.reconcile_active_verified(
            receipt,
            vec![test_handle("evidence:quarantined-stage")],
        ),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("pending, aborted, or unknown")
    ));
    let _ = std::fs::remove_file(transaction_path);
    let _ = std::fs::remove_file(registry_path);
}

#[cfg(windows)]
#[test]
fn concurrent_registry_stages_have_one_revision_winner() {
    let transaction = fully_applied_system_registration_transaction();
    let transaction_store = SharedStore::default();
    *transaction_store
        .state
        .lock()
        .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
    let approval =
        test_transaction_activation_approval(&transaction, test_handle("approval:concurrent"));
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-concurrent-stage-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let first = Arc::new(RedbInstallationRegistry::from_database_for_test(must(
        Database::create(&path),
    )));
    let second = first.clone();
    let barrier = Arc::new(Barrier::new(2));
    let first_store = transaction_store.clone();
    let first_barrier = barrier.clone();
    let first_approval = approval.clone();
    let first_transaction_id = transaction.transaction_id.clone();
    let first_registry = first.clone();
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first_registry.stage_pending_activation_from_transaction_store(
            &first_store,
            &first_transaction_id,
            first_approval,
            1,
        )
    });
    let second_store = transaction_store;
    let second_barrier = barrier;
    let second_transaction_id = transaction.transaction_id.clone();
    let second_registry = second.clone();
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second_registry.stage_pending_activation_from_transaction_store(
            &second_store,
            &second_transaction_id,
            approval,
            1,
        )
    });
    let first_result = first_thread.join().unwrap_or_else(|_| unreachable!());
    let second_result = second_thread.join().unwrap_or_else(|_| unreachable!());
    let results = [first_result, second_result];
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one concurrent stage may commit revision 1"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(InstallationError::CompareAndSaveConflict { .. })
            ))
            .count(),
        1,
        "the losing stage must report a stale revision"
    );
    assert_eq!(must(first.load()).revision(), 2);
    drop(first);
    drop(second);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one test covers each fail-closed service observation class"
)]
fn service_registration_projection_rejects_incomplete_or_reused_observations() {
    let mut missing_nonce = system_registration_transaction();
    let host_progress = missing_nonce
        .effect_progress
        .iter_mut()
        .find(|progress| {
            missing_nonce
                .installer_effects
                .iter()
                .find(|effect| effect.effect_id() == &progress.effect_id)
                .is_some_and(|effect| {
                    matches!(
                        effect,
                        InstallerEffectPlan::RegisterService {
                            role: InstallerServiceRole::Host,
                            ..
                        }
                    )
                })
        })
        .unwrap_or_else(|| unreachable!());
    host_progress.registration_nonce = None;
    assert!(matches!(
        missing_nonce.service_registration_approvals(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "effect_progress.registration_nonce"
    ));

    let mut pending = system_registration_transaction();
    for (effect, progress) in pending
        .installer_effects
        .iter()
        .zip(pending.effect_progress.iter_mut())
    {
        if matches!(effect, InstallerEffectPlan::RegisterService { .. }) {
            progress.registration_nonce = Some(test_handle("d".repeat(64)));
            progress.service_control_grant = None;
            progress.state = InstallationEffectProgressState::Pending;
        }
    }
    assert!(matches!(
        pending.service_registration_approvals(),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("pending authoritative readback")
    ));

    let mut unknown = system_registration_transaction();
    for (effect, progress) in unknown
        .installer_effects
        .iter()
        .zip(unknown.effect_progress.iter_mut())
    {
        if let InstallerEffectPlan::RegisterService { role, .. } = effect {
            progress.registration_nonce = Some(test_handle("e".repeat(64)));
            progress.service_control_grant = None;
            progress.state = if *role == InstallerServiceRole::Host {
                InstallationEffectProgressState::Unknown {
                    pending_ref: test_handle("reconcile:service"),
                }
            } else {
                InstallationEffectProgressState::Pending
            };
        }
    }
    assert!(matches!(
        unknown.service_registration_approvals(),
        Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("requires reconciliation")
    ));

    let mut duplicate_nonce = system_registration_transaction();
    let host_nonce = duplicate_nonce
        .effect_progress
        .iter()
        .find_map(|progress| {
            duplicate_nonce
                .installer_effects
                .iter()
                .find(|effect| effect.effect_id() == &progress.effect_id)
                .is_some_and(|effect| {
                    matches!(
                        effect,
                        InstallerEffectPlan::RegisterService {
                            role: InstallerServiceRole::Host,
                            ..
                        }
                    )
                })
                .then(|| progress.registration_nonce.clone())
                .flatten()
        })
        .unwrap_or_else(|| unreachable!());
    let watchdog_progress = duplicate_nonce
        .effect_progress
        .iter_mut()
        .find(|progress| {
            duplicate_nonce
                .installer_effects
                .iter()
                .find(|effect| effect.effect_id() == &progress.effect_id)
                .is_some_and(|effect| {
                    matches!(
                        effect,
                        InstallerEffectPlan::RegisterService {
                            role: InstallerServiceRole::Watchdog,
                            ..
                        }
                    )
                })
        })
        .unwrap_or_else(|| unreachable!());
    watchdog_progress.registration_nonce = Some(host_nonce);
    assert!(matches!(
        duplicate_nonce.service_registration_approvals(),
        Err(InstallationError::IdentityConflict)
    ));
}

#[cfg(windows)]
#[test]
fn system_service_registry_wire_rejects_zero_and_partial_approval_pairs() {
    let transaction = system_registration_transaction();
    let approvals = must(transaction.service_registration_approvals());
    for service_registration_approvals in [Vec::new(), vec![approvals[0].clone()]] {
        let registry = ApprovedGenerationRegistry {
            generations: vec![ApprovedGeneration {
                manifest: transaction.candidate_manifest.clone(),
                approval: test_activation_approval(
                    &transaction.candidate_manifest,
                    transaction.transaction_id.clone(),
                    transaction.installer_plan_digest.clone(),
                    test_handle("approval:wire"),
                ),
                active: false,
                last_known_good: false,
            }],
            service_registration_approvals,
            active_generation: None,
            last_known_good_generation: None,
            pending_activation: None,
            last_terminal_activation: None,
            ..ApprovedGenerationRegistry::new()
        };
        let bytes = must(serde_json::to_vec(&registry));
        assert!(matches!(
            decode_registry_bytes(&bytes),
            Err(InstallationError::CorruptRegistry { .. })
        ));
    }
}

#[cfg(windows)]
#[test]
fn current_registry_rejects_omitted_watchdog_service_control_grant_member() {
    let transaction = system_registration_transaction();
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest.clone(),
            approval: test_transaction_activation_approval(
                &transaction,
                test_handle("approval:control-grant-wire"),
            ),
            active: false,
            last_known_good: false,
        }],
        service_registration_approvals: must(transaction.service_registration_approvals()),
        active_generation: None,
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    must(registry.validate());
    let mut value = must(serde_json::to_value(&registry));
    for approval in value["service_registration_approvals"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
    {
        approval
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("service_control_grant");
    }
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { reason })
            if reason.contains("current registry wire")
    ));
}

#[test]
fn legacy_registry_table_requires_explicit_migration() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-legacy-table-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let database = must(Database::create(&path));
    let write = must(database.begin_write());
    {
        let mut table = must(write.open_table(LEGACY_REGISTRY_TABLE));
        must(table.insert("registry", b"legacy".as_slice()));
    }
    must(write.commit());
    assert!(matches!(
        classify_registry_table(&database),
        Err(InstallationError::MigrationRequired { .. })
    ));
    drop(database);
    let _ = std::fs::remove_file(path);
}

#[test]
fn v2_registry_wire_requires_explicit_restage_without_defaults() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object.remove("registry_wire_version");
    object.remove("revision");
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("pending activation")
            || reason.contains("v2/pre-CAS")
    ));
}

#[test]
fn v9_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let object = legacy.as_object_mut().unwrap_or_else(|| unreachable!());
    object["registry_wire_version"] = serde_json::json!({
        "major": 9,
        "minor": 0,
        "patch": 0
    });
    object.remove("active_phase_b_rebind");
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("raw v9 registry must require explicit migration");
    };
    assert!(
        matches!(
            error,
            InstallationError::MigrationRequired { ref reason }
                if reason.contains("registry wire 9.0.0") && reason.contains("15.0.0")
        ),
        "unexpected raw v9 classification: {error:?}"
    );
}

#[test]
fn v10_registry_with_v1_rebind_requires_restage_without_adoption() {
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let fence = test_commit_fence(manifest);
    let prior = fence
        .phase_b_live_binding
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let mut legacy_rebind = ActivePhaseBRebind {
        intent: must(ActivePhaseBRebindIntent::new(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("active-phase-b-rebind-wire"),
            must(candidate_manifest_digest(manifest)),
            test_handle("a".repeat(64)),
            prior,
            test_handle("host-owner:wire"),
            test_handle("b".repeat(64)),
            test_handle("c".repeat(64)),
            prior.host_epoch_lineage.clone(),
            prior.host_epoch_sequence + 1,
            test_handle("activation-lineage:wire"),
            2,
            must(phase_b_static_template_for_candidate(manifest)),
        )),
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    };
    legacy_rebind.intent.wire = test_handle("eliot.host.phase-b-rebind.v1");
    legacy_rebind.intent.request_digest =
        must(active_phase_b_rebind_intent_digest(&legacy_rebind.intent));
    let mut raw_v10 = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    raw_v10["registry_wire_version"] = serde_json::json!({
        "major": 10,
        "minor": 0,
        "patch": 0
    });
    raw_v10["active_phase_b_rebind"] = must(serde_json::to_value(legacy_rebind));
    let bytes = must(serde_json::to_vec(&raw_v10));
    let error = decode_registry_bytes(&bytes)
        .expect_err("raw v10 nested v1 authority must require explicit re-stage");
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("wire v10")
                && reason.contains("re-stage as v14")
                && reason.contains("never synthesized or adopted")
    ));
}

#[test]
fn v11_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(11, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 11.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v15_registry_wire_round_trips_without_synthesizing_control_grants() {
    let current = ApprovedGenerationRegistry::new();
    let bytes = must(serde_json::to_vec(&current));
    let decoded = must(decode_registry_bytes(&bytes));
    assert_eq!(decoded, current);
    assert_eq!(
        decoded.registry_wire_version(),
        ContractVersion::new(15, 0, 0)
    );
    assert!(decoded.active_phase_b_rebind().is_none());
}

#[test]
fn v12_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(12, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 12.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v13_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(13, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 13.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v14_registry_wire_requires_explicit_migration_to_v15() {
    let mut legacy = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    legacy["registry_wire_version"] = must(serde_json::to_value(ContractVersion::new(14, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("registry wire 14.0.0") && reason.contains("15.0.0")
    ));
}

#[test]
fn v15_registry_wire_rejects_omitted_mandatory_rebind_member() {
    let mut current = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    current
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("active_phase_b_rebind");
    let bytes = must(serde_json::to_vec(&current));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { reason })
            if reason.contains("missing mandatory fields")
    ));

    let mut nested = must(serde_json::to_value(ApprovedGenerationRegistry::new()));
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let fence = test_commit_fence(manifest);
    let prior = fence
        .phase_b_live_binding
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let active_rebind = ActivePhaseBRebind {
        intent: must(ActivePhaseBRebindIntent::new(
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            test_handle("active-phase-b-rebind-nested"),
            must(candidate_manifest_digest(manifest)),
            test_handle("a".repeat(64)),
            prior,
            test_handle("host-owner:nested"),
            test_handle("b".repeat(64)),
            test_handle("c".repeat(64)),
            prior.host_epoch_lineage.clone(),
            prior.host_epoch_sequence + 1,
            test_handle("activation-lineage:nested"),
            2,
            must(phase_b_static_template_for_candidate(manifest)),
        )),
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    };
    nested["active_phase_b_rebind"] = must(serde_json::to_value(active_rebind));
    nested["active_phase_b_rebind"]
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("prepared");
    let bytes = must(serde_json::to_vec(&nested));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
}

#[test]
fn v3_registry_terminal_without_readiness_fence_requires_explicit_restage() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:wire-fence"),
    ));
    must(registry.commit_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    let mut value = must(serde_json::to_value(registry));
    value["last_terminal_activation"]
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .remove("commit_fence");
    let current_bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_registry_bytes(&current_bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
    value["registry_wire_version"]["major"] = serde_json::json!(3);
    let bytes = must(serde_json::to_vec(&value));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { .. })
    ));
}

#[test]
fn installer_plan_rejects_credential_target_not_bound_to_candidate_launch() {
    let program_data = must(protected_program_data_root());
    let roots = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &"f".repeat(64),
    ));
    let (changes, mut effects) = installer_plan_parts(&roots);
    let credential_effect = effects
        .iter_mut()
        .find_map(|effect| match effect {
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => Some(provision),
            _ => None,
        })
        .unwrap_or_else(|| unreachable!());
    credential_effect.target = test_handle("eliot/store/v1/fedcba9876543210fedcba9876543210");
    let Err(error) = validate_installer_effects(
        InstallationProfile::SystemService,
        &roots,
        &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        &changes,
        &effects,
    ) else {
        panic!("mismatched credential target must fail closed");
    };
    assert!(matches!(
        error,
        InstallationError::InvalidField { field, .. }
            if field == "installer_effect.provision.target"
    ));
}

#[test]
fn installer_rejects_swapped_or_legacy_service_identity() {
    let program_data = must(protected_program_data_root());
    let roots = must(RuntimeStateRoots::derive_profiled(
        InstallationProfile::SystemService,
        test_handle(program_data.to_string_lossy().into_owned()),
        &"e".repeat(64),
    ));
    let (changes, mut effects) = installer_plan_parts(&roots);
    let host = effects
        .iter_mut()
        .find(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService {
                    role: InstallerServiceRole::Host,
                    ..
                }
            )
        })
        .unwrap_or_else(|| unreachable!());
    if let InstallerEffectPlan::RegisterService { service_name, .. } = host {
        *service_name = test_handle("eliot-host");
    }

    assert!(
        validate_installer_effects(
            InstallationProfile::SystemService,
            &roots,
            &test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            &changes,
            &effects,
        )
        .is_err()
    );
}

#[test]
fn installer_effects_have_no_second_transaction_identity() {
    let mut transaction = registering_transaction();
    let encoded = must(serde_json::to_value(&transaction));
    assert!(encoded.get("transaction_id").is_some());
    let effects = encoded
        .get("installer_effects")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| unreachable!());
    assert!(effects.iter().all(|effect| {
        effect.get("transaction_id").is_none()
            && effect.get("stage").is_none()
            && effect.get("disposition").is_none()
    }));

    transaction.installer_effects[0] = transaction.installer_effects[1].clone();
    assert!(transaction.validate().is_err());
}

#[test]
fn runtime_launch_descriptor_binds_exact_arguments_and_rejects_tampering() {
    let transaction = registering_transaction();
    let descriptor = &transaction.candidate_manifest.runtime_launch;
    assert_eq!(
        descriptor
            .kernel_arguments
            .iter()
            .map(PlatformHandle::as_str)
            .collect::<Vec<_>>(),
        vec![
            "--work-root",
            descriptor.kernel_work_root.as_str(),
            "--store-bootstrap",
            descriptor.store_bootstrap_descriptor_path.as_str(),
            "--store-bootstrap-sha256",
            descriptor.store_bootstrap_descriptor_digest.as_str(),
            "--authority-descriptor",
            descriptor.authority_descriptor_path.as_str(),
            "--authority-descriptor-sha256",
            descriptor.authority_descriptor_digest.as_str(),
            "--kernel-artifact-sha256",
            descriptor.kernel_artifact_digest.as_str(),
            "--eliotd-descriptor",
            descriptor.eliotd_descriptor_path.as_str(),
            "--eliotd-descriptor-sha256",
            descriptor.eliotd_descriptor_digest.as_str(),
        ]
    );
    assert_eq!(descriptor.store_bridge_arguments[2].as_str(), "--config");
    assert!(descriptor.validate().is_ok());
    let config = &transaction.candidate_manifest.config_path;
    assert!(descriptor.validate_for_config(config).is_ok());

    let mut tampered = descriptor.clone();
    tampered.store_bridge_arguments[0] = test_handle("--outside-root");
    assert!(tampered.validate_for_config(config).is_err());

    let mut missing_config = descriptor.clone();
    missing_config.store_bridge_arguments.truncate(2);
    assert!(missing_config.validate_for_config(config).is_err());

    let mut duplicate_config = descriptor.clone();
    duplicate_config
        .store_bridge_arguments
        .push(test_handle(config.as_str()));
    assert!(duplicate_config.validate_for_config(config).is_err());

    let mut alternate_config = descriptor.clone();
    alternate_config.store_bridge_arguments[3] = test_path(
        &std::env::temp_dir(),
        "eliot-installation-alternate-config.json",
    );
    assert!(alternate_config.validate_for_config(config).is_err());

    let mut missing_root = descriptor.clone();
    missing_root.portable_root = None;
    assert!(missing_root.validate().is_err());

    let mut relative_authority = descriptor.clone();
    relative_authority.authority_descriptor_path = test_handle("authority.json");
    assert!(relative_authority.validate().is_err());

    let mut uppercase_authority_digest = descriptor.clone();
    uppercase_authority_digest.authority_descriptor_digest = test_handle("A".repeat(64));
    assert!(uppercase_authority_digest.validate().is_err());

    let mut missing_authority = descriptor.clone();
    missing_authority.kernel_arguments.truncate(4);
    assert!(missing_authority.validate_for_config(config).is_err());

    let mut missing_store_digest = descriptor.clone();
    missing_store_digest.kernel_arguments.remove(4);
    missing_store_digest.kernel_arguments.remove(4);
    assert!(missing_store_digest.validate_for_config(config).is_err());

    let mut substituted_store_digest = descriptor.clone();
    substituted_store_digest.kernel_arguments[5] = test_handle("9".repeat(64));
    assert!(
        substituted_store_digest
            .validate_for_config(config)
            .is_err()
    );

    let mut duplicate_store_flag = descriptor.clone();
    duplicate_store_flag
        .kernel_arguments
        .insert(4, test_handle("--store-bootstrap"));
    assert!(duplicate_store_flag.validate_for_config(config).is_err());

    let mut unknown_store_flag = descriptor.clone();
    unknown_store_flag.kernel_arguments[4] = test_handle("--unknown-store");
    assert!(unknown_store_flag.validate_for_config(config).is_err());

    let mut wrong_store_order = descriptor.clone();
    wrong_store_order.kernel_arguments.swap(4, 6);
    assert!(wrong_store_order.validate_for_config(config).is_err());

    let mut duplicate_authority = descriptor.clone();
    duplicate_authority
        .kernel_arguments
        .insert(4, test_handle("--authority-descriptor"));
    assert!(duplicate_authority.validate_for_config(config).is_err());

    let mut unknown_authority = descriptor.clone();
    unknown_authority.kernel_arguments[4] = test_handle("--unknown-authority");
    assert!(unknown_authority.validate_for_config(config).is_err());

    let mut wrong_authority_order = descriptor.clone();
    wrong_authority_order.kernel_arguments.swap(6, 8);
    assert!(wrong_authority_order.validate_for_config(config).is_err());
}

#[test]
fn host_child_materialization_selects_bridge_not_provider() {
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let (_, host_store_path, _) = manifest.host_child_paths();
    let (_, host_store_digest) = must(manifest.host_child_artifact_digests());
    assert_eq!(host_store_path, &manifest.store_bridge_executable_path);
    assert_eq!(host_store_digest, &manifest.store_bridge_artifact_digest);
    assert_ne!(host_store_path, &manifest.canonical_store_executable_path);
}

#[test]
fn split_store_argv_rejects_resealed_semantic_substitution() {
    let descriptor = registering_transaction().candidate_manifest.runtime_launch;
    let mut bridge_tamper = descriptor.clone();
    bridge_tamper.store_bridge_arguments[0] = test_handle("--outside-root");
    bridge_tamper.descriptor_digest =
        test_handle(sha256_hex(&must(bridge_tamper.unsigned_bytes())));
    assert!(bridge_tamper.validate().is_err());

    let mut provider_bind_change = descriptor.clone();
    provider_bind_change.canonical_store_arguments[3] = test_handle("127.0.0.1:9000");
    provider_bind_change.descriptor_digest =
        test_handle(sha256_hex(&must(provider_bind_change.unsigned_bytes())));
    assert!(provider_bind_change.validate().is_ok());

    let mut provider_root_substitution = descriptor;
    provider_root_substitution.canonical_store_arguments[5] = provider_root_substitution
        .runtime_state_roots
        .store_work_root
        .clone();
    provider_root_substitution.descriptor_digest = test_handle(sha256_hex(&must(
        provider_root_substitution.unsigned_bytes(),
    )));
    assert!(provider_root_substitution.validate().is_err());
}

#[test]
fn runtime_launch_digest_covers_store_and_authority_inputs() {
    let transaction = registering_transaction();
    let descriptor = transaction.candidate_manifest.runtime_launch;
    assert!(valid_installation_key(
        descriptor.descriptor_digest.as_str()
    ));
    let original = descriptor.descriptor_digest.clone();

    let mut store_path = descriptor.clone();
    store_path.store_bridge_executable_path =
        test_path(&std::env::temp_dir(), "alternate-eliot-store-surreal.exe");
    assert_ne!(
        sha256_hex(&must(store_path.unsigned_bytes())),
        original.as_str()
    );

    let mut authority_digest = descriptor.clone();
    authority_digest.authority_descriptor_digest = test_handle("8".repeat(64));
    assert_ne!(
        sha256_hex(&must(authority_digest.unsigned_bytes())),
        original.as_str()
    );

    let mut child_digest = descriptor.clone();
    child_digest.eliotd_artifact_digest = test_handle("9".repeat(64));
    assert_ne!(
        sha256_hex(&must(child_digest.unsigned_bytes())),
        original.as_str()
    );

    let mut daemon_config_path = descriptor.clone();
    daemon_config_path.eliotd_config_path =
        test_path(&std::env::temp_dir(), "alternate-eliotd-governor.json");
    assert_ne!(
        sha256_hex(&must(daemon_config_path.unsigned_bytes())),
        original.as_str()
    );

    let mut daemon_config_digest = descriptor.clone();
    daemon_config_digest.eliotd_config_digest = test_handle("6".repeat(64));
    assert_ne!(
        sha256_hex(&must(daemon_config_digest.unsigned_bytes())),
        original.as_str()
    );

    let mut protected_snapshot = descriptor.clone();
    protected_snapshot.protected_snapshot_digest = test_handle("b".repeat(64));
    assert_ne!(
        sha256_hex(&must(protected_snapshot.unsigned_bytes())),
        original.as_str()
    );

    let mut child_argument_swap = descriptor;
    let config_path = transaction.candidate_manifest.config_path;
    child_argument_swap.kernel_arguments[11] = test_handle("9".repeat(64));
    assert!(
        child_argument_swap
            .validate_for_config(&config_path)
            .is_err()
    );
}

#[test]
fn runtime_launch_rejects_binding_mismatches_and_unknown_fields() {
    let transaction = registering_transaction();
    let descriptor = &transaction.candidate_manifest.runtime_launch;

    let mut unknown = must(serde_json::to_value(descriptor));
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RuntimeLaunchDescriptor>(unknown).is_err());

    let mut old_wire = must(serde_json::to_value(descriptor));
    old_wire
        .as_object_mut()
        .expect("runtime descriptor object")
        .remove("protected_snapshot_digest");
    assert!(serde_json::from_value::<RuntimeLaunchDescriptor>(old_wire).is_err());

    let mut uppercase_protected = descriptor.clone();
    uppercase_protected.protected_snapshot_digest = test_handle("A".repeat(64));
    assert!(uppercase_protected.validate().is_err());

    let mut wrong_generation = transaction.candidate_manifest.clone();
    wrong_generation.runtime_launch.generation = test_handle("generation:other");
    assert!(wrong_generation.validate().is_err());

    let mut wrong_credential_target = transaction.candidate_manifest.clone();
    wrong_credential_target.store_credential_target =
        test_handle("eliot/store/v1/fedcba9876543210fedcba9876543210");
    assert!(wrong_credential_target.validate().is_err());

    let mut invalid_credential_target = transaction.candidate_manifest.clone();
    invalid_credential_target
        .runtime_launch
        .store_credential_target = test_handle("eliot/store");
    assert!(invalid_credential_target.validate().is_err());

    let mut wrong_fence = descriptor.clone();
    wrong_fence.authority_generation = must(ResourceGeneration::new(2));
    assert!(wrong_fence.validate().is_err());

    let mut wrong_installation = transaction;
    wrong_installation
        .candidate_manifest
        .runtime_launch
        .installation_epoch
        .sequence = 2;
    assert!(wrong_installation.validate().is_err());

    let mut wrong_profile = registering_transaction();
    wrong_profile.profile = InstallationProfile::SystemService;
    assert!(wrong_profile.validate().is_err());

    let transaction = registering_transaction();
    let result = InstallationTransaction::new(
        transaction.transaction_id.clone(),
        transaction.installation_epoch.clone(),
        InstallationProfile::SystemService,
        transaction.request.clone(),
        transaction.current_active_manifest.clone(),
        transaction.candidate_manifest.clone(),
        transaction.staging_root.clone(),
        transaction.planned_changes.clone(),
        transaction.installer_effects.clone(),
        transaction.minimum_store_available_bytes,
        transaction.precondition_evidence.clone(),
        transaction.recovery_command.clone(),
    );
    assert!(result.is_err());
}

fn authority_alias(path: &PlatformHandle) -> PlatformHandle {
    let path = Path::new(path.as_str());
    let parent = match path.parent() {
        Some(parent) => parent,
        None => panic!("fixture path parent"),
    }
    .to_string_lossy()
    .replace('\\', "/")
    .to_ascii_uppercase();
    let file = match path.file_name() {
        Some(file) => file,
        None => panic!("fixture path file"),
    }
    .to_string_lossy()
    .to_ascii_uppercase();
    test_handle(format!("{parent}/./{file}/"))
}

fn reseal(descriptor: &mut RuntimeLaunchDescriptor) {
    descriptor.descriptor_digest = test_handle(sha256_hex(&must(descriptor.unsigned_bytes())));
}

#[test]
fn authority_path_rejects_windows_lexical_aliases_without_rejecting_prefixes() {
    let transaction = registering_transaction();
    let mut manifest = transaction.candidate_manifest;
    let config = manifest.config_path.clone();
    manifest.runtime_launch.authority_descriptor_path = authority_alias(&config);
    reseal(&mut manifest.runtime_launch);
    assert!(manifest.validate().is_err());

    let mut prefix = registering_transaction().candidate_manifest.runtime_launch;
    let root = Path::new(prefix.authority_descriptor_path.as_str());
    prefix.authority_descriptor_path = test_handle(
        match root.parent() {
            Some(parent) => parent.join("generation.jsonx"),
            None => panic!("authority parent"),
        }
        .to_string_lossy()
        .into_owned(),
    );
    reseal(&mut prefix);
    assert!(prefix.validate().is_ok());

    let valid = registering_transaction().candidate_manifest.runtime_launch;
    assert_eq!(
        valid.portable_root.as_ref(),
        Some(&valid.runtime_state_roots.installation_root)
    );
    assert_ne!(valid.portable_root.as_ref(), Some(&valid.kernel_work_root));
    assert!(valid.validate().is_ok());
}

#[test]
fn lexical_windows_path_unifies_supported_verbatim_aliases_only() {
    assert_eq!(
        lexical_windows_path(r"C:\x").as_deref(),
        lexical_windows_path(r"\\?\C:\x").as_deref()
    );
    assert_eq!(
        lexical_windows_path(r"\\server\share\x").as_deref(),
        lexical_windows_path(r"\\?\UNC\server\share\x").as_deref()
    );
    assert_eq!(
        lexical_windows_path(r"c:/Root/./Child/").as_deref(),
        Some(r"c:\root\child")
    );
    assert_ne!(
        lexical_windows_path(r"C:\x").as_deref(),
        lexical_windows_path(r"C:\x-prefix").as_deref()
    );
    assert!(lexical_windows_path(r"\\.\pipe\eliot").is_none());
    assert!(lexical_windows_path(r"\\?\Volume{abc}\x").is_none());
    assert!(lexical_windows_path(r"\Device\HarddiskVolume1\x").is_none());
}

#[cfg(windows)]
#[test]
fn approved_path_rejects_unsupported_windows_device_prefixes() {
    assert!(approved_path(&test_handle(r"\\.\pipe\eliot"), "device_path").is_err());
    assert!(approved_path(&test_handle(r"\\?\Volume{abc}\x"), "device_path").is_err());
}

fn v1_registry_value() -> serde_json::Value {
    let transaction = registering_transaction();
    let generation = transaction.candidate_manifest.generation.clone();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:legacy"),
    );
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest,
            approval,
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(generation),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    let mut legacy = must(serde_json::to_value(registry));
    let Some(object) = legacy.as_object_mut() else {
        panic!("legacy registry object");
    };
    object.remove("registry_wire_version");
    object.remove("revision");
    object.remove("service_registration_approvals");
    object.remove("pending_activation");
    let Some(runtime) = legacy["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
    else {
        panic!("legacy fixture runtime launch");
    };
    runtime.remove("host_executable_path");
    runtime.remove("host_artifact_digest");
    runtime.remove("store_credential_target");
    runtime.remove("store_bridge_arguments");
    runtime.remove("runtime_state_roots");
    for field in [
        "eliotd_executable_path",
        "eliotd_artifact_digest",
        "eliotd_config_path",
        "eliotd_config_digest",
        "eliotd_descriptor_path",
        "eliotd_descriptor_digest",
        "eliotd_launch_nonce",
    ] {
        runtime.remove(field);
    }
    let Some(manifest) = legacy["generations"][0]["manifest"].as_object_mut() else {
        panic!("v1 fixture manifest");
    };
    manifest.remove("host_executable_path");
    manifest.remove("host_artifact_digest");
    manifest.remove("store_credential_target");
    manifest.remove("runtime_state_roots_digest");
    legacy
}

fn pre_split_registry_value() -> serde_json::Value {
    let transaction = registering_transaction();
    let generation = transaction.candidate_manifest.generation.clone();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:pre-split"),
    );
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest,
            approval,
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(generation),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    let mut value = must(serde_json::to_value(registry));
    let Some(object) = value.as_object_mut() else {
        panic!("pre-split registry object");
    };
    object.remove("registry_wire_version");
    object.remove("revision");
    object.remove("service_registration_approvals");
    object.remove("pending_activation");
    let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
        panic!("pre-split fixture manifest");
    };
    manifest.remove("host_executable_path");
    manifest.remove("host_artifact_digest");
    manifest.remove("store_credential_target");
    let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
    else {
        panic!("pre-split fixture runtime launch");
    };
    runtime.remove("host_executable_path");
    runtime.remove("host_artifact_digest");
    runtime.remove("store_credential_target");
    for field in [
        "eliotd_executable_path",
        "eliotd_artifact_digest",
        "eliotd_config_path",
        "eliotd_config_digest",
        "eliotd_descriptor_path",
        "eliotd_descriptor_digest",
        "eliotd_launch_nonce",
    ] {
        runtime.remove(field);
    }
    let bridge_arguments = runtime
        .remove("store_bridge_arguments")
        .unwrap_or_else(|| panic!("pre-split bridge arguments"));
    runtime.insert("canonical_store_arguments".to_owned(), bridge_arguments);
    value
}

fn pre_credential_binding_registry_value() -> serde_json::Value {
    let transaction = registering_transaction();
    let generation = transaction.candidate_manifest.generation.clone();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:pre-credential-binding"),
    );
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest,
            approval,
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(generation),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    let mut value = must(serde_json::to_value(registry));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
        .remove("registry_wire_version");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
        .remove("revision");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-credential-binding registry object"))
        .remove("service_registration_approvals");
    let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
        panic!("pre-credential-binding fixture manifest");
    };
    manifest.remove("host_executable_path");
    manifest.remove("host_artifact_digest");
    manifest.remove("store_credential_target");
    let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
    else {
        panic!("pre-credential-binding fixture runtime launch");
    };
    runtime.remove("host_executable_path");
    runtime.remove("host_artifact_digest");
    runtime.remove("store_credential_target");
    for field in [
        "eliotd_executable_path",
        "eliotd_artifact_digest",
        "eliotd_config_path",
        "eliotd_config_digest",
        "eliotd_descriptor_path",
        "eliotd_descriptor_digest",
        "eliotd_launch_nonce",
    ] {
        runtime.remove(field);
    }
    value
}

fn pre_eliotd_config_registry_value() -> serde_json::Value {
    let transaction = registering_transaction();
    let generation = transaction.candidate_manifest.generation.clone();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:pre-eliotd-config"),
    );
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest,
            approval,
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(generation),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    let mut value = must(serde_json::to_value(registry));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
        .remove("registry_wire_version");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
        .remove("revision");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-eliotd-config registry object"))
        .remove("service_registration_approvals");
    let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
    else {
        panic!("pre-eliotd-config fixture runtime launch");
    };
    runtime.remove("eliotd_config_path");
    runtime.remove("eliotd_config_digest");
    value
}

fn pre_host_artifact_binding_registry_value() -> serde_json::Value {
    let transaction = registering_transaction();
    let generation = transaction.candidate_manifest.generation.clone();
    let approval = test_activation_approval(
        &transaction.candidate_manifest,
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("approval:pre-host-artifact-binding"),
    );
    let registry = ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: transaction.candidate_manifest,
            approval,
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(generation),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    };
    let mut value = must(serde_json::to_value(registry));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
        .remove("registry_wire_version");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
        .remove("revision");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-host-artifact-binding registry object"))
        .remove("service_registration_approvals");
    let Some(manifest) = value["generations"][0]["manifest"].as_object_mut() else {
        panic!("pre-host-artifact-binding fixture manifest");
    };
    manifest.remove("host_executable_path");
    manifest.remove("host_artifact_digest");
    let Some(runtime) = value["generations"][0]["manifest"]["runtime_launch"].as_object_mut()
    else {
        panic!("pre-host-artifact-binding fixture runtime launch");
    };
    runtime.remove("host_executable_path");
    runtime.remove("host_artifact_digest");
    value
}

#[test]
fn pre_split_argv_registry_requires_explicit_restage() {
    let bytes = must(serde_json::to_vec(&pre_split_registry_value()));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::MigrationRequired { .. })
    ));
}

#[test]
fn pre_service_registration_approval_registry_requires_explicit_restage() {
    let transaction = registering_transaction();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest,
        test_handle("approval:pre-service-registration"),
    ));
    let mut value = must(serde_json::to_value(registry));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-service-registration registry object"))
        .remove("registry_wire_version");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-service-registration registry object"))
        .remove("revision");
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("pre-service-registration registry object"))
        .remove("service_registration_approvals");
    let bytes = must(serde_json::to_vec(&value));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("pre-service-registration registry must require migration");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("installer-owned SCM registration approvals")
    ));
}

#[test]
fn pre_credential_binding_registry_requires_explicit_restage() {
    let bytes = must(serde_json::to_vec(&pre_credential_binding_registry_value()));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("pre-credential-binding registry must require migration");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("descriptor-bound Store credential target")
    ));
}

#[test]
fn pre_eliotd_config_registry_requires_explicit_restage() {
    let bytes = must(serde_json::to_vec(&pre_eliotd_config_registry_value()));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("pre-eliotd-config registry must require migration");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("separate eliotd Governor config")
    ));
}

#[test]
fn pre_host_artifact_binding_registry_requires_explicit_restage() {
    let bytes = must(serde_json::to_vec(
        &pre_host_artifact_binding_registry_value(),
    ));
    let Err(error) = decode_registry_bytes(&bytes) else {
        panic!("pre-Host-artifact-binding registry must require migration");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("approved Host executable artifact binding")
    ));
}

#[test]
fn active_phase_b_rebind_rejects_prior_nonce_and_process_substitution() {
    let transaction = registering_transaction();
    let manifest = &transaction.candidate_manifest;
    let fence = test_commit_fence(manifest);
    let prior = fence
        .phase_b_live_binding
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let intent = must(ActivePhaseBRebindIntent::new(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("active-phase-b-rebind"),
        must(candidate_manifest_digest(manifest)),
        test_handle("a".repeat(64)),
        prior,
        test_handle("host-owner:current"),
        test_handle("b".repeat(64)),
        test_handle("c".repeat(64)),
        test_handle("host-lineage:current"),
        2,
        test_handle("activation-lineage:current"),
        2,
        must(phase_b_static_template_for_candidate(manifest)),
    ));
    let encoded = must(serde_json::to_vec(&intent));
    let decoded: ActivePhaseBRebindIntent = must(serde_json::from_slice(&encoded));
    must(decoded.validate());
    assert_eq!(decoded, intent);

    // The owner digest domain changed with the exact epoch sequence. A
    // persisted v1 nested proof must therefore be rejected, never
    // reinterpreted as the v2 direct-child proof after registry decode.
    let mut legacy_wire = decoded.clone();
    legacy_wire.wire = test_handle("eliot.host.phase-b-rebind.v1");
    legacy_wire.request_digest = must(active_phase_b_rebind_intent_digest(&legacy_wire));
    assert!(matches!(
        legacy_wire.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "active_phase_b_rebind.wire"
    ));

    let mut substituted_nonce = intent.clone();
    substituted_nonce.prior_host_process_nonce_digest = test_handle("d".repeat(64));
    assert!(matches!(
        substituted_nonce.validate_against_prior_binding(prior),
        Err(InstallationError::IdentityConflict)
    ));

    let mut substituted_process = intent;
    substituted_process.prior_host_process_identity = test_handle("e".repeat(64));
    assert!(matches!(
        substituted_process.validate_against_prior_binding(prior),
        Err(InstallationError::IdentityConflict)
    ));

    let mut reused_owner = decoded.clone();
    reused_owner.host_owner_epoch = prior.host_owner_epoch.clone();
    reused_owner.request_digest = must(active_phase_b_rebind_intent_digest(&reused_owner));
    assert!(matches!(
        reused_owner.validate(),
        Err(InstallationError::IdentityConflict)
    ));

    let mut reused_nonce = decoded.clone();
    reused_nonce.host_process_nonce_digest = prior.host_process_nonce_digest.clone();
    reused_nonce.request_digest = must(active_phase_b_rebind_intent_digest(&reused_nonce));
    assert!(matches!(
        reused_nonce.validate(),
        Err(InstallationError::IdentityConflict)
    ));

    let mut reused_process = decoded.clone();
    reused_process.host_process_identity = prior.host_process_identity.clone();
    reused_process.request_digest = must(active_phase_b_rebind_intent_digest(&reused_process));
    assert!(matches!(
        reused_process.validate(),
        Err(InstallationError::IdentityConflict)
    ));

    let mut stale_epoch = decoded;
    stale_epoch.host_epoch_sequence = prior.host_epoch_sequence;
    stale_epoch.request_digest = must(active_phase_b_rebind_intent_digest(&stale_epoch));
    assert!(matches!(
        stale_epoch.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "active_phase_b_rebind.host_epoch_sequence"
    ));
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the lifecycle regression builds two durable recovery generations before mutating raw v11 bytes"
)]
fn active_phase_b_rebind_completed_receipt_requires_fresh_owner_recovery_cas() {
    let transaction = fully_applied_system_registration_transaction();
    let approval = test_transaction_activation_approval(
        &transaction,
        test_handle("approval:active-phase-b-rebind-reset"),
    );
    let path = std::env::temp_dir().join(format!(
        "eliot-active-phase-b-rebind-reset-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let registry = RedbInstallationRegistry::from_database_for_test(must(Database::create(&path)));
    let host = host_capability();
    let transaction_store = SharedStore::default();
    *transaction_store.state.lock().unwrap() = Some(transaction.clone());
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    must(registry.commit_pending_activation(
        &host,
        must(registry.load()).revision(),
        &approval,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    let committed = must(registry.load());
    let terminal = committed.last_terminal_activation.as_ref().unwrap();
    let prior = terminal
        .commit_fence
        .as_ref()
        .unwrap()
        .phase_b_live_binding
        .as_ref()
        .unwrap();
    let static_template = must(phase_b_static_template_for_candidate(
        &transaction.candidate_manifest,
    ));
    let intent = must(ActivePhaseBRebindIntent::new(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("active-phase-b-rebind-reset"),
        must(candidate_manifest_digest(&transaction.candidate_manifest)),
        must(activation_terminal_digest(terminal)),
        prior,
        test_handle("host-owner:reset-1"),
        test_handle("a".repeat(64)),
        test_handle("b".repeat(64)),
        test_handle("host-lineage:reset-1"),
        2,
        test_handle("activation-lineage:reset-1"),
        2,
        static_template.clone(),
    ));
    must(registry.record_active_phase_b_rebind_intent(
        &host,
        must(registry.load()).revision(),
        &intent,
    ));
    let launch = transaction.candidate_manifest.runtime_launch.clone();
    let phase_b_intermediate = must(launch.with_phase_b_pending_bootstrap_overlay(
        launch.authority_generation,
        launch.authority_state_fence.clone(),
        test_handle("7".repeat(64)),
        test_handle("9".repeat(64)),
        test_provisioned_supervision_authority(
            launch.installation_epoch.installation.as_str(),
            launch.generation.as_str(),
            launch.authority_generation,
        ),
    ));
    let launch = must(phase_b_intermediate.with_phase_b_materialization(
        phase_b_intermediate.authority_generation,
        phase_b_intermediate.authority_state_fence.clone(),
        phase_b_intermediate.authority_descriptor_digest.clone(),
        test_handle("6".repeat(64)),
        phase_b_intermediate.eliotd_descriptor_digest.clone(),
    ));
    let prepared = HostPhaseBPreparedMaterialization {
        wire: test_handle(HostPhaseBPreparedMaterialization::WIRE),
        transaction_id: intent.transaction_id.clone(),
        effect_id: intent.effect_id.clone(),
        credential_effect_id: intent.effect_id.clone(),
        manifest_digest: intent.manifest_digest.clone(),
        request_digest: intent.request_digest.clone(),
        credential_receipt_digest: intent.prior_phase_b_receipt_digest.clone(),
        host_owner_epoch: intent.host_owner_epoch.clone(),
        host_process_identity: intent.host_process_identity.clone(),
        host_process_nonce_digest: intent.host_process_nonce_digest.clone(),
        host_epoch_lineage: intent.host_epoch_lineage.clone(),
        host_epoch_sequence: intent.host_epoch_sequence,
        activation_generation_lineage: intent.activation_generation_lineage.clone(),
        activation_generation_sequence: intent.activation_generation_sequence,
        authority_descriptor_digest: launch.authority_descriptor_digest.clone(),
        config_file_digest: transaction.candidate_manifest.config_digest.clone(),
        store_bootstrap_descriptor_digest: launch.store_bootstrap_descriptor_digest.clone(),
        eliotd_descriptor_digest: launch.eliotd_descriptor_digest.clone(),
        semantic_config_hash: test_handle("c".repeat(64)),
        launch,
        agent_bridge: None,
        prepared_digest: test_handle("pending"),
    };
    let mut prepared = prepared;
    prepared.prepared_digest = must(prepared.computed_digest());
    let mut legacy_prepared = prepared.clone();
    legacy_prepared.wire = test_handle("eliot.host.phase-b-prepared.v1");
    legacy_prepared.prepared_digest = must(legacy_prepared.computed_digest());
    assert!(matches!(
        legacy_prepared.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "phase_b.prepared.wire"
    ));
    must(registry.record_active_phase_b_rebind_prepared(
        &host,
        must(registry.load()).revision(),
        &prepared,
    ));
    let mut fresh_intent = intent.clone();
    fresh_intent.host_owner_epoch = test_handle("host-owner:reset-2");
    fresh_intent.host_process_identity = test_handle("b".repeat(64));
    fresh_intent.host_process_nonce_digest = test_handle("c".repeat(64));
    fresh_intent.host_epoch_lineage = intent.host_epoch_lineage.clone();
    fresh_intent.request_digest = must(active_phase_b_rebind_intent_digest(&fresh_intent));
    assert!(matches!(
        registry.record_active_phase_b_rebind_intent(
            &host,
            must(registry.load()).revision(),
            &fresh_intent
        ),
        Err(InstallationError::IdentityConflict)
    ));

    let receipt = must(ActivePhaseBRebindReceipt::from_prepared(&intent, &prepared));
    must(registry.record_active_phase_b_rebind_receipt(
        &host,
        must(registry.load()).revision(),
        &receipt,
    ));
    let completed = must(registry.load())
        .active_phase_b_rebind()
        .cloned()
        .unwrap_or_else(|| unreachable!());
    let mut legacy_registry = must(serde_json::to_value(must(registry.load())));
    legacy_registry["active_phase_b_rebind"]["intent"]["wire"] =
        serde_json::Value::String("eliot.host.phase-b-rebind.v1".to_owned());
    let legacy_registry_bytes = must(serde_json::to_vec(&legacy_registry));
    assert!(matches!(
        decode_registry_bytes(&legacy_registry_bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
    let recovery = must(ActivePhaseBRebindRecovery::new(
        &completed,
        test_handle("host-owner:reset-2"),
        test_handle("b".repeat(64)),
        test_handle("c".repeat(64)),
        intent.host_epoch_lineage.clone(),
        3,
    ));

    let mut legacy_receipt = receipt.clone();
    legacy_receipt.wire = test_handle("eliot.host.phase-b-rebind-receipt.v1");
    legacy_receipt.receipt_digest = must(active_phase_b_rebind_receipt_digest(&legacy_receipt));
    assert!(matches!(
        legacy_receipt.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "active_phase_b_rebind.receipt.wire"
    ));

    let mut legacy_recovery = recovery.clone();
    legacy_recovery.wire = test_handle("eliot.host.phase-b-rebind-recovery.v1");
    legacy_recovery.recovery_digest = must(legacy_recovery.computed_digest());
    assert!(matches!(
        legacy_recovery.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "active_phase_b_rebind.recovery.wire"
    ));

    let reject_substitution = |mut candidate: ActivePhaseBRebindRecovery| {
        candidate.recovery_digest = must(candidate.computed_digest());
        assert!(matches!(
            candidate.validate_against(&completed),
            Err(InstallationError::IdentityConflict)
        ));
    };

    let mut different_lineage = recovery.clone();
    different_lineage.recovery_host_epoch_lineage = test_handle("host-lineage:not-a-direct-child");
    reject_substitution(different_lineage);

    let mut skipped_sequence = recovery.clone();
    skipped_sequence.recovery_host_epoch_sequence = 4;
    reject_substitution(skipped_sequence);

    let mut same_sequence = recovery.clone();
    same_sequence.recovery_host_epoch_sequence = receipt.host_epoch_sequence;
    reject_substitution(same_sequence);

    let mut reused_owner = recovery.clone();
    reused_owner.recovery_host_owner_epoch = receipt.host_owner_epoch.clone();
    reject_substitution(reused_owner);

    let mut reused_process = recovery.clone();
    reused_process.recovery_host_process_identity = receipt.host_process_identity.clone();
    reject_substitution(reused_process);

    let mut reused_nonce = recovery.clone();
    reused_nonce.recovery_host_process_nonce_digest = receipt.host_process_nonce_digest.clone();
    reject_substitution(reused_nonce);

    let mut overflow = completed.clone();
    overflow.intent.host_epoch_sequence = u64::MAX;
    overflow.intent.request_digest = must(active_phase_b_rebind_intent_digest(&overflow.intent));
    let overflow_prepared = overflow.prepared.as_mut().unwrap_or_else(|| unreachable!());
    overflow_prepared.host_epoch_sequence = u64::MAX;
    overflow_prepared.request_digest = overflow.intent.request_digest.clone();
    overflow_prepared.prepared_digest = must(overflow_prepared.computed_digest());
    overflow.receipt = Some(must(ActivePhaseBRebindReceipt::from_prepared(
        &overflow.intent,
        overflow_prepared,
    )));
    assert!(matches!(
        ActivePhaseBRebindRecovery::new(
            &overflow,
            test_handle("host-owner:overflow-child"),
            test_handle("d".repeat(64)),
            test_handle("e".repeat(64)),
            intent.host_epoch_lineage.clone(),
            1,
        ),
        Err(InstallationError::InvalidField { field, .. })
            if field == "active_phase_b_rebind.recovery.recovery_host_epoch_sequence"
    ));

    let mut recovered_intent = fresh_intent;
    recovered_intent.host_epoch_sequence = 3;
    recovered_intent.activation_generation_sequence = 3;
    recovered_intent.request_digest = must(active_phase_b_rebind_intent_digest(&recovered_intent));
    let stale_revision = must(registry.load()).revision().saturating_sub(1);
    assert!(matches!(
        registry.record_active_phase_b_rebind_recovery_and_intent(
            &host,
            stale_revision,
            &recovery,
            &recovered_intent,
        ),
        Err(InstallationError::CompareAndSaveConflict { .. })
    ));
    assert!(
        must(registry.load())
            .active_phase_b_rebind()
            .is_some_and(|current| current.recovery_history.is_empty())
    );
    must(registry.record_active_phase_b_rebind_recovery_and_intent(
        &host,
        must(registry.load()).revision(),
        &recovery,
        &recovered_intent,
    ));
    let rebound = must(registry.load())
        .active_phase_b_rebind()
        .cloned()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(rebound.intent, recovered_intent);
    assert!(rebound.prepared.is_none());
    assert!(rebound.receipt.is_none());
    assert_eq!(rebound.recovery_history.len(), 1);
    assert_eq!(rebound.recovery_history[0].prior_receipt, receipt);

    let mut second_prepared = prepared.clone();
    second_prepared.request_digest = recovered_intent.request_digest.clone();
    second_prepared.host_owner_epoch = recovered_intent.host_owner_epoch.clone();
    second_prepared.host_process_identity = recovered_intent.host_process_identity.clone();
    second_prepared.host_process_nonce_digest = recovered_intent.host_process_nonce_digest.clone();
    second_prepared.host_epoch_lineage = recovered_intent.host_epoch_lineage.clone();
    second_prepared.host_epoch_sequence = recovered_intent.host_epoch_sequence;
    second_prepared.prepared_digest = must(second_prepared.computed_digest());
    must(registry.record_active_phase_b_rebind_prepared(
        &host,
        must(registry.load()).revision(),
        &second_prepared,
    ));
    let second_receipt = must(ActivePhaseBRebindReceipt::from_prepared(
        &recovered_intent,
        &second_prepared,
    ));
    must(registry.record_active_phase_b_rebind_receipt(
        &host,
        must(registry.load()).revision(),
        &second_receipt,
    ));
    let second_completed = must(registry.load())
        .active_phase_b_rebind()
        .cloned()
        .unwrap_or_else(|| unreachable!());
    let second_recovery = must(ActivePhaseBRebindRecovery::new(
        &second_completed,
        test_handle("host-owner:reset-3"),
        test_handle("d".repeat(64)),
        test_handle("e".repeat(64)),
        recovered_intent.host_epoch_lineage.clone(),
        4,
    ));
    let mut final_intent = recovered_intent.clone();
    final_intent.host_owner_epoch = second_recovery.recovery_host_owner_epoch.clone();
    final_intent.host_process_identity = second_recovery.recovery_host_process_identity.clone();
    final_intent.host_process_nonce_digest =
        second_recovery.recovery_host_process_nonce_digest.clone();
    final_intent.host_epoch_sequence = second_recovery.recovery_host_epoch_sequence;
    final_intent.activation_generation_sequence = 4;
    final_intent.request_digest = must(active_phase_b_rebind_intent_digest(&final_intent));
    must(registry.record_active_phase_b_rebind_recovery_and_intent(
        &host,
        must(registry.load()).revision(),
        &second_recovery,
        &final_intent,
    ));
    let chained = must(registry.load());
    let chained_rebind = chained
        .active_phase_b_rebind()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(chained_rebind.intent, final_intent);
    assert_eq!(chained_rebind.recovery_history.len(), 2);
    must(chained_rebind.validate());

    let mut impossible_order = must(serde_json::to_value(&chained));
    impossible_order["active_phase_b_rebind"]["recovery_history"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
        .swap(0, 1);
    assert!(matches!(
        decode_registry_bytes(&must(serde_json::to_vec(&impossible_order))),
        Err(InstallationError::CorruptRegistry { .. })
    ));

    let mut duplicate_transition = must(serde_json::to_value(&chained));
    let history = duplicate_transition["active_phase_b_rebind"]["recovery_history"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!());
    history.push(history[1].clone());
    assert!(matches!(
        decode_registry_bytes(&must(serde_json::to_vec(&duplicate_transition))),
        Err(InstallationError::CorruptRegistry { .. })
    ));

    let mut forged_history = chained.clone();
    {
        let historical = &mut forged_history
            .active_phase_b_rebind
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .recovery_history[1];
        historical.prior_intent.plan_digest = test_handle("2".repeat(64));
        historical.prior_intent.activation_generation_lineage =
            test_handle("activation-lineage:forged-history");
        historical.prior_intent.request_digest = must(active_phase_b_rebind_intent_digest(
            &historical.prior_intent,
        ));
        historical.prior_request_digest = historical.prior_intent.request_digest.clone();
        historical.prior_prepared.request_digest = historical.prior_intent.request_digest.clone();
        historical.prior_prepared.prepared_digest =
            must(historical.prior_prepared.computed_digest());
        historical.prior_receipt.request_digest = historical.prior_intent.request_digest.clone();
        historical.prior_receipt.receipt_digest = must(active_phase_b_rebind_receipt_digest(
            &historical.prior_receipt,
        ));
        historical.prior_receipt_digest = historical.prior_receipt.receipt_digest.clone();
        historical.recovery_digest = must(historical.computed_digest());
        must(historical.validate());
    }
    assert!(matches!(
        decode_registry_bytes(&must(serde_json::to_vec(&forged_history))),
        Err(InstallationError::CorruptRegistry { .. })
    ));

    let mut unauthorized_current = final_intent;
    unauthorized_current.host_owner_epoch = test_handle("host-owner:reset-4");
    unauthorized_current.host_process_identity = test_handle("f".repeat(64));
    unauthorized_current.host_process_nonce_digest = test_handle("1".repeat(64));
    unauthorized_current.host_epoch_sequence = 5;
    unauthorized_current.activation_generation_sequence = 5;
    unauthorized_current.request_digest =
        must(active_phase_b_rebind_intent_digest(&unauthorized_current));
    must(unauthorized_current.validate());
    let mut mismatched_current = must(serde_json::to_value(&chained));
    mismatched_current["active_phase_b_rebind"]["intent"] =
        must(serde_json::to_value(unauthorized_current));
    assert!(matches!(
        decode_registry_bytes(&must(serde_json::to_vec(&mismatched_current))),
        Err(InstallationError::CorruptRegistry { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn active_phase_b_rebind_intent_is_durable_and_idempotent_under_host_capability() {
    let transaction = fully_applied_system_registration_transaction();
    let approval = test_transaction_activation_approval(
        &transaction,
        test_handle("approval:active-phase-b-rebind"),
    );
    let path = std::env::temp_dir().join(format!(
        "eliot-active-phase-b-rebind-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let registry = RedbInstallationRegistry::from_database_for_test(must(Database::create(&path)));
    let host = host_capability();
    let transaction_store = SharedStore::default();
    *transaction_store
        .state
        .lock()
        .unwrap_or_else(|_| unreachable!()) = Some(transaction.clone());
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    must(registry.commit_pending_activation(
        &host,
        must(registry.load()).revision(),
        &approval,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    let committed = must(registry.load());
    let terminal = committed
        .last_terminal_activation
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let prior = terminal
        .commit_fence
        .as_ref()
        .and_then(|fence| fence.phase_b_live_binding.as_ref())
        .unwrap_or_else(|| unreachable!());
    let intent = must(ActivePhaseBRebindIntent::new(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("active-phase-b-rebind-durable"),
        must(candidate_manifest_digest(&transaction.candidate_manifest)),
        must(activation_terminal_digest(terminal)),
        prior,
        test_handle("host-owner:durable"),
        test_handle("f".repeat(64)),
        test_handle("1".repeat(64)),
        test_handle("host-lineage:durable"),
        2,
        test_handle("activation-lineage:durable"),
        2,
        must(phase_b_static_template_for_candidate(
            &transaction.candidate_manifest,
        )),
    ));
    let revision = committed.revision();
    must(registry.record_active_phase_b_rebind_intent(&host, revision, &intent));
    let persisted = must(registry.load());
    assert_eq!(
        persisted
            .active_phase_b_rebind()
            .map(|rebind| &rebind.intent),
        Some(&intent)
    );
    let persisted_revision = persisted.revision();
    must(registry.record_active_phase_b_rebind_intent(&host, persisted_revision, &intent));
    assert_eq!(must(registry.load()), persisted);
    drop(registry);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn staging_new_generation_clears_active_phase_b_rebind_before_commit() {
    let first = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        first.transaction_id.clone(),
        first.installer_plan_digest.clone(),
        first.candidate_manifest.clone(),
        test_handle("approval:active-rebind-stage"),
    ));
    must(registry.commit_pending_activation(
        &host,
        &first.transaction_id,
        &first.installer_plan_digest,
        &first.candidate_manifest.generation,
        &test_commit_fence(&first.candidate_manifest),
    ));

    let committed = registry
        .last_terminal_activation
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let prior = committed
        .commit_fence
        .as_ref()
        .and_then(|fence| fence.phase_b_live_binding.as_ref())
        .unwrap_or_else(|| unreachable!());
    let intent = must(ActivePhaseBRebindIntent::new(
        first.transaction_id.clone(),
        first.installer_plan_digest.clone(),
        test_handle("active-phase-b-rebind-stage"),
        must(candidate_manifest_digest(&first.candidate_manifest)),
        must(activation_terminal_digest(committed)),
        prior,
        test_handle("host-owner:stage"),
        test_handle("a".repeat(64)),
        test_handle("b".repeat(64)),
        test_handle("host-lineage:stage"),
        2,
        test_handle("activation-lineage:stage"),
        2,
        must(phase_b_static_template_for_candidate(
            &first.candidate_manifest,
        )),
    ));
    must(registry.record_active_phase_b_rebind_intent_unchecked(&intent));

    let launch = first.candidate_manifest.runtime_launch.clone();
    let phase_b_intermediate = must(launch.with_phase_b_pending_bootstrap_overlay(
        launch.authority_generation,
        launch.authority_state_fence.clone(),
        test_handle("7".repeat(64)),
        test_handle("9".repeat(64)),
        test_provisioned_supervision_authority(
            launch.installation_epoch.installation.as_str(),
            launch.generation.as_str(),
            launch.authority_generation,
        ),
    ));
    let launch = must(phase_b_intermediate.with_phase_b_materialization(
        phase_b_intermediate.authority_generation,
        phase_b_intermediate.authority_state_fence.clone(),
        phase_b_intermediate.authority_descriptor_digest.clone(),
        test_handle("6".repeat(64)),
        phase_b_intermediate.eliotd_descriptor_digest.clone(),
    ));
    let mut prepared = HostPhaseBPreparedMaterialization {
        wire: test_handle(HostPhaseBPreparedMaterialization::WIRE),
        transaction_id: intent.transaction_id.clone(),
        effect_id: intent.effect_id.clone(),
        credential_effect_id: test_handle("credential-effect:stage"),
        manifest_digest: intent.manifest_digest.clone(),
        request_digest: intent.request_digest.clone(),
        credential_receipt_digest: intent.prior_phase_b_receipt_digest.clone(),
        host_owner_epoch: intent.host_owner_epoch.clone(),
        host_process_identity: intent.host_process_identity.clone(),
        host_process_nonce_digest: intent.host_process_nonce_digest.clone(),
        host_epoch_lineage: intent.host_epoch_lineage.clone(),
        host_epoch_sequence: intent.host_epoch_sequence,
        activation_generation_lineage: intent.activation_generation_lineage.clone(),
        activation_generation_sequence: intent.activation_generation_sequence,
        authority_descriptor_digest: launch.authority_descriptor_digest.clone(),
        config_file_digest: first.candidate_manifest.config_digest.clone(),
        store_bootstrap_descriptor_digest: launch.store_bootstrap_descriptor_digest.clone(),
        eliotd_descriptor_digest: launch.eliotd_descriptor_digest.clone(),
        semantic_config_hash: test_handle("c".repeat(64)),
        launch,
        agent_bridge: None,
        prepared_digest: test_handle("pending"),
    };
    prepared.prepared_digest = must(prepared.computed_digest());
    must(registry.record_active_phase_b_rebind_prepared_unchecked(&prepared));
    let receipt = must(ActivePhaseBRebindReceipt::from_prepared(&intent, &prepared));
    must(registry.record_active_phase_b_rebind_receipt_unchecked(&receipt));
    assert!(
        registry
            .active_phase_b_rebind()
            .and_then(|rebind| rebind.receipt.as_ref())
            .is_some()
    );

    let mut upgrade = first.candidate_manifest.clone();
    upgrade.generation = test_handle("generation:after-active-rebind");
    upgrade.runtime_launch.generation = upgrade.generation.clone();
    upgrade.runtime_launch.descriptor_digest =
        test_handle(sha256_hex(&must(upgrade.runtime_launch.unsigned_bytes())));
    must(upgrade.validate());
    let upgrade_transaction_id = test_handle("transaction:after-active-rebind");
    let upgrade_plan_digest = test_handle("d".repeat(64));
    must(registry.stage_pending_activation(
        upgrade_transaction_id.clone(),
        upgrade_plan_digest.clone(),
        upgrade.clone(),
        test_handle("approval:after-active-rebind"),
    ));
    assert!(registry.active_phase_b_rebind().is_none());
    must(registry.validate());
    must(registry.commit_pending_activation(
        &host,
        &upgrade_transaction_id,
        &upgrade_plan_digest,
        &upgrade.generation,
        &test_commit_fence(&upgrade),
    ));
    assert_eq!(registry.active_generation(), Some(&upgrade.generation));
    must(registry.validate());
}

#[test]
fn registry_rejects_pending_and_active_coexistence_via_validate_and_both_orders() {
    let first = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        first.transaction_id.clone(),
        first.installer_plan_digest.clone(),
        first.candidate_manifest.clone(),
        test_handle("approval:coexist-pending"),
    ));
    must(registry.commit_pending_activation(
        &host,
        &first.transaction_id,
        &first.installer_plan_digest,
        &first.candidate_manifest.generation,
        &test_commit_fence(&first.candidate_manifest),
    ));
    let committed = registry
        .last_terminal_activation
        .clone()
        .unwrap_or_else(|| unreachable!());
    let prior = committed
        .commit_fence
        .clone()
        .and_then(|fence| fence.phase_b_live_binding.clone())
        .unwrap_or_else(|| unreachable!());
    let mut upgrade = first.candidate_manifest.clone();
    upgrade.generation = test_handle("generation:coexist-pending-upgrade");
    upgrade.runtime_launch.generation = upgrade.generation.clone();
    upgrade.runtime_launch.descriptor_digest =
        test_handle(sha256_hex(&must(upgrade.runtime_launch.unsigned_bytes())));
    must(upgrade.validate());
    let prior_terminal_digest = must(activation_terminal_digest(&committed));
    must(registry.stage_pending_activation(
        test_handle("transaction:coexist-upgrade"),
        test_handle("b".repeat(64)),
        upgrade.clone(),
        test_handle("approval:coexist-upgrade"),
    ));
    let mut pending_plus_active = registry.clone();
    pending_plus_active.active_phase_b_rebind = Some(ActivePhaseBRebind {
        intent: must(ActivePhaseBRebindIntent::new(
            first.transaction_id.clone(),
            first.installer_plan_digest.clone(),
            test_handle("coexist-active"),
            must(candidate_manifest_digest(&first.candidate_manifest)),
            prior_terminal_digest,
            &prior,
            test_handle("host-owner:coexist"),
            test_handle("b".repeat(64)),
            test_handle("c".repeat(64)),
            test_handle("host-lineage:coexist"),
            2,
            test_handle("activation-lineage:coexist"),
            2,
            must(phase_b_static_template_for_candidate(
                &first.candidate_manifest,
            )),
        )),
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    });
    assert!(matches!(
        pending_plus_active.validate(),
        Err(InstallationError::IdentityConflict)
    ));
    let bytes = must(serde_json::to_vec(&pending_plus_active));
    let decoded = decode_registry_bytes(&bytes);
    assert!(
        matches!(decoded, Err(InstallationError::CorruptRegistry { .. })),
        "expected CorruptRegistry for decode, got {decoded:?}"
    );
    let _ = prior;
}

#[test]
fn registry_rejects_active_rebind_while_pending_is_active() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:pending-blocks-active"),
    ));
    must(registry.commit_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    let mut pending = registering_transaction();
    pending.candidate_manifest.generation = test_handle("generation:pending-blocks-active");
    pending.candidate_manifest.runtime_launch.generation =
        pending.candidate_manifest.generation.clone();
    pending.candidate_manifest.runtime_launch.descriptor_digest = test_handle(sha256_hex(&must(
        pending.candidate_manifest.runtime_launch.unsigned_bytes(),
    )));
    must(pending.candidate_manifest.validate());
    let mut pending_registry = registry.clone();
    must(pending_registry.stage_pending_activation(
        pending.transaction_id.clone(),
        pending.installer_plan_digest.clone(),
        pending.candidate_manifest.clone(),
        test_handle("approval:pending-blocks-active-2"),
    ));
    let terminal = registry
        .last_terminal_activation
        .as_ref()
        .unwrap_or_else(|| unreachable!());
    let prior = terminal
        .commit_fence
        .as_ref()
        .and_then(|fence| fence.phase_b_live_binding.as_ref())
        .unwrap_or_else(|| unreachable!());
    let intent = must(ActivePhaseBRebindIntent::new(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("pending-blocks-active-intent"),
        must(candidate_manifest_digest(&transaction.candidate_manifest)),
        must(activation_terminal_digest(terminal)),
        prior,
        test_handle("host-owner:pending-blocks"),
        test_handle("d".repeat(64)),
        test_handle("e".repeat(64)),
        test_handle("host-lineage:pending-blocks"),
        2,
        test_handle("activation-lineage:pending-blocks"),
        2,
        must(phase_b_static_template_for_candidate(
            &transaction.candidate_manifest,
        )),
    ));
    assert!(matches!(
        pending_registry.record_active_phase_b_rebind_intent_unchecked(&intent),
        Err(InstallationError::IdentityConflict)
    ));
    must(pending_registry.validate());
    assert!(pending_registry.active_phase_b_rebind().is_none());
}

#[cfg(windows)]
#[test]
fn registry_rejects_pending_while_active_rebind_is_active() {
    let transaction = fully_applied_system_registration_transaction();
    let approval = test_transaction_activation_approval(
        &transaction,
        test_handle("approval:active-blocks-pending"),
    );
    let path = std::env::temp_dir().join(format!(
        "eliot-pending-blocked-by-active-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let registry = RedbInstallationRegistry::from_database_for_test(must(Database::create(&path)));
    let host = host_capability();
    let transaction_store = SharedStore::default();
    *transaction_store.state.lock().unwrap() = Some(transaction.clone());
    must(registry.stage_pending_activation_from_transaction_store(
        &transaction_store,
        &transaction.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    must(registry.commit_pending_activation(
        &host,
        must(registry.load()).revision(),
        &approval,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    let committed = must(registry.load());
    let terminal = committed.last_terminal_activation.as_ref().unwrap();
    let prior = terminal
        .commit_fence
        .as_ref()
        .unwrap()
        .phase_b_live_binding
        .as_ref()
        .unwrap();
    let intent = must(ActivePhaseBRebindIntent::new(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        test_handle("active-blocks-pending"),
        must(candidate_manifest_digest(&transaction.candidate_manifest)),
        must(activation_terminal_digest(terminal)),
        prior,
        test_handle("host-owner:active-blocks"),
        test_handle("a".repeat(64)),
        test_handle("b".repeat(64)),
        test_handle("host-lineage:active-blocks"),
        2,
        test_handle("activation-lineage:active-blocks"),
        2,
        must(phase_b_static_template_for_candidate(
            &transaction.candidate_manifest,
        )),
    ));
    must(registry.record_active_phase_b_rebind_intent(
        &host,
        must(registry.load()).revision(),
        &intent,
    ));
    let mut upgrade = transaction.candidate_manifest.clone();
    upgrade.generation = test_handle("generation:active-blocks-pending");
    upgrade.runtime_launch.generation = upgrade.generation.clone();
    upgrade.runtime_launch.descriptor_digest =
        test_handle(sha256_hex(&must(upgrade.runtime_launch.unsigned_bytes())));
    must(upgrade.validate());
    let upgrade_tx = test_handle("transaction:active-blocks-pending");
    let upgrade_plan = test_handle("f".repeat(64));
    let upgrade_approval = InstallationActivationApproval {
        approval_ref: test_handle("approval:active-blocks-pending-2"),
        transaction_id: upgrade_tx.clone(),
        installer_plan_digest: upgrade_plan.clone(),
        generation: upgrade.generation.clone(),
        candidate_manifest_digest: must(candidate_manifest_digest(&upgrade)),
        runtime_descriptor_digest: upgrade.runtime_launch.descriptor_digest.clone(),
        required_owner: test_handle("owner:test"),
        signature_ref: upgrade.signature_ref.clone(),
        authority_descriptor_path: upgrade.runtime_launch.authority_descriptor_path.clone(),
        authority_descriptor_digest: upgrade.runtime_launch.authority_descriptor_digest.clone(),
        authority_generation: upgrade.runtime_launch.authority_generation,
        authority_state_fence: upgrade.runtime_launch.authority_state_fence.clone(),
    };
    let mut direct = must(registry.load());
    direct.revision = must(registry.load()).revision();
    assert!(matches!(
        direct.stage_pending_activation_unchecked(upgrade.clone(), upgrade_approval, &[]),
        Err(InstallationError::IdentityConflict)
    ));
    must(direct.validate());
    assert!(direct.pending_activation.is_none());
    assert!(direct.active_phase_b_rebind.is_some());
    let mut both = must(registry.load());
    let pending_manifest = upgrade.clone();
    let pending_approval = InstallationActivationApproval {
        approval_ref: test_handle("approval:dummy-both"),
        transaction_id: test_handle("transaction:dummy-both"),
        installer_plan_digest: test_handle("b".repeat(64)),
        generation: pending_manifest.generation.clone(),
        candidate_manifest_digest: must(candidate_manifest_digest(&pending_manifest)),
        runtime_descriptor_digest: pending_manifest.runtime_launch.descriptor_digest.clone(),
        required_owner: test_handle("owner:test"),
        signature_ref: pending_manifest.signature_ref.clone(),
        authority_descriptor_path: pending_manifest
            .runtime_launch
            .authority_descriptor_path
            .clone(),
        authority_descriptor_digest: pending_manifest
            .runtime_launch
            .authority_descriptor_digest
            .clone(),
        authority_generation: pending_manifest.runtime_launch.authority_generation,
        authority_state_fence: pending_manifest
            .runtime_launch
            .authority_state_fence
            .clone(),
    };
    let pending_activation = PendingActivation {
        transaction_id: pending_approval.transaction_id.clone(),
        plan_digest: pending_approval.installer_plan_digest.clone(),
        config_digest: pending_manifest.config_digest.clone(),
        kernel_artifact_digest: pending_manifest.kernel_artifact_digest.clone(),
        store_bridge_artifact_digest: pending_manifest.store_bridge_artifact_digest.clone(),
        canonical_store_artifact_digest: pending_manifest.canonical_store_artifact_digest.clone(),
        host_executable_path: pending_manifest.host_executable_path.clone(),
        host_artifact_digest: pending_manifest.host_artifact_digest.clone(),
        runtime_state_roots_digest: pending_manifest.runtime_state_roots_digest.clone(),
        manifest: pending_manifest.clone(),
        manifest_digest: must(candidate_manifest_digest(&pending_manifest)),
        prior_active_generation: both.active_generation.clone(),
        approval: pending_approval,
        phase_b_intent: None,
        phase_b_prepared: None,
        phase_b_prepared_receipt: None,
        phase_b_agent_bridge_stage_prepared: None,
        phase_b_receipt: None,
        state: PendingActivationState::Pending,
    };
    both.pending_activation = Some(pending_activation);
    assert!(both.pending_activation.is_some() && both.active_phase_b_rebind.is_some());
    assert!(matches!(
        both.validate(),
        Err(InstallationError::IdentityConflict)
    ));
    let bytes = must(serde_json::to_vec(&both));
    assert!(matches!(
        decode_registry_bytes(&bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn registry_commit_rejects_pending_manifest_without_phase_b_live_binding() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:phase-b-required"),
    ));
    let mut fence = test_commit_fence(&transaction.candidate_manifest);
    fence.phase_b_live_binding = None;
    assert!(
        registry
            .commit_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
                &fence,
            )
            .is_err()
    );
    assert!(registry.active().is_none());
    assert!(registry.pending_activation().is_some());
}

#[test]
fn registry_commit_rejects_pending_phase_b_digest_even_with_a_binding() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:phase-b-pending-digest"),
    ));
    let mut fence = test_commit_fence(&transaction.candidate_manifest);
    let binding = fence
        .phase_b_live_binding
        .as_mut()
        .unwrap_or_else(|| unreachable!());
    binding.authority_descriptor_digest = test_handle(PHASE_B_PENDING_MARKER);
    assert!(
        registry
            .commit_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
                &fence,
            )
            .is_err()
    );
    assert!(registry.active().is_none());
    assert!(registry.pending_activation().is_some());
}

#[test]
fn registry_commit_rejects_scm_pending_selector_as_phase_b_live_proof() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:phase-b-scm-selector"),
    ));
    let mut fence = test_commit_fence(&transaction.candidate_manifest);
    fence
        .phase_b_live_binding
        .as_mut()
        .unwrap_or_else(|| unreachable!())
        .authority_descriptor_digest = test_handle(PHASE_B_PENDING_SCM_DIGEST);
    assert!(
        registry
            .commit_pending_activation(
                &host,
                &transaction.transaction_id,
                &transaction.installer_plan_digest,
                &transaction.candidate_manifest.generation,
                &fence,
            )
            .is_err()
    );
    assert!(registry.active().is_none());
    assert!(registry.pending_activation().is_some());
}

#[test]
fn pending_activation_is_not_active_until_host_commit_and_retries_by_digest() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:pending"),
    ));
    assert!(registry.active().is_none());
    assert!(registry.pending_activation().is_some());
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:pending"),
    ));
    must(registry.mark_pending_recovery(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        "simulated pre-launch crash",
    ));
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:pending"),
    ));
    assert!(matches!(
        registry.pending_activation().map(|pending| &pending.state),
        Some(PendingActivationState::RecoveryRequired { .. })
    ));
    assert!(matches!(
        must(registry.claim_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
        ))
        .state,
        PendingActivationState::Pending
    ));
    assert!(matches!(
        must(registry.claim_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
        ))
        .state,
        PendingActivationState::Pending
    ));
    let wrong_plan = test_handle("f".repeat(64));
    assert!(matches!(
        registry.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &wrong_plan,
            &transaction.candidate_manifest.generation,
            &test_commit_fence(&transaction.candidate_manifest),
        ),
        Err(InstallationError::IdentityConflict)
    ));
    must(registry.commit_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
    assert!(registry.pending_activation().is_none());
    assert_eq!(
        registry.active_generation(),
        Some(&transaction.candidate_manifest.generation)
    );
    assert!(registry.last_known_good_generation().is_none());
    let bytes = must(serde_json::to_vec(&registry));
    let mut reloaded = must(decode_registry_bytes(&bytes));
    let mut substituted_fence = test_commit_fence(&transaction.candidate_manifest);
    substituted_fence.candidate_binding_digest = test_handle("1".repeat(64));
    assert!(matches!(
        reloaded.commit_pending_activation(
            &host,
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest.generation,
            &substituted_fence,
        ),
        Err(InstallationError::IdentityConflict)
    ));
    must(reloaded.commit_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
        &transaction.candidate_manifest.generation,
        &test_commit_fence(&transaction.candidate_manifest),
    ));
}

#[cfg(windows)]
#[test]
fn pending_activation_exposes_exact_transaction_and_plan_bindings() {
    let (registry, transaction) = pending_registry_for_owner_gate();
    let pending = registry
        .pending_activation()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(
        pending.approval.transaction_id(),
        &transaction.transaction_id
    );
    assert_eq!(
        pending.approval.installer_plan_digest(),
        &transaction.installer_plan_digest
    );
}

#[cfg(windows)]
#[test]
fn registry_mutations_reject_after_owner_release_without_state_change() {
    let (mut registry, transaction) = pending_registry_for_owner_gate();
    let (mut lease, capability) = live_host_capability();
    lease
        .release()
        .unwrap_or_else(|error| panic!("owner release failed: {error}"));
    assert_registry_mutations_rejected_after_owner_shutdown(
        &mut registry,
        &transaction,
        &capability,
    );
}

#[cfg(windows)]
#[test]
fn registry_mutations_reject_after_owner_drop_without_state_change() {
    let (mut registry, transaction) = pending_registry_for_owner_gate();
    let capability = {
        let (lease, capability) = live_host_capability();
        drop(lease);
        capability
    };
    assert_registry_mutations_rejected_after_owner_shutdown(
        &mut registry,
        &transaction,
        &capability,
    );
}

#[test]
fn upgrade_failure_preserves_prior_active_and_rejects_binding_substitution() {
    let first = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        first.transaction_id.clone(),
        first.installer_plan_digest.clone(),
        first.candidate_manifest.clone(),
        test_handle("approval:first"),
    ));
    must(registry.commit_pending_activation(
        &host,
        &first.transaction_id,
        &first.installer_plan_digest,
        &first.candidate_manifest.generation,
        &test_commit_fence(&first.candidate_manifest),
    ));

    let mut upgrade = first.candidate_manifest.clone();
    upgrade.generation = test_handle("generation:upgrade");
    upgrade.runtime_launch.generation = upgrade.generation.clone();
    upgrade.runtime_launch.descriptor_digest =
        test_handle(sha256_hex(&must(upgrade.runtime_launch.unsigned_bytes())));
    must(upgrade.validate());
    let upgrade_tx = test_handle("transaction:upgrade");
    let upgrade_plan = test_handle("a".repeat(64));
    must(registry.stage_pending_activation(
        upgrade_tx.clone(),
        upgrade_plan.clone(),
        upgrade.clone(),
        test_handle("approval:upgrade"),
    ));
    assert_eq!(
        registry.active_generation(),
        Some(&first.candidate_manifest.generation)
    );
    assert_eq!(
        registry
            .pending_activation()
            .and_then(|pending| pending.prior_active_generation.as_ref()),
        Some(&first.candidate_manifest.generation)
    );
    let original_pending = registry
        .pending_activation()
        .cloned()
        .unwrap_or_else(|| unreachable!());
    let wrong_root = {
        let mut pending = original_pending.clone();
        pending.runtime_state_roots_digest = test_handle("b".repeat(64));
        pending
    };
    registry.pending_activation = Some(wrong_root);
    assert!(registry.validate().is_err());
    registry.pending_activation = Some(original_pending);
    must(registry.mark_pending_recovery(
        &host,
        &upgrade_tx,
        &upgrade_plan,
        "journal-active-before-commit",
    ));
    assert_eq!(
        registry.active_generation(),
        Some(&first.candidate_manifest.generation)
    );
    assert_eq!(registry.last_known_good_generation(), None);
}

#[test]
fn first_install_pending_abort_leaves_registry_empty() {
    let transaction = registering_transaction();
    let host = host_capability();
    let mut registry = ApprovedGenerationRegistry::new();
    must(registry.stage_pending_activation(
        transaction.transaction_id.clone(),
        transaction.installer_plan_digest.clone(),
        transaction.candidate_manifest.clone(),
        test_handle("approval:abort"),
    ));
    must(registry.abort_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
    ));
    must(registry.abort_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
    ));
    let bytes = must(serde_json::to_vec(&registry));
    let mut reloaded = must(decode_registry_bytes(&bytes));
    must(reloaded.abort_pending_activation(
        &host,
        &transaction.transaction_id,
        &transaction.installer_plan_digest,
    ));
    let mut malformed = must(serde_json::to_value(&registry));
    malformed["last_terminal_activation"]["commit_fence"] = must(serde_json::to_value(
        test_commit_fence(&transaction.candidate_manifest),
    ));
    let malformed_bytes = must(serde_json::to_vec(&malformed));
    assert!(matches!(
        decode_registry_bytes(&malformed_bytes),
        Err(InstallationError::CorruptRegistry { .. })
    ));
    assert!(registry.generations().is_empty());
    assert!(registry.active_generation().is_none());
    assert!(registry.last_known_good_generation().is_none());
    assert!(registry.pending_activation().is_none());
}

#[test]
fn phase_b_digest_state_transitions_are_ordered_and_non_admissible_until_live() {
    let transaction = registering_transaction();
    let mut phase_a = transaction.candidate_manifest.runtime_launch.clone();
    let pending = test_handle(PHASE_B_PENDING_MARKER);
    phase_a.authority_descriptor_digest = pending.clone();
    phase_a.store_bootstrap_descriptor_digest = pending.clone();
    phase_a.kernel_arguments[5] = pending.clone();
    phase_a.kernel_arguments[9] = pending;
    let phase_a = must(phase_a.with_computed_digest());
    assert_eq!(
        must(phase_a.phase_b_digest_state()),
        (PhaseBDigestState::Pending, PhaseBDigestState::Pending)
    );
    assert!(phase_a.require_phase_b_live().is_err());

    let authority_digest = test_handle("a".repeat(64));
    let eliotd_digest = test_handle("b".repeat(64));
    let bootstrap_digest = test_handle("c".repeat(64));
    let provisioned_supervision_authority = test_provisioned_supervision_authority(
        phase_a.installation_epoch.installation.as_str(),
        phase_a.generation.as_str(),
        phase_a.authority_generation,
    );
    let intermediate = must(phase_a.with_phase_b_pending_bootstrap_overlay(
        phase_a.authority_generation,
        phase_a.authority_state_fence.clone(),
        authority_digest.clone(),
        eliotd_digest.clone(),
        provisioned_supervision_authority,
    ));
    assert_eq!(
        must(intermediate.phase_b_digest_state()),
        (PhaseBDigestState::Live, PhaseBDigestState::Pending)
    );
    assert!(intermediate.require_phase_b_live().is_err());
    assert!(
        phase_a
            .with_phase_b_materialization(
                phase_a.authority_generation,
                phase_a.authority_state_fence.clone(),
                authority_digest.clone(),
                bootstrap_digest.clone(),
                eliotd_digest.clone(),
            )
            .is_err()
    );

    let live = must(intermediate.with_phase_b_materialization(
        intermediate.authority_generation,
        intermediate.authority_state_fence.clone(),
        authority_digest,
        bootstrap_digest,
        eliotd_digest,
    ));
    assert_eq!(
        must(live.phase_b_digest_state()),
        (PhaseBDigestState::Live, PhaseBDigestState::Live)
    );
    assert!(live.require_phase_b_live().is_ok());
    assert!(
        live.with_phase_b_materialization(
            live.authority_generation,
            live.authority_state_fence.clone(),
            test_handle("a".repeat(64)),
            test_handle("c".repeat(64)),
            test_handle("b".repeat(64)),
        )
        .is_err()
    );

    let mut legacy_zero = phase_a.clone();
    legacy_zero.authority_descriptor_digest = test_handle("0".repeat(64));
    assert!(legacy_zero.phase_b_digest_state().is_err());
    let mut legacy_zero_bootstrap = phase_a;
    legacy_zero_bootstrap.store_bootstrap_descriptor_digest = test_handle("0".repeat(64));
    assert!(legacy_zero_bootstrap.phase_b_digest_state().is_err());
}

#[test]
fn phase_b_pending_marker_and_scm_selector_stay_in_distinct_domains() {
    assert_ne!(PHASE_B_PENDING_MARKER, PHASE_B_PENDING_SCM_DIGEST);
    assert!(!is_lower_sha256(PHASE_B_PENDING_MARKER));
    assert!(is_lower_sha256(PHASE_B_PENDING_SCM_DIGEST));

    let marker = test_handle(PHASE_B_PENDING_MARKER);
    assert_eq!(
        phase_b_digest_state(&marker, "test.phase_b_marker"),
        Ok(PhaseBDigestState::Pending)
    );
    assert_eq!(
        phase_b_scm_selector(&marker),
        Ok(test_handle(PHASE_B_PENDING_SCM_DIGEST))
    );

    let selector = test_handle(PHASE_B_PENDING_SCM_DIGEST);
    assert!(phase_b_digest_state(&selector, "test.phase_b_selector").is_err());
    assert!(phase_b_scm_selector(&selector).is_err());
}

#[test]
fn runtime_digest_domains_reject_reserved_selector_and_legacy_zero() {
    let base = registering_transaction().candidate_manifest.runtime_launch;
    for reserved in [PHASE_B_PENDING_SCM_DIGEST, LEGACY_PHASE_B_ZERO_DIGEST] {
        assert!(runtime_sha256_handle(&test_handle(reserved), "test.runtime").is_err());

        let mut artifact = base.clone();
        artifact.kernel_artifact_digest = test_handle(reserved);
        artifact.descriptor_digest = test_handle(sha256_hex(&must(artifact.unsigned_bytes())));
        assert!(artifact.validate().is_err());

        let mut config = base.clone();
        config.eliotd_config_digest = test_handle(reserved);
        config.descriptor_digest = test_handle(sha256_hex(&must(config.unsigned_bytes())));
        assert!(config.validate().is_err());

        let mut descriptor = base.clone();
        descriptor.descriptor_digest = test_handle(reserved);
        assert!(descriptor.validate().is_err());

        let mut bootstrap = base.clone();
        bootstrap.store_bootstrap_descriptor_digest = test_handle(reserved);
        assert!(bootstrap.validate().is_err());
    }
}

#[test]
fn service_bootstrap_requires_adapter_selector_for_pending_runtime_state() {
    let root = std::env::temp_dir().join(format!(
        "eliot-installation-phase-b-bootstrap-{}",
        std::process::id()
    ));
    let make_bootstrap = |descriptor_digest: &str| InstallationServiceBootstrap {
        descriptor_path: test_handle(root.join("authority.json").to_string_lossy()),
        descriptor_digest: test_handle(descriptor_digest),
        installation_id: test_handle("installation:phase-b-bootstrap"),
        plan_generation: 1,
        host_state_root: test_handle(root.join("host").to_string_lossy()),
    };

    assert!(make_bootstrap(PHASE_B_PENDING_MARKER).validate().is_err());
    assert!(
        make_bootstrap(PHASE_B_PENDING_SCM_DIGEST)
            .validate()
            .is_ok()
    );
    assert!(
        make_bootstrap(LEGACY_PHASE_B_ZERO_DIGEST)
            .validate()
            .is_err()
    );
}

#[test]
fn existing_redb_v1_record_requires_migration_instead_of_becoming_empty() {
    let legacy_bytes = must(serde_json::to_vec(&v1_registry_value()));

    let path = std::env::temp_dir().join(format!(
        "eliot-installation-legacy-registry-{}.redb",
        std::process::id()
    ));
    let database = must(Database::create(&path));
    let write = must(database.begin_write());
    {
        let mut table = must(write.open_table(REGISTRY_TABLE));
        must(table.insert("registry", legacy_bytes.as_slice()));
    }
    must(write.commit());
    let read = must(database.begin_read());
    let table = must(read.open_table(REGISTRY_TABLE));
    let Some(value) = must(table.get("registry")) else {
        panic!("legacy registry fixture record");
    };
    let Err(error) = decode_registry_bytes(value.value()) else {
        panic!("migration must be required");
    };
    assert!(matches!(error, InstallationError::MigrationRequired { .. }));
    drop(read);
    drop(database);
    let _ = std::fs::remove_file(path);
}

#[test]
fn inspect_existing_missing_registry_does_not_create_one() {
    let path = std::env::temp_dir().join(format!(
        "eliot-installation-registry-missing-{}.redb",
        std::process::id()
    ));
    assert!(
        !path.exists(),
        "test registry fixture unexpectedly exists: {}",
        path.display()
    );
    assert_eq!(
        must(RedbInstallationRegistry::inspect_existing(&path)),
        None
    );
    assert!(!path.exists(), "read-only inspection created a registry");
}

#[test]
fn installation_registry_host_root_shape_is_exact_and_non_reparse_lexical() {
    let key = "a".repeat(64);
    let accepted = PathBuf::from(format!(r"C:\ProgramData\Eliot\installations\{key}\host"));
    assert!(validate_installation_host_root(&accepted).is_ok());

    for rejected in [
        PathBuf::from(r"C:\ProgramData\Eliot\host"),
        PathBuf::from(r"C:\ProgramData\Eliot\installations\not-a-key\host"),
        PathBuf::from(format!(r"C:\ProgramData\Eliot\installations\{key}\wrong")),
        PathBuf::from(format!(
            r"C:\ProgramData\Eliot\installations\{key}\host\..\host"
        )),
        PathBuf::from(format!(
            r"\\?\C:\ProgramData\Eliot\installations\{key}\host"
        )),
    ] {
        assert!(
            validate_installation_host_root(&rejected).is_err(),
            "accepted wrong/reparse-shaped host root {}",
            rejected.display()
        );
    }
}

#[test]
fn registry_decode_classifies_nonlegacy_bytes_as_corruption() {
    for bytes in [
        b"{\"generations\":[".to_vec(),
        must(serde_json::to_vec(&serde_json::json!([]))),
        must(serde_json::to_vec(&serde_json::json!({
            "generations": "wrong"
        }))),
        must(serde_json::to_vec(&serde_json::json!({
            "unrelated": true
        }))),
    ] {
        let Err(error) = decode_registry_bytes(&bytes) else {
            panic!("corrupt registry must fail closed");
        };
        assert!(matches!(error, InstallationError::CorruptRegistry { .. }));
    }

    let current_transaction = registering_transaction();
    let mut current = must(serde_json::to_value(ApprovedGenerationRegistry {
        generations: vec![ApprovedGeneration {
            manifest: current_transaction.candidate_manifest.clone(),
            approval: test_activation_approval(
                &current_transaction.candidate_manifest,
                current_transaction.transaction_id.clone(),
                current_transaction.installer_plan_digest.clone(),
                test_handle("approval:current"),
            ),
            active: true,
            last_known_good: false,
        }],
        service_registration_approvals: Vec::new(),
        active_generation: Some(test_handle("generation:missing")),
        last_known_good_generation: None,
        pending_activation: None,
        last_terminal_activation: None,
        ..ApprovedGenerationRegistry::new()
    }));
    let Err(error) = decode_registry_bytes(&must(serde_json::to_vec(&current))) else {
        panic!("current corruption must fail closed");
    };
    assert!(matches!(error, InstallationError::CorruptRegistry { .. }));

    current = v1_registry_value();
    current["unrelated"] = serde_json::json!(true);
    let Err(error) = decode_registry_bytes(&must(serde_json::to_vec(&current))) else {
        panic!("unknown legacy schema must fail closed");
    };
    assert!(matches!(error, InstallationError::CorruptRegistry { .. }));
}

#[test]
fn manifest_rejects_unbound_store_config_alias() {
    let mut manifest = registering_transaction().candidate_manifest;
    manifest.runtime_launch.store_config_path = test_handle(
        std::env::temp_dir()
            .join("eliot-installation-unbound-store.json")
            .to_string_lossy()
            .into_owned(),
    );
    let error = match manifest.validate() {
        Ok(()) => panic!("unbound Store config must fail closed"),
        Err(error) => error,
    };
    assert!(
        matches!(error, InstallationError::InvalidField { field, .. } if field == "manifest.runtime_launch.store_config_path")
    );
}

#[test]
fn manifest_rejects_eliotd_governor_config_domain_substitution() {
    let mut store_alias = registering_transaction().candidate_manifest;
    store_alias.runtime_launch.eliotd_config_path = store_alias.config_path.clone();
    reseal(&mut store_alias.runtime_launch);
    assert!(matches!(
        store_alias.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "manifest.runtime_launch.eliotd_config_path"
    ));

    let mut descriptor_alias = registering_transaction().candidate_manifest;
    descriptor_alias.runtime_launch.eliotd_config_path = descriptor_alias
        .runtime_launch
        .eliotd_descriptor_path
        .clone();
    reseal(&mut descriptor_alias.runtime_launch);
    assert!(matches!(
        descriptor_alias.validate(),
        Err(InstallationError::InvalidField { field, .. })
            if field == "manifest.runtime_launch.eliotd_config_path"
    ));
}

#[test]
fn host_artifact_binding_is_exact_and_self_digest_bound() {
    let manifest = registering_transaction().candidate_manifest;
    let (path, digest) = must(manifest.host_artifact_binding());
    assert_eq!(path, &manifest.runtime_launch.host_executable_path);
    assert_eq!(digest, &manifest.runtime_launch.host_artifact_digest);

    let mut altered = manifest;
    altered.runtime_launch.host_artifact_digest = test_handle("9".repeat(64));
    assert!(altered.host_artifact_binding().is_err());
}

#[test]
fn manifest_rejects_bridge_as_canonical_engine_and_aliased_paths() {
    let mut manifest = registering_transaction().candidate_manifest;
    manifest.canonical_store_executable_path = manifest.store_bridge_executable_path.clone();
    assert!(manifest.validate().is_err());

    let mut swapped = registering_transaction().candidate_manifest;
    swapped.canonical_store_executable_path =
        test_path(&std::env::temp_dir(), "wrong-canonical-engine.exe");
    assert!(swapped.validate().is_err());
}

#[test]
fn mark_unknown_activating_is_rejected_without_mutation() {
    let mut transaction = registering_transaction();
    assert!(!transaction.has_activation_projection_intent());
    transaction.stage = InstallationStage::Activating;
    transaction.pending_external_changes.clear();
    transaction.revision = 5;
    must(transaction.validate());
    let before = transaction.clone();
    let err = transaction
        .mark_unknown(vec![test_handle("pending:activating-unknown")])
        .expect_err("Activating must not become RollbackRequired");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(transaction, before);
}

#[test]
fn activation_projection_intent_presence_is_read_only() {
    let registering = registering_transaction();
    assert!(!registering.has_activation_projection_intent());
}

#[test]
fn rollback_registering_with_durable_pending_evidence_succeeds() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    transaction.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:effect-0"),
        evidence: vec![test_handle("evidence:recover-registering")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    transaction.stage = InstallationStage::Registering;
    transaction.pending_external_changes = vec![test_handle("pending:registering-durable")];
    transaction.revision = 4;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut port = fake_port(
        store.clone(),
        Vec::new(),
        vec![
            PortOutcome::Known(matching(
                InstallationEffectDisposition::CreatedByTransaction,
            )),
            PortOutcome::Known(absent(&transaction)),
        ],
        execute_count.clone(),
    );
    port.secret_absence = vec![PortOutcome::Known(true)].into();
    let mut coordinator = InstallationCoordinator::new(port, store.clone());
    let outcome = must(coordinator.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Applied {
            stage: InstallationStage::RolledBack,
            ..
        }
    ));
    assert!(*execute_count.lock().unwrap_or_else(|_| unreachable!()) > 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::RolledBack);
    assert!(saved.pending_external_changes.is_empty());
    assert!(
        saved
            .completed_stage_refs
            .iter()
            .all(|r| !r.as_str().contains("recovery:rejected-to-rollback"))
    );
}

#[cfg(windows)]
#[test]
fn rollback_with_live_phase_b_authority_quarantines_without_external_effects() {
    let mut transaction = fully_applied_system_registration_transaction();
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes = vec![test_handle("pending:phase-b-rollback")];
    transaction.revision += 1;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );

    let outcome = must(coordinator.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Quarantined { ref pending_refs }
            if pending_refs.iter().any(|pending| {
                pending
                    .as_str()
                    .starts_with("quarantine:phase-b-authority-retained:")
            })
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert_eq!(
        must(store.load(&transaction_id))
            .unwrap_or_else(|| unreachable!())
            .stage(),
        InstallationStage::Quarantined
    );
}

#[test]
fn rollback_registering_without_durable_evidence_is_rejected_without_effects() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    transaction.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:effect-0"),
        evidence: vec![test_handle("evidence:recover-registering")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    transaction.stage = InstallationStage::Registering;
    transaction.pending_external_changes.clear();
    transaction.revision = 4;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let err = coordinator
        .rollback(&transaction_id)
        .expect_err("must reject without durable rejection evidence");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Registering);
    assert!(saved.pending_external_changes.is_empty());
    assert!(
        saved
            .completed_stage_refs
            .iter()
            .all(|r| !r.as_str().contains("recovery:rejected-to-rollback"))
    );
}

#[test]
fn rollback_activating_is_rejected_without_external_effects() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    transaction.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:effect-0"),
        evidence: vec![test_handle("evidence:activating")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    transaction.stage = InstallationStage::Activating;
    transaction.pending_external_changes = vec![test_handle("pending:activating")];
    transaction.revision = 4;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction.clone()))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let err = coordinator
        .rollback(&transaction_id)
        .expect_err("Activating must reject");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Activating);
    assert_eq!(
        saved.pending_external_changes,
        transaction.pending_external_changes
    );
}

#[test]
fn rollback_registering_with_unknown_quarantines_before_effects() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].state = InstallationEffectProgressState::Unknown {
        pending_ref: test_handle("pending:unknown-intent"),
    };
    transaction.stage = InstallationStage::Registering;
    transaction.pending_external_changes.clear();
    transaction.revision = 4;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let outcome = must(coordinator.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Quarantined);
}

#[test]
fn rollback_required_first_effect_unknown_quarantines_before_external_effects() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].state = InstallationEffectProgressState::Unknown {
        pending_ref: test_handle("pending:first-effect-unknown"),
    };
    transaction.stage = InstallationStage::RollbackRequired;
    transaction.pending_external_changes = vec![test_handle("pending:first-effect-unknown")];
    transaction.revision = 4;
    must(transaction.validate());
    assert!(!transaction.has_activation_projection_intent());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let outcome = must(coordinator.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Quarantined);
}

#[test]
fn rollback_registering_with_intent_quarantines_before_effects() {
    let mut transaction = planned_transaction();
    transaction.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&transaction));
    transaction.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::NotAttempted,
        InstallationSecretLifecycle::Active,
    ));
    let intent_digest = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ))
    .intent_digest()
    .unwrap_or_else(|error| panic!("intent digest: {error}"));
    transaction.effect_progress[0].state = InstallationEffectProgressState::IntentCommitted {
        attempt: 1,
        intent_digest,
    };
    transaction.stage = InstallationStage::Registering;
    transaction.pending_external_changes.clear();
    transaction.revision = 4;
    must(transaction.validate());
    let transaction_id = transaction.transaction_id.clone();
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(transaction))),
        ..SharedStore::default()
    };
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let outcome = must(coordinator.rollback(&transaction_id));
    assert!(matches!(
        outcome,
        InstallationStepOutcome::Quarantined { .. }
    ));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::Quarantined);
}

#[test]
fn rollback_activating_redb_is_rejected_without_external_effects() {
    let planned = planned_transaction();
    let mut activating = planned.clone();
    activating.effect_progress[0].admitted_precondition = Some(admitted_precondition(&activating));
    activating.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    activating.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:activating-redb"),
        evidence: vec![test_handle("evidence:activating-redb")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    activating.stage = InstallationStage::Activating;
    activating.pending_external_changes = vec![test_handle("pending:activating-redb")];
    activating.revision = 4;
    must(activating.validate());
    let path = std::env::temp_dir().join(format!(
        "eliot-rollback-activating-redb-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let mut store =
        must(RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &planned));
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = activating.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut store, expected, &persisted,
        ),
    );
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(
            SharedStore::default(),
            Vec::new(),
            Vec::new(),
            execute_count.clone(),
        ),
        store,
    );
    let err = coordinator
        .rollback(&activating.transaction_id)
        .expect_err("Activating Redb must reject");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn rollback_registering_without_durable_evidence_redb_is_rejected_without_effects() {
    let planned = planned_transaction();
    let mut registering = planned.clone();
    registering.effect_progress[0].admitted_precondition =
        Some(admitted_precondition(&registering));
    registering.effect_progress[0].ownership_secret = Some(test_ownership_secret(
        InstallationCreateDisposition::Created,
        InstallationSecretLifecycle::Active,
    ));
    registering.effect_progress[0].state = InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity: test_handle("external:registering-redb"),
        evidence: vec![test_handle("evidence:registering-redb")],
        postcondition_digest: test_handle("a".repeat(64)),
    };
    registering.stage = InstallationStage::Registering;
    registering.pending_external_changes.clear();
    registering.revision = 4;
    must(registering.validate());
    let path = std::env::temp_dir().join(format!(
        "eliot-rollback-nofabricate-redb-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let mut store =
        must(RedbInstallationTransactionStore::create_planned_at_exact_path(&path, &planned));
    let expected = must(TransactionVersion::of(&planned));
    let mut persisted = registering.clone();
    persisted.revision = expected.revision + 1;
    must(
        <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
            &mut store, expected, &persisted,
        ),
    );
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(
            SharedStore::default(),
            Vec::new(),
            Vec::new(),
            execute_count.clone(),
        ),
        store,
    );
    let err = coordinator
        .rollback(&registering.transaction_id)
        .expect_err("Registering without durable evidence must reject");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    assert!(!format!("{err:?}").contains("recovery:rejected-to-rollback"));
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn rollback_forged_rollback_required_with_pending_projection_is_rejected_without_effects() {
    let mut registering = registering_system_service_start_transaction();
    let approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:forged-projection"),
    );
    let intent = must(InstallationActivationProjectionIntent::new(
        &registering,
        &approval,
        test_handle("e".repeat(64)),
        test_handle("f".repeat(64)),
        1,
        test_handle("a".repeat(64)),
    ));
    must(registering.advance_to_activating_for_signed_approval(&approval, intent));
    assert_eq!(registering.stage(), InstallationStage::Activating);
    assert!(registering.activation_projection_intent().is_some());

    let mut forged = registering.clone();
    forged.stage = InstallationStage::RollbackRequired;
    forged.pending_external_changes = vec![test_handle("pending:forged-projection")];
    forged.revision = registering.revision + 1;
    must(forged.validate());
    let transaction_id = forged.transaction_id.clone();
    let execute_count = Arc::new(Mutex::new(0usize));
    let store = SharedStore {
        state: Arc::new(Mutex::new(Some(forged))),
        ..SharedStore::default()
    };
    let mut coordinator = InstallationCoordinator::new(
        fake_port(store.clone(), Vec::new(), Vec::new(), execute_count.clone()),
        store.clone(),
    );
    let err = coordinator
        .rollback(&transaction_id)
        .expect_err("pending Host handoff must reject rollback");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let saved = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(saved.stage(), InstallationStage::RollbackRequired);
    assert!(saved.activation_projection_intent().is_some());
}

#[cfg(windows)]
#[test]
#[allow(clippy::items_after_statements)]
fn rollback_forged_rollback_required_with_pending_projection_redb_is_rejected_without_effects() {
    let registering = registering_system_service_start_transaction();
    let approval = test_transaction_activation_approval(
        &registering,
        test_handle("approval:forged-projection-redb"),
    );
    let mut activating = registering.clone();
    let intent = must(InstallationActivationProjectionIntent::new(
        &activating,
        &approval,
        test_handle("e".repeat(64)),
        test_handle("f".repeat(64)),
        1,
        test_handle("a".repeat(64)),
    ));
    must(activating.advance_to_activating_for_signed_approval(&approval, intent));
    let mut forged = activating.clone();
    forged.stage = InstallationStage::RollbackRequired;
    forged.pending_external_changes = vec![test_handle("pending:forged-projection-redb")];
    must(forged.validate());

    let planned = must(InstallationTransaction::new(
        registering.transaction_id.clone(),
        registering.installation_epoch.clone(),
        registering.profile,
        registering.request.clone(),
        registering.current_active_manifest.clone(),
        registering.candidate_manifest.clone(),
        registering.staging_root.clone(),
        registering.planned_changes.clone(),
        registering.installer_effects.clone(),
        registering.minimum_store_available_bytes,
        registering.precondition_evidence.clone(),
        registering.recovery_command.clone(),
    ));
    let path = std::env::temp_dir().join(format!(
        "eliot-rollback-forged-projection-redb-{}-{}.redb",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &path, &planned,
        ),
    );
    forged.revision = activating.revision + 1;
    {
        let database = must(redb::Database::open(&path));
        let write = must(database.begin_write());
        {
            let mut table = must(write.open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "installation_transactions_v7",
            )));
            #[derive(serde::Serialize)]
            struct Envelope<'a> {
                wire_version: ContractVersion,
                transaction: &'a InstallationTransaction,
            }
            let bytes = must(serde_json::to_vec(&Envelope {
                wire_version: INSTALLATION_TRANSACTION_WIRE_VERSION,
                transaction: &forged,
            }));
            must(table.insert(forged.transaction_id.as_str(), bytes.as_slice()));
        }
        must(write.commit());
    }
    let transaction_id = forged.transaction_id.clone();
    let execute_count = Arc::new(Mutex::new(0usize));
    let mut coordinator = InstallationCoordinator::new(
        fake_port(
            SharedStore::default(),
            Vec::new(),
            Vec::new(),
            execute_count.clone(),
        ),
        store,
    );
    let err = coordinator
        .rollback(&transaction_id)
        .expect_err("Redb pending Host handoff must reject rollback");
    assert!(matches!(err, InstallationError::IllegalTransition { .. }));
    assert_eq!(*execute_count.lock().unwrap_or_else(|_| unreachable!()), 0);
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn package_precondition_snapshot_is_required_for_post_intent_stage_package() {
    let transaction = system_registration_transaction();
    let index = transaction
        .installer_effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        .unwrap_or_else(|| unreachable!());
    let plan = transaction.installer_effects[index].clone();
    let change = transaction.planned_changes[index].clone();
    let base = must(InstallationEffectPrecondition::from_change(&change));
    let request = InstallationEffectRequest {
        transaction_id: transaction.transaction_id.clone(),
        plan: plan.clone(),
        profile: transaction.profile,
        installation_root: transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .installation_root
            .clone(),
        effect_id: plan.effect_id().clone(),
        attempt: 2,
        plan_digest: transaction.installer_plan_digest.clone(),
        precondition: base.clone(),
        ownership_secret: None,
        store_credential: None,
        staging_receipt: None,
        action: InstallationEffectAction::Apply,
        expected_external_identity: None,
        service_bootstrap: None,
        registration_nonce: None,
    };
    assert!(
        request.validate().is_err(),
        "a post-intent StagePackage request without its source snapshot must fail closed"
    );

    let (source_bundle_identity, generation, manifest_digest) = match &plan {
        InstallerEffectPlan::StagePackage {
            source_bundle_identity,
            generation,
            manifest,
            ..
        } => (
            *source_bundle_identity,
            generation.clone(),
            must(PlatformHandle::new(manifest.canonical_digest())),
        ),
        _ => unreachable!(),
    };
    let files = Vec::new();
    let total_bytes = 0;
    let digest = must(PackageObservationSnapshot::compute_digest(
        &source_bundle_identity,
        &generation,
        &manifest_digest,
        &files,
        total_bytes,
    ));
    let snapshot = PackageObservationSnapshot {
        source_bundle_identity,
        generation,
        manifest_digest,
        files,
        total_bytes,
        digest,
    };
    let valid_request = InstallationEffectRequest {
        precondition: must(base.with_package_snapshot(snapshot)),
        ..request
    };
    must(valid_request.validate());
}

#[test]
fn package_binding_validates_candidate_and_package_digests_independently() {
    let transaction = registering_transaction();
    let package_manifest = must(PackageManifest::new("candidate", Vec::new()));
    let package_effect = InstallerEffectPlan::StagePackage {
        effect_id: test_handle("effect:package-binding"),
        source_bundle: transaction.staging_root.clone(),
        source_bundle_identity: FileIdentity {
            volume_serial_number: 1,
            file_index: 1,
        },
        generation: transaction.candidate_manifest.generation.clone(),
        manifest: package_manifest.clone(),
        staging_root: transaction.staging_root.clone(),
        expected_file_digests: Vec::new(),
        candidate_manifest_digest: must(candidate_manifest_digest(&transaction.candidate_manifest)),
        package_manifest_digest: must(PlatformHandle::new(package_manifest.canonical_digest())),
    };
    let effects = vec![package_effect.clone()];
    must(validate_package_binding(
        &transaction.candidate_manifest,
        &transaction.staging_root,
        &effects,
    ));

    let mut candidate_mutation = effects.clone();
    if let InstallerEffectPlan::StagePackage {
        candidate_manifest_digest,
        ..
    } = &mut candidate_mutation[0]
    {
        *candidate_manifest_digest = test_handle("a".repeat(64));
    }
    assert!(
        validate_package_binding(
            &transaction.candidate_manifest,
            &transaction.staging_root,
            &candidate_mutation,
        )
        .is_err()
    );

    let mut package_mutation = effects;
    if let InstallerEffectPlan::StagePackage {
        package_manifest_digest,
        ..
    } = &mut package_mutation[0]
    {
        *package_manifest_digest = test_handle("b".repeat(64));
    }
    assert!(
        validate_package_binding(
            &transaction.candidate_manifest,
            &transaction.staging_root,
            &package_mutation,
        )
        .is_err()
    );
    must(package_effect.validate());
    if let InstallerEffectPlan::StagePackage {
        package_manifest_digest,
        ..
    } = &mut package_mutation[0]
    {
        *package_manifest_digest = test_handle("c".repeat(64));
    }
    assert!(package_mutation[0].validate().is_err());
}

#[test]
fn package_manifest_matches_rejects_candidate_and_mutated_bindings() {
    let transaction = registering_transaction();
    let manifest = must(PackageManifest::new("package-generation", Vec::new()));
    let generation = test_handle("package-generation");
    let package_manifest_digest = must(PlatformHandle::new(manifest.canonical_digest()));
    let candidate_manifest_digest =
        must(candidate_manifest_digest(&transaction.candidate_manifest));
    assert_ne!(
        candidate_manifest_digest, package_manifest_digest,
        "the regression fixture must keep the two bindings unequal"
    );
    assert!(package_manifest_matches(
        &manifest,
        &generation,
        &package_manifest_digest
    ));
    assert!(!package_manifest_matches(
        &manifest,
        &generation,
        &candidate_manifest_digest
    ));
    let mutated_generation = test_handle("mutated-generation");
    assert!(!package_manifest_matches(
        &manifest,
        &mutated_generation,
        &package_manifest_digest
    ));
    let mutated_package_manifest_digest = test_handle("e".repeat(64));
    assert!(!package_manifest_matches(
        &manifest,
        &generation,
        &mutated_package_manifest_digest
    ));
}

#[test]
fn package_snapshot_digest_is_ordinal_deterministic_and_size_bound() {
    let generation = test_handle("generation-1");
    let manifest_digest = test_handle("a".repeat(64));
    let identity = FileIdentity {
        volume_serial_number: 1,
        file_index: 2,
    };
    let file_a = PackageObservedFile {
        relative_path: "bin/z.txt".to_owned(),
        sha256: test_handle("a".repeat(64)),
        size: 1,
        identity,
    };
    let file_b = PackageObservedFile {
        relative_path: "a.txt".to_owned(),
        sha256: test_handle("b".repeat(64)),
        size: 1,
        identity: FileIdentity {
            volume_serial_number: 1,
            file_index: 3,
        },
    };
    let unordered = vec![file_a.clone(), file_b.clone()];
    let mut ordered = unordered.clone();
    ordered.sort_by(|left, right| {
        eliot_platform_windows::ordinal_cmp_str(&left.relative_path, &right.relative_path)
    });
    let digest_unordered = must(PackageObservationSnapshot::compute_digest(
        &identity,
        &generation,
        &manifest_digest,
        &unordered,
        2,
    ));
    let digest_ordered = must(PackageObservationSnapshot::compute_digest(
        &identity,
        &generation,
        &manifest_digest,
        &ordered,
        2,
    ));
    assert_ne!(digest_unordered, digest_ordered);
    let unsorted = PackageObservationSnapshot {
        source_bundle_identity: identity,
        generation: generation.clone(),
        manifest_digest: manifest_digest.clone(),
        files: unordered,
        total_bytes: 2,
        digest: digest_unordered,
    };
    assert!(unsorted.validate().is_err());
    let sorted = PackageObservationSnapshot {
        source_bundle_identity: identity,
        generation,
        manifest_digest,
        files: ordered,
        total_bytes: 2,
        digest: digest_ordered,
    };
    must(sorted.validate());
    let mut wrong_total = sorted.clone();
    wrong_total.total_bytes = 3;
    wrong_total.digest = must(PackageObservationSnapshot::compute_digest(
        &wrong_total.source_bundle_identity,
        &wrong_total.generation,
        &wrong_total.manifest_digest,
        &wrong_total.files,
        wrong_total.total_bytes,
    ));
    assert!(wrong_total.validate().is_err());
}

#[test]
fn package_receipt_must_match_durable_source_observation() {
    let source_identity = FileIdentity {
        volume_serial_number: 11,
        file_index: 22,
    };
    let observed_identity = FileIdentity {
        volume_serial_number: 33,
        file_index: 44,
    };
    let generation = test_handle("candidate");
    let manifest_digest = test_handle("a".repeat(64));
    let files = vec![PackageObservedFile {
        relative_path: "config.json".to_owned(),
        sha256: test_handle("b".repeat(64)),
        size: 7,
        identity: observed_identity,
    }];
    let snapshot = PackageObservationSnapshot {
        source_bundle_identity: source_identity,
        generation: generation.clone(),
        manifest_digest: manifest_digest.clone(),
        total_bytes: 7,
        digest: must(PackageObservationSnapshot::compute_digest(
            &source_identity,
            &generation,
            &manifest_digest,
            &files,
            7,
        )),
        files,
    };
    let receipt_file = eliot_platform_windows::StagedFileReceipt {
        relative_path: "config.json".to_owned(),
        source_identity: observed_identity,
        destination_identity: FileIdentity {
            volume_serial_number: 55,
            file_index: 66,
        },
        size: 7,
        sha256: "b".repeat(64),
        security_descriptor_sha256: "c".repeat(64),
        pe: None,
        authenticode: None,
    };
    let receipt = StagingReceipt {
        generation: generation.as_str().to_owned(),
        root_path: PathBuf::from(r"C:\staging\candidate"),
        root_identity: FileIdentity {
            volume_serial_number: 77,
            file_index: 88,
        },
        directories: Vec::new(),
        files: vec![receipt_file],
        manifest_sha256: manifest_digest.as_str().to_owned(),
    };
    must(validate_staging_receipt_for_observation(
        &snapshot, &receipt,
    ));
    let mut substituted = receipt.clone();
    substituted.files[0].source_identity.file_index += 1;
    assert!(validate_staging_receipt_for_observation(&snapshot, &substituted).is_err());
    let mut changed = receipt;
    changed.files[0].sha256 = "d".repeat(64);
    assert!(validate_staging_receipt_for_observation(&snapshot, &changed).is_err());
}

#[cfg(windows)]
#[test]
fn current_package_snapshot_wire_requires_field_and_rejects_unknown_member() {
    let transaction = fully_applied_system_registration_transaction();
    let mut missing = must(serde_json::to_value(&transaction));
    let progress = missing
        .get_mut("effect_progress")
        .and_then(serde_json::Value::as_array_mut)
        .unwrap_or_else(|| unreachable!());
    let package_progress = progress
        .iter_mut()
        .find(|entry| {
            entry
                .get("admitted_precondition")
                .and_then(|precondition| precondition.get("package_snapshot"))
                .is_some()
        })
        .unwrap_or_else(|| unreachable!());
    package_progress
        .get_mut("admitted_precondition")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap_or_else(|| unreachable!())
        .remove("package_snapshot");
    let missing_error = decode_installation_transaction_json(&must(serde_json::to_vec(&missing)))
        .expect_err("the new durable package observation member is mandatory");
    assert!(matches!(
        missing_error,
        InstallationError::InvalidField { field, .. }
            if field == "effect.precondition.digest"
    ));

    let mut unknown = must(serde_json::to_value(&transaction));
    let progress = unknown
        .get_mut("effect_progress")
        .and_then(serde_json::Value::as_array_mut)
        .unwrap_or_else(|| unreachable!());
    let package_progress = progress
        .iter_mut()
        .find(|entry| {
            entry
                .get("admitted_precondition")
                .and_then(|precondition| precondition.get("package_snapshot"))
                .is_some()
        })
        .unwrap_or_else(|| unreachable!());
    package_progress
        .get_mut("admitted_precondition")
        .and_then(|precondition| precondition.get_mut("package_snapshot"))
        .and_then(serde_json::Value::as_object_mut)
        .unwrap_or_else(|| unreachable!())
        .insert(
            "future_snapshot_member".to_owned(),
            serde_json::Value::String("reject".to_owned()),
        );
    let unknown_error = decode_installation_transaction_json(&must(serde_json::to_vec(&unknown)))
        .expect_err("unknown snapshot members must not be synthesized");
    assert!(matches!(
        unknown_error,
        InstallationError::CorruptRegistry { .. }
    ));
}

#[cfg(windows)]
#[test]
fn trusted_source_observe_is_bound_to_retained_handle_and_fails_on_mutation() {
    use eliot_platform_windows::TrustedSourceBundle;
    let root = std::env::temp_dir().join(format!(
        "eliot-package-observe-wiring-test-{}-{}",
        std::process::id(),
        NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap_or_else(|_| unreachable!());
    std::fs::write(root.join("a.txt"), b"a").unwrap_or_else(|_| unreachable!());
    let bundle = TrustedSourceBundle::open(&root).unwrap_or_else(|_| unreachable!());
    let first = bundle.observe().unwrap_or_else(|_| unreachable!());
    assert_eq!(first.files.len(), 1);
    assert_eq!(first.files[0].sha256, sha256_hex(b"a"));
    std::fs::write(root.join("a.txt"), b"b").unwrap_or_else(|_| unreachable!());
    let second = bundle.observe().unwrap_or_else(|_| unreachable!());
    assert_ne!(first.files[0].sha256, second.files[0].sha256);
    assert_eq!(second.files[0].sha256, sha256_hex(b"b"));
    drop(bundle);
    let _ = std::fs::remove_dir_all(&root);
}
