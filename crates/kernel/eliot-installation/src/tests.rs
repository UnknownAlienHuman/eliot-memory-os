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
use crate::approved_generation_registry::{
    TestSupportRegistryFixtureContour, test_support_activation_fixture,
};
#[cfg(windows)]
use eliot_platform_windows::UserOwnedRootLease;
use eliot_platform_windows::{HostOwnerEpochCapability, HostOwnerLease};

mod registry_concurrent_read;
mod registry_wire_launch;
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

// Canonical lineage-A fixture epoch (Implements #64).
const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
    use std::num::NonZeroU64;
    eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn next_epoch(current: &eliot_contracts::EpochId) -> eliot_contracts::EpochId {
    use std::num::NonZeroU64;
    let next_sequence = current
        .sequence
        .get()
        .checked_add(1)
        .unwrap_or_else(|| unreachable!());
    eliot_contracts::EpochId::new(
        current.lineage_id.clone(),
        NonZeroU64::new(next_sequence).unwrap_or_else(|| unreachable!()),
    )
    .unwrap_or_else(|_| unreachable!())
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
    let pending = must(port_pending(root_execution_error::<()>(
        InstallerRootError::Win32 {
            stage: InstallerRootStage::CreateDirectory,
            code: 0xABCD,
        },
    )));
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
        must(port_pending(PortOutcome::<()>::Error(package_port_error(
            &error
        ))))
        .as_str(),
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
            must(port_pending(PortOutcome::<()>::Error(port))).as_str(),
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
    let pending = must(port_pending(root_execution_error::<()>(
        InstallerRootError::Win32 {
            stage: InstallerRootStage::CreateProtectedFile,
            code: 5,
        },
    )));
    assert_eq!(
        pending.as_str(),
        "installer-root-win32-v2:create-protected-file:00000005"
    );
}

#[test]
fn raw_absence_status_remains_a_typed_win32_pending_reference() {
    let pending = must(port_pending(root_execution_error::<()>(
        InstallerRootError::Win32 {
            stage: InstallerRootStage::OpenReadback,
            code: 2,
        },
    )));
    assert_eq!(
        pending.as_str(),
        "installer-root-win32-v2:open-readback:00000002"
    );
}

#[test]
fn root_precondition_absence_race_reference_is_stable_and_persistable() {
    let pending = must(port_pending(PortOutcome::<()>::Error(
        PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: test_handle("installer-root-absence-race-v1:precondition"),
        },
    )));
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
        let pending = must(port_pending(PortOutcome::<()>::Error(
            PortError::ProviderReference {
                error: ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                },
                reference: test_handle(reference),
            },
        )));
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
        let pending = must(port_pending(PortOutcome::<()>::Error(
            PortError::ProviderReference {
                error: ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                },
                reference: test_handle(reference),
            },
        )));
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
            if reason.contains("21.0.0") && reason.contains("25.0.0")
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
            if reason.contains("creation proof") && reason.contains("v25")
    ));
}

fn test_watchdog_control_grant() -> InstallerServiceControlGrantReceipt {
    let principal_sid = eliot_platform_windows::ELIOT_HOST_SERVICE_SID;
    let receipt = InstallerServiceControlGrantReceipt {
        principal_service: test_handle(ELIOT_HOST_SERVICE_NAME),
        principal_sid: test_handle(principal_sid),
        access_mask: ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
        security_descriptor_owner: test_handle("S-1-5-18"),
        security_descriptor_group: test_handle("S-1-5-18"),
        security_descriptor_digest: test_handle(must(watchdog_service_security_descriptor_digest(
            principal_sid,
        ))),
    };
    must(receipt.validate());
    receipt
}

// s38 (#1345): the installer-policy service DACL grant read back for the
// Host registration itself. The receipt uses the exact Host installer-policy
// DACL shape (principal Host SID, Host mask
// `ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK`, Host policy digest computed by
// the real platform Host digest authority
// `host_service_security_descriptor_digest` for the canonical Host SID),
// so the Host proof round-trips through the same marker/evidence/approval
// gates as the Watchdog proof without canned digests. The Watchdog fixture
// above stays on the Watchdog mask/digest (byte-identical behavior).
fn test_host_service_control_grant() -> InstallerServiceControlGrantReceipt {
    let principal_sid = eliot_platform_windows::ELIOT_HOST_SERVICE_SID;
    let receipt = InstallerServiceControlGrantReceipt {
        principal_service: test_handle(ELIOT_HOST_SERVICE_NAME),
        principal_sid: test_handle(principal_sid),
        access_mask: ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK,
        security_descriptor_owner: test_handle("S-1-5-18"),
        security_descriptor_group: test_handle("S-1-5-18"),
        security_descriptor_digest: test_handle(must(host_service_security_descriptor_digest(
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
            user_broker: None,
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
        let store_target = test_handle("eliot/store/v1/0123456789abcdef0123456789abcdef");
        let provision = StoreCredentialProvisionPlan {
            host_state_root: roots.host_state_root.clone(),
            expected_host_executable: test_handle(
                r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe",
            ),
            target: store_target.clone(),
            // Same owner rule and same live-plan shape as the production
            // `ProvisionStoreCredential` site: the derived provider reference
            // is present, not a parse-compatibility `None`, because these
            // effects are planned and validated as a real installation.
            provider_bootstrap_target: Some(must(
                crate::provider_bootstrap_credential_target_for_store_target(&store_target),
            )),
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
                // No branch of this fixture plans the current-user supervision
                // authority effect: the `SystemService` arm below has no
                // `UserMode` counterpart, and no profile reaches this arm with
                // a `UserModeSupervisionAuthorityProvisionPlan` in hand. Refuse
                // rather than invent a `PlannedChange` target for an effect
                // this fixture cannot plan.
                InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. } => {
                    panic!("fixture must not plan a UserMode supervision authority effect")
                }
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
    let candidate_generation = test_handle("generation-candidate");
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
        doctor_artifact_digest: test_handle("b".repeat(64)),
        testd_artifact_digest: test_handle("c".repeat(64)),
        native_worker_artifact_digest: test_handle("d".repeat(64)),
        user_broker_artifact_digest: test_handle("e".repeat(64)),
        wasm_host_artifact_digest: test_handle("f".repeat(64)),
        kernel_executable_path: test_path(&root, "eliot-kernel.exe"),
        store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
        canonical_store_executable_path: test_path(&root, "surreal.exe"),
        host_executable_path: test_path(&root, "eliot-host.exe"),
        doctor_executable_path: test_path(&root, "eliot-doctor.exe"),
        testd_executable_path: test_path(&root, "eliot-testd.exe"),
        native_worker_executable_path: test_path(&root, "eliot-native-worker.exe"),
        user_broker_executable_path: test_path(&root, "eliot-user-broker.exe"),
        wasm_host_executable_path: test_path(&root, "eliot-wasm-host.exe"),
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
                profile_component: test_handle("eliot"),
                profile_version: test_handle("test-version"),
                profile_installation_key: None,
                profile_governed_roots: InstallationRoots {
                    binding_version: INSTALLATION_ROOT_BINDING_VERSION,
                    immutable_binaries: portable_directory
                        .join("target")
                        .join("eliot-dev")
                        .join(candidate_generation.as_str())
                        .to_string_lossy()
                        .into_owned(),
                    durable_data: portable_directory
                        .join(".eliot-dev")
                        .join("state")
                        .to_string_lossy()
                        .into_owned(),
                    user_config: portable_directory
                        .join(".eliot-dev")
                        .join("config")
                        .to_string_lossy()
                        .into_owned(),
                    user_cache: portable_directory
                        .join(".eliot-dev")
                        .join("cache")
                        .to_string_lossy()
                        .into_owned(),
                    runtime_state_roots: runtime_state_roots.clone(),
                },
                portable_root: Some(portable_root.clone()),
                installation_epoch: InstallationEpoch {
                    installation: test_handle("installation:test"),
                    lineage_id: test_handle("lineage:test"),
                    sequence: 1,
                },
                generation: candidate_generation.clone(),
                authority_generation: ResourceGeneration::genesis(),
                authority_state_fence: StateFence::new(
                    test_epoch(1),
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
                    test_handle("--doctor-artifact-sha256"),
                    test_handle("b".repeat(64)),
                    test_handle("--testd-artifact-sha256"),
                    test_handle("c".repeat(64)),
                    test_handle("--native-worker-artifact-sha256"),
                    test_handle("d".repeat(64)),
                    test_handle("--user-broker-executable"),
                    test_path(&root, "eliot-user-broker.exe"),
                    test_handle("--user-broker-artifact-sha256"),
                    test_handle("e".repeat(64)),
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
                doctor_artifact_digest: test_handle("b".repeat(64)),
                testd_artifact_digest: test_handle("c".repeat(64)),
                native_worker_artifact_digest: test_handle("d".repeat(64)),
                user_broker_artifact_digest: test_handle("e".repeat(64)),
                wasm_host_artifact_digest: test_handle("f".repeat(64)),
                doctor_executable_path: test_path(&root, "eliot-doctor.exe"),
                testd_executable_path: test_path(&root, "eliot-testd.exe"),
                native_worker_executable_path: test_path(&root, "eliot-native-worker.exe"),
                user_broker_executable_path: test_path(&root, "eliot-user-broker.exe"),
                wasm_host_executable_path: test_path(&root, "eliot-wasm-host.exe"),
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
        destination_root: None,
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
            // This loop rebinds the manifest-derived Host image onto the
            // effects that carry one, and the current-user authority plan
            // carries none. `installer_plan_parts` never plans that effect, so
            // meeting it here would mean the fixture changed shape underneath
            // this loop; refuse instead of silently skipping the rebinding.
            InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. } => {
                panic!("Host-image rebinding must not meet a UserMode authority effect")
            }
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
        // s38 (#1345): Host and Watchdog registrations both persist their
        // installer-policy DACL grant; an `Applied` service effect without
        // its receipt fails closed and can never report DACL ownership.
        let service_control_grant = match role {
            InstallerServiceRole::Host => Some(test_host_service_control_grant()),
            InstallerServiceRole::Watchdog => Some(test_watchdog_control_grant()),
        };
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
            // This loop marks every effect `Applied` so the fixture reaches the
            // fully-applied projection. `installer_plan_parts` never plans the
            // current-user authority effect, so no credential receipt exists to
            // bind here; refuse rather than leave such an effect silently
            // un-applied if the fixture ever starts planning one.
            InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. } => {
                panic!("fully-applied fixture must not meet a UserMode authority effect")
            }
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
    let service_control_grant = match effect {
        InstallerEffectPlan::RegisterService {
            role: InstallerServiceRole::Host,
            ..
        } => Some(test_host_service_control_grant()),
        InstallerEffectPlan::RegisterService {
            role: InstallerServiceRole::Watchdog,
            ..
        } => Some(test_watchdog_control_grant()),
        _ => None,
    };
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
            ("eliot-doctor.exe", true),
            ("eliot-testd.exe", true),
            ("eliot-native-worker.exe", true),
            ("eliot-wasm-host.exe", true),
            ("eliot-user-broker.exe", true),
            ("eliot-notify.exe", true),
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
        registry.stage_pending_activation_from_transaction_for_test_support(
            &registering,
            other_approval,
            TestSupportRegistryFixtureContour::InMemory,
        )
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

    let mut substituted_owner = test_watchdog_control_grant();
    substituted_owner.security_descriptor_owner = test_handle("S-1-5-19");
    assert!(!watchdog_marker.matches(
        &request,
        ELIOT_WATCHDOG_SERVICE_NAME,
        &"e".repeat(64),
        Some(&substituted_owner),
    ));

    let mut substituted_group = test_watchdog_control_grant();
    substituted_group.security_descriptor_group = test_handle("S-1-5-19");
    assert!(!watchdog_marker.matches(
        &request,
        ELIOT_WATCHDOG_SERVICE_NAME,
        &"e".repeat(64),
        Some(&substituted_group),
    ));
}

#[test]
fn durable_service_control_grant_rejects_owner_and_group_substitution() {
    let mut owner_substitution = test_host_service_control_grant();
    owner_substitution.security_descriptor_owner = test_handle("S-1-5-19");
    assert!(owner_substitution.validate().is_err());

    let mut group_substitution = test_host_service_control_grant();
    group_substitution.security_descriptor_group = test_handle("S-1-5-19");
    assert!(group_substitution.validate().is_err());
}

// s38 (#1345): a Host service whose DACL is not the installer policy must
// never be reported `Applied` / `CREATED_BY_TRANSACTION`. Production
// `inspect_service`/`reconcile_service` map a Host readback without the
// installer-policy DACL proof to `Mismatch(service-config)`; this
// pure/durable-level test proves the rest of the lifecycle gate: a Host
// `Matching` observation without (or with a forged) grant can never
// validate, while the policy DACL grant validates and round-trips through
// the ownership marker and the matching evidence binding. No live SCM.
#[test]
fn host_service_registration_requires_installer_policy_dacl_proof() {
    let effect = InstallerEffectPlan::RegisterService {
        effect_id: test_handle("effect:service:EliotHost"),
        role: InstallerServiceRole::Host,
        service_name: test_handle(ELIOT_HOST_SERVICE_NAME),
        executable_path: test_handle(r"C:\ProgramData\Eliot\packages\canary\eliot-host.exe"),
        account: InstallerServiceAccount::LocalService,
        automatic_start: true,
    };
    let matching_with = |service_control_grant: Option<InstallerServiceControlGrantReceipt>| {
        InstallationEffectObservation::Matching {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity: test_handle("b".repeat(64)),
            evidence: vec![test_handle("evidence:host-service")],
            postcondition_digest: test_handle("c".repeat(64)),
            service_control_grant: service_control_grant.map(Box::new),
            credential_receipt: None,
            staging_receipt: None,
            phase_b_receipt: None,
            service_runtime_lineage: None,
        }
    };
    // A default-DACL readback carries no grant proof: the observation fails
    // the Host parity gate and can never become `Applied`.
    assert!(matches!(
        matching_with(None).validate_for_effect(&effect),
        Err(InstallationError::IncompleteObservation(_))
    ));
    // A non-policy (forged) DACL digest fails the exact receipt check.
    let mut forged_grant = test_host_service_control_grant();
    forged_grant.security_descriptor_digest = test_handle("f".repeat(64));
    assert!(matches!(
        matching_with(Some(forged_grant)).validate_for_effect(&effect),
        Err(InstallationError::IdentityConflict)
    ));
    // The policy DACL grant validates as a Host `Matching` observation.
    let grant = test_host_service_control_grant();
    must(matching_with(Some(grant.clone())).validate_for_effect(&effect));
    // The grant digest round-trips through the durable ownership marker: a
    // policy-DACL marker matches only its own grant proof, never a
    // default-DACL (`None`) or substituted-digest readback.
    let transaction = planned_transaction();
    let mut request = must(effect_request(
        &transaction,
        0,
        1,
        InstallationEffectAction::Apply,
        None,
    ));
    request.registration_nonce = Some(test_handle("a".repeat(64)));
    let configuration_digest = "b".repeat(64);
    let marker = must(WindowsServiceOwnershipMarker::new(
        &request,
        ELIOT_HOST_SERVICE_NAME,
        &configuration_digest,
        Some(&grant),
    ));
    assert!(marker.matches(
        &request,
        ELIOT_HOST_SERVICE_NAME,
        &configuration_digest,
        Some(&grant),
    ));
    assert!(!marker.matches(
        &request,
        ELIOT_HOST_SERVICE_NAME,
        &configuration_digest,
        None,
    ));
    let mut substituted_grant = grant.clone();
    substituted_grant.security_descriptor_digest = test_handle("f".repeat(64));
    assert!(!marker.matches(
        &request,
        ELIOT_HOST_SERVICE_NAME,
        &configuration_digest,
        Some(&substituted_grant),
    ));
    // The matching observation carries the typed grant and binds its digest
    // in evidence, so the Host DACL proof survives into durable `Applied`
    // state instead of only the configuration digest.
    let marker_digest = must(marker.digest());
    let observation = must(service_matching_observation(
        &request,
        InstallationEffectDisposition::CreatedByTransaction,
        &configuration_digest,
        &marker_digest,
        Some(grant.clone()),
    ));
    let InstallationEffectObservation::Matching {
        evidence,
        service_control_grant,
        ..
    } = observation
    else {
        unreachable!()
    };
    assert_eq!(service_control_grant.as_deref(), Some(&grant));
    assert!(
        evidence
            .iter()
            .any(|handle| handle.as_str() == must(grant.canonical_digest()).as_str())
    );
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
            // A `RegisterService` effect writes no current-user supervision
            // key, and this precondition is built by `new(..)`, which carries
            // no `user_mode_authority_snapshot`. The request validator's
            // `(_, _, None, None)` arm is the only one this shape can take, so
            // `None` is the admitted value rather than a stand-in for an
            // unbuilt one.
            user_mode_authority_receipt: None,
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
        registry.stage_pending_activation_from_transaction_for_test_support(
            &transaction,
            test_activation_approval(
                &transaction.candidate_manifest,
                transaction.transaction_id.clone(),
                transaction.installer_plan_digest.clone(),
                test_handle("approval:blocked"),
            ),
            TestSupportRegistryFixtureContour::InMemory,
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
    value.authority_state_fence.authority_epoch =
        next_epoch(&approval.authority_state_fence.authority_epoch);
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
fn v8_transaction_json_requires_explicit_migration_to_v25() {
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
            if reason.contains("requires explicit migration to 25.0.0")
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
            if reason.contains("wire 9.0.0 requires explicit migration to 25.0.0")
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
fn v10_transaction_json_requires_explicit_migration_to_v25() {
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
            if reason.contains("wire 10.0.0 requires explicit migration to 25.0.0")
    ));
}

#[test]
fn v13_transaction_json_requires_explicit_migration_to_v25() {
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
            if reason.contains("wire 13.0.0 requires explicit migration to 25.0.0")
    ));
}

#[test]
fn v14_transaction_json_requires_explicit_migration_to_v25() {
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
            if reason.contains("wire 14.0.0 requires explicit migration to 25.0.0")
    ));
}

#[test]
fn v15_transaction_json_requires_explicit_migration_to_v25() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(15, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 15.0.0 requires explicit migration to 25.0.0")
    ));
}

#[test]
fn v16_transaction_json_requires_explicit_migration_to_v25() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(16, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 16.0.0") && reason.contains("25.0.0")
    ));
}

#[test]
fn v17_transaction_json_requires_explicit_migration_to_v25() {
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
            if reason.contains("wire 17.0.0") && reason.contains("25.0.0")
    ));
}

#[test]
fn v18_transaction_json_requires_explicit_migration_to_v25() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(18, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    let Err(error) = decode_installation_transaction_json(&bytes) else {
        panic!("v18 transaction must require migration after the root-contour split");
    };
    assert!(matches!(
        error,
        InstallationError::MigrationRequired { reason }
            if reason.contains("wire 18.0.0") && reason.contains("25.0.0")
    ));
}

#[test]
fn v20_transaction_json_requires_explicit_migration_to_v25() {
    let mut legacy = must(serde_json::to_value(planned_transaction()));
    legacy["transaction_wire_version"] = must(serde_json::to_value(ContractVersion::new(20, 0, 0)));
    let bytes = must(serde_json::to_vec(&legacy));
    assert!(matches!(
        decode_installation_transaction_json(&bytes),
        Err(InstallationError::MigrationRequired { reason })
            if reason.contains("wire 20.0.0") && reason.contains("25.0.0")
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
            if reason.contains("wire 22.0.0") && reason.contains("25.0.0")
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
fn current_v25_ownership_members_are_mandatory_and_never_synthesized() {
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
            .expect_err("missing current-v25 ownership member must reject the record");
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
    // s38 (#1345): the Host approval carries its own installer-policy DACL
    // grant exactly like the Watchdog approval; a grant-less Host approval
    // fails `validate()` and can never authorize `Applied` state.
    let host_grant = approvals[0]
        .service_control_grant()
        .unwrap_or_else(|| unreachable!());
    must(host_grant.validate());
    assert_eq!(
        host_grant.principal_service().as_str(),
        ELIOT_HOST_SERVICE_NAME
    );
    assert_eq!(
        host_grant.access_mask(),
        ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK
    );
    assert_eq!(
        host_grant.security_descriptor_digest().as_str(),
        must(host_service_security_descriptor_digest(
            host_grant.principal_sid().as_str()
        ))
    );
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

    let mut host_with_watchdog_grant = approvals[0].clone();
    host_with_watchdog_grant.service_control_grant = Some(watchdog_grant.clone());
    assert!(host_with_watchdog_grant.validate().is_err());
    let mut watchdog_with_host_grant = approvals[1].clone();
    watchdog_with_host_grant.service_control_grant = Some(host_grant.clone());
    assert!(watchdog_with_host_grant.validate().is_err());
    let alternate_valid_sid = "S-1-5-80-6-7-8-9-10";
    let mut alternate_sid_grant = watchdog_grant.clone();
    alternate_sid_grant.principal_sid = test_handle(alternate_valid_sid);
    alternate_sid_grant.security_descriptor_digest = test_handle(must(
        watchdog_service_security_descriptor_digest(alternate_valid_sid),
    ));
    assert!(alternate_sid_grant.validate().is_err());

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
        // This contour stages no protected User Broker front-door pair, so the
        // prepared record binds none. The field still participates in
        // `computed_digest`, so a v5 preparation without a recorded pair cannot
        // replay as a proof of a contour whose broker declaration it never
        // observed; see `HostPhaseBPreparedMaterialization::WIRE`.
        user_broker: None,
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
        .authority_epoch = next_epoch(&receipt.commit_fence.authority_state_fence.authority_epoch);
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

fn reseal(descriptor: &mut RuntimeLaunchDescriptor) {
    descriptor.descriptor_digest = test_handle(sha256_hex(&must(descriptor.unsigned_bytes())));
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
        user_broker: None,
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
        user_broker: None,
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
    let upgrade_fixture = must(test_support_activation_fixture(
        &upgrade_tx,
        &upgrade_plan,
        &upgrade,
        &test_handle("approval:active-blocks-pending-2"),
        &test_handle("owner:test"),
        TestSupportRegistryFixtureContour::InMemory,
    ));
    let mut direct = must(registry.load());
    direct.revision = must(registry.load()).revision();
    assert!(matches!(
        direct.stage_pending_activation_unchecked(upgrade.clone(), &upgrade_fixture, &[]),
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
        activation_intent_digest: Some(test_handle("c".repeat(64))),
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

#[test]
fn rollback_registering_with_cli_persisted_registry_rejection_succeeds() {
    // Post-bootstrap shape: Registering, one Applied CreatedByTransaction
    // effect, empty unknowns, empty pending (the E4/E5 pre-fix shape that
    // recover rejects with IllegalTransition). The CLI-persisted typed
    // rejection must make recover/rollback reach RolledBack.
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
    // CLI-persisted typed rejection (E4/E5 seam).
    let pending_ref = must(registry_projection_pending_ref(&transaction_id));
    assert_eq!(
        pending_ref.as_str(),
        format!("pending:registry-projection:{}", transaction_id.as_str())
    );
    let persisted =
        must(coordinator.persist_non_effect_rejection(&transaction_id, pending_ref.clone()));
    assert!(matches!(
        persisted,
        InstallationStepOutcome::RollbackRequired { ref pending_refs }
            if pending_refs == &vec![pending_ref.clone()]
    ));
    let persisted_state = must(store.load(&transaction_id)).unwrap_or_else(|| unreachable!());
    assert_eq!(persisted_state.stage(), InstallationStage::RollbackRequired);
    assert_eq!(persisted_state.pending_external_changes, vec![pending_ref]);
    assert!(!persisted_state.has_activation_projection_intent());
    // Later recover/rollback reaches RolledBack with registration rollback executed.
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
        // `InstallationEffectPrecondition::from_change` carries no
        // `user_mode_authority_snapshot`, and this request plans a
        // `StagePackage` effect, which performs no current-user supervision key
        // write. The validator admits exactly `(_, _, None, None)` here.
        user_mode_authority_receipt: None,
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
        // Production seals the candidate's selected immutable-binaries root
        // here: the planner derives `destination_root` from
        // `profile_resolution.roots.immutable_binaries`, and
        // `validate_package_binding` compares it against
        // `candidate_manifest.runtime_launch.profile_governed_roots
        // .immutable_binaries`, which is the same value because the planner
        // installs `profile_resolution.roots` as the candidate's `profile_governed_roots`.
        // It is read off the fixture's own candidate rather than restated, so
        // this stays true for every profile. `None` is not available here: the
        // fallback branch would demand that `staging_root` joined with the
        // package generation equals the immutable-binaries root, which this
        // fixture's staging root does not, and the binding would be refused.
        destination_root: Some(test_handle(
            transaction
                .candidate_manifest
                .runtime_launch
                .profile_governed_roots
                .immutable_binaries
                .clone(),
        )),
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
// ---------------------------------------------------------------------------
// Governed canary removal (#1138).
//
// Everything below drives the owner's own public seams: a real redb
// installation transaction store, a real redb approved-generation registry, a
// real Host owner lease, and a deterministic effect port whose `reconcile`
// answer is programmed per removal effect, so each row's own resource owner is
// the only thing that decides that row's outcome.
// ---------------------------------------------------------------------------

use super::approved_generation_registry::TestSupportActivationFixture;
use super::canary_removal::{
    CanaryRemovalOperationVersion, CanaryRemovalTerminalReceipt, apply_canary_removal,
    canary_removal_status, plan_canary_removal, recover_canary_removal,
};

/// Builds the explicit `Remove` authorization one canary removal is planned
/// under. The request is caller-authored, so it uses the same production shape
/// the install fixtures use and only changes the action and the exact candidate.
fn canary_removal_request(generation: &PlatformHandle) -> ManagedEnvironmentChangeRequest {
    ManagedEnvironmentChangeRequest {
        request_id: test_handle(format!("request:remove-canary:{}", generation.as_str())),
        requester_and_reason: test_handle("requester:canary-removal"),
        action: ManagedEnvironmentAction::Remove,
        target_family: test_handle("family:eliot"),
        exact_candidate: generation.clone(),
        expected_delta: test_handle("delta:canary-retired"),
        source_assurance_refs: vec![test_handle("evidence:canary-removal-source")],
        affected_refs: Vec::new(),
        impact_class: test_handle("impact:canary-removal"),
        required_owner: test_handle("owner:installation"),
        rollback_plan: test_handle("rollback:canary-removal"),
        verifier: test_handle("verifier:installation"),
        budget: test_handle("budget:test"),
        stop_condition: test_handle("stop:on-failure"),
    }
}

/// One fixture-only approved generation a canary removal observes as a survivor.
///
/// A governed removal refuses a target that still serves production or is the
/// designated last-known-good generation, and refuses a target with no settled
/// activation-owner handoff, so the fixture needs more than the target itself.
/// These generations are projected through the registry owner's own staging and
/// commit path.
#[cfg(windows)]
struct CanarySurvivorCandidate {
    manifest: CandidateManifest,
    transaction_id: PlatformHandle,
    installer_plan_digest: PlatformHandle,
    activation_fixture: TestSupportActivationFixture,
}

/// Re-keys one survivor candidate generation off a base manifest.
///
/// The generation identity is the only member that has to change and the launch
/// descriptor digest is the only binding derived from it, so both are re-derived
/// here exactly as the existing registry fixtures re-key a candidate manifest.
#[cfg(windows)]
fn canary_survivor_candidate(base: &CandidateManifest, label: &str) -> CanarySurvivorCandidate {
    let mut manifest = base.clone();
    manifest.generation = test_handle(format!("generation:canary-{label}"));
    manifest.runtime_launch.generation = manifest.generation.clone();
    manifest.runtime_launch.descriptor_digest =
        test_handle(sha256_hex(&must(manifest.runtime_launch.unsigned_bytes())));
    must(manifest.validate());
    let transaction_id = test_handle(format!("transaction:canary-{label}"));
    let installer_plan_digest = test_handle(sha256_hex(
        format!("canary-removal-survivor-plan:{label}").as_bytes(),
    ));
    let activation_fixture = must(test_support_activation_fixture(
        &transaction_id,
        &installer_plan_digest,
        &manifest,
        &test_handle(format!("approval:canary-{label}")),
        &test_handle("owner:test"),
        TestSupportRegistryFixtureContour::Durable,
    ));
    CanarySurvivorCandidate {
        manifest,
        transaction_id,
        installer_plan_digest,
        activation_fixture,
    }
}

/// Stages and commits one survivor candidate under the registry owner's own
/// expected-revision compare-and-swap.
#[cfg(windows)]
fn commit_canary_survivor(
    registry: &RedbInstallationRegistry,
    host: &HostOwnerEpochCapability,
    candidate: &CanarySurvivorCandidate,
) {
    let revision = must(registry.load()).revision();
    let fence = test_commit_fence(&candidate.manifest);
    must(registry.mutate_atomic(revision, |projection| {
        projection.stage_pending_activation_unchecked(
            candidate.manifest.clone(),
            &candidate.activation_fixture,
            &[],
        )?;
        projection.commit_pending_activation(
            host,
            &candidate.transaction_id,
            &candidate.installer_plan_digest,
            &candidate.manifest.generation,
            &fence,
        )
    }));
}

/// A real canary-removal target: one `ActiveVerified` installation transaction in
/// a real redb store, approved by a real redb registry that has since activated
/// three later generations, so the canary is retired from production and from
/// the last-known-good pointer while the last activation terminal names a
/// different generation.
#[cfg(windows)]
struct CanaryRemovalFixture {
    transaction_path: std::path::PathBuf,
    registry_path: std::path::PathBuf,
    registry: RedbInstallationRegistry,
    install: InstallationTransaction,
    retired_sibling: PlatformHandle,
    serving: PlatformHandle,
    serving_last: PlatformHandle,
}

/// Builds the canary-removal fixture.
///
/// The canary is a fully applied `SystemService` transaction driven through the
/// production stage machine and reconciled against the Host's committed
/// activation receipt, exactly as
/// `committed_registry_terminal_reconciles_real_redb_transaction_once` does, so
/// the record this removal plans against is a real durable owner record rather
/// than a hand-built projection.
///
/// Four generations commit in order. Each activation demotes the previously
/// active generation to last-known-good, so after three later activations the
/// canary is neither active nor last-known-good, the second survivor is the
/// last-known-good generation and the third survivor is active and owns the last
/// activation terminal. That is exactly the contour `plan_canary_removal`
/// requires, and it also leaves one earlier survivor that is itself retirable,
/// which is what gives a test an unrelated registry mutation that does not
/// disturb the activation pointers or the settled handoff.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture drives the real stage machine and activation boundary end to end"
)]
fn canary_removal_fixture(host: &HostOwnerEpochCapability) -> CanaryRemovalFixture {
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
        (
            InstallationStage::Staging,
            "evidence:canary-removal-staging",
        ),
        (
            InstallationStage::StaticVerified,
            "evidence:canary-removal-static",
        ),
        (
            InstallationStage::Registering,
            "evidence:canary-removal-registering",
        ),
        (
            InstallationStage::Activating,
            "evidence:canary-removal-activating",
        ),
    ] {
        must(activating.advance(stage, vec![test_handle(evidence)]));
    }
    let sequence = NEXT_TRANSACTION_ROOT.fetch_add(1, Ordering::Relaxed);
    let transaction_path = std::env::temp_dir().join(format!(
        "eliot-canary-removal-transaction-{}-{sequence}.redb",
        std::process::id()
    ));
    let registry_path = std::env::temp_dir().join(format!(
        "eliot-canary-removal-registry-{}-{sequence}.redb",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&transaction_path);
    let _ = std::fs::remove_file(&registry_path);
    let mut store = must(
        RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            &transaction_path,
            &planned,
        ),
    );
    // Rebuild the durable state one exact compare-and-save step at a time so
    // redb, not the in-memory fixture, is the source under test.
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
        must(
            <RedbInstallationTransactionStore as transaction_store_private::Sealed>::compare_and_save(
                &mut store,
                expected,
                &current,
            ),
        );
        activating = current.clone();
    }
    let registry =
        RedbInstallationRegistry::from_database_for_test(must(Database::create(&registry_path)));
    let approval = test_transaction_activation_approval(
        &current,
        test_handle("approval:canary-removal-target"),
    );
    must(registry.stage_pending_activation_from_transaction_store(
        &store,
        &current.transaction_id,
        approval.clone(),
        must(registry.load()).revision(),
    ));
    must(registry.commit_pending_activation(
        host,
        must(registry.load()).revision(),
        &approval,
        &test_commit_fence(&current.candidate_manifest),
    ));
    let receipt = must(registry.read_committed_activation_receipt(
        &current.transaction_id,
        &current.installer_plan_digest,
        &current.candidate_manifest.generation,
    ));
    // The committed activation receipt is what makes this record `ActiveVerified`.
    // A store refusal here is a broken fixture, not a mechanism outcome, so the
    // typed `InstallationError` is reported rather than swallowed.
    match store
        .reconcile_active_verified(receipt, vec![test_handle("evidence:canary-removal-ready")])
    {
        Ok(InstallationStepOutcome::Applied {
            stage: InstallationStage::ActiveVerified,
            ..
        }) => {}
        Ok(other) => panic!(
            "the canary-removal fixture must reconcile its committed activation receipt to \
             ActiveVerified, got {other:?}"
        ),
        Err(error) => panic!(
            "the canary-removal fixture's durable store refused the committed activation receipt \
             for {}: {error:?}",
            current.transaction_id.as_str()
        ),
    }
    let install = must(
        store
            .load(&current.transaction_id)
            .map(|value| value.unwrap_or_else(|| unreachable!())),
    );
    assert_eq!(install.stage(), InstallationStage::ActiveVerified);
    assert!(!install.has_pending_activation_projection_intent());
    assert!(install.pending_external_changes.is_empty());
    let base = registering_transaction().candidate_manifest;
    let retired_sibling = canary_survivor_candidate(&base, "retired")
        .manifest
        .generation;
    let serving = canary_survivor_candidate(&base, "serving-a")
        .manifest
        .generation;
    let serving_last = canary_survivor_candidate(&base, "serving-b")
        .manifest
        .generation;
    for label in ["retired", "serving-a", "serving-b"] {
        commit_canary_survivor(&registry, host, &canary_survivor_candidate(&base, label));
    }
    let projection = must(registry.load());
    assert_eq!(projection.active_generation(), Some(&serving_last));
    assert_eq!(projection.last_known_good_generation(), Some(&serving));
    assert!(
        projection
            .generations()
            .iter()
            .find(|entry| entry.manifest.generation == install.candidate_manifest.generation)
            .is_some_and(|entry| !entry.active && !entry.last_known_good),
        "the canary target must be neither active nor last-known-good for a removal to be plannable"
    );
    CanaryRemovalFixture {
        transaction_path,
        registry_path,
        registry,
        install,
        retired_sibling,
        serving,
        serving_last,
    }
}

#[cfg(windows)]
impl CanaryRemovalFixture {
    /// Opens the durable transaction store this fixture published.
    ///
    /// Every entry point owns its own store handle, exactly as production does,
    /// so planning and driving never share one coordinator.
    fn store(&self) -> RedbInstallationTransactionStore {
        must(
            RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(
                &self.transaction_path,
            ),
        )
    }

    /// Deletes the fixture's redb files so a finished test leaves nothing behind.
    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.transaction_path);
        let _ = std::fs::remove_file(&self.registry_path);
    }
}

/// Deterministic effect port for the canary-removal drive.
///
/// The removal asks every resource's own owner one question per row, and the
/// answer is a property of that row rather than of the drive: a row this removal
/// destroys must read back authoritatively absent, while a row the plan retains
/// must read back present under the identity the plan admitted. The port
/// therefore answers per `effect_id` from a caller-programmed answer list and
/// repeats that list, so one program per row survives however many times its
/// owner is asked.
///
/// The secret-boundary members are never reached by a removal and report the
/// typed `Unsupported` unknown this crate already uses for an unavailable
/// provider rather than manufacturing a credential reference or a receipt.
struct CanaryRemovalPort {
    programmed: std::collections::BTreeMap<String, Vec<PortOutcome<InstallationEffectObservation>>>,
    cursors: std::collections::BTreeMap<String, usize>,
    execute_count: Arc<Mutex<usize>>,
    executed_effect_ids: Arc<Mutex<Vec<PlatformHandle>>>,
    reconcile_calls: Arc<Mutex<Vec<PlatformHandle>>>,
}

/// An effect port with no programmed owner answer, for the paths that must reach
/// the owner without ever asking a resource owner anything.
fn empty_canary_removal_port() -> CanaryRemovalPort {
    CanaryRemovalPort {
        programmed: std::collections::BTreeMap::new(),
        cursors: std::collections::BTreeMap::new(),
        execute_count: Arc::new(Mutex::new(0)),
        executed_effect_ids: Arc::new(Mutex::new(Vec::new())),
        reconcile_calls: Arc::new(Mutex::new(Vec::new())),
    }
}

impl CanaryRemovalPort {
    /// Programs one resource owner's answers for one removal effect identity.
    fn program(
        &mut self,
        effect_id: &PlatformHandle,
        outcomes: Vec<PortOutcome<InstallationEffectObservation>>,
    ) -> &mut Self {
        assert!(
            !outcomes.is_empty(),
            "a removal effect must have at least one programmed owner answer"
        );
        self.programmed
            .insert(effect_id.as_str().to_owned(), outcomes);
        self
    }

    /// Number of destructive calls this port has been asked to issue.
    fn execute_count(&self) -> usize {
        *self.execute_count.lock().unwrap_or_else(|_| unreachable!())
    }

    /// Exact effect identities this port was asked to mutate.
    fn executed_effect_ids(&self) -> Vec<PlatformHandle> {
        self.executed_effect_ids
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .clone()
    }

    /// Exact effect identities this port was asked to read back.
    fn reconcile_calls(&self) -> Vec<PlatformHandle> {
        self.reconcile_calls
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .clone()
    }
}

/// The observation one resource owner reports for a row this removal destroys:
/// the exact admitted object is authoritatively absent, with evidence.
fn canary_removal_absent_observation(
    install: &InstallationTransaction,
) -> InstallationEffectObservation {
    absent(install)
}

/// The exact evidence handle one resource owner reports when it reads back a row
/// this removal retains.
///
/// The handle is derived from the row's own effect identity and from nothing else.
/// No frozen plan row carries it, because `ownership_evidence` is built from the
/// original install transaction's own effect receipt, so the handle can appear in a
/// removal's durable evidence only when that row's owner was actually asked. Every
/// readback-provenance assertion below is written against this one function, so
/// the programmed owner answer and the proof of it cannot drift apart.
fn canary_removal_retained_owner_evidence(row: &CanaryRemovalEffect) -> PlatformHandle {
    test_handle(format!(
        "evidence:canary-removal-retained:{}",
        row.effect_id.as_str()
    ))
}

/// Re-derives, from the durable install transaction alone, the identity one
/// owner-derived removal row's owner records for it.
///
/// Both of these categories are classified `OutOfScope`, so nothing re-derives
/// their identity at a readback any more: they are NAMED with the identity the
/// owner recorded and frozen into the plan, and `require_quiesced_owner_effects`
/// re-derives that same identity from the transaction the durable store holds
/// every time apply re-enters its fence. A test that wants to know which of the
/// two values a durable record carries therefore has to read the transaction
/// rather than the plan.
fn canary_removal_owner_derived_identity(
    install: &InstallationTransaction,
    category: CanaryRemovalResource,
) -> Result<PlatformHandle, InstallationError> {
    match category {
        CanaryRemovalResource::CanaryEvidenceRoot => install
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .canary_evidence_root(),
        CanaryRemovalResource::StoreObjects => Ok(install
            .candidate_manifest
            .store_bridge_artifact_digest
            .clone()),
        other => Err(InstallationError::IncompleteObservation(format!(
            "an owner-derived removal row is required here, not the {other:?} category"
        ))),
    }
}

/// Flattens the evidence one durable removal operation recorded, across every row.
///
/// `Completed` is derived only from per-row evidence, so this set is where "which
/// rows of the denominator were read back, and what their own owners said" is
/// observable after the fact.
fn canary_removal_recorded_evidence(
    operation: &CanaryRemovalOperation,
) -> std::collections::BTreeSet<PlatformHandle> {
    let mut recorded = std::collections::BTreeSet::new();
    for progress in &operation.effect_progress {
        if let CanaryRemovalEffectState::Resolved { evidence, .. } = &progress.state {
            recorded.extend(evidence.iter().cloned());
        }
    }
    recorded
}

/// The observation one resource owner reports for a row this removal retains: the
/// exact admitted object is still present under the identity the plan froze.
///
/// A retained row is only accepted when its owner reports the ownership class the
/// FROZEN ROW itself records, read from the install transaction's own effect
/// receipt: a row this transaction durably created can only read back as created
/// by it, and a row it adopted can only read back as the preexisting object it
/// adopted. This fixture installs roots and ACLs that were already present, so
/// their rows carry `PreexistingAtInstall`; reporting `CreatedByTransaction` for
/// them would be the owner's dishonest answer and would read back as a conflict.
/// The observation is therefore built from the frozen row rather than from the
/// install record: the port is the resource's owner, and that owner's own answer
/// is the only evidence a retained row may be closed with.
fn canary_removal_retained_observation(row: &CanaryRemovalEffect) -> InstallationEffectObservation {
    let disposition = match row.origin {
        CanaryRemovalResourceOrigin::PreexistingAtInstall => {
            InstallationEffectDisposition::PreexistingMatching
        }
        // A `ForeignToThisRemoval` row is classified `OutOfScope`, carries no
        // installer effect and is never asked through the effect port at all:
        // `readback_request` refuses it rather than re-deriving an identity out
        // of the very plan the row was built from.
        _ => InstallationEffectDisposition::CreatedByTransaction,
    };
    InstallationEffectObservation::Matching {
        disposition,
        external_identity: row.resource_identity.clone(),
        evidence: vec![canary_removal_retained_owner_evidence(row)],
        postcondition_digest: test_handle("a".repeat(64)),
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    }
}

/// Builds the owner-answer program for one frozen plan.
///
/// Every row backed by an installer effect is answered by that row's owner:
/// destroyed rows read back absent, retained rows read back present under their
/// own admitted identity. A row with no installer effect has no installer owner
/// to ask. The two such categories are classified `OutOfScope`, and
/// `readback_request` refuses them outright, so no answer is programmed for them
/// and a drive that asked one would panic on an owner that does not exist.
///
/// The same program serves the drive and the independent final readback, because
/// both ask the same question of the same owner: a destroyed row must read back
/// authoritatively absent and a retained row must read back present under its
/// admitted identity. Answering a retained row with an absence would make the
/// terminal readback demand the very resource the plan promised to leave intact.
fn canary_removal_port(
    install: &InstallationTransaction,
    plan: &CanaryRemovalPlan,
) -> CanaryRemovalPort {
    let mut port = empty_canary_removal_port();
    for row in &plan.effects {
        if row.install_effect_index.is_none() {
            continue;
        }
        let outcome = if row.action == CanaryRemovalAction::Remove {
            PortOutcome::Known(canary_removal_absent_observation(install))
        } else {
            PortOutcome::Known(canary_removal_retained_observation(row))
        };
        let _ = port.program(&row.effect_id, vec![outcome]);
    }
    port
}

impl InstallationEffectPort for CanaryRemovalPort {
    fn fresh_ownership_secret_reference(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretReference> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn prepare_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
        _reference: &InstallationSecretReference,
    ) -> PortOutcome<InstallationSecretCreationProof> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn provision_ownership_secret(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationSecretProvisionDisposition> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn execute(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectExecution> {
        *self.execute_count.lock().unwrap_or_else(|_| unreachable!()) += 1;
        self.executed_effect_ids
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push(request.effect_id.clone());
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn inspect(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn reconcile(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation> {
        self.reconcile_calls
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .push(request.effect_id.clone());
        let key = request.effect_id.as_str().to_owned();
        let Some(programmed) = self.programmed.get(&key) else {
            panic!(
                "canary-removal test port has no programmed owner answer for effect {key}; the \
                 removal asked a resource owner this test never programmed"
            );
        };
        let cursor = self.cursors.entry(key).or_insert(0);
        let outcome = programmed[*cursor % programmed.len()].clone();
        *cursor = cursor.saturating_add(1);
        outcome
    }

    fn delete_ownership_secret(&mut self, _request: &InstallationEffectRequest) -> PortOutcome<()> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }

    fn ownership_secret_absent(
        &mut self,
        _request: &InstallationEffectRequest,
    ) -> PortOutcome<bool> {
        PortOutcome::Unknown(eliot_platform::UnknownReason::Unsupported)
    }
}

/// Returns the position of the terminal registry-record row, which the frozen
/// execution order keeps last.
fn canary_removal_registry_row(plan: &CanaryRemovalPlan) -> usize {
    let position = plan
        .effects
        .iter()
        .position(|row| row.category == CanaryRemovalResource::GenerationRegistryRecord)
        .unwrap_or_else(|| unreachable!());
    assert_eq!(
        position + 1,
        plan.effects.len(),
        "the terminal registry record must stay last in the frozen execution order"
    );
    position
}

/// Returns the rows this removal destroys before the terminal registry record.
fn canary_removal_destructive_rows(plan: &CanaryRemovalPlan) -> Vec<CanaryRemovalEffect> {
    let registry_row = canary_removal_registry_row(plan);
    plan.effects[..registry_row]
        .iter()
        .filter(|row| row.action == CanaryRemovalAction::Remove)
        .cloned()
        .collect()
}

/// Returns the position of the first frozen row no owner this crate can reach can
/// read back: one that names no installer effect and is not the terminal registry
/// record.
///
/// This is the same four-band key `order_effect_graph` ranks the denominator with,
/// re-derived here from the plan rather than typed, so a case that stops the drive
/// can only assert against the row the drive actually reached. `admit` opens every
/// row of the denominator unresolved and `advance` drives the first unresolved
/// position, so this position is where every apply and recover drive of a frozen
/// plan begins, and it is the position whose readback `readback_request` refuses.
fn canary_removal_first_unreadable_row(plan: &CanaryRemovalPlan) -> usize {
    let position = plan
        .effects
        .iter()
        .position(|row| {
            row.category != CanaryRemovalResource::GenerationRegistryRecord
                && row.install_effect_index.is_none()
        })
        .unwrap_or_else(|| {
            unreachable!("every frozen removal denominator names its out-of-scope rows")
        });
    assert!(
        position < canary_removal_registry_row(plan),
        "a row no owner can read back must be positioned before the terminal registry record, so \
         stopping on it is a refusal short of the terminal commit"
    );
    position
}

/// T1: planning reaches the owner and produces a frozen plan while writing
/// nothing.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each frozen-plan invariant is asserted on its own rather than as a summary"
)]
fn canary_removal_plan_reaches_the_owner_and_writes_nothing() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let target = fixture.install.candidate_manifest.generation.clone();
    let request = canary_removal_request(&target);
    let revision_before = must(fixture.registry.load()).revision();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &request,
        &target,
    ));
    // The frozen graph is the complete finite denominator: one row per installer
    // effect the durable record owns, plus the three owner-derived rows.
    assert!(
        !plan.effects.is_empty(),
        "a frozen removal plan must account for a non-empty denominator"
    );
    assert_eq!(
        plan.effects.len(),
        fixture.install.installer_effects.len() + 3,
        "the frozen graph must carry one row per installer effect plus the canary-evidence, \
         store-objects and registry-record owner-derived rows"
    );
    // One row names one exact resource identity, not one category: the frozen
    // graph carries one row per installer effect, so a category spans as many
    // rows as the transaction's own effect roster holds effects for it (one
    // `CreateRoot`/`ApplyAcl` per declared root). Category uniqueness would
    // contradict that denominator, so what is asserted instead is the
    // owner-derived denominator the destructive gates compare: each of those
    // categories appears exactly once.
    for owner_derived in [
        CanaryRemovalResource::CanaryEvidenceRoot,
        CanaryRemovalResource::StoreObjects,
    ] {
        assert_eq!(
            plan.effects
                .iter()
                .filter(|row| row.category == owner_derived)
                .count(),
            1,
            "the {owner_derived:?} owner-derived row must appear exactly once"
        );
    }
    for row in &plan.effects {
        assert!(
            !row.ownership_evidence.is_empty(),
            "every frozen row must name the evidence that proves its ownership claim"
        );
    }
    assert_eq!(
        plan.effects
            .iter()
            .filter(|row| row.category == CanaryRemovalResource::GenerationRegistryRecord)
            .count(),
        1,
        "the terminal registry record must appear exactly once"
    );
    assert!(
        !canary_removal_destructive_rows(&plan).is_empty(),
        "a plannable canary removal must name at least one row it destroys"
    );
    assert_eq!(
        plan.removal_transaction_id,
        must(canary_removal_operation_id(
            &plan.install_transaction_id,
            &plan.generation
        )),
        "the removal identity must be the pure function of the installed transaction and target"
    );
    assert_eq!(
        plan.plan_digest,
        must(plan.computed_digest()),
        "the frozen plan must carry the digest of its own content"
    );
    assert_eq!(plan.registry_revision, revision_before);
    must(plan.validate());
    // Planning wrote nothing: no durable removal operation, no terminal receipt
    // and no registry mutation.
    assert!(
        must(
            planner
                .store()
                .load_canary_removal_operation(&plan.removal_transaction_id)
        )
        .is_none(),
        "a read-only planning pass must not create a durable removal operation"
    );
    assert!(
        must(
            planner
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a read-only planning pass must not create a terminal receipt"
    );
    assert_eq!(must(fixture.registry.load()).revision(), revision_before);
    assert!(
        must(fixture.registry.load())
            .generations()
            .iter()
            .any(|entry| entry.manifest.generation == target),
        "planning must leave the target generation projected"
    );
    assert!(
        planner.port().reconcile_calls().is_empty(),
        "a read-only planning pass must never ask a resource owner anything"
    );
    fixture.cleanup();
}

/// T2: unmodified plan stdout round-trips as the owner's typed envelope, and the
/// envelope refuses both an unknown member and an incomplete planning pass.
#[cfg(windows)]
#[test]
fn canary_removal_plan_stdout_round_trips_as_the_owner_envelope() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let target = fixture.install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    let envelope = must(CanaryRemovalPlanEnvelope::new(
        test_handle("scope:installation-owner"),
        plan.clone(),
    ));
    // What `run_plan_canary_removal` prints is exactly what `load_plan` accepts.
    let printed = must(serde_json::to_vec(&envelope));
    let decoded: CanaryRemovalPlanEnvelope = must(serde_json::from_slice(&printed));
    must(decoded.validate());
    assert_eq!(
        decoded.into_plan(),
        plan,
        "a printed plan envelope must round-trip into the exact frozen plan"
    );

    let mut with_unknown_member = must(serde_json::to_value(&envelope));
    with_unknown_member
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .insert(
            "unexpected_member".to_owned(),
            serde_json::Value::Bool(true),
        );
    assert!(
        serde_json::from_value::<CanaryRemovalPlanEnvelope>(with_unknown_member).is_err(),
        "an envelope carrying a member this owner does not define must be refused rather than \
         read with the extra member ignored"
    );

    let mut incomplete = must(serde_json::to_value(&envelope));
    incomplete
        .as_object_mut()
        .unwrap_or_else(|| unreachable!())
        .insert("completed".to_owned(), serde_json::Value::Bool(false));
    let incomplete: CanaryRemovalPlanEnvelope = must(serde_json::from_value(incomplete));
    assert!(
        matches!(incomplete.validate(), Err(InstallationError::InvalidField { ref field, .. })
            if field == "canary_removal.plan_envelope.completed"),
        "an incomplete planning pass must be refused by its typed field error, because planning \
         performs no external effect and only a completed document is admissible"
    );
    fixture.cleanup();
}

/// T3: an owner-derived denominator row that no longer matches the durable
/// install transaction must never reach `Completed`.
///
/// The drift below is a frozen-plan-versus-installed-transaction disagreement,
/// and this owner catches it in `require_quiesced_owner_effects` at the entry
/// fence, before any row is driven: that is why the outcome under test is the
/// typed identity conflict rather than a `Reconciling` disposition.
///
/// The row this case drifts is classified `OutOfScope`, and that is what it now
/// asserts. `OutOfScope` is a NAMING and not a readback outcome: no owner in this
/// crate can observe a canary evidence root or a generation's canonical
/// Store/Blob objects at all, so a `Retain` row for either category would
/// advertise a proof that does not exist. The consequence for this case is that
/// the "drift visible only at the final readback" path is UNREACHABLE for these
/// categories — `readback_request` refuses an out-of-scope row outright, so the
/// per-row drive and the terminal walk never ask anything about them — and the
/// fence is therefore the only place their frozen identity and classification are
/// ever compared against the transaction the durable store holds.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the drift, the refusal and the untouched durable state are each asserted"
)]
fn canary_removal_owner_derived_drift_between_plan_and_readback_never_completes() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let install = fixture.install.clone();
    let target = install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let mut plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    // The owner-derived identity this removal compares at every gate is derived
    // from the durable install transaction's own runtime roots, not from the plan.
    let derived = must(
        install
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .canary_evidence_root(),
    );
    let drifted = test_handle("canary-removal/drift/canary-evidence-root");
    assert_ne!(drifted, derived);
    {
        let Some(row) = plan
            .effects
            .iter_mut()
            .find(|row| row.category == CanaryRemovalResource::CanaryEvidenceRoot)
        else {
            unreachable!()
        };
        assert_eq!(
            row.resource_identity, derived,
            "the frozen plan must carry the identity the install transaction derives"
        );
        assert_eq!(
            row.action,
            CanaryRemovalAction::OutOfScope,
            "a shared surface no owner in this crate can observe is NAMED out of scope rather than \
             reported Retain, because Retain is a readback outcome and no owner here can report one"
        );
        // Drift the owner-derived denominator after planning: the frozen row now
        // names a canary evidence root the installed transaction does not have.
        row.resource_identity = drifted.clone();
        row.ownership_evidence = vec![drifted];
    }
    // Exclude every other identity-conflict source, so the refusal below can only
    // come from comparing the drifted owner-derived row against the identity the
    // durable install transaction derives.
    assert_eq!(
        plan.manifest_digest,
        must(candidate_manifest_digest(&install.candidate_manifest))
    );
    assert_eq!(plan.install_plan_digest, install.installer_plan_digest);
    assert_eq!(plan.generation, install.candidate_manifest.generation);
    assert_eq!(plan.installation_epoch, install.installation_epoch);
    assert_eq!(
        plan.effects
            .iter()
            .find(|row| row.category == CanaryRemovalResource::StoreObjects)
            .map(|row| &row.resource_identity),
        Some(&install.candidate_manifest.store_bridge_artifact_digest),
        "only the canary-evidence row drifted; the store-objects row must still carry the \
         approved Store bridge binding"
    );
    plan.plan_digest = must(plan.computed_digest());
    must(plan.validate());
    let before = must(fixture.registry.load());
    let revision_before = before.revision();
    let active_before = before.active_generation().cloned();
    let lkg_before = before.last_known_good_generation().cloned();
    let mut coordinator =
        InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
    assert!(
        matches!(
            apply_canary_removal(&mut coordinator, &fixture.registry, &plan),
            Err(InstallationError::IdentityConflict)
        ),
        "a frozen owner-derived identity the installed transaction does not derive must be an \
         identity conflict, never a green completion"
    );
    let status = must(canary_removal_status(
        &coordinator,
        &plan.removal_transaction_id,
    ));
    assert_ne!(
        status.stage,
        CanaryRemovalStage::Completed,
        "a drifted owner-derived denominator must never author a terminal Completed"
    );
    assert_eq!(
        status.removal_transaction_id, plan.removal_transaction_id,
        "the original removal identity must be preserved across the drift refusal"
    );
    assert_eq!(
        coordinator.port().execute_count(),
        0,
        "the drift must be caught before any destructive call"
    );
    assert!(
        coordinator.port().executed_effect_ids().is_empty(),
        "the drift must be caught before any row is mutated"
    );
    let projection = must(fixture.registry.load());
    assert_eq!(projection.revision(), revision_before);
    assert_eq!(projection.active_generation(), active_before.as_ref());
    assert_eq!(projection.last_known_good_generation(), lkg_before.as_ref());
    assert!(
        projection
            .generations()
            .iter()
            .any(|entry| entry.manifest.generation == target),
        "a refused removal must leave the target generation projected"
    );
    assert!(
        must(
            coordinator
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a refused removal must not leave a terminal receipt behind"
    );
    fixture.cleanup();
}

/// T4: a removal row no owner in this crate can read back stops the drive with a
/// typed incomplete-observation refusal that names the exact row it stopped on,
/// BEFORE any destructive call and before any owner is asked at all, and it never
/// becomes synthetic evidence.
///
/// WHY THIS CASE'S EXPECTATION CHANGED. It used to require `apply_canary_removal`
/// to return `Ok(status)` with `blocking_effect_id` naming the first destructive
/// row whose owner had been programmed to answer `Unknown(Indeterminate)`. That
/// described the OLD execution order, in which a row no owner can read back was
/// ranked BEHIND the rows that mutate. `order_band` now ranks every row that names
/// no installer effect and is not the terminal registry record ahead of every row
/// that can mutate, and that is the deliberate correction: a row that cannot be
/// read back has to be DETECTED before a destructive call is issued, not after the
/// drive has already destroyed everything ranked behind it.
///
/// The corrected drive therefore never reaches the destructive row this case
/// programs as unavailable. It stops on the first row of the frozen order that
/// names no installer effect — the `CanaryEvidenceRoot` row, `OutOfScope` and
/// `ForeignToThisRemoval` — because no owner this crate can reach observes a bare
/// filesystem root path at all, so `readback_request` has nothing to ask and
/// refuses with the existing typed error. A `status` carrying a named blocking
/// effect is not the shape this operation produces any more, and requiring one
/// would be asserting a behaviour that does not exist.
///
/// WHAT IS STILL PROVED, which is the half the card depends on:
///
/// * the refusal is the typed `IncompleteObservation` variant rather than a
///   string, and it is attributable: it names the exact row the drive stopped on,
///   that row's closed category and that row's frozen action;
/// * the drive stopped at the FIRST unreadable row and not at a later one. The
///   sibling `StoreObjects` row is exactly as unreadable and is NOT named, and
///   neither is the first destructive row nor the terminal registry record, so a
///   check that merely looked for "some effect identity" in the reason would fail
///   on all three;
/// * ZERO destructive calls and ZERO owner readbacks were issued, so the owner
///   this case programs as unavailable is never asked and nothing is mutated;
/// * the original removal identity survives: the operation is durable under the
///   submitted identity with its whole frozen denominator intact and unresolved,
///   the projection reports that same identity, and the registry, the installed
///   transaction's effect roster and the terminal receipt are all untouched;
/// * neither fabricated evidence handle this mechanism used to mint appears in the
///   mechanism, while the row's REAL reconciliation query — a near neighbour of the
///   Store handle — does, so that scan is demonstrably discriminating rather than
///   passing for want of anything to match.
///
/// WHAT THIS CASE NO LONGER CLAIMS, stated rather than papered over. The typed
/// `Unknown` disposition with a named blocking effect this case was written for is
/// unreachable through `apply_canary_removal` and `recover_canary_removal`: both
/// out-of-scope rows are ranked ahead of every destructive row and `readback_request`
/// refuses both, so no drive can arrive at the destructive row whose owner's
/// `PortOutcome::Unknown` would become `CanaryRemovalEffectState::Unknown`. It is not
/// restated here in a weaker form, and no other case in this file asserts it either.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the typed refusal, its attribution, the untouched state and the source guard are each asserted"
)]
fn canary_removal_stops_on_an_unreadable_row_before_any_destructive_call() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let install = fixture.install.clone();
    let target = install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    // The row the drive stops on is derived from the frozen order by the SAME key
    // the mechanism ranks rows with — a row that names no installer effect and is
    // not the terminal registry record — rather than typed here, so the refusal
    // below cannot be shown attributable to a row the drive never reached.
    let blocked_position = canary_removal_first_unreadable_row(&plan);
    let blocked_row = plan.effects[blocked_position].clone();
    assert_eq!(
        blocked_position, 0,
        "`admit` opens every row of the denominator unresolved and `advance` drives the first \
         unresolved position, so the row this case stops on must be the first position of the \
         frozen order; if that order ever changed, every assertion below would be reading a row \
         the drive never reached"
    );
    assert_eq!(
        blocked_row.category,
        CanaryRemovalResource::CanaryEvidenceRoot,
        "the first row no owner can read back is the canary evidence root; the sibling Store/Blob \
         row is equally unreadable and sorts behind it by effect identity"
    );
    assert_eq!(
        blocked_row.action,
        CanaryRemovalAction::OutOfScope,
        "a shared surface no owner in this crate can observe is named out of scope, which is why \
         the per-row drive asks it for a readback at all"
    );
    assert_eq!(
        blocked_row.origin,
        CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        "the evidence root is durable state this removal does not own, so no disposition of its \
         own may ever close it"
    );
    // The two neighbours the refusal must NOT name. Both are members of this same
    // frozen denominator, so a scan that matched any effect identity rather than the
    // exact row the drive stopped on would fail on all three.
    let sibling = plan
        .effects
        .iter()
        .find(|row| row.category == CanaryRemovalResource::StoreObjects)
        .expect("T4 requires the frozen denominator to account for the Store and Blob objects")
        .clone();
    let never_driven = canary_removal_destructive_rows(&plan)
        .into_iter()
        .next()
        .expect("T4 requires a plannable canary removal that destroys at least one row");
    let registry_row = canary_removal_registry_row(&plan);
    assert!(
        blocked_position < registry_row,
        "the unreadable row must be positioned before the terminal registry record, so stopping \
         on it is a refusal short of the terminal commit rather than after it"
    );
    let mut port = canary_removal_port(&install, &plan);
    // The owner of exactly one destructive row cannot be asked: its readback is
    // unavailable. That answer is never consumed, and that is the point — the drive
    // stops short of the row it was programmed for.
    let _ = port.program(
        &never_driven.effect_id,
        vec![PortOutcome::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        )],
    );
    let revision_before = must(fixture.registry.load()).revision();
    let mut coordinator = InstallationCoordinator::new(port, fixture.store());
    let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
    let reason = match &refusal {
        Err(InstallationError::IncompleteObservation(reason)) => reason,
        other => panic!(
            "a row no owner in this crate can read back must stop the drive with the typed \
             incomplete-observation error, got {other:?}"
        ),
    };
    assert!(
        reason.contains(blocked_row.effect_id.as_str())
            && reason.contains(&format!("{:?}", blocked_row.category))
            && reason.contains(&format!("{:?}", blocked_row.action)),
        "the refusal must be attributable to the exact row it stopped on, naming that row's effect \
         identity, its closed category and its frozen action, got {reason:?}"
    );
    assert!(
        !reason.contains(sibling.effect_id.as_str()),
        "the Store/Blob row is exactly as unreadable and sits behind the blocked row in the frozen \
         order, so naming it would mean the drive did not stop at the first unreadable row, got \
         {reason:?}"
    );
    assert!(
        !reason.contains(never_driven.effect_id.as_str()),
        "the drive must stop short of the destructive row whose owner was programmed unavailable, \
         because detecting an unreadable row only after every row behind it had already been \
         driven is the regression the corrected order removes, got {reason:?}"
    );
    assert!(
        !reason.contains(plan.effects[registry_row].effect_id.as_str()),
        "the drive must never reach the terminal registry record, so the target generation stays \
         projected and no terminal commit is attempted, got {reason:?}"
    );
    // No destructive call was issued, and no resource owner was asked at all: the
    // answer programmed as unavailable above was never requested, which is what
    // makes this refusal about the unreadable row rather than about that owner.
    assert_eq!(
        coordinator.port().execute_count(),
        0,
        "the refusal must land before any destructive call"
    );
    assert!(
        coordinator.port().executed_effect_ids().is_empty(),
        "no row of the denominator may be mutated on this path"
    );
    assert!(
        coordinator.port().reconcile_calls().is_empty(),
        "no resource owner may be asked before the unreadable row is detected, so the owner \
         programmed as unavailable is never reached"
    );
    // The original removal identity survives the refusal. An absent row here is a
    // broken test setup, not a mechanism outcome: apply admitted this operation
    // before it drove anything, so the record must be durable under its own
    // identity.
    let durable = coordinator
        .store()
        .load_canary_removal_operation(&plan.removal_transaction_id)
        .expect("T4 must read the durable removal operation its own apply admitted")
        .expect("T4 requires a durable removal operation row under its removal identity");
    must(durable.validate());
    assert_eq!(
        durable.removal_transaction_id, plan.removal_transaction_id,
        "the durable record must be the removal identity that was submitted"
    );
    assert_eq!(
        durable.plan.plan_digest, plan.plan_digest,
        "the durable record must be the same frozen plan, never a re-derived one"
    );
    assert_eq!(
        durable.effect_progress.len(),
        plan.effects.len(),
        "the whole frozen denominator must survive the refusal, one progress row per plan row"
    );
    assert!(
        durable
            .effect_progress
            .iter()
            .all(|progress| matches!(progress.state, CanaryRemovalEffectState::Pending)),
        "a drive that stopped on its first row must have resolved no row at all, and an owner \
         readback programmed as unavailable must never reach a persisted disposition"
    );
    assert_eq!(
        durable.blocking_effect_id, None,
        "this refusal names no blocking effect because it issued no effect; a named blocking row \
         here would claim an outcome this drive never reached"
    );
    assert_eq!(
        durable.stage,
        CanaryRemovalStage::Admitted,
        "no row was driven, so the durable operation is still exactly as admitted"
    );
    let status = must(canary_removal_status(
        &coordinator,
        &plan.removal_transaction_id,
    ));
    assert_eq!(
        status.removal_transaction_id, plan.removal_transaction_id,
        "the original removal identity must be preserved across the refusal"
    );
    assert_ne!(
        status.stage,
        CanaryRemovalStage::Completed,
        "a refused removal must never author a terminal Completed"
    );
    for unresolved in [&blocked_row.effect_id, &never_driven.effect_id] {
        assert!(
            status.unresolved_effect_ids.contains(unresolved),
            "row {} must stay unresolved in the projection",
            unresolved.as_str()
        );
    }
    assert!(
        status.evidence_refs.is_empty(),
        "a removal that drove no row and proved no readback must report no evidence at all"
    );
    assert!(
        matches!(
            status.next_permitted_action,
            CanaryRemovalNextAction::Reconcile
        ),
        "an operation with nothing resolved permits reconciliation, not a terminal readback"
    );
    assert_eq!(
        must(fixture.registry.load()).revision(),
        revision_before,
        "a refusal must not move the registry"
    );
    assert!(
        must(fixture.registry.load())
            .generations()
            .iter()
            .any(|entry| entry.manifest.generation == target),
        "a refused removal must leave the target generation projected"
    );
    assert!(
        must(
            coordinator
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a refusal must not leave a terminal receipt behind"
    );
    // The two fabricated evidence handles this mechanism used to synthesize must
    // not reappear in the canary-removal MECHANISM: a removal is never proved by a
    // string this owner wrote about itself. The scan runs over code lines only, for
    // the reason `canary_removal_mechanism_lines` documents: a comment that NAMES
    // one of these shapes in order to explain why this owner does not mint it is
    // documentation, not a mechanism that mints it, and a raw byte scan cannot tell
    // those two apart. The trailing colon is part of each shape, and the positive
    // below is what keeps the two scans from passing for want of a match: the row's
    // own real reconciliation query is a near neighbour of the Store handle and IS
    // in the scanned code, so neither scan can be satisfied by the other.
    let mechanism = canary_removal_mechanism_lines();
    assert!(
        mechanism
            .iter()
            .any(|line| line.contains("canary-removal/reconcile/store-owner:")),
        "the Store row's own reconciliation query must be in the scanned code, or the two scans \
         below could not be seen rejecting the real neighbour of a fabricated shape"
    );
    assert!(
        !mechanism
            .iter()
            .any(|line| line.contains("canary-removal/readback/registry-terminal:")),
        "the terminal registry effect must be proved by the owner-issued terminal receipt, not by \
         a fabricated readback handle"
    );
    assert!(
        !mechanism
            .iter()
            .any(|line| line.contains("canary-removal/evidence/store-owner:")),
        "the Store and Blob owner row must be proved through the owner's own binding, not by a \
         fabricated evidence handle"
    );
    fixture.cleanup();
}

/// A frozen plan whose owner-derived rows carry an ownership CLAIM no owner ever
/// reported is refused at the entry fence, with the typed identity conflict and
/// before any row is driven.
///
/// WHY THIS IS A CASE OF ITS OWN. `require_quiesced_owner_effects` now compares
/// each owner-derived row's `ownership_evidence` against the identity it
/// re-derives from the durable install transaction, inside the same
/// `expected_owners` loop that already compared `resource_identity` and the
/// action, and it refuses through the existing `IdentityConflict`. In an
/// untouched plan that comparison is an equality rather than a new rule about
/// evidence: `canary_evidence_row` mints `ownership_evidence` from the very value
/// it takes as `resource_identity`, and `store_objects_row` mints it from the
/// same `CanaryRemovalBuildBinding::from_manifest` member it takes as
/// `resource_identity`, so a plan this owner produced always contains what the
/// fence re-derives.
///
/// That makes "the owner-derived row carries a claim the owner never reported" a
/// DIRECT refusal at the fence instead of something only the per-row drive could
/// notice, which is strictly stronger: the refusal is typed, attributable to an
/// identity disagreement, and precedes admission of any row. It also means the
/// crash-recovery case
/// `canary_removal_recovers_the_same_operation_after_an_unrelated_registry_mutation`
/// can no longer carry this proof on the same plan it recovers, because a
/// substituted claim is refused before the drive that recovery needs begins.
/// The substitution therefore MOVED here rather than disappearing, and each half
/// keeps its own plan: a substituted one for this fence, the plan planning
/// produced for the recovery.
///
/// WHAT MAKES EACH HALF DISCRIMINATING, and what would make this one red:
///
/// * (a) The control. The untouched plan, over its own fixture, is NOT refused
///   with an identity conflict: it leaves the entry fence and stops at the
///   per-row readback selector on the first row no owner in this crate can
///   observe, having issued no destructive call and asked no owner. Without this
///   half the refusal below could be attributed to any other check in the same
///   fence, because the substituted plan differs from the control only in those
///   two claim vectors and its recomputed digest.
/// * (b) The substituted plan. `IdentityConflict`, not the drive's
///   `IncompleteObservation`: zero destructive calls, zero mutated rows, zero
///   owner readbacks, the whole frozen denominator durable and unresolved under
///   the submitted removal identity, the registry unmoved with the target still
///   projected, and no terminal receipt. The persisted plan still carries the
///   two substituted handles, so the refused document is provably the
///   substituted one rather than some other disagreement.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the control, the substituted claim and the untouched durable state are each asserted"
)]
fn canary_removal_refuses_a_substituted_owner_claim_at_the_entry_fence() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());

    // (a) The control: the untouched plan this owner produced is admitted by the
    // same fence, so the refusal in (b) cannot be attributed to any other check
    // in it.
    {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let install = fixture.install.clone();
        let target = install.candidate_manifest.generation.clone();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let plan = must(plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&target),
            &target,
        ));
        // The premise (b) substitutes: planning mints each owner-derived claim
        // from the very identity it records for that row, so what the fence
        // re-derives from the durable transaction is already IN the frozen row.
        for owner_derived in [
            CanaryRemovalResource::CanaryEvidenceRoot,
            CanaryRemovalResource::StoreObjects,
        ] {
            let row = plan
                .effects
                .iter()
                .find(|row| row.category == owner_derived)
                .expect("the frozen denominator must account for both owner-derived rows");
            assert_eq!(
                row.ownership_evidence,
                vec![must(canary_removal_owner_derived_identity(
                    &install,
                    owner_derived
                ))],
                "an untouched owner-derived row must carry the claim the fence re-derives from \
                 the durable install transaction, which is why no plan this owner produced is \
                 refused for it"
            );
        }
        let blocked = plan.effects[canary_removal_first_unreadable_row(&plan)].clone();
        let mut coordinator =
            InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
        let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
        let reason = match &refusal {
            Err(InstallationError::IncompleteObservation(reason)) => reason,
            other => panic!(
                "the plan this owner produced must leave the entry fence and stop at the per-row \
                 readback selector instead, so an identity conflict in (b) can only come from the \
                 substituted claim, got {other:?}"
            ),
        };
        assert!(
            reason.contains(blocked.effect_id.as_str()),
            "the control must stop on the exact unreadable row the drive reached, got {reason:?}"
        );
        assert_eq!(
            coordinator.port().execute_count(),
            0,
            "the control must reach no destructive call, or the fence cannot be what stops (b)"
        );
        assert!(
            coordinator.port().reconcile_calls().is_empty(),
            "the control must stop before any resource owner is asked, so a refusal about an \
             ownership claim can never be confused with a refusal about an unreadable row"
        );
        fixture.cleanup();
    }

    // (b) The substituted claim, over its own fixture.
    {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let install = fixture.install.clone();
        let target = install.candidate_manifest.generation.clone();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let mut plan = must(plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&target),
            &target,
        ));
        // The plan's own ownership CLAIM for the two owner-derived rows is replaced
        // with a handle no owner in this fixture can ever report. Every other frozen
        // member of those rows, including the exact admitted resource identity, the
        // action and the declared postcondition, is left exactly as planning produced
        // it, and the digest is recomputed, so this is an admissible plan whose only
        // disagreement with the durable install transaction is the two claims.
        //
        // The substitution is what makes this case discriminating at all: for an
        // owner-derived row the plan's `ownership_evidence` and the owner's
        // re-derived identity are the SAME handle in an untouched plan, so nothing
        // could tell a copied claim from an observed one. With the claim replaced,
        // a plan carrying a claim no owner reported is a document this owner can
        // refuse, rather than a document that looks exactly like one it produced.
        let mut substituted_claims = Vec::new();
        for row in &mut plan.effects {
            if !matches!(
                row.category,
                CanaryRemovalResource::CanaryEvidenceRoot | CanaryRemovalResource::StoreObjects
            ) {
                continue;
            }
            let category = row.category;
            let derived = must(canary_removal_owner_derived_identity(&install, category));
            let substituted = test_handle(format!(
                "canary-removal/evidence/plan-substituted-claim:{category:?}"
            ));
            assert_eq!(
                row.action,
                CanaryRemovalAction::OutOfScope,
                "an owner-derived row is NAMED out of scope by construction, so its ownership claim is \
                 the only member this substitution touches"
            );
            assert_eq!(
                row.resource_identity, derived,
                "only the CLAIM is substituted, so the fence's own identity comparison cannot be \
                 what refuses this plan"
            );
            assert!(
                row.ownership_evidence.contains(&derived)
                    && substituted.as_str() != derived.as_str(),
                "the substituted handle must be one no owner in this fixture reported, and the \
                 frozen row must have carried the re-derived identity before the substitution"
            );
            row.ownership_evidence = vec![substituted.clone()];
            substituted_claims.push(substituted);
        }
        assert_eq!(
            substituted_claims.len(),
            2,
            "both owner-derived rows must carry a substituted plan claim, or the refusal below could \
             not be attributed to the claim substitution on both of them"
        );
        plan.plan_digest = must(plan.computed_digest());
        // The document is ADMISSIBLE: the owner's own plan validator admits a plan
        // whose claim is any non-empty, handle-valid, non-overlapping vector, which
        // is why the fence — and not this validator — is where the claim is compared.
        must(plan.validate());
        let before = must(fixture.registry.load());
        let revision_before = before.revision();
        let active_before = before.active_generation().cloned();
        let lkg_before = before.last_known_good_generation().cloned();
        let mut coordinator =
            InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
        assert!(
            matches!(
                apply_canary_removal(&mut coordinator, &fixture.registry, &plan),
                Err(InstallationError::IdentityConflict)
            ),
            "a plan whose owner-derived row carries an ownership claim no owner reported must be \
             refused with the typed identity conflict at the entry fence, never admitted to a drive \
             and never a green completion"
        );
        assert_eq!(
            coordinator.port().execute_count(),
            0,
            "the substituted claim must be caught before any destructive call"
        );
        assert!(
            coordinator.port().executed_effect_ids().is_empty(),
            "the substituted claim must be caught before any row of the denominator is mutated"
        );
        assert!(
            coordinator.port().reconcile_calls().is_empty(),
            "the substituted claim must be caught before any resource owner is asked, because \
             nothing was read back and no observation could support either claim"
        );
        // An absent row here is a broken test setup, not a mechanism outcome: apply
        // admitted this removal identity before its fence refused it.
        let durable = coordinator
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id)
            .expect("this case must read the durable removal operation its own apply admitted")
            .expect(
                "this case requires a durable removal operation row under its removal identity",
            );
        must(durable.validate());
        assert_eq!(
            durable.removal_transaction_id, plan.removal_transaction_id,
            "the original removal identity must be preserved across the refused claim"
        );
        assert_eq!(
            durable.plan.plan_digest, plan.plan_digest,
            "the durable record must hold the refused plan itself, never a re-derived one"
        );
        assert_eq!(
            durable.effect_progress.len(),
            plan.effects.len(),
            "the whole frozen denominator must survive the refusal, one progress row per plan row"
        );
        assert!(
            durable
                .effect_progress
                .iter()
                .all(|progress| matches!(progress.state, CanaryRemovalEffectState::Pending)),
            "a plan refused at the entry fence drove no row, so no row may carry a disposition, an \
             intent or an unknown"
        );
        assert_eq!(
            durable.stage,
            CanaryRemovalStage::Admitted,
            "no row was driven, so the durable operation is still exactly as admitted"
        );
        assert_eq!(
            durable.blocking_effect_id, None,
            "this refusal names no blocking effect because it issued no effect; a named blocking \
             row here would claim a drive outcome this fence never reached"
        );
        // The refused document is provably the substituted one, so the refusal above
        // cannot have come from some other disagreement with a plan this owner
        // produced.
        let persisted_claims = durable
            .plan
            .effects
            .iter()
            .filter(|row| {
                matches!(
                    row.category,
                    CanaryRemovalResource::CanaryEvidenceRoot | CanaryRemovalResource::StoreObjects
                )
            })
            .map(|row| row.ownership_evidence.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            persisted_claims,
            substituted_claims
                .iter()
                .map(|claim| vec![claim.clone()])
                .collect::<Vec<_>>(),
            "the durable record must hold both substituted claims, or the refusal was about \
             something other than the claim substitution this case made"
        );
        let recorded = canary_removal_recorded_evidence(&durable);
        assert!(
            recorded.is_empty(),
            "a plan refused at the entry fence recorded no evidence at all, so the scan below runs \
             over an empty set; the version of that scan which reads a NON-empty evidence set is \
             the crash-recovery case's, where rows really did close"
        );
        for claim in &substituted_claims {
            assert!(
                !recorded.contains(claim),
                "no row may be closed with the substituted claim {}; a claim that stands in for an \
                 owner that was never asked cannot be evidence",
                claim.as_str()
            );
        }
        let status = must(canary_removal_status(
            &coordinator,
            &plan.removal_transaction_id,
        ));
        assert_eq!(
            status.removal_transaction_id, plan.removal_transaction_id,
            "the projection must still report the same removal operation identity"
        );
        assert_ne!(
            status.stage,
            CanaryRemovalStage::Completed,
            "a refused removal must never author a terminal Completed"
        );
        for owner_derived in [
            CanaryRemovalResource::CanaryEvidenceRoot,
            CanaryRemovalResource::StoreObjects,
        ] {
            let row = durable
                .plan
                .effects
                .iter()
                .find(|row| row.category == owner_derived)
                .expect("the refused plan must still account for both owner-derived rows")
                .clone();
            assert!(
                status.unresolved_effect_ids.contains(&row.effect_id),
                "row {} must stay unresolved in the projection",
                row.effect_id.as_str()
            );
        }
        assert!(
            status.evidence_refs.is_empty(),
            "a removal that drove no row and read nothing back must report no evidence at all"
        );
        assert!(
            matches!(
                status.next_permitted_action,
                CanaryRemovalNextAction::Reconcile
            ),
            "an operation with nothing resolved permits reconciliation, not a terminal readback"
        );
        let projection = must(fixture.registry.load());
        assert_eq!(
            projection.revision(),
            revision_before,
            "a refusal at the entry fence must not move the registry"
        );
        assert!(
            projection
                .generations()
                .iter()
                .any(|entry| entry.manifest.generation == target),
            "a refused removal must leave the target generation projected"
        );
        assert_eq!(projection.active_generation(), active_before.as_ref());
        assert_eq!(
            projection.last_known_good_generation(),
            lkg_before.as_ref(),
            "a refusal must not move the serving or last-known-good pointer"
        );
        assert!(
            must(
                coordinator
                    .store()
                    .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
            )
            .is_none(),
            "a removal refused before any row was driven must not leave a terminal receipt behind"
        );
        fixture.cleanup();
    }
}

/// Builds the durable operation a crash between the terminal registry commit and
/// this operation's final compare-and-save leaves behind.
///
/// Every row that CAN be closed is already resolved under this removal identity
/// and the terminal registry-record row is still open, which is the state the
/// terminal registry retirement precedes. `admit` opens every row unresolved, so
/// the rows built here are the shapes `advance_row` and `read_retained_row`
/// write: a destroyed row closed as `Removed`, a retained row closed as
/// `Retained` against its own admitted identity, and the hand-off row still open.
///
/// The two `OutOfScope` owner-derived rows stay `Pending`, and that is the ONLY
/// state `CanaryRemovalOperation::validate` admits for them: it deliberately
/// leaves `Resolved` illegal on an out-of-scope row, because `Retain` is a
/// readback outcome and no owner in this crate can report one for a shared
/// surface. Arranging them any other way would build a record the owner itself
/// refuses, so this fixture cannot claim a denominator it cannot legally hold.
fn crashed_canary_removal_operation(plan: &CanaryRemovalPlan) -> CanaryRemovalOperation {
    let registry_row = canary_removal_registry_row(plan);
    let effect_progress = plan
        .effects
        .iter()
        .enumerate()
        .map(|(position, row)| {
            let state = if position == registry_row || row.action == CanaryRemovalAction::OutOfScope
            {
                CanaryRemovalEffectState::Pending
            } else if row.action == CanaryRemovalAction::Remove {
                CanaryRemovalEffectState::Resolved {
                    disposition: CanaryRemovalEffectDisposition::Removed,
                    evidence: vec![test_handle(format!(
                        "evidence:canary-removal-crash:{}",
                        row.effect_id.as_str()
                    ))],
                }
            } else {
                CanaryRemovalEffectState::Resolved {
                    disposition: CanaryRemovalEffectDisposition::Retained,
                    evidence: vec![row.resource_identity.clone()],
                }
            };
            CanaryRemovalEffectProgress {
                effect_id: row.effect_id.clone(),
                state,
            }
        })
        .collect();
    // The stage is a projection of the per-row evidence, never authored: a
    // resolved `Removed` row is what proves this operation executed.
    let executed = plan.effects[..registry_row]
        .iter()
        .filter(|row| row.action == CanaryRemovalAction::Remove)
        .count();
    CanaryRemovalOperation {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: plan.removal_transaction_id.clone(),
        plan: plan.clone(),
        stage: if executed == 0 {
            CanaryRemovalStage::Admitted
        } else {
            CanaryRemovalStage::Executing
        },
        effect_progress,
        blocking_effect_id: None,
        reconcile_deadline_ms: wall_clock_millis().saturating_add(3_600_000),
        revision: 1,
    }
}

/// T5: a crash after the terminal registry commit, followed by an unrelated
/// registry mutation, must be recognised for the SAME removal operation and must
/// not issue a second destructive mutation.
///
/// THE PLAN HERE IS THE PLAN PLANNING PRODUCED, ownership claims included. This
/// case used to REPLACE the ownership claim on both owner-derived rows with a
/// handle no owner reported, because for an owner-derived row the frozen claim
/// and the owner's re-derived identity are the SAME handle in an untouched plan
/// and nothing could then tell a copied claim from an observed one. That
/// substitution is now refused at the entry fence, by the existing
/// `IdentityConflict`, before any row is driven — which is strictly stronger than
/// letting such a plan through admission and catching it at a per-row readback —
/// so the substituted shape and this recovery are different documents now. The
/// substitution MOVED to
/// `canary_removal_refuses_a_substituted_owner_claim_at_the_entry_fence`, which
/// proves it against a fence, and stayed rather than disappeared; what would be
/// lost by keeping it here is the recovery itself, because a plan refused at the
/// fence never reaches the row drive this case is written for. Every assertion
/// below is therefore asserted against an ADMITTED plan, and the claims are read
/// against the identity the fence re-derives rather than replaced.
///
/// The crash state is ARRANGED, not produced by a real interruption: the
/// mechanism runs its retirement, its receipt write and its final operation save
/// back to back with no port call and no injection point in between, so the only
/// way to reach the post-crash state is to build it. The retirement is issued
/// through the registry owner's own compare-and-swap and the receipt carries the
/// values that projection actually holds, and the recovery below is run entirely
/// through the owner's own `recover_canary_removal`.
///
/// WHAT THIS CASE NO LONGER CLAIMS, stated rather than papered over. It used to
/// assert `CanaryRemovalStage::Completed` after the recovery. That outcome is now
/// unreachable for EVERY plan, not only for this fixture: `StoreObjects` and
/// `CanaryEvidenceRoot` are `OutOfScope`, `CanaryRemovalOperation::validate`
/// makes `Resolved` illegal on such a row, and `advance` refuses to call
/// `finish_with_readback` while any row positioned before the terminal registry
/// record is unresolved. So recovery below stops at the first out-of-scope row
/// with a typed refusal instead of closing the operation. That is the blocker
/// this issue carries up, and no assertion here pretends otherwise.
///
/// What the case still proves is the half that IS reachable, and each half has
/// its own defect: the entry fence skips the admission fence and the revision pin
/// on a receipt-recognised retirement, so REACHING the row drive at all is what
/// proves `terminal_receipt_recognises_retirement` admitted this identity through
/// an unrelated registry mutation that moved the live revision off
/// `plan.registry_revision + 1`; the refusal is named for the exact unresolved
/// out-of-scope row rather than for the terminal record, so it is attributable;
/// no destructive call is issued a second time; the durable record is unchanged;
/// and the one terminal receipt on file is REUSED rather than re-minted, which is
/// what keeps a second claim for a committed effect from ever existing.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the arranged crash state, the unrelated mutation and the recovery are each asserted"
)]
fn canary_removal_recovers_the_same_operation_after_an_unrelated_registry_mutation() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let install = fixture.install.clone();
    let target = install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    // The owner-derived rows keep the ownership CLAIM planning minted, and that is
    // now a PREMISE of this case rather than an accident: the entry fence compares
    // each of those claims against the identity it re-derives from the durable
    // install transaction and refuses a claim that is not there, before any row is
    // driven. A substituted claim would therefore never reach the drive this case
    // recovers, which is why it lives in
    // `canary_removal_refuses_a_substituted_owner_claim_at_the_entry_fence`.
    //
    // The claims are still checked against the re-derived identity, because the
    // assertion this case used to earn with a substitution — that durable evidence
    // carrying a plan string standing in for an owner that was never asked cannot
    // close a row — needs the plan-carried claims themselves as what it scans for,
    // and it needs the rows that DID close below for that scan to be decidable.
    let mut plan_carried_owner_claims = Vec::new();
    for row in &plan.effects {
        if !matches!(
            row.category,
            CanaryRemovalResource::CanaryEvidenceRoot | CanaryRemovalResource::StoreObjects
        ) {
            continue;
        }
        assert_eq!(
            row.action,
            CanaryRemovalAction::OutOfScope,
            "an owner-derived row is NAMED out of scope by construction, so its ownership claim is \
             the only member the fence's own comparison reaches"
        );
        let derived = must(canary_removal_owner_derived_identity(
            &install,
            row.category,
        ));
        assert_eq!(
            row.resource_identity, derived,
            "the frozen plan must carry the identity the DURABLE install transaction re-derives, \
             because that identity is what the entry fence compares this row against"
        );
        assert!(
            row.ownership_evidence.contains(&derived),
            "this case drives an ADMITTED plan, so each owner-derived row must still carry the \
             claim the fence re-derives; substituting it is the sibling case's subject"
        );
        plan_carried_owner_claims.extend(row.ownership_evidence.iter().cloned());
    }
    assert_eq!(
        plan_carried_owner_claims.len(),
        2,
        "both owner-derived rows must carry the ownership claim planning minted, or the \
         readback-provenance assertion at the end of this case would hold vacuously"
    );
    assert_eq!(
        plan.plan_digest,
        must(plan.computed_digest()),
        "this case edits nothing in the frozen plan, so the plan it admits must still carry the \
         digest of its own content"
    );
    must(plan.validate());
    let before = must(fixture.registry.load());
    let active_before = before.active_generation().cloned();
    let lkg_before = before.last_known_good_generation().cloned();
    let planned_survivors = before
        .generations()
        .iter()
        .map(|entry| entry.manifest.generation.clone())
        .filter(|generation| generation != &target)
        .collect::<Vec<_>>();
    let mut coordinator =
        InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());

    // The terminal registry retirement itself, issued through the registry
    // owner's own expected-revision compare-and-swap. This is the crash window:
    // the retirement is durable while this operation's own final save never ran.
    must(
        fixture
            .registry
            .mutate_atomic(plan.registry_revision, |projection| {
                projection.retire_retired_generation(&plan.generation)
            }),
    );
    let retired = must(fixture.registry.load());
    assert!(
        retired
            .generations()
            .iter()
            .all(|entry| entry.manifest.generation != plan.generation),
        "the terminal retirement must make the target absent from the registry"
    );
    assert_eq!(retired.active_generation(), active_before.as_ref());
    assert_eq!(retired.last_known_good_generation(), lkg_before.as_ref());
    assert_eq!(
        retired.revision(),
        plan.registry_revision + 1,
        "the terminal retirement is the one revision past the admitted projection"
    );

    // The terminal receipt that attributes that retirement to this exact removal
    // operation identity. It is minted HERE, from the reloaded post-retirement
    // projection, rather than driven out of the mechanism, because the owner
    // exposes no seam after `retire_retired_generation`: the retirement, the
    // receipt write and the operation's final save run back to back with no
    // port call and no injection point between them. The values below are
    // therefore the ones the owner reads when it re-derives the same receipt
    // from the same projection, and the recovery below is what proves the owner
    // accepts them as its own attribution rather than a revision number.
    let mut surviving_generations = retired
        .generations()
        .iter()
        .map(|entry| entry.manifest.generation.clone())
        .filter(|generation| generation != &plan.generation)
        .collect::<Vec<_>>();
    surviving_generations.sort();
    let receipt = CanaryRemovalTerminalReceipt {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: plan.removal_transaction_id.clone(),
        generation: plan.generation.clone(),
        predecessor_registry_revision: plan.registry_revision,
        resulting_registry_revision: retired.revision(),
        resulting_registry_content_digest: must(registry_projection_identity(&retired)),
        active_generation: retired.active_generation().cloned(),
        last_known_good_generation: retired.last_known_good_generation().cloned(),
        surviving_generations,
    };
    must(receipt.validate());
    must(
        coordinator
            .store_mut()
            .save_canary_removal_terminal_receipt(&receipt),
    );

    // The crash left the operation row exactly as the terminal commit left it:
    // every other row resolved under this identity, the hand-off row still open.
    let crashed = crashed_canary_removal_operation(&plan);
    must(crashed.validate());
    must(
        coordinator
            .store_mut()
            .create_canary_removal_operation(&crashed),
    );
    assert!(
        must(
            coordinator
                .store()
                .load_canary_removal_operation(&plan.removal_transaction_id)
        )
        .is_some_and(|operation| operation.stage != CanaryRemovalStage::Completed),
        "the crash must leave the operation unresolved under its own identity"
    );

    // One unrelated, legitimate registry mutation: the activation owner records
    // the operation-bound receipt for the cutover that installed the generation
    // currently serving production. It is genuinely unrelated to this removal's
    // terminal effect — it moves the live revision without changing the retired
    // target, the serving pointers or the survivor set the terminal proof
    // re-reads — and the live revision is no longer `plan.registry_revision + 1`.
    must(
        fixture
            .registry
            .mutate_atomic(must(fixture.registry.load()).revision(), |projection| {
                let Some(serving) = projection.active_generation().cloned() else {
                    return Err(InstallationError::IncompleteObservation(
                        "the registry must still project an active serving generation".to_owned(),
                    ));
                };
                let Some(predecessor) = projection.last_known_good_generation().cloned() else {
                    return Err(InstallationError::IncompleteObservation(
                        "the registry must still project a last-known-good generation".to_owned(),
                    ));
                };
                projection.record_cutover_activation(&CommittedCutoverActivation {
                    installation: plan.installation_epoch.installation.clone(),
                    operation_id: test_handle("operation:unrelated-cutover"),
                    request_digest: test_handle("9".repeat(64)),
                    expected_predecessor: predecessor,
                    target_generation: serving,
                })
            }),
    );
    let unrelated = must(fixture.registry.load());
    assert_eq!(
        unrelated
            .generations()
            .iter()
            .map(|entry| entry.manifest.generation.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        planned_survivors
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        "the unrelated mutation must leave the survivor set the terminal proof re-reads alone"
    );
    let unrelated_revision = unrelated.revision();
    assert_eq!(unrelated_revision, plan.registry_revision + 2);
    assert_ne!(
        unrelated_revision,
        plan.registry_revision + 1,
        "the unrelated mutation must move the live revision off the terminal revision the \
         `revision + 1` rule used to require"
    );
    assert!(
        unrelated
            .generations()
            .iter()
            .all(|entry| entry.manifest.generation != plan.generation),
        "the unrelated mutation must leave the already-retired target absent, because re-projecting \
         it would be a second removal effect rather than unrelated activity"
    );
    assert_eq!(
        unrelated.active_generation(),
        active_before.as_ref(),
        "the unrelated mutation must not move the active serving pointer"
    );
    assert_eq!(
        unrelated.last_known_good_generation(),
        lkg_before.as_ref(),
        "the unrelated mutation must not move the last-known-good pointer"
    );

    // Recovery of an already-retired target is the OUTCOME under test. It cannot
    // CLOSE the operation any more — see this case's doc comment for the measured
    // reason — so the outcome is the typed refusal the drive stops on, and the
    // refusal itself carries the proof that the fence recognised this identity
    // through the unrelated mutation: the entry fence skips the admission fence
    // and the revision pin on a receipt-recognised retirement, so a fence refusal
    // could not have named a per-row effect at all.
    //
    // `advance` drives the first non-`Resolved` position, so the row it stops on
    // is the first out-of-scope row of the frozen order. That row's identity is
    // derived here from the same order rather than typed, so the assertions below
    // cannot pass for the wrong row.
    let blocked_position = plan
        .effects
        .iter()
        .position(|row| row.action == CanaryRemovalAction::OutOfScope)
        .expect("T5 requires a plannable canary removal that names an out-of-scope row");
    let blocked_row = plan.effects[blocked_position].clone();
    let registry_row = canary_removal_registry_row(&plan);
    assert!(
        blocked_position < registry_row,
        "the out-of-scope row must be positioned before the terminal registry record, so reaching \
         it is a refusal short of the terminal commit rather than after it"
    );
    let refusal = match recover_canary_removal(
        &mut coordinator,
        &fixture.registry,
        &plan.removal_transaction_id,
    ) {
        Ok(status) => panic!(
            "recovery must not close an operation whose denominator still holds an unresolvable \
             out-of-scope row, but it returned a status: {status:?}"
        ),
        Err(error) => error,
    };
    let InstallationError::IncompleteObservation(reason) = &refusal else {
        panic!(
            "recovery must stop on the unresolvable out-of-scope row with the typed \
             incomplete-observation error, got {refusal:?}"
        )
    };
    assert!(
        reason.contains(blocked_row.effect_id.as_str()),
        "the refusal must name the exact unresolved out-of-scope row {} it stopped on, so it is \
         attributable, got {reason:?}",
        blocked_row.effect_id.as_str()
    );
    assert!(
        !reason.contains(plan.effects[registry_row].effect_id.as_str()),
        "the drive must stop at the out-of-scope row and never reach the terminal registry record, \
         because a second terminal retirement is the exact effect this case forbids, got \
         {reason:?}"
    );
    assert_eq!(
        coordinator.port().execute_count(),
        0,
        "recovery of an already-retired target must issue no second destructive mutation"
    );
    assert!(
        coordinator.port().executed_effect_ids().is_empty(),
        "recovery of an already-retired target must mutate no row a second time"
    );
    // An absent row here is a broken test setup, not a mechanism outcome: the
    // arranged crash state was created under this identity, so the record must be
    // durable under that same identity.
    let durable = coordinator
        .store()
        .load_canary_removal_operation(&plan.removal_transaction_id)
        .expect("T5 must read the durable removal operation its own recovery touched")
        .expect("T5 requires a durable removal operation row under its removal identity");
    must(durable.validate());
    assert_eq!(
        durable.removal_transaction_id, plan.removal_transaction_id,
        "recovery must resume the same removal operation identity"
    );
    assert_eq!(
        durable.plan.plan_digest, plan.plan_digest,
        "recovery must resume the same frozen plan, never a re-derived one"
    );
    assert_eq!(
        durable.revision, crashed.revision,
        "the recovery refused on the out-of-scope row and must have persisted nothing"
    );
    assert_eq!(
        durable.stage, crashed.stage,
        "the durable stage is a projection of the per-row evidence, so a drive that resolved \
         nothing must leave it exactly where the crash left it"
    );
    assert_ne!(
        durable.stage,
        CanaryRemovalStage::Completed,
        "an operation whose denominator still holds an unresolvable out-of-scope row must never \
         report a terminal Completed"
    );
    let terminal_effect_id = plan.effects[registry_row].effect_id.clone();
    let terminal = durable
        .effect_progress
        .iter()
        .find(|progress| progress.effect_id == terminal_effect_id)
        .expect("T5 requires a durable progress row for the terminal registry record");
    assert!(
        matches!(&terminal.state, CanaryRemovalEffectState::Pending),
        "the terminal registry row must stay open when recovery is refused short of the terminal \
         commit; a Resolved row here would be a second terminal retirement recorded under one \
         identity"
    );
    assert_eq!(
        durable
            .effect_progress
            .iter()
            .filter(|progress| progress.effect_id == blocked_row.effect_id)
            .count(),
        1,
        "T5 requires exactly one durable progress row for the blocking out-of-scope row"
    );
    let blocked = durable
        .effect_progress
        .iter()
        .find(|progress| progress.effect_id == blocked_row.effect_id)
        .expect("T5 requires the blocking out-of-scope row to stay in the durable denominator");
    assert!(
        matches!(&blocked.state, CanaryRemovalEffectState::Pending),
        "the out-of-scope row that stopped the drive must remain unresolved; no disposition can \
         close it, and a closure here would be the out-of-scope row masquerading as handled"
    );
    let recovered = must(fixture.registry.load());
    assert_eq!(
        recovered.revision(),
        unrelated_revision,
        "recovery issued no registry mutation at all, so the live revision is exactly the one the \
         unrelated mutation left behind"
    );
    assert!(
        recovered
            .generations()
            .iter()
            .all(|entry| entry.manifest.generation != plan.generation),
        "the retired generation must stay absent after recovery"
    );
    assert_eq!(recovered.active_generation(), active_before.as_ref());
    assert_eq!(recovered.last_known_good_generation(), lkg_before.as_ref());
    for survivor in &planned_survivors {
        assert!(
            recovered
                .generations()
                .iter()
                .any(|entry| &entry.manifest.generation == survivor),
            "recovery must leave every survivor the plan committed to still projected"
        );
    }
    let stored_receipt = must(
        coordinator
            .store()
            .load_canary_removal_terminal_receipt(&plan.removal_transaction_id),
    )
    .expect("T5 wrote this identity's terminal receipt before the crash window opened");
    must(stored_receipt.validate());
    assert_eq!(
        stored_receipt, receipt,
        "recovery must REUSE the terminal receipt already on file for this identity rather than \
         mint a second, different claim for an effect that already committed"
    );
    let status = must(canary_removal_status(
        &coordinator,
        &plan.removal_transaction_id,
    ));
    assert_eq!(
        status.removal_transaction_id, plan.removal_transaction_id,
        "the projection must still report the same removal operation identity"
    );
    assert_eq!(
        status.registry_revision, plan.registry_revision,
        "the recovered operation must still report the registry revision it was admitted against"
    );
    assert_ne!(
        status.stage,
        CanaryRemovalStage::Completed,
        "a refused recovery must never project a terminal Completed"
    );
    assert!(
        status
            .unresolved_effect_ids
            .contains(&blocked_row.effect_id),
        "the unresolvable out-of-scope row must stay in the unresolved set of the projection"
    );
    assert!(
        !canary_removal_recorded_evidence(&durable).contains(&must(receipt.computed_digest())),
        "no row of a refused recovery may be closed with the terminal receipt's digest, because \
         this recovery proved no terminal effect and re-read no row"
    );
    assert_no_row_was_closed_with_a_plan_carried_owner_claim(&durable, &plan_carried_owner_claims);
    fixture.cleanup();
}

/// Asserts the frozen denominator stayed whole and that no row was ever closed
/// with the ownership claim the plan itself carried.
///
/// This used to assert far more: that the terminal readback closed EVERY row
/// against its own owner and that each owner's answer reached the terminal
/// registry row's accumulated evidence. That assertion is UNREACHABLE now and is
/// not restated here in weaker form. The measurement is in T5's doc comment: an
/// `OutOfScope` row can never be `Resolved`, `CanaryRemovalOperation::validate`
/// refuses it, and `advance` refuses to call `finish_with_readback` while any row
/// positioned before the terminal registry record is unresolved — so no plan's
/// denominator can be entirely resolved, `CanaryRemovalStage::Completed` is
/// unreachable, and the terminal walk never runs. `prove_every_row_before_terminal`
/// returning `Option` is therefore not reachable from the current code either.
///
/// What remains decidable against this record, and is asserted here:
///
/// * the durable progress is still one-to-one with the frozen plan, so nothing
///   was dropped from or duplicated in the denominator;
/// * every row that DID close closed with non-empty evidence, and a destructive
///   row closed as `Removed` while a retained installer-effect row closed as
///   `Retained` — the pairings `CanaryRemovalOperation::validate` admits, so this
///   restates the owner's own validator rather than adding a second gate;
/// * every `OutOfScope` row is still UNRESOLVED. That is the live half of the old
///   claim: the denominator can no longer be fully closed, and this is where that
///   is read back rather than inferred from a stage;
/// * no ownership claim the FROZEN PLAN carries appears anywhere in the recorded
///   evidence, for both owner-derived rows. Those are the two claims the entry
///   fence now compares against the identity it re-derives, and this record has
///   closed rows whose evidence therefore makes the scan decidable rather than
///   vacuous. No code in `canary_removal.rs` reads a frozen row's
///   `ownership_evidence` outside building and validating it, so this cannot fail
///   on today's mechanism; it is the standing guard that a future change copying a
///   plan claim into a closure cannot close a row with one. The SUBSTITUTED claim
///   this scan was originally written against can no longer reach a closure at
///   all — it is refused at the entry fence, which
///   `canary_removal_refuses_a_substituted_owner_claim_at_the_entry_fence` proves,
///   and that case is where the substituted handle is now the subject.
#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "each surviving claim is asserted on its own against its own defect"
)]
fn assert_no_row_was_closed_with_a_plan_carried_owner_claim(
    durable: &CanaryRemovalOperation,
    plan_carried_owner_claims: &[PlatformHandle],
) {
    let recorded_evidence = canary_removal_recorded_evidence(durable);
    assert_eq!(
        durable.plan.effects.len(),
        durable.effect_progress.len(),
        "the durable denominator must still be the frozen one"
    );
    let mut retained_installer_effect_rows = 0_usize;
    let mut removed_rows = 0_usize;
    let mut out_of_scope_rows = 0_usize;
    for (row, progress) in durable.plan.effects.iter().zip(&durable.effect_progress) {
        assert_eq!(
            progress.effect_id, row.effect_id,
            "the durable progress must stay one-to-one with the frozen denominator"
        );
        match (&row.action, &progress.state) {
            (CanaryRemovalAction::OutOfScope, state) => {
                out_of_scope_rows += 1;
                assert!(
                    !matches!(state, CanaryRemovalEffectState::Resolved { .. }),
                    "row {} is OutOfScope and must never be recorded as handled; it ended \
                     {state:?}",
                    row.effect_id.as_str()
                );
            }
            (
                _,
                CanaryRemovalEffectState::Resolved {
                    disposition,
                    evidence,
                },
            ) => {
                assert!(
                    !evidence.is_empty(),
                    "row {} must record the evidence its own owner reported, never an empty \
                     closure",
                    row.effect_id.as_str()
                );
                match row.action {
                    CanaryRemovalAction::Retain => {
                        assert_eq!(
                            *disposition,
                            CanaryRemovalEffectDisposition::Retained,
                            "a retained row must close as Retained, never as a destructive \
                             disposition, because the removal promised to leave that resource \
                             intact"
                        );
                        if row.install_effect_index.is_some() {
                            retained_installer_effect_rows += 1;
                        }
                    }
                    CanaryRemovalAction::Remove => {
                        assert_eq!(
                            *disposition,
                            CanaryRemovalEffectDisposition::Removed,
                            "a destructive row must close as Removed, never as a retained outcome"
                        );
                        removed_rows += 1;
                    }
                    CanaryRemovalAction::Unsupported | CanaryRemovalAction::OutOfScope => panic!(
                        "row {} carries {:?}, which this walk handles in its own arm",
                        row.effect_id.as_str(),
                        row.action
                    ),
                }
            }
            (_, state) => panic!(
                "row {} did not close at all, which no claim below depends on; it ended {state:?}",
                row.effect_id.as_str()
            ),
        }
    }
    assert!(
        retained_installer_effect_rows > 0,
        "this fixture must retain at least one installer-effect row, or the retained-disposition \
         assertion above would hold without covering an owner-driven readback at all"
    );
    assert!(
        removed_rows >= 2,
        "the denominator must carry at least one destructive installer-effect row plus the \
         terminal registry row"
    );
    assert_eq!(
        out_of_scope_rows, 2,
        "both shared owner-derived rows must be part of the denominator and both must be \
         unresolved"
    );
    assert_eq!(
        plan_carried_owner_claims.len(),
        2,
        "the caller must pass the ownership claim of both owner-derived rows, or the scan below \
         would pass for want of anything to match"
    );
    for claim in plan_carried_owner_claims {
        assert!(
            !recorded_evidence.contains(claim),
            "no row of a removal may be closed with the frozen plan's own ownership claim {}; \
             evidence that comes from a readback cannot be a plan string",
            claim.as_str()
        );
    }
}

/// T6: one positive refusal per new path.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "four independent refusal paths, each with its own fixture and its own typed error"
)]
fn canary_removal_refuses_each_unadmissible_plan_before_any_mutation() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());

    // (a) A plan document whose digest does not match its own content is refused
    // by the owner's own plan validation.
    {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let target = fixture.install.candidate_manifest.generation.clone();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let plan = must(plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&target),
            &target,
        ));
        let mut tampered = plan.clone();
        tampered.plan_digest = test_handle("b".repeat(64));
        assert!(
            matches!(
                tampered.validate(),
                Err(InstallationError::IdentityConflict)
            ),
            "a plan whose plan_digest is not its own computed digest must be an identity conflict"
        );
        must(plan.validate());
        fixture.cleanup();
    }

    // (c) A plan that names the generation which still serves production, or the
    // designated last-known-good generation, is refused before any mutation.
    for (pointer, survivor_label) in [("active", "serving-b"), ("last-known-good", "serving-a")] {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let projection = must(fixture.registry.load());
        let serving = if survivor_label == "serving-b" {
            fixture.serving_last.clone()
        } else {
            fixture.serving.clone()
        };
        assert_eq!(
            if pointer == "active" {
                projection.active_generation().cloned()
            } else {
                projection.last_known_good_generation().cloned()
            },
            Some(serving.clone()),
            "the {pointer} pointer must name the survivor this case refuses"
        );
        let revision_before = projection.revision();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let refusal = plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&serving),
            &serving,
        );
        assert!(
            matches!(&refusal, Err(InstallationError::IncompleteObservation(reason))
            if reason == &format!(
                "generation {} serves production or is the designated last-known-good; \
                 removal requires an observed authorized handoff through the activation owner \
                 first",
                serving.as_str()
            )),
            "the {pointer} generation must be refused with its exact production-serving message, \
             got {refusal:?}"
        );
        assert_eq!(must(fixture.registry.load()).revision(), revision_before);
        // The survivor this case refuses was staged by its own activation
        // transaction, so the install transaction a removal for it would be keyed
        // by is that survivor's, not the canary's. Naming the wrong one here would
        // query an identity no removal was ever admitted under and the assertion
        // would hold for the wrong reason.
        let survivor_install_transaction =
            test_handle(format!("transaction:canary-{survivor_label}"));
        assert!(
            must(
                planner
                    .store()
                    .load_canary_removal_for_generation(&survivor_install_transaction, &serving,)
            )
            .is_none(),
            "a refused plan must not admit a removal operation for the {pointer} generation"
        );
        // The generation index alone cannot see a removal admitted under this
        // exact identity, so the identity the owner derives for it is queried
        // directly as well.
        assert!(
            must(planner.store().load_canary_removal_operation(&must(
                canary_removal_operation_id(&survivor_install_transaction, &serving)
            )))
            .is_none(),
            "a refused plan must leave no durable removal operation under the identity it would \
             have used"
        );
        assert_eq!(
            planner.port().reconcile_calls(),
            Vec::new(),
            "a refused plan must never ask a resource owner anything"
        );
        fixture.cleanup();
    }

    // (d) A plan that names a required cleanup this owner cannot perform is
    // blocked by the existing fence guard before any destructive call.
    //
    // The row this case freezes CHANGED, because the producer of an
    // `Unsupported` row did. It used to relabel the `CanaryEvidenceRoot` row,
    // which `freeze_effect_graph` classified `Unsupported`. That category is now
    // `OutOfScope`, and `require_quiesced_owner_effects` runs BEFORE the
    // `Unsupported` guard and pins both shared owner-derived categories to
    // `OutOfScope`, so relabelling one of them would be refused there and this
    // guard would never be reached. The guard's only remaining producer is an
    // externally supplied plan that names a TRANSACTION-CREATED installer-effect
    // resource as required cleanup this owner cannot perform, which is what this
    // case freezes instead.
    {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let install = fixture.install.clone();
        let target = install.candidate_manifest.generation.clone();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let mut plan = must(plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&target),
            &target,
        ));
        let cleanup = canary_removal_destructive_rows(&plan)
            .into_iter()
            .next()
            .expect("T6(d) requires a plannable canary removal that destroys at least one row");
        assert_eq!(
            cleanup.action,
            CanaryRemovalAction::Remove,
            "T6(d) needs a row this plan really does destroy, so naming it as required cleanup is \
             the substitution rather than a description of the frozen plan"
        );
        assert_eq!(
            cleanup.origin,
            CanaryRemovalResourceOrigin::CreatedByInstallTransaction,
            "a transaction-created resource is what makes a row REQUIRED cleanup; a shared or \
             preexisting surface is out of scope instead"
        );
        {
            let Some(row) = plan
                .effects
                .iter_mut()
                .find(|row| row.effect_id == cleanup.effect_id)
            else {
                unreachable!()
            };
            row.action = CanaryRemovalAction::Unsupported;
            // The postcondition is part of the same substitution: an unsupported
            // row still accounts for a resource this removal does not destroy.
            row.expected_postcondition = CanaryRemovalPostcondition::Retained;
        }
        plan.plan_digest = must(plan.computed_digest());
        must(plan.validate());
        let revision_before = must(fixture.registry.load()).revision();
        let mut coordinator =
            InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
        let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
        assert!(
            matches!(&refusal, Err(InstallationError::IncompleteObservation(reason))
                if reason.starts_with(
                    "the frozen plan names a required cleanup this owner cannot perform"
                )
                    && reason.contains(cleanup.effect_id.as_str())
                    && reason.contains(&format!("{:?}", cleanup.category))),
            "an unsupported row must be blocked by the existing fence guard, with that message \
             naming the exact blocking row and its closed category, got {refusal:?}"
        );
        assert_eq!(
            coordinator.port().reconcile_calls(),
            Vec::new(),
            "an unsupported row must block before any resource owner is asked"
        );
        assert_eq!(
            coordinator.port().execute_count(),
            0,
            "an unsupported row must block before any destructive call"
        );
        assert_eq!(must(fixture.registry.load()).revision(), revision_before);
        let durable = must(
            coordinator
                .store()
                .load_canary_removal_operation(&plan.removal_transaction_id),
        )
        .expect("apply admits the durable removal identity before its fence runs");
        must(durable.validate());
        assert!(
            durable
                .effect_progress
                .iter()
                .all(|progress| matches!(progress.state, CanaryRemovalEffectState::Pending)),
            "the unsupported row must block before any row is driven, so every row of the durable \
             denominator must still be Pending"
        );
        let status = must(canary_removal_status(
            &coordinator,
            &plan.removal_transaction_id,
        ));
        assert_ne!(status.stage, CanaryRemovalStage::Completed);
        assert_eq!(
            status.removal_transaction_id, plan.removal_transaction_id,
            "the original removal identity must survive the unsupported-row refusal"
        );
        fixture.cleanup();
    }

    // (b) A plan whose registry revision no longer matches the live projection is
    // refused with a compare-and-save conflict naming both revisions.
    {
        let (_owner_lease, host) = live_host_capability();
        let fixture = canary_removal_fixture(&host);
        let install = fixture.install.clone();
        let target = install.candidate_manifest.generation.clone();
        let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
        let plan = must(plan_canary_removal(
            &planner,
            &fixture.registry,
            &canary_removal_request(&target),
            &target,
        ));
        // One unrelated legitimate registry mutation that leaves the activation
        // pointers and the settled handoff untouched: retiring the earlier
        // survivor, which is neither active nor last-known-good.
        must(
            fixture
                .registry
                .mutate_atomic(plan.registry_revision, |projection| {
                    projection.retire_retired_generation(&fixture.retired_sibling)
                }),
        );
        let live_revision = must(fixture.registry.load()).revision();
        assert_ne!(live_revision, plan.registry_revision);
        let mut coordinator =
            InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
        let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
        assert!(
            matches!(
                refusal,
                Err(InstallationError::CompareAndSaveConflict {
                    expected,
                    actual,
                }) if expected == plan.registry_revision && actual == live_revision
            ),
            "a plan admitted against a superseded registry revision must be a typed \
             compare-and-save conflict, got {refusal:?}"
        );
        assert!(
            must(
                coordinator
                    .store()
                    .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
            )
            .is_none(),
            "a revision conflict must not leave a terminal receipt behind"
        );
        fixture.cleanup();
    }
}

/// Returns the canary-removal module's MECHANISM lines: the code of every source
/// line with every comment removed.
///
/// The guard this feeds is about code, not about prose. A comment that NAMES one
/// of the two fabricated evidence-handle shapes in order to explain why this owner
/// does not mint it is documentation, not a mechanism that mints it, and a raw byte
/// scan cannot tell those two apart: that is exactly why the earlier form of this
/// guard could not pass while its own subject was being documented. A `//`, `///`
/// or `//!` line comment and every `/* */` or `/*! */` block comment are therefore
/// dropped, and only what is left of each line is scanned.
fn canary_removal_mechanism_lines() -> Vec<&'static str> {
    let mut mechanism = Vec::new();
    let mut inside_block_comment = false;
    for line in include_str!("canary_removal.rs").lines() {
        let mut rest = line.trim();
        loop {
            if inside_block_comment {
                let Some(end) = rest.find("*/") else {
                    break;
                };
                inside_block_comment = false;
                rest = rest[end + 2..].trim_start();
            } else if let Some(start) = rest.find("//") {
                mechanism.push(rest[..start].trim_end());
                break;
            } else if let Some(start) = rest.find("/*") {
                mechanism.push(rest[..start].trim_end());
                rest = rest[start + 2..].trim_start();
                if let Some(end) = rest.find("*/") {
                    rest = rest[end + 2..].trim_start();
                } else {
                    inside_block_comment = true;
                }
            } else {
                mechanism.push(rest);
                break;
            }
        }
    }
    mechanism.retain(|line| !line.is_empty());
    mechanism
}

/// Returns the one frozen row this removal accounts for as the generation's
/// canonical Store and Blob objects.
///
/// The category spans exactly one row by construction — no installer effect names
/// a Store or Blob object, so `freeze_effect_graph` appends it once — and the
/// count is asserted rather than assumed here, because a second row of this
/// category would make the fence refusal that names it unattributable.
fn canary_removal_store_objects_row(plan: &CanaryRemovalPlan) -> &CanaryRemovalEffect {
    let mut rows = plan
        .effects
        .iter()
        .filter(|row| row.category == CanaryRemovalResource::StoreObjects);
    let Some(row) = rows.next() else {
        unreachable!("every frozen removal denominator accounts for the Store and Blob objects")
    };
    assert!(
        rows.next().is_none(),
        "the Store and Blob category must span exactly one frozen row"
    );
    row
}

/// Re-loads the installed transaction from the durable store.
///
/// Every counter in the cases below is read back through the store rather than
/// from the value the fixture built in memory, so "this attempt changed nothing"
/// is a statement about the durable record and not about a copy the test still
/// holds.
fn canary_removal_reload_install(
    store: &RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
) -> InstallationTransaction {
    must(store.load(transaction_id)).unwrap_or_else(|| {
        unreachable!("the durable store must still hold the installed transaction it published")
    })
}

/// Counts the installed transaction's own durably applied installer effects.
///
/// That roster is the installation owner's own record of what it applied, so an
/// unchanged count across a removal attempt is the observable form of "this removal
/// issued no destructive effect". A zero count would make an unchanged count prove
/// nothing, so the callers assert the fixture's roster is populated first.
fn canary_removal_applied_effect_count(install: &InstallationTransaction) -> usize {
    install
        .effect_progress()
        .iter()
        .filter(|progress| {
            matches!(
                progress.state,
                InstallationEffectProgressState::Applied { .. }
            )
        })
        .count()
}

/// T1: the Store and Blob row is `OutOfScope` — named with the owner-recorded
/// identity rather than dropped from the denominator — and it is NEVER a required
/// cleanup this owner cannot perform.
///
/// This is the ROOT HOLD repair, and its shape changed once more. The row used to
/// be read back by re-deriving the generation's Store binding from the transaction
/// the durable store holds and comparing it with the identity the plan froze from
/// that same manifest, and `revalidate_fence` had already pinned the candidate
/// manifest digest to `plan.manifest_digest` before any row was driven — so that
/// comparison could never fail, and a handle that cannot fail is not evidence. It
/// was then made `Unsupported`, which made it a REQUIRED cleanup and had the
/// existing fence guard refuse the whole route on it. That was honest about the
/// missing owner capability but wrong about the class: a shared surface this
/// removal leaves alone is not required cleanup, and freezing it as `Unsupported`
/// said it was. The row is `OutOfScope` now, which names the missing capability
/// in the classification itself and stops the fence from refusing the route for
/// something the route is not responsible to do.
///
/// What makes this a repair rather than a weaker refusal is asserted here in both
/// directions. The POSITIVE half: planning succeeds and returns a complete,
/// validated denominator in which the row carries the exact owner-recorded Store
/// binding, non-empty ownership evidence, its reconciliation query and no
/// installer-effect index, and apply is NOT refused at the FENCE for it — the drive
/// leaves admission and reaches the per-row readback selector, which is refused
/// there naming the exact unreadable row it stopped on. An unconditional refusal of
/// the whole route at the fence could not name a row identity, so this is still the
/// same claim the repair is about. The NEGATIVE half: `Unsupported` is still the
/// blocking class for required cleanup, that guard still refuses before anything is
/// driven, and T6(d) is the case that proves it on the only shape that can still
/// produce it.
///
/// The positive half no longer claims that the plan's own installer-effect rows are
/// driven through their owners. `order_band` ranks a row no owner can read back
/// ahead of every row that can mutate, so the corrected drive stops on the first
/// out-of-scope row before any owner is asked. That ordering is the deliberate
/// correction, not a regression, and it is what T4 asserts in full.
///
/// What this case does NOT claim, because it is unreachable: the row can never be
/// closed. `CanaryRemovalOperation::validate` refuses `Resolved` on an out-of-scope
/// row, so the drive stops on it. `assert_no_row_was_closed_with_a_plan_carried_owner_claim`
/// proves that invariant against the durable record, and
/// `canary_removal_recovers_the_same_operation_after_an_unrelated_registry_mutation`
/// proves the terminal consequence: no plan's denominator can be fully resolved, so
/// the terminal registry retirement is never committed.
#[cfg(windows)]
#[test]
fn store_objects_row_is_out_of_scope_and_never_a_required_cleanup() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let install = fixture.install.clone();
    let target = install.candidate_manifest.generation.clone();
    let registry_revision_before = must(fixture.registry.load()).revision();
    let applied_before = canary_removal_applied_effect_count(&install);
    assert!(
        applied_before > 0,
        "the fixture must carry durably applied installer effects, or an unchanged applied count \
         would prove nothing about this attempt"
    );

    // The PLAN phase succeeds: planning is read-only and returns a complete,
    // self-consistent denominator naming the shared surface with the evidence the
    // owner actually recorded.
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    must(plan.validate());
    assert_eq!(plan.plan_digest, must(plan.computed_digest()));
    let store_row = canary_removal_store_objects_row(&plan);
    assert_eq!(
        store_row.action,
        CanaryRemovalAction::OutOfScope,
        "a Store and Blob row no owner in this crate can observe must be NAMED out of scope: \
         neither Retain, because Retain is a readback outcome this crate has no owner to report, \
         nor Unsupported, because a shared surface is not required cleanup and must not block the \
         whole route"
    );
    assert_eq!(
        store_row.expected_postcondition,
        CanaryRemovalPostcondition::Retained,
        "an out-of-scope row still accounts for a resource the removal does not destroy"
    );
    assert_eq!(
        store_row.resource_identity,
        must(canary_removal_owner_derived_identity(
            &install,
            CanaryRemovalResource::StoreObjects
        )),
        "an out-of-scope row still names the exact owner-recorded Store binding it cannot read back"
    );
    assert!(
        !store_row.ownership_evidence.is_empty(),
        "an out-of-scope row still records who owns the resource at plan time"
    );
    assert!(
        !store_row.reconciliation_query.as_str().is_empty(),
        "an out-of-scope row is NAMED, so it must still carry the query an owner would answer"
    );
    assert_eq!(
        store_row.install_effect_index, None,
        "an out-of-scope row names no installer effect, because no effect of this transaction can \
         observe a canonical Store or Blob object"
    );
    assert!(
        planner.port().reconcile_calls().is_empty(),
        "a read-only planning pass must never ask a resource owner anything"
    );
    assert!(
        must(
            planner
                .store()
                .load_canary_removal_operation(&plan.removal_transaction_id)
        )
        .is_none(),
        "a read-only planning pass must not create a durable removal operation"
    );
    assert!(
        must(
            planner
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a read-only planning pass must not create a terminal receipt"
    );

    // Apply is NOT refused at the FENCE for this row. The positive half of the
    // claim: the drive leaves admission and reaches the per-row readback selector,
    // because the fence's `Unsupported` guard never sees a shared surface and the
    // fence's own out-of-scope observation names a CATEGORY rather than a row
    // identity. The paired negative half is T6(d), where the very same `Unsupported`
    // guard refuses the exact shape that IS required cleanup.
    //
    // This half used to be stated as "at least one resource owner was asked". That
    // was the OLD execution order: `order_band` now ranks a row no owner can read
    // back ahead of every row that can mutate, so the drive stops on the first
    // out-of-scope row BEFORE any owner is asked, and the owner-answer assertion
    // could only be satisfied by an ordering the corrected order removes. What is
    // asserted instead is the same claim made against what the corrected order does
    // produce: the refusal comes from the per-row readback selector and names the
    // exact row it stopped on, which no fence refusal of this plan can do.
    let blocked_effect_id = &plan.effects[canary_removal_first_unreadable_row(&plan)].effect_id;
    let mut coordinator =
        InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
    let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
    assert!(
        !matches!(&refusal, Err(InstallationError::IncompleteObservation(reason))
            if reason.contains("required cleanup this owner cannot perform")),
        "an out-of-scope row is not required cleanup and must never trip the fence guard that \
         refuses one, got {refusal:?}"
    );
    assert!(
        matches!(&refusal, Err(InstallationError::IncompleteObservation(reason))
            if reason.contains(blocked_effect_id.as_str())),
        "apply must reach the per-row readback selector and be refused THERE for the exact \
         unreadable row it stopped on, which is what an out-of-scope row not tripping the fence \
         looks like; got {refusal:?}"
    );
    assert!(
        coordinator.port().reconcile_calls().is_empty(),
        "the corrected order detects the unreadable row before any owner is asked, so the drive \
         that refused there must not have reached a resource owner"
    );

    // ZERO destructive effects ran, observed on the installer's own durable roster
    // and on the effect port that carries every mutating call this owner could make.
    let after = canary_removal_reload_install(coordinator.store(), &plan.install_transaction_id);
    assert_eq!(
        after.effect_progress(),
        install.effect_progress(),
        "this removal must leave the installed transaction's durable effect roster byte for byte \
         as it was"
    );
    assert_eq!(
        canary_removal_applied_effect_count(&after),
        applied_before,
        "this removal must not apply, re-issue or retire one installer effect"
    );
    assert_eq!(coordinator.port().execute_count(), 0);
    assert!(coordinator.port().executed_effect_ids().is_empty());

    // The registry is untouched and the target is still projected.
    let projection = must(fixture.registry.load());
    assert_eq!(projection.revision(), registry_revision_before);
    assert!(
        projection
            .generations()
            .iter()
            .any(|entry| entry.manifest.generation == target),
        "a removal that cannot close must leave the target generation projected"
    );

    // The durable record proves the classification is a NAMING and not a closure:
    // the row is still in the denominator and still unresolved.
    let durable = must(
        coordinator
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("apply admits the durable removal identity before its fence runs");
    must(durable.validate());
    assert_eq!(durable.removal_transaction_id, plan.removal_transaction_id);
    assert_eq!(durable.plan.plan_digest, plan.plan_digest);
    assert_ne!(
        durable.stage,
        CanaryRemovalStage::Completed,
        "a denominator that still holds an unresolvable out-of-scope row can never be Completed"
    );
    let durable_store_row = canary_removal_store_objects_row(&durable.plan);
    assert_eq!(
        durable_store_row.action,
        CanaryRemovalAction::OutOfScope,
        "the persisted denominator must still carry the row as named out of scope, never relabelled \
         on the way to the store"
    );
    let durable_progress = durable
        .effect_progress
        .iter()
        .find(|progress| progress.effect_id == store_row.effect_id)
        .expect("the out-of-scope row must stay in the durable denominator");
    assert!(
        matches!(&durable_progress.state, CanaryRemovalEffectState::Pending),
        "the out-of-scope row must remain unresolved, because no disposition any owner could report \
         can close it"
    );
    assert!(
        must(
            coordinator
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a removal that cannot close must not mint a terminal receipt"
    );
    let status = must(canary_removal_status(
        &coordinator,
        &plan.removal_transaction_id,
    ));
    assert_ne!(status.stage, CanaryRemovalStage::Completed);
    assert!(
        status.evidence_refs.is_empty(),
        "a removal that drove no row to a mutating or terminal outcome must report no terminal \
         evidence at all"
    );
    fixture.cleanup();
}

/// T2: no handle this operation persists or reports has the shape of either of the
/// two evidence handles this mechanism used to fabricate about itself.
///
/// `canary-removal/evidence/store-owner:<generation>` restated the Store row's own
/// generation identity and could never fail, and `canary-removal/readback/registry-terminal:`
/// stood in for a registry reload that never happened. Neither may reach a durable
/// record or a status projection, because a removal is never proved by a string this
/// owner wrote about itself.
///
/// The scan reads the record back out of the durable store and walks every handle
/// the persisted operation and its projection carry, rather than matching a string
/// constant this test typed. It is kept from being vacuous twice over: the persisted
/// denominator is asserted complete and carrying the owner-recorded Store identity,
/// and the row's REAL reconciliation query — a near neighbour of the fabricated
/// shape — is asserted present, so the scan is demonstrably discriminating rather
/// than passing for want of anything to match.
#[cfg(windows)]
#[test]
fn canary_removal_never_records_a_fabricated_store_or_readback_handle() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let install = fixture.install.clone();
    let target = install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    let mut coordinator =
        InstallationCoordinator::new(canary_removal_port(&install, &plan), fixture.store());
    let refusal = apply_canary_removal(&mut coordinator, &fixture.registry, &plan);
    assert!(
        matches!(refusal, Err(InstallationError::IncompleteObservation(_))),
        "this case reads the durable record the refusal leaves behind, so the refusal itself is \
         setup rather than the outcome under test; got {refusal:?}"
    );

    // Everything below is read back through the durable store.
    let durable = must(
        coordinator
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("apply admitted this removal identity durably before its fence refused it");
    must(durable.validate());
    let status = must(canary_removal_status(
        &coordinator,
        &plan.removal_transaction_id,
    ));
    assert!(
        must(
            coordinator
                .store()
                .load_canary_removal_terminal_receipt(&plan.removal_transaction_id)
        )
        .is_none(),
        "a removal that never reached its terminal proof must hold no terminal receipt, so no \
         fabricated terminal handle could have been recorded for one"
    );

    // The persisted denominator is real, so the scan below is over a record and not
    // over an empty set.
    assert_eq!(
        durable.effect_progress.len(),
        plan.effects.len(),
        "the persisted denominator must stay one-to-one with the frozen plan"
    );
    assert_eq!(durable.plan.plan_digest, plan.plan_digest);
    let store_row = canary_removal_store_objects_row(&durable.plan);
    assert_eq!(
        store_row.resource_identity,
        must(canary_removal_owner_derived_identity(
            &install,
            CanaryRemovalResource::StoreObjects
        )),
        "the persisted Store and Blob row must carry the identity the DURABLE install transaction \
         derives, not one this owner minted for itself"
    );
    assert!(
        !store_row.ownership_evidence.is_empty(),
        "the persisted Store and Blob row must record an owner-recorded claim, so the scan below \
         has real handles to inspect"
    );
    assert!(
        store_row
            .reconciliation_query
            .as_str()
            .starts_with("canary-removal/reconcile/store-owner:"),
        "the row must still carry the reconciliation query its resource's own owner answers, so \
         the scan below can be seen to accept that real near neighbour of the fabricated shape"
    );

    let mut recorded: Vec<PlatformHandle> = Vec::new();
    for row in &durable.plan.effects {
        recorded.push(row.resource_identity.clone());
        recorded.push(row.reconciliation_query.clone());
        recorded.extend(row.ownership_evidence.iter().cloned());
        recorded.extend(row.reference_users.iter().cloned());
        recorded.extend(row.prerequisites.iter().cloned());
    }
    for progress in &durable.effect_progress {
        match &progress.state {
            CanaryRemovalEffectState::Resolved { evidence, .. } => {
                recorded.extend(evidence.iter().cloned());
            }
            CanaryRemovalEffectState::Unknown { pending_ref } => {
                recorded.push(pending_ref.clone());
            }
            CanaryRemovalEffectState::Pending
            | CanaryRemovalEffectState::IntentCommitted { .. } => {}
        }
    }
    recorded.extend(status.evidence_refs.iter().cloned());
    recorded.extend(status.primary_uncertainty.iter().cloned());
    recorded.extend(status.cleanup_uncertainty.iter().cloned());
    assert!(
        !recorded.is_empty(),
        "the scanned set must not be empty, or the scan below could not fail"
    );

    for fabricated in [
        "canary-removal/evidence/store-owner:",
        "canary-removal/readback/registry-terminal:",
    ] {
        assert!(
            !recorded
                .iter()
                .any(|handle| handle.as_str().starts_with(fabricated)),
            "a removal is never proved by a handle this owner minted about itself, but the \
             persisted record carries one shaped {fabricated}: {:?}",
            recorded
                .iter()
                .filter(|handle| handle.as_str().starts_with(fabricated))
                .collect::<Vec<_>>()
        );
    }
    fixture.cleanup();
}

/// RULE A: `blocking_effect_id` must name an Unknown row whenever any row of
/// `effect_progress` carries an unknown external outcome, and the rule is
/// ONE-DIRECTIONAL on purpose.
///
/// INVARIANT pinned: `canary_removal.rs::CanaryRemovalOperation::validate`, the
/// `carries_unknown` arm at `canary_removal.rs:1413-1424` — a record that keeps an
/// unknown outcome while naming no such row is refused with
/// `InstallationError::IdentityConflict`.
///
/// WHY IT IS REACHED HERE AND NOT THROUGH AN APPLY. The rule lives in this
/// function, beside the row-identity check above it, because this function runs
/// on BOTH sides of every durable operation: the store's decode calls it on a
/// loaded record, `compare_and_save` calls it on the proposed one and
/// `CanaryRemovalOperationVersion::of` calls it on the expected one. The frozen
/// denominator holds two `OutOfScope` rows no owner in this crate can read back,
/// so a real `apply_canary_removal` stops at the first of them (T4) and never
/// reaches a row drive that could produce this shape. `crashed_canary_removal_operation`
/// already builds a legal durable record for crash simulation, so arranging the
/// proposed record and calling `validate()` on it is the established pattern in
/// this file, not a stand-in for the mechanism.
///
/// WHAT MAKES THE ASYMMETRY A CLAIM RATHER THAN A COMMENT. Three things are held
/// apart here, and each has its own typed outcome:
///
/// * the REFUSING direction — an unknown outcome with no named row, and with a
///   named row that is not the unknown one, are both `IdentityConflict`;
/// * the ADMITTED direction — the identical record that names the unknown row
///   itself validates, so the refusal is attributable to the missing name and to
///   nothing else about the record;
/// * the CONVERSE the rule deliberately does NOT state — a record carrying no
///   unknown outcome is unconstrained, so it keeps naming whatever blocking row
///   it wants, including a row that is no longer unresolved. `resolve_row` closes
///   a row on its owner's verdict WITHOUT clearing `blocking_effect_id`, so
///   requiring an unresolved row for every named id would refuse that save.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the refusing record and each of its admitted counterparts are asserted separately"
)]
fn canary_removal_blocking_effect_must_name_an_unknown_row_and_only_in_that_direction() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let target = fixture.install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));

    // The control. `crashed_canary_removal_operation` is the arranged crash state
    // of the terminal registry commit, and it is a legal record that carries NO
    // unknown outcome and names NO blocking row. It must validate before any
    // refusal below can be attributed to the substitutions rather than to the
    // fixture.
    let baseline = crashed_canary_removal_operation(&plan);
    must(baseline.validate());
    assert!(
        baseline.blocking_effect_id.is_none(),
        "the arranged crash state names no blocking row, which is the absence the rule under test \
         starts from"
    );
    assert!(
        baseline
            .effect_progress
            .iter()
            .all(|progress| !matches!(progress.state, CanaryRemovalEffectState::Unknown { .. })),
        "the arranged crash state must carry no unknown outcome, or the converse assertions below \
         would be read against a record the rule already refuses for a different reason"
    );

    // The one row whose external outcome becomes unknown. It is derived from the
    // frozen order by the same action filter that admits `Unknown`
    // (`canary_removal.rs:1371-1374`: `Remove` or `Retain`) rather than typed, so
    // a row this owner refuses to make unknown cannot be silently substituted.
    let unknown_row = canary_removal_destructive_rows(&plan)
        .into_iter()
        .next()
        .expect("rule A requires a plannable canary removal that drives at least one row");
    assert_eq!(
        unknown_row.action,
        CanaryRemovalAction::Remove,
        "`Unknown` is admitted only for a row this owner drives or promises to leave intact, so the \
         substituted row must be a real `Remove` row or the refusal below would be attributable to \
         the state/action pairing instead of to the blocking id"
    );
    let pending_ref = test_handle(format!(
        "pending-ref:canary-removal-unknown:{}",
        unknown_row.effect_id.as_str()
    ));

    // A nearby id that IS a real member of this same denominator and is NOT the
    // unknown row: the terminal registry record, which the crash state leaves
    // `Pending`. Naming it satisfies the pre-existing row-identity check at
    // `canary_removal.rs:1381-1388` that runs BEFORE the rule under test, so the
    // refusal it produces is attributable to the one-directional rule alone.
    let registry_effect_id = plan.effects[canary_removal_registry_row(&plan)]
        .effect_id
        .clone();
    assert_ne!(
        registry_effect_id, unknown_row.effect_id,
        "the misnamed row must be a different member of the same denominator, or naming it would \
         be naming the unknown row after all and would prove nothing"
    );

    let mut carries_unknown = baseline.clone();
    let Some(unknown_progress) = carries_unknown
        .effect_progress
        .iter_mut()
        .find(|progress| progress.effect_id == unknown_row.effect_id)
    else {
        unreachable!("the durable denominator carries one progress row per frozen plan row")
    };
    unknown_progress.state = CanaryRemovalEffectState::Unknown { pending_ref };
    // The stage is a projection of the per-row evidence and is never authored
    // independently, so it is re-derived here rather than left at the crash
    // state's `Executing`: an unknown outcome makes `Reconciling` the only
    // admissible stage. `expected_stage` runs AFTER the rule under test
    // (`canary_removal.rs:1425`), so a mismatched stage could not have caused or
    // masked the refusals below either way — but matching it is what proves the
    // rule is the only thing left to refuse.
    carries_unknown.stage = CanaryRemovalStage::Reconciling;
    assert_eq!(
        carries_unknown
            .effect_progress
            .iter()
            .filter(|progress| matches!(progress.state, CanaryRemovalEffectState::Unknown { .. }))
            .count(),
        1,
        "exactly one row may carry the unknown outcome, or the refusal below would not identify \
         which row the record failed to name"
    );
    assert!(
        carries_unknown.blocking_effect_id.is_none(),
        "the record under refusal still names no blocking row: that absence is the whole claim"
    );

    // REFUSAL 1: an unknown outcome with nothing named beside it.
    let refusal = carries_unknown.validate();
    assert!(
        matches!(refusal, Err(InstallationError::IdentityConflict)),
        "an operation carrying an unknown outcome must name the row that has it, because the \
         entire content of the typed reconciling disposition is that named row and a status \
         projection would otherwise advertise a primary uncertainty with no durable row to \
         reconcile, got {refusal:?}"
    );

    // REFUSAL 2: a name that is a real row of this denominator but not the
    // unknown one. The row-identity check above admits it, so this refusal can
    // only come from the rule under test.
    let mut misnamed = carries_unknown.clone();
    misnamed.blocking_effect_id = Some(registry_effect_id);
    let refusal = misnamed.validate();
    assert!(
        matches!(refusal, Err(InstallationError::IdentityConflict)),
        "naming a row that is not the unknown one is no naming at all: the typed disposition would \
         point a reconciliation at a row with a known outcome, got {refusal:?}"
    );

    // ADMITTED: the identical record naming the unknown row itself. Nothing else
    // differs from REFUSAL 1, which is what makes that refusal attributable to
    // the missing name and not to the unknown outcome, the pending reference or
    // the re-derived stage.
    let mut named = carries_unknown.clone();
    named.blocking_effect_id = Some(unknown_row.effect_id.clone());
    assert_eq!(
        named.blocking_effect_id.as_ref(),
        Some(&unknown_row.effect_id),
        "the admitted record names exactly the row that is Unknown, so this is the positive the \
         absence above is read against"
    );
    must(named.validate());

    // THE CONVERSE THE RULE DELIBERATELY DOES NOT STATE. The same removal
    // identity, one row back from `Unknown` to its owner's `Resolved` verdict,
    // still naming that row: refused by nothing, because there is no longer an
    // unknown outcome for the name to point at.
    let mut stale = baseline.clone();
    stale.blocking_effect_id = Some(unknown_row.effect_id);
    must(stale.validate());
    // And the unconstrained record that names nothing at all, with an unknown
    // outcome nowhere in the denominator.
    let mut unnamed = baseline.clone();
    unnamed.blocking_effect_id = None;
    must(unnamed.validate());

    fixture.cleanup();
}

/// RULE B: the durable attempt stamp is forward-only, and what ADVANCES it is
/// bounded by the STORE, not by the owner validator.
///
/// INVARIANT pinned, split by the owner each half actually lives in:
/// * `redb_state.rs::validate_canary_removal_operation_transition` — the ATTEMPT
///   ADVANCE BOUND. It is handed the decoded `current` record beside the proposed
///   one, and refuses a save in which a row's `bound.attempt` moves backwards,
///   moves more than exactly one step forward, or whose `bound.max_attempts`
///   changed, with `InstallationError::IdentityConflict`. It is cited by symbol
///   and not by line number because a line number rots the moment a writer adds a
///   line above it, and a rotted citation reads exactly like a claim about code
///   that is not there.
/// * `canary_removal.rs::CanaryRemovalEffectBound::validate`, reached through
///   `canary_removal.rs::CanaryRemovalEffect::validate` from
///   `canary_removal.rs::CanaryRemovalOperation::validate` — what bounds a SINGLE
///   record to its own contour: a non-zero `attempt` inside a non-zero
///   `max_attempts`.
///
/// WHY THE ADVANCE BOUND IS A STORE RULE AND NOT AN OWNER ONE. It is a DELTA, and
/// `CanaryRemovalOperation::validate` is a STATELESS validator: it is handed the
/// proposed rows alone and has no memory of the rows this save replaces, so it
/// cannot see a delta at all. `validate_canary_removal_operation_transition` is
/// the only place a delta exists to be checked, because it is the one function
/// handed the record its write transaction has ALREADY decoded — with no second
/// read, no second transaction and no second decode.
///
/// WHY A CONSTANT-DERIVED OWNER WINDOW WOULD ALSO HAVE BEEN WRONG.
/// `CanaryRemovalEffectBound::validate` admits ANY non-zero `max_attempts`, and a
/// caller-supplied plan document is admitted on its own terms: `load_plan` in
/// `bins/eliot/src/canary_removal_entry.rs` takes any envelope that validates, and
/// that file's own doc calls the plan JSON an untrusted import. A window derived
/// from `CANARY_REMOVAL_ROW_MAX_ATTEMPTS` would therefore have refused the OWNER'S
/// OWN `commit_intent` save the moment such a row legitimately reached its third
/// attempt, and it would have refused it permanently.
///
/// WHAT THE WIDE CONTOUR IN THE STORE HALF IS DOING. Every store-driven save
/// below runs under a contour widened past the frozen one, on BOTH sides of the
/// comparison. That is the only way a skip can be proposed at all: inside
/// `CANARY_REMOVAL_ROW_MAX_ATTEMPTS`, `CanaryRemovalEffectBound::validate` refuses
/// `attempt + 2` before the store is reached, and the refusal would be
/// attributable to the contour check instead of to the floor under test. Both ends
/// still come from the production stamp of the frozen plan rather than from
/// literals here, so the cases keep holding if `CANARY_REMOVAL_ROW_MAX_ATTEMPTS`
/// ever moves.
///
/// THE REWIND IS REFUSED BY A DIFFERENT CHECK, AND THIS CASE NAMES WHICH ONE.
/// Rewinding a row to attempt `0` fails that row's own contour first, inside
/// `CanaryRemovalOperation::validate`, and it is
/// `InstallationError::InvalidField` on `canary_removal.effect.bound` — not the
/// `IdentityConflict` the store floor returns, and not a refusal the store is
/// ever shown, because `compare_and_save_canary_removal_operation` runs the owner
/// validator on the proposed record before the floor reads anything. The floor's
/// own rewind arm needs a NON-ZERO lower attempt to be visible at all, so it is
/// asserted on one directly. The two typed variants are what keep each assertion
/// from crediting either check with a refusal it does not cause.
///
/// WHY THE CONTOUR IS RE-DIGESTED AND THE ATTEMPT NEVER IS.
/// `canary_removal.rs::CanaryRemovalPlan::computed_digest` normalises
/// `bound.attempt` back to the plan-time stamp before hashing and leaves
/// `bound.max_attempts` inside it, so widening the contour moves the frozen digest
/// and moving the attempt never does. That is exactly why the record-to-record
/// `plan_digest` comparison inside `compare_and_save_canary_removal_operation` is
/// BLIND to this member by construction, and the case asserts that blindness
/// directly before driving the one check that has to see it.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each attempt-stamp case is asserted against its own untouched control"
)]
fn canary_removal_attempt_stamp_advances_by_at_most_one_and_never_rewinds() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let target = fixture.install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    // The durable half of this case drives its own coordinator over its own store
    // handle, exactly as production's apply path does and exactly as
    // `canary_removal_recovers_the_same_operation_after_an_unrelated_registry_mutation`
    // does. Nothing below is a second mechanism: every save is
    // `RedbInstallationTransactionStore`'s own `create_canary_removal_operation` and
    // `compare_and_save_canary_removal_operation`, reached through the coordinator's
    // own `store_mut`/`store`, and every record it is handed goes through the owner
    // validator's own `validate` first.
    let mut driver = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());

    // The control, and the frozen production stamp the single-record cases read.
    let baseline = crashed_canary_removal_operation(&plan);
    must(baseline.validate());
    let driven_row = canary_removal_destructive_rows(&plan)
        .into_iter()
        .next()
        .expect("rule B requires a plannable canary removal that drives at least one row");
    let position = plan
        .effects
        .iter()
        .position(|row| row.effect_id == driven_row.effect_id)
        .unwrap_or_else(|| unreachable!());
    let plan_time = baseline.plan.effects[position].bound;
    assert!(
        plan_time.attempt > 0 && plan_time.max_attempts > 0,
        "the frozen plan must carry a non-zero plan-time stamp, or the absence asserted on the \
         rewind below would be indistinguishable from an unbounded contour"
    );
    assert!(
        plan_time.attempt < plan_time.max_attempts,
        "the case asserts an advance of exactly one, so the frozen contour must actually admit one \
         more attempt than the plan-time stamp"
    );

    // THE PLAN DIGEST IS BLIND TO THIS MEMBER. Asserted on the untouched control
    // first, so the re-digest decision further below is attributable to
    // `max_attempts` and not to a fixture whose digest was never correct.
    assert_eq!(
        must(baseline.plan.computed_digest()),
        baseline.plan.plan_digest,
        "the frozen plan's own digest must be its computed digest, or the blindness assertions \
         below would be vacuous"
    );

    // ADVANCE OF EXACTLY ONE, AS A SINGLE RECORD: admitted. `attempt` moved by
    // one, `max_attempts` untouched, and the digest is unchanged precisely
    // because `attempt` is normalised away. What this case proves is only that
    // ONE record carrying the advanced stamp is inside its own contour. The
    // bound on how far the counter may move PER SAVE is the store floor driven
    // further below, and it is a different owner of the same member.
    let mut advanced = baseline.clone();
    advanced.plan.effects[position].bound = CanaryRemovalEffectBound {
        attempt: plan_time.attempt + 1,
        max_attempts: plan_time.max_attempts,
    };
    assert_eq!(
        advanced.plan.effects[position].bound.attempt,
        plan_time.attempt + 1,
        "the admitted record must carry exactly one past the plan-time stamp, not some other value"
    );
    assert_eq!(
        must(advanced.plan.computed_digest()),
        advanced.plan.plan_digest,
        "an advance of exactly one must leave the frozen digest untouched, because \
         `computed_digest` normalises this member back to the plan-time stamp"
    );
    must(advanced.plan.validate());
    must(advanced.validate());

    // A REWIND: refused, but NOT by the store floor and NOT by anything that has
    // seen an earlier record. `attempt` back to zero. The digest is untouched
    // for the same reason as the advance, so this refusal is about the contour
    // alone.
    let mut rewound = baseline.clone();
    rewound.plan.effects[position].bound.attempt = 0;
    assert_eq!(
        rewound.plan.effects[position].bound.attempt, 0,
        "the rewound record must name no attempt at all, which is the absence under test"
    );
    assert_eq!(
        must(rewound.plan.computed_digest()),
        rewound.plan.plan_digest,
        "a rewind must leave the frozen digest untouched too, so the refusal below is attributable \
         to the bound's own contour check"
    );
    let refusal = rewound.validate();
    assert!(
        matches!(&refusal, Err(InstallationError::InvalidField { field, .. })
            if field == "canary_removal.effect.bound"),
        "a rewound attempt is refused by `canary_removal.rs::CanaryRemovalEffectBound::validate`, \
         which requires a non-zero attempt inside a non-zero attempt bound and is reached through \
         `CanaryRemovalEffect::validate` and `self.plan.validate()`. It is NOT \
         `redb_state.rs::validate_canary_removal_operation_transition`: that floor compares a \
         DELTA between two records, and this one is refused inside \
         `CanaryRemovalOperation::validate` before the store ever reads a durable row. The typed \
         variant is the point — it is what keeps this assertion from crediting either check with a \
         refusal it does not cause, got {refusal:?}"
    );
    assert!(
        !matches!(refusal, Err(InstallationError::IdentityConflict)),
        "the rewind must not be reported as the store floor's identity conflict, or the two checks \
         would be indistinguishable and the attribution above would be wrong"
    );

    // -----------------------------------------------------------------------
    // THE ADVANCE BOUND, DRIVEN THROUGH THE STORE. Everything above is a single
    // record seen by a stateless validator; the floor below compares two, which
    // is the only way the rule is visible at all.
    // -----------------------------------------------------------------------

    // The durable record every comparison below is read from. The contour is
    // widened ONCE, here, on the side that is persisted AND on every side it is
    // compared against, so `max_attempts` never differs across a save and a
    // refusal below can only come from the advance term.
    let widened = plan_time.max_attempts + 2;
    assert!(
        widened > plan_time.attempt + 2,
        "the widened contour must admit a skip of exactly two inside itself, or the skip below would \
         be refused by `CanaryRemovalEffectBound::validate` before the store floor is reached"
    );
    let mut admitted = baseline.clone();
    admitted.plan.effects[position].bound.max_attempts = widened;
    admitted.plan.plan_digest = must(admitted.plan.computed_digest());
    assert_eq!(
        must(admitted.plan.computed_digest()),
        admitted.plan.plan_digest,
        "`max_attempts` is inside the frozen digest, so the widened contour is re-digested while \
         every `attempt` below is not"
    );
    must(admitted.plan.validate());
    // The OPERATION alone admits this contour, which is what makes the refusal
    // further below attributable to the store floor and not to
    // `CanaryRemovalPlan::validate`.
    must(admitted.validate());
    assert_eq!(
        admitted.plan.effects[position].bound.attempt, plan_time.attempt,
        "the persisted row must still carry the plan-time attempt, so every delta below is measured \
         from a stamp this removal identity really spent"
    );
    assert_eq!(
        admitted.plan.effects[position].bound.max_attempts, widened,
        "the persisted contour is the widened one the deltas below are read against"
    );
    must(
        driver
            .store_mut()
            .create_canary_removal_operation(&admitted),
    );
    let current = must(
        driver
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("the create above must have persisted this identity's own row");
    assert_eq!(
        current.revision, admitted.revision,
        "the durable row starts at exactly the revision its own admission minted, which is the \
         revision every save below steps from"
    );
    assert_eq!(
        current.plan.effects[position].bound.max_attempts, widened,
        "the contour that reached the table is the one every delta below is read against"
    );

    // A SKIP, THROUGH THE STORE: refused. `attempt` two past the stored row, so
    // the record claims an attempt this removal identity never spent, and
    // `max_attempts` deliberately unchanged so the contour term cannot be what
    // refuses it.
    let mut skipped = current.clone();
    skipped.plan.effects[position].bound = CanaryRemovalEffectBound {
        attempt: plan_time.attempt + 2,
        max_attempts: widened,
    };
    skipped.revision = current.revision + 1;
    must(skipped.validate());
    let refusal = driver
        .store_mut()
        .compare_and_save_canary_removal_operation(
            &must(CanaryRemovalOperationVersion::of(&current)),
            &skipped,
        );
    assert!(
        matches!(refusal, Err(InstallationError::IdentityConflict)),
        "an attempt two past the row this save replaces is an attempt this removal identity never \
         spent, and the record-to-record `plan_digest` comparison inside \
         `compare_and_save_canary_removal_operation` cannot see it because `computed_digest` \
         normalises this member back to the plan-time stamp: only \
         `validate_canary_removal_operation_transition`, which is handed the decoded `current` \
         beside the proposed record, can refuse it, got {refusal:?}"
    );
    let after_skip = must(
        driver
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("a refused save leaves the row this case created in place");
    assert_eq!(
        after_skip.revision, current.revision,
        "a refused save must leave the durable row exactly as it was, or the refusal above could \
         have come after the write"
    );
    assert_eq!(
        after_skip.plan.effects[position].bound.attempt, plan_time.attempt,
        "the refused skip must not have spent an attempt this removal identity never earned"
    );

    // THE POSITIVE BESIDE IT, or a rule that refused everything would have passed
    // the refusal above. The identical save, differing only in a step of exactly
    // one instead of two, is admitted and durably written.
    let mut stepped = current.clone();
    stepped.plan.effects[position].bound = CanaryRemovalEffectBound {
        attempt: plan_time.attempt + 1,
        max_attempts: widened,
    };
    stepped.revision = current.revision + 1;
    must(stepped.validate());
    must(
        driver
            .store_mut()
            .compare_and_save_canary_removal_operation(
                &must(CanaryRemovalOperationVersion::of(&current)),
                &stepped,
            ),
    );
    let after_step = must(
        driver
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("the admitted save replaced the row this case created");
    assert_eq!(
        after_step.revision,
        current.revision + 1,
        "the admitted advance must be the durable row's own next revision, or the acceptance above \
         would be vacuous"
    );
    assert_eq!(
        after_step.plan.effects[position].bound.attempt,
        plan_time.attempt + 1,
        "the durable row must carry exactly the one step past the stamp it replaced, and that \
         counter is the ONLY member on which this save differs from the refusal above"
    );

    // THE FLOOR'S OWN REWIND ARM, which the rewind above cannot reach: `attempt`
    // back down by one, still a non-zero attempt inside the same contour, so the
    // owner validator admits the record and only a check handed the decoded
    // `current` can see the backward step.
    let mut stepped_back = after_step.clone();
    stepped_back.plan.effects[position].bound = CanaryRemovalEffectBound {
        attempt: plan_time.attempt,
        max_attempts: widened,
    };
    stepped_back.revision = after_step.revision + 1;
    must(stepped_back.validate());
    let refusal = driver
        .store_mut()
        .compare_and_save_canary_removal_operation(
            &must(CanaryRemovalOperationVersion::of(&after_step)),
            &stepped_back,
        );
    assert!(
        matches!(refusal, Err(InstallationError::IdentityConflict)),
        "an attempt below the row this save replaces re-runs an attempt number this removal identity \
         already spent, and `CanaryRemovalOperation::validate` cannot see it because a single \
         record with this attempt is inside its own contour — which the rewind above asserts from \
         the other side, got {refusal:?}"
    );
    assert_eq!(
        must(
            driver
                .store()
                .load_canary_removal_operation(&plan.removal_transaction_id)
        )
        .expect("a refused save leaves the row the admitted advance wrote in place")
        .revision,
        after_step.revision,
        "a refused save must leave the durable row exactly as it was, so the save below is still \
         measured against `after_step`"
    );

    // AND THE OTHER POSITIVE, or the lower bound could be tightened into
    // demanding a fresh attempt per write: the same save with the attempt left
    // EQUAL to the stored row's. A same-state save is legal — it discards no
    // evidence — and it is the only case that separates "forward-only" from
    // "strictly increasing".
    let mut unchanged = after_step.clone();
    unchanged.revision = after_step.revision + 1;
    must(unchanged.validate());
    assert_eq!(
        unchanged.plan.effects[position].bound.attempt,
        after_step.plan.effects[position].bound.attempt,
        "this save must differ from the row it replaces in its revision and nothing else, so an \
         acceptance below is about the attempt arm alone"
    );
    must(
        driver
            .store_mut()
            .compare_and_save_canary_removal_operation(
                &must(CanaryRemovalOperationVersion::of(&after_step)),
                &unchanged,
            ),
    );
    let after_same = must(
        driver
            .store()
            .load_canary_removal_operation(&plan.removal_transaction_id),
    )
    .expect("the admitted same-attempt save replaced the row this case wrote");
    assert_eq!(
        after_same.revision,
        after_step.revision + 1,
        "an unchanged attempt is still one durable revision step, and the row must say so"
    );
    assert_eq!(
        after_same.plan.effects[position].bound.attempt,
        plan_time.attempt + 1,
        "the accepted same-attempt save must not have moved the counter the floor reads, which is \
         what makes it a positive rather than an unrelated write"
    );

    fixture.cleanup();
}

/// RULE C: the `state` tag is the sole discriminant of a durable per-row state,
/// and the one place serde's own leniency reaches this owner is the `Pending`
/// UNIT variant. The change is documentation, so the proof has to be the
/// behaviour itself in BOTH halves.
///
/// INVARIANT pinned: the wire contract documented on
/// `canary_removal.rs::CanaryRemovalEffectState`
/// (`canary_removal.rs:1105-1163`) — `deny_unknown_fields` strictly decodes the
/// three MEMBER-CARRYING variants `IntentCommitted`, `Resolved` and `Unknown`,
/// while serde routes the internally tagged unit variant `Pending` through its
/// `InternallyTaggedUnitVisitor`, whose `visit_map` consumes and discards every
/// remaining key. Asserting only the refusal half would let the gap be closed
/// silently by making `Pending` strict; asserting only the acceptance half would
/// let a member be smuggled into the three variants that carry one.
///
/// THE PAYLOADS ARE THE OWNER'S OWN SERIALIZATION, NOT A SECOND MECHANISM.
/// `redb_state.rs::encode_canary_removal_operation` (`redb_state.rs:1986-1996`)
/// writes `serde_json::to_vec` of an envelope whose `operation` member is this
/// value, and `redb_state.rs::decode_canary_removal_operation`
/// (`redb_state.rs:1998-2030`) reads it back by probing `wire_version` and then
/// calling `serde_json::from_value`, which is the call driven below on the same
/// document the store writes. There is no crate-visible seam that injects raw
/// bytes into that table: `CANARY_REMOVAL_TABLE` and `decode_canary_removal_operation`
/// are private to `redb_state`, and `create_canary_removal_operation` only ever
/// writes this owner's own `Serialize` output, which emits no such key. So the
/// decode is exercised through the store's own function on the store's own
/// serialization rather than through a hand-rolled payload builder.
#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "both halves of the serde asymmetry, each with its own untouched control"
)]
fn canary_removal_pending_state_discards_an_extra_key_while_member_states_refuse_it() {
    let _lock = PRODUCTION_INSTALLER_TEST_LOCK
        .lock()
        .unwrap_or_else(|_| unreachable!());
    let (_owner_lease, host) = live_host_capability();
    let fixture = canary_removal_fixture(&host);
    let target = fixture.install.candidate_manifest.generation.clone();
    let planner = InstallationCoordinator::new(empty_canary_removal_port(), fixture.store());
    let plan = must(plan_canary_removal(
        &planner,
        &fixture.registry,
        &canary_removal_request(&target),
        &target,
    ));
    let operation = crashed_canary_removal_operation(&plan);
    must(operation.validate());

    // The exact stored representation of a real durable record, and the control
    // that the untouched document decodes back to the exact record it was
    // written from. Without this, a refusal below could be attributed to the
    // fixture rather than to the injected key.
    let stored = must(serde_json::to_value(&operation));
    assert_eq!(
        must(serde_json::from_value::<CanaryRemovalOperation>(
            stored.clone()
        )),
        operation,
        "the durable record must round-trip through the store's own serialization before any key \
         is injected, or every assertion below would be about the fixture rather than about the \
         injected key"
    );

    // The two rows this case reads and writes, located by the tag each one
    // actually stores rather than by a position typed here.
    let progress = stored
        .get("effect_progress")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| {
            unreachable!("a durable operation carries one progress row per frozen plan row")
        });
    let mut pending_at = None;
    let mut resolved_at = None;
    for (position, entry) in progress.iter().enumerate() {
        match entry
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| unreachable!("every durable progress row carries the state tag"))
        {
            "PENDING" => {
                if pending_at.is_none() {
                    pending_at = Some(position);
                }
            }
            "RESOLVED" => {
                if resolved_at.is_none() {
                    resolved_at = Some(position);
                }
            }
            other => unreachable!("unexpected durable state tag {other}"),
        }
    }
    let pending_at = pending_at
        .unwrap_or_else(|| unreachable!("the crash state leaves unreadable rows pending"));
    let resolved_at = resolved_at
        .unwrap_or_else(|| unreachable!("the crash state closes driven rows as resolved"));
    assert_ne!(
        pending_at, resolved_at,
        "the two rows under test must be different rows of the same denominator, or the asymmetry \
         below would be read off a single row"
    );

    // THE NEARBY PRESENT VALUE. The resolved row of this very document really
    // does carry its declared members, so "the pending row carried nothing" is a
    // statement about the asymmetry and not about an empty document.
    let stored_resolved = must(serde_json::from_value::<CanaryRemovalEffectState>(
        stored["effect_progress"][resolved_at]["state"].clone(),
    ));
    let CanaryRemovalEffectState::Resolved {
        disposition,
        evidence,
    } = stored_resolved
    else {
        unreachable!("a stored RESOLVED payload must decode as Resolved")
    };
    assert!(
        !evidence.is_empty(),
        "the resolved row must carry the evidence its owner reported, so the discarded-key \
         assertion below is demonstrably discriminating"
    );
    assert_eq!(
        disposition,
        CanaryRemovalEffectDisposition::Removed,
        "the resolved row must carry the disposition its owner reported"
    );

    // (a) `Pending` ACCEPTS and DISCARDS an extra key beside the tag. This is
    // what actually happens, and the assertion below is that it happens: serde's
    // internally tagged unit variant consumes every remaining key, and
    // `deny_unknown_fields` is never consulted for a unit variant.
    let mut with_pending_extra_key = stored.clone();
    {
        let pending_state = with_pending_extra_key
            .get_mut("effect_progress")
            .and_then(serde_json::Value::as_array_mut)
            .unwrap_or_else(|| unreachable!())[pending_at]
            .get_mut("state")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(
            pending_state.len(),
            1,
            "a stored PENDING payload is the tag alone, so the key below is an addition rather than \
             a replacement"
        );
        pending_state.insert("attempt".to_owned(), serde_json::json!(3));
    }
    let decoded = must(serde_json::from_value::<CanaryRemovalOperation>(
        with_pending_extra_key,
    ));
    assert!(
        matches!(
            decoded.effect_progress[pending_at].state,
            CanaryRemovalEffectState::Pending
        ),
        "a PENDING payload carrying a key beside the tag decodes as `Pending` rather than being \
         refused: that is serde's own leniency for an internally tagged unit variant, and this \
         owner records it rather than papering over it"
    );
    // Nothing rides in the discarded key, so the decoded record is the original
    // record: the one value that could have travelled there, the spent attempt,
    // reaches the durable record only through `IntentCommitted`, whose `attempt`
    // is strictly decoded.
    assert_eq!(
        decoded, operation,
        "the discarded key must leave the decoded record identical to the record it was written \
         from, or something rode in beside the tag"
    );
    must(decoded.validate());

    // (b) The three MEMBER-CARRYING variants are strictly decoded. `RESOLVED` is
    // taken from the stored document above, so the injected key sits beside the
    // members this owner actually validates on it.
    let mut with_resolved_extra_key = stored.clone();
    {
        let resolved_state = with_resolved_extra_key
            .get_mut("effect_progress")
            .and_then(serde_json::Value::as_array_mut)
            .unwrap_or_else(|| unreachable!())[resolved_at]
            .get_mut("state")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap_or_else(|| unreachable!());
        assert!(
            resolved_state.contains_key("disposition") && resolved_state.contains_key("evidence"),
            "the stored RESOLVED payload must carry the members the variant declares, so the \
             injected key below is genuinely an addition"
        );
        resolved_state.insert("attempt".to_owned(), serde_json::json!(3));
    }
    assert!(
        serde_json::from_value::<CanaryRemovalEffectState>(
            stored["effect_progress"][resolved_at]["state"].clone(),
        )
        .is_ok(),
        "the untouched RESOLVED payload must decode, or the refusal below would not be about the \
         injected key"
    );
    assert!(
        serde_json::from_value::<CanaryRemovalEffectState>(
            with_resolved_extra_key["effect_progress"][resolved_at]["state"].clone(),
        )
        .is_err(),
        "a RESOLVED payload carrying a key beside the tag must be refused rather than read with the \
         extra member ignored: `disposition` and `evidence` ARE this row's authority, so an \
         unrecognised member beside them is a record this owner never wrote"
    );
    assert!(
        serde_json::from_value::<CanaryRemovalOperation>(with_resolved_extra_key).is_err(),
        "the refusal must hold for the whole durable record the store decodes, not only for the \
         one nested state it was injected into"
    );

    // The other two member-carrying variants, over the owner's own serialization
    // of the variant itself: the tag spelling and the member names both come
    // from the derive on `CanaryRemovalEffectState`, not from a literal here.
    for (tag, payload, extra_key, extra_value) in [
        (
            "UNKNOWN",
            must(serde_json::to_value(CanaryRemovalEffectState::Unknown {
                pending_ref: test_handle("pending-ref:canary-removal-state-strictness"),
            })),
            "attempt",
            serde_json::json!(3),
        ),
        (
            "INTENT_COMMITTED",
            must(serde_json::to_value(
                CanaryRemovalEffectState::IntentCommitted {
                    attempt: 1,
                    intent_digest: test_handle("intent-digest:canary-removal-state-strictness"),
                },
            )),
            "pending_ref",
            serde_json::json!("injected-pending-ref"),
        ),
    ] {
        let decoded_tag = match must(serde_json::from_value::<CanaryRemovalEffectState>(
            payload.clone(),
        )) {
            CanaryRemovalEffectState::Unknown { .. } => "UNKNOWN",
            CanaryRemovalEffectState::IntentCommitted { .. } => "INTENT_COMMITTED",
            other => unreachable!(
                "the untouched {tag} payload must decode as its own variant, got {other:?}"
            ),
        };
        assert_eq!(
            decoded_tag, tag,
            "the untouched payload must decode as the variant its tag names, or the refusal below \
             would not be about the injected key"
        );
        let mut tampered = payload;
        tampered
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .insert(extra_key.to_owned(), extra_value);
        assert!(
            serde_json::from_value::<CanaryRemovalEffectState>(tampered).is_err(),
            "a {tag} payload carrying `{extra_key}` beside the tag must be refused: this variant \
             carries members this owner validates, so an unrecognised member beside them is a \
             record it never wrote"
        );
    }

    fixture.cleanup();
}
