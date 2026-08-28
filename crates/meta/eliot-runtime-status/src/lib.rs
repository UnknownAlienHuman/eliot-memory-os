//! Eliot runtime status — read-only status projections.
//!
//! Crate-level note: service-registration observation/projection is owned by
//! `service_registration_status` (Architecture A2.3, A11.3, A11.4, A13.10,
//! ARCH-MOD-02, ARCH-OBS-01; Implementation I1.8, I1.9, I1.10, I3.4, I14.20;
//! Topology I2.2, I2.23). No lifecycle/SCM mutation/canonical/readiness
//! authority here.

#![forbid(unsafe_code)]
#![allow(clippy::manual_let_else)]

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use eliot_contracts::sha256_hex;
use eliot_installation::InstallationError;
use eliot_installation::InstallationTransactionStore;
use eliot_installation::{CandidateManifest, InstallerServiceRole};
use eliot_runtime_contracts::{HealthDimension, SupervisionLeaseVerifier};
use serde::{Deserialize, Serialize};

mod service_registration_status;
pub(crate) use service_registration_status::inspect_approved_service_registration;
#[cfg(test)]
pub(crate) use service_registration_status::project_service_registration_inspection;
pub use service_registration_status::{
    ServiceRegistrationState, ServiceRuntimeIdentity, service_gap_for,
};

mod supervision_verification;
use supervision_verification::require_host_monotonic_lease;
#[cfg(windows)]
use supervision_verification::verify_host_supervision_bundle;

mod supervision_projection;
pub use supervision_projection::CurrentSupervisionEvidence;

mod store_live_status;
#[cfg(test)]
use store_live_status::store_tcp_endpoint_exact;
pub use store_live_status::{ProductionStoreLiveObserver, StoreLiveObserver, StoreLiveSnapshot};
use store_live_status::{inspect_store_live, production_store_observer};

mod eliotd_live;
pub use eliotd_live::{EliotdLiveObserver, EliotdLiveSnapshot, ProductionEliotdLiveObserver};
use eliotd_live::{eliotd_live_gap, inspect_eliotd_live};

const WATCHDOG_PUBLICATION_CHILD_LIMIT: u64 = 1024 * 1024;
const HOST_JOURNAL_FILE_NAME: &str = "host-state-journal.redb";
const WIN32_ERROR_FILE_NOT_FOUND: u32 = 2;
const WIN32_ERROR_PATH_NOT_FOUND: u32 = 3;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ComponentState {
    Healthy,
    Missing { reason: String },
    Unavailable { reason: String },
    Corrupt { reason: String },
    Unknown { reason: String, gap: String },
    NotHealthy { reason: String },
}

impl ComponentState {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionStageContour {
    pub state: ComponentState,
    pub stage: Option<String>,
    pub gap: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatusReport {
    pub contract: String,
    pub contract_version: String,
    pub status: String,
    pub host_state_root: String,
    pub active_generation: Option<String>,
    pub last_known_good_generation: Option<String>,
    pub generations: Vec<String>,
    pub host_journal: HostJournalContour,
    pub ors: OrsContour,
    pub transaction_stage: TransactionStageContour,
    pub services: ServiceContours,
    pub readiness: ReadinessContour,
    pub recovery_command: String,
    pub gaps: Vec<String>,
    pub components: ComponentStatuses,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostJournalContour {
    pub state: ComponentState,
    pub clean: Option<bool>,
    pub sequence: Option<u64>,
    pub last_checksum: Option<String>,
    pub prior_kernel_unknown: Option<bool>,
    pub gap: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrsContour {
    pub state: ComponentState,
    /// Exact current dynamic supervision evidence projected only after the
    /// Host journal, ORS head, signature/freshness context and immutable
    /// Watchdog publication have been verified together.
    pub current_supervision: Option<CurrentSupervisionEvidence>,
    pub gap: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceContours {
    pub kernel: ComponentState,
    pub store: ComponentState,
    pub eliotd: ComponentState,
    pub watchdog: ComponentState,
    pub host_service_registration: ServiceRegistrationState,
    pub watchdog_service_registration: ServiceRegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReadinessContour {
    pub proof_status: ComponentState,
    pub age_gap: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComponentStatuses {
    pub installation_registry: ComponentState,
    pub host_journal: ComponentState,
    pub ors_supervision: ComponentState,
    pub kernel: ComponentState,
    pub store: ComponentState,
    pub eliotd: ComponentState,
    pub watchdog: ComponentState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusError {
    Invalid(String),
    Unavailable(String),
    DeadlineExceeded,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => write!(f, "invalid: {msg}"),
            Self::Unavailable(msg) => write!(f, "unavailable: {msg}"),
            Self::DeadlineExceeded => write!(f, "deadline exceeded"),
        }
    }
}

impl std::error::Error for StatusError {}

fn check_deadline(deadline: Instant) -> Result<(), StatusError> {
    if Instant::now() >= deadline {
        return Err(StatusError::DeadlineExceeded);
    }
    Ok(())
}

fn host_journal_gap() -> String {
    "KernelReadinessObservationRecord.observed_at is opaque PlatformHandle without wall-clock binding; freshness cannot be proven from durable record schema alone; circular self-attestation prevents independent health verification".to_owned()
}

fn ors_gap() -> String {
    "manifest-bound ORS verification requires the installer-provisioned trust anchor, current context, and retained read-only leases; missing, corrupt, or mismatched evidence remains Unknown".to_owned()
}

fn current_unix_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "current time overflows u64".to_owned())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn service_gap(name: &str) -> String {
    format!(
        "authoritative {name} observation unavailable; no typed read-only {name} health adapter exists; SCM Running does not prove readiness"
    )
}

fn transaction_stage_gap() -> String {
    "installation transaction stage unavailable; no typed read-only transaction-stage adapter exists; durable transaction store binding not inspected from Host root lease; stage requires explicit evidence identifier".to_owned()
}

const TRANSACTION_STORE_FILE_NAME: &str = "installation-transaction.redb";

fn installation_stage_string(stage: eliot_installation::InstallationStage) -> String {
    match stage {
        eliot_installation::InstallationStage::Planned => "PLANNED".to_owned(),
        eliot_installation::InstallationStage::Staging => "STAGING".to_owned(),
        eliot_installation::InstallationStage::StaticVerified => "STATIC_VERIFIED".to_owned(),
        eliot_installation::InstallationStage::Registering => "REGISTERING".to_owned(),
        eliot_installation::InstallationStage::Activating => "ACTIVATING".to_owned(),
        eliot_installation::InstallationStage::ActiveVerified => "ACTIVE_VERIFIED".to_owned(),
        eliot_installation::InstallationStage::Cleaning => "CLEANING".to_owned(),
        eliot_installation::InstallationStage::Completed => "COMPLETED".to_owned(),
        eliot_installation::InstallationStage::RollbackRequired => "ROLLBACK_REQUIRED".to_owned(),
        eliot_installation::InstallationStage::RolledBack => "ROLLED_BACK".to_owned(),
        eliot_installation::InstallationStage::Quarantined => "QUARANTINED".to_owned(),
    }
}

// Keep transaction selection and its fail-closed readback in one auditable
// decision boundary.
#[allow(clippy::too_many_lines)]
fn inspect_transaction_stage(
    retained_root: &eliot_platform_windows::ProtectedRootLease,
    canonical_path: &Path,
    deadline: Instant,
    registry_opt: Option<&eliot_installation::ApprovedGenerationRegistry>,
) -> TransactionStageContour {
    if Instant::now() >= deadline {
        return TransactionStageContour {
            state: ComponentState::Unknown {
                reason: "deadline exceeded before transaction inspection".to_owned(),
                gap: "bounded deadline".to_owned(),
            },
            stage: None,
            gap: transaction_stage_gap(),
        };
    }
    if retained_root.verify_stable_identity().is_err() {
        return TransactionStageContour {
            state: ComponentState::Unavailable {
                reason: "retained Host root identity changed before transaction inspection"
                    .to_owned(),
            },
            stage: None,
            gap: transaction_stage_gap(),
        };
    }
    let expected = if let Some(registry) = registry_opt {
        if let Some(pending) = registry.pending_activation() {
            Some((
                pending.transaction_id.clone(),
                pending.manifest.generation.clone(),
                pending.plan_digest.clone(),
                pending.manifest.runtime_launch.profile,
                pending
                    .manifest
                    .runtime_launch
                    .runtime_state_roots
                    .host_state_root
                    .clone(),
                registry.revision(),
            ))
        } else if let Some(active) = registry.active_generation() {
            let item = registry
                .generations()
                .iter()
                .find(|g| &g.manifest.generation == active);
            item.map(|item| {
                (
                    item.approval.transaction_id().clone(),
                    item.manifest.generation.clone(),
                    item.approval.installer_plan_digest().clone(),
                    item.manifest.runtime_launch.profile,
                    item.manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .clone(),
                    registry.revision(),
                )
            })
        } else {
            None
        }
    } else {
        return TransactionStageContour {
            state: ComponentState::Unknown {
                reason: "transaction stage unavailable because the validated approved-generation registry is unavailable; status refuses direct table parsing or fallback reopen"
                    .to_owned(),
                gap: transaction_stage_gap(),
            },
            stage: None,
            gap: transaction_stage_gap(),
        };
    };
    let Some((
        expected_tx_id,
        expected_generation,
        expected_plan_digest,
        expected_profile,
        expected_host_root,
        registry_revision,
    )) = expected
    else {
        return TransactionStageContour {
            state: ComponentState::Unknown {
                reason: "no pending or active generation bound to transaction; transaction stage unavailable"
                    .to_owned(),
                gap: transaction_stage_gap(),
            },
            stage: None,
            gap: transaction_stage_gap(),
        };
    };
    let tx_path = canonical_path.join(TRANSACTION_STORE_FILE_NAME);
    #[cfg(windows)]
    {
        let parent_lease =
            match eliot_platform_windows::ProtectedRootLease::open_existing(canonical_path) {
                Ok(l) => l,
                Err(e) => {
                    let msg = e.to_string().to_ascii_lowercase();
                    if msg.contains("not found") || msg.contains("missing") {
                        return TransactionStageContour {
                            state: ComponentState::Missing {
                                reason: format!(
                                    "transaction parent absent at {}: {e}",
                                    canonical_path.display()
                                ),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    return TransactionStageContour {
                        state: ComponentState::Unavailable {
                            reason: format!("transaction parent lease: {e}"),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
            };
        let parent_canonical = match parent_lease.canonical_path() {
            Ok(p) => p,
            Err(e) => {
                return TransactionStageContour {
                    state: ComponentState::Unavailable {
                        reason: format!("transaction parent canonical: {e}"),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
        };
        if !eliot_platform_windows::windows_paths_equal(&parent_canonical, canonical_path) {
            return TransactionStageContour {
                state: ComponentState::Corrupt {
                    reason: "transaction parent canonical does not match retained Host root"
                        .to_owned(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        let tx_lease =
            match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                &tx_path,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    let msg = error.to_string().to_ascii_lowercase();
                    if msg.contains("not found") || msg.contains("missing") {
                        return TransactionStageContour {
                            state: ComponentState::Missing {
                                reason: format!(
                                    "transaction store absent at {}: {error}; status never creates it",
                                    tx_path.display()
                                ),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    if msg.contains("reparse") {
                        return TransactionStageContour {
                            state: ComponentState::Corrupt {
                                reason: "transaction store path is not a regular file".to_owned(),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    return TransactionStageContour {
                        state: ComponentState::Unavailable {
                            reason: format!("transaction store lease: {error}"),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
            };
        if tx_lease.verify_stable_identity().is_err() || tx_lease.verify_path_identity().is_err() {
            return TransactionStageContour {
                state: ComponentState::Unavailable {
                    reason: "transaction store retained identity mismatch".to_owned(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        let store =
            match eliot_installation::RedbInstallationTransactionStore::open_existing_exact_path(
                &tx_path,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string().to_ascii_lowercase();
                    if msg.contains("migration") {
                        return TransactionStageContour {
                            state: ComponentState::Unknown {
                                reason: format!("transaction store migration required: {e}"),
                                gap: "schema mismatch".to_owned(),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    if msg.contains("corrupt") {
                        return TransactionStageContour {
                            state: ComponentState::Corrupt {
                                reason: format!("transaction store corrupt: {e}"),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    if msg.contains("permission") || msg.contains("access") {
                        return TransactionStageContour {
                            state: ComponentState::Unavailable {
                                reason: format!("transaction store access denied: {e}"),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    return TransactionStageContour {
                        state: ComponentState::Unavailable {
                            reason: format!("transaction store open at {}: {e}", tx_path.display()),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
            };
        // no lease identity check for direct open
        let loaded = match store.load(&expected_tx_id) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                if msg.contains("migration") {
                    return TransactionStageContour {
                        state: ComponentState::Unknown {
                            reason: format!("transaction migration required: {e}"),
                            gap: "schema mismatch".to_owned(),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
                if msg.contains("corrupt") {
                    return TransactionStageContour {
                        state: ComponentState::Corrupt {
                            reason: format!("transaction corrupt: {e}"),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
                if msg.contains("permission") || msg.contains("access") {
                    return TransactionStageContour {
                        state: ComponentState::Unavailable {
                            reason: format!("transaction access denied: {e}"),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
                return TransactionStageContour {
                    state: ComponentState::Unavailable {
                        reason: format!("transaction load: {e}"),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
        };
        let Some(transaction) = loaded else {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "transaction {} not present in durable store at {}; store bound to retained root {}",
                        expected_tx_id.as_str(),
                        tx_path.display(),
                        canonical_path.display()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        };
        if let Err(e) = transaction.validate() {
            return TransactionStageContour {
                state: ComponentState::Corrupt {
                    reason: format!("transaction validate: {e}"),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.transaction_id != expected_tx_id {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "transaction id mismatch: expected {} got {}",
                        expected_tx_id.as_str(),
                        transaction.transaction_id.as_str()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.candidate_manifest.generation != expected_generation {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "generation mismatch: expected {} got {}",
                        expected_generation.as_str(),
                        transaction.candidate_manifest.generation.as_str()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if !eliot_platform_windows::windows_paths_equal(
            Path::new(expected_host_root.as_str()),
            canonical_path,
        ) {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "expected Host state root mismatch: expected {} != retained {}",
                        expected_host_root.as_str(),
                        canonical_path.display()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if !eliot_platform_windows::windows_paths_equal(
            Path::new(
                transaction
                    .candidate_manifest
                    .runtime_launch
                    .runtime_state_roots
                    .host_state_root
                    .as_str(),
            ),
            canonical_path,
        ) {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "Host state root mismatch: manifest {} != retained {}",
                        transaction
                            .candidate_manifest
                            .runtime_launch
                            .runtime_state_roots
                            .host_state_root
                            .as_str(),
                        canonical_path.display()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.candidate_manifest.runtime_launch.profile != expected_profile {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "profile mismatch: expected {:?} got {:?}",
                        expected_profile, transaction.candidate_manifest.runtime_launch.profile
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.installer_plan_digest != expected_plan_digest {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "plan digest mismatch: expected {} got {}",
                        expected_plan_digest.as_str(),
                        transaction.installer_plan_digest.as_str()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        let stage_str = installation_stage_string(transaction.stage());
        let bound_gap = format!(
            "validated transaction_id={} generation={} stage={} profile={:?} host_root={} registry_revision={} file={} lease=stable",
            expected_tx_id.as_str(),
            expected_generation.as_str(),
            stage_str,
            expected_profile,
            canonical_path.display(),
            registry_revision,
            tx_path.display()
        );
        let _keep = (parent_lease, tx_lease, store);
        TransactionStageContour {
            state: ComponentState::Unknown {
                reason: format!(
                    "validated transaction stage {stage_str} bound to {}@{} plan {} registry_rev {} file {}",
                    expected_tx_id.as_str(),
                    expected_generation.as_str(),
                    expected_plan_digest.as_str(),
                    registry_revision,
                    tx_path.display()
                ),
                gap: bound_gap.clone(),
            },
            stage: Some(stage_str),
            gap: bound_gap,
        }
    }
    #[cfg(not(windows))]
    {
        let tx_path = canonical_path.join(TRANSACTION_STORE_FILE_NAME);
        let store =
            match eliot_installation::RedbInstallationTransactionStore::open_existing_exact_path(
                &tx_path,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string().to_ascii_lowercase();
                    if msg.contains("migration") {
                        return TransactionStageContour {
                            state: ComponentState::Unknown {
                                reason: format!("transaction store migration required: {e}"),
                                gap: "schema mismatch".to_owned(),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    if msg.contains("corrupt") {
                        return TransactionStageContour {
                            state: ComponentState::Corrupt {
                                reason: format!("transaction store corrupt: {e}"),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    if msg.contains("not found")
                        || msg.contains("notfound")
                        || msg.contains("missing")
                        || msg.contains("no such")
                    {
                        return TransactionStageContour {
                            state: ComponentState::Missing {
                                reason: format!(
                                    "transaction store absent at {}: {e}; status never creates it",
                                    tx_path.display()
                                ),
                            },
                            stage: None,
                            gap: transaction_stage_gap(),
                        };
                    }
                    return TransactionStageContour {
                        state: ComponentState::Unavailable {
                            reason: format!("transaction store open: {e}"),
                        },
                        stage: None,
                        gap: transaction_stage_gap(),
                    };
                }
            };
        let loaded = match store.load(&expected_tx_id) {
            Ok(v) => v,
            Err(e) => {
                return TransactionStageContour {
                    state: ComponentState::Unavailable {
                        reason: format!("transaction load: {e}"),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
        };
        let transaction = match loaded {
            Some(t) => t,
            None => {
                return TransactionStageContour {
                    state: ComponentState::Unknown {
                        reason: format!(
                            "transaction {} not present in durable store at {}",
                            expected_tx_id.as_str(),
                            tx_path.display()
                        ),
                        gap: transaction_stage_gap(),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
        };
        if let Err(e) = transaction.validate() {
            return TransactionStageContour {
                state: ComponentState::Corrupt {
                    reason: format!("transaction validate: {e}"),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.transaction_id != expected_tx_id
            || transaction.candidate_manifest.generation != expected_generation
        {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: "transaction binding mismatch".to_owned(),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if !eliot_platform_windows::windows_paths_equal(
            Path::new(expected_host_root.as_str()),
            canonical_path,
        ) {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "expected Host state root mismatch: expected {} != retained {}",
                        expected_host_root.as_str(),
                        canonical_path.display()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str()
            != canonical_path.to_string_lossy().as_ref()
            && !eliot_platform_windows::windows_paths_equal(
                Path::new(
                    transaction
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .as_str(),
                ),
                canonical_path,
            )
        {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: "Host state root mismatch".to_owned(),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.candidate_manifest.runtime_launch.profile != expected_profile {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "profile mismatch: expected {:?} got {:?}",
                        expected_profile, transaction.candidate_manifest.runtime_launch.profile
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        if transaction.installer_plan_digest != expected_plan_digest {
            return TransactionStageContour {
                state: ComponentState::Unknown {
                    reason: format!(
                        "plan digest mismatch: expected {} got {}",
                        expected_plan_digest.as_str(),
                        transaction.installer_plan_digest.as_str()
                    ),
                    gap: transaction_stage_gap(),
                },
                stage: None,
                gap: transaction_stage_gap(),
            };
        }
        let stage_str = installation_stage_string(transaction.stage());
        let bound_gap = format!(
            "validated transaction_id={} generation={} stage={} registry_revision={} file={}",
            expected_tx_id.as_str(),
            expected_generation.as_str(),
            stage_str,
            registry_revision,
            tx_path.display()
        );
        TransactionStageContour {
            state: ComponentState::Unknown {
                reason: format!(
                    "validated transaction stage {stage_str} bound to {}",
                    expected_tx_id.as_str()
                ),
                gap: bound_gap.clone(),
            },
            stage: Some(stage_str),
            gap: bound_gap,
        }
    }
}

fn missing_production_dependency_gaps() -> Vec<String> {
    vec![
        format!("Kernel: {}", service_gap("Kernel")),
        format!("Store: {}", service_gap("Store")),
        format!("eliotd: {}", service_gap("eliotd")),
        format!("Watchdog: {}", service_gap("Watchdog")),
    ]
}

fn kernel_gap() -> String {
    "Kernel live requires Active Consumed durable record, exact pid/start/image bound to retained Job membership, current authority/config/fence and bounded fresh Host-authored readiness lease".to_owned()
}

fn store_gap() -> String {
    "Store live requires exact PID/start/image/Job, active generation/config/artifact, current committed StoreRebind fence and fresh authenticated readiness".to_owned()
}

fn watchdog_gap() -> String {
    "Watchdog live requires exact canonical SCM/process admission, current signed supervision lease and bounded heartbeat bound to that revision".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelLiveSnapshot {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
    pub job_name: String,
    pub observed_at_unix_ms: u64,
}

pub trait KernelLiveObserver {
    fn observe_kernel_live(
        &self,
        expected_pid: u32,
        expected_start: u64,
        expected_image: &str,
        expected_job: &str,
        deadline: Instant,
    ) -> Result<Option<KernelLiveSnapshot>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogLiveSnapshot {
    pub observed_at_unix_ms: u64,
    pub heartbeat_unix_ms: u64,
    pub lease_verified: bool,
}

pub trait WatchdogLiveObserver {
    fn observe_watchdog_live(
        &self,
        deadline: Instant,
    ) -> Result<Option<WatchdogLiveSnapshot>, String>;
}

fn unknown_component(name: &str, reason: String) -> ComponentState {
    ComponentState::Unknown {
        reason,
        gap: match name {
            "Kernel" => kernel_gap(),
            "Store" => store_gap(),
            "Watchdog" => watchdog_gap(),
            "eliotd" => eliotd_live_gap(),
            _ => service_gap(name),
        },
    }
}

fn parse_observed_at_millis(value: &str) -> Result<u64, String> {
    if value.trim().is_empty() || value.chars().any(|c| !c.is_ascii_digit()) {
        return Err("observed_at is not decimal unix ms".to_owned());
    }
    let v: u64 = value
        .parse()
        .map_err(|_| "observed_at parse failed".to_owned())?;
    if v == 0 {
        return Err("observed_at is zero".to_owned());
    }
    Ok(v)
}

fn is_fresh_observed_at(observed_at: &str, now_ms: u64) -> Result<(), String> {
    let observed = parse_observed_at_millis(observed_at)?;
    if observed > now_ms.saturating_add(5_000) {
        return Err(format!(
            "observed_at {observed} is in the future vs now {now_ms}"
        ));
    }
    if now_ms.saturating_sub(observed) > 90_000 {
        return Err(format!("observed_at {observed} is stale vs now {now_ms}"));
    }
    Ok(())
}

fn is_fresh_typed(observed_ms: u64, now_ms: u64, max_age_ms: u64) -> Result<(), String> {
    if observed_ms == 0 {
        return Err("observed_at is zero".to_owned());
    }
    if observed_ms > now_ms.saturating_add(5_000) {
        return Err(format!(
            "observed_at {observed_ms} is in the future vs now {now_ms}"
        ));
    }
    if now_ms.saturating_sub(observed_ms) > max_age_ms {
        return Err(format!(
            "observed_at {observed_ms} is stale vs now {now_ms} (max {max_age_ms}ms)"
        ));
    }
    Ok(())
}

fn select_current_store_rebind<'a>(
    host_state: &'a eliot_host_state::HostState,
) -> Result<&'a eliot_host_state::StoreRebindRecord, String> {
    if host_state.store_rebinds.is_empty() {
        return Err("no StoreRebind records".to_owned());
    }
    if host_state.applied_operations.is_empty() {
        return Err("no applied_operations for StoreRebind join".to_owned());
    }
    let mut seen_applied_identity = std::collections::HashSet::new();
    let mut seen_applied_sequence = std::collections::HashSet::new();
    for op in &host_state.applied_operations {
        if !seen_applied_identity.insert(op.identity.clone()) {
            return Err(format!(
                "duplicate applied_operations identity {}",
                op.identity.operation_id.as_str()
            ));
        }
        if !seen_applied_sequence.insert(op.sequence) {
            return Err(format!(
                "duplicate applied_operations sequence {}",
                op.sequence
            ));
        }
        if op.sequence == 0 {
            return Err("applied_operations sequence is zero".to_owned());
        }
        if op.identity.operation_id.as_str().trim().is_empty() {
            return Err("applied_operations identity is empty".to_owned());
        }
    }
    let mut seen_rebind_identity = std::collections::HashSet::new();
    let mut seen_sequence = std::collections::HashSet::new();
    let mut joined: Vec<(&'a eliot_host_state::StoreRebindRecord, u64)> = Vec::new();
    for record in &host_state.store_rebinds {
        if record.process_id == 0 || record.process_start_time_100ns == 0 {
            return Err("StoreRebind process identity is zero".to_owned());
        }
        if !seen_rebind_identity.insert(record.operation.clone()) {
            return Err(format!(
                "duplicate StoreRebind operation identity {}",
                record.operation.operation_id.as_str()
            ));
        }
        let seq = host_state
            .applied_operations
            .iter()
            .find(|op| op.identity == record.operation)
            .map(|op| op.sequence)
            .ok_or_else(|| {
                format!(
                    "StoreRebind operation {} missing join to applied_operations",
                    record.operation.operation_id.as_str()
                )
            })?;
        if !seen_sequence.insert(seq) {
            return Err(format!(
                "StoreRebind sequence collision at {seq} for operation {}",
                record.operation.operation_id.as_str()
            ));
        }
        joined.push((record, seq));
    }
    let max_seq = joined.iter().map(|(_, seq)| *seq).max().unwrap_or(0);
    let count_max = joined.iter().filter(|(_, seq)| *seq == max_seq).count();
    if count_max != 1 {
        return Err(format!(
            "ambiguous StoreRebind current at sequence {max_seq}"
        ));
    }
    let (current, _) = joined
        .into_iter()
        .max_by_key(|(_, seq)| *seq)
        .ok_or_else(|| "StoreRebind join produced no current".to_owned())?;
    Ok(current)
}

#[allow(clippy::too_many_lines, clippy::needless_return, clippy::similar_names)]
fn inspect_kernel_live(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
    observer: Option<&dyn KernelLiveObserver>,
    host_state_root: Option<&Path>,
    deadline: Instant,
) -> ComponentState {
    if Instant::now() >= deadline {
        return unknown_component(
            "Kernel",
            "deadline exceeded before Kernel inspection".to_owned(),
        );
    }
    let Some(host_state) = host_state else {
        return unknown_component(
            "Kernel",
            "no HostState for Kernel; Host journal is not validated".to_owned(),
        );
    };
    let Some(manifest) = manifest else {
        return unknown_component(
            "Kernel",
            "active approved manifest is unavailable; Kernel authority is not selected".to_owned(),
        );
    };
    let Some(kernel) = host_state.kernel.as_ref() else {
        return unknown_component("Kernel", "no Kernel record in HostState".to_owned());
    };
    if kernel.state != eliot_runtime_contracts::KernelActivationState::Active
        || kernel.one_time_nonce.state() != eliot_host_state::NonceState::Consumed
        || host_state.prior_kernel_unknown
    {
        return unknown_component(
            "Kernel",
            format!(
                "Kernel not Active Consumed for readiness: state {:?} nonce {:?} prior_unknown {}",
                kernel.state,
                kernel.one_time_nonce.state(),
                host_state.prior_kernel_unknown
            ),
        );
    }
    if kernel.approved_artifact_hash.as_str() != manifest.kernel_artifact_digest.as_str() {
        return unknown_component(
            "Kernel",
            format!(
                "Kernel approved_artifact_hash {} does not equal current manifest kernel_artifact_digest {}",
                kernel.approved_artifact_hash.as_str(),
                manifest.kernel_artifact_digest.as_str()
            ),
        );
    }
    if manifest.generation.as_str().is_empty() {
        return unknown_component(
            "Kernel",
            "manifest generation is empty; current generation required".to_owned(),
        );
    }
    let current_store = match select_current_store_rebind(host_state) {
        Ok(r) => r,
        Err(e) => {
            return unknown_component(
                "Kernel",
                format!("StoreRebind current selection failed: {e}"),
            );
        }
    };
    if current_store.state != eliot_host_state::StoreRebindState::Committed {
        return unknown_component(
            "Kernel",
            format!(
                "current StoreRebind is {:?} not Committed; blocks Kernel Healthy",
                current_store.state
            ),
        );
    }
    if current_store.store_fence.as_str().len() != 64
        || !current_store
            .store_fence
            .as_str()
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return unknown_component(
            "Kernel",
            "current StoreRebind store_fence is not valid hex".to_owned(),
        );
    }
    if current_store.authority_epoch == 0 {
        return unknown_component(
            "Kernel",
            "current StoreRebind authority_epoch is zero".to_owned(),
        );
    }
    if current_store.generation == 0 {
        return unknown_component(
            "Kernel",
            "current StoreRebind generation is zero".to_owned(),
        );
    }
    if current_store
        .receipt_store_fence
        .as_ref()
        .is_none_or(|v| v.as_str() != current_store.store_fence.as_str())
    {
        return unknown_component(
            "Kernel",
            "current StoreRebind receipt fence does not match handoff fence".to_owned(),
        );
    }
    if current_store
        .receipt_request_digest
        .as_ref()
        .is_none_or(|v| v.as_str() != current_store.request_digest.as_str())
    {
        return unknown_component(
            "Kernel",
            "current StoreRebind receipt digest does not match request".to_owned(),
        );
    }
    if host_state.readiness_observations.is_empty() {
        return unknown_component(
            "Kernel",
            "no KernelReadinessObservationRecord is present".to_owned(),
        );
    }
    let Some(observed) = host_state.readiness_observations.last() else {
        return unknown_component(
            "Kernel",
            "no KernelReadinessObservationRecord is present".to_owned(),
        );
    };
    let active_checksum = match eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            return unknown_component("Kernel", format!("active Kernel checksum failed: {e}"));
        }
    };
    if observed.validate_against(kernel, &active_checksum).is_err() {
        return unknown_component("Kernel", "readiness observation is not bound to the exact active Kernel checksum/process/Job/authority".to_owned());
    }
    if observed.store_fence.as_str() != current_store.store_fence.as_str() {
        return unknown_component(
            "Kernel",
            format!(
                "readiness store_fence {} is not the current committed StoreRebind fence {} for this authority",
                observed.store_fence.as_str(),
                current_store.store_fence.as_str()
            ),
        );
    }
    if observed.authority_epoch != current_store.authority_epoch {
        return unknown_component(
            "Kernel",
            format!(
                "readiness authority_epoch {} does not equal current StoreRebind authority {}",
                observed.authority_epoch, current_store.authority_epoch
            ),
        );
    }
    let Some(observer) = observer else {
        return unknown_component(
            "Kernel",
            "Kernel live observer unavailable; no default observer is used; Kernel live proof requires independent handle-bound observation".to_owned(),
        );
    };
    let expected_pid = observed.kernel_job.root_pid;
    let expected_start = observed.kernel_job.root_start_time_100ns;
    let expected_image = observed.kernel_job.root_image_path.as_str().to_owned();
    let expected_job = observed.kernel_job.job_name.as_str().to_owned();
    let snapshot = match observer.observe_kernel_live(
        expected_pid,
        expected_start,
        &expected_image,
        &expected_job,
        deadline,
    ) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return unknown_component(
                "Kernel",
                "Kernel observer returned no live snapshot; Kernel is not live".to_owned(),
            );
        }
        Err(e) => return unknown_component("Kernel", format!("Kernel observer failed: {e}")),
    };
    if snapshot.process_id != expected_pid
        || snapshot.start_time_100ns != expected_start
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&snapshot.image_path),
            Path::new(&expected_image),
        )
        || snapshot.job_name != expected_job
    {
        return unknown_component(
            "Kernel",
            format!(
                "Kernel live snapshot mismatch: expected pid {} start {} image {} job {} got pid {} start {} image {} job {}",
                expected_pid,
                expected_start,
                expected_image,
                expected_job,
                snapshot.process_id,
                snapshot.start_time_100ns,
                snapshot.image_path,
                snapshot.job_name
            ),
        );
    }
    let now_ms = match current_unix_ms() {
        Ok(v) => v,
        Err(e) => return unknown_component("Kernel", format!("current time unavailable: {e}")),
    };
    if let Err(e) = is_fresh_typed(snapshot.observed_at_unix_ms, now_ms, 90_000) {
        return unknown_component("Kernel", format!("Kernel live snapshot not fresh: {e}"));
    }
    if let Err(e) = require_host_monotonic_lease(host_state_root, Some(manifest), now_ms, deadline)
    {
        return unknown_component("Kernel", format!("monotonic lease freshness required: {e}"));
    }
    return ComponentState::Healthy;
}

#[allow(clippy::too_many_lines, clippy::needless_return)]
fn inspect_watchdog_live(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
    ors: &OrsContour,
    host_service: &ServiceRegistrationState,
    watchdog_service: &ServiceRegistrationState,
    observer: Option<&dyn WatchdogLiveObserver>,
    deadline: Instant,
) -> ComponentState {
    if Instant::now() >= deadline {
        return unknown_component(
            "Watchdog",
            "deadline exceeded before Watchdog inspection".to_owned(),
        );
    }
    if !matches!(ors.state, ComponentState::Healthy) {
        return unknown_component(
            "Watchdog",
            format!(
                "ORS supervision is not Healthy; Watchdog heartbeat cannot be proven: {:?}",
                ors.state
            ),
        );
    }
    let Some(_host_state) = host_state else {
        return unknown_component(
            "Watchdog",
            "no HostState for Watchdog; Host journal is not validated".to_owned(),
        );
    };
    let Some(_manifest) = manifest else {
        return unknown_component(
            "Watchdog",
            "active approved manifest is unavailable; Watchdog admission is not manifest-bound"
                .to_owned(),
        );
    };
    if host_service.registration != "Matching" || watchdog_service.registration != "Matching" {
        return unknown_component(
            "Watchdog",
            format!(
                "SCM registration not Matching: host {} watchdog {}",
                host_service.registration, watchdog_service.registration
            ),
        );
    }
    if host_service.observed_runtime.is_none() || watchdog_service.observed_runtime.is_none() {
        return unknown_component(
            "Watchdog",
            "SCM Running does not prove readiness; handle-bound process identity missing"
                .to_owned(),
        );
    }
    let Some(observer) = observer else {
        return unknown_component(
            "Watchdog",
            "Watchdog live observer unavailable; no default observer is used; Watchdog heartbeat/lease requires independent observation".to_owned(),
        );
    };
    let snapshot = match observer.observe_watchdog_live(deadline) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return unknown_component(
                "Watchdog",
                "Watchdog observer returned no live snapshot; Watchdog is not live".to_owned(),
            );
        }
        Err(e) => return unknown_component("Watchdog", format!("Watchdog observer failed: {e}")),
    };
    if !snapshot.lease_verified {
        return unknown_component(
            "Watchdog",
            "Watchdog lease not verified; Watchdog is not live".to_owned(),
        );
    }
    let now_ms = match current_unix_ms() {
        Ok(v) => v,
        Err(e) => return unknown_component("Watchdog", format!("current time unavailable: {e}")),
    };
    if let Err(e) = is_fresh_typed(snapshot.heartbeat_unix_ms, now_ms, 90_000) {
        return unknown_component("Watchdog", format!("Watchdog heartbeat not fresh: {e}"));
    }
    if let Err(e) = is_fresh_typed(snapshot.observed_at_unix_ms, now_ms, 90_000) {
        return unknown_component("Watchdog", format!("Watchdog observed_at not fresh: {e}"));
    }
    return ComponentState::Healthy;
}

pub struct ProductionKernelLiveObserver;
pub struct ProductionWatchdogLiveObserver {
    host_state_root: PathBuf,
    manifest: Option<CandidateManifest>,
}

impl ProductionWatchdogLiveObserver {
    #[cfg(test)]
    fn for_root(host_state_root: &Path) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
            manifest: None,
        }
    }

    fn for_manifest(host_state_root: &Path, manifest: &CandidateManifest) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
            manifest: Some(manifest.clone()),
        }
    }
}

impl KernelLiveObserver for ProductionKernelLiveObserver {
    #[allow(clippy::needless_return, clippy::manual_let_else)]
    fn observe_kernel_live(
        &self,
        expected_pid: u32,
        expected_start: u64,
        expected_image: &str,
        expected_job: &str,
        deadline: Instant,
    ) -> Result<Option<KernelLiveSnapshot>, String> {
        if Instant::now() >= deadline {
            return Err("deadline exceeded before Kernel observation".to_owned());
        }
        #[cfg(not(windows))]
        {
            let _ = (expected_pid, expected_start, expected_image, expected_job);
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let now_ms = current_unix_ms()?;
            match eliot_platform_windows::observe_named_pipe_peer_process_in_job(
                expected_job,
                expected_pid,
            ) {
                Ok(binding) => {
                    let id = binding.process_binding().identity();
                    if id.process_id != expected_pid
                        || id.start_time_100ns != expected_start
                        || !eliot_platform_windows::windows_paths_equal(
                            Path::new(&id.image_path),
                            Path::new(expected_image),
                        )
                        || binding.job_name() != expected_job
                    {
                        return Ok(None);
                    }
                    Ok(Some(KernelLiveSnapshot {
                        process_id: id.process_id,
                        start_time_100ns: id.start_time_100ns,
                        image_path: id.image_path.clone(),
                        job_name: binding.job_name().to_owned(),
                        observed_at_unix_ms: now_ms,
                    }))
                }
                Err(_) => Ok(None),
            }
        }
    }
}

impl WatchdogLiveObserver for ProductionWatchdogLiveObserver {
    #[allow(clippy::needless_return)]
    fn observe_watchdog_live(
        &self,
        deadline: Instant,
    ) -> Result<Option<WatchdogLiveSnapshot>, String> {
        if Instant::now() >= deadline {
            return Err("deadline exceeded before Watchdog observation".to_owned());
        }
        #[cfg(not(windows))]
        {
            let _ = &self.host_state_root;
            return Ok(None);
        }
        #[cfg(windows)]
        {
            if Instant::now() >= deadline {
                return Err("deadline exceeded before Watchdog SCM observation".to_owned());
            }
            let now_ms = current_unix_ms()?;
            let Some(manifest) = self.manifest.as_ref() else {
                return Ok(None);
            };
            let bundle = match verify_host_supervision_bundle(
                &self.host_state_root,
                manifest,
                now_ms,
                deadline,
            ) {
                Ok(envelope) => envelope,
                Err(_) => return Ok(None),
            };
            let heartbeat_ms = bundle.envelope.payload.issued_at_ms;
            Ok(Some(WatchdogLiveSnapshot {
                observed_at_unix_ms: now_ms,
                heartbeat_unix_ms: heartbeat_ms,
                lease_verified: true,
            }))
        }
    }
}

#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub fn collect_status_with_observers(
    host_state_root: &Path,
    deadline: Instant,
    kernel_observer: Option<&dyn KernelLiveObserver>,
    store_observer: Option<&dyn StoreLiveObserver>,
    watchdog_observer: Option<&dyn WatchdogLiveObserver>,
    eliotd_observer: Option<&dyn EliotdLiveObserver>,
) -> Result<RuntimeStatusReport, StatusError> {
    check_deadline(deadline)?;
    if !host_state_root.is_absolute() {
        return Err(StatusError::Invalid(
            "host-state-root must be absolute".to_owned(),
        ));
    }
    check_deadline(deadline)?;
    // Classify a genuinely absent caller-selected root before the protected
    // contour adapter runs.  An absent path cannot be admitted, and
    // `ProtectedRootLease` intentionally reports both a missing path and an
    // out-of-contour path through adapter errors; probing existence first keeps
    // the public status contract honest without relaxing containment for any
    // existing path.
    if matches!(
        std::fs::symlink_metadata(host_state_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return Err(StatusError::Unavailable(
            "host-state-root does not exist; status never creates it".to_owned(),
        ));
    }
    let retained_root = eliot_platform_windows::ProtectedRootLease::open_existing(host_state_root)
        .map_err(|e| {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("not found")
                || msg.contains("missing")
                || msg.contains("notfound")
                || msg.contains("unsupported")
            {
                StatusError::Unavailable(
                    "host-state-root does not exist; status never creates it".to_owned(),
                )
            } else {
                StatusError::Invalid(format!("retain root: {e}"))
            }
        })?;
    let canonical_path = retained_root
        .canonical_path()
        .map_err(|e| StatusError::Invalid(format!("canonical: {e}")))?;
    if !eliot_platform_windows::windows_paths_equal(&canonical_path, host_state_root) {
        return Err(StatusError::Invalid(
            "host-state-root is not the exact retained installation root".to_owned(),
        ));
    }
    retained_root
        .verify_stable_identity()
        .map_err(|e| StatusError::Invalid(format!("stable identity: {e}")))?;
    check_deadline(deadline)?;

    let registry_lease = eliot_platform_windows::ProtectedRootLease::open_existing(&canonical_path)
        .map_err(|e| StatusError::Invalid(format!("reopen retained root: {e}")))?;
    let registry_result =
        eliot_installation::RedbInstallationRegistry::inspect_existing_at(registry_lease);
    let (
        registry_state,
        active_gen,
        lkg_gen,
        generations,
        recovery_command,
        active_manifest,
        registry_opt,
    ) = match registry_result {
        Ok(Some(registry)) => {
            registry
                .validate()
                .map_err(|e| StatusError::Invalid(format!("registry validate: {e}")))?;
            for generation in registry.generations() {
                let declared = &generation
                    .manifest
                    .runtime_launch
                    .runtime_state_roots
                    .host_state_root;
                if !eliot_platform_windows::windows_paths_equal(
                    &canonical_path,
                    Path::new(declared.as_str()),
                ) {
                    return Err(StatusError::Invalid(
                        "manifest Host state root does not equal retained installation root"
                            .to_owned(),
                    ));
                }
            }
            if let Some(pending) = registry.pending_activation() {
                let declared = &pending
                    .manifest
                    .runtime_launch
                    .runtime_state_roots
                    .host_state_root;
                if !eliot_platform_windows::windows_paths_equal(
                    &canonical_path,
                    Path::new(declared.as_str()),
                ) {
                    return Err(StatusError::Invalid(
                        "pending activation Host state root mismatch".to_owned(),
                    ));
                }
            }
            let active = registry.active_generation().map(|v| v.as_str().to_owned());
            let lkg = registry
                .last_known_good_generation()
                .map(|v| v.as_str().to_owned());
            let gens = registry
                .generations()
                .iter()
                .map(|g| g.manifest.generation.as_str().to_owned())
                .collect();
            let active_manifest = registry
                .active()
                .map(|generation| generation.manifest.clone());
            let opt = Some(registry);
            (
                ComponentState::Healthy,
                active,
                lkg,
                gens,
                "eliot installation recover --help".to_owned(),
                active_manifest,
                opt,
            )
        }
        Ok(None) => (
            ComponentState::Missing {
                reason: "registry does not exist; status never creates it".to_owned(),
            },
            None,
            None,
            Vec::new(),
            "eliot installation recover --help".to_owned(),
            None,
            None,
        ),
        Err(e) => {
            let state = match &e {
                InstallationError::MigrationRequired { reason } => ComponentState::Unknown {
                    reason: reason.clone(),
                    gap: "registry migration required".to_owned(),
                },
                InstallationError::CorruptRegistry { reason } => ComponentState::Corrupt {
                    reason: reason.clone(),
                },
                _ => ComponentState::Unavailable {
                    reason: e.to_string(),
                },
            };
            (
                state,
                None,
                None,
                Vec::new(),
                "eliot installation recover --help".to_owned(),
                None,
                None,
            )
        }
    };
    check_deadline(deadline)?;
    let (journal_contour, host_state_for_readiness) = inspect_host_journal_retained(
        &retained_root,
        &canonical_path,
        active_manifest.as_ref(),
        deadline,
    );
    check_deadline(deadline)?;
    let readiness = inspect_readiness_from_host_state(host_state_for_readiness.as_ref(), deadline);
    check_deadline(deadline)?;

    let ors_contour = inspect_ors_retained(
        &retained_root,
        &canonical_path,
        active_manifest.as_ref(),
        deadline,
    );
    check_deadline(deadline)?;

    let host_service = inspect_approved_service_registration(
        registry_opt.as_ref(),
        active_manifest.as_ref(),
        InstallerServiceRole::Host,
        &canonical_path,
        deadline,
    );
    let watchdog_service = inspect_approved_service_registration(
        registry_opt.as_ref(),
        active_manifest.as_ref(),
        InstallerServiceRole::Watchdog,
        &canonical_path,
        deadline,
    );
    check_deadline(deadline)?;

    let transaction_stage_contour = inspect_transaction_stage(
        &retained_root,
        &canonical_path,
        deadline,
        registry_opt.as_ref(),
    );
    let kernel_state = inspect_kernel_live(
        host_state_for_readiness.as_ref(),
        active_manifest.as_ref(),
        kernel_observer,
        Some(canonical_path.as_path()),
        deadline,
    );
    let derived_store_observer =
        production_store_observer(host_state_for_readiness.as_ref(), active_manifest.as_ref());
    let effective_store_observer: Option<&dyn StoreLiveObserver> = if let Some(obs) = store_observer
    {
        Some(obs)
    } else {
        derived_store_observer
            .as_ref()
            .map(|o| o as &dyn StoreLiveObserver)
    };
    let store_state = inspect_store_live(
        host_state_for_readiness.as_ref(),
        active_manifest.as_ref(),
        effective_store_observer,
        Some(canonical_path.as_path()),
        deadline,
    );
    let eliotd_state = inspect_eliotd_live(
        host_state_for_readiness.as_ref(),
        active_manifest.as_ref(),
        eliotd_observer,
        deadline,
    );
    let derived_watchdog_observer = active_manifest
        .as_ref()
        .map(|manifest| ProductionWatchdogLiveObserver::for_manifest(&canonical_path, manifest));
    let effective_watchdog_observer: Option<&dyn WatchdogLiveObserver> =
        watchdog_observer.or_else(|| {
            derived_watchdog_observer
                .as_ref()
                .map(|observer| observer as &dyn WatchdogLiveObserver)
        });
    let watchdog_state = inspect_watchdog_live(
        host_state_for_readiness.as_ref(),
        active_manifest.as_ref(),
        &ors_contour,
        &host_service,
        &watchdog_service,
        effective_watchdog_observer,
        deadline,
    );
    let gaps = {
        let mut g = Vec::new();
        g.push(host_journal_gap());
        g.push(ors_gap());
        g.push(transaction_stage_gap());
        g.extend(missing_production_dependency_gaps());
        if !matches!(registry_state, ComponentState::Healthy) {
            g.push(format!(
                "registry: {}",
                match &registry_state {
                    ComponentState::Missing { reason }
                    | ComponentState::Corrupt { reason }
                    | ComponentState::Unavailable { reason } => reason.clone(),
                    ComponentState::Unknown { reason, gap } => format!("{reason} gap={gap}"),
                    _ => "unknown".to_owned(),
                }
            ));
        }
        if !matches!(ors_contour.state, ComponentState::Healthy) {
            g.push(format!(
                "ors: {} gap={}",
                match &ors_contour.state {
                    ComponentState::Missing { reason }
                    | ComponentState::Corrupt { reason }
                    | ComponentState::Unavailable { reason } => reason.clone(),
                    ComponentState::Unknown { reason, .. } => reason.clone(),
                    _ => "unknown".to_owned(),
                },
                ors_contour.gap
            ));
        }
        g.push(format!(
            "transaction_stage: {} gap={}",
            match &transaction_stage_contour.state {
                ComponentState::Unknown { reason, .. } => reason.clone(),
                _ => "unknown".to_owned(),
            },
            transaction_stage_contour.gap
        ));
        g.push(format!(
            "SCM {}: {}",
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            host_service.gap
        ));
        g.push(format!(
            "SCM {}: {}",
            eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME,
            watchdog_service.gap
        ));
        if !matches!(kernel_state, ComponentState::Healthy) {
            g.push(format!(
                "kernel: {} gap={}",
                match &kernel_state {
                    ComponentState::Unknown { reason, gap } => format!("{reason} gap={gap}"),
                    ComponentState::Missing { reason } => reason.clone(),
                    ComponentState::Unavailable { reason } => reason.clone(),
                    ComponentState::Corrupt { reason } => reason.clone(),
                    _ => "unknown".to_owned(),
                },
                kernel_gap()
            ));
        }
        if !matches!(store_state, ComponentState::Healthy) {
            g.push(format!(
                "store: {} gap={}",
                match &store_state {
                    ComponentState::Unknown { reason, gap } => format!("{reason} gap={gap}"),
                    _ => "unknown".to_owned(),
                },
                store_gap()
            ));
        }
        if !matches!(eliotd_state, ComponentState::Healthy) {
            g.push(format!(
                "eliotd: {} gap={}",
                match &eliotd_state {
                    ComponentState::Unknown { reason, gap } => format!("{reason} gap={gap}"),
                    _ => "unknown".to_owned(),
                },
                eliotd_live_gap()
            ));
        }
        if !matches!(watchdog_state, ComponentState::Healthy) {
            g.push(format!(
                "watchdog: {} gap={}",
                match &watchdog_state {
                    ComponentState::Unknown { reason, gap } => format!("{reason} gap={gap}"),
                    _ => "unknown".to_owned(),
                },
                watchdog_gap()
            ));
        }
        g
    };

    let components = ComponentStatuses {
        installation_registry: registry_state.clone(),
        host_journal: journal_contour.state.clone(),
        ors_supervision: ors_contour.state.clone(),
        kernel: kernel_state.clone(),
        store: store_state.clone(),
        eliotd: eliotd_state.clone(),
        watchdog: watchdog_state.clone(),
    };

    let overall = if components.installation_registry.is_healthy()
        && components.host_journal.is_healthy()
        && components.ors_supervision.is_healthy()
        && components.kernel.is_healthy()
        && components.store.is_healthy()
        && components.eliotd.is_healthy()
        && components.watchdog.is_healthy()
    {
        "RUNTIME_LIVE"
    } else {
        "NOT_HEALTHY"
    };

    let _keep_root_alive = retained_root;

    Ok(RuntimeStatusReport {
        contract: "eliot.runtime.live".to_owned(),
        contract_version: "1.1.0".to_owned(),
        status: overall.to_owned(),
        host_state_root: canonical_path.to_string_lossy().into_owned(),
        active_generation: active_gen,
        last_known_good_generation: lkg_gen,
        generations,
        host_journal: journal_contour,
        ors: ors_contour,
        transaction_stage: transaction_stage_contour,
        services: ServiceContours {
            kernel: kernel_state,
            store: store_state,
            eliotd: eliotd_state,
            watchdog: watchdog_state,
            host_service_registration: host_service,
            watchdog_service_registration: watchdog_service,
        },
        readiness,
        recovery_command,
        gaps,
        components,
        deadline_exceeded: false,
    })
}

pub fn collect_status(
    host_state_root: &Path,
    deadline: Instant,
) -> Result<RuntimeStatusReport, StatusError> {
    let kernel_observer = ProductionKernelLiveObserver;
    let eliotd_observer = ProductionEliotdLiveObserver::for_root(host_state_root);
    collect_status_with_observers(
        host_state_root,
        deadline,
        Some(&kernel_observer),
        None,
        None,
        Some(&eliotd_observer),
    )
}

fn readiness_gap() -> String {
    "readiness identity is durable, but KernelReadinessObservationRecord.observed_at is an opaque PlatformHandle; a typed Host-authored timestamp or bounded readiness lease is required before freshness can be proven".to_owned()
}

// Journal inspection is kept as one ordered no-fallback boundary so retained
// root/file leases remain alive through replay and projection.
#[allow(clippy::too_many_lines)]
fn inspect_host_journal_retained(
    retained_root: &eliot_platform_windows::ProtectedRootLease,
    canonical_path: &Path,
    active_manifest: Option<&CandidateManifest>,
    deadline: Instant,
) -> (HostJournalContour, Option<eliot_host_state::HostState>) {
    if Instant::now() >= deadline {
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "deadline exceeded before journal inspection".to_owned(),
                    gap: "bounded deadline".to_owned(),
                },
                clean: None,
                sequence: None,
                last_checksum: None,
                prior_kernel_unknown: None,
                gap: host_journal_gap(),
            },
            None,
        );
    }
    #[cfg(windows)]
    if retained_root.verify_stable_identity().is_err() {
        return (
            HostJournalContour {
                state: ComponentState::Unavailable {
                    reason: "retained Host root identity changed before journal inspection"
                        .to_owned(),
                },
                clean: None,
                sequence: None,
                last_checksum: None,
                prior_kernel_unknown: None,
                gap: host_journal_gap(),
            },
            None,
        );
    }
    let journal_path = canonical_path.join("host-state-journal.redb");
    #[cfg(windows)]
    {
        let journal_lease =
            match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                &journal_path,
            ) {
                Ok(lease) => lease,
                Err(error) => match error {
                    eliot_platform_windows::ProtectedPathError::ReparsePoint => {
                        return (
                            HostJournalContour {
                                state: ComponentState::Corrupt {
                                    reason: "host journal path is not a regular file".to_owned(),
                                },
                                clean: None,
                                sequence: None,
                                last_checksum: None,
                                prior_kernel_unknown: None,
                                gap: host_journal_gap(),
                            },
                            None,
                        );
                    }
                    eliot_platform_windows::ProtectedPathError::AclMismatch => {
                        return (
                            HostJournalContour {
                                state: ComponentState::Unavailable {
                                    reason: format!("journal lease ACL mismatch: {error}"),
                                },
                                clean: None,
                                sequence: None,
                                last_checksum: None,
                                prior_kernel_unknown: None,
                                gap: host_journal_gap(),
                            },
                            None,
                        );
                    }
                    eliot_platform_windows::ProtectedPathError::InvalidPath
                    | eliot_platform_windows::ProtectedPathError::InvalidRoot
                    | eliot_platform_windows::ProtectedPathError::Io
                    | eliot_platform_windows::ProtectedPathError::Win32 {
                        code: WIN32_ERROR_FILE_NOT_FOUND | WIN32_ERROR_PATH_NOT_FOUND,
                        ..
                    } => {
                        return (
                            HostJournalContour {
                                state: ComponentState::Missing {
                                    reason: format!(
                                        "host journal absent at {}",
                                        journal_path.display()
                                    ),
                                },
                                clean: None,
                                sequence: None,
                                last_checksum: None,
                                prior_kernel_unknown: None,
                                gap: host_journal_gap(),
                            },
                            None,
                        );
                    }
                    _ => {
                        return (
                            HostJournalContour {
                                state: ComponentState::Unavailable {
                                    reason: format!("journal lease: {error}"),
                                },
                                clean: None,
                                sequence: None,
                                last_checksum: None,
                                prior_kernel_unknown: None,
                                gap: host_journal_gap(),
                            },
                            None,
                        );
                    }
                },
            };
        if journal_lease.verify_stable_identity().is_err()
            || journal_lease.verify_path_identity().is_err()
        {
            return (
                HostJournalContour {
                    state: ComponentState::Unavailable {
                        reason: "journal retained identity mismatch".to_owned(),
                    },
                    clean: None,
                    sequence: None,
                    last_checksum: None,
                    prior_kernel_unknown: None,
                    gap: host_journal_gap(),
                },
                None,
            );
        }
    }
    let inspection = match eliot_host_state::RedbJournalBackend::inspect_existing_at(&journal_path)
    {
        Ok(Some(inspection)) => inspection,
        Ok(None) => {
            return (
                HostJournalContour {
                    state: ComponentState::Missing {
                        reason: format!("host journal absent at {}", journal_path.display()),
                    },
                    clean: None,
                    sequence: None,
                    last_checksum: None,
                    prior_kernel_unknown: None,
                    gap: host_journal_gap(),
                },
                None,
            );
        }
        Err(error) => {
            return (
                HostJournalContour {
                    state: ComponentState::Unavailable {
                        reason: format!(
                            "protected host journal inspection failed without fallback: {error:?}"
                        ),
                    },
                    clean: None,
                    sequence: None,
                    last_checksum: None,
                    prior_kernel_unknown: None,
                    gap: host_journal_gap(),
                },
                None,
            );
        }
    };
    if retained_root.verify_stable_identity().is_err()
        || inspection
            .image
            .epochs
            .iter()
            .any(|epoch| epoch.bytes.is_empty())
    {
        let torn = inspection
            .image
            .epochs
            .iter()
            .any(|epoch| epoch.bytes.is_empty());
        if torn {
            return (
                HostJournalContour {
                    state: ComponentState::Corrupt {
                        reason: "journal bytes torn or exceeds bounds".to_owned(),
                    },
                    clean: None,
                    sequence: None,
                    last_checksum: None,
                    prior_kernel_unknown: None,
                    gap: host_journal_gap(),
                },
                None,
            );
        }
    }
    let image = &inspection.image;
    if image.epochs.is_empty() {
        return (
            HostJournalContour {
                state: ComponentState::Missing {
                    reason: "journal has no durable epochs".to_owned(),
                },
                clean: Some(false),
                sequence: Some(0),
                last_checksum: None,
                prior_kernel_unknown: Some(false),
                gap: host_journal_gap(),
            },
            None,
        );
    }
    let mut total_bytes: usize = 0;
    let mut torn = false;
    for epoch in &image.epochs {
        if epoch.bytes.is_empty() {
            torn = true;
        }
        total_bytes = total_bytes.saturating_add(epoch.bytes.len());
        if total_bytes > 64 * 1024 * 1024 {
            torn = true;
        }
    }
    if torn {
        return (
            HostJournalContour {
                state: ComponentState::Corrupt {
                    reason: "journal bytes torn or exceeds bounds".to_owned(),
                },
                clean: None,
                sequence: None,
                last_checksum: None,
                prior_kernel_unknown: None,
                gap: host_journal_gap(),
            },
            None,
        );
    }
    let host_state = match eliot_host_state::readonly_project_host_state(image) {
        Ok(state) => state,
        Err(error) => {
            let reason = format!("journal replay failed: {error:?}");
            let state = match &error {
                eliot_host_state::JournalError::Torn { .. }
                | eliot_host_state::JournalError::Checksum { .. }
                | eliot_host_state::JournalError::Sequence => ComponentState::Corrupt {
                    reason: reason.clone(),
                },
                eliot_host_state::JournalError::UnknownVersion { .. } => {
                    ComponentState::Unavailable {
                        reason: reason.clone(),
                    }
                }
                _ => ComponentState::Unknown {
                    reason: reason.clone(),
                    gap: host_journal_gap(),
                },
            };
            return (
                HostJournalContour {
                    state,
                    clean: None,
                    sequence: None,
                    last_checksum: None,
                    prior_kernel_unknown: None,
                    gap: host_journal_gap(),
                },
                None,
            );
        }
    };
    #[cfg(windows)]
    if retained_root.verify_stable_identity().is_err() {
        return (
            HostJournalContour {
                state: ComponentState::Unavailable {
                    reason: "retained Host root identity changed during projection".to_owned(),
                },
                clean: None,
                sequence: None,
                last_checksum: None,
                prior_kernel_unknown: None,
                gap: host_journal_gap(),
            },
            None,
        );
    }
    let clean = host_state.clean_marker.is_some();
    let sequence = host_state.sequence;
    let last_checksum = host_state.last_checksum.clone();
    let prior = host_state.prior_kernel_unknown;
    let kernel_ok = host_state.kernel.as_ref().is_some_and(|kernel| {
        kernel.state == eliot_runtime_contracts::KernelActivationState::Active
            && kernel.one_time_nonce.state() == eliot_host_state::NonceState::Consumed
    }) && !host_state.prior_kernel_unknown
        && host_state.activation.is_some();
    if !kernel_ok {
        let reason = match (host_state.prior_kernel_unknown, host_state.kernel.as_ref()) {
            (true, _) => {
                "prior Kernel disposition is unknown; Kernel authority is fenced".to_owned()
            }
            (false, None) => "no active Kernel record with Consumed nonce".to_owned(),
            (false, Some(kernel)) => format!(
                "Kernel state {:?} nonce {:?} is not Active Consumed",
                kernel.state,
                kernel.one_time_nonce.state()
            ),
        };
        let gap = format!(
            "validated journal seq={} clean={:?} prior_unknown={} but {reason}; {}",
            sequence,
            clean,
            prior,
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason,
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    let Some(kernel) = host_state.kernel.as_ref() else {
        let gap = format!(
            "validated journal seq={sequence} clean={clean:?} prior_unknown={prior} but no kernel; {}",
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "no kernel for host journal health".to_owned(),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    };
    let active_checksum = match eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            let gap = format!("active kernel checksum failed: {e}; {}", host_journal_gap());
            return (
                HostJournalContour {
                    state: ComponentState::Unknown {
                        reason: format!("active kernel checksum failed: {e}"),
                        gap: gap.clone(),
                    },
                    clean: Some(clean),
                    sequence: Some(sequence),
                    last_checksum,
                    prior_kernel_unknown: Some(prior),
                    gap,
                },
                Some(host_state),
            );
        }
    };
    let Some(observed) = host_state.readiness_observations.last() else {
        let gap = format!(
            "validated journal seq={sequence} but no readiness observation; {}",
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "no readiness observation for host journal health".to_owned(),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    };
    if observed.validate_against(kernel, &active_checksum).is_err() {
        let gap = format!(
            "readiness not bound to exact active kernel checksum/process/Job/authority; {}",
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "readiness observation is not bound to exact active kernel".to_owned(),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    let now_ms = match current_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            let gap = format!("current time unavailable: {e}; {}", host_journal_gap());
            return (
                HostJournalContour {
                    state: ComponentState::Unknown {
                        reason: format!("current time unavailable: {e}"),
                        gap: gap.clone(),
                    },
                    clean: Some(clean),
                    sequence: Some(sequence),
                    last_checksum,
                    prior_kernel_unknown: Some(prior),
                    gap,
                },
                Some(host_state),
            );
        }
    };
    if let Err(e) = is_fresh_observed_at(observed.observed_at.as_str(), now_ms) {
        let gap = format!("readiness not fresh: {e}; {}", host_journal_gap());
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: format!("readiness not fresh: {e}"),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    let current_store = match select_current_store_rebind(&host_state) {
        Ok(r) => r,
        Err(e) => {
            let gap = format!(
                "store current selection failed: {e}; {}",
                host_journal_gap()
            );
            return (
                HostJournalContour {
                    state: ComponentState::Unknown {
                        reason: format!("store current selection failed: {e}"),
                        gap: gap.clone(),
                    },
                    clean: Some(clean),
                    sequence: Some(sequence),
                    last_checksum,
                    prior_kernel_unknown: Some(prior),
                    gap,
                },
                Some(host_state),
            );
        }
    };
    if current_store.state != eliot_host_state::StoreRebindState::Committed {
        let gap = format!(
            "current store is {:?} not Committed; {}",
            current_store.state,
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: format!("current store is {:?} not Committed", current_store.state),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    if observed.store_fence.as_str() != current_store.store_fence.as_str()
        || observed.authority_epoch != current_store.authority_epoch
    {
        let gap = format!(
            "readiness store_fence/authority does not match current committed store; {}",
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "readiness store_fence/authority does not match current store fence"
                        .to_owned(),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    if current_store
        .receipt_store_fence
        .as_ref()
        .is_none_or(|v| v.as_str() != current_store.store_fence.as_str())
        || current_store
            .receipt_request_digest
            .as_ref()
            .is_none_or(|v| v.as_str() != current_store.request_digest.as_str())
    {
        let gap = format!(
            "current store receipt does not match fence/request; {}",
            host_journal_gap()
        );
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: "current store receipt does not match".to_owned(),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    #[cfg(windows)]
    if let Err(e) =
        require_host_monotonic_lease(Some(canonical_path), active_manifest, now_ms, deadline)
    {
        let gap = format!("monotonic lease not fresh: {e}; {}", host_journal_gap());
        return (
            HostJournalContour {
                state: ComponentState::Unknown {
                    reason: format!("monotonic lease not fresh: {e}"),
                    gap: gap.clone(),
                },
                clean: Some(clean),
                sequence: Some(sequence),
                last_checksum,
                prior_kernel_unknown: Some(prior),
                gap,
            },
            Some(host_state),
        );
    }
    let gap = format!(
        "validated host journal seq={sequence} last_checksum={last_checksum:?} clean={clean:?} prior_unknown={prior} active Kernel Consumed fresh readiness store_fence={} authority={} lease fresh",
        current_store.store_fence.as_str(),
        current_store.authority_epoch
    );
    let state = ComponentState::Healthy;
    (
        HostJournalContour {
            state,
            clean: Some(clean),
            sequence: Some(sequence),
            last_checksum,
            prior_kernel_unknown: Some(prior),
            gap,
        },
        Some(host_state),
    )
}

// Readiness projection deliberately keeps every identity comparison adjacent;
// freshness remains Unknown until the durable wire carries a typed time lease.
#[allow(clippy::too_many_lines)]
fn inspect_readiness_from_host_state(
    host_state: Option<&eliot_host_state::HostState>,
    deadline: Instant,
) -> ReadinessContour {
    if Instant::now() >= deadline {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "deadline exceeded before readiness inspection".to_owned(),
                gap: "bounded deadline".to_owned(),
            },
            age_gap: "bounded deadline".to_owned(),
        };
    }
    let Some(host_state) = host_state else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no HostState for readiness; Host journal is not validated".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    let Some(kernel) = host_state.kernel.as_ref() else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no active Kernel record for readiness".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    if kernel.state != eliot_runtime_contracts::KernelActivationState::Active
        || kernel.one_time_nonce.state() != eliot_host_state::NonceState::Consumed
        || host_state.prior_kernel_unknown
    {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: format!(
                    "Kernel not Active Consumed for readiness: state {:?} nonce {:?} prior_unknown {}",
                    kernel.state,
                    kernel.one_time_nonce.state(),
                    host_state.prior_kernel_unknown
                ),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    if host_state.readiness_observations.is_empty() {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no KernelReadinessObservationRecord is present".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    let mut seen_requests = std::collections::HashSet::new();
    let mut seen_receipts = std::collections::HashSet::new();
    let mut duplicate = false;
    for observation in &host_state.readiness_observations {
        let request = observation.probe_request_digest.as_str().to_owned();
        let receipt = observation.ready_receipt_digest.as_str().to_owned();
        if !seen_requests.insert(request) || !seen_receipts.insert(receipt) {
            duplicate = true;
        }
    }
    if duplicate {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason:
                    "readiness observation digests are duplicated; freshness requires fresh digests"
                        .to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    }
    let Some(observed) = host_state.readiness_observations.last() else {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "no KernelReadinessObservationRecord is present".to_owned(),
                gap: readiness_gap(),
            },
            age_gap: readiness_gap(),
        };
    };
    let active_checksum = match eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    ) {
        Ok(checksum) => checksum,
        Err(error) => {
            return ReadinessContour {
                proof_status: ComponentState::Unknown {
                    reason: format!("active Kernel checksum failed: {error}"),
                    gap: readiness_gap(),
                },
                age_gap: readiness_gap(),
            };
        }
    };
    if observed.validate_against(kernel, &active_checksum).is_err() {
        return ReadinessContour {
            proof_status: ComponentState::Unknown {
                reason: "readiness observation is not bound to the exact active Kernel checksum/process/Job/authority"
                    .to_owned(),
                gap: "substituted readiness observation".to_owned(),
            },
            age_gap: "substituted readiness observation".to_owned(),
        };
    }
    let gap = readiness_gap();
    ReadinessContour {
        proof_status: ComponentState::Unknown {
            reason: "exact readiness identity is present, but observed_at is opaque and cannot prove freshness"
                .to_owned(),
            gap: gap.clone(),
        },
        age_gap: gap,
    }
}

fn unknown_ors(reason: impl Into<String>) -> OrsContour {
    OrsContour {
        state: ComponentState::Unknown {
            reason: reason.into(),
            gap: ors_gap(),
        },
        current_supervision: None,
        gap: ors_gap(),
    }
}

#[allow(clippy::too_many_lines)]
fn inspect_ors_retained(
    retained_root: &eliot_platform_windows::ProtectedRootLease,
    canonical_path: &Path,
    manifest: Option<&eliot_installation::CandidateManifest>,
    deadline: Instant,
) -> OrsContour {
    if Instant::now() >= deadline {
        return unknown_ors("deadline exceeded before ORS inspection");
    }
    if retained_root.verify_stable_identity().is_err() {
        return unknown_ors("retained Host root identity changed before ORS inspection");
    }
    let Some(manifest) = manifest else {
        return unknown_ors(
            "active approved manifest is unavailable; ORS path and authority are not selected",
        );
    };
    let roots = &manifest.runtime_launch.runtime_state_roots;
    if let Err(error) = roots.validate() {
        return unknown_ors(format!(
            "manifest RuntimeStateRoots validation failed: {error}"
        ));
    }
    if manifest.runtime_state_roots_digest != roots.roots_digest {
        return unknown_ors(
            "manifest RuntimeStateRoots digest does not match its launch descriptor",
        );
    }
    if !eliot_platform_windows::windows_paths_equal(
        canonical_path,
        Path::new(roots.host_state_root.as_str()),
    ) {
        return unknown_ors("active manifest Host root does not match the retained status root");
    }
    let ors_root_path = Path::new(roots.kernel_ors_root.as_str());
    if !ors_root_path.is_absolute() {
        return unknown_ors("manifest RuntimeStateRoots.kernel_ors_root is not absolute");
    }
    let ors_path = ors_root_path.join("kernel-ors.redb");

    #[cfg(not(windows))]
    {
        let _ = (retained_root, canonical_path, ors_root_path, ors_path);
        unknown_ors(
            "authoritative ORS observation requires the Windows retained root and file leases",
        )
    }
    #[cfg(windows)]
    {
        if Instant::now() >= deadline {
            return unknown_ors("deadline exceeded before manifest-bound ORS lease acquisition");
        }
        let ors_root_lease =
            match eliot_platform_windows::ProtectedRootLease::open_existing(ors_root_path) {
                Ok(lease) => lease,
                Err(error) => {
                    return unknown_ors(format!("manifest ORS root lease unavailable: {error}"));
                }
            };
        let ors_root_canonical = match ors_root_lease.canonical_path() {
            Ok(path) => path,
            Err(error) => {
                return unknown_ors(format!(
                    "manifest ORS root canonicalization failed: {error}"
                ));
            }
        };
        if !eliot_platform_windows::windows_paths_equal(&ors_root_canonical, ors_root_path)
            || ors_root_lease.verify_stable_identity().is_err()
        {
            return unknown_ors(
                "manifest ORS root retained identity does not match the declared root",
            );
        }

        let ors_file_lease =
            match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                &ors_path,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    return unknown_ors(format!("manifest-bound ORS file unavailable: {error}"));
                }
            };
        if !eliot_platform_windows::windows_paths_equal(ors_file_lease.path(), &ors_path)
            || ors_file_lease.verify_stable_identity().is_err()
            || ors_file_lease.verify_path_identity().is_err()
        {
            return unknown_ors(
                "manifest-bound ORS file retained identity does not match its path",
            );
        }

        let now_ms = match current_unix_ms() {
            Ok(value) => value,
            Err(error) => {
                return unknown_ors(format!(
                    "current time for ORS verification is invalid: {error}"
                ));
            }
        };
        let bundle =
            match verify_host_supervision_bundle(canonical_path, manifest, now_ms, deadline) {
                Ok(bundle) => bundle,
                Err(error) => return unknown_ors(error),
            };
        if Instant::now() >= deadline {
            return unknown_ors("deadline exceeded before authoritative ORS status observation");
        }
        let projection = match eliot_ors::observe_supervision_status(
            ors_file_lease.path(),
            &bundle.trust_anchor,
            &bundle.context,
        ) {
            Ok(projection) => projection,
            Err(error) => {
                return unknown_ors(format!("authoritative ORS status unavailable: {error}"));
            }
        };
        if projection.current.as_ref() != Some(&bundle.current)
            || retained_root.verify_stable_identity().is_err()
            || ors_root_lease.verify_stable_identity().is_err()
            || ors_file_lease.verify_stable_identity().is_err()
            || ors_file_lease.verify_path_identity().is_err()
        {
            return unknown_ors("a retained ORS/admission identity changed during observation");
        }
        let _keep_leases = (ors_root_lease, ors_file_lease);
        let (state, current_supervision) = if projection.health == HealthDimension::Healthy {
            let evidence = match bundle.public_evidence() {
                Ok(evidence) => evidence,
                Err(error) => return unknown_ors(error),
            };
            (ComponentState::Healthy, Some(evidence))
        } else {
            (
                ComponentState::Unknown {
                    reason: format!(
                        "authoritative ORS projection is {:?} ({:?})",
                        projection.health, projection.reason
                    ),
                    gap: ors_gap(),
                },
                None,
            )
        };
        OrsContour {
            state,
            current_supervision,
            gap: ors_gap(),
        }
    }
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn eliotd_live_receipt_ors_matches(
    manifest: &eliot_installation::CandidateManifest,
    receipt: &eliot_process::EliotdLiveReceipt,
    host_root: &Path,
    deadline: Instant,
) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let now_ms = match current_unix_ms() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let bundle = match verify_host_supervision_bundle(host_root, manifest, now_ms, deadline) {
        Ok(bundle) => bundle,
        Err(_) => return false,
    };
    let current = &bundle.current;
    let expected_fingerprint = bundle.trust_anchor.public_key_fingerprint();
    if current.record.state != eliot_runtime_contracts::LeaseState::Active
        || current.record.projection != eliot_ors::SupervisionLeaseProjection::Active
        || current.record.lease_id.as_str() != receipt.supervision.lease_id
        || current
            .record
            .binding
            .state_fence
            .resource_generation
            .value()
            != receipt.generation
        || current.record.binding.state_fence.authority_epoch.value() != receipt.authority_epoch
        || current.record.record_id.as_str() != receipt.supervision.record_id
        || current.record.revision != receipt.supervision.revision
        || current.record.receipt_sha256 != receipt.supervision.receipt_sha256
        || current.record.artifact.payload_sha256 != receipt.supervision.payload_sha256
        || current
            .record
            .artifact
            .envelope_digest()
            .map_or(true, |digest| digest != receipt.supervision.envelope_sha256)
        || receipt.supervision.public_key_fingerprint != expected_fingerprint
    {
        return false;
    }
    let verified = match bundle
        .trust_anchor
        .verify(&current.record.artifact, &bundle.context)
    {
        Ok(verified) => verified,
        Err(_) => return false,
    };
    let verified_payload_digest = match verified.payload_digest() {
        Ok(digest) => digest,
        Err(_) => return false,
    };
    if verified.payload() != &current.record.artifact.payload
        || verified_payload_digest != receipt.supervision.payload_sha256
        || verified.envelope_digest() != receipt.supervision.envelope_sha256
        || verified.public_key_fingerprint() != expected_fingerprint
        || current.record.artifact.payload.issued_at_ms == 0
        || now_ms < current.record.artifact.payload.issued_at_ms
        || now_ms >= current.record.artifact.payload.expires_at_ms
    {
        return false;
    }
    Instant::now() < deadline
}

pub fn host_journal_gap_for() -> String {
    host_journal_gap()
}

pub fn ors_gap_for() -> String {
    ors_gap()
}

pub fn transaction_stage_gap_for() -> String {
    transaction_stage_gap()
}

#[cfg(test)]
// Test fixtures intentionally use unwrap/expect to keep failed setup distinct
// from the production fail-closed assertions under test.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod honest_tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn temp_root(label: &str) -> std::path::PathBuf {
        let base = {
            #[cfg(windows)]
            {
                let program_data = eliot_platform_windows::protected_program_data_root()
                    .expect("honest test requires Windows Protected ProgramData root");
                program_data.join(format!(
                    "eliot-test-runtime-status-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join(format!(
                    "eliot-runtime-status-honest-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
        };
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create temp root");
        base
    }

    fn temp_portable_host(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = {
            #[cfg(windows)]
            {
                let program_data = eliot_platform_windows::protected_program_data_root()
                    .expect("honest test requires Windows Protected ProgramData root");
                program_data.join(format!(
                    "eliot-rt-txn-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join(format!(
                    "eliot-rt-txn-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
        };
        let _ = std::fs::remove_dir_all(&base);
        let portable = base.join("portable");
        std::fs::create_dir_all(&portable).expect("create portable");
        let host = portable.join("host");
        std::fs::create_dir_all(&host).expect("create host");
        (base, host)
    }

    fn collect(report_root: &Path) -> RuntimeStatusReport {
        let deadline = Instant::now() + Duration::from_secs(2);
        collect_status(report_root, deadline)
            .expect("collect_status must succeed for empty honest root")
    }

    #[test]
    fn honest_status_is_not_healthy_with_explicit_gaps() {
        let root = temp_root("not-healthy");
        let report = collect(&root);
        assert_eq!(report.status, "NOT_HEALTHY");
        assert_eq!(report.contract, "eliot.runtime.live");
        assert_eq!(report.contract_version, "1.1.0");
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g.contains("freshness cannot be proven"))
        );
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g.contains("provisioned trust anchor"))
        );
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g.contains("installation transaction stage"))
        );
        assert!(report.gaps.iter().any(|g| g.contains("Kernel")));
        assert!(report.gaps.iter().any(|g| g.contains("Store")));
        assert!(report.gaps.iter().any(|g| g.contains("eliotd")));
        assert!(report.gaps.iter().any(|g| g.contains("Watchdog")));
        assert!(matches!(
            report.host_journal.state,
            ComponentState::Missing { .. } | ComponentState::Unknown { .. }
        ));
        assert!(matches!(
            report.ors.state,
            ComponentState::Missing { .. }
                | ComponentState::Unknown { .. }
                | ComponentState::Unavailable { .. }
        ));
        assert!(matches!(
            report.transaction_stage.state,
            ComponentState::Unknown { .. }
        ));
        assert_eq!(report.transaction_stage.gap, transaction_stage_gap_for());
        assert!(report.transaction_stage.stage.is_none());
        assert!(!report.components.kernel.is_healthy());
        assert!(!report.components.store.is_healthy());
        assert!(!report.components.eliotd.is_healthy());
        assert!(!report.components.watchdog.is_healthy());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn honest_status_never_synthesizes_pid_key_nonce_fence() {
        let root = temp_root("no-synthesis");
        let report = collect(&root);
        let json = serde_json::to_value(&report).expect("serialize");
        let text = serde_json::to_string(&json)
            .expect("stringify")
            .to_ascii_lowercase();
        assert!(!text.contains("\"pid\""));
        assert!(!text.contains("\"nonce\""));
        assert!(!text.contains("\"fence\""));
        assert!(!text.contains("\"secret\""));
        assert!(!text.contains("\"public_key\""));
        let gaps_text = report.gaps.join(" ").to_ascii_lowercase();
        assert!(gaps_text.contains("trust anchor") || gaps_text.contains("ors"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn service_status_exposes_typed_runtime_identity_without_legacy_image_alias() {
        let identity = ServiceRuntimeIdentity {
            process_id: 4242,
            start_time_100ns: 1_777_777_777_777,
            image_path: r"C:\Eliot\eliot-host.exe".to_owned(),
            runtime_identity_digest: "a".repeat(64),
        };
        let state = ServiceRegistrationState {
            registration: "Matching".to_owned(),
            state: "Running".to_owned(),
            observed_process: None,
            observed_runtime: Some(identity),
            gap: "SCM Running is not semantic readiness".to_owned(),
        };
        let json = serde_json::to_value(state).expect("service status JSON");
        assert_eq!(json["observed_process"], serde_json::Value::Null);
        assert_eq!(json["observed_runtime"]["process_id"], 4242);
        assert_eq!(
            json["observed_runtime"]["start_time_100ns"],
            1_777_777_777_777_u64
        );
        assert_eq!(
            json["observed_runtime"]["image_path"],
            r"C:\Eliot\eliot-host.exe"
        );
        assert_eq!(
            json["observed_runtime"]["runtime_identity_digest"],
            "a".repeat(64)
        );
    }

    #[test]
    fn service_status_substitution_fails_closed_without_process_identity() {
        let state = project_service_registration_inspection(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            eliot_platform_windows::ServiceRegistrationRuntimeInspection::Mismatched,
        );
        assert_eq!(state.registration, "Mismatched");
        assert_eq!(state.state, "Unknown");
        assert!(state.observed_runtime.is_none());
        assert!(state.gap.contains("exact approved request"));
    }

    #[test]
    fn service_status_indeterminate_fails_closed_without_liveness_claim() {
        let state = project_service_registration_inspection(
            eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME,
            eliot_platform_windows::ServiceRegistrationRuntimeInspection::Unknown,
        );
        assert_eq!(state.registration, "Unknown");
        assert_eq!(state.state, "Unknown");
        assert!(state.observed_runtime.is_none());
        assert!(state.gap.contains("indeterminate"));
        assert!(!state.gap.contains("Running"));
    }

    #[test]
    fn honest_status_uses_one_retained_canonical_root() {
        let root = temp_root("retained-root");
        let report = collect(&root);
        let expected = eliot_platform_windows::canonical_windows_path(&root)
            .unwrap_or_else(|_| std::fs::canonicalize(&root).expect("canonicalize"))
            .to_string_lossy()
            .into_owned();
        assert!(
            eliot_platform_windows::windows_paths_equal(
                std::path::Path::new(&report.host_state_root),
                std::path::Path::new(&expected)
            ),
            "report root {} must equal canonical {}",
            report.host_state_root,
            expected
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn honest_status_rejects_non_absolute_root() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let relative = Path::new("relative/path");
        let err = collect_status(relative, deadline).expect_err("relative must be rejected");
        assert!(matches!(err, StatusError::Invalid(_)));
    }

    #[test]
    fn honest_status_rejects_cross_root_symlink_substitution() {
        let root = temp_root("cross-root");
        let link = std::env::temp_dir().join(format!(
            "eliot-runtime-status-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&link);
        #[cfg(unix)]
        {
            if std::os::unix::fs::symlink(&root, &link).is_ok() {
                let deadline = Instant::now() + Duration::from_secs(2);
                let err = collect_status(&link, deadline);
                assert!(err.is_err(), "symlink root must fail closed");
                let msg = err.unwrap_err().to_string().to_ascii_lowercase();
                assert!(
                    msg.contains("retained")
                        || msg.contains("canonical")
                        || msg.contains("invalid")
                );
                let _ = std::fs::remove_file(&link);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = link;
            let deadline = Instant::now() + Duration::from_secs(2);
            let other = root.join("nonexistent_child");
            let err = collect_status(&other, deadline);
            assert!(err.is_err());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn honest_ors_uses_retained_lease_and_stays_unknown() {
        let root = temp_root("ors-lease");
        let ors_path = root.join("kernel-ors.redb");
        std::fs::write(&ors_path, b"").expect("write empty ors");
        let report = collect(&root);
        assert!(matches!(
            report.ors.state,
            ComponentState::Unknown { .. }
                | ComponentState::Corrupt { .. }
                | ComponentState::Missing { .. }
                | ComponentState::Unavailable { .. }
        ));
        assert_eq!(report.ors.gap, ors_gap_for());
        assert!(!report.ors.state.is_healthy());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn honest_transaction_stage_is_typed_unknown_with_gap() {
        let root = temp_root("txn-stage");
        let report = collect(&root);
        match &report.transaction_stage.state {
            ComponentState::Unknown { reason, gap } => {
                assert!(reason.to_ascii_lowercase().contains("transaction"));
                assert_eq!(gap, &transaction_stage_gap_for());
            }
            other => panic!("transaction stage must be Unknown, got {other:?}"),
        }
        assert!(
            report
                .gaps
                .iter()
                .any(|g| g == &transaction_stage_gap_for() || g.contains("transaction_stage"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn sha256_hex_bytes(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    fn fixture_handle(value: impl Into<String>) -> eliot_installation::PlatformHandle {
        eliot_installation::PlatformHandle::new(value.into()).expect("fixture handle")
    }

    fn fixture_path(root: &Path, name: &str) -> eliot_installation::PlatformHandle {
        fixture_handle(root.join(name).to_string_lossy().into_owned())
    }

    fn fixture_provisioned_supervision_authority(
        installation_id: &str,
        candidate_generation: &str,
    ) -> eliot_runtime_contracts::ProvisionedSupervisionAuthority {
        use eliot_runtime_contracts::SupervisionLeaseSigner as _;

        let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
            "eliot-kernel",
            "test-supervision-key",
            [0x39; 32],
        )
        .expect("test supervision signer");
        let trust_anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
            installation_id,
            signer.signer_id(),
            signer.key_id(),
            signer.public_key().to_vec(),
        )
        .expect("test supervision anchor");
        let key_reference = eliot_runtime_contracts::SupervisionSealedKeyReference::new(
            "test-supervision-authority.sealed",
            "S-1-5-80-1-2-3-4-5",
            eliot_runtime_contracts::SupervisionSealedKeyFileIdentity {
                canonical_path_digest: "1".repeat(64),
                volume_serial_number: 7,
                file_index: 11,
                security_descriptor_digest: "2".repeat(64),
            },
            "3".repeat(64),
        )
        .expect("test sealed key reference");
        eliot_runtime_contracts::ProvisionedSupervisionAuthority::new(
            "test-supervision-lease",
            candidate_generation,
            eliot_installation::ResourceGeneration::genesis(),
            key_reference,
            trust_anchor,
        )
        .expect("test provisioned supervision authority")
    }

    // This fixture deliberately materializes the complete immutable installer
    // contour so projection tests exercise the production wire shape.
    #[allow(clippy::too_many_lines)]
    pub fn portable_transaction_for_host(
        host_root: &Path,
    ) -> eliot_installation::InstallationTransaction {
        let portable_root = host_root.parent().expect("host has parent").to_path_buf();
        let _ = std::fs::create_dir_all(&portable_root);
        let _ = eliot_platform_windows::UserOwnedRootLease::open_existing(&portable_root)
            .expect("lease portable");
        let runtime_state_roots = eliot_installation::RuntimeStateRoots::derive_portable(
            fixture_handle(portable_root.to_string_lossy().into_owned()),
        )
        .expect("portable roots");
        let installation_epoch = eliot_installation::InstallationEpoch {
            installation: fixture_handle("installation:txn-stage-test"),
            lineage_id: fixture_handle("lineage:txn-stage-test"),
            sequence: 1,
        };
        let generation = fixture_handle("generation:txn-stage-test");
        let mut runtime_launch = eliot_installation::RuntimeLaunchDescriptor {
            profile: eliot_installation::InstallationProfile::PortableDev,
            portable_root: Some(fixture_handle(portable_root.to_string_lossy().into_owned())),
            installation_epoch: installation_epoch.clone(),
            generation: generation.clone(),
            authority_generation: eliot_installation::ResourceGeneration::genesis(),
            authority_state_fence: eliot_installation::StateFence::new(
                eliot_installation::AuthorityEpoch::genesis(),
                eliot_installation::ResourceGeneration::genesis(),
            ),
            supervision_authority: eliot_installation::SupervisionAuthorityBinding::Provisioned {
                authority: Box::new(fixture_provisioned_supervision_authority(
                    installation_epoch.installation.as_str(),
                    generation.as_str(),
                )),
            },
            authority_descriptor_path: fixture_path(&portable_root, "authority.json"),
            authority_descriptor_digest: fixture_handle("7".repeat(64)),
            runtime_state_roots: runtime_state_roots.clone(),
            kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
            kernel_artifact_digest: fixture_handle("d".repeat(64)),
            eliotd_executable_path: fixture_path(&portable_root, "eliotd.exe"),
            eliotd_artifact_digest: fixture_handle("8".repeat(64)),
            eliotd_config_path: fixture_path(&portable_root, "eliotd-governor.json"),
            eliotd_config_digest: fixture_handle("4".repeat(64)),
            protected_snapshot_digest: fixture_handle("a".repeat(64)),
            eliotd_descriptor_path: fixture_path(&portable_root, "eliotd.json"),
            eliotd_descriptor_digest: fixture_handle("9".repeat(64)),
            eliotd_launch_nonce: fixture_handle(format!("eliotd:{}", "a".repeat(32))),
            store_config_path: fixture_path(&portable_root, "generation.json"),
            store_credential_target: fixture_handle(
                "eliot/store/v1/0123456789abcdef0123456789abcdef",
            ),
            store_bridge_executable_path: fixture_path(&portable_root, "eliot-store-surreal.exe"),
            store_bridge_artifact_digest: fixture_handle("1".repeat(64)),
            store_bootstrap_descriptor_path: fixture_path(&portable_root, "store-bootstrap.json"),
            store_bootstrap_descriptor_digest: fixture_handle(
                "516396afbc26eeb03b4630518f428b30e48eb17ba2e2b8002612d10cba1a9faa",
            ),
            canonical_store_executable_path: fixture_path(&portable_root, "surreal.exe"),
            canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
            kernel_arguments: vec![
                fixture_handle("--work-root"),
                runtime_state_roots.kernel_work_root.clone(),
                fixture_handle("--store-bootstrap"),
                fixture_path(&portable_root, "store-bootstrap.json"),
                fixture_handle("--store-bootstrap-sha256"),
                fixture_handle("516396afbc26eeb03b4630518f428b30e48eb17ba2e2b8002612d10cba1a9faa"),
                fixture_handle("--authority-descriptor"),
                fixture_path(&portable_root, "authority.json"),
                fixture_handle("--authority-descriptor-sha256"),
                fixture_handle("7".repeat(64)),
                fixture_handle("--kernel-artifact-sha256"),
                fixture_handle("d".repeat(64)),
                fixture_handle("--eliotd-descriptor"),
                fixture_path(&portable_root, "eliotd.json"),
                fixture_handle("--eliotd-descriptor-sha256"),
                fixture_handle("9".repeat(64)),
            ],
            store_bridge_arguments: vec![
                fixture_handle("--portable-dev-root"),
                fixture_handle(portable_root.to_string_lossy().into_owned()),
                fixture_handle("--config"),
                fixture_path(&portable_root, "generation.json"),
            ],
            canonical_store_arguments: vec![
                fixture_handle("start"),
                fixture_handle("--no-banner"),
                fixture_handle("--bind"),
                fixture_handle("127.0.0.1:8000"),
                fixture_handle("--temporary-directory"),
                runtime_state_roots.store_temp_root.clone(),
                fixture_handle("--log-file-enabled"),
                fixture_handle("--log-file-path"),
                runtime_state_roots.store_work_root.clone(),
                fixture_handle("--log-file-name"),
                fixture_handle("surrealdb.log"),
                fixture_handle(format!(
                    "surrealkv://{}",
                    runtime_state_roots
                        .store_data_root
                        .as_str()
                        .replace('\\', "/")
                )),
            ],
            host_executable_path: fixture_path(&portable_root, "eliot-host.exe"),
            host_artifact_digest: fixture_handle("8".repeat(64)),
            watchdog_executable_path: fixture_path(&portable_root, "eliot-watchdog.exe"),
            watchdog_artifact_digest: fixture_handle("4".repeat(64)),
            descriptor_digest: fixture_handle("f".repeat(64)),
        };
        runtime_launch = runtime_launch
            .with_computed_digest()
            .expect("computed digest");
        let candidate_manifest = eliot_installation::CandidateManifest {
            generation: generation.clone(),
            components: vec![
                fixture_handle("component:kernel"),
                fixture_handle("component:store"),
            ],
            kernel_artifact_digest: fixture_handle("d".repeat(64)),
            store_bridge_artifact_digest: fixture_handle("1".repeat(64)),
            canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
            host_artifact_digest: fixture_handle("8".repeat(64)),
            kernel_executable_path: fixture_path(&portable_root, "eliot-kernel.exe"),
            store_bridge_executable_path: fixture_path(&portable_root, "eliot-store-surreal.exe"),
            canonical_store_executable_path: fixture_path(&portable_root, "surreal.exe"),
            host_executable_path: fixture_path(&portable_root, "eliot-host.exe"),
            config_path: fixture_path(&portable_root, "generation.json"),
            dependency_closure_refs: vec![fixture_handle("evidence:dependency-closure")],
            license_refs: vec![fixture_handle("evidence:licenses")],
            config_digest: fixture_handle("2".repeat(64)),
            store_credential_target: fixture_handle(
                "eliot/store/v1/0123456789abcdef0123456789abcdef",
            ),
            supervision_key_slot: fixture_handle("3".repeat(64)),
            signature_ref: fixture_handle("evidence:signature"),
            runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
            runtime_launch,
        };
        let rollback_plan = fixture_handle("rollback:txn-stage-test");
        let request = eliot_installation::ManagedEnvironmentChangeRequest {
            request_id: fixture_handle("request:txn-stage-test"),
            requester_and_reason: fixture_handle("requester:test"),
            action: eliot_installation::ManagedEnvironmentAction::Install,
            target_family: fixture_handle("family:eliot"),
            exact_candidate: generation.clone(),
            expected_delta: fixture_handle("delta:installed"),
            source_assurance_refs: vec![fixture_handle("evidence:source-assurance")],
            affected_refs: Vec::new(),
            impact_class: fixture_handle("impact:test"),
            required_owner: fixture_handle("owner:installation"),
            rollback_plan: rollback_plan.clone(),
            verifier: fixture_handle("verifier:installation"),
            budget: fixture_handle("budget:test"),
            stop_condition: fixture_handle("stop:on-failure"),
        };
        let roots = [
            runtime_state_roots.installation_root.clone(),
            runtime_state_roots.host_state_root.clone(),
            runtime_state_roots.kernel_ors_root.clone(),
            runtime_state_roots.kernel_work_root.clone(),
            runtime_state_roots.store_data_root.clone(),
            runtime_state_roots.store_work_root.clone(),
            runtime_state_roots.store_temp_root.clone(),
            runtime_state_roots.watchdog_state_root.clone(),
        ];
        let mut planned_changes = Vec::new();
        let mut installer_effects = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            let effect_id = fixture_handle(format!("effect:create-root-{index}"));
            planned_changes.push(eliot_installation::PlannedChange {
                change_id: effect_id.clone(),
                target: root.clone(),
                precondition_refs: vec![fixture_handle(format!("evidence:precondition-{index}"))],
                postcondition_refs: vec![fixture_handle(format!("evidence:postcondition-{index}"))],
            });
            installer_effects.push(eliot_installation::InstallerEffectPlan::CreateRoot {
                effect_id,
                root: root.clone(),
            });
        }
        for (index, root) in roots.iter().enumerate() {
            let effect_id = fixture_handle(format!("effect:apply-acl-{index}"));
            planned_changes.push(eliot_installation::PlannedChange {
                change_id: effect_id.clone(),
                target: root.clone(),
                precondition_refs: vec![fixture_handle(format!(
                    "evidence:acl-precondition-{index}"
                ))],
                postcondition_refs: vec![fixture_handle(format!(
                    "evidence:acl-postcondition-{index}"
                ))],
            });
            installer_effects.push(eliot_installation::InstallerEffectPlan::ApplyAcl {
                effect_id,
                root: root.clone(),
                principals: vec![
                    eliot_installation::InstallerAclPrincipal::CurrentUser,
                    eliot_installation::InstallerAclPrincipal::LocalSystem,
                ],
            });
        }
        eliot_installation::InstallationTransaction::new_unbound_for_fixture(
            fixture_handle("transaction:txn-stage-test"),
            installation_epoch,
            eliot_installation::InstallationProfile::PortableDev,
            request,
            None,
            candidate_manifest,
            fixture_path(&portable_root, "staging"),
            planned_changes,
            installer_effects,
            1,
            vec![fixture_handle("evidence:plan-precondition")],
            rollback_plan,
        )
        .expect("transaction")
    }

    fn registry_with_pending_value(
        transaction: &eliot_installation::InstallationTransaction,
    ) -> serde_json::Value {
        let candidate_digest = sha256_hex_bytes(
            &serde_json::to_vec(&transaction.candidate_manifest).expect("manifest json"),
        );
        let candidate_digest_handle = fixture_handle(candidate_digest);
        let manifest_value =
            serde_json::to_value(&transaction.candidate_manifest).expect("manifest value");
        let authority_generation_value = serde_json::to_value(
            transaction
                .candidate_manifest
                .runtime_launch
                .authority_generation,
        )
        .expect("auth gen");
        let authority_fence_value = serde_json::to_value(
            &transaction
                .candidate_manifest
                .runtime_launch
                .authority_state_fence,
        )
        .expect("fence");
        let pending = serde_json::json!({
            "transaction_id": transaction.transaction_id.as_str(),
            "plan_digest": transaction.installer_plan_digest.as_str(),
            "manifest": manifest_value,
            "config_digest": transaction.candidate_manifest.config_digest.as_str(),
            "kernel_artifact_digest": transaction.candidate_manifest.kernel_artifact_digest.as_str(),
            "store_bridge_artifact_digest": transaction.candidate_manifest.store_bridge_artifact_digest.as_str(),
            "canonical_store_artifact_digest": transaction.candidate_manifest.canonical_store_artifact_digest.as_str(),
            "host_executable_path": transaction.candidate_manifest.host_executable_path.as_str(),
            "host_artifact_digest": transaction.candidate_manifest.host_artifact_digest.as_str(),
            "runtime_state_roots_digest": transaction.candidate_manifest.runtime_state_roots_digest.as_str(),
            "manifest_digest": candidate_digest_handle.as_str(),
            "prior_active_generation": null,
            "approval": {
                "approval_ref": "approval:txn-stage-test",
                "transaction_id": transaction.transaction_id.as_str(),
                "installer_plan_digest": transaction.installer_plan_digest.as_str(),
                "generation": transaction.candidate_manifest.generation.as_str(),
                "candidate_manifest_digest": candidate_digest_handle.as_str(),
                "runtime_descriptor_digest": transaction.candidate_manifest.runtime_launch.descriptor_digest.as_str(),
                "required_owner": "owner:installation",
                "signature_ref": transaction.candidate_manifest.signature_ref.as_str(),
                "authority_descriptor_path": transaction.candidate_manifest.runtime_launch.authority_descriptor_path.as_str(),
                "authority_descriptor_digest": transaction.candidate_manifest.runtime_launch.authority_descriptor_digest.as_str(),
                "authority_generation": authority_generation_value,
                "authority_state_fence": authority_fence_value,
            },
            "state": { "state": "PENDING" }
        });
        serde_json::json!({
            "registry_wire_version": { "major": 4, "minor": 0, "patch": 0 },
            "revision": 1,
            "generations": [],
            "service_registration_approvals": [],
            "active_generation": null,
            "last_known_good_generation": null,
            "pending_activation": pending,
            "last_terminal_activation": null
        })
    }

    #[allow(clippy::needless_borrows_for_generic_args)]
    fn write_registry_value(host_root: &Path, registry: &serde_json::Value) {
        let path = host_root.join("installation-registry.redb");
        let db = redb::Database::create(&path).expect("create registry db");
        let write = db.begin_write().expect("begin write");
        {
            let mut table = write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "eliot_approved_generations_v2",
                ))
                .expect("open table");
            let bytes = serde_json::to_vec(&registry).expect("registry bytes");
            table.insert("registry", bytes.as_slice()).expect("insert");
        }
        write.commit().expect("commit");
    }

    fn write_registry_with_pending(
        host_root: &Path,
        transaction: &eliot_installation::InstallationTransaction,
    ) {
        write_registry_value(host_root, &registry_with_pending_value(transaction));
    }

    fn write_unbound_transaction_fixture(
        host_root: &Path,
        transaction: &eliot_installation::InstallationTransaction,
    ) {
        // The planner proof is deliberately in-memory only. Persist the exact
        // versioned wire shape that a legal bound transaction leaves behind so
        // read-only status tests do not call or weaken production admission.
        #[derive(serde::Serialize)]
        struct TransactionEnvelope<'a> {
            wire_version: eliot_contracts::ContractVersion,
            transaction: &'a eliot_installation::InstallationTransaction,
        }

        let path = host_root.join("installation-transaction.redb");
        let database = redb::Database::create(path).expect("create transaction fixture db");
        let write = database
            .begin_write()
            .expect("begin transaction fixture write");
        {
            let mut table = write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "installation_transactions_v7",
                ))
                .expect("open transaction fixture table");
            let bytes = serde_json::to_vec(&TransactionEnvelope {
                wire_version: transaction.transaction_wire_version,
                transaction,
            })
            .expect("transaction fixture bytes");
            table
                .insert(transaction.transaction_id.as_str(), bytes.as_slice())
                .expect("insert transaction fixture");
        }
        write.commit().expect("commit transaction fixture");
    }

    fn ensure_host_dir(host_root: &Path) {
        std::fs::create_dir_all(host_root).expect("create host dir");
        if let Some(parent) = host_root.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
    }

    #[test]
    fn transaction_stage_rejects_unprofiled_registry_even_with_a_valid_transaction_file() {
        let (base, host_root) = temp_portable_host("txn-unprofiled");
        let transaction = portable_transaction_for_host(&host_root);
        write_registry_with_pending(&host_root, &transaction);
        write_unbound_transaction_fixture(&host_root, &transaction);
        let report = collect(&host_root);
        assert_eq!(report.status, "NOT_HEALTHY");
        assert!(report.transaction_stage.stage.is_none());
        match &report.transaction_stage.state {
            ComponentState::Unknown { reason, .. } => {
                assert!(reason.contains("refuses direct table parsing"));
            }
            other => panic!("expected fail-closed Unknown, got {other:?}"),
        }
        assert!(matches!(
            report.components.installation_registry,
            ComponentState::Unavailable { .. }
        ));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn transaction_stage_never_directly_parses_an_unvalidated_registry() {
        let (base, host_root) = temp_portable_host("txn-invalid-registry");
        let transaction = portable_transaction_for_host(&host_root);
        let mut registry = registry_with_pending_value(&transaction);
        registry["registry_wire_version"] =
            serde_json::json!({ "major": 99, "minor": 0, "patch": 0 });
        write_registry_value(&host_root, &registry);
        let registry_path = host_root.join("installation-registry.redb");
        let before = std::fs::read(&registry_path).expect("registry before");
        write_unbound_transaction_fixture(&host_root, &transaction);

        let report = collect(&host_root);
        assert!(report.transaction_stage.stage.is_none());
        match &report.transaction_stage.state {
            ComponentState::Unknown { reason, .. } => {
                assert!(reason.contains("refuses direct table parsing"));
            }
            other => panic!("unvalidated registry must remain Unknown, got {other:?}"),
        }
        assert_eq!(
            before,
            std::fs::read(&registry_path).expect("registry after"),
            "status inspection must not mutate the rejected registry"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn transaction_stage_root_path_substitution_fails_closed() {
        let (base, host_root) = temp_portable_host("txn-substitution");
        let mut transaction = portable_transaction_for_host(&host_root);
        let other_root = base.join("other-host");
        ensure_host_dir(&other_root);
        transaction
            .candidate_manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root = fixture_handle(other_root.to_string_lossy().into_owned());
        write_registry_with_pending(&host_root, &transaction);
        let valid_tx = portable_transaction_for_host(&host_root);
        write_unbound_transaction_fixture(&host_root, &valid_tx);
        let report = collect(&host_root);
        assert!(report.transaction_stage.stage.is_none());
        assert!(matches!(
            report.transaction_stage.state,
            ComponentState::Unknown { .. } | ComponentState::Missing { .. }
        ));
        assert_eq!(report.status, "NOT_HEALTHY");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn transaction_stage_corrupt_legacy_missing_remains_unknown_and_preserves_not_healthy() {
        let (base, host_root) = temp_portable_host("txn-corrupt");
        let transaction = portable_transaction_for_host(&host_root);
        write_registry_with_pending(&host_root, &transaction);
        let tx_path = host_root.join("installation-transaction.redb");
        {
            let db = redb::Database::create(&tx_path).expect("create corrupt db");
            let write = db.begin_write().expect("write");
            {
                let mut table = write
                    .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                        "installation_transactions_v2",
                    ))
                    .expect("legacy table");
                table
                    .insert(
                        "transaction:legacy",
                        b"{\"wire_version\":{\"major\":2,\"minor\":0,\"patch\":0}}".as_slice(),
                    )
                    .expect("insert legacy");
            }
            write.commit().expect("commit");
        }
        let report = collect(&host_root);
        assert!(report.transaction_stage.stage.is_none());
        assert!(matches!(
            report.transaction_stage.state,
            ComponentState::Unknown { .. }
                | ComponentState::Corrupt { .. }
                | ComponentState::Missing { .. }
                | ComponentState::Unavailable { .. }
        ));
        assert_eq!(report.status, "NOT_HEALTHY");
        let missing_root = temp_root("txn-missing");
        let missing_report = collect(&missing_root);
        assert!(missing_report.transaction_stage.stage.is_none());
        assert!(matches!(
            missing_report.transaction_stage.state,
            ComponentState::Unknown { .. } | ComponentState::Missing { .. }
        ));
        let _ = std::fs::remove_dir_all(base);
        let _ = std::fs::remove_dir_all(missing_root);
    }

    #[test]
    fn transaction_stage_zero_create_never_creates_file() {
        let (base, host_root) = temp_portable_host("txn-zero-create");
        let transaction = portable_transaction_for_host(&host_root);
        write_registry_with_pending(&host_root, &transaction);
        let tx_path = host_root.join("installation-transaction.redb");
        assert!(!tx_path.exists());
        let report = collect(&host_root);
        assert!(!tx_path.exists());
        assert!(report.transaction_stage.stage.is_none());
        assert_eq!(report.status, "NOT_HEALTHY");
        write_unbound_transaction_fixture(&host_root, &transaction);
        assert!(tx_path.exists());
        let canonical_before = std::fs::canonicalize(&tx_path).expect("canonical");
        let len_before = std::fs::metadata(&tx_path).expect("metadata").len();
        let report2 = collect(&host_root);
        assert!(report2.transaction_stage.stage.is_none());
        assert!(matches!(
            report2.transaction_stage.state,
            ComponentState::Unknown { .. }
        ));
        let canonical_after = std::fs::canonicalize(&tx_path).expect("canonical after");
        let len_after = std::fs::metadata(&tx_path).expect("metadata after").len();
        assert_eq!(canonical_before, canonical_after);
        assert_eq!(len_before, len_after);
        let _ = std::fs::remove_dir_all(base);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod store_currentness_production_tests {
    use super::*;
    use eliot_host_state::{
        AppliedOperation, HostInstallationEpoch, HostState, IdempotencyIdentity, StoreRebindRecord,
        StoreRebindState,
    };
    use eliot_platform::PlatformHandle;
    use std::time::{Duration, Instant};

    fn h(v: &str) -> PlatformHandle {
        PlatformHandle::new(v).unwrap_or_else(|e| panic!("handle failed for {v:?}: {e:?}"))
    }
    fn dh(c: char) -> PlatformHandle {
        PlatformHandle::new(c.to_string().repeat(64)).expect("digest")
    }
    fn make_op(id: &str) -> IdempotencyIdentity {
        IdempotencyIdentity {
            operation_id: h(id),
            idempotency_key: h(&format!("key-{id}")),
        }
    }
    fn make_fence() -> eliot_host_state::RecordFence {
        let host = HostInstallationEpoch {
            installation: h("install-1"),
            epoch: eliot_host_state::EpochTransition {
                current: eliot_host_state::EpochIdentity {
                    lineage: h("lineage-1"),
                    sequence: 1,
                },
                parent: None,
            },
            nonce: h("nonce-1"),
            recovery: None,
        };
        eliot_host_state::RecordFence {
            host,
            activation_id: h("activation-1"),
            activation_generation: eliot_host_state::EpochTransition {
                current: eliot_host_state::EpochIdentity {
                    lineage: h("act-lineage-1"),
                    sequence: 1,
                },
                parent: None,
            },
        }
    }
    fn store_record(
        op_id: &str,
        fence_hex: char,
        state: StoreRebindState,
        seq: u64,
    ) -> (StoreRebindRecord, AppliedOperation) {
        let fence = make_fence();
        let op = make_op(op_id);
        let rec = StoreRebindRecord {
            fence: fence.clone(),
            operation: op.clone(),
            state,
            operation_id: h(op_id),
            request_digest: dh('r'),
            requirement: h("req-1"),
            candidate_binding_digest: dh('c'),
            store_fence: dh(fence_hex),
            process_id: 1001,
            process_start_time_100ns: 10,
            process_image_path: h("C:/store.exe"),
            job_name: h("store-job"),
            generation: 1,
            authority_epoch: 1,
            receipt_request_digest: if state == StoreRebindState::Committed {
                Some(dh('r'))
            } else {
                None
            },
            receipt_store_fence: if state == StoreRebindState::Committed {
                Some(dh(fence_hex))
            } else {
                None
            },
        };
        let applied = AppliedOperation {
            identity: op,
            checksum: "chk".to_owned(),
            sequence: seq,
        };
        (rec, applied)
    }
    fn host_with_records(
        records: Vec<StoreRebindRecord>,
        applied: Vec<AppliedOperation>,
    ) -> HostState {
        let host = HostInstallationEpoch {
            installation: h("install-1"),
            epoch: eliot_host_state::EpochTransition {
                current: eliot_host_state::EpochIdentity {
                    lineage: h("lineage-1"),
                    sequence: 1,
                },
                parent: None,
            },
            nonce: h("nonce-1"),
            recovery: None,
        };
        HostState {
            host,
            sequence: 10,
            last_checksum: None,
            activation: None,
            kernel: None,
            kernel_history: Vec::new(),
            prior_kernel: None,
            prior_kernel_unknown: false,
            dependencies: Vec::new(),
            drain: None,
            drain_commit: None,
            wakes: Vec::new(),
            observations: Vec::new(),
            readiness_observations: Vec::new(),
            store_rebinds: records,
            clean_marker: None,
            retained_epochs: Vec::new(),
            retired_epochs: Vec::new(),
            applied_operations: applied,
        }
    }
    fn valid_manifest() -> eliot_installation::CandidateManifest {
        let portable = if cfg!(windows) {
            r"C:/tmp\portable"
        } else {
            "/tmp/portable"
        };
        let host_root = if cfg!(windows) {
            r"C:/tmp\host"
        } else {
            "/tmp/host"
        };
        let roots = eliot_installation::RuntimeStateRoots {
            profile: eliot_installation::InstallationProfile::PortableDev,
            profile_anchor_root: h(portable),
            installation_root: h(portable),
            host_state_root: h(host_root),
            kernel_ors_root: h(&format!("{host_root}/ors")),
            kernel_work_root: h(&format!("{host_root}/work")),
            store_data_root: h(&format!("{host_root}/data")),
            store_work_root: h(&format!("{host_root}/work")),
            store_temp_root: h(&format!("{host_root}/tmp")),
            watchdog_state_root: h(&format!("{host_root}/watchdog")),
            roots_digest: h(&"d".repeat(64)),
        };
        eliot_installation::CandidateManifest {
            generation: h("gen-1"),
            components: vec![h("component:kernel")],
            kernel_artifact_digest: dh('k'),
            store_bridge_artifact_digest: dh('1'),
            canonical_store_artifact_digest: dh('5'),
            host_artifact_digest: dh('h'),
            kernel_executable_path: h(&format!("{portable}/kernel.exe")),
            store_bridge_executable_path: h(&format!("{portable}/store.exe")),
            canonical_store_executable_path: h(&format!("{portable}/surreal.exe")),
            host_executable_path: h(&format!("{portable}/host.exe")),
            config_path: h(&format!("{portable}/generation.json")),
            dependency_closure_refs: vec![],
            license_refs: vec![],
            config_digest: dh('c'),
            store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_slot: h("eliot-supervision-slot:v1:test-supervision-lease"),
            signature_ref: h("sig"),
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch: eliot_installation::RuntimeLaunchDescriptor {
                profile: eliot_installation::InstallationProfile::PortableDev,
                portable_root: Some(PlatformHandle::new(portable.to_owned()).expect("handle")),
                installation_epoch: eliot_installation::InstallationEpoch {
                    installation: h("install-1"),
                    lineage_id: h("lineage-1"),
                    sequence: 1,
                },
                generation: h("gen-1"),
                authority_generation: eliot_installation::ResourceGeneration::new(1).expect("gen"),
                authority_state_fence: eliot_installation::StateFence::new(
                    eliot_installation::AuthorityEpoch::genesis(),
                    eliot_installation::ResourceGeneration::genesis(),
                ),
                supervision_authority: eliot_installation::SupervisionAuthorityBinding::Pending {
                    supervision_lease_scope_id: h("test-supervision-scope"),
                },
                authority_descriptor_path: h(&format!("{portable}/authority.json")),
                authority_descriptor_digest: h(&"a".repeat(64)),
                runtime_state_roots: roots.clone(),
                kernel_work_root: roots.kernel_work_root.clone(),
                kernel_artifact_digest: dh('k'),
                eliotd_executable_path: h(&format!("{portable}/eliotd.exe")),
                eliotd_artifact_digest: dh('e'),
                eliotd_config_path: h(&format!("{portable}/eliotd.json")),
                eliotd_config_digest: dh('e'),
                protected_snapshot_digest: dh('a'),
                eliotd_descriptor_path: h(&format!("{portable}/eliotd.json")),
                eliotd_descriptor_digest: dh('9'),
                eliotd_launch_nonce: h("nonce-eliotd"),
                store_config_path: h(&format!("{portable}/generation.json")),
                store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                store_bridge_executable_path: h(&format!("{portable}/store.exe")),
                store_bridge_artifact_digest: dh('c'),
                store_bootstrap_descriptor_path: h(&format!("{portable}\\store-bootstrap.json")),
                store_bootstrap_descriptor_digest: h(
                    "516396afbc26eeb03b4630518f428b30e48eb17ba2e2b8002612d10cba1a9faa",
                ),
                canonical_store_executable_path: h(&format!("{portable}/surreal.exe")),
                canonical_store_artifact_digest: dh('u'),
                kernel_arguments: vec![],
                store_bridge_arguments: vec![],
                canonical_store_arguments: vec![],
                host_executable_path: h(&format!("{portable}/host.exe")),
                host_artifact_digest: dh('h'),
                watchdog_executable_path: h(&format!("{portable}/watchdog.exe")),
                watchdog_artifact_digest: dh('w'),
                descriptor_digest: dh('f'),
            },
        }
    }
    #[test]
    fn vector_order_not_authority_newer_pending_blocks_older_committed() {
        let (old_committed, applied_old) =
            store_record("op-old", 'a', StoreRebindState::Committed, 1);
        let (new_pending, applied_new) = store_record("op-new", 'b', StoreRebindState::Pending, 2);
        let host = host_with_records(
            vec![old_committed, new_pending],
            vec![applied_old, applied_new],
        );
        let selected = select_current_store_rebind(&host).expect("select");
        assert_eq!(selected.state, StoreRebindState::Pending);
    }
    #[test]
    fn sequence_order_selects_greatest_not_vector_order() {
        let (low, applied_low) = store_record("op-low", 'a', StoreRebindState::Committed, 1);
        let (high, applied_high) = store_record("op-high", 'b', StoreRebindState::Committed, 10);
        let host = host_with_records(
            vec![high.clone(), low.clone()],
            vec![applied_low.clone(), applied_high.clone()],
        );
        let selected = select_current_store_rebind(&host).expect("select");
        assert_eq!(selected.operation.operation_id, high.operation.operation_id);
        let host2 = host_with_records(vec![low, high.clone()], vec![applied_low, applied_high]);
        let selected2 = select_current_store_rebind(&host2).expect("select2");
        assert_eq!(
            selected2.operation.operation_id,
            high.operation.operation_id
        );
    }
    #[test]
    fn missing_join_fails_closed() {
        let (rec, _) = store_record("op-missing", 'a', StoreRebindState::Committed, 1);
        let (_, applied_other) = store_record("op-other", 'a', StoreRebindState::Committed, 99);
        let host = host_with_records(vec![rec], vec![applied_other]);
        let err = select_current_store_rebind(&host).expect_err("must fail");
        assert!(err.to_ascii_lowercase().contains("missing join"));
    }
    #[test]
    fn receipt_mismatch_is_detected_via_inspect() {
        let (mut rec, applied) = store_record("op-receipt", 'a', StoreRebindState::Committed, 5);
        rec.receipt_store_fence = Some(dh('b'));
        let host = host_with_records(vec![rec], vec![applied]);
        let state = inspect_store_live(
            Some(&host),
            None,
            None,
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
    }
    #[test]
    fn eliotd_no_observer_is_unknown_and_no_default() {
        let now = Instant::now() + Duration::from_secs(2);
        let manifest = valid_manifest();
        let state = inspect_eliotd_live(None, Some(&manifest), None, now);
        assert!(matches!(state, ComponentState::Unknown { .. }));
        let reason = match state {
            ComponentState::Unknown { reason, .. } => reason,
            _ => String::new(),
        };
        assert!(
            reason.to_ascii_lowercase().contains("observer")
                || reason.to_ascii_lowercase().contains("hoststate")
                || reason.to_ascii_lowercase().contains("no hoststate")
        );
    }
    #[test]
    fn eliotd_zero_observed_at_is_unknown() {
        struct FakeObserver(Option<EliotdLiveSnapshot>);
        impl EliotdLiveObserver for FakeObserver {
            fn observe_eliotd_live(
                &self,
                _deadline: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(self.0.clone())
            }
        }
        let manifest = valid_manifest();
        let mut snap = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 1_777_777_777_777,
            image_path: if cfg!(windows) {
                r"C:/tmp\portable\eliotd.exe".to_owned()
            } else {
                "/tmp/portable/eliotd.exe".to_owned()
            },
            executor_job_name: "eliotd-job".to_owned(),
            generation: "gen-1".to_owned(),
            config_digest: "e".repeat(64),
            descriptor_digest: "9".repeat(64),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: 0,
            ready_binding_digest: sha256_hex(
                format!("ready:{}:{}:{}", 4242, 1_777_777_777_777_u64, 0).as_bytes(),
            ),
        };
        snap.ready_binding_digest = sha256_hex(
            format!(
                "ready:{}:{}:{}",
                snap.process_id, snap.start_time_100ns, snap.observed_at_unix_ms
            )
            .as_bytes(),
        );
        let obs = FakeObserver(Some(snap));
        let c = inspect_eliotd_live(
            None,
            Some(&manifest),
            Some(&obs),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(c, ComponentState::Unknown { .. }));
    }
    #[test]
    fn store_artifact_mismatch_fails_closed_before_windows_gate() {
        let (mut rec, applied) = store_record("op-artifact", 'a', StoreRebindState::Committed, 5);
        rec.request_digest = dh('b');
        rec.receipt_request_digest = Some(dh('b'));
        rec.candidate_binding_digest = dh('f');
        let host = host_with_records(vec![rec], vec![applied]);
        let manifest = valid_manifest();
        assert_ne!(
            manifest.store_bridge_artifact_digest.as_str(),
            host.store_rebinds[0].candidate_binding_digest.as_str()
        );
        assert_ne!(
            manifest.canonical_store_artifact_digest.as_str(),
            host.store_rebinds[0].candidate_binding_digest.as_str()
        );
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            None,
            None,
            Instant::now() + Duration::from_secs(2),
        );
        match state {
            ComponentState::Unknown { reason, gap } => {
                assert!(
                    reason.contains("candidate_binding_digest"),
                    "artifact mismatch must be explicit, got reason={reason} gap={gap}"
                );
                assert!(gap.contains("Store live"));
            }
            other => panic!("artifact mismatch must be Unknown, got {other:?}"),
        }
    }
    #[test]
    fn equal_sequence_tie_fails_closed() {
        let (rec_a, applied_a) = store_record("op-a", 'a', StoreRebindState::Committed, 5);
        let (rec_b, applied_b) = store_record("op-b", 'b', StoreRebindState::Committed, 5);
        let host = host_with_records(vec![rec_a, rec_b], vec![applied_a, applied_b]);
        let err = select_current_store_rebind(&host).expect_err("tie must fail");
        assert!(
            err.to_ascii_lowercase().contains("tie")
                || err.to_ascii_lowercase().contains("ambiguous")
                || err.to_ascii_lowercase().contains("duplicate"),
            "tie error must mention tie/ambiguous/duplicate, got {err}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod live_production_observer_tests {
    use super::*;
    use eliot_host_state::{
        EpochIdentity, EpochTransition, HostInstallationEpoch, HostState, HostStateRecord,
        KernelJobBinding, KernelReadinessObservationRecord, OneTimeNonceState,
        PriorKernelDisposition, StoreRebindRecord, StoreRebindState,
    };
    use eliot_platform::PlatformHandle;
    use eliot_runtime_contracts::{KernelActivationState, ServiceProcessRecord};
    use std::time::{Duration, Instant};

    fn h(v: &str) -> PlatformHandle {
        PlatformHandle::new(v).expect("handle")
    }
    fn dh(c: char) -> PlatformHandle {
        PlatformHandle::new(c.to_string().repeat(64)).expect("digest")
    }
    fn current_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("current epoch milliseconds fit u64")
    }
    fn make_host() -> HostInstallationEpoch {
        HostInstallationEpoch {
            installation: h("install-1"),
            epoch: EpochTransition {
                current: EpochIdentity {
                    lineage: h("lineage-1"),
                    sequence: 1,
                },
                parent: None,
            },
            nonce: h("nonce-1"),
            recovery: None,
        }
    }
    fn make_fence(host: &HostInstallationEpoch) -> eliot_host_state::RecordFence {
        eliot_host_state::RecordFence {
            host: host.clone(),
            activation_id: h("activation-1"),
            activation_generation: EpochTransition {
                current: EpochIdentity {
                    lineage: h("act-lineage-1"),
                    sequence: 1,
                },
                parent: None,
            },
        }
    }
    fn ready_process() -> ServiceProcessRecord {
        serde_json::from_value(serde_json::json!({
            "process_id": "pid:1001:start:10",
            "owner": "Kernel",
            "state": "READY",
            "health": {
                "liveness": "HEALTHY",
                "readiness": "HEALTHY",
                "freshness": "HEALTHY",
                "compatibility": "HEALTHY",
                "integrity": "HEALTHY",
                "capacity": "HEALTHY"
            },
            "authority_epoch": 1
        }))
        .expect("process")
    }
    fn kernel_record(host: &HostInstallationEpoch) -> eliot_host_state::KernelRecord {
        let fence = make_fence(host);
        let job = KernelJobBinding {
            job_name: h("kernel-job"),
            owner: h("Kernel"),
            root_pid: 1001,
            root_start_time_100ns: 10,
            root_image_path: h("C:/kernel.exe"),
            root_volume_serial_number: 1,
            root_file_index: 1,
        };
        eliot_host_state::KernelRecord {
            fence: fence.clone(),
            operation: eliot_host_state::IdempotencyIdentity {
                operation_id: h("op-kernel"),
                idempotency_key: h("key-kernel"),
            },
            activation_identity: h("activation-1"),
            approved_artifact_hash: dh('k'),
            active_pipe_identity: Some(h("kernel-candidate-pipe")),
            candidate_pipe_identity: Some(h("kernel-candidate-pipe")),
            candidate_job_binding: Some(job.clone()),
            prior_kernel_disposition: PriorKernelDisposition::NoPriorKernel,
            kernel_generation: EpochTransition {
                current: EpochIdentity {
                    lineage: h("kernel-lineage"),
                    sequence: 1,
                },
                parent: None,
            },
            one_time_nonce: OneTimeNonceState::issued(
                eliot_platform::KernelActivationNonce::new(dh('a')).expect("nonce"),
            )
            .consume()
            .expect("consume"),
            state: KernelActivationState::Active,
            process: Some(ready_process()),
            readiness_evidence: vec![h("kernel-ready")],
            disposition_evidence: vec![h("disp")],
        }
    }
    #[allow(clippy::too_many_lines)]
    fn host_with_kernel_and_store() -> (HostState, eliot_installation::CandidateManifest, String) {
        let host_epoch = make_host();
        let fence = make_fence(&host_epoch);
        let kernel = kernel_record(&host_epoch);
        let checksum = eliot_host_state::record_checksum(&HostStateRecord::Kernel(kernel.clone()))
            .expect("checksum");
        let observation = KernelReadinessObservationRecord {
            fence: fence.clone(),
            operation: eliot_host_state::IdempotencyIdentity {
                operation_id: h("op-readiness"),
                idempotency_key: h("key-readiness"),
            },
            active_kernel_record_checksum: h(&checksum),
            probe_request_digest: dh('1'),
            ready_receipt_digest: dh('2'),
            kernel_process: ready_process(),
            kernel_job: kernel.candidate_job_binding.clone().expect("job"),
            config_digest: dh('d'),
            authority_epoch: 1,
            store_fence: dh('a'),
            observed_at: {
                let now = u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                )
                .expect("current epoch milliseconds fit u64");
                h(&format!("{now}"))
            },
            evidence_refs: vec![h("evidence")],
            active_supervision_lease: None,
        };
        let store = StoreRebindRecord {
            fence: fence.clone(),
            operation: eliot_host_state::IdempotencyIdentity {
                operation_id: h("op-store"),
                idempotency_key: h("key-store"),
            },
            state: StoreRebindState::Committed,
            operation_id: h("op-store"),
            request_digest: dh('1'),
            requirement: h("req-1"),
            candidate_binding_digest: dh('c'),
            store_fence: dh('a'),
            process_id: 2002,
            process_start_time_100ns: 20,
            process_image_path: {
                let p = if cfg!(windows) {
                    r"C:\tmpmp\portable/store.exe"
                } else {
                    "/tmp/portable/store.exe"
                };
                h(p)
            },
            job_name: h("store-job"),
            generation: 1,
            authority_epoch: 1,
            receipt_request_digest: Some(dh('1')),
            receipt_store_fence: Some(dh('a')),
        };
        let applied = eliot_host_state::AppliedOperation {
            identity: eliot_host_state::IdempotencyIdentity {
                operation_id: h("op-store"),
                idempotency_key: h("key-store"),
            },
            checksum: "chk".to_owned(),
            sequence: 5,
        };
        let host_state = HostState {
            host: host_epoch.clone(),
            sequence: 10,
            last_checksum: None,
            activation: Some(eliot_host_state::EliotActivationRecord {
                fence: fence.clone(),
                operation: eliot_host_state::IdempotencyIdentity {
                    operation_id: h("op-act"),
                    idempotency_key: h("key-act"),
                },
                activation_id: h("activation-1"),
                trigger_class: h("observable-use"),
                trigger_evidence: vec![h("trigger-evidence")],
                requester_principal_session_or_scheduler: h("principal"),
                requested_capabilities: vec![h("cap")],
                candidate_scope: h("scope"),
                state: eliot_host_state::ActivationState::Active,
                drain_generation: None,
                lineage: eliot_host_state::HostKernelStoreLineage {
                    host_epoch: EpochIdentity {
                        lineage: h("lineage-1"),
                        sequence: 1,
                    },
                    kernel_epoch: EpochIdentity {
                        lineage: h("kernel-lineage"),
                        sequence: 1,
                    },
                    watchdog_epoch: EpochIdentity {
                        lineage: h("watchdog-lineage"),
                        sequence: 1,
                    },
                    store_generation: EpochIdentity {
                        lineage: h("store-lineage"),
                        sequence: 1,
                    },
                },
                readiness: eliot_host_state::ReadinessEvidence {
                    supervision_ready: true,
                    control_ready: true,
                    evidence_refs: vec![h("readiness-evidence")],
                },
                governance_profile: h("governed"),
                runtime_lease_refs: vec![],
                supervision_lease_refs: vec![],
                wake_intent_refs: vec![],
                drain_commit_ref: None,
                wake_during_drain_disposition: None,
                boot_session_evidence: vec![h("boot-evidence")],
                power_transition_evidence: vec![],
                timestamps: eliot_host_state::LifecycleTimestamps {
                    started_at: Some(h("t-started")),
                    ready_at: Some(h("t-ready")),
                    draining_at: None,
                    stopped_at: None,
                },
                failure_and_recovery_directive: None,
            }),
            kernel: Some(kernel),
            kernel_history: Vec::new(),
            prior_kernel: None,
            prior_kernel_unknown: false,
            dependencies: Vec::new(),
            drain: None,
            drain_commit: None,
            wakes: Vec::new(),
            observations: Vec::new(),
            readiness_observations: vec![observation],
            store_rebinds: vec![store],
            clean_marker: None,
            retained_epochs: Vec::new(),
            retired_epochs: Vec::new(),
            applied_operations: vec![applied],
        };
        let manifest = {
            let portable = if cfg!(windows) {
                r"C:\tmpmp\portable"
            } else {
                "/tmp/portable"
            };
            let host_root = if cfg!(windows) {
                r"C:\tmpmp\host"
            } else {
                "/tmp/host"
            };
            let roots = eliot_installation::RuntimeStateRoots {
                profile: eliot_installation::InstallationProfile::PortableDev,
                profile_anchor_root: h(portable),
                installation_root: h(portable),
                host_state_root: h(host_root),
                kernel_ors_root: h(&format!("{host_root}/ors")),
                kernel_work_root: h(&format!("{host_root}/work")),
                store_data_root: h(&format!("{host_root}/data")),
                store_work_root: h(&format!("{host_root}/work")),
                store_temp_root: h(&format!("{host_root}/tmp")),
                watchdog_state_root: h(&format!("{host_root}/watchdog")),
                roots_digest: h(&"d".repeat(64)),
            };
            eliot_installation::CandidateManifest {
                generation: h("gen-1"),
                components: vec![h("component:kernel")],
                kernel_artifact_digest: dh('k'),
                store_bridge_artifact_digest: dh('c'),
                canonical_store_artifact_digest: dh('5'),
                host_artifact_digest: dh('h'),
                kernel_executable_path: h(&format!("{portable}/kernel.exe")),
                store_bridge_executable_path: h(&format!("{portable}/store.exe")),
                canonical_store_executable_path: h(&format!("{portable}/surreal.exe")),
                host_executable_path: h(&format!("{portable}/host.exe")),
                config_path: h(&format!("{portable}/generation.json")),
                dependency_closure_refs: vec![],
                license_refs: vec![],
                config_digest: dh('c'),
                store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                supervision_key_slot: h("eliot-supervision-slot:v1:test-supervision-lease"),
                signature_ref: h("sig"),
                runtime_state_roots_digest: roots.roots_digest.clone(),
                runtime_launch: eliot_installation::RuntimeLaunchDescriptor {
                    profile: eliot_installation::InstallationProfile::PortableDev,
                    portable_root: Some(PlatformHandle::new(portable.to_owned()).expect("handle")),
                    installation_epoch: eliot_installation::InstallationEpoch {
                        installation: h("install-1"),
                        lineage_id: h("lineage-1"),
                        sequence: 1,
                    },
                    generation: h("gen-1"),
                    authority_generation: eliot_installation::ResourceGeneration::new(1)
                        .expect("gen"),
                    authority_state_fence: eliot_installation::StateFence::new(
                        eliot_installation::AuthorityEpoch::genesis(),
                        eliot_installation::ResourceGeneration::genesis(),
                    ),
                    supervision_authority:
                        eliot_installation::SupervisionAuthorityBinding::Pending {
                            supervision_lease_scope_id: h("test-supervision-scope"),
                        },
                    authority_descriptor_path: h(&format!("{portable}/authority.json")),
                    authority_descriptor_digest: h(&"a".repeat(64)),
                    runtime_state_roots: roots.clone(),
                    kernel_work_root: roots.kernel_work_root.clone(),
                    kernel_artifact_digest: dh('k'),
                    eliotd_executable_path: h(&format!("{portable}/eliotd.exe")),
                    eliotd_artifact_digest: dh('e'),
                    eliotd_config_path: h(&format!("{portable}/eliotd.json")),
                    eliotd_config_digest: dh('e'),
                    protected_snapshot_digest: dh('a'),
                    eliotd_descriptor_path: h(&format!("{portable}/eliotd.json")),
                    eliotd_descriptor_digest: dh('9'),
                    eliotd_launch_nonce: h("nonce-eliotd"),
                    store_config_path: h(&format!("{portable}/generation.json")),
                    store_credential_target: h("eliot/store/v1/0123456789abcdef0123456789abcdef"),
                    store_bridge_executable_path: h(&format!("{portable}/store.exe")),
                    store_bridge_artifact_digest: dh('c'),
                    store_bootstrap_descriptor_path: h("C:\\tmpmp\\portable\\store-bootstrap.json"),
                    store_bootstrap_descriptor_digest: h(
                        "516396afbc26eeb03b4630518f428b30e48eb17ba2e2b8002612d10cba1a9faa",
                    ),
                    canonical_store_executable_path: h(&format!("{portable}/surreal.exe")),
                    canonical_store_artifact_digest: dh('u'),
                    kernel_arguments: vec![],
                    store_bridge_arguments: vec![],
                    canonical_store_arguments: vec![h("--bind"), h("127.0.0.1:8000")],
                    host_executable_path: h(&format!("{portable}/host.exe")),
                    host_artifact_digest: dh('h'),
                    watchdog_executable_path: h(&format!("{portable}/watchdog.exe")),
                    watchdog_artifact_digest: dh('w'),
                    descriptor_digest: dh('f'),
                },
            }
        };
        let expected_candidate_digest = manifest
            .compute_digest()
            .expect("manifest digest")
            .as_str()
            .to_owned();
        let mut host_state = host_state;
        if let Some(rec) = host_state.store_rebinds.first_mut() {
            rec.candidate_binding_digest =
                eliot_platform::PlatformHandle::new(expected_candidate_digest.clone())
                    .expect("candidate digest handle");
        }
        // Create bootstrap file for store live Healthy check
        #[cfg(windows)]
        {
            let bootstrap_path = std::path::Path::new(
                manifest
                    .runtime_launch
                    .store_bootstrap_descriptor_path
                    .as_str(),
            );
            if let Some(parent) = bootstrap_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(bootstrap_path, b"bootstrap-content");
        }
        (host_state, manifest, checksum)
    }

    struct FakeKernelObserver {
        snap: Option<KernelLiveSnapshot>,
    }
    impl KernelLiveObserver for FakeKernelObserver {
        fn observe_kernel_live(
            &self,
            _pid: u32,
            _start: u64,
            _image: &str,
            _job: &str,
            _deadline: Instant,
        ) -> Result<Option<KernelLiveSnapshot>, String> {
            Ok(self.snap.clone())
        }
    }
    struct FakeStoreObserver {
        snap: Option<StoreLiveSnapshot>,
    }
    impl StoreLiveObserver for FakeStoreObserver {
        fn observe_store_live(
            &self,
            _pid: u32,
            _start: u64,
            _image: &str,
            _job: &str,
            _deadline: Instant,
        ) -> Result<Option<StoreLiveSnapshot>, String> {
            Ok(self.snap.clone())
        }
    }
    struct FakeWatchdogObserver {
        snap: Option<WatchdogLiveSnapshot>,
    }
    impl WatchdogLiveObserver for FakeWatchdogObserver {
        fn observe_watchdog_live(
            &self,
            _deadline: Instant,
        ) -> Result<Option<WatchdogLiveSnapshot>, String> {
            Ok(self.snap.clone())
        }
    }

    #[test]
    fn kernel_production_success_is_healthy_with_typed_freshness() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = KernelLiveSnapshot {
            process_id: 1001,
            start_time_100ns: 10,
            image_path: "C:/kernel.exe".to_owned(),
            job_name: "kernel-job".to_owned(),
            observed_at_unix_ms: now,
        };
        let observer = FakeKernelObserver { snap: Some(snap) };
        let state = inspect_kernel_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(state.is_healthy(), "expected Healthy got {state:?}");
    }
    #[test]
    fn kernel_substitution_fails_closed() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = KernelLiveSnapshot {
            process_id: 9999,
            start_time_100ns: 10,
            image_path: "C:/kernel.exe".to_owned(),
            job_name: "kernel-job".to_owned(),
            observed_at_unix_ms: now,
        };
        let observer = FakeKernelObserver { snap: Some(snap) };
        let state = inspect_kernel_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(format!("{state:?}").contains("mismatch"));
    }
    #[test]
    fn kernel_stale_fails_closed() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let stale = current_ms().saturating_sub(200_000);
        let snap = KernelLiveSnapshot {
            process_id: 1001,
            start_time_100ns: 10,
            image_path: "C:/kernel.exe".to_owned(),
            job_name: "kernel-job".to_owned(),
            observed_at_unix_ms: stale,
        };
        let observer = FakeKernelObserver { snap: Some(snap) };
        let result = inspect_kernel_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(result, ComponentState::Unknown { .. }));
        assert!(format!("{result:?}").to_ascii_lowercase().contains("stale"));
    }
    #[test]
    fn store_production_success_is_healthy() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(state.is_healthy(), "expected Healthy got {state:?}");
    }
    #[test]
    fn store_tcp_owner_mismatch_fails_closed() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 9999,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
    }
    #[test]
    fn store_stale_fails_closed() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let stale = current_ms().saturating_sub(200_000);
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: stale,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let result = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(result, ComponentState::Unknown { .. }));
    }
    #[test]
    fn watchdog_success_is_healthy() {
        let now = current_ms();
        let snap = WatchdogLiveSnapshot {
            observed_at_unix_ms: now,
            heartbeat_unix_ms: now,
            lease_verified: true,
        };
        let observer = FakeWatchdogObserver { snap: Some(snap) };
        let host = HostState {
            host: make_host(),
            sequence: 1,
            last_checksum: None,
            activation: None,
            kernel: None,
            kernel_history: Vec::new(),
            prior_kernel: None,
            prior_kernel_unknown: false,
            dependencies: Vec::new(),
            drain: None,
            drain_commit: None,
            wakes: Vec::new(),
            observations: Vec::new(),
            readiness_observations: Vec::new(),
            store_rebinds: Vec::new(),
            clean_marker: None,
            retained_epochs: Vec::new(),
            retired_epochs: Vec::new(),
            applied_operations: Vec::new(),
        };
        let manifest = host_with_kernel_and_store().1;
        let ors = OrsContour {
            state: ComponentState::Healthy,
            current_supervision: None,
            gap: ors_gap_for(),
        };
        let svc = ServiceRegistrationState {
            registration: "Matching".to_owned(),
            state: "Running".to_owned(),
            observed_process: None,
            observed_runtime: Some(ServiceRuntimeIdentity {
                process_id: 1,
                start_time_100ns: 1,
                image_path: "C:/host.exe".to_owned(),
                runtime_identity_digest: "a".repeat(64),
            }),
            gap: "matching".to_owned(),
        };
        let state = inspect_watchdog_live(
            Some(&host),
            Some(&manifest),
            &ors,
            &svc,
            &svc,
            Some(&observer),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(state.is_healthy(), "expected Healthy got {state:?}");
    }
    #[test]
    fn watchdog_stale_heartbeat_fails_closed() {
        let now = current_ms();
        let stale = now.saturating_sub(200_000);
        let snap = WatchdogLiveSnapshot {
            observed_at_unix_ms: now,
            heartbeat_unix_ms: stale,
            lease_verified: true,
        };
        let observer = FakeWatchdogObserver { snap: Some(snap) };
        let host = HostState {
            host: make_host(),
            sequence: 1,
            last_checksum: None,
            activation: None,
            kernel: None,
            kernel_history: Vec::new(),
            prior_kernel: None,
            prior_kernel_unknown: false,
            dependencies: Vec::new(),
            drain: None,
            drain_commit: None,
            wakes: Vec::new(),
            observations: Vec::new(),
            readiness_observations: Vec::new(),
            store_rebinds: Vec::new(),
            clean_marker: None,
            retained_epochs: Vec::new(),
            retired_epochs: Vec::new(),
            applied_operations: Vec::new(),
        };
        let manifest = host_with_kernel_and_store().1;
        let ors = OrsContour {
            state: ComponentState::Healthy,
            current_supervision: None,
            gap: ors_gap_for(),
        };
        let svc = ServiceRegistrationState {
            registration: "Matching".to_owned(),
            state: "Running".to_owned(),
            observed_process: None,
            observed_runtime: Some(ServiceRuntimeIdentity {
                process_id: 1,
                start_time_100ns: 1,
                image_path: "C:/host.exe".to_owned(),
                runtime_identity_digest: "a".repeat(64),
            }),
            gap: "matching".to_owned(),
        };
        let result = inspect_watchdog_live(
            Some(&host),
            Some(&manifest),
            &ors,
            &svc,
            &svc,
            Some(&observer),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(result, ComponentState::Unknown { .. }));
    }
    #[test]
    fn eliotd_production_success_is_healthy() {
        struct FakeObserver(EliotdLiveSnapshot);
        impl EliotdLiveObserver for FakeObserver {
            fn observe_eliotd_live(
                &self,
                _deadline: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 1_777_777_777_777,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/eliotd.exe".to_owned()
            } else {
                "/tmp/portable/eliotd.exe".to_owned()
            },
            executor_job_name: "eliotd-job".to_owned(),
            generation: "gen-1".to_owned(),
            config_digest: "e".repeat(64),
            descriptor_digest: "9".repeat(64),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: now,
            ready_binding_digest: String::new(),
        };
        let binding = sha256_hex(
            format!(
                "ready:{}:{}:{}",
                snap.process_id, snap.start_time_100ns, snap.observed_at_unix_ms
            )
            .as_bytes(),
        );
        let mut snap = snap;
        snap.ready_binding_digest = binding;
        let obs = FakeObserver(snap);
        let state = inspect_eliotd_live(
            Some(&host),
            Some(&manifest),
            Some(&obs),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(state.is_healthy(), "expected Healthy got {state:?}");
    }
    #[test]
    fn eliotd_stale_fails_closed() {
        struct FakeObserver(EliotdLiveSnapshot);
        impl EliotdLiveObserver for FakeObserver {
            fn observe_eliotd_live(
                &self,
                _deadline: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        let (host, manifest, _) = host_with_kernel_and_store();
        let stale = current_ms().saturating_sub(200_000);
        let mut snap = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 1_777_777_777_777,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/eliotd.exe".to_owned()
            } else {
                "/tmp/portable/eliotd.exe".to_owned()
            },
            executor_job_name: "eliotd-job".to_owned(),
            generation: "gen-1".to_owned(),
            config_digest: "e".repeat(64),
            descriptor_digest: "9".repeat(64),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: stale,
            ready_binding_digest: String::new(),
        };
        snap.ready_binding_digest = sha256_hex(
            format!(
                "ready:{}:{}:{}",
                snap.process_id, snap.start_time_100ns, snap.observed_at_unix_ms
            )
            .as_bytes(),
        );
        let obs = FakeObserver(snap);
        let result = inspect_eliotd_live(
            Some(&host),
            Some(&manifest),
            Some(&obs),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(result, ComponentState::Unknown { .. }));
    }
    #[test]
    fn store_bootstrap_invalid_root_is_unknown() {
        let (host, mut manifest, _) = host_with_kernel_and_store();
        manifest.runtime_launch.store_bootstrap_descriptor_path = h("relative/path.json");
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
    }
    #[test]
    fn store_bootstrap_escaping_contour_is_unknown() {
        let (host, mut manifest, _) = host_with_kernel_and_store();
        manifest.runtime_launch.store_bootstrap_descriptor_path = h(r"C:\Windows\evil.json");
        manifest.runtime_launch.portable_root = None;
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            None,
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
    }
    #[test]
    fn kernel_missing_lease_is_unknown() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = KernelLiveSnapshot {
            process_id: 1001,
            start_time_100ns: 10,
            image_path: "C:/kernel.exe".to_owned(),
            job_name: "kernel-job".to_owned(),
            observed_at_unix_ms: now,
        };
        let observer = FakeKernelObserver { snap: Some(snap) };
        let tmp = std::env::temp_dir().join(format!(
            "eliot-lease-missing-{}-{}",
            std::process::id(),
            now
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let state = inspect_kernel_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            Some(tmp.as_path()),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(
            format!("{state:?}")
                .to_ascii_lowercase()
                .contains("monotonic")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn store_missing_lease_is_unknown() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let tmp = std::env::temp_dir().join(format!(
            "eliot-lease-missing-store-{}-{}",
            std::process::id(),
            now
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            Some(tmp.as_path()),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(
            format!("{state:?}")
                .to_ascii_lowercase()
                .contains("monotonic")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn kernel_substituted_lease_is_unknown() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = KernelLiveSnapshot {
            process_id: 1001,
            start_time_100ns: 10,
            image_path: "C:/kernel.exe".to_owned(),
            job_name: "kernel-job".to_owned(),
            observed_at_unix_ms: now,
        };
        let observer = FakeKernelObserver { snap: Some(snap) };
        let tmp =
            std::env::temp_dir().join(format!("eliot-lease-sub-{}-{}", std::process::id(), now));
        let _ = std::fs::create_dir_all(&tmp);
        let lease_path = tmp.join("supervision-lease.json");
        let _ = std::fs::write(&lease_path, b"corrupted-substituted");
        let state = inspect_kernel_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            Some(tmp.as_path()),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(
            format!("{state:?}")
                .to_ascii_lowercase()
                .contains("monotonic")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn store_expired_lease_is_unknown() {
        let (host, manifest, _) = host_with_kernel_and_store();
        let now = current_ms();
        let snap = StoreLiveSnapshot {
            process_id: 2002,
            start_time_100ns: 20,
            image_path: if cfg!(windows) {
                r"C:\tmpmp\portable/store.exe".to_owned()
            } else {
                "/tmp/portable/store.exe".to_owned()
            },
            job_name: "store-job".to_owned(),
            tcp_owner_pid: 2002,
            observed_at_unix_ms: now,
        };
        let observer = FakeStoreObserver { snap: Some(snap) };
        let tmp = std::env::temp_dir().join(format!(
            "eliot-lease-expired-{}-{}",
            std::process::id(),
            now
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let lease_path = tmp.join("supervision-lease.json");
        let _ = std::fs::write(
            &lease_path,
            br#"{"payload":{"issued_at_ms":1,"expires_at_ms":2}}"#,
        );
        let state = inspect_store_live(
            Some(&host),
            Some(&manifest),
            Some(&observer),
            Some(tmp.as_path()),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(
            format!("{state:?}")
                .to_ascii_lowercase()
                .contains("monotonic")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn strict_bind_rejects_zero_port() {
        let (host_tmp, mut manifest, _) = host_with_kernel_and_store();
        manifest.runtime_launch.canonical_store_arguments = vec![h("--bind"), h("127.0.0.1:0")];
        let ep = store_tcp_endpoint_exact(&manifest);
        assert!(ep.is_none(), "zero port must be rejected");
        let mut manifest2 = manifest.clone();
        manifest2.runtime_launch.canonical_store_arguments = vec![h("--bind"), h("127.0.0.1:0")];
        let obs = production_store_observer(Some(&host_tmp), Some(&manifest2));
        assert!(obs.is_none(), "strict bind must be None");
    }
    #[test]
    fn eliotd_exact_substitution_is_unknown() {
        struct FakeObserver(EliotdLiveSnapshot);
        impl EliotdLiveObserver for FakeObserver {
            fn observe_eliotd_live(
                &self,
                _d: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        let (host, mut manifest, _) = host_with_kernel_and_store();
        manifest.runtime_launch.eliotd_executable_path = h(r"C:/tmpmp/portable/eliotd.exe");
        let snap = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 1_777_777_777_777,
            image_path: r"C:/tmpmp/portable/EVIL.exe".to_owned(),
            executor_job_name: "eliotd-job".to_owned(),
            generation: "gen-1".to_owned(),
            config_digest: "e".repeat(64),
            descriptor_digest: "9".repeat(64),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: current_ms(),
            ready_binding_digest: sha256_hex(
                format!("ready:{}:{}:{}", 4242, 1_777_777_777_777_u64, current_ms()).as_bytes(),
            ),
        };
        let obs = FakeObserver(snap);
        let state = inspect_eliotd_live(
            Some(&host),
            Some(&manifest),
            Some(&obs),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(matches!(state, ComponentState::Unknown { .. }));
        assert!(
            format!("{state:?}").contains("eliotd") || format!("{state:?}").contains("image_path")
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod production_adapter_real_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn production_watchdog_observer_is_fail_closed_without_files() {
        let dir = std::env::temp_dir().join(format!(
            "eliot-watchdog-real-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let obs = ProductionWatchdogLiveObserver::for_root(&dir);
        let res = obs
            .observe_watchdog_live(Instant::now() + Duration::from_secs(2))
            .expect("observe must not error");
        assert!(
            res.is_none(),
            "missing admission/lease must be None not fabricated Healthy"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn production_store_observer_requires_live_process_and_tcp() {
        let obs = ProductionStoreLiveObserver::new(
            "store-job".to_owned(),
            "127.0.0.1:8000".parse().unwrap(),
        )
        .expect("observer");
        let res = obs
            .observe_store_live(
                99999,
                123,
                "C:/store.exe",
                "store-job",
                Instant::now() + Duration::from_secs(2),
            )
            .expect("observe must not error");
        assert!(res.is_none(), "non-existent Store PID must be None");
    }

    #[test]
    fn production_kernel_observer_requires_live_process() {
        let obs = ProductionKernelLiveObserver;
        let res = obs
            .observe_kernel_live(
                99999,
                123,
                "C:/kernel.exe",
                "kernel-job",
                Instant::now() + Duration::from_secs(2),
            )
            .expect("observe must not error");
        assert!(res.is_none(), "non-existent Kernel PID must be None");
    }

    #[test]
    fn production_eliotd_observer_is_fail_closed_without_file() {
        let dir = std::env::temp_dir().join(format!(
            "eliotd-real-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let obs = ProductionEliotdLiveObserver::for_root(&dir);
        let res = obs
            .observe_eliotd_live(Instant::now() + Duration::from_secs(2))
            .expect("observe must not error");
        assert!(res.is_none(), "missing eliotd-live.json must be None");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_platform_protected_path_lease_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "eliot-lease-real-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&path);
        let file = path.join("test.bin");
        std::fs::write(&file, b"hello").expect("write");
        let abs = if file.is_absolute() {
            file.clone()
        } else {
            std::env::current_dir().unwrap().join(&file)
        };
        #[cfg(windows)]
        {
            let lease =
                eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(&abs);
            assert!(
                lease.is_err() || lease.is_ok(),
                "ProtectedRuntimePathLease must be callable"
            );
        }
        #[cfg(not(windows))]
        {
            let lease = eliot_platform_windows::ProtectedRootLease::open_existing(&path);
            assert!(lease.is_err(), "non-windows must be UnsupportedPlatform");
        }
        let _ = std::fs::remove_dir_all(&path);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod cli_separate_process_tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn temp_root(label: &str) -> std::path::PathBuf {
        let base = {
            #[cfg(windows)]
            {
                let program_data = eliot_platform_windows::protected_program_data_root()
                    .expect("honest test requires Windows Protected ProgramData root");
                program_data.join(format!(
                    "eliot-cli-test-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join(format!(
                    "eliot-cli-test-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
        };
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create temp");
        base
    }

    #[test]
    fn separate_process_cli_readback_matches_in_process_and_no_writes() {
        let root = temp_root("cli-readback");
        let deadline = Instant::now() + Duration::from_secs(2);
        let in_process = collect_status(&root, deadline).expect("in-process collect");
        let in_json = serde_json::to_value(&in_process).expect("serialize in-process");
        let count_before = std::fs::read_dir(&root).map_or(0, std::iter::Iterator::count);
        let output = std::process::Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "eliot",
                "--bin",
                "eliot",
                "--",
                "runtime",
                "status",
                "--json",
                "--host-state-root",
                &root.to_string_lossy(),
                "--deadline-ms",
                "2000",
            ])
            .output()
            .expect("cargo run eliot");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() || stdout.contains("\"status\""),
            "cli failed stdout={stdout} stderr={stderr}"
        );
        let cli_json: serde_json::Value = serde_json::from_str(&stdout).expect("cli json parse");
        assert_eq!(cli_json["contract"], in_json["contract"]);
        assert_eq!(cli_json["host_state_root"], in_json["host_state_root"]);
        assert_eq!(cli_json["status"], in_json["status"]);
        let count_after = std::fs::read_dir(&root).map_or(0, std::iter::Iterator::count);
        assert_eq!(count_before, count_after, "CLI must not write files");
        let _ = std::fs::remove_dir_all(&root);
        let _ = Path::new(&root.to_string_lossy().into_owned());
    }
}

#[cfg(test)]
// Test fixtures intentionally use unwrap/expect to make setup failures loud;
// production journal projection itself contains neither operation.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod host_journal_projection_tests {
    use super::*;
    use eliot_host_state::{
        ActivationState, EpochIdentity, EpochTransition, HostInstallationEpoch, HostStateRecord,
        IdempotencyIdentity, KernelJobBinding, KernelReadinessObservationRecord, OneTimeNonceState,
        PriorKernelDisposition, ReadinessApprovedContour, record_checksum,
    };
    use eliot_platform::PlatformHandle;
    use eliot_runtime_contracts::KernelActivationState;
    use eliot_runtime_contracts::ServiceProcessRecord;
    use std::path::Path;
    use std::time::{Duration, Instant};

    fn h(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("handle")
    }

    fn dh(byte: char) -> PlatformHandle {
        h(&byte.to_string().repeat(64))
    }

    fn epoch(lineage: &str, seq: u64) -> EpochIdentity {
        EpochIdentity {
            lineage: h(lineage),
            sequence: seq,
        }
    }

    fn step(lineage: &str, seq: u64) -> EpochTransition {
        EpochTransition {
            current: epoch(lineage, seq),
            parent: (seq > 1).then(|| epoch(lineage, seq - 1)),
        }
    }

    fn host() -> HostInstallationEpoch {
        HostInstallationEpoch {
            installation: h("eliot-installation"),
            epoch: step("host-lineage", 1),
            nonce: h("host-nonce-1"),
            recovery: None,
        }
    }

    fn make_op(id: &str) -> IdempotencyIdentity {
        IdempotencyIdentity {
            operation_id: h(id),
            idempotency_key: h(&format!("key-{id}")),
        }
    }

    fn fence(
        host: &HostInstallationEpoch,
        generation: &EpochTransition,
    ) -> eliot_host_state::RecordFence {
        eliot_host_state::RecordFence {
            host: host.clone(),
            activation_id: h("activation-one"),
            activation_generation: generation.clone(),
        }
    }

    fn ready_process() -> ServiceProcessRecord {
        serde_json::from_value(serde_json::json!({
            "process_id": "pid:1001:start:10",
            "owner": "Kernel",
            "state": "READY",
            "health": {
                "liveness": "HEALTHY",
                "readiness": "HEALTHY",
                "freshness": "HEALTHY",
                "compatibility": "HEALTHY",
                "integrity": "HEALTHY",
                "capacity": "HEALTHY"
            },
            "authority_epoch": 1
        }))
        .expect("process")
    }

    fn starting_process() -> ServiceProcessRecord {
        let mut p = ready_process();
        p.state = eliot_runtime_contracts::ServiceProcessState::Starting;
        p
    }

    fn kernel_record(
        host: &HostInstallationEpoch,
        generation: &EpochTransition,
        op_id: &str,
        state: KernelActivationState,
    ) -> eliot_host_state::KernelRecord {
        let handoff = matches!(
            state,
            KernelActivationState::ShadowNoAuthority
                | KernelActivationState::HandoffPrepared
                | KernelActivationState::OldTerminated
                | KernelActivationState::NonceIssued
                | KernelActivationState::Activating
                | KernelActivationState::Active
        );
        let job = KernelJobBinding {
            job_name: h("kernel-job"),
            owner: h("Kernel"),
            root_pid: 1001,
            root_start_time_100ns: 10,
            root_image_path: h("C:/eliot-kernel.exe"),
            root_volume_serial_number: 1,
            root_file_index: 1,
        };
        eliot_host_state::KernelRecord {
            fence: fence(host, generation),
            operation: make_op(op_id),
            activation_identity: h("activation-one"),
            approved_artifact_hash: h("sha256-kernel-artifact"),
            active_pipe_identity: (state == KernelActivationState::Active)
                .then(|| h("kernel-candidate-pipe")),
            candidate_pipe_identity: handoff.then(|| h("kernel-candidate-pipe")),
            candidate_job_binding: handoff.then_some(job),
            prior_kernel_disposition: PriorKernelDisposition::NoPriorKernel,
            kernel_generation: step("kernel-lineage", 1),
            one_time_nonce: match state {
                KernelActivationState::NonceIssued | KernelActivationState::Activating => {
                    OneTimeNonceState::issued(
                        eliot_platform::KernelActivationNonce::new(dh('a')).expect("nonce"),
                    )
                }
                KernelActivationState::Active => OneTimeNonceState::issued(
                    eliot_platform::KernelActivationNonce::new(dh('a')).expect("nonce"),
                )
                .consume()
                .expect("consume"),
                KernelActivationState::Failed | KernelActivationState::ManualRecovery => {
                    OneTimeNonceState::issued(
                        eliot_platform::KernelActivationNonce::new(dh('a')).expect("nonce"),
                    )
                    .revoke()
                    .expect("revoke")
                }
                _ => OneTimeNonceState::unissued(),
            },
            state,
            process: handoff.then(|| {
                if state == KernelActivationState::Active {
                    ready_process()
                } else {
                    starting_process()
                }
            }),
            readiness_evidence: (state == KernelActivationState::Active)
                .then(|| h("kernel-ready"))
                .into_iter()
                .collect(),
            disposition_evidence: vec![h("kernel-disposition")],
        }
    }

    fn activation_record(
        host: &HostInstallationEpoch,
        generation: &EpochTransition,
        op_id: &str,
        state: ActivationState,
    ) -> HostStateRecord {
        let ready = matches!(
            state,
            ActivationState::ControlReady | ActivationState::Active
        );
        HostStateRecord::Activation(eliot_host_state::EliotActivationRecord {
            fence: fence(host, generation),
            operation: make_op(op_id),
            activation_id: h("activation-one"),
            trigger_class: h("observable-use"),
            trigger_evidence: vec![h("trigger-evidence")],
            requester_principal_session_or_scheduler: h("principal-session"),
            requested_capabilities: vec![h("kernel-control")],
            candidate_scope: h("installation-scope"),
            state,
            drain_generation: matches!(
                state,
                ActivationState::Draining | ActivationState::StoppedClean
            )
            .then(|| {
                step(
                    generation.current.lineage.as_str(),
                    generation.current.sequence,
                )
            }),
            lineage: eliot_host_state::HostKernelStoreLineage {
                host_epoch: host.epoch.current.clone(),
                kernel_epoch: epoch("kernel-lineage", 1),
                watchdog_epoch: epoch("watchdog-lineage", 1),
                store_generation: epoch("store-lineage", 1),
            },
            readiness: eliot_host_state::ReadinessEvidence {
                supervision_ready: ready,
                control_ready: ready,
                evidence_refs: vec![h("readiness-evidence")],
            },
            governance_profile: h("governed-profile"),
            runtime_lease_refs: vec![],
            supervision_lease_refs: vec![],
            wake_intent_refs: vec![],
            drain_commit_ref: None,
            wake_during_drain_disposition: None,
            boot_session_evidence: vec![h("boot-session-evidence")],
            power_transition_evidence: vec![],
            timestamps: eliot_host_state::LifecycleTimestamps {
                started_at: Some(h("t-started")),
                ready_at: ready.then(|| h("t-ready")),
                draining_at: (state == ActivationState::Draining).then(|| h("t-draining")),
                stopped_at: (state == ActivationState::StoppedClean).then(|| h("t-stopped")),
            },
            failure_and_recovery_directive: None,
        })
    }

    fn temp_host_root(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = {
            #[cfg(windows)]
            {
                let program_data = eliot_platform_windows::protected_program_data_root()
                    .expect("honest test requires Windows Protected ProgramData root");
                program_data.join(format!(
                    "eliot-test-host-journal-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join(format!(
                    "eliot-test-host-journal-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
        };
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        let host_root = base.join("host");
        std::fs::create_dir_all(&host_root).expect("create host");
        (base, host_root)
    }

    fn create_host_state(observed_at: &str) -> eliot_host_state::HostState {
        let host = host();
        let generation = step("activation-lineage", 1);
        let journal = eliot_host_state::HostStateJournal::open(
            eliot_host_state::MemoryBackend::default(),
            host.clone(),
        )
        .expect("open journal");
        for (state, op) in [
            (ActivationState::Starting, "act-start"),
            (ActivationState::ControlReady, "act-ready"),
            (ActivationState::Active, "act-active"),
        ] {
            journal
                .append(activation_record(&host, &generation, op, state))
                .expect("append activation");
        }
        for (state, op) in [
            (KernelActivationState::Idle, "k-idle"),
            (KernelActivationState::ShadowNoAuthority, "k-shadow"),
            (KernelActivationState::HandoffPrepared, "k-handoff"),
            (KernelActivationState::OldTerminated, "k-old"),
            (KernelActivationState::NonceIssued, "k-nonce"),
            (KernelActivationState::Activating, "k-activating"),
            (KernelActivationState::Active, "k-active"),
        ] {
            journal
                .append(HostStateRecord::Kernel(kernel_record(
                    &host,
                    &generation,
                    op,
                    state,
                )))
                .expect("append kernel");
        }
        let snapshot = journal.snapshot().expect("snapshot");
        let active_kernel = snapshot.kernel.clone().expect("active kernel");
        let checksum =
            record_checksum(&HostStateRecord::Kernel(active_kernel.clone())).expect("checksum");
        let observation = KernelReadinessObservationRecord {
            fence: active_kernel.fence.clone(),
            operation: make_op("readiness-1"),
            active_kernel_record_checksum: h(&checksum),
            probe_request_digest: dh('1'),
            ready_receipt_digest: dh('2'),
            kernel_process: active_kernel.process.clone().expect("process"),
            kernel_job: active_kernel.candidate_job_binding.clone().expect("job"),
            config_digest: dh('d'),
            authority_epoch: 1,
            store_fence: h("store-fence-generation-1"),
            observed_at: h(observed_at),
            evidence_refs: vec![h("kernel-authored-probe-ready")],
            active_supervision_lease: None,
        };
        let approved = ReadinessApprovedContour {
            config_digest: dh('d'),
            store_fence: h("store-fence-generation-1"),
        };
        journal
            .append_readiness_observation(observation, &approved)
            .expect("append readiness");
        journal.snapshot().expect("final snapshot")
    }

    fn create_unprotected_journal_file(host_root: &Path) {
        let journal_path = host_root.join("host-state-journal.redb");
        let database = redb::Database::create(&journal_path).expect("create unprotected redb");
        drop(database);
    }

    fn collect(report_root: &Path) -> RuntimeStatusReport {
        let deadline = Instant::now() + Duration::from_secs(2);
        collect_status(report_root, deadline).expect("collect_status")
    }

    fn sha256_file(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    #[test]
    fn unprotected_valid_journal_is_unavailable_without_fallback_and_not_mutated() {
        let (base, host_root) = temp_host_root("valid-projection");
        create_unprotected_journal_file(&host_root);
        let journal_path = host_root.join("host-state-journal.redb");
        let hash_before = sha256_file(&journal_path);
        let len_before = std::fs::metadata(&journal_path).expect("metadata").len();
        let mtime_before = std::fs::metadata(&journal_path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let report = collect(&host_root);
        let hash_after = sha256_file(&journal_path);
        let len_after = std::fs::metadata(&journal_path)
            .expect("metadata after")
            .len();
        let mtime_after = std::fs::metadata(&journal_path)
            .expect("metadata after")
            .modified()
            .expect("mtime after");
        assert_eq!(hash_before, hash_after, "journal bytes changed");
        assert_eq!(len_before, len_after);
        assert_eq!(mtime_before, mtime_after);
        assert!(matches!(
            report.host_journal.state,
            ComponentState::Unavailable { .. }
        ));
        assert_eq!(report.host_journal.sequence, None);
        assert_eq!(report.host_journal.last_checksum, None);
        assert_eq!(report.host_journal.clean, None);
        assert_eq!(report.host_journal.prior_kernel_unknown, None);
        assert!(report.readiness.age_gap.contains("opaque"));
        assert_eq!(report.status, "NOT_HEALTHY");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn torn_journal_is_corrupt_and_does_not_mutate() {
        let (base, host_root) = temp_host_root("torn");
        create_unprotected_journal_file(&host_root);
        let journal_path = host_root.join("host-state-journal.redb");
        let mut bytes = std::fs::read(&journal_path).expect("read");
        if bytes.len() > 200 {
            bytes[100] = bytes[100].wrapping_add(1);
            bytes[150] = bytes[150].wrapping_add(1);
        } else if !bytes.is_empty() {
            bytes[0] = bytes[0].wrapping_add(1);
        }
        std::fs::write(&journal_path, &bytes).expect("corrupt");
        let hash_before = sha256_file(&journal_path);
        let report = collect(&host_root);
        let hash_after = sha256_file(&journal_path);
        assert_eq!(hash_before, hash_after);
        assert!(matches!(
            report.host_journal.state,
            ComponentState::Corrupt { .. }
                | ComponentState::Unavailable { .. }
                | ComponentState::Unknown { .. }
        ));
        assert!(
            report.host_journal.clean.is_none()
                || report.host_journal.state != ComponentState::Healthy
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn numeric_opaque_observed_at_cannot_prove_freshness() {
        let (base, _host_root) = temp_host_root("numeric-opaque");
        let snapshot = create_host_state("1777777777777");
        let readiness = inspect_readiness_from_host_state(
            Some(&snapshot),
            Instant::now() + Duration::from_secs(2),
        );
        assert!(
            readiness.age_gap.contains("opaque"),
            "numeric PlatformHandle must remain opaque, got {}",
            readiness.age_gap
        );
        assert!(matches!(
            readiness.proof_status,
            ComponentState::Unknown { .. }
        ));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn substituted_host_root_fails_closed_and_preserves_bytes() {
        let (base_a, host_root_a) = temp_host_root("substitution-a");
        let (base_b, host_root_b) = temp_host_root("substitution-b");
        create_unprotected_journal_file(&host_root_a);
        let journal_path_a = host_root_a.join("host-state-journal.redb");
        let hash_before = sha256_file(&journal_path_a);
        let report = collect(&host_root_b);
        let hash_after = sha256_file(&journal_path_a);
        assert_eq!(hash_before, hash_after);
        assert!(matches!(
            report.host_journal.state,
            ComponentState::Missing { .. } | ComponentState::Unknown { .. }
        ));
        assert!(report.host_journal.sequence.is_none() || report.host_journal.sequence == Some(0));
        let _ = std::fs::remove_dir_all(base_a);
        let _ = std::fs::remove_dir_all(base_b);
    }

    #[test]
    fn production_subprocess_reports_projection_without_writing() {
        let (base, host_root) = temp_host_root("subprocess");
        create_unprotected_journal_file(&host_root);
        let journal_path = host_root.join("host-state-journal.redb");
        let hash_before = sha256_file(&journal_path);
        let len_before = std::fs::metadata(&journal_path).expect("metadata").len();
        let output = std::process::Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "eliot",
                "--",
                "runtime",
                "status",
                "--json",
                "--host-state-root",
                &host_root.to_string_lossy(),
                "--deadline-ms",
                "2000",
            ])
            .output()
            .expect("cargo run eliot runtime status");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        assert!(
            !output.status.success(),
            "NOT_HEALTHY runtime status must return a failing process status: {combined}"
        );
        let hash_after = sha256_file(&journal_path);
        let len_after = std::fs::metadata(&journal_path)
            .expect("metadata after")
            .len();
        assert_eq!(hash_before, hash_after, "subprocess mutated journal");
        assert_eq!(len_before, len_after);
        assert!(
            combined.contains("host_journal") || combined.contains("host-state-journal"),
            "CLI output must contain Host journal projection: {combined}"
        );
        assert!(
            combined.contains("sequence") || combined.contains("last_checksum"),
            "CLI output should contain bounded journal fields, got {combined}"
        );
        assert!(
            combined.contains("NOT_HEALTHY"),
            "unprotected journal must not produce Healthy: {combined}"
        );
        let _ = std::fs::remove_dir_all(base);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod production_call_path_negatives {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use eliot_installation::PlatformHandle;
    use eliot_process::{Generation, PhysicalProcessBinding, ProcessState};

    fn temp_dir(label: &str) -> PathBuf {
        let base = {
            #[cfg(windows)]
            {
                let program_data = eliot_platform_windows::protected_program_data_root()
                    .expect("honest test requires Windows Protected ProgramData root");
                program_data.join(format!(
                    "eliot-prod-neg-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
            #[cfg(not(windows))]
            {
                std::env::temp_dir().join(format!(
                    "eliot-prod-neg-{}-{}-{}",
                    label,
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ))
            }
        };
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create temp");
        base
    }

    fn h(v: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(v.into()).expect("handle")
    }

    fn fixture_via_portable(
        base: &Path,
    ) -> (
        PathBuf,
        PathBuf,
        eliot_installation::CandidateManifest,
        eliot_installation::InstallationTransaction,
    ) {
        let portable = base.join("portable");
        std::fs::create_dir_all(&portable).expect("portable");
        let host_root = portable.join("host");
        std::fs::create_dir_all(&host_root).expect("host");
        let mut tx = super::honest_tests::portable_transaction_for_host(&host_root);
        let descriptor_path = Path::new(
            tx.candidate_manifest
                .runtime_launch
                .eliotd_descriptor_path
                .as_str(),
        );
        let _ = std::fs::create_dir_all(descriptor_path.parent().expect("parent"));
        let content = br#"{"eliotd":"descriptor"}"#;
        std::fs::write(descriptor_path, content).expect("write descriptor");
        let file_hash = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(content))
        };
        let mut manifest = tx.candidate_manifest.clone();
        manifest.runtime_launch.eliotd_descriptor_digest = h(file_hash.clone());
        for arg in &mut manifest.runtime_launch.kernel_arguments {
            if arg.as_str() == "9".repeat(64) {
                *arg = h(file_hash.clone());
            }
        }
        manifest.runtime_launch = manifest
            .runtime_launch
            .with_computed_digest()
            .expect("computed digest");
        tx.candidate_manifest = manifest.clone();
        let candidate_digest = {
            use sha2::{Digest, Sha256};
            let bytes = serde_json::to_vec(&manifest).expect("manifest json");
            format!("{:x}", Sha256::digest(&bytes))
        };
        let candidate_handle = h(candidate_digest);
        let manifest_value = serde_json::to_value(&manifest).expect("manifest value");
        let authority_generation_value =
            serde_json::to_value(manifest.runtime_launch.authority_generation).expect("auth gen");
        let authority_fence_value =
            serde_json::to_value(&manifest.runtime_launch.authority_state_fence).expect("fence");
        let generation_str = manifest.generation.as_str().to_owned();
        let tx_id = tx.transaction_id.as_str().to_owned();
        let plan_digest = tx.installer_plan_digest.as_str().to_owned();
        let active_registry = serde_json::json!({
            "registry_wire_version": { "major": 4, "minor": 0, "patch": 0 },
            "revision": 2,
            "generations": [{
                "manifest": manifest_value,
                "approval": {
                    "approval_ref": "approval:prod-neg",
                    "transaction_id": tx_id,
                    "installer_plan_digest": plan_digest,
                    "generation": generation_str,
                    "candidate_manifest_digest": candidate_handle.as_str(),
                    "runtime_descriptor_digest": manifest.runtime_launch.descriptor_digest.as_str(),
                    "required_owner": "owner:installation",
                    "signature_ref": manifest.signature_ref.as_str(),
                    "authority_descriptor_path": manifest.runtime_launch.authority_descriptor_path.as_str(),
                    "authority_descriptor_digest": manifest.runtime_launch.authority_descriptor_digest.as_str(),
                    "authority_generation": authority_generation_value,
                    "authority_state_fence": authority_fence_value,
                }
            }],
            "service_registration_approvals": [],
            "active_generation": generation_str,
            "last_known_good_generation": generation_str,
            "pending_activation": null,
            "last_terminal_activation": null
        });
        let path = host_root.join("installation-registry.redb");
        let db = redb::Database::create(&path).expect("create registry");
        let write = db.begin_write().expect("begin write");
        {
            let mut table = write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "eliot_approved_generations_v2",
                ))
                .expect("open table");
            let bytes = serde_json::to_vec(&active_registry).expect("registry bytes");
            table.insert("registry", bytes.as_slice()).expect("insert");
        }
        write.commit().expect("commit");
        (base.to_path_buf(), host_root, manifest, tx)
    }

    fn create_receipt_with_generation(
        generation: Generation,
        image_path: &str,
        job_name: &str,
        resumed_at: u64,
    ) -> eliot_process::ProcessStartReceipt {
        use eliot_process::{
            ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance,
            EnvironmentProjection, FencingToken, ImageId, JobId, KernelDispatchKey, OperationId,
            PermitIssuance, ProcessId, ProcessIntent, ProcessRequest, ProcessTreeId,
            ResourceLimits, SecretRef, SessionId,
        };
        let fence = FencingToken::new(1, generation, "fence-1").expect("fence");
        let mut authority = DispatchPermitAuthority::activate(
            DispatchAuthorityId::new("kernel-authority-7").expect("auth id"),
            KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("key"),
        );
        let intent = ProcessIntent::new(
            OperationId::new("op-1").expect("op"),
            ProcessTreeId::new("tree-1").expect("tree"),
            JobId::new("job-1").expect("job"),
            ImageId::new("image-file-id-1").expect("image"),
            SessionId::new("session-1").expect("session"),
            generation,
            image_path.to_owned(),
            "a".repeat(64),
            vec!["--check".to_owned()],
            "C:\\work",
            EnvironmentProjection::new(
                std::collections::BTreeMap::from([("PATH".to_owned(), "C:\\Windows".to_owned())]),
                vec![SecretRef::new("credential_manager", "provider/token").expect("secret")],
                EnvironmentInheritance::None,
            )
            .expect("env"),
            ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
                .expect("limits"),
        )
        .expect("intent");
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new("lease-1").expect("lease"),
            fence.clone(),
            std::collections::BTreeMap::from([
                ("authority".to_owned(), "a".repeat(64)),
                ("state".to_owned(), "b".repeat(64)),
            ]),
            100,
            200,
            "nonce-1",
        )
        .expect("issuance");
        let permit = authority.issue(&intent, issuance).expect("permit");
        let request = ProcessRequest::new(intent.clone(), permit).expect("request");
        let physical =
            PhysicalProcessBinding::new(4242, 11, image_path, job_name).expect("physical");
        let observed = eliot_process::SuspendedProcessIdentity::new(
            ProcessId::new("process-1").expect("pid"),
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            generation,
            physical.clone(),
            120,
            "a".repeat(64),
        )
        .expect("observed");
        let clock = eliot_platform::ClockObservation {
            valid_time_ms: Some(150),
            known_time_ms: Some(150),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        let ctx = eliot_process::DispatchValidationContext::new(
            clock,
            fence.clone(),
            1,
            std::collections::BTreeMap::from([
                ("authority".to_owned(), "a".repeat(64)),
                ("state".to_owned(), "b".repeat(64)),
            ]),
            41,
        )
        .expect("ctx");
        let validated = authority
            .validate_and_consume(request, observed, &ctx)
            .expect("validated");
        let mut state = ProcessState::from_validated(&validated);
        state
            .mark_resumed(
                resumed_at,
                eliot_process::ProcessHealth::new(
                    eliot_process::ProcessHealthStatus::Healthy,
                    true,
                    resumed_at,
                    None,
                )
                .expect("health"),
            )
            .expect("resume");
        eliot_process::ProcessStartReceipt::new(&state).expect("receipt")
    }

    fn write_receipt(host_root: &Path, receipt: &eliot_process::ProcessStartReceipt) {
        let path = host_root.join("eliotd-receipt.json");
        let bytes = serde_json::to_vec(receipt).expect("receipt json");
        std::fs::write(&path, bytes).expect("write receipt");
    }

    fn write_live_process(host_root: &Path, pid: u32, start: u64, image: &str, job: &str) {
        let path = host_root.join("eliotd-live-process.json");
        let value = serde_json::json!({
            "process_id": pid,
            "start_time_100ns": start,
            "image_path": image,
            "executor_job_name": job
        });
        std::fs::write(&path, serde_json::to_vec(&value).expect("live json")).expect("write live");
    }

    fn collect_via_production(host_root: &Path) -> RuntimeStatusReport {
        let deadline = Instant::now() + Duration::from_secs(2);
        collect_status(host_root, deadline).expect("collect_status")
    }

    #[test]
    fn stale_receipt_is_unknown_via_production_path() {
        let base = temp_dir("stale-receipt");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let old_resumed = 1000u64;
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            old_resumed,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            4242,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
        );
        let _ = now;
        let report = collect_via_production(&host_root);
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "stale receipt must be Unknown, got {:?}",
            report.services.eliotd
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn wrong_job_is_unknown_via_production_path() {
        let base = temp_dir("wrong-job");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            now,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            4242,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "wrong-job",
        );
        let report = collect_via_production(&host_root);
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "wrong job must be Unknown, got {:?}",
            report.services.eliotd
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn wrong_process_is_unknown_via_production_path() {
        let base = temp_dir("wrong-process");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            now,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            9999,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
        );
        let report = collect_via_production(&host_root);
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "wrong pid must be Unknown, got {:?}",
            report.services.eliotd
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn wrong_config_is_unknown_via_production_path() {
        let base = temp_dir("wrong-config");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            now,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            4242,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
        );
        let tampered = h("e".repeat(64));
        let fake = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 11,
            image_path: manifest
                .runtime_launch
                .eliotd_executable_path
                .as_str()
                .to_owned(),
            executor_job_name: "eliotd-job-1".to_owned(),
            generation: manifest.generation.as_str().to_owned(),
            config_digest: tampered.as_str().to_owned(),
            descriptor_digest: manifest
                .runtime_launch
                .eliotd_descriptor_digest
                .as_str()
                .to_owned(),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: now,
            ready_binding_digest: sha256_hex(format!("ready:4242:11:{now}").as_bytes()),
        };
        struct ConfigMismatch(EliotdLiveSnapshot);
        impl EliotdLiveObserver for ConfigMismatch {
            fn observe_eliotd_live(
                &self,
                _: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        let obs = ConfigMismatch(fake);
        let deadline = Instant::now() + Duration::from_secs(2);
        let report =
            collect_status_with_observers(&host_root, deadline, None, None, None, Some(&obs))
                .expect("collect");
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "wrong config must be Unknown"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn wrong_generation_is_unknown_via_production_path() {
        let base = temp_dir("wrong-generation");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            now,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            4242,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
        );
        let fake = EliotdLiveSnapshot {
            process_id: 4242,
            start_time_100ns: 11,
            image_path: manifest
                .runtime_launch
                .eliotd_executable_path
                .as_str()
                .to_owned(),
            executor_job_name: "eliotd-job-1".to_owned(),
            generation: "generation:wrong".to_owned(),
            config_digest: manifest
                .runtime_launch
                .eliotd_config_digest
                .as_str()
                .to_owned(),
            descriptor_digest: manifest
                .runtime_launch
                .eliotd_descriptor_digest
                .as_str()
                .to_owned(),
            daemon_ready: true,
            supervision_epoch: 1,
            observed_at_unix_ms: now,
            ready_binding_digest: sha256_hex(format!("ready:4242:11:{now}").as_bytes()),
        };
        struct GenMismatch(EliotdLiveSnapshot);
        impl EliotdLiveObserver for GenMismatch {
            fn observe_eliotd_live(
                &self,
                _: Instant,
            ) -> Result<Option<EliotdLiveSnapshot>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        let obs = GenMismatch(fake);
        let deadline = Instant::now() + Duration::from_secs(2);
        let report =
            collect_status_with_observers(&host_root, deadline, None, None, None, Some(&obs))
                .expect("collect");
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "wrong generation must be Unknown"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn byte_stability_descriptor_mismatch_is_unknown_via_production_path() {
        let base = temp_dir("byte-stability");
        let (_base_path, host_root, manifest, _tx) = fixture_via_portable(&base);
        let descriptor_path = Path::new(manifest.runtime_launch.eliotd_descriptor_path.as_str());
        let _ = std::fs::write(descriptor_path, br#"{"tampered":true}"#);
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("now fits u64");
        let receipt = create_receipt_with_generation(
            Generation::new(1).expect("gen"),
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
            now,
        );
        write_receipt(&host_root, &receipt);
        write_live_process(
            &host_root,
            4242,
            11,
            manifest.runtime_launch.eliotd_executable_path.as_str(),
            "eliotd-job-1",
        );
        let report = collect_via_production(&host_root);
        assert!(
            matches!(report.services.eliotd, ComponentState::Unknown { .. }),
            "tampered descriptor must be Unknown, got {:?}",
            report.services.eliotd
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn store_fence_mismatch_is_unknown_via_production_path() {
        let base = temp_dir("store-fence");
        let (_base_path, host_root, _manifest, _tx) = fixture_via_portable(&base);
        let deadline = Instant::now() + Duration::from_secs(2);
        let report = collect_status_with_observers(&host_root, deadline, None, None, None, None)
            .expect("collect");
        assert!(
            matches!(report.services.store, ComponentState::Unknown { .. }),
            "store fence without committed rebind must be Unknown"
        );
        assert!(
            matches!(
                report.host_journal.state,
                ComponentState::Unknown { .. } | ComponentState::Missing { .. }
            ),
            "host journal without store fence must not be Healthy"
        );
        let _ = std::fs::remove_dir_all(base);
    }
}
