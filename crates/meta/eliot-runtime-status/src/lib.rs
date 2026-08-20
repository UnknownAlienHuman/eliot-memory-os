#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::sha256_hex;
use eliot_installation::InstallationError;
use eliot_installation::InstallationTransactionStore;
use eliot_runtime_contracts::{
    HealthDimension, SignedSupervisionLease, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionTrustAnchor,
};
use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};

const WATCHDOG_ADMISSION_SCHEMA: &str = "eliot.watchdog-admission.v1";
const WATCHDOG_ADMISSION_LIMIT: u64 = 1024 * 1024;
const SUPERVISION_LEASE_LIMIT: u64 = 1024 * 1024;

/// The installer-owned Watchdog admission projection.  This deliberately
/// mirrors the existing durable schema instead of introducing a status writer
/// or accepting caller-authored trust material.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAdmissionConfig {
    schema: String,
    installation_id: String,
    approved_generation: String,
    trust_anchor: SupervisionTrustAnchor,
    context: SupervisionLeaseVerificationContext,
}

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
pub struct ServiceRegistrationState {
    pub registration: String,
    pub state: String,
    pub observed_process: Option<String>,
    pub gap: String,
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
        match std::fs::symlink_metadata(&tx_path) {
            Ok(m) if m.is_file() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
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
            Ok(_) => {
                return TransactionStageContour {
                    state: ComponentState::Corrupt {
                        reason: "transaction store path is not a regular file".to_owned(),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
            Err(e) => {
                return TransactionStageContour {
                    state: ComponentState::Unavailable {
                        reason: format!("transaction store metadata: {e}"),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
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
        let _keep = (parent_lease, store);
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
        match std::fs::symlink_metadata(&tx_path) {
            Ok(m) if m.is_file() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
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
            Ok(_) => {
                return TransactionStageContour {
                    state: ComponentState::Corrupt {
                        reason: "transaction store path is not a regular file".to_owned(),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
            Err(e) => {
                return TransactionStageContour {
                    state: ComponentState::Unavailable {
                        reason: format!("transaction store metadata: {e}"),
                    },
                    stage: None,
                    gap: transaction_stage_gap(),
                };
            }
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

#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub fn collect_status(
    host_state_root: &Path,
    deadline: Instant,
) -> Result<RuntimeStatusReport, StatusError> {
    check_deadline(deadline)?;
    if !host_state_root.is_absolute() {
        return Err(StatusError::Invalid(
            "host-state-root must be absolute".to_owned(),
        ));
    }
    let metadata = std::fs::symlink_metadata(host_state_root).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StatusError::Unavailable(
                "host-state-root does not exist; status never creates it".to_owned(),
            )
        } else {
            StatusError::Invalid(format!("host-state-root metadata: {e}"))
        }
    })?;
    if !metadata.is_dir() {
        return Err(StatusError::Invalid(
            "host-state-root is not an existing directory".to_owned(),
        ));
    }
    check_deadline(deadline)?;
    let retained_root = eliot_platform_windows::ProtectedRootLease::open_existing(host_state_root)
        .map_err(|e| StatusError::Invalid(format!("retain root: {e}")))?;
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
    let (journal_contour, host_state_for_readiness) =
        inspect_host_journal_retained(&retained_root, &canonical_path, deadline);
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

    let host_service = inspect_service_registration("eliot-host", deadline);
    let watchdog_service = inspect_service_registration("eliot-watchdog", deadline);
    check_deadline(deadline)?;

    let transaction_stage_contour = inspect_transaction_stage(
        &retained_root,
        &canonical_path,
        deadline,
        registry_opt.as_ref(),
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
        g
    };

    let components = ComponentStatuses {
        installation_registry: registry_state.clone(),
        host_journal: journal_contour.state.clone(),
        ors_supervision: ors_contour.state.clone(),
        kernel: ComponentState::Unknown {
            reason: "Kernel live proof unavailable".to_owned(),
            gap: service_gap("Kernel"),
        },
        store: ComponentState::Unknown {
            reason: "Store live proof unavailable".to_owned(),
            gap: service_gap("Store"),
        },
        eliotd: ComponentState::Unknown {
            reason: "eliotd live proof unavailable".to_owned(),
            gap: service_gap("eliotd"),
        },
        watchdog: ComponentState::Unknown {
            reason: "Watchdog live proof unavailable".to_owned(),
            gap: service_gap("Watchdog"),
        },
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
        contract_version: "1.0.0".to_owned(),
        status: overall.to_owned(),
        host_state_root: canonical_path.to_string_lossy().into_owned(),
        active_generation: active_gen,
        last_known_good_generation: lkg_gen,
        generations,
        host_journal: journal_contour,
        ors: ors_contour,
        transaction_stage: transaction_stage_contour,
        services: ServiceContours {
            kernel: ComponentState::Unknown {
                reason: "Kernel live proof unavailable".to_owned(),
                gap: service_gap("Kernel"),
            },
            store: ComponentState::Unknown {
                reason: "Store live proof unavailable".to_owned(),
                gap: service_gap("Store"),
            },
            eliotd: ComponentState::Unknown {
                reason: "eliotd live proof unavailable".to_owned(),
                gap: service_gap("eliotd"),
            },
            watchdog: ComponentState::Unknown {
                reason: "Watchdog live proof unavailable".to_owned(),
                gap: service_gap("Watchdog"),
            },
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

fn readiness_gap() -> String {
    "readiness identity is durable, but KernelReadinessObservationRecord.observed_at is an opaque PlatformHandle; a typed Host-authored timestamp or bounded readiness lease is required before freshness can be proven".to_owned()
}

// Journal inspection is kept as one ordered no-fallback boundary so retained
// root/file leases remain alive through replay and projection.
#[allow(clippy::too_many_lines)]
fn inspect_host_journal_retained(
    retained_root: &eliot_platform_windows::ProtectedRootLease,
    canonical_path: &Path,
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
    match std::fs::symlink_metadata(&journal_path) {
        Ok(m) if m.is_file() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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
        Ok(_) => {
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
        Err(error) => {
            return (
                HostJournalContour {
                    state: ComponentState::Unavailable {
                        reason: format!("journal metadata: {error}"),
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
                    state: ComponentState::Unavailable {
                        reason: "protected host journal disappeared before retained inspection"
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
    let gap = format!(
        "validated host journal seq={sequence} last_checksum={last_checksum:?} clean={clean:?} prior_unknown={prior} active Kernel Consumed"
    );
    let state = ComponentState::Unknown {
        reason: format!("validated host journal Active Kernel Consumed seq={sequence}"),
        gap: gap.clone(),
    };
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

        let admission_path = canonical_path.join("watchdog-admission.json");
        let lease_path = canonical_path.join("supervision-lease.json");
        let admission_file_lease =
            match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                &admission_path,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    return unknown_ors(format!("Watchdog admission file unavailable: {error}"));
                }
            };
        let supervision_file_lease =
            match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                &lease_path,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    return unknown_ors(format!("supervision lease file unavailable: {error}"));
                }
            };
        if !eliot_platform_windows::windows_paths_equal(
            admission_file_lease.path(),
            &admission_path,
        ) || !eliot_platform_windows::windows_paths_equal(
            supervision_file_lease.path(),
            &lease_path,
        ) || admission_file_lease.verify_stable_identity().is_err()
            || admission_file_lease.verify_path_identity().is_err()
            || supervision_file_lease.verify_stable_identity().is_err()
            || supervision_file_lease.verify_path_identity().is_err()
        {
            return unknown_ors(
                "Watchdog admission file identity does not match the retained Host paths",
            );
        }
        let admission_bytes = match admission_file_lease.read_bounded(WATCHDOG_ADMISSION_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) => return unknown_ors(format!("Watchdog admission read failed: {error}")),
        };
        let mut config: RuntimeAdmissionConfig = match serde_json::from_slice(&admission_bytes) {
            Ok(config) => config,
            Err(error) => return unknown_ors(format!("Watchdog admission is corrupt: {error}")),
        };
        if config.schema != WATCHDOG_ADMISSION_SCHEMA {
            return unknown_ors("Watchdog admission schema is unsupported");
        }
        if config.trust_anchor.validate().is_err() {
            return unknown_ors("Watchdog admission trust anchor is invalid");
        }
        let mut shape_context = config.context.clone();
        shape_context.now_ms = 1;
        if shape_context.validate().is_err() {
            return unknown_ors("Watchdog admission verification context is invalid");
        }
        let expected_installation = manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str();
        if config.installation_id != expected_installation
            || config.trust_anchor.installation_id != expected_installation
        {
            return unknown_ors("Watchdog admission installation identity is not manifest-bound");
        }
        if config.approved_generation != manifest.generation.as_str() {
            return unknown_ors(
                "Watchdog admission generation is not the active manifest generation",
            );
        }
        if !is_sha256_hex(manifest.config_digest.as_str())
            || sha256_hex(&admission_bytes) != manifest.config_digest.as_str()
        {
            return unknown_ors(
                "Watchdog admission bytes do not match the active manifest config digest",
            );
        }
        let expected_fingerprint = manifest.supervision_key_fingerprint.as_str();
        if config.trust_anchor.public_key_fingerprint() != expected_fingerprint
            || config.context.public_key_fingerprint != expected_fingerprint
        {
            return unknown_ors(
                "Watchdog admission trust fingerprint is not the active manifest fingerprint",
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
        config.context.now_ms = now_ms;
        if let Err(error) = config.context.validate() {
            return unknown_ors(format!(
                "current ORS verification context is invalid: {error}"
            ));
        }
        let supervision_bytes = match supervision_file_lease.read_bounded(SUPERVISION_LEASE_LIMIT) {
            Ok(bytes) => bytes,
            Err(error) => return unknown_ors(format!("supervision lease read failed: {error}")),
        };
        let envelope: SignedSupervisionLease = match serde_json::from_slice(&supervision_bytes) {
            Ok(envelope) => envelope,
            Err(error) => return unknown_ors(format!("supervision lease is corrupt: {error}")),
        };
        if let Err(error) = config.trust_anchor.verify(&envelope, &config.context) {
            return unknown_ors(format!("supervision lease verification failed: {error}"));
        }
        if Instant::now() >= deadline {
            return unknown_ors("deadline exceeded before authoritative ORS status observation");
        }
        let database = match eliot_ors::open_existing_read_only(ors_file_lease.path()) {
            Ok(database) => database,
            Err(error) => {
                return unknown_ors(format!("manifest-bound ORS database open failed: {error}"));
            }
        };
        let read = match database.begin_read() {
            Ok(read) => read,
            Err(error) => return unknown_ors(format!("manifest-bound ORS read failed: {error}")),
        };
        drop(read);
        let projection = match eliot_ors::observe_supervision_status(
            ors_file_lease.path(),
            &config.trust_anchor,
            &config.context,
        ) {
            Ok(projection) => projection,
            Err(error) => {
                return unknown_ors(format!("authoritative ORS status unavailable: {error}"));
            }
        };
        if retained_root.verify_stable_identity().is_err()
            || ors_root_lease.verify_stable_identity().is_err()
            || ors_file_lease.verify_stable_identity().is_err()
            || ors_file_lease.verify_path_identity().is_err()
            || admission_file_lease.verify_stable_identity().is_err()
            || admission_file_lease.verify_path_identity().is_err()
            || supervision_file_lease.verify_stable_identity().is_err()
            || supervision_file_lease.verify_path_identity().is_err()
        {
            return unknown_ors("a retained ORS/admission identity changed during observation");
        }
        let _keep_leases = (
            ors_root_lease,
            ors_file_lease,
            admission_file_lease,
            supervision_file_lease,
            database,
        );
        let state = if projection.health == HealthDimension::Healthy {
            ComponentState::Healthy
        } else {
            ComponentState::Unknown {
                reason: format!(
                    "authoritative ORS projection is {:?} ({:?})",
                    projection.health, projection.reason
                ),
                gap: ors_gap(),
            }
        };
        OrsContour {
            state,
            gap: ors_gap(),
        }
    }
}

fn inspect_service_registration(name: &str, deadline: Instant) -> ServiceRegistrationState {
    if Instant::now() >= deadline {
        return ServiceRegistrationState {
            registration: "Unknown".to_owned(),
            state: "Unknown".to_owned(),
            observed_process: None,
            gap: "deadline exceeded before service inspection".to_owned(),
        };
    }
    #[cfg(windows)]
    {
        read_service_registration_windows(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        ServiceRegistrationState {
            registration: "Unknown".to_owned(),
            state: "Unknown".to_owned(),
            observed_process: None,
            gap: service_gap(name),
        }
    }
}

#[cfg(windows)]
fn read_service_registration_windows(name: &str) -> ServiceRegistrationState {
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    ) {
        Ok(m) => m,
        Err(e) => {
            return ServiceRegistrationState {
                registration: "Unknown".to_owned(),
                state: "Unknown".to_owned(),
                observed_process: None,
                gap: format!("SCM connect failed for {name}: {e}"),
            };
        }
    };
    let service = match manager.open_service(
        name,
        windows_service::service::ServiceAccess::QUERY_STATUS
            | windows_service::service::ServiceAccess::QUERY_CONFIG,
    ) {
        Ok(s) => s,
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            if msg.contains("does not exist") || msg.contains("not found") {
                return ServiceRegistrationState {
                    registration: "Absent".to_owned(),
                    state: "Absent".to_owned(),
                    observed_process: None,
                    gap: format!("service {name} not registered"),
                };
            }
            return ServiceRegistrationState {
                registration: "Unknown".to_owned(),
                state: "Unknown".to_owned(),
                observed_process: None,
                gap: format!("open service {name} failed: {e}"),
            };
        }
    };
    let config = match service.query_config() {
        Ok(c) => c,
        Err(e) => {
            return ServiceRegistrationState {
                registration: "Unknown".to_owned(),
                state: "Unknown".to_owned(),
                observed_process: None,
                gap: format!("query config {name} failed: {e}"),
            };
        }
    };
    let status = match service.query_status() {
        Ok(s) => s,
        Err(e) => {
            return ServiceRegistrationState {
                registration: "Unknown".to_owned(),
                state: "Unknown".to_owned(),
                observed_process: None,
                gap: format!("query status {name} failed: {e}"),
            };
        }
    };
    let state_str = format!("{:?}", status.current_state);
    let binary = config.executable_path.to_string_lossy().into_owned();
    ServiceRegistrationState {
        registration: "Present".to_owned(),
        state: state_str,
        observed_process: Some(binary),
        gap: service_gap(name),
    }
}

pub fn service_gap_for(name: &str) -> String {
    service_gap(name)
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
                    .unwrap_or_else(|_| std::env::temp_dir());
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
            let program_data = eliot_platform_windows::protected_program_data_root()
                .unwrap_or_else(|_| std::env::temp_dir());
            program_data.join(format!(
                "eliot-rt-txn-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
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
        assert_eq!(report.contract_version, "1.0.0");
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

    // This fixture deliberately materializes the complete immutable installer
    // contour so projection tests exercise the production wire shape.
    #[allow(clippy::too_many_lines)]
    fn portable_transaction_for_host(
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
            authority_descriptor_path: fixture_path(&portable_root, "authority.json"),
            authority_descriptor_digest: fixture_handle("7".repeat(64)),
            runtime_state_roots: runtime_state_roots.clone(),
            kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
            kernel_artifact_digest: fixture_handle("0".repeat(64)),
            eliotd_executable_path: fixture_path(&portable_root, "eliotd.exe"),
            eliotd_artifact_digest: fixture_handle("8".repeat(64)),
            eliotd_config_path: fixture_path(&portable_root, "eliotd-governor.json"),
            eliotd_config_digest: fixture_handle("4".repeat(64)),
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
            store_bootstrap_descriptor_digest: fixture_handle("6".repeat(64)),
            canonical_store_executable_path: fixture_path(&portable_root, "surreal.exe"),
            canonical_store_artifact_digest: fixture_handle("5".repeat(64)),
            kernel_arguments: vec![
                fixture_handle("--work-root"),
                runtime_state_roots.kernel_work_root.clone(),
                fixture_handle("--store-bootstrap"),
                fixture_path(&portable_root, "store-bootstrap.json"),
                fixture_handle("--store-bootstrap-sha256"),
                fixture_handle("6".repeat(64)),
                fixture_handle("--authority-descriptor"),
                fixture_path(&portable_root, "authority.json"),
                fixture_handle("--authority-descriptor-sha256"),
                fixture_handle("7".repeat(64)),
                fixture_handle("--kernel-artifact-sha256"),
                fixture_handle("0".repeat(64)),
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
            descriptor_digest: fixture_handle("0".repeat(64)),
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
            kernel_artifact_digest: fixture_handle("0".repeat(64)),
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
            supervision_key_fingerprint: fixture_handle("3".repeat(64)),
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
        eliot_installation::InstallationTransaction::new(
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
        let tx_path = host_root.join("installation-transaction.redb");
        eliot_installation::RedbInstallationTransactionStore::create_planned_at_exact_path(
            &tx_path,
            &transaction,
        )
        .expect("create transaction store");
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
        let tx_path = host_root.join("installation-transaction.redb");
        eliot_installation::RedbInstallationTransactionStore::create_planned_at_exact_path(
            &tx_path,
            &transaction,
        )
        .expect("create transaction store");

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
        let tx_path = host_root.join("installation-transaction.redb");
        let valid_tx = portable_transaction_for_host(&host_root);
        eliot_installation::RedbInstallationTransactionStore::create_planned_at_exact_path(
            &tx_path, &valid_tx,
        )
        .expect("create store");
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
        eliot_installation::RedbInstallationTransactionStore::create_planned_at_exact_path(
            &tx_path,
            &transaction,
        )
        .expect("create");
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
                    .unwrap_or_else(|_| std::env::temp_dir());
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
