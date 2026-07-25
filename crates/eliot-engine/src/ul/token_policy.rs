use crate::EngineError;
use eliot_store::CanonicalStore;
use eliot_types::{
    MaterialPacketFrame, ProjectId, TaskContract, TaskId, UlExperimentArm, UlInjectionMode,
    UlTaskClass, UlTaskClassPolicy, UlTaskExperimentAssignment, UlTaskLedger,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const MIN_CONTROL_TASKS: usize = 5;
const MIN_TREATMENT_TASKS: usize = 10;

pub struct UlTokenPolicyService {
    store: CanonicalStore,
    runtime_root: Option<PathBuf>,
}

impl UlTokenPolicyService {
    #[must_use]
    pub const fn new(store: CanonicalStore) -> Self {
        Self {
            store,
            runtime_root: None,
        }
    }

    #[must_use]
    pub fn with_runtime_root(store: CanonicalStore, runtime_root: &Path) -> Self {
        Self {
            store,
            runtime_root: Some(runtime_root.to_path_buf()),
        }
    }

    #[must_use]
    pub fn classify(
        task: Option<&TaskContract>,
        frame: Option<&MaterialPacketFrame>,
        resolved_concept_ids: &[String],
        touched_paths: &[String],
    ) -> UlTaskClass {
        let normalized_paths = touched_paths
            .iter()
            .map(|path| {
                path.replace('\\', "/")
                    .trim_start_matches("./")
                    .to_ascii_lowercase()
            })
            .filter(|path| !path.is_empty())
            .collect::<BTreeSet<_>>();
        let concepts = resolved_concept_ids
            .iter()
            .map(|concept| concept.trim())
            .filter(|concept| !concept.is_empty())
            .collect::<BTreeSet<_>>();
        let action_class = if frame.is_none() {
            "read_only"
        } else if normalized_paths.len() > 4 || concepts.len() >= 2 {
            "cross_subsystem"
        } else if normalized_paths.len() <= 1 {
            "single_file"
        } else {
            "multi_file"
        };
        let subsystem = concepts
            .iter()
            .next()
            .map_or_else(|| "unknown".to_owned(), |concept| (*concept).to_owned());
        let artifact_classes = normalized_paths
            .iter()
            .map(|path| artifact_class(path))
            .collect::<BTreeSet<_>>();
        let artifact_class = if artifact_classes.len() > 1 {
            "mixed"
        } else {
            artifact_classes.iter().next().copied().unwrap_or("other")
        };
        let _ = task;
        UlTaskClass {
            action_class: action_class.to_owned(),
            subsystem,
            artifact_class: artifact_class.to_owned(),
        }
    }

    pub async fn assignment(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        task_class: &UlTaskClass,
        config_hash: &str,
    ) -> Result<UlTaskExperimentAssignment, EngineError> {
        self.store
            .assign_ul_experiment_arm(project_id, task_id, task_class, config_hash)
            .await
            .map_err(Into::into)
    }

    pub async fn load_assignment(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> Result<Option<UlTaskExperimentAssignment>, EngineError> {
        self.store
            .load_ul_experiment_assignment(project_id, task_id)
            .await
            .map_err(Into::into)
    }

    pub async fn effective_mode(
        &self,
        assignment: &UlTaskExperimentAssignment,
    ) -> Result<Option<UlInjectionMode>, EngineError> {
        if assignment.arm == UlExperimentArm::Control {
            return Ok(None);
        }
        let policy = self
            .store
            .load_ul_task_class_policy(assignment.project_id, &assignment.task_class.key())
            .await?;
        Ok(Some(policy.map_or(assignment.injection_mode, |policy| {
            policy.injection_mode
        })))
    }

    pub async fn evaluate_and_persist(
        &self,
        project_id: ProjectId,
        task_class_key: &str,
    ) -> Result<Option<UlTaskClassPolicy>, EngineError> {
        let current = self
            .store
            .load_ul_task_class_policy(project_id, task_class_key)
            .await?;
        let ledgers = self
            .store
            .load_ul_task_class_ledgers(project_id, task_class_key)
            .await?;
        let Some(policy) =
            Self::evaluate_policy(current.as_ref(), project_id, task_class_key, &ledgers)
        else {
            return Ok(None);
        };
        if current.as_ref() != Some(&policy) {
            self.store.upsert_ul_task_class_policy(&policy).await?;
        }
        if let Some(runtime_root) = &self.runtime_root {
            Self::write_downgrade_report(runtime_root, &policy)?;
        }
        Ok(Some(policy))
    }

    pub fn write_downgrade_report(
        runtime_root: &Path,
        policy: &UlTaskClassPolicy,
    ) -> Result<PathBuf, EngineError> {
        let date = OffsetDateTime::now_utc().date();
        let class_hash = blake3::hash(policy.task_class_key.as_bytes())
            .to_hex()
            .to_string();
        let report_id = format!(
            "UL-DOWNGRADE-{}-{:04}{:02}{:02}",
            &class_hash[..16],
            date.year(),
            u8::from(date.month()),
            date.day()
        );
        let report_dir = runtime_root.join("reports").join("ul-token-policy");
        fs::create_dir_all(&report_dir)?;
        let report_path = report_dir.join(format!("{report_id}.json"));
        if report_path.is_file() {
            return Ok(report_path);
        }
        let payload = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "eliot-ul-token-policy-downgrade-v1",
            "report_id": report_id,
            "project_id": policy.project_id,
            "task_class_key": policy.task_class_key,
            "injection_mode": policy.injection_mode,
            "control_tasks": policy.control_tasks,
            "treatment_tasks": policy.treatment_tasks,
            "control_median_exploration_tokens": policy.control_median_exploration_tokens,
            "treatment_median_net_delta": policy.treatment_median_net_delta,
            "reason": policy.reason,
            "evidence_task_ids": policy.evidence_task_ids,
        }))?;
        let temporary_path = report_dir.join(format!(".{report_id}.{}.tmp", std::process::id()));
        fs::write(&temporary_path, payload)?;
        match fs::rename(&temporary_path, &report_path) {
            Ok(()) => Ok(report_path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists && report_path.is_file() => {
                let _ = fs::remove_file(&temporary_path);
                Ok(report_path)
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary_path);
                Err(error.into())
            }
        }
    }

    #[must_use]
    pub fn evaluate_policy(
        current: Option<&UlTaskClassPolicy>,
        project_id: ProjectId,
        task_class_key: &str,
        ledgers: &[UlTaskLedger],
    ) -> Option<UlTaskClassPolicy> {
        if let Some(current) = current
            && current.injection_mode == UlInjectionMode::HandlesOnly
        {
            return Some(current.clone());
        }
        let completed = ledgers
            .iter()
            .filter(|ledger| {
                ledger.project_id == project_id
                    && ledger.task_class_key == task_class_key
                    && ledger.first_mutation_seen
            })
            .collect::<Vec<_>>();
        let controls = completed
            .iter()
            .filter(|ledger| ledger.arm == Some(UlExperimentArm::Control))
            .copied()
            .collect::<Vec<_>>();
        let treatments = completed
            .iter()
            .filter(|ledger| ledger.arm == Some(UlExperimentArm::Treatment))
            .copied()
            .collect::<Vec<_>>();
        if controls.len() < MIN_CONTROL_TASKS || treatments.len() < MIN_TREATMENT_TASKS {
            return None;
        }
        let control_median = median_u64(
            controls
                .iter()
                .map(|ledger| ledger.exploration_tokens)
                .collect(),
        );
        let treatment_median = median_i64(
            treatments
                .iter()
                .map(|ledger| ledger.net_token_delta)
                .collect(),
        );
        if treatment_median <= 0 {
            return None;
        }
        let mut evidence_task_ids = completed
            .iter()
            .map(|ledger| ledger.task_id)
            .collect::<Vec<_>>();
        evidence_task_ids.sort();
        evidence_task_ids.dedup();
        Some(UlTaskClassPolicy {
            project_id,
            task_class_key: task_class_key.to_owned(),
            injection_mode: UlInjectionMode::HandlesOnly,
            treatment_tasks: u32::try_from(treatments.len()).unwrap_or(u32::MAX),
            control_tasks: u32::try_from(controls.len()).unwrap_or(u32::MAX),
            control_median_exploration_tokens: control_median,
            treatment_median_net_delta: treatment_median,
            reason: "positive_median_net_token_delta".to_owned(),
            evidence_task_ids,
        })
    }
}

fn artifact_class(path: &str) -> &'static str {
    let extension = path.rsplit('.').next().unwrap_or_default();
    match extension {
        "rs" | "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "cs" | "go" | "java" | "kt" | "kts"
        | "swift" | "js" | "jsx" | "ts" | "tsx" | "lua" => "code",
        "toml" | "json" | "yaml" | "yml" | "lock" => "config",
        "md" | "rst" | "txt" => "docs",
        _ => "other",
    }
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn median_i64(mut values: Vec<i64>) -> i64 {
    values.sort_unstable();
    values[values.len() / 2]
}
