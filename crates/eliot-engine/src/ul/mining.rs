use super::injection::deterministic_write_id;
use crate::codecortex::run_process;
use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::{
    AgentId, CoChangeEdge, CommandContext, FIX_CLASSIFIER_VERSION, HotspotScore, LifecycleStatus,
    MiningConfig, MiningRun, ProjectId, RelationInput, RelationType, SemanticCommand, TaintClass,
    UlArtifact, UlArtifactBatchRecordCommand, Visibility, WriteReceipt, normalize_path,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const GIT_MARKER: &str = "@@ELIOT@@";
const SECONDS_PER_DAY: f64 = 86_400.0;
const DAYS_PER_MONTH: i64 = 30;
const HOTSPOT_HALF_LIFE_DAYS: f64 = 90.0;
const FIX_KEYWORDS: &[&str] = &[
    "fix",
    "bug",
    "hotfix",
    "patch",
    "revert",
    "regression",
    "repair",
    "исправ",
    "фикс",
    "чин",
    "баг",
    "откат",
];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GitMiningArtifacts {
    pub run: MiningRun,
    pub edges: Vec<CoChangeEdge>,
    pub hotspots: Vec<HotspotScore>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitMiningStatus {
    Written,
    Noop,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UlArtifactWriteReport {
    pub artifacts_written: usize,
    pub relations_written: usize,
    pub receipts: Vec<WriteReceipt>,
}

#[derive(Clone, Debug)]
pub struct GitMiningService {
    config: MiningConfig,
}

impl Default for GitMiningService {
    fn default() -> Self {
        Self::new(MiningConfig::default())
    }
}

impl GitMiningService {
    #[must_use]
    pub const fn new(config: MiningConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn config(&self) -> &MiningConfig {
        &self.config
    }

    pub fn config_hash(&self) -> Result<String, EngineError> {
        let material = json!({
            "config": self.config,
            "classifier_version": FIX_CLASSIFIER_VERSION,
        });
        Ok(blake3::hash(&serde_json::to_vec(&material)?)
            .to_hex()
            .to_string())
    }

    pub fn mine(
        &self,
        project_id: ProjectId,
        root: &Path,
        failure_density: &BTreeMap<String, u32>,
    ) -> Result<GitMiningArtifacts, EngineError> {
        self.validate_config()?;
        let root_text = root.to_str().ok_or_else(|| {
            EngineError::WriteRejected("repository root is not valid UTF-8".to_owned())
        })?;
        let max_commits = self.config.max_commits.to_string();
        let args = [
            "-C",
            root_text,
            "log",
            "--no-merges",
            "--date=unix",
            "--pretty=format:@@ELIOT@@%H%x1f%an%x1f%ad%x1f%s",
            "--name-only",
            "-n",
            max_commits.as_str(),
        ];
        let output = run_process(root, "git", &args)?;
        if !output.status {
            return Err(EngineError::ServiceNotReady {
                service: "git-mining".to_owned(),
                reason: format!(
                    "git log failed with exit {:?}: {}",
                    output.code,
                    output.stderr.trim()
                ),
            });
        }
        self.mine_history(project_id, &output.stdout, failure_density)
    }

    pub fn mine_history(
        &self,
        project_id: ProjectId,
        history: &str,
        failure_density: &BTreeMap<String, u32>,
    ) -> Result<GitMiningArtifacts, EngineError> {
        self.validate_config()?;
        let commits = parse_history(history, self.config.max_files_per_basket)?;
        let head_commit = commits
            .first()
            .map(|commit| commit.hash.clone())
            .ok_or_else(|| EngineError::WriteRejected("git history has no commits".to_owned()))?;
        let commits_scanned = count_u32(commits.len());
        let reference_unix = commits
            .iter()
            .map(|commit| commit.timestamp)
            .max()
            .unwrap_or_default();
        let window_seconds = i64::from(self.config.window_months)
            .saturating_mul(DAYS_PER_MONTH)
            .saturating_mul(86_400);
        let cutoff = reference_unix.saturating_sub(window_seconds);
        let baskets = merge_baskets(
            commits,
            cutoff,
            self.config.author_merge_seconds,
            self.config.max_files_per_basket,
        );
        let config_hash = self.config_hash()?;
        let run_id = deterministic_artifact_id(
            "mining-run",
            &[&project_id.to_string(), &head_commit, &config_hash],
        );

        let (touches, pair_counts) = mining_counts(&baskets);
        let edges = build_edges(
            project_id,
            &head_commit,
            &config_hash,
            &run_id,
            &self.config,
            &touches,
            pair_counts,
        );
        let hotspots = build_hotspots(
            project_id,
            &head_commit,
            &config_hash,
            &run_id,
            reference_unix,
            &touches,
            failure_density,
        );

        Ok(GitMiningArtifacts {
            run: MiningRun {
                run_id,
                project_id,
                head_commit,
                config_hash,
                commits_scanned,
                baskets_used: count_u32(baskets.len()),
                edges_written: count_u32(edges.len()),
                classifier_version: FIX_CLASSIFIER_VERSION.to_owned(),
                cue_bindings: Vec::new(),
            },
            edges,
            hotspots,
        })
    }

    #[must_use]
    pub fn is_noop(&self, artifacts: &GitMiningArtifacts, existing: Option<&MiningRun>) -> bool {
        existing.is_some_and(|run| {
            run.run_id == artifacts.run.run_id
                && run.project_id == artifacts.run.project_id
                && run.head_commit == artifacts.run.head_commit
                && run.config_hash == artifacts.run.config_hash
        })
    }

    fn validate_config(&self) -> Result<(), EngineError> {
        if self.config.max_commits == 0
            || self.config.window_months == 0
            || self.config.author_merge_seconds < 0
            || self.config.max_files_per_basket < 2
            || self.config.max_files_per_basket > 30
            || self.config.min_support == 0
            || !(0.0..=1.0).contains(&self.config.min_confidence)
        {
            return Err(EngineError::WriteRejected(
                "invalid Git mining configuration".to_owned(),
            ));
        }
        Ok(())
    }
}

type TouchMap<'a> = BTreeMap<String, Vec<&'a Basket>>;
type PairCounts = BTreeMap<(String, String), (u32, i64)>;

fn mining_counts(baskets: &[Basket]) -> (TouchMap<'_>, PairCounts) {
    let mut touches = BTreeMap::<String, Vec<&Basket>>::new();
    let mut pair_counts = PairCounts::new();
    for basket in baskets {
        let paths = basket.paths.iter().collect::<Vec<_>>();
        for path in &paths {
            touches.entry((*path).clone()).or_default().push(basket);
        }
        for left in 0..paths.len() {
            for right in (left + 1)..paths.len() {
                let key = (paths[left].clone(), paths[right].clone());
                let entry = pair_counts.entry(key).or_insert((0, basket.timestamp));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = entry.1.max(basket.timestamp);
            }
        }
    }
    (touches, pair_counts)
}

fn build_edges(
    project_id: ProjectId,
    head_commit: &str,
    config_hash: &str,
    run_id: &str,
    config: &MiningConfig,
    touches: &TouchMap<'_>,
    pair_counts: PairCounts,
) -> Vec<CoChangeEdge> {
    let mut edges = pair_counts
        .into_iter()
        .filter_map(|((path_a, path_b), (support, last_cochange_at_unix))| {
            let touch_a = count_u32(touches.get(&path_a).map_or(0, Vec::len));
            let touch_b = count_u32(touches.get(&path_b).map_or(0, Vec::len));
            let confidence_ab = f64::from(support) / f64::from(touch_a);
            let confidence_ba = f64::from(support) / f64::from(touch_b);
            (support >= config.min_support
                && confidence_ab.max(confidence_ba) >= config.min_confidence)
                .then(|| CoChangeEdge {
                    edge_id: deterministic_artifact_id(
                        "co-change",
                        &[
                            &project_id.to_string(),
                            head_commit,
                            config_hash,
                            &path_a,
                            &path_b,
                        ],
                    ),
                    project_id,
                    path_a,
                    path_b,
                    support,
                    confidence_ab,
                    confidence_ba,
                    last_cochange_at_unix,
                    static_edge_exists: None,
                    mining_run_ref: run_id.to_owned(),
                    cue_bindings: Vec::new(),
                })
        })
        .collect::<Vec<_>>();
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    edges
}

fn build_hotspots(
    project_id: ProjectId,
    head_commit: &str,
    config_hash: &str,
    run_id: &str,
    reference_unix: i64,
    touches: &TouchMap<'_>,
    failure_density: &BTreeMap<String, u32>,
) -> Vec<HotspotScore> {
    let mut churn = touches
        .iter()
        .map(|(path, path_baskets)| {
            let value = path_baskets
                .iter()
                .map(|basket| decayed_touch(reference_unix, basket.timestamp))
                .sum::<f64>();
            (path.clone(), value)
        })
        .collect::<Vec<_>>();
    churn.sort_by(|left, right| left.0.cmp(&right.0));
    let churn_values = churn.iter().map(|(_, value)| *value).collect::<Vec<_>>();
    let mut hotspots = churn
        .into_iter()
        .map(|(path, churn_decayed)| {
            let path_baskets = &touches[&path];
            let touches_count = count_u32(path_baskets.len());
            let fix_touches = count_u32(
                path_baskets
                    .iter()
                    .filter(|basket| basket.fix_classified)
                    .count(),
            );
            let bugfix_density = f64::from(fix_touches) / f64::from(touches_count);
            let base = percentile_rank(churn_decayed, &churn_values);
            let mut raw = round_half_up(base * 100.0 * (0.5 + 0.5 * bugfix_density));
            let bound_failure_density = failure_density.get(&path).copied().unwrap_or_default();
            if bound_failure_density > 0 {
                raw = round_half_up(raw * 1.2);
            }
            HotspotScore {
                hotspot_id: deterministic_artifact_id(
                    "hotspot",
                    &[&project_id.to_string(), head_commit, config_hash, &path],
                ),
                project_id,
                path,
                touches: touches_count,
                fix_touches,
                churn_decayed,
                bugfix_density,
                failure_density: bound_failure_density,
                score: bounded_score(raw),
                mining_run_ref: run_id.to_owned(),
                cue_bindings: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    hotspots.sort_by(|left, right| left.hotspot_id.cmp(&right.hotspot_id));
    hotspots
}

fn decayed_touch(reference_unix: i64, timestamp: i64) -> f64 {
    let age_seconds =
        u32::try_from(reference_unix.saturating_sub(timestamp).max(0)).unwrap_or(u32::MAX);
    let age_days = f64::from(age_seconds) / SECONDS_PER_DAY;
    (-age_days * std::f64::consts::LN_2 / HOTSPOT_HALF_LIFE_DAYS).exp()
}

#[derive(Clone, Debug, Default)]
pub struct UlArtifactWriterService;

impl UlArtifactWriterService {
    pub async fn write_mining(
        &self,
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        artifacts: &GitMiningArtifacts,
    ) -> Result<UlArtifactWriteReport, EngineError> {
        let mut report = UlArtifactWriteReport {
            artifacts_written: 0,
            relations_written: 0,
            receipts: Vec::new(),
        };
        submit_batch(
            writer,
            admission,
            artifacts.run.project_id,
            &artifacts.run.run_id,
            "mining-run",
            0,
            vec![UlArtifact::MiningRun(artifacts.run.clone())],
            Vec::new(),
            &mut report,
        )
        .await?;

        for (chunk_index, chunk) in artifacts.edges.chunks(50).enumerate() {
            let relations = chunk
                .iter()
                .map(|edge| RelationInput {
                    relation_type: RelationType::CoChange,
                    from: edge.path_a.clone(),
                    to: edge.path_b.clone(),
                })
                .collect();
            let chunk_artifacts = chunk
                .iter()
                .cloned()
                .map(UlArtifact::CoChangeEdge)
                .collect();
            submit_batch(
                writer,
                admission,
                artifacts.run.project_id,
                &artifacts.run.run_id,
                "co-change",
                chunk_index,
                chunk_artifacts,
                relations,
                &mut report,
            )
            .await?;
        }
        for (chunk_index, chunk) in artifacts.hotspots.chunks(50).enumerate() {
            let chunk_artifacts = chunk
                .iter()
                .cloned()
                .map(UlArtifact::HotspotScore)
                .collect();
            submit_batch(
                writer,
                admission,
                artifacts.run.project_id,
                &artifacts.run.run_id,
                "hotspot",
                chunk_index,
                chunk_artifacts,
                Vec::new(),
                &mut report,
            )
            .await?;
        }
        Ok(report)
    }

    pub async fn write_module_cards(
        &self,
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        run_id: &str,
        cards: &[eliot_types::ModuleCard],
    ) -> Result<UlArtifactWriteReport, EngineError> {
        let project_id = cards
            .first()
            .map(|card| card.project_id)
            .ok_or_else(|| EngineError::WriteRejected("module card batch is empty".to_owned()))?;
        let mut sorted = cards.to_vec();
        sorted.sort_by(|left, right| left.card_id.cmp(&right.card_id));
        let mut report = UlArtifactWriteReport {
            artifacts_written: 0,
            relations_written: 0,
            receipts: Vec::new(),
        };
        for (chunk_index, chunk) in sorted.chunks(50).enumerate() {
            let relations = chunk
                .iter()
                .map(|card| RelationInput {
                    relation_type: RelationType::CardCovers,
                    from: format!("card:{}", card.card_id),
                    to: format!("file:{}", card.path),
                })
                .collect();
            let chunk_artifacts = chunk.iter().cloned().map(UlArtifact::ModuleCard).collect();
            submit_batch(
                writer,
                admission,
                project_id,
                run_id,
                "module-card",
                chunk_index,
                chunk_artifacts,
                relations,
                &mut report,
            )
            .await?;
        }
        Ok(report)
    }
}

#[allow(clippy::too_many_arguments)]
async fn submit_batch(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    project_id: ProjectId,
    run_id: &str,
    phase: &str,
    chunk_index: usize,
    mut artifacts: Vec<UlArtifact>,
    mut relations: Vec<RelationInput>,
    report: &mut UlArtifactWriteReport,
) -> Result<(), EngineError> {
    artifacts.sort_by(|left, right| left.artifact_id().cmp(right.artifact_id()));
    relations.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.to.cmp(&right.to))
    });
    let write_id =
        deterministic_write_id(&format!("ul05|{project_id}|{run_id}|{phase}|{chunk_index}"));
    let command = SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(write_id.as_uuid()),
            session_id: None,
            project_id,
            task_id: None,
            scope: format!("project:{project_id}:ul-artifacts"),
            authority: "local-ul-builder".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalTool,
            lifecycle_status: LifecycleStatus::Active,
        },
        artifacts,
        relations,
    });
    let envelope = admission.admit(&command)?;
    report.artifacts_written = report
        .artifacts_written
        .saturating_add(envelope.tool_observations.len());
    report.relations_written = report
        .relations_written
        .saturating_add(envelope.relations.len());
    report.receipts.push(writer.submit(envelope).await?);
    Ok(())
}

#[derive(Clone, Debug)]
struct ParsedCommit {
    hash: String,
    author: String,
    timestamp: i64,
    fix_classified: bool,
    paths: BTreeSet<String>,
    oversized: bool,
}

#[derive(Clone, Debug)]
struct Basket {
    author: String,
    timestamp: i64,
    fix_classified: bool,
    paths: BTreeSet<String>,
}

fn parse_history(
    history: &str,
    max_files_per_basket: usize,
) -> Result<Vec<ParsedCommit>, EngineError> {
    let mut commits = Vec::new();
    let mut current: Option<ParsedCommit> = None;
    for raw_line in history.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(metadata) = line.strip_prefix(GIT_MARKER) {
            if let Some(commit) = current.take() {
                commits.push(commit);
            }
            let mut parts = metadata.splitn(4, '\u{1f}');
            let hash = parts.next().unwrap_or_default().trim();
            let author = parts.next().unwrap_or_default().trim();
            let timestamp = parts
                .next()
                .unwrap_or_default()
                .trim()
                .parse::<i64>()
                .map_err(|error| {
                    EngineError::WriteRejected(format!("invalid git commit timestamp: {error}"))
                })?;
            let subject = parts.next().unwrap_or_default();
            if hash.is_empty() || author.is_empty() {
                return Err(EngineError::WriteRejected(
                    "git marker omitted commit hash or author".to_owned(),
                ));
            }
            current = Some(ParsedCommit {
                hash: hash.to_owned(),
                author: author.to_owned(),
                timestamp,
                fix_classified: is_fix_subject(subject),
                paths: BTreeSet::new(),
                oversized: false,
            });
        } else if !line.trim().is_empty()
            && let Some(commit) = &mut current
        {
            let path = normalize_path(line, None);
            if !path.is_empty() && !is_generated_path(&path) {
                commit.paths.insert(path);
                commit.oversized = commit.paths.len() > max_files_per_basket;
            }
        }
    }
    if let Some(commit) = current {
        commits.push(commit);
    }
    Ok(commits)
}

fn merge_baskets(
    commits: Vec<ParsedCommit>,
    cutoff: i64,
    author_merge_seconds: i64,
    max_files_per_basket: usize,
) -> Vec<Basket> {
    let mut baskets = Vec::new();
    let mut pending: Option<Basket> = None;
    for commit in commits {
        if commit.timestamp < cutoff || commit.paths.is_empty() || commit.oversized {
            flush_pending(&mut pending, &mut baskets);
            continue;
        }
        let can_merge = pending.as_ref().is_some_and(|basket| {
            basket.author == commit.author
                && basket.timestamp.abs_diff(commit.timestamp)
                    <= u64::try_from(author_merge_seconds).unwrap_or_default()
                && basket.paths.union(&commit.paths).count() <= max_files_per_basket
        });
        if can_merge {
            if let Some(basket) = pending.as_mut() {
                basket.paths.extend(commit.paths);
                basket.timestamp = basket.timestamp.max(commit.timestamp);
                basket.fix_classified |= commit.fix_classified;
            }
        } else {
            flush_pending(&mut pending, &mut baskets);
            pending = Some(Basket {
                author: commit.author,
                timestamp: commit.timestamp,
                fix_classified: commit.fix_classified,
                paths: commit.paths,
            });
        }
    }
    flush_pending(&mut pending, &mut baskets);
    baskets
}

fn flush_pending(pending: &mut Option<Basket>, baskets: &mut Vec<Basket>) {
    if let Some(basket) = pending.take()
        && basket.paths.len() >= 2
    {
        baskets.push(basket);
    }
}

fn is_generated_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lock"))
        || path
            .split('/')
            .any(|segment| matches!(segment, "target" | "node_modules" | "dist" | "vendor"))
}

fn is_fix_subject(subject: &str) -> bool {
    let lower = subject
        .chars()
        .flat_map(char::to_lowercase)
        .collect::<String>();
    FIX_KEYWORDS.iter().any(|keyword| lower.contains(keyword))
}

fn percentile_rank(value: f64, values: &[f64]) -> f64 {
    if values.len() <= 1 {
        return 1.0;
    }
    let lower = values
        .iter()
        .filter(|candidate| **candidate < value)
        .count();
    f64::from(u32::try_from(lower).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(values.len() - 1).unwrap_or(u32::MAX))
}

fn round_half_up(value: f64) -> f64 {
    (value + 0.5).floor()
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn bounded_score(raw: f64) -> u8 {
    raw.clamp(0.0, 100.0) as u8
}

fn deterministic_artifact_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(b"|");
        hasher.update(part.as_bytes());
    }
    format!("{prefix}-{}", hasher.finalize().to_hex())
}

fn count_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
