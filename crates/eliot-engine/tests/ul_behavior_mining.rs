use eliot_engine::{GitMiningService, WriteAdmissionService};
use eliot_types::{
    AgentId, CommandContext, LifecycleStatus, ProjectId, RelationInput, RelationType,
    SemanticCommand, TaintClass, UlArtifact, UlArtifactBatchRecordCommand, Visibility, WriteId,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn t05_hidden_pair_is_mined() -> TestResult {
    let repo = TempGitRepo::new("hidden-pair")?;
    for index in 0..25 {
        let (paths, subject) = if index < 8 {
            (vec!["src/a.rs", "src/b.rs"], "feature pair")
        } else {
            (vec!["src/other.rs", "src/peer.rs"], "other work")
        };
        repo.commit(index, &paths, subject)?;
    }
    let project_id = ProjectId::new_v7();
    let mined = GitMiningService::default().mine(project_id, repo.path(), &BTreeMap::new())?;
    let edge = mined
        .edges
        .iter()
        .find(|edge| edge.path_a == "src/a.rs" && edge.path_b == "src/b.rs")
        .ok_or("hidden co-change edge missing")?;

    assert_eq!(mined.run.commits_scanned, 25);
    assert_eq!(edge.support, 8);
    assert!(edge.confidence_ab >= 0.99);
    assert!(edge.confidence_ba >= 0.99);
    assert!(edge.static_edge_exists.is_none() || edge.static_edge_exists == Some(false));

    let command = SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
        context: ul_context(project_id),
        artifacts: vec![UlArtifact::CoChangeEdge(edge.clone())],
        relations: vec![RelationInput {
            relation_type: RelationType::CoChange,
            from: format!("file:{}", edge.path_a),
            to: format!("file:{}", edge.path_b),
        }],
    });
    let envelope = WriteAdmissionService.admit(&command)?;
    assert_eq!(envelope.relations.len(), 1);
    assert_eq!(envelope.relations[0].relation_type, RelationType::CoChange);
    Ok(())
}

#[test]
fn t05_rerun_same_head_is_noop() -> TestResult {
    let repo = TempGitRepo::new("rerun")?;
    for index in 0..4 {
        repo.commit(index, &["src/a.rs", "src/b.rs"], "paired work")?;
    }
    let project_id = ProjectId::new_v7();
    let service = GitMiningService::default();
    let first = service.mine(project_id, repo.path(), &BTreeMap::new())?;
    let mut artifact_count = 1 + first.edges.len() + first.hotspots.len();
    let mut relation_count = first.edges.len();

    let second = service.mine(project_id, repo.path(), &BTreeMap::new())?;
    let noop = service.is_noop(&second, Some(&first.run));
    if !noop {
        artifact_count += 1 + second.edges.len() + second.hotspots.len();
        relation_count += second.edges.len();
    }

    assert!(noop);
    assert_eq!(first.run.run_id, second.run.run_id);
    assert_eq!(artifact_count, 1 + first.edges.len() + first.hotspots.len());
    assert_eq!(relation_count, first.edges.len());
    Ok(())
}

#[test]
fn t05_hotspot_order_matches_fixture() -> TestResult {
    let repo = TempGitRepo::new("hotspot-order")?;
    for index in 0..12 {
        repo.commit(
            index,
            &["src/c.rs", "src/d.rs"],
            if index < 6 {
                "fix regression in c"
            } else {
                "extend c"
            },
        )?;
    }
    for index in 12..16 {
        repo.commit(index, &["src/a.rs", "src/b.rs"], "extend a")?;
    }
    let mined =
        GitMiningService::default().mine(ProjectId::new_v7(), repo.path(), &BTreeMap::new())?;
    let c = hotspot(&mined.hotspots, "src/c.rs")?;
    let a = hotspot(&mined.hotspots, "src/a.rs")?;

    assert_eq!(c.touches, 12);
    assert_eq!(c.fix_touches, 6);
    assert_eq!(a.touches, 4);
    assert_eq!(a.fix_touches, 0);
    assert!(c.score > a.score);
    Ok(())
}

#[test]
fn t05_generated_paths_are_excluded() -> TestResult {
    let repo = TempGitRepo::new("generated")?;
    for index in 0..3 {
        repo.commit(
            index,
            &[
                "src/a.rs",
                "src/b.rs",
                "target/gen.rs",
                "node_modules/pkg/index.js",
                "dist/bundle.js",
                "vendor/source.c",
                "Cargo.lock",
            ],
            "feature with generated output",
        )?;
    }
    let mined =
        GitMiningService::default().mine(ProjectId::new_v7(), repo.path(), &BTreeMap::new())?;
    let paths = mined
        .hotspots
        .iter()
        .map(|hotspot| hotspot.path.as_str())
        .chain(
            mined
                .edges
                .iter()
                .flat_map(|edge| [edge.path_a.as_str(), edge.path_b.as_str()]),
        )
        .collect::<Vec<_>>();

    assert!(paths.contains(&"src/a.rs"));
    assert!(paths.contains(&"src/b.rs"));
    assert!(paths.iter().all(|path| !is_generated_or_vendor(path)));
    Ok(())
}

fn hotspot<'a>(
    hotspots: &'a [eliot_types::HotspotScore],
    path: &str,
) -> TestResult<&'a eliot_types::HotspotScore> {
    hotspots
        .iter()
        .find(|hotspot| hotspot.path == path)
        .ok_or_else(|| format!("hotspot missing for {path}").into())
}

fn ul_context(project_id: ProjectId) -> CommandContext {
    CommandContext {
        write_id: WriteId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: None,
        scope: format!("project:{project_id}:ul-test"),
        authority: "local-ul-builder".to_owned(),
        visibility: Visibility::Project,
        taint: TaintClass::LocalTool,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn is_generated_or_vendor(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lock"))
        || path
            .split('/')
            .any(|part| matches!(part, "target" | "node_modules" | "dist" | "vendor"))
}

struct TempGitRepo {
    root: PathBuf,
}

impl TempGitRepo {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "eliot-ul-t05-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        git(&root, &["config", "core.autocrlf", "false"])?;
        git(&root, &["config", "user.name", "UL Test"])?;
        git(&root, &["config", "user.email", "ul-test@example.invalid"])?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn commit(&self, index: usize, paths: &[&str], subject: &str) -> TestResult {
        for path in paths {
            let target = self.root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, format!("{subject}-{index}\n"))?;
        }
        git(&self.root, &["add", "--all"])?;
        let timestamp = 1_760_000_000_i64.saturating_add(
            i64::try_from(index)
                .unwrap_or(i64::MAX)
                .saturating_mul(3_600),
        );
        let date = format!("@{timestamp} +0000");
        let status = Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["commit", "--quiet", "-m", subject])
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date)
            .status()?;
        if !status.success() {
            return Err(format!("git commit failed with {status}").into());
        }
        Ok(())
    }
}

impl Drop for TempGitRepo {
    fn drop(&mut self) {
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-t05-"))
            && self.root.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn git(root: &Path, args: &[&str]) -> TestResult {
    let status = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("git {args:?} failed with {status}").into());
    }
    Ok(())
}
