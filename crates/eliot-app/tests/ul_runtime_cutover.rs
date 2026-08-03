use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const DAEMON_SETUP_SOURCE: &str = "crates/eliot-app/src/mcp_stdio.rs";
const DISPATCH_SOURCE: &str = "crates/eliot-app/src/mcp_stdio/dispatch.rs";
const UL_INTEGRATION_SOURCE: &str = "crates/eliot-app/src/mcp_stdio/ul.rs";

#[test]
fn daemon_has_one_understanding_runtime_owner_and_no_ul_compatibility_owner() -> TestResult {
    let repo = repository_root()?;
    let sources = tracked_app_rust_sources(&repo)?;
    assert!(
        !sources.is_empty(),
        "no tracked eliot-app Rust sources found"
    );

    let mut violations = Vec::new();
    let mut understanding_constructions = Vec::new();

    for relative in sources {
        let source = fs::read_to_string(repo.join(&relative))?;
        let compact = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let display = relative.to_string_lossy().replace('\\', "/");

        for (label, needle) in [
            ("struct UlRuntime", "structUlRuntime"),
            ("UlRuntime::new", "UlRuntime::new"),
            ("Arc<UlRuntime>", "Arc<UlRuntime>"),
            ("state.ul", "state.ul"),
        ] {
            if compact.contains(needle) {
                violations.push(format!("{display}: {label}"));
            }
        }

        if mcp_state_has_ul_field(&compact) {
            violations.push(format!("{display}: McpState field `ul`"));
        }

        understanding_constructions.extend(std::iter::repeat_n(
            display,
            compact.matches("UnderstandingRuntime::new(").count(),
        ));
    }

    assert!(
        violations.is_empty(),
        "legacy UL compatibility owner remains:\n{}",
        violations.join("\n")
    );
    assert_eq!(
        understanding_constructions.len(),
        1,
        "expected exactly one production UnderstandingRuntime::new construction, found {understanding_constructions:?}"
    );
    assert_eq!(
        understanding_constructions[0], DAEMON_SETUP_SOURCE,
        "UnderstandingRuntime must be constructed by the MCP daemon setup"
    );
    Ok(())
}

#[test]
fn receipt_hydration_installs_boot_state_atomically_with_the_session() -> TestResult {
    let repo = repository_root()?;
    let source = fs::read_to_string(repo.join(UL_INTEGRATION_SOURCE))?;
    let hydration = source
        .split_once("pub(super) async fn ensure_understanding_session")
        .ok_or("understanding session hydration function missing")?
        .1
        .split_once("pub(super) async fn production_injection_mode")
        .ok_or("understanding session hydration boundary missing")?
        .0;

    assert!(hydration.contains("restore_session_if_absent(RestoredSession"));
    assert!(hydration.contains("load_pending_injections"));
    assert!(hydration.contains("PendingRestoreSource::PendingInjectionAndReceipts"));
    assert!(hydration.contains("boot_sent: boot_not_onboarded || (boot_charter && boot_map)"));
    assert!(
        !hydration.contains("mark_boot_sent"),
        "boot receipt hydration must not publish the session before boot state"
    );
    Ok(())
}

#[test]
fn pending_candidate_is_committed_before_the_same_queue_becomes_visible() -> TestResult {
    let repo = repository_root()?;
    let source = fs::read_to_string(repo.join(DISPATCH_SOURCE))?;
    let prepare = source
        .find("prepare_pending_candidate(")
        .ok_or("pure pending candidate admission missing")?;
    let persist = source
        .find("persist_pending_injection_candidate(")
        .ok_or("atomic pending candidate persistence missing")?;
    let install = source
        .find("install_pending_candidate(")
        .ok_or("pending candidate runtime publication missing")?;

    assert!(source.contains("acquire_pending_commit().await"));
    assert!(prepare < persist && persist < install);
    Ok(())
}

fn mcp_state_has_ul_field(compact_source: &str) -> bool {
    let Some(start) = compact_source.find("structMcpState{") else {
        return false;
    };
    let body = &compact_source[start + "structMcpState{".len()..];
    let mut depth = 1_u32;
    for (index, character) in body.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return body[..index].contains("ul:");
                }
            }
            _ => {}
        }
    }
    false
}

fn repository_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let stdout = git_output(manifest_dir, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(String::from_utf8(stdout)?.trim());
    if !root.join("crates/eliot-app/Cargo.toml").is_file() {
        return Err(format!("git root is not the Eliot repository: {}", root.display()).into());
    }
    Ok(root)
}

fn tracked_app_rust_sources(repo: &Path) -> TestResult<Vec<PathBuf>> {
    let stdout = git_output(repo, &["ls-files", "-z", "--", "crates/eliot-app/src"])?;
    let mut paths = stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8(entry.to_vec()).map(PathBuf::from))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| {
        path.extension() == Some(OsStr::new("rs"))
            && !path.components().any(|component| {
                matches!(
                    component,
                    Component::Normal(name)
                        if name == OsStr::new(".eliot") || name == OsStr::new("target")
                )
            })
    });
    paths.sort();
    Ok(paths)
}

fn git_output(current_dir: &Path, args: &[&str]) -> TestResult<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(current_dir)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            current_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(output.stdout)
}
