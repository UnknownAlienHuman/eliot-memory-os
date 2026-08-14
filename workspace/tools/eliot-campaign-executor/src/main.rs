#![allow(clippy::needless_pass_by_value, clippy::print_stdout)]

use anyhow::{Context, Result, ensure};
use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use eliot_campaign_executor::{
    BOOTSTRAP_RECEIPT_SHA256, CHECKPOINT0_SHA256, CHECKPOINT1_SHA256, CampaignExecutor,
    CampaignLedger, CampaignStore, CapabilityProbe, D01_HANDLE_SHA256, D01_REPORT_SHA256,
    EVENT9_HEAD_SHA256, EpochId, EvidenceFile, OpenCodeEvidence, OpenCodeRoutePolicy, PLAN_ID,
    PRIMARY_OPENCODE_MODEL, RecoveryEvidence, SlotLaunchReceipt,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "eliot-campaign-executor",
    about = "D-02 development campaign control"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    Verify {
        #[arg(long)]
        campaign_root: PathBuf,
    },
    AdoptBootstrap {
        #[arg(long)]
        campaign_root: PathBuf,
        #[arg(long)]
        repository_root: PathBuf,
        #[arg(long)]
        policy_json: PathBuf,
        #[arg(long)]
        epoch_lineage: String,
        #[arg(long)]
        epoch_sequence: u64,
        #[arg(long, alias = "report")]
        d01_report: Option<PathBuf>,
        #[arg(long, alias = "handle")]
        d01_handle: Option<PathBuf>,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long, alias = "event9-evidence")]
        event9: Option<PathBuf>,
        #[arg(long)]
        bootstrap_receipt: Option<PathBuf>,
        #[arg(long)]
        checkpoint0: Option<PathBuf>,
    },
    Recover {
        #[arg(long)]
        campaign_root: PathBuf,
    },
    PlanDispatch {
        #[arg(long)]
        campaign_root: PathBuf,
        #[arg(long)]
        probe_json: PathBuf,
    },
    RecordCodexLaunches {
        #[arg(long)]
        campaign_root: PathBuf,
        #[arg(long)]
        receipts_json: PathBuf,
    },
    BindOpencodePrimary {
        #[arg(long)]
        campaign_root: PathBuf,
        #[arg(long, alias = "result")]
        result_path: PathBuf,
        #[arg(long, alias = "stdout")]
        stdout_path: PathBuf,
        #[arg(long, alias = "stderr")]
        stderr_path: PathBuf,
        #[arg(long, conflicts_with = "scratch_dir")]
        contract_argv_json: Option<PathBuf>,
        #[arg(long, conflicts_with = "contract_argv_json")]
        scratch_dir: Option<PathBuf>,
    },
    Apply {
        #[arg(long)]
        campaign_root: PathBuf,
        /// A closed command name. Unknown names are reported as REJECT.
        #[arg(long)]
        command: String,
    },
    Inspect {
        #[arg(long)]
        campaign_root: PathBuf,
    },
}

#[derive(Debug, Clone, Copy)]
enum ApplyCommand {
    Observe,
    ClaimWork,
    Checkpoint,
    WriteSource,
    AssemblePackage,
    IntegratePackage,
    Replan,
    FinishParent,
}

impl ApplyCommand {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "observe" => Self::Observe,
            "claim-work" => Self::ClaimWork,
            "checkpoint" => Self::Checkpoint,
            "write-source" => Self::WriteSource,
            "assemble-package" => Self::AssemblePackage,
            "integrate-package" => Self::IntegratePackage,
            "replan" => Self::Replan,
            "finish-parent" => Self::FinishParent,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::ClaimWork => "claim-work",
            Self::Checkpoint => "checkpoint",
            Self::WriteSource => "write-source",
            Self::AssemblePackage => "assemble-package",
            Self::IntegratePackage => "integrate-package",
            Self::Replan => "replan",
            Self::FinishParent => "finish-parent",
        }
    }
}

fn resolve_evidence_path(
    root: &Path,
    explicit: Option<PathBuf>,
    names: &[&str],
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ensure!(
            path.is_file(),
            "evidence path is not a file: {}",
            path.display()
        );
        return Ok(path);
    }
    let mut candidates = names.iter().map(|name| root.join(name));
    candidates
        .find(|path| path.is_file())
        .with_context(|| format!("could not derive evidence path under {}", root.display()))
}

fn evidence_file(path: PathBuf, expected_sha256: &str) -> Result<EvidenceFile> {
    ensure!(
        path.is_file(),
        "evidence path is not a file: {}",
        path.display()
    );
    Ok(EvidenceFile {
        path,
        expected_sha256: expected_sha256.to_owned(),
    })
}

fn event_path(root: &Path, sequence: u64, event_type: &str) -> PathBuf {
    let kind = event_type
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    root.join("events")
        .join(format!("{sequence:06}-{kind}.json"))
}

fn state_fence_after(epoch: &EpochId, sequence: u64, event_hash: &str) -> String {
    format!(
        "{}:{}:{sequence}:{event_hash}",
        epoch.lineage, epoch.sequence
    )
}

fn contract_argv(
    contract_argv_json: Option<PathBuf>,
    scratch_dir: Option<PathBuf>,
) -> Result<Vec<String>> {
    match (contract_argv_json, scratch_dir) {
        (Some(path), None) => {
            let bytes = fs::read(&path)
                .with_context(|| format!("read OpenCode contract argv: {}", path.display()))?;
            let argv: Vec<String> = serde_json::from_slice(&bytes)
                .context("parse OpenCode contract argv JSON array")?;
            ensure!(!argv.is_empty(), "OpenCode contract argv is empty");
            Ok(argv)
        }
        (None, Some(path)) => {
            ensure!(
                path.is_dir(),
                "OpenCode scratch directory is not a directory"
            );
            Ok(vec![
                "run".to_owned(),
                "--format".to_owned(),
                "json".to_owned(),
                "--agent".to_owned(),
                "plan".to_owned(),
                "--dir".to_owned(),
                path.to_string_lossy().into_owned(),
                "--model".to_owned(),
                PRIMARY_OPENCODE_MODEL.to_owned(),
            ])
        }
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "provide either --contract-argv-json or --scratch-dir, not both"
        )),
        (None, None) => Err(anyhow::anyhow!(
            "one of --contract-argv-json or --scratch-dir is required"
        )),
    }
}

fn opencode_evidence(
    result_path: PathBuf,
    _stdout_path: PathBuf,
    _stderr_path: PathBuf,
    _contract_argv: Vec<String>,
) -> Result<OpenCodeEvidence> {
    let bytes = fs::read(&result_path)
        .with_context(|| format!("read OpenCode HTTP/SSE result: {}", result_path.display()))?;
    let result = serde_json::from_slice(&bytes).context("parse OpenCode HTTP/SSE result")?;
    Ok(OpenCodeEvidence::from_result(result))
}

fn policy(path: &Path) -> Result<OpenCodeRoutePolicy> {
    let bytes = fs::read(path).with_context(|| format!("read policy: {}", path.display()))?;
    let policy: OpenCodeRoutePolicy =
        serde_json::from_slice(&bytes).context("parse policy JSON")?;
    policy.verify()?;
    Ok(policy)
}

fn epoch(lineage: &str, sequence: u64) -> Result<EpochId> {
    ensure!(sequence != 0, "epoch sequence must be nonzero");
    Ok(EpochId {
        lineage: Uuid::parse_str(lineage).context("parse epoch lineage UUID")?,
        sequence,
    })
}

fn projection_files(root: &Path) -> BTreeSet<PathBuf> {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("projection-")
                        && Path::new(name)
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                })
        })
        .collect()
}

fn projection_path(before: &BTreeSet<PathBuf>, root: &Path) -> Option<PathBuf> {
    projection_files(root).difference(before).next().cloned()
}

fn ledger_projection(ledger: &CampaignLedger, command: &str, status: &str, detail: Value) -> Value {
    json!({
        "schema_version": "eliot-campaign-executor-projection-v1",
        "plan": PLAN_ID,
        "plan_id": PLAN_ID,
        "command": command,
        "status": status,
        "journal_head": ledger.head_hash(),
        "state_fence": ledger.state_fence(),
        "genesis": ledger.genesis(),
        "events": ledger.suffix(),
        "detail": detail,
    })
}

fn receipt(
    command: &str,
    status: &str,
    journal_head: Option<&str>,
    object_refs: Value,
    gaps: Vec<String>,
    proof_ceiling: &str,
    error: Option<String>,
) -> Value {
    json!({
        "schema_version": "eliot-campaign-executor-receipt-v1",
        "plan": PLAN_ID,
        "plan_id": PLAN_ID,
        "command": command,
        "status": status,
        "journal_head": journal_head,
        "object_refs": object_refs,
        "gaps": gaps,
        "proof_ceiling": proof_ceiling,
        "error": error,
    })
}

fn refs(paths: impl IntoIterator<Item = PathBuf>) -> Value {
    Value::Array(
        paths
            .into_iter()
            .map(|path| Value::String(path.display().to_string()))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn adopt_bootstrap(
    campaign_root: PathBuf,
    repository_root: PathBuf,
    policy_json: PathBuf,
    epoch_lineage: String,
    epoch_sequence: u64,
    d01_report: Option<PathBuf>,
    d01_handle: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
    event9: Option<PathBuf>,
    bootstrap_receipt: Option<PathBuf>,
    checkpoint0: Option<PathBuf>,
) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    let old_head = ledger.head_hash().to_owned();
    let old_fence = ledger.state_fence();
    let report = resolve_evidence_path(
        &campaign_root,
        d01_report,
        &["evidence/sha256/1734908ea5451bc11f066631dcda61f3f709b8dac081ce9dfb8399c966d1334b.json"],
    )?;
    let handle = resolve_evidence_path(
        &campaign_root,
        d01_handle,
        &["evidence-handles/D-01-bootstrap-control-accepted-seq-000008.json"],
    )?;
    let checkpoint = resolve_evidence_path(
        &campaign_root,
        checkpoint,
        &["global-integration-checkpoint-1.json"],
    )?;
    let event9 = resolve_evidence_path(
        &campaign_root,
        event9,
        &["events/000009-global-integration-checkpoint-1-recorded.json"],
    )?;
    let bootstrap_receipt = resolve_evidence_path(
        &campaign_root,
        bootstrap_receipt,
        &["bootstrap-campaign-seed.receipt.json"],
    )?;
    let checkpoint0 = resolve_evidence_path(
        &campaign_root,
        checkpoint0,
        &["global-integration-checkpoint-0.json"],
    )?;
    let report_evidence = evidence_file(report.clone(), D01_REPORT_SHA256)?;
    let handle_evidence = evidence_file(handle.clone(), D01_HANDLE_SHA256)?;
    let checkpoint1_evidence = evidence_file(checkpoint.clone(), CHECKPOINT1_SHA256)?;
    let event9_evidence = evidence_file(event9.clone(), EVENT9_HEAD_SHA256)?;
    let bootstrap_receipt_evidence =
        evidence_file(bootstrap_receipt.clone(), BOOTSTRAP_RECEIPT_SHA256)?;
    let checkpoint0_evidence = evidence_file(checkpoint0.clone(), CHECKPOINT0_SHA256)?;
    let policy = policy(&policy_json)?;
    let recovery = RecoveryEvidence {
        bootstrap_receipt: bootstrap_receipt_evidence,
        d01_report: report_evidence,
        d01_handle: handle_evidence,
        checkpoint0: checkpoint0_evidence,
        checkpoint: checkpoint1_evidence,
        event9: event9_evidence,
        repository_root: repository_root.clone(),
        event9_head_sha256: EVENT9_HEAD_SHA256.to_owned(),
    };
    recovery.verify_with_policy(&policy)?;
    let epoch = epoch(&epoch_lineage, epoch_sequence)?;
    let mut executor = CampaignExecutor::new(ledger);
    let adoption = executor.adopt_with_policy(epoch, &recovery, &policy)?;
    let event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("adoption did not produce a bridge event")?;
    store.append_event_checked(&event, &old_head, None, &old_fence)?;
    let before = projection_files(&campaign_root);
    store.write_projection(&ledger_projection(
        &executor.ledger,
        "adopt-bootstrap",
        "ACCEPTED",
        serde_json::to_value(&adoption)?,
    ))?;
    let projection = projection_path(&before, &campaign_root);
    let event_path = campaign_root.join("events").join(format!(
        "{:06}-controller-epoch-adopted.json",
        event.sequence
    ));
    let mut object_paths = vec![
        bootstrap_receipt,
        checkpoint0,
        report,
        handle,
        checkpoint,
        event9,
        policy_json,
        event_path,
    ];
    if let Some(path) = projection {
        object_paths.push(path);
    }
    Ok(receipt(
        "adopt-bootstrap",
        "ACCEPTED",
        Some(executor.ledger.head_hash()),
        refs(object_paths),
        Vec::new(),
        "candidate_only; no host spawn or oracle authority",
        None,
    ))
}

fn verify(campaign_root: PathBuf) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    ledger.verify_suffix()?;
    ledger.verify_legacy_suffix_with_head(EVENT9_HEAD_SHA256)?;
    Ok(receipt(
        "verify",
        "ACCEPTED",
        Some(ledger.head_hash()),
        refs([
            campaign_root.join("bootstrap-campaign-seed.json"),
            campaign_root.join("events"),
        ]),
        Vec::new(),
        "observe_only",
        None,
    ))
}

fn recover(campaign_root: PathBuf) -> Result<(Value, bool)> {
    let store = CampaignStore::acquire(&campaign_root)?;
    match store.load() {
        Ok(ledger) => {
            ledger.verify_suffix()?;
            ledger.verify_legacy_suffix_with_head(EVENT9_HEAD_SHA256)?;
            let before = projection_files(&campaign_root);
            let projection = ledger_projection(
                &ledger,
                "recover",
                "ACCEPTED",
                json!({"replayed": true, "quarantined": false}),
            );
            store.write_projection(&projection)?;
            let object_refs = projection_path(&before, &campaign_root)
                .map_or_else(|| refs([campaign_root.join("events")]), |path| refs([path]));
            Ok((
                receipt(
                    "recover",
                    "ACCEPTED",
                    Some(ledger.head_hash()),
                    object_refs,
                    Vec::new(),
                    "observe_only; replayed without journal rewrite",
                    None,
                ),
                false,
            ))
        }
        Err(error) => {
            let detail = json!({
                "replayed": false,
                "quarantined": true,
                "reason": error.to_string(),
                "journal_preserved": true,
            });
            let before = projection_files(&campaign_root);
            store.write_projection(&json!({
                "schema_version": "eliot-campaign-executor-projection-v1",
                "plan": PLAN_ID,
                "command": "recover",
                "status": "QUARANTINE",
                "detail": detail,
            }))?;
            let projection = projection_path(&before, &campaign_root);
            let refs_value = projection.map_or_else(
                || refs([campaign_root.join("events")]),
                |path| refs([path, campaign_root.join("events")]),
            );
            Ok((
                receipt(
                    "recover",
                    "QUARANTINE",
                    None,
                    refs_value,
                    vec![error.to_string()],
                    "observe_only; journal quarantined and preserved",
                    Some(error.to_string()),
                ),
                true,
            ))
        }
    }
}

fn plan_dispatch(campaign_root: PathBuf, probe_json: PathBuf) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    ensure!(
        !ledger
            .suffix()
            .iter()
            .any(|event| event.event_type == "capability_probe_recorded"),
        "capability probe is already persisted"
    );
    ensure!(
        !ledger
            .suffix()
            .iter()
            .any(|event| event.event_type == "codex_slots_staffed"),
        "Codex slot staffing is already persisted"
    );
    let epoch = ledger
        .active_controller_epoch()
        .cloned()
        .context("plan-dispatch requires an adopted controller epoch")?;
    let probe_bytes = fs::read(&probe_json)?;
    let probe: CapabilityProbe =
        serde_json::from_slice(&probe_bytes).context("parse probe JSON")?;
    probe.validate_before_staffing()?;
    let old_head = ledger.head_hash().to_owned();
    let old_fence = ledger.state_fence();
    let mut executor = CampaignExecutor::new(ledger);
    executor.record_capability_probe(probe.clone())?;
    let capability_event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("capability probe did not produce a journal event")?;
    executor.staff_codex_slots()?;
    let staffed_event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("Codex staffing did not produce a journal event")?;
    let intents = executor.plan_codex_dispatches()?.to_vec();
    let intent_event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("Codex dispatch planning did not produce a journal event")?;
    store.append_event_checked(&capability_event, &old_head, Some(&epoch), &old_fence)?;
    store.append_event_checked(
        &staffed_event,
        &capability_event.event_hash,
        Some(&epoch),
        &state_fence_after(
            &epoch,
            capability_event.sequence,
            &capability_event.event_hash,
        ),
    )?;
    store.append_event_checked(
        &intent_event,
        &staffed_event.event_hash,
        Some(&epoch),
        &state_fence_after(&epoch, staffed_event.sequence, &staffed_event.event_hash),
    )?;
    let intents_value = serde_json::to_value(&intents)?;
    let before = projection_files(&campaign_root);
    store.write_projection(&ledger_projection(
        &executor.ledger,
        "plan-dispatch",
        "CANDIDATE_ONLY",
        json!({
            "capability_probe": probe,
            "dispatch_intents": intents_value.clone(),
            "host_spawn_authority": false,
            "host_acknowledged": false,
        }),
    ))?;
    let mut object_refs = vec![probe_json, campaign_root.join("events")];
    if let Some(path) = projection_path(&before, &campaign_root) {
        object_refs.push(path);
    }
    Ok(receipt(
        "plan-dispatch",
        "CANDIDATE_ONLY",
        Some(executor.ledger.head_hash()),
        json!({
            "refs": refs(object_refs),
            "dispatch_intents": intents_value,
            "dispatch_intents_persisted": true,
            "host_spawn_authority": false,
            "host_acknowledged": false,
        }),
        vec!["host launch acknowledgement remains pending".to_owned()],
        "candidate_only; typed dispatch intents only; no host spawn authority",
        None,
    ))
}

fn record_codex_launches(campaign_root: PathBuf, receipts_json: PathBuf) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    let old_head = ledger.head_hash().to_owned();
    let old_fence = ledger.state_fence();
    let epoch = ledger
        .active_controller_epoch()
        .cloned()
        .context("record-codex-launches requires an adopted controller epoch")?;
    let bytes = fs::read(&receipts_json)
        .with_context(|| format!("read Codex launch receipts: {}", receipts_json.display()))?;
    let receipts: Vec<SlotLaunchReceipt> =
        serde_json::from_slice(&bytes).context("parse Codex launch receipts JSON array")?;
    ensure!(!receipts.is_empty(), "Codex launch receipts are empty");
    let mut executor = CampaignExecutor::from_replayed_ledger(ledger)?;
    executor.record_slot_launch_receipts(&receipts)?;
    let event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("Codex launch receipts did not produce a journal event")?;
    ensure!(
        event.event_type == "codex_slot_launch_receipts"
            && event.payload == serde_json::to_value(&receipts)?,
        "generated Codex launch receipt event is not the typed input"
    );
    store.append_event_checked(&event, &old_head, Some(&epoch), &old_fence)?;
    Ok(receipt(
        "record-codex-launches",
        "ACCEPTED",
        Some(executor.ledger.head_hash()),
        json!({
            "refs": refs([
                receipts_json,
                event_path(&campaign_root, event.sequence, &event.event_type),
            ]),
            "host_acknowledged": true,
            "host_spawn_authority": false,
        }),
        Vec::new(),
        "candidate_only; host acknowledgement bound; no spawn authority",
        None,
    ))
}

fn bind_opencode_primary(
    campaign_root: PathBuf,
    result_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    contract_argv_json: Option<PathBuf>,
    scratch_dir: Option<PathBuf>,
) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    let old_head = ledger.head_hash().to_owned();
    let old_fence = ledger.state_fence();
    let epoch = ledger
        .active_controller_epoch()
        .cloned()
        .context("bind-opencode-primary requires an adopted controller epoch")?;
    let contract_argv = contract_argv(contract_argv_json.clone(), scratch_dir.clone())?;
    let evidence = opencode_evidence(
        result_path.clone(),
        stdout_path.clone(),
        stderr_path.clone(),
        contract_argv,
    )?;
    let mut executor = CampaignExecutor::from_replayed_ledger(ledger)?;
    let mut admission_event = None;
    if executor.opencode_primary().is_none() {
        executor.admit_opencode_primary()?;
        let event = executor
            .ledger
            .suffix()
            .last()
            .cloned()
            .context("OpenCode admission did not produce a journal event")?;
        ensure!(
            event.event_type == "opencode_attempt_admitted",
            "unexpected OpenCode admission event"
        );
        admission_event = Some(event);
    }
    let attempt = executor
        .opencode_primary()
        .cloned()
        .context("OpenCode primary admission is missing")?;
    executor.verify_opencode_attempt(&attempt, &evidence)?;
    let verification_event = executor
        .ledger
        .suffix()
        .last()
        .cloned()
        .context("OpenCode verification did not produce a journal event")?;
    ensure!(
        verification_event.event_type == "opencode_attempt_verified",
        "unexpected OpenCode verification event"
    );
    if let Some(admission_event) = &admission_event {
        store.append_event_checked(admission_event, &old_head, Some(&epoch), &old_fence)?;
        let admission_fence = state_fence_after(
            &epoch,
            admission_event.sequence,
            &admission_event.event_hash,
        );
        store.append_event_checked(
            &verification_event,
            &admission_event.event_hash,
            Some(&epoch),
            &admission_fence,
        )?;
    } else {
        store.append_event_checked(&verification_event, &old_head, Some(&epoch), &old_fence)?;
    }
    let mut object_paths = vec![
        result_path,
        stdout_path,
        stderr_path,
        event_path(
            &campaign_root,
            verification_event.sequence,
            &verification_event.event_type,
        ),
    ];
    if let Some(path) = contract_argv_json {
        object_paths.push(path);
    }
    if let Some(path) = scratch_dir {
        object_paths.push(path);
    }
    if let Some(event) = admission_event {
        object_paths.push(event_path(
            &campaign_root,
            event.sequence,
            &event.event_type,
        ));
    }
    Ok(receipt(
        "bind-opencode-primary",
        "CANDIDATE_ONLY",
        Some(executor.ledger.head_hash()),
        json!({
            "refs": refs(object_paths),
            "host_spawn_authority": false,
            "candidate_only": true,
        }),
        Vec::new(),
        "candidate_only; A-04 HTTP/SSE result verified; no host spawn authority",
        None,
    ))
}

fn inspect(campaign_root: PathBuf) -> Result<Value> {
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    Ok(receipt(
        "inspect",
        "ACCEPTED",
        Some(ledger.head_hash()),
        json!({
            "campaign_root": campaign_root.display().to_string(),
            "event_count": ledger.suffix().len(),
            "state_fence": ledger.state_fence(),
            "active_controller_epoch": ledger.active_controller_epoch(),
        }),
        Vec::new(),
        "observe_only",
        None,
    ))
}

fn apply(campaign_root: PathBuf, command: String) -> Result<Value> {
    let Some(command_kind) = ApplyCommand::parse(&command) else {
        return Ok(receipt(
            "apply",
            "REJECT",
            None,
            json!({"command": command, "accepted_command_enum": "closed"}),
            vec!["unsupported apply command".to_owned()],
            "none",
            Some("unsupported command; arbitrary event JSON is not accepted".to_owned()),
        ));
    };
    let store = CampaignStore::acquire(&campaign_root)?;
    let ledger = store.load()?;
    let _ = ledger;
    Ok(receipt(
        "apply",
        "REJECT",
        None,
        json!({"command": command_kind.as_str(), "accepted_command_enum": "closed"}),
        vec!["apply has no host or journal mutation authority".to_owned()],
        "none",
        Some("typed command recognized but unsupported by this fail-closed CLI".to_owned()),
    ))
}

fn dispatch(command: Option<Command>) -> Result<(Value, bool)> {
    let Some(command) = command else {
        return Ok((
            receipt(
                "parse",
                "REJECT",
                None,
                json!({}),
                vec!["a subcommand is required".to_owned()],
                "none",
                Some("missing subcommand".to_owned()),
            ),
            true,
        ));
    };
    match command {
        Command::Verify { campaign_root } => Ok((verify(campaign_root)?, false)),
        Command::AdoptBootstrap {
            campaign_root,
            repository_root,
            policy_json,
            epoch_lineage,
            epoch_sequence,
            d01_report,
            d01_handle,
            checkpoint,
            event9,
            bootstrap_receipt,
            checkpoint0,
        } => Ok((
            adopt_bootstrap(
                campaign_root,
                repository_root,
                policy_json,
                epoch_lineage,
                epoch_sequence,
                d01_report,
                d01_handle,
                checkpoint,
                event9,
                bootstrap_receipt,
                checkpoint0,
            )?,
            false,
        )),
        Command::Recover { campaign_root } => recover(campaign_root),
        Command::PlanDispatch {
            campaign_root,
            probe_json,
        } => Ok((plan_dispatch(campaign_root, probe_json)?, false)),
        Command::RecordCodexLaunches {
            campaign_root,
            receipts_json,
        } => Ok((record_codex_launches(campaign_root, receipts_json)?, false)),
        Command::BindOpencodePrimary {
            campaign_root,
            result_path,
            stdout_path,
            stderr_path,
            contract_argv_json,
            scratch_dir,
        } => Ok((
            bind_opencode_primary(
                campaign_root,
                result_path,
                stdout_path,
                stderr_path,
                contract_argv_json,
                scratch_dir,
            )?,
            false,
        )),
        Command::Apply {
            campaign_root,
            command,
        } => {
            let receipt = apply(campaign_root, command)?;
            let rejected = receipt.get("status").and_then(Value::as_str) == Some("REJECT");
            Ok((receipt, rejected))
        }
        Command::Inspect { campaign_root } => Ok((inspect(campaign_root)?, false)),
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let value = receipt(
                if informational { "help" } else { "parse" },
                if informational { "ACCEPTED" } else { "REJECT" },
                None,
                if informational {
                    json!({"text": error.to_string()})
                } else {
                    json!({})
                },
                if informational {
                    Vec::new()
                } else {
                    vec![error.to_string()]
                },
                if informational {
                    "observe_only"
                } else {
                    "none"
                },
                if informational {
                    None
                } else {
                    Some("invalid command line".to_owned())
                },
            );
            println!("{value}");
            return if informational {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
    };
    match dispatch(cli.command) {
        Ok((value, failed)) => {
            println!("{value}");
            if failed
                || value.get("status").and_then(Value::as_str) == Some("REJECT")
                || value.get("status").and_then(Value::as_str) == Some("QUARANTINE")
            {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            let value = receipt(
                "executor",
                "REJECT",
                None,
                json!({}),
                vec![error.to_string()],
                "none",
                Some(error.to_string()),
            );
            println!("{value}");
            ExitCode::from(1)
        }
    }
}
