//! True two-process contention and admission proof for the Host-to-Watchdog
//! heartbeat transport (unit-test module, Windows only).
//!
//! The in-module suite proves serialization with same-process threads and
//! same-process handle proxies. This module closes the residual realism gap:
//! every contender below is a real second OS process (a re-executed test
//! binary in a peer role), so the `LockFileEx` exclusion and the
//! `host-heartbeat-rejected-peers` evidence are exerted across processes.
//!
//! Peer vehicle: [`two_process_peer_entrypoint`] re-executes the current test
//! binary with `--exact` plus `ELIOT_HB2_ROLE`. Under an ordinary suite run
//! the role variable is absent and the entrypoint returns immediately; it is
//! a subprocess role, never a standalone assertion. All real assertions live
//! in the three parent tests, which classify each peer by its outcome file
//! and nonzero exits fail with the peer stderr attached.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use eliot_runtime_contracts::{WATCHDOG_HEARTBEAT_PROTOCOL, WATCHDOG_HEARTBEAT_SERVICE};

use super::observe_armed_heartbeat;
use super::{ALREADY_BOUND_CONFLICT, HeartbeatTransportDescriptor};
use crate::watchdog_service_start::VerifiedWatchdogScmRunning;

static TWO_PROCESS_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Full libtest path of the peer entrypoint, used for `--exact` re-execution.
const PEER_TEST_PATH: &str = "watchdog_heartbeat::two_process_tests::two_process_peer_entrypoint";
/// Role variable selecting the peer behavior in the re-executed binary.
const ROLE_ENV: &str = "ELIOT_HB2_ROLE";
const ROLE_BIND_ONCE: &str = "bind_once";
const ROLE_PUBLISH_ONCE: &str = "publish_once";
const ROLE_CONNECT_FOREIGN: &str = "connect_foreign";
const ROLE_WRITE_BEATS: &str = "write_beats";

fn two_process_dir() -> PathBuf {
    let n = TWO_PROCESS_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("eliot-host-hb2-{}-{n}", std::process::id()))
}

fn issue_two_process_descriptor() -> HeartbeatTransportDescriptor {
    HeartbeatTransportDescriptor::issue("test-installation-1750", 7)
        .unwrap_or_else(|_| panic!("two-process descriptor must issue"))
}

/// Exact wire bytes one legit writer emits, mirroring the in-module message
/// shape (service, protocol, ADMITTED heartbeat, epochs 7/11, 2s tick).
fn two_process_message(descriptor: &HeartbeatTransportDescriptor, sequence: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "service": WATCHDOG_HEARTBEAT_SERVICE,
        "protocol": WATCHDOG_HEARTBEAT_PROTOCOL,
        "authority_state": "ADMITTED_HEARTBEAT",
        "coverage_claimed": true,
        "kernel_epoch": 7,
        "watchdog_epoch": 11,
        "tick_interval_ms": 2000,
        "service_instance_guid": descriptor.service_instance_guid,
        "host_challenge_nonce": descriptor.host_challenge_nonce,
        "watchdog_readiness_sequence": sequence,
        "watchdog_incarnation_pid": descriptor.watchdog_incarnation_pid,
        "watchdog_incarnation_start_100ns": descriptor.watchdog_incarnation_start_100ns,
    }))
    .unwrap_or_else(|_| panic!("two-process message must encode"))
}

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::fs::exists(path).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    std::fs::exists(path).unwrap_or(false)
}

fn signal_file(path: &Path) {
    std::fs::write(path, b"go").unwrap_or_else(|_| panic!("two-process signal must write"));
}

fn write_outcome(path: &Path, lines: &[(&str, &str)]) {
    let mut text = String::new();
    for (key, value) in lines {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    std::fs::write(path, text).unwrap_or_else(|_| panic!("peer outcome must write"));
}

fn read_outcome(path: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("peer outcome must read"));
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn outcome_value(outcome: &[(String, String)], key: &str) -> String {
    for (entry, value) in outcome {
        if entry == key {
            return value.clone();
        }
    }
    panic!("peer outcome must carry {key}")
}

/// Spawns one peer: the current test binary re-executed with `--exact` on
/// the peer entrypoint plus the role variables. Output is piped so a peer
/// failure can report its stderr.
fn spawn_peer(role: &str, vars: &[(&str, &str)]) -> std::process::Child {
    let exe = std::env::current_exe().unwrap_or_else(|_| panic!("test image must resolve"));
    let mut command = std::process::Command::new(exe);
    command
        .arg("--exact")
        .arg(PEER_TEST_PATH)
        .arg("--nocapture")
        .env(ROLE_ENV, role);
    for (key, value) in vars {
        command.env(key, value);
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("two-process peer must spawn"))
}

/// Waits for one peer, failing with its captured stderr when it exits
/// nonzero. Returns the parsed outcome file.
fn wait_peer(child: std::process::Child, role: &str, outcome_path: &Path) -> Vec<(String, String)> {
    let output = child
        .wait_with_output()
        .unwrap_or_else(|_| panic!("two-process peer must exit"));
    assert!(
        output.status.success(),
        "two-process peer {role} must exit cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_outcome(outcome_path)
}

fn peer_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("peer is missing {key}"))
}

fn peer_open_pipe(
    pipe_name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    let start = Instant::now();
    let mut attempts = 0_u32;
    loop {
        attempts += 1;
        match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(error) => {
                if start.elapsed() >= Duration::from_secs(15) {
                    return Err(format!(
                        "pipe open failed after {attempts} attempts: {error}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
}

fn peer_bind_once() {
    let dir = PathBuf::from(peer_var("ELIOT_HB2_DIR"));
    let outcome_path = PathBuf::from(peer_var("ELIOT_HB2_OUTCOME"));
    let pid = std::process::id();
    let start = eliot_windows_ipc::process_creation_ticks(pid)
        .unwrap_or_else(|_| panic!("peer creation ticks must query"));
    match HeartbeatTransportDescriptor::bind_incarnation(&dir, pid, start) {
        Ok(_) => write_outcome(
            &outcome_path,
            &[
                ("OUTCOME", "BOUND"),
                ("PID", pid.to_string().as_str()),
                ("START", start.to_string().as_str()),
            ],
        ),
        Err(error) => write_outcome(
            &outcome_path,
            &[
                ("OUTCOME", "CONFLICT"),
                ("PID", pid.to_string().as_str()),
                ("START", start.to_string().as_str()),
                ("DETAIL", format!("{error:?}").as_str()),
            ],
        ),
    }
}

fn peer_publish_once() {
    let dir = PathBuf::from(peer_var("ELIOT_HB2_DIR"));
    let outcome_path = PathBuf::from(peer_var("ELIOT_HB2_OUTCOME"));
    let descriptor = issue_two_process_descriptor();
    match descriptor.publish(&dir) {
        Ok(_) => write_outcome(
            &outcome_path,
            &[
                ("OUTCOME", "PUBLISHED"),
                ("NONCE", descriptor.host_challenge_nonce.as_str()),
                ("GUID", descriptor.service_instance_guid.as_str()),
                ("PIPE", descriptor.pipe_name.as_str()),
            ],
        ),
        Err(error) => write_outcome(
            &outcome_path,
            &[
                ("OUTCOME", "ERROR"),
                ("DETAIL", format!("{error:?}").as_str()),
            ],
        ),
    }
}

fn peer_connect_foreign() {
    let pipe_name = peer_var("ELIOT_HB2_PIPE");
    let outcome_path = PathBuf::from(peer_var("ELIOT_HB2_OUTCOME"));
    // Ready before the admission window opens: the parent absorbs process
    // startup here so the bounded window only ever measures pipe latency.
    signal_file(Path::new(&peer_var("ELIOT_HB2_READY")));
    if !wait_for_file(
        Path::new(&peer_var("ELIOT_HB2_GO")),
        Duration::from_secs(20),
    ) {
        write_outcome(
            &outcome_path,
            &[("OUTCOME", "ERROR"), ("DETAIL", "go file never appeared")],
        );
        return;
    }
    // The open must run inside a Tokio runtime context: `ClientOptions`
    // registers the handle with the reactor on creation and panics
    // outside one. The retry loop itself stays synchronous.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| panic!("peer runtime must build"));
    let open = runtime.block_on(async { peer_open_pipe(pipe_name.as_str()) });
    let _held = match open {
        Ok(held) => held,
        Err(detail) => {
            write_outcome(
                &outcome_path,
                &[("OUTCOME", "OPEN_FAILED"), ("DETAIL", detail.as_str())],
            );
            return;
        }
    };
    signal_file(Path::new(&peer_var("ELIOT_HB2_CONN")));
    // Hold the foreign connection open until the parent finishes the
    // window: closing early would let the accept observe a disconnect
    // instead of a foreign peer.
    if !wait_for_file(
        Path::new(&peer_var("ELIOT_HB2_DONE")),
        Duration::from_secs(20),
    ) {
        write_outcome(
            &outcome_path,
            &[("OUTCOME", "ERROR"), ("DETAIL", "done file never appeared")],
        );
        return;
    }
    write_outcome(&outcome_path, &[("OUTCOME", "CONNECTED")]);
}

fn peer_write_beats() {
    use tokio::io::AsyncWriteExt as _;
    let pipe_name = peer_var("ELIOT_HB2_PIPE");
    let outcome_path = PathBuf::from(peer_var("ELIOT_HB2_OUTCOME"));
    // Ready before the admission window opens (see foreign role).
    signal_file(Path::new(&peer_var("ELIOT_HB2_READY")));
    if !wait_for_file(
        Path::new(&peer_var("ELIOT_HB2_GO")),
        Duration::from_secs(20),
    ) {
        write_outcome(
            &outcome_path,
            &[("OUTCOME", "ERROR"), ("DETAIL", "go file never appeared")],
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| panic!("peer runtime must build"));
    runtime.block_on(async {
        for slot in [1, 2] {
            let file = if slot == 1 {
                peer_var("ELIOT_HB2_MSG1")
            } else {
                peer_var("ELIOT_HB2_MSG2")
            };
            let bytes = std::fs::read(&file).unwrap_or_else(|_| panic!("peer message must read"));
            let open = peer_open_pipe(pipe_name.as_str());
            let mut client = match open {
                Ok(client) => client,
                Err(detail) => panic!("peer pipe open must succeed: {detail}"),
            };
            client
                .write_all(bytes.as_slice())
                .await
                .unwrap_or_else(|_| panic!("peer must write beat {slot}"));
            client
                .write_all(b"\n")
                .await
                .unwrap_or_else(|_| panic!("peer must terminate beat {slot}"));
            client
                .flush()
                .await
                .unwrap_or_else(|_| panic!("peer must flush beat {slot}"));
        }
    });
    // Stay alive until the parent admits: admission checks peer liveness,
    // so exiting before the window closes would fail a live writer.
    if !wait_for_file(
        Path::new(&peer_var("ELIOT_HB2_DONE")),
        Duration::from_secs(20),
    ) {
        write_outcome(
            &outcome_path,
            &[("OUTCOME", "ERROR"), ("DETAIL", "done file never appeared")],
        );
        return;
    }
    write_outcome(&outcome_path, &[("OUTCOME", "WROTE")]);
}

/// Subprocess role entrypoint (see module docs): dispatches on
/// `ELIOT_HB2_ROLE`, no-op when unset so ordinary suite runs stay green.
#[test]
fn two_process_peer_entrypoint() {
    let Ok(role) = std::env::var(ROLE_ENV) else {
        return;
    };
    match role.as_str() {
        ROLE_BIND_ONCE => peer_bind_once(),
        ROLE_PUBLISH_ONCE => peer_publish_once(),
        ROLE_CONNECT_FOREIGN => peer_connect_foreign(),
        ROLE_WRITE_BEATS => peer_write_beats(),
        other => panic!("unknown two-process peer role: {other}"),
    }
}

/// Two real OS processes racing `bind_incarnation` on one unbound
/// descriptor: the `LockFileEx` guard serializes the load-bind-reload
/// critical section, so exactly one writer binds and every loser fails
/// closed on the already-bound conflict (never a silent clobber).
#[test]
fn two_processes_racing_bind_serialize_with_one_winner() {
    const WRITERS: usize = 3;
    let dir = two_process_dir();
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("two-process dir must build"));
    let issued = issue_two_process_descriptor();
    issued
        .publish(&dir)
        .unwrap_or_else(|_| panic!("descriptor must publish"));
    let outcome_paths: Vec<PathBuf> = (0..WRITERS)
        .map(|index| dir.join(format!("bind-outcome-{index}.txt")))
        .collect();
    let children: Vec<std::process::Child> = outcome_paths
        .iter()
        .map(|outcome| {
            spawn_peer(
                ROLE_BIND_ONCE,
                &[
                    ("ELIOT_HB2_DIR", dir.to_string_lossy().as_ref()),
                    ("ELIOT_HB2_OUTCOME", outcome.to_string_lossy().as_ref()),
                ],
            )
        })
        .collect();
    let outcomes: Vec<Vec<(String, String)>> = children
        .into_iter()
        .zip(outcome_paths.iter())
        .map(|(child, outcome)| wait_peer(child, ROLE_BIND_ONCE, outcome))
        .collect();
    // Every peer ran in its own OS process with its own real incarnation:
    // PIDs are distinct proof of separate processes, not synthetic IDs.
    let mut winner: Option<(u32, u64)> = None;
    let mut losers = 0_usize;
    for outcome in &outcomes {
        let status = outcome_value(outcome, "OUTCOME");
        let pid: u32 = outcome_value(outcome, "PID")
            .parse()
            .unwrap_or_else(|_| panic!("peer PID must parse"));
        let start: u64 = outcome_value(outcome, "START")
            .parse()
            .unwrap_or_else(|_| panic!("peer start must parse"));
        assert_ne!(pid, std::process::id(), "winner must be a peer process");
        assert_ne!(start, 0, "peer start must be a real creation time");
        if status == "BOUND" {
            assert!(winner.is_none(), "exactly one cross-process bind must win");
            winner = Some((pid, start));
        } else {
            assert_eq!(status, "CONFLICT", "cross-process bind loser must conflict");
            assert!(
                outcome_value(outcome, "DETAIL").contains(ALREADY_BOUND_CONFLICT),
                "cross-process bind loser must fail on the already-bound conflict"
            );
            losers += 1;
        }
    }
    assert_eq!(
        losers,
        WRITERS - 1,
        "every other cross-process bind must lose closed"
    );
    let (pid, start) = winner.unwrap_or_else(|| panic!("one cross-process winner must exist"));
    let bound = HeartbeatTransportDescriptor::load(&dir)
        .unwrap_or_else(|_| panic!("descriptor must load"))
        .unwrap_or_else(|| panic!("descriptor must be present"));
    assert_eq!(bound.watchdog_incarnation_pid, pid);
    assert_eq!(bound.watchdog_incarnation_start_100ns, start);
    assert_eq!(bound.host_challenge_nonce, issued.host_challenge_nonce);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two real OS processes racing `publish` with distinct challenges: every
/// publisher completes under the lock and the durable file equals exactly
/// one of them (no torn write, no blend of two challenges).
#[test]
fn two_processes_racing_publish_leave_single_winner_bytes() {
    const WRITERS: usize = 3;
    let dir = two_process_dir();
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("two-process dir must build"));
    let outcome_paths: Vec<PathBuf> = (0..WRITERS)
        .map(|index| dir.join(format!("publish-outcome-{index}.txt")))
        .collect();
    let children: Vec<std::process::Child> = outcome_paths
        .iter()
        .map(|outcome| {
            spawn_peer(
                ROLE_PUBLISH_ONCE,
                &[
                    ("ELIOT_HB2_DIR", dir.to_string_lossy().as_ref()),
                    ("ELIOT_HB2_OUTCOME", outcome.to_string_lossy().as_ref()),
                ],
            )
        })
        .collect();
    let outcomes: Vec<Vec<(String, String)>> = children
        .into_iter()
        .zip(outcome_paths.iter())
        .map(|(child, outcome)| wait_peer(child, ROLE_PUBLISH_ONCE, outcome))
        .collect();
    for outcome in &outcomes {
        assert_eq!(
            outcome_value(outcome, "OUTCOME"),
            "PUBLISHED",
            "every cross-process publisher must complete"
        );
    }
    // Distinct challenges prove three separate writers really ran.
    let mut nonces: Vec<String> = outcomes
        .iter()
        .map(|outcome| outcome_value(outcome, "NONCE"))
        .collect();
    nonces.sort();
    nonces.dedup();
    assert_eq!(
        nonces.len(),
        WRITERS,
        "each peer must mint its own challenge"
    );
    let stored = HeartbeatTransportDescriptor::load(&dir)
        .unwrap_or_else(|_| panic!("descriptor must load"))
        .unwrap_or_else(|| panic!("descriptor must be present"));
    let matched = outcomes
        .iter()
        .filter(|outcome| {
            outcome_value(outcome, "NONCE") == stored.host_challenge_nonce
                && outcome_value(outcome, "GUID") == stored.service_instance_guid
                && outcome_value(outcome, "PIPE") == stored.pipe_name
        })
        .count();
    assert_eq!(
        matched, 1,
        "stored descriptor must equal exactly one of the cross-process publishers"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Live legit-writer peer for the admission proof: its OS process, real
/// incarnation, pipe name, and coordination files.
struct WriterPeer {
    child: std::process::Child,
    pid: u32,
    start_100ns: u64,
    pipe_name: String,
}

/// Publishes one descriptor, spawns the writer peer blocked on its go file,
/// binds the rendezvous to the writer's real incarnation, and stages its
/// two beat messages. The caller owns the returned process plus every path
/// below `dir`.
fn spawn_writer_peer(dir: &Path) -> WriterPeer {
    let go_file = dir.join("go-writer");
    let ready_file = dir.join("ready-writer");
    let done_file = dir.join("done");
    let msg1_path = dir.join("beat-1.json");
    let msg2_path = dir.join("beat-2.json");
    let outcome_path = dir.join("writer-outcome.txt");
    let issued = issue_two_process_descriptor();
    issued
        .publish(dir)
        .unwrap_or_else(|_| panic!("descriptor must publish"));
    let child = spawn_peer(
        ROLE_WRITE_BEATS,
        &[
            ("ELIOT_HB2_PIPE", issued.pipe_name.as_str()),
            ("ELIOT_HB2_GO", go_file.to_string_lossy().as_ref()),
            ("ELIOT_HB2_READY", ready_file.to_string_lossy().as_ref()),
            ("ELIOT_HB2_DONE", done_file.to_string_lossy().as_ref()),
            ("ELIOT_HB2_MSG1", msg1_path.to_string_lossy().as_ref()),
            ("ELIOT_HB2_MSG2", msg2_path.to_string_lossy().as_ref()),
            ("ELIOT_HB2_OUTCOME", outcome_path.to_string_lossy().as_ref()),
        ],
    );
    let pid = child.id();
    assert_ne!(pid, std::process::id(), "writer must be a peer process");
    let start_100ns = eliot_windows_ipc::process_creation_ticks(pid)
        .unwrap_or_else(|_| panic!("writer creation ticks must query"));
    HeartbeatTransportDescriptor::bind_incarnation(dir, pid, start_100ns)
        .unwrap_or_else(|_| panic!("writer incarnation must bind"));
    // The writer messages name the writer incarnation the descriptor binds.
    let mut bound = issued.clone();
    bound.watchdog_incarnation_pid = pid;
    bound.watchdog_incarnation_start_100ns = start_100ns;
    std::fs::write(&msg1_path, two_process_message(&bound, 1))
        .unwrap_or_else(|_| panic!("beat file must write"));
    std::fs::write(&msg2_path, two_process_message(&bound, 2))
        .unwrap_or_else(|_| panic!("beat file must write"));
    WriterPeer {
        child,
        pid,
        start_100ns,
        pipe_name: issued.pipe_name.clone(),
    }
}

/// Foreign peer plus its release sequencer for the admission proof: the
/// sequencer releases the foreign peer first so its connect reaches the
/// window before the writer beats, then releases the writer once the
/// foreign connection is established server-side.
struct ForeignPeer {
    child: std::process::Child,
    sequencer: std::thread::JoinHandle<()>,
    outcome_path: PathBuf,
}

fn spawn_foreign_peer(dir: &Path, pipe_name: &str, writer_pid: u32) -> ForeignPeer {
    let go_writer = dir.join("go-writer");
    let go_foreign = dir.join("go-foreign");
    let ready_writer = dir.join("ready-writer");
    let ready_foreign = dir.join("ready-foreign");
    let conn_foreign = dir.join("conn-foreign");
    let done_file = dir.join("done");
    let outcome_path = dir.join("foreign-outcome.txt");
    let child = spawn_peer(
        ROLE_CONNECT_FOREIGN,
        &[
            ("ELIOT_HB2_PIPE", pipe_name),
            ("ELIOT_HB2_GO", go_foreign.to_string_lossy().as_ref()),
            ("ELIOT_HB2_READY", ready_foreign.to_string_lossy().as_ref()),
            ("ELIOT_HB2_CONN", conn_foreign.to_string_lossy().as_ref()),
            ("ELIOT_HB2_DONE", done_file.to_string_lossy().as_ref()),
            ("ELIOT_HB2_OUTCOME", outcome_path.to_string_lossy().as_ref()),
        ],
    );
    assert_ne!(
        child.id(),
        writer_pid,
        "foreign peer must be a third process"
    );
    // Absorb peer process startup before the bounded window opens: both
    // peers are warm and waiting on their go files, so the eight-second
    // admission window only ever measures pipe latency.
    assert!(
        wait_for_file(&ready_writer, Duration::from_secs(30)),
        "writer peer must become ready"
    );
    assert!(
        wait_for_file(&ready_foreign, Duration::from_secs(30)),
        "foreign peer must become ready"
    );
    let outcome_diag = outcome_path.clone();
    let sequencer = std::thread::spawn(move || {
        signal_file(&go_foreign);
        if !wait_for_file(&conn_foreign, Duration::from_secs(20)) {
            let diagnosis = std::fs::read_to_string(&outcome_diag).unwrap_or_default();
            panic!("foreign peer must connect (outcome: {diagnosis})");
        }
        signal_file(&go_writer);
    });
    ForeignPeer {
        child,
        sequencer,
        outcome_path,
    }
}

/// Full two-process admission: a legit writer peer emits two beats from its
/// own real incarnation while a second peer process connects foreign. The
/// window admits the beats and the foreign connect stays visible as
/// `host-heartbeat-rejected-peers:1` instead of being erased.
#[test]
fn two_process_admission_counts_foreign_connect_in_rejected_peers_ref() {
    let dir = two_process_dir();
    std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("two-process dir must build"));
    let done_file = dir.join("done");
    let writer_outcome = dir.join("writer-outcome.txt");
    // The legit writer is a live peer process: publish first, then bind the
    // rendezvous to its real incarnation once it exists.
    let writer = spawn_writer_peer(&dir);
    let writer_pid = writer.pid;
    let writer_start = writer.start_100ns;
    let pipe_name = writer.pipe_name.clone();
    let writer_child = writer.child;
    let foreign = spawn_foreign_peer(&dir, pipe_name.as_str(), writer_pid);
    let foreign_child = foreign.child;
    let foreign_outcome = foreign.outcome_path;
    let sequencer = foreign.sequencer;
    let image = std::env::current_exe()
        .unwrap_or_else(|_| panic!("test image must resolve"))
        .to_string_lossy()
        .into_owned();
    let scm = VerifiedWatchdogScmRunning {
        process: eliot_platform_windows::ProcessIdentity {
            process_id: writer_pid,
            start_time_100ns: writer_start,
            image_path: image,
        },
        wait_hint_ms: 0,
        approved_plan_generation: None,
    };
    // The full production admission path: listener bind, windowed accepts
    // with recreation on the foreign rejection, derivation, admission, and
    // the rejected-peers evidence ref. Peers are always reaped (with their
    // stderr on failure) even when the window fails, so a peer panic can
    // never hide behind the admission error.
    let observed = observe_armed_heartbeat(&dir, 7, 11, &scm);
    signal_file(&done_file);
    // Reap peers before judging the window or the sequencer: a peer panic
    // surfaces here with its stderr instead of hiding behind later errors.
    let writer_outcome = wait_peer(writer_child, ROLE_WRITE_BEATS, &writer_outcome);
    let foreign_outcome = wait_peer(foreign_child, ROLE_CONNECT_FOREIGN, &foreign_outcome);
    assert!(
        sequencer.join().is_ok(),
        "sequencer must finish; writer={} foreign={}",
        outcome_value(&writer_outcome, "OUTCOME"),
        outcome_value(&foreign_outcome, "OUTCOME"),
    );
    assert_eq!(
        outcome_value(&writer_outcome, "OUTCOME"),
        "WROTE",
        "writer peer must emit both beats"
    );
    assert_eq!(
        outcome_value(&foreign_outcome, "OUTCOME"),
        "CONNECTED",
        "foreign peer must hold its connection through the window"
    );
    let refs = observed.unwrap_or_else(|error| {
        panic!("two-process admission must succeed: {error:?}");
    });
    let texts: Vec<String> = refs
        .iter()
        .map(|handle| handle.as_str().to_owned())
        .collect();
    assert_eq!(
        texts.len(),
        8,
        "admission must emit seven refs plus rejected-peers"
    );
    assert_eq!(
        texts[1], "host-heartbeat-coverage:CONTINUOUS",
        "the two cross-process beats must chain to continuous coverage"
    );
    assert_eq!(
        texts[6], "host-heartbeat-handshakes:2",
        "both writer beats must bank"
    );
    assert_eq!(
        texts[7], "host-heartbeat-rejected-peers:1",
        "the foreign peer connect must stay visible, not erased"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
