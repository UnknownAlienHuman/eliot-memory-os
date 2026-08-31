use eliot_instrument_api::InstrumentInvocation;
use eliot_process::{
    DispatchAuthorityId, DispatchPermitAuthority, EnvironmentInheritance, EnvironmentProjection,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_testd_core::{
    KernelProcessAdmissionEvidence, KernelProcessAdmissionProvider, KernelProcessAdmissionRequest,
    RetryPolicy, TargetRoots, TestdError, TestdStore, issue_process_admission,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_jobs_v1");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_events_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_meta_v1");

fn database_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("eliot-testd-sequence-{label}-{nonce}.redb"))
}

fn create_store(path: &PathBuf) -> TestdStore {
    TestdStore::open(path, RetryPolicy::default()).expect("open testd store")
}

struct FixtureProvider {
    process: Mutex<Option<ProcessRequest>>,
    contour_root: String,
}

impl KernelProcessAdmissionProvider for FixtureProvider {
    fn admit(
        &self,
        _request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError> {
        let process = self
            .process
            .lock()
            .expect("fixture provider lock")
            .take()
            .expect("fixture process is available once");
        Ok(KernelProcessAdmissionEvidence {
            process,
            contour_root: self.contour_root.clone(),
            grant_id: "fixture-grant".to_owned(),
        })
    }
}

fn fixture_invocation(operation_id: &str) -> InstrumentInvocation {
    serde_json::from_value(json!({
        "request": {
            "request_id": operation_id,
            "session_id": null,
            "task_id": null,
            "product_id": "product-1",
            "source_id": "source-1",
            "state_fence": {
                "authority_epoch": 7,
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            },
            "clock": {
                "valid_time_ms": 1,
                "known_time_ms": 1,
                "transaction_sequence": null,
                "monotonic_ns": 1
            }
        },
        "instrument": "eliot.instrument.test",
        "kind": "TEST",
        "profile": "cargo-test",
        "target": "C:\\source",
        "arguments": [],
        "input_artifacts": [],
        "declared_scope": "workspace",
        "requested_at": {
            "valid_time_ms": 1,
            "known_time_ms": 1,
            "transaction_sequence": null,
            "monotonic_ns": 1
        }
    }))
    .expect("fixture invocation")
}

fn fixture_process(
    job_id: &str,
    operation_id: &str,
    source_root: &str,
    target_root: &str,
) -> ProcessRequest {
    let generation = Generation::new(1).expect("fixture generation");
    let intent = ProcessIntent::new(
        OperationId::new(operation_id).expect("fixture operation"),
        ProcessTreeId::new(format!("tree-{job_id}")).expect("fixture tree"),
        JobId::new(job_id).expect("fixture job"),
        ImageId::new("image-1").expect("fixture image"),
        SessionId::new("session-1").expect("fixture session"),
        generation,
        "C:\\tools\\worker.exe",
        "c".repeat(64),
        vec!["--check".to_owned()],
        source_root,
        EnvironmentProjection::new(
            BTreeMap::from([
                ("CARGO_TARGET_DIR".to_owned(), target_root.to_owned()),
                ("CARGO_HOME".to_owned(), target_root.to_owned()),
            ]),
            Vec::new(),
            EnvironmentInheritance::None,
        )
        .expect("fixture environment"),
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 4)
            .expect("fixture limits"),
    )
    .expect("fixture process intent");
    let mut authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("authority-1").expect("fixture authority"),
        KernelDispatchKey::from_secret_bytes([0x5a; 32]).expect("fixture dispatch key"),
    );
    let permit = authority
        .issue(
            &intent,
            PermitIssuance::new(
                eliot_process::ActionLeaseRef::new(format!("lease-{job_id}"))
                    .expect("fixture lease"),
                FencingToken::new(7, generation, format!("fence-{job_id}")).expect("fixture fence"),
                BTreeMap::from([
                    ("authority".to_owned(), "a".repeat(64)),
                    ("state".to_owned(), "b".repeat(64)),
                ]),
                1,
                2,
                format!("nonce-{job_id}"),
            )
            .expect("fixture issuance"),
        )
        .expect("fixture permit");
    ProcessRequest::new(intent, permit).expect("fixture process request")
}

fn submit_fixture(
    store: &TestdStore,
    job_id: &str,
    project_id: &str,
    roots: &TargetRoots,
) -> Result<eliot_testd_core::TestJob, TestdError> {
    let operation_id = format!("operation-{job_id}");
    let invocation = fixture_invocation(&operation_id);
    let process = fixture_process(
        job_id,
        &operation_id,
        &roots.source_root,
        &roots.target_root,
    );
    let provider = FixtureProvider {
        process: Mutex::new(Some(process)),
        contour_root: roots.allowed_contour_root.clone(),
    };
    let request = KernelProcessAdmissionRequest {
        job_id: job_id.to_owned(),
        project_id: project_id.to_owned(),
        invocation: invocation.clone(),
        source_root: roots.source_root.clone(),
        target_root: roots.target_root.clone(),
        cache_root: roots.cache_root.clone(),
    };
    let permit = issue_process_admission(&provider, &request)?;
    store.submit(job_id, project_id, invocation, permit, roots.clone(), 0, 1)
}

fn fixture_roots(path: &Path) -> (PathBuf, TargetRoots) {
    let roots_base = path.with_extension("roots");
    let contour = roots_base.join("contour");
    let source = roots_base.join("source");
    let target = contour.join("build");
    std::fs::create_dir_all(&target).expect("create contour target");
    std::fs::create_dir_all(&source).expect("create source root");
    let roots = TargetRoots::new(
        contour.to_string_lossy(),
        source.to_string_lossy(),
        target.to_string_lossy(),
        target.to_string_lossy(),
    )
    .expect("valid fixture roots");
    (roots_base, roots)
}

fn job_bytes(job_id: &str, project_id: &str, project_sequence: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "job_id": job_id,
        "project_id": project_id,
        "project_sequence": project_sequence,
        "invocation": {
            "request": {
                "request_id": "operation-1",
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": {
                    "authority_epoch": 7,
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                },
                "clock": {
                    "valid_time_ms": 1,
                    "known_time_ms": 1,
                    "transaction_sequence": null,
                    "monotonic_ns": 1
                }
            },
            "instrument": "eliot.instrument.test",
            "kind": "TEST",
            "profile": "cargo-test",
            "target": "C:\\source",
            "arguments": [],
            "input_artifacts": [],
            "declared_scope": "workspace",
            "requested_at": {
                "valid_time_ms": 1,
                "known_time_ms": 1,
                "transaction_sequence": null,
                "monotonic_ns": 1
            }
        },
        "process": {
            "job_id": job_id,
            "operation_id": "operation-1",
            "process_tree_id": "tree-1",
            "generation": 1,
            "authority_epoch": 7,
            "invocation_digest": "digest"
        },
        "target_roots": {
            "allowed_contour_root": "C:\\contour",
            "source_root": "C:\\source",
            "target_root": "C:\\contour\\build",
            "cache_root": "C:\\contour\\build"
        },
        "priority": 0,
        "state": "queued",
        "attempts": 0,
        "not_before_ms": 0,
        "lease": null,
        "execution": null,
        "verification": null,
        "receipt": null,
        "updated_at_ms": 0,
        "payload_digest": "digest"
    }))
    .expect("encode job fixture")
}

fn seed_database(
    path: &PathBuf,
    jobs: &[(&str, &str, u64)],
    metadata: &[(&str, &[u8])],
    events: &[(&str, &[u8])],
) {
    let database = Database::create(path).expect("create database");
    let write = database.begin_write().expect("begin write");
    {
        let mut table = write.open_table(JOBS).expect("open jobs");
        for (job_id, project_id, sequence) in jobs {
            let encoded = job_bytes(job_id, project_id, *sequence);
            table
                .insert(*job_id, encoded.as_slice())
                .expect("insert job");
        }
    }
    {
        let mut table = write.open_table(META).expect("open metadata");
        for (key, value) in metadata {
            table.insert(*key, *value).expect("insert metadata");
        }
    }
    {
        let mut table = write.open_table(EVENTS).expect("open events");
        for (key, value) in events {
            table.insert(*key, *value).expect("insert event");
        }
    }
    write.commit().expect("commit fixture");
}

fn durable_snapshot(path: &PathBuf) -> Vec<(String, Vec<u8>)> {
    let database = Database::create(path).expect("open database for snapshot");
    let read = database.begin_read().expect("begin snapshot read");
    let mut snapshot = Vec::new();
    {
        let table = read.open_table(JOBS).expect("open jobs snapshot");
        for item in table.iter().expect("iterate jobs snapshot") {
            let (key, value) = item.expect("read jobs snapshot item");
            snapshot.push((format!("jobs:{}", key.value()), value.value().to_vec()));
        }
    }
    {
        let table = read.open_table(EVENTS).expect("open events snapshot");
        for item in table.iter().expect("iterate events snapshot") {
            let (key, value) = item.expect("read events snapshot item");
            snapshot.push((format!("events:{}", key.value()), value.value().to_vec()));
        }
    }
    {
        let table = read.open_table(META).expect("open metadata snapshot");
        for item in table.iter().expect("iterate metadata snapshot") {
            let (key, value) = item.expect("read metadata snapshot item");
            snapshot.push((format!("meta:{}", key.value()), value.value().to_vec()));
        }
    }
    snapshot.sort();
    snapshot
}

fn assert_reopen_corrupt_without_mutation(path: &PathBuf) {
    let before = durable_snapshot(path);
    let error = match TestdStore::open(path, RetryPolicy::default()) {
        Ok(_) => panic!("reopen must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, TestdError::Corrupt(_)));
    let after = durable_snapshot(path);
    assert_eq!(
        after, before,
        "failed startup must not mutate durable state"
    );
}

#[test]
fn clean_first_start_and_durable_restart_preserve_absent_state() {
    let path = database_path("first-start");
    let store = create_store(&path);
    assert!(store.get("missing-job").expect("read absent job").is_none());
    drop(store);

    let restarted = create_store(&path);
    assert!(
        restarted
            .get("missing-job")
            .expect("read absent job after restart")
            .is_none()
    );
    drop(restarted);
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn submission_sequences_are_monotonic_across_restart_and_project_local() {
    let path = database_path("allocation");
    let (roots_base, roots) = fixture_roots(&path);

    let store = create_store(&path);
    assert_eq!(
        submit_fixture(&store, "job-a", "project-a", &roots)
            .expect("submit job a")
            .project_sequence,
        1
    );
    assert_eq!(
        submit_fixture(&store, "job-b", "project-a", &roots)
            .expect("submit job b")
            .project_sequence,
        2
    );
    assert_eq!(
        submit_fixture(&store, "job-c", "project-b", &roots)
            .expect("submit job c")
            .project_sequence,
        1
    );
    drop(store);

    let restarted = create_store(&path);
    assert_eq!(
        restarted
            .get("job-a")
            .expect("read job a")
            .unwrap()
            .project_sequence,
        1
    );
    assert_eq!(
        restarted
            .get("job-b")
            .expect("read job b")
            .unwrap()
            .project_sequence,
        2
    );
    assert_eq!(
        restarted
            .get("job-c")
            .expect("read job c")
            .unwrap()
            .project_sequence,
        1
    );
    drop(restarted);
    std::fs::remove_file(path).expect("remove test database");
    std::fs::remove_dir_all(roots_base).expect("remove fixture roots");
}

#[test]
fn project_sequence_exhaustion_rejects_submission_without_mutation() {
    let path = database_path("project-exhaustion");
    seed_database(
        &path,
        &[("job-a", "project-a", u64::MAX)],
        &[("project:project-a", br#"18446744073709551615"#)],
        &[],
    );
    let (roots_base, roots) = fixture_roots(&path);
    let before = durable_snapshot(&path);
    let store = create_store(&path);
    let error = submit_fixture(&store, "job-b", "project-a", &roots)
        .expect_err("an exhausted project sequence must fail");
    assert!(matches!(error, TestdError::Corrupt(_)));
    drop(store);
    assert_eq!(durable_snapshot(&path), before);
    std::fs::remove_file(path).expect("remove test database");
    std::fs::remove_dir_all(roots_base).expect("remove fixture roots");
}

#[test]
fn malformed_empty_and_wrong_type_project_metadata_fail_closed() {
    for (label, value) in [("empty", b"".as_slice()), ("wrong-type", br#"\"one\""#)] {
        let path = database_path(label);
        let store = create_store(&path);
        drop(store);
        seed_database(&path, &[], &[("project:alpha", value)], &[]);
        assert_reopen_corrupt_without_mutation(&path);
        std::fs::remove_file(path).expect("remove test database");
    }
}

#[test]
fn conflicting_project_inventory_fails_closed_without_mutation() {
    let path = database_path("conflict");
    seed_database(
        &path,
        &[("job-a", "project-a", 1)],
        &[("project:project-a", br#"2"#)],
        &[],
    );
    assert_reopen_corrupt_without_mutation(&path);
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn project_sequences_are_independent_and_unrelated_event_keys_are_ignored() {
    let path = database_path("independent");
    seed_database(
        &path,
        &[("job-a", "project-a", 1), ("job-b", "project-b", 1)],
        &[
            ("project:project-a", br#"1"#),
            ("project:project-b", br#"1"#),
        ],
        &[("unrelated:not-a-sequence", b"not-an-event")],
    );
    let store = create_store(&path);
    assert_eq!(
        store
            .get("job-a")
            .expect("read project a")
            .unwrap()
            .project_sequence,
        1
    );
    assert_eq!(
        store
            .get("job-b")
            .expect("read project b")
            .unwrap()
            .project_sequence,
        1
    );
    drop(store);
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn matching_empty_non_decimal_overflow_and_ambiguous_event_suffixes_fail_closed() {
    for (label, suffix, second) in [
        ("empty-event", "", None),
        ("non-decimal-event", "not-a-number", None),
        ("overflow-event", "18446744073709551616", None),
        ("ambiguous-event", "1", Some("01")),
    ] {
        let path = database_path(label);
        let first = format!("job-a:{suffix}");
        let second_key = second.map(|value| format!("job-a:{value}"));
        let mut events = vec![(first, b"event".as_slice())];
        if let Some(key) = &second_key {
            events.push((key.clone(), b"event".as_slice()));
        }
        let event_refs = events
            .iter()
            .map(|(key, value)| (key.as_str(), *value))
            .collect::<Vec<_>>();
        seed_database(
            &path,
            &[("job-a", "project-a", 1)],
            &[("project:project-a", br#"1"#)],
            &event_refs,
        );
        assert_reopen_corrupt_without_mutation(&path);
        std::fs::remove_file(path).expect("remove test database");
    }
}
