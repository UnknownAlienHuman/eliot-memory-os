use super::{CanonicalStore, CognitiveProjectionFamily, CognitiveProjectionPublicationStatus};
use crate::DbClientSet;
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, CredentialProviderKind, EpistemicStatus, GovernorConfig,
    IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions, MemoryConfidence, MemoryRevision,
    MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence, ReadConsistencyMode,
    RecallL0Request, RecallL0Response, SemanticCommandKind, SurrealServerConfig, TaintClass,
    TaskId, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use time::OffsetDateTime;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB 3.1.4 guardian"]
async fn c7_03b_real_fts_candidates_rank_five_provider_free_cases() -> TestResult {
    let config = isolated_config()?;
    require_exact_surreal_version(&config)?;
    let owned_pid = guardian_pid(&config)?;
    require(
        eliot_windows_ipc::process_is_alive(owned_pid)?,
        "the isolated SurrealDB guardian is not alive",
    )?;

    let clients = Arc::new(DbClientSet::start(config).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = run_five_cases(&store).await;
    let shutdown_result = clients.shutdown().await;

    match (body_result, shutdown_result) {
        (Ok(()), Ok(_)) => require(
            eliot_windows_ipc::process_is_alive(owned_pid)?,
            "DbClientSet shutdown stopped the external isolated guardian",
        ),
        (Err(body_error), Ok(_)) => Err(body_error),
        (Ok(()), Err(shutdown_error)) => Err(Box::new(shutdown_error) as Box<dyn Error>),
        (Err(body_error), Err(shutdown_error)) => Err(format!(
            "FTS live proof failed: {body_error}; explicit DbClientSet shutdown also failed: {shutdown_error}"
        )
        .into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB 3.1.4 guardian"]
async fn c7_03c_real_projection_lease_preserves_retry_and_block_barriers() -> TestResult {
    let config = isolated_config()?;
    require_exact_surreal_version(&config)?;
    let owned_pid = guardian_pid(&config)?;
    require(
        eliot_windows_ipc::process_is_alive(owned_pid)?,
        "the isolated SurrealDB guardian is not alive",
    )?;

    let clients = Arc::new(DbClientSet::start(config).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = run_projection_lease_cases(&store, &clients).await;
    let shutdown_result = clients.shutdown().await;
    match (body_result, shutdown_result) {
        (Ok(()), Ok(_)) => require(
            eliot_windows_ipc::process_is_alive(owned_pid)?,
            "DbClientSet shutdown stopped the external isolated guardian",
        ),
        (Err(body_error), Ok(_)) => Err(body_error),
        (Ok(()), Err(shutdown_error)) => Err(Box::new(shutdown_error) as Box<dyn Error>),
        (Err(body_error), Err(shutdown_error)) => Err(format!(
            "projection lease proof failed: {body_error}; shutdown also failed: {shutdown_error}"
        )
        .into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB 3.1.4 guardian"]
async fn c7_03c_real_same_revision_dependency_dirty_fence_is_atomic() -> TestResult {
    let config = isolated_config()?;
    require_exact_surreal_version(&config)?;
    let owned_pid = guardian_pid(&config)?;
    let clients = Arc::new(DbClientSet::start(config).await?);
    let store = CanonicalStore::from_client_set(Arc::clone(&clients));
    let body_result = run_same_revision_dependency_dirty_cases(&store).await;
    let shutdown_result = clients.shutdown().await;
    match (body_result, shutdown_result) {
        (Ok(()), Ok(_)) => require(
            eliot_windows_ipc::process_is_alive(owned_pid)?,
            "DbClientSet shutdown stopped the external isolated guardian",
        ),
        (Err(body_error), Ok(_)) => Err(body_error),
        (Ok(()), Err(shutdown_error)) => Err(Box::new(shutdown_error) as Box<dyn Error>),
        (Err(body_error), Err(shutdown_error)) => Err(format!(
            "same-revision dirty proof failed: {body_error}; shutdown also failed: {shutdown_error}"
        )
        .into()),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_same_revision_dependency_dirty_cases(store: &CanonicalStore) -> TestResult {
    store.migrate_schema().await?;
    let revision = MemoryRevision::new(5);
    let project_id = ProjectId::new_v7();
    store
        .publish_cognitive_projection_family_state(
            project_id,
            CognitiveProjectionFamily::DependencyDirty,
            revision,
            Some(revision),
            CognitiveProjectionPublicationStatus::Published,
            None,
        )
        .await?;
    store
        .enqueue_cognitive_projection_intent(
            project_id,
            "dependency-dirty:race-a",
            revision,
            &[CognitiveProjectionFamily::DependencyDirty],
        )
        .await?;
    require_dependency_status(
        store,
        project_id,
        CognitiveProjectionPublicationStatus::Stale,
        "first same-revision enqueue did not atomically stale the family",
    )
    .await?;
    let first = store
        .claim_cognitive_projection_project("dirty-race-owner-a", 10, 8)
        .await?
        .ok_or("first same-revision dirty row was not leased")?;
    store
        .enqueue_cognitive_projection_intent(
            project_id,
            "dependency-dirty:race-b",
            revision,
            &[CognitiveProjectionFamily::DependencyDirty],
        )
        .await?;
    let publish_during_race = store
        .publish_cognitive_projection_family_state(
            project_id,
            CognitiveProjectionFamily::DependencyDirty,
            revision,
            Some(revision),
            CognitiveProjectionPublicationStatus::Published,
            None,
        )
        .await?;
    require(
        publish_during_race.status == CognitiveProjectionPublicationStatus::Stale,
        "projection publication ignored a newer non-applied dirty watermark",
    )?;
    store.complete_cognitive_projection_through(&first).await?;
    require_dependency_status(
        store,
        project_id,
        CognitiveProjectionPublicationStatus::Stale,
        "completing A published over still-pending same-revision B",
    )
    .await?;
    let second = store
        .claim_cognitive_projection_project("dirty-race-owner-b", 10, 8)
        .await?
        .ok_or("second same-revision dirty row was not leased")?;
    store
        .block_cognitive_projection(&second, "synthetic same-revision block")
        .await?;
    require_dependency_status(
        store,
        project_id,
        CognitiveProjectionPublicationStatus::Blocked,
        "blocking the remaining dirty lease was not atomic with family state",
    )
    .await?;

    let complete_then_enqueue_project = ProjectId::new_v7();
    store
        .publish_cognitive_projection_family_state(
            complete_then_enqueue_project,
            CognitiveProjectionFamily::DependencyDirty,
            revision,
            Some(revision),
            CognitiveProjectionPublicationStatus::Published,
            None,
        )
        .await?;
    store
        .enqueue_cognitive_projection_intent(
            complete_then_enqueue_project,
            "dependency-dirty:complete-first",
            revision,
            &[CognitiveProjectionFamily::DependencyDirty],
        )
        .await?;
    let complete_first = store
        .claim_cognitive_projection_project("dirty-complete-first", 10, 8)
        .await?
        .ok_or("complete-first dirty row was not leased")?;
    store
        .publish_cognitive_projection_family_state(
            complete_then_enqueue_project,
            CognitiveProjectionFamily::DependencyDirty,
            revision,
            Some(revision),
            CognitiveProjectionPublicationStatus::Published,
            None,
        )
        .await?;
    store
        .complete_cognitive_projection_through(&complete_first)
        .await?;
    require_dependency_status(
        store,
        complete_then_enqueue_project,
        CognitiveProjectionPublicationStatus::Published,
        "last exact dirty completion did not publish its family",
    )
    .await?;
    store
        .enqueue_cognitive_projection_intent(
            complete_then_enqueue_project,
            "dependency-dirty:enqueue-after-complete",
            revision,
            &[CognitiveProjectionFamily::DependencyDirty],
        )
        .await?;
    require_dependency_status(
        store,
        complete_then_enqueue_project,
        CognitiveProjectionPublicationStatus::Stale,
        "enqueue-after-complete did not atomically downgrade the family",
    )
    .await?;

    // A retryable row must not downgrade an independently established hard
    // family block. The coordinator is single-owner today, but keeping this
    // mutation monotonic also protects recovery and future scheduling changes.
    let blocked_retry_project = ProjectId::new_v7();
    let blocked_retry_event_id = format!("dependency-dirty:blocked-retry:{blocked_retry_project}");
    store
        .publish_cognitive_projection_family_state(
            blocked_retry_project,
            CognitiveProjectionFamily::DependencyDirty,
            revision,
            None,
            CognitiveProjectionPublicationStatus::Blocked,
            Some("synthetic existing hard block"),
        )
        .await?;
    store
        .enqueue_cognitive_projection_intent(
            blocked_retry_project,
            &blocked_retry_event_id,
            revision,
            &[CognitiveProjectionFamily::DependencyDirty],
        )
        .await?;
    let blocked_retry_lease = store
        .claim_cognitive_projection_project("dirty-blocked-retry-owner", 10, 8)
        .await?
        .ok_or("blocked-retry dirty row was not leased")?;
    store
        .fail_cognitive_projection_retryable(
            &blocked_retry_lease,
            "synthetic retryable projection error",
            10,
        )
        .await?;
    let blocked_retry_state = store
        .cognitive_projection_family_states(blocked_retry_project)
        .await?
        .into_iter()
        .find(|state| state.family == CognitiveProjectionFamily::DependencyDirty)
        .ok_or("blocked-retry dependency family state was not persisted")?;
    require(
        blocked_retry_state.status == CognitiveProjectionPublicationStatus::Blocked
            && blocked_retry_state.last_error.as_deref() == Some("synthetic existing hard block"),
        "retryable failure downgraded or rewrote an existing dependency hard block",
    )
}

async fn require_dependency_status(
    store: &CanonicalStore,
    project_id: ProjectId,
    expected: CognitiveProjectionPublicationStatus,
    message: &str,
) -> TestResult {
    let states = store.cognitive_projection_family_states(project_id).await?;
    require(
        states.iter().any(|state| {
            state.family == CognitiveProjectionFamily::DependencyDirty && state.status == expected
        }),
        message,
    )
}

#[allow(clippy::too_many_lines)]
async fn run_projection_lease_cases(store: &CanonicalStore, clients: &DbClientSet) -> TestResult {
    store.migrate_schema().await?;
    let project_id = ProjectId::new_v7();
    let inverted_project = ProjectId::new_v7();
    let unrelated_project = ProjectId::new_v7();
    establish_projection_project(store, project_id, "lease-main").await?;
    establish_projection_project(store, inverted_project, "lease-inverted").await?;
    establish_projection_project(store, unrelated_project, "lease-unrelated").await?;

    let first_project_text = project_id.to_string();
    let second_project_text = inverted_project.to_string();
    require(
        first_project_text[..8] == second_project_text[..8],
        "same-millisecond UUIDv7 recovery fixture did not share its coercible prefix",
    )?;
    let recovery_revision = MemoryRevision::new(1);
    let recovery_families = [
        CognitiveProjectionFamily::Search,
        CognitiveProjectionFamily::Cue,
        CognitiveProjectionFamily::DependencyDirty,
    ];
    let first_recovery_id = format!("recovery:{project_id}:{}", recovery_revision.value());
    let second_recovery_id = format!("recovery:{inverted_project}:{}", recovery_revision.value());
    let first_recovery = store
        .enqueue_cognitive_projection_intent(
            project_id,
            &first_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    let second_recovery = store
        .enqueue_cognitive_projection_intent(
            inverted_project,
            &second_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    require(
        first_recovery.event_id == first_recovery_id
            && second_recovery.event_id == second_recovery_id,
        "transport-safe recovery identifiers did not round-trip exactly",
    )?;
    require_projection_outbox_write_ids_are_strings(clients, 5).await?;

    let pending_before_replay = store.cognitive_projection_backlog().await?.pending;
    let replayed_recovery = store
        .enqueue_cognitive_projection_intent(
            project_id,
            &first_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    require(
        replayed_recovery == first_recovery
            && store.cognitive_projection_backlog().await?.pending == pending_before_replay,
        "identical recovery replay created a second durable intent",
    )?;
    require(
        store
            .enqueue_cognitive_projection_intent(
                project_id,
                &first_recovery_id,
                MemoryRevision::new(2),
                &[CognitiveProjectionFamily::Search],
            )
            .await
            .is_err(),
        "divergent recovery replay bypassed the durable intent conflict fence",
    )?;

    let expected_recovery_ids =
        HashSet::from([first_recovery_id.clone(), second_recovery_id.clone()]);
    let mut leased_recovery_ids = HashSet::new();
    for owner in ["recovery-proof-one", "recovery-proof-two"] {
        let lease = store
            .claim_cognitive_projection_project(owner, 5, 8)
            .await?
            .ok_or("transport-safe recovery intent was not claimable")?;
        require(
            lease.claimed_rows == 1 && lease.write_ids.len() == 1,
            "recovery lease did not preserve one exact durable row",
        )?;
        leased_recovery_ids.insert(lease.write_ids[0].clone());
        store.complete_cognitive_projection_through(&lease).await?;
    }
    require(
        leased_recovery_ids == expected_recovery_ids,
        "recovery claims did not preserve both exact transport-safe identifiers",
    )?;

    let applied_replay = store
        .enqueue_cognitive_projection_intent(
            project_id,
            &first_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    let clean_before_rearm = store.cognitive_projection_backlog().await?;
    require(
        applied_replay.event_id == first_recovery_id
            && applied_replay.status == "applied"
            && clean_before_rearm.pending == 0
            && clean_before_rearm.leased == 0
            && clean_before_rearm.retryable == 0
            && clean_before_rearm.blocked == 0,
        "generic recovery replay changed an applied intent",
    )?;

    let rearmed_recovery = store
        .rearm_cognitive_projection_recovery_intent(
            project_id,
            &first_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    let rearmed_backlog = store.cognitive_projection_backlog().await?;
    require(
        rearmed_recovery.event_id == first_recovery_id
            && rearmed_recovery.project_id == project_id
            && rearmed_recovery.updated_revision == recovery_revision
            && rearmed_recovery.families == recovery_families
            && rearmed_recovery.status == "pending"
            && rearmed_backlog.pending == 1
            && rearmed_backlog.leased == 0
            && rearmed_backlog.retryable == 0
            && rearmed_backlog.blocked == 0,
        "recovery-specific replay did not re-arm the exact applied intent",
    )?;

    let rearmed_lease = store
        .claim_cognitive_projection_project("recovery-rearm-proof", 5, 8)
        .await?
        .ok_or("re-armed recovery intent was not claimable")?;
    require(
        rearmed_lease.project_id == project_id
            && rearmed_lease.write_ids == [first_recovery_id.as_str()]
            && rearmed_lease.families == recovery_families
            && rearmed_lease.claimed_rows == 1
            && rearmed_lease.max_attempt_count == 1,
        "re-armed recovery lease did not reset one-cycle attempt state",
    )?;
    store
        .complete_cognitive_projection_through(&rearmed_lease)
        .await?;

    let applied_after_rearm = store
        .enqueue_cognitive_projection_intent(
            project_id,
            &first_recovery_id,
            recovery_revision,
            &recovery_families,
        )
        .await?;
    let clean_after_rearm = store.cognitive_projection_backlog().await?;
    require(
        applied_after_rearm.event_id == first_recovery_id
            && applied_after_rearm.status == "applied"
            && clean_after_rearm.pending == 0
            && clean_after_rearm.leased == 0
            && clean_after_rearm.retryable == 0
            && clean_after_rearm.blocked == 0,
        "completed re-armed recovery intent left projection backlog",
    )?;

    let oldest_event_id = format!("lease-oldest:{project_id}");
    let newer_event_id = format!("lease-newer:{project_id}");
    store
        .enqueue_cognitive_projection_intent(
            project_id,
            &oldest_event_id,
            MemoryRevision::new(7),
            &[CognitiveProjectionFamily::Search],
        )
        .await?;
    let first = store
        .claim_cognitive_projection_project("lease-owner-one", 1, 8)
        .await?
        .ok_or("oldest projection intent was not leased")?;
    require(
        first.write_ids == [oldest_event_id.as_str()] && first.max_attempt_count == 1,
        "first projection lease did not bind the exact oldest row",
    )?;

    store
        .enqueue_cognitive_projection_intent(
            project_id,
            &newer_event_id,
            MemoryRevision::new(8),
            &[CognitiveProjectionFamily::Search],
        )
        .await?;
    require(
        store
            .claim_cognitive_projection_project("lease-overtake-active", 1, 8)
            .await?
            .is_none(),
        "a newer project row overtook an active older lease",
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let reclaimed = store
        .claim_cognitive_projection_project("lease-owner-two", 1, 8)
        .await?
        .ok_or("expired oldest lease was not reclaimed")?;
    require(
        reclaimed.write_ids == [oldest_event_id.as_str()] && reclaimed.max_attempt_count == 2,
        "expired reclaim did not preserve exact row identity and attempt count",
    )?;
    let mut forged = reclaimed.clone();
    forged.lease_owner = "forged-owner".to_owned();
    require(
        store
            .complete_cognitive_projection_through(&forged)
            .await
            .is_err(),
        "forged projection lease owner mutated the claimed row",
    )?;
    let mut forged_set = reclaimed.clone();
    forged_set.write_ids.push("forged-extra-row".to_owned());
    forged_set.claimed_rows += 1;
    require(
        store
            .complete_cognitive_projection_through(&forged_set)
            .await
            .is_err(),
        "forged projection lease row set mutated a strict subset",
    )?;
    let mut forged_family = reclaimed.clone();
    forged_family.families = vec![CognitiveProjectionFamily::Cue];
    require(
        store
            .complete_cognitive_projection_through(&forged_family)
            .await
            .is_err(),
        "forged projection lease family set passed exact mutation",
    )?;
    let mut forged_revision = reclaimed.clone();
    forged_revision.through_revision = MemoryRevision::new(
        reclaimed
            .through_revision
            .value()
            .checked_add(1)
            .ok_or("test revision overflow")?,
    );
    require(
        store
            .complete_cognitive_projection_through(&forged_revision)
            .await
            .is_err(),
        "forged projection lease revision passed exact mutation",
    )?;
    store
        .fail_cognitive_projection_retryable(&reclaimed, "synthetic retry", 1)
        .await?;
    require(
        store
            .claim_cognitive_projection_project("lease-overtake-retry", 1, 8)
            .await?
            .is_none(),
        "a newer project row overtook a not-yet-due retry barrier",
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let third = store
        .claim_cognitive_projection_project("lease-owner-three", 5, 8)
        .await?
        .ok_or("retryable oldest row did not become claimable")?;
    require(
        third.write_ids == [oldest_event_id.as_str()] && third.max_attempt_count == 3,
        "retry reclaim did not preserve strict project order",
    )?;
    store
        .block_cognitive_projection(&third, "synthetic deterministic block")
        .await?;
    require(
        store
            .claim_cognitive_projection_project("lease-overtake-block", 5, 8)
            .await?
            .is_none(),
        "a newer project row overtook an older blocked barrier",
    )?;

    // Simulate a legacy/concurrent inversion: an active newer lease already
    // exists when an older revision is inserted. The global project lease
    // guard must still prevent a second owner.
    let inverted_newer_event_id = format!("lease-inverted-newer:{inverted_project}");
    let inverted_older_event_id = format!("lease-inverted-older:{inverted_project}");
    store
        .enqueue_cognitive_projection_intent(
            inverted_project,
            &inverted_newer_event_id,
            MemoryRevision::new(8),
            &[CognitiveProjectionFamily::Cue],
        )
        .await?;
    let active_newer = store
        .claim_cognitive_projection_project("lease-inverted-owner", 5, 8)
        .await?
        .ok_or("inverted newer row was not leased")?;
    store
        .enqueue_cognitive_projection_intent(
            inverted_project,
            &inverted_older_event_id,
            MemoryRevision::new(7),
            &[CognitiveProjectionFamily::Cue],
        )
        .await?;
    require(
        store
            .claim_cognitive_projection_project("lease-inverted-second-owner", 5, 8)
            .await?
            .is_none(),
        "an older pending row created a second active project lease",
    )?;
    store
        .complete_cognitive_projection_through(&active_newer)
        .await?;
    let inverted_older = store
        .claim_cognitive_projection_project("lease-inverted-cleanup", 5, 8)
        .await?
        .ok_or("inverted older row did not become claimable after lease completion")?;
    store
        .complete_cognitive_projection_through(&inverted_older)
        .await?;

    let unrelated_event_id = format!("lease-unrelated:{unrelated_project}");
    store
        .enqueue_cognitive_projection_intent(
            unrelated_project,
            &unrelated_event_id,
            MemoryRevision::new(1),
            &[CognitiveProjectionFamily::Cue],
        )
        .await?;
    let unrelated = store
        .claim_cognitive_projection_project("lease-unrelated-owner", 5, 8)
        .await?
        .ok_or("blocked project incorrectly stalled an unrelated project")?;
    require(
        unrelated.project_id == unrelated_project
            && unrelated.write_ids == [unrelated_event_id.as_str()],
        "lease selection crossed the strict unrelated-project boundary",
    )?;
    store
        .complete_cognitive_projection_through(&unrelated)
        .await?;

    let inventory = store.load_cognitive_projection_projects(0, 100).await?;
    require(
        !inventory.truncated,
        "lease proof project inventory was unexpectedly truncated",
    )?;
    require_project_backlog(&inventory, project_id, 1, 0, 0, 1)?;
    require_project_backlog(&inventory, inverted_project, 0, 0, 0, 0)?;
    require_project_backlog(&inventory, unrelated_project, 0, 0, 0, 0)
}

async fn establish_projection_project(
    store: &CanonicalStore,
    project_id: ProjectId,
    label: &str,
) -> TestResult {
    let envelope = retrieval_envelope(
        project_id,
        TaskId::new_v7(),
        vec![claim(format!("{label} project head"), label)],
    )?;
    let expected_write_id = envelope.write_id.to_string();
    store.apply_write_envelope(&envelope).await?;
    let lease = store
        .claim_cognitive_projection_project(&format!("{label}-bootstrap-owner"), 10, 8)
        .await?
        .ok_or("project bootstrap projection row was not leased")?;
    require(
        lease.project_id == project_id && lease.write_ids == [expected_write_id.as_str()],
        "project bootstrap lease crossed its canonical head boundary",
    )?;
    store.complete_cognitive_projection_through(&lease).await?;
    Ok(())
}

fn require_project_backlog(
    inventory: &super::CognitiveProjectionProjectPage,
    project_id: ProjectId,
    pending: u64,
    leased: u64,
    retryable: u64,
    blocked: u64,
) -> TestResult {
    let project = inventory
        .projects
        .iter()
        .find(|project| project.project_id == project_id)
        .ok_or("lease proof project was absent from project-scoped inventory")?;
    require(
        project.pending == pending
            && project.leased == leased
            && project.retryable == retryable
            && project.blocked == blocked
            && (pending == 0) == project.oldest_pending_created_at.is_none(),
        &format!("lease proof project backlog was unexpected: {project:?}"),
    )
}

async fn require_projection_outbox_write_ids_are_strings(
    clients: &DbClientSet,
    minimum_rows: u64,
) -> TestResult {
    let value = clients
        .execute_admin_sql(
            "LET $all = SELECT VALUE id FROM memory_search_outbox; LET $invalid = SELECT VALUE id FROM memory_search_outbox WHERE type::is_string(write_id) = false; RETURN { total: array::len($all), non_string: array::len($invalid) };",
            json!({}),
        )
        .await?;
    let result = value
        .as_array()
        .and_then(|statements| statements.last())
        .and_then(|statement| statement.get("result"))
        .ok_or("projection write-id type query omitted its result")?;
    let total = result
        .get("total")
        .and_then(serde_json::Value::as_u64)
        .ok_or("projection write-id type query omitted total")?;
    let non_string = result
        .get("non_string")
        .and_then(serde_json::Value::as_u64)
        .ok_or("projection write-id type query omitted non_string")?;
    require(
        total >= minimum_rows && non_string == 0,
        &format!("projection outbox write-id type invariant failed: {result}"),
    )
}

#[allow(clippy::too_many_lines)]
async fn run_five_cases(store: &CanonicalStore) -> TestResult {
    store.migrate_schema().await?;
    assert_bound_typed_fts_route()?;

    let rollback_project_id = ProjectId::new_v7();
    let rollback_envelope = retrieval_envelope(
        rollback_project_id,
        TaskId::new_v7(),
        vec![claim(
            "transaction rollback sentinel".to_owned(),
            "rollback",
        )],
    )?;
    require(
        store
            .apply_write_envelope_with_outbox_failure(&rollback_envelope)
            .await
            .is_err(),
        "failure injection unexpectedly committed the canonical transaction",
    )?;
    require(
        store
            .write_receipt_by_id(&rollback_envelope.write_id)
            .await?
            .is_none(),
        "canonical receipt survived an outbox failure in the same transaction",
    )?;
    require(
        store
            .claim_cognitive_projection_project("fts-rollback-proof", 30, 8)
            .await?
            .is_none(),
        "projection outbox survived a transaction that rolled back canonical truth",
    )?;

    let project_id = ProjectId::new_v7();
    let foreign_project_id = ProjectId::new_v7();

    let foreign_claims = (0..260)
        .map(|ordinal| {
            claim(
                format!("shared project isolation marker foreign distractor {ordinal:03}"),
                "project-isolation-foreign",
            )
        })
        .collect::<Vec<_>>();
    let foreign_handles = foreign_claims
        .iter()
        .map(|item| format!("claim:{}", item.claim_id))
        .collect::<HashSet<_>>();
    require(
        foreign_handles.len() > 257,
        "project-isolation corpus must contain more than 257 foreign same-term rows",
    )?;

    let mut local_claims = (0..32)
        .map(|ordinal| {
            claim(
                format!("english retrieval needle distractor {ordinal:02}"),
                "english-distractor",
            )
        })
        .collect::<Vec<_>>();
    let english_target = claim(
        "english unique retrieval needle alpha omega".to_owned(),
        "english-target",
    );
    let unicode_target = claim(
        "Русская память находит Юникод границу библиотекаря".to_owned(),
        "unicode-target",
    );
    let opaque_target = claim(
        "opaque exact handle target".to_owned(),
        "opaque-handle-target",
    );
    let local_isolation_target = claim(
        "shared project isolation marker local authoritative hit".to_owned(),
        "project-isolation-local",
    );
    let english_handle = format!("claim:{}", english_target.claim_id);
    let unicode_handle = format!("claim:{}", unicode_target.claim_id);
    let opaque_handle = format!("claim:{}", opaque_target.claim_id);
    let local_isolation_handle = format!("claim:{}", local_isolation_target.claim_id);
    local_claims.extend([
        english_target,
        unicode_target,
        opaque_target,
        local_isolation_target,
    ]);

    let foreign_receipt = store
        .apply_write_envelope(&retrieval_envelope(
            foreign_project_id,
            TaskId::new_v7(),
            foreign_claims,
        )?)
        .await?;
    require(
        foreign_receipt.status == WriteStatus::Committed,
        "foreign project corpus did not commit through the canonical typed write path",
    )?;
    let local_receipt = store
        .apply_write_envelope(&retrieval_envelope(
            project_id,
            TaskId::new_v7(),
            local_claims,
        )?)
        .await?;
    require(
        local_receipt.status == WriteStatus::Committed,
        "local project corpus did not commit through the canonical typed write path",
    )?;

    store
        .rebuild_memory_search_projection(foreign_project_id)
        .await?;
    store.rebuild_memory_search_projection(project_id).await?;

    let plan = store
        .memory_search_query_plan(project_id, "english unique retrieval needle alpha omega")
        .await?;
    let plan_text = serde_json::to_string(&plan)?;
    require(
        plan_text.contains("FullTextScan"),
        "SurrealDB EXPLAIN did not select FullTextScan",
    )?;
    require(
        plan_text.contains("idx_memory_search_projection_fts_v1"),
        "SurrealDB EXPLAIN did not select idx_memory_search_projection_fts_v1",
    )?;

    // Case 1: the complete English target must outrank same-corpus distractors.
    let english = store
        .recall_l0(&recall_request(
            project_id,
            "english unique retrieval needle alpha omega",
        ))
        .await?;
    require_top_handle(&english, &english_handle, "English target")?;

    // Case 2: the production FTS path must retain Unicode terms end to end.
    let unicode = store
        .recall_l0(&recall_request(
            project_id,
            "Русская память Юникод библиотекаря",
        ))
        .await?;
    require_top_handle(&unicode, &unicode_handle, "Unicode target")?;

    // Case 3: an opaque exact handle bypasses lexical ambiguity and ranks first.
    let opaque = store
        .recall_l0(&recall_request(project_id, opaque_handle.clone()))
        .await?;
    require_top_handle(&opaque, &opaque_handle, "opaque exact handle")?;
    require(
        opaque
            .rank_trace
            .feature_scores
            .first()
            .is_some_and(|score| score.exact_identifier == 1_000),
        "opaque exact handle did not receive the exact-identifier rank feature",
    )?;

    // Case 4: both an empty normalized term set and a genuine miss are explicit no-memory.
    for (label, query) in [
        ("no normalized terms", "the and or"),
        ("no FTS hit", "quasar telemetry absent"),
    ] {
        let response = store.recall_l0(&recall_request(project_id, query)).await?;
        require(
            response.handles.is_empty()
                && response.rank_trace.no_useful_memory
                && response.memory_confidence == MemoryConfidence::None,
            &format!("{label} did not return the explicit no_useful_memory result"),
        )?;
    }

    // Case 5: >257 foreign same-term rows cannot consume the local project's FTS cap.
    let isolated = store
        .recall_l0(&recall_request(
            project_id,
            "shared project isolation marker",
        ))
        .await?;
    require_top_handle(
        &isolated,
        &local_isolation_handle,
        "project-isolated local hit",
    )?;
    require(
        isolated.rank_trace.candidates_considered <= 256,
        "FTS candidate loader exceeded the 256-row bound",
    )?;
    require(
        isolated
            .handles
            .iter()
            .all(|item| !foreign_handles.contains(&item.handle)),
        "foreign-project FTS rows leaked into the local result",
    )?;

    Ok(())
}

fn assert_bound_typed_fts_route() -> TestResult {
    let query = include_str!("../surql/load_memory_search_fts_candidates.surql");
    require(
        query.contains("search_document @0,OR@ $query_text")
            && query.contains("math::max(search::score(0)) AS relevance_score")
            && query.contains("GROUP BY handle")
            && query.contains("ORDER BY relevance_score DESC, authority_rank DESC, handle ASC"),
        "FTS loader must bind query_text in the checked-in SurQL template",
    )?;

    let source = include_str!("../canonical_store.rs");
    let Some(route_start) = source.find("pub async fn recall_l0") else {
        return Err("public recall_l0 source anchor is missing".into());
    };
    let route_tail = &source[route_start..];
    let Some(route_end) = route_tail.find("\n    async fn recall_l0_paged") else {
        return Err("recall_l0_fts_candidate end anchor is missing".into());
    };
    let route = &route_tail[..route_end];
    require(
        route.contains("NamedSurqlOp::LoadMemorySearchFtsCandidates")
            && route.contains("\"query_text\": memory_search_query_text(request)")
            && route.contains(".execute_value("),
        "FTS candidate route must use the typed named operation with bound variables",
    )?;
    require(
        !route.contains("execute_admin_sql") && !route.contains("execute_classified"),
        "FTS candidate route must not execute raw SQL",
    )?;
    require(
        !route.contains("rebuild_memory_search_projection"),
        "public recall must never rebuild a project synchronously",
    )
}

fn isolated_config() -> TestResult<SurrealServerConfig> {
    require(
        std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1"),
        "ELIOT_DISABLE_REAL_PROVIDER=1 is required for this provider-free live proof",
    )?;
    let mut config = GovernorConfig::default().db.surreal;
    config.exe = required_env("ELIOT_SURREAL_EXE")?;
    config.bind = required_env("ELIOT_TEST_SURREAL_BIND")?;
    config.endpoint = required_env("ELIOT_TEST_SURREAL_ENDPOINT")?;
    config.password_file = required_env("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
    config.storage = required_env("ELIOT_TEST_SURREAL_STORAGE")?;
    config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
    config.query_timeout_ms = 20_000;
    config.startup_timeout_ms = 20_000;
    Ok(config)
}

fn require_exact_surreal_version(config: &SurrealServerConfig) -> TestResult {
    let output = Command::new(&config.exe).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    require(
        output.status.success() && version.split_whitespace().next() == Some("3.1.4"),
        &format!(
            "C7-03B requires exactly SurrealDB 3.1.4, got {}",
            version.trim()
        ),
    )
}

fn required_env(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|error| format!("{name} is required: {error}").into())
}

fn guardian_pid(config: &SurrealServerConfig) -> TestResult<u32> {
    let storage = config
        .storage
        .strip_prefix("rocksdb:")
        .ok_or("isolated storage must use rocksdb:")?;
    let storage = PathBuf::from(storage);
    let owned_root = storage
        .parent()
        .ok_or("isolated storage has no owned root")?;
    read_pid(&owned_root.join("tmp").join("owned-surreal.pid"))
}

fn read_pid(path: &Path) -> TestResult<u32> {
    Ok(std::fs::read_to_string(path)?.trim().parse()?)
}

fn retrieval_envelope(
    project_id: ProjectId,
    task_id: TaskId,
    claims: Vec<ClaimCardInput>,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let write_id = WriteId::new_v7();
    let input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "project_id": project_id,
        "claims": claims,
    }))?)
    .to_hex()
    .to_string();
    Ok(MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash,
        policy_snapshot_id: Some("policy:c7-03b-fts-live".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "c7-03b-fts-live".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: Vec::new(),
        failures: Vec::new(),
        claims,
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    })
}

fn claim(statement: String, topic: &str) -> ClaimCardInput {
    ClaimCardInput {
        claim_id: ClaimId::new_v7(),
        statement,
        status: EpistemicStatus::Verified,
        payload: json!({ "topic": topic }),
    }
}

fn recall_request(project_id: ProjectId, query: impl Into<String>) -> RecallL0Request {
    RecallL0Request {
        project_id,
        query: query.into(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
        task_id: None,
        task_class_cues: Vec::new(),
        scope_refs: Vec::new(),
        concept_refs: Vec::new(),
    }
}

fn require_top_handle(
    response: &RecallL0Response,
    expected_handle: &str,
    label: &str,
) -> TestResult {
    require(
        response
            .handles
            .first()
            .is_some_and(|item| item.handle == expected_handle),
        &format!("{label} was not the first result"),
    )
}

fn require(condition: bool, message: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
