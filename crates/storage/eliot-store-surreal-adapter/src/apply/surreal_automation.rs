//! Canonical user-automation execution for the `SurrealDB` bridge
//! (issue #1779).
//!
//! Mirrors the reference contour's closed legs through the store-api wire
//! contract, persisted in five automation tables plus the ephemeral
//! `automation_continuation` owner table: `automation_revision` holds one
//! immutable row per `(automation_id, revision)` carrying the verbatim
//! Kernel-owned revision document; `automation_current` holds one
//! compare-and-set pointer per automation carrying the current revision
//! plus the closed admission state; `automation_invocation` holds one
//! create-only row per stable occurrence identity carrying the verbatim
//! invocation document; `automation_failure` holds one immutable row per
//! `(automation_id, revision, fingerprint)` carrying the verbatim
//! failure document with first-writer provenance; `automation_last_failure`
//! holds one last-wins pointer per automation naming the most recently
//! committed failure row. Revision and failure documents stay opaque:
//! lineage validity is Kernel-owned, and this module arbitrates keys,
//! pointers, and immutability only. Concurrent writers arbitrate through
//! the in-transaction compare-and-set inside the canonical transaction;
//! retries recompute from fresh rows, never from stale reads. Rows commit
//! inside the canonical transaction beside the receipt and outbox rows,
//! so rows, receipt, and outbox stay atomic.
//!
//! Revision rows are addressed by a joined record id
//! (`automation_id` + `\x1f` + `revision`). The join is collision-free by
//! construction: the wire contract rejects control characters in both
//! halves, so the unit separator can never occur inside either half and
//! splitting is unambiguous. The halves also travel as separate row
//! fields, so no reader ever parses the address.

use eliot_store_api::{
    AutomationContinuationBinding, AutomationContinuationDirection, AutomationContinuationFailure,
    AutomationContinuationOrder, AutomationContinuationOrderKey, AutomationContinuationQuery,
    AutomationContinuationReadBinding, AutomationContinuationRef, DecodedAutomationMutation,
    NamedMutationOperation, NamedReadOperation, StateFence, StoreError, TransitionClass,
    decode_automation_mutation, verify_automation_continuation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::fmt::Write as _;

use crate::SurrealAdapterConfig;
use crate::client::{self, RpcTransport};
use crate::error::AdapterError;
use crate::schema;

/// Joins one revision row address. Collision-free: neither half may
/// contain control characters per the wire contract.
fn revision_key(automation_id: &str, revision: &str) -> String {
    format!("{automation_id}\x1f{revision}")
}

/// One computed revision-row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AutomationRevisionWrite {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Verbatim canonical revision document.
    pub revision_json: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// One computed current-pointer write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AutomationCurrentWrite {
    /// Stable automation identity (record id).
    pub automation_id: String,
    /// Revision the pointer must name after this write.
    pub revision: String,
    /// Closed admission state for the pointer.
    pub configuration_state: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
    /// Current revision observed at pre-transaction read (`None` for creates).
    pub expected_revision: Option<String>,
}

/// One computed invocation-row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AutomationInvocationWrite {
    /// Stable occurrence identity (record id).
    pub occurrence_id: String,
    /// Stable automation identity.
    pub automation_id: String,
    /// Verbatim canonical invocation document.
    pub invocation_json: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// One computed failure-row write for the canonical transaction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AutomationFailureWrite {
    /// Canonical failure key (record id).
    pub failure_key: String,
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision that owns the failure class.
    pub revision: String,
    /// Stable occurrence identity retained as history context.
    pub occurrence_id: String,
    /// Deterministic failure-class fingerprint.
    pub fingerprint: String,
    /// Verbatim canonical failure document.
    pub failure_json: String,
    /// First-writer operation identity.
    pub source_operation_id: String,
    /// Admission fence of the transition.
    pub state_fence: StateFence,
    /// Scope provenance from the transition envelope.
    pub scope_id: String,
    /// Task-binding provenance from the transition envelope, when bound.
    pub task_id: Option<String>,
}

/// One computed last-failure-pointer write for the canonical
/// transaction. Last write wins; no expected revision.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AutomationLastFailureWrite {
    /// Stable automation identity (record id).
    pub automation_id: String,
    /// Failure key of the most recently committed failure row.
    pub failure_key: String,
}

/// Computed automation row writes for one admitted transition.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct AutomationWrites {
    /// Revision creates in admitted command order.
    pub revisions: Vec<AutomationRevisionWrite>,
    /// Current-pointer creates/updates in admitted command order.
    pub currents: Vec<AutomationCurrentWrite>,
    /// Invocation creates in admitted command order.
    pub invocations: Vec<AutomationInvocationWrite>,
    /// Failure creates/converges in admitted command order.
    pub failures: Vec<AutomationFailureWrite>,
    /// Last-failure pointer moves in admitted command order.
    pub last_failures: Vec<AutomationLastFailureWrite>,
}

/// Stored revision row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredAutomationRevision {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub revision: String,
    /// Verbatim canonical revision document.
    pub revision_json: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Stored current-pointer shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredAutomationCurrent {
    /// Stable automation identity.
    pub automation_id: String,
    /// Revision the pointer names.
    pub revision: String,
    /// Closed admission state.
    pub configuration_state: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Stored invocation row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredAutomationInvocation {
    /// Stable occurrence identity.
    pub occurrence_id: String,
    /// Stable automation identity.
    pub automation_id: String,
    /// Verbatim canonical invocation document.
    pub invocation_json: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

/// Stored failure row shape as projected by reads.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StoredAutomationFailure {
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision that owns the failure class.
    pub revision: String,
    /// Stable occurrence identity retained as history context.
    pub occurrence_id: String,
    /// Deterministic failure-class fingerprint.
    pub fingerprint: String,
    /// Verbatim canonical failure document.
    pub failure_json: String,
    /// First-writer operation identity.
    pub source_operation_id: String,
    /// Admission fence.
    pub state_fence: StateFence,
}

const CONTINUATION_GUARD_ID: &str = "owner_guard";
const CONTINUATION_GUARD_KIND: &str = "owner_guard";
const CONTINUATION_ACTIVE_KIND: &str = "active";
const CONTINUATION_TERMINAL_KIND: &str = "terminal";
const CONTINUATION_EXPIRY_REASON: &str = "expired";
const CONTINUATION_GUARD_CONFLICT: &str = "automation_continuation_guard_conflict";
const CONTINUATION_PARENT_CONFLICT: &str = "automation_continuation_parent_conflict";

/// Owner metadata retained behind one opaque V2 reference. The row boundary
/// exists only here; callers can submit only the record identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AutomationContinuationMetadata {
    read_operation: String,
    query: String,
    include_retired: bool,
    automation_id: String,
    read_revision: String,
    state_fence: StateFence,
    order_key: String,
    direction: String,
    exclusive_returned_tail: String,
    max_records: u16,
    issuer_identity: String,
    issuer_generation: u64,
}

/// Active continuation record. Metadata contains no history/invocation row
/// bodies and is bounded by the shared continuation policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ActiveAutomationContinuation {
    record_kind: String,
    identifier: String,
    metadata: AutomationContinuationMetadata,
    creation_revision: u64,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    // Empty string is the persisted no-successor marker; this avoids treating
    // Surreal JSON NULL/NONE wire distinctions as authorization state.
    successor_identifier: String,
    metadata_bytes: usize,
}

/// Expired capability tombstone. It retains enough provenance to classify an
/// expired reference explicitly, without retaining the row boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TerminalAutomationContinuation {
    record_kind: String,
    identifier: String,
    creation_revision: u64,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    reclaim_after_unix_ms: u64,
    issuer_identity: String,
    issuer_generation: u64,
    terminal_reason: String,
    metadata_bytes: usize,
}

/// Single contention row serializing quota/reclamation and child-link writes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AutomationContinuationGuard {
    record_kind: String,
    identifier: String,
    sequence: u64,
    active_records: usize,
    active_metadata_bytes: usize,
    terminal_records: usize,
    terminal_metadata_bytes: usize,
}

#[derive(Debug)]
struct AutomationContinuationInventory {
    guard: AutomationContinuationGuard,
    active: Vec<ActiveAutomationContinuation>,
    terminal: Vec<TerminalAutomationContinuation>,
}

enum ContinuationParentIssue {
    Root,
    Continue(Box<ActiveAutomationContinuation>),
    Replay(String),
}

struct ReclaimedContinuationRows {
    active: Vec<ActiveAutomationContinuation>,
    expired_active: Vec<ActiveAutomationContinuation>,
    terminal: Vec<TerminalAutomationContinuation>,
}

struct AutomationContinuationIssuePlan {
    next_guard: AutomationContinuationGuard,
    expired_active: Vec<ActiveAutomationContinuation>,
    deleted_terminal: Vec<TerminalAutomationContinuation>,
    retained_terminal_ids: std::collections::BTreeSet<String>,
    linked_parent: Option<ActiveAutomationContinuation>,
    child: ActiveAutomationContinuation,
}

/// Ensures the automation tables exist (idempotent).
///
/// Schemaless tables auto-create on write, but reads and the
/// in-transaction compare-and-set fail closed on missing tables. This
/// one-shot definition keeps first use on a fresh database exact; it
/// changes no migration chain and carries no data.
async fn ensure_automation_tables(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let sql = format!(
        "DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS; DEFINE TABLE IF NOT EXISTS {} SCHEMALESS;",
        crate::schema::table::AUTOMATION_REVISION,
        crate::schema::table::AUTOMATION_CURRENT,
        crate::schema::table::AUTOMATION_INVOCATION,
        crate::schema::table::AUTOMATION_FAILURE,
        crate::schema::table::AUTOMATION_LAST_FAILURE
    );
    let mut response =
        client::query(db, config, "automation.ensure_tables", &sql, Map::new()).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(())
}

/// Computes the stable Surreal owner identity and schema incarnation used in
/// retained bindings. Canonical owner fields are hashed so identifiers,
/// namespaces, and database names do not travel in the public reference.
pub(crate) fn automation_continuation_owner(
    config: &SurrealAdapterConfig,
) -> Result<(String, u64), AdapterError> {
    let generation = config.expected_schema_generation.as_str();
    let generation_major = generation
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        .filter(|major| *major > 0)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "surreal.continuation.generation",
            reason: "schema generation must begin with a positive numeric major version",
        }))?;
    let identity_material = eliot_store_api::canonical_json_bytes(&(
        "eliot.surreal.automation-continuation-owner.v1",
        crate::config::ADAPTER_NAME,
        config.installation_id.as_str(),
        config.namespace.as_str(),
        config.database.as_str(),
        generation,
    ))
    .map_err(|_| AdapterError::PartialOutcome)?;
    let identity = format!(
        "surreal-owner:{}",
        eliot_store_api::sha256_hex(&identity_material)
    );
    Ok((identity, generation_major))
}

fn continuation_query_name(query: AutomationContinuationQuery) -> &'static str {
    match query {
        AutomationContinuationQuery::History => "history",
        AutomationContinuationQuery::Invocations => "invocations",
    }
}

fn continuation_query_from_name(name: &str) -> Option<AutomationContinuationQuery> {
    match name {
        "history" => Some(AutomationContinuationQuery::History),
        "invocations" => Some(AutomationContinuationQuery::Invocations),
        _ => None,
    }
}

fn continuation_order(query: AutomationContinuationQuery) -> AutomationContinuationOrder {
    AutomationContinuationOrder {
        key: match query {
            AutomationContinuationQuery::History => AutomationContinuationOrderKey::Revision,
            AutomationContinuationQuery::Invocations => {
                AutomationContinuationOrderKey::OccurrenceId
            }
        },
        direction: AutomationContinuationDirection::Ascending,
    }
}

fn continuation_metadata_bytes(
    record: &ActiveAutomationContinuation,
) -> Result<usize, AdapterError> {
    // Normalize the accounting field while measuring the complete serialized
    // owner metadata. This keeps the byte count deterministic without
    // self-referential sizing.
    let mut measured = record.clone();
    measured.metadata_bytes = 0;
    serde_json::to_vec(&measured)
        .map(|bytes| bytes.len())
        .map_err(|_| AdapterError::PartialOutcome)
}

fn continuation_tombstone_bytes(
    record: &TerminalAutomationContinuation,
) -> Result<usize, AdapterError> {
    let mut measured = record.clone();
    measured.metadata_bytes = 0;
    serde_json::to_vec(&measured)
        .map(|bytes| bytes.len())
        .map_err(|_| AdapterError::PartialOutcome)
}

fn continuation_failure(failure: AutomationContinuationFailure) -> AdapterError {
    AdapterError::Store(StoreError::AutomationContinuation(failure))
}

fn invalid_continuation() -> AdapterError {
    continuation_failure(AutomationContinuationFailure::InvalidOrUnknown)
}

fn stale_continuation() -> AdapterError {
    continuation_failure(AutomationContinuationFailure::StaleSnapshot)
}

fn parse_active_continuation(value: Value) -> Result<ActiveAutomationContinuation, AdapterError> {
    serde_json::from_value(value).map_err(|_| invalid_continuation())
}

fn parse_terminal_continuation(
    value: Value,
) -> Result<TerminalAutomationContinuation, AdapterError> {
    serde_json::from_value(value).map_err(|_| invalid_continuation())
}

fn parse_continuation_guard(value: Value) -> Result<AutomationContinuationGuard, AdapterError> {
    let guard: AutomationContinuationGuard =
        serde_json::from_value(value).map_err(|_| AdapterError::PartialOutcome)?;
    if guard.record_kind != CONTINUATION_GUARD_KIND {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(guard)
}

/// Creates the quota guard on the first truncated page. This is deliberately
/// called only from issuance, never from the read resolver or range path.
async fn ensure_continuation_guard(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<(), AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "continuation_table".to_owned(),
        json!(schema::table::AUTOMATION_CONTINUATION),
    );
    bindings.insert("guard_id".to_owned(), json!(CONTINUATION_GUARD_ID));
    bindings.insert(
        "guard_record".to_owned(),
        json!({
            "record_kind": CONTINUATION_GUARD_KIND,
            "identifier": CONTINUATION_GUARD_ID,
            "sequence": 0_u64,
            "active_records": 0_usize,
            "active_metadata_bytes": 0_usize,
            "terminal_records": 0_usize,
            "terminal_metadata_bytes": 0_usize,
        }),
    );
    // This CREATE is the only code path that defines the schemaless table.
    // A duplicate means another issuer already established the guard; the
    // following inventory read validates the persisted shape and counters.
    let sql = "CREATE type::record($continuation_table, $guard_id) CONTENT $guard_record;";
    let mut response = client::query(
        db,
        config,
        "automation.continuation.ensure_guard",
        sql,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if errors.is_empty()
        || errors.iter().any(|error| {
            let folded = error.to_ascii_lowercase();
            folded.contains("already exists") || folded.contains("duplicate")
        })
    {
        return Ok(());
    }
    Err(AdapterError::PartialOutcome)
}

/// Reads the bounded continuation inventory and verifies that the persisted
/// quota counters still describe it exactly before planning any mutation.
async fn read_continuation_inventory(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
) -> Result<AutomationContinuationInventory, AdapterError> {
    let sql = format!(
        "SELECT * FROM {} ORDER BY identifier;",
        schema::table::AUTOMATION_CONTINUATION
    );
    let mut response = client::query(
        db,
        config,
        "automation.continuation.inventory",
        &sql,
        Map::new(),
    )
    .await?;
    let errors = response.take_errors();
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let values: Vec<Value> = response.take(0)?;
    let mut guard = None;
    let mut active = Vec::new();
    let mut terminal = Vec::new();
    for value in values {
        let kind = value
            .get("record_kind")
            .and_then(Value::as_str)
            .ok_or(AdapterError::PartialOutcome)?;
        match kind {
            CONTINUATION_GUARD_KIND => {
                if guard.replace(parse_continuation_guard(value)?).is_some() {
                    return Err(AdapterError::PartialOutcome);
                }
            }
            CONTINUATION_ACTIVE_KIND => active.push(parse_active_continuation(value)?),
            CONTINUATION_TERMINAL_KIND => terminal.push(parse_terminal_continuation(value)?),
            _ => return Err(AdapterError::PartialOutcome),
        }
    }
    let guard = guard.ok_or(AdapterError::PartialOutcome)?;
    let mut identifiers = std::collections::BTreeSet::new();
    let mut active_bytes = 0_usize;
    for record in &active {
        if record.record_kind != CONTINUATION_ACTIVE_KIND
            || !identifiers.insert(record.identifier.as_str())
            || continuation_metadata_bytes(record)? != record.metadata_bytes
        {
            return Err(AdapterError::PartialOutcome);
        }
        active_bytes = active_bytes
            .checked_add(record.metadata_bytes)
            .ok_or(AdapterError::PartialOutcome)?;
    }
    let mut terminal_bytes = 0_usize;
    for record in &terminal {
        if record.record_kind != CONTINUATION_TERMINAL_KIND
            || record.reclaim_after_unix_ms <= record.expires_at_unix_ms
            || !identifiers.insert(record.identifier.as_str())
            || continuation_tombstone_bytes(record)? != record.metadata_bytes
        {
            return Err(AdapterError::PartialOutcome);
        }
        terminal_bytes = terminal_bytes
            .checked_add(record.metadata_bytes)
            .ok_or(AdapterError::PartialOutcome)?;
    }
    if guard.active_records != active.len()
        || guard.active_metadata_bytes != active_bytes
        || guard.terminal_records != terminal.len()
        || guard.terminal_metadata_bytes != terminal_bytes
    {
        return Err(AdapterError::PartialOutcome);
    }
    Ok(AutomationContinuationInventory {
        guard,
        active,
        terminal,
    })
}

/// Resolves and verifies one opaque reference before the caller obtains its
/// private row boundary. The lookup is read-only and never creates the table.
pub(crate) async fn resolve_automation_continuation(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    reference: &AutomationContinuationRef,
    expected: AutomationContinuationReadBinding<'_>,
    now_unix_ms: u64,
) -> Result<eliot_store_api::VerifiedAutomationContinuation, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "continuation_table".to_owned(),
        json!(schema::table::AUTOMATION_CONTINUATION),
    );
    bindings.insert("continuation_id".to_owned(), json!(reference.identifier()));
    let sql = "SELECT * FROM ONLY type::record($continuation_table, $continuation_id);";
    let mut response =
        client::query(db, config, "automation.continuation.resolve", sql, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Err(invalid_continuation());
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let value: Option<Value> = response.take(0)?;
    let value = value.ok_or(invalid_continuation())?;
    let kind = value
        .get("record_kind")
        .and_then(Value::as_str)
        .ok_or(invalid_continuation())?;
    if kind == CONTINUATION_TERMINAL_KIND {
        let terminal = parse_terminal_continuation(value)?;
        if terminal.identifier != reference.identifier()
            || terminal.terminal_reason != CONTINUATION_EXPIRY_REASON
            || continuation_tombstone_bytes(&terminal)? != terminal.metadata_bytes
        {
            return Err(invalid_continuation());
        }
        return if now_unix_ms >= terminal.expires_at_unix_ms {
            Err(continuation_failure(AutomationContinuationFailure::Expired))
        } else {
            Err(invalid_continuation())
        };
    }
    if kind != CONTINUATION_ACTIVE_KIND {
        return Err(invalid_continuation());
    }
    let record = parse_active_continuation(value)?;
    if record.identifier != reference.identifier()
        || continuation_metadata_bytes(&record)? != record.metadata_bytes
    {
        return Err(invalid_continuation());
    }
    let retained = continuation_binding(&record)?;
    verify_automation_continuation(reference, retained, expected, now_unix_ms)
        .map_err(AdapterError::Store)
}

/// Issues a durable continuation after the caller has fixed and sliced its
/// eligible page. The quota guard serializes reclamation, capacity accounting,
/// child creation, and parent-to-child linking in one Surreal transaction.
/// Replaying a parent with an existing child returns that child's same opaque
/// identifier after checking it against the just-produced page tail.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn issue_automation_continuation(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    query: AutomationContinuationQuery,
    include_retired: bool,
    automation_id: &str,
    read_revision: &str,
    state_fence: &StateFence,
    exclusive_returned_tail: &str,
    max_records: u16,
    parent_identifier: Option<&str>,
    now_unix_ms: u64,
) -> Result<String, AdapterError> {
    let (issuer_identity, issuer_generation) = automation_continuation_owner(config)?;
    ensure_continuation_guard(db, config).await?;

    let expected = AutomationContinuationReadBinding {
        read_operation: NamedReadOperation::GetUserAutomationState,
        query,
        include_retired,
        automation_id,
        read_revision,
        state_fence,
        order: continuation_order(query),
        max_records,
        issuer_identity: &issuer_identity,
        issuer_generation,
    };

    for _attempt in 0..4 {
        let inventory = read_continuation_inventory(db, config).await?;
        let parent_issue = continuation_parent_issue(
            &inventory,
            parent_identifier,
            expected,
            exclusive_returned_tail,
            now_unix_ms,
        )?;
        let parent = match parent_issue {
            ContinuationParentIssue::Root => None,
            ContinuationParentIssue::Continue(parent) => Some(*parent),
            ContinuationParentIssue::Replay(wire) => return Ok(wire),
        };
        let next_revision = next_continuation_revision(&inventory.guard)?;
        let child = new_active_continuation(
            expected,
            exclusive_returned_tail,
            next_revision,
            parent.as_ref(),
            now_unix_ms,
        )?;
        let child_wire = child.1.to_wire().map_err(AdapterError::Store)?;
        let plan = plan_continuation_issue(&inventory, parent.as_ref(), child.0, now_unix_ms)?;

        match commit_continuation_issue(db, config, &inventory.guard, &plan).await {
            Ok(()) => return Ok(child_wire),
            Err(ContinuationIssueCommitError::Race) => {}
            Err(ContinuationIssueCommitError::Failure(error)) => return Err(error),
        }
    }
    Err(stale_continuation())
}

fn continuation_parent_issue(
    inventory: &AutomationContinuationInventory,
    parent_identifier: Option<&str>,
    expected: AutomationContinuationReadBinding<'_>,
    actual_tail: &str,
    now_unix_ms: u64,
) -> Result<ContinuationParentIssue, AdapterError> {
    let Some(identifier) = parent_identifier else {
        return Ok(ContinuationParentIssue::Root);
    };
    let parent = inventory
        .active
        .iter()
        .find(|record| record.identifier == identifier)
        .ok_or_else(|| {
            if inventory
                .terminal
                .iter()
                .any(|record| record.identifier == identifier)
            {
                continuation_failure(AutomationContinuationFailure::Expired)
            } else {
                invalid_continuation()
            }
        })?;
    if now_unix_ms >= parent.expires_at_unix_ms {
        return Err(continuation_failure(AutomationContinuationFailure::Expired));
    }
    if parent.successor_identifier.is_empty() {
        return Ok(ContinuationParentIssue::Continue(Box::new(parent.clone())));
    }
    let child = inventory
        .active
        .iter()
        .find(|candidate| candidate.identifier == parent.successor_identifier)
        .ok_or(stale_continuation())?;
    let child_ref = AutomationContinuationRef::from_owner_identifier(child.identifier.clone())
        .map_err(AdapterError::Store)?;
    let verified = verify_automation_continuation(
        &child_ref,
        continuation_binding(child)?,
        expected,
        now_unix_ms,
    )
    .map_err(AdapterError::Store)?;
    if verified.exclusive_returned_tail() != actual_tail
        || child.creation_revision <= parent.creation_revision
        || child.expires_at_unix_ms > parent.expires_at_unix_ms
    {
        return Err(stale_continuation());
    }
    Ok(ContinuationParentIssue::Replay(
        child_ref.to_wire().map_err(AdapterError::Store)?,
    ))
}

fn next_continuation_revision(guard: &AutomationContinuationGuard) -> Result<u64, AdapterError> {
    guard.sequence.checked_add(1).ok_or(continuation_failure(
        AutomationContinuationFailure::CapacityPressure,
    ))
}

fn new_active_continuation(
    expected: AutomationContinuationReadBinding<'_>,
    exclusive_returned_tail: &str,
    creation_revision: u64,
    parent: Option<&ActiveAutomationContinuation>,
    now_unix_ms: u64,
) -> Result<(ActiveAutomationContinuation, AutomationContinuationRef), AdapterError> {
    let expires_at_unix_ms = match parent {
        Some(parent) => parent.expires_at_unix_ms,
        None => now_unix_ms
            .checked_add(eliot_store_api::AUTOMATION_CONTINUATION_TTL_MS)
            .ok_or(AdapterError::PartialOutcome)?,
    };
    if expires_at_unix_ms <= now_unix_ms {
        return Err(continuation_failure(AutomationContinuationFailure::Expired));
    }
    let identifier = uuid::Uuid::new_v4().to_string();
    let order_key = match expected.order.key {
        AutomationContinuationOrderKey::Revision => "revision",
        AutomationContinuationOrderKey::OccurrenceId => "occurrence_id",
    };
    let metadata = AutomationContinuationMetadata {
        read_operation: "GetUserAutomationState".to_owned(),
        query: continuation_query_name(expected.query).to_owned(),
        include_retired: expected.include_retired,
        automation_id: expected.automation_id.to_owned(),
        read_revision: expected.read_revision.to_owned(),
        state_fence: expected.state_fence.clone(),
        order_key: order_key.to_owned(),
        direction: "ascending".to_owned(),
        exclusive_returned_tail: exclusive_returned_tail.to_owned(),
        max_records: expected.max_records,
        issuer_identity: expected.issuer_identity.to_owned(),
        issuer_generation: expected.issuer_generation,
    };
    let mut child = ActiveAutomationContinuation {
        record_kind: CONTINUATION_ACTIVE_KIND.to_owned(),
        identifier: identifier.clone(),
        metadata,
        creation_revision,
        created_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
        successor_identifier: String::new(),
        metadata_bytes: 0,
    };
    child.metadata_bytes = continuation_metadata_bytes(&child)?;
    let child_ref = AutomationContinuationRef::from_owner_identifier(identifier)
        .map_err(AdapterError::Store)?;
    verify_automation_continuation(
        &child_ref,
        continuation_binding(&child)?,
        expected,
        now_unix_ms,
    )
    .map_err(AdapterError::Store)?;
    Ok((child, child_ref))
}

fn plan_continuation_issue(
    inventory: &AutomationContinuationInventory,
    parent: Option<&ActiveAutomationContinuation>,
    child: ActiveAutomationContinuation,
    now_unix_ms: u64,
) -> Result<AutomationContinuationIssuePlan, AdapterError> {
    let reclaimed = continuation_rows_after_reclaim(inventory, now_unix_ms)?;
    let mut active = reclaimed.active;
    let expired_active = reclaimed.expired_active;
    let terminal = reclaimed.terminal;
    let linked_parent = match parent {
        Some(parent) => {
            let updated = active
                .iter_mut()
                .find(|record| record.identifier == parent.identifier)
                .ok_or(stale_continuation())?;
            updated.successor_identifier.clone_from(&child.identifier);
            updated.metadata_bytes = continuation_metadata_bytes(updated)?;
            Some(updated.clone())
        }
        None => None,
    };
    active.push(child.clone());
    let active_metadata_bytes = active
        .iter()
        .try_fold(0_usize, |total, record| {
            total.checked_add(record.metadata_bytes)
        })
        .ok_or(continuation_failure(
            AutomationContinuationFailure::CapacityPressure,
        ))?;
    if active.len() > eliot_store_api::AUTOMATION_CONTINUATION_MAX_ACTIVE_RECORDS
        || active_metadata_bytes
            > eliot_store_api::AUTOMATION_CONTINUATION_MAX_ACTIVE_METADATA_BYTES
    {
        return Err(continuation_failure(
            AutomationContinuationFailure::CapacityPressure,
        ));
    }

    let terminal = retain_bounded_terminal_continuations(terminal)?;
    let terminal_metadata_bytes = terminal
        .iter()
        .try_fold(0_usize, |total, record| {
            total.checked_add(record.metadata_bytes)
        })
        .ok_or(continuation_failure(
            AutomationContinuationFailure::CapacityPressure,
        ))?;
    let retained_terminal_ids = terminal
        .iter()
        .map(|record| record.identifier.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let deleted_terminal = inventory
        .terminal
        .iter()
        .filter(|record| !retained_terminal_ids.contains(&record.identifier))
        .cloned()
        .collect();
    let next_guard = AutomationContinuationGuard {
        record_kind: CONTINUATION_GUARD_KIND.to_owned(),
        identifier: CONTINUATION_GUARD_ID.to_owned(),
        sequence: next_continuation_revision(&inventory.guard)?,
        active_records: active.len(),
        active_metadata_bytes,
        terminal_records: terminal.len(),
        terminal_metadata_bytes,
    };
    Ok(AutomationContinuationIssuePlan {
        next_guard,
        expired_active,
        deleted_terminal,
        retained_terminal_ids,
        linked_parent,
        child,
    })
}

fn continuation_rows_after_reclaim(
    inventory: &AutomationContinuationInventory,
    now_unix_ms: u64,
) -> Result<ReclaimedContinuationRows, AdapterError> {
    let mut active = Vec::new();
    let mut terminal = inventory
        .terminal
        .iter()
        .filter(|record| record.reclaim_after_unix_ms > now_unix_ms)
        .cloned()
        .collect::<Vec<_>>();
    let mut expired_active = Vec::new();
    for record in &inventory.active {
        if record.expires_at_unix_ms > now_unix_ms {
            active.push(record.clone());
        } else {
            expired_active.push(record.clone());
            if let Some(tombstone) = expired_continuation_tombstone(record, now_unix_ms)? {
                terminal.push(tombstone);
            }
        }
    }
    Ok(ReclaimedContinuationRows {
        active,
        expired_active,
        terminal,
    })
}

fn expired_continuation_tombstone(
    record: &ActiveAutomationContinuation,
    now_unix_ms: u64,
) -> Result<Option<TerminalAutomationContinuation>, AdapterError> {
    let reclaim_after_unix_ms = record
        .expires_at_unix_ms
        .checked_add(eliot_store_api::AUTOMATION_CONTINUATION_TTL_MS)
        .ok_or(AdapterError::PartialOutcome)?;
    if reclaim_after_unix_ms <= now_unix_ms {
        return Ok(None);
    }
    let mut tombstone = TerminalAutomationContinuation {
        record_kind: CONTINUATION_TERMINAL_KIND.to_owned(),
        identifier: record.identifier.clone(),
        creation_revision: record.creation_revision,
        created_at_unix_ms: record.created_at_unix_ms,
        expires_at_unix_ms: record.expires_at_unix_ms,
        reclaim_after_unix_ms,
        issuer_identity: record.metadata.issuer_identity.clone(),
        issuer_generation: record.metadata.issuer_generation,
        terminal_reason: CONTINUATION_EXPIRY_REASON.to_owned(),
        metadata_bytes: 0,
    };
    tombstone.metadata_bytes = continuation_tombstone_bytes(&tombstone)?;
    Ok(Some(tombstone))
}

fn retain_bounded_terminal_continuations(
    mut terminal: Vec<TerminalAutomationContinuation>,
) -> Result<Vec<TerminalAutomationContinuation>, AdapterError> {
    terminal.sort_by(|left, right| {
        left.creation_revision
            .cmp(&right.creation_revision)
            .then_with(|| left.identifier.cmp(&right.identifier))
    });
    while terminal.len() > eliot_store_api::AUTOMATION_CONTINUATION_MAX_TERMINAL_TOMBSTONES
        || terminal
            .iter()
            .try_fold(0_usize, |total, record| {
                total.checked_add(record.metadata_bytes)
            })
            .is_none_or(|bytes| {
                bytes > eliot_store_api::AUTOMATION_CONTINUATION_MAX_TERMINAL_METADATA_BYTES
            })
    {
        if terminal.is_empty() {
            return Err(continuation_failure(
                AutomationContinuationFailure::CapacityPressure,
            ));
        }
        terminal.remove(0);
    }
    Ok(terminal)
}

fn continuation_binding(
    record: &ActiveAutomationContinuation,
) -> Result<AutomationContinuationBinding<'_>, AdapterError> {
    if record.metadata.read_operation != "GetUserAutomationState"
        || record.metadata.direction != "ascending"
    {
        return Err(invalid_continuation());
    }
    let query =
        continuation_query_from_name(&record.metadata.query).ok_or(invalid_continuation())?;
    let key = match record.metadata.order_key.as_str() {
        "revision" => AutomationContinuationOrderKey::Revision,
        "occurrence_id" => AutomationContinuationOrderKey::OccurrenceId,
        _ => return Err(invalid_continuation()),
    };
    Ok(AutomationContinuationBinding {
        identifier: &record.identifier,
        read_operation: NamedReadOperation::GetUserAutomationState,
        query,
        include_retired: record.metadata.include_retired,
        automation_id: &record.metadata.automation_id,
        read_revision: &record.metadata.read_revision,
        state_fence: &record.metadata.state_fence,
        order: AutomationContinuationOrder {
            key,
            direction: AutomationContinuationDirection::Ascending,
        },
        exclusive_returned_tail: &record.metadata.exclusive_returned_tail,
        max_records: record.metadata.max_records,
        issuer_identity: &record.metadata.issuer_identity,
        issuer_generation: record.metadata.issuer_generation,
        creation_revision: record.creation_revision,
        created_at_unix_ms: record.created_at_unix_ms,
        expires_at_unix_ms: record.expires_at_unix_ms,
    })
}

enum ContinuationIssueCommitError {
    Race,
    Failure(AdapterError),
}

/// Commits reclamation, child creation, parent linking, and quota advancement
/// against one guard sequence. Every issuer writes the same guard row, so a
/// racing transaction rolls back and retries from a fresh inventory.
async fn commit_continuation_issue(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    current_guard: &AutomationContinuationGuard,
    plan: &AutomationContinuationIssuePlan,
) -> Result<(), ContinuationIssueCommitError> {
    let mut sql = String::from("BEGIN TRANSACTION;");
    let mut bindings = Map::new();
    bindings.insert(
        "continuation_table".to_owned(),
        json!(schema::table::AUTOMATION_CONTINUATION),
    );
    bindings.insert("guard_id".to_owned(), json!(CONTINUATION_GUARD_ID));
    bindings.insert(
        "guard_expected_sequence".to_owned(),
        json!(current_guard.sequence),
    );
    append_expired_active_changes(
        &mut sql,
        &mut bindings,
        &plan.expired_active,
        &plan.retained_terminal_ids,
    )?;
    append_terminal_deletions(&mut sql, &mut bindings, &plan.deleted_terminal)?;
    append_continuation_child(&mut sql, &mut bindings, &plan.child);
    if let Some(parent) = &plan.linked_parent {
        append_continuation_parent_link(&mut sql, &mut bindings, parent)?;
    }
    append_continuation_guard_update(&mut sql, &mut bindings, &plan.next_guard)?;

    let mut response = client::query(db, config, "automation.continuation.issue", &sql, bindings)
        .await
        .map_err(ContinuationIssueCommitError::Failure)?;
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    let race = errors.iter().any(|error| {
        error.contains(CONTINUATION_GUARD_CONFLICT)
            || error.contains(CONTINUATION_PARENT_CONFLICT)
            || {
                let folded = error.to_ascii_lowercase();
                folded.contains("already exists") || folded.contains("duplicate")
            }
    });
    if race {
        Err(ContinuationIssueCommitError::Race)
    } else {
        Err(ContinuationIssueCommitError::Failure(
            AdapterError::PartialOutcome,
        ))
    }
}

fn append_expired_active_changes(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    records: &[ActiveAutomationContinuation],
    retained_terminal_ids: &std::collections::BTreeSet<String>,
) -> Result<(), ContinuationIssueCommitError> {
    for (index, record) in records.iter().enumerate() {
        bindings.insert(format!("expired_id_{index}"), json!(record.identifier));
        bindings.insert(
            format!("expired_revision_{index}"),
            json!(record.creation_revision),
        );
        bindings.insert(
            format!("expired_at_{index}"),
            json!(record.expires_at_unix_ms),
        );
        bindings.insert(
            format!("expired_issuer_generation_{index}"),
            json!(record.metadata.issuer_generation),
        );
        bindings.insert(
            format!("expired_issuer_identity_{index}"),
            json!(record.metadata.issuer_identity),
        );
        if retained_terminal_ids.contains(&record.identifier) {
            append_expired_tombstone_update(sql, bindings, index, record)?;
        } else {
            append_expired_active_delete(sql, index)?;
        }
    }
    Ok(())
}

fn append_expired_tombstone_update(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    record: &ActiveAutomationContinuation,
) -> Result<(), ContinuationIssueCommitError> {
    let mut tombstone = expired_continuation_tombstone(record, record.expires_at_unix_ms)
        .map_err(ContinuationIssueCommitError::Failure)?
        .ok_or(ContinuationIssueCommitError::Failure(
            AdapterError::PartialOutcome,
        ))?;
    tombstone.metadata_bytes =
        continuation_tombstone_bytes(&tombstone).map_err(ContinuationIssueCommitError::Failure)?;
    bindings.insert(format!("expired_record_{index}"), json!(tombstone));
    write_continuation_sql(
        sql,
        format_args!(
            "LET $expired_update_{index} = (UPDATE type::record($continuation_table, $expired_id_{index}) CONTENT $expired_record_{index} WHERE record_kind = '{CONTINUATION_ACTIVE_KIND}' AND creation_revision = $expired_revision_{index} AND expires_at_unix_ms = $expired_at_{index} AND metadata.issuer_identity = $expired_issuer_identity_{index} AND metadata.issuer_generation = $expired_issuer_generation_{index} RETURN AFTER); IF array::len($expired_update_{index} ?? []) != 1 {{ THROW '{CONTINUATION_GUARD_CONFLICT}'; }};"
        ),
    )
}

fn append_expired_active_delete(
    sql: &mut String,
    index: usize,
) -> Result<(), ContinuationIssueCommitError> {
    write_continuation_sql(
        sql,
        format_args!(
            "LET $expired_delete_{index} = (DELETE automation_continuation WHERE identifier = $expired_id_{index} AND record_kind = '{CONTINUATION_ACTIVE_KIND}' AND creation_revision = $expired_revision_{index} AND expires_at_unix_ms = $expired_at_{index} AND metadata.issuer_identity = $expired_issuer_identity_{index} AND metadata.issuer_generation = $expired_issuer_generation_{index} RETURN BEFORE); IF array::len($expired_delete_{index} ?? []) != 1 {{ THROW '{CONTINUATION_GUARD_CONFLICT}'; }};"
        ),
    )
}

fn append_terminal_deletions(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    records: &[TerminalAutomationContinuation],
) -> Result<(), ContinuationIssueCommitError> {
    for (index, record) in records.iter().enumerate() {
        bindings.insert(format!("terminal_id_{index}"), json!(record.identifier));
        bindings.insert(
            format!("terminal_revision_{index}"),
            json!(record.creation_revision),
        );
        bindings.insert(
            format!("terminal_generation_{index}"),
            json!(record.issuer_generation),
        );
        bindings.insert(
            format!("terminal_issuer_identity_{index}"),
            json!(record.issuer_identity),
        );
        write_continuation_sql(
            sql,
            format_args!(
                "LET $terminal_delete_{index} = (DELETE automation_continuation WHERE identifier = $terminal_id_{index} AND record_kind = '{CONTINUATION_TERMINAL_KIND}' AND creation_revision = $terminal_revision_{index} AND issuer_identity = $terminal_issuer_identity_{index} AND issuer_generation = $terminal_generation_{index} RETURN BEFORE); IF array::len($terminal_delete_{index} ?? []) != 1 {{ THROW '{CONTINUATION_GUARD_CONFLICT}'; }};"
            ),
        )?;
    }
    Ok(())
}

fn append_continuation_child(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    child: &ActiveAutomationContinuation,
) {
    bindings.insert("child_id".to_owned(), json!(child.identifier));
    bindings.insert("child_record".to_owned(), json!(child));
    sql.push_str("LET $continuation_create = (CREATE type::record($continuation_table, $child_id) CONTENT $child_record RETURN AFTER); IF array::len($continuation_create ?? []) != 1 { THROW 'automation_continuation_guard_conflict'; };");
}

fn append_continuation_parent_link(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    parent: &ActiveAutomationContinuation,
) -> Result<(), ContinuationIssueCommitError> {
    bindings.insert("parent_id".to_owned(), json!(parent.identifier));
    bindings.insert(
        "parent_creation_revision".to_owned(),
        json!(parent.creation_revision),
    );
    bindings.insert(
        "parent_issuer_identity".to_owned(),
        json!(parent.metadata.issuer_identity),
    );
    bindings.insert(
        "parent_issuer_generation".to_owned(),
        json!(parent.metadata.issuer_generation),
    );
    bindings.insert(
        "parent_metadata_bytes".to_owned(),
        json!(parent.metadata_bytes),
    );
    write_continuation_sql(
        sql,
        format_args!(
            "LET $parent_link = (UPDATE type::record($continuation_table, $parent_id) SET successor_identifier = $child_id, metadata_bytes = $parent_metadata_bytes WHERE record_kind = '{CONTINUATION_ACTIVE_KIND}' AND creation_revision = $parent_creation_revision AND metadata.issuer_identity = $parent_issuer_identity AND metadata.issuer_generation = $parent_issuer_generation AND successor_identifier = '' RETURN AFTER); IF array::len($parent_link ?? []) != 1 {{ THROW '{CONTINUATION_PARENT_CONFLICT}'; }};"
        ),
    )
}

fn append_continuation_guard_update(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    next_guard: &AutomationContinuationGuard,
) -> Result<(), ContinuationIssueCommitError> {
    bindings.insert("guard_record".to_owned(), json!(next_guard));
    write_continuation_sql(
        sql,
        format_args!(
            "LET $guard_update = (UPDATE type::record($continuation_table, $guard_id) CONTENT $guard_record WHERE sequence = $guard_expected_sequence RETURN AFTER); IF array::len($guard_update ?? []) != 1 {{ THROW '{CONTINUATION_GUARD_CONFLICT}'; }}; COMMIT TRANSACTION;"
        ),
    )
}

fn write_continuation_sql(
    sql: &mut String,
    arguments: std::fmt::Arguments<'_>,
) -> Result<(), ContinuationIssueCommitError> {
    sql.write_fmt(arguments)
        .map_err(|_| ContinuationIssueCommitError::Failure(AdapterError::PartialOutcome))
}

/// Computes automation row writes for one admitted transition.
///
/// Reads current rows, validates every command through the shared wire
/// contract, enforces key existence and pointer agreement
/// pre-transaction, and returns the resulting writes for the
/// in-transaction compare-and-set. Transitions without automation
/// operations yield no writes. Pure reads plus pure compute: rows are
/// written only by the canonical transaction.
pub(crate) async fn prepare_automation_writes(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    transition: &eliot_store_api::PreparedTransition,
) -> Result<AutomationWrites, AdapterError> {
    let mut commanded = false;
    for command in &transition.named_operations {
        if command.operation == NamedMutationOperation::ApplyUserAutomationState {
            commanded = true;
        }
    }
    if !commanded {
        return Ok(AutomationWrites::default());
    }
    if transition.transition_class != TransitionClass::UserAutomation {
        return Err(AdapterError::Store(StoreError::TransitionClassExceeded));
    }
    // The tables are schemaless and auto-create on write, but reads and
    // the in-transaction compare-and-set fail closed on missing tables
    // instead of reading empty. Ensuring them here (idempotent) keeps
    // first use on a fresh database exact without a schema-migration bump.
    ensure_automation_tables(db, config).await?;
    let mut writes = AutomationWrites::default();
    let context = PrepareContext {
        db,
        config,
        transition,
    };
    for command in &transition.named_operations {
        let decoded = match command.operation {
            NamedMutationOperation::ApplyUserAutomationState => {
                decode_automation_mutation(command.operation, &command.parameters)
                    .map_err(AdapterError::Store)?
            }
            _ => continue,
        };
        context.apply_leg(&mut writes, decoded).await?;
    }
    Ok(writes)
}

/// Pre-transaction compute context shared by the automation leg helpers.
struct PrepareContext<'a> {
    db: &'a RpcTransport,
    config: &'a SurrealAdapterConfig,
    transition: &'a eliot_store_api::PreparedTransition,
}

impl PrepareContext<'_> {
    /// Computes one decoded leg into row writes.
    async fn apply_leg(
        &self,
        writes: &mut AutomationWrites,
        decoded: DecodedAutomationMutation,
    ) -> Result<(), AdapterError> {
        match decoded {
            DecodedAutomationMutation::Create {
                automation_id,
                revision,
                revision_json,
                configuration_state,
            } => {
                self.apply_create(
                    writes,
                    automation_id,
                    revision,
                    revision_json,
                    configuration_state,
                )
                .await
            }
            DecodedAutomationMutation::Edit {
                automation_id,
                previous_revision,
                revision,
                revision_json,
                configuration_state,
            } => {
                self.apply_edit(
                    writes,
                    automation_id,
                    previous_revision,
                    revision,
                    revision_json,
                    configuration_state,
                )
                .await
            }
            DecodedAutomationMutation::StateTransition {
                automation_id,
                revision,
                configuration_state,
                ..
            } => {
                self.apply_state_transition(writes, automation_id, revision, configuration_state)
                    .await
            }
            DecodedAutomationMutation::RunNow {
                automation_id,
                revision,
                occurrence_id,
                invocation_json,
            } => {
                self.apply_run_now(
                    writes,
                    automation_id,
                    revision,
                    occurrence_id,
                    invocation_json,
                )
                .await
            }
            DecodedAutomationMutation::Failure {
                automation_id,
                revision,
                occurrence_id,
                failure,
                failure_json,
            } => {
                self.apply_failure(
                    writes,
                    automation_id,
                    revision,
                    occurrence_id,
                    failure.fingerprint,
                    failure_json,
                )
                .await
            }
        }
    }

    /// Provenance columns carried by every automation row write.
    fn provenance(&self) -> (StateFence, String, Option<String>) {
        (
            self.transition.state_fence.clone(),
            self.transition.scope_id.to_string(),
            self.transition.task_id.clone(),
        )
    }

    /// Create leg: fresh revision row plus fresh current pointer.
    async fn apply_create(
        &self,
        writes: &mut AutomationWrites,
        automation_id: String,
        revision: String,
        revision_json: String,
        configuration_state: String,
    ) -> Result<(), AdapterError> {
        require_absent_revision(self.db, self.config, &automation_id, &revision).await?;
        require_absent_current(self.db, self.config, &automation_id).await?;
        let (state_fence, scope_id, task_id) = self.provenance();
        writes.revisions.push(AutomationRevisionWrite {
            automation_id: automation_id.clone(),
            revision: revision.clone(),
            revision_json,
            state_fence: state_fence.clone(),
            scope_id: scope_id.clone(),
            task_id: task_id.clone(),
        });
        writes.currents.push(AutomationCurrentWrite {
            automation_id,
            revision,
            configuration_state,
            state_fence,
            scope_id,
            task_id,
            expected_revision: None,
        });
        Ok(())
    }

    /// Edit leg: fresh revision row plus pointer move off the lineage base.
    async fn apply_edit(
        &self,
        writes: &mut AutomationWrites,
        automation_id: String,
        previous_revision: String,
        revision: String,
        revision_json: String,
        configuration_state: String,
    ) -> Result<(), AdapterError> {
        let current =
            require_current_revision(self.db, self.config, &automation_id, &previous_revision)
                .await?;
        if current.state_fence != self.transition.state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
        require_absent_revision(self.db, self.config, &automation_id, &revision).await?;
        let (state_fence, scope_id, task_id) = self.provenance();
        writes.revisions.push(AutomationRevisionWrite {
            automation_id: automation_id.clone(),
            revision: revision.clone(),
            revision_json,
            state_fence: state_fence.clone(),
            scope_id: scope_id.clone(),
            task_id: task_id.clone(),
        });
        writes.currents.push(AutomationCurrentWrite {
            automation_id,
            revision,
            configuration_state,
            state_fence,
            scope_id,
            task_id,
            expected_revision: Some(current.revision),
        });
        Ok(())
    }

    /// Pause/resume/remove leg: pointer move only; the immutable revision
    /// row is read, never rewritten.
    async fn apply_state_transition(
        &self,
        writes: &mut AutomationWrites,
        automation_id: String,
        revision: String,
        configuration_state: String,
    ) -> Result<(), AdapterError> {
        require_revision_row(self.db, self.config, &automation_id, &revision).await?;
        let current =
            require_current_revision(self.db, self.config, &automation_id, &revision).await?;
        if current.state_fence != self.transition.state_fence {
            return Err(AdapterError::Store(StoreError::FenceMismatch));
        }
        let (state_fence, scope_id, task_id) = self.provenance();
        writes.currents.push(AutomationCurrentWrite {
            automation_id,
            revision,
            configuration_state,
            state_fence,
            scope_id,
            task_id,
            expected_revision: Some(current.revision),
        });
        Ok(())
    }

    /// Run-now leg: invocation row only; the named revision must exist.
    async fn apply_run_now(
        &self,
        writes: &mut AutomationWrites,
        automation_id: String,
        revision: String,
        occurrence_id: String,
        invocation_json: String,
    ) -> Result<(), AdapterError> {
        require_revision_row(self.db, self.config, &automation_id, &revision).await?;
        require_absent_invocation(self.db, self.config, &occurrence_id, &invocation_json).await?;
        let (state_fence, scope_id, task_id) = self.provenance();
        writes.invocations.push(AutomationInvocationWrite {
            occurrence_id,
            automation_id,
            invocation_json,
            state_fence,
            scope_id,
            task_id,
        });
        Ok(())
    }

    /// Failure leg: immutable failure row plus last-failure pointer move;
    /// the named revision must exist. Repeats of one failure class
    /// converge on the existing row (the pointer still moves to it);
    /// divergent documents fail closed.
    async fn apply_failure(
        &self,
        writes: &mut AutomationWrites,
        automation_id: String,
        revision: String,
        occurrence_id: String,
        fingerprint: String,
        failure_json: String,
    ) -> Result<(), AdapterError> {
        require_revision_row(self.db, self.config, &automation_id, &revision).await?;
        let failure_key =
            eliot_store_api::automation_failure_key(&automation_id, &revision, &fingerprint);
        match read_failure_row(self.db, self.config, &failure_key).await? {
            None => {
                let (state_fence, scope_id, task_id) = self.provenance();
                writes.failures.push(AutomationFailureWrite {
                    failure_key: failure_key.clone(),
                    automation_id: automation_id.clone(),
                    revision,
                    occurrence_id,
                    fingerprint,
                    failure_json,
                    source_operation_id: self.transition.identity.operation_id.to_string(),
                    state_fence,
                    scope_id,
                    task_id,
                });
            }
            Some(row) if row.failure_json != failure_json => {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            Some(_) => {}
        }
        writes.last_failures.push(AutomationLastFailureWrite {
            automation_id,
            failure_key,
        });
        Ok(())
    }
}

/// Reads one revision row by its halves.
async fn read_revision_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    revision: &str,
) -> Result<Option<StoredAutomationRevision>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "automation_table".to_owned(),
        json!(crate::schema::table::AUTOMATION_REVISION),
    );
    bindings.insert(
        "automation_key".to_owned(),
        json!(revision_key(automation_id, revision)),
    );
    let statement = "SELECT * FROM ONLY type::record($automation_table, $automation_key);";
    let mut response =
        client::query(db, config, "automation.read_revision", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_revision_row).transpose()
}

/// Reads one current pointer by automation identity.
async fn read_current_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
) -> Result<Option<StoredAutomationCurrent>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "automation_table".to_owned(),
        json!(crate::schema::table::AUTOMATION_CURRENT),
    );
    bindings.insert("automation_key".to_owned(), json!(automation_id));
    let statement = "SELECT * FROM ONLY type::record($automation_table, $automation_key);";
    let mut response =
        client::query(db, config, "automation.read_current", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_current_row).transpose()
}

/// Reads one invocation row by occurrence identity.
async fn read_invocation_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    occurrence_id: &str,
) -> Result<Option<StoredAutomationInvocation>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "automation_table".to_owned(),
        json!(crate::schema::table::AUTOMATION_INVOCATION),
    );
    bindings.insert("automation_key".to_owned(), json!(occurrence_id));
    let statement = "SELECT * FROM ONLY type::record($automation_table, $automation_key);";
    let mut response = client::query(
        db,
        config,
        "automation.read_invocation",
        statement,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_invocation_row).transpose()
}

/// Reads one failure row by its canonical failure key.
async fn read_failure_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    failure_key: &str,
) -> Result<Option<StoredAutomationFailure>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "automation_table".to_owned(),
        json!(crate::schema::table::AUTOMATION_FAILURE),
    );
    bindings.insert("automation_key".to_owned(), json!(failure_key));
    let statement = "SELECT * FROM ONLY type::record($automation_table, $automation_key);";
    let mut response =
        client::query(db, config, "automation.read_failure", statement, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    row.as_ref().map(decode_failure_row).transpose()
}

/// Reads one last-failure pointer by automation identity.
async fn read_last_failure_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
) -> Result<Option<String>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert(
        "automation_table".to_owned(),
        json!(crate::schema::table::AUTOMATION_LAST_FAILURE),
    );
    bindings.insert("automation_key".to_owned(), json!(automation_id));
    let statement = "SELECT * FROM ONLY type::record($automation_table, $automation_key);";
    let mut response = client::query(
        db,
        config,
        "automation.read_last_failure",
        statement,
        bindings,
    )
    .await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(None);
    }
    if !errors.is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let row: Option<Value> = response.take(0)?;
    Ok(row
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| object.get("failure_key"))
        .and_then(Value::as_str)
        .map(str::to_owned))
}

/// Reports whether provider errors prove only that an automation table
/// has no rows yet (fresh database, no migration): a missing table
/// carries no rows, so empty is exact truth here rather than an
/// inference. Any other error stays a partial outcome.
pub(crate) fn missing_automation_table(errors: &[String]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error.contains("does not exist")
                && (error.contains(schema::table::AUTOMATION_REVISION)
                    || error.contains(schema::table::AUTOMATION_CURRENT)
                    || error.contains(schema::table::AUTOMATION_INVOCATION)
                    || error.contains(schema::table::AUTOMATION_FAILURE)
                    || error.contains(schema::table::AUTOMATION_LAST_FAILURE)
                    || error.contains(schema::table::AUTOMATION_CONTINUATION))
        })
}

async fn require_absent_revision(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    revision: &str,
) -> Result<(), AdapterError> {
    if read_revision_row(db, config, automation_id, revision)
        .await?
        .is_some()
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(())
}

async fn require_revision_row(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    revision: &str,
) -> Result<StoredAutomationRevision, AdapterError> {
    read_revision_row(db, config, automation_id, revision)
        .await?
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.revision",
            reason: "unknown automation revision",
        }))
}

async fn require_absent_current(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
) -> Result<(), AdapterError> {
    if read_current_row(db, config, automation_id).await?.is_some() {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(())
}

async fn require_current_revision(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    expected: &str,
) -> Result<StoredAutomationCurrent, AdapterError> {
    let current = read_current_row(db, config, automation_id)
        .await?
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.automation_id",
            reason: "unknown automation",
        }))?;
    if current.revision != expected {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(current)
}

async fn require_absent_invocation(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    occurrence_id: &str,
    invocation_json: &str,
) -> Result<(), AdapterError> {
    match read_invocation_row(db, config, occurrence_id).await? {
        None => Ok(()),
        Some(row) if row.invocation_json == invocation_json => Ok(()),
        Some(_) => Err(AdapterError::Store(StoreError::IdentityConflict)),
    }
}

fn text_row_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, AdapterError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.row",
            reason: "automation row is missing a text field",
        }))
}

fn fence_row_field(object: &serde_json::Map<String, Value>) -> Result<StateFence, AdapterError> {
    serde_json::from_value(object.get("state_fence").cloned().unwrap_or(Value::Null))
        .map_err(|error| AdapterError::Store(StoreError::Serialization(error.to_string())))
}

fn decode_revision_row(value: &Value) -> Result<StoredAutomationRevision, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.row",
            reason: "automation row must be an object",
        }))?;
    Ok(StoredAutomationRevision {
        automation_id: text_row_field(object, "automation_id")?,
        revision: text_row_field(object, "revision")?,
        revision_json: text_row_field(object, "revision_json")?,
        state_fence: fence_row_field(object)?,
    })
}

fn decode_current_row(value: &Value) -> Result<StoredAutomationCurrent, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.row",
            reason: "automation row must be an object",
        }))?;
    Ok(StoredAutomationCurrent {
        automation_id: text_row_field(object, "automation_id")?,
        revision: text_row_field(object, "revision")?,
        configuration_state: text_row_field(object, "configuration_state")?,
        state_fence: fence_row_field(object)?,
    })
}

fn decode_invocation_row(value: &Value) -> Result<StoredAutomationInvocation, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.row",
            reason: "automation row must be an object",
        }))?;
    Ok(StoredAutomationInvocation {
        occurrence_id: text_row_field(object, "occurrence_id")?,
        automation_id: text_row_field(object, "automation_id")?,
        invocation_json: text_row_field(object, "invocation_json")?,
        state_fence: fence_row_field(object)?,
    })
}

fn decode_failure_row(value: &Value) -> Result<StoredAutomationFailure, AdapterError> {
    let object = value
        .as_object()
        .ok_or(AdapterError::Store(StoreError::InvalidField {
            field: "automation.row",
            reason: "automation row must be an object",
        }))?;
    Ok(StoredAutomationFailure {
        automation_id: text_row_field(object, "automation_id")?,
        revision: text_row_field(object, "revision")?,
        occurrence_id: text_row_field(object, "occurrence_id")?,
        fingerprint: text_row_field(object, "fingerprint")?,
        failure_json: text_row_field(object, "failure_json")?,
        source_operation_id: text_row_field(object, "source_operation_id")?,
        state_fence: fence_row_field(object)?,
    })
}

/// Builds the canonical-transaction fragment persisting automation rows.
///
/// Revision and invocation writes are create-or-converge: missing rows
/// create, identical rows pass silently, divergent rows abort the
/// transaction. Current-pointer writes compare-and-set on the observed
/// revision string: creates refuse when a pointer already exists,
/// updates refuse on missing pointers or revision drift. Drift surfaces
/// the `automation_revision_conflict` / `automation_current_conflict` /
/// `automation_invocation_conflict` markers so the apply loop retries
/// with fresh rows. Rows commit in the same transaction as the receipt
/// and outbox rows, so rows, receipt, and outbox stay atomic.
pub(crate) fn automation_write_statements(
    writes: &AutomationWrites,
) -> (String, Map<String, Value>) {
    let mut sql = String::new();
    let mut bindings = Map::new();
    for (index, write) in writes.revisions.iter().enumerate() {
        append_revision_statement(&mut sql, &mut bindings, index, write);
    }
    for (index, write) in writes.currents.iter().enumerate() {
        append_current_statement(&mut sql, &mut bindings, index, write);
    }
    for (index, write) in writes.invocations.iter().enumerate() {
        append_invocation_statement(&mut sql, &mut bindings, index, write);
    }
    for (index, write) in writes.failures.iter().enumerate() {
        append_failure_statement(&mut sql, &mut bindings, index, write);
    }
    for (index, write) in writes.last_failures.iter().enumerate() {
        append_last_failure_statement(&mut sql, &mut bindings, index, write);
    }
    (sql, bindings)
}

/// Appends one revision create-or-converge fragment.
fn append_revision_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &AutomationRevisionWrite,
) {
    let suffix = format!("revision_{index}");
    sql.push_str(
            "LET $automation_current_{s} = (SELECT revision_json FROM ONLY type::record($automation_table_{s}, $automation_key_{s})); IF type::is_object($automation_current_{s}) { IF $automation_current_{s}.revision_json != $automation_expected_{s} { THROW 'automation_revision_conflict'; }; } ELSE { CREATE type::record($automation_table_{s}, $automation_key_{s}) CONTENT $automation_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("automation_table_{suffix}"),
        json!(schema::table::AUTOMATION_REVISION),
    );
    bindings.insert(
        format!("automation_key_{suffix}"),
        json!(revision_key(&write.automation_id, &write.revision)),
    );
    bindings.insert(
        format!("automation_expected_{suffix}"),
        json!(&write.revision_json),
    );
    bindings.insert(
        format!("automation_record_{suffix}"),
        json!({
            "automation_id": write.automation_id,
            "revision": write.revision,
            "revision_json": write.revision_json,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Appends one current-pointer create-or-update fragment.
fn append_current_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &AutomationCurrentWrite,
) {
    let suffix = format!("current_{index}");
    if write.expected_revision.is_some() {
        sql.push_str(
                "LET $pointer_current_{s} = (SELECT revision FROM ONLY type::record($pointer_table_{s}, $pointer_key_{s})); IF type::is_object($pointer_current_{s}) { IF $pointer_current_{s}.revision != $pointer_expected_{s} { THROW 'automation_current_conflict'; } ELSE { UPDATE type::record($pointer_table_{s}, $pointer_key_{s}) CONTENT $pointer_record_{s}; }; } ELSE { THROW 'automation_current_conflict'; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
    } else {
        sql.push_str(
                "LET $pointer_current_{s} = (SELECT revision FROM ONLY type::record($pointer_table_{s}, $pointer_key_{s})); IF type::is_object($pointer_current_{s}) { THROW 'automation_current_conflict'; } ELSE { CREATE type::record($pointer_table_{s}, $pointer_key_{s}) CONTENT $pointer_record_{s}; };"
                    .replace("{s}", &suffix)
                    .as_str(),
            );
    }
    bindings.insert(
        format!("pointer_table_{suffix}"),
        json!(schema::table::AUTOMATION_CURRENT),
    );
    bindings.insert(format!("pointer_key_{suffix}"), json!(&write.automation_id));
    bindings.insert(
        format!("pointer_expected_{suffix}"),
        json!(write.expected_revision),
    );
    bindings.insert(
        format!("pointer_record_{suffix}"),
        json!({
            "automation_id": write.automation_id,
            "revision": write.revision,
            "configuration_state": write.configuration_state,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Appends one invocation create-or-converge fragment.
fn append_invocation_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &AutomationInvocationWrite,
) {
    let suffix = format!("invocation_{index}");
    sql.push_str(
            "LET $invoke_current_{s} = (SELECT invocation_json FROM ONLY type::record($invoke_table_{s}, $invoke_key_{s})); IF type::is_object($invoke_current_{s}) { IF $invoke_current_{s}.invocation_json != $invoke_expected_{s} { THROW 'automation_invocation_conflict'; }; } ELSE { CREATE type::record($invoke_table_{s}, $invoke_key_{s}) CONTENT $invoke_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("invoke_table_{suffix}"),
        json!(schema::table::AUTOMATION_INVOCATION),
    );
    bindings.insert(format!("invoke_key_{suffix}"), json!(&write.occurrence_id));
    bindings.insert(
        format!("invoke_expected_{suffix}"),
        json!(&write.invocation_json),
    );
    bindings.insert(
        format!("invoke_record_{suffix}"),
        json!({
            "occurrence_id": write.occurrence_id,
            "automation_id": write.automation_id,
            "invocation_json": write.invocation_json,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Appends one failure create-or-converge fragment.
fn append_failure_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &AutomationFailureWrite,
) {
    let suffix = format!("failure_{index}");
    sql.push_str(
            "LET $failure_current_{s} = (SELECT failure_json FROM ONLY type::record($failure_table_{s}, $failure_key_{s})); IF type::is_object($failure_current_{s}) { IF $failure_current_{s}.failure_json != $failure_expected_{s} { THROW 'automation_failure_conflict'; }; } ELSE { CREATE type::record($failure_table_{s}, $failure_key_{s}) CONTENT $failure_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("failure_table_{suffix}"),
        json!(schema::table::AUTOMATION_FAILURE),
    );
    bindings.insert(format!("failure_key_{suffix}"), json!(&write.failure_key));
    bindings.insert(
        format!("failure_expected_{suffix}"),
        json!(&write.failure_json),
    );
    bindings.insert(
        format!("failure_record_{suffix}"),
        json!({
            "automation_id": write.automation_id,
            "revision": write.revision,
            "occurrence_id": write.occurrence_id,
            "fingerprint": write.fingerprint,
            "failure_json": write.failure_json,
            "source_operation_id": write.source_operation_id,
            "state_fence": write.state_fence,
            "scope_id": write.scope_id,
            "task_id": write.task_id,
        }),
    );
}

/// Appends one last-failure pointer create-or-update fragment. Latest
/// write wins; no conflict marker.
fn append_last_failure_statement(
    sql: &mut String,
    bindings: &mut Map<String, Value>,
    index: usize,
    write: &AutomationLastFailureWrite,
) {
    let suffix = format!("last_failure_{index}");
    sql.push_str(
            "LET $last_current_{s} = (SELECT failure_key FROM ONLY type::record($last_table_{s}, $last_key_{s})); IF type::is_object($last_current_{s}) { UPDATE type::record($last_table_{s}, $last_key_{s}) CONTENT $last_record_{s}; } ELSE { CREATE type::record($last_table_{s}, $last_key_{s}) CONTENT $last_record_{s}; };"
                .replace("{s}", &suffix)
                .as_str(),
        );
    bindings.insert(
        format!("last_table_{suffix}"),
        json!(schema::table::AUTOMATION_LAST_FAILURE),
    );
    bindings.insert(format!("last_key_{suffix}"), json!(&write.automation_id));
    bindings.insert(
        format!("last_record_{suffix}"),
        json!({
            "automation_id": write.automation_id,
            "failure_key": write.failure_key,
        }),
    );
}

/// Reads all current pointers in deterministic automation-id order.
pub(crate) async fn read_currents_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    limit: usize,
) -> Result<Vec<StoredAutomationCurrent>, AdapterError> {
    let sql = format!(
        "SELECT * FROM {} ORDER BY automation_id LIMIT {limit};",
        schema::table::AUTOMATION_CURRENT
    );
    let mut response =
        client::query(db, config, "automation.read_currents", &sql, Map::new()).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "automation snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.iter().map(decode_current_row).collect()
}

/// Reads one current pointer for the current query.
pub(crate) async fn read_current_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
) -> Result<Option<StoredAutomationCurrent>, AdapterError> {
    read_current_row(db, config, automation_id).await
}

/// Reads one immutable revision by its exact record identity for an owner
/// read. This bypasses the bounded history page; a current pointer may name a
/// revision outside the first page after enough edits.
pub(crate) async fn read_revision_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    revision: &str,
) -> Result<Option<StoredAutomationRevision>, AdapterError> {
    read_revision_row(db, config, automation_id, revision).await
}

/// Reads revision rows for one automation in deterministic key order.
pub(crate) async fn read_revisions_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    limit: usize,
) -> Result<Vec<StoredAutomationRevision>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert("automation_id".to_owned(), json!(automation_id));
    let sql = format!(
        "SELECT * FROM {} WHERE automation_id = $automation_id ORDER BY revision LIMIT {limit};",
        schema::table::AUTOMATION_REVISION
    );
    let mut response =
        client::query(db, config, "automation.read_revisions", &sql, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "automation snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.iter().map(decode_revision_row).collect()
}

/// Reads invocation rows for one automation in deterministic key order.
pub(crate) async fn read_invocations_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    limit: usize,
) -> Result<Vec<StoredAutomationInvocation>, AdapterError> {
    let mut bindings = Map::new();
    bindings.insert("automation_id".to_owned(), json!(automation_id));
    let sql = format!(
        "SELECT * FROM {} WHERE automation_id = $automation_id ORDER BY occurrence_id LIMIT {limit};",
        schema::table::AUTOMATION_INVOCATION
    );
    let mut response =
        client::query(db, config, "automation.read_invocations", &sql, bindings).await?;
    let errors = response.take_errors();
    if missing_automation_table(&errors) {
        return Ok(Vec::new());
    }
    if !errors.is_empty() {
        return Err(AdapterError::Store(StoreError::Serialization(
            "automation snapshot query failed".to_owned(),
        )));
    }
    let rows: Vec<Value> = response.take(0)?;
    rows.iter().map(decode_invocation_row).collect()
}

/// Reads one invocation row by exact occurrence and automation identity.
pub(crate) async fn read_invocation_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
    occurrence_id: &str,
) -> Result<Option<StoredAutomationInvocation>, AdapterError> {
    let row = read_invocation_row(db, config, occurrence_id).await?;
    Ok(row.filter(|row| row.automation_id == automation_id))
}

/// Reads the last failure row for one automation, if any.
pub(crate) async fn read_failure_for_read(
    db: &RpcTransport,
    config: &SurrealAdapterConfig,
    automation_id: &str,
) -> Result<Option<StoredAutomationFailure>, AdapterError> {
    let Some(failure_key) = read_last_failure_row(db, config, automation_id).await? else {
        return Ok(None);
    };
    read_failure_row(db, config, &failure_key).await
}

#[cfg(test)]
mod template_tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use std::num::NonZeroU64;

    fn test_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn writes() -> AutomationWrites {
        AutomationWrites {
            revisions: vec![AutomationRevisionWrite {
                automation_id: "auto-1".to_owned(),
                revision: "r-1".to_owned(),
                revision_json: r#"{"revision":"r-1"}"#.to_owned(),
                state_fence: test_fence(),
                scope_id: "user-automation".to_owned(),
                task_id: None,
            }],
            currents: vec![
                AutomationCurrentWrite {
                    automation_id: "auto-1".to_owned(),
                    revision: "r-1".to_owned(),
                    configuration_state: "ACTIVE".to_owned(),
                    state_fence: test_fence(),
                    scope_id: "user-automation".to_owned(),
                    task_id: None,
                    expected_revision: None,
                },
                AutomationCurrentWrite {
                    automation_id: "auto-2".to_owned(),
                    revision: "r-3".to_owned(),
                    configuration_state: "PAUSED".to_owned(),
                    state_fence: test_fence(),
                    scope_id: "user-automation".to_owned(),
                    task_id: None,
                    expected_revision: Some("r-2".to_owned()),
                },
            ],
            invocations: vec![AutomationInvocationWrite {
                occurrence_id: "user-automation-occurrence:abc".to_owned(),
                automation_id: "auto-1".to_owned(),
                invocation_json: r#"{"nonce":"n-1"}"#.to_owned(),
                state_fence: test_fence(),
                scope_id: "user-automation".to_owned(),
                task_id: None,
            }],
            failures: vec![AutomationFailureWrite {
                failure_key: "auto-1\x1ffp-9".to_owned(),
                automation_id: "auto-1".to_owned(),
                revision: "r-1".to_owned(),
                occurrence_id: "user-automation-occurrence:abc".to_owned(),
                fingerprint: "fp-9".to_owned(),
                failure_json: r#"{"fingerprint":"fp-9"}"#.to_owned(),
                source_operation_id: "op-1".to_owned(),
                state_fence: test_fence(),
                scope_id: "user-automation".to_owned(),
                task_id: None,
            }],
            last_failures: vec![AutomationLastFailureWrite {
                automation_id: "auto-1".to_owned(),
                failure_key: "auto-1\x1ffp-9".to_owned(),
            }],
        }
    }

    #[test]
    fn fragments_carry_cas_guards_and_verbatim_rows() {
        let (sql, bindings) = automation_write_statements(&writes());
        assert!(
            sql.contains("THROW 'automation_revision_conflict'"),
            "revision legs guard divergence"
        );
        assert!(
            sql.contains("THROW 'automation_current_conflict'"),
            "pointer legs guard revision drift"
        );
        assert!(
            sql.contains("THROW 'automation_invocation_conflict'"),
            "invocation legs guard divergence"
        );
        assert!(
            sql.contains("CREATE type::record($automation_table_revision_0"),
            "revision leg creates"
        );
        assert!(
            sql.contains("CREATE type::record($pointer_table_current_0"),
            "pointer create leg creates"
        );
        assert!(
            sql.contains("UPDATE type::record($pointer_table_current_1"),
            "pointer update leg updates"
        );
        assert!(
            sql.contains("CREATE type::record($invoke_table_invocation_0"),
            "invocation leg creates"
        );
        assert!(
            sql.contains("THROW 'automation_failure_conflict'"),
            "failure legs guard divergence"
        );
        assert!(
            sql.contains("CREATE type::record($failure_table_failure_0"),
            "failure leg creates"
        );
        assert!(
            sql.contains("UPDATE type::record($last_table_last_failure_0"),
            "last-failure pointer moves"
        );
        for name in [
            "automation_table_revision_0",
            "automation_key_revision_0",
            "automation_record_revision_0",
            "automation_expected_revision_0",
            "pointer_table_current_0",
            "pointer_key_current_0",
            "pointer_record_current_0",
            "pointer_table_current_1",
            "pointer_key_current_1",
            "pointer_record_current_1",
            "pointer_expected_current_1",
            "invoke_table_invocation_0",
            "invoke_key_invocation_0",
            "invoke_record_invocation_0",
            "invoke_expected_invocation_0",
            "failure_table_failure_0",
            "failure_key_failure_0",
            "failure_record_failure_0",
            "failure_expected_failure_0",
            "last_table_last_failure_0",
            "last_key_last_failure_0",
            "last_record_last_failure_0",
        ] {
            assert!(bindings.contains_key(name), "binding travels: {name}");
        }
        assert_eq!(
            bindings.get("pointer_key_current_0"),
            Some(&json!("auto-1")),
            "pointer create leg keys the automation index"
        );
    }

    #[test]
    fn revision_keys_join_without_collision() {
        assert_eq!(revision_key("auto-1", "r-1"), "auto-1\x1fr-1");
    }

    #[test]
    fn missing_table_errors_are_exact() {
        assert!(
            missing_automation_table(&["table automation_revision does not exist".to_owned()]),
            "revision table absence reads empty"
        );
        assert!(
            missing_automation_table(&["table automation_current does not exist".to_owned()]),
            "pointer table absence reads empty"
        );
        assert!(
            missing_automation_table(&["table automation_invocation does not exist".to_owned()]),
            "invocation table absence reads empty"
        );
        assert!(
            !missing_automation_table(&["table write_receipt does not exist".to_owned()]),
            "foreign table absence is not automation evidence"
        );
        assert!(
            !missing_automation_table(&["boom".to_owned()]),
            "unrelated errors stay partial outcomes"
        );
        assert!(!missing_automation_table(&[]), "empty sets never classify");
    }
}
