//! Canonical user-automation execution for the `SurrealDB` bridge
//! (issue #1779).
//!
//! Mirrors the reference contour's closed legs through the store-api wire
//! contract, persisted in five tables: `automation_revision` holds one
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
    DecodedAutomationMutation, NamedMutationOperation, StateFence, StoreError, TransitionClass,
    decode_automation_mutation,
};
use serde_json::{Map, Value, json};

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
                    || error.contains(schema::table::AUTOMATION_LAST_FAILURE))
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
