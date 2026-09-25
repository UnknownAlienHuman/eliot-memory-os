//! Fixed isolated-restore operation registration for the Surreal seam.
//!
//! Only the closed restore operations below may execute. Caller text never
//! becomes a statement: every operation maps to one pinned `&'static str`
//! template with bound-parameter placeholders. Connection endpoints and
//! credentials never cross this seam; they remain inside adapter configuration.
//!
//! Durable restore state lives in the admitted `recovery_job` registry table
//! (the same physical table the Dreamer ledger uses, referenced as
//! [`RESTORE_REGISTRY_TABLE`]) under the private [`RESTORE_NAMESPACE`]. There
//! is no new table, no DDL and no schema-generation change: the destination
//! fence row, the per-operation record row, the archive-placement row and the
//! current purge-ledger rows are keyed rows of one already-indexed table, so
//! restore inherits the v2 baseline plus its unique `(namespace, key)` index
//! for insert-if-absent exclusion, exact replay and changed-content conflict.
//! A restore transaction never touches a canonical table, never executes
//! archive text and never imports operational session/lease/grant/epoch state.

use crate::error::AdapterError;
use eliot_store_api::BACKUP_IO_CAPABILITY_ISOLATED_RESTORE;

/// Prepares an isolated restore destination without touching live state.
pub(crate) const RESTORE_OPERATION_PREPARE: &str = "restore_prepare_isolated_destination";
/// Applies one canonical restore batch into the isolated destination.
pub(crate) const RESTORE_OPERATION_APPLY: &str = "restore_canonical_batch";
/// Validates the isolated destination against the restore manifest.
pub(crate) const RESTORE_OPERATION_VALIDATE: &str = "restore_validate";
/// Reconciles one restore operation by its exact admitted identity.
pub(crate) const RESTORE_OPERATION_RECONCILE: &str = "restore_reconcile_operation";
/// Observes the durable destination admission/fence/build/purge evidence.
pub(crate) const RESTORE_OPERATION_FENCE: &str = "restore_destination_fence";
/// Observes the current purge ledger for one restored member scope.
pub(crate) const RESTORE_OPERATION_PURGE_LEDGER: &str = "restore_current_purge_ledger";

/// Closed restore vocabulary, in canonical registration order.
///
/// Exactly the four [`crate::backup_restore`] port operations. Each maps to one
/// pinned statement; nothing outside this list is executable.
pub(crate) const RESTORE_OPERATIONS: &[&str] = &[
    RESTORE_OPERATION_PREPARE,
    RESTORE_OPERATION_APPLY,
    RESTORE_OPERATION_VALIDATE,
    RESTORE_OPERATION_RECONCILE,
];

/// Closed provider-side observation vocabulary, in canonical order.
///
/// The two observations the port must perform before it may write: the durable
/// destination admission/fence/build/purge readback and the current
/// purge-ledger readback. They are disjoint from [`RESTORE_OPERATIONS`], so
/// the fixed registry's closed set is exactly the union and nothing else.
pub(crate) const RESTORE_PROVIDER_OBSERVATIONS: &[&str] =
    &[RESTORE_OPERATION_FENCE, RESTORE_OPERATION_PURGE_LEDGER];

/// Private registry namespace for isolated-restore state.
///
/// One versioned namespace inside the existing recovery registry table, exactly
/// as the Dreamer ledger owns `dreamer-job-v1` there: keys discriminate the
/// row families, so no second ledger, table or migration is introduced.
pub(crate) const RESTORE_NAMESPACE: &str = "eliot.storage.restore.v1";

/// Physical registry table, referenced from its single owner in
/// [`crate::schema`] so restore never restates the name as its own constant
/// source of truth.
pub(crate) const RESTORE_REGISTRY_TABLE: &str = crate::schema::table::RECOVERY_JOB;

/// Destination fence/admission row prefix inside [`RESTORE_NAMESPACE`].
pub(crate) const RESTORE_KEY_DESTINATION_PREFIX: &str = "destination_";
/// Per-operation record (durable restore receipt) row prefix.
pub(crate) const RESTORE_KEY_RECORD_PREFIX: &str = "record_";
/// Archive-placement exclusivity row prefix: one placement of one archive
/// member into one destination, ever.
pub(crate) const RESTORE_KEY_PLACEMENT_PREFIX: &str = "placement_";
/// Current purge-ledger subject row prefix, keyed by the archive member digest
/// the obligation applies to.
pub(crate) const RESTORE_KEY_PURGE_MEMBER_PREFIX: &str = "purge_member_";
/// Current purge-ledger scope row prefix, keyed by the source installation the
/// obligation applies to.
pub(crate) const RESTORE_KEY_PURGE_SCOPE_PREFIX: &str = "purge_scope_";

/// Payload schema of a destination fence/admission row.
pub(crate) const RESTORE_SCHEMA_DESTINATION: &str = "eliot.storage.restore.v1:destination";
/// Payload schema of a per-operation record row.
pub(crate) const RESTORE_SCHEMA_RECORD: &str = "eliot.storage.restore.v1:record";
/// Payload schema of an archive-placement exclusivity row.
pub(crate) const RESTORE_SCHEMA_PLACEMENT: &str = "eliot.storage.restore.v1:placement";
/// Payload schema of a current purge-ledger row.
pub(crate) const RESTORE_SCHEMA_PURGE: &str = "eliot.storage.restore.v1:purge-ledger";

/// Marker thrown when the destination fence row is absent at apply time.
pub(crate) const RESTORE_DESTINATION_ABSENT: &str = "restore_destination_absent";
/// Marker thrown when the destination fence row lost its compare-and-set race.
pub(crate) const RESTORE_DESTINATION_CAS_CONFLICT: &str = "restore_destination_cas_conflict";
/// Marker thrown when a concurrent winner created the destination row first.
pub(crate) const RESTORE_DESTINATION_CREATE_CONFLICT: &str = "restore_destination_create_conflict";
/// Marker thrown when the per-operation record row already exists.
pub(crate) const RESTORE_RECORD_CREATE_CONFLICT: &str = "restore_record_create_conflict";
/// Marker thrown when the archive placement is already owned by another
/// operation identity.
pub(crate) const RESTORE_PLACEMENT_CREATE_CONFLICT: &str = "restore_placement_create_conflict";

/// Generic registry read: one keyed row by exact namespace/key.
///
/// The projection is the registry's canonical column shape. `LIMIT 1` plus the
/// unique `(namespace, key)` index means the read is exact: an absent row is a
/// positive observation, never an assumed outcome.
const RESTORE_STATEMENT_READ_ROW: &str = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $restore_namespace AND key = $restore_key LIMIT 1;";

/// Pinned statement for [`RESTORE_OPERATION_FENCE`].
///
/// The destination fence/admission readback the port must perform before any
/// write. Selectors arrive only as bound parameters.
const RESTORE_STATEMENT_FENCE: &str = RESTORE_STATEMENT_READ_ROW;

/// Pinned statement for [`RESTORE_OPERATION_VALIDATE`].
///
/// The ready-gate readback of the per-operation record row. Deliberately the
/// same exact keyed read as the fence observation: the gate derives its verdict
/// from the provider, never from local memory.
const RESTORE_STATEMENT_VALIDATE: &str = RESTORE_STATEMENT_READ_ROW;

/// Pinned statement for [`RESTORE_OPERATION_RECONCILE`].
///
/// The exact durable readback used to reconcile a lost response by operation
/// identity. Same keyed read, different operation label.
const RESTORE_STATEMENT_RECONCILE: &str = RESTORE_STATEMENT_READ_ROW;

/// Pinned statement for [`RESTORE_OPERATION_PURGE_LEDGER`].
///
/// Two exact keyed reads in one dispatch: the member-scoped current purge
/// obligation and the source-scope obligation. Both keys arrive as bound
/// parameters; an absent row means "no recorded obligation for that scope",
/// never "no purge policy".
const RESTORE_STATEMENT_PURGE_LEDGER: &str = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $restore_namespace AND key = $restore_member_key LIMIT 1; SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $restore_namespace AND key = $restore_scope_key LIMIT 1;";

/// Pinned statement for [`RESTORE_OPERATION_PREPARE`].
///
/// One provider transaction that inserts the destination fence/admission row
/// with its freshly derived destination operational identity. The row is
/// create-only: a concurrent or repeated winner raises the unique-index
/// duplicate, which the port classifies as replay-or-conflict by exact
/// readback rather than by overwriting the fence.
const RESTORE_STATEMENT_PREPARE: &str = r"
BEGIN TRANSACTION;
LET $prepared = (CREATE type::record($restore_table, $restore_destination_row_id) CONTENT { namespace: $restore_destination_record.namespace, key: $restore_destination_record.key, state_fence: $restore_destination_record.state_fence, revision: $restore_destination_record.revision, schema: $restore_destination_record.schema, payload: <bytes>$restore_destination_record.payload, value_digest: $restore_destination_record.value_digest } RETURN AFTER);
IF array::len($prepared ?? []) != 1 { THROW 'restore_destination_create_conflict'; };
COMMIT TRANSACTION;
";

/// Pinned statement for [`RESTORE_OPERATION_APPLY`].
///
/// One provider transaction that binds the restored members and their durable
/// restore receipt to the destination fence in the same commit: the fence
/// compare-and-set (revision + state fence), the per-operation record row, and
/// the archive-placement exclusivity row land together or not at all. Every
/// identity arrives as a bound parameter; no row content is ever interpolated
/// into the statement text.
const RESTORE_STATEMENT_APPLY: &str = r"
BEGIN TRANSACTION;
LET $fence_guard = (SELECT VALUE { revision: revision, state_fence: state_fence } FROM recovery_job WHERE namespace = $restore_namespace AND key = $restore_destination_key LIMIT 1);
IF array::len($fence_guard ?? []) != 1 { THROW 'restore_destination_absent'; };
LET $destination_cas = (UPDATE type::record($restore_table, $restore_destination_row_id) CONTENT { namespace: $restore_destination_record.namespace, key: $restore_destination_record.key, state_fence: $restore_destination_record.state_fence, revision: $restore_destination_record.revision, schema: $restore_destination_record.schema, payload: <bytes>$restore_destination_record.payload, value_digest: $restore_destination_record.value_digest } WHERE namespace = $restore_namespace AND key = $restore_destination_key AND revision = $restore_expected_destination_revision AND state_fence = $restore_expected_destination_fence RETURN AFTER);
IF array::len($destination_cas ?? []) != 1 { THROW 'restore_destination_cas_conflict'; };
LET $record_create = (CREATE type::record($restore_table, $restore_record_row_id) CONTENT { namespace: $restore_record_row.namespace, key: $restore_record_row.key, state_fence: $restore_record_row.state_fence, revision: $restore_record_row.revision, schema: $restore_record_row.schema, payload: <bytes>$restore_record_row.payload, value_digest: $restore_record_row.value_digest } RETURN AFTER);
IF array::len($record_create ?? []) != 1 { THROW 'restore_record_create_conflict'; };
LET $placement_create = (CREATE type::record($restore_table, $restore_placement_row_id) CONTENT { namespace: $restore_placement_row.namespace, key: $restore_placement_row.key, state_fence: $restore_placement_row.state_fence, revision: $restore_placement_row.revision, schema: $restore_placement_row.schema, payload: <bytes>$restore_placement_row.payload, value_digest: $restore_placement_row.value_digest } RETURN AFTER);
IF array::len($placement_create ?? []) != 1 { THROW 'restore_placement_create_conflict'; };
COMMIT TRANSACTION;
";

/// Redacted operation label used in every restore error.
///
/// The label is a static string so unknown caller input is never echoed back
/// through an error path.
const RESTORE_ERROR_OPERATION: &str = "restore";

/// Reports whether `name` is a member of the closed restore vocabulary.
pub(crate) fn is_restore_operation(name: &str) -> bool {
    RESTORE_OPERATIONS.contains(&name)
}

/// Admits only members of the closed fixed-provider restore vocabulary.
///
/// The closed set is the four port operations plus the two provider-side
/// observations. Unknown names fail with a redacted static label; the input is
/// never echoed into the error.
pub(crate) fn validate_restore_operation(name: &str) -> Result<(), AdapterError> {
    if is_restore_operation(name) || RESTORE_PROVIDER_OBSERVATIONS.contains(&name) {
        Ok(())
    } else {
        Err(AdapterError::NamedOperationUnavailable {
            operation: RESTORE_ERROR_OPERATION.to_owned(),
        })
    }
}

/// Maps a closed restore operation to its pinned fixed statement.
///
/// Each arm returns a `&'static str` constant containing only
/// bound-parameter placeholders. Unknown operations fail with the same
/// redacted static label used by [`validate_restore_operation`].
pub(crate) fn fixed_restore_statement(operation: &str) -> Result<&'static str, AdapterError> {
    if operation == RESTORE_OPERATION_PREPARE {
        Ok(RESTORE_STATEMENT_PREPARE)
    } else if operation == RESTORE_OPERATION_FENCE {
        Ok(RESTORE_STATEMENT_FENCE)
    } else if operation == RESTORE_OPERATION_PURGE_LEDGER {
        Ok(RESTORE_STATEMENT_PURGE_LEDGER)
    } else if operation == RESTORE_OPERATION_APPLY {
        Ok(RESTORE_STATEMENT_APPLY)
    } else if operation == RESTORE_OPERATION_VALIDATE {
        Ok(RESTORE_STATEMENT_VALIDATE)
    } else if operation == RESTORE_OPERATION_RECONCILE {
        Ok(RESTORE_STATEMENT_RECONCILE)
    } else {
        Err(AdapterError::NamedOperationUnavailable {
            operation: RESTORE_ERROR_OPERATION.to_owned(),
        })
    }
}

/// Reports whether one provider statement error is a duplicate/unique-index
/// rejection, i.e. a concurrent winner created the row first.
///
/// The restore registry relies on the unique `(namespace, key)` index for
/// insert-if-absent exclusion, so a duplicate is a deterministic conflict to be
/// resolved by exact readback, never a reason to overwrite the row. The
/// explicit guards cover the provider shape that reports an empty create
/// instead of raising the unique-index error.
#[must_use]
pub(crate) fn is_restore_duplicate(error: &str) -> bool {
    if error.contains(RESTORE_DESTINATION_CREATE_CONFLICT)
        || error.contains(RESTORE_RECORD_CREATE_CONFLICT)
        || error.contains(RESTORE_PLACEMENT_CREATE_CONFLICT)
    {
        return true;
    }
    crate::client::is_dreamer_conflict(error)
}

/// Reports whether one provider statement error is the destination fence
/// compare-and-set losing a concurrent restore of the same destination.
#[must_use]
pub(crate) fn is_restore_fence_race(error: &str) -> bool {
    error.contains(RESTORE_DESTINATION_CAS_CONFLICT)
}

/// Reports whether one provider statement error observed the destination fence
/// row as absent: the isolated destination was never prepared, so no write may
/// proceed.
#[must_use]
pub(crate) fn is_restore_destination_absent(error: &str) -> bool {
    error.contains(RESTORE_DESTINATION_ABSENT)
}

/// Returns the public backup capability this fixed registry implements.
///
/// The isolated-restore capability string is owned by `eliot-store-api`; this
/// module only surfaces it so callers can advertise the fixed behavior.
pub(crate) fn restore_capability() -> &'static str {
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_vocabulary_contains_all_four_in_order() {
        assert_eq!(
            RESTORE_OPERATIONS,
            &[
                RESTORE_OPERATION_PREPARE,
                RESTORE_OPERATION_APPLY,
                RESTORE_OPERATION_VALIDATE,
                RESTORE_OPERATION_RECONCILE,
            ]
        );
    }

    #[test]
    fn membership_matches_closed_vocabulary() {
        for operation in RESTORE_OPERATIONS {
            assert!(is_restore_operation(operation));
            assert!(validate_restore_operation(operation).is_ok());
            assert!(fixed_restore_statement(operation).is_ok());
        }
        assert!(!is_restore_operation("restore_drop_everything"));
        assert!(!is_restore_operation(""));
    }

    #[test]
    fn unknown_operations_are_redacted() {
        let probe = "restore_drop_everything; DROP restore_record";
        let error = match validate_restore_operation(probe) {
            Ok(()) => panic!("unknown op must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            AdapterError::NamedOperationUnavailable {
                operation: "restore".to_owned(),
            }
        );
        let error = match fixed_restore_statement(probe) {
            Ok(_) => panic!("unknown op must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            AdapterError::NamedOperationUnavailable {
                operation: "restore".to_owned(),
            }
        );
    }

    #[test]
    fn statements_use_bound_parameters_only() {
        for operation in RESTORE_OPERATIONS {
            let statement = match fixed_restore_statement(operation) {
                Ok(statement) => statement,
                Err(_) => panic!("closed op must map"),
            };
            assert!(statement.contains('$'));
        }
    }

    #[test]
    fn capability_is_isolated_restore() {
        assert_eq!(restore_capability(), "isolated_restore");
    }
}
