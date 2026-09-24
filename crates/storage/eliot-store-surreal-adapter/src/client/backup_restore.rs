//! Fixed isolated-restore operation registration for the Surreal seam.
//!
//! Only the four closed restore operations below may execute. Caller text never
//! becomes a statement: every operation maps to one pinned `&'static str`
//! template with bound-parameter placeholders. Connection endpoints and
//! credentials never cross this seam; they remain inside adapter configuration.

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

/// Closed restore vocabulary, in canonical registration order.
pub(crate) const RESTORE_OPERATIONS: &[&str] = &[
    RESTORE_OPERATION_PREPARE,
    RESTORE_OPERATION_APPLY,
    RESTORE_OPERATION_VALIDATE,
    RESTORE_OPERATION_RECONCILE,
];

/// Pinned statement for [`RESTORE_OPERATION_PREPARE`].
///
/// Reads only the isolated destination row keyed by bound parameters; the
/// destination identifier and manifest digest always arrive as bindings.
const STATEMENT_RESTORE_PREPARE: &str = "SELECT * FROM restore_destination WHERE destination_id = $destination_id AND manifest_digest = $manifest_digest LIMIT 1";

/// Pinned statement for [`RESTORE_OPERATION_APPLY`].
///
/// Creates one canonical restore record in the isolated destination. Record
/// identity, payload bytes, and sequencing arrive only as bound parameters.
const STATEMENT_RESTORE_APPLY: &str = "CREATE restore_record SET operation_id = $operation_id, destination_id = $destination_id, sequence_no = $sequence_no, payload = $payload";

/// Pinned statement for [`RESTORE_OPERATION_VALIDATE`].
///
/// Reads back the isolated destination summary for manifest comparison. All
/// selectors arrive as bound parameters; no caller text enters the statement.
const STATEMENT_RESTORE_VALIDATE: &str = "SELECT count() AS applied_batches, manifest_digest FROM restore_record WHERE destination_id = $destination_id GROUP BY manifest_digest";

/// Pinned statement for [`RESTORE_OPERATION_RECONCILE`].
///
/// Resolves one restore operation outcome by its exact admitted identity. The
/// operation identity arrives only as a bound parameter.
const STATEMENT_RESTORE_RECONCILE: &str = "SELECT operation_id, applied FROM restore_record WHERE operation_id = $operation_id AND destination_id = $destination_id LIMIT 1";

/// Redacted operation label used in every restore error.
///
/// The label is a static string so unknown caller input is never echoed back
/// through an error path.
const RESTORE_ERROR_OPERATION: &str = "restore";

/// Reports whether `name` is a member of the closed restore vocabulary.
pub(crate) fn is_restore_operation(name: &str) -> bool {
    RESTORE_OPERATIONS.contains(&name)
}

/// Admits only members of the closed restore vocabulary.
///
/// Unknown names fail with a redacted static label; the input is never
/// echoed into the error.
pub(crate) fn validate_restore_operation(name: &str) -> Result<(), AdapterError> {
    if is_restore_operation(name) {
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
        Ok(STATEMENT_RESTORE_PREPARE)
    } else if operation == RESTORE_OPERATION_APPLY {
        Ok(STATEMENT_RESTORE_APPLY)
    } else if operation == RESTORE_OPERATION_VALIDATE {
        Ok(STATEMENT_RESTORE_VALIDATE)
    } else if operation == RESTORE_OPERATION_RECONCILE {
        Ok(STATEMENT_RESTORE_RECONCILE)
    } else {
        Err(AdapterError::NamedOperationUnavailable {
            operation: RESTORE_ERROR_OPERATION.to_owned(),
        })
    }
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
