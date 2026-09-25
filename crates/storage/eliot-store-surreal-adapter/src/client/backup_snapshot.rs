//! Fixed coherent-snapshot operation registration for the `SurrealDB` seam.
//!
//! Only the four closed `snapshot.*` operations below may execute. Caller text
//! never becomes a statement: every operation maps to one pinned `&'static str`
//! composed once from the single-owner consts in [`crate::schema`] and
//! [`crate::backup_snapshot`], and a snapshot statement carries no bindings at
//! all, so no caller value can reach the provider. Connection endpoints and
//! credentials never cross this seam; they remain inside adapter
//! configuration.
//!
//! Both pinned batches are one `BEGIN TRANSACTION;` … `COMMIT TRANSACTION;`
//! sequence. This is the only coherent boundary available in this crate:
//! [`crate::client::session`] issues only the `version`, `signin`, `use` and
//! `query` RPC methods, so there is no `let`/cursor RPC and an open
//! cross-RPC transaction cannot exist. The shape is the one already proven
//! twice in this crate — `schema::READ_GENESIS_SCHEMA_AND_STATE` and
//! `apply::read_boundary::READ_VALIDATION_SNAPSHOT`.
//!
//! I5.1 keeps the bridge inside "validates protocol and schema generation;
//! executes named operations; returns receipts and exact errors"; I5.3 keeps
//! "No command contains a raw query string" true at this seam. A2.3
//! (ARCH-MOD-03) keeps one owner per mutable truth: the physical table names
//! stay owned by [`crate::schema`] and the class dispositions by
//! [`crate::backup_snapshot`]; this module only *references* both and
//! composes their text.

use std::sync::OnceLock;

use eliot_store_api::BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT;

use crate::backup_snapshot::{
    SNAPSHOT_BEGIN_OPERATION, SNAPSHOT_END_OPERATION, SNAPSHOT_PAGE_OPERATION,
    capture_point_statements, captured_member_tables,
};
use crate::error::AdapterError;
use crate::schema::{TX_BEGIN, TX_COMMIT};

/// Closed named-operation label for the canonical-member enumeration.
///
/// The three point labels live beside the capture logic in
/// [`crate::backup_snapshot`]; this label joins them in one closed vocabulary
/// so the member read can never be issued under an unregistered name.
pub(crate) const SNAPSHOT_MEMBERS_OPERATION: &str = "snapshot.members";

/// Redacted operation label used in every snapshot registry error.
///
/// Static text, so unknown caller input is never echoed back through an error
/// path.
const SNAPSHOT_ERROR_OPERATION: &str = "snapshot";

/// Read clause prefix for one admitted canonical source class.
///
/// `SELECT *` is this crate's own whole-record read form (see
/// `schema::TX_GUARD_FENCE`, which reads `SELECT * FROM ONLY
/// canonical_fence:current`), so no column list is restated here and the DDL
/// keeps its single owner. The narrower `SELECT VALUE body FROM <table>`
/// projection is deliberately NOT used: `canonical_event`,
/// `relation_record`, `recovery_owner` and `recovery_job` rows are written
/// without a `body` member (`apply/atomic_write.rs:425` writes only
/// `event_id`/`operation_id`, `apply/atomic_write.rs:468` only
/// `relation_id`/`relation_kind`/`operation_id`/`state_fence`, and the
/// `recovery_*` column lists carry no `body`), so that projection would read
/// `NONE` for four of the nine admitted classes and silently lose canonical
/// state A13.7 requires.
const MEMBER_CLASS_CLAUSE: &str = "SELECT * FROM ";

/// Closed snapshot vocabulary, in canonical registration order.
pub(crate) const SNAPSHOT_OPERATIONS: &[&str] = &[
    SNAPSHOT_BEGIN_OPERATION,
    SNAPSHOT_END_OPERATION,
    SNAPSHOT_MEMBERS_OPERATION,
    SNAPSHOT_PAGE_OPERATION,
];

/// Transaction delimiter that opens every pinned snapshot batch.
///
/// Referenced, never redefined, so the single owner in [`crate::schema`]
/// keeps both delimiters (A2.3 / ARCH-MOD-03).
pub(crate) fn begin_transaction_prefix() -> &'static str {
    TX_BEGIN
}

/// Transaction delimiter that closes every pinned snapshot batch.
pub(crate) fn commit_transaction_suffix() -> &'static str {
    TX_COMMIT
}

/// Interns one adapter-owned statement once and returns the same
/// `&'static str` for the process lifetime.
///
/// `concat!` accepts literals only, so the composed text cannot be a `const`
/// item: the bytes are built once from the single-owner consts and reused, so
/// the statement stays pinned and reproducible across calls.
fn intern(cell: &'static OnceLock<Box<str>>, build: impl FnOnce() -> String) -> &'static str {
    cell.get_or_init(|| build().into_boxed_str()).as_ref()
}

/// Composes the capture-point batch: the schema generation first, then the
/// canonical fence, in one transaction.
///
/// The two point reads are the exact single-owner projections in
/// [`crate::schema`], so the physical names keep their owner and the read shape
/// stays the one already proven by `apply::read_boundary`.
fn point_batch() -> String {
    let mut sql = String::with_capacity(256);
    sql.push_str(begin_transaction_prefix());
    for statement in capture_point_statements() {
        sql.push(' ');
        sql.push_str(statement);
    }
    sql.push(' ');
    sql.push_str(commit_transaction_suffix());
    sql
}

/// Composes the canonical-member batch: the same capture point, then one
/// whole-record read per admitted canonical source class, in one transaction.
///
/// One batch is one coherent point, so the denominator the capture binds is
/// observed at exactly the fence and schema generation read by the first two
/// statements. No paging is applied inside the batch: a page bound would split
/// the read across two points and destroy the coherence this module exists to
/// provide. Paging happens in Rust, over the frozen observed member set.
fn members_batch() -> String {
    let mut sql = String::with_capacity(4_096);
    sql.push_str(begin_transaction_prefix());
    for statement in capture_point_statements() {
        sql.push(' ');
        sql.push_str(statement);
    }
    for table in captured_member_tables() {
        sql.push(' ');
        sql.push_str(MEMBER_CLASS_CLAUSE);
        sql.push_str(table);
        sql.push(';');
    }
    sql.push(' ');
    sql.push_str(commit_transaction_suffix());
    sql
}

/// Pinned capture-point statement shared by the three point operations.
///
/// The three labels stay distinct so the provider error and the pool read lane
/// can attribute an outcome to the exact call, while the read itself is one
/// statement: the bound point is the same observation wherever it is taken.
fn point_statement() -> &'static str {
    static STATEMENT: OnceLock<Box<str>> = OnceLock::new();
    intern(&STATEMENT, point_batch)
}

/// Pinned canonical-member statement for [`SNAPSHOT_MEMBERS_OPERATION`].
fn members_statement() -> &'static str {
    static STATEMENT: OnceLock<Box<str>> = OnceLock::new();
    intern(&STATEMENT, members_batch)
}

/// Reports whether `name` is a member of the closed snapshot vocabulary.
pub(crate) fn is_snapshot_operation(name: &str) -> bool {
    SNAPSHOT_OPERATIONS.contains(&name)
}

/// Admits only members of the closed snapshot vocabulary.
///
/// Unknown names fail with a redacted static label; the input is never echoed
/// into the error.
pub(crate) fn validate_snapshot_operation(name: &str) -> Result<(), AdapterError> {
    if is_snapshot_operation(name) {
        Ok(())
    } else {
        Err(AdapterError::NamedOperationUnavailable {
            operation: SNAPSHOT_ERROR_OPERATION.to_owned(),
        })
    }
}

/// Maps a closed snapshot operation to its pinned fixed statement.
///
/// Each arm returns a `&'static str` composed only from single-owner consts.
/// Unknown operations fail with the same redacted static label used by
/// [`validate_snapshot_operation`].
pub(crate) fn fixed_snapshot_statement(operation: &str) -> Result<&'static str, AdapterError> {
    if operation == SNAPSHOT_MEMBERS_OPERATION {
        Ok(members_statement())
    } else if is_snapshot_operation(operation) {
        Ok(point_statement())
    } else {
        Err(AdapterError::NamedOperationUnavailable {
            operation: SNAPSHOT_ERROR_OPERATION.to_owned(),
        })
    }
}

/// Returns the public backup capability this fixed registry implements.
///
/// The coherent-snapshot capability string is owned by `eliot-store-api`; this
/// module only surfaces it so the capture can domain-separate the owner-issued
/// consistency point it issues.
pub(crate) const fn snapshot_capability() -> &'static str {
    BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT
}
