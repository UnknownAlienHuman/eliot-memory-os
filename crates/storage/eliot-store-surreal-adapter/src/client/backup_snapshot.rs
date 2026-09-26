//! Fixed coherent-snapshot operation registration for the `SurrealDB` seam.
//!
//! Only the four closed `snapshot.*` operations below may execute. Caller text
//! never becomes a statement: every operation maps to one fixed `&'static str`
//! built from the single-owner consts in [`crate::schema`],
//! [`crate::backup_snapshot`] and the `eliot_store_api` capture ceilings, and a
//! snapshot statement carries no bindings at
//! all, so no caller value can reach the provider. Connection endpoints and
//! credentials never cross this seam; they remain inside adapter
//! configuration.
//!
//! Both batches are one `BEGIN TRANSACTION;` … `COMMIT TRANSACTION;` sequence.
//! This is the only coherent boundary reachable through this crate's client
//! seam: [`crate::client::session`] issues only the `version`, `signin`, `use`
//! and `query` RPC methods, so this seam has no way to hold a transaction open
//! across RPC calls. (The provider protocol does expose `begin`/`commit`/
//! `cancel`; reaching them would mean extending `client/session.rs`, which is
//! outside this leaf's mutable scope. Do not read the sentence above as a
//! claim that the provider lacks them.) The batch shape is the one already
//! proven twice in this crate — `schema::READ_GENESIS_SCHEMA_AND_STATE` and
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

/// Clause that binds the fixed row ceiling onto one class read.
const MEMBER_CLASS_LIMIT_CLAUSE: &str = " LIMIT ";

/// Row ceiling the fixed member batch places on every captured class.
///
/// The provider read is bounded by a *fixed, adapter-owned* ceiling, never by a
/// caller value. A request-derived `LIMIT` would put caller text into the
/// statement, which this module forbids outright ("a snapshot statement carries
/// no bindings at all, so no caller value can reach the provider"), so the
/// request's own `bounds.max_members` cannot be pushed into the provider read;
/// what this constant does instead is make the read finite and make overflow
/// *detectable*.
///
/// The value is exactly `eliot_store_api::MAX_SNAPSHOT_MEMBERS`, the same
/// single-owner ceiling `begin_snapshot` enforces on the observed denominator.
/// That makes the bound tight rather than arbitrary: a capture that could serve
/// at most `MAX_SNAPSHOT_MEMBERS` members in total can never legitimately hold
/// more than that in one class, so this limit never truncates an admissible
/// capture. Before this bound the member batch read every row of every captured
/// table with no ceiling at all, so a store too large to capture was read into
/// bridge memory in full and refused only afterwards.
pub(crate) const MEMBER_CLASS_ROW_LIMIT: usize = eliot_store_api::MAX_SNAPSHOT_MEMBERS;

/// Row ceiling actually written into the statement: the capture ceiling plus
/// one, so truncation is *provable* rather than guessed.
///
/// A class holding exactly [`MEMBER_CLASS_ROW_LIMIT`] rows is complete, and
/// refusing it would reject a capture the bounds allow. Reading one row more
/// than the ceiling is what makes the difference observable: a class that comes
/// back with more than [`MEMBER_CLASS_ROW_LIMIT`] rows is certainly truncated,
/// while one that comes back with exactly the ceiling is certainly not. This is
/// the same one-over discipline the capture bounds use elsewhere.
const MEMBER_CLASS_ROW_LIMIT_ONE_OVER: usize = MEMBER_CLASS_ROW_LIMIT + 1;

/// Closed snapshot vocabulary, in canonical registration order.
pub(crate) const SNAPSHOT_OPERATIONS: &[&str] = &[
    SNAPSHOT_BEGIN_OPERATION,
    SNAPSHOT_END_OPERATION,
    SNAPSHOT_MEMBERS_OPERATION,
    SNAPSHOT_PAGE_OPERATION,
];

/// Transaction delimiter that opens every snapshot batch.
///
/// Referenced, never redefined, so the single owner in [`crate::schema`]
/// keeps both delimiters (A2.3 / ARCH-MOD-03).
pub(crate) fn begin_transaction_prefix() -> &'static str {
    TX_BEGIN
}

/// Transaction delimiter that closes every snapshot batch.
pub(crate) fn commit_transaction_suffix() -> &'static str {
    TX_COMMIT
}

/// Interns one adapter-owned statement once and returns the same
/// `&'static str` for the process lifetime.
///
/// The composed text is *not* a `const` item, and this is a deliberate,
/// stated mechanism rather than an accident:
///
/// * `concat!` accepts literals only. It cannot interpolate
///   `crate::schema::table::*`, so the only way to express these batches as
///   one `concat!` would be to restate every physical table name in this
///   module — a second owner for names A2.3 reserves to
///   [`crate::schema`], and exactly the duplication the module doc forbids.
/// * Therefore the bytes are assembled at first use from the single-owner
///   consts and stored in a [`OnceLock`].
///
/// The result is still a process-stable `&'static str`, so callers hold the
/// same pointer for the process lifetime and the statement text is
/// reproducible. What it is *not* is decided at compile time; nothing here
/// should claim otherwise.
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
/// bounded whole-record read per admitted canonical source class, in one
/// transaction.
///
/// One batch is one coherent point, so the denominator the capture binds is
/// observed at exactly the fence and schema generation read by the first two
/// statements. The read is *bounded*, not paged: each class carries the fixed
/// [`MEMBER_CLASS_ROW_LIMIT_ONE_OVER`] ceiling, because paging inside the batch
/// would split one logical read across two points and destroy the coherence
/// this module exists to provide. Paging happens in Rust, over the frozen
/// observed member set. A class that exceeds the capture ceiling is certainly
/// truncated, and `read_enumeration` refuses it explicitly rather than letting a
/// possibly incomplete denominator pass as a complete one.
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
        // The ceiling is a `usize` const of this crate, never caller text, so
        // composing it here adds no caller-reachable input to the statement.
        sql.push_str(MEMBER_CLASS_LIMIT_CLAUSE);
        sql.push_str(&MEMBER_CLASS_ROW_LIMIT_ONE_OVER.to_string());
        sql.push(';');
    }
    sql.push(' ');
    sql.push_str(commit_transaction_suffix());
    sql
}

/// Interned capture-point statement shared by the three point operations.
///
/// The three labels stay distinct so the provider error and the pool read lane
/// can attribute an outcome to the exact call, while the read itself is one
/// statement: the bound point is the same observation wherever it is taken.
fn point_statement() -> &'static str {
    static STATEMENT: OnceLock<Box<str>> = OnceLock::new();
    intern(&STATEMENT, point_batch)
}

/// Interned canonical-member statement for [`SNAPSHOT_MEMBERS_OPERATION`].
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

/// Maps a closed snapshot operation to its fixed interned statement.
///
/// Each arm returns a process-stable `&'static str` assembled only from
/// single-owner consts. Unknown operations fail with the same redacted static
/// label used by [`validate_snapshot_operation`].
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
