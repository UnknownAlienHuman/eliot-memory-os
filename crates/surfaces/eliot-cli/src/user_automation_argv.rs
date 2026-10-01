//! Closed argv parser for the advertised `user-automation` command (#1779).
//!
//! The catalogue row published by [`super`] already advertises
//! `eliot user-automation <create|list|status|history|pause|resume|edit|run-now|remove|inspect-last-failure>`
//! with [`super::ArgumentKind::UserAutomation`]. This module is the parser that
//! row advertises: it turns one explicit argv selection into the closed
//! [`UserAutomationCommand`] operation vocabulary owned by
//! `eliot_kernel_core`, and refuses anything that vocabulary does not admit.
//!
//! Three properties this parser holds, and that the argv entrypoint depends on:
//!
//! 1. **It mints nothing.** It builds an *operation*, never a
//!    [`RequestIdentity`](eliot_protocol::RequestIdentity). Principal, session,
//!    state fence, deadline, cancellation and idempotency identity arrive with
//!    the admitted host request, `AuthenticatedKernelPort` binds them through
//!    `set_request_identity`, and the Kernel admits on exactly those. There is
//!    no constructor here that could produce one.
//! 2. **It defaults nothing.** Every field is explicit. `include_retired` is a
//!    required boolean rather than a defaulted flag, `run-now` carries the
//!    Human-issued manual nonce the Human must supply (I11.12:33), and
//!    `create`/`edit` carry whole owner-authored immutable revisions rather
//!    than assembled partials — an ambiguous phrase is never guessed and a
//!    missing revision member is never filled in.
//! 3. **It is a second spelling, not a second authority.**
//!    [`admitted_operation`] binds this parser's output to the operation the
//!    admitted [`CommandRequest`] actually carries and refuses any
//!    disagreement, so `eliot user-automation run-now` can never run a
//!    `create`. The caller then dispatches the *admitted* request through the
//!    same `CommandCatalogue::dispatch` the `eliot dispatch` channel uses, so
//!    the argv path cannot bypass the Kernel front door.
//!
//! `run-now` mutates no schedule. [`UserAutomationOperation::RunNow`] carries
//! no schedule member at all, so a manual run cannot move the normalized
//! trigger contract even if this parser wanted it to; the immutable revision
//! to run is named by identity, and the Kernel executes that revision.
//!
//! The closed operation vocabulary, its field bounds, and the revision
//! validation are the owner's (`eliot_kernel_core`), not a second local copy:
//! this module only refuses blank and control-character argv text locally so
//! the refusal names the offending flag, then defers every other admission
//! rule to [`UserAutomationOperation::validate`].

use eliot_kernel_core::{UserAutomationOperation, UserAutomationRevision};

use super::{CliError, CommandArguments, CommandId, CommandRequest, UserAutomationCommand};

/// One explicit `eliot user-automation` argv selection.
///
/// Every variant names exactly the members its closed operation carries. No
/// variant has an optional member and no member is derived from another, so a
/// selection can only be built from fields the operator actually supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserAutomationArgv {
    /// `create`: persist the first immutable revision.
    Create {
        /// Whole owner-authored immutable revision.
        revision: Box<UserAutomationRevision>,
    },
    /// `list`: read the visible revision projection.
    List {
        /// Explicitly chosen projection width; never defaulted.
        include_retired: bool,
    },
    /// `status`: read current status for one automation.
    Status {
        /// Stable automation identity.
        automation_id: String,
    },
    /// `history`: read immutable execution/history records.
    History {
        /// Stable automation identity.
        automation_id: String,
    },
    /// `pause`: stop future admissions at one exact revision.
    Pause {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being paused.
        automation_revision: String,
    },
    /// `resume`: resume future admissions at the same immutable revision.
    Resume {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being resumed.
        automation_revision: String,
    },
    /// `edit`: create a new immutable superseding revision.
    Edit {
        /// Whole current revision that must be superseded.
        previous_revision: Box<UserAutomationRevision>,
        /// Whole new immutable revision.
        revision: Box<UserAutomationRevision>,
    },
    /// `run-now`: run once under an explicit manual nonce.
    RunNow {
        /// Stable automation identity.
        automation_id: String,
        /// Exact immutable revision to run.
        automation_revision: String,
        /// Explicit Human-issued manual nonce; never supplied or derived here.
        nonce: String,
    },
    /// `remove`: retire future work while preserving history.
    Remove {
        /// Stable automation identity.
        automation_id: String,
        /// Exact revision being retired.
        automation_revision: String,
    },
    /// `inspect-last-failure`: read the last owner-issued failure.
    InspectLastFailure {
        /// Stable automation identity.
        automation_id: String,
    },
}

impl UserAutomationArgv {
    /// The exact advertised subcommand spelling this selection was parsed from.
    ///
    /// These ten spellings are the ones `lib.rs` prints in the catalogue usage
    /// string, so the help text and the parser cannot name different things.
    pub const fn subcommand(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::List { .. } => "list",
            Self::Status { .. } => "status",
            Self::History { .. } => "history",
            Self::Pause { .. } => "pause",
            Self::Resume { .. } => "resume",
            Self::Edit { .. } => "edit",
            Self::RunNow { .. } => "run-now",
            Self::Remove { .. } => "remove",
            Self::InspectLastFailure { .. } => "inspect-last-failure",
        }
    }

    /// Compiles this argv selection into the closed typed operation.
    ///
    /// Blank or control-character argv text refuses here so the refusal names
    /// the flag the operator typed; every other admission rule — the
    /// 16 KiB text bound, the revision lineage and supersession check, the
    /// nested work scope, task, capability, route/cost and provider policies,
    /// and the preflight contract revision — belongs to the owner's
    /// [`UserAutomationOperation::validate`] and is not restated here.
    pub fn command(&self) -> Result<UserAutomationCommand, CliError> {
        let operation = match self.clone() {
            Self::Create { revision } => UserAutomationOperation::Create { revision },
            Self::List { include_retired } => UserAutomationOperation::List { include_retired },
            Self::Status { automation_id } => UserAutomationOperation::Status {
                automation_id: text(&automation_id, "automation-id")?,
            },
            Self::History { automation_id } => UserAutomationOperation::History {
                automation_id: text(&automation_id, "automation-id")?,
            },
            Self::Pause {
                automation_id,
                automation_revision,
            } => UserAutomationOperation::Pause {
                automation_id: text(&automation_id, "automation-id")?,
                automation_revision: text(&automation_revision, "automation-revision")?,
            },
            Self::Resume {
                automation_id,
                automation_revision,
            } => UserAutomationOperation::Resume {
                automation_id: text(&automation_id, "automation-id")?,
                automation_revision: text(&automation_revision, "automation-revision")?,
            },
            Self::Edit {
                previous_revision,
                revision,
            } => UserAutomationOperation::Edit {
                previous_revision,
                revision,
            },
            Self::RunNow {
                automation_id,
                automation_revision,
                nonce,
            } => UserAutomationOperation::RunNow {
                automation_id: text(&automation_id, "automation-id")?,
                automation_revision: text(&automation_revision, "automation-revision")?,
                nonce: text(&nonce, "nonce")?,
            },
            Self::Remove {
                automation_id,
                automation_revision,
            } => UserAutomationOperation::Remove {
                automation_id: text(&automation_id, "automation-id")?,
                automation_revision: text(&automation_revision, "automation-revision")?,
            },
            Self::InspectLastFailure { automation_id } => {
                UserAutomationOperation::InspectLastFailure {
                    automation_id: text(&automation_id, "automation-id")?,
                }
            }
        };
        operation
            .validate()
            .map_err(|error| CliError::UserAutomation(error.to_string()))?;
        Ok(operation)
    }
}

/// Binds one argv selection to the operation the admitted request carries.
///
/// This is the binding that makes the argv path a second *spelling* rather
/// than a second authority. It returns the admitted operation only when three
/// independent facts agree:
///
/// 1. the argv selection compiles under the owner's closed validation,
/// 2. the admitted request's typed `command` is `UserAutomation`, and
/// 3. the admitted request's `UserAutomation` operation is byte-for-byte the
///    operation the argv selection names.
///
/// Any disagreement refuses with [`CliError`] before a byte reaches the
/// Kernel, so `eliot user-automation run-now` can never dispatch a `create`,
/// a `list` can never be widened by a substituted payload, and no argv
/// selection can introduce an operation the advertised usage does not name
/// (notably `DecideImprovementBrief`, which stays reachable only through the
/// dispatch channel that carries it in full).
///
/// The correlated [`RequestIdentity`] itself is never inspected for
/// authorization here and never constructed here: it is validated by
/// [`CommandRequest::validate`] and bound by `AuthenticatedKernelPort`, so
/// this function adds a field-level agreement check without becoming a second
/// admission point.
pub fn admitted_operation(
    selection: &UserAutomationArgv,
    request: &CommandRequest,
) -> Result<UserAutomationCommand, CliError> {
    let expected = selection.command()?;
    if request.command != CommandId::UserAutomation {
        return Err(CliError::ArgumentCommandMismatch);
    }
    let CommandArguments::UserAutomation { operation } = &request.arguments else {
        return Err(CliError::ArgumentCommandMismatch);
    };
    if operation != &expected {
        return Err(CliError::UserAutomation(format!(
            "the admitted request carries a different operation than the `{}` subcommand selects",
            selection.subcommand()
        )));
    }
    Ok(expected)
}

/// Refuses blank or control-character argv text, naming the offending flag.
fn text(value: &str, field: &str) -> Result<String, CliError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::UserAutomation(format!(
            "argument --{field} is blank or contains control characters"
        )));
    }
    Ok(value.to_owned())
}
