//! The one post-commit orchestration record of the authenticated
//! `UserAutomation` operator route (issue #2806).
//!
//! A canonical `UserAutomation` Store row is configuration evidence, not proof
//! that a scheduled wake was published, that a due occurrence was executed, or
//! that a retirement cancelled its pending wakes. This module owns the single
//! record that binds one committed operator operation to the runtime
//! obligations it still owns:
//!
//! ```text
//! parent operator operation
//! + committed automation/revision receipt digest
//! + current State Fence
//! + one entry per requested runtime obligation
//!     = exact owner operation identity
//!     + exact occurrence/wake identities the obligation covers
//!     + durable per-obligation disposition
//! ```
//!
//! The record is the *projection* of obligations that are retained durably
//! before any owner effect is issued, under the existing Kernel operational
//! outbox (`eliot_ors::HostRequestRecord`, staged by
//! `KernelStoreGateway::retain_user_automation_obligation`). Every identity in
//! it is derived from immutable content — the parent canonical operation
//! identity triple, the obligation kind, and the exact occurrence/wake
//! identities — so the same parent operation finds the same record after a
//! process restart instead of re-deriving a fresh replay handle.
//!
//! Store commit, wake publication/cancellation, Durable Job admission,
//! external execution and delivery stay separate phases. Nothing here claims a
//! cross-store atomic transaction, and nothing here is a scheduler, an
//! occurrence journal, a job state machine, a second canonical writer, or a
//! process-local retry ledger.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_store_api::OperationIdentity;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::user_automation_execution::UserAutomationWakePublication;

/// Domain separator of one derived runtime-obligation identity.
const OBLIGATION_IDENTITY_DOMAIN: &str = "eliot.user_automation.runtime-obligation.v1";

/// Label prefix of the derived owner operation identity of one obligation.
const OBLIGATION_OPERATION_PREFIX: &str = "ua-obligation";

/// The authenticated Host execution channel every retained obligation is issued
/// over. It is the existing wire operation name of the owned runtime transport,
/// recorded so a durable obligation names the transport that must reconcile it;
/// it is never a new route or a new authority.
pub const USER_AUTOMATION_RUNTIME_CHANNEL: &str = "USER_AUTOMATION_RUNTIME_OPERATION";

/// Closed kind of the runtime effect one committed operator operation owns.
///
/// Each variant names exactly one boundary at which a response can be lost
/// after the effect may already have been issued. A `RunNow` occurrence and a
/// read carry no kind here: neither owns an outbound effect on this route, so
/// neither retains an obligation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UserAutomationRuntimeObligationKind {
    /// Bounded recurring wake horizon published to the existing
    /// WakeIntent/Task Scheduler owner.
    WakeHorizonPublication,
    /// Exact unadmitted pending wakes cancelled at a committed retirement.
    WakeCancellation,
}

impl UserAutomationRuntimeObligationKind {
    /// Returns the stable wire spelling of this obligation kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WakeHorizonPublication => "wake_horizon_publication",
            Self::WakeCancellation => "wake_cancellation",
        }
    }

    /// Returns the capability this obligation requests from its owner.
    ///
    /// It is recorded so a durable obligation names the capability that must
    /// reconcile it, not merely the transport that carried one attempt.
    #[must_use]
    pub const fn capability_ref(self) -> &'static str {
        match self {
            Self::WakeHorizonPublication => "eliot.user-automation.wake-horizon-publication",
            Self::WakeCancellation => "eliot.user-automation.wake-cancellation",
        }
    }
}

/// The exact owner answer retained for one answered runtime obligation.
///
/// It is the bounded response body the durable outbox serves verbatim on exact
/// replay, so a lost response is resumed from the retained record rather than
/// re-derived from a fresh owner call.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationRuntimeObligationAnswer {
    /// Exact acknowledgement the schedule owner returned for the bounded
    /// horizon publication of one immutable revision.
    WakeHorizonPublication {
        /// The owner's own acknowledgement, retained verbatim.
        acknowledgement: Box<UserAutomationWakePublication>,
    },
    /// Exact wake identities the wake owner reported as cancelled.
    WakeCancellation {
        /// The owner's own cancelled wake identities, retained verbatim.
        cancelled_wake_ids: Vec<String>,
    },
}

/// Durable disposition of one retained runtime obligation.
///
/// Each variant is the projection of one state the composition-bound
/// operational outbox actually holds, so a caller reads a disposition that
/// survives a process restart instead of one re-derived from a fresh owner
/// answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationRuntimeObligationDisposition {
    /// The obligation is durably retained and its owner effect has not been
    /// issued. Nothing is known to have happened, so the effect may still be
    /// issued under the retained owner operation identity.
    Retained,
    /// The owner effect was issued and its answer is not durably known. The
    /// obligation is not safe to repeat, because a later read of the committed
    /// configuration is empty of the effect; the original owner operation
    /// identity must be reconciled first.
    Reconciling {
        /// Closed reason the obligation is not answered.
        reason: String,
    },
    /// The exact owner answer is durably retained under this obligation.
    Answered {
        /// The retained bounded owner answer, replayed verbatim.
        answer: Box<UserAutomationRuntimeObligationAnswer>,
    },
    /// No durable retention was possible, so no owner effect was issued at all.
    /// The obligation is still owed, but it carries no retained record a
    /// reconciliation could read, which is stated rather than implied.
    Unavailable {
        /// Closed reason the obligation could not be retained.
        reason: String,
    },
}

impl UserAutomationRuntimeObligationDisposition {
    /// Reports whether the durable owner proved this obligation.
    #[must_use]
    pub fn resolved(&self) -> bool {
        matches!(self, Self::Answered { .. })
    }
}

/// One requested runtime obligation of a committed operator operation, with the
/// durable disposition of the record that retains it.
///
/// `owner_operation_id` and `request_digest` are derived once, from immutable
/// content, and never re-derived at a boundary: the first is the ORIGINAL owner
/// operation identity the effect is issued and reconciled under, and the second
/// binds it to the exact occurrence or wake identities it covers. A later
/// attempt of the same parent operator operation therefore resumes the same
/// durable record instead of minting a second one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRuntimeObligation {
    /// Closed kind of the runtime effect this obligation owns.
    pub kind: UserAutomationRuntimeObligationKind,
    /// Original owner operation identity this obligation is issued and
    /// reconciled under.
    pub owner_operation_id: String,
    /// Durable digest binding this obligation to its exact subject identities.
    pub request_digest: String,
    /// Exact occurrence or wake identities this obligation covers, in the
    /// owner's own order.
    ///
    /// A horizon publication carries the exact requested slice of its
    /// revision's own normalized denominator; a cancellation carries the exact
    /// committed occurrence denominator of the retired revision whose
    /// unadmitted pending wakes are in scope. Both are immutable properties of
    /// the committed revision, so the set is identical on every later attempt.
    pub subject_ids: Vec<String>,
    /// Durable disposition of the retained record.
    pub disposition: UserAutomationRuntimeObligationDisposition,
}

/// The one post-commit orchestration record of a parent operator operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOrchestrationRecord {
    /// Exact parent operator operation identity that owns every obligation here.
    pub parent: OperationIdentity,
    /// State Fence every phase of this record was observed under.
    pub state_fence: StateFence,
    /// Stable automation identity the committed revision belongs to.
    pub automation_id: String,
    /// Immutable committed revision identity the obligations are bound to.
    pub automation_revision: String,
    /// Immutable digest of that committed revision.
    pub revision_digest: String,
    /// Exact digest of the canonical Store receipt this record follows.
    pub committed_receipt_digest: String,
    /// One entry per requested runtime obligation, each with its disposition.
    pub obligations: Vec<UserAutomationRuntimeObligation>,
}

impl UserAutomationOrchestrationRecord {
    /// Composes the one post-commit record from its committed bindings and the
    /// obligations the route retained for them.
    #[must_use]
    pub fn new(
        parent: OperationIdentity,
        state_fence: StateFence,
        automation_id: String,
        automation_revision: String,
        revision_digest: String,
        committed_receipt_digest: String,
        obligations: Vec<UserAutomationRuntimeObligation>,
    ) -> Self {
        Self {
            parent,
            state_fence,
            automation_id,
            automation_revision,
            revision_digest,
            committed_receipt_digest,
            obligations,
        }
    }

    /// Returns the obligations whose owner effect is not durably answered.
    #[must_use]
    pub fn outstanding(&self) -> Vec<&UserAutomationRuntimeObligation> {
        self.obligations
            .iter()
            .filter(|obligation| !obligation.disposition.resolved())
            .collect()
    }

    /// Reports whether every requested obligation is durably answered.
    #[must_use]
    pub fn resolved(&self) -> bool {
        self.outstanding().is_empty()
    }

    /// Rejects a record whose own projection is not internally honest.
    ///
    /// Every obligation re-derives its own durable key from this record, so a
    /// record that names an owner operation identity or a request digest it
    /// cannot re-derive is refused instead of being served as a resume handle.
    /// An unanswered disposition must also name a reason when it is not a plain
    /// retained intent, so no obligation can be reported as silently pending.
    pub fn validate(&self) -> Result<(), UserAutomationOrchestrationError> {
        self.parent.validate().map_err(|error| {
            UserAutomationOrchestrationError::InvalidParent {
                detail: error.to_string(),
            }
        })?;
        self.state_fence.validate().map_err(|error| {
            UserAutomationOrchestrationError::InvalidFence {
                detail: error.to_string(),
            }
        })?;
        validate_text(&self.automation_id, "orchestration.automation_id")?;
        validate_text(
            &self.automation_revision,
            "orchestration.automation_revision",
        )?;
        validate_digest(&self.revision_digest, "orchestration.revision_digest")?;
        validate_digest(
            &self.committed_receipt_digest,
            "orchestration.committed_receipt_digest",
        )?;
        if self.obligations.is_empty() {
            return Err(UserAutomationOrchestrationError::NoObligations);
        }
        let mut kinds = BTreeSet::new();
        for obligation in &self.obligations {
            if !kinds.insert(obligation.kind) {
                return Err(UserAutomationOrchestrationError::DuplicateObligationKind {
                    kind: obligation.kind.as_str(),
                });
            }
            let operation_id = runtime_obligation_operation_id(
                obligation.kind,
                &self.parent,
                &obligation.subject_ids,
            )?;
            if operation_id != obligation.owner_operation_id {
                return Err(
                    UserAutomationOrchestrationError::ObligationIdentityMismatch {
                        kind: obligation.kind.as_str(),
                    },
                );
            }
            let request_digest = runtime_obligation_request_digest(
                obligation.kind,
                &self.automation_id,
                &self.automation_revision,
                &self.revision_digest,
                &obligation.subject_ids,
            )?;
            if request_digest != obligation.request_digest {
                return Err(
                    UserAutomationOrchestrationError::ObligationIdentityMismatch {
                        kind: obligation.kind.as_str(),
                    },
                );
            }
            match &obligation.disposition {
                UserAutomationRuntimeObligationDisposition::Retained => {}
                UserAutomationRuntimeObligationDisposition::Reconciling { reason }
                | UserAutomationRuntimeObligationDisposition::Unavailable { reason } => {
                    validate_text(reason, "orchestration.obligation.reason")?;
                }
                UserAutomationRuntimeObligationDisposition::Answered { answer } => {
                    validate_answer(obligation.kind, answer, &obligation.subject_ids)?;
                }
            }
        }
        Ok(())
    }
}

/// Retained owner answer of one runtime obligation, bound to the obligation kind
/// and to the exact subject identities it was issued for.
fn validate_answer(
    kind: UserAutomationRuntimeObligationKind,
    answer: &UserAutomationRuntimeObligationAnswer,
    subject_ids: &[String],
) -> Result<(), UserAutomationOrchestrationError> {
    match (kind, answer) {
        (
            UserAutomationRuntimeObligationKind::WakeHorizonPublication,
            UserAutomationRuntimeObligationAnswer::WakeHorizonPublication { acknowledgement },
        ) => {
            let accounted = acknowledgement
                .acknowledged_occurrence_ids
                .iter()
                .chain(acknowledgement.remaining_occurrence_ids.iter())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            // The retained answer may account for a strict subset of the exact
            // requested slice, but it may never account for an occurrence this
            // obligation never requested: that would be a different obligation's
            // answer served under this identity.
            if subject_ids
                .iter()
                .any(|subject| !accounted.contains(subject.as_str()))
            {
                return Err(UserAutomationOrchestrationError::AnswerOutsideObligation {
                    kind: kind.as_str(),
                });
            }
            Ok(())
        }
        (
            UserAutomationRuntimeObligationKind::WakeCancellation,
            UserAutomationRuntimeObligationAnswer::WakeCancellation { cancelled_wake_ids },
        ) => {
            if cancelled_wake_ids.is_empty() {
                return Err(UserAutomationOrchestrationError::EmptyCancellationAnswer {
                    kind: kind.as_str(),
                });
            }
            let mut unique = BTreeSet::new();
            for wake_id in cancelled_wake_ids {
                validate_text(wake_id, "orchestration.cancelled_wake_id")?;
                if !unique.insert(wake_id.as_str()) {
                    return Err(UserAutomationOrchestrationError::DuplicateCancellationAnswer);
                }
            }
            Ok(())
        }
        (kind, _) => Err(UserAutomationOrchestrationError::AnswerKindMismatch {
            kind: kind.as_str(),
        }),
    }
}

/// Derives the ORIGINAL owner operation identity of one runtime obligation.
///
/// The identity is a pure function of the parent canonical operation identity
/// triple, the obligation kind, and the exact subject identities, so it is
/// identical after a process restart and different for a different parent
/// operation, a different obligation kind, or a different exact subject set. It
/// grants nothing: it names the operation a reconciliation must read, and the
/// durable record it keys is the only thing that may be replayed under it.
pub fn runtime_obligation_operation_id(
    kind: UserAutomationRuntimeObligationKind,
    parent: &OperationIdentity,
    subject_ids: &[String],
) -> Result<String, UserAutomationOrchestrationError> {
    parent
        .validate()
        .map_err(|error| UserAutomationOrchestrationError::InvalidParent {
            detail: error.to_string(),
        })?;
    validate_subject_ids(subject_ids)?;
    let bytes = canonical_json_bytes(&(
        OBLIGATION_IDENTITY_DOMAIN,
        "operation",
        kind.as_str(),
        parent.operation_id.as_str(),
        parent.idempotency_key.as_str(),
        parent.canonical_request_hash.as_str(),
        subject_ids,
    ))
    .map_err(
        |error| UserAutomationOrchestrationError::CanonicalEncoding {
            detail: error.to_string(),
        },
    )?;
    Ok(format!(
        "{OBLIGATION_OPERATION_PREFIX}:{}:{}",
        kind.as_str(),
        sha256_hex(&bytes)
    ))
}

/// Derives the durable request digest that binds one runtime obligation to the
/// immutable automation/revision and the exact occurrence or wake identities it
/// covers.
pub fn runtime_obligation_request_digest(
    kind: UserAutomationRuntimeObligationKind,
    automation_id: &str,
    automation_revision: &str,
    revision_digest: &str,
    subject_ids: &[String],
) -> Result<String, UserAutomationOrchestrationError> {
    validate_text(automation_id, "obligation.automation_id")?;
    validate_text(automation_revision, "obligation.automation_revision")?;
    validate_digest(revision_digest, "obligation.revision_digest")?;
    validate_subject_ids(subject_ids)?;
    let bytes = canonical_json_bytes(&(
        OBLIGATION_IDENTITY_DOMAIN,
        "request",
        kind.as_str(),
        automation_id,
        automation_revision,
        revision_digest,
        subject_ids,
    ))
    .map_err(
        |error| UserAutomationOrchestrationError::CanonicalEncoding {
            detail: error.to_string(),
        },
    )?;
    Ok(sha256_hex(&bytes))
}

/// Derives the digest over the exact subject identities alone, used as the
/// durable payload digest of the retained record so the exact occurrence/wake
/// set is bound independently of the automation binding.
pub fn runtime_obligation_payload_digest(
    subject_ids: &[String],
) -> Result<String, UserAutomationOrchestrationError> {
    validate_subject_ids(subject_ids)?;
    let bytes = canonical_json_bytes(&(OBLIGATION_IDENTITY_DOMAIN, "payload", subject_ids))
        .map_err(
            |error| UserAutomationOrchestrationError::CanonicalEncoding {
                detail: error.to_string(),
            },
        )?;
    Ok(sha256_hex(&bytes))
}

/// Builds the durable obligation of one runtime effect, at the disposition that
/// says the intent is retained and the effect has not been issued yet.
pub fn retained_user_automation_obligation(
    kind: UserAutomationRuntimeObligationKind,
    parent: &OperationIdentity,
    automation_id: &str,
    automation_revision: &str,
    revision_digest: &str,
    subject_ids: &[String],
) -> Result<UserAutomationRuntimeObligation, UserAutomationOrchestrationError> {
    Ok(UserAutomationRuntimeObligation {
        kind,
        owner_operation_id: runtime_obligation_operation_id(kind, parent, subject_ids)?,
        request_digest: runtime_obligation_request_digest(
            kind,
            automation_id,
            automation_revision,
            revision_digest,
            subject_ids,
        )?,
        subject_ids: subject_ids.to_vec(),
        disposition: UserAutomationRuntimeObligationDisposition::Retained,
    })
}

/// Rejects a subject set that is empty, blank, or contains a duplicate, because
/// a durable obligation over an unnamed or double-counted set cannot be
/// reconciled by identity.
fn validate_subject_ids(subject_ids: &[String]) -> Result<(), UserAutomationOrchestrationError> {
    if subject_ids.is_empty() {
        return Err(UserAutomationOrchestrationError::NoSubjectIdentities);
    }
    let mut unique = BTreeSet::new();
    for subject_id in subject_ids {
        validate_text(subject_id, "obligation.subject_id")?;
        if !unique.insert(subject_id.as_str()) {
            return Err(UserAutomationOrchestrationError::DuplicateSubjectIdentity);
        }
    }
    Ok(())
}

/// Rejects a blank or control-character-bearing identity field.
fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationOrchestrationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationOrchestrationError::InvalidField { field });
    }
    Ok(())
}

/// Rejects a field that is not a lowercase SHA-256 digest.
fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), UserAutomationOrchestrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UserAutomationOrchestrationError::InvalidDigest { field });
    }
    Ok(())
}

/// Typed failure of one post-commit orchestration record.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationOrchestrationError {
    /// The parent operator operation identity is not a well-formed identity.
    #[error("post-commit orchestration parent operation identity is invalid: {detail}")]
    InvalidParent {
        /// Owner refusal from the canonical operation identity.
        detail: String,
    },
    /// The State Fence of the record is not a well-formed fence.
    #[error("post-commit orchestration State Fence is invalid: {detail}")]
    InvalidFence {
        /// Owner refusal from the State Fence.
        detail: String,
    },
    /// A record field is blank or carries a control character.
    #[error("post-commit orchestration {field} must be non-blank text")]
    InvalidField {
        /// The offending field.
        field: &'static str,
    },
    /// A digest field is not a lowercase SHA-256 digest.
    #[error("post-commit orchestration {field} must be a lowercase SHA-256 digest")]
    InvalidDigest {
        /// The offending field.
        field: &'static str,
    },
    /// The exact identity material could not be canonically encoded.
    #[error("post-commit orchestration identity encoding failed: {detail}")]
    CanonicalEncoding {
        /// Owner refusal from the canonical encoder.
        detail: String,
    },
    /// A record that owns no obligation would claim an orchestration it never
    /// performed.
    #[error("a post-commit orchestration record must name the obligations it owns")]
    NoObligations,
    /// One obligation kind was requested twice under the same parent operation.
    #[error("post-commit orchestration requested the {kind} obligation twice")]
    DuplicateObligationKind {
        /// The repeated obligation kind.
        kind: &'static str,
    },
    /// A retained obligation names a durable key it cannot re-derive from the
    /// immutable bindings of its own record.
    #[error("post-commit orchestration {kind} obligation names a durable key it cannot re-derive")]
    ObligationIdentityMismatch {
        /// The offending obligation kind.
        kind: &'static str,
    },
    /// An obligation covers no exact occurrence or wake identity.
    #[error("a runtime obligation must name the exact occurrence or wake identities it covers")]
    NoSubjectIdentities,
    /// An obligation covers one identity twice.
    #[error("a runtime obligation must not count one occurrence or wake identity twice")]
    DuplicateSubjectIdentity,
    /// A retained cancellation answer is empty, which no owner that was handed
    /// a non-empty exact target set can return.
    #[error("a retained {kind} answer with no cancelled wake identity is not an owner answer")]
    EmptyCancellationAnswer {
        /// The offending obligation kind.
        kind: &'static str,
    },
    /// A retained cancellation answer counts one wake identity twice.
    #[error("a retained cancellation answer must not count one wake identity twice")]
    DuplicateCancellationAnswer,
    /// A retained answer accounts for an occurrence this obligation never
    /// requested, so it belongs to a different obligation.
    #[error("a retained {kind} answer accounts for an occurrence outside this obligation")]
    AnswerOutsideObligation {
        /// The offending obligation kind.
        kind: &'static str,
    },
    /// A retained answer does not match the obligation kind it is filed under.
    #[error("a retained answer of another kind cannot answer this {kind} obligation")]
    AnswerKindMismatch {
        /// The offending obligation kind.
        kind: &'static str,
    },
}
