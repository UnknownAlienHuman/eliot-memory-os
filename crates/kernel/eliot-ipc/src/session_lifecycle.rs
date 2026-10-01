//! I7.14 application-owned session lifecycle, independent of transport reconnects.
//!
//! The transport session fence ([`SessionState`]) is a per-connection object.
//! The application session authority owned here is the Kernel source of truth
//! for one ELIOT session: transport bindings are replaceable continuity
//! observations, and only application-level expiry, revocation or explicit
//! detach moves the session to a terminal state.
//!
//! Canonical lifecycle (I7.14):
//!
//! ```text
//! ATTACHING → ACTIVE ↔ SUSPENDED → DETACHED | EXPIRED | REVOKED
//! ```
//!
//! Session loss revokes session-bound leases, checkpoints durable tasks/jobs,
//! never deletes work/evidence, raises the Authority Epoch before reassignment,
//! and retains Route Continuation State only under an explicit policy/TTL.
//! MCP connection loss, stdio restart or HTTP reconnect does not end the
//! ELIOT Session: a replacement transport binding is recorded as a continuity
//! observation and the application session stays [`ApplicationSessionState::Active`].

use std::collections::BTreeMap;
use std::fmt;

use eliot_contracts::{EpochId, EpochRelation};
use thiserror::Error;

use crate::role_lease::{
    AgentRole, CapabilityContext, DelegatedAuthority, IndependenceDowngrade, RoleLeaseError,
    RoleTransitionRecord, ScopeBinding, WorkScopePolicy,
};

/// Maximum retained transport binding continuity observations per session.
const MAX_TRANSPORT_BINDINGS: usize = 1024;

/// Maximum retained durable work checkpoints per session.
const MAX_DURABLE_CHECKPOINTS: usize = 1024;

/// Canonical application-owned session lifecycle states (I7.14).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationSessionState {
    /// The session is being established; no transport binding is active yet.
    Attaching,
    /// The session is live; transport bindings may be replaced freely.
    Active,
    /// The session is temporarily suspended; it may resume or end.
    Suspended,
    /// Explicit application detach; terminal.
    Detached,
    /// Application-level expiry; terminal.
    Expired,
    /// Explicit application revocation; terminal. Revokes session-bound leases
    /// and checkpoints durable work.
    Revoked,
}

impl fmt::Display for ApplicationSessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Attaching => "ATTACHING",
            Self::Active => "ACTIVE",
            Self::Suspended => "SUSPENDED",
            Self::Detached => "DETACHED",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
        };
        formatter.write_str(name)
    }
}

impl ApplicationSessionState {
    /// Returns whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Detached | Self::Expired | Self::Revoked)
    }

    /// Validates one legal I7.14 transition, failing closed on any other.
    ///
    /// Legal transitions are `Attaching → Active`, `Active ↔ Suspended`, and
    /// `Active | Suspended → Detached | Expired | Revoked`. Terminal states
    /// have no outgoing transition.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] for any transition
    /// outside the canonical lifecycle.
    pub fn transition_to(&self, next: Self) -> Result<(), SessionLifecycleError> {
        let legal = match self {
            Self::Attaching => matches!(next, Self::Active),
            Self::Active => matches!(
                next,
                Self::Suspended | Self::Detached | Self::Expired | Self::Revoked
            ),
            Self::Suspended => matches!(
                next,
                Self::Active | Self::Detached | Self::Expired | Self::Revoked
            ),
            Self::Detached | Self::Expired | Self::Revoked => false,
        };
        if legal {
            Ok(())
        } else {
            Err(SessionLifecycleError::IllegalTransition {
                from: *self,
                to: next,
            })
        }
    }
}

/// Fail-closed failures of the application session lifecycle.
///
/// Every variant fails closed: no denial implies a narrower permission.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SessionLifecycleError {
    /// The requested transition is outside the canonical I7.14 lifecycle.
    #[error("illegal application session transition {from} -> {to}")]
    IllegalTransition {
        /// Current state.
        from: ApplicationSessionState,
        /// Requested state.
        to: ApplicationSessionState,
    },
    /// A required text binding is empty or carries control characters.
    #[error("invalid session binding {field:?}: empty or control characters")]
    InvalidBinding {
        /// Binding field name.
        field: &'static str,
    },
    /// A transport binding identity is empty or carries control characters.
    #[error("invalid transport binding id: empty or control characters")]
    InvalidBindingId,
    /// The transport binding or checkpoint registry is full.
    #[error("application session registry is full")]
    RegistryFull,
    /// The lease window does not open before it expires.
    #[error("lease expiry {expires_at_unix_ms} does not exceed issuance {issued_at_unix_ms}")]
    InvalidLeaseWindow {
        /// Owner-observed issuance time.
        issued_at_unix_ms: u64,
        /// Owner-observed expiry.
        expires_at_unix_ms: u64,
    },
    /// Reassignment was attempted without a higher authority epoch.
    #[error("reassignment requires a higher authority epoch than the recorded {current:?}")]
    EpochNotAdvanced {
        /// Currently recorded authority epoch.
        current: EpochId,
    },
    /// Continuation state was retained without an explicit policy/TTL.
    #[error("continuation state retention requires an explicit policy/TTL")]
    ContinuationPolicyRequired,
    /// The continuation state TTL must be a positive duration.
    #[error("continuation state TTL must be positive")]
    InvalidContinuationTtl,
    /// Role capability compilation, admission or transition failed closed.
    #[error(transparent)]
    RoleLease(#[from] RoleLeaseError),
    /// A role capability admission was attempted while one is already
    /// admitted for this session; transition instead.
    #[error("role capability context is already admitted for this session")]
    RoleCapabilityAlreadyAdmitted,
    /// A role transition was attempted with no admitted role capability
    /// context for this session.
    #[error("no role capability context is admitted for this session")]
    RoleCapabilityNotAdmitted,
}

/// The replaceable transport kinds that can bind to one application session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// Local authenticated EBP/1 named pipe.
    Pipe,
    /// stdio bridge restart.
    Stdio,
    /// HTTP reconnect.
    Http,
}

/// One replaceable transport binding recorded as a continuity observation.
///
/// A transport binding never authorizes anything on its own; it only records
/// that a transport was bound to the application session at a point in time.
/// A reconnect replaces the binding and appends a new observation, leaving the
/// application session [`ApplicationSessionState::Active`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportBindingObservation {
    /// Exact connection/transport identity of this binding.
    pub binding_id: String,
    /// The transport kind of this binding.
    pub transport: TransportKind,
    /// Transport session fence captured at bind time; never reused.
    pub session_epoch: u64,
    /// Owner-observed bind time (Unix ms).
    pub observed_at_unix_ms: u64,
}

/// One session-bound lease tracked by the application session authority.
///
/// A lease is bound to the session for its whole lifetime; session loss revokes
/// every bound lease. The lease window is owner-observed and validated
/// fail-closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLease {
    /// Exact lease identity.
    pub lease_id: String,
    /// Owner-assigned lease epoch; bumped on every role transition.
    pub lease_epoch: u64,
    /// Owner-observed issuance time (Unix ms).
    pub issued_at_unix_ms: u64,
    /// Owner-observed expiry (Unix ms); must exceed issuance.
    pub expires_at_unix_ms: u64,
    /// Whether this lease was revoked by session revocation.
    pub revoked: bool,
}

/// One durable task/job checkpoint recorded for the session.
///
/// Checkpoints preserve the exact durable work state so a later session can
/// resume without deleting work or evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableWorkCheckpoint {
    /// Exact checkpoint identity.
    pub checkpoint_id: String,
    /// The durable task/job reference that was checkpointed.
    pub work_ref: String,
    /// Owner-observed checkpoint time (Unix ms).
    pub checkpointed_at_unix_ms: u64,
}

/// The Kernel application-owned session authority (I7.14).
///
/// This is the source of truth for one ELIOT session. It is deliberately
/// independent of any single transport: transport bindings are recorded as
/// replaceable continuity observations, and only application-level expiry,
/// revocation or explicit detach moves the session to a terminal state.
///
/// Session loss revokes every session-bound lease, checkpoints durable
/// tasks/jobs, never deletes work/evidence, raises the Authority Epoch before
/// reassignment, and retains Route Continuation State only under an explicit
/// policy/TTL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationSession {
    session_id: String,
    authority_epoch: EpochId,
    state: ApplicationSessionState,
    transport_bindings: Vec<TransportBindingObservation>,
    bound_leases: BTreeMap<String, SessionLease>,
    durable_checkpoints: Vec<DurableWorkCheckpoint>,
    continuation_ttl_ms: Option<u64>,
    role_capability: Option<CapabilityContext>,
}

impl ApplicationSession {
    /// Creates a new application session authority in
    /// [`ApplicationSessionState::Attaching`] under `authority_epoch`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::InvalidBinding`] when `session_id` is
    /// empty or carries control characters.
    pub fn new(
        session_id: impl Into<String>,
        authority_epoch: EpochId,
    ) -> Result<Self, SessionLifecycleError> {
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        Ok(Self {
            session_id,
            authority_epoch,
            state: ApplicationSessionState::Attaching,
            transport_bindings: Vec::new(),
            bound_leases: BTreeMap::new(),
            durable_checkpoints: Vec::new(),
            continuation_ttl_ms: None,
            role_capability: None,
        })
    }

    /// Transitions the session to [`ApplicationSessionState::Active`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Attaching`].
    pub fn attach(&mut self) -> Result<(), SessionLifecycleError> {
        self.transition_to(ApplicationSessionState::Active)
    }

    /// Suspends an [`ApplicationSessionState::Active`] session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Active`].
    pub fn suspend(&mut self) -> Result<(), SessionLifecycleError> {
        self.transition_to(ApplicationSessionState::Suspended)
    }

    /// Resumes an [`ApplicationSessionState::Suspended`] session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Suspended`].
    pub fn resume(&mut self) -> Result<(), SessionLifecycleError> {
        self.transition_to(ApplicationSessionState::Active)
    }

    /// Performs an explicit application detach.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Active`] or
    /// [`ApplicationSessionState::Suspended`]. `now_unix_ms` is the session
    /// owner's observed detach time used for the durable checkpoint.
    pub fn detach(&mut self, now_unix_ms: u64) -> Result<(), SessionLifecycleError> {
        self.lose_session(ApplicationSessionState::Detached, now_unix_ms)
    }

    /// Applies an application-level expiry.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Active`] or
    /// [`ApplicationSessionState::Suspended`]. `now_unix_ms` is the session
    /// owner's observed expiry time used for the durable checkpoint.
    pub fn expire(&mut self, now_unix_ms: u64) -> Result<(), SessionLifecycleError> {
        self.lose_session(ApplicationSessionState::Expired, now_unix_ms)
    }

    /// Performs an explicit application revocation.
    ///
    /// Revokes every session-bound lease and records a durable work checkpoint
    /// so durable tasks/jobs survive the revocation. Work and evidence records
    /// are never deleted. Reassignment stays blocked until a higher authority
    /// epoch is recorded via [`Self::reassign`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] unless the current
    /// state is [`ApplicationSessionState::Active`] or
    /// [`ApplicationSessionState::Suspended`].
    pub fn revoke(&mut self, now_unix_ms: u64) -> Result<(), SessionLifecycleError> {
        self.lose_session(ApplicationSessionState::Revoked, now_unix_ms)
    }

    /// Raises the authority epoch and prepares the session for reassignment.
    ///
    /// Reassignment is blocked until a higher same-lineage authority epoch is
    /// provided. On success the session returns to
    /// [`ApplicationSessionState::Attaching`] under the new epoch, so a
    /// successor transport can bind without inheriting the revoked session's
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] when the session is
    /// not terminal, or [`SessionLifecycleError::EpochNotAdvanced`] when
    /// `new_epoch` is not a higher same-lineage epoch.
    pub fn reassign(&mut self, new_epoch: EpochId) -> Result<(), SessionLifecycleError> {
        if !self.state.is_terminal() {
            return Err(SessionLifecycleError::IllegalTransition {
                from: self.state,
                to: ApplicationSessionState::Attaching,
            });
        }
        if !matches!(
            new_epoch.relation_to(&self.authority_epoch),
            EpochRelation::DirectParent | EpochRelation::SameLineageNewer
        ) {
            return Err(SessionLifecycleError::EpochNotAdvanced {
                current: self.authority_epoch.clone(),
            });
        }
        self.authority_epoch = new_epoch;
        self.state = ApplicationSessionState::Attaching;
        Ok(())
    }

    /// Binds one session-bound lease to this session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::InvalidBinding`] when `lease_id` is
    /// empty or carries control characters, or
    /// [`SessionLifecycleError::InvalidLeaseWindow`] when the lease window does
    /// not open before it expires. Returns
    /// [`SessionLifecycleError::IllegalTransition`] when the session is terminal.
    pub fn bind_lease(
        &mut self,
        lease_id: impl Into<String>,
        lease_epoch: u64,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        if self.state.is_terminal() {
            return Err(SessionLifecycleError::IllegalTransition {
                from: self.state,
                to: ApplicationSessionState::Active,
            });
        }
        let lease_id = lease_id.into();
        validate_session_id(&lease_id)?;
        if expires_at_unix_ms <= issued_at_unix_ms {
            return Err(SessionLifecycleError::InvalidLeaseWindow {
                issued_at_unix_ms,
                expires_at_unix_ms,
            });
        }
        if self.bound_leases.contains_key(&lease_id) {
            return Err(SessionLifecycleError::InvalidBinding { field: "lease_id" });
        }
        self.bound_leases.insert(
            lease_id.clone(),
            SessionLease {
                lease_id,
                lease_epoch,
                issued_at_unix_ms,
                expires_at_unix_ms,
                revoked: false,
            },
        );
        Ok(())
    }

    /// Admits the server-side role capability context for this session.
    ///
    /// This is the server admission production caller for
    /// [`CapabilityContext::admit`] (issue #1943): the I7.21 role default is
    /// compiled into a server-enforced capability token bound to the exact
    /// role, scope, task/work item, route, `GovernanceProfile` revision,
    /// exact `State Fence`, lease epoch and expiry carried by `binding`, and
    /// narrowed by `WorkScope` policy and delegated authority. The admitted
    /// context is session-bound: exactly one is live per session, and session
    /// loss drops it alongside the session-bound leases.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] when the session
    /// is terminal, [`SessionLifecycleError::RoleCapabilityAlreadyAdmitted`]
    /// when a context is already admitted, or
    /// [`SessionLifecycleError::RoleLease`] when compilation fails closed.
    pub fn admit_role_capability(
        &mut self,
        context_id: impl Into<String>,
        role: AgentRole,
        binding: ScopeBinding,
        workscope: &WorkScopePolicy,
        delegated: &DelegatedAuthority,
    ) -> Result<(), SessionLifecycleError> {
        if self.state.is_terminal() {
            return Err(SessionLifecycleError::IllegalTransition {
                from: self.state,
                to: ApplicationSessionState::Active,
            });
        }
        if self.role_capability.is_some() {
            return Err(SessionLifecycleError::RoleCapabilityAlreadyAdmitted);
        }
        let context = CapabilityContext::admit(context_id, role, binding, workscope, delegated)?;
        self.role_capability = Some(context);
        Ok(())
    }

    /// Performs the server-side role transition for this session.
    ///
    /// This is the server transition production caller for
    /// [`CapabilityContext::transition`] (issue #1943): the preceding
    /// capability context is closed and revoked, a newly scoped context is
    /// created at `new_binding`'s advanced lease epoch, and the Independence
    /// Profile is updated, so stronger authority from the previous role is
    /// never silently retained. A Verifier moving to a mutating role still
    /// requires the explicit [`IndependenceDowngrade`] record.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::IllegalTransition`] when the session
    /// is terminal, [`SessionLifecycleError::RoleCapabilityNotAdmitted`]
    /// when no context was admitted, or
    /// [`SessionLifecycleError::RoleLease`] when the transition fails closed.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_role_capability(
        &mut self,
        new_context_id: impl Into<String>,
        new_role: AgentRole,
        new_binding: &ScopeBinding,
        workscope: &WorkScopePolicy,
        delegated: &DelegatedAuthority,
        downgrade: Option<IndependenceDowngrade>,
        now_unix_ms: u64,
    ) -> Result<RoleTransitionRecord, SessionLifecycleError> {
        if self.state.is_terminal() {
            return Err(SessionLifecycleError::IllegalTransition {
                from: self.state,
                to: ApplicationSessionState::Active,
            });
        }
        let Some(context) = self.role_capability.as_mut() else {
            return Err(SessionLifecycleError::RoleCapabilityNotAdmitted);
        };
        let record = context.transition(
            new_context_id,
            new_role,
            new_binding,
            workscope,
            delegated,
            downgrade,
            now_unix_ms,
        )?;
        Ok(record)
    }

    /// Records one replaceable transport binding as a continuity observation.
    ///
    /// This is the reconnect path: it appends a continuity observation and
    /// never changes the application session state, so a pipe/stdio/HTTP
    /// reconnect binds a replacement transport without transitioning the
    /// session to a terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::InvalidBindingId`] when `binding_id` is
    /// empty or carries control characters,
    /// [`SessionLifecycleError::IllegalTransition`] when the session is terminal,
    /// or [`SessionLifecycleError::RegistryFull`] when the bounded observation
    /// registry is full.
    pub fn record_transport_binding(
        &mut self,
        binding_id: impl Into<String>,
        transport: TransportKind,
        session_epoch: u64,
        observed_at_unix_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        if self.state.is_terminal() {
            return Err(SessionLifecycleError::IllegalTransition {
                from: self.state,
                to: ApplicationSessionState::Active,
            });
        }
        let binding_id = binding_id.into();
        if binding_id.trim().is_empty() || binding_id.chars().any(char::is_control) {
            return Err(SessionLifecycleError::InvalidBindingId);
        }
        if self.transport_bindings.len() >= MAX_TRANSPORT_BINDINGS {
            return Err(SessionLifecycleError::RegistryFull);
        }
        self.transport_bindings.push(TransportBindingObservation {
            binding_id,
            transport,
            session_epoch,
            observed_at_unix_ms,
        });
        Ok(())
    }

    /// Checkpoints one durable task/job so it survives session loss.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::InvalidBinding`] when `work_ref` is
    /// empty or carries control characters, or
    /// [`SessionLifecycleError::RegistryFull`] when the bounded checkpoint
    /// registry is full.
    pub fn checkpoint_durable_work(
        &mut self,
        work_ref: impl Into<String>,
        now_unix_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        let work_ref = work_ref.into();
        validate_session_id(&work_ref)?;
        self.record_durable_checkpoint(work_ref, now_unix_ms)
    }

    /// Sets the explicit policy/TTL for retained Route Continuation State.
    ///
    /// # Errors
    ///
    /// Returns [`SessionLifecycleError::InvalidContinuationTtl`] when `ttl_ms`
    /// is zero.
    pub fn set_continuation_ttl_policy(
        &mut self,
        ttl_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        if ttl_ms == 0 {
            return Err(SessionLifecycleError::InvalidContinuationTtl);
        }
        self.continuation_ttl_ms = Some(ttl_ms);
        Ok(())
    }

    /// Checks whether Route Continuation State retained at `retained_at_unix_ms`
    /// may still be retained at `now_unix_ms` under the explicit policy/TTL.
    ///
    /// Retention is permitted only when an explicit TTL policy is set and
    /// `now_unix_ms` is still inside the retention window. With no policy, no
    /// continuation state is retained.
    #[must_use]
    pub fn continuation_state_retained(&self, retained_at_unix_ms: u64, now_unix_ms: u64) -> bool {
        match self.continuation_ttl_ms {
            Some(ttl_ms) => {
                let deadline = retained_at_unix_ms.saturating_add(ttl_ms);
                now_unix_ms < deadline
            }
            None => false,
        }
    }

    /// Returns the exact session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the current application session state.
    #[must_use]
    pub const fn state(&self) -> ApplicationSessionState {
        self.state
    }

    /// Returns the currently recorded authority epoch.
    #[must_use]
    pub fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the retained transport binding continuity observations, in order.
    #[must_use]
    pub fn transport_bindings(&self) -> &[TransportBindingObservation] {
        &self.transport_bindings
    }

    /// Returns the session-bound leases keyed by lease identity.
    #[must_use]
    pub fn bound_leases(&self) -> &BTreeMap<String, SessionLease> {
        &self.bound_leases
    }

    /// Returns the admitted server-side role capability context, if any.
    ///
    /// Server authorization reads the active token through this context, so
    /// role authority is enforceable only while the session holds it.
    #[must_use]
    pub const fn role_capability(&self) -> Option<&CapabilityContext> {
        self.role_capability.as_ref()
    }

    /// Returns the durable work checkpoints, in order.
    #[must_use]
    pub fn durable_checkpoints(&self) -> &[DurableWorkCheckpoint] {
        &self.durable_checkpoints
    }

    /// Returns the explicit continuation state policy/TTL, if set.
    #[must_use]
    pub const fn continuation_ttl_ms(&self) -> Option<u64> {
        self.continuation_ttl_ms
    }

    fn transition_to(
        &mut self,
        next: ApplicationSessionState,
    ) -> Result<(), SessionLifecycleError> {
        self.state.transition_to(next)?;
        self.state = next;
        Ok(())
    }

    fn lose_session(
        &mut self,
        terminal_state: ApplicationSessionState,
        now_unix_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        self.state.transition_to(terminal_state)?;
        self.record_durable_checkpoint(self.session_id.clone(), now_unix_ms)?;
        self.state = terminal_state;
        for lease in self.bound_leases.values_mut() {
            lease.revoked = true;
        }
        self.role_capability = None;
        Ok(())
    }

    fn record_durable_checkpoint(
        &mut self,
        work_ref: String,
        now_unix_ms: u64,
    ) -> Result<(), SessionLifecycleError> {
        if self.durable_checkpoints.len() >= MAX_DURABLE_CHECKPOINTS {
            return Err(SessionLifecycleError::RegistryFull);
        }
        let checkpoint_id = format!(
            "{}-checkpoint-{}",
            self.session_id,
            self.durable_checkpoints.len()
        );
        self.durable_checkpoints.push(DurableWorkCheckpoint {
            checkpoint_id,
            work_ref,
            checkpointed_at_unix_ms: now_unix_ms,
        });
        Ok(())
    }
}

fn validate_session_id(value: &str) -> Result<(), SessionLifecycleError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SessionLifecycleError::InvalidBinding {
            field: "session_id",
        });
    }
    Ok(())
}
