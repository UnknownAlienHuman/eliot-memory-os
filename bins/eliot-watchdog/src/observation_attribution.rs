//! Observation identity and attribution limits (#1755 W4).
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose).
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes).
//!
//! A file change is event evidence, not original file contents, tool intent,
//! or principal identity: [`FileChangeEvidence`] carries the path, its scope
//! membership, and its origin — and nothing else. There is no content,
//! intent, or principal field to fill, so none can leak into an attribution.
//!
//! Scope membership is resolved against registered identities and their
//! historical mapping ([`resolve_scope_membership`]): path reuse, rename, or
//! unresolved membership never authorizes attributing the event to a task.
//! Only [`ScopeMembership::CurrentMember`] plus an authenticated origin does
//! ([`FileChangeEvidence::attribute_to_task`]).
//!
//! Origin stays [`EventOrigin::Unknown`] unless an authenticated correlation
//! supplies the actual process and attempt
//! ([`EventOrigin::authenticated_correlation`], fed by a sealed
//! OS-observed [`ProcessIdentity`](eliot_platform_windows::ProcessIdentity)).
//! There is no constructor from a bare PID, name, or self-report.
//!
//! The resolution takes one explicit path and the registered sets: this owner
//! performs no volume scan, reads no arbitrary source contents, and never
//! crosses into unregistered or private roots to fill an observation gap —
//! there is no scan or read API here to misuse.
//!
//! STITCH: the production consumer is the W3 registered-scope filesystem
//! replay increment of this same issue, which feeds one journal event path
//! plus its volume/journal binding through [`resolve_scope_membership`],
//! upgrades the origin only through [`EventOrigin::authenticated_correlation`],
//! and attributes only through [`FileChangeEvidence::attribute_to_task`].
//! No filesystem event flows through this owner yet, so no caller exists to
//! wire without fabricating events.
//!
//! Forbidden by construction: task attribution from path reuse, rename, or
//! unresolved membership; origin from anything but an authenticated
//! correlation; and gap-filling reads outside registered scopes.

use std::path::{Path, PathBuf};

use eliot_platform_windows::ProcessIdentity;
use thiserror::Error;

/// Typed refusal for an unusable scope registration or attribution.
///
/// Every refusal fails closed toward [`EventOrigin::Unknown`] and
/// [`ScopeMembership::Unresolved`]: a refused attribution is an unobserved
/// origin, never a guessed one.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AttributionError {
    /// The scope root is not absolute.
    #[error("registered scope root must be absolute")]
    RelativeScopeRoot,
    /// The scope generation is empty.
    #[error("registered scope generation must be non-empty")]
    EmptyScopeGeneration,
    /// No authenticated correlation supplies the actual process.
    #[error("no authenticated correlation supplies the actual process")]
    MissingCorrelation,
    /// The attempt identity is empty.
    #[error("attempt identity must be non-empty")]
    EmptyAttemptIdentity,
    /// Scope membership or origin does not authorize task attribution.
    #[error("event is not attributable to a task: scope membership or origin does not authorize it")]
    RefusedTaskAttribution,
}

/// One registered filesystem scope: an exact root plus its scope generation.
///
/// The root is an absolute path and the generation is non-empty; both are
/// validated at construction. Root liveness binding (volume/journal
/// identity) is established by the W3 replay owner against this registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredScope {
    root: PathBuf,
    scope_generation: String,
}

impl RegisteredScope {
    /// Registers one scope root under its scope generation.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionError`] when the root is not absolute or the
    /// generation is empty.
    pub fn new(root: PathBuf, scope_generation: &str) -> Result<Self, AttributionError> {
        if !root.is_absolute() {
            return Err(AttributionError::RelativeScopeRoot);
        }
        if scope_generation.is_empty() {
            return Err(AttributionError::EmptyScopeGeneration);
        }
        Ok(Self {
            root,
            scope_generation: scope_generation.to_owned(),
        })
    }

    /// Returns the registered scope root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the scope generation this registration belongs to.
    #[must_use]
    pub fn scope_generation(&self) -> &str {
        &self.scope_generation
    }
}

/// Scope membership of one observed path against registered identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeMembership {
    /// The path sits under a currently registered scope root.
    CurrentMember,
    /// The path sits only under a historical (superseded) scope root:
    /// path reuse across generations, never current membership.
    HistoricalOnly,
    /// Membership cannot be established (non-absolute path or rename
    /// without lineage).
    Unresolved,
    /// The path sits under no registered root, current or historical.
    OutsideRegistered,
}

impl ScopeMembership {
    /// Returns the stable wire name of this membership.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentMember => "current_member",
            Self::HistoricalOnly => "historical_only",
            Self::Unresolved => "unresolved",
            Self::OutsideRegistered => "outside_registered",
        }
    }
}

/// Resolves one explicit path against the registered scopes and their
/// historical mapping.
///
/// The match is component-wise prefix only, and current registration wins:
/// a path under a current root is [`ScopeMembership::CurrentMember`], under
/// a historical root only is [`ScopeMembership::HistoricalOnly`], under
/// neither is [`ScopeMembership::OutsideRegistered`], and a non-absolute
/// path is [`ScopeMembership::Unresolved`]. Prefix membership is necessary
/// but not sufficient for task attribution — the origin must additionally be
/// authenticated (see [`FileChangeEvidence::attribute_to_task`]) — so rename
/// within a root without lineage still cannot authorize an attribution on
/// its own.
#[must_use]
pub fn resolve_scope_membership(
    path: &Path,
    current: &[RegisteredScope],
    historical: &[RegisteredScope],
) -> ScopeMembership {
    if !path.is_absolute() {
        return ScopeMembership::Unresolved;
    }
    if current.iter().any(|scope| path.starts_with(scope.root())) {
        return ScopeMembership::CurrentMember;
    }
    if historical.iter().any(|scope| path.starts_with(scope.root())) {
        return ScopeMembership::HistoricalOnly;
    }
    ScopeMembership::OutsideRegistered
}

/// Origin of one observed event: unknown unless an authenticated correlation
/// supplies the actual process and attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventOrigin {
    /// The origin is unknown: no authenticated correlation was supplied.
    Unknown,
    /// An authenticated correlation bound the exact OS-observed process to
    /// the exact attempt. The process key binds the full
    /// PID/creation/image triple, never a bare PID.
    AuthenticatedPeer {
        /// Sealed process key of the correlated peer.
        process_key: String,
        /// Attempt the correlation was established for.
        attempt: String,
    },
}

impl EventOrigin {
    /// Returns the unknown origin: no authenticated correlation.
    #[must_use]
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    /// Correlates an origin from the sealed OS-observed process identity and
    /// the exact attempt it was established for.
    ///
    /// The process value must be a usable observed identity (nonzero PID and
    /// creation time, non-empty image path): a bare PID, a name, or a
    /// self-report cannot construct one. The attempt identity must be
    /// non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionError`] when the process identity is unusable or
    /// the attempt identity is empty.
    pub fn authenticated_correlation(
        process: &ProcessIdentity,
        attempt: &str,
    ) -> Result<Self, AttributionError> {
        if process.process_id == 0
            || process.start_time_100ns == 0
            || process.image_path.is_empty()
        {
            return Err(AttributionError::MissingCorrelation);
        }
        if attempt.is_empty() {
            return Err(AttributionError::EmptyAttemptIdentity);
        }
        Ok(Self::AuthenticatedPeer {
            process_key: process.stable_key(),
            attempt: attempt.to_owned(),
        })
    }

    /// Whether an authenticated correlation supplies the actual
    /// process and attempt.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self, Self::AuthenticatedPeer { .. })
    }
}

/// One file change as event evidence: path, scope membership, and origin.
///
/// Carries no file contents, no tool intent, and no principal identity —
/// there is no field for any of them. A fresh observation always starts
/// with [`EventOrigin::Unknown`]; only
/// [`FileChangeEvidence::correlate_origin`] can upgrade it, and only through
/// an authenticated correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileChangeEvidence {
    path: PathBuf,
    membership: ScopeMembership,
    origin: EventOrigin,
}

impl FileChangeEvidence {
    /// Records one observed file change as event evidence with unknown
    /// origin.
    #[must_use]
    pub fn observed(path: PathBuf, membership: ScopeMembership) -> Self {
        Self {
            path,
            membership,
            origin: EventOrigin::Unknown,
        }
    }

    /// Upgrades the origin through an authenticated correlation supplying
    /// the actual process and attempt.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionError`] when the correlation is not
    /// authenticated; the stored origin is left unchanged.
    pub fn correlate_origin(
        &mut self,
        process: &ProcessIdentity,
        attempt: &str,
    ) -> Result<(), AttributionError> {
        self.origin = EventOrigin::authenticated_correlation(process, attempt)?;
        Ok(())
    }

    /// Returns the observed path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the resolved scope membership.
    #[must_use]
    pub const fn membership(&self) -> ScopeMembership {
        self.membership
    }

    /// Returns the event origin, unknown unless correlated.
    #[must_use]
    pub const fn origin(&self) -> &EventOrigin {
        &self.origin
    }

    /// Authorizes attributing this event to a task.
    ///
    /// Only a current scope member with an authenticated origin qualifies:
    /// path reuse, rename, or unresolved membership
    /// ([`ScopeMembership::HistoricalOnly`], [`ScopeMembership::Unresolved`],
    /// [`ScopeMembership::OutsideRegistered`]) and unknown origin
    /// ([`EventOrigin::Unknown`]) refuse, never guess.
    ///
    /// # Errors
    ///
    /// Returns [`AttributionError::RefusedTaskAttribution`] unless the event
    /// is a current member with an authenticated origin.
    pub fn attribute_to_task(&self) -> Result<TaskAttribution, AttributionError> {
        match (&self.membership, &self.origin) {
            (
                ScopeMembership::CurrentMember,
                EventOrigin::AuthenticatedPeer {
                    process_key,
                    attempt,
                },
            ) => Ok(TaskAttribution {
                process_key: process_key.clone(),
                attempt: attempt.clone(),
            }),
            _ => Err(AttributionError::RefusedTaskAttribution),
        }
    }
}

/// An authorized task attribution: the correlated process key and attempt.
///
/// Produced only by [`FileChangeEvidence::attribute_to_task`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskAttribution {
    process_key: String,
    attempt: String,
}

impl TaskAttribution {
    /// Returns the correlated process key.
    #[must_use]
    pub fn process_key(&self) -> &str {
        &self.process_key
    }

    /// Returns the correlated attempt identity.
    #[must_use]
    pub fn attempt(&self) -> &str {
        &self.attempt
    }
}
