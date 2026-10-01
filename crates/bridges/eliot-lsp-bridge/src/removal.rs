//! Honest removal and status for the LSP bridge (issue #1797, W7).
//!
//! Declared versus observed capability/health and the current
//! contract/artifact revisions are exposed as a projection value built from
//! the admitted generation line and caller-attested receipt evidence. An
//! absent observation stays an explicit unknown: only an observed completed
//! success proves responsiveness and only an observed exit code proves
//! degradation, so observation state is never copied into a support claim,
//! and there is no support field to promote.
//!
//! Removal fences new launches, drains owned operations by exact operation
//! identity, records the precise route/operation revocations through their
//! owners, and releases only bridge-owned artifacts (bridge-named SCIP
//! sidecars from the admitted configuration) before finishing. Shared
//! state, another generation's credentials, and the user's upstream
//! installation have no representation here and cannot pass through this
//! plan. The plan holds values only; exportable observations and unresolved
//! effect references travel on the returned receipt to their existing
//! privacy/retention owners. There is no bridge-local task database and no
//! new journal.
//!
//! Wiring: the crate root declares `mod removal;` and re-exports this
//! sequence. The launch path consults `blocks_new_calls` before launch,
//! feeds per-operation exit evidence from real receipts, and the
//! composition owner performs the revocations and the artifact release the
//! receipt enumerates.

use std::collections::BTreeMap;

use thiserror::Error;

use super::generation::{ActiveGeneration, InFlightLedger};
use super::{AnalyzerConfig, FailureDisposition, Freshness, ObservationReceipt};

/// Typed failures of the removal sequence.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RemovalError {
    /// A revocation or finish was attempted before new launches were fenced.
    #[error("removal step requires fenced new launches first")]
    NotFenced,
    /// Old in-flight work is still open; removal cannot finish yet.
    #[error("removal cannot finish with {count} open operations")]
    InFlightRemain {
        /// Open operation identities still being drained.
        count: usize,
    },
    /// A revocation reference or unresolved-effect reference was blank.
    #[error("removal reference must not be blank: {field}")]
    BlankReference {
        /// Which reference was blank.
        field: &'static str,
    },
    /// The configuration names no bridge-owned sidecar to declare.
    #[error("no bridge-owned artifact to declare: configuration names no SCIP sidecar")]
    NoOwnedSidecar,
}

/// Observed availability of the bridge, derived from receipt evidence only.
///
/// A receipt the bridge never produced cannot imply health: without an
/// observed success or exit code the state is unknown, never responsive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedHealth {
    /// An observed run completed with a success disposition on fresh output.
    Responsive,
    /// An observed run failed with an observed exit code.
    Degraded {
        /// Observed tool exit code.
        exit_code: i32,
    },
    /// No dispatch was observed, or the evidence speaks to something other
    /// than bridge availability (truncation, parse shape, admission).
    Unknown,
}

impl ObservedHealth {
    /// Derives availability from the last observed exit code, if any.
    #[must_use]
    pub fn from_last_exit(last_exit: Option<i32>) -> Self {
        match last_exit {
            None => Self::Unknown,
            Some(0) => Self::Responsive,
            Some(exit_code) => Self::Degraded { exit_code },
        }
    }

    /// Derives availability from one observation receipt.
    ///
    /// Only [`FailureDisposition::Success`] on [`Freshness::Current`]
    /// proves responsiveness and only [`FailureDisposition::ToolFailed`]
    /// with an observed exit code proves degradation; every other
    /// disposition (truncation, parse shape, unsupported operation) or a
    /// stale receipt yields unknown rather than a health claim the receipt
    /// does not support.
    #[must_use]
    pub fn from_receipt(receipt: &ObservationReceipt) -> Self {
        match &receipt.disposition {
            FailureDisposition::ToolFailed { exit_code } => match exit_code {
                Some(code) => Self::Degraded { exit_code: *code },
                None => Self::Unknown,
            },
            FailureDisposition::Success => match &receipt.freshness {
                Freshness::Current => Self::Responsive,
                Freshness::Stale { .. } => Self::Unknown,
            },
            FailureDisposition::OutputTruncated
            | FailureDisposition::ParseFailed { .. }
            | FailureDisposition::UnsupportedOperation => Self::Unknown,
        }
    }
}

/// One declared operation with its last caller-observed exit, if any.
///
/// The declaration comes from the admitted generation; the exit comes from
/// a real receipt handed in by the caller. An operation with no observed
/// receipt keeps an explicit unknown instead of inheriting bridge-level
/// health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationStatusRow {
    operation: String,
    last_exit: Option<i32>,
}

impl OperationStatusRow {
    /// Returns the declared operation token.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the last caller-observed exit for this operation, if any.
    #[must_use]
    pub fn last_exit(&self) -> Option<i32> {
        self.last_exit
    }

    /// Derives this operation's observed health from its own evidence only.
    #[must_use]
    pub fn health(&self) -> ObservedHealth {
        ObservedHealth::from_last_exit(self.last_exit)
    }
}

/// Declared-versus-observed status projection for one admitted line.
///
/// The declared block (route, upstream identity lines, admitted
/// operations) is the contract side; the observed block (overall and
/// per-operation health) is evidence side. The two are rendered side by
/// side so a reader can see drift without the bridge ever claiming support
/// it did not observe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeStatusProjection {
    bridge_route: String,
    declared_upstream_version_line: String,
    declared_operations: Vec<String>,
    retained_upstream_version_line: Option<String>,
    overall: ObservedHealth,
    operations: Vec<OperationStatusRow>,
}

impl BridgeStatusProjection {
    /// Projects status from the admitted line and caller-attested evidence.
    ///
    /// `overall` is the caller-derived bridge health (usually
    /// [`ObservedHealth::from_receipt`] over the most recent receipt, or
    /// [`ObservedHealth::Unknown`] when nothing was observed);
    /// `per_operation_exits` carries the last observed exit per operation
    /// token from real receipts. Operations with no entry stay unknown.
    #[must_use]
    pub fn project(
        current: &ActiveGeneration,
        retained: Option<&ActiveGeneration>,
        overall: ObservedHealth,
        per_operation_exits: &BTreeMap<String, i32>,
    ) -> Self {
        let operations = current
            .admitted_operations()
            .iter()
            .map(|operation| OperationStatusRow {
                operation: operation.clone(),
                last_exit: per_operation_exits.get(operation).copied(),
            })
            .collect();
        Self {
            bridge_route: current.route_executable().to_owned(),
            declared_upstream_version_line: current.upstream_version_line().to_owned(),
            declared_operations: current.admitted_operations().to_owned(),
            retained_upstream_version_line: retained
                .map(|generation| generation.upstream_version_line().to_owned()),
            overall,
            operations,
        }
    }

    /// Projects status directly from the last observation receipt, if any.
    ///
    /// Convenience over [`BridgeStatusProjection::project`] for the overall
    /// health only; per-operation exits still arrive through the caller map
    /// so no receipt is double-counted as evidence it does not carry.
    #[must_use]
    pub fn project_from_receipt(
        current: &ActiveGeneration,
        retained: Option<&ActiveGeneration>,
        receipt: Option<&ObservationReceipt>,
        per_operation_exits: &BTreeMap<String, i32>,
    ) -> Self {
        let overall = receipt.map_or(ObservedHealth::Unknown, ObservedHealth::from_receipt);
        Self::project(current, retained, overall, per_operation_exits)
    }

    /// Returns the declared bridge route.
    #[must_use]
    pub fn bridge_route(&self) -> &str {
        &self.bridge_route
    }

    /// Returns the declared live upstream identity line.
    #[must_use]
    pub fn declared_upstream_version_line(&self) -> &str {
        &self.declared_upstream_version_line
    }

    /// Returns the declared admitted operations.
    #[must_use]
    pub fn declared_operations(&self) -> &[String] {
        &self.declared_operations
    }

    /// Returns the retained generation's upstream identity line, when one
    /// is kept.
    #[must_use]
    pub fn retained_upstream_version_line(&self) -> Option<&str> {
        self.retained_upstream_version_line.as_deref()
    }

    /// Returns the overall observed health (unknown when unobserved).
    #[must_use]
    pub fn overall(&self) -> ObservedHealth {
        self.overall
    }

    /// Returns the per-operation declared/observed rows.
    #[must_use]
    pub fn operations(&self) -> &[OperationStatusRow] {
        &self.operations
    }
}

/// Which owner reference a revocation record attests.
///
/// This bridge holds no sessions and no credentials: revocation covers the
/// dispatch route and the reconciled operation identities. Session and
/// credential revocation stay with the executor admission owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationKind {
    /// The analyzer route served by the bridge.
    Route,
    /// One reconciled operation identity.
    Operation,
}

/// One owner-performed revocation, recorded by reference.
///
/// The bridge performs no revocation itself: the composition owner revokes
/// the precise route/operation references through their owners and hands
/// the references back here so the removal receipt enumerates exactly what
/// was revoked before owned artifacts were released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationRecord {
    kind: RevocationKind,
    reference: String,
}

impl RevocationRecord {
    /// Records a route revocation by reference.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::BlankReference`] on a blank reference.
    pub fn route(reference: impl Into<String>) -> Result<Self, RemovalError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(RemovalError::BlankReference { field: "route" });
        }
        Ok(Self {
            kind: RevocationKind::Route,
            reference,
        })
    }

    /// Records an operation-identity revocation by reference.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::BlankReference`] on a blank reference.
    pub fn operation(reference: impl Into<String>) -> Result<Self, RemovalError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(RemovalError::BlankReference { field: "operation" });
        }
        Ok(Self {
            kind: RevocationKind::Operation,
            reference,
        })
    }

    /// Returns the revoked reference kind.
    #[must_use]
    pub fn kind(&self) -> RevocationKind {
        self.kind
    }

    /// Returns the revoked owner reference.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// One bridge-owned artifact eligible for release on removal.
///
/// The only on-disk artifact this bridge names is the SCIP sidecar output
/// path carried by the admitted analyzer configuration, so the only
/// constructor takes the configuration that names one. Shared state,
/// another generation's credentials, and the user's upstream installation
/// cannot be expressed in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedSidecar {
    path: String,
}

impl OwnedSidecar {
    /// Declares the sidecar named by an admitted analyzer configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::NoOwnedSidecar`] when the configuration
    /// names no sidecar path.
    pub fn from_config(config: &AnalyzerConfig) -> Result<Self, RemovalError> {
        let Some(path) = config.scip_output_path.clone() else {
            return Err(RemovalError::NoOwnedSidecar);
        };
        Ok(Self { path })
    }

    /// Returns the sidecar path the owner must release.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Removal phase of one plan. Ordering is enforced by the plan methods:
///
/// ```text
/// open -> fence_new_launches -> (drain, revoke) -> finish
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RemovalPhase {
    /// New launches still flow; evidence may accumulate.
    #[default]
    Open,
    /// New launches are fenced; draining, revocation, and release follow.
    Fenced,
}

/// One bridge removal plan, held by the composition owner.
///
/// Removal fences new launches first, then drains owned operations by exact
/// identity, records owner-performed revocations, and only then releases
/// the declared bridge-owned artifacts. Finishing requires the fence and a
/// drained ledger; revocations, owned artifacts, and unresolved effect
/// references travel on the returned receipt whether or not any exist
/// (empty means none, never an implicit claim).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemovalPlan {
    phase: RemovalPhase,
    revocations: Vec<RevocationRecord>,
    owned: Vec<OwnedSidecar>,
    unresolved: Vec<String>,
}

impl RemovalPlan {
    /// Opens a removal plan with new launches still flowing.
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// Returns the current removal phase.
    #[must_use]
    pub fn phase(&self) -> RemovalPhase {
        self.phase
    }

    /// Reports whether the launch path must refuse new launches.
    ///
    /// The stitch caller consults this before launch; the plan itself
    /// launches nothing.
    #[must_use]
    pub fn blocks_new_calls(&self) -> bool {
        self.phase != RemovalPhase::Open
    }

    /// Fences new launches. Launch consults
    /// [`RemovalPlan::blocks_new_calls`] from this point on.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::NotFenced`] when the plan is already fenced;
    /// fencing is enforced by refusal rather than by a silent second fence.
    pub fn fence_new_calls(&mut self) -> Result<(), RemovalError> {
        if self.phase != RemovalPhase::Open {
            return Err(RemovalError::NotFenced);
        }
        self.phase = RemovalPhase::Fenced;
        Ok(())
    }

    /// Records one owner-performed revocation. Requires the fence.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::NotFenced`] when new launches still flow.
    pub fn record_revocation(&mut self, record: RevocationRecord) -> Result<(), RemovalError> {
        if self.phase == RemovalPhase::Open {
            return Err(RemovalError::NotFenced);
        }
        self.revocations.push(record);
        Ok(())
    }

    /// Declares one bridge-owned artifact for release at finish.
    pub fn declare_owned(&mut self, owned: OwnedSidecar) {
        self.owned.push(owned);
    }

    /// Retains one unresolved effect reference for reconciliation by its
    /// owner (for example a launch invocation identity whose post-dispatch
    /// outcome stayed unknown).
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::BlankReference`] on a blank reference.
    pub fn note_unresolved(&mut self, reference: impl Into<String>) -> Result<(), RemovalError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(RemovalError::BlankReference {
                field: "unresolved",
            });
        }
        self.unresolved.push(reference);
        Ok(())
    }

    /// Finishes removal after the fence and the drain.
    ///
    /// Requires fenced new launches and a drained in-flight ledger. The
    /// returned receipt enumerates the revocations, the owned artifact
    /// paths the owner must now release, and the unresolved references;
    /// the plan deletes nothing itself.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalError::NotFenced`] when new launches still flow, or
    /// [`RemovalError::InFlightRemain`] while identities stay open.
    pub fn finish(
        self,
        route_executable: impl Into<String>,
        ledger: &InFlightLedger,
    ) -> Result<RemovalReceipt, RemovalError> {
        if self.phase == RemovalPhase::Open {
            return Err(RemovalError::NotFenced);
        }
        if !ledger.is_drained() {
            return Err(RemovalError::InFlightRemain {
                count: ledger.in_flight_count(),
            });
        }
        let route_executable = route_executable.into();
        if route_executable.trim().is_empty() {
            return Err(RemovalError::BlankReference {
                field: "route_executable",
            });
        }
        Ok(RemovalReceipt {
            bridge_route: route_executable,
            revocations: self.revocations,
            owned_release_order: self.owned.iter().map(|owned| owned.path.clone()).collect(),
            unresolved: self.unresolved,
        })
    }
}

/// Removal receipt: what was fenced, drained, revoked, and released.
///
/// Held by the composition owner under its existing retention; the bridge
/// keeps no copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovalReceipt {
    bridge_route: String,
    revocations: Vec<RevocationRecord>,
    owned_release_order: Vec<String>,
    unresolved: Vec<String>,
}

impl RemovalReceipt {
    /// Returns the removed bridge route.
    #[must_use]
    pub fn bridge_route(&self) -> &str {
        &self.bridge_route
    }

    /// Returns the recorded owner revocations, in record order.
    #[must_use]
    pub fn revocations(&self) -> &[RevocationRecord] {
        &self.revocations
    }

    /// Returns the bridge-owned artifact paths the owner must release, in
    /// release order.
    #[must_use]
    pub fn owned_release_order(&self) -> &[String] {
        &self.owned_release_order
    }

    /// Returns the unresolved effect references retained for
    /// reconciliation.
    #[must_use]
    pub fn unresolved(&self) -> &[String] {
        &self.unresolved
    }
}
