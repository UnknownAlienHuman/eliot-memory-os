//! Typed process-origin collision evidence and the recovery directive it
//! produces (issue #1775 checklist W3/A1/W7).
//!
//! # Why this cell exists
//!
//! A foreign occupant of a planned installation endpoint used to be reported
//! as a free-form reason string plus a static event name. I3.3 requires the
//! opposite: *"The installer chooses and records an installation-owned
//! loopback endpoint/data root, verifies the owning PID/artifact/`HostState`
//! lineage before every start/reconnect, and returns a Recovery Directive on
//! collision. Legacy data enters only through an explicit read-only
//! inspection/import/migration path."* I3.4 requires the directive to carry
//! the classified origin, the precise allowed/blocked operation class, and the
//! missing ownership evidence. I7.20 requires the *next admissible action* to
//! be named rather than prose.
//!
//! This module therefore owns structured evidence and one typed directive. It
//! owns **no** issuer, key, challenge database, connection, `Store` client or
//! process-control service: it cannot kill, adopt, log in to, reuse or migrate
//! anything, and it holds no durable state.
//!
//! # A1: a read-only status receipt cannot become a `Kill`
//!
//! The destructive-control vocabulary lives in [`AdmittedOriginControl`], which
//! has **no read-only variant at all**. The only way to reach it from the
//! broader [`OriginOperationClass`] is [`TryFrom`], and that conversion returns
//! [`OriginCollisionError::NotAControlOperation`] naming the refused read-only
//! class. There is deliberately no `From`/`Into`/`as_*` coercion from a
//! read-only class to a control class anywhere in this module, so naming a
//! control class on a read-only request is unrepresentable rather than merely
//! discouraged. Symmetrically, the directive's permitted
//! [`OriginNextAction`] set has no destructive variant, so a collision
//! directive can never be read as a control permission.
//!
//! # What this module does not do
//!
//! It does not re-derive the expected answer from the list it is measuring,
//! and it does not treat "a handle is well formed" or "a digest is present" as
//! evidence binding. [`OriginCollisionDirective::validate`] refuses a
//! directive whose collision contradicts the installation's own retained
//! lineage, and refuses a directive built around a read-only blocked
//! operation, because in that case there is nothing to block.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use eliot_contracts::StateFence;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::RecoveryDirective;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact I7.20 reason code raised for an unproven process-owner relation.
///
/// Reused from the canonical registry in
/// `crates/foundation/eliot-protocol/src/reason_codes.rs`
/// (`PROCESS_OWNERSHIP_UNPROVEN`); this module does not mint a new code.
pub const PROCESS_OWNERSHIP_UNPROVEN: &str = "PROCESS_OWNERSHIP_UNPROVEN";

/// Bounded cap on collision evidence references carried by one directive.
///
/// Issue #1775 implementation step 7 ("Bound probes, challenge lifetime/
/// count, descendants, IO and cleanup"): a directive is an operator-facing
/// projection, not a log dump.
pub const MAX_COLLISION_EVIDENCE_REFS: usize = 16;

/// Errors raised while classifying a collision or building its directive.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OriginCollisionError {
    /// A read-only operation class was offered where a destructive-control
    /// class is required. The refused class is named by its own variant label.
    ///
    /// This is the A1 refusal: no observe-only request is ever given a
    /// control class on its behalf.
    #[error("origin collision: {0} is read-only and has no destructive-control class")]
    NotAControlOperation(&'static str),
    /// An evidence or directive field is malformed.
    #[error("origin collision: field {field} is invalid: {reason}")]
    InvalidField {
        /// Malformed field name.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// The directive would assert something the evidence contradicts.
    #[error("origin collision: directive is contradictory: {0}")]
    ContradictoryEvidence(&'static str),
}

/// Classified origin of one observed process, using the closed I3.4
/// vocabulary (`INSIDE_MANAGED_TREE | SHARED_SUBSTRATE | ELSEWHERE | UNKNOWN`).
///
/// A classification is an observation, never ownership: none of these values
/// authorizes a control effect, and `SharedSubstrate` in particular must never
/// become exclusive ownership automatically.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessOriginClassification {
    /// Observed inside this installation's managed process tree.
    InsideManagedTree,
    /// Observed on a shared runtime substrate, ownership not exclusive.
    SharedSubstrate,
    /// Observed outside the managed tree and outside any shared substrate.
    Elsewhere,
    /// The origin could not be classified. Inability to read is not absence.
    Unknown,
}

impl ProcessOriginClassification {
    /// Returns the frozen I3.4 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InsideManagedTree => "INSIDE_MANAGED_TREE",
            Self::SharedSubstrate => "SHARED_SUBSTRATE",
            Self::Elsewhere => "ELSEWHERE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for ProcessOriginClassification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Operation class requested against one observed process origin.
///
/// This is the *requested* class, which may legitimately be read-only.
/// It carries no authority: answering with a value here authorizes nothing.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OriginOperationClass {
    /// Read-only status read. Observe only, never a control class.
    ReadStatus,
    /// General observation probe. Observe only, never a control class.
    ProbeObserve,
    /// Stop the observed process. Requires a current control proof.
    Stop,
    /// Mutate the observed process. Requires a current control proof.
    Mutate,
    /// Adopt the observed process. Requires a current control proof.
    Adopt,
    /// Attach a credential to the observed process. Requires a current proof.
    AttachCredential,
}

impl OriginOperationClass {
    /// Returns whether the class is a destructive-control class that needs a
    /// current installation/identity/epoch-bound proof at the effect boundary.
    ///
    /// An operation-class fact consumed by the governed authority, not a
    /// decision: answering `true` authorizes nothing.
    #[must_use]
    pub const fn is_control_class(self) -> bool {
        matches!(
            self,
            Self::Stop | Self::Mutate | Self::Adopt | Self::AttachCredential
        )
    }

    /// Returns whether the class is observe-only and therefore disjoint from
    /// every destructive-control class.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !self.is_control_class()
    }

    /// Returns the frozen operation-class wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadStatus => "ReadStatus",
            Self::ProbeObserve => "ProbeObserve",
            Self::Stop => "Stop",
            Self::Mutate => "Mutate",
            Self::Adopt => "Adopt",
            Self::AttachCredential => "AttachCredential",
        }
    }
}

impl std::fmt::Display for OriginOperationClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Admitted destructive-control class for one process origin.
///
/// The type is control-only by construction: it has **no** read-only variant,
/// so a `ProcessStatusReceipt`, a probe result or any other observation has
/// nowhere to land. The sole construction path from the broader
/// [`OriginOperationClass`] is the fallible [`TryFrom`] below, which names the
/// refused read-only class instead of silently substituting a destructive one.
///
/// This type is a *label*, not a proof. It grants nothing: the existing
/// Kernel-owned `OriginControlGrant` remains the exclusive authority for a real
/// effect, and this module neither issues nor mints one.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmittedOriginControl {
    /// Stop the bound process.
    Stop,
    /// Mutate the bound process.
    Mutate,
    /// Adopt the bound process.
    Adopt,
    /// Attach a credential to the bound process.
    AttachCredential,
}

impl AdmittedOriginControl {
    /// Returns the frozen control-class wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "Stop",
            Self::Mutate => "Mutate",
            Self::Adopt => "Adopt",
            Self::AttachCredential => "AttachCredential",
        }
    }

    /// Returns the requested operation class this control class stands for.
    #[must_use]
    pub const fn operation_class(self) -> OriginOperationClass {
        match self {
            Self::Stop => OriginOperationClass::Stop,
            Self::Mutate => OriginOperationClass::Mutate,
            Self::Adopt => OriginOperationClass::Adopt,
            Self::AttachCredential => OriginOperationClass::AttachCredential,
        }
    }
}

impl std::fmt::Display for AdmittedOriginControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Explicitly fallible widening from a requested operation class to an
/// admitted destructive-control class.
///
/// I3.4 states that *"the same ambiguous origin may permit read-only status,
/// choose an alternate launch port and still forbid shutdown/mutation"*, so
/// the read-only classes must stay disjoint rather than be rounded up to the
/// nearest destructive class. `ReadStatus` and `ProbeObserve` are therefore
/// refused with [`OriginCollisionError::NotAControlOperation`], and the error
/// names the refused class so a caller can report the real disposition.
///
/// There is intentionally no infallible `From`/`Into`/`as_control` in this
/// module: an observe-only request has no path to a `Stop`, `Mutate`, `Adopt`
/// or `AttachCredential` label.
impl TryFrom<OriginOperationClass> for AdmittedOriginControl {
    type Error = OriginCollisionError;

    fn try_from(operation: OriginOperationClass) -> Result<Self, Self::Error> {
        match operation {
            OriginOperationClass::Stop => Ok(Self::Stop),
            OriginOperationClass::Mutate => Ok(Self::Mutate),
            OriginOperationClass::Adopt => Ok(Self::Adopt),
            OriginOperationClass::AttachCredential => Ok(Self::AttachCredential),
            OriginOperationClass::ReadStatus => {
                Err(OriginCollisionError::NotAControlOperation("ReadStatus"))
            }
            OriginOperationClass::ProbeObserve => {
                Err(OriginCollisionError::NotAControlOperation("ProbeObserve"))
            }
        }
    }
}

/// One exact ownership fact that is absent and therefore blocks a control
/// effect against a collided endpoint.
///
/// Naming the *specific* missing fact is what makes the directive actionable
/// and is what distinguishes it from a free-form reason string.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissingOwnershipEvidence {
    /// The occupant's installation/lineage relation is unproven.
    InstallationLineage,
    /// The occupant's process start identity was not observed.
    ProcessStartIdentity,
    /// The occupant's image/artifact identity was not bound.
    ImageArtifact,
    /// The current authority epoch and state fence were not bound.
    AuthorityEpochAndStateFence,
    /// No current, operation-bound control challenge exists.
    OperationChallenge,
    /// The identity of the process owning the connection was not retained.
    ConnectionOwner,
}

impl MissingOwnershipEvidence {
    /// Returns the frozen wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallationLineage => "INSTALLATION_LINEAGE",
            Self::ProcessStartIdentity => "PROCESS_START_IDENTITY",
            Self::ImageArtifact => "IMAGE_ARTIFACT",
            Self::AuthorityEpochAndStateFence => "AUTHORITY_EPOCH_AND_STATE_FENCE",
            Self::OperationChallenge => "OPERATION_CHALLENGE",
            Self::ConnectionOwner => "CONNECTION_OWNER",
        }
    }
}

impl std::fmt::Display for MissingOwnershipEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Next action a collision directive may name.
///
/// The vocabulary is deliberately **control-free**: I3.3 permits "inspection/
/// import or separately admitted alternate-endpoint options; no kill, login,
/// adoption, reuse or automatic data migration". Because no destructive
/// variant exists, a directive structurally cannot be mistaken for permission
/// to terminate, adopt, authenticate against or migrate from the occupant.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OriginNextAction {
    /// Observe the foreign occupant further, read-only and bounded.
    InspectForeignOccupant,
    /// Explicitly import legacy data through the read-only import path.
    ImportLegacyDataReadOnly,
    /// Select a separately admitted alternate installation-owned endpoint.
    SelectAlternateEndpoint,
}

impl OriginNextAction {
    /// Returns the frozen wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InspectForeignOccupant => "INSPECT_FOREIGN_OCCUPANT",
            Self::ImportLegacyDataReadOnly => "IMPORT_LEGACY_DATA_READ_ONLY",
            Self::SelectAlternateEndpoint => "SELECT_ALTERNATE_ENDPOINT",
        }
    }

    /// Returns whether the action is a read-only observation. Every variant in
    /// this vocabulary is read-only or a configuration choice; none mutates
    /// or controls the occupant.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        true
    }

    /// Returns every member of the control-free next-action vocabulary.
    ///
    /// Exhaustive on purpose: adding a destructive variant later becomes a
    /// compile error at every use of this list rather than a silent capability
    /// expansion of the directive.
    #[must_use]
    pub const fn read_only_actions() -> [Self; 3] {
        [
            Self::InspectForeignOccupant,
            Self::ImportLegacyDataReadOnly,
            Self::SelectAlternateEndpoint,
        ]
    }
}

impl std::fmt::Display for OriginNextAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Structured evidence for one occupied planned installation endpoint.
///
/// The occupant is an observation. `observed_owner_process_id` is `None` when
/// the owner could not be read, which I3.3 states is **not** the same as "no
/// occupant" — an unreadable owner therefore still blocks a launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreEndpointCollision {
    /// Canonical text form of the planned loopback host.
    pub planned_endpoint_host: String,
    /// Planned loopback port, nonzero.
    pub planned_endpoint_port: u16,
    /// Installation identity that planned and owns this endpoint.
    pub installation: PlatformHandle,
    /// Admitted generation that planned this endpoint.
    pub generation: PlatformHandle,
    /// State fence under which the endpoint was planned and observed.
    pub state_fence: StateFence,
    /// Classified origin of the observed occupant.
    pub origin: ProcessOriginClassification,
    /// Owner process ID observed at the endpoint, or `None` when the owner
    /// could not be read. Never an ownership proof.
    pub observed_owner_process_id: Option<u32>,
    /// Process ID of the child this installation retains on that endpoint, if
    /// one is currently retained.
    pub retained_owned_process_id: Option<u32>,
    /// Unix milliseconds at which the observation was taken.
    pub observed_at_unix_ms: u64,
    /// Bounded, role-filtered evidence references (no raw keys, bearer tokens
    /// or sensitive argv/config).
    pub evidence_refs: Vec<String>,
}

impl StoreEndpointCollision {
    /// Returns the parsed planned endpoint, or `None` when the recorded host is
    /// not a parseable address literal.
    #[must_use]
    pub fn planned_endpoint(&self) -> Option<SocketAddr> {
        format!(
            "{}:{}",
            self.planned_endpoint_host.trim(),
            self.planned_endpoint_port
        )
        .parse::<SocketAddr>()
        .ok()
    }

    /// Returns whether the observed occupant is the process this installation
    /// already retains on the planned endpoint.
    ///
    /// A collision is by definition a *foreign* occupant, so this must be
    /// `false` for a directive to be legal. Two `None` values are not a match:
    /// an unreadable owner and an absent retained child are different facts.
    #[must_use]
    pub const fn occupant_is_retained_owned(&self) -> bool {
        match (self.observed_owner_process_id, self.retained_owned_process_id) {
            (Some(observed), Some(retained)) => observed == retained,
            _ => false,
        }
    }

    fn validate(&self) -> Result<(), OriginCollisionError> {
        if self.planned_endpoint_port == 0 {
            return Err(OriginCollisionError::InvalidField {
                field: "planned_endpoint_port",
                reason: "must be nonzero",
            });
        }
        let endpoint = self.planned_endpoint().ok_or(OriginCollisionError::InvalidField {
            field: "planned_endpoint_host",
            reason: "must be a parseable address literal",
        })?;
        if !endpoint.ip().is_loopback() {
            return Err(OriginCollisionError::InvalidField {
                field: "planned_endpoint_host",
                reason: "planned installation endpoint must be loopback",
            });
        }
        if self.observed_owner_process_id == Some(0) || self.retained_owned_process_id == Some(0) {
            return Err(OriginCollisionError::InvalidField {
                field: "observed_owner_process_id",
                reason: "an observed process ID is never zero",
            });
        }
        if self.installation.as_str().trim().is_empty()
            || self.generation.as_str().trim().is_empty()
        {
            return Err(OriginCollisionError::InvalidField {
                field: "installation/generation",
                reason: "installation and generation identities must be non-blank",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_error| OriginCollisionError::InvalidField {
                field: "state_fence",
                reason: "state fence is not a valid contract fence",
            })?;
        if self.observed_at_unix_ms == 0 {
            return Err(OriginCollisionError::InvalidField {
                field: "observed_at_unix_ms",
                reason: "must be nonzero",
            });
        }
        if self.evidence_refs.is_empty() || self.evidence_refs.len() > MAX_COLLISION_EVIDENCE_REFS {
            return Err(OriginCollisionError::InvalidField {
                field: "evidence_refs",
                reason: "must be present and within the bounded reference limit",
            });
        }
        Ok(())
    }
}

/// Typed recovery directive for one collided installation endpoint.
///
/// Produced instead of a free-form reason string. It answers I3.4's
/// "classified origin, precise allowed/blocked operation, missing ownership
/// evidence and safe next action" and renders into the existing
/// [`RecoveryDirective`] wire projection rather than defining a second
/// directive family.
///
/// A directive never carries a control permission: [`next_actions`] is drawn
/// from the control-free [`OriginNextAction`] vocabulary, and the blocked
/// operation it names is a *blocked* class, not a granted one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginCollisionDirective {
    /// Exact I7.20 reason code. Always [`PROCESS_OWNERSHIP_UNPROVEN`].
    pub reason_code: PlatformHandle,
    /// Structured collision evidence.
    pub collision: StoreEndpointCollision,
    /// Control class that the collision blocks. Must be a destructive-control
    /// class: a read-only class is never blocked by a collision (I3.4), and a
    /// directive naming one would misreport the disposition.
    pub blocked_operation: OriginOperationClass,
    /// Permitted next actions. Control-free by construction.
    pub next_actions: Vec<OriginNextAction>,
    /// Exact ownership facts that are absent.
    pub missing_evidence: Vec<MissingOwnershipEvidence>,
}

impl OriginCollisionDirective {
    /// Builds a directive for one collision and one blocked control class.
    ///
    /// # Errors
    ///
    /// Returns [`OriginCollisionError::NotAControlOperation`] when
    /// `blocked_operation` is read-only, and
    /// [`OriginCollisionError::ContradictoryEvidence`] when the collision
    /// evidence itself is inconsistent.
    pub fn new(
        collision: StoreEndpointCollision,
        blocked_operation: OriginOperationClass,
        next_actions: &[OriginNextAction],
        missing_evidence: &[MissingOwnershipEvidence],
    ) -> Result<Self, OriginCollisionError> {
        if !blocked_operation.is_control_class() {
            return Err(OriginCollisionError::NotAControlOperation(
                blocked_operation.as_str(),
            ));
        }
        let directive = Self {
            reason_code: PlatformHandle::new(PROCESS_OWNERSHIP_UNPROVEN).map_err(|_error| {
                OriginCollisionError::InvalidField {
                    field: "reason_code",
                    reason: "canonical reason code is not a valid handle",
                }
            })?,
            collision,
            blocked_operation,
            next_actions: next_actions.to_vec(),
            missing_evidence: missing_evidence.to_vec(),
        };
        directive.validate()?;
        Ok(directive)
    }

    /// Returns the exact control class the collision blocks, or `None` when
    /// the blocked class is read-only.
    ///
    /// A read-only blocked class is a malformed directive; the constructor
    /// refuses it so this accessor is total.
    #[must_use]
    pub fn blocked_control(&self) -> Option<AdmittedOriginControl> {
        AdmittedOriginControl::try_from(self.blocked_operation).ok()
    }

    /// Validates the directive against the evidence it carries.
    ///
    /// # Errors
    ///
    /// Returns [`OriginCollisionError`] when the directive would assert
    /// something the evidence contradicts.
    pub fn validate(&self) -> Result<(), OriginCollisionError> {
        if self.reason_code.as_str() != PROCESS_OWNERSHIP_UNPROVEN {
            return Err(OriginCollisionError::ContradictoryEvidence(
                "a process-origin collision always reports PROCESS_OWNERSHIP_UNPROVEN",
            ));
        }
        if !self.blocked_operation.is_control_class() {
            return Err(OriginCollisionError::ContradictoryEvidence(
                "a collision blocks a destructive-control class, never a read-only one",
            ));
        }
        self.collision.validate()?;
        if self.collision.occupant_is_retained_owned() {
            return Err(OriginCollisionError::ContradictoryEvidence(
                "the observed occupant is this installation's own retained process",
            ));
        }
        if self.next_actions.is_empty() {
            return Err(OriginCollisionError::InvalidField {
                field: "next_actions",
                reason: "a directive must name at least one admissible next action",
            });
        }
        if !self
            .next_actions
            .iter()
            .all(|action| action.is_read_only())
        {
            return Err(OriginCollisionError::ContradictoryEvidence(
                "a collision next action must be read-only or a separately admitted endpoint choice",
            ));
        }
        if has_duplicates(&self.next_actions) {
            return Err(OriginCollisionError::InvalidField {
                field: "next_actions",
                reason: "next actions must be unique",
            });
        }
        if self.missing_evidence.is_empty() {
            return Err(OriginCollisionError::InvalidField {
                field: "missing_evidence",
                reason: "a directive must name the exact missing ownership evidence",
            });
        }
        if has_duplicates(&self.missing_evidence) {
            return Err(OriginCollisionError::InvalidField {
                field: "missing_evidence",
                reason: "missing evidence entries must be unique",
            });
        }
        // An unclassified or unreadable occupant cannot have its start identity
        // or connection owner bound, so those two facts are necessarily
        // absent. This derives the expected evidence set from the collision
        // itself, never from the list being measured.
        if matches!(
            self.collision.origin,
            ProcessOriginClassification::Unknown | ProcessOriginClassification::SharedSubstrate
        ) {
            for required in [
                MissingOwnershipEvidence::ProcessStartIdentity,
                MissingOwnershipEvidence::ConnectionOwner,
            ] {
                if !self.missing_evidence.contains(&required) {
                    return Err(OriginCollisionError::ContradictoryEvidence(
                        "an unclassified or shared-substrate occupant cannot have its start identity or connection owner bound",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Renders this typed directive into the existing
    /// `eliot_runtime_contracts::RecoveryDirective` wire projection.
    ///
    /// Reuses the single existing directive owner instead of defining a
    /// second family. The rendered `required_authority` names the authority a
    /// *future* control effect would need; it does not grant it.
    ///
    /// # Errors
    ///
    /// Returns [`OriginCollisionError`] when this directive is not valid or
    /// the rendered projection is rejected.
    pub fn render(&self) -> Result<RecoveryDirective, OriginCollisionError> {
        self.validate()?;
        let next = self
            .next_actions
            .iter()
            .map(|action| action.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let missing = self
            .missing_evidence
            .iter()
            .map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let rendered = RecoveryDirective {
            reason: format!(
                "{} at planned endpoint {}:{} (origin {}, installation {}, generation {})",
                PROCESS_OWNERSHIP_UNPROVEN,
                self.collision.planned_endpoint_host,
                self.collision.planned_endpoint_port,
                self.collision.origin,
                self.collision.installation.as_str(),
                self.collision.generation.as_str(),
            ),
            next_action: next,
            required_authority: format!(
                "blocked control class {} requires a current installation/lineage, process start identity, image artifact, authority epoch and state fence, and an operation-bound challenge; missing: {missing}",
                self.blocked_operation,
            ),
            evidence_refs: self.collision.evidence_refs.clone(),
        };
        rendered
            .validate()
            .map_err(|_error| OriginCollisionError::InvalidField {
                field: "rendered directive",
                reason: "rendered recovery directive is empty or malformed",
            })?;
        Ok(rendered)
    }
}

fn has_duplicates<T: Ord + Copy>(values: &[T]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OBSERVED_AT: u64 = 1_700_000_000_000;

    fn test_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(4).expect("generation"),
        )
    }

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("handle")
    }

    fn collision(origin: ProcessOriginClassification, owner: Option<u32>) -> StoreEndpointCollision {
        StoreEndpointCollision {
            planned_endpoint_host: "127.0.0.1".to_owned(),
            planned_endpoint_port: 8000,
            installation: handle("installation-7"),
            generation: handle("generation-7"),
            state_fence: test_fence(),
            origin,
            observed_owner_process_id: owner,
            retained_owned_process_id: Some(4242),
            observed_at_unix_ms: OBSERVED_AT,
            evidence_refs: vec!["endpoint-observation:8000".to_owned()],
        }
    }

    fn full_evidence() -> [MissingOwnershipEvidence; 6] {
        [
            MissingOwnershipEvidence::InstallationLineage,
            MissingOwnershipEvidence::ProcessStartIdentity,
            MissingOwnershipEvidence::ImageArtifact,
            MissingOwnershipEvidence::AuthorityEpochAndStateFence,
            MissingOwnershipEvidence::OperationChallenge,
            MissingOwnershipEvidence::ConnectionOwner,
        ]
    }

    #[test]
    fn read_only_class_cannot_become_a_control_class() {
        // The A1 refusal. There is no infallible path: both read-only classes
        // are refused by name, and the refusal is the same variant the
        // daemon-side process-origin contract uses.
        assert_eq!(
            AdmittedOriginControl::try_from(OriginOperationClass::ReadStatus),
            Err(OriginCollisionError::NotAControlOperation("ReadStatus"))
        );
        assert_eq!(
            AdmittedOriginControl::try_from(OriginOperationClass::ProbeObserve),
            Err(OriginCollisionError::NotAControlOperation("ProbeObserve"))
        );
        for read_only in [
            OriginOperationClass::ReadStatus,
            OriginOperationClass::ProbeObserve,
        ] {
            assert!(read_only.is_read_only());
            assert!(!read_only.is_control_class());
            assert!(AdmittedOriginControl::try_from(read_only).is_err());
        }
        // Every control class maps to exactly its own label, never a neighbour.
        for control in [
            OriginOperationClass::Stop,
            OriginOperationClass::Mutate,
            OriginOperationClass::Adopt,
            OriginOperationClass::AttachCredential,
        ] {
            let admitted = AdmittedOriginControl::try_from(control).expect("control class");
            assert_eq!(admitted.operation_class(), control);
        }
        assert_eq!(
            AdmittedOriginControl::try_from(OriginOperationClass::Adopt)
                .expect("adopt")
                .as_str(),
            "Adopt"
        );
    }

    #[test]
    fn directive_refuses_a_read_only_blocked_operation() {
        let observed = collision(ProcessOriginClassification::Elsewhere, Some(5150));
        let error = OriginCollisionDirective::new(
            observed,
            OriginOperationClass::ReadStatus,
            &[OriginNextAction::InspectForeignOccupant],
            &full_evidence(),
        )
        .expect_err("a read-only class is never blocked by a collision");
        assert_eq!(
            error,
            OriginCollisionError::NotAControlOperation("ReadStatus")
        );
    }

    #[test]
    fn directive_refuses_this_installations_own_retained_process() {
        // The occupant is exactly the retained child: there is no collision,
        // so a directive would be a false guarantee.
        let observed = collision(ProcessOriginClassification::InsideManagedTree, Some(4242));
        assert!(observed.occupant_is_retained_owned());
        let error = OriginCollisionDirective::new(
            observed,
            OriginOperationClass::Stop,
            &[OriginNextAction::InspectForeignOccupant],
            &full_evidence(),
        )
        .expect_err("own retained process is not a foreign collision");
        assert_eq!(
            error,
            OriginCollisionError::ContradictoryEvidence(
                "the observed occupant is this installation's own retained process"
            )
        );
    }

    #[test]
    fn unreadable_owner_is_not_absence() {
        // `None` observed owner is distinct from "no occupant": it never
        // matches the retained child, and it still blocks the launch.
        let observed = collision(ProcessOriginClassification::Unknown, None);
        assert!(!observed.occupant_is_retained_owned());
        let directive = OriginCollisionDirective::new(
            observed,
            OriginOperationClass::Stop,
            &[
                OriginNextAction::InspectForeignOccupant,
                OriginNextAction::SelectAlternateEndpoint,
            ],
            &full_evidence(),
        )
        .expect("unreadable owner still produces a directive");
        assert_eq!(directive.blocked_control(), Some(AdmittedOriginControl::Stop));
        assert!(directive.render().is_ok());
    }

    #[test]
    fn unclassified_origin_requires_start_identity_and_connection_owner() {
        // The expected evidence set is derived from the collision's own
        // classification, not from whatever the caller happened to list.
        let observed = collision(ProcessOriginClassification::Unknown, Some(5150));
        let incomplete: Vec<MissingOwnershipEvidence> = full_evidence()
            .into_iter()
            .filter(|item| item != &MissingOwnershipEvidence::ProcessStartIdentity)
            .collect();
        assert_eq!(
            OriginCollisionDirective::new(
                observed.clone(),
                OriginOperationClass::Stop,
                &[OriginNextAction::InspectForeignOccupant],
                &incomplete,
            ),
            Err(OriginCollisionError::ContradictoryEvidence(
                "an unclassified or shared-substrate occupant cannot have its start identity or connection owner bound"
            ))
        );
        // The same list is legal once the classification can actually support it.
        assert!(OriginCollisionDirective::new(
            observed,
            OriginOperationClass::Stop,
            &[OriginNextAction::InspectForeignOccupant],
            &incomplete,
        )
        .is_err());
        let mut complete = incomplete;
        complete.push(MissingOwnershipEvidence::ProcessStartIdentity);
        complete.push(MissingOwnershipEvidence::ConnectionOwner);
        assert!(OriginCollisionDirective::new(
            collision(ProcessOriginClassification::Unknown, Some(5150)),
            OriginOperationClass::Stop,
            &[OriginNextAction::InspectForeignOccupant],
            &complete,
        )
        .is_ok());
    }

    #[test]
    fn rendered_directive_names_the_code_and_carries_no_control_permission() {
        let directive = OriginCollisionDirective::new(
            collision(ProcessOriginClassification::SharedSubstrate, Some(5150)),
            OriginOperationClass::AttachCredential,
            &[OriginNextAction::ImportLegacyDataReadOnly],
            &full_evidence(),
        )
        .expect("shared substrate with complete evidence is legal");
        let rendered = directive.render().expect("render");
        assert!(rendered.reason.contains(PROCESS_OWNERSHIP_UNPROVEN));
        assert!(rendered.reason.contains("SHARED_SUBSTRATE"));
        assert_eq!(rendered.next_action, "IMPORT_LEGACY_DATA_READ_ONLY");
        assert!(rendered
            .required_authority
            .contains("AttachCredential"));
        assert!(rendered.required_authority.contains("blocked control class"));
        // No rendered field can be read as a granted control permission: the
        // next action vocabulary has no destructive member to leak.
        for action in OriginNextAction::read_only_actions() {
            assert!(action.is_read_only());
            assert!(!action.as_str().to_ascii_lowercase().contains("kill"));
            assert!(!action.as_str().to_ascii_lowercase().contains("adopt"));
            assert!(!action.as_str().to_ascii_lowercase().contains("login"));
        }
    }
}
