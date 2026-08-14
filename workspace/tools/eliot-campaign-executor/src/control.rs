//! Pure D-02 controller and worker control semantics.
//!
//! This module deliberately contains no I/O and does not append campaign
//! events.  Callers persist the returned receipts through their own ledger
//! boundary after the transition has been accepted.

use crate::EpochId;
use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The fence carried by every controller and worker attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateFence {
    pub controller_epoch: EpochId,
    pub ledger_sequence: u64,
    pub head_hash: String,
}

impl StateFence {
    pub fn new(
        controller_epoch: EpochId,
        ledger_sequence: u64,
        head_hash: impl Into<String>,
    ) -> Self {
        Self {
            controller_epoch,
            ledger_sequence,
            head_hash: head_hash.into(),
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }

    pub fn is_older_than(&self, other: &Self) -> bool {
        self.controller_epoch.lineage == other.controller_epoch.lineage
            && self.controller_epoch.sequence < other.controller_epoch.sequence
            || self.controller_epoch == other.controller_epoch
                && self.ledger_sequence < other.ledger_sequence
    }
}

pub type ControllerEpoch = EpochId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControllerAttempt {
    pub attempt_id: String,
    pub controller_id: String,
    pub fence: StateFence,
}

impl ControllerAttempt {
    pub fn new(
        attempt_id: impl Into<String>,
        controller_id: impl Into<String>,
        fence: StateFence,
    ) -> Result<Self> {
        let attempt = Self {
            attempt_id: attempt_id.into(),
            controller_id: controller_id.into(),
            fence,
        };
        ensure!(
            !attempt.attempt_id.trim().is_empty(),
            "controller attempt id is required"
        );
        ensure!(
            !attempt.controller_id.trim().is_empty(),
            "controller id is required"
        );
        Ok(attempt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerAttempt {
    pub attempt_id: String,
    pub worker_id: String,
    pub controller_epoch: EpochId,
    pub fence: StateFence,
}

impl WorkerAttempt {
    pub fn new(
        attempt_id: impl Into<String>,
        worker_id: impl Into<String>,
        fence: StateFence,
    ) -> Result<Self> {
        let attempt = Self {
            attempt_id: attempt_id.into(),
            worker_id: worker_id.into(),
            controller_epoch: fence.controller_epoch.clone(),
            fence,
        };
        ensure!(
            !attempt.attempt_id.trim().is_empty(),
            "worker attempt id is required"
        );
        ensure!(
            !attempt.worker_id.trim().is_empty(),
            "worker id is required"
        );
        Ok(attempt)
    }

    pub fn is_current(&self, fence: &StateFence) -> bool {
        self.fence.matches(fence)
    }
}

fn clean_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_matches('/')
        .to_ascii_lowercase()
}

fn path_contains(parent: &str, child: &str) -> bool {
    parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Write scopes are closed and exact.  A path claim overlaps descendants;
/// package claims overlap all claims in that package; generated claims only
/// overlap the same generated output key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ClaimScope {
    Path {
        path: String,
    },
    Symbol {
        package: String,
        path: String,
        symbol: String,
    },
    Package {
        package: String,
    },
    Generated {
        key: String,
    },
}

impl ClaimScope {
    pub fn path(path: impl Into<String>) -> Self {
        Self::Path {
            path: clean_path(&path.into()),
        }
    }
    pub fn symbol(
        package: impl Into<String>,
        path: impl Into<String>,
        symbol: impl Into<String>,
    ) -> Self {
        Self::Symbol {
            package: package.into(),
            path: clean_path(&path.into()),
            symbol: symbol.into(),
        }
    }
    pub fn package(package: impl Into<String>) -> Self {
        Self::Package {
            package: package.into(),
        }
    }
    pub fn generated(key: impl Into<String>) -> Self {
        Self::Generated { key: key.into() }
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Generated { key: left }, Self::Generated { key: right })
            | (Self::Package { package: left }, Self::Package { package: right }) => left == right,
            (Self::Package { package }, Self::Symbol { package: other, .. })
            | (Self::Symbol { package: other, .. }, Self::Package { package }) => package == other,
            (Self::Package { package }, Self::Path { path })
            | (Self::Path { path }, Self::Package { package }) => {
                path_contains(&clean_path(package), path)
            }
            (Self::Path { path: left }, Self::Path { path: right }) => {
                path_contains(left, right) || path_contains(right, left)
            }
            (
                Self::Path { path },
                Self::Symbol {
                    path: symbol_path, ..
                },
            )
            | (
                Self::Symbol {
                    path: symbol_path, ..
                },
                Self::Path { path },
            ) => path_contains(path, symbol_path),
            (
                Self::Symbol {
                    package: lp,
                    path: lpath,
                    symbol: ls,
                },
                Self::Symbol {
                    package: rp,
                    path: rpath,
                    symbol: rs,
                },
            ) => lp == rp && lpath == rpath && ls == rs,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequest {
    pub claim_id: String,
    pub owner_id: String,
    pub scope: ClaimScope,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub claim_id: String,
    pub owner_id: String,
    pub scope: ClaimScope,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimRegistry {
    pub claims: BTreeMap<String, Claim>,
}

impl ClaimRegistry {
    pub fn claim(&mut self, request: ClaimRequest) -> Result<Claim> {
        ensure!(!request.claim_id.trim().is_empty(), "claim id is required");
        ensure!(
            !request.owner_id.trim().is_empty(),
            "claim owner is required"
        );
        if self.claims.contains_key(&request.claim_id) {
            bail!("claim id already exists: {}", request.claim_id);
        }
        if let Some(existing) = self
            .claims
            .values()
            .find(|claim| claim.scope.overlaps(&request.scope))
        {
            bail!("claim overlaps existing claim {}", existing.claim_id);
        }
        let claim = Claim {
            claim_id: request.claim_id,
            owner_id: request.owner_id,
            scope: request.scope,
            fence: request.fence,
        };
        self.claims.insert(claim.claim_id.clone(), claim.clone());
        Ok(claim)
    }

    pub fn release(&mut self, claim_id: &str, owner_id: &str) -> Result<Claim> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| anyhow!("unknown claim: {claim_id}"))?;
        ensure!(
            claim.owner_id == owner_id,
            "only the claim owner may release a claim"
        );
        self.claims
            .remove(claim_id)
            .ok_or_else(|| anyhow!("claim disappeared: {claim_id}"))
    }

    pub fn active(&self) -> impl Iterator<Item = &Claim> {
        self.claims.values()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkLeaseState {
    Active,
    WorkerLost,
    Reassigned,
    Completed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Saved,
    LostWorker,
    Reassigned,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkCheckpoint {
    pub checkpoint_id: String,
    pub lease_id: String,
    pub worker_attempt_id: String,
    pub generation: u64,
    pub fence: StateFence,
    pub status: CheckpointStatus,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkLease {
    pub lease_id: String,
    pub owner_id: String,
    pub worker_attempt_id: String,
    pub scope: ClaimScope,
    pub fence: StateFence,
    pub generation: u64,
    pub state: WorkLeaseState,
    pub last_checkpoint: Option<WorkCheckpoint>,
}

impl WorkLease {
    pub fn new(
        lease_id: impl Into<String>,
        owner_id: impl Into<String>,
        worker_attempt_id: impl Into<String>,
        scope: ClaimScope,
        fence: StateFence,
    ) -> Result<Self> {
        let lease = Self {
            lease_id: lease_id.into(),
            owner_id: owner_id.into(),
            worker_attempt_id: worker_attempt_id.into(),
            scope,
            fence,
            generation: 1,
            state: WorkLeaseState::Active,
            last_checkpoint: None,
        };
        ensure!(
            !lease.lease_id.trim().is_empty(),
            "work lease id is required"
        );
        ensure!(
            !lease.owner_id.trim().is_empty(),
            "work lease owner is required"
        );
        ensure!(
            !lease.worker_attempt_id.trim().is_empty(),
            "worker attempt is required"
        );
        Ok(lease)
    }

    pub fn checkpoint(&mut self, checkpoint: WorkCheckpoint) -> Result<()> {
        ensure!(
            self.state == WorkLeaseState::Active,
            "work lease is not active"
        );
        ensure!(
            checkpoint.lease_id == self.lease_id,
            "checkpoint lease mismatch"
        );
        ensure!(
            checkpoint.worker_attempt_id == self.worker_attempt_id,
            "checkpoint worker mismatch"
        );
        ensure!(
            checkpoint.generation == self.generation,
            "stale work slice generation"
        );
        ensure!(
            checkpoint.fence.matches(&self.fence),
            "stale work slice fence"
        );
        self.last_checkpoint = Some(checkpoint);
        Ok(())
    }

    pub fn mark_worker_lost(
        &mut self,
        checkpoint_id: impl Into<String>,
        evidence_digest: impl Into<String>,
    ) -> Result<WorkCheckpoint> {
        ensure!(
            self.state == WorkLeaseState::Active,
            "work lease is not active"
        );
        let checkpoint = WorkCheckpoint {
            checkpoint_id: checkpoint_id.into(),
            lease_id: self.lease_id.clone(),
            worker_attempt_id: self.worker_attempt_id.clone(),
            generation: self.generation,
            fence: self.fence.clone(),
            status: CheckpointStatus::LostWorker,
            evidence_digest: evidence_digest.into(),
        };
        ensure!(
            !checkpoint.checkpoint_id.trim().is_empty(),
            "lost-worker checkpoint id is required"
        );
        ensure!(
            !checkpoint.evidence_digest.trim().is_empty(),
            "lost-worker evidence is required"
        );
        self.last_checkpoint = Some(checkpoint.clone());
        self.state = WorkLeaseState::WorkerLost;
        Ok(checkpoint)
    }

    pub fn reassign(
        &mut self,
        worker_attempt_id: impl Into<String>,
        fence: StateFence,
    ) -> Result<WorkCheckpoint> {
        ensure!(
            self.state == WorkLeaseState::WorkerLost,
            "only a lost worker lease may be reassigned"
        );
        let worker_attempt_id = worker_attempt_id.into();
        ensure!(
            !worker_attempt_id.trim().is_empty(),
            "replacement worker attempt is required"
        );
        ensure!(
            self.fence.controller_epoch == fence.controller_epoch,
            "replacement crosses controller epoch"
        );
        ensure!(
            self.fence.is_older_than(&fence),
            "replacement worker fence is stale"
        );
        self.generation = self.generation.saturating_add(1);
        self.worker_attempt_id = worker_attempt_id;
        self.fence = fence.clone();
        self.state = WorkLeaseState::Reassigned;
        let checkpoint = WorkCheckpoint {
            checkpoint_id: format!("{}:reassign:{}", self.lease_id, self.generation),
            lease_id: self.lease_id.clone(),
            worker_attempt_id: self.worker_attempt_id.clone(),
            generation: self.generation,
            fence,
            status: CheckpointStatus::Reassigned,
            evidence_digest: self
                .last_checkpoint
                .as_ref()
                .map_or_else(String::new, |c| c.evidence_digest.clone()),
        };
        self.last_checkpoint = Some(checkpoint.clone());
        self.state = WorkLeaseState::Active;
        Ok(checkpoint)
    }

    pub fn complete(&mut self, worker_attempt_id: &str, fence: &StateFence) -> Result<()> {
        ensure!(
            self.state == WorkLeaseState::Active,
            "work lease is not active"
        );
        ensure!(
            self.worker_attempt_id == worker_attempt_id,
            "worker does not own work lease"
        );
        ensure!(self.fence.matches(fence), "stale work slice fence");
        self.state = WorkLeaseState::Completed;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageLeaseState {
    Held,
    Released,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageAssemblyLease {
    pub lease_id: String,
    pub package: String,
    pub assembler_id: String,
    pub fence: StateFence,
    pub state: PackageLeaseState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrationLease {
    pub lease_id: String,
    pub package: String,
    pub integrator_id: String,
    pub author_id: String,
    pub fence: StateFence,
    pub state: PackageLeaseState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRequest {
    pub package: String,
    pub author_id: String,
    pub integrator_id: String,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageLeaseBook {
    pub assembly: BTreeMap<String, PackageAssemblyLease>,
    pub integration: Option<IntegrationLease>,
    pub pending_integration: BTreeMap<String, IntegrationRequest>,
}

impl PackageLeaseBook {
    pub fn acquire_assembly(
        &mut self,
        lease_id: impl Into<String>,
        package: impl Into<String>,
        assembler_id: impl Into<String>,
        fence: StateFence,
    ) -> Result<PackageAssemblyLease> {
        let package = package.into();
        ensure!(
            !self.assembly.contains_key(&package),
            "package assembly lease already held"
        );
        let lease = PackageAssemblyLease {
            lease_id: lease_id.into(),
            package: package.clone(),
            assembler_id: assembler_id.into(),
            fence,
            state: PackageLeaseState::Held,
        };
        ensure!(
            !lease.lease_id.trim().is_empty(),
            "assembly lease id is required"
        );
        ensure!(
            !lease.assembler_id.trim().is_empty(),
            "assembler id is required"
        );
        self.assembly.insert(package, lease.clone());
        Ok(lease)
    }

    pub fn release_assembly(
        &mut self,
        package: &str,
        assembler_id: &str,
        fence: &StateFence,
    ) -> Result<PackageAssemblyLease> {
        let lease = self
            .assembly
            .get(package)
            .ok_or_else(|| anyhow!("no package assembly lease"))?;
        ensure!(
            lease.assembler_id == assembler_id,
            "only assembler may release assembly lease"
        );
        ensure!(lease.fence.matches(fence), "stale assembly lease fence");
        let mut lease = self
            .assembly
            .remove(package)
            .ok_or_else(|| anyhow!("assembly lease disappeared"))?;
        lease.state = PackageLeaseState::Released;
        Ok(lease)
    }

    pub fn queue_integration(&mut self, request: IntegrationRequest) -> Result<()> {
        ensure!(!request.package.trim().is_empty(), "package is required");
        ensure!(!request.author_id.trim().is_empty(), "author is required");
        ensure!(
            !request.integrator_id.trim().is_empty(),
            "integrator is required"
        );
        ensure!(
            request.author_id != request.integrator_id,
            "author may not self-integrate"
        );
        ensure!(
            !self.pending_integration.contains_key(&request.package),
            "package is already queued for integration"
        );
        self.pending_integration
            .insert(request.package.clone(), request);
        Ok(())
    }

    pub fn acquire_next_integration(
        &mut self,
        lease_id: impl Into<String>,
        integrator_id: &str,
        fence: StateFence,
    ) -> Result<IntegrationLease> {
        ensure!(
            self.integration.is_none(),
            "an integration lease is already held"
        );
        let package = self
            .pending_integration
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| anyhow!("integration queue is empty"))?;
        let request = self
            .pending_integration
            .get(&package)
            .cloned()
            .ok_or_else(|| anyhow!("integration queue changed"))?;
        ensure!(
            request.integrator_id == integrator_id,
            "integration lease recipient mismatch"
        );
        ensure!(
            request.author_id != integrator_id,
            "author may not self-integrate"
        );
        ensure!(
            request.fence.matches(&fence),
            "stale integration queue fence"
        );
        let request = self
            .pending_integration
            .remove(&package)
            .ok_or_else(|| anyhow!("integration queue changed"))?;
        let lease = IntegrationLease {
            lease_id: lease_id.into(),
            package,
            integrator_id: integrator_id.to_owned(),
            author_id: request.author_id,
            fence,
            state: PackageLeaseState::Held,
        };
        ensure!(
            !lease.lease_id.trim().is_empty(),
            "integration lease id is required"
        );
        self.integration = Some(lease.clone());
        Ok(lease)
    }

    pub fn release_integration(
        &mut self,
        lease_id: &str,
        integrator_id: &str,
        fence: &StateFence,
    ) -> Result<IntegrationLease> {
        let lease = self
            .integration
            .as_ref()
            .ok_or_else(|| anyhow!("no integration lease"))?;
        ensure!(lease.lease_id == lease_id, "integration lease id mismatch");
        ensure!(
            lease.integrator_id == integrator_id,
            "only integrator may release integration lease"
        );
        ensure!(lease.fence.matches(fence), "stale integration lease fence");
        let mut lease = self
            .integration
            .take()
            .ok_or_else(|| anyhow!("integration lease disappeared"))?;
        lease.state = PackageLeaseState::Released;
        Ok(lease)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandoffKind {
    Review,
    Assembly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Offered,
    Accepted,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HandoffReceipt {
    pub receipt_id: String,
    pub author_id: String,
    pub recipient_id: String,
    pub kind: HandoffKind,
    pub slot: u8,
    pub fence: StateFence,
    pub evidence_digest: String,
    pub status: HandoffStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HandoffSlot {
    pub receipt: Option<HandoffReceipt>,
}

impl HandoffSlot {
    pub fn offer(
        &mut self,
        receipt_id: impl Into<String>,
        author_id: impl Into<String>,
        recipient_id: impl Into<String>,
        kind: HandoffKind,
        fence: StateFence,
        evidence_digest: impl Into<String>,
    ) -> Result<HandoffReceipt> {
        ensure!(self.receipt.is_none(), "the one-slot handoff is occupied");
        let receipt = HandoffReceipt {
            receipt_id: receipt_id.into(),
            author_id: author_id.into(),
            recipient_id: recipient_id.into(),
            kind,
            slot: 1,
            fence,
            evidence_digest: evidence_digest.into(),
            status: HandoffStatus::Offered,
        };
        ensure!(
            !receipt.author_id.trim().is_empty() && !receipt.recipient_id.trim().is_empty(),
            "handoff participants are required"
        );
        ensure!(
            receipt.author_id != receipt.recipient_id,
            "author may not receive own handoff"
        );
        ensure!(
            !receipt.evidence_digest.trim().is_empty(),
            "handoff evidence is required"
        );
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn accept(
        &mut self,
        receipt_id: &str,
        recipient_id: &str,
        fence: &StateFence,
    ) -> Result<HandoffReceipt> {
        let receipt = self
            .receipt
            .as_mut()
            .ok_or_else(|| anyhow!("no handoff offered"))?;
        ensure!(receipt.receipt_id == receipt_id, "handoff receipt mismatch");
        ensure!(
            receipt.recipient_id == recipient_id,
            "handoff recipient mismatch"
        );
        ensure!(receipt.fence.matches(fence), "stale handoff fence");
        ensure!(
            receipt.status == HandoffStatus::Offered,
            "handoff is not awaiting acceptance"
        );
        receipt.status = HandoffStatus::Accepted;
        Ok(receipt.clone())
    }

    pub fn complete(
        &mut self,
        receipt_id: &str,
        recipient_id: &str,
        fence: &StateFence,
    ) -> Result<HandoffReceipt> {
        let receipt = self
            .receipt
            .as_mut()
            .ok_or_else(|| anyhow!("no handoff offered"))?;
        ensure!(receipt.receipt_id == receipt_id, "handoff receipt mismatch");
        ensure!(
            receipt.recipient_id == recipient_id,
            "handoff recipient mismatch"
        );
        ensure!(receipt.fence.matches(fence), "stale handoff fence");
        ensure!(
            receipt.status == HandoffStatus::Accepted,
            "handoff must be accepted first"
        );
        receipt.status = HandoffStatus::Completed;
        let completed = receipt.clone();
        self.receipt = None;
        Ok(completed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct BuildFingerprint(pub String);

impl BuildFingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(!value.trim().is_empty(), "build fingerprint is required");
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildWaiter {
    pub waiter_id: String,
    pub fingerprint: BuildFingerprint,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildProducer {
    pub producer_id: String,
    pub fingerprint: BuildFingerprint,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildWakeEvidence {
    pub fingerprint: BuildFingerprint,
    pub producer_id: String,
    pub waiter_ids: Vec<String>,
    pub failure_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildFailureReceipt {
    pub fingerprint: BuildFingerprint,
    pub producer_id: String,
    pub evidence: String,
    pub wake: BuildWakeEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuildJoin {
    Producer(BuildProducer),
    Waiter(BuildWaiter),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildCoordinator {
    producers: BTreeMap<BuildFingerprint, BuildProducer>,
    waiters: BTreeMap<BuildFingerprint, BTreeMap<String, BuildWaiter>>,
    completed: BTreeSet<BuildFingerprint>,
}

impl BuildCoordinator {
    pub fn join(
        &mut self,
        producer_id: impl Into<String>,
        waiter_id: impl Into<String>,
        fingerprint: BuildFingerprint,
        fence: StateFence,
    ) -> Result<BuildJoin> {
        let producer_id = producer_id.into();
        let waiter_id = waiter_id.into();
        ensure!(
            !producer_id.trim().is_empty(),
            "build producer id is required"
        );
        ensure!(!waiter_id.trim().is_empty(), "build waiter id is required");
        if self.completed.contains(&fingerprint) {
            return Ok(BuildJoin::Waiter(BuildWaiter {
                waiter_id,
                fingerprint,
                fence,
            }));
        }
        if let Some(producer) = self.producers.get(&fingerprint) {
            let waiter = BuildWaiter {
                waiter_id: waiter_id.clone(),
                fingerprint: fingerprint.clone(),
                fence,
            };
            self.waiters
                .entry(fingerprint)
                .or_default()
                .insert(waiter_id, waiter.clone());
            let _ = producer;
            return Ok(BuildJoin::Waiter(waiter));
        }
        let producer = BuildProducer {
            producer_id,
            fingerprint: fingerprint.clone(),
            fence,
        };
        self.producers.insert(fingerprint, producer.clone());
        Ok(BuildJoin::Producer(producer))
    }

    pub fn complete(
        &mut self,
        fingerprint: &BuildFingerprint,
        producer_id: &str,
    ) -> Result<Vec<BuildWaiter>> {
        let producer = self
            .producers
            .get(fingerprint)
            .ok_or_else(|| anyhow!("no build producer"))?;
        ensure!(
            producer.producer_id == producer_id,
            "only build producer may complete"
        );
        let waiters = self
            .waiters
            .remove(fingerprint)
            .unwrap_or_default()
            .into_values()
            .collect();
        self.producers.remove(fingerprint);
        self.completed.insert(fingerprint.clone());
        Ok(waiters)
    }

    pub fn fail(
        &mut self,
        fingerprint: &BuildFingerprint,
        producer_id: &str,
        evidence: impl Into<String>,
    ) -> Result<BuildFailureReceipt> {
        let producer = self
            .producers
            .get(fingerprint)
            .ok_or_else(|| anyhow!("no build producer"))?;
        ensure!(
            producer.producer_id == producer_id,
            "only build producer may fail"
        );
        let evidence = evidence.into();
        ensure!(
            !evidence.trim().is_empty(),
            "failed producer evidence is required"
        );
        let waiter_ids = self
            .waiters
            .remove(fingerprint)
            .unwrap_or_default()
            .into_keys()
            .collect::<Vec<_>>();
        self.producers.remove(fingerprint);
        Ok(BuildFailureReceipt {
            fingerprint: fingerprint.clone(),
            producer_id: producer_id.to_owned(),
            evidence: evidence.clone(),
            wake: BuildWakeEvidence {
                fingerprint: fingerprint.clone(),
                producer_id: producer_id.to_owned(),
                waiter_ids,
                failure_evidence: evidence,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    Live,
    Unreachable,
    Finished,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParentFinishBlock {
    pub parent_id: String,
    pub blocking_children: BTreeMap<String, ChildState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParentFinishGate {
    pub children: BTreeMap<String, ChildState>,
}

impl ParentFinishGate {
    pub fn set_child(&mut self, child_id: impl Into<String>, state: ChildState) -> Result<()> {
        let child_id = child_id.into();
        ensure!(!child_id.trim().is_empty(), "child id is required");
        self.children.insert(child_id, state);
        Ok(())
    }

    pub fn finish(&self, parent_id: impl Into<String>) -> Result<()> {
        let parent_id = parent_id.into();
        let blocking_children = self
            .children
            .iter()
            .filter(|(_, state)| **state != ChildState::Finished)
            .map(|(id, state)| (id.clone(), *state))
            .collect::<BTreeMap<_, _>>();
        if !blocking_children.is_empty() {
            return Err(anyhow!(
                "parent finish blocked: {}",
                serde_json::to_string(&ParentFinishBlock {
                    parent_id,
                    blocking_children
                })?
            ));
        }
        Ok(())
    }

    pub fn can_finish(&self) -> bool {
        self.children
            .values()
            .all(|state| *state == ChildState::Finished)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCeiling {
    Observe,
    Claim,
    Write,
    Assemble,
    Integrate,
    Controller,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ControlCommand {
    Observe,
    ClaimWork,
    Checkpoint,
    WriteSource,
    AssemblePackage,
    IntegratePackage,
    Replan,
    FinishParent,
}

impl ControlCommand {
    pub fn required_ceiling(self) -> AuthorityCeiling {
        match self {
            Self::Observe => AuthorityCeiling::Observe,
            Self::ClaimWork => AuthorityCeiling::Claim,
            Self::Checkpoint | Self::WriteSource => AuthorityCeiling::Write,
            Self::AssemblePackage => AuthorityCeiling::Assemble,
            Self::IntegratePackage => AuthorityCeiling::Integrate,
            Self::Replan | Self::FinishParent => AuthorityCeiling::Controller,
        }
    }
}

impl AuthorityCeiling {
    pub fn permits(self, command: ControlCommand) -> bool {
        self >= command.required_ceiling()
    }

    pub fn reject_command(self, command: ControlCommand) -> Result<()> {
        ensure!(
            self.permits(command),
            "authority ceiling {self:?} rejects command {command:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fence() -> StateFence {
        StateFence::new(
            EpochId {
                lineage: Uuid::nil(),
                sequence: 1,
            },
            3,
            "head",
        )
    }

    #[test]
    fn claims_reject_ancestor_and_symbol_overlap() {
        let mut registry = ClaimRegistry::default();
        registry
            .claim(ClaimRequest {
                claim_id: "one".into(),
                owner_id: "a".into(),
                scope: ClaimScope::path("src"),
                fence: fence(),
            })
            .unwrap();
        assert!(
            registry
                .claim(ClaimRequest {
                    claim_id: "two".into(),
                    owner_id: "b".into(),
                    scope: ClaimScope::symbol("pkg", "src/lib.rs", "x"),
                    fence: fence()
                })
                .is_err()
        );
    }

    #[test]
    fn failed_build_wakes_all_waiters_with_evidence() {
        let mut builds = BuildCoordinator::default();
        let fp = BuildFingerprint::new("abc").unwrap();
        assert!(matches!(
            builds.join("p", "p", fp.clone(), fence()).unwrap(),
            BuildJoin::Producer(_)
        ));
        assert!(matches!(
            builds.join("p", "w", fp.clone(), fence()).unwrap(),
            BuildJoin::Waiter(_)
        ));
        let failed = builds.fail(&fp, "p", "compiler error").unwrap();
        assert_eq!(failed.wake.waiter_ids, vec!["w"]);
    }

    #[test]
    fn stale_checkpoint_and_parent_finish_are_rejected() {
        let mut lease =
            WorkLease::new("l", "owner", "worker", ClaimScope::path("src"), fence()).unwrap();
        let mut stale = fence();
        stale.ledger_sequence += 1;
        let checkpoint = WorkCheckpoint {
            checkpoint_id: "c".into(),
            lease_id: "l".into(),
            worker_attempt_id: "worker".into(),
            generation: 1,
            fence: stale,
            status: CheckpointStatus::Saved,
            evidence_digest: "e".into(),
        };
        assert!(lease.checkpoint(checkpoint).is_err());
        let mut gate = ParentFinishGate::default();
        gate.set_child("child", ChildState::Unreachable).unwrap();
        assert!(!gate.can_finish());
        assert!(gate.finish("parent").is_err());
    }
}
