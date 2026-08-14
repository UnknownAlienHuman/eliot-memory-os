//! Pure D-02 peer coordination semantics.
//!
//! Maps, replans, deliveries, review anchors, and mechanism failures remain
//! ordinary values until a caller persists the accompanying receipt.

use crate::control::{ControllerAttempt, StateFence};
use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirstPassMap {
    pub worker_id: String,
    pub map_digest: String,
    pub fence: StateFence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MapSealReason {
    AllFirstPasses,
    ExactTimeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapSealReceipt {
    pub reason: MapSealReason,
    pub map_ids: Vec<String>,
    pub sealed_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndependentMaps {
    pub expected_workers: BTreeSet<String>,
    pub first_passes: BTreeMap<String, FirstPassMap>,
    pub deadline: Option<u64>,
    pub sealed: Option<MapSealReceipt>,
}

impl IndependentMaps {
    pub fn new<I, S>(workers: I, timeout_tick: Option<u64>) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let expected_workers = workers.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        ensure!(
            !expected_workers.is_empty(),
            "at least one independent map worker is required"
        );
        ensure!(
            expected_workers
                .iter()
                .all(|worker| !worker.trim().is_empty()),
            "map worker id is required"
        );
        Ok(Self {
            expected_workers,
            first_passes: BTreeMap::new(),
            deadline: timeout_tick,
            sealed: None,
        })
    }

    pub fn submit_first_pass(&mut self, map: FirstPassMap) -> Result<()> {
        ensure!(self.sealed.is_none(), "independent maps are already sealed");
        ensure!(
            self.expected_workers.contains(&map.worker_id),
            "worker is not part of the independent map set"
        );
        ensure!(!map.map_digest.trim().is_empty(), "map digest is required");
        ensure!(
            !self.first_passes.contains_key(&map.worker_id),
            "worker first pass already submitted"
        );
        self.first_passes.insert(map.worker_id.clone(), map);
        Ok(())
    }

    pub fn seal(&mut self, now: u64) -> Result<MapSealReceipt> {
        if let Some(receipt) = self.sealed.clone() {
            return Ok(receipt);
        }
        let complete = self.first_passes.len() == self.expected_workers.len();
        let timed_out = self.deadline.is_some_and(|deadline| now == deadline);
        ensure!(
            complete || timed_out,
            "independent maps may seal only after all first passes or the exact timeout"
        );
        ensure!(
            self.deadline
                .is_none_or(|deadline| now <= deadline || timed_out),
            "map seal passed the exact timeout"
        );
        let receipt = MapSealReceipt {
            reason: if complete {
                MapSealReason::AllFirstPasses
            } else {
                MapSealReason::ExactTimeout
            },
            map_ids: self.first_passes.keys().cloned().collect(),
            sealed_at: now,
        };
        self.sealed = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Replan {
    pub replan_id: String,
    pub controller_id: String,
    pub fence: StateFence,
    pub plan_digest: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplanPublication {
    pub published: Option<Replan>,
}

impl ReplanPublication {
    pub fn publish(&mut self, replan: Replan, caller_is_controller: bool) -> Result<Replan> {
        ensure!(
            caller_is_controller,
            "only the controller may publish a replan"
        );
        ensure!(self.published.is_none(), "replan publication is immutable");
        ensure!(!replan.replan_id.trim().is_empty(), "replan id is required");
        ensure!(
            !replan.controller_id.trim().is_empty(),
            "controller id is required"
        );
        ensure!(
            !replan.plan_digest.trim().is_empty(),
            "replan digest is required"
        );
        self.published = Some(replan.clone());
        Ok(replan)
    }

    pub fn publish_from_controller(
        &mut self,
        attempt: &ControllerAttempt,
        replan: Replan,
    ) -> Result<Replan> {
        ensure!(
            replan.controller_id == attempt.controller_id,
            "replan controller identity mismatch"
        );
        ensure!(
            replan.fence.matches(&attempt.fence),
            "replan fence does not match controller attempt"
        );
        self.publish(replan, true)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerDeliveryState {
    EventIntegrated,
    ToolOnly,
    OfflineWorker,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerDelivery {
    pub delivery_id: String,
    pub recipient: String,
    pub fence: StateFence,
    pub evidence_digest: String,
    pub dedup_key: String,
    pub state: PeerDeliveryState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerDeliveryBook {
    pub deliveries: BTreeMap<String, PeerDelivery>,
    pub dedup: BTreeMap<String, String>,
}

impl PeerDeliveryBook {
    pub fn deliver(&mut self, delivery: PeerDelivery) -> Result<PeerDelivery> {
        ensure!(
            !delivery.delivery_id.trim().is_empty(),
            "delivery id is required"
        );
        ensure!(
            !delivery.recipient.trim().is_empty(),
            "delivery recipient is required"
        );
        ensure!(
            !delivery.evidence_digest.trim().is_empty(),
            "delivery evidence is required"
        );
        ensure!(
            !delivery.dedup_key.trim().is_empty(),
            "delivery dedup key is required"
        );
        if let Some(existing_id) = self.dedup.get(&delivery.dedup_key) {
            if existing_id == &delivery.delivery_id {
                return self
                    .deliveries
                    .get(existing_id)
                    .cloned()
                    .ok_or_else(|| anyhow!("dedup binding is dangling"));
            }
            bail!("delivery dedup key is already bound");
        }
        ensure!(
            !self.deliveries.contains_key(&delivery.delivery_id),
            "delivery id already exists"
        );
        self.dedup
            .insert(delivery.dedup_key.clone(), delivery.delivery_id.clone());
        self.deliveries
            .insert(delivery.delivery_id.clone(), delivery.clone());
        Ok(delivery)
    }

    pub fn for_next_boundary(&self, recipient: &str, fence: &StateFence) -> Vec<&PeerDelivery> {
        self.deliveries
            .values()
            .filter(|delivery| delivery.recipient == recipient && delivery.fence.matches(fence))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewAnchor {
    pub anchor_id: String,
    pub path: String,
    pub symbol: String,
    pub line: u32,
    pub context_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewItem {
    pub review_id: String,
    pub batch_id: String,
    pub anchor: ReviewAnchor,
    pub summary: String,
    pub open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorRevision {
    pub anchor_id: String,
    pub batch_id: String,
    pub path: String,
    pub symbol: String,
    pub line: u32,
    pub context_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorResolution {
    Exact,
    Ambiguous,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnchorResolutionReceipt {
    pub review_id: String,
    pub anchor_id: String,
    pub resolution: AnchorResolution,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewBook {
    pub items: BTreeMap<String, ReviewItem>,
    pub revisions: BTreeMap<String, Vec<AnchorRevision>>,
}

impl ReviewBook {
    pub fn add(&mut self, item: ReviewItem) -> Result<()> {
        ensure!(!item.review_id.trim().is_empty(), "review id is required");
        ensure!(
            !item.anchor.anchor_id.trim().is_empty(),
            "anchor id is required"
        );
        ensure!(!item.batch_id.trim().is_empty(), "review batch is required");
        ensure!(
            !self.items.contains_key(&item.review_id),
            "review id already exists"
        );
        self.items.insert(item.review_id.clone(), item);
        Ok(())
    }

    pub fn revise_anchor(&mut self, revision: AnchorRevision) -> Result<()> {
        ensure!(
            !revision.anchor_id.trim().is_empty(),
            "anchor id is required"
        );
        ensure!(
            !revision.batch_id.trim().is_empty(),
            "anchor batch is required"
        );
        let item = self
            .items
            .values()
            .find(|item| item.anchor.anchor_id == revision.anchor_id)
            .ok_or_else(|| anyhow!("unknown review anchor"))?;
        ensure!(
            revision.batch_id != item.batch_id
                || revision.path != item.anchor.path
                || revision.symbol != item.anchor.symbol
                || revision.context_digest != item.anchor.context_digest,
            "anchor revision does not change the anchor"
        );
        ensure!(
            !self
                .revisions
                .get(&revision.anchor_id)
                .is_some_and(|revisions| revisions.iter().any(|existing| existing == &revision)),
            "duplicate anchor revision"
        );
        self.revisions
            .entry(revision.anchor_id.clone())
            .or_default()
            .push(revision);
        Ok(())
    }

    pub fn resolve_anchor<I>(
        &self,
        review_id: &str,
        candidates: I,
    ) -> Result<AnchorResolutionReceipt>
    where
        I: IntoIterator<Item = AnchorRevision>,
    {
        let item = self
            .items
            .get(review_id)
            .ok_or_else(|| anyhow!("unknown review item"))?;
        let candidates = candidates
            .into_iter()
            .filter(|candidate| candidate.anchor_id == item.anchor.anchor_id)
            .collect::<Vec<_>>();
        let (resolution, anchor_id) = match candidates.len() {
            1 => (AnchorResolution::Exact, candidates[0].anchor_id.clone()),
            0 => (AnchorResolution::Missing, item.anchor.anchor_id.clone()),
            _ => (AnchorResolution::Ambiguous, item.anchor.anchor_id.clone()),
        };
        // Ambiguous candidates are deliberately reported, never nearest-attached.
        Ok(AnchorResolutionReceipt {
            review_id: review_id.to_owned(),
            anchor_id,
            resolution,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MechanismFailure {
    pub mechanism: String,
    pub failure_digest: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MechanismReview {
    pub mechanism: String,
    pub failures: Vec<MechanismFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureDisposition {
    Recorded,
    MechanismReviewOpened,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MechanismFailureBook {
    pub failures: BTreeMap<String, Vec<MechanismFailure>>,
    pub reviews: BTreeMap<String, MechanismReview>,
}

impl MechanismFailureBook {
    #[allow(clippy::needless_pass_by_value)]
    pub fn record(&mut self, failure: MechanismFailure) -> Result<FailureDisposition> {
        ensure!(
            !failure.mechanism.trim().is_empty(),
            "mechanism is required"
        );
        ensure!(
            !failure.failure_digest.trim().is_empty(),
            "failure digest is required"
        );
        ensure!(
            !failure.evidence.trim().is_empty(),
            "failure evidence is required"
        );
        let mechanism = failure.mechanism.clone();
        let failures = self.failures.entry(mechanism.clone()).or_default();
        ensure!(
            !failures
                .iter()
                .any(|existing| existing.failure_digest == failure.failure_digest),
            "duplicate mechanism failure"
        );
        failures.push(failure.clone());
        if failures.len() >= 2 {
            self.reviews
                .entry(mechanism.clone())
                .or_insert_with(|| MechanismReview {
                    mechanism,
                    failures: failures.clone(),
                });
            return Ok(FailureDisposition::MechanismReviewOpened);
        }
        Ok(FailureDisposition::Recorded)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fence() -> StateFence {
        StateFence::new(
            crate::EpochId {
                lineage: Uuid::nil(),
                sequence: 1,
            },
            1,
            "head",
        )
    }

    #[test]
    fn maps_seal_only_on_completion_or_exact_timeout() {
        let mut maps = IndependentMaps::new(["a", "b"], Some(10)).unwrap();
        maps.submit_first_pass(FirstPassMap {
            worker_id: "a".into(),
            map_digest: "a1".into(),
            fence: fence(),
        })
        .unwrap();
        assert!(maps.seal(9).is_err());
        let receipt = maps.seal(10).unwrap();
        assert_eq!(receipt.reason, MapSealReason::ExactTimeout);
        assert!(
            maps.submit_first_pass(FirstPassMap {
                worker_id: "b".into(),
                map_digest: "b1".into(),
                fence: fence()
            })
            .is_err()
        );
    }

    #[test]
    fn second_same_mechanism_failure_opens_review_and_ambiguity_is_explicit() {
        let mut failures = MechanismFailureBook::default();
        assert_eq!(
            failures
                .record(MechanismFailure {
                    mechanism: "transport".into(),
                    failure_digest: "1".into(),
                    evidence: "e1".into()
                })
                .unwrap(),
            FailureDisposition::Recorded
        );
        assert_eq!(
            failures
                .record(MechanismFailure {
                    mechanism: "transport".into(),
                    failure_digest: "2".into(),
                    evidence: "e2".into()
                })
                .unwrap(),
            FailureDisposition::MechanismReviewOpened
        );
        let mut reviews = ReviewBook::default();
        reviews
            .add(ReviewItem {
                review_id: "r".into(),
                batch_id: "b1".into(),
                anchor: ReviewAnchor {
                    anchor_id: "a".into(),
                    path: "old.rs".into(),
                    symbol: "f".into(),
                    line: 4,
                    context_digest: "ctx".into(),
                },
                summary: "fix".into(),
                open: true,
            })
            .unwrap();
        let result = reviews
            .resolve_anchor(
                "r",
                [
                    AnchorRevision {
                        anchor_id: "a".into(),
                        batch_id: "b2".into(),
                        path: "new.rs".into(),
                        symbol: "f".into(),
                        line: 5,
                        context_digest: "ctx".into(),
                    },
                    AnchorRevision {
                        anchor_id: "a".into(),
                        batch_id: "b3".into(),
                        path: "other.rs".into(),
                        symbol: "f".into(),
                        line: 5,
                        context_digest: "ctx".into(),
                    },
                ],
            )
            .unwrap();
        assert_eq!(result.resolution, AnchorResolution::Ambiguous);
    }
}
