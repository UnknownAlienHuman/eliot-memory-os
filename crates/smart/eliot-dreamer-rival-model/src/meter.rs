//! Shared bounded-operation accounting for the rival-model pipeline.

use crate::error::RivalModelError;
use crate::states::WorkStage;
use crate::unknown::UnknownSlotRef;
use eliot_dreamer_contracts::grounding::ArtifactId;
use std::collections::BTreeSet;

/// Source-width observation retained between the input gate and result packer.
///
/// `upper_bound` is the known owner count plus distinct handles whose owner is
/// unavailable; it is deliberately conservative and does not claim that an
/// unknown handle names an independent source.
#[derive(Clone, Debug)]
pub(crate) struct SourceWidthObservation {
    pub known_owner_count: usize,
    pub unknown_owner_handles: BTreeSet<ArtifactId>,
    pub upper_bound: usize,
}

/// Source-addressable point at which optional rival analysis stopped.
#[derive(Clone, Debug)]
pub(crate) struct WorkFrontier {
    pub stage: WorkStage,
    pub model_id: Option<ArtifactId>,
    /// Current prediction identity when a lookup stopped before a pair.
    pub prediction_id: Option<ArtifactId>,
    pub pair: Option<(ArtifactId, ArtifactId)>,
    /// Prediction identities at a discriminator pair frontier.
    pub prediction_pair: Option<(ArtifactId, ArtifactId)>,
}

/// Borrowed source address carried into discriminator work accounting.
#[derive(Clone, Copy)]
pub(crate) struct WorkAddress<'a> {
    pub model_id: Option<&'a ArtifactId>,
    pub prediction_id: Option<&'a ArtifactId>,
    pub pair: Option<(&'a ArtifactId, &'a ArtifactId)>,
    pub prediction_pair: Option<(&'a ArtifactId, &'a ArtifactId)>,
}

impl<'a> WorkAddress<'a> {
    pub(crate) fn model(model_id: &'a ArtifactId) -> Self {
        Self {
            model_id: Some(model_id),
            prediction_id: None,
            pair: None,
            prediction_pair: None,
        }
    }

    pub(crate) fn prediction(model_id: &'a ArtifactId, prediction_id: &'a ArtifactId) -> Self {
        Self {
            model_id: Some(model_id),
            prediction_id: Some(prediction_id),
            pair: None,
            prediction_pair: None,
        }
    }

    pub(crate) fn pair(
        model_id: &'a ArtifactId,
        prediction_id: &'a ArtifactId,
        peer_model_id: &'a ArtifactId,
        peer_prediction_id: &'a ArtifactId,
    ) -> Self {
        Self {
            model_id: Some(model_id),
            prediction_id: Some(prediction_id),
            pair: Some((model_id, peer_model_id)),
            prediction_pair: Some((prediction_id, peer_prediction_id)),
        }
    }
}

/// One monotonic meter shared by model, dependency, equivalence, and
/// discriminator work. Input/output bytes and caller observations remain
/// separate dimensions.
pub(crate) struct OperationMeter {
    used: u64,
    maximum: u64,
    frontier: Option<WorkFrontier>,
    pub input_wire_bytes: usize,
    pub initial_work: usize,
    pub unknown_count: usize,
    unknowns: Vec<UnknownSlotRef>,
    pub reference_width: usize,
    pub source_width: SourceWidthObservation,
}

pub(crate) enum MeterCharge {
    Charged,
    Exhausted,
}

impl OperationMeter {
    pub(crate) fn new(
        maximum: u64,
        initial_work: usize,
        input_wire_bytes: usize,
        unknowns: Vec<UnknownSlotRef>,
        reference_width: usize,
        source_width: SourceWidthObservation,
    ) -> Result<Self, RivalModelError> {
        let initial = u64::try_from(initial_work).map_err(|_| RivalModelError::Bound {
            field: "analysis.work_units",
            maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
            actual: initial_work,
        })?;
        if initial > maximum {
            return Err(RivalModelError::Bound {
                field: "analysis.work_units",
                maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
                actual: initial_work,
            });
        }
        Ok(Self {
            used: initial,
            maximum,
            frontier: None,
            input_wire_bytes,
            initial_work,
            unknown_count: unknowns.len(),
            unknowns,
            reference_width,
            source_width,
        })
    }

    /// Charges mandatory accounting. Mandatory shells cannot be omitted when
    /// the operation budget is already exhausted.
    pub(crate) fn reserve(
        &mut self,
        amount: usize,
        field: &'static str,
    ) -> Result<(), RivalModelError> {
        let amount = u64::try_from(amount).map_err(|_| RivalModelError::Bound {
            field,
            maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
            actual: amount,
        })?;
        self.used = self
            .used
            .checked_add(amount)
            .ok_or(RivalModelError::Bound {
                field,
                maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
                actual: usize::MAX,
            })?;
        if self.used > self.maximum {
            return Err(RivalModelError::Bound {
                field,
                maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
                actual: usize::try_from(self.used).unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    pub(crate) fn can_reserve(&self, amount: usize) -> bool {
        u64::try_from(amount)
            .ok()
            .and_then(|amount| self.used.checked_add(amount))
            .is_some_and(|next| next <= self.maximum)
    }

    pub(crate) fn charge(
        &mut self,
        amount: usize,
        stage: WorkStage,
        model_id: Option<&ArtifactId>,
        pair: Option<(&ArtifactId, &ArtifactId)>,
    ) -> Result<MeterCharge, RivalModelError> {
        self.charge_addressed(
            amount,
            stage,
            WorkAddress {
                model_id,
                prediction_id: None,
                pair,
                prediction_pair: None,
            },
        )
    }

    pub(crate) fn charge_addressed(
        &mut self,
        amount: usize,
        stage: WorkStage,
        address: WorkAddress<'_>,
    ) -> Result<MeterCharge, RivalModelError> {
        if self.frontier.is_some() {
            return Ok(MeterCharge::Exhausted);
        }
        let amount = u64::try_from(amount).map_err(|_| RivalModelError::Bound {
            field: "analysis.work_units",
            maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
            actual: amount,
        })?;
        let Some(next) = self.used.checked_add(amount) else {
            self.record_addressed_frontier(stage, address);
            return Ok(MeterCharge::Exhausted);
        };
        if next > self.maximum {
            self.record_addressed_frontier(stage, address);
            return Ok(MeterCharge::Exhausted);
        }
        self.used = next;
        Ok(MeterCharge::Charged)
    }

    /// Charges bounded KiB work for materializing a retained body after its
    /// borrowed wire probe has already admitted the clone.
    pub(crate) fn charge_materialization(
        &mut self,
        wire_bytes: usize,
        model_id: Option<&ArtifactId>,
    ) -> Result<MeterCharge, RivalModelError> {
        let kib = wire_bytes
            .checked_add(1023)
            .and_then(|bytes| bytes.checked_div(1024))
            .ok_or(RivalModelError::Bound {
                field: "result.materialization_work",
                maximum: usize::MAX,
                actual: wire_bytes,
            })?
            .max(1);
        self.charge(kib, WorkStage::ResultPacking, model_id, None)
    }

    fn record_addressed_frontier(&mut self, stage: WorkStage, address: WorkAddress<'_>) {
        self.frontier = Some(WorkFrontier {
            stage,
            model_id: address.model_id.cloned(),
            prediction_id: address.prediction_id.cloned(),
            pair: address
                .pair
                .map(|(left, right)| (left.clone(), right.clone())),
            prediction_pair: address
                .prediction_pair
                .map(|(left, right)| (left.clone(), right.clone())),
        });
    }

    pub(crate) fn charge_discriminator(
        &mut self,
        amount: usize,
        stage: WorkStage,
        expected_model: &ArtifactId,
        expected_prediction: &ArtifactId,
        falsifying: Option<(&ArtifactId, &ArtifactId)>,
    ) -> Result<MeterCharge, RivalModelError> {
        self.charge_addressed(
            amount,
            stage,
            WorkAddress {
                model_id: Some(expected_model),
                prediction_id: Some(expected_prediction),
                pair: falsifying.map(|(model, _)| (expected_model, model)),
                prediction_pair: falsifying
                    .map(|(_, prediction)| (expected_prediction, prediction)),
            },
        )
    }

    pub(crate) fn mark_addressed_frontier(&mut self, stage: WorkStage, address: WorkAddress<'_>) {
        if self.frontier.is_none() {
            self.record_addressed_frontier(stage, address);
        }
    }

    pub(crate) fn mark_discriminator_frontier(
        &mut self,
        expected_model: &ArtifactId,
        expected_prediction: &ArtifactId,
        falsifying_model: &ArtifactId,
        falsifying_prediction: &ArtifactId,
    ) {
        self.mark_addressed_frontier(
            WorkStage::DiscriminatorLimit,
            WorkAddress {
                model_id: Some(expected_model),
                prediction_id: Some(expected_prediction),
                pair: Some((expected_model, falsifying_model)),
                prediction_pair: Some((expected_prediction, falsifying_prediction)),
            },
        );
    }

    pub(crate) fn mark_packing_frontier(&mut self, model_id: &ArtifactId) {
        if self.frontier.is_none() {
            self.frontier = Some(WorkFrontier {
                stage: WorkStage::ResultPacking,
                model_id: Some(model_id.clone()),
                prediction_id: None,
                pair: None,
                prediction_pair: None,
            });
        }
    }

    pub(crate) fn frontier(&self) -> Option<&WorkFrontier> {
        self.frontier.as_ref()
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.frontier.is_some()
    }

    pub(crate) fn observation(&self) -> (usize, usize, usize, usize, usize, usize) {
        (
            self.input_wire_bytes,
            self.initial_work,
            self.unknown_count,
            self.reference_width,
            self.source_width.known_owner_count,
            self.source_width.unknown_owner_handles.len(),
        )
    }

    pub(crate) fn unknowns(&self) -> &[UnknownSlotRef] {
        &self.unknowns
    }
}
