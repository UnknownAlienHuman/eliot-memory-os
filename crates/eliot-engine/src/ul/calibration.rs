use eliot_types::{CalibrationScore, PredictionRecord, PredictionResolution, ProjectId};
use std::collections::BTreeMap;

pub struct CalibrationService;

impl CalibrationService {
    #[must_use]
    pub fn scores(
        project_id: ProjectId,
        predictions: &[PredictionRecord],
    ) -> Vec<CalibrationScore> {
        let mut counts = BTreeMap::<Option<String>, (u32, u32)>::new();
        for prediction in predictions
            .iter()
            .filter(|prediction| prediction.project_id == project_id)
        {
            let entry = counts
                .entry(prediction.subsystem_concept_id.clone())
                .or_default();
            match prediction.resolution {
                Some(PredictionResolution::Hit) => entry.0 = entry.0.saturating_add(1),
                Some(PredictionResolution::Miss) => entry.1 = entry.1.saturating_add(1),
                Some(PredictionResolution::Unresolvable) | None => {}
            }
        }
        counts
            .into_iter()
            .filter_map(|(subsystem_concept_id, (hits, misses))| {
                let resolved_predictions = hits.saturating_add(misses);
                (resolved_predictions > 0).then_some(CalibrationScore {
                    project_id,
                    subsystem_concept_id,
                    resolved_predictions,
                    hits,
                    misses,
                    hit_rate: f64::from(hits) / f64::from(resolved_predictions),
                })
            })
            .collect()
    }
}
