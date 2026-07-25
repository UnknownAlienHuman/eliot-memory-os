use super::blast_fraction_milli;
use eliot_types::{
    CalibrationScore, CalibrationTrend, PredictionConfidence, PredictionRecord,
    PredictionResolution, ProjectId,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct CalibrationAccumulator {
    hits: u32,
    misses: u32,
    unresolvable: u32,
    unresolved: u32,
    brier_sum: u64,
    brier_count: u32,
    path_precision_num: u32,
    path_precision_den: u32,
    path_recall_num: u32,
    path_recall_den: u32,
    verifier_precision_num: u32,
    verifier_precision_den: u32,
    verifier_recall_num: u32,
    verifier_recall_den: u32,
}

pub struct CalibrationService;

impl CalibrationService {
    #[must_use]
    pub fn scores(
        project_id: ProjectId,
        predictions: &[PredictionRecord],
    ) -> Vec<CalibrationScore> {
        Self::scores_with_weekly_hit_rate(project_id, predictions, &BTreeMap::new())
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn scores_with_weekly_hit_rate(
        project_id: ProjectId,
        predictions: &[PredictionRecord],
        weekly_hit_rate: &BTreeMap<Option<String>, Vec<u16>>,
    ) -> Vec<CalibrationScore> {
        let mut groups = BTreeMap::<Option<String>, CalibrationAccumulator>::new();
        for prediction in predictions
            .iter()
            .filter(|prediction| prediction.project_id == project_id)
        {
            let entry = groups
                .entry(prediction.subsystem_concept_id.clone())
                .or_default();
            match prediction.resolution {
                Some(PredictionResolution::Hit) => entry.hits = entry.hits.saturating_add(1),
                Some(PredictionResolution::Miss) => entry.misses = entry.misses.saturating_add(1),
                Some(PredictionResolution::Unresolvable) => {
                    entry.unresolvable = entry.unresolvable.saturating_add(1);
                }
                None => entry.unresolved = entry.unresolved.saturating_add(1),
            }
            if let (Some(confidence), Some(resolution)) =
                (prediction.confidence, prediction.resolution)
                && matches!(
                    resolution,
                    PredictionResolution::Hit | PredictionResolution::Miss
                )
            {
                let probability = confidence_probability_milli(confidence);
                let outcome = if resolution == PredictionResolution::Hit {
                    1_000_i32
                } else {
                    0
                };
                let delta = i32::from(probability) - outcome;
                entry.brier_sum = entry
                    .brier_sum
                    .saturating_add(u64::try_from(delta * delta).unwrap_or_default() / 1_000);
                entry.brier_count = entry.brier_count.saturating_add(1);
            }
            if let Some(score) = &prediction.blast_score {
                entry.path_precision_num = entry
                    .path_precision_num
                    .saturating_add(score.path_precision_num);
                entry.path_precision_den = entry
                    .path_precision_den
                    .saturating_add(score.path_precision_den);
                entry.path_recall_num = entry.path_recall_num.saturating_add(score.path_recall_num);
                entry.path_recall_den = entry.path_recall_den.saturating_add(score.path_recall_den);
                entry.verifier_precision_num = entry
                    .verifier_precision_num
                    .saturating_add(score.verifier_precision_num);
                entry.verifier_precision_den = entry
                    .verifier_precision_den
                    .saturating_add(score.verifier_precision_den);
                entry.verifier_recall_num = entry
                    .verifier_recall_num
                    .saturating_add(score.verifier_recall_num);
                entry.verifier_recall_den = entry
                    .verifier_recall_den
                    .saturating_add(score.verifier_recall_den);
            }
        }
        groups
            .into_iter()
            .map(|(subsystem_concept_id, entry)| {
                let resolved_predictions = entry.hits.saturating_add(entry.misses);
                CalibrationScore {
                    project_id,
                    trend: weekly_hit_rate
                        .get(&subsystem_concept_id)
                        .map_or(CalibrationTrend::InsufficientData, |windows| {
                            calibration_trend(windows)
                        }),
                    subsystem_concept_id,
                    resolved_predictions,
                    hits: entry.hits,
                    misses: entry.misses,
                    hit_rate: if resolved_predictions == 0 {
                        0.0
                    } else {
                        f64::from(entry.hits) / f64::from(resolved_predictions)
                    },
                    unresolvable: entry.unresolvable,
                    unresolved: entry.unresolved,
                    brier_milli: (entry.brier_count > 0).then(|| {
                        u32::try_from(entry.brier_sum / u64::from(entry.brier_count))
                            .unwrap_or(1_000)
                    }),
                    blast_path_precision_milli: fraction_option(
                        entry.path_precision_num,
                        entry.path_precision_den,
                    ),
                    blast_path_recall_milli: fraction_option(
                        entry.path_recall_num,
                        entry.path_recall_den,
                    ),
                    blast_verifier_precision_milli: fraction_option(
                        entry.verifier_precision_num,
                        entry.verifier_precision_den,
                    ),
                    blast_verifier_recall_milli: fraction_option(
                        entry.verifier_recall_num,
                        entry.verifier_recall_den,
                    ),
                }
            })
            .collect()
    }
}

#[must_use]
pub const fn confidence_probability_milli(confidence: PredictionConfidence) -> u16 {
    match confidence {
        PredictionConfidence::Low => 600,
        PredictionConfidence::Medium => 800,
        PredictionConfidence::High => 950,
    }
}

#[must_use]
pub fn calibration_trend(completed_weekly_hit_rate: &[u16]) -> CalibrationTrend {
    let windows = completed_weekly_hit_rate
        .iter()
        .rev()
        .take(3)
        .copied()
        .collect::<Vec<_>>();
    if windows.len() < 3 {
        return CalibrationTrend::InsufficientData;
    }
    let (newest, middle, oldest) = (windows[0], windows[1], windows[2]);
    if oldest < middle && middle < newest {
        CalibrationTrend::Improving
    } else if oldest > middle && middle > newest {
        CalibrationTrend::Degrading
    } else {
        CalibrationTrend::Flat
    }
}

fn fraction_option(numerator: u32, denominator: u32) -> Option<u32> {
    (numerator > 0 || denominator > 0).then(|| blast_fraction_milli(numerator, denominator))
}
