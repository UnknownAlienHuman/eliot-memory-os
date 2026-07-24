use super::capsule_freshness;
use eliot_types::{
    CapsuleFreshness, ConceptNode, CoverageClass, CueKind, CueRecordSource, DangerPath,
    HotspotScore, ModuleCard, SubsystemCapsule, SubsystemCoverage, UlMetacognitionView,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct MetacognitionService;

impl MetacognitionService {
    #[must_use]
    pub fn evaluate(
        project_root: &Path,
        concepts: &[ConceptNode],
        capsules: &[SubsystemCapsule],
        cards: &[ModuleCard],
        hotspots: &[HotspotScore],
        cue_sources: &[CueRecordSource],
        touched_paths: &[String],
    ) -> UlMetacognitionView {
        let capsules = capsules
            .iter()
            .map(|capsule| (capsule.concept_id.as_str(), capsule))
            .collect::<BTreeMap<_, _>>();
        let mut coverage = Vec::new();
        for concept in concepts {
            let sources = cue_sources
                .iter()
                .filter(|source| source_matches_concept(source, concept))
                .collect::<Vec<_>>();
            let claim_count = count_kind(&sources, &["claim", "claim_card"]);
            let decision_count = count_kind(&sources, &["decision"]);
            let failure_count = u32::try_from(
                sources
                    .iter()
                    .filter(|source| {
                        source.negative_memory || source.record_kind == "failure_fingerprint"
                    })
                    .map(|source| source.record_ref.as_str())
                    .collect::<BTreeSet<_>>()
                    .len(),
            )
            .unwrap_or(u32::MAX);
            let module_card_count = u32::try_from(
                cards
                    .iter()
                    .filter(|card| {
                        concept
                            .boundary_paths
                            .iter()
                            .any(|boundary| path_matches_boundary(&card.path, boundary))
                    })
                    .count(),
            )
            .unwrap_or(u32::MAX);
            let capsule = capsules.get(concept.concept_id.as_str()).copied();
            let capsule_fresh = capsule.is_some_and(|capsule| {
                capsule_freshness(capsule, project_root) == CapsuleFreshness::Fresh
            });
            let knowledge_count = claim_count
                .saturating_add(decision_count)
                .saturating_add(failure_count);
            let class = if capsule.is_none() {
                CoverageClass::Blind
            } else if capsule_fresh && module_card_count >= 1 && knowledge_count >= 3 {
                CoverageClass::Covered
            } else {
                CoverageClass::Thin
            };
            coverage.push(SubsystemCoverage {
                concept_id: concept.concept_id.clone(),
                capsule_ref: capsule.map(|capsule| format!("capsule:{}", capsule.capsule_id)),
                capsule_fresh,
                module_card_count,
                claim_count,
                decision_count,
                failure_count,
                coverage: class,
            });
        }
        coverage.sort_by(|left, right| left.concept_id.cmp(&right.concept_id));

        let mut touched = touched_paths.to_vec();
        touched.sort();
        touched.dedup();
        let novel_paths = touched
            .iter()
            .filter(|path| concept_for_path(concepts, path).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let novelty_percent = if touched.is_empty() {
            0
        } else {
            u8::try_from((novel_paths.len() * 100) / touched.len()).unwrap_or(100)
        };
        let danger_paths = danger_paths(hotspots, cue_sources);
        UlMetacognitionView {
            coverage,
            novelty_percent,
            novel_paths,
            danger_paths,
        }
    }

    #[must_use]
    pub fn concept_for_paths(concepts: &[ConceptNode], paths: &[String]) -> Option<String> {
        paths
            .iter()
            .filter_map(|path| concept_for_path(concepts, path))
            .max_by_key(|concept| {
                concept
                    .boundary_paths
                    .iter()
                    .filter(|boundary| {
                        paths
                            .iter()
                            .any(|path| path_matches_boundary(path, boundary))
                    })
                    .map(String::len)
                    .max()
                    .unwrap_or_default()
            })
            .map(|concept| concept.concept_id.clone())
    }

    #[must_use]
    pub fn coverage_for_paths(
        concepts: &[ConceptNode],
        view: &UlMetacognitionView,
        paths: &[String],
    ) -> (CoverageClass, Option<String>) {
        if let Some(path) = paths
            .iter()
            .find(|path| concept_for_path(concepts, path).is_none())
        {
            return (CoverageClass::Blind, Some(path.clone()));
        }
        let relevant = concepts
            .iter()
            .filter(|concept| {
                paths.iter().any(|path| {
                    concept
                        .boundary_paths
                        .iter()
                        .any(|boundary| path_matches_boundary(path, boundary))
                })
            })
            .filter_map(|concept| {
                view.coverage
                    .iter()
                    .find(|coverage| coverage.concept_id == concept.concept_id)
            })
            .collect::<Vec<_>>();
        if let Some(blind) = relevant
            .iter()
            .find(|coverage| coverage.coverage == CoverageClass::Blind)
        {
            return (CoverageClass::Blind, Some(blind.concept_id.clone()));
        }
        if let Some(thin) = relevant
            .iter()
            .find(|coverage| coverage.coverage == CoverageClass::Thin)
        {
            return (CoverageClass::Thin, Some(thin.concept_id.clone()));
        }
        if relevant.is_empty() {
            (CoverageClass::Blind, paths.first().cloned())
        } else {
            (CoverageClass::Covered, None)
        }
    }

    #[must_use]
    pub fn recommended_probe(cards: &[ModuleCard], paths: &[String]) -> Option<String> {
        let mut probes = cards
            .iter()
            .filter(|card| {
                paths
                    .iter()
                    .any(|path| path_matches_boundary(path, &card.path))
            })
            .map(|card| card.verifier.clone())
            .filter(|verifier| !verifier.trim().is_empty())
            .collect::<Vec<_>>();
        probes.sort();
        probes.dedup();
        probes.into_iter().next()
    }
}

fn count_kind(sources: &[&CueRecordSource], kinds: &[&str]) -> u32 {
    u32::try_from(
        sources
            .iter()
            .filter(|source| kinds.contains(&source.record_kind.as_str()))
            .map(|source| source.record_ref.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u32::MAX)
}

fn source_matches_concept(source: &CueRecordSource, concept: &ConceptNode) -> bool {
    source.cue_bindings.iter().any(|binding| {
        matches!(binding.cue_kind, CueKind::FilePath | CueKind::DirPath)
            && concept
                .boundary_paths
                .iter()
                .any(|boundary| path_matches_boundary(&binding.cue_value, boundary))
    })
}

fn danger_paths(hotspots: &[HotspotScore], cue_sources: &[CueRecordSource]) -> Vec<DangerPath> {
    let mut failures = BTreeMap::<String, BTreeSet<String>>::new();
    for source in cue_sources
        .iter()
        .filter(|source| source.negative_memory || source.record_kind == "failure_fingerprint")
    {
        for binding in &source.cue_bindings {
            if matches!(binding.cue_kind, CueKind::FilePath | CueKind::DirPath) {
                failures
                    .entry(binding.cue_value.clone())
                    .or_default()
                    .insert(source.record_ref.clone());
            }
        }
    }
    let mut scores = hotspots
        .iter()
        .map(|hotspot| (hotspot.path.clone(), hotspot.score))
        .collect::<BTreeMap<_, _>>();
    for path in failures.keys() {
        scores.entry(path.clone()).or_insert(0);
    }
    scores
        .into_iter()
        .filter_map(|(path, score)| {
            let failure_refs = failures
                .remove(&path)
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            (score >= 70 || failure_refs.len() >= 2).then_some(DangerPath {
                path,
                score,
                failure_refs,
            })
        })
        .collect()
}

fn concept_for_path<'a>(concepts: &'a [ConceptNode], path: &str) -> Option<&'a ConceptNode> {
    concepts
        .iter()
        .filter(|concept| {
            concept
                .boundary_paths
                .iter()
                .any(|boundary| path_matches_boundary(path, boundary))
        })
        .max_by_key(|concept| {
            concept
                .boundary_paths
                .iter()
                .filter(|boundary| path_matches_boundary(path, boundary))
                .map(String::len)
                .max()
                .unwrap_or_default()
        })
}

fn path_matches_boundary(path: &str, boundary: &str) -> bool {
    let path = path.replace('\\', "/");
    let boundary = boundary.replace('\\', "/");
    path == boundary
        || path
            .strip_prefix(boundary.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}
