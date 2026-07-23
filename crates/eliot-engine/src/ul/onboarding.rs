use super::capsule::{
    CapsuleEvidence, PyramidBuilder, PyramidDecision, PyramidDependency, PyramidFailure,
};
use super::{
    CueIndexService, GitMiningArtifacts, GitMiningService, ModuleCardService,
    UlArtifactWriterService, failure_bindings_by_path,
};
use crate::codecortex::run_process;
use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_store::CanonicalStore;
use eliot_types::{
    CoChangeEdge, ConceptKind, ConceptNode, CueBinding, CueKind, CueMatchMode, CueRecordSource,
    CueStrength, HotspotScore, ManifestPackage, MiningRun, ModuleCard, OnboardingCheckpoint,
    OnboardingReport, OnboardingStage, OnboardingTestHook, ProjectId, UlArtifact,
    normalize_bindings,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_CONCEPTS: usize = 20;
const PURPOSE_LIMIT_BYTES: usize = 240;
const EXPECTED_REUSE_NOTE: &str = "when working in this subsystem or its boundary paths";
const ARTIFACT_READ_LIMIT: u16 = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConceptSeedResult {
    pub concepts: Vec<ConceptNode>,
    pub assignments: BTreeMap<String, String>,
    pub concept_dependencies: Vec<(String, String)>,
    pub unassigned_files: Vec<String>,
}

pub struct OnboardingService {
    store: CanonicalStore,
    writer: WriterHandle,
    cue_index: CueIndexService,
    pyramid: PyramidBuilder,
}

impl OnboardingService {
    #[must_use]
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        Self {
            cue_index: CueIndexService::new(store.clone()),
            store,
            writer,
            pyramid: PyramidBuilder,
        }
    }

    pub fn discover_manifests(root: &Path) -> Result<Vec<ManifestPackage>, EngineError> {
        if !root.join("Cargo.toml").is_file() {
            return Ok(Vec::new());
        }
        let output = run_process(
            root,
            "cargo",
            &["metadata", "--format-version", "1", "--no-deps"],
        )?;
        if !output.status {
            return Err(EngineError::ServiceNotReady {
                service: "cargo metadata".to_owned(),
                reason: process_failure(&output),
            });
        }
        let value: Value = serde_json::from_str(&output.stdout)?;
        let root = root.canonicalize()?;
        let source_files = discover_source_files(&root)?;
        let mut manifests = value
            .get("packages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|package| {
                let name = package.get("name")?.as_str()?.to_owned();
                let manifest_path =
                    relative_path(&root, Path::new(package.get("manifest_path")?.as_str()?))?;
                let boundary_path = Path::new(&manifest_path)
                    .parent()
                    .map(normalized_path)
                    .filter(|path| !path.is_empty())
                    .unwrap_or_else(|| ".".to_owned());
                let mut package_sources = source_files
                    .iter()
                    .filter(|path| path_matches_boundary(path, &boundary_path))
                    .cloned()
                    .collect::<Vec<_>>();
                package_sources.sort();
                Some(ManifestPackage {
                    name,
                    description: package
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    manifest_path,
                    boundary_path,
                    source_files: package_sources,
                })
            })
            .collect::<Vec<_>>();
        manifests.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
        Ok(manifests)
    }

    #[allow(clippy::too_many_lines)]
    pub fn seed_concepts(
        root: &Path,
        mining: &GitMiningArtifacts,
        manifests: &[ManifestPackage],
    ) -> Result<ConceptSeedResult, EngineError> {
        let all_files = discover_source_files(root)?;
        let mut candidates = manifest_candidates(root, manifests);
        candidates.extend(top_level_candidates(&all_files));
        candidates.extend(cochange_candidates(&all_files, &mining.edges));
        merge_overlapping_candidates(&mut candidates);
        cap_candidates(&mut candidates, MAX_CONCEPTS.saturating_sub(1));
        candidates.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.seed_id.cmp(&right.seed_id))
        });

        let mut assignments = BTreeMap::new();
        let mut unassigned_files = Vec::new();
        for file in &all_files {
            let selected = candidates
                .iter()
                .filter(|candidate| candidate.files.contains(file))
                .max_by(|left, right| compare_candidate_for_file(file, left, right));
            if let Some(candidate) = selected {
                assignments.insert(file.clone(), candidate.seed_id.clone());
            } else {
                unassigned_files.push(file.clone());
            }
        }

        if !unassigned_files.is_empty() {
            let seed_id = candidate_id("_unassigned", &unassigned_files);
            let boundaries = unassigned_boundaries(&unassigned_files);
            candidates.push(Candidate {
                seed_id: seed_id.clone(),
                name: "_unassigned".to_owned(),
                priority: 3,
                boundaries,
                files: unassigned_files.iter().cloned().collect(),
                description: None,
                description_ref: None,
            });
            for file in &unassigned_files {
                assignments.insert(file.clone(), seed_id.clone());
            }
        }

        let hotspot_by_path = mining
            .hotspots
            .iter()
            .map(|hotspot| (hotspot.path.as_str(), hotspot))
            .collect::<HashMap<_, _>>();
        let mut concepts = Vec::new();
        let mut seed_to_concept = BTreeMap::new();
        for candidate in candidates {
            let assigned = assignments
                .iter()
                .filter(|(_, seed)| *seed == &candidate.seed_id)
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            if assigned.is_empty() {
                continue;
            }
            let (purpose, purpose_ref) = purpose_for_candidate(root, &candidate)?;
            let concept_id = deterministic_id(
                "concept",
                &[
                    &mining.run.project_id.to_string(),
                    &candidate.name,
                    &assigned.join("\0"),
                ],
            );
            let mut hotspots = assigned
                .iter()
                .filter_map(|path| hotspot_by_path.get(path.as_str()).copied())
                .collect::<Vec<_>>();
            hotspots.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| left.path.cmp(&right.path))
            });
            let hotspot_refs = hotspots
                .iter()
                .take(3)
                .map(|hotspot| hotspot.hotspot_id.clone())
                .collect::<Vec<_>>();
            let entrypoint_refs = entrypoints(&assigned);
            let cue_bindings = concept_cues(
                &candidate.name,
                &candidate.boundaries,
                hotspots.iter().take(3).map(|hotspot| hotspot.path.as_str()),
            )?;
            let source_refs = purpose_ref.into_iter().collect::<Vec<_>>();
            seed_to_concept.insert(candidate.seed_id, concept_id.clone());
            concepts.push(ConceptNode {
                concept_id,
                project_id: mining.run.project_id,
                name: candidate.name,
                kind: ConceptKind::Subsystem,
                purpose,
                boundary_paths: candidate.boundaries,
                invariant_refs: Vec::new(),
                hotspot_refs,
                entrypoint_refs,
                parent_concept_id: None,
                cue_bindings,
                source_refs,
            });
        }
        for assignment in assignments.values_mut() {
            if let Some(concept_id) = seed_to_concept.get(assignment) {
                *assignment = concept_id.clone();
            }
        }
        concepts.sort_by(|left, right| left.concept_id.cmp(&right.concept_id));
        let concept_dependencies = concept_dependencies(&assignments, &mining.edges);
        Ok(ConceptSeedResult {
            concepts,
            assignments,
            concept_dependencies,
            unassigned_files,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub async fn run(
        &self,
        project_id: ProjectId,
        project_root: &Path,
        runtime_root: &Path,
        hook: OnboardingTestHook,
    ) -> Result<OnboardingReport, EngineError> {
        let project_root = validate_project_root(project_root)?;
        self.store.migrate_schema().await?;
        let head_commit = git_head(&project_root)?;
        validate_git_state(&project_root)?;
        let cue_sources = self.store.load_cue_records(project_id).await?;
        let mining = self
            .ensure_mining(project_id, &project_root, &head_commit, &cue_sources)
            .await?;
        let manifests = Self::discover_manifests(&project_root)?;
        let cards = self
            .ensure_module_cards(&project_root, &mining, &cue_sources)
            .await?;
        let mut seed = Self::seed_concepts(&project_root, &mining, &manifests)?;
        bind_invariants(&mut seed.concepts, &seed.assignments, &cue_sources);

        let inputs_hash = onboarding_inputs_hash(
            project_id,
            &project_root,
            &head_commit,
            &mining,
            &manifests,
            &cards,
        )?;
        let checkpoint_path = checkpoint_path(runtime_root, project_id);
        let mut checkpoint = load_checkpoint(&checkpoint_path)?
            .filter(|checkpoint| checkpoint.inputs_hash == inputs_hash)
            .unwrap_or(OnboardingCheckpoint {
                project_id,
                stage: OnboardingStage::Validated,
                inputs_hash: inputs_hash.clone(),
                completed_artifact_refs: Vec::new(),
            });

        if !stage_is_canonical(
            &self.store,
            project_id,
            "concept_node",
            seed.concepts
                .iter()
                .map(|concept| concept.concept_id.as_str()),
            checkpoint.stage >= OnboardingStage::Concepts,
        )
        .await?
        {
            UlArtifactWriterService
                .write_concepts(
                    &self.writer,
                    &WriteAdmissionService,
                    &mining.run.run_id,
                    &seed.concepts,
                    &seed.concept_dependencies,
                )
                .await?;
            for concept in &seed.concepts {
                self.cue_index
                    .replace_record_bindings(
                        project_id,
                        &format!("concept:{}", concept.concept_id),
                        "concept_node",
                        &concept.purpose,
                        &concept.cue_bindings,
                        false,
                    )
                    .await?;
            }
            checkpoint.completed_artifact_refs.extend(
                seed.concepts
                    .iter()
                    .map(|concept| format!("concept:{}", concept.concept_id)),
            );
        }
        checkpoint.stage = OnboardingStage::Concepts;
        normalize_checkpoint(&mut checkpoint);
        save_checkpoint(&checkpoint_path, &checkpoint)?;
        if hook == OnboardingTestHook::InterruptAfterConcepts {
            return Err(EngineError::ServiceNotReady {
                service: "ul onboarding test hook".to_owned(),
                reason: "interrupted after concepts".to_owned(),
            });
        }

        let evidence =
            onboarding_evidence(&seed, &mining, &cards, &cue_sources, &self.store).await?;
        let mut capsules = Vec::new();
        let mut rejected_builds = Vec::new();
        for concept in &seed.concepts {
            let capsule_evidence = evidence
                .get(&concept.concept_id)
                .cloned()
                .unwrap_or_default();
            match self
                .pyramid
                .build_capsule(&project_root, concept, &capsule_evidence, None)
            {
                Ok(promoted) => {
                    self.ensure_pyramid_target(
                        project_id,
                        &mining.run.run_id,
                        UlArtifact::SubsystemCapsule(promoted.artifact.clone()),
                        promoted.build,
                    )
                    .await?;
                    self.cue_index
                        .replace_record_bindings(
                            project_id,
                            &format!("capsule:{}", promoted.artifact.capsule_id),
                            "subsystem_capsule",
                            &promoted.artifact.body_md,
                            &promoted.artifact.cue_bindings,
                            false,
                        )
                        .await?;
                    checkpoint
                        .completed_artifact_refs
                        .push(format!("capsule:{}", promoted.artifact.capsule_id));
                    capsules.push(promoted.artifact);
                }
                Err(error) => rejected_builds.push(format!("{}: {error}", concept.concept_id)),
            }
        }
        checkpoint.stage = OnboardingStage::Capsules;
        normalize_checkpoint(&mut checkpoint);
        save_checkpoint(&checkpoint_path, &checkpoint)?;

        let promoted_map = self.pyramid.build_system_map(
            project_id,
            &project_root,
            &seed.concepts,
            &mining.edges,
            None,
        )?;
        self.ensure_pyramid_target(
            project_id,
            &mining.run.run_id,
            UlArtifact::SystemMap(promoted_map.artifact.clone()),
            promoted_map.build,
        )
        .await?;
        self.cue_index
            .replace_record_bindings(
                project_id,
                &format!("system-map:{}", promoted_map.artifact.map_id),
                "system_map",
                &promoted_map.artifact.body_md,
                &promoted_map.artifact.cue_bindings,
                false,
            )
            .await?;
        checkpoint.stage = OnboardingStage::SystemMap;
        checkpoint
            .completed_artifact_refs
            .push(format!("system-map:{}", promoted_map.artifact.map_id));
        normalize_checkpoint(&mut checkpoint);
        save_checkpoint(&checkpoint_path, &checkpoint)?;

        let invariant_refs = seed
            .concepts
            .iter()
            .flat_map(|concept| concept.invariant_refs.iter().cloned())
            .collect::<Vec<_>>();
        let promoted_charter = self.pyramid.build_charter(
            project_id,
            &project_root,
            &seed.concepts,
            &invariant_refs,
            None,
        )?;
        self.ensure_pyramid_target(
            project_id,
            &mining.run.run_id,
            UlArtifact::ProjectCharter(promoted_charter.artifact.clone()),
            promoted_charter.build,
        )
        .await?;
        self.cue_index
            .replace_record_bindings(
                project_id,
                &format!("charter:{}", promoted_charter.artifact.charter_id),
                "project_charter",
                &promoted_charter.artifact.body_md,
                &promoted_charter.artifact.cue_bindings,
                false,
            )
            .await?;
        checkpoint.stage = OnboardingStage::Complete;
        checkpoint
            .completed_artifact_refs
            .push(format!("charter:{}", promoted_charter.artifact.charter_id));
        normalize_checkpoint(&mut checkpoint);
        save_checkpoint(&checkpoint_path, &checkpoint)?;

        let report = OnboardingReport {
            project_id,
            head_commit,
            concept_count: seed.concepts.len(),
            capsule_count: capsules.len(),
            module_card_count: cards.len(),
            charter_ref: format!("charter:{}", promoted_charter.artifact.charter_id),
            map_ref: format!("system-map:{}", promoted_map.artifact.map_id),
            unassigned_files: seed.unassigned_files,
            rejected_builds,
            reasoning_job_calls: 0,
        };
        save_report(runtime_root, &report)?;
        Ok(report)
    }

    async fn ensure_mining(
        &self,
        project_id: ProjectId,
        root: &Path,
        head_commit: &str,
        cue_sources: &[CueRecordSource],
    ) -> Result<GitMiningArtifacts, EngineError> {
        let service = GitMiningService::default();
        let config_hash = service.config_hash()?;
        let runs = self
            .store
            .load_ul_artifacts::<MiningRun>(project_id, &["mining_run"], ARTIFACT_READ_LIMIT)
            .await?;
        let current = runs
            .into_iter()
            .find(|record| {
                record.receipt_body.head_commit == head_commit
                    && record.receipt_body.config_hash == config_hash
            })
            .map(|record| record.receipt_body);
        if let Some(run) = current {
            let edges = self
                .store
                .load_ul_artifacts::<CoChangeEdge>(
                    project_id,
                    &["co_change_edge"],
                    ARTIFACT_READ_LIMIT,
                )
                .await?
                .into_iter()
                .map(|record| record.receipt_body)
                .filter(|edge| edge.mining_run_ref == run.run_id)
                .collect();
            let hotspots = self
                .store
                .load_ul_artifacts::<HotspotScore>(
                    project_id,
                    &["hotspot_score"],
                    ARTIFACT_READ_LIMIT,
                )
                .await?
                .into_iter()
                .map(|record| record.receipt_body)
                .filter(|hotspot| hotspot.mining_run_ref == run.run_id)
                .collect();
            return Ok(GitMiningArtifacts {
                run,
                edges,
                hotspots,
            });
        }
        let failure_density = failure_bindings_by_path(cue_sources)
            .into_iter()
            .map(|(path, refs)| (path, u32::try_from(refs.len()).unwrap_or(u32::MAX)))
            .collect();
        let mining = service.mine(project_id, root, &failure_density)?;
        UlArtifactWriterService
            .write_mining(&self.writer, &WriteAdmissionService, &mining)
            .await?;
        Ok(mining)
    }

    async fn ensure_module_cards(
        &self,
        root: &Path,
        mining: &GitMiningArtifacts,
        cue_sources: &[CueRecordSource],
    ) -> Result<Vec<ModuleCard>, EngineError> {
        let failure_refs = failure_bindings_by_path(cue_sources);
        let cards = ModuleCardService::build(
            mining.run.project_id,
            root,
            &mining.hotspots,
            &mining.edges,
            &failure_refs,
            &BTreeMap::new(),
        )?;
        if !cards.is_empty() {
            UlArtifactWriterService
                .write_module_cards(
                    &self.writer,
                    &WriteAdmissionService,
                    &mining.run.run_id,
                    &cards,
                )
                .await?;
            for card in &cards {
                self.cue_index
                    .replace_record_bindings(
                        mining.run.project_id,
                        &format!("card:{}", card.card_id),
                        "module_card",
                        &card.body_md,
                        &card.cue_bindings,
                        false,
                    )
                    .await?;
            }
        }
        Ok(cards)
    }

    async fn ensure_pyramid_target(
        &self,
        project_id: ProjectId,
        run_id: &str,
        target: UlArtifact,
        build: eliot_types::CapsuleBuild,
    ) -> Result<(), EngineError> {
        if self
            .store
            .ul_artifact_by_id::<Value>(project_id, target.receipt_kind(), target.artifact_id())
            .await?
            .is_none()
        {
            UlArtifactWriterService
                .write_pyramid_target(&self.writer, &WriteAdmissionService, run_id, target, build)
                .await?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Candidate {
    seed_id: String,
    name: String,
    priority: u8,
    boundaries: Vec<String>,
    files: BTreeSet<String>,
    description: Option<String>,
    description_ref: Option<String>,
}

fn manifest_candidates(root: &Path, manifests: &[ManifestPackage]) -> Vec<Candidate> {
    manifests
        .iter()
        .map(|manifest| {
            let files = manifest
                .source_files
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            Candidate {
                seed_id: candidate_id(&manifest.name, &manifest.source_files),
                name: manifest.name.clone(),
                priority: 0,
                boundaries: vec![manifest.boundary_path.clone()],
                files,
                description: manifest.description.clone(),
                description_ref: manifest.description.as_ref().map(|_| {
                    let line = line_containing(&root.join(&manifest.manifest_path), "description")
                        .unwrap_or(1);
                    format!("file:{}#L{line}-L{line}", manifest.manifest_path)
                }),
            }
        })
        .collect()
}

fn top_level_candidates(files: &[String]) -> Vec<Candidate> {
    let mut groups = BTreeMap::<String, Vec<String>>::new();
    for file in files {
        let boundary = file.split('/').next().unwrap_or(file);
        if !boundary.is_empty() {
            groups
                .entry(boundary.to_owned())
                .or_default()
                .push(file.clone());
        }
    }
    groups
        .into_iter()
        .filter(|(_, files)| files.len() >= 3)
        .map(|(boundary, files)| Candidate {
            seed_id: candidate_id(&boundary, &files),
            name: normalized_name(&boundary),
            priority: 1,
            boundaries: vec![boundary],
            files: files.into_iter().collect(),
            description: None,
            description_ref: None,
        })
        .collect()
}

fn cochange_candidates(files: &[String], edges: &[CoChangeEdge]) -> Vec<Candidate> {
    let known = files.iter().cloned().collect::<HashSet<_>>();
    let mut parents = BTreeMap::<String, String>::new();
    for edge in edges.iter().filter(|edge| {
        edge.confidence_ab.max(edge.confidence_ba) >= 0.7
            && known.contains(&edge.path_a)
            && known.contains(&edge.path_b)
    }) {
        union(&mut parents, &edge.path_a, &edge.path_b);
    }
    let keys = parents.keys().cloned().collect::<Vec<_>>();
    let mut components = BTreeMap::<String, Vec<String>>::new();
    for key in keys {
        let root = find(&mut parents, &key);
        components.entry(root).or_default().push(key);
    }
    components
        .into_values()
        .filter(|component| component.len() >= 3)
        .map(|mut component| {
            component.sort();
            let seed = candidate_id("cluster", &component);
            Candidate {
                seed_id: seed.clone(),
                name: format!("cluster_{}", &seed[seed.len().saturating_sub(8)..]),
                priority: 2,
                boundaries: common_boundaries(&component),
                files: component.into_iter().collect(),
                description: None,
                description_ref: None,
            }
        })
        .collect()
}

fn merge_overlapping_candidates(candidates: &mut Vec<Candidate>) {
    loop {
        let mut pair = None;
        'outer: for left in 0..candidates.len() {
            for right in (left + 1)..candidates.len() {
                if overlap_at_least_sixty_percent(&candidates[left].files, &candidates[right].files)
                {
                    pair = Some((left, right));
                    break 'outer;
                }
            }
        }
        let Some((left, right)) = pair else {
            break;
        };
        let (preferred_index, absorbed_index) =
            if candidate_precedes(&candidates[left], &candidates[right]) {
                (left, right)
            } else {
                (right, left)
            };
        let absorbed = candidates.remove(absorbed_index);
        let preferred = if absorbed_index < preferred_index {
            preferred_index.saturating_sub(1)
        } else {
            preferred_index
        };
        let candidate = &mut candidates[preferred];
        candidate.files.extend(absorbed.files);
        candidate.boundaries.extend(absorbed.boundaries);
        candidate.boundaries.sort();
        candidate.boundaries.dedup();
        let file_list = candidate.files.iter().cloned().collect::<Vec<_>>();
        candidate.seed_id = candidate_id(&candidate.name, &file_list);
    }
}

fn cap_candidates(candidates: &mut Vec<Candidate>, cap: usize) {
    while candidates.len() > cap {
        let smallest = candidates
            .iter()
            .enumerate()
            .min_by(|(_, left), (_, right)| {
                left.files
                    .len()
                    .cmp(&right.files.len())
                    .then_with(|| left.seed_id.cmp(&right.seed_id))
            })
            .map(|(index, _)| index)
            .unwrap_or_default();
        let source = candidates.remove(smallest);
        let parent = source
            .boundaries
            .first()
            .and_then(|boundary| Path::new(boundary).parent())
            .map(normalized_path)
            .unwrap_or_default();
        let target = candidates
            .iter()
            .enumerate()
            .max_by_key(|(_, candidate)| {
                candidate
                    .boundaries
                    .iter()
                    .map(|boundary| common_prefix_components(&parent, boundary))
                    .max()
                    .unwrap_or_default()
            })
            .map(|(index, _)| index)
            .unwrap_or_default();
        candidates[target].files.extend(source.files);
        candidates[target].boundaries.extend(source.boundaries);
        candidates[target].boundaries.sort();
        candidates[target].boundaries.dedup();
    }
}

fn compare_candidate_for_file(
    file: &str,
    left: &Candidate,
    right: &Candidate,
) -> std::cmp::Ordering {
    let left_overlap = left
        .boundaries
        .iter()
        .map(|boundary| common_prefix_components(file, boundary))
        .max()
        .unwrap_or_default();
    let right_overlap = right
        .boundaries
        .iter()
        .map(|boundary| common_prefix_components(file, boundary))
        .max()
        .unwrap_or_default();
    left_overlap
        .cmp(&right_overlap)
        .then_with(|| {
            left.boundaries
                .iter()
                .map(String::len)
                .max()
                .unwrap_or_default()
                .cmp(
                    &right
                        .boundaries
                        .iter()
                        .map(String::len)
                        .max()
                        .unwrap_or_default(),
                )
        })
        .then_with(|| right.seed_id.cmp(&left.seed_id))
}

fn purpose_for_candidate(
    root: &Path,
    candidate: &Candidate,
) -> Result<(String, Option<String>), EngineError> {
    if let Some(description) = candidate.description.as_deref() {
        return Ok((
            truncate_bytes(description, PURPOSE_LIMIT_BYTES),
            candidate.description_ref.clone(),
        ));
    }
    let mut entrypoints = candidate
        .files
        .iter()
        .filter(|path| {
            path.ends_with("/lib.rs")
                || path.ends_with("/main.rs")
                || path.ends_with("/mod.rs")
                || path.as_str() == "lib.rs"
                || path.as_str() == "main.rs"
                || path.as_str() == "mod.rs"
        })
        .cloned()
        .collect::<Vec<_>>();
    entrypoints.sort();
    for path in entrypoints {
        if let Some((sentence, start, end)) = module_doc_sentence(&root.join(&path))? {
            return Ok((
                truncate_bytes(&sentence, PURPOSE_LIMIT_BYTES),
                Some(format!("file:{path}#L{start}-L{end}")),
            ));
        }
    }
    for boundary in &candidate.boundaries {
        for readme in ["README.md", "README.MD", "Readme.md"] {
            let path = if boundary == "." {
                readme.to_owned()
            } else {
                format!("{boundary}/{readme}")
            };
            if let Some((sentence, start, end)) = prose_sentence(&root.join(&path))? {
                return Ok((
                    truncate_bytes(&sentence, PURPOSE_LIMIT_BYTES),
                    Some(format!("file:{path}#L{start}-L{end}")),
                ));
            }
        }
    }
    let boundary = candidate
        .boundaries
        .first()
        .cloned()
        .unwrap_or_else(|| "_unassigned".to_owned());
    Ok((format!("Owns project behavior under {boundary}."), None))
}

fn concept_cues<'a>(
    name: &str,
    boundaries: &[String],
    hotspots: impl Iterator<Item = &'a str>,
) -> Result<Vec<CueBinding>, EngineError> {
    let mut bindings = vec![CueBinding {
        cue_kind: CueKind::Subsystem,
        cue_value: name.to_owned(),
        match_mode: CueMatchMode::Exact,
        strength: CueStrength::Primary,
        expected_reuse_note: EXPECTED_REUSE_NOTE.to_owned(),
    }];
    bindings.extend(
        boundaries
            .iter()
            .filter(|boundary| boundary.as_str() != ".")
            .take(3)
            .map(|boundary| CueBinding {
                cue_kind: CueKind::DirPath,
                cue_value: boundary.clone(),
                match_mode: CueMatchMode::Prefix,
                strength: CueStrength::Primary,
                expected_reuse_note: EXPECTED_REUSE_NOTE.to_owned(),
            }),
    );
    bindings.extend(hotspots.take(3).map(|path| CueBinding {
        cue_kind: CueKind::FilePath,
        cue_value: path.to_owned(),
        match_mode: CueMatchMode::Exact,
        strength: CueStrength::Secondary,
        expected_reuse_note: EXPECTED_REUSE_NOTE.to_owned(),
    }));
    normalize_bindings(bindings, None)
        .map_err(|error| EngineError::WriteRejected(error.to_string()))
}

fn entrypoints(files: &[String]) -> Vec<String> {
    let mut values = files
        .iter()
        .filter(|path| {
            path.ends_with("/lib.rs") || path.ends_with("/main.rs") || path.ends_with("/mod.rs")
        })
        .map(|path| format!("file:{path}"))
        .collect::<Vec<_>>();
    values.sort();
    values.truncate(3);
    values
}

fn concept_dependencies(
    assignments: &BTreeMap<String, String>,
    edges: &[CoChangeEdge],
) -> Vec<(String, String)> {
    let mut dependencies = BTreeSet::new();
    for edge in edges.iter().filter(|edge| {
        edge.confidence_ab.max(edge.confidence_ba) >= 0.7 || edge.static_edge_exists == Some(true)
    }) {
        let Some(left) = assignments.get(&edge.path_a) else {
            continue;
        };
        let Some(right) = assignments.get(&edge.path_b) else {
            continue;
        };
        if left != right {
            dependencies.insert((left.clone(), right.clone()));
            dependencies.insert((right.clone(), left.clone()));
        }
    }
    dependencies.into_iter().collect()
}

fn bind_invariants(
    concepts: &mut [ConceptNode],
    assignments: &BTreeMap<String, String>,
    sources: &[CueRecordSource],
) {
    let mut by_concept = BTreeMap::<String, BTreeSet<String>>::new();
    for source in sources
        .iter()
        .filter(|source| source.record_kind == "invariant")
    {
        for binding in &source.cue_bindings {
            if binding.cue_kind == CueKind::FilePath
                && let Some(concept_id) = assignments.get(&binding.cue_value)
            {
                by_concept
                    .entry(concept_id.clone())
                    .or_default()
                    .insert(source.record_ref.clone());
            }
        }
    }
    for concept in concepts {
        concept.invariant_refs = by_concept
            .remove(&concept.concept_id)
            .unwrap_or_default()
            .into_iter()
            .collect();
    }
}

#[allow(clippy::too_many_lines)]
async fn onboarding_evidence(
    seed: &ConceptSeedResult,
    mining: &GitMiningArtifacts,
    cards: &[ModuleCard],
    cue_sources: &[CueRecordSource],
    store: &CanonicalStore,
) -> Result<BTreeMap<String, CapsuleEvidence>, EngineError> {
    let mut evidence = seed
        .concepts
        .iter()
        .map(|concept| (concept.concept_id.clone(), CapsuleEvidence::default()))
        .collect::<BTreeMap<_, _>>();
    for card in cards {
        if let Some(concept_id) = seed.assignments.get(&card.path) {
            evidence
                .entry(concept_id.clone())
                .or_default()
                .module_cards
                .push(card.clone());
        }
    }
    for hotspot in &mining.hotspots {
        if let Some(concept_id) = seed.assignments.get(&hotspot.path) {
            evidence
                .entry(concept_id.clone())
                .or_default()
                .hotspots
                .push(hotspot.clone());
        }
    }
    for source in cue_sources {
        let matching = source
            .cue_bindings
            .iter()
            .filter(|binding| binding.cue_kind == CueKind::FilePath)
            .filter_map(|binding| seed.assignments.get(&binding.cue_value))
            .cloned()
            .collect::<BTreeSet<_>>();
        for concept_id in matching {
            let entry = evidence.entry(concept_id).or_default();
            if source.negative_memory {
                entry.failures.push(PyramidFailure {
                    reference: source.record_ref.clone(),
                    summary: source.preview_text.clone(),
                });
            }
            if source.record_kind == "invariant" {
                entry.invariant_refs.push(source.record_ref.clone());
            }
        }
    }
    let claims = store
        .canonical_records_by_kind::<Value>(
            mining.run.project_id,
            None,
            &["claim_card"],
            ARTIFACT_READ_LIMIT,
        )
        .await?;
    for record in claims {
        let statement = record
            .receipt_body
            .get("statement")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !statement.to_ascii_lowercase().contains("decision") {
            continue;
        }
        let reference = format!("claim:{}", record.subject_ref.trim_start_matches("claim:"));
        let candidate = record
            .receipt_body
            .get("status")
            .and_then(Value::as_str)
            .is_none_or(|status| status != "verified");
        let sequence = record
            .project_sequence
            .map_or(0, eliot_types::ProjectSequence::value);
        for (concept_id, entry) in &mut evidence {
            let concept = seed
                .concepts
                .iter()
                .find(|concept| &concept.concept_id == concept_id);
            if concept.is_some_and(|concept| {
                concept.boundary_paths.iter().any(|boundary| {
                    statement
                        .to_ascii_lowercase()
                        .contains(&boundary.to_ascii_lowercase())
                })
            }) {
                entry.decisions.push(PyramidDecision {
                    reference: reference.clone(),
                    rationale: statement.to_owned(),
                    candidate,
                    sequence,
                });
                entry.claim_refs.push(reference.clone());
            }
        }
    }
    for edge in &mining.edges {
        let (Some(left), Some(right)) = (
            seed.assignments.get(&edge.path_a),
            seed.assignments.get(&edge.path_b),
        ) else {
            continue;
        };
        if left == right {
            continue;
        }
        let confidence = edge.confidence_ab.max(edge.confidence_ba);
        evidence
            .entry(left.clone())
            .or_default()
            .outgoing_dependencies
            .push(PyramidDependency {
                concept_id: right.clone(),
                evidence_ref: edge.edge_id.clone(),
                confidence,
            });
        evidence
            .entry(right.clone())
            .or_default()
            .outgoing_dependencies
            .push(PyramidDependency {
                concept_id: left.clone(),
                evidence_ref: edge.edge_id.clone(),
                confidence,
            });
    }
    for entry in evidence.values_mut() {
        entry
            .verifiers
            .extend(entry.module_cards.iter().map(|card| card.verifier.clone()));
    }
    Ok(evidence)
}

async fn stage_is_canonical<'a>(
    store: &CanonicalStore,
    project_id: ProjectId,
    kind: &str,
    ids: impl Iterator<Item = &'a str>,
    checkpoint_claims_complete: bool,
) -> Result<bool, EngineError> {
    if !checkpoint_claims_complete {
        return Ok(false);
    }
    for id in ids {
        if store
            .ul_artifact_by_id::<Value>(project_id, kind, id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_project_root(root: &Path) -> Result<PathBuf, EngineError> {
    if !root.is_dir() {
        return Err(EngineError::WriteRejected(format!(
            "onboarding root is not a directory: {}",
            root.display()
        )));
    }
    let canonical = root.canonicalize()?;
    if !canonical.join(".git").exists() {
        return Err(EngineError::WriteRejected(
            "onboarding root is not a git repository".to_owned(),
        ));
    }
    Ok(canonical)
}

fn git_head(root: &Path) -> Result<String, EngineError> {
    let output = run_process(root, "git", &["rev-parse", "HEAD"])?;
    if !output.status {
        return Err(EngineError::ServiceNotReady {
            service: "git".to_owned(),
            reason: process_failure(&output),
        });
    }
    Ok(output.stdout.trim().to_owned())
}

fn validate_git_state(root: &Path) -> Result<(), EngineError> {
    let output = run_process(root, "git", &["status", "--porcelain=v1"])?;
    if !output.status {
        return Err(EngineError::ServiceNotReady {
            service: "git".to_owned(),
            reason: process_failure(&output),
        });
    }
    Ok(())
}

fn onboarding_inputs_hash(
    project_id: ProjectId,
    root: &Path,
    head: &str,
    mining: &GitMiningArtifacts,
    manifests: &[ManifestPackage],
    cards: &[ModuleCard],
) -> Result<String, EngineError> {
    let mut files = discover_source_files(root)?
        .into_iter()
        .map(|path| {
            let hash = file_blake3(&root.join(&path))?;
            Ok((path, hash))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    files.sort();
    let value = json!({
        "project_id": project_id,
        "head_commit": head,
        "mining_run": mining.run,
        "manifests": manifests,
        "module_cards": cards,
        "files": files,
    });
    Ok(blake3::hash(&serde_json::to_vec(&value)?)
        .to_hex()
        .to_string())
}

fn checkpoint_path(runtime_root: &Path, project_id: ProjectId) -> PathBuf {
    runtime_root
        .join("reports")
        .join("ul")
        .join("onboarding")
        .join(project_id.to_string())
        .join("checkpoint.json")
}

fn load_checkpoint(path: &Path) -> Result<Option<OnboardingCheckpoint>, EngineError> {
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

fn save_checkpoint(path: &Path, checkpoint: &OnboardingCheckpoint) -> Result<(), EngineError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(checkpoint)?)?;
    Ok(())
}

fn save_report(runtime_root: &Path, report: &OnboardingReport) -> Result<(), EngineError> {
    let path = runtime_root
        .join("reports")
        .join("ul")
        .join("onboarding")
        .join(report.project_id.to_string())
        .join("report.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

fn normalize_checkpoint(checkpoint: &mut OnboardingCheckpoint) {
    checkpoint.completed_artifact_refs.sort();
    checkpoint.completed_artifact_refs.dedup();
}

fn discover_source_files(root: &Path) -> Result<Vec<String>, EngineError> {
    let root = root.canonicalize()?;
    let mut files = Vec::new();
    visit_source_files(&root, &root, &mut files)?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn visit_source_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<String>,
) -> Result<(), EngineError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "target" | ".eliot-governor" | ".codex" | "node_modules"
            ) {
                continue;
            }
            visit_source_files(root, &path, output)?;
        } else if file_type.is_file()
            && is_source_or_config(&path)
            && let Some(relative) = relative_path(root, &path)
        {
            output.push(relative);
        }
    }
    Ok(())
}

fn is_source_or_config(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if matches!(
        name,
        "Cargo.toml" | "Cargo.lock" | "Justfile" | "rust-toolchain.toml"
    ) {
        return true;
    }
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("rs" | "toml" | "surql" | "json" | "yaml" | "yml" | "md" | "ps1" | "sh")
    )
}

fn module_doc_sentence(path: &Path) -> Result<Option<(String, usize, usize)>, EngineError> {
    if !path.is_file() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let mut fragments = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim_start().trim_start_matches('\u{feff}');
        if let Some(fragment) = trimmed.strip_prefix("//!") {
            if start == 0 {
                start = index + 1;
            }
            end = index + 1;
            if !fragment.trim().is_empty() {
                fragments.push(fragment.trim());
            }
        } else if start > 0 || !trimmed.is_empty() {
            break;
        }
    }
    let sentence = first_sentence(&fragments.join(" "));
    Ok((!sentence.is_empty()).then_some((sentence, start, end)))
}

fn prose_sentence(path: &Path) -> Result<Option<(String, usize, usize)>, EngineError> {
    if !path.is_file() {
        return Ok(None);
    }
    for (index, line) in fs::read_to_string(path)?.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Ok(Some((first_sentence(trimmed), index + 1, index + 1)));
    }
    Ok(None)
}

fn first_sentence(value: &str) -> String {
    let value = value.trim();
    value
        .char_indices()
        .find(|(_, character)| matches!(character, '.' | '!' | '?'))
        .map_or_else(
            || value.to_owned(),
            |(index, character)| value[..index + character.len_utf8()].to_owned(),
        )
}

fn line_containing(path: &Path, needle: &str) -> Option<usize> {
    fs::read_to_string(path)
        .ok()?
        .lines()
        .position(|line| line.trim_start().starts_with(needle))
        .map(|index| index + 1)
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let absolute = path.canonicalize().ok()?;
    absolute.strip_prefix(root).ok().map(normalized_path)
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalized_name(boundary: &str) -> String {
    boundary
        .trim_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("project")
        .replace([' ', '-'], "_")
}

fn unassigned_boundaries(files: &[String]) -> Vec<String> {
    let mut boundaries = files
        .iter()
        .filter_map(|file| Path::new(file).parent())
        .map(normalized_path)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    boundaries.sort();
    boundaries.dedup();
    boundaries.truncate(3);
    if boundaries.is_empty() {
        boundaries.push("_unassigned".to_owned());
    }
    boundaries
}

fn common_boundaries(files: &[String]) -> Vec<String> {
    let mut boundaries = files
        .iter()
        .filter_map(|file| file.split('/').next())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    boundaries.sort();
    boundaries.dedup();
    boundaries.truncate(3);
    boundaries
}

fn candidate_id(name: &str, files: &[String]) -> String {
    deterministic_id("seed", &[name, &files.join("\0")])
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    let digest = hasher.finalize().to_hex().to_string();
    format!("{prefix}-{}", &digest[..32])
}

fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].trim_end().to_owned()
}

fn path_matches_boundary(path: &str, boundary: &str) -> bool {
    boundary == "."
        || path == boundary
        || path
            .strip_prefix(boundary.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn common_prefix_components(left: &str, right: &str) -> usize {
    left.split('/')
        .zip(right.split('/'))
        .take_while(|(left, right)| left == right)
        .count()
}

fn overlap_at_least_sixty_percent(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    let intersection = left.intersection(right).count();
    let union = left.union(right).count();
    union > 0 && intersection.saturating_mul(5) >= union.saturating_mul(3)
}

fn candidate_precedes(left: &Candidate, right: &Candidate) -> bool {
    left.priority < right.priority
        || (left.priority == right.priority
            && (left.name < right.name
                || (left.name == right.name && left.seed_id < right.seed_id)))
}

fn find(parents: &mut BTreeMap<String, String>, value: &str) -> String {
    let parent = parents
        .entry(value.to_owned())
        .or_insert_with(|| value.to_owned())
        .clone();
    if parent == value {
        value.to_owned()
    } else {
        let root = find(parents, &parent);
        parents.insert(value.to_owned(), root.clone());
        root
    }
}

fn union(parents: &mut BTreeMap<String, String>, left: &str, right: &str) {
    let left_root = find(parents, left);
    let right_root = find(parents, right);
    if left_root == right_root {
        return;
    }
    let (first, second) = if left_root < right_root {
        (left_root, right_root)
    } else {
        (right_root, left_root)
    };
    parents.insert(second, first);
}

fn file_blake3(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn process_failure(output: &crate::codecortex::ProcessOutput) -> String {
    output
        .stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .or_else(|| output.stdout.lines().find(|line| !line.trim().is_empty()))
        .map_or_else(|| format!("exit_code={:?}", output.code), str::to_owned)
}
