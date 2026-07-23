use crate::EngineError;
use eliot_types::{
    CapsuleBuild, CapsuleFreshness, CoChangeEdge, ConceptNode, CueBinding, CueKind, CueMatchMode,
    CueStrength, DependencyManifest, FileDependency, HotspotScore, ModuleCard, ProjectCharter,
    ProjectId, PyramidBuildStatus, PyramidTargetKind, SubsystemCapsule, SystemFlow, SystemMap,
    inspect_text_encoding, normalize_bindings, ul_token_estimate,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const CAPSULE_LIMIT: u32 = 500;
const MAP_LIMIT: u32 = 600;
const CHARTER_LIMIT: u32 = 200;
const STALE_PREFIX: &str = "[STALE: changed dependencies: ";

const CAPSULE_HEADERS: &[&str] = &[
    "PURPOSE",
    "BOUNDARIES",
    "KEY ENTRYPOINTS",
    "INVARIANTS",
    "DRAGONS",
    "KEY DECISIONS",
    "VERIFIERS",
];
const MAP_HEADERS: &[&str] = &["SYSTEMS", "FLOWS"];
const CHARTER_HEADERS: &[&str] = &[
    "WHAT",
    "FOR WHOM",
    "TOP INVARIANTS",
    "NON-GOALS",
    "VOCABULARY",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PyramidFailure {
    pub reference: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PyramidDecision {
    pub reference: String,
    pub rationale: String,
    pub candidate: bool,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PyramidDependency {
    pub concept_id: String,
    pub evidence_ref: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapsuleEvidence {
    pub module_cards: Vec<ModuleCard>,
    pub hotspots: Vec<HotspotScore>,
    pub invariant_refs: Vec<String>,
    pub failures: Vec<PyramidFailure>,
    pub decisions: Vec<PyramidDecision>,
    pub verifiers: Vec<String>,
    pub outgoing_dependencies: Vec<PyramidDependency>,
    pub claim_refs: Vec<String>,
    pub report_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotedPyramid<T> {
    pub artifact: T,
    pub build: CapsuleBuild,
}

#[derive(Clone, Debug, Default)]
pub struct PyramidBuilder;

impl PyramidBuilder {
    #[allow(clippy::too_many_lines)]
    pub fn build_capsule(
        &self,
        project_root: &Path,
        concept: &ConceptNode,
        evidence: &CapsuleEvidence,
        previous_build_id: Option<String>,
    ) -> Result<PromotedPyramid<SubsystemCapsule>, EngineError> {
        let mut entrypoints = capsule_entrypoints(concept, &evidence.module_cards);
        let mut invariants = concept.invariant_refs.clone();
        invariants.extend(evidence.invariant_refs.iter().cloned());
        sort_dedup(&mut invariants);

        let mut failures = evidence.failures.clone();
        failures.sort_by(|left, right| left.reference.cmp(&right.reference));
        failures.truncate(3);
        let mut hotspots = evidence.hotspots.clone();
        hotspots.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.path.cmp(&right.path))
        });
        hotspots.truncate(3);
        let mut decisions = evidence.decisions.clone();
        decisions.sort_by(|left, right| {
            right
                .sequence
                .cmp(&left.sequence)
                .then_with(|| left.reference.cmp(&right.reference))
        });
        decisions.truncate(3);
        let mut dependencies = evidence.outgoing_dependencies.clone();
        dependencies.sort_by(|left, right| {
            right
                .confidence
                .total_cmp(&left.confidence)
                .then_with(|| left.concept_id.cmp(&right.concept_id))
                .then_with(|| left.evidence_ref.cmp(&right.evidence_ref))
        });
        dependencies.dedup_by(|left, right| left.concept_id == right.concept_id);
        let mut verifiers = evidence.verifiers.clone();
        verifiers.extend(
            evidence
                .module_cards
                .iter()
                .map(|card| card.verifier.clone())
                .filter(|verifier| !verifier.trim().is_empty()),
        );
        sort_dedup(&mut verifiers);

        let body_md = loop {
            let rendered = render_capsule_body(
                concept,
                &entrypoints,
                &invariants,
                &failures,
                &hotspots,
                &decisions,
                &verifiers,
                &dependencies,
            );
            if ul_token_estimate(&rendered) <= CAPSULE_LIMIT {
                break rendered;
            }
            if decisions.len() > 1 {
                decisions.pop();
            } else if hotspots.len() > 1 {
                hotspots.pop();
            } else if entrypoints.len() > 2 {
                entrypoints.pop();
            } else if dependencies.len() > 3 {
                dependencies.pop();
            } else {
                return rejected_budget("subsystem capsule", CAPSULE_LIMIT, &rendered);
            }
        };

        let mut source_refs = concept.source_refs.clone();
        source_refs.extend(entrypoints.iter().map(|entry| entry.source_ref.clone()));
        source_refs.extend(failures.iter().map(|failure| failure.reference.clone()));
        source_refs.extend(decisions.iter().map(|decision| decision.reference.clone()));
        source_refs.extend(hotspots.iter().map(|hotspot| hotspot.hotspot_id.clone()));
        sort_dedup(&mut source_refs);

        let mut dependency_paths = source_refs
            .iter()
            .filter_map(|reference| file_path_from_ref(reference))
            .collect::<Vec<_>>();
        dependency_paths.extend(entrypoints.iter().map(|entry| entry.path.clone()));
        sort_dedup(&mut dependency_paths);
        let dependency_manifest = dependency_manifest(
            project_root,
            &dependency_paths,
            &evidence.claim_refs,
            &decisions
                .iter()
                .map(|decision| decision.reference.clone())
                .collect::<Vec<_>>(),
            &dependencies
                .iter()
                .map(|dependency| dependency.evidence_ref.clone())
                .collect::<Vec<_>>(),
            &evidence.report_refs,
        )?;

        validate_body(
            project_root,
            &body_md,
            CAPSULE_HEADERS,
            CAPSULE_LIMIT,
            &source_refs,
        )?;
        let inputs_hash = inputs_hash(&json!({
            "project_id": concept.project_id,
            "concept": concept,
            "body_md": body_md,
            "dependency_manifest": dependency_manifest,
        }))?;
        let capsule_id = deterministic_id(
            "ul-capsule",
            &[
                &concept.project_id.to_string(),
                &concept.concept_id,
                &inputs_hash,
            ],
        );
        let build_id = deterministic_id(
            "ul-build",
            &[&concept.project_id.to_string(), &capsule_id, &inputs_hash],
        );
        let artifact = SubsystemCapsule {
            capsule_id: capsule_id.clone(),
            project_id: concept.project_id,
            concept_id: concept.concept_id.clone(),
            body_md,
            dependency_manifest,
            build_id: build_id.clone(),
            cue_bindings: concept.cue_bindings.clone(),
            source_refs,
        };
        let build = promoted_build(
            build_id,
            concept.project_id,
            PyramidTargetKind::SubsystemCapsule,
            capsule_id,
            inputs_hash,
            CAPSULE_LIMIT,
            ul_token_estimate(&artifact.body_md),
            previous_build_id,
            CAPSULE_HEADERS,
        );
        Ok(PromotedPyramid { artifact, build })
    }

    #[allow(clippy::too_many_lines)]
    pub fn build_system_map(
        &self,
        project_id: ProjectId,
        project_root: &Path,
        concepts: &[ConceptNode],
        edges: &[CoChangeEdge],
        previous_build_id: Option<String>,
    ) -> Result<PromotedPyramid<SystemMap>, EngineError> {
        let mut sorted_concepts = concepts.to_vec();
        sorted_concepts.sort_by(|left, right| left.concept_id.cmp(&right.concept_id));
        let assignments = file_assignments(&sorted_concepts, edges);
        let mut selected: BTreeMap<(String, String, String), (f64, u32, String)> = BTreeMap::new();
        for edge in edges {
            let Some(from) = assignments.get(&edge.path_a) else {
                continue;
            };
            let Some(to) = assignments.get(&edge.path_b) else {
                continue;
            };
            if from == to {
                continue;
            }
            let (from, to) = if from < to {
                (from.clone(), to.clone())
            } else {
                (to.clone(), from.clone())
            };
            let kind = if edge.static_edge_exists == Some(true) {
                "static_dependency"
            } else {
                "hidden_cochange"
            };
            let confidence = edge.confidence_ab.max(edge.confidence_ba);
            let candidate = (confidence, edge.support, edge.edge_id.clone());
            selected
                .entry((from, to, kind.to_owned()))
                .and_modify(|current| {
                    let confidence_order = candidate.0.total_cmp(&current.0);
                    if confidence_order.is_gt()
                        || (confidence_order.is_eq() && candidate.1 > current.1)
                        || (confidence_order.is_eq()
                            && candidate.1 == current.1
                            && candidate.2 < current.2)
                    {
                        *current = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
        let mut ranked_flows = selected
            .into_iter()
            .map(
                |((from_concept, to_concept, flow_kind), (confidence, support, evidence_ref))| {
                    (
                        confidence,
                        support,
                        SystemFlow {
                            from_concept,
                            to_concept,
                            flow_kind,
                            evidence_ref,
                        },
                    )
                },
            )
            .collect::<Vec<_>>();
        ranked_flows.sort_by(|left, right| {
            right
                .0
                .total_cmp(&left.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.from_concept.cmp(&right.2.from_concept))
                .then_with(|| left.2.to_concept.cmp(&right.2.to_concept))
        });
        let mut flow_edges = ranked_flows
            .into_iter()
            .map(|(_, _, flow)| flow)
            .collect::<Vec<_>>();
        let body_md = loop {
            let rendered = render_system_map(&sorted_concepts, &flow_edges);
            if ul_token_estimate(&rendered) <= MAP_LIMIT {
                break rendered;
            }
            if flow_edges.pop().is_none() {
                return rejected_budget("system map", MAP_LIMIT, &rendered);
            }
        };

        let mut source_refs = sorted_concepts
            .iter()
            .flat_map(|concept| concept.source_refs.iter().cloned())
            .collect::<Vec<_>>();
        sort_dedup(&mut source_refs);
        let dependency_paths = source_refs
            .iter()
            .filter_map(|reference| file_path_from_ref(reference))
            .collect::<Vec<_>>();
        let dependency_manifest = dependency_manifest(
            project_root,
            &dependency_paths,
            &[],
            &[],
            &flow_edges
                .iter()
                .map(|flow| flow.evidence_ref.clone())
                .collect::<Vec<_>>(),
            &[],
        )?;
        validate_body(project_root, &body_md, MAP_HEADERS, MAP_LIMIT, &source_refs)?;
        let inputs_hash = inputs_hash(&json!({
            "project_id": project_id,
            "concepts": sorted_concepts,
            "flow_edges": flow_edges,
            "body_md": body_md,
            "dependency_manifest": dependency_manifest,
        }))?;
        let map_id = deterministic_id("ul-map", &[&project_id.to_string(), &inputs_hash]);
        let build_id = deterministic_id(
            "ul-build",
            &[&project_id.to_string(), &map_id, &inputs_hash],
        );
        let cue_bindings = target_cues("system map")?;
        let artifact = SystemMap {
            map_id: map_id.clone(),
            project_id,
            body_md,
            subsystem_concept_refs: sorted_concepts
                .iter()
                .map(|concept| concept.concept_id.clone())
                .collect(),
            flow_edges,
            dependency_manifest,
            build_id: build_id.clone(),
            cue_bindings,
        };
        let build = promoted_build(
            build_id,
            project_id,
            PyramidTargetKind::SystemMap,
            map_id,
            inputs_hash,
            MAP_LIMIT,
            ul_token_estimate(&artifact.body_md),
            previous_build_id,
            MAP_HEADERS,
        );
        Ok(PromotedPyramid { artifact, build })
    }

    pub fn build_charter(
        &self,
        project_id: ProjectId,
        project_root: &Path,
        concepts: &[ConceptNode],
        invariant_refs: &[String],
        previous_build_id: Option<String>,
    ) -> Result<PromotedPyramid<ProjectCharter>, EngineError> {
        let project_name = project_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("project");
        let (what, what_ref) = project_what(project_root, project_name)?;
        let mut invariants = invariant_refs.to_vec();
        sort_dedup(&mut invariants);
        invariants.truncate(5);
        let (mut non_goals, non_goal_refs) = read_non_goals(project_root)?;
        let mut vocabulary = concepts
            .iter()
            .map(|concept| concept.name.clone())
            .collect::<Vec<_>>();
        sort_dedup(&mut vocabulary);
        vocabulary.truncate(10);
        let body_md = loop {
            let rendered = render_charter(&what, &invariants, &non_goals, &vocabulary);
            if ul_token_estimate(&rendered) <= CHARTER_LIMIT {
                break rendered;
            }
            if vocabulary.len() > 1 {
                vocabulary.pop();
            } else if invariants.len() > 1 {
                invariants.pop();
            } else if non_goals.len() > 1 {
                non_goals.pop();
            } else {
                return rejected_budget("project charter", CHARTER_LIMIT, &rendered);
            }
        };
        let mut source_refs = Vec::new();
        if let Some(reference) = what_ref {
            source_refs.push(reference);
        }
        source_refs.extend(non_goal_refs);
        source_refs.extend(
            concepts
                .iter()
                .flat_map(|concept| concept.source_refs.iter().cloned()),
        );
        sort_dedup(&mut source_refs);
        let dependency_paths = source_refs
            .iter()
            .filter_map(|reference| file_path_from_ref(reference))
            .collect::<Vec<_>>();
        let dependency_manifest =
            dependency_manifest(project_root, &dependency_paths, &[], &[], &[], &[])?;
        validate_body(
            project_root,
            &body_md,
            CHARTER_HEADERS,
            CHARTER_LIMIT,
            &source_refs,
        )?;
        let mut concept_refs = concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect::<Vec<_>>();
        sort_dedup(&mut concept_refs);
        let inputs_hash = inputs_hash(&json!({
            "project_id": project_id,
            "body_md": body_md,
            "concept_refs": concept_refs,
            "dependency_manifest": dependency_manifest,
        }))?;
        let charter_id = deterministic_id("ul-charter", &[&project_id.to_string(), &inputs_hash]);
        let build_id = deterministic_id(
            "ul-build",
            &[&project_id.to_string(), &charter_id, &inputs_hash],
        );
        let artifact = ProjectCharter {
            charter_id: charter_id.clone(),
            project_id,
            body_md,
            concept_refs,
            dependency_manifest,
            build_id: build_id.clone(),
            cue_bindings: target_cues(project_name)?,
        };
        let build = promoted_build(
            build_id,
            project_id,
            PyramidTargetKind::ProjectCharter,
            charter_id,
            inputs_hash,
            CHARTER_LIMIT,
            ul_token_estimate(&artifact.body_md),
            previous_build_id,
            CHARTER_HEADERS,
        );
        Ok(PromotedPyramid { artifact, build })
    }
}

#[must_use]
pub fn capsule_freshness(capsule: &SubsystemCapsule, project_root: &Path) -> CapsuleFreshness {
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    for dependency in &capsule.dependency_manifest.file_deps {
        let path = project_root.join(&dependency.path);
        if !path.is_file() {
            missing.push(dependency.path.clone());
            continue;
        }
        match file_blake3(&path) {
            Ok(actual) if actual == dependency.blake3 => {}
            Ok(_) | Err(_) => changed.push(dependency.path.clone()),
        }
    }
    sort_dedup(&mut changed);
    sort_dedup(&mut missing);
    if changed.is_empty() && missing.is_empty() {
        CapsuleFreshness::Fresh
    } else {
        CapsuleFreshness::Stale { changed, missing }
    }
}

#[must_use]
pub fn render_capsule(capsule: &SubsystemCapsule, project_root: &Path) -> String {
    match capsule_freshness(capsule, project_root) {
        CapsuleFreshness::Fresh => capsule.body_md.clone(),
        CapsuleFreshness::Stale {
            mut changed,
            missing,
        } => {
            changed.extend(missing);
            sort_dedup(&mut changed);
            format!(
                "{STALE_PREFIX}{}] — verify against code before relying.\n{}",
                changed.join(", "),
                capsule.body_md
            )
        }
    }
}

#[derive(Clone)]
struct Entrypoint {
    path: String,
    label: String,
    source_ref: String,
}

fn capsule_entrypoints(concept: &ConceptNode, cards: &[ModuleCard]) -> Vec<Entrypoint> {
    let mut entries = cards
        .iter()
        .filter(|card| path_in_concept(&card.path, concept))
        .map(|card| Entrypoint {
            path: card.path.clone(),
            label: truncate_bytes(card.body_md.lines().next().unwrap_or(&card.path), 100),
            source_ref: card
                .source_refs
                .first()
                .cloned()
                .unwrap_or_else(|| format!("file:{}", card.path)),
        })
        .collect::<Vec<_>>();
    entries.extend(concept.entrypoint_refs.iter().map(|reference| Entrypoint {
        path: file_path_from_ref(reference).unwrap_or_else(|| reference.clone()),
        label: reference.clone(),
        source_ref: reference.clone(),
    }));
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries.dedup_by(|left, right| left.path == right.path);
    entries.truncate(3);
    entries
}

#[allow(clippy::too_many_arguments)]
fn render_capsule_body(
    concept: &ConceptNode,
    entrypoints: &[Entrypoint],
    invariants: &[String],
    failures: &[PyramidFailure],
    hotspots: &[HotspotScore],
    decisions: &[PyramidDecision],
    verifiers: &[String],
    dependencies: &[PyramidDependency],
) -> String {
    let mut lines = vec![
        "PURPOSE".to_owned(),
        concept.purpose.clone(),
        String::new(),
        "BOUNDARIES".to_owned(),
    ];
    lines.extend(
        concept
            .boundary_paths
            .iter()
            .map(|path| format!("- {path}")),
    );
    lines.extend(dependencies.iter().map(|dependency| {
        format!(
            "- depends on concept:{} [{}]",
            dependency.concept_id, dependency.evidence_ref
        )
    }));
    lines.extend([String::new(), "KEY ENTRYPOINTS".to_owned()]);
    if entrypoints.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(
            entrypoints
                .iter()
                .map(|entry| format!("- {} [{}]", entry.label, entry.source_ref)),
        );
    }
    lines.extend([String::new(), "INVARIANTS".to_owned()]);
    if invariants.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(invariants.iter().map(|reference| format!("- {reference}")));
    }
    lines.extend([String::new(), "DRAGONS".to_owned()]);
    if failures.is_empty() && hotspots.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(failures.iter().map(|failure| {
            format!(
                "- failure: {} [{}]",
                truncate_bytes(&failure.summary, 120),
                failure.reference
            )
        }));
        lines.extend(hotspots.iter().map(|hotspot| {
            format!(
                "- hotspot: {} score={} [{}]",
                hotspot.path, hotspot.score, hotspot.hotspot_id
            )
        }));
    }
    lines.extend([String::new(), "KEY DECISIONS".to_owned()]);
    if decisions.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(decisions.iter().map(|decision| {
            let suffix = if decision.candidate {
                " [candidate]"
            } else {
                ""
            };
            format!(
                "- {} [{}]{}",
                truncate_bytes(&decision.rationale, 100),
                decision.reference,
                suffix
            )
        }));
    }
    lines.extend([String::new(), "VERIFIERS".to_owned()]);
    if verifiers.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(verifiers.iter().map(|verifier| format!("- {verifier}")));
    }
    lines.join("\n")
}

fn render_system_map(concepts: &[ConceptNode], flows: &[SystemFlow]) -> String {
    let mut lines = vec!["SYSTEMS".to_owned()];
    lines.extend(concepts.iter().map(|concept| {
        format!(
            "- {}: {}",
            concept.name,
            truncate_bytes(&concept.purpose, 80)
        )
    }));
    lines.extend([String::new(), "FLOWS".to_owned()]);
    if flows.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(flows.iter().map(|flow| {
            format!(
                "- {} -> {}: {} [{}]",
                flow.from_concept, flow.to_concept, flow.flow_kind, flow.evidence_ref
            )
        }));
    }
    lines.join("\n")
}

fn render_charter(
    what: &str,
    invariants: &[String],
    non_goals: &[String],
    vocabulary: &[String],
) -> String {
    let mut lines = vec![
        "WHAT".to_owned(),
        what.to_owned(),
        String::new(),
        "FOR WHOM".to_owned(),
        "Agents and operators changing this repository under verifier control.".to_owned(),
        String::new(),
        "TOP INVARIANTS".to_owned(),
    ];
    if invariants.is_empty() {
        lines.push("- preserve existing registered verifier contracts".to_owned());
    } else {
        lines.extend(invariants.iter().map(|invariant| format!("- {invariant}")));
    }
    lines.extend([String::new(), "NON-GOALS".to_owned()]);
    if non_goals.is_empty() {
        lines.push("- no project-specific non-goals were deterministically extracted".to_owned());
    } else {
        lines.extend(non_goals.iter().map(|non_goal| format!("- {non_goal}")));
    }
    lines.extend([String::new(), "VOCABULARY".to_owned()]);
    if vocabulary.is_empty() {
        lines.push("- none recorded".to_owned());
    } else {
        lines.extend(vocabulary.iter().map(|term| format!("- {term}")));
    }
    lines.join("\n")
}

fn dependency_manifest(
    root: &Path,
    paths: &[String],
    claim_deps: &[String],
    decision_deps: &[String],
    edge_deps: &[String],
    report_deps: &[String],
) -> Result<DependencyManifest, EngineError> {
    let mut paths = paths.to_vec();
    sort_dedup(&mut paths);
    let mut file_deps = Vec::new();
    for path in paths {
        let absolute = root.join(&path);
        if !absolute.is_file() {
            return Err(EngineError::WriteRejected(format!(
                "pyramid dependency file does not exist: {path}"
            )));
        }
        file_deps.push(FileDependency {
            path,
            blake3: file_blake3(&absolute)?,
        });
    }
    let mut manifest = DependencyManifest {
        file_deps,
        claim_deps: claim_deps.to_vec(),
        decision_deps: decision_deps.to_vec(),
        edge_deps: edge_deps.to_vec(),
        report_deps: report_deps.to_vec(),
    };
    manifest
        .file_deps
        .sort_by(|left, right| left.path.cmp(&right.path));
    sort_dedup(&mut manifest.claim_deps);
    sort_dedup(&mut manifest.decision_deps);
    sort_dedup(&mut manifest.edge_deps);
    sort_dedup(&mut manifest.report_deps);
    Ok(manifest)
}

fn validate_body(
    root: &Path,
    body: &str,
    headers: &[&str],
    budget: u32,
    source_refs: &[String],
) -> Result<Vec<String>, EngineError> {
    for reference in source_refs {
        if let Some(path) = file_path_from_ref(reference)
            && !root.join(&path).is_file()
        {
            return Err(EngineError::WriteRejected(format!(
                "pyramid source ref does not resolve: {reference}"
            )));
        }
    }
    let violations = inspect_text_encoding(&json!(body));
    if !violations.is_empty() {
        return Err(EngineError::EncodingRejected { violations });
    }
    let mut previous = None;
    for header in headers {
        if body.lines().filter(|line| line.trim() == *header).count() != 1 {
            return Err(EngineError::WriteRejected(format!(
                "required pyramid header {header} must occur exactly once"
            )));
        }
        let position = body.find(header).ok_or_else(|| {
            EngineError::WriteRejected(format!("required pyramid header {header} is missing"))
        })?;
        if previous.is_some_and(|value| position <= value) {
            return Err(EngineError::WriteRejected(
                "pyramid headers are out of order".to_owned(),
            ));
        }
        previous = Some(position);
    }
    if ul_token_estimate(body) > budget {
        return rejected_budget("pyramid artifact", budget, body);
    }
    Ok(headers
        .iter()
        .map(|header| format!("header:{header}:ok"))
        .chain(
            source_refs
                .iter()
                .map(|reference| format!("{reference}:ok")),
        )
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn promoted_build(
    build_id: String,
    project_id: ProjectId,
    target_kind: PyramidTargetKind,
    target_id: String,
    inputs_hash: String,
    budget_limit: u32,
    token_estimate: u32,
    previous_build_id: Option<String>,
    headers: &[&str],
) -> CapsuleBuild {
    CapsuleBuild {
        build_id,
        project_id,
        target_kind,
        target_id,
        inputs_hash,
        anchor_validation: headers
            .iter()
            .map(|header| format!("header:{header}:ok"))
            .collect(),
        budget_limit,
        token_estimate,
        status: PyramidBuildStatus::Promoted,
        previous_build_id,
    }
}

fn file_assignments(concepts: &[ConceptNode], edges: &[CoChangeEdge]) -> BTreeMap<String, String> {
    let paths = edges
        .iter()
        .flat_map(|edge| [edge.path_a.clone(), edge.path_b.clone()])
        .collect::<BTreeSet<_>>();
    paths
        .into_iter()
        .filter_map(|path| {
            concepts
                .iter()
                .filter(|concept| path_in_concept(&path, concept))
                .max_by(|left, right| {
                    longest_boundary(&path, left)
                        .cmp(&longest_boundary(&path, right))
                        .then_with(|| right.concept_id.cmp(&left.concept_id))
                })
                .map(|concept| (path, concept.concept_id.clone()))
        })
        .collect()
}

fn longest_boundary(path: &str, concept: &ConceptNode) -> usize {
    concept
        .boundary_paths
        .iter()
        .filter(|boundary| path_matches_boundary(path, boundary))
        .map(String::len)
        .max()
        .unwrap_or_default()
}

fn path_in_concept(path: &str, concept: &ConceptNode) -> bool {
    concept
        .boundary_paths
        .iter()
        .any(|boundary| path_matches_boundary(path, boundary))
}

fn path_matches_boundary(path: &str, boundary: &str) -> bool {
    path == boundary
        || path
            .strip_prefix(boundary.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn project_what(root: &Path, project_name: &str) -> Result<(String, Option<String>), EngineError> {
    for name in ["README.md", "README.MD", "Readme.md"] {
        let path = root.join(name);
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        if let Some((sentence, start, end)) = first_non_heading_sentence(&content) {
            return Ok((
                truncate_bytes(&sentence, 320),
                Some(format!("file:{name}#L{start}-L{end}")),
            ));
        }
    }
    Ok((format!("Governed software project {project_name}."), None))
}

fn read_non_goals(root: &Path) -> Result<(Vec<String>, Vec<String>), EngineError> {
    let mut values = Vec::new();
    let mut refs = Vec::new();
    for name in ["README.md", "README.MD", "Readme.md"] {
        let path = root.join(name);
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(path)?;
        let lines = content.lines().collect::<Vec<_>>();
        let mut capture = false;
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                let heading = trimmed.trim_start_matches('#').trim().to_ascii_lowercase();
                capture = matches!(heading.as_str(), "non-goal" | "non-goals");
                continue;
            }
            if capture && !trimmed.is_empty() {
                let value = trimmed.trim_start_matches(['-', '*']).trim().to_owned();
                if !value.is_empty() {
                    values.push(truncate_bytes(&value, 160));
                    refs.push(format!("file:{name}#L{}-L{}", index + 1, index + 1));
                    if values.len() == 3 {
                        return Ok((values, refs));
                    }
                }
            }
        }
    }
    Ok((values, refs))
}

fn first_non_heading_sentence(content: &str) -> Option<(String, usize, usize)> {
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(['[', '!']) {
            continue;
        }
        let sentence = trimmed
            .split_inclusive(['.', '!', '?'])
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_owned();
        if !sentence.is_empty() {
            return Some((sentence, index + 1, index + 1));
        }
    }
    None
}

fn target_cues(value: &str) -> Result<Vec<CueBinding>, EngineError> {
    normalize_bindings(
        vec![CueBinding {
            cue_kind: CueKind::Concept,
            cue_value: value.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "when orienting to this project".to_owned(),
        }],
        None,
    )
    .map_err(|error| EngineError::WriteRejected(error.to_string()))
}

fn file_path_from_ref(reference: &str) -> Option<String> {
    reference
        .strip_prefix("file:")
        .map(|value| value.split('#').next().unwrap_or(value))
        .map(|value| value.strip_suffix(":module-doc").unwrap_or(value))
        .map(normalize_relative_path)
        .filter(|path| !path.is_empty())
}

fn normalize_relative_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_owned()
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

fn inputs_hash<T: Serialize>(value: &T) -> Result<String, EngineError> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
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

fn rejected_budget<T>(kind: &str, limit: u32, body: &str) -> Result<T, EngineError> {
    Err(EngineError::WriteRejected(format!(
        "{kind} exceeds {limit} token units after deterministic trimming (actual {})",
        ul_token_estimate(body)
    )))
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

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[must_use]
pub fn canonical_project_root(runtime_root: &Path) -> PathBuf {
    if runtime_root.file_name().and_then(|value| value.to_str()) == Some(".eliot-governor") {
        runtime_root.parent().unwrap_or(runtime_root).to_path_buf()
    } else {
        runtime_root.to_path_buf()
    }
}
