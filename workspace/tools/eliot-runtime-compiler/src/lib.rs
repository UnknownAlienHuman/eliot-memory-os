use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PLAN_ID: &str = "D-01:plan-v2";
const EXPECTED_MANIFEST_SHA256: &str =
    "4f53344519857e3237379fc26d6bc839f683271347bdc1d2110aa02798ee1d89";
const EXPECTED_PAYLOAD_ROOT_SHA256: &str =
    "32e3f3b3193bc081eba15cdd199aac5dcbdb819bd9848ea2a47ffd7c1075918d";
const EXPECTED_ARCHITECTURE_SHA256: &str =
    "58e71a2bdb10925c63d85a708ed768aee8617bed0fb52eb044478ec20ab439d8";
const EXPECTED_IMPLEMENTATION_SHA256: &str =
    "c216fb7f6fdbc62d108c748be6f61ca7ef9e5d24e5bb13af2677c31a58460c0b";
const EXPECTED_RUNTIME_SHA256: &str =
    "8cee5d0fb4fa58bf37730b9a92edf1a1e37d83695c62febfabb4e0450a3814bf";
const EXPECTED_TEMPLATE_SHA256: &str =
    "154b63ab7583dcd07dbd5e62ae2781c73b96332ceac1f1dafe6ac5c27b475c74";
const EXPECTED_WORK_GRAPH_SHA256: &str =
    "2e82caaf35d95bcf20ff168d6c881ac8626bec26d5393a3a87bb75e9b19cae52";
const EXPECTED_WORK_GRAPH_ARRAY_SHA256: &str =
    "2cc172ea0b4d1ab7a884fffedd73e0d44d5ca13c2bfb6aa65b93d3a43bc2d929";
const GLOBAL_COMPOSITION_PROFILES: [&str; 5] = [
    "CONTROL_BOOTABLE",
    "SPINE_FUNCTIONAL",
    "D2_OPERATIONAL",
    "D3A_ORIENTATION",
    "FULL_COMPOSITION",
];
const ALLOWED_PORT_EXTERNALS: [&str; 3] = [
    "external:eliot_research_system",
    "external:surrealdb_process",
    "external:windows_scm",
];
const MIGRATION_WRITE_SCOPE: &str =
    "exact legacy/donor roots only; target roots remain owned by target Work IDs";
type WorkDependencies = BTreeMap<String, BTreeSet<String>>;
type WorkGraphParts = (BTreeSet<String>, WorkDependencies);

#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub runtime_root: PathBuf,
    pub normative_root: PathBuf,
    pub repository: PathBuf,
    pub report: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct Audit {
    errors: Vec<Value>,
    warnings: Vec<Value>,
    checks: Vec<Value>,
}

impl Audit {
    fn check(&mut self, id: &str, ok: bool, message: &str, details: Value) {
        let error_details = (!ok).then(|| details.clone());
        let mut record = Map::new();
        record.insert("check_id".to_owned(), Value::String(id.to_owned()));
        record.insert("passed".to_owned(), Value::Bool(ok));
        record.insert("message".to_owned(), Value::String(message.to_owned()));
        record.insert("details".to_owned(), details);
        self.checks.push(Value::Object(record));
        if !ok {
            self.errors.push(json!({
                "check_id": id,
                "message": message,
                "details": error_details.unwrap_or(Value::Null)
            }));
        }
    }
    fn error(&mut self, id: &str, message: &str, details: Value) {
        self.check(id, false, message, details);
    }
}

fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, value) in m {
                out.insert(k.clone(), canonical(value));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        _ => v.clone(),
    }
}

fn canonical_bytes(v: &Value) -> Vec<u8> {
    match serde_json::to_vec(&canonical(v)) {
        Ok(bytes) => bytes,
        Err(error) => panic!("JSON Value serialization failed unexpectedly: {error}"),
    }
}

fn read_json(path: &Path) -> Result<(Value, Vec<u8>)> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Ok((value, bytes))
}

fn obj<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key)
}
fn arr<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    obj(v, key)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing array field {key}"))
}
fn strv<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    obj(v, key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {key}"))
}
fn resolve_payload(runtime: &Path, normative: &Path, name: &str) -> Option<PathBuf> {
    if matches!(name, "ELIOT_ARCHITECTURE.md" | "ELIOT_IMPLEMENTATION.md") {
        let p = normative.join(name);
        return p.is_file().then_some(p);
    }
    let p = runtime.join(name);
    p.is_file().then_some(p)
}

fn graph_analysis(
    nodes: &BTreeSet<String>,
    deps: &BTreeMap<String, BTreeSet<String>>,
) -> (bool, Vec<String>, Vec<String>, usize) {
    let mut out: BTreeMap<String, BTreeSet<String>> =
        nodes.iter().map(|n| (n.clone(), BTreeSet::new())).collect();
    let mut indeg: BTreeMap<String, usize> = nodes.iter().map(|n| (n.clone(), 0)).collect();
    for (consumer, providers) in deps {
        for provider in providers {
            if let Some(edges) = out.get_mut(provider) {
                edges.insert(consumer.clone());
            }
            if let Some(d) = indeg.get_mut(consumer) {
                *d += 1;
            }
        }
    }
    let roots: Vec<String> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| n.clone())
        .collect();
    let mut queue: VecDeque<String> = roots.iter().cloned().collect();
    let mut order = Vec::new();
    let mut layer: BTreeMap<String, usize> = roots.iter().map(|n| (n.clone(), 0)).collect();
    while let Some(n) = queue.pop_front() {
        order.push(n.clone());
        for child in out.get(&n).into_iter().flatten() {
            let next_layer = layer.get(&n).copied().unwrap_or(0) + 1;
            let current = layer.entry(child.clone()).or_insert(0);
            *current = (*current).max(next_layer);
            if let Some(d) = indeg.get_mut(child) {
                *d -= 1;
                if *d == 0 {
                    queue.push_back(child.clone());
                }
            }
        }
    }
    let max_layer = layer.values().copied().max().unwrap_or(0) + 1;
    let reachable = reachable(nodes, &out, &roots);
    (order.len() == nodes.len(), order, reachable, max_layer)
}

fn reachable(
    nodes: &BTreeSet<String>,
    out: &BTreeMap<String, BTreeSet<String>>,
    roots: &[String],
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut q: VecDeque<String> = roots.iter().cloned().collect();
    while let Some(n) = q.pop_front() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(next) = out.get(&n) {
            q.extend(next.iter().cloned());
        }
    }
    seen.retain(|n| nodes.contains(n));
    seen.into_iter().collect()
}

fn ancestors(node: &str, deps: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut q: VecDeque<String> = deps.get(node).into_iter().flatten().cloned().collect();
    while let Some(n) = q.pop_front() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(next) = deps.get(&n) {
            q.extend(next.iter().cloned());
        }
    }
    seen
}

fn strict_strings(v: &Value, allow_empty: bool, field: &str) -> Result<BTreeSet<String>> {
    strict_string_set(v, allow_empty)
        .ok_or_else(|| anyhow!("{field} must be a unique nonblank string array"))
}

fn strict_string_set(v: &Value, allow_empty: bool) -> Option<BTreeSet<String>> {
    let values = v.as_array()?;
    if !allow_empty && values.is_empty() {
        return None;
    }
    let mut result = BTreeSet::new();
    for value in values {
        let string = value.as_str()?;
        if string.trim().is_empty() || !result.insert(string.to_owned()) {
            return None;
        }
    }
    Some(result)
}

fn known_port_owner(owner: &str, nodes: &BTreeSet<String>) -> bool {
    nodes.contains(owner) || ALLOWED_PORT_EXTERNALS.contains(&owner)
}

fn profile_port_set(
    profile: &Value,
    field: &str,
    known_ports: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    let rows = profile.get(field)?.as_array()?;
    let mut ports = BTreeSet::new();
    for row in rows {
        let port = row.get("port_id")?.as_str()?;
        if port.trim().is_empty() || !known_ports.contains(port) || !ports.insert(port.to_owned()) {
            return None;
        }
    }
    Some(ports)
}

// Cross-document profile coverage is cohesive and must not partially succeed.
#[allow(clippy::too_many_lines)]
fn provider_profile_projection(
    readiness: &Value,
    composition: &Value,
    known_ports: &BTreeSet<String>,
    catalog_active: &BTreeSet<(String, String)>,
) -> Vec<String> {
    let mut bad = Vec::new();
    let mut readiness_profiles = BTreeSet::new();
    let mut readiness_active = BTreeSet::new();
    let mut readiness_unavailable = BTreeSet::new();
    let Some(profile_rows) = readiness
        .get("composition_profile_records")
        .and_then(Value::as_array)
    else {
        bad.push("readiness:composition_profile_records".to_owned());
        return bad;
    };
    for profile in profile_rows {
        let Some(profile_id) = profile.get("global_profile").and_then(Value::as_str) else {
            bad.push("readiness:global_profile".to_owned());
            continue;
        };
        if !GLOBAL_COMPOSITION_PROFILES.contains(&profile_id)
            || !readiness_profiles.insert(profile_id.to_owned())
        {
            bad.push(format!("readiness:global_profile:{profile_id}"));
        }
        let Some(active) = profile_port_set(profile, "active_runtime_ports", known_ports) else {
            bad.push(format!("readiness:{profile_id}:active_runtime_ports"));
            continue;
        };
        let Some(unavailable) =
            profile_port_set(profile, "declared_unavailable_runtime_ports", known_ports)
        else {
            bad.push(format!(
                "readiness:{profile_id}:declared_unavailable_runtime_ports"
            ));
            continue;
        };
        if !active.is_disjoint(&unavailable) {
            bad.push(format!("readiness:{profile_id}:active_unavailable_overlap"));
        }
        readiness_active.extend(active.into_iter().map(|port| (port, profile_id.to_owned())));
        readiness_unavailable.extend(
            unavailable
                .into_iter()
                .map(|port| (port, profile_id.to_owned())),
        );
    }
    let expected_profiles: BTreeSet<String> = GLOBAL_COMPOSITION_PROFILES
        .iter()
        .map(|profile| (*profile).to_owned())
        .collect();
    if readiness_profiles != expected_profiles {
        bad.push("readiness:profile_universe".to_owned());
    }
    if &readiness_active != catalog_active {
        bad.push(format!(
            "provider:active_profile_projection:{}:{}",
            catalog_active.len(),
            readiness_active.len()
        ));
    }
    let catalog_profiles: BTreeSet<String> = catalog_active
        .iter()
        .map(|(_, profile)| profile.clone())
        .collect();
    if catalog_profiles != expected_profiles {
        bad.push("provider:profile_universe".to_owned());
    }

    let mut manifest_profiles = BTreeSet::new();
    let mut binary_profiles = BTreeSet::new();
    let mut binary_covered = BTreeSet::new();
    let mut binary_active = BTreeSet::new();
    let Some(manifests) = composition.get("manifests").and_then(Value::as_array) else {
        bad.push("binary:manifests".to_owned());
        return bad;
    };
    for manifest in manifests {
        match manifest.get("profile").and_then(Value::as_str) {
            Some(profile) if GLOBAL_COMPOSITION_PROFILES.contains(&profile) => {
                manifest_profiles.insert(profile.to_owned());
            }
            _ => bad.push("binary:manifest_profile".to_owned()),
        }
        let Some(bindings) = manifest
            .get("runtime_port_bindings")
            .and_then(Value::as_array)
        else {
            bad.push("binary:runtime_port_bindings".to_owned());
            continue;
        };
        for binding in bindings {
            let Some(port) = binding.get("port_id").and_then(Value::as_str) else {
                bad.push("binary:port_id".to_owned());
                continue;
            };
            if !known_ports.contains(port) {
                bad.push(format!("binary:unknown_port:{port}"));
            }
            let Some(states) = binding
                .get("global_profile_states")
                .and_then(Value::as_array)
            else {
                bad.push(format!("binary:{port}:global_profile_states"));
                continue;
            };
            let mut binding_profiles = BTreeSet::new();
            for state in states {
                let Some(profile) = state.get("global_profile").and_then(Value::as_str) else {
                    bad.push(format!("binary:{port}:global_profile"));
                    continue;
                };
                let state_value = state.get("state").and_then(Value::as_str);
                if !GLOBAL_COMPOSITION_PROFILES.contains(&profile)
                    || !binding_profiles.insert(profile.to_owned())
                    || !matches!(state_value, Some("ACTIVE" | "DECLARED_UNAVAILABLE"))
                {
                    bad.push(format!("binary:{port}:{profile}:state"));
                    continue;
                }
                binary_profiles.insert(profile.to_owned());
                let pair = (port.to_owned(), profile.to_owned());
                binary_covered.insert(pair.clone());
                if state_value == Some("ACTIVE") {
                    binary_active.insert(pair);
                }
            }
        }
    }
    if binary_profiles != expected_profiles {
        bad.push("binary:profile_universe".to_owned());
    }
    if manifest_profiles != expected_profiles {
        bad.push("binary:manifest_profile_universe".to_owned());
    }
    let readiness_covered: BTreeSet<(String, String)> = readiness_active
        .union(&readiness_unavailable)
        .cloned()
        .collect();
    if binary_covered != readiness_covered {
        bad.push(format!(
            "binary:profile_coverage:{}:{}",
            binary_covered.len(),
            readiness_covered.len()
        ));
    }
    if !binary_active.is_subset(catalog_active) {
        bad.push("binary:active_outside_catalog".to_owned());
    }
    bad
}

// ACTIVE readiness rows select exact binary manifests and exact port-state evidence.
#[allow(clippy::too_many_lines)]
fn binary_active_alignment_issues(
    readiness: &Value,
    composition: &Value,
    known_ports: &BTreeSet<String>,
) -> Vec<Value> {
    let mut issues = Vec::new();
    let Some(profile_rows) = readiness
        .get("composition_profile_records")
        .and_then(Value::as_array)
    else {
        return vec![json!({"field":"readiness.composition_profile_records"})];
    };
    let Some(manifests) = composition.get("manifests").and_then(Value::as_array) else {
        return vec![json!({"field":"composition.manifests"})];
    };
    let mut manifests_by_id: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for manifest in manifests {
        match manifest.get("manifest_id").and_then(Value::as_str) {
            Some(id) if !id.trim().is_empty() => {
                manifests_by_id.entry(id).or_default().push(manifest);
            }
            _ => issues.push(json!({"field":"manifest_id"})),
        }
    }
    for profile_row in profile_rows {
        let Some(profile) = profile_row.get("global_profile").and_then(Value::as_str) else {
            issues.push(json!({"field":"global_profile"}));
            continue;
        };
        let Some(selected_manifests) = profile_row
            .get("selected_binary_manifests")
            .and_then(Value::as_object)
        else {
            issues.push(json!({"profile":profile,"field":"selected_binary_manifests"}));
            continue;
        };
        let Some(active_ports) = profile_row
            .get("active_runtime_ports")
            .and_then(Value::as_array)
        else {
            issues.push(json!({"profile":profile,"field":"active_runtime_ports"}));
            continue;
        };
        for active_port in active_ports {
            let Some(port) = active_port.get("port_id").and_then(Value::as_str) else {
                issues.push(json!({"profile":profile,"field":"port_id"}));
                continue;
            };
            if !known_ports.contains(port) {
                issues.push(json!({"profile":profile,"port_id":port,"field":"known_port"}));
            }
            let Some(participants) = strict_string_set(
                active_port
                    .get("selected_participants")
                    .unwrap_or(&Value::Null),
                false,
            ) else {
                issues.push(
                    json!({"profile":profile,"port_id":port,"field":"selected_participants"}),
                );
                continue;
            };
            for participant in participants {
                let Some(manifest_id) = selected_manifests
                    .get(&participant)
                    .and_then(Value::as_str)
                    .filter(|id| !id.trim().is_empty())
                else {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"field":"selected_binary_manifest"}));
                    continue;
                };
                let Some(selected) = manifests_by_id.get(manifest_id) else {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"manifest_resolution"}));
                    continue;
                };
                if selected.len() != 1 {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"manifest_uniqueness","actual":selected.len()}));
                    continue;
                }
                let manifest = selected[0];
                if manifest.get("work_id").and_then(Value::as_str) != Some(participant.as_str()) {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"manifest_identity"}));
                    continue;
                }
                let Some(bindings) = manifest
                    .get("runtime_port_bindings")
                    .and_then(Value::as_array)
                else {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"runtime_port_bindings"}));
                    continue;
                };
                let matching_bindings: Vec<&Value> = bindings
                    .iter()
                    .filter(|binding| binding.get("port_id").and_then(Value::as_str) == Some(port))
                    .collect();
                if matching_bindings.len() != 1 {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"binding_uniqueness","actual":matching_bindings.len()}));
                    continue;
                }
                let Some(states) = matching_bindings[0]
                    .get("global_profile_states")
                    .and_then(Value::as_array)
                else {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"global_profile_states"}));
                    continue;
                };
                let matching_states: Vec<&Value> = states
                    .iter()
                    .filter(|state| {
                        state.get("global_profile").and_then(Value::as_str) == Some(profile)
                    })
                    .collect();
                if matching_states.len() != 1 {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"state_uniqueness","actual":matching_states.len()}));
                    continue;
                }
                let state = matching_states[0];
                let missing_peers = strict_string_set(
                    state.get("missing_peer_artifacts").unwrap_or(&Value::Null),
                    true,
                );
                if state.get("state").and_then(Value::as_str) != Some("ACTIVE")
                    || state
                        .get("contract_available_in_manifest")
                        .and_then(Value::as_bool)
                        != Some(true)
                    || missing_peers.is_none_or(|peers| !peers.is_empty())
                {
                    issues.push(json!({"profile":profile,"port_id":port,"participant":participant,"manifest_id":manifest_id,"field":"active_contract_state"}));
                }
            }
        }
    }
    issues
}

fn check_graph(a: &mut Audit, graph: &Value) -> Result<WorkGraphParts> {
    let rows = arr(graph, "graph")?;
    let mut nodes = BTreeSet::new();
    let mut deps = BTreeMap::new();
    for row in rows {
        let id = strv(row, "id")?.to_owned();
        if !nodes.insert(id.clone()) {
            a.error(
                "workgraph.unique_ids",
                "duplicate Work ID",
                json!({"work_id": id}),
            );
        }
        let ds = strict_strings(
            obj(row, "deps").ok_or_else(|| anyhow!("missing deps"))?,
            true,
            "WorkGraph.graph[].deps",
        )?;
        deps.insert(id, ds);
    }
    let unknown: BTreeSet<_> = deps
        .values()
        .flatten()
        .filter(|d| !nodes.contains(*d))
        .cloned()
        .collect();
    a.check(
        "workgraph.endpoints",
        unknown.is_empty(),
        "all WorkGraph dependencies resolve",
        json!({"unknown": unknown}),
    );
    let (acyclic, _order, reached, layers) = graph_analysis(&nodes, &deps);
    let roots: Vec<_> = deps
        .iter()
        .filter(|(_, d)| d.is_empty())
        .map(|(n, _)| n.clone())
        .collect();
    let edges: usize = deps.values().map(BTreeSet::len).sum();
    a.check(
        "workgraph.count",
        nodes.len() == 146,
        "WorkGraph has 146 nodes",
        json!({"actual": nodes.len()}),
    );
    a.check(
        "workgraph.edges",
        edges == 342,
        "WorkGraph has 342 reduced edges",
        json!({"actual": edges}),
    );
    a.check("workgraph.dag", acyclic, "WorkGraph is acyclic", json!({}));
    a.check(
        "workgraph.root",
        roots == ["MIG-00"],
        "MIG-00 is the sole WorkGraph root",
        json!({"roots": roots}),
    );
    a.check(
        "workgraph.reachable",
        reached.len() == nodes.len(),
        "all WorkGraph nodes are reachable",
        json!({"reached": reached.len()}),
    );
    a.check(
        "workgraph.layers",
        layers == 23,
        "WorkGraph has 23 layers",
        json!({"actual": layers}),
    );
    let release = ancestors("E-13", &deps);
    a.check(
        "workgraph.release_ancestors",
        release.len() == 144 && !release.contains("M-08"),
        "E-13 has 144 mandatory ancestors",
        json!({"actual": release.len(), "contains_conditional_m08": release.contains("M-08")}),
    );
    let mut redundant = Vec::new();
    for (consumer, providers) in &deps {
        for p in providers {
            for q in providers {
                if p != q && ancestors(q, &deps).contains(p) {
                    redundant.push(format!("{p}->{consumer}"));
                    break;
                }
            }
        }
    }
    a.check(
        "workgraph.transitive_reduction",
        redundant.is_empty(),
        "WorkGraph is transitively reduced",
        json!({"redundant": redundant}),
    );
    Ok((nodes, deps))
}

fn migration_source_roots(work_id: &str) -> Option<&'static [&'static str]> {
    match work_id {
        "MIG-01" => Some(&["crates/eliot-windows-ipc"]),
        "MIG-02" => Some(&["crates/eliot-store"]),
        "MIG-03" => Some(&["crates/eliot-types"]),
        "MIG-04" => Some(&["crates/eliot-engine"]),
        "MIG-05" => Some(&["crates/eliot-app"]),
        "MIG-06" => Some(&["apps/Eliot.Operator"]),
        "MIG-07" => Some(&["tests", "scripts", ".github"]),
        "MIG-08" => Some(&["docs", "integrations", "skills", "hooks"]),
        _ => None,
    }
}

fn claim_belongs_to_root(claim: &str, root: &str) -> bool {
    claim == root
        || claim.starts_with(&format!("{root}::"))
        || claim.starts_with(&format!("{root}/"))
}

// Projection cross-validation is intentionally kept as one cohesive atomic audit.
#[allow(clippy::too_many_lines)]
fn check_index_plans(
    a: &mut Audit,
    index: &Value,
    plans: &Value,
    nodes: &BTreeSet<String>,
    deps: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let rows = arr(index, "work_items")?;
    let plan_rows = arr(plans, "plans")?;
    let mut index_by = BTreeMap::new();
    for row in rows {
        let id = strv(row, "work_id")?.to_owned();
        if index_by.insert(id.clone(), row).is_some() {
            a.error(
                "index.unique_ids",
                "duplicate Work ID in NormativeWorkIndex",
                json!({"work_id":id}),
            );
        }
    }
    let mut plan_by = BTreeMap::new();
    for row in plan_rows {
        let id = strv(row, "work_id")?.to_owned();
        if plan_by.insert(id.clone(), row).is_some() {
            a.error(
                "plans.unique_ids",
                "duplicate Work ID in CellExecutionPlans",
                json!({"work_id":id}),
            );
        }
    }
    let index_ids: BTreeSet<String> = index_by.keys().cloned().collect();
    let plan_ids: BTreeSet<String> = plan_by.keys().cloned().collect();
    a.check(
        "index.coverage",
        rows.len() == 146 && index_ids == *nodes,
        "NormativeWorkIndex is bijective with WorkGraph",
        json!({"actual": rows.len()}),
    );
    a.check(
        "plans.coverage",
        plan_rows.len() == 146 && plan_ids == *nodes,
        "CellExecutionPlans are bijective with WorkGraph",
        json!({"actual": plan_rows.len()}),
    );
    let mut mismatches = Vec::new();
    let mut migration_claim_bad = Vec::new();
    if plans.get("schema_version").and_then(Value::as_str) != Some("eliot-cell-execution-plans-v3")
    {
        mismatches.push(json!({"field":"schema_version"}));
    }
    if plans.get("acceptance_graph_digest").and_then(Value::as_str)
        != Some(EXPECTED_WORK_GRAPH_SHA256)
    {
        mismatches.push(json!({"field":"acceptance_graph_digest"}));
    }
    for id in nodes {
        let Some(row) = index_by.get(id) else {
            continue;
        };
        let Some(plan) = plan_by.get(id) else {
            continue;
        };
        let row_deps = strict_strings(
            obj(row, "acceptance_dependencies").unwrap_or(&Value::Null),
            true,
            "NormativeWorkIndex.work_items[].acceptance_dependencies",
        )?;
        if row_deps != deps[id] {
            mismatches.push(json!({"work_id":id,"field":"acceptance_dependencies"}));
        }
        let pairs = [
            (
                "causal_property",
                obj(plan, "causal_property"),
                obj(row, "responsibility"),
            ),
            (
                "primary_lifecycle_owner",
                obj(plan, "primary_lifecycle_owner"),
                obj(row, "primary_lifecycle_owner"),
            ),
            (
                "acceptance_dependencies",
                obj(plan, "acceptance_dependencies"),
                obj(row, "acceptance_dependencies"),
            ),
            (
                "required_readiness_gates",
                obj(plan, "required_readiness_gates"),
                obj(row, "readiness_and_activation_gates"),
            ),
            (
                "plan_id",
                obj(plan, "plan_id"),
                obj(row, "cell_execution_plan_ref"),
            ),
        ];
        for (field, left, right) in pairs {
            if left != right {
                mismatches.push(json!({"work_id":id,"field":field}));
            }
        }
        let plan_kind = plan.get("plan_kind").and_then(Value::as_str);
        if !matches!(plan_kind, Some("single_slice" | "split")) {
            mismatches.push(json!({"work_id":id,"field":"plan_kind"}));
        }
        if plan
            .get("fallback")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            mismatches.push(json!({"work_id":id,"field":"fallback"}));
        }
        if strict_string_set(plan.get("invalidation").unwrap_or(&Value::Null), false).is_none() {
            mismatches.push(json!({"work_id":id,"field":"invalidation"}));
        }
        let assembly = plan.get("assembly").unwrap_or(&Value::Null);
        let proof = assembly.get("required_proof");
        if proof != obj(row, "local_proof_profile")
            || proof
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
        {
            mismatches.push(json!({"work_id":id,"field":"required_proof"}));
        }
        let terminal = assembly.get("terminal_policy");
        if terminal != obj(row, "terminal_policy")
            || terminal
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
        {
            mismatches.push(json!({"work_id":id,"field":"terminal_policy"}));
        }
        if assembly
            .get("author_may_integrate_own_candidate")
            .and_then(Value::as_bool)
            != Some(false)
        {
            mismatches
                .push(json!({"work_id":id,"field":"assembly.author_may_integrate_own_candidate"}));
        }
        let expected_cell_assembler = format!("{id}:non_author_assembler");
        let assembler_valid = match plan_kind {
            Some("split") => {
                assembly.get("cell_assembly_owner").and_then(Value::as_str)
                    == Some(expected_cell_assembler.as_str())
            }
            Some("single_slice") => assembly
                .get("cell_assembly_owner")
                .is_some_and(Value::is_null),
            _ => false,
        };
        if !assembler_valid {
            mismatches.push(json!({"work_id":id,"field":"assembly.cell_assembly_owner"}));
        }
        let kind = strv(row, "kind")?;
        let target_kind = matches!(
            kind,
            "target_cell" | "development_control" | "edge_or_scenario" | "release_gate"
        );
        let index_roots = if target_kind {
            strict_string_set(
                obj(row, "source_packages_and_module_roots").unwrap_or(&Value::Null),
                false,
            )
            .unwrap_or_else(|| {
                mismatches
                    .push(json!({"work_id":id,"field":"index.source_packages_and_module_roots"}));
                BTreeSet::new()
            })
        } else {
            BTreeSet::new()
        };
        let declared_legacy_claims = if kind == "migration_facade" {
            let claims = strict_string_set(
                obj(row, "legacy_or_donor_source_claims").unwrap_or(&Value::Null),
                false,
            );
            if claims.is_none() {
                mismatches
                    .push(json!({"work_id":id,"field":"index.legacy_or_donor_source_claims"}));
                migration_claim_bad
                    .push(json!({"work_id":id,"field":"index.legacy_or_donor_source_claims"}));
            }
            claims
        } else {
            None
        };
        let expected_migration_claims = migration_source_roots(id).map(|roots| {
            roots
                .iter()
                .map(|root| (*root).to_owned())
                .collect::<BTreeSet<String>>()
        });
        if kind == "migration_facade" {
            match &expected_migration_claims {
                Some(expected) if declared_legacy_claims.as_ref() == Some(expected) => {}
                Some(expected) => migration_claim_bad.push(json!({
                    "work_id":id,
                    "field":"index.legacy_or_donor_source_claims",
                    "expected":expected,
                    "actual":declared_legacy_claims
                })),
                None => migration_claim_bad
                    .push(json!({"work_id":id,"field":"unexpected_migration_work_id"})),
            }
        }
        let expected_containers = match kind {
            "target_cell" | "development_control" | "edge_or_scenario" | "release_gate" => {
                index_roots.clone()
            }
            "donor_audit" => strict_string_set(
                obj(row, "read_only_source_scope").unwrap_or(&Value::Null),
                false,
            )
            .unwrap_or_else(|| {
                mismatches.push(json!({"work_id":id,"field":"index.read_only_source_scope"}));
                BTreeSet::new()
            }),
            "migration_facade" => expected_migration_claims.clone().unwrap_or_default(),
            "baseline_snapshot" => BTreeSet::new(),
            _ => {
                mismatches.push(json!({"work_id":id,"field":"index.kind"}));
                BTreeSet::new()
            }
        };
        let plan_containers =
            strict_string_set(obj(plan, "source_containers").unwrap_or(&Value::Null), true);
        if plan_containers != Some(expected_containers.clone()) {
            mismatches.push(json!({"work_id":id,"field":"source_containers"}));
        }
        if kind == "migration_facade"
            && plan_containers.as_ref() != expected_migration_claims.as_ref()
        {
            migration_claim_bad.push(json!({"work_id":id,"field":"plan.source_containers"}));
        }
        match kind {
            "donor_audit" => {
                if strict_string_set(plan.get("read_only_scope").unwrap_or(&Value::Null), false)
                    != Some(expected_containers.clone())
                {
                    mismatches.push(json!({"work_id":id,"field":"read_only_scope"}));
                }
                if plan.get("migration_write_scope").is_some() {
                    mismatches.push(json!({"work_id":id,"field":"migration_write_scope"}));
                }
            }
            "migration_facade" => {
                if plan.get("read_only_scope").is_some() {
                    mismatches.push(json!({"work_id":id,"field":"read_only_scope"}));
                }
                if plan.get("migration_write_scope").and_then(Value::as_str)
                    != Some(MIGRATION_WRITE_SCOPE)
                {
                    mismatches.push(json!({"work_id":id,"field":"migration_write_scope"}));
                }
            }
            _ => {
                for field in ["read_only_scope", "migration_write_scope"] {
                    if plan.get(field).is_some() {
                        mismatches.push(json!({"work_id":id,"field":field}));
                    }
                }
            }
        }
        let expected_claims = match kind {
            "migration_facade" => expected_migration_claims.clone().unwrap_or_default(),
            "target_cell" | "development_control" | "edge_or_scenario" | "release_gate" => {
                index_roots
            }
            _ => BTreeSet::new(),
        };
        let assembly_claims = strict_string_set(
            obj(assembly, "package_root_public_surface_claims").unwrap_or(&Value::Null),
            true,
        );
        if assembly_claims != Some(expected_claims.clone()) {
            mismatches
                .push(json!({"work_id":id,"field":"assembly.package_root_public_surface_claims"}));
        }
        if kind == "migration_facade"
            && assembly_claims.as_ref() != expected_migration_claims.as_ref()
        {
            migration_claim_bad
                .push(json!({"work_id":id,"field":"assembly.package_root_public_surface_claims"}));
        }
        let package_owner_valid = if expected_claims.is_empty() {
            assembly
                .get("package_assembly_owner")
                .is_some_and(Value::is_null)
        } else {
            assembly
                .get("package_assembly_owner")
                .and_then(Value::as_str)
                == Some(id.as_str())
        };
        if !package_owner_valid {
            mismatches.push(json!({"work_id":id,"field":"assembly.package_assembly_owner"}));
        }
        let Some(slices) = plan.get("slices").and_then(Value::as_array) else {
            mismatches.push(json!({"work_id":id,"field":"slices"}));
            continue;
        };
        if slices.is_empty() {
            mismatches.push(json!({"work_id":id,"field":"slices.empty"}));
        }
        if (matches!(plan_kind, Some("single_slice")) && slices.len() != 1)
            || (matches!(plan_kind, Some("split")) && slices.len() < 2)
        {
            mismatches.push(json!({"work_id":id,"field":"plan_kind.slice_count"}));
        }
        let mut slice_ids = BTreeSet::new();
        let mut providers = BTreeSet::new();
        for slice in slices {
            let slice_id = slice
                .get("slice_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty());
            if slice_id.is_none_or(|value| {
                !value.starts_with(&format!("{id}:")) || !slice_ids.insert(value.to_owned())
            }) {
                mismatches.push(json!({"work_id":id,"field":"slice_id"}));
            }
            let expected_role = match kind {
                "donor_audit" => "read_only",
                "baseline_snapshot" => "read_only_environment_observation",
                _ => "mutating_or_evidence_as_admission_allows",
            };
            let write_claims = strict_string_set(
                slice.get("write_claims").unwrap_or(&Value::Null),
                matches!(kind, "donor_audit" | "baseline_snapshot"),
            );
            if write_claims.is_none() {
                mismatches.push(json!({"work_id":id,"field":"slice.write_claims"}));
            }
            let provider_requirements = strict_string_set(
                slice.get("provider_requirements").unwrap_or(&Value::Null),
                true,
            );
            match provider_requirements {
                Some(requirements) => providers.extend(requirements),
                None => {
                    mismatches.push(json!({"work_id":id,"field":"slice.provider_requirements"}));
                }
            }
            let read_claims_valid = match kind {
                "donor_audit" => {
                    strict_string_set(slice.get("read_claims").unwrap_or(&Value::Null), false)
                        == Some(expected_containers.clone())
                        && write_claims.as_ref().is_some_and(BTreeSet::is_empty)
                }
                "baseline_snapshot" => {
                    slice.get("read_claims")
                        == Some(&json!([
                            "repository",
                            "build",
                            "runtime",
                            "store",
                            "integrations"
                        ]))
                        && strict_string_set(
                            slice.get("read_claims").unwrap_or(&Value::Null),
                            false,
                        )
                        .is_some()
                        && write_claims.as_ref().is_some_and(BTreeSet::is_empty)
                }
                _ => slice.get("read_claims").is_none(),
            };
            if !read_claims_valid {
                mismatches.push(json!({"work_id":id,"field":"slice.read_claims"}));
            }
            for field in [
                "causal_subproperty",
                "expected_output",
                "local_proof",
                "role",
            ] {
                if slice
                    .get(field)
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    mismatches.push(json!({"work_id":id,"field":format!("slice.{field}")}));
                }
            }
            if !slice
                .get("may_run_in_parallel_with_siblings")
                .is_some_and(Value::is_boolean)
            {
                mismatches
                    .push(json!({"work_id":id,"field":"slice.may_run_in_parallel_with_siblings"}));
            }
            if slice.get("local_proof") != assembly.get("required_proof") {
                mismatches.push(json!({"work_id":id,"field":"slice.local_proof"}));
            }
            if slice.get("expected_output").and_then(Value::as_str)
                != Some("immutable slice candidate plus raw proof/evidence")
            {
                mismatches.push(json!({"work_id":id,"field":"slice.expected_output"}));
            }
            if slice.get("role").and_then(Value::as_str) != Some(expected_role) {
                mismatches.push(json!({"work_id":id,"field":"slice.role"}));
            }
            if kind == "migration_facade" {
                match (write_claims.as_ref(), expected_migration_claims.as_ref()) {
                    (Some(claims), Some(expected_roots)) => {
                        for claim in claims {
                            let owner_count = expected_roots
                                .iter()
                                .filter(|root| claim_belongs_to_root(claim, root))
                                .count();
                            if owner_count != 1 {
                                migration_claim_bad.push(json!({
                                    "work_id":id,
                                    "field":"slice.write_claims.root_ownership",
                                    "claim":claim,
                                    "owner_count":owner_count
                                }));
                            }
                        }
                        for root in expected_roots {
                            if !claims
                                .iter()
                                .any(|claim| claim_belongs_to_root(claim, root))
                            {
                                migration_claim_bad.push(json!({
                                    "work_id":id,
                                    "field":"slice.write_claims.root_coverage",
                                    "root":root
                                }));
                            }
                        }
                    }
                    _ => {
                        migration_claim_bad
                            .push(json!({"work_id":id,"field":"slice.write_claims"}));
                    }
                }
            }
            for claim in write_claims.as_ref().into_iter().flatten() {
                if !expected_containers
                    .iter()
                    .any(|root| claim_belongs_to_root(claim, root))
                {
                    mismatches
                        .push(json!({"work_id":id,"field":"slice.write_claims","claim":claim}));
                }
            }
        }
        if providers != row_deps {
            mismatches.push(json!({"work_id":id,"field":"slice.provider_requirements"}));
        }
    }
    a.check(
        "index.plan_semantics",
        mismatches.is_empty(),
        "Cell plans equal their index rows",
        json!({"mismatches":mismatches}),
    );
    a.check(
        "migration.source_claim_bijection",
        migration_claim_bad.is_empty(),
        "migration index, plan, assembly, and slice claims equal pinned physical roots",
        json!({"bad":migration_claim_bad}),
    );
    Ok(())
}

// Binding coverage and its reverse index must be decided by one atomic audit.
#[allow(clippy::too_many_lines)]
fn check_bindings(
    a: &mut Audit,
    binding_doc: &Value,
    index: &Value,
    nodes: &BTreeSet<String>,
    deps: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let bindings = arr(binding_doc, "bindings")?;
    let mut ids = BTreeSet::new();
    let mut accepted = BTreeMap::<(String, String), usize>::new();
    let mut by_consumer = BTreeMap::<String, BTreeSet<String>>::new();
    let mut semantic_bad = Vec::new();
    let mut endpoint_bad = Vec::new();
    let allowed_external_providers = BTreeSet::from([
        "external:agent_host",
        "external:user_session_bootstrap",
        "external:user_shell",
        "external:windows_scm",
        "external:windows_task_scheduler",
    ]);
    for b in bindings {
        let bid = strv(b, "binding_id")?.to_owned();
        if !ids.insert(bid.clone()) {
            a.error(
                "bindings.unique_ids",
                "duplicate typed binding ID",
                json!({"binding_id":bid}),
            );
        }
        let consumer = strv(b, "consumer_work_id")?;
        let provider = strv(b, "provider_work_id")?;
        by_consumer
            .entry(consumer.to_owned())
            .or_default()
            .insert(bid.clone());
        if !nodes.contains(consumer) {
            endpoint_bad.push(format!("{bid}:consumer:{consumer}"));
        }
        let external_allowed = allowed_external_providers.contains(provider)
            && b.get("relation").and_then(Value::as_str) == Some("external_lifecycle_root");
        if !nodes.contains(provider) && !external_allowed {
            endpoint_bad.push(format!("{bid}:provider:{provider}"));
        }
        for field in [
            "relation",
            "invalidation",
            "required_milestone",
            "first_proof",
            "unsupported_or_degraded_behavior",
        ] {
            let valid = if field == "invalidation" {
                b.get(field).and_then(Value::as_array).is_some_and(|items| {
                    !items.is_empty()
                        && items
                            .iter()
                            .all(|item| item.as_str().is_some_and(|value| !value.trim().is_empty()))
                })
            } else {
                b.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            };
            if !valid {
                semantic_bad.push(json!({"binding_id":bid,"field":field}));
            }
        }
        if b.get("acceptance_edge").and_then(Value::as_bool) == Some(true) {
            let p = provider.to_owned();
            let c = consumer.to_owned();
            *accepted.entry((p, c.clone())).or_default() += 1;
            if b.get("semantic_purpose")
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
            {
                semantic_bad.push(json!({"binding_id":bid,"field":"semantic_purpose"}));
            }
        }
    }
    let mut expected = BTreeMap::new();
    for (c, ps) in deps {
        for p in ps {
            expected.insert((p.clone(), c.clone()), 1usize);
        }
    }
    a.check(
        "bindings.acceptance_edges",
        accepted == expected,
        "typed acceptance bindings equal every WorkGraph edge",
        json!({"actual":accepted.len(),"expected":expected.len()}),
    );
    let mut ref_bad = Vec::new();
    for row in arr(index, "work_items")? {
        let id = strv(row, "work_id")?;
        let refs = strict_strings(
            obj(row, "provider_binding_refs").unwrap_or(&Value::Null),
            true,
            "NormativeWorkIndex.work_items[].provider_binding_refs",
        )?;
        if refs != by_consumer.get(id).cloned().unwrap_or_default() {
            ref_bad.push(id.to_owned());
        }
    }
    a.check(
        "bindings.index_refs",
        ref_bad.is_empty(),
        "index provider binding refs are exact",
        json!({"work_ids":ref_bad}),
    );
    a.check(
        "bindings.work_ids",
        endpoint_bad.is_empty(),
        "binding endpoints resolve",
        json!({"bad":endpoint_bad}),
    );
    a.check(
        "bindings.semantic_fields",
        semantic_bad.is_empty(),
        "acceptance bindings carry typed semantic fields",
        json!({"bad":semantic_bad}),
    );
    Ok(())
}

// Port shape, ownership, participants, and reverse references form one validator.
#[allow(clippy::too_many_lines)]
fn check_provider_ports(
    a: &mut Audit,
    binding_doc: &Value,
    readiness: &Value,
    composition: &Value,
    index: &Value,
    nodes: &BTreeSet<String>,
) -> Result<()> {
    let ports = arr(binding_doc, "runtime_port_catalog")?;
    let mut port_ids = BTreeSet::new();
    let mut port_bad = Vec::new();
    if binding_doc.get("schema_version").and_then(Value::as_str)
        != Some("eliot-provider-surface-bindings-v6")
    {
        port_bad.push("document:schema_version".to_owned());
    }
    let mut catalog_active = BTreeSet::<(String, String)>::new();
    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for port in ports {
        let pid = strv(port, "port_id")?;
        if pid.trim().is_empty() {
            port_bad.push("port_id:empty".to_owned());
        }
        if !port_ids.insert(pid.to_owned()) {
            port_bad.push(format!("{pid}:duplicate"));
        }
        for field in [
            "protocol",
            "direction",
            "authority_ceiling",
            "unavailable_behavior",
        ] {
            if port
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|value| value.trim().is_empty())
            {
                port_bad.push(format!("{pid}:{field}"));
            }
        }
        if port
            .get("contract_owner")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            port_bad.push(format!("{pid}:contract_owner"));
        }
        if !port
            .get("phase_owners")
            .and_then(Value::as_object)
            .is_some_and(|owners| {
                !owners.is_empty()
                    && owners
                        .values()
                        .all(|owner| owner.as_str().is_some_and(|value| !value.trim().is_empty()))
            })
        {
            port_bad.push(format!("{pid}:phase_owners"));
        }
        if port
            .get("artifact_participants")
            .and_then(Value::as_object)
            .is_none_or(serde_json::Map::is_empty)
        {
            port_bad.push(format!("{pid}:artifact_participants"));
        }
        match strict_string_set(
            port.get("active_global_composition_profiles")
                .unwrap_or(&Value::Null),
            false,
        ) {
            Some(profiles)
                if profiles
                    .iter()
                    .all(|profile| GLOBAL_COMPOSITION_PROFILES.contains(&profile.as_str())) =>
            {
                catalog_active.extend(
                    profiles
                        .into_iter()
                        .map(|profile| (pid.to_owned(), profile)),
                );
            }
            _ => port_bad.push(format!("{pid}:active_global_composition_profiles")),
        }
        match strict_string_set(
            port.get("external_participants").unwrap_or(&Value::Null),
            true,
        ) {
            Some(externals)
                if externals
                    .iter()
                    .all(|external| ALLOWED_PORT_EXTERNALS.contains(&external.as_str())) => {}
            _ => port_bad.push(format!("{pid}:external_participants")),
        }
        if let Some(owner) = port.get("contract_owner").and_then(Value::as_str) {
            if nodes.contains(owner) {
                expected
                    .entry(owner.to_owned())
                    .or_default()
                    .insert(format!("{pid}:contract_owner"));
            } else if !known_port_owner(owner, nodes) {
                port_bad.push(format!("{pid}:contract_owner:{owner}"));
            }
        }
        if let Some(owners) = port.get("phase_owners").and_then(Value::as_object) {
            for (phase, owner) in owners {
                if let Some(owner) = owner.as_str() {
                    if nodes.contains(owner) {
                        expected
                            .entry(owner.to_owned())
                            .or_default()
                            .insert(format!("{pid}:phase:{phase}"));
                    } else if !known_port_owner(owner, nodes) {
                        port_bad.push(format!("{pid}:phase:{phase}:{owner}"));
                    }
                }
            }
        }
        if let Some(participants) = port.get("artifact_participants").and_then(Value::as_object) {
            for (work, role) in participants {
                if nodes.contains(work) {
                    if role.as_str().is_none_or(|value| value.trim().is_empty()) {
                        port_bad.push(format!("{pid}:participant:{work}:role"));
                    }
                    expected.entry(work.to_owned()).or_default().insert(format!(
                        "{pid}:artifact:{work}:{}",
                        role.as_str().unwrap_or("")
                    ));
                } else {
                    port_bad.push(format!("{pid}:participant:{work}"));
                }
            }
        }
        let participants = port.get("artifact_participants").and_then(Value::as_object);
        let Some(legacy) = port.get("legacy_shorthand").and_then(Value::as_object) else {
            port_bad.push(format!("{pid}:legacy_shorthand"));
            continue;
        };
        let consumer = legacy.get("consumer_work_id").and_then(Value::as_str);
        let consumer_artifact = legacy
            .get("consumer_artifact_work_id")
            .and_then(Value::as_str);
        if consumer.is_none_or(|work| {
            work.trim().is_empty()
                || consumer_artifact != Some(work)
                || participants.is_none_or(|values| !values.contains_key(work))
        }) {
            port_bad.push(format!("{pid}:legacy_shorthand:consumer"));
        }
        let provider = legacy.get("provider_owner").and_then(Value::as_str);
        let provider_artifact = legacy.get("provider_artifact_work_id");
        match provider {
            Some(owner) if ALLOWED_PORT_EXTERNALS.contains(&owner) => {
                if !provider_artifact.is_some_and(Value::is_null) {
                    port_bad.push(format!("{pid}:legacy_shorthand:external_provider_artifact"));
                }
            }
            Some(owner) if nodes.contains(owner) => {
                if provider_artifact
                    .and_then(Value::as_str)
                    .is_none_or(|work| {
                        work.trim().is_empty()
                            || participants.is_none_or(|values| !values.contains_key(work))
                    })
                {
                    port_bad.push(format!("{pid}:legacy_shorthand:provider_artifact"));
                }
            }
            _ => port_bad.push(format!("{pid}:legacy_shorthand:provider_owner")),
        }
    }
    let mut bad = Vec::new();
    for row in arr(index, "work_items")? {
        let work = strv(row, "work_id")?;
        let actual = strict_string_set(row.get("runtime_port_refs").unwrap_or(&Value::Null), true);
        if actual != Some(expected.get(work).cloned().unwrap_or_default()) {
            bad.push(work.to_owned());
        }
    }
    let profile_bad =
        provider_profile_projection(readiness, composition, &port_ids, &catalog_active);
    let alignment_bad = binary_active_alignment_issues(readiness, composition, &port_ids);
    bad.extend(profile_bad);
    bad.extend(port_bad);
    a.check(
        "provider.runtime_port_refs",
        bad.is_empty(),
        "runtime-port index refs are an exact reverse projection",
        json!({"work_ids":bad}),
    );
    a.check(
        "provider.binary_active_alignment",
        alignment_bad.is_empty(),
        "every ACTIVE selected participant has one matching ACTIVE binary binding",
        json!({"status":if alignment_bad.is_empty() {"PASS"} else {"PLAN_GAP"},"bad":alignment_bad}),
    );
    Ok(())
}

// Owner rows and both reverse indexes are validated as one cohesive projection.
#[allow(clippy::too_many_lines)]
fn check_owner_bindings(
    a: &mut Audit,
    owner: &Value,
    index: &Value,
    nodes: &BTreeSet<String>,
) -> Result<()> {
    let object_rows = arr(owner, "object_phase_bindings")?;
    let process_rows = arr(owner, "process_tree_bindings")?;
    let mut object_ids = BTreeSet::new();
    let mut object_keys = BTreeSet::new();
    let mut object_by_work: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unknown_refs = Vec::new();
    for row in object_rows {
        let binding = strv(row, "binding_id")?;
        let key = format!(
            "{}:{}",
            strv(row, "exact_object_kind")?,
            strv(row, "lifecycle_phase")?
        );
        if !object_ids.insert(binding.to_owned()) || !object_keys.insert(key) {
            a.error(
                "owner.object_unique",
                "duplicate object-phase owner binding",
                json!({"binding_id":binding}),
            );
        }
        if let Some(work) = row.get("authoritative_owner").and_then(Value::as_str) {
            if nodes.contains(work) {
                object_by_work
                    .entry(work.to_owned())
                    .or_default()
                    .insert(binding.strip_prefix("owner:").unwrap_or(binding).to_owned());
            } else if !work.starts_with("external:") && !work.starts_with("resolver:") {
                unknown_refs.push(binding.to_owned());
            }
        }
    }
    let fields = [
        "artifact_admission_owner",
        "contract_owner",
        "installation_registration_owner",
        "launch_executor",
        "live_registration_owner",
        "mechanics_owner",
        "operational_lineage_owner",
        "physical_tree_owner",
        "platform_adapter",
        "process_contract",
        "process_implementation",
        "process_role_owner",
    ];
    let mut process_by_work: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in process_rows {
        let tree = strv(row, "tree_class")?;
        for field in fields {
            if let Some(work) = row.get(field).and_then(Value::as_str) {
                if nodes.contains(work) {
                    process_by_work
                        .entry(work.to_owned())
                        .or_default()
                        .insert(format!("{tree}:{field}"));
                } else if !work.starts_with("external:") && !work.starts_with("resolver:") {
                    unknown_refs.push(format!("{tree}:{field}"));
                }
            }
        }
    }
    let mut object_bad = Vec::new();
    let mut process_bad = Vec::new();
    for row in arr(index, "work_items")? {
        let work = strv(row, "work_id")?;
        if strict_strings(
            row.get("owned_object_phase_refs").unwrap_or(&Value::Null),
            true,
            "NormativeWorkIndex.work_items[].owned_object_phase_refs",
        )? != object_by_work.get(work).cloned().unwrap_or_default()
        {
            object_bad.push(work.to_owned());
        }
        if strict_strings(
            row.get("process_tree_phase_refs").unwrap_or(&Value::Null),
            true,
            "NormativeWorkIndex.work_items[].process_tree_phase_refs",
        )? != process_by_work.get(work).cloned().unwrap_or_default()
        {
            process_bad.push(work.to_owned());
        }
    }
    a.check(
        "owner.object_refs",
        object_bad.is_empty(),
        "owned object-phase refs are exact",
        json!({"work_ids":object_bad}),
    );
    a.check(
        "owner.process_refs",
        process_bad.is_empty(),
        "process-tree refs are exact",
        json!({"work_ids":process_bad}),
    );
    a.check(
        "owner.references",
        unknown_refs.is_empty(),
        "owner bindings resolve to WorkGraph IDs",
        json!({"bad":unknown_refs}),
    );
    a.check(
        "owner.object_count",
        object_rows.len() == 144,
        "OwnerBindings has 144 object-phase rows",
        json!({"actual":object_rows.len()}),
    );
    a.check(
        "owner.process_count",
        process_rows.len() == 23,
        "OwnerBindings has 23 process-tree rows",
        json!({"actual":process_rows.len()}),
    );
    let p04_physical: Vec<&str> = process_rows
        .iter()
        .filter(|row| row.get("physical_tree_owner").and_then(Value::as_str) == Some("P-04"))
        .filter_map(|row| row.get("tree_class").and_then(Value::as_str))
        .collect();
    a.check(
        "owner.p04_not_tree_owner",
        p04_physical.is_empty(),
        "P-04 owns process mechanics, never a physical process tree",
        json!({"tree_classes":p04_physical}),
    );
    let critical_owners = [
        ("host_service_process", "external:windows_scm"),
        ("kernel_testd_generation", "P-08"),
        ("testd_descendants", "I-04"),
        ("user_broker_ui_descendant", "A-09"),
        ("watchdog_service_process", "external:windows_scm"),
    ];
    let critical_bad: Vec<Value> = critical_owners
        .into_iter()
        .filter_map(|(tree, expected_owner)| {
            let matching: Vec<&Value> = process_rows
                .iter()
                .filter(|row| row.get("tree_class").and_then(Value::as_str) == Some(tree))
                .collect();
            let actual = matching
                .first()
                .and_then(|row| row.get("physical_tree_owner"))
                .and_then(Value::as_str);
            (matching.len() != 1 || actual != Some(expected_owner)).then(|| {
                json!({"tree_class":tree,"expected":expected_owner,"actual":actual,"rows":matching.len()})
            })
        })
        .collect();
    a.check(
        "owner.critical_process_trees",
        critical_bad.is_empty(),
        "critical physical process-tree owners are exact",
        json!({"bad":critical_bad}),
    );
    Ok(())
}

// Readiness field, recovery, and DAG invariants are one atomic milestone audit.
#[allow(clippy::too_many_lines)]
fn check_readiness(a: &mut Audit, readiness: &Value, nodes: &BTreeSet<String>) -> Result<()> {
    let rows = arr(readiness, "milestones")?;
    let ids: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let mut missing = Vec::new();
    if ids.len() != rows.len() {
        a.error(
            "readiness.unique_ids",
            "duplicate readiness milestone",
            json!({"rows":rows.len(),"ids":ids.len()}),
        );
    }
    let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let id = strv(row, "id")?.to_owned();
        deps.entry(id.clone()).or_default();
        for field in [
            "evidence_requirements",
            "invalidation",
            "providers",
            "publication_phases",
            "observable_property",
            "publication_owner",
            "unsupported_or_degraded_behavior",
        ] {
            if !row.get(field).is_some_and(Value::is_array) {
                if matches!(
                    field,
                    "observable_property"
                        | "publication_owner"
                        | "unsupported_or_degraded_behavior"
                ) {
                    if !row.get(field).is_some_and(Value::is_string) {
                        missing.push(json!({"id":id,"field":field}));
                    }
                } else {
                    missing.push(json!({"id":id,"field":field}));
                }
            }
        }
        for provider in strict_strings(
            row.get("providers").unwrap_or(&Value::Null),
            true,
            "ReadinessMilestones.milestones[].providers",
        )? {
            if ids.contains(&provider) {
                deps.entry(id.clone()).or_default().insert(provider);
            }
        }
        if let Some(phases) = row.get("publication_phases").and_then(Value::as_array) {
            for phase in phases {
                for field in [
                    "phase_id",
                    "evaluation_owner",
                    "execution_owner",
                    "evidence_ceiling",
                ] {
                    if !phase.get(field).is_some_and(Value::is_string) {
                        missing.push(json!({"id":id,"phase_field":field}));
                    }
                }
                if !matches!(
                    phase.get("phase_id").and_then(Value::as_str),
                    Some(
                        "BOOTSTRAP_EXECUTOR_CAPABILITY_PROOF"
                            | "BOOTSTRAP_SHAPE_PUBLICATION"
                            | "CURRENT_PATH_EXECUTED_GATE"
                            | "DERIVED_GATE_PUBLICATION"
                            | "INSTRUMENTED_PUBLICATION"
                            | "INSTRUMENTED_REQUALIFICATION"
                    )
                ) {
                    missing.push(json!({"id":id,"phase_field":"phase_id"}));
                }
            }
        }
    }
    let (acyclic, _, _, _) = graph_analysis(&ids, &deps);
    let cycle = rows.iter().any(|row| {
        row.get("publication_phases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|phase| {
                phase.get("phase_id").and_then(Value::as_str) == Some("BOOTSTRAP_SHAPE_PUBLICATION")
                    && row
                        .get("providers")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .any(|provider| {
                            provider == "I-04:CELL_ACCEPTED" || provider == "I-07:CELL_ACCEPTED"
                        })
            })
    });
    let recovery_ids: BTreeSet<String> = rows
        .iter()
        .filter(|row| {
            row.get("publication_phases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|phase| {
                    phase.get("phase_id").and_then(Value::as_str)
                        == Some("CURRENT_PATH_EXECUTED_GATE")
                })
        })
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let expected_recovery: BTreeSet<String> = [
        "MIG-02:CURRENT_MEMORY_DATA_READY",
        "MIG-04:CURRENT_HARD_BOUNDARY_REPAIR_READY",
        "MIG-05:CURRENT_SPINE_RUNTIME_READY",
        "MIG-07:CURRENT_INSTRUMENT_PATH_READY",
        "D-02:OPERATIONAL_SPINE_PROOF_1_ACCEPTED",
        "D-02:MEMORY_REHABILITATION_GATE_ACCEPTED",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    a.check(
        "readiness.count",
        rows.len() == 63 && ids.len() == 63,
        "63 unique readiness milestones",
        json!({"actual":rows.len()}),
    );
    a.check(
        "readiness.fields",
        missing.is_empty(),
        "readiness milestone fields are complete",
        json!({"bad":missing}),
    );
    a.check(
        "readiness.dag",
        acyclic,
        "readiness provider graph is acyclic",
        json!({}),
    );
    a.check(
        "readiness.no_bootstrap_cycle",
        !cycle,
        "bootstrap publication has no terminal self-cycle",
        json!({}),
    );
    a.check(
        "readiness.recovery_executed",
        recovery_ids == expected_recovery,
        "exact recovery executed gates are explicit",
        json!({"actual":recovery_ids}),
    );
    a.check(
        "readiness.owners",
        rows.iter().all(|row| {
            row.get("publication_owner")
                .and_then(Value::as_str)
                .is_some_and(|owner| nodes.contains(owner))
        }),
        "readiness publication owners resolve",
        json!({}),
    );
    let testd_self_host = rows
        .iter()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("B-06:SPINE_PROFILE_READY"))
        .and_then(|row| row.get("providers"))
        .and_then(Value::as_array)
        .is_some_and(|providers| {
            providers.first().and_then(Value::as_str) == Some("I-04:LOCAL_IMPLEMENTATION_READY")
                && providers.get(1).and_then(Value::as_str)
                    == Some("P-04:LOCAL_IMPLEMENTATION_READY")
        });
    a.check(
        "readiness.testd_self_host",
        testd_self_host,
        "testd self-host begins with both ordered local implementation providers",
        json!({}),
    );
    Ok(())
}

// Composition closure and index reverse references are one atomic audit.
#[allow(clippy::too_many_lines)]
fn check_composition(
    a: &mut Audit,
    composition: &Value,
    package_doc: &Value,
    cargo: &Value,
    index: &Value,
    nodes: &BTreeSet<String>,
) -> Result<()> {
    let manifests = arr(composition, "manifests")?;
    let packages: BTreeMap<String, &Value> = arr(package_doc, "packages")?
        .iter()
        .filter_map(|row| {
            row.get("package_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), row))
        })
        .collect();
    let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in arr(cargo, "edges")? {
        if edge.get("kind").and_then(Value::as_str) == Some("required")
            && let (Some(c), Some(p)) = (
                edge.get("consumer_package").and_then(Value::as_str),
                edge.get("provider_package").and_then(Value::as_str),
            )
        {
            required
                .entry(c.to_owned())
                .or_default()
                .insert(p.to_owned());
        }
    }
    let mut closure_bad = Vec::new();
    let mut package_bad = Vec::new();
    let mut refs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut packages_by_manifest = BTreeMap::<String, BTreeSet<String>>::new();
    for manifest in manifests {
        let id = strv(manifest, "manifest_id")?;
        let direct = strict_strings(
            manifest
                .get("direct_composition_packages")
                .unwrap_or(&Value::Null),
            true,
            "BinaryCompositionManifests.manifests[].direct_composition_packages",
        )?;
        let root = strv(manifest, "root_package")?;
        let mut need = BTreeSet::from([root.to_owned()]);
        need.extend(direct);
        let mut queue: Vec<String> = need.iter().cloned().collect();
        while let Some(package) = queue.pop() {
            for provider in required.get(&package).into_iter().flatten() {
                if need.insert(provider.clone()) {
                    queue.push(provider.clone());
                }
            }
        }
        let got = strict_strings(
            manifest.get("packages").unwrap_or(&Value::Null),
            false,
            "BinaryCompositionManifests.manifests[].packages",
        )?;
        packages_by_manifest.insert(id.to_owned(), got.clone());
        if got != need {
            closure_bad.push(id.to_owned());
        }
        if got.iter().any(|package| !packages.contains_key(package)) {
            package_bad.push(id.to_owned());
        }
        if strv(manifest, "work_id")
            .ok()
            .is_some_and(|work| nodes.contains(work))
        {
            refs.entry(strv(manifest, "work_id")?.to_owned())
                .or_default()
                .insert(id.to_owned());
        }
        for work in strict_strings(
            manifest
                .get("direct_composition_work_ids")
                .unwrap_or(&Value::Null),
            false,
            "BinaryCompositionManifests.manifests[].direct_composition_work_ids",
        )? {
            if nodes.contains(&work) {
                refs.entry(work).or_default().insert(id.to_owned());
            }
        }
    }
    let mut full = BTreeSet::new();
    for manifest in manifests.iter().filter(|manifest| {
        manifest.get("profile").and_then(Value::as_str) == Some("FULL_COMPOSITION")
    }) {
        if let Some(packages) = packages_by_manifest.get(strv(manifest, "manifest_id")?) {
            full.extend(packages.iter().cloned());
        }
    }
    let production: BTreeSet<String> = packages
        .iter()
        .filter(|(_, row)| {
            matches!(
                row.get("production_role").and_then(Value::as_str),
                Some("production_library" | "surface_only")
            )
        })
        .map(|(id, _)| id.clone())
        .collect();
    let missing_full: Vec<_> = production.difference(&full).cloned().collect();
    let mut ref_bad = Vec::new();
    for row in arr(index, "work_items")? {
        let work = strv(row, "work_id")?;
        if strict_strings(
            row.get("binary_manifest_refs").unwrap_or(&Value::Null),
            true,
            "NormativeWorkIndex.work_items[].binary_manifest_refs",
        )? != refs.get(work).cloned().unwrap_or_default()
        {
            ref_bad.push(work.to_owned());
        }
    }
    let manifest_ids: BTreeSet<String> = manifests
        .iter()
        .filter_map(|m| {
            m.get("manifest_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let artifact_values: Vec<&str> = manifests
        .iter()
        .filter_map(|manifest| manifest.get("artifact").and_then(Value::as_str))
        .filter(|artifact| !artifact.trim().is_empty())
        .collect();
    let artifacts: BTreeSet<&str> = artifact_values.iter().copied().collect();
    let u01_manifests: Vec<&Value> = manifests
        .iter()
        .filter(|manifest| manifest.get("work_id").and_then(Value::as_str) == Some("U-01"))
        .collect();
    a.check(
        "composition.count",
        manifests.len() == 36 && manifest_ids.len() == 36,
        "36 unique composition manifests",
        json!({"actual":manifests.len()}),
    );
    a.check(
        "composition.artifact_count",
        artifact_values.len() == manifests.len() && artifacts.len() == 16,
        "composition manifests cover exactly 16 distinct nonblank artifacts",
        json!({"distinct":artifacts.len(),"typed":artifact_values.len(),"manifests":manifests.len()}),
    );
    a.check(
        "composition.winui_profile",
        !u01_manifests.is_empty()
            && u01_manifests.iter().all(|manifest| {
                manifest.get("build_system").and_then(Value::as_str) == Some("dotnet_msbuild")
            }),
        "every U-01 composition manifest uses dotnet_msbuild",
        json!({"u01_manifests":u01_manifests.len()}),
    );
    a.check(
        "composition.package_resolution",
        package_bad.is_empty(),
        "composition package roots resolve",
        json!({"bad":package_bad}),
    );
    a.check(
        "composition.required_closure",
        closure_bad.is_empty(),
        "composition packages equal required closure",
        json!({"bad":closure_bad}),
    );
    a.check(
        "composition.full_reachability",
        missing_full.is_empty(),
        "FULL_COMPOSITION reaches production roots",
        json!({"missing":missing_full}),
    );
    a.check(
        "composition.no_test_support",
        !packages_by_manifest
            .values()
            .flatten()
            .any(|p| p == "crates/foundation/eliot-test-support"),
        "test-support is not in production composition",
        json!({}),
    );
    a.check(
        "composition.index_refs",
        ref_bad.is_empty(),
        "binary manifest reverse refs are exact",
        json!({"work_ids":ref_bad}),
    );
    Ok(())
}

fn check_authority(a: &mut Audit, authority: &Value, owner: &Value) -> Result<()> {
    let profiles = arr(authority, "profiles")?;
    let expected = BTreeSet::from([
        "LEGACY_REPAIR",
        "D0_SHADOW_TARGET",
        "COMPLETE_TARGET_DISPOSABLE",
        "MIGRATION_REHEARSAL",
        "POST_CUTOVER_FINAL",
    ]);
    let actual: BTreeSet<_> = profiles
        .iter()
        .filter_map(|p| p.get("profile").and_then(Value::as_str))
        .collect();
    let object_ids: BTreeSet<_> = arr(owner, "object_phase_bindings")?
        .iter()
        .filter_map(|b| b.get("binding_id").and_then(Value::as_str))
        .collect();
    let process_ids: BTreeSet<_> = arr(owner, "process_tree_bindings")?
        .iter()
        .filter_map(|b| b.get("binding_id").and_then(Value::as_str))
        .collect();
    let mut bad_refs = Vec::new();
    for profile in profiles {
        let active_owner = strict_strings(
            profile
                .get("active_target_owner_phase_binding_refs")
                .unwrap_or(&Value::Null),
            true,
            "AuthorityCompositionGraph.profiles[].active_target_owner_phase_binding_refs",
        )?;
        let inactive_owner = strict_strings(
            profile
                .get("inactive_target_owner_phase_binding_refs")
                .unwrap_or(&Value::Null),
            true,
            "AuthorityCompositionGraph.profiles[].inactive_target_owner_phase_binding_refs",
        )?;
        let active_process = strict_strings(
            profile
                .get("active_target_process_tree_binding_refs")
                .unwrap_or(&Value::Null),
            true,
            "AuthorityCompositionGraph.profiles[].active_target_process_tree_binding_refs",
        )?;
        let inactive_process = match profile.get("inactive_target_process_tree_binding_refs") {
            None | Some(Value::Null) => BTreeSet::new(),
            Some(value) => strict_strings(
                value,
                true,
                "AuthorityCompositionGraph.profiles[].inactive_target_process_tree_binding_refs",
            )?,
        };
        let owner_schema = strict_strings(
            profile
                .get("owner_schema_binding_refs")
                .unwrap_or(&Value::Null),
            true,
            "AuthorityCompositionGraph.profiles[].owner_schema_binding_refs",
        )?;
        if !active_owner.is_disjoint(&inactive_owner)
            || !active_process.is_disjoint(&inactive_process)
        {
            bad_refs.push(format!(
                "{}:active_inactive_overlap",
                profile
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        for reference in active_owner
            .iter()
            .chain(&inactive_owner)
            .chain(&active_process)
            .chain(&inactive_process)
            .chain(&owner_schema)
        {
            if !object_ids.contains(reference.as_str()) && !process_ids.contains(reference.as_str())
            {
                bad_refs.push(reference.clone());
            }
        }
        if profile.get("profile").and_then(Value::as_str) == Some("LEGACY_REPAIR")
            && (!active_owner.is_empty() || !active_process.is_empty())
        {
            bad_refs.push("LEGACY_REPAIR:active_target".to_owned());
        }
    }
    a.check(
        "authority.profiles",
        actual == expected,
        "authority profiles are exact",
        json!({"actual":actual,"expected":expected}),
    );
    a.check(
        "authority.refs",
        bad_refs.is_empty(),
        "authority binding refs resolve",
        json!({"bad":bad_refs}),
    );
    Ok(())
}

fn check_coordination(
    a: &mut Audit,
    coordination: &Value,
    owner: &Value,
    nodes: &BTreeSet<String>,
    seed: &Value,
) -> Result<()> {
    let pair = coordination
        .get("normative_pair_identity")
        .ok_or_else(|| anyhow!("coordination normative identity missing"))?;
    let fixed = seed
        .get("bootstrap_campaign_seed_template")
        .and_then(|v| v.get("template_payload"))
        .and_then(|v| v.get("fixed_identity_values"))
        .ok_or_else(|| anyhow!("seed fixed identity missing"))?;
    let identity_ok = [
        "architecture_sha256",
        "implementation_sha256",
        "runtime_sha256",
    ]
    .iter()
    .all(|key| pair.get(*key) == fixed.get(*key));
    let object_ids: BTreeSet<_> = arr(owner, "object_phase_bindings")?
        .iter()
        .filter_map(|b| b.get("binding_id").and_then(Value::as_str))
        .collect();
    let mut refs_bad = Vec::new();
    for value in coordination
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
    {
        if let Some(reference) = value.get("owner_binding_ref").and_then(Value::as_str)
            && !object_ids.contains(reference)
        {
            refs_bad.push(reference.to_owned());
        }
        for reference in value
            .get("owner_binding_refs")
            .into_iter()
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(Value::as_str)
        {
            if !object_ids.contains(reference) {
                refs_bad.push(reference.to_owned());
            }
        }
        for work in value
            .get("owner_work_ids")
            .into_iter()
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(Value::as_str)
        {
            if !nodes.contains(work) {
                refs_bad.push(work.to_owned());
            }
        }
    }
    let expected_bindings = json!({
        "contract":["C0-06"], "development_control":["D-02","E-18"],
        "production_coordination":["G-11","A-02","A-07","E-11"],
        "context_admission":["M-04"], "human_review_surface":["A-08","U-01","E-08"],
        "change_and_anchor":["G-14","I-05","E-14"], "provenance":["M-06"], "profiles":["I-10"]
    });
    a.check(
        "coordination.identity",
        identity_ok,
        "coordination contract binds normative identity",
        json!({}),
    );
    a.check(
        "coordination.owner_refs",
        refs_bad.is_empty(),
        "coordination owner/work refs resolve",
        json!({"bad":refs_bad}),
    );
    a.check(
        "coordination.work_bindings",
        coordination.get("work_id_bindings") == Some(&expected_bindings),
        "coordination Work-ID bindings are exact",
        json!({}),
    );
    Ok(())
}

fn check_execution(a: &mut Audit, execution: &Value) -> Result<()> {
    let rules = arr(execution, "rules")?;
    let counts = rules
        .iter()
        .filter_map(|r| r.get("class").and_then(Value::as_str))
        .fold(BTreeMap::<String, usize>::new(), |mut map, class| {
            *map.entry(class.to_owned()).or_default() += 1;
            map
        });
    let expected = BTreeMap::from([
        ("Contract".to_owned(), 27),
        ("Default".to_owned(), 6),
        ("Guardrail".to_owned(), 7),
        ("HardBoundary".to_owned(), 14),
    ]);
    let fields_ok = rules.iter().all(|r| {
        [
            "rule_id",
            "class",
            "title",
            "statement",
            "authority_ceiling",
        ]
        .iter()
        .all(|field| r.get(*field).is_some_and(Value::is_string))
    });
    a.check(
        "execution.count",
        rules.len() == 54 && counts == expected,
        "execution rules have exact classes and count",
        json!({"actual":counts}),
    );
    a.check(
        "execution.fields",
        fields_ok,
        "execution rules carry typed fields",
        json!({}),
    );
    Ok(())
}

fn check_conformance(a: &mut Audit, conformance: &Value) -> Result<()> {
    let required = BTreeSet::from([
        "AGENT-COORDINATION-EVIDENCE-SCOPE-01",
        "AGENT-COORDINATION-EXISTING-OWNERS-01",
        "ARCHITECTURE-COVERAGE-CLOSED-01",
        "BOOTSTRAP-CAMPAIGN-SEED-01",
        "BOOTSTRAP-SHIP-ALL-01",
        "CELL-PLAN-INDEX-SEMANTIC-BIJECTION-01",
        "DELIVERY-VS-RELEASE-01",
        "IMPL-DISP-CODE-GRAPH-01",
        "IMPL-DISP-COMMON-01",
        "IMPL-DISP-ELIOT-IPC-01",
        "IMPL-DISP-PLATFORM-UNIX-01",
        "IMPL-DISP-SCIP-01",
        "IMPL-GAP-WORKSPACE-TOPOLOGY-01",
        "IMPLEMENTATION-COVERAGE-CLOSED-01",
        "INDEX-PROJECTION-REFERENCE-BIJECTION-01",
        "IPC-C4-COMPOSITION-01",
        "MACHINE-VOCABULARY-EXACT-01",
        "MIG-08-ONE-OWNER-01",
        "R5-INDEX-SEMANTIC-BIJECTION-01",
        "RUNTIME-IDENTITY-EXTERNAL-01",
    ]);
    let ids: BTreeSet<_> = arr(conformance, "records")?
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_str))
        .collect();
    a.check(
        "conformance.required_ids",
        ids == required,
        "conformance decision IDs are complete",
        json!({"actual":ids.len()}),
    );
    Ok(())
}

fn check_donor(a: &mut Audit, donor: &Value, nodes: &BTreeSet<String>) -> Result<()> {
    let edges = arr(donor, "edges")?;
    let mut ids = BTreeSet::new();
    let mut bad = Vec::new();
    for edge in edges {
        let id = strv(edge, "edge_id")?;
        if !ids.insert(id.to_owned()) {
            bad.push(id.to_owned());
        }
        let target = id.starts_with("target:");
        let required_fields = if target {
            [
                "donor_work_id",
                "required_state",
                "target_state",
                "authority_ceiling",
            ]
        } else {
            [
                "migration_work_id",
                "donor_work_id",
                "required_state",
                "authority_ceiling",
            ]
        };
        for field in required_fields {
            if !edge.get(field).is_some_and(Value::is_string) {
                bad.push(format!("{id}:{field}"));
            }
        }
        for field in ["migration_work_id", "donor_work_id"] {
            if let Some(work) = edge.get(field).and_then(Value::as_str)
                && !nodes.contains(work)
            {
                bad.push(work.to_owned());
            }
        }
    }
    let mut closure_bad = Vec::new();
    for row in arr(donor, "migration_target_closures")? {
        let work = strv(row, "migration_work_id")?;
        if !nodes.contains(work)
            || !row
                .get("static_required_target_states")
                .is_some_and(Value::is_array)
        {
            closure_bad.push(work.to_owned());
        }
    }
    a.check(
        "donor.edge_refs",
        bad.is_empty(),
        "donor evidence edges are typed and resolve",
        json!({"bad":bad}),
    );
    a.check(
        "donor.closures",
        closure_bad.is_empty(),
        "donor migration closures are typed",
        json!({"bad":closure_bad}),
    );
    Ok(())
}

// Handle and complete coverage checks share the same immutable book line indexes.
#[allow(clippy::too_many_lines)]
fn check_normative_references(
    a: &mut Audit,
    index: &Value,
    nodes: &BTreeSet<String>,
    architecture: &[u8],
    implementation: &[u8],
) -> Result<()> {
    let arch_text = String::from_utf8_lossy(architecture);
    let impl_text = String::from_utf8_lossy(implementation);
    let arch_lines: Vec<&str> = arch_text.lines().collect();
    let impl_lines: Vec<&str> = impl_text.lines().collect();
    let mut bad_handles = Vec::new();
    for row in arr(index, "work_items")? {
        let work = strv(row, "work_id")?;
        if !nodes.contains(work) {
            bad_handles.push(work.to_owned());
            continue;
        }
        for handle in row
            .get("architecture_handles")
            .into_iter()
            .filter_map(Value::as_array)
            .flatten()
        {
            let anchor = strv(handle, "anchor_id")?;
            for line in handle
                .get("occurrence_lines")
                .into_iter()
                .filter_map(Value::as_array)
                .flatten()
                .filter_map(Value::as_u64)
            {
                if line == 0
                    || one_based_line(&arch_lines, line)
                        .is_none_or(|source| !source.contains(anchor))
                {
                    bad_handles.push(format!("{work}:{anchor}:{line}"));
                }
            }
        }
        for handle in row
            .get("implementation_handles")
            .into_iter()
            .filter_map(Value::as_array)
            .flatten()
        {
            let start = handle
                .get("start_line")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let title = strv(handle, "title")?;
            if start == 0
                || one_based_line(&impl_lines, start).is_none_or(|source| !source.contains(title))
            {
                bad_handles.push(format!("{work}:{}", strv(handle, "id")?));
            }
        }
    }
    let architecture_coverage: Vec<&Value> = index
        .get("architecture_section_coverage")
        .into_iter()
        .filter_map(Value::as_array)
        .flatten()
        .collect();
    let implementation_coverage: Vec<&Value> = index
        .get("implementation_section_coverage")
        .into_iter()
        .filter_map(Value::as_array)
        .flatten()
        .collect();
    let mut coverage_bad = Vec::new();
    let arch_ids: BTreeSet<_> = architecture_coverage
        .iter()
        .filter_map(|row| row.get("section_id").and_then(Value::as_str))
        .collect();
    let impl_ids: BTreeSet<_> = implementation_coverage
        .iter()
        .filter_map(|row| row.get("section_id").and_then(Value::as_str))
        .collect();
    if architecture_coverage.len() != 144 || arch_ids.len() != architecture_coverage.len() {
        coverage_bad
            .push(json!({"kind":"architecture_count","actual":architecture_coverage.len()}));
    }
    if implementation_coverage.len() != 532 || impl_ids.len() != implementation_coverage.len() {
        coverage_bad
            .push(json!({"kind":"implementation_count","actual":implementation_coverage.len()}));
    }
    for row in architecture_coverage {
        if row
            .get("normative_document_sha256")
            .is_none_or(|v| v != &Value::String(sha256(architecture)))
            || !section_anchor_valid(row, &arch_lines)
        {
            coverage_bad.push(row.get("section_id").cloned().unwrap_or(Value::Null));
        }
    }
    for row in implementation_coverage {
        if row
            .get("normative_document_sha256")
            .is_none_or(|v| v != &Value::String(sha256(implementation)))
            || !section_anchor_valid(row, &impl_lines)
        {
            coverage_bad.push(row.get("section_id").cloned().unwrap_or(Value::Null));
        }
    }
    a.check(
        "references.handles",
        bad_handles.is_empty(),
        "normative handles resolve exact lines and anchors",
        json!({"bad":bad_handles}),
    );
    a.check(
        "references.coverage",
        coverage_bad.is_empty(),
        "normative section coverage binds document hashes and headings",
        json!({"bad":coverage_bad}),
    );
    Ok(())
}

fn one_based_line<'a>(lines: &'a [&str], line: u64) -> Option<&'a str> {
    let index = usize::try_from(line).ok()?.checked_sub(1)?;
    lines.get(index).copied()
}

fn section_anchor_valid(row: &Value, lines: &[&str]) -> bool {
    let start = row.get("start_line").and_then(Value::as_u64).unwrap_or(0);
    let end = row.get("end_line").and_then(Value::as_u64).unwrap_or(0);
    let title = row.get("title").and_then(Value::as_str).unwrap_or("");
    let Some(start_index) = usize::try_from(start)
        .ok()
        .and_then(|value| value.checked_sub(1))
    else {
        return false;
    };
    let Ok(end_index) = usize::try_from(end) else {
        return false;
    };
    start > 0
        && end >= start
        && end_index <= lines.len()
        && lines
            .get(start_index)
            .is_some_and(|line| line.contains(title))
}

fn check_finish_edges(a: &mut Audit, finish: &Value, graph: &Value, index: &Value) -> Result<()> {
    let terminal_policy_by_work: BTreeMap<String, String> = arr(index, "work_items")?
        .iter()
        .filter_map(|row| {
            Some((
                row.get("work_id")?.as_str()?.to_owned(),
                row.get("terminal_policy")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    let finish_nodes: BTreeSet<String> = arr(finish, "nodes")?
        .iter()
        .filter_map(|node| node.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let edges: BTreeSet<(String, String)> = arr(finish, "edges")?
        .iter()
        .filter_map(|edge| {
            Some((
                edge.get("from")?.as_str()?.to_owned(),
                edge.get("to")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    let mut missing = Vec::new();
    for row in arr(graph, "graph")? {
        let consumer = strv(row, "id")?;
        for provider in strict_strings(
            row.get("deps").unwrap_or(&Value::Null),
            true,
            "WorkGraph.graph[].deps",
        )? {
            if let Some(policy) = terminal_policy_by_work.get(&provider) {
                let terminal = format!("{provider}:{policy}");
                let expected = (terminal, format!("{consumer}:READY"));
                if !edges.contains(&expected) {
                    missing.push(json!({"from":expected.0,"to":expected.1}));
                }
            } else {
                missing.push(json!({"provider":provider,"consumer":consumer}));
            }
        }
    }
    let ready_missing: Vec<_> = terminal_policy_by_work
        .keys()
        .filter(|work| !finish_nodes.contains(&format!("{work}:READY")))
        .cloned()
        .collect();
    let required_terminal_states = [
        "E-13:RELEASE_VERDICT_TERMINAL",
        "M-08:RELEASE_SATISFYING_TERMINAL",
    ];
    let terminal_missing: Vec<_> = required_terminal_states
        .iter()
        .filter(|id| !finish_nodes.contains(**id))
        .collect();
    a.check(
        "finish.acceptance_edges",
        missing.is_empty(),
        "every WorkGraph acceptance edge reaches consumer READY",
        json!({"missing":missing}),
    );
    a.check(
        "finish.required_ready_states",
        ready_missing.is_empty(),
        "every Work ID has a READY state",
        json!({"missing":ready_missing}),
    );
    a.check(
        "finish.required_terminal_states",
        terminal_missing.is_empty(),
        "finish graph exposes required terminal states",
        json!({"missing":terminal_missing}),
    );
    Ok(())
}

// Bootstrap trust bindings are intentionally decided together to prevent partial trust.
#[allow(clippy::too_many_lines)]
fn check_bootstrap_identity(
    a: &mut Audit,
    manifest: &Value,
    seed: &Value,
    manifest_names: &BTreeSet<String>,
    payload_hashes: &Map<String, Value>,
    work: &Value,
    raw_manifest_sha256: &str,
) -> Result<()> {
    a.check(
        "bootstrap.manifest_trust",
        raw_manifest_sha256 == EXPECTED_MANIFEST_SHA256,
        "bundle manifest identity is pinned",
        json!({"actual":raw_manifest_sha256}),
    );
    a.check(
        "bootstrap.payload_root_trust",
        manifest.get("payload_root_sha256").and_then(Value::as_str)
            == Some(EXPECTED_PAYLOAD_ROOT_SHA256),
        "payload root identity is pinned",
        json!({}),
    );
    let excluded = BTreeSet::from([
        "Eliot_Runtime_BundleManifest.json",
        "Eliot_Runtime_Validation.json",
        "Eliot_Runtime_IndependentAudit.json",
    ]);
    let required: BTreeSet<String> = arr(seed, "required_bundle_members")?
        .iter()
        .filter_map(Value::as_str)
        .filter(|name| !excluded.contains(*name))
        .map(str::to_owned)
        .collect();
    a.check(
        "bootstrap.payload_set",
        *manifest_names == required,
        "manifest payload set equals BootstrapSeed required members",
        json!({"missing":required.difference(manifest_names).collect::<Vec<_>>(),"extra":manifest_names.difference(&required).collect::<Vec<_>>() }),
    );
    let semantic: BTreeSet<String> = arr(seed, "semantic_projection_files")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    a.check(
        "bootstrap.semantic_set",
        semantic.is_subset(manifest_names),
        "all semantic projections are shipped payloads",
        json!({}),
    );
    let seed_revision = seed.get("runtime_revision");
    a.check(
        "bootstrap.revision",
        seed_revision == manifest.get("runtime_revision"),
        "seed and manifest runtime revisions match",
        json!({}),
    );
    let campaign = seed
        .get("bootstrap_campaign_seed_template")
        .ok_or_else(|| anyhow!("bootstrap_campaign_seed_template missing"))?;
    let fixed = campaign
        .get("template_payload")
        .ok_or_else(|| anyhow!("template_payload missing"))?;
    let template_hash = campaign
        .get("template_payload_sha256")
        .and_then(Value::as_str);
    let actual_template_hash = sha256(&canonical_bytes(fixed));
    a.check(
        "bootstrap.template_identity",
        template_hash == Some(EXPECTED_TEMPLATE_SHA256)
            && actual_template_hash == EXPECTED_TEMPLATE_SHA256,
        "bootstrap template payload identity matches",
        json!({"actual":actual_template_hash,"expected":EXPECTED_TEMPLATE_SHA256}),
    );
    let fixed_values = fixed
        .get("fixed_identity_values")
        .ok_or_else(|| anyhow!("fixed_identity_values missing"))?;
    let expected_docs = [
        (
            "architecture_sha256",
            "architecture",
            "ELIOT_ARCHITECTURE.md",
        ),
        (
            "implementation_sha256",
            "implementation",
            "ELIOT_IMPLEMENTATION.md",
        ),
        ("runtime_sha256", "runtime", "ELIOT_RUNTIME.md"),
    ];
    let mut doc_bad = Vec::new();
    for (key, seed_doc, file) in expected_docs {
        if fixed_values.get(key).and_then(Value::as_str)
            != payload_hashes.get(file).and_then(Value::as_str)
            || seed
                .get("documents")
                .and_then(|docs| docs.get(seed_doc))
                .and_then(|doc| doc.get("sha256"))
                .and_then(Value::as_str)
                != payload_hashes.get(file).and_then(Value::as_str)
        {
            doc_bad.push(file);
        }
    }
    let graph_hash = payload_hashes
        .get("Eliot_Runtime_WorkGraph.json")
        .and_then(Value::as_str);
    let graph_array_hash = sha256(&canonical_bytes(
        work.get("graph")
            .ok_or_else(|| anyhow!("WorkGraph graph missing"))?,
    ));
    if fixed_values
        .get("work_graph_file_sha256")
        .and_then(Value::as_str)
        != graph_hash
        || fixed_values
            .get("work_graph_array_sha256")
            .and_then(Value::as_str)
            != Some(graph_array_hash.as_str())
    {
        doc_bad.push("Eliot_Runtime_WorkGraph.json");
    }
    a.check(
        "bootstrap.normative_identity",
        doc_bad.is_empty()
            && fixed_values
                .get("architecture_sha256")
                .and_then(Value::as_str)
                == Some(EXPECTED_ARCHITECTURE_SHA256)
            && fixed_values
                .get("implementation_sha256")
                .and_then(Value::as_str)
                == Some(EXPECTED_IMPLEMENTATION_SHA256)
            && fixed_values.get("runtime_sha256").and_then(Value::as_str)
                == Some(EXPECTED_RUNTIME_SHA256)
            && fixed_values
                .get("work_graph_file_sha256")
                .and_then(Value::as_str)
                == Some(EXPECTED_WORK_GRAPH_SHA256)
            && fixed_values
                .get("work_graph_array_sha256")
                .and_then(Value::as_str)
                == Some(EXPECTED_WORK_GRAPH_ARRAY_SHA256),
        "normative books and graph identities match pinned seed",
        json!({"bad":doc_bad}),
    );
    let receipts: BTreeSet<String> = [
        "Eliot_Runtime_Validation.json",
        "Eliot_Runtime_IndependentAudit.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let declared: BTreeSet<String> = manifest
        .get("post_manifest_receipts")
        .into_iter()
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    a.check(
        "bootstrap.receipts",
        declared == receipts,
        "manifest declares exact post-manifest receipts",
        json!({}),
    );
    Ok(())
}

// Package bijection, source gaps, and Cargo graph checks are one package-map audit.
#[allow(clippy::too_many_lines)]
fn check_packages(
    a: &mut Audit,
    package_doc: &Value,
    index: &Value,
    cargo: &Value,
    repository: &Path,
    cargo_manifests: Option<&BTreeMap<PathBuf, String>>,
) -> Result<Vec<Value>> {
    let rows = arr(package_doc, "packages")?;
    let mut packages = BTreeMap::new();
    for row in rows {
        let id = strv(row, "package_id")?.to_owned();
        if packages.insert(id.clone(), row).is_some() {
            a.error(
                "packages.unique_roots",
                "duplicate physical package root",
                json!({"package_id":id}),
            );
        }
    }
    a.check(
        "packages.count",
        rows.len() == 137
            && package_doc.get("schema_version").and_then(Value::as_str)
                == Some("eliot-physical-package-map-v3"),
        "physical package map has 137 unique roots",
        json!({"actual":rows.len(),"schema_version":package_doc.get("schema_version")}),
    );
    let expected_layers: BTreeSet<&str> = ["C0", "C1", "C2", "C3", "C4"].into_iter().collect();
    let actual_layers: BTreeSet<&str> = rows
        .iter()
        .filter_map(|row| row.get("source_layer").and_then(Value::as_str))
        .collect();
    let layer_bad: Vec<Value> = rows
        .iter()
        .filter(|row| {
            row.get("source_layer")
                .and_then(Value::as_str)
                .is_none_or(|layer| !expected_layers.contains(layer))
        })
        .map(|row| row.get("package_id").cloned().unwrap_or(Value::Null))
        .collect();
    a.check(
        "packages.layers",
        layer_bad.is_empty() && actual_layers == expected_layers,
        "every package has one source layer and C0 through C4 are present",
        json!({"actual":actual_layers,"bad":layer_bad}),
    );
    let required_named = BTreeSet::from([
        "crates/kernel/eliot-ipc",
        "crates/instrument/eliot-instrument-scip",
        "crates/instrument/eliot-code-graph",
    ]);
    let missing_named: Vec<_> = required_named
        .iter()
        .filter(|package| !packages.contains_key(**package))
        .copied()
        .collect();
    a.check(
        "packages.required_named",
        missing_named.is_empty(),
        "required named packages are materialized",
        json!({"missing":missing_named}),
    );
    let forbidden_named = [
        "crates/kernel/eliot-platform-unix",
        "crates/foundation/eliot-common",
    ];
    let present_forbidden: Vec<_> = forbidden_named
        .into_iter()
        .filter(|package| packages.contains_key(*package))
        .collect();
    a.check(
        "packages.explicit_nonpackages",
        present_forbidden.is_empty(),
        "explicit Windows-first non-packages remain absent",
        json!({"present":present_forbidden}),
    );
    let blob_split = packages
        .get("crates/storage/eliot-blob-api")
        .and_then(|row| row.get("source_layer"))
        .and_then(Value::as_str)
        == Some("C0")
        && packages
            .get("crates/storage/eliot-blob")
            .and_then(|row| row.get("source_layer"))
            .and_then(Value::as_str)
            == Some("C3");
    a.check(
        "packages.blob_split",
        blob_split,
        "blob API and implementation keep exact roots and layers",
        json!({}),
    );
    let mut expected = BTreeMap::new();
    let mut duplicate_index_roots = Vec::new();
    let index_work_ids: BTreeSet<String> = arr(index, "work_items")?
        .iter()
        .filter_map(|row| {
            row.get("work_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    for row in arr(index, "work_items")? {
        let work = strv(row, "work_id")?;
        for b in arr(row, "package_source_layer_bindings")? {
            let p = strv(b, "package_or_module_root")?.to_owned();
            if expected
                .insert(
                    p.clone(),
                    (work.to_owned(), strv(b, "source_layer")?.to_owned()),
                )
                .is_some()
            {
                duplicate_index_roots.push(p);
            }
        }
    }
    let mut owner_bad = Vec::new();
    for row in rows {
        let package = strv(row, "package_id")?;
        let work = strv(row, "work_id")?;
        for field in [
            "package_root_owner",
            "lifecycle_owner",
            "public_surface_owner",
        ] {
            if row.get(field).and_then(Value::as_str) != Some(work)
                || !index_work_ids.contains(work)
            {
                owner_bad.push(format!("{package}:{field}"));
            }
        }
    }
    let actual: BTreeMap<_, _> = packages
        .iter()
        .filter_map(|(p, r)| {
            Some((
                p.clone(),
                (
                    strv(r, "work_id").ok()?.to_owned(),
                    strv(r, "source_layer").ok()?.to_owned(),
                ),
            ))
        })
        .collect();
    a.check(
        "packages.index_bijection",
        actual == expected && duplicate_index_roots.is_empty() && owner_bad.is_empty(),
        "physical package map equals index package bindings",
        json!({"actual":actual.len(),"expected":expected.len(),"duplicate_index_roots":duplicate_index_roots,"owner_bad":owner_bad}),
    );
    let mut gaps = Vec::new();
    for package_id in packages.keys() {
        let Some(row) = packages.get(package_id) else {
            return Err(anyhow!("package map lost indexed entry {package_id}"));
        };
        let path = repository.join(package_id);
        let kind = row.get("kind").and_then(Value::as_str).unwrap_or("");
        let present = if kind == "dotnet_winui_app" {
            path.is_dir()
        } else {
            path.is_dir() && path.join("Cargo.toml").is_file()
        };
        if !present {
            gaps.push(json!({"package_id":package_id,"work_id":row.get("work_id").cloned().unwrap_or(Value::Null),"source_layer":row.get("source_layer").cloned().unwrap_or(Value::Null),"reason":"target_root_absent"}));
        } else if kind != "dotnet_winui_app"
            && let Some(metadata) = cargo_manifests
        {
            let manifest = path
                .join("Cargo.toml")
                .canonicalize()
                .with_context(|| format!("canonicalize Cargo manifest {}", path.display()))?;
            if !metadata.contains_key(&manifest) {
                gaps.push(json!({"package_id":package_id,"work_id":row.get("work_id").cloned().unwrap_or(Value::Null),"source_layer":row.get("source_layer").cloned().unwrap_or(Value::Null),"reason":"cargo_metadata_manifest_mismatch","manifest":manifest}));
            }
        }
    }
    let mut cargo_pred: BTreeMap<String, BTreeSet<String>> = packages
        .keys()
        .map(|p| (p.clone(), BTreeSet::new()))
        .collect();
    let edges = arr(cargo, "edges")?;
    let mut bad_endpoints = Vec::new();
    let mut inversions = Vec::new();
    let mut test_support_bad = Vec::new();
    let mut ipc_edges = 0usize;
    let mut ipc_composed = 0usize;
    let rank = |s: &str| s.strip_prefix('C').and_then(|x| x.parse::<usize>().ok());
    for e in edges {
        let c = strv(e, "consumer_package")?;
        let p = strv(e, "provider_package")?;
        if !packages.contains_key(c) || !packages.contains_key(p) {
            bad_endpoints.push(json!({"consumer":c,"provider":p}));
        }
        if e.get("kind").and_then(Value::as_str) == Some("required") {
            cargo_pred
                .entry(c.to_owned())
                .or_default()
                .insert(p.to_owned());
        }
        if matches!(
            e.get("kind").and_then(Value::as_str),
            Some("required" | "composition_profile")
        ) && let (Some(cr), Some(pr)) = (
            rank(
                packages
                    .get(c)
                    .and_then(|v| strv(v, "source_layer").ok())
                    .unwrap_or(""),
            ),
            rank(
                packages
                    .get(p)
                    .and_then(|v| strv(v, "source_layer").ok())
                    .unwrap_or(""),
            ),
        ) && cr < pr
        {
            inversions.push(json!({"consumer":c,"provider":p}));
        }
        let kind = e.get("kind").and_then(Value::as_str);
        if p == "crates/foundation/eliot-test-support" && kind != Some("dev_test") {
            test_support_bad.push(json!({"consumer":c,"kind":kind}));
        }
        if c == "bins/eliot-kernel" && p == "crates/kernel/eliot-ipc" {
            ipc_edges += 1;
            if kind == Some("composition_profile") {
                ipc_composed += 1;
            }
        }
    }
    let node_set: BTreeSet<_> = packages.keys().cloned().collect();
    let (acyclic, _, _, _) = graph_analysis(&node_set, &cargo_pred);
    a.check(
        "cargo.endpoints",
        bad_endpoints.is_empty(),
        "Cargo graph endpoints resolve",
        json!({"bad":bad_endpoints}),
    );
    a.check(
        "cargo.required_dag",
        acyclic,
        "required Cargo graph is acyclic",
        json!({}),
    );
    a.check(
        "cargo.layer_direction",
        inversions.is_empty(),
        "Cargo direction follows source layers",
        json!({"inversions":inversions}),
    );
    a.check(
        "cargo.test_support_isolation",
        test_support_bad.is_empty(),
        "eliot-test-support is a provider only on dev_test edges",
        json!({"bad":test_support_bad}),
    );
    a.check(
        "cargo.ipc_composed",
        ipc_edges == 1 && ipc_composed == 1,
        "Kernel selects the IPC implementation exactly once at composition",
        json!({"pair_edges":ipc_edges,"composition_edges":ipc_composed}),
    );
    Ok(gaps)
}

fn check_admission(a: &mut Audit, admission: &Value, nodes: &BTreeSet<String>) -> Result<()> {
    let valid: BTreeSet<_> = [
        "MUTATE",
        "READ_ONLY_EVIDENCE",
        "CONDITIONAL_MUTATE",
        "FROZEN_NO_SOURCE_MUTATION",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let stages = arr(admission, "stages")?;
    a.check(
        "admission.stage_count",
        stages.len() == 7,
        "admission has seven stages",
        json!({"actual":stages.len()}),
    );
    let mut bad = Vec::new();
    for stage in stages {
        let mut seen = BTreeSet::new();
        for row in arr(stage, "source_modes")? {
            let id = strv(row, "work_id")?;
            let mode = strv(row, "source_mode")?;
            seen.insert(id.to_owned());
            if !nodes.contains(id) || !valid.contains(mode) {
                bad.push(json!({"stage":stage.get("id"),"work_id":id,"mode":mode}));
            }
        }
        if seen != *nodes {
            bad.push(json!({"stage":stage.get("id"),"coverage":seen.len()}));
        }
    }
    a.check(
        "admission.coverage",
        bad.is_empty(),
        "every admission stage classifies all Work IDs",
        json!({"bad":bad}),
    );
    Ok(())
}

fn check_state_graph(a: &mut Audit, doc: &Value, name: &str, expected_root: &str) -> Result<()> {
    let rows = arr(doc, "nodes")?;
    let nodes: BTreeSet<_> = rows
        .iter()
        .map(|n| strv(n, "id").map(str::to_owned))
        .collect::<Result<_>>()?;
    a.check(
        &format!("{name}.unique_nodes"),
        nodes.len() == rows.len(),
        "state graph node IDs are unique",
        json!({"rows":rows.len(),"nodes":nodes.len()}),
    );
    let mut deps: BTreeMap<String, BTreeSet<String>> =
        nodes.iter().map(|n| (n.clone(), BTreeSet::new())).collect();
    let mut unknown = Vec::new();
    for e in arr(doc, "edges")? {
        let from = strv(e, "from")?;
        let to = strv(e, "to")?;
        if nodes.contains(from) && nodes.contains(to) {
            deps.entry(to.to_owned())
                .or_default()
                .insert(from.to_owned());
        } else {
            unknown.push(json!({"from":from,"to":to}));
        }
    }
    let (acyclic, _, reached, layers) = graph_analysis(&nodes, &deps);
    let roots: Vec<_> = deps
        .iter()
        .filter(|(_, d)| d.is_empty())
        .map(|(n, _)| n.clone())
        .collect();
    a.check(
        &format!("{name}.dag"),
        acyclic,
        "state graph is acyclic",
        json!({}),
    );
    a.check(
        &format!("{name}.root"),
        roots == [expected_root],
        "state graph has one expected root",
        json!({"roots":roots}),
    );
    a.check(
        &format!("{name}.reachable"),
        reached.len() == nodes.len() && unknown.is_empty(),
        "state graph is fully reachable",
        json!({"reached":reached.len(),"nodes":nodes.len(),"unknown":unknown,"layers":layers}),
    );
    Ok(())
}

fn check_migration(a: &mut Audit, migration: &Value, nodes: &BTreeSet<String>) -> Result<()> {
    let external = arr(migration, "external_prerequisites")?;
    let mut bad = Vec::new();
    let mut destinations = BTreeSet::new();
    let migration_nodes: BTreeSet<String> = arr(migration, "nodes")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    for row in external {
        let destination = strv(row, "destination_state")?;
        if !destinations.insert(destination.to_owned())
            || !migration_nodes.contains(destination)
            || row
                .get("required_external_states")
                .is_none_or(|v| !v.is_array())
        {
            bad.push(destination.to_owned());
        }
        if let Some(required) = row
            .get("required_external_states")
            .and_then(Value::as_array)
        {
            for state in required.iter().filter_map(Value::as_str) {
                if !nodes.contains(state.split(':').next().unwrap_or("")) {
                    bad.push(state.to_owned());
                }
            }
        }
    }
    let forbidden_mig08: Vec<_> = migration_nodes
        .iter()
        .filter(|id| id.starts_with("MIG-08a:") || id.starts_with("MIG-08b:"))
        .cloned()
        .collect();
    let mut outgoing: BTreeMap<String, BTreeSet<String>> = migration_nodes
        .iter()
        .map(|id| (id.clone(), BTreeSet::new()))
        .collect();
    for edge in arr(migration, "edges")? {
        let from = strv(edge, "from")?;
        let to = strv(edge, "to")?;
        if migration_nodes.contains(from) && migration_nodes.contains(to) {
            outgoing
                .entry(from.to_owned())
                .or_default()
                .insert(to.to_owned());
        }
    }
    let has_path = |start: &str, goal: &str| {
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([start.to_owned()]);
        while let Some(current) = queue.pop_front() {
            if current == goal {
                return true;
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if let Some(next) = outgoing.get(&current) {
                queue.extend(next.iter().cloned());
            }
        }
        false
    };
    let required_paths = [
        ("MIG-08:FACADE_READY", "E-16:REHEARSAL_PASSED"),
        ("E-16:REHEARSAL_PASSED", "MIG-08:CUTOVER_COMMITTED"),
        ("MIG-08:CUTOVER_COMMITTED", "E-16:POST_CUTOVER_PROOF_PASSED"),
        (
            "E-16:POST_CUTOVER_PROOF_PASSED",
            "MIG-08:RETIREMENT_VERIFIED",
        ),
        ("MIG-08:MIGRATION_TERMINAL", "E-16:CELL_ACCEPTED"),
    ];
    let missing_paths: Vec<_> = required_paths
        .iter()
        .filter(|(start, goal)| !has_path(start, goal))
        .map(|(start, goal)| json!({"from":start,"to":goal}))
        .collect();
    a.check(
        "migration.external_prereqs",
        bad.is_empty(),
        "migration external prerequisites are exact and conjunctive",
        json!({"bad":bad}),
    );
    a.check(
        "migration.single_mig08",
        forbidden_mig08.is_empty(),
        "migration has no deprecated MIG-08 split owner paths",
        json!({"forbidden":forbidden_mig08}),
    );
    a.check(
        "migration.phase_path",
        missing_paths.is_empty(),
        "migration phase path reaches all required cutover states",
        json!({"missing":missing_paths}),
    );
    Ok(())
}

fn collect_manifests(directory: &Path, repository: &Path, manifests: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !matches!(name, ".git" | "target" | ".eliot") {
                collect_manifests(&path, repository, manifests);
            }
        } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
            manifests.push(
                path.strip_prefix(repository)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn run_command(repository: &Path, program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(repository)
        .output()
        .with_context(|| format!("spawn {program}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{program} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).context("command output is not UTF-8")
}

fn cargo_metadata_manifests(repository: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let mut manifests = BTreeMap::new();
    let mut ingest = |raw: &str| -> Result<()> {
        let metadata: Value = serde_json::from_str(raw).context("cargo metadata JSON")?;
        for package in arr(&metadata, "packages")? {
            let name = strv(package, "name")?.to_owned();
            let manifest = PathBuf::from(strv(package, "manifest_path")?);
            let manifest = manifest
                .canonicalize()
                .with_context(|| format!("canonicalize Cargo manifest {}", manifest.display()))?;
            if let Some(existing) = manifests.insert(manifest.clone(), name.clone())
                && existing != name
            {
                return Err(anyhow!(
                    "cargo metadata duplicated manifest {}",
                    manifest.display()
                ));
            }
        }
        Ok(())
    };
    let raw = run_command(
        repository,
        "cargo",
        &[
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
            "--locked",
        ],
    )?;
    ingest(&raw)?;
    Ok(manifests)
}

fn source_support_status(gaps: &[Value]) -> &'static str {
    if gaps.is_empty() {
        "root_membership_observed"
    } else {
        "source_unverified"
    }
}

fn source_snapshot(repository: &Path, gaps: &[Value]) -> Result<Value> {
    let mut manifests = Vec::new();
    collect_manifests(repository, repository, &mut manifests);
    manifests.sort();
    let manifest_records: Vec<Value> = manifests
        .iter()
        .map(|relative| {
            let path = repository.join(relative);
            Ok(json!({"path":relative,"sha256":sha256(&fs::read(path)?)}))
        })
        .collect::<Result<_>>()?;
    let head = run_command(repository, "git", &["rev-parse", "HEAD"])?;
    let dirty = run_command(
        repository,
        "git",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?
    .replace(char::from(13), "");
    let diff = run_command(
        repository,
        "git",
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            "--full-index",
            "HEAD",
            "--",
        ],
    )?;
    let untracked = run_command(
        repository,
        "git",
        &["ls-files", "--others", "--exclude-standard"],
    )?;
    let untracked_records: Vec<Value> = untracked
        .lines()
        .filter(|path| !path.is_empty())
        .map(|relative| {
            let path = repository.join(relative);
            Ok(json!({"path":relative,"size":fs::metadata(&path)?.len(),"sha256":sha256(&fs::read(path)?)}))
        })
        .collect::<Result<_>>()?;
    let frontier_material = json!({
        "dirty_status":dirty,
        "diff_sha256":sha256(diff.as_bytes()),
        "untracked":untracked_records.clone(),
    });
    let metadata_raw = run_command(
        repository,
        "cargo",
        &[
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
            "--locked",
        ],
    )?;
    let metadata: Value = serde_json::from_str(&metadata_raw).context("cargo metadata JSON")?;
    let metadata_manifests: Vec<Value> = metadata
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| package.get("manifest_path").and_then(Value::as_str))
        .map(|path| {
            let path = PathBuf::from(path);
            Ok(json!({"path":path.to_string_lossy().replace('\\',"/"),"sha256":sha256(&fs::read(path)?)}))
        })
        .collect::<Result<_>>()?;
    Ok(json!({
        "repository":repository,
        "git_head":head.trim(),
        "dirty_status_sha256":sha256(dirty.as_bytes()),
        "dirty_status_bytes":dirty.len(),
        "diff_sha256":sha256(diff.as_bytes()),
        "untracked_files":untracked_records,
        "source_frontier_sha256":sha256(&canonical_bytes(&frontier_material)),
        "cargo_manifest_paths":manifest_records,
        "cargo_metadata_manifests":metadata_manifests,
        "target_root_gaps":gaps,
        "source_support_status":source_support_status(gaps),
        "source_identity_verified":false,
        "target_roots_present":gaps.is_empty()
    }))
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let candidate = if path.exists() {
        let Ok(existing) = path.canonicalize() else {
            return false;
        };
        existing
    } else {
        let Some(parent) = path.parent() else {
            return false;
        };
        let Ok(parent) = parent.canonicalize() else {
            return false;
        };
        let Some(name) = path.file_name() else {
            return false;
        };
        parent.join(name)
    };
    candidate.starts_with(root)
}

fn write_report_atomic(report: &Path, bytes: &[u8], opts: &CompileOptions) -> Result<()> {
    if path_is_within(report, &opts.runtime_root)
        || path_is_within(report, &opts.normative_root)
        || path_is_within(report, &opts.repository)
    {
        return Err(anyhow!(
            "report must be external to runtime, normative and repository roots"
        ));
    }
    if report.exists() {
        let existing = fs::read(report)?;
        if existing != bytes {
            return Err(anyhow!("existing report differs; refusing overwrite"));
        }
        return Ok(());
    }
    let parent = report
        .parent()
        .ok_or_else(|| anyhow!("report has no parent"))?;
    if !parent.is_dir() {
        return Err(anyhow!("report parent does not exist"));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!(e))?
        .as_nanos();
    let temp = parent.join(format!(
        ".{}-tmp-{}-{}",
        report
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("receipt"),
        std::process::id(),
        nonce
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, report)?;
    if fs::read(report)? != bytes {
        return Err(anyhow!("report bytes failed post-rename verification"));
    }
    Ok(())
}

/// Compiles the sealed runtime projection into one bounded verification receipt.
#[must_use]
// The compiler keeps the fail-closed audit sequence visible in one orchestration function.
#[allow(clippy::too_many_lines)]
pub fn compile(opts: &CompileOptions) -> Value {
    let mut audit = Audit::default();
    let mut payload_hashes = Map::new();
    let mut manifest_sha = Value::Null;
    let mut payload_root = Value::Null;
    let mut gaps = Vec::new();
    let result: Result<()> = (|| {
        let manifest_path = opts.runtime_root.join("Eliot_Runtime_BundleManifest.json");
        let (manifest, manifest_bytes) = read_json(&manifest_path).context("bundle manifest")?;
        manifest_sha = Value::String(sha256(&manifest_bytes));
        let listed = arr(&manifest, "payload_files")?;
        let mut names = BTreeSet::new();
        let mut missing = Vec::new();
        let mut bad = Vec::new();
        let mut root_rows = Vec::new();
        for entry in listed {
            let name = strv(entry, "path")?.to_owned();
            if !names.insert(name.clone()) {
                audit.error(
                    "manifest.unique_members",
                    "duplicate payload member",
                    json!({"path":name}),
                );
            }
            if Path::new(&name).is_absolute() || name.contains("..\\") || name.contains("../") {
                audit.error(
                    "manifest.safe_member",
                    "payload member escapes roots",
                    json!({"path":name}),
                );
                continue;
            }
            let Some(path) = resolve_payload(&opts.runtime_root, &opts.normative_root, &name)
            else {
                missing.push(name.clone());
                continue;
            };
            let bytes = fs::read(&path)?;
            let actual = sha256(&bytes);
            let size = bytes.len() as u64;
            payload_hashes.insert(name.clone(), Value::String(actual.clone()));
            root_rows.push(json!({"path":name,"size":size,"sha256":actual}));
            if entry.get("sha256").and_then(Value::as_str) != Some(actual.as_str())
                || entry.get("size").and_then(Value::as_u64) != Some(size)
            {
                bad.push(
                    json!({"path":name,"expected":entry,"actual_sha256":actual,"actual_size":size}),
                );
            }
        }
        audit.check(
            "manifest.members",
            missing.is_empty(),
            "all manifest payload members exist",
            json!({"missing":missing}),
        );
        audit.check(
            "manifest.hashes",
            bad.is_empty(),
            "all payload hashes and sizes match",
            json!({"bad":bad}),
        );
        root_rows.sort_by(|a, b| {
            a.get("path")
                .and_then(Value::as_str)
                .cmp(&b.get("path").and_then(Value::as_str))
        });
        let computed = sha256(&canonical_bytes(&Value::Array(root_rows)));
        payload_root = Value::String(computed.clone());
        audit.check(
            "manifest.payload_root",
            manifest.get("payload_root_sha256").and_then(Value::as_str) == Some(computed.as_str()),
            "manifest payload root matches",
            json!({"actual":computed,"expected":manifest.get("payload_root_sha256")}),
        );
        let seed_path = opts.runtime_root.join("Eliot_Runtime_BootstrapSeed.json");
        let (seed, _) = read_json(&seed_path).context("bootstrap seed")?;
        let read = |name: &str| -> Result<Value> {
            let path = resolve_payload(&opts.runtime_root, &opts.normative_root, name)
                .ok_or_else(|| anyhow!("missing payload {name}"))?;
            Ok(read_json(&path)?.0)
        };
        let work = read("Eliot_Runtime_WorkGraph.json")?;
        let (nodes, deps) = check_graph(&mut audit, &work)?;
        let manifest_names = names.clone();
        check_bootstrap_identity(
            &mut audit,
            &manifest,
            &seed,
            &manifest_names,
            &payload_hashes,
            &work,
            manifest_sha.as_str().unwrap_or_default(),
        )?;
        let index = read("Eliot_Runtime_NormativeWorkIndex.json")?;
        let plans = read("Eliot_Runtime_CellExecutionPlans.json")?;
        check_index_plans(&mut audit, &index, &plans, &nodes, &deps)?;
        let provider = read("Eliot_Runtime_ProviderSurfaceBindings.json")?;
        check_bindings(&mut audit, &provider, &index, &nodes, &deps)?;
        let composition = read("Eliot_Runtime_BinaryCompositionManifests.json")?;
        let readiness = read("Eliot_Runtime_ReadinessMilestones.json")?;
        check_provider_ports(
            &mut audit,
            &provider,
            &readiness,
            &composition,
            &index,
            &nodes,
        )?;
        let owner = read("Eliot_Runtime_OwnerBindings.json")?;
        check_owner_bindings(&mut audit, &owner, &index, &nodes)?;
        let package_doc = read("Eliot_Runtime_PhysicalPackageMap.json")?;
        let cargo = read("Eliot_Runtime_CargoDependencyGraph.json")?;
        let cargo_manifests = cargo_metadata_manifests(&opts.repository)?;
        gaps = check_packages(
            &mut audit,
            &package_doc,
            &index,
            &cargo,
            &opts.repository,
            Some(&cargo_manifests),
        )?;
        check_composition(
            &mut audit,
            &composition,
            &package_doc,
            &cargo,
            &index,
            &nodes,
        )?;
        check_readiness(&mut audit, &readiness, &nodes)?;
        check_authority(
            &mut audit,
            &read("Eliot_Runtime_AuthorityCompositionGraph.json")?,
            &owner,
        )?;
        check_coordination(
            &mut audit,
            &read("Eliot_Runtime_AgentCoordinationContracts.json")?,
            &owner,
            &nodes,
            &seed,
        )?;
        check_execution(&mut audit, &read("Eliot_Runtime_ExecutionRules.json")?)?;
        check_conformance(
            &mut audit,
            &read("Eliot_Runtime_ConformanceDecisions.json")?,
        )?;
        check_donor(
            &mut audit,
            &read("Eliot_Runtime_DonorEvidenceGraph.json")?,
            &nodes,
        )?;
        check_normative_references(
            &mut audit,
            &index,
            &nodes,
            &fs::read(opts.normative_root.join("ELIOT_ARCHITECTURE.md"))?,
            &fs::read(opts.normative_root.join("ELIOT_IMPLEMENTATION.md"))?,
        )?;
        check_admission(
            &mut audit,
            &read("Eliot_Runtime_AdmissionPolicyGraph.json")?,
            &nodes,
        )?;
        let migration = read("Eliot_Runtime_MigrationGraph.json")?;
        check_state_graph(&mut audit, &migration, "migration", "MIG-00:READY")?;
        check_migration(&mut audit, &migration, &nodes)?;
        let finish = read("Eliot_Runtime_StateExpandedFinishGraph.json")?;
        check_state_graph(&mut audit, &finish, "finish", "MIG-00:READY")?;
        check_finish_edges(&mut audit, &finish, &work, &index)?;
        Ok(())
    })();
    if let Err(e) = result {
        audit.error(
            "compiler.fatal",
            "document cannot be compiled",
            json!({"error":e.to_string()}),
        );
    }
    let source = match source_snapshot(&opts.repository, &gaps) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            audit.error(
                "source.frontier",
                "source frontier snapshot unavailable",
                json!({"error":error.to_string()}),
            );
            json!({"status":"UNAVAILABLE","error":error.to_string(),"target_root_gaps":gaps})
        }
    };
    let passed = audit.errors.is_empty();
    let receipt = json!({"schema_version":"eliot-runtime-compiler-receipt-v1","work_id":"D-01","plan_id":PLAN_ID,"verdict":if passed{"PASS"}else{"FAIL"},"document_status_ceiling":"DOCUMENT_CONFORMANT / CODEX_W0_READY only; source/runtime/product/release unverified","manifest_sha256":manifest_sha,"payload_root_sha256":payload_root,"payload_sha256":payload_hashes,"checks":audit.checks,"checks_passed":audit.checks.iter().filter(|x|x.get("passed")==Some(&Value::Bool(true))).count(),"checks_total":audit.checks.len(),"errors":audit.errors,"warnings":audit.warnings,"current_source_gap":gaps,"source_snapshot":source});
    if let Some(report) = &opts.report {
        let bytes = match serde_json::to_vec_pretty(&receipt) {
            Ok(bytes) => bytes,
            Err(error) => {
                return json!({"schema_version":"eliot-runtime-compiler-receipt-v1","work_id":"D-01","plan_id":PLAN_ID,"verdict":"FAIL","errors":[{"check_id":"report.serialize","message":error.to_string()}]});
            }
        };
        if let Err(e) = write_report_atomic(report, &bytes, opts) {
            return json!({"schema_version":"eliot-runtime-compiler-receipt-v1","work_id":"D-01","plan_id":PLAN_ID,"verdict":"FAIL","errors":[{"check_id":"report.write","message":e.to_string()}]});
        }
    }
    receipt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[track_caller]
    fn must<T, E: Debug>(result: std::result::Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = must(SystemTime::now().duration_since(UNIX_EPOCH), "clock").as_nanos();
        let path = std::env::temp_dir().join(format!("eliot-runtime-compiler-{name}-{nonce}"));
        must(fs::create_dir_all(&path), "temp dir");
        path
    }

    fn target_plan_fixture() -> (Value, Value, BTreeSet<String>, WorkDependencies) {
        let nodes = BTreeSet::from(["A-01".to_owned()]);
        let deps = BTreeMap::from([("A-01".to_owned(), BTreeSet::new())]);
        let index = json!({"work_items":[{
            "work_id":"A-01", "kind":"target_cell", "acceptance_dependencies":[],
            "responsibility":"cause", "primary_lifecycle_owner":"A-01",
            "readiness_and_activation_gates":[], "cell_execution_plan_ref":"A-01:plan-v2",
            "local_proof_profile":"proof", "terminal_policy":"TERM",
            "source_packages_and_module_roots":["crates/a"],
            "legacy_or_donor_source_claims":[]
        }]});
        let plans = json!({
            "schema_version":"eliot-cell-execution-plans-v3",
            "acceptance_graph_digest":EXPECTED_WORK_GRAPH_SHA256,
            "plans":[{
                "work_id":"A-01", "plan_id":"A-01:plan-v2", "plan_kind":"single_slice",
                "causal_property":"cause", "primary_lifecycle_owner":"A-01",
                "acceptance_dependencies":[], "required_readiness_gates":[],
                "fallback":"sequential execution", "invalidation":["source change"],
                "assembly":{
                    "required_proof":"proof", "terminal_policy":"TERM",
                    "author_may_integrate_own_candidate":false,
                    "cell_assembly_owner":null, "package_assembly_owner":"A-01",
                    "package_root_public_surface_claims":["crates/a"]
                },
                "source_containers":["crates/a"],
                "slices":[{
                    "slice_id":"A-01:whole", "causal_subproperty":"whole",
                    "expected_output":"immutable slice candidate plus raw proof/evidence",
                    "local_proof":"proof", "may_run_in_parallel_with_siblings":false,
                    "provider_requirements":[],
                    "role":"mutating_or_evidence_as_admission_allows",
                    "write_claims":["crates/a::module"]
                }]
            }]
        });
        (index, plans, nodes, deps)
    }

    fn check_passed(audit: &Audit, check_id: &str) -> bool {
        audit
            .checks
            .iter()
            .any(|check| check["check_id"] == check_id && check["passed"].as_bool() == Some(true))
    }

    fn package_parity_fixture() -> (Value, Value, Value) {
        let roots = [
            ("crates/kernel/eliot-ipc", "C0"),
            ("crates/instrument/eliot-instrument-scip", "C1"),
            ("crates/instrument/eliot-code-graph", "C2"),
            ("crates/storage/eliot-blob-api", "C0"),
            ("crates/storage/eliot-blob", "C3"),
            ("bins/eliot-kernel", "C4"),
        ];
        let packages: Vec<Value> = roots
            .iter()
            .map(|(root, layer)| {
                json!({
                    "package_id":root,
                    "work_id":"A-01",
                    "source_layer":layer,
                    "kind":"rust_crate",
                    "package_root_owner":"A-01",
                    "lifecycle_owner":"A-01",
                    "public_surface_owner":"A-01"
                })
            })
            .collect();
        let bindings: Vec<Value> = roots
            .iter()
            .map(|(root, layer)| json!({"package_or_module_root":root,"source_layer":layer}))
            .collect();
        (
            json!({"schema_version":"eliot-physical-package-map-v3","packages":packages}),
            json!({"work_items":[{
                "work_id":"A-01","package_source_layer_bindings":bindings
            }]}),
            json!({"edges":[{
                "consumer_package":"bins/eliot-kernel",
                "provider_package":"crates/kernel/eliot-ipc",
                "kind":"composition_profile"
            }]}),
        )
    }

    fn package_audit(package: &Value, index: &Value, cargo: &Value) -> Audit {
        let root = temp_dir("package-parity");
        let mut audit = Audit::default();
        let _ = must(
            check_packages(&mut audit, package, index, cargo, &root, None),
            "package parity fixture",
        );
        let _ = fs::remove_dir_all(root);
        audit
    }

    fn owner_parity_fixture() -> (Value, Value, BTreeSet<String>) {
        let owner = json!({
            "object_phase_bindings":[],
            "process_tree_bindings":[
                {"tree_class":"host_service_process","physical_tree_owner":"external:windows_scm"},
                {"tree_class":"kernel_testd_generation","physical_tree_owner":"P-08"},
                {"tree_class":"testd_descendants","physical_tree_owner":"I-04"},
                {"tree_class":"user_broker_ui_descendant","physical_tree_owner":"A-09"},
                {"tree_class":"watchdog_service_process","physical_tree_owner":"external:windows_scm"}
            ]
        });
        let index = json!({"work_items":[
            {"work_id":"P-08","owned_object_phase_refs":[],"process_tree_phase_refs":["kernel_testd_generation:physical_tree_owner"]},
            {"work_id":"I-04","owned_object_phase_refs":[],"process_tree_phase_refs":["testd_descendants:physical_tree_owner"]},
            {"work_id":"A-09","owned_object_phase_refs":[],"process_tree_phase_refs":["user_broker_ui_descendant:physical_tree_owner"]},
            {"work_id":"P-04","owned_object_phase_refs":[],"process_tree_phase_refs":[]}
        ]});
        let nodes = ["P-08", "I-04", "A-09", "P-04"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        (owner, index, nodes)
    }

    fn composition_parity_fixture() -> (Value, Value, Value, Value, BTreeSet<String>) {
        let manifests: Vec<Value> = (0..16)
            .map(|index| {
                let work = if index == 0 { "U-01" } else { "A-01" };
                json!({
                    "manifest_id":format!("manifest-{index}"),
                    "artifact":format!("artifact-{index}"),
                    "work_id":work,
                    "profile":"D0_FOUNDATION",
                    "build_system":if work == "U-01" {"dotnet_msbuild"} else {"cargo"},
                    "root_package":"crates/a",
                    "direct_composition_packages":[],
                    "packages":["crates/a"],
                    "direct_composition_work_ids":[work]
                })
            })
            .collect();
        let a_refs: Vec<Value> = (1..16)
            .map(|index| Value::String(format!("manifest-{index}")))
            .collect();
        (
            json!({"manifests":manifests}),
            json!({"packages":[{
                "package_id":"crates/a","production_role":"fixture"
            }]}),
            json!({"edges":[]}),
            json!({"work_items":[
                {"work_id":"U-01","binary_manifest_refs":["manifest-0"]},
                {"work_id":"A-01","binary_manifest_refs":a_refs}
            ]}),
            ["U-01", "A-01"].into_iter().map(str::to_owned).collect(),
        )
    }
    #[test]
    fn graph_cycle_is_rejected() {
        let mut n = BTreeSet::new();
        n.extend(["A".to_owned(), "B".to_owned()]);
        let mut d = BTreeMap::new();
        d.insert("A".to_owned(), BTreeSet::from(["B".to_owned()]));
        d.insert("B".to_owned(), BTreeSet::from(["A".to_owned()]));
        let (ok, _, _, _) = graph_analysis(&n, &d);
        assert!(!ok);
    }
    #[test]
    fn canonical_hash_is_deterministic() {
        let a = json!({"z":1,"a":{"b":2,"a":1}});
        let b = json!({"a":{"a":1,"b":2},"z":1});
        assert_eq!(sha256(&canonical_bytes(&a)), sha256(&canonical_bytes(&b)));
    }

    #[test]
    fn missing_member_is_fail_closed() {
        let root = temp_dir("missing-member");
        let manifest = json!({"payload_files":[{"path":"missing.json","sha256":"00","size":1}],"payload_root_sha256":"00"});
        must(
            fs::write(
                root.join("Eliot_Runtime_BundleManifest.json"),
                must(serde_json::to_vec(&manifest), "serialize manifest"),
            ),
            "write manifest",
        );
        let receipt = compile(&CompileOptions {
            runtime_root: root.clone(),
            normative_root: root.clone(),
            repository: root.clone(),
            report: None,
        });
        assert_eq!(receipt["verdict"], "FAIL");
        assert!(receipt["errors"].as_array().is_some_and(|errors| {
            errors
                .iter()
                .any(|error| error["check_id"] == "manifest.members")
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hash_mismatch_is_fail_closed() {
        let root = temp_dir("hash-mismatch");
        must(fs::write(root.join("payload.txt"), b"actual"), "payload");
        let manifest = json!({"payload_files":[{"path":"payload.txt","sha256":"00","size":0}],"payload_root_sha256":"00"});
        must(
            fs::write(
                root.join("Eliot_Runtime_BundleManifest.json"),
                must(serde_json::to_vec(&manifest), "serialize manifest"),
            ),
            "write manifest",
        );
        let receipt = compile(&CompileOptions {
            runtime_root: root.clone(),
            normative_root: root.clone(),
            repository: root.clone(),
            report: None,
        });
        assert_eq!(receipt["verdict"], "FAIL");
        assert!(receipt["errors"].as_array().is_some_and(|errors| {
            errors
                .iter()
                .any(|error| error["check_id"] == "manifest.hashes")
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_work_id_is_rejected() {
        let mut audit = Audit::default();
        let graph = json!({"graph":[{"id":"A","deps":[]},{"id":"A","deps":[]}]});
        let _ = must(check_graph(&mut audit, &graph), "shape is parseable");
        assert!(
            audit
                .errors
                .iter()
                .any(|e| e["check_id"] == "workgraph.unique_ids")
        );
    }

    #[test]
    fn absent_target_root_is_reported_as_gap() {
        let mut audit = Audit::default();
        let package =
            json!({"packages":[{"package_id":"future/pkg","work_id":"A-01","source_layer":"C2"}]});
        let index = json!({"work_items":[{"work_id":"A-01","package_source_layer_bindings":[{"package_or_module_root":"future/pkg","source_layer":"C2"}]}]});
        let cargo = json!({"edges":[]});
        let root = temp_dir("source-gap");
        let gaps = must(
            check_packages(&mut audit, &package, &index, &cargo, &root, None),
            "shape is parseable",
        );
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["package_id"], "future/pkg");
        assert_eq!(gaps[0]["reason"], "target_root_absent");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn normative_shadowing_resolves_only_from_normative_root() {
        let runtime = temp_dir("runtime-shadow");
        let normative = temp_dir("normative-shadow");
        must(
            fs::write(runtime.join("ELIOT_ARCHITECTURE.md"), b"runtime shadow"),
            "runtime shadow",
        );
        must(
            fs::write(normative.join("ELIOT_ARCHITECTURE.md"), b"canonical"),
            "normative book",
        );
        assert_eq!(
            resolve_payload(&runtime, &normative, "ELIOT_ARCHITECTURE.md"),
            Some(normative.join("ELIOT_ARCHITECTURE.md"))
        );
        let _ = fs::remove_dir_all(runtime);
        let _ = fs::remove_dir_all(normative);
    }

    #[test]
    fn report_collision_preserves_existing_bytes() {
        let runtime = temp_dir("report-runtime");
        let normative = temp_dir("report-normative");
        let repository = temp_dir("report-repository");
        let report_dir = temp_dir("report-output");
        let report = report_dir.join("receipt.json");
        must(fs::write(&report, b"immutable"), "existing report");
        let opts = CompileOptions {
            runtime_root: runtime.clone(),
            normative_root: normative.clone(),
            repository: repository.clone(),
            report: None,
        };
        assert!(write_report_atomic(&report, b"replacement", &opts).is_err());
        assert_eq!(must(fs::read(&report), "read report"), b"immutable");
        let _ = fs::remove_dir_all(runtime);
        let _ = fs::remove_dir_all(normative);
        let _ = fs::remove_dir_all(repository);
        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn missing_owner_reference_is_rejected() {
        let mut audit = Audit::default();
        let owner = json!({
            "object_phase_bindings": [{
                "binding_id":"owner:object",
                "exact_object_kind":"Object",
                "lifecycle_phase":"phase",
                "authoritative_owner":"MISSING"
            }],
            "process_tree_bindings": []
        });
        let index = json!({"work_items": [{
            "work_id":"A-01",
            "owned_object_phase_refs":[],
            "process_tree_phase_refs":[]
        }]});
        let nodes = BTreeSet::from(["A-01".to_owned()]);
        must(
            check_owner_bindings(&mut audit, &owner, &index, &nodes),
            "shape is parseable",
        );
        assert!(
            audit
                .errors
                .iter()
                .any(|e| e["check_id"] == "owner.references")
        );
    }

    #[test]
    fn semantic_projection_cannot_fall_back_to_normative_root() {
        let runtime = temp_dir("runtime-no-fallback");
        let normative = temp_dir("normative-no-fallback");
        must(
            fs::write(normative.join("Eliot_Runtime_WorkGraph.json"), b"shadow"),
            "semantic shadow",
        );
        assert!(resolve_payload(&runtime, &normative, "Eliot_Runtime_WorkGraph.json").is_none());
        let _ = fs::remove_dir_all(runtime);
        let _ = fs::remove_dir_all(normative);
    }

    #[test]
    fn cell_plan_projection_mutation_is_rejected() {
        let (index, plans, nodes, deps) = target_plan_fixture();
        let mut audit = Audit::default();
        must(
            check_index_plans(&mut audit, &index, &plans, &nodes, &deps),
            "shape",
        );
        assert!(audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == true
        }));
        let mut tampered = plans;
        tampered["plans"][0]["source_containers"] = json!([]);
        let mut tampered_audit = Audit::default();
        must(
            check_index_plans(&mut tampered_audit, &index, &tampered, &nodes, &deps),
            "shape",
        );
        assert!(tampered_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == false
        }));
    }

    #[test]
    // One cohesive fixture proves both the pinned baseline and all migration claim attacks.
    #[allow(clippy::too_many_lines)]
    fn migration_plan_containers_and_claims_are_pinned() {
        let nodes = BTreeSet::from(["MIG-01".to_owned()]);
        let deps = BTreeMap::from([("MIG-01".to_owned(), BTreeSet::new())]);
        let index = json!({"work_items":[{
            "work_id":"MIG-01", "kind":"migration_facade", "acceptance_dependencies":[],
            "responsibility":"migrate", "primary_lifecycle_owner":"MIG-01",
            "readiness_and_activation_gates":[], "cell_execution_plan_ref":"MIG-01:plan-v2",
            "local_proof_profile":"proof", "terminal_policy":"MIGRATION_TERMINAL",
            "source_packages_and_module_roots":[],
            "legacy_or_donor_source_claims":["crates/eliot-windows-ipc"]
        }]});
        let plans = json!({
            "schema_version":"eliot-cell-execution-plans-v3",
            "acceptance_graph_digest":EXPECTED_WORK_GRAPH_SHA256,
            "plans":[{
                "work_id":"MIG-01", "plan_id":"MIG-01:plan-v2", "plan_kind":"split",
                "causal_property":"migrate", "primary_lifecycle_owner":"MIG-01",
                "acceptance_dependencies":[], "required_readiness_gates":[],
                "fallback":"sequential execution", "invalidation":["legacy change"],
                "migration_write_scope":"exact legacy/donor roots only; target roots remain owned by target Work IDs",
                "assembly":{
                    "required_proof":"proof", "terminal_policy":"MIGRATION_TERMINAL",
                    "author_may_integrate_own_candidate":false,
                    "cell_assembly_owner":"MIG-01:non_author_assembler",
                    "package_assembly_owner":"MIG-01",
                    "package_root_public_surface_claims":["crates/eliot-windows-ipc"]
                },
                "source_containers":["crates/eliot-windows-ipc"],
                "slices":[
                    {
                        "slice_id":"MIG-01:inventory", "causal_subproperty":"inventory",
                        "expected_output":"immutable slice candidate plus raw proof/evidence",
                        "local_proof":"proof", "may_run_in_parallel_with_siblings":true,
                        "provider_requirements":[],
                        "role":"mutating_or_evidence_as_admission_allows",
                        "write_claims":["crates/eliot-windows-ipc::inventory"]
                    },
                    {
                        "slice_id":"MIG-01:cutover", "causal_subproperty":"cutover",
                        "expected_output":"immutable slice candidate plus raw proof/evidence",
                        "local_proof":"proof", "may_run_in_parallel_with_siblings":true,
                        "provider_requirements":[],
                        "role":"mutating_or_evidence_as_admission_allows",
                        "write_claims":["crates/eliot-windows-ipc::cutover"]
                    }
                ]
            }]
        });
        let mut clean_audit = Audit::default();
        must(
            check_index_plans(&mut clean_audit, &index, &plans, &nodes, &deps),
            "clean migration plan",
        );
        assert!(clean_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == true
        }));
        assert!(clean_audit.checks.iter().any(|check| {
            check["check_id"] == "migration.source_claim_bijection" && check["passed"] == true
        }));

        let mut resealed_index = index.clone();
        let mut resealed_plan = plans.clone();
        resealed_index["work_items"][0]["legacy_or_donor_source_claims"] = json!(["attacker/root"]);
        resealed_plan["plans"][0]["source_containers"] = json!(["attacker/root"]);
        resealed_plan["plans"][0]["assembly"]["package_root_public_surface_claims"] =
            json!(["attacker/root"]);
        resealed_plan["plans"][0]["slices"][0]["write_claims"] =
            json!(["attacker/root::inventory"]);
        resealed_plan["plans"][0]["slices"][1]["write_claims"] = json!(["attacker/root::cutover"]);
        let mut resealed_audit = Audit::default();
        must(
            check_index_plans(
                &mut resealed_audit,
                &resealed_index,
                &resealed_plan,
                &nodes,
                &deps,
            ),
            "resealed migration source tamper",
        );
        assert!(resealed_audit.checks.iter().any(|check| {
            check["check_id"] == "migration.source_claim_bijection" && check["passed"] == false
        }));

        let mut container_tamper = plans.clone();
        container_tamper["plans"][0]["source_containers"] = json!(["attacker/root"]);
        let mut container_audit = Audit::default();
        must(
            check_index_plans(
                &mut container_audit,
                &index,
                &container_tamper,
                &nodes,
                &deps,
            ),
            "container tamper",
        );
        assert!(container_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == false
        }));

        let mut claim_tamper = plans.clone();
        claim_tamper["plans"][0]["assembly"]["package_root_public_surface_claims"] =
            json!(["attacker/root"]);
        let mut claim_audit = Audit::default();
        must(
            check_index_plans(&mut claim_audit, &index, &claim_tamper, &nodes, &deps),
            "claim tamper",
        );
        assert!(claim_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == false
        }));

        let mut scope_tamper = plans.clone();
        scope_tamper["plans"][0]["migration_write_scope"] = json!("   ");
        let mut scope_audit = Audit::default();
        must(
            check_index_plans(&mut scope_audit, &index, &scope_tamper, &nodes, &deps),
            "migration scope tamper",
        );
        assert!(scope_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == false
        }));

        let mut read_tamper = plans;
        read_tamper["plans"][0]["slices"][0]["read_claims"] = json!([]);
        let mut read_audit = Audit::default();
        must(
            check_index_plans(&mut read_audit, &index, &read_tamper, &nodes, &deps),
            "migration read-claim tamper",
        );
        assert!(read_audit.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == false
        }));
    }

    #[test]
    fn donor_read_only_claims_are_exact() {
        let nodes = BTreeSet::from(["LEG-01".to_owned()]);
        let deps = BTreeMap::from([("LEG-01".to_owned(), BTreeSet::new())]);
        let index = json!({"work_items":[{
            "work_id":"LEG-01", "kind":"donor_audit", "acceptance_dependencies":[],
            "responsibility":"audit", "primary_lifecycle_owner":"LEG-01",
            "readiness_and_activation_gates":[], "cell_execution_plan_ref":"LEG-01:plan-v2",
            "local_proof_profile":"proof", "terminal_policy":"DONOR_AUDIT_TERMINAL",
            "source_packages_and_module_roots":[], "read_only_source_scope":["repo"]
        }]});
        let plans = json!({
            "schema_version":"eliot-cell-execution-plans-v3",
            "acceptance_graph_digest":EXPECTED_WORK_GRAPH_SHA256,
            "plans":[{
                "work_id":"LEG-01", "plan_id":"LEG-01:plan-v2", "plan_kind":"single_slice",
                "causal_property":"audit", "primary_lifecycle_owner":"LEG-01",
                "acceptance_dependencies":[], "required_readiness_gates":[],
                "fallback":"sequential audit", "invalidation":["donor change"],
                "source_containers":["repo"], "read_only_scope":["repo"],
                "assembly":{
                    "required_proof":"proof", "terminal_policy":"DONOR_AUDIT_TERMINAL",
                    "author_may_integrate_own_candidate":false, "cell_assembly_owner":null,
                    "package_assembly_owner":null, "package_root_public_surface_claims":[]
                },
                "slices":[{
                    "slice_id":"LEG-01:audit", "causal_subproperty":"audit",
                    "expected_output":"immutable slice candidate plus raw proof/evidence",
                    "local_proof":"proof", "may_run_in_parallel_with_siblings":false,
                    "provider_requirements":[], "role":"read_only",
                    "read_claims":["repo"], "write_claims":[]
                }]
            }]
        });
        let mut clean = Audit::default();
        must(
            check_index_plans(&mut clean, &index, &plans, &nodes, &deps),
            "clean donor plan",
        );
        assert!(clean.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == true
        }));
        for (field, value) in [
            ("scope", json!(["other"])),
            ("read", json!(["other"])),
            ("write", json!(["repo::mutation"])),
        ] {
            let mut candidate = plans.clone();
            match field {
                "scope" => candidate["plans"][0]["read_only_scope"] = value,
                "read" => candidate["plans"][0]["slices"][0]["read_claims"] = value,
                _ => candidate["plans"][0]["slices"][0]["write_claims"] = value,
            }
            let mut audit = Audit::default();
            must(
                check_index_plans(&mut audit, &index, &candidate, &nodes, &deps),
                "donor claim tamper",
            );
            assert!(audit.checks.iter().any(|check| {
                check["check_id"] == "index.plan_semantics" && check["passed"] == false
            }));
        }
    }

    #[test]
    fn baseline_observation_claims_are_exact() {
        let nodes = BTreeSet::from(["MIG-00".to_owned()]);
        let deps = BTreeMap::from([("MIG-00".to_owned(), BTreeSet::new())]);
        let index = json!({"work_items":[{
            "work_id":"MIG-00", "kind":"baseline_snapshot", "acceptance_dependencies":[],
            "responsibility":"snapshot", "primary_lifecycle_owner":"MIG-00",
            "readiness_and_activation_gates":[], "cell_execution_plan_ref":"MIG-00:plan-v2",
            "local_proof_profile":"proof", "terminal_policy":"BASELINE_SNAPSHOT_ACCEPTED",
            "source_packages_and_module_roots":[], "legacy_or_donor_source_claims":[]
        }]});
        let plans = json!({
            "schema_version":"eliot-cell-execution-plans-v3",
            "acceptance_graph_digest":EXPECTED_WORK_GRAPH_SHA256,
            "plans":[{
                "work_id":"MIG-00", "plan_id":"MIG-00:plan-v2", "plan_kind":"single_slice",
                "causal_property":"snapshot", "primary_lifecycle_owner":"MIG-00",
                "acceptance_dependencies":[], "required_readiness_gates":[],
                "fallback":"sequential observation", "invalidation":["environment change"],
                "source_containers":[],
                "assembly":{
                    "required_proof":"proof", "terminal_policy":"BASELINE_SNAPSHOT_ACCEPTED",
                    "author_may_integrate_own_candidate":false, "cell_assembly_owner":null,
                    "package_assembly_owner":null, "package_root_public_surface_claims":[]
                },
                "slices":[{
                    "slice_id":"MIG-00:baseline", "causal_subproperty":"observe",
                    "expected_output":"immutable slice candidate plus raw proof/evidence",
                    "local_proof":"proof", "may_run_in_parallel_with_siblings":false,
                    "provider_requirements":[], "role":"read_only_environment_observation",
                    "read_claims":["repository","build","runtime","store","integrations"],
                    "write_claims":[]
                }]
            }]
        });
        let mut clean = Audit::default();
        must(
            check_index_plans(&mut clean, &index, &plans, &nodes, &deps),
            "clean baseline plan",
        );
        assert!(clean.checks.iter().any(|check| {
            check["check_id"] == "index.plan_semantics" && check["passed"] == true
        }));
        for (field, value) in [
            ("scope", json!([])),
            (
                "read",
                json!(["build", "repository", "runtime", "store", "integrations"]),
            ),
            ("write", json!(["repository::mutation"])),
        ] {
            let mut candidate = plans.clone();
            match field {
                "scope" => candidate["plans"][0]["read_only_scope"] = value,
                "read" => candidate["plans"][0]["slices"][0]["read_claims"] = value,
                _ => candidate["plans"][0]["slices"][0]["write_claims"] = value,
            }
            let mut audit = Audit::default();
            must(
                check_index_plans(&mut audit, &index, &candidate, &nodes, &deps),
                "baseline claim tamper",
            );
            assert!(audit.checks.iter().any(|check| {
                check["check_id"] == "index.plan_semantics" && check["passed"] == false
            }));
        }
    }

    #[test]
    fn duplicated_plan_and_index_dependencies_are_rejected() {
        let (mut index, mut plans, mut nodes, mut deps) = target_plan_fixture();
        nodes.insert("B-01".to_owned());
        deps.insert("A-01".to_owned(), BTreeSet::from(["B-01".to_owned()]));
        deps.insert("B-01".to_owned(), BTreeSet::new());
        index["work_items"][0]["acceptance_dependencies"] = json!(["B-01", "B-01"]);
        plans["plans"][0]["acceptance_dependencies"] = json!(["B-01", "B-01"]);
        plans["plans"][0]["slices"][0]["provider_requirements"] = json!(["B-01", "B-01"]);
        let mut audit = Audit::default();
        assert!(check_index_plans(&mut audit, &index, &plans, &nodes, &deps).is_err());
    }

    #[test]
    fn plan_fallback_invalidation_and_mutating_claims_are_required() {
        let (index, plans, nodes, deps) = target_plan_fixture();
        for (field, tamper) in [
            ("fallback", json!("   ")),
            ("invalidation", json!([])),
            ("package_assembly_owner", json!("   ")),
            ("write_claims", json!([])),
        ] {
            let mut candidate = plans.clone();
            if field == "write_claims" {
                candidate["plans"][0]["slices"][0][field] = tamper;
            } else if field == "package_assembly_owner" {
                candidate["plans"][0]["assembly"][field] = tamper;
            } else {
                candidate["plans"][0][field] = tamper;
            }
            let mut audit = Audit::default();
            must(
                check_index_plans(&mut audit, &index, &candidate, &nodes, &deps),
                "plan required field tamper",
            );
            assert!(audit.checks.iter().any(|check| {
                check["check_id"] == "index.plan_semantics" && check["passed"] == false
            }));
        }
    }

    #[test]
    fn provider_port_duplicates_and_unknowns_are_rejected() {
        let mut audit = Audit::default();
        let nodes = BTreeSet::from(["A-01".to_owned()]);
        let binding = json!({"runtime_port_catalog":[
            {"port_id":"p","protocol":"","direction":"x","authority_ceiling":"x","unavailable_behavior":"x","contract_owner":"MISSING","artifact_participants":{"A-01":"role"}},
            {"port_id":"p","protocol":"x","direction":"x","authority_ceiling":"x","unavailable_behavior":"x","contract_owner":"A-01","artifact_participants":{"MISSING":"role"}}
        ]});
        let index = json!({"work_items":[{"work_id":"A-01","runtime_port_refs":["p:contract_owner","p:artifact:A-01:role"]}]});
        must(
            check_provider_ports(
                &mut audit,
                &binding,
                &json!({"composition_profile_records":[]}),
                &json!({"manifests":[]}),
                &index,
                &nodes,
            ),
            "shape",
        );
        assert!(audit.checks.iter().any(|check| {
            check["check_id"] == "provider.runtime_port_refs" && check["passed"] == false
        }));
    }

    #[test]
    fn whitespace_non_acceptance_binding_is_rejected() {
        let mut audit = Audit::default();
        let binding = json!({"bindings":[{
            "binding_id":"b", "provider_work_id":"A-01", "consumer_work_id":"A-01",
            "relation":"   ", "invalidation":["changed"], "required_milestone":"READY",
            "first_proof":"proof", "unsupported_or_degraded_behavior":"degraded",
            "acceptance_edge":false
        }]});
        let index = json!({"work_items":[{"work_id":"A-01","provider_binding_refs":["b"]}]});
        must(
            check_bindings(
                &mut audit,
                &binding,
                &index,
                &BTreeSet::from(["A-01".to_owned()]),
                &BTreeMap::from([("A-01".to_owned(), BTreeSet::new())]),
            ),
            "shape",
        );
        assert!(audit.checks.iter().any(|check| {
            check["check_id"] == "bindings.semantic_fields" && check["passed"] == false
        }));
    }

    #[test]
    fn non_acceptance_unknown_endpoint_is_rejected() {
        let mut audit = Audit::default();
        let binding = json!({"bindings":[{
            "binding_id":"b", "provider_work_id":"MISSING", "consumer_work_id":"A-01",
            "relation":"runtime_dependency", "invalidation":["changed"],
            "required_milestone":"READY", "first_proof":"proof",
            "unsupported_or_degraded_behavior":"degraded", "acceptance_edge":false
        }]});
        let index = json!({"work_items":[{"work_id":"A-01","provider_binding_refs":["b"]}]});
        must(
            check_bindings(
                &mut audit,
                &binding,
                &index,
                &BTreeSet::from(["A-01".to_owned()]),
                &BTreeMap::from([("A-01".to_owned(), BTreeSet::new())]),
            ),
            "shape",
        );
        assert!(
            audit.checks.iter().any(|check| {
                check["check_id"] == "bindings.work_ids" && check["passed"] == false
            })
        );
    }

    #[test]
    fn non_string_reverse_refs_are_rejected() {
        let nodes = BTreeSet::from(["A-01".to_owned()]);
        let binding = json!({"bindings":[{
            "binding_id":"b", "provider_work_id":"A-01", "consumer_work_id":"A-01",
            "relation":"runtime_dependency", "invalidation":["changed"],
            "required_milestone":"READY", "first_proof":"proof",
            "unsupported_or_degraded_behavior":"degraded", "acceptance_edge":false
        }]});
        let binding_index = json!({"work_items":[{"work_id":"A-01","provider_binding_refs":[1]}]});
        let mut binding_audit = Audit::default();
        assert!(
            check_bindings(
                &mut binding_audit,
                &binding,
                &binding_index,
                &nodes,
                &BTreeMap::from([("A-01".to_owned(), BTreeSet::new())]),
            )
            .is_err()
        );

        let owner = json!({"object_phase_bindings":[],"process_tree_bindings":[]});
        let owner_index = json!({"work_items":[{
            "work_id":"A-01", "owned_object_phase_refs":[1], "process_tree_phase_refs":[]
        }]});
        let mut owner_audit = Audit::default();
        assert!(check_owner_bindings(&mut owner_audit, &owner, &owner_index, &nodes).is_err());
    }

    #[test]
    fn package_parity_rules_reject_resealed_tampers() {
        let (package, index, cargo) = package_parity_fixture();
        let clean = package_audit(&package, &index, &cargo);
        for check_id in [
            "packages.layers",
            "packages.required_named",
            "packages.explicit_nonpackages",
            "packages.blob_split",
            "cargo.test_support_isolation",
            "cargo.ipc_composed",
        ] {
            assert!(check_passed(&clean, check_id), "clean {check_id}");
        }

        let mut bad_layer = package.clone();
        bad_layer["packages"][0]["source_layer"] = json!("C9");
        assert!(!check_passed(
            &package_audit(&bad_layer, &index, &cargo),
            "packages.layers"
        ));

        let mut missing_named = package.clone();
        if let Some(rows) = missing_named["packages"].as_array_mut() {
            let _ = rows.remove(2);
        }
        assert!(!check_passed(
            &package_audit(&missing_named, &index, &cargo),
            "packages.required_named"
        ));

        let mut forbidden = package.clone();
        if let Some(rows) = forbidden["packages"].as_array_mut() {
            rows.push(json!({
                "package_id":"crates/foundation/eliot-common","work_id":"A-01",
                "source_layer":"C0","kind":"rust_crate","package_root_owner":"A-01",
                "lifecycle_owner":"A-01","public_surface_owner":"A-01"
            }));
        }
        assert!(!check_passed(
            &package_audit(&forbidden, &index, &cargo),
            "packages.explicit_nonpackages"
        ));

        let mut blob = package.clone();
        blob["packages"][4]["source_layer"] = json!("C2");
        assert!(!check_passed(
            &package_audit(&blob, &index, &cargo),
            "packages.blob_split"
        ));

        let mut test_support = cargo.clone();
        if let Some(edges) = test_support["edges"].as_array_mut() {
            edges.push(json!({
                "consumer_package":"bins/eliot-kernel",
                "provider_package":"crates/foundation/eliot-test-support",
                "kind":"required"
            }));
        }
        assert!(!check_passed(
            &package_audit(&package, &index, &test_support),
            "cargo.test_support_isolation"
        ));

        let mut ipc = cargo.clone();
        ipc["edges"][0]["kind"] = json!("required");
        assert!(!check_passed(
            &package_audit(&package, &index, &ipc),
            "cargo.ipc_composed"
        ));
    }

    #[test]
    fn critical_process_tree_owners_are_exact() {
        let (owner, index, nodes) = owner_parity_fixture();
        let mut clean = Audit::default();
        must(
            check_owner_bindings(&mut clean, &owner, &index, &nodes),
            "owner parity fixture",
        );
        assert!(check_passed(&clean, "owner.p04_not_tree_owner"));
        assert!(check_passed(&clean, "owner.critical_process_trees"));

        let mut tampered = owner;
        tampered["process_tree_bindings"][1]["physical_tree_owner"] = json!("P-04");
        let mut bad = Audit::default();
        must(
            check_owner_bindings(&mut bad, &tampered, &index, &nodes),
            "owner parity tamper",
        );
        assert!(!check_passed(&bad, "owner.p04_not_tree_owner"));
        assert!(!check_passed(&bad, "owner.critical_process_trees"));
    }

    #[test]
    fn testd_self_host_provider_order_is_exact() {
        let readiness = json!({"milestones":[{
            "id":"B-06:SPINE_PROFILE_READY",
            "evidence_requirements":[],"invalidation":[],
            "providers":["I-04:LOCAL_IMPLEMENTATION_READY","P-04:LOCAL_IMPLEMENTATION_READY"],
            "publication_phases":[],"observable_property":"ready",
            "publication_owner":"B-06","unsupported_or_degraded_behavior":"unavailable"
        }]});
        let nodes = BTreeSet::from(["B-06".to_owned()]);
        let mut clean = Audit::default();
        must(
            check_readiness(&mut clean, &readiness, &nodes),
            "readiness parity fixture",
        );
        assert!(check_passed(&clean, "readiness.testd_self_host"));

        let mut tampered = readiness;
        tampered["milestones"][0]["providers"] = json!([
            "P-04:LOCAL_IMPLEMENTATION_READY",
            "I-04:LOCAL_IMPLEMENTATION_READY"
        ]);
        let mut bad = Audit::default();
        must(
            check_readiness(&mut bad, &tampered, &nodes),
            "readiness provider order tamper",
        );
        assert!(!check_passed(&bad, "readiness.testd_self_host"));
    }

    #[test]
    fn composition_artifact_and_winui_profiles_are_exact() {
        let (composition, packages, cargo, index, nodes) = composition_parity_fixture();
        let mut clean = Audit::default();
        must(
            check_composition(&mut clean, &composition, &packages, &cargo, &index, &nodes),
            "composition parity fixture",
        );
        assert!(check_passed(&clean, "composition.artifact_count"));
        assert!(check_passed(&clean, "composition.winui_profile"));

        let mut artifact_tamper = composition.clone();
        artifact_tamper["manifests"][15]["artifact"] = json!("artifact-0");
        let mut artifact_audit = Audit::default();
        must(
            check_composition(
                &mut artifact_audit,
                &artifact_tamper,
                &packages,
                &cargo,
                &index,
                &nodes,
            ),
            "composition artifact tamper",
        );
        assert!(!check_passed(&artifact_audit, "composition.artifact_count"));

        let mut winui_tamper = composition;
        winui_tamper["manifests"][0]["build_system"] = json!("cargo");
        let mut winui_audit = Audit::default();
        must(
            check_composition(
                &mut winui_audit,
                &winui_tamper,
                &packages,
                &cargo,
                &index,
                &nodes,
            ),
            "composition WinUI tamper",
        );
        assert!(!check_passed(&winui_audit, "composition.winui_profile"));
    }

    #[test]
    fn active_binary_alignment_is_participant_exact() {
        let readiness = json!({"composition_profile_records":[{
            "global_profile":"D2_OPERATIONAL",
            "selected_binary_manifests":{"B-09":"b09-d2"},
            "active_runtime_ports":[{
                "port_id":"ui.broker_launch","selected_participants":["B-09"]
            }]
        }]});
        let composition = json!({"manifests":[{
            "manifest_id":"b09-d2","work_id":"B-09","profile":"D2_OPERATIONAL",
            "runtime_port_bindings":[{
                "port_id":"ui.broker_launch","global_profile_states":[{
                    "global_profile":"D2_OPERATIONAL","state":"ACTIVE",
                    "contract_available_in_manifest":true,"missing_peer_artifacts":[]
                }]
            }]
        }]});
        let ports = BTreeSet::from(["ui.broker_launch".to_owned()]);
        assert!(binary_active_alignment_issues(&readiness, &composition, &ports).is_empty());

        let mut unavailable = composition;
        unavailable["manifests"][0]["runtime_port_bindings"][0]["global_profile_states"][0]["state"] =
            json!("DECLARED_UNAVAILABLE");
        assert!(!binary_active_alignment_issues(&readiness, &unavailable, &ports).is_empty());

        let mut duplicated = readiness;
        duplicated["composition_profile_records"][0]["active_runtime_ports"][0]["selected_participants"] =
            json!(["B-09", "B-09"]);
        assert!(!binary_active_alignment_issues(&duplicated, &unavailable, &ports).is_empty());
    }

    #[test]
    fn zero_source_gaps_do_not_claim_identity_verification() {
        assert_eq!(source_support_status(&[]), "root_membership_observed");
        assert_eq!(source_support_status(&[json!({})]), "source_unverified");
    }

    #[test]
    fn physical_package_owner_tamper_is_rejected() {
        let package_doc = json!({
            "schema_version":"eliot-physical-package-map-v3",
            "packages":[{
                "package_id":"future/pkg", "work_id":"A-01", "source_layer":"C2",
                "kind":"rust_crate", "package_root_owner":"A-01",
                "lifecycle_owner":"MISSING", "public_surface_owner":"A-01"
            }]
        });
        let index = json!({"work_items":[{
            "work_id":"A-01",
            "package_source_layer_bindings":[{
                "package_or_module_root":"future/pkg", "source_layer":"C2"
            }]
        }]});
        let root = temp_dir("package-owner-tamper");
        let mut audit = Audit::default();
        let _ = must(
            check_packages(
                &mut audit,
                &package_doc,
                &index,
                &json!({"edges":[]}),
                &root,
                None,
            ),
            "shape",
        );
        assert!(audit.checks.iter().any(|check| {
            check["check_id"] == "packages.index_bijection" && check["passed"] == false
        }));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cargo_manifest_not_in_metadata_is_an_explicit_gap() {
        let root = temp_dir("cargo-metadata-gap");
        let package = root.join("crates/a");
        must(fs::create_dir_all(&package), "package");
        must(
            fs::write(
                package.join("Cargo.toml"),
                "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
            ),
            "manifest",
        );
        let package_doc = json!({"packages":[{
            "package_id":"crates/a", "work_id":"A-01", "source_layer":"C0",
            "kind":"rust_crate", "package_root_owner":"A-01",
            "lifecycle_owner":"A-01", "public_surface_owner":"A-01"
        }]});
        let index = json!({"work_items":[{"work_id":"A-01","package_source_layer_bindings":[{"package_or_module_root":"crates/a","source_layer":"C0"}]}]});
        let mut audit = Audit::default();
        let metadata = BTreeMap::new();
        let gaps = must(
            check_packages(
                &mut audit,
                &package_doc,
                &index,
                &json!({"edges":[]}),
                &root,
                Some(&metadata),
            ),
            "shape",
        );
        assert!(
            gaps.iter()
                .any(|gap| gap["reason"] == "cargo_metadata_manifest_mismatch")
        );
        let _ = fs::remove_dir_all(root);
    }
}
