"""Executable acceptance matrix for the source-bound collection inventory (#885)."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "long_lived_collection_inventory.py"
_spec = importlib.util.spec_from_file_location("long_lived_collection_inventory", SCRIPT)
assert _spec is not None and _spec.loader is not None
oracle = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = oracle
_spec.loader.exec_module(oracle)

UNRESOLVED = {"unbounded long-lived candidate", "ownership/lifetime unknown"}
REQUIRED_HEADER_KEYS = {
    "schema", "rule_revision", "tool_version", "source_sha", "scan_roots", "scan_packages",
    "scan_denominator_files", "scan_denominator_bytes", "scan_denominator_packages",
    "cargo_inputs", "dependency_classifications", "build_targets", "build_features",
    "dependency_proof_ceiling", "candidate_count", "classified_count", "unresolved_count",
    "generation_command", "coverage_disposition", "coverage_reason", "safety_disposition",
    "proof_ceiling", "exclusions", "classifications",
}
REQUIRED_ROW_KEYS = {
    "id", "package", "path", "struct_name", "field_name", "field_type", "span_start",
    "span_end", "source_sha256", "span_digest", "row_digest", "owner", "lifetime",
    "creation_site", "destruction_site", "persistence", "growth_callsites", "removal_callsites",
    "bound", "bound_status", "cardinality_key", "cardinality_domain", "cardinality_driver",
    "untrusted_key_influence", "item_size", "persistence_amplification", "lock_owner",
    "build_classification", "risk_security", "risk_correctness", "risk_memory", "risk_disk",
    "risk_operational", "affected_boundary", "experiments_before_policy",
    "observed_bound_references", "unresolved_evidence", "concurrency", "at_capacity_behavior",
    "over_capacity_behavior", "classification", "evidence", "repair_owner", "repair_issue",
    "invalidation", "successor_scope",
}


@contextlib.contextmanager
def _workspace(
    sources: dict[str, str], *, manifest_overrides: dict[str, str] | None = None
) -> Iterator[Path]:
    """Create an isolated, metadata-bearing Cargo workspace for one source probe."""
    package_dirs = sorted({PurePosixPath(name).parts[0] for name in sources})
    overrides = manifest_overrides or {}
    with tempfile.TemporaryDirectory(prefix="cs2-885-matrix-") as directory:
        root = Path(directory)
        members = ", ".join(json.dumps(item) for item in package_dirs)
        (root / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "2"\nmembers = [{members}]\n', encoding="utf-8"
        )
        for package_dir in package_dirs:
            folder = root / package_dir
            folder.mkdir(parents=True, exist_ok=True)
            package_name = package_dir.replace("_", "-")
            default_manifest = (
                "[package]\n"
                f'name = "{package_name}"\n'
                'version = "0.1.0"\n'
                'edition = "2021"\n'
            )
            manifest_rel = f"{package_dir}/Cargo.toml"
            (root / manifest_rel).write_text(
                overrides.get(manifest_rel, default_manifest), encoding="utf-8"
            )
        for relative, source in sources.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        for relative, content in overrides.items():
            if relative == "Cargo.toml":
                (root / relative).write_text(content, encoding="utf-8")
            elif relative not in {f"{item}/Cargo.toml" for item in package_dirs}:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
        yield root


def _default_scans(root: Path) -> list[str]:
    return sorted({path.relative_to(root).parts[0] for path in root.rglob("*.rs")})


def _build(root: Path, scans: list[str] | None = None) -> dict[str, object]:
    selected = _default_scans(root) if scans is None else scans
    return oracle.build_inventory(root, selected, "matrix-test")


def _row(
    inventory: dict[str, object], field: str, *, struct_name: str | None = None,
    path: str | None = None,
) -> dict[str, object]:
    rows = inventory["rows"]
    assert isinstance(rows, list)
    selected = [
        row for row in rows if isinstance(row, dict)
        and row.get("field_name") == field
        and (struct_name is None or row.get("struct_name") == struct_name)
        and (path is None or row.get("path") == path)
    ]
    if len(selected) != 1:
        raise AssertionError(f"expected one row for {struct_name}.{field} at {path}; got {selected!r}")
    return selected[0]


def _refresh_digest(artifact: dict[str, object]) -> None:
    material = {"header": artifact["header"], "rows": artifact["rows"]}
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    artifact["inventory_digest"] = hashlib.sha256(encoded).hexdigest()


def _store_artifact(root: Path, inventory: dict[str, object]) -> Path:
    target = root / oracle.OWNED_TOML
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(oracle._emit_toml(inventory))
    return target


def _command(callable_) -> int:
    """Capture CLI output and normalize its documented fail-closed exception path."""
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return int(callable_())
        except oracle.InventoryError:
            return 2


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


class TestLongLivedCollectionInventory(unittest.TestCase):
    # WORK_UNIT_CASE: 885/1
    def test_885_01_exact_scan_and_package_denominator(self) -> None:
        with _workspace(
            {"alpha/src/lib.rs": "pub struct Alpha;\n", "beta/src/lib.rs": "pub struct Beta;\n"},
            manifest_overrides={
                "alpha/Cargo.toml": (
                    '[package]\nname = "alpha"\nversion = "0.1.0"\nedition = "2021"\n'
                    '[features]\ndefault = []\nfast = []\n'
                    '[dependencies]\nbeta = { path = "../beta", optional = true }\n'
                )
            },
        ) as root:
            scans = ["alpha/src/lib.rs", "beta/src/lib.rs"]
            header = _build(root, scans)["header"]
            self.assertEqual(header["scan_roots"], scans)
            self.assertEqual(header["scan_denominator_files"], 2)
            self.assertEqual(header["scan_denominator_packages"], 2)
            self.assertCountEqual(header["scan_packages"], ["alpha", "beta"])
            cargo_inputs = json.dumps(header["cargo_inputs"], sort_keys=True)
            self.assertIn("Cargo.toml", cargo_inputs)
            self.assertIn("alpha/Cargo.toml", cargo_inputs)
            self.assertIn("beta/Cargo.toml", cargo_inputs)
            self.assertIn("beta", json.dumps(header["dependency_classifications"], sort_keys=True))
            self.assertEqual(header["build_targets"], ["all-declared-targets-symbolic"])
            self.assertTrue(header["build_features"])
            self.assertIn("PACKAGE_BUILD_REACHABILITY_ONLY", header["dependency_proof_ceiling"])
            self.assertEqual(header["scan_denominator_bytes"], sum((root / p).stat().st_size for p in scans))

    # WORK_UNIT_CASE: 885/2
    def test_885_02_request_local_vec_push_is_frame_bounded(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub fn build_batch() {
                let mut batch: Vec<u8> = Vec::new();
                batch.push(1);
            }
        """}) as root:
            inventory = _build(root, ["pkg/src/lib.rs"])
            row = _row(inventory, "batch")
            self.assertEqual(row["classification"], "request-local/stack-bounded")
            self.assertTrue(any("push" in str(site) for site in row["growth_callsites"]))
            self.assertIn("function", str(row["lifetime"]).lower())
            self.assertEqual(inventory["header"]["coverage_disposition"], "COMPLETE")

    # WORK_UNIT_CASE: 885/3
    def test_885_03_immutable_dto_has_no_inferred_growth(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            #[derive(Clone, Debug)]
            pub struct SnapshotDto { pub entries: Vec<String> }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="SnapshotDto")
            self.assertEqual(row["growth_callsites"], [])
            self.assertNotEqual(row["classification"], "unbounded long-lived candidate")
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertTrue(str(row["item_size"]).startswith("UNKNOWN"))

    # WORK_UNIT_CASE: 885/4
    def test_885_04_test_only_collection_is_separate(self) -> None:
        with _workspace({"pkg/tests/collections.rs": """
            struct Harness { events: Vec<u8> }
            impl Harness { fn record(&mut self) { self.events.push(1); } }
        """}) as root:
            row = _row(_build(root, ["pkg/tests/collections.rs"]), "events", struct_name="Harness")
            self.assertEqual(row["classification"], "test-only")
            self.assertTrue(any("push" in str(site) for site in row["growth_callsites"]))
            self.assertTrue(row["risk_operational"])

    # WORK_UNIT_CASE: 885/5
    def test_885_05_mutex_hashmap_growth_is_found_or_explicitly_unresolved(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            use std::sync::Mutex;
            pub struct Registry { inner: Mutex<HashMap<String, Vec<u8>>> }
            impl Registry {
                pub fn insert(&self, key: String, value: Vec<u8>) {
                    self.inner.lock().unwrap().insert(key, value);
                }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "inner", struct_name="Registry")
            self.assertEqual(row["concurrency"], "Mutex")
            self.assertIn("inner", str(row["lock_owner"]))
            observed = json.dumps(row["growth_callsites"]) + json.dumps(row["unresolved_evidence"])
            self.assertIn("insert", observed, "lock-chain growth must not disappear")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["repair_issue"], "none-required")

    # WORK_UNIT_CASE: 885/6
    def test_885_06_static_global_growth_is_found(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            use std::sync::Mutex;
            static GLOBAL: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
            pub fn record(key: String, value: u64) {
                GLOBAL.lock().unwrap().insert(key, value);
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "GLOBAL")
            observed = json.dumps(row["growth_callsites"]) + json.dumps(row["unresolved_evidence"])
            self.assertIn("insert", observed)
            self.assertIn("global", str(row["lifetime"]).lower())
            self.assertIn(row["classification"], UNRESOLVED)

    # WORK_UNIT_CASE: 885/7
    def test_885_07_serde_is_capability_not_restart_proof(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use serde::{Deserialize, Serialize};
            #[derive(Serialize, Deserialize)]
            pub struct PersistedState { entries: Vec<String> }
            impl PersistedState {
                pub fn add(&mut self, entry: String) { self.entries.push(entry); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="PersistedState")
            self.assertIn("serialization capability", str(row["persistence"]).lower())
            self.assertTrue(str(row["persistence_amplification"]).startswith("UNKNOWN"))
            self.assertIn(row["classification"], UNRESOLVED)

    # WORK_UNIT_CASE: 885/8
    def test_885_08_alias_escape_is_resolved_or_remains_explicitly_unknown(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct Registry { entries: Vec<u8> }
            fn append_through_helper(entries: &mut Vec<u8>) { entries.push(1); }
            impl Registry {
                pub fn add(&mut self) {
                    let alias = &mut self.entries;
                    append_through_helper(alias);
                }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="Registry")
            evidence = json.dumps(row["growth_callsites"]) + json.dumps(row["unresolved_evidence"])
            self.assertTrue("push" in evidence or "alias" in evidence.lower() or "helper" in evidence.lower())
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertNotEqual(row["repair_issue"], "none-required")
        with _workspace({
            "pkg/src/lib.rs": """
                mod owner;
                use owner::Registry as CacheRegistry;
                pub fn grow_through_module_alias(cache: &mut CacheRegistry) {
                    cache.entries.push(1);
                }
            """,
            "pkg/src/owner.rs": """
                pub struct Registry { pub(crate) entries: Vec<u8> }
            """,
        }) as root:
            row = _row(_build(root, ["pkg/src"]), "entries", struct_name="owner::Registry", path="pkg/src/owner.rs")
            evidence = json.dumps(row["growth_callsites"]) + json.dumps(row["unresolved_evidence"])
            self.assertTrue("push" in evidence or "CacheRegistry" in evidence or "owner" in evidence)
            self.assertIn(row["classification"], UNRESOLVED)

    # WORK_UNIT_CASE: 885/9
    def test_885_09_entry_or_insert_growth_is_found(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            pub struct Registry { entries: HashMap<String, u8> }
            impl Registry {
                pub fn add(&mut self, key: String) { self.entries.entry(key).or_insert(1); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="Registry")
            self.assertTrue(any("entry" in str(site) for site in row["growth_callsites"]))
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertEqual(row["cardinality_key"], "String")

    # WORK_UNIT_CASE: 885/10
    def test_885_10_cross_impl_callsites_stay_with_exact_owner(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct Alpha { items: Vec<u8> }
            pub struct Beta { items: Vec<u8> }
            impl Alpha { pub fn add(&mut self) { self.items.push(1); } }
            impl Beta { pub fn clear_for_test(&mut self) { self.items.clear(); } }
        """}) as root:
            inventory = _build(root, ["pkg/src/lib.rs"])
            alpha = _row(inventory, "items", struct_name="Alpha")
            beta = _row(inventory, "items", struct_name="Beta")
            self.assertTrue(any("push" in str(site) for site in alpha["growth_callsites"]))
            self.assertEqual(alpha["removal_callsites"], [])
            self.assertEqual(beta["growth_callsites"], [])
            self.assertTrue(any("clear" in str(site) for site in beta["removal_callsites"]))
            self.assertNotEqual(beta["repair_issue"], "none-required")

    # WORK_UNIT_CASE: 885/11
    def test_885_11_exact_guard_and_deserialize_bypass(self) -> None:
        guarded = """
            pub struct Guarded { items: Vec<u8> }
            impl Guarded {
                pub fn new() -> Self { Self { items: Vec::new() } }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    self.items.push(item);
                }
            }
        """
        with _workspace({"pkg/src/lib.rs": guarded}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="Guarded")
            self.assertEqual(row["classification"], "long-lived hard-bounded")
            self.assertEqual(row["bound_status"], "hard")
            self.assertIn("8", str(row["bound"]))
            self.assertEqual(row["repair_issue"], "none-required")
        owner_alias_escape = """
            pub struct Guarded { items: Vec<u8> }
            impl Guarded {
                pub fn new() -> Self { Self { items: Vec::new() } }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    self.items.push(item);
                }
            }
            type Alias = Guarded;
            fn append(owner: &mut Alias, item: u8) { owner.items.push(item); }
        """
        with _workspace({"pkg/src/lib.rs": owner_alias_escape}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="Guarded")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertTrue(row["unresolved_evidence"])
        constructor_alias = """
            pub struct Guarded { items: Vec<u8> }
            impl Guarded {
                pub fn new() -> Self { Self { items: Vec::new() } }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    self.items.push(item);
                }
            }
            type Alias = Guarded;
            fn from(items: Vec<u8>) -> Alias { Alias { items } }
        """
        with _workspace({"pkg/src/lib.rs": constructor_alias}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="Guarded")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertTrue(row["unresolved_evidence"])
        unguarded_sibling = """
            pub struct MultiPath { entries: Vec<u8> }
            impl MultiPath {
                pub fn new() -> Self { Self { entries: Vec::new() } }
                pub fn guarded(&mut self, item: u8) {
                    if self.entries.len() >= 8 { return; }
                    self.entries.push(item);
                }
                pub fn bypass(&mut self, item: u8) { self.entries.push(item); }
            }
        """
        with _workspace({"pkg/src/lib.rs": unguarded_sibling}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="MultiPath")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
        shorthand = """
            pub struct Shorthand { items: Vec<u8> }
            impl Shorthand {
                pub fn new() -> Self {
                    let items = Vec::with_capacity(4);
                    Self { items }
                }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    self.items.push(item);
                }
            }
        """
        with _workspace({"pkg/src/lib.rs": shorthand}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="Shorthand")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertIn("items", str(row["creation_site"]))
        local_alias = """
            pub struct AliasBound { items: Vec<u8> }
            impl AliasBound {
                pub fn new() -> Self { Self { items: Vec::new() } }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    let target = &mut self.items;
                    target.push(item);
                }
            }
        """
        with _workspace({"pkg/src/lib.rs": local_alias}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="AliasBound")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertTrue(row["unresolved_evidence"])
        deserialize_bypass = """
            use serde::Deserialize;
            #[derive(Deserialize)]
            pub struct Imported { items: Vec<u8> }
            impl Imported {
                pub fn new() -> Self { Self { items: Vec::new() } }
                pub fn add(&mut self, item: u8) {
                    if self.items.len() >= 8 { return; }
                    self.items.push(item);
                }
            }
        """
        with _workspace({"pkg/src/lib.rs": deserialize_bypass}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "items", struct_name="Imported")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotEqual(row["bound_status"], "hard")
            self.assertNotEqual(row["repair_issue"], "none-required")
            self.assertIn("serialization capability", str(row["persistence"]).lower())
            self.assertIn("deserial", (str(row["unresolved_evidence"]) + str(row["evidence"])).lower())

    # WORK_UNIT_CASE: 885/12
    def test_885_12_policy_and_empirical_names_never_promote_unknown(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct PolicyCache { policy_entries: Vec<String> }
            impl PolicyCache {
                pub fn add(&mut self, entry: String) { self.policy_entries.push(entry); }
                pub fn observe(&self) -> usize {
                    let empirical_max_observed = self.policy_entries.len();
                    empirical_max_observed
                }
                pub fn preallocate() -> Vec<String> { Vec::with_capacity(32) }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "policy_entries", struct_name="PolicyCache")
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertIn(row["bound_status"], {"none", "unknown"})
            refs = json.dumps(row["observed_bound_references"], sort_keys=True).lower()
            self.assertIn("policy", refs)
            self.assertIn("empirical_max_observed", refs)
            self.assertNotEqual(row["repair_issue"], "none-required")

    # WORK_UNIT_CASE: 885/13
    def test_885_13_removal_retain_clear_and_drain_are_inventoried(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct Store { entries: Vec<u8> }
            impl Store {
                pub fn add(&mut self) { self.entries.push(1); }
                pub fn cleanup(&mut self) {
                    self.entries.retain(|value| *value != 0);
                    self.entries.clear();
                    let _ = self.entries.drain(..);
                }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="Store")
            removals = json.dumps(row["removal_callsites"])
            for method in ("retain", "clear", "drain"):
                self.assertIn(method, removals)
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertIn(row["bound_status"], {"none", "unknown"})

    # WORK_UNIT_CASE: 885/14
    def test_885_14_test_only_removal_cannot_bound_production_growth(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct State { entries: Vec<u8> }
            impl State {
                pub fn add(&mut self) { self.entries.push(1); }
                #[cfg(test)]
                fn remove_in_test(&mut self) { self.entries.clear(); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="State")
            self.assertTrue(any("clear" in str(site) for site in row["removal_callsites"]))
            evidence = (str(row["unresolved_evidence"]) + str(row["evidence"])).lower()
            self.assertIn("test", evidence)
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertIn(row["bound_status"], {"none", "unknown"})

    # WORK_UNIT_CASE: 885/15
    def test_885_15_cfg_gated_removal_stays_unknown(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct State { entries: Vec<u8> }
            impl State {
                pub fn add(&mut self) { self.entries.push(1); }
                #[cfg(feature = "maintenance")]
                fn maybe_remove(&mut self) { self.entries.clear(); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="State")
            self.assertTrue(any("clear" in str(site) for site in row["removal_callsites"]))
            evidence = (str(row["unresolved_evidence"]) + str(row["evidence"])).lower()
            self.assertTrue("cfg" in evidence or "feature" in evidence or "unreachable" in evidence)
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertIn(row["bound_status"], {"none", "unknown"})

    # WORK_UNIT_CASE: 885/16
    def test_885_16_ttl_retain_without_scheduled_owner_is_not_bounded(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            pub struct LeaseCache { ttl_entries: HashMap<String, Vec<u8>> }
            impl LeaseCache {
                pub fn add(&mut self, key: String, value: Vec<u8>) { self.ttl_entries.insert(key, value); }
                pub fn prune_expired(&mut self) { self.ttl_entries.retain(|_, _| true); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "ttl_entries", struct_name="LeaseCache")
            self.assertTrue(any("retain" in str(site) for site in row["removal_callsites"]))
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertIn(row["bound_status"], {"none", "unknown"})
            self.assertNotEqual(row["repair_issue"], "none-required")

    # WORK_UNIT_CASE: 885/17
    def test_885_17_external_compaction_evidence_is_owner_specific_and_unresolved(self) -> None:
        with _workspace(
            {
                "pkg/src/lib.rs": "mod owner;\nmod maintenance;\n",
                "pkg/src/owner.rs": """
                    pub(crate) struct OwnerA { pub(crate) events: Vec<u8> }
                    impl OwnerA { pub fn add(&mut self) { self.events.push(1); } }
                    pub(crate) struct OwnerB { pub(crate) events: Vec<u8> }
                    impl OwnerB { pub fn add(&mut self) { self.events.push(2); } }
                """,
                "pkg/src/maintenance.rs": """
                    use crate::owner::OwnerA;
                    impl OwnerA { pub fn compact(&mut self) { self.events.retain(|_| true); } }
                """,
            }
        ) as root:
            inventory = _build(root, ["pkg/src"])
            owner_a = _row(inventory, "events", struct_name="owner::OwnerA", path="pkg/src/owner.rs")
            owner_b = _row(inventory, "events", struct_name="owner::OwnerB", path="pkg/src/owner.rs")
            self.assertTrue(any("maintenance.rs" in str(site) and "retain" in str(site) for site in owner_a["removal_callsites"]))
            self.assertFalse(any("maintenance.rs" in str(site) for site in owner_b["removal_callsites"]))
            self.assertIn(owner_a["classification"], UNRESOLVED)
            self.assertIn(owner_a["bound_status"], {"none", "unknown"})
            self.assertNotEqual(owner_a["repair_issue"], "none-required")

    # WORK_UNIT_CASE: 885/18
    def test_885_18_in_memory_append_retention_does_not_invent_durability(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct EventState { events: Vec<String> }
            impl EventState {
                pub fn add(&mut self, event: String) { self.events.push(event); }
                pub fn compact(&mut self) { self.events.retain(|event| !event.is_empty()); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "events", struct_name="EventState")
            self.assertIn(row["classification"], UNRESOLVED)
            persistence = (str(row["persistence"]) + str(row["persistence_amplification"])).lower()
            self.assertNotIn("durable segmented", persistence)
            self.assertNotIn("restart replays", persistence)
            self.assertTrue(str(row["persistence_amplification"]).startswith("UNKNOWN"))

    # WORK_UNIT_CASE: 885/19
    def test_885_19_untrusted_cardinality_driver_and_key_type_are_visible(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            pub struct Registry { entries: HashMap<String, Vec<u8>> }
            impl Registry {
                pub fn add(&mut self, user_supplied_key: String, value: Vec<u8>) {
                    self.entries.insert(user_supplied_key, value);
                }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="Registry")
            self.assertEqual(row["cardinality_key"], "String")
            self.assertIn("unknown", str(row["cardinality_domain"]).lower())
            self.assertTrue(str(row["cardinality_driver"]).strip())
            influence = str(row["untrusted_key_influence"]).lower()
            self.assertTrue("untrusted" in influence or "unknown" in influence)
            self.assertIn("before policy choice", influence)

    # WORK_UNIT_CASE: 885/20
    def test_885_20_unknown_item_size_stays_unknown(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashMap;
            pub struct Registry { entries: HashMap<String, Vec<u8>> }
            impl Registry {
                pub fn add(&mut self, key: String, value: Vec<u8>) { self.entries.insert(key, value); }
            }
        """}) as root:
            row = _row(_build(root, ["pkg/src/lib.rs"]), "entries", struct_name="Registry")
            self.assertTrue(str(row["item_size"]).startswith("UNKNOWN"))
            self.assertIn(row["classification"], UNRESOLVED)
            self.assertNotRegex(str(row["item_size"]), r"\d")

    # WORK_UNIT_CASE: 885/21
    def test_885_21_each_candidate_has_one_closed_classification(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            use std::collections::HashSet;
            pub struct One { items: Vec<u8> }
            pub struct Two { entries: Vec<u8> }
            pub struct Three { labels: HashSet<String> }
            impl One { pub fn add(&mut self) { self.items.push(1); } }
            impl Two { pub fn add(&mut self) { self.entries.push(2); } }
        """}) as root:
            inventory = _build(root, ["pkg/src/lib.rs"])
            header, rows = inventory["header"], inventory["rows"]
            self.assertEqual(header["candidate_count"], len(rows))
            self.assertEqual(header["classified_count"], len(rows))
            self.assertEqual(len({row["id"] for row in rows}), len(rows))
            self.assertEqual(len({row["row_digest"] for row in rows}), len(rows))
            self.assertEqual(len(header["classifications"]), 12)
            self.assertEqual(len(set(header["classifications"])), 12)
            for row in rows:
                self.assertTrue(REQUIRED_ROW_KEYS.issubset(row.keys()))
                self.assertIn(row["classification"], header["classifications"])
                self.assertIsInstance(row["classification"], str)
            self.assertTrue(REQUIRED_HEADER_KEYS.issubset(header.keys()))

    # WORK_UNIT_CASE: 885/22
    def test_885_22_duplicate_or_overlapping_identity_is_rejected(self) -> None:
        with _workspace({"pkg/src/lib.rs": "pub struct Registry { items: Vec<u8> }\n"}) as root:
            original = _build(root, ["pkg/src/lib.rs"])
            duplicated = json.loads(json.dumps(original))
            rows = duplicated["rows"]
            rows.append(json.loads(json.dumps(rows[0])))
            duplicated["header"]["candidate_count"] += 1
            duplicated["header"]["classified_count"] += 1
            if rows[0]["classification"] in UNRESOLVED:
                duplicated["header"]["unresolved_count"] += 1
            _refresh_digest(duplicated)
            with self.assertRaises(oracle.InventoryError) as raised:
                oracle._validate_artifact(duplicated)
            self.assertEqual(raised.exception.code, "DUPLICATE_ROW_IDENTITY")
            overlap = json.loads(json.dumps(original))
            extra = json.loads(json.dumps(overlap["rows"][0]))
            extra["id"] = str(extra["id"]) + "-distinct-id"
            extra["row_digest"] = oracle._digest({key: value for key, value in extra.items() if key != "row_digest"})
            overlap["rows"].append(extra)
            overlap["header"]["candidate_count"] += 1
            overlap["header"]["classified_count"] += 1
            if extra["classification"] in UNRESOLVED:
                overlap["header"]["unresolved_count"] += 1
            _refresh_digest(overlap)
            with self.assertRaises(oracle.InventoryError) as overlapping:
                oracle._validate_artifact(overlap)
            self.assertEqual(overlapping.exception.code, "DUPLICATE_ROW_IDENTITY")

    # WORK_UNIT_CASE: 885/23
    def test_885_23_complete_findings_stay_blocking_and_cannot_be_relabelled(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct Registry { items: Vec<u8> }
            impl Registry { pub fn add(&mut self) { self.items.push(1); } }
        """}) as root:
            inventory = _build(root, ["pkg/src/lib.rs"])
            header = inventory["header"]
            self.assertEqual(header["coverage_disposition"], "COMPLETE")
            self.assertEqual(header["safety_disposition"], "FINDINGS_REMAIN_BLOCKING")
            self.assertGreater(header["unresolved_count"], 0)
            self.assertEqual(header["proof_ceiling"], "STATIC_SOURCE_CLASSIFICATION_ONLY")
            false_clearance = json.loads(json.dumps(inventory))
            false_clearance["header"]["safety_disposition"] = "NO_UNRESOLVED_GROWTH"
            _refresh_digest(false_clearance)
            with self.assertRaises(oracle.InventoryError):
                oracle._validate_artifact(false_clearance)
            product_claim = json.loads(json.dumps(inventory))
            product_claim["header"]["safety_disposition"] = "PRODUCT_BOUNDED_OR_LEAK_FREE"
            _refresh_digest(product_claim)
            with self.assertRaises(oracle.InventoryError):
                oracle._validate_artifact(product_claim)

    # WORK_UNIT_CASE: 885/24
    def test_885_24_defect_has_issue_or_explicit_blocking_unresolved_handoff(self) -> None:
        with _workspace({"pkg/src/lib.rs": """
            pub struct Registry { items: Vec<u8> }
            impl Registry { pub fn add(&mut self) { self.items.push(1); } }
        """}) as root:
            inventory = _build(root, ["pkg/src/lib.rs"])
            row = _row(inventory, "items", struct_name="Registry")
            if row["repair_owner"] == "UNRESOLVED" or row["repair_issue"] == "UNRESOLVED":
                self.assertEqual(row["repair_owner"], "UNRESOLVED")
                self.assertEqual(row["repair_issue"], "UNRESOLVED")
                self.assertEqual(inventory["header"]["safety_disposition"], "FINDINGS_REMAIN_BLOCKING")
                self.assertTrue(row["evidence"])
            else:
                self.assertTrue(str(row["repair_owner"]).strip())
                self.assertTrue(str(row["repair_issue"]).strip())
                self.assertNotEqual(row["repair_issue"], "none-required")
            self.assertTrue(row["successor_scope"])

    # WORK_UNIT_CASE: 885/25
    def test_885_25_priority_inputs_are_scanned_or_excluded_with_evidence(self) -> None:
        scans = list(oracle.DEFAULT_SCAN)
        inventory = _build(ROOT, scans)
        header = inventory["header"]
        expected_files = oracle._collect_inputs(ROOT, scans)
        self.assertEqual(header["scan_roots"], sorted(scans))
        self.assertEqual(header["scan_denominator_files"], len(expected_files))
        expected_bytes = sum((ROOT / relative).stat().st_size for relative in expected_files)
        self.assertEqual(header["scan_denominator_bytes"], expected_bytes)
        exclusions = json.dumps(header.get("exclusions", []))
        for relative in scans:
            if (ROOT / relative).is_file():
                self.assertIn(relative, expected_files)
            else:
                self.assertIn(relative, exclusions)
                self.assertIn("absent at this revision", exclusions)
        packages = {oracle._package_of(ROOT, ROOT / relative) for relative in expected_files}
        self.assertEqual(header["scan_denominator_packages"], len(packages))
        self.assertCountEqual(header["scan_packages"], sorted(packages))

    # WORK_UNIT_CASE: 885/26
    def test_885_26_changed_deleted_and_moved_source_invalidates_artifact(self) -> None:
        original = "pub struct Registry { items: Vec<u8> }\n"
        with _workspace({"pkg/src/lib.rs": original}) as root:
            scans = ["pkg/src/lib.rs"]
            _store_artifact(root, _build(root, scans))
            source = root / scans[0]
            source.write_text(original + "// changed\n", encoding="utf-8")
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)
        with _workspace({"pkg/src/lib.rs": original}) as root:
            scans = ["pkg/src/lib.rs"]
            _store_artifact(root, _build(root, scans))
            (root / scans[0]).unlink()
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)
        with _workspace({"pkg/src/lib.rs": original}) as root:
            scans = ["pkg/src/lib.rs"]
            _store_artifact(root, _build(root, scans))
            source = root / scans[0]
            source.rename(root / "pkg/src/moved.rs")
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)
        with _workspace({"pkg/src/lib.rs": original}) as root:
            scans = ["pkg/src/lib.rs"]
            _store_artifact(root, _build(root, scans))
            manifest = root / "pkg/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8") + '\n[features]\nchanged = []\n',
                encoding="utf-8",
            )
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)

    # WORK_UNIT_CASE: 885/27
    def test_885_27_shuffled_traversal_has_identical_toml_and_digest(self) -> None:
        with _workspace({
            "alpha/src/a.rs": "pub struct A { items: Vec<u8> }\n",
            "beta/src/b.rs": "pub struct B { entries: Vec<String> }\n",
        }) as root:
            first = _build(root, ["alpha/src/a.rs", "beta/src/b.rs"])
            shuffled = _build(root, ["beta/src/b.rs", "alpha/src/a.rs"])
            self.assertEqual(first["inventory_digest"], shuffled["inventory_digest"])
            self.assertEqual(oracle._emit_toml(first), oracle._emit_toml(shuffled))

    # WORK_UNIT_CASE: 885/28
    def test_885_28_sync_is_repeatable_and_check_detects_hand_edits_read_only(self) -> None:
        with _workspace({"pkg/src/lib.rs": "pub struct Registry { items: Vec<u8> }\n"}) as root:
            scans = ["pkg/src/lib.rs"]
            self.assertEqual(_command(lambda: oracle.cmd_sync(root, scans, "matrix-test")), 0)
            target = root / oracle.OWNED_TOML
            first = target.read_bytes()
            self.assertEqual(_command(lambda: oracle.cmd_sync(root, scans, "matrix-test")), 0)
            second = target.read_bytes()
            self.assertEqual(first, second)
            before_check = _snapshot(root)
            self.assertEqual(_command(lambda: oracle.cmd_check(root)), 0)
            self.assertEqual(_snapshot(root), before_check, "check must not write or rewrite files")
            target.write_bytes(second + b"\n# hand edit\n")
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)

    # WORK_UNIT_CASE: 885/29
    def test_885_29_parse_malformed_and_incomplete_inputs_fail_closed(self) -> None:
        with self.assertRaises(oracle.InventoryError) as malformed_toml:
            oracle._parse_toml(b"[header\n", source="test")
        self.assertEqual(malformed_toml.exception.code, "MALFORMED_INVENTORY")
        with _workspace({"pkg/src/lib.rs": 'pub fn broken() { let text = "unterminated; }\n'}) as root:
            with self.assertRaises(oracle.InventoryError) as malformed_rust:
                _build(root, ["pkg/src/lib.rs"])
            self.assertEqual(malformed_rust.exception.code, "MALFORMED_RUST_SOURCE")
        with _workspace({"pkg/src/lib.rs": "pub struct Present { values: Vec<u8> }\n"}) as root:
            valid = _build(root, ["pkg/src/lib.rs"])
            missing_key = json.loads(json.dumps(valid))
            del missing_key["header"]["coverage_reason"]
            _refresh_digest(missing_key)
            with self.assertRaises(oracle.InventoryError):
                oracle._validate_artifact(missing_key)
            extra_key = json.loads(json.dumps(valid))
            extra_key["header"]["unsupported_claim"] = "silently accepted"
            _refresh_digest(extra_key)
            with self.assertRaises(oracle.InventoryError):
                oracle._validate_artifact(extra_key)
        with _workspace({"pkg/src/lib.rs": "pub struct Present;\n"}) as root:
            scans = ["pkg/src/lib.rs", "pkg/src/missing.rs"]
            self.assertEqual(_command(lambda: oracle.cmd_sync(root, scans, "matrix-test")), 2)
            target = root / oracle.OWNED_TOML
            self.assertTrue(target.is_file(), "sync records explicit incomplete coverage before failing")
            artifact = oracle._parse_toml(target.read_bytes(), source=target.as_posix())
            self.assertEqual(artifact["header"]["coverage_disposition"], "INCOMPLETE")
            self.assertNotEqual(_command(lambda: oracle.cmd_check(root)), 0)

    # WORK_UNIT_CASE: 885/30
    def test_885_30_source_api_guard_is_read_only_without_ambient_execution(self) -> None:
        source_text = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source_text)
        forbidden_modules = {"subprocess", "socket", "urllib", "requests", "http", "time", "datetime"}
        forbidden_calls = {
            "subprocess.run", "subprocess.Popen", "subprocess.call", "os.system", "os.popen",
            "eval", "exec", "time.time", "time.monotonic", "datetime.now",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse(any(alias.name.split(".")[0] in forbidden_modules for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], forbidden_modules)
            elif isinstance(node, ast.Call):
                parts: list[str] = []
                current = node.func
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                self.assertNotIn(".".join(reversed(parts)), forbidden_calls)
        self.assertEqual(oracle.OWNED_TOML.as_posix(), ".github/work-units/long-lived-collection-inventory.toml")
        with _workspace({"pkg/src/lib.rs": "pub struct Registry { items: Vec<u8> }\n"}) as root:
            before = _snapshot(root)
            _build(root, ["pkg/src/lib.rs"])
            self.assertEqual(_snapshot(root), before, "discovery must not mutate source or Cargo inputs")
        test_source = Path(__file__).read_text(encoding="utf-8")
        markers = re.findall(r"(?m)^    # WORK_UNIT_CASE: 885/(\d+)\n    def (test_[^(]+)", test_source)
        self.assertEqual([case for case, _ in markers], [str(number) for number in range(1, 31)])
        self.assertEqual(len({name for _, name in markers}), 30)
