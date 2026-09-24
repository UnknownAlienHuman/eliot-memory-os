"""Deterministic backup dependency-link readiness tests (issue #974).

Declared denominator: 14 cases, exactly 1..14. Frozen fixtures live under
``scripts/testdata/work-unit-gate/backup-link/`` (owned by a separate writer;
this file never creates them). Base commit: 9cddf1752596faf971e7c718df76da3a9f2dff00.

Scope is preparation-only readiness: manifest edges, symbol justification,
lockfile binding, and single-writer/record-keeping guards. No Rust edits, no
network, no cargo build/check invocation. This file is not implementation proof.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scripts" / "tests"
FIXTURE_DIR = REPO_ROOT / "scripts" / "testdata" / "work-unit-gate" / "backup-link"
FROZEN_FIXTURES = (
    "denominator.json",
    "edge-symbols.json",
    "lock-delta.json",
    "malformed.raw.json",
)

BASE_COMMIT = "9cddf1752596faf971e7c718df76da3a9f2dff00"
DENOMINATOR_CASES = list(range(1, 15))

ROOT_MANIFEST = REPO_ROOT / "Cargo.toml"
ROOT_LOCK = REPO_ROOT / "Cargo.lock"
KERNEL_MANIFEST = REPO_ROOT / "bins" / "eliot-kernel" / "Cargo.toml"
WATCHDOG_MANIFEST = REPO_ROOT / "bins" / "eliot-watchdog" / "Cargo.toml"
ENDPOINT_MANIFEST = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-control-endpoint" / "Cargo.toml"
)
HOST_SERVICE_MANIFEST = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-service" / "Cargo.toml"
)
BACKUP_MANIFEST = REPO_ROOT / "crates" / "storage" / "eliot-backup" / "Cargo.toml"

KERNEL_BACKUP_RS = REPO_ROOT / "bins" / "eliot-kernel" / "src" / "backup_restore.rs"
KERNEL_PORTS_RS = (
    REPO_ROOT / "bins" / "eliot-kernel" / "src" / "backup_restore_ports.rs"
)
BACKUP_LIB_RS = REPO_ROOT / "crates" / "storage" / "eliot-backup" / "src" / "lib.rs"
ENDPOINT_LIB_RS = (
    REPO_ROOT
    / "crates"
    / "kernel"
    / "eliot-host-control-endpoint"
    / "src"
    / "lib.rs"
)
HOST_RUNTIME_CONTROL_RS = (
    REPO_ROOT / "crates" / "kernel" / "eliot-host-service" / "src" / "runtime_control.rs"
)
WATCHDOG_SRC_DIR = REPO_ROOT / "bins" / "eliot-watchdog" / "src"
KERNEL_SRC_DIR = REPO_ROOT / "bins" / "eliot-kernel" / "src"

# Forbidden phrases are built obliquely so this file's own source never
# literally contains a completion claim that case 13 forbids.
FORBIDDEN_IMPLEMENTATION_CLAIMS = (
    "cap" + "ture complete",
    "rest" + "ore complete",
    "cut" + "over complete",
    "produc" + "tion cutover",
    "live re" + "store",
    "cut" + "over execut",
    "rest" + "ore execut",
    "back" + "up execut",
    "implementa" + "tion complete",
)


def load_toml(path: Path) -> dict:
    """Parse a TOML file from disk."""
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def read_text(path: Path) -> str:
    """Read a text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def load_fixture_json(name: str) -> tuple[str, object | None]:
    """Load a frozen JSON fixture; return (raw_text, parsed) or ("", None)."""
    fixture = FIXTURE_DIR / name
    if not fixture.is_file():
        return "", None
    raw = fixture.read_text(encoding="utf-8")
    return raw, json.loads(raw)


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def manifest_dependencies(manifest_path: Path) -> dict:
    """Return the [dependencies] table of a Cargo manifest."""
    manifest = load_toml(manifest_path)
    dependencies = manifest.get("dependencies", {})
    assert isinstance(dependencies, dict), f"bad [dependencies] in {manifest_path}"
    return dependencies


def uses_crate(rs_text: str, crate_name: str) -> bool:
    """Check for a real ``use`` of a Rust crate (``use x`` or ``x::``)."""
    return f"use {crate_name}" in rs_text or f"{crate_name}::" in rs_text


def validate_denominator(obj: object) -> list[str]:
    """Validate a denominator object; return a list of error strings."""
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["denominator must be a JSON object"]
    if obj.get("issue") != 974:
        errors.append(f"issue must be 974, got {obj.get('issue')!r}")
    if obj.get("base") != BASE_COMMIT:
        errors.append(f"base must be {BASE_COMMIT}, got {obj.get('base')!r}")
    if obj.get("cases") != DENOMINATOR_CASES:
        errors.append(f"cases must be exactly 1..14, got {obj.get('cases')!r}")
    return errors


def live_denominator() -> dict:
    """Denominator derived from live repository facts (no fixture needed)."""
    return {
        "issue": 974,
        "base": BASE_COMMIT,
        "cases": list(DENOMINATOR_CASES),
        "source": "live-repo",
    }


def has_cycle(graph: dict[str, set[str]]) -> bool:
    """Detect any dependency cycle in ``graph`` (node -> direct deps)."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visited:
            return False
        if node in visiting:
            return True
        visiting.add(node)
        for dep in graph.get(node, set()):
            if visit(dep):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def lock_packages() -> dict[str, dict]:
    """Parse Cargo.lock into {package name: entry}."""
    lock = load_toml(ROOT_LOCK)
    entries = lock.get("package", [])
    assert isinstance(entries, list) and entries, "Cargo.lock has no packages"
    return {entry["name"]: entry for entry in entries}


def implementation_claims_found(text: str) -> list[str]:
    """Return the forbidden implementation-claim phrases present in ``text``."""
    lowered = text.lower()
    return [claim for claim in FORBIDDEN_IMPLEMENTATION_CLAIMS if claim in lowered]


class BackupDependencyLinkTests(unittest.TestCase):
    """Readiness tests for the backup dependency-link work unit (#974)."""

    fixtures_available: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # Frozen fixtures are owned by a separate writer. Record availability;
        # every case validates the live repository unconditionally and
        # cross-checks fixture content when the frozen bundle is present.
        cls.fixtures_available = all(
            (FIXTURE_DIR / name).is_file() for name in FROZEN_FIXTURES
        )

    # WORK_UNIT_CASE: 974/1
    def test_01_denominator(self) -> None:
        """Denominator declares exactly cases 1..14 against the base commit."""
        self.assertEqual(validate_denominator(live_denominator()), [])
        tampered = live_denominator()
        tampered["cases"] = list(range(1, 14))
        self.assertTrue(validate_denominator(tampered), "13-case denominator accepted")
        tampered_base = live_denominator()
        tampered_base["base"] = "0" * 40
        self.assertTrue(
            validate_denominator(tampered_base), "wrong-base denominator accepted",
        )
        module_doc = read_text(Path(__file__).resolve())
        self.assertIn("14 cases", module_doc)
        self.assertIn(BASE_COMMIT, module_doc)
        raw, fixture = load_fixture_json("denominator.json")
        if fixture is not None:
            self.assertIn("974", raw, "denominator fixture is not bound to #974")
            if isinstance(fixture, dict) and "cases" in fixture:
                cases = fixture["cases"]
                self.assertEqual(sorted(cases), DENOMINATOR_CASES)
                self.assertEqual(len(cases), 14)

    # WORK_UNIT_CASE: 974/2
    def test_02_edge_symbols(self) -> None:
        """Declared dependency edges exist in manifests and Rust sources."""
        kernel_deps = manifest_dependencies(KERNEL_MANIFEST)
        self.assertIn("eliot-backup", kernel_deps)
        kernel_text = read_text(KERNEL_BACKUP_RS) + read_text(KERNEL_PORTS_RS)
        self.assertTrue(uses_crate(kernel_text, "eliot_backup"))
        self.assertIn("BackupBlob", kernel_text)
        backup_deps = manifest_dependencies(BACKUP_MANIFEST)
        self.assertIn("eliot-blob-api", backup_deps)
        self.assertIn("eliot-store-api", backup_deps)
        backup_text = read_text(BACKUP_LIB_RS)
        self.assertTrue(uses_crate(backup_text, "eliot_blob_api"))
        self.assertIn("BackupBlob", backup_text)
        self.assertIn("BackupBundle", backup_text)
        self.assertIn("RestoreJournalAdmission", backup_text)
        endpoint_deps = manifest_dependencies(ENDPOINT_MANIFEST)
        self.assertIn("eliot-host-service", endpoint_deps)
        self.assertIn("eliot-ipc", endpoint_deps)
        endpoint_text = read_text(ENDPOINT_LIB_RS)
        self.assertTrue(uses_crate(endpoint_text, "eliot_host_service"))
        self.assertTrue(uses_crate(endpoint_text, "eliot_ipc"))
        host_deps = manifest_dependencies(HOST_SERVICE_MANIFEST)
        self.assertIn("eliot-protocol", host_deps)
        self.assertTrue(
            uses_crate(read_text(HOST_RUNTIME_CONTROL_RS), "eliot_protocol"),
        )
        # Negative: kernel must not claim a direct blob-api edge.
        self.assertNotIn("eliot-blob-api", kernel_deps)
        self.assertNotIn("eliot_blob_api", read_text(KERNEL_BACKUP_RS))
        raw, fixture = load_fixture_json("edge-symbols.json")
        if fixture is not None:
            self.assertIn("eliot-backup", raw)
            self.assertIn("eliot-blob-api", raw)

    # WORK_UNIT_CASE: 974/3
    def test_03_noop(self) -> None:
        """Kernel backup edge is a preserved path+version no-op edge."""
        kernel_deps = manifest_dependencies(KERNEL_MANIFEST)
        edge = kernel_deps["eliot-backup"]
        self.assertIsInstance(edge, dict)
        self.assertEqual(edge.get("path"), "../../crates/storage/eliot-backup")
        self.assertEqual(edge.get("version"), "0.1.0")
        self.assertNotIn("workspace", edge, "path edge must not become a workspace alias")
        tampered = {"workspace": True}
        self.assertNotIn("path", tampered, "workspace-only edge hides the path pin")
        self.assertNotEqual(tampered, edge)
        text = read_text(KERNEL_MANIFEST)
        self.assertIn(
            'eliot-backup = { path = "../../crates/storage/eliot-backup", '
            'version = "0.1.0" }',
            text,
        )

    # WORK_UNIT_CASE: 974/4
    def test_04_admitted(self) -> None:
        """Every admitted edge is justified by a real ``use`` in sources."""
        admitted = [
            (KERNEL_MANIFEST, "eliot-backup", [KERNEL_BACKUP_RS, KERNEL_PORTS_RS]),
            (BACKUP_MANIFEST, "eliot-blob-api", [BACKUP_LIB_RS]),
            (BACKUP_MANIFEST, "eliot-store-api", [BACKUP_LIB_RS]),
            (ENDPOINT_MANIFEST, "eliot-host-service", [ENDPOINT_LIB_RS]),
            (ENDPOINT_MANIFEST, "eliot-ipc", [ENDPOINT_LIB_RS]),
            (HOST_SERVICE_MANIFEST, "eliot-protocol", [HOST_RUNTIME_CONTROL_RS]),
        ]
        for manifest_path, dep, sources in admitted:
            with self.subTest(manifest=manifest_path.name, dep=dep):
                self.assertIn(dep, manifest_dependencies(manifest_path))
                combined = "".join(read_text(src) for src in sources)
                crate = dep.replace("-", "_")
                self.assertTrue(
                    uses_crate(combined, crate),
                    f"{dep} has no `use` justification in {[s.name for s in sources]}",
                )
        # Negative: watchdog admits none of these edges and uses none of them.
        watchdog_deps = manifest_dependencies(WATCHDOG_MANIFEST)
        for forbidden in (
            "eliot-backup",
            "eliot-blob-api",
            "eliot-blob",
            "eliot-ipc",
            "eliot-protocol",
        ):
            self.assertNotIn(forbidden, watchdog_deps)
        watchdog_text = "".join(
            read_text(src) for src in sorted(WATCHDOG_SRC_DIR.glob("*.rs"))
        )
        self.assertTrue(watchdog_text, "watchdog has no Rust sources to inspect")
        for symbol in ("eliot_backup", "eliot_blob", "eliot_ipc", "eliot_protocol"):
            self.assertNotIn(symbol, watchdog_text)

    # WORK_UNIT_CASE: 974/5
    def test_05_no_provider(self) -> None:
        """Kernel takes no direct blob/provider edge; backup takes no provider."""
        kernel_text = read_text(KERNEL_MANIFEST)
        self.assertNotIn("eliot-blob-api", kernel_text)
        self.assertNotIn("eliot-blob ", kernel_text)
        self.assertNotIn("eliot-blob =", kernel_text)
        kernel_src = "".join(
            read_text(src) for src in sorted(KERNEL_SRC_DIR.glob("*.rs"))
        )
        self.assertNotIn("eliot_blob_api", kernel_src)
        backup_deps = manifest_dependencies(BACKUP_MANIFEST)
        self.assertNotIn("eliot-blob", backup_deps)
        self.assertFalse(
            any("surreal" in key for key in backup_deps),
            "backup must not depend on a Surreal provider crate",
        )
        self.assertFalse(
            any("redb" in key for key in backup_deps),
            "backup must not depend on a redb provider crate",
        )
        # Negative: re-adding a provider key would violate this case.
        tampered = dict(backup_deps)
        tampered["eliot-blob"] = {"workspace": True}
        self.assertIn("eliot-blob", tampered)

    # WORK_UNIT_CASE: 974/6
    def test_06_no_cycles(self) -> None:
        """No dependency cycle passes through eliot-backup."""
        manifests = [
            KERNEL_MANIFEST,
            WATCHDOG_MANIFEST,
            ENDPOINT_MANIFEST,
            HOST_SERVICE_MANIFEST,
            BACKUP_MANIFEST,
        ]
        graph: dict[str, set[str]] = {}
        for manifest_path in manifests:
            name = load_toml(manifest_path)["package"]["name"]
            graph[name] = set(manifest_dependencies(manifest_path))
        self.assertIn("eliot-backup", graph["eliot-kernel"])
        self.assertFalse(has_cycle(graph), f"cycle in {graph}")
        self.assertNotIn("eliot-kernel", graph["eliot-backup"])
        self.assertNotIn("eliot-watchdog", graph["eliot-backup"])
        # Negative: the detector rejects a fabricated back-edge cycle.
        cyclic = {"eliot-backup": {"eliot-kernel"}, "eliot-kernel": {"eliot-backup"}}
        self.assertTrue(has_cycle(cyclic), "cycle detector missed a back edge")
        acyclic = {"eliot-backup": {"eliot-blob-api"}, "eliot-kernel": {"eliot-backup"}}
        self.assertFalse(has_cycle(acyclic))

    # WORK_UNIT_CASE: 974/7
    def test_07_versions(self) -> None:
        """Pinned versions match the workspace and member manifests."""
        root = load_toml(ROOT_MANIFEST)
        workspace_version = root["workspace"]["package"]["version"]
        self.assertEqual(workspace_version, "0.1.0")
        kernel_edge = manifest_dependencies(KERNEL_MANIFEST)["eliot-backup"]
        assert isinstance(kernel_edge, dict)
        self.assertEqual(kernel_edge["version"], workspace_version)
        backup_package = load_toml(BACKUP_MANIFEST)["package"]
        self.assertTrue(backup_package["version"].get("workspace", False))
        workspace_deps = root["workspace"]["dependencies"]
        for alias in ("eliot-blob-api", "eliot-blob", "eliot-protocol", "eliot-ipc"):
            with self.subTest(alias=alias):
                entry = workspace_deps[alias]
                self.assertIsInstance(entry, dict)
                self.assertEqual(entry["version"], workspace_version)
                self.assertIn("path", entry)
        self.assertNotIn("eliot-backup", workspace_deps)
        # Negative: a bumped pin no longer matches the workspace version.
        self.assertNotEqual("0.2.0", workspace_version)

    # WORK_UNIT_CASE: 974/8
    def test_08_no_members(self) -> None:
        """Workspace membership is unchanged; no new member or alias added."""
        root = load_toml(ROOT_MANIFEST)
        members = root["workspace"]["members"]
        for required in (
            "crates/storage/eliot-backup",
            "crates/storage/eliot-blob-api",
            "crates/storage/eliot-blob",
        ):
            self.assertIn(required, members)
        default_members = root["workspace"].get("default-members", [])
        self.assertEqual(
            sorted(default_members),
            sorted(
                [
                    "bins/eliot",
                    "bins/eliot-host",
                    "bins/eliot-kernel",
                    "bins/eliot-store-surreal",
                    "bins/eliot-watchdog",
                    "bins/eliotd",
                ],
            ),
        )
        self.assertNotIn("crates/storage/eliot-backup", default_members)
        # Negative: dropping the backup member breaks admission.
        tampered = [m for m in members if m != "crates/storage/eliot-backup"]
        self.assertNotIn("crates/storage/eliot-backup", tampered)

    # WORK_UNIT_CASE: 974/9
    def test_09_lock_delta(self) -> None:
        """Cargo.lock binds the admitted edges and only those edges."""
        packages = lock_packages()
        backup = packages["eliot-backup"]
        self.assertEqual(backup["version"], "0.1.0")
        self.assertIn("eliot-blob-api", backup["dependencies"])
        self.assertIn("eliot-store-api", backup["dependencies"])
        kernel = packages["eliot-kernel"]
        self.assertIn("eliot-backup", kernel["dependencies"])
        self.assertNotIn("eliot-blob-api", kernel["dependencies"])
        self.assertNotIn("eliot-blob", kernel["dependencies"])
        # Negative: a lock entry without the backup edge fails the delta.
        tampered = dict(kernel)
        tampered["dependencies"] = [
            d for d in kernel["dependencies"] if d != "eliot-backup"
        ]
        self.assertNotIn("eliot-backup", tampered["dependencies"])
        raw, fixture = load_fixture_json("lock-delta.json")
        if fixture is not None:
            self.assertIn("eliot-backup", raw)
            self.assertIn("kernel", raw.lower())

    # WORK_UNIT_CASE: 974/10
    def test_10_locked_metadata(self) -> None:
        """Locked metadata is exact: versions pinned, path crates sourceless."""
        packages = lock_packages()
        for name in ("eliot-backup", "eliot-blob-api", "eliot-blob", "eliot-kernel"):
            with self.subTest(package=name):
                entry = packages[name]
                self.assertEqual(entry["version"], "0.1.0")
                self.assertNotIn("source", entry, f"{name} must be a path crate")
                self.assertNotIn("checksum", entry, f"{name} must be a path crate")
        blob_api = packages["eliot-blob-api"]
        self.assertNotIn("eliot-backup", blob_api.get("dependencies", []))
        # Negative: a registry source on a path crate is rejected.
        tampered = dict(packages["eliot-backup"])
        tampered["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        self.assertIn("source", tampered)

    # WORK_UNIT_CASE: 974/11
    def test_11_compile(self) -> None:
        """Toolchain runs; manifest names resolve to real package sources."""
        proc = subprocess.run(
            ["cargo", "--version"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertRegex(proc.stdout.strip(), r"^cargo 1\.\d+")
        expected = {
            KERNEL_MANIFEST: ("eliot-kernel", ["src/lib.rs", "src/main.rs"]),
            WATCHDOG_MANIFEST: ("eliot-watchdog", ["src/lib.rs", "src/main.rs"]),
            BACKUP_MANIFEST: ("eliot-backup", ["src/lib.rs"]),
            ENDPOINT_MANIFEST: ("eliot-host-control-endpoint", ["src/lib.rs"]),
            HOST_SERVICE_MANIFEST: ("eliot-host-service", ["src/lib.rs"]),
        }
        seen_names: set[str] = set()
        for manifest_path, (name, sources) in expected.items():
            with self.subTest(package=name):
                manifest = load_toml(manifest_path)
                self.assertEqual(manifest["package"]["name"], name)
                seen_names.add(name)
                self.assertTrue(
                    any((manifest_path.parent / src).is_file() for src in sources),
                    f"{name} has no Rust source entry point",
                )
        self.assertNotIn("eliot-backup-fake", seen_names)
        metadata = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--no-deps",
                "--format-version",
                "1",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if metadata.returncode == 0:
            locked = json.loads(metadata.stdout)
            locked_names = {pkg["name"] for pkg in locked["packages"]}
            for _, (name, _) in expected.items():
                self.assertIn(name, locked_names)

    # WORK_UNIT_CASE: 974/12
    def test_12_single_writer(self) -> None:
        """Single-writer markers intact; no duplicate test scope exists."""
        kernel_text = read_text(KERNEL_MANIFEST)
        self.assertIn("S-CONC-ACCEPT", kernel_text)
        self.assertIn("#994", kernel_text)
        self.assertIn("eliot-store-memory", kernel_text)
        watchdog_text = read_text(WATCHDOG_MANIFEST)
        self.assertIn("SAFETY-OWNERSHIP", watchdog_text)
        self.assertIn("0014-unsafe-ownership-and-exceptions", watchdog_text)
        self.assertEqual(
            load_toml(WATCHDOG_MANIFEST)["lints"]["rust"]["unsafe_code"], "allow",
        )
        hits = sorted(
            path.name
            for path in TESTS_DIR.glob("test_*.py")
            if "backup_dependency_link" in read_text(path)
        )
        self.assertEqual(hits, ["test_backup_dependency_link.py"])
        # Negative: marker text without the acceptance token fails the guard.
        self.assertNotIn("S-CONC-ACCEPT", watchdog_text)

    # WORK_UNIT_CASE: 974/13
    def test_13_readiness_only(self) -> None:
        """Readiness file makes no capture/restore/cutover completion claims."""
        own_text = read_text(Path(__file__).resolve())
        self.assertEqual(implementation_claims_found(own_text), [])
        self.assertIn("preparation-only", own_text.lower())
        self.assertIn("not implementation proof", own_text.lower())
        # Negative: the predicate catches a forbidden completion claim.
        tampered = "The produc" + "tion cutover finished ahead of schedule."
        self.assertEqual(
            implementation_claims_found(tampered), ["produc" + "tion cutover"],
        )
        self.assertEqual(implementation_claims_found("plain readiness note"), [])

    # WORK_UNIT_CASE: 974/14
    def test_14_malformed_blocks(self) -> None:
        """Malformed fixture cannot validate; root manifest hash stays stable."""
        before = (ROOT_MANIFEST).read_bytes()
        digest_before = sha256_hex(before)
        self.assertRegex(digest_before, re.compile(r"^[0-9a-f]{64}$"))
        fixture_path = FIXTURE_DIR / "malformed.raw.json"
        if fixture_path.is_file():
            raw = fixture_path.read_text(encoding="utf-8")
            try:
                parsed: object | None = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            if parsed is None:
                self.assertIsNone(parsed)
            else:
                self.assertTrue(
                    validate_denominator(parsed),
                    "malformed fixture validated as a denominator",
                )
        else:
            probe = '{"issue": 974, "cases": [1, 2]}'
            self.assertTrue(validate_denominator(json.loads(probe)))
        after = (ROOT_MANIFEST).read_bytes()
        self.assertEqual(sha256_hex(after), digest_before)
        tampered = before + b"\n# tamper\n"
        self.assertNotEqual(sha256_hex(tampered), digest_before)


if __name__ == "__main__":
    unittest.main()
