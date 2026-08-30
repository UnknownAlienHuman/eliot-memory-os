"""Deterministic compiler fixtures and self-test."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .compiler import compile_registry
from .model import (
    PAIR_ALGORITHM,
    PAIR_DOMAIN,
    PAIR_SCHEMA,
    SCOPE_SCHEMA,
    RegistryError,
    fail,
    sha256,
    source_identity,
)


def fixture(root: Path) -> tuple[Path, str]:
    (root / "docs/architecture").mkdir(parents=True)
    architecture = root / "docs/architecture/ELIOT_ARCHITECTURE.md"
    implementation = root / "docs/architecture/ELIOT_IMPLEMENTATION.md"
    architecture.write_text("architecture\n", encoding="utf-8")
    implementation.write_text("implementation\n", encoding="utf-8")
    architecture_hash = sha256(architecture.read_bytes())
    implementation_hash = sha256(implementation.read_bytes())
    pair = "sha256:" + sha256(
        PAIR_DOMAIN
        + architecture_hash.encode()
        + b"\x00"
        + implementation_hash.encode()
        + b"\x00"
    )
    (root / "docs/normative-pair.toml").write_text(
        f'''schema_version = "{PAIR_SCHEMA}"
status = "accepted"
repository_authority_branch = "main"
pair_key_algorithm = "{PAIR_ALGORITHM}"
pair_key = "{pair}"
architecture_path = "docs/architecture/ELIOT_ARCHITECTURE.md"
architecture_sha256 = "{architecture_hash}"
implementation_path = "docs/architecture/ELIOT_IMPLEMENTATION.md"
implementation_sha256 = "{implementation_hash}"
''',
        encoding="utf-8",
    )
    (root / "workstreams/core-daemons").mkdir(parents=True)
    (root / "workstreams/core-daemons/inventory.json").write_text(
        json.dumps(
            {
                "units": [
                    {"id": "host", "paths": ["crates/host"]},
                    {"id": "kernel", "paths": ["crates/kernel"]},
                ]
            }
        ),
        encoding="utf-8",
    )

    package = root / "crates/host"
    (package / "src").mkdir(parents=True)
    (package / "src/lib.rs").write_text("pub struct Contract;\n", encoding="utf-8")
    (package / "Cargo.toml").write_text(
        '''[package]
name = "eliot-host-test"
version = "0.1.0"
edition = "2024"
[package.metadata.eliot]
source_maintenance_owner = "source.host"
cell_manifest = "capability-cells.toml"
''',
        encoding="utf-8",
    )
    (root / "config").mkdir(parents=True)
    (root / "config/capability-cell-registry-scope.toml").write_text(
        "\n".join(
            [
                f'schema = "{SCOPE_SCHEMA}"',
                'inventory_path = "workstreams/core-daemons/inventory.json"',
                "inventory_unit_ids = []",
                'package_roots = ["crates/host"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    manifest = package / "capability-cells.toml"
    manifest.write_text(
        '''schema = "eliot.capability-cells.v1"
package = "eliot-host-test"
[[cell]]
cell_id = "host.journal"
causal_responsibility = "Own one exact host journal transition."
lifecycle_owner = "runtime.host"
runtime_owner = "runtime.host"
runtime_bundle = "eliot-host"
execution_contour = "static_native"
replacement_class = "host_generation"
removal_boundary = "Migration proof is required."
stateless = false
owned_state = [{ state_id = "host_state_journal", owner = "runtime.host" }]
allowed_effect_classes = ["host_journal_write"]
contract_owner = "contract.host-journal"
contract_sources = ["crates/host/src/lib.rs"]
proof_entrypoint = "cargo test -p eliot-host-test"
proof_ceiling = "MODULE_ONLY"
edge_profiles = ["host-journal-write-readback"]
product_pulse = "D0_HOST_JOURNAL"
implementation_support = "CURRENT_UNVERIFIED"
evidence_execution_status = "NOT_EXECUTED"
providers = []
consumers = ["eliot-host"]
invalidation = ["source_sha", "normative_pair", "contract_digest"]
''',
        encoding="utf-8",
    )
    return manifest, pair


def self_test() -> None:
    for value in ("a" * 40, "b" * 64):
        if source_identity(value) != value:
            fail("valid source identity changed")
    for value in (
        "a" * 39,
        "a" * 41,
        "a" * 63,
        "a" * 65,
        "A" * 40,
        "g" * 40,
    ):
        try:
            source_identity(value)
        except RegistryError:
            pass
        else:
            fail(f"invalid source identity was accepted: {value[:8]}... len={len(value)}")

    with tempfile.TemporaryDirectory(prefix="eliot-cell-registry-") as temporary:
        root = Path(temporary)
        manifest, pair = fixture(root)
        registry, findings = compile_registry(root, "c" * 40)
        if findings or registry["status"] != "COMPLETE" or len(registry["cells"]) != 1:
            fail("valid fixture did not compile cleanly")
        scope = registry["scope"]
        if scope["coverage_status"] != "DECLARED_PARTIAL_SCOPE":
            fail("fixture did not preserve its explicit partial coverage denominator")
        if scope["unselected_inventory_units"] != ("host", "kernel"):
            fail("fixture did not expose unselected inventory units")

        original = manifest.read_text(encoding="utf-8")
        manifest.write_text(
            original.replace(
                'proof_entrypoint = "cargo test -p eliot-host-test"\n', ""
            ),
            encoding="utf-8",
        )
        _, broken = compile_registry(root, "d" * 64)
        if not any(finding.code == "invalid_cell_manifest" for finding in broken):
            fail("missing proof entrypoint was accepted")
        manifest.write_text(original, encoding="utf-8")

        receipt = root / "docs/normative-pair.toml"
        receipt.write_text(
            receipt.read_text(encoding="utf-8").replace(
                pair, "sha256:" + "0" * 64
            ),
            encoding="utf-8",
        )
        try:
            compile_registry(root, "e" * 40)
        except RegistryError:
            pass
        else:
            fail("stale normative pair was accepted")

    print("CAPABILITY_CELL_REGISTRY_SELF_TEST: PASS cases=13")
