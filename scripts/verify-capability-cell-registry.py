#!/usr/bin/env python3
"""Independent negative/current-slice verifier for capability-cell evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(f"CAPABILITY_CELL_REGISTRY_VERIFY_FAIL: {message}")


def load_generator(path: Path):
    spec = importlib.util.spec_from_file_location("eliot_capability_cell_registry", path)
    if spec is None or spec.loader is None:
        fail(f"cannot load generator: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def add_conflicting_package(root: Path) -> None:
    inventory_path = root / "workstreams/core-daemons/inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["units"][0]["paths"].append("crates/host-conflict")
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")

    package = root / "crates/host-conflict"
    (package / "src").mkdir(parents=True)
    (package / "src/lib.rs").write_text("pub struct OtherContract;\n", encoding="utf-8")
    (package / "Cargo.toml").write_text(
        '''[package]
name = "eliot-host-conflict"
version = "0.1.0"
edition = "2024"
[package.metadata.eliot]
source_maintenance_owner = "source.host-conflict"
cell_manifest = "capability-cells.toml"
''',
        encoding="utf-8",
    )
    (package / "capability-cells.toml").write_text(
        '''schema = "eliot.capability-cells.v1"
package = "eliot-host-conflict"
[[cell]]
cell_id = "host.conflict"
causal_responsibility = "Attempt to steal existing state and contract ownership."
lifecycle_owner = "runtime.host-conflict"
runtime_owner = "runtime.host-conflict"
runtime_bundle = "eliot-host-conflict"
execution_contour = "static_native"
replacement_class = "host_generation"
removal_boundary = "Conflict fixture only."
stateless = false
owned_state = [{ state_id = "host_state_journal", owner = "runtime.host-conflict" }]
allowed_effect_classes = []
contract_owner = "contract.host-conflict"
contract_sources = ["crates/host/src/lib.rs"]
proof_entrypoint = "cargo test -p eliot-host-conflict"
proof_ceiling = "MODULE_ONLY"
edge_profiles = []
product_pulse = "D0_HOST_CONFLICT"
implementation_support = "CURRENT_UNVERIFIED"
evidence_execution_status = "NOT_EXECUTED"
providers = []
consumers = []
invalidation = ["source_sha", "contract_digest"]
''',
        encoding="utf-8",
    )


def self_test(generator) -> None:
    with tempfile.TemporaryDirectory(prefix="eliot-cell-registry-verify-") as temporary:
        root = Path(temporary)
        generator.fixture(root)
        add_conflicting_package(root)
        registry, findings = generator.compile_registry(root, "a" * 40)
        codes = {finding.code for finding in findings}
        expected = {"duplicate_state_owner", "duplicate_contract_owner"}
        missing = expected.difference(codes)
        if missing:
            fail(f"duplicate ownership fixture missed: {', '.join(sorted(missing))}")
        if registry["status"] != "PARTIAL":
            fail("duplicate ownership fixture did not produce PARTIAL registry")

    print("CAPABILITY_CELL_REGISTRY_NEGATIVE_SELF_TEST: PASS cases=2")


def verify_current(generator, root: Path, source_sha: str, output: Path | None) -> None:
    registry, findings = generator.compile_registry(root, source_sha)
    expected = {
        "eliot-runtime-status": {
            "pulse": "D0_RUNTIME_STATUS_RECOVERY_VIEW_01",
            "ids": {
                "meta.runtime-status.report-composition",
                "meta.runtime-status.service-registration-observation",
                "meta.runtime-status.supervision-verification",
                "meta.runtime-status.supervision-projection",
                "meta.runtime-status.store-live-observation",
                "meta.runtime-status.eliotd-live-observation",
                "meta.runtime-status.watchdog-live-observation",
                "meta.runtime-status.readiness-projection",
            },
        },
        "eliot-runtime-contracts": {
            "pulse": "D0_RUNTIME_CONTRACT_COMPATIBILITY_01",
            "ids": {
                "foundation.runtime-contracts.lifecycle-core",
                "foundation.runtime-contracts.installation-activation",
                "foundation.runtime-contracts.runtime-live-store-identity",
                "foundation.runtime-contracts.supervision-authority",
                "foundation.runtime-contracts.supervision-incarnation",
                "foundation.runtime-contracts.supervision-lease",
                "foundation.runtime-contracts.watchdog-admission-publication",
            },
        },
    }
    checked = 0
    for package, profile in expected.items():
        cells = [cell for cell in registry["cells"] if cell["package"] == package]
        observed_ids = {cell["cell_id"] for cell in cells}
        if observed_ids != profile["ids"]:
            fail(
                f"{package} cell set mismatch: "
                f"missing={sorted(profile['ids'] - observed_ids)} "
                f"extra={sorted(observed_ids - profile['ids'])}"
            )
        package_findings = [finding for finding in findings if finding.package == package]
        if package_findings:
            fail(
                f"{package} has registry findings: "
                + ", ".join(sorted({finding.code for finding in package_findings}))
            )
        for cell in cells:
            if not cell["stateless"] or cell["owned_state"] or cell["allowed_effect_classes"]:
                fail(f"{cell['cell_id']} exceeds its stateless no-effect boundary")
            if (
                cell["implementation_support"] != "CURRENT_UNVERIFIED"
                or cell["evidence_execution_status"] != "NOT_EXECUTED"
            ):
                fail(f"{cell['cell_id']} overclaims support or executed evidence")
            if cell["product_pulse"] != profile["pulse"]:
                fail(f"{cell['cell_id']} is not bound to {profile['pulse']}")
            checked += 1

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "CAPABILITY_CELL_REGISTRY_CURRENT_VERIFY: PASS "
        f"declared_cells={checked} repository_findings={len(findings)} "
        f"registry_status={registry['status']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("self-test", "current"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    root = args.repo.resolve()
    generator_path = root / "scripts/generate-capability-cell-registry.py"
    if not generator_path.is_file():
        fail(f"generator is missing: {generator_path}")
    generator = load_generator(generator_path)

    if args.command == "self-test":
        self_test(generator)
    else:
        if not args.source_sha:
            fail("current verification requires --source-sha")
        verify_current(generator, root, generator.source_identity(args.source_sha), args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerificationError, Exception) as error:
        if isinstance(error, SystemExit):
            raise
        print(error, file=sys.stderr)
        raise SystemExit(1)
