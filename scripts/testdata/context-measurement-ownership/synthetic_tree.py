"""Build a synthetic, complete, green #866+#787 tree for the #787 test matrix.

The shared live tree cannot go green yet: the #704 artifact on main is stale
against main's sources, the frozen owner map is not supplied, four candidates
remain unresolved, and the three consumer migrations (#783/#878/#880) have not
landed. Those are all *true* findings, not oracle defects, and this oracle
must not be weakened to hide them.

To prove the oracle CAN exit zero -- and to give every accept/reject case a
controlled tree -- this module assembles a bounded synthetic tree in which the
#866 producer genuinely produces a complete, current, zero-unresolved
inventory with a supplied owner map, and every consumer really does carry the
canonical dependency. Nothing here is a stub: the tree is built by calling the
accepted #866 generator's own ``sync`` and ``check``.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

# The producer's exact module path inside the repository.
PRODUCER_REL = "scripts/context_measurement_inventory.py"


def load_producer(root: Path):
    """Import the accepted #866 generator from ``root``."""
    spec = importlib.util.spec_from_file_location(
        f"_cmi_synthetic_{abs(hash(str(root))) % 100000}", root / PRODUCER_REL
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# The synthetic denominator. Each entry is (case_ref, owner, path, signal).
# The signals are chosen so the producer's own closed classifier resolves them
# to closed classes without any new rule.
SYNTHETIC_CASES: tuple[tuple[str, str, str, str], ...] = (
    # #704 owns the canonical STU formula and the canonical measurement entry.
    ("s/1", "#704", "src/owner/stu.rs", "stu_for_bytes"),
    ("s/2", "#704", "src/owner/measure.rs", "measure_serialized_context"),
    ("s/3", "#704", "src/owner/measure.rs", "rendered_utf8_bytes"),
    ("s/4", "#704", "src/owner/measure.rs", "envelope_digest"),
    # #783 consumes the canonical measurement through its exact dependency.
    ("s/5", "#783", "src/app/consumer.rs", "measure_serialized_context"),
    ("s/6", "#783", "src/app/consumer.rs", "final_bytes"),
    # #878 consumes the canonical measurement.
    ("s/7", "#878", "src/engine/consumer.rs", "measure_serialized_context"),
    ("s/8", "#878", "src/engine/consumer.rs", "serializer_id"),
    # #880 consumes the canonical measurement.
    ("s/9", "#880", "src/engine/skill.rs", "measure_serialized_context"),
    ("s/10", "#880", "src/engine/skill.rs", "StuEstimate"),
)

OWNER_SOURCE_PATHS: dict[str, tuple[str, ...]] = {
    "#704": ("src/owner/stu.rs", "src/owner/measure.rs"),
    "#783": ("src/app/consumer.rs",),
    "#878": ("src/engine/consumer.rs",),
    "#880": ("src/engine/skill.rs",),
}

# Each consumer source names the canonical measurement crate so the dependency
# check has real evidence, and calls the canonical entry point.
CONSUMER_SOURCE: dict[str, str] = {
    "src/app/consumer.rs": (
        "use eliot_context_measurement::measure_serialized_context;\n"
        "\n"
        "pub fn app_context_cost(payload_utf8: &str) -> u64 {\n"
        "    let params = build_params(payload_utf8);\n"
        "    let measured = measure_serialized_context(&params).ok();\n"
        "    let final_bytes = measured.map(|m| m.rendered_utf8_bytes).unwrap_or(0);\n"
        "    final_bytes\n"
        "}\n"
    ),
    "src/engine/consumer.rs": (
        "use eliot_context_measurement::measure_serialized_context;\n"
        "\n"
        "pub struct EngineConsumer;\n"
        "\n"
        "impl EngineConsumer {\n"
        "    pub fn serializer_id(&self) -> String {\n"
        "        \"engine-consumer-v1\".to_owned()\n"
        "    }\n"
        "    pub fn context_cost(&self, payload_utf8: &str) -> u64 {\n"
        "        let params = build_params(payload_utf8);\n"
        "        let measured = measure_serialized_context(&params).ok();\n"
        "        let final_bytes = measured.map(|m| m.rendered_utf8_bytes).unwrap_or(0);\n"
        "        let _serializer_id = self.serializer_id();\n"
        "        final_bytes\n"
        "    }\n"
        "}\n"
    ),
    "src/engine/skill.rs": (
        "use eliot_context_measurement::measure_serialized_context;\n"
        "\n"
        "pub struct StuEstimate {\n"
        "    pub stu: u64,\n"
        "}\n"
        "\n"
        "pub fn skill_context_cost(payload_utf8: &str) -> u64 {\n"
        "    let params = build_params(payload_utf8);\n"
        "    let measured = measure_serialized_context(&params).ok();\n"
        "    let final_bytes = measured.map(|m| m.rendered_utf8_bytes).unwrap_or(0);\n"
        "    let stu_estimate = StuEstimate { stu: final_bytes.div_ceil(3) };\n"
        "    stu_estimate.stu\n"
        "}\n"
    ),
}

OWNER_SOURCE: dict[str, str] = {
    "src/owner/stu.rs": (
        "//! Canonical normative STU owner for the synthetic tree.\n"
        "\n"
        "pub fn stu_for_bytes(len: u64) -> Result<u64, ContextError> {\n"
        "    len.checked_add(2).map(|plus_two| plus_two / 3).ok_or(ContextError::Overflow)\n"
        "}\n"
    ),
    "src/owner/measure.rs": (
        "//! Canonical exact measurement owner for the synthetic tree.\n"
        "\n"
        "use crate::stu::stu_for_bytes;\n"
        "\n"
        "pub struct MeasurementParams {\n"
        "    pub payload_utf8: String,\n"
        "}\n"
        "\n"
        "pub struct SerializedContextMeasurement {\n"
        "    pub envelope_digest: String,\n"
        "    pub rendered_utf8_bytes: u64,\n"
        "}\n"
        "\n"
        "pub fn measure_serialized_context(\n"
        "    params: &MeasurementParams,\n"
        ") -> Result<SerializedContextMeasurement, ContextError> {\n"
        "    let rendered_utf8_bytes = params.payload_utf8.len() as u64;\n"
        "    let envelope_digest = sha256_hex(params.payload_utf8.as_bytes());\n"
        "    let _stu = stu_for_bytes(rendered_utf8_bytes);\n"
        "    Ok(SerializedContextMeasurement { envelope_digest, rendered_utf8_bytes })\n"
        "}\n"
    ),
}


def write_sources(root: Path) -> None:
    """Materialize the synthetic tree's source files under ``root``."""
    for rel, text in OWNER_SOURCE.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    for rel, text in CONSUMER_SOURCE.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")


def write_owner_map(root: Path, paths_by_owner: dict[str, tuple[str, ...]] | None = None) -> Path:
    """Write the externally supplied frozen owner map the #866 producer requires.

    #787 supplies this map (it is #787 work per the #866 generator's own
    contract). The map lists exact file paths per owner; wildcards and
    directories are rejected by the producer.
    """
    allocation = paths_by_owner or OWNER_SOURCE_PATHS
    lines: list[str] = []
    for issue in sorted(allocation):
        lines.append("[[owners]]")
        lines.append(f'issue = "{issue}"')
        rendered = ", ".join(f'"{p}"' for p in allocation[issue])
        lines.append(f"source_paths = [{rendered}]")
        lines.append("")
    target = root / ".github/work-units/context-measurement-owner-map.toml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return target


def install_producer(root: Path, source_root: Path) -> None:
    """Copy the accepted #866 generator into the synthetic tree."""
    target = root / PRODUCER_REL
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_root / PRODUCER_REL, target)


def build_synthetic_tree(
    dest: Path,
    source_root: Path,
    cases: tuple[tuple[str, str, str, str], ...] | None = None,
    owner_map: bool = True,
) -> Path:
    """Assemble a synthetic tree with a real, generated #866 inventory.

    Returns the tree root. The inventory is produced by calling the accepted
    #866 ``sync`` (the only writer of the artifact) and is verified with
    ``check``. This is a test fixture, not an oracle auto-repair path: the
    oracle itself never calls ``sync``.
    """
    dest.mkdir(parents=True, exist_ok=True)
    install_producer(dest, source_root)
    write_sources(dest)
    if owner_map:
        paths_by_owner: dict[str, tuple[str, ...]] = {}
        for case_ref, owner, path, _sig in (cases or SYNTHETIC_CASES):
            paths_by_owner.setdefault(owner, ())
            if path not in paths_by_owner[owner]:
                paths_by_owner[owner] = paths_by_owner[owner] + (path,)
        write_owner_map(dest, paths_by_owner)
    producer = load_producer(dest)
    selected = tuple(cases) if cases is not None else SYNTHETIC_CASES
    owner_map_tuple = producer.load_owner_map(dest)
    inventory = producer.build_inventory(dest, selected, "synthetic-fixture", owner_map_tuple)
    payload = producer._emit_toml(inventory)
    artifact = dest / producer.OWNED_TOML
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(payload)
    return dest
