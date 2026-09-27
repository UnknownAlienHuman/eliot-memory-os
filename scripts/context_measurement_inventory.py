#!/usr/bin/env python3
"""Deterministic source-bound inventory of serialized-context measurement cases.

Issue: https://github.com/UnknownAlienHuman/eliot-memory-os/issues/866

The inventory is static-source evidence, not authority. It never builds or
runs repository code, never mutates Rust/Cargo sources, never touches the
network or ambient clock, never spawns subprocesses, and never measures,
admits, delivers, or repairs any context payload. ``sync`` atomically writes
exactly one owned TOML artifact; ``check`` is read-only.

Proof ceiling: STATIC_SOURCE_CLASSIFICATION_ONLY. A complete honest
inventory with findings stays explicitly findings-bearing; it must never be
read as a product measured/fit/safe claim. Unresolved rows remain
launch/release blockers until the coordinator links each to a concrete
bounded implementation issue. The scanner proposes rows and successor
scopes only; it creates no GitHub tasks.

Denominator (rule revision 866.2)
-------------------------------
Revision 866.1 scanned only ``crates/smart/eliot-context-*``. Its declared
allocations therefore counted rows that were never found in the consumers'
own code. 866.2 keeps every 866.1 baseline row byte-identical (baseline row
identity is preserved, never erased) and widens the declared scan-root
denominator to the real per-consumer source seams named by the issue:

  #704  algorithm owner      crates/smart/eliot-context-{measurement,
                              assembly,contracts}          (writable)
  #783  app consumer seam    crates/eliot-app/src/mcp_stdio.rs,
                              crates/eliot-app/src/mcp_stdio/*.rs,
                              crates/eliot-app/src/commands/data_and_memory.rs
  #878  engine Context /     crates/eliot-engine/src/context.rs,
        packet-quality /     crates/eliot-engine/src/context_contracts.rs,
        Host                 crates/eliot-engine/src/context/packet_quality.rs,
                              crates/eliot-engine/src/host.rs
  #880  engine Skill/memory  crates/eliot-engine/src/skill.rs,
                              crates/eliot-engine/src/skill_curator.rs,
                              crates/eliot-engine/src/memory_distillation.rs,
                              crates/eliot-engine/src/memory_lifecycle.rs
  #787  serialized integration owner; sole writer of the owned TOML after
        the three consumers merge. It is never a source-row owner.

A baseline row whose declared owner is #783/#878/#880 lives in a #704
algorithm crate, so it is carried as an explicit READ-ONLY span of that
consumer. Read-only sharing is not shared mutable scope.

Candidates outside every declared seam are rows with owner ``unresolved``
and ``write_scope = "none"``. They are never deleted to obtain green; they
make the coverage disposition INCOMPLETE and block dispatch.

Closed classifications (exactly one per candidate row, 15 total):
  exact-utf8-envelope | normative-stu-estimate |
  serializer-identity-bound | route-identity-bound |
  estimator-policy-unvalidated | capacity-fit-analysis |
  exact-observation | stale-or-absent-observation |
  transformed-observation | test-only                      (revision 866.1)
  token_estimate_without_tokenizer |
  character_count_mislabeled_as_tokens |
  bare_measurement_field_or_conversion |
  unrelated_byte_or_character_metric | unresolved         (revision 866.2)

Classification rules (RULE_REVISION 866.2, first match wins, evidence kept):
  1. signal is "#[test]" or "cfg(test)", or the enclosing item scope is a
     real test scope -> test-only
  2. signal contains "stu_for_bytes" or signal is "StuEstimate"
     -> normative-stu-estimate
  3. signal in (measure_serialized_context, measure_exact_utf8,
     rendered_utf8_bytes, envelope_digest, declared_len, content_digest,
     payload_utf8, max_serialized_bytes, final_bytes, utf8_bytes,
     ExactUtf8) -> exact-utf8-envelope
  4. signal in (serializer_id, serializer_options_digest, schema_version,
     SerializerIdentity) -> serializer-identity-bound
  5. signal in (route_id, model_id, provider_id, tokenizer_hash,
     tokenizer_config_digest) -> route-identity-bound
  6. signal contains "estimator" or signal is "candidate_digests"
     -> estimator-policy-unvalidated
  7. signal in (fixed_overhead, output_reserve, review_reserve,
     route_capacity, headroom, proves_fit, receipt_digest, false_safe,
     false_reject) -> capacity-fit-analysis
  8. signal in (ProviderTokenizerRun, observed_tokens, TokenizerObservation)
     -> exact-observation
  9. signal in (Transformed, rewrite, Truncation, Normalization, Rewrite)
     -> transformed-observation
  10. signal in (Stale, Absent, Unavailable, Unsupported, Unknown)
     -> stale-or-absent-observation
  11. signal defines its own byte/char ratio (chars().count() with div_ceil(4))
     -> character_count_mislabeled_as_tokens
  12. signal applies div_ceil(4) to a byte length without a tokenizer
     -> token_estimate_without_tokenizer
  13. signal carries a measured field or a unit conversion across an exact
     numeric conversion boundary -> bare_measurement_field_or_conversion
  14. signal is a declared unrelated byte/character metric
     -> unrelated_byte_or_character_metric
  15. otherwise -> fail-closed InventoryError (never silent, never empty
     success)

Freshness
---------
Freshness binds to the ACTUAL scanned inputs, never to raw HEAD equality:
``source_sha`` is sha256 over sorted ``<path>:<sha256>`` lines of the declared
scan roots, ``rule_digest`` covers the closed rule set, and ``owner_digest``
covers the owner allocation. The generated artifact is never one of its own
inputs, so committing the generated TOML alone does not stale it, while any
scanned source, rule or owner-map change does. No wall-clock field and no
commit SHA affects semantic bytes; per-lane HEADs are not comparable and a
HEAD field would break cross-lane determinism, so provenance is recorded as
the content digest of the declared input universe.

Frozen owner map
----------------
Owner allocation is validated against an externally supplied frozen
committed owner map (``OWNER_MAP_PATH``) with no normal-runtime GitHub
access. This repository does not carry that map yet, so:

  * ``sync`` records its absence explicitly (``owner_map_status``) and
    refuses to certify any consumer as dispatch-ready;
  * ``check`` REFUSES to certify anything without the map and exits
    non-zero with code OWNER_MAP_MISSING naming the file.

The map is never invented here. Supplying and committing it is #787 work.

Discovery/classification API reuse:
  ``discover_context_measurements`` and ``classify_context_measurement``
  are the single stable entry points. Issue #787 reuses these two
  functions directly (import, never copy) so denominator drift in one
  place invalidates both consumers.

Usage:
  python scripts/context_measurement_inventory.py sync --root .
  python scripts/context_measurement_inventory.py check --root .
  python scripts/context_measurement_inventory.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path

SCHEMA = "eliot.context-measurement-inventory.v2"
RULE_REVISION = "866.2"
TOOL_VERSION = "0.2.0"
OWNED_TOML = Path(".github/work-units/context-measurement-inventory.toml")
OWNER_MAP_PATH = Path(".github/work-units/context-measurement-owner-map.toml")
PROOF_CEILING = "STATIC_SOURCE_CLASSIFICATION_ONLY"

# I2.16 (docs/architecture/I02-16-crate-size-and-agent-context-envelope.md):
# STU = ceil(UTF-8 bytes / 3); smallest qualified 100k envelope carries a
# 45-55k STU workset target and a 65k STU upper review band.
STU_RULE = "STU = ceil(UTF-8 bytes / 3) per docs/architecture/I02-16-crate-size-and-agent-context-envelope.md"
UPPER_REVIEW_BAND_STU = 65000

TEST_PATH_TRACKING_EVIDENCE = (
    "git ls-files --error-unmatch <path> in the owning worktree; the generator "
    "re-verifies existence, byte count and sha256 without spawning git"
)

CLASSIFICATIONS = (
    # revision 866.1 closed set, preserved verbatim
    "exact-utf8-envelope",
    "normative-stu-estimate",
    "serializer-identity-bound",
    "route-identity-bound",
    "estimator-policy-unvalidated",
    "capacity-fit-analysis",
    "exact-observation",
    "stale-or-absent-observation",
    "transformed-observation",
    "test-only",
    # revision 866.2 additions required by the widened denominator
    "token_estimate_without_tokenizer",
    "character_count_mislabeled_as_tokens",
    "bare_measurement_field_or_conversion",
    "unrelated_byte_or_character_metric",
    "unresolved",
)

FORBIDDEN_OWNER = "#785"
UNRESOLVED_OWNER = "unresolved"
CLOSED_OWNERS = ("#704", "#783", "#878", "#880")
INTEGRATION_OWNER = "#787"

# ---------------------------------------------------------------------------
# Baseline denominator: the 31 frozen cases of rule revision 866.1, kept
# byte-identical so baseline row identity survives migration reconciliation.
# (case_ref, owner, source_path, signal)
# ---------------------------------------------------------------------------
BASELINE_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("704/1", "#704", "crates/smart/eliot-context-measurement/src/stu.rs", "stu_for_bytes"),
    ("704/2", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "measure_serialized_context"),
    ("704/3", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "measure_exact_utf8"),
    ("704/4", "#704", "crates/smart/eliot-context-measurement/src/envelope.rs", "declared_len"),
    ("704/5", "#704", "crates/smart/eliot-context-measurement/src/envelope.rs", "content_digest"),
    ("704/6", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "rendered_utf8_bytes"),
    ("704/7", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "estimator_id"),
    ("704/8", "#704", "crates/smart/eliot-context-measurement/src/lib.rs", "candidate_digests"),
    ("704/9", "#704", "crates/smart/eliot-context-measurement/src/receipt.rs", "receipt_digest"),
    ("783/1", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "final_bytes"),
    ("783/2", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "envelope_digest"),
    ("783/3", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "serializer_id"),
    ("783/4", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "route_id"),
    ("783/5", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "model_id"),
    ("783/6", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "proves_fit"),
    ("783/7", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "fixed_overhead"),
    ("783/8", "#783", "crates/smart/eliot-context-assembly/src/measurement.rs", "ExactUtf8"),
    ("878/1", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "serializer_id"),
    ("878/2", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "serializer_options_digest"),
    ("878/3", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "schema_version"),
    ("878/4", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "StuEstimate"),
    ("878/5", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "TokenizerObservation"),
    ("878/6", "#878", "crates/smart/eliot-context-contracts/src/measurement.rs", "utf8_bytes"),
    ("880/1", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "fixed_overhead"),
    ("880/2", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "headroom"),
    ("880/3", "#880", "crates/smart/eliot-context-measurement/src/capacity.rs", "observed_tokens"),
    ("880/4", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "ProviderTokenizerRun"),
    ("880/5", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Transformed"),
    ("880/6", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Stale"),
    ("880/7", "#880", "crates/smart/eliot-context-measurement/src/observation.rs", "Absent"),
    ("880/8", "#880", "crates/smart/eliot-context-measurement/tests/measurement.rs", "#[test]"),
)

EXPECTED_BASELINE_COUNT = 31

# ---------------------------------------------------------------------------
# Consumer-seam denominator: measured app/engine source seams. Every needle
# below was acquired with git grep and its first masked occurrence verified
# against the exact source line. A needle that starts with "fn " anchors a
# whole enclosing item span (case 12: multiline expression keeps exact span).
# ---------------------------------------------------------------------------
CONSUMER_SEAM_CASES: tuple[tuple[str, str, str, str], ...] = (
    # #783 app seam -- crates/eliot-app
    ("783/10", "#783", "crates/eliot-app/src/mcp_stdio.rs", "description.chars().count().div_ceil(4)"),
    ("783/11", "#783", "crates/eliot-app/src/mcp_stdio.rs", "combined_ul_tokens"),
    ("783/12", "#783", "crates/eliot-app/src/mcp_stdio/memory.rs", "serialized_bytes: u64::try_from(serde_json::to_vec(&record.receipt_body)?.len())?"),
    ("783/13", "#783", "crates/eliot-app/src/mcp_stdio/memory.rs", "let serialized_bytes = u64::try_from(serde_json::to_vec(&record.receipt_body)?.len())?"),
    ("783/14", "#783", "crates/eliot-app/src/mcp_stdio/memory.rs", "token_units: serialized_bytes.div_ceil(4).max(1)"),
    ("783/15", "#783", "crates/eliot-app/src/mcp_stdio/dispatch.rs", "estimated_tokens,"),
    ("783/16", "#783", "crates/eliot-app/src/mcp_stdio/dispatch.rs", "details.section_tokens"),
    ("783/17", "#783", "crates/eliot-app/src/mcp_stdio/autonomy.rs", "cost_or_tokens_used: Some(runtime.ledger.cost_or_token_units.to_string())"),
    ("783/18", "#783", "crates/eliot-app/src/mcp_stdio/task_handlers.rs", "estimated_tokens: 431"),
    ("783/19", "#783", "crates/eliot-app/src/mcp_stdio/autonomy.rs", "&& intent.cost_or_token_units == 0)"),
    ("783/20", "#783", "crates/eliot-app/src/mcp_stdio/operator.rs", ", score.context_cost, false),"),
    ("783/21", "#783", "crates/eliot-app/src/commands/data_and_memory.rs", "estimated_context_cost: 128"),
    ("783/22", "#783", "crates/eliot-app/src/mcp_stdio/skill.rs", "estimated_context_cost: 128"),
    # #878 engine Context / packet-quality / Host seam
    ("878/10", "#878", "crates/eliot-engine/src/context.rs", "Ok(serde_json::to_vec(supplement)?.len().div_ceil(4))"),
    ("878/11", "#878", "crates/eliot-engine/src/context.rs", "fn estimate_tokens(packet: &ContextPacketL3)"),
    ("878/12", "#878", "crates/eliot-engine/src/context.rs", "estimate_tokens(packet)?);"),
    ("878/13", "#878", "crates/eliot-engine/src/context.rs", "serde_json::to_vec(packet)?.len().div_ceil(4)"),
    ("878/14", "#878", "crates/eliot-engine/src/context_contracts.rs", "pub estimated_tokens: usize,"),
    ("878/15", "#878", "crates/eliot-engine/src/context/packet_quality.rs", "estimated_tokens: structured_bytes.div_ceil(4)"),
    ("878/16", "#878", "crates/eliot-engine/src/host.rs", "pub estimated_tokens: usize,"),
    ("878/17", "#878", "crates/eliot-engine/src/host.rs", "let estimated_tokens = body.chars().count().div_ceil(4)"),
    ("878/18", "#878", "crates/eliot-engine/src/host.rs", "if description.chars().count().div_ceil(4) > 25"),
    ("878/19", "#878", "crates/eliot-engine/src/host.rs", "pub listing_characters: usize,"),
    ("878/20", "#878", "crates/eliot-engine/src/host.rs", "if descriptions.div_ceil(4) > 100"),
    # #880 engine Skill / memory seam
    ("880/10", "#880", "crates/eliot-engine/src/skill.rs", "fn estimated_skill_context_cost(skill: &SkillCardV2) -> u64"),
    ("880/11", "#880", "crates/eliot-engine/src/skill.rs", "pub estimated_context_cost: u64,"),
    ("880/12", "#880", "crates/eliot-engine/src/skill.rs", "context_cost: Some(estimated_skill_context_cost(skill))"),
    ("880/13", "#880", "crates/eliot-engine/src/skill_curator.rs", "fn estimated_skill_context_cost(skill: &SkillCardV2) -> u64"),
    ("880/14", "#880", "crates/eliot-engine/src/skill_curator.rs", "let cost = i64::try_from(estimated_skill_context_cost(skill)).unwrap_or(i64::MAX);"),
    ("880/15", "#880", "crates/eliot-engine/src/skill_curator.rs", "context_cost_delta_tokens: expected_context_delta(action, skill)"),
    ("880/16", "#880", "crates/eliot-engine/src/skill_curator.rs", "estimated_skill_context_cost(skill) >= 180"),
    ("880/17", "#880", "crates/eliot-engine/src/memory_distillation.rs", ".saturating_add(record.serialized_bytes.div_ceil(1024).max(1))"),
    ("880/18", "#880", "crates/eliot-engine/src/memory_distillation.rs", "MemoryUtilitySignalKind::ContextTokenCost => {"),
    ("880/19", "#880", "crates/eliot-engine/src/memory_distillation.rs", "-i64::try_from(item.token_units.saturating_mul(4))"),
    ("880/20", "#880", "crates/eliot-engine/src/memory_distillation.rs", "active_bytes = active_bytes.saturating_add(item.token_units.saturating_mul(4))"),
    ("880/21", "#880", "crates/eliot-engine/src/memory_lifecycle.rs", "pub context_cost_tokens: u64,"),
    ("880/22", "#880", "crates/eliot-engine/src/memory_lifecycle.rs", "context_cost_tokens: 64"),
)

# ---------------------------------------------------------------------------
# Unallocated candidates: real measurement sites outside every declared seam.
# They stay rows with owner "unresolved"; no owner is invented for them.
# ---------------------------------------------------------------------------
UNRESOLVED_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("unres/1", UNRESOLVED_OWNER, "crates/eliot-engine/src/control_plane.rs", "pub cost_or_token_units: u64,"),
    ("unres/2", UNRESOLVED_OWNER, "crates/eliot-engine/src/control_plane.rs", ".cost_or_token_budget"),
    ("unres/3", UNRESOLVED_OWNER, "crates/eliot-engine/src/control_plane.rs", ".saturating_add(intent.cost_or_token_units)"),
    ("unres/4", UNRESOLVED_OWNER, "crates/eliot-engine/src/cognition.rs", "|| treatment.estimated_tokens < control.estimated_tokens"),
)

DENOMINATOR_CASES: tuple[tuple[str, str, str, str], ...] = (
    BASELINE_CASES + CONSUMER_SEAM_CASES + UNRESOLVED_CASES
)
EXPECTED_DENOMINATOR_COUNT = 72
EXPECTED_OWNER_ALLOCATIONS = (
    ("#704", 9),
    ("#783", 21),
    ("#878", 17),
    ("#880", 21),
    (UNRESOLVED_OWNER, 4),
)

# ---------------------------------------------------------------------------
# Declared unrelated byte/character metrics. Each one carries exact exclusion
# evidence (file, line, span digest, reason) instead of a broad package skip.
# ---------------------------------------------------------------------------
EXCLUSION_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("exc/1", "crates/eliot-app/src/cognitive_field_runner.rs", "executions.len().div_ceil(target_chunks)",
     "collection-length partition for execution chunking (executions/target_chunks); no byte/char/token/STU semantic"),
    ("exc/2", "crates/eliot-app/src/host_runtime/event_and_authority.rs", "input.ttl_seconds.div_ceil(60)",
     "seconds-to-minutes ceiling for a TTL; no byte/char/token/STU semantic"),
    ("exc/3", "crates/eliot-app/src/host_runtime/supervised_process.rs", "hash.chars().count() <= 128",
     "digest text length bound on a hash string; no byte/char/token/STU semantic"),
    ("exc/4", "crates/eliot-app/src/host_runtime/supervised_process.rs", "if detail.chars().count() > 512",
     "log-detail truncation bound; no byte/char/token/STU semantic"),
    ("exc/5", "crates/eliot-engine/src/host.rs", "let nonblank_lines = body.lines().filter(|line| !line.trim().is_empty()).count()",
     "nonblank markdown line count for a skill body; a documentation metric, never divided or relabelled as tokens"),
    ("exc/6", "crates/eliot-engine/src/host.rs", "descriptions += description.chars().count()",
     "summed description character count reported only as listing_characters; never divided or relabelled as tokens"),
)

# ---------------------------------------------------------------------------
# Per-consumer declarations. The issue body is the only source of these:
#   "Consumers: app #783, engine #878 and #880 (superseding #785),
#    enforcement/integration #787; algorithm owner #704."
#   "#783 gets its exact app seam; #878 gets Context/packet-quality/Host;
#    #880 gets Skill/memory."
# ---------------------------------------------------------------------------
CONSUMER_SEAMS: dict[str, str] = {
    "#704": "smart-measurement-algorithm",
    "#783": "app",
    "#878": "engine-context-packet-quality-host",
    "#880": "engine-skill-memory",
}

CONSUMER_ROLES: dict[str, str] = {
    "#704": "algorithm-owner",
    "#783": "app-consumer",
    "#878": "engine-consumer",
    "#880": "engine-consumer",
}

# Routed required reading, identical closed set for every consumer: the five
# shards the issue names, the I2.17 assignment/write-isolation contract, the
# delegation work-unit contract, the development doctrine, and the nearest
# AGENTS.md files of the consumer's own crates.
_ROUTED_SHARDS = (
    "docs/architecture/I02-16-crate-size-and-agent-context-envelope.md",
    "docs/architecture/I12-32-context-economy-ledger.md",
    "docs/architecture/I18-27-oracle-ownership-and-test-change-governance.md",
    "docs/architecture/I18-21-local-and-ci-parity.md",
    "docs/architecture/I07-20-agent-facing-error-contract.md",
    "docs/architecture/I02-17-parallel-agent-development-contract.md",
    "docs/architecture/A10-04-delegation.md",
    "docs/architecture/A14-08-development-doctrine.md",
)

_OWNED_TOML_EDGE = (
    "single-writer: .github/work-units/context-measurement-inventory.toml belongs to "
    + INTEGRATION_OWNER
    + " only; every other consumer is read-only on it and regenerates nothing"
)

CONSUMER_TEST_PATHS: dict[str, tuple[str, ...]] = {
    "#704": (
        "crates/smart/eliot-context-measurement/tests/measurement.rs",
    ),
    "#783": (
        "crates/eliot-app/tests/ul_convenience_forms.rs",
        "crates/eliot-app/tests/ul_e_surface.rs",
    ),
    "#878": (
        "crates/eliot-engine/tests/context_packets_and_proofs.rs",
        "crates/eliot-engine/tests/host_integration.rs",
        "crates/eliot-engine/tests/project_understanding.rs",
    ),
    "#880": (
        "crates/eliot-engine/tests/skill_lifecycle.rs",
        "crates/eliot-engine/tests/skill_curator.rs",
        "crates/eliot-engine/tests/memory_distillation.rs",
        "crates/eliot-engine/tests/memory_ecology.rs",
    ),
}

CONSUMER_ROUTED_READING: dict[str, tuple[str, ...]] = {
    "#704": _ROUTED_SHARDS + (
        "crates/AGENTS.md",
    ),
    "#783": _ROUTED_SHARDS + (
        "crates/AGENTS.md",
        "crates/eliot-app/AGENTS.md",
    ),
    "#878": _ROUTED_SHARDS + (
        "crates/AGENTS.md",
    ),
    "#880": _ROUTED_SHARDS + (
        "crates/AGENTS.md",
    ),
}

CONSUMER_WRITE_EDGES: dict[str, tuple[str, ...]] = {
    "#704": (
        "single-writer: crates/smart/eliot-context-{measurement,assembly,contracts}/** is the #704 algorithm write scope",
        "read-only for #783/#878/#880: their 866.1 baseline rows inside these crates are carried as explicit read-only spans",
        _OWNED_TOML_EDGE,
        "serialized-after: " + INTEGRATION_OWNER + " regenerates the inventory once #704/#783/#878/#880 have merged",
    ),
    "#783": (
        "single-writer: crates/eliot-app/src/mcp_stdio.rs, crates/eliot-app/src/mcp_stdio/{memory,dispatch,task_handlers,operator,skill}.rs and crates/eliot-app/src/commands/data_and_memory.rs are the #783 app seam",
        "parallel-with: #878 and #880, on disjoint engine paths; no shared mutable source path between the three",
        "blocked-for-others: " + _OWNED_TOML_EDGE,
        "serialized-after: #704 algorithm merge, then " + INTEGRATION_OWNER + " regeneration",
    ),
    "#878": (
        "single-writer: crates/eliot-engine/src/{context.rs,context_contracts.rs,host.rs} and crates/eliot-engine/src/context/packet_quality.rs are the #878 Context/packet-quality/Host seam",
        "parallel-with: #783 and #880, on disjoint paths; no shared mutable source path between the three",
        "blocked-for-others: " + _OWNED_TOML_EDGE,
        "serialized-after: #704 algorithm merge, then " + INTEGRATION_OWNER + " regeneration",
    ),
    "#880": (
        "single-writer: crates/eliot-engine/src/{skill.rs,skill_curator.rs,memory_distillation.rs,memory_lifecycle.rs} are the #880 Skill/memory seam",
        "parallel-with: #783 and #878, on disjoint paths; no shared mutable source path between the three",
        "blocked-for-others: " + _OWNED_TOML_EDGE,
        "serialized-after: #704 algorithm merge, then " + INTEGRATION_OWNER + " regeneration",
    ),
}

# Closed versioned header keys (exact set; any drift fails validation).
HEADER_KEYS = frozenset(
    {
        "schema",
        "rule_revision",
        "tool_version",
        "source_sha",
        "source_sha_kind",
        "rule_digest",
        "owner_digest",
        "owner_map_path",
        "owner_map_status",
        "owner_map_digest",
        "scan_roots",
        "scan_denominator_files",
        "scan_denominator_bytes",
        "candidate_count",
        "classified_count",
        "owned_count",
        "unresolved_count",
        "generation_command",
        "coverage_disposition",
        "coverage_reason",
        "proof_ceiling",
        "exclusions",
        "classifications",
        "owner_allocations",
        "consumer_worksets_digest",
        "stu_accounting_rule",
        "upper_review_band_stu",
        "test_path_tracking_evidence",
    }
)

ROW_KEYS = frozenset(
    {
        "id",
        "case_ref",
        "tier",
        "owner",
        "seam",
        "write_scope",
        "path",
        "package",
        "item",
        "item_scope",
        "signal",
        "span_start",
        "span_end",
        "span_bytes",
        "source_sha256",
        "span_digest",
        "row_digest",
        "classification",
        "status",
        "dispatch_blocked",
        "evidence",
        "successor_scope",
        "invalidation",
    }
)

WORKSET_KEYS = frozenset(
    {
        "issue",
        "role",
        "seam",
        "row_ids",
        "source_paths",
        "items",
        "source_span_bytes",
        "source_span_stu",
        "read_only_paths",
        "read_only_spans",
        "read_only_bytes",
        "read_only_stu",
        "test_paths",
        "test_path_evidence",
        "test_bytes",
        "test_stu",
        "routed_required_reading",
        "source_scope_bytes",
        "source_scope_stu",
        "workset_bytes",
        "workset_stu",
        "scan_root_bytes",
        "scan_root_stu",
        "workset_stu_share_of_scan_root",
        "share_basis",
        "upper_review_band_stu",
        "band_disposition",
        "write_serialization_edges",
        "dispatch_ready",
        "dispatch_block_reason",
        "unresolved_row_count",
        "workset_digest",
    }
)

TOP_LEVEL_KEYS = frozenset({"header", "rows", "consumer_worksets", "inventory_digest"})

TEST_MARKER_ATTR = re.compile(r"#\[(?:cfg\(test\)|test|tokio::test|test_case|rstest|async_std::test)")
ITEM_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"(?P<kind>fn|struct|enum|impl|trait|union|mod|const|static|type)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
CONVERTER_DEFINED = re.compile(
    r"\b(?:u8|u16|u32|u64|usize|i8|i16|i32|i64|isize|f32|f64)\s*::\s*"
    r"(?:try_from|from|as)\b|"
    r"\btry_into\s*\(\s*\)|"
    r"\bserde_json::to_(?:vec|string)\s*\(|"
    r"\bdiv_ceil\s*\(|\bsaturating_(?:add|mul)\s*\(|"
    r"\bmap_or\s*\("
)
CHAR_RATIO = re.compile(r"chars\(\)\.count\(\)[^;,)\n]*div_ceil\(\s*4\s*\)")
ESTIMATOR_HELPER_RE = re.compile(
    r"^fn\s+(?:estimate|estimated|measure)_[a-z0-9_]*"
    r"(?:token|stu|context|serialized_context)[a-z0-9_]*\s*\("
)
ESTIMATOR_CALL_RE = re.compile(
    r"\b(?:estimate_tokens|estimate_stu|estimated_skill_context_cost|"
    r"measure_serialized_context|measure_exact_utf8|expected_context_delta)\s*\("
)
BYTE_RATIO = re.compile(r"div_ceil\(\s*4\s*\)")
MEASURED_FIELD = re.compile(
    r"\b(?:estimated_tokens|estimated_context_cost|context_cost_tokens|ContextTokenCost|"
    r"estimated_skill_context_cost|context_cost|token_units|serialized_bytes|"
    r"listing_characters|cost_or_token_units|cost_or_token_budget|"
    r"context_cost_delta_tokens|description_ul_tokens|combined_ul_tokens|"
    r"mandatory_floor_tokens|section_tokens|expected_context_delta)\b"
)
TOLERATED_LITERAL = re.compile(r"^\s*\(?\s*(?:pub\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*[\"']")


class InventoryError(RuntimeError):
    """Stable fail-closed error carrying a machine-readable reason code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _stu(byte_count: int) -> int:
    """Source Token Unit = ceil(bytes / 3) (I2.16)."""
    if byte_count <= 0:
        return 0
    return -(-int(byte_count) // 3)


def _mask_rust(text: str) -> str:
    """Replace comments and literal bodies with spaces, preserving layout."""
    chars = list(text)
    length = len(chars)
    index = 0

    def blank(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] not in "\r\n":
                chars[pos] = " "

    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if text.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif text.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            if depth:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated block comment")
            blank(index, cursor)
            index = cursor
            continue
        raw_match = re.match(r"(?:b|c)?r(#{0,255})\"", text[index:])
        if raw_match:
            hashes = raw_match.group(1)
            body_start = index + raw_match.end()
            terminator = '"' + hashes
            end = text.find(terminator, body_start)
            if end < 0:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated raw string")
            end += len(terminator)
            blank(index, end)
            index = end
            continue
        if text.startswith("'", index) or text.startswith("b'", index):
            char_match = _CHAR_RE.match(text[index:])
            if char_match:
                blank(index, index + char_match.end())
                index += char_match.end()
                continue
            lifetime_match = _LIFETIME_RE.match(text[index:])
            if lifetime_match:
                index += lifetime_match.end()
                continue
        prefix = (
            1
            if text[index : index + 1] in {"b", "c"} and text[index + 1 : index + 2] == '"'
            else 0
        )
        quote_pos = index + prefix
        if quote_pos < length and text[quote_pos] == '"':
            cursor = quote_pos + 1
            escaped = False
            while cursor < length:
                current = text[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            else:
                raise InventoryError("MALFORMED_RUST_SOURCE", "unterminated string literal")
            blank(index, cursor)
            index = cursor
            continue
        index += 1
    return "".join(chars)


_CHAR_RE = re.compile(
    r"^(?:b)?'(?:\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F_]{1,6}\}|\\[\\'\"0nrt]|[^\\'\n\r])'"
)
_LIFETIME_RE = re.compile(r"^'[a-zA-Z_][a-zA-Z0-9_]*")


def _root(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise InventoryError("REPOSITORY_UNAVAILABLE", f"root is unavailable: {path}") from exc


def _inside(root: Path, path: Path) -> Path:
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InventoryError("PATH_ESCAPE", f"path is outside scan root: {path}") from exc
    return resolved


def _read_source(root: Path, rel: str) -> bytes:
    resolved = _inside(root, root / rel)
    if resolved.is_symlink() or not resolved.is_file():
        raise InventoryError(
            "SOURCE_NOT_REGULAR_FILE", f"expected a regular non-symlink file: {rel}"
        )
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise InventoryError("SOURCE_UNREADABLE", f"cannot read source: {rel}") from exc


def _package_of(root: Path, rel: str) -> str:
    """Nearest Cargo package name above the file, else the parent dir."""
    current = _inside(root, root / rel).parent
    while True:
        manifest = current / "Cargo.toml"
        if manifest.is_file() and not manifest.is_symlink():
            try:
                text = manifest.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                break
            match = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
            if match:
                return match.group(1)
            break
        if current == root:
            break
        parent = current.parent
        try:
            parent.relative_to(root)
        except ValueError:
            break
        current = parent
    try:
        relative_parent = _inside(root, root / rel).parent.relative_to(root).as_posix()
    except InventoryError:
        return "unknown"
    return relative_parent if relative_parent not in ("", ".") else "unknown"


def _depths(masked_lines: list[str]) -> list[int]:
    """Brace depth before each line (comments and literals already blanked)."""
    depths: list[int] = []
    depth = 0
    for line in masked_lines:
        depths.append(depth)
        depth += line.count("{") - line.count("}")
    return depths


def _item_extent(masked_lines: list[str], depths: list[int], start: int) -> int:
    """Last line (1-based) whose body belongs to the item declared at ``start``.

    A declaration owns every line until the brace depth returns to the depth
    it had before the declaration. A declaration with no body (a field-free
    ``struct Foo;``) owns its own declaration lines only, so the scan stops at
    the next item instead of swallowing the rest of the file.
    """
    base = depths[start - 1]
    last = start
    opened = False
    for index in range(start, len(depths)):
        if depths[index] > base:
            opened = True
        elif opened:
            return index
        elif index + 1 > start and ITEM_RE.match(masked_lines[index]) is not None:
            return last
        last = index + 1
    return last


def _scope_of(masked_lines: list[str], depths: list[int], lineno: int, rel: str) -> tuple[str, str]:
    """Return (enclosing_item, item_scope) for a 1-based line.

    ``item_scope`` is ``"test"`` only when the real enclosing chain carries a
    test marker: a test attribute on the enclosing item, a test attribute
    between the enclosing item and the line, an enclosing ``mod tests``, or a
    file inside a Cargo ``tests/`` integration-test crate. Text after
    ``#[cfg(test)]`` is never assumed test-only, and production code before
    it is never assumed test.
    """
    best_index = 0
    best_name = "<file>"
    pending_test = False
    chain_test = False
    test_modules: list[tuple[int, int]] = []
    for index in range(0, lineno - 1):
        line = masked_lines[index]
        stripped = line.strip()
        if stripped.startswith("#") and stripped.endswith("]"):
            if TEST_MARKER_ATTR.search(stripped):
                pending_test = True
            continue
        match = ITEM_RE.match(line)
        if match is None:
            continue
        name = match.group("name")
        extent = _item_extent(masked_lines, depths, index + 1)
        if extent >= lineno:
            best_index = index + 1
            best_name = f"{match.group('kind')} {name}"
            if pending_test:
                chain_test = True
            if match.group("kind") == "mod" and name in ("tests", "test"):
                test_modules.append((index + 1, extent))
                chain_test = True
        pending_test = False
    scope = "production"
    if chain_test:
        scope = "test"
    for start, end in test_modules:
        if start <= best_index <= end:
            scope = "test"
    if "/tests/" in f"/{rel}":
        scope = "test"
    return (best_name, scope)
def _rule_digest() -> str:
    """Digest of the closed rule set (revision + classifications + order)."""
    payload = {
        "rule_revision": RULE_REVISION,
        "classifications": list(CLASSIFICATIONS),
        "forbidden_owner": FORBIDDEN_OWNER,
        "unresolved_owner": UNRESOLVED_OWNER,
        "integration_owner": INTEGRATION_OWNER,
        "consumer_seams": dict(sorted(CONSUMER_SEAMS.items())),
        "stu_accounting_rule": STU_RULE,
        "upper_review_band_stu": UPPER_REVIEW_BAND_STU,
    }
    return _sha256(_canonical_bytes(payload))


def _owner_digest(cases: tuple[tuple[str, str, str, str], ...]) -> str:
    """Digest of the frozen owner allocation map (sorted, order-free)."""
    grouped: dict[str, list[str]] = {}
    for case_ref, owner, _path, _signal in cases:
        grouped.setdefault(owner, []).append(case_ref)
    canonical = [
        {"owner": owner, "cases": sorted(refs)} for owner, refs in sorted(grouped.items())
    ]
    return _sha256(_canonical_bytes(canonical))


def _case_sort_key(case_ref: str) -> tuple[str, int, str]:
    """Natural order: owner prefix, then the numeric case index, then the rest."""
    prefix, _, tail = case_ref.partition("/")
    digits = ""
    for char in tail:
        if char.isdigit():
            digits += char
        else:
            break
    return (prefix, int(digits) if digits else -1, tail)


def _same_case_set(
    left: tuple[tuple[str, str, str, str], ...] | list[tuple[str, str, str, str]],
    right: tuple[tuple[str, str, str, str], ...] | list[tuple[str, str, str, str]],
) -> bool:
    """Order-free equality of two denominator case selections.

    The build mode (full expectation gate, exclusion scan, declared path
    verification) is decided by the CONTENT of the selected cases, never by
    how the caller ordered or passed them, so a shuffled traversal of the
    real denominator produces byte-identical output.
    """
    return sorted(tuple(item) for item in left) == sorted(tuple(item) for item in right)


def _load_files(root: Path, rels: tuple[str, ...] | list[str]) -> dict[str, dict[str, object]]:
    """Read, hash and mask every declared input exactly once, fail-closed."""
    cache: dict[str, dict[str, object]] = {}
    for rel in sorted(set(rels)):
        raw = _read_source(root, rel)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError("INVALID_RUST_ENCODING", f"source is not UTF-8: {rel}") from exc
        try:
            masked = _mask_rust(text)
        except InventoryError as exc:
            raise InventoryError(exc.code, f"{rel}: {exc.detail}") from exc
        masked_lines = masked.splitlines()
        lines = text.splitlines()
        cache[rel] = {
            "path": rel,
            "sha256": _sha256(raw),
            "bytes": len(raw),
            "package": _package_of(root, rel),
            "masked": masked,
            "masked_lines": masked_lines,
            "depths": _depths(masked_lines),
            "lines": lines,
            "line_bytes": [len(line.encode("utf-8")) + 1 for line in lines],
        }
    return cache


def _locate_signal(record: dict[str, object], rel: str, signal: str) -> tuple[int, int]:
    """First masked line holding ``signal``; whole item span for fn needles."""
    masked_lines = record["masked_lines"]
    assert isinstance(masked_lines, list)
    span_start = 0
    for lineno, line in enumerate(masked_lines, start=1):
        if signal in line:
            span_start = lineno
            break
    if span_start == 0:
        raise InventoryError(
            "SIGNAL_ABSENT",
            f"denominator signal {signal!r} absent from masked source: {rel}",
        )
    span_end = span_start
    if signal.startswith("fn "):
        depths = record["depths"]
        assert isinstance(depths, list)
        span_end = _item_extent(masked_lines, depths, span_start)
    return (span_start, span_end)


def _span_bytes(record: dict[str, object], span_start: int, span_end: int) -> int:
    line_bytes = record["line_bytes"]
    assert isinstance(line_bytes, list)
    total = 0
    for lineno in range(span_start, span_end + 1):
        if 1 <= lineno <= len(line_bytes):
            total += int(line_bytes[lineno - 1])
    if total == 0:
        raise InventoryError(
            "EMPTY_SPAN",
            f"span {span_start}-{span_end} carries no bytes in {record['path']}",
        )
    return total


def _span_digest(record: dict[str, object], span_start: int, span_end: int) -> str:
    lines = record["lines"]
    assert isinstance(lines, list)
    body = "\n".join(lines[span_start - 1 : span_end])
    if not body:
        raise InventoryError(
            "EMPTY_SPAN", f"span {span_start}-{span_end} is empty in {record['path']}"
        )
    return _sha256(f"{record['path']}\n{body}".encode("utf-8"))


def classify_context_measurement(
    signal: str, path: str = "", item_scope: str = "production"
) -> tuple[str, str]:
    """Classify one denominator signal into exactly one closed class.

    This is the stable classification API reused by issue #787 (import
    this function, never copy its rules). First match wins; unknown
    signals fail closed with CLASSIFICATION_OPEN instead of inventing a
    class. ``path`` is accepted for scope evidence and is never used to
    widen a closed class. ``item_scope`` is the measured enclosing scope,
    never an assumption about everything after ``#[cfg(test)]``.
    """
    _ = path
    if signal in ("#[test]", "cfg(test)") or item_scope == "test":
        return (
            "test-only",
            f"test marker or measured test scope in scanned slice; no shipped measurement ({signal!r})",
        )
    if "stu_for_bytes" in signal or signal == "StuEstimate":
        return (
            "normative-stu-estimate",
            f"normative STU signal {signal!r}: ceil(bytes/3) estimate, never proves fit",
        )
    if signal in (
        "measure_serialized_context",
        "measure_exact_utf8",
        "rendered_utf8_bytes",
        "envelope_digest",
        "declared_len",
        "content_digest",
        "payload_utf8",
        "max_serialized_bytes",
        "final_bytes",
        "utf8_bytes",
        "ExactUtf8",
    ):
        return (
            "exact-utf8-envelope",
            f"exact envelope signal {signal!r}: final UTF-8 bytes and digest binding",
        )
    if signal in (
        "serializer_id",
        "serializer_options_digest",
        "schema_version",
        "SerializerIdentity",
    ):
        return (
            "serializer-identity-bound",
            f"serializer identity signal {signal!r}: serializer/schema binding",
        )
    if signal in (
        "route_id",
        "model_id",
        "provider_id",
        "tokenizer_hash",
        "tokenizer_config_digest",
    ):
        return (
            "route-identity-bound",
            f"route identity signal {signal!r}: route/provider/model/tokenizer binding",
        )
    if "estimator" in signal or signal == "candidate_digests":
        return (
            "estimator-policy-unvalidated",
            f"estimator signal {signal!r}: UNVALIDATED planning evidence, candidates cited only",
        )
    if signal in (
        "fixed_overhead",
        "output_reserve",
        "review_reserve",
        "route_capacity",
        "headroom",
        "proves_fit",
        "receipt_digest",
        "false_safe",
        "false_reject",
    ):
        return (
            "capacity-fit-analysis",
            f"capacity signal {signal!r}: reserves/fit/headroom/error/receipt binding",
        )
    if signal in ("ProviderTokenizerRun", "observed_tokens", "TokenizerObservation"):
        return (
            "exact-observation",
            f"exact observation signal {signal!r}: actually-run route tokenizer count",
        )
    if signal in ("Transformed", "rewrite", "Truncation", "Normalization", "Rewrite"):
        return (
            "transformed-observation",
            f"transformed signal {signal!r}: provider rewrite evidence, no count comparison",
        )
    if signal in ("Stale", "Absent", "Unavailable", "Unsupported", "Unknown"):
        return (
            "stale-or-absent-observation",
            f"non-exact signal {signal!r}: absent/unavailable/stale/unsupported/unknown, never zero",
        )
    if ESTIMATOR_HELPER_RE.match(signal):
        return (
            "token_estimate_without_tokenizer",
            f"local estimator helper {signal!r}: a named token/STU/context-cost estimator "
            f"declared at this item; its measured body is bound by the recorded item span",
        )
    if CHAR_RATIO.search(signal):
        return (
            "character_count_mislabeled_as_tokens",
            f"character count divided by four and carried as tokens: {signal!r}; no tokenizer ran",
        )
    if BYTE_RATIO.search(signal):
        return (
            "token_estimate_without_tokenizer",
            f"byte length divided by four and carried as tokens: {signal!r}; planning fallback, not a tokenizer count",
        )
    if ESTIMATOR_CALL_RE.search(signal):
        return (
            "token_estimate_without_tokenizer",
            f"call into a declared local estimator: {signal!r}; consumes an unvalidated "
            f"byte/character ratio, never a run route tokenizer",
        )
    if MEASURED_FIELD.search(signal):
        if CONVERTER_DEFINED.search(signal):
            return (
                "bare_measurement_field_or_conversion",
                f"bare unit conversion feeding a measurement field: {signal!r}; no estimator policy",
            )
        if TOLERATED_LITERAL.match(signal):
            return (
                "bare_measurement_field_or_conversion",
                f"measurement field declared from a literal or a bare value: {signal!r}; no measured input",
            )
        return (
            "bare_measurement_field_or_conversion",
            f"bare measurement field or projection: {signal!r}; carries no estimator policy of its own",
        )
    if any(signal == needle for _ref, _path, needle, _reason in EXCLUSION_CASES):
        return (
            "unrelated_byte_or_character_metric",
            f"declared unrelated byte/character metric: {signal!r}; excluded with exact evidence, not a package skip",
        )
    raise InventoryError(
        "CLASSIFICATION_OPEN", f"signal is outside the closed {len(CLASSIFICATIONS)}-class set: {signal!r}"
    )


def load_owner_map(
    root: Path,
) -> tuple[dict[str, dict[str, list[str]]] | None, str, str]:
    """Load the externally supplied frozen owner map (offline, no GitHub).

    Returns ``(mapping, status, digest)``. ``mapping`` is ``None`` when the
    required input is absent; the status records that fact explicitly so
    ``sync`` can record it and ``check`` can refuse to certify.
    """
    target = root / OWNER_MAP_PATH
    if target.is_symlink() or not target.is_file():
        return (
            None,
            "ABSENT_EXTERNAL_INPUT_REQUIRED",
            "not-supplied",
        )
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise InventoryError(
            "OWNER_MAP_UNREADABLE", f"cannot read required owner map: {OWNER_MAP_PATH.as_posix()}"
        ) from exc
    digest = _sha256(raw)
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError(
            "OWNER_MAP_MALFORMED", f"required owner map is malformed: {OWNER_MAP_PATH.as_posix()}"
        ) from exc
    entries = document.get("owners")
    if not isinstance(entries, list) or not entries:
        raise InventoryError(
            "OWNER_MAP_MALFORMED",
            f"required owner map holds no [[owners]] entries: {OWNER_MAP_PATH.as_posix()}",
        )
    mapping: dict[str, dict[str, list[str]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise InventoryError("OWNER_MAP_MALFORMED", "owner map entry must be a table")
        issue = entry.get("issue")
        source_paths = entry.get("source_paths")
        if not isinstance(issue, str) or not isinstance(source_paths, list):
            raise InventoryError(
                "OWNER_MAP_MALFORMED", "owner map entry needs issue and source_paths"
            )
        if issue in mapping:
            raise InventoryError("OWNER_MAP_MALFORMED", f"duplicate owner map entry: {issue}")
        if issue == FORBIDDEN_OWNER:
            raise InventoryError("FORBIDDEN_OWNER", f"owner {FORBIDDEN_OWNER} is never allocated")
        if issue not in CONSUMER_SEAMS:
            raise InventoryError(
                "OWNER_MAP_UNKNOWN_OWNER",
                f"owner map names an owner outside the closed set: {issue}",
            )
        declared: list[str] = []
        for value in source_paths:
            if not isinstance(value, str) or not value or "*" in value or value.endswith("/"):
                raise InventoryError(
                    "OWNER_MAP_MALFORMED",
                    f"owner map scope must hold exact file paths, never a wildcard: {value!r}",
                )
            _read_source(root, value)
            declared.append(value)
        mapping[issue] = {"source_paths": declared}
    return (mapping, "SUPPLIED", digest)


def _owner_confirmed(
    owner: str, path: str, mapping: dict[str, dict[str, list[str]]] | None
) -> tuple[str, str]:
    """Resolve one row owner against the frozen map; never invent an owner."""
    if owner == UNRESOLVED_OWNER:
        return (
            "unresolved",
            "candidate is outside every declared #704/#783/#878/#880 seam; no exact-scope owner exists",
        )
    if mapping is None:
        return (
            "owned",
            "owner is the exact-scope allocation stated by issue #866; the frozen owner map is not supplied, so dispatch stays blocked",
        )
    entry = mapping.get(owner)
    if entry is None:
        return ("unresolved", f"frozen owner map has no entry for {owner}")
    if path not in entry["source_paths"]:
        return (
            "unresolved",
            f"frozen owner map scope for {owner} does not contain {path}",
        )
    return ("owned", f"frozen owner map confirms exact-scope ownership for {path}")


def discover_context_measurements(
    root: Path,
    cases: tuple[tuple[str, str, str, str], ...] | None = None,
    extra_paths: tuple[str, ...] = (),
    file_cache: dict[str, dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Discover one candidate per denominator case (stable API for #787).

    Returns (file_records, candidates). Candidates are sorted by case_ref
    so shuffled input traversal yields identical digests. Each candidate
    carries the source sha, the enclosing Rust item and its measured scope,
    the exact span, the span digest and byte count, the owner, the signal
    and the classified label with evidence. Missing signals, duplicate
    identities, forbidden owners or malformed sources fail closed.
    """
    root = _root(root)
    selected = tuple(cases) if cases is not None else DENOMINATOR_CASES
    if not selected:
        raise InventoryError("EMPTY_SCAN", "denominator selected no cases; refusing empty coverage")
    ordered_cases = sorted(selected, key=lambda item: _case_sort_key(item[0]))
    seen_refs: set[str] = set()
    for case_ref, owner, _path, _signal in ordered_cases:
        if case_ref in seen_refs:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", f"duplicate case_ref: {case_ref}")
        seen_refs.add(case_ref)
        if owner == FORBIDDEN_OWNER:
            raise InventoryError(
                "FORBIDDEN_OWNER", f"owner {FORBIDDEN_OWNER} is never allocated: {case_ref}"
            )
        if owner != UNRESOLVED_OWNER and owner not in CONSUMER_SEAMS:
            raise InventoryError(
                "OWNER_NOT_CLOSED", f"owner is outside the closed consumer set: {owner}"
            )
    distinct_rels = tuple(sorted({path for _ref, _owner, path, _sig in ordered_cases} | set(extra_paths)))
    cache = file_cache if file_cache is not None else _load_files(root, distinct_rels)
    for rel in distinct_rels:
        if rel not in cache:
            raise InventoryError("SCAN_INPUT_MISSING", f"declared scan root was not loaded: {rel}")
    file_records: list[dict[str, object]] = [
        {
            "path": rel,
            "sha256": str(cache[rel]["sha256"]),
            "bytes": int(cache[rel]["bytes"]),  # type: ignore[arg-type]
            "package": str(cache[rel]["package"]),
        }
        for rel in distinct_rels
    ]
    file_records.sort(key=lambda item: str(item["path"]))
    candidates: list[dict[str, object]] = []
    for case_ref, owner, rel, signal in ordered_cases:
        record = cache[rel]
        span_start, span_end = _locate_signal(record, rel, signal)
        masked_lines = record["masked_lines"]
        assert isinstance(masked_lines, list)
        depths = record["depths"]
        assert isinstance(depths, list)
        item, item_scope = _scope_of(masked_lines, depths, span_start, rel)
        classification, evidence = classify_context_measurement(signal, rel, item_scope)
        if classification not in CLASSIFICATIONS:
            raise InventoryError(
                "CLASSIFICATION_NOT_CLOSED", f"class is outside the closed set: {classification!r}"
            )
        candidates.append(
            {
                "case_ref": case_ref,
                "owner": owner,
                "path": rel,
                "signal": signal,
                "span_start": span_start,
                "span_end": span_end,
                "span_bytes": _span_bytes(record, span_start, span_end),
                "source_sha256": str(record["sha256"]),
                "span_digest": _span_digest(record, span_start, span_end),
                "classification": classification,
                "evidence": evidence,
                "package": str(record["package"]),
                "item": item,
                "item_scope": item_scope,
            }
        )
    candidates.sort(key=lambda item: _case_sort_key(str(item["case_ref"])))
    return file_records, candidates


def discover_exclusions(
    root: Path,
    cases: tuple[tuple[str, str, str, str], ...] = EXCLUSION_CASES,
    file_cache: dict[str, dict[str, object]] | None = None,
) -> list[str]:
    """Emit exact exclusion evidence for declared unrelated metrics."""
    root = _root(root)
    rels = tuple(sorted({rel for _ref, rel, _needle, _reason in cases}))
    cache = file_cache if file_cache is not None else _load_files(root, rels)
    out: list[str] = []
    seen: set[str] = set()
    for case_ref, rel, needle, reason in sorted(cases, key=lambda item: _case_sort_key(item[0])):
        if case_ref in seen:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", f"duplicate exclusion: {case_ref}")
        seen.add(case_ref)
        record = cache.get(rel)
        if record is None:
            raise InventoryError("SCAN_INPUT_MISSING", f"exclusion input was not loaded: {rel}")
        span_start, span_end = _locate_signal(record, rel, needle)
        label, label_reason = classify_context_measurement(needle, rel)
        if label != "unrelated_byte_or_character_metric":
            raise InventoryError(
                "EXCLUSION_NOT_UNRELATED",
                f"declared exclusion {case_ref} classified as {label!r}",
            )
        out.append(
            "|".join(
                (
                    case_ref,
                    f"{rel}:{span_start}-{span_end}",
                    label,
                    _span_digest(record, span_start, span_end)[:16],
                    reason,
                    label_reason,
                )
            )
        )
    return out


_BASELINE_REFS = frozenset(item[0] for item in BASELINE_CASES)
_SEAM_REFS = frozenset(item[0] for item in CONSUMER_SEAM_CASES)


def _tier_of(case_ref: str) -> str:
    if case_ref in _BASELINE_REFS:
        return "baseline-frozen-866.1"
    if case_ref in _SEAM_REFS:
        return "consumer-seam"
    return "unallocated-candidate"


def _write_scope_of(owner: str, tier: str) -> str:
    if tier == "unallocated-candidate":
        return "none"
    if tier == "consumer-seam":
        return "writable"
    return "writable" if owner == "#704" else "read-only"


def _successor_scope(owner: str, case_ref: str, classification: str) -> str:
    if classification == "test-only":
        return "none-required"
    if owner == UNRESOLVED_OWNER:
        return (
            f"blocked: candidate {case_ref} has no existing exact-scope owner; "
            f"{INTEGRATION_OWNER} must allocate it or #704 must classify it, and the row "
            f"is never deleted to obtain green"
        )
    return (
        f"bounded successor scope: consumer {owner} owns case {case_ref} "
        f"({classification}); prove fit/error/receipt in the owning issue"
    )


def _build_rows(
    candidates: list[dict[str, object]],
    mapping: dict[str, dict[str, list[str]]] | None,
) -> list[dict[str, object]]:
    ordered = sorted(candidates, key=lambda item: _case_sort_key(str(item["case_ref"])))
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for position, item in enumerate(ordered, start=1):
        identity = (
            f"{item['owner']}|{item['case_ref']}|{item['path']}|{item['signal']}|"
            f"{item['span_start']}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError(
                "DUPLICATE_ROW_IDENTITY", f"duplicate/overlapping row identity: {identity}"
            )
        seen.add(identity_digest)
        classification = str(item["classification"])
        if classification not in CLASSIFICATIONS:
            raise InventoryError(
                "CLASSIFICATION_NOT_CLOSED", f"class is outside the closed set: {classification!r}"
            )
        owner = str(item["owner"])
        case_ref = str(item["case_ref"])
        path = str(item["path"])
        tier = _tier_of(case_ref)
        write_scope = _write_scope_of(owner, tier)
        status, owner_evidence = _owner_confirmed(owner, path, mapping)
        dispatch_blocked = status != "owned"
        evidence = str(item["evidence"])
        if tier != "baseline-frozen-866.1":
            evidence = (
                f"{evidence}; measured at {path}:{item['span_start']}-{item['span_end']} "
                f"inside `{item['item']}`; {owner_evidence}"
            )
        else:
            evidence = f"{evidence}; {owner_evidence}"
        row: dict[str, object] = {
            "id": f"c{position:04d}",
            "case_ref": case_ref,
            "tier": tier,
            "owner": owner,
            "seam": CONSUMER_SEAMS.get(owner, "unassigned"),
            "write_scope": write_scope,
            "path": path,
            "package": str(item["package"]),
            "item": str(item["item"]),
            "item_scope": str(item["item_scope"]),
            "signal": str(item["signal"]),
            "span_start": int(item["span_start"]),  # type: ignore[arg-type]
            "span_end": int(item["span_end"]),  # type: ignore[arg-type]
            "span_bytes": int(item["span_bytes"]),  # type: ignore[arg-type]
            "source_sha256": str(item["source_sha256"]),
            "span_digest": str(item["span_digest"]),
            "classification": classification,
            "status": status,
            "dispatch_blocked": dispatch_blocked,
            "evidence": evidence,
            "successor_scope": _successor_scope(owner, case_ref, classification),
            "invalidation": (
                "row invalid when the source span digest, file sha, rule revision, "
                "owner map, or owner allocation changes; rerun sync"
            ),
        }
        row["row_digest"] = _sha256(_canonical_bytes(row))
        if set(row.keys()) != ROW_KEYS:
            raise InventoryError("ROW_NOT_CLOSED", "row keys are not the closed set")
        rows.append(row)
    return rows


def _verify_declared_paths(
    root: Path, rels: tuple[str, ...] | list[str], label: str, suffix: str
) -> list[dict[str, object]]:
    """Verify declared finite paths exist as exact regular files."""
    verified: list[dict[str, object]] = []
    for rel in rels:
        if "*" in rel or rel.endswith("/") or not rel.endswith(suffix):
            raise InventoryError(
                "DECLARED_PATH_NOT_EXACT",
                f"{label} must be exact existing files, never a glob or directory: {rel!r}",
            )
        raw = _read_source(root, rel)
        verified.append({"path": rel, "bytes": len(raw), "sha256": _sha256(raw)})
    return verified


def _build_consumer_worksets(
    root: Path,
    rows: list[dict[str, object]],
    file_records: list[dict[str, object]],
    map_status: str,
    verify_declared: bool,
) -> list[dict[str, object]]:
    bytes_by_path = {str(r["path"]): int(r["bytes"]) for r in file_records}  # type: ignore[arg-type]
    worksets: list[dict[str, object]] = []
    test_owner: dict[str, str] = {}
    source_owner: dict[str, str] = {}
    for owner in sorted(CONSUMER_SEAMS):
        owned_rows = [row for row in rows if row["owner"] == owner]
        writable = [row for row in owned_rows if row["write_scope"] == "writable"]
        read_only = [row for row in owned_rows if row["write_scope"] == "read-only"]
        unresolved_rows = [row for row in owned_rows if row["status"] != "owned"]
        source_paths = sorted({str(row["path"]) for row in writable})
        read_only_paths = sorted({str(row["path"]) for row in read_only})
        source_bytes = sum(int(row["span_bytes"]) for row in writable)  # type: ignore[arg-type]
        read_only_bytes = sum(int(row["span_bytes"]) for row in read_only)  # type: ignore[arg-type]
        if verify_declared:
            test_records = _verify_declared_paths(
                root, CONSUMER_TEST_PATHS[owner], "test_paths", ".rs"
            )
            reading_records = _verify_declared_paths(
                root, CONSUMER_ROUTED_READING[owner], "routed_required_reading", ".md"
            )
        else:
            test_records = []
            reading_records = []
        for path in source_paths:
            if path in source_owner:
                raise InventoryError(
                    "SOURCE_PATH_COLLISION",
                    f"shared mutable source path {path} is allocated to "
                    f"{source_owner[path]} and {owner}; the inventory grants no write "
                    f"access to a path another consumer already owns",
                )
            source_owner[path] = owner
        for record in test_records:
            path = str(record["path"])
            if path in test_owner:
                raise InventoryError(
                    "TEST_PATH_COLLISION",
                    f"shared mutable test path {path} is allocated to {test_owner[path]} and {owner}",
                )
            test_owner[path] = owner
        test_bytes = sum(int(record["bytes"]) for record in test_records)
        reading_paths = sorted({str(record["path"]) for record in reading_records})
        items = [
            f"{row['id']}:{row['path']}:{row['span_start']}-{row['span_end']}" for row in writable
        ]
        read_only_spans = [
            f"{row['id']}:{row['path']}:{row['span_start']}-{row['span_end']}" for row in read_only
        ]
        workset_bytes = source_bytes + read_only_bytes + test_bytes
        workset_stu = _stu(workset_bytes)
        source_scope_bytes = source_bytes + read_only_bytes
        source_scope_stu = _stu(source_scope_bytes)
        scan_root_bytes = sum(
            bytes_by_path.get(path, 0) for path in sorted(set(source_paths) | set(read_only_paths))
        )
        scan_root_stu = _stu(scan_root_bytes)
        share = 0.0 if scan_root_stu == 0 else source_scope_stu / scan_root_stu
        band_ok = workset_stu <= UPPER_REVIEW_BAND_STU
        block_reasons: list[str] = []
        if map_status != "SUPPLIED":
            block_reasons.append(
                f"frozen owner map absent at {OWNER_MAP_PATH.as_posix()}; "
                f"{INTEGRATION_OWNER} must supply and commit it before any dispatch"
            )
        if unresolved_rows:
            block_reasons.append(
                f"{len(unresolved_rows)} row(s) of this consumer have no confirmed exact-scope owner"
            )
        if not band_ok:
            block_reasons.append(
                f"workset {workset_stu} STU exceeds the {UPPER_REVIEW_BAND_STU} STU I2.16 upper review band; "
                f"a blocking split proposal is required"
            )
        if not verify_declared:
            block_reasons.append(
                "custom denominator: declared consumer source/test/read paths are not verified in this tree"
            )
        elif not test_records:
            block_reasons.append(
                "no finite exact test_paths are allocated to this consumer"
            )
        workset: dict[str, object] = {
            "issue": owner,
            "role": CONSUMER_ROLES[owner],
            "seam": CONSUMER_SEAMS[owner],
            "row_ids": [str(row["id"]) for row in owned_rows],
            "source_paths": source_paths,
            "items": items,
            "source_span_bytes": source_bytes,
            "source_span_stu": _stu(source_bytes),
            "read_only_paths": read_only_paths,
            "read_only_spans": read_only_spans,
            "read_only_bytes": read_only_bytes,
            "read_only_stu": _stu(read_only_bytes),
            "test_paths": sorted(str(record["path"]) for record in test_records),
            "test_path_evidence": TEST_PATH_TRACKING_EVIDENCE,
            "test_bytes": test_bytes,
            "test_stu": _stu(test_bytes),
            "routed_required_reading": reading_paths,
            "source_scope_bytes": source_scope_bytes,
            "source_scope_stu": source_scope_stu,
            "workset_bytes": workset_bytes,
            "workset_stu": workset_stu,
            "scan_root_bytes": scan_root_bytes,
            "scan_root_stu": scan_root_stu,
            "workset_stu_share_of_scan_root": f"{share:.4f}",
            "share_basis": (
                "source_scope_stu / scan_root_stu: the exact source plus read-only spans "
                "against the declared scan-root universe; a scan-root universe is never context"
            ),
            "upper_review_band_stu": UPPER_REVIEW_BAND_STU,
            "band_disposition": (
                "WITHIN_UPPER_REVIEW_BAND" if band_ok else "EXCEEDS_UPPER_REVIEW_BAND_BLOCKING_SPLIT"
            ),
            "write_serialization_edges": list(CONSUMER_WRITE_EDGES[owner]),
            "dispatch_ready": not block_reasons,
            "dispatch_block_reason": "; ".join(block_reasons) if block_reasons else "none",
            "unresolved_row_count": len(unresolved_rows),
        }
        workset["workset_digest"] = _sha256(_canonical_bytes(workset))
        if set(workset.keys()) != WORKSET_KEYS:
            raise InventoryError("WORKSET_NOT_CLOSED", f"workset keys drifted: {owner}")
        worksets.append(workset)
    return worksets


def build_inventory(
    root: Path,
    cases: tuple[tuple[str, str, str, str], ...] | list[tuple[str, str, str, str]] | None,
    generation_command: str,
    owner_map: tuple[dict[str, dict[str, list[str]]] | None, str, str] | None = None,
) -> dict[str, object]:
    """Build the deterministic inventory (sorted, clock-free, fail-closed)."""
    root = _root(root)
    selected: tuple[tuple[str, str, str, str], ...] = (
        tuple(tuple(item) for item in cases)  # type: ignore[arg-type]
        if cases is not None
        else DENOMINATOR_CASES
    )
    default_denominator = _same_case_set(selected, DENOMINATOR_CASES)
    mapping, map_status, map_digest = load_owner_map(root) if owner_map is None else owner_map
    active_cases = selected
    if not active_cases:
        raise InventoryError("EMPTY_SCAN", "no denominator cases selected")
    extra_paths = (
        tuple(sorted({rel for _ref, rel, _needle, _reason in EXCLUSION_CASES}))
        if default_denominator
        else ()
    )
    cache = _load_files(
        root, tuple(sorted({path for _ref, _owner, path, _sig in active_cases} | set(extra_paths)))
    )
    file_records, candidates = discover_context_measurements(root, active_cases, (), cache)
    if not candidates:
        raise InventoryError("EMPTY_SCAN", "scan yielded no candidates; refusing empty success")
    exclusions = discover_exclusions(root, EXCLUSION_CASES, cache) if default_denominator else []
    if default_denominator:
        if len(active_cases) != EXPECTED_DENOMINATOR_COUNT:
            raise InventoryError(
                "COUNT_MISMATCH",
                f"default denominator holds {len(active_cases)}, expected {EXPECTED_DENOMINATOR_COUNT}",
            )
        if len(candidates) != EXPECTED_DENOMINATOR_COUNT:
            raise InventoryError(
                "COUNT_MISMATCH",
                f"default scan yielded {len(candidates)}, expected {EXPECTED_DENOMINATOR_COUNT}",
            )
    source_pairs = sorted(f"{record['path']}:{record['sha256']}" for record in file_records)
    source_sha = _sha256("\n".join(source_pairs).encode("utf-8"))
    rows = _build_rows(candidates, mapping)
    counts: dict[str, int] = {}
    for _ref, owner, _path, _sig in active_cases:
        counts[owner] = counts.get(owner, 0) + 1
    if default_denominator and tuple(sorted(counts.items())) != tuple(
        sorted(EXPECTED_OWNER_ALLOCATIONS)
    ):
        raise InventoryError(
            "OWNER_ALLOCATION_DRIFT",
            f"measured owner allocation {sorted(counts.items())} differs from the declared "
            f"{sorted(EXPECTED_OWNER_ALLOCATIONS)}",
        )
    owner_allocations = sorted(f"{owner}:{count}" for owner, count in counts.items())
    unresolved_rows = [row for row in rows if row["status"] != "owned"]
    owned_count = len(rows) - len(unresolved_rows)
    if default_denominator and any(
        row["status"] == "owned" and row["owner"] == UNRESOLVED_OWNER for row in rows
    ):
        raise InventoryError("UNRESOLVED_ROW_MARKED_OWNED", "an unresolved row was marked owned")
    block_reasons: list[str] = []
    if unresolved_rows:
        block_reasons.append(f"{len(unresolved_rows)} candidate(s) have no exact-scope owner")
    if map_status != "SUPPLIED":
        block_reasons.append(
            f"frozen owner map not supplied at {OWNER_MAP_PATH.as_posix()}"
        )
    coverage_disposition = "INCOMPLETE" if block_reasons else "COMPLETE"
    coverage_reason = (
        "every declared denominator case was discovered exactly once with a closed class, "
        "the frozen owner map is supplied, and no candidate remains unallocated"
        if not block_reasons
        else "incomplete: " + "; ".join(block_reasons)
    )
    worksets = _build_consumer_worksets(
        root, rows, file_records, map_status, default_denominator
    )
    header: dict[str, object] = {
        "schema": SCHEMA,
        "rule_revision": RULE_REVISION,
        "tool_version": TOOL_VERSION,
        "source_sha": source_sha,
        "source_sha_kind": (
            "sha256 over sorted <path>:<sha256> of the declared scan roots; the generated "
            "artifact is never one of its own inputs, so committing it does not stale the inventory"
        ),
        "rule_digest": _rule_digest(),
        "owner_digest": _owner_digest(tuple(active_cases)),
        "owner_map_path": OWNER_MAP_PATH.as_posix(),
        "owner_map_status": map_status,
        "owner_map_digest": map_digest,
        "scan_roots": sorted({str(record["path"]) for record in file_records}),
        "scan_denominator_files": len(file_records),
        "scan_denominator_bytes": sum(int(record["bytes"]) for record in file_records),  # type: ignore[arg-type]
        "candidate_count": len(candidates),
        "classified_count": len(rows),
        "owned_count": owned_count,
        "unresolved_count": len(unresolved_rows),
        "generation_command": generation_command,
        "coverage_disposition": coverage_disposition,
        "coverage_reason": coverage_reason,
        "proof_ceiling": PROOF_CEILING,
        "exclusions": exclusions,
        "classifications": list(CLASSIFICATIONS),
        "owner_allocations": owner_allocations,
        "consumer_worksets_digest": _sha256(_canonical_bytes(worksets)),
        "stu_accounting_rule": STU_RULE,
        "upper_review_band_stu": UPPER_REVIEW_BAND_STU,
        "test_path_tracking_evidence": TEST_PATH_TRACKING_EVIDENCE,
    }
    if set(header.keys()) != HEADER_KEYS:
        raise InventoryError("HEADER_NOT_CLOSED", "header keys drifted from the closed set")
    inventory: dict[str, object] = {
        "header": header,
        "rows": rows,
        "consumer_worksets": worksets,
    }
    inventory["inventory_digest"] = _sha256(_canonical_bytes(inventory))
    return inventory
def _toml_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return '"' + "".join(
        ch if 0x20 <= ord(ch) != 0x7F else f"\\u{ord(ch):04X}" for ch in escaped
    ) + '"'


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_string(str(item)) for item in value) + "]"
    return _toml_string(str(value))


HEADER_ORDER = (
    "schema",
    "rule_revision",
    "tool_version",
    "source_sha",
    "source_sha_kind",
    "rule_digest",
    "owner_digest",
    "owner_map_path",
    "owner_map_status",
    "owner_map_digest",
    "scan_denominator_files",
    "scan_denominator_bytes",
    "candidate_count",
    "classified_count",
    "owned_count",
    "unresolved_count",
    "generation_command",
    "coverage_disposition",
    "coverage_reason",
    "proof_ceiling",
    "stu_accounting_rule",
    "upper_review_band_stu",
    "test_path_tracking_evidence",
    "scan_roots",
    "exclusions",
    "classifications",
    "owner_allocations",
    "consumer_worksets_digest",
)

ROW_ORDER = (
    "id",
    "case_ref",
    "tier",
    "owner",
    "seam",
    "write_scope",
    "path",
    "package",
    "item",
    "item_scope",
    "signal",
    "span_start",
    "span_end",
    "span_bytes",
    "source_sha256",
    "span_digest",
    "classification",
    "status",
    "dispatch_blocked",
    "row_digest",
    "evidence",
    "successor_scope",
    "invalidation",
)

WORKSET_ORDER = (
    "issue",
    "role",
    "seam",
    "row_ids",
    "source_paths",
    "items",
    "source_span_bytes",
    "source_span_stu",
    "read_only_paths",
    "read_only_spans",
    "read_only_bytes",
    "read_only_stu",
    "test_paths",
    "test_path_evidence",
    "test_bytes",
    "test_stu",
    "routed_required_reading",
    "source_scope_bytes",
    "source_scope_stu",
    "workset_bytes",
    "workset_stu",
    "scan_root_bytes",
    "scan_root_stu",
    "workset_stu_share_of_scan_root",
    "share_basis",
    "upper_review_band_stu",
    "band_disposition",
    "write_serialization_edges",
    "dispatch_ready",
    "dispatch_block_reason",
    "unresolved_row_count",
    "workset_digest",
)


def _emit_table(
    out: list[str],
    name: str,
    table: dict[str, object],
    order: tuple[str, ...],
    array: bool = False,
) -> None:
    if name:
        out.append(f"[[{name}]]" if array else f"[{name}]")
    for key in order:
        out.append(f"{key} = {_toml_value(table[key])}")


def _emit_toml(inventory: dict[str, object]) -> bytes:
    header = inventory["header"]
    rows = inventory["rows"]
    worksets = inventory["consumer_worksets"]
    digest = inventory["inventory_digest"]
    assert isinstance(header, dict)
    assert isinstance(rows, list)
    assert isinstance(worksets, list)
    assert isinstance(digest, str)
    out: list[str] = [f"inventory_digest = {_toml_string(digest)}", ""]
    _emit_table(out, "header", header, HEADER_ORDER)
    for row in rows:
        assert isinstance(row, dict)
        out.append("")
        _emit_table(out, "rows", row, ROW_ORDER, array=True)
    for workset in worksets:
        assert isinstance(workset, dict)
        out.append("")
        _emit_table(out, "consumer_worksets", workset, WORKSET_ORDER, array=True)
    return ("\n".join(out) + "\n").encode("utf-8")


def _parse_toml(raw: bytes, *, source: str) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML is malformed: {source}") from exc
    if not isinstance(value, dict):
        raise InventoryError("MALFORMED_INVENTORY", f"owned TOML must hold a table: {source}")
    return value


def _validate_artifact(
    artifact: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    if set(artifact.keys()) != TOP_LEVEL_KEYS:
        raise InventoryError(
            "MALFORMED_INVENTORY", "owned TOML must hold header/rows/consumer_worksets/digest only"
        )
    header = artifact["header"]
    rows = artifact["rows"]
    worksets = artifact["consumer_worksets"]
    digest = artifact["inventory_digest"]
    if (
        not isinstance(header, dict)
        or not isinstance(rows, list)
        or not isinstance(worksets, list)
        or not isinstance(digest, str)
    ):
        raise InventoryError("MALFORMED_INVENTORY", "owned TOML field types are wrong")
    if set(header.keys()) != HEADER_KEYS:
        raise InventoryError("HEADER_NOT_CLOSED", "header keys are not the closed versioned set")
    for key in HEADER_ORDER:
        if key not in header:
            raise InventoryError("MALFORMED_INVENTORY", f"header is missing {key}")
    if header["schema"] != SCHEMA:
        raise InventoryError("SCHEMA_MISMATCH", f"schema is not {SCHEMA}")
    if header["rule_revision"] != RULE_REVISION:
        raise InventoryError("RULE_MISMATCH", f"rule revision is not {RULE_REVISION}")
    if header["rule_digest"] != _rule_digest():
        raise InventoryError("RULE_MISMATCH", "rule digest disagrees with closed rules")
    if header["owner_map_path"] != OWNER_MAP_PATH.as_posix():
        raise InventoryError("OWNER_MAP_MISMATCH", "owner map path disagrees with the closed input")
    if header["owner_map_status"] not in ("SUPPLIED", "ABSENT_EXTERNAL_INPUT_REQUIRED"):
        raise InventoryError("OWNER_MAP_MISMATCH", "owner map status is not closed")
    if list(header["classifications"]) != list(CLASSIFICATIONS):  # type: ignore[arg-type]
        raise InventoryError(
            "CLASSIFICATION_NOT_CLOSED", "classifications drifted from the closed set"
        )
    if len(set(str(x) for x in header["classifications"])) != len(CLASSIFICATIONS):  # type: ignore[arg-type]
        raise InventoryError("CLASSIFICATION_NOT_CLOSED", "classifications must be unique")
    if header["coverage_disposition"] not in ("COMPLETE", "INCOMPLETE"):
        raise InventoryError("MALFORMED_INVENTORY", "coverage disposition is not closed")
    allocations = [str(x) for x in header["owner_allocations"]]  # type: ignore[arg-type]
    if allocations != sorted(allocations):
        raise InventoryError("MALFORMED_INVENTORY", "owner allocations are not in sorted order")
    total = 0
    seen_owners: set[str] = set()
    for entry in allocations:
        if ":" not in entry:
            raise InventoryError("MALFORMED_INVENTORY", f"owner allocation is malformed: {entry}")
        owner, count_text = entry.split(":", 1)
        if owner == FORBIDDEN_OWNER:
            raise InventoryError("FORBIDDEN_OWNER", f"owner {FORBIDDEN_OWNER} is never allocated")
        if owner != UNRESOLVED_OWNER and owner not in CONSUMER_SEAMS:
            raise InventoryError("OWNER_NOT_CLOSED", f"owner is outside the closed set: {owner}")
        if owner in seen_owners:
            raise InventoryError("MALFORMED_INVENTORY", f"duplicate owner allocation: {owner}")
        seen_owners.add(owner)
        try:
            count = int(count_text)
        except ValueError as exc:
            raise InventoryError(
                "MALFORMED_INVENTORY", f"owner count is not an integer: {entry}"
            ) from exc
        if count < 0:
            raise InventoryError("MALFORMED_INVENTORY", f"owner count is negative: {entry}")
        total += count
    candidate_count = int(header["candidate_count"])  # type: ignore[arg-type]
    classified_count = int(header["classified_count"])  # type: ignore[arg-type]
    owned_count = int(header["owned_count"])  # type: ignore[arg-type]
    unresolved_count = int(header["unresolved_count"])  # type: ignore[arg-type]
    if total != candidate_count:
        raise InventoryError(
            "COUNT_MISMATCH",
            f"owner allocations sum to {total}, candidate_count is {candidate_count}",
        )
    if classified_count != len(rows):
        raise InventoryError("COUNT_MISMATCH", "classified_count disagrees with row count")
    if candidate_count != classified_count:
        raise InventoryError("COUNT_MISMATCH", "candidate/classified counts disagree")
    if owned_count + unresolved_count != classified_count:
        raise InventoryError("COUNT_MISMATCH", "owned+unresolved disagrees with classified count")
    if not rows:
        raise InventoryError("EMPTY_SCAN", "empty inventory never succeeds")
    seen: set[str] = set()
    seen_ids: set[str] = set()
    typed_rows: list[dict[str, object]] = []
    measured_unresolved = 0
    for row in rows:
        if not isinstance(row, dict):
            raise InventoryError("MALFORMED_INVENTORY", "row must be a table")
        if set(row.keys()) != ROW_KEYS:
            raise InventoryError("MALFORMED_INVENTORY", "row keys are not the closed set")
        for key in ("id", "case_ref", "owner", "path", "signal", "classification"):
            if key not in row:
                raise InventoryError("MALFORMED_INVENTORY", f"row is missing {key}")
        if str(row["id"]) in seen_ids:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", f"duplicate row id: {row['id']}")
        seen_ids.add(str(row["id"]))
        classification = row["classification"]
        if classification not in CLASSIFICATIONS:
            raise InventoryError(
                "CLASSIFICATION_NOT_CLOSED",
                f"row classification is not in the closed set: {classification!r}",
            )
        if row["owner"] == FORBIDDEN_OWNER:
            raise InventoryError("FORBIDDEN_OWNER", "row owner is never allocated")
        if row["status"] not in ("owned", "unresolved"):
            raise InventoryError("MALFORMED_INVENTORY", "row status is not closed")
        if bool(row["dispatch_blocked"]) != (row["status"] != "owned"):
            raise InventoryError("MALFORMED_INVENTORY", "row dispatch_blocked disagrees with status")
        if row["owner"] == UNRESOLVED_OWNER and row["status"] != "unresolved":
            raise InventoryError("UNRESOLVED_ROW_MARKED_OWNED", "an unresolved row was marked owned")
        if row["status"] != "owned":
            measured_unresolved += 1
        if row["write_scope"] not in ("writable", "read-only", "none"):
            raise InventoryError("MALFORMED_INVENTORY", "row write_scope is not closed")
        if int(row["span_end"]) < int(row["span_start"]) or int(row["span_bytes"]) <= 0:
            raise InventoryError("MALFORMED_INVENTORY", "row span is empty or inverted")
        identity = (
            f"{row.get('owner')}|{row.get('case_ref')}|{row.get('path')}|"
            f"{row.get('signal')}|{row.get('span_start')}"
        )
        identity_digest = _sha256(identity.encode("utf-8"))
        if identity_digest in seen:
            raise InventoryError("DUPLICATE_ROW_IDENTITY", "owned TOML holds duplicated rows")
        seen.add(identity_digest)
        recomputed_row = {k: v for k, v in row.items() if k != "row_digest"}
        if _sha256(_canonical_bytes(recomputed_row)) != row["row_digest"]:
            raise InventoryError("DIGEST_MISMATCH", f"row digest disagrees with content: {row['id']}")
        typed_rows.append(row)
    if measured_unresolved != unresolved_count:
        raise InventoryError(
            "COUNT_MISMATCH",
            f"measured {measured_unresolved} unresolved rows, header says {unresolved_count}",
        )
    if (unresolved_count > 0 or header["owner_map_status"] != "SUPPLIED") and header[
        "coverage_disposition"
    ] != "INCOMPLETE":
        raise InventoryError(
            "COVERAGE_NOT_CLOSED",
            "unresolved rows or an unsupplied owner map must leave the coverage disposition INCOMPLETE",
        )
    if not worksets:
        raise InventoryError("MALFORMED_INVENTORY", "inventory must carry one workset per consumer")
    test_owner: dict[str, str] = {}
    typed_worksets: list[dict[str, object]] = []
    for workset in worksets:
        if not isinstance(workset, dict):
            raise InventoryError("MALFORMED_INVENTORY", "workset must be a table")
        if set(workset.keys()) != WORKSET_KEYS:
            raise InventoryError("MALFORMED_INVENTORY", "workset keys are not the closed set")
        issue = str(workset["issue"])
        if issue not in CONSUMER_SEAMS:
            raise InventoryError("OWNER_NOT_CLOSED", f"workset names a closed-set owner: {issue}")
        if str(workset["seam"]) != CONSUMER_SEAMS[issue]:
            raise InventoryError("MALFORMED_INVENTORY", f"workset seam disagrees: {issue}")
        for path in workset["test_paths"]:  # type: ignore[union-attr]
            rel = str(path)
            if "*" in rel or rel.endswith("/"):
                raise InventoryError(
                    "DECLARED_PATH_NOT_EXACT", f"workset test path is not exact: {rel}"
                )
            if rel in test_owner:
                raise InventoryError(
                    "TEST_PATH_COLLISION",
                    f"shared mutable test path {rel} is allocated to {test_owner[rel]} and {issue}",
                )
            test_owner[rel] = issue
        if not workset["row_ids"] and bool(workset["dispatch_ready"]):
            raise InventoryError(
                "EMPTY_ALLOCATION", f"dispatch-ready workset carries no rows: {issue}"
            )
        for row_id in workset["row_ids"]:  # type: ignore[union-attr]
            if str(row_id) not in seen_ids:
                raise InventoryError(
                    "MALFORMED_INVENTORY", f"workset references an unknown row: {row_id}"
                )
        if bool(workset["dispatch_ready"]):
            if not workset["test_paths"]:
                raise InventoryError(
                    "EMPTY_TEST_ALLOCATION",
                    f"dispatch-ready workset has no finite exact test_paths: {issue}",
                )
            if header["unresolved_count"] != 0 or header["owner_map_status"] != "SUPPLIED":
                raise InventoryError(
                    "UNRESOLVED_ROW_BLOCKS_DISPATCH",
                    f"dispatch-ready workset with unresolved rows or an unsupplied owner map: {issue}",
                )
            if workset["band_disposition"] != "WITHIN_UPPER_REVIEW_BAND":
                raise InventoryError(
                    "OVERSIZED_SLICE_BLOCKED",
                    f"dispatch-ready workset exceeds its review band: {issue}",
                )
        if int(workset["upper_review_band_stu"]) != UPPER_REVIEW_BAND_STU:
            raise InventoryError("MALFORMED_INVENTORY", "workset review band is not the closed band")
        if int(workset["workset_stu"]) > int(workset["workset_bytes"]) // 3 + 1:
            raise InventoryError("MALFORMED_INVENTORY", "workset STU accounting is inconsistent")
        recomputed_workset = {k: v for k, v in workset.items() if k != "workset_digest"}
        if _sha256(_canonical_bytes(recomputed_workset)) != workset["workset_digest"]:
            raise InventoryError(
                "DIGEST_MISMATCH", f"workset digest disagrees with content: {issue}"
            )
        typed_worksets.append(workset)
    if {str(w["issue"]) for w in typed_worksets} != set(CONSUMER_SEAMS):
        raise InventoryError(
            "MALFORMED_INVENTORY", "every closed consumer must hold exactly one workset"
        )
    if _sha256(_canonical_bytes(typed_worksets)) != header["consumer_worksets_digest"]:
        raise InventoryError("DIGEST_MISMATCH", "consumer workset digest disagrees with content")
    recomputed = _sha256(
        {"header": header, "rows": typed_rows, "consumer_worksets": typed_worksets} and
        _canonical_bytes(
            {"header": header, "rows": typed_rows, "consumer_worksets": typed_worksets}
        )
    )
    if recomputed != digest:
        raise InventoryError("DIGEST_MISMATCH", "inventory digest disagrees with content")
    return header, typed_rows, typed_worksets


def _fail(code: str, detail: str, status: str = "error") -> int:
    print(json.dumps({"status": status, "code": code, "detail": detail}, sort_keys=True))
    return 1 if status == "stale" else 2


def cmd_sync(root: Path, generation_command: str) -> int:
    owner_map = load_owner_map(root)
    inventory = build_inventory(root, None, generation_command, owner_map)
    payload = _emit_toml(inventory)
    target = root / OWNED_TOML
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InventoryError("OUTPUT_UNAVAILABLE", f"cannot create owned parent: {exc}") from exc
    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=".inventory-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(tmp_name, target)
    except OSError as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise InventoryError("OUTPUT_UNAVAILABLE", f"atomic write failed: {exc}") from exc
    header = inventory["header"]
    assert isinstance(header, dict)
    print(
        json.dumps(
            {
                "status": "ok",
                "output": OWNED_TOML.as_posix(),
                "files": header["scan_denominator_files"],
                "candidates": header["candidate_count"],
                "owned": header["owned_count"],
                "unresolved": header["unresolved_count"],
                "coverage_disposition": header["coverage_disposition"],
                "owner_map_status": header["owner_map_status"],
                "inventory_digest": inventory["inventory_digest"],
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_check(root: Path) -> int:
    target = root / OWNED_TOML
    if not target.is_file() or target.is_symlink():
        return _fail(
            "ARTIFACT_MISSING",
            "owned inventory TOML is absent; run sync",
            "stale",
        )
    try:
        stored_raw = target.read_bytes()
    except OSError as exc:
        raise InventoryError("ARTIFACT_UNREADABLE", f"cannot read owned TOML: {exc}") from exc
    artifact = _parse_toml(stored_raw, source=OWNED_TOML.as_posix())
    try:
        header, _rows, worksets = _validate_artifact(artifact)
    except InventoryError as exc:
        return _fail(exc.code, exc.detail)
    mapping, map_status, _map_digest = load_owner_map(root)
    if map_status != "SUPPLIED":
        return _fail(
            "OWNER_MAP_MISSING",
            "the externally supplied frozen owner map required by issue #866 is absent: "
            f"{OWNER_MAP_PATH.as_posix()}; {INTEGRATION_OWNER} must commit it before this "
            "inventory can be certified. sync records the absence explicitly and refuses to "
            "mark any consumer dispatch-ready.",
            "blocked",
        )
    if header["owner_map_status"] != map_status or header["owner_map_digest"] != _map_digest:
        return _fail(
            "STALE_ARTIFACT",
            "owner map input changed since the last sync; run sync",
            "stale",
        )
    fresh = build_inventory(root, None, str(header.get("generation_command", "")), (mapping, map_status, _map_digest))
    fresh_raw = _emit_toml(fresh)
    if fresh_raw != stored_raw:
        return _fail(
            "STALE_ARTIFACT",
            "scanned sources, rules, or owner allocation changed; run sync",
            "stale",
        )
    unresolved = int(header["unresolved_count"])  # type: ignore[arg-type]
    if unresolved or header["coverage_disposition"] != "COMPLETE":
        return _fail(
            "UNRESOLVED_ROWS_BLOCK_COMPLETE_DENOMINATOR",
            f"{unresolved} candidate(s) carry no exact-scope owner; the migration denominator "
            "is incomplete and dispatch stays blocked until each is allocated",
            "blocked",
        )
    not_ready = [str(w["issue"]) for w in worksets if not bool(w["dispatch_ready"])]
    if not_ready:
        return _fail(
            "WORKSET_NOT_DISPATCH_READY",
            "worksets remain blocked: " + ", ".join(sorted(not_ready)),
            "blocked",
        )
    print(
        json.dumps(
            {
                "status": "ok",
                "coverage_disposition": header.get("coverage_disposition"),
                "candidates": header.get("candidate_count"),
                "unresolved": header.get("unresolved_count"),
                "inventory_digest": artifact.get("inventory_digest"),
                "note": "a findings-bearing inventory stays findings-bearing, never a safety pass",
            },
            sort_keys=True,
        )
    )
    return 0


def run_self_tests() -> int:
    sample = """
    // line comment with stu_for_bytes(
    /* block rendered_utf8_bytes */
    struct Envelope {
        rendered_utf8_bytes: u64,
    }
    fn local() {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(1);
        let s = "rendered_utf8_bytes(";
        let raw = r#"stu_for_bytes"#;
    }
    """
    masked = _mask_rust(sample)
    assert "// line comment" not in masked
    assert "block rendered" not in masked
    assert '"rendered_utf8_bytes(' not in masked
    assert 'stu_for_bytes"#' not in masked
    assert "struct Envelope" in masked
    assert "buf.push" in masked
    for bad in ("/* unclosed", 'let s = "unclosed;', 'let r = r#"unclosed;'):
        try:
            _mask_rust(bad)
        except InventoryError as exc:
            assert exc.code == "MALFORMED_RUST_SOURCE", exc.code
        else:
            raise AssertionError(f"expected fail-closed masking: {bad!r}")

    first = _sha256(_canonical_bytes({"b": 2, "a": [1]}))
    second = _sha256(_canonical_bytes({"a": [1], "b": 2}))
    assert first == second, "digests must be key-order independent"
    assert len(set(CLASSIFICATIONS)) == len(CLASSIFICATIONS), "classifications must be unique"
    assert len(BASELINE_CASES) == EXPECTED_BASELINE_COUNT, "baseline must hold 31 cases"
    assert len(DENOMINATOR_CASES) == EXPECTED_DENOMINATOR_COUNT, "denominator count drifted"
    measured: dict[str, int] = {}
    writable_paths: dict[str, str] = {}
    for _ref, owner, _path, _sig in DENOMINATOR_CASES:
        measured[owner] = measured.get(owner, 0) + 1
    for case_ref, owner, path, _signal in DENOMINATOR_CASES:
        if owner == UNRESOLVED_OWNER:
            continue
        if _write_scope_of(owner, _tier_of(case_ref)) != "writable":
            continue
        if writable_paths.setdefault(path, owner) != owner:
            raise AssertionError(
                f"declared denominator grants two consumers write access to {path}"
            )
    assert tuple(sorted(measured.items())) == tuple(
        sorted(EXPECTED_OWNER_ALLOCATIONS)
    ), "declared owner allocation drifted"
    assert all(owner != FORBIDDEN_OWNER for owner in CONSUMER_SEAMS)
    assert all(
        owner != FORBIDDEN_OWNER for _ref, owner, _path, _sig in DENOMINATOR_CASES
    )
    # Baseline cases are untouched by the widened seam denominator.
    assert tuple(BASELINE_CASES) == tuple(DENOMINATOR_CASES[:EXPECTED_BASELINE_COUNT])
    # Every rule arm resolves to a closed class; unknown fails closed.
    for _ref, _owner, _path, signal in DENOMINATOR_CASES:
        label, evidence = classify_context_measurement(signal)
        assert label in CLASSIFICATIONS, signal
        assert evidence, signal
    for signal in ("#[test]", "cfg(test)"):
        assert classify_context_measurement(signal)[0] == "test-only"
    assert classify_context_measurement("rendered_utf8_bytes", "", "test")[0] == "test-only"
    assert (
        classify_context_measurement("body.chars().count().div_ceil(4)")[0]
        == "character_count_mislabeled_as_tokens"
    )
    assert (
        classify_context_measurement("serialized_bytes.div_ceil(4).max(1)")[0]
        == "token_estimate_without_tokenizer"
    )
    assert (
        classify_context_measurement("pub estimated_tokens: usize,")[0]
        == "bare_measurement_field_or_conversion"
    )
    for _ref, _path, needle, _reason in EXCLUSION_CASES:
        assert (
            classify_context_measurement(needle)[0] == "unrelated_byte_or_character_metric"
        ), needle
    try:
        classify_context_measurement("definitely-not-a-measurement-signal-xyz")
    except InventoryError as exc:
        assert exc.code == "CLASSIFICATION_OPEN", exc.code
    else:
        raise AssertionError("expected fail-closed classification for unknown signal")
    assert _rule_digest() == _rule_digest(), "rule digest must be deterministic"
    assert _owner_digest(DENOMINATOR_CASES) == _owner_digest(tuple(reversed(DENOMINATOR_CASES)))
    assert _same_case_set(tuple(reversed(DENOMINATOR_CASES)), DENOMINATOR_CASES), (
        "the build mode is decided by case content, never by caller order"
    )
    assert not _same_case_set(BASELINE_CASES, DENOMINATOR_CASES)
    assert _stu(0) == 0 and _stu(1) == 1 and _stu(3) == 1 and _stu(4) == 2
    # Enclosing-scope detection: production before cfg(test), test inside it.
    scope_sample = (
        "pub fn production_site() -> usize {\n"
        "    let estimated_tokens = 1usize;\n"
        "    estimated_tokens\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    fn helper() -> usize {\n"
        "        2usize\n"
        "    }\n"
        "}\n"
    )
    scope_masked = _mask_rust(scope_sample).splitlines()
    scope_depths = _depths(scope_masked)
    assert _scope_of(scope_masked, scope_depths, 2, "scan/a.rs")[1] == "production"
    assert _scope_of(scope_masked, scope_depths, 9, "scan/a.rs")[1] == "test"
    assert _scope_of(scope_masked, scope_depths, 2, "scan/tests/a.rs")[1] == "test"
    assert _item_extent(scope_masked, scope_depths, 1) == 4
    assert _item_extent(scope_masked, scope_depths, 6) == 10
    assert _item_extent(scope_masked, scope_depths, 7) == 9

    with tempfile.TemporaryDirectory() as td:
        troot = Path(td).resolve()
        scan = troot / "scan"
        scan.mkdir()
        (scan / "demo.rs").write_text(
            "pub struct Envelope {\n    pub rendered_utf8_bytes: u64,\n}\n",
            encoding="utf-8",
        )
        (scan / "helper.rs").write_text(
            "fn estimate_tokens(body: &str) -> usize {\n    body.len().div_ceil(4)\n}\n",
            encoding="utf-8",
        )
        demo_cases = (
            ("704/9", "#704", "scan/demo.rs", "rendered_utf8_bytes"),
            ("783/10", "#783", "scan/helper.rs", "fn estimate_tokens(body: &str)"),
        )
        first_build = build_inventory(troot, demo_cases, "self-test")
        second_build = build_inventory(troot, list(reversed(demo_cases)), "self-test")
        assert _emit_toml(first_build) == _emit_toml(second_build), "build must be deterministic"
        assert int(first_build["header"]["candidate_count"]) == 2  # type: ignore[arg-type]
        assert str(first_build["header"]["coverage_disposition"]) == "INCOMPLETE"
        for workset in first_build["consumer_worksets"]:  # type: ignore[union-attr]
            assert not bool(workset["dispatch_ready"]), workset["issue"]
        round_tripped = _parse_toml(_emit_toml(first_build), source="self-test")
        _validate_artifact(round_tripped)
        # Owner map handling is explicit, never a silent fallback.
        assert load_owner_map(troot)[1] == "ABSENT_EXTERNAL_INPUT_REQUIRED"
        map_dir = troot / OWNER_MAP_PATH.parent
        map_dir.mkdir(parents=True, exist_ok=True)
        (map_dir / OWNER_MAP_PATH.name).write_text("owners = [\n", encoding="utf-8")
        try:
            load_owner_map(troot)
        except InventoryError as exc:
            assert exc.code == "OWNER_MAP_MALFORMED", exc.code
        else:
            raise AssertionError("malformed owner map must fail closed")
        (map_dir / OWNER_MAP_PATH.name).unlink()
        # A dispatch-ready row may not carry an empty or wildcard test allocation.
        tampered = _parse_toml(_emit_toml(first_build), source="self-test")
        for workset in tampered["consumer_worksets"]:  # type: ignore[union-attr]
            workset["test_paths"] = []
            workset["dispatch_ready"] = True
        try:
            _validate_artifact(tampered)
        except InventoryError as exc:
            assert exc.code in ("EMPTY_TEST_ALLOCATION", "DIGEST_MISMATCH"), exc.code
        else:
            raise AssertionError("empty test allocation on a dispatch-ready row must fail closed")
        # Duplicate test path across consumers is a collision.
        collided = _parse_toml(_emit_toml(first_build), source="self-test")
        first_ws, second_ws = collided["consumer_worksets"][0:2]  # type: ignore[union-attr]
        first_ws["test_paths"] = ["scan/a.rs"]
        second_ws["test_paths"] = ["scan/a.rs"]
        try:
            _validate_artifact(collided)
        except InventoryError as exc:
            assert exc.code in ("TEST_PATH_COLLISION", "DIGEST_MISMATCH"), exc.code
        else:
            raise AssertionError("shared mutable test path must fail closed")
        # Empty denominator, missing input, and malformed source all fail closed.
        for bad in ((), (("704/1", "#704", "no/such.rs", "rendered_utf8_bytes"),)):
            try:
                build_inventory(troot, bad, "self-test")
            except InventoryError as exc:
                assert exc.code in ("EMPTY_SCAN", "SOURCE_NOT_REGULAR_FILE"), exc.code
            else:
                raise AssertionError(f"expected fail-closed build for {bad!r}")
        (scan / "bad.rs").write_text('let s = "unclosed;\n', encoding="utf-8")
        try:
            build_inventory(troot, (("704/1", "#704", "scan/bad.rs", "rendered_utf8_bytes"),), "u")
        except InventoryError as exc:
            assert exc.code == "MALFORMED_RUST_SOURCE", exc.code
        else:
            raise AssertionError("malformed Rust source must fail closed")
        # An absent artifact is stale, never an empty success.
        assert cmd_check(troot) == 1

        # check rejects missing / extra / hand-edited rows without writing.
        baseline_raw = _emit_toml(first_build)
        for label, mutate in (
            ("missing", lambda art: art["rows"].pop()),
            ("extra", lambda art: art["rows"].append(dict(art["rows"][0], id="c9999"))),
            (
                "hand-edited",
                lambda art: art["rows"][0].__setitem__("classification", "test-only"),
            ),
            ("dropped-span", lambda art: art["rows"][0].__setitem__("span_start", 0)),
        ):
            tampered_rows = _parse_toml(baseline_raw, source="self-test")
            mutate(tampered_rows)
            try:
                _validate_artifact(tampered_rows)
            except InventoryError as exc:
                assert exc.code != "OK", label
            else:
                raise AssertionError(f"check must reject a {label} row")
        # Rule and owner allocation digests are sensitive to their inputs.
        assert _sha256(_canonical_bytes({"a": 1})) != _sha256(_canonical_bytes({"a": 2}))
        assert _owner_digest(DENOMINATOR_CASES) != _owner_digest(BASELINE_CASES)
        assert _rule_digest() == _sha256(
            _canonical_bytes(
                {
                    "rule_revision": RULE_REVISION,
                    "classifications": list(CLASSIFICATIONS),
                    "forbidden_owner": FORBIDDEN_OWNER,
                    "unresolved_owner": UNRESOLVED_OWNER,
                    "integration_owner": INTEGRATION_OWNER,
                    "consumer_seams": dict(sorted(CONSUMER_SEAMS.items())),
                    "stu_accounting_rule": STU_RULE,
                    "upper_review_band_stu": UPPER_REVIEW_BAND_STU,
                }
            )
        )

    print("PASS: context_measurement_inventory self-tests completed successfully")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("sync", "check"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        if args.command is not None:
            print("error: --self-test takes no command", file=sys.stderr)
            return 2
        try:
            return run_self_tests()
        except (InventoryError, AssertionError) as exc:
            print(f"SELF_TEST_FAILED: {exc}", file=sys.stderr)
            return 1
    if args.command == "sync":
        generation = (
            "python scripts/context_measurement_inventory.py sync"
            f" --root {args.root.as_posix()}"
        )
        try:
            return cmd_sync(args.root, generation)
        except InventoryError as exc:
            print(
                json.dumps(
                    {"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True
                ),
                file=sys.stderr,
            )
            return 2
    if args.command == "check":
        try:
            return cmd_check(args.root)
        except InventoryError as exc:
            print(
                json.dumps(
                    {"status": "error", "code": exc.code, "detail": exc.detail}, sort_keys=True
                ),
                file=sys.stderr,
            )
            return 2
    print("error: expected sync, check, or --self-test", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
