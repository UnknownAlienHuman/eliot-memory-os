---
name: eliot-understanding
description: "Guides Claude to build decision-sufficient causal understanding before code changes, debugging conclusions, architecture decisions, or research synthesis."
---

# ELIOT understanding

Use this skill when the causal path is not already established by current facts.
Do not load it merely to repeat a known command or answer a trivial question.

## Frame the decision

1. State the exact decision, proposed action, or conclusion to justify.
2. Call `eliot_host_session_status` to learn the current authority boundary.
3. Resolve the project with `eliot_project_identity`.
4. Read task and current state before querying historical memory.
5. Name the observable that would distinguish the leading explanations.

## Request bounded evidence

1. Use current source, metadata, diagnostics, and tests as repository truth.
2. Recall only a relevant failure, invariant, or experience pattern.
3. Expand exact handles with `eliot_fetch_l2`; avoid whole-history reads.
4. Compile one causal packet only if the selected evidence is insufficient.
5. Preserve conflicting evidence and negative memory in the packet.
6. Do not request provider-private roots, credentials, or direct database data.

## Separate epistemic classes

- Verified: supported by current source, canonical record, or verifier output.
- Supported: backed by evidence but not yet decisive for this revision.
- Assumed: plausible and explicitly awaiting a check.
- Conflicted: credible evidence points in incompatible directions.
- Stale: valid for an older revision or environment only.
- Unknown: no decision-sufficient evidence is available.

## Trace causality

1. Connect intent to the affected boundary.
2. Connect the boundary to the exact symbol, config, or artifact.
3. Connect that artifact to a runtime or package behavior.
4. Connect the behavior to one observable result.
5. Connect the observable to a registered verifier or focused probe.
6. Identify blast radius, rollback boundary, and remaining uncertainty.

## Test memory applicability

1. Treat an ExperienceCase or ExperiencePattern as recalled evidence only.
2. Compare all matching, mismatching, and negative conditions locally.
3. Reject a deceptive near-match when one required condition is absent.
4. Record use, adaptation, rejection, or `NO_USEFUL_MEMORY` through
   `eliot_memory_influence_trace` when that tool is exposed.

## Produce the outcome

State the evidence that changed the decision and the cheapest remaining probe.
Submit only novel candidate evidence; never promote truth or completion yourself.
Unknown authority means deny or ask, not silent permission.
