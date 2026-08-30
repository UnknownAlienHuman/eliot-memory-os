### I10.8.19. Code-intelligence adapter arbitration and RepoWise pilot

`CapabilityRouteDecision` is the code-intelligence specialization of the existing `ToolRouteDecision`; it does not create another scheduler, policy owner or durable decision family. It selects the owner for one query family and packet generation:

```yaml
CapabilityRouteDecision:
  capability:
  query_intent:
  scope_and_source_fence:
  policy_and_capability_registry_revisions:
  candidates:
    - adapter_id:
      coverage_state:
      generation:
      assurance_ceiling:
      expected_cost:
      known_failures:
  selected_owner:
  fallback_owner:
  disagreement_policy:
  evidence_required:
  validity_and_invalidation:
  decision_receipt_ref:
```

A common adapter manifest includes executable/protocol hashes, index generation, source revision, dirty-state/cache-root identity, coverage, parser failures, response budget, lifecycle owner, network and license profile.

A common result envelope includes:

```text
capability/query intent;
adapter/generation/source fence;
complete/partial/ambiguous/stale/unavailable/unknown status;
navigation candidates;
evidence atoms;
derived relations;
impact directives;
ambiguity sets;
coverage and approximation;
omission handles;
raw result reference;
authority = derived observation.
```

Disagreement preserves both observations, compares source fences/coverage and requests the cheapest discriminative probe. Confidence values are never averaged into truth.

RepoWise and `codebase-memory-mcp` are admitted only as supervised derived adapters:

```text
pinned immutable artifact and license record;
isolated cache root;
read-mostly capability subset;
no direct ELIOT write;
no direct agent hooks/Skills/ADR mutation;
no generated answer as proof;
no `safe_to_delete` authority;
no second auto-watch owner;
no broad generated wiki injection;
no Python/third-party dependency in Kernel or semantic core.
```

RepoWise is especially valuable as a donor/pilot arm for session episodes, Git behavior, reversible payloads, source skeletons, risk/test directives and context delivery. `codebase-memory-mcp` is a competing/overlapping source-semantic graph arm. Capability ownership is selected by a sealed pilot over real Rust/ELIOT tasks, coverage, freshness, resource use, failure recovery and agent decision delta. Neither receives monopoly by README claim.

AGPL or other restrictive code is not copied into ELIOT. Process separation is an architectural isolation boundary, not a license exemption. Redistribution, packaging or hosted use requires a separate license review; until admitted, a pilot uses a user-supplied or maintainer-local pinned artifact and publishes no donor code. Selected mechanisms are reimplemented clean-room in first-party contracts.


### Bulk mechanics execute as a program, not as model turns

When a task requires many similar operations — fan-out over queries, filtering, joins, deduplication, normalization or per-item extraction — a turn-per-operation loop is the wrong shape. Each operation costs one inference round trip, intermediate candidates pollute context, one failure can end the whole trajectory, and mechanical work is performed semantically.

The admitted shape separates three responsibilities:

```text
the route proposes the semantic strategy and the shape of the result;
a deterministic bounded program executes the repetitive mechanics inside the Instrument Plane;
only samples, aggregates, errors and selected evidence return to the model context.
```

The program is an instrument invocation with the normal contract: exact executable identity, bounded resources, cancellation, per-item failure isolation, durable intermediate artifacts and an `EvidenceEnvelope`. It receives no ambient authority, and per-branch failure never discards successful siblings.

This shifts mechanics out of the model loop; it does not remove the need for evidence, coverage accounting or verification. A generated program can be efficient and still retrieve the wrong sources.

