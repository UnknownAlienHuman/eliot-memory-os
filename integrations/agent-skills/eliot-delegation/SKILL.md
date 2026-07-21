---
name: eliot-delegation
description: "Guides Claude to delegate or consume separately verifiable agent work through ELIOT when parallel execution, specialist evidence, review, or handoff has positive value."
---

# ELIOT delegation

Use this skill only when separation adds independent evidence or reduces latency.
Do not delegate a tiny sequential step or duplicate work already in flight.

## Confirm authority and value

1. Read `eliot_host_session_status` for the active task-scoped role lease.
2. Confirm the exact task, acceptance item, and current revision.
3. Explain why the work is independently verifiable and worth delegating.
4. Controller operations require a live controller lease and `delegate` scope.
5. Host or provider identity never supplies controller authority.

## Define one bounded work item

1. Name one outcome and one acceptance boundary.
2. Specify read scope, write scope, and prohibited side effects.
3. Select the smallest role-specific packet and exact evidence handles.
4. Identify the expected result kind and registered verifier.
5. Bind task, work item, role lease, work lease, and revision fence.
6. Use a retry-stable idempotency key to prevent blind duplicates.

## Dispatch

1. Call `eliot_agent_delegate` only after all bindings are known.
2. Choose an existing eligible host route; do not invent one.
3. Pass compact handles, not raw history or architecture documents.
4. Preserve candidate-only authority for model or provider output.
5. On unknown dispatch outcome, reconcile before retrying.

## Execute as a target

1. Claim only work whose role and work leases match the current session.
2. Read the supplied packet and expand exact handles only as needed.
3. Stay inside the declared path and mutation scope.
4. Return evidence, verifier suggestions, uncertainties, and candidate status.
5. Never claim task completion merely because local work succeeded.

## Consume as controller

1. Read the exact candidate through `eliot_agent_result`.
2. Inspect its evidence and current revision; do not trust prose alone.
3. Run or require the mapped independent verifier.
4. Call `eliot_agent_result_disposition` to accept, reject, or request a probe.
5. Preserve one canonical task history and record how the result influenced it.
6. Release or close only the leases owned by this bounded work item.

If required coordination tools are absent from the compact live surface, stop and
return the bounded handoff need; never route around Governor through direct chat.
