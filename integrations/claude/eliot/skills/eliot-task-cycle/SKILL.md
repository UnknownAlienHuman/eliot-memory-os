---
name: eliot-task-cycle
description: "Guides Claude through starting, resuming, reframing, or completing a material task with ELIOT task state, scoped evidence, receipts, and finish gates."
---

# ELIOT task cycle

Use this skill for material work with acceptance criteria or durable state.
Skip it for a conversational answer that creates no reusable project result.

## Establish scope

1. Call `eliot_host_session_status` and inspect the active session binding.
2. Resolve one stable identity with `eliot_project_identity`.
3. Read `eliot_task_state` when an exact task is already in scope.
4. Read `eliot_current_state` before broad recall or local mutation.
5. Confirm goal, scope, acceptance, revision, role lease, and work lease.
6. If scope is ambiguous, ask or return a bounded candidate; do not invent it.

## Classify information

- Current truth is live repository or canonical current-state evidence.
- Recalled experience is a lead with recorded applicability conditions.
- A hypothesis is an explanation still awaiting a discriminative check.
- An unknown is material missing evidence, not a reason to guess.
- Permission comes from the current role and action/work lease intersection.
- Completion evidence comes from registered verifiers and accepted artifacts.

## Build the smallest context

1. Use `eliot_recall_l0` only for a concrete decision or failure pattern.
2. Expand exact selected handles with `eliot_fetch_l2`.
3. Use `eliot_compile_packet_l3` when state plus exact handles is insufficient.
4. Keep packet scope decision-local and preserve conflicts and unknowns.
5. Load no architecture master, raw database state, or unrelated history.

## Perform governed work

1. Trace goal to the boundary, artifact, observable, and verifier.
2. Use `eliot-understanding` before a material mutation or conclusion.
3. Request only actions allowed by the current tool surface and leases.
4. Record novel evidence or a candidate with a retry-stable write ID.
5. Never copy a recalled claim into a new candidate as if newly observed.
6. When delegation has positive value, switch to `eliot-delegation`.

## Finish honestly

1. Switch to `eliot-verify-finish` after implementation or diagnosis.
2. Map each acceptance item to exact current evidence.
3. Submit a candidate result when this host lacks completion authority.
4. Respect controller disposition and the canonical FinishGate.
5. Report skipped checks, stale revisions, blockers, and uncertainty.

The host name never grants a role. Skill guidance never bypasses Governor policy.
