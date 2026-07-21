---
name: eliot-verify-finish
description: "Guides Claude to verify current artifacts and choose an honest verified, partial, blocked, failed, or unsafe-to-finish result before any completion claim."
---

# ELIOT verify and finish

Use this skill after implementation or diagnosis and before claiming completion.
A model statement that work looks correct is never verification evidence.

## Restore the acceptance boundary

1. Read `eliot_host_session_status` and the exact task-scoped role.
2. Read `eliot_task_state` for acceptance items and finish gaps.
3. Confirm the current revision and exact accepted artifact scope.
4. Separate work performed from work accepted by the task contract.
5. Treat stale or differently scoped evidence as unresolved.

## Map evidence

For every acceptance item, record:

- the exact artifact or behavior under test;
- the registered verifier or focused probe;
- the current output or receipt reference;
- the revision and environment identity;
- the pass, fail, skipped, stale, or unknown state.

Do not use a successful unrelated check to cover a missing verifier.
Do not treat package creation, UI loading, or model prose as runtime success.

## Run the smallest honest verifier set

1. Prefer exact source, compiler, test, schema, and live client evidence.
2. Run focused checks before one bounded final suite.
3. Capture non-secret output, exit status, and artifact hashes.
4. Record a failure without erasing prior successful evidence.
5. Re-run only when the artifact or discriminating condition changed.
6. Detect revision drift before accepting an older result.

## Decide status

- Verified: every acceptance item has current authoritative evidence.
- Partial: bounded useful work exists but one or more items remain open.
- Blocked: a named external dependency prevents an otherwise ready check.
- Failed: a required verifier currently fails on accepted artifacts.
- Unsafe to finish: authority, scope, revision, or secret boundary is unknown.

## Submit or hand off

1. Record exact VerificationRuns when the live surface exposes that tool.
2. Submit a CompletionProof only with current completion authority.
3. Otherwise submit a bounded candidate result for controller disposition.
4. Respect the canonical FinishGate; never manufacture `DONE_VERIFIED`.
5. Report skipped checks, residual issues, rollback, and next verifier.

Hook success, MCP connection, and provider authentication are separate facts.
Unknown completion authority means partial or blocked, never silent success.
