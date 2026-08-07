# Opus 5 decision: run006 public projection loss

- Session: `57aae3d9-c309-474e-9728-49fa6bd63d63`
- Model: `claude-opus-5`
- Effort: `max`
- Tools: `Read`, `Grep`, `Glob` only; strict empty MCP config; plan permission mode
- Result: completed in 388.2 s wall / 385.3 s API time
- Reported cost: USD 1.692341
- Provider/model calls other than this consultation: zero

## Decision

The missing ignored `reports/cognitive-field/core-qualification/...` trees are a recoverable
projection-loss incident only when every restored load-bearing byte is verified against a
pre-loss commitment held outside the lost projection. The accepted private U03 evidence remains
authoritative; the verifier and seal/generation checks must remain unchanged.

`cq-core-20260730-006` generation 2 remains conditionally valid because generation 1 is typed
`Abandoned`, its recovery receipt is complete, authority is retired, staged artifacts were
hash-preservingly quarantined and no provider call occurred. The condition is mechanical:
restoration must satisfy the unmodified prior-role verifier and run006's restored contract must
reproduce the generation-1 `contract_sha256`.

## Accepted recovery shape

1. Generic restoration mechanism with tuple-scoped incident authorization.
2. Inventory with zero writes; every file must have a surviving independent commitment.
3. Stage under the private run root and verify before publication.
4. Persist a typed `eliot-public-projection-restoration-v1` record as `InProgress` before
   publishing.
5. Publish create-only: identical existing bytes are an idempotent no-op; divergence is a hard
   error; never overwrite or delete.
6. Re-read and re-verify every published file, then run an unmodified seal dry-run.
7. Mark the restoration record `Complete` only after all postconditions pass.

Raw-byte inputs such as provider output artifacts, deterministic reports and hash-qualified
content references must reproduce exact SHA-256. Parsed/canonical artifacts still must satisfy
their existing structural and canonical-hash checks. Historical plan hashes must be computed from
raw JSON values with only the hash field blanked, never by round-tripping a newer typed struct.

## Critical caveat

`preflight.json` currently has no observed strong pre-loss digest. Its `reader_surface_scans.clean`
claim must not be recreated from the current binary alone, because that creates a
self-certification loop. It is admissible only if an independent digest-bound surviving artifact
attests the scan. Otherwise the affected prior role is not reusable and the task is `BLOCKED`.

## Fallback ladder

- Primary: exact restoration, then run006 generation 2 with eight fresh calls.
- If restoration succeeds but run006's contract cannot reproduce generation-1 SHA: a new run007
  may reuse the same four U03 roles and retain the eight/max-nine fresh-call budget.
- If any U03 dependency lacks a commitment or mismatches: `BLOCKED`. Do not silently convert U03
  to fresh calls; twelve calls require an explicit operator amendment.

## Required gates before provider use

- restoration dry-run: zero writes and every commitment resolved;
- restoration apply: complete record and fresh-read post-hash verification;
- unmodified run006 seal dry-run: four reused U03 roles, eight fresh calls, zero provider calls,
  no provider plan and no staging residue;
- next generation exactly 2, no Staged/Activated seal record;
- zero-model Governor MCP/runtime preflight;
- focused Task 02R2 Cargo, fmt, check, strict Clippy and diff gates.

## Do not do

- Do not relax or special-case the prior-role verifier.
- Do not overwrite or delete public evidence.
- Do not reconstruct any file without a surviving pre-loss commitment.
- Do not treat the scratch probe as evidence.
- Do not re-run prepare against the original run006 public root before exact restoration.
- Do not dispatch a provider or consume call nine for projection recovery.
- Do not rewrite run003/run005 acceptance or hash historical JSON through current structs.
