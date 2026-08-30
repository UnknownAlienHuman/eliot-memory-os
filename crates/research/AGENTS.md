# Research source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


This subtree owns inquiry/acquisition contracts, source portfolio/coverage and
candidate evidence exchange. It does not own synthesis truth, Cognitive
Inheritance admission, task authority, canonical writes, policy, provider
process mechanics or finish. Issue #24 owns provider execution; #100 owns the
shared native-process contract; Governor owns admission.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Hard boundaries

- Research results remain candidate/evidence material with exact source,
  provenance, freshness, coverage denominator, route, privacy and usage
  evidence.
- “No result” is not absence/completeness without a declared denominator and
  provider/coverage disposition.
- Provider executables/generations are resolved through admitted immutable
  manifests and the shared governed process contract. No environment-selected
  path, caller-supplied command, ambient credentials or generic shell.
- Provider-local job IDs are locators only. Bind them to ELIOT operation,
  request digest, provider artifact/process generation, fence, deadline and
  cancellation/reconciliation identity.
- Preserve raw output/exit/process evidence or immutable omission handles before
  reduction. Timeout, cancellation, crash, unavailable source and unknown
  provider outcome remain distinct.
- Researcher may grade/source/assemble evidence sets; it cannot turn output into
  current belief, memory influence, policy or task completion.
- Paid/network/privacy fallback is explicit and separately authorized; never
  widen route or data class silently.
- Candidate evidence enters canonical state only through Governor admission;
  this subtree has no canonical-store write authority.

## Proof and stop condition

Changes require typed protocol fixtures plus a real provider edge for artifact
approval, timeout, cancellation, cleanup, duplicate/unknown job,
route/privacy/budget/fence mismatch and unavailable-provider degradation.
Admission into memory/epistemic position is a Governor/cognitive issue, not a
provider adapter shortcut.

Stop when requested behavior needs semantic synthesis, canonical storage,
authority, model policy, task/finish ownership or ambient process/credential
access.
