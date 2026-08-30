### I10.8.10. Migration from overlapping verification paths

Current migration source contains overlapping high-level verification, patch verification, repository automation and CI definitions. They converge on one InstrumentRunner:

```text
high-level verification domain
  → profile/result types and reporting over actual InstrumentRuns;

PatchRunner
  → disposable worktree/candidate handling only;
  → no private command map and no reverse-patch transaction illusion;

Justfile and CI
  → thin invokers of the same named profile;

CodeCortex
  → consumes existing instrument evidence; does not rerun diagnostics privately.
```

Synthetic successful command records, synthetic flake reports, hard-coded baseline pass text, hard-coded CodeCortex invariants and static test inventory as authority are removed or quarantined. Normal agent edits happen in leased worktrees; external patch candidates are applied and verified in disposable worktrees, then promoted as an IntegrationCandidate.

Path identity preserves case. Existing paths use handle-derived Windows/file/Git identity when equality or security matters; proposed paths use traversal-safe lexical normalization without lowercasing.

