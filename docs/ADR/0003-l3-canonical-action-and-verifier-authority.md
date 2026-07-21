# ADR 0003: L3 canonical action and verifier authority

Known facts:
- L2 accepted caller-authored provenance strings and a free-text verifier artifact scope.
- SurrealDB record identifiers use `table:id` syntax, so authority references beginning with that shape can round-trip as records rather than opaque strings.
- A passed command is authoritative only for the exact worktree, commit, dirty state, inputs, verifier configuration, and acceptance mapping it observed.

Causal mechanism:
- Persuasive strings can name nonexistent, stale, cross-task, or cross-project evidence while looking syntactically complete.
- A verification result detached from its artifact fingerprint remains reusable after mutation and can create a false `DONE_VERIFIED` state.
- Binding task writes to the authenticated IPC session preserves the transport principal in the canonical write envelope instead of inventing an agent from the task ID.

Conclusion:
- Compile a deterministic packet reference from the current TaskContract and the current project memory revision, including negative-memory surfaces.
- Resolve every evidence handle to a committed WriteReceipt with the exact project, task, and revision scope before issuing an ActionLease.
- Persist the resulting `ActionProvenanceSet` and require its hash on the observation and verifier transitions.
- Register verifier implementations and compute `VerifierArtifactScope` inside the daemon; caller text is never scope authority.
- Re-resolve the stored VerificationRun and artifact scope at FinishGate time, so a changed commit, branch, worktree, dirty state, artifact, config, or evidence mapping denies completion.
- Use slash-prefixed opaque references such as `eliot/verifier/...` and `eliot/task/...` so they round-trip through SurrealDB without record-ID coercion.
