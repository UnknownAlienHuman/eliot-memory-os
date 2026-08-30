### I10.8.5. IP3 — streaming evidence and normalization

`ProcessExecutor` streams stdout/stderr concurrently:

```text
process stream
→ bounded preview ring;
→ incremental parser;
→ append-only temporary raw evidence object;
→ final BlobRef + digest + truncation/parse metadata.
```

Independent limits exist for preview bytes, stored raw bytes, event count, line length, idle/wall time and Job Object resources. Pipe saturation must not deadlock the child. Truncation is explicit evidence, never silent.

Every normalized result is an `EvidenceEnvelope` with independent dimensions:

```text
Authority:
  source identity | compiler/language | compiler-derived semantics |
  deterministic runtime/test | heuristic static | model interpretation;

Freshness:
  exact_candidate | exact_commit | exact_quiesced_worktree |
  known_older_snapshot | stale | unknown;

Coverage:
  complete_for_scope | partial_for_scope | not_applicable | unknown;

Provenance:
  executable hash/version/file identity;
  config/environment/feature/toolchain hash;
  WorkScope/base/candidate/worktree;
  invocation and profile revision;
  start/finish/resource outcome;
  raw evidence handles.
```

Authority is property-relative, not a universal scalar. Rust compiler evidence outranks a heuristic parser for type validity; a runtime test outranks static inference for the observed behavior it actually exercises.

