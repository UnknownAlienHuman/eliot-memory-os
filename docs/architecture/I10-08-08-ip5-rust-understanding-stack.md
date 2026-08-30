### I10.8.8. IP5 — Rust understanding stack

Rust code understanding uses layered evidence:

```text
Layer A: Git and Cargo
  exact candidate identity, changed files, package/target/feature graph,
  reverse package dependencies and affected test binaries;

Layer B: pinned rust-analyzer/SCIP
  definitions, references and implementations on an exact quiesced candidate;

Layer C: optional heuristic scout
  Codebase Memory or another admitted graph for architecture clusters,
  candidate paths and exploration reduction;

Layer D: CodeCortex compositor
  task-relative fusion with ELIOT decisions, invariants, failures,
  diagnostics, runtime observations and verifiers.
```

Rules:

```text
Cargo metadata is parsed through a maintained Rust library, not ad-hoc traversal;
clean tracked files use Git tree/index identity; only dirty/untracked content is rehashed;
rust-analyzer/SCIP starts one-shot on exact candidate before persistent LSP is considered;
rustc/Clippy remain build/type authority; rust-analyzer supplies navigation evidence;
heuristic graphs are optional and never authorize writes or prove negative facts;
all graph outputs carry adapter build, candidate identity, freshness and coverage;
CodeCortex does not parse Rust through hard-coded regexes or invent invariant cards.
```

A Codebase Memory pilot, if admitted, runs as a pinned CLI process under ProcessExecutor with isolated cache, no host installation, no hooks/Skills/ADR/UI/daemon/watcher and read-only query subset. It remains heuristic until the ELIOT golden suite proves freshness, worktree identity, negative-result correctness and resource cleanup.

