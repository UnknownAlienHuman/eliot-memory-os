# Code navigation: crates, Rust modules, logical blocks, and Code Graph

This is the operational entry point from a repository path to its current source
boundary. It complements the normative documentation router; it does not replace
Architecture, Implementation, exact source, tests, or runtime proof.

## Start from a path

Run code navigation and the verified documentation reader before a material
source/configuration change:

```powershell
python scripts/code_navigation.py route --path crates/instrument/eliot-code-graph/src/lib.rs
python scripts/docs_read.py read --path crates/instrument/eliot-code-graph/src/lib.rs --topic "code graph ownership and change impact" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

The code-navigation route returns:

- the owning Cargo package and whether it is a default member, another workspace
  member, or a nonmember/prototype package;
- a filesystem-derived Rust module locator;
- the nearest applicable `AGENTS.md` chain;
- matching logical responsibility blocks;
- current documentation route IDs and representative normative handles;
- direct local path dependencies and reverse workspace dependencies;
- the mandatory CodeBase Memory MCP query/coverage loop.

A filesystem module locator is navigation only. Inline modules, `#[path]`,
conditional compilation, macro expansion, symbol resolution, calls, references,
implementations, and reachability must be resolved through Code Graph and exact
source.

## Live and committed indexes

The live registry is generated from the current checkout; no committed
code-graph database or hand-maintained crate list is authoritative. Two
deterministic projections make package-to-document navigation reviewable in
GitHub:

- [`PACKAGE_DOCS_INDEX.md`](code-navigation/PACKAGE_DOCS_INDEX.md) covers every
  package admitted by the exact root `Cargo.toml`;
- [`PROTOTYPE_DOCS_INDEX.md`](code-navigation/PROTOTYPE_DOCS_INDEX.md) covers
  every discovered nonmember Cargo package and requires explicit
  `prototype = true` plus a nonempty `workspace_admission`.

Both projections bind manifests to inherited package-family `AGENTS.md`
contracts, logical responsibility blocks, and canonical documentation handles.
Prototype presence is not workspace admission, implementation completion,
runtime support, or Product acceptance.

```powershell
# Every Cargo package, with workspace/default/nonmember admission.
python scripts/code_navigation.py list --view crates

# Every Rust source file with a filesystem-derived module locator.
python scripts/code_navigation.py list --view modules

# Logical responsibility blocks, path selectors, docs routes, and handles.
python scripts/code_navigation.py list --view blocks

# Machine-readable full registry.
python scripts/code_navigation.py list --view crates --format json

# Rewrite both committed package-to-document projections.
python scripts/code_navigation.py sync-index --root .
```

The root `Cargo.toml` is the sole workspace-member/default-member input.
Additional `Cargo.toml` files are still discovered and labelled `nonmember`; this
prevents candidate/prototype crates from disappearing from navigation or being
mistaken for admitted workspace members.

The logical block map is
[`code-navigation/logical-blocks.toml`](code-navigation/logical-blocks.toml).
`python scripts/code_navigation.py check --root .` fails when:

- the workspace denominator contains a missing, duplicate, or unexpected package;
- a workspace/default member resolves to no manifest or target front door;
- any discovered Cargo package falls outside every logical block;
- a package block has no governing handle or resolves no documentation route;
- a package does not inherit the required `crates/`, `bins/`, or
  `workspace/tools/` `AGENTS.md` contract;
- a family contract omits the verified-reader command, reading-protocol link, or
  required index backlink;
- a nonmember package is not explicitly classified as a prototype or has no
  `workspace_admission`;
- either committed package-to-document index is missing, stale, or hand-edited;
- a configured path escapes the repository or matches no current file;
- a configured normative handle is absent from the generated handle index;
- the generated registry is nondeterministic.

## Path rules

All stored and emitted paths are repository-relative POSIX paths, even on
Windows. Drive-qualified, absolute, and `..`-traversing paths are rejected.
Commands may receive either `/` or `\`; output always uses `/`.

Use the exact changed file whenever possible. Routing a broad directory is
permitted for discovery, but it does not prove the exact source, target,
feature/configuration, caller, consumer, or test closure.

Path ownership is longest-prefix based, so a nested Cargo package is not
silently attributed to an enclosing package. Local dependency edges are derived
from package dependency tables and inherited `[workspace.dependencies]`; reverse
edges are computed from the same current manifests.

## Mandatory CodeBase Memory MCP loop

For every nontrivial source change, use CodeBase Memory MCP actively before and
after editing. The default mutation tier is **Verify**. Use **Auditor** for
exhaustive impact, absence, dead-code, or deletion claims.

### Before editing

1. Confirm the exact repository/worktree and the active CodeBase Memory project.
2. Record the tool version, project, current index generation/status, and
   worktree/source revision. Do not reuse a receipt from another branch or
   checkout.
3. Run `get_graph_schema`, then use `get_architecture` and `search_graph` to find
   the owning package, qualified symbols, definitions, implementations,
   references, and tests.
4. Use `trace_path` (alias `trace_call_path`) or read-only `query_graph` for the
   bounded inbound/outbound call and dependency closure.
5. Run `check_index_coverage` for every graph-cited path and for the whole scope
   behind any negative or exhaustive claim.
6. Read the exact source, contracts, tests, Cargo manifests, nearest
   `AGENTS.md`, and documentation fragments returned by the repository routers.

Record a `CodeUnderstandingProof` in the issue/PR:

```text
tool/version:
project and index generation/status:
source/worktree revision:
paths and qualified symbols:
queries and pagination:
coverage result per cited path:
graph findings:
exact-source confirmations:
ambiguities/fallbacks:
```

### After editing

1. Refresh or reindex the same project and record the new generation/status.
2. Run `detect_changes` against the exact candidate diff.
3. Re-run the relevant symbol, call-path, implementation/reference, test, and
   reverse-dependency queries.
4. Repeat `check_index_coverage` for changed and newly cited paths.
5. Run the package/module/edge verifiers selected from exact source.
6. Record a `CompletionProof` containing the candidate revision, changed
   symbols, graph delta, affected edges/tests, coverage, executed verifiers, and
   residual unknowns.

### Hard boundaries

Code Graph results are derived navigation and impact observations, not source,
semantic, runtime, or product authority. A clean coverage response means only
that the tool reports no known indexing gap; it is not proof of completeness.

`STALE`, `SPLIT_VIEW`, `FAILED`, partial, ambiguous, skipped, excluded, or
unknown coverage cannot prove absence, non-impact, dead code, safe deletion, or
complete test selection. Fall back to exact source/build/verifier evidence or
return an explicit unknown.

Do not:

- let CodeBase Memory write Architecture/Implementation or ELIOT canonical
  memory/state;
- use its ADR store as a second repository authority;
- commit `.codebase-memory/`, caches, graph snapshots, logs, or generated
  reports;
- start a second always-on watcher for the same repository root;
- add a runtime dependency from ELIOT Kernel/Governor/semantic core to the
  external MCP server.

The repository-owned `eliot-code-graph`/Code Cortex contracts and external
CodeBase Memory MCP may coexist only as explicitly bounded projections with one
selected lifecycle owner per index root.

## Validation

```powershell
python scripts/code_navigation.py self-test
python scripts/code_navigation.py check --root .
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
just quick
```

The script and its configuration are owned by issue
[#280](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/280), with
complete Cargo-package ↔ documentation closure extended by issue
[#577](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/577).
Their proof ceiling is repository navigation and static path/dependency
consistency. They do not prove Rust compilation, graph completeness, runtime
behavior, storage correctness, or Product acceptance.

See also:

- [`code-navigation/PACKAGE_DOCS_INDEX.md`](code-navigation/PACKAGE_DOCS_INDEX.md)
  for every admitted workspace package;
- [`code-navigation/PROTOTYPE_DOCS_INDEX.md`](code-navigation/PROTOTYPE_DOCS_INDEX.md)
  for every explicitly classified nonmember prototype package;
- [`PROJECT_MAP.md`](PROJECT_MAP.md) for high-level runtime/source planes;
- [`architecture/READING_PROTOCOL.md`](architecture/READING_PROTOCOL.md) for
  bounded normative reading;
- [`architecture/I10-08-17-code-intelligence-capability-planes-and-query-semantics.md`](architecture/I10-08-17-code-intelligence-capability-planes-and-query-semantics.md)
  for query/coverage semantics;
- [`architecture/I10-08-19-code-intelligence-adapter-arbitration-and-repowise-pilot.md`](architecture/I10-08-19-code-intelligence-adapter-arbitration-and-repowise-pilot.md)
  for external-adapter boundaries.
