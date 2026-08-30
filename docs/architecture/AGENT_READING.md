# Mandatory documentation routing for agents

ELIOT has one accepted normative pair:

- [`ELIOT_ARCHITECTURE.md`](./ELIOT_ARCHITECTURE.md) — intent, theory,
  invariants, and Hard Boundaries;
- [`ELIOT_IMPLEMENTATION.md`](./ELIOT_IMPLEMENTATION.md) — concrete owners,
  contracts, failure behavior, defaults, and migration.

The two canonical files retain their accepted paths and exact SHA-256 identities.
They are not normal whole-prompt inputs. `scripts/docs_router.py` turns them into
byte-exact semantic slices and records which slices a work unit was required to
read.

## Non-negotiable workflow

Before the first implementation edit:

1. List every path the work unit expects to change. Include tests, manifests,
   documentation, build files, generated contracts, and one-hop consumers.
2. Run the router with every planned path and the closest task profile.
3. Read **every required slice** returned by the router. A heading list or a
   summary is not a substitute for the source slice.
4. Keep the generated `reading-receipt.json` with the work-unit evidence or
   reproduce its `pair_key`, `reading_map_sha256`, routes, selectors, and
   `receipt_sha256` in the handoff/PR.
5. If the changed-path set, owner, external effect, or causal scope expands,
   rerun the router and read the newly added slices before continuing.

An unmapped path or task is an error. Do not guess a nearby chapter and do not
silently use the full books. Add an explicit route to
[`reading-map.toml`](./reading-map.toml), or use `--allow-fallback` only as a
visible temporary fallback and record that fact in the receipt.

## Commands

Validate pair identity, every configured selector, and lossless reconstruction:

```powershell
python scripts/docs_router.py check
```

Resolve a minimal reading set without copying the books:

```powershell
python scripts/docs_router.py route `
  --task kernel `
  --path bins/eliot-kernel/src/control_plane.rs `
  --path crates/kernel/eliot-platform/src/handle_nonce.rs `
  --write-receipt .eliot/reading/kernel.json
```

Print the exact selected source text for direct reading:

```powershell
python scripts/docs_router.py route `
  --task kernel `
  --path bins/eliot-kernel/src/control_plane.rs `
  --content
```

Materialize only the selected slices as separate Markdown files:

```powershell
python scripts/docs_router.py materialize `
  --task kernel `
  --path bins/eliot-kernel/src/control_plane.rs `
  --output .eliot-docs/current
```

Materialize the complete lossless semantic split of both accepted books:

```powershell
python scripts/docs_router.py materialize `
  --all `
  --output .eliot-docs/all
```

The complete materialization writes a manifest and independently reconstructs
each canonical file from ordered blocks. It fails unless reconstructed bytes and
SHA-256 match the accepted source exactly.

## Selection model

The router combines four kinds of information:

| Input | Effect |
|---|---|
| Base reading floor | Small authority/support-status set required for all work |
| Changed repository paths | Select the highest-priority matching owner route for each path |
| Task profile | Add the route needed for the work's causal purpose |
| Optional expansion | Add adjacent contracts only when the current decision requires them |

Route output is a union. Overlapping source ranges are coalesced so an agent does
not reread the same bytes. Exact source handles and slice hashes remain in the
receipt.

Section selectors use stable handles, not line numbers:

- `A12.3` — one exact section subtree;
- `I14` — a complete top-level section subtree;
- `I14..I16` — a contiguous inclusive range.

Line ranges in receipts are diagnostic only. The handle and source digest are
the stable identity.

## Required handoff evidence

A completed agent work unit states:

```text
Normative pair:
Reading-map SHA-256:
Matched routes:
Required selectors read:
Reading receipt SHA-256:
Scope expanded after initial routing: yes/no
```

A work unit is not ready for integration when:

- a changed path was omitted from routing;
- the receipt belongs to another normative-pair or reading-map digest;
- a required selector was not read;
- an unknown path was ignored;
- the implementation scope expanded without rerouting;
- a summary, generated index, donor document, or stale prompt was treated as
  normative source text.

## Editing the documentation system

Changes to the canonical pair still follow
[`../ARCHITECTURE_CONTRACT.md`](../ARCHITECTURE_CONTRACT.md). The router,
reading map, indexes, and generated slices are projections; they cannot alter
normative meaning.

Any change to `reading-map.toml`, this protocol, the router, or a documentation
index must run:

```powershell
python scripts/docs_router.py check
python scripts/check_docs_links.py
```

The canonical paths remain valid for existing code comments, ADRs, external
bookmarks, and section links. New agent instructions should point here or to the
router rather than telling an agent to load either complete book.
