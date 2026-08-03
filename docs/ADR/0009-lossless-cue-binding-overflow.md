# ADR 0009: Lossless cue binding overflow

## Status

Accepted for C7-03C2.

## Context

UL v1.4 says that cue cardinality is bounded. That can be read as a semantic
quota, although the existing limit of 12 bindings applies to one admitted
transport unit. Valuable logical memory may require more searchable or fireable
bindings. Dropping later bindings would make canonical content unreachable and
violate the lossless-memory invariant.

## Decision

`MAX_CUE_BINDINGS_PER_PAGE = 12` is a transport bound, not a logical-memory
quota.

A canonical cue set is handled as follows:

1. Normalize, project-scope, deduplicate, and deterministically order all valid
   bindings before partitioning.
2. Carry no more than 12 bindings inline in one envelope or typed page.
3. Persist every additional binding in ordered `CueBindingPage` records tied
   to the same logical parent handle and content-addressed blob.
4. Bind each page to its ordinal, total page count, deterministic page ID, and
   page-set hash; also bind the manifest to the page count and set hash.
5. Send segments and cue pages through the existing Writer authority before
   admitting the parent manifest.
6. Admit the parent only when the exact segment and cue-page sets are complete,
   contiguous, hash-matching, and transport-bounded.
7. Have the ProjectionCoordinator's cue builder read the complete inline and
   overflow set before publishing a revision for firing.

No valid binding may be silently truncated, sampled, or replaced by ambient
fill. A binding that cannot fit one page is rejected explicitly; canonical
content remains in BlobStore and is referenced by bounded handles rather than
being clipped to fabricate a cue. Packet, pyramid, and firing caps constrain
active views only; canonical bindings remain expandable and rebuildable.

## Consequences

- Legacy records with at most 12 inline bindings remain valid.
- Search and cue firing retain complete deterministic coverage after restart,
  rebuild, retry, and replay.
- Incomplete or mixed-generation child sets cannot make a parent current.
- CanonicalStore, Writer, and ProjectionCoordinator keep their existing
  authority boundaries; no database, index owner, or direct cue mutation path
  is added.
- Storage grows with valuable logical bindings, while each transport and hot
  view remains bounded.

## Acceptance evidence

- Twenty-nine valid bindings partition as 12, 12, and 5 with no loss.
- Every page obeys both the count and encoded-byte limits.
- Parent-last admission rejects missing, surplus, reordered, or hash-mismatched
  pages.
- Cue load, rebuild, publication, and firing consume the complete page set.
