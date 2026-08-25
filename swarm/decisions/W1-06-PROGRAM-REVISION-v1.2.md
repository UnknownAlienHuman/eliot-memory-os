# W1-06 program revision v1.2

Status: `ACCEPTED_EVIDENCE_ONLY`; W2 remains blocked by the aggregate W0 gate
and by any still-unaccepted W1 inventory.

Owner: Root/Sol.

Source revision: `1122e21b081a82a6a335c53f018e9ae60846cdd5` plus the current recovery
worktree.

## Trigger

The W1-06 kill condition fired normally. Independent source audits falsified
two of the three original premises:

| Original premise | Disposition | Bounded evidence |
|---|---|---|
| The named contours are not connected | `UNKNOWN` broadly; `NOT_FALSIFIED` for direct Cargo edges | zero A-to-B and B-to-A direct Cargo edges; runtime/process/IPC edges require the W1-05 census |
| All 132 E2E tests are disabled | `FALSE` | unignored full-stack/UL tests execute under `cargo test --workspace`; the current generator's 331/82/249 split is heuristic evidence, not a normative denominator |
| The signed set contains no executable product | `FALSE` | seven Authenticode PE roles; materializer role set is six executables plus three JSON files |

Primary independent sessions:

- `ses_fccbf4de9ffeL1cpHpKbkslv59` — fresh OpenRouter W1-06-B source-only lane;
- `ses_fcc616fb4ffeufOS6MRXnDYfDk` — separate OpenRouter current-source
  falsification of original and revised premises.

## Revised premises

The generated oracle at `swarm/inventory/w1-06-premises.json` measures:

- `C1` exact Authenticode membership: `TRUE` from static role-table evidence;
- `C2` exact ordered materializer membership: `TRUE` from static role-table
  evidence;
- `C3` production launch reachability: `UNKNOWN`; a static suspended-process
  chain is not a runtime receipt;
- `C4` Governor constitutive authority: `TRUE` in Cargo/source composition,
  without claiming an observed canonical transition.

The generator also retains A1-A3 as historical falsification records. Verdicts
are derived from explicit predicates and the independent verifier rejects a
hard-coded `TRUE` tamper.

## Decision

The local task copy is revised to v1.2. C3's `UNKNOWN` is an input to W2: W2 is
the experiment intended to produce or falsify runtime reachability. Requiring
that receipt before W2 would make the proof circular.

This decision does not:

- claim W0 or W1 complete;
- treat signed bytes as a functional product;
- treat static Governor ownership as a live `commit_canonical` call;
- choose the W3 cutover;
- authorize canonical write authority or product completion.

## Recheck and rollback

Recheck when the signing role table, materializer role table, production launch
script, Governor composition, default workspace test gate, or named contour
sets change. Rollback means block W2, regenerate the original and revised
premise inventories from the new source, and issue a new program revision; it
never means restoring either falsified premise as an assumption.
