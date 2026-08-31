# `eliot-app` migration-facade instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from origin/main`
for the complete branch delta, including deletions. Open the verified bundle and
read every required item before mutation. A route alone is navigation, not
reading evidence.

Record the route receipt ID, read receipt ID, required handles/fragments and
hashes, verified bundle SHA-256, and explicit reading attestation. Optional
fragments are loaded only when the current decision crosses their boundary. A
legacy `ELIOT_*` compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale/missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Status

`crates/eliot-app` and its `eliot-governor` binary are a **legacy migration and
regression facade**. They are workspace members so current consumers and
historical paths can be reproduced, extracted, and removed safely. They are not
the current production Governor composition root and are not root
`default-members`.

Current owners and surfaces:

- canonical operator CLI: `bins/eliot` + `crates/surfaces/eliot-cli`;
- semantic application daemon: `bins/eliotd` + `crates/governor/*`;
- failure-surviving authority/fencing/recovery: `bins/eliot-kernel` +
  `crates/kernel/*`;
- agent/MCP surfaces: `bins/eliot-agent-bridge` and `crates/surfaces/*`;
- store execution: the closed store bridge and storage crates.

The existence of an `eliot-governor` command group, test, or old caller does not
create current ownership or justify adding a feature here.

## Allowed work

A change in this directory requires an open issue that proves the current path
still terminates here and falls into one of these classes:

1. reproduce or repair an exact current regression owned by #7, #8, or #9;
2. extract behavior to its declared current owner under #18 and bind the cell
   and proof through #13;
3. maintain a compatibility fixture required by a current named consumer;
4. remove migrated or unreferenced legacy behavior.

Every allowed patch states the target owner, current consumer, old-path
discriminator, affected edge proof, and removal/migration consequence.

## Forbidden work

Do not add:

- a new task, WorkScope, memory, policy, finish, coordination, scheduling,
  Module Catalog, storage, recovery, provider, or runtime owner;
- a new canonical CLI or public command simply because this binary already has
  a command tree;
- direct canonical-store authority, raw vendor queries, or a second write path;
- new Dreamer/Watchdog/Doctor authority or product semantics;
- a dependency or state cache whose only purpose is to keep the facade alive;
- a broad unrelated repair while touching a regression path.

Do not rename a legacy local PASS into current product support. Package tests
prove only the exact facade behavior they execute.

## Proof and stop condition

Minimum result:

```yaml
owning_issue:
current_caller_and_path:
target_current_owner:
old_path_discriminator:
changed_legacy_surface:
module_or_fixture_proof:
affected_edge_proof:
product_pulse_or_not_applicable_reason:
removal_or_remaining_migration:
residual_unknowns:
```

Stop and return a Contract Challenge when the current caller cannot be proven,
the requested feature belongs to a current crate/binary, or the patch would make
`eliot-app` a second authority owner. The facade is retired when all current
consumers and regression fixtures have migrated or been removed.
