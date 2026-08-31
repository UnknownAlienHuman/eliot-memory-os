# Runtime composition-root instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. Open the
verified bundle and read every required item before mutation. A route alone is
navigation, not reading evidence.

Record the route receipt ID, read receipt ID, matched routes, required handles,
fragment paths and SHA-256 values, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale or missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`../docs/architecture/READING_PROTOCOL.md`](../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


`bins/*` wires admitted capability cells into processes. A binary name does not
create lifecycle, state, semantic, canonical-store, repair, provider or
authority ownership.

## Mandatory rules

- Start from current `main`, one open issue, one issue-numbered branch, one
  mutable path owner, and one PR.
- Read the owning subtree `AGENTS.md`, the executable's Cargo manifest, and its
  issue before changing the composition root.
- Keep `main.rs` and adjacent composition modules limited to argument/config
  decoding, authenticated contract construction, dependency wiring, service or
  one-shot lifecycle, typed shutdown, and terminal receipt/status projection.
- Put deterministic state machines, durable state, vendor adapters, protocol
  semantics, process mechanics, and reusable proof fixtures in their declared
  first-party owner crates.
- Do not infer process ownership from PID, name, path, port, current directory,
  environment variables, or a successful exit.
- Direct native-process launch in a runtime root is forbidden unless the exact
  file is recorded as temporary debt in `config/architecture-boundaries.toml`.
  Debt is unresolved work, not permission to expand the pattern.
- No production `todo!` or `unimplemented!`.
- Do not add task, memory, policy, finish, scheduling, canonical write, store,
  Dreamer, provider, credential, or repair semantics to a composition binary.

## Runtime roots and owners

| Root | Current owner/work item |
|---|---|
| `eliot-host` | Host lifecycle and journal boundary, #14 |
| `eliot-kernel` | fencing, ORS, reserve and generation routing, #15 |
| `eliotd` | semantic Governor application owner, #18 |
| `eliot-watchdog` | independent supervision, #16 |
| `eliot-doctor` | one-shot bounded repair, #17 |
| `eliot-store-surreal` | closed store bridge; external DB generation remains separate, #19 |
| `eliot-testd` | typed Instrument execution only, #20 |
| `eliot-wasm-host` | capability-limited component mechanics, #21 |
| `eliot-native-worker` | isolated native generation, #22 |
| `eliot-user-broker` | SID/session-bound launch and resources, #23 |
| `eliot-mod-research` | governed provider acquisition; candidate-only output, #24 |
| `eliot-notify`, `eliot-agent-bridge` | thin stateless/near-stateless surfaces, #13 |
| `eliot` | current operator CLI and installation/runtime-status front door; live proof #11 |

`eliot-governor` under `crates/eliot-app` is a legacy migration/regression
facade, not a current composition root. Follow its local instructions.

## Proof and stop condition

A composition change requires a package-local wiring/negative proof and the
real affected process/protocol/store edge. Use #11 when the installed
operational spine can change. Stop and return a Contract Challenge when the
requested behavior needs a new owner, broadens authority/effects, or cannot be
implemented without duplicating a state machine already owned elsewhere.
