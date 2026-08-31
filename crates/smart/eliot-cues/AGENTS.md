# `eliot-cues` package instructions

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
permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


`eliot-cues` is a stateless projection and activation-contract package. It
owns normalized cue lookup keys, projection-row lifecycle metadata, immutable
snapshots, and deterministic model-free firing. It does not own canonical
memory, understanding, storage, admission policy, or runtime lifecycle.

Keep normalization shared by observation and firing. A key is admissible only
when its scope and normalized value are non-empty and contain no control
characters. Preserve the existing cue kind, match mode, identity, source,
duplicate, freshness, and firing behavior unless an issue explicitly changes
that contract.

Projection lifecycle is local metadata only. Deletion and supersession may
extinguish a non-terminal row; `Extinguished` is terminal, and the existing
archived-to-suppressed restriction remains enforced. Snapshot invalidation
must advance the immutable projection revision strictly.

Do not reactivate historical per-function prototype crates or add a second
state owner. The package proof ceiling is projection integrity. Governor
admission, canonical projection publication, Context consumption, runtime
delivery, and Product Proof belong to their owning issues and consumers.
