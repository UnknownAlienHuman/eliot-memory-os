# `eliot-cues` package instructions

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
