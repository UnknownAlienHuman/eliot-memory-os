### I10.8.16. IP8 — component build and generation promotion service

Component build is an Instrument profile family, not a second deployment authority.

```text
source/worktree candidate
→ build native core tests
→ compile `wasm32-wasip2` Component
→ inspect WIT/interface digest and imports
→ run common conformance/differential corpus
→ recorded deterministic replay
→ publish immutable GenerationManifest
→ shadow comparison
→ canary under Governor policy
→ ORS route cutover / Authority Epoch
→ rollback by forward route switch when required.
```

The builder signs or hashes the artifact set, records toolchain/lockfile/dependency provenance and returns a `GenerationCandidateReceipt`. It cannot activate a generation. Activation is a Kernel/Governor operation under I14.19 and I14.20.

WASI 0.3/`wasm32-wasip3`, AOT strategy, pooling and native promotion are separate empirical profiles. The production baseline remains `wasm32-wasip2` until the same corpus passes on Windows with the exact pinned Wasmtime generation.


