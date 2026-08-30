## I0.12. Prototype and execution-contour policy

ELIOT is crate-rich, process-sparse, and owner-sparse. Source decomposition, execution isolation, and deployment lifecycle are separate decisions.

Current execution defaults:

```text
pure bounded experimental logic
  → capability-limited component contour (currently WASM Component Model);

OS/Cargo/Git/LSP/browser/native-library/credential-heavy logic
  → isolated native process generation;

measured trusted hot path
  → static native release generation only after evidence.
```

For the default no-authority component contour, `PrototypeContourDecision` is generated automatically from the Module contract and manifest. Manual rationale is mandatory only when a prototype:

```text
selects a non-default contour;
receives credentials, authority, or external effects;
enters canary or active traffic;
changes state, migration, or recovery semantics;
claims static-native promotion.
```

Promotion remains generational:

```text
contract/conformance
→ replay
→ effect-free shadow
→ bounded canary
→ ORS cutover and new epoch
→ drain / forward rollback.
```

Neither WASM, process isolation, nor static linking creates semantic authority. One contour-independent core and conformance corpus test equivalence across admissible backends.

