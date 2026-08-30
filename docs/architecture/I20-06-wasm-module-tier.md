## I20.6. WASM module tier

The current portable component baseline is defined in I14.19. Evolution follows compatibility evidence rather than ecosystem fashion.

```text
current production candidate:
  Wasmtime Component Model + `wasm32-wasip2` + versioned WIT;

laboratory lane:
  WASI 0.3 / `wasm32-wasip3`, async functions, streams and futures;

possible future:
  another component runtime satisfying the same WIT/capability/conformance contract.
```

A runtime change requires:

```text
same component conformance and differential corpus;
Windows startup/latency/RSS/cancellation measurements;
AOT/cache compatibility proof;
state migration and rollback rehearsal;
capability-denial/security tests;
shadow/canary GenerationCutover.
```

The component boundary remains replaceable. Wasmtime types never leak into domain/core crates or canonical records.

