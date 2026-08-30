## I7.1. Eliot Bridge Protocol (`EBP/1`)

EBP is a stable language-neutral message contract. Transport and encoding are negotiated profiles; neither is allowed to leak into domain records.

First delivery profile:

```text
transport: length-delimited frames over Windows named pipes;
encoding: UTF-8 JSON generated from Serde types;
debugging: the wire payload is directly inspectable and replayable;
large data: immutable Blob/Resource handles, never giant inline frames.
```

This JSON-first choice is deliberate: D0/D1 need a working bridge, simple diagnostics and one schema system more than speculative serialization speed. `protobuf-v1` through `prost` remains an optional encoding profile behind RGF-PROTOCOL-TRANSPORT. It is promoted only if measured local load shows a material latency/CPU/size benefit without creating a second divergent contract. Both encodings MUST pass the same semantic fixtures and compatibility tests.

Named pipes and JSON are current Windows-first Defaults, not security or performance proofs. Transport admission requires the production profile to disclose framing, ACL/authentication, reconnect, contention, crash, message-size and backpressure behavior on the exact Product Identity. A local microbenchmark cannot establish universal superiority, and changing transport/encoding cannot change the semantic contract or proof ceiling.

Reasons for EBP itself:

```text
stable contract across Rust/compiler versions;
independent hot module builds;
streaming, cancellation and server events;
future non-Rust modules without Rust ABI/C-layout coupling;
explicit compatibility, authority and failure semantics.
```

