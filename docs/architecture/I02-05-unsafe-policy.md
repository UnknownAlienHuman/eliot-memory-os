## I2.5. `unsafe` policy

`unsafe` is allowed only in explicitly listed crates:

```text
eliot-platform-windows;
eliot-platform-unix;
when necessary, a separate audited FFI bridge.
```

Every unsafe block has a `// SAFETY:` rationale, local invariant test, and owning reviewer. Domain, contract, and Kernel pure-core crates use `#![forbid(unsafe_code)]`.

