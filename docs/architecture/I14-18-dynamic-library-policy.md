## I14.18. Dynamic library policy

Rust dynamic libraries are NOT the production plugin ABI because Rust ABI is unstable and unload safety is weak.

Allowed:

```text
platform DLLs behind audited FFI bridge;
third-party DLL loaded inside disposable process module;
optional future C-ABI component with explicit ownership and no Rust types.
```

Primary hot replacement uses processes.

