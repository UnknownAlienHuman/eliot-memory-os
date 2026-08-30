## I2.14. Cargo feature, dependency, codegen, and cache hygiene

Many crates accelerate development only under a disciplined graph.

### Feature policy

```text
a workspace-wide `full` feature is prohibited without measured justification;
Tokio features are selected per crate;
vendor SDK features terminate at bridge implementation;
platform, storage, and provider feature sets do not leak into domain crates;
default features are disabled when they pull unused runtimes, TLS, or storage;
a feature flag does not silently change authority or semantic meaning.
```

### Expensive-unit isolation

The following are isolated separately:

```text
proc-macro crates;
build-script-heavy crates;
generated code;
FFI/native linking;
large generic/codegen-heavy algorithms;
heavy dev/test dependencies;
nightly/fuzz/mutation crates.
```

Proc-macro, binary, and linker-invoking crates are not treated as ordinary cacheable units. A binary wrapper remains thin.

### Generic boundaries

A generic-heavy public API may shift monomorphization into every consumer. Therefore:

```text
a generic algorithm stays in a leaf or core crate where practical;
a contract hub exports concrete data and narrow traits;
`dyn` or erasure is allowed at a cold or replaceable boundary after measurement;
`#[inline]` and LTO are not doctrine;
compile-time and runtime trade-offs are measured.
```

### Dependency diagnostics

Every dependency-changing unit runs:

```text
`cargo tree -d`;
`cargo tree -e features` for affected packages;
license/advisory/source review;
compile-time and binary-size delta;
removal-boundary check;
feature-set stability check.
```

### Workspace-hack / cargo-hakari

`workspace-hack` is not a day-one Default. It is allowed after a Research Gate when BuildTimings or BuildFingerprints show repeated compilation of common dependencies because of divergent feature sets. Promotion requires measured Windows improvement, a generated manifest, a verification step, and a removal path.

