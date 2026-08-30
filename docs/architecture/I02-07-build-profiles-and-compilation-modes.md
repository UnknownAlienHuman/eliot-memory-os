## I2.7. Build profiles and compilation modes

ELIOT does not use one Cargo profile for every purpose.

### `dev-local`

```text
incremental = true;
separate target root per worktree or build fingerprint;
package-local `cargo check -p` and focused tests;
fastest possible feedback to the active agent;
`sccache` is not assumed effective while incremental compilation is enabled.
```

### `dev-shared`

```text
incremental = false;
`sccache` MAY be used through ProcessExecutor;
content-addressed BuildFingerprint;
suitable for repeated builds across worktrees or agents;
is not proof without an actual test or verifier run.
```

### `edge`

```text
real adapter/process/store/protocol boundary;
separate fixture namespace and resource lease;
codegen and linking errors are checked by a real build, not only `cargo check`.
```

### `product-pulse`

```text
actual front door;
accepted owner path;
minimum real artifact or effect;
bounded frequency;
may run on a candidate generation beside the live stable generation.
```

### `release`

```text
locked dependencies;
reproducible manifest/SBOM/license inputs;
clean or declared cache state;
all required workspaces/profiles;
full release proof.
```

### Rules

```text
`cargo check` provides a fast Shape or Module signal, but does not prove codegen, linking, or runtime;
`cargo build --timings` regularly measures compiler units, critical path, and parallelism;
profile identity belongs to BuildFingerprint;
a result from one profile is not renamed as proof for another;
a cache hit accelerates compilation but transfers no test verdict.
```

Release binaries are built from thin binary crates; substantial logic lives in library crates. This improves independently cached and tested source units and prevents a binary crate from becoming an integration monolith.

