### I10.8.14. Build artifact and evidence reuse

Build artifacts may be reused only by an exact `BuildFingerprint`:

```text
source/candidate identity;
Cargo lock and relevant manifests;
toolchain and executable identity;
features/targets/profile;
environment and build-script inputs;
target/build class;
contract/profile revision.
```

Reuse rules:

```text
cached compilation artifact may avoid recompilation when fingerprint is exact;
cache hit carries provenance and does not create a new compiler observation by itself;
test verdict is not reused merely because the binary is cached;
raw evidence/result may be reused only under its explicit dependency/freshness contract;
unknown build-script/environment input disables authoritative reuse;
cache corruption or identity mismatch deletes/quarantines only the affected entry.
```

Compiler cache is a performance organ, not a truth owner. It can reduce build time without changing Instrument profile semantics.

