## I17.3. Canonical Product Identity

A release/candidate identity binds:

```text
source commit and dirty-state hash;
lockfile/toolchain and generated schemas;
binary/package hashes and service/module manifests;
config/policy/credential-profile hashes;
DB schema/migration and canonical revision;
active Host/Kernel/daemon/store/module generations and epochs;
plugin/Skill/hook/adapter hashes;
verifier/test manifest and environment;
installation receipts and invalidation conditions.
```

There is one accepted identity. Branch, worktree, installed runtime, DB state and reports may differ as observations, but cannot all claim to be current. Every status/report/result carries the identity it observed. Dependency change invalidates the corresponding claim automatically.

