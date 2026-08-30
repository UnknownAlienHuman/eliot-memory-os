## I2.22. Parallel build, cache, artifact and environment lanes

Each mutating work item receives:

```text
worktree;
BuildFingerprint;
target/build mode;
fixture namespace;
runtime environment lease;
resource claims;
contract revision;
candidate identity.
```

### Target roots

```text
%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>
```

Governed instruments do not use the repository `target/` directory by default.

### Cache modes

```text
interactive incremental
  separate worktree target; best repeated feedback within one lane;

shared non-incremental + sccache
  reuse across agents and worktrees under an exact normalized fingerprint;

release
  locked and declared cache; proof depends on source, tool, and run identity,
  not on the fact of a cache hit.
```

Incremental compilation and sccache are not enabled together as a universal magic optimization. Instrument Plane measures hit rate, cold and warm time, cache size, and invalidation.

### Derived-cache trust and reuse

Any reuse of a derived cache or artifact is bound to exact dependency closure:

```text
source and generated-input digests;
toolchain/compiler/parser/runtime versions;
configuration, features and environment fingerprint;
producer identity and generation;
cache root identity, owner/ACL and reparse/symlink disposition;
format/schema revision;
content integrity digest;
```

Rules:

```text
checksum detects corruption but does not authenticate producer or root;
missing, unreadable, untrusted or mismatched cache is a cache miss, not a correctness failure;
no correctness path depends on cache availability;
a result derived from one observed subset cannot overwrite a broader valid cache union
unless the cache contract declares replacement semantics;
partial cache load preserves known-good entries and records rejected/corrupt entries;
restore or copy never upgrades cache authority without requalification;
cache hit carries artifact lineage but never reuses an old test/verifier verdict.
```

The cache layer is rebuildable and may improve performance only after equality checks against the uncached reference path.

### Test concurrency

Test groups declare resource weight and exclusive resources. Nextest partitioning and filtersets distribute independent tests across lanes; stateful ports, services, and database volumes receive separate leases. A worktree does not isolate runtime resources.

Verification has priority over background indexing, coverage, mutation, and Dreamer jobs. A background build cannot displace Kernel, Watchdog, Control Reserve, or interactive product work.

