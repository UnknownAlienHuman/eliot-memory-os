## I2.1. Primary decision: crate-rich, process-sparse, owner-sparse

ELIOT uses **many small crates** as the normal unit of build, package-selective testing, dependency containment, and agent context. A crate may have a source-maintenance owner, but creates no lifecycle, mutable-state, or authority owner by itself; those owners belong to the `FunctionalCapabilityCell` or service contract and may span several crates.

Restricting the system to a few large crates is incorrect. Cargo workspaces select packages through `-p`, `--workspace`, and `default-members`, compile independent units in parallel, and reuse metadata and incremental artifacts. The practical limit is determined not by the number of lines in `[workspace].members`, but by dependency-graph quality, feature sets, proc macros and build scripts, linker load, test binaries, ownership, and agent context.

Target formula:

```text
many source and build crates
+ substantially fewer runtime bundles and processes
+ one owner for each mutable state
+ one canonical semantic path.
```

A crate is not a microservice and does not create IPC by itself. Dozens of crates may be statically linked into one fast `eliotd.exe`. A process boundary appears only for a separate failure, resource, credential, or update boundary.

### Three independent quantities

```text
crate count
  compile/test/context granularity;

runtime bundle count
  independently released set of crates;

process count
  independently crashable, supervised and hot-replaceable runtime generations.
```

They must not be conflated.

### Four levels of modularity

```text
Rust module
  minimum source navigation within one owner;

Cargo crate
  independently selectable build/test/context/contract boundary;

runtime bundle / process generation
  independently supervised, fenced and hot-replaceable executable boundary;

deployment/service unit
  OS installation, activation, upgrade and rollback boundary.
```

Moving to the next level requires separate justification. A good Rust module need not become a crate; a good crate need not become a process; a process need not become a permanently running service.

### Migration baseline

The five current source owners remain migration facades, not permanent target structure:

```text
eliot-types
eliot-engine
eliot-store
eliot-windows-ipc
eliot-app
```

A new capability first receives an ELIOT-owned contract and test seam. Code is then extracted into a separate crate without a big-bang rewrite. The old crate temporarily re-exports the new contract or invokes the new service until callers migrate.

The previous donor decision of “four or five large crates” is retained only as a map of initial responsibility owners and migration facades. As target physical source topology, it is superseded by this crate-rich strategy: large responsibility domains remain, but split into independently selectable contract, core, service, and adapter crates.

Do not create parallel:

```text
task graph;
attempt journal;
provider reservation system;
canonical memory;
agent database;
finish authority;
recovery path.
```

Micro-modularity changes physical packaging, but does not multiply semantic owners.

### Workspace capacity is measured, not planned by crate count

Implementation does not assign a crate-count band to a Delivery Depth. Such bands are an easily optimized proxy: an agent can create packages that satisfy a table while making contracts, compilation and coordination worse. A crate appears only after `CrateExtractionDecision` proves a real build/test/context/dependency seam; it disappears or merges when that seam is false.

Workspace capacity is demonstrated by measurements on the actual graph and representative synthetic stress profiles:

```text
Cargo metadata and package-selection latency;
incremental and clean critical paths;
reverse-dependency fan-out;
rust-analyzer/index load;
test discovery/sharding cost;
cache/target contention under parallel agents;
manifest/contract orientation burden;
typical changed-closure size and Product Pulse outcome.
```

Delivery Depth names capability families, not package counts. The same depth may be implemented with fewer larger crates or more smaller crates when the causal/test seams and measured agent outcomes justify it. `RGF-CRATE-BUILD` owns fleet-scale experiments; its result may tune tooling profiles but never becomes a quota to fill.

### Performance model

A many-crate layout provides:

```text
a smaller invalidation unit for private changes;
more independent `rustc` jobs and package-selective commands;
a smaller agent source and context workset;
separated vendor and feature dependencies;
a smaller merge, test, and ownership blast radius.
```

Costs:

```text
fixed `rustc` and metadata overhead per crate;
more incremental artifacts and rust-analyzer crate nodes;
a public API change rebuilds its reverse closure;
generic or monomorphized code may compile in consumers;
overly small crates create manifest, glue, and context fragmentation;
a shared target root may become a lock or I/O bottleneck;
a proc-macro or build-script dependency multiplies compile cost across fan-out.
```

The optimum is not the maximum crate count, but the smallest typical change closure with acceptable fixed overhead. I2.16, I2.23, and CrateBuildProfile measure both sides.

