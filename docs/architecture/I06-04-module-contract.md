## I6.4. Module contract

Every hot module ships immutable `module.toml`:

```toml
module_id = "codegraph.git"
version = "0.1.0"
artifact_hash = "blake3:..."
protocol = ["ebp.module.v1"]
architecture = ["ARCH-GROUND-01", "ARCH-MOD-02"]
capabilities = ["codegraph.query", "codegraph.refresh"]
required_capabilities = ["filesystem.read", "git.read"]
optional_capabilities = ["lsp.symbols"]
advisory_capabilities = ["behavioral_graph.read"]
startup_after = ["filesystem.read", "git.read"]
drain_before = ["filesystem.read", "git.read"]
invalidation_triggers = ["git.head", "git.dirty", "module.config"]
state_owner = "module-derived"
failure_domain = "process:codegraph.git"
hot_replace = true
supervision_plan = "one_for_one"
child_restart = "transient"
restart_intensity = "3/10m"
resource_profile = "background-medium"
privacy_classes = ["project_code"]
permissions = ["read:scope_root"]
health_contract = "health/codegraph-v1"
checkpoint_contract = "checkpoint/derived-v1"
compatibility_state = "rebuildable"
independent_test_profile = "module/codegraph-git"
contract_fixture_set = "ebp.module.v1/codegraph.query"
affected_test_tags = ["codegraph", "git", "process"]
```

Module contract MUST declare:

```text
owner;
inputs/outputs;
owned mutable/derived state;
authority/effects;
dependencies typed as required, optional or advisory;
startup/drain order and invalidation triggers;
failure domain and protocol range;
eligible supervision strategy, restart-intensity window and cooldown;
health/readiness/freshness;
restart/rebuild/quarantine;
state migration or rebuild path;
telemetry;
independent module/contract/fault test entrypoints;
consumer/provider fixture revisions;
removal boundary.
```

The graph of `required_capabilities` must be acyclic before a generation can reach `READY`. Optional/advisory back-references may carry observations or hints, but they cannot become mutual liveness prerequisites. Startup follows required dependencies; drain runs in reverse; a missing optional/advisory dependency is expressed as a capability/freshness downgrade, not a deadlock.

