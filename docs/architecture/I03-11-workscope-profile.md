## I3.11. WorkScope Profile

The old `ProjectProfile` semantics are retained as `WorkScopeProfile`:

```yaml
WorkScopeProfile:
  scope_id:
  roots_and_resources:
  scope_kind:
  owners:
  truth_surfaces:
  adapters_and_verifiers:
  manifests_and_load_order:
  protected_and_generated_paths:
  network_and_tool_policy:
  model/privacy/cost_policy:
  cue_and_graph_rules:
  retention_and_backup_policy:
  compatibility_requirements:
```

A profile describes available surfaces and policy; it does not assert that an adapter is healthy or a claim is true.

