## I19.8. Hook/plugin migration

```text
inventory duplicates;
install one active bridge profile;
disable old direct Surreal/MCP paths;
verify runtime events, not config only;
publish one immutable `ReleaseSurfaceManifest` binding source/commit, generated plugin/Skills/schemas,
  installed cache/config/registration, bridge/binary hashes, hooks, route profiles and active runtime generation;
make Doctor fail on missing surface, digest mismatch or semantic drift between those identities;
keep rollback copy;
watch for old process/config reappearance.
```

```yaml
ReleaseSurfaceManifest:
  product_and_source_identity:
  architecture_and_implementation_digests:
  generated_schema_plugin_skill_hook_and_prompt_digests:
  installed_cache_config_registration_and_bridge_digests:
  executable_package_route_and_module_generation_digests:
  active_service_process_store_and_user_broker_fingerprints:
  capability_and_Governance_Profile_refs:
  migration_and_rollback_refs:
  invalidation_and_expiry:
  release_receipt_and_signing_identity:
```

The manifest is immutable for one installed release. A source-compatible but byte-different installed surface is a different Product Identity. Doctor compares exact fields and reports `MISSING`, `MISMATCH`, `STALE` or `UNKNOWN`; it does not rewrite the manifest to match the observed installation.

