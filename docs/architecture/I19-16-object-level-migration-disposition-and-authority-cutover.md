## I19.16. Object-level migration disposition and authority cutover

Migration is complete only with a bijective-or-explicit-disposition ledger:

```yaml
MigrationDisposition:
  source_object_identity_and_hash:
  source_semantics_and_owner:
  target_object_identity_and_hash:
  disposition: MIGRATED | MERGED | SUPERSEDED | ARCHIVED | REJECTED | UNRESOLVED
  transform_and_verifier_refs:
  provider_memory_or_external_effect_reconciliation:
  rollback_or_no_return_boundary:
  canonical_cutover_receipt:
```

Every active source object has one disposition; every target object identifies its source or declares it new. Shadow/dual-read is comparison only and cannot create two authorities. One cutover receipt selects the new owner; after the no-return boundary, rollback is a forward repair/migration, not resurrection of the old truth. Missing mappings return `MIGRATION_MAPPING_INCOMPLETE` and block retirement only for the affected scope.

