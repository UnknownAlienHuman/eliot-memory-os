## I5.27. Canonical operation identity and effect identity

Idempotency is defined over canonical bytes, not over caller spelling or an unversioned hash.

```yaml
CanonicalOperationIdentity:
  installation_id:
  domain_separator:
  idempotency_namespace:
  canonical_encoding_version:
  canonical_request_hash:
  semantic_command_kind:
  principal_and_scope:
  operation_id:
  retention_and_collision_window:
```

Canonical encoding is deterministic and versioned; fields affecting authority, scope, ordering, privacy or effect cannot be omitted/defaulted silently. Reusing an idempotency key with a different canonical request hash returns `IDENTITY_CONFLICT` and performs no transition.

Database idempotency and external-effect idempotency remain separate. An external effect has its own effect identity, provider capability statement and reconciliation state; a committed canonical intent never proves that the effect occurred exactly once.

