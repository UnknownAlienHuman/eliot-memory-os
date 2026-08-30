## I15.19. Authenticated origin and supply-chain evidence

A content digest proves byte identity, not who produced or authorized it. Origin-sensitive artifacts use an `OriginAuthenticationReceipt`:

```yaml
OriginAuthenticationReceipt:
  artifact_digest:
  producer_principal_or_service:
  producer_generation_and_epoch:
  source_revision_and_build_identity:
  signing_key_or_os_identity_ref:
  signature_or_attestation:
  nonce_or_replay_binding:
  verification_policy_and_result:
  revocation_and_expiry:
```

Local first-party artifacts may use protected Windows service identity plus installation keys; distributed/vendor artifacts may require signed provenance/attestation. SLSA-like metadata is an admissible mechanism, not a universal Architecture mandate. Failure to authenticate origin returns `ORIGIN_AUTHENTICATION_FAILED` for the dependent promotion/effect; sandboxed output remains candidate even when origin is authenticated.

