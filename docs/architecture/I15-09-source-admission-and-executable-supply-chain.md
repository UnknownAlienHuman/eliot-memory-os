## I15.9. Source admission and executable supply chain

### Source admission before materialization

Root registration is necessary but not sufficient. Every file/object membership is evaluated before materialization, indexing or model disclosure under one contract compiled from the System Owner baseline and applicable WorkScope Owner/Human-policy narrowing; providers enforce it but do not own or widen it.

```yaml
SourceAdmissionPolicy:
  policy_revision_and_owner:
  admitted_roots_and_final-handle_escape_policy:
  denied_system_locations_and_file_format_classes:
  credential_private_key_and_token_detector_profiles:
  generated_vendor_archive_binary_policy:
  file_archive_and_materialization_limits:
  sensitivity_classes_and_grant_ceiling:
  explicit_override_authority_scope_and_expiry:
  disclosure_logging_and_index_payload_policy:
```

OS/browser credential stores, private-key locations and known token files are deny-by-default. A symlink/reparse/final-handle escape is checked against the resolved target, not the display path. Sensitive repository material requires explicit compatible policy and grant ceiling. Detection returns only a class, bounded coordinate and reason/receipt; it never copies the secret into logs, indexes, vector payloads, diagnostics or model packets. An override is narrow, expiring and auditable and cannot silently widen inference/client disclosure.

### Executable module supply chain

Production artifact requires:

```text
source commit/repository;
Cargo.lock/build toolchain;
license report;
SBOM;
artifact hash/signature;
module manifest;
test/canary receipts;
known vulnerabilities/exceptions;
owner and rollback.
```

Use `cargo deny` or equivalent for license/advisory/source checks. New dependency requires owner/removal boundary.

Default license policy:

```text
permissive licenses (MIT, Apache-2.0, BSD, ISC, Zlib, CC0)
→ ordinary dependency review;

weak copyleft / file-level obligations
→ explicit compatibility review and containment;

AGPL, SSPL, BUSL or BSL, source-available, or another restrictive license
→ is not linked into Kernel or daemon as a library without a separate decision;
→ a separate process bridge is preferred only as engineering isolation,
  but is not treated as a license exemption;
→ redistribution, packaging, hosted use, and network-service obligations receive
  separate legal and license review;
→ replacement and export path and user restrictions are recorded.
```

SurrealDB is an explicit temporary source-available exception, isolated behind the storage bridge and mandatory ECXF export path. The exception does not extend automatically to other dependencies.

