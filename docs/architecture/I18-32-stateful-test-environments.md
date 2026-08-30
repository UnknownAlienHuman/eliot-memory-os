## I18.32. Stateful test environments

Tests that start databases, services, browsers, ports, user-session tools or other mutable resources receive a `TestEnvironmentLease`, implemented as a testing specialization/view of the existing `ExecutionEnvironmentLease` rather than a second lease owner or table:

```yaml
TestEnvironmentLease:
  environment_id:
  candidate_and_profile_ref:
  owner_and_epoch:
  isolated_paths_and_data_roots:
  namespaces_databases_ports_profiles:
  credential_refs:
  process_job_ref:
  resource_limits:
  serial_or_conflict_group:
  cleanup_and_residue_verifier:
  expiry:
```

Rules:

```text
production data roots, credentials and user profiles are denied by default;
every mutable fixture has a unique or explicitly serialized identity;
fixture services start through ProcessExecutor and remain in a Job Object;
base snapshots may be reused read-only; writable overlays are per environment;
test success requires both property evidence and cleanup/residue disposition;
unknown external effect or failed cleanup quarantines the environment and opens Problem State;
parallel tests sharing a declared resource use one serial/conflict group rather than racing;
stateful isolation is observed, not asserted by a synthetic report.
```

The lease is a testing/resource boundary, not project authority. It cannot grant access to canonical production state or make a test result applicable outside its exact environment.

