# Kernel Store Gateway extraction — CrateExtractionDecision v1

Authority: `swarm/decisions/ROOT-DIRECTIVE-v1.5.md` SHA-256
`53A950CC13546A85462AF075645E7619FEC303B3AF05C1DE1608AEEF45BF47C2`.

Normative basis: ELIOT Implementation I1.2 §2, I2.2, I2.16 and I2.23.

```yaml
CrateExtractionDecision:
  affected_functional_cells_and_lifecycle_owners: >-
    Kernel canonical transition gateway and connection-to-store-bridge ownership;
    Kernel service lifecycle owner P-07. No Governor semantic owner moves.
  current_source_dependency_and_change_closure: >-
    bins/eliot-kernel/src/lib.rs GatewayFlight, GatewayFlightState,
    GatewayFlightGuard and KernelStoreGateway; their direct synchronization,
    admission, coordinator, EBP client and neutral Store API dependencies; the
    existing Kernel composition construction and gateway tests are consumers.
  proposed_package_boundary: >-
    Move the gateway implementation to the existing
    crates/kernel/eliot-kernel-service package as store_gateway; keep only
    composition, construction and a compatibility re-export in eliot-kernel.
  public_contract_and_independent_test_entrypoint: >-
    eliot_kernel_service::KernelStoreGateway with the existing typed methods and
    cargo test --locked -p eliot-kernel-service --all-targets; preserve
    eliot_kernel::KernelStoreGateway through a temporary public re-export.
  first_real_consumer_or_time_bounded_migration_facade: >-
    bins/eliot-kernel is the immediate production consumer; its compatibility
    re-export expires when downstream references use eliot-kernel-service
    directly or a later accepted API revision removes it.
  source_maintenance_owner_and_vendor_type_boundary: >-
    Kernel service lifecycle maintainers own the implementation. Public method
    signatures use existing ELIOT Kernel/Store types; no vendor SDK type crosses
    the boundary.
  dependency_security_license_and_build_isolation: >-
    Use only dependencies already admitted by eliot-kernel-service. No new
    dependency, feature, license, unsafe boundary, service, or provider is added.
  expected_agent_workset_context_and_reverse_fanout_delta: >-
    Remove one self-contained synchronization/gateway block from the 15k-line
    binary composition file. Reverse fan-out remains one production consumer
    plus tests; the moved code gains a package-local proof surface.
  expected_compile_test_integration_and_release_cost_delta: >-
    Small incremental compile/test movement from eliot-kernel to the already
    required eliot-kernel-service package; no new release artifact or runtime
    process. Both focused packages remain mandatory gates.
  migration_reexport_rollback_removal_and_expiry: >-
    Keep an eliot-kernel public re-export during migration. Rollback is the exact
    inverse source move with no persisted-state migration. Remove the re-export
    only through a separately reviewed public API change.
  counter_risks_merge_or_rejoin_condition: >-
    Rejoin or keep the block in the composition module if extraction requires a
    Kernel-to-Governor dependency, duplicates ORS/store semantics, introduces a
    dependency cycle, or cannot retain exact fencing and replacement behavior.
  evidence_status_and_review_owner: >-
    Root source/Cargo-metadata preflight plus GPT Luna implementation and focused
    compiler/clippy evidence. The existing focused test is retained with the
    moved private implementation but is not executed by current user direction;
    Root owns final review and acceptance.
  disposition: split
```

Proof ceiling: this decision authorizes only the existing neutral Store gateway
implementation move. It does not authorize Governor owner decoding, WorkScope,
session/task/current-plan recovery, a new crate, or a claim that Kernel recovery
routing is complete.
