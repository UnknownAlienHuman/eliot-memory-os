## I2.8. Package metadata, source ownership and generated registry

A separate `OWNER.toml` for every small crate creates file ceremony. Derivable source and build metadata lives in `Cargo.toml`; causal and lifecycle ownership remains with `FunctionalCapabilityCell` and Module or service contracts.

```toml
[package.metadata.eliot]
layer = "C1"
purpose = "bounded responsibility statement"
source_maintenance_owner = "source-owner-id"
functional_cell_refs = ["cell-id"]
independent_proof_profile = "crate-fast"
contract_refs = ["..."]
component_contract_ref = "" # only when a real multi-contour component exists
```

`CrateRegistry` is generated from `cargo metadata`, source annotations, the contract catalogue, test inventory, and runtime manifests:

```text
crate identity and version;
layer and dependency rules;
source-maintenance owner and current WorkLease holder;
FunctionalCapabilityCell references and their separate lifecycle owners;
public contract digest;
source/context footprint;
reverse dependencies and fan-out;
build/test profiles and proof ceiling;
runtime bundle/module-generation mappings derived from referenced cell/runtime manifests;
hot-path participation derived per cell;
current conformance evidence.
```

`state_class`, `effect_class`, failure and replacement boundaries, and runtime authority are not inferred from package name or source owner: they belong to referenced functional cells and Module manifests. A private Rust module receives no separate manifest. A transient agent editing a crate receives a WorkLease and becomes neither source owner nor lifecycle owner.

