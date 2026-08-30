## I2.21. Crate and boundary validation

`eliot dev crate validate` checks:

```text
layer direction and cycles;
public vendor-type leakage;
missing purpose/owner/test selector;
source and Agent Workset budgets;
public contract digest;
FunctionalCapabilityCell coverage and one lifecycle owner per mutable state;
generated EffectiveMicroModuleManifest freshness and catalogue digest;
replacement class, iteration lane and ProofLatencyProfile for automatic scheduling;
reverse-dependency fan-out;
forbidden dependency islands in hot/core crates;
crate-to-runtime-bundle mapping;
state/effect owner uniqueness;
required edge profiles;
zero-test selection;
forbidden direct process/store calls;
Cargo feature duplication and profile drift.
```

Validation returns evidence and a recommendation. It does not declare the Architecture correct merely because the dependency graph is clean.

### `CrateScaleReview`

Review starts on any of:

```text
physical review/high-review band on the applicable profile;
Agent Workset upper review band or absence of a qualified complete envelope;
high compile critical-path cost;
high reverse-dependency fan-out × change frequency;
two independent fixture or test families;
repeated defect escape across the crate boundary;
systematic co-change with a neighboring crate;
the appearance of a second causal responsibility.
```

Outcome:

```text
keep;
split;
merge;
extract contract;
move heavy dependency to adapter/workspace;
create thin facade;
mark migration legacy with expiry;
run experiment before change.
```

