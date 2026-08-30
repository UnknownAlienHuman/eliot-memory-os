## I18.3. Impact graph and selection

`eliot dev` / Instrument Profile Resolver builds the affected graph from:

```text
Git diff and candidate identity;
Cargo package/target/feature/resolve graph;
crate groups, CrateContextProfile and CrateBuildProfile;
MicroModule and OWNER manifests;
public contract/schema dependencies;
process/module manifests;
state/schema/migration/effect markers;
Architecture/Implementation anchors;
latest code-intelligence evidence;
behavioral co-change and historical failures as widening hints.
```

Selection is conservative:

```text
exact known dependencies select mandatory checks;
heuristic/historical edges may widen checks;
stale, incomplete or missing graph never proves non-impact;
unknown impact becomes an explicit plan gap or broader tier;
Human/Main Agent may widen freely;
narrowing a mandatory group requires scoped evidence/deviation.
```

The resulting `ChangeImpactPlan` is stored with reasons for every selected and omitted profile. Its selection-evidence block records:

```text
selector and comparator kind/version;
test/package/binary/feature/configuration granularity;
discovered, selected, reference and actually executed sets;
omitted and extra selections against actual failure/fault outcomes;
stable failure, flaky, infrastructure, parser and unknown labels;
de-flake/retry policy and reference/full-run sampling probability;
selection rate, failed-test/fault recall, set disagreement and uncertainty;
offline analysis, online selection and execution overhead separately.
```

Selected-set agreement with another selector is not safety. A selector may accelerate local feedback, but it never replaces an independent release proof or a sampled/full reference run.

