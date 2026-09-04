# Assignment reservation

Owning issue: #787
Implementation PR: #788
Branch: `fix/787-context-measurement-oracle`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `scripts/audit-context-measurement-ownership.py`, exact script-local fixtures/sidecar when frozen first, and this temporary marker. After #704/#783/#785 integrate, enforce one A-15 schema owner and one F-STU algorithm owner; detect ad hoc ratios, duplicate schemas/estimators, mislabeled units, unqualified fit claims, tokenizer-zero fallbacks and bypassing consumers with a complete fail-closed deterministic denominator.

Forbidden: Rust/Cargo, measurement implementation or consumer migration, another script, Justfile, workflows, verification scripts, docs, broad allowlists or automatic repair. D-CI #750/#825 wires this oracle only after integration. Remove this marker before ready.
