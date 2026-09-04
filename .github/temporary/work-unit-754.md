# Assignment reservation

Owning issue: #754
Implementation PR: #755
Branch: `fix/754-runtime-hygiene-oracle`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`
Integrated baseline: PR #812 / merge `1a670836a746ee8e1029d247034fc0a1bb444ecc`

Exclusive scope: `scripts/audit-runtime-source-hygiene.py` and this temporary marker. Begin with a requirement-by-requirement residual audit of #812. Preserve its accepted item-removal, source-family and unsafe-async fixes; implement only the still-unproven common lexer/cfg/item/span denominator, immutable per-file analysis model, detector unification, fail-closed parse/coverage behavior, reconciled arithmetic and deterministic output/self-tests required by #754.

Forbidden: Rust or other scripts, workflows, Justfile, configuration, workspace/lockfile, hygiene policy/threshold changes, automatic source repair, or claiming scanned runtime correctness. Remove this marker before the pull request is marked ready.
