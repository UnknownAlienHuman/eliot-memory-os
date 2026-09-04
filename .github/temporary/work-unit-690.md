# Assignment reservation

Owning issue: #690
Implementation PR: pending
Branch: `docs/690-package-reader-closure`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: the existing package/prototype documentation-index generators, validators, deterministic projections, shard-size verifier, their focused fixtures, and supported-script/navigation documentation named by #690. The implementation must re-audit current `main` after merged PR #809, preserve already-integrated closure repairs, resolve governing handles to exact canonical fragment paths and anchors, prove every package manifest and target front door has an exact route, produce deterministic package↔documentation navigation, and enforce the issue's fail-closed canonical-shard bound.

Forbidden: Architecture/Implementation semantic edits, Rust/Cargo topology changes, workflows or GitHub policy, unrelated generated indexes, and any claim that Actions/full-checkout verification ran without a real runner.

Issue #690 is the complete execution contract. Rebase on actual current `main`, freeze the residual old→new gap before mutation, and remove this marker before the pull request is marked ready.
