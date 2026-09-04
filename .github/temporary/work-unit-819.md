# Assignment reservation

Owning issue: #819
Implementation PR: pending
Branch: `work/819-learning-closure`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: the existing Learning-closure implementation module and focused tests/fixtures under `crates/meta/eliot-improvement/**`, minimal package-local re-export lines, an exact router correction only when proven, and this temporary marker. The module assembles one deterministic evidence-bound `CampaignLearningClosure` candidate from A-32 contracts and immutable A-33…A-36 runtime-produced values.

Forbidden: edits to A-32…A-36 packages, unrelated `eliot-improvement` modules, live Context/runtime/Store/provider/model access, overlay activation or rollback execution, campaign/policy mutation, canonical promotion/retirement/disablement, authority/effects, task finish, root Cargo/lock/index, workflows, or normative documentation.

Issue #819 is the complete execution contract. A-37 preserves Delta ≠ admission ≠ activation ≠ use ≠ outcome ≠ benefit ≠ causality ≠ external promotion. Rebase on actual current `main`, resolve any package overlap before mutation, and remove this marker before the pull request is marked ready.
