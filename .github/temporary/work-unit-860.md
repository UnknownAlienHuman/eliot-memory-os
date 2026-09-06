# Assignment reservation

Owning issue: #860
Branch: `fix/860-windows-guard-abort-boundary`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Semantic owner: explicit restoration failures and documented security fail-stop containment for four Windows guard abort sites
Required matrix: 16 cases

Exclusive mutable scope is limited to the two source files and package-local `abort_boundary` tests named in issue #860. Remove this marker when implementation begins and before ready-for-review.
