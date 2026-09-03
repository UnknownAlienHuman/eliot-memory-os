# Assignment reservation

Owning issue: #602
Implementation PR: #603
Branch: `work/602-dreamer-claim-grounding`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct ownership: pure A-14b binder from A-03 `ModelDraft` plus A-04 frozen bundle/manifest to A-03 `GroundedDreamDraft`/ledger. A-05 is the downstream runtime consumer, not a dependency. Preserve exact Curation screen binding but do not import A-19c/A-20 or decide eligibility. No source acquisition, semantic handler, truth promotion, state/effect or finish path.

The full execution contract is issue #602 and its authoritative correction comment. Rebase on actual current `main` before implementation and remove this marker before ready.
