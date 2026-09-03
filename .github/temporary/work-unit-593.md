# Assignment reservation

Owning issue: #593
Implementation PR: #594
Branch: `work/593-dreamer-bundle`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct ownership: pure A-04 bundle assembler over A-03 job/bundle contracts and A-15 Context contracts. Correct package-local `module.toml` to match the existing A-03+A-15 Cargo contract edge. For Curation, require exact A-03 owner-neutral references to the source snapshot, denominator and screen profile; do not import/run A-19c/A-20. Missing mandatory screen references yields `DreamBundleIncomplete`.

The full execution contract is issue #593 and its authoritative correction comment. Rebase on actual current `main` before implementation and remove this marker before ready.
