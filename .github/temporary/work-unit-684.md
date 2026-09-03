# Assignment reservation

Owning issue: #684
Implementation PR: #685
Branch: `work/684-dreamer-curation`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: mandatory-screen A-31 fan-in over A-03 validated items, one supplied A-19c/A-20 result and one injected A-03 registry. Account exactly 11 wire kinds and ten handler families; Merge and Split remain distinct and both map to A-27. Do not compile-link or invoke A-05, A-20 or concrete A-21…A-30 handlers. Validate registry/results, dispatch each eligible item exactly once, preserve every non-dispatched disposition and perform no semantic recomputation or canonical mutation.

The complete English execution contract is issue #684; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
