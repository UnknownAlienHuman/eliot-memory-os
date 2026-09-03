# Assignment reservation

Owning issue: #595
Implementation PR: #596
Branch: `work/595-dreamer-candidate-validation`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct ownership: one common pure pre-handler gate. A-04 bundle plus A-14b grounded draft enters A-05; A-05 emits A-03 `ValidatedDreamDraft`/validated items and receipt; only then may a semantic handler run. Do not validate handler-produced candidates here, import handlers/A-31, or create a second public schema. Handlers consume the validated value through A-03 without compile-linking A-05.

The complete English execution contract is issue #595; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
