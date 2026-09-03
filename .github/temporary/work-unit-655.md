# Assignment reservation

Owning issue: #655
Implementation PR: #656
Branch: `work/655-dreamer-relation`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement only the A-03 Relation handler port for wire kind `Relation`. Consume A-03 validated item/A-05 receipt values and exact endpoint/relation projections; do not compile-link or invoke A-05/A-14b, A-31 or sibling handlers. Return A-03 `TypedCurationHandlerResult` and preserve screen eligibility/common identities.

The full semantic execution contract is issue #655 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
