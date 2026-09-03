# Assignment reservation

Owning issue: #661
Implementation PR: #662
Branch: `work/661-dreamer-procedure`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement only the A-03 Procedure handler port for wire kind `Procedure`. Consume A-03 validated item/A-05 receipt values and exact declarative capability/effect/verifier projections; do not compile-link or invoke A-05/A-14b, A-31 or sibling handlers. Return A-03 `TypedCurationHandlerResult`; the candidate remains inert and preserves screen eligibility/common identities.

The full semantic execution contract is issue #661 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
