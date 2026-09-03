# Assignment reservation

Owning issue: #665
Implementation PR: #666
Branch: `work/665-dreamer-structure-repair`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Correct boundary: implement one A-03 handler family `StructureRepair` accepting exactly the two distinct wire kinds `[Merge, Split]`. Preserve each kind/payload/result; do not create a wire kind named `StructureRepair`. Consume A-03 validated item/A-05 receipt values; do not compile-link or invoke A-05/A-14b, A-31 or sibling handlers. False-merge reversal remains an evidence-bound A-27 semantic mode, not a hidden twelfth wire kind.

The full semantic execution contract is issue #665 and its authoritative correction comment; topology correction is #816. Rebase on actual current `main` before implementation and remove this marker before ready.
