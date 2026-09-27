<!-- generated: eliot-doc-shards-v1 -->
# Documentation sharding integrity report

This report records the deterministic layout migration. It does not add a
third normative source.

- Normative pair key: `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`
- Canonical semantic byte streams changed: **no**
- Legacy file paths retained as compatibility maps: **yes**
- Cross-fragment self-links rewritten only as navigation metadata: **yes**

| Source | Original bytes | Fragments | Largest rendered fragment | Reconstructed SHA-256 |
|---|---:|---:|---:|---|
| Architecture | 150260 | 123 | 10212 | `a3c5b2028d9df89a53cd565f8ff493484be74078e4efd7b534c0f1c3169577c7` |
| Implementation | 1008830 | 504 | 25823 | `ead4ceff2db254e4202c8fa7ae167225a6f65b720c222075ada61fc45fc407a4` |

Verification reconstructs each source by reversing only recorded link-target
rewrites and concatenating fragments in manifest order. Any missing byte,
reordered fragment, stale index, stale compatibility anchor, or changed
fragment hash fails closed.
