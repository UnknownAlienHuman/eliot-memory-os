# Assignment reservation

Owning issue: #883
Branch: `fix/883-memory-store-clone-contract`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Semantic owner: public deep-copy MemoryStore clone/fork boundary
Required matrix: 14 cases

Do not replace the independent deep copy with `Arc` or shared mutable state. Exact source evidence decides whether `Clone` is removed or replaced by an explicit fallible fork. Remove this marker when implementation begins and before ready-for-review.
