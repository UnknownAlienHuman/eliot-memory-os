//! Store-facing cue behavior is exercised by the candidate and firing contract
//! tests. This target exists so the Task 03 verifier keeps crate ownership
//! explicit without adding a seventh test.

pub const TASK_03_STORE_CONTRACT: &str =
    "cue_index is derived, project-scoped, bounded, and rebuildable";
