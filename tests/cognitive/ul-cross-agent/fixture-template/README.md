# UL cross-agent relay fixture

This directory is copied into a new temporary Git repository for each real
UL-11 certification run. The two Rust files provide stable file and branch
cues only. They intentionally contain no certification marker, reusable memory
statement, provider output, or ELIOT memory handle.

The harness creates one committed baseline and keeps the worktree clean for the
entire eight-call run.
