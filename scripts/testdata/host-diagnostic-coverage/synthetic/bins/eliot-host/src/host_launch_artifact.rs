//! Synthetic Host launch artifact re-export (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: a pure re-export facade with no behavior of its
//! own. Its exclusion target is the launch owner that implements the seam.

pub use crate::host_launch_options::reject_installation;
