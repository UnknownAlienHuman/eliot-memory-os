//! Immutable experience read-aid view over owner projection vocabulary
//! (#223, review repair, unit #4).
//!
//! The projection cell lives in [`projection`]; this root only re-exports
//! the cell surface so Smart consumers keep one vocabulary.

#![forbid(unsafe_code)]

mod projection;

pub use projection::{
    ExperienceView, FREEZE_ID, revalidate_bank_refs, revalidate_feedback_refs,
    revalidate_journal_presence,
};
