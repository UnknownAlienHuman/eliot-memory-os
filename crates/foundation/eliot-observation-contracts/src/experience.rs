//! System Experience contracts cell: owner-side experience envelopes and records.
//!
//! [`projection`] owns the revision/fence-bound projection envelopes consumed
//! without retrieval (`JournalProjection`, `BankProjection`,
//! `FeedbackProjection` with reconciled counts and blind intervals).
//! [`records`] owns the admitted bank/feedback record shapes committed through
//! the store bridge. This hub only composes the cell surface; validation,
//! coverage posture, and fence recovery stay with the owning modules.

mod projection;
mod records;

pub use projection::*;
pub use records::*;
