//! Fixture: unsupported macro syntax stays explicit unknown (case 9).
//! The macro-generated record cannot be resolved by regex discovery, so the
//! scanner must emit one unknown row with unsupported-macro evidence instead
//! of empty success.

use serde::Deserialize;

macro_rules! make_deser {
    ($name:ident) => {
        pub struct $name {
            pub identity: String,
        }
    };
}

make_deser!(GeneratedRecord);

serde_derive_magic!(MagicRecord);

#[derive(Debug, Deserialize)]
pub struct VisibleRecord {
    pub identity: String,
}
