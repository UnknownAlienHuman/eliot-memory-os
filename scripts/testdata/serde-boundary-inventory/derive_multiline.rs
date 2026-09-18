//! Fixture: multiline derive attributes plus manual Deserialize impl (case 4).
//! Scanner must resolve derives split across lines and manual impl blocks,
//! including a custom Visitor. Expect three candidates: MultilineRecord
//! (derive, strict), ManualRecord (manual impl), ManualVisitor (visitor).

use serde::{Deserialize, Deserializer};
use serde::de::{MapAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize
)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case"
)]
pub struct MultilineRecord {
    pub identity: String,
    pub scope: String,
}

pub struct ManualRecord {
    pub identity: String,
}

struct ManualVisitor {
    marker: PhantomData<fn() -> ManualRecord>,
}

impl<'de> Visitor<'de> for ManualVisitor {
    type Value = ManualRecord;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a record map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<ManualRecord, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut identity: Option<String> = None;
        while let Some(key) = access.next_key::<String>()? {
            if key == "identity" {
                identity = Some(access.next_value()?);
            } else {
                let _: serde::de::IgnoredAny = access.next_value()?;
            }
        }
        Ok(ManualRecord {
            identity: identity.unwrap_or_default(),
        })
    }
}

impl<'de> Deserialize<'de> for ManualRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ManualVisitor {
            marker: PhantomData,
        })
    }
}
