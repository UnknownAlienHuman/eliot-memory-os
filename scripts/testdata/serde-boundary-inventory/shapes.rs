//! Fixture: tagged/untagged/flatten/alias/default shapes (case 6).
//! Each shape must be classified distinctly, never merged.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum TaggedEnum {
    Request { identity: String },
    Response { scope: String },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum UntaggedEnum {
    Text(String),
    Structured { identity: String },
}

#[derive(Debug, Deserialize)]
pub struct InnerBlock {
    pub authority: String,
}

#[derive(Debug, Deserialize)]
pub struct FlattenHolder {
    #[serde(flatten)]
    pub inner: InnerBlock,
    #[serde(alias = "ident")]
    pub identity: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    String::from("task:default")
}
