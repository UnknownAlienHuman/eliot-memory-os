//! Fixture: strings/comments must not become candidates (case 8).
//! Only RealAfterNoise is a production candidate.

// #[derive(Deserialize)]
// pub struct FakeInLineComment {
//     pub identity: String,
// }

/*
#[derive(Deserialize)]
pub struct FakeInBlockComment {
    pub identity: String,
}
*/

const FAKE_IN_STRING: &str = "#[derive(Deserialize)] pub struct FakeInString;";
const FAKE_RAW: &str = r#"#[derive(Deserialize)] pub struct FakeInRaw;"#;
const FAKE_CHAR: char = '"';

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealAfterNoise {
    pub identity: String,
    pub scope: String,
}
