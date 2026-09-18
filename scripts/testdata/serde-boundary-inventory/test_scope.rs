//! Fixture: test scope is production-distinct (case 8, second half).
//! File lives under scripts/testdata so every row is test/admission-risk by
//! path, even though the syntax is a normal derive. The cfg(test) module adds
//! an explicit test-only candidate that must never be current-closed.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TestdataScopedDto {
    pub identity: String,
    pub scope: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct TestOnlyDto {
        pub identity: String,
    }
}
