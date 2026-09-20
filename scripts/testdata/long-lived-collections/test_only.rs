// Fixture: attribute-region test-only collection (issue #885).
// The struct lives inside #[cfg(test)]; production code must never inherit
// this label from the distant test module in the same file.

#[cfg(test)]
mod tests {
    pub struct TestCache {
        pub entries: Vec<String>,
    }

    impl TestCache {
        pub fn add(&mut self, value: String) {
            self.entries.push(value);
        }
    }
}
