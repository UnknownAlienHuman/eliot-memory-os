// Fixture: lifecycle-removal Vec (issue #885).
// Same-slice removal bounds growth without a literal hard bound.

pub struct Session {
    tokens: Vec<String>,
}

impl Session {
    pub fn add(&mut self, token: String) {
        self.tokens.push(token);
    }

    pub fn end(&mut self) {
        self.tokens.clear();
    }
}
