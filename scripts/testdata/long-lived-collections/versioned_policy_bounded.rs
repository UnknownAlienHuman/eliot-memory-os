// Fixture: versioned-policy-bounded collection (issue #885).
// Policy-owned bound signal with growth: versioned-policy-bounded.

pub struct PolicySet {
    policies: Vec<String>,
}

impl PolicySet {
    pub fn admit(&mut self, policy: String) {
        self.policies.push(policy);
    }
}
