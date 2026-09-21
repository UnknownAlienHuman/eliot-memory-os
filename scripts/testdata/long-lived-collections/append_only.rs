// Fixture: append-only event log with segmented retention (issue #885).

pub struct Event {
    pub name: String,
}

pub struct EventLog {
    events: Vec<Event>,
}

impl EventLog {
    pub fn record(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn rotate(&mut self) {
        self.events.truncate(1024);
    }
}
