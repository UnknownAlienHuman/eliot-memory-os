// Bounded reject fixture: a second, mutable copy of the canonical
// SerializedContextMeasurement schema. A non-divergent alias or re-export is
// allowed only as an inventoried projection; a second struct definition is a
// second mutable schema and must be rejected.

pub struct SerializedContextMeasurement {
    pub envelope_digest: String,
    pub serializer_id: String,
    pub route_id: String,
    pub rendered_utf8_bytes: u64,
}

impl SerializedContextMeasurement {
    pub fn rendered_utf8_bytes(&self) -> u64 {
        self.rendered_utf8_bytes
    }
}
