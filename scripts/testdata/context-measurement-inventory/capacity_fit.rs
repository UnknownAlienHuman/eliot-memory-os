// Frozen fixture for #866: capacity fit analysis (capacity-fit-analysis).
pub struct Capacity {
    pub fixed_overhead: u64,
    pub headroom: Option<u64>,
}
pub fn total(cap: &Capacity, cost: u64) -> u64 {
    cap.fixed_overhead + cost
}
