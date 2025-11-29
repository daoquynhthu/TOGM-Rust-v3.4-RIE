pub struct BandwidthLimiter;

impl BandwidthLimiter {
    pub fn new() -> Self { Self }
    pub fn check(&self, _size: usize) -> bool { true }
}
