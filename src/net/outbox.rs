pub struct Outbox;

impl Outbox {
    pub fn new() -> Self { Self }
    pub fn push(&self, _msg: &[u8]) {}
}
