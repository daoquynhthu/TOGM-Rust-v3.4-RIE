use alloc::vec::Vec;

pub struct HistoryShare {
    pub id: [u8; 32],
    pub data: Vec<u8>,
}

impl HistoryShare {
    pub fn new(id: [u8; 32], data: Vec<u8>) -> Self {
        Self { id, data }
    }
}
