use super::HistoryError;

pub struct HistoryIndex {
    pub last_index: u64,
}

impl HistoryIndex {
    pub fn new() -> Self {
        Self { last_index: 0 }
    }

    pub fn append(&mut self) -> Result<u64, HistoryError> {
        self.last_index += 1;
        Ok(self.last_index)
    }
}
