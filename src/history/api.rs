use super::HistoryError;
use alloc::vec::Vec;

pub fn get_messages(_start_index: u64, _count: usize) -> Result<Vec<Vec<u8>>, HistoryError> {
    // Retrieve messages from history
    Ok(Vec::new())
}
