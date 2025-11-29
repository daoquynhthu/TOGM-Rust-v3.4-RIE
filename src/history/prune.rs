use super::HistoryError;

pub fn prune_history(_older_than: u64) -> Result<usize, HistoryError> {
    // Prune entries older than timestamp
    // Return count of pruned entries
    Ok(0)
}
