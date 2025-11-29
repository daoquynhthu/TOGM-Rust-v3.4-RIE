pub mod api;
pub mod index;
pub mod prune;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryError {
    NotFound,
    InvalidRange,
    StorageError,
    PruningFailed,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::NotFound => write!(f, "History entry not found"),
            HistoryError::InvalidRange => write!(f, "Invalid history range"),
            HistoryError::StorageError => write!(f, "Storage error"),
            HistoryError::PruningFailed => write!(f, "Pruning failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HistoryError {}
