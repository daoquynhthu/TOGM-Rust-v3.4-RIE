pub mod policy;
pub mod share;
pub mod verify;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupHistoryError {
    InvalidPolicy,
    VerificationFailed,
    ShareNotFound,
    StorageError,
}

impl fmt::Display for GroupHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupHistoryError::InvalidPolicy => write!(f, "Invalid history policy"),
            GroupHistoryError::VerificationFailed => write!(f, "History verification failed"),
            GroupHistoryError::ShareNotFound => write!(f, "History share not found"),
            GroupHistoryError::StorageError => write!(f, "Storage error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GroupHistoryError {}
