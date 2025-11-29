pub mod export;
pub mod import;
pub mod local_transfer;
pub mod verify;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    ExportFailed,
    ImportFailed,
    InvalidFormat,
    ChecksumMismatch,
    StorageError,
    TransferFailed,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::ExportFailed => write!(f, "Export failed"),
            RecoveryError::ImportFailed => write!(f, "Import failed"),
            RecoveryError::InvalidFormat => write!(f, "Invalid format"),
            RecoveryError::ChecksumMismatch => write!(f, "Checksum mismatch"),
            RecoveryError::StorageError => write!(f, "Storage error"),
            RecoveryError::TransferFailed => write!(f, "Transfer failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoveryError {}
