pub mod cleanup;
pub mod delete;
pub mod file_transfer;
pub mod queue;
pub mod retract;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingError {
    QueueFull,
    MessageTooLarge,
    InvalidRecipient,
    EncryptionFailed,
    DecryptionFailed,
    FileNotFound,
    ChunkError,
    StorageError,
    Timeout,
}

impl fmt::Display for MessagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessagingError::QueueFull => write!(f, "Message queue is full"),
            MessagingError::MessageTooLarge => write!(f, "Message is too large"),
            MessagingError::InvalidRecipient => write!(f, "Invalid recipient"),
            MessagingError::EncryptionFailed => write!(f, "Encryption failed"),
            MessagingError::DecryptionFailed => write!(f, "Decryption failed"),
            MessagingError::FileNotFound => write!(f, "File not found"),
            MessagingError::ChunkError => write!(f, "Chunk processing error"),
            MessagingError::StorageError => write!(f, "Storage error"),
            MessagingError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MessagingError {}
