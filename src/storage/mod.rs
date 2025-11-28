//! Storage Module.
//!
//! Handles persistent storage of data, including:
//! - Raw file storage for shares and pads.
//! - Encrypted structured storage (Scrypt-protected).
//!
//! # Whitepaper Compliance
//! - Section 1.2/9: Secure storage and persistence.

pub mod raw_files;
pub mod sqlite_scrypt;

/// Errors related to storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// File not found.
    NotFound,
    /// Permission denied.
    PermissionDenied,
    /// IO error (generic).
    IoError,
    /// Data corruption or integrity check failed.
    Corruption,
    /// Encryption/Decryption failure.
    CryptoError,
    /// Storage is full.
    DiskFull,
    /// Invalid path or filename.
    InvalidPath,
}

#[cfg(feature = "std")]
impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => StorageError::NotFound,
            std::io::ErrorKind::PermissionDenied => StorageError::PermissionDenied,
            _ => StorageError::IoError,
        }
    }
}
