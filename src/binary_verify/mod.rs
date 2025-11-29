pub mod genesis_hash;
pub mod local_self_verify;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    HashMismatch,
    InvalidFormat,
    SignatureVerificationFailed,
    FileNotFound,
    IOError,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::HashMismatch => write!(f, "Hash mismatch"),
            VerificationError::InvalidFormat => write!(f, "Invalid format"),
            VerificationError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            VerificationError::FileNotFound => write!(f, "File not found"),
            VerificationError::IOError => write!(f, "I/O error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
