pub mod pc;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    NotSupported,
    AccessDenied,
    IOError,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::NotSupported => write!(f, "Platform feature not supported"),
            PlatformError::AccessDenied => write!(f, "Access denied"),
            PlatformError::IOError => write!(f, "I/O error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PlatformError {}
