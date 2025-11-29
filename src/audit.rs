use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    WriteFailed,
    ReadFailed,
    InvalidFormat,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::WriteFailed => write!(f, "Failed to write audit log"),
            AuditError::ReadFailed => write!(f, "Failed to read audit log"),
            AuditError::InvalidFormat => write!(f, "Invalid audit log format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuditError {}

pub struct AuditEntry {
    pub timestamp: u64,
    pub action: Vec<u8>,
    pub result: bool,
}

pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn log(&mut self, action: Vec<u8>, result: bool) -> Result<(), AuditError> {
        let timestamp = {
            #[cfg(feature = "std")]
            {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            }
            #[cfg(not(feature = "std"))]
            {
                0 // Placeholder: platform-specific timer required
            }
        };

        self.entries.push(AuditEntry {
            timestamp,
            action,
            result,
        });
        Ok(())
    }

    pub fn get_entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}
