//! Master Pad Management Module.
//!
//! This module handles the lifecycle, storage, protection, and destruction of the Master Pad.
//! The Master Pad is the source of all One-Time Pad (OTP) key material and is critical
//! for the information-theoretic security of the system.
//!
//! # Components
//! - `lifecycle`: Manages initialization, rotation, and access to the pad.
//! - `usage_stats`: Tracks consumed bytes to strictly enforce "One-Time" usage.
//! - `burn`: Implements secure, irreversible deletion of key material.
//! - `monitor`: Integrates with the Watchdog system for anomaly detection.
//! - `share_encrypt`: Encrypts/decrypts local pad shares (Scrypt-based).
//!
//! # Security Guarantees
//! - **Memory Protection**: Uses `mlock` (via `memmap2`) where possible to prevent swapping.
//! - **Zeroization**: All key material is zeroized on drop or burn.
//! - **Usage Enforcement**: Strict tracking prevents key reuse.
//! - **Integrity**: Optional integrity checks on stored pads.
//!
//! # Whitepaper Compliance
//! - Section 2: Master Pad Generation & Lifecycle.
//! - Section 3: Usage Tracking.
//! - Section 8: Emergency Destruction (Burn).

pub mod lifecycle;
pub mod usage_stats;
pub mod burn;
pub mod monitor;
pub mod share_encrypt;

/// Errors related to Master Pad operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadError {
    /// Pad has been exhausted (no more bytes available).
    Exhausted,
    /// Requested slice is out of bounds.
    OutOfBounds,
    /// Pad integrity check failed.
    IntegrityFailure,
    /// Storage I/O error.
    StorageError,
    /// Encryption/Decryption failed.
    CryptoError,
    /// Pad is locked or not initialized.
    NotReady,
    /// Anomaly detected by watchdog.
    SecurityLockdown,
}
