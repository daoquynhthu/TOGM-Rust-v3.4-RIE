//! Protocol Layer.
//!
//! This module implements the high-level TOGM protocol logic, including:
//! - State Machine Management (Whitepaper Section 8)
//! - Bootstrap Orchestration (Whitepaper Section 6)
//! - Access Control & Permissions (Whitepaper Section 7.2)
//! - Multi-device Support
//!
//! # Iron Laws Compliance
//! This layer is responsible for enforcing the Iron Laws defined in `src/iron_laws.rs`.

pub mod bootstrap;
pub mod control;
pub mod group_permissions;
pub mod multi_device;
pub mod messaging;
pub mod state_machine;

/// Errors related to protocol execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Operation cannot be performed in the current state.
    InvalidState,
    /// Bootstrap process failed or was aborted.
    BootstrapFailed,
    /// Authentication or signature verification failed.
    AuthenticationFailed,
    /// Underlying network error.
    NetworkError,
    /// Operation timed out.
    Timeout,
    /// Cryptographic failure (e.g., MPC reconstruction failed).
    CryptoError,
    /// Insufficient permissions for the requested operation.
    PermissionDenied,
    /// Iron Law violation detected.
    IronLawViolation,
}
