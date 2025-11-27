//! Multi-Party Computation (MPC) and Secret Sharing.
//!
//! This module implements Threshold Cryptography primitives, primarily
//! Shamir's Secret Sharing (SSS) over GF(256).
//!
//! # Components
//! - `share`: Definition of a secret share.
//! - `quorum`: Threshold logic and polynomial generation.
//! - `reconstruct`: Lagrange interpolation for secret recovery.
//! - `aggregate`: Operations on shares (e.g., proactive refresh).
//!
//! # Security
//! - **Constant-Time**: All GF(256) operations are constant-time.
//! - **Zeroization**: Shares and secrets are zeroized on drop.
//! - **Integrity**: Shares include integrity checks (optional, depending on implementation).

pub mod share;
pub mod quorum;
pub mod reconstruct;
pub mod aggregate;

/// Errors for MPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcError {
    /// Invalid share index (must be 1..=255).
    InvalidShareIndex,
    /// Share value is empty.
    EmptyShare,
    /// Threshold configuration error (k > n, k < 2, etc.).
    InvalidThreshold,
    /// Not enough shares to reconstruct.
    InsufficientShares,
    /// Duplicate share indices provided.
    DuplicateShareIndex,
    /// Mismatch in share lengths.
    ShareLengthMismatch,
    /// Integrity check failed.
    IntegrityFailure,
    /// Random number generator failure.
    RngFailure,
}
