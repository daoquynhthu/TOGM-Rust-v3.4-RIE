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
pub(crate) mod polynomial;

use alloc::vec::Vec;
use crate::entropy::EntropySource;

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

/// Trait for Secret Sharing Schemes.
///
/// Abstract interface to support future extensions (e.g., other fields or schemes).
pub trait SecretSharingScheme {
    type Share;
    type Secret;
    type Error;

    /// Splits a secret into n shares with threshold k.
    fn split<R: EntropySource + ?Sized>(
        &self, 
        secret: &Self::Secret, 
        k: u8, 
        n: u8, 
        rng: &mut R
    ) -> Result<Vec<Self::Share>, Self::Error>;

    /// Reconstructs a secret from shares.
    fn reconstruct(
        &self, 
        shares: &[Self::Share],
        k: u8
    ) -> Result<Self::Secret, Self::Error>;
}

/// Shamir's Secret Sharing over GF(256).
pub struct ShamirGF256;

impl SecretSharingScheme for ShamirGF256 {
    type Share = share::Share;
    type Secret = Vec<u8>;
    type Error = MpcError;

    fn split<R: EntropySource + ?Sized>(
        &self, 
        secret: &Self::Secret, 
        k: u8, 
        n: u8, 
        rng: &mut R
    ) -> Result<Vec<Self::Share>, Self::Error> {
        quorum::split_secret(secret, k, n, rng)
    }

    fn reconstruct(
        &self, 
        shares: &[Self::Share],
        k: u8
    ) -> Result<Self::Secret, Self::Error> {
        reconstruct::reconstruct_secret(shares, k)
    }
}
