//! Entropy collection and management module.
//!
//! This module defines the interfaces for entropy sources and manages the aggregation
//! of randomness from multiple inputs (OS, CPU jitter, user input, etc.) to seed
//! the CSPRNG.
//!
//! # Design
//! - **Multi-Source**: Aggregates entropy from independent sources to prevent single-point failure.
//! - **Fail-Safe**: If one source fails, others can still provide entropy (though security reduces).
//! - **Constant-Time**: Aggregation logic avoids timing leaks.
//!
//! # Whitepaper Compliance
//! - Section 3.1: Entropy Gathering Protocols.

pub mod jitter;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod rdrand;

#[cfg(feature = "std")]
pub mod audio;
#[cfg(feature = "std")]
pub mod video;

pub mod custom;
pub mod sources;
pub mod aggregator;
pub mod sp800_90b;

/// Error types for entropy collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// Source initialization failed.
    InitFailed,
    /// Failed to collect sufficient entropy bytes.
    CollectionFailed,
    /// Source is exhausted (e.g., fixed buffer).
    Exhausted,
    /// Health test failure (SP 800-90B).
    HealthTestFailed,
    /// Platform not supported.
    NotSupported,
}

/// A trait for entropy sources.
pub trait EntropySource {
    /// Returns a unique identifier for the source.
    fn name(&self) -> &'static str;

    /// Fills `dest` with random bytes from the source.
    ///
    /// # Arguments
    /// * `dest` - Buffer to fill with entropy.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(EntropyError)` if the source fails.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError>;

    /// Returns the estimated entropy per byte (in bits, 0.0-8.0).
    ///
    /// This is a conservative estimate used for health monitoring.
    fn entropy_estimate(&self) -> f64;
}
