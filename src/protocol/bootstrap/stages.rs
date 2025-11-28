//! Bootstrap Stages.
//!
//! Defines the granular stages of the bootstrap process.
//! strictly ordered to ensure protocol security.
//!
//! # Whitepaper Compliance
//! - Section 6: 12 stage enum (rollback + timeout + audit notes).

/// The ordered stages of the bootstrap protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootstrapStage {
    /// 0. Not started.
    Idle,
    /// 1. Discovery of potential peers.
    Discovery,
    /// 2. Establishing secure channels (Noise XX).
    ConnectionEstablishment,
    /// 3. Agreeing on group parameters (t, n, etc.).
    ParameterNegotiation,
    /// 4. Exchanging commitments for DKG.
    CommitmentExchange,
    /// 5. Verifying received commitments.
    CommitmentVerification,
    /// 6. Distributing secret shares.
    ShareDistribution,
    /// 7. Verifying received shares against commitments.
    ShareVerification,
    /// 8. Checking view consistency across the quorum.
    ConsistencyCheck,
    /// 9. Deriving group secrets / master pad.
    KeyDerivation,
    /// 10. Persisting state to secure storage.
    Persistence,
    /// 11. Bootstrap successfully completed.
    Complete,
}

impl BootstrapStage {
    /// Returns the next logical stage.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Idle => Some(Self::Discovery),
            Self::Discovery => Some(Self::ConnectionEstablishment),
            Self::ConnectionEstablishment => Some(Self::ParameterNegotiation),
            Self::ParameterNegotiation => Some(Self::CommitmentExchange),
            Self::CommitmentExchange => Some(Self::CommitmentVerification),
            Self::CommitmentVerification => Some(Self::ShareDistribution),
            Self::ShareDistribution => Some(Self::ShareVerification),
            Self::ShareVerification => Some(Self::ConsistencyCheck),
            Self::ConsistencyCheck => Some(Self::KeyDerivation),
            Self::KeyDerivation => Some(Self::Persistence),
            Self::Persistence => Some(Self::Complete),
            Self::Complete => None,
        }
    }

    /// Returns the recommended timeout for this stage in seconds.
    pub fn timeout_seconds(&self) -> u64 {
        match self {
            Self::Idle => 0,
            Self::Discovery => 60,
            Self::ConnectionEstablishment => 30,
            Self::ParameterNegotiation => 10,
            Self::CommitmentExchange => 10,
            Self::CommitmentVerification => 5,
            Self::ShareDistribution => 10,
            Self::ShareVerification => 5,
            Self::ConsistencyCheck => 5,
            Self::KeyDerivation => 60, // Computationally expensive (Scrypt)
            Self::Persistence => 5,
            Self::Complete => 0,
        }
    }
}
