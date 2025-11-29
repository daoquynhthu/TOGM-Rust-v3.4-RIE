pub mod anonymous_net;
pub mod bandwidth;
pub mod drand;
pub mod i2p;
pub mod noise_xx;
pub mod outbox;
pub mod pairwise;
pub mod rendezvous;
pub mod sequencer;
pub mod tor;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    ConnectionFailed,
    Timeout,
    EncryptionError,
    DecryptionError,
    InvalidMessage,
    BandwidthLimitExceeded,
    IOError,
    NotImplemented,
    HandshakeFailed,
    StreamClosed,
    InvalidAddress,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::ConnectionFailed => write!(f, "Connection failed"),
            NetError::Timeout => write!(f, "Operation timed out"),
            NetError::EncryptionError => write!(f, "Encryption failed"),
            NetError::DecryptionError => write!(f, "Decryption failed"),
            NetError::InvalidMessage => write!(f, "Invalid message format"),
            NetError::BandwidthLimitExceeded => write!(f, "Bandwidth limit exceeded"),
            NetError::IOError => write!(f, "I/O error"),
            NetError::NotImplemented => write!(f, "Feature not implemented"),
            NetError::HandshakeFailed => write!(f, "Handshake failed"),
            NetError::StreamClosed => write!(f, "Stream closed"),
            NetError::InvalidAddress => write!(f, "Invalid address format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetError {}
