pub mod client;
pub mod health;
pub mod stream;
pub mod verify;

pub use client::DrandClient;
pub use stream::BeaconStream;
pub use verify::{verify_beacon, verify_chain};

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrandError {
    ConnectionError,
    VerificationError,
    Timeout,
    InvalidBeacon,
    OutOfSync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrandBeacon {
    pub round: u64,
    pub randomness: Vec<u8>,
    pub signature: Vec<u8>,
    pub previous_signature: Vec<u8>,
}
