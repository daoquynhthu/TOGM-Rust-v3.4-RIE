//! Protocol Messaging.
//!
//! Defines the structure and types of messages exchanged in the TOGM protocol.

extern crate alloc;
use alloc::vec::Vec;
use core::convert::TryFrom;
use crate::protocol::ProtocolError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Types of protocol messages.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum MessageType {
    /// Bootstrap protocol messages (DKG, etc.).
    Bootstrap = 0x01,
    /// Encrypted chat messages.
    Chat = 0x02,
    /// Group control messages (add/remove member).
    Control = 0x03,
    /// Keep-alive / Status.
    Heartbeat = 0x04,
    /// Multi-device sync.
    Sync = 0x05,
    /// Unknown / Invalid.
    Unknown = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::Bootstrap),
            0x02 => Ok(Self::Chat),
            0x03 => Ok(Self::Control),
            0x04 => Ok(Self::Heartbeat),
            0x05 => Ok(Self::Sync),
            _ => Err(ProtocolError::InvalidState),
        }
    }
}

/// A generic protocol message.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProtocolMessage {
    /// The type of message.
    pub msg_type: MessageType,
    /// The raw payload.
    pub payload: Vec<u8>,
    /// The sender's ID (e.g., hash of public key).
    pub sender_id: [u8; 32],
}

impl ProtocolMessage {
    /// Creates a new protocol message.
    pub fn new(msg_type: MessageType, payload: Vec<u8>, sender_id: [u8; 32]) -> Self {
        Self {
            msg_type,
            payload,
            sender_id,
        }
    }
}
