//! Protocol Messaging.
//!
//! Defines the structure and types of messages exchanged in the TOGM protocol.

extern crate alloc;
use alloc::vec::Vec;

/// Types of protocol messages.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl From<u8> for MessageType {
    fn from(byte: u8) -> Self {
        match byte {
            0x01 => Self::Bootstrap,
            0x02 => Self::Chat,
            0x03 => Self::Control,
            0x04 => Self::Heartbeat,
            0x05 => Self::Sync,
            _ => Self::Unknown,
        }
    }
}

/// A generic protocol message.
#[derive(Debug, Clone)]
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
