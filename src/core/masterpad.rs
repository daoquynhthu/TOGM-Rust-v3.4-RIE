#![forbid(unsafe_code)]

use crate::core::sip64::MAC_LEN;

// MasterPad provides constant-time, monotonic block allocation over a backing pad.
// Blocks are laid out as `keystream || mac_key(64B)` and never reused.
// No unsafe; strict bounds checking; suitable for OTP keystream provisioning.

#[derive(Debug, PartialEq, Eq)]
pub enum PadError {
    Insufficient,
}

pub enum PadBuf {
    Heap(Vec<u8>),
}

pub struct MasterPad {
    buf: PadBuf,
    pos: usize,
}

impl MasterPad {
    // Create from heap buffer; position starts at 0.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        MasterPad { buf: PadBuf::Heap(bytes), pos: 0 }
    }

    // Remaining bytes available for allocation.
    pub fn available(&self) -> usize {
        match &self.buf { PadBuf::Heap(v) => v.len().saturating_sub(self.pos) }
    }

    // Borrow the next block `payload_len + MAC_LEN` without advancing.
    pub fn peek_block(&self, payload_len: usize) -> Result<&[u8], PadError> {
        let need = payload_len + MAC_LEN;
        if self.available() < need { return Err(PadError::Insufficient); }
        match &self.buf {
            PadBuf::Heap(v) => Ok(&v[self.pos..self.pos + need]),
        }
    }

    // Consume and return the next block by borrowing; advances position.
    pub fn consume_block(&mut self, payload_len: usize) -> Result<&[u8], PadError> {
        let need = payload_len + MAC_LEN;
        if self.available() < need { return Err(PadError::Insufficient); }
        let start = self.pos;
        let end = start + need;
        self.pos = end;
        match &self.buf {
            PadBuf::Heap(v) => Ok(&v[start..end]),
        }
    }

    // Consume and return the next block by value; advances position.
    pub fn take_block(&mut self, payload_len: usize) -> Result<Vec<u8>, PadError> {
        let need = payload_len + MAC_LEN;
        if self.available() < need { return Err(PadError::Insufficient); }
        let start = self.pos;
        let end = start + need;
        self.pos = end;
        match &self.buf {
            PadBuf::Heap(v) => Ok(v[start..end].to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::otp_engine::{encrypt_and_tag, decrypt_and_verify};

    #[test]
    fn test_masterpad_consume_and_roundtrip() {
        let payload_len = 16;
        let mut backing = Vec::new();
        backing.extend_from_slice(&[0x11u8; 16]);
        backing.extend_from_slice(&[0x22u8; MAC_LEN]);
        backing.extend_from_slice(&[0x33u8; 16]);
        backing.extend_from_slice(&[0x44u8; MAC_LEN]);
        let mut pad = MasterPad::from_bytes(backing);

        let b1 = pad.take_block(payload_len).unwrap();
        let (ct, tag) = encrypt_and_tag(b"HELLO, OTP!!!", b"M", &b1).unwrap();
        let pt = decrypt_and_verify(&ct, b"M", &b1, &tag).unwrap();
        assert_eq!(pt, b"HELLO, OTP!!!");

        let b2 = pad.take_block(payload_len).unwrap();
        assert_ne!(b1.as_ptr(), b2.as_ptr());
        assert_eq!(pad.available(), 0);
        assert!(pad.consume_block(payload_len).is_err());
    }
}
