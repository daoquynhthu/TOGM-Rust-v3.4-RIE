#![forbid(unsafe_code)]

use crate::core::masterpad::{MasterPad, PadError};
use crate::core::sip64::{MAC_LEN, verify as sip_verify};
use crate::core::otp_engine::{encrypt_and_tag, decrypt, split_block};

// Ratchet provides forward-only session progression over a MasterPad.
// Each step consumes a block `keystream || mac_key(64B)` and binds the counter
// into metadata to prevent reordering and replay.
// No unsafe; constant-time encryption/decryption via otp_engine; strict bounds.

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    Pad(PadError),
    TagMismatch,
}

pub struct Ratchet {
    pad: MasterPad,
    ctr: u64,
}

impl From<PadError> for RatchetError {
    fn from(e: PadError) -> Self { RatchetError::Pad(e) }
}

impl Ratchet {
    // Create from a MasterPad; counter starts at 0.
    pub fn from_pad(pad: MasterPad) -> Self {
        Ratchet { pad, ctr: 0 }
    }

    // Remaining pad bytes.
    pub fn available(&self) -> usize { self.pad.available() }

    // Current counter value.
    pub fn counter(&self) -> u64 { self.ctr }

    fn meta(&self, ad: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(8 + ad.len());
        m.extend_from_slice(&self.ctr.to_le_bytes());
        m.extend_from_slice(ad);
        m
    }

    // Seal: consume a block, bind counter + ad into MAC, return (ct, tag).
    pub fn seal(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Vec<u8>, [u8; MAC_LEN]), RatchetError> {
        let block = self.pad.take_block(plaintext.len())?;
        let meta = self.meta(ad);
        let sealed = encrypt_and_tag(plaintext, &meta, &block).map_err(|_| RatchetError::TagMismatch)?;
        self.ctr = self.ctr.wrapping_add(1);
        Ok(sealed)
    }

    // Open: peek block, verify MAC without consuming; on success, consume and decrypt.
    pub fn open(&mut self, ciphertext: &[u8], ad: &[u8], tag: &[u8; MAC_LEN]) -> Result<Vec<u8>, RatchetError> {
        let meta = self.meta(ad);
        let ks_owned = {
            let block = self.pad.peek_block(ciphertext.len())?;
            let (keystream, mac_key) = split_block(block, ciphertext.len()).map_err(|_| RatchetError::TagMismatch)?;
            let ks = keystream.to_vec();
            let mut mk: [u8; MAC_LEN] = [0u8; MAC_LEN];
            mk.copy_from_slice(mac_key);
            if !sip_verify(ciphertext, &meta, &mk, tag) {
                return Err(RatchetError::TagMismatch);
            }
            ks
        };
        let _ = self.pad.consume_block(ciphertext.len())?;
        let pt = decrypt(ciphertext, &ks_owned).map_err(|_| RatchetError::TagMismatch)?;
        self.ctr = self.ctr.wrapping_add(1);
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::masterpad::MasterPad;

    fn make_pad(payload_len: usize, msgs: usize) -> MasterPad {
        let mut backing = Vec::new();
        for i in 0..msgs {
            for _ in 0..payload_len { backing.push(i as u8); }
            backing.extend_from_slice(&[(i as u8).wrapping_mul(7); MAC_LEN]);
        }
        MasterPad::from_bytes(backing)
    }

    #[test]
    fn test_ratchet_roundtrip_two_messages() {
        let payload_len = 12;
        let pad = make_pad(payload_len, 2);
        let mut sender = Ratchet::from_pad(pad);

        let (ct1, tag1) = sender.seal(b"hello world!", b"A").unwrap();
        let (ct2, tag2) = sender.seal(b"HELLO WORLD!", b"B").unwrap();

        let pad2 = make_pad(payload_len, 2);
        let mut receiver = Ratchet::from_pad(pad2);
        let pt1 = receiver.open(&ct1, b"A", &tag1).unwrap();
        let pt2 = receiver.open(&ct2, b"B", &tag2).unwrap();
        assert_eq!(pt1, b"hello world!");
        assert_eq!(pt2, b"HELLO WORLD!");
        assert_eq!(receiver.counter(), 2);
    }

    #[test]
    fn test_ratchet_reordering_fails() {
        let payload_len = 8;
        let pad = make_pad(payload_len, 2);
        let mut sender = Ratchet::from_pad(pad);
        let (ct1, tag1) = sender.seal(b"MSG-ONE!", b"X").unwrap();
        let (ct2, tag2) = sender.seal(b"MSG-TWO!", b"Y").unwrap();

        let pad2 = make_pad(payload_len, 2);
        let mut receiver = Ratchet::from_pad(pad2);
        // Try to open second before first: counter mismatch → tag mismatch
        assert!(receiver.open(&ct2, b"Y", &tag2).is_err());
        let pt1 = receiver.open(&ct1, b"X", &tag1).unwrap();
        let pt2 = receiver.open(&ct2, b"Y", &tag2).unwrap();
        assert_eq!(pt1, b"MSG-ONE!");
        assert_eq!(pt2, b"MSG-TWO!");
    }
}
