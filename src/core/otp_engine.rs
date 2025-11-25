#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;

use core::convert::TryInto;

use crate::core::xor::xor;
use crate::core::sip64::{sip64_tag, verify as verify_sip64, MAC_LEN};


#[derive(Debug, PartialEq, Eq)]
pub enum OtpError {
    KeystreamTooShort,
    BlockTooSmall,
    TagMismatch,
}

/// Constant-time OTP encryption using the shared `xor()` path.
/// Requires `keystream.len() >= plaintext.len()`. Returns `KeystreamTooShort` on failure.
#[inline(always)]
pub fn encrypt(plaintext: &[u8], keystream: &[u8]) -> Result<Vec<u8>, OtpError> {
    if keystream.len() < plaintext.len() {
        return Err(OtpError::KeystreamTooShort);
    }
    let mut out = vec![0u8; plaintext.len()];
    xor(plaintext, keystream, &mut out);
    Ok(out)
}

/// Constant-time OTP decryption via the same `xor()` path as encryption.
#[inline(always)]
pub fn decrypt(ciphertext: &[u8], keystream: &[u8]) -> Result<Vec<u8>, OtpError> {
    encrypt(ciphertext, keystream)
}


/// Combined API: encrypt with `keystream` and generate a SIP-64 MAC using `mac_key`.
/// The `block` layout is `keystream || mac_key(64B)`.
#[inline(always)]
pub fn encrypt_and_tag(plaintext: &[u8], metadata: &[u8], block: &[u8]) -> Result<(Vec<u8>, [u8; MAC_LEN]), OtpError> {
    if block.len() < plaintext.len() + MAC_LEN {
        return Err(OtpError::BlockTooSmall);
    }
    let (keystream, mac_key_slice) = block.split_at(plaintext.len());
    let mac_key: &[u8; MAC_LEN] = mac_key_slice[..MAC_LEN].try_into().map_err(|_| OtpError::BlockTooSmall)?;
    let ct = encrypt(plaintext, keystream)?;
    let tag = sip64_tag(&ct, metadata, mac_key);
    Ok((ct, tag))
}

/// Combined API: verify MAC first (Encrypt-then-MAC), then decrypt.
#[inline(always)]
pub fn decrypt_and_verify(ciphertext: &[u8], metadata: &[u8], block: &[u8], expected_tag: &[u8; MAC_LEN]) -> Result<Vec<u8>, OtpError> {
    if block.len() < ciphertext.len() + MAC_LEN {
        return Err(OtpError::BlockTooSmall);
    }
    let (keystream, mac_key_slice) = block.split_at(ciphertext.len());
    let mac_key: &[u8; MAC_LEN] = mac_key_slice[..MAC_LEN].try_into().map_err(|_| OtpError::BlockTooSmall)?;
    let valid = verify_sip64(ciphertext, metadata, mac_key, expected_tag);
    if !valid {
        return Err(OtpError::TagMismatch);
    }
    decrypt(ciphertext, keystream)
}


/// Split a `block` into `(&keystream, &mac_key)` with strict bounds checking.
#[inline(always)]
pub fn split_block(block: &[u8], payload_len: usize) -> Result<(&[u8], &[u8; MAC_LEN]), OtpError> {
    if block.len() < payload_len + MAC_LEN {
        return Err(OtpError::BlockTooSmall);
    }
    let (keystream, mac_key_slice) = block.split_at(payload_len);
    let mac_key: &[u8; MAC_LEN] = mac_key_slice[..MAC_LEN].try_into().map_err(|_| OtpError::BlockTooSmall)?;
    Ok((keystream, mac_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let p = [1u8, 2, 3, 4, 5, 6];
        let k = [6u8, 5, 4, 3, 2, 1];
        let ct = encrypt(&p, &k).unwrap();
        let pt = decrypt(&ct, &k).unwrap();
        assert_eq!(pt, p);
    }

    #[test]
    fn test_sip64_tag_verify() {
        let ct = [10u8, 20, 30, 40, 50, 60, 70];
        let md = [0xAAu8, 0xBB, 0xCC];
        let mut key = [0u8; MAC_LEN];
        for i in 0..MAC_LEN { key[i] = i as u8; }
        let t1 = sip64_tag(&ct, &md, &key);
        let t2 = sip64_tag(&ct, &md, &key);
        assert_eq!(t1, t2);
        assert!(verify_sip64(&ct, &md, &key, &t1));
        let mut wrong = t1;
        wrong[0] ^= 1;
        assert!(!verify_sip64(&ct, &md, &key, &wrong));
    }

    #[test]
    fn test_encrypt_and_decrypt_with_block() {
        let p = [1u8, 2, 3, 4, 5];
        let mut block = Vec::new();
        block.extend_from_slice(&[9u8, 9, 9, 9, 9]);
        let mut mac_key = [0u8; MAC_LEN];
        for i in 0..MAC_LEN { mac_key[i] = (i as u8).wrapping_mul(3); }
        block.extend_from_slice(&mac_key);
        let (ct, tag) = encrypt_and_tag(&p, b"m", &block).unwrap();
        let pt = decrypt_and_verify(&ct, b"m", &block, &tag).unwrap();
        assert_eq!(pt, p);
    }
}
