//! Encrypted Storage for Pad Shares.
//!
//! This module provides encryption and decryption for local storage of pad shares
//! (or the pad itself) using Scrypt for key derivation and BLAKE3 for
//! stream encryption and authentication.
//!
//! # Scheme
//! 1. **KDF**: Scrypt(password, salt) -> Master Key (MK)
//! 2. **Derivation**: 
//!    - EncKey = BLAKE3_KDF(MK, context="TOGM_V3.4_SHARE_ENC")
//!    - MacKey = BLAKE3_KDF(MK, context="TOGM_V3.4_SHARE_MAC")
//! 3. **Encryption**: XOR(Plaintext, BLAKE3_XOF(EncKey))
//! 4. **MAC**: BLAKE3_Keyed(MacKey, Ciphertext)
//! 5. **Format**: `[Salt (32)] [MAC (32)] [Ciphertext (...)]`
//!
//! # Security
//! - **Scrypt**: Resistance against brute-force/ASIC attacks.
//! - **Encrypt-then-MAC**: Ensures integrity before decryption.
//! - **Constant-time MAC check**: Via BLAKE3 equality checks (or manual).
//!
//! # Whitepaper Compliance
//! - Section 1.2: Encryption of local state.

use alloc::vec::Vec;
use crate::entropy::EntropySource;
use super::PadError;
use zeroize::Zeroizing;

const SALT_LEN: usize = 32;
const MAC_LEN: usize = 32;
// Scrypt parameters: N=32768 (2^15), r=8, p=1
// Adjusted for mobile/desktop balance.
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Encrypts a data slice using a password.
pub fn encrypt_share<R: EntropySource + ?Sized>(
    data: &[u8],
    password: &[u8],
    rng: &mut R
) -> Result<Vec<u8>, PadError> {
    // 1. Generate Salt
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt).map_err(|_| PadError::CryptoError)?;

    // 2. Derive Master Key (MK) via Scrypt
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, scrypt::Params::RECOMMENDED_LEN)
        .map_err(|_| PadError::CryptoError)?;
    
    let mut mk = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, &salt, &params, &mut *mk)
        .map_err(|_| PadError::CryptoError)?;

    // 3. Derive Subkeys
    let enc_key = derive_subkey(&mk, "TOGM_V3.4_SHARE_ENC");
    let mac_key = derive_subkey(&mk, "TOGM_V3.4_SHARE_MAC");

    // 4. Encrypt (Stream Cipher via BLAKE3 XOF)
    let mut ciphertext = vec![0u8; data.len()];
    apply_keystream(&enc_key, data, &mut ciphertext);

    // 5. Compute MAC
    let mac = compute_mac(&mac_key, &ciphertext);

    // 6. Assemble: Salt || MAC || Ciphertext
    let mut result = Vec::with_capacity(SALT_LEN + MAC_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&mac);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts a data slice using a password.
pub fn decrypt_share(
    encrypted_data: &[u8],
    password: &[u8]
) -> Result<Vec<u8>, PadError> {
    if encrypted_data.len() < SALT_LEN + MAC_LEN {
        return Err(PadError::IntegrityFailure);
    }

    // 1. Parse components
    let (salt, rest) = encrypted_data.split_at(SALT_LEN);
    let (stored_mac, ciphertext) = rest.split_at(MAC_LEN);

    // 2. Re-derive Master Key
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, scrypt::Params::RECOMMENDED_LEN)
        .map_err(|_| PadError::CryptoError)?;
    
    let mut mk = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &params, &mut *mk)
        .map_err(|_| PadError::CryptoError)?;

    // 3. Re-derive Subkeys
    let enc_key = derive_subkey(&mk, "TOGM_V3.4_SHARE_ENC");
    let mac_key = derive_subkey(&mk, "TOGM_V3.4_SHARE_MAC");

    // 4. Verify MAC
    let computed_mac = compute_mac(&mac_key, ciphertext);
    // Constant-time comparison
    if !constant_time_eq(stored_mac, &computed_mac) {
        return Err(PadError::IntegrityFailure);
    }

    // 5. Decrypt
    let mut plaintext = vec![0u8; ciphertext.len()];
    apply_keystream(&enc_key, ciphertext, &mut plaintext);

    Ok(plaintext)
}

// --- Helpers ---

fn derive_subkey(mk: &[u8; 32], context: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(mk);
    Zeroizing::new(hasher.finalize().into())
}

fn apply_keystream(key: &[u8; 32], input: &[u8], output: &mut [u8]) {
    // Use BLAKE3 in XOF mode as a stream cipher
    let mut output_reader = blake3::Hasher::new_keyed(key).finalize_xof();
    
    // Process in chunks to avoid large allocations for keystream
    // But for XOR, we can just byte-by-byte or chunk
    let mut stream_byte = [0u8; 1];
    for (i, &in_byte) in input.iter().enumerate() {
        output_reader.fill(&mut stream_byte);
        output[i] = in_byte ^ stream_byte[0];
    }
}

fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::Hasher::new_keyed(key).update(data).finalize().into()
}

// Simple constant-time comparison for MACs
#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{EntropyError, EntropySource};

    struct MockEntropy;
    impl EntropySource for MockEntropy {
        fn name(&self) -> &'static str { "Mock" }
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            // Deterministic salt for testing
            for (i, b) in dest.iter_mut().enumerate() {
                *b = i as u8;
            }
            Ok(())
        }
        fn entropy_estimate(&self) -> f64 { 8.0 }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = MockEntropy;
        let password = b"correct-horse-battery-staple";
        let secret_data = b"This is a secret message!";

        let encrypted = encrypt_share(secret_data, password, &mut rng).unwrap();
        
        // Ensure ciphertext is different
        assert_ne!(secret_data, &encrypted[SALT_LEN + MAC_LEN..]);

        let decrypted = decrypt_share(&encrypted, password).unwrap();
        assert_eq!(secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_bad_password() {
        let mut rng = MockEntropy;
        let password = b"password123";
        let secret_data = b"Secret";

        let encrypted = encrypt_share(secret_data, password, &mut rng).unwrap();
        let wrong_password = b"password124";

        let result = decrypt_share(&encrypted, wrong_password);
        assert_eq!(result, Err(PadError::IntegrityFailure));
    }

    #[test]
    fn test_integrity_tamper() {
        let mut rng = MockEntropy;
        let password = b"password";
        let secret_data = b"Secret";

        let mut encrypted = encrypt_share(secret_data, password, &mut rng).unwrap();
        
        // Tamper with the MAC
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let result = decrypt_share(&encrypted, password);
        assert_eq!(result, Err(PadError::IntegrityFailure));
    }
}
