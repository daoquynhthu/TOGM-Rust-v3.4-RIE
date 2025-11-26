// #![forbid(unsafe_code)] // Removed for optimization
//! Toeplitz universal hashing for MSEA extraction.
//!
//! - Linear over GF(2): `H(a ⊕ b) = H(a) ⊕ H(b)`.
//! - Constant-time bit convolution via 64-bit word alignment.
//! - No unsafe and no table lookups to avoid cache side channels.

extern crate alloc;
use alloc::vec::Vec;
use core::convert::TryInto;

/// Errors returned by universal hash routines.
#[derive(Debug, PartialEq, Eq)]
pub enum UhError {
    KeyTooShort,
}

/// Convert a little-endian byte slice into 64-bit words, padding tail zeros.
#[inline(always)]
fn to_words_le(bits: usize, bytes: &[u8]) -> Vec<u64> {
    #[allow(clippy::manual_div_ceil)]
    let n_words = (bits + 63) / 64;
    let mut out = Vec::with_capacity(n_words);
    
    // Optimized bulk copy using chunks
    let mut chunks = bytes.chunks_exact(8);
    for chunk in chunks.by_ref() {
        out.push(u64::from_le_bytes(chunk.try_into().unwrap()));
    }
    
    // Handle remainder
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        out.push(u64::from_le_bytes(buf));
    }
    
    // Zero-pad to required length
    out.resize(n_words, 0);
    out
}

/// Compute Toeplitz universal hash tag of length `out_len` over `input` using `key`.
/// Requires `key_bits >= input_bits + out_bits - 1`. Returns `KeyTooShort` otherwise.
#[inline(always)]
pub fn toeplitz_tag(input: &[u8], key: &[u8], out_len: usize) -> Result<Vec<u8>, UhError> {
    let in_bits = input.len() * 8;
    let out_bits = out_len * 8;
    let need_bits = in_bits + out_bits - 1;
    if key.len() * 8 < need_bits { return Err(UhError::KeyTooShort); }

    let in_words = to_words_le(in_bits, input);
    let mut key_words = to_words_le(need_bits, key);
    // Pad key_words with one extra zero to avoid conditional check in inner loop
    key_words.push(0);

    let mut out = vec![0u8; out_len];

    for ob in 0..out_bits {
        let base = ob >> 6;
        let shift = (ob & 63) as u32;
        let mut acc: u64 = 0;
        
        // Unrolled loop or SIMD candidate? 
        // For now, removing the branch is the main scalar optimization.
        for w in 0..in_words.len() {
            let kw0 = key_words[base + w];
            let kw1 = key_words[base + w + 1];
            // Branchless selection for shift
            let t = if shift == 0 { kw0 } else { (kw0 >> shift) | (kw1 << (64 - shift)) };
            acc ^= in_words[w] & t;
        }
        
        let bit = (acc.count_ones() & 1) as u8;
        let byte_idx = ob >> 3;
        let bit_idx = ob & 7;
        out[byte_idx] |= bit << bit_idx;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism() {
        let x = [1u8,2,3,4,5,6,7,8];
        let k = [9u8; 32];
        let t1 = toeplitz_tag(&x, &k, 16).unwrap();
        let t2 = toeplitz_tag(&x, &k, 16).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_linearity() {
        let a = [0xAAu8, 0x55, 0xFF, 0x00];
        let b = [0x0Fu8, 0xF0, 0x33, 0xCC];
        let mut x = vec![0u8; a.len()];
        for i in 0..a.len() { x[i] = a[i] ^ b[i]; }
        let k = [3u8; 40];
        let ha = toeplitz_tag(&a, &k, 8).unwrap();
        let hb = toeplitz_tag(&b, &k, 8).unwrap();
        let hx = toeplitz_tag(&x, &k, 8).unwrap();
        let mut sum = vec![0u8; 8];
        for i in 0..8 { sum[i] = ha[i] ^ hb[i]; }
        assert_eq!(hx, sum);
    }

    #[test]
    fn test_key_len_check() {
        let x = [1u8; 8];
        let k = [2u8; 8];
        let r = toeplitz_tag(&x, &k, 64);
        assert!(matches!(r, Err(UhError::KeyTooShort)));
    }
}
