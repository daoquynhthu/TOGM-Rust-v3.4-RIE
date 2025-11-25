#![forbid(unsafe_code)]
// SIP-64 information-theoretic MAC over GF(2^8).
// - Parallel Horner evaluation: each byte of the 64-byte key is an independent x_i.
// - Constant-time: fixed iterations, no data-dependent branches or memory accesses.
// - No unsafe and no table lookups, avoiding cache-based side channels.
// - Suitable for message integrity and DBAP proofs per the whitepaper.

use crate::core::gf256::GF256;

pub const MAC_LEN: usize = 64;

/// Compute SIP-64 tag for `metadata || ciphertext` with a 64-byte GF(2^8) key.
#[inline(always)]
pub fn sip64_tag(ciphertext: &[u8], metadata: &[u8], mac_key: &[u8; MAC_LEN]) -> [u8; MAC_LEN] {
    let mut xs: [GF256; MAC_LEN] = [GF256(0); MAC_LEN];
    for i in 0..MAC_LEN { xs[i] = GF256(mac_key[i]); }
    let mut acc: [GF256; MAC_LEN] = [GF256(0); MAC_LEN];
    for &c in metadata.iter().rev() {
        let gc = GF256(c);
        let mut i = 0;
        while i + 4 <= MAC_LEN {
            acc[i] = acc[i] * xs[i] + gc;
            acc[i + 1] = acc[i + 1] * xs[i + 1] + gc;
            acc[i + 2] = acc[i + 2] * xs[i + 2] + gc;
            acc[i + 3] = acc[i + 3] * xs[i + 3] + gc;
            i += 4;
        }
        while i < MAC_LEN {
            acc[i] = acc[i] * xs[i] + gc;
            i += 1;
        }
    }
    for &c in ciphertext.iter().rev() {
        let gc = GF256(c);
        let mut i = 0;
        while i + 4 <= MAC_LEN {
            acc[i] = acc[i] * xs[i] + gc;
            acc[i + 1] = acc[i + 1] * xs[i + 1] + gc;
            acc[i + 2] = acc[i + 2] * xs[i + 2] + gc;
            acc[i + 3] = acc[i + 3] * xs[i + 3] + gc;
            i += 4;
        }
        while i < MAC_LEN {
            acc[i] = acc[i] * xs[i] + gc;
            i += 1;
        }
    }
    let mut out = [0u8; MAC_LEN];
    for i in 0..MAC_LEN { out[i] = acc[i].0; }
    out
}

/// Constant-time equality check for two 64-byte tags.
#[inline(always)]
pub fn ct_eq(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..MAC_LEN { diff |= a[i] ^ b[i]; }
    diff == 0
}

/// Verify a SIP-64 tag in constant time.
#[inline(always)]
pub fn verify(ciphertext: &[u8], metadata: &[u8], mac_key: &[u8; MAC_LEN], tag: &[u8; MAC_LEN]) -> bool {
    let computed = sip64_tag(ciphertext, metadata, mac_key);
    ct_eq(&computed, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sip64_tag_consistency() {
        let ct = [0x10u8, 0x20, 0x30, 0x40, 0x50];
        let md = [0xAAu8, 0xBB, 0xCC];
        let mut key = [0u8; MAC_LEN];
        for i in 0..MAC_LEN { key[i] = i as u8; }
        let t1 = sip64_tag(&ct, &md, &key);
        let t2 = sip64_tag(&ct, &md, &key);
        assert_eq!(t1, t2);
        assert!(verify(&ct, &md, &key, &t1));
        let mut wrong = t1;
        wrong[0] ^= 1;
        assert!(!verify(&ct, &md, &key, &wrong));
    }
}
// End of SIP-64 module.
