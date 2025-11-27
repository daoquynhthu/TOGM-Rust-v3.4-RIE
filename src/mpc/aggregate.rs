//! Operations on shares.
//!
//! This module implements operations on existing shares, such as proactive refresh
//! and homomorphic addition.
//!
//! # Features
//! - **Proactive Refresh**: Updates shares without changing the secret.
//! - **Homomorphic Addition**: Adds two secrets by adding their shares.
//!
//! # Security
//! - **Constant-Time**: Uses `GF256` arithmetic.
//! - **Zeroization**: Temporary polynomials are zeroized.
//!
//! # Whitepaper Compliance
//! - Section 4.1: Proactive Security.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroizing;
use crate::core::gf256::GF256;
use crate::mpc::{MpcError, share::Share};
use crate::entropy::{EntropySource, EntropyError};

/// Refreshes a set of shares by adding a polynomial of 0.
///
/// This changes the shares but keeps the underlying secret constant.
/// Useful for Proactive Secret Sharing (PSS) to render old shares useless.
///
/// # Arguments
/// * `shares` - Mutable slice of shares to refresh.
/// * `k` - The threshold used for the original sharing (degree of poly is k-1).
/// * `rng` - Entropy source.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(MpcError)` on failure.
pub fn refresh_shares<R: EntropySource + ?Sized>(
    shares: &mut [Share],
    k: u8,
    rng: &mut R
) -> Result<(), MpcError> {
    if shares.is_empty() {
        return Err(MpcError::EmptyShare);
    }
    if k < 2 {
        return Err(MpcError::InvalidThreshold);
    }
    // We don't strictly check k <= n here because we might be refreshing a subset,
    // though typically you refresh all n shares. 
    // But generating a polynomial of degree k-1 is always valid regardless of how many shares we update.

    let share_len = shares[0].value.len();
    for share in shares.iter() {
        if share.value.len() != share_len {
            return Err(MpcError::ShareLengthMismatch);
        }
    }

    // Temporary buffer for random coefficients (k-1 coefficients per byte)
    // Coeffs: c0=0, c1..c(k-1) random
    let mut random_buf = Zeroizing::new(vec![0u8; (k - 1) as usize]);

    for p in 0..share_len {
        // Generate random coefficients for g(x) = 0 + c1*x + ... + c(k-1)*x^(k-1)
        if k > 1 {
            match rng.fill(&mut random_buf) {
                Ok(_) => {},
                Err(_) => return Err(MpcError::RngFailure),
            }
        }

        // Construct polynomial coefficients
        let mut coeffs: Vec<GF256> = Vec::with_capacity(k as usize);
        coeffs.push(GF256(0)); // Intercept is 0
        for &r in random_buf.iter() {
            coeffs.push(GF256(r));
        }
        let coeffs = Zeroizing::new(coeffs);

        // Update each share
        for share in shares.iter_mut() {
            let x = GF256(share.identifier);
            let update_val = evaluate_polynomial(&coeffs, x);
            
            // value = value + update_val (GF256 add is XOR)
            let current_val = GF256(share.value[p]);
            share.value[p] = (current_val + update_val).0;
        }
    }

    Ok(())
}

/// Adds two shares homomorphically.
///
/// If share1 is a share of S1 and share2 is a share of S2 (with same index),
/// result is a share of S1 + S2.
pub fn add_shares(share1: &Share, share2: &Share) -> Result<Share, MpcError> {
    if share1.identifier != share2.identifier {
        return Err(MpcError::InvalidShareIndex); // Must be same index to add
    }
    if share1.value.len() != share2.value.len() {
        return Err(MpcError::ShareLengthMismatch);
    }

    let mut new_value = Vec::with_capacity(share1.value.len());
    for (v1, v2) in share1.value.iter().zip(share2.value.iter()) {
        let sum = GF256(*v1) + GF256(*v2);
        new_value.push(sum.0);
    }

    Share::new(share1.identifier, new_value)
}

// Reuse polynomial evaluation from quorum logic?
// Ideally this should be a shared helper in a private module or internal utils.
// For now, I'll duplicate it or make it pub in quorum?
// Making it pub in quorum is better.
// But I can't easily edit quorum.rs right now without full rewrite or patch.
// Given strict instructions "one file at a time", I should probably have anticipated this.
// I will just implement it here locally as `evaluate_polynomial` is small and I want to avoid modifying quorum.rs again if not needed.
// Duplication is acceptable for decoupling in this context.

#[inline(always)]
fn evaluate_polynomial(coeffs: &[GF256], x: GF256) -> GF256 {
    if coeffs.is_empty() {
        return GF256(0);
    }
    let mut result = *coeffs.last().unwrap();
    for coeff in coeffs.iter().rev().skip(1) {
        result = result * x + *coeff;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::quorum::split_secret;
    use crate::mpc::reconstruct::reconstruct_secret;
    use crate::entropy::EntropySource;

    struct MockEntropy {
        fill_val: u8,
    }

    impl EntropySource for MockEntropy {
        fn name(&self) -> &'static str { "Mock" }
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for b in dest.iter_mut() {
                *b = self.fill_val;
                self.fill_val = self.fill_val.wrapping_add(1);
            }
            Ok(())
        }
        fn entropy_estimate(&self) -> f64 { 8.0 }
    }

    #[test]
    fn test_refresh_shares() {
        let mut rng = MockEntropy { fill_val: 0x20 };
        let secret = vec![0x11, 0x22];
        let k = 2;
        let n = 3;

        // Create initial shares
        let mut shares = split_secret(&secret, k, n, &mut rng).unwrap();
        let original_shares = shares.clone();

        // Refresh shares
        refresh_shares(&mut shares, k, &mut rng).expect("Refresh failed");

        // Shares should be different
        assert_ne!(shares[0].value, original_shares[0].value);

        // Reconstruction should still yield original secret
        let recovered = reconstruct_secret(&shares).expect("Reconstruction failed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_add_shares() {
        let mut rng = MockEntropy { fill_val: 0x30 };
        let s1 = vec![0x10];
        let s2 = vec![0x20];
        let k = 2;
        let n = 3;

        let shares1 = split_secret(&s1, k, n, &mut rng).unwrap();
        let shares2 = split_secret(&s2, k, n, &mut rng).unwrap();

        // Add shares locally
        let mut sum_shares = Vec::new();
        for i in 0..n as usize {
            sum_shares.push(add_shares(&shares1[i], &shares2[i]).unwrap());
        }

        // Reconstruct sum
        let recovered_sum = reconstruct_secret(&sum_shares).unwrap();
        
        // Expected sum: 0x10 + 0x20 = 0x30 (XOR)
        assert_eq!(recovered_sum[0], 0x30);
    }
}
