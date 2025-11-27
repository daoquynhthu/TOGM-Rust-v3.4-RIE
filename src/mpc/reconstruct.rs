//! Secret reconstruction from shares.
//!
//! This module implements Lagrange interpolation over GF(256) to reconstruct
//! the original secret from a threshold number of shares.
//!
//! # Security
//! - **Constant-Time**: Uses `GF256` arithmetic.
//! - **Validation**: Checks for duplicate indices and length mismatches.
//!
//! # Whitepaper Compliance
//! - Section 2.5: Secret Reconstruction.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroizing;
use crate::core::gf256::GF256;
use crate::mpc::{MpcError, share::Share};

/// Reconstructs the secret from a list of shares.
///
/// Uses Lagrange interpolation at x=0 to recover the polynomial intercept (the secret).
///
/// # Arguments
/// * `shares` - A slice of shares to reconstruct from.
/// * `k` - The threshold number of shares required.
///
/// # Returns
/// * `Ok(Vec<u8>)` - The reconstructed secret.
/// * `Err(MpcError)` - If inputs are invalid (mismatch lengths, duplicates, insufficient shares, etc.).
pub fn reconstruct_secret(shares: &[Share], k: u8) -> Result<Vec<u8>, MpcError> {
    if shares.is_empty() {
        return Err(MpcError::InsufficientShares);
    }
    // Validation: Check if we have enough shares
    if shares.len() < k as usize {
        return Err(MpcError::InsufficientShares);
    }

    let num_shares = shares.len();
    let share_len = shares[0].value.len();

    // 1. Validation
    // Check all shares have the same length
    for share in shares {
        if share.value.len() != share_len {
            return Err(MpcError::ShareLengthMismatch);
        }
    }

    // Check for duplicate indices
    // Optimized to O(N) using a boolean array
    let mut seen = [false; 256];
    for share in shares {
        let idx = share.identifier as usize;
        if seen[idx] {
            return Err(MpcError::DuplicateShareIndex);
        }
        seen[idx] = true;
    }

    // 2. Precompute Lagrange basis polynomials at x=0
    // lambda_j = product_{m != j} (x_m / (x_m - x_j))
    // Note: in GF(2^8), subtraction is addition (XOR).
    // So lambda_j = product_{m != j} (x_m / (x_m + x_j))
    
    // Zeroizing wrapper to protect sensitive Lagrange coefficients
    let mut lambdas = Zeroizing::new(Vec::with_capacity(num_shares));
    for j in 0..num_shares {
        let xj = GF256(shares[j].identifier);
        let mut numerator = GF256(1);
        let mut denominator = GF256(1);

        for m in 0..num_shares {
            if j == m {
                continue;
            }
            let xm = GF256(shares[m].identifier);
            
            numerator *= xm;
            denominator *= xm + xj;
        }

        // lambda_j = numerator * (denominator)^-1
        lambdas.push(numerator * denominator.inv());
    }

    // 3. Reconstruct secret byte-by-byte
    // S[p] = sum_{j} (share_j[p] * lambda_j)
    
    let mut secret = Vec::with_capacity(share_len);
    for p in 0..share_len {
        let mut sum = GF256(0);
        for j in 0..num_shares {
            let y = GF256(shares[j].value[p]);
            sum += y * lambdas[j];
        }
        secret.push(sum.0);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::quorum::split_secret;
    use crate::entropy::EntropySource;
    use crate::entropy::EntropyError;

    // Mock entropy from quorum tests
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
    fn test_reconstruct_basic() {
        let mut rng = MockEntropy { fill_val: 0x10 };
        let secret = vec![0x42, 0x99, 0xAB];
        let k = 3;
        let n = 5;

        // Split
        let shares = split_secret(&secret, k, n, &mut rng).unwrap();

        // Reconstruct with all shares
        let recovered = reconstruct_secret(&shares, k).expect("Reconstruction failed");
        assert_eq!(recovered, secret);

        // Reconstruct with subset (k shares)
        let subset = &shares[0..3];
        let recovered_subset = reconstruct_secret(subset, k).expect("Subset reconstruction failed");
        assert_eq!(recovered_subset, secret);

        // Reconstruct with different subset
        let subset2 = &[shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered_subset2 = reconstruct_secret(subset2, k).expect("Subset 2 reconstruction failed");
        assert_eq!(recovered_subset2, secret);
    }

    #[test]
    fn test_reconstruct_errors() {
        let share1 = Share::new(1, vec![1, 2]).unwrap();
        let share2 = Share::new(2, vec![3]).unwrap(); // Mismatch length
        let share3 = Share::new(1, vec![1, 2]).unwrap(); // Duplicate ID
        let k = 2;

        // Length mismatch
        assert_eq!(
            reconstruct_secret(&[share1.clone(), share2], k),
            Err(MpcError::ShareLengthMismatch)
        );

        // Duplicate index
        assert_eq!(
            reconstruct_secret(&[share1.clone(), share3], k),
            Err(MpcError::DuplicateShareIndex)
        );

        // Empty
        assert_eq!(
            reconstruct_secret(&[], k),
            Err(MpcError::InsufficientShares)
        );

        // Insufficient shares (len < k)
        assert_eq!(
            reconstruct_secret(&[share1.clone()], k),
            Err(MpcError::InsufficientShares)
        );
    }
}
