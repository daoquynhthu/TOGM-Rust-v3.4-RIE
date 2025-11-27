//! Quorum logic for Shamir's Secret Sharing over GF(256).
//!
//! This module implements the threshold logic and polynomial generation required
//! to split secrets into shares.
//!
//! # Security
//! - **Constant-Time**: Uses `GF256` arithmetic which is branch-free.
//! - **Zeroization**: Polynomial coefficients are zeroized after use.
//! - **Validation**: Checks threshold parameters ($k \le n$, $k \ge 2$).
//!
//! # Whitepaper Compliance
//! - Section 2.3: Polynomial Generation.
//! - Section 2.4: Share Calculation.

extern crate alloc;
use alloc::vec::Vec;
use zeroize::Zeroizing;
use crate::core::gf256::GF256;
use crate::mpc::{MpcError, share::Share};
use crate::entropy::{EntropySource, EntropyError};

/// Splits a secret into `n` shares, requiring `k` shares to reconstruct.
///
/// # Arguments
/// * `secret` - The secret data to split.
/// * `k` - The threshold number of shares required for reconstruction.
/// * `n` - The total number of shares to generate.
/// * `rng` - A mutable reference to an entropy source.
///
/// # Returns
/// * `Ok(Vec<Share>)` containing `n` shares on success.
/// * `Err(MpcError)` on failure (invalid params, rng failure, etc.).
pub fn split_secret<R: EntropySource + ?Sized>(
    secret: &[u8],
    k: u8,
    n: u8,
    rng: &mut R
) -> Result<Vec<Share>, MpcError> {
    // Input validation
    if secret.is_empty() {
        return Err(MpcError::EmptyShare); // Using EmptyShare to signify empty payload
    }
    if k < 2 {
        return Err(MpcError::InvalidThreshold);
    }
    if k > n {
        return Err(MpcError::InvalidThreshold);
    }
    if n == 0 {
        return Err(MpcError::InvalidShareIndex);
    }

    // Initialize storage for shares
    // We process the secret byte-by-byte, but we want to return shares
    // where each share contains the byte-slices for that share index.
    // share_values[i] corresponds to share with index i+1.
    let mut share_values: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
    for _ in 0..n {
        share_values.push(Vec::with_capacity(secret.len()));
    }

    // Temporary buffer for random coefficients (k-1 coefficients per byte)
    // We allocate this once and reuse it to minimize allocations.
    // Wrapped in Zeroizing to ensure cleanup.
    let mut random_buf = Zeroizing::new(vec![0u8; (k - 1) as usize]);

    for &byte in secret {
        // 1. Generate random coefficients for f(x) = a0 + a1*x + ... + ak-1*x^(k-1)
        // a0 is the secret byte.
        // a1..ak-1 are random.
        
        // Fill random buffer
        if k > 1 {
            match rng.fill(&mut random_buf) {
                Ok(_) => {},
                Err(_) => return Err(MpcError::RngFailure),
            }
        }

        // Construct polynomial coefficients
        // coefficients[0] = secret
        // coefficients[1..] = random
        let mut coeffs: Vec<GF256> = Vec::with_capacity(k as usize);
        coeffs.push(GF256(byte));
        for &r in random_buf.iter() {
            coeffs.push(GF256(r));
        }
        // Wrap coefficients in Zeroizing to ensure they are wiped
        let coeffs = Zeroizing::new(coeffs);

        // 2. Evaluate polynomial for each share x = 1..=n
        for i in 0..n {
            let x = GF256(i + 1); // Share indices are 1-based
            let y = evaluate_polynomial(&coeffs, x);
            share_values[i as usize].push(y.0);
        }
    }

    // Construct Share objects
    let mut shares = Vec::with_capacity(n as usize);
    for (i, value) in share_values.into_iter().enumerate() {
        // Share indices must be 1..=255
        let identifier = (i + 1) as u8;
        shares.push(Share::new(identifier, value)?);
    }

    Ok(shares)
}

/// Evaluates a polynomial at a given point x using Horner's method.
///
/// f(x) = c[0] + c[1]*x + ... + c[k-1]*x^(k-1)
///
/// # Arguments
/// * `coeffs` - Coefficients [c0, c1, ..., ck-1]
/// * `x` - The point to evaluate at
///
/// # Returns
/// * The value f(x)
#[inline(always)]
fn evaluate_polynomial(coeffs: &[GF256], x: GF256) -> GF256 {
    // Horner's method:
    // result = c[k-1]
    // result = result * x + c[k-2]
    // ...
    // result = result * x + c[0]
    
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
    use crate::entropy::EntropySource;
    
    /// Mock entropy source for deterministic testing
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
    fn test_split_secret_basic() {
        let mut rng = MockEntropy { fill_val: 0x10 };
        let secret = vec![0x42, 0x99]; // Secret bytes
        let k = 2;
        let n = 3;

        let shares = split_secret(&secret, k, n, &mut rng).expect("Split failed");

        assert_eq!(shares.len(), 3);
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.identifier, (i + 1) as u8);
            assert_eq!(share.value.len(), 2);
        }
    }

    #[test]
    fn test_invalid_params() {
        let mut rng = MockEntropy { fill_val: 0 };
        let secret = vec![1, 2, 3];

        // k > n
        assert_eq!(split_secret(&secret, 4, 3, &mut rng), Err(MpcError::InvalidThreshold));
        
        // k < 2
        assert_eq!(split_secret(&secret, 1, 3, &mut rng), Err(MpcError::InvalidThreshold));

        // empty secret
        assert_eq!(split_secret(&[], 2, 3, &mut rng), Err(MpcError::EmptyShare));
    }

    #[test]
    fn test_polynomial_eval() {
        // f(x) = 1 + 2x
        // f(1) = 1 + 2 = 3
        // f(2) = 1 + 4 = 5
        // f(3) = 1 + 6 = 7
        let coeffs = vec![GF256(1), GF256(2)];
        
        assert_eq!(evaluate_polynomial(&coeffs, GF256(1)), GF256(3));
        assert_eq!(evaluate_polynomial(&coeffs, GF256(2)), GF256(5));
        assert_eq!(evaluate_polynomial(&coeffs, GF256(3)), GF256(7));
    }
}
