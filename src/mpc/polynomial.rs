//! Polynomial operations for MPC.
//!
//! This module provides shared polynomial functions used by quorum, aggregate,
//! and reconstruct modules to avoid code duplication.

use crate::core::gf256::GF256;

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
pub(crate) fn evaluate_polynomial(coeffs: &[GF256], x: GF256) -> GF256 {
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
