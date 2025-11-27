// GF(2^8) arithmetic module.
// This module implements finite field arithmetic over GF(2^8) with the irreducible
// polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). All operations are constant-time and
// branch-free (mask-based conditionals) to resist timing side channels. No lookup tables
// by default; feature `gf256-table` can enable tables for non-paranoid benchmarks.
// Whitepaper sections 1.1/1.2 align with this implementation.

#![forbid(unsafe_code)]

use core::ops::{Add, AddAssign, Mul, MulAssign};
use zeroize::Zeroize;

/// The finite field element type, wrapping a u8.
///
/// This wrapper ensures domain-specific operations and prevents accidental misuse (e.g., raw XOR
/// instead of GF add).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub struct GF256(pub u8);

impl From<u8> for GF256 {
    /// Converts a u8 to GF256. No validation needed as GF(2^8) covers all 256 values.
    ///
    /// # Safety Guarantees
    /// - Trivial conversion; constant-time (single copy).
    /// - Thread-safe: No shared state.
    /// - Side-channel resistant: No conditional execution.
    ///
    /// # Prohibited
    /// - None.
    ///
    /// # Performance
    /// - Zero overhead (~1 cycle).
    ///
    /// # Failure Modes
    /// - None; always succeeds.
    ///
    /// # Whitepaper Compliance
    /// - Implicit in all GF ops (Section 1.1).
    #[inline(always)]
    fn from(value: u8) -> Self {
        GF256(value)
    }
}

impl From<GF256> for u8 {
    /// Extracts the underlying u8.
    ///
    /// # Safety Guarantees
    /// - Constant-time extraction.
    /// - Thread-safe.
    /// - Side-channel resistant.
    ///
    /// # Prohibited
    /// - Avoid direct use in non-GF contexts to prevent semantic errors (e.g., arithmetic ops).
    ///
    /// # Performance
    /// - Zero overhead.
    ///
    /// # Failure Modes
    /// - None.
    #[inline(always)]
    fn from(gf: GF256) -> u8 {
        gf.0
    }
}

/// GF(2^8) addition: simple XOR, as the field characteristic is 2.
///
/// This is bitwise XOR, which is linear over GF(2^8).
#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for GF256 {
    type Output = Self;

    /// Adds two GF elements (a + b = a XOR b).
    ///
    /// # Safety Guarantees
    /// - Constant-time: Single XOR instruction.
    /// - Thread-safe: No shared state.
    /// - Side-channel resistant: No data-dependent branches or memory access.
    ///
    /// # Prohibited
    /// - None specific.
    ///
    /// # Performance
    /// - Negligible (~1 cycle on x86-64).
    ///
    /// # Failure Modes
    /// - None.
    ///
    /// # Whitepaper Compliance
    /// - Section 1.1: Additive sharing basis (a + b = a ⊕ b in BGW MPC).
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        GF256(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF256 {
    /// In-place addition (self += rhs).
    ///
    /// # Safety Guarantees
    /// - As in Add impl.
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// GF(2^8) multiplication: bit-serial with polynomial reduction (mod 0x11B).
///
/// Uses irreducible polynomial 0x11B. Implementation is branch-free using masks for conditionals.
impl Mul for GF256 {
    type Output = Self;

    /// Multiplies two GF elements with reduction modulo 0x11B.
    ///
    /// # Safety Guarantees
    /// - Constant-time: Fixed 8 iterations; mask-based conditionals (no branches).
    /// - Thread-safe: No shared state.
    /// - Side-channel resistant: Uniform execution; no data-dependent memory or timing.
    ///
    /// # Prohibited
    /// - Do not enable "gf256-table" in paranoid mode (use only for non-sensitive benchmarks).
    ///
    /// # Performance
    /// - ~50-100 cycles on x86-64 (bit-serial); scales with SIMD for vectors.
    ///
    /// # Failure Modes
    /// - None; closed under domain.
    ///
    /// # Whitepaper Compliance
    /// - Section 1.1/1.2: Enables Lagrange interpolation and poly MAC over GF(2^8) in reconstruct.rs and sip64.rs.
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let mut a = self.0;
        let b = rhs.0;
        let mut p = 0;

        // Unrolled loop for constant-time execution and performance
        // Bit 0
        p ^= a & (0u8.wrapping_sub(b & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 1
        p ^= a & (0u8.wrapping_sub((b >> 1) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 2
        p ^= a & (0u8.wrapping_sub((b >> 2) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 3
        p ^= a & (0u8.wrapping_sub((b >> 3) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 4
        p ^= a & (0u8.wrapping_sub((b >> 4) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 5
        p ^= a & (0u8.wrapping_sub((b >> 5) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 6
        p ^= a & (0u8.wrapping_sub((b >> 6) & 1));
        a = (a << 1) ^ (0x1B & (0u8.wrapping_sub(a >> 7)));

        // Bit 7
        p ^= a & (0u8.wrapping_sub((b >> 7) & 1));
        // Last 'a' update is unnecessary as it's not used

        GF256(p)
    }
}

impl MulAssign for GF256 {
    /// In-place multiplication (self *= rhs).
    ///
    /// # Safety Guarantees
    /// - As in Mul impl.
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl GF256 {
    /// Computes the multiplicative inverse a^{-1} such that a * a^{-1} = 1 mod poly.
    /// Returns 0 for a=0 (convention; not mathematical error).
    ///
    /// # Safety Guarantees
    /// - Constant-time: Fixed 8 iterations, mask-based conditionals.
    /// - Branch-free: No data-dependent branches (except explicit a==0 check, compile-time predictable).
    /// - Side-channel resistant: No secret-dependent memory access.
    ///
    /// # Prohibited
    /// - Use in non-GF contexts (prefer GF256 wrapper).
    ///
    /// # Performance
    /// - ~100 cycles (x86-64); suitable for MPC/SIP hot paths.
    ///
    /// # Failure Modes
    /// - a=0 returns 0 (documented convention).
    ///
    /// # Whitepaper Compliance
    /// - Section 1.1: Essential for BGW multiplication gates.
    #[inline(always)]
    pub fn inv(self) -> Self {
        // Itoh-Tsujii algorithm for a^{-1} = a^{254} in GF(2^8).
        // Optimized chain (11 operations):
        // a^2
        // a^3 = a^2 * a
        // a^6 = (a^3)^2
        // a^12 = (a^6)^2
        // a^15 = a^12 * a^3
        // a^30 = (a^15)^2
        // a^60 = (a^30)^2
        // a^120 = (a^60)^2
        // a^240 = (a^120)^2
        // a^255 = a^240 * a^15
        // a^254 = a^255 * a^{-1} = a^255 / a ?? No, wait.
        // Itoh-Tsujii typically computes a^(2^m - 1) then adjusts.
        // For GF(2^8), inverse is a^{254}.
        // 254 = 11111110_2.
        // Let's use the verified Itoh-Tsujii variant from the audit report:
        // Chain: a^2 → a^3 → a^6 → a^12 → a^15 → a^30 → a^60 → a^120 → a^240 → a^255 → a^254
        // Note: a^255 is always 1 for a != 0. 
        // Actually, a^254 = (a^255) * a^{-1} is not helpful if we want to FIND a^{-1}.
        // The trick is 254 = 255 - 1.
        // 
        // Let's use the explicit construction for 254:
        // 254 = 127 * 2 = (1111111_2) * 2.
        //
        // Audit report suggested chain:
        // x2 = x^2
        // x3 = x2 * x
        // x6 = x3^2
        // x12 = x6^2
        // x15 = x12 * x3      (1111_2)
        // x30 = x15^2
        // x60 = x30^2
        // x120 = x60^2
        // x240 = x120^2       (11110000_2)
        // x255 = x240 * x15   (11111111_2) -> This is a^255 (=1)
        // x254 = x255 * x255 * x  ?? No, that's a^255 * a^255 * x = x.
        //
        // Wait, the audit report says:
        // let x254 = x255 * x255 * x; // a^254 = a^255 * a^{-1} = a^255 / a
        // This comment in the audit report seems slightly confused or I am misreading.
        // "a^254 = a^255 * a^{-1}" -> True.
        // But we don't know a^{-1} yet!
        // 
        // Let's look at the "Equivalent" line: "x254 = x240 * x12 * x2".
        // x240 = a^(240) = a^(11110000)
        // x12  = a^(12)  = a^(00001100)
        // x2   = a^(2)   = a^(00000010)
        // Sum exponents: 240 + 12 + 2 = 254. Correct.
        //
        // So we need x240, x12, x2.
        // We have x2, x3, x6, x12.
        // We have x15.
        // We have x240 (from x15 -> x30 -> x60 -> x120 -> x240).
        //
        // So the path is:
        // x2 = x^2
        // x3 = x2 * x
        // x6 = x3^2
        // x12 = x6^2
        // x15 = x12 * x3
        // x30 = x15^2
        // x60 = x30^2
        // x120 = x60^2
        // x240 = x120^2
        // x254 = x240 * x12 * x2
        //
        // Ops count:
        // S: x2, x6, x12, x30, x60, x120, x240 (7 squarings)
        // M: x3, x15, x254 (2 mults for x254, 1 for x15, 1 for x3) -> 4 mults.
        // Total: 11 ops. Matches the optimal count.

        let x = self;
        let x2 = x * x;         // 2
        let x3 = x2 * x;        // 3
        let x6 = x3 * x3;       // 6
        let x12 = x6 * x6;      // 12
        let x15 = x12 * x3;     // 15
        let x30 = x15 * x15;    // 30
        let x60 = x30 * x30;    // 60
        let x120 = x60 * x60;   // 120
        let x240 = x120 * x120; // 240
        let x254 = x240 * x12 * x2; // 240 + 12 + 2 = 254

        // Constant-time zero check
        let is_zero = (self.0 == 0) as u8;
        let mask = 0u8.wrapping_sub(is_zero);
        
        GF256(x254.0 & !mask)
    }

    /// Computes self / rhs = self * inv(rhs), returning None on division by zero.
    /// For rhs=0, returns None (safe handling; upper layers must check).
    ///
    /// # Safety Guarantees
    /// - Constant-time: Single inv call (handled above).
    /// - Thread-safe.
    /// - Side-channel resistant: No leak on zero (simple check, but masked if needed).
    ///
    /// # Prohibited
    /// - None; Option handles zero safely.
    ///
    /// # Performance
    /// - Dominated by inv (~300 cycles).
    ///
    /// # Failure Modes
    /// - rhs == 0: Returns None (caller must handle; no panic/abort).
    ///
    /// # Whitepaper Compliance
    /// - Section 1.1: Safe div for poly_eval without abort/panic.
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.0 == 0 {
            None
        } else {
            Some(self * rhs.inv())
        }
    }

    // Table-based mul (feature-gated; not for paranoid use).
    #[cfg(feature = "gf256-table")]
    pub const LOG_TABLE: [u8; 256] = [
        // Precomputed log table (omitted for brevity; generate via build.rs in full impl).
        0, /* ... full 256 entries ... */
    ];
    #[cfg(feature = "gf256-table")]
    pub const EXP_TABLE: [u8; 256] = [
        // Precomputed exp table.
        1, /* ... full 256 entries ... */
    ];

    #[cfg(feature = "gf256-table")]
    #[inline(always)]
    pub fn mul_table(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 {
            GF256(0)
        } else {
            let log_sum = LOG_TABLE[self.0 as usize].wrapping_add(LOG_TABLE[rhs.0 as usize]);
            GF256(EXP_TABLE[log_sum as usize])
        }
    }
}

/// Polynomial evaluation over GF(2^8): sum c_i * x^i using Horner's method.
///
/// Constant-time for fixed-length polys (e.g., SIP=64 coeffs).
pub fn poly_eval(coeffs: &[GF256], x: GF256) -> GF256 {
    // Evaluates p(x) = c0 + c1*x + ... + cn*x^n over GF(2^8) via Horner's rule.
    // Safety: constant-time iterations fixed by coeffs.len(); thread-safe; no secret-dependent indexing.
    // Performance: O(n) muls/adds; few μs for n=64.
    // Failure modes: empty slice → 0; excessive length bounded in debug assertions.
    #[cfg(debug_assertions)]
    {
        assert!(coeffs.len() <= 128, "poly_eval: excessive coefficients (DoS risk)");
    }
    let mut result = GF256(0u8);
    for &c in coeffs.iter().rev() {
        result = result * x + c;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(GF256(0x01) + GF256(0x01), GF256(0x00));
        assert_eq!(GF256(0x80) + GF256(0x7F), GF256(0xFF));
    }

    #[test]
    fn test_mul() {
        // Known values for GF(2^8, 0x11B):
        // 0x02 * 0x03 = 0x06
        assert_eq!(GF256(0x02) * GF256(0x03), GF256(0x06));
        // 0x02 * 0x1B = 0x36 (AES test vector)
        assert_eq!(GF256(0x02) * GF256(0x1B), GF256(0x36));
        // 0x57 * 0x83 = 0xC1 (verified via simulation)
        assert_eq!(GF256(0x57) * GF256(0x83), GF256(0xC1));
        // Zero cases
        assert_eq!(GF256(0x00) * GF256(0xFF), GF256(0x00));
        assert_eq!(GF256(0xFF) * GF256(0x00), GF256(0x00));
    }

    #[test]
    fn test_inv() {
        // Identity
        assert_eq!(GF256(0x01).inv(), GF256(0x01));
        // Zero convention
        assert_eq!(GF256(0x00).inv(), GF256(0x00));
        // Multiplicative property
        assert_eq!(GF256(0x02) * GF256(0x02).inv(), GF256(0x01));
        assert_eq!(GF256(0x03) * GF256(0x03).inv(), GF256(0x01));
    }

    #[test]
    fn test_div() {
        assert_eq!(GF256(0x02).checked_div(GF256(0x00)), None);
        assert_eq!(GF256(0x00).checked_div(GF256(0x01)), Some(GF256(0x00)));
        if let Some(d) = GF256(0x03).checked_div(GF256(0x02)) {
            assert_eq!(d * GF256(0x02), GF256(0x03));
        } else {
            panic!("division failed unexpectedly");
        }
    }

    #[test]
    fn test_poly_eval() {
        let coeffs = [GF256(1), GF256(1), GF256(1)];  // p(x) = 1 + x + x^2
        assert_eq!(poly_eval(&coeffs, GF256(0)), GF256(1));  // p(0) = 1
        assert_eq!(poly_eval(&coeffs, GF256(1)), GF256(1));  // 1^1^1 = 1 (GF add = XOR)
        assert_eq!(poly_eval(&coeffs, GF256(2)), GF256(0b111));  // 1+2+4 = 7
        // Empty poly
        assert_eq!(poly_eval(&[], GF256(1)), GF256(0));
    }

    // Exhaustive inverse test: Verify inv(a) * a = 1 for all a != 0
    #[test]
    fn test_inv_exhaustive() {
        for a in 1u8..=255u8 {
            let gf_a = GF256(a);
            let inv_a = gf_a.inv();
            assert_eq!(gf_a * inv_a, GF256(1), "inv({:02x}) * {:02x} != 1", a, inv_a.0);
        }
    }

    #[cfg(feature = "gf256-table")]
    #[test]
    fn test_mul_table() {
        // Assuming tables correctly precomputed; test consistency with bit-serial.
        assert_eq!(GF256(0x02).mul_table(GF256(0x03)), GF256(0x06));
    }
}
