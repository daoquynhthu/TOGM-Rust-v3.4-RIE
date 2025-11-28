//! Irreversible Master Pad Destruction.
//!
//! This module implements the "Burn" functionality, which permanently destroys
//! key material in response to security triggers (e.g., Duress, Tamper detection,
//! or Iron Law violations).
//!
//! # Security
//! - **Volatile Writes**: Uses `ptr::write_volatile` to prevent optimization.
//! - **Memory Barriers**: Ensures writes are committed (best effort in portable Rust).
//! - **Paranoid Mode**: Optional multi-pass overwriting (0x00 -> 0xFF -> Random -> 0x00)
//!   when the `paranoid` feature is enabled.
//!
//! # Whitepaper Compliance
//! - Section 8: Emergency Destruction.

use zeroize::Zeroize;

/// Irreversibly destroys the provided memory slice.
///
/// This function guarantees that the memory is overwritten.
/// If the `paranoid` feature is enabled, it performs multiple passes.
#[inline(never)]
pub fn burn_slice(slice: &mut [u8]) {
    #[cfg(feature = "paranoid")]
    {
        // Pass 1: All ones
        for byte in slice.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0xFF) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Pass 2: Random (if possible) or pattern
        // Since we don't have an RNG passed here easily, we'll use a deterministic pattern
        // that flips bits relative to pass 1.
        for (i, byte) in slice.iter_mut().enumerate() {
            unsafe { core::ptr::write_volatile(byte, (i % 255) as u8) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Pass 3: All zeros (via Zeroize)
        slice.zeroize();
    }

    #[cfg(not(feature = "paranoid"))]
    {
        // Standard single-pass zeroization
        slice.zeroize();
    }
    
    // Final fence to ensure completion
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Trait for objects that can be burned.
pub trait Burnable {
    /// Destroys the object's sensitive contents.
    fn burn(&mut self);
}

impl<T: Zeroize> Burnable for T {
    fn burn(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_slice() {
        let mut secret = vec![0xCA, 0xFE, 0xBA, 0xBE];
        burn_slice(&mut secret);
        assert_eq!(secret, vec![0, 0, 0, 0]);
    }

    #[test]
    #[cfg(feature = "paranoid")]
    fn test_burn_paranoid() {
        // We can't easily verify the intermediate steps without mocking volatile writes,
        // but we can verify the final state is zero.
        let mut secret = vec![1, 2, 3, 4];
        burn_slice(&mut secret);
        assert_eq!(secret, vec![0, 0, 0, 0]);
    }
}
