//! CPU Jitter Entropy Source.
//!
//! Harvests entropy from CPU execution timing variations (jitter).
//! Sources of jitter include:
//! - Cache misses (L1/L2/L3)
//! - Pipeline stalls
//! - Branch prediction misses
//! - OS interrupts/scheduler behavior
//!
//! This module provides a hardware-independent fallback for entropy gathering,
//! critical for `no_std` environments where OS RNG might be unavailable.
//!
//! # Design
//! - **Timestamp Source**: Uses `rdtsc` (x86) or `cntvct_el0` (ARM) for high-resolution timing.
//! - **Oscillator**: Executes a CPU-intensive loop and measures execution time variance.
//! - **Whitening**: Raw jitter is often biased; we use a Von Neumann debiaser or simple folding.
//!
//! # Whitepaper Compliance
//! - Section 3.2: Hardware-independent Jitter Entropy.

use super::{EntropyError, EntropySource};

/// CPU Jitter Entropy Source.
pub struct JitterRng {
    _private: (),
}

impl JitterRng {
    /// Creates a new, seeded JitterRng instance.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Reads a high-resolution CPU timestamp counter.
    #[inline(always)]
    fn get_timestamp() -> u64 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // Safety: _rdtsc is available on all modern x86/x64 CPUs (Pentium+).
            // In very old CPUs or restricted VMs it might fault, but that's out of scope.
            #[cfg(target_arch = "x86")]
            use core::arch::x86::_rdtsc;
            #[cfg(target_arch = "x86_64")]
            use core::arch::x86_64::_rdtsc;
            
            unsafe { _rdtsc() }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // Use CNTVCT_EL0 (Virtual Count Register)
            let mut cnt: u64;
            unsafe {
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt);
            }
            cnt
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        {
            // Fallback for unsupported architectures: return 0.
            // This will cause the source to produce zero entropy, which is detected by health tests.
            0
        }
    }

    /// Performs a tiny amount of CPU-intensive work to induce jitter.
    #[inline(always)]
    fn jitter_loop() {
        // Volatile read/write or black_box to prevent optimization
        let mut x = 0u64;
        for i in 0..10 {
            x = x.wrapping_add(i);
            core::hint::black_box(x);
        }
    }
}

impl Default for JitterRng {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for JitterRng {
    fn name(&self) -> &'static str {
        "CpuJitter"
    }

    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        // Verify we have a working timer
        let t1 = Self::get_timestamp();
        Self::jitter_loop();
        let t2 = Self::get_timestamp();
        if t1 == t2 && t1 == 0 {
            return Err(EntropyError::NotSupported);
        }

        // Entropy harvesting loop
        for byte in dest.iter_mut() {
            let mut acc = 0u8;
            
            // Gather 8 bits, oversampling by 8x (64 samples per byte)
            for _ in 0..8 {
                let mut bit_entropy = 0u64;
                for _ in 0..8 {
                    let start = Self::get_timestamp();
                    Self::jitter_loop();
                    let end = Self::get_timestamp();
                    
                    // Delta contains the jitter
                    let delta = end.wrapping_sub(start);
                    
                    // Fold the delta into our entropy pool
                    // We XOR the least significant bits where jitter is highest
                    bit_entropy ^= delta;
                }
                
                // Compress 8 samples into 1 bit (parity)
                // This acts as a simple compression/whitening
                let bit = (bit_entropy.count_ones() % 2) as u8;
                acc = (acc << 1) | bit;
            }
            *byte = acc;
        }

        Ok(())
    }

    fn entropy_estimate(&self) -> f64 {
        // CPU jitter quality varies wildly. 
        // We assume ~0.5 bits of min-entropy per output bit after 8x oversampling.
        // This is conservative.
        4.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_rng_fill() {
        let mut rng = JitterRng::new();
        let mut buf = [0u8; 32];
        match rng.fill(&mut buf) {
            Ok(_) => {
                // Check that buffer is not all zeros (vanishingly unlikely)
                assert!(buf.iter().any(|&x| x != 0), "JitterRng produced all zeros");
                // Check variance? Hard in unit test.
            }
            Err(EntropyError::NotSupported) => {
                // If on unsupported platform, this is acceptable
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
                panic!("JitterRng should be supported on this architecture");
            }
            Err(e) => panic!("JitterRng failed: {:?}", e),
        }
    }
}
