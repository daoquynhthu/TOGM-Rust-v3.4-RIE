//! Video/Camera Entropy Source.
//!
//! Intended to harvest entropy from camera sensor noise (thermal noise in CCD/CMOS).
//! Currently a stub requiring application-level integration or external crates.

use super::{EntropyError, EntropySource};

/// Entropy source derived from video/camera input.
pub struct VideoSource {
    _private: (),
}

impl VideoSource {
    /// Creates a new VideoSource.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for VideoSource {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for VideoSource {
    fn name(&self) -> &'static str {
        "VideoNoise"
    }

    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
        // TODO: Integrate with OS camera APIs (V4L2, MediaFoundation, AVFoundation).
        // Since this crate is minimal/no-std friendly, we don't depend on heavy media libs.
        // This serves as a placeholder for the architecture.
        Err(EntropyError::NotSupported)
    }

    fn entropy_estimate(&self) -> f64 {
        // High-quality camera noise can be > 6 bits/byte, but 0.0 here since unimplemented.
        0.0
    }
}
