//! Audio/Microphone Entropy Source.
//!
//! Intended to harvest entropy from microphone thermal noise and environmental audio.
//! Currently a stub requiring application-level integration or external crates.

use super::{EntropyError, EntropySource};

/// Entropy source derived from audio input.
pub struct AudioSource {
    _private: (),
}

impl AudioSource {
    /// Creates a new AudioSource.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AudioSource {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for AudioSource {
    fn name(&self) -> &'static str {
        "AudioNoise"
    }

    fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
        // TODO: Integrate with OS audio APIs (ALSA, WASAPI, CoreAudio).
        // Placeholder implementation.
        Err(EntropyError::NotSupported)
    }

    fn entropy_estimate(&self) -> f64 {
        0.0
    }
}
