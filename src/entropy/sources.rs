//! Standard Entropy Sources Registry.
//!
//! Re-exports available entropy sources for convenient access.

pub use super::jitter::JitterRng;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use super::rdrand::RdRandSource;

#[cfg(feature = "std")]
pub use super::audio::AudioSource;
#[cfg(feature = "std")]
pub use super::video::VideoSource;

pub use super::custom::CustomSource;
