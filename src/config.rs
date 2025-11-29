//! Configuration management for TOGM.
//!
//! Defines the structure for user-configurable settings.

use alloc::vec::Vec;
use alloc::string::String;

/// Main configuration structure for the TOGM library.
///
/// This struct should be populated by the host application (CLI/GUI) and passed
/// to the respective modules.
#[derive(Debug, Clone)]
pub struct TogmConfig {
    /// List of Drand beacon URLs (e.g., "https://api.drand.sh").
    pub drand_urls: Vec<String>,
    
    /// Chain hash for Drand verification (hex string).
    pub drand_chain_hash: String,
    
    /// Address of the I2P SAM bridge (e.g., "127.0.0.1:7656").
    pub i2p_sam_address: String,
    
    /// Path to store the Master Pad and other persistent data.
    /// If None, uses memory-only or platform defaults.
    pub storage_path: Option<String>,
    
    /// Tor configuration.
    pub tor: TorConfig,
}

impl Default for TogmConfig {
    fn default() -> Self {
        Self {
            drand_urls: alloc::vec![
                String::from("https://api.drand.sh"),
                String::from("https://drand.cloudflare.com")
            ],
            // Chain hash for "default" (quicknet) or "fastnet" should be specified here.
            // This is the hash for the default league of entropy.
            drand_chain_hash: String::from("8990e7a9aaed2f2b79c4388b4e1d788549783a54788c2563f965df810a3fa057"),
            i2p_sam_address: String::from("127.0.0.1:7656"),
            storage_path: None,
            tor: TorConfig::default(),
        }
    }
}

/// Configuration specific to the Tor network layer.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Whether to use the embedded Arti client.
    pub use_embedded: bool,
    
    /// Optional proxy to use for bootstrapping Tor (e.g., if in a censored region).
    /// Format: "socks5://127.0.0.1:9050"
    pub proxy: Option<String>,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            use_embedded: true,
            proxy: None,
        }
    }
}
