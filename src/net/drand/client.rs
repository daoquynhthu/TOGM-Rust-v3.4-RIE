use super::{DrandError, DrandBeacon};
use super::verify::verify_beacon;
use alloc::vec::Vec;
use alloc::string::String;

#[cfg(feature = "drand")]
use reqwest::blocking::Client;
#[cfg(feature = "drand")]
use serde::Deserialize;
#[cfg(feature = "drand")]
use std::time::Duration;

#[cfg(feature = "drand")]
#[derive(Deserialize)]
struct DrandResponse {
    round: u64,
    randomness: String,
    signature: String,
    previous_signature: String,
}

pub struct DrandClient {
    urls: Vec<String>,
    chain_hash: [u8; 32],
    #[cfg(feature = "drand")]
    client: Client,
}

impl DrandClient {
    pub fn new(urls: Vec<String>, chain_hash: [u8; 32]) -> Self {
        Self { 
            urls, 
            chain_hash,
            #[cfg(feature = "drand")]
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fetches the latest beacon.
    pub fn get_latest(&self) -> Result<DrandBeacon, DrandError> {
        #[cfg(feature = "drand")]
        {
            for url in &self.urls {
                let endpoint = format!("{}/public/latest", url);
                if let Ok(beacon) = self.fetch_beacon(&endpoint) {
                    return Ok(beacon);
                }
            }
            Err(DrandError::ConnectionError)
        }
        #[cfg(not(feature = "drand"))]
        {
             // Mock for no-std / no-feature
             // For testing purposes, return a dummy beacon
            let _ = &self.urls; // Suppress unused warning
            Ok(DrandBeacon {
                round: 1,
                randomness: vec![0u8; 32],
                signature: vec![0u8; 48], 
                previous_signature: vec![0u8; 48],
            })
        }
    }
    
    /// Fetches a specific round.
    pub fn get_round(&self, round: u64) -> Result<DrandBeacon, DrandError> {
        #[cfg(feature = "drand")]
        {
            for url in &self.urls {
                let endpoint = format!("{}/public/{}", url, round);
                if let Ok(beacon) = self.fetch_beacon(&endpoint) {
                    return Ok(beacon);
                }
            }
            Err(DrandError::ConnectionError)
        }
        #[cfg(not(feature = "drand"))]
        {
            Ok(DrandBeacon {
                round,
                randomness: vec![0u8; 32],
                signature: vec![0u8; 48],
                previous_signature: vec![0u8; 48],
            })
        }
    }
    
    #[cfg(feature = "drand")]
    fn fetch_beacon(&self, url: &str) -> Result<DrandBeacon, DrandError> {
        let resp = self.client.get(url)
            .send()
            .map_err(|_| DrandError::ConnectionError)?;
            
        if !resp.status().is_success() {
            return Err(DrandError::ConnectionError);
        }

        let json: DrandResponse = resp.json()
            .map_err(|_| DrandError::InvalidBeacon)?;

        Ok(DrandBeacon {
            round: json.round,
            randomness: hex::decode(&json.randomness).map_err(|_| DrandError::InvalidBeacon)?,
            signature: hex::decode(&json.signature).map_err(|_| DrandError::InvalidBeacon)?,
            previous_signature: hex::decode(&json.previous_signature).map_err(|_| DrandError::InvalidBeacon)?,
        })
    }

    /// Verifies a beacon using the client's chain hash.
    pub fn verify(&self, beacon: &DrandBeacon) -> Result<bool, DrandError> {
        verify_beacon(beacon, &self.chain_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::string::ToString;

    #[test]
    fn test_client_structure() {
        let client = DrandClient::new(vec!["http://localhost".to_string()], [0u8; 32]);
        // In test env without feature "drand" enabled in test profile, this might run the mock
        // If we want to test real network, we need to enable the feature.
        // Here we just ensure it compiles and runs.
        let _ = client.get_latest();
    }
}
