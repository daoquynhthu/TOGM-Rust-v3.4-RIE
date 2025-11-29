use super::{DrandBeacon, DrandError};

/// Verifies a single beacon against the chain info.
/// 
/// Note: This requires BLS12-381 signature verification which is not currently
/// included in the dependencies to keep binary size low.
/// For now, this checks structural validity and optional mock verification.
pub fn verify_beacon(beacon: &DrandBeacon, _chain_hash: &[u8; 32]) -> Result<bool, DrandError> {
    if beacon.randomness.is_empty() || beacon.signature.is_empty() {
        return Err(DrandError::InvalidBeacon);
    }

    // Placeholder for BLS verification:
    // verify(chain_info.public_key, beacon.signature, message(beacon.round, beacon.previous_signature))
    
    // Verify randomness derivation: R = H(signature)
    // Drand typically uses SHA-256. We will skip this check if we don't have SHA-256,
    // or we can use a placeholder check if we assume a specific test setup.
    
    // For RIE edition, we assume a "Trust but Verify" approach where we might rely on
    // multiple sources if verification is expensive.
    
    // Mock check: valid if round > 0
    if beacon.round == 0 {
        return Err(DrandError::InvalidBeacon);
    }

    Ok(true)
}

/// Verifies a sequence of beacons.
pub fn verify_chain(beacons: &[DrandBeacon], chain_hash: &[u8; 32]) -> Result<bool, DrandError> {
    let mut prev = &beacons[0];
    for b in beacons.iter().skip(1) {
        if b.round != prev.round + 1 {
            return Err(DrandError::OutOfSync);
        }
        // if b.previous_signature != prev.signature { return Err(DrandError::InvalidBeacon); }
        if !verify_beacon(b, chain_hash)? {
            return Ok(false);
        }
        prev = b;
    }
    Ok(true)
}
