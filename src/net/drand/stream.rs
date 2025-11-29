use super::{DrandClient, DrandBeacon, DrandError};

pub struct BeaconStream {
    client: DrandClient,
    last_round: u64,
}

impl BeaconStream {
    pub fn new(client: DrandClient) -> Self {
        Self {
            client,
            last_round: 0,
        }
    }

    /// Polls for the next beacon.
    /// Returns None if no new beacon is available yet.
    pub fn poll(&mut self) -> Option<Result<DrandBeacon, DrandError>> {
        // In a real implementation, this would check if the next round is available
        // based on time (Drand has fixed intervals).
        
        // For mock, we just return the next round immediately.
        let next_round = self.last_round + 1;
        match self.client.get_round(next_round) {
            Ok(beacon) => {
                self.last_round = next_round;
                Some(Ok(beacon))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
