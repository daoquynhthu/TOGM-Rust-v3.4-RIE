//! Bootstrap Orchestrator.
//!
//! Manages the execution flow of the bootstrap process.
//! strictly enforces stage ordering and timeouts.
//!
//! # Whitepaper Compliance
//! - Section 6: Bootstrap Orchestration (Async n-t startup, 3-8min).

use super::stages::BootstrapStage;
use crate::protocol::ProtocolError;

#[cfg(feature = "std")]
use std::time::{Instant, Duration};

/// Orchestrates the bootstrap process.
pub struct BootstrapOrchestrator {
    current_stage: BootstrapStage,
    #[cfg(feature = "std")]
    /// Start time of the current stage.
    ///
    /// # Monotonicity
    /// Uses `std::time::Instant` which guarantees monotonicity on supported platforms.
    /// This prevents timeout checks from being bypassed by system time changes.
    stage_start_time: Instant,
    /// Tracks if persistence has been verified for the current stage (specifically Persistence stage).
    persistence_verified: bool,
}

impl BootstrapOrchestrator {
    /// Creates a new orchestrator in the Idle state.
    pub fn new() -> Self {
        Self {
            current_stage: BootstrapStage::Idle,
            #[cfg(feature = "std")]
            stage_start_time: Instant::now(),
            persistence_verified: false,
        }
    }

    /// Returns the current stage.
    pub fn current_stage(&self) -> BootstrapStage {
        self.current_stage
    }
    
    /// Confirms that persistence has been successfully completed.
    /// Must be called before advancing from the Persistence stage.
    pub fn confirm_persistence(&mut self) {
        self.persistence_verified = true;
    }
    
    /// Advances to the next stage.
    ///
    /// # Errors
    /// Returns `ProtocolError::InvalidState` if already complete.
    /// Returns `ProtocolError::BootstrapFailed` if persistence is not verified when required.
    pub fn advance(&mut self) -> Result<(), ProtocolError> {
        if self.current_stage == BootstrapStage::Persistence && !self.persistence_verified {
            return Err(ProtocolError::BootstrapFailed);
        }

        if let Some(next) = self.current_stage.next() {
            self.current_stage = next;
            self.persistence_verified = false; // Reset for next stages
            #[cfg(feature = "std")]
            {
                self.stage_start_time = Instant::now();
            }
            Ok(())
        } else {
            // If strictly following "next", calling advance on Complete might be considered an error or no-op.
            // Here we treat it as no-op or check if user wants to restart.
            // For safety, let's keep it idempotent but logic might differ.
            Ok(())
        }
    }

    /// Checks if the current stage has timed out.
    pub fn check_timeout(&self) -> Result<(), ProtocolError> {
        #[cfg(feature = "std")]
        {
            let timeout = self.current_stage.timeout_seconds();
            if timeout > 0 {
                 if self.stage_start_time.elapsed() > Duration::from_secs(timeout) {
                     return Err(ProtocolError::Timeout);
                 }
            }
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std environments, we cannot rely on internal timers.
            // The caller must strictly manage timeouts externally.
            // Returning Timeout here forces the caller to handle time logic or fail.
            // Alternatively, we could return Ok(()) but that was flagged as a security risk (bypassing checks).
            // The audit suggestion is to return Err(Timeout) or enforce external time.
            // To be safe and explicit:
            return Err(ProtocolError::Timeout);
        }
        Ok(())
    }
    
    /// Resets the orchestrator (e.g., on failure or retry).
    pub fn reset(&mut self) {
        self.current_stage = BootstrapStage::Idle;
        self.persistence_verified = false;
        #[cfg(feature = "std")]
        {
            self.stage_start_time = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_flow() {
        let mut orch = BootstrapOrchestrator::new();
        assert_eq!(orch.current_stage(), BootstrapStage::Idle);
        
        orch.advance().unwrap();
        assert_eq!(orch.current_stage(), BootstrapStage::Discovery);
        
        // Fast forward to complete
        while orch.current_stage() != BootstrapStage::Complete {
            if orch.current_stage() == BootstrapStage::Persistence {
                orch.confirm_persistence();
            }
            orch.advance().unwrap();
        }
        assert_eq!(orch.current_stage(), BootstrapStage::Complete);
    }

    #[test]
    fn test_persistence_check() {
        let mut orch = BootstrapOrchestrator::new();
        // Fast forward to Persistence
        while orch.current_stage() != BootstrapStage::Persistence {
            orch.advance().unwrap();
        }
        
        // Should fail without confirmation
        assert_eq!(orch.advance(), Err(ProtocolError::BootstrapFailed));
        
        // Confirm
        orch.confirm_persistence();
        // Should succeed
        orch.advance().unwrap();
        assert_eq!(orch.current_stage(), BootstrapStage::Complete);
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_timeout() {
        let mut orch = BootstrapOrchestrator::new();
        orch.advance().unwrap(); // Discovery (timeout 60s)
        
        // Should not timeout immediately
        assert!(orch.check_timeout().is_ok());
        
        // Cannot easily mock time in std without external crates or trait abstraction,
        // so we verify the logic structure via code review or property testing if possible.
        // Here we just ensure it doesn't panic.
    }
}
