//! Pad Access Monitor (Watchdog Integration).
//!
//! Monitors access to the Master Pad to detect anomalies such as rapid consumption
//! or repeated invalid access attempts.
//!
//! # Security
//! - **Rate Limiting**: Restricts data consumption speed (requires `std`).
//! - **Lockdown**: Automatically locks the pad after repeated failures.

use super::PadError;

#[cfg(feature = "std")]
use std::time::Instant;

/// Configuration for the pad monitor.
#[derive(Debug, Clone, Copy)]
pub struct MonitorConfig {
    /// Maximum bytes allowed to be consumed within a time window.
    pub rate_limit_bytes: u64,
    /// Time window for rate limiting in seconds.
    pub rate_limit_window: u64,
    /// Maximum consecutive failed access attempts before lockdown.
    pub max_failures: u32,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            rate_limit_bytes: 10 * 1024 * 1024, // 10 MB
            rate_limit_window: 60,              // 1 minute
            max_failures: 3,
        }
    }
}

/// Monitors pad usage and enforces security policies.
pub struct PadMonitor {
    config: MonitorConfig,
    failures: u32,
    
    #[cfg(feature = "std")]
    window_start: Instant,
    #[cfg(feature = "std")]
    bytes_in_window: u64,
}

impl PadMonitor {
    /// Creates a new monitor with the given configuration.
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            config,
            failures: 0,
            #[cfg(feature = "std")]
            window_start: Instant::now(),
            #[cfg(feature = "std")]
            bytes_in_window: 0,
        }
    }

    /// Records a successful consumption of bytes.
    ///
    /// # Returns
    /// * `Ok(())` if the access is within limits.
    /// * `Err(PadError::SecurityLockdown)` if the rate limit is exceeded or pad is locked.
    pub fn record_access(&mut self, bytes: u64) -> Result<(), PadError> {
        if self.is_locked() {
             return Err(PadError::SecurityLockdown);
        }

        #[cfg(feature = "std")]
        {
            let now = Instant::now();
            let elapsed = now.duration_since(self.window_start).as_secs();
            
            if elapsed >= self.config.rate_limit_window {
                // Reset window
                self.window_start = now;
                self.bytes_in_window = 0;
            }
            
            self.bytes_in_window = self.bytes_in_window.saturating_add(bytes);
            
            if self.bytes_in_window > self.config.rate_limit_bytes {
                return Err(PadError::SecurityLockdown);
            }
        }
        
        // Silence unused variable warning in no_std
        #[cfg(not(feature = "std"))]
        let _ = bytes;
        
        Ok(())
    }

    /// Records a failed access attempt (e.g., out of bounds, integrity failure).
    pub fn record_failure(&mut self) -> Result<(), PadError> {
        self.failures = self.failures.saturating_add(1);
        if self.is_locked() {
            return Err(PadError::SecurityLockdown);
        }
        Ok(())
    }
    
    /// Resets the failure counter (e.g., after successful admin intervention).
    pub fn reset_failures(&mut self) {
        self.failures = 0;
        #[cfg(feature = "std")]
        {
            self.bytes_in_window = 0;
            self.window_start = Instant::now();
        }
    }
    
    /// Checks if the monitor is in a locked state.
    pub fn is_locked(&self) -> bool {
        self.failures >= self.config.max_failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_lockdown() {
        let config = MonitorConfig {
            max_failures: 2,
            ..Default::default()
        };
        let mut monitor = PadMonitor::new(config);
        
        assert!(!monitor.is_locked());
        
        monitor.record_failure().unwrap();
        assert!(!monitor.is_locked());
        
        let res = monitor.record_failure(); // Hits limit (2)
        assert_eq!(res, Err(PadError::SecurityLockdown));
        assert!(monitor.is_locked());
        
        // Subsequent accesses should fail
        assert_eq!(monitor.record_access(10), Err(PadError::SecurityLockdown));
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_rate_limiting() {
        let config = MonitorConfig {
            rate_limit_bytes: 100,
            rate_limit_window: 10,
            ..Default::default()
        };
        let mut monitor = PadMonitor::new(config);
        
        monitor.record_access(50).unwrap();
        monitor.record_access(50).unwrap(); // Total 100
        
        let res = monitor.record_access(1); // Total 101 > 100
        assert_eq!(res, Err(PadError::SecurityLockdown));
    }
}
