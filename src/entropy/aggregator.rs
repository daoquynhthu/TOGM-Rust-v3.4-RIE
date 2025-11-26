//! Entropy Aggregator.
//!
//! Combines multiple entropy sources into a unified stream.

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use super::{EntropySource, EntropyError};

/// Aggregator that collects from multiple sources.
pub struct EntropyAggregator {
    sources: Vec<Box<dyn EntropySource + Send + Sync>>,
}

impl EntropyAggregator {
    /// Creates a new empty aggregator.
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Adds a source to the aggregator.
    pub fn add_source<S>(&mut self, source: S)
    where
        S: EntropySource + Send + Sync + 'static,
    {
        self.sources.push(Box::new(source));
    }

    /// Fills the destination buffer by collecting from all sources and XORing the results.
    ///
    /// This ensures that if any single source is good, the result is good (assuming independent sources).
    pub fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        if self.sources.is_empty() {
            return Err(EntropyError::InitFailed);
        }

        // Initialize dest with zeros so we can XOR into it
        for b in dest.iter_mut() {
            *b = 0;
        }

        let mut temp_buf = alloc::vec![0u8; dest.len()];
        let mut success_count = 0;

        for source in &mut self.sources {
            // Try to fill temp buffer
            if source.fill(&mut temp_buf).is_ok() {
                // XOR into dest
                for (d, s) in dest.iter_mut().zip(temp_buf.iter()) {
                    *d ^= *s;
                }
                success_count += 1;
            }
        }

        if success_count == 0 {
            return Err(EntropyError::CollectionFailed);
        }

        Ok(())
    }
}

impl Default for EntropyAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for EntropyAggregator {
    fn name(&self) -> &'static str {
        "Aggregator"
    }

    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        self.fill(dest)
    }

    fn entropy_estimate(&self) -> f64 {
        // Return the maximum estimate from all sources?
        // Or the sum (capped at 8.0)?
        // For safety, we return the max estimate of any single source, 
        // because we don't know if sources are independent.
        // But if we assume independence, it would be higher.
        // Let's go with a conservative approach: max(estimates).
        
        let mut max_est = 0.0;
        for source in &self.sources {
            let est = source.entropy_estimate();
            if est > max_est {
                max_est = est;
            }
        }
        max_est
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::custom::CustomSource;

    #[test]
    fn test_aggregator_mixing() {
        let mut agg = EntropyAggregator::new();
        
        let mut s1 = CustomSource::new();
        s1.add_bytes(&[0xAA, 0xAA]);
        agg.add_source(s1);

        let mut s2 = CustomSource::new();
        s2.add_bytes(&[0x55, 0x55]);
        agg.add_source(s2);

        let mut buf = [0u8; 2];
        assert!(agg.fill(&mut buf).is_ok());
        
        // AA ^ 55 = FF
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn test_aggregator_partial_failure() {
        let mut agg = EntropyAggregator::new();
        
        let s1 = CustomSource::new();
        // Empty source, will fail to fill
        agg.add_source(s1);

        let mut s2 = CustomSource::new();
        s2.add_bytes(&[0x01, 0x02]);
        agg.add_source(s2);

        let mut buf = [0u8; 2];
        assert!(agg.fill(&mut buf).is_ok());
        
        // 00 ^ 0102 = 0102
        assert_eq!(buf, [0x01, 0x02]);
    }
}
