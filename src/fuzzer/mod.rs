//! Fuzzer module - High-speed parameter and payload fuzzing
//!
//! Implements functionality similar to Burp Turbo Intruder and ZAP Fuzzer.
//! Supports multiple attack modes, wordlists, and concurrent requests.

mod engine;
mod payloads;
mod results;

pub use engine::{Fuzzer, FuzzerConfig, AttackMode, FuzzerState};
pub use payloads::{PayloadSet, PayloadGenerator, PayloadPosition};
pub use results::{FuzzResult, FuzzResultSet};

use anyhow::Result;
use std::sync::Arc;
use parking_lot::RwLock;

/// Fuzzer statistics
#[derive(Debug, Clone, Default)]
pub struct FuzzerStats {
    /// Total requests sent
    pub requests_sent: usize,
    /// Total requests remaining
    pub requests_remaining: usize,
    /// Requests per second
    pub requests_per_second: f64,
    /// Errors encountered
    pub errors: usize,
    /// Interesting results found
    pub interesting_count: usize,
    /// Start time
    pub start_time: Option<std::time::Instant>,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
}

impl FuzzerStats {
    pub fn progress(&self) -> f64 {
        let total = self.requests_sent + self.requests_remaining;
        if total == 0 {
            0.0
        } else {
            self.requests_sent as f64 / total as f64
        }
    }
}
