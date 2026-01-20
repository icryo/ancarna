//! Fuzzing result collection and analysis

use std::collections::HashMap;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Single fuzzing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Request number
    pub request_num: usize,
    /// Payload(s) used
    pub payloads: Vec<String>,
    /// Position names
    pub positions: Vec<String>,
    /// HTTP status code
    pub status_code: u16,
    /// Response length in bytes
    pub response_length: usize,
    /// Response time
    pub response_time: Duration,
    /// Response body (truncated)
    pub response_body: String,
    /// Response headers
    pub response_headers: HashMap<String, String>,
    /// Whether this is flagged as interesting
    pub interesting: bool,
    /// Reason for being interesting
    pub interesting_reason: Option<String>,
    /// Error message if request failed
    pub error: Option<String>,
}

impl FuzzResult {
    pub fn new(request_num: usize, payloads: Vec<String>, positions: Vec<String>) -> Self {
        Self {
            request_num,
            payloads,
            positions,
            status_code: 0,
            response_length: 0,
            response_time: Duration::ZERO,
            response_body: String::new(),
            response_headers: HashMap::new(),
            interesting: false,
            interesting_reason: None,
            error: None,
        }
    }

    pub fn with_response(
        mut self,
        status_code: u16,
        response_length: usize,
        response_time: Duration,
        response_body: String,
        response_headers: HashMap<String, String>,
    ) -> Self {
        self.status_code = status_code;
        self.response_length = response_length;
        self.response_time = response_time;
        self.response_body = response_body;
        self.response_headers = response_headers;
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    pub fn mark_interesting(&mut self, reason: &str) {
        self.interesting = true;
        self.interesting_reason = Some(reason.to_string());
    }
}

/// Collection of fuzzing results with analysis
#[derive(Debug, Clone, Default)]
pub struct FuzzResultSet {
    /// All results
    pub results: Vec<FuzzResult>,
    /// Baseline status code
    pub baseline_status: Option<u16>,
    /// Baseline response length
    pub baseline_length: Option<usize>,
    /// Status code distribution
    pub status_distribution: HashMap<u16, usize>,
    /// Interesting threshold for length variance (percentage)
    pub length_variance_threshold: f64,
}

impl FuzzResultSet {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            baseline_status: None,
            baseline_length: None,
            status_distribution: HashMap::new(),
            length_variance_threshold: 10.0, // 10% variance
        }
    }

    /// Set baseline from first request
    pub fn set_baseline(&mut self, status: u16, length: usize) {
        self.baseline_status = Some(status);
        self.baseline_length = Some(length);
    }

    /// Add a result and analyze it
    pub fn add_result(&mut self, mut result: FuzzResult) {
        // Update status distribution
        *self.status_distribution.entry(result.status_code).or_insert(0) += 1;

        // Analyze for interesting behavior
        self.analyze_result(&mut result);

        self.results.push(result);
    }

    /// Analyze a result for interesting behavior
    fn analyze_result(&self, result: &mut FuzzResult) {
        // Check status code difference
        if let Some(baseline) = self.baseline_status {
            if result.status_code != baseline {
                result.mark_interesting(&format!(
                    "Status code changed from {} to {}",
                    baseline, result.status_code
                ));
                return;
            }
        }

        // Check length variance
        if let Some(baseline_len) = self.baseline_length {
            let variance = ((result.response_length as f64 - baseline_len as f64).abs()
                / baseline_len as f64)
                * 100.0;
            if variance > self.length_variance_threshold {
                result.mark_interesting(&format!(
                    "Response length changed by {:.1}% ({} -> {})",
                    variance, baseline_len, result.response_length
                ));
                return;
            }
        }

        // Check for error indicators in response
        let error_indicators = [
            "error",
            "exception",
            "stack trace",
            "syntax error",
            "warning",
            "fatal",
            "sql",
            "mysql",
            "postgres",
            "oracle",
            "sqlite",
        ];

        let body_lower = result.response_body.to_lowercase();
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                result.mark_interesting(&format!("Response contains '{}'", indicator));
                return;
            }
        }

        // Check for specific status codes that might be interesting
        match result.status_code {
            500..=599 => {
                result.mark_interesting("Server error response");
            }
            401 | 403 => {
                // Only interesting if baseline was different
                if self.baseline_status != Some(result.status_code) {
                    result.mark_interesting("Authentication/authorization response");
                }
            }
            _ => {}
        }
    }

    /// Get interesting results
    pub fn interesting_results(&self) -> Vec<&FuzzResult> {
        self.results.iter().filter(|r| r.interesting).collect()
    }

    /// Get results by status code
    pub fn by_status_code(&self, status: u16) -> Vec<&FuzzResult> {
        self.results.iter().filter(|r| r.status_code == status).collect()
    }

    /// Get results sorted by response time
    pub fn sorted_by_time(&self) -> Vec<&FuzzResult> {
        let mut results: Vec<_> = self.results.iter().collect();
        results.sort_by_key(|r| r.response_time);
        results
    }

    /// Get results sorted by response length
    pub fn sorted_by_length(&self) -> Vec<&FuzzResult> {
        let mut results: Vec<_> = self.results.iter().collect();
        results.sort_by_key(|r| r.response_length);
        results
    }

    /// Get statistics
    pub fn stats(&self) -> FuzzResultStats {
        let total = self.results.len();
        let errors = self.results.iter().filter(|r| r.error.is_some()).count();
        let interesting = self.results.iter().filter(|r| r.interesting).count();

        let avg_time = if total > 0 {
            let total_time: Duration = self.results.iter().map(|r| r.response_time).sum();
            total_time / total as u32
        } else {
            Duration::ZERO
        };

        let avg_length = if total > 0 {
            let total_len: usize = self.results.iter().map(|r| r.response_length).sum();
            total_len / total
        } else {
            0
        };

        FuzzResultStats {
            total_requests: total,
            successful_requests: total - errors,
            error_count: errors,
            interesting_count: interesting,
            average_response_time: avg_time,
            average_response_length: avg_length,
            status_distribution: self.status_distribution.clone(),
        }
    }
}

/// Statistics from fuzzing results
#[derive(Debug, Clone)]
pub struct FuzzResultStats {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub error_count: usize,
    pub interesting_count: usize,
    pub average_response_time: Duration,
    pub average_response_length: usize,
    pub status_distribution: HashMap<u16, usize>,
}
