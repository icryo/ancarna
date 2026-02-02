//! Core fuzzer engine with concurrent request handling

use super::{FuzzResult, FuzzResultSet, FuzzerStats, PayloadPosition, PayloadSet};
use crate::http::Request;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Attack mode determines how payloads are combined
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    /// Single payload position at a time, iterate through all payloads (like Burp Sniper)
    Sniper,
    /// Same payload to all positions simultaneously (like Burp Battering Ram)
    Battering,
    /// Parallel iteration through payload sets (like Burp Pitchfork)
    Pitchfork,
    /// Cartesian product of all payloads (like Burp Cluster Bomb)
    ClusterBomb,
}

impl AttackMode {
    pub fn all() -> &'static [AttackMode] {
        &[
            AttackMode::Sniper,
            AttackMode::Battering,
            AttackMode::Pitchfork,
            AttackMode::ClusterBomb,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            AttackMode::Sniper => "Sniper",
            AttackMode::Battering => "Battering Ram",
            AttackMode::Pitchfork => "Pitchfork",
            AttackMode::ClusterBomb => "Cluster Bomb",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AttackMode::Sniper => "Single position at a time with all payloads",
            AttackMode::Battering => "Same payload to all positions",
            AttackMode::Pitchfork => "Parallel iteration through payload sets",
            AttackMode::ClusterBomb => "All combinations of payloads",
        }
    }
}

/// Fuzzer state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzerState {
    Idle,
    Running,
    Paused,
    Stopped,
    Completed,
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Delay between requests in milliseconds
    pub delay_ms: u64,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Whether to follow redirects
    pub follow_redirects: bool,
    /// Maximum response body size to capture (bytes)
    pub max_response_size: usize,
    /// Length variance threshold for marking interesting (percentage)
    pub length_variance_threshold: f64,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            delay_ms: 0,
            timeout_secs: 30,
            follow_redirects: true,
            max_response_size: 10 * 1024 * 1024, // 10MB
            length_variance_threshold: 10.0,
        }
    }
}

/// High-speed fuzzer engine
pub struct Fuzzer {
    /// Configuration
    config: FuzzerConfig,
    /// Current state
    state: Arc<RwLock<FuzzerState>>,
    /// Results
    results: Arc<RwLock<FuzzResultSet>>,
    /// Statistics
    stats: Arc<RwLock<FuzzerStats>>,
    /// Internal reqwest client
    client: reqwest::Client,
}

impl Fuzzer {
    /// Create a new fuzzer
    pub fn new(config: FuzzerConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(FuzzerState::Idle)),
            results: Arc::new(RwLock::new(FuzzResultSet::new())),
            stats: Arc::new(RwLock::new(FuzzerStats::default())),
            client,
        })
    }

    /// Run fuzzing attack
    pub async fn fuzz(
        &self,
        base_request: &Request,
        positions: Vec<PayloadPosition>,
        payload_sets: Vec<PayloadSet>,
        mode: AttackMode,
    ) -> Result<FuzzResultSet> {
        // Validate inputs
        if positions.is_empty() {
            anyhow::bail!("No payload positions defined");
        }
        if payload_sets.is_empty() {
            anyhow::bail!("No payload sets provided");
        }

        // Reset state
        {
            *self.state.write() = FuzzerState::Running;
            *self.results.write() = FuzzResultSet::new();
            let mut stats = self.stats.write();
            *stats = FuzzerStats::default();
            stats.start_time = Some(Instant::now());
        }

        // Generate all payload combinations
        let combinations = self.generate_combinations(&positions, &payload_sets, mode);

        // Update remaining count
        {
            let mut stats = self.stats.write();
            stats.requests_remaining = combinations.len();
        }

        // Get baseline response
        let baseline = self.send_request(base_request).await;
        if let Ok(ref response) = baseline {
            let mut results = self.results.write();
            results.set_baseline(response.status, response.body.len());
        }

        // Create semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));

        // Process all combinations
        let mut handles = Vec::new();

        for (idx, (payload_values, position_names)) in combinations.into_iter().enumerate() {
            // Check if stopped
            if *self.state.read() == FuzzerState::Stopped {
                break;
            }

            // Wait if paused
            while *self.state.read() == FuzzerState::Paused {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }

            // Apply delay
            if self.config.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
            }

            // Acquire semaphore permit
            let permit = semaphore.clone().acquire_owned().await?;

            // Clone needed data for spawned task
            let client = self.client.clone();
            let results = self.results.clone();
            let stats = self.stats.clone();
            let state = self.state.clone();
            let max_response_size = self.config.max_response_size;

            // Build request with payloads
            let fuzz_request = self.build_request_with_payloads(base_request, &positions, &payload_values);

            let handle = tokio::spawn(async move {
                // Check if stopped
                if *state.read() == FuzzerState::Stopped {
                    drop(permit);
                    return;
                }

                let start = Instant::now();
                let mut result = FuzzResult::new(idx + 1, payload_values.clone(), position_names.clone());

                // Build reqwest request
                let req_builder = match fuzz_request.method.to_uppercase().as_str() {
                    "GET" => client.get(&fuzz_request.url),
                    "POST" => client.post(&fuzz_request.url),
                    "PUT" => client.put(&fuzz_request.url),
                    "DELETE" => client.delete(&fuzz_request.url),
                    "PATCH" => client.patch(&fuzz_request.url),
                    "HEAD" => client.head(&fuzz_request.url),
                    _ => client.get(&fuzz_request.url),
                };

                // Add headers
                let mut req_builder = req_builder;
                for (key, value) in &fuzz_request.headers {
                    if let (Ok(name), Ok(val)) = (
                        reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                        reqwest::header::HeaderValue::from_str(value),
                    ) {
                        req_builder = req_builder.header(name, val);
                    }
                }

                // Add body
                if let Some(body) = &fuzz_request.body {
                    req_builder = req_builder.body(body.clone());
                }

                // Execute request
                match req_builder.send().await {
                    Ok(response) => {
                        let elapsed = start.elapsed();
                        let status = response.status().as_u16();
                        let headers: HashMap<String, String> = response
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();

                        match response.text().await {
                            Ok(body_text) => {
                                let body_len = body_text.len();
                                let body = if body_len > max_response_size {
                                    // Find safe char boundary
                                    let mut end = max_response_size;
                                    while end > 0 && !body_text.is_char_boundary(end) {
                                        end -= 1;
                                    }
                                    body_text[..end].to_string()
                                } else {
                                    body_text
                                };

                                result = result.with_response(
                                    status,
                                    body_len,
                                    elapsed,
                                    body,
                                    headers,
                                );
                            }
                            Err(e) => {
                                result = result.with_error(format!("Failed to read body: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        result = result.with_error(e.to_string());
                    }
                }

                // Add result
                results.write().add_result(result);

                // Update stats
                {
                    let mut stats = stats.write();
                    stats.requests_sent += 1;
                    stats.requests_remaining = stats.requests_remaining.saturating_sub(1);
                    if let Some(start_time) = stats.start_time {
                        stats.elapsed_ms = start_time.elapsed().as_millis() as u64;
                        if stats.elapsed_ms > 0 {
                            stats.requests_per_second =
                                stats.requests_sent as f64 / (stats.elapsed_ms as f64 / 1000.0);
                        }
                    }
                }

                drop(permit);
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Update final state
        *self.state.write() = FuzzerState::Completed;

        // Return results
        Ok(self.results.read().clone())
    }

    /// Generate payload combinations based on attack mode
    fn generate_combinations(
        &self,
        positions: &[PayloadPosition],
        payload_sets: &[PayloadSet],
        mode: AttackMode,
    ) -> Vec<(Vec<String>, Vec<String>)> {
        let position_names: Vec<String> = positions.iter().map(|p| p.name.clone()).collect();

        let empty_set = PayloadSet::new("empty", vec![]);

        match mode {
            AttackMode::Sniper => {
                // Each position gets each payload, one at a time
                let mut combinations = Vec::new();
                let set = payload_sets.first().unwrap_or(&empty_set);
                for (pos_idx, pos) in positions.iter().enumerate() {
                    for payload in &set.payloads {
                        let mut values: Vec<String> = positions
                            .iter()
                            .map(|p| p.original_value.clone())
                            .collect();
                        values[pos_idx] = payload.clone();
                        combinations.push((values, vec![pos.name.clone()]));
                    }
                }
                combinations
            }
            AttackMode::Battering => {
                // Same payload to all positions
                let set = payload_sets.first().unwrap_or(&empty_set);
                set.payloads
                    .iter()
                    .map(|payload| {
                        let values = vec![payload.clone(); positions.len()];
                        (values, position_names.clone())
                    })
                    .collect()
            }
            AttackMode::Pitchfork => {
                // Parallel iteration through payload sets
                let min_len = payload_sets.iter().map(|s| s.len()).min().unwrap_or(0);
                (0..min_len)
                    .map(|i| {
                        let values: Vec<String> = payload_sets
                            .iter()
                            .map(|s| s.payloads.get(i).cloned().unwrap_or_default())
                            .collect();
                        (values, position_names.clone())
                    })
                    .collect()
            }
            AttackMode::ClusterBomb => {
                // Cartesian product
                let mut combinations = vec![(Vec::new(), position_names.clone())];
                for set in payload_sets {
                    let mut new_combinations = Vec::new();
                    for (existing, names) in &combinations {
                        for payload in &set.payloads {
                            let mut new_values = existing.clone();
                            new_values.push(payload.clone());
                            new_combinations.push((new_values, names.clone()));
                        }
                    }
                    combinations = new_combinations;
                }
                combinations
            }
        }
    }

    /// Build a request with payloads substituted
    fn build_request_with_payloads(
        &self,
        base: &Request,
        positions: &[PayloadPosition],
        payloads: &[String],
    ) -> Request {
        let mut url = base.url.clone();
        let mut headers = base.headers.clone();
        let mut body = base.body.clone();

        // Substitute payloads at positions
        // For simplicity, we replace §marker§ patterns in URL, headers, and body
        for (pos, payload) in positions.iter().zip(payloads.iter()) {
            let marker = format!("§{}§", pos.name);

            // Replace in URL
            url = url.replace(&marker, payload);

            // Replace in headers
            for value in headers.values_mut() {
                if value.contains(&marker) {
                    *value = value.replace(&marker, payload);
                }
            }

            // Replace in body
            if let Some(ref mut body_str) = body {
                if body_str.contains(&marker) {
                    *body_str = body_str.replace(&marker, payload);
                }
            }
        }

        // Also handle direct position replacement by name in query params
        if let Ok(mut parsed_url) = url::Url::parse(&url) {
            let mut pairs: Vec<(String, String)> = parsed_url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for (pos, payload) in positions.iter().zip(payloads.iter()) {
                for (key, value) in &mut pairs {
                    if key == &pos.name || value == &pos.original_value {
                        *value = payload.clone();
                    }
                }
            }

            parsed_url.query_pairs_mut().clear();
            for (k, v) in &pairs {
                parsed_url.query_pairs_mut().append_pair(k, v);
            }
            url = parsed_url.to_string();
        }

        Request {
            url,
            method: base.method.clone(),
            headers,
            body,
            ..base.clone()
        }
    }

    /// Send a single request for baseline
    async fn send_request(&self, request: &Request) -> Result<BaselineResponse> {
        let req_builder = match request.method.to_uppercase().as_str() {
            "GET" => self.client.get(&request.url),
            "POST" => self.client.post(&request.url),
            "PUT" => self.client.put(&request.url),
            "DELETE" => self.client.delete(&request.url),
            _ => self.client.get(&request.url),
        };

        let response = req_builder.send().await?;
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(BaselineResponse { status, body })
    }

    /// Stop the fuzzer
    pub fn stop(&self) {
        *self.state.write() = FuzzerState::Stopped;
    }

    /// Pause the fuzzer
    pub fn pause(&self) {
        let mut state = self.state.write();
        if *state == FuzzerState::Running {
            *state = FuzzerState::Paused;
        }
    }

    /// Resume the fuzzer
    pub fn resume(&self) {
        let mut state = self.state.write();
        if *state == FuzzerState::Paused {
            *state = FuzzerState::Running;
        }
    }

    /// Get current state
    pub fn state(&self) -> FuzzerState {
        *self.state.read()
    }

    /// Get current stats
    pub fn stats(&self) -> FuzzerStats {
        self.stats.read().clone()
    }

    /// Get current results
    pub fn results(&self) -> FuzzResultSet {
        self.results.read().clone()
    }
}

/// Simple response for baseline comparison
struct BaselineResponse {
    status: u16,
    body: String,
}

impl Clone for Fuzzer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::new(RwLock::new(*self.state.read())),
            results: Arc::new(RwLock::new(self.results.read().clone())),
            stats: Arc::new(RwLock::new(self.stats.read().clone())),
            client: self.client.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_mode_names() {
        assert_eq!(AttackMode::Sniper.name(), "Sniper");
        assert_eq!(AttackMode::ClusterBomb.name(), "Cluster Bomb");
    }

    #[test]
    fn test_fuzzer_config_default() {
        let config = FuzzerConfig::default();
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.delay_ms, 0);
    }
}
