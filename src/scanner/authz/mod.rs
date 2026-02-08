//! Authorization Testing Module (Autorize-like)
//!
//! Automatically tests for Broken Access Control (BAC), IDOR, and
//! privilege escalation vulnerabilities by replaying requests with
//! different user sessions.
//!
//! # Usage
//! ```ignore
//! let mut authz = AuthzTester::new();
//!
//! // Define user sessions
//! authz.add_session(UserSession::new("admin")
//!     .with_cookie("session", "admin_token_xxx"));
//! authz.add_session(UserSession::new("user")
//!     .with_cookie("session", "user_token_yyy"));
//! authz.add_session(UserSession::new("unauthenticated"));
//!
//! // Test a request
//! let results = authz.test_request(&request).await?;
//! for result in results {
//!     if result.is_vulnerable() {
//!         println!("BAC found: {} can access {}", result.session_name, request.url);
//!     }
//! }
//! ```

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A user session for authorization testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    /// Session name/identifier (e.g., "admin", "user", "guest")
    pub name: String,
    /// Session role/privilege level (higher = more privileged)
    pub privilege_level: u8,
    /// Cookies to include in requests
    pub cookies: HashMap<String, String>,
    /// Headers to include in requests (e.g., Authorization)
    pub headers: HashMap<String, String>,
    /// Whether this session is the "baseline" (original) session
    pub is_baseline: bool,
}

impl UserSession {
    /// Create a new user session
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            privilege_level: 0,
            cookies: HashMap::new(),
            headers: HashMap::new(),
            is_baseline: false,
        }
    }

    /// Set privilege level (0 = unauthenticated, higher = more privileged)
    pub fn with_privilege_level(mut self, level: u8) -> Self {
        self.privilege_level = level;
        self
    }

    /// Add a cookie to the session
    pub fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }

    /// Add a header to the session
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Set as baseline session
    pub fn as_baseline(mut self) -> Self {
        self.is_baseline = true;
        self
    }

    /// Build cookie header string
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }
}

/// Result of testing a request with a specific session
#[derive(Debug, Clone)]
pub struct AuthzTestResult {
    /// Session that was used
    pub session_name: String,
    /// Session privilege level
    pub privilege_level: u8,
    /// Original request URL
    pub url: String,
    /// HTTP method
    pub method: String,
    /// Response status code
    pub status_code: u16,
    /// Response body length
    pub response_length: usize,
    /// Whether access was granted
    pub access_granted: bool,
    /// Enforcement status
    pub enforcement: EnforcementStatus,
    /// The response received
    pub response: Option<Response>,
}

/// Authorization enforcement status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Authorization is properly enforced (access denied for lower privilege)
    Enforced,
    /// Authorization is NOT enforced (potential vulnerability)
    Bypassed,
    /// Could not determine (e.g., different response structure)
    Unknown,
    /// This is the baseline request
    Baseline,
}

impl AuthzTestResult {
    /// Check if this result indicates a vulnerability
    pub fn is_vulnerable(&self) -> bool {
        self.enforcement == EnforcementStatus::Bypassed
    }
}

/// Comparison mode for detecting authorization bypass
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonMode {
    /// Compare status codes only
    StatusCode,
    /// Compare response body length (with tolerance)
    BodyLength,
    /// Compare response body content similarity
    BodySimilarity,
    /// Compare specific patterns in response
    PatternMatch,
    /// Use all methods
    All,
}

/// Configuration for the authorization tester
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    /// Comparison mode for detecting bypasses
    pub comparison_mode: ComparisonMode,
    /// Body length tolerance (percentage)
    pub length_tolerance: f32,
    /// Similarity threshold (0.0 - 1.0)
    pub similarity_threshold: f32,
    /// Status codes that indicate access granted
    pub success_status_codes: Vec<u16>,
    /// Status codes that indicate access denied
    pub denied_status_codes: Vec<u16>,
    /// Patterns that indicate access denied
    pub denied_patterns: Vec<String>,
    /// Patterns that indicate access granted
    pub success_patterns: Vec<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            comparison_mode: ComparisonMode::All,
            length_tolerance: 0.1, // 10%
            similarity_threshold: 0.9,
            success_status_codes: vec![200, 201, 202, 204],
            denied_status_codes: vec![401, 403, 404, 302],
            denied_patterns: vec![
                "access denied".to_string(),
                "unauthorized".to_string(),
                "forbidden".to_string(),
                "login required".to_string(),
                "permission denied".to_string(),
                "not authorized".to_string(),
            ],
            success_patterns: vec![],
            timeout_secs: 30,
        }
    }
}

/// Authorization tester (Autorize-like functionality)
pub struct AuthzTester {
    /// User sessions to test
    sessions: Vec<UserSession>,
    /// Configuration
    config: AuthzConfig,
    /// HTTP client
    client: Client,
    /// Baseline responses cache (URL -> Response)
    baseline_cache: Arc<RwLock<HashMap<String, Response>>>,
    /// Test results history
    results: Arc<RwLock<Vec<AuthzTestResult>>>,
}

impl AuthzTester {
    /// Create a new authorization tester
    pub fn new() -> Self {
        Self::with_config(AuthzConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: AuthzConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        Self {
            sessions: Vec::new(),
            config,
            client,
            baseline_cache: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a user session
    pub fn add_session(&mut self, session: UserSession) {
        self.sessions.push(session);
    }

    /// Get all sessions
    pub fn sessions(&self) -> &[UserSession] {
        &self.sessions
    }

    /// Clear all sessions
    pub fn clear_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Test a request with all sessions
    pub async fn test_request(&self, request: &Request) -> Result<Vec<AuthzTestResult>> {
        let mut results = Vec::new();

        // Find baseline session (if any)
        let baseline_session = self.sessions.iter().find(|s| s.is_baseline);

        // Get or fetch baseline response
        let baseline_response = if let Some(baseline) = baseline_session {
            Some(self.send_request(request, baseline).await?)
        } else if !self.sessions.is_empty() {
            // Use first session as baseline
            Some(self.send_request(request, &self.sessions[0]).await?)
        } else {
            None
        };

        // Test each session
        for session in &self.sessions {
            let response = self.send_request(request, session).await?;

            let enforcement = if session.is_baseline {
                EnforcementStatus::Baseline
            } else {
                self.check_enforcement(&response, baseline_response.as_ref(), session)
            };

            let access_granted = self.is_access_granted(&response);

            let result = AuthzTestResult {
                session_name: session.name.clone(),
                privilege_level: session.privilege_level,
                url: request.url.clone(),
                method: request.method.clone(),
                status_code: response.status,
                response_length: response.body.len(),
                access_granted,
                enforcement,
                response: Some(response),
            };

            results.push(result);
        }

        // Store results
        {
            let mut history = self.results.write().await;
            history.extend(results.clone());
        }

        Ok(results)
    }

    /// Send a request with a specific session
    async fn send_request(&self, request: &Request, session: &UserSession) -> Result<Response> {
        let mut req_builder = match request.method.to_uppercase().as_str() {
            "GET" => self.client.get(&request.url),
            "POST" => self.client.post(&request.url),
            "PUT" => self.client.put(&request.url),
            "DELETE" => self.client.delete(&request.url),
            "PATCH" => self.client.patch(&request.url),
            "HEAD" => self.client.head(&request.url),
            "OPTIONS" => self.client.request(reqwest::Method::OPTIONS, &request.url),
            _ => self.client.get(&request.url),
        };

        // Add original headers (except auth-related)
        for (key, value) in &request.headers {
            let key_lower = key.to_lowercase();
            if !key_lower.contains("cookie")
                && !key_lower.contains("authorization")
                && !key_lower.contains("auth")
            {
                req_builder = req_builder.header(key, value);
            }
        }

        // Add session headers
        for (key, value) in &session.headers {
            req_builder = req_builder.header(key, value);
        }

        // Add session cookies
        if let Some(cookie_header) = session.cookie_header() {
            req_builder = req_builder.header("Cookie", cookie_header);
        }

        // Add body if present
        if let Some(ref body) = request.body {
            req_builder = req_builder.body(body.clone());
        }

        let response = req_builder.send().await.context("Failed to send request")?;

        let status = response.status().as_u16();
        let status_text = response.status().to_string();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response.bytes().await.context("Failed to read response body")?;

        Ok(Response {
            status,
            status_text,
            headers,
            body: body.to_vec(),
            duration_ms: 0,
            size: body.len(),
            http_version: "HTTP/1.1".to_string(),
            remote_addr: None,
            tls_info: None,
            timing: None,
            cookies: Vec::new(),
        })
    }

    /// Check if access was granted based on response
    fn is_access_granted(&self, response: &Response) -> bool {
        // Check status code
        if self.config.success_status_codes.contains(&response.status) {
            return true;
        }

        if self.config.denied_status_codes.contains(&response.status) {
            return false;
        }

        // Check body patterns
        let body_lower = String::from_utf8_lossy(&response.body).to_lowercase();

        for pattern in &self.config.denied_patterns {
            if body_lower.contains(&pattern.to_lowercase()) {
                return false;
            }
        }

        for pattern in &self.config.success_patterns {
            if body_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        // Default to granted if 2xx
        response.status >= 200 && response.status < 300
    }

    /// Check authorization enforcement
    fn check_enforcement(
        &self,
        response: &Response,
        baseline: Option<&Response>,
        session: &UserSession,
    ) -> EnforcementStatus {
        let access_granted = self.is_access_granted(response);

        // If access denied, authorization is enforced
        if !access_granted {
            return EnforcementStatus::Enforced;
        }

        // If no baseline to compare, we can't determine
        let baseline = match baseline {
            Some(b) => b,
            None => return EnforcementStatus::Unknown,
        };

        // Access was granted - check if it matches baseline
        match self.config.comparison_mode {
            ComparisonMode::StatusCode => {
                if response.status == baseline.status {
                    EnforcementStatus::Bypassed
                } else {
                    EnforcementStatus::Enforced
                }
            }
            ComparisonMode::BodyLength => {
                let len_diff =
                    (response.body.len() as f32 - baseline.body.len() as f32).abs();
                let tolerance = baseline.body.len() as f32 * self.config.length_tolerance;

                if len_diff <= tolerance {
                    EnforcementStatus::Bypassed
                } else {
                    EnforcementStatus::Unknown
                }
            }
            ComparisonMode::BodySimilarity => {
                let similarity = self.calculate_similarity(&response.body, &baseline.body);
                if similarity >= self.config.similarity_threshold {
                    EnforcementStatus::Bypassed
                } else {
                    EnforcementStatus::Unknown
                }
            }
            ComparisonMode::PatternMatch | ComparisonMode::All => {
                // Check multiple factors
                let status_match = response.status == baseline.status;

                let len_diff =
                    (response.body.len() as f32 - baseline.body.len() as f32).abs();
                let tolerance = baseline.body.len() as f32 * self.config.length_tolerance;
                let length_match = len_diff <= tolerance.max(100.0);

                if status_match && length_match {
                    EnforcementStatus::Bypassed
                } else if status_match {
                    EnforcementStatus::Unknown
                } else {
                    EnforcementStatus::Enforced
                }
            }
        }
    }

    /// Calculate similarity between two byte arrays (simple ratio)
    fn calculate_similarity(&self, a: &[u8], b: &[u8]) -> f32 {
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }

        if a.is_empty() || b.is_empty() {
            return 0.0;
        }

        let max_len = a.len().max(b.len());
        let min_len = a.len().min(b.len());

        // Length-based similarity
        let length_sim = min_len as f32 / max_len as f32;

        // Content-based similarity (sample comparison)
        let sample_size = min_len.min(1000);
        let mut matches = 0;

        for i in 0..sample_size {
            if a.get(i) == b.get(i) {
                matches += 1;
            }
        }

        let content_sim = matches as f32 / sample_size as f32;

        (length_sim + content_sim) / 2.0
    }

    /// Get test results history
    pub async fn get_results(&self) -> Vec<AuthzTestResult> {
        self.results.read().await.clone()
    }

    /// Get vulnerable results only
    pub async fn get_vulnerabilities(&self) -> Vec<AuthzTestResult> {
        self.results
            .read()
            .await
            .iter()
            .filter(|r| r.is_vulnerable())
            .cloned()
            .collect()
    }

    /// Generate findings from results
    pub async fn generate_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for result in self.get_vulnerabilities().await {
            let severity = if result.privilege_level == 0 {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(
                Finding::new(
                    &format!("Broken Access Control - {}", result.session_name),
                    severity,
                    &result.url,
                )
                .with_method(&result.method)
                .with_description(&format!(
                    "The endpoint {} {} is accessible by '{}' (privilege level {}) \
                     when it should be restricted. Response status: {}, length: {} bytes.",
                    result.method,
                    result.url,
                    result.session_name,
                    result.privilege_level,
                    result.status_code,
                    result.response_length
                ))
                .with_evidence(&format!(
                    "Status: {}, Body Length: {}",
                    result.status_code, result.response_length
                ))
                .with_remediation(
                    "Implement proper authorization checks on the server-side. \
                     Verify user permissions before granting access to resources.",
                )
                .with_reference("https://owasp.org/Top10/A01_2021-Broken_Access_Control/")
                .with_cwe(284)
                .with_scanner("authz"),
            );
        }

        findings
    }

    /// Clear results history
    pub async fn clear_results(&self) {
        self.results.write().await.clear();
    }
}

impl Default for AuthzTester {
    fn default() -> Self {
        Self::new()
    }
}

/// IDOR (Insecure Direct Object Reference) tester
pub struct IdorTester {
    /// Base authorization tester
    authz: AuthzTester,
    /// ID patterns to detect and fuzz
    id_patterns: Vec<IdorPattern>,
}

/// Pattern for detecting and fuzzing IDs
#[derive(Debug, Clone)]
pub struct IdorPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern to match IDs
    pub pattern: String,
    /// Test values to try
    pub test_values: Vec<String>,
}

impl IdorTester {
    /// Create a new IDOR tester
    pub fn new() -> Self {
        Self {
            authz: AuthzTester::new(),
            id_patterns: Self::default_patterns(),
        }
    }

    /// Default ID patterns
    fn default_patterns() -> Vec<IdorPattern> {
        vec![
            IdorPattern {
                name: "Numeric ID".to_string(),
                pattern: r"/(\d+)(?:/|$|\?)".to_string(),
                test_values: vec![
                    "1".to_string(),
                    "2".to_string(),
                    "0".to_string(),
                    "-1".to_string(),
                    "999999".to_string(),
                ],
            },
            IdorPattern {
                name: "UUID".to_string(),
                pattern: r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})".to_string(),
                test_values: vec![
                    "00000000-0000-0000-0000-000000000000".to_string(),
                    "11111111-1111-1111-1111-111111111111".to_string(),
                ],
            },
            IdorPattern {
                name: "Base64 ID".to_string(),
                pattern: r"[?&]id=([A-Za-z0-9+/]+=*)".to_string(),
                test_values: vec!["MQ==".to_string(), "Mg==".to_string()],
            },
        ]
    }

    /// Add a session
    pub fn add_session(&mut self, session: UserSession) {
        self.authz.add_session(session);
    }

    /// Test for IDOR vulnerabilities
    pub async fn test_idor(&self, request: &Request) -> Result<Vec<AuthzTestResult>> {
        let mut all_results = Vec::new();

        // Test original request
        let original_results = self.authz.test_request(request).await?;
        all_results.extend(original_results);

        // Find and fuzz IDs in the URL
        for pattern in &self.id_patterns {
            let re = regex::Regex::new(&pattern.pattern)?;

            if let Some(captures) = re.captures(&request.url) {
                if let Some(id_match) = captures.get(1) {
                    let original_id = id_match.as_str();

                    // Try each test value
                    for test_value in &pattern.test_values {
                        if test_value == original_id {
                            continue;
                        }

                        let mut modified_request = request.clone();
                        modified_request.url =
                            request.url.replace(original_id, test_value);

                        let results = self.authz.test_request(&modified_request).await?;
                        all_results.extend(results);
                    }
                }
            }
        }

        Ok(all_results)
    }
}

impl Default for IdorTester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_session_creation() {
        let session = UserSession::new("admin")
            .with_privilege_level(10)
            .with_cookie("session", "abc123")
            .with_header("Authorization", "Bearer token");

        assert_eq!(session.name, "admin");
        assert_eq!(session.privilege_level, 10);
        assert_eq!(session.cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(
            session.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
    }

    #[test]
    fn test_cookie_header_building() {
        let session = UserSession::new("test")
            .with_cookie("session", "abc")
            .with_cookie("user", "xyz");

        let cookie_header = session.cookie_header().unwrap();
        assert!(cookie_header.contains("session=abc"));
        assert!(cookie_header.contains("user=xyz"));
    }

    #[test]
    fn test_enforcement_status() {
        let result = AuthzTestResult {
            session_name: "guest".to_string(),
            privilege_level: 0,
            url: "http://example.com/admin".to_string(),
            method: "GET".to_string(),
            status_code: 200,
            response_length: 1000,
            access_granted: true,
            enforcement: EnforcementStatus::Bypassed,
            response: None,
        };

        assert!(result.is_vulnerable());
    }

    #[test]
    fn test_default_config() {
        let config = AuthzConfig::default();
        assert!(config.success_status_codes.contains(&200));
        assert!(config.denied_status_codes.contains(&403));
        assert!(!config.denied_patterns.is_empty());
    }
}
