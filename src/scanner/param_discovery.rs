//! Parameter Discovery Module
//!
//! Implements functionality similar to Burp Param Miner plugin.
//! Discovers hidden parameters, headers, and cache poisoning opportunities.

#![allow(dead_code)]

use anyhow::Result;
use std::time::Duration;

/// Common hidden parameter names to test
pub const COMMON_PARAMS: &[&str] = &[
    // Debug/Admin parameters
    "debug", "test", "admin", "internal", "dev", "staging", "local",
    "verbose", "trace", "log", "dump", "profile", "benchmark",
    // Authentication bypass
    "bypass", "skip_auth", "skip", "noauth", "anonymous", "guest",
    "token", "api_key", "apikey", "key", "secret", "auth",
    // Feature flags
    "feature", "flag", "enable", "disable", "beta", "alpha", "preview",
    "experiment", "variant", "version", "v",
    // Redirect/URL parameters
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "next", "url", "uri", "dest", "destination", "target", "goto", "link",
    "continue", "forward", "ref", "callback", "path", "file",
    // Injection points
    "id", "user", "user_id", "uid", "username", "email", "name",
    "page", "p", "q", "s", "search", "query", "filter",
    "sort", "order", "orderby", "order_by", "limit", "offset",
    "start", "end", "from", "to", "date", "time",
    // Format/output
    "format", "type", "output", "content_type", "accept", "mime",
    "json", "xml", "html", "raw", "text", "download", "export",
    // JSONP/callback
    "callback", "jsonp", "cb", "fn", "function",
    // Action/method
    "action", "method", "cmd", "command", "op", "operation", "do",
    "mode", "task", "func", "function",
    // Include/template
    "template", "tpl", "include", "inc", "load", "require", "import",
    "view", "layout", "theme", "skin", "style",
    // Cache busting
    "cache", "nocache", "no_cache", "refresh", "reload", "bust",
    "timestamp", "ts", "t", "rand", "random", "r", "v", "ver",
    // CORS/security
    "origin", "cors", "allow", "access", "csrf", "xsrf", "nonce",
    // Misc
    "config", "setting", "settings", "option", "options", "param",
    "data", "payload", "body", "input", "value", "val",
    "lang", "language", "locale", "i18n", "l10n", "region", "country",
];

/// Common hidden headers to test
pub const COMMON_HEADERS: &[&str] = &[
    // Cache poisoning headers
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Port",
    "X-Forwarded-For",
    "X-Forwarded-Server",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-Host",
    // HTTP method override
    "X-HTTP-Method",
    "X-HTTP-Method-Override",
    "X-Method-Override",
    // Custom headers
    "X-Custom-IP-Authorization",
    "X-Debug",
    "X-Debug-Token",
    "X-Debug-Mode",
    "X-Token",
    "X-Api-Key",
    "X-Api-Version",
    "X-Real-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "True-Client-IP",
    "Client-IP",
    // Admin/bypass headers
    "X-Admin",
    "X-Internal",
    "X-Backend",
    "X-Source",
    "X-Request-Id",
    "X-Correlation-Id",
    "X-Trace-Id",
    // Content negotiation
    "X-Requested-With",
    "X-Accept",
    "X-Content-Type",
    // Cloudflare/CDN specific
    "CF-Connecting-IP",
    "CF-IPCountry",
    "CF-RAY",
    "CF-Visitor",
    // AWS specific
    "X-Amzn-Trace-Id",
    "X-Amz-Cf-Id",
    // Fastly specific
    "Fastly-Client-IP",
    "Fastly-FF",
];

/// Parameter discovery result
#[derive(Debug, Clone)]
pub struct DiscoveredParam {
    /// Parameter name
    pub name: String,
    /// Location (query, body, header, cookie)
    pub location: ParamLocation,
    /// Baseline response length
    pub baseline_length: usize,
    /// Response length with parameter
    pub response_length: usize,
    /// Baseline status code
    pub baseline_status: u16,
    /// Response status with parameter
    pub response_status: u16,
    /// Whether this caused a significant change
    pub is_interesting: bool,
    /// Reason for being interesting
    pub reason: Option<String>,
    /// Response time difference (ms)
    pub time_difference_ms: i64,
}

/// Parameter location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamLocation {
    QueryString,
    PostBody,
    Header,
    Cookie,
    PathSegment,
}

impl ParamLocation {
    pub fn name(&self) -> &'static str {
        match self {
            ParamLocation::QueryString => "Query",
            ParamLocation::PostBody => "Body",
            ParamLocation::Header => "Header",
            ParamLocation::Cookie => "Cookie",
            ParamLocation::PathSegment => "Path",
        }
    }
}

/// Parameter miner configuration
#[derive(Debug, Clone)]
pub struct ParamMinerConfig {
    /// Custom parameters to test
    pub custom_params: Vec<String>,
    /// Custom headers to test
    pub custom_headers: Vec<String>,
    /// Test values for parameters
    pub test_values: Vec<String>,
    /// Concurrent requests
    pub concurrent: usize,
    /// Request delay (ms)
    pub delay_ms: u64,
    /// Length variance threshold (%) to consider interesting
    pub length_threshold: f64,
    /// Time variance threshold (ms) to consider interesting
    pub time_threshold_ms: i64,
    /// Test query parameters
    pub test_query: bool,
    /// Test POST body parameters
    pub test_body: bool,
    /// Test headers
    pub test_headers: bool,
    /// Test cookies
    pub test_cookies: bool,
}

impl Default for ParamMinerConfig {
    fn default() -> Self {
        Self {
            custom_params: Vec::new(),
            custom_headers: Vec::new(),
            test_values: vec![
                "1".to_string(),
                "true".to_string(),
                "admin".to_string(),
                "test".to_string(),
                "{{callback}}".to_string(),
            ],
            concurrent: 5,
            delay_ms: 50,
            length_threshold: 5.0,
            time_threshold_ms: 500,
            test_query: true,
            test_body: true,
            test_headers: true,
            test_cookies: false,
        }
    }
}

/// Parameter miner
pub struct ParamMiner {
    /// Configuration
    config: ParamMinerConfig,
    /// HTTP client
    client: reqwest::Client,
}

impl ParamMiner {
    /// Create a new parameter miner
    pub fn new(config: ParamMinerConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self { config, client })
    }

    /// Get parameters to test
    pub fn get_params(&self) -> Vec<&str> {
        let mut params: Vec<&str> = COMMON_PARAMS.to_vec();
        params.extend(self.config.custom_params.iter().map(|s| s.as_str()));
        params
    }

    /// Get headers to test
    pub fn get_headers(&self) -> Vec<&str> {
        let mut headers: Vec<&str> = COMMON_HEADERS.to_vec();
        headers.extend(self.config.custom_headers.iter().map(|s| s.as_str()));
        headers
    }

    /// Mine parameters for a URL
    pub async fn mine(&self, base_url: &str) -> Result<Vec<DiscoveredParam>> {
        let mut results = Vec::new();

        // Get baseline response
        let baseline = self.get_baseline(base_url).await?;

        // Test query parameters
        if self.config.test_query {
            let params = self.get_params();
            for param in params {
                for value in &self.config.test_values {
                    let result = self
                        .test_query_param(base_url, param, value, &baseline)
                        .await?;
                    if result.is_interesting {
                        results.push(result);
                        break; // Found interesting, move to next param
                    }
                }

                // Rate limiting
                if self.config.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                }
            }
        }

        // Test headers
        if self.config.test_headers {
            let headers = self.get_headers();
            for header in headers {
                for value in &self.config.test_values {
                    let result = self
                        .test_header(base_url, header, value, &baseline)
                        .await?;
                    if result.is_interesting {
                        results.push(result);
                        break;
                    }
                }

                if self.config.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
                }
            }
        }

        Ok(results)
    }

    /// Get baseline response
    async fn get_baseline(&self, url: &str) -> Result<BaselineResponse> {
        let start = std::time::Instant::now();
        let response = self.client.get(url).send().await?;
        let elapsed = start.elapsed();

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(BaselineResponse {
            status,
            length: body.len(),
            time_ms: elapsed.as_millis() as i64,
            body,
        })
    }

    /// Test a query parameter
    async fn test_query_param(
        &self,
        base_url: &str,
        param: &str,
        value: &str,
        baseline: &BaselineResponse,
    ) -> Result<DiscoveredParam> {
        let mut url = url::Url::parse(base_url)?;
        url.query_pairs_mut().append_pair(param, value);

        let start = std::time::Instant::now();
        let response = self.client.get(url.as_str()).send().await?;
        let elapsed = start.elapsed();

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        let length = body.len();
        let time_ms = elapsed.as_millis() as i64;

        let (is_interesting, reason) =
            self.analyze_difference(baseline, status, length, time_ms, &body);

        Ok(DiscoveredParam {
            name: param.to_string(),
            location: ParamLocation::QueryString,
            baseline_length: baseline.length,
            response_length: length,
            baseline_status: baseline.status,
            response_status: status,
            is_interesting,
            reason,
            time_difference_ms: time_ms - baseline.time_ms,
        })
    }

    /// Test a header
    async fn test_header(
        &self,
        base_url: &str,
        header: &str,
        value: &str,
        baseline: &BaselineResponse,
    ) -> Result<DiscoveredParam> {
        let start = std::time::Instant::now();
        let response = self.client.get(base_url).header(header, value).send().await?;
        let elapsed = start.elapsed();

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        let length = body.len();
        let time_ms = elapsed.as_millis() as i64;

        let (is_interesting, reason) =
            self.analyze_difference(baseline, status, length, time_ms, &body);

        Ok(DiscoveredParam {
            name: header.to_string(),
            location: ParamLocation::Header,
            baseline_length: baseline.length,
            response_length: length,
            baseline_status: baseline.status,
            response_status: status,
            is_interesting,
            reason,
            time_difference_ms: time_ms - baseline.time_ms,
        })
    }

    /// Analyze difference between baseline and response
    fn analyze_difference(
        &self,
        baseline: &BaselineResponse,
        status: u16,
        length: usize,
        time_ms: i64,
        body: &str,
    ) -> (bool, Option<String>) {
        // Status code change
        if status != baseline.status {
            return (
                true,
                Some(format!(
                    "Status changed: {} -> {}",
                    baseline.status, status
                )),
            );
        }

        // Significant length change
        let length_diff =
            ((length as f64 - baseline.length as f64).abs() / baseline.length as f64) * 100.0;
        if length_diff > self.config.length_threshold {
            return (
                true,
                Some(format!(
                    "Length changed by {:.1}%: {} -> {}",
                    length_diff, baseline.length, length
                )),
            );
        }

        // Time-based detection
        let time_diff = (time_ms - baseline.time_ms).abs();
        if time_diff > self.config.time_threshold_ms {
            return (
                true,
                Some(format!(
                    "Response time increased by {}ms",
                    time_diff
                )),
            );
        }

        // Check for reflection of test value in response
        if body.contains("admin") && !baseline.body.contains("admin") {
            return (
                true,
                Some("Test value reflected in response".to_string()),
            );
        }

        // Check for error messages that weren't in baseline
        let error_indicators = ["error", "exception", "invalid", "denied", "forbidden"];
        for indicator in &error_indicators {
            if body.to_lowercase().contains(indicator)
                && !baseline.body.to_lowercase().contains(indicator)
            {
                return (
                    true,
                    Some(format!("New error indicator: '{}'", indicator)),
                );
            }
        }

        (false, None)
    }
}

/// Baseline response data
struct BaselineResponse {
    status: u16,
    length: usize,
    time_ms: i64,
    body: String,
}

/// Cache poisoning tester
pub struct CachePoisonTester {
    client: reqwest::Client,
}

impl CachePoisonTester {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client })
    }

    /// Test for cache poisoning via header injection
    pub async fn test_cache_poisoning(
        &self,
        url: &str,
    ) -> Result<Vec<CachePoisonResult>> {
        let mut results = Vec::new();

        // Generate unique cache buster
        let cache_buster = uuid::Uuid::new_v4().to_string();
        let test_url = if url.contains('?') {
            format!("{}&cb={}", url, cache_buster)
        } else {
            format!("{}?cb={}", url, cache_buster)
        };

        // Test X-Forwarded-Host
        let canary = format!("poison-test-{}", uuid::Uuid::new_v4());
        let response = self
            .client
            .get(&test_url)
            .header("X-Forwarded-Host", &canary)
            .send()
            .await?;
        let body = response.text().await.unwrap_or_default();

        if body.contains(&canary) {
            results.push(CachePoisonResult {
                header: "X-Forwarded-Host".to_string(),
                reflected: true,
                cached: false, // Would need second request to verify
                details: "Header value reflected in response".to_string(),
            });
        }

        // Test X-Forwarded-Scheme
        let response = self
            .client
            .get(&test_url)
            .header("X-Forwarded-Scheme", "https")
            .send()
            .await?;
        let _headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();

        if body.contains("https://") && !url.starts_with("https://") {
            results.push(CachePoisonResult {
                header: "X-Forwarded-Scheme".to_string(),
                reflected: true,
                cached: false,
                details: "Scheme reflected in response URLs".to_string(),
            });
        }

        Ok(results)
    }
}

impl Default for CachePoisonTester {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Cache poisoning test result
#[derive(Debug, Clone)]
pub struct CachePoisonResult {
    /// Header that was tested
    pub header: String,
    /// Whether the header was reflected
    pub reflected: bool,
    /// Whether the poisoned response was cached
    pub cached: bool,
    /// Details
    pub details: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_miner_config() {
        let config = ParamMinerConfig::default();
        assert!(config.test_query);
        assert!(config.test_headers);
        assert_eq!(config.concurrent, 5);
    }

    #[test]
    fn test_common_params_not_empty() {
        assert!(!COMMON_PARAMS.is_empty());
        assert!(COMMON_PARAMS.contains(&"debug"));
        assert!(COMMON_PARAMS.contains(&"admin"));
    }

    #[test]
    fn test_common_headers_not_empty() {
        assert!(!COMMON_HEADERS.is_empty());
        assert!(COMMON_HEADERS.contains(&"X-Forwarded-Host"));
        assert!(COMMON_HEADERS.contains(&"X-Original-URL"));
    }
}
