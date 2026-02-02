//! Cache Control Security Analysis Rule

use std::collections::HashMap;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Cache control analysis passive scanner rule
pub struct CacheControlRule {
    enabled: bool,
}

impl CacheControlRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for CacheControlRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for CacheControlRule {
    fn name(&self) -> &str {
        "Cache Control"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        Self::analyze(response, &request.url)
    }
}

impl CacheControlRule {
    /// Analyze response for cache-related security issues
    pub fn analyze(response: &Response, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let cache_control = get_header(&response.headers, "cache-control").unwrap_or("");
        let is_sensitive = is_potentially_sensitive(response, url);

        // Missing cache control on sensitive pages
        if is_sensitive && cache_control.is_empty() {
            findings.push(
                Finding::new(
                    "Missing Cache-Control Header on Sensitive Page",
                    Severity::Medium,
                    url,
                )
                .with_description(
                    "The response from a potentially sensitive page does not include a \
                     Cache-Control header. This may allow sensitive data to be cached.",
                )
                .with_remediation(
                    "Add Cache-Control: no-store, no-cache, must-revalidate, private",
                )
                .with_cwe(525)
                .with_owasp("A01:2021 – Broken Access Control")
                .with_scanner("passive/cache"),
            );
        }

        // Public caching on sensitive pages
        if is_sensitive && cache_control.to_lowercase().contains("public") {
            findings.push(
                Finding::new(
                    "Public Cache Allowed on Sensitive Page",
                    Severity::Medium,
                    url,
                )
                .with_description(
                    "The Cache-Control header includes 'public' directive on a sensitive page.",
                )
                .with_evidence(&format!("Cache-Control: {}", cache_control))
                .with_remediation("Use 'private' instead of 'public' for sensitive content.")
                .with_cwe(525)
                .with_owasp("A01:2021 – Broken Access Control")
                .with_scanner("passive/cache"),
            );
        }

        findings
    }
}

fn get_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let name_lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name_lower)
        .map(|(_, v)| v.as_str())
}

fn is_potentially_sensitive(response: &Response, url: &str) -> bool {
    let url_lower = url.to_lowercase();
    let sensitive_paths = [
        "login", "signin", "account", "profile", "admin", "api/", "password", "auth",
    ];

    if sensitive_paths.iter().any(|p| url_lower.contains(p)) {
        return true;
    }

    response.headers.keys().any(|k| {
        let k_lower = k.to_lowercase();
        k_lower == "authorization" || k_lower == "set-cookie"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_header() {
        let mut headers = HashMap::new();
        headers.insert("Cache-Control".to_string(), "no-cache".to_string());
        assert_eq!(get_header(&headers, "cache-control"), Some("no-cache"));
    }
}
