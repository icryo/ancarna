//! JWT Token Analysis Rule
//!
//! Detects and analyzes JWT tokens in responses.

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::jwt::JwtAnalyzer;
use crate::scanner::passive::PassiveRule;
use regex::Regex;

/// JWT analysis passive scanner rule
pub struct JwtRule {
    enabled: bool,
    analyzer: JwtAnalyzer,
    jwt_pattern: Regex,
}

impl JwtRule {
    pub fn new() -> Self {
        // Pattern to find JWTs: three base64url parts separated by dots
        let jwt_pattern = Regex::new(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        ).unwrap();

        Self {
            enabled: true,
            analyzer: JwtAnalyzer::new(),
            jwt_pattern,
        }
    }

    fn find_jwts(&self, text: &str) -> Vec<String> {
        self.jwt_pattern
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    fn analyze_jwt(&self, token: &str, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match self.analyzer.analyze(token) {
            Ok(report) => {
                // Check for weak secret
                if let Some(secret) = report.found_weak_secret() {
                    findings.push(
                        Finding::new("JWT Weak HMAC Secret", Severity::Critical, url)
                            .with_description(&format!(
                                "The JWT token is signed with a weak/guessable secret: '{}'",
                                secret
                            ))
                            .with_evidence(&format!("Token: {}...", &token[..50.min(token.len())]))
                            .with_remediation("Use a strong, random secret of at least 256 bits.")
                            .with_cwe(521)
                            .with_owasp("A02:2021 – Cryptographic Failures")
                            .with_scanner("passive/jwt")
                    );
                }

                // Report detected vulnerabilities
                for vuln in &report.vulnerabilities {
                    let severity = if vuln.starts_with("CRITICAL") {
                        Severity::Critical
                    } else if vuln.starts_with("HIGH") {
                        Severity::High
                    } else if vuln.starts_with("MEDIUM") {
                        Severity::Medium
                    } else if vuln.starts_with("LOW") {
                        Severity::Low
                    } else {
                        Severity::Informational
                    };

                    findings.push(
                        Finding::new("JWT Security Issue", severity, url)
                            .with_description(vuln)
                            .with_evidence(&format!("Algorithm: {}", report.token.header.alg))
                            .with_scanner("passive/jwt")
                    );
                }

                // Check for algorithm none
                if report.token.header.alg.to_lowercase() == "none" {
                    findings.push(
                        Finding::new("JWT Algorithm None Accepted", Severity::Critical, url)
                            .with_description("The JWT uses the 'none' algorithm, meaning the token is not cryptographically signed.")
                            .with_evidence(&format!("Token: {}...", &token[..50.min(token.len())]))
                            .with_remediation("Reject tokens with 'none' algorithm on the server.")
                            .with_cwe(327)
                            .with_owasp("A02:2021 – Cryptographic Failures")
                            .with_scanner("passive/jwt")
                    );
                }
            }
            Err(_) => {
                // Invalid JWT format - not a vulnerability, just skip
            }
        }

        findings
    }
}

impl Default for JwtRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for JwtRule {
    fn name(&self) -> &str {
        "JWT Analysis"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();
        let url = &request.url;

        // Check Authorization header in response
        if let Some(auth) = response.header("authorization") {
            if auth.starts_with("Bearer ") {
                let token = auth.trim_start_matches("Bearer ");
                findings.extend(self.analyze_jwt(token, url));
            }
        }

        // Check Set-Cookie headers for JWT tokens
        if let Some(cookie) = response.header("set-cookie") {
            for jwt in self.find_jwts(cookie) {
                findings.extend(self.analyze_jwt(&jwt, url));
            }
        }

        // Check response body for JWT tokens
        let body = response.body_text();
        for jwt in self.find_jwts(&body) {
            findings.extend(self.analyze_jwt(&jwt, url));
        }

        // Also check request headers (for completeness)
        if let Some(auth) = request.headers.get("authorization") {
            if auth.starts_with("Bearer ") {
                let token = auth.trim_start_matches("Bearer ");
                findings.extend(self.analyze_jwt(token, url));
            }
        }

        // Deduplicate findings by name
        findings.sort_by(|a, b| a.name.cmp(&b.name));
        findings.dedup_by(|a, b| a.name == b.name && a.description == b.description);

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_jwts() {
        let rule = JwtRule::new();
        let text = r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}"#;
        let jwts = rule.find_jwts(text);
        assert_eq!(jwts.len(), 1);
        assert!(jwts[0].starts_with("eyJ"));
    }
}
