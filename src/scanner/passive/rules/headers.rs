//! Security headers analysis

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Rule for checking security headers
pub struct SecurityHeadersRule {
    enabled: bool,
}

impl SecurityHeadersRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl PassiveRule for SecurityHeadersRule {
    fn name(&self) -> &str {
        "Security Headers"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for missing security headers
        let security_headers = [
            ("X-Content-Type-Options", "Missing X-Content-Type-Options Header",
             "The X-Content-Type-Options header is not set. This could allow MIME type sniffing attacks.",
             Severity::Low, 16),
            ("X-Frame-Options", "Missing X-Frame-Options Header",
             "The X-Frame-Options header is not set. This could allow clickjacking attacks.",
             Severity::Medium, 1021),
            ("Content-Security-Policy", "Missing Content-Security-Policy Header",
             "The Content-Security-Policy header is not set. This could allow XSS and data injection attacks.",
             Severity::Medium, 693),
            ("Strict-Transport-Security", "Missing Strict-Transport-Security Header",
             "The HSTS header is not set. This could allow protocol downgrade attacks.",
             Severity::Medium, 319),
            ("X-XSS-Protection", "Missing X-XSS-Protection Header",
             "The X-XSS-Protection header is not set.",
             Severity::Low, 79),
            ("Referrer-Policy", "Missing Referrer-Policy Header",
             "The Referrer-Policy header is not set. Sensitive information might leak via the Referer header.",
             Severity::Low, 200),
            ("Permissions-Policy", "Missing Permissions-Policy Header",
             "The Permissions-Policy header is not set.",
             Severity::Informational, 0),
        ];

        for (header, name, description, severity, cwe) in security_headers {
            if response.header(header).is_none() {
                let mut finding = Finding::new(name, severity, &request.url)
                    .with_description(description)
                    .with_scanner("passive/security-headers")
                    .with_remediation(&format!("Add the {} header to responses.", header));

                if cwe > 0 {
                    finding = finding.with_cwe(cwe);
                }

                findings.push(finding);
            }
        }

        // Check for X-Powered-By header (information disclosure)
        if let Some(powered_by) = response.header("X-Powered-By") {
            findings.push(
                Finding::new("X-Powered-By Header Disclosure", Severity::Low, &request.url)
                    .with_description("The X-Powered-By header reveals server technology information.")
                    .with_evidence(powered_by)
                    .with_scanner("passive/security-headers")
                    .with_cwe(200)
                    .with_remediation("Remove or obfuscate the X-Powered-By header."),
            );
        }

        // Check for Server header (information disclosure)
        if let Some(server) = response.header("Server") {
            // Only flag if it contains version information
            if server.contains('/') || server.chars().any(|c| c.is_numeric()) {
                findings.push(
                    Finding::new("Server Header Version Disclosure", Severity::Low, &request.url)
                        .with_description("The Server header reveals version information.")
                        .with_evidence(server)
                        .with_scanner("passive/security-headers")
                        .with_cwe(200)
                        .with_remediation("Remove version information from the Server header."),
                );
            }
        }

        // Check for insecure CSP
        if let Some(csp) = response.header("Content-Security-Policy") {
            if csp.contains("unsafe-inline") {
                findings.push(
                    Finding::new("CSP Contains unsafe-inline", Severity::Medium, &request.url)
                        .with_description("The Content-Security-Policy contains 'unsafe-inline' which reduces XSS protection.")
                        .with_evidence(csp)
                        .with_scanner("passive/security-headers")
                        .with_cwe(79)
                        .with_remediation("Remove 'unsafe-inline' from CSP and use nonces or hashes instead."),
                );
            }

            if csp.contains("unsafe-eval") {
                findings.push(
                    Finding::new("CSP Contains unsafe-eval", Severity::Medium, &request.url)
                        .with_description("The Content-Security-Policy contains 'unsafe-eval' which allows eval() and similar functions.")
                        .with_evidence(csp)
                        .with_scanner("passive/security-headers")
                        .with_cwe(79)
                        .with_remediation("Remove 'unsafe-eval' from CSP and refactor code to avoid eval()."),
                );
            }
        }

        findings
    }
}

impl Default for SecurityHeadersRule {
    fn default() -> Self {
        Self::new()
    }
}
