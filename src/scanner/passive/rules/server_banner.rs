//! Server Banner/Technology Disclosure Rule

use std::collections::HashMap;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;
use regex::Regex;

/// Server banner disclosure passive scanner rule
pub struct ServerBannerRule {
    enabled: bool,
}

impl ServerBannerRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for ServerBannerRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for ServerBannerRule {
    fn name(&self) -> &str {
        "Server Banner"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        Self::analyze(response, &request.url)
    }
}

impl ServerBannerRule {
    /// Analyze response for server/technology disclosure
    pub fn analyze(response: &Response, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check Server header
        if let Some(server) = get_header(&response.headers, "server") {
            if let Some(finding) = analyze_server_header(server, url) {
                findings.push(finding);
            }
        }

        // Check X-Powered-By header
        if let Some(powered_by) = get_header(&response.headers, "x-powered-by") {
            findings.push(
                Finding::new("X-Powered-By Header Disclosure", Severity::Low, url)
                    .with_description(&format!(
                        "The X-Powered-By header discloses the technology stack: {}",
                        powered_by
                    ))
                    .with_evidence(&format!("X-Powered-By: {}", powered_by))
                    .with_remediation("Remove the X-Powered-By header in production.")
                    .with_cwe(200)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/server_banner"),
            );
        }

        // Check X-AspNet-Version
        if let Some(aspnet) = get_header(&response.headers, "x-aspnet-version") {
            findings.push(
                Finding::new("ASP.NET Version Disclosure", Severity::Low, url)
                    .with_description(&format!(
                        "The X-AspNet-Version header discloses the ASP.NET version: {}",
                        aspnet
                    ))
                    .with_evidence(&format!("X-AspNet-Version: {}", aspnet))
                    .with_remediation("Disable version headers in production.")
                    .with_cwe(200)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/server_banner"),
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

fn analyze_server_header(server: &str, url: &str) -> Option<Finding> {
    let version_pattern = Regex::new(r"[\d]+\.[\d]+(?:\.[\d]+)?").ok()?;

    if version_pattern.is_match(server) {
        return Some(
            Finding::new("Server Version Disclosure", Severity::Low, url)
                .with_description(&format!(
                    "The Server header discloses version information: {}",
                    server
                ))
                .with_evidence(&format!("Server: {}", server))
                .with_remediation("Configure the web server to remove version information.")
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration")
                .with_scanner("passive/server_banner"),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_server_header() {
        let finding = analyze_server_header("Apache/2.4.41 (Ubuntu)", "https://example.com");
        assert!(finding.is_some());

        let finding = analyze_server_header("cloudflare", "https://example.com");
        assert!(finding.is_none());
    }
}
