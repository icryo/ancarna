//! Content Security Policy (CSP) Analysis Rule
//!
//! Analyzes CSP headers for security weaknesses.

use std::collections::HashMap;

use crate::http::Response;
use crate::scanner::findings::{Finding, Severity};

/// CSP analysis passive scanner rule
pub struct CspRule;

impl CspRule {
    /// Analyze response for CSP issues
    pub fn analyze(response: &Response, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let csp = get_header(&response.headers, "content-security-policy");
        let csp_report_only = get_header(&response.headers, "content-security-policy-report-only");

        // No CSP header at all
        if csp.is_none() && csp_report_only.is_none() {
            if is_html_response(response) {
                findings.push(
                    Finding::new("Missing Content-Security-Policy Header", Severity::Medium, url)
                        .with_description(
                            "The response does not include a Content-Security-Policy header. \
                             CSP helps prevent XSS, clickjacking, and other code injection attacks.",
                        )
                        .with_remediation(
                            "Implement a Content-Security-Policy header with restrictive directives.",
                        )
                        .with_cwe(1021)
                        .with_owasp("A05:2021 – Security Misconfiguration")
                        .with_scanner("passive/csp"),
                );
            }
            return findings;
        }

        // Analyze CSP directives
        let csp_value = csp.or(csp_report_only).unwrap_or("");
        let directives = parse_csp(csp_value);

        // Check for unsafe directives
        for (directive, values) in &directives {
            // Unsafe-inline
            if values.contains(&"'unsafe-inline'") {
                let severity = match directive.as_str() {
                    "script-src" | "default-src" => Severity::High,
                    "style-src" => Severity::Low,
                    _ => Severity::Medium,
                };

                findings.push(
                    Finding::new(
                        &format!("CSP: {} contains 'unsafe-inline'", directive),
                        severity,
                        url,
                    )
                    .with_description(&format!(
                        "The {} directive contains 'unsafe-inline' which allows inline scripts/styles, \
                         significantly reducing XSS protection.",
                        directive
                    ))
                    .with_evidence(&format!("CSP: {}", csp_value))
                    .with_remediation(
                        "Remove 'unsafe-inline' and use nonces or hashes for legitimate inline code.",
                    )
                    .with_cwe(79)
                    .with_owasp("A03:2021 – Injection")
                    .with_scanner("passive/csp"),
                );
            }

            // Unsafe-eval
            if values.contains(&"'unsafe-eval'") {
                let severity = match directive.as_str() {
                    "script-src" | "default-src" => Severity::High,
                    _ => Severity::Medium,
                };

                findings.push(
                    Finding::new(
                        &format!("CSP: {} contains 'unsafe-eval'", directive),
                        severity,
                        url,
                    )
                    .with_description(&format!(
                        "The {} directive contains 'unsafe-eval' which allows eval() and similar \
                         functions, enabling code execution from strings.",
                        directive
                    ))
                    .with_evidence(&format!("CSP: {}", csp_value))
                    .with_remediation(
                        "Remove 'unsafe-eval' and refactor code to avoid dynamic code execution.",
                    )
                    .with_cwe(79)
                    .with_owasp("A03:2021 – Injection")
                    .with_scanner("passive/csp"),
                );
            }

            // Wildcard sources
            if values.contains(&"*") {
                findings.push(
                    Finding::new(
                        &format!("CSP: {} contains wildcard (*)", directive),
                        Severity::Medium,
                        url,
                    )
                    .with_description(&format!(
                        "The {} directive contains a wildcard (*) which allows resources from any origin.",
                        directive
                    ))
                    .with_evidence(&format!("CSP: {}", csp_value))
                    .with_remediation("Replace wildcard with specific trusted domains.")
                    .with_cwe(16)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/csp"),
                );
            }
        }

        // Check for missing important directives
        if !directives.contains_key("default-src") && !directives.contains_key("script-src") {
            findings.push(
                Finding::new(
                    "CSP: Missing script-src or default-src directive",
                    Severity::Medium,
                    url,
                )
                .with_description(
                    "The CSP lacks both script-src and default-src directives, \
                     providing no protection against script injection.",
                )
                .with_evidence(&format!("CSP: {}", csp_value))
                .with_remediation("Add a restrictive script-src or default-src directive.")
                .with_cwe(79)
                .with_owasp("A03:2021 – Injection")
                .with_scanner("passive/csp"),
            );
        }

        // Check for report-only mode
        if csp.is_none() && csp_report_only.is_some() {
            findings.push(
                Finding::new(
                    "CSP: Report-Only Mode (Not Enforcing)",
                    Severity::Low,
                    url,
                )
                .with_description(
                    "The Content-Security-Policy-Report-Only header is set but no enforcing CSP header exists. \
                     CSP violations are only reported, not blocked.",
                )
                .with_evidence(&format!("CSP-Report-Only: {}", csp_report_only.unwrap_or("")))
                .with_remediation(
                    "After testing, move from report-only to enforcing CSP with Content-Security-Policy header.",
                )
                .with_cwe(16)
                .with_owasp("A05:2021 – Security Misconfiguration")
                .with_scanner("passive/csp"),
            );
        }

        findings
    }
}

/// Get header value (case-insensitive)
fn get_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let name_lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name_lower)
        .map(|(_, v)| v.as_str())
}

/// Parse CSP header into directives and their values
fn parse_csp(csp: &str) -> HashMap<String, Vec<&str>> {
    let mut directives = HashMap::new();

    for directive_part in csp.split(';') {
        let parts: Vec<&str> = directive_part.trim().split_whitespace().collect();
        if let Some((&name, values)) = parts.split_first() {
            directives.insert(name.to_lowercase(), values.to_vec());
        }
    }

    directives
}

/// Check if response is HTML
fn is_html_response(response: &Response) -> bool {
    get_header(&response.headers, "content-type")
        .map(|ct| ct.contains("text/html"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csp() {
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src *";
        let directives = parse_csp(csp);

        assert!(directives.contains_key("default-src"));
        assert!(directives.contains_key("script-src"));
        assert!(directives.contains_key("style-src"));
        assert!(directives["script-src"].contains(&"'unsafe-inline'"));
        assert!(directives["style-src"].contains(&"*"));
    }
}
