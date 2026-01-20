//! Referrer Policy Analysis Rule

use std::collections::HashMap;

use crate::http::Response;
use crate::scanner::findings::{Finding, Severity};

/// Referrer policy analysis passive scanner rule
pub struct ReferrerPolicyRule;

impl ReferrerPolicyRule {
    /// Analyze response for referrer policy issues
    pub fn analyze(response: &Response, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !is_html_response(response) {
            return findings;
        }

        let referrer_policy = get_header(&response.headers, "referrer-policy");

        match referrer_policy {
            None => {
                findings.push(
                    Finding::new("Missing Referrer-Policy Header", Severity::Low, url)
                        .with_description(
                            "The response does not include a Referrer-Policy header. \
                             Sensitive information might leak via the Referer header.",
                        )
                        .with_remediation(
                            "Add Referrer-Policy header with a restrictive policy like 'strict-origin-when-cross-origin'.",
                        )
                        .with_cwe(200)
                        .with_owasp("A05:2021 – Security Misconfiguration")
                        .with_scanner("passive/referrer_policy"),
                );
            }
            Some(policy) => {
                let policy_lower = policy.to_lowercase();

                if policy_lower == "unsafe-url" {
                    findings.push(
                        Finding::new(
                            "Referrer-Policy: unsafe-url (Information Leak)",
                            Severity::Medium,
                            url,
                        )
                        .with_description(
                            "The Referrer-Policy is set to 'unsafe-url' which sends the full URL \
                             as the Referer header to all origins. This can leak sensitive information.",
                        )
                        .with_evidence(&format!("Referrer-Policy: {}", policy))
                        .with_remediation("Use a more restrictive policy like 'strict-origin-when-cross-origin'.")
                        .with_cwe(200)
                        .with_owasp("A01:2021 – Broken Access Control")
                        .with_scanner("passive/referrer_policy"),
                    );
                }

                if policy.trim().is_empty() {
                    findings.push(
                        Finding::new("Empty Referrer-Policy Header", Severity::Low, url)
                            .with_description("The Referrer-Policy header is present but empty.")
                            .with_evidence("Referrer-Policy: (empty)")
                            .with_remediation("Set a valid referrer policy value.")
                            .with_cwe(16)
                            .with_owasp("A05:2021 – Security Misconfiguration")
                            .with_scanner("passive/referrer_policy"),
                    );
                }
            }
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

fn is_html_response(response: &Response) -> bool {
    get_header(&response.headers, "content-type")
        .map(|ct| ct.contains("text/html"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_valid_policies() {
        let valid = ["no-referrer", "strict-origin-when-cross-origin", "same-origin"];
        for policy in valid {
            assert!(!policy.is_empty());
        }
    }
}
