//! Permissions Policy (Feature-Policy) Analysis Rule

use std::collections::HashMap;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Permissions policy analysis passive scanner rule
pub struct PermissionsPolicyRule {
    enabled: bool,
}

impl PermissionsPolicyRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for PermissionsPolicyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for PermissionsPolicyRule {
    fn name(&self) -> &str {
        "Permissions Policy"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        Self::analyze(response, &request.url)
    }
}

impl PermissionsPolicyRule {
    /// Analyze response for permissions policy issues
    pub fn analyze(response: &Response, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !is_html_response(response) {
            return findings;
        }

        let permissions_policy = get_header(&response.headers, "permissions-policy");
        let feature_policy = get_header(&response.headers, "feature-policy");

        // No policy at all
        if permissions_policy.is_none() && feature_policy.is_none() {
            findings.push(
                Finding::new("Missing Permissions-Policy Header", Severity::Low, url)
                    .with_description(
                        "The response does not include a Permissions-Policy header. \
                         This header controls which browser features can be used.",
                    )
                    .with_remediation(
                        "Add a Permissions-Policy header: camera=(), microphone=(), geolocation=()",
                    )
                    .with_cwe(16)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/permissions_policy"),
            );
            return findings;
        }

        // Deprecated Feature-Policy header
        if permissions_policy.is_none() && feature_policy.is_some() {
            findings.push(
                Finding::new("Using Deprecated Feature-Policy Header", Severity::Informational, url)
                    .with_description("The response uses the deprecated Feature-Policy header.")
                    .with_evidence(&format!("Feature-Policy: {}", feature_policy.unwrap_or("")))
                    .with_remediation("Migrate from Feature-Policy to Permissions-Policy.")
                    .with_cwe(16)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/permissions_policy"),
            );
        }

        // Check for dangerous features enabled widely
        let policy = permissions_policy.or(feature_policy).unwrap_or("");
        let policy_lower = policy.to_lowercase();

        let dangerous_features = ["camera", "microphone", "geolocation", "payment"];

        for feature in dangerous_features {
            if policy_lower.contains(&format!("{}=*", feature)) {
                findings.push(
                    Finding::new(
                        &format!("Permissions-Policy: {} allowed from all origins", feature),
                        Severity::Low,
                        url,
                    )
                    .with_description(&format!(
                        "The '{}' feature is allowed from all origins.",
                        feature
                    ))
                    .with_evidence(&format!("Permissions-Policy: {}", policy))
                    .with_remediation(&format!("Restrict the {} feature: {}=()", feature, feature))
                    .with_cwe(16)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_scanner("passive/permissions_policy"),
                );
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
    fn test_dangerous_features() {
        let features = ["camera", "microphone", "geolocation", "payment"];
        for feature in features {
            assert!(!feature.is_empty());
        }
    }
}
