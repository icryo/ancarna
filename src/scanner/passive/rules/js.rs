//! JavaScript Analysis Rule
//!
//! Detects secrets, endpoints, and vulnerable libraries in JavaScript responses.

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::js_analysis::{JsAnalyzer, SecretType};
use crate::scanner::passive::PassiveRule;

/// JavaScript analysis passive scanner rule
pub struct JsAnalysisRule {
    enabled: bool,
    analyzer: JsAnalyzer,
}

impl JsAnalysisRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            analyzer: JsAnalyzer::new(),
        }
    }

    fn is_javascript_response(response: &Response) -> bool {
        if let Some(content_type) = response.header("content-type") {
            let ct = content_type.to_lowercase();
            return ct.contains("javascript") || ct.contains("application/json");
        }
        false
    }
}

impl Default for JsAnalysisRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for JsAnalysisRule {
    fn name(&self) -> &str {
        "JavaScript Analysis"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();
        let url = &request.url;
        let body = response.body_text();

        // Only analyze JavaScript responses or responses with substantial JS content
        if !Self::is_javascript_response(response) && body.len() < 1000 {
            return findings;
        }

        // Detect secrets
        for secret in self.analyzer.detect_secrets(&body, url) {
            let severity = match secret.secret_type.severity() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Informational,
            };

            findings.push(
                Finding::new(
                    &format!("Exposed {} in JavaScript", secret.secret_type.name()),
                    severity,
                    url,
                )
                .with_description(&format!(
                    "A {} was detected in JavaScript code. Confidence: {}%",
                    secret.secret_type.name(),
                    secret.confidence
                ))
                .with_evidence(&format!("Value: {} | Context: {}", secret.value, secret.context))
                .with_remediation(self.get_secret_remediation(&secret.secret_type))
                .with_cwe(798) // CWE-798: Use of Hard-coded Credentials
                .with_owasp("A02:2021 – Cryptographic Failures")
                .with_scanner("passive/js-analysis"),
            );
        }

        // Detect vulnerable libraries
        for lib in self.analyzer.detect_vulnerable_libraries(&body) {
            for vuln in &lib.vulnerabilities {
                let severity = match vuln.severity.as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Informational,
                };

                let cve_info = vuln.cve.as_ref()
                    .map(|c| format!(" ({})", c))
                    .unwrap_or_default();

                findings.push(
                    Finding::new(
                        &format!("Vulnerable JavaScript Library: {} {}{}", lib.name, lib.version, cve_info),
                        severity,
                        url,
                    )
                    .with_description(&vuln.description)
                    .with_evidence(&format!("Library: {} version {}", lib.name, lib.version))
                    .with_remediation(&format!("Update {} to the latest version.", lib.name))
                    .with_cwe(1104) // CWE-1104: Use of Unmaintained Third Party Components
                    .with_owasp("A06:2021 – Vulnerable and Outdated Components")
                    .with_scanner("passive/js-analysis"),
                );
            }
        }

        findings
    }
}

impl JsAnalysisRule {
    fn get_secret_remediation(&self, secret_type: &SecretType) -> &'static str {
        match secret_type {
            SecretType::AwsAccessKey | SecretType::AwsSecretKey => {
                "Remove AWS credentials from client-side code. Use IAM roles or temporary credentials instead."
            }
            SecretType::GoogleApiKey => {
                "Restrict the API key to specific APIs and domains. Consider using server-side API calls."
            }
            SecretType::GitHubToken | SecretType::GitLabToken => {
                "Rotate the token immediately and remove from client-side code."
            }
            SecretType::StripeKey => {
                "Never expose Stripe secret keys in client code. Use publishable keys for client-side."
            }
            SecretType::PrivateKey => {
                "Remove private keys from JavaScript. Store securely on server-side only."
            }
            SecretType::DatabaseUrl => {
                "Database connections should only be made from server-side code."
            }
            _ => {
                "Remove sensitive credentials from client-side JavaScript and use server-side APIs."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_js_response(body: &str) -> Response {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/javascript".to_string());
        Response {
            status: 200,
            status_text: "OK".to_string(),
            headers,
            body: body.as_bytes().to_vec(),
            duration_ms: Some(100),
            remote_addr: None,
        }
    }

    #[test]
    fn test_detects_aws_key() {
        let rule = JsAnalysisRule::new();
        let request = Request::new("GET", "https://example.com/app.js");
        // Using a realistic AWS key format (AKIA + 16 uppercase alphanumeric)
        let response = create_js_response(r#"const key = "AKIAI44QH8DHBTEST12X";"#);

        let findings = rule.scan(&request, &response);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.name.contains("AWS")));
    }
}
