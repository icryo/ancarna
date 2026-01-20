//! CORS (Cross-Origin Resource Sharing) analysis

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Rule for checking CORS configuration
pub struct CorsRule {
    enabled: bool,
}

impl CorsRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl PassiveRule for CorsRule {
    fn name(&self) -> &str {
        "CORS Configuration"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        let acao = response.header("access-control-allow-origin");
        let acac = response.header("access-control-allow-credentials");

        // Check for overly permissive CORS
        if let Some(origin) = acao {
            if origin == "*" {
                if acac.map(|v| v == "true").unwrap_or(false) {
                    // Wildcard with credentials is actually invalid per CORS spec
                    // but some servers misconfigure this
                    findings.push(
                        Finding::new(
                            "Invalid CORS: Wildcard with Credentials",
                            Severity::High,
                            &request.url,
                        )
                        .with_description(
                            "The Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is 'true'. This is invalid but indicates a security misconfiguration.",
                        )
                        .with_evidence(&format!(
                            "Access-Control-Allow-Origin: {}, Access-Control-Allow-Credentials: true",
                            origin
                        ))
                        .with_scanner("passive/cors")
                        .with_cwe(942)
                        .with_owasp("A01:2021 – Broken Access Control")
                        .with_remediation("Do not use wildcard origin with credentials. Specify explicit origins."),
                    );
                } else {
                    findings.push(
                        Finding::new(
                            "CORS Wildcard Origin",
                            Severity::Low,
                            &request.url,
                        )
                        .with_description(
                            "The Access-Control-Allow-Origin is set to '*', allowing any origin to access this resource.",
                        )
                        .with_evidence(&format!("Access-Control-Allow-Origin: {}", origin))
                        .with_scanner("passive/cors")
                        .with_cwe(942)
                        .with_remediation("Consider restricting CORS to specific trusted origins."),
                    );
                }
            }

            // Check for null origin (can be exploited)
            if origin == "null" {
                findings.push(
                    Finding::new(
                        "CORS Allows Null Origin",
                        Severity::Medium,
                        &request.url,
                    )
                    .with_description(
                        "The Access-Control-Allow-Origin allows 'null' origin, which can be exploited via sandboxed iframes.",
                    )
                    .with_evidence(&format!("Access-Control-Allow-Origin: {}", origin))
                    .with_scanner("passive/cors")
                    .with_cwe(942)
                    .with_remediation("Do not allow 'null' as an origin. Use explicit origins."),
                );
            }

            // Check for origin reflection (potential vulnerability)
            if let Some(request_origin) = request.headers.get("origin") {
                if origin == request_origin && !origin.contains("*") {
                    // Check if it's reflecting any origin (would need multiple requests to confirm)
                    // For now, just note that origin is being reflected
                    findings.push(
                        Finding::new(
                            "CORS Origin Reflection",
                            Severity::Informational,
                            &request.url,
                        )
                        .with_description(
                            "The server reflects the Origin header. If the server reflects any origin without validation, this could be exploited.",
                        )
                        .with_evidence(&format!(
                            "Request Origin: {}, Response ACAO: {}",
                            request_origin, origin
                        ))
                        .with_scanner("passive/cors")
                        .with_cwe(942)
                        .with_confidence(0.3) // Low confidence without further testing
                        .with_remediation("Verify that the server only allows trusted origins."),
                    );
                }
            }
        }

        // Check for exposed headers that might leak sensitive info
        if let Some(exposed) = response.header("access-control-expose-headers") {
            let sensitive_headers = ["authorization", "x-api-key", "x-auth-token", "set-cookie"];
            let exposed_lower = exposed.to_lowercase();

            for sensitive in sensitive_headers {
                if exposed_lower.contains(sensitive) {
                    findings.push(
                        Finding::new(
                            "CORS Exposes Sensitive Headers",
                            Severity::Medium,
                            &request.url,
                        )
                        .with_description(&format!(
                            "The Access-Control-Expose-Headers includes '{}', which could expose sensitive information.",
                            sensitive
                        ))
                        .with_evidence(&format!("Access-Control-Expose-Headers: {}", exposed))
                        .with_scanner("passive/cors")
                        .with_cwe(200)
                        .with_remediation("Only expose necessary headers via CORS."),
                    );
                }
            }
        }

        findings
    }
}

impl Default for CorsRule {
    fn default() -> Self {
        Self::new()
    }
}
