//! Anti-CSRF Token Detection Rule

use std::collections::HashMap;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;
use regex::Regex;

/// CSRF analysis passive scanner rule
pub struct CsrfRule {
    enabled: bool,
}

impl CsrfRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for CsrfRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveRule for CsrfRule {
    fn name(&self) -> &str {
        "CSRF Protection"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        Self::analyze(response, &request.url, &response.body_text())
    }
}

impl CsrfRule {
    /// Analyze response for CSRF protection
    pub fn analyze(response: &Response, url: &str, body: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !is_html_response(response) {
            return findings;
        }

        // Check for forms without CSRF tokens
        let forms = extract_forms(body);
        for form in forms {
            let method = form.method.to_uppercase();
            if method != "POST" && method != "PUT" && method != "DELETE" {
                continue;
            }

            let has_csrf_token = form.inputs.iter().any(|name| is_csrf_token_name(name));

            if !has_csrf_token {
                findings.push(
                    Finding::new("Form Without CSRF Protection", Severity::Medium, url)
                        .with_description(&format!(
                            "A form with method '{}' does not appear to have CSRF protection.",
                            form.method
                        ))
                        .with_evidence(&format!("Form action: {}", form.action.as_deref().unwrap_or("(same page)")))
                        .with_remediation("Implement CSRF protection using synchronizer tokens.")
                        .with_cwe(352)
                        .with_owasp("A01:2021 – Broken Access Control")
                        .with_scanner("passive/csrf"),
                );
            }
        }

        // Check SameSite cookie attribute
        if let Some(set_cookie) = get_header(&response.headers, "set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();
            if (cookie_lower.contains("session") || cookie_lower.contains("auth"))
                && !cookie_lower.contains("samesite")
            {
                findings.push(
                    Finding::new("Session Cookie Missing SameSite Attribute", Severity::Low, url)
                        .with_description("A session cookie is set without the SameSite attribute.")
                        .with_evidence(&format!("Set-Cookie: {}", set_cookie))
                        .with_remediation("Add SameSite=Strict or SameSite=Lax to session cookies.")
                        .with_cwe(352)
                        .with_owasp("A01:2021 – Broken Access Control")
                        .with_scanner("passive/csrf"),
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

fn is_csrf_token_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    let csrf_names = [
        "csrf", "_csrf", "csrftoken", "csrf_token", "_token", "authenticity_token", "xsrf",
    ];
    csrf_names.iter().any(|n| name_lower.contains(n))
}

struct FormInfo {
    method: String,
    action: Option<String>,
    inputs: Vec<String>,
}

fn extract_forms(html: &str) -> Vec<FormInfo> {
    let mut forms = Vec::new();
    let form_pattern = Regex::new(r"(?is)<form[^>]*>(.*?)</form>").ok();
    let method_pattern = Regex::new(r#"(?i)method\s*=\s*["']?(\w+)["']?"#).ok();
    let action_pattern = Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).ok();
    let input_pattern = Regex::new(r#"(?i)<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>"#).ok();

    if let Some(form_re) = form_pattern {
        for cap in form_re.captures_iter(html) {
            let form_html = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let form_body = cap.get(1).map(|m| m.as_str()).unwrap_or("");

            let method = method_pattern.as_ref()
                .and_then(|p| p.captures(form_html))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "GET".to_string());

            let action = action_pattern.as_ref()
                .and_then(|p| p.captures(form_html))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            let mut inputs = Vec::new();
            if let Some(input_re) = &input_pattern {
                for input_cap in input_re.captures_iter(form_body) {
                    if let Some(name) = input_cap.get(1) {
                        inputs.push(name.as_str().to_string());
                    }
                }
            }

            forms.push(FormInfo { method, action, inputs });
        }
    }

    forms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_csrf_token_name() {
        assert!(is_csrf_token_name("csrf_token"));
        assert!(is_csrf_token_name("authenticity_token"));
        assert!(!is_csrf_token_name("username"));
    }
}
