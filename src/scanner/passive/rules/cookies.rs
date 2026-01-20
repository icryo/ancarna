//! Cookie security analysis

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Rule for checking cookie security
pub struct CookieSecurityRule {
    enabled: bool,
}

impl CookieSecurityRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl PassiveRule for CookieSecurityRule {
    fn name(&self) -> &str {
        "Cookie Security"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_https = request.url.starts_with("https://");

        for cookie in &response.cookies {
            // Check for missing Secure flag on HTTPS
            if is_https && !cookie.secure {
                findings.push(
                    Finding::new(
                        "Cookie Without Secure Flag",
                        Severity::Medium,
                        &request.url,
                    )
                    .with_description(&format!(
                        "Cookie '{}' is set without the Secure flag on an HTTPS connection.",
                        cookie.name
                    ))
                    .with_evidence(&format!("Cookie: {}", cookie.name))
                    .with_scanner("passive/cookie-security")
                    .with_cwe(614)
                    .with_remediation("Add the Secure flag to the cookie."),
                );
            }

            // Check for missing HttpOnly flag on session-like cookies
            if !cookie.http_only && is_session_cookie(&cookie.name) {
                findings.push(
                    Finding::new(
                        "Session Cookie Without HttpOnly Flag",
                        Severity::Medium,
                        &request.url,
                    )
                    .with_description(&format!(
                        "Session cookie '{}' is set without the HttpOnly flag, making it accessible to JavaScript.",
                        cookie.name
                    ))
                    .with_evidence(&format!("Cookie: {}", cookie.name))
                    .with_scanner("passive/cookie-security")
                    .with_cwe(1004)
                    .with_remediation("Add the HttpOnly flag to session cookies."),
                );
            }

            // Check for missing SameSite attribute
            if cookie.same_site.is_none() {
                findings.push(
                    Finding::new(
                        "Cookie Without SameSite Attribute",
                        Severity::Low,
                        &request.url,
                    )
                    .with_description(&format!(
                        "Cookie '{}' is set without the SameSite attribute.",
                        cookie.name
                    ))
                    .with_evidence(&format!("Cookie: {}", cookie.name))
                    .with_scanner("passive/cookie-security")
                    .with_cwe(1275)
                    .with_remediation("Add the SameSite attribute to cookies (preferably 'Strict' or 'Lax')."),
                );
            }

            // Check for SameSite=None without Secure
            if let Some(same_site) = &cookie.same_site {
                if same_site.to_lowercase() == "none" && !cookie.secure {
                    findings.push(
                        Finding::new(
                            "SameSite=None Without Secure Flag",
                            Severity::Medium,
                            &request.url,
                        )
                        .with_description(&format!(
                            "Cookie '{}' has SameSite=None but no Secure flag. Modern browsers will reject this cookie.",
                            cookie.name
                        ))
                        .with_evidence(&format!("Cookie: {}", cookie.name))
                        .with_scanner("passive/cookie-security")
                        .with_cwe(614)
                        .with_remediation("Add the Secure flag when using SameSite=None."),
                    );
                }
            }

            // Check for overly broad domain
            if let Some(domain) = &cookie.domain {
                if domain.starts_with('.') && domain.matches('.').count() == 1 {
                    findings.push(
                        Finding::new(
                            "Cookie With Overly Broad Domain",
                            Severity::Low,
                            &request.url,
                        )
                        .with_description(&format!(
                            "Cookie '{}' has an overly broad domain '{}' which could expose it to subdomains.",
                            cookie.name, domain
                        ))
                        .with_evidence(&format!("Cookie domain: {}", domain))
                        .with_scanner("passive/cookie-security")
                        .with_cwe(1275)
                        .with_remediation("Use a more specific domain for cookies."),
                    );
                }
            }

            // Check for potentially sensitive data in cookie name/value
            let sensitive_patterns = ["password", "pwd", "secret", "token", "key", "api_key", "apikey"];
            let cookie_lower = cookie.name.to_lowercase();
            for pattern in sensitive_patterns {
                if cookie_lower.contains(pattern) && !cookie.http_only {
                    findings.push(
                        Finding::new(
                            "Potentially Sensitive Cookie Without HttpOnly",
                            Severity::Medium,
                            &request.url,
                        )
                        .with_description(&format!(
                            "Cookie '{}' appears to contain sensitive data but lacks the HttpOnly flag.",
                            cookie.name
                        ))
                        .with_evidence(&format!("Cookie name contains: {}", pattern))
                        .with_scanner("passive/cookie-security")
                        .with_cwe(1004)
                        .with_remediation("Add the HttpOnly flag to sensitive cookies."),
                    );
                    break;
                }
            }
        }

        findings
    }
}

/// Check if a cookie name looks like a session cookie
fn is_session_cookie(name: &str) -> bool {
    let session_patterns = [
        "session", "sess", "sid", "phpsessid", "jsessionid",
        "asp.net_sessionid", "aspsessionid", "cfid", "cftoken",
        "connect.sid", "auth", "login", "user", "token",
    ];

    let name_lower = name.to_lowercase();
    session_patterns.iter().any(|p| name_lower.contains(p))
}

impl Default for CookieSecurityRule {
    fn default() -> Self {
        Self::new()
    }
}
