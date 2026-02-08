//! Nuclei-compatible template engine
//!
//! Supports YAML-based vulnerability detection templates compatible with
//! ProjectDiscovery's Nuclei format.

mod parser;
mod matcher;
mod executor;
#[cfg(test)]
mod tests;

pub use parser::{Template, TemplateInfo, HttpRequest, Matcher, MatcherType, MatcherCondition, Severity};
pub use matcher::{MatchResult, execute_matcher, execute_matchers};
pub use executor::{TemplateExecutor, TemplateVariables, ActiveScanResult};

use anyhow::Result;
use std::path::Path;

/// Load templates from a directory (recursively)
pub fn load_templates_from_dir(dir: &Path) -> Result<Vec<Template>> {
    let mut templates = Vec::new();

    if !dir.exists() {
        return Ok(templates);
    }

    load_templates_recursive(dir, &mut templates)?;
    Ok(templates)
}

fn load_templates_recursive(dir: &Path, templates: &mut Vec<Template>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            load_templates_recursive(&path, templates)?;
        } else if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
            match Template::from_file(&path) {
                Ok(template) => templates.push(template),
                Err(e) => tracing::warn!("Failed to load template {}: {}", path.display(), e),
            }
        }
    }
    Ok(())
}

/// Load a single template from a file
pub fn load_template(path: &Path) -> Result<Template> {
    Template::from_file(path)
}

/// Get bundled templates (passive + active)
pub fn bundled_templates() -> Vec<Template> {
    let mut templates = Vec::new();

    // Add bundled passive templates
    templates.extend(bundled::security_headers());
    templates.extend(bundled::information_disclosure());
    templates.extend(bundled::misconfigurations());
    templates.extend(bundled::vulnerabilities());

    // Add bundled active templates from YAML
    templates.extend(bundled::active_templates());

    templates
}

/// Get only passive bundled templates
pub fn bundled_passive_templates() -> Vec<Template> {
    let mut templates = Vec::new();
    templates.extend(bundled::security_headers());
    templates.extend(bundled::information_disclosure());
    templates.extend(bundled::misconfigurations());
    templates.extend(bundled::vulnerabilities());
    templates
}

/// Get only active bundled templates
pub fn bundled_active_templates() -> Vec<Template> {
    bundled::active_templates()
}

/// Bundled template definitions
mod bundled {
    use super::*;

    pub fn security_headers() -> Vec<Template> {
        vec![
            Template::passive("missing-hsts")
                .name("Missing HSTS Header")
                .severity(Severity::Low)
                .description("Strict-Transport-Security header is missing")
                .tags(&["headers", "security", "hsts"])
                .matcher(Matcher::header_missing("Strict-Transport-Security"))
                .build(),

            Template::passive("missing-csp")
                .name("Missing Content-Security-Policy")
                .severity(Severity::Medium)
                .description("Content-Security-Policy header is missing")
                .tags(&["headers", "security", "csp"])
                .matcher(Matcher::header_missing("Content-Security-Policy"))
                .build(),

            Template::passive("missing-x-frame-options")
                .name("Missing X-Frame-Options")
                .severity(Severity::Medium)
                .description("X-Frame-Options header is missing, vulnerable to clickjacking")
                .tags(&["headers", "security", "clickjacking"])
                .matcher(Matcher::header_missing("X-Frame-Options"))
                .cwe(1021)
                .build(),

            Template::passive("missing-x-content-type-options")
                .name("Missing X-Content-Type-Options")
                .severity(Severity::Low)
                .description("X-Content-Type-Options header is missing")
                .tags(&["headers", "security"])
                .matcher(Matcher::header_missing("X-Content-Type-Options"))
                .build(),

            Template::passive("missing-referrer-policy")
                .name("Missing Referrer-Policy")
                .severity(Severity::Low)
                .description("Referrer-Policy header is missing")
                .tags(&["headers", "security", "privacy"])
                .matcher(Matcher::header_missing("Referrer-Policy"))
                .build(),

            Template::passive("missing-permissions-policy")
                .name("Missing Permissions-Policy")
                .severity(Severity::Info)
                .description("Permissions-Policy header is missing")
                .tags(&["headers", "security"])
                .matcher(Matcher::header_missing("Permissions-Policy"))
                .build(),
        ]
    }

    pub fn information_disclosure() -> Vec<Template> {
        vec![
            Template::passive("server-header-disclosure")
                .name("Server Header Information Disclosure")
                .severity(Severity::Info)
                .description("Server header reveals version information")
                .tags(&["headers", "disclosure"])
                .matcher(Matcher::header_regex("Server", r"(?i)(apache|nginx|iis|tomcat|jetty)/[\d.]+"))
                .build(),

            Template::passive("x-powered-by-disclosure")
                .name("X-Powered-By Header Disclosure")
                .severity(Severity::Info)
                .description("X-Powered-By header reveals technology stack")
                .tags(&["headers", "disclosure"])
                .matcher(Matcher::header_exists("X-Powered-By"))
                .build(),

            Template::passive("x-aspnet-version-disclosure")
                .name("ASP.NET Version Disclosure")
                .severity(Severity::Info)
                .description("X-AspNet-Version header reveals ASP.NET version")
                .tags(&["headers", "disclosure", "aspnet"])
                .matcher(Matcher::header_exists("X-AspNet-Version"))
                .build(),

            Template::passive("php-version-disclosure")
                .name("PHP Version Disclosure")
                .severity(Severity::Low)
                .description("X-Powered-By header reveals PHP version")
                .tags(&["headers", "disclosure", "php"])
                .matcher(Matcher::header_regex("X-Powered-By", r"(?i)php/[\d.]+"))
                .build(),

            Template::passive("stack-trace-disclosure")
                .name("Stack Trace Disclosure")
                .severity(Severity::Medium)
                .description("Application stack trace exposed in response")
                .tags(&["disclosure", "error"])
                .matcher(Matcher::body_regex(r"(?i)(stack\s*trace|at\s+[\w.$]+\([\w.$]+\.java:\d+\)|Traceback \(most recent call last\))"))
                .cwe(209)
                .build(),

            Template::passive("sql-error-disclosure")
                .name("SQL Error Message Disclosure")
                .severity(Severity::Medium)
                .description("SQL error message exposed in response")
                .tags(&["disclosure", "error", "sql"])
                .matcher(Matcher::body_regex(r"(?i)(SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|ORA-\d{5}|Microsoft.*ODBC.*SQL Server|SQLITE_ERROR)"))
                .cwe(209)
                .build(),

            Template::passive("private-ip-disclosure")
                .name("Private IP Address Disclosure")
                .severity(Severity::Low)
                .description("Private IP address (RFC1918) disclosed in response")
                .tags(&["disclosure", "network"])
                // Proper octet validation: 0-255 = (25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)
                .matcher(Matcher::body_regex(r"\b(10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"))
                .build(),

            Template::passive("email-disclosure")
                .name("Email Address Disclosure")
                .severity(Severity::Info)
                .description("Email addresses found in response")
                .tags(&["disclosure", "pii"])
                .matcher(Matcher::body_regex(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"))
                .build(),

            Template::passive("credit-card-disclosure")
                .name("Potential Credit Card Number")
                .severity(Severity::High)
                .description("Potential credit card number found in response")
                .tags(&["disclosure", "pii", "payment"])
                .matcher(Matcher::body_regex(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"))
                .cwe(359)
                .build(),

            Template::passive("ssn-disclosure")
                .name("Potential SSN Disclosure")
                .severity(Severity::High)
                .description("Potential Social Security Number found in response")
                .tags(&["disclosure", "pii"])
                .matcher(Matcher::body_regex(r"\b\d{3}-\d{2}-\d{4}\b"))
                .cwe(359)
                .build(),

            Template::passive("aws-key-disclosure")
                .name("AWS Access Key Disclosure")
                .severity(Severity::Critical)
                .description("AWS access key found in response")
                .tags(&["disclosure", "secrets", "aws"])
                .matcher(Matcher::body_regex(r"(?i)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"))
                .cwe(798)
                .build(),

            Template::passive("generic-api-key")
                .name("Potential API Key Disclosure")
                .severity(Severity::Medium)
                .description("Potential API key or secret found in response")
                .tags(&["disclosure", "secrets"])
                .matcher(Matcher::body_regex(r#"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)['":\s]*[=:]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?"#))
                .cwe(798)
                .build(),
        ]
    }

    pub fn misconfigurations() -> Vec<Template> {
        vec![
            Template::passive("insecure-cookie-no-httponly")
                .name("Cookie Without HttpOnly Flag")
                .severity(Severity::Low)
                .description("Cookie set without HttpOnly flag")
                .tags(&["cookies", "security"])
                // Use compound matcher: Set-Cookie exists AND doesn't contain HttpOnly
                .matcher(Matcher::and(vec![
                    Matcher::header_exists("Set-Cookie"),
                    Matcher::header_not_contains("Set-Cookie", "httponly"),
                ]))
                .cwe(1004)
                .build(),

            Template::passive("insecure-cookie-no-secure")
                .name("Cookie Without Secure Flag")
                .severity(Severity::Medium)
                .description("Cookie set without Secure flag on HTTPS")
                .tags(&["cookies", "security"])
                .matcher(Matcher::and(vec![
                    Matcher::header_exists("Set-Cookie"),
                    Matcher::header_not_contains("Set-Cookie", "secure"),
                ]))
                .cwe(614)
                .build(),

            Template::passive("insecure-cookie-no-samesite")
                .name("Cookie Without SameSite Attribute")
                .severity(Severity::Low)
                .description("Cookie set without SameSite attribute")
                .tags(&["cookies", "security", "csrf"])
                .matcher(Matcher::and(vec![
                    Matcher::header_exists("Set-Cookie"),
                    Matcher::header_not_contains("Set-Cookie", "samesite"),
                ]))
                .build(),

            Template::passive("cors-wildcard")
                .name("CORS Wildcard Origin")
                .severity(Severity::Medium)
                .description("Access-Control-Allow-Origin set to wildcard")
                .tags(&["cors", "security"])
                .matcher(Matcher::header_value("Access-Control-Allow-Origin", "*"))
                .cwe(942)
                .build(),

            Template::passive("cors-null-origin")
                .name("CORS Null Origin Allowed")
                .severity(Severity::Medium)
                .description("Access-Control-Allow-Origin allows null origin")
                .tags(&["cors", "security"])
                .matcher(Matcher::header_value("Access-Control-Allow-Origin", "null"))
                .cwe(942)
                .build(),

            Template::passive("directory-listing")
                .name("Directory Listing Enabled")
                .severity(Severity::Low)
                .description("Directory listing is enabled")
                .tags(&["misconfiguration"])
                .matcher(Matcher::body_words(&["Index of /", "Parent Directory", "[To Parent Directory]"]))
                .cwe(548)
                .build(),

            Template::passive("application-error-500")
                .name("Application Error (500)")
                .severity(Severity::Info)
                .description("Server returned internal error")
                .tags(&["error"])
                .matcher(Matcher::status(500))
                .build(),

            Template::passive("debug-mode-enabled")
                .name("Debug Mode Enabled")
                .severity(Severity::Medium)
                .description("Application running in debug mode")
                .tags(&["misconfiguration", "debug"])
                .matcher(Matcher::body_words(&["DEBUG = True", "DJANGO_DEBUG", "APP_DEBUG", "debug mode is enabled"]))
                .cwe(489)
                .build(),
        ]
    }

    pub fn vulnerabilities() -> Vec<Template> {
        vec![
            Template::passive("mixed-content")
                .name("Mixed Content")
                .severity(Severity::Medium)
                .description("HTTPS page loads HTTP resources")
                .tags(&["ssl", "security"])
                .matcher(Matcher::body_regex(r#"(src|href|action)=["']http://[^"']*["']"#))
                .cwe(311)
                .build(),

            Template::passive("session-id-in-url")
                .name("Session ID in URL")
                .severity(Severity::Medium)
                .description("Session identifier exposed in URL")
                .tags(&["session", "security"])
                .matcher(Matcher::body_regex(r"(?i)(jsessionid|phpsessid|aspsessionid|sid|session_id)=[a-zA-Z0-9]+"))
                .cwe(598)
                .build(),

            Template::passive("open-redirect-param")
                .name("Potential Open Redirect")
                .severity(Severity::Low)
                .description("Potential open redirect via URL parameter")
                .tags(&["redirect", "security"])
                .matcher(Matcher::body_regex(r"(?i)(redirect|return|next|url|goto|target|dest|destination|rurl|return_url)=https?://"))
                .cwe(601)
                .build(),

            Template::passive("hash-disclosure")
                .name("Password Hash Disclosure")
                .severity(Severity::High)
                .description("Potential password hash found in response")
                .tags(&["disclosure", "passwords"])
                .matcher(Matcher::body_regex(r"\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}|\$6\$[./A-Za-z0-9]{8,}\$[./A-Za-z0-9]{86}|[a-f0-9]{32}:[a-f0-9]{32}"))
                .cwe(916)
                .build(),

            Template::passive("jwt-in-response")
                .name("JWT Token in Response")
                .severity(Severity::Info)
                .description("JWT token found in response body")
                .tags(&["jwt", "auth"])
                .matcher(Matcher::body_regex(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"))
                .build(),

            Template::passive("insecure-form-action")
                .name("Insecure Form Action")
                .severity(Severity::Medium)
                .description("Form submits to HTTP endpoint")
                .tags(&["forms", "security"])
                .matcher(Matcher::body_regex(r#"<form[^>]*action=["']http://[^"']*["']"#))
                .cwe(319)
                .build(),

            Template::passive("missing-csrf-token")
                .name("Form Missing CSRF Token")
                .severity(Severity::Medium)
                .description("POST form without apparent CSRF token")
                .tags(&["csrf", "security"])
                .matcher(Matcher::and(vec![
                    Matcher::body_regex(r#"<form[^>]*method=["']?post["']?[^>]*>"#),
                    Matcher::body_not_contains(&["csrf", "_token", "authenticity_token", "__RequestVerificationToken"]),
                ]))
                .cwe(352)
                .build(),
        ]
    }

    /// Active vulnerability detection templates (from YAML)
    pub fn active_templates() -> Vec<Template> {
        let mut templates = Vec::new();

        // Embed YAML templates at compile time
        const SQLI_TEMPLATE: &str = include_str!("active/sqli-error-based.yaml");
        const SQLI_BLIND_TEMPLATE: &str = include_str!("active/sqli-blind.yaml");
        const XSS_TEMPLATE: &str = include_str!("active/xss-reflected.yaml");
        const CMDI_TEMPLATE: &str = include_str!("active/command-injection.yaml");
        const LFI_TEMPLATE: &str = include_str!("active/path-traversal.yaml");
        const SSRF_TEMPLATE: &str = include_str!("active/ssrf.yaml");
        const XXE_TEMPLATE: &str = include_str!("active/xxe.yaml");
        const SMUGGLING_TEMPLATE: &str = include_str!("active/request-smuggling.yaml");
        const SSTI_TEMPLATE: &str = include_str!("active/ssti.yaml");
        const LDAP_TEMPLATE: &str = include_str!("active/ldap-injection.yaml");
        const CRLF_TEMPLATE: &str = include_str!("active/crlf-injection.yaml");
        const REDIRECT_TEMPLATE: &str = include_str!("active/open-redirect.yaml");
        const HOST_HEADER_TEMPLATE: &str = include_str!("active/host-header-injection.yaml");
        const DESER_TEMPLATE: &str = include_str!("active/deserialization.yaml");
        const BLIND_OOB_TEMPLATE: &str = include_str!("active/blind-oob.yaml");

        let yaml_sources = [
            ("sqli-error-based", SQLI_TEMPLATE),
            ("sqli-blind", SQLI_BLIND_TEMPLATE),
            ("xss-reflected", XSS_TEMPLATE),
            ("command-injection", CMDI_TEMPLATE),
            ("path-traversal", LFI_TEMPLATE),
            ("ssrf", SSRF_TEMPLATE),
            ("xxe", XXE_TEMPLATE),
            ("request-smuggling", SMUGGLING_TEMPLATE),
            ("ssti", SSTI_TEMPLATE),
            ("ldap-injection", LDAP_TEMPLATE),
            ("crlf-injection", CRLF_TEMPLATE),
            ("open-redirect", REDIRECT_TEMPLATE),
            ("host-header-injection", HOST_HEADER_TEMPLATE),
            ("deserialization", DESER_TEMPLATE),
            ("blind-oob", BLIND_OOB_TEMPLATE),
        ];

        for (name, yaml) in yaml_sources {
            // Handle multi-document YAML (separated by ---)
            for doc in yaml.split("\n---\n") {
                let doc = doc.trim();
                if doc.is_empty() || doc == "---" {
                    continue;
                }
                match Template::from_yaml(doc) {
                    Ok(template) => templates.push(template),
                    Err(e) => tracing::warn!("Failed to parse bundled template {}: {}", name, e),
                }
            }
        }

        templates
    }
}
