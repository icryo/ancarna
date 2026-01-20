//! Information disclosure detection

use regex::Regex;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Rule for detecting information disclosure
pub struct InformationDisclosureRule {
    enabled: bool,
    patterns: Vec<DisclosurePattern>,
}

struct DisclosurePattern {
    name: &'static str,
    pattern: Regex,
    severity: Severity,
    description: &'static str,
    cwe: u32,
}

impl InformationDisclosureRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            patterns: Self::default_patterns(),
        }
    }

    fn default_patterns() -> Vec<DisclosurePattern> {
        vec![
            DisclosurePattern {
                name: "Private IP Address Disclosure",
                pattern: Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b").unwrap(),
                severity: Severity::Low,
                description: "A private IP address was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "Email Address Disclosure",
                pattern: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
                severity: Severity::Informational,
                description: "An email address was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "AWS Access Key Disclosure",
                pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                severity: Severity::Critical,
                description: "An AWS access key was found in the response.",
                cwe: 798,
            },
            DisclosurePattern {
                name: "AWS Secret Key Disclosure",
                pattern: Regex::new(r"[A-Za-z0-9/+=]{40}").unwrap(),
                severity: Severity::Critical,
                description: "A potential AWS secret key was found in the response.",
                cwe: 798,
            },
            DisclosurePattern {
                name: "Generic API Key Pattern",
                pattern: Regex::new(r#"['"](api[_-]?key|apikey|api[_-]?secret)['"]\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#).unwrap(),
                severity: Severity::High,
                description: "A potential API key was found in the response.",
                cwe: 798,
            },
            DisclosurePattern {
                name: "Private Key Disclosure",
                pattern: Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
                description: "A private key was found in the response.",
                cwe: 321,
            },
            DisclosurePattern {
                name: "Database Connection String",
                pattern: Regex::new(r#"(mongodb|mysql|postgres|postgresql|mssql|redis)://[^\s'"]+"#).unwrap(),
                severity: Severity::High,
                description: "A database connection string was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "JWT Token",
                pattern: Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
                severity: Severity::Medium,
                description: "A JWT token was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "Stack Trace Disclosure",
                pattern: Regex::new(r"(at\s+[\w.$]+\([^)]+\)\s*\n?)+").unwrap(),
                severity: Severity::Medium,
                description: "A stack trace was found in the response, revealing internal code structure.",
                cwe: 209,
            },
            DisclosurePattern {
                name: "SQL Error Message",
                pattern: Regex::new(r"(mysql_fetch|ORA-[0-9]+|pg_query|SQL syntax|SQLite|microsoft sql|ODBC Driver)").unwrap(),
                severity: Severity::Medium,
                description: "A SQL error message was found in the response.",
                cwe: 209,
            },
            DisclosurePattern {
                name: "PHP Error Disclosure",
                pattern: Regex::new(r"(Fatal error|Parse error|Warning):\s+.*\s+in\s+.*\s+on line\s+\d+").unwrap(),
                severity: Severity::Medium,
                description: "A PHP error message was found in the response.",
                cwe: 209,
            },
            DisclosurePattern {
                name: "File Path Disclosure",
                pattern: Regex::new(r#"([A-Za-z]:\\[^\s:*?"<>|]+|/(?:home|var|usr|etc|opt)/[^\s:*?"<>|]+)"#).unwrap(),
                severity: Severity::Low,
                description: "A file system path was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "Credit Card Number",
                pattern: Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap(),
                severity: Severity::Critical,
                description: "A potential credit card number was found in the response.",
                cwe: 200,
            },
            DisclosurePattern {
                name: "Social Security Number",
                pattern: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                severity: Severity::Critical,
                description: "A potential Social Security Number was found in the response.",
                cwe: 200,
            },
        ]
    }
}

impl PassiveRule for InformationDisclosureRule {
    fn name(&self) -> &str {
        "Information Disclosure"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();
        let body_text = response.body_text();

        for pattern in &self.patterns {
            if let Some(mat) = pattern.pattern.find(&body_text) {
                let matched_text = mat.as_str();

                // Truncate long matches safely
                let evidence = if matched_text.len() > 100 {
                    let mut end = 100;
                    while end > 0 && !matched_text.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{}...", &matched_text[..end])
                } else {
                    matched_text.to_string()
                };

                findings.push(
                    Finding::new(pattern.name, pattern.severity, &request.url)
                        .with_description(pattern.description)
                        .with_evidence(&evidence)
                        .with_scanner("passive/information-disclosure")
                        .with_cwe(pattern.cwe),
                );
            }
        }

        findings
    }
}

impl Default for InformationDisclosureRule {
    fn default() -> Self {
        Self::new()
    }
}
