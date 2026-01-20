//! Content-Type header analysis

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use crate::scanner::passive::PassiveRule;

/// Safely truncate a string at a character boundary
fn safe_truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Rule for checking content type issues
pub struct ContentTypeRule {
    enabled: bool,
}

impl ContentTypeRule {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl PassiveRule for ContentTypeRule {
    fn name(&self) -> &str {
        "Content-Type Analysis"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for missing Content-Type
        if response.header("content-type").is_none() {
            findings.push(
                Finding::new("Missing Content-Type Header", Severity::Low, &request.url)
                    .with_description(
                        "The response does not include a Content-Type header, which could lead to MIME sniffing attacks.",
                    )
                    .with_scanner("passive/content-type")
                    .with_cwe(16)
                    .with_remediation("Add a Content-Type header to all responses."),
            );
            return findings;
        }

        let content_type = response.header("content-type").unwrap();

        // Check for charset in text content types
        if content_type.starts_with("text/") && !content_type.contains("charset") {
            findings.push(
                Finding::new("Content-Type Without Charset", Severity::Low, &request.url)
                    .with_description(
                        "The Content-Type header does not specify a charset, which could lead to encoding issues.",
                    )
                    .with_evidence(content_type)
                    .with_scanner("passive/content-type")
                    .with_cwe(16)
                    .with_remediation("Specify charset in Content-Type header (e.g., text/html; charset=utf-8)."),
            );
        }

        // Check for content type mismatch with body
        if content_type.contains("json") {
            let body = response.body_text();
            let trimmed = body.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with('{')
                && !trimmed.starts_with('[')
            {
                findings.push(
                    Finding::new("Content-Type Mismatch", Severity::Low, &request.url)
                        .with_description(
                            "The Content-Type indicates JSON but the body does not appear to be valid JSON.",
                        )
                        .with_evidence(&format!("Content-Type: {}, Body starts with: {}",
                            content_type,
                            safe_truncate(trimmed, 50)
                        ))
                        .with_scanner("passive/content-type")
                        .with_cwe(16),
                );
            }
        }

        // Check for HTML content served as text/plain
        if content_type.contains("text/plain") {
            let body = response.body_text();
            if body.contains("<html") || body.contains("<script") || body.contains("<!DOCTYPE") {
                findings.push(
                    Finding::new("HTML Content Served as text/plain", Severity::Low, &request.url)
                        .with_description(
                            "HTML content is being served with text/plain Content-Type, which could indicate a misconfiguration.",
                        )
                        .with_evidence(content_type)
                        .with_scanner("passive/content-type")
                        .with_cwe(16)
                        .with_remediation("Use appropriate Content-Type for HTML content (text/html)."),
                );
            }
        }

        // Check for XML content type issues
        if content_type.contains("xml") {
            let body = response.body_text();

            // Check for external entity processing
            if body.contains("<!ENTITY") || body.contains("<!DOCTYPE") {
                findings.push(
                    Finding::new("XML with Entity Declarations", Severity::Medium, &request.url)
                        .with_description(
                            "XML response contains entity declarations which could indicate XXE vulnerability potential.",
                        )
                        .with_scanner("passive/content-type")
                        .with_cwe(611)
                        .with_remediation("Disable external entity processing in XML parsers."),
                );
            }
        }

        findings
    }
}

impl Default for ContentTypeRule {
    fn default() -> Self {
        Self::new()
    }
}
