//! HTTP Request Smuggling Detection
//!
//! Implements detection for HTTP request smuggling vulnerabilities:
//! - CL.TE (Content-Length preferred by front-end, Transfer-Encoding by back-end)
//! - TE.CL (Transfer-Encoding preferred by front-end, Content-Length by back-end)
//! - TE.TE (Transfer-Encoding obfuscation)
//!
//! Based on techniques from PortSwigger research and HTTP Request Smuggler extension.

use anyhow::Result;
use std::time::Duration;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// Request smuggling detection techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmugglingTechnique {
    /// Content-Length takes precedence (front-end), Transfer-Encoding (back-end)
    ClTe,
    /// Transfer-Encoding takes precedence (front-end), Content-Length (back-end)
    TeCl,
    /// Transfer-Encoding header obfuscation
    TeTe,
}

impl SmugglingTechnique {
    pub fn name(&self) -> &'static str {
        match self {
            SmugglingTechnique::ClTe => "CL.TE",
            SmugglingTechnique::TeCl => "TE.CL",
            SmugglingTechnique::TeTe => "TE.TE",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SmugglingTechnique::ClTe => {
                "Front-end uses Content-Length, back-end uses Transfer-Encoding"
            }
            SmugglingTechnique::TeCl => {
                "Front-end uses Transfer-Encoding, back-end uses Content-Length"
            }
            SmugglingTechnique::TeTe => "Transfer-Encoding header obfuscation bypass",
        }
    }
}

/// Smuggling detection result
#[derive(Debug, Clone)]
pub struct SmugglingResult {
    /// Technique that was detected
    pub technique: SmugglingTechnique,
    /// Whether vulnerability was confirmed
    pub confirmed: bool,
    /// Detection method used
    pub detection_method: String,
    /// Response time difference (if time-based)
    pub time_difference_ms: Option<i64>,
    /// Additional evidence
    pub evidence: String,
}

/// Transfer-Encoding obfuscation techniques
const TE_OBFUSCATIONS: &[&str] = &[
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
    "Transfer-encoding: chunked",
    "Transfer-Encoding:\tchunked",
    "Transfer-Encoding:\nchunked",
    "Transfer-Encoding: \tchunked",
    " Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked ",
    "X: X\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding: cow",
    "Transfer-Encoding:\r\n chunked",
];

/// Scan for HTTP Request Smuggling vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Test CL.TE smuggling
    if let Some(result) = test_cl_te(client, target_url).await? {
        findings.push(create_finding(target_url, result));
    }

    // Test TE.CL smuggling
    if let Some(result) = test_te_cl(client, target_url).await? {
        findings.push(create_finding(target_url, result));
    }

    // Test TE.TE smuggling with obfuscation
    if let Some(result) = test_te_te(client, target_url).await? {
        findings.push(create_finding(target_url, result));
    }

    Ok(findings)
}

/// Test for CL.TE smuggling
/// Front-end uses Content-Length, back-end uses Transfer-Encoding
async fn test_cl_te(client: &HttpClient, url: &str) -> Result<Option<SmugglingResult>> {
    // Time-based detection: send a request that will cause the back-end to wait
    // if it processes Transfer-Encoding

    // Normal request (baseline)
    let baseline_time = {
        let request = Request::new("POST", url);
        let start = std::time::Instant::now();
        let _ = client.execute(&request).await;
        start.elapsed()
    };

    // CL.TE probe: Content-Length indicates body ends, but Transfer-Encoding chunk is incomplete
    // This causes the back-end (using TE) to wait for the end of the chunk
    let probe_body = "0\r\n\r\nG";
    let mut probe_request = Request::new("POST", url);
    probe_request.headers.insert("Content-Length".to_string(), probe_body.len().to_string());
    probe_request.headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    probe_request.body = Some(probe_body.to_string());

    let probe_time = {
        let start = std::time::Instant::now();
        // Use a longer timeout for this test
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            client.execute(&probe_request),
        ).await;
        start.elapsed()
    };

    // If probe takes significantly longer, might indicate CL.TE
    let time_diff = probe_time.as_millis() as i64 - baseline_time.as_millis() as i64;

    if time_diff > 5000 {
        return Ok(Some(SmugglingResult {
            technique: SmugglingTechnique::ClTe,
            confirmed: false, // Time-based is indicative but not confirmed
            detection_method: "Time-based delay detection".to_string(),
            time_difference_ms: Some(time_diff),
            evidence: format!(
                "Response delayed by {}ms. Front-end used Content-Length ({} bytes), back-end may be waiting for chunked data.",
                time_diff, probe_body.len()
            ),
        }));
    }

    Ok(None)
}

/// Test for TE.CL smuggling
/// Front-end uses Transfer-Encoding, back-end uses Content-Length
async fn test_te_cl(client: &HttpClient, url: &str) -> Result<Option<SmugglingResult>> {
    // TE.CL probe: Transfer-Encoding chunk is complete, but Content-Length indicates more data
    // This causes the back-end (using CL) to wait for more data

    // Normal request (baseline)
    let baseline_time = {
        let request = Request::new("POST", url);
        let start = std::time::Instant::now();
        let _ = client.execute(&request).await;
        start.elapsed()
    };

    // Chunked body that's complete
    let chunk_data = "1\r\nX\r\n0\r\n\r\n";
    // But Content-Length says there's more
    let fake_length = chunk_data.len() + 100;

    let mut probe_request = Request::new("POST", url);
    probe_request.headers.insert("Content-Length".to_string(), fake_length.to_string());
    probe_request.headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    probe_request.body = Some(chunk_data.to_string());

    let probe_time = {
        let start = std::time::Instant::now();
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            client.execute(&probe_request),
        ).await;
        start.elapsed()
    };

    let time_diff = probe_time.as_millis() as i64 - baseline_time.as_millis() as i64;

    if time_diff > 5000 {
        return Ok(Some(SmugglingResult {
            technique: SmugglingTechnique::TeCl,
            confirmed: false,
            detection_method: "Time-based delay detection".to_string(),
            time_difference_ms: Some(time_diff),
            evidence: format!(
                "Response delayed by {}ms. Front-end processed chunked encoding, back-end may be waiting for {} bytes.",
                time_diff, fake_length
            ),
        }));
    }

    Ok(None)
}

/// Test for TE.TE smuggling with obfuscation
async fn test_te_te(client: &HttpClient, url: &str) -> Result<Option<SmugglingResult>> {
    // Test various TE obfuscation techniques
    // One server might process the obfuscated header while another ignores it

    for obfuscation in TE_OBFUSCATIONS {
        // Skip standard chunked for this test
        if *obfuscation == "Transfer-Encoding: chunked" {
            continue;
        }

        // Normal baseline
        let baseline_time = {
            let request = Request::new("POST", url);
            let start = std::time::Instant::now();
            let _ = client.execute(&request).await;
            start.elapsed()
        };

        // Probe with obfuscated TE
        let probe_body = "0\r\n\r\n";
        let mut probe_request = Request::new("POST", url);

        // Parse the obfuscation to set headers
        if obfuscation.contains("\r\n") {
            // Multiple headers - set them individually
            for line in obfuscation.split("\r\n") {
                if let Some(idx) = line.find(':') {
                    let name = line[..idx].trim();
                    let value = line[idx + 1..].trim();
                    probe_request.headers.insert(name.to_string(), value.to_string());
                }
            }
        } else if let Some(idx) = obfuscation.find(':') {
            let name = obfuscation[..idx].to_string();
            let value = obfuscation[idx + 1..].trim().to_string();
            probe_request.headers.insert(name, value);
        }

        probe_request.headers.insert("Content-Length".to_string(), "0".to_string());
        probe_request.body = Some(probe_body.to_string());

        let probe_time = {
            let start = std::time::Instant::now();
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                client.execute(&probe_request),
            ).await;
            start.elapsed()
        };

        let time_diff = probe_time.as_millis() as i64 - baseline_time.as_millis() as i64;

        if time_diff > 5000 {
            return Ok(Some(SmugglingResult {
                technique: SmugglingTechnique::TeTe,
                confirmed: false,
                detection_method: "TE obfuscation with time-based detection".to_string(),
                time_difference_ms: Some(time_diff),
                evidence: format!(
                    "Response delayed by {}ms with TE obfuscation: {}",
                    time_diff, obfuscation
                ),
            }));
        }
    }

    Ok(None)
}

/// Create a finding from a smuggling result
fn create_finding(url: &str, result: SmugglingResult) -> Finding {
    Finding::new(
        &format!("HTTP Request Smuggling ({})", result.technique.name()),
        Severity::Critical,
        url,
    )
    .with_description(&format!(
        "{}\n\nDetection: {}\n\n{}",
        result.technique.description(),
        result.detection_method,
        if result.confirmed { "CONFIRMED" } else { "Possible vulnerability (requires verification)" }
    ))
    .with_evidence(&result.evidence)
    .with_scanner("active/request-smuggling")
    .with_cwe(444)
    .with_owasp("A04:2021 – Insecure Design")
    .with_remediation(
        "1. Configure front-end server to normalize ambiguous requests\n\
         2. Use HTTP/2 end-to-end (not downgraded to HTTP/1)\n\
         3. Configure back-end to reject ambiguous requests\n\
         4. Ensure both servers use the same method to determine request boundaries"
    )
}

/// Generate differential smuggling probe for manual testing
pub fn generate_differential_probe(technique: SmugglingTechnique, method: &str, path: &str) -> String {
    match technique {
        SmugglingTechnique::ClTe => {
            // CL.TE: Front uses CL, Back uses TE
            // The "G" at the end becomes the start of the next request for the back-end
            format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 6\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 0\r\n\
                 \r\n\
                 G"
            )
        }
        SmugglingTechnique::TeCl => {
            // TE.CL: Front uses TE, Back uses CL
            // The back-end sees everything after the first chunk as the next request
            format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 5c\r\n\
                 GPOST / HTTP/1.1\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 15\r\n\
                 \r\n\
                 x=1\r\n\
                 0\r\n\
                 \r\n"
            )
        }
        SmugglingTechnique::TeTe => {
            // TE.TE with obfuscation - front sees obfuscated, back sees standard
            format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 4\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Transfer-encoding: cow\r\n\
                 \r\n\
                 5c\r\n\
                 GPOST / HTTP/1.1\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 15\r\n\
                 \r\n\
                 x=1\r\n\
                 0\r\n\
                 \r\n"
            )
        }
    }
}

/// Check if HTTP/2 is being downgraded (potential smuggling vector)
pub async fn check_h2_downgrade(client: &HttpClient, url: &str) -> Result<bool> {
    // If we can detect that HTTP/2 is being downgraded to HTTP/1.1 to a backend,
    // this is a potential smuggling vector

    // This is a simplified check - in reality, you'd need to analyze the connection
    // and see if ALPN negotiated h2 but responses show HTTP/1.1 behavior

    let request = Request::new("GET", url);
    if let Ok(response) = client.execute(&request).await {
        // Check for H2 to H1 conversion indicators
        let headers_text = format!("{:?}", response.headers);
        if headers_text.contains("via:") || headers_text.contains("Via:") {
            // "Via" header often indicates proxy involvement
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smuggling_technique_names() {
        assert_eq!(SmugglingTechnique::ClTe.name(), "CL.TE");
        assert_eq!(SmugglingTechnique::TeCl.name(), "TE.CL");
        assert_eq!(SmugglingTechnique::TeTe.name(), "TE.TE");
    }

    #[test]
    fn test_te_obfuscations_not_empty() {
        assert!(!TE_OBFUSCATIONS.is_empty());
        assert!(TE_OBFUSCATIONS.len() > 10); // We have many obfuscation techniques
    }

    #[test]
    fn test_generate_cl_te_probe() {
        let probe = generate_differential_probe(SmugglingTechnique::ClTe, "POST", "/");
        assert!(probe.contains("Content-Length: 6"));
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.ends_with("G"));
    }

    #[test]
    fn test_generate_te_cl_probe() {
        let probe = generate_differential_probe(SmugglingTechnique::TeCl, "POST", "/");
        assert!(probe.contains("Content-Length: 4"));
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.contains("GPOST"));
    }

    #[test]
    fn test_generate_te_te_probe() {
        let probe = generate_differential_probe(SmugglingTechnique::TeTe, "POST", "/");
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.contains("Transfer-encoding: cow")); // Obfuscated
    }

    #[test]
    fn test_smuggling_result() {
        let result = SmugglingResult {
            technique: SmugglingTechnique::ClTe,
            confirmed: false,
            detection_method: "Time-based".to_string(),
            time_difference_ms: Some(6000),
            evidence: "Test evidence".to_string(),
        };

        assert!(!result.confirmed);
        assert_eq!(result.time_difference_ms, Some(6000));
    }
}
