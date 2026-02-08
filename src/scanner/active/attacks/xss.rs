//! Cross-Site Scripting (XSS) testing

#![allow(dead_code)]

use anyhow::Result;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// XSS test payloads with unique identifiers
const XSS_PAYLOADS: &[(&str, &str)] = &[
    ("<script>alert('XSS')</script>", "script-tag"),
    ("<img src=x onerror=alert('XSS')>", "img-onerror"),
    ("<svg onload=alert('XSS')>", "svg-onload"),
    ("javascript:alert('XSS')", "javascript-uri"),
    ("'\"><script>alert('XSS')</script>", "breakout-script"),
    ("</title><script>alert('XSS')</script>", "title-breakout"),
    ("</textarea><script>alert('XSS')</script>", "textarea-breakout"),
    ("<body onload=alert('XSS')>", "body-onload"),
    ("<input onfocus=alert('XSS') autofocus>", "input-autofocus"),
    ("<marquee onstart=alert('XSS')>", "marquee-onstart"),
    ("<details open ontoggle=alert('XSS')>", "details-ontoggle"),
    ("<iframe src=\"javascript:alert('XSS')\">", "iframe-javascript"),
    ("<math><mtext></mtext></math><script>alert('XSS')</script>", "math-breakout"),
    ("'-alert('XSS')-'", "js-context-break"),
    ("\";alert('XSS');//", "js-string-break"),
];

/// Reflected XSS indicators - simplified payload patterns for detection
const REFLECTED_INDICATORS: &[&str] = &[
    "<script>",
    "onerror=",
    "onload=",
    "onfocus=",
    "onmouseover=",
    "javascript:",
    "alert(",
];

/// Scan for XSS vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if params.is_empty() {
        return Ok(findings);
    }

    for (param_name, _) in &params {
        for (payload, payload_type) in XSS_PAYLOADS {
            // Build URL with payload
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

            // Check if payload is reflected in response
            if body.contains(payload) {
                // Payload is reflected exactly - likely vulnerable
                findings.push(
                    Finding::new("Reflected Cross-Site Scripting (XSS)", Severity::High, target_url)
                        .with_description(&format!(
                            "XSS vulnerability detected in parameter '{}'. The payload is reflected unencoded in the response.",
                            param_name
                        ))
                        .with_parameter(param_name)
                        .with_evidence(&format!("Payload type: {}, Payload: {}", payload_type, payload))
                        .with_scanner("active/xss")
                        .with_cwe(79)
                        .with_owasp("A03:2021 – Injection")
                        .with_remediation(
                            "Encode all user input before rendering in HTML. Use context-aware output encoding."
                        )
                        .with_request(&format!("GET {}", test_url)),
                );

                // Found vulnerability, move to next parameter
                break;
            }

            // Check for partial reflection (might still be exploitable)
            for indicator in REFLECTED_INDICATORS {
                if payload.contains(indicator) && body.to_lowercase().contains(&indicator.to_lowercase()) {
                    // Check if it's from our payload or existing in page
                    let original_request = Request::new("GET", target_url);
                    if let Ok(original_response) = client.execute(&original_request).await {
                        let original_body = original_response.body_text();
                        if !original_body.to_lowercase().contains(&indicator.to_lowercase()) {
                            // The indicator appeared after our payload - potential XSS
                            findings.push(
                                Finding::new(
                                    "Potential Reflected XSS",
                                    Severity::Medium,
                                    target_url,
                                )
                                .with_description(&format!(
                                    "Potential XSS in parameter '{}'. XSS indicator '{}' reflected in response.",
                                    param_name, indicator
                                ))
                                .with_parameter(param_name)
                                .with_evidence(&format!("Payload: {}, Indicator: {}", payload, indicator))
                                .with_scanner("active/xss")
                                .with_cwe(79)
                                .with_confidence(0.6)
                                .with_remediation(
                                    "Review the context where user input is reflected and apply appropriate encoding."
                                ),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

/// Check for DOM-based XSS indicators
pub fn check_dom_xss_sinks(html: &str) -> Vec<String> {
    let mut sinks = Vec::new();

    let dom_sinks = [
        "document.write",
        "document.writeln",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "Function(",
        "location.href",
        "location.assign",
        "location.replace",
        "$.html(",
        ".html(",
    ];

    for sink in dom_sinks {
        if html.contains(sink) {
            sinks.push(sink.to_string());
        }
    }

    sinks
}

/// Check for DOM-based XSS sources
pub fn check_dom_xss_sources(html: &str) -> Vec<String> {
    let mut sources = Vec::new();

    let dom_sources = [
        "location.search",
        "location.hash",
        "location.href",
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.name",
        "document.cookie",
    ];

    for source in dom_sources {
        if html.contains(source) {
            sources.push(source.to_string());
        }
    }

    sources
}
