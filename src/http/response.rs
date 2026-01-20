//! HTTP response types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// HTTP status code
    pub status: u16,

    /// Status text (e.g., "OK", "Not Found")
    pub status_text: String,

    /// Response headers
    pub headers: HashMap<String, String>,

    /// Response body
    pub body: Vec<u8>,

    /// Response time in milliseconds
    pub duration_ms: u64,

    /// Size of the response body in bytes
    pub size: usize,

    /// HTTP version
    pub http_version: String,

    /// Remote address
    pub remote_addr: Option<String>,

    /// TLS certificate info
    pub tls_info: Option<TlsInfo>,

    /// Timing information
    pub timing: Option<ResponseTiming>,

    /// Cookies set by the response
    pub cookies: Vec<Cookie>,
}

/// TLS certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Certificate subject
    pub subject: String,

    /// Certificate issuer
    pub issuer: String,

    /// Valid from
    pub valid_from: String,

    /// Valid until
    pub valid_until: String,

    /// TLS version
    pub version: String,

    /// Cipher suite
    pub cipher: String,
}

/// Detailed timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTiming {
    /// DNS lookup time in ms
    pub dns_ms: u64,

    /// TCP connection time in ms
    pub connect_ms: u64,

    /// TLS handshake time in ms
    pub tls_ms: Option<u64>,

    /// Time to first byte in ms
    pub ttfb_ms: u64,

    /// Transfer time in ms
    pub transfer_ms: u64,

    /// Total time in ms
    pub total_ms: u64,
}

/// Cookie from response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name
    pub name: String,

    /// Cookie value
    pub value: String,

    /// Domain
    pub domain: Option<String>,

    /// Path
    pub path: Option<String>,

    /// Expiration
    pub expires: Option<String>,

    /// Max age in seconds
    pub max_age: Option<i64>,

    /// Secure flag
    pub secure: bool,

    /// HttpOnly flag
    pub http_only: bool,

    /// SameSite attribute
    pub same_site: Option<String>,
}

impl Response {
    /// Check if response is successful (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if response is redirect (3xx)
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Check if response is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    /// Check if response is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status)
    }

    /// Get body as string
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Parse body as JSON
    pub fn json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Get content type header
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(|s| s.as_str())
    }

    /// Check if content is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("json"))
            .unwrap_or(false)
    }

    /// Check if content is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("html"))
            .unwrap_or(false)
    }

    /// Check if content is XML
    pub fn is_xml(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("xml"))
            .unwrap_or(false)
    }

    /// Get a specific header (case-insensitive)
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: 0,
            status_text: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            duration_ms: 0,
            size: 0,
            http_version: "HTTP/1.1".to_string(),
            remote_addr: None,
            tls_info: None,
            timing: None,
            cookies: Vec::new(),
        }
    }
}
