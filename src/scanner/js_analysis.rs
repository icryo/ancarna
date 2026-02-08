//! JavaScript Analysis Module
//!
//! Implements functionality similar to:
//! - JS Link Finder (extract endpoints from JS)
//! - Retire.js (detect vulnerable JS libraries)
//! - SecretFinder (detect secrets/API keys in JS)

#![allow(dead_code)]

use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Extracted endpoint from JavaScript
#[derive(Debug, Clone)]
pub struct JsEndpoint {
    /// The extracted URL/path
    pub path: String,
    /// HTTP method (if detected)
    pub method: Option<String>,
    /// Source JS file
    pub source: String,
    /// Line number (if available)
    pub line: Option<usize>,
    /// Context around the finding
    pub context: String,
    /// Type of endpoint (API, relative path, full URL, etc.)
    pub endpoint_type: EndpointType,
}

/// Type of discovered endpoint
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointType {
    /// Full URL (http:// or https://)
    FullUrl,
    /// API endpoint (/api/v1/...)
    ApiEndpoint,
    /// Relative path
    RelativePath,
    /// WebSocket URL
    WebSocket,
    /// GraphQL endpoint
    GraphQL,
}

/// Detected secret or sensitive data
#[derive(Debug, Clone)]
pub struct JsSecret {
    /// Type of secret
    pub secret_type: SecretType,
    /// The secret value (partially masked)
    pub value: String,
    /// Full match context
    pub context: String,
    /// Source file
    pub source: String,
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GoogleApiKey,
    GoogleOAuth,
    GitHubToken,
    GitLabToken,
    SlackToken,
    SlackWebhook,
    StripeKey,
    TwilioKey,
    JwtSecret,
    PrivateKey,
    BasicAuthCredentials,
    GenericApiKey,
    GenericSecret,
    DatabaseUrl,
    S3Bucket,
}

impl SecretType {
    pub fn name(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::GoogleApiKey => "Google API Key",
            SecretType::GoogleOAuth => "Google OAuth Token",
            SecretType::GitHubToken => "GitHub Token",
            SecretType::GitLabToken => "GitLab Token",
            SecretType::SlackToken => "Slack Token",
            SecretType::SlackWebhook => "Slack Webhook",
            SecretType::StripeKey => "Stripe API Key",
            SecretType::TwilioKey => "Twilio API Key",
            SecretType::JwtSecret => "JWT Secret",
            SecretType::PrivateKey => "Private Key",
            SecretType::BasicAuthCredentials => "Basic Auth Credentials",
            SecretType::GenericApiKey => "Generic API Key",
            SecretType::GenericSecret => "Generic Secret",
            SecretType::DatabaseUrl => "Database Connection URL",
            SecretType::S3Bucket => "S3 Bucket URL",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey | SecretType::AwsSecretKey => "Critical",
            SecretType::PrivateKey => "Critical",
            SecretType::DatabaseUrl => "Critical",
            SecretType::GitHubToken | SecretType::GitLabToken => "High",
            SecretType::StripeKey | SecretType::TwilioKey => "High",
            SecretType::SlackToken | SecretType::SlackWebhook => "Medium",
            SecretType::GoogleApiKey | SecretType::GoogleOAuth => "Medium",
            SecretType::BasicAuthCredentials => "High",
            SecretType::JwtSecret => "High",
            SecretType::GenericApiKey | SecretType::GenericSecret => "Medium",
            SecretType::S3Bucket => "Low",
        }
    }
}

/// Vulnerable JavaScript library
#[derive(Debug, Clone)]
pub struct VulnerableLibrary {
    /// Library name
    pub name: String,
    /// Detected version
    pub version: String,
    /// Known vulnerabilities
    pub vulnerabilities: Vec<LibraryVulnerability>,
    /// Detection method
    pub detection_method: String,
}

/// Individual vulnerability in a library
#[derive(Debug, Clone)]
pub struct LibraryVulnerability {
    /// CVE ID (if available)
    pub cve: Option<String>,
    /// Severity (low, medium, high, critical)
    pub severity: String,
    /// Brief description
    pub description: String,
    /// Fixed in version
    pub fixed_in: Option<String>,
    /// Reference URL
    pub reference: Option<String>,
}

/// Known vulnerable library patterns (Retire.js style database subset)
const VULNERABLE_LIBRARIES: &[(&str, &str, &str, &str, &str)] = &[
    // (name, version_regex, severity, cve, description)
    ("jquery", r"([1-2]\.[0-9]+\.[0-9]+)", "medium", "CVE-2020-11022", "XSS vulnerability in jQuery < 3.5.0"),
    ("jquery", r"1\.[0-8]\.[0-9]+", "high", "CVE-2015-9251", "XSS vulnerability in jQuery < 1.9.0"),
    ("angular", r"1\.[0-5]\.[0-9]+", "high", "CVE-2019-10768", "Prototype pollution in AngularJS"),
    ("angular", r"1\.[0-9]+\.[0-9]+", "medium", "", "AngularJS 1.x is end-of-life"),
    ("bootstrap", r"[2-3]\.[0-9]+\.[0-9]+", "medium", "CVE-2019-8331", "XSS in Bootstrap < 4.3.1"),
    ("lodash", r"4\.[0-9]+\.[0-9]+", "high", "CVE-2019-10744", "Prototype pollution in lodash < 4.17.12"),
    ("lodash", r"[0-3]\.[0-9]+\.[0-9]+", "high", "CVE-2018-16487", "Prototype pollution in lodash < 4.17.5"),
    ("moment", r"[0-2]\.[0-9]+\.[0-9]+", "low", "", "moment.js is in maintenance mode"),
    ("handlebars", r"[0-3]\.[0-9]+\.[0-9]+", "critical", "CVE-2019-19919", "RCE in Handlebars < 4.3.0"),
    ("vue", r"2\.[0-5]\.[0-9]+", "medium", "CVE-2018-11235", "XSS in Vue.js < 2.5.17"),
    ("react", r"0\.[0-9]+\.[0-9]+", "medium", "", "React 0.x is outdated"),
    ("dompurify", r"[0-1]\.[0-9]+\.[0-9]+", "high", "CVE-2020-26870", "XSS bypass in DOMPurify < 2.0.17"),
    ("axios", r"0\.[0-9]+\.[0-9]+", "medium", "CVE-2020-28168", "SSRF in axios < 0.21.1"),
    ("serialize-javascript", r"[0-2]\.[0-9]+\.[0-9]+", "high", "CVE-2020-7660", "RCE in serialize-javascript < 3.1.0"),
    ("minimist", r"[0-1]\.[0-1]\.[0-9]+", "medium", "CVE-2020-7598", "Prototype pollution in minimist < 1.2.3"),
];

/// Secret detection patterns
const SECRET_PATTERNS: &[(&str, &str, SecretType, u8)] = &[
    // AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", SecretType::AwsAccessKey, 95),
    (r#"(?i)aws.{0,20}secret.{0,20}["'][0-9a-zA-Z/+=]{40}["']"#, "AWS Secret Key", SecretType::AwsSecretKey, 80),

    // Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", SecretType::GoogleApiKey, 90),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth", SecretType::GoogleOAuth, 95),

    // GitHub/GitLab
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", SecretType::GitHubToken, 95),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", SecretType::GitHubToken, 95),
    (r"ghu_[0-9a-zA-Z]{36}", "GitHub User Token", SecretType::GitHubToken, 95),
    (r"ghr_[0-9a-zA-Z]{36}", "GitHub Refresh Token", SecretType::GitHubToken, 95),
    (r"glpat-[0-9a-zA-Z\-_]{20,}", "GitLab Personal Access Token", SecretType::GitLabToken, 95),

    // Slack
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*", "Slack Token", SecretType::SlackToken, 90),
    (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}", "Slack Webhook", SecretType::SlackWebhook, 95),

    // Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key", SecretType::StripeKey, 95),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", SecretType::StripeKey, 95),

    // Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", SecretType::TwilioKey, 70),

    // Private Keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key", SecretType::PrivateKey, 95),

    // Database URLs
    (r#"(?i)(mongodb|postgres|mysql|redis)://[^\s"']+"#, "Database URL", SecretType::DatabaseUrl, 85),

    // S3 Buckets
    (r"[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com", "S3 Bucket", SecretType::S3Bucket, 70),
    (r"s3://[a-zA-Z0-9.\-]+", "S3 Bucket", SecretType::S3Bucket, 80),

    // Generic patterns (lower confidence)
    (r#"(?i)["']?api[_\-]?key["']?\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']"#, "Generic API Key", SecretType::GenericApiKey, 60),
    (r#"(?i)["']?secret["']?\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']"#, "Generic Secret", SecretType::GenericSecret, 50),
    (r#"(?i)["']?password["']?\s*[:=]\s*["'][^"']{8,}["']"#, "Password", SecretType::GenericSecret, 40),
    (r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+", "Basic Auth", SecretType::BasicAuthCredentials, 80),
];

/// Endpoint extraction patterns
const ENDPOINT_PATTERNS: &[(&str, EndpointType)] = &[
    // Full URLs
    (r#"https?://[^\s\"'<>\)\]\}]+"#, EndpointType::FullUrl),
    // WebSocket URLs
    (r#"wss?://[^\s\"'<>\)\]\}]+"#, EndpointType::WebSocket),
    // API endpoints
    (r#"[\"'](/api/[v]?[0-9]*/[a-zA-Z0-9/_\-]+)[\"']"#, EndpointType::ApiEndpoint),
    (r#"[\"'](/v[0-9]+/[a-zA-Z0-9/_\-]+)[\"']"#, EndpointType::ApiEndpoint),
    // Relative paths that look like API endpoints
    (r#"[\"'](/[a-zA-Z0-9/_\-]+\.(json|xml|api))[\"']"#, EndpointType::ApiEndpoint),
    // GraphQL
    (r#"[\"'](/graphql[/]?)[\"']"#, EndpointType::GraphQL),
    // Generic relative paths (with file extensions or specific patterns)
    (r#"[\"'](/[a-zA-Z0-9/_\-]+)[\"']"#, EndpointType::RelativePath),
];

/// HTTP method indicators in JS
const HTTP_METHOD_PATTERNS: &[(&str, &str)] = &[
    (r#"\.get\s*\(\s*[\"']"#, "GET"),
    (r#"\.post\s*\(\s*[\"']"#, "POST"),
    (r#"\.put\s*\(\s*[\"']"#, "PUT"),
    (r#"\.delete\s*\(\s*[\"']"#, "DELETE"),
    (r#"\.patch\s*\(\s*[\"']"#, "PATCH"),
    (r#"method\s*:\s*[\"']GET[\"']"#, "GET"),
    (r#"method\s*:\s*[\"']POST[\"']"#, "POST"),
    (r#"method\s*:\s*[\"']PUT[\"']"#, "PUT"),
    (r#"method\s*:\s*[\"']DELETE[\"']"#, "DELETE"),
    (r#"method\s*:\s*[\"']PATCH[\"']"#, "PATCH"),
];

/// JavaScript analyzer
pub struct JsAnalyzer {
    /// Compiled regex patterns for endpoints
    endpoint_patterns: Vec<(Regex, EndpointType)>,
    /// Compiled regex patterns for secrets
    secret_patterns: Vec<(Regex, &'static str, SecretType, u8)>,
    /// Compiled regex patterns for HTTP methods
    method_patterns: Vec<(Regex, &'static str)>,
    /// Minimum confidence threshold for secrets
    min_confidence: u8,
}

impl JsAnalyzer {
    /// Create a new JavaScript analyzer
    pub fn new() -> Self {
        let endpoint_patterns: Vec<_> = ENDPOINT_PATTERNS
            .iter()
            .filter_map(|(pattern, endpoint_type)| {
                Regex::new(pattern).ok().map(|r| (r, endpoint_type.clone()))
            })
            .collect();

        let secret_patterns: Vec<_> = SECRET_PATTERNS
            .iter()
            .filter_map(|(pattern, desc, secret_type, conf)| {
                Regex::new(pattern).ok().map(|r| (r, *desc, secret_type.clone(), *conf))
            })
            .collect();

        let method_patterns: Vec<_> = HTTP_METHOD_PATTERNS
            .iter()
            .filter_map(|(pattern, method)| {
                Regex::new(pattern).ok().map(|r| (r, *method))
            })
            .collect();

        Self {
            endpoint_patterns,
            secret_patterns,
            method_patterns,
            min_confidence: 50,
        }
    }

    /// Set minimum confidence threshold for secret detection
    pub fn with_min_confidence(mut self, confidence: u8) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Extract endpoints from JavaScript content
    pub fn extract_endpoints(&self, js_content: &str, source: &str) -> Vec<JsEndpoint> {
        let mut endpoints = Vec::new();
        let mut seen = HashSet::new();

        for (regex, endpoint_type) in &self.endpoint_patterns {
            for cap in regex.find_iter(js_content) {
                let path = cap.as_str().trim_matches(|c| c == '"' || c == '\'');

                // Skip if already seen
                if seen.contains(path) {
                    continue;
                }
                seen.insert(path.to_string());

                // Skip common false positives
                if self.is_false_positive_endpoint(path) {
                    continue;
                }

                // Try to detect HTTP method
                let method = self.detect_http_method(js_content, cap.start());

                // Extract context (surrounding code)
                let context = self.extract_context(js_content, cap.start(), cap.end());

                // Calculate line number
                let line = js_content[..cap.start()].matches('\n').count() + 1;

                endpoints.push(JsEndpoint {
                    path: path.to_string(),
                    method,
                    source: source.to_string(),
                    line: Some(line),
                    context,
                    endpoint_type: endpoint_type.clone(),
                });
            }
        }

        endpoints
    }

    /// Detect secrets in JavaScript content
    pub fn detect_secrets(&self, js_content: &str, source: &str) -> Vec<JsSecret> {
        let mut secrets = Vec::new();

        for (regex, _desc, secret_type, confidence) in &self.secret_patterns {
            if *confidence < self.min_confidence {
                continue;
            }

            for cap in regex.find_iter(js_content) {
                let value = cap.as_str();

                // Skip if it's clearly a placeholder
                if self.is_placeholder(value) {
                    continue;
                }

                let context = self.extract_context(js_content, cap.start(), cap.end());
                let masked_value = self.mask_secret(value);

                secrets.push(JsSecret {
                    secret_type: secret_type.clone(),
                    value: masked_value,
                    context,
                    source: source.to_string(),
                    confidence: *confidence,
                });
            }
        }

        secrets
    }

    /// Detect vulnerable JavaScript libraries
    pub fn detect_vulnerable_libraries(&self, js_content: &str) -> Vec<VulnerableLibrary> {
        let mut vulnerable = Vec::new();

        // Extract library versions from common patterns
        let library_versions = self.extract_library_versions(js_content);

        for (lib_name, version) in library_versions {
            let vulns = self.check_library_vulnerabilities(&lib_name, &version);
            if !vulns.is_empty() {
                vulnerable.push(VulnerableLibrary {
                    name: lib_name,
                    version,
                    vulnerabilities: vulns,
                    detection_method: "Version string analysis".to_string(),
                });
            }
        }

        vulnerable
    }

    /// Extract library versions from JavaScript content
    fn extract_library_versions(&self, content: &str) -> HashMap<String, String> {
        let mut versions = HashMap::new();

        // jQuery patterns
        let jquery_patterns = [
            r#"jQuery\s+v?(\d+\.\d+\.\d+)"#,
            r#"jquery["']?\s*:\s*["']?(\d+\.\d+\.\d+)"#,
            r#"jQuery\.fn\.jquery\s*=\s*["'](\d+\.\d+\.\d+)"#,
        ];
        for pattern in jquery_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(content) {
                    if let Some(version) = cap.get(1) {
                        versions.insert("jquery".to_string(), version.as_str().to_string());
                    }
                }
            }
        }

        // Angular patterns
        let angular_patterns = [
            r#"angular["']?\s*:\s*["']?(\d+\.\d+\.\d+)"#,
            r#"AngularJS\s+v?(\d+\.\d+\.\d+)"#,
            r#"angular\.version\.full\s*=\s*["'](\d+\.\d+\.\d+)"#,
        ];
        for pattern in angular_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(content) {
                    if let Some(version) = cap.get(1) {
                        versions.insert("angular".to_string(), version.as_str().to_string());
                    }
                }
            }
        }

        // Bootstrap patterns
        let bootstrap_patterns = [
            r#"Bootstrap\s+v?(\d+\.\d+\.\d+)"#,
            r#"bootstrap["']?\s*:\s*["']?(\d+\.\d+\.\d+)"#,
        ];
        for pattern in bootstrap_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(content) {
                    if let Some(version) = cap.get(1) {
                        versions.insert("bootstrap".to_string(), version.as_str().to_string());
                    }
                }
            }
        }

        // Lodash patterns
        if let Ok(re) = Regex::new(r#"lodash["']?\s*:\s*["']?(\d+\.\d+\.\d+)"#) {
            if let Some(cap) = re.captures(content) {
                if let Some(version) = cap.get(1) {
                    versions.insert("lodash".to_string(), version.as_str().to_string());
                }
            }
        }

        // Vue.js patterns
        if let Ok(re) = Regex::new(r#"Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)"#) {
            if let Some(cap) = re.captures(content) {
                if let Some(version) = cap.get(1) {
                    versions.insert("vue".to_string(), version.as_str().to_string());
                }
            }
        }

        // React patterns
        if let Ok(re) = Regex::new(r#"React\.version\s*=\s*["'](\d+\.\d+\.\d+)"#) {
            if let Some(cap) = re.captures(content) {
                if let Some(version) = cap.get(1) {
                    versions.insert("react".to_string(), version.as_str().to_string());
                }
            }
        }

        versions
    }

    /// Check if a library version has known vulnerabilities
    fn check_library_vulnerabilities(&self, name: &str, version: &str) -> Vec<LibraryVulnerability> {
        let mut vulns = Vec::new();

        for (lib_name, version_pattern, severity, cve, description) in VULNERABLE_LIBRARIES {
            if *lib_name != name {
                continue;
            }

            if let Ok(re) = Regex::new(version_pattern) {
                if re.is_match(version) {
                    vulns.push(LibraryVulnerability {
                        cve: if cve.is_empty() { None } else { Some(cve.to_string()) },
                        severity: severity.to_string(),
                        description: description.to_string(),
                        fixed_in: None,
                        reference: None,
                    });
                }
            }
        }

        vulns
    }

    /// Detect HTTP method used with an endpoint
    fn detect_http_method(&self, content: &str, position: usize) -> Option<String> {
        // Look in a window before the endpoint for method indicators
        let start = position.saturating_sub(100);
        let window = &content[start..position];

        for (regex, method) in &self.method_patterns {
            if regex.is_match(window) {
                return Some(method.to_string());
            }
        }

        None
    }

    /// Extract context around a finding
    fn extract_context(&self, content: &str, start: usize, end: usize) -> String {
        let context_start = start.saturating_sub(50);
        let context_end = (end + 50).min(content.len());

        let mut context = String::new();
        if context_start > 0 {
            context.push_str("...");
        }
        context.push_str(&content[context_start..context_end]);
        if context_end < content.len() {
            context.push_str("...");
        }

        // Clean up whitespace
        context.replace(['\n', '\r', '\t'], " ")
    }

    /// Check if an endpoint is a common false positive
    fn is_false_positive_endpoint(&self, path: &str) -> bool {
        let false_positives = [
            // Common non-API paths
            ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot",
            // Version numbers that look like paths
            "/1.", "/2.", "/3.",
            // Common framework paths that aren't real endpoints
            "node_modules", "bower_components",
            // Generic placeholders
            "${", "{{", "<%",
        ];

        for fp in false_positives {
            if path.contains(fp) {
                return true;
            }
        }

        // Too short to be meaningful
        if path.len() < 3 {
            return true;
        }

        false
    }

    /// Check if a secret value is likely a placeholder
    fn is_placeholder(&self, value: &str) -> bool {
        let placeholders = [
            "xxx", "XXX", "your_", "YOUR_", "replace_", "REPLACE_",
            "example_", "_example", "placeholder", "PLACEHOLDER",
            "insert_", "INSERT_", "todo_", "TODO_", "fixme", "FIXME",
            "changeme", "CHANGEME", "secret_here", "api_key_here",
            "xxxxxxxxx", "000000000", "111111111",
        ];

        let lower = value.to_lowercase();
        for p in placeholders {
            if lower.contains(&p.to_lowercase()) {
                return true;
            }
        }

        // Check if value is mostly repeated characters (like "aaaaaaa" or "1111111")
        if value.len() >= 8 {
            let first = value.chars().next().unwrap_or(' ');
            if value.chars().all(|c| c == first) {
                return true;
            }
        }

        false
    }

    /// Mask a secret value for safe display
    fn mask_secret(&self, value: &str) -> String {
        if value.len() <= 8 {
            return "*".repeat(value.len());
        }

        let visible_start = 4;
        let visible_end = 4;
        let masked_len = value.len() - visible_start - visible_end;

        format!(
            "{}{}{}",
            &value[..visible_start],
            "*".repeat(masked_len.max(4)),
            &value[value.len() - visible_end..]
        )
    }
}

impl Default for JsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze JavaScript from a URL
pub async fn analyze_js_from_url(client: &crate::http::HttpClient, url: &str) -> Result<JsAnalysisReport> {
    let request = crate::http::Request::new("GET", url);
    let response = client.execute(&request).await?;
    let content = response.body_text();

    let analyzer = JsAnalyzer::new();

    Ok(JsAnalysisReport {
        source: url.to_string(),
        endpoints: analyzer.extract_endpoints(&content, url),
        secrets: analyzer.detect_secrets(&content, url),
        vulnerable_libraries: analyzer.detect_vulnerable_libraries(&content),
    })
}

/// Complete analysis report for JavaScript
#[derive(Debug, Clone)]
pub struct JsAnalysisReport {
    /// Source URL/file
    pub source: String,
    /// Discovered endpoints
    pub endpoints: Vec<JsEndpoint>,
    /// Detected secrets
    pub secrets: Vec<JsSecret>,
    /// Vulnerable libraries
    pub vulnerable_libraries: Vec<VulnerableLibrary>,
}

impl JsAnalysisReport {
    /// Check if any issues were found
    pub fn has_findings(&self) -> bool {
        !self.endpoints.is_empty() || !self.secrets.is_empty() || !self.vulnerable_libraries.is_empty()
    }

    /// Get high severity findings count
    pub fn high_severity_count(&self) -> usize {
        let secret_count = self.secrets.iter()
            .filter(|s| matches!(s.secret_type.severity(), "Critical" | "High"))
            .count();

        let vuln_count = self.vulnerable_libraries.iter()
            .flat_map(|v| &v.vulnerabilities)
            .filter(|v| v.severity == "critical" || v.severity == "high")
            .count();

        secret_count + vuln_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_endpoints() {
        let analyzer = JsAnalyzer::new();
        let js = r#"
            fetch("/api/v1/users");
            axios.get("/api/v2/products");
            $.post("/api/orders");
        "#;

        let endpoints = analyzer.extract_endpoints(js, "test.js");
        assert!(!endpoints.is_empty());
        assert!(endpoints.iter().any(|e| e.path.contains("/api/")));
    }

    #[test]
    fn test_detect_secrets_aws() {
        let analyzer = JsAnalyzer::new();
        // Using a realistic-looking (but fake) AWS access key - exactly 20 chars (AKIA + 16)
        let js = r#"
            const accessKey = "AKIAI44QH8DHBTEST12X";
            const apiKey = "sk_test_FAKE_KEY_FOR_TESTING_ONLY";
        "#;

        let secrets = analyzer.detect_secrets(js, "test.js");
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| matches!(s.secret_type, SecretType::AwsAccessKey)));
    }

    #[test]
    fn test_detect_vulnerable_libraries() {
        let analyzer = JsAnalyzer::new();
        let js = r#"
            /*! jQuery v1.8.3 */
            jQuery.fn.jquery = "1.8.3";
        "#;

        let vulns = analyzer.detect_vulnerable_libraries(js);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.name == "jquery"));
    }

    #[test]
    fn test_mask_secret() {
        let analyzer = JsAnalyzer::new();

        let masked = analyzer.mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.ends_with("MPLE"));
        assert!(masked.contains("*"));
    }

    #[test]
    fn test_is_placeholder() {
        let analyzer = JsAnalyzer::new();

        assert!(analyzer.is_placeholder("YOUR_API_KEY_HERE"));
        assert!(analyzer.is_placeholder("xxxxxxxxxxxxxxxx"));
        assert!(analyzer.is_placeholder("REPLACE_ME_WITH_KEY"));
        assert!(!analyzer.is_placeholder("AKIAI44QH8DHBTEST12"));
        assert!(!analyzer.is_placeholder("ghp_z9K8xBvNmP1qR5sT7uW3yA2cD4fG6hJ9kL0"));
    }

    #[test]
    fn test_endpoint_types() {
        let analyzer = JsAnalyzer::new();
        let js = r#"
            fetch("https://api.example.com/data");
            socket = new WebSocket("wss://ws.example.com");
            graphql("/graphql");
        "#;

        let endpoints = analyzer.extract_endpoints(js, "test.js");
        assert!(endpoints.iter().any(|e| e.endpoint_type == EndpointType::FullUrl));
        assert!(endpoints.iter().any(|e| e.endpoint_type == EndpointType::WebSocket));
    }

    #[test]
    fn test_secret_severity() {
        assert_eq!(SecretType::AwsSecretKey.severity(), "Critical");
        assert_eq!(SecretType::GitHubToken.severity(), "High");
        assert_eq!(SecretType::SlackToken.severity(), "Medium");
    }
}
