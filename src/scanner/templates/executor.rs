//! Template executor
//!
//! Executes Nuclei-compatible templates against HTTP request/response pairs.
//! Supports both passive scanning (analyzing existing responses) and active
//! scanning (sending templated requests with payloads).

use super::matcher::{execute_matchers, MatchResult};
use super::parser::{
    HttpRequest as TemplateHttpRequest, MatcherCondition, Severity as TemplateSeverity, Template,
    TemplateType,
};
use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use url::Url;

/// Regex for matching template variables like {{BaseURL}}, {{Hostname}}, etc.
fn variable_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{(\w+)\}\}").expect("Invalid variable regex"))
}

/// Variables available for template substitution
#[derive(Debug, Clone, Default)]
pub struct TemplateVariables {
    /// Base URL (e.g., "https://example.com")
    pub base_url: String,
    /// Root URL (e.g., "https://example.com/")
    pub root_url: String,
    /// Hostname (e.g., "example.com")
    pub hostname: String,
    /// Host (alias for hostname)
    pub host: String,
    /// Port (e.g., "443")
    pub port: String,
    /// Scheme (e.g., "https")
    pub scheme: String,
    /// Path from original request (e.g., "/api/users")
    pub path: String,
    /// Full URL of the original request
    pub full_url: String,
    /// Custom variables from payloads
    pub custom: HashMap<String, String>,
}

impl TemplateVariables {
    /// Create variables from a base URL
    pub fn from_url(url: &str) -> Self {
        let parsed = Url::parse(url).ok();

        let (scheme, host, port, path) = if let Some(ref u) = parsed {
            let scheme = u.scheme().to_string();
            let host = u.host_str().unwrap_or("").to_string();
            let port = u
                .port_or_known_default()
                .map(|p| p.to_string())
                .unwrap_or_else(|| if scheme == "https" { "443" } else { "80" }.to_string());
            let path = u.path().to_string();
            (scheme, host, port, path)
        } else {
            ("http".to_string(), url.to_string(), "80".to_string(), "/".to_string())
        };

        let base_url = if let Some(ref u) = parsed {
            // Include port if explicitly specified or non-default
            if let Some(explicit_port) = u.port() {
                format!("{}://{}:{}", u.scheme(), u.host_str().unwrap_or(""), explicit_port)
            } else {
                format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""))
            }
        } else {
            url.to_string()
        };

        let root_url = format!("{}/", base_url.trim_end_matches('/'));

        Self {
            base_url: base_url.clone(),
            root_url,
            hostname: host.clone(),
            host,
            port,
            scheme,
            path,
            full_url: url.to_string(),
            custom: HashMap::new(),
        }
    }

    /// Add a custom variable
    pub fn with_var(mut self, name: &str, value: &str) -> Self {
        self.custom.insert(name.to_string(), value.to_string());
        self
    }

    /// Substitute variables in a string
    /// Both built-in and custom variables are case-insensitive for Nuclei compatibility
    pub fn substitute(&self, input: &str) -> String {
        variable_regex()
            .replace_all(input, |caps: &regex::Captures| {
                let var_name = &caps[1];
                let var_name_lower = var_name.to_lowercase();
                match var_name_lower.as_str() {
                    "baseurl" | "base_url" => self.base_url.clone(),
                    "rooturl" | "root_url" => self.root_url.clone(),
                    "hostname" => self.hostname.clone(),
                    "host" => self.host.clone(),
                    "port" => self.port.clone(),
                    "scheme" | "protocol" => self.scheme.clone(),
                    "path" => self.path.clone(),
                    "fullurl" | "full_url" | "url" => self.full_url.clone(),
                    _ => {
                        // Case-insensitive lookup for custom variables
                        self.custom
                            .iter()
                            .find(|(k, _)| k.to_lowercase() == var_name_lower)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_else(|| caps[0].to_string())
                    }
                }
            })
            .to_string()
    }
}

/// Result from active template execution
#[derive(Debug, Clone)]
pub struct ActiveScanResult {
    /// The finding if vulnerability detected
    pub finding: Option<Finding>,
    /// Request that was sent
    pub request: Request,
    /// Response received
    pub response: Response,
    /// Template ID that was executed
    pub template_id: String,
    /// Payload values used (if any)
    pub payloads: HashMap<String, String>,
}

/// Executor for running templates against HTTP traffic
pub struct TemplateExecutor {
    /// Templates to execute
    templates: Vec<Template>,
    /// Only run passive templates
    passive_only: bool,
}

impl TemplateExecutor {
    /// Create a new executor with the given templates
    pub fn new(templates: Vec<Template>) -> Self {
        Self {
            templates,
            passive_only: true,
        }
    }

    /// Create executor with bundled templates
    pub fn with_bundled() -> Self {
        Self::new(super::bundled_templates())
    }

    /// Create executor with bundled templates plus templates from a directory
    pub fn with_bundled_and_dir(templates_dir: &std::path::Path) -> Self {
        let mut templates = super::bundled_templates();
        match super::load_templates_from_dir(templates_dir) {
            Ok(custom_templates) => {
                tracing::info!(
                    "Loaded {} custom templates from {:?}",
                    custom_templates.len(),
                    templates_dir
                );
                templates.extend(custom_templates);
            }
            Err(e) => {
                tracing::warn!("Failed to load templates from {:?}: {}", templates_dir, e);
            }
        }
        Self::new(templates)
    }

    /// Set whether to run only passive templates
    pub fn passive_only(mut self, passive_only: bool) -> Self {
        self.passive_only = passive_only;
        self
    }

    /// Add additional templates
    pub fn add_templates(&mut self, templates: Vec<Template>) {
        self.templates.extend(templates);
    }

    /// Get the number of loaded templates
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    /// Get templates by tag
    pub fn templates_with_tag(&self, tag: &str) -> Vec<&Template> {
        self.templates.iter().filter(|t| t.has_tag(tag)).collect()
    }

    /// Execute all templates against a request/response pair
    pub fn execute(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        for template in &self.templates {
            // Skip active templates if passive_only
            if self.passive_only && template.template_type == TemplateType::Active {
                continue;
            }

            if let Some(finding) = self.execute_template(template, request, response) {
                findings.push(finding);
            }
        }

        findings
    }

    /// Execute a single template
    fn execute_template(
        &self,
        template: &Template,
        request: &Request,
        response: &Response,
    ) -> Option<Finding> {
        // For passive templates, use passive_matchers
        let matchers = if template.template_type == TemplateType::Passive {
            &template.passive_matchers
        } else if let Some(http_req) = template.http.first() {
            &http_req.matchers
        } else {
            return None;
        };

        if matchers.is_empty() {
            return None;
        }

        // Get the condition for combining matchers
        let condition = if template.template_type == TemplateType::Passive {
            MatcherCondition::And
        } else {
            template
                .http
                .first()
                .map(|h| h.matchers_condition)
                .unwrap_or(MatcherCondition::And)
        };

        // Execute matchers
        let results = execute_matchers(matchers, condition, request, response);

        // If any matchers matched, create a finding
        if !results.is_empty() && results.iter().any(|r| r.matched) {
            Some(self.create_finding(template, request, &results))
        } else {
            None
        }
    }

    /// Create a Finding from a matched template
    fn create_finding(
        &self,
        template: &Template,
        request: &Request,
        match_results: &[MatchResult],
    ) -> Finding {
        let severity = convert_severity(template.info.severity);

        let mut finding = Finding::new(&template.info.name, severity, &request.url)
            .with_description(&template.info.description)
            .with_method(&request.method)
            .with_scanner(&format!("template:{}", template.id));

        // Add CWE if available
        if let Some(cwe) = template.cwe {
            finding = finding.with_cwe(cwe);
        }

        // Add references
        for reference in &template.info.reference {
            finding = finding.with_reference(reference);
        }

        // Add evidence from match results
        let evidence: Vec<String> = match_results
            .iter()
            .filter(|r| r.matched)
            .flat_map(|r| {
                let mut parts = Vec::new();
                if let Some(name) = &r.name {
                    parts.push(format!("Matched: {}", name));
                }
                if !r.extracts.is_empty() {
                    parts.push(format!("Found: {}", r.extracts.join(", ")));
                }
                parts
            })
            .collect();

        if !evidence.is_empty() {
            finding = finding.with_evidence(&evidence.join("\n"));
        }

        // Set confidence based on matcher type
        let confidence = calculate_confidence(match_results);
        finding = finding.with_confidence(confidence);

        finding
    }

    /// Execute templates filtered by tag
    pub fn execute_with_tag(
        &self,
        tag: &str,
        request: &Request,
        response: &Response,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for template in &self.templates {
            if !template.has_tag(tag) {
                continue;
            }

            if self.passive_only && template.template_type == TemplateType::Active {
                continue;
            }

            if let Some(finding) = self.execute_template(template, request, response) {
                findings.push(finding);
            }
        }

        findings
    }

    /// Execute templates filtered by severity
    pub fn execute_with_min_severity(
        &self,
        min_severity: TemplateSeverity,
        request: &Request,
        response: &Response,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for template in &self.templates {
            if severity_level(template.info.severity) < severity_level(min_severity) {
                continue;
            }

            if self.passive_only && template.template_type == TemplateType::Active {
                continue;
            }

            if let Some(finding) = self.execute_template(template, request, response) {
                findings.push(finding);
            }
        }

        findings
    }

    /// Execute active templates against a target URL
    ///
    /// This sends actual HTTP requests based on template definitions.
    /// Returns findings for any vulnerabilities detected.
    pub async fn execute_active(
        &self,
        client: &crate::http::HttpClient,
        target_url: &str,
    ) -> Vec<ActiveScanResult> {
        let mut results = Vec::new();
        let variables = TemplateVariables::from_url(target_url);

        for template in &self.templates {
            // Only run active templates
            if template.template_type != TemplateType::Active {
                continue;
            }

            let template_results = self
                .execute_active_template(client, template, &variables)
                .await;
            results.extend(template_results);
        }

        results
    }

    /// Execute a single active template
    async fn execute_active_template(
        &self,
        client: &crate::http::HttpClient,
        template: &Template,
        base_variables: &TemplateVariables,
    ) -> Vec<ActiveScanResult> {
        let mut results = Vec::new();

        for http_req in &template.http {
            let payload_combinations = generate_payload_combinations(&http_req.payloads);

            // If no payloads, execute once with base variables
            if payload_combinations.is_empty() {
                if let Some(result) = self
                    .execute_single_request(client, template, http_req, base_variables, HashMap::new())
                    .await
                {
                    let found_vuln = result.finding.is_some();
                    results.push(result);
                    if http_req.stop_at_first_match && found_vuln {
                        break;
                    }
                }
            } else {
                // Execute for each payload combination
                for payload_values in payload_combinations {
                    let mut variables = base_variables.clone();
                    for (key, value) in &payload_values {
                        variables.custom.insert(key.clone(), value.clone());
                    }

                    if let Some(result) = self
                        .execute_single_request(client, template, http_req, &variables, payload_values)
                        .await
                    {
                        let found_vuln = result.finding.is_some();
                        results.push(result);
                        if http_req.stop_at_first_match && found_vuln {
                            break;
                        }
                    }
                }
            }
        }

        results
    }

    /// Execute a single HTTP request from a template
    async fn execute_single_request(
        &self,
        client: &crate::http::HttpClient,
        template: &Template,
        http_req: &TemplateHttpRequest,
        variables: &TemplateVariables,
        payload_values: HashMap<String, String>,
    ) -> Option<ActiveScanResult> {
        // Build the request from template
        let request = self.build_request_from_template(http_req, variables)?;

        // Execute the request
        let response = match client.execute(&request).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(
                    "Template {} request failed: {}",
                    template.id,
                    e
                );
                return None;
            }
        };

        // Run matchers against the response
        let matchers = &http_req.matchers;
        if matchers.is_empty() {
            return Some(ActiveScanResult {
                finding: None,
                request,
                response,
                template_id: template.id.clone(),
                payloads: payload_values,
            });
        }

        let results = execute_matchers(matchers, http_req.matchers_condition, &request, &response);

        let finding = if !results.is_empty() && results.iter().any(|r| r.matched) {
            Some(self.create_finding(template, &request, &results))
        } else {
            None
        };

        Some(ActiveScanResult {
            finding,
            request,
            response,
            template_id: template.id.clone(),
            payloads: payload_values,
        })
    }

    /// Build an HTTP request from a template definition
    fn build_request_from_template(
        &self,
        http_req: &TemplateHttpRequest,
        variables: &TemplateVariables,
    ) -> Option<Request> {
        // Get the path and substitute variables
        let path = http_req
            .path
            .first()
            .map(|p| variables.substitute(p))
            .unwrap_or_else(|| "/".to_string());

        // Build full URL - check AFTER substitution if it's already a full URL
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            // Path is already a full URL after substitution
            path
        } else {
            format!(
                "{}{}",
                variables.base_url.trim_end_matches('/'),
                if path.starts_with('/') { path } else { format!("/{}", path) }
            )
        };

        // Get method (default to GET)
        let method = if http_req.method.is_empty() {
            "GET".to_string()
        } else {
            variables.substitute(&http_req.method).to_uppercase()
        };

        // Build headers with variable substitution
        let mut headers = HashMap::new();
        for (key, value) in &http_req.headers {
            headers.insert(
                variables.substitute(key),
                variables.substitute(value),
            );
        }

        // Build body with variable substitution
        let body = if http_req.body.is_empty() {
            None
        } else {
            Some(variables.substitute(&http_req.body))
        };

        Some(Request {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("Template: {}", variables.custom.get("payload").unwrap_or(&"scan".to_string())),
            method,
            url,
            headers,
            params: HashMap::new(),
            body,
            content_type: None,
            auth: None,
            pre_script: None,
            post_script: None,
            timeout: None,
            follow_redirects: http_req.follow_redirects,
        })
    }

    /// Execute active templates filtered by tag
    pub async fn execute_active_with_tag(
        &self,
        client: &crate::http::HttpClient,
        target_url: &str,
        tag: &str,
    ) -> Vec<ActiveScanResult> {
        let mut results = Vec::new();
        let variables = TemplateVariables::from_url(target_url);

        for template in &self.templates {
            if template.template_type != TemplateType::Active {
                continue;
            }
            if !template.has_tag(tag) {
                continue;
            }

            let template_results = self
                .execute_active_template(client, template, &variables)
                .await;
            results.extend(template_results);
        }

        results
    }

    /// Get all active templates
    pub fn active_templates(&self) -> Vec<&Template> {
        self.templates
            .iter()
            .filter(|t| t.template_type == TemplateType::Active)
            .collect()
    }

    /// Get all passive templates
    pub fn passive_templates(&self) -> Vec<&Template> {
        self.templates
            .iter()
            .filter(|t| t.template_type == TemplateType::Passive)
            .collect()
    }
}

/// Generate all combinations of payload values
fn generate_payload_combinations(
    payloads: &HashMap<String, Vec<String>>,
) -> Vec<HashMap<String, String>> {
    if payloads.is_empty() {
        return Vec::new();
    }

    let keys: Vec<&String> = payloads.keys().collect();
    let mut combinations = Vec::new();

    // Start with empty combination
    combinations.push(HashMap::new());

    for key in keys {
        let values = &payloads[key];
        let mut new_combinations = Vec::new();

        for combo in &combinations {
            for value in values {
                let mut new_combo = combo.clone();
                new_combo.insert(key.clone(), value.clone());
                new_combinations.push(new_combo);
            }
        }

        combinations = new_combinations;
    }

    combinations
}

/// Convert template severity to finding severity
fn convert_severity(template_severity: TemplateSeverity) -> Severity {
    match template_severity {
        TemplateSeverity::Critical => Severity::Critical,
        TemplateSeverity::High => Severity::High,
        TemplateSeverity::Medium => Severity::Medium,
        TemplateSeverity::Low => Severity::Low,
        TemplateSeverity::Info => Severity::Informational,
    }
}

/// Get numeric severity level for comparison
fn severity_level(severity: TemplateSeverity) -> u8 {
    match severity {
        TemplateSeverity::Info => 0,
        TemplateSeverity::Low => 1,
        TemplateSeverity::Medium => 2,
        TemplateSeverity::High => 3,
        TemplateSeverity::Critical => 4,
    }
}

/// Calculate confidence based on match quality
fn calculate_confidence(results: &[MatchResult]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }

    let matched_count = results.iter().filter(|r| r.matched).count();
    let has_extracts = results.iter().any(|r| !r.extracts.is_empty());

    // Base confidence on how many matchers matched
    let base_confidence = matched_count as f64 / results.len() as f64;

    // Boost confidence if we have extracted evidence
    let confidence = if has_extracts {
        (base_confidence + 0.1).min(1.0)
    } else {
        base_confidence
    };

    // Round to 2 decimal places
    (confidence * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_request() -> Request {
        Request {
            id: "test-1".to_string(),
            name: "Test".to_string(),
            method: "GET".to_string(),
            url: "https://example.com/test".to_string(),
            headers: HashMap::new(),
            params: HashMap::new(),
            body: None,
            content_type: None,
            auth: None,
            pre_script: None,
            post_script: None,
            timeout: None,
            follow_redirects: true,
        }
    }

    fn create_test_response(status: u16, headers: HashMap<String, String>, body: &str) -> Response {
        Response {
            status,
            status_text: "OK".to_string(),
            headers,
            body: body.as_bytes().to_vec(),
            duration_ms: 100,
            size: body.len(),
            http_version: "HTTP/1.1".to_string(),
            remote_addr: None,
            tls_info: None,
            timing: None,
            cookies: Vec::new(),
        }
    }

    #[test]
    fn test_executor_with_bundled_templates() {
        let executor = TemplateExecutor::with_bundled();
        assert!(executor.template_count() > 0);
    }

    #[test]
    fn test_missing_hsts_detection() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();
        let response = create_test_response(200, HashMap::new(), "<html></html>");

        let findings = executor.execute(&request, &response);

        // Should detect missing HSTS header
        assert!(findings.iter().any(|f| f.name.contains("HSTS")));
    }

    #[test]
    fn test_hsts_present_no_finding() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();

        let mut headers = HashMap::new();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );

        let response = create_test_response(200, headers, "<html></html>");
        let findings = executor.execute(&request, &response);

        // Should NOT detect missing HSTS
        assert!(!findings.iter().any(|f| f.name.contains("Missing HSTS")));
    }

    #[test]
    fn test_server_header_disclosure() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();

        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41".to_string());

        let response = create_test_response(200, headers, "<html></html>");
        let findings = executor.execute(&request, &response);

        // Should detect server header disclosure
        assert!(findings.iter().any(|f| f.name.contains("Server Header")));
    }

    #[test]
    fn test_sql_error_disclosure() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();

        let body = r#"<html><body>SQL syntax error: You have an error in your SQL syntax near MySQL</body></html>"#;
        let response = create_test_response(500, HashMap::new(), body);

        let findings = executor.execute(&request, &response);

        // Should detect SQL error disclosure
        assert!(findings.iter().any(|f| f.name.contains("SQL Error")));
    }

    #[test]
    fn test_aws_key_disclosure() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();

        let body = r#"{"aws_access_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let response = create_test_response(200, HashMap::new(), body);

        let findings = executor.execute(&request, &response);

        // Should detect AWS key disclosure
        assert!(findings.iter().any(|f| f.name.contains("AWS")));
    }

    #[test]
    fn test_execute_with_tag() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_test_request();
        let response = create_test_response(200, HashMap::new(), "<html></html>");

        let findings = executor.execute_with_tag("headers", &request, &response);

        // All findings should be header-related
        for finding in &findings {
            assert!(finding
                .scanner
                .contains("missing-")
                || finding.scanner.contains("disclosure"));
        }
    }
}
