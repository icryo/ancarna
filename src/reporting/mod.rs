//! Report Generation Module
//!
//! Generates security scan reports in various formats:
//! - HTML (styled, interactive)
//! - JSON (machine-readable)
//! - CSV (spreadsheet-compatible)
//! - Markdown (documentation-friendly)

#![allow(dead_code)]

pub mod formats;

use crate::scanner::{Finding, Severity};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report title
    pub title: String,
    /// Target URL/scope
    pub target: String,
    /// Scan start time
    pub start_time: DateTime<Utc>,
    /// Scan end time
    pub end_time: DateTime<Utc>,
    /// Scanner version
    pub scanner_version: String,
    /// Report generation time
    pub generated_at: DateTime<Utc>,
    /// Custom notes
    pub notes: Option<String>,
}

impl Default for ReportMetadata {
    fn default() -> Self {
        Self {
            title: "Security Scan Report".to_string(),
            target: String::new(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: Utc::now(),
            notes: None,
        }
    }
}

/// Summary statistics for a report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total number of findings
    pub total_findings: usize,
    /// Findings by severity
    pub by_severity: HashMap<String, usize>,
    /// Findings by category/type
    pub by_category: HashMap<String, usize>,
    /// Number of unique hosts
    pub unique_hosts: usize,
    /// Number of unique URLs
    pub unique_urls: usize,
    /// Scan duration in seconds
    pub duration_secs: u64,
    /// Risk score (0-100)
    pub risk_score: u8,
}

impl ReportSummary {
    /// Calculate summary from findings
    pub fn from_findings(findings: &[Finding], metadata: &ReportMetadata) -> Self {
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut urls: std::collections::HashSet<String> = std::collections::HashSet::new();

        for finding in findings {
            // Count by severity
            let severity_name = finding.severity_level().name().to_string();
            *by_severity.entry(severity_name).or_insert(0) += 1;

            // Count by category
            *by_category.entry(finding.name.clone()).or_insert(0) += 1;

            // Track unique hosts and URLs
            if let Ok(url) = url::Url::parse(&finding.url) {
                if let Some(host) = url.host_str() {
                    hosts.insert(host.to_string());
                }
            }
            urls.insert(finding.url.clone());
        }

        // Calculate risk score
        let risk_score = Self::calculate_risk_score(findings);

        let duration = metadata.end_time.signed_duration_since(metadata.start_time);

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            unique_hosts: hosts.len(),
            unique_urls: urls.len(),
            duration_secs: duration.num_seconds().max(0) as u64,
            risk_score,
        }
    }

    /// Calculate overall risk score (0-100)
    fn calculate_risk_score(findings: &[Finding]) -> u8 {
        if findings.is_empty() {
            return 0;
        }

        let mut score: f64 = 0.0;

        for finding in findings {
            score += match finding.severity_level() {
                Severity::Critical => 25.0,
                Severity::High => 15.0,
                Severity::Medium => 8.0,
                Severity::Low => 3.0,
                Severity::Informational => 1.0,
            };
        }

        // Cap at 100
        (score.min(100.0)) as u8
    }
}

/// Complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Summary statistics
    pub summary: ReportSummary,
    /// All findings
    pub findings: Vec<Finding>,
    /// OWASP Top 10 mapping
    pub owasp_mapping: HashMap<String, Vec<usize>>,
}

impl ScanReport {
    /// Create a new report from findings
    pub fn new(findings: Vec<Finding>, metadata: ReportMetadata) -> Self {
        let summary = ReportSummary::from_findings(&findings, &metadata);
        let owasp_mapping = Self::map_to_owasp(&findings);

        Self {
            metadata,
            summary,
            findings,
            owasp_mapping,
        }
    }

    /// Map findings to OWASP Top 10 categories
    fn map_to_owasp(findings: &[Finding]) -> HashMap<String, Vec<usize>> {
        let mut mapping: HashMap<String, Vec<usize>> = HashMap::new();

        // Initialize all OWASP categories
        let categories = [
            "A01:2021 – Broken Access Control",
            "A02:2021 – Cryptographic Failures",
            "A03:2021 – Injection",
            "A04:2021 – Insecure Design",
            "A05:2021 – Security Misconfiguration",
            "A06:2021 – Vulnerable Components",
            "A07:2021 – Auth Failures",
            "A08:2021 – Data Integrity Failures",
            "A09:2021 – Security Logging Failures",
            "A10:2021 – Server-Side Request Forgery",
        ];

        for cat in categories {
            mapping.insert(cat.to_string(), Vec::new());
        }

        // Map findings based on their OWASP category
        for (idx, finding) in findings.iter().enumerate() {
            if let Some(owasp) = &finding.owasp_category {
                if let Some(indices) = mapping.get_mut(owasp) {
                    indices.push(idx);
                }
            }
        }

        mapping
    }

    /// Export to HTML format
    pub fn to_html(&self) -> Result<String> {
        formats::html::generate(self)
    }

    /// Export to JSON format
    pub fn to_json(&self) -> Result<String> {
        formats::json::generate(self)
    }

    /// Export to CSV format
    pub fn to_csv(&self) -> Result<String> {
        formats::csv::generate(self)
    }

    /// Export to Markdown format
    pub fn to_markdown(&self) -> Result<String> {
        formats::markdown::generate(self)
    }

    /// Save report to file with auto-detected format
    pub fn save(&self, path: &Path) -> Result<()> {
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("html");

        let content = match extension {
            "html" | "htm" => self.to_html()?,
            "json" => self.to_json()?,
            "csv" => self.to_csv()?,
            "md" | "markdown" => self.to_markdown()?,
            _ => self.to_html()?,
        };

        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Json,
    Csv,
    Markdown,
}

impl ReportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Html => "html",
            ReportFormat::Json => "json",
            ReportFormat::Csv => "csv",
            ReportFormat::Markdown => "md",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            ReportFormat::Html => "text/html",
            ReportFormat::Json => "application/json",
            ReportFormat::Csv => "text/csv",
            ReportFormat::Markdown => "text/markdown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_findings() -> Vec<Finding> {
        vec![
            Finding::new("SQL Injection", Severity::Critical, "https://example.com/api")
                .with_owasp("A03:2021 – Injection"),
            Finding::new("Missing Security Headers", Severity::Medium, "https://example.com/")
                .with_owasp("A05:2021 – Security Misconfiguration"),
            Finding::new("Information Disclosure", Severity::Low, "https://example.com/debug"),
        ]
    }

    #[test]
    fn test_report_summary() {
        let findings = create_test_findings();
        let metadata = ReportMetadata::default();
        let summary = ReportSummary::from_findings(&findings, &metadata);

        assert_eq!(summary.total_findings, 3);
        assert!(summary.by_severity.contains_key("Critical"));
        assert!(summary.risk_score > 0);
    }

    #[test]
    fn test_owasp_mapping() {
        let findings = create_test_findings();
        let mapping = ScanReport::map_to_owasp(&findings);

        assert!(mapping.contains_key("A03:2021 – Injection"));
        assert!(!mapping["A03:2021 – Injection"].is_empty());
    }

    #[test]
    fn test_risk_score_calculation() {
        let findings = vec![
            Finding::new("Critical", Severity::Critical, "https://example.com"),
            Finding::new("High", Severity::High, "https://example.com"),
        ];

        let score = ReportSummary::calculate_risk_score(&findings);
        assert_eq!(score, 40); // 25 + 15
    }

    #[test]
    fn test_report_format_extension() {
        assert_eq!(ReportFormat::Html.extension(), "html");
        assert_eq!(ReportFormat::Json.extension(), "json");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
        assert_eq!(ReportFormat::Markdown.extension(), "md");
    }
}
