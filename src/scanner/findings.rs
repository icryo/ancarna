//! Vulnerability findings

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Severity::Informational => "Informational",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Informational,
        }
    }
}

/// A security finding/vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique ID
    pub id: String,

    /// Finding name/title
    pub name: String,

    /// Severity level
    pub severity: String,

    /// Description of the vulnerability
    pub description: String,

    /// URL where the vulnerability was found
    pub url: String,

    /// HTTP method
    pub method: String,

    /// Affected parameter (if applicable)
    pub parameter: Option<String>,

    /// Evidence/proof of the vulnerability
    pub evidence: Option<String>,

    /// Remediation advice
    pub remediation: Option<String>,

    /// CWE ID (if applicable)
    pub cwe_id: Option<u32>,

    /// OWASP category
    pub owasp_category: Option<String>,

    /// References/links
    pub references: Vec<String>,

    /// Request that triggered the finding
    pub request: Option<String>,

    /// Response that confirmed the finding
    pub response: Option<String>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,

    /// Scanner/plugin that found this
    pub scanner: String,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Whether this finding has been confirmed
    pub confirmed: bool,

    /// Whether this is a false positive
    pub false_positive: bool,

    /// User notes
    pub notes: Option<String>,
}

impl Finding {
    /// Create a new finding
    pub fn new(name: &str, severity: Severity, url: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            severity: severity.as_str().to_string(),
            description: String::new(),
            url: url.to_string(),
            method: "GET".to_string(),
            parameter: None,
            evidence: None,
            remediation: None,
            cwe_id: None,
            owasp_category: None,
            references: Vec::new(),
            request: None,
            response: None,
            timestamp: Utc::now(),
            confidence: 1.0,
            scanner: "manual".to_string(),
            metadata: HashMap::new(),
            confirmed: false,
            false_positive: false,
            notes: None,
        }
    }

    /// Builder pattern methods
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn with_parameter(mut self, param: &str) -> Self {
        self.parameter = Some(param.to_string());
        self
    }

    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = Some(evidence.to_string());
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn with_cwe(mut self, cwe_id: u32) -> Self {
        self.cwe_id = Some(cwe_id);
        self
    }

    pub fn with_owasp(mut self, category: &str) -> Self {
        self.owasp_category = Some(category.to_string());
        self
    }

    pub fn with_reference(mut self, reference: &str) -> Self {
        self.references.push(reference.to_string());
        self
    }

    pub fn with_request(mut self, request: &str) -> Self {
        self.request = Some(request.to_string());
        self
    }

    pub fn with_response(mut self, response: &str) -> Self {
        self.response = Some(response.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_scanner(mut self, scanner: &str) -> Self {
        self.scanner = scanner.to_string();
        self
    }

    /// Get severity as enum
    pub fn severity_level(&self) -> Severity {
        Severity::from_str(&self.severity)
    }
}

/// Finding filter for searching/filtering
#[derive(Debug, Default)]
pub struct FindingFilter {
    pub severity: Option<Severity>,
    pub min_severity: Option<Severity>,
    pub scanner: Option<String>,
    pub confirmed_only: bool,
    pub exclude_false_positives: bool,
    pub url_contains: Option<String>,
    pub name_contains: Option<String>,
}

impl FindingFilter {
    pub fn matches(&self, finding: &Finding) -> bool {
        if self.exclude_false_positives && finding.false_positive {
            return false;
        }

        if self.confirmed_only && !finding.confirmed {
            return false;
        }

        if let Some(severity) = self.severity {
            if finding.severity_level() != severity {
                return false;
            }
        }

        if let Some(min_severity) = self.min_severity {
            if finding.severity_level() < min_severity {
                return false;
            }
        }

        if let Some(scanner) = &self.scanner {
            if !finding.scanner.contains(scanner) {
                return false;
            }
        }

        if let Some(url_filter) = &self.url_contains {
            if !finding.url.contains(url_filter) {
                return false;
            }
        }

        if let Some(name_filter) = &self.name_contains {
            if !finding.name.to_lowercase().contains(&name_filter.to_lowercase()) {
                return false;
            }
        }

        true
    }
}
