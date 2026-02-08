//! Nuclei template parser
//!
//! Parses YAML templates in Nuclei-compatible format.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Severity level for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// Template classification (CVSS, CWE, etc.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Classification {
    #[serde(rename = "cvss-metrics")]
    pub cvss_metrics: Option<String>,
    #[serde(rename = "cvss-score")]
    pub cvss_score: Option<f32>,
    #[serde(rename = "cwe-id")]
    pub cwe_id: Option<u32>,
    #[serde(rename = "cve-id")]
    pub cve_id: Option<String>,
}

/// Template metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reference: Vec<String>,
    #[serde(default)]
    pub tags: String,
    #[serde(default)]
    pub classification: Classification,
    #[serde(default)]
    pub metadata: HashMap<String, serde_yaml::Value>,
}

/// Matcher type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherType {
    /// Match response status code
    Status,
    /// Match words in response
    Word,
    /// Match regex pattern
    Regex,
    /// Match binary data
    Binary,
    /// DSL expression
    Dsl,
}

/// Matcher condition for combining multiple matchers
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherCondition {
    #[default]
    And,
    Or,
}

/// Where to apply the matcher
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherPart {
    #[default]
    Body,
    Header,
    All,
}

/// A matcher for detecting vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: MatcherType,

    #[serde(default)]
    pub name: Option<String>,

    /// Status codes to match
    #[serde(default)]
    pub status: Vec<u16>,

    /// Words to match
    #[serde(default)]
    pub words: Vec<String>,

    /// Regex patterns to match
    #[serde(default)]
    pub regex: Vec<String>,

    /// DSL expressions
    #[serde(default)]
    pub dsl: Vec<String>,

    /// Part of response to match
    #[serde(default)]
    pub part: MatcherPart,

    /// Condition for multiple patterns
    #[serde(default)]
    pub condition: MatcherCondition,

    /// Negative match (match if NOT found)
    #[serde(default)]
    pub negative: bool,

    /// Case insensitive matching
    #[serde(default = "default_true")]
    pub case_insensitive: bool,

    /// Internal flag - whether this is inverted
    #[serde(skip)]
    pub inverted: bool,

    /// Sub-matchers for compound AND/OR conditions
    #[serde(skip)]
    pub sub_matchers: Vec<Matcher>,
}

fn default_true() -> bool {
    true
}

impl Matcher {
    /// Create a matcher that checks for missing header
    pub fn header_missing(header: &str) -> Self {
        Self {
            matcher_type: MatcherType::Regex,
            name: Some(format!("missing-{}", header.to_lowercase())),
            // (?im) = case-insensitive + multiline (^ matches start of each line)
            regex: vec![format!("(?im)^{}:", regex::escape(header))],
            part: MatcherPart::Header,
            negative: true,
            ..Default::default()
        }
    }

    /// Create a matcher that checks for header existence
    pub fn header_exists(header: &str) -> Self {
        Self {
            matcher_type: MatcherType::Regex,
            name: Some(header.to_lowercase()),
            // (?im) = case-insensitive + multiline
            regex: vec![format!("(?im)^{}:", regex::escape(header))],
            part: MatcherPart::Header,
            ..Default::default()
        }
    }

    /// Create a matcher that checks header value with regex
    pub fn header_regex(header: &str, pattern: &str) -> Self {
        Self {
            matcher_type: MatcherType::Regex,
            name: Some(header.to_lowercase()),
            // (?im) = case-insensitive + multiline
            regex: vec![format!("(?im)^{}:.*{}", regex::escape(header), pattern)],
            part: MatcherPart::Header,
            ..Default::default()
        }
    }

    /// Create a matcher that checks header exact value
    pub fn header_value(header: &str, value: &str) -> Self {
        Self {
            matcher_type: MatcherType::Word,
            name: Some(header.to_lowercase()),
            words: vec![format!("{}: {}", header, value)],
            part: MatcherPart::Header,
            ..Default::default()
        }
    }

    /// Create a matcher that checks if header contains a value (case-insensitive)
    /// Used as a building block - combine with negative flag or Matcher::and() for "not contains"
    pub fn header_contains(header: &str, value: &str) -> Self {
        Self {
            matcher_type: MatcherType::Word,
            name: Some(format!("{}-contains-{}", header.to_lowercase(), value.to_lowercase())),
            // Check if header line contains the value (case-insensitive by default)
            words: vec![value.to_string()],
            part: MatcherPart::Header,
            case_insensitive: true,
            ..Default::default()
        }
    }

    /// Create a matcher that checks if header does NOT contain a value (case-insensitive)
    pub fn header_not_contains(header: &str, value: &str) -> Self {
        // We need to check: header exists AND header value doesn't contain the target
        // Since we can't use lookahead, we use the negative flag on a word matcher
        // This will match if the value is NOT found in the header text
        Self {
            matcher_type: MatcherType::Word,
            name: Some(format!("{}-missing-{}", header.to_lowercase(), value.to_lowercase())),
            words: vec![value.to_string()],
            part: MatcherPart::Header,
            case_insensitive: true,
            negative: true, // Match if NOT found
            ..Default::default()
        }
    }

    /// Create a body regex matcher
    pub fn body_regex(pattern: &str) -> Self {
        Self {
            matcher_type: MatcherType::Regex,
            regex: vec![pattern.to_string()],
            part: MatcherPart::Body,
            ..Default::default()
        }
    }

    /// Create a body word matcher
    pub fn body_words(words: &[&str]) -> Self {
        Self {
            matcher_type: MatcherType::Word,
            words: words.iter().map(|s| s.to_string()).collect(),
            part: MatcherPart::Body,
            condition: MatcherCondition::Or,
            ..Default::default()
        }
    }

    /// Create a body contains check (negative)
    pub fn body_not_contains(words: &[&str]) -> Self {
        Self {
            matcher_type: MatcherType::Word,
            words: words.iter().map(|s| s.to_string()).collect(),
            part: MatcherPart::Body,
            condition: MatcherCondition::Or,
            negative: true,
            ..Default::default()
        }
    }

    /// Create a status code matcher
    pub fn status(code: u16) -> Self {
        Self {
            matcher_type: MatcherType::Status,
            status: vec![code],
            ..Default::default()
        }
    }

    /// Create an AND condition matcher combining multiple matchers
    pub fn and(matchers: Vec<Matcher>) -> Self {
        Self {
            matcher_type: MatcherType::Word, // Placeholder, sub_matchers takes precedence
            name: Some("compound-and".to_string()),
            condition: MatcherCondition::And,
            sub_matchers: matchers,
            ..Default::default()
        }
    }

    /// Create an OR condition matcher combining multiple matchers
    pub fn or(matchers: Vec<Matcher>) -> Self {
        Self {
            matcher_type: MatcherType::Word,
            name: Some("compound-or".to_string()),
            condition: MatcherCondition::Or,
            sub_matchers: matchers,
            ..Default::default()
        }
    }
}

impl Default for Matcher {
    fn default() -> Self {
        Self {
            matcher_type: MatcherType::Word,
            name: None,
            status: Vec::new(),
            words: Vec::new(),
            regex: Vec::new(),
            dsl: Vec::new(),
            part: MatcherPart::Body,
            condition: MatcherCondition::And,
            negative: false,
            case_insensitive: true,
            inverted: false,
            sub_matchers: Vec::new(),
        }
    }
}

/// HTTP request definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default)]
    pub method: String,

    #[serde(default)]
    pub path: Vec<String>,

    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default)]
    pub body: String,

    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub matchers: Vec<Matcher>,

    #[serde(rename = "matchers-condition", default)]
    pub matchers_condition: MatcherCondition,

    #[serde(rename = "stop-at-first-match", default)]
    pub stop_at_first_match: bool,

    #[serde(rename = "host-redirects", default)]
    pub follow_redirects: bool,

    #[serde(rename = "max-redirects", default)]
    pub max_redirects: u8,
}

/// Template type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TemplateType {
    /// Passive - analyzes responses without sending requests
    #[default]
    Passive,
    /// Active - sends attack payloads
    Active,
}

/// A Nuclei-compatible template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// Template ID
    pub id: String,

    /// Template metadata
    pub info: TemplateInfo,

    /// HTTP requests (for active templates)
    #[serde(default)]
    pub http: Vec<HttpRequest>,

    /// Template type (computed)
    #[serde(skip)]
    pub template_type: TemplateType,

    /// Additional matchers for passive scanning
    #[serde(skip)]
    pub passive_matchers: Vec<Matcher>,

    /// CWE ID (convenience field)
    #[serde(skip)]
    pub cwe: Option<u32>,
}

impl Template {
    /// Parse template from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let mut template: Template = serde_yaml::from_str(yaml)
            .context("Failed to parse template YAML")?;

        // Determine template type
        template.template_type = if template.http.is_empty() {
            TemplateType::Passive
        } else if template.http.iter().any(|h| !h.payloads.is_empty()) {
            TemplateType::Active
        } else {
            TemplateType::Passive
        };

        // Extract CWE from classification
        template.cwe = template.info.classification.cwe_id;

        Ok(template)
    }

    /// Parse template from file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context(format!("Failed to read template file: {}", path.display()))?;
        Self::from_yaml(&content)
    }

    /// Create a passive template builder
    pub fn passive(id: &str) -> TemplateBuilder {
        TemplateBuilder::new(id, TemplateType::Passive)
    }

    /// Create an active template builder
    pub fn active(id: &str) -> TemplateBuilder {
        TemplateBuilder::new(id, TemplateType::Active)
    }

    /// Get tags as a vector
    pub fn tags(&self) -> Vec<&str> {
        self.info.tags.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
    }

    /// Check if template has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.info.tags.to_lowercase().contains(&tag.to_lowercase())
    }
}

/// Builder for creating templates programmatically
pub struct TemplateBuilder {
    id: String,
    name: String,
    author: String,
    severity: Severity,
    description: String,
    tags: Vec<String>,
    matchers: Vec<Matcher>,
    template_type: TemplateType,
    cwe: Option<u32>,
    references: Vec<String>,
}

impl TemplateBuilder {
    pub fn new(id: &str, template_type: TemplateType) -> Self {
        Self {
            id: id.to_string(),
            name: String::new(),
            author: "ancarna".to_string(),
            severity: Severity::Info,
            description: String::new(),
            tags: Vec::new(),
            matchers: Vec::new(),
            template_type,
            cwe: None,
            references: Vec::new(),
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags = tags.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn matcher(mut self, matcher: Matcher) -> Self {
        self.matchers.push(matcher);
        self
    }

    pub fn cwe(mut self, cwe: u32) -> Self {
        self.cwe = Some(cwe);
        self
    }

    pub fn reference(mut self, reference: &str) -> Self {
        self.references.push(reference.to_string());
        self
    }

    pub fn build(self) -> Template {
        Template {
            id: self.id,
            info: TemplateInfo {
                name: self.name,
                author: self.author,
                severity: self.severity,
                description: self.description,
                tags: self.tags.join(","),
                reference: self.references,
                classification: Classification {
                    cwe_id: self.cwe,
                    ..Default::default()
                },
                metadata: HashMap::new(),
            },
            http: Vec::new(),
            template_type: self.template_type,
            passive_matchers: self.matchers,
            cwe: self.cwe,
        }
    }
}
