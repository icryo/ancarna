//! Passive security scanner
//!
//! Analyzes HTTP traffic without modifying requests.

#![allow(dead_code)]

pub mod rules;

use crate::http::{Request, Response};
use crate::scanner::findings::Finding;
use crate::scanner::templates::TemplateExecutor;
use std::path::Path;

/// Passive scanner
pub struct PassiveScanner {
    /// Enabled rules
    rules: Vec<Box<dyn PassiveRule + Send + Sync>>,
    /// Template-based scanner
    template_executor: TemplateExecutor,
    /// Whether to use template-based scanning
    use_templates: bool,
}

/// Trait for passive scan rules
pub trait PassiveRule {
    /// Rule name
    fn name(&self) -> &str;

    /// Check if the rule is enabled
    fn is_enabled(&self) -> bool {
        true
    }

    /// Scan request/response for issues
    fn scan(&self, request: &Request, response: &Response) -> Vec<Finding>;
}

impl PassiveScanner {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
            template_executor: TemplateExecutor::with_bundled(),
            use_templates: true,
        }
    }

    /// Create a scanner with an optional custom templates directory
    pub fn with_templates_dir(templates_dir: Option<&Path>) -> Self {
        let template_executor = match templates_dir {
            Some(dir) => TemplateExecutor::with_bundled_and_dir(dir),
            None => TemplateExecutor::with_bundled(),
        };
        Self {
            rules: Self::default_rules(),
            template_executor,
            use_templates: true,
        }
    }

    /// Create a scanner using only template-based detection (Nuclei-compatible)
    pub fn templates_only() -> Self {
        Self {
            rules: Vec::new(),
            template_executor: TemplateExecutor::with_bundled(),
            use_templates: true,
        }
    }

    /// Create a scanner using only rule-based detection (legacy)
    pub fn rules_only() -> Self {
        Self {
            rules: Self::default_rules(),
            template_executor: TemplateExecutor::new(Vec::new()),
            use_templates: false,
        }
    }

    fn default_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
        vec![
            Box::new(rules::SecurityHeadersRule::new()),
            Box::new(rules::CookieSecurityRule::new()),
            Box::new(rules::InformationDisclosureRule::new()),
            Box::new(rules::ContentTypeRule::new()),
            Box::new(rules::CorsRule::new()),
            Box::new(rules::CspRule::new()),
            Box::new(rules::CacheControlRule::new()),
            Box::new(rules::CsrfRule::new()),
            Box::new(rules::PermissionsPolicyRule::new()),
            Box::new(rules::ReferrerPolicyRule::new()),
            Box::new(rules::ServerBannerRule::new()),
            Box::new(rules::JwtRule::new()),
            Box::new(rules::JsAnalysisRule::new()),
        ]
    }

    /// Scan a request/response pair
    pub fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Run rule-based scanning
        for rule in &self.rules {
            if rule.is_enabled() {
                findings.extend(rule.scan(request, response));
            }
        }

        // Run template-based scanning
        if self.use_templates {
            findings.extend(self.template_executor.execute(request, response));
        }

        // Deduplicate findings by name + URL
        deduplicate_findings(findings)
    }

    /// Get number of loaded templates
    pub fn template_count(&self) -> usize {
        self.template_executor.template_count()
    }

    /// Enable a rule by name
    pub fn enable_rule(&mut self, _name: &str) {
        // Would need to track enabled state
    }

    /// Disable a rule by name
    pub fn disable_rule(&mut self, _name: &str) {
        // Would need to track enabled state
    }

    /// Get list of rule names
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name()).collect()
    }
}

impl Default for PassiveScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Deduplicate findings by name + URL to avoid duplicate reports
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for finding in findings {
        let key = format!("{}|{}", finding.name, finding.url);
        if seen.insert(key) {
            result.push(finding);
        }
    }

    result
}
