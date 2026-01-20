//! Passive security scanner
//!
//! Analyzes HTTP traffic without modifying requests.

pub mod rules;

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};

/// Passive scanner
pub struct PassiveScanner {
    /// Enabled rules
    rules: Vec<Box<dyn PassiveRule + Send + Sync>>,
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
        }
    }

    fn default_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
        vec![
            Box::new(rules::SecurityHeadersRule::new()),
            Box::new(rules::CookieSecurityRule::new()),
            Box::new(rules::InformationDisclosureRule::new()),
            Box::new(rules::ContentTypeRule::new()),
            Box::new(rules::CorsRule::new()),
        ]
    }

    /// Scan a request/response pair
    pub fn scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            if rule.is_enabled() {
                findings.extend(rule.scan(request, response));
            }
        }

        findings
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
