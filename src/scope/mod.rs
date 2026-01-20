//! Scope Management Module
//!
//! Controls which targets are in-scope for security testing.
//! Supports URL patterns, domain matching, and IP ranges.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

/// Scope configuration for a security testing context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Scope name/identifier
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Include patterns (URLs/domains that ARE in scope)
    pub include: Vec<ScopePattern>,
    /// Exclude patterns (URLs/domains that are NOT in scope)
    pub exclude: Vec<ScopePattern>,
    /// Whether scope is enabled
    pub enabled: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            name: "Default".to_string(),
            description: None,
            include: Vec::new(),
            exclude: Vec::new(),
            enabled: true,
        }
    }
}

impl Scope {
    /// Create a new scope with a name
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Add an include pattern
    pub fn add_include(&mut self, pattern: ScopePattern) {
        self.include.push(pattern);
    }

    /// Add an exclude pattern
    pub fn add_exclude(&mut self, pattern: ScopePattern) {
        self.exclude.push(pattern);
    }

    /// Add a target URL (auto-creates appropriate pattern)
    pub fn add_target_url(&mut self, url: &str) -> Result<(), ScopeError> {
        let pattern = ScopePattern::from_url(url)?;
        self.include.push(pattern);
        Ok(())
    }

    /// Add a target domain
    pub fn add_target_domain(&mut self, domain: &str, include_subdomains: bool) {
        self.include.push(ScopePattern::Domain {
            domain: domain.to_string(),
            include_subdomains,
        });
    }

    /// Check if a URL is in scope
    pub fn is_in_scope(&self, url: &str) -> bool {
        if !self.enabled {
            return true; // If scope is disabled, everything is in scope
        }

        // First check excludes - if URL matches any exclude, it's out of scope
        for pattern in &self.exclude {
            if pattern.matches(url) {
                return false;
            }
        }

        // If no includes defined, nothing is in scope
        if self.include.is_empty() {
            return false;
        }

        // Check if URL matches any include pattern
        for pattern in &self.include {
            if pattern.matches(url) {
                return true;
            }
        }

        false
    }

    /// Get all in-scope domains
    pub fn get_domains(&self) -> HashSet<String> {
        let mut domains = HashSet::new();
        for pattern in &self.include {
            if let Some(domain) = pattern.get_domain() {
                domains.insert(domain);
            }
        }
        domains
    }

    /// Check if scope has any patterns defined
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        format!(
            "{} include, {} exclude patterns",
            self.include.len(),
            self.exclude.len()
        )
    }
}

/// A pattern for matching URLs/domains
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScopePattern {
    /// Match exact URL
    ExactUrl { url: String },
    /// Match URL prefix
    UrlPrefix { prefix: String },
    /// Match domain (with optional subdomain matching)
    Domain {
        domain: String,
        include_subdomains: bool,
    },
    /// Match using regex pattern
    Regex { pattern: String },
    /// Match IP address or CIDR range
    IpRange { cidr: String },
    /// Match any path under a base URL
    BaseUrl { base: String },
}

impl ScopePattern {
    /// Create a pattern from a URL string (auto-detects best pattern type)
    pub fn from_url(url: &str) -> Result<Self, ScopeError> {
        // Parse URL to validate and extract components
        let parsed = Url::parse(url).map_err(|e| ScopeError::InvalidUrl(e.to_string()))?;

        // Use the URL as a base URL pattern (matches all paths under it)
        let base = format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(""),
            if let Some(port) = parsed.port() {
                format!(":{}", port)
            } else {
                String::new()
            }
        );

        Ok(ScopePattern::BaseUrl { base })
    }

    /// Create a domain pattern
    pub fn domain(domain: &str, include_subdomains: bool) -> Self {
        ScopePattern::Domain {
            domain: domain.to_string(),
            include_subdomains,
        }
    }

    /// Create a regex pattern
    pub fn regex(pattern: &str) -> Result<Self, ScopeError> {
        // Validate regex
        Regex::new(pattern).map_err(|e| ScopeError::InvalidRegex(e.to_string()))?;
        Ok(ScopePattern::Regex {
            pattern: pattern.to_string(),
        })
    }

    /// Create an IP/CIDR pattern
    pub fn ip_range(cidr: &str) -> Result<Self, ScopeError> {
        // Validate CIDR or IP
        if cidr.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(ScopeError::InvalidCidr(cidr.to_string()));
            }
            IpAddr::from_str(parts[0]).map_err(|_| ScopeError::InvalidCidr(cidr.to_string()))?;
            parts[1]
                .parse::<u8>()
                .map_err(|_| ScopeError::InvalidCidr(cidr.to_string()))?;
        } else {
            // Single IP
            IpAddr::from_str(cidr).map_err(|_| ScopeError::InvalidCidr(cidr.to_string()))?;
        }
        Ok(ScopePattern::IpRange {
            cidr: cidr.to_string(),
        })
    }

    /// Check if this pattern matches a URL
    pub fn matches(&self, url: &str) -> bool {
        match self {
            ScopePattern::ExactUrl { url: pattern_url } => url == pattern_url,

            ScopePattern::UrlPrefix { prefix } => url.starts_with(prefix),

            ScopePattern::Domain {
                domain,
                include_subdomains,
            } => {
                if let Ok(parsed) = Url::parse(url) {
                    if let Some(host) = parsed.host_str() {
                        if *include_subdomains {
                            host == domain || host.ends_with(&format!(".{}", domain))
                        } else {
                            host == domain
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            ScopePattern::Regex { pattern } => {
                if let Ok(re) = Regex::new(pattern) {
                    re.is_match(url)
                } else {
                    false
                }
            }

            ScopePattern::IpRange { cidr } => {
                if let Ok(parsed) = Url::parse(url) {
                    if let Some(host) = parsed.host_str() {
                        match_ip_range(host, cidr)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            ScopePattern::BaseUrl { base } => {
                let url_lower = url.to_lowercase();
                let base_lower = base.to_lowercase();
                url_lower.starts_with(&base_lower)
            }
        }
    }

    /// Get the domain from this pattern (if applicable)
    pub fn get_domain(&self) -> Option<String> {
        match self {
            ScopePattern::Domain { domain, .. } => Some(domain.clone()),
            ScopePattern::BaseUrl { base } => {
                Url::parse(base).ok().and_then(|u| u.host_str().map(String::from))
            }
            ScopePattern::ExactUrl { url } | ScopePattern::UrlPrefix { prefix: url } => {
                Url::parse(url).ok().and_then(|u| u.host_str().map(String::from))
            }
            _ => None,
        }
    }

    /// Get a display string for this pattern
    pub fn display(&self) -> String {
        match self {
            ScopePattern::ExactUrl { url } => format!("Exact: {}", url),
            ScopePattern::UrlPrefix { prefix } => format!("Prefix: {}*", prefix),
            ScopePattern::Domain {
                domain,
                include_subdomains,
            } => {
                if *include_subdomains {
                    format!("Domain: *.{}", domain)
                } else {
                    format!("Domain: {}", domain)
                }
            }
            ScopePattern::Regex { pattern } => format!("Regex: {}", pattern),
            ScopePattern::IpRange { cidr } => format!("IP: {}", cidr),
            ScopePattern::BaseUrl { base } => format!("Base: {}/*", base),
        }
    }
}

/// Check if an IP/hostname matches a CIDR range
fn match_ip_range(host: &str, cidr: &str) -> bool {
    // Try to parse host as IP
    let host_ip = match IpAddr::from_str(host) {
        Ok(ip) => ip,
        Err(_) => return false, // Not an IP address
    };

    if cidr.contains('/') {
        // CIDR notation
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network_ip = match IpAddr::from_str(parts[0]) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let prefix_len: u8 = match parts[1].parse() {
            Ok(len) => len,
            Err(_) => return false,
        };

        // Check if IPs are same type
        match (host_ip, network_ip) {
            (IpAddr::V4(host_v4), IpAddr::V4(network_v4)) => {
                if prefix_len > 32 {
                    return false;
                }
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let host_bits = u32::from(host_v4);
                let network_bits = u32::from(network_v4);
                (host_bits & mask) == (network_bits & mask)
            }
            (IpAddr::V6(host_v6), IpAddr::V6(network_v6)) => {
                if prefix_len > 128 {
                    return false;
                }
                let host_bits = u128::from(host_v6);
                let network_bits = u128::from(network_v6);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                (host_bits & mask) == (network_bits & mask)
            }
            _ => false, // Mismatched IP versions
        }
    } else {
        // Single IP
        if let Ok(cidr_ip) = IpAddr::from_str(cidr) {
            host_ip == cidr_ip
        } else {
            false
        }
    }
}

/// Scope management errors
#[derive(Debug, Clone)]
pub enum ScopeError {
    InvalidUrl(String),
    InvalidRegex(String),
    InvalidCidr(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::InvalidUrl(e) => write!(f, "Invalid URL: {}", e),
            ScopeError::InvalidRegex(e) => write!(f, "Invalid regex: {}", e),
            ScopeError::InvalidCidr(e) => write!(f, "Invalid CIDR: {}", e),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Scope manager for handling multiple scopes
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeManager {
    /// All defined scopes
    pub scopes: Vec<Scope>,
    /// Index of active scope
    pub active_scope: Option<usize>,
}

impl ScopeManager {
    /// Create a new scope manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a scope
    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.push(scope);
        if self.active_scope.is_none() {
            self.active_scope = Some(0);
        }
    }

    /// Get the active scope
    pub fn get_active(&self) -> Option<&Scope> {
        self.active_scope.and_then(|i| self.scopes.get(i))
    }

    /// Get the active scope mutably
    pub fn get_active_mut(&mut self) -> Option<&mut Scope> {
        self.active_scope.and_then(|i| self.scopes.get_mut(i))
    }

    /// Set active scope by index
    pub fn set_active(&mut self, index: usize) -> bool {
        if index < self.scopes.len() {
            self.active_scope = Some(index);
            true
        } else {
            false
        }
    }

    /// Check if URL is in scope (using active scope)
    pub fn is_in_scope(&self, url: &str) -> bool {
        match self.get_active() {
            Some(scope) => scope.is_in_scope(url),
            None => true, // No scope defined = everything in scope
        }
    }

    /// Remove a scope by index
    pub fn remove_scope(&mut self, index: usize) -> Option<Scope> {
        if index < self.scopes.len() {
            let scope = self.scopes.remove(index);
            // Adjust active index
            if let Some(active) = self.active_scope {
                if active >= self.scopes.len() {
                    self.active_scope = if self.scopes.is_empty() {
                        None
                    } else {
                        Some(self.scopes.len() - 1)
                    };
                } else if active > index {
                    self.active_scope = Some(active - 1);
                }
            }
            Some(scope)
        } else {
            None
        }
    }

    /// Get scope names for display
    pub fn scope_names(&self) -> Vec<&str> {
        self.scopes.iter().map(|s| s.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_pattern() {
        let pattern = ScopePattern::domain("example.com", false);
        assert!(pattern.matches("https://example.com/path"));
        assert!(!pattern.matches("https://sub.example.com/path"));
        assert!(!pattern.matches("https://other.com/"));

        let pattern_with_subs = ScopePattern::domain("example.com", true);
        assert!(pattern_with_subs.matches("https://example.com/path"));
        assert!(pattern_with_subs.matches("https://sub.example.com/path"));
        assert!(pattern_with_subs.matches("https://a.b.example.com/"));
    }

    #[test]
    fn test_base_url_pattern() {
        let pattern = ScopePattern::from_url("https://example.com").unwrap();
        assert!(pattern.matches("https://example.com/"));
        assert!(pattern.matches("https://example.com/api/v1"));
        assert!(!pattern.matches("http://example.com/")); // Different scheme
    }

    #[test]
    fn test_regex_pattern() {
        let pattern = ScopePattern::regex(r"https://.*\.example\.com/.*").unwrap();
        assert!(pattern.matches("https://api.example.com/v1"));
        assert!(pattern.matches("https://www.example.com/page"));
        assert!(!pattern.matches("https://example.com/page"));
    }

    #[test]
    fn test_ip_range_single() {
        let pattern = ScopePattern::ip_range("192.168.1.1").unwrap();
        assert!(pattern.matches("http://192.168.1.1/"));
        assert!(!pattern.matches("http://192.168.1.2/"));
    }

    #[test]
    fn test_ip_range_cidr() {
        let pattern = ScopePattern::ip_range("192.168.1.0/24").unwrap();
        assert!(pattern.matches("http://192.168.1.1/"));
        assert!(pattern.matches("http://192.168.1.254/"));
        assert!(!pattern.matches("http://192.168.2.1/"));
    }

    #[test]
    fn test_scope_include_exclude() {
        let mut scope = Scope::new("Test");
        scope.add_target_domain("example.com", true);
        scope.add_exclude(ScopePattern::UrlPrefix {
            prefix: "https://admin.example.com".to_string(),
        });

        assert!(scope.is_in_scope("https://example.com/api"));
        assert!(scope.is_in_scope("https://www.example.com/"));
        assert!(!scope.is_in_scope("https://admin.example.com/login"));
        assert!(!scope.is_in_scope("https://other.com/"));
    }

    #[test]
    fn test_scope_manager() {
        let mut manager = ScopeManager::new();

        let mut scope1 = Scope::new("Production");
        scope1.add_target_domain("prod.example.com", false);
        manager.add_scope(scope1);

        let mut scope2 = Scope::new("Staging");
        scope2.add_target_domain("staging.example.com", false);
        manager.add_scope(scope2);

        assert!(manager.is_in_scope("https://prod.example.com/"));
        assert!(!manager.is_in_scope("https://staging.example.com/"));

        manager.set_active(1);
        assert!(!manager.is_in_scope("https://prod.example.com/"));
        assert!(manager.is_in_scope("https://staging.example.com/"));
    }

    #[test]
    fn test_empty_scope() {
        let scope = Scope::new("Empty");
        assert!(!scope.is_in_scope("https://any.com/")); // Empty scope = nothing in scope
    }

    #[test]
    fn test_disabled_scope() {
        let mut scope = Scope::new("Disabled");
        scope.add_target_domain("example.com", false);
        scope.enabled = false;

        assert!(scope.is_in_scope("https://any.com/")); // Disabled = everything in scope
    }
}
