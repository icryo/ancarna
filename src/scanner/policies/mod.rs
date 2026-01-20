//! Scan policies for configuring scan behavior

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPolicy {
    /// Policy name
    pub name: String,

    /// Description
    pub description: String,

    /// Enabled attack modules
    pub modules: HashMap<String, ModuleConfig>,

    /// Global settings
    pub settings: PolicySettings,
}

/// Configuration for an individual scan module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Whether the module is enabled
    pub enabled: bool,

    /// Scan strength (1-5)
    pub strength: u8,

    /// Alert threshold (1-5)
    pub threshold: u8,

    /// Module-specific options
    pub options: HashMap<String, String>,
}

/// Global policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Maximum requests per second
    pub max_rps: u32,

    /// Request timeout in seconds
    pub timeout: u64,

    /// Maximum concurrent threads
    pub max_threads: usize,

    /// Follow redirects
    pub follow_redirects: bool,

    /// Maximum redirect depth
    pub max_redirects: usize,

    /// Delay between requests in milliseconds
    pub delay_ms: u64,

    /// User agent string
    pub user_agent: String,

    /// Whether to scan query parameters
    pub scan_query_params: bool,

    /// Whether to scan POST body
    pub scan_post_body: bool,

    /// Whether to scan headers
    pub scan_headers: bool,

    /// Whether to scan cookies
    pub scan_cookies: bool,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl ScanPolicy {
    /// Standard scan policy - balanced between speed and coverage
    pub fn standard() -> Self {
        let mut modules = HashMap::new();

        // Active scanning modules
        modules.insert("sqli".to_string(), ModuleConfig {
            enabled: true,
            strength: 3,
            threshold: 2,
            options: HashMap::new(),
        });

        modules.insert("xss".to_string(), ModuleConfig {
            enabled: true,
            strength: 3,
            threshold: 2,
            options: HashMap::new(),
        });

        modules.insert("path_traversal".to_string(), ModuleConfig {
            enabled: true,
            strength: 3,
            threshold: 2,
            options: HashMap::new(),
        });

        modules.insert("command_injection".to_string(), ModuleConfig {
            enabled: true,
            strength: 2,
            threshold: 3,
            options: HashMap::new(),
        });

        modules.insert("xxe".to_string(), ModuleConfig {
            enabled: true,
            strength: 2,
            threshold: 2,
            options: HashMap::new(),
        });

        modules.insert("ssrf".to_string(), ModuleConfig {
            enabled: true,
            strength: 2,
            threshold: 2,
            options: HashMap::new(),
        });

        Self {
            name: "Standard".to_string(),
            description: "Balanced scan with common vulnerability checks".to_string(),
            modules,
            settings: PolicySettings::default(),
        }
    }

    /// Quick scan - fast but limited coverage
    pub fn quick() -> Self {
        let mut policy = Self::standard();
        policy.name = "Quick".to_string();
        policy.description = "Fast scan with reduced payloads".to_string();

        for (_, config) in policy.modules.iter_mut() {
            config.strength = 1;
        }

        policy.settings.max_threads = 20;
        policy.settings.delay_ms = 0;

        policy
    }

    /// Full scan - comprehensive but slow
    pub fn full() -> Self {
        let mut policy = Self::standard();
        policy.name = "Full".to_string();
        policy.description = "Comprehensive scan with all checks enabled".to_string();

        for (_, config) in policy.modules.iter_mut() {
            config.strength = 5;
            config.threshold = 1;
        }

        policy
    }

    /// API-focused scan
    pub fn api() -> Self {
        let mut policy = Self::standard();
        policy.name = "API".to_string();
        policy.description = "Optimized for REST/GraphQL APIs".to_string();

        // Disable HTML-specific checks
        if let Some(xss) = policy.modules.get_mut("xss") {
            xss.strength = 2;
        }

        policy.settings.scan_headers = true;
        policy.settings.scan_post_body = true;

        policy
    }

    /// Passive-only scan
    pub fn passive_only() -> Self {
        let mut policy = Self::standard();
        policy.name = "Passive Only".to_string();
        policy.description = "Only passive analysis, no active attacks".to_string();

        // Disable all active modules
        for (_, config) in policy.modules.iter_mut() {
            config.enabled = false;
        }

        policy
    }

    /// Check if a module is enabled
    pub fn is_enabled(&self, module: &str) -> bool {
        self.modules
            .get(module)
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Get module configuration
    pub fn get_module(&self, module: &str) -> Option<&ModuleConfig> {
        self.modules.get(module)
    }

    /// Enable a module
    pub fn enable_module(&mut self, module: &str) {
        if let Some(config) = self.modules.get_mut(module) {
            config.enabled = true;
        }
    }

    /// Disable a module
    pub fn disable_module(&mut self, module: &str) {
        if let Some(config) = self.modules.get_mut(module) {
            config.enabled = false;
        }
    }

    /// Set module strength
    pub fn set_strength(&mut self, module: &str, strength: u8) {
        if let Some(config) = self.modules.get_mut(module) {
            config.strength = strength.clamp(1, 5);
        }
    }
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            max_rps: 10,
            timeout: 30,
            max_threads: 5,
            follow_redirects: true,
            max_redirects: 5,
            delay_ms: 100,
            user_agent: format!("Ancarna/{}", env!("CARGO_PKG_VERSION")),
            scan_query_params: true,
            scan_post_body: true,
            scan_headers: false,
            scan_cookies: false,
        }
    }
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strength: 3,
            threshold: 2,
            options: HashMap::new(),
        }
    }
}
