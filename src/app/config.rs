//! Application configuration management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// General settings
    pub general: GeneralConfig,

    /// Proxy settings
    pub proxy: ProxyConfig,

    /// Scanner settings
    pub scanner: ScannerConfig,

    /// TUI settings
    pub tui: TuiConfig,

    /// Scripting settings
    pub scripting: ScriptingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Default workspace directory
    pub workspace_dir: Option<PathBuf>,

    /// Auto-save interval in seconds (0 to disable)
    pub auto_save_interval: u64,

    /// Maximum items in history
    pub max_history_items: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Proxy listen address
    pub listen_addr: String,

    /// Default proxy port
    pub default_port: u16,

    /// Enable HTTPS interception
    pub https_intercept: bool,

    /// CA certificate path (auto-generated if not specified)
    pub ca_cert_path: Option<PathBuf>,

    /// CA private key path
    pub ca_key_path: Option<PathBuf>,

    /// Request size limit in bytes
    pub max_request_size: usize,

    /// Response size limit in bytes
    pub max_response_size: usize,

    /// Upstream proxy (for chaining)
    pub upstream_proxy: Option<String>,

    /// Domains to exclude from interception
    pub exclude_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    /// Maximum concurrent scan threads
    pub max_threads: usize,

    /// Request timeout in seconds
    pub request_timeout: u64,

    /// Delay between requests in milliseconds
    pub request_delay: u64,

    /// Follow redirects
    pub follow_redirects: bool,

    /// Maximum redirect depth
    pub max_redirects: usize,

    /// Default scan policy
    pub default_policy: String,

    /// User agent string
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TuiConfig {
    /// Color theme
    pub theme: String,

    /// Enable vim-like keybindings
    pub vim_mode: bool,

    /// Show line numbers in editors
    pub show_line_numbers: bool,

    /// Syntax highlighting
    pub syntax_highlighting: bool,

    /// Response body size limit for display (in bytes)
    pub max_display_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptingConfig {
    /// Enable JavaScript scripting
    pub enabled: bool,

    /// Script timeout in milliseconds
    pub timeout_ms: u64,

    /// Maximum memory for script execution (in bytes)
    pub max_memory: usize,
}


impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            workspace_dir: None,
            auto_save_interval: 60,
            max_history_items: 1000,
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            default_port: 8080,
            https_intercept: true, // Enable MITM to capture HTTPS traffic
            ca_cert_path: None,
            ca_key_path: None,
            max_request_size: 10 * 1024 * 1024,  // 10MB
            max_response_size: 50 * 1024 * 1024, // 50MB
            upstream_proxy: None,
            exclude_domains: vec![],
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_threads: 10,
            request_timeout: 30,
            request_delay: 100,
            follow_redirects: true,
            max_redirects: 10,
            default_policy: "default".to_string(),
            user_agent: format!("Ancarna/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            theme: "default".to_string(),
            vim_mode: true,
            show_line_numbers: true,
            syntax_highlighting: true,
            max_display_size: 1024 * 1024, // 1MB
        }
    }
}

impl Default for ScriptingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
            max_memory: 64 * 1024 * 1024, // 64MB
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = match path {
            Some(p) => PathBuf::from(p),
            None => Self::default_config_path()?,
        };

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config from {:?}", config_path))?;

            let config: Config = toml::from_str(&contents)
                .with_context(|| "Failed to parse configuration file")?;

            tracing::info!("Loaded configuration from {:?}", config_path);
            Ok(config)
        } else {
            tracing::info!("No configuration file found, using defaults");
            Ok(Self::default())
        }
    }

    /// Save configuration to file
    pub fn save(&self, path: Option<&str>) -> Result<()> {
        let config_path = match path {
            Some(p) => PathBuf::from(p),
            None => Self::default_config_path()?,
        };

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, contents)?;

        tracing::info!("Saved configuration to {:?}", config_path);
        Ok(())
    }

    /// Get default configuration file path
    fn default_config_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("io", "ancarna", "ancarna")
            .context("Failed to determine config directory")?;

        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Get data directory path
    pub fn data_dir() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("io", "ancarna", "ancarna")
            .context("Failed to determine data directory")?;

        Ok(dirs.data_dir().to_path_buf())
    }

    /// Get cache directory path
    pub fn cache_dir() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("io", "ancarna", "ancarna")
            .context("Failed to determine cache directory")?;

        Ok(dirs.cache_dir().to_path_buf())
    }
}
